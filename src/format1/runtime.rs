use super::cel::{self, Environment};
use super::compile::{
    hash_json, root_external_variables, root_input_variables, Bundle, CompiledAction,
    CompiledActionKind, CompiledChoice, CompiledSendTarget, CompiledStateKind, CompiledTarget,
    CompiledTransition, Component, ComponentDefinition, Machine, State,
};
use super::counter::Counter;
use super::model::{
    BindingExpressions, Bindings, DefinitionBinding, Delivery, Envelope, EventDeclaration,
    EventDirection, IdentityOrigin, MachineIdentity, Target, VariableDeclaration,
};
use crate::value::{InstanceReference, Value};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeStatus {
    Running,
    Completed,
    Faulted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    Handled,
    Unhandled,
    Rejected,
    Faulted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rejection {
    pub code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FaultRecord {
    pub definition_fingerprint: String,
    pub runtime_id: String,
    pub cause_id: String,
    pub code: String,
    pub step_sequence: Counter,
    pub source_locator: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Emission {
    pub emitting_runtime_id: String,
    pub emitting_owner_runtime_id: Option<String>,
    pub event: String,
    pub event_id: Option<String>,
    pub target: Target,
    pub payload: BTreeMap<String, Value>,
    pub correlation_id: Option<String>,
    pub effect_id: Option<String>,
    pub sequence: Option<Counter>,
}

impl Emission {
    pub fn envelope(&self) -> Option<Envelope> {
        Some(Envelope {
            event: self.event.clone(),
            event_id: self.event_id.clone()?,
            target: self.target.clone(),
            payload: self.payload.clone(),
            correlation_id: self.correlation_id.clone(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct CoreResult {
    pub status: ResultStatus,
    pub disposition: Option<Disposition>,
    pub state: Option<AggregateState>,
    pub emissions: Vec<Emission>,
    pub fault: Option<FaultRecord>,
    pub rejection: Option<Rejection>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultStatus {
    Running,
    Completed,
    Faulted,
    Rejected,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AggregateState {
    pub validated_bundle_fingerprint: String,
    pub namespace: String,
    pub root_instance_id: String,
    pub creation_id: String,
    pub migration_sequence: Counter,
    pub wire_runtime_order: Vec<String>,
    pub root: RuntimeState,
    pub next_logical_step_sequence: Counter,
    pub next_output_sequence: Counter,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RuntimeState {
    pub runtime_id: String,
    pub identity_origin: IdentityOrigin,
    pub target_identity: Target,
    pub current_definition: DefinitionBinding,
    pub machine_id: String,
    pub machine_version: i64,
    pub definition: Machine,
    pub status: RuntimeStatus,
    pub active: BTreeSet<String>,
    pub variables: BTreeMap<String, VariableSlot>,
    pub history: BTreeMap<String, Option<Vec<String>>>,
    pub components: Vec<ComponentRuntime>,
    pub owned_instances: Vec<OwnedRuntime>,
    pub next_spawn_sequence: Counter,
    pub next_component_activation_sequence: BTreeMap<String, Counter>,
    pub next_state_activation_sequence: BTreeMap<String, Counter>,
    pub active_state_activation_sequence: BTreeMap<String, Counter>,
    pub fault: Option<FaultRecord>,
    pub relation: RuntimeRelation,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VariableSlot {
    pub name: String,
    pub declaration_path: String,
    pub declaration_pointer: String,
    pub declaration: VariableDeclaration,
    pub value: Value,
    pub state_activation_sequence: Counter,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RuntimeRelation {
    Root,
    Component {
        owner_runtime_id: String,
        owner_target: Box<Target>,
        owner_state_path: String,
        component_id: String,
        component_pointer: String,
        declaration_index: usize,
        activation_sequence: Counter,
    },
    Spawned {
        owner_runtime_id: String,
        owner_target: Box<Target>,
        spawn_sequence: Counter,
        spawn_pointer: String,
        reference: InstanceReference,
        holder_path: Option<String>,
        holder_pointer: Option<String>,
        holder_activation_sequence: Counter,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct ComponentRuntime {
    pub component_id: String,
    pub pointer: String,
    pub declaration_index: usize,
    pub activation_sequence: Counter,
    pub runtime: RuntimeState,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OwnedRuntime {
    pub spawn_sequence: Counter,
    pub holder_path: Option<String>,
    pub holder_pointer: Option<String>,
    pub holder_activation_sequence: Counter,
    pub reference: InstanceReference,
    pub runtime: RuntimeState,
}

#[derive(Debug, Clone)]
struct StepFault {
    code: &'static str,
    source_locator: String,
}

struct StepContext<'a> {
    bundle: &'a Bundle,
    root_instance_id: &'a str,
    step_sequence: Counter,
    cause_id: String,
    next_output_sequence: &'a mut Counter,
    emissions: &'a mut Vec<Emission>,
}

pub fn create(
    bundle: &Bundle,
    machine_id: &str,
    root_instance_id: &str,
    creation_id: &str,
    bindings: &Bindings,
) -> CoreResult {
    if root_instance_id.is_empty() || creation_id.is_empty() {
        return rejected_creation("invalid_creation_request");
    }
    let Some(machine) = bundle.machines.get(machine_id).cloned() else {
        return rejected_creation("invalid_machine_target");
    };
    let root_runtime_id = root_runtime_identity(bundle, &machine, root_instance_id);
    let root_definition = definition_binding(bundle, &machine);
    let root_target = Target::Root {
        root_instance_id: root_instance_id.to_string(),
        root_runtime_id: root_runtime_id.clone(),
    };
    let mut aggregate = AggregateState {
        validated_bundle_fingerprint: bundle.fingerprint.clone(),
        namespace: bundle.namespace.clone(),
        root_instance_id: root_instance_id.to_string(),
        creation_id: creation_id.to_string(),
        migration_sequence: Counter::zero(),
        wire_runtime_order: vec![root_runtime_id.clone()],
        root: RuntimeState::new(
            root_runtime_id.clone(),
            machine.clone(),
            RuntimeRelation::Root,
            IdentityOrigin::Root {
                definition: root_definition.clone(),
                root_instance_id: root_instance_id.to_string(),
            },
            root_target,
            root_definition,
        ),
        next_logical_step_sequence: Counter::zero(),
        next_output_sequence: Counter::zero(),
    };
    if initialize_root_variables(&mut aggregate.root, bindings).is_err() {
        return rejected_creation("invalid_binding");
    }

    let cause_id = initialization_cause(
        "root_initialization",
        root_instance_id,
        &root_runtime_id,
        &root_runtime_id,
        creation_id,
        &Counter::zero(),
        &machine.root_pointer,
        &Counter::zero(),
    );
    let mut emissions = Vec::new();
    let mut context = StepContext {
        bundle,
        root_instance_id,
        step_sequence: Counter::zero(),
        cause_id: cause_id.clone(),
        next_output_sequence: &mut aggregate.next_output_sequence,
        emissions: &mut emissions,
    };
    let initialization = initialize_runtime(&mut aggregate.root, bindings, &mut context, true);
    aggregate.next_logical_step_sequence = Counter::from(1_u64);
    match initialization {
        Ok(()) => CoreResult {
            status: result_status(aggregate.root.status),
            disposition: None,
            fault: aggregate.root.fault.clone(),
            state: Some(aggregate),
            emissions,
            rejection: None,
        },
        Err(fault) => {
            let record = FaultRecord {
                definition_fingerprint: bundle.fingerprint.clone(),
                runtime_id: root_runtime_id,
                cause_id,
                code: fault.code.to_string(),
                step_sequence: Counter::zero(),
                source_locator: fault.source_locator,
            };
            let mut diagnostic = RuntimeState::new(
                aggregate.root.runtime_id.clone(),
                machine,
                RuntimeRelation::Root,
                aggregate.root.identity_origin.clone(),
                aggregate.root.target_identity.clone(),
                aggregate.root.current_definition.clone(),
            );
            diagnostic.history.clear();
            diagnostic.status = RuntimeStatus::Faulted;
            diagnostic.fault = Some(record.clone());
            aggregate.root = diagnostic;
            aggregate.next_output_sequence = Counter::zero();
            CoreResult {
                status: ResultStatus::Faulted,
                disposition: None,
                state: Some(aggregate),
                emissions: Vec::new(),
                fault: Some(record),
                rejection: None,
            }
        }
    }
}

pub fn dispatch(
    bundle: &Bundle,
    prior_state: &AggregateState,
    delivery: Option<Delivery>,
) -> CoreResult {
    if !validate_prior_state(prior_state) {
        return rejected_dispatch(prior_state, "invalid_prior_state");
    }
    if prior_state.validated_bundle_fingerprint != bundle.fingerprint {
        return rejected_dispatch(prior_state, "incompatible_bundle");
    }
    if !validate_prior_state_bundle_binding(prior_state, bundle) {
        return rejected_dispatch(prior_state, "invalid_prior_state");
    }
    let Some(delivery) = delivery else {
        return CoreResult {
            status: result_status(prior_state.root.status),
            disposition: None,
            state: Some(prior_state.clone()),
            emissions: Vec::new(),
            fault: prior_state.root.fault.clone(),
            rejection: None,
        };
    };
    let (mode, envelope) = match delivery {
        Delivery::Input(envelope) => (DeliveryMode::Input, envelope),
        Delivery::Internal(envelope) => (DeliveryMode::Internal, envelope),
    };
    if prior_state.root.status == RuntimeStatus::Faulted {
        return rejected_dispatch(prior_state, "invalid_instance_target");
    }
    if matches!(mode, DeliveryMode::Input) && matches!(envelope.target, Target::Component { .. }) {
        return rejected_dispatch(prior_state, "invalid_instance_target");
    }
    let address = match resolve_delivery_target(prior_state, &envelope.target) {
        Ok(address) => address,
        Err(code) => return rejected_dispatch(prior_state, code),
    };
    let Some(target_runtime) = runtime_at(&prior_state.root, &address) else {
        return rejected_dispatch(
            prior_state,
            if matches!(envelope.target, Target::Component { .. }) {
                "inactive_component_target"
            } else {
                "invalid_instance_target"
            },
        );
    };
    if target_runtime.status != RuntimeStatus::Running {
        return rejected_dispatch(
            prior_state,
            if matches!(envelope.target, Target::Component { .. }) {
                "inactive_component_target"
            } else {
                "invalid_instance_target"
            },
        );
    }
    let normalized_envelope = match validate_envelope(bundle, target_runtime, mode, &envelope) {
        Ok(envelope) => envelope,
        Err(code) => return rejected_dispatch(prior_state, code),
    };
    let selected = match select_handler(target_runtime, &normalized_envelope) {
        Ok(selected) => selected,
        Err(fault) => {
            return fault_dispatch(bundle, prior_state, &address, &normalized_envelope, fault)
        }
    };
    let Some((source_path, transition)) = selected else {
        if matches!(
            normalized_envelope.event.as_str(),
            "determa.component_failed" | "determa.spawned_instance_failed"
        ) {
            return fault_dispatch(
                bundle,
                prior_state,
                &address,
                &normalized_envelope,
                StepFault {
                    code: "contained_runtime_fault",
                    source_locator: "system:unhandled_contained_failure".to_string(),
                },
            );
        }
        return CoreResult {
            status: result_status(prior_state.root.status),
            disposition: Some(Disposition::Unhandled),
            state: Some(prior_state.clone()),
            emissions: Vec::new(),
            fault: prior_state.root.fault.clone(),
            rejection: None,
        };
    };

    let mut aggregate = prior_state.clone();
    let step_sequence = aggregate.next_logical_step_sequence.allocate();
    let mut emissions = Vec::new();
    let root_instance_id = aggregate.root_instance_id.clone();
    let cause_id = normalized_envelope.event_id.clone();
    let execution = {
        let next_output_sequence = &mut aggregate.next_output_sequence;
        let runtime = runtime_at_mut(&mut aggregate.root, &address)
            .expect("validated runtime address remains present");
        let mut context = StepContext {
            bundle,
            root_instance_id: &root_instance_id,
            step_sequence: step_sequence.clone(),
            cause_id,
            next_output_sequence,
            emissions: &mut emissions,
        };
        execute_transition(
            runtime,
            &source_path,
            &transition,
            &normalized_envelope,
            &mut context,
        )
    };
    match execution {
        Ok(()) => {
            append_parallel_done_if_needed(
                &mut aggregate,
                &address,
                &normalized_envelope.event_id,
                step_sequence.clone(),
                &mut emissions,
            );
            dispose_completed_spawned_at_path(&mut aggregate.root, &address);
            CoreResult {
                status: result_status(aggregate.root.status),
                disposition: Some(Disposition::Handled),
                fault: runtime_at(&aggregate.root, &address)
                    .and_then(|runtime| runtime.fault.clone())
                    .or_else(|| aggregate.root.fault.clone()),
                state: Some(aggregate),
                emissions,
                rejection: None,
            }
        }
        Err(fault) => fault_dispatch(bundle, prior_state, &address, &normalized_envelope, fault),
    }
}

#[derive(Clone, Copy)]
enum DeliveryMode {
    Input,
    Internal,
}

#[derive(Debug, Clone)]
enum AddressSegment {
    Component(String, Counter),
    Spawn(Counter),
}

type RuntimeAddress = Vec<AddressSegment>;

impl RuntimeState {
    fn new(
        runtime_id: String,
        definition: Machine,
        relation: RuntimeRelation,
        identity_origin: IdentityOrigin,
        target_identity: Target,
        current_definition: DefinitionBinding,
    ) -> Self {
        let history = definition
            .states
            .values()
            .filter(|state| !matches!(state.history, super::model::HistoryKind::None))
            .map(|state| (state.path.clone(), None))
            .collect();
        Self {
            runtime_id,
            identity_origin,
            target_identity,
            current_definition,
            machine_id: definition.machine_id.clone(),
            machine_version: definition.version,
            definition,
            status: RuntimeStatus::Running,
            active: BTreeSet::new(),
            variables: BTreeMap::new(),
            history,
            components: Vec::new(),
            owned_instances: Vec::new(),
            next_spawn_sequence: Counter::zero(),
            next_component_activation_sequence: BTreeMap::new(),
            next_state_activation_sequence: BTreeMap::new(),
            active_state_activation_sequence: BTreeMap::new(),
            fault: None,
            relation,
        }
    }

    pub fn config(&self) -> Vec<String> {
        let mut leaves = self
            .active
            .iter()
            .filter(|path| {
                !self
                    .active
                    .iter()
                    .any(|candidate| candidate != *path && is_descendant(candidate, path))
            })
            .filter(|path| path.as_str() != "root")
            .cloned()
            .collect::<Vec<_>>();
        leaves.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        leaves
    }

    pub fn visible_variables(&self) -> BTreeMap<String, Value> {
        let scope = self
            .config()
            .first()
            .cloned()
            .unwrap_or_else(|| "root".to_string());
        visible_variables(self, &scope)
    }
}

fn result_status(status: RuntimeStatus) -> ResultStatus {
    match status {
        RuntimeStatus::Running => ResultStatus::Running,
        RuntimeStatus::Completed => ResultStatus::Completed,
        RuntimeStatus::Faulted => ResultStatus::Faulted,
    }
}

fn rejected_creation(code: &str) -> CoreResult {
    CoreResult {
        status: ResultStatus::Rejected,
        disposition: None,
        state: None,
        emissions: Vec::new(),
        fault: None,
        rejection: Some(Rejection {
            code: code.to_string(),
        }),
    }
}

fn rejected_dispatch(prior_state: &AggregateState, code: &str) -> CoreResult {
    CoreResult {
        status: result_status(prior_state.root.status),
        disposition: Some(Disposition::Rejected),
        state: Some(prior_state.clone()),
        emissions: Vec::new(),
        fault: prior_state.root.fault.clone(),
        rejection: Some(Rejection {
            code: code.to_string(),
        }),
    }
}

fn fault_dispatch(
    _bundle: &Bundle,
    prior_state: &AggregateState,
    address: &RuntimeAddress,
    envelope: &Envelope,
    fault: StepFault,
) -> CoreResult {
    let mut aggregate = prior_state.clone();
    let step_sequence = aggregate.next_logical_step_sequence.allocate();
    let runtime = runtime_at_mut(&mut aggregate.root, address).expect("fault target was validated");
    let record = FaultRecord {
        definition_fingerprint: runtime
            .current_definition
            .validated_bundle_fingerprint
            .clone(),
        runtime_id: runtime.runtime_id.clone(),
        cause_id: envelope.event_id.clone(),
        code: fault.code.to_string(),
        step_sequence: step_sequence.clone(),
        source_locator: fault.source_locator,
    };
    runtime.status = RuntimeStatus::Faulted;
    runtime.fault = Some(record.clone());
    let root_fault = address.is_empty();
    let mut emissions = Vec::new();
    if !root_fault {
        let root_instance_id = aggregate.root_instance_id.clone();
        let mut context = StepContext {
            bundle: _bundle,
            root_instance_id: &root_instance_id,
            step_sequence,
            cause_id: envelope.event_id.clone(),
            next_output_sequence: &mut aggregate.next_output_sequence,
            emissions: &mut emissions,
        };
        let target = runtime_at(&aggregate.root, address)
            .expect("faulted runtime remains retained")
            .clone();
        emit_failure_notification(&target, &record, &mut context);
    }
    CoreResult {
        status: result_status(aggregate.root.status),
        disposition: Some(Disposition::Faulted),
        state: Some(aggregate),
        emissions,
        fault: Some(record),
        rejection: None,
    }
}

fn validate_prior_state(state: &AggregateState) -> bool {
    if state.validated_bundle_fingerprint.is_empty()
        || state.namespace.is_empty()
        || state.root_instance_id.is_empty()
        || state.creation_id.is_empty()
        || !matches!(state.root.relation, RuntimeRelation::Root)
        || !validate_root_identity(state)
    {
        return false;
    }
    validate_runtime_shape(state, &state.root, &state.root.definition)
}

fn validate_root_identity(state: &AggregateState) -> bool {
    let IdentityOrigin::Root {
        definition,
        root_instance_id,
    } = &state.root.identity_origin
    else {
        return false;
    };
    if root_instance_id != &state.root_instance_id {
        return false;
    }
    let expected = hash_json(serde_json::json!([
        "determa-root-runtime-identity-2",
        "1",
        definition.validated_bundle_fingerprint,
        definition.machine.namespace,
        definition.machine.machine_id,
        definition.machine.machine_version.to_string(),
        state.root_instance_id
    ]));
    state.root.runtime_id == expected
        && state.root.target_identity
            == Target::Root {
                root_instance_id: state.root_instance_id.clone(),
                root_runtime_id: state.root.runtime_id.clone(),
            }
}

fn validate_runtime_identity(aggregate: &AggregateState, runtime: &RuntimeState) -> bool {
    match (
        &runtime.identity_origin,
        &runtime.target_identity,
        &runtime.relation,
    ) {
        (
            IdentityOrigin::Root {
                definition,
                root_instance_id,
            },
            Target::Root {
                root_instance_id: target_root_instance_id,
                root_runtime_id,
            },
            RuntimeRelation::Root,
        ) => {
            let expected = hash_json(serde_json::json!([
                "determa-root-runtime-identity-2",
                "1",
                definition.validated_bundle_fingerprint,
                definition.machine.namespace,
                definition.machine.machine_id,
                definition.machine.machine_version.to_string(),
                root_instance_id
            ]));
            root_instance_id == &aggregate.root_instance_id
                && target_root_instance_id == &aggregate.root_instance_id
                && root_runtime_id == &runtime.runtime_id
                && expected == runtime.runtime_id
        }
        (
            IdentityOrigin::Component {
                definition,
                owner_runtime_id,
                component_definition_pointer,
                activation_sequence,
                ..
            },
            Target::Component {
                root_instance_id,
                owner_runtime_id: target_owner_runtime_id,
                component_runtime_id,
                activation_sequence: target_activation_sequence,
                ..
            },
            RuntimeRelation::Component {
                owner_runtime_id: current_owner_runtime_id,
                activation_sequence: current_activation_sequence,
                ..
            },
        ) => {
            let expected = hash_json(serde_json::json!([
                "determa-component-runtime-identity-1",
                "1",
                aggregate.root_instance_id,
                owner_runtime_id,
                component_definition_pointer,
                activation_sequence.to_string(),
                definition.machine.namespace,
                definition.machine.machine_id,
                definition.machine.machine_version.to_string()
            ]));
            root_instance_id == &aggregate.root_instance_id
                && owner_runtime_id == target_owner_runtime_id
                && owner_runtime_id == current_owner_runtime_id
                && component_runtime_id == &runtime.runtime_id
                && activation_sequence == target_activation_sequence
                && activation_sequence == current_activation_sequence
                && expected == runtime.runtime_id
        }
        (
            IdentityOrigin::OwnedSpawnedInstance {
                definition,
                owner_runtime_id,
                spawn_action_pointer,
                spawn_sequence,
            },
            Target::SpawnedInstance(reference),
            RuntimeRelation::Spawned {
                owner_runtime_id: current_owner_runtime_id,
                spawn_sequence: current_spawn_sequence,
                reference: current_reference,
                ..
            },
        ) => {
            let expected = hash_json(serde_json::json!([
                "determa-spawned-runtime-identity-1",
                "1",
                aggregate.root_instance_id,
                owner_runtime_id,
                spawn_action_pointer,
                spawn_sequence.to_string(),
                definition.machine.namespace,
                definition.machine.machine_id,
                definition.machine.machine_version.to_string()
            ]));
            owner_runtime_id == current_owner_runtime_id
                && spawn_sequence == current_spawn_sequence
                && reference == current_reference
                && reference.root_instance_id == aggregate.root_instance_id
                && reference.instance_id == runtime.runtime_id
                && reference.machine_id == definition.machine.machine_id
                && reference.machine_version == definition.machine.machine_version
                && expected == runtime.runtime_id
        }
        _ => false,
    }
}

fn validate_prior_state_bundle_binding(state: &AggregateState, bundle: &Bundle) -> bool {
    if state.namespace != bundle.namespace {
        return false;
    }
    let Some(machine) = bundle.machines.get(&state.root.machine_id) else {
        return false;
    };
    validate_runtime_bundle_binding(&state.root, machine, bundle)
}

pub(crate) fn aggregate_is_valid_for_bundle(state: &AggregateState, bundle: &Bundle) -> bool {
    validate_prior_state(state)
        && state.validated_bundle_fingerprint == bundle.fingerprint
        && validate_prior_state_bundle_binding(state, bundle)
}

fn validate_runtime_shape(
    aggregate: &AggregateState,
    runtime: &RuntimeState,
    expected_definition: &Machine,
) -> bool {
    if runtime.runtime_id.is_empty()
        || runtime.machine_id != expected_definition.machine_id
        || runtime.machine_version != expected_definition.version
        || runtime.definition != *expected_definition
        || runtime.current_definition.machine.namespace != aggregate.namespace
        || runtime.current_definition.machine.machine_id != runtime.machine_id
        || runtime.current_definition.machine.machine_version != runtime.machine_version
        || runtime.current_definition.machine.root_definition_pointer
            != runtime.definition.root_pointer
        || runtime.current_definition.validated_bundle_fingerprint
            != aggregate.validated_bundle_fingerprint
        || runtime.machine_version <= 0
        || !validate_machine_shape(&runtime.definition)
        || !validate_runtime_identity(aggregate, runtime)
    {
        return false;
    }

    let empty_diagnostic_shape = runtime.status == RuntimeStatus::Faulted
        && runtime.active.is_empty()
        && runtime.variables.is_empty()
        && runtime.components.is_empty()
        && runtime.owned_instances.is_empty()
        && runtime.next_spawn_sequence == Counter::zero()
        && runtime.next_component_activation_sequence.is_empty()
        && runtime.next_state_activation_sequence.is_empty()
        && runtime.active_state_activation_sequence.is_empty();
    let creation_diagnostic = empty_diagnostic_shape
        && matches!(runtime.relation, RuntimeRelation::Root)
        && aggregate.next_logical_step_sequence == Counter::from(1_u64)
        && runtime
            .fault
            .as_ref()
            .is_some_and(|fault| fault.step_sequence == Counter::zero());
    let contained_initialization_diagnostic =
        empty_diagnostic_shape && !matches!(runtime.relation, RuntimeRelation::Root);
    let empty_diagnostic_history = creation_diagnostic || contained_initialization_diagnostic;
    let expected_history = runtime
        .definition
        .states
        .values()
        .filter(|state| !matches!(state.history, super::model::HistoryKind::None))
        .map(|state| state.path.as_str())
        .collect::<BTreeSet<_>>();
    if (empty_diagnostic_history && !runtime.history.is_empty())
        || (!empty_diagnostic_history
            && runtime
                .history
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
                != expected_history)
        || !runtime.history.iter().all(|(slot, value)| {
            value
                .as_ref()
                .is_none_or(|paths| validate_history_value(&runtime.definition, slot, paths))
        })
    {
        return false;
    }

    if !validate_active_configuration(runtime)
        || runtime
            .active_state_activation_sequence
            .keys()
            .collect::<BTreeSet<_>>()
            != runtime.active.iter().collect::<BTreeSet<_>>()
        || runtime
            .active_state_activation_sequence
            .iter()
            .any(|(path, sequence)| {
                runtime
                    .next_state_activation_sequence
                    .get(path)
                    .is_none_or(|next| next <= sequence)
            })
        || runtime
            .next_state_activation_sequence
            .iter()
            .any(|(path, next)| {
                !runtime.definition.states.contains_key(path) || next == &Counter::zero()
            })
        || runtime
            .next_component_activation_sequence
            .iter()
            .any(|(pointer, next)| {
                !machine_has_component_pointer(&runtime.definition, pointer)
                    || next == &Counter::zero()
            })
    {
        return false;
    }

    for (key, slot) in &runtime.variables {
        let Some(state) = runtime.definition.states.get(&slot.declaration_path) else {
            return false;
        };
        let Some(declaration) = state.variables.get(&slot.name) else {
            return false;
        };
        if key != &variable_key(&slot.declaration_path, &slot.name)
            || declaration != &slot.declaration
            || slot.declaration_pointer
                != format!(
                    "{}/variables/{}",
                    state.pointer,
                    super::source::escape_pointer(&slot.name)
                )
            || runtime
                .active_state_activation_sequence
                .get(&slot.declaration_path)
                != Some(&slot.state_activation_sequence)
            || !valid_slot_value(&slot.value, declaration)
        {
            return false;
        }
    }
    if runtime.active.iter().any(|path| {
        runtime.definition.states[path]
            .variables
            .keys()
            .any(|name| !runtime.variables.contains_key(&variable_key(path, name)))
    }) {
        return false;
    }

    match runtime.status {
        RuntimeStatus::Running if runtime.fault.is_some() => return false,
        RuntimeStatus::Completed
            if runtime.fault.is_some()
                || !runtime.active.is_empty()
                || !runtime.variables.is_empty()
                || !runtime.components.is_empty()
                || !runtime.owned_instances.is_empty() =>
        {
            return false;
        }
        RuntimeStatus::Faulted => {
            let Some(fault) = &runtime.fault else {
                return false;
            };
            if fault.runtime_id != runtime.runtime_id
                || fault.cause_id.is_empty()
                || fault.step_sequence >= aggregate.next_logical_step_sequence
                || !is_sha256(&fault.definition_fingerprint)
                || (fault.definition_fingerprint
                    == runtime.current_definition.validated_bundle_fingerprint
                    && !validate_fault_locator(runtime, &fault.code, &fault.source_locator))
                || (fault.definition_fingerprint
                    != runtime.current_definition.validated_bundle_fingerprint
                    && !validate_historical_fault(&fault.code, &fault.source_locator))
            {
                return false;
            }
        }
        _ => {}
    }

    let mut component_keys = BTreeSet::new();
    for component in &runtime.components {
        let Some((owner_state, declaration)) =
            find_component_declaration(&runtime.definition, component)
        else {
            return false;
        };
        if !component_keys.insert((
            component.pointer.as_str(),
            component.activation_sequence.clone(),
        )) || !runtime.active.contains(&owner_state.path)
            || runtime
                .next_component_activation_sequence
                .get(&component.pointer)
                .is_none_or(|next| next <= &component.activation_sequence)
        {
            return false;
        }
        let expected_definition = match &declaration.definition {
            ComponentDefinition::Machine(machine_id) => {
                if component.runtime.machine_id != *machine_id {
                    return false;
                }
                &component.runtime.definition
            }
            ComponentDefinition::Inline(machine) => machine.as_ref(),
        };
        let RuntimeRelation::Component {
            owner_runtime_id,
            owner_target,
            owner_state_path,
            component_id,
            component_pointer,
            declaration_index,
            activation_sequence,
        } = &component.runtime.relation
        else {
            return false;
        };
        if owner_runtime_id != &runtime.runtime_id
            || owner_target.as_ref() != &runtime_target(runtime, &aggregate.root_instance_id)
            || owner_state_path != &owner_state.path
            || component_id != &component.component_id
            || component_pointer != &component.pointer
            || *declaration_index != component.declaration_index
            || activation_sequence != &component.activation_sequence
            || !validate_runtime_shape(aggregate, &component.runtime, expected_definition)
        {
            return false;
        }
    }
    let expected_components = runtime
        .active
        .iter()
        .flat_map(|path| runtime.definition.states[path].components.iter())
        .map(|component| component.pointer.as_str())
        .collect::<BTreeSet<_>>();
    if runtime
        .components
        .iter()
        .map(|component| component.pointer.as_str())
        .collect::<BTreeSet<_>>()
        != expected_components
    {
        return false;
    }

    let mut spawn_sequences = BTreeSet::new();
    for owned in &runtime.owned_instances {
        if owned.runtime.status == RuntimeStatus::Completed
            || !spawn_sequences.insert(owned.spawn_sequence.clone())
            || runtime.next_spawn_sequence <= owned.spawn_sequence
            || owned.reference.root_instance_id != aggregate.root_instance_id
            || owned.reference.instance_id != owned.runtime.runtime_id
        {
            return false;
        }
        let RuntimeRelation::Spawned {
            owner_runtime_id,
            owner_target,
            spawn_sequence,
            spawn_pointer,
            reference,
            holder_path,
            holder_pointer,
            holder_activation_sequence,
        } = &owned.runtime.relation
        else {
            return false;
        };
        if owner_runtime_id != &runtime.runtime_id
            || owner_target.as_ref() != &runtime_target(runtime, &aggregate.root_instance_id)
            || spawn_sequence != &owned.spawn_sequence
            || reference != &owned.reference
            || holder_path != &owned.holder_path
            || holder_pointer != &owned.holder_pointer
            || holder_activation_sequence != &owned.holder_activation_sequence
            || find_spawn_declaration(&runtime.definition, spawn_pointer)
                .is_none_or(|machine_id| machine_id != owned.runtime.machine_id)
            || !validate_holder(runtime, owned)
            || !validate_runtime_shape(aggregate, &owned.runtime, &owned.runtime.definition)
        {
            return false;
        }
    }
    true
}

fn is_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

fn validate_historical_fault(code: &str, locator: &str) -> bool {
    matches!(
        code,
        "action_fault"
            | "binding_not_empty"
            | "cascade_fault"
            | "contained_runtime_fault"
            | "guard_fault"
            | "inactive_component_target"
            | "invalid_instance_target"
            | "invariant_fault"
    ) && (locator.starts_with('/') || locator.starts_with("system:"))
}

fn validate_active_configuration(runtime: &RuntimeState) -> bool {
    if runtime
        .active
        .iter()
        .any(|path| !runtime.definition.states.contains_key(path))
        || runtime.active.iter().any(|path| {
            let mut parent = runtime.definition.states[path].parent.as_ref();
            while let Some(path) = parent {
                if !runtime.active.contains(path) {
                    return true;
                }
                parent = runtime.definition.states[path].parent.as_ref();
            }
            false
        })
    {
        return false;
    }
    if runtime.status == RuntimeStatus::Running && !runtime.active.contains("root") {
        return false;
    }
    for path in &runtime.active {
        let state = &runtime.definition.states[path];
        if matches!(
            state.kind,
            CompiledStateKind::Choice | CompiledStateKind::Final
        ) {
            return false;
        }
        let active_children = state
            .children
            .iter()
            .filter(|child| runtime.active.contains(*child))
            .count();
        match state.kind {
            CompiledStateKind::Composite => {
                let expected_children = usize::from(!state.children.is_empty());
                if active_children != expected_children {
                    return false;
                }
            }
            _ if active_children != 0 => return false,
            _ => {}
        }
    }
    true
}

fn validate_history_value(machine: &Machine, slot: &str, paths: &[String]) -> bool {
    let Some(declaration) = machine.states.get(slot) else {
        return false;
    };
    if paths.is_empty()
        || paths.iter().collect::<BTreeSet<_>>().len() != paths.len()
        || paths.iter().any(|path| {
            !machine.states.contains_key(path)
                || !is_descendant(path, slot)
                || matches!(
                    machine.states[path].kind,
                    CompiledStateKind::Choice | CompiledStateKind::Final
                )
        })
    {
        return false;
    }
    match declaration.history {
        super::model::HistoryKind::None => false,
        super::model::HistoryKind::Shallow => {
            paths.len() == 1 && machine.states[&paths[0]].parent.as_deref() == Some(slot)
        }
        super::model::HistoryKind::Deep => paths.len() == 1,
    }
}

fn machine_has_component_pointer(machine: &Machine, pointer: &str) -> bool {
    machine
        .states
        .values()
        .flat_map(|state| state.components.iter())
        .any(|component| component.pointer == pointer)
}

fn validate_machine_shape(machine: &Machine) -> bool {
    let Some(root) = machine.states.get("root") else {
        return false;
    };
    if root.parent.is_some() || root.path != "root" || machine.root_pointer != root.pointer {
        return false;
    }
    machine.states.iter().all(|(path, state)| {
        path == &state.path
            && !state.pointer.is_empty()
            && state.parent.as_ref().is_none_or(|parent| {
                machine
                    .states
                    .get(parent)
                    .is_some_and(|state| state.children.iter().any(|child| child == path))
            })
            && state.children.iter().all(|child| {
                machine
                    .states
                    .get(child)
                    .is_some_and(|child| child.parent.as_deref() == Some(path.as_str()))
            })
    })
}

fn valid_slot_value(value: &Value, declaration: &VariableDeclaration) -> bool {
    if declaration.value_type == "instance_reference" {
        match value {
            Value::Null => declaration.nullable == Some(true),
            Value::InstanceReference(reference) => {
                reference.machine_version > 0
                    && !reference.root_instance_id.is_empty()
                    && !reference.instance_id.is_empty()
                    && !reference.machine_id.is_empty()
                    && declaration
                        .machine_id
                        .as_ref()
                        .is_none_or(|machine_id| machine_id == &reference.machine_id)
            }
            _ => false,
        }
    } else {
        value.is_canonical_portable() && value.normalize_for_type(&declaration.value_type).is_some()
    }
}

fn find_component_declaration<'a>(
    machine: &'a Machine,
    runtime: &ComponentRuntime,
) -> Option<(&'a State, &'a Component)> {
    machine.states.values().find_map(|state| {
        state
            .components
            .iter()
            .find(|component| {
                component.pointer == runtime.pointer
                    && component.component_id == runtime.component_id
                    && component.declaration_index == runtime.declaration_index
            })
            .map(|component| (state, component))
    })
}

fn find_spawn_declaration<'a>(machine: &'a Machine, pointer: &str) -> Option<&'a str> {
    machine.states.values().find_map(|state| {
        all_state_actions(state).find_map(|action| match &action.kind {
            CompiledActionKind::Spawn { machine_id, .. }
                if format!("{}/spawn", action.pointer) == pointer =>
            {
                Some(machine_id.as_str())
            }
            _ => None,
        })
    })
}

fn all_state_actions(state: &State) -> impl Iterator<Item = &CompiledAction> {
    state
        .entry
        .iter()
        .chain(state.exit.iter())
        .chain(
            state
                .initial
                .iter()
                .flat_map(|initial| initial.action.iter()),
        )
        .chain(
            state
                .handlers
                .values()
                .flatten()
                .flat_map(|transition| transition.action.iter()),
        )
        .chain(
            state
                .choice
                .iter()
                .flatten()
                .flat_map(|choice| choice.action.iter()),
        )
}

fn validate_fault_locator(runtime: &RuntimeState, code: &str, locator: &str) -> bool {
    match code {
        "contained_runtime_fault" => locator == "system:unhandled_contained_failure",
        "cascade_fault" => locator == "system:cascade_cleanup",
        "invariant_fault" => locator == "system:invariant",
        "guard_fault" => runtime.definition.states.values().any(|state| {
            state
                .handlers
                .values()
                .flatten()
                .any(|transition| transition.guard_pointer.as_deref() == Some(locator))
                || state
                    .choice
                    .iter()
                    .flatten()
                    .any(|choice| choice.guard_pointer.as_deref() == Some(locator))
        }),
        "action_fault" => runtime.definition.states.values().any(|state| {
            state.variables.iter().any(|(name, _)| {
                let pointer = format!(
                    "{}/variables/{}",
                    state.pointer,
                    super::source::escape_pointer(name)
                );
                locator == pointer || locator == format!("{pointer}/init")
            }) || state
                .components
                .iter()
                .any(|component| component_action_locator(component, locator))
                || all_state_actions(state).any(|action| action_fault_locator(action, locator))
        }),
        "invalid_instance_target" | "inactive_component_target" => runtime
            .definition
            .states
            .values()
            .flat_map(all_state_actions)
            .any(|action| send_target_locator(action, locator)),
        "binding_not_empty" => runtime
            .definition
            .states
            .values()
            .flat_map(all_state_actions)
            .any(|action| {
                matches!(
                    action.kind,
                    CompiledActionKind::Spawn {
                        bind_to: Some(_),
                        ..
                    }
                ) && locator == format!("{}/spawn/bind_to", action.pointer)
            }),
        _ => false,
    }
}

fn component_action_locator(component: &Component, locator: &str) -> bool {
    if locator == format!("{}/with", component.pointer) {
        return true;
    }
    for (kind, bindings) in [
        ("input", &component.bindings.input),
        ("external", &component.bindings.external),
    ] {
        if bindings.keys().any(|name| {
            locator
                == format!(
                    "{}/with/{kind}/{}",
                    component.pointer,
                    super::source::escape_pointer(name)
                )
        }) {
            return true;
        }
    }
    false
}

fn action_fault_locator(action: &CompiledAction, locator: &str) -> bool {
    match &action.kind {
        CompiledActionKind::Assign { variable, .. } => {
            locator
                == format!(
                    "{}/assign/{}",
                    action.pointer,
                    super::source::escape_pointer(variable)
                )
        }
        CompiledActionKind::Send {
            targets,
            payload,
            correlation_id,
            ..
        } => {
            payload.keys().any(|name| {
                locator
                    == format!(
                        "{}/send/payload/{}",
                        action.pointer,
                        super::source::escape_pointer(name)
                    )
            }) || locator == format!("{}/send/payload", action.pointer)
                || correlation_id
                    .as_ref()
                    .is_some_and(|_| locator == format!("{}/send/correlation_id", action.pointer))
                || targets.iter().enumerate().any(|(index, target)| {
                    matches!(target, CompiledSendTarget::Instance(_))
                        && locator == target_expression_pointer(action, targets, index)
                })
        }
        CompiledActionKind::Refresh { only } => {
            locator == format!("{}/refresh", action.pointer)
                || only.as_ref().is_some_and(|only| {
                    only.iter().enumerate().any(|(index, _)| {
                        locator == format!("{}/refresh/only/{index}", action.pointer)
                    })
                })
        }
        CompiledActionKind::Spawn { bindings, .. } => {
            if locator == format!("{}/spawn/bindings", action.pointer) {
                return true;
            }
            for (kind, values) in [("input", &bindings.input), ("external", &bindings.external)] {
                if values.keys().any(|name| {
                    locator
                        == format!(
                            "{}/spawn/bindings/{kind}/{}",
                            action.pointer,
                            super::source::escape_pointer(name)
                        )
                }) {
                    return true;
                }
            }
            false
        }
        CompiledActionKind::Cancel { .. } => {
            locator == format!("{}/cancel/instance", action.pointer)
        }
        CompiledActionKind::Stop => false,
    }
}

fn send_target_locator(action: &CompiledAction, locator: &str) -> bool {
    let CompiledActionKind::Send { targets, .. } = &action.kind else {
        return false;
    };
    targets.iter().enumerate().any(|(index, target)| {
        let base = if targets.len() == 1 {
            format!("{}/send/to", action.pointer)
        } else {
            format!("{}/send/targets/{index}", action.pointer)
        };
        locator == base
            || (matches!(target, CompiledSendTarget::Instance(_))
                && locator == format!("{base}/instance"))
    })
}

fn validate_holder(owner: &RuntimeState, owned: &OwnedRuntime) -> bool {
    match (
        &owned.holder_path,
        &owned.holder_pointer,
        &owned.runtime.relation,
    ) {
        (
            Some(path),
            Some(pointer),
            RuntimeRelation::Spawned {
                holder_activation_sequence,
                ..
            },
        ) => owner.variables.values().any(|slot| {
            &slot.declaration_path == path
                && &slot.declaration_pointer == pointer
                && &slot.state_activation_sequence == holder_activation_sequence
        }),
        (None, None, RuntimeRelation::Spawned { .. }) => true,
        _ => false,
    }
}

fn validate_runtime_bundle_binding(
    runtime: &RuntimeState,
    expected: &Machine,
    bundle: &Bundle,
) -> bool {
    if runtime.definition != *expected {
        return false;
    }
    for component in &runtime.components {
        let Some((_, declaration)) = find_component_declaration(expected, component) else {
            return false;
        };
        let target = match &declaration.definition {
            ComponentDefinition::Machine(machine_id) => {
                let Some(machine) = bundle.machines.get(machine_id) else {
                    return false;
                };
                machine
            }
            ComponentDefinition::Inline(machine) => machine,
        };
        if !validate_runtime_bundle_binding(&component.runtime, target, bundle) {
            return false;
        }
    }
    for owned in &runtime.owned_instances {
        let RuntimeRelation::Spawned { spawn_pointer, .. } = &owned.runtime.relation else {
            return false;
        };
        let Some(machine_id) = find_spawn_declaration(expected, spawn_pointer) else {
            return false;
        };
        let Some(target) = bundle.machines.get(machine_id) else {
            return false;
        };
        if !validate_runtime_bundle_binding(&owned.runtime, target, bundle) {
            return false;
        }
    }
    true
}

fn initialize_root_variables(runtime: &mut RuntimeState, bindings: &Bindings) -> Result<(), ()> {
    let input = root_input_variables(&runtime.definition);
    let external = root_external_variables(&runtime.definition);
    if bindings.input.keys().any(|key| !input.contains_key(key))
        || bindings
            .external
            .keys()
            .any(|key| !external.contains_key(key))
    {
        return Err(());
    }
    for (name, declaration) in input.iter().chain(external.iter()) {
        let supplied = if declaration.input {
            bindings.input.get(name)
        } else {
            bindings.external.get(name)
        };
        if let Some(value) = supplied {
            if value.normalize_for_type(&declaration.value_type).is_none() {
                return Err(());
            }
        } else if declaration.init.is_none() {
            return Err(());
        }
    }
    Ok(())
}

fn resolve_delivery_target(
    aggregate: &AggregateState,
    target: &Target,
) -> Result<RuntimeAddress, &'static str> {
    match target {
        Target::Root {
            root_instance_id,
            root_runtime_id,
        } if root_instance_id == &aggregate.root_instance_id
            && root_runtime_id == &aggregate.root.runtime_id =>
        {
            Ok(Vec::new())
        }
        Target::SpawnedInstance(reference) => {
            find_spawn_address(&aggregate.root, reference).ok_or("invalid_instance_target")
        }
        Target::Component {
            root_instance_id,
            owner_runtime_id,
            component_id,
            component_runtime_id,
            activation_sequence,
        } if root_instance_id == &aggregate.root_instance_id => find_component_address(
            &aggregate.root,
            owner_runtime_id,
            component_id,
            component_runtime_id,
            activation_sequence,
        )
        .ok_or("inactive_component_target"),
        Target::Component { .. } => Err("inactive_component_target"),
        _ => Err("invalid_instance_target"),
    }
}

fn runtime_at<'a>(
    runtime: &'a RuntimeState,
    address: &[AddressSegment],
) -> Option<&'a RuntimeState> {
    let Some((head, tail)) = address.split_first() else {
        return Some(runtime);
    };
    match head {
        AddressSegment::Component(component_id, activation_sequence) => runtime
            .components
            .iter()
            .find(|component| {
                &component.component_id == component_id
                    && &component.activation_sequence == activation_sequence
            })
            .and_then(|component| runtime_at(&component.runtime, tail)),
        AddressSegment::Spawn(spawn_sequence) => runtime
            .owned_instances
            .iter()
            .find(|owned| &owned.spawn_sequence == spawn_sequence)
            .and_then(|owned| runtime_at(&owned.runtime, tail)),
    }
}

fn runtime_at_mut<'a>(
    runtime: &'a mut RuntimeState,
    address: &[AddressSegment],
) -> Option<&'a mut RuntimeState> {
    let Some((head, tail)) = address.split_first() else {
        return Some(runtime);
    };
    match head {
        AddressSegment::Component(component_id, activation_sequence) => runtime
            .components
            .iter_mut()
            .find(|component| {
                &component.component_id == component_id
                    && &component.activation_sequence == activation_sequence
            })
            .and_then(|component| runtime_at_mut(&mut component.runtime, tail)),
        AddressSegment::Spawn(spawn_sequence) => runtime
            .owned_instances
            .iter_mut()
            .find(|owned| &owned.spawn_sequence == spawn_sequence)
            .and_then(|owned| runtime_at_mut(&mut owned.runtime, tail)),
    }
}

fn find_spawn_address(
    runtime: &RuntimeState,
    reference: &InstanceReference,
) -> Option<RuntimeAddress> {
    if runtime.status != RuntimeStatus::Running {
        return None;
    }
    for owned in &runtime.owned_instances {
        if owned.reference == *reference {
            return Some(vec![AddressSegment::Spawn(owned.spawn_sequence.clone())]);
        }
        if let Some(mut nested) = find_spawn_address(&owned.runtime, reference) {
            let mut address = vec![AddressSegment::Spawn(owned.spawn_sequence.clone())];
            address.append(&mut nested);
            return Some(address);
        }
    }
    for component in &runtime.components {
        if let Some(mut nested) = find_spawn_address(&component.runtime, reference) {
            let mut address = vec![AddressSegment::Component(
                component.component_id.clone(),
                component.activation_sequence.clone(),
            )];
            address.append(&mut nested);
            return Some(address);
        }
    }
    None
}

fn find_component_address(
    runtime: &RuntimeState,
    owner_runtime_id: &str,
    component_id: &str,
    component_runtime_id: &str,
    activation_sequence: &Counter,
) -> Option<RuntimeAddress> {
    if runtime.status != RuntimeStatus::Running {
        return None;
    }
    if runtime.runtime_id == owner_runtime_id {
        let component = runtime.components.iter().find(|component| {
            component.component_id == component_id
                && &component.activation_sequence == activation_sequence
                && component.runtime.runtime_id == component_runtime_id
        })?;
        return Some(vec![AddressSegment::Component(
            component.component_id.clone(),
            component.activation_sequence.clone(),
        )]);
    }
    for component in &runtime.components {
        if let Some(mut nested) = find_component_address(
            &component.runtime,
            owner_runtime_id,
            component_id,
            component_runtime_id,
            activation_sequence,
        ) {
            let mut address = vec![AddressSegment::Component(
                component.component_id.clone(),
                component.activation_sequence.clone(),
            )];
            address.append(&mut nested);
            return Some(address);
        }
    }
    for owned in &runtime.owned_instances {
        if let Some(mut nested) = find_component_address(
            &owned.runtime,
            owner_runtime_id,
            component_id,
            component_runtime_id,
            activation_sequence,
        ) {
            let mut address = vec![AddressSegment::Spawn(owned.spawn_sequence.clone())];
            address.append(&mut nested);
            return Some(address);
        }
    }
    None
}

fn root_runtime_identity(bundle: &Bundle, machine: &Machine, root_instance_id: &str) -> String {
    root_runtime_identity_parts(
        &bundle.fingerprint,
        &bundle.namespace,
        machine,
        root_instance_id,
    )
}

fn definition_binding(bundle: &Bundle, machine: &Machine) -> DefinitionBinding {
    DefinitionBinding {
        validated_bundle_fingerprint: bundle.fingerprint.clone(),
        machine: MachineIdentity {
            namespace: bundle.namespace.clone(),
            machine_id: machine.machine_id.clone(),
            machine_version: machine.version,
            root_definition_pointer: machine.root_pointer.clone(),
        },
    }
}

fn root_runtime_identity_parts(
    fingerprint: &str,
    namespace: &str,
    machine: &Machine,
    root_instance_id: &str,
) -> String {
    hash_json(serde_json::json!([
        "determa-root-runtime-identity-2",
        "1",
        fingerprint,
        namespace,
        machine.machine_id,
        machine.version.to_string(),
        root_instance_id
    ]))
}

#[allow(clippy::too_many_arguments)]
fn initialization_cause(
    cause_kind: &str,
    root_instance_id: &str,
    source_runtime_id: &str,
    target_runtime_id: &str,
    parent_provenance: &str,
    step_sequence: &Counter,
    source_locator: &str,
    ordinal: &Counter,
) -> String {
    hash_json(serde_json::json!([
        "determa-cause-identity-1",
        "1",
        cause_kind,
        root_instance_id,
        source_runtime_id,
        target_runtime_id,
        parent_provenance,
        step_sequence.to_string(),
        source_locator,
        ordinal.to_string()
    ]))
}

fn internal_event_identity(
    root_instance_id: &str,
    source_runtime_id: &str,
    target_runtime_id: &str,
    cause_id: &str,
    step_sequence: &Counter,
    locator: &str,
    ordinal: usize,
) -> String {
    hash_json(serde_json::json!([
        "determa-event-identity-1",
        "1",
        root_instance_id,
        source_runtime_id,
        target_runtime_id,
        cause_id,
        step_sequence.to_string(),
        locator,
        ordinal.to_string()
    ]))
}

fn external_effect_identity(
    bundle: &Bundle,
    runtime: &RuntimeState,
    root_instance_id: &str,
    cause_id: &str,
    step_sequence: &Counter,
    locator: &str,
    ordinal: usize,
) -> String {
    hash_json(serde_json::json!([
        "determa-effect-identity-1",
        "1",
        [
            bundle.namespace,
            runtime.machine_id,
            runtime.machine_version.to_string()
        ],
        root_instance_id,
        runtime.runtime_id,
        cause_id,
        step_sequence.to_string(),
        locator,
        ordinal.to_string()
    ]))
}

fn component_runtime_identity(
    bundle: &Bundle,
    root_instance_id: &str,
    owner_runtime_id: &str,
    component: &Component,
    activation_sequence: &Counter,
    machine: &Machine,
) -> String {
    component_runtime_identity_parts(
        &bundle.namespace,
        root_instance_id,
        owner_runtime_id,
        component,
        activation_sequence,
        machine,
    )
}

fn component_runtime_identity_parts(
    namespace: &str,
    root_instance_id: &str,
    owner_runtime_id: &str,
    component: &Component,
    activation_sequence: &Counter,
    machine: &Machine,
) -> String {
    hash_json(serde_json::json!([
        "determa-component-runtime-identity-1",
        "1",
        root_instance_id,
        owner_runtime_id,
        component.pointer,
        activation_sequence.to_string(),
        namespace,
        machine.machine_id,
        machine.version.to_string()
    ]))
}

fn spawned_runtime_identity(
    bundle: &Bundle,
    root_instance_id: &str,
    owner_runtime_id: &str,
    spawn_pointer: &str,
    spawn_sequence: &Counter,
    machine: &Machine,
) -> String {
    spawned_runtime_identity_parts(
        &bundle.namespace,
        root_instance_id,
        owner_runtime_id,
        spawn_pointer,
        spawn_sequence,
        machine,
    )
}

fn spawned_runtime_identity_parts(
    namespace: &str,
    root_instance_id: &str,
    owner_runtime_id: &str,
    spawn_pointer: &str,
    spawn_sequence: &Counter,
    machine: &Machine,
) -> String {
    hash_json(serde_json::json!([
        "determa-spawned-runtime-identity-1",
        "1",
        root_instance_id,
        owner_runtime_id,
        spawn_pointer,
        spawn_sequence.to_string(),
        namespace,
        machine.machine_id,
        machine.version.to_string()
    ]))
}

fn is_descendant(path: &str, ancestor: &str) -> bool {
    ancestor == "root" && path != "root"
        || path
            .strip_prefix(ancestor)
            .is_some_and(|suffix| suffix.starts_with('.'))
}

fn validate_envelope(
    bundle: &Bundle,
    runtime: &RuntimeState,
    mode: DeliveryMode,
    envelope: &Envelope,
) -> Result<Envelope, &'static str> {
    if envelope.event_id.is_empty() {
        return Err("invalid_event");
    }
    let declaration = runtime
        .definition
        .events
        .get(&envelope.event)
        .or_else(|| bundle.events.get(&envelope.event));
    match envelope.event.as_str() {
        "env" => {
            match mode {
                DeliveryMode::Input
                    if matches!(
                        envelope.target,
                        Target::Root { .. } | Target::SpawnedInstance(_)
                    ) => {}
                DeliveryMode::Input => return Err("invalid_instance_target"),
                DeliveryMode::Internal if matches!(envelope.target, Target::Component { .. }) => {}
                DeliveryMode::Internal => return Err("invalid_event"),
            }
            if envelope.correlation_id.is_some() {
                return Err("invalid_correlation");
            }
            let Some(Value::Map(changed)) = envelope.payload.get("changed") else {
                return Err("invalid_payload");
            };
            if envelope.payload.len() != 1 || changed.is_empty() {
                return Err("invalid_payload");
            }
            let external = root_external_variables(&runtime.definition);
            let mut normalized = BTreeMap::new();
            for (name, value) in changed {
                let Some(declaration) = external.get(name) else {
                    return Err("invalid_payload");
                };
                let value = value
                    .normalize_for_type(&declaration.value_type)
                    .ok_or("invalid_payload")?;
                normalized.insert(name.clone(), value);
            }
            return Ok(Envelope {
                payload: BTreeMap::from([("changed".to_string(), Value::Map(normalized))]),
                ..envelope.clone()
            });
        }
        "done"
        | "determa.component_completed"
        | "determa.component_failed"
        | "determa.spawned_instance_failed" => {
            if matches!(mode, DeliveryMode::Input) {
                return Err("invalid_event");
            }
            if envelope.correlation_id.is_some() {
                return Err("invalid_correlation");
            }
            validate_reserved_lifecycle_payload(&envelope.event, &envelope.payload)
                .map_err(|_| "invalid_payload")?;
            return Ok(envelope.clone());
        }
        _ => {}
    }
    let Some(declaration) = declaration else {
        return Err("invalid_event");
    };
    match (mode, declaration.direction) {
        (DeliveryMode::Input, EventDirection::Input)
            if matches!(
                envelope.target,
                Target::Root { .. } | Target::SpawnedInstance(_)
            ) => {}
        (DeliveryMode::Internal, EventDirection::Internal) => {}
        (DeliveryMode::Input, _) | (DeliveryMode::Internal, _) => {
            return Err("invalid_event");
        }
    }
    if envelope
        .correlation_id
        .as_ref()
        .is_some_and(String::is_empty)
        || declaration.correlates_to.is_some() && envelope.correlation_id.is_none()
    {
        return Err("invalid_correlation");
    }
    let payload =
        normalize_payload(declaration, &envelope.payload).map_err(|_| "invalid_payload")?;
    Ok(Envelope {
        payload,
        ..envelope.clone()
    })
}

fn normalize_payload(
    declaration: &EventDeclaration,
    supplied: &BTreeMap<String, Value>,
) -> Result<BTreeMap<String, Value>, ()> {
    if supplied
        .keys()
        .any(|name| !declaration.payload.contains_key(name))
    {
        return Err(());
    }
    let mut normalized = BTreeMap::new();
    for (name, field) in &declaration.payload {
        if let Some(value) = supplied.get(name) {
            let value = value.normalize_for_type(&field.value_type).ok_or(())?;
            normalized.insert(name.clone(), value);
        } else if let Some(default) = &field.default {
            normalized.insert(
                name.clone(),
                default.normalize_for_type(&field.value_type).ok_or(())?,
            );
        } else if field.required {
            return Err(());
        }
    }
    Ok(normalized)
}

fn validate_reserved_lifecycle_payload(
    event: &str,
    payload: &BTreeMap<String, Value>,
) -> Result<(), ()> {
    match event {
        "determa.component_completed" => {
            require_exact_keys(payload, &["component_id", "component_runtime_id"])?;
            require_identifier(payload.get("component_id"))?;
            require_non_empty_string(payload.get("component_runtime_id"))?;
        }
        "determa.component_failed" => {
            require_exact_keys(payload, &["component_id", "component_runtime_id", "fault"])?;
            require_identifier(payload.get("component_id"))?;
            require_non_empty_string(payload.get("component_runtime_id"))?;
            validate_public_fault(payload.get("fault"))?;
        }
        "determa.spawned_instance_failed" => {
            require_exact_keys(
                payload,
                &[
                    "instance",
                    "instance_id",
                    "machine_id",
                    "machine_version",
                    "fault",
                ],
            )?;
            let reference = require_instance_reference(payload.get("instance"))?;
            if payload.get("instance_id") != Some(&Value::String(reference.instance_id.clone()))
                || payload.get("machine_id") != Some(&Value::String(reference.machine_id.clone()))
                || payload.get("machine_version") != Some(&Value::Int(reference.machine_version))
            {
                return Err(());
            }
            validate_public_fault(payload.get("fault"))?;
        }
        "done" => match payload.get("relationship") {
            Some(Value::String(relationship)) if relationship == "parallel" => {
                require_exact_keys(payload, &["relationship", "state_path", "owner_runtime_id"])?;
                require_state_path(payload.get("state_path"))?;
                require_non_empty_string(payload.get("owner_runtime_id"))?;
            }
            Some(Value::String(relationship)) if relationship == "spawned_instance" => {
                require_exact_keys(
                    payload,
                    &[
                        "relationship",
                        "instance",
                        "instance_id",
                        "machine_id",
                        "machine_version",
                    ],
                )?;
                let reference = require_instance_reference(payload.get("instance"))?;
                if payload.get("instance_id") != Some(&Value::String(reference.instance_id.clone()))
                    || payload.get("machine_id")
                        != Some(&Value::String(reference.machine_id.clone()))
                    || payload.get("machine_version")
                        != Some(&Value::Int(reference.machine_version))
                {
                    return Err(());
                }
            }
            _ => return Err(()),
        },
        _ => return Err(()),
    }
    Ok(())
}

fn require_exact_keys(payload: &BTreeMap<String, Value>, keys: &[&str]) -> Result<(), ()> {
    if payload.len() != keys.len() || keys.iter().any(|key| !payload.contains_key(*key)) {
        return Err(());
    }
    Ok(())
}

fn require_non_empty_string(value: Option<&Value>) -> Result<&str, ()> {
    match value {
        Some(Value::String(value)) if !value.is_empty() => Ok(value),
        _ => Err(()),
    }
}

fn require_identifier(value: Option<&Value>) -> Result<&str, ()> {
    let value = require_non_empty_string(value)?;
    if !is_identifier(value) {
        return Err(());
    }
    Ok(value)
}

fn is_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn require_state_path(value: Option<&Value>) -> Result<(), ()> {
    let value = require_non_empty_string(value)?;
    if value.split('.').all(|part| {
        let mut bytes = part.bytes();
        bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
            && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    }) {
        Ok(())
    } else {
        Err(())
    }
}

fn require_instance_reference(value: Option<&Value>) -> Result<&InstanceReference, ()> {
    let Some(Value::InstanceReference(reference)) = value else {
        return Err(());
    };
    if reference.root_instance_id.is_empty()
        || reference.instance_id.is_empty()
        || !is_identifier(&reference.machine_id)
        || reference.machine_version <= 0
    {
        return Err(());
    }
    Ok(reference)
}

fn validate_public_fault(value: Option<&Value>) -> Result<(), ()> {
    let Some(Value::Map(fault)) = value else {
        return Err(());
    };
    require_exact_keys(
        fault,
        &[
            "runtime_id",
            "cause_id",
            "code",
            "step_sequence",
            "source_locator",
        ],
    )?;
    require_non_empty_string(fault.get("runtime_id"))?;
    require_non_empty_string(fault.get("cause_id"))?;
    require_non_empty_string(fault.get("code"))?;
    require_non_empty_string(fault.get("source_locator"))?;
    let step_sequence = require_non_empty_string(fault.get("step_sequence"))?;
    Counter::from_decimal(step_sequence).map_err(|_| ())?;
    Ok(())
}

fn select_handler(
    runtime: &RuntimeState,
    envelope: &Envelope,
) -> Result<Option<(String, CompiledTransition)>, StepFault> {
    let mut candidates = runtime.config();
    if candidates.is_empty() && runtime.active.contains("root") {
        candidates.push("root".to_string());
    }
    candidates.sort_by_key(|path| std::cmp::Reverse(path_depth(path)));
    let mut visited = BTreeSet::new();
    for leaf in candidates {
        let mut current = Some(leaf);
        while let Some(path) = current {
            if !visited.insert(path.clone()) {
                current = runtime.definition.states[&path].parent.clone();
                continue;
            }
            let state = &runtime.definition.states[&path];
            if let Some(transitions) = state.handlers.get(&envelope.event) {
                let environment = action_environment(runtime, &path, Some(envelope));
                for transition in transitions {
                    if let Some(guard) = &transition.guard {
                        match cel::evaluate_boolean(guard, &environment) {
                            Ok(true) => return Ok(Some((path, transition.clone()))),
                            Ok(false) => continue,
                            Err(_) => {
                                return Err(StepFault {
                                    code: "guard_fault",
                                    source_locator: transition
                                        .guard_pointer
                                        .clone()
                                        .expect("guard pointer"),
                                })
                            }
                        }
                    } else {
                        return Ok(Some((path, transition.clone())));
                    }
                }
            }
            current = state.parent.clone();
        }
    }
    Ok(None)
}

fn initialize_runtime(
    runtime: &mut RuntimeState,
    bindings: &Bindings,
    context: &mut StepContext<'_>,
    root_variables_prevalidated: bool,
) -> Result<(), StepFault> {
    enter_state(
        runtime,
        "root",
        bindings,
        None,
        context,
        root_variables_prevalidated,
    )?;
    if runtime.status == RuntimeStatus::Completed {
        return Ok(());
    }
    descend_initial(runtime, "root", context)?;
    if runtime
        .config()
        .iter()
        .any(|path| runtime.definition.states[path].kind == CompiledStateKind::Final)
    {
        complete_runtime(runtime, context)?;
    }
    Ok(())
}

fn execute_transition(
    runtime: &mut RuntimeState,
    source_path: &str,
    transition: &CompiledTransition,
    envelope: &Envelope,
    context: &mut StepContext<'_>,
) -> Result<(), StepFault> {
    run_actions(
        runtime,
        source_path,
        &transition.action,
        Some(envelope),
        context,
    )?;
    if runtime.status == RuntimeStatus::Completed {
        return Ok(());
    }
    let Some(target) = &transition.target else {
        return Ok(());
    };
    let (target, history) = resolve_choice_chain(runtime, target.clone(), envelope, context)?;
    if runtime.status == RuntimeStatus::Completed {
        return Ok(());
    }
    perform_transition(
        runtime,
        source_path,
        &target,
        history,
        transition.local,
        context,
    )?;
    if runtime
        .config()
        .iter()
        .any(|path| runtime.definition.states[path].kind == CompiledStateKind::Final)
    {
        complete_runtime(runtime, context)?;
    }
    Ok(())
}

fn resolve_choice_chain(
    runtime: &mut RuntimeState,
    mut target: CompiledTarget,
    envelope: &Envelope,
    context: &mut StepContext<'_>,
) -> Result<(String, bool), StepFault> {
    let mut history = matches!(target, CompiledTarget::History(_));
    loop {
        let path = match &target {
            CompiledTarget::State(path) | CompiledTarget::History(path) => path.clone(),
        };
        let Some(branches) = runtime.definition.states[&path].choice.clone() else {
            return Ok((path, history));
        };
        let mut selected = None;
        for branch in branches {
            if choice_enabled(runtime, &path, &branch, envelope)? {
                selected = Some(branch);
                break;
            }
        }
        let branch = selected.expect("validated choice has a default");
        run_actions(runtime, &path, &branch.action, Some(envelope), context)?;
        if runtime.status == RuntimeStatus::Completed {
            return Ok((path, false));
        }
        target = branch.target;
        history = matches!(target, CompiledTarget::History(_));
    }
}

fn choice_enabled(
    runtime: &RuntimeState,
    scope: &str,
    branch: &CompiledChoice,
    envelope: &Envelope,
) -> Result<bool, StepFault> {
    let Some(guard) = &branch.guard else {
        return Ok(true);
    };
    cel::evaluate_boolean(guard, &action_environment(runtime, scope, Some(envelope))).map_err(
        |_| StepFault {
            code: "guard_fault",
            source_locator: branch.guard_pointer.clone().expect("guard pointer"),
        },
    )
}

fn perform_transition(
    runtime: &mut RuntimeState,
    source_path: &str,
    target_path: &str,
    history: bool,
    local: bool,
    context: &mut StepContext<'_>,
) -> Result<(), StepFault> {
    let boundary = if source_path == target_path {
        runtime.definition.states[source_path]
            .parent
            .clone()
            .expect("root self-transitions are rejected during loading")
    } else if is_descendant(target_path, source_path) {
        if source_path == "root" || local {
            source_path.to_string()
        } else {
            runtime.definition.states[source_path]
                .parent
                .clone()
                .expect("non-root source has a parent")
        }
    } else if is_descendant(source_path, target_path) {
        target_path.to_string()
    } else {
        lowest_common_ancestor(&runtime.definition, source_path, target_path)
    };
    let mut exits = runtime
        .active
        .iter()
        .filter(|path| path.as_str() != boundary && is_descendant(path, &boundary))
        .cloned()
        .collect::<Vec<_>>();
    for path in &exits {
        let state = runtime.definition.states[path].clone();
        capture_history(runtime, &state);
    }
    exits.sort_by_key(|path| std::cmp::Reverse(path_depth(path)));
    for path in exits {
        exit_state(runtime, &path, context)?;
    }
    let mut entry_chain = ancestors_to_root(&runtime.definition, target_path);
    entry_chain.reverse();
    for path in entry_chain {
        if path == boundary {
            continue;
        }
        if runtime.active.contains(&path) {
            continue;
        }
        enter_state(runtime, &path, &Bindings::default(), None, context, false)?;
        if runtime.status == RuntimeStatus::Completed {
            return Ok(());
        }
    }
    if history {
        restore_history(runtime, target_path, context)?;
    } else {
        descend_initial(runtime, target_path, context)?;
    }
    Ok(())
}

fn enter_state(
    runtime: &mut RuntimeState,
    path: &str,
    bindings: &Bindings,
    _owner_variables: Option<&BTreeMap<String, Value>>,
    context: &mut StepContext<'_>,
    root_variables_prevalidated: bool,
) -> Result<(), StepFault> {
    let state = runtime.definition.states[path].clone();
    let activation_sequence = runtime
        .next_state_activation_sequence
        .entry(path.to_string())
        .or_default();
    let allocated_activation = activation_sequence.allocate();
    runtime
        .active_state_activation_sequence
        .insert(path.to_string(), allocated_activation.clone());
    runtime.active.insert(path.to_string());

    if state.kind == CompiledStateKind::Parallel {
        allocate_components(runtime, &state, context)?;
    }
    initialize_state_variables(
        runtime,
        &state,
        bindings,
        allocated_activation.clone(),
        root_variables_prevalidated,
    )?;
    run_actions(runtime, path, &state.entry, None, context)?;
    if runtime.status == RuntimeStatus::Completed {
        return Ok(());
    }
    if state.kind == CompiledStateKind::Parallel {
        initialize_components(runtime, &state, context)?;
    }
    Ok(())
}

fn initialize_state_variables(
    runtime: &mut RuntimeState,
    state: &State,
    bindings: &Bindings,
    state_activation_sequence: Counter,
    root_variables_prevalidated: bool,
) -> Result<(), StepFault> {
    for (name, declaration) in &state.variables {
        let supplied = if state.path == "root" && declaration.input {
            bindings.input.get(name)
        } else if state.path == "root" && declaration.external {
            bindings.external.get(name)
        } else {
            None
        };
        let value = supplied
            .cloned()
            .or_else(|| {
                declaration
                    .init
                    .clone()
                    .map(|value| value.unwrap_or(Value::Null))
            })
            .ok_or_else(|| StepFault {
                code: "action_fault",
                source_locator: format!(
                    "{}/variables/{}",
                    state.pointer,
                    super::source::escape_pointer(name)
                ),
            })?;
        let value = if declaration.value_type == "instance_reference" && value == Value::Null {
            Value::Null
        } else {
            value
                .normalize_for_type(&declaration.value_type)
                .ok_or_else(|| StepFault {
                    code: "action_fault",
                    source_locator: format!(
                        "{}/variables/{}/init",
                        state.pointer,
                        super::source::escape_pointer(name)
                    ),
                })?
        };
        let key = variable_key(&state.path, name);
        runtime.variables.insert(
            key,
            VariableSlot {
                name: name.clone(),
                declaration_path: state.path.clone(),
                declaration_pointer: format!(
                    "{}/variables/{}",
                    state.pointer,
                    super::source::escape_pointer(name)
                ),
                declaration: declaration.clone(),
                value,
                state_activation_sequence: state_activation_sequence.clone(),
            },
        );
    }
    let _ = root_variables_prevalidated;
    Ok(())
}

fn descend_initial(
    runtime: &mut RuntimeState,
    start_path: &str,
    context: &mut StepContext<'_>,
) -> Result<(), StepFault> {
    let mut current = start_path.to_string();
    loop {
        let state = runtime.definition.states[&current].clone();
        if state.kind != CompiledStateKind::Composite {
            return Ok(());
        }
        let initial = state.initial.expect("validated composite initial");
        run_actions(runtime, &current, &initial.action, None, context)?;
        if runtime.status == RuntimeStatus::Completed {
            return Ok(());
        }
        let target = initial.target;
        let mut chain = ancestors_to_root(&runtime.definition, &target);
        chain.reverse();
        for path in chain {
            if runtime.active.contains(&path) {
                continue;
            }
            enter_state(runtime, &path, &Bindings::default(), None, context, false)?;
            if runtime.status == RuntimeStatus::Completed {
                return Ok(());
            }
        }
        current = target;
    }
}

fn restore_history(
    runtime: &mut RuntimeState,
    composite_path: &str,
    context: &mut StepContext<'_>,
) -> Result<(), StepFault> {
    let state = runtime.definition.states[composite_path].clone();
    let record = runtime.history.get(composite_path).cloned().flatten();
    let Some(record) = record else {
        return descend_initial(runtime, composite_path, context);
    };
    match state.history {
        super::model::HistoryKind::Shallow => {
            if let Some(direct) = record.first() {
                enter_path_and_descend(runtime, direct, context)
            } else {
                descend_initial(runtime, composite_path, context)
            }
        }
        super::model::HistoryKind::Deep => {
            for leaf in record {
                let mut chain = ancestors_to_root(&runtime.definition, &leaf);
                chain.reverse();
                for path in chain {
                    if !runtime.active.contains(&path) {
                        enter_state(runtime, &path, &Bindings::default(), None, context, false)?;
                    }
                }
            }
            Ok(())
        }
        super::model::HistoryKind::None => descend_initial(runtime, composite_path, context),
    }
}

fn enter_path_and_descend(
    runtime: &mut RuntimeState,
    target: &str,
    context: &mut StepContext<'_>,
) -> Result<(), StepFault> {
    let mut chain = ancestors_to_root(&runtime.definition, target);
    chain.reverse();
    for path in chain {
        if !runtime.active.contains(&path) {
            enter_state(runtime, &path, &Bindings::default(), None, context, false)?;
        }
    }
    descend_initial(runtime, target, context)
}

fn run_actions(
    runtime: &mut RuntimeState,
    scope: &str,
    actions: &[CompiledAction],
    envelope: Option<&Envelope>,
    context: &mut StepContext<'_>,
) -> Result<(), StepFault> {
    for action in actions {
        match &action.kind {
            CompiledActionKind::Assign {
                variable,
                expression,
            } => {
                let environment = action_environment(runtime, scope, envelope);
                let value = cel::evaluate(expression, &environment).map_err(|_| StepFault {
                    code: "action_fault",
                    source_locator: format!(
                        "{}/assign/{}",
                        action.pointer,
                        super::source::escape_pointer(variable)
                    ),
                })?;
                let key =
                    resolve_variable_key(runtime, scope, variable).ok_or_else(|| StepFault {
                        code: "action_fault",
                        source_locator: format!(
                            "{}/assign/{}",
                            action.pointer,
                            super::source::escape_pointer(variable)
                        ),
                    })?;
                let slot = runtime.variables.get_mut(&key).expect("resolved variable");
                if slot.declaration.external {
                    return Err(StepFault {
                        code: "action_fault",
                        source_locator: format!(
                            "{}/assign/{}",
                            action.pointer,
                            super::source::escape_pointer(variable)
                        ),
                    });
                }
                let normalized = if slot.declaration.value_type == "instance_reference" {
                    match value {
                        Value::Null | Value::InstanceReference(_) => value,
                        _ => {
                            return Err(StepFault {
                                code: "action_fault",
                                source_locator: format!(
                                    "{}/assign/{}",
                                    action.pointer,
                                    super::source::escape_pointer(variable)
                                ),
                            })
                        }
                    }
                } else {
                    value
                        .normalize_for_type(&slot.declaration.value_type)
                        .ok_or_else(|| StepFault {
                            code: "action_fault",
                            source_locator: format!(
                                "{}/assign/{}",
                                action.pointer,
                                super::source::escape_pointer(variable)
                            ),
                        })?
                };
                slot.value = normalized;
            }
            CompiledActionKind::Send {
                event,
                targets,
                payload,
                correlation_id,
            } => execute_send(
                runtime,
                scope,
                envelope,
                action,
                event,
                targets,
                payload,
                correlation_id,
                context,
            )?,
            CompiledActionKind::Refresh { only } => {
                let Some(envelope) = envelope.filter(|envelope| envelope.event == "env") else {
                    return Err(StepFault {
                        code: "action_fault",
                        source_locator: format!("{}/refresh", action.pointer),
                    });
                };
                let Some(Value::Map(changed)) = envelope.payload.get("changed") else {
                    return Err(StepFault {
                        code: "action_fault",
                        source_locator: format!("{}/refresh", action.pointer),
                    });
                };
                let selected = only
                    .clone()
                    .unwrap_or_else(|| changed.keys().cloned().collect());
                let mut updates = Vec::new();
                for (index, name) in selected.iter().enumerate() {
                    let Some(value) = changed.get(name) else {
                        return Err(StepFault {
                            code: "action_fault",
                            source_locator: format!("{}/refresh/only/{index}", action.pointer),
                        });
                    };
                    let key =
                        resolve_variable_key(runtime, scope, name).ok_or_else(|| StepFault {
                            code: "action_fault",
                            source_locator: format!("{}/refresh/only/{index}", action.pointer),
                        })?;
                    let slot = &runtime.variables[&key];
                    if !slot.declaration.external {
                        return Err(StepFault {
                            code: "action_fault",
                            source_locator: format!("{}/refresh/only/{index}", action.pointer),
                        });
                    }
                    let normalized = value
                        .normalize_for_type(&slot.declaration.value_type)
                        .ok_or_else(|| StepFault {
                            code: "action_fault",
                            source_locator: format!("{}/refresh/only/{index}", action.pointer),
                        })?;
                    updates.push((key, normalized));
                }
                for (key, value) in updates {
                    runtime.variables.get_mut(&key).expect("refresh key").value = value;
                }
            }
            CompiledActionKind::Spawn {
                machine_id,
                bindings,
                bind_to,
            } => execute_spawn(
                runtime,
                scope,
                envelope,
                action,
                machine_id,
                bindings,
                bind_to.as_deref(),
                context,
            )?,
            CompiledActionKind::Cancel { instance } => {
                let value = cel::evaluate(instance, &action_environment(runtime, scope, envelope))
                    .map_err(|_| StepFault {
                        code: "action_fault",
                        source_locator: format!("{}/cancel/instance", action.pointer),
                    })?;
                if let Value::InstanceReference(reference) = value {
                    let _ = cancel_owned(runtime, &reference, context)?;
                }
            }
            CompiledActionKind::Stop => {
                complete_runtime(runtime, context)?;
                return Ok(());
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn execute_send(
    runtime: &mut RuntimeState,
    scope: &str,
    envelope: Option<&Envelope>,
    action: &CompiledAction,
    event: &str,
    targets: &[CompiledSendTarget],
    payload_expressions: &BTreeMap<String, String>,
    correlation_expression: &Option<String>,
    context: &mut StepContext<'_>,
) -> Result<(), StepFault> {
    let environment = action_environment(runtime, scope, envelope);
    let mut payload = BTreeMap::new();
    for (name, expression) in payload_expressions {
        let value = cel::evaluate(expression, &environment).map_err(|_| StepFault {
            code: "action_fault",
            source_locator: format!(
                "{}/send/payload/{}",
                action.pointer,
                super::source::escape_pointer(name)
            ),
        })?;
        payload.insert(name.clone(), value);
    }
    let correlation_id = correlation_expression
        .as_ref()
        .map(|expression| {
            cel::evaluate(expression, &environment)
                .map_err(|_| StepFault {
                    code: "action_fault",
                    source_locator: format!("{}/send/correlation_id", action.pointer),
                })
                .and_then(|value| match value {
                    Value::String(value) if !value.is_empty() => Ok(value),
                    _ => Err(StepFault {
                        code: "action_fault",
                        source_locator: format!("{}/send/correlation_id", action.pointer),
                    }),
                })
        })
        .transpose()?;
    let mut dynamic_values = Vec::new();
    for (index, target) in targets.iter().enumerate() {
        if let CompiledSendTarget::Instance(expression) = target {
            let value = cel::evaluate(expression, &environment).map_err(|_| StepFault {
                code: "action_fault",
                source_locator: target_expression_pointer(action, targets, index),
            })?;
            dynamic_values.push(Some(value));
        } else {
            dynamic_values.push(None);
        }
    }
    let declaration = if event == "env" {
        None
    } else {
        runtime
            .definition
            .events
            .get(event)
            .or_else(|| context.bundle.events.get(event))
    };
    if let Some(declaration) = declaration {
        payload = normalize_payload(declaration, &payload).map_err(|_| StepFault {
            code: "action_fault",
            source_locator: format!("{}/send/payload", action.pointer),
        })?;
    }
    let mut resolved = Vec::new();
    for (index, target) in targets.iter().enumerate() {
        resolved.push(resolve_author_target(
            runtime,
            target,
            dynamic_values[index].as_ref(),
            context.root_instance_id,
            action,
            targets,
            index,
        )?);
    }
    for (ordinal, target) in resolved.into_iter().enumerate() {
        if matches!(target, Target::External) {
            let sequence = context.next_output_sequence.allocate();
            context.emissions.push(Emission {
                emitting_runtime_id: runtime.runtime_id.clone(),
                emitting_owner_runtime_id: runtime_owner_runtime_id(runtime),
                event: event.to_string(),
                event_id: None,
                target,
                payload: payload.clone(),
                correlation_id: correlation_id.clone(),
                effect_id: Some(external_effect_identity(
                    context.bundle,
                    runtime,
                    context.root_instance_id,
                    &context.cause_id,
                    &context.step_sequence,
                    &format!("{}/send", action.pointer),
                    ordinal,
                )),
                sequence: Some(sequence),
            });
        } else {
            let target_runtime_id = target_runtime_id(&target);
            context.emissions.push(Emission {
                emitting_runtime_id: runtime.runtime_id.clone(),
                emitting_owner_runtime_id: runtime_owner_runtime_id(runtime),
                event: event.to_string(),
                event_id: Some(internal_event_identity(
                    context.root_instance_id,
                    &runtime.runtime_id,
                    &target_runtime_id,
                    &context.cause_id,
                    &context.step_sequence,
                    &format!("{}/send", action.pointer),
                    ordinal,
                )),
                target,
                payload: payload.clone(),
                correlation_id: correlation_id.clone(),
                effect_id: None,
                sequence: None,
            });
        }
    }
    Ok(())
}

fn target_expression_pointer(
    action: &CompiledAction,
    targets: &[CompiledSendTarget],
    index: usize,
) -> String {
    if targets.len() == 1 {
        format!("{}/send/to/instance", action.pointer)
    } else {
        format!("{}/send/targets/{index}/instance", action.pointer)
    }
}

fn resolve_author_target(
    runtime: &RuntimeState,
    target: &CompiledSendTarget,
    dynamic: Option<&Value>,
    root_instance_id: &str,
    action: &CompiledAction,
    targets: &[CompiledSendTarget],
    index: usize,
) -> Result<Target, StepFault> {
    let pointer = if targets.len() == 1 {
        format!("{}/send/to", action.pointer)
    } else {
        format!("{}/send/targets/{index}", action.pointer)
    };
    match target {
        CompiledSendTarget::SelfTarget => Ok(runtime_target(runtime, root_instance_id)),
        CompiledSendTarget::Owner => owner_target(runtime, root_instance_id).ok_or(StepFault {
            code: "invalid_instance_target",
            source_locator: pointer,
        }),
        CompiledSendTarget::Component(component_id) => {
            let component = runtime
                .components
                .iter()
                .find(|component| component.component_id == *component_id)
                .ok_or_else(|| StepFault {
                    code: "inactive_component_target",
                    source_locator: pointer.clone(),
                })?;
            if component.runtime.status != RuntimeStatus::Running {
                return Err(StepFault {
                    code: "inactive_component_target",
                    source_locator: pointer,
                });
            }
            Ok(component.runtime.target_identity.clone())
        }
        CompiledSendTarget::Instance(_) => {
            let Some(Value::InstanceReference(reference)) = dynamic else {
                return Err(StepFault {
                    code: "invalid_instance_target",
                    source_locator: target_expression_pointer(action, targets, index),
                });
            };
            if find_spawn_address(runtime, reference).is_none() {
                return Err(StepFault {
                    code: "invalid_instance_target",
                    source_locator: target_expression_pointer(action, targets, index),
                });
            }
            Ok(Target::SpawnedInstance(reference.clone()))
        }
        CompiledSendTarget::External => Ok(Target::External),
    }
}

fn runtime_target(runtime: &RuntimeState, root_instance_id: &str) -> Target {
    let _ = root_instance_id;
    runtime.target_identity.clone()
}

fn runtime_owner_runtime_id(runtime: &RuntimeState) -> Option<String> {
    match &runtime.relation {
        RuntimeRelation::Root => None,
        RuntimeRelation::Component {
            owner_runtime_id, ..
        }
        | RuntimeRelation::Spawned {
            owner_runtime_id, ..
        } => Some(owner_runtime_id.clone()),
    }
}

fn owner_target(runtime: &RuntimeState, _root_instance_id: &str) -> Option<Target> {
    match &runtime.relation {
        RuntimeRelation::Root => None,
        RuntimeRelation::Component { owner_target, .. }
        | RuntimeRelation::Spawned { owner_target, .. } => Some((**owner_target).clone()),
    }
}

fn target_runtime_id(target: &Target) -> String {
    match target {
        Target::Root {
            root_runtime_id, ..
        } => root_runtime_id.clone(),
        Target::SpawnedInstance(reference) => reference.instance_id.clone(),
        Target::Component {
            component_runtime_id,
            ..
        } => component_runtime_id.clone(),
        Target::External => String::new(),
    }
}

#[allow(clippy::too_many_arguments)]
fn execute_spawn(
    runtime: &mut RuntimeState,
    scope: &str,
    envelope: Option<&Envelope>,
    action: &CompiledAction,
    machine_id: &str,
    binding_expressions: &BindingExpressions,
    bind_to: Option<&str>,
    context: &mut StepContext<'_>,
) -> Result<(), StepFault> {
    let machine = context
        .bundle
        .machines
        .get(machine_id)
        .expect("validated spawn machine")
        .clone();
    let bindings = evaluate_bindings(
        runtime,
        scope,
        envelope,
        binding_expressions,
        &format!("{}/spawn/bindings", action.pointer),
    )?;
    validate_runtime_bindings(&machine, &bindings).map_err(|_| StepFault {
        code: "action_fault",
        source_locator: format!("{}/spawn/bindings", action.pointer),
    })?;
    let spawn_sequence = runtime.next_spawn_sequence.allocate();
    let spawn_action_pointer = format!("{}/spawn", action.pointer);
    let instance_id = spawned_runtime_identity(
        context.bundle,
        context.root_instance_id,
        &runtime.runtime_id,
        &spawn_action_pointer,
        &spawn_sequence,
        &machine,
    );
    let reference = InstanceReference {
        root_instance_id: context.root_instance_id.to_string(),
        instance_id: instance_id.clone(),
        machine_id: machine.machine_id.clone(),
        machine_version: machine.version,
    };
    let (holder_path, holder_pointer, holder_activation_sequence) = if let Some(variable) = bind_to
    {
        let key = resolve_variable_key(runtime, scope, variable).expect("validated bind_to");
        let slot = runtime.variables.get_mut(&key).expect("bind slot");
        if slot.value != Value::Null {
            return Err(StepFault {
                code: "binding_not_empty",
                source_locator: format!("{}/spawn/bind_to", action.pointer),
            });
        }
        slot.value = Value::InstanceReference(reference.clone());
        (
            Some(slot.declaration_path.clone()),
            Some(slot.declaration_pointer.clone()),
            slot.state_activation_sequence.clone(),
        )
    } else {
        (None, None, Counter::zero())
    };
    let relation = RuntimeRelation::Spawned {
        owner_runtime_id: runtime.runtime_id.clone(),
        owner_target: Box::new(runtime_target(runtime, context.root_instance_id)),
        spawn_sequence: spawn_sequence.clone(),
        spawn_pointer: spawn_action_pointer.clone(),
        reference: reference.clone(),
        holder_path: holder_path.clone(),
        holder_pointer: holder_pointer.clone(),
        holder_activation_sequence: holder_activation_sequence.clone(),
    };
    let definition = definition_binding(context.bundle, &machine);
    let target_identity = Target::SpawnedInstance(reference.clone());
    let identity_origin = IdentityOrigin::OwnedSpawnedInstance {
        definition: definition.clone(),
        owner_runtime_id: runtime.runtime_id.clone(),
        spawn_action_pointer: spawn_action_pointer.clone(),
        spawn_sequence: spawn_sequence.clone(),
    };
    let mut child = RuntimeState::new(
        instance_id.clone(),
        machine,
        relation,
        identity_origin,
        target_identity,
        definition,
    );
    initialize_root_variables(&mut child, &bindings).map_err(|_| StepFault {
        code: "action_fault",
        source_locator: format!("{}/spawn/bindings", action.pointer),
    })?;
    let child_cause = initialization_cause(
        "spawned_initialization",
        context.root_instance_id,
        &runtime.runtime_id,
        &instance_id,
        &context.cause_id,
        &context.step_sequence,
        &spawn_action_pointer,
        &spawn_sequence,
    );
    let emission_checkpoint = context.emissions.len();
    let output_sequence_checkpoint = context.next_output_sequence.clone();
    let parent_cause = std::mem::replace(&mut context.cause_id, child_cause.clone());
    let initialization = initialize_runtime(&mut child, &bindings, context, true);
    context.cause_id = parent_cause;
    if let Err(fault) = initialization {
        context.emissions.truncate(emission_checkpoint);
        *context.next_output_sequence = output_sequence_checkpoint;
        let record = FaultRecord {
            definition_fingerprint: child
                .current_definition
                .validated_bundle_fingerprint
                .clone(),
            runtime_id: child.runtime_id.clone(),
            cause_id: child_cause,
            code: fault.code.to_string(),
            step_sequence: context.step_sequence.clone(),
            source_locator: fault.source_locator,
        };
        child = RuntimeState::new(
            child.runtime_id.clone(),
            child.definition.clone(),
            child.relation.clone(),
            child.identity_origin.clone(),
            child.target_identity.clone(),
            child.current_definition.clone(),
        );
        child.history.clear();
        child.status = RuntimeStatus::Faulted;
        child.fault = Some(record.clone());
        emit_failure_notification(&child, &record, context);
    }
    if child.status != RuntimeStatus::Completed {
        runtime.owned_instances.push(OwnedRuntime {
            spawn_sequence,
            holder_path,
            holder_pointer,
            holder_activation_sequence,
            reference,
            runtime: child,
        });
    }
    Ok(())
}

fn evaluate_bindings(
    runtime: &RuntimeState,
    scope: &str,
    envelope: Option<&Envelope>,
    expressions: &BindingExpressions,
    pointer: &str,
) -> Result<Bindings, StepFault> {
    let mut environment = action_environment(runtime, scope, envelope);
    environment.values.insert(
        "owner".to_string(),
        Value::Map(BTreeMap::from([(
            "variables".to_string(),
            Value::Map(visible_variables(runtime, scope)),
        )])),
    );
    let mut bindings = Bindings::default();
    for (kind, source, output) in [
        ("input", &expressions.input, &mut bindings.input),
        ("external", &expressions.external, &mut bindings.external),
    ] {
        for (name, expression) in source {
            let value = cel::evaluate(expression, &environment).map_err(|_| StepFault {
                code: "action_fault",
                source_locator: format!("{pointer}/{kind}/{}", super::source::escape_pointer(name)),
            })?;
            output.insert(name.clone(), value);
        }
    }
    Ok(bindings)
}

fn validate_runtime_bindings(machine: &Machine, bindings: &Bindings) -> Result<(), ()> {
    let input = root_input_variables(machine);
    let external = root_external_variables(machine);
    if bindings.input.keys().any(|name| !input.contains_key(name))
        || bindings
            .external
            .keys()
            .any(|name| !external.contains_key(name))
    {
        return Err(());
    }
    for (name, declaration) in input.iter().chain(external.iter()) {
        let supplied = if declaration.input {
            bindings.input.get(name)
        } else {
            bindings.external.get(name)
        };
        if let Some(value) = supplied {
            if value.normalize_for_type(&declaration.value_type).is_none() {
                return Err(());
            }
        } else if declaration.init.is_none() {
            return Err(());
        }
    }
    Ok(())
}

fn allocate_components(
    runtime: &mut RuntimeState,
    state: &State,
    context: &StepContext<'_>,
) -> Result<(), StepFault> {
    for component in &state.components {
        let next = runtime
            .next_component_activation_sequence
            .entry(component.pointer.clone())
            .or_default();
        let activation_sequence = next.allocate();
        let machine = match &component.definition {
            ComponentDefinition::Machine(machine_id) => context.bundle.machines[machine_id].clone(),
            ComponentDefinition::Inline(machine) => machine.as_ref().clone(),
        };
        let runtime_id = component_runtime_identity(
            context.bundle,
            context.root_instance_id,
            &runtime.runtime_id,
            component,
            &activation_sequence,
            &machine,
        );
        let relation = RuntimeRelation::Component {
            owner_runtime_id: runtime.runtime_id.clone(),
            owner_target: Box::new(runtime_target(runtime, context.root_instance_id)),
            owner_state_path: state.path.clone(),
            component_id: component.component_id.clone(),
            component_pointer: component.pointer.clone(),
            declaration_index: component.declaration_index,
            activation_sequence: activation_sequence.clone(),
        };
        let definition = definition_binding(context.bundle, &machine);
        let target_identity = Target::Component {
            root_instance_id: context.root_instance_id.to_string(),
            owner_runtime_id: runtime.runtime_id.clone(),
            component_id: component.component_id.clone(),
            component_runtime_id: runtime_id.clone(),
            activation_sequence: activation_sequence.clone(),
        };
        let identity_origin = IdentityOrigin::Component {
            definition: definition.clone(),
            owner_runtime_id: runtime.runtime_id.clone(),
            component_definition_pointer: component.pointer.clone(),
            activation_sequence: activation_sequence.clone(),
            declaration_index: Counter::from(component.declaration_index),
        };
        runtime.components.push(ComponentRuntime {
            component_id: component.component_id.clone(),
            pointer: component.pointer.clone(),
            declaration_index: component.declaration_index,
            activation_sequence,
            runtime: RuntimeState::new(
                runtime_id,
                machine,
                relation,
                identity_origin,
                target_identity,
                definition,
            ),
        });
    }
    Ok(())
}

fn initialize_components(
    runtime: &mut RuntimeState,
    state: &State,
    context: &mut StepContext<'_>,
) -> Result<(), StepFault> {
    let owner_snapshot = runtime.clone();
    for component_definition in &state.components {
        let index = runtime
            .components
            .iter()
            .position(|component| {
                component.pointer == component_definition.pointer
                    && component.runtime.active.is_empty()
                    && component.runtime.status == RuntimeStatus::Running
            })
            .expect("allocated pending component");
        let bindings = evaluate_bindings(
            &owner_snapshot,
            &state.path,
            None,
            &component_definition.bindings,
            &format!("{}/with", component_definition.pointer),
        )?;
        let child = &mut runtime.components[index].runtime;
        validate_runtime_bindings(&child.definition, &bindings).map_err(|_| StepFault {
            code: "action_fault",
            source_locator: format!("{}/with", component_definition.pointer),
        })?;
        let child_cause = initialization_cause(
            "component_initialization",
            context.root_instance_id,
            &runtime.runtime_id,
            &child.runtime_id,
            &context.cause_id,
            &context.step_sequence,
            &component_definition.pointer,
            &Counter::from(component_definition.declaration_index),
        );
        let emission_checkpoint = context.emissions.len();
        let output_sequence_checkpoint = context.next_output_sequence.clone();
        let parent_cause = std::mem::replace(&mut context.cause_id, child_cause.clone());
        let initialization = initialize_runtime(child, &bindings, context, true);
        context.cause_id = parent_cause;
        if let Err(fault) = initialization {
            context.emissions.truncate(emission_checkpoint);
            *context.next_output_sequence = output_sequence_checkpoint;
            let relation = child.relation.clone();
            let definition = child.definition.clone();
            let runtime_id = child.runtime_id.clone();
            let identity_origin = child.identity_origin.clone();
            let target_identity = child.target_identity.clone();
            let current_definition = child.current_definition.clone();
            let record = FaultRecord {
                definition_fingerprint: current_definition.validated_bundle_fingerprint.clone(),
                runtime_id: runtime_id.clone(),
                cause_id: child_cause.clone(),
                code: fault.code.to_string(),
                step_sequence: context.step_sequence.clone(),
                source_locator: fault.source_locator,
            };
            *child = RuntimeState::new(
                runtime_id,
                definition,
                relation,
                identity_origin,
                target_identity,
                current_definition,
            );
            child.history.clear();
            child.status = RuntimeStatus::Faulted;
            child.fault = Some(record.clone());
            emit_failure_notification(child, &record, context);
        }
        if runtime.components[index].runtime.status == RuntimeStatus::Completed
            && runtime
                .components
                .iter()
                .all(|component| component.runtime.status == RuntimeStatus::Completed)
        {
            push_parallel_done(
                runtime,
                &state.path,
                &child_cause,
                &context.step_sequence,
                context.root_instance_id,
                context.emissions,
            );
        }
    }
    Ok(())
}

fn complete_runtime(
    runtime: &mut RuntimeState,
    context: &mut StepContext<'_>,
) -> Result<(), StepFault> {
    complete_runtime_inner(runtime, context).map_err(|_| cascade_step_fault())
}

fn complete_runtime_inner(
    runtime: &mut RuntimeState,
    context: &mut StepContext<'_>,
) -> Result<(), StepFault> {
    if runtime.status == RuntimeStatus::Completed {
        return Ok(());
    }
    cleanup_all_descendants(runtime, context)?;
    let mut exits = runtime.active.iter().cloned().collect::<Vec<_>>();
    exits.sort_by_key(|path| std::cmp::Reverse(path_depth(path)));
    for path in exits {
        exit_state(runtime, &path, context)?;
    }
    runtime.status = RuntimeStatus::Completed;
    emit_completion_notification(runtime, context);
    Ok(())
}

fn exit_state(
    runtime: &mut RuntimeState,
    path: &str,
    context: &mut StepContext<'_>,
) -> Result<(), StepFault> {
    let state = runtime.definition.states[path].clone();
    cleanup_state_children(runtime, path, context)?;
    run_actions(runtime, path, &state.exit, None, context)?;
    runtime
        .variables
        .retain(|_, slot| slot.declaration_path != path);
    runtime.active.remove(path);
    runtime.active_state_activation_sequence.remove(path);
    Ok(())
}

fn capture_history(runtime: &mut RuntimeState, state: &State) {
    match state.history {
        super::model::HistoryKind::None => {}
        super::model::HistoryKind::Deep => {
            let record = runtime
                .config()
                .into_iter()
                .filter(|leaf| is_descendant(leaf, &state.path))
                .collect::<Vec<_>>();
            runtime.history.insert(state.path.clone(), Some(record));
        }
        super::model::HistoryKind::Shallow => {
            let record = runtime
                .config()
                .into_iter()
                .filter(|leaf| is_descendant(leaf, &state.path))
                .filter_map(|leaf| direct_child_path(&leaf, &state.path))
                .take(1)
                .collect::<Vec<_>>();
            runtime.history.insert(state.path.clone(), Some(record));
        }
    }
}

fn cleanup_state_children(
    runtime: &mut RuntimeState,
    path: &str,
    context: &mut StepContext<'_>,
) -> Result<(), StepFault> {
    let mut component_indices = runtime
        .components
        .iter()
        .enumerate()
        .filter_map(|(index, component)| match &component.runtime.relation {
            RuntimeRelation::Component {
                owner_state_path, ..
            } if owner_state_path == path => Some(index),
            _ => None,
        })
        .collect::<Vec<_>>();
    sort_component_cleanup_indices(runtime, &mut component_indices);
    for index in component_indices {
        cleanup_runtime(&mut runtime.components[index].runtime, context)?;
    }
    runtime.components.retain(|component| {
        !matches!(
            &component.runtime.relation,
            RuntimeRelation::Component {
                owner_state_path,
                ..
            } if owner_state_path == path
        )
    });

    let mut selected = runtime
        .owned_instances
        .iter()
        .enumerate()
        .filter(|(_, owned)| owned.holder_path.as_deref() == Some(path))
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    sort_owned_cleanup_indices(runtime, &mut selected);
    let selected_sequences = selected
        .iter()
        .map(|index| runtime.owned_instances[*index].spawn_sequence.clone())
        .collect::<BTreeSet<_>>();
    for index in selected {
        cleanup_runtime(&mut runtime.owned_instances[index].runtime, context)?;
    }
    runtime
        .owned_instances
        .retain(|owned| !selected_sequences.contains(&owned.spawn_sequence));
    Ok(())
}

fn cleanup_all_descendants(
    runtime: &mut RuntimeState,
    context: &mut StepContext<'_>,
) -> Result<(), StepFault> {
    let mut component_indices = (0..runtime.components.len()).collect::<Vec<_>>();
    sort_component_cleanup_indices(runtime, &mut component_indices);
    for index in component_indices {
        cleanup_runtime(&mut runtime.components[index].runtime, context)?;
    }
    runtime.components.clear();
    let mut owned_indices = (0..runtime.owned_instances.len()).collect::<Vec<_>>();
    sort_owned_cleanup_indices(runtime, &mut owned_indices);
    for index in owned_indices {
        cleanup_runtime(&mut runtime.owned_instances[index].runtime, context)?;
    }
    runtime.owned_instances.clear();
    Ok(())
}

fn sort_component_cleanup_indices(runtime: &RuntimeState, indices: &mut [usize]) {
    indices.sort_by(|left, right| {
        let left = component_cleanup_key(runtime, &runtime.components[*left]);
        let right = component_cleanup_key(runtime, &runtime.components[*right]);
        right.cmp(&left)
    });
}

fn component_cleanup_key(
    owner: &RuntimeState,
    component: &ComponentRuntime,
) -> (String, Counter, usize, Counter) {
    let RuntimeRelation::Component {
        owner_state_path, ..
    } = &component.runtime.relation
    else {
        unreachable!("component collection contains a non-component runtime");
    };
    (
        owner.definition.states[owner_state_path].pointer.clone(),
        owner.active_state_activation_sequence[owner_state_path].clone(),
        component.declaration_index,
        component.activation_sequence.clone(),
    )
}

fn sort_owned_cleanup_indices(runtime: &RuntimeState, indices: &mut [usize]) {
    indices.sort_by_key(|index| {
        let owned = &runtime.owned_instances[*index];
        (
            usize::from(owned.holder_path.is_none()),
            owned.holder_pointer.clone().unwrap_or_default(),
            owned.holder_activation_sequence.clone(),
            owned.spawn_sequence.clone(),
        )
    });
}

fn cleanup_runtime(
    runtime: &mut RuntimeState,
    context: &mut StepContext<'_>,
) -> Result<(), StepFault> {
    cleanup_runtime_inner(runtime, context).map_err(|_| cascade_step_fault())
}

fn cleanup_runtime_inner(
    runtime: &mut RuntimeState,
    context: &mut StepContext<'_>,
) -> Result<(), StepFault> {
    cleanup_all_descendants(runtime, context)?;
    if runtime.status == RuntimeStatus::Running {
        let mut exits = runtime.active.iter().cloned().collect::<Vec<_>>();
        exits.sort_by_key(|path| std::cmp::Reverse(path_depth(path)));
        for path in exits {
            let state = runtime.definition.states[&path].clone();
            run_actions(runtime, &path, &state.exit, None, context)?;
            runtime
                .variables
                .retain(|_, slot| slot.declaration_path != path);
            runtime.active.remove(&path);
        }
    }
    runtime.status = RuntimeStatus::Completed;
    Ok(())
}

fn cascade_step_fault() -> StepFault {
    StepFault {
        code: "cascade_fault",
        source_locator: "system:cascade_cleanup".to_string(),
    }
}

fn cancel_owned(
    runtime: &mut RuntimeState,
    reference: &InstanceReference,
    context: &mut StepContext<'_>,
) -> Result<bool, StepFault> {
    if let Some(index) = runtime
        .owned_instances
        .iter()
        .position(|owned| owned.reference == *reference)
    {
        cleanup_runtime(&mut runtime.owned_instances[index].runtime, context)?;
        runtime.owned_instances.remove(index);
        return Ok(true);
    }
    for owned in &mut runtime.owned_instances {
        if cancel_owned(&mut owned.runtime, reference, context)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn emit_completion_notification(runtime: &RuntimeState, context: &mut StepContext<'_>) {
    match &runtime.relation {
        RuntimeRelation::Root => {}
        RuntimeRelation::Component {
            owner_target,
            owner_state_path,
            component_id,
            ..
        } => {
            let target = (**owner_target).clone();
            let payload = BTreeMap::from([
                (
                    "component_id".to_string(),
                    Value::String(component_id.clone()),
                ),
                (
                    "component_runtime_id".to_string(),
                    Value::String(runtime.runtime_id.clone()),
                ),
            ]);
            push_system_emission(
                runtime,
                "determa.component_completed",
                target.clone(),
                payload,
                "system:component_completion",
                0,
                context,
            );
            // The owner emits the parallel done once all retained placements complete.
            // The owner runtime is not directly available here; the caller's delivery
            // path checks this relation and appends done when appropriate.
            let _ = owner_state_path;
        }
        RuntimeRelation::Spawned {
            owner_target,
            reference,
            ..
        } => {
            let target = (**owner_target).clone();
            let payload = BTreeMap::from([
                (
                    "relationship".to_string(),
                    Value::String("spawned_instance".to_string()),
                ),
                (
                    "instance".to_string(),
                    Value::InstanceReference(reference.clone()),
                ),
                (
                    "instance_id".to_string(),
                    Value::String(reference.instance_id.clone()),
                ),
                (
                    "machine_id".to_string(),
                    Value::String(reference.machine_id.clone()),
                ),
                (
                    "machine_version".to_string(),
                    Value::Int(reference.machine_version),
                ),
            ]);
            push_system_emission(
                runtime,
                "done",
                target,
                payload,
                "system:spawned_completion",
                0,
                context,
            );
        }
    }
}

fn emit_failure_notification(
    runtime: &RuntimeState,
    record: &FaultRecord,
    context: &mut StepContext<'_>,
) {
    let public_fault = Value::Map(BTreeMap::from([
        (
            "runtime_id".to_string(),
            Value::String(record.runtime_id.clone()),
        ),
        (
            "cause_id".to_string(),
            Value::String(record.cause_id.clone()),
        ),
        ("code".to_string(), Value::String(record.code.clone())),
        (
            "step_sequence".to_string(),
            Value::String(record.step_sequence.to_string()),
        ),
        (
            "source_locator".to_string(),
            Value::String(record.source_locator.clone()),
        ),
    ]));
    match &runtime.relation {
        RuntimeRelation::Component {
            owner_target,
            component_id,
            ..
        } => {
            let payload = BTreeMap::from([
                (
                    "component_id".to_string(),
                    Value::String(component_id.clone()),
                ),
                (
                    "component_runtime_id".to_string(),
                    Value::String(runtime.runtime_id.clone()),
                ),
                ("fault".to_string(), public_fault),
            ]);
            push_system_emission(
                runtime,
                "determa.component_failed",
                (**owner_target).clone(),
                payload,
                "system:component_failure",
                0,
                context,
            );
        }
        RuntimeRelation::Spawned {
            owner_target,
            reference,
            ..
        } => {
            let payload = BTreeMap::from([
                (
                    "instance".to_string(),
                    Value::InstanceReference(reference.clone()),
                ),
                (
                    "instance_id".to_string(),
                    Value::String(reference.instance_id.clone()),
                ),
                (
                    "machine_id".to_string(),
                    Value::String(reference.machine_id.clone()),
                ),
                (
                    "machine_version".to_string(),
                    Value::Int(reference.machine_version),
                ),
                ("fault".to_string(), public_fault),
            ]);
            push_system_emission(
                runtime,
                "determa.spawned_instance_failed",
                (**owner_target).clone(),
                payload,
                "system:spawned_failure",
                0,
                context,
            );
        }
        RuntimeRelation::Root => {}
    }
}

#[allow(clippy::too_many_arguments)]
fn push_system_emission(
    runtime: &RuntimeState,
    event: &str,
    target: Target,
    payload: BTreeMap<String, Value>,
    locator: &str,
    ordinal: usize,
    context: &mut StepContext<'_>,
) {
    context.emissions.push(Emission {
        emitting_runtime_id: runtime.runtime_id.clone(),
        emitting_owner_runtime_id: runtime_owner_runtime_id(runtime),
        event: event.to_string(),
        event_id: Some(internal_event_identity(
            context.root_instance_id,
            &runtime.runtime_id,
            &target_runtime_id(&target),
            &context.cause_id,
            &context.step_sequence,
            locator,
            ordinal,
        )),
        target,
        payload,
        correlation_id: None,
        effect_id: None,
        sequence: None,
    });
}

fn dispose_completed_spawned_at_path(runtime: &mut RuntimeState, address: &[AddressSegment]) {
    let Some((head, tail)) = address.split_first() else {
        return;
    };
    match head {
        AddressSegment::Spawn(sequence) if tail.is_empty() => {
            runtime.owned_instances.retain(|owned| {
                owned.spawn_sequence != *sequence
                    || owned.runtime.status != RuntimeStatus::Completed
            });
        }
        AddressSegment::Spawn(sequence) => {
            if let Some(owned) = runtime
                .owned_instances
                .iter_mut()
                .find(|owned| owned.spawn_sequence == *sequence)
            {
                dispose_completed_spawned_at_path(&mut owned.runtime, tail);
            }
        }
        AddressSegment::Component(component_id, activation_sequence) => {
            if let Some(component) = runtime.components.iter_mut().find(|component| {
                component.component_id == *component_id
                    && component.activation_sequence == *activation_sequence
            }) {
                dispose_completed_spawned_at_path(&mut component.runtime, tail);
            }
        }
    }
}

fn append_parallel_done_if_needed(
    aggregate: &mut AggregateState,
    address: &[AddressSegment],
    cause_id: &str,
    step_sequence: Counter,
    emissions: &mut Vec<Emission>,
) {
    let Some(AddressSegment::Component(component_id, activation_sequence)) = address.last() else {
        return;
    };
    let parent_address = &address[..address.len() - 1];
    let Some(owner) = runtime_at(&aggregate.root, parent_address) else {
        return;
    };
    let Some(completed) = owner.components.iter().find(|component| {
        component.component_id == *component_id
            && component.activation_sequence == *activation_sequence
    }) else {
        return;
    };
    if completed.runtime.status != RuntimeStatus::Completed
        || owner
            .components
            .iter()
            .any(|component| component.runtime.status != RuntimeStatus::Completed)
    {
        return;
    }
    let RuntimeRelation::Component {
        owner_state_path, ..
    } = &completed.runtime.relation
    else {
        return;
    };
    push_parallel_done(
        owner,
        owner_state_path,
        cause_id,
        &step_sequence,
        &aggregate.root_instance_id,
        emissions,
    );
}

fn push_parallel_done(
    owner: &RuntimeState,
    owner_state_path: &str,
    cause_id: &str,
    step_sequence: &Counter,
    root_instance_id: &str,
    emissions: &mut Vec<Emission>,
) {
    let target = runtime_target(owner, root_instance_id);
    let payload = BTreeMap::from([
        (
            "relationship".to_string(),
            Value::String("parallel".to_string()),
        ),
        (
            "state_path".to_string(),
            Value::String(owner_state_path.to_string()),
        ),
        (
            "owner_runtime_id".to_string(),
            Value::String(owner.runtime_id.clone()),
        ),
    ]);
    let event_id = internal_event_identity(
        root_instance_id,
        &owner.runtime_id,
        &owner.runtime_id,
        cause_id,
        step_sequence,
        "system:component_completion",
        1,
    );
    emissions.push(Emission {
        emitting_runtime_id: owner.runtime_id.clone(),
        emitting_owner_runtime_id: runtime_owner_runtime_id(owner),
        event: "done".to_string(),
        event_id: Some(event_id),
        target,
        payload,
        correlation_id: None,
        effect_id: None,
        sequence: None,
    });
}

fn action_environment(
    runtime: &RuntimeState,
    scope: &str,
    envelope: Option<&Envelope>,
) -> Environment {
    let mut values = visible_variables(runtime, scope);
    if let Some(envelope) = envelope {
        values.insert(
            "event".to_string(),
            Value::Map(BTreeMap::from([(
                "payload".to_string(),
                Value::Map(envelope.payload.clone()),
            )])),
        );
    }
    Environment { values }
}

fn visible_variables(runtime: &RuntimeState, scope: &str) -> BTreeMap<String, Value> {
    let mut values = BTreeMap::new();
    let mut current = Some(scope.to_string());
    while let Some(path) = current {
        for slot in runtime
            .variables
            .values()
            .filter(|slot| slot.declaration_path == path)
        {
            values
                .entry(slot.name.clone())
                .or_insert_with(|| slot.value.clone());
        }
        current = runtime.definition.states[&path].parent.clone();
    }
    values
}

fn resolve_variable_key(runtime: &RuntimeState, scope: &str, name: &str) -> Option<String> {
    let mut current = Some(scope.to_string());
    while let Some(path) = current {
        let key = variable_key(&path, name);
        if runtime.variables.contains_key(&key) {
            return Some(key);
        }
        current = runtime.definition.states[&path].parent.clone();
    }
    None
}

fn variable_key(path: &str, name: &str) -> String {
    format!("{path}\u{0}{name}")
}

fn path_depth(path: &str) -> usize {
    if path == "root" {
        0
    } else {
        path.split('.').count()
    }
}

fn ancestors_to_root(machine: &Machine, path: &str) -> Vec<String> {
    let mut output = Vec::new();
    let mut current = Some(path.to_string());
    while let Some(path) = current {
        output.push(path.clone());
        current = machine.states[&path].parent.clone();
    }
    output
}

fn lowest_common_ancestor(machine: &Machine, left: &str, right: &str) -> String {
    let left_ancestors = ancestors_to_root(machine, left)
        .into_iter()
        .collect::<BTreeSet<_>>();
    ancestors_to_root(machine, right)
        .into_iter()
        .find(|path| left_ancestors.contains(path))
        .expect("root is a common ancestor")
}

fn direct_child_path(leaf: &str, parent: &str) -> Option<String> {
    if parent == "root" {
        return leaf.split('.').next().map(str::to_string);
    }
    let suffix = leaf.strip_prefix(parent)?.strip_prefix('.')?;
    let child = suffix.split('.').next()?;
    Some(format!("{parent}.{child}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format1::load_bundle;

    const IDENTITY_VECTOR_BUNDLE: &str = r#"
format: 1
namespace: example.turnstile
events:
  tick:
    payload:
      amount: { type: float, default: 1 }
meta:
  large_integer: 9007199254740993
  integer_one: 1
  floating_one: 1.0
machines:
  - machine_id: turnstile
    events:
      local_notice:
        payload:
          value: { type: int, required: true }
    root:
      type: composite
      variables:
        attempts: { type: int, init: 0 }
      initial: { transition_to: locked }
      states:
        locked:
          type: parallel
          components:
            - component_id: left
              root: {}
            - component_id: right
              root: {}
          on_events:
            tick:
              transition_to: unlocked
              action:
                - send:
                    event: local_notice
                    payload: { value: "1" }
        unlocked: {}
"#;

    fn cascade_fault_bundle(mode: &str) -> String {
        let root = match mode {
            "cancel" => {
                r#"
    root:
      type: composite
      variables:
        child:
          type: instance_reference
          machine_id: faulty
          nullable: true
          init: null
      entry:
        - spawn: { machine_id: faulty, bind_to: child }
      initial: { transition_to: active }
      states:
        active:
          on_events:
            trigger:
              action:
                - cancel: { instance: "child" }
"#
            }
            "holder" => {
                r#"
    root:
      type: composite
      initial: { transition_to: active }
      states:
        active:
          variables:
            child:
              type: instance_reference
              machine_id: faulty
              nullable: true
              init: null
          entry:
            - spawn: { machine_id: faulty, bind_to: child }
          on_events:
            trigger: { transition_to: done }
        done: {}
"#
            }
            "stop" => {
                r#"
    root:
      type: composite
      variables:
        child:
          type: instance_reference
          machine_id: faulty
          nullable: true
          init: null
      entry:
        - spawn: { machine_id: faulty, bind_to: child }
      initial: { transition_to: active }
      states:
        active:
          on_events:
            trigger:
              action:
                - stop: {}
"#
            }
            "completion" => {
                r#"
    root:
      type: composite
      variables:
        child:
          type: instance_reference
          machine_id: faulty
          nullable: true
          init: null
      entry:
        - spawn: { machine_id: faulty, bind_to: child }
      initial: { transition_to: active }
      states:
        active:
          on_events:
            trigger: { transition_to: finished }
        finished: { type: final }
"#
            }
            "parallel" => {
                r#"
    root:
      type: composite
      initial: { transition_to: active }
      states:
        active:
          type: parallel
          components:
            - component_id: faulty
              root:
                type: composite
                variables:
                  value: { type: int, init: 1 }
                exit:
                  - send:
                      event: cleanup_started
                      to: { external: true }
                      correlation_id: "'cleanup'"
                  - assign: { value: "value / 0" }
                initial: { transition_to: running }
                states:
                  running: {}
            - component_id: healthy
              root: {}
          on_events:
            trigger: { transition_to: done }
        done: {}
"#
            }
            _ => unreachable!(),
        };
        format!(
            r#"
format: 1
namespace: test.cascade_{mode}
events:
  trigger: {{ direction: input }}
  cleanup_started: {{ direction: output }}
machines:
  - machine_id: owner
{root}
  - machine_id: faulty
    root:
      type: composite
      variables:
        value: {{ type: int, init: 1 }}
      exit:
        - send:
            event: cleanup_started
            to: {{ external: true }}
            correlation_id: "'cleanup'"
        - assign: {{ value: "value / 0" }}
      initial: {{ transition_to: running }}
      states:
        running: {{}}
"#
        )
    }

    #[test]
    fn reserved_lifecycle_payloads_are_closed_and_coherent() {
        let component_completed = BTreeMap::from([
            (
                "component_id".to_string(),
                Value::String("worker".to_string()),
            ),
            (
                "component_runtime_id".to_string(),
                Value::String("component-runtime".to_string()),
            ),
        ]);
        assert!(validate_reserved_lifecycle_payload(
            "determa.component_completed",
            &component_completed
        )
        .is_ok());
        let mut extra_component_field = component_completed;
        extra_component_field.insert("extra".to_string(), Value::Bool(true));
        assert!(validate_reserved_lifecycle_payload(
            "determa.component_completed",
            &extra_component_field
        )
        .is_err());

        let reference = InstanceReference {
            root_instance_id: "root-1".to_string(),
            instance_id: "child-1".to_string(),
            machine_id: "worker".to_string(),
            machine_version: 1,
        };
        let fault = Value::Map(BTreeMap::from([
            (
                "runtime_id".to_string(),
                Value::String("child-1".to_string()),
            ),
            ("cause_id".to_string(), Value::String("cause-1".to_string())),
            (
                "code".to_string(),
                Value::String("action_fault".to_string()),
            ),
            (
                "step_sequence".to_string(),
                Value::String("9007199254740993".to_string()),
            ),
            (
                "source_locator".to_string(),
                Value::String("/machines/0/root/entry/0/assign/value".to_string()),
            ),
        ]));
        let spawned_failure = BTreeMap::from([
            (
                "instance".to_string(),
                Value::InstanceReference(reference.clone()),
            ),
            (
                "instance_id".to_string(),
                Value::String(reference.instance_id.clone()),
            ),
            (
                "machine_id".to_string(),
                Value::String(reference.machine_id.clone()),
            ),
            (
                "machine_version".to_string(),
                Value::Int(reference.machine_version),
            ),
            ("fault".to_string(), fault),
        ]);
        assert!(validate_reserved_lifecycle_payload(
            "determa.spawned_instance_failed",
            &spawned_failure
        )
        .is_ok());
        let mut mismatched_reference = spawned_failure;
        mismatched_reference.insert(
            "machine_id".to_string(),
            Value::String("other_worker".to_string()),
        );
        assert!(validate_reserved_lifecycle_payload(
            "determa.spawned_instance_failed",
            &mismatched_reference
        )
        .is_err());

        let parallel_done = BTreeMap::from([
            (
                "relationship".to_string(),
                Value::String("parallel".to_string()),
            ),
            (
                "state_path".to_string(),
                Value::String("processing.work".to_string()),
            ),
            (
                "owner_runtime_id".to_string(),
                Value::String("owner-1".to_string()),
            ),
        ]);
        assert!(validate_reserved_lifecycle_payload("done", &parallel_done).is_ok());
        let mut incomplete_done = parallel_done;
        incomplete_done.remove("owner_runtime_id");
        assert!(validate_reserved_lifecycle_payload("done", &incomplete_done).is_err());
    }

    #[test]
    fn exact_normative_identity_vectors() {
        let bundle = load_bundle(IDENTITY_VECTOR_BUNDLE).unwrap();
        assert_eq!(
            bundle.fingerprint,
            "sha256:7e48ad82ea5305c24b7730f4fd24c36ec196a0875c982b85eba5b3a5ddcbb92f"
        );
        let result = create(
            &bundle,
            "turnstile",
            "turnstile-42",
            "create-7",
            &Bindings::default(),
        );
        assert_eq!(result.status, ResultStatus::Running);
        let aggregate = result.state.unwrap();
        assert_eq!(
            aggregate.root.runtime_id,
            "sha256:72dca6d0b2b3690ae28bda2f17a461179b18fbf11daad7a12709d9384a500c64"
        );
        let left = &aggregate.root.components[0];
        assert_eq!(left.component_id, "left");
        assert_eq!(
            left.runtime.runtime_id,
            "sha256:43db74b6a8d6f31543f7d142fb5e25a49e33eb3bf548e7bfd20d59513778cbc3"
        );
        assert_eq!(
            initialization_cause(
                "root_initialization",
                "turnstile-42",
                &aggregate.root.runtime_id,
                &aggregate.root.runtime_id,
                "create-7",
                &Counter::zero(),
                "/machines/0/root",
                &Counter::zero(),
            ),
            "sha256:c9e8e89a01362f40e9a74c01392d09abe2323f31c8f14f22e05bfcaf6dfac0ab"
        );
        assert_eq!(
            runtime_target(&left.runtime, &aggregate.root_instance_id),
            Target::Component {
                root_instance_id: "turnstile-42".to_string(),
                owner_runtime_id: aggregate.root.runtime_id.clone(),
                component_id: "left".to_string(),
                component_runtime_id: left.runtime.runtime_id.clone(),
                activation_sequence: Counter::zero(),
            }
        );
    }

    #[test]
    fn event_and_effect_hashes_preserve_large_counter_decimals() {
        let bundle = load_bundle(IDENTITY_VECTOR_BUNDLE).unwrap();
        let aggregate = create(
            &bundle,
            "turnstile",
            "turnstile-42",
            "create-7",
            &Bindings::default(),
        )
        .state
        .unwrap();
        let root_id = &aggregate.root.runtime_id;
        let component_id = &aggregate.root.components[0].runtime.runtime_id;
        let cause_id = "sha256:c9e8e89a01362f40e9a74c01392d09abe2323f31c8f14f22e05bfcaf6dfac0ab";
        let step = Counter::from_decimal("9007199254740993").unwrap();
        let locator = "/machines/0/root/states/locked/on_events/tick/action/0";
        assert_eq!(
            internal_event_identity(
                "turnstile-42",
                root_id,
                component_id,
                cause_id,
                &step,
                locator,
                0,
            ),
            "sha256:4546950b5141f5c27568f01832a44571dbb2f8b4b62f7ed0e1985f93a817bf12"
        );
        assert_eq!(
            external_effect_identity(
                &bundle,
                &aggregate.root,
                "turnstile-42",
                cause_id,
                &step,
                locator,
                0,
            ),
            "sha256:7386c6dfe80ee1019984b2b96d275d0ca90eddc9ba9075d57e120a3bd6b13386"
        );
    }

    #[test]
    fn every_root_completion_cascade_uses_canonical_component_and_holder_order() {
        let mut source = r#"
format: 1
namespace: test.lifecycle_order
events:
  stop_all: { direction: input }
  leave: { direction: input }
  cleaned:
    direction: output
    payload:
      label: { type: string, required: true }
machines:
  - machine_id: owner
    root:
      type: composite
      initial: { transition_to: processing }
      states:
        processing:
          type: parallel
          variables:
            a_holder:
              type: instance_reference
              machine_id: worker
              nullable: true
              init: null
            z_holder:
              type: instance_reference
              machine_id: worker
              nullable: true
              init: null
          entry:
            - spawn:
                machine_id: worker
                bindings: { input: { label: "'spawn-z'" } }
                bind_to: z_holder
            - spawn:
                machine_id: worker
                bindings: { input: { label: "'spawn-a'" } }
                bind_to: a_holder
            - spawn:
                machine_id: worker
                bindings: { input: { label: "'spawn-unbound'" } }
          components:
"#
        .to_string();
        for index in 0..11 {
            source.push_str(&format!(
                r#"
            - component_id: component_{index}
              root:
                type: composite
                variables:
                  label: {{ type: string, init: component-{index} }}
                exit:
                  - send:
                      event: cleaned
                      to: {{ external: true }}
                      payload: {{ label: "label" }}
                      correlation_id: "label"
                initial: {{ transition_to: active }}
                states:
                  active: {{}}
"#
            ));
        }
        source.push_str(
            r#"
          on_events:
            stop_all:
              action:
                - stop: {}
            leave: { transition_to: finished }
        finished: {}
  - machine_id: worker
    root:
      type: composite
      variables:
        label: { type: string, input: true }
      exit:
        - send:
            event: cleaned
            to: { external: true }
            payload: { label: "label" }
            correlation_id: "label"
      initial: { transition_to: active }
      states:
        active: {}
"#,
        );
        let bundle = load_bundle(&source).unwrap();
        let created = create(
            &bundle,
            "owner",
            "lifecycle-order-1",
            "create-lifecycle-order-1",
            &Bindings::default(),
        );
        let prior = created.state.unwrap();
        let result = dispatch(
            &bundle,
            &prior,
            Some(Delivery::Input(Envelope {
                event: "stop_all".to_string(),
                event_id: "stop-all-1".to_string(),
                target: runtime_target(&prior.root, &prior.root_instance_id),
                payload: BTreeMap::new(),
                correlation_id: None,
            })),
        );
        assert_eq!(
            result.status,
            ResultStatus::Completed,
            "unexpected stop result: {result:?}"
        );
        let labels = result
            .emissions
            .iter()
            .map(|emission| match &emission.payload["label"] {
                Value::String(value) => value.as_str(),
                value => panic!("unexpected cleanup label {value:?}"),
            })
            .collect::<Vec<_>>();
        assert_eq!(
            labels,
            vec![
                "component-10",
                "component-9",
                "component-8",
                "component-7",
                "component-6",
                "component-5",
                "component-4",
                "component-3",
                "component-2",
                "component-1",
                "component-0",
                "spawn-a",
                "spawn-z",
                "spawn-unbound",
            ]
        );

        let transition_prior = create(
            &bundle,
            "owner",
            "lifecycle-order-2",
            "create-lifecycle-order-2",
            &Bindings::default(),
        )
        .state
        .unwrap();
        let transitioned = dispatch(
            &bundle,
            &transition_prior,
            Some(Delivery::Input(Envelope {
                event: "leave".to_string(),
                event_id: "leave-2".to_string(),
                target: runtime_target(&transition_prior.root, &transition_prior.root_instance_id),
                payload: BTreeMap::new(),
                correlation_id: None,
            })),
        );
        let transition_labels = transitioned
            .emissions
            .iter()
            .map(|emission| match &emission.payload["label"] {
                Value::String(value) => value.as_str(),
                value => panic!("unexpected transition cleanup label {value:?}"),
            })
            .collect::<Vec<_>>();
        assert_eq!(transition_labels, labels[..13]);
        let state = transitioned.state.unwrap();
        assert_eq!(state.root.config(), vec!["finished"]);
        assert_eq!(state.root.owned_instances.len(), 1);
        assert!(state.root.owned_instances[0].holder_path.is_none());
    }

    #[test]
    fn every_cascade_entry_point_classifies_cleanup_failures_atomically() {
        for mode in ["cancel", "holder", "stop", "completion", "parallel"] {
            let bundle = load_bundle(&cascade_fault_bundle(mode))
                .unwrap_or_else(|error| panic!("{mode}: {error}"));
            let prior = create(
                &bundle,
                "owner",
                &format!("cascade-{mode}"),
                &format!("create-cascade-{mode}"),
                &Bindings::default(),
            )
            .state
            .unwrap();
            let result = dispatch(
                &bundle,
                &prior,
                Some(Delivery::Input(Envelope {
                    event: "trigger".to_string(),
                    event_id: format!("trigger-{mode}"),
                    target: runtime_target(&prior.root, &prior.root_instance_id),
                    payload: BTreeMap::new(),
                    correlation_id: None,
                })),
            );
            assert_eq!(result.status, ResultStatus::Faulted, "{mode}: {result:?}");
            assert_eq!(result.disposition, Some(Disposition::Faulted), "{mode}");
            let fault = result.fault.as_ref().unwrap();
            assert_eq!(fault.code, "cascade_fault", "{mode}");
            assert_eq!(fault.source_locator, "system:cascade_cleanup", "{mode}");
            assert!(result.emissions.is_empty(), "{mode}");
            let state = result.state.unwrap();
            assert_eq!(state.root.status, RuntimeStatus::Faulted, "{mode}");
            assert_eq!(
                state.root.components.len(),
                prior.root.components.len(),
                "{mode}"
            );
            assert_eq!(
                state.root.owned_instances.len(),
                prior.root.owned_instances.len(),
                "{mode}"
            );
            assert!(state
                .root
                .components
                .iter()
                .all(|component| component.runtime.status == RuntimeStatus::Running));
            assert!(state
                .root
                .owned_instances
                .iter()
                .all(|owned| owned.runtime.status == RuntimeStatus::Running));
        }
    }
}
