use super::cel::{self, Environment};
use super::compile::{
    hash_json, root_external_variables, root_input_variables, Bundle, CompiledAction,
    CompiledActionKind, CompiledChoice, CompiledSendTarget, CompiledStateKind, CompiledTarget,
    CompiledTransition, Component, ComponentDefinition, Machine, State,
};
use super::model::{
    BindingExpressions, Bindings, Delivery, Envelope, EventDeclaration, EventDirection, Target,
    VariableDeclaration,
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
    pub runtime_id: String,
    pub cause_id: String,
    pub code: String,
    pub step_sequence: u64,
    pub source_locator: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Emission {
    pub event: String,
    pub event_id: Option<String>,
    pub target: Target,
    pub payload: BTreeMap<String, Value>,
    pub correlation_id: Option<String>,
    pub effect_id: Option<String>,
    pub sequence: Option<u64>,
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

#[derive(Debug, Clone)]
pub struct AggregateState {
    pub validated_bundle_fingerprint: String,
    pub namespace: String,
    pub root_instance_id: String,
    pub root: RuntimeState,
    pub next_logical_step_sequence: u64,
    pub next_output_sequence: u64,
}

#[derive(Debug, Clone)]
pub struct RuntimeState {
    pub runtime_id: String,
    pub machine_id: String,
    pub machine_version: i64,
    pub definition: Machine,
    pub status: RuntimeStatus,
    pub active: BTreeSet<String>,
    pub variables: BTreeMap<String, VariableSlot>,
    pub history: BTreeMap<String, Option<Vec<String>>>,
    pub components: Vec<ComponentRuntime>,
    pub owned_instances: Vec<OwnedRuntime>,
    pub next_spawn_sequence: u64,
    pub next_component_activation_sequence: BTreeMap<String, u64>,
    pub next_state_activation_sequence: BTreeMap<String, u64>,
    pub active_state_activation_sequence: BTreeMap<String, u64>,
    pub fault: Option<FaultRecord>,
    pub relation: RuntimeRelation,
}

#[derive(Debug, Clone)]
pub struct VariableSlot {
    pub name: String,
    pub declaration_path: String,
    pub declaration_pointer: String,
    pub declaration: VariableDeclaration,
    pub value: Value,
    pub state_activation_sequence: u64,
}

#[derive(Debug, Clone)]
pub enum RuntimeRelation {
    Root,
    Component {
        owner_runtime_id: String,
        owner_state_path: String,
        component_id: String,
        component_pointer: String,
        declaration_index: usize,
        activation_sequence: u64,
    },
    Spawned {
        owner_runtime_id: String,
        spawn_sequence: u64,
        spawn_pointer: String,
        reference: InstanceReference,
        holder_path: Option<String>,
        holder_pointer: Option<String>,
        holder_activation_sequence: u64,
    },
}

#[derive(Debug, Clone)]
pub struct ComponentRuntime {
    pub component_id: String,
    pub pointer: String,
    pub declaration_index: usize,
    pub activation_sequence: u64,
    pub runtime: RuntimeState,
}

#[derive(Debug, Clone)]
pub struct OwnedRuntime {
    pub spawn_sequence: u64,
    pub holder_path: Option<String>,
    pub holder_pointer: Option<String>,
    pub holder_activation_sequence: u64,
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
    step_sequence: u64,
    cause_id: String,
    next_output_sequence: &'a mut u64,
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
    let mut aggregate = AggregateState {
        validated_bundle_fingerprint: bundle.fingerprint.clone(),
        namespace: bundle.namespace.clone(),
        root_instance_id: root_instance_id.to_string(),
        root: RuntimeState::new(
            root_runtime_id.clone(),
            machine.clone(),
            RuntimeRelation::Root,
        ),
        next_logical_step_sequence: 0,
        next_output_sequence: 0,
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
        0,
        &machine.root_pointer,
        0,
    );
    let mut emissions = Vec::new();
    let mut context = StepContext {
        bundle,
        root_instance_id,
        step_sequence: 0,
        cause_id: cause_id.clone(),
        next_output_sequence: &mut aggregate.next_output_sequence,
        emissions: &mut emissions,
    };
    let initialization = initialize_runtime(&mut aggregate.root, bindings, &mut context, true);
    aggregate.next_logical_step_sequence = 1;
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
                runtime_id: root_runtime_id,
                cause_id,
                code: fault.code.to_string(),
                step_sequence: 0,
                source_locator: fault.source_locator,
            };
            let mut diagnostic = RuntimeState::new(
                aggregate.root.runtime_id.clone(),
                machine,
                RuntimeRelation::Root,
            );
            diagnostic.status = RuntimeStatus::Faulted;
            diagnostic.fault = Some(record.clone());
            aggregate.root = diagnostic;
            aggregate.next_output_sequence = 0;
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
    let address = match resolve_delivery_target(prior_state, &envelope.target) {
        Ok(address) => address,
        Err(code) => return rejected_dispatch(prior_state, code),
    };
    if prior_state.root.status == RuntimeStatus::Faulted {
        return rejected_dispatch(prior_state, "invalid_instance_target");
    }
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
    let step_sequence = aggregate.next_logical_step_sequence;
    aggregate.next_logical_step_sequence += 1;
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
            step_sequence,
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
                step_sequence,
                &mut emissions,
                bundle,
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
    Component(String, u64),
    Spawn(u64),
}

type RuntimeAddress = Vec<AddressSegment>;

impl RuntimeState {
    fn new(runtime_id: String, definition: Machine, relation: RuntimeRelation) -> Self {
        let history = definition
            .states
            .values()
            .filter(|state| !matches!(state.history, super::model::HistoryKind::None))
            .map(|state| (state.path.clone(), None))
            .collect();
        Self {
            runtime_id,
            machine_id: definition.machine_id.clone(),
            machine_version: definition.version,
            definition,
            status: RuntimeStatus::Running,
            active: BTreeSet::new(),
            variables: BTreeMap::new(),
            history,
            components: Vec::new(),
            owned_instances: Vec::new(),
            next_spawn_sequence: 0,
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
    let step_sequence = aggregate.next_logical_step_sequence;
    aggregate.next_logical_step_sequence += 1;
    let runtime = runtime_at_mut(&mut aggregate.root, address).expect("fault target was validated");
    let record = FaultRecord {
        runtime_id: runtime.runtime_id.clone(),
        cause_id: envelope.event_id.clone(),
        code: fault.code.to_string(),
        step_sequence,
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
    !state.validated_bundle_fingerprint.is_empty()
        && !state.namespace.is_empty()
        && !state.root_instance_id.is_empty()
        && !state.root.runtime_id.is_empty()
        && !state.root.machine_id.is_empty()
        && state.root.machine_version > 0
        && matches!(state.root.relation, RuntimeRelation::Root)
        && state
            .root
            .active
            .iter()
            .all(|path| state.root.definition.states.contains_key(path))
        && state.root.variables.values().all(|slot| {
            state
                .root
                .definition
                .states
                .get(&slot.declaration_path)
                .and_then(|definition| definition.variables.get(&slot.name))
                .is_some()
                && (slot.declaration.value_type == "instance_reference"
                    && matches!(slot.value, Value::Null | Value::InstanceReference(_))
                    || slot
                        .value
                        .normalize_for_type(&slot.declaration.value_type)
                        .is_some())
        })
        && matches!(
            state.root.status,
            RuntimeStatus::Running | RuntimeStatus::Completed | RuntimeStatus::Faulted
        )
}

fn validate_prior_state_bundle_binding(state: &AggregateState, bundle: &Bundle) -> bool {
    state.namespace == bundle.namespace
        && bundle
            .machines
            .get(&state.root.machine_id)
            .is_some_and(|machine| {
                machine.version == state.root.machine_version
                    && machine.machine_index == state.root.definition.machine_index
                    && machine.root_pointer == state.root.definition.root_pointer
                    && machine
                        .states
                        .keys()
                        .eq(state.root.definition.states.keys())
            })
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
        Target::SpawnedInstance(reference)
            if reference.root_instance_id == aggregate.root_instance_id =>
        {
            find_spawn_address(&aggregate.root, &reference.instance_id)
                .ok_or("invalid_instance_target")
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
            *activation_sequence,
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

fn find_spawn_address(runtime: &RuntimeState, instance_id: &str) -> Option<RuntimeAddress> {
    for owned in &runtime.owned_instances {
        if owned.reference.instance_id == instance_id {
            return Some(vec![AddressSegment::Spawn(owned.spawn_sequence)]);
        }
        if let Some(mut nested) = find_spawn_address(&owned.runtime, instance_id) {
            let mut address = vec![AddressSegment::Spawn(owned.spawn_sequence)];
            address.append(&mut nested);
            return Some(address);
        }
    }
    for component in &runtime.components {
        if let Some(mut nested) = find_spawn_address(&component.runtime, instance_id) {
            let mut address = vec![AddressSegment::Component(
                component.component_id.clone(),
                component.activation_sequence,
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
    activation_sequence: u64,
) -> Option<RuntimeAddress> {
    if runtime.runtime_id == owner_runtime_id {
        let component = runtime.components.iter().find(|component| {
            component.component_id == component_id
                && component.activation_sequence == activation_sequence
                && component.runtime.runtime_id == component_runtime_id
        })?;
        return Some(vec![AddressSegment::Component(
            component.component_id.clone(),
            component.activation_sequence,
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
                component.activation_sequence,
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
            let mut address = vec![AddressSegment::Spawn(owned.spawn_sequence)];
            address.append(&mut nested);
            return Some(address);
        }
    }
    None
}

fn root_runtime_identity(bundle: &Bundle, machine: &Machine, root_instance_id: &str) -> String {
    hash_json(serde_json::json!([
        "determa-root-runtime-identity-2",
        "1",
        bundle.fingerprint,
        bundle.namespace,
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
    step_sequence: u64,
    source_locator: &str,
    ordinal: u64,
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
    step_sequence: u64,
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
    step_sequence: u64,
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
    activation_sequence: u64,
    machine: &Machine,
) -> String {
    hash_json(serde_json::json!([
        "determa-component-runtime-identity-1",
        "1",
        root_instance_id,
        owner_runtime_id,
        component.pointer,
        activation_sequence.to_string(),
        bundle.namespace,
        machine.machine_id,
        machine.version.to_string()
    ]))
}

fn spawned_runtime_identity(
    bundle: &Bundle,
    root_instance_id: &str,
    owner_runtime_id: &str,
    spawn_pointer: &str,
    spawn_sequence: u64,
    machine: &Machine,
) -> String {
    hash_json(serde_json::json!([
        "determa-spawned-runtime-identity-1",
        "1",
        root_instance_id,
        owner_runtime_id,
        spawn_pointer,
        spawn_sequence.to_string(),
        bundle.namespace,
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
            if matches!(mode, DeliveryMode::Input)
                && !matches!(
                    envelope.target,
                    Target::Root { .. } | Target::SpawnedInstance(_)
                )
            {
                return Err("invalid_instance_target");
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
            for (name, value) in changed {
                let Some(declaration) = external.get(name) else {
                    return Err("invalid_payload");
                };
                if value.normalize_for_type(&declaration.value_type).is_none() {
                    return Err("invalid_payload");
                }
            }
            return Ok(envelope.clone());
        }
        "done"
        | "determa.component_completed"
        | "determa.component_failed"
        | "determa.spawned_instance_failed" => {
            if matches!(mode, DeliveryMode::Input) {
                return Err("invalid_event");
            }
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
    if declaration.correlates_to.is_some()
        && envelope
            .correlation_id
            .as_ref()
            .is_none_or(String::is_empty)
    {
        return Err("invalid_correlation");
    }
    if declaration.correlates_to.is_none() && envelope.correlation_id.is_some() {
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
        .or_insert(0);
    let allocated_activation = *activation_sequence;
    *activation_sequence += 1;
    runtime
        .active_state_activation_sequence
        .insert(path.to_string(), allocated_activation);
    runtime.active.insert(path.to_string());

    if state.kind == CompiledStateKind::Parallel {
        allocate_components(runtime, &state, context)?;
    }
    initialize_state_variables(
        runtime,
        &state,
        bindings,
        allocated_activation,
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
    state_activation_sequence: u64,
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
                state_activation_sequence,
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
                    cancel_owned(runtime, &reference, context)?;
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
            let sequence = *context.next_output_sequence;
            *context.next_output_sequence += 1;
            context.emissions.push(Emission {
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
                    context.step_sequence,
                    &action.pointer,
                    ordinal,
                )),
                sequence: Some(sequence),
            });
        } else {
            let target_runtime_id = target_runtime_id(&target);
            context.emissions.push(Emission {
                event: event.to_string(),
                event_id: Some(internal_event_identity(
                    context.root_instance_id,
                    &runtime.runtime_id,
                    &target_runtime_id,
                    &context.cause_id,
                    context.step_sequence,
                    &action.pointer,
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
            Ok(Target::Component {
                root_instance_id: root_instance_id.to_string(),
                owner_runtime_id: runtime.runtime_id.clone(),
                component_id: component.component_id.clone(),
                component_runtime_id: component.runtime.runtime_id.clone(),
                activation_sequence: component.activation_sequence,
            })
        }
        CompiledSendTarget::Instance(_) => {
            let Some(Value::InstanceReference(reference)) = dynamic else {
                return Err(StepFault {
                    code: "invalid_instance_target",
                    source_locator: target_expression_pointer(action, targets, index),
                });
            };
            if find_spawn_address(runtime, &reference.instance_id).is_none() {
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
    match &runtime.relation {
        RuntimeRelation::Root => Target::Root {
            root_instance_id: root_instance_id.to_string(),
            root_runtime_id: runtime.runtime_id.clone(),
        },
        RuntimeRelation::Component {
            owner_runtime_id,
            component_id,
            activation_sequence,
            ..
        } => Target::Component {
            root_instance_id: root_instance_id.to_string(),
            owner_runtime_id: owner_runtime_id.clone(),
            component_id: component_id.clone(),
            component_runtime_id: runtime.runtime_id.clone(),
            activation_sequence: *activation_sequence,
        },
        RuntimeRelation::Spawned { reference, .. } => Target::SpawnedInstance(reference.clone()),
    }
}

fn owner_target(runtime: &RuntimeState, root_instance_id: &str) -> Option<Target> {
    match &runtime.relation {
        RuntimeRelation::Root => None,
        RuntimeRelation::Component {
            owner_runtime_id, ..
        }
        | RuntimeRelation::Spawned {
            owner_runtime_id, ..
        } => Some(Target::Root {
            root_instance_id: root_instance_id.to_string(),
            root_runtime_id: owner_runtime_id.clone(),
        }),
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
    let spawn_sequence = runtime.next_spawn_sequence;
    runtime.next_spawn_sequence += 1;
    let instance_id = spawned_runtime_identity(
        context.bundle,
        context.root_instance_id,
        &runtime.runtime_id,
        &action.pointer,
        spawn_sequence,
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
            slot.state_activation_sequence,
        )
    } else {
        (None, None, 0)
    };
    let relation = RuntimeRelation::Spawned {
        owner_runtime_id: runtime.runtime_id.clone(),
        spawn_sequence,
        spawn_pointer: action.pointer.clone(),
        reference: reference.clone(),
        holder_path: holder_path.clone(),
        holder_pointer: holder_pointer.clone(),
        holder_activation_sequence,
    };
    let mut child = RuntimeState::new(instance_id.clone(), machine, relation);
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
        context.step_sequence,
        &action.pointer,
        spawn_sequence,
    );
    let parent_cause = std::mem::replace(&mut context.cause_id, child_cause.clone());
    let initialization = initialize_runtime(&mut child, &bindings, context, true);
    context.cause_id = parent_cause;
    if let Err(fault) = initialization {
        let record = FaultRecord {
            runtime_id: child.runtime_id.clone(),
            cause_id: child_cause,
            code: fault.code.to_string(),
            step_sequence: context.step_sequence,
            source_locator: fault.source_locator,
        };
        child = RuntimeState::new(
            child.runtime_id.clone(),
            child.definition.clone(),
            child.relation.clone(),
        );
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
            .or_insert(0);
        let activation_sequence = *next;
        *next += 1;
        let machine = match &component.definition {
            ComponentDefinition::Machine(machine_id) => context.bundle.machines[machine_id].clone(),
            ComponentDefinition::Inline(machine) => machine.as_ref().clone(),
        };
        let runtime_id = component_runtime_identity(
            context.bundle,
            context.root_instance_id,
            &runtime.runtime_id,
            component,
            activation_sequence,
            &machine,
        );
        let relation = RuntimeRelation::Component {
            owner_runtime_id: runtime.runtime_id.clone(),
            owner_state_path: state.path.clone(),
            component_id: component.component_id.clone(),
            component_pointer: component.pointer.clone(),
            declaration_index: component.declaration_index,
            activation_sequence,
        };
        runtime.components.push(ComponentRuntime {
            component_id: component.component_id.clone(),
            pointer: component.pointer.clone(),
            declaration_index: component.declaration_index,
            activation_sequence,
            runtime: RuntimeState::new(runtime_id, machine, relation),
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
            context.step_sequence,
            &component_definition.pointer,
            component_definition.declaration_index as u64,
        );
        let parent_cause = std::mem::replace(&mut context.cause_id, child_cause.clone());
        let initialization = initialize_runtime(child, &bindings, context, true);
        context.cause_id = parent_cause;
        if let Err(fault) = initialization {
            let relation = child.relation.clone();
            let definition = child.definition.clone();
            let runtime_id = child.runtime_id.clone();
            let record = FaultRecord {
                runtime_id: runtime_id.clone(),
                cause_id: child_cause,
                code: fault.code.to_string(),
                step_sequence: context.step_sequence,
                source_locator: fault.source_locator,
            };
            *child = RuntimeState::new(runtime_id, definition, relation);
            child.status = RuntimeStatus::Faulted;
            child.fault = Some(record.clone());
            emit_failure_notification(child, &record, context);
        }
    }
    Ok(())
}

fn complete_runtime(
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
    component_indices.sort_by_key(|index| {
        let component = &runtime.components[*index];
        std::cmp::Reverse((
            component.pointer.clone(),
            component.declaration_index,
            component.activation_sequence,
        ))
    });
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
    selected.sort_by_key(|index| {
        let owned = &runtime.owned_instances[*index];
        (
            owned.holder_pointer.clone().unwrap_or_default(),
            owned.holder_activation_sequence,
            owned.spawn_sequence,
        )
    });
    let selected_sequences = selected
        .iter()
        .map(|index| runtime.owned_instances[*index].spawn_sequence)
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
    component_indices.sort_by_key(|index| {
        let component = &runtime.components[*index];
        std::cmp::Reverse((
            component.pointer.clone(),
            component.declaration_index,
            component.activation_sequence,
        ))
    });
    for index in component_indices {
        cleanup_runtime(&mut runtime.components[index].runtime, context)?;
    }
    runtime.components.clear();
    let mut owned_indices = (0..runtime.owned_instances.len()).collect::<Vec<_>>();
    owned_indices.sort_by_key(|index| {
        let owned = &runtime.owned_instances[*index];
        (
            usize::from(owned.holder_path.is_none()),
            owned.holder_pointer.clone().unwrap_or_default(),
            owned.holder_activation_sequence,
            owned.spawn_sequence,
        )
    });
    for index in owned_indices {
        cleanup_runtime(&mut runtime.owned_instances[index].runtime, context)?;
    }
    runtime.owned_instances.clear();
    Ok(())
}

fn cleanup_runtime(
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

fn cancel_owned(
    runtime: &mut RuntimeState,
    reference: &InstanceReference,
    context: &mut StepContext<'_>,
) -> Result<(), StepFault> {
    if let Some(index) = runtime
        .owned_instances
        .iter()
        .position(|owned| owned.reference == *reference)
    {
        cleanup_runtime(&mut runtime.owned_instances[index].runtime, context)?;
        runtime.owned_instances.remove(index);
        return Ok(());
    }
    for owned in &mut runtime.owned_instances {
        if cancel_owned(&mut owned.runtime, reference, context).is_ok()
            && find_spawn_address(&owned.runtime, &reference.instance_id).is_none()
        {
            return Ok(());
        }
    }
    Ok(())
}

fn emit_completion_notification(runtime: &RuntimeState, context: &mut StepContext<'_>) {
    match &runtime.relation {
        RuntimeRelation::Root => {}
        RuntimeRelation::Component {
            owner_runtime_id,
            owner_state_path,
            component_id,
            ..
        } => {
            let target = Target::Root {
                root_instance_id: context.root_instance_id.to_string(),
                root_runtime_id: owner_runtime_id.clone(),
            };
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
            owner_runtime_id,
            reference,
            ..
        } => {
            let target = Target::Root {
                root_instance_id: context.root_instance_id.to_string(),
                root_runtime_id: owner_runtime_id.clone(),
            };
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
            owner_runtime_id,
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
                Target::Root {
                    root_instance_id: context.root_instance_id.to_string(),
                    root_runtime_id: owner_runtime_id.clone(),
                },
                payload,
                "system:component_failure",
                0,
                context,
            );
        }
        RuntimeRelation::Spawned {
            owner_runtime_id,
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
                Target::Root {
                    root_instance_id: context.root_instance_id.to_string(),
                    root_runtime_id: owner_runtime_id.clone(),
                },
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
        event: event.to_string(),
        event_id: Some(internal_event_identity(
            context.root_instance_id,
            &runtime.runtime_id,
            &target_runtime_id(&target),
            &context.cause_id,
            context.step_sequence,
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
    step_sequence: u64,
    emissions: &mut Vec<Emission>,
    bundle: &Bundle,
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
    let target = runtime_target(owner, &aggregate.root_instance_id);
    let payload = BTreeMap::from([
        (
            "relationship".to_string(),
            Value::String("parallel".to_string()),
        ),
        (
            "state_path".to_string(),
            Value::String(owner_state_path.clone()),
        ),
        (
            "owner_runtime_id".to_string(),
            Value::String(owner.runtime_id.clone()),
        ),
    ]);
    let event_id = internal_event_identity(
        &aggregate.root_instance_id,
        &owner.runtime_id,
        &owner.runtime_id,
        cause_id,
        step_sequence,
        "system:component_completion",
        1,
    );
    let _ = bundle;
    emissions.push(Emission {
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
