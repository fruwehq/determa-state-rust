use super::cel;
use super::model::{
    Action, BindingExpressions, ChoiceBranch, EventDeclaration, EventDirection, HistoryKind,
    InitialTransition, RawBundle, RawComponent, RawMachine, RawState, StateType, TargetExpression,
    Transition, TransitionOrList, TransitionTarget, VariableDeclaration,
};
use super::source::{escape_pointer, LoadErrorCode};
use crate::value::Value;
use serde_json::{Map, Value as JsonValue};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

#[derive(Debug, Clone)]
pub struct SemanticError {
    pub code: LoadErrorCode,
    pub path: String,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct Bundle {
    pub namespace: String,
    pub events: BTreeMap<String, EventDeclaration>,
    pub machines: BTreeMap<String, Machine>,
    pub machine_order: Vec<String>,
    pub fingerprint: String,
    pub normalized: JsonValue,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Machine {
    pub machine_id: String,
    pub version: i64,
    pub machine_index: usize,
    pub events: BTreeMap<String, EventDeclaration>,
    pub states: BTreeMap<String, State>,
    pub root_pointer: String,
    pub meta: Option<JsonValue>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct State {
    pub path: String,
    pub pointer: String,
    pub parent: Option<String>,
    pub kind: CompiledStateKind,
    pub variables: BTreeMap<String, VariableDeclaration>,
    pub entry: Vec<CompiledAction>,
    pub exit: Vec<CompiledAction>,
    pub initial: Option<CompiledInitial>,
    pub children: Vec<String>,
    pub components: Vec<Component>,
    pub handlers: BTreeMap<String, Vec<CompiledTransition>>,
    pub history: HistoryKind,
    pub choice: Option<Vec<CompiledChoice>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompiledStateKind {
    Simple,
    Composite,
    Parallel,
    Final,
    Choice,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Component {
    pub component_id: String,
    pub declaration_index: usize,
    pub pointer: String,
    pub definition: ComponentDefinition,
    pub bindings: BindingExpressions,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ComponentDefinition {
    Machine(String),
    Inline(Box<Machine>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct CompiledInitial {
    pub target: String,
    pub action: Vec<CompiledAction>,
    pub pointer: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CompiledChoice {
    pub target: CompiledTarget,
    pub guard: Option<String>,
    pub guard_pointer: Option<String>,
    pub action: Vec<CompiledAction>,
    pub pointer: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CompiledTransition {
    pub target: Option<CompiledTarget>,
    pub guard: Option<String>,
    pub guard_pointer: Option<String>,
    pub action: Vec<CompiledAction>,
    pub local: bool,
    pub pointer: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CompiledTarget {
    State(String),
    History(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct CompiledAction {
    pub kind: CompiledActionKind,
    pub pointer: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CompiledActionKind {
    Assign {
        variable: String,
        expression: String,
    },
    Send {
        event: String,
        targets: Vec<CompiledSendTarget>,
        payload: BTreeMap<String, String>,
        correlation_id: Option<String>,
    },
    Refresh {
        only: Option<Vec<String>>,
    },
    Spawn {
        machine_id: String,
        bindings: BindingExpressions,
        bind_to: Option<String>,
    },
    Cancel {
        instance: String,
    },
    Stop,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CompiledSendTarget {
    SelfTarget,
    Owner,
    Component(String),
    Instance(String),
    External,
}

pub fn compile_bundle(mut document: JsonValue) -> Result<Bundle, SemanticError> {
    normalize_bundle(&mut document)?;
    reject_fractional_machine_versions(&document)?;
    let raw: RawBundle =
        serde_json::from_value(document.clone()).map_err(|error| SemanticError {
            code: LoadErrorCode::StructuralValidation,
            path: "/".to_string(),
            message: error.to_string(),
        })?;
    if raw.format != 1 {
        return semantic("/", "format must be the integer 1");
    }

    let fingerprint = typed_hash(&[
        JsonValue::String("determa-validated-bundle-fingerprint-1".to_string()),
        typed_projection(&document),
    ]);
    let mut machines = BTreeMap::new();
    let mut machine_order = Vec::new();
    let all_machine_ids: HashSet<String> = raw
        .machines
        .iter()
        .map(|machine| machine.machine_id.clone())
        .collect();
    if all_machine_ids.len() != raw.machines.len() {
        return semantic("/machines", "machine_id values must be unique");
    }
    validate_event_defaults(&raw.events, "/events")?;
    for (machine_index, raw_machine) in raw.machines.iter().enumerate() {
        validate_event_defaults(
            &raw_machine.events,
            &format!("/machines/{machine_index}/events"),
        )?;
        let machine = compile_machine(
            raw_machine,
            machine_index,
            &raw.namespace,
            &raw.events,
            &all_machine_ids,
        )?;
        machine_order.push(machine.machine_id.clone());
        machines.insert(machine.machine_id.clone(), machine);
    }
    validate_bindings_across_bundle(&machines)?;
    validate_cel_across_bundle(&machines, &raw.events)?;
    validate_public_events(&raw.events)?;
    validate_initialization_cycles(&machines)?;
    Ok(Bundle {
        namespace: raw.namespace,
        events: raw.events,
        machines,
        machine_order,
        fingerprint,
        normalized: document,
    })
}

fn reject_fractional_machine_versions(document: &JsonValue) -> Result<(), SemanticError> {
    let Some(machines) = document.get("machines").and_then(JsonValue::as_array) else {
        return Ok(());
    };
    for (index, machine) in machines.iter().enumerate() {
        if machine
            .get("version")
            .and_then(JsonValue::as_number)
            .is_some_and(|number| number.as_i64().is_none())
        {
            return semantic(
                &format!("/machines/{index}/version"),
                "machine version must use an integer source value",
            );
        }
    }
    Ok(())
}

fn validate_event_defaults(
    events: &BTreeMap<String, EventDeclaration>,
    pointer: &str,
) -> Result<(), SemanticError> {
    for (event_name, event) in events {
        for (field_name, field) in &event.payload {
            if let Some(default) = &field.default {
                if default.normalize_for_type(&field.value_type).is_none() {
                    return semantic(
                        &format!(
                            "{}/{}/payload/{}/default",
                            pointer,
                            escape_pointer(event_name),
                            escape_pointer(field_name)
                        ),
                        "payload default does not match its declared type",
                    );
                }
            }
        }
    }
    Ok(())
}

fn compile_machine(
    raw: &RawMachine,
    machine_index: usize,
    namespace: &str,
    bundle_events: &BTreeMap<String, EventDeclaration>,
    all_machine_ids: &HashSet<String>,
) -> Result<Machine, SemanticError> {
    let root_pointer = format!("/machines/{machine_index}/root");
    let mut states = BTreeMap::new();
    let mut component_ids = HashSet::new();
    compile_state(
        &raw.root,
        "root",
        &root_pointer,
        None,
        raw,
        machine_index,
        namespace,
        bundle_events,
        all_machine_ids,
        &mut states,
        &mut component_ids,
    )?;
    let mut machine = Machine {
        machine_id: raw.machine_id.clone(),
        version: raw.version,
        machine_index,
        events: raw.events.clone(),
        states,
        root_pointer,
        meta: raw.meta.clone(),
    };
    resolve_machine_targets(&mut machine)?;
    validate_machine(&machine, bundle_events, all_machine_ids)?;
    Ok(machine)
}

fn resolve_machine_targets(machine: &mut Machine) -> Result<(), SemanticError> {
    let paths = machine.states.keys().cloned().collect::<Vec<_>>();
    let snapshot = machine.clone();
    for path in paths {
        let state = machine.states.get_mut(&path).expect("state path");
        if let Some(initial) = &mut state.initial {
            initial.target = resolve_state_reference(&snapshot, &path, &initial.target)
                .ok_or_else(|| SemanticError {
                    code: LoadErrorCode::SemanticValidation,
                    path: format!("{}/transition_to", initial.pointer),
                    message: format!("unknown state target {:?}", initial.target),
                })?;
        }
        for transitions in state.handlers.values_mut() {
            for transition in transitions {
                if let Some(target) = &mut transition.target {
                    resolve_compiled_target(&snapshot, &path, target, &transition.pointer)?;
                }
            }
        }
        if let Some(branches) = &mut state.choice {
            for branch in branches {
                resolve_compiled_target(&snapshot, &path, &mut branch.target, &branch.pointer)?;
            }
        }
    }
    Ok(())
}

fn resolve_compiled_target(
    machine: &Machine,
    source: &str,
    target: &mut CompiledTarget,
    pointer: &str,
) -> Result<(), SemanticError> {
    let raw = match target {
        CompiledTarget::State(path) | CompiledTarget::History(path) => path.clone(),
    };
    let resolved = resolve_state_reference(machine, source, &raw).ok_or_else(|| SemanticError {
        code: LoadErrorCode::SemanticValidation,
        path: format!("{pointer}/transition_to"),
        message: format!("unknown state target {raw:?}"),
    })?;
    match target {
        CompiledTarget::State(path) | CompiledTarget::History(path) => *path = resolved,
    }
    Ok(())
}

fn resolve_state_reference(machine: &Machine, source: &str, raw: &str) -> Option<String> {
    if machine.states.contains_key(raw) {
        return Some(raw.to_string());
    }
    let mut scope = Some(source.to_string());
    while let Some(path) = scope {
        let child = if path == "root" {
            raw.to_string()
        } else {
            format!("{path}.{raw}")
        };
        if machine.states.contains_key(&child) {
            return Some(child);
        }
        let sibling = machine.states[&path].parent.as_ref().map(|parent| {
            if parent == "root" {
                raw.to_string()
            } else {
                format!("{parent}.{raw}")
            }
        });
        if let Some(sibling) = sibling {
            if machine.states.contains_key(&sibling) {
                return Some(sibling);
            }
        }
        scope = machine.states[&path].parent.clone();
    }
    let suffix = format!(".{raw}");
    let matches = machine
        .states
        .keys()
        .filter(|path| path.ends_with(&suffix))
        .cloned()
        .collect::<Vec<_>>();
    (matches.len() == 1).then(|| matches[0].clone())
}

#[allow(clippy::too_many_arguments)]
fn compile_state(
    raw: &RawState,
    path: &str,
    pointer: &str,
    parent: Option<&str>,
    raw_machine: &RawMachine,
    machine_index: usize,
    namespace: &str,
    bundle_events: &BTreeMap<String, EventDeclaration>,
    all_machine_ids: &HashSet<String>,
    states: &mut BTreeMap<String, State>,
    component_ids: &mut HashSet<String>,
) -> Result<(), SemanticError> {
    let kind = if raw.choice.is_some() {
        CompiledStateKind::Choice
    } else {
        match raw.state_type.unwrap_or(StateType::Simple) {
            StateType::Simple => CompiledStateKind::Simple,
            StateType::Composite => CompiledStateKind::Composite,
            StateType::Parallel => CompiledStateKind::Parallel,
            StateType::Final => CompiledStateKind::Final,
        }
    };
    let mut children = Vec::new();
    for (name, child) in &raw.states {
        let child_path = if path == "root" {
            name.clone()
        } else {
            format!("{path}.{name}")
        };
        let child_pointer = format!("{pointer}/states/{}", escape_pointer(name));
        compile_state(
            child,
            &child_path,
            &child_pointer,
            Some(path),
            raw_machine,
            machine_index,
            namespace,
            bundle_events,
            all_machine_ids,
            states,
            component_ids,
        )?;
        children.push(child_path);
    }

    let mut components = Vec::new();
    for (index, raw_component) in raw.components.iter().enumerate() {
        if !component_ids.insert(raw_component.component_id.clone()) {
            return semantic(
                &format!("{pointer}/components/{index}/component_id"),
                "component_id must be unique in the containing machine",
            );
        }
        let component_pointer = format!("{pointer}/components/{index}");
        components.push(compile_component(
            raw_component,
            index,
            &component_pointer,
            raw_machine,
            machine_index,
            namespace,
            bundle_events,
            all_machine_ids,
        )?);
    }

    let entry = compile_actions(&raw.entry, &format!("{pointer}/entry"))?;
    let exit = compile_actions(&raw.exit, &format!("{pointer}/exit"))?;
    let initial = raw
        .initial
        .as_ref()
        .map(|initial| compile_initial(initial, pointer))
        .transpose()?;
    let mut handlers = BTreeMap::new();
    for (event, transitions) in &raw.on_events {
        let list = match transitions.clone() {
            TransitionOrList::One(transition) => vec![transition],
            TransitionOrList::List(transitions) => transitions,
        };
        let base = format!("{pointer}/on_events/{}", escape_pointer(event));
        let compiled = list
            .iter()
            .enumerate()
            .map(|(index, transition)| {
                let transition_pointer = if list.len() == 1 {
                    base.clone()
                } else {
                    format!("{base}/{index}")
                };
                compile_transition(transition, &transition_pointer)
            })
            .collect::<Result<Vec<_>, _>>()?;
        handlers.insert(event.clone(), compiled);
    }
    let choice = raw
        .choice
        .as_ref()
        .map(|branches| {
            branches
                .iter()
                .enumerate()
                .map(|(index, branch)| compile_choice(branch, &format!("{pointer}/choice/{index}")))
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?;
    states.insert(
        path.to_string(),
        State {
            path: path.to_string(),
            pointer: pointer.to_string(),
            parent: parent.map(str::to_string),
            kind,
            variables: raw.variables.clone(),
            entry,
            exit,
            initial,
            children,
            components,
            handlers,
            history: raw.history.unwrap_or(HistoryKind::None),
            choice,
        },
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn compile_component(
    raw: &RawComponent,
    declaration_index: usize,
    pointer: &str,
    containing_machine: &RawMachine,
    machine_index: usize,
    namespace: &str,
    bundle_events: &BTreeMap<String, EventDeclaration>,
    all_machine_ids: &HashSet<String>,
) -> Result<Component, SemanticError> {
    validate_binding_expressions(&raw.bindings, &format!("{pointer}/with"))?;
    let definition = if let Some(machine_id) = &raw.machine_id {
        if !all_machine_ids.contains(machine_id) {
            return semantic(
                &format!("{pointer}/machine_id"),
                "component references an unknown machine_id",
            );
        }
        ComponentDefinition::Machine(machine_id.clone())
    } else if let Some(root) = &raw.root {
        let inline_raw = RawMachine {
            machine_id: containing_machine.machine_id.clone(),
            version: containing_machine.version,
            languages: containing_machine.languages.clone(),
            events: containing_machine.events.clone(),
            root: root.clone(),
            meta: raw.meta.clone(),
        };
        let mut states = BTreeMap::new();
        let mut component_ids = HashSet::new();
        compile_state(
            root,
            "root",
            &format!("{pointer}/root"),
            None,
            &inline_raw,
            machine_index,
            namespace,
            bundle_events,
            all_machine_ids,
            &mut states,
            &mut component_ids,
        )?;
        let mut machine = Machine {
            machine_id: containing_machine.machine_id.clone(),
            version: containing_machine.version,
            machine_index,
            events: containing_machine.events.clone(),
            states,
            root_pointer: format!("{pointer}/root"),
            meta: raw.meta.clone(),
        };
        resolve_machine_targets(&mut machine)?;
        validate_machine(&machine, bundle_events, all_machine_ids)?;
        ComponentDefinition::Inline(Box::new(machine))
    } else {
        return semantic(pointer, "component has no definition");
    };
    Ok(Component {
        component_id: raw.component_id.clone(),
        declaration_index,
        pointer: pointer.to_string(),
        definition,
        bindings: raw.bindings.clone(),
    })
}

fn compile_initial(
    initial: &InitialTransition,
    state_pointer: &str,
) -> Result<CompiledInitial, SemanticError> {
    Ok(CompiledInitial {
        target: initial.transition_to.clone(),
        action: compile_actions(&initial.action, &format!("{state_pointer}/initial/action"))?,
        pointer: format!("{state_pointer}/initial"),
    })
}

fn compile_transition(
    transition: &Transition,
    pointer: &str,
) -> Result<CompiledTransition, SemanticError> {
    Ok(CompiledTransition {
        target: transition.transition_to.as_ref().map(compile_target),
        guard: transition.guard.clone(),
        guard_pointer: transition
            .guard
            .as_ref()
            .map(|_| format!("{pointer}/guard")),
        action: compile_actions(&transition.action, &format!("{pointer}/action"))?,
        local: transition.local.unwrap_or(false),
        pointer: pointer.to_string(),
    })
}

fn compile_choice(branch: &ChoiceBranch, pointer: &str) -> Result<CompiledChoice, SemanticError> {
    Ok(CompiledChoice {
        target: compile_target(&branch.transition_to),
        guard: branch.guard.clone(),
        guard_pointer: branch.guard.as_ref().map(|_| format!("{pointer}/guard")),
        action: compile_actions(&branch.action, &format!("{pointer}/action"))?,
        pointer: pointer.to_string(),
    })
}

fn compile_target(target: &TransitionTarget) -> CompiledTarget {
    match target {
        TransitionTarget::State(path) => CompiledTarget::State(path.clone()),
        TransitionTarget::History { history } => CompiledTarget::History(history.clone()),
    }
}

fn compile_actions(
    actions: &[Action],
    pointer: &str,
) -> Result<Vec<CompiledAction>, SemanticError> {
    actions
        .iter()
        .enumerate()
        .map(|(index, action)| {
            let action_pointer = format!("{pointer}/{index}");
            let kind = match action {
                Action::Assign(assignments) => {
                    let (variable, expression) = assignments
                        .iter()
                        .next()
                        .expect("schema requires one assignment");
                    CompiledActionKind::Assign {
                        variable: variable.clone(),
                        expression: expression.clone(),
                    }
                }
                Action::Send(send) => {
                    let raw_targets = if let Some(targets) = &send.targets {
                        targets.clone()
                    } else if let Some(target) = &send.to {
                        vec![target.clone()]
                    } else {
                        vec![TargetExpression::SelfTarget { _self_target: true }]
                    };
                    let targets = raw_targets
                        .iter()
                        .enumerate()
                        .map(|(target_index, target)| {
                            compile_send_target(
                                target,
                                &action_pointer,
                                send.targets.is_some(),
                                target_index,
                            )
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    CompiledActionKind::Send {
                        event: send.event.clone(),
                        targets,
                        payload: send.payload.clone(),
                        correlation_id: send.correlation_id.clone(),
                    }
                }
                Action::Refresh(refresh) => CompiledActionKind::Refresh {
                    only: refresh.only.clone(),
                },
                Action::Spawn(spawn) => {
                    validate_binding_expressions(
                        &spawn.bindings,
                        &format!("{action_pointer}/spawn/bindings"),
                    )?;
                    CompiledActionKind::Spawn {
                        machine_id: spawn.machine_id.clone(),
                        bindings: spawn.bindings.clone(),
                        bind_to: spawn.bind_to.clone(),
                    }
                }
                Action::Cancel(cancel) => CompiledActionKind::Cancel {
                    instance: cancel.instance.clone(),
                },
                Action::Stop(_) => CompiledActionKind::Stop,
            };
            Ok(CompiledAction {
                kind,
                pointer: action_pointer,
            })
        })
        .collect()
}

fn compile_send_target(
    target: &TargetExpression,
    action_pointer: &str,
    is_list: bool,
    index: usize,
) -> Result<CompiledSendTarget, SemanticError> {
    Ok(match target {
        TargetExpression::SelfTarget { .. } => CompiledSendTarget::SelfTarget,
        TargetExpression::Owner { .. } => CompiledSendTarget::Owner,
        TargetExpression::Component { component } => {
            CompiledSendTarget::Component(component.clone())
        }
        TargetExpression::Instance { instance } => {
            let _ = (action_pointer, is_list, index);
            CompiledSendTarget::Instance(instance.clone())
        }
        TargetExpression::External { .. } => CompiledSendTarget::External,
    })
}

fn validate_binding_expressions(
    bindings: &BindingExpressions,
    pointer: &str,
) -> Result<(), SemanticError> {
    let _ = (bindings, pointer);
    Ok(())
}

fn validate_public_events(
    events: &BTreeMap<String, EventDeclaration>,
) -> Result<(), SemanticError> {
    for (name, declaration) in events {
        if let Some(output) = &declaration.correlates_to {
            let Some(target) = events.get(output) else {
                return semantic(
                    &format!("/events/{}/correlates_to", escape_pointer(name)),
                    "correlates_to references an unknown event",
                );
            };
            if declaration.direction != EventDirection::Input
                || target.direction != EventDirection::Output
            {
                return semantic(
                    &format!("/events/{}/correlates_to", escape_pointer(name)),
                    "correlates_to must connect an input to an output",
                );
            }
        }
    }
    Ok(())
}

fn validate_machine(
    machine: &Machine,
    bundle_events: &BTreeMap<String, EventDeclaration>,
    all_machine_ids: &HashSet<String>,
) -> Result<(), SemanticError> {
    let event_names: HashSet<&str> = bundle_events
        .keys()
        .chain(machine.events.keys())
        .map(String::as_str)
        .collect();
    for state in machine.states.values() {
        for (name, declaration) in &state.variables {
            if let Some(init) = &declaration.init {
                let init = init.clone().unwrap_or(Value::Null);
                let valid = if declaration.value_type == "instance_reference" {
                    init == Value::Null
                } else {
                    init.normalize_for_type(&declaration.value_type).is_some()
                };
                if !valid {
                    return semantic(
                        &format!("{}/variables/{}/init", state.pointer, escape_pointer(name)),
                        "variable init does not match its declared type",
                    );
                }
            }
        }
        for (event, transitions) in &state.handlers {
            if !event_names.contains(event.as_str())
                && !matches!(
                    event.as_str(),
                    "env"
                        | "done"
                        | "determa.component_completed"
                        | "determa.component_failed"
                        | "determa.spawned_instance_failed"
                )
            {
                return semantic(
                    &format!("{}/on_events/{}", state.pointer, escape_pointer(event)),
                    "handler references an undeclared event",
                );
            }
            let mut saw_default = false;
            for transition in transitions {
                if saw_default {
                    return semantic(&transition.pointer, "an unguarded transition must be last");
                }
                saw_default = transition.guard.is_none();
                validate_transition(machine, state, transition)?;
                validate_actions(
                    machine,
                    state,
                    transition.target.as_ref(),
                    &transition.action,
                    bundle_events,
                    all_machine_ids,
                )?;
            }
        }
        if let Some(initial) = &state.initial {
            require_state(
                machine,
                &initial.target,
                &format!("{}/transition_to", initial.pointer),
            )?;
            validate_actions(
                machine,
                state,
                Some(&CompiledTarget::State(initial.target.clone())),
                &initial.action,
                bundle_events,
                all_machine_ids,
            )?;
        }
        if let Some(branches) = &state.choice {
            let defaults = branches
                .iter()
                .enumerate()
                .filter_map(|(index, branch)| branch.guard.is_none().then_some(index))
                .collect::<Vec<_>>();
            if defaults.len() != 1 || defaults[0] != branches.len() - 1 {
                return semantic(&state.pointer, "choice requires one final default branch");
            }
            for branch in branches {
                require_target(machine, &branch.target, &branch.pointer)?;
                validate_actions(
                    machine,
                    state,
                    Some(&branch.target),
                    &branch.action,
                    bundle_events,
                    all_machine_ids,
                )?;
            }
        }
        validate_actions(
            machine,
            state,
            None,
            &state.entry,
            bundle_events,
            all_machine_ids,
        )?;
        validate_actions(
            machine,
            state,
            None,
            &state.exit,
            bundle_events,
            all_machine_ids,
        )?;
    }
    validate_reachability(machine)?;
    validate_choice_cycles(machine)?;
    Ok(())
}

fn validate_transition(
    machine: &Machine,
    source: &State,
    transition: &CompiledTransition,
) -> Result<(), SemanticError> {
    if let Some(target) = &transition.target {
        require_target(machine, target, &transition.pointer)?;
        let target_path = target_path(target);
        if target_path == "root" {
            return Err(SemanticError {
                code: LoadErrorCode::RootReentry,
                path: format!("{}/transition_to", transition.pointer),
                message: "the machine root cannot be re-entered".to_string(),
            });
        }
        if transition.local {
            if source.path == "root" {
                return Err(SemanticError {
                    code: LoadErrorCode::RootLocalTransition,
                    path: format!("{}/local", transition.pointer),
                    message: "local transition from root is unsupported".to_string(),
                });
            }
            if !is_descendant(target_path, &source.path) {
                return semantic(
                    &format!("{}/local", transition.pointer),
                    "local target must be a strict descendant",
                );
            }
        }
    }
    Ok(())
}

fn validate_actions(
    machine: &Machine,
    source: &State,
    transition_target: Option<&CompiledTarget>,
    actions: &[CompiledAction],
    bundle_events: &BTreeMap<String, EventDeclaration>,
    all_machine_ids: &HashSet<String>,
) -> Result<(), SemanticError> {
    for action in actions {
        match &action.kind {
            CompiledActionKind::Assign { variable, .. } => {
                let declaration_path = find_variable_declaration(machine, &source.path, variable)
                    .ok_or_else(|| SemanticError {
                    code: LoadErrorCode::SemanticValidation,
                    path: format!("{}/assign/{}", action.pointer, escape_pointer(variable)),
                    message: "assign references an unknown variable".to_string(),
                })?;
                if declaration_path.1.external {
                    return semantic(&action.pointer, "external variables are read-only");
                }
                if let Some(target) = transition_target {
                    if declaration_path.0 != "root"
                        && !scope_survives(machine, source, target, &declaration_path.0)
                    {
                        return Err(SemanticError {
                            code: LoadErrorCode::DestroyedVariableWrite,
                            path: action.pointer.clone(),
                            message: "transition action writes a destroyed variable".to_string(),
                        });
                    }
                }
            }
            CompiledActionKind::Spawn {
                machine_id,
                bindings,
                bind_to,
            } => {
                if !all_machine_ids.contains(machine_id) {
                    return semantic(&action.pointer, "spawn references an unknown machine");
                }
                validate_author_bindings(machine_id, bindings, machine)?;
                if let Some(variable) = bind_to {
                    let (declaration_path, declaration) =
                        find_variable_declaration(machine, &source.path, variable).ok_or_else(
                            || SemanticError {
                                code: LoadErrorCode::InvalidBinding,
                                path: format!("{}/spawn/bind_to", action.pointer),
                                message: "bind_to references an unknown variable".to_string(),
                            },
                        )?;
                    if declaration.value_type != "instance_reference"
                        || declaration
                            .machine_id
                            .as_ref()
                            .is_some_and(|expected| expected != machine_id)
                    {
                        return Err(SemanticError {
                            code: LoadErrorCode::InvalidBinding,
                            path: format!("{}/spawn/bind_to", action.pointer),
                            message: "bind_to has an incompatible type".to_string(),
                        });
                    }
                    if let Some(target) = transition_target {
                        if !scope_survives(machine, source, target, &declaration_path) {
                            return Err(SemanticError {
                                code: LoadErrorCode::DestroyedReferenceBinding,
                                path: format!("{}/spawn/bind_to", action.pointer),
                                message: "spawn binds into a destroyed reference".to_string(),
                            });
                        }
                    }
                }
            }
            CompiledActionKind::Send {
                event,
                targets,
                payload,
                correlation_id,
            } => {
                validate_send(
                    event,
                    targets,
                    payload,
                    correlation_id,
                    action,
                    machine,
                    bundle_events,
                )?;
            }
            CompiledActionKind::Refresh { only } => {
                let names = only
                    .clone()
                    .unwrap_or_else(|| root_external_variables(machine).keys().cloned().collect());
                for name in names {
                    let declaration = find_variable_declaration(machine, &source.path, &name)
                        .ok_or_else(|| SemanticError {
                            code: LoadErrorCode::DestroyedVariableWrite,
                            path: action.pointer.clone(),
                            message: "refresh references an unknown variable".to_string(),
                        })?;
                    if !declaration.1.external {
                        return semantic(&action.pointer, "refresh requires external variables");
                    }
                    if let Some(target) = transition_target {
                        if machine.states[target_path(target)].kind == CompiledStateKind::Final
                            || !scope_survives(machine, source, target, &declaration.0)
                        {
                            return Err(SemanticError {
                                code: LoadErrorCode::DestroyedVariableWrite,
                                path: action.pointer.clone(),
                                message: "refresh writes a destroyed variable".to_string(),
                            });
                        }
                    }
                }
            }
            CompiledActionKind::Cancel { .. } | CompiledActionKind::Stop => {}
        }
    }
    Ok(())
}

fn validate_send(
    event: &str,
    targets: &[CompiledSendTarget],
    payload: &BTreeMap<String, String>,
    correlation_id: &Option<String>,
    action: &CompiledAction,
    machine: &Machine,
    bundle_events: &BTreeMap<String, EventDeclaration>,
) -> Result<(), SemanticError> {
    if event == "env" {
        if targets.len() != 1
            || !matches!(targets[0], CompiledSendTarget::Component(_))
            || correlation_id.is_some()
            || payload.len() != 1
            || payload.get("changed").is_none_or(|expression| {
                let expression = expression.trim();
                !expression.starts_with('{') || expression == "{}"
            })
        {
            return semantic(&action.pointer, "env has one component-only send shape");
        }
        if let CompiledSendTarget::Component(component_id) = &targets[0] {
            let target = machine
                .states
                .values()
                .flat_map(|state| state.components.iter())
                .find(|component| &component.component_id == component_id);
            if let Some(Component {
                definition: ComponentDefinition::Inline(target),
                ..
            }) = target
            {
                let expression = &payload["changed"];
                if let Ok(Value::Map(values)) =
                    cel::evaluate(expression, &cel::Environment::default())
                {
                    let external = root_external_variables(target);
                    if values.len() != external.len()
                        || values.iter().any(|(name, value)| {
                            external.get(name).is_none_or(|declaration| {
                                value.normalize_for_type(&declaration.value_type).is_none()
                            })
                        })
                    {
                        return semantic(
                            &format!("{}/send/payload/changed", action.pointer),
                            "env.changed does not match the component external variables",
                        );
                    }
                }
            }
        }
        return Ok(());
    }
    if matches!(
        event,
        "done"
            | "determa.component_completed"
            | "determa.component_failed"
            | "determa.spawned_instance_failed"
    ) {
        return semantic(&action.pointer, "reserved lifecycle events cannot be sent");
    }
    let declaration = machine
        .events
        .get(event)
        .or_else(|| bundle_events.get(event))
        .ok_or_else(|| SemanticError {
            code: LoadErrorCode::SemanticValidation,
            path: format!("{}/send/event", action.pointer),
            message: "send references an undeclared event".to_string(),
        })?;
    let has_external = targets
        .iter()
        .any(|target| matches!(target, CompiledSendTarget::External));
    if has_external {
        if targets
            .iter()
            .any(|target| !matches!(target, CompiledSendTarget::External))
            || declaration.direction != EventDirection::Output
            || correlation_id.is_none()
        {
            return semantic(&action.pointer, "external send violates event direction");
        }
    } else if declaration.direction != EventDirection::Internal {
        return semantic(&action.pointer, "internal send violates event direction");
    }
    Ok(())
}

fn validate_author_bindings(
    _machine_id: &str,
    _bindings: &BindingExpressions,
    _machine: &Machine,
) -> Result<(), SemanticError> {
    // Cross-machine declaration compatibility is checked after all machines compile.
    Ok(())
}

fn validate_bindings_across_bundle(
    machines: &BTreeMap<String, Machine>,
) -> Result<(), SemanticError> {
    for machine in machines.values() {
        for state in machine.states.values() {
            for component in &state.components {
                let target = match &component.definition {
                    ComponentDefinition::Machine(machine_id) => &machines[machine_id],
                    ComponentDefinition::Inline(machine) => machine,
                };
                validate_binding_names(
                    target,
                    &component.bindings,
                    &format!("{}/with", component.pointer),
                )?;
            }
            for action in state
                .entry
                .iter()
                .chain(state.exit.iter())
                .chain(
                    state
                        .handlers
                        .values()
                        .flatten()
                        .flat_map(|transition| transition.action.iter()),
                )
                .chain(
                    state
                        .initial
                        .iter()
                        .flat_map(|initial| initial.action.iter()),
                )
                .chain(
                    state
                        .choice
                        .iter()
                        .flatten()
                        .flat_map(|branch| branch.action.iter()),
                )
            {
                if let CompiledActionKind::Spawn {
                    machine_id,
                    bindings,
                    ..
                } = &action.kind
                {
                    validate_binding_names(
                        &machines[machine_id],
                        bindings,
                        &format!("{}/spawn/bindings", action.pointer),
                    )?;
                }
            }
        }
    }
    Ok(())
}

fn validate_cel_across_bundle(
    machines: &BTreeMap<String, Machine>,
    bundle_events: &BTreeMap<String, EventDeclaration>,
) -> Result<(), SemanticError> {
    for machine in machines.values() {
        validate_machine_cel(machine, machines, bundle_events)?;
    }
    Ok(())
}

fn validate_machine_cel(
    machine: &Machine,
    machines: &BTreeMap<String, Machine>,
    bundle_events: &BTreeMap<String, EventDeclaration>,
) -> Result<(), SemanticError> {
    for state in machine.states.values() {
        let lifecycle_environment = lexical_type_environment(machine, &state.path);
        validate_typed_actions(
            machine,
            state,
            &state.entry,
            &lifecycle_environment,
            machines,
            bundle_events,
        )?;
        validate_typed_actions(
            machine,
            state,
            &state.exit,
            &lifecycle_environment,
            machines,
            bundle_events,
        )?;
        if let Some(initial) = &state.initial {
            validate_typed_actions(
                machine,
                state,
                &initial.action,
                &lifecycle_environment,
                machines,
                bundle_events,
            )?;
        }
        if let Some(branches) = &state.choice {
            for branch in branches {
                if let Some(guard) = &branch.guard {
                    cel::check(
                        guard,
                        branch
                            .guard_pointer
                            .as_deref()
                            .expect("guard pointer is retained"),
                        &lifecycle_environment,
                        &cel::CelType::Bool,
                    )?;
                }
                validate_typed_actions(
                    machine,
                    state,
                    &branch.action,
                    &lifecycle_environment,
                    machines,
                    bundle_events,
                )?;
            }
        }
        for (event_name, transitions) in &state.handlers {
            let event = event_declaration(machine, bundle_events, event_name);
            let mut event_environment = lifecycle_environment.clone();
            event_environment.values.insert(
                "event".to_string(),
                cel::CelType::Record(BTreeMap::from([(
                    "payload".to_string(),
                    cel::RecordField {
                        value_type: event_payload_type(machine, event_name, event),
                        optional: false,
                    },
                )])),
            );
            for transition in transitions {
                if let Some(guard) = &transition.guard {
                    cel::check(
                        guard,
                        transition
                            .guard_pointer
                            .as_deref()
                            .expect("guard pointer is retained"),
                        &event_environment,
                        &cel::CelType::Bool,
                    )?;
                }
                validate_typed_actions(
                    machine,
                    state,
                    &transition.action,
                    &event_environment,
                    machines,
                    bundle_events,
                )?;
            }
        }
        for component in &state.components {
            let target = match &component.definition {
                ComponentDefinition::Machine(machine_id) => &machines[machine_id],
                ComponentDefinition::Inline(inline) => inline.as_ref(),
            };
            let owner_variables = visible_declaration_types(machine, &state.path);
            let owner_environment = cel::TypeEnvironment {
                values: BTreeMap::from([(
                    "owner".to_string(),
                    cel::CelType::Record(BTreeMap::from([(
                        "variables".to_string(),
                        cel::RecordField {
                            value_type: cel::CelType::Record(owner_variables),
                            optional: false,
                        },
                    )])),
                )]),
            };
            validate_typed_bindings(
                target,
                &component.bindings,
                &owner_environment,
                &format!("{}/with", component.pointer),
            )?;
            if let ComponentDefinition::Inline(inline) = &component.definition {
                validate_machine_cel(inline, machines, bundle_events)?;
            }
        }
    }
    Ok(())
}

fn declaration_cel_type(declaration: &VariableDeclaration) -> cel::CelType {
    match (
        declaration.value_type.as_str(),
        declaration.init.as_ref().and_then(|value| value.as_ref()),
    ) {
        ("list" | "map", Some(value)) => cel::value_type(value),
        _ => cel::declared_type(&declaration.value_type, declaration.machine_id.as_deref()),
    }
}

fn lexical_type_environment(machine: &Machine, scope: &str) -> cel::TypeEnvironment {
    cel::TypeEnvironment {
        values: visible_declaration_types(machine, scope)
            .into_iter()
            .map(|(name, field)| (name, field.value_type))
            .collect(),
    }
}

fn visible_declaration_types(machine: &Machine, scope: &str) -> BTreeMap<String, cel::RecordField> {
    let mut output = BTreeMap::new();
    let mut current = Some(scope.to_string());
    while let Some(path) = current {
        let state = &machine.states[&path];
        for (name, declaration) in &state.variables {
            output
                .entry(name.clone())
                .or_insert_with(|| cel::RecordField {
                    value_type: declaration_cel_type(declaration),
                    optional: false,
                });
        }
        current = state.parent.clone();
    }
    output
}

fn event_declaration<'a>(
    machine: &'a Machine,
    bundle_events: &'a BTreeMap<String, EventDeclaration>,
    event_name: &str,
) -> Option<&'a EventDeclaration> {
    machine
        .events
        .get(event_name)
        .or_else(|| bundle_events.get(event_name))
}

fn payload_record(payload: &BTreeMap<String, super::model::PayloadField>) -> cel::CelType {
    cel::CelType::Record(
        payload
            .iter()
            .map(|(name, field)| {
                (
                    name.clone(),
                    cel::RecordField {
                        value_type: cel::declared_type(&field.value_type, None),
                        optional: !field.required && field.default.is_none(),
                    },
                )
            })
            .collect(),
    )
}

fn event_payload_type(
    machine: &Machine,
    event_name: &str,
    declaration: Option<&EventDeclaration>,
) -> cel::CelType {
    if let Some(declaration) = declaration {
        return payload_record(&declaration.payload);
    }
    let string = |optional| cel::RecordField {
        value_type: cel::CelType::String,
        optional,
    };
    let integer = |optional| cel::RecordField {
        value_type: cel::CelType::Int,
        optional,
    };
    let reference = |optional| cel::RecordField {
        value_type: cel::CelType::InstanceReference(None),
        optional,
    };
    let public_fault = cel::CelType::Record(BTreeMap::from([
        ("runtime_id".to_string(), string(false)),
        ("cause_id".to_string(), string(false)),
        ("code".to_string(), string(false)),
        ("step_sequence".to_string(), string(false)),
        ("source_locator".to_string(), string(false)),
    ]));
    match event_name {
        "env" => cel::CelType::Record(BTreeMap::from([(
            "changed".to_string(),
            cel::RecordField {
                value_type: cel::CelType::Record(
                    root_external_variables(machine)
                        .into_iter()
                        .map(|(name, declaration)| {
                            (
                                name,
                                cel::RecordField {
                                    value_type: declaration_cel_type(&declaration),
                                    optional: true,
                                },
                            )
                        })
                        .collect(),
                ),
                optional: false,
            },
        )])),
        "done" => cel::CelType::Record(BTreeMap::from([
            ("relationship".to_string(), string(false)),
            ("state_path".to_string(), string(true)),
            ("owner_runtime_id".to_string(), string(true)),
            ("instance".to_string(), reference(true)),
            ("instance_id".to_string(), string(true)),
            ("machine_id".to_string(), string(true)),
            ("machine_version".to_string(), integer(true)),
        ])),
        "determa.component_completed" => cel::CelType::Record(BTreeMap::from([
            ("component_id".to_string(), string(false)),
            ("component_runtime_id".to_string(), string(false)),
        ])),
        "determa.component_failed" => cel::CelType::Record(BTreeMap::from([
            ("component_id".to_string(), string(false)),
            ("component_runtime_id".to_string(), string(false)),
            (
                "fault".to_string(),
                cel::RecordField {
                    value_type: public_fault,
                    optional: false,
                },
            ),
        ])),
        "determa.spawned_instance_failed" => cel::CelType::Record(BTreeMap::from([
            ("instance".to_string(), reference(false)),
            ("instance_id".to_string(), string(false)),
            ("machine_id".to_string(), string(false)),
            ("machine_version".to_string(), integer(false)),
            (
                "fault".to_string(),
                cel::RecordField {
                    value_type: public_fault,
                    optional: false,
                },
            ),
        ])),
        _ => cel::CelType::Record(BTreeMap::new()),
    }
}

fn validate_typed_actions(
    machine: &Machine,
    source: &State,
    actions: &[CompiledAction],
    environment: &cel::TypeEnvironment,
    machines: &BTreeMap<String, Machine>,
    bundle_events: &BTreeMap<String, EventDeclaration>,
) -> Result<(), SemanticError> {
    for action in actions {
        match &action.kind {
            CompiledActionKind::Assign {
                variable,
                expression,
            } => {
                let (_, declaration) = find_variable_declaration(machine, &source.path, variable)
                    .expect("unknown assignments were rejected");
                cel::check(
                    expression,
                    &format!("{}/assign/{}", action.pointer, escape_pointer(variable)),
                    environment,
                    &cel::declared_type(&declaration.value_type, declaration.machine_id.as_deref()),
                )?;
            }
            CompiledActionKind::Send {
                event,
                targets,
                payload,
                correlation_id,
            } => {
                if event == "env" {
                    let expression = payload.get("changed").expect("the env shape was validated");
                    let inferred = cel::infer_expression(
                        expression,
                        &format!("{}/send/payload/changed", action.pointer),
                        environment,
                    )?;
                    if !matches!(inferred, cel::CelType::Map(_) | cel::CelType::Record(_)) {
                        return semantic(
                            &format!("{}/send/payload/changed", action.pointer),
                            "env.changed must infer a map",
                        );
                    }
                } else {
                    let declaration = event_declaration(machine, bundle_events, event)
                        .expect("send event was validated");
                    if payload
                        .keys()
                        .any(|name| !declaration.payload.contains_key(name))
                        || declaration
                            .payload
                            .iter()
                            .any(|(name, field)| field.required && !payload.contains_key(name))
                    {
                        return semantic(
                            &format!("{}/send/payload", action.pointer),
                            "send payload does not cover the declared event schema",
                        );
                    }
                    for (name, expression) in payload {
                        let field = &declaration.payload[name];
                        cel::check(
                            expression,
                            &format!("{}/send/payload/{}", action.pointer, escape_pointer(name)),
                            environment,
                            &cel::declared_type(&field.value_type, None),
                        )?;
                    }
                }
                if let Some(expression) = correlation_id {
                    cel::check(
                        expression,
                        &format!("{}/send/correlation_id", action.pointer),
                        environment,
                        &cel::CelType::String,
                    )?;
                }
                for (index, target) in targets.iter().enumerate() {
                    if let CompiledSendTarget::Instance(expression) = target {
                        cel::check(
                            expression,
                            &format!("{}/send/targets/{index}/instance", action.pointer),
                            environment,
                            &cel::CelType::InstanceReference(None),
                        )?;
                    }
                }
            }
            CompiledActionKind::Spawn {
                machine_id,
                bindings,
                ..
            } => validate_typed_bindings(
                &machines[machine_id],
                bindings,
                environment,
                &format!("{}/spawn/bindings", action.pointer),
            )?,
            CompiledActionKind::Cancel { instance } => {
                cel::check(
                    instance,
                    &format!("{}/cancel/instance", action.pointer),
                    environment,
                    &cel::CelType::InstanceReference(None),
                )?;
            }
            CompiledActionKind::Refresh { .. } | CompiledActionKind::Stop => {}
        }
    }
    Ok(())
}

fn validate_typed_bindings(
    target: &Machine,
    bindings: &BindingExpressions,
    environment: &cel::TypeEnvironment,
    pointer: &str,
) -> Result<(), SemanticError> {
    let input = root_input_variables(target);
    let external = root_external_variables(target);
    for (kind, expressions, declarations) in [
        ("input", &bindings.input, &input),
        ("external", &bindings.external, &external),
    ] {
        for (name, expression) in expressions {
            let expression_pointer = format!("{pointer}/{kind}/{}", escape_pointer(name));
            let inferred = cel::infer_expression(expression, &expression_pointer, environment)?;
            let declaration = &declarations[name];
            let expected =
                cel::declared_type(&declaration.value_type, declaration.machine_id.as_deref());
            if !cel::is_assignable(&inferred, &expected) {
                return Err(SemanticError {
                    code: LoadErrorCode::InvalidBinding,
                    path: expression_pointer,
                    message: format!(
                        "binding expression type {inferred:?} is not assignable to {expected:?}"
                    ),
                });
            }
        }
    }
    Ok(())
}

fn validate_binding_names(
    target: &Machine,
    bindings: &BindingExpressions,
    pointer: &str,
) -> Result<(), SemanticError> {
    let input = root_input_variables(target);
    let external = root_external_variables(target);
    if bindings.input.keys().any(|name| !input.contains_key(name))
        || bindings
            .external
            .keys()
            .any(|name| !external.contains_key(name))
        || input.iter().any(|(name, declaration)| {
            declaration.init.is_none() && !bindings.input.contains_key(name)
        })
        || external.iter().any(|(name, declaration)| {
            declaration.init.is_none() && !bindings.external.contains_key(name)
        })
    {
        return Err(SemanticError {
            code: LoadErrorCode::InvalidBinding,
            path: pointer.to_string(),
            message: "component/spawn bindings do not cover the target root".to_string(),
        });
    }
    Ok(())
}

fn validate_reachability(machine: &Machine) -> Result<(), SemanticError> {
    let mut reachable = HashSet::from(["root".to_string()]);
    let mut work = vec!["root".to_string()];
    while let Some(path) = work.pop() {
        let state = &machine.states[&path];
        if let Some(initial) = &state.initial {
            if reachable.insert(initial.target.clone()) {
                work.push(initial.target.clone());
            }
        }
        for transitions in state.handlers.values() {
            for transition in transitions {
                if let Some(target) = &transition.target {
                    let target = target_path(target).to_string();
                    if reachable.insert(target.clone()) {
                        work.push(target);
                    }
                }
            }
        }
        if let Some(branches) = &state.choice {
            for branch in branches {
                let target = target_path(&branch.target).to_string();
                if reachable.insert(target.clone()) {
                    work.push(target);
                }
            }
        }
        let mut parent = state.parent.clone();
        while let Some(path) = parent {
            if reachable.insert(path.clone()) {
                work.push(path.clone());
            }
            parent = machine.states[&path].parent.clone();
        }
    }
    for state in machine.states.values() {
        if !reachable.contains(&state.path) {
            return semantic(&state.pointer, "state is unreachable");
        }
    }
    Ok(())
}

fn validate_choice_cycles(machine: &Machine) -> Result<(), SemanticError> {
    fn visit(
        machine: &Machine,
        path: &str,
        visiting: &mut HashSet<String>,
        visited: &mut HashSet<String>,
    ) -> bool {
        if !visiting.insert(path.to_string()) {
            return true;
        }
        if !visited.insert(path.to_string()) {
            visiting.remove(path);
            return false;
        }
        if let Some(branches) = &machine.states[path].choice {
            for branch in branches {
                let target = target_path(&branch.target);
                if machine.states[target].kind == CompiledStateKind::Choice
                    && visit(machine, target, visiting, visited)
                {
                    return true;
                }
            }
        }
        visiting.remove(path);
        false
    }
    let mut visiting = HashSet::new();
    let mut visited = HashSet::new();
    for state in machine.states.values() {
        if state.kind == CompiledStateKind::Choice
            && visit(machine, &state.path, &mut visiting, &mut visited)
        {
            return semantic(&state.pointer, "choice graph contains a cycle");
        }
    }
    Ok(())
}

fn validate_initialization_cycles(
    machines: &BTreeMap<String, Machine>,
) -> Result<(), SemanticError> {
    let mut graph: HashMap<String, BTreeSet<String>> = HashMap::new();
    for machine in machines.values() {
        let mut dependencies = BTreeSet::new();
        for state in machine.states.values() {
            for component in &state.components {
                if let ComponentDefinition::Machine(machine_id) = &component.definition {
                    dependencies.insert(machine_id.clone());
                }
            }
            for action in state.entry.iter().chain(
                state
                    .initial
                    .iter()
                    .flat_map(|initial| initial.action.iter()),
            ) {
                if let CompiledActionKind::Spawn { machine_id, .. } = &action.kind {
                    dependencies.insert(machine_id.clone());
                }
            }
        }
        graph.insert(machine.machine_id.clone(), dependencies);
    }
    fn cycle(
        node: &str,
        graph: &HashMap<String, BTreeSet<String>>,
        active: &mut HashSet<String>,
        done: &mut HashSet<String>,
    ) -> bool {
        if active.contains(node) {
            return true;
        }
        if done.contains(node) {
            return false;
        }
        active.insert(node.to_string());
        for dependency in graph.get(node).into_iter().flatten() {
            if cycle(dependency, graph, active, done) {
                return true;
            }
        }
        active.remove(node);
        done.insert(node.to_string());
        false
    }
    let mut active = HashSet::new();
    let mut done = HashSet::new();
    for machine_id in machines.keys() {
        if cycle(machine_id, &graph, &mut active, &mut done) {
            return semantic("/machines", "synchronous initialization dependency cycle");
        }
    }
    Ok(())
}

fn require_target(
    machine: &Machine,
    target: &CompiledTarget,
    pointer: &str,
) -> Result<(), SemanticError> {
    require_state(machine, target_path(target), pointer)
}

fn require_state(machine: &Machine, path: &str, pointer: &str) -> Result<(), SemanticError> {
    if machine.states.contains_key(path) {
        Ok(())
    } else {
        semantic(pointer, &format!("unknown state target {path:?}"))
    }
}

fn target_path(target: &CompiledTarget) -> &str {
    match target {
        CompiledTarget::State(path) | CompiledTarget::History(path) => path,
    }
}

fn is_descendant(path: &str, ancestor: &str) -> bool {
    ancestor == "root" && path != "root"
        || path
            .strip_prefix(ancestor)
            .is_some_and(|suffix| suffix.starts_with('.'))
}

fn find_variable_declaration<'a>(
    machine: &'a Machine,
    scope: &str,
    name: &str,
) -> Option<(String, &'a VariableDeclaration)> {
    let mut current = Some(scope.to_string());
    while let Some(path) = current {
        let state = &machine.states[&path];
        if let Some(declaration) = state.variables.get(name) {
            return Some((path, declaration));
        }
        current = state.parent.clone();
    }
    None
}

pub fn root_input_variables(machine: &Machine) -> BTreeMap<String, VariableDeclaration> {
    machine.states["root"]
        .variables
        .iter()
        .filter(|(_, declaration)| declaration.input)
        .map(|(name, declaration)| (name.clone(), declaration.clone()))
        .collect()
}

pub fn root_external_variables(machine: &Machine) -> BTreeMap<String, VariableDeclaration> {
    machine.states["root"]
        .variables
        .iter()
        .filter(|(_, declaration)| declaration.external)
        .map(|(name, declaration)| (name.clone(), declaration.clone()))
        .collect()
}

fn scope_survives(
    machine: &Machine,
    source: &State,
    target: &CompiledTarget,
    declaration_path: &str,
) -> bool {
    let target_path = target_path(target);
    if machine.states[target_path].kind == CompiledStateKind::Final {
        return false;
    }
    if declaration_path == "root" {
        return true;
    }
    if source.path == declaration_path && target_path == declaration_path {
        return false;
    }
    target_path == declaration_path || is_descendant(target_path, declaration_path)
}

fn normalize_bundle(document: &mut JsonValue) -> Result<(), SemanticError> {
    let Some(bundle) = document.as_object_mut() else {
        return semantic("/", "bundle must be an object");
    };
    if let Some(events) = bundle.get_mut("events").and_then(JsonValue::as_object_mut) {
        normalize_events(events)?;
    }
    let Some(machines) = bundle.get_mut("machines").and_then(JsonValue::as_array_mut) else {
        return semantic("/machines", "machines must be an array");
    };
    for (machine_index, machine) in machines.iter_mut().enumerate() {
        let Some(machine) = machine.as_object_mut() else {
            continue;
        };
        machine
            .entry("version")
            .or_insert_with(|| JsonValue::Number(1.into()));
        let languages = machine
            .entry("languages")
            .or_insert_with(|| JsonValue::Object(Map::new()));
        if let Some(languages) = languages.as_object_mut() {
            languages
                .entry("guard")
                .or_insert_with(|| JsonValue::String("cel".to_string()));
            languages
                .entry("action")
                .or_insert_with(|| JsonValue::String("determa".to_string()));
        }
        if let Some(events) = machine.get_mut("events").and_then(JsonValue::as_object_mut) {
            normalize_events(events)?;
        }
        if let Some(root) = machine.get_mut("root") {
            normalize_state(root, &format!("/machines/{machine_index}/root"))?;
        }
    }
    Ok(())
}

fn normalize_events(events: &mut Map<String, JsonValue>) -> Result<(), SemanticError> {
    for declaration in events.values_mut() {
        let Some(declaration) = declaration.as_object_mut() else {
            continue;
        };
        declaration
            .entry("direction")
            .or_insert_with(|| JsonValue::String("internal".to_string()));
        if let Some(payload) = declaration
            .get_mut("payload")
            .and_then(JsonValue::as_object_mut)
        {
            for field in payload.values_mut() {
                let Some(field) = field.as_object_mut() else {
                    continue;
                };
                field
                    .entry("required")
                    .or_insert_with(|| JsonValue::Bool(false));
                normalize_typed_literal(field, "default")?;
            }
        }
    }
    Ok(())
}

fn normalize_state(state: &mut JsonValue, pointer: &str) -> Result<(), SemanticError> {
    let Some(state) = state.as_object_mut() else {
        return Ok(());
    };
    if !state.contains_key("choice") {
        state
            .entry("type")
            .or_insert_with(|| JsonValue::String("simple".to_string()));
    }
    if state.get("type").and_then(JsonValue::as_str) == Some("composite") {
        state
            .entry("history")
            .or_insert_with(|| JsonValue::String("none".to_string()));
    }
    if let Some(variables) = state
        .get_mut("variables")
        .and_then(JsonValue::as_object_mut)
    {
        for declaration in variables.values_mut() {
            let Some(declaration) = declaration.as_object_mut() else {
                continue;
            };
            if declaration.get("type").and_then(JsonValue::as_str) != Some("instance_reference") {
                declaration
                    .entry("input")
                    .or_insert_with(|| JsonValue::Bool(false));
                declaration
                    .entry("external")
                    .or_insert_with(|| JsonValue::Bool(false));
            }
            normalize_typed_literal(declaration, "init")?;
        }
    }
    if let Some(states) = state.get_mut("states").and_then(JsonValue::as_object_mut) {
        for (name, child) in states {
            normalize_state(child, &format!("{pointer}/states/{}", escape_pointer(name)))?;
        }
    }
    if let Some(components) = state
        .get_mut("components")
        .and_then(JsonValue::as_array_mut)
    {
        for (index, component) in components.iter_mut().enumerate() {
            if let Some(root) = component
                .as_object_mut()
                .and_then(|component| component.get_mut("root"))
            {
                normalize_state(root, &format!("{pointer}/components/{index}/root"))?;
            }
        }
    }
    if let Some(handlers) = state
        .get_mut("on_events")
        .and_then(JsonValue::as_object_mut)
    {
        for transition in handlers.values_mut() {
            match transition {
                JsonValue::Array(transitions) => {
                    for transition in transitions {
                        normalize_transition(transition)?;
                    }
                }
                _ => normalize_transition(transition)?,
            }
        }
    }
    for action_member in ["entry", "exit"] {
        if let Some(actions) = state
            .get_mut(action_member)
            .and_then(JsonValue::as_array_mut)
        {
            normalize_actions(actions);
        }
    }
    if let Some(initial) = state.get_mut("initial").and_then(JsonValue::as_object_mut) {
        if let Some(actions) = initial.get_mut("action").and_then(JsonValue::as_array_mut) {
            normalize_actions(actions);
        }
    }
    if let Some(choice) = state.get_mut("choice").and_then(JsonValue::as_array_mut) {
        for branch in choice {
            if let Some(actions) = branch
                .as_object_mut()
                .and_then(|branch| branch.get_mut("action"))
                .and_then(JsonValue::as_array_mut)
            {
                normalize_actions(actions);
            }
        }
    }
    Ok(())
}

fn normalize_transition(transition: &mut JsonValue) -> Result<(), SemanticError> {
    let Some(transition) = transition.as_object_mut() else {
        return Ok(());
    };
    transition
        .entry("lang")
        .or_insert_with(|| JsonValue::String("cel".to_string()));
    if let Some(actions) = transition
        .get_mut("action")
        .and_then(JsonValue::as_array_mut)
    {
        normalize_actions(actions);
    }
    Ok(())
}

fn normalize_actions(actions: &mut [JsonValue]) {
    for action in actions {
        let Some(send) = action
            .as_object_mut()
            .and_then(|action| action.get_mut("send"))
            .and_then(JsonValue::as_object_mut)
        else {
            continue;
        };
        if !send.contains_key("to") && !send.contains_key("targets") {
            send.insert("to".to_string(), serde_json::json!({ "self": true }));
        }
    }
}

fn normalize_typed_literal(
    declaration: &mut Map<String, JsonValue>,
    member: &str,
) -> Result<(), SemanticError> {
    if declaration.get("type").and_then(JsonValue::as_str) == Some("float") {
        if let Some(value) = declaration.get_mut(member) {
            if let Some(integer) = value.as_i64() {
                *value = JsonValue::Number(
                    serde_json::Number::from_f64(integer as f64).expect("finite integer float"),
                );
            }
        }
    }
    Ok(())
}

pub(crate) fn typed_projection(value: &JsonValue) -> JsonValue {
    match value {
        JsonValue::Null => serde_json::json!(["null"]),
        JsonValue::Bool(value) => serde_json::json!(["boolean", value]),
        JsonValue::String(value) => serde_json::json!(["string", value]),
        JsonValue::Number(value) if value.as_i64().is_some() => {
            serde_json::json!(["integer", value.as_i64().unwrap().to_string()])
        }
        JsonValue::Number(value) => {
            let mut float = value.as_f64().expect("validated number");
            if float == 0.0 {
                float = 0.0;
            }
            serde_json::json!(["float", format!("{:016x}", float.to_bits())])
        }
        JsonValue::Array(values) => JsonValue::Array(vec![
            JsonValue::String("list".to_string()),
            JsonValue::Array(values.iter().map(typed_projection).collect()),
        ]),
        JsonValue::Object(values) => {
            let mut entries = values
                .iter()
                .map(|(key, value)| {
                    JsonValue::Array(vec![
                        JsonValue::String(key.clone()),
                        typed_projection(value),
                    ])
                })
                .collect::<Vec<_>>();
            entries.sort_by(|left, right| {
                left[0]
                    .as_str()
                    .unwrap()
                    .as_bytes()
                    .cmp(right[0].as_str().unwrap().as_bytes())
            });
            JsonValue::Array(vec![
                JsonValue::String("map".to_string()),
                JsonValue::Array(entries),
            ])
        }
    }
}

pub(crate) fn hash_json(value: JsonValue) -> String {
    let canonical = canonical_json(&value);
    let digest = Sha256::digest(canonical.as_bytes());
    format!("sha256:{digest:x}")
}

fn typed_hash(values: &[JsonValue]) -> String {
    hash_json(JsonValue::Array(values.to_vec()))
}

fn canonical_json(value: &JsonValue) -> String {
    match value {
        JsonValue::Null => "null".to_string(),
        JsonValue::Bool(value) => value.to_string(),
        JsonValue::Number(value) => value.to_string(),
        JsonValue::String(value) => serde_json::to_string(value).expect("string serializes"),
        JsonValue::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(",")
        ),
        JsonValue::Object(values) => {
            let mut entries = values.iter().collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
            format!(
                "{{{}}}",
                entries
                    .into_iter()
                    .map(|(key, value)| format!(
                        "{}:{}",
                        serde_json::to_string(key).expect("key serializes"),
                        canonical_json(value)
                    ))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
    }
}

fn semantic<T>(path: &str, message: &str) -> Result<T, SemanticError> {
    Err(SemanticError {
        code: LoadErrorCode::SemanticValidation,
        path: path.to_string(),
        message: message.to_string(),
    })
}
