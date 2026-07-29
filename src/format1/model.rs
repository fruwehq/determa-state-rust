use super::counter::Counter;
use crate::value::Value;
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawBundle {
    pub format: i64,
    pub namespace: String,
    #[serde(default)]
    pub events: BTreeMap<String, EventDeclaration>,
    pub machines: Vec<RawMachine>,
    #[serde(default)]
    #[serde(rename = "meta")]
    pub _meta: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawMachine {
    pub machine_id: String,
    #[serde(default = "default_version")]
    pub version: i64,
    #[serde(default)]
    pub languages: Languages,
    #[serde(default)]
    pub events: BTreeMap<String, EventDeclaration>,
    pub root: RawState,
    #[serde(default)]
    pub meta: Option<serde_json::Value>,
}

fn default_version() -> i64 {
    1
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Languages {
    pub guard: String,
    pub action: String,
}

impl Default for Languages {
    fn default() -> Self {
        Self {
            guard: "cel".to_string(),
            action: "determa".to_string(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EventDeclaration {
    #[serde(default)]
    pub direction: EventDirection,
    #[serde(default)]
    pub payload: BTreeMap<String, PayloadField>,
    #[serde(default)]
    pub correlates_to: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventDirection {
    #[default]
    Internal,
    Input,
    Output,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PayloadField {
    #[serde(rename = "type")]
    pub value_type: String,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub default: Option<Value>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct VariableDeclaration {
    #[serde(rename = "type")]
    pub value_type: String,
    #[serde(default, deserialize_with = "deserialize_present_value")]
    pub init: Option<Option<Value>>,
    #[serde(default)]
    pub input: bool,
    #[serde(default)]
    pub external: bool,
    #[serde(default)]
    pub nullable: Option<bool>,
    #[serde(default)]
    pub machine_id: Option<String>,
}

fn deserialize_present_value<'de, D>(deserializer: D) -> Result<Option<Option<Value>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<Value>::deserialize(deserializer).map(Some)
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawState {
    #[serde(rename = "type", default)]
    pub state_type: Option<StateType>,
    #[serde(default)]
    #[serde(rename = "meta")]
    pub _meta: Option<serde_json::Value>,
    #[serde(default)]
    pub variables: BTreeMap<String, VariableDeclaration>,
    #[serde(default)]
    pub entry: Vec<Action>,
    #[serde(default)]
    pub exit: Vec<Action>,
    #[serde(default)]
    pub initial: Option<InitialTransition>,
    #[serde(default)]
    pub states: BTreeMap<String, RawState>,
    #[serde(default)]
    pub components: Vec<RawComponent>,
    #[serde(default)]
    pub on_events: BTreeMap<String, TransitionOrList>,
    #[serde(default)]
    pub history: Option<HistoryKind>,
    #[serde(default)]
    pub choice: Option<Vec<ChoiceBranch>>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StateType {
    Simple,
    Composite,
    Parallel,
    Final,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HistoryKind {
    None,
    Shallow,
    Deep,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawComponent {
    pub component_id: String,
    #[serde(default)]
    pub machine_id: Option<String>,
    #[serde(default)]
    pub root: Option<RawState>,
    #[serde(default, rename = "with")]
    pub bindings: BindingExpressions,
    #[serde(default)]
    pub meta: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct BindingExpressions {
    pub input: BTreeMap<String, String>,
    pub external: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Bindings {
    pub input: BTreeMap<String, Value>,
    pub external: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineIdentity {
    pub namespace: String,
    pub machine_id: String,
    pub machine_version: i64,
    pub root_definition_pointer: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefinitionBinding {
    pub validated_bundle_fingerprint: String,
    pub machine: MachineIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityOrigin {
    Root {
        definition: DefinitionBinding,
        root_instance_id: String,
    },
    Component {
        definition: DefinitionBinding,
        owner_runtime_id: String,
        component_definition_pointer: String,
        activation_sequence: Counter,
        declaration_index: Counter,
    },
    OwnedSpawnedInstance {
        definition: DefinitionBinding,
        owner_runtime_id: String,
        spawn_action_pointer: String,
        spawn_sequence: Counter,
    },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitialTransition {
    pub transition_to: String,
    #[serde(default)]
    pub action: Vec<Action>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChoiceBranch {
    pub transition_to: TransitionTarget,
    #[serde(default)]
    pub guard: Option<String>,
    #[serde(default)]
    pub action: Vec<Action>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum TransitionOrList {
    One(Transition),
    List(Vec<Transition>),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transition {
    #[serde(default)]
    pub transition_to: Option<TransitionTarget>,
    #[serde(default)]
    pub guard: Option<String>,
    #[serde(default)]
    #[serde(rename = "lang")]
    pub _lang: Option<String>,
    #[serde(default)]
    pub action: Vec<Action>,
    #[serde(default)]
    pub local: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum TransitionTarget {
    State(String),
    History { history: String },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Assign(BTreeMap<String, String>),
    Send(SendAction),
    Refresh(RefreshAction),
    Spawn(SpawnAction),
    Cancel(CancelAction),
    Stop(EmptyAction),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendAction {
    pub event: String,
    #[serde(default)]
    pub to: Option<TargetExpression>,
    #[serde(default)]
    pub targets: Option<Vec<TargetExpression>>,
    #[serde(default)]
    pub payload: BTreeMap<String, String>,
    #[serde(default)]
    pub correlation_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum TargetExpression {
    SelfTarget {
        #[serde(rename = "self")]
        _self_target: bool,
    },
    Owner {
        #[serde(rename = "owner")]
        _owner: bool,
    },
    Component {
        component: String,
    },
    Instance {
        instance: String,
    },
    External {
        #[serde(rename = "external")]
        _external: bool,
    },
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefreshAction {
    #[serde(default)]
    pub only: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpawnAction {
    pub machine_id: String,
    #[serde(default)]
    pub bindings: BindingExpressions,
    #[serde(default)]
    pub bind_to: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelAction {
    pub instance: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmptyAction {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Target {
    Root {
        root_instance_id: String,
        root_runtime_id: String,
    },
    SpawnedInstance(crate::value::InstanceReference),
    Component {
        root_instance_id: String,
        owner_runtime_id: String,
        component_id: String,
        component_runtime_id: String,
        activation_sequence: Counter,
    },
    External,
}

use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Envelope {
    pub event: String,
    pub event_id: String,
    pub target: Target,
    #[serde(default)]
    pub payload: BTreeMap<String, Value>,
    #[serde(default)]
    pub correlation_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Delivery {
    Input(Envelope),
    Internal(Envelope),
}
