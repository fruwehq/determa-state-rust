use super::compile::{Bundle, Component, ComponentDefinition, Machine};
use super::counter::Counter;
use super::model::{
    DefinitionBinding, IdentityOrigin, MachineIdentity, Target, VariableDeclaration,
};
use super::persistence::DefinitionResolver;
use super::runtime::{
    AggregateState, ComponentRuntime, FaultRecord, OwnedRuntime, RuntimeRelation, RuntimeState,
    RuntimeStatus, VariableSlot,
};
use super::strict_json;
use crate::value::{InstanceReference, Value};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{json, Value as JsonValue};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistenceErrorCode {
    UnsupportedAggregateStateFormat,
    UnsupportedAggregateStateSchemaVersion,
    UnsupportedMigrationDescriptorFormat,
    UnsupportedMigrationDescriptorSchemaVersion,
    UnsupportedAggregateStatePackageFormat,
    UnsupportedAggregateStatePackageSchemaVersion,
    InvalidAggregateState,
    InvalidAggregateStatePackage,
    AggregateStateDigestMismatch,
    SourceDefinitionUnavailable,
    DefinitionUntrusted,
    TargetDefinitionUnavailable,
    DefinitionFingerprintMismatch,
    MigrationDescriptorUntrusted,
    InvalidMigrationDescriptor,
    InvalidMigrationRequest,
    MigrationRouteMissing,
    MigrationRouteMismatch,
    MigrationTransformFault,
    MigrationTotalityFailure,
    MigrationResourceLimitExceeded,
    TerminalMigrationRequiresMaintenance,
    TerminalMigrationRejected,
}

impl PersistenceErrorCode {
    /// Complete failure set defined by the portable persistence registry.
    pub const PORTABLE_CODES: &'static [Self] = &[
        Self::UnsupportedAggregateStateFormat,
        Self::UnsupportedAggregateStateSchemaVersion,
        Self::UnsupportedMigrationDescriptorFormat,
        Self::UnsupportedMigrationDescriptorSchemaVersion,
        Self::UnsupportedAggregateStatePackageFormat,
        Self::UnsupportedAggregateStatePackageSchemaVersion,
        Self::InvalidAggregateState,
        Self::InvalidAggregateStatePackage,
        Self::AggregateStateDigestMismatch,
        Self::SourceDefinitionUnavailable,
        Self::DefinitionUntrusted,
        Self::TargetDefinitionUnavailable,
        Self::DefinitionFingerprintMismatch,
        Self::MigrationDescriptorUntrusted,
        Self::InvalidMigrationDescriptor,
        Self::InvalidMigrationRequest,
        Self::MigrationRouteMissing,
        Self::MigrationRouteMismatch,
        Self::MigrationTransformFault,
        Self::MigrationTotalityFailure,
        Self::MigrationResourceLimitExceeded,
        Self::TerminalMigrationRequiresMaintenance,
        Self::TerminalMigrationRejected,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedAggregateStateFormat => "unsupported_aggregate_state_format",
            Self::UnsupportedAggregateStateSchemaVersion => {
                "unsupported_aggregate_state_schema_version"
            }
            Self::UnsupportedMigrationDescriptorFormat => "unsupported_migration_descriptor_format",
            Self::UnsupportedMigrationDescriptorSchemaVersion => {
                "unsupported_migration_descriptor_schema_version"
            }
            Self::UnsupportedAggregateStatePackageFormat => {
                "unsupported_aggregate_state_package_format"
            }
            Self::UnsupportedAggregateStatePackageSchemaVersion => {
                "unsupported_aggregate_state_package_schema_version"
            }
            Self::InvalidAggregateState => "invalid_aggregate_state",
            Self::InvalidAggregateStatePackage => "invalid_aggregate_state_package",
            Self::AggregateStateDigestMismatch => "aggregate_state_digest_mismatch",
            Self::SourceDefinitionUnavailable => "source_definition_unavailable",
            Self::DefinitionUntrusted => "definition_untrusted",
            Self::TargetDefinitionUnavailable => "target_definition_unavailable",
            Self::DefinitionFingerprintMismatch => "definition_fingerprint_mismatch",
            Self::MigrationDescriptorUntrusted => "migration_descriptor_untrusted",
            Self::InvalidMigrationDescriptor => "invalid_migration_descriptor",
            Self::InvalidMigrationRequest => "invalid_migration_request",
            Self::MigrationRouteMissing => "migration_route_missing",
            Self::MigrationRouteMismatch => "migration_route_mismatch",
            Self::MigrationTransformFault => "migration_transform_fault",
            Self::MigrationTotalityFailure => "migration_totality_failure",
            Self::MigrationResourceLimitExceeded => "migration_resource_limit_exceeded",
            Self::TerminalMigrationRequiresMaintenance => "terminal_migration_requires_maintenance",
            Self::TerminalMigrationRejected => "terminal_migration_rejected",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistenceError {
    pub code: PersistenceErrorCode,
    pub message: String,
}

impl PersistenceError {
    pub fn new(code: PersistenceErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for PersistenceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for PersistenceError {}

#[derive(Debug, Clone, PartialEq)]
pub enum TypedValue {
    Null,
    Boolean(bool),
    String(String),
    Integer(i64),
    Float(f64),
    List(Vec<TypedValue>),
    Map(Vec<(String, TypedValue)>),
}

impl TypedValue {
    pub fn from_value(value: &Value) -> Self {
        match value {
            Value::Null => Self::Null,
            Value::Bool(value) => Self::Boolean(*value),
            Value::String(value) => Self::String(value.clone()),
            Value::Int(value) => Self::Integer(*value),
            Value::Float(value) => Self::Float(if *value == 0.0 { 0.0 } else { *value }),
            Value::List(values) => {
                Self::List(values.iter().map(Self::from_value).collect::<Vec<_>>())
            }
            Value::Map(values) => Self::Map(
                values
                    .iter()
                    .map(|(key, value)| (key.clone(), Self::from_value(value)))
                    .collect(),
            ),
            Value::InstanceReference(reference) => {
                let mut values = vec![
                    (
                        "instance_id".to_string(),
                        Self::String(reference.instance_id.clone()),
                    ),
                    (
                        "machine_id".to_string(),
                        Self::String(reference.machine_id.clone()),
                    ),
                    (
                        "machine_version".to_string(),
                        Self::Integer(reference.machine_version),
                    ),
                    (
                        "root_instance_id".to_string(),
                        Self::String(reference.root_instance_id.clone()),
                    ),
                ];
                values.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
                Self::Map(values)
            }
        }
    }

    pub fn to_value(
        &self,
        declaration: Option<&VariableDeclaration>,
    ) -> Result<Value, PersistenceError> {
        let value = match self {
            Self::Null => Value::Null,
            Self::Boolean(value) => Value::Bool(*value),
            Self::String(value) => Value::String(value.clone()),
            Self::Integer(value) => Value::Int(*value),
            Self::Float(value) if value.is_finite() => {
                Value::Float(if *value == 0.0 { 0.0 } else { *value })
            }
            Self::Float(_) => {
                return Err(invalid_state("typed float is not finite"));
            }
            Self::List(values) => Value::List(
                values
                    .iter()
                    .map(|value| value.to_value(None))
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            Self::Map(values) => Value::Map(
                values
                    .iter()
                    .map(|(key, value)| Ok((key.clone(), value.to_value(None)?)))
                    .collect::<Result<BTreeMap<_, _>, PersistenceError>>()?,
            ),
        };
        if declaration.is_some_and(|declaration| declaration.value_type == "instance_reference")
            && !matches!(value, Value::Null)
        {
            return instance_reference_from_value(value);
        }
        Ok(value)
    }

    pub(crate) fn canonical_size(&self) -> Result<usize, PersistenceError> {
        canonical_bytes(self)
            .map(|bytes| bytes.len())
            .map_err(|error| invalid_state(error.to_string()))
    }

    fn from_projection(value: JsonValue) -> Result<Self, String> {
        let JsonValue::Array(mut values) = value else {
            return Err("typed value must be an array".to_string());
        };
        if values.is_empty() {
            return Err("typed value must have a tag".to_string());
        }
        let JsonValue::String(tag) = values.remove(0) else {
            return Err("typed value tag must be a string".to_string());
        };
        match (tag.as_str(), values.as_slice()) {
            ("null", []) => Ok(Self::Null),
            ("boolean", [JsonValue::Bool(value)]) => Ok(Self::Boolean(*value)),
            ("string", [JsonValue::String(value)]) => Ok(Self::String(value.clone())),
            ("integer", [JsonValue::String(value)]) => value
                .parse::<i64>()
                .map(Self::Integer)
                .map_err(|_| "typed integer is outside signed 64-bit".to_string()),
            ("float", [JsonValue::String(value)]) => {
                let bits = u64::from_str_radix(value, 16)
                    .map_err(|_| "invalid typed float bits".to_string())?;
                let float = f64::from_bits(bits);
                if !float.is_finite() || (float == 0.0 && float.is_sign_negative()) {
                    return Err("typed float is noncanonical".to_string());
                }
                Ok(Self::Float(float))
            }
            ("list", [JsonValue::Array(values)]) => Ok(Self::List(
                values
                    .iter()
                    .cloned()
                    .map(Self::from_projection)
                    .collect::<Result<Vec<_>, _>>()?,
            )),
            ("map", [JsonValue::Array(values)]) => {
                let mut output = Vec::new();
                let mut previous: Option<Vec<u8>> = None;
                for value in values {
                    let JsonValue::Array(entry) = value else {
                        return Err("typed map entry must be an array".to_string());
                    };
                    if entry.len() != 2 {
                        return Err("typed map entry must have two members".to_string());
                    }
                    let JsonValue::String(key) = &entry[0] else {
                        return Err("typed map key must be a string".to_string());
                    };
                    if previous
                        .as_ref()
                        .is_some_and(|previous| previous.as_slice() >= key.as_bytes())
                    {
                        return Err("typed map keys are not canonical".to_string());
                    }
                    previous = Some(key.as_bytes().to_vec());
                    output.push((key.clone(), Self::from_projection(entry[1].clone())?));
                }
                Ok(Self::Map(output))
            }
            _ => Err("invalid typed value projection".to_string()),
        }
    }

    fn projection(&self) -> JsonValue {
        match self {
            Self::Null => json!(["null"]),
            Self::Boolean(value) => json!(["boolean", value]),
            Self::String(value) => json!(["string", value]),
            Self::Integer(value) => json!(["integer", value.to_string()]),
            Self::Float(value) => {
                let normalized = if *value == 0.0 { 0.0 } else { *value };
                json!(["float", format!("{:016x}", normalized.to_bits())])
            }
            Self::List(values) => json!([
                "list",
                values.iter().map(Self::projection).collect::<Vec<_>>()
            ]),
            Self::Map(values) => json!([
                "map",
                values
                    .iter()
                    .map(|(key, value)| json!([key, value.projection()]))
                    .collect::<Vec<_>>()
            ]),
        }
    }
}

impl Serialize for TypedValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.projection().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for TypedValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::from_projection(JsonValue::deserialize(deserializer)?)
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireMachineIdentity {
    pub namespace: String,
    pub machine_id: String,
    pub machine_version: String,
    pub root_definition_pointer: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireDefinitionBinding {
    pub validated_bundle_fingerprint: String,
    pub machine: WireMachineIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WireIdentityOrigin {
    Root {
        definition: WireDefinitionBinding,
        root_instance_id: String,
    },
    Component {
        definition: WireDefinitionBinding,
        owner_runtime_id: String,
        component_definition_pointer: String,
        activation_sequence: String,
        declaration_index: String,
    },
    OwnedSpawnedInstance {
        definition: WireDefinitionBinding,
        owner_runtime_id: String,
        spawn_action_pointer: String,
        spawn_sequence: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireRootTarget {
    pub root_instance_id: String,
    pub root_runtime_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireComponentTarget {
    pub root_instance_id: String,
    pub owner_runtime_id: String,
    pub component_id: String,
    pub component_runtime_id: String,
    pub activation_sequence: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireInstanceReference {
    pub root_instance_id: String,
    pub instance_id: String,
    pub machine_id: String,
    pub machine_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum WireTarget {
    Root {
        root: WireRootTarget,
    },
    Component {
        component: WireComponentTarget,
    },
    SpawnedInstance {
        spawned_instance: WireInstanceReference,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireLifetimeHolder {
    pub holder_runtime_id: String,
    pub variable_declaration_pointer: String,
    pub holder_state_activation_sequence: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WireRelation {
    Root,
    Component {
        owner_runtime_id: String,
        component_id: String,
        current_component_definition_pointer: String,
        activation_sequence: String,
        declaration_index: String,
    },
    OwnedSpawnedInstance {
        owner_runtime_id: String,
        current_spawn_action_pointer: String,
        spawn_sequence: String,
        lifetime_holder: Option<WireLifetimeHolder>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireStateActivation {
    pub state_definition_pointer: String,
    pub activation_sequence: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireVariable {
    pub variable_declaration_pointer: String,
    pub declaring_state_activation_sequence: String,
    pub value: TypedValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireHistory {
    pub history_declaration_pointer: String,
    pub recorded_state_definition_pointers: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireNextCounter {
    pub definition_pointer: String,
    pub next_sequence: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireFault {
    pub definition_fingerprint: String,
    pub runtime_id: String,
    pub cause_id: String,
    pub code: String,
    pub step_sequence: String,
    pub source_locator: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireRuntime {
    pub runtime_id: String,
    pub identity_origin: WireIdentityOrigin,
    pub target_identity: WireTarget,
    pub current_definition: WireDefinitionBinding,
    pub relation: WireRelation,
    pub status: RuntimeStatus,
    pub active_leaf_state_definition_pointers: Vec<String>,
    pub active_state_activations: Vec<WireStateActivation>,
    pub variables: Vec<WireVariable>,
    pub history: Vec<WireHistory>,
    pub next_spawn_sequence: String,
    pub next_state_activation_sequences: Vec<WireNextCounter>,
    pub next_component_activation_sequences: Vec<WireNextCounter>,
    pub fault: Option<WireFault>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AggregateEnvelope {
    pub aggregate_state_format: String,
    pub aggregate_state_schema_version: i64,
    pub machine_format: i64,
    pub validated_bundle_fingerprint: String,
    pub namespace: String,
    pub root_machine_id: String,
    pub root_machine_version: String,
    pub root_instance_id: String,
    pub creation_id: String,
    pub root_runtime_id: String,
    pub migration_sequence: String,
    pub next_logical_step_sequence: String,
    pub next_output_sequence: String,
    pub runtimes: Vec<WireRuntime>,
    pub aggregate_state_digest: String,
}

impl AggregateEnvelope {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PersistenceError> {
        canonical_bytes(self).map_err(|error| invalid_state(error.to_string()))
    }

    pub fn recompute_digest(&mut self) -> Result<(), PersistenceError> {
        let value =
            serde_json::to_value(&*self).map_err(|error| invalid_state(error.to_string()))?;
        self.aggregate_state_digest = aggregate_digest(&value)?;
        Ok(())
    }
}

pub fn encode_aggregate(
    bundle: &Bundle,
    state: &AggregateState,
) -> Result<(AggregateEnvelope, Vec<u8>), PersistenceError> {
    if !super::runtime::aggregate_is_valid_for_bundle(state, bundle) {
        return Err(invalid_state(
            "abstract aggregate is not valid under the supplied definition",
        ));
    }
    let mut runtimes = Vec::new();
    flatten_runtime(&state.root, &mut runtimes)?;
    if state.wire_runtime_order.len() == runtimes.len()
        && state.wire_runtime_order.iter().collect::<BTreeSet<_>>()
            == runtimes
                .iter()
                .map(|runtime| &runtime.runtime_id)
                .collect::<BTreeSet<_>>()
    {
        let order = state
            .wire_runtime_order
            .iter()
            .enumerate()
            .map(|(index, runtime_id)| (runtime_id.as_str(), index))
            .collect::<BTreeMap<_, _>>();
        runtimes.sort_by_key(|runtime| order[runtime.runtime_id.as_str()]);
    } else {
        runtimes.sort_by(|left, right| left.runtime_id.as_bytes().cmp(right.runtime_id.as_bytes()));
    }
    let mut envelope = AggregateEnvelope {
        aggregate_state_format: "determa.aggregate_state".to_string(),
        aggregate_state_schema_version: 1,
        machine_format: 1,
        validated_bundle_fingerprint: state.validated_bundle_fingerprint.clone(),
        namespace: state.namespace.clone(),
        root_machine_id: state.root.machine_id.clone(),
        root_machine_version: state.root.machine_version.to_string(),
        root_instance_id: state.root_instance_id.clone(),
        creation_id: state.creation_id.clone(),
        root_runtime_id: state.root.runtime_id.clone(),
        migration_sequence: state.migration_sequence.to_string(),
        next_logical_step_sequence: state.next_logical_step_sequence.to_string(),
        next_output_sequence: state.next_output_sequence.to_string(),
        runtimes,
        aggregate_state_digest: String::new(),
    };
    envelope.recompute_digest()?;
    validate_envelope_semantics(&envelope)?;
    let bytes = envelope.canonical_bytes()?;
    Ok((envelope, bytes))
}

pub fn restore_aggregate(
    source: &[u8],
    resolver: &(impl DefinitionResolver + ?Sized),
) -> Result<AggregateState, PersistenceError> {
    let (envelope, _) = parse_aggregate_envelope(source)?;
    restore_envelope(&envelope, resolver)
}

pub(crate) fn restore_envelope(
    envelope: &AggregateEnvelope,
    resolver: &(impl DefinitionResolver + ?Sized),
) -> Result<AggregateState, PersistenceError> {
    let mut definitions = BTreeMap::new();
    for runtime in &envelope.runtimes {
        collect_definition(&runtime.current_definition, resolver, &mut definitions)?;
        match &runtime.identity_origin {
            WireIdentityOrigin::Root { definition, .. }
            | WireIdentityOrigin::Component { definition, .. }
            | WireIdentityOrigin::OwnedSpawnedInstance { definition, .. } => {
                collect_definition(definition, resolver, &mut definitions)?;
            }
        }
        if let Some(fault) = &runtime.fault {
            collect_fingerprint(&fault.definition_fingerprint, resolver, &mut definitions)?;
        }
    }

    let targets = envelope
        .runtimes
        .iter()
        .map(|runtime| {
            Ok((
                runtime.runtime_id.clone(),
                target_from_wire(&runtime.target_identity)?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>, PersistenceError>>()?;
    let mut records = envelope
        .runtimes
        .iter()
        .map(|runtime| Ok((runtime.runtime_id.clone(), runtime.clone())))
        .collect::<Result<BTreeMap<_, _>, PersistenceError>>()?;
    let root_record = records
        .remove(&envelope.root_runtime_id)
        .ok_or_else(|| invalid_state("root runtime record is absent"))?;
    if !matches!(root_record.relation, WireRelation::Root) {
        return Err(invalid_state("root runtime relation is not root"));
    }
    let root = restore_runtime_tree(root_record, &mut records, &definitions, &targets, envelope)?;
    if !records.is_empty() {
        return Err(invalid_state("runtime ownership graph is disconnected"));
    }
    validate_root_header(envelope, &root)?;
    let aggregate = AggregateState {
        validated_bundle_fingerprint: envelope.validated_bundle_fingerprint.clone(),
        namespace: envelope.namespace.clone(),
        root_instance_id: envelope.root_instance_id.clone(),
        creation_id: envelope.creation_id.clone(),
        migration_sequence: Counter::from_decimal(&envelope.migration_sequence)
            .map_err(invalid_state)?,
        wire_runtime_order: envelope
            .runtimes
            .iter()
            .map(|runtime| runtime.runtime_id.clone())
            .collect(),
        root,
        next_logical_step_sequence: Counter::from_decimal(&envelope.next_logical_step_sequence)
            .map_err(invalid_state)?,
        next_output_sequence: Counter::from_decimal(&envelope.next_output_sequence)
            .map_err(invalid_state)?,
    };
    let current = definitions
        .get(&envelope.validated_bundle_fingerprint)
        .ok_or_else(|| {
            PersistenceError::new(
                PersistenceErrorCode::SourceDefinitionUnavailable,
                "aggregate definition is unavailable",
            )
        })?;
    if !super::runtime::aggregate_is_valid_for_bundle(&aggregate, current) {
        return Err(invalid_state(
            "restored aggregate is not valid under its current definition",
        ));
    }
    Ok(aggregate)
}

fn validate_root_header(
    envelope: &AggregateEnvelope,
    root: &RuntimeState,
) -> Result<(), PersistenceError> {
    let Target::Root {
        root_instance_id,
        root_runtime_id,
    } = &root.target_identity
    else {
        return Err(invalid_state("root runtime target is not root"));
    };
    if envelope.root_runtime_id != root.runtime_id
        || root_runtime_id != &root.runtime_id
        || envelope.root_instance_id != *root_instance_id
        || envelope.namespace != root.current_definition.machine.namespace
        || envelope.root_machine_id != root.current_definition.machine.machine_id
        || envelope.root_machine_version
            != root.current_definition.machine.machine_version.to_string()
        || envelope.validated_bundle_fingerprint
            != root.current_definition.validated_bundle_fingerprint
        || root.machine_id != root.current_definition.machine.machine_id
        || root.machine_version != root.current_definition.machine.machine_version
        || root.definition.root_pointer != root.current_definition.machine.root_definition_pointer
    {
        return Err(invalid_state(
            "aggregate header does not match the restored root runtime",
        ));
    }
    Ok(())
}

fn collect_definition(
    definition: &WireDefinitionBinding,
    resolver: &(impl DefinitionResolver + ?Sized),
    definitions: &mut BTreeMap<String, Bundle>,
) -> Result<(), PersistenceError> {
    collect_fingerprint(
        &definition.validated_bundle_fingerprint,
        resolver,
        definitions,
    )?;
    let bundle = &definitions[&definition.validated_bundle_fingerprint];
    let machine = find_machine_by_root_pointer(bundle, &definition.machine.root_definition_pointer)
        .ok_or_else(|| {
            PersistenceError::new(
                PersistenceErrorCode::DefinitionFingerprintMismatch,
                "definition root pointer does not resolve",
            )
        })?;
    if definition.machine.namespace != bundle.namespace
        || definition.machine.machine_id != machine.machine_id
        || definition.machine.machine_version != machine.version.to_string()
    {
        return Err(PersistenceError::new(
            PersistenceErrorCode::DefinitionFingerprintMismatch,
            "definition identity does not match normalized bundle",
        ));
    }
    Ok(())
}

fn collect_fingerprint(
    fingerprint: &str,
    resolver: &(impl DefinitionResolver + ?Sized),
    definitions: &mut BTreeMap<String, Bundle>,
) -> Result<(), PersistenceError> {
    if definitions.contains_key(fingerprint) {
        return Ok(());
    }
    let resolved = resolver.resolve_definition(fingerprint).ok_or_else(|| {
        PersistenceError::new(
            PersistenceErrorCode::SourceDefinitionUnavailable,
            "required definition is unavailable",
        )
    })?;
    if !resolved.trusted {
        return Err(PersistenceError::new(
            PersistenceErrorCode::DefinitionUntrusted,
            "required definition is not trusted",
        ));
    }
    if resolved.bundle.fingerprint != fingerprint {
        return Err(PersistenceError::new(
            PersistenceErrorCode::DefinitionFingerprintMismatch,
            "resolver key does not match the normalized definition fingerprint",
        ));
    }
    definitions.insert(fingerprint.to_string(), resolved.bundle);
    Ok(())
}

fn restore_runtime_tree(
    wire: WireRuntime,
    records: &mut BTreeMap<String, WireRuntime>,
    definitions: &BTreeMap<String, Bundle>,
    targets: &BTreeMap<String, Target>,
    envelope: &AggregateEnvelope,
) -> Result<RuntimeState, PersistenceError> {
    let mut runtime = restore_runtime(&wire, definitions, targets, envelope)?;
    let child_ids = records
        .iter()
        .filter_map(|(runtime_id, record)| match &record.relation {
            WireRelation::Component {
                owner_runtime_id, ..
            }
            | WireRelation::OwnedSpawnedInstance {
                owner_runtime_id, ..
            } if owner_runtime_id == &wire.runtime_id => Some(runtime_id.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    for child_id in child_ids {
        let record = records
            .remove(&child_id)
            .ok_or_else(|| invalid_state("owned runtime record disappeared"))?;
        let mut child =
            restore_runtime_tree(record.clone(), records, definitions, targets, envelope)?;
        match record.relation {
            WireRelation::Component {
                component_id,
                current_component_definition_pointer,
                activation_sequence,
                declaration_index,
                ..
            } => {
                let declaration = find_component_by_pointer(
                    &runtime.definition,
                    &current_component_definition_pointer,
                )
                .ok_or_else(|| {
                    invalid_state("component relation pointer does not resolve in owner")
                })?;
                if declaration.component_id != component_id
                    || declaration.declaration_index != parse_usize(&declaration_index)?
                {
                    return Err(invalid_state(
                        "component relation does not match owner definition",
                    ));
                }
                let owner_state_path =
                    parent_state_path(&current_component_definition_pointer, &runtime.definition)?;
                let RuntimeRelation::Component {
                    owner_state_path: child_owner_state_path,
                    ..
                } = &mut child.relation
                else {
                    return Err(invalid_state("component child relation changed kind"));
                };
                *child_owner_state_path = owner_state_path;
                runtime.components.push(ComponentRuntime {
                    component_id,
                    pointer: current_component_definition_pointer,
                    declaration_index: parse_usize(&declaration_index)?,
                    activation_sequence: parse_counter(&activation_sequence)?,
                    runtime: child,
                });
            }
            WireRelation::OwnedSpawnedInstance {
                current_spawn_action_pointer,
                spawn_sequence,
                lifetime_holder,
                ..
            } => {
                let reference = match &child.target_identity {
                    Target::SpawnedInstance(reference) => reference.clone(),
                    _ => return Err(invalid_state("owned runtime target is not spawned")),
                };
                let (holder_path, holder_pointer, holder_activation_sequence) =
                    if let Some(holder) = lifetime_holder {
                        let owner_machine = &runtime.definition;
                        let (path, _, _) = find_variable_by_pointer(
                            owner_machine,
                            &holder.variable_declaration_pointer,
                        )
                        .ok_or_else(|| invalid_state("lifetime holder pointer does not resolve"))?;
                        (
                            Some(path),
                            Some(holder.variable_declaration_pointer),
                            parse_counter(&holder.holder_state_activation_sequence)?,
                        )
                    } else {
                        (None, None, Counter::zero())
                    };
                let RuntimeRelation::Spawned {
                    holder_path: child_holder_path,
                    holder_pointer: child_holder_pointer,
                    holder_activation_sequence: child_holder_activation_sequence,
                    ..
                } = &mut child.relation
                else {
                    return Err(invalid_state("owned child relation changed kind"));
                };
                *child_holder_path = holder_path.clone();
                *child_holder_pointer = holder_pointer.clone();
                *child_holder_activation_sequence = holder_activation_sequence.clone();
                runtime.owned_instances.push(OwnedRuntime {
                    spawn_sequence: parse_counter(&spawn_sequence)?,
                    holder_path,
                    holder_pointer,
                    holder_activation_sequence,
                    reference,
                    runtime: child,
                });
                if current_spawn_action_pointer.is_empty() {
                    return Err(invalid_state("spawn relation pointer is empty"));
                }
            }
            WireRelation::Root => return Err(invalid_state("nested runtime has root relation")),
        }
    }
    runtime.components.sort_by(|left, right| {
        left.declaration_index
            .cmp(&right.declaration_index)
            .then_with(|| left.activation_sequence.cmp(&right.activation_sequence))
    });
    runtime
        .owned_instances
        .sort_by(|left, right| left.spawn_sequence.cmp(&right.spawn_sequence));
    Ok(runtime)
}

fn restore_runtime(
    wire: &WireRuntime,
    definitions: &BTreeMap<String, Bundle>,
    targets: &BTreeMap<String, Target>,
    envelope: &AggregateEnvelope,
) -> Result<RuntimeState, PersistenceError> {
    let bundle = definitions
        .get(&wire.current_definition.validated_bundle_fingerprint)
        .ok_or_else(|| invalid_state("current definition is unavailable"))?;
    let machine = find_machine_by_root_pointer(
        bundle,
        &wire.current_definition.machine.root_definition_pointer,
    )
    .cloned()
    .ok_or_else(|| invalid_state("current machine root pointer does not resolve"))?;
    let target = target_from_wire(&wire.target_identity)?;
    if target_root_instance_id(&target) != envelope.root_instance_id {
        return Err(invalid_state("runtime target has the wrong root instance"));
    }
    let (origin, origin_component_id) = origin_from_wire(&wire.identity_origin, definitions)?;
    let relation = relation_from_wire(&wire.relation, targets, &target)?;
    let pointer_states = machine
        .states
        .values()
        .map(|state| (state.pointer.clone(), state))
        .collect::<BTreeMap<_, _>>();
    let mut active = BTreeSet::new();
    for pointer in &wire.active_leaf_state_definition_pointers {
        let state = pointer_states
            .get(pointer)
            .ok_or_else(|| invalid_state("active state pointer does not resolve"))?;
        let mut path = Some(state.path.clone());
        while let Some(current) = path {
            if !active.insert(current.clone()) {
                break;
            }
            path = machine.states[&current].parent.clone();
        }
    }
    let mut active_state_activation_sequence = BTreeMap::new();
    for activation in &wire.active_state_activations {
        let state = pointer_states
            .get(&activation.state_definition_pointer)
            .ok_or_else(|| invalid_state("active-state activation pointer does not resolve"))?;
        active_state_activation_sequence.insert(
            state.path.clone(),
            parse_counter(&activation.activation_sequence)?,
        );
    }
    if active
        .iter()
        .any(|path| !active_state_activation_sequence.contains_key(path))
        || active_state_activation_sequence
            .keys()
            .any(|path| !active.contains(path))
    {
        return Err(invalid_state(
            "active-state pointers and activation records disagree",
        ));
    }
    let mut variables = BTreeMap::new();
    for variable in &wire.variables {
        let (path, name, declaration) =
            find_variable_by_pointer(&machine, &variable.variable_declaration_pointer)
                .ok_or_else(|| invalid_state("variable declaration pointer does not resolve"))?;
        let value = variable.value.to_value(Some(&declaration))?;
        validate_restored_value(&value, &declaration)?;
        variables.insert(
            format!("{path}\u{0}{name}"),
            VariableSlot {
                name,
                declaration_path: path,
                declaration_pointer: variable.variable_declaration_pointer.clone(),
                declaration,
                value,
                state_activation_sequence: parse_counter(
                    &variable.declaring_state_activation_sequence,
                )?,
            },
        );
    }
    let mut history = BTreeMap::new();
    for entry in &wire.history {
        let pointer = entry
            .history_declaration_pointer
            .strip_suffix("/history")
            .ok_or_else(|| invalid_state("history pointer is malformed"))?;
        let state = pointer_states
            .get(pointer)
            .ok_or_else(|| invalid_state("history pointer does not resolve"))?;
        let recorded = entry
            .recorded_state_definition_pointers
            .as_ref()
            .map(|pointers| {
                pointers
                    .iter()
                    .map(|pointer| {
                        pointer_states
                            .get(pointer)
                            .map(|state| state.path.clone())
                            .ok_or_else(|| {
                                invalid_state("recorded history pointer does not resolve")
                            })
                    })
                    .collect()
            })
            .transpose()?;
        history.insert(state.path.clone(), recorded);
    }
    let mut next_state_activation_sequence = BTreeMap::new();
    for entry in &wire.next_state_activation_sequences {
        let state = pointer_states
            .get(&entry.definition_pointer)
            .ok_or_else(|| invalid_state("state counter pointer does not resolve"))?;
        next_state_activation_sequence
            .insert(state.path.clone(), parse_counter(&entry.next_sequence)?);
    }
    let mut next_component_activation_sequence = BTreeMap::new();
    for entry in &wire.next_component_activation_sequences {
        find_component_by_pointer(&machine, &entry.definition_pointer)
            .ok_or_else(|| invalid_state("component counter pointer does not resolve"))?;
        next_component_activation_sequence.insert(
            entry.definition_pointer.clone(),
            parse_counter(&entry.next_sequence)?,
        );
    }
    let fault = wire
        .fault
        .as_ref()
        .map(|fault| {
            Ok(FaultRecord {
                definition_fingerprint: fault.definition_fingerprint.clone(),
                runtime_id: fault.runtime_id.clone(),
                cause_id: fault.cause_id.clone(),
                code: fault.code.clone(),
                step_sequence: parse_counter(&fault.step_sequence)?,
                source_locator: fault.source_locator.clone(),
            })
        })
        .transpose()?;
    Ok(RuntimeState {
        runtime_id: wire.runtime_id.clone(),
        identity_origin: origin,
        target_identity: target,
        current_definition: definition_from_wire(&wire.current_definition)?,
        origin_component_id,
        machine_id: machine.machine_id.clone(),
        machine_version: machine.version,
        definition: machine,
        status: wire.status,
        active,
        variables,
        history,
        components: Vec::new(),
        owned_instances: Vec::new(),
        next_spawn_sequence: parse_counter(&wire.next_spawn_sequence)?,
        next_component_activation_sequence,
        next_state_activation_sequence,
        active_state_activation_sequence,
        fault,
        relation,
    })
}

pub(crate) fn parse_aggregate_envelope(
    source: &[u8],
) -> Result<(AggregateEnvelope, JsonValue), PersistenceError> {
    let value = strict_json::parse(source).map_err(|error| invalid_state(error.to_string()))?;
    let Some(object) = value.as_object() else {
        return Err(invalid_state("aggregate state must be an object"));
    };
    match object.get("aggregate_state_format") {
        Some(JsonValue::String(value)) if value == "determa.aggregate_state" => {}
        _ => {
            return Err(PersistenceError::new(
                PersistenceErrorCode::UnsupportedAggregateStateFormat,
                "unsupported aggregate-state format",
            ));
        }
    }
    match object.get("aggregate_state_schema_version") {
        Some(JsonValue::Number(value)) if value.as_i64() == Some(1) => {}
        _ => {
            return Err(PersistenceError::new(
                PersistenceErrorCode::UnsupportedAggregateStateSchemaVersion,
                "unsupported aggregate-state schema version",
            ));
        }
    }
    validate_schema(
        &value,
        include_str!("../../schema/aggregate-state.schema.json"),
        PersistenceErrorCode::InvalidAggregateState,
    )?;
    let envelope: AggregateEnvelope =
        serde_json::from_value(value.clone()).map_err(|error| invalid_state(error.to_string()))?;
    validate_envelope_semantics(&envelope)?;
    let computed = aggregate_digest(&value)?;
    if envelope.aggregate_state_digest != computed {
        return Err(PersistenceError::new(
            PersistenceErrorCode::AggregateStateDigestMismatch,
            "aggregate-state digest does not match its contents",
        ));
    }
    Ok((envelope, value))
}

pub(crate) fn canonical_bytes<T: Serialize>(value: &T) -> serde_json::Result<Vec<u8>> {
    serde_json_canonicalizer::to_vec(value)
}

pub(crate) fn jcs_hash(value: &JsonValue) -> Result<String, PersistenceError> {
    let bytes = canonical_bytes(value).map_err(|error| invalid_state(error.to_string()))?;
    let digest = Sha256::digest(bytes);
    Ok(format!("sha256:{digest:x}"))
}

pub(crate) fn aggregate_digest(value: &JsonValue) -> Result<String, PersistenceError> {
    let mut envelope = value.clone();
    let Some(object) = envelope.as_object_mut() else {
        return Err(invalid_state("aggregate state must be an object"));
    };
    object.remove("aggregate_state_digest");
    jcs_hash(&json!(["determa-aggregate-state-digest-1", envelope]))
}

pub(crate) fn validate_schema(
    value: &JsonValue,
    schema_source: &str,
    code: PersistenceErrorCode,
) -> Result<(), PersistenceError> {
    let schema: JsonValue = serde_json::from_str(schema_source).expect("bundled schema is valid");
    let validator = jsonschema::validator_for(&schema)
        .map_err(|error| PersistenceError::new(code, error.to_string()))?;
    if let Some(error) = validator.iter_errors(value).next() {
        return Err(PersistenceError::new(code, error.to_string()));
    }
    Ok(())
}

fn invalid_state(message: impl Into<String>) -> PersistenceError {
    PersistenceError::new(PersistenceErrorCode::InvalidAggregateState, message)
}

fn parse_counter(value: &str) -> Result<Counter, PersistenceError> {
    Counter::from_decimal(value).map_err(invalid_state)
}

fn parse_usize(value: &str) -> Result<usize, PersistenceError> {
    value
        .parse::<usize>()
        .map_err(|_| invalid_state("decimal value is outside platform usize"))
}

fn definition_from_wire(
    definition: &WireDefinitionBinding,
) -> Result<DefinitionBinding, PersistenceError> {
    Ok(DefinitionBinding {
        validated_bundle_fingerprint: definition.validated_bundle_fingerprint.clone(),
        machine: MachineIdentity {
            namespace: definition.machine.namespace.clone(),
            machine_id: definition.machine.machine_id.clone(),
            machine_version: definition
                .machine
                .machine_version
                .parse()
                .map_err(|_| invalid_state("machine version is outside signed 64-bit"))?,
            root_definition_pointer: definition.machine.root_definition_pointer.clone(),
        },
    })
}

fn origin_from_wire(
    origin: &WireIdentityOrigin,
    definitions: &BTreeMap<String, Bundle>,
) -> Result<(IdentityOrigin, Option<String>), PersistenceError> {
    Ok(match origin {
        WireIdentityOrigin::Root {
            definition,
            root_instance_id,
        } => (
            IdentityOrigin::Root {
                definition: definition_from_wire(definition)?,
                root_instance_id: root_instance_id.clone(),
            },
            None,
        ),
        WireIdentityOrigin::Component {
            definition,
            owner_runtime_id,
            component_definition_pointer,
            activation_sequence,
            declaration_index,
        } => {
            let bundle = definitions
                .get(&definition.validated_bundle_fingerprint)
                .ok_or_else(|| invalid_state("component origin definition is unavailable"))?;
            let component =
                find_component_in_bundle_by_pointer(bundle, component_definition_pointer)
                    .ok_or_else(|| {
                        invalid_state("component origin pointer does not resolve in its definition")
                    })?;
            if component.declaration_index != parse_usize(declaration_index)? {
                return Err(invalid_state(
                    "component origin declaration index does not match its definition",
                ));
            }
            (
                IdentityOrigin::Component {
                    definition: definition_from_wire(definition)?,
                    owner_runtime_id: owner_runtime_id.clone(),
                    component_definition_pointer: component_definition_pointer.clone(),
                    activation_sequence: parse_counter(activation_sequence)?,
                    declaration_index: parse_counter(declaration_index)?,
                },
                Some(component.component_id.clone()),
            )
        }
        WireIdentityOrigin::OwnedSpawnedInstance {
            definition,
            owner_runtime_id,
            spawn_action_pointer,
            spawn_sequence,
        } => (
            IdentityOrigin::OwnedSpawnedInstance {
                definition: definition_from_wire(definition)?,
                owner_runtime_id: owner_runtime_id.clone(),
                spawn_action_pointer: spawn_action_pointer.clone(),
                spawn_sequence: parse_counter(spawn_sequence)?,
            },
            None,
        ),
    })
}

pub(crate) fn target_from_wire(target: &WireTarget) -> Result<Target, PersistenceError> {
    Ok(match target {
        WireTarget::Root { root } => Target::Root {
            root_instance_id: root.root_instance_id.clone(),
            root_runtime_id: root.root_runtime_id.clone(),
        },
        WireTarget::Component { component } => Target::Component {
            root_instance_id: component.root_instance_id.clone(),
            owner_runtime_id: component.owner_runtime_id.clone(),
            component_id: component.component_id.clone(),
            component_runtime_id: component.component_runtime_id.clone(),
            activation_sequence: parse_counter(&component.activation_sequence)?,
        },
        WireTarget::SpawnedInstance { spawned_instance } => {
            Target::SpawnedInstance(InstanceReference {
                root_instance_id: spawned_instance.root_instance_id.clone(),
                instance_id: spawned_instance.instance_id.clone(),
                machine_id: spawned_instance.machine_id.clone(),
                machine_version: spawned_instance.machine_version.parse().map_err(|_| {
                    invalid_state("spawned machine version is outside signed 64-bit")
                })?,
            })
        }
    })
}

fn target_root_instance_id(target: &Target) -> &str {
    match target {
        Target::Root {
            root_instance_id, ..
        }
        | Target::Component {
            root_instance_id, ..
        } => root_instance_id,
        Target::SpawnedInstance(reference) => &reference.root_instance_id,
        Target::External => "",
    }
}

fn relation_from_wire(
    relation: &WireRelation,
    targets: &BTreeMap<String, Target>,
    runtime_target: &Target,
) -> Result<RuntimeRelation, PersistenceError> {
    Ok(match relation {
        WireRelation::Root => RuntimeRelation::Root,
        WireRelation::Component {
            owner_runtime_id,
            component_id,
            current_component_definition_pointer,
            activation_sequence,
            declaration_index,
        } => {
            let owner_target = targets
                .get(owner_runtime_id)
                .cloned()
                .ok_or_else(|| invalid_state("component owner runtime is absent"))?;
            RuntimeRelation::Component {
                owner_runtime_id: owner_runtime_id.clone(),
                owner_target: Box::new(owner_target),
                owner_state_path: String::new(),
                component_id: component_id.clone(),
                component_pointer: current_component_definition_pointer.clone(),
                declaration_index: parse_usize(declaration_index)?,
                activation_sequence: parse_counter(activation_sequence)?,
            }
        }
        WireRelation::OwnedSpawnedInstance {
            owner_runtime_id,
            current_spawn_action_pointer,
            spawn_sequence,
            lifetime_holder,
        } => {
            let owner_target = targets
                .get(owner_runtime_id)
                .cloned()
                .ok_or_else(|| invalid_state("spawn owner runtime is absent"))?;
            let reference = match runtime_target {
                Target::SpawnedInstance(reference) => Some(reference.clone()),
                _ => None,
            }
            .ok_or_else(|| invalid_state("spawned target is absent"))?;
            let (holder_path, holder_pointer, holder_activation_sequence) =
                if let Some(holder) = lifetime_holder {
                    (
                        None,
                        Some(holder.variable_declaration_pointer.clone()),
                        parse_counter(&holder.holder_state_activation_sequence)?,
                    )
                } else {
                    (None, None, Counter::zero())
                };
            RuntimeRelation::Spawned {
                owner_runtime_id: owner_runtime_id.clone(),
                owner_target: Box::new(owner_target),
                spawn_sequence: parse_counter(spawn_sequence)?,
                spawn_pointer: current_spawn_action_pointer.clone(),
                reference,
                holder_path,
                holder_pointer,
                holder_activation_sequence,
            }
        }
    })
}

pub(crate) fn find_machine_by_root_pointer<'a>(
    bundle: &'a Bundle,
    pointer: &str,
) -> Option<&'a Machine> {
    for machine in bundle.machines.values() {
        if let Some(found) = find_machine_recursive(machine, pointer) {
            return Some(found);
        }
    }
    None
}

fn find_component_in_bundle_by_pointer<'a>(
    bundle: &'a Bundle,
    pointer: &str,
) -> Option<&'a Component> {
    bundle
        .machines
        .values()
        .find_map(|machine| find_component_recursive(machine, pointer))
}

fn find_component_recursive<'a>(machine: &'a Machine, pointer: &str) -> Option<&'a Component> {
    for state in machine.states.values() {
        for component in &state.components {
            if component.pointer == pointer {
                return Some(component);
            }
            if let ComponentDefinition::Inline(inline) = &component.definition {
                if let Some(found) = find_component_recursive(inline, pointer) {
                    return Some(found);
                }
            }
        }
    }
    None
}

fn find_machine_recursive<'a>(machine: &'a Machine, pointer: &str) -> Option<&'a Machine> {
    if machine.root_pointer == pointer {
        return Some(machine);
    }
    for state in machine.states.values() {
        for component in &state.components {
            if let ComponentDefinition::Inline(inline) = &component.definition {
                if let Some(found) = find_machine_recursive(inline, pointer) {
                    return Some(found);
                }
            }
        }
    }
    None
}

fn find_component_by_pointer<'a>(machine: &'a Machine, pointer: &str) -> Option<&'a Component> {
    machine
        .states
        .values()
        .flat_map(|state| &state.components)
        .find(|component| component.pointer == pointer)
}

fn parent_state_path(pointer: &str, machine: &Machine) -> Result<String, PersistenceError> {
    machine
        .states
        .values()
        .find(|state| {
            pointer
                .strip_prefix(&state.pointer)
                .is_some_and(|suffix| suffix.starts_with("/components/"))
        })
        .map(|state| state.path.clone())
        .ok_or_else(|| invalid_state("component owner state does not resolve"))
}

pub(crate) fn find_variable_by_pointer(
    machine: &Machine,
    pointer: &str,
) -> Option<(String, String, VariableDeclaration)> {
    for state in machine.states.values() {
        for (name, declaration) in &state.variables {
            if format!("{}/variables/{}", state.pointer, escape_pointer_token(name)) == pointer {
                return Some((state.path.clone(), name.clone(), declaration.clone()));
            }
        }
    }
    None
}

fn escape_pointer_token(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

fn validate_restored_value(
    value: &Value,
    declaration: &VariableDeclaration,
) -> Result<(), PersistenceError> {
    let valid = match declaration.value_type.as_str() {
        "null" => matches!(value, Value::Null),
        "bool" => matches!(value, Value::Bool(_)),
        "string" => matches!(value, Value::String(_)),
        "int" => matches!(value, Value::Int(_)),
        "float" => matches!(value, Value::Float(value) if value.is_finite()),
        "list" => matches!(value, Value::List(_)),
        "map" => matches!(value, Value::Map(_)),
        "instance_reference" => matches!(value, Value::InstanceReference(_)),
        _ => false,
    } || matches!(value, Value::Null) && declaration.nullable == Some(true);
    if valid {
        Ok(())
    } else {
        Err(invalid_state(
            "restored variable value does not match its declaration",
        ))
    }
}

fn instance_reference_from_value(value: Value) -> Result<Value, PersistenceError> {
    let Value::Map(values) = value else {
        return Err(invalid_state("instance_reference projection must be a map"));
    };
    let string = |name: &str| match values.get(name) {
        Some(Value::String(value)) if !value.is_empty() => Ok(value.clone()),
        _ => Err(invalid_state(format!(
            "instance_reference member {name:?} is invalid"
        ))),
    };
    let machine_version = match values.get("machine_version") {
        Some(Value::Int(value)) if *value > 0 => *value,
        _ => {
            return Err(invalid_state(
                "instance_reference machine_version is invalid",
            ));
        }
    };
    if values.len() != 4 {
        return Err(invalid_state("instance_reference has unknown members"));
    }
    Ok(Value::InstanceReference(InstanceReference {
        root_instance_id: string("root_instance_id")?,
        instance_id: string("instance_id")?,
        machine_id: string("machine_id")?,
        machine_version,
    }))
}

fn definition_to_wire(definition: &DefinitionBinding) -> WireDefinitionBinding {
    WireDefinitionBinding {
        validated_bundle_fingerprint: definition.validated_bundle_fingerprint.clone(),
        machine: WireMachineIdentity {
            namespace: definition.machine.namespace.clone(),
            machine_id: definition.machine.machine_id.clone(),
            machine_version: definition.machine.machine_version.to_string(),
            root_definition_pointer: definition.machine.root_definition_pointer.clone(),
        },
    }
}

fn origin_to_wire(origin: &IdentityOrigin) -> WireIdentityOrigin {
    match origin {
        IdentityOrigin::Root {
            definition,
            root_instance_id,
        } => WireIdentityOrigin::Root {
            definition: definition_to_wire(definition),
            root_instance_id: root_instance_id.clone(),
        },
        IdentityOrigin::Component {
            definition,
            owner_runtime_id,
            component_definition_pointer,
            activation_sequence,
            declaration_index,
        } => WireIdentityOrigin::Component {
            definition: definition_to_wire(definition),
            owner_runtime_id: owner_runtime_id.clone(),
            component_definition_pointer: component_definition_pointer.clone(),
            activation_sequence: activation_sequence.to_string(),
            declaration_index: declaration_index.to_string(),
        },
        IdentityOrigin::OwnedSpawnedInstance {
            definition,
            owner_runtime_id,
            spawn_action_pointer,
            spawn_sequence,
        } => WireIdentityOrigin::OwnedSpawnedInstance {
            definition: definition_to_wire(definition),
            owner_runtime_id: owner_runtime_id.clone(),
            spawn_action_pointer: spawn_action_pointer.clone(),
            spawn_sequence: spawn_sequence.to_string(),
        },
    }
}

pub(crate) fn target_to_wire(target: &Target) -> Result<WireTarget, PersistenceError> {
    Ok(match target {
        Target::Root {
            root_instance_id,
            root_runtime_id,
        } => WireTarget::Root {
            root: WireRootTarget {
                root_instance_id: root_instance_id.clone(),
                root_runtime_id: root_runtime_id.clone(),
            },
        },
        Target::Component {
            root_instance_id,
            owner_runtime_id,
            component_id,
            component_runtime_id,
            activation_sequence,
        } => WireTarget::Component {
            component: WireComponentTarget {
                root_instance_id: root_instance_id.clone(),
                owner_runtime_id: owner_runtime_id.clone(),
                component_id: component_id.clone(),
                component_runtime_id: component_runtime_id.clone(),
                activation_sequence: activation_sequence.to_string(),
            },
        },
        Target::SpawnedInstance(reference) => WireTarget::SpawnedInstance {
            spawned_instance: WireInstanceReference {
                root_instance_id: reference.root_instance_id.clone(),
                instance_id: reference.instance_id.clone(),
                machine_id: reference.machine_id.clone(),
                machine_version: reference.machine_version.to_string(),
            },
        },
        Target::External => {
            return Err(invalid_state(
                "external target cannot identify a retained runtime",
            ));
        }
    })
}

fn relation_to_wire(relation: &RuntimeRelation) -> WireRelation {
    match relation {
        RuntimeRelation::Root => WireRelation::Root,
        RuntimeRelation::Component {
            owner_runtime_id,
            component_id,
            component_pointer,
            declaration_index,
            activation_sequence,
            ..
        } => WireRelation::Component {
            owner_runtime_id: owner_runtime_id.clone(),
            component_id: component_id.clone(),
            current_component_definition_pointer: component_pointer.clone(),
            activation_sequence: activation_sequence.to_string(),
            declaration_index: declaration_index.to_string(),
        },
        RuntimeRelation::Spawned {
            owner_runtime_id,
            spawn_sequence,
            spawn_pointer,
            holder_pointer,
            holder_activation_sequence,
            ..
        } => WireRelation::OwnedSpawnedInstance {
            owner_runtime_id: owner_runtime_id.clone(),
            current_spawn_action_pointer: spawn_pointer.clone(),
            spawn_sequence: spawn_sequence.to_string(),
            lifetime_holder: holder_pointer.as_ref().map(|pointer| WireLifetimeHolder {
                holder_runtime_id: owner_runtime_id.clone(),
                variable_declaration_pointer: pointer.clone(),
                holder_state_activation_sequence: holder_activation_sequence.to_string(),
            }),
        },
    }
}

fn flatten_runtime(
    runtime: &RuntimeState,
    output: &mut Vec<WireRuntime>,
) -> Result<(), PersistenceError> {
    for component in &runtime.components {
        flatten_runtime(&component.runtime, output)?;
    }
    for owned in &runtime.owned_instances {
        flatten_runtime(&owned.runtime, output)?;
    }
    output.push(runtime_to_wire(runtime)?);
    Ok(())
}

fn runtime_to_wire(runtime: &RuntimeState) -> Result<WireRuntime, PersistenceError> {
    let mut leaves = runtime
        .active
        .iter()
        .filter(|path| {
            !runtime
                .active
                .iter()
                .any(|candidate| candidate != *path && is_descendant(candidate, path))
        })
        .map(|path| runtime.definition.states[path].pointer.clone())
        .collect::<Vec<_>>();
    leaves.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));

    let mut activations = runtime
        .active_state_activation_sequence
        .iter()
        .map(|(path, sequence)| WireStateActivation {
            state_definition_pointer: runtime.definition.states[path].pointer.clone(),
            activation_sequence: sequence.to_string(),
        })
        .collect::<Vec<_>>();
    activations.sort_by(|left, right| {
        left.state_definition_pointer
            .as_bytes()
            .cmp(right.state_definition_pointer.as_bytes())
            .then_with(|| decimal_cmp(&left.activation_sequence, &right.activation_sequence))
    });

    let mut variables = runtime
        .variables
        .values()
        .map(|slot| WireVariable {
            variable_declaration_pointer: slot.declaration_pointer.clone(),
            declaring_state_activation_sequence: slot.state_activation_sequence.to_string(),
            value: TypedValue::from_value(&slot.value),
        })
        .collect::<Vec<_>>();
    variables.sort_by(|left, right| {
        left.variable_declaration_pointer
            .as_bytes()
            .cmp(right.variable_declaration_pointer.as_bytes())
            .then_with(|| {
                decimal_cmp(
                    &left.declaring_state_activation_sequence,
                    &right.declaring_state_activation_sequence,
                )
            })
    });

    let mut history = runtime
        .history
        .iter()
        .map(|(path, recorded)| {
            let state = &runtime.definition.states[path];
            let mut recorded = recorded.as_ref().map(|paths| {
                paths
                    .iter()
                    .map(|path| runtime.definition.states[path].pointer.clone())
                    .collect::<Vec<_>>()
            });
            if let Some(recorded) = &mut recorded {
                recorded.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
            }
            WireHistory {
                history_declaration_pointer: format!("{}/history", state.pointer),
                recorded_state_definition_pointers: recorded,
            }
        })
        .collect::<Vec<_>>();
    history.sort_by(|left, right| {
        left.history_declaration_pointer
            .as_bytes()
            .cmp(right.history_declaration_pointer.as_bytes())
    });

    let mut next_state = runtime
        .next_state_activation_sequence
        .iter()
        .map(|(path, sequence)| WireNextCounter {
            definition_pointer: runtime.definition.states[path].pointer.clone(),
            next_sequence: sequence.to_string(),
        })
        .collect::<Vec<_>>();
    next_state.sort_by(|left, right| {
        left.definition_pointer
            .as_bytes()
            .cmp(right.definition_pointer.as_bytes())
    });
    let mut next_component = runtime
        .next_component_activation_sequence
        .iter()
        .map(|(pointer, sequence)| WireNextCounter {
            definition_pointer: pointer.clone(),
            next_sequence: sequence.to_string(),
        })
        .collect::<Vec<_>>();
    next_component.sort_by(|left, right| {
        left.definition_pointer
            .as_bytes()
            .cmp(right.definition_pointer.as_bytes())
    });

    Ok(WireRuntime {
        runtime_id: runtime.runtime_id.clone(),
        identity_origin: origin_to_wire(&runtime.identity_origin),
        target_identity: target_to_wire(&runtime.target_identity)?,
        current_definition: definition_to_wire(&runtime.current_definition),
        relation: relation_to_wire(&runtime.relation),
        status: runtime.status,
        active_leaf_state_definition_pointers: leaves,
        active_state_activations: activations,
        variables,
        history,
        next_spawn_sequence: runtime.next_spawn_sequence.to_string(),
        next_state_activation_sequences: next_state,
        next_component_activation_sequences: next_component,
        fault: runtime.fault.as_ref().map(|fault| WireFault {
            definition_fingerprint: fault.definition_fingerprint.clone(),
            runtime_id: fault.runtime_id.clone(),
            cause_id: fault.cause_id.clone(),
            code: fault.code.clone(),
            step_sequence: fault.step_sequence.to_string(),
            source_locator: fault.source_locator.clone(),
        }),
    })
}

fn validate_envelope_semantics(envelope: &AggregateEnvelope) -> Result<(), PersistenceError> {
    require_canonical_decimal(&envelope.root_machine_version, true)?;
    require_canonical_decimal(&envelope.migration_sequence, false)?;
    require_canonical_decimal(&envelope.next_logical_step_sequence, false)?;
    require_canonical_decimal(&envelope.next_output_sequence, false)?;
    if envelope.runtimes.is_empty() {
        return Err(invalid_state("runtime records must not be empty"));
    }
    let ids = envelope
        .runtimes
        .iter()
        .map(|runtime| runtime.runtime_id.as_str())
        .collect::<BTreeSet<_>>();
    if ids.len() != envelope.runtimes.len() || !ids.contains(envelope.root_runtime_id.as_str()) {
        return Err(invalid_state(
            "runtime identities are incomplete or duplicated",
        ));
    }
    for runtime in &envelope.runtimes {
        validate_wire_runtime(runtime)?;
    }
    Ok(())
}

fn validate_wire_runtime(runtime: &WireRuntime) -> Result<(), PersistenceError> {
    require_canonical_decimal(&runtime.next_spawn_sequence, false)?;
    require_ordered_unique(&runtime.active_leaf_state_definition_pointers)?;
    require_ordered_by(
        &runtime.active_state_activations,
        |value| value.state_definition_pointer.as_bytes(),
        |left, right| decimal_cmp(&left.activation_sequence, &right.activation_sequence),
    )?;
    require_ordered_by(
        &runtime.variables,
        |value| value.variable_declaration_pointer.as_bytes(),
        |left, right| {
            decimal_cmp(
                &left.declaring_state_activation_sequence,
                &right.declaring_state_activation_sequence,
            )
        },
    )?;
    require_ordered_by(
        &runtime.history,
        |value| value.history_declaration_pointer.as_bytes(),
        |_, _| std::cmp::Ordering::Equal,
    )?;
    require_ordered_by(
        &runtime.next_state_activation_sequences,
        |value| value.definition_pointer.as_bytes(),
        |_, _| std::cmp::Ordering::Equal,
    )?;
    require_ordered_by(
        &runtime.next_component_activation_sequences,
        |value| value.definition_pointer.as_bytes(),
        |_, _| std::cmp::Ordering::Equal,
    )?;
    for activation in &runtime.active_state_activations {
        require_canonical_decimal(&activation.activation_sequence, false)?;
    }
    for variable in &runtime.variables {
        require_canonical_decimal(&variable.declaring_state_activation_sequence, false)?;
    }
    for counter in runtime
        .next_state_activation_sequences
        .iter()
        .chain(&runtime.next_component_activation_sequences)
    {
        require_canonical_decimal(&counter.next_sequence, false)?;
    }
    match &runtime.identity_origin {
        WireIdentityOrigin::Root { definition, .. } => validate_wire_definition(definition)?,
        WireIdentityOrigin::Component {
            definition,
            activation_sequence,
            declaration_index,
            ..
        } => {
            validate_wire_definition(definition)?;
            require_canonical_decimal(activation_sequence, false)?;
            require_canonical_decimal(declaration_index, false)?;
        }
        WireIdentityOrigin::OwnedSpawnedInstance {
            definition,
            spawn_sequence,
            ..
        } => {
            validate_wire_definition(definition)?;
            require_canonical_decimal(spawn_sequence, false)?;
        }
    }
    validate_wire_definition(&runtime.current_definition)?;
    match &runtime.target_identity {
        WireTarget::Root { .. } => {}
        WireTarget::Component { component } => {
            require_canonical_decimal(&component.activation_sequence, false)?;
        }
        WireTarget::SpawnedInstance { spawned_instance } => {
            require_canonical_decimal(&spawned_instance.machine_version, true)?;
            spawned_instance
                .machine_version
                .parse::<i64>()
                .map_err(|_| invalid_state("spawned target machine_version is outside i64"))?;
        }
    }
    match &runtime.relation {
        WireRelation::Root => {}
        WireRelation::Component {
            activation_sequence,
            declaration_index,
            ..
        } => {
            require_canonical_decimal(activation_sequence, false)?;
            require_canonical_decimal(declaration_index, false)?;
        }
        WireRelation::OwnedSpawnedInstance {
            spawn_sequence,
            lifetime_holder,
            ..
        } => {
            require_canonical_decimal(spawn_sequence, false)?;
            if let Some(holder) = lifetime_holder {
                require_canonical_decimal(&holder.holder_state_activation_sequence, false)?;
            }
        }
    }
    if let Some(fault) = &runtime.fault {
        require_canonical_decimal(&fault.step_sequence, false)?;
    }
    Ok(())
}

fn validate_wire_definition(definition: &WireDefinitionBinding) -> Result<(), PersistenceError> {
    require_canonical_decimal(&definition.machine.machine_version, true)?;
    definition
        .machine
        .machine_version
        .parse::<i64>()
        .map_err(|_| invalid_state("machine_version is outside signed 64-bit"))?;
    Ok(())
}

fn require_canonical_decimal(value: &str, positive: bool) -> Result<(), PersistenceError> {
    let canonical = if positive {
        !value.is_empty()
            && !value.starts_with('0')
            && value.bytes().all(|byte| byte.is_ascii_digit())
    } else {
        value == "0"
            || (!value.is_empty()
                && !value.starts_with('0')
                && value.bytes().all(|byte| byte.is_ascii_digit()))
    };
    if canonical {
        Ok(())
    } else {
        Err(invalid_state("noncanonical decimal string"))
    }
}

fn require_ordered_unique(values: &[String]) -> Result<(), PersistenceError> {
    if values
        .windows(2)
        .any(|values| values[0].as_bytes() >= values[1].as_bytes())
    {
        Err(invalid_state("array is not in canonical order"))
    } else {
        Ok(())
    }
}

fn require_ordered_by<T>(
    values: &[T],
    key: impl Fn(&T) -> &[u8],
    secondary: impl Fn(&T, &T) -> std::cmp::Ordering,
) -> Result<(), PersistenceError> {
    if values.windows(2).any(|values| {
        key(&values[0])
            .cmp(key(&values[1]))
            .then_with(|| secondary(&values[0], &values[1]))
            != std::cmp::Ordering::Less
    }) {
        Err(invalid_state("array is not in canonical order"))
    } else {
        Ok(())
    }
}

fn decimal_cmp(left: &str, right: &str) -> std::cmp::Ordering {
    left.len()
        .cmp(&right.len())
        .then_with(|| left.as_bytes().cmp(right.as_bytes()))
}

fn is_descendant(path: &str, ancestor: &str) -> bool {
    ancestor == "root" && path != "root"
        || path
            .strip_prefix(ancestor)
            .is_some_and(|suffix| suffix.starts_with('.'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format1::{load_bundle, InMemoryDefinitionResolver};

    #[test]
    fn restores_and_canonicalizes_normative_aggregate() {
        let directory = "conformance-suite/conformance/core/94-aggregate-wire-round-trip";
        let bundle =
            load_bundle(&std::fs::read_to_string(format!("{directory}/machine.yaml")).unwrap())
                .unwrap();
        let mut resolver = InMemoryDefinitionResolver::default();
        assert!(resolver.insert(bundle.clone(), true));
        let source = std::fs::read(format!("{directory}/source-aggregate-state.json")).unwrap();
        let restored = restore_aggregate(&source, &resolver).unwrap();
        let (_, bytes) = encode_aggregate(&bundle, &restored).unwrap();
        assert_eq!(
            bytes,
            std::fs::read(format!("{directory}/source-aggregate-state.canonical.json")).unwrap()
        );
    }

    #[test]
    fn rejects_digest_consistent_root_header_forgery() {
        let directory = "conformance-suite/conformance/core/94-aggregate-wire-round-trip";
        let bundle =
            load_bundle(&std::fs::read_to_string(format!("{directory}/machine.yaml")).unwrap())
                .unwrap();
        let mut resolver = InMemoryDefinitionResolver::default();
        assert!(resolver.insert(bundle, true));
        let source = std::fs::read(format!("{directory}/source-aggregate-state.json")).unwrap();

        for (member, forged) in [("root_machine_id", "forged"), ("root_machine_version", "2")] {
            let mut value: JsonValue = serde_json::from_slice(&source).unwrap();
            value[member] = JsonValue::String(forged.to_string());
            let digest = aggregate_digest(&value).unwrap();
            value["aggregate_state_digest"] = JsonValue::String(digest);
            let bytes = canonical_bytes(&value).unwrap();
            let failure = restore_aggregate(&bytes, &resolver).unwrap_err();
            assert_eq!(
                failure.code,
                PersistenceErrorCode::InvalidAggregateState,
                "{member}"
            );
        }
    }

    #[test]
    fn rejects_forged_immutable_component_target_name() {
        let directory = "conformance-suite/conformance/core/104-component-migration";
        let bundle =
            load_bundle(&std::fs::read_to_string(format!("{directory}/machine.yaml")).unwrap())
                .unwrap();
        let mut resolver = InMemoryDefinitionResolver::default();
        assert!(resolver.insert(bundle.clone(), true));
        let source = std::fs::read(format!("{directory}/source-aggregate-state.json")).unwrap();
        let mut restored = restore_aggregate(&source, &resolver).unwrap();
        let Target::Component { component_id, .. } =
            &mut restored.root.components[0].runtime.target_identity
        else {
            panic!("fixture component target changed kind");
        };
        *component_id = "forged".to_string();
        let dispatch = super::super::runtime::dispatch(&bundle, &restored, None);
        assert_eq!(
            dispatch.rejection.as_ref().map(|value| value.code.as_str()),
            Some("invalid_prior_state")
        );

        let mut value: JsonValue = serde_json::from_slice(&source).unwrap();
        let component = value["runtimes"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|runtime| runtime["identity_origin"]["kind"] == "component")
            .unwrap();
        component["target_identity"]["component"]["component_id"] =
            JsonValue::String("forged".to_string());
        let digest = aggregate_digest(&value).unwrap();
        value["aggregate_state_digest"] = JsonValue::String(digest);
        let bytes = canonical_bytes(&value).unwrap();

        let failure = restore_aggregate(&bytes, &resolver).unwrap_err();
        assert_eq!(failure.code, PersistenceErrorCode::InvalidAggregateState);
    }
}
