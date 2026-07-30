use super::cel::{self, Environment};
use super::compile::{
    Bundle, CompiledActionKind, CompiledStateKind, ComponentDefinition, Machine, State,
};
use super::counter::Counter;
use super::persistence::MigrationArtifactResolver;
use super::wire::{
    canonical_bytes, find_machine_by_root_pointer, find_variable_by_pointer, jcs_hash,
    parse_aggregate_envelope, restore_envelope, AggregateEnvelope, PersistenceError,
    PersistenceErrorCode, TypedValue, WireDefinitionBinding, WireHistory, WireLifetimeHolder,
    WireNextCounter, WireRelation, WireVariable,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use std::collections::{BTreeSet, HashSet};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceLimits {
    pub maximum_aggregate_bytes: Counter,
    pub maximum_definition_bytes: Counter,
    pub maximum_descriptor_bytes: Counter,
    pub maximum_transformed_output_bytes: Counter,
    pub maximum_json_nesting_depth: Counter,
    pub maximum_runtimes: Counter,
    pub maximum_active_states_per_runtime: Counter,
    pub maximum_variables_per_runtime: Counter,
    pub maximum_map_members: Counter,
    pub maximum_list_members: Counter,
    pub maximum_string_utf8_bytes: Counter,
    pub maximum_chain_length: Counter,
    pub maximum_descriptor_rules: Counter,
    pub maximum_cel_expression_length: Counter,
    pub maximum_cel_ast_nodes: Counter,
    pub maximum_cel_evaluation_steps: Counter,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            maximum_aggregate_bytes: 1_048_576_u64.into(),
            maximum_definition_bytes: 1_048_576_u64.into(),
            maximum_descriptor_bytes: 65_536_u64.into(),
            maximum_transformed_output_bytes: 65_536_u64.into(),
            maximum_json_nesting_depth: 64_u64.into(),
            maximum_runtimes: 256_u64.into(),
            maximum_active_states_per_runtime: 1_024_u64.into(),
            maximum_variables_per_runtime: 4_096_u64.into(),
            maximum_map_members: 4_096_u64.into(),
            maximum_list_members: 4_096_u64.into(),
            maximum_string_utf8_bytes: 65_536_u64.into(),
            maximum_chain_length: 8_u64.into(),
            maximum_descriptor_rules: 1_024_u64.into(),
            maximum_cel_expression_length: 65_536_u64.into(),
            maximum_cel_ast_nodes: 65_536_u64.into(),
            maximum_cel_evaluation_steps: 1_000_000_u64.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationRequest {
    pub migration_route: Vec<String>,
    pub target_validated_bundle_fingerprint: String,
    pub maintenance_mode: bool,
}

impl MigrationRequest {
    pub fn from_json(value: &JsonValue) -> Result<Self, PersistenceError> {
        let object = value.as_object().ok_or_else(|| {
            error(
                PersistenceErrorCode::InvalidMigrationRequest,
                "migration request must be an object",
            )
        })?;
        if object.keys().map(String::as_str).collect::<BTreeSet<_>>()
            != BTreeSet::from([
                "maintenance_mode",
                "migration_route",
                "target_validated_bundle_fingerprint",
            ])
        {
            return Err(error(
                PersistenceErrorCode::InvalidMigrationRequest,
                "migration request members are not closed",
            ));
        }
        let migration_route = object["migration_route"]
            .as_array()
            .ok_or_else(|| {
                error(
                    PersistenceErrorCode::InvalidMigrationRequest,
                    "migration route must be an array",
                )
            })?
            .iter()
            .map(|value| {
                value.as_str().map(str::to_string).ok_or_else(|| {
                    error(
                        PersistenceErrorCode::InvalidMigrationRequest,
                        "migration route digest must be a string",
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            migration_route,
            target_validated_bundle_fingerprint: object["target_validated_bundle_fingerprint"]
                .as_str()
                .ok_or_else(|| {
                    error(
                        PersistenceErrorCode::InvalidMigrationRequest,
                        "target fingerprint must be a string",
                    )
                })?
                .to_string(),
            maintenance_mode: object["maintenance_mode"].as_bool().ok_or_else(|| {
                error(
                    PersistenceErrorCode::InvalidMigrationRequest,
                    "maintenance mode must be Boolean",
                )
            })?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationAuditRecord {
    pub migration_audit_record_schema_version: i64,
    pub root_instance_id: String,
    pub root_runtime_id: String,
    pub migration_sequence: String,
    pub source_validated_bundle_fingerprint: String,
    pub target_validated_bundle_fingerprint: String,
    pub migration_descriptor_digest: String,
    pub source_aggregate_state_digest: String,
    pub target_aggregate_state_digest: String,
    pub result_code: String,
}

#[derive(Debug, Clone)]
pub struct MigrationOutcome {
    pub aggregate: super::runtime::AggregateState,
    pub aggregate_envelope: AggregateEnvelope,
    pub aggregate_bytes: Vec<u8>,
    pub audit_records: Vec<MigrationAuditRecord>,
}

#[derive(Debug, Clone)]
pub struct MigrationDispatchOutcome {
    pub migration: MigrationOutcome,
    pub disposition: Option<super::runtime::Disposition>,
    pub emissions: Vec<super::runtime::Emission>,
    pub fault: Option<super::runtime::FaultRecord>,
    pub rejection: Option<super::runtime::Rejection>,
}

pub fn migrate_and_dispatch(
    source: &[u8],
    request: &MigrationRequest,
    resolver: &(impl MigrationArtifactResolver + ?Sized),
    limits: &ResourceLimits,
    delivery: Option<super::model::Delivery>,
) -> Result<MigrationDispatchOutcome, PersistenceError> {
    let mut migration = migrate_aggregate(source, request, resolver, limits)?;
    let target = resolve_definition(
        resolver,
        &migration.aggregate_envelope.validated_bundle_fingerprint,
        DefinitionRole::Target,
    )?;
    let result = super::runtime::dispatch(&target, &migration.aggregate, delivery);
    let state = result
        .state
        .ok_or_else(|| totality("core dispatch did not return aggregate state"))?;
    let (aggregate_envelope, aggregate_bytes) = super::wire::encode_aggregate(&target, &state)?;
    migration.aggregate = state;
    migration.aggregate_envelope = aggregate_envelope;
    migration.aggregate_bytes = aggregate_bytes;
    Ok(MigrationDispatchOutcome {
        migration,
        disposition: result.disposition,
        emissions: result.emissions,
        fault: result.fault,
        rejection: result.rejection,
    })
}

pub fn migrate_aggregate(
    source: &[u8],
    request: &MigrationRequest,
    resolver: &(impl MigrationArtifactResolver + ?Sized),
    limits: &ResourceLimits,
) -> Result<MigrationOutcome, PersistenceError> {
    require_within(source.len(), &limits.maximum_aggregate_bytes)?;
    require_within(request.migration_route.len(), &limits.maximum_chain_length)?;
    let (mut envelope, _) = parse_aggregate_envelope(source)?;
    enforce_aggregate_limits(&envelope, limits)?;
    let source_bundle = resolve_definition(
        resolver,
        &envelope.validated_bundle_fingerprint,
        DefinitionRole::Source,
    )?;
    enforce_definition_limits(&source_bundle, limits)?;
    restore_envelope(&envelope, resolver)?;

    if request.migration_route.is_empty() {
        if request.target_validated_bundle_fingerprint != envelope.validated_bundle_fingerprint {
            return Err(error(
                PersistenceErrorCode::MigrationRouteMissing,
                "empty route does not reach requested definition",
            ));
        }
        let aggregate = restore_envelope(&envelope, resolver)?;
        return Ok(MigrationOutcome {
            aggregate,
            aggregate_envelope: envelope,
            aggregate_bytes: source.to_vec(),
            audit_records: Vec::new(),
        });
    }
    if envelope
        .runtimes
        .iter()
        .any(|runtime| runtime.status != super::runtime::RuntimeStatus::Running)
        && !request.maintenance_mode
    {
        return Err(error(
            PersistenceErrorCode::TerminalMigrationRequiresMaintenance,
            "terminal aggregate migration requires maintenance mode",
        ));
    }
    let mut seen_digests = HashSet::new();
    let mut seen_fingerprints = HashSet::from([envelope.validated_bundle_fingerprint.clone()]);
    let mut expected_source_fingerprint = envelope.validated_bundle_fingerprint.clone();
    let mut expected_source_bundle = source_bundle;
    let mut prepared_route = Vec::new();
    for (route_index, digest) in request.migration_route.iter().enumerate() {
        if !seen_digests.insert(digest.clone()) {
            return Err(route_mismatch("descriptor digest repeats"));
        }
        let descriptor = resolve_descriptor(resolver, digest, limits)?;
        let source_fingerprint =
            string(&descriptor, "source_validated_bundle_fingerprint")?.to_string();
        let target_fingerprint =
            string(&descriptor, "target_validated_bundle_fingerprint")?.to_string();
        if source_fingerprint != expected_source_fingerprint {
            return Err(route_mismatch("descriptor source does not match candidate"));
        }
        if !seen_fingerprints.insert(target_fingerprint.clone()) {
            return Err(route_mismatch("descriptor route contains a cycle"));
        }
        if route_index + 1 == request.migration_route.len()
            && target_fingerprint != request.target_validated_bundle_fingerprint
        {
            return Err(route_mismatch("route does not reach requested definition"));
        }
        let target_bundle =
            resolve_definition(resolver, &target_fingerprint, DefinitionRole::Target)?;
        enforce_definition_limits(&target_bundle, limits)?;
        validate_descriptor_definitions(&descriptor, &expected_source_bundle, &target_bundle)?;
        enforce_descriptor_rules(&descriptor, limits)?;
        enforce_terminal_policy(&envelope, &descriptor)?;
        expected_source_fingerprint = target_fingerprint;
        expected_source_bundle = target_bundle.clone();
        prepared_route.push((digest.clone(), descriptor, target_bundle));
    }

    let mut audit_records = Vec::new();
    let mut current_bytes = source.to_vec();
    for (digest, descriptor, target_bundle) in prepared_route {
        let source_fingerprint =
            string(&descriptor, "source_validated_bundle_fingerprint")?.to_string();
        let target_fingerprint =
            string(&descriptor, "target_validated_bundle_fingerprint")?.to_string();
        let source_digest = envelope.aggregate_state_digest.clone();
        apply_descriptor(&mut envelope, &descriptor, &target_bundle, limits)?;
        envelope.recompute_digest()?;
        enforce_aggregate_limits(&envelope, limits)?;
        let aggregate = restore_envelope(&envelope, resolver)
            .map_err(|failure| totality(failure.to_string()))?;
        current_bytes = envelope.canonical_bytes()?;
        require_within(current_bytes.len(), &limits.maximum_aggregate_bytes)?;
        audit_records.push(MigrationAuditRecord {
            migration_audit_record_schema_version: 1,
            root_instance_id: envelope.root_instance_id.clone(),
            root_runtime_id: envelope.root_runtime_id.clone(),
            migration_sequence: envelope.migration_sequence.clone(),
            source_validated_bundle_fingerprint: source_fingerprint,
            target_validated_bundle_fingerprint: target_fingerprint,
            migration_descriptor_digest: digest,
            source_aggregate_state_digest: source_digest,
            target_aggregate_state_digest: envelope.aggregate_state_digest.clone(),
            result_code: "migration_applied".to_string(),
        });
        drop(aggregate);
    }
    let aggregate = restore_envelope(&envelope, resolver)?;
    Ok(MigrationOutcome {
        aggregate,
        aggregate_envelope: envelope,
        aggregate_bytes: current_bytes,
        audit_records,
    })
}

enum DefinitionRole {
    Source,
    Target,
}

fn resolve_definition(
    resolver: &(impl MigrationArtifactResolver + ?Sized),
    fingerprint: &str,
    role: DefinitionRole,
) -> Result<Bundle, PersistenceError> {
    let resolved = resolver.resolve_definition(fingerprint).ok_or_else(|| {
        error(
            match role {
                DefinitionRole::Source => PersistenceErrorCode::SourceDefinitionUnavailable,
                DefinitionRole::Target => PersistenceErrorCode::TargetDefinitionUnavailable,
            },
            "definition is unavailable",
        )
    })?;
    if !resolved.trusted {
        return Err(error(
            PersistenceErrorCode::DefinitionUntrusted,
            "definition is not trusted",
        ));
    }
    if resolved.bundle.fingerprint != fingerprint {
        return Err(error(
            PersistenceErrorCode::DefinitionFingerprintMismatch,
            "definition resolver key does not match content",
        ));
    }
    Ok(resolved.bundle)
}

fn resolve_descriptor(
    resolver: &(impl MigrationArtifactResolver + ?Sized),
    digest: &str,
    limits: &ResourceLimits,
) -> Result<JsonValue, PersistenceError> {
    let resolved = resolver
        .resolve_migration_descriptor(digest)
        .ok_or_else(|| {
            error(
                PersistenceErrorCode::MigrationRouteMismatch,
                "migration descriptor is unavailable",
            )
        })?;
    if !resolved.trusted {
        return Err(error(
            PersistenceErrorCode::MigrationDescriptorUntrusted,
            "migration descriptor is not trusted",
        ));
    }
    require_within(resolved.bytes.len(), &limits.maximum_descriptor_bytes)?;
    let value = super::strict_json::parse(&resolved.bytes).map_err(|parse| {
        error(
            PersistenceErrorCode::InvalidMigrationDescriptor,
            parse.to_string(),
        )
    })?;
    let object = value.as_object().ok_or_else(|| {
        error(
            PersistenceErrorCode::InvalidMigrationDescriptor,
            "descriptor must be an object",
        )
    })?;
    match object.get("migration_descriptor_format") {
        Some(JsonValue::String(value)) if value == "determa.aggregate_migration" => {}
        _ => {
            return Err(error(
                PersistenceErrorCode::UnsupportedMigrationDescriptorFormat,
                "unsupported migration descriptor format",
            ));
        }
    }
    match object.get("migration_descriptor_schema_version") {
        Some(JsonValue::Number(value)) if value.as_i64() == Some(1) => {}
        _ => {
            return Err(error(
                PersistenceErrorCode::UnsupportedMigrationDescriptorSchemaVersion,
                "unsupported migration descriptor schema version",
            ));
        }
    }
    super::wire::validate_schema(
        &value,
        include_str!("../../schema/migration-descriptor.schema.json"),
        PersistenceErrorCode::InvalidMigrationDescriptor,
    )?;
    let mut without_digest = value.clone();
    without_digest
        .as_object_mut()
        .expect("checked object")
        .remove("migration_descriptor_digest");
    let computed = jcs_hash(&json!(["determa-migration-descriptor-1", without_digest]))?;
    if computed != digest || string(&value, "migration_descriptor_digest")? != digest {
        return Err(error(
            PersistenceErrorCode::InvalidMigrationDescriptor,
            "migration descriptor digest mismatch",
        ));
    }
    Ok(value)
}

fn validate_descriptor_definitions(
    descriptor: &JsonValue,
    source: &Bundle,
    target: &Bundle,
) -> Result<(), PersistenceError> {
    if string(descriptor, "source_validated_bundle_fingerprint")? != source.fingerprint
        || string(descriptor, "target_validated_bundle_fingerprint")? != target.fingerprint
    {
        return Err(route_mismatch(
            "descriptor definition fingerprints do not match resolved definitions",
        ));
    }
    let source_shape = aggregate_shape_fingerprint(source)?;
    let target_shape = aggregate_shape_fingerprint(target)?;
    if string(descriptor, "source_aggregate_shape_fingerprint")? != source_shape
        || string(descriptor, "target_aggregate_shape_fingerprint")? != target_shape
    {
        return Err(invalid_descriptor(
            "descriptor aggregate-shape fingerprint does not match definition",
        ));
    }
    if string(descriptor, "mode")? == "compatible" && source_shape != target_shape {
        return Err(invalid_descriptor(
            "compatible descriptor requires equal aggregate shapes",
        ));
    }
    validate_migration_expressions(descriptor, source, target)?;
    Ok(())
}

fn validate_migration_expressions(
    descriptor: &JsonValue,
    source: &Bundle,
    target: &Bundle,
) -> Result<(), PersistenceError> {
    let mappings = descriptor["mappings"]
        .as_object()
        .ok_or_else(|| invalid_descriptor("mappings must be an object"))?;
    for (rule_index, rule) in array(mappings, "variables")?.iter().enumerate() {
        let operation = string(rule, "operation")?;
        if !matches!(operation, "transform" | "initialize") {
            continue;
        }
        let target_pointer = string(rule, "target_declaration_pointer")?;
        let target_declaration = find_bundle_variable(target, target_pointer)
            .ok_or_else(|| invalid_descriptor("migration target variable does not resolve"))?;
        if target_declaration.value_type == "instance_reference" {
            return Err(invalid_descriptor(
                "migration CEL cannot produce an instance_reference",
            ));
        }
        let mut environment = cel::TypeEnvironment::default();
        if operation == "transform" {
            for (source_index, pointer) in rule["source_declaration_pointers"]
                .as_array()
                .ok_or_else(|| invalid_descriptor("transform sources must be an array"))?
                .iter()
                .enumerate()
            {
                let pointer = pointer
                    .as_str()
                    .ok_or_else(|| invalid_descriptor("transform source must be a string"))?;
                let declaration = find_bundle_variable(source, pointer).ok_or_else(|| {
                    invalid_descriptor("migration source variable does not resolve")
                })?;
                if declaration.value_type == "instance_reference" {
                    return Err(invalid_descriptor(
                        "migration CEL cannot consume an instance_reference",
                    ));
                }
                environment.values.insert(
                    format!("source_{source_index}"),
                    cel::declared_type(&declaration.value_type, declaration.machine_id.as_deref()),
                );
            }
        }
        let expression = string(rule, "expression")?;
        cel::check(
            expression,
            &format!("/mappings/variables/{rule_index}/expression"),
            &environment,
            &cel::declared_type(
                &target_declaration.value_type,
                target_declaration.machine_id.as_deref(),
            ),
        )
        .map_err(|failure| {
            invalid_descriptor(format!(
                "migration CEL validation failed at {}: {}",
                failure.path, failure.message
            ))
        })?;
    }
    Ok(())
}

fn find_bundle_variable(
    bundle: &Bundle,
    pointer: &str,
) -> Option<super::model::VariableDeclaration> {
    bundle
        .machines
        .values()
        .find_map(|machine| find_variable_by_pointer(machine, pointer).map(|(_, _, value)| value))
}

pub fn aggregate_shape_fingerprint(bundle: &Bundle) -> Result<String, PersistenceError> {
    let mut machines = Vec::new();
    for machine_id in &bundle.machine_order {
        let machine = &bundle.machines[machine_id];
        machines.push(json!({
            "machine_id": machine.machine_id,
            "version": machine.version,
            "root": state_shape(machine, &machine.states["root"])?,
        }));
    }
    let tree = json!({
        "format": 1,
        "namespace": bundle.namespace,
        "machines": machines,
    });
    jcs_hash(&json!([
        "determa-aggregate-shape-fingerprint-1",
        super::compile::typed_projection(&tree)
    ]))
}

fn state_shape(machine: &Machine, state: &State) -> Result<JsonValue, PersistenceError> {
    let state_type = match state.kind {
        CompiledStateKind::Simple => "simple",
        CompiledStateKind::Composite => "composite",
        CompiledStateKind::Parallel => "parallel",
        CompiledStateKind::Final => "final",
        CompiledStateKind::Choice => "choice",
    };
    let mut projection = serde_json::Map::new();
    projection.insert(
        "definition_pointer".to_string(),
        JsonValue::String(state.pointer.clone()),
    );
    projection.insert(
        "type".to_string(),
        JsonValue::String(state_type.to_string()),
    );
    if state.kind == CompiledStateKind::Composite {
        let history = match state.history {
            super::model::HistoryKind::None => "none",
            super::model::HistoryKind::Shallow => "shallow",
            super::model::HistoryKind::Deep => "deep",
        };
        projection.insert(
            "history".to_string(),
            JsonValue::String(history.to_string()),
        );
    }
    let mut variables = state
        .variables
        .iter()
        .map(|(name, declaration)| {
            let mut variable = serde_json::Map::new();
            variable.insert(
                "declaration_pointer".to_string(),
                JsonValue::String(format!(
                    "{}/variables/{}",
                    state.pointer,
                    name.replace('~', "~0").replace('/', "~1")
                )),
            );
            variable.insert(
                "type".to_string(),
                JsonValue::String(declaration.value_type.clone()),
            );
            variable.insert(
                "nullable".to_string(),
                JsonValue::Bool(
                    declaration.value_type == "instance_reference"
                        && declaration.nullable == Some(true),
                ),
            );
            variable.insert("input".to_string(), JsonValue::Bool(declaration.input));
            variable.insert(
                "external".to_string(),
                JsonValue::Bool(declaration.external),
            );
            if let Some(machine_id) = &declaration.machine_id {
                variable.insert(
                    "machine_id".to_string(),
                    JsonValue::String(machine_id.clone()),
                );
            }
            JsonValue::Object(variable)
        })
        .collect::<Vec<_>>();
    variables.sort_by(|left, right| {
        left["declaration_pointer"]
            .as_str()
            .unwrap()
            .as_bytes()
            .cmp(right["declaration_pointer"].as_str().unwrap().as_bytes())
    });
    if !variables.is_empty() {
        projection.insert("variables".to_string(), JsonValue::Array(variables));
    }
    let mut children = state
        .children
        .iter()
        .map(|path| state_shape(machine, &machine.states[path]))
        .collect::<Result<Vec<_>, _>>()?;
    children.sort_by(|left, right| {
        left["definition_pointer"]
            .as_str()
            .unwrap()
            .as_bytes()
            .cmp(right["definition_pointer"].as_str().unwrap().as_bytes())
    });
    if !children.is_empty() {
        projection.insert("states".to_string(), JsonValue::Array(children));
    }
    let mut components = Vec::new();
    for component in &state.components {
        let mut value = serde_json::Map::new();
        value.insert(
            "declaration_pointer".to_string(),
            JsonValue::String(component.pointer.clone()),
        );
        value.insert(
            "declaration_index".to_string(),
            JsonValue::Number(component.declaration_index.into()),
        );
        value.insert(
            "component_id".to_string(),
            JsonValue::String(component.component_id.clone()),
        );
        match &component.definition {
            ComponentDefinition::Machine(machine_id) => {
                value.insert(
                    "machine_id".to_string(),
                    JsonValue::String(machine_id.clone()),
                );
            }
            ComponentDefinition::Inline(inline) => {
                value.insert(
                    "inline_root".to_string(),
                    state_shape(inline, &inline.states["root"])?,
                );
            }
        }
        components.push(JsonValue::Object(value));
    }
    if !components.is_empty() {
        projection.insert("components".to_string(), JsonValue::Array(components));
    }
    let mut spawn_sites = Vec::new();
    collect_spawn_sites(machine, state, &mut spawn_sites)?;
    spawn_sites.sort_by(|left, right| {
        left["action_pointer"]
            .as_str()
            .unwrap()
            .as_bytes()
            .cmp(right["action_pointer"].as_str().unwrap().as_bytes())
    });
    if !spawn_sites.is_empty() {
        projection.insert("spawn_sites".to_string(), JsonValue::Array(spawn_sites));
    }
    Ok(JsonValue::Object(projection))
}

fn collect_spawn_sites(
    machine: &Machine,
    state: &State,
    output: &mut Vec<JsonValue>,
) -> Result<(), PersistenceError> {
    let actions = state
        .entry
        .iter()
        .chain(&state.exit)
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
        );
    for action in actions {
        if let CompiledActionKind::Spawn {
            machine_id,
            bind_to,
            ..
        } = &action.kind
        {
            output.push(json!({
                "action_pointer": format!("{}/spawn", action.pointer),
                "machine_id": machine_id,
                "holder_variable_declaration_pointer": bind_to
                    .as_ref()
                    .and_then(|name| variable_pointer_in_scope(machine, &state.path, name)),
            }));
        }
    }
    Ok(())
}

fn variable_pointer_in_scope(machine: &Machine, path: &str, name: &str) -> Option<String> {
    let mut current = Some(path);
    while let Some(path) = current {
        let state = &machine.states[path];
        if state.variables.contains_key(name) {
            return Some(format!(
                "{}/variables/{}",
                state.pointer,
                name.replace('~', "~0").replace('/', "~1")
            ));
        }
        current = state.parent.as_deref();
    }
    None
}

fn enforce_terminal_policy(
    envelope: &AggregateEnvelope,
    descriptor: &JsonValue,
) -> Result<(), PersistenceError> {
    let status = envelope
        .runtimes
        .iter()
        .find(|runtime| runtime.runtime_id == envelope.root_runtime_id)
        .map(|runtime| runtime.status)
        .ok_or_else(|| totality("root runtime is missing"))?;
    let policy = match status {
        super::runtime::RuntimeStatus::Completed => Some("completed"),
        super::runtime::RuntimeStatus::Faulted => Some("faulted"),
        super::runtime::RuntimeStatus::Running => None,
    };
    if let Some(policy) = policy {
        if descriptor["terminal_policy"][policy] != "preserve" {
            return Err(error(
                PersistenceErrorCode::TerminalMigrationRejected,
                "descriptor rejects terminal aggregate migration",
            ));
        }
    }
    Ok(())
}

fn apply_descriptor(
    envelope: &mut AggregateEnvelope,
    descriptor: &JsonValue,
    target_bundle: &Bundle,
    limits: &ResourceLimits,
) -> Result<(), PersistenceError> {
    let source_fingerprint = envelope.validated_bundle_fingerprint.clone();
    let target_fingerprint = target_bundle.fingerprint.clone();
    let mode = string(descriptor, "mode")?;
    if mode == "compatible" {
        if descriptor["mappings"].as_object().is_some_and(|mappings| {
            mappings
                .values()
                .any(|value| value.as_array().is_some_and(|v| !v.is_empty()))
        }) {
            return Err(invalid_descriptor(
                "compatible descriptor has mapping rules",
            ));
        }
        for runtime in &mut envelope.runtimes {
            runtime.current_definition.validated_bundle_fingerprint = target_fingerprint.clone();
        }
    } else {
        transform_runtimes(
            envelope,
            descriptor,
            target_bundle,
            &source_fingerprint,
            limits,
        )?;
    }
    envelope.validated_bundle_fingerprint = target_fingerprint.clone();
    let root = envelope
        .runtimes
        .iter()
        .find(|runtime| runtime.runtime_id == envelope.root_runtime_id)
        .ok_or_else(|| totality("root runtime is missing after migration"))?;
    envelope.namespace = root.current_definition.machine.namespace.clone();
    envelope.root_machine_id = root.current_definition.machine.machine_id.clone();
    envelope.root_machine_version = root.current_definition.machine.machine_version.clone();
    let mut sequence = Counter::from_decimal(&envelope.migration_sequence).map_err(totality)?;
    sequence.allocate();
    envelope.migration_sequence = sequence.to_string();
    Ok(())
}

fn transform_runtimes(
    envelope: &mut AggregateEnvelope,
    descriptor: &JsonValue,
    target_bundle: &Bundle,
    source_fingerprint: &str,
    limits: &ResourceLimits,
) -> Result<(), PersistenceError> {
    let mappings = descriptor["mappings"]
        .as_object()
        .ok_or_else(|| invalid_descriptor("mappings must be an object"))?;
    let requirements = DeclaredLimits::from_descriptor(descriptor)?;
    validate_static_expressions(descriptor, limits, &requirements)?;
    let mut tracker = ResourceTracker::default();
    for runtime in &mut envelope.runtimes {
        if runtime.current_definition.validated_bundle_fingerprint != source_fingerprint {
            continue;
        }
        let source_root = runtime
            .current_definition
            .machine
            .root_definition_pointer
            .clone();
        let target_root = map_machine_root(mappings, &source_root)?;
        let target_machine = find_machine_by_root_pointer(target_bundle, &target_root)
            .ok_or_else(|| totality("target machine pointer does not resolve"))?;
        let old_runtime = runtime.clone();
        runtime.current_definition = WireDefinitionBinding {
            validated_bundle_fingerprint: target_bundle.fingerprint.clone(),
            machine: super::wire::WireMachineIdentity {
                namespace: target_bundle.namespace.clone(),
                machine_id: target_machine.machine_id.clone(),
                machine_version: target_machine.version.to_string(),
                root_definition_pointer: target_machine.root_pointer.clone(),
            },
        };
        runtime.active_leaf_state_definition_pointers = map_active_leaves(
            &old_runtime.active_leaf_state_definition_pointers,
            array(mappings, "active_states")?,
        )?;
        runtime.active_state_activations = old_runtime
            .active_state_activations
            .iter()
            .map(|activation| {
                Ok(super::wire::WireStateActivation {
                    state_definition_pointer: map_counter_pointer(
                        array(mappings, "counters")?,
                        &activation.state_definition_pointer,
                    )?,
                    activation_sequence: activation.activation_sequence.clone(),
                })
            })
            .collect::<Result<Vec<_>, PersistenceError>>()?;
        runtime.active_state_activations.sort_by(|left, right| {
            left.state_definition_pointer
                .as_bytes()
                .cmp(right.state_definition_pointer.as_bytes())
                .then_with(|| decimal_cmp(&left.activation_sequence, &right.activation_sequence))
        });
        runtime.variables = migrate_variables(
            &old_runtime,
            &runtime.active_state_activations,
            target_machine,
            array(mappings, "variables")?,
            limits,
            &requirements,
            &mut tracker,
        )?;
        runtime.history = migrate_history(&old_runtime.history, array(mappings, "history")?)?;
        runtime.next_state_activation_sequences = migrate_counters(
            &old_runtime.next_state_activation_sequences,
            array(mappings, "counters")?,
        )?;
        runtime.next_component_activation_sequences = migrate_component_counters(
            &old_runtime.next_component_activation_sequences,
            array(mappings, "components")?,
        )?;
        migrate_relation(runtime, mappings)?;
    }
    Ok(())
}

fn map_machine_root(
    mappings: &serde_json::Map<String, JsonValue>,
    source_root: &str,
) -> Result<String, PersistenceError> {
    let machine_matches = array(mappings, "machines")?
        .iter()
        .filter(|rule| {
            rule.get("source_definition_pointer")
                .and_then(JsonValue::as_str)
                == Some(source_root)
        })
        .collect::<Vec<_>>();
    if machine_matches.len() == 1 {
        return Ok(string(machine_matches[0], "target_definition_pointer")?.to_string());
    }
    if let Some(component_pointer) = source_root.strip_suffix("/root") {
        let component_matches = array(mappings, "components")?
            .iter()
            .filter(|rule| {
                rule.get("source_component_definition_pointer")
                    .and_then(JsonValue::as_str)
                    == Some(component_pointer)
            })
            .collect::<Vec<_>>();
        if component_matches.len() == 1 {
            return Ok(format!(
                "{}/root",
                string(component_matches[0], "target_component_definition_pointer")?
            ));
        }
    }
    Err(totality("machine/root mapping is absent or ambiguous"))
}

fn migrate_relation(
    runtime: &mut super::wire::WireRuntime,
    mappings: &serde_json::Map<String, JsonValue>,
) -> Result<(), PersistenceError> {
    match &mut runtime.relation {
        WireRelation::Root => {}
        WireRelation::Component {
            component_id,
            current_component_definition_pointer,
            ..
        } => {
            let rule = unique_rule(
                array(mappings, "components")?,
                "source_component_definition_pointer",
                current_component_definition_pointer,
            )?;
            *current_component_definition_pointer =
                string(rule, "target_component_definition_pointer")?.to_string();
            *component_id = string(rule, "target_component_id")?.to_string();
        }
        WireRelation::OwnedSpawnedInstance {
            current_spawn_action_pointer,
            lifetime_holder,
            ..
        } => {
            let rule = unique_rule(
                array(mappings, "owned_runtimes")?,
                "source_spawn_action_pointer",
                current_spawn_action_pointer,
            )?;
            *current_spawn_action_pointer =
                string(rule, "target_spawn_action_pointer")?.to_string();
            if let Some(holder) = lifetime_holder {
                migrate_holder(holder, array(mappings, "lifetime_holders")?)?;
            }
        }
    }
    Ok(())
}

fn migrate_holder(
    holder: &mut WireLifetimeHolder,
    rules: &[JsonValue],
) -> Result<(), PersistenceError> {
    let rule = unique_rule(
        rules,
        "source_variable_declaration_pointer",
        &holder.variable_declaration_pointer,
    )?;
    holder.variable_declaration_pointer =
        string(rule, "target_variable_declaration_pointer")?.to_string();
    Ok(())
}

fn map_active_leaves(
    leaves: &[String],
    rules: &[JsonValue],
) -> Result<Vec<String>, PersistenceError> {
    let mut output = Vec::new();
    for leaf in leaves {
        let matches = rules
            .iter()
            .filter(|rule| {
                rule.get("source_leaf_state_definition_pointer")
                    .and_then(JsonValue::as_str)
                    == Some(leaf)
            })
            .collect::<Vec<_>>();
        if matches.len() > 1 {
            return Err(invalid_descriptor(
                "active-state source is mapped more than once",
            ));
        }
        let rule = matches
            .first()
            .copied()
            .ok_or_else(|| totality("active-state mapping is absent"))?;
        output.extend(
            rule["target_leaf_state_definition_pointers"]
                .as_array()
                .ok_or_else(|| invalid_descriptor("target leaves must be an array"))?
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .map(str::to_string)
                        .ok_or_else(|| invalid_descriptor("target leaf must be a string"))
                })
                .collect::<Result<Vec<_>, _>>()?,
        );
    }
    output.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    if output.windows(2).any(|items| items[0] == items[1]) {
        return Err(totality("active-state mapping produces duplicate leaves"));
    }
    Ok(output)
}

fn migrate_variables(
    runtime: &super::wire::WireRuntime,
    target_activations: &[super::wire::WireStateActivation],
    target_machine: &super::compile::Machine,
    rules: &[JsonValue],
    limits: &ResourceLimits,
    requirements: &DeclaredLimits,
    tracker: &mut ResourceTracker,
) -> Result<Vec<WireVariable>, PersistenceError> {
    let mut consumed = BTreeSet::new();
    let mut produced = BTreeSet::new();
    let mut output = Vec::new();
    for rule in rules {
        match string(rule, "operation")? {
            "copy" => {
                let source_pointer = string(rule, "source_declaration_pointer")?;
                for variable in runtime
                    .variables
                    .iter()
                    .filter(|variable| variable.variable_declaration_pointer == source_pointer)
                {
                    consume(&mut consumed, variable)?;
                    let target_pointer = string(rule, "target_declaration_pointer")?.to_string();
                    produce(
                        &mut produced,
                        &mut output,
                        target_pointer,
                        variable.declaring_state_activation_sequence.clone(),
                        variable.value.clone(),
                    )?;
                }
            }
            "drop" => {
                let source_pointer = string(rule, "source_declaration_pointer")?;
                for variable in runtime
                    .variables
                    .iter()
                    .filter(|variable| variable.variable_declaration_pointer == source_pointer)
                {
                    consume(&mut consumed, variable)?;
                }
            }
            "transform" => {
                let source_pointers = rule["source_declaration_pointers"]
                    .as_array()
                    .ok_or_else(|| invalid_descriptor("transform sources must be an array"))?;
                let first_pointer = source_pointers[0]
                    .as_str()
                    .ok_or_else(|| invalid_descriptor("transform source must be a string"))?;
                let occurrences = runtime
                    .variables
                    .iter()
                    .filter(|variable| variable.variable_declaration_pointer == first_pointer)
                    .collect::<Vec<_>>();
                for first in occurrences {
                    let mut environment = Environment::default();
                    for (index, pointer) in source_pointers.iter().enumerate() {
                        let pointer = pointer.as_str().ok_or_else(|| {
                            invalid_descriptor("transform source must be a string")
                        })?;
                        let candidates = runtime
                            .variables
                            .iter()
                            .filter(|variable| {
                                variable.variable_declaration_pointer == pointer
                                    && variable.declaring_state_activation_sequence
                                        == first.declaring_state_activation_sequence
                            })
                            .collect::<Vec<_>>();
                        if candidates.len() != 1 {
                            return Err(totality(
                                "transform source occurrence is absent or ambiguous",
                            ));
                        }
                        consume(&mut consumed, candidates[0])?;
                        environment.values.insert(
                            format!("source_{index}"),
                            candidates[0].value.to_value(None)?,
                        );
                    }
                    let expression = string(rule, "expression")?;
                    let maximum_steps = remaining_evaluation_steps(limits, requirements, tracker)?;
                    let (value, work) =
                        cel::evaluate_migration(expression, &environment, maximum_steps)
                            .map_err(classify_migration_evaluation)?;
                    tracker.cel_evaluation_steps += work;
                    let typed = TypedValue::from_value(&value);
                    tracker.transformed_output_bytes += typed.canonical_size()?;
                    require_work(
                        tracker.transformed_output_bytes,
                        &limits.maximum_transformed_output_bytes,
                        &requirements.maximum_transformed_output_bytes,
                    )?;
                    produce(
                        &mut produced,
                        &mut output,
                        string(rule, "target_declaration_pointer")?.to_string(),
                        first.declaring_state_activation_sequence.clone(),
                        typed,
                    )?;
                }
            }
            "initialize" => {
                let pointer = string(rule, "target_declaration_pointer")?;
                let (_, _, declaration) = find_variable_by_pointer(target_machine, pointer)
                    .ok_or_else(|| invalid_descriptor("initialize target does not resolve"))?;
                let declaring_state = pointer
                    .split("/variables/")
                    .next()
                    .ok_or_else(|| invalid_descriptor("variable pointer is malformed"))?;
                let activations = target_activations
                    .iter()
                    .filter(|activation| activation.state_definition_pointer == declaring_state)
                    .collect::<Vec<_>>();
                if activations.len() != 1 {
                    return Err(totality(
                        "initialize target declaration is not live exactly once",
                    ));
                }
                let expression = string(rule, "expression")?;
                let maximum_steps = remaining_evaluation_steps(limits, requirements, tracker)?;
                let (value, work) =
                    cel::evaluate_migration(expression, &Environment::default(), maximum_steps)
                        .map_err(classify_migration_evaluation)?;
                tracker.cel_evaluation_steps += work;
                let typed = TypedValue::from_value(&value);
                typed
                    .to_value(Some(&declaration))
                    .map_err(|_| totality("initialized value does not match target declaration"))?;
                tracker.transformed_output_bytes += typed.canonical_size()?;
                require_work(
                    tracker.transformed_output_bytes,
                    &limits.maximum_transformed_output_bytes,
                    &requirements.maximum_transformed_output_bytes,
                )?;
                produce(
                    &mut produced,
                    &mut output,
                    pointer.to_string(),
                    activations[0].activation_sequence.clone(),
                    typed,
                )?;
            }
            _ => return Err(invalid_descriptor("unknown variable operation")),
        }
    }
    if consumed.len() != runtime.variables.len() {
        return Err(totality(
            "not every source variable occurrence was consumed",
        ));
    }
    for variable in &output {
        let (_, _, declaration) =
            find_variable_by_pointer(target_machine, &variable.variable_declaration_pointer)
                .ok_or_else(|| totality("target variable pointer does not resolve"))?;
        variable
            .value
            .to_value(Some(&declaration))
            .map_err(|_| totality("target variable type is invalid"))?;
    }
    output.sort_by(|left, right| {
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
    Ok(output)
}

fn consume(
    consumed: &mut BTreeSet<(String, String)>,
    variable: &WireVariable,
) -> Result<(), PersistenceError> {
    if consumed.insert((
        variable.variable_declaration_pointer.clone(),
        variable.declaring_state_activation_sequence.clone(),
    )) {
        Ok(())
    } else {
        Err(invalid_descriptor(
            "variable occurrence is consumed more than once",
        ))
    }
}

fn produce(
    produced: &mut BTreeSet<(String, String)>,
    output: &mut Vec<WireVariable>,
    pointer: String,
    activation: String,
    value: TypedValue,
) -> Result<(), PersistenceError> {
    if !produced.insert((pointer.clone(), activation.clone())) {
        return Err(invalid_descriptor(
            "variable occurrence is produced more than once",
        ));
    }
    output.push(WireVariable {
        variable_declaration_pointer: pointer,
        declaring_state_activation_sequence: activation,
        value,
    });
    Ok(())
}

fn migrate_history(
    source: &[WireHistory],
    rules: &[JsonValue],
) -> Result<Vec<WireHistory>, PersistenceError> {
    let mut output = Vec::new();
    let mut consumed = BTreeSet::new();
    for entry in source {
        let rule = unique_rule(
            rules,
            "source_history_declaration_pointer",
            &entry.history_declaration_pointer,
        )?;
        consumed.insert(entry.history_declaration_pointer.clone());
        match string(rule, "operation")? {
            "drop" => {}
            "map" => {
                let recorded = entry
                    .recorded_state_definition_pointers
                    .as_ref()
                    .map(|pointers| {
                        pointers
                            .iter()
                            .map(|pointer| {
                                unique_pointer_mapping(
                                    rule["recorded_state_mappings"].as_array().ok_or_else(
                                        || {
                                            invalid_descriptor(
                                                "recorded state mappings must be an array",
                                            )
                                        },
                                    )?,
                                    "source_definition_pointer",
                                    "target_definition_pointer",
                                    pointer,
                                )
                            })
                            .collect()
                    })
                    .transpose()?;
                output.push(WireHistory {
                    history_declaration_pointer: string(
                        rule,
                        "target_history_declaration_pointer",
                    )?
                    .to_string(),
                    recorded_state_definition_pointers: recorded,
                });
            }
            _ => return Err(invalid_descriptor("unknown history operation")),
        }
    }
    for rule in rules {
        if string(rule, "operation")? == "initialize_null" {
            output.push(WireHistory {
                history_declaration_pointer: string(rule, "target_history_declaration_pointer")?
                    .to_string(),
                recorded_state_definition_pointers: None,
            });
        }
    }
    output.sort_by(|left, right| {
        left.history_declaration_pointer
            .as_bytes()
            .cmp(right.history_declaration_pointer.as_bytes())
    });
    Ok(output)
}

fn migrate_counters(
    source: &[WireNextCounter],
    rules: &[JsonValue],
) -> Result<Vec<WireNextCounter>, PersistenceError> {
    let mut output = Vec::new();
    for counter in source {
        let matches = rules
            .iter()
            .filter(|rule| {
                rule.get("source_definition_pointer")
                    .and_then(JsonValue::as_str)
                    == Some(&counter.definition_pointer)
            })
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(totality("counter mapping is absent or ambiguous"));
        }
        match string(matches[0], "operation")? {
            "map" => output.push(WireNextCounter {
                definition_pointer: string(matches[0], "target_definition_pointer")?.to_string(),
                next_sequence: counter.next_sequence.clone(),
            }),
            "merge_max" => {
                return Err(invalid_descriptor(
                    "merge_max must be evaluated as a target-domain rule",
                ));
            }
            _ => return Err(invalid_descriptor("counter operation is invalid")),
        }
    }
    for rule in rules {
        if string(rule, "operation")? == "initialize_zero" {
            output.push(WireNextCounter {
                definition_pointer: string(rule, "target_definition_pointer")?.to_string(),
                next_sequence: "0".to_string(),
            });
        }
    }
    output.sort_by(|left, right| {
        left.definition_pointer
            .as_bytes()
            .cmp(right.definition_pointer.as_bytes())
    });
    if output
        .windows(2)
        .any(|items| items[0].definition_pointer == items[1].definition_pointer)
    {
        return Err(totality("counter target is produced more than once"));
    }
    Ok(output)
}

fn migrate_component_counters(
    source: &[WireNextCounter],
    rules: &[JsonValue],
) -> Result<Vec<WireNextCounter>, PersistenceError> {
    let mut output = source
        .iter()
        .map(|counter| {
            Ok(WireNextCounter {
                definition_pointer: unique_pointer_mapping(
                    rules,
                    "source_component_definition_pointer",
                    "target_component_definition_pointer",
                    &counter.definition_pointer,
                )?,
                next_sequence: counter.next_sequence.clone(),
            })
        })
        .collect::<Result<Vec<_>, PersistenceError>>()?;
    output.sort_by(|left, right| {
        left.definition_pointer
            .as_bytes()
            .cmp(right.definition_pointer.as_bytes())
    });
    Ok(output)
}

fn map_counter_pointer(rules: &[JsonValue], pointer: &str) -> Result<String, PersistenceError> {
    let candidates = rules
        .iter()
        .filter(|rule| {
            rule.get("source_definition_pointer")
                .and_then(JsonValue::as_str)
                == Some(pointer)
        })
        .collect::<Vec<_>>();
    if candidates.len() != 1 || string(candidates[0], "operation")? != "map" {
        return Err(totality(
            "active state counter mapping is absent or ambiguous",
        ));
    }
    Ok(string(candidates[0], "target_definition_pointer")?.to_string())
}

fn enforce_descriptor_rules(
    descriptor: &JsonValue,
    limits: &ResourceLimits,
) -> Result<(), PersistenceError> {
    let count = descriptor["mappings"]
        .as_object()
        .map(|mappings| {
            mappings
                .values()
                .map(|value| value.as_array().map_or(0, Vec::len))
                .sum()
        })
        .unwrap_or(usize::MAX);
    require_within(count, &limits.maximum_descriptor_rules)
}

fn enforce_definition_limits(
    bundle: &Bundle,
    limits: &ResourceLimits,
) -> Result<(), PersistenceError> {
    let typed_normalized = super::compile::typed_projection(&bundle.normalized);
    let bytes =
        canonical_bytes(&typed_normalized).map_err(|failure| totality(failure.to_string()))?;
    require_within(bytes.len(), &limits.maximum_definition_bytes)?;
    let statistics = super::strict_json::statistics(&bundle.normalized);
    require_within(statistics.depth, &limits.maximum_json_nesting_depth)?;
    require_within(statistics.maximum_map_members, &limits.maximum_map_members)?;
    require_within(
        statistics.maximum_list_members,
        &limits.maximum_list_members,
    )?;
    require_within(
        statistics.maximum_string_bytes,
        &limits.maximum_string_utf8_bytes,
    )
}

fn enforce_aggregate_limits(
    envelope: &AggregateEnvelope,
    limits: &ResourceLimits,
) -> Result<(), PersistenceError> {
    require_within(envelope.runtimes.len(), &limits.maximum_runtimes)?;
    for runtime in &envelope.runtimes {
        require_within(
            runtime.active_state_activations.len(),
            &limits.maximum_active_states_per_runtime,
        )?;
        require_within(
            runtime.variables.len(),
            &limits.maximum_variables_per_runtime,
        )?;
    }
    let value = serde_json::to_value(envelope).map_err(|failure| totality(failure.to_string()))?;
    let statistics = super::strict_json::statistics(&value);
    require_within(statistics.depth, &limits.maximum_json_nesting_depth)?;
    require_within(statistics.maximum_map_members, &limits.maximum_map_members)?;
    require_within(
        statistics.maximum_list_members,
        &limits.maximum_list_members,
    )?;
    require_within(
        statistics.maximum_string_bytes,
        &limits.maximum_string_utf8_bytes,
    )
}

#[derive(Default)]
struct ResourceTracker {
    transformed_output_bytes: usize,
    cel_evaluation_steps: usize,
}

struct DeclaredLimits {
    maximum_transformed_output_bytes: Counter,
    maximum_cel_expression_length: Counter,
    maximum_cel_ast_nodes: Counter,
    maximum_cel_evaluation_steps: Counter,
}

impl DeclaredLimits {
    fn from_descriptor(descriptor: &JsonValue) -> Result<Self, PersistenceError> {
        let requirements = descriptor["resource_requirements"]
            .as_object()
            .ok_or_else(|| invalid_descriptor("resource requirements must be an object"))?;
        let counter = |name: &str| {
            Counter::from_decimal(
                requirements
                    .get(name)
                    .and_then(JsonValue::as_str)
                    .ok_or_else(|| {
                        invalid_descriptor(format!("resource requirement {name:?} is absent"))
                    })?,
            )
            .map_err(invalid_descriptor)
        };
        Ok(Self {
            maximum_transformed_output_bytes: counter("maximum_transformed_output_bytes")?,
            maximum_cel_expression_length: counter("maximum_cel_expression_length")?,
            maximum_cel_ast_nodes: counter("maximum_cel_ast_nodes")?,
            maximum_cel_evaluation_steps: counter("maximum_cel_evaluation_steps")?,
        })
    }
}

fn validate_static_expressions(
    descriptor: &JsonValue,
    limits: &ResourceLimits,
    requirements: &DeclaredLimits,
) -> Result<(), PersistenceError> {
    let mut expressions = BTreeSet::new();
    for rule in array(
        descriptor["mappings"]
            .as_object()
            .ok_or_else(|| invalid_descriptor("mappings must be an object"))?,
        "variables",
    )? {
        if matches!(
            rule.get("operation").and_then(JsonValue::as_str),
            Some("transform" | "initialize")
        ) {
            expressions.insert(string(rule, "expression")?);
        }
    }
    let expression_bytes = expressions.iter().map(|expression| expression.len()).sum();
    require_work(
        expression_bytes,
        &limits.maximum_cel_expression_length,
        &requirements.maximum_cel_expression_length,
    )?;
    let ast_nodes = expressions
        .iter()
        .map(|expression| {
            cel::migration_expression_info(expression).map_err(|failure| {
                invalid_descriptor(format!("migration CEL expression is invalid: {failure}"))
            })
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .sum();
    require_work(
        ast_nodes,
        &limits.maximum_cel_ast_nodes,
        &requirements.maximum_cel_ast_nodes,
    )
}

fn remaining_evaluation_steps(
    limits: &ResourceLimits,
    requirements: &DeclaredLimits,
    tracker: &ResourceTracker,
) -> Result<usize, PersistenceError> {
    let maximum = counter_as_usize(&limits.maximum_cel_evaluation_steps)
        .min(counter_as_usize(&requirements.maximum_cel_evaluation_steps));
    maximum
        .checked_sub(tracker.cel_evaluation_steps)
        .ok_or_else(resource_limit)
}

fn counter_as_usize(value: &Counter) -> usize {
    value.to_string().parse().unwrap_or(usize::MAX)
}

fn classify_migration_evaluation(failure: cel::EvaluationError) -> PersistenceError {
    if failure
        .to_string()
        .contains("migration CEL evaluation step limit exceeded")
    {
        resource_limit()
    } else {
        error(
            PersistenceErrorCode::MigrationTransformFault,
            failure.to_string(),
        )
    }
}

fn resource_limit() -> PersistenceError {
    error(
        PersistenceErrorCode::MigrationResourceLimitExceeded,
        "configured migration resource limit exceeded",
    )
}

fn require_work(
    value: usize,
    configured: &Counter,
    declared: &Counter,
) -> Result<(), PersistenceError> {
    require_within(value, configured)?;
    require_within(value, declared)
}

fn require_within(value: usize, maximum: &Counter) -> Result<(), PersistenceError> {
    let value = Counter::from(value);
    if value <= *maximum {
        Ok(())
    } else {
        Err(error(
            PersistenceErrorCode::MigrationResourceLimitExceeded,
            "configured migration resource limit exceeded",
        ))
    }
}

fn unique_pointer_mapping(
    rules: &[JsonValue],
    source_name: &str,
    target_name: &str,
    pointer: &str,
) -> Result<String, PersistenceError> {
    let rule = unique_rule(rules, source_name, pointer)?;
    Ok(string(rule, target_name)?.to_string())
}

fn unique_rule<'a>(
    rules: &'a [JsonValue],
    source_name: &str,
    pointer: &str,
) -> Result<&'a JsonValue, PersistenceError> {
    let matches = rules
        .iter()
        .filter(|rule| rule.get(source_name).and_then(JsonValue::as_str) == Some(pointer))
        .collect::<Vec<_>>();
    if matches.len() == 1 {
        Ok(matches[0])
    } else {
        Err(totality("mapping rule is absent or ambiguous"))
    }
}

fn array<'a>(
    mappings: &'a serde_json::Map<String, JsonValue>,
    name: &str,
) -> Result<&'a [JsonValue], PersistenceError> {
    mappings
        .get(name)
        .and_then(JsonValue::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| invalid_descriptor(format!("mapping array {name:?} is absent")))
}

fn string<'a>(value: &'a JsonValue, name: &str) -> Result<&'a str, PersistenceError> {
    value
        .get(name)
        .and_then(JsonValue::as_str)
        .ok_or_else(|| invalid_descriptor(format!("member {name:?} is not a string")))
}

fn decimal_cmp(left: &str, right: &str) -> std::cmp::Ordering {
    left.len()
        .cmp(&right.len())
        .then_with(|| left.as_bytes().cmp(right.as_bytes()))
}

fn error(code: PersistenceErrorCode, message: impl Into<String>) -> PersistenceError {
    PersistenceError::new(code, message)
}

fn invalid_descriptor(message: impl Into<String>) -> PersistenceError {
    error(PersistenceErrorCode::InvalidMigrationDescriptor, message)
}

fn totality(message: impl Into<String>) -> PersistenceError {
    error(PersistenceErrorCode::MigrationTotalityFailure, message)
}

fn route_mismatch(message: impl Into<String>) -> PersistenceError {
    error(PersistenceErrorCode::MigrationRouteMismatch, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format1::{
        create, encode_aggregate, load_bundle, Bindings, InMemoryDefinitionResolver,
    };

    #[test]
    fn applies_normative_compatible_migration() {
        let directory = "conformance-suite/conformance/core/99-compatible-definition-upgrade";
        let source_bundle =
            load_bundle(&std::fs::read_to_string(format!("{directory}/machine.yaml")).unwrap())
                .unwrap();
        let target_bundle =
            load_bundle(&std::fs::read_to_string(format!("{directory}/target.yaml")).unwrap())
                .unwrap();
        let descriptor = std::fs::read(format!("{directory}/migration-descriptor.json")).unwrap();
        let descriptor_value: JsonValue = serde_json::from_slice(&descriptor).unwrap();
        let digest = descriptor_value["migration_descriptor_digest"]
            .as_str()
            .unwrap()
            .to_string();
        let mut resolver = InMemoryDefinitionResolver::default();
        assert!(resolver.insert(source_bundle, true));
        assert!(resolver.insert(target_bundle.clone(), true));
        assert!(resolver.insert_descriptor(digest.clone(), descriptor, true));
        let result = migrate_aggregate(
            &std::fs::read(format!("{directory}/source-aggregate-state.json")).unwrap(),
            &MigrationRequest {
                migration_route: vec![digest],
                target_validated_bundle_fingerprint: target_bundle.fingerprint,
                maintenance_mode: false,
            },
            &resolver,
            &ResourceLimits::default(),
        )
        .unwrap();
        assert_eq!(
            result.aggregate_bytes,
            std::fs::read(format!(
                "{directory}/expected-aggregate-state.canonical.json"
            ))
            .unwrap()
        );
        assert_eq!(
            serde_json::to_value(result.audit_records).unwrap(),
            serde_json::from_slice::<JsonValue>(
                &std::fs::read(format!("{directory}/expected-migration-audit.json")).unwrap()
            )
            .unwrap()
        );
    }

    #[test]
    fn applies_normative_variable_transform() {
        assert_single_hop_case(
            "102-variable-migration",
            "source-aggregate-state.json",
            "expected-aggregate-state.canonical.json",
            "expected-migration-audit.json",
        );
    }

    #[test]
    fn applies_normative_structural_transforms() {
        for case in [
            "100-explicit-active-state-remap",
            "104-component-migration",
            "105-owned-runtime-migration",
            "106-counter-and-identity-preservation",
        ] {
            assert_single_hop_case(
                case,
                "source-aggregate-state.json",
                "expected-aggregate-state.canonical.json",
                "expected-migration-audit.json",
            );
        }
    }

    #[test]
    fn applies_occurrence_local_transforms() {
        assert_single_hop_case(
            "114-occurrence-local-transform-binding",
            "repeated-runtime-source.json",
            "repeated-runtime-expected.canonical.json",
            "repeated-runtime-audit.json",
        );
        assert_single_hop_case(
            "114-occurrence-local-transform-binding",
            "repeated-activation-source.json",
            "repeated-activation-expected.canonical.json",
            "repeated-activation-audit.json",
        );
    }

    #[test]
    fn applies_normative_history_transforms() {
        assert_single_hop_case(
            "103-history-migration",
            "source-aggregate-state.json",
            "expected-aggregate-state.canonical.json",
            "expected-migration-audit.json",
        );
        assert_single_hop_case(
            "103-history-migration",
            "recorded-source-aggregate-state.json",
            "recorded-expected-aggregate-state.canonical.json",
            "recorded-expected-migration-audit.json",
        );
        assert_single_hop_case_with_descriptor(
            "103-history-migration",
            "shallow-source-aggregate-state.json",
            "shallow-expected-aggregate-state.canonical.json",
            "shallow-expected-migration-audit.json",
            "shallow-migration-descriptor.json",
        );
    }

    #[test]
    fn definition_byte_limits_use_exact_typed_large_integer_projection() {
        let source_bundle = large_version_bundle("9007199254740992", "");
        let target_bundle = large_version_bundle("9007199254740992", "meta:\n  release: next\n");
        let adjacent_bundle = large_version_bundle("9007199254740993", "");
        let source_typed = super::super::compile::typed_projection(&source_bundle.normalized);
        let target_typed = super::super::compile::typed_projection(&target_bundle.normalized);
        let adjacent_typed = super::super::compile::typed_projection(&adjacent_bundle.normalized);
        let source_bytes = canonical_bytes(&source_typed).unwrap();
        let target_bytes = canonical_bytes(&target_typed).unwrap();
        let adjacent_bytes = canonical_bytes(&adjacent_typed).unwrap();
        assert_ne!(source_bundle.fingerprint, adjacent_bundle.fingerprint);
        assert_ne!(source_bytes, adjacent_bytes);

        let shape = aggregate_shape_fingerprint(&source_bundle).unwrap();
        assert_eq!(shape, aggregate_shape_fingerprint(&target_bundle).unwrap());
        let mut descriptor: JsonValue = serde_json::from_slice(
            &std::fs::read(
                "conformance-suite/conformance/core/99-compatible-definition-upgrade/migration-descriptor.json",
            )
            .unwrap(),
        )
        .unwrap();
        descriptor["source_validated_bundle_fingerprint"] =
            JsonValue::String(source_bundle.fingerprint.clone());
        descriptor["target_validated_bundle_fingerprint"] =
            JsonValue::String(target_bundle.fingerprint.clone());
        descriptor["source_aggregate_shape_fingerprint"] = JsonValue::String(shape.clone());
        descriptor["target_aggregate_shape_fingerprint"] = JsonValue::String(shape);
        let mut digest_input = descriptor.clone();
        digest_input
            .as_object_mut()
            .unwrap()
            .remove("migration_descriptor_digest");
        let digest = jcs_hash(&json!(["determa-migration-descriptor-1", digest_input])).unwrap();
        descriptor["migration_descriptor_digest"] = JsonValue::String(digest.clone());
        let descriptor_bytes = canonical_bytes(&descriptor).unwrap();

        let created = create(
            &source_bundle,
            "job",
            "large-version-root",
            "large-version-create",
            &Bindings::default(),
        );
        let source_state = created.state.unwrap();
        let (_, aggregate_bytes) = encode_aggregate(&source_bundle, &source_state).unwrap();
        let mut resolver = InMemoryDefinitionResolver::default();
        assert!(resolver.insert(source_bundle, true));
        assert!(resolver.insert(target_bundle.clone(), true));
        assert!(resolver.insert_descriptor(digest.clone(), descriptor_bytes, true));
        let request = MigrationRequest {
            migration_route: vec![digest],
            target_validated_bundle_fingerprint: target_bundle.fingerprint,
            maintenance_mode: false,
        };
        let exact_limit = source_bytes.len().max(target_bytes.len());
        let insufficient = ResourceLimits {
            maximum_definition_bytes: Counter::from(exact_limit - 1),
            ..ResourceLimits::default()
        };
        assert_eq!(
            migrate_aggregate(&aggregate_bytes, &request, &resolver, &insufficient)
                .unwrap_err()
                .code,
            PersistenceErrorCode::MigrationResourceLimitExceeded
        );
        let exact = ResourceLimits {
            maximum_definition_bytes: Counter::from(exact_limit),
            ..ResourceLimits::default()
        };
        migrate_aggregate(&aggregate_bytes, &request, &resolver, &exact).unwrap();
    }

    fn large_version_bundle(version: &str, extra: &str) -> Bundle {
        load_bundle(&format!(
            "format: 1\nnamespace: example.large_version\n{extra}machines:\n  - machine_id: job\n    version: {version}\n    root: {{}}\n"
        ))
        .unwrap()
    }

    fn assert_single_hop_case(
        case: &str,
        source_file: &str,
        expected_file: &str,
        audit_file: &str,
    ) {
        assert_single_hop_case_with_descriptor(
            case,
            source_file,
            expected_file,
            audit_file,
            "migration-descriptor.json",
        );
    }

    fn assert_single_hop_case_with_descriptor(
        case: &str,
        source_file: &str,
        expected_file: &str,
        audit_file: &str,
        descriptor_file: &str,
    ) {
        let directory = format!("conformance-suite/conformance/core/{case}");
        let (machine_file, target_file) = if descriptor_file.starts_with("shallow-") {
            ("shallow-machine.yaml", "shallow-target.yaml")
        } else {
            ("machine.yaml", "target.yaml")
        };
        let source_bundle =
            load_bundle(&std::fs::read_to_string(format!("{directory}/{machine_file}")).unwrap())
                .unwrap();
        let target_bundle =
            load_bundle(&std::fs::read_to_string(format!("{directory}/{target_file}")).unwrap())
                .unwrap();
        let descriptor = std::fs::read(format!("{directory}/{descriptor_file}")).unwrap();
        let descriptor_value: JsonValue = serde_json::from_slice(&descriptor).unwrap();
        let digest = descriptor_value["migration_descriptor_digest"]
            .as_str()
            .unwrap()
            .to_string();
        let mut resolver = InMemoryDefinitionResolver::default();
        assert!(resolver.insert(source_bundle, true));
        assert!(resolver.insert(target_bundle.clone(), true));
        assert!(resolver.insert_descriptor(digest.clone(), descriptor, true));
        let result = migrate_aggregate(
            &std::fs::read(format!("{directory}/{source_file}")).unwrap(),
            &MigrationRequest {
                migration_route: vec![digest],
                target_validated_bundle_fingerprint: target_bundle.fingerprint,
                maintenance_mode: false,
            },
            &resolver,
            &ResourceLimits::default(),
        )
        .unwrap();
        assert_eq!(
            result.aggregate_bytes,
            std::fs::read(format!("{directory}/{expected_file}")).unwrap()
        );
        assert_eq!(
            serde_json::to_value(result.audit_records).unwrap(),
            serde_json::from_slice::<JsonValue>(
                &std::fs::read(format!("{directory}/{audit_file}")).unwrap()
            )
            .unwrap()
        );
    }
}
