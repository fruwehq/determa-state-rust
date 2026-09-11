use super::compile::Bundle;
use super::counter::Counter;
use super::migration::MigrationRequest;
use super::model::{Bindings, Delivery, Envelope, Target};
use super::persistence::{
    DefinitionResolver, InMemoryDefinitionResolver, MigrationArtifactResolver,
};
use super::runtime::{
    create, deferred_event_capacity, dispatch, fault_deferred_capacity, runtime_by_id,
    structural_recall_eligible, validate_delivery_for_admission,
    validate_queued_event_for_migration, AggregateState, DispatchRejectionCode, Disposition,
    Emission, ResultStatus, RuntimeState, RuntimeStatus,
};
use super::strict_json;
use super::wire::{self, AggregateEnvelope, PersistenceErrorCode, TypedValue};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value as JsonValue};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version2Error {
    pub code: String,
    pub message: String,
}

impl Version2Error {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

impl std::fmt::Display for Version2Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for Version2Error {}

#[derive(Debug, Clone, PartialEq)]
pub struct QueueBearingAggregate {
    pub(crate) value: JsonValue,
    pub(crate) state: AggregateState,
}

impl QueueBearingAggregate {
    pub fn value(&self) -> &JsonValue {
        &self.value
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Version2Error> {
        canonical_bytes(&self.value)
    }

    pub fn abstract_state(&self) -> &AggregateState {
        &self.state
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueueEnvelope {
    pub event: String,
    pub event_id: String,
    pub cause_id: String,
    pub source: JsonValue,
    pub target: JsonValue,
    pub payload: TypedValue,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionDelivery {
    pub delivery_mode: String,
    pub envelope: QueueEnvelope,
    pub envelope_digest: String,
}

const ADMISSION_DELIVERY_SCHEMA: &str = r#"
{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "type":"object",
  "required":["delivery_mode","envelope","envelope_digest"],
  "additionalProperties":false,
  "properties":{
    "delivery_mode":{"type":"string"},
    "envelope":{"$ref":"https://determa.dev/state/schema/aggregate-state-v2.schema.json#/$defs/envelope"},
    "envelope_digest":{"$ref":"https://determa.dev/state/schema/aggregate-state-v2.schema.json#/$defs/sha256"}
  }
}
"#;

pub(crate) fn validate_admission_delivery_schema(
    delivery: &JsonValue,
) -> Result<(), Version2Error> {
    validate_v2_schema(
        delivery,
        ADMISSION_DELIVERY_SCHEMA,
        &[
            (
                "https://determa.dev/state/schema/aggregate-state-v2.schema.json",
                include_str!("../../schema/aggregate-state-v2.schema.json"),
            ),
            (
                "https://determa.dev/state/schema/aggregate-state.schema.json",
                include_str!("../../schema/aggregate-state.schema.json"),
            ),
        ],
        "invalid_delivery_source",
    )
}

pub fn restore_aggregate_v2(
    source: &[u8],
    resolver: &(impl DefinitionResolver + ?Sized),
) -> Result<QueueBearingAggregate, Version2Error> {
    let value = strict_json::parse(source)
        .map_err(|error| Version2Error::new("invalid_aggregate_state", error.to_string()))?;
    restore_aggregate_v2_value(value, resolver)
}

pub fn create_v2(
    bundle: &Bundle,
    machine_id: &str,
    root_instance_id: &str,
    creation_id: &str,
    bindings: &Bindings,
) -> Result<QueueBearingAggregate, Version2Error> {
    create_v2_with_evidence(bundle, machine_id, root_instance_id, creation_id, bindings)
        .map(|result| result.aggregate)
}

pub(crate) struct CreateV2Evidence {
    pub aggregate: QueueBearingAggregate,
    pub status: String,
    pub emissions: Vec<JsonValue>,
    pub lifecycle_dispositions: Vec<JsonValue>,
    pub fault: Option<JsonValue>,
}

pub(crate) fn create_v2_with_evidence(
    bundle: &Bundle,
    machine_id: &str,
    root_instance_id: &str,
    creation_id: &str,
    bindings: &Bindings,
) -> Result<CreateV2Evidence, Version2Error> {
    let result = create(bundle, machine_id, root_instance_id, creation_id, bindings);
    if result.status == ResultStatus::Rejected {
        return Err(Version2Error::new(
            result
                .rejection
                .as_ref()
                .map_or("invalid_creation_request", |rejection| {
                    rejection.code.as_str()
                }),
            "queue-bearing aggregate creation was rejected",
        ));
    }
    let state = result.state.ok_or_else(|| {
        Version2Error::new("invalid_aggregate_state", "creation returned no state")
    })?;
    let (_, bytes) = super::wire::encode_aggregate(bundle, &state).map_err(map_persistence)?;
    let mut value: JsonValue = serde_json::from_slice(&bytes)
        .map_err(|error| Version2Error::new("invalid_aggregate_state", error.to_string()))?;
    upgrade_value(&mut value)?;
    let status = match result.status {
        ResultStatus::Running => "running",
        ResultStatus::Completed => "completed",
        ResultStatus::Faulted => "faulted",
        ResultStatus::Rejected => unreachable!("rejected creation returned before state"),
    }
    .to_string();
    let fault = result
        .fault
        .as_ref()
        .map(serde_json::to_value)
        .transpose()
        .map_err(|error| invalid_aggregate(error.to_string()))?;
    let mut aggregate = QueueBearingAggregate { value, state };
    let (emissions, lifecycle_dispositions) =
        append_internal_emissions(&mut aggregate, &result.emissions)?;
    aggregate.value = seal_aggregate(aggregate.value)?;
    Ok(CreateV2Evidence {
        aggregate,
        status,
        emissions,
        lifecycle_dispositions,
        fault,
    })
}

pub fn upgrade_aggregate_v1_to_v2(
    source: &[u8],
    resolver: &(impl DefinitionResolver + ?Sized),
) -> Result<QueueBearingAggregate, Version2Error> {
    let state = super::wire::restore_aggregate(source, resolver).map_err(map_persistence)?;
    let mut value = strict_json::parse(source)
        .map_err(|error| Version2Error::new("invalid_aggregate_state", error.to_string()))?;
    upgrade_value(&mut value)?;
    restore_aggregate_v2_value(value, resolver).map(|mut aggregate| {
        aggregate.state = state;
        aggregate
    })
}

pub fn downgrade_aggregate_v2_to_v1(
    aggregate: &QueueBearingAggregate,
) -> Result<Vec<u8>, Version2Error> {
    let object = aggregate_object(&aggregate.value)?;
    if object
        .get("next_acceptance_sequence")
        .and_then(JsonValue::as_str)
        != Some("0")
        || object
            .get("next_queue_sequence")
            .and_then(JsonValue::as_str)
            != Some("0")
        || runtimes(&aggregate.value)?.iter().any(|runtime| {
            ["ready_mailbox", "deferred_mailbox"].iter().any(|field| {
                runtime
                    .get(*field)
                    .and_then(JsonValue::as_array)
                    .is_none_or(|entries| !entries.is_empty())
            })
        })
    {
        return Err(Version2Error::new(
            "migration_totality_failure",
            "a queue-bearing aggregate can be downgraded only before mailbox allocation",
        ));
    }
    canonical_bytes(&project_v1(&aggregate.value)?)
}

pub fn migrate_aggregate_v2(
    aggregate: &QueueBearingAggregate,
    source_bundle: &Bundle,
    target_bundle: &Bundle,
    descriptor_source: &[u8],
    maintenance_mode: bool,
    limits: &super::migration::ResourceLimits,
) -> Result<JsonValue, Version2Error> {
    let result = migrate_aggregate_v2_with_evidence(
        aggregate,
        source_bundle,
        target_bundle,
        descriptor_source,
        maintenance_mode,
        limits,
    )?;
    Ok(public_migration_result(result))
}

pub fn migrate_aggregate_v2_route(
    aggregate: &QueueBearingAggregate,
    request: &MigrationRequest,
    resolver: &impl MigrationArtifactResolver,
    limits: &super::migration::ResourceLimits,
) -> Result<JsonValue, Version2Error> {
    migrate_aggregate_v2_route_with_evidence(aggregate, request, resolver, limits)
        .map(public_migration_result)
}

pub(crate) fn migrate_aggregate_v2_route_with_evidence(
    aggregate: &QueueBearingAggregate,
    request: &MigrationRequest,
    resolver: &impl MigrationArtifactResolver,
    limits: &super::migration::ResourceLimits,
) -> Result<JsonValue, Version2Error> {
    if request.migration_route.is_empty() {
        if request.target_validated_bundle_fingerprint
            != aggregate.value["validated_bundle_fingerprint"]
        {
            return Err(Version2Error::new(
                "migration_totality_failure",
                "empty migration route requires the current bundle fingerprint",
            ));
        }
        return Ok(json!({
            "result": "success",
            "aggregate_state": aggregate.value,
            "dispositions": [],
            "audit_records": []
        }));
    }

    let mut current = aggregate.clone();
    let mut dispositions = Vec::new();
    let mut audit_records = Vec::new();
    for digest in &request.migration_route {
        let descriptor = resolver
            .resolve_migration_descriptor(digest)
            .ok_or_else(|| {
                Version2Error::new(
                    "migration_descriptor_not_found",
                    "migration descriptor is unavailable",
                )
            })?;
        if !descriptor.trusted {
            return Err(Version2Error::new(
                "migration_descriptor_not_trusted",
                "migration descriptor is not trusted",
            ));
        }
        let decoded = decode_descriptor_v2(&descriptor.bytes)?;
        if decoded["migration_descriptor_digest"].as_str() != Some(digest) {
            return Err(Version2Error::new(
                "invalid_migration_descriptor",
                "resolved migration descriptor does not match its route digest",
            ));
        }
        let source_fingerprint = current.value["validated_bundle_fingerprint"]
            .as_str()
            .ok_or_else(|| invalid_aggregate("current bundle fingerprint is absent"))?;
        let source = resolver
            .resolve_definition(source_fingerprint)
            .ok_or_else(|| {
                Version2Error::new("definition_not_found", "source definition is unavailable")
            })?;
        let target_fingerprint = decoded["base_descriptor"]["target_validated_bundle_fingerprint"]
            .as_str()
            .ok_or_else(|| {
                Version2Error::new(
                    "invalid_migration_descriptor",
                    "target bundle fingerprint is absent",
                )
            })?;
        let target = resolver
            .resolve_definition(target_fingerprint)
            .ok_or_else(|| {
                Version2Error::new("definition_not_found", "target definition is unavailable")
            })?;
        if !source.trusted
            || source.bundle.fingerprint != source_fingerprint
            || !target.trusted
            || target.bundle.fingerprint != target_fingerprint
        {
            return Err(Version2Error::new(
                "definition_not_trusted",
                "migration definition is not trusted or content-addressed correctly",
            ));
        }
        let result = migrate_aggregate_v2_with_evidence_resolved(
            &current,
            &source.bundle,
            &target.bundle,
            &descriptor.bytes,
            request.maintenance_mode,
            limits,
            Some(resolver),
        )?;
        dispositions.extend(result["dispositions"].as_array().unwrap().iter().cloned());
        audit_records.extend(result["audit_records"].as_array().unwrap().iter().cloned());
        current = restore_aggregate_v2_value(result["aggregate_state"].clone(), resolver)?;
    }
    if current.value["validated_bundle_fingerprint"].as_str()
        != Some(request.target_validated_bundle_fingerprint.as_str())
    {
        return Err(Version2Error::new(
            "migration_totality_failure",
            "migration route does not reach the requested target bundle",
        ));
    }
    Ok(json!({
        "result": "success",
        "aggregate_state": current.value,
        "dispositions": dispositions,
        "audit_records": audit_records
    }))
}

fn public_migration_result(mut result: JsonValue) -> JsonValue {
    result["dispositions"] = json!(result["dispositions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|disposition| json!({
            "disposition": disposition["disposition"],
            "reason": disposition["reason"],
            "migration_descriptor_digest": disposition["migration_descriptor_digest"]
        }))
        .collect::<Vec<_>>());
    result
}

pub(crate) fn migrate_aggregate_v2_with_evidence(
    aggregate: &QueueBearingAggregate,
    source_bundle: &Bundle,
    target_bundle: &Bundle,
    descriptor_source: &[u8],
    maintenance_mode: bool,
    limits: &super::migration::ResourceLimits,
) -> Result<JsonValue, Version2Error> {
    migrate_aggregate_v2_with_evidence_resolved(
        aggregate,
        source_bundle,
        target_bundle,
        descriptor_source,
        maintenance_mode,
        limits,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn migrate_aggregate_v2_with_evidence_resolved(
    aggregate: &QueueBearingAggregate,
    source_bundle: &Bundle,
    target_bundle: &Bundle,
    descriptor_source: &[u8],
    maintenance_mode: bool,
    limits: &super::migration::ResourceLimits,
    artifact_resolver: Option<&dyn MigrationArtifactResolver>,
) -> Result<JsonValue, Version2Error> {
    if aggregate.value["validated_bundle_fingerprint"].as_str()
        != Some(source_bundle.fingerprint.as_str())
    {
        return Err(Version2Error::new(
            "definition_fingerprint_mismatch",
            "source bundle does not match queue-bearing aggregate",
        ));
    }
    let descriptor = decode_descriptor_v2(descriptor_source)?;
    let base = descriptor["base_descriptor"].clone();
    let base_digest = base["migration_descriptor_digest"]
        .as_str()
        .ok_or_else(|| Version2Error::new("invalid_migration_descriptor", "base digest is absent"))?
        .to_string();
    let base_bytes = canonical_bytes(&base)?;
    let mut resolver = InMemoryDefinitionResolver::default();
    resolver.insert(source_bundle.clone(), true);
    resolver.insert(target_bundle.clone(), true);
    if let Some(artifact_resolver) = artifact_resolver {
        let mut fingerprints = BTreeSet::new();
        collect_bundle_fingerprints(&aggregate.value, &mut fingerprints);
        for fingerprint in fingerprints {
            let resolved = artifact_resolver
                .resolve_definition(&fingerprint)
                .ok_or_else(|| {
                    Version2Error::new(
                        "source_definition_unavailable",
                        "retained provenance definition is unavailable",
                    )
                })?;
            if !resolved.trusted || resolved.bundle.fingerprint != fingerprint {
                return Err(Version2Error::new(
                    "source_definition_untrusted",
                    "retained provenance definition is not trusted",
                ));
            }
            resolver.insert(resolved.bundle, true);
        }
    }
    resolver.insert_descriptor(base_digest.clone(), base_bytes, true);
    let source = canonical_bytes(&project_v1(&aggregate.value)?)?;
    let request = super::migration::MigrationRequest {
        migration_route: vec![base_digest],
        target_validated_bundle_fingerprint: target_bundle.fingerprint.clone(),
        maintenance_mode,
    };
    let outcome = super::migration::migrate_aggregate(&source, &request, &resolver, limits)
        .map_err(map_persistence)?;
    let id_map = runtime_id_map(&aggregate.state.root, &outcome.aggregate.root)?;
    let mut value =
        merge_migrated_state(target_bundle, &aggregate.value, &outcome.aggregate, &id_map)?;
    let descriptor_digest = descriptor["migration_descriptor_digest"]
        .as_str()
        .ok_or_else(|| Version2Error::new("invalid_migration_descriptor", "digest is absent"))?;
    let rules = descriptor["queued_event_rules"]
        .as_array()
        .ok_or_else(|| Version2Error::new("invalid_migration_descriptor", "rules are absent"))?;
    let dispositions = apply_queued_event_rules(
        &mut value,
        &outcome.aggregate,
        target_bundle,
        rules,
        descriptor_digest,
    )?;
    recall_deferred(&mut value, &outcome.aggregate)?;
    validate_migrated_capacity(&value, &outcome.aggregate)?;
    value = seal_aggregate(value)?;
    let audit_records = outcome
        .audit_records
        .into_iter()
        .map(|record| {
            json!({
                "migration_audit_record_schema_version": record.migration_audit_record_schema_version,
                "root_instance_id": record.root_instance_id,
                "root_runtime_id": record.root_runtime_id,
                "migration_sequence": record.migration_sequence,
                "source_validated_bundle_fingerprint": source_bundle.fingerprint,
                "target_validated_bundle_fingerprint": target_bundle.fingerprint,
                "migration_descriptor_digest": descriptor_digest,
                "source_aggregate_state_digest": aggregate.value["aggregate_state_digest"],
                "target_aggregate_state_digest": value["aggregate_state_digest"],
                "result_code": record.result_code
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "result": "success",
        "aggregate_state": value,
        "dispositions": dispositions,
        "audit_records": audit_records
    }))
}

fn collect_bundle_fingerprints(value: &JsonValue, fingerprints: &mut BTreeSet<String>) {
    match value {
        JsonValue::Object(object) => {
            if let Some(fingerprint) = object
                .get("validated_bundle_fingerprint")
                .and_then(JsonValue::as_str)
            {
                fingerprints.insert(fingerprint.to_string());
            }
            for child in object.values() {
                collect_bundle_fingerprints(child, fingerprints);
            }
        }
        JsonValue::Array(values) => {
            for child in values {
                collect_bundle_fingerprints(child, fingerprints);
            }
        }
        _ => {}
    }
}

pub(crate) fn decode_descriptor_v2(source: &[u8]) -> Result<JsonValue, Version2Error> {
    let value = strict_json::parse(source)
        .map_err(|error| Version2Error::new("invalid_migration_descriptor", error.to_string()))?;
    if value["migration_descriptor_format"].as_str() != Some("determa.aggregate_migration") {
        return Err(Version2Error::new(
            "unsupported_migration_descriptor_format",
            "unsupported migration descriptor format",
        ));
    }
    if value["migration_descriptor_schema_version"].as_i64() != Some(2) {
        return Err(Version2Error::new(
            "unsupported_migration_descriptor_schema_version",
            "unsupported migration descriptor schema version",
        ));
    }
    validate_v2_schema(
        &value,
        include_str!("../../schema/migration-descriptor-v2.schema.json"),
        &[(
            "https://determa.dev/state/schema/migration-descriptor.schema.json",
            include_str!("../../schema/migration-descriptor.schema.json"),
        )],
        "invalid_migration_descriptor",
    )?;
    let mut unsigned = value.clone();
    unsigned
        .as_object_mut()
        .expect("schema requires object")
        .remove("migration_descriptor_digest");
    let expected = wire::jcs_hash(&json!(["determa-migration-descriptor-2", unsigned]))
        .map_err(map_persistence)?;
    if value["migration_descriptor_digest"].as_str() != Some(expected.as_str()) {
        return Err(Version2Error::new(
            "invalid_migration_descriptor",
            "migration descriptor digest does not match content",
        ));
    }
    let mut selectors = BTreeSet::new();
    for rule in value["queued_event_rules"]
        .as_array()
        .expect("schema requires rules")
    {
        let selector = (
            rule["machine_id"].as_str().unwrap(),
            rule["event"].as_str().unwrap(),
            rule["delivery_mode"].as_str().unwrap(),
        );
        if !selectors.insert(selector) {
            return Err(Version2Error::new(
                "invalid_migration_descriptor",
                "queued event selectors must be unique",
            ));
        }
    }
    Ok(value)
}

fn runtime_id_map(
    old: &RuntimeState,
    new: &RuntimeState,
) -> Result<BTreeMap<String, String>, Version2Error> {
    let mut result = BTreeMap::from([(old.runtime_id.clone(), new.runtime_id.clone())]);
    for old_component in &old.components {
        let new_component = new
            .components
            .iter()
            .find(|candidate| {
                candidate.component_id == old_component.component_id
                    && candidate.activation_sequence == old_component.activation_sequence
            })
            .ok_or_else(|| {
                Version2Error::new(
                    "migration_totality_failure",
                    "component runtime mapping is absent",
                )
            })?;
        result.extend(runtime_id_map(
            &old_component.runtime,
            &new_component.runtime,
        )?);
    }
    for old_owned in &old.owned_instances {
        let new_owned = new
            .owned_instances
            .iter()
            .find(|candidate| candidate.spawn_sequence == old_owned.spawn_sequence)
            .ok_or_else(|| {
                Version2Error::new(
                    "migration_totality_failure",
                    "spawned runtime mapping is absent",
                )
            })?;
        result.extend(runtime_id_map(&old_owned.runtime, &new_owned.runtime)?);
    }
    Ok(result)
}

fn merge_migrated_state(
    target_bundle: &Bundle,
    old: &JsonValue,
    state: &AggregateState,
    id_map: &BTreeMap<String, String>,
) -> Result<JsonValue, Version2Error> {
    let (_, bytes) =
        super::wire::encode_aggregate(target_bundle, state).map_err(map_persistence)?;
    let mut value: JsonValue =
        serde_json::from_slice(&bytes).map_err(|error| invalid_aggregate(error.to_string()))?;
    value["aggregate_state_schema_version"] = json!(2);
    value["next_acceptance_sequence"] = old["next_acceptance_sequence"].clone();
    value["next_queue_sequence"] = old["next_queue_sequence"].clone();
    let old_runtimes = runtimes(old)?;
    for runtime in runtimes_mut(&mut value)? {
        let new_id = runtime["runtime_id"].as_str().unwrap();
        let old_id = id_map
            .iter()
            .find_map(|(old, new)| (new == new_id).then_some(old.as_str()));
        let old_runtime = old_id.and_then(|old_id| {
            old_runtimes
                .iter()
                .find(|candidate| candidate["runtime_id"].as_str() == Some(old_id))
        });
        runtime["ready_mailbox"] =
            old_runtime.map_or_else(|| json!([]), |old| old["ready_mailbox"].clone());
        runtime["deferred_mailbox"] =
            old_runtime.map_or_else(|| json!([]), |old| old["deferred_mailbox"].clone());
        replace_runtime_ids(&mut runtime["ready_mailbox"], id_map);
        replace_runtime_ids(&mut runtime["deferred_mailbox"], id_map);
    }
    let root_instance_id = aggregate_root_instance_id(&value)?.to_string();
    for runtime in runtimes_mut(&mut value)? {
        for field in ["ready_mailbox", "deferred_mailbox"] {
            for entry in runtime[field].as_array_mut().unwrap() {
                let envelope: QueueEnvelope = serde_json::from_value(entry["envelope"].clone())
                    .map_err(|error| invalid_aggregate(error.to_string()))?;
                let mode = entry["delivery_mode"].as_str().unwrap();
                entry["envelope_digest"] =
                    json!(envelope_digest(&root_instance_id, mode, &envelope)?);
            }
        }
    }
    seal_aggregate(value)
}

fn replace_runtime_ids(value: &mut JsonValue, replacements: &BTreeMap<String, String>) {
    match value {
        JsonValue::String(text) => {
            if let Some(replacement) = replacements.get(text) {
                *text = replacement.clone();
            }
        }
        JsonValue::Array(values) => {
            for value in values {
                replace_runtime_ids(value, replacements);
            }
        }
        JsonValue::Object(values) => {
            for value in values.values_mut() {
                replace_runtime_ids(value, replacements);
            }
        }
        _ => {}
    }
}

fn apply_queued_event_rules(
    value: &mut JsonValue,
    state: &AggregateState,
    target_bundle: &Bundle,
    rules: &[JsonValue],
    descriptor_digest: &str,
) -> Result<Vec<JsonValue>, Version2Error> {
    let mut dispositions = Vec::new();
    let runtime_ids = runtimes(value)?
        .iter()
        .map(|runtime| runtime["runtime_id"].as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    for runtime_id in runtime_ids {
        let machine_id = runtime_by_id(&state.root, &runtime_id)
            .ok_or_else(|| invalid_aggregate("migrated runtime is absent"))?
            .machine_id
            .clone();
        for field in ["ready_mailbox", "deferred_mailbox"] {
            let entries = runtime_object_mut(value, &runtime_id)?[field]
                .as_array_mut()
                .ok_or_else(|| invalid_aggregate("mailbox is not an array"))?;
            let mut retained = Vec::new();
            for entry in std::mem::take(entries) {
                let event = entry["envelope"]["event"].as_str().unwrap();
                let mode = entry["delivery_mode"].as_str().unwrap();
                if let Some(rule) = rules.iter().find(|rule| {
                    rule["machine_id"].as_str() == Some(machine_id.as_str())
                        && rule["event"].as_str() == Some(event)
                        && rule["delivery_mode"].as_str() == Some(mode)
                }) {
                    dispositions.push(json!({
                        "event_id": entry["envelope"]["event_id"],
                        "request_digest": entry["envelope_digest"],
                        "acceptance_sequence": entry["acceptance_sequence"],
                        "final_queue_sequence": entry["queue_sequence"],
                        "target_runtime_id": runtime_id,
                        "disposition": "migration_disposed",
                        "reason": rule["reason"],
                        "migration_descriptor_digest": descriptor_digest
                    }));
                    continue;
                }
                let delivery: AdmissionDelivery = serde_json::from_value(json!({
                    "delivery_mode": entry["delivery_mode"],
                    "envelope": entry["envelope"],
                    "envelope_digest": entry["envelope_digest"]
                }))
                .map_err(|error| invalid_aggregate(error.to_string()))?;
                let core = core_delivery(&delivery)?;
                validate_queued_event_for_migration(target_bundle, state, &core).map_err(|_| {
                    Version2Error::new(
                        "migration_totality_failure",
                        "queued event is incompatible with target definition",
                    )
                })?;
                retained.push(entry);
            }
            runtime_object_mut(value, &runtime_id)?[field] = json!(retained);
        }
    }
    Ok(dispositions)
}

fn validate_migrated_capacity(
    value: &JsonValue,
    state: &AggregateState,
) -> Result<(), Version2Error> {
    for runtime in runtimes(value)? {
        let runtime_id = runtime["runtime_id"].as_str().unwrap();
        let runtime_state = runtime_by_id(&state.root, runtime_id)
            .ok_or_else(|| invalid_aggregate("migrated runtime is absent"))?;
        let count = runtime["deferred_mailbox"].as_array().unwrap().len();
        if deferred_event_capacity(runtime_state)
            .is_some_and(|capacity| count > usize::try_from(capacity).unwrap_or(0))
        {
            return Err(Version2Error::new(
                "migration_totality_failure",
                "deferred mailbox exceeds target capacity",
            ));
        }
    }
    Ok(())
}

pub fn admit_v2(
    bundle: &Bundle,
    aggregate: &QueueBearingAggregate,
    deliveries: &[AdmissionDelivery],
) -> Result<JsonValue, Version2Error> {
    let mut seen = BTreeSet::new();
    if deliveries
        .iter()
        .any(|delivery| !seen.insert(delivery.envelope.event_id.as_str()))
    {
        return Err(Version2Error::new(
            "duplicate_event_id_in_batch",
            "delivery batch contains a duplicate event id",
        ));
    }

    let locations = mailbox_locations(&aggregate.value)?;
    let mut replay = Vec::new();
    let mut fresh = Vec::new();
    for delivery in deliveries {
        validate_admission_delivery_schema(
            &serde_json::to_value(delivery).map_err(|error| {
                Version2Error::new("invalid_delivery_source", error.to_string())
            })?,
        )?;
        let computed = envelope_digest(
            aggregate_root_instance_id(&aggregate.value)?,
            &delivery.delivery_mode,
            &delivery.envelope,
        )?;
        if let Some(existing) = locations.get(&delivery.envelope.event_id) {
            if existing.digest != computed {
                return Err(Version2Error::new(
                    "event_id_conflict",
                    "event identity is already retained with different content",
                ));
            }
            replay.push((delivery, existing));
            continue;
        }
        if delivery.envelope_digest != computed {
            return Err(Version2Error::new(
                "delivery_digest_mismatch",
                "supplied envelope digest does not match canonical content",
            ));
        }
        validate_source(delivery, &aggregate.value)?;
        let core_delivery = core_delivery(delivery)?;
        let runtime_id = validate_delivery_for_admission(bundle, &aggregate.state, &core_delivery)
            .map_err(map_dispatch_rejection)?;
        fresh.push((delivery, runtime_id));
    }

    if !replay.is_empty() && fresh.is_empty() && replay.len() == 1 {
        let (delivery, location) = replay[0];
        return Ok(json!({
            "result": "replay",
            "status": aggregate_status(&aggregate.value)?,
            "state": aggregate.value,
            "event_id": delivery.envelope.event_id,
            "acceptance_sequence": location.acceptance_sequence,
            "location": location.location,
            "rejection": null
        }));
    }

    let mut value = aggregate.value.clone();
    let mut accepted = Vec::new();
    for (delivery, runtime_id) in fresh {
        let acceptance_sequence = allocate_counter(&mut value, "next_acceptance_sequence")?;
        let queue_sequence = allocate_counter(&mut value, "next_queue_sequence")?;
        let entry = json!({
            "acceptance_sequence": acceptance_sequence.to_string(),
            "queue_sequence": queue_sequence.to_string(),
            "delivery_mode": delivery.delivery_mode,
            "envelope": delivery.envelope,
            "envelope_digest": delivery.envelope_digest,
            "deferral_count": "0"
        });
        runtime_object_mut(&mut value, &runtime_id)?
            .get_mut("ready_mailbox")
            .and_then(JsonValue::as_array_mut)
            .ok_or_else(|| invalid_aggregate("runtime ready mailbox is absent"))?
            .push(entry);
        accepted.push(json!({
            "event_id": delivery.envelope.event_id,
            "acceptance_sequence": acceptance_sequence.to_string(),
            "queue_sequence": queue_sequence.to_string()
        }));
    }
    value = seal_aggregate(value)?;
    Ok(json!({
        "result": "accepted",
        "status": aggregate_status(&value)?,
        "state": value,
        "accepted": accepted,
        "rejection": null
    }))
}

pub fn step_v2(
    bundle: &Bundle,
    aggregate: &QueueBearingAggregate,
    target_runtime_id: &str,
) -> Result<JsonValue, Version2Error> {
    let root_status = aggregate_status(&aggregate.value)?;
    if aggregate.value["validated_bundle_fingerprint"].as_str() != Some(bundle.fingerprint.as_str())
    {
        return core_step_rejected(aggregate, "incompatible_bundle");
    }
    let runtime = runtimes(&aggregate.value)?
        .iter()
        .find(|runtime| runtime["runtime_id"].as_str() == Some(target_runtime_id));
    let Some(runtime) = runtime else {
        return core_step_rejected(aggregate, "invalid_instance_target");
    };
    let relation = runtime["relation"]["kind"].as_str().unwrap_or("root");
    if root_status == "faulted" || runtime["status"].as_str() != Some("running") {
        let code = if root_status != "faulted" && relation == "component" {
            "inactive_component_target"
        } else {
            "invalid_instance_target"
        };
        return core_step_rejected(aggregate, code);
    }
    let ready = runtime["ready_mailbox"]
        .as_array()
        .ok_or_else(|| invalid_aggregate("runtime ready mailbox is absent"))?;
    if ready.is_empty() {
        return core_step_result(
            aggregate.value.clone(),
            "not_runnable",
            Vec::new(),
            Vec::new(),
            None,
            None,
        );
    }
    let causal_entry = ready[0].clone();
    let delivery: AdmissionDelivery = serde_json::from_value(json!({
        "delivery_mode": causal_entry["delivery_mode"],
        "envelope": causal_entry["envelope"],
        "envelope_digest": causal_entry["envelope_digest"]
    }))
    .map_err(|error| invalid_aggregate(error.to_string()))?;
    let core_delivery = core_delivery(&delivery)?;
    let envelope = match &core_delivery {
        Delivery::Input(envelope) | Delivery::Internal(envelope) => envelope.clone(),
    };
    let result = dispatch(bundle, &aggregate.state, Some(core_delivery));

    if result.disposition == Some(Disposition::Deferred) {
        let runtime_state = runtime_by_id(&aggregate.state.root, target_runtime_id)
            .ok_or_else(|| invalid_aggregate("target runtime is absent from abstract state"))?;
        let deferred_len = runtime["deferred_mailbox"]
            .as_array()
            .ok_or_else(|| invalid_aggregate("runtime deferred mailbox is absent"))?
            .len();
        if deferred_event_capacity(runtime_state)
            .is_some_and(|capacity| deferred_len >= usize::try_from(capacity).unwrap_or(0))
        {
            let faulted = fault_deferred_capacity(bundle, &aggregate.state, &envelope);
            let state = faulted
                .state
                .as_ref()
                .ok_or_else(|| invalid_aggregate("capacity fault returned no state"))?;
            let mut value = merge_abstract_state(bundle, &aggregate.value, state)?;
            remove_ready_head(&mut value, target_runtime_id)?;
            let mut lifecycle = dispose_removed_mailboxes(
                &aggregate.value,
                &mut value,
                &faulted.emissions,
                state.root.status,
                &delivery.envelope.event_id,
            )?;
            let emission_results = append_step_emissions(
                &mut value,
                &aggregate.value,
                &faulted.emissions,
                &mut lifecycle,
            )?;
            value = seal_aggregate(value)?;
            return core_step_result(
                value,
                "faulted",
                emission_results,
                lifecycle,
                faulted
                    .fault
                    .as_ref()
                    .map(serde_json::to_value)
                    .transpose()
                    .map_err(|error| invalid_aggregate(error.to_string()))?,
                None,
            );
        }
        let mut value = aggregate.value.clone();
        allocate_counter(&mut value, "next_logical_step_sequence")?;
        let mut entry = remove_ready_head(&mut value, target_runtime_id)?;
        let queue_sequence = allocate_counter(&mut value, "next_queue_sequence")?;
        entry["queue_sequence"] = json!(queue_sequence.to_string());
        let mut deferrals = counter_value(&entry, "deferral_count")?;
        deferrals.allocate();
        entry["deferral_count"] = json!(deferrals.to_string());
        runtime_object_mut(&mut value, target_runtime_id)?["deferred_mailbox"]
            .as_array_mut()
            .ok_or_else(|| invalid_aggregate("runtime deferred mailbox is absent"))?
            .push(entry);
        value = seal_aggregate(value)?;
        return core_step_result(value, "deferred", Vec::new(), Vec::new(), None, None);
    }

    let state = result
        .state
        .as_ref()
        .ok_or_else(|| invalid_aggregate("core step returned no aggregate state"))?;
    let mut value = merge_abstract_state(bundle, &aggregate.value, state)?;
    remove_ready_head(&mut value, target_runtime_id)?;
    let mut lifecycle = dispose_removed_mailboxes(
        &aggregate.value,
        &mut value,
        &result.emissions,
        state.root.status,
        &delivery.envelope.event_id,
    )?;
    let emission_results = append_step_emissions(
        &mut value,
        &aggregate.value,
        &result.emissions,
        &mut lifecycle,
    )?;
    if result.disposition == Some(Disposition::Handled)
        && state.root.status == RuntimeStatus::Running
    {
        recall_deferred(&mut value, state)?;
    }
    value = seal_aggregate(value)?;
    let disposition = result
        .disposition
        .map(Disposition::as_str)
        .unwrap_or("handled");
    let fault = result
        .fault
        .as_ref()
        .map(serde_json::to_value)
        .transpose()
        .map_err(|error| invalid_aggregate(error.to_string()))?;
    let rejection = result
        .rejection
        .as_ref()
        .map(|rejection| json!({"code": rejection.code}));
    core_step_result(
        value,
        disposition,
        emission_results,
        lifecycle,
        fault,
        rejection,
    )
}

fn merge_abstract_state(
    bundle: &Bundle,
    old: &JsonValue,
    state: &AggregateState,
) -> Result<JsonValue, Version2Error> {
    let (_, bytes) = super::wire::encode_aggregate(bundle, state).map_err(map_persistence)?;
    let mut value: JsonValue =
        serde_json::from_slice(&bytes).map_err(|error| invalid_aggregate(error.to_string()))?;
    value["aggregate_state_schema_version"] = json!(2);
    value["next_acceptance_sequence"] = old["next_acceptance_sequence"].clone();
    value["next_queue_sequence"] = old["next_queue_sequence"].clone();
    for runtime in runtimes_mut(&mut value)? {
        let runtime_id = runtime["runtime_id"]
            .as_str()
            .ok_or_else(|| invalid_aggregate("runtime id is absent"))?;
        let old_runtime = runtimes(old)?
            .iter()
            .find(|candidate| candidate["runtime_id"].as_str() == Some(runtime_id));
        runtime["ready_mailbox"] =
            old_runtime.map_or_else(|| json!([]), |item| item["ready_mailbox"].clone());
        runtime["deferred_mailbox"] =
            old_runtime.map_or_else(|| json!([]), |item| item["deferred_mailbox"].clone());
    }
    seal_aggregate(value)
}

fn remove_ready_head(value: &mut JsonValue, runtime_id: &str) -> Result<JsonValue, Version2Error> {
    let ready = runtime_object_mut(value, runtime_id)?["ready_mailbox"]
        .as_array_mut()
        .ok_or_else(|| invalid_aggregate("runtime ready mailbox is absent"))?;
    if ready.is_empty() {
        return Err(invalid_aggregate("runtime ready mailbox is empty"));
    }
    Ok(ready.remove(0))
}

fn recall_deferred(value: &mut JsonValue, state: &AggregateState) -> Result<(), Version2Error> {
    let runtime_ids = runtimes(value)?
        .iter()
        .filter_map(|runtime| runtime["runtime_id"].as_str().map(str::to_string))
        .collect::<Vec<_>>();
    for runtime_id in runtime_ids {
        let Some(runtime_state) = runtime_by_id(&state.root, &runtime_id) else {
            continue;
        };
        if runtime_state.status != RuntimeStatus::Running {
            continue;
        }
        let entries = runtime_object_mut(value, &runtime_id)?["deferred_mailbox"]
            .as_array_mut()
            .ok_or_else(|| invalid_aggregate("runtime deferred mailbox is absent"))?;
        let frozen = std::mem::take(entries);
        let mut retained = Vec::new();
        let mut recalled = Vec::new();
        for mut entry in frozen {
            let event = entry["envelope"]["event"]
                .as_str()
                .ok_or_else(|| invalid_aggregate("mailbox event is absent"))?;
            if structural_recall_eligible(runtime_state, event) {
                let queue = allocate_counter(value, "next_queue_sequence")?;
                entry["queue_sequence"] = json!(queue.to_string());
                recalled.push(entry);
            } else {
                retained.push(entry);
            }
        }
        runtime_object_mut(value, &runtime_id)?["deferred_mailbox"] = json!(retained);
        runtime_object_mut(value, &runtime_id)?["ready_mailbox"]
            .as_array_mut()
            .ok_or_else(|| invalid_aggregate("runtime ready mailbox is absent"))?
            .extend(recalled);
    }
    Ok(())
}

fn dispose_removed_mailboxes(
    old: &JsonValue,
    new: &mut JsonValue,
    emissions: &[Emission],
    root_status: RuntimeStatus,
    causal_event_id: &str,
) -> Result<Vec<JsonValue>, Version2Error> {
    let retained_ids = runtimes(new)?
        .iter()
        .filter_map(|runtime| runtime["runtime_id"].as_str().map(str::to_string))
        .collect::<BTreeSet<_>>();
    let completed_ids = emissions
        .iter()
        .filter(|emission| emission.event == "determa.component_completed")
        .map(|emission| emission.emitting_runtime_id.as_str())
        .collect::<BTreeSet<_>>();
    let mut dispositions = Vec::new();
    for runtime in runtimes(old)? {
        let runtime_id = runtime["runtime_id"]
            .as_str()
            .ok_or_else(|| invalid_aggregate("runtime id is absent"))?;
        if retained_ids.contains(runtime_id) && root_status != RuntimeStatus::Completed {
            continue;
        }
        let reason = if root_status == RuntimeStatus::Completed {
            "aggregate_completed"
        } else if completed_ids.contains(runtime_id) {
            "runtime_completed"
        } else {
            "runtime_cancelled"
        };
        let source = if retained_ids.contains(runtime_id) {
            runtimes(new)?
                .iter()
                .find(|candidate| candidate["runtime_id"].as_str() == Some(runtime_id))
                .unwrap_or(runtime)
                .clone()
        } else {
            runtime.clone()
        };
        for field in ["ready_mailbox", "deferred_mailbox"] {
            for entry in source[field]
                .as_array()
                .ok_or_else(|| invalid_aggregate("mailbox is not an array"))?
            {
                if entry["envelope"]["event_id"].as_str() == Some(causal_event_id) {
                    continue;
                }
                dispositions.push(lifecycle_disposition(entry, runtime_id, reason)?);
            }
        }
        if retained_ids.contains(runtime_id) {
            runtime_object_mut(new, runtime_id)?["ready_mailbox"] = json!([]);
            runtime_object_mut(new, runtime_id)?["deferred_mailbox"] = json!([]);
        }
    }
    Ok(dispositions)
}

fn append_step_emissions(
    value: &mut JsonValue,
    old: &JsonValue,
    emissions: &[Emission],
    lifecycle: &mut Vec<JsonValue>,
) -> Result<Vec<JsonValue>, Version2Error> {
    let mut results = Vec::new();
    for (index, emission) in emissions.iter().enumerate() {
        if matches!(emission.target, Target::External) {
            results.push(json!({
                "effect_id": emission.effect_id,
                "sequence": emission.sequence,
                "event": emission.event,
                "payload": TypedValue::from_value(&crate::value::Value::Map(emission.payload.clone())),
                "correlation_id": emission.correlation_id
            }));
            continue;
        }
        let event_id = emission
            .event_id
            .as_ref()
            .ok_or_else(|| invalid_aggregate("internal emission has no event id"))?;
        let cause_id = emission
            .cause_id
            .as_ref()
            .ok_or_else(|| invalid_aggregate("internal emission has no causal event id"))?;
        let source = if let Some(locator) = &emission.system_source {
            json!({"system": locator})
        } else {
            let source_target = runtime_target(value, &emission.emitting_runtime_id)
                .or_else(|| runtime_target(old, &emission.emitting_runtime_id))
                .ok_or_else(|| invalid_aggregate("internal emission source runtime is absent"))?;
            json!({"runtime": source_target})
        };
        let envelope = QueueEnvelope {
            event: emission.event.clone(),
            event_id: event_id.clone(),
            cause_id: cause_id.clone(),
            source,
            target: core_target_to_queue(&emission.target)?,
            payload: TypedValue::from_value(&crate::value::Value::Map(emission.payload.clone())),
            correlation_id: emission.correlation_id.clone(),
        };
        let acceptance = allocate_counter(value, "next_acceptance_sequence")?;
        let queue = allocate_counter(value, "next_queue_sequence")?;
        let digest = envelope_digest(aggregate_root_instance_id(value)?, "internal", &envelope)?;
        let entry = json!({
            "acceptance_sequence": acceptance.to_string(),
            "queue_sequence": queue.to_string(),
            "delivery_mode": "internal",
            "envelope": envelope,
            "envelope_digest": digest,
            "deferral_count": "0"
        });
        let target_id = target_runtime_id(&emission.target);
        let target_status = target_id.and_then(|target_id| runtime_status(value, target_id));
        if let Some(target_id) = target_id.filter(|_| {
            matches!(target_status, Some("running" | "faulted"))
                && aggregate_status(value).ok() != Some("completed")
        }) {
            runtime_object_mut(value, target_id)?["ready_mailbox"]
                .as_array_mut()
                .ok_or_else(|| invalid_aggregate("target ready mailbox is absent"))?
                .push(entry);
            results.push(json!({
                "kind": "internal_mailbox",
                "emission_index": index.to_string(),
                "event_id": event_id,
                "acceptance_sequence": acceptance.to_string(),
                "queue_sequence": queue.to_string()
            }));
        } else {
            let target_id =
                target_id.ok_or_else(|| invalid_aggregate("internal target is external"))?;
            let disposition_index = lifecycle.len();
            let reason = if value["root_runtime_id"].as_str() == Some(target_id)
                && aggregate_status(value)? == "completed"
            {
                "aggregate_completed"
            } else if target_status == Some("completed") {
                "runtime_completed"
            } else {
                "runtime_cancelled"
            };
            lifecycle.push(lifecycle_disposition(&entry, target_id, reason)?);
            results.push(json!({
                "kind": "internal_disposed",
                "emission_index": index.to_string(),
                "event_id": event_id,
                "acceptance_sequence": acceptance.to_string(),
                "lifecycle_disposition_index": disposition_index.to_string()
            }));
        }
    }
    Ok(results)
}

fn lifecycle_disposition(
    entry: &JsonValue,
    runtime_id: &str,
    reason: &str,
) -> Result<JsonValue, Version2Error> {
    Ok(json!({
        "event_id": entry["envelope"]["event_id"],
        "request_digest": entry["envelope_digest"],
        "acceptance_sequence": entry["acceptance_sequence"],
        "final_queue_sequence": entry["queue_sequence"],
        "target_runtime_id": runtime_id,
        "reason": reason
    }))
}

fn runtime_target(value: &JsonValue, runtime_id: &str) -> Option<JsonValue> {
    value["runtimes"]
        .as_array()?
        .iter()
        .find(|runtime| runtime["runtime_id"].as_str() == Some(runtime_id))
        .map(|runtime| runtime["target_identity"].clone())
}

fn runtime_status<'a>(value: &'a JsonValue, runtime_id: &str) -> Option<&'a str> {
    value["runtimes"]
        .as_array()?
        .iter()
        .find(|runtime| runtime["runtime_id"].as_str() == Some(runtime_id))
        .and_then(|runtime| runtime["status"].as_str())
}

fn queue_target_to_core(value: &JsonValue) -> Result<Target, Version2Error> {
    let mut target = value.clone();
    if let Some(spawned) = target
        .get_mut("spawned_instance")
        .and_then(JsonValue::as_object_mut)
    {
        let version = spawned
            .get("machine_version")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| invalid_aggregate("spawned machine version is absent"))?
            .parse::<i64>()
            .map_err(|error| invalid_aggregate(error.to_string()))?;
        spawned.insert("machine_version".to_string(), json!(version));
    }
    serde_json::from_value(target).map_err(|error| invalid_aggregate(error.to_string()))
}

fn core_target_to_queue(target: &Target) -> Result<JsonValue, Version2Error> {
    let mut value =
        serde_json::to_value(target).map_err(|error| invalid_aggregate(error.to_string()))?;
    if let Some(spawned) = value
        .get_mut("spawned_instance")
        .and_then(JsonValue::as_object_mut)
    {
        let version = spawned
            .get("machine_version")
            .and_then(JsonValue::as_i64)
            .ok_or_else(|| invalid_aggregate("spawned machine version is absent"))?;
        spawned.insert("machine_version".to_string(), json!(version.to_string()));
    }
    Ok(value)
}

fn target_runtime_id(target: &Target) -> Option<&str> {
    match target {
        Target::Root {
            root_runtime_id, ..
        } => Some(root_runtime_id),
        Target::Component {
            component_runtime_id,
            ..
        } => Some(component_runtime_id),
        Target::SpawnedInstance(reference) => Some(&reference.instance_id),
        Target::External => None,
    }
}

fn core_step_rejected(
    aggregate: &QueueBearingAggregate,
    code: &str,
) -> Result<JsonValue, Version2Error> {
    core_step_result(
        aggregate.value.clone(),
        "rejected",
        Vec::new(),
        Vec::new(),
        None,
        Some(json!({"code": code})),
    )
}

fn core_step_result(
    state: JsonValue,
    disposition: &str,
    emissions: Vec<JsonValue>,
    lifecycle_dispositions: Vec<JsonValue>,
    fault: Option<JsonValue>,
    rejection: Option<JsonValue>,
) -> Result<JsonValue, Version2Error> {
    let status = aggregate_status(&state)?;
    Ok(json!({
        "core_step_result_format": "determa.core_step_result",
        "core_step_result_schema_version": 2,
        "status": status,
        "disposition": disposition,
        "state": state,
        "emissions": emissions,
        "lifecycle_dispositions": lifecycle_dispositions,
        "fault": fault,
        "rejection": rejection
    }))
}

struct MailboxLocation<'a> {
    digest: &'a str,
    acceptance_sequence: &'a str,
    location: &'static str,
}

fn mailbox_locations(
    value: &JsonValue,
) -> Result<BTreeMap<String, MailboxLocation<'_>>, Version2Error> {
    let mut locations = BTreeMap::new();
    for runtime in runtimes(value)? {
        for (field, location) in [("ready_mailbox", "ready"), ("deferred_mailbox", "deferred")] {
            let entries = runtime[field]
                .as_array()
                .ok_or_else(|| invalid_aggregate("mailbox is not an array"))?;
            for entry in entries {
                let event_id = entry["envelope"]["event_id"]
                    .as_str()
                    .ok_or_else(|| invalid_aggregate("mailbox event id is absent"))?;
                let digest = entry["envelope_digest"]
                    .as_str()
                    .ok_or_else(|| invalid_aggregate("mailbox digest is absent"))?;
                let acceptance_sequence = entry["acceptance_sequence"]
                    .as_str()
                    .ok_or_else(|| invalid_aggregate("mailbox acceptance sequence is absent"))?;
                locations.insert(
                    event_id.to_string(),
                    MailboxLocation {
                        digest,
                        acceptance_sequence,
                        location,
                    },
                );
            }
        }
    }
    Ok(locations)
}

pub(crate) fn restore_aggregate_v2_value(
    value: JsonValue,
    resolver: &(impl DefinitionResolver + ?Sized),
) -> Result<QueueBearingAggregate, Version2Error> {
    let object = aggregate_object(&value)?;
    if object
        .get("aggregate_state_format")
        .and_then(JsonValue::as_str)
        != Some("determa.aggregate_state")
    {
        return Err(Version2Error::new(
            "unsupported_aggregate_state_format",
            "unsupported aggregate-state format",
        ));
    }
    if object
        .get("aggregate_state_schema_version")
        .and_then(JsonValue::as_i64)
        != Some(2)
    {
        return Err(Version2Error::new(
            "unsupported_aggregate_state_schema_version",
            "unsupported queue-bearing aggregate-state schema version",
        ));
    }
    validate_aggregate_schema(&value)?;
    let expected = aggregate_digest(&value)?;
    if object
        .get("aggregate_state_digest")
        .and_then(JsonValue::as_str)
        != Some(expected.as_str())
    {
        return Err(Version2Error::new(
            "aggregate_state_digest_mismatch",
            "queue-bearing aggregate-state digest does not match content",
        ));
    }
    validate_mailbox_integrity(&value)?;
    let projected = project_v1(&value)?;
    let envelope: AggregateEnvelope =
        serde_json::from_value(projected).map_err(|error| invalid_aggregate(error.to_string()))?;
    let state = super::wire::restore_envelope(&envelope, resolver).map_err(map_persistence)?;
    validate_mailbox_semantics(&value, &state, resolver)?;
    Ok(QueueBearingAggregate { value, state })
}

fn upgrade_value(value: &mut JsonValue) -> Result<(), Version2Error> {
    let object = aggregate_object_mut(value)?;
    object.insert("aggregate_state_schema_version".to_string(), json!(2));
    object.insert("next_acceptance_sequence".to_string(), json!("0"));
    object.insert("next_queue_sequence".to_string(), json!("0"));
    for runtime in object
        .get_mut("runtimes")
        .and_then(JsonValue::as_array_mut)
        .ok_or_else(|| invalid_aggregate("aggregate runtimes are absent"))?
    {
        let runtime = runtime
            .as_object_mut()
            .ok_or_else(|| invalid_aggregate("runtime must be an object"))?;
        runtime.insert("ready_mailbox".to_string(), json!([]));
        runtime.insert("deferred_mailbox".to_string(), json!([]));
    }
    *value = seal_aggregate(value.clone())?;
    Ok(())
}

fn project_v1(value: &JsonValue) -> Result<JsonValue, Version2Error> {
    let mut projected = value.clone();
    {
        let object = aggregate_object_mut(&mut projected)?;
        object.insert("aggregate_state_schema_version".to_string(), json!(1));
        object.remove("next_acceptance_sequence");
        object.remove("next_queue_sequence");
        for runtime in object
            .get_mut("runtimes")
            .and_then(JsonValue::as_array_mut)
            .ok_or_else(|| invalid_aggregate("aggregate runtimes are absent"))?
        {
            let runtime = runtime
                .as_object_mut()
                .ok_or_else(|| invalid_aggregate("runtime must be an object"))?;
            runtime.remove("ready_mailbox");
            runtime.remove("deferred_mailbox");
        }
    }
    let digest = wire::aggregate_digest(&projected).map_err(map_persistence)?;
    aggregate_object_mut(&mut projected)?
        .insert("aggregate_state_digest".to_string(), json!(digest));
    Ok(projected)
}

fn seal_aggregate(mut value: JsonValue) -> Result<JsonValue, Version2Error> {
    for runtime in runtimes_mut(&mut value)? {
        for field in ["ready_mailbox", "deferred_mailbox"] {
            runtime[field]
                .as_array_mut()
                .ok_or_else(|| invalid_aggregate("mailbox is not an array"))?
                .sort_by(|left, right| {
                    counter_field(left, "queue_sequence")
                        .cmp(&counter_field(right, "queue_sequence"))
                });
        }
    }
    value["runtimes"]
        .as_array_mut()
        .ok_or_else(|| invalid_aggregate("aggregate runtimes are absent"))?
        .sort_by(|left, right| {
            string_field(left, "runtime_id").cmp(string_field(right, "runtime_id"))
        });
    let digest = aggregate_digest(&value)?;
    value["aggregate_state_digest"] = json!(digest);
    Ok(value)
}

fn aggregate_digest(value: &JsonValue) -> Result<String, Version2Error> {
    let mut unsigned = value.clone();
    aggregate_object_mut(&mut unsigned)?.remove("aggregate_state_digest");
    wire::jcs_hash(&json!(["determa-aggregate-state-digest-2", unsigned])).map_err(map_persistence)
}

pub(crate) fn envelope_digest(
    root_instance_id: &str,
    delivery_mode: &str,
    envelope: &QueueEnvelope,
) -> Result<String, Version2Error> {
    wire::jcs_hash(&json!([
        "determa-inbox-envelope-digest-2",
        "2",
        root_instance_id,
        delivery_mode,
        envelope
    ]))
    .map_err(map_persistence)
}

fn core_delivery(delivery: &AdmissionDelivery) -> Result<Delivery, Version2Error> {
    let payload = delivery
        .envelope
        .payload
        .to_value(None)
        .map_err(map_persistence)?;
    let crate::value::Value::Map(payload) = payload else {
        return Err(Version2Error::new(
            "invalid_payload",
            "queue payload is not a typed map",
        ));
    };
    let envelope = Envelope {
        event: delivery.envelope.event.clone(),
        event_id: delivery.envelope.event_id.clone(),
        target: queue_target_to_core(&delivery.envelope.target)?,
        payload,
        correlation_id: delivery.envelope.correlation_id.clone(),
    };
    match delivery.delivery_mode.as_str() {
        "input" => Ok(Delivery::Input(envelope)),
        "internal" => Ok(Delivery::Internal(envelope)),
        _ => Err(Version2Error::new(
            "invalid_delivery_mode",
            "invalid delivery mode",
        )),
    }
}

fn validate_source(
    delivery: &AdmissionDelivery,
    aggregate: &JsonValue,
) -> Result<(), Version2Error> {
    let source =
        delivery.envelope.source.as_object().ok_or_else(|| {
            Version2Error::new("invalid_delivery_source", "source must be an object")
        })?;
    let host = source.len() == 1 && source.get("host").and_then(JsonValue::as_bool) == Some(true);
    if delivery.delivery_mode == "input" {
        if !host || delivery.envelope.cause_id != delivery.envelope.event_id {
            return Err(Version2Error::new(
                "invalid_delivery_source",
                "input must be host-sourced with cause equal to event id",
            ));
        }
    } else if delivery.delivery_mode == "internal" {
        let valid = if let Some(runtime) = source.get("runtime").filter(|_| source.len() == 1) {
            runtimes(aggregate)?
                .iter()
                .any(|candidate| candidate["target_identity"] == *runtime)
        } else if let Some(locator) = source
            .get("system")
            .and_then(JsonValue::as_str)
            .filter(|_| source.len() == 1)
        {
            system_locator_matches_event(locator, &delivery.envelope.event)
        } else {
            false
        };
        if !valid || !valid_internal_source_shape(source) {
            return Err(Version2Error::new(
                "invalid_delivery_source",
                "internal delivery provenance is invalid",
            ));
        }
    }
    Ok(())
}

fn system_locator_matches_event(locator: &str, event: &str) -> bool {
    matches!(
        (locator, event),
        (
            "system:component_completion",
            "determa.component_completed" | "done"
        ) | ("system:spawned_completion", "done")
            | ("system:component_failure", "determa.component_failed")
            | ("system:spawned_failure", "determa.spawned_instance_failed")
    )
}

fn valid_internal_source_shape(source: &serde_json::Map<String, JsonValue>) -> bool {
    if source.len() != 1 {
        return false;
    }
    match source
        .iter()
        .next()
        .map(|(key, value)| (key.as_str(), value))
    {
        Some(("runtime", value)) => value.as_object().is_some(),
        Some(("system", value)) => value
            .as_str()
            .is_some_and(|locator| locator.starts_with("system:") && locator.len() > 7),
        Some(("legacy_v1_internal", value)) => value.as_object().is_some_and(|legacy| {
            legacy.len() == 2
                && legacy
                    .get("producing_receipt_sequence")
                    .and_then(JsonValue::as_str)
                    .is_some()
                && legacy
                    .get("emission_index")
                    .and_then(JsonValue::as_str)
                    .is_some()
        }),
        _ => false,
    }
}

fn validate_aggregate_schema(value: &JsonValue) -> Result<(), Version2Error> {
    let schema: JsonValue =
        serde_json::from_str(include_str!("../../schema/aggregate-state-v2.schema.json"))
            .expect("bundled aggregate v2 schema is valid");
    let base: JsonValue =
        serde_json::from_str(include_str!("../../schema/aggregate-state.schema.json"))
            .expect("bundled aggregate v1 schema is valid");
    let resource = jsonschema::Resource::from_contents(base)
        .map_err(|error| invalid_aggregate(error.to_string()))?;
    let validator = jsonschema::options()
        .with_resource(
            "https://determa.dev/state/schema/aggregate-state.schema.json",
            resource,
        )
        .build(&schema)
        .map_err(|error| invalid_aggregate(error.to_string()))?;
    validator
        .validate(value)
        .map_err(|error| invalid_aggregate(error.to_string()))
}

pub(crate) fn validate_v2_schema(
    value: &JsonValue,
    schema_source: &str,
    resources: &[(&str, &str)],
    code: &str,
) -> Result<(), Version2Error> {
    let schema: JsonValue = serde_json::from_str(schema_source)
        .map_err(|error| Version2Error::new(code, error.to_string()))?;
    let mut options = jsonschema::options();
    for (uri, source) in resources {
        let resource_value: JsonValue = serde_json::from_str(source)
            .map_err(|error| Version2Error::new(code, error.to_string()))?;
        let resource = jsonschema::Resource::from_contents(resource_value)
            .map_err(|error| Version2Error::new(code, error.to_string()))?;
        options = options.with_resource((*uri).to_string(), resource);
    }
    let validator = options
        .build(&schema)
        .map_err(|error| Version2Error::new(code, error.to_string()))?;
    validator
        .validate(value)
        .map_err(|error| Version2Error::new(code, error.to_string()))
}

fn validate_mailbox_integrity(value: &JsonValue) -> Result<(), Version2Error> {
    let next_acceptance = counter_value(value, "next_acceptance_sequence")?;
    let next_queue = counter_value(value, "next_queue_sequence")?;
    let mut event_ids = BTreeSet::new();
    let mut acceptances = BTreeSet::new();
    let mut queues = BTreeSet::new();
    for runtime in runtimes(value)? {
        for field in ["ready_mailbox", "deferred_mailbox"] {
            let mut previous = None;
            for entry in runtime[field]
                .as_array()
                .ok_or_else(|| invalid_aggregate("mailbox is not an array"))?
            {
                let acceptance = counter_value(entry, "acceptance_sequence")?;
                let queue = counter_value(entry, "queue_sequence")?;
                if previous.as_ref().is_some_and(|prior| prior >= &queue)
                    || acceptance >= next_acceptance
                    || queue >= next_queue
                {
                    return Err(invalid_aggregate("mailbox counter ordering is invalid"));
                }
                previous = Some(queue.clone());
                let event_id = entry["envelope"]["event_id"]
                    .as_str()
                    .ok_or_else(|| invalid_aggregate("mailbox event id is absent"))?;
                if !event_ids.insert(event_id.to_string())
                    || !acceptances.insert(acceptance)
                    || !queues.insert(queue)
                {
                    return Err(invalid_aggregate("mailbox identities are not unique"));
                }
                let envelope: QueueEnvelope = serde_json::from_value(entry["envelope"].clone())
                    .map_err(|error| invalid_aggregate(error.to_string()))?;
                let mode = entry["delivery_mode"]
                    .as_str()
                    .ok_or_else(|| invalid_aggregate("delivery mode is absent"))?;
                let expected =
                    envelope_digest(aggregate_root_instance_id(value)?, mode, &envelope)?;
                if entry["envelope_digest"].as_str() != Some(expected.as_str()) {
                    return Err(invalid_aggregate(
                        "mailbox envelope digest does not match content",
                    ));
                }
            }
        }
    }
    Ok(())
}

fn validate_mailbox_semantics(
    value: &JsonValue,
    state: &AggregateState,
    resolver: &(impl DefinitionResolver + ?Sized),
) -> Result<(), Version2Error> {
    for runtime_value in runtimes(value)? {
        let runtime_id = runtime_value["runtime_id"]
            .as_str()
            .ok_or_else(|| invalid_aggregate("mailbox runtime id is absent"))?;
        let runtime = runtime_by_id(&state.root, runtime_id)
            .ok_or_else(|| invalid_aggregate("mailbox runtime is absent from restored state"))?;
        let fingerprint = &runtime.current_definition.validated_bundle_fingerprint;
        let resolved = resolver.resolve_definition(fingerprint).ok_or_else(|| {
            invalid_aggregate("mailbox target definition is unavailable during restore")
        })?;
        if !resolved.trusted || resolved.bundle.fingerprint != *fingerprint {
            return Err(invalid_aggregate(
                "mailbox target definition is untrusted or content-addressed incorrectly",
            ));
        }
        for field in ["ready_mailbox", "deferred_mailbox"] {
            for entry in runtime_value[field]
                .as_array()
                .ok_or_else(|| invalid_aggregate("mailbox is not an array"))?
            {
                let envelope: QueueEnvelope = serde_json::from_value(entry["envelope"].clone())
                    .map_err(|error| invalid_aggregate(error.to_string()))?;
                let mode = entry["delivery_mode"]
                    .as_str()
                    .ok_or_else(|| invalid_aggregate("delivery mode is absent"))?;
                if queue_target_to_core(&envelope.target)? != runtime.target_identity {
                    return Err(invalid_aggregate(
                        "mailbox target does not identify its containing runtime",
                    ));
                }
                validate_restored_source(mode, &envelope, value)?;
                let delivery = core_delivery(&AdmissionDelivery {
                    delivery_mode: mode.to_string(),
                    envelope,
                    envelope_digest: entry["envelope_digest"]
                        .as_str()
                        .ok_or_else(|| invalid_aggregate("mailbox digest is absent"))?
                        .to_string(),
                })?;
                validate_queued_event_for_migration(&resolved.bundle, state, &delivery).map_err(
                    |code| {
                        invalid_aggregate(format!(
                            "mailbox delivery is invalid against its resolved definition: {}",
                            code.as_str()
                        ))
                    },
                )?;
            }
        }
    }
    Ok(())
}

fn validate_restored_source(
    delivery_mode: &str,
    envelope: &QueueEnvelope,
    aggregate: &JsonValue,
) -> Result<(), Version2Error> {
    let source = envelope
        .source
        .as_object()
        .ok_or_else(|| invalid_aggregate("mailbox source must be an object"))?;
    let valid = match delivery_mode {
        "input" => {
            source.len() == 1
                && source.get("host").and_then(JsonValue::as_bool) == Some(true)
                && envelope.cause_id == envelope.event_id
        }
        "internal" => {
            if let Some(runtime_source) = source.get("runtime").filter(|_| source.len() == 1) {
                runtimes(aggregate)?
                    .iter()
                    .any(|runtime| runtime["target_identity"] == *runtime_source)
                    && envelope.cause_id != envelope.event_id
            } else if let Some(locator) = source
                .get("system")
                .and_then(JsonValue::as_str)
                .filter(|_| source.len() == 1)
            {
                system_locator_matches_event(locator, &envelope.event)
                    && envelope.cause_id != envelope.event_id
            } else if source
                .get("legacy_v1_internal")
                .filter(|_| source.len() == 1)
                .is_some()
            {
                valid_internal_source_shape(source) && envelope.cause_id == envelope.event_id
            } else {
                false
            }
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(invalid_aggregate("mailbox source provenance is invalid"))
    }
}

fn append_internal_emissions(
    aggregate: &mut QueueBearingAggregate,
    emissions: &[Emission],
) -> Result<(Vec<JsonValue>, Vec<JsonValue>), Version2Error> {
    let before = aggregate.value.clone();
    let mut lifecycle = Vec::new();
    let references =
        append_step_emissions(&mut aggregate.value, &before, emissions, &mut lifecycle)?;
    Ok((references, lifecycle))
}

fn map_dispatch_rejection(code: DispatchRejectionCode) -> Version2Error {
    Version2Error::new(code.as_str(), "delivery is not admissible")
}

fn map_persistence(error: super::wire::PersistenceError) -> Version2Error {
    Version2Error::new(error.code.as_str(), error.message)
}

fn invalid_aggregate(message: impl Into<String>) -> Version2Error {
    Version2Error::new(
        PersistenceErrorCode::InvalidAggregateState.as_str(),
        message,
    )
}

pub(crate) fn canonical_bytes(value: &JsonValue) -> Result<Vec<u8>, Version2Error> {
    wire::canonical_bytes(value)
        .map_err(|error| Version2Error::new("invalid_aggregate_state", error.to_string()))
}

fn aggregate_object(value: &JsonValue) -> Result<&Map<String, JsonValue>, Version2Error> {
    value
        .as_object()
        .ok_or_else(|| invalid_aggregate("aggregate state must be an object"))
}

fn aggregate_object_mut(
    value: &mut JsonValue,
) -> Result<&mut Map<String, JsonValue>, Version2Error> {
    value
        .as_object_mut()
        .ok_or_else(|| invalid_aggregate("aggregate state must be an object"))
}

fn runtimes(value: &JsonValue) -> Result<&Vec<JsonValue>, Version2Error> {
    value["runtimes"]
        .as_array()
        .ok_or_else(|| invalid_aggregate("aggregate runtimes are absent"))
}

fn runtimes_mut(value: &mut JsonValue) -> Result<&mut Vec<JsonValue>, Version2Error> {
    value["runtimes"]
        .as_array_mut()
        .ok_or_else(|| invalid_aggregate("aggregate runtimes are absent"))
}

fn runtime_object_mut<'a>(
    value: &'a mut JsonValue,
    runtime_id: &str,
) -> Result<&'a mut Map<String, JsonValue>, Version2Error> {
    runtimes_mut(value)?
        .iter_mut()
        .find(|runtime| runtime["runtime_id"].as_str() == Some(runtime_id))
        .and_then(JsonValue::as_object_mut)
        .ok_or_else(|| invalid_aggregate("target runtime is absent"))
}

fn aggregate_root_instance_id(value: &JsonValue) -> Result<&str, Version2Error> {
    value["root_instance_id"]
        .as_str()
        .ok_or_else(|| invalid_aggregate("root instance id is absent"))
}

fn aggregate_status(value: &JsonValue) -> Result<&str, Version2Error> {
    let root_id = value["root_runtime_id"]
        .as_str()
        .ok_or_else(|| invalid_aggregate("root runtime id is absent"))?;
    runtimes(value)?
        .iter()
        .find(|runtime| runtime["runtime_id"].as_str() == Some(root_id))
        .and_then(|runtime| runtime["status"].as_str())
        .ok_or_else(|| invalid_aggregate("root runtime status is absent"))
}

fn allocate_counter(value: &mut JsonValue, field: &str) -> Result<Counter, Version2Error> {
    let current = counter_value(value, field)?;
    let mut next = current.clone();
    next.allocate();
    value[field] = json!(next.to_string());
    Ok(current)
}

fn counter_value(value: &JsonValue, field: &str) -> Result<Counter, Version2Error> {
    Counter::from_decimal(
        value[field]
            .as_str()
            .ok_or_else(|| invalid_aggregate(format!("{field} is absent")))?,
    )
    .map_err(invalid_aggregate)
}

fn counter_field(value: &JsonValue, field: &str) -> Counter {
    Counter::from_decimal(value[field].as_str().expect("validated counter"))
        .expect("validated counter")
}

fn string_field<'a>(value: &'a JsonValue, field: &str) -> &'a [u8] {
    value[field].as_str().expect("validated string").as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mailbox_bundle() -> Bundle {
        super::super::load_bundle(
            r#"
format: 1
namespace: test.v2_restore_mailbox
events:
  request_sent: { direction: output }
  request:
    direction: input
    correlates_to: request_sent
    payload:
      amount: { type: float, required: true }
      request_id: { type: string, required: true }
  internal_notice: { direction: internal }
machines:
  - machine_id: worker
    root:
      on_events:
        request: {}
        internal_notice: {}
"#,
        )
        .expect("mailbox semantic test bundle")
    }

    fn aggregate_with_input_mailbox(bundle: &Bundle) -> JsonValue {
        let aggregate = create_v2(
            bundle,
            "worker",
            "restore-root",
            "restore-create",
            &Bindings::default(),
        )
        .expect("create queue-bearing aggregate");
        let target = aggregate.value()["runtimes"][0]["target_identity"].clone();
        let envelope = QueueEnvelope {
            event: "request".to_string(),
            event_id: "request-1".to_string(),
            cause_id: "request-1".to_string(),
            source: json!({"host": true}),
            target,
            payload: TypedValue::Map(vec![
                ("amount".to_string(), TypedValue::Float(1.0)),
                (
                    "request_id".to_string(),
                    TypedValue::String("request-1".to_string()),
                ),
            ]),
            correlation_id: Some("request-1".to_string()),
        };
        let digest = envelope_digest("restore-root", "input", &envelope).unwrap();
        let result = admit_v2(
            bundle,
            &aggregate,
            &[AdmissionDelivery {
                delivery_mode: "input".to_string(),
                envelope,
                envelope_digest: digest,
            }],
        )
        .expect("admit semantic test delivery");
        result["state"].clone()
    }

    fn assert_resealed_mailbox_rejected(
        source: &JsonValue,
        bundle: &Bundle,
        mutate: impl FnOnce(&mut JsonValue),
    ) {
        let mut forged = source.clone();
        let root_instance_id = forged["root_instance_id"].as_str().unwrap().to_string();
        let entry = &mut forged["runtimes"][0]["ready_mailbox"][0];
        mutate(entry);
        let envelope: QueueEnvelope = serde_json::from_value(entry["envelope"].clone())
            .unwrap_or_else(|error| panic!("forged envelope schema: {error}; {entry}"));
        entry["envelope_digest"] = json!(envelope_digest(
            &root_instance_id,
            entry["delivery_mode"].as_str().unwrap(),
            &envelope
        )
        .unwrap());
        forged = seal_aggregate(forged).unwrap();
        let mut resolver = InMemoryDefinitionResolver::default();
        resolver.insert(bundle.clone(), true);
        let bytes = canonical_bytes(&forged).unwrap();
        assert_eq!(
            restore_aggregate_v2(&bytes, &resolver).unwrap_err().code,
            "invalid_aggregate_state"
        );
    }

    #[test]
    fn restore_rejects_resealed_mailboxes_invalid_against_resolved_definition() {
        let bundle = mailbox_bundle();
        let aggregate = aggregate_with_input_mailbox(&bundle);

        assert_resealed_mailbox_rejected(&aggregate, &bundle, |entry| {
            entry["delivery_mode"] = json!("internal");
            entry["envelope"]["source"] = json!({"runtime": entry["envelope"]["target"].clone()});
            entry["envelope"]["cause_id"] = json!("request-cause");
        });
        assert_resealed_mailbox_rejected(&aggregate, &bundle, |entry| {
            entry["delivery_mode"] = json!("internal");
            entry["envelope"]["event"] = json!("internal_notice");
            entry["envelope"]["payload"] = json!(["map", []]);
            entry["envelope"]
                .as_object_mut()
                .unwrap()
                .remove("correlation_id");
            entry["envelope"]["source"] = json!({"runtime": {"root": {
                "root_instance_id": "restore-root",
                "root_runtime_id": "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            }}});
            entry["envelope"]["cause_id"] = json!("request-cause");
        });
        assert_resealed_mailbox_rejected(&aggregate, &bundle, |entry| {
            entry["delivery_mode"] = json!("internal");
            entry["envelope"]["event"] = json!("internal_notice");
            entry["envelope"]["payload"] = json!(["map", []]);
            entry["envelope"]
                .as_object_mut()
                .unwrap()
                .remove("correlation_id");
            entry["envelope"]["source"] = json!({"system": "system:component_completion"});
            entry["envelope"]["cause_id"] = json!("request-cause");
        });
        assert_resealed_mailbox_rejected(&aggregate, &bundle, |entry| {
            entry["envelope"]["payload"][1]
                .as_array_mut()
                .unwrap()
                .retain(|field| field[0] != "request_id");
        });
        assert_resealed_mailbox_rejected(&aggregate, &bundle, |entry| {
            entry["envelope"]["payload"][1]
                .as_array_mut()
                .unwrap()
                .push(json!(["unexpected", ["string", "value"]]));
        });
        assert_resealed_mailbox_rejected(&aggregate, &bundle, |entry| {
            entry["envelope"]["payload"][1][0][1] = json!(["integer", "1"]);
        });
        assert_resealed_mailbox_rejected(&aggregate, &bundle, |entry| {
            entry["envelope"]
                .as_object_mut()
                .unwrap()
                .remove("correlation_id");
        });
    }
}
