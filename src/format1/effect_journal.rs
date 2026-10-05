//! Semantic checkpoint/journal pairing. Content validation does not activate an
//! imported participant or prove worker authority, native storage or call fate.

use super::{model::EventDirection, native, DefinitionResolver, TypedValue};
use crate::checkpoint::ExecutionCheckpoint;
use num_bigint::BigUint;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug)]
pub struct EffectJournalError(String);
impl std::fmt::Display for EffectJournalError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}
impl std::error::Error for EffectJournalError {}
fn failure(error: impl std::fmt::Display) -> EffectJournalError {
    EffectJournalError(error.to_string())
}
fn require(condition: bool, reason: &str) -> Result<(), EffectJournalError> {
    if condition {
        Ok(())
    } else {
        Err(failure(reason))
    }
}
fn array<'a>(value: &'a Value, field: &str) -> Result<&'a [Value], EffectJournalError> {
    value[field]
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| failure(format!("{field} absent")))
}
fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str, EffectJournalError> {
    value[field]
        .as_str()
        .ok_or_else(|| failure(format!("{field} absent")))
}
fn hash(value: &Value) -> Result<String, EffectJournalError> {
    native::jcs_hash(value).map_err(failure)
}
fn ordered_unique(values: &[Value], field: &str) -> Result<(), EffectJournalError> {
    let mut previous: Option<&str> = None;
    for value in values {
        let current = text(value, field)?;
        require(
            previous.is_none_or(|prior| prior.as_bytes() < current.as_bytes()),
            "unordered or duplicate identity",
        )?;
        previous = Some(current);
    }
    Ok(())
}

/// Immutable content validated with its exact checkpoint and retained response
/// bodies. Response hashes prove content integrity only, never public replay
/// admissibility. This type is never an authority or native participant credential.
#[derive(Clone)]
pub struct ValidatedEffectJournal {
    value: Value,
    responses: BTreeMap<String, Value>,
}
impl ValidatedEffectJournal {
    pub fn value(&self) -> &Value {
        &self.value
    }
    pub fn retained_responses(&self) -> &BTreeMap<String, Value> {
        &self.responses
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EffectJournalError> {
        serde_json_canonicalizer::to_vec(&self.value).map_err(failure)
    }
    pub fn restore(
        source: &[u8],
        checkpoint: &ExecutionCheckpoint,
        scope: &str,
        responses: &BTreeMap<String, Value>,
        resolver: &(impl DefinitionResolver + ?Sized),
    ) -> Result<Self, EffectJournalError> {
        let journal = super::validate_contract_artifact("host_effect_journal_v1", source, resolver)
            .map_err(failure)?;
        let mut unsigned = journal.clone();
        unsigned
            .as_object_mut()
            .ok_or_else(|| failure("journal is not an object"))?
            .remove("host_effect_journal_digest");
        require(
            !scope.is_empty()
                && journal["scope_identity"] == scope
                && journal["root_instance_id"] == checkpoint.root_instance_id()
                && journal["checkpoint_revision"] == checkpoint.revision()
                && journal["checkpoint_digest"] == checkpoint.digest()
                && journal["host_effect_journal_digest"]
                    == hash(&json!(["determa-host-effect-journal-digest-1", unsigned]))?,
            "torn checkpoint/journal or unequal digest",
        )?;
        let records = array(&journal, "effect_records")?;
        ordered_unique(records, "effect_id")?;
        let references = array(&journal, "operation_response_references")?;
        ordered_unique(references, "operation_id")?;
        require(
            references.len() == responses.len(),
            "retained response inventory mismatch",
        )?;
        for reference in references {
            let response = responses
                .get(text(reference, "operation_id")?)
                .ok_or_else(|| failure("complete retained response absent"))?;
            require(
                reference["response_digest"]
                    == hash(&json!(["determa-host-operation-response-1", response]))?,
                "retained response digest mismatch",
            )?;
        }
        for record in records {
            validate_record(checkpoint, record, resolver)?;
        }
        Ok(Self {
            value: journal,
            responses: responses.clone(),
        })
    }
}

fn validate_record(
    checkpoint: &ExecutionCheckpoint,
    record: &Value,
    resolver: &(impl DefinitionResolver + ?Sized),
) -> Result<(), EffectJournalError> {
    let effect = text(record, "effect_id")?;
    let value = checkpoint.value();
    let mut locations = Vec::new();
    for field in ["pending_outbox_intents", "terminal_outbox_records"] {
        for item in array(value, field)? {
            if item["intent"]["effect_id"] == effect {
                locations.push(hash(&json!([
                    "determa-outbox-intent-digest-1",
                    "1",
                    checkpoint.root_instance_id(),
                    item["intent"]
                ]))?);
            }
        }
    }
    for item in array(value, "outbox_effect_tombstones")? {
        if item["effect_id"] == effect {
            locations.push(text(item, "intent_digest")?.to_owned());
        }
    }
    require(
        locations.len() == 1 && record["intent_digest"] == locations[0],
        "dangling or duplicate intent",
    )?;
    let reports = array(record, "attempt_records")?;
    let fence: BigUint = text(record, "attempt_fence")?.parse().map_err(failure)?;
    let mut previous: Option<BigUint> = None;
    for report in reports {
        let current: BigUint = text(report, "attempt_fence")?.parse().map_err(failure)?;
        require(
            current != BigUint::from(0u8)
                && current <= fence
                && previous.as_ref().is_none_or(|prior| prior < &current),
            "invalid attempt report order/fence",
        )?;
        previous = Some(current);
    }
    let state = text(record, "invocation_state")?;
    let current_report = reports
        .iter()
        .find(|item| item["attempt_fence"] == record["attempt_fence"]);
    let terminal_reports: Vec<_> = reports
        .iter()
        .filter(|item| {
            matches!(
                item["report_kind"].as_str(),
                Some("succeeded" | "domain_rejected" | "terminal_failure" | "cancelled")
            )
        })
        .collect();
    require(
        terminal_reports.len() <= 1,
        "terminal attempt cannot be superseded",
    )?;
    require(
        !matches!(state, "leased" | "ambiguous") || fence != BigUint::from(0u8),
        "active invocation has zero fence",
    )?;
    require(
        !matches!(state, "unclaimed" | "leased" | "ambiguous") || terminal_reports.is_empty(),
        "terminal report cannot become retryable work",
    )?;
    require(
        state != "unclaimed" || fence == BigUint::from(0u8) || current_report.is_some(),
        "safe retry report absent",
    )?;
    if let Some(report) = current_report {
        require(
            state != "leased"
                && (state != "unclaimed" || report["report_kind"] == "retryable_failure")
                && (state != "ambiguous" || report["report_kind"] == "ambiguous"),
            "attempt report contradicts invocation state",
        )?;
    }
    let outcome = &record["outcome"];
    if record["cancellation"]["state"] == "prevented_start" {
        require(
            matches!(state, "outcome_recorded" | "result_admitted" | "closed")
                && fence == BigUint::from(0u8)
                && reports.is_empty()
                && outcome["kind"] == "cancelled"
                && outcome["attempt_fence"] == "0",
            "prevented start requires preclaim cancelled outcome",
        )?;
    }
    let result_id = &record["result_event_id"];
    let receipt = &record["admission_receipt"];
    match state {
        "unclaimed" | "leased" | "ambiguous" => require(
            outcome.is_null() && result_id.is_null() && receipt.is_null(),
            "nonterminal invocation has terminal evidence",
        )?,
        "outcome_recorded" => require(
            !outcome.is_null() && !result_id.is_null() && receipt.is_null(),
            "recorded outcome has invalid admission evidence",
        )?,
        "result_admitted" | "closed" => require(
            !outcome.is_null()
                && !result_id.is_null()
                && !receipt.is_null()
                && receipt["event_id"] == *result_id
                && array(value, "operation_receipts")?.contains(receipt),
            "admission receipt absent or not retained",
        )?,
        _ => return Err(failure("unknown invocation state")),
    }
    let (target, bundle, machine_pointer) = pinned_target(checkpoint, record, resolver)?;
    let machine = native::find_machine_by_root_pointer(&bundle, &machine_pointer)
        .ok_or_else(|| failure("pinned machine absent"))?;
    let mappings = array(record, "result_mapping")?;
    validate_result_mappings(&bundle, machine, mappings)?;
    if outcome.is_null() {
        return Ok(());
    }
    require(
        outcome["attempt_fence"] == record["attempt_fence"],
        "outcome fence differs from current attempt",
    )?;
    require(
        outcome["digest"]
            == hash(&json!([
                "determa-effect-outcome-1",
                record["effect_id"],
                record["operation_token"],
                outcome["kind"],
                outcome["payload"],
                outcome["attempt_fence"]
            ]))?,
        "outcome digest mismatch",
    )?;
    let mapping = mappings
        .iter()
        .find(|mapping| mapping["outcome_kind"] == outcome["kind"])
        .ok_or_else(|| failure("terminal result mapping absent"))?;
    require(
        *result_id
            == hash(&json!([
                "determa-effect-result-event-1",
                record["effect_id"],
                mapping["result_slot"]
            ]))?,
        "result event identity mismatch",
    )?;
    let preclaim_cancel = outcome["kind"] == "cancelled"
        && outcome["attempt_fence"] == "0"
        && record["attempt_fence"] == "0"
        && record["cancellation"]["state"] == "prevented_start";
    if preclaim_cancel {
        require(
            reports.is_empty(),
            "preclaim cancellation has attempt reports",
        )?;
    } else {
        let report = reports
            .iter()
            .find(|report| report["attempt_fence"] == outcome["attempt_fence"])
            .ok_or_else(|| failure("immutable outcome attempt report absent"))?;
        require(
            report["report_kind"] == outcome["kind"]
                && report["report_digest"]
                    == hash(&json!([
                        "determa-effect-attempt-report-1",
                        record["effect_id"],
                        record["operation_token"],
                        outcome["attempt_fence"],
                        outcome["kind"],
                        outcome["payload"],
                        report["reason"]
                    ]))?,
            "outcome attempt report mismatch",
        )?;
    }
    let mut payload: TypedValue =
        serde_json::from_value(outcome["payload"].clone()).map_err(failure)?;
    if mapping["operation_token_location"]["kind"] == "payload" {
        let pointer = text(&mapping["operation_token_location"], "pointer")?;
        let key = pointer[1..].replace("~1", "/").replace("~0", "~");
        let TypedValue::Map(fields) = &mut payload else {
            return Err(failure("result payload is not a declared map"));
        };
        let existing = fields.iter_mut().find(|(name, _)| *name == key);
        if let Some((_, supplied)) = existing {
            require(
                matches!(supplied, TypedValue::String(_)),
                "result token payload is not a string",
            )?;
            *supplied = TypedValue::String(text(record, "operation_token")?.to_owned());
        } else {
            fields.push((
                key,
                TypedValue::String(text(record, "operation_token")?.to_owned()),
            ));
            fields.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
        }
    }
    let crate::value::Value::Map(logical) = payload.to_value(None).map_err(failure)? else {
        return Err(failure("result payload is not a declared map"));
    };
    let event = text(mapping, "event")?;
    let declaration = machine
        .events
        .get(event)
        .or_else(|| bundle.events.get(event))
        .ok_or_else(|| failure("undeclared result event"))?;
    let logical = super::runtime::normalize_payload(declaration, &logical)
        .map_err(|_| failure("invalid declared result payload"))?;
    let payload = TypedValue::from_value(&crate::value::Value::Map(logical));
    let mut envelope = json!({"event":mapping["event"],"event_id":result_id,"cause_id":result_id,"source":{"host":true},"target":target,"payload":payload});
    if mapping["operation_token_location"]["kind"] == "correlation_id" {
        envelope["correlation_id"] = record["operation_token"].clone();
    }
    if matches!(state, "result_admitted" | "closed") {
        require(
            receipt["operation_kind"] == "acceptance"
                && receipt["delivery_mode"] == "input"
                && receipt["request_digest"]
                    == hash(&json!([
                        "determa-inbox-envelope-digest-1",
                        "1",
                        checkpoint.root_instance_id(),
                        "input",
                        envelope
                    ]))?,
            "retained acceptance does not bind exact pinned result",
        )?;
    }
    Ok(())
}

fn pinned_target(
    checkpoint: &ExecutionCheckpoint,
    record: &Value,
    resolver: &(impl DefinitionResolver + ?Sized),
) -> Result<(Value, super::Bundle, String), EffectJournalError> {
    let target = &record["target"];
    let origin = &target["runtime_incarnation"];
    let definition = &origin["definition"];
    let identity = &definition["machine"];
    let root = checkpoint.root_instance_id();
    require(
        target["root_instance_id"] == root,
        "pinned target belongs to another root",
    )?;
    let fingerprint = text(definition, "validated_bundle_fingerprint")?;
    let resolved = resolver
        .resolve_definition(fingerprint)
        .ok_or_else(|| failure("pinned definition unavailable"))?;
    require(
        resolved.trusted && resolved.bundle.fingerprint == fingerprint,
        "pinned definition untrusted or content-address mismatch",
    )?;
    let pointer = text(identity, "root_definition_pointer")?;
    let machine = native::find_machine_by_root_pointer(&resolved.bundle, pointer)
        .ok_or_else(|| failure("pinned machine pointer unavailable"))?;
    let machine_version = machine.version.to_string();
    require(
        identity["namespace"] == resolved.bundle.namespace
            && identity["machine_id"] == machine.machine_id
            && identity["machine_version"].as_str() == Some(machine_version.as_str()),
        "pinned machine identity mismatch",
    )?;
    let runtime = text(target, "runtime_id")?;
    let (expected, envelope_target) = match text(origin, "kind")? {
        "root" => {
            let retained = &checkpoint.value()["root_record"];
            let root_runtime = if retained["status"] == "tombstone" {
                &retained["root_runtime_id"]
            } else {
                &retained["aggregate_state"]["root_runtime_id"]
            };
            require(
                origin["root_instance_id"] == root && root_runtime == runtime,
                "pinned root origin mismatch",
            )?;
            (
                hash(&json!([
                    "determa-root-runtime-identity-1",
                    "1",
                    fingerprint,
                    identity["namespace"],
                    identity["machine_id"],
                    identity["machine_version"],
                    root
                ]))?,
                json!({"root":{"root_instance_id":root,"root_runtime_id":runtime}}),
            )
        }
        "component" => {
            let placement_pointer = text(origin, "component_definition_pointer")?;
            let placement = resolved
                .bundle
                .normalized
                .pointer(placement_pointer)
                .ok_or_else(|| failure("pinned component placement unavailable"))?;
            require(
                origin["declaration_index"] == placement_pointer.rsplit('/').next().unwrap_or(""),
                "component declaration index mismatch",
            )?;
            let component = text(placement, "component_id")?;
            (
                hash(&json!([
                    "determa-component-runtime-identity-1",
                    "1",
                    root,
                    origin["owner_runtime_id"],
                    origin["component_definition_pointer"],
                    origin["activation_sequence"],
                    identity["namespace"],
                    identity["machine_id"],
                    identity["machine_version"]
                ]))?,
                json!({"component":{"root_instance_id":root,"owner_runtime_id":origin["owner_runtime_id"],"component_id":component,"component_runtime_id":runtime,"activation_sequence":origin["activation_sequence"]}}),
            )
        }
        "owned_spawned_instance" => (
            hash(&json!([
                "determa-spawned-runtime-identity-1",
                "1",
                root,
                origin["owner_runtime_id"],
                origin["spawn_action_pointer"],
                origin["spawn_sequence"],
                identity["namespace"],
                identity["machine_id"],
                identity["machine_version"]
            ]))?,
            json!({"spawned_instance":{"root_instance_id":root,"instance_id":runtime,"machine_id":identity["machine_id"],"machine_version":identity["machine_version"]}}),
        ),
        _ => return Err(failure("unknown pinned runtime kind")),
    };
    require(expected == runtime, "pinned runtime identity mismatch")?;
    // An extant target must agree with its independently reconstructed original
    // incarnation. Historical results use the original target, never an alias.
    if let Some(runtimes) =
        checkpoint.value()["root_record"]["aggregate_state"]["runtimes"].as_array()
    {
        if let Some(retained) = runtimes.iter().find(|item| item["runtime_id"] == runtime) {
            require(
                retained["identity_origin"] == *origin
                    && retained["target_identity"] == envelope_target,
                "retained target disagrees with pinned incarnation",
            )?;
        }
    }
    let pointer = pointer.to_owned();
    Ok((envelope_target, resolved.bundle, pointer))
}

/// Resolve and validate the complete route before producing core actions.
/// Empty outboxes cannot waive configuration checks.
pub(crate) fn validate_route_mapping(
    bundle: &super::Bundle,
    machine_id: &str,
    mappings: &Value,
) -> Result<(), EffectJournalError> {
    let machine = bundle
        .machines
        .get(machine_id)
        .ok_or_else(|| failure("route root machine absent"))?;
    let mappings = mappings
        .as_array()
        .ok_or_else(|| failure("result mappings are not an array"))?;
    validate_result_mappings(bundle, machine, mappings)
}

fn validate_result_mappings(
    bundle: &super::Bundle,
    machine: &super::compile::Machine,
    mappings: &[Value],
) -> Result<(), EffectJournalError> {
    let mut kinds = BTreeSet::new();
    let mut slots = BTreeSet::new();
    for mapping in mappings {
        super::contracts::validate_effect_result_mapping(mapping).map_err(failure)?;
        require(
            kinds.insert(text(mapping, "outcome_kind")?)
                && slots.insert(text(mapping, "result_slot")?),
            "duplicate result mapping kind/slot",
        )?;
        let declaration = machine
            .events
            .get(text(mapping, "event")?)
            .or_else(|| bundle.events.get(mapping["event"].as_str().unwrap()))
            .ok_or_else(|| failure("undeclared result event"))?;
        require(
            declaration.direction == EventDirection::Input,
            "result event is not declared input",
        )?;
        let location = &mapping["operation_token_location"];
        if location["kind"] == "payload" {
            // Format1 declared payload fields are flat. A pointer into a nested
            // map cannot establish a declared string slot.
            let name = text(location, "pointer")?
                .strip_prefix('/')
                .ok_or_else(|| failure("token pointer must name a declared field"))?;
            require(
                !name.contains('/'),
                "token pointer does not name a declared string field",
            )?;
            let name = name.replace("~1", "/").replace("~0", "~");
            require(
                declaration
                    .payload
                    .get(&name)
                    .is_some_and(|field| field.value_type == "string"),
                "token slot is not a declared string",
            )?;
        }
    }
    Ok(())
}

/// Native retained source evidence keeps integer/float distinctions in canonical
/// storage. It grants no executable provider, resolver trust or imported authority.
#[cfg(feature = "sqlite")]
pub(crate) fn native_definition_evidence(bundle: &super::Bundle) -> Value {
    super::compile::typed_projection(&bundle.normalized)
}

/// Derive the complete normalized result envelope without resolving mutable
/// routes. Native first-reply/history checks use retained typed source bytes;
/// executable restoration and source/provider verification remain separate.
#[cfg(feature = "sqlite")]
pub(crate) fn native_result_delivery(
    record: &Value,
    root: &str,
    evidence: &Value,
) -> Result<Value, EffectJournalError> {
    let origin = &record["target"]["runtime_incarnation"];
    let identity = &origin["definition"]["machine"];
    require(
        origin["kind"] == "root"
            && record["target"]["root_instance_id"] == root
            && origin["root_instance_id"] == root,
        "native result target must be the original root incarnation",
    )?;
    require(
        super::compile::hash_json(json!(["determa-validated-bundle-fingerprint-1", evidence]))
            == origin["definition"]["validated_bundle_fingerprint"],
        "retained result source fingerprint mismatch",
    )?;
    let source: TypedValue = serde_json::from_value(evidence.clone()).map_err(failure)?;
    let normalized =
        serde_json::to_value(source.to_value(None).map_err(failure)?).map_err(failure)?;
    require(
        normalized["format"] == 1 && normalized["namespace"] == identity["namespace"],
        "retained source identity mismatch",
    )?;
    let pointer = text(identity, "root_definition_pointer")?
        .strip_suffix("/root")
        .ok_or_else(|| failure("retained native machine root pointer invalid"))?;
    let machine = normalized
        .pointer(pointer)
        .ok_or_else(|| failure("retained result machine absent"))?;
    let version = machine
        .get("version")
        .and_then(Value::as_i64)
        .unwrap_or(1)
        .to_string();
    require(
        machine["machine_id"] == identity["machine_id"] && identity["machine_version"] == version,
        "retained result machine identity mismatch",
    )?;
    let outcome = &record["outcome"];
    require(!outcome.is_null(), "native result outcome absent")?;
    let mapping = array(record, "result_mapping")?
        .iter()
        .find(|mapping| mapping["outcome_kind"] == outcome["kind"])
        .ok_or_else(|| failure("native result mapping absent"))?;
    let event = text(mapping, "event")?;
    let declaration = machine["events"]
        .get(event)
        .or_else(|| normalized["events"].get(event))
        .ok_or_else(|| failure("retained result declaration absent"))?;
    let declaration: super::model::EventDeclaration =
        serde_json::from_value(declaration.clone()).map_err(failure)?;
    require(
        declaration.direction == super::model::EventDirection::Input,
        "native result event is not input",
    )?;
    let mut payload: TypedValue =
        serde_json::from_value(outcome["payload"].clone()).map_err(failure)?;
    if mapping["operation_token_location"]["kind"] == "payload" {
        let pointer = text(&mapping["operation_token_location"], "pointer")?;
        let key = pointer
            .strip_prefix('/')
            .filter(|key| !key.contains('/'))
            .ok_or_else(|| failure("native token pointer is not flat"))?
            .replace("~1", "/")
            .replace("~0", "~");
        let TypedValue::Map(fields) = &mut payload else {
            return Err(failure("native result payload is not a map"));
        };
        if let Some((_, supplied)) = fields.iter_mut().find(|(name, _)| *name == key) {
            require(
                matches!(supplied, TypedValue::String(_)),
                "native result token is not a string",
            )?;
            *supplied = TypedValue::String(text(record, "operation_token")?.to_owned());
        } else {
            fields.push((
                key,
                TypedValue::String(text(record, "operation_token")?.to_owned()),
            ));
            fields.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
        }
    }
    let crate::value::Value::Map(logical) = payload.to_value(None).map_err(failure)? else {
        return Err(failure("native result payload is not a map"));
    };
    let logical = super::runtime::normalize_payload(&declaration, &logical)
        .map_err(|_| failure("invalid declared native result payload"))?;
    let payload = TypedValue::from_value(&crate::value::Value::Map(logical));
    let event_id = hash(&json!([
        "determa-effect-result-event-1",
        record["effect_id"],
        mapping["result_slot"]
    ]))?;
    require(
        record["result_event_id"] == event_id,
        "native result event identity mismatch",
    )?;
    let mut envelope = json!({"event":event,"event_id":event_id,"cause_id":event_id,"source":{"host":true},
        "target":{"root":{"root_instance_id":root,"root_runtime_id":record["target"]["runtime_id"]}},"payload":payload});
    if mapping["operation_token_location"]["kind"] == "correlation_id" {
        envelope["correlation_id"] = record["operation_token"].clone();
    }
    let digest = hash(&json!([
        "determa-inbox-envelope-digest-1",
        "1",
        root,
        "input",
        envelope
    ]))?;
    Ok(json!({"delivery_mode":"input","envelope":envelope,"envelope_digest":digest}))
}
