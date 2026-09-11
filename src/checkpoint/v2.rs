use crate::format1::native::jcs_hash;
use crate::format1::strict_json;
use crate::format1::v2::{
    canonical_bytes, migrate_aggregate_v2_route_with_evidence, step_v2_with_emission_indexes,
    validate_admission_delivery_schema, validate_v2_schema,
};
use crate::format1::{
    admit, restore_aggregate, Aggregate, ArtifactError, Bindings, Bundle, Counter,
    DefinitionResolver, Delivery, MigrationArtifactResolver, MigrationRequest, ResourceLimits,
    TypedValue,
};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

use super::types::{
    OutboxIntent, PendingOutboxState, ProcessingRequest, PruneRequest, TerminalOutboxOutcome,
};

#[derive(Debug, Clone, PartialEq)]
pub struct ExecutionCheckpoint {
    value: Value,
    aggregate: Option<Aggregate>,
}

impl ExecutionCheckpoint {
    pub fn value(&self) -> &Value {
        &self.value
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ArtifactError> {
        canonical_bytes(&self.value)
    }

    pub fn root_instance_id(&self) -> &str {
        self.value["root_instance_id"]
            .as_str()
            .expect("validated checkpoint root identity")
    }

    pub fn revision(&self) -> &str {
        self.value["revision"]
            .as_str()
            .expect("validated checkpoint revision")
    }

    pub fn digest(&self) -> &str {
        self.value["execution_checkpoint_digest"]
            .as_str()
            .expect("validated checkpoint digest")
    }

    pub fn bundle_fingerprint(&self) -> Option<&str> {
        self.aggregate
            .as_ref()
            .and_then(|aggregate| aggregate.value()["validated_bundle_fingerprint"].as_str())
    }
}

pub fn create_execution_checkpoint_v2(
    bundle: &Bundle,
    machine_id: &str,
    root_instance_id: &str,
    creation_id: &str,
    bindings: &Bindings,
    supplied_request_digest: Option<&str>,
    replay_retention: Value,
) -> Result<ExecutionCheckpoint, ArtifactError> {
    let request_digest =
        creation_request_digest(bundle, machine_id, root_instance_id, creation_id, bindings)?;
    if supplied_request_digest.is_some_and(|supplied| supplied != request_digest) {
        return Err(invalid(
            "supplied creation request digest does not match canonical content",
        ));
    }
    let created = crate::format1::v2::create_v2_with_evidence(
        bundle,
        machine_id,
        root_instance_id,
        creation_id,
        bindings,
    )?;
    let aggregate = created.aggregate.value().clone();
    let mut value = json!({
        "execution_checkpoint_format": "determa.execution_checkpoint",
        "execution_checkpoint_schema_version": 2,
        "root_instance_id": root_instance_id,
        "revision": "0",
        "root_record": {"status": "retained", "aggregate_state": aggregate},
        "replay_retention": replay_retention,
        "next_operation_receipt_sequence": "1",
        "operation_receipts": [],
        "event_identity_tombstones": [],
        "pending_outbox_intents": [],
        "next_outbox_terminal_sequence": "0",
        "terminal_outbox_records": [],
        "outbox_effect_tombstones": [],
        "migration_audit_records": []
    });
    let lifecycle_sequences = (0..created.lifecycle_dispositions.len())
        .map(|_| allocate(&mut value, "next_operation_receipt_sequence"))
        .collect::<Result<Vec<_>, _>>()?;
    let references = append_checkpoint_emissions(
        &mut value,
        &created.emissions,
        &created.emission_indexes,
        &lifecycle_sequences,
        &json!("0"),
    )?;
    value["operation_receipts"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "operation_kind": "creation",
            "receipt_sequence": "0",
            "creation_id": creation_id,
            "request_digest": request_digest,
            "committed_revision": "0",
            "resulting_aggregate_state_digest": aggregate["aggregate_state_digest"],
            "status": created.status,
            "fault": created.fault,
            "emission_references": references
        }));
    for (disposition, receipt_sequence) in created
        .lifecycle_dispositions
        .iter()
        .zip(lifecycle_sequences)
    {
        value["operation_receipts"]
            .as_array_mut()
            .unwrap()
            .push(lifecycle_receipt(
                disposition,
                &receipt_sequence,
                &json!("0"),
                &aggregate["aggregate_state_digest"],
                &json!(created.status),
            ));
    }
    seal_checkpoint(&mut value)?;
    let mut resolver = crate::format1::InMemoryDefinitionResolver::default();
    resolver.insert(bundle.clone(), true);
    restore_value(value, &resolver)
}

pub fn creation_request_digest(
    bundle: &Bundle,
    machine_id: &str,
    root_instance_id: &str,
    creation_id: &str,
    bindings: &Bindings,
) -> Result<String, ArtifactError> {
    let machine = bundle.machines.get(machine_id).ok_or_else(|| {
        ArtifactError::new("invalid_machine", "creation machine is absent from bundle")
    })?;
    let bindings = crate::value::Value::Map(BTreeMap::from([
        (
            "external".to_string(),
            crate::value::Value::Map(bindings.external.clone()),
        ),
        (
            "input".to_string(),
            crate::value::Value::Map(bindings.input.clone()),
        ),
    ]));
    jcs_hash(&json!([
        "determa-creation-request-digest-2",
        "2",
        bundle.fingerprint,
        bundle.namespace,
        machine_id,
        machine.version.to_string(),
        root_instance_id,
        creation_id,
        TypedValue::from_value(&bindings)
    ]))
    .map_err(|error| invalid(error.to_string()))
}

pub fn restore_execution_checkpoint(
    source: &[u8],
    resolver: &(impl DefinitionResolver + ?Sized),
) -> Result<ExecutionCheckpoint, ArtifactError> {
    let value = strict_json::parse(source).map_err(invalid)?;
    restore_value(value, resolver)
}

pub fn checkpoint_admit_v2(
    bundle: &Bundle,
    checkpoint: &ExecutionCheckpoint,
    deliveries: &[Value],
    expected_revision: Option<&str>,
    expected_checkpoint_digest: Option<&str>,
) -> Result<Value, ArtifactError> {
    checkpoint_admit_v2_with_optional_bundle(
        Some(bundle),
        checkpoint,
        deliveries,
        expected_revision,
        expected_checkpoint_digest,
    )
}

pub(super) fn checkpoint_admit_v2_with_optional_bundle(
    bundle: Option<&Bundle>,
    checkpoint: &ExecutionCheckpoint,
    deliveries: &[Value],
    expected_revision: Option<&str>,
    expected_checkpoint_digest: Option<&str>,
) -> Result<Value, ArtifactError> {
    let tombstoned = checkpoint.value["root_record"]["status"] == "tombstone";
    let root_instance_id = checkpoint.value["root_instance_id"].as_str().unwrap();
    let parsed = deliveries
        .iter()
        .map(|delivery| {
            validate_admission_delivery_schema(delivery)
                .map_err(|_| failure("malformed_delivery"))?;
            serde_json::from_value::<Delivery>(delivery.clone())
                .map_err(|_| failure("malformed_delivery"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if deliveries.iter().any(|delivery| {
        target_root_instance_id(&delivery["envelope"]["target"])
            .is_some_and(|root| root != root_instance_id)
    }) {
        return Err(failure("wrong_root"));
    }
    let retained = retained_identity(&checkpoint.value)?;
    let mut members = vec![None; deliveries.len()];
    let mut fresh = Vec::new();
    let mut seen = BTreeSet::new();
    for (index, parsed) in parsed.into_iter().enumerate() {
        let event_id = parsed.envelope.event_id.as_str();
        if !seen.insert(event_id.to_string()) {
            return Err(failure("duplicate_event_id_in_batch"));
        }
        let candidate = crate::format1::v2::envelope_digest(
            root_instance_id,
            &parsed.delivery_mode,
            &parsed.envelope,
        )?;
        if let Some(identity) = retained.get(event_id) {
            if identity.digest != candidate {
                return Err(failure("event_id_conflict"));
            }
            let evidence = identity.replay.clone();
            members[index] = Some(json!({
                "event_id": event_id,
                "disposition": "replay",
                "evidence": evidence
            }));
        } else {
            fresh.push((index, parsed));
        }
    }
    if fresh.is_empty() && members.len() == 1 {
        return Ok(members[0].as_ref().unwrap()["evidence"].clone());
    }
    if fresh.is_empty() {
        return Ok(
            json!({"result":"batch", "checkpoint":checkpoint.value, "members":members.into_iter().flatten().collect::<Vec<_>>()}),
        );
    }
    if tombstoned {
        return Err(failure("tombstoned_root"));
    }
    let aggregate = checkpoint
        .aggregate
        .as_ref()
        .ok_or_else(|| failure("terminal_root"))?;
    if aggregate.value()["runtimes"]
        .as_array()
        .is_some_and(|runtimes| {
            runtimes.iter().any(|runtime| {
                runtime["relation"]["kind"] == "root" && runtime["status"] != "running"
            })
        })
    {
        return Err(failure("terminal_root"));
    }
    let bundle = bundle.ok_or_else(|| failure("terminal_root"))?;
    if aggregate.value()["validated_bundle_fingerprint"].as_str()
        != Some(bundle.fingerprint.as_str())
    {
        return Err(failure("incompatible_bundle"));
    }
    guard(checkpoint, expected_revision, expected_checkpoint_digest)?;
    let fresh_deliveries = fresh
        .iter()
        .map(|(_, delivery)| delivery.clone())
        .collect::<Vec<_>>();
    let core = admit(bundle, aggregate, &fresh_deliveries)?;
    let state = core["state"].clone();
    let mut value = checkpoint.value.clone();
    let new_revision = incremented(&value["revision"])?;
    value["revision"] = new_revision.clone();
    value["root_record"]["aggregate_state"] = state;
    let accepted = core["accepted"].as_array().cloned().unwrap_or_default();
    for ((index, delivery), accepted) in fresh.iter().zip(accepted) {
        let sequence = allocate(&mut value, "next_operation_receipt_sequence")?;
        value["operation_receipts"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "operation_kind": "acceptance",
                "receipt_sequence": sequence,
                "event_id": delivery.envelope.event_id,
                "request_digest": delivery.envelope_digest,
                "acceptance_sequence": accepted["acceptance_sequence"],
                "accepted_revision": new_revision,
                "delivery_mode": delivery.delivery_mode
            }));
        members[*index] = Some(json!({
            "event_id": delivery.envelope.event_id,
            "disposition": "accepted",
            "acceptance_sequence": accepted["acceptance_sequence"],
            "queue_sequence": accepted["queue_sequence"]
        }));
    }
    seal_checkpoint(&mut value)?;
    if members.len() == 1
        && members[0]
            .as_ref()
            .is_some_and(|member| member["disposition"] == "accepted")
    {
        Ok(value)
    } else {
        Ok(
            json!({"result": "batch", "checkpoint": value, "members": members.into_iter().flatten().collect::<Vec<_>>() }),
        )
    }
}

pub fn checkpoint_step_v2(
    bundle: &Bundle,
    checkpoint: &ExecutionCheckpoint,
    request: &ProcessingRequest,
    expected_revision: Option<&str>,
    expected_checkpoint_digest: Option<&str>,
) -> Result<Value, ArtifactError> {
    if !matches!(request.processing_mode.as_str(), "delayed" | "foreground") {
        return Err(failure("invalid_execution_checkpoint"));
    }
    guard(checkpoint, expected_revision, expected_checkpoint_digest)?;
    if let Some(receipt) = checkpoint.value["operation_receipts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|receipt| {
            receipt["operation_kind"] == "event_terminal"
                && receipt["event_id"].as_str() == Some(&request.event_id)
        })
    {
        return if receipt["request_digest"].as_str() == Some(&request.envelope_digest)
            && receipt["acceptance_sequence"].as_str() == Some(&request.acceptance_sequence)
            && receipt["final_queue_sequence"].as_str() == Some(&request.queue_sequence)
        {
            Ok(receipt.clone())
        } else {
            Err(failure("event_id_conflict"))
        };
    }
    if let Some(tombstone) = checkpoint.value["event_identity_tombstones"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["event_id"].as_str() == Some(&request.event_id))
    {
        return if tombstone["request_digest"].as_str() == Some(&request.envelope_digest)
            && tombstone["acceptance_sequence"].as_str() == Some(&request.acceptance_sequence)
        {
            Ok(tombstone.clone())
        } else {
            Err(failure("event_id_conflict"))
        };
    }
    let aggregate = checkpoint
        .aggregate
        .as_ref()
        .ok_or_else(|| failure("terminal_root"))?;
    if aggregate.value()["validated_bundle_fingerprint"].as_str()
        != Some(bundle.fingerprint.as_str())
    {
        return Err(failure("incompatible_bundle"));
    }
    let causal = ready_head(aggregate.value(), &request.target_runtime_id)?.clone();
    if causal["envelope"]["event_id"].as_str() != Some(&request.event_id)
        || causal["envelope_digest"].as_str() != Some(&request.envelope_digest)
        || causal["acceptance_sequence"].as_str() != Some(&request.acceptance_sequence)
        || causal["queue_sequence"].as_str() != Some(&request.queue_sequence)
    {
        return Err(failure("invalid_execution_checkpoint"));
    }
    let (core, emission_indexes) =
        step_v2_with_emission_indexes(bundle, aggregate, &request.target_runtime_id)?;
    apply_step_result(&checkpoint.value, &causal, core, emission_indexes)
}

fn apply_step_result(
    checkpoint: &Value,
    causal: &Value,
    core: Value,
    emission_indexes: Vec<String>,
) -> Result<Value, ArtifactError> {
    if core["disposition"] == "not_runnable" || core["disposition"] == "rejected" {
        return Ok(core);
    }
    let mut value = checkpoint.clone();
    let new_revision = incremented(&value["revision"])?;
    value["revision"] = new_revision.clone();
    let resulting_state = core["state"].clone();
    value["root_record"]["aggregate_state"] = resulting_state.clone();
    if core["disposition"] == "deferred" {
        seal_checkpoint(&mut value)?;
        return Ok(value);
    }

    let terminal_sequence = allocate(&mut value, "next_operation_receipt_sequence")?;
    let lifecycle = core["lifecycle_dispositions"]
        .as_array()
        .ok_or_else(|| invalid("core lifecycle dispositions are absent"))?;
    let lifecycle_sequences = (0..lifecycle.len())
        .map(|_| allocate(&mut value, "next_operation_receipt_sequence"))
        .collect::<Result<Vec<_>, _>>()?;
    let references = append_checkpoint_emissions(
        &mut value,
        core["emissions"]
            .as_array()
            .ok_or_else(|| invalid("core emissions are absent"))?,
        &emission_indexes,
        &lifecycle_sequences,
        &new_revision,
    )?;
    value["operation_receipts"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "operation_kind": "event_terminal",
            "receipt_sequence": terminal_sequence,
            "event_id": causal["envelope"]["event_id"],
            "request_digest": causal["envelope_digest"],
            "acceptance_sequence": causal["acceptance_sequence"],
            "final_queue_sequence": causal["queue_sequence"],
            "committed_revision": new_revision,
            "resulting_aggregate_state_digest": resulting_state["aggregate_state_digest"],
            "outcome": {
                "status": core["status"],
                "disposition": core["disposition"],
                "fault": core["fault"],
                "rejection": core["rejection"]
            },
            "emission_references": references
        }));
    rewrite_producer_reference(&mut value, causal, &terminal_sequence)?;
    for (disposition, receipt_sequence) in lifecycle.iter().zip(lifecycle_sequences) {
        let receipt = lifecycle_receipt(
            disposition,
            &receipt_sequence,
            &new_revision,
            &resulting_state["aggregate_state_digest"],
            &core["status"],
        );
        value["operation_receipts"]
            .as_array_mut()
            .unwrap()
            .push(receipt);
        rewrite_producer_event_reference(
            &mut value,
            disposition["event_id"].as_str().unwrap(),
            &receipt_sequence,
        )?;
    }
    seal_checkpoint(&mut value)?;
    Ok(value)
}

pub fn checkpoint_process(
    bundle: &Bundle,
    checkpoint: &ExecutionCheckpoint,
    delivery: Value,
    processing_mode: &str,
    expected_revision: Option<&str>,
    expected_checkpoint_digest: Option<&str>,
) -> Result<Value, ArtifactError> {
    let resolver = single_bundle_resolver(bundle);
    checkpoint_process_resolved(
        bundle,
        checkpoint,
        delivery,
        processing_mode,
        expected_revision,
        expected_checkpoint_digest,
        &resolver,
    )
}

#[allow(clippy::too_many_arguments)]
fn checkpoint_process_resolved(
    bundle: &Bundle,
    checkpoint: &ExecutionCheckpoint,
    delivery: Value,
    processing_mode: &str,
    expected_revision: Option<&str>,
    expected_checkpoint_digest: Option<&str>,
    resolver: &(impl DefinitionResolver + ?Sized),
) -> Result<Value, ArtifactError> {
    if !matches!(processing_mode, "delayed" | "foreground") {
        return Err(failure("invalid_execution_checkpoint"));
    }
    guard(checkpoint, expected_revision, expected_checkpoint_digest)?;
    let event_id = delivery["envelope"]["event_id"]
        .as_str()
        .ok_or_else(|| failure("malformed_delivery"))?
        .to_string();
    let admitted = checkpoint_admit_v2(
        bundle,
        checkpoint,
        &[delivery],
        expected_revision,
        expected_checkpoint_digest,
    )?;
    if admitted["execution_checkpoint_format"] != "determa.execution_checkpoint" {
        return Ok(admitted);
    }
    let admitted_value = admitted;
    let aggregate = restore_aggregate(
        &canonical_bytes(&admitted_value["root_record"]["aggregate_state"])?,
        resolver,
    )
    .map_err(|error| invalid(error.message))?;
    let mut selected = None;
    for runtime in aggregate.value()["runtimes"].as_array().unwrap() {
        if let Some(entry) = runtime["ready_mailbox"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["envelope"]["event_id"].as_str() == Some(&event_id))
        {
            selected = Some((runtime, entry));
            break;
        }
    }
    let (runtime, causal) = selected.ok_or_else(|| invalid("admitted event is not runnable"))?;
    let causal = causal.clone();
    let (core, emission_indexes) =
        step_v2_with_emission_indexes(bundle, &aggregate, runtime["runtime_id"].as_str().unwrap())?;
    let stepped = apply_step_result(&admitted_value, &causal, core, emission_indexes)?;
    if stepped["execution_checkpoint_format"] != "determa.execution_checkpoint" {
        return Ok(stepped);
    }
    collapse_process_revision(checkpoint, stepped)
}

#[allow(clippy::too_many_arguments)]
pub fn checkpoint_process_with_migration(
    checkpoint: &ExecutionCheckpoint,
    migration: &MigrationRequest,
    resolver: &impl MigrationArtifactResolver,
    limits: &ResourceLimits,
    delivery: Value,
    processing_mode: &str,
    expected_revision: Option<&str>,
    expected_checkpoint_digest: Option<&str>,
) -> Result<Value, ArtifactError> {
    guard(checkpoint, expected_revision, expected_checkpoint_digest)?;
    let aggregate = checkpoint
        .aggregate
        .as_ref()
        .ok_or_else(|| failure("terminal_root"))?;
    let migrated =
        migrate_aggregate_v2_route_with_evidence(aggregate, migration, resolver, limits)?;
    let prepared = apply_transaction_migration(checkpoint, migrated)?;
    let prepared = restore_value(prepared, resolver)?;
    let target = resolver
        .resolve_definition(&migration.target_validated_bundle_fingerprint)
        .filter(|resolved| {
            resolved.trusted
                && resolved.bundle.fingerprint == migration.target_validated_bundle_fingerprint
        })
        .ok_or_else(|| failure("target_definition_unavailable"))?;
    let processed = checkpoint_process_resolved(
        &target.bundle,
        &prepared,
        delivery,
        processing_mode,
        Some(prepared.revision()),
        Some(prepared.digest()),
        resolver,
    )?;
    collapse_process_revision(checkpoint, processed)
}

fn apply_transaction_migration(
    checkpoint: &ExecutionCheckpoint,
    migrated: Value,
) -> Result<Value, ArtifactError> {
    let mut value = checkpoint.value.clone();
    value["revision"] = incremented(&value["revision"])?;
    let revision = value["revision"].clone();
    let aggregate = migrated["aggregate_state"].clone();
    let status = aggregate["runtimes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|runtime| runtime["runtime_id"] == aggregate["root_runtime_id"])
        .and_then(|runtime| runtime["status"].as_str())
        .ok_or_else(|| invalid("migrated root runtime status is absent"))?
        .to_string();
    value["root_record"]["aggregate_state"] = aggregate.clone();
    for disposition in migrated["dispositions"]
        .as_array()
        .ok_or_else(|| invalid("migration dispositions are absent"))?
    {
        let receipt_sequence = allocate(&mut value, "next_operation_receipt_sequence")?;
        value["operation_receipts"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "operation_kind": "event_terminal",
                "receipt_sequence": receipt_sequence,
                "event_id": disposition["event_id"],
                "request_digest": disposition["request_digest"],
                "acceptance_sequence": disposition["acceptance_sequence"],
                "final_queue_sequence": disposition["final_queue_sequence"],
                "committed_revision": revision,
                "resulting_aggregate_state_digest": aggregate["aggregate_state_digest"],
                "outcome": {
                    "status": status,
                    "disposition": "migration_disposed",
                    "reason": disposition["reason"],
                    "migration_descriptor_digest": disposition["migration_descriptor_digest"],
                    "fault": null,
                    "rejection": null
                },
                "emission_references": []
            }));
        rewrite_producer_event_reference(
            &mut value,
            disposition["event_id"].as_str().unwrap(),
            &receipt_sequence,
        )?;
    }
    value["migration_audit_records"]
        .as_array_mut()
        .unwrap()
        .extend(
            migrated["audit_records"]
                .as_array()
                .ok_or_else(|| invalid("migration audit records are absent"))?
                .iter()
                .cloned(),
        );
    seal_and_validate_checkpoint(&mut value)?;
    Ok(value)
}

fn collapse_process_revision(
    checkpoint: &ExecutionCheckpoint,
    mut value: Value,
) -> Result<Value, ArtifactError> {
    let committed_revision = incremented(&checkpoint.value["revision"])?;
    let prior_next = counter(&checkpoint.value, "next_operation_receipt_sequence")?;
    value["revision"] = committed_revision.clone();
    for receipt in value["operation_receipts"].as_array_mut().unwrap() {
        if counter(receipt, "receipt_sequence")? < prior_next {
            continue;
        }
        if receipt["operation_kind"] == "acceptance" {
            receipt["accepted_revision"] = committed_revision.clone();
        } else if receipt.get("committed_revision").is_some() {
            receipt["committed_revision"] = committed_revision.clone();
        }
    }
    for pending in value["pending_outbox_intents"].as_array_mut().unwrap() {
        if Counter::from_decimal(pending["state_revision"].as_str().unwrap()).map_err(invalid)?
            > counter(&checkpoint.value, "revision")?
        {
            pending["state_revision"] = committed_revision.clone();
        }
    }
    seal_and_validate_checkpoint(&mut value)?;
    Ok(value)
}

fn single_bundle_resolver(bundle: &Bundle) -> crate::format1::InMemoryDefinitionResolver {
    let mut resolver = crate::format1::InMemoryDefinitionResolver::default();
    resolver.insert(bundle.clone(), true);
    resolver
}

fn append_checkpoint_emissions(
    value: &mut Value,
    emissions: &[Value],
    emission_indexes: &[String],
    lifecycle_sequences: &[String],
    committed_revision: &Value,
) -> Result<Vec<Value>, ArtifactError> {
    if emissions.len() != emission_indexes.len() {
        return Err(invalid("core emission ordinal evidence is incomplete"));
    }
    let mut references = Vec::with_capacity(emissions.len());
    for (emission, emission_index) in emissions.iter().zip(emission_indexes) {
        match emission["kind"].as_str() {
            Some("internal_mailbox") => references.push(emission.clone()),
            Some("internal_disposed") => {
                let disposition_index = emission["lifecycle_disposition_index"]
                    .as_str()
                    .ok_or_else(|| invalid("disposed emission has no lifecycle index"))?
                    .parse::<usize>()
                    .map_err(invalid)?;
                let terminal = lifecycle_sequences
                    .get(disposition_index)
                    .ok_or_else(|| invalid("disposed emission lifecycle index is out of range"))?;
                references.push(json!({
                    "kind": "internal_terminal",
                    "emission_index": emission["emission_index"],
                    "event_id": emission["event_id"],
                    "acceptance_sequence": emission["acceptance_sequence"],
                    "terminal_receipt_sequence": terminal
                }));
            }
            None => {
                let effect_id = emission["effect_id"]
                    .as_str()
                    .ok_or_else(|| invalid("external emission has no effect id"))?;
                if retained_effect_ids(value).contains(effect_id) {
                    return Err(invalid("external emission effect identity is duplicated"));
                }
                value["pending_outbox_intents"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({
                        "intent": emission,
                        "state_revision": committed_revision,
                        "delivery_state": {"status": "not_attempted"}
                    }));
                references.push(json!({
                    "kind": "external_outbox",
                    "emission_index": emission_index,
                    "effect_id": effect_id
                }));
            }
            Some(_) => return Err(invalid("unknown core emission kind")),
        }
    }
    Ok(references)
}

fn lifecycle_receipt(
    disposition: &Value,
    receipt_sequence: &str,
    committed_revision: &Value,
    aggregate_digest: &Value,
    status: &Value,
) -> Value {
    json!({
        "operation_kind": "event_terminal",
        "receipt_sequence": receipt_sequence,
        "event_id": disposition["event_id"],
        "request_digest": disposition["request_digest"],
        "acceptance_sequence": disposition["acceptance_sequence"],
        "final_queue_sequence": disposition["final_queue_sequence"],
        "committed_revision": committed_revision,
        "resulting_aggregate_state_digest": aggregate_digest,
        "outcome": {
            "status": status,
            "disposition": "disposed",
            "reason": disposition["reason"],
            "fault": null,
            "rejection": null
        },
        "emission_references": []
    })
}

pub fn checkpoint_prune_v2(
    checkpoint: &ExecutionCheckpoint,
    request: &PruneRequest,
    expected_revision: Option<&str>,
    expected_checkpoint_digest: Option<&str>,
) -> Result<Value, ArtifactError> {
    let requested = Counter::from_decimal(&request.cutoff_receipt_sequence).map_err(invalid)?;
    let current_mode = checkpoint.value["replay_retention"]["mode"]
        .as_str()
        .ok_or_else(|| invalid("retention mode is absent"))?;
    if request.target_mode != "bounded"
        || request
            .policy_identifier
            .as_deref()
            .is_none_or(str::is_empty)
        || !request.dependency_receipt_sequences.is_empty()
        || !request.dependency_effect_ids.is_empty()
        || current_mode == "bounded"
            && checkpoint.value["replay_retention"]["policy_identifier"].as_str()
                != request.policy_identifier.as_deref()
    {
        return Err(failure("invalid_execution_checkpoint"));
    }
    let prior = checkpoint.value["replay_retention"]["pruned_through_receipt_sequence"]
        .as_str()
        .map(Counter::from_decimal)
        .transpose()
        .map_err(invalid)?;
    if prior.as_ref() == Some(&requested) {
        return Ok(checkpoint.value.clone());
    }
    guard(checkpoint, expected_revision, expected_checkpoint_digest)?;
    if requested >= counter(&checkpoint.value, "next_operation_receipt_sequence")? {
        return Err(failure("invalid_execution_checkpoint"));
    }
    if prior.as_ref().is_some_and(|value| value > &requested) {
        return Err(failure("invalid_execution_checkpoint"));
    }
    let receipts = checkpoint.value["operation_receipts"].as_array().unwrap();
    let removable = receipts
        .iter()
        .filter(|receipt| {
            receipt["receipt_sequence"] != "0"
                && Counter::from_decimal(receipt["receipt_sequence"].as_str().unwrap()).unwrap()
                    <= requested
        })
        .collect::<Vec<_>>();
    if removable.is_empty()
        || receipts.iter().any(|receipt| {
            receipt["receipt_sequence"] != "0"
                && Counter::from_decimal(receipt["receipt_sequence"].as_str().unwrap()).unwrap()
                    < requested
                && !removable.contains(&receipt)
        })
    {
        return Err(failure("invalid_execution_checkpoint"));
    }
    validate_prune_dependencies(receipts, &removable, prior.as_ref())?;
    let mut value = checkpoint.value.clone();
    let removed_sequences = removable
        .iter()
        .map(|r| r["receipt_sequence"].as_str().unwrap().to_string())
        .collect::<BTreeSet<_>>();
    let mut tombstones = value["event_identity_tombstones"]
        .as_array()
        .unwrap()
        .clone();
    for receipt in &removable {
        if receipt["operation_kind"] == "event_terminal" {
            tombstones.push(json!({
                "event_id": receipt["event_id"],
                "request_digest": receipt["request_digest"],
                "request_digest_domain": "determa-inbox-envelope-digest-2",
                "acceptance_sequence": receipt["acceptance_sequence"],
                "terminal_receipt_sequence": receipt["receipt_sequence"],
                "terminal_disposition": receipt["outcome"]["disposition"]
            }));
        }
    }
    value["operation_receipts"] = json!(receipts
        .iter()
        .filter(|r| !removed_sequences.contains(r["receipt_sequence"].as_str().unwrap()))
        .cloned()
        .collect::<Vec<_>>());
    tombstones.sort_by_key(|item| {
        Counter::from_decimal(item["terminal_receipt_sequence"].as_str().unwrap()).unwrap()
    });
    value["event_identity_tombstones"] = json!(tombstones);
    value["replay_retention"] = json!({
        "mode": "bounded",
        "permanent_replay_eligible": false,
        "pruned_through_receipt_sequence": request.cutoff_receipt_sequence,
        "policy_identifier": request.policy_identifier.as_ref().unwrap()
    });
    value["revision"] = incremented(&value["revision"])?;
    seal_checkpoint(&mut value)?;
    Ok(value)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn checkpoint_maintenance_migration_route(
    checkpoint: &ExecutionCheckpoint,
    request: &MigrationRequest,
    operation_id: &str,
    request_digest: &str,
    resolver: &impl MigrationArtifactResolver,
    limits: &ResourceLimits,
    expected_revision: Option<&str>,
    expected_checkpoint_digest: Option<&str>,
) -> Result<Value, ArtifactError> {
    guard(checkpoint, expected_revision, expected_checkpoint_digest)?;
    let aggregate = checkpoint
        .aggregate
        .as_ref()
        .ok_or_else(|| failure("terminal_root"))?;
    let migrated = migrate_aggregate_v2_route_with_evidence(aggregate, request, resolver, limits)?;
    apply_checkpoint_migration_v2(
        checkpoint,
        migrated,
        operation_id,
        request_digest,
        &request.target_validated_bundle_fingerprint,
    )
}

fn apply_checkpoint_migration_v2(
    checkpoint: &ExecutionCheckpoint,
    migrated: Value,
    operation_id: &str,
    request_digest: &str,
    target_validated_bundle_fingerprint: &str,
) -> Result<Value, ArtifactError> {
    let mut value = checkpoint.value.clone();
    value["revision"] = incremented(&value["revision"])?;
    let revision = value["revision"].clone();
    let source_aggregate_state_digest =
        checkpoint.value["root_record"]["aggregate_state"]["aggregate_state_digest"].clone();
    let aggregate = migrated["aggregate_state"].clone();
    let status = aggregate["runtimes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|runtime| runtime["runtime_id"] == aggregate["root_runtime_id"])
        .and_then(|runtime| runtime["status"].as_str())
        .ok_or_else(|| invalid("migrated root runtime status is absent"))?
        .to_string();
    value["root_record"]["aggregate_state"] = aggregate.clone();
    let migration_sequences = migrated["audit_records"]
        .as_array()
        .ok_or_else(|| invalid("migration audit records are absent"))?
        .iter()
        .map(|audit| audit["migration_sequence"].clone())
        .collect::<Vec<_>>();
    let receipt_sequence = allocate(&mut value, "next_operation_receipt_sequence")?;
    value["operation_receipts"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "operation_kind": "maintenance_migration",
            "receipt_sequence": receipt_sequence,
            "operation_id": operation_id,
            "request_digest": request_digest,
            "committed_revision": revision,
            "source_aggregate_state_digest": source_aggregate_state_digest,
            "target_validated_bundle_fingerprint": target_validated_bundle_fingerprint,
            "resulting_aggregate_state_digest": aggregate["aggregate_state_digest"],
            "migration_sequences": migration_sequences,
            "result_code": if migrated["audit_records"].as_array().unwrap().is_empty() {
                "migration_no_operation"
            } else {
                "migration_applied"
            }
        }));
    for disposition in migrated["dispositions"].as_array().unwrap() {
        let receipt_sequence = allocate(&mut value, "next_operation_receipt_sequence")?;
        value["operation_receipts"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "operation_kind": "event_terminal",
                "receipt_sequence": receipt_sequence,
                "event_id": disposition["event_id"],
                "request_digest": disposition["request_digest"],
                "acceptance_sequence": disposition["acceptance_sequence"],
                "final_queue_sequence": disposition["final_queue_sequence"],
                "committed_revision": revision,
                "resulting_aggregate_state_digest": aggregate["aggregate_state_digest"],
                "outcome": {
                "status": status,
                    "disposition": "migration_disposed",
                    "reason": disposition["reason"],
                    "migration_descriptor_digest": disposition["migration_descriptor_digest"],
                    "fault": null,
                    "rejection": null
                },
                "emission_references": []
            }));
        rewrite_producer_event_reference(
            &mut value,
            disposition["event_id"].as_str().unwrap(),
            &receipt_sequence,
        )?;
    }
    value["migration_audit_records"]
        .as_array_mut()
        .unwrap()
        .extend(
            migrated["audit_records"]
                .as_array()
                .unwrap()
                .iter()
                .cloned(),
        );
    seal_and_validate_checkpoint(&mut value)?;
    Ok(value)
}

pub fn checkpoint_update_pending_outbox(
    checkpoint: &ExecutionCheckpoint,
    effect_id: &str,
    delivery_state: PendingOutboxState,
    expected_revision: Option<&str>,
    expected_checkpoint_digest: Option<&str>,
) -> Result<Value, ArtifactError> {
    let delivery_state = serde_json::to_value(delivery_state).map_err(invalid)?;
    let existing = checkpoint.value["pending_outbox_intents"]
        .as_array()
        .unwrap()
        .iter()
        .find(|record| record["intent"]["effect_id"].as_str() == Some(effect_id))
        .ok_or_else(|| failure("effect_id_conflict"))?;
    if existing["delivery_state"] == delivery_state {
        return Ok(checkpoint.value.clone());
    }
    guard(checkpoint, expected_revision, expected_checkpoint_digest)?;
    let mut value = checkpoint.value.clone();
    value["revision"] = incremented(&value["revision"])?;
    let revision = value["revision"].clone();
    let record = value["pending_outbox_intents"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|record| record["intent"]["effect_id"].as_str() == Some(effect_id))
        .unwrap();
    record["delivery_state"] = delivery_state;
    record["state_revision"] = revision;
    seal_and_validate_checkpoint(&mut value)?;
    Ok(value)
}

pub fn checkpoint_terminalize_outbox(
    checkpoint: &ExecutionCheckpoint,
    effect_id: &str,
    outcome: TerminalOutboxOutcome,
    expected_revision: Option<&str>,
    expected_checkpoint_digest: Option<&str>,
) -> Result<Value, ArtifactError> {
    let outcome = serde_json::to_value(outcome).map_err(invalid)?;
    if let Some(record) = checkpoint.value["terminal_outbox_records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|record| record["intent"]["effect_id"].as_str() == Some(effect_id))
    {
        return if record["outcome"] == outcome {
            Ok(checkpoint.value.clone())
        } else {
            Err(failure("effect_id_conflict"))
        };
    }
    if let Some(record) = checkpoint.value["outbox_effect_tombstones"]
        .as_array()
        .unwrap()
        .iter()
        .find(|record| record["effect_id"].as_str() == Some(effect_id))
    {
        return if record["outcome"] == outcome {
            Ok(checkpoint.value.clone())
        } else {
            Err(failure("effect_id_conflict"))
        };
    }
    guard(checkpoint, expected_revision, expected_checkpoint_digest)?;
    let mut value = checkpoint.value.clone();
    let index = value["pending_outbox_intents"]
        .as_array()
        .unwrap()
        .iter()
        .position(|record| record["intent"]["effect_id"].as_str() == Some(effect_id))
        .ok_or_else(|| failure("effect_id_conflict"))?;
    value["revision"] = incremented(&value["revision"])?;
    let pending = value["pending_outbox_intents"]
        .as_array_mut()
        .unwrap()
        .remove(index);
    let terminal_sequence = allocate(&mut value, "next_outbox_terminal_sequence")?;
    let record = json!({
        "terminal_sequence": terminal_sequence,
        "intent": pending["intent"],
        "committed_revision": value["revision"],
        "outcome": outcome
    });
    value["terminal_outbox_records"]
        .as_array_mut()
        .unwrap()
        .push(record);
    seal_and_validate_checkpoint(&mut value)?;
    Ok(value)
}

pub fn checkpoint_compact_outbox(
    checkpoint: &ExecutionCheckpoint,
    effect_id: &str,
    expected_revision: Option<&str>,
    expected_checkpoint_digest: Option<&str>,
) -> Result<Value, ArtifactError> {
    if checkpoint.value["outbox_effect_tombstones"]
        .as_array()
        .unwrap()
        .iter()
        .any(|record| record["effect_id"].as_str() == Some(effect_id))
    {
        return Ok(checkpoint.value.clone());
    }
    guard(checkpoint, expected_revision, expected_checkpoint_digest)?;
    let mut value = checkpoint.value.clone();
    let index = value["terminal_outbox_records"]
        .as_array()
        .unwrap()
        .iter()
        .position(|record| record["intent"]["effect_id"].as_str() == Some(effect_id))
        .ok_or_else(|| failure("effect_id_conflict"))?;
    value["revision"] = incremented(&value["revision"])?;
    let terminal = value["terminal_outbox_records"]
        .as_array_mut()
        .unwrap()
        .remove(index);
    let intent: OutboxIntent =
        serde_json::from_value(terminal["intent"].clone()).map_err(invalid)?;
    let intent_digest = outbox_intent_digest(checkpoint.root_instance_id(), &intent)?;
    value["outbox_effect_tombstones"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "terminal_sequence": terminal["terminal_sequence"],
            "effect_id": effect_id,
            "intent_digest": intent_digest,
            "committed_revision": terminal["committed_revision"],
            "outcome": terminal["outcome"]
        }));
    value["outbox_effect_tombstones"]
        .as_array_mut()
        .unwrap()
        .sort_by_key(|record| {
            Counter::from_decimal(record["terminal_sequence"].as_str().unwrap()).unwrap()
        });
    seal_and_validate_checkpoint(&mut value)?;
    Ok(value)
}

pub fn checkpoint_tombstone_root(
    checkpoint: &ExecutionCheckpoint,
    operation_id: &str,
    expected_revision: Option<&str>,
    expected_checkpoint_digest: Option<&str>,
) -> Result<Value, ArtifactError> {
    if operation_id.is_empty() {
        return Err(invalid("tombstone operation id is empty"));
    }
    if checkpoint.value["root_record"]["status"] == "tombstone" {
        return if checkpoint.value["root_record"]["tombstone_operation_id"].as_str()
            == Some(operation_id)
        {
            Ok(checkpoint.value.clone())
        } else {
            Err(failure("operation_id_conflict"))
        };
    }
    if !checkpoint.value["pending_outbox_intents"]
        .as_array()
        .unwrap()
        .is_empty()
    {
        return Err(invalid("root has unresolved pending outbox work"));
    }
    guard(checkpoint, expected_revision, expected_checkpoint_digest)?;
    let aggregate = checkpoint.value["root_record"]["aggregate_state"].clone();
    let root_runtime = aggregate["runtimes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|runtime| runtime["runtime_id"] == aggregate["root_runtime_id"])
        .ok_or_else(|| invalid("aggregate root runtime is absent"))?;
    let terminal_status = match root_runtime["status"].as_str() {
        Some("completed") => "completed",
        Some("faulted") => "faulted",
        _ => return Err(invalid("running aggregate cannot be tombstoned")),
    };
    let mut value = checkpoint.value.clone();
    value["revision"] = incremented(&value["revision"])?;
    let revision = value["revision"].clone();
    for runtime in aggregate["runtimes"].as_array().unwrap() {
        for field in ["ready_mailbox", "deferred_mailbox"] {
            for entry in runtime[field].as_array().unwrap() {
                let receipt_sequence = allocate(&mut value, "next_operation_receipt_sequence")?;
                value["operation_receipts"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({
                        "operation_kind": "event_terminal",
                        "receipt_sequence": receipt_sequence,
                        "event_id": entry["envelope"]["event_id"],
                        "request_digest": entry["envelope_digest"],
                        "acceptance_sequence": entry["acceptance_sequence"],
                        "final_queue_sequence": entry["queue_sequence"],
                        "committed_revision": revision,
                        "resulting_aggregate_state_digest": aggregate["aggregate_state_digest"],
                        "outcome": {
                            "status": terminal_status,
                            "disposition": "disposed",
                            "reason": "root_tombstoned",
                            "fault": null,
                            "rejection": null
                        },
                        "emission_references": []
                    }));
                rewrite_producer_event_reference(
                    &mut value,
                    entry["envelope"]["event_id"].as_str().unwrap(),
                    &receipt_sequence,
                )?;
            }
        }
    }
    value["root_record"] = json!({
        "status": "tombstone",
        "root_runtime_id": aggregate["root_runtime_id"],
        "creation_id": aggregate["creation_id"],
        "terminal_status": terminal_status,
        "final_aggregate_state_digest": aggregate["aggregate_state_digest"],
        "tombstone_operation_id": operation_id
    });
    seal_and_validate_checkpoint(&mut value)?;
    Ok(value)
}

struct Identity {
    digest: String,
    replay: Value,
}

fn retained_identity(value: &Value) -> Result<BTreeMap<String, Identity>, ArtifactError> {
    let mut result = BTreeMap::new();
    if value["root_record"]["status"] == "retained" {
        for runtime in value["root_record"]["aggregate_state"]["runtimes"]
            .as_array()
            .unwrap()
        {
            for (field, location) in [("ready_mailbox", "ready"), ("deferred_mailbox", "deferred")]
            {
                for entry in runtime[field].as_array().unwrap() {
                    let event_id = entry["envelope"]["event_id"].as_str().unwrap().to_string();
                    result.insert(event_id.clone(), Identity { digest: entry["envelope_digest"].as_str().unwrap().to_string(), replay: json!({
                        "result": "replay", "event_id": event_id,
                        "acceptance_sequence": entry["acceptance_sequence"], "location": location
                    }) });
                }
            }
        }
    }
    let acceptance = value["operation_receipts"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["operation_kind"] == "acceptance")
        .map(|r| (r["event_id"].as_str().unwrap(), r))
        .collect::<BTreeMap<_, _>>();
    for receipt in value["operation_receipts"].as_array().unwrap() {
        if receipt["operation_kind"] == "event_terminal" {
            let event_id = receipt["event_id"].as_str().unwrap().to_string();
            let acceptance_sequence = receipt["acceptance_sequence"].as_str().unwrap();
            let acceptance_receipt = acceptance
                .get(event_id.as_str())
                .filter(|r| r["acceptance_sequence"].as_str() == Some(acceptance_sequence));
            let replay = if let Some(acceptance_receipt) = acceptance_receipt {
                json!({"result":"replay","acceptance_receipt_sequence":acceptance_receipt["receipt_sequence"],"terminal_receipt_sequence":receipt["receipt_sequence"]})
            } else {
                json!({"result":"replay","terminal_receipt_sequence":receipt["receipt_sequence"]})
            };
            result.insert(
                event_id,
                Identity {
                    digest: receipt["request_digest"].as_str().unwrap().to_string(),
                    replay,
                },
            );
        }
    }
    for item in value["event_identity_tombstones"].as_array().unwrap() {
        result.insert(item["event_id"].as_str().unwrap().to_string(), Identity {
            digest: item["request_digest"].as_str().unwrap().to_string(),
            replay: json!({"result":"replay","terminal_receipt_sequence":item["terminal_receipt_sequence"],"terminal_disposition":item["terminal_disposition"]})
        });
    }
    Ok(result)
}

fn restore_value(
    value: Value,
    resolver: &(impl DefinitionResolver + ?Sized),
) -> Result<ExecutionCheckpoint, ArtifactError> {
    validate_v2_schema(
        &value,
        include_str!("../../schema/execution-checkpoint-v2.schema.json"),
        &[(
            "https://determa.dev/state/schema/aggregate-state-v2.schema.json",
            include_str!("../../schema/aggregate-state-v2.schema.json"),
        )],
        "invalid_execution_checkpoint",
    )?;
    let aggregate = if value["root_record"]["status"] == "retained" {
        Some(
            restore_aggregate(
                &canonical_bytes(&value["root_record"]["aggregate_state"])?,
                resolver,
            )
            .map_err(|error| invalid(error.message))?,
        )
    } else {
        None
    };
    let expected = checkpoint_digest(&value)?;
    if value["execution_checkpoint_digest"].as_str() != Some(expected.as_str()) {
        return Err(ArtifactError::new(
            "execution_checkpoint_digest_mismatch",
            "checkpoint digest does not match content",
        ));
    }
    validate_semantics(&value)?;
    Ok(ExecutionCheckpoint { value, aggregate })
}

fn validate_semantics(value: &Value) -> Result<(), ArtifactError> {
    let revision = counter(value, "revision")?;
    let next_receipt = counter(value, "next_operation_receipt_sequence")?;
    let receipts = value["operation_receipts"].as_array().unwrap();
    let mut sequences = BTreeSet::new();
    let mut prior_sequence = None;
    let mut prior_commit = Counter::zero();
    let mut creation_id = None;
    let mut creation_count = 0_usize;
    let mut acceptance_by_event = BTreeMap::new();
    let mut acceptance_sequences = BTreeSet::new();
    let mut terminal_by_event = BTreeMap::new();
    for receipt in receipts {
        let sequence = counter(receipt, "receipt_sequence")?;
        if sequence >= next_receipt
            || !sequences.insert(sequence.clone())
            || prior_sequence
                .as_ref()
                .is_some_and(|prior| prior >= &sequence)
        {
            return Err(invalid("receipt sequence is invalid"));
        }
        prior_sequence = Some(sequence);
        let kind = receipt["operation_kind"].as_str().unwrap();
        let committed = match kind {
            "creation" => {
                creation_count += 1;
                creation_id = receipt["creation_id"].as_str();
                Some(counter(receipt, "committed_revision")?)
            }
            "acceptance" => {
                let accepted = counter(receipt, "accepted_revision")?;
                if accepted > revision {
                    return Err(invalid("acceptance revision is in the future"));
                }
                let event_id = receipt["event_id"].as_str().unwrap();
                let acceptance = counter(receipt, "acceptance_sequence")?;
                if acceptance_by_event.insert(event_id, receipt).is_some()
                    || !acceptance_sequences.insert(acceptance)
                {
                    return Err(invalid("acceptance identity is duplicated"));
                }
                None
            }
            "event_terminal" => {
                let event_id = receipt["event_id"].as_str().unwrap();
                if terminal_by_event.insert(event_id, receipt).is_some() {
                    return Err(invalid("terminal event identity is duplicated"));
                }
                Some(counter(receipt, "committed_revision")?)
            }
            "maintenance_migration" => Some(counter(receipt, "committed_revision")?),
            _ => return Err(invalid("unknown operation receipt kind")),
        };
        if let Some(committed) = committed {
            if committed > revision
                || committed < prior_commit
                || (kind == "maintenance_migration" && committed <= prior_commit)
            {
                return Err(invalid("receipt chronology is invalid"));
            }
            prior_commit = committed;
        }
    }
    if creation_count != 1
        || receipts.first().is_none_or(|receipt| {
            !matches!(receipt["operation_kind"].as_str(), Some("creation"))
                || receipt["receipt_sequence"] != "0"
        })
    {
        return Err(invalid("checkpoint creation evidence is invalid"));
    }
    validate_receipt_retention(value, receipts, &next_receipt)?;

    let mut mailbox_events = BTreeMap::new();
    if value["root_record"]["status"] == "retained" {
        let aggregate = &value["root_record"]["aggregate_state"];
        if value["root_instance_id"] != aggregate["root_instance_id"]
            || creation_id != aggregate["creation_id"].as_str()
        {
            return Err(invalid("root or creation identity is inconsistent"));
        }
        if revision == Counter::zero()
            && receipts.len() == 1
            && receipts[0]["operation_kind"] == "creation"
            && receipts[0]["resulting_aggregate_state_digest"]
                != aggregate["aggregate_state_digest"]
        {
            return Err(invalid(
                "creation receipt aggregate digest attestation is invalid",
            ));
        }
        let next_acceptance = counter(aggregate, "next_acceptance_sequence")?;
        let next_queue = counter(aggregate, "next_queue_sequence")?;
        if acceptance_sequences
            .iter()
            .any(|acceptance| acceptance >= &next_acceptance)
            || terminal_by_event.values().any(|receipt| {
                counter(receipt, "acceptance_sequence").unwrap() >= next_acceptance
                    || counter(receipt, "final_queue_sequence").unwrap() >= next_queue
            })
        {
            return Err(invalid("event allocation exceeds aggregate counters"));
        }
        validate_migration_audits(value, aggregate)?;
        validate_maintenance_receipts(value, Some(aggregate))?;
        validate_mailboxes(
            value,
            aggregate,
            &acceptance_by_event,
            receipts,
            &mut mailbox_events,
        )?;
    }
    if value["root_record"]["status"] == "tombstone" {
        validate_maintenance_receipts(value, None)?;
    }

    let mut tombstone_ids = BTreeSet::new();
    let mut prior_tombstone_sequence = None;
    for tombstone in value["event_identity_tombstones"].as_array().unwrap() {
        let event_id = tombstone["event_id"].as_str().unwrap();
        let terminal_sequence = counter(tombstone, "terminal_receipt_sequence")?;
        if !tombstone_ids.insert(event_id)
            || mailbox_events.contains_key(event_id)
            || terminal_by_event.contains_key(event_id)
            || acceptance_by_event.contains_key(event_id)
            || terminal_sequence >= next_receipt
            || prior_tombstone_sequence
                .as_ref()
                .is_some_and(|prior| prior >= &terminal_sequence)
        {
            return Err(invalid("event tombstone identity is invalid"));
        }
        prior_tombstone_sequence = Some(terminal_sequence);
    }
    if value["root_record"]["status"] == "tombstone"
        && value["root_record"]["creation_id"].as_str() != creation_id
    {
        return Err(invalid("root tombstone creation identity is invalid"));
    }
    if let Some(cutoff) = value["replay_retention"]["pruned_through_receipt_sequence"].as_str() {
        let cutoff = Counter::from_decimal(cutoff).map_err(invalid)?;
        if value["operation_receipts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| {
                r["receipt_sequence"] != "0" && counter(r, "receipt_sequence").unwrap() <= cutoff
            })
        {
            return Err(invalid("checkpoint pruning claim is invalid"));
        }
    }
    validate_terminal_relationships(
        value,
        receipts,
        &acceptance_by_event,
        &terminal_by_event,
        &mailbox_events,
    )?;
    validate_emission_and_outbox_relationships(value, receipts, &terminal_by_event)?;
    Ok(())
}

fn validate_receipt_retention(
    checkpoint: &Value,
    receipts: &[Value],
    next_receipt: &Counter,
) -> Result<(), ArtifactError> {
    let cutoff = checkpoint["replay_retention"]["pruned_through_receipt_sequence"]
        .as_str()
        .map(Counter::from_decimal)
        .transpose()
        .map_err(invalid)?;
    if cutoff.as_ref().is_some_and(|cutoff| cutoff >= next_receipt) {
        return Err(invalid("receipt retention cutoff reaches its next counter"));
    }
    let mut expected = cutoff.unwrap_or_else(|| Counter::from(0_u64));
    expected.allocate();
    for receipt in receipts.iter().skip(1) {
        if counter(receipt, "receipt_sequence")? != expected {
            return Err(invalid("receipt retention contains an unattested gap"));
        }
        expected.allocate();
    }
    if &expected != next_receipt {
        return Err(invalid("next receipt sequence contains an unattested gap"));
    }
    Ok(())
}

fn validate_maintenance_receipts(
    checkpoint: &Value,
    aggregate: Option<&Value>,
) -> Result<(), ArtifactError> {
    let audits = checkpoint["migration_audit_records"].as_array().unwrap();
    let audits_by_sequence = audits
        .iter()
        .map(|audit| (audit["migration_sequence"].as_str().unwrap(), audit))
        .collect::<BTreeMap<_, _>>();
    let mut operation_ids = BTreeSet::new();
    let mut referenced_sequences = BTreeSet::new();
    let _ = aggregate;
    for receipt in checkpoint["operation_receipts"].as_array().unwrap() {
        if receipt["operation_kind"] != "maintenance_migration" {
            continue;
        }
        let operation_id = receipt["operation_id"].as_str().unwrap();
        if !operation_ids.insert(operation_id) {
            return Err(invalid("maintenance operation identity is duplicated"));
        }
        let sequences = receipt["migration_sequences"].as_array().unwrap();
        let selected = sequences
            .iter()
            .map(|sequence| {
                let sequence = sequence.as_str().unwrap();
                if !referenced_sequences.insert(sequence) {
                    return Err(invalid("migration audit has multiple receipt references"));
                }
                audits_by_sequence
                    .get(sequence)
                    .copied()
                    .ok_or_else(|| invalid("maintenance receipt references absent audit"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        match receipt["result_code"].as_str().unwrap() {
            "migration_no_operation" => {
                if !selected.is_empty()
                    || receipt["source_aggregate_state_digest"]
                        != receipt["resulting_aggregate_state_digest"]
                {
                    return Err(invalid("no-operation maintenance receipt is inconsistent"));
                }
                if !maintenance_request_digest_matches(
                    checkpoint,
                    receipt,
                    operation_id,
                    receipt["target_validated_bundle_fingerprint"]
                        .as_str()
                        .unwrap(),
                    &[],
                )? {
                    return Err(invalid("maintenance request digest is inconsistent"));
                }
            }
            "migration_applied" => {
                if selected.is_empty()
                    || selected.windows(2).any(|pair| {
                        Counter::from_decimal(pair[0]["migration_sequence"].as_str().unwrap())
                            .is_ok_and(|mut left| {
                                left.allocate();
                                Counter::from_decimal(
                                    pair[1]["migration_sequence"].as_str().unwrap(),
                                )
                                .is_ok_and(|right| right != left)
                            })
                    })
                    || selected[0]["source_aggregate_state_digest"]
                        != receipt["source_aggregate_state_digest"]
                    || selected.last().unwrap()["target_aggregate_state_digest"]
                        != receipt["resulting_aggregate_state_digest"]
                    || selected.windows(2).any(|pair| {
                        pair[0]["target_aggregate_state_digest"]
                            != pair[1]["source_aggregate_state_digest"]
                    })
                {
                    return Err(invalid("maintenance receipt audit chain is inconsistent"));
                }
                let target_fingerprint = selected.last().unwrap()
                    ["target_validated_bundle_fingerprint"]
                    .as_str()
                    .unwrap();
                if receipt["target_validated_bundle_fingerprint"].as_str()
                    != Some(target_fingerprint)
                {
                    return Err(invalid("maintenance target fingerprint is inconsistent"));
                }
                let descriptor_route = selected
                    .iter()
                    .map(|audit| audit["migration_descriptor_digest"].clone())
                    .collect::<Vec<_>>();
                if !maintenance_request_digest_matches(
                    checkpoint,
                    receipt,
                    operation_id,
                    target_fingerprint,
                    &descriptor_route,
                )? {
                    return Err(invalid("maintenance request digest is inconsistent"));
                }
            }
            _ => return Err(invalid("maintenance result code is invalid")),
        }
    }
    Ok(())
}

fn maintenance_request_digest_matches(
    checkpoint: &Value,
    receipt: &Value,
    operation_id: &str,
    target_fingerprint: &str,
    descriptor_route: &[Value],
) -> Result<bool, ArtifactError> {
    for maintenance_mode in [false, true] {
        let expected = jcs_hash(&json!([
            "determa-maintenance-migration-request-digest-2",
            "2",
            checkpoint["root_instance_id"],
            operation_id,
            receipt["source_aggregate_state_digest"],
            target_fingerprint,
            descriptor_route,
            maintenance_mode
        ]))
        .map_err(invalid)?;
        if receipt["request_digest"].as_str() == Some(expected.as_str()) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn validate_migration_audits(checkpoint: &Value, aggregate: &Value) -> Result<(), ArtifactError> {
    let root_instance_id = checkpoint["root_instance_id"].as_str().unwrap();
    let root_runtime_id = aggregate["root_runtime_id"].as_str().unwrap();
    let aggregate_migration_sequence = counter(aggregate, "migration_sequence")?;
    let mut observed_sequence = Counter::zero();
    let mut prior_target_digest = None;
    let mut prior_target_fingerprint = None;
    let mut first_source_digest = None;
    for audit in checkpoint["migration_audit_records"].as_array().unwrap() {
        let sequence = counter(audit, "migration_sequence")?;
        observed_sequence.allocate();
        if audit["root_instance_id"].as_str() != Some(root_instance_id)
            || audit["root_runtime_id"].as_str() != Some(root_runtime_id)
            || sequence != observed_sequence
            || prior_target_digest.is_some_and(|digest| {
                audit["source_aggregate_state_digest"].as_str() != Some(digest)
            })
            || prior_target_fingerprint.is_some_and(|fingerprint| {
                audit["source_validated_bundle_fingerprint"].as_str() != Some(fingerprint)
            })
        {
            return Err(invalid(
                "migration audit chronology or provenance is invalid",
            ));
        }
        if first_source_digest.is_none() {
            first_source_digest = audit["source_aggregate_state_digest"].as_str();
        }
        prior_target_digest = audit["target_aggregate_state_digest"].as_str();
        prior_target_fingerprint = audit["target_validated_bundle_fingerprint"].as_str();
    }
    let final_digest_is_attested = prior_target_digest
        == aggregate["aggregate_state_digest"].as_str()
        || migration_precedes_same_revision_processing(
            checkpoint,
            first_source_digest,
            aggregate["aggregate_state_digest"].as_str().unwrap(),
        )?;
    if observed_sequence != aggregate_migration_sequence
        || (aggregate_migration_sequence != Counter::zero()
            && (prior_target_fingerprint != aggregate["validated_bundle_fingerprint"].as_str()
                || !final_digest_is_attested))
    {
        return Err(invalid(
            "migration audit history is incomplete or does not attest the retained aggregate",
        ));
    }
    Ok(())
}

fn migration_precedes_same_revision_processing(
    checkpoint: &Value,
    source_digest: Option<&str>,
    current_digest: &str,
) -> Result<bool, ArtifactError> {
    let Some(source_digest) = source_digest else {
        return Ok(false);
    };
    let receipts = checkpoint["operation_receipts"].as_array().unwrap();
    let source_revision = receipts
        .iter()
        .filter(|receipt| {
            receipt["resulting_aggregate_state_digest"].as_str() == Some(source_digest)
        })
        .filter_map(|receipt| {
            receipt
                .get("committed_revision")
                .and_then(Value::as_str)
                .or_else(|| receipt.get("accepted_revision").and_then(Value::as_str))
        })
        .map(Counter::from_decimal)
        .collect::<Result<Vec<_>, _>>()
        .map_err(invalid)?
        .into_iter()
        .max();
    let Some(source_revision) = source_revision else {
        return Ok(false);
    };
    let current_revision = counter(checkpoint, "revision")?;
    if source_revision >= current_revision {
        return Ok(false);
    }
    for terminal in receipts.iter().filter(|receipt| {
        receipt["operation_kind"] == "event_terminal"
            && receipt["resulting_aggregate_state_digest"].as_str() == Some(current_digest)
            && receipt["committed_revision"] == checkpoint["revision"]
    }) {
        let event_id = terminal["event_id"].as_str().unwrap();
        let terminal_sequence = counter(terminal, "receipt_sequence")?;
        let matching_acceptance = receipts.iter().any(|acceptance| {
            acceptance["operation_kind"] == "acceptance"
                && acceptance["event_id"].as_str() == Some(event_id)
                && acceptance["request_digest"] == terminal["request_digest"]
                && acceptance["acceptance_sequence"] == terminal["acceptance_sequence"]
                && acceptance["accepted_revision"] == checkpoint["revision"]
                && counter(acceptance, "receipt_sequence")
                    .is_ok_and(|sequence| sequence < terminal_sequence)
        });
        if matching_acceptance {
            return Ok(true);
        }
    }
    Ok(false)
}

fn validate_mailboxes<'a>(
    checkpoint: &Value,
    aggregate: &'a Value,
    acceptances: &BTreeMap<&str, &'a Value>,
    receipts: &[Value],
    mailbox_events: &mut BTreeMap<&'a str, &'a Value>,
) -> Result<(), ArtifactError> {
    let root_instance_id = checkpoint["root_instance_id"].as_str().unwrap();
    let next_acceptance = counter(aggregate, "next_acceptance_sequence")?;
    let next_queue = counter(aggregate, "next_queue_sequence")?;
    let runtimes = aggregate["runtimes"].as_array().unwrap();
    let runtime_targets = runtimes
        .iter()
        .map(|runtime| {
            (
                runtime["runtime_id"].as_str().unwrap(),
                &runtime["target_identity"],
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut acceptance_allocations = BTreeSet::new();
    let mut queue_allocations = BTreeSet::new();
    for runtime in runtimes {
        let runtime_id = runtime["runtime_id"].as_str().unwrap();
        for field in ["ready_mailbox", "deferred_mailbox"] {
            let mut prior_queue = None;
            for entry in runtime[field].as_array().unwrap() {
                let envelope = &entry["envelope"];
                let event_id = envelope["event_id"].as_str().unwrap();
                let acceptance = counter(entry, "acceptance_sequence")?;
                let queue = counter(entry, "queue_sequence")?;
                if mailbox_events.insert(event_id, entry).is_some()
                    || !acceptance_allocations.insert(acceptance.clone())
                    || !queue_allocations.insert(queue.clone())
                    || acceptance >= next_acceptance
                    || queue >= next_queue
                    || prior_queue.as_ref().is_some_and(|prior| prior >= &queue)
                    || target_runtime_id(&envelope["target"])? != runtime_id
                    || target_root_instance_id(&envelope["target"]) != Some(root_instance_id)
                {
                    return Err(invalid(
                        "mailbox identity, target, allocation, or order is invalid",
                    ));
                }
                prior_queue = Some(queue);
                let parsed: crate::format1::Envelope =
                    serde_json::from_value(envelope.clone()).map_err(invalid)?;
                let expected = crate::format1::v2::envelope_digest(
                    root_instance_id,
                    entry["delivery_mode"].as_str().unwrap(),
                    &parsed,
                )?;
                if entry["envelope_digest"].as_str() != Some(expected.as_str()) {
                    return Err(invalid("mailbox envelope digest or cause is invalid"));
                }
                match entry["delivery_mode"].as_str().unwrap() {
                    "input" => {
                        if envelope["source"] != json!({"host": true})
                            || envelope["cause_id"] != envelope["event_id"]
                            || !acceptances.get(event_id).is_some_and(|receipt| {
                                receipt["request_digest"] == entry["envelope_digest"]
                                    && receipt["acceptance_sequence"]
                                        == entry["acceptance_sequence"]
                                    && receipt["delivery_mode"] == "input"
                            })
                        {
                            return Err(invalid("host mailbox provenance is invalid"));
                        }
                    }
                    "internal" => {
                        let source = envelope["source"]
                            .as_object()
                            .ok_or_else(|| invalid("internal mailbox source is not an object"))?;
                        let runtime_source = source.len() == 1
                            && source.get("runtime").is_some_and(|source| {
                                runtime_targets.values().any(|target| *target == source)
                            });
                        let system_source = source.len() == 1
                            && source.get("system").and_then(Value::as_str).is_some_and(
                                |locator| {
                                    system_locator_matches_event(
                                        locator,
                                        envelope["event"].as_str().unwrap(),
                                    )
                                },
                            );
                        let producer_valid = receipts.iter().any(|receipt| {
                            receipt["emission_references"]
                                .as_array()
                                .into_iter()
                                .flatten()
                                .any(|reference| {
                                    reference["kind"] == "internal_mailbox"
                                        && reference["event_id"] == envelope["event_id"]
                                        && reference["acceptance_sequence"]
                                            == entry["acceptance_sequence"]
                                        && reference["queue_sequence"] == entry["queue_sequence"]
                                })
                        });
                        let valid = if runtime_source || system_source {
                            envelope["cause_id"] != envelope["event_id"] && producer_valid
                        } else {
                            false
                        };
                        if !valid {
                            return Err(invalid("internal mailbox provenance is invalid"));
                        }
                    }
                    _ => return Err(invalid("mailbox delivery mode is invalid")),
                }
            }
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

fn validate_terminal_relationships(
    checkpoint: &Value,
    receipts: &[Value],
    acceptances: &BTreeMap<&str, &Value>,
    terminals: &BTreeMap<&str, &Value>,
    mailboxes: &BTreeMap<&str, &Value>,
) -> Result<(), ArtifactError> {
    for (event_id, terminal) in terminals {
        if mailboxes.contains_key(event_id) {
            return Err(invalid("event has both live and terminal locations"));
        }
        let acceptance = acceptances.get(event_id).is_some_and(|receipt| {
            receipt["request_digest"] == terminal["request_digest"]
                && receipt["acceptance_sequence"] == terminal["acceptance_sequence"]
                && counter(receipt, "receipt_sequence").unwrap()
                    < counter(terminal, "receipt_sequence").unwrap()
                && counter(receipt, "accepted_revision").unwrap()
                    <= counter(terminal, "committed_revision").unwrap()
        });
        let producer = receipts.iter().any(|receipt| {
            receipt["emission_references"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|reference| {
                    reference["kind"] == "internal_terminal"
                        && reference["event_id"].as_str() == Some(event_id)
                        && reference["acceptance_sequence"] == terminal["acceptance_sequence"]
                        && reference["terminal_receipt_sequence"] == terminal["receipt_sequence"]
                })
        });
        let prior_attestation = checkpoint["replay_retention"]["pruned_through_receipt_sequence"]
            .as_str()
            .is_some_and(|cutoff| {
                Counter::from_decimal(cutoff).unwrap()
                    < counter(terminal, "receipt_sequence").unwrap()
            });
        if (acceptance && producer) || (!acceptance && !producer && !prior_attestation) {
            return Err(invalid(
                "terminal event admission or producer evidence is invalid",
            ));
        }
    }
    Ok(())
}

fn validate_emission_and_outbox_relationships(
    checkpoint: &Value,
    receipts: &[Value],
    terminals: &BTreeMap<&str, &Value>,
) -> Result<(), ArtifactError> {
    let pending = checkpoint["pending_outbox_intents"].as_array().unwrap();
    let terminal_outbox = checkpoint["terminal_outbox_records"].as_array().unwrap();
    let effect_tombstones = checkpoint["outbox_effect_tombstones"].as_array().unwrap();
    let mut effects = BTreeSet::new();
    let mut outbox_sequences = BTreeSet::new();
    let next_terminal = counter(checkpoint, "next_outbox_terminal_sequence")?;
    let mut terminal_sequences = BTreeSet::new();
    for records in [pending, terminal_outbox] {
        let mut prior_outbox_sequence = None;
        for record in records {
            let intent = &record["intent"];
            let sequence = counter(intent, "sequence")?;
            if !effects.insert(intent["effect_id"].as_str().unwrap())
                || !outbox_sequences.insert(sequence.clone())
                || prior_outbox_sequence
                    .as_ref()
                    .is_some_and(|prior| prior >= &sequence)
                || counter(
                    record,
                    if record.get("state_revision").is_some() {
                        "state_revision"
                    } else {
                        "committed_revision"
                    },
                )? > counter(checkpoint, "revision")?
            {
                return Err(invalid(
                    "outbox identity, allocation, or chronology is invalid",
                ));
            }
            prior_outbox_sequence = Some(sequence);
            if record.get("terminal_sequence").is_some() {
                let terminal_sequence = counter(record, "terminal_sequence")?;
                if terminal_sequence >= next_terminal
                    || !terminal_sequences.insert(terminal_sequence)
                {
                    return Err(invalid("outbox terminal allocation is invalid"));
                }
            }
        }
    }
    for tombstone in effect_tombstones {
        if !effects.insert(tombstone["effect_id"].as_str().unwrap()) {
            return Err(invalid("outbox effect identity is duplicated"));
        }
    }
    for receipt in receipts {
        let Some(references) = receipt["emission_references"].as_array() else {
            continue;
        };
        for reference in references {
            match reference["kind"].as_str().unwrap() {
                "internal_mailbox" => {}
                "internal_terminal" => {
                    if !terminals
                        .get(reference["event_id"].as_str().unwrap())
                        .is_some_and(|terminal| {
                            terminal["receipt_sequence"] == reference["terminal_receipt_sequence"]
                                && terminal["acceptance_sequence"]
                                    == reference["acceptance_sequence"]
                        })
                    {
                        return Err(invalid("internal terminal reference is dangling"));
                    }
                }
                "external_outbox" => {
                    let effect_id = reference["effect_id"].as_str().unwrap();
                    if !effects.contains(effect_id) {
                        return Err(invalid("external outbox reference is dangling"));
                    }
                }
                "internal_delivery" => {}
                _ => return Err(invalid("emission reference kind is invalid")),
            }
        }
    }
    Ok(())
}

fn validate_prune_dependencies(
    receipts: &[Value],
    removed: &[&Value],
    prior: Option<&Counter>,
) -> Result<(), ArtifactError> {
    for receipt in removed {
        if receipt["operation_kind"] == "acceptance" {
            let event = receipt["event_id"].as_str().unwrap();
            if !removed
                .iter()
                .any(|r| r["operation_kind"] == "event_terminal" && r["event_id"] == event)
            {
                return Err(failure("invalid_execution_checkpoint"));
            }
        }
        for reference in receipt["emission_references"]
            .as_array()
            .into_iter()
            .flatten()
        {
            if reference["kind"] == "internal_mailbox" {
                return Err(failure("invalid_execution_checkpoint"));
            }
        }
        if receipt["operation_kind"] == "event_terminal" {
            let has_acceptance = removed.iter().any(|r| {
                r["operation_kind"] == "acceptance" && r["event_id"] == receipt["event_id"]
            });
            let has_producer = receipts.iter().any(|producer| {
                producer["emission_references"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|reference| {
                        reference["kind"] == "internal_terminal"
                            && reference["terminal_receipt_sequence"] == receipt["receipt_sequence"]
                    })
            });
            let prior_attests =
                prior.is_some_and(|p| p < &counter(receipt, "receipt_sequence").unwrap());
            if !has_acceptance && !has_producer && !prior_attests {
                return Err(failure("invalid_execution_checkpoint"));
            }
        }
    }
    Ok(())
}

fn rewrite_producer_reference(
    value: &mut Value,
    causal: &Value,
    terminal: &str,
) -> Result<(), ArtifactError> {
    let source = &causal["envelope"]["source"];
    if source.get("runtime").is_some() || source.get("system").is_some() {
        let event_id = causal["envelope"]["event_id"].as_str().unwrap();
        rewrite_producer_event_reference(value, event_id, terminal)?;
    }
    Ok(())
}

fn rewrite_producer_event_reference(
    value: &mut Value,
    event_id: &str,
    terminal: &str,
) -> Result<(), ArtifactError> {
    let mut matches = 0;
    for receipt in value["operation_receipts"].as_array_mut().unwrap() {
        if let Some(references) = receipt
            .get_mut("emission_references")
            .and_then(Value::as_array_mut)
        {
            for reference in references {
                if reference["kind"] == "internal_mailbox"
                    && reference["event_id"].as_str() == Some(event_id)
                {
                    *reference = json!({"kind":"internal_terminal","emission_index":reference["emission_index"],"event_id":reference["event_id"],"acceptance_sequence":reference["acceptance_sequence"],"terminal_receipt_sequence":terminal});
                    matches += 1;
                }
            }
        }
    }
    if matches > 1 {
        return Err(invalid("internal event has multiple producer references"));
    }
    Ok(())
}

fn retained_effect_ids(value: &Value) -> BTreeSet<&str> {
    value["pending_outbox_intents"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|item| item["intent"]["effect_id"].as_str())
        .chain(
            value["terminal_outbox_records"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|item| item["intent"]["effect_id"].as_str()),
        )
        .chain(
            value["outbox_effect_tombstones"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|item| item["effect_id"].as_str()),
        )
        .collect()
}

fn ready_head<'a>(aggregate: &'a Value, runtime_id: &str) -> Result<&'a Value, ArtifactError> {
    let runtime = aggregate["runtimes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["runtime_id"] == runtime_id)
        .ok_or_else(|| failure("invalid_instance_target"))?;
    runtime["ready_mailbox"]
        .as_array()
        .and_then(|v| v.first())
        .ok_or_else(|| failure("not_runnable"))
}

fn target_runtime_id(target: &Value) -> Result<&str, ArtifactError> {
    target
        .get("root")
        .and_then(|v| v["root_runtime_id"].as_str())
        .or_else(|| {
            target
                .get("component")
                .and_then(|v| v["component_runtime_id"].as_str())
        })
        .or_else(|| {
            target
                .get("spawned_instance")
                .and_then(|v| v["instance_id"].as_str())
        })
        .ok_or_else(|| invalid("target runtime identity is absent"))
}

fn target_root_instance_id(target: &Value) -> Option<&str> {
    target
        .get("root")
        .and_then(|v| v["root_instance_id"].as_str())
        .or_else(|| {
            target
                .get("component")
                .and_then(|v| v["root_instance_id"].as_str())
        })
        .or_else(|| {
            target
                .get("spawned_instance")
                .and_then(|v| v["root_instance_id"].as_str())
        })
}

fn guard(
    checkpoint: &ExecutionCheckpoint,
    revision: Option<&str>,
    digest: Option<&str>,
) -> Result<(), ArtifactError> {
    if revision.is_some_and(|expected| checkpoint.value["revision"].as_str() != Some(expected))
        || digest.is_some_and(|expected| {
            checkpoint.value["execution_checkpoint_digest"].as_str() != Some(expected)
        })
    {
        return Err(failure("checkpoint_revision_conflict"));
    }
    Ok(())
}

pub(crate) fn validate_mutation_guard(
    checkpoint: &ExecutionCheckpoint,
    expected_revision: &str,
    expected_checkpoint_digest: &str,
) -> Result<(), ArtifactError> {
    guard(
        checkpoint,
        Some(expected_revision),
        Some(expected_checkpoint_digest),
    )
}

fn seal_checkpoint(value: &mut Value) -> Result<(), ArtifactError> {
    value["operation_receipts"]
        .as_array_mut()
        .unwrap()
        .sort_by_key(|r| Counter::from_decimal(r["receipt_sequence"].as_str().unwrap()).unwrap());
    value["execution_checkpoint_digest"] = json!(checkpoint_digest(value)?);
    Ok(())
}

fn seal_and_validate_checkpoint(value: &mut Value) -> Result<(), ArtifactError> {
    seal_checkpoint(value)?;
    validate_v2_schema(
        value,
        include_str!("../../schema/execution-checkpoint-v2.schema.json"),
        &[(
            "https://determa.dev/state/schema/aggregate-state-v2.schema.json",
            include_str!("../../schema/aggregate-state-v2.schema.json"),
        )],
        "invalid_execution_checkpoint",
    )?;
    validate_semantics(value)
}

fn checkpoint_digest(value: &Value) -> Result<String, ArtifactError> {
    let mut unsigned = value.clone();
    unsigned
        .as_object_mut()
        .ok_or_else(|| invalid("checkpoint must be an object"))?
        .remove("execution_checkpoint_digest");
    jcs_hash(&json!(["determa-execution-checkpoint-digest-2", unsigned]))
        .map_err(|e| invalid(e.to_string()))
}

fn outbox_intent_digest(
    root_instance_id: &str,
    intent: &OutboxIntent,
) -> Result<String, ArtifactError> {
    jcs_hash(&json!([
        "determa-outbox-intent-digest-2",
        "2",
        root_instance_id,
        intent
    ]))
    .map_err(invalid)
}

fn counter(value: &Value, field: &str) -> Result<Counter, ArtifactError> {
    Counter::from_decimal(
        value[field]
            .as_str()
            .ok_or_else(|| invalid(format!("{field} is absent")))?,
    )
    .map_err(invalid)
}
fn allocate(value: &mut Value, field: &str) -> Result<String, ArtifactError> {
    let mut c = counter(value, field)?;
    let a = c.allocate().to_string();
    value[field] = json!(c.to_string());
    Ok(a)
}
fn incremented(value: &Value) -> Result<Value, ArtifactError> {
    let mut c = Counter::from_decimal(value.as_str().ok_or_else(|| invalid("counter is absent"))?)
        .map_err(invalid)?;
    c.allocate();
    Ok(json!(c.to_string()))
}
fn invalid(message: impl ToString) -> ArtifactError {
    ArtifactError::new("invalid_execution_checkpoint", message.to_string())
}
fn failure(code: &str) -> ArtifactError {
    ArtifactError::new(code, "checkpoint operation was rejected")
}
