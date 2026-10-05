use crate::format1::native::jcs_hash;
use crate::format1::strict_json;
use crate::format1::v1::{
    canonical_bytes, migrate_aggregate_v1_route_with_evidence, step_v1_with_emission_indexes,
    validate_admission_delivery_schema, validate_v1_schema,
};
use crate::format1::{
    admit, restore_aggregate, AdmissionDelivery, Aggregate, ArtifactError, Bindings, Bundle,
    Counter, DefinitionResolver, MigrationArtifactResolver, MigrationRequest, ResourceLimits,
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

pub fn create_execution_checkpoint_v1(
    bundle: &Bundle,
    machine_id: &str,
    root_instance_id: &str,
    creation_id: &str,
    bindings: &Bindings,
    supplied_request_digest: Option<&str>,
    replay_retention: Value,
) -> Result<ExecutionCheckpoint, ArtifactError> {
    create_with_response(
        bundle,
        machine_id,
        root_instance_id,
        creation_id,
        bindings,
        (supplied_request_digest, None),
        replay_retention,
    )
    .map(|(checkpoint, _)| checkpoint)
}

pub(crate) fn create_with_response(
    bundle: &Bundle,
    machine_id: &str,
    root_instance_id: &str,
    creation_id: &str,
    bindings: &Bindings,
    binding_evidence: (Option<&str>, Option<&Value>),
    replay_retention: Value,
) -> Result<(ExecutionCheckpoint, Value), ArtifactError> {
    let (supplied_request_digest, normalized_bindings) = binding_evidence;
    let request_digest = if let Some(normalized_bindings) = normalized_bindings {
        let machine = bundle
            .machines
            .get(machine_id)
            .ok_or_else(|| invalid("missing creation machine"))?;
        jcs_hash(&json!([
            "determa-creation-request-digest-1",
            "1",
            bundle.fingerprint,
            bundle.namespace,
            machine_id,
            machine.version.to_string(),
            root_instance_id,
            creation_id,
            normalized_bindings
        ]))
        .map_err(|e| invalid(e.to_string()))?
    } else {
        creation_request_digest(bundle, machine_id, root_instance_id, creation_id, bindings)?
    };
    if supplied_request_digest.is_some_and(|supplied| supplied != request_digest) {
        return Err(invalid(
            "supplied creation request digest does not match canonical content",
        ));
    }
    let created = crate::format1::v1::create_v1_with_evidence(
        bundle,
        machine_id,
        root_instance_id,
        creation_id,
        bindings,
    )?;
    let aggregate = created.aggregate.value().clone();
    let mut value = json!({
        "execution_checkpoint_format": "determa.execution_checkpoint",
        "execution_checkpoint_schema_version": 1,
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
    let checkpoint = restore_value(value, &resolver)?;
    let response = json!({"checkpoint":checkpoint.value(),
        "creation_receipt":checkpoint.value()["operation_receipts"][0],
        "status":created.status,"emissions":created.emissions,
        "lifecycle_dispositions":created.lifecycle_dispositions,"fault":created.fault});
    Ok((checkpoint, response))
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
        "determa-creation-request-digest-1",
        "1",
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

pub fn checkpoint_admit_v1(
    bundle: &Bundle,
    checkpoint: &ExecutionCheckpoint,
    deliveries: &[Value],
    expected_revision: Option<&str>,
    expected_checkpoint_digest: Option<&str>,
) -> Result<Value, ArtifactError> {
    checkpoint_admit_v1_with_optional_bundle(
        Some(bundle),
        checkpoint,
        deliveries,
        expected_revision,
        expected_checkpoint_digest,
    )
}

pub(super) fn checkpoint_admit_v1_with_optional_bundle(
    bundle: Option<&Bundle>,
    checkpoint: &ExecutionCheckpoint,
    deliveries: &[Value],
    expected_revision: Option<&str>,
    expected_checkpoint_digest: Option<&str>,
) -> Result<Value, ArtifactError> {
    if deliveries.is_empty() {
        return Err(failure("malformed_delivery"));
    }
    let tombstoned = checkpoint.value["root_record"]["status"] == "tombstone";
    let root_instance_id = checkpoint.value["root_instance_id"].as_str().unwrap();
    let parsed = deliveries
        .iter()
        .map(|delivery| {
            validate_admission_delivery_schema(delivery)
                .map_err(|_| failure("malformed_delivery"))?;
            serde_json::from_value::<AdmissionDelivery>(delivery.clone())
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
        let candidate = crate::format1::v1::envelope_digest(
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

pub fn checkpoint_step_v1(
    bundle: &Bundle,
    checkpoint: &ExecutionCheckpoint,
    request: &ProcessingRequest,
    expected_revision: Option<&str>,
    expected_checkpoint_digest: Option<&str>,
) -> Result<Value, ArtifactError> {
    checkpoint_step_v1_with_core(
        bundle,
        checkpoint,
        request,
        expected_revision,
        expected_checkpoint_digest,
    )
    .map(|(checkpoint, _)| checkpoint)
}

pub(crate) fn checkpoint_step_v1_with_core(
    bundle: &Bundle,
    checkpoint: &ExecutionCheckpoint,
    request: &ProcessingRequest,
    expected_revision: Option<&str>,
    expected_checkpoint_digest: Option<&str>,
) -> Result<(Value, Option<Value>), ArtifactError> {
    if let Some(replay) = checkpoint_step_replay(checkpoint, request)? {
        return Ok((replay, None));
    }
    guard(checkpoint, expected_revision, expected_checkpoint_digest)?;
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
        step_v1_with_emission_indexes(bundle, aggregate, &request.target_runtime_id)?;
    let updated = apply_step_result(&checkpoint.value, &causal, core.clone(), emission_indexes)?;
    Ok((updated, Some(core)))
}

pub(crate) fn checkpoint_step_replay(
    checkpoint: &ExecutionCheckpoint,
    request: &ProcessingRequest,
) -> Result<Option<Value>, ArtifactError> {
    if !matches!(request.processing_mode.as_str(), "delayed" | "foreground") {
        return Err(failure("invalid_execution_checkpoint"));
    }
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
            Ok(Some(receipt.clone()))
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
            Ok(Some(tombstone.clone()))
        } else {
            Err(failure("event_id_conflict"))
        };
    }
    Ok(None)
}

pub(crate) fn apply_step_result(
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
    synchronize_internal_mailbox_references(&mut value)?;
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

fn synchronize_internal_mailbox_references(checkpoint: &mut Value) -> Result<(), ArtifactError> {
    let mut sequences = BTreeMap::new();
    for runtime in checkpoint["root_record"]["aggregate_state"]["runtimes"]
        .as_array()
        .ok_or_else(|| invalid("aggregate runtimes are absent"))?
    {
        for field in ["ready_mailbox", "deferred_mailbox"] {
            for entry in runtime[field]
                .as_array()
                .ok_or_else(|| invalid("aggregate mailbox is absent"))?
            {
                if entry["delivery_mode"] == "internal" {
                    sequences.insert(
                        (
                            entry["envelope"]["event_id"].as_str().unwrap().to_string(),
                            entry["acceptance_sequence"].as_str().unwrap().to_string(),
                        ),
                        entry["queue_sequence"].clone(),
                    );
                }
            }
        }
    }
    for receipt in checkpoint["operation_receipts"].as_array_mut().unwrap() {
        for reference in receipt
            .get_mut("emission_references")
            .and_then(Value::as_array_mut)
            .into_iter()
            .flatten()
        {
            if reference["kind"] == "internal_mailbox" {
                let key = (
                    reference["event_id"].as_str().unwrap().to_string(),
                    reference["acceptance_sequence"]
                        .as_str()
                        .unwrap()
                        .to_string(),
                );
                if let Some(sequence) = sequences.get(&key) {
                    reference["queue_sequence"] = sequence.clone();
                }
            }
        }
    }
    Ok(())
}

pub fn checkpoint_process(
    bundle: &Bundle,
    checkpoint: &ExecutionCheckpoint,
    delivery: Value,
    processing_mode: &str,
    expected_revision: Option<&str>,
    expected_checkpoint_digest: Option<&str>,
) -> Result<Value, ArtifactError> {
    checkpoint_process_with_core(
        bundle,
        checkpoint,
        delivery,
        processing_mode,
        expected_revision,
        expected_checkpoint_digest,
    )
    .map(|(checkpoint, _)| checkpoint)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn checkpoint_process_with_core(
    bundle: &Bundle,
    checkpoint: &ExecutionCheckpoint,
    delivery: Value,
    processing_mode: &str,
    expected_revision: Option<&str>,
    expected_checkpoint_digest: Option<&str>,
) -> Result<(Value, Option<Value>), ArtifactError> {
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
) -> Result<(Value, Option<Value>), ArtifactError> {
    if let Some(replay) = checkpoint_process_replay(checkpoint, &delivery, processing_mode)? {
        return Ok((replay, None));
    }
    guard(checkpoint, expected_revision, expected_checkpoint_digest)?;
    let event_id = delivery["envelope"]["event_id"]
        .as_str()
        .ok_or_else(|| failure("malformed_delivery"))?
        .to_string();
    let admitted = checkpoint_admit_v1(
        bundle,
        checkpoint,
        &[delivery],
        expected_revision,
        expected_checkpoint_digest,
    )?;
    if admitted["execution_checkpoint_format"] != "determa.execution_checkpoint" {
        return Ok((admitted, None));
    }
    let admitted_value = admitted;
    let aggregate = restore_aggregate(
        &canonical_bytes(&admitted_value["root_record"]["aggregate_state"])?,
        resolver,
    )
    .map_err(|error| invalid(error.message))?;
    let mut selected = None;
    for runtime in aggregate.value()["runtimes"].as_array().unwrap() {
        if runtime["ready_mailbox"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["envelope"]["event_id"].as_str() == Some(&event_id))
        {
            selected = runtime["ready_mailbox"]
                .as_array()
                .unwrap()
                .first()
                .map(|entry| (runtime, entry));
            break;
        }
    }
    let (runtime, causal) = selected.ok_or_else(|| invalid("admitted event is not runnable"))?;
    let causal = causal.clone();
    let (core, emission_indexes) =
        step_v1_with_emission_indexes(bundle, &aggregate, runtime["runtime_id"].as_str().unwrap())?;
    let stepped = apply_step_result(&admitted_value, &causal, core.clone(), emission_indexes)?;
    if stepped["execution_checkpoint_format"] != "determa.execution_checkpoint" {
        return Ok((stepped, Some(core)));
    }
    Ok((collapse_process_revision(checkpoint, stepped)?, Some(core)))
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
    checkpoint_process_with_migration_with_core(
        checkpoint,
        migration,
        resolver,
        limits,
        delivery,
        processing_mode,
        expected_revision,
        expected_checkpoint_digest,
    )
    .map(|(checkpoint, _)| checkpoint)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn checkpoint_process_with_migration_with_core(
    checkpoint: &ExecutionCheckpoint,
    migration: &MigrationRequest,
    resolver: &impl MigrationArtifactResolver,
    limits: &ResourceLimits,
    delivery: Value,
    processing_mode: &str,
    expected_revision: Option<&str>,
    expected_checkpoint_digest: Option<&str>,
) -> Result<(Value, Option<Value>), ArtifactError> {
    if let Some(replay) = checkpoint_process_replay(checkpoint, &delivery, processing_mode)? {
        return Ok((replay, None));
    }
    guard(checkpoint, expected_revision, expected_checkpoint_digest)?;
    let aggregate = checkpoint
        .aggregate
        .as_ref()
        .ok_or_else(|| failure("terminal_root"))?;
    let migrated =
        migrate_aggregate_v1_route_with_evidence(aggregate, migration, resolver, limits)?;
    let prepared = apply_transaction_migration(checkpoint, migrated)?;
    let prepared = restore_value(prepared, resolver)?;
    let target = resolver
        .resolve_definition(&migration.target_validated_bundle_fingerprint)
        .filter(|resolved| {
            resolved.trusted
                && resolved.bundle.fingerprint == migration.target_validated_bundle_fingerprint
        })
        .ok_or_else(|| failure("target_definition_unavailable"))?;
    let (processed, core) = checkpoint_process_resolved(
        &target.bundle,
        &prepared,
        delivery,
        processing_mode,
        Some(prepared.revision()),
        Some(prepared.digest()),
        resolver,
    )?;
    Ok((collapse_process_revision(checkpoint, processed)?, core))
}

pub(crate) fn checkpoint_process_replay(
    checkpoint: &ExecutionCheckpoint,
    delivery: &Value,
    processing_mode: &str,
) -> Result<Option<Value>, ArtifactError> {
    if !matches!(processing_mode, "delayed" | "foreground") {
        return Err(failure("invalid_execution_checkpoint"));
    }
    validate_admission_delivery_schema(delivery).map_err(|_| failure("malformed_delivery"))?;
    let parsed: AdmissionDelivery =
        serde_json::from_value(delivery.clone()).map_err(|_| failure("malformed_delivery"))?;
    let root_instance_id = checkpoint.root_instance_id();
    if target_root_instance_id(&parsed.envelope.target).is_some_and(|root| root != root_instance_id)
    {
        return Err(failure("wrong_root"));
    }
    let request_digest = crate::format1::v1::envelope_digest(
        root_instance_id,
        &parsed.delivery_mode,
        &parsed.envelope,
    )?;
    let event_id = parsed.envelope.event_id.as_str();
    let retained = retained_identity(checkpoint.value())?;
    let Some(identity) = retained.get(event_id) else {
        return Ok(None);
    };
    if identity.digest != request_digest || identity.digest != parsed.envelope_digest {
        return Err(failure("event_id_conflict"));
    }
    if let Some(receipt) = checkpoint.value()["operation_receipts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|receipt| {
            receipt["operation_kind"] == "event_terminal"
                && receipt["event_id"].as_str() == Some(event_id)
        })
    {
        return Ok(Some(receipt.clone()));
    }
    Ok(Some(identity.replay.clone()))
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
    synchronize_internal_mailbox_references(&mut value)?;
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

pub fn checkpoint_prune_v1(
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
    let pending_effect_ids = checkpoint.value["pending_outbox_intents"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|record| record["intent"]["effect_id"].as_str())
        .collect::<BTreeSet<_>>();
    if removable.iter().any(|receipt| {
        receipt["emission_references"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|reference| {
                reference["kind"] == "external_outbox"
                    && reference["effect_id"]
                        .as_str()
                        .is_some_and(|effect_id| pending_effect_ids.contains(effect_id))
            })
    }) {
        return Err(failure("invalid_execution_checkpoint"));
    }
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
                "request_digest_domain": "determa-inbox-envelope-digest-1",
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
    let retained_effect_ids = value["operation_receipts"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|receipt| {
            receipt["emission_references"]
                .as_array()
                .into_iter()
                .flatten()
        })
        .filter(|reference| reference["kind"] == "external_outbox")
        .filter_map(|reference| reference["effect_id"].as_str())
        .map(str::to_string)
        .collect::<BTreeSet<_>>();
    value["terminal_outbox_records"]
        .as_array_mut()
        .unwrap()
        .retain(|record| {
            record["intent"]["effect_id"]
                .as_str()
                .is_some_and(|effect_id| retained_effect_ids.contains(effect_id))
        });
    value["outbox_effect_tombstones"]
        .as_array_mut()
        .unwrap()
        .retain(|record| {
            record["effect_id"]
                .as_str()
                .is_some_and(|effect_id| retained_effect_ids.contains(effect_id))
        });
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
    seal_and_validate_checkpoint(&mut value)?;
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
    let migrated = migrate_aggregate_v1_route_with_evidence(aggregate, request, resolver, limits)?;
    apply_checkpoint_migration_v1(
        checkpoint,
        migrated,
        operation_id,
        request_digest,
        &request.target_validated_bundle_fingerprint,
    )
}

fn apply_checkpoint_migration_v1(
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
    synchronize_internal_mailbox_references(&mut value)?;
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
    let acceptance = value["operation_receipts"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|receipt| receipt["operation_kind"] == "acceptance")
        .map(|receipt| (receipt["event_id"].as_str().unwrap(), receipt))
        .collect::<BTreeMap<_, _>>();
    if value["root_record"]["status"] == "retained" {
        for runtime in value["root_record"]["aggregate_state"]["runtimes"]
            .as_array()
            .unwrap()
        {
            for (field, location) in [("ready_mailbox", "ready"), ("deferred_mailbox", "deferred")]
            {
                for entry in runtime[field].as_array().unwrap() {
                    let event_id = entry["envelope"]["event_id"].as_str().unwrap().to_string();
                    let evidence = acceptance.get(event_id.as_str()).copied().cloned().unwrap_or_else(|| json!({
                        "result": "replay", "event_id": event_id,
                        "acceptance_sequence": entry["acceptance_sequence"], "location": location
                    }));
                    result.insert(
                        event_id.clone(),
                        Identity {
                            digest: entry["envelope_digest"].as_str().unwrap().to_string(),
                            replay: evidence,
                        },
                    );
                }
            }
        }
    }
    for receipt in value["operation_receipts"].as_array().unwrap() {
        if receipt["operation_kind"] == "event_terminal" {
            let event_id = receipt["event_id"].as_str().unwrap().to_string();
            let acceptance_sequence = receipt["acceptance_sequence"].as_str().unwrap();
            let acceptance_receipt = acceptance
                .get(event_id.as_str())
                .filter(|r| r["acceptance_sequence"].as_str() == Some(acceptance_sequence));
            let replay = acceptance_receipt
                .copied()
                .cloned()
                .unwrap_or_else(|| receipt.clone());
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
        result.insert(
            item["event_id"].as_str().unwrap().to_string(),
            Identity {
                digest: item["request_digest"].as_str().unwrap().to_string(),
                replay: item.clone(),
            },
        );
    }
    Ok(result)
}

fn restore_value(
    value: Value,
    resolver: &(impl DefinitionResolver + ?Sized),
) -> Result<ExecutionCheckpoint, ArtifactError> {
    validate_v1_schema(
        &value,
        include_str!("../../schema/execution-checkpoint-v1.schema.json"),
        &[(
            "https://determa.dev/state/schema/aggregate-state-v1.schema.json",
            include_str!("../../schema/aggregate-state-v1.schema.json"),
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
    let mut prior_effective_revision = Counter::zero();
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
        let effective_revision = match kind {
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
                Some(accepted)
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
        if let Some(effective_revision) = effective_revision {
            if effective_revision > revision
                || effective_revision < prior_effective_revision
                || (kind == "maintenance_migration"
                    && effective_revision <= prior_effective_revision)
            {
                return Err(invalid("receipt chronology is invalid"));
            }
            prior_effective_revision = effective_revision;
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
    let root_runtime_id = value["root_record"]["status"]
        .as_str()
        .filter(|status| *status == "retained")
        .map_or(&value["root_record"]["root_runtime_id"], |_| {
            &value["root_record"]["aggregate_state"]["root_runtime_id"]
        });
    let mut prior_audit_sequence = None;
    for audit in value["migration_audit_records"].as_array().unwrap() {
        let sequence = counter(audit, "migration_sequence")?;
        if audit["root_instance_id"] != value["root_instance_id"]
            || audit["root_runtime_id"] != *root_runtime_id
            || prior_audit_sequence
                .as_ref()
                .is_some_and(|prior| prior >= &sequence)
        {
            return Err(invalid("migration audit identity or order is invalid"));
        }
        prior_audit_sequence = Some(sequence);
    }
    if acceptance_by_event.keys().any(|event_id| {
        !mailbox_events.contains_key(event_id) && !terminal_by_event.contains_key(event_id)
    }) {
        return Err(invalid("acceptance receipt has no live or terminal event"));
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
            || terminal_by_event.values().any(|terminal| {
                terminal["receipt_sequence"] == tombstone["terminal_receipt_sequence"]
            })
            || prior_tombstone_sequence
                .as_ref()
                .is_some_and(|prior| prior >= &terminal_sequence)
        {
            return Err(invalid("event tombstone identity is invalid"));
        }
        prior_tombstone_sequence = Some(terminal_sequence);
    }
    let aggregate = value["root_record"].get("aggregate_state");
    let next_acceptance = aggregate
        .map(|aggregate| counter(aggregate, "next_acceptance_sequence"))
        .transpose()?;
    let next_queue = aggregate
        .map(|aggregate| counter(aggregate, "next_queue_sequence"))
        .transpose()?;
    let mut acceptance_owners = BTreeMap::new();
    let mut record_acceptance = |event_id: &str, sequence: Counter| -> Result<(), ArtifactError> {
        if next_acceptance
            .as_ref()
            .is_some_and(|next| sequence >= *next)
            || acceptance_owners
                .insert(sequence.clone(), event_id.to_string())
                .is_some_and(|prior| prior != event_id)
        {
            return Err(invalid("acceptance allocation owner is invalid"));
        }
        Ok(())
    };
    let mut queue_allocations = BTreeSet::new();
    for (event_id, entry) in &mailbox_events {
        record_acceptance(event_id, counter(entry, "acceptance_sequence")?)?;
        queue_allocations.insert(counter(entry, "queue_sequence")?);
    }
    for (event_id, receipt) in &acceptance_by_event {
        record_acceptance(event_id, counter(receipt, "acceptance_sequence")?)?;
    }
    for (event_id, receipt) in &terminal_by_event {
        record_acceptance(event_id, counter(receipt, "acceptance_sequence")?)?;
        let sequence = counter(receipt, "final_queue_sequence")?;
        if next_queue.as_ref().is_some_and(|next| sequence >= *next)
            || !queue_allocations.insert(sequence)
        {
            return Err(invalid(
                "terminal queue allocation is duplicated or invalid",
            ));
        }
    }
    for tombstone in value["event_identity_tombstones"].as_array().unwrap() {
        record_acceptance(
            tombstone["event_id"].as_str().unwrap(),
            counter(tombstone, "acceptance_sequence")?,
        )?;
    }
    let current_digest = aggregate.map_or(
        &value["root_record"]["final_aggregate_state_digest"],
        |aggregate| &aggregate["aggregate_state_digest"],
    );
    let mut terminal_digests = BTreeMap::new();
    for terminal in terminal_by_event.values() {
        let committed = counter(terminal, "committed_revision")?;
        let digest = terminal["resulting_aggregate_state_digest"]
            .as_str()
            .unwrap();
        if terminal_digests
            .insert(committed.clone(), digest)
            .is_some_and(|prior| prior != digest)
            || (committed == revision && current_digest.as_str() != Some(digest))
        {
            return Err(invalid("terminal result digest is inconsistent"));
        }
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
    validate_emission_and_outbox_relationships(
        value,
        receipts,
        &terminal_by_event,
        &mailbox_events,
    )?;
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
            "determa-maintenance-migration-request-digest-1",
            "1",
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
                let parsed: crate::format1::QueueEnvelope =
                    serde_json::from_value(envelope.clone()).map_err(invalid)?;
                let expected = crate::format1::v1::envelope_digest(
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
    mailboxes: &BTreeMap<&str, &Value>,
) -> Result<(), ArtifactError> {
    let pending = checkpoint["pending_outbox_intents"].as_array().unwrap();
    let terminal_outbox = checkpoint["terminal_outbox_records"].as_array().unwrap();
    let effect_tombstones = checkpoint["outbox_effect_tombstones"].as_array().unwrap();
    let mut effects = BTreeSet::new();
    let mut outbox_sequences = BTreeSet::new();
    let next_terminal = counter(checkpoint, "next_outbox_terminal_sequence")?;
    let mut terminal_sequences = BTreeSet::new();
    for (pending_records, records) in [(true, pending), (false, terminal_outbox)] {
        let mut prior_outbox_sequence = None;
        let mut prior_terminal_sequence = None;
        for record in records {
            let intent = &record["intent"];
            let sequence = counter(intent, "sequence")?;
            if !effects.insert(intent["effect_id"].as_str().unwrap())
                || !outbox_sequences.insert(sequence.clone())
                || (pending_records
                    && prior_outbox_sequence
                        .as_ref()
                        .is_some_and(|prior| prior >= &sequence))
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
                    || prior_terminal_sequence
                        .as_ref()
                        .is_some_and(|prior| prior >= &terminal_sequence)
                    || !terminal_sequences.insert(terminal_sequence.clone())
                {
                    return Err(invalid("outbox terminal allocation is invalid"));
                }
                prior_terminal_sequence = Some(terminal_sequence);
            }
        }
    }
    let mut prior_effect_tombstone_sequence = None;
    for tombstone in effect_tombstones {
        let sequence = counter(tombstone, "terminal_sequence")?;
        if !effects.insert(tombstone["effect_id"].as_str().unwrap())
            || sequence >= next_terminal
            || !terminal_sequences.insert(sequence.clone())
            || prior_effect_tombstone_sequence
                .as_ref()
                .is_some_and(|prior| prior >= &sequence)
        {
            return Err(invalid(
                "outbox effect identity or terminal sequence is invalid",
            ));
        }
        prior_effect_tombstone_sequence = Some(sequence);
    }
    let mut internal_references = BTreeSet::new();
    let mut outbox_references = BTreeSet::new();
    for receipt in receipts {
        let Some(references) = receipt["emission_references"].as_array() else {
            continue;
        };
        for reference in references {
            match reference["kind"].as_str().unwrap() {
                "internal_mailbox" => {
                    let event_id = reference["event_id"].as_str().unwrap();
                    if !internal_references.insert(event_id)
                        || !mailboxes.get(event_id).is_some_and(|entry| {
                            entry["delivery_mode"] == "internal"
                                && entry["acceptance_sequence"] == reference["acceptance_sequence"]
                                && entry["queue_sequence"] == reference["queue_sequence"]
                        })
                    {
                        return Err(invalid(
                            "internal mailbox reference is duplicated or dangling",
                        ));
                    }
                }
                "internal_terminal" => {
                    let event_id = reference["event_id"].as_str().unwrap();
                    let retained_terminal = terminals.get(event_id).is_some_and(|terminal| {
                        terminal["receipt_sequence"] == reference["terminal_receipt_sequence"]
                            && terminal["acceptance_sequence"] == reference["acceptance_sequence"]
                            && counter(receipt, "receipt_sequence").unwrap()
                                < counter(terminal, "receipt_sequence").unwrap()
                            && counter(receipt, "committed_revision").unwrap()
                                <= counter(terminal, "committed_revision").unwrap()
                    });
                    let pruned_terminal = checkpoint["event_identity_tombstones"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .any(|tombstone| {
                            tombstone["event_id"] == event_id
                                && tombstone["terminal_receipt_sequence"]
                                    == reference["terminal_receipt_sequence"]
                                && tombstone["acceptance_sequence"]
                                    == reference["acceptance_sequence"]
                                && counter(receipt, "receipt_sequence").unwrap()
                                    < counter(tombstone, "terminal_receipt_sequence").unwrap()
                        });
                    if !internal_references.insert(event_id)
                        || !(retained_terminal || pruned_terminal)
                    {
                        return Err(invalid("internal terminal reference is dangling"));
                    }
                }
                "external_outbox" => {
                    let effect_id = reference["effect_id"].as_str().unwrap();
                    if !effects.contains(effect_id) || !outbox_references.insert(effect_id) {
                        return Err(invalid(
                            "external outbox reference is duplicated or dangling",
                        ));
                    }
                }
                "internal_delivery" => {}
                _ => return Err(invalid("emission reference kind is invalid")),
            }
        }
    }
    if outbox_references != effects {
        return Err(invalid("outbox effect producer reference is absent"));
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
    validate_v1_schema(
        value,
        include_str!("../../schema/execution-checkpoint-v1.schema.json"),
        &[(
            "https://determa.dev/state/schema/aggregate-state-v1.schema.json",
            include_str!("../../schema/aggregate-state-v1.schema.json"),
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
    jcs_hash(&json!(["determa-execution-checkpoint-digest-1", unsigned]))
        .map_err(|e| invalid(e.to_string()))
}

fn outbox_intent_digest(
    root_instance_id: &str,
    intent: &OutboxIntent,
) -> Result<String, ArtifactError> {
    jcs_hash(&json!([
        "determa-outbox-intent-digest-1",
        "1",
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

#[cfg(test)]
mod reference_integrity_tests {
    use super::{
        checkpoint_maintenance_migration_route, checkpoint_step_v1, create_execution_checkpoint_v1,
        restore_execution_checkpoint, restore_value, ProcessingRequest,
    };
    use crate::format1::{
        load_bundle, Bindings, InMemoryDefinitionResolver, MigrationRequest, ResourceLimits,
    };
    use serde_json::{json, Value};

    #[test]
    fn maintenance_migration_recall_updates_internal_producer_reference() {
        let source_text = r#"
format: 1
namespace: test.migration_recall
events:
  loop: { direction: internal }
machines:
  - machine_id: worker
    root:
      type: composite
      deferred_event_capacity: 4
      initial: { transition_to: busy }
      states:
        busy:
          entry:
            - send: { event: loop, to: { self: true } }
          deferred_events: [loop]
          on_events: {}
"#;
        let source = load_bundle(source_text).unwrap();
        let target =
            load_bundle(&source_text.replace("          deferred_events: [loop]\n", "")).unwrap();
        let created = create_execution_checkpoint_v1(
            &source, "worker", "migration-recall", "create-migration-recall",
            &Bindings::default(), None,
            json!({"mode":"permanent","permanent_replay_eligible":true,"pruned_through_receipt_sequence":null,"policy_identifier":null}),
        ).unwrap();
        let entry =
            &created.value()["root_record"]["aggregate_state"]["runtimes"][0]["ready_mailbox"][0];
        let request = ProcessingRequest {
            target_runtime_id: created.value()["root_record"]["aggregate_state"]["runtimes"][0]
                ["runtime_id"]
                .as_str()
                .unwrap()
                .to_string(),
            event_id: entry["envelope"]["event_id"].as_str().unwrap().to_string(),
            envelope_digest: entry["envelope_digest"].as_str().unwrap().to_string(),
            acceptance_sequence: entry["acceptance_sequence"].as_str().unwrap().to_string(),
            queue_sequence: entry["queue_sequence"].as_str().unwrap().to_string(),
            processing_mode: "delayed".to_string(),
        };
        let deferred = checkpoint_step_v1(&source, &created, &request, None, None).unwrap();
        let mut resolver = InMemoryDefinitionResolver::default();
        resolver.insert(source.clone(), true);
        resolver.insert(target.clone(), true);
        let deferred = restore_value(deferred, &resolver).unwrap();
        let mut descriptor: Value = json!({
            "migration_descriptor_format": "determa.aggregate_migration",
            "migration_descriptor_schema_version": 1,
            "mode": "compatible",
            "source_machine_format": 1,
            "target_machine_format": 1,
            "mappings": {"active_states":[],"components":[],"counters":[],"history":[],"lifetime_holders":[],"machines":[],"owned_runtimes":[],"variables":[]},
            "queued_event_default": "preserve_if_compatible",
            "queued_event_rules": [],
            "resource_requirements": {"maximum_cel_ast_nodes":"0","maximum_cel_evaluation_steps":"0","maximum_cel_expression_length":"0","maximum_transformed_output_bytes":"0"},
            "terminal_policy": {"completed":"preserve","faulted":"preserve"}
        });
        descriptor["source_validated_bundle_fingerprint"] = json!(source.fingerprint);
        descriptor["target_validated_bundle_fingerprint"] = json!(target.fingerprint);
        descriptor["source_aggregate_shape_fingerprint"] =
            json!(crate::format1::migration::aggregate_shape_fingerprint(&source).unwrap());
        descriptor["target_aggregate_shape_fingerprint"] =
            json!(crate::format1::migration::aggregate_shape_fingerprint(&target).unwrap());
        descriptor
            .as_object_mut()
            .unwrap()
            .remove("migration_descriptor_digest");
        let digest =
            super::jcs_hash(&json!(["determa-migration-descriptor-1", descriptor])).unwrap();
        descriptor["migration_descriptor_digest"] = json!(digest);
        resolver.insert_descriptor(&digest, serde_json::to_vec(&descriptor).unwrap(), true);
        let migration = MigrationRequest {
            migration_route: vec![digest],
            target_validated_bundle_fingerprint: target.fingerprint.clone(),
            maintenance_mode: false,
        };
        let request_digest = super::jcs_hash(&json!([
            "determa-maintenance-migration-request-digest-1",
            "1",
            deferred.root_instance_id(),
            "maintenance-recall",
            deferred.value()["root_record"]["aggregate_state"]["aggregate_state_digest"],
            target.fingerprint,
            migration.migration_route,
            false
        ]))
        .unwrap();
        let migrated = checkpoint_maintenance_migration_route(
            &deferred,
            &migration,
            "maintenance-recall",
            &request_digest,
            &resolver,
            &ResourceLimits::default(),
            None,
            None,
        )
        .unwrap();
        let recalled =
            &migrated["root_record"]["aggregate_state"]["runtimes"][0]["ready_mailbox"][0];
        let producer = &migrated["operation_receipts"][0]["emission_references"][0];
        assert_eq!(producer["kind"], "internal_mailbox");
        assert_eq!(producer["queue_sequence"], recalled["queue_sequence"]);
        restore_execution_checkpoint(&serde_json::to_vec(&migrated).unwrap(), &resolver).unwrap();
    }
}
