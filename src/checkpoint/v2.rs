use crate::format1::strict_json;
use crate::format1::v2::{
    canonical_bytes, migrate_aggregate_v2_route_with_evidence, validate_admission_delivery_schema,
    validate_v2_schema,
};
use crate::format1::wire::jcs_hash;
use crate::format1::{
    admit_v2, restore_aggregate_v2, step_v2, upgrade_aggregate_v1_to_v2, AdmissionDelivery,
    Bindings, Bundle, Counter, DefinitionResolver, MigrationArtifactResolver, MigrationRequest,
    QueueBearingAggregate, ResourceLimits, TypedValue, Version2Error,
};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

use super::wire::{PendingOutboxState, TerminalOutboxOutcome};

#[derive(Debug, Clone, PartialEq)]
pub struct ExecutionCheckpointV2 {
    value: Value,
    aggregate: Option<QueueBearingAggregate>,
}

impl ExecutionCheckpointV2 {
    pub fn value(&self) -> &Value {
        &self.value
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Version2Error> {
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
) -> Result<ExecutionCheckpointV2, Version2Error> {
    let request_digest =
        creation_request_digest_v2(bundle, machine_id, root_instance_id, creation_id, bindings)?;
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

pub fn creation_request_digest_v2(
    bundle: &Bundle,
    machine_id: &str,
    root_instance_id: &str,
    creation_id: &str,
    bindings: &Bindings,
) -> Result<String, Version2Error> {
    let machine = bundle.machines.get(machine_id).ok_or_else(|| {
        Version2Error::new("invalid_machine", "creation machine is absent from bundle")
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

pub fn restore_execution_checkpoint_v2(
    source: &[u8],
    resolver: &(impl DefinitionResolver + ?Sized),
) -> Result<ExecutionCheckpointV2, Version2Error> {
    let value = strict_json::parse(source).map_err(invalid)?;
    restore_value(value, resolver)
}

pub fn upgrade_execution_checkpoint_v1_to_v2(
    source: &[u8],
    resolver: &(impl DefinitionResolver + ?Sized),
) -> Result<ExecutionCheckpointV2, Version2Error> {
    super::wire::restore_execution_checkpoint(source, resolver)
        .map_err(|error| Version2Error::new(error.code.as_str(), error.message))?;
    let source_value = strict_json::parse(source).map_err(invalid)?;
    let aggregate_source = canonical_bytes(&source_value["root_record"]["aggregate_state"])?;
    let aggregate = upgrade_aggregate_v1_to_v2(&aggregate_source, resolver)?;
    let mut aggregate_value = aggregate.value().clone();
    aggregate_value["next_acceptance_sequence"] = source_value["next_delivery_sequence"].clone();
    let mut next_queue = Counter::zero();
    let mut next_receipt = counter(&source_value, "next_operation_receipt_sequence")?;
    let mut receipts = source_value["operation_receipts"]
        .as_array()
        .ok_or_else(|| invalid("operation receipts are absent"))?
        .iter()
        .map(|receipt| {
            json!({
                "operation_kind": if receipt["operation_kind"] == "creation" {
                    "legacy_v1_creation"
                } else {
                    "legacy_v1_operation"
                },
                "receipt_sequence": receipt["receipt_sequence"],
                "legacy_receipt": receipt
            })
        })
        .collect::<Vec<_>>();
    let mut pending = source_value["pending_deliveries"]
        .as_array()
        .ok_or_else(|| invalid("pending deliveries are absent"))?
        .clone();
    pending.sort_by_key(|item| {
        Counter::from_decimal(item["delivery_sequence"].as_str().unwrap()).unwrap()
    });
    for delivery in pending {
        let origin = &delivery["origin"];
        let mut envelope = delivery["envelope"].clone();
        envelope["cause_id"] = envelope["event_id"].clone();
        envelope["source"] = if origin["kind"] == "host_input" {
            json!({"host": true})
        } else {
            json!({"legacy_v1_internal": {
                "producing_receipt_sequence": origin["producing_receipt_sequence"],
                "emission_index": origin["emission_index"]
            }})
        };
        let runtime_id = target_runtime_id(&envelope["target"])?;
        let queue_sequence = next_queue.allocate().to_string();
        let mode = delivery["delivery_mode"].as_str().unwrap();
        let digest = jcs_hash(&json!([
            "determa-inbox-envelope-digest-2",
            "2",
            source_value["root_instance_id"],
            mode,
            envelope
        ]))
        .map_err(|error| invalid(error.to_string()))?;
        let entry = json!({
            "acceptance_sequence": delivery["delivery_sequence"],
            "queue_sequence": queue_sequence,
            "delivery_mode": delivery["delivery_mode"],
            "envelope": envelope,
            "envelope_digest": digest,
            "deferral_count": "0"
        });
        runtime_mut(&mut aggregate_value, runtime_id)?["ready_mailbox"]
            .as_array_mut()
            .ok_or_else(|| invalid("ready mailbox is absent"))?
            .push(entry);
        let receipt_sequence = next_receipt.allocate().to_string();
        let mut receipt = json!({
            "operation_kind": "acceptance",
            "receipt_sequence": receipt_sequence,
            "event_id": delivery["envelope"]["event_id"],
            "request_digest": digest,
            "acceptance_sequence": delivery["delivery_sequence"],
            "accepted_revision": delivery["accepted_revision"],
            "delivery_mode": delivery["delivery_mode"]
        });
        if mode == "internal" {
            receipt["legacy_v1_delivery"] = json!({
                "delivery_sequence": delivery["delivery_sequence"],
                "envelope_digest": delivery["envelope_digest"],
                "origin": delivery["origin"]
            });
        }
        receipts.push(receipt);
    }
    aggregate_value["next_queue_sequence"] = json!(next_queue.to_string());
    aggregate_value = seal_aggregate(aggregate_value)?;
    let mut value = json!({
        "execution_checkpoint_format": "determa.execution_checkpoint",
        "execution_checkpoint_schema_version": 2,
        "root_instance_id": source_value["root_instance_id"],
        "revision": incremented(&source_value["revision"])? ,
        "root_record": {"status": "retained", "aggregate_state": aggregate_value},
        "replay_retention": source_value["replay_retention"],
        "next_operation_receipt_sequence": next_receipt.to_string(),
        "operation_receipts": receipts,
        "event_identity_tombstones": [],
        "pending_outbox_intents": source_value["pending_outbox_intents"],
        "next_outbox_terminal_sequence": source_value["next_outbox_terminal_sequence"],
        "terminal_outbox_records": source_value["terminal_outbox_records"],
        "outbox_effect_tombstones": source_value["outbox_effect_tombstones"],
        "migration_audit_records": source_value["migration_audit_records"]
    });
    seal_checkpoint(&mut value)?;
    restore_value(value, resolver)
}

pub fn checkpoint_admit_v2(
    bundle: &Bundle,
    checkpoint: &ExecutionCheckpointV2,
    deliveries: &[Value],
    expected_revision: Option<&str>,
    expected_checkpoint_digest: Option<&str>,
) -> Result<Value, Version2Error> {
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
    checkpoint: &ExecutionCheckpointV2,
    deliveries: &[Value],
    expected_revision: Option<&str>,
    expected_checkpoint_digest: Option<&str>,
) -> Result<Value, Version2Error> {
    let tombstoned = checkpoint.value["root_record"]["status"] == "tombstone";
    let root_instance_id = checkpoint.value["root_instance_id"].as_str().unwrap();
    let parsed = deliveries
        .iter()
        .map(|delivery| {
            let domain = delivery["request_digest_domain"]
                .as_str()
                .unwrap_or("determa-inbox-envelope-digest-2");
            if domain == "determa-inbox-envelope-digest-2" {
                validate_admission_delivery_schema(delivery)
                    .map_err(|_| failure("malformed_delivery"))?;
                let parsed = serde_json::from_value::<AdmissionDelivery>(delivery.clone())
                    .map_err(|_| failure("malformed_delivery"))?;
                Ok((domain, Some(parsed)))
            } else if domain == "determa-inbox-envelope-digest-1"
                && delivery.as_object().is_some_and(|object| {
                    object.keys().all(|key| {
                        matches!(
                            key.as_str(),
                            "delivery_mode"
                                | "envelope"
                                | "envelope_digest"
                                | "request_digest_domain"
                        )
                    })
                })
                && delivery["delivery_mode"].as_str().is_some()
                && delivery["envelope"]["event_id"].as_str().is_some()
                && delivery["envelope"]["target"].is_object()
            {
                Ok((domain, None))
            } else {
                Err(failure("malformed_delivery"))
            }
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
    for (index, (delivery, (domain, parsed))) in deliveries.iter().zip(parsed).enumerate() {
        let event_id = delivery["envelope"]["event_id"]
            .as_str()
            .ok_or_else(|| failure("malformed_delivery"))?;
        if !seen.insert(event_id.to_string()) {
            return Err(failure("duplicate_event_id_in_batch"));
        }
        let candidate = if domain == "determa-inbox-envelope-digest-1" {
            jcs_hash(&json!([
                domain,
                "1",
                root_instance_id,
                delivery["delivery_mode"],
                delivery["envelope"]
            ]))
            .map_err(|e| invalid(e.to_string()))?
        } else {
            crate::format1::v2::envelope_digest(
                root_instance_id,
                &parsed.as_ref().unwrap().delivery_mode,
                &parsed.as_ref().unwrap().envelope,
            )?
        };
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
            if domain != "determa-inbox-envelope-digest-2" {
                return Err(failure("malformed_delivery"));
            }
            fresh.push((index, parsed.unwrap()));
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
    let core = admit_v2(bundle, aggregate, &fresh_deliveries)?;
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
    checkpoint: &ExecutionCheckpointV2,
    target_runtime_id: &str,
    expected_revision: Option<&str>,
    expected_checkpoint_digest: Option<&str>,
) -> Result<Value, Version2Error> {
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
    let causal = ready_head(aggregate.value(), target_runtime_id)?.clone();
    let core = step_v2(bundle, aggregate, target_runtime_id)?;
    if core["disposition"] == "not_runnable" || core["disposition"] == "rejected" {
        return Ok(core);
    }
    let mut value = checkpoint.value.clone();
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
    rewrite_producer_reference(&mut value, &causal, &terminal_sequence)?;
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

fn append_checkpoint_emissions(
    value: &mut Value,
    emissions: &[Value],
    lifecycle_sequences: &[String],
    committed_revision: &Value,
) -> Result<Vec<Value>, Version2Error> {
    let mut references = Vec::with_capacity(emissions.len());
    for (index, emission) in emissions.iter().enumerate() {
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
                    "emission_index": index.to_string(),
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
    checkpoint: &ExecutionCheckpointV2,
    cutoff: &str,
    expected_revision: Option<&str>,
    expected_checkpoint_digest: Option<&str>,
) -> Result<Value, Version2Error> {
    let requested = Counter::from_decimal(cutoff).map_err(invalid)?;
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
        } else if receipt["operation_kind"] == "legacy_v1_operation"
            && receipt["legacy_receipt"]["operation_kind"] == "delivery"
        {
            let legacy = &receipt["legacy_receipt"];
            tombstones.push(json!({
                "event_id": legacy["event_id"],
                "request_digest": legacy["request_digest"],
                "request_digest_domain": "determa-inbox-envelope-digest-1",
                "acceptance_sequence": legacy["accepted_delivery_sequence"],
                "terminal_receipt_sequence": receipt["receipt_sequence"],
                "terminal_disposition": legacy["outcome"]["disposition"]
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
    value["replay_retention"]["pruned_through_receipt_sequence"] = json!(cutoff);
    value["revision"] = incremented(&value["revision"])?;
    seal_checkpoint(&mut value)?;
    Ok(value)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn checkpoint_maintenance_migration_v2_route(
    checkpoint: &ExecutionCheckpointV2,
    request: &MigrationRequest,
    operation_id: &str,
    request_digest: &str,
    resolver: &impl MigrationArtifactResolver,
    limits: &ResourceLimits,
    expected_revision: Option<&str>,
    expected_checkpoint_digest: Option<&str>,
) -> Result<Value, Version2Error> {
    guard(checkpoint, expected_revision, expected_checkpoint_digest)?;
    let aggregate = checkpoint
        .aggregate
        .as_ref()
        .ok_or_else(|| failure("terminal_root"))?;
    let migrated = migrate_aggregate_v2_route_with_evidence(aggregate, request, resolver, limits)?;
    apply_checkpoint_migration_v2(checkpoint, migrated, operation_id, request_digest)
}

fn apply_checkpoint_migration_v2(
    checkpoint: &ExecutionCheckpointV2,
    migrated: Value,
    operation_id: &str,
    request_digest: &str,
) -> Result<Value, Version2Error> {
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

pub fn checkpoint_update_pending_outbox_v2(
    checkpoint: &ExecutionCheckpointV2,
    effect_id: &str,
    delivery_state: PendingOutboxState,
    expected_revision: Option<&str>,
    expected_checkpoint_digest: Option<&str>,
) -> Result<Value, Version2Error> {
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

pub fn checkpoint_terminalize_outbox_v2(
    checkpoint: &ExecutionCheckpointV2,
    effect_id: &str,
    outcome: TerminalOutboxOutcome,
    expected_revision: Option<&str>,
    expected_checkpoint_digest: Option<&str>,
) -> Result<Value, Version2Error> {
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

pub fn checkpoint_compact_outbox_v2(
    checkpoint: &ExecutionCheckpointV2,
    effect_id: &str,
    expected_revision: Option<&str>,
    expected_checkpoint_digest: Option<&str>,
) -> Result<Value, Version2Error> {
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
    let intent: crate::checkpoint::OutboxIntent =
        serde_json::from_value(terminal["intent"].clone()).map_err(invalid)?;
    let intent_digest =
        crate::checkpoint::wire::outbox_intent_digest(checkpoint.root_instance_id(), &intent)
            .map_err(invalid)?;
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

pub fn checkpoint_tombstone_root_v2(
    checkpoint: &ExecutionCheckpointV2,
    operation_id: &str,
    expected_revision: Option<&str>,
    expected_checkpoint_digest: Option<&str>,
) -> Result<Value, Version2Error> {
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

fn retained_identity(value: &Value) -> Result<BTreeMap<String, Identity>, Version2Error> {
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
        } else if receipt["operation_kind"] == "legacy_v1_operation"
            && receipt["legacy_receipt"]["operation_kind"] == "delivery"
        {
            let legacy = &receipt["legacy_receipt"];
            result.insert(
                legacy["event_id"].as_str().unwrap().to_string(),
                Identity {
                    digest: legacy["request_digest"].as_str().unwrap().to_string(),
                    replay: legacy_replay(legacy, &receipt["receipt_sequence"]),
                },
            );
        }
    }
    for item in value["event_identity_tombstones"].as_array().unwrap() {
        result.insert(item["event_id"].as_str().unwrap().to_string(), Identity {
            digest: item["request_digest"].as_str().unwrap().to_string(),
            replay: if item["request_digest_domain"] == "determa-inbox-envelope-digest-1" {
                json!({
                    "result":"replay", "event_id":item["event_id"],
                    "request_digest_domain":item["request_digest_domain"],
                    "acceptance_sequence":item["acceptance_sequence"],
                    "terminal_receipt_sequence":item["terminal_receipt_sequence"],
                    "terminal_disposition":item["terminal_disposition"]
                })
            } else {
                json!({"result":"replay","terminal_receipt_sequence":item["terminal_receipt_sequence"],"terminal_disposition":item["terminal_disposition"]})
            }
        });
    }
    Ok(result)
}

fn legacy_replay(legacy: &Value, terminal_sequence: &Value) -> Value {
    json!({
        "result":"replay", "event_id":legacy["event_id"],
        "request_digest_domain":"determa-inbox-envelope-digest-1",
        "acceptance_sequence":legacy["accepted_delivery_sequence"],
        "terminal_receipt_sequence":terminal_sequence,
        "terminal_disposition":legacy["outcome"]["disposition"]
    })
}

fn restore_value(
    value: Value,
    resolver: &(impl DefinitionResolver + ?Sized),
) -> Result<ExecutionCheckpointV2, Version2Error> {
    validate_v2_schema(
        &value,
        include_str!("../../schema/execution-checkpoint-v2.schema.json"),
        &[
            (
                "https://determa.dev/state/schema/execution-checkpoint.schema.json",
                include_str!("../../schema/execution-checkpoint.schema.json"),
            ),
            (
                "https://determa.dev/state/schema/aggregate-state.schema.json",
                include_str!("../../schema/aggregate-state.schema.json"),
            ),
            (
                "https://determa.dev/state/schema/aggregate-state-v2.schema.json",
                include_str!("../../schema/aggregate-state-v2.schema.json"),
            ),
        ],
        "invalid_execution_checkpoint",
    )?;
    let aggregate = if value["root_record"]["status"] == "retained" {
        Some(
            restore_aggregate_v2(
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
        return Err(Version2Error::new(
            "execution_checkpoint_digest_mismatch",
            "checkpoint digest does not match content",
        ));
    }
    validate_semantics(&value)?;
    Ok(ExecutionCheckpointV2 { value, aggregate })
}

fn validate_semantics(value: &Value) -> Result<(), Version2Error> {
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
            "legacy_v1_creation" => {
                creation_count += 1;
                creation_id = receipt["legacy_receipt"]["creation_id"].as_str();
                Some(counter(&receipt["legacy_receipt"], "committed_revision")?)
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
            "legacy_v1_operation" => {
                if receipt["legacy_receipt"]["operation_kind"] == "delivery" {
                    let acceptance =
                        counter(&receipt["legacy_receipt"], "accepted_delivery_sequence")?;
                    if !acceptance_sequences.insert(acceptance) {
                        return Err(invalid("acceptance identity is duplicated"));
                    }
                }
                Some(counter(&receipt["legacy_receipt"], "committed_revision")?)
            }
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
            !matches!(
                receipt["operation_kind"].as_str(),
                Some("creation" | "legacy_v1_creation")
            ) || receipt["receipt_sequence"] != "0"
        })
    {
        return Err(invalid("checkpoint creation evidence is invalid"));
    }
    validate_receipt_retention(value, receipts, &next_receipt)?;
    validate_legacy_acceptance_relationships(receipts, &acceptance_by_event)?;

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
) -> Result<(), Version2Error> {
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
) -> Result<(), Version2Error> {
    let audits = checkpoint["migration_audit_records"].as_array().unwrap();
    let audits_by_sequence = audits
        .iter()
        .map(|audit| (audit["migration_sequence"].as_str().unwrap(), audit))
        .collect::<BTreeMap<_, _>>();
    let mut operation_ids = BTreeSet::new();
    let mut referenced_sequences = BTreeSet::new();
    let mut current_fingerprint = audits
        .first()
        .and_then(|audit| audit["source_validated_bundle_fingerprint"].as_str())
        .or_else(|| {
            aggregate.and_then(|aggregate| aggregate["validated_bundle_fingerprint"].as_str())
        });
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
                if let Some(fingerprint) = current_fingerprint {
                    if !maintenance_request_digest_matches(
                        checkpoint,
                        receipt,
                        operation_id,
                        fingerprint,
                        &[],
                    )? {
                        return Err(invalid("maintenance request digest is inconsistent"));
                    }
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
                current_fingerprint = Some(target_fingerprint);
            }
            _ => return Err(invalid("maintenance result code is invalid")),
        }
    }
    if checkpoint["replay_retention"]["mode"] == "permanent"
        && referenced_sequences.len() != audits.len()
    {
        return Err(invalid(
            "permanent migration audit lacks maintenance receipt",
        ));
    }
    Ok(())
}

fn maintenance_request_digest_matches(
    checkpoint: &Value,
    receipt: &Value,
    operation_id: &str,
    target_fingerprint: &str,
    descriptor_route: &[Value],
) -> Result<bool, Version2Error> {
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

fn validate_legacy_acceptance_relationships(
    receipts: &[Value],
    acceptances: &BTreeMap<&str, &Value>,
) -> Result<(), Version2Error> {
    for acceptance in acceptances
        .values()
        .filter(|receipt| receipt["delivery_mode"] == "internal")
    {
        let evidence = &acceptance["legacy_v1_delivery"];
        let origin = &evidence["origin"];
        let producer_sequence = origin["producing_receipt_sequence"]
            .as_str()
            .ok_or_else(|| invalid("legacy internal producer sequence is absent"))?;
        let emission_index = origin["emission_index"]
            .as_str()
            .ok_or_else(|| invalid("legacy internal emission index is absent"))?;
        if origin["kind"] != "internal_emission"
            || evidence["delivery_sequence"] != acceptance["acceptance_sequence"]
            || Counter::from_decimal(producer_sequence).map_err(invalid)?
                >= counter(acceptance, "receipt_sequence")?
        {
            return Err(invalid("legacy delivery origin is invalid"));
        }
        let producer = receipts
            .iter()
            .find(|receipt| receipt["receipt_sequence"].as_str() == Some(producer_sequence))
            .ok_or_else(|| invalid("legacy delivery producer receipt is absent"))?;
        if !matches!(
            producer["operation_kind"].as_str(),
            Some("legacy_v1_creation" | "legacy_v1_operation")
        ) {
            return Err(invalid(
                "legacy delivery producer is not a wrapped v1 receipt",
            ));
        }
        let matching = producer["legacy_receipt"]["emission_references"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|reference| {
                reference["kind"] == "internal_delivery"
                    && reference["emission_index"].as_str() == Some(emission_index)
                    && reference["delivery_sequence"] == evidence["delivery_sequence"]
                    && reference["event_id"] == acceptance["event_id"]
            })
            .count();
        if matching != 1 {
            return Err(invalid("wrapped v1 producer reference is invalid"));
        }
    }
    Ok(())
}

fn validate_migration_audits(checkpoint: &Value, aggregate: &Value) -> Result<(), Version2Error> {
    let root_instance_id = checkpoint["root_instance_id"].as_str().unwrap();
    let root_runtime_id = aggregate["root_runtime_id"].as_str().unwrap();
    let aggregate_migration_sequence = counter(aggregate, "migration_sequence")?;
    let mut observed_sequence = Counter::zero();
    let mut prior_target_digest = None;
    let mut prior_target_fingerprint = None;
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
        prior_target_digest = audit["target_aggregate_state_digest"].as_str();
        prior_target_fingerprint = audit["target_validated_bundle_fingerprint"].as_str();
    }
    if observed_sequence != aggregate_migration_sequence
        || (aggregate_migration_sequence != Counter::zero()
            && (prior_target_fingerprint != aggregate["validated_bundle_fingerprint"].as_str()
                || prior_target_digest != aggregate["aggregate_state_digest"].as_str()))
    {
        return Err(invalid(
            "migration audit history is incomplete or does not attest the retained aggregate",
        ));
    }
    Ok(())
}

fn validate_mailboxes<'a>(
    checkpoint: &Value,
    aggregate: &'a Value,
    acceptances: &BTreeMap<&str, &'a Value>,
    receipts: &[Value],
    mailbox_events: &mut BTreeMap<&'a str, &'a Value>,
) -> Result<(), Version2Error> {
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
                        let legacy_source = source.len() == 1
                            && source.get("legacy_v1_internal").is_some_and(|legacy| {
                                legacy.as_object().is_some_and(|legacy| {
                                    legacy.len() == 2
                                        && legacy["producing_receipt_sequence"].is_string()
                                        && legacy["emission_index"].is_string()
                                })
                            });
                        let acceptance = acceptances.get(event_id);
                        let acceptance_valid = acceptance.is_some_and(|receipt| {
                            receipt["request_digest"] == entry["envelope_digest"]
                                && receipt["acceptance_sequence"] == entry["acceptance_sequence"]
                                && receipt["delivery_mode"] == "internal"
                                && !receipt["legacy_v1_delivery"].is_null()
                        });
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
                        let legacy_source_matches = source
                            .get("legacy_v1_internal")
                            .zip(acceptance)
                            .is_some_and(|(source, receipt)| {
                                source["producing_receipt_sequence"]
                                    == receipt["legacy_v1_delivery"]["origin"]
                                        ["producing_receipt_sequence"]
                                    && source["emission_index"]
                                        == receipt["legacy_v1_delivery"]["origin"]["emission_index"]
                            });
                        let native = runtime_source || system_source;
                        let valid = if native {
                            envelope["cause_id"] != envelope["event_id"]
                                && !acceptance_valid
                                && producer_valid
                        } else if legacy_source {
                            acceptance_valid && legacy_source_matches && !producer_valid
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
) -> Result<(), Version2Error> {
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
) -> Result<(), Version2Error> {
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
        for (index, reference) in references.iter().enumerate() {
            if reference["emission_index"].as_str() != Some(index.to_string().as_str()) {
                return Err(invalid("emission reference order is invalid"));
            }
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
) -> Result<(), Version2Error> {
    let removed_sequences = removed
        .iter()
        .map(|r| r["receipt_sequence"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
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
    for receipt in receipts.iter().filter(|receipt| {
        !removed_sequences.contains(receipt["receipt_sequence"].as_str().unwrap())
    }) {
        if receipt["operation_kind"] == "acceptance"
            && receipt["legacy_v1_delivery"]["origin"]["kind"] == "internal_emission"
        {
            let producer = receipt["legacy_v1_delivery"]["origin"]["producing_receipt_sequence"]
                .as_str()
                .unwrap();
            if removed_sequences.contains(producer) {
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
) -> Result<(), Version2Error> {
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
) -> Result<(), Version2Error> {
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

fn ready_head<'a>(aggregate: &'a Value, runtime_id: &str) -> Result<&'a Value, Version2Error> {
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

fn runtime_mut<'a>(
    aggregate: &'a mut Value,
    runtime_id: &str,
) -> Result<&'a mut Value, Version2Error> {
    aggregate["runtimes"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|r| r["runtime_id"] == runtime_id)
        .ok_or_else(|| invalid("runtime target is absent"))
}

fn target_runtime_id(target: &Value) -> Result<&str, Version2Error> {
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
    checkpoint: &ExecutionCheckpointV2,
    revision: Option<&str>,
    digest: Option<&str>,
) -> Result<(), Version2Error> {
    if revision.is_some_and(|expected| checkpoint.value["revision"].as_str() != Some(expected))
        || digest.is_some_and(|expected| {
            checkpoint.value["execution_checkpoint_digest"].as_str() != Some(expected)
        })
    {
        return Err(failure("checkpoint_revision_conflict"));
    }
    Ok(())
}

fn seal_aggregate(mut value: Value) -> Result<Value, Version2Error> {
    value["runtimes"]
        .as_array_mut()
        .unwrap()
        .sort_by(|a, b| a["runtime_id"].as_str().cmp(&b["runtime_id"].as_str()));
    let mut unsigned = value.clone();
    unsigned
        .as_object_mut()
        .unwrap()
        .remove("aggregate_state_digest");
    value["aggregate_state_digest"] =
        json!(
            jcs_hash(&json!(["determa-aggregate-state-digest-2", unsigned]))
                .map_err(|e| invalid(e.to_string()))?
        );
    Ok(value)
}

fn seal_checkpoint(value: &mut Value) -> Result<(), Version2Error> {
    value["operation_receipts"]
        .as_array_mut()
        .unwrap()
        .sort_by_key(|r| Counter::from_decimal(r["receipt_sequence"].as_str().unwrap()).unwrap());
    value["execution_checkpoint_digest"] = json!(checkpoint_digest(value)?);
    Ok(())
}

fn seal_and_validate_checkpoint(value: &mut Value) -> Result<(), Version2Error> {
    seal_checkpoint(value)?;
    validate_v2_schema(
        value,
        include_str!("../../schema/execution-checkpoint-v2.schema.json"),
        &[
            (
                "https://determa.dev/state/schema/execution-checkpoint.schema.json",
                include_str!("../../schema/execution-checkpoint.schema.json"),
            ),
            (
                "https://determa.dev/state/schema/aggregate-state.schema.json",
                include_str!("../../schema/aggregate-state.schema.json"),
            ),
            (
                "https://determa.dev/state/schema/aggregate-state-v2.schema.json",
                include_str!("../../schema/aggregate-state-v2.schema.json"),
            ),
        ],
        "invalid_execution_checkpoint",
    )?;
    validate_semantics(value)
}

fn checkpoint_digest(value: &Value) -> Result<String, Version2Error> {
    let mut unsigned = value.clone();
    unsigned
        .as_object_mut()
        .ok_or_else(|| invalid("checkpoint must be an object"))?
        .remove("execution_checkpoint_digest");
    jcs_hash(&json!(["determa-execution-checkpoint-digest-2", unsigned]))
        .map_err(|e| invalid(e.to_string()))
}

fn counter(value: &Value, field: &str) -> Result<Counter, Version2Error> {
    Counter::from_decimal(
        value[field]
            .as_str()
            .ok_or_else(|| invalid(format!("{field} is absent")))?,
    )
    .map_err(invalid)
}
fn allocate(value: &mut Value, field: &str) -> Result<String, Version2Error> {
    let mut c = counter(value, field)?;
    let a = c.allocate().to_string();
    value[field] = json!(c.to_string());
    Ok(a)
}
fn incremented(value: &Value) -> Result<Value, Version2Error> {
    let mut c = Counter::from_decimal(value.as_str().ok_or_else(|| invalid("counter is absent"))?)
        .map_err(invalid)?;
    c.allocate();
    Ok(json!(c.to_string()))
}
fn invalid(message: impl ToString) -> Version2Error {
    Version2Error::new("invalid_execution_checkpoint", message.to_string())
}
fn failure(code: &str) -> Version2Error {
    Version2Error::new(code, "checkpoint operation was rejected")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format1::v2::{envelope_digest, restore_aggregate_v2_value};
    use crate::format1::{create_v2, load_bundle, InMemoryDefinitionResolver, QueueEnvelope};

    fn checkpoint(name: &str) -> Value {
        let source = match name {
            "admitted" => include_str!(concat!(
                "../../conformance-suite/conformance/profiles/execution-checkpoint/",
                "checkpoint-04-version2-mailboxes/admitted-checkpoint-v2.json"
            )),
            "outbox" => include_str!(concat!(
                "../../conformance-suite/conformance/profiles/execution-checkpoint/",
                "checkpoint-04-version2-mailboxes/upgraded-outbox-checkpoint-v2.json"
            )),
            "legacy" => include_str!(concat!(
                "../../conformance-suite/conformance/profiles/execution-checkpoint/",
                "checkpoint-04-version2-mailboxes/upgraded-checkpoint-v2.json"
            )),
            "legacy_processed" => include_str!(concat!(
                "../../conformance-suite/conformance/profiles/execution-checkpoint/",
                "checkpoint-04-version2-mailboxes/processed-upgraded-internal-checkpoint-v2.json"
            )),
            "maintenance" => include_str!(concat!(
                "../../conformance-suite/conformance/profiles/execution-checkpoint/",
                "checkpoint-04-version2-mailboxes/maintenance-one-hop-checkpoint-v2.json"
            )),
            _ => unreachable!(),
        };
        serde_json::from_str(source).unwrap()
    }

    #[test]
    fn native_creation_receipt_attests_exact_initial_aggregate_digest() {
        let bundle = load_bundle(include_str!(concat!(
            "../../conformance-suite/conformance/profiles/execution-checkpoint/",
            "checkpoint-04-version2-mailboxes/machine.yaml"
        )))
        .unwrap();
        let checkpoint = create_execution_checkpoint_v2(
            &bundle,
            "counter",
            "creation-digest-root",
            "creation-digest-operation",
            &Bindings::default(),
            None,
            json!({
                "mode": "permanent",
                "permanent_replay_eligible": true,
                "policy_identifier": null,
                "pruned_through_receipt_sequence": null
            }),
        )
        .unwrap();
        assert_eq!(
            checkpoint.value()["operation_receipts"][0]["resulting_aggregate_state_digest"],
            checkpoint.value()["root_record"]["aggregate_state"]["aggregate_state_digest"]
        );

        let mut forged = checkpoint.value().clone();
        forged["operation_receipts"][0]["resulting_aggregate_state_digest"] =
            json!("sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        seal_checkpoint(&mut forged).unwrap();
        let mut resolver = InMemoryDefinitionResolver::default();
        resolver.insert(bundle, true);
        assert_eq!(
            restore_value(forged, &resolver).unwrap_err().code,
            "invalid_execution_checkpoint"
        );
    }

    #[test]
    fn semantic_restore_rejects_forged_identity_allocation_chronology_and_order() {
        let admitted = checkpoint("admitted");
        validate_semantics(&admitted).unwrap();

        let mut duplicate_receipt = admitted.clone();
        duplicate_receipt["operation_receipts"][1]["receipt_sequence"] = json!("0");
        assert!(validate_semantics(&duplicate_receipt).is_err());

        let mut wrong_provenance = admitted.clone();
        wrong_provenance["operation_receipts"][1]["request_digest"] =
            json!("sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        assert!(validate_semantics(&wrong_provenance).is_err());

        let mut future_allocation = admitted.clone();
        future_allocation["operation_receipts"][1]["acceptance_sequence"] = json!("1");
        assert!(validate_semantics(&future_allocation).is_err());

        let mut outbox = checkpoint("outbox");
        validate_semantics(&outbox).unwrap();
        outbox["pending_outbox_intents"]
            .as_array_mut()
            .unwrap()
            .reverse();
        assert!(validate_semantics(&outbox).is_err());

        let mut maintenance = checkpoint("maintenance");
        maintenance["operation_receipts"][1]["committed_revision"] = json!("0");
        seal_checkpoint(&mut maintenance).unwrap();
        let mut resolver = InMemoryDefinitionResolver::default();
        resolver.insert(
            load_bundle(include_str!(concat!(
                "../../conformance-suite/conformance/profiles/execution-checkpoint/",
                "checkpoint-04-version2-mailboxes/maintenance-source.yaml"
            )))
            .unwrap(),
            true,
        );
        resolver.insert(
            load_bundle(include_str!(concat!(
                "../../conformance-suite/conformance/profiles/execution-checkpoint/",
                "checkpoint-04-version2-mailboxes/maintenance-target-one.yaml"
            )))
            .unwrap(),
            true,
        );
        assert_eq!(
            restore_value(maintenance, &resolver).unwrap_err().code,
            "invalid_execution_checkpoint"
        );
    }

    #[test]
    fn restore_rejects_resealed_checkpoint_with_deleted_migration_audit() {
        let source_bundle = load_bundle(include_str!(concat!(
            "../../conformance-suite/conformance/core/118-version2-persistence/",
            "machine.yaml"
        )))
        .unwrap();
        let target_bundle = load_bundle(include_str!(concat!(
            "../../conformance-suite/conformance/core/118-version2-persistence/",
            "target-compatible.yaml"
        )))
        .unwrap();
        let checkpoint = create_execution_checkpoint_v2(
            &source_bundle,
            "transaction_server",
            "audit-root",
            "audit-create",
            &Bindings::default(),
            None,
            json!({
                "mode": "permanent",
                "permanent_replay_eligible": true,
                "policy_identifier": null,
                "pruned_through_receipt_sequence": null
            }),
        )
        .unwrap();
        let descriptor_bytes = include_bytes!(concat!(
            "../../conformance-suite/conformance/core/118-version2-persistence/",
            "descriptor-compatible-v2.json"
        ));
        let descriptor: Value = serde_json::from_slice(descriptor_bytes).unwrap();
        let descriptor_digest = descriptor["migration_descriptor_digest"]
            .as_str()
            .unwrap()
            .to_string();
        let mut resolver = InMemoryDefinitionResolver::default();
        resolver.insert(source_bundle.clone(), true);
        resolver.insert(target_bundle.clone(), true);
        resolver.insert_descriptor(descriptor_digest.clone(), descriptor_bytes.to_vec(), true);
        let operation_id = "audit-migration";
        let request_digest = jcs_hash(&json!([
            "determa-maintenance-migration-request-digest-1",
            "1",
            "audit-root",
            operation_id,
            checkpoint.value()["root_record"]["aggregate_state"]["aggregate_state_digest"],
            target_bundle.fingerprint,
            [descriptor_digest.clone()],
            true
        ]))
        .unwrap();
        let mut migrated = checkpoint_maintenance_migration_v2_route(
            &checkpoint,
            &MigrationRequest {
                migration_route: vec![descriptor_digest],
                target_validated_bundle_fingerprint: target_bundle.fingerprint.clone(),
                maintenance_mode: true,
            },
            operation_id,
            &request_digest,
            &resolver,
            &ResourceLimits::default(),
            Some(checkpoint.revision()),
            Some(checkpoint.digest()),
        )
        .unwrap();
        assert_eq!(
            migrated["migration_audit_records"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        migrated["migration_audit_records"] = json!([]);
        seal_checkpoint(&mut migrated).unwrap();
        assert_eq!(
            restore_value(migrated, &resolver).unwrap_err().code,
            "invalid_execution_checkpoint"
        );
    }

    fn legacy_resolver() -> InMemoryDefinitionResolver {
        let bundle = load_bundle(include_str!(concat!(
            "../../conformance-suite/conformance/profiles/execution-checkpoint/",
            "checkpoint-04-version2-mailboxes/machine.yaml"
        )))
        .unwrap();
        let mut resolver = InMemoryDefinitionResolver::default();
        resolver.insert(bundle, true);
        resolver
    }

    fn reseal_legacy_mailbox(value: &mut Value) {
        let root_instance_id = value["root_instance_id"].as_str().unwrap().to_string();
        let event_id = value["operation_receipts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|receipt| receipt["operation_kind"] == "acceptance")
            .unwrap()["event_id"]
            .as_str()
            .unwrap()
            .to_string();
        let aggregate = &mut value["root_record"]["aggregate_state"];
        let entry = aggregate["runtimes"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .flat_map(|runtime| runtime["ready_mailbox"].as_array_mut().unwrap())
            .find(|entry| entry["envelope"]["event_id"] == event_id)
            .unwrap();
        let envelope: QueueEnvelope = serde_json::from_value(entry["envelope"].clone()).unwrap();
        let digest = envelope_digest(
            &root_instance_id,
            entry["delivery_mode"].as_str().unwrap(),
            &envelope,
        )
        .unwrap();
        entry["envelope_digest"] = json!(digest);
        let aggregate = seal_aggregate(aggregate.clone()).unwrap();
        value["root_record"]["aggregate_state"] = aggregate;
        let acceptance = value["operation_receipts"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|receipt| {
                receipt["operation_kind"] == "acceptance" && receipt["event_id"] == event_id
            })
            .unwrap();
        acceptance["request_digest"] = json!(digest);
        seal_checkpoint(value).unwrap();
    }

    #[test]
    fn restore_rejects_resealed_legacy_provenance_forgery() {
        let resolver = legacy_resolver();

        let mut wrong_origin = checkpoint("legacy");
        let acceptance = wrong_origin["operation_receipts"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|receipt| receipt["operation_kind"] == "acceptance")
            .unwrap();
        acceptance["legacy_v1_delivery"]["origin"] = json!({"kind": "host_input"});
        seal_checkpoint(&mut wrong_origin).unwrap();
        assert_eq!(
            restore_value(wrong_origin, &resolver).unwrap_err().code,
            "invalid_execution_checkpoint"
        );

        let mut wrong_source_locator = checkpoint("legacy");
        wrong_source_locator["root_record"]["aggregate_state"]["runtimes"][0]["ready_mailbox"][0]
            ["envelope"]["source"]["legacy_v1_internal"]["producing_receipt_sequence"] = json!("1");
        reseal_legacy_mailbox(&mut wrong_source_locator);
        assert_eq!(
            restore_value(wrong_source_locator, &resolver)
                .unwrap_err()
                .code,
            "invalid_execution_checkpoint"
        );

        let mut wrong_wrapped_reference = checkpoint("legacy");
        wrong_wrapped_reference["operation_receipts"][2]["legacy_receipt"]["emission_references"]
            [0]["emission_index"] = json!("1");
        seal_checkpoint(&mut wrong_wrapped_reference).unwrap();
        assert_eq!(
            restore_value(wrong_wrapped_reference, &resolver)
                .unwrap_err()
                .code,
            "invalid_execution_checkpoint"
        );

        let mut native_relabel = checkpoint("legacy");
        let runtime_source = native_relabel["root_record"]["aggregate_state"]["runtimes"][0]
            ["target_identity"]
            .clone();
        let envelope = &mut native_relabel["root_record"]["aggregate_state"]["runtimes"][0]
            ["ready_mailbox"][0]["envelope"];
        envelope["source"] = json!({"runtime": runtime_source});
        envelope["cause_id"] = json!("native-cause");
        reseal_legacy_mailbox(&mut native_relabel);
        assert_eq!(
            restore_value(native_relabel, &resolver).unwrap_err().code,
            "invalid_execution_checkpoint"
        );

        let mut wrong_preserved_origin = checkpoint("legacy_processed");
        let acceptance = wrong_preserved_origin["operation_receipts"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|receipt| receipt["operation_kind"] == "acceptance")
            .unwrap();
        acceptance["legacy_v1_delivery"]["origin"]["producing_receipt_sequence"] = json!("1");
        seal_checkpoint(&mut wrong_preserved_origin).unwrap();
        assert_eq!(
            restore_value(wrong_preserved_origin, &resolver)
                .unwrap_err()
                .code,
            "invalid_execution_checkpoint"
        );

        let mut legacy_native_collision = checkpoint("legacy_processed");
        legacy_native_collision["operation_receipts"][2]["legacy_receipt"]
            ["accepted_delivery_sequence"] = json!("2");
        seal_checkpoint(&mut legacy_native_collision).unwrap();
        assert_eq!(
            restore_value(legacy_native_collision, &resolver)
                .unwrap_err()
                .code,
            "invalid_execution_checkpoint"
        );

        let mut legacy_out_of_range = checkpoint("legacy_processed");
        legacy_out_of_range["operation_receipts"][2]["legacy_receipt"]
            ["accepted_delivery_sequence"] = json!("3");
        seal_checkpoint(&mut legacy_out_of_range).unwrap();
        assert_eq!(
            restore_value(legacy_out_of_range, &resolver)
                .unwrap_err()
                .code,
            "invalid_execution_checkpoint"
        );
    }

    #[test]
    fn restore_reports_digest_mismatch_after_embedded_aggregate_validation() {
        let mut value = checkpoint("admitted");
        value["execution_checkpoint_digest"] =
            json!("sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        let bundle = load_bundle(include_str!(concat!(
            "../../conformance-suite/conformance/profiles/execution-checkpoint/",
            "checkpoint-04-version2-mailboxes/machine.yaml"
        )))
        .unwrap();
        let mut resolver = InMemoryDefinitionResolver::default();
        resolver.insert(bundle, true);
        let error = restore_value(value, &resolver).unwrap_err();
        assert_eq!(error.code, "execution_checkpoint_digest_mismatch");
    }

    #[test]
    fn admission_rejects_nested_source_extras_before_wrong_root() {
        let value = checkpoint("admitted");
        let bundle = load_bundle(include_str!(concat!(
            "../../conformance-suite/conformance/profiles/execution-checkpoint/",
            "checkpoint-04-version2-mailboxes/machine.yaml"
        )))
        .unwrap();
        let mut resolver = InMemoryDefinitionResolver::default();
        resolver.insert(bundle.clone(), true);
        let restored = restore_value(value.clone(), &resolver).unwrap();
        let entry = &value["root_record"]["aggregate_state"]["runtimes"][0]["ready_mailbox"][0];
        let mut delivery = json!({
            "delivery_mode": entry["delivery_mode"],
            "envelope": entry["envelope"],
            "envelope_digest": entry["envelope_digest"]
        });
        delivery["envelope"]["source"]["extra"] = json!(true);
        delivery["envelope"]["target"]["root"]["root_instance_id"] = json!("wrong-root");
        let error = checkpoint_admit_v2(&bundle, &restored, &[delivery], None, None).unwrap_err();
        assert_eq!(error.code, "malformed_delivery");
        assert_eq!(restored.value(), &value);
    }

    #[test]
    fn bundle_compatibility_precedes_empty_ready_mailbox() {
        let mut value = checkpoint("admitted");
        value["root_record"]["aggregate_state"]["runtimes"][0]["ready_mailbox"] = json!([]);
        value["root_record"]["aggregate_state"] =
            seal_aggregate(value["root_record"]["aggregate_state"].clone()).unwrap();
        seal_checkpoint(&mut value).unwrap();
        let bundle = load_bundle(include_str!(concat!(
            "../../conformance-suite/conformance/profiles/execution-checkpoint/",
            "checkpoint-04-version2-mailboxes/machine.yaml"
        )))
        .unwrap();
        let mut resolver = InMemoryDefinitionResolver::default();
        resolver.insert(bundle.clone(), true);
        let restored = restore_value(value, &resolver).unwrap();
        let mut incompatible = bundle;
        incompatible.fingerprint =
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string();
        let runtime_id = restored.value()["root_record"]["aggregate_state"]["root_runtime_id"]
            .as_str()
            .unwrap();
        let error =
            checkpoint_step_v2(&incompatible, &restored, runtime_id, None, None).unwrap_err();
        assert_eq!(error.code, "incompatible_bundle");
    }

    #[test]
    fn contained_capacity_overflow_enqueues_failure_that_faults_owner_when_unhandled() {
        let bundle = load_bundle(
            r#"
format: 1
namespace: test.capacity
events:
  trigger: { direction: input }
  work: { direction: internal }
machines:
  - machine_id: owner
    root:
      type: parallel
      on_events:
        trigger:
          action:
            - send: { event: work, to: { component: child } }
      components:
        - component_id: child
          root:
            deferred_event_capacity: 0
            deferred_events: [work]
        - component_id: peer
          root: {}
"#,
        )
        .unwrap();
        let created = create_v2(&bundle, "owner", "root", "create", &Bindings::default()).unwrap();
        let root_runtime_id = created.value()["root_runtime_id"].as_str().unwrap();
        let envelope = crate::format1::QueueEnvelope {
            event: "trigger".to_string(),
            event_id: "trigger-1".to_string(),
            cause_id: "trigger-1".to_string(),
            source: json!({"host": true}),
            target: json!({"root": {
                "root_instance_id": "root",
                "root_runtime_id": root_runtime_id
            }}),
            payload: serde_json::from_value(json!(["map", []])).unwrap(),
            correlation_id: None,
        };
        let digest = envelope_digest("root", "input", &envelope).unwrap();
        let admitted = admit_v2(
            &bundle,
            &created,
            &[AdmissionDelivery {
                delivery_mode: "input".to_string(),
                envelope,
                envelope_digest: digest,
            }],
        )
        .unwrap();
        let admitted = restore_aggregate_v2_value(admitted["state"].clone(), &{
            let mut resolver = InMemoryDefinitionResolver::default();
            resolver.insert(bundle.clone(), true);
            resolver
        })
        .unwrap();
        let emitted = step_v2(&bundle, &admitted, root_runtime_id).unwrap();
        let emitted = restore_aggregate_v2_value(emitted["state"].clone(), &{
            let mut resolver = InMemoryDefinitionResolver::default();
            resolver.insert(bundle.clone(), true);
            resolver
        })
        .unwrap();
        let child_runtime_id = emitted.value()["runtimes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|runtime| {
                runtime["relation"]["kind"] == "component"
                    && runtime["ready_mailbox"]
                        .as_array()
                        .is_some_and(|mailbox| !mailbox.is_empty())
            })
            .unwrap()["runtime_id"]
            .as_str()
            .unwrap();
        let overflow = step_v2(&bundle, &emitted, child_runtime_id).unwrap();
        assert_eq!(overflow["disposition"], "faulted");
        assert_eq!(overflow["status"], "running");
        assert_eq!(
            overflow["fault"]["code"],
            "deferred_event_capacity_exceeded"
        );
        let overflow = restore_aggregate_v2_value(overflow["state"].clone(), &{
            let mut resolver = InMemoryDefinitionResolver::default();
            resolver.insert(bundle.clone(), true);
            resolver
        })
        .unwrap();
        let owner_failure = step_v2(&bundle, &overflow, root_runtime_id).unwrap();
        assert_eq!(owner_failure["status"], "faulted");
        assert_eq!(owner_failure["fault"]["code"], "contained_runtime_fault");
    }

    #[test]
    fn root_tombstone_terminalizes_frozen_native_internal_work() {
        let bundle = load_bundle(
            r#"
format: 1
namespace: test.tombstone
events:
  trigger: { direction: input }
  boom: { direction: input }
  work: { direction: internal }
machines:
  - machine_id: root
    root:
      variables:
        count: { type: int, init: 0 }
      on_events:
        trigger:
          action:
            - send: { event: work }
        boom:
          action:
            - assign: { count: "1 / 0" }
        work:
          action:
            - assign: { count: "count + 1" }
"#,
        )
        .unwrap();
        let mut resolver = InMemoryDefinitionResolver::default();
        resolver.insert(bundle.clone(), true);
        let created = create_execution_checkpoint_v2(
            &bundle,
            "root",
            "root",
            "create",
            &Bindings::default(),
            None,
            json!({
                "mode": "permanent",
                "permanent_replay_eligible": true,
                "policy_identifier": null,
                "pruned_through_receipt_sequence": null
            }),
        )
        .unwrap();
        let runtime_id = created.value()["root_record"]["aggregate_state"]["root_runtime_id"]
            .as_str()
            .unwrap();
        let delivery = |event: &str| {
            let envelope = QueueEnvelope {
                event: event.to_string(),
                event_id: format!("{event}-1"),
                cause_id: format!("{event}-1"),
                source: json!({"host": true}),
                target: json!({"root": {
                    "root_instance_id": "root",
                    "root_runtime_id": runtime_id
                }}),
                payload: serde_json::from_value(json!(["map", []])).unwrap(),
                correlation_id: None,
            };
            let digest = envelope_digest("root", "input", &envelope).unwrap();
            serde_json::to_value(AdmissionDelivery {
                delivery_mode: "input".to_string(),
                envelope,
                envelope_digest: digest,
            })
            .unwrap()
        };
        let admitted = checkpoint_admit_v2(
            &bundle,
            &created,
            &[delivery("trigger"), delivery("boom")],
            None,
            None,
        )
        .unwrap();
        let admitted = restore_value(admitted["checkpoint"].clone(), &resolver).unwrap();
        let triggered = checkpoint_step_v2(&bundle, &admitted, runtime_id, None, None).unwrap();
        let triggered = restore_value(triggered, &resolver).unwrap();
        let faulted = checkpoint_step_v2(&bundle, &triggered, runtime_id, None, None).unwrap();
        let faulted = restore_value(faulted, &resolver).unwrap();
        assert_eq!(
            faulted.value()["root_record"]["aggregate_state"]["runtimes"][0]["ready_mailbox"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        let tombstoned = checkpoint_tombstone_root_v2(&faulted, "tombstone", None, None).unwrap();
        let restored = restore_value(tombstoned, &resolver).unwrap();
        assert_eq!(restored.value()["root_record"]["status"], "tombstone");
        assert!(restored.value()["operation_receipts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|receipt| {
                receipt["event_id"] == "work-1"
                    || (receipt["outcome"]["disposition"] == "disposed"
                        && receipt["outcome"]["reason"] == "root_tombstoned")
            }));
    }
}
