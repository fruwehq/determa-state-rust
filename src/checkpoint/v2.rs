use crate::format1::strict_json;
use crate::format1::v2::{canonical_bytes, validate_v2_schema};
use crate::format1::wire::jcs_hash;
use crate::format1::{
    admit_v2, restore_aggregate_v2, step_v2, upgrade_aggregate_v1_to_v2, AdmissionDelivery, Bundle,
    Counter, DefinitionResolver, QueueBearingAggregate, Version2Error,
};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

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
    let tombstoned = checkpoint.value["root_record"]["status"] == "tombstone";
    let root_instance_id = checkpoint.value["root_instance_id"].as_str().unwrap();
    if deliveries.iter().any(|delivery| {
        target_root_instance_id(&delivery["envelope"]["target"])
            .is_some_and(|root| root != root_instance_id)
    }) {
        return Err(failure("wrong_root"));
    }
    let retained = retained_identity(&checkpoint.value)?;
    let mut members = Vec::new();
    let mut fresh = Vec::new();
    let mut seen = BTreeSet::new();
    for delivery in deliveries {
        let event_id = delivery["envelope"]["event_id"]
            .as_str()
            .ok_or_else(|| failure("malformed_delivery"))?;
        if !seen.insert(event_id.to_string()) {
            return Err(failure("duplicate_event_id_in_batch"));
        }
        let domain = delivery["request_digest_domain"]
            .as_str()
            .unwrap_or("determa-inbox-envelope-digest-2");
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
            let parsed: AdmissionDelivery = serde_json::from_value(delivery.clone())
                .map_err(|_| failure("malformed_delivery"))?;
            crate::format1::v2::envelope_digest(
                root_instance_id,
                &parsed.delivery_mode,
                &parsed.envelope,
            )?
        };
        if let Some(identity) = retained.get(event_id) {
            if identity.digest != candidate {
                return Err(failure("event_id_conflict"));
            }
            let evidence = identity.replay.clone();
            members.push(json!({
                "event_id": event_id,
                "disposition": "replay",
                "evidence": evidence
            }));
        } else {
            if domain != "determa-inbox-envelope-digest-2" {
                return Err(failure("invalid_delivery_digest_domain"));
            }
            fresh.push(
                serde_json::from_value::<AdmissionDelivery>(delivery.clone())
                    .map_err(|_| failure("malformed_delivery"))?,
            );
        }
    }
    if fresh.is_empty() && members.len() == 1 {
        return Ok(members.remove(0)["evidence"].clone());
    }
    if fresh.is_empty() {
        return Ok(json!({"result":"batch", "checkpoint":checkpoint.value, "members":members}));
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
    guard(checkpoint, expected_revision, expected_checkpoint_digest)?;
    let core = admit_v2(bundle, aggregate, &fresh)?;
    let state = core["state"].clone();
    let mut value = checkpoint.value.clone();
    let new_revision = incremented(&value["revision"])?;
    value["revision"] = new_revision.clone();
    value["root_record"]["aggregate_state"] = state;
    let accepted = core["accepted"].as_array().cloned().unwrap_or_default();
    for (delivery, accepted) in fresh.iter().zip(accepted) {
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
        members.push(json!({
            "event_id": delivery.envelope.event_id,
            "disposition": "accepted",
            "acceptance_sequence": accepted["acceptance_sequence"],
            "queue_sequence": accepted["queue_sequence"]
        }));
    }
    seal_checkpoint(&mut value)?;
    if members.len() == 1 && members[0]["disposition"] == "accepted" {
        Ok(value)
    } else {
        Ok(json!({"result": "batch", "checkpoint": value, "members": members}))
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
    let causal = ready_head(aggregate.value(), target_runtime_id)?.clone();
    let core = step_v2(bundle, aggregate, target_runtime_id)?;
    if core["disposition"] == "not_runnable" || core["disposition"] == "rejected" {
        return Ok(core);
    }
    let mut value = checkpoint.value.clone();
    let new_revision = incremented(&value["revision"])?;
    value["revision"] = new_revision.clone();
    let mut resulting_state = core["state"].clone();
    if core["disposition"] == "unhandled" && is_converted_v1_acceptance(&value, &causal) {
        resulting_state["next_logical_step_sequence"] =
            aggregate.value()["next_logical_step_sequence"].clone();
        resulting_state = seal_aggregate(resulting_state)?;
    }
    value["root_record"]["aggregate_state"] = resulting_state.clone();
    let terminal_sequence = allocate(&mut value, "next_operation_receipt_sequence")?;
    let mut references = Vec::new();
    for emission in core["emissions"].as_array().cloned().unwrap_or_default() {
        if emission["kind"] == "internal_mailbox" {
            references.push(emission);
        }
    }
    let receipt = json!({
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
    });
    value["operation_receipts"]
        .as_array_mut()
        .unwrap()
        .push(receipt);
    rewrite_producer_reference(&mut value, &causal, &terminal_sequence)?;
    seal_checkpoint(&mut value)?;
    Ok(value)
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
    let expected = checkpoint_digest(&value)?;
    if value["execution_checkpoint_digest"].as_str() != Some(expected.as_str()) {
        return Err(invalid("checkpoint digest does not match content"));
    }
    validate_semantics(&value)?;
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
    Ok(ExecutionCheckpointV2 { value, aggregate })
}

fn validate_semantics(value: &Value) -> Result<(), Version2Error> {
    let revision = counter(value, "revision")?;
    let next_receipt = counter(value, "next_operation_receipt_sequence")?;
    let mut sequences = BTreeSet::new();
    let mut live_ids = BTreeSet::new();
    let mut creation_id = None;
    for receipt in value["operation_receipts"].as_array().unwrap() {
        let sequence = counter(receipt, "receipt_sequence")?;
        if sequence >= next_receipt || !sequences.insert(sequence) {
            return Err(invalid("receipt sequence is invalid"));
        }
        if receipt
            .get("accepted_revision")
            .is_some_and(|r| Counter::from_decimal(r.as_str().unwrap()).unwrap() > revision)
        {
            return Err(invalid("receipt revision is in the future"));
        }
        if receipt["operation_kind"] == "acceptance" {
            live_ids.insert(receipt["event_id"].as_str().unwrap().to_string());
        }
        if receipt["operation_kind"] == "creation" {
            creation_id = receipt["creation_id"].as_str();
        }
        if receipt["operation_kind"] == "legacy_v1_creation" {
            creation_id = receipt["legacy_receipt"]["creation_id"].as_str();
        }
    }
    for tombstone in value["event_identity_tombstones"].as_array().unwrap() {
        if !live_ids.insert(tombstone["event_id"].as_str().unwrap().to_string())
            || counter(tombstone, "terminal_receipt_sequence")? >= next_receipt
        {
            return Err(invalid("event tombstone identity is invalid"));
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
    if let Some(runtime) = source.get("runtime") {
        let _ = runtime;
        let event_id = causal["envelope"]["event_id"].as_str().unwrap();
        for receipt in value["operation_receipts"].as_array_mut().unwrap() {
            if let Some(references) = receipt
                .get_mut("emission_references")
                .and_then(Value::as_array_mut)
            {
                for reference in references {
                    if reference["kind"] == "internal_mailbox" && reference["event_id"] == event_id
                    {
                        *reference = json!({"kind":"internal_terminal","emission_index":reference["emission_index"],"event_id":reference["event_id"],"acceptance_sequence":reference["acceptance_sequence"],"terminal_receipt_sequence":terminal});
                        return Ok(());
                    }
                }
            }
        }
    }
    Ok(())
}

fn is_converted_v1_acceptance(value: &Value, causal: &Value) -> bool {
    let event_id = &causal["envelope"]["event_id"];
    let checkpoint_revision = Counter::from_decimal(value["revision"].as_str().unwrap()).unwrap();
    value["operation_receipts"]
        .as_array()
        .unwrap()
        .iter()
        .any(|receipt| {
            receipt["operation_kind"] == "acceptance"
                && receipt["event_id"] == *event_id
                && Counter::from_decimal(receipt["accepted_revision"].as_str().unwrap()).unwrap()
                    < checkpoint_revision
        })
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
