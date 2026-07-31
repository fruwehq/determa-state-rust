use determa_state::checkpoint::{
    register_bundled_adapters, validate_outbox_compaction, AcceptanceResult, AdapterError,
    AdapterErrorCode, AdapterRegistry, CheckpointHost, CreationRequest, DeliveryRequest,
    EmissionReference, ExecutionCheckpoint, ExecutionStore, ExecutionStoreCapability,
    ExecutionStoreFactory, HostFeature, HostProfile, MaintenanceMigrationRequest,
    MemoryExecutionStore, MutationGuard, OperationReceipt, OutboxRecord, PendingOutboxState,
    PreAcceptanceFailureCode, ProcessingMigration, ReplayRetention, RootRecord, StoreError,
    StoreRecord, StoreWriteResult, TerminalOutboxOutcome, TerminalRootStatus,
};
use determa_state::{
    load_bundle, Bindings, Bundle, InMemoryDefinitionResolver, MigrationRequest, ResourceLimits,
    RuntimeStatus, Value,
};
use serde_json::{json, Value as JsonValue};
use std::any::Any;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

const PROFILE: &str = "conformance-suite/conformance/profiles/execution-checkpoint";

#[test]
fn all_checkpoint_artifacts_have_the_declared_classification() {
    for case in case_directories() {
        let document = read_yaml(&case.join("test.yaml"));
        let inputs = read_json(&case.join("inputs.json"));
        let (resolver, _) = resolver_for_case(&case, &inputs);
        for artifact in document["artifacts"]["documents"]
            .as_array()
            .expect("artifact list")
        {
            if artifact["kind"].as_str() != Some("execution_checkpoint") {
                continue;
            }
            let name = artifact["file"].as_str().expect("artifact file");
            let source = fs::read(case.join(name)).expect("checkpoint artifact");
            let restored =
                determa_state::checkpoint::restore_execution_checkpoint(&source, &resolver);
            let valid = artifact["valid"].as_bool().expect("artifact validity");
            if name == "invalid-compact-intent-digest-checkpoint.json" {
                let checkpoint = restored.expect("context-free artifact is structurally valid");
                let before = restore_fixture(&case, "outbox-total-checkpoint.json", &resolver);
                let effect_id = checkpoint.outbox_effect_tombstones[0].effect_id.as_str();
                let error = validate_outbox_compaction(&before, &checkpoint, effect_id, &resolver)
                    .expect_err("invalid relational compaction");
                assert_eq!(error.code.as_str(), "invalid_execution_checkpoint");
                continue;
            }
            assert_eq!(
                restored.is_ok(),
                valid,
                "{} {} classification: {:?}",
                case.display(),
                name,
                restored.err()
            );
            if let Some(expected) = artifact["error"].as_str() {
                assert_eq!(
                    restored.expect_err("invalid artifact").code.as_str(),
                    expected,
                    "{name}"
                );
            }
        }
    }
}

#[test]
fn all_85_execution_checkpoint_vectors_run_through_the_host() {
    let mut count = 0;
    for case in case_directories() {
        let document = read_yaml(&case.join("test.yaml"));
        let inputs = read_json(&case.join("inputs.json"));
        let (resolver, bundles) = resolver_for_case(&case, &inputs);
        for vector in document["execution_checkpoint_profile"]["vectors"]
            .as_array()
            .expect("checkpoint vectors")
        {
            count += 1;
            run_vector(&case, &inputs, &resolver, &bundles, vector);
        }
    }
    assert_eq!(count, 85);
}

#[test]
fn host_rejects_schema_invalid_delivery_candidates_without_mutation() {
    let case = PathBuf::from(PROFILE).join("checkpoint-01-delivery-lifecycle");
    let inputs = read_json(&case.join("inputs.json"));
    let (resolver, _) = resolver_for_case(&case, &inputs);
    let memory = Arc::new(MemoryExecutionStore::new());
    memory.initialize_schema().expect("memory schema");
    let checkpoint = restore_fixture(&case, "created-checkpoint.json", &resolver);
    let before = StoreRecord::from_checkpoint(&checkpoint).expect("created checkpoint record");
    memory
        .insert_if_absent(before.clone())
        .expect("seed created checkpoint");
    let host = CheckpointHost::new(memory.clone(), Arc::new(resolver));
    let input = &inputs["requests"]["accept_increment"];

    let mut candidates = Vec::new();
    let mut non_string_digest = delivery_request("checkpoint-root", input);
    non_string_digest.candidate["envelope_digest"] = json!(7);
    candidates.push(non_string_digest);
    let mut invalid_event = delivery_request("checkpoint-root", input);
    invalid_event.candidate["envelope"]["event"] = json!("invalid.event");
    invalid_event
        .candidate
        .as_object_mut()
        .expect("candidate")
        .remove("envelope_digest");
    candidates.push(invalid_event);
    let mut empty_correlation = delivery_request("checkpoint-root", input);
    empty_correlation.candidate["envelope"]["correlation_id"] = json!("");
    empty_correlation
        .candidate
        .as_object_mut()
        .expect("candidate")
        .remove("envelope_digest");
    candidates.push(empty_correlation);

    for request in candidates {
        let result = host
            .accept_delivery(request)
            .expect("closed acceptance result");
        assert!(matches!(
            result,
            AcceptanceResult::NotAccepted(value)
                if value.failure.code == PreAcceptanceFailureCode::MalformedDelivery
        ));
        assert_eq!(
            memory
                .load("checkpoint-root")
                .expect("checkpoint load")
                .expect("checkpoint"),
            before
        );
    }
}

#[test]
fn replay_and_conflict_precede_delivery_mode_and_origin_validation() {
    let case = PathBuf::from(PROFILE).join("checkpoint-01-delivery-lifecycle");
    let inputs = read_json(&case.join("inputs.json"));
    let (resolver, _) = resolver_for_case(&case, &inputs);

    let committed_store = Arc::new(MemoryExecutionStore::new());
    committed_store.initialize_schema().expect("memory schema");
    let committed = restore_fixture(&case, "processed-checkpoint.json", &resolver);
    let committed_record =
        StoreRecord::from_checkpoint(&committed).expect("processed checkpoint record");
    committed_store
        .insert_if_absent(committed_record.clone())
        .expect("seed processed checkpoint");
    let committed_host = CheckpointHost::new(committed_store.clone(), Arc::new(resolver.clone()));

    let invalid_origin = delivery_request("checkpoint-root", &inputs["requests"]["invalid_origin"]);
    let result = committed_host
        .accept_delivery(invalid_origin)
        .expect("committed replay result");
    assert!(matches!(
        result,
        AcceptanceResult::Committed(value)
            if value.receipt.event_id == "delivery-increment"
                && value.receipt.accepted_delivery_sequence.to_string() == "0"
    ));
    assert_eq!(
        committed_store
            .load("checkpoint-root")
            .expect("checkpoint load")
            .expect("checkpoint"),
        committed_record
    );

    let invalid_mode = delivery_request("checkpoint-root", &inputs["requests"]["invalid_mode"]);
    let result = committed_host
        .accept_delivery(invalid_mode)
        .expect("mode conflict result");
    assert!(matches!(
        result,
        AcceptanceResult::NotAccepted(value)
            if value.failure.code == PreAcceptanceFailureCode::EventIdConflict
    ));

    let pending_store = Arc::new(MemoryExecutionStore::new());
    pending_store.initialize_schema().expect("memory schema");
    let pending = restore_fixture(&case, "accepted-checkpoint.json", &resolver);
    let pending_record =
        StoreRecord::from_checkpoint(&pending).expect("accepted checkpoint record");
    pending_store
        .insert_if_absent(pending_record.clone())
        .expect("seed accepted checkpoint");
    let pending_host = CheckpointHost::new(pending_store.clone(), Arc::new(resolver));
    let invalid_origin = delivery_request("checkpoint-root", &inputs["requests"]["invalid_origin"]);
    let result = pending_host
        .accept_delivery(invalid_origin)
        .expect("pending replay result");
    assert!(matches!(
        result,
        AcceptanceResult::Pending(value)
            if value.event_id == "delivery-increment"
                && value.delivery_sequence.to_string() == "0"
                && value.accepted_revision.to_string() == "1"
    ));
    assert_eq!(
        pending_store
            .load("checkpoint-root")
            .expect("checkpoint load")
            .expect("checkpoint"),
        pending_record
    );
}

#[test]
fn candidate_validation_includes_full_json_schema() {
    let case = PathBuf::from(PROFILE).join("checkpoint-01-delivery-lifecycle");
    let inputs = read_json(&case.join("inputs.json"));
    let (resolver, _) = resolver_for_case(&case, &inputs);
    let mut checkpoint = restore_fixture(&case, "created-checkpoint.json", &resolver);
    let OperationReceipt::Creation(receipt) = &mut checkpoint.operation_receipts[0] else {
        panic!("creation receipt");
    };
    receipt.request_digest = "not-a-sha256-digest".to_string();
    checkpoint.recompute_digest().expect("recompute checkpoint");
    checkpoint
        .validate_semantics(&resolver)
        .expect("cross-field semantics alone do not validate the digest string syntax");
    assert!(
        checkpoint.validate_for_persistence(&resolver).is_err(),
        "persistence validation must include the complete checkpoint JSON schema"
    );
}

#[test]
fn restore_reconciles_internal_origin_status_and_tombstone_evidence() {
    let delivery_case = PathBuf::from(PROFILE).join("checkpoint-01-delivery-lifecycle");
    let delivery_inputs = read_json(&delivery_case.join("inputs.json"));
    let (delivery_resolver, _) = resolver_for_case(&delivery_case, &delivery_inputs);
    let mut internal = restore_fixture(
        &delivery_case,
        "internal-pending-checkpoint.json",
        &delivery_resolver,
    );
    let reference = internal
        .operation_receipts
        .iter_mut()
        .find_map(|receipt| {
            let references = match receipt {
                OperationReceipt::Creation(value) => &mut value.emission_references,
                OperationReceipt::Delivery(value) => &mut value.emission_references,
                OperationReceipt::MaintenanceMigration(_) => return None,
            };
            references
                .iter_mut()
                .find(|reference| matches!(reference, EmissionReference::InternalDelivery { .. }))
        })
        .expect("internal emission reference");
    let EmissionReference::InternalDelivery { event_id, .. } = reference else {
        unreachable!("filtered internal reference");
    };
    *event_id = "different-event-id".to_string();
    assert_invalid_after_digest(&mut internal, &delivery_resolver);

    let lifecycle_case = PathBuf::from(PROFILE).join("checkpoint-03-retention-and-root-lifecycle");
    let lifecycle_inputs = read_json(&lifecycle_case.join("inputs.json"));
    let (lifecycle_resolver, _) = resolver_for_case(&lifecycle_case, &lifecycle_inputs);
    let mut completed = restore_fixture(
        &lifecycle_case,
        "completed-checkpoint.json",
        &lifecycle_resolver,
    );
    let OperationReceipt::Creation(receipt) = &mut completed.operation_receipts[0] else {
        panic!("creation receipt");
    };
    receipt.status = RuntimeStatus::Running;
    assert_invalid_after_digest(&mut completed, &lifecycle_resolver);

    let mut tombstone = restore_fixture(
        &lifecycle_case,
        "tombstone-checkpoint.json",
        &lifecycle_resolver,
    );
    let RootRecord::Tombstone(root) = &mut tombstone.root_record else {
        panic!("root tombstone");
    };
    root.terminal_status = TerminalRootStatus::Faulted;
    assert_invalid_after_digest(&mut tombstone, &lifecycle_resolver);
}

#[test]
fn bounded_pruning_can_remove_the_latest_non_creation_receipt() {
    let case = PathBuf::from(PROFILE).join("checkpoint-03-retention-and-root-lifecycle");
    let inputs = read_json(&case.join("inputs.json"));
    let (resolver, _) = resolver_for_case(&case, &inputs);
    let memory = Arc::new(MemoryExecutionStore::new());
    memory.initialize_schema().expect("memory schema");
    let checkpoint = restore_fixture(&case, "bounded-checkpoint.json", &resolver);
    let guard = MutationGuard::new(
        checkpoint.revision.to_string(),
        checkpoint.execution_checkpoint_digest.clone(),
    );
    memory
        .insert_if_absent(StoreRecord::from_checkpoint(&checkpoint).expect("bounded record"))
        .expect("seed bounded checkpoint");
    let host = CheckpointHost::new(memory, Arc::new(resolver));
    let target: ReplayRetention = serde_json::from_value(json!({
        "mode": "bounded",
        "permanent_replay_eligible": false,
        "pruned_through_receipt_sequence": "6",
        "policy_identifier": "bounded-window"
    }))
    .expect("bounded target");
    host.update_replay_retention("checkpoint-root", target, &guard)
        .expect("prune through latest non-creation receipt");
    let restored = host
        .load_checkpoint("checkpoint-root")
        .expect("load pruned checkpoint")
        .expect("pruned checkpoint");
    assert_eq!(restored.operation_receipts.len(), 1);
    assert_eq!(
        restored.replay_retention.cutoff().map(ToString::to_string),
        Some("6".to_string())
    );
}

#[test]
fn delivery_triggered_migration_retains_restorable_permanent_evidence() {
    let case = PathBuf::from(PROFILE).join("checkpoint-03-retention-and-root-lifecycle");
    let inputs = read_json(&case.join("inputs.json"));
    let (resolver, _) = resolver_for_case(&case, &inputs);
    let memory = Arc::new(MemoryExecutionStore::new());
    memory.initialize_schema().expect("memory schema");
    let checkpoint = restore_fixture(&case, "maintenance-created-checkpoint.json", &resolver);
    let guard = MutationGuard::new(
        checkpoint.revision.to_string(),
        checkpoint.execution_checkpoint_digest.clone(),
    );
    let root_runtime_id = checkpoint
        .retained_aggregate()
        .expect("retained aggregate")
        .root_runtime_id
        .clone();
    memory
        .insert_if_absent(StoreRecord::from_checkpoint(&checkpoint).expect("source record"))
        .expect("seed source checkpoint");
    let host = CheckpointHost::new(memory.clone(), Arc::new(resolver.clone()));
    let migration = ProcessingMigration {
        request: MigrationRequest {
            migration_route: vec![
                "sha256:b79f764863cb9b02a706d6feb5a2fb8a78907fd85bff31f7810466a9815e62af"
                    .to_string(),
            ],
            target_validated_bundle_fingerprint:
                "sha256:67e01dc52ceedc38b15cd248001532d0b44ed62b5a8b622aae20b0e533cb0b10"
                    .to_string(),
            maintenance_mode: false,
        },
        limits: ResourceLimits::default(),
    };
    let request = DeliveryRequest {
        checkpoint_root_instance_id: "maintenance-root".to_string(),
        candidate: json!({
            "root_instance_id": "maintenance-root",
            "delivery_mode": "input",
            "origin": { "kind": "host_input" },
            "envelope": {
                "event": "increment",
                "event_id": "migration-delivery",
                "target": {
                    "root": {
                        "root_instance_id": "maintenance-root",
                        "root_runtime_id": root_runtime_id
                    }
                },
                "payload": ["map", []]
            }
        }),
        guard,
    };
    let receipt = host
        .foreground_process_delivery(request, Some(&migration))
        .expect("delivery-triggered migration");
    assert_eq!(receipt.receipt_sequence.to_string(), "1");
    let record = memory
        .load("maintenance-root")
        .expect("migrated checkpoint load")
        .expect("migrated checkpoint");
    let restored =
        determa_state::checkpoint::restore_execution_checkpoint(&record.bytes, &resolver)
            .expect("delivery-migrated checkpoint restores");
    assert_eq!(restored.migration_audit_records.len(), 1);
    assert!(restored.replay_retention.is_permanent());
}

fn run_vector(
    case: &Path,
    inputs: &JsonValue,
    resolver: &InMemoryDefinitionResolver,
    bundles: &BTreeMap<String, Bundle>,
    vector: &JsonValue,
) {
    let name = vector["name"].as_str().expect("vector name");
    let operation = vector["operation"].as_str().expect("operation");
    let expect = &vector["expect"];
    if matches!(
        operation,
        "inject_execution_store" | "register_adapter" | "resolve_adapter" | "validate_host_profile"
    ) {
        let (result, code, mutation) = run_registration_or_profile(case, resolver, vector);
        assert_result(name, expect, &result, code.as_deref());
        assert_eq!(
            mutation,
            expect["checkpoint_mutation"]
                .as_str()
                .expect("registry/profile mutation"),
            "{name} registry/profile mutation"
        );
        assert_eq!(
            expect["core_call"].as_str(),
            Some("none"),
            "{name} registry/profile core call"
        );
        return;
    }

    let memory = Arc::new(MemoryExecutionStore::new());
    memory.initialize_schema().expect("memory schema");
    if let Some(before) = vector["checkpoint_before"].as_str() {
        let checkpoint = restore_fixture(case, before, resolver);
        let record = StoreRecord::from_checkpoint(&checkpoint).expect("fixture record");
        assert_eq!(
            memory.insert_if_absent(record).expect("seed store"),
            StoreWriteResult::Committed
        );
    }
    let attempted_records = Arc::new(Mutex::new(Vec::new()));
    let boundary = match vector["failure_boundary"].as_str() {
        Some("before_commit") => Some(FaultBoundary::BeforeCommit),
        Some("after_commit_before_response") => Some(FaultBoundary::AfterCommit),
        _ => None,
    };
    let store: Arc<dyn ExecutionStore> = Arc::new(FaultStore::new(
        memory.clone(),
        boundary,
        attempted_records.clone(),
    ));
    let host = CheckpointHost::new(store, Arc::new(resolver.clone()));
    let input = vector
        .get("input")
        .and_then(|value| value.get("pointer"))
        .and_then(JsonValue::as_str)
        .map(|pointer| resolve_pointer(inputs, pointer));
    let mutation_root = mutation_root(input, vector);
    let before_record = memory.load(&mutation_root).expect("load checkpoint before");
    let outcome = run_host_operation(&host, bundles, operation, input, vector);
    assert_result(name, expect, &outcome.result, outcome.code.as_deref());
    let after_record = memory.load(&mutation_root).expect("load checkpoint after");
    let attempted_record = attempted_records
        .lock()
        .expect("attempted records")
        .last()
        .cloned();
    assert_host_evidence(
        name,
        case,
        vector,
        expect,
        &outcome,
        before_record.as_ref(),
        after_record.as_ref(),
        attempted_record.as_ref(),
    );

    match expect["checkpoint_after"].as_str() {
        Some(after) => {
            let expected = restore_fixture(case, after, resolver)
                .canonical_bytes()
                .expect("expected canonical checkpoint");
            let root = root_for_vector(input, vector, &expected);
            let actual = memory
                .load(&root)
                .expect("load actual checkpoint")
                .expect("checkpoint exists")
                .bytes;
            assert_eq!(actual, expected, "{name} checkpoint bytes");
        }
        None => {
            if let Some(root) = input.and_then(|value| value["root_instance_id"].as_str()) {
                assert!(
                    memory.load(root).expect("load absent checkpoint").is_none(),
                    "{name} must not reserve a root"
                );
            }
        }
    }
}

fn run_host_operation(
    host: &CheckpointHost<InMemoryDefinitionResolver>,
    bundles: &BTreeMap<String, Bundle>,
    operation: &str,
    input: Option<&JsonValue>,
    vector: &JsonValue,
) -> HostOperationOutcome {
    let input = input.unwrap_or(&JsonValue::Null);
    match operation {
        "create" => {
            let bundle_file = input["bundle_file"].as_str().expect("bundle file");
            let bundle = &bundles[bundle_file];
            let bindings = bindings_from_json(&input["bindings"]);
            let request = CreationRequest {
                bundle,
                namespace: input["namespace"].as_str().expect("namespace"),
                machine_id: input["machine_id"].as_str().expect("machine id"),
                machine_version: decimal_i64(&input["machine_version"]),
                root_instance_id: input["root_instance_id"].as_str().expect("root id"),
                creation_id: input["creation_id"].as_str().expect("creation id"),
                bindings: &bindings,
                supplied_request_digest: input["request_digest"].as_str(),
            };
            match host.create(request) {
                Ok(receipt) => HostOperationOutcome::success(
                    "committed",
                    json!({ "result": "committed", "receipt": receipt }),
                ),
                Err(error) => HostOperationOutcome::failure("failure", error.code.as_str()),
            }
        }
        "accept_delivery" => {
            let root = checkpoint_root(input, vector);
            let request = delivery_request(root, input);
            match host.accept_delivery(request) {
                Ok(value) => {
                    let result = match &value {
                        AcceptanceResult::Pending(_) => "pending",
                        AcceptanceResult::Committed(_) => "committed",
                        AcceptanceResult::NotAccepted(_) => "not_accepted",
                    };
                    let code = match &value {
                        AcceptanceResult::NotAccepted(value) => {
                            Some(preaccept_code(value.failure.code).to_string())
                        }
                        _ => None,
                    };
                    HostOperationOutcome {
                        result: result.to_string(),
                        code,
                        response: Some(
                            serde_json::to_value(value).expect("acceptance response serialization"),
                        ),
                    }
                }
                Err(error) => HostOperationOutcome::failure("failure", error.code.as_str()),
            }
        }
        "foreground_process_delivery" | "process_pending_delivery" => {
            let root = checkpoint_root(input, vector);
            let request = delivery_request(root, input);
            let result = if operation == "foreground_process_delivery" {
                host.foreground_process_delivery(request, None)
            } else {
                host.process_pending_delivery(request, None)
            };
            match result {
                Ok(receipt) => HostOperationOutcome::success(
                    "committed",
                    json!({ "result": "committed", "receipt": receipt }),
                ),
                Err(error) if error.code.as_str() == "response_lost_after_commit" => {
                    HostOperationOutcome::failure("response_lost", error.code.as_str())
                }
                Err(error) => HostOperationOutcome::failure("failure", error.code.as_str()),
            }
        }
        "update_pending_outbox" => {
            let guard = guard(input);
            let desired: PendingOutboxState =
                serde_json::from_value(input["desired_pending_state"].clone())
                    .expect("pending outbox state");
            match host.update_pending_outbox(
                root_from_before(vector),
                input["effect_id"].as_str().expect("effect id"),
                desired,
                &guard,
            ) {
                Ok(value) => HostOperationOutcome::success(
                    "committed",
                    json!({ "result": "committed", "record": value }),
                ),
                Err(error) => HostOperationOutcome::failure("failure", error.code.as_str()),
            }
        }
        "terminalize_outbox" => {
            let guard = guard(input);
            let outcome: TerminalOutboxOutcome =
                serde_json::from_value(input["terminal_outcome"].clone())
                    .expect("terminal outcome");
            match host.terminalize_outbox(
                root_from_before(vector),
                input["effect_id"].as_str().expect("effect id"),
                outcome,
                &guard,
            ) {
                Ok(value @ (OutboxRecord::Terminal(_) | OutboxRecord::Tombstone(_))) => {
                    HostOperationOutcome::success(
                        "committed",
                        json!({ "result": "committed", "record": value }),
                    )
                }
                Ok(OutboxRecord::Pending(_)) => panic!("terminal operation returned pending"),
                Err(error) => HostOperationOutcome::failure("failure", error.code.as_str()),
            }
        }
        "compact_outbox" => match host.compact_outbox(
            root_from_before(vector),
            input["effect_id"].as_str().expect("effect id"),
            &guard(input),
        ) {
            Ok(value) => HostOperationOutcome::success(
                "committed",
                json!({ "result": "committed", "record": value }),
            ),
            Err(error) => HostOperationOutcome::failure("failure", error.code.as_str()),
        },
        "delete_outbox_record" => match host.delete_outbox_record(
            root_from_before(vector),
            input["effect_id"].as_str().expect("effect id"),
            &guard(input),
        ) {
            Ok(()) => HostOperationOutcome::success("committed", json!({ "result": "committed" })),
            Err(error) => HostOperationOutcome::failure("failure", error.code.as_str()),
        },
        "maintenance_migration" => {
            let request = MaintenanceMigrationRequest {
                root_instance_id: root_from_before(vector).to_string(),
                operation_id: input["operation_id"]
                    .as_str()
                    .expect("operation id")
                    .to_string(),
                source_aggregate_state_digest: input["source_aggregate_state_digest"]
                    .as_str()
                    .expect("source digest")
                    .to_string(),
                target_validated_bundle_fingerprint: input["target_validated_bundle_fingerprint"]
                    .as_str()
                    .expect("target fingerprint")
                    .to_string(),
                migration_descriptor_digest_route: strings(
                    &input["migration_descriptor_digest_route"],
                ),
                maintenance_mode: input["maintenance_mode"]
                    .as_bool()
                    .expect("maintenance mode"),
                supplied_request_digest: input["request_digest"].as_str().map(str::to_string),
                guard: guard(input),
                limits: ResourceLimits::default(),
            };
            match host.maintenance_migration(&request) {
                Ok(receipt) => HostOperationOutcome::success(
                    "committed",
                    json!({ "result": "committed", "receipt": receipt }),
                ),
                Err(error) if error.code.as_str() == "response_lost_after_commit" => {
                    HostOperationOutcome::failure("response_lost", error.code.as_str())
                }
                Err(error) => HostOperationOutcome::failure("failure", error.code.as_str()),
            }
        }
        "update_replay_retention" => {
            let target: ReplayRetention =
                serde_json::from_value(input["target_replay_retention"].clone())
                    .expect("retention target");
            match host.update_replay_retention(root_from_before(vector), target, &guard(input)) {
                Ok(value) => HostOperationOutcome::success(
                    "committed",
                    json!({ "result": "committed", "replay_retention": value }),
                ),
                Err(error) => HostOperationOutcome::failure("failure", error.code.as_str()),
            }
        }
        "tombstone_root" => match host.tombstone_root(
            root_from_before(vector),
            input["operation_id"].as_str().expect("operation id"),
            &guard(input),
        ) {
            Ok(value) => HostOperationOutcome::success(
                "tombstoned",
                json!({ "result": "tombstoned", "tombstone": value }),
            ),
            Err(error) => HostOperationOutcome::failure("failure", error.code.as_str()),
        },
        "delete_checkpoint" => {
            match host.delete_checkpoint(root_from_before(vector), &guard(input)) {
                Ok(()) => {
                    HostOperationOutcome::success("committed", json!({ "result": "committed" }))
                }
                Err(error) if error.code.as_str() == "physical_deletion_unsupported" => {
                    HostOperationOutcome::failure("unsupported", error.code.as_str())
                }
                Err(error) => HostOperationOutcome::failure("failure", error.code.as_str()),
            }
        }
        other => panic!("unsupported host vector operation {other}"),
    }
}

struct HostOperationOutcome {
    result: String,
    code: Option<String>,
    response: Option<JsonValue>,
}

impl HostOperationOutcome {
    fn success(result: &str, response: JsonValue) -> Self {
        Self {
            result: result.to_string(),
            code: None,
            response: Some(response),
        }
    }

    fn failure(result: &str, code: &str) -> Self {
        Self {
            result: result.to_string(),
            code: Some(code.to_string()),
            response: None,
        }
    }
}

fn run_registration_or_profile(
    case: &Path,
    resolver: &InMemoryDefinitionResolver,
    vector: &JsonValue,
) -> (String, Option<String>, &'static str) {
    let operation = vector["operation"].as_str().expect("operation");
    if operation == "inject_execution_store" {
        let store: Arc<dyn ExecutionStore> = Arc::new(MemoryExecutionStore::new());
        let resolver = Arc::new(InMemoryDefinitionResolver::default());
        let _host = CheckpointHost::new(store, resolver);
        return ("accepted".to_string(), None, "absent");
    }
    if operation == "validate_host_profile" {
        let declared_capabilities = capabilities(&vector["advertised_capabilities"]);
        let features = host_features(&vector["host_features"]);
        let profile = host_profile(vector["host_profile"].as_str().expect("host profile"));
        let concrete = Arc::new(ProfileStateStore::new(ProfileStore::for_capabilities(
            &declared_capabilities,
        )));
        concrete.initialize_schema().expect("profile store schema");
        if let Some(before) = vector["checkpoint_before"].as_str() {
            let checkpoint = restore_fixture(case, before, resolver);
            concrete
                .insert_if_absent(
                    StoreRecord::from_checkpoint(&checkpoint).expect("profile checkpoint record"),
                )
                .expect("seed profile checkpoint");
        }
        let root = root_from_before(vector);
        let before = concrete.load(root).expect("profile checkpoint before");
        let store: Arc<dyn ExecutionStore> = concrete.clone();
        assert_eq!(
            store.capabilities(),
            declared_capabilities,
            "conformance profile store declaration"
        );
        let host = CheckpointHost::new(store, Arc::new(InMemoryDefinitionResolver::default()));
        let result = host.validate_profile(
            profile,
            &features,
            vector["checkpoint_retention_mode"].as_str() == Some("permanent"),
        );
        let after = concrete.load(root).expect("profile checkpoint after");
        let mutation = match (&before, &after) {
            (None, None) => "absent",
            (Some(before), Some(after)) if before == after => "unchanged",
            (None, Some(_)) => "created",
            (Some(_), Some(_)) => "changed",
            (Some(_), None) => "deleted",
        };
        let (result, code) = adapter_result(result);
        return (result, code, mutation);
    }

    let identifier = vector["adapter_identifier"]
        .as_str()
        .expect("adapter identifier");
    let requested = capabilities(&vector["requested_capabilities"]);
    let registry = AdapterRegistry::new();
    if operation == "register_adapter" && identifier == "memory" {
        let result = register_bundled_adapters(&registry);
        let (result, code) = adapter_result(result);
        return (result, code, "absent");
    }
    if identifier == "memory" || identifier == "file" || identifier == "sqlite" {
        register_bundled_adapters(&registry).expect("register bundled adapters");
    } else if identifier != "absent-store" {
        registry
            .register(
                identifier,
                Arc::new(StaticFactory {
                    valid: vector["configuration_valid"].as_bool().unwrap_or(true),
                    capabilities: capabilities(&vector["advertised_capabilities"]),
                }),
            )
            .expect("register static adapter");
    }
    if operation == "register_adapter" {
        let result = registry.register(
            identifier,
            Arc::new(StaticFactory {
                valid: true,
                capabilities: capabilities(&vector["advertised_capabilities"]),
            }),
        );
        let (result, code) = adapter_result(result);
        return (result, code, "absent");
    }
    let configuration = match identifier {
        "memory" => "memory:".to_string(),
        "file" => format!(
            "file:{}/determa-checkpoint-file-capability",
            std::env::temp_dir().display()
        ),
        "sqlite" => format!(
            "sqlite:{}/determa-checkpoint-capability.sqlite3#receipt_retention=bounded&outbox_retention=bounded",
            std::env::temp_dir().display()
        ),
        other => format!("{other}:"),
    };
    let result = registry.resolve(&configuration, &requested).map(|_| ());
    let (result, code) = adapter_result(result);
    (result, code, "absent")
}

fn assert_result(name: &str, expect: &JsonValue, result: &str, code: Option<&str>) {
    assert_eq!(
        result,
        expect["result"].as_str().expect("expected result"),
        "{name}: {code:?}"
    );
    assert_eq!(code, expect["code"].as_str(), "{name} failure code");
}

#[allow(clippy::too_many_arguments)]
fn assert_host_evidence(
    name: &str,
    case: &Path,
    vector: &JsonValue,
    expect: &JsonValue,
    outcome: &HostOperationOutcome,
    before: Option<&StoreRecord>,
    after: Option<&StoreRecord>,
    attempted: Option<&StoreRecord>,
) {
    let actual_mutation = match (before, after) {
        (None, None) => "absent",
        (None, Some(_)) => "created",
        (Some(before), Some(after)) if before == after => "unchanged",
        (Some(_), Some(_)) => "changed",
        (Some(_), None) => "deleted",
    };
    assert_eq!(
        actual_mutation,
        expect["checkpoint_mutation"]
            .as_str()
            .expect("checkpoint mutation"),
        "{name} checkpoint mutation"
    );

    if let Some(response) = &outcome.response {
        assert_eq!(
            response["result"].as_str(),
            Some(outcome.result.as_str()),
            "{name} exact public result member"
        );
        assert_eq!(
            response.as_object().expect("public response object").len(),
            expected_response_member_count(&outcome.result, response),
            "{name} closed public response shape"
        );
    }

    let checkpoint = after
        .or(attempted)
        .and_then(|record| serde_json::from_slice::<ExecutionCheckpoint>(&record.bytes).ok());
    if let Some(expected_sequence) = expect["receipt_sequence"].as_str() {
        let checkpoint = checkpoint.as_ref().expect("receipt-bearing checkpoint");
        let receipt = checkpoint
            .operation_receipts
            .iter()
            .find(|receipt| receipt.receipt_sequence().to_string() == expected_sequence)
            .unwrap_or_else(|| panic!("{name} receipt sequence {expected_sequence}"));
        if let Some(response_receipt) = outcome
            .response
            .as_ref()
            .and_then(|response| response.get("receipt"))
        {
            assert_eq!(
                response_receipt,
                &serde_json::to_value(receipt).expect("receipt serialization"),
                "{name} public receipt body"
            );
        }
    }
    if let Some(expected_sequence) = expect["delivery_sequence"].as_str() {
        let checkpoint = checkpoint.as_ref().expect("pending checkpoint");
        let pending = checkpoint
            .pending_deliveries
            .iter()
            .find(|pending| pending.delivery_sequence.to_string() == expected_sequence)
            .expect("pending delivery sequence");
        assert_eq!(
            outcome
                .response
                .as_ref()
                .and_then(|response| response["delivery_sequence"].as_str()),
            Some(expected_sequence),
            "{name} delivery sequence response"
        );
        assert_eq!(
            outcome
                .response
                .as_ref()
                .and_then(|response| response["event_id"].as_str()),
            Some(pending.envelope.event_id.as_str()),
            "{name} pending event identity response"
        );
    }
    if let Some(expected_revision) = expect["accepted_revision"].as_str() {
        assert_eq!(
            outcome
                .response
                .as_ref()
                .and_then(|response| response["accepted_revision"].as_str()),
            Some(expected_revision),
            "{name} accepted revision response"
        );
    }

    let expected_core_call = expect["core_call"].as_str().expect("core call");
    let core_reference = vector.get("core_result");
    if expected_core_call == "none" {
        assert!(
            core_reference.is_none(),
            "{name} no-core vector must not carry a core result"
        );
        return;
    }
    let core_reference = core_reference.expect("core result reference");
    let core_document =
        read_json(&case.join(core_reference["file"].as_str().expect("core result file")));
    let core_result = resolve_pointer(
        &core_document,
        core_reference["pointer"]
            .as_str()
            .expect("core result pointer"),
    );
    assert_eq!(
        core_result["core_operation"].as_str(),
        Some(expected_core_call),
        "{name} core call"
    );
    let prior_aggregate_state_digest = before
        .and_then(|record| serde_json::from_slice::<ExecutionCheckpoint>(&record.bytes).ok())
        .and_then(|checkpoint| {
            checkpoint
                .retained_aggregate()
                .map(|aggregate| aggregate.aggregate_state_digest.clone())
        });
    assert_eq!(
        serde_json::to_value(prior_aggregate_state_digest)
            .expect("prior aggregate digest serialization"),
        core_result["prior_aggregate_state_digest"],
        "{name} exact core prior aggregate"
    );

    let Some(checkpoint) = attempted
        .or(after)
        .and_then(|record| serde_json::from_slice::<ExecutionCheckpoint>(&record.bytes).ok())
    else {
        assert_eq!(
            core_result["aggregate_state"],
            JsonValue::Null,
            "{name} rejected core call must not produce aggregate state"
        );
        assert!(
            !core_result["rejection"].is_null() || !core_result["failure"].is_null(),
            "{name} rejected core call evidence"
        );
        return;
    };
    assert_eq!(
        serde_json::to_value(checkpoint.retained_aggregate())
            .expect("aggregate state serialization"),
        core_result["aggregate_state"],
        "{name} exact core aggregate result"
    );
    if let Some(audit_records) = core_result.get("audit_records") {
        assert_eq!(
            serde_json::to_value(&checkpoint.migration_audit_records)
                .expect("migration audit serialization"),
            *audit_records,
            "{name} exact migration audit result"
        );
    }
    if let Some(expected_sequence) = expect["receipt_sequence"].as_str() {
        let receipt = checkpoint
            .operation_receipts
            .iter()
            .find(|receipt| receipt.receipt_sequence().to_string() == expected_sequence)
            .expect("core receipt");
        assert_receipt_matches_core_result(name, &checkpoint, receipt, core_result);
    }
}

fn expected_response_member_count(result: &str, response: &JsonValue) -> usize {
    match result {
        "pending" => 4,
        "not_accepted" => 2,
        "committed" if response.get("receipt").is_some() => 2,
        "committed" if response.get("record").is_some() => 2,
        "committed" if response.get("replay_retention").is_some() => 2,
        "committed" => 1,
        "tombstoned" => 2,
        other => panic!("unexpected public success result {other}"),
    }
}

fn assert_receipt_matches_core_result(
    name: &str,
    checkpoint: &ExecutionCheckpoint,
    receipt: &OperationReceipt,
    core_result: &JsonValue,
) {
    match receipt {
        OperationReceipt::Creation(receipt) => {
            assert_eq!(
                serde_json::to_value(receipt.status).expect("status serialization"),
                core_result["status"],
                "{name} creation status"
            );
            assert_eq!(
                serde_json::to_value(&receipt.fault).expect("fault serialization"),
                core_result["fault"],
                "{name} creation fault"
            );
            assert_core_emissions(
                name,
                checkpoint,
                &receipt.emission_references,
                &core_result["emissions"],
            );
        }
        OperationReceipt::Delivery(receipt) => {
            assert_eq!(
                serde_json::to_value(receipt.outcome.status).expect("status serialization"),
                core_result["status"],
                "{name} delivery status"
            );
            assert_eq!(
                serde_json::to_value(receipt.outcome.disposition)
                    .expect("disposition serialization"),
                core_result["disposition"],
                "{name} delivery disposition"
            );
            assert_eq!(
                serde_json::to_value(&receipt.outcome.fault).expect("fault serialization"),
                core_result["fault"],
                "{name} delivery fault"
            );
            assert_eq!(
                serde_json::to_value(&receipt.outcome.rejection).expect("rejection serialization"),
                core_result["rejection"],
                "{name} delivery rejection"
            );
            assert_core_emissions(
                name,
                checkpoint,
                &receipt.emission_references,
                &core_result["emissions"],
            );
        }
        OperationReceipt::MaintenanceMigration(_) => {
            assert!(
                core_result["failure"].is_null(),
                "{name} committed migration core result"
            );
        }
    }
}

fn assert_core_emissions(
    name: &str,
    checkpoint: &ExecutionCheckpoint,
    references: &[EmissionReference],
    expected: &JsonValue,
) {
    let actual = references
        .iter()
        .map(|reference| match reference {
            EmissionReference::InternalDelivery {
                delivery_sequence, ..
            } => {
                let pending = checkpoint
                    .pending_deliveries
                    .iter()
                    .find(|pending| &pending.delivery_sequence == delivery_sequence)
                    .expect("referenced internal delivery");
                let mut emission = serde_json::to_value(&pending.envelope)
                    .expect("internal emission serialization");
                emission
                    .as_object_mut()
                    .expect("internal emission object")
                    .insert("kind".to_string(), json!("internal"));
                emission
            }
            EmissionReference::ExternalOutbox { effect_id, .. } => {
                let pending = checkpoint
                    .pending_outbox_intents
                    .iter()
                    .find(|pending| &pending.intent.effect_id == effect_id)
                    .expect("referenced external outbox intent");
                json!({
                    "kind": "external",
                    "event": pending.intent.event,
                    "effect_id": pending.intent.effect_id,
                    "sequence": pending.intent.sequence,
                    "payload": pending.intent.payload,
                    "correlation_id": pending.intent.correlation_id,
                })
            }
        })
        .collect::<Vec<_>>();
    assert_eq!(
        serde_json::to_value(actual).expect("core emissions serialization"),
        *expected,
        "{name} exact core emissions"
    );
}

fn resolver_for_case(
    case: &Path,
    inputs: &JsonValue,
) -> (InMemoryDefinitionResolver, BTreeMap<String, Bundle>) {
    let mut resolver = InMemoryDefinitionResolver::default();
    let mut bundles = BTreeMap::new();
    for entry in fs::read_dir(case).expect("case directory") {
        let path = entry.expect("case entry").path();
        if path.extension().and_then(|value| value.to_str()) != Some("yaml")
            || path.file_name().and_then(|value| value.to_str()) == Some("test.yaml")
        {
            continue;
        }
        let source = fs::read_to_string(&path).expect("bundle fixture");
        if let Ok(bundle) = load_bundle(&source) {
            let file = path
                .file_name()
                .and_then(|value| value.to_str())
                .expect("bundle file name")
                .to_string();
            resolver.insert(bundle.clone(), true);
            bundles.insert(file, bundle);
        }
    }
    for request in inputs["requests"]
        .as_object()
        .expect("checkpoint requests")
        .values()
    {
        for member in ["bundle_file", "target_bundle_file"] {
            let Some(file) = request[member].as_str() else {
                continue;
            };
            if bundles.contains_key(file) {
                continue;
            }
            let source = fs::read_to_string(case.join(file)).expect("bundle fixture");
            let bundle = load_bundle(&source).expect("bundle loads");
            resolver.insert(bundle.clone(), true);
            bundles.insert(file.to_string(), bundle);
        }
        let files = request["migration_descriptor_files"].as_array();
        let route = request["migration_descriptor_digest_route"].as_array();
        if let (Some(files), Some(route)) = (files, route) {
            for (file, digest) in files.iter().zip(route) {
                let bytes = fs::read(case.join(file.as_str().expect("descriptor file")))
                    .expect("descriptor");
                resolver.insert_descriptor(
                    digest.as_str().expect("descriptor digest"),
                    bytes,
                    true,
                );
            }
        }
    }
    (resolver, bundles)
}

fn case_directories() -> Vec<PathBuf> {
    let mut cases = fs::read_dir(PROFILE)
        .expect("checkpoint profile")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.join("test.yaml").is_file())
        .collect::<Vec<_>>();
    cases.sort();
    cases
}

fn restore_fixture(
    case: &Path,
    name: &str,
    resolver: &InMemoryDefinitionResolver,
) -> determa_state::checkpoint::ExecutionCheckpoint {
    let source = fs::read(case.join(name)).expect("checkpoint fixture");
    determa_state::checkpoint::restore_execution_checkpoint(&source, resolver)
        .unwrap_or_else(|error| panic!("{name}: {error}"))
}

fn assert_invalid_after_digest(
    checkpoint: &mut determa_state::checkpoint::ExecutionCheckpoint,
    resolver: &InMemoryDefinitionResolver,
) {
    checkpoint.recompute_digest().expect("checkpoint digest");
    let bytes = checkpoint.canonical_bytes().expect("checkpoint bytes");
    let error = determa_state::checkpoint::restore_execution_checkpoint(&bytes, resolver)
        .expect_err("checkpoint must be rejected");
    assert_eq!(error.code.as_str(), "invalid_execution_checkpoint");
}

fn read_yaml(path: &Path) -> JsonValue {
    serde_yaml::from_str(&fs::read_to_string(path).expect("YAML fixture")).expect("valid YAML")
}

fn read_json(path: &Path) -> JsonValue {
    serde_json::from_slice(&fs::read(path).expect("JSON fixture")).expect("valid JSON")
}

fn resolve_pointer<'a>(document: &'a JsonValue, pointer: &str) -> &'a JsonValue {
    document.pointer(pointer).expect("input pointer")
}

fn delivery_request(root: &str, input: &JsonValue) -> DeliveryRequest {
    let candidate = if input.get("candidate").is_some() {
        input["candidate"].clone()
    } else {
        json!({
            "root_instance_id": input["root_instance_id"],
            "delivery_mode": input["delivery_mode"],
            "origin": input["origin"],
            "envelope": input["envelope"],
            "envelope_digest": input["envelope_digest"]
        })
    };
    DeliveryRequest {
        checkpoint_root_instance_id: root.to_string(),
        candidate,
        guard: guard(input),
    }
}

fn guard(input: &JsonValue) -> MutationGuard {
    MutationGuard::new(
        input["expected_revision"].as_str().unwrap_or("0"),
        input["expected_checkpoint_digest"].as_str().unwrap_or(""),
    )
}

fn checkpoint_root<'a>(input: &'a JsonValue, vector: &'a JsonValue) -> &'a str {
    if input["root_instance_id"].as_str() == Some("another-root") {
        return root_from_before(vector);
    }
    input["root_instance_id"]
        .as_str()
        .unwrap_or_else(|| root_from_before(vector))
}

fn root_from_before(vector: &JsonValue) -> &str {
    let name = vector["checkpoint_before"].as_str().unwrap_or("");
    if name.starts_with("outbox-") {
        "outbox-root"
    } else if name.starts_with("maintenance") {
        "maintenance-root"
    } else if name == "completed-checkpoint.json" || name == "tombstone-checkpoint.json" {
        "terminal-root"
    } else {
        "checkpoint-root"
    }
}

fn root_for_vector(input: Option<&JsonValue>, vector: &JsonValue, expected: &[u8]) -> String {
    serde_json::from_slice::<JsonValue>(expected)
        .expect("expected checkpoint JSON")
        .get("root_instance_id")
        .and_then(JsonValue::as_str)
        .map(str::to_string)
        .or_else(|| {
            input
                .and_then(|value| value["root_instance_id"].as_str())
                .map(str::to_string)
        })
        .unwrap_or_else(|| root_from_before(vector).to_string())
}

fn mutation_root(input: Option<&JsonValue>, vector: &JsonValue) -> String {
    if vector["checkpoint_before"].as_str().is_some() {
        root_from_before(vector).to_string()
    } else {
        input
            .and_then(|value| value["root_instance_id"].as_str())
            .unwrap_or_else(|| root_from_before(vector))
            .to_string()
    }
}

fn bindings_from_json(value: &JsonValue) -> Bindings {
    Bindings {
        input: value_map(&value["input"]),
        external: value_map(&value["external"]),
    }
}

fn value_map(value: &JsonValue) -> BTreeMap<String, Value> {
    value
        .as_object()
        .expect("binding map")
        .iter()
        .map(|(key, value)| {
            (
                key.clone(),
                Value::from_json(value).expect("portable binding value"),
            )
        })
        .collect()
}

fn decimal_i64(value: &JsonValue) -> i64 {
    value
        .as_str()
        .expect("decimal string")
        .parse()
        .expect("i64 decimal")
}

fn strings(value: &JsonValue) -> Vec<String> {
    value
        .as_array()
        .expect("string array")
        .iter()
        .map(|value| value.as_str().expect("string").to_string())
        .collect()
}

fn preaccept_code(code: PreAcceptanceFailureCode) -> &'static str {
    match code {
        PreAcceptanceFailureCode::MalformedDelivery => "malformed_delivery",
        PreAcceptanceFailureCode::WrongRoot => "wrong_root",
        PreAcceptanceFailureCode::InvalidDeliveryMode => "invalid_delivery_mode",
        PreAcceptanceFailureCode::InvalidDeliveryOrigin => "invalid_delivery_origin",
        PreAcceptanceFailureCode::DeliveryDigestMismatch => "delivery_digest_mismatch",
        PreAcceptanceFailureCode::EventIdConflict => "event_id_conflict",
        PreAcceptanceFailureCode::TombstonedRoot => "tombstoned_root",
    }
}

fn capabilities(value: &JsonValue) -> BTreeSet<ExecutionStoreCapability> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .map(|value| match value.as_str().expect("capability") {
            "ephemeral" => ExecutionStoreCapability::Ephemeral,
            "restart_persistent" => ExecutionStoreCapability::RestartPersistent,
            "durable_single_writer" => ExecutionStoreCapability::DurableSingleWriter,
            "durable_concurrent" => ExecutionStoreCapability::DurableConcurrent,
            "shared_application_transaction" => {
                ExecutionStoreCapability::SharedApplicationTransaction
            }
            "permanent_receipt_retention" => ExecutionStoreCapability::PermanentReceiptRetention,
            "root_identity_retention" => ExecutionStoreCapability::RootIdentityRetention,
            "permanent_outbox_terminal_retention" => {
                ExecutionStoreCapability::PermanentOutboxTerminalRetention
            }
            "compact_effect_identity_retention" => {
                ExecutionStoreCapability::CompactEffectIdentityRetention
            }
            other => panic!("unknown capability {other}"),
        })
        .collect()
}

fn host_features(value: &JsonValue) -> BTreeSet<HostFeature> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .map(|value| match value.as_str().expect("host feature") {
            "atomic_checkpoint_processing" => HostFeature::AtomicCheckpointProcessing,
            "acknowledge_after_checkpoint_commit" => HostFeature::AcknowledgeAfterCheckpointCommit,
            "durable_redelivery" => HostFeature::DurableRedelivery,
            "outbox_worker" => HostFeature::OutboxWorker,
            "total_outbox_lifecycle" => HostFeature::TotalOutboxLifecycle,
            "retain_unresolved_outbox" => HostFeature::RetainUnresolvedOutbox,
            "retain_referenced_effect_tombstones" => HostFeature::RetainReferencedEffectTombstones,
            "native_shared_application_transaction" => {
                HostFeature::NativeSharedApplicationTransaction
            }
            other => panic!("unknown host feature {other}"),
        })
        .collect()
}

fn host_profile(value: &str) -> HostProfile {
    match value {
        "durable_embedded_processing" => HostProfile::DurableEmbeddedProcessing,
        "exactly_once_committed_processing" => HostProfile::ExactlyOnceCommittedProcessing,
        "broker_integrated" => HostProfile::BrokerIntegrated,
        "strict_durable_outbox" => HostProfile::StrictDurableOutbox,
        "compact_durable_outbox" => HostProfile::CompactDurableOutbox,
        "shared_application_transaction" => HostProfile::SharedApplicationTransaction,
        other => panic!("unknown host profile {other}"),
    }
}

fn adapter_result(result: Result<(), AdapterError>) -> (String, Option<String>) {
    match result {
        Ok(()) => ("accepted".to_string(), None),
        Err(error) => ("failure".to_string(), Some(error.code.as_str().to_string())),
    }
}

struct StaticFactory {
    valid: bool,
    capabilities: BTreeSet<ExecutionStoreCapability>,
}

impl ExecutionStoreFactory for StaticFactory {
    fn create(&self, _configuration: &str) -> Result<Arc<dyn ExecutionStore>, AdapterError> {
        if !self.valid {
            return Err(AdapterError::new(
                AdapterErrorCode::InvalidAdapterConfiguration,
                "invalid test configuration",
            ));
        }
        Ok(Arc::new(StaticStore {
            capabilities: self.capabilities.clone(),
        }))
    }
}

struct StaticStore {
    capabilities: BTreeSet<ExecutionStoreCapability>,
}

impl ExecutionStore for StaticStore {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn capabilities(&self) -> BTreeSet<ExecutionStoreCapability> {
        self.capabilities.clone()
    }

    fn initialize_schema(&self) -> Result<(), StoreError> {
        Ok(())
    }

    fn health(&self) -> Result<determa_state::checkpoint::HealthStatus, StoreError> {
        Ok(determa_state::checkpoint::HealthStatus::healthy("static"))
    }

    fn load(&self, _root_instance_id: &str) -> Result<Option<StoreRecord>, StoreError> {
        Ok(None)
    }

    fn insert_if_absent(&self, _record: StoreRecord) -> Result<StoreWriteResult, StoreError> {
        Ok(StoreWriteResult::Committed)
    }

    fn compare_and_swap(
        &self,
        _root_instance_id: &str,
        _expected_revision: &str,
        _expected_checkpoint_digest: &str,
        _replacement: StoreRecord,
    ) -> Result<StoreWriteResult, StoreError> {
        Ok(StoreWriteResult::Committed)
    }
}

enum ProfileStore {
    RestartWithRootIdentity,
    DurableSingleWithoutRootIdentity,
    DurableSingle,
    DurableSinglePermanent,
    DurableConcurrent,
    DurableConcurrentStrict,
    DurableConcurrentCompact,
    DurableConcurrentShared,
}

impl ProfileStore {
    fn for_capabilities(capabilities: &BTreeSet<ExecutionStoreCapability>) -> Self {
        use ExecutionStoreCapability::{
            CompactEffectIdentityRetention, DurableConcurrent, DurableSingleWriter,
            PermanentOutboxTerminalRetention, PermanentReceiptRetention, RestartPersistent,
            RootIdentityRetention, SharedApplicationTransaction,
        };
        if capabilities == &BTreeSet::from([RestartPersistent, RootIdentityRetention]) {
            Self::RestartWithRootIdentity
        } else if capabilities == &BTreeSet::from([DurableSingleWriter]) {
            Self::DurableSingleWithoutRootIdentity
        } else if capabilities == &BTreeSet::from([DurableSingleWriter, RootIdentityRetention]) {
            Self::DurableSingle
        } else if capabilities
            == &BTreeSet::from([
                DurableSingleWriter,
                RootIdentityRetention,
                PermanentReceiptRetention,
            ])
        {
            Self::DurableSinglePermanent
        } else if capabilities == &BTreeSet::from([DurableConcurrent, RootIdentityRetention]) {
            Self::DurableConcurrent
        } else if capabilities
            == &BTreeSet::from([
                DurableConcurrent,
                RootIdentityRetention,
                PermanentOutboxTerminalRetention,
            ])
        {
            Self::DurableConcurrentStrict
        } else if capabilities
            == &BTreeSet::from([
                DurableConcurrent,
                RootIdentityRetention,
                CompactEffectIdentityRetention,
            ])
        {
            Self::DurableConcurrentCompact
        } else if capabilities
            == &BTreeSet::from([
                DurableConcurrent,
                RootIdentityRetention,
                SharedApplicationTransaction,
            ])
        {
            Self::DurableConcurrentShared
        } else {
            panic!("no fixed conformance profile store for {capabilities:?}");
        }
    }
}

impl ExecutionStore for ProfileStore {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn capabilities(&self) -> BTreeSet<ExecutionStoreCapability> {
        use ExecutionStoreCapability::{
            CompactEffectIdentityRetention, DurableConcurrent, DurableSingleWriter,
            PermanentOutboxTerminalRetention, PermanentReceiptRetention, RestartPersistent,
            RootIdentityRetention, SharedApplicationTransaction,
        };
        match self {
            Self::RestartWithRootIdentity => {
                BTreeSet::from([RestartPersistent, RootIdentityRetention])
            }
            Self::DurableSingleWithoutRootIdentity => BTreeSet::from([DurableSingleWriter]),
            Self::DurableSingle => BTreeSet::from([DurableSingleWriter, RootIdentityRetention]),
            Self::DurableSinglePermanent => BTreeSet::from([
                DurableSingleWriter,
                RootIdentityRetention,
                PermanentReceiptRetention,
            ]),
            Self::DurableConcurrent => BTreeSet::from([DurableConcurrent, RootIdentityRetention]),
            Self::DurableConcurrentStrict => BTreeSet::from([
                DurableConcurrent,
                RootIdentityRetention,
                PermanentOutboxTerminalRetention,
            ]),
            Self::DurableConcurrentCompact => BTreeSet::from([
                DurableConcurrent,
                RootIdentityRetention,
                CompactEffectIdentityRetention,
            ]),
            Self::DurableConcurrentShared => BTreeSet::from([
                DurableConcurrent,
                RootIdentityRetention,
                SharedApplicationTransaction,
            ]),
        }
    }

    fn initialize_schema(&self) -> Result<(), StoreError> {
        Ok(())
    }

    fn health(&self) -> Result<determa_state::checkpoint::HealthStatus, StoreError> {
        Ok(determa_state::checkpoint::HealthStatus::healthy(
            "fixed conformance profile store",
        ))
    }

    fn load(&self, _root_instance_id: &str) -> Result<Option<StoreRecord>, StoreError> {
        Ok(None)
    }

    fn insert_if_absent(&self, _record: StoreRecord) -> Result<StoreWriteResult, StoreError> {
        Ok(StoreWriteResult::Committed)
    }

    fn compare_and_swap(
        &self,
        _root_instance_id: &str,
        _expected_revision: &str,
        _expected_checkpoint_digest: &str,
        _replacement: StoreRecord,
    ) -> Result<StoreWriteResult, StoreError> {
        Ok(StoreWriteResult::Committed)
    }
}

struct ProfileStateStore {
    profile: ProfileStore,
    inner: MemoryExecutionStore,
}

impl ProfileStateStore {
    fn new(profile: ProfileStore) -> Self {
        Self {
            profile,
            inner: MemoryExecutionStore::new(),
        }
    }
}

impl ExecutionStore for ProfileStateStore {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn capabilities(&self) -> BTreeSet<ExecutionStoreCapability> {
        self.profile.capabilities()
    }

    fn initialize_schema(&self) -> Result<(), StoreError> {
        self.inner.initialize_schema()
    }

    fn health(&self) -> Result<determa_state::checkpoint::HealthStatus, StoreError> {
        self.inner.health()
    }

    fn load(&self, root_instance_id: &str) -> Result<Option<StoreRecord>, StoreError> {
        self.inner.load(root_instance_id)
    }

    fn insert_if_absent(&self, record: StoreRecord) -> Result<StoreWriteResult, StoreError> {
        self.inner.insert_if_absent(record)
    }

    fn compare_and_swap(
        &self,
        root_instance_id: &str,
        expected_revision: &str,
        expected_checkpoint_digest: &str,
        replacement: StoreRecord,
    ) -> Result<StoreWriteResult, StoreError> {
        self.inner.compare_and_swap(
            root_instance_id,
            expected_revision,
            expected_checkpoint_digest,
            replacement,
        )
    }
}

#[derive(Clone, Copy)]
enum FaultBoundary {
    BeforeCommit,
    AfterCommit,
}

struct FaultStore {
    inner: Arc<MemoryExecutionStore>,
    boundary: Option<FaultBoundary>,
    fired: AtomicBool,
    attempted_records: Arc<Mutex<Vec<StoreRecord>>>,
}

impl FaultStore {
    fn new(
        inner: Arc<MemoryExecutionStore>,
        boundary: Option<FaultBoundary>,
        attempted_records: Arc<Mutex<Vec<StoreRecord>>>,
    ) -> Self {
        Self {
            inner,
            boundary,
            fired: AtomicBool::new(false),
            attempted_records,
        }
    }

    fn record_attempt(&self, record: &StoreRecord) -> Result<(), StoreError> {
        self.attempted_records
            .lock()
            .map_err(|_| StoreError::new("attempted record lock is poisoned"))?
            .push(record.clone());
        Ok(())
    }
}

impl ExecutionStore for FaultStore {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn capabilities(&self) -> BTreeSet<ExecutionStoreCapability> {
        self.inner.capabilities()
    }

    fn initialize_schema(&self) -> Result<(), StoreError> {
        self.inner.initialize_schema()
    }

    fn health(&self) -> Result<determa_state::checkpoint::HealthStatus, StoreError> {
        self.inner.health()
    }

    fn load(&self, root_instance_id: &str) -> Result<Option<StoreRecord>, StoreError> {
        self.inner.load(root_instance_id)
    }

    fn insert_if_absent(&self, record: StoreRecord) -> Result<StoreWriteResult, StoreError> {
        self.record_attempt(&record)?;
        self.inner.insert_if_absent(record)
    }

    fn compare_and_swap(
        &self,
        root_instance_id: &str,
        expected_revision: &str,
        expected_checkpoint_digest: &str,
        replacement: StoreRecord,
    ) -> Result<StoreWriteResult, StoreError> {
        self.record_attempt(&replacement)?;
        let Some(boundary) = self.boundary else {
            return self.inner.compare_and_swap(
                root_instance_id,
                expected_revision,
                expected_checkpoint_digest,
                replacement,
            );
        };
        if self.fired.swap(true, Ordering::SeqCst) {
            return self.inner.compare_and_swap(
                root_instance_id,
                expected_revision,
                expected_checkpoint_digest,
                replacement,
            );
        }
        match boundary {
            FaultBoundary::BeforeCommit => {
                Err(StoreError::injected_pre_commit("injected before commit"))
            }
            FaultBoundary::AfterCommit => {
                let result = self.inner.compare_and_swap(
                    root_instance_id,
                    expected_revision,
                    expected_checkpoint_digest,
                    replacement,
                )?;
                assert_eq!(result, StoreWriteResult::Committed);
                Err(StoreError::response_lost_after_commit(
                    "response lost after commit",
                ))
            }
        }
    }
}
