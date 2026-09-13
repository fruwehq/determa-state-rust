use determa_state::checkpoint::{
    validate_store_host_profile, AdapterError, AdapterErrorCode, AdapterRegistry, AdmissionSource,
    CheckpointHost, DurableCheckpointOperation, DurableFailurePolicy, DurableHostResult,
    DurableProcessRequest, DurableQuarantineReleaseRequest, DurableStoreMode, ExecutionStore,
    ExecutionStoreCapability, ExecutionStoreFactory, HealthStatus, HostFeature, HostProfile,
    MemoryExecutionStore, MutationGuard, OutboxRetentionMode, PendingOutboxState,
    ProcessingRequest, PruneRequest, ReceiptRetentionMode, ScopedStoreRecord, SqliteExecutionStore,
    StoreError, StoreRecord, StoreScope, StoreWriteResult, TerminalOutboxOutcome,
};
use determa_state::{
    load_bundle, Bindings, InMemoryDefinitionResolver, MigrationRequest, ResourceLimits,
};
use serde_json::{json, Value};
use std::any::Any;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

#[test]
fn all_138_durable_host_vectors_execute_exactly() {
    let mut count = 0;
    let mut failures = Vec::new();
    for directory in profile_directories() {
        let manifest = yaml(&fs::read_to_string(directory.join("test.yaml")).unwrap());
        let Some(vectors) = manifest["durable_host_vectors"].as_array() else {
            continue;
        };
        for vector in vectors {
            count += 1;
            if let Err(error) = run_vector(&directory, vector) {
                failures.push(format!(
                    "{}/{}: {error}",
                    directory.file_name().unwrap().to_string_lossy(),
                    vector["name"].as_str().unwrap()
                ));
            }
        }
    }
    assert_eq!(count, 138, "durable-host vector count changed");
    assert!(
        failures.is_empty(),
        "{} durable-host vector(s) failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn permanent_quarantine_obeys_retained_replay_and_conflict_precedence() {
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
        "conformance-suite/conformance/profiles/persistence/persistence-05-permanent-quarantine-release",
    );
    let inputs = json_bytes(&fs::read(directory.join("inputs-v2.json")).unwrap());
    let committed = json_bytes(&fs::read(directory.join("committed-store-v2.json")).unwrap());
    let request = inputs.pointer("/requests/replay").unwrap();
    let database = std::env::temp_dir().join(format!(
        "determa-durable-quarantine-precedence-{}.sqlite",
        std::process::id()
    ));
    let _ = fs::remove_file(&database);
    let sqlite = Arc::new(
        SqliteExecutionStore::open(
            &database,
            DurableStoreMode::new(
                ReceiptRetentionMode::Permanent,
                OutboxRetentionMode::Bounded,
            ),
        )
        .unwrap(),
    );
    sqlite.initialize_schema().unwrap();
    sqlite.import_durable_host_snapshot(&committed).unwrap();
    let host = CheckpointHost::new(sqlite.clone(), Arc::new(resolver(&directory)));

    let mut replay = process_request(request);
    replay.failure_policy = DurableFailurePolicy::PermanentQuarantine;
    let replayed = host.execute_durable_process(&replay).unwrap();
    assert_eq!(replayed.result.result, "replayed");
    assert_eq!(replayed.result.mutation, "none");
    assert_eq!(
        sqlite
            .export_durable_host_snapshot(&replay.root_instance_id)
            .unwrap(),
        committed
    );

    let mut conflict = replay;
    conflict.envelope_digest =
        "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string();
    conflict.delivery["envelope_digest"] = json!(conflict.envelope_digest);
    let rejected = host.execute_durable_process(&conflict).unwrap();
    assert_eq!(rejected.result.result, "rejected");
    assert_eq!(rejected.result.code.as_deref(), Some("event_id_conflict"));
    assert_eq!(rejected.result.mutation, "none");
    assert_eq!(
        sqlite
            .export_durable_host_snapshot(&conflict.root_instance_id)
            .unwrap(),
        committed
    );
    drop(host);
    drop(sqlite);
    let _ = fs::remove_file(database);
}

fn run_vector(directory: &Path, vector: &Value) -> Result<(), String> {
    let request = request(directory, vector);
    let expected = pointer_file(directory, &vector["result"]);
    let actual = if vector["operation"]
        .as_str()
        .unwrap()
        .starts_with("persistence_")
    {
        run_persistence(directory, vector, &request)?
    } else if matches!(
        vector["operation"].as_str().unwrap(),
        "checkpoint_backup_restore_v2"
            | "checkpoint_inject_store_v2"
            | "checkpoint_register_adapter_v2"
            | "checkpoint_resolve_adapter_v2"
            | "checkpoint_scope_operation_v2"
            | "checkpoint_validate_capabilities_v2"
    ) {
        run_contract(directory, vector, &request)
    } else {
        run_checkpoint(directory, vector, &request)?
    };
    (actual == expected)
        .then_some(())
        .ok_or_else(|| format!("result mismatch: expected {expected}, got {actual}"))
}

fn run_checkpoint(directory: &Path, vector: &Value, request: &Value) -> Result<Value, String> {
    let before_name = vector["checkpoint_before"].as_str();
    let stored_before_name = vector["stored_checkpoint_before"].as_str().or(before_name);
    let after_name = vector["checkpoint_after"].as_str();
    let initial = stored_before_name.map(|name| fs::read(directory.join(name)).unwrap());
    let root = initial
        .as_deref()
        .map(|bytes| {
            json_bytes(bytes)["root_instance_id"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .unwrap_or_else(|| request["root_instance_id"].as_str().unwrap().to_string());
    let memory = Arc::new(MemoryExecutionStore::new());
    memory.initialize_schema().unwrap();
    if let Some(bytes) = &initial {
        assert_eq!(
            memory.insert_if_absent(record(bytes)).unwrap(),
            StoreWriteResult::Committed
        );
    }
    let boundary = vector["failure_boundary"].as_str();
    let store: Arc<dyn ExecutionStore> = Arc::new(FaultStore::new(memory.clone(), boundary));
    let host = CheckpointHost::new(store, Arc::new(resolver(directory)));
    let guard = request.get("expected_checkpoint").map_or_else(
        || MutationGuard::new("", ""),
        |value| {
            MutationGuard::new(
                value["revision"].as_str().unwrap(),
                value["digest"].as_str().unwrap(),
            )
        },
    );
    let operation = vector["operation"].as_str().unwrap();
    let acknowledge_after_commit =
        directory.file_name().unwrap() == "checkpoint-01-native-lifecycle";
    let result = match operation {
        "checkpoint_create_v2" => {
            let bundle = load_bundle(
                &fs::read_to_string(directory.join(request["bundle"]["file"].as_str().unwrap()))
                    .unwrap(),
            )
            .map_err(load_error)?;
            let bindings = bindings(&request["bindings"]);
            host.execute_checkpoint_operation(
                DurableCheckpointOperation::Create {
                    bundle: &bundle,
                    machine_id: request["machine"]["machine_id"].as_str().unwrap(),
                    root_instance_id: request["root_instance_id"].as_str().unwrap(),
                    creation_id: request["creation_id"].as_str().unwrap(),
                    bindings: &bindings,
                    supplied_request_digest: None,
                    replay_retention: json!({"mode":"permanent","permanent_replay_eligible":true,"pruned_through_receipt_sequence":null,"policy_identifier":null}),
                },
                acknowledge_after_commit,
            )
        }
        "checkpoint_admit_v2" => {
            let sources = admission_sources(request);
            host.execute_checkpoint_operation(
                DurableCheckpointOperation::Admit {
                    root_instance_id: &root,
                    sources: &sources,
                    guard: &guard,
                },
                acknowledge_after_commit,
            )
        }
        "checkpoint_step_v2" => {
            let processing = processing_request(request);
            host.execute_checkpoint_operation(
                DurableCheckpointOperation::Step {
                    root_instance_id: &root,
                    request: &processing,
                    guard: &guard,
                },
                acknowledge_after_commit,
            )
        }
        "checkpoint_update_outbox_v2" => host.execute_checkpoint_operation(
            DurableCheckpointOperation::UpdatePendingOutbox {
                root_instance_id: &root,
                effect_id: request["effect_id"].as_str().unwrap(),
                desired: pending_state(request),
                guard: &guard,
            },
            acknowledge_after_commit,
        ),
        "checkpoint_terminalize_outbox_v2" => host.execute_checkpoint_operation(
            DurableCheckpointOperation::TerminalizeOutbox {
                root_instance_id: &root,
                effect_id: request["effect_id"].as_str().unwrap(),
                outcome: terminal_outcome(request),
                guard: &guard,
            },
            acknowledge_after_commit,
        ),
        "checkpoint_compact_outbox_v2" => host.execute_checkpoint_operation(
            DurableCheckpointOperation::CompactOutbox {
                root_instance_id: &root,
                effect_id: request["effect_id"].as_str().unwrap(),
                guard: &guard,
            },
            acknowledge_after_commit,
        ),
        "checkpoint_prune_v2" => {
            let prune = prune_request(request);
            host.execute_checkpoint_operation(
                DurableCheckpointOperation::Prune {
                    root_instance_id: &root,
                    request: &prune,
                    guard: &guard,
                },
                acknowledge_after_commit,
            )
        }
        "checkpoint_tombstone_v2" => host.execute_checkpoint_operation(
            DurableCheckpointOperation::Tombstone {
                root_instance_id: &root,
                operation_id: request["tombstone_operation_id"].as_str().unwrap(),
                guard: &guard,
            },
            acknowledge_after_commit,
        ),
        "checkpoint_delete_retained_record_v2" => host.execute_checkpoint_operation(
            DurableCheckpointOperation::DeleteRetainedRecord {
                root_instance_id: &root,
                guard: &guard,
            },
            acknowledge_after_commit,
        ),
        other => return Err(format!("unsupported checkpoint operation {other}")),
    };
    let stored = memory.load(&root).unwrap().map(|item| item.bytes);
    let expected_after = after_name.map(|name| fs::read(directory.join(name)).unwrap());
    if !same_document(stored.as_deref(), expected_after.as_deref()) {
        let actual = stored.as_deref().map(json_bytes).unwrap_or(Value::Null);
        let expected = expected_after
            .as_deref()
            .map(json_bytes)
            .unwrap_or(Value::Null);
        let mut expected_semantics = expected.clone();
        let mut actual_semantics = actual.clone();
        remove_state_digests(&mut expected_semantics);
        remove_state_digests(&mut actual_semantics);
        return Err(format!(
            "checkpoint_after differs after {}: {}; semantic difference: {}",
            serde_json::to_string(&result).unwrap(),
            first_difference(&expected, &actual, ""),
            first_difference(&expected_semantics, &actual_semantics, "")
        ));
    }
    let actual = serde_json::to_value(result).map_err(load_error)?;
    (actual == pointer_file(directory, &vector["result"]))
        .then_some(actual)
        .ok_or_else(|| "operation result mismatch".to_string())
}

fn run_contract(directory: &Path, vector: &Value, request: &Value) -> Value {
    serde_json::to_value(invoke_contract(directory, vector, request)).unwrap()
}

fn invoke_contract(directory: &Path, vector: &Value, request: &Value) -> DurableHostResult {
    match vector["operation"].as_str().unwrap() {
        "checkpoint_inject_store_v2" => {
            let host: CheckpointHost<InMemoryDefinitionResolver> = CheckpointHost::new(
                Arc::new(StaticStore::new(capabilities(&request["capabilities"]))),
                Arc::new(InMemoryDefinitionResolver::default()),
            );
            host.injected_store_result()
        }
        "checkpoint_register_adapter_v2" => {
            let registry = AdapterRegistry::new();
            adapter_result(
                register_all(&registry, &request["existing_registrations"]).and_then(|_| {
                    register_all(&registry, &json!([request["registration"].clone()]))
                }),
            )
        }
        "checkpoint_resolve_adapter_v2" => {
            let registry = AdapterRegistry::new();
            if let Err(code) = register_all(&registry, &request["registrations"]) {
                return DurableHostResult::validation_rejected(&code);
            }
            let scheme = request["uri"].as_str().unwrap().split_once(':').unwrap().0;
            let result = request["registrations"]
                .as_array()
                .unwrap()
                .iter()
                .find(|item| item["uri_scheme"] == scheme)
                .map_or_else(
                    || {
                        registry.resolve(
                            request["uri"].as_str().unwrap(),
                            &capabilities(&request["requested_capabilities"]),
                        )
                    },
                    |registration| {
                        registry.resolve_configured(
                            request["uri"].as_str().unwrap(),
                            &registration["configuration_schema"],
                            &request["configuration"],
                            &capabilities(&request["requested_capabilities"]),
                        )
                    },
                );
            adapter_result(
                result
                    .map(|_| ())
                    .map_err(|error| error.code.as_str().to_string()),
            )
        }
        "checkpoint_validate_capabilities_v2" => adapter_result(
            validate_store_host_profile(
                &StaticStore::new(capabilities(&request["store_capabilities"])),
                profile(request["host_profile"].as_str().unwrap()),
                &features(&request["host_guarantees"]),
                request["retention_mode"] == "permanent",
            )
            .map_err(|error| error.code.as_str().to_string()),
        ),
        "checkpoint_scope_operation_v2" => {
            let host: CheckpointHost<InMemoryDefinitionResolver> = CheckpointHost::new(
                Arc::new(StaticStore::new(BTreeSet::new())),
                Arc::new(InMemoryDefinitionResolver::default()),
            );
            host.validate_scope_operation(
                &store_scope(&request["scope"]),
                &scoped_records(&request["store_records"]),
                request["portable_identity"].as_str().unwrap(),
                request["effect_id"].as_str().unwrap(),
            )
        }
        "checkpoint_backup_restore_v2" => {
            let Some(file) = vector["checkpoint_before"].as_str() else {
                return DurableHostResult::validation_rejected("invalid_execution_checkpoint");
            };
            let host = CheckpointHost::new(
                Arc::new(StaticStore::new(BTreeSet::new())),
                Arc::new(resolver(directory)),
            );
            host.validate_backup_restore(
                &fs::read(directory.join(file)).unwrap(),
                &string_array(&request["trusted_artifact_digests"]),
                &string_array(&request["checkpoint_digests"]),
                request["retention_mode"].as_str().unwrap(),
            )
        }
        other => DurableHostResult::validation_rejected(&format!("unsupported operation {other}")),
    }
}

fn run_persistence(directory: &Path, vector: &Value, request: &Value) -> Result<Value, String> {
    let before =
        json_bytes(&fs::read(directory.join(vector["store_before"].as_str().unwrap())).unwrap());
    let expected_after =
        json_bytes(&fs::read(directory.join(vector["store_after"].as_str().unwrap())).unwrap());
    let expected_calls =
        json_bytes(&fs::read(directory.join(vector["call_log"].as_str().unwrap())).unwrap())
            ["calls"]
            .clone();
    let database = std::env::temp_dir().join(format!(
        "determa-durable-{}-{}-{}.sqlite",
        std::process::id(),
        directory.file_name().unwrap().to_string_lossy(),
        vector["name"].as_str().unwrap()
    ));
    let _ = fs::remove_file(&database);
    let mode = DurableStoreMode::new(
        if request["retention_mode"] == "permanent" {
            ReceiptRetentionMode::Permanent
        } else {
            ReceiptRetentionMode::Bounded
        },
        OutboxRetentionMode::Bounded,
    );
    let sqlite = Arc::new(SqliteExecutionStore::open(&database, mode).map_err(load_error)?);
    sqlite.initialize_schema().map_err(load_error)?;
    sqlite
        .import_durable_host_snapshot(&before)
        .map_err(load_error)?;
    let host = CheckpointHost::new(sqlite.clone(), Arc::new(resolver(directory)));
    let execution = if vector["operation"] == "persistence_release_quarantine_v2" {
        host.release_durable_quarantine(&DurableQuarantineReleaseRequest {
            root_instance_id: request["expected_checkpoint"]["root_instance_id"]
                .as_str()
                .unwrap()
                .to_string(),
            event_id: request["event_id"].as_str().unwrap().to_string(),
            envelope_digest: request["envelope_digest"].as_str().unwrap().to_string(),
            reason_code: request["quarantine_reason_code"]
                .as_str()
                .unwrap()
                .to_string(),
            release_authorization: request["release_authorization"]
                .as_str()
                .unwrap()
                .to_string(),
            guard: checkpoint_guard(request),
        })
        .map_err(load_error)?
    } else {
        host.execute_durable_process(&process_request(request))
            .map_err(load_error)?
    };
    let store = sqlite
        .export_durable_host_snapshot(
            request["expected_checkpoint"]["root_instance_id"]
                .as_str()
                .unwrap(),
        )
        .map_err(load_error)?;
    let _ = fs::remove_file(&database);
    if store != expected_after {
        return Err(format!(
            "store_after differs: {}",
            first_difference(&expected_after, &store, "")
        ));
    }
    let calls = Value::Array(execution.calls.into_iter().map(Value::String).collect());
    if calls != expected_calls {
        return Err(format!(
            "call log differs: {}",
            first_difference(&expected_calls, &calls, "")
        ));
    }
    serde_json::to_value(DurableHostResult {
        result: execution.result.result,
        mutation: execution.result.mutation,
        core_calls: execution.result.core_calls,
        broker_acknowledged: execution.result.broker_acknowledged,
        code: execution.result.code,
    })
    .map_err(load_error)
}

fn process_request(request: &Value) -> DurableProcessRequest {
    let transaction = &request["transaction_inputs"];
    DurableProcessRequest {
        root_instance_id: request["expected_checkpoint"]["root_instance_id"]
            .as_str()
            .unwrap()
            .to_string(),
        event_id: request["presented_envelope"]["event_id"]
            .as_str()
            .unwrap()
            .to_string(),
        envelope_digest: request["envelope_digest"].as_str().unwrap().to_string(),
        delivery: json!({
            "delivery_mode": "input",
            "envelope": request["presented_envelope"],
            "envelope_digest": request["envelope_digest"]
        }),
        processing_mode: "delayed".to_string(),
        migration: MigrationRequest {
            target_validated_bundle_fingerprint: transaction["target_validated_bundle_fingerprint"]
                .as_str()
                .unwrap()
                .to_string(),
            migration_route: string_array(&transaction["migration_descriptor_digest_route"]),
            maintenance_mode: false,
        },
        migration_limits: ResourceLimits::default(),
        application_writes: transaction["application_writes"]
            .as_object()
            .unwrap()
            .clone(),
        failure_policy: failure_policy(transaction["failure_policy"].as_str().unwrap()),
        guard: checkpoint_guard(request),
        profile: profile(request["host_profile"].as_str().unwrap()),
        host_features: features(&request["host_guarantees"]),
        permanent_retention: request["retention_mode"] == "permanent",
    }
}

fn adapter_result(result: Result<(), String>) -> DurableHostResult {
    match result {
        Ok(()) => DurableHostResult::validated(),
        Err(code) => DurableHostResult::validation_rejected(&code),
    }
}

fn store_scope(value: &Value) -> StoreScope {
    StoreScope {
        scope_id: value["scope_id"].as_str().unwrap().to_string(),
        ownership_binding: value["ownership_binding"].as_str().unwrap().to_string(),
        authorized: value["authorization"] == "authorized",
    }
}

fn scoped_records(value: &Value) -> Vec<ScopedStoreRecord> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|record| ScopedStoreRecord {
            scope_id: record["scope_id"].as_str().unwrap().to_string(),
            ownership_binding: record["ownership_binding"].as_str().unwrap().to_string(),
            portable_identity: record["portable_identity"].as_str().unwrap().to_string(),
            effect_id: record["effect_id"].as_str().unwrap().to_string(),
        })
        .collect()
}

fn admission_sources(request: &Value) -> Vec<AdmissionSource> {
    if let Some(values) = request["envelopes"].as_array() {
        return values
            .iter()
            .cloned()
            .map(AdmissionSource::JsonValue)
            .collect();
    }
    request["ordered_member_sources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|source| {
            source["json_value"].as_object().map_or_else(
                || {
                    AdmissionSource::Utf8Json(
                        source["utf8_json"].as_str().unwrap().as_bytes().to_vec(),
                    )
                },
                |_| AdmissionSource::JsonValue(source["json_value"].clone()),
            )
        })
        .collect()
}

fn bindings(value: &Value) -> Bindings {
    Bindings {
        input: binding_map(&value["input"]),
        external: binding_map(&value["external"]),
    }
}

fn string_array(value: &Value) -> Vec<String> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item.as_str().unwrap().to_string())
        .collect()
}

fn checkpoint_guard(request: &Value) -> MutationGuard {
    MutationGuard::new(
        request["expected_checkpoint"]["revision"].as_str().unwrap(),
        request["expected_checkpoint"]["digest"].as_str().unwrap(),
    )
}

fn failure_policy(value: &str) -> DurableFailurePolicy {
    match value {
        "commit" => DurableFailurePolicy::Commit,
        "inject_pre_commit" => DurableFailurePolicy::InjectPreCommit,
        "inject_post_commit_response_loss" => DurableFailurePolicy::InjectPostCommitResponseLoss,
        "transient_retry" => DurableFailurePolicy::TransientRetry,
        "permanent_quarantine" => DurableFailurePolicy::PermanentQuarantine,
        value => panic!("unknown durable failure policy {value}"),
    }
}

fn prune_request(request: &Value) -> PruneRequest {
    PruneRequest {
        cutoff_receipt_sequence: request["cutoff_receipt_sequence"]
            .as_str()
            .unwrap()
            .to_string(),
        target_mode: request["target_mode"].as_str().unwrap().to_string(),
        policy_identifier: request["policy_identifier"].as_str().map(str::to_string),
        dependency_receipt_sequences: string_array(&request["dependency_receipt_sequences"]),
        dependency_effect_ids: string_array(&request["dependency_effect_ids"]),
    }
}

fn binding_map(value: &Value) -> BTreeMap<String, determa_state::Value> {
    value
        .as_object()
        .into_iter()
        .flat_map(|object| object.iter())
        .map(|(name, value)| (name.clone(), typed_value(value)))
        .collect()
}

fn typed_value(value: &Value) -> determa_state::Value {
    let tagged = value.as_array().unwrap();
    match tagged[0].as_str().unwrap() {
        "null" => determa_state::Value::Null,
        "boolean" => determa_state::Value::Bool(tagged[1].as_bool().unwrap()),
        "string" => determa_state::Value::String(tagged[1].as_str().unwrap().to_string()),
        "integer" => determa_state::Value::Int(tagged[1].as_str().unwrap().parse().unwrap()),
        "float" => determa_state::Value::Float(tagged[1].as_str().unwrap().parse().unwrap()),
        "list" => determa_state::Value::List(
            tagged[1]
                .as_array()
                .unwrap()
                .iter()
                .map(typed_value)
                .collect(),
        ),
        "map" => determa_state::Value::Map(
            tagged[1]
                .as_array()
                .unwrap()
                .iter()
                .map(|entry| {
                    let entry = entry.as_array().unwrap();
                    (
                        entry[0].as_str().unwrap().to_string(),
                        typed_value(&entry[1]),
                    )
                })
                .collect(),
        ),
        tag => panic!("unknown typed value tag {tag}"),
    }
}

fn pending_state(request: &Value) -> PendingOutboxState {
    match request["target_disposition"].as_str().unwrap() {
        "retryable_failure" => PendingOutboxState::RetryableFailure {
            reason_code: request["outcome"]["reason_code"]
                .as_str()
                .unwrap()
                .to_string(),
        },
        "ambiguous" => PendingOutboxState::Ambiguous {
            reason_code: request["outcome"]["reason_code"]
                .as_str()
                .unwrap()
                .to_string(),
        },
        value => panic!("invalid pending state {value}"),
    }
}
fn terminal_outcome(request: &Value) -> TerminalOutboxOutcome {
    let reason = request["outcome"]["reason_code"]
        .as_str()
        .map(str::to_string);
    match request["target_disposition"].as_str().unwrap() {
        "confirmed" => TerminalOutboxOutcome::Confirmed,
        "permanently_rejected" => TerminalOutboxOutcome::PermanentlyRejected {
            reason_code: reason.unwrap(),
        },
        "operator_cancelled" => TerminalOutboxOutcome::OperatorCancelled {
            reason_code: reason.unwrap(),
        },
        "discarded" => TerminalOutboxOutcome::Discarded {
            reason_code: reason.unwrap(),
        },
        "dead_lettered" => TerminalOutboxOutcome::DeadLettered {
            reason_code: reason.unwrap(),
        },
        value => panic!("invalid terminal outcome {value}"),
    }
}
fn target_runtime_id(target: &Value) -> &str {
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
        .unwrap()
}

fn processing_request(request: &Value) -> ProcessingRequest {
    ProcessingRequest {
        target_runtime_id: target_runtime_id(&request["target"]).to_string(),
        event_id: request["event_id"].as_str().unwrap().to_string(),
        envelope_digest: request["envelope_digest"].as_str().unwrap().to_string(),
        acceptance_sequence: request["acceptance_sequence"].as_str().unwrap().to_string(),
        queue_sequence: request["queue_sequence"].as_str().unwrap().to_string(),
        processing_mode: request["processing_mode"].as_str().unwrap().to_string(),
    }
}

fn resolver(directory: &Path) -> InMemoryDefinitionResolver {
    let mut resolver = suite_definition_resolver().clone();
    for entry in fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|v| v.to_str()) == Some("yaml") {
            if let Ok(bundle) = load_bundle(&fs::read_to_string(&path).unwrap()) {
                resolver.insert(bundle, true);
            }
        } else if path.extension().and_then(|v| v.to_str()) == Some("json") {
            if let Ok(value) = serde_json::from_slice::<Value>(&fs::read(&path).unwrap()) {
                if value["migration_descriptor_format"] == "determa.aggregate_migration" {
                    resolver.insert_descriptor(
                        value["migration_descriptor_digest"].as_str().unwrap(),
                        serde_json_canonicalizer::to_vec(&value).unwrap(),
                        true,
                    );
                }
            }
        }
    }
    resolver
}

fn suite_definition_resolver() -> &'static InMemoryDefinitionResolver {
    static RESOLVER: OnceLock<InMemoryDefinitionResolver> = OnceLock::new();
    RESOLVER.get_or_init(|| {
        let mut resolver = InMemoryDefinitionResolver::default();
        collect_machine_documents(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("conformance-suite/conformance"),
            &mut resolver,
        );
        resolver
    })
}

fn collect_machine_documents(directory: &Path, resolver: &mut InMemoryDefinitionResolver) {
    for entry in fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect_machine_documents(&path, resolver);
        } else if path.extension().and_then(|value| value.to_str()) == Some("yaml") {
            if let Ok(bundle) = load_bundle(&fs::read_to_string(path).unwrap()) {
                resolver.insert(bundle, true);
            }
        }
    }
}

fn register_all(registry: &AdapterRegistry, registrations: &Value) -> Result<(), String> {
    for item in registrations.as_array().unwrap() {
        registry
            .register(
                item["uri_scheme"].as_str().unwrap(),
                Arc::new(DeclaredFactory {
                    capabilities: capabilities(&item["capabilities"]),
                    valid: true,
                }),
            )
            .map_err(|e| e.code.as_str().to_string())?;
    }
    Ok(())
}
struct DeclaredFactory {
    capabilities: BTreeSet<ExecutionStoreCapability>,
    valid: bool,
}
impl ExecutionStoreFactory for DeclaredFactory {
    fn create(&self, _: &str) -> Result<Arc<dyn ExecutionStore>, AdapterError> {
        if self.valid {
            Ok(Arc::new(StaticStore::new(self.capabilities.clone())))
        } else {
            Err(AdapterError::new(
                AdapterErrorCode::InvalidAdapterConfiguration,
                "invalid configuration",
            ))
        }
    }
}
struct StaticStore {
    capabilities: BTreeSet<ExecutionStoreCapability>,
}
impl StaticStore {
    fn new(capabilities: BTreeSet<ExecutionStoreCapability>) -> Self {
        Self { capabilities }
    }
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
    fn health(&self) -> Result<HealthStatus, StoreError> {
        Ok(HealthStatus::healthy("static"))
    }
    fn load(&self, _: &str) -> Result<Option<StoreRecord>, StoreError> {
        Ok(None)
    }
    fn insert_if_absent(&self, _: StoreRecord) -> Result<StoreWriteResult, StoreError> {
        unreachable!()
    }
    fn compare_and_swap(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: StoreRecord,
    ) -> Result<StoreWriteResult, StoreError> {
        unreachable!()
    }
}
struct FaultStore {
    inner: Arc<MemoryExecutionStore>,
    boundary: Option<String>,
}
impl FaultStore {
    fn new(inner: Arc<MemoryExecutionStore>, boundary: Option<&str>) -> Self {
        Self {
            inner,
            boundary: boundary.map(str::to_string),
        }
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
    fn health(&self) -> Result<HealthStatus, StoreError> {
        self.inner.health()
    }
    fn load(&self, id: &str) -> Result<Option<StoreRecord>, StoreError> {
        self.inner.load(id)
    }
    fn insert_if_absent(&self, r: StoreRecord) -> Result<StoreWriteResult, StoreError> {
        self.write(|| self.inner.insert_if_absent(r))
    }
    fn compare_and_swap(
        &self,
        id: &str,
        rev: &str,
        digest: &str,
        r: StoreRecord,
    ) -> Result<StoreWriteResult, StoreError> {
        self.write(|| self.inner.compare_and_swap(id, rev, digest, r))
    }
}
impl FaultStore {
    fn write(
        &self,
        operation: impl FnOnce() -> Result<StoreWriteResult, StoreError>,
    ) -> Result<StoreWriteResult, StoreError> {
        if self.boundary.as_deref() == Some("before_commit") {
            return Err(StoreError::injected_pre_commit("injected"));
        }
        let result = operation()?;
        if self.boundary.as_deref() == Some("after_commit_before_acknowledgement") {
            return Err(StoreError::response_lost_after_commit("lost"));
        }
        Ok(result)
    }
}

fn capabilities(value: &Value) -> BTreeSet<ExecutionStoreCapability> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|v| match v.as_str().unwrap() {
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
            value => panic!("unknown capability {value}"),
        })
        .collect()
}
fn features(value: &Value) -> BTreeSet<HostFeature> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|v| match v.as_str().unwrap() {
            "atomic_accept_process" => HostFeature::AtomicCheckpointProcessing,
            "ingress_ack_after_commit" => HostFeature::AcknowledgeAfterCheckpointCommit,
            "durable_redelivery" => HostFeature::DurableRedelivery,
            "outbox_worker" => HostFeature::OutboxWorker,
            "total_outbox_lifecycle" => HostFeature::TotalOutboxLifecycle,
            "retain_unresolved_outbox" => HostFeature::RetainUnresolvedOutbox,
            "retain_receipt_references" => HostFeature::RetainReferencedEffectTombstones,
            "native_shared_transaction_used" => HostFeature::NativeSharedApplicationTransaction,
            value => panic!("unknown feature {value}"),
        })
        .collect()
}
fn profile(value: &str) -> HostProfile {
    match value {
        "durable_embedded_processing" => HostProfile::DurableEmbeddedProcessing,
        "exactly_once_committed_processing" => HostProfile::ExactlyOnceCommittedProcessing,
        "broker_integrated" => HostProfile::BrokerIntegrated,
        "strict_durable_outbox" => HostProfile::StrictDurableOutbox,
        "compact_durable_outbox" => HostProfile::CompactDurableOutbox,
        "shared_application_transaction" => HostProfile::SharedApplicationTransaction,
        value => panic!("unknown profile {value}"),
    }
}

fn request(directory: &Path, vector: &Value) -> Value {
    if !vector["raw_admission_request"].is_null() {
        return vector["raw_admission_request"].clone();
    }
    pointer_file(directory, &vector["request"])
}
fn pointer_file(directory: &Path, reference: &Value) -> Value {
    let value = json_bytes(&fs::read(directory.join(reference["file"].as_str().unwrap())).unwrap());
    value
        .pointer(reference["pointer"].as_str().unwrap())
        .unwrap()
        .clone()
}
fn record(bytes: &[u8]) -> StoreRecord {
    let value = json_bytes(bytes);
    StoreRecord {
        root_instance_id: value["root_instance_id"].as_str().unwrap().to_string(),
        revision: value["revision"].as_str().unwrap().to_string(),
        execution_checkpoint_digest: value["execution_checkpoint_digest"]
            .as_str()
            .unwrap()
            .to_string(),
        bytes: bytes.to_vec(),
    }
}
fn json_bytes(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap()
}
fn same_document(left: Option<&[u8]>, right: Option<&[u8]>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => json_bytes(left) == json_bytes(right),
        (None, None) => true,
        _ => false,
    }
}
fn first_difference(expected: &Value, actual: &Value, path: &str) -> String {
    if expected == actual {
        return String::new();
    }
    match (expected, actual) {
        (Value::Object(expected), Value::Object(actual)) => {
            let mut keys = expected.keys().chain(actual.keys()).collect::<Vec<_>>();
            keys.sort();
            keys.dedup();
            for key in keys {
                if expected.get(key) != actual.get(key) {
                    return first_difference(
                        expected.get(key).unwrap_or(&Value::Null),
                        actual.get(key).unwrap_or(&Value::Null),
                        &format!("{path}/{key}"),
                    );
                }
            }
            path.to_string()
        }
        (Value::Array(expected), Value::Array(actual)) => {
            for index in 0..expected.len().max(actual.len()) {
                if expected.get(index) != actual.get(index) {
                    return first_difference(
                        expected.get(index).unwrap_or(&Value::Null),
                        actual.get(index).unwrap_or(&Value::Null),
                        &format!("{path}/{index}"),
                    );
                }
            }
            path.to_string()
        }
        _ => format!("{path}: expected {expected}, got {actual}"),
    }
}

fn remove_state_digests(value: &mut Value) {
    value.as_object_mut().into_iter().for_each(|object| {
        object.remove("execution_checkpoint_digest");
        if let Some(aggregate) = object
            .get_mut("root_record")
            .and_then(|root| root.get_mut("aggregate_state"))
            .and_then(Value::as_object_mut)
        {
            aggregate.remove("aggregate_state_digest");
        }
    });
}
fn yaml(source: &str) -> Value {
    serde_json::to_value(serde_yaml::from_str::<serde_yaml::Value>(source).unwrap()).unwrap()
}
fn load_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}
fn profile_directories() -> Vec<PathBuf> {
    let root =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("conformance-suite/conformance/profiles");
    let mut result = Vec::new();
    for family in fs::read_dir(root).unwrap() {
        for case in fs::read_dir(family.unwrap().path()).unwrap() {
            let path = case.unwrap().path();
            if path.join("test.yaml").is_file() {
                result.push(path);
            }
        }
    }
    result.sort();
    result
}
