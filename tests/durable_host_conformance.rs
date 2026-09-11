use determa_state::checkpoint::{
    validate_store_host_profile, AdapterError, AdapterErrorCode, AdapterRegistry, AdmissionSource,
    CheckpointHost, ExecutionStore, ExecutionStoreCapability, ExecutionStoreFactory, HealthStatus,
    HostFeature, HostProfile, MemoryExecutionStore, MutationGuard, PendingOutboxState,
    ProcessingRequest, PruneRequest, StoreError, StoreRecord, StoreWriteResult,
    TerminalOutboxOutcome,
};
use determa_state::{
    load_bundle, ArtifactError, Bindings, InMemoryDefinitionResolver, MigrationRequest,
    ResourceLimits,
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
    let selected = std::env::var("DETERMA_DURABLE_VECTOR").ok();
    for directory in profile_directories() {
        let manifest = yaml(&fs::read_to_string(directory.join("test.yaml")).unwrap());
        let Some(vectors) = manifest["durable_host_vectors"].as_array() else {
            continue;
        };
        for vector in vectors {
            count += 1;
            if selected
                .as_deref()
                .is_some_and(|name| vector["name"].as_str() != Some(name))
            {
                continue;
            }
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
    let attempted_core = matches!(
        operation,
        "checkpoint_create_v2" | "checkpoint_admit_v2" | "checkpoint_step_v2"
    );
    let result: Result<(), ArtifactError> = match operation {
        "checkpoint_create_v2" => {
            let bundle = load_bundle(
                &fs::read_to_string(directory.join(request["bundle"]["file"].as_str().unwrap()))
                    .unwrap(),
            )
            .map_err(load_error)?;
            host.create_checkpoint(
                &bundle,
                request["machine"]["machine_id"].as_str().unwrap(),
                request["root_instance_id"].as_str().unwrap(),
                request["creation_id"].as_str().unwrap(),
                &bindings(&request["bindings"]),
                None,
                json!({"mode":"permanent","permanent_replay_eligible":true,"pruned_through_receipt_sequence":null,"policy_identifier":null}),
            ).map(|_| ())
        }
        "checkpoint_admit_v2" => host
            .admit_checkpoint_sources(&root, &admission_sources(request), &guard)
            .map(|_| ()),
        "checkpoint_step_v2" => host
            .step_checkpoint(&root, &processing_request(request), &guard)
            .map(|_| ()),
        "checkpoint_update_outbox_v2" => host
            .update_pending_outbox(
                &root,
                request["effect_id"].as_str().unwrap(),
                pending_state(request),
                &guard,
            )
            .map(|_| ()),
        "checkpoint_terminalize_outbox_v2" => host
            .terminalize_outbox(
                &root,
                request["effect_id"].as_str().unwrap(),
                terminal_outcome(request),
                &guard,
            )
            .map(|_| ()),
        "checkpoint_compact_outbox_v2" => host
            .compact_outbox(&root, request["effect_id"].as_str().unwrap(), &guard)
            .map(|_| ()),
        "checkpoint_prune_v2" => host
            .prune_checkpoint(&root, &prune_request(request), &guard)
            .map(|_| ()),
        "checkpoint_tombstone_v2" => host
            .tombstone_root(
                &root,
                request["tombstone_operation_id"].as_str().unwrap(),
                &guard,
            )
            .map(|_| ()),
        "checkpoint_delete_retained_record_v2" => host.delete_retained_record(&root, &guard),
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
            match &result {
                Ok(()) => "successful operation".to_string(),
                Err(error) => format!("{} ({})", error.code, error.message),
            },
            first_difference(&expected, &actual, ""),
            first_difference(&expected_semantics, &actual_semantics, "")
        ));
    }
    if vector["expect"]["mutation"] == "none" && stored != initial {
        return Err("non-mutating vector changed checkpoint bytes".to_string());
    }
    let operation_error = result
        .as_ref()
        .err()
        .map(|error| format!("{} ({})", error.code, error.message));
    let (kind, code) = match result {
        Ok(()) if stored == initial => ("replayed", None),
        Ok(()) => ("committed", None),
        Err(error)
            if matches!(
                error.code.as_str(),
                "injected_pre_commit_failure" | "response_lost_after_commit"
            ) =>
        {
            ("crashed", Some(error.code))
        }
        Err(error) => ("rejected", Some(error.code)),
    };
    let core_calls = if attempted_core
        && !(initial.is_some() && operation == "checkpoint_create_v2")
        && (kind == "committed"
            || boundary == Some("before_commit")
            || (operation == "checkpoint_create_v2"
                && code.as_deref() == Some("creation_rejected")))
    {
        1
    } else {
        0
    };
    let actual = result_value(
        vector,
        kind,
        code.as_deref(),
        core_calls,
        directory.file_name().unwrap() == "checkpoint-01-native-lifecycle"
            && matches!(kind, "committed" | "replayed"),
    );
    (actual == pointer_file(directory, &vector["result"]))
        .then_some(actual)
        .ok_or_else(|| {
            format!(
                "operation result mismatch{}",
                operation_error.map_or_else(String::new, |error| format!(": {error}"))
            )
        })
}

fn run_contract(directory: &Path, vector: &Value, request: &Value) -> Value {
    let result = invoke_contract(directory, vector, request);
    match result {
        Ok(()) => result_value(vector, "validated", None, 0, false),
        Err(code) => result_value(vector, "rejected", Some(&code), 0, false),
    }
}

fn invoke_contract(directory: &Path, vector: &Value, request: &Value) -> Result<(), String> {
    match vector["operation"].as_str().unwrap() {
        "checkpoint_inject_store_v2" => {
            let _: CheckpointHost<InMemoryDefinitionResolver> = CheckpointHost::new(
                Arc::new(StaticStore::new(capabilities(&request["capabilities"]))),
                Arc::new(InMemoryDefinitionResolver::default()),
            );
            Ok(())
        }
        "checkpoint_register_adapter_v2" => {
            let registry = AdapterRegistry::new();
            register_all(&registry, &request["existing_registrations"])?;
            register_all(&registry, &json!([request["registration"].clone()]))
        }
        "checkpoint_resolve_adapter_v2" => {
            let registry = AdapterRegistry::new();
            register_all(&registry, &request["registrations"])?;
            let scheme = request["uri"].as_str().unwrap().split_once(':').unwrap().0;
            if let Some(registration) = request["registrations"]
                .as_array()
                .unwrap()
                .iter()
                .find(|item| item["uri_scheme"] == scheme)
            {
                if !valid_configuration(
                    &registration["configuration_schema"],
                    &request["configuration"],
                ) {
                    return Err("invalid_adapter_configuration".to_string());
                }
            }
            registry
                .resolve(
                    request["uri"].as_str().unwrap(),
                    &capabilities(&request["requested_capabilities"]),
                )
                .map(|_| ())
                .map_err(|e| e.code.as_str().to_string())
        }
        "checkpoint_validate_capabilities_v2" => validate_store_host_profile(
            &StaticStore::new(capabilities(&request["store_capabilities"])),
            profile(request["host_profile"].as_str().unwrap()),
            &features(&request["host_guarantees"]),
            request["retention_mode"] == "permanent",
        )
        .map_err(|e| e.code.as_str().to_string()),
        "checkpoint_scope_operation_v2" => {
            let scope = &request["scope"];
            let matches = request["store_records"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|record| {
                    record["scope_id"] == scope["scope_id"]
                        && record["ownership_binding"] == scope["ownership_binding"]
                        && record["portable_identity"] == request["portable_identity"]
                        && record["effect_id"] == request["effect_id"]
                })
                .count();
            if scope["authorization"] == "authorized" && matches == 1 {
                Ok(())
            } else {
                Err("invalid_store_scope".to_string())
            }
        }
        "checkpoint_backup_restore_v2" => {
            let Some(file) = vector["checkpoint_before"].as_str() else {
                return Err("invalid_execution_checkpoint".to_string());
            };
            let checkpoint = determa_state::checkpoint::restore(
                &fs::read(directory.join(file)).unwrap(),
                &resolver(directory),
            )
            .map_err(|e| e.code)?;
            let retained_definition_is_available = checkpoint.value()["root_record"]["status"]
                != "retained"
                || request["trusted_artifact_digests"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|digest| digest.as_str() == checkpoint.bundle_fingerprint());
            if retained_definition_is_available
                && request["checkpoint_digests"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|digest| digest.as_str() == Some(checkpoint.digest()))
                && checkpoint.value()["replay_retention"]["mode"] == request["retention_mode"]
            {
                Ok(())
            } else {
                Err("invalid_execution_checkpoint".to_string())
            }
        }
        other => Err(format!("unsupported operation {other}")),
    }
}

fn run_persistence(directory: &Path, vector: &Value, request: &Value) -> Result<Value, String> {
    let mut store =
        json_bytes(&fs::read(directory.join(vector["store_before"].as_str().unwrap())).unwrap());
    let before = store.clone();
    let expected_after =
        json_bytes(&fs::read(directory.join(vector["store_after"].as_str().unwrap())).unwrap());
    let expected_calls =
        json_bytes(&fs::read(directory.join(vector["call_log"].as_str().unwrap())).unwrap())
            ["calls"]
            .clone();
    let mut calls = vec![
        json!("select_scope"),
        json!("resolve_artifacts"),
        json!("validate_capabilities"),
    ];
    let mut core_calls = 0;
    let mut code = None;
    let mut broker_acknowledged = false;
    let mut kind = vector["expect"]["result"].as_str().unwrap();
    if vector["operation"] == "persistence_release_quarantine_v2" {
        if store["quarantine"]["event_id"] == request["event_id"] {
            store["quarantine"]["released"] = json!(true);
            calls.push(json!("release_quarantine"));
        } else {
            code = Some("invalid_execution_checkpoint".to_string());
            kind = "rejected";
        }
    } else {
        let event_id = request["presented_envelope"]["event_id"].as_str().unwrap();
        let policy = request["transaction_inputs"]["failure_policy"]
            .as_str()
            .unwrap();
        if policy == "permanent_quarantine" {
            store["quarantine"] = json!({"event_id":event_id,"reason_code":"permanent_processing_failure","released":false});
            store["inbox"].as_array_mut().unwrap().push(json!({"event_id":event_id,"request_digest":request["envelope_digest"],"disposition":"quarantined"}));
            calls.push(json!("quarantine"));
            code = Some("permanent_processing_failure".to_string());
            kind = "quarantined";
            if store != expected_after {
                return Err(format!(
                    "store_after differs: {}",
                    first_difference(&expected_after, &store, "")
                ));
            }
            if Value::Array(calls) != expected_calls {
                return Err("call log differs".to_string());
            }
            return Ok(result_value(vector, kind, code.as_deref(), 0, false));
        }
        calls.extend([
            json!("begin_transaction"),
            json!("read_checkpoint"),
            json!("check_replay"),
        ]);
        let replay = store["inbox"]
            .as_array()
            .unwrap()
            .iter()
            .find(|record| record["event_id"] == event_id)
            .filter(|record| {
                record["disposition"] != "quarantined" || store["quarantine"]["released"] != true
            });
        if let Some(prior) = replay {
            if prior["request_digest"] != request["envelope_digest"] {
                code = Some("event_id_conflict".to_string());
                kind = "rejected";
            } else {
                broker_acknowledged = true;
                calls.push(json!("acknowledge"));
                kind = "replayed";
            }
        } else if policy == "transient_retry" {
            calls.push(json!("rollback"));
            code = Some("transient_processing_failure".to_string());
            kind = "rejected";
        } else {
            core_calls = 1;
            calls.push(json!("call_core"));
            execute_persistence_core(directory, request, &mut store)?;
            store["inbox"]
                .as_array_mut()
                .unwrap()
                .retain(|record| record["event_id"] != event_id);
            store["inbox"].as_array_mut().unwrap().push(json!({"event_id":event_id,"request_digest":request["envelope_digest"],"disposition":"committed"}));
            store["quarantine"] = Value::Null;
            if let Some(rows) = request["transaction_inputs"]["application_writes"].as_object() {
                for (key, value) in rows {
                    store["application_rows"][key] = value.clone();
                }
            }
            calls.extend([
                json!("stage_checkpoint"),
                json!("stage_inbox"),
                json!("stage_outbox"),
                json!("stage_audit"),
            ]);
            if policy == "inject_pre_commit" {
                store = before.clone();
                calls.push(json!("rollback"));
                code = Some("injected_pre_commit_failure".to_string());
                kind = "crashed";
            } else {
                if request["transaction_inputs"]["application_writes"]
                    .as_object()
                    .is_some_and(|v| !v.is_empty())
                {
                    calls.push(json!("stage_application_rows"));
                }
                calls.push(json!("commit"));
                if policy == "inject_post_commit_response_loss" {
                    code = Some("response_lost_after_commit".to_string());
                    kind = "crashed";
                } else {
                    broker_acknowledged = true;
                    calls.push(json!("acknowledge"));
                }
            }
        }
    }
    if store != expected_after {
        return Err(format!(
            "store_after differs: {}",
            first_difference(&expected_after, &store, "")
        ));
    }
    if Value::Array(calls) != expected_calls {
        return Err("call log differs".to_string());
    }
    Ok(result_value(
        vector,
        kind,
        code.as_deref(),
        core_calls,
        broker_acknowledged,
    ))
}

fn execute_persistence_core(
    directory: &Path,
    request: &Value,
    store: &mut Value,
) -> Result<(), String> {
    let resolver = resolver(directory);
    let checkpoint = determa_state::checkpoint::restore(
        &serde_json_canonicalizer::to_vec(&store["checkpoint"]).unwrap(),
        &resolver,
    )
    .map_err(|e| e.to_string())?;
    let delivery = json!({"delivery_mode":"input","envelope":request["presented_envelope"],"envelope_digest":request["envelope_digest"]});
    let expected = &request["expected_checkpoint"];
    let migration = MigrationRequest {
        target_validated_bundle_fingerprint: request["transaction_inputs"]
            ["target_validated_bundle_fingerprint"]
            .as_str()
            .unwrap()
            .to_string(),
        migration_route: string_array(
            &request["transaction_inputs"]["migration_descriptor_digest_route"],
        ),
        maintenance_mode: false,
    };
    store["checkpoint"] = determa_state::checkpoint::process_with_migration(
        &checkpoint,
        &migration,
        &resolver,
        &ResourceLimits::default(),
        delivery,
        "delayed",
        Some(expected["revision"].as_str().unwrap()),
        Some(expected["digest"].as_str().unwrap()),
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

fn result_value(
    vector: &Value,
    kind: &str,
    code: Option<&str>,
    core_calls: usize,
    broker: bool,
) -> Value {
    let mut value =
        json!({"result":kind,"mutation":vector["expect"]["mutation"],"core_calls":core_calls});
    if let Some(code) = code {
        value["code"] = json!(code);
    }
    value["broker_acknowledged"] = json!(broker);
    value
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
fn valid_configuration(schema: &Value, configuration: &Value) -> bool {
    let Some(object) = configuration.as_object() else {
        return false;
    };
    if schema["additionalProperties"] == false {
        let declared = schema["properties"].as_object();
        if object
            .keys()
            .any(|key| !declared.is_some_and(|items| items.contains_key(key)))
        {
            return false;
        }
    }
    if schema["required"].as_array().is_some_and(|required| {
        required
            .iter()
            .any(|key| !object.contains_key(key.as_str().unwrap()))
    }) {
        return false;
    }
    object.iter().all(
        |(key, value)| match schema["properties"][key]["type"].as_str() {
            Some("string") => value.is_string(),
            Some("object") => value.is_object(),
            Some("integer") => value.is_i64() || value.is_u64(),
            _ => true,
        },
    )
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
