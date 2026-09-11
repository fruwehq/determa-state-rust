use determa_state::checkpoint::{
    checkpoint_admit_v2, checkpoint_prune_v2, checkpoint_step_v2, restore_execution_checkpoint_v2,
    upgrade_execution_checkpoint_v1_to_v2, CheckpointHost, DeliveryRequest, ExecutionStore,
    MaintenanceMigrationRequest, MemoryExecutionStore, MutationGuard, StoreRecord,
};
use determa_state::{load_bundle, InMemoryDefinitionResolver, ResourceLimits, Version2Error};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

fn directory() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
        "conformance-suite/conformance/profiles/execution-checkpoint/checkpoint-04-version2-mailboxes",
    )
}

#[test]
fn all_version2_checkpoint_vectors() {
    let directory = directory();
    let test = yaml(&directory.join("test.yaml"));
    let requests = json(&directory.join("operation-inputs.json"));
    let (resolver, bundles) = definitions(&directory);
    let vectors = test["version2_vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 60);
    let mut failures = Vec::new();
    for vector in vectors {
        let name = vector["name"].as_str().unwrap();
        if let Err(error) = run_vector(&directory, &requests, vector, &resolver, &bundles) {
            failures.push(format!("{name}: {error}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} checkpoint v2 vector(s) failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn all_version2_checkpoint_artifacts() {
    let directory = directory();
    let test = yaml(&directory.join("test.yaml"));
    let (resolver, _) = definitions(&directory);
    let mut failures = Vec::new();
    for document in test["artifacts"]["documents"].as_array().unwrap() {
        if document["kind"] != "execution_checkpoint_v2" {
            continue;
        }
        let file = document["file"].as_str().unwrap();
        let actual =
            restore_execution_checkpoint_v2(&fs::read(directory.join(file)).unwrap(), &resolver);
        let valid = document["valid"].as_bool().unwrap();
        if actual.is_ok() != valid {
            failures.push(format!("{file}: expected valid={valid}, got {actual:?}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} checkpoint artifact(s) failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

fn run_vector(
    directory: &Path,
    requests: &Value,
    vector: &Value,
    resolver: &InMemoryDefinitionResolver,
    bundles: &BTreeMap<String, determa_state::Bundle>,
) -> Result<(), String> {
    let request = requests
        .pointer(vector["request_pointer"].as_str().unwrap())
        .unwrap();
    let before = fs::read(directory.join(vector["checkpoint_before"].as_str().unwrap())).unwrap();
    let operation = vector["operation"].as_str().unwrap();
    let actual = match operation {
        "upgrade_checkpoint_v1_to_v2" => {
            upgrade_execution_checkpoint_v1_to_v2(&before, resolver).map(|v| v.value().clone())
        }
        "checkpoint_admit_v2" => {
            let checkpoint = match restore_execution_checkpoint_v2(&before, resolver) {
                Ok(v) => v,
                Err(e) => return assert_vector(directory, vector, Err(e)),
            };
            let bundle = bundle_for(
                &checkpoint.value()["root_record"]["aggregate_state"],
                bundles,
            )
            .unwrap_or_else(|_| bundles.values().next().unwrap());
            checkpoint_admit_v2(
                bundle,
                &checkpoint,
                request["deliveries"].as_array().unwrap_or(&Vec::new()),
                request["expected_revision"].as_str(),
                request["expected_checkpoint_digest"].as_str(),
            )
        }
        "checkpoint_step_v2" => {
            let checkpoint = match restore_execution_checkpoint_v2(&before, resolver) {
                Ok(v) => v,
                Err(e) => return assert_vector(directory, vector, Err(e)),
            };
            let bundle = bundle_for(
                &checkpoint.value()["root_record"]["aggregate_state"],
                bundles,
            )?;
            checkpoint_step_v2(
                bundle,
                &checkpoint,
                request["target_runtime_id"].as_str().unwrap(),
                request["expected_revision"].as_str(),
                request["expected_checkpoint_digest"].as_str(),
            )
        }
        "checkpoint_prune_v2" => {
            let checkpoint = match restore_execution_checkpoint_v2(&before, resolver) {
                Ok(v) => v,
                Err(e) => return assert_vector(directory, vector, Err(e)),
            };
            checkpoint_prune_v2(
                &checkpoint,
                request["cutoff_receipt_sequence"].as_str().unwrap(),
                request["expected_revision"].as_str(),
                request["expected_checkpoint_digest"].as_str(),
            )
        }
        "checkpoint_migrate_v2" => {
            checkpoint_migrate_v2(directory, &before, request, vector, resolver)
        }
        "checkpoint_v1_accept" => {
            checkpoint_v1_accept(directory, &before, request, vector, resolver)
        }
        other => return Err(format!("unsupported operation {other}")),
    };
    assert_vector(directory, vector, actual)
}

fn checkpoint_migrate_v2(
    directory: &Path,
    before: &[u8],
    request: &Value,
    vector: &Value,
    resolver: &InMemoryDefinitionResolver,
) -> Result<Value, Version2Error> {
    let checkpoint: Value = serde_json::from_slice(before).unwrap();
    let root_instance_id = checkpoint["root_instance_id"].as_str().unwrap();
    let store = Arc::new(MemoryExecutionStore::new());
    store
        .insert_if_absent(StoreRecord {
            root_instance_id: root_instance_id.to_string(),
            revision: checkpoint["revision"].as_str().unwrap().to_string(),
            execution_checkpoint_digest: checkpoint["execution_checkpoint_digest"]
                .as_str()
                .unwrap()
                .to_string(),
            bytes: before.to_vec(),
        })
        .unwrap();
    let mut host_resolver = resolver.clone();
    for file in request["migration_descriptor_files"]
        .as_array()
        .into_iter()
        .flatten()
    {
        let bytes = fs::read(directory.join(file.as_str().unwrap())).unwrap();
        let descriptor: Value = serde_json::from_slice(&bytes).unwrap();
        host_resolver.insert_descriptor(
            descriptor["migration_descriptor_digest"]
                .as_str()
                .unwrap()
                .to_string(),
            bytes,
            true,
        );
    }
    let host = CheckpointHost::new(store.clone(), Arc::new(host_resolver));
    let result = host.maintenance_migration_v2(&MaintenanceMigrationRequest {
        root_instance_id: root_instance_id.to_string(),
        operation_id: request["operation_id"].as_str().unwrap().to_string(),
        source_aggregate_state_digest: checkpoint["root_record"]["aggregate_state"]
            ["aggregate_state_digest"]
            .as_str()
            .unwrap()
            .to_string(),
        target_validated_bundle_fingerprint: request["target_bundle"]
            ["validated_bundle_fingerprint"]
            .as_str()
            .unwrap()
            .to_string(),
        migration_descriptor_digest_route: request["migration_descriptor_digest_route"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_string())
            .collect(),
        maintenance_mode: request["maintenance_mode"].as_bool().unwrap(),
        supplied_request_digest: Some(request["request_digest"].as_str().unwrap().to_string()),
        guard: MutationGuard::new(
            request["expected_revision"].as_str().unwrap(),
            request["expected_checkpoint_digest"].as_str().unwrap(),
        ),
        limits: ResourceLimits::default(),
    });
    let persisted = store.load(root_instance_id).unwrap().unwrap();
    if result.is_err() && persisted.bytes != before {
        return Err(Version2Error::new(
            "invalid_execution_checkpoint",
            "failed maintenance vector changed the exact checkpoint bytes",
        ));
    }
    let expected_checkpoint = if result.is_ok() {
        vector["checkpoint_after"].as_str().unwrap()
    } else {
        vector["expect"]["unchanged_file"].as_str().unwrap()
    };
    let actual: Value = serde_json::from_slice(&persisted.bytes).unwrap();
    let expected = json(&directory.join(expected_checkpoint));
    if actual != expected {
        return Err(Version2Error::new(
            "invalid_execution_checkpoint",
            difference(&expected, &actual, "persisted"),
        ));
    }
    result
}

fn checkpoint_v1_accept(
    directory: &Path,
    before: &[u8],
    request: &Value,
    vector: &Value,
    resolver: &InMemoryDefinitionResolver,
) -> Result<Value, Version2Error> {
    let checkpoint: Value = serde_json::from_slice(before).unwrap();
    let store = Arc::new(MemoryExecutionStore::new());
    store
        .insert_if_absent(StoreRecord {
            root_instance_id: checkpoint["root_instance_id"].as_str().unwrap().to_string(),
            revision: checkpoint["revision"].as_str().unwrap().to_string(),
            execution_checkpoint_digest: checkpoint["execution_checkpoint_digest"]
                .as_str()
                .unwrap()
                .to_string(),
            bytes: before.to_vec(),
        })
        .unwrap();
    let mut host_resolver = resolver.clone();
    let bundle = load_bundle(
        &fs::read_to_string(directory.join(vector["bundle"].as_str().unwrap())).unwrap(),
    )
    .unwrap();
    let selected_bundle_fingerprint = bundle.fingerprint.clone();
    host_resolver.insert(bundle, true);
    let host = CheckpointHost::new(store.clone(), Arc::new(host_resolver));
    let result = host.accept_delivery_for_bundle(
        DeliveryRequest {
            checkpoint_root_instance_id: checkpoint["root_instance_id"]
                .as_str()
                .unwrap()
                .to_string(),
            candidate: request["deliveries"][0].clone(),
            guard: MutationGuard::new(
                request["expected_revision"].as_str().unwrap(),
                request["expected_checkpoint_digest"].as_str().unwrap(),
            ),
        },
        &selected_bundle_fingerprint,
    );
    let after = store
        .load(checkpoint["root_instance_id"].as_str().unwrap())
        .unwrap()
        .unwrap();
    if after.bytes != before {
        return Err(Version2Error::new(
            "invalid_execution_checkpoint",
            "version-1 rejection mutated the stored checkpoint",
        ));
    }
    match result {
        Ok(determa_state::checkpoint::AcceptanceResult::NotAccepted(result)) => Err(
            Version2Error::new(result.failure.code.as_str(), "delivery was not accepted"),
        ),
        Ok(_) => Ok(Value::Null),
        Err(error) => Err(Version2Error::new(error.code.as_str(), error.message)),
    }
}

fn assert_vector(
    directory: &Path,
    vector: &Value,
    actual: Result<Value, Version2Error>,
) -> Result<(), String> {
    let expect = &vector["expect"];
    if expect["result"] == "failure" {
        return match actual {
            Err(error) if error.code == expect["code"].as_str().unwrap() => Ok(()),
            Err(error) => Err(format!("failure {} != {}", error.code, expect["code"])),
            Ok(_) => Err(format!("expected failure {}, got success", expect["code"])),
        };
    }
    let actual = actual.map_err(|error| error.to_string())?;
    let expected = json(&directory.join(expect["exact_result_file"].as_str().unwrap()));
    (actual == expected)
        .then_some(())
        .ok_or_else(|| difference(&expected, &actual, ""))
}

fn definitions(
    directory: &Path,
) -> (
    InMemoryDefinitionResolver,
    BTreeMap<String, determa_state::Bundle>,
) {
    let mut resolver = InMemoryDefinitionResolver::default();
    let mut bundles = BTreeMap::new();
    let profile = directory.parent().unwrap();
    for path in files(profile) {
        if path.extension().and_then(|v| v.to_str()) != Some("yaml")
            || path.file_name().unwrap() == "test.yaml"
        {
            continue;
        }
        if let Ok(bundle) = load_bundle(&fs::read_to_string(&path).unwrap()) {
            resolver.insert(bundle.clone(), true);
            bundles.insert(bundle.fingerprint.clone(), bundle);
        }
    }
    (resolver, bundles)
}

fn files(directory: &Path) -> Vec<PathBuf> {
    let mut result = Vec::new();
    for entry in fs::read_dir(directory).unwrap().flatten() {
        let path = entry.path();
        if path.is_dir() {
            result.extend(files(&path));
        } else {
            result.push(path);
        }
    }
    result
}

fn bundle_for<'a>(
    aggregate: &Value,
    bundles: &'a BTreeMap<String, determa_state::Bundle>,
) -> Result<&'a determa_state::Bundle, String> {
    bundles
        .get(
            aggregate["validated_bundle_fingerprint"]
                .as_str()
                .unwrap_or(""),
        )
        .ok_or_else(|| {
            format!(
                "bundle not found for {}",
                aggregate["validated_bundle_fingerprint"]
            )
        })
}

fn difference(expected: &Value, actual: &Value, path: &str) -> String {
    if expected == actual {
        return String::new();
    }
    if let (Some(e), Some(a)) = (expected.as_object(), actual.as_object()) {
        let mut keys = e.keys().chain(a.keys()).collect::<Vec<_>>();
        keys.sort();
        keys.dedup();
        for key in keys {
            if key.ends_with("_digest") {
                continue;
            }
            if e.get(key) != a.get(key) {
                return difference(
                    e.get(key).unwrap_or(&Value::Null),
                    a.get(key).unwrap_or(&Value::Null),
                    &format!("{path}/{key}"),
                );
            }
        }
    }
    format!("{path}: expected {expected}, got {actual}")
}

fn json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}
fn yaml(path: &Path) -> Value {
    serde_json::to_value(
        serde_yaml::from_str::<serde_yaml::Value>(&fs::read_to_string(path).unwrap()).unwrap(),
    )
    .unwrap()
}
