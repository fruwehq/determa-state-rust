use determa_state::{
    admit_v2, create_v2, downgrade_aggregate_v2_to_v1, load_bundle, migrate_aggregate_v2,
    migrate_aggregate_v2_route, restore_aggregate_v2, restore_package_v2, step_v2,
    upgrade_aggregate_v1_to_v2, AdmissionDelivery, Bindings, InMemoryDefinitionResolver,
    MigrationRequest, ResourceLimits,
};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

fn case(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("conformance-suite/conformance/core")
        .join(name)
}

#[test]
fn version2_package_artifacts() {
    let directory = case("118-version2-persistence");
    let mut resolver = InMemoryDefinitionResolver::default();
    let package = restore_package_v2(
        &fs::read(directory.join("package-v2.json")).unwrap(),
        &mut resolver,
    )
    .unwrap();
    assert_eq!(package.migration_route.len(), 1);
    assert_eq!(
        package.aggregate.value()["aggregate_state_schema_version"],
        2
    );
    let error = restore_package_v2(
        &fs::read(directory.join("invalid-package-v2.json")).unwrap(),
        &mut resolver,
    )
    .unwrap_err();
    assert_eq!(
        error.code,
        "unsupported_aggregate_state_package_schema_version"
    );
}

#[test]
fn version2_creation_retains_initial_internal_work() {
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
        "conformance-suite/conformance/profiles/execution-checkpoint/checkpoint-04-version2-mailboxes",
    );
    let bundle = load_bundle(
        &fs::read_to_string(directory.join("creation-owned-work-machine.yaml")).unwrap(),
    )
    .unwrap();
    let aggregate = create_v2(
        &bundle,
        "internal_creator",
        "internal-creation-root",
        "internal-creation",
        &Bindings::default(),
    )
    .unwrap();
    assert_eq!(aggregate.value()["next_acceptance_sequence"], "1");
    assert_eq!(aggregate.value()["next_queue_sequence"], "1");
    assert_eq!(
        aggregate.value()["runtimes"][0]["ready_mailbox"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn all_queue_bearing_persistence_vectors() {
    let directory = case("118-version2-persistence");
    let test = parse_yaml(&fs::read_to_string(directory.join("test.yaml")).unwrap());
    let requests: Value =
        serde_json::from_slice(&fs::read(directory.join("operation-inputs.json")).unwrap())
            .unwrap();
    let vectors = test["version2_vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 15);
    let mut failures = Vec::new();
    for vector in vectors {
        let name = vector["name"].as_str().unwrap();
        if let Err(error) = run_persistence_vector(&directory, &requests, vector) {
            failures.push(format!("{name}: {error}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} queue-bearing persistence vector(s) failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn successful_public_migration_returns_ordered_audit_records() {
    let directory = case("118-version2-persistence");
    let source_bundle =
        load_bundle(&fs::read_to_string(directory.join("machine.yaml")).unwrap()).unwrap();
    let target_bundle =
        load_bundle(&fs::read_to_string(directory.join("target-compatible.yaml")).unwrap())
            .unwrap();
    let mut resolver = InMemoryDefinitionResolver::default();
    resolver.insert(source_bundle.clone(), true);
    let aggregate = restore_aggregate_v2(
        &fs::read(directory.join("base-aggregate-v2.json")).unwrap(),
        &resolver,
    )
    .unwrap();
    let result = migrate_aggregate_v2(
        &aggregate,
        &source_bundle,
        &target_bundle,
        &fs::read(directory.join("descriptor-compatible-v2.json")).unwrap(),
        true,
        &ResourceLimits::default(),
    )
    .unwrap();
    let audits = result["audit_records"].as_array().unwrap();
    assert_eq!(audits.len(), 1);
    assert_eq!(audits[0]["migration_sequence"], "1");
    assert_eq!(
        audits[0]["source_aggregate_state_digest"],
        aggregate.value()["aggregate_state_digest"]
    );
    assert_eq!(
        audits[0]["target_aggregate_state_digest"],
        result["aggregate_state"]["aggregate_state_digest"]
    );
    let before_entry = &aggregate.value()["runtimes"][0]["ready_mailbox"][0]["envelope"];
    let after_entry = &result["aggregate_state"]["runtimes"][0]["ready_mailbox"][0]["envelope"];
    assert_eq!(after_entry["payload"], before_entry["payload"]);
    assert_eq!(after_entry["source"], before_entry["source"]);
    assert_eq!(after_entry["cause_id"], before_entry["cause_id"]);
}

fn run_persistence_vector(
    directory: &Path,
    requests: &Value,
    vector: &Value,
) -> Result<(), String> {
    let request = requests
        .pointer(vector["request_pointer"].as_str().unwrap())
        .ok_or_else(|| "request pointer is absent".to_string())?;
    let before = fs::read(directory.join(vector["state_before"].as_str().unwrap())).unwrap();
    let source_bundle = load_bundle(&fs::read_to_string(directory.join("machine.yaml")).unwrap())
        .map_err(|error| error.to_string())?;
    let mut resolver = InMemoryDefinitionResolver::default();
    resolver.insert(source_bundle.clone(), true);
    for declared in requests.as_object().unwrap().values() {
        let Some(file) = declared["target_bundle"]["bundle_file"].as_str() else {
            continue;
        };
        let bundle = load_bundle(&fs::read_to_string(directory.join(file)).unwrap())
            .map_err(|error| error.to_string())?;
        resolver.insert(bundle, true);
    }
    let legacy_bundle = directory
        .parent()
        .unwrap()
        .join("94-aggregate-wire-round-trip/machine.yaml");
    resolver.insert(
        load_bundle(&fs::read_to_string(legacy_bundle).unwrap()).unwrap(),
        true,
    );
    let actual = match vector["operation"].as_str().unwrap() {
        "upgrade_aggregate_v1_to_v2" => upgrade_aggregate_v1_to_v2(&before, &resolver)
            .map(|aggregate| aggregate.value().clone()),
        "downgrade_aggregate_v2_to_v1" => {
            let aggregate = match restore_aggregate_v2(&before, &resolver) {
                Ok(aggregate) => aggregate,
                Err(error) => return assert_vector(directory, vector, Err(error)),
            };
            downgrade_aggregate_v2_to_v1(&aggregate).and_then(|bytes| {
                let aggregate_state: Value = serde_json::from_slice(&bytes).map_err(|error| {
                    determa_state::Version2Error::new("invalid_aggregate_state", error.to_string())
                })?;
                Ok(serde_json::json!({
                    "result": "success",
                    "aggregate_state": aggregate_state
                }))
            })
        }
        "migrate_aggregate_v2" => {
            let aggregate = match restore_aggregate_v2(&before, &resolver) {
                Ok(aggregate) => aggregate,
                Err(error) => return assert_vector(directory, vector, Err(error)),
            };
            let target_file = request["target_bundle"]["bundle_file"].as_str().unwrap();
            let target_bundle =
                load_bundle(&fs::read_to_string(directory.join(target_file)).unwrap())
                    .map_err(|error| error.to_string())?;
            resolver.insert(target_bundle, true);
            let route = request["migration_descriptor_digest_route"]
                .as_array()
                .unwrap()
                .iter()
                .map(|digest| digest.as_str().unwrap().to_string())
                .collect::<Vec<_>>();
            let descriptor_files = request["migration_descriptor_files"]
                .as_array()
                .map(|files| files.iter().map(|file| file.as_str().unwrap()).collect())
                .unwrap_or_else(|| {
                    request["migration_descriptor_file"]
                        .as_str()
                        .into_iter()
                        .collect::<Vec<_>>()
                });
            for (digest, file) in route.iter().zip(descriptor_files) {
                resolver.insert_descriptor(
                    digest.clone(),
                    fs::read(directory.join(file)).unwrap(),
                    true,
                );
            }
            migrate_aggregate_v2_route(
                &aggregate,
                &MigrationRequest {
                    migration_route: route,
                    target_validated_bundle_fingerprint: request["target_bundle"]
                        ["validated_bundle_fingerprint"]
                        .as_str()
                        .unwrap()
                        .to_string(),
                    maintenance_mode: request["maintenance_mode"].as_bool().unwrap(),
                },
                &resolver,
                &ResourceLimits::default(),
            )
        }
        operation => return Err(format!("unsupported operation {operation}")),
    };
    assert_vector(directory, vector, actual)
}

#[test]
fn all_queue_bearing_core_vectors() {
    let directory = case("117-version2-mailboxes");
    let test = parse_yaml(&fs::read_to_string(directory.join("test.yaml")).unwrap());
    let requests: Value =
        serde_json::from_slice(&fs::read(directory.join("operation-inputs.json")).unwrap())
            .unwrap();
    let vectors = test["version2_vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 38);
    let mut failures = Vec::new();
    for vector in vectors {
        let name = vector["name"].as_str().unwrap();
        if let Err(error) = run_mailbox_vector(&directory, &requests, vector) {
            failures.push(format!("{name}: {error}"));
        }
    }
    assert!(
        failures.is_empty(),
        "{} queue-bearing vector(s) failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

fn run_mailbox_vector(directory: &Path, requests: &Value, vector: &Value) -> Result<(), String> {
    let bundle_path = directory.join(vector["bundle"].as_str().unwrap());
    let bundle = load_bundle(&fs::read_to_string(bundle_path).unwrap())
        .map_err(|error| error.to_string())?;
    let mut resolver = InMemoryDefinitionResolver::default();
    resolver.insert(bundle.clone(), true);
    let request = requests
        .pointer(vector["request_pointer"].as_str().unwrap())
        .ok_or_else(|| "request pointer is absent".to_string())?;
    let operation = vector["operation"].as_str().unwrap();
    let actual = match operation {
        "create_v2" => create_v2(
            &bundle,
            request["machine_id"].as_str().unwrap(),
            request["root_instance_id"].as_str().unwrap(),
            request["creation_id"].as_str().unwrap(),
            &Bindings::default(),
        )
        .map(|aggregate| aggregate.value().clone()),
        "admit_v2" => {
            let before =
                fs::read(directory.join(vector["state_before"].as_str().unwrap())).unwrap();
            let aggregate =
                restore_aggregate_v2(&before, &resolver).map_err(|error| error.to_string())?;
            let deliveries: Vec<AdmissionDelivery> =
                serde_json::from_value(request["deliveries"].clone()).unwrap();
            admit_v2(&bundle, &aggregate, &deliveries)
        }
        "step_v2" => {
            let before =
                fs::read(directory.join(vector["state_before"].as_str().unwrap())).unwrap();
            let aggregate =
                restore_aggregate_v2(&before, &resolver).map_err(|error| error.to_string())?;
            step_v2(
                &bundle,
                &aggregate,
                request["target_runtime_id"].as_str().unwrap(),
            )
        }
        other => return Err(format!("unsupported operation {other}")),
    };
    assert_vector(directory, vector, actual)
}

fn assert_vector(
    directory: &Path,
    vector: &Value,
    actual: Result<Value, determa_state::Version2Error>,
) -> Result<(), String> {
    let expect = &vector["expect"];
    if expect["result"].as_str() == Some("failure") {
        let error = actual.map_err(|error| error.code).unwrap_err();
        let expected = expect["code"].as_str().unwrap();
        return (error == expected)
            .then_some(())
            .ok_or_else(|| format!("failure {error} != {expected}"));
    }
    let actual = actual.map_err(|error| error.to_string())?;
    let expected: Value = serde_json::from_slice(
        &fs::read(directory.join(expect["exact_result_file"].as_str().unwrap())).unwrap(),
    )
    .unwrap();
    (actual == expected)
        .then_some(())
        .ok_or_else(|| first_difference(&expected, &actual, ""))
}

fn first_difference(expected: &Value, actual: &Value, path: &str) -> String {
    if expected == actual {
        return String::new();
    }
    match (expected, actual) {
        (Value::Object(expected), Value::Object(actual)) => {
            for key in expected.keys().chain(actual.keys()) {
                if key.ends_with("_digest") {
                    continue;
                }
                let child = format!("{path}/{key}");
                if expected.get(key) != actual.get(key) {
                    return first_difference(
                        expected.get(key).unwrap_or(&Value::Null),
                        actual.get(key).unwrap_or(&Value::Null),
                        &child,
                    );
                }
            }
            format!("difference at {path}")
        }
        _ => format!("{path}: expected {expected}, got {actual}"),
    }
}

fn parse_yaml(source: &str) -> Value {
    serde_json::to_value(serde_yaml::from_str::<serde_yaml::Value>(source).unwrap()).unwrap()
}
