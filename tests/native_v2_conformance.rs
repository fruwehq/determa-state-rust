use determa_state::checkpoint::{
    CheckpointHost, ExecutionStore, MaintenanceMigrationRequest, MemoryExecutionStore,
    MutationGuard, StoreRecord, StoreWriteResult,
};
use determa_state::{
    admit_v2, create_v2, load_bundle, migrate_aggregate_v2_route, restore_aggregate_v2,
    restore_package_v2, step_v2, AdmissionDelivery, Bindings, InMemoryDefinitionResolver,
    MigrationRequest, ResourceLimits, Version2Error,
};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const CASES: &[&str] = &[
    "117-version2-mailboxes",
    "118-version2-persistence",
    "119-native-v2-aggregate-integrity",
    "120-native-v2-definition-package",
    "121-native-v2-migration-totality",
    "122-native-v2-migration-execution",
    "123-native-v2-migration-guards",
    "124-native-v2-occurrence-identity",
];

#[test]
fn all_162_native_v2_vectors_match_exactly() {
    let mut count = 0;
    let mut failures = Vec::new();
    for case in CASES {
        let directory = case_dir(case);
        let manifest = parse_yaml(&fs::read_to_string(directory.join("test.yaml")).unwrap());
        for vector in manifest["version2_vectors"].as_array().unwrap() {
            count += 1;
            if let Err(error) = run_vector(&directory, vector) {
                failures.push(format!(
                    "{case}/{}: {error}",
                    vector["name"].as_str().unwrap()
                ));
            }
        }
    }
    let (checkpoint_count, checkpoint_failures) = run_checkpoint_vectors();
    count += checkpoint_count;
    failures.extend(checkpoint_failures);
    assert_eq!(count, 162);
    assert!(
        failures.is_empty(),
        "{} native-v2 vector(s) failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

fn run_checkpoint_vectors() -> (usize, Vec<String>) {
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
        "conformance-suite/conformance/profiles/execution-checkpoint/checkpoint-04-version2-mailboxes",
    );
    let manifest = parse_yaml(&fs::read_to_string(directory.join("test.yaml")).unwrap());
    let requests: Value =
        serde_json::from_slice(&fs::read(directory.join("operation-inputs.json")).unwrap())
            .unwrap();
    let mut failures = Vec::new();
    let vectors = manifest["version2_vectors"].as_array().unwrap();
    for vector in vectors {
        if let Err(error) = run_checkpoint_vector(&directory, &requests, vector) {
            failures.push(format!(
                "checkpoint-04-version2-mailboxes/{}: {error}",
                vector["name"].as_str().unwrap()
            ));
        }
    }
    (vectors.len(), failures)
}

fn run_checkpoint_vector(directory: &Path, requests: &Value, vector: &Value) -> Result<(), String> {
    let request = requests
        .pointer(vector["request_pointer"].as_str().unwrap())
        .unwrap();
    let mut resolver = InMemoryDefinitionResolver::default();
    for key in ["source_bundle", "target_bundle"] {
        let declared = &request[key];
        let bundle = load_bundle(
            &fs::read_to_string(directory.join(declared["bundle_file"].as_str().unwrap())).unwrap(),
        )
        .map_err(|error| error.to_string())?;
        resolver.insert_at(
            declared["validated_bundle_fingerprint"].as_str().unwrap(),
            bundle,
            true,
        );
    }
    for entry in fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("yaml") {
            continue;
        }
        if let Ok(bundle) = load_bundle(&fs::read_to_string(path).unwrap()) {
            resolver.insert(bundle, true);
        }
    }
    for (digest, file) in request["migration_descriptor_digest_route"]
        .as_array()
        .unwrap()
        .iter()
        .zip(request["migration_descriptor_files"].as_array().unwrap())
    {
        resolver.insert_descriptor(
            digest.as_str().unwrap(),
            fs::read(directory.join(file.as_str().unwrap())).unwrap(),
            true,
        );
    }
    let before_bytes =
        fs::read(directory.join(vector["checkpoint_before"].as_str().unwrap())).unwrap();
    let before: Value = serde_json::from_slice(&before_bytes).unwrap();
    let root_instance_id = before["root_instance_id"].as_str().unwrap();
    let record = StoreRecord {
        root_instance_id: root_instance_id.to_string(),
        revision: before["revision"].as_str().unwrap().to_string(),
        execution_checkpoint_digest: before["execution_checkpoint_digest"]
            .as_str()
            .unwrap()
            .to_string(),
        bytes: before_bytes.clone(),
    };
    let store: Arc<dyn ExecutionStore> = Arc::new(MemoryExecutionStore::new());
    store.initialize_schema().unwrap();
    assert_eq!(
        store.insert_if_absent(record).unwrap(),
        StoreWriteResult::Committed
    );
    let host = CheckpointHost::new(store.clone(), Arc::new(resolver));
    let operation_id = request["operation_id"].as_str().unwrap();
    let source_digest = before["root_record"]["aggregate_state"]["aggregate_state_digest"]
        .as_str()
        .or_else(|| {
            before["operation_receipts"]
                .as_array()
                .unwrap()
                .iter()
                .find(|receipt| receipt["operation_id"].as_str() == Some(operation_id))
                .and_then(|receipt| receipt["source_aggregate_state_digest"].as_str())
        })
        .unwrap();
    let actual = host.maintenance_migration_v2(&MaintenanceMigrationRequest {
        root_instance_id: root_instance_id.to_string(),
        operation_id: operation_id.to_string(),
        source_aggregate_state_digest: source_digest.to_string(),
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
    let asserted = assert_result(directory, vector, actual);
    if vector["expect"]["result"] == "failure" {
        let after = store.load(root_instance_id).unwrap().unwrap();
        if after.bytes != before_bytes {
            return Err("failure changed checkpoint bytes".to_string());
        }
    } else if let Some(after_file) = vector["checkpoint_after"].as_str() {
        let after = store.load(root_instance_id).unwrap().unwrap();
        let expected = fs::read(directory.join(after_file)).unwrap();
        if after.bytes != expected {
            let actual: Value = serde_json::from_slice(&after.bytes).unwrap();
            let expected: Value = serde_json::from_slice(&expected).unwrap();
            return Err(format!(
                "committed checkpoint bytes differ: {}",
                first_difference(&expected, &actual, "")
            ));
        }
    }
    asserted
}

fn run_vector(directory: &Path, vector: &Value) -> Result<(), String> {
    let requests: Value = serde_json::from_slice(
        &fs::read(directory.join(vector["request_file"].as_str().unwrap())).unwrap(),
    )
    .unwrap();
    let request = requests
        .pointer(vector["request_pointer"].as_str().unwrap())
        .ok_or_else(|| "request pointer is absent".to_string())?;
    let mut resolver = resolver_from(directory, request)?;
    let before = vector["state_before"]
        .as_str()
        .map(|file| fs::read(directory.join(file)).unwrap());
    let before_copy = before.clone();
    let operation = vector["operation"].as_str().unwrap();
    let actual = (|| -> Result<Value, Version2Error> {
        match operation {
            "create_v2" => {
                let bundle_file = vector["bundle"]
                    .as_str()
                    .or_else(|| request["bundle"]["bundle_file"].as_str())
                    .unwrap();
                let bundle = load_bundle(&fs::read_to_string(directory.join(bundle_file)).unwrap())
                    .map_err(invalid)?;
                create_v2(
                    &bundle,
                    request["machine_id"].as_str().unwrap(),
                    request["root_instance_id"].as_str().unwrap(),
                    request["creation_id"].as_str().unwrap(),
                    &Bindings::default(),
                )
                .map(|aggregate| aggregate.value().clone())
            }
            "round_trip_aggregate_v2" => restore_aggregate_v2(
                before.as_deref().expect("round trip requires state_before"),
                &resolver,
            )
            .map(|aggregate| aggregate.value().clone()),
            "restore_package_v2" => {
                restore_package_operation(directory, request, vector, &mut resolver)
            }
            "admit_v2" => {
                let bundle = vector_bundle(directory, vector)?;
                let aggregate = restore_aggregate_v2(before.as_deref().unwrap(), &resolver)?;
                let deliveries: Vec<AdmissionDelivery> =
                    serde_json::from_value(request["deliveries"].clone()).map_err(invalid)?;
                admit_v2(&bundle, &aggregate, &deliveries)
            }
            "step_v2" => {
                let bundle = vector_bundle(directory, vector)?;
                let aggregate = restore_aggregate_v2(before.as_deref().unwrap(), &resolver)?;
                step_v2(
                    &bundle,
                    &aggregate,
                    request["target_runtime_id"].as_str().unwrap(),
                )
            }
            "migrate_aggregate_v2" => {
                migrate_operation(directory, request, before.as_deref().unwrap(), &resolver)
            }
            "migrate_then_process_v2" => {
                migrate_then_process(directory, request, before.as_deref().unwrap(), &resolver)
            }
            other => Err(Version2Error::new("unsupported_operation", other)),
        }
    })();
    let assertion = assert_result(directory, vector, actual);
    if vector["expect"]["result"] == "failure" && before != before_copy {
        return Err("failure mutated checkpoint/aggregate input bytes".to_string());
    }
    assertion
}

fn restore_package_operation(
    directory: &Path,
    request: &Value,
    vector: &Value,
    resolver: &mut InMemoryDefinitionResolver,
) -> Result<Value, Version2Error> {
    let package = restore_package_v2(
        &fs::read(directory.join(request["package_file"].as_str().unwrap())).unwrap(),
        resolver,
    )?;
    let drives_route = vector["covers"].as_array().unwrap().iter().any(|cover| {
        matches!(
            cover.as_str(),
            Some("attachments_seed_empty_resolver_and_drive_route")
                | Some("put_if_absent_is_idempotent")
        )
    });
    if !drives_route {
        return Ok(package.aggregate.value().clone());
    }
    let final_descriptor = resolver
        .descriptor(package.migration_route.last().unwrap())
        .ok_or_else(|| Version2Error::new("migration_descriptor_not_found", "route is absent"))?;
    let descriptor: Value = serde_json::from_slice(&final_descriptor.bytes).map_err(invalid)?;
    migrate_aggregate_v2_route(
        &package.aggregate,
        &MigrationRequest {
            migration_route: package.migration_route,
            target_validated_bundle_fingerprint: descriptor["target_validated_bundle_fingerprint"]
                .as_str()
                .unwrap()
                .to_string(),
            maintenance_mode: request["maintenance_mode"].as_bool().unwrap(),
        },
        resolver,
        &ResourceLimits::default(),
    )
}

fn migrate_operation(
    _directory: &Path,
    request: &Value,
    before: &[u8],
    resolver: &InMemoryDefinitionResolver,
) -> Result<Value, Version2Error> {
    let aggregate = restore_aggregate_v2(before, resolver)?;
    let migration_request = migration_request(request)?;
    let limits = request
        .get("resource_limits")
        .map(|value| serde_json::from_value(value.clone()).map_err(invalid))
        .transpose()?
        .unwrap_or_default();
    let result = migrate_aggregate_v2_route(&aggregate, &migration_request, resolver, &limits)?;
    for _ in 1..request["repeat_count"].as_u64().unwrap_or(1) {
        let repeated =
            migrate_aggregate_v2_route(&aggregate, &migration_request, resolver, &limits)?;
        if repeated != result {
            return Err(Version2Error::new(
                "migration_route_mismatch",
                "identical migration retry produced a different result",
            ));
        }
    }
    Ok(result)
}

fn migrate_then_process(
    directory: &Path,
    request: &Value,
    before: &[u8],
    resolver: &InMemoryDefinitionResolver,
) -> Result<Value, Version2Error> {
    let migrated = migrate_operation(directory, request, before, resolver)?;
    let target_file = request["target_bundle"]["bundle_file"].as_str().unwrap();
    let target = load_bundle(&fs::read_to_string(directory.join(target_file)).unwrap())
        .map_err(|error| Version2Error::new("invalid_definition", error.to_string()))?;
    let aggregate = restore_aggregate_v2(
        &serde_json_canonicalizer::to_vec(&migrated["aggregate_state"]).map_err(invalid)?,
        resolver,
    )?;
    let delivery: AdmissionDelivery =
        serde_json::from_value(request["delivery"].clone()).map_err(invalid)?;
    let admitted = match admit_v2(&target, &aggregate, std::slice::from_ref(&delivery)) {
        Ok(admitted) => admitted,
        Err(error) => {
            let root = aggregate.value()["runtimes"]
                .as_array()
                .unwrap()
                .iter()
                .find(|runtime| runtime["runtime_id"] == aggregate.value()["root_runtime_id"])
                .unwrap();
            return Ok(json!({
                "result": "migrated_and_processed",
                "migration_audit_records": migrated["audit_records"],
                "processing": {
                    "core_step_result_format": "determa.core_step_result",
                    "core_step_result_schema_version": 2,
                    "disposition": "rejected",
                    "emissions": [],
                    "fault": null,
                    "lifecycle_dispositions": [],
                    "rejection": { "code": error.code },
                    "state": aggregate.value(),
                    "status": root["status"]
                }
            }));
        }
    };
    let admitted_aggregate = restore_aggregate_v2(
        &serde_json_canonicalizer::to_vec(&admitted["state"]).map_err(invalid)?,
        resolver,
    )?;
    let runtime_id = target_runtime_id(&delivery.envelope.target)?;
    let processing = step_v2(&target, &admitted_aggregate, runtime_id)?;
    Ok(json!({
        "result": "migrated_and_processed",
        "migration_audit_records": migrated["audit_records"],
        "processing": processing
    }))
}

fn migration_request(request: &Value) -> Result<MigrationRequest, Version2Error> {
    let target = request["target_bundle"]["validated_bundle_fingerprint"].clone();
    MigrationRequest::from_json(&json!({
        "migration_route": request["migration_descriptor_digest_route"],
        "target_validated_bundle_fingerprint": target,
        "maintenance_mode": request["maintenance_mode"]
    }))
    .map_err(|error| Version2Error::new(error.code.as_str(), error.message))
}

fn resolver_from(directory: &Path, request: &Value) -> Result<InMemoryDefinitionResolver, String> {
    let mut resolver = InMemoryDefinitionResolver::default();
    let declaration = request
        .get("definition_resolver")
        .or_else(|| request.get("artifact_resolver"));
    if let Some(declaration) = declaration {
        for definition in declaration["definitions"].as_array().unwrap() {
            let bundle = load_bundle(
                &fs::read_to_string(directory.join(definition["bundle_file"].as_str().unwrap()))
                    .unwrap(),
            )
            .map_err(|error| error.to_string())?;
            resolver.insert_at(
                definition["validated_bundle_fingerprint"].as_str().unwrap(),
                bundle,
                definition["trusted"].as_bool().unwrap(),
            );
        }
        for descriptor in declaration["migration_descriptors"].as_array().unwrap() {
            resolver.insert_descriptor(
                descriptor["migration_descriptor_digest"].as_str().unwrap(),
                fs::read(directory.join(descriptor["descriptor_file"].as_str().unwrap())).unwrap(),
                descriptor["trusted"].as_bool().unwrap(),
            );
        }
    } else {
        for entry in fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("yaml") {
                continue;
            }
            if let Ok(bundle) = load_bundle(&fs::read_to_string(path).unwrap()) {
                resolver.insert(bundle, true);
            }
        }
        if let (Some(route), Some(files)) = (
            request["migration_descriptor_digest_route"].as_array(),
            request["migration_descriptor_files"].as_array(),
        ) {
            for (digest, file) in route.iter().zip(files) {
                resolver.insert_descriptor(
                    digest.as_str().unwrap(),
                    fs::read(directory.join(file.as_str().unwrap())).unwrap(),
                    true,
                );
            }
        } else if let (Some(digest), Some(file)) = (
            request["migration_descriptor_digest_route"]
                .as_array()
                .and_then(|route| route.first())
                .and_then(Value::as_str),
            request["migration_descriptor_file"].as_str(),
        ) {
            resolver.insert_descriptor(digest, fs::read(directory.join(file)).unwrap(), true);
        }
    }
    Ok(resolver)
}

fn vector_bundle(directory: &Path, vector: &Value) -> Result<determa_state::Bundle, Version2Error> {
    load_bundle(&fs::read_to_string(directory.join(vector["bundle"].as_str().unwrap())).unwrap())
        .map_err(invalid)
}

fn target_runtime_id(target: &Value) -> Result<&str, Version2Error> {
    target
        .get("root")
        .and_then(|value| value["root_runtime_id"].as_str())
        .or_else(|| {
            target
                .get("component")
                .and_then(|value| value["component_runtime_id"].as_str())
        })
        .or_else(|| {
            target
                .get("spawned_instance")
                .and_then(|value| value["instance_id"].as_str())
        })
        .ok_or_else(|| Version2Error::new("invalid_instance_target", "target is malformed"))
}

fn assert_result(
    directory: &Path,
    vector: &Value,
    actual: Result<Value, Version2Error>,
) -> Result<(), String> {
    let expected = &vector["expect"];
    if expected["result"] == "failure" {
        let error = actual.expect_err("failure vector unexpectedly succeeded");
        return (error.code == expected["code"].as_str().unwrap())
            .then_some(())
            .ok_or_else(|| format!("failure {} != {}", error.code, expected["code"]));
    }
    let actual = actual.map_err(|error| error.to_string())?;
    let expected: Value = serde_json::from_slice(
        &fs::read(directory.join(vector["expect"]["exact_result_file"].as_str().unwrap())).unwrap(),
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
            format!("difference at {path}")
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
            format!("difference at {path}")
        }
        _ => format!("{path}: expected {expected}, got {actual}"),
    }
}

fn invalid(error: impl std::fmt::Display) -> Version2Error {
    Version2Error::new("invalid_aggregate_state", error.to_string())
}

fn parse_yaml(source: &str) -> Value {
    serde_json::to_value(serde_yaml::from_str::<serde_yaml::Value>(source).unwrap()).unwrap()
}

fn case_dir(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("conformance-suite/conformance/core")
        .join(name)
}
