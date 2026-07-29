use determa_state::{
    create, dispatch, encode_aggregate, load_bundle, migrate_aggregate, migrate_and_dispatch,
    restore_aggregate, restore_package, restore_package_and_migrate, Bindings, DefinitionResolver,
    Delivery, Disposition, Envelope, InMemoryDefinitionResolver, MigrationRequest, ResourceLimits,
};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

fn persistence_cases() -> Vec<PathBuf> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("conformance-suite/conformance/core");
    let mut cases = fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| name.split('-').next())
                .and_then(|number| number.parse::<u32>().ok())
                .is_some_and(|number| (94..=115).contains(&number))
        })
        .collect::<Vec<_>>();
    cases.sort();
    cases
}

#[test]
fn all_portable_persistence_vectors() {
    let cases = persistence_cases();
    assert_eq!(cases.len(), 22, "expected persistence cases 94 through 115");
    let mut failures = Vec::new();
    for case in cases {
        let document = parse_yaml(&fs::read_to_string(case.join("test.yaml")).unwrap()).unwrap();
        for vector in document["persistence_vectors"].as_array().unwrap() {
            let name = vector["name"].as_str().unwrap_or("<unnamed>");
            if let Err(failure) = run_vector(&case, vector) {
                failures.push(format!(
                    "{}/{}: {failure}",
                    case.file_name().unwrap().to_string_lossy(),
                    name
                ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} persistence vector(s) failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

fn run_vector(case: &Path, vector: &Value) -> Result<(), String> {
    let mut resolver = build_resolver(case, vector)?;
    let limits = vector
        .get("resource_limits")
        .and_then(Value::as_str)
        .map(|file| {
            serde_json::from_slice::<ResourceLimits>(&fs::read(case.join(file)).unwrap())
                .map_err(|error| error.to_string())
        })
        .transpose()?
        .unwrap_or_default();
    let operation = vector["operation"]
        .as_str()
        .ok_or_else(|| "operation is absent".to_string())?;
    let migration_request = if matches!(
        operation,
        "restore_package_and_migrate" | "migrate_aggregate" | "migrate_and_dispatch"
    ) {
        match request_from_vector(vector) {
            Ok(request) => Some(request),
            Err(failure) => return assert_result(case, vector, Err(failure)),
        }
    } else {
        None
    };
    let result = match operation {
        "serialize_created_aggregate" => serialize_created(case, vector),
        "restore_and_serialize" => {
            let source = artifact(case, vector, "aggregate_state")?;
            restore_aggregate(&source, &resolver)
                .and_then(|state| {
                    let bundle = resolver
                        .resolve_definition(&state.validated_bundle_fingerprint)
                        .ok_or_else(|| {
                            determa_state::PersistenceError::new(
                                determa_state::PersistenceErrorCode::SourceDefinitionUnavailable,
                                "definition unavailable",
                            )
                        })?
                        .bundle;
                    encode_aggregate(&bundle, &state).map(|(_, bytes)| bytes)
                })
                .map(|bytes| Successful {
                    bytes,
                    audit: None,
                    disposition: None,
                    emissions: Some(json!([])),
                    resolver: None,
                })
        }
        "restore_and_dispatch" => restore_and_dispatch(case, vector, &resolver),
        "restore_package" => {
            let source = artifact(case, vector, "aggregate_state_package")?;
            restore_package(&source, &mut resolver).map(|restored| Successful {
                bytes: restored.aggregate_bytes,
                audit: None,
                disposition: None,
                emissions: Some(json!([])),
                resolver: Some(resolver_snapshot(case, &resolver).unwrap()),
            })
        }
        "restore_package_and_migrate" => {
            let source = artifact(case, vector, "aggregate_state_package")?;
            let request = migration_request.as_ref().unwrap();
            restore_package_and_migrate(
                &source,
                &mut resolver,
                request.target_validated_bundle_fingerprint.clone(),
                request.maintenance_mode,
                &limits,
            )
            .map(|outcome| Successful {
                bytes: outcome.aggregate_bytes,
                audit: Some(serde_json::to_value(outcome.audit_records).unwrap()),
                disposition: None,
                emissions: Some(json!([])),
                resolver: Some(resolver_snapshot(case, &resolver).unwrap()),
            })
        }
        "migrate_aggregate" => {
            let source = artifact(case, vector, "aggregate_state")?;
            let request = migration_request.as_ref().unwrap();
            migrate_aggregate(&source, request, &resolver, &limits).map(|outcome| Successful {
                bytes: outcome.aggregate_bytes,
                audit: Some(serde_json::to_value(outcome.audit_records).unwrap()),
                disposition: None,
                emissions: Some(json!([])),
                resolver: None,
            })
        }
        "migrate_and_dispatch" => {
            let source = artifact(case, vector, "aggregate_state")?;
            let request = migration_request.as_ref().unwrap();
            let envelope: Envelope =
                serde_json::from_slice(&artifact(case, vector, "input_envelope")?)
                    .map_err(|error| error.to_string())?;
            migrate_and_dispatch(
                &source,
                request,
                &resolver,
                &limits,
                Some(Delivery::Input(envelope)),
            )
            .map(|outcome| Successful {
                bytes: outcome.migration.aggregate_bytes,
                audit: Some(serde_json::to_value(outcome.migration.audit_records).unwrap()),
                disposition: outcome.disposition,
                emissions: Some(serde_json::to_value(outcome.emissions).unwrap()),
                resolver: None,
            })
        }
        _ => return Err(format!("unknown operation {operation}")),
    };
    assert_result(case, vector, result)
}

struct Successful {
    bytes: Vec<u8>,
    audit: Option<Value>,
    disposition: Option<Disposition>,
    emissions: Option<Value>,
    resolver: Option<Value>,
}

fn serialize_created(
    case: &Path,
    vector: &Value,
) -> Result<Successful, determa_state::PersistenceError> {
    let bundle = load_bundle(
        &fs::read_to_string(case.join(vector["source_bundle"].as_str().unwrap())).unwrap(),
    )
    .unwrap();
    let creation = &vector["creation"];
    let result = create(
        &bundle,
        creation["machine_id"].as_str().unwrap(),
        creation["root_instance_id"].as_str().unwrap(),
        creation["creation_id"].as_str().unwrap(),
        &Bindings::default(),
    );
    let state = result.state.expect("successful normative creation");
    encode_aggregate(&bundle, &state).map(|(_, bytes)| Successful {
        bytes,
        audit: None,
        disposition: None,
        emissions: Some(json!([])),
        resolver: None,
    })
}

fn restore_and_dispatch(
    case: &Path,
    vector: &Value,
    resolver: &InMemoryDefinitionResolver,
) -> Result<Successful, determa_state::PersistenceError> {
    let source = artifact(case, vector, "aggregate_state").unwrap();
    let state = restore_aggregate(&source, resolver)?;
    let bundle = resolver
        .resolve_definition(&state.validated_bundle_fingerprint)
        .unwrap()
        .bundle;
    let envelope: Envelope =
        serde_json::from_slice(&artifact(case, vector, "input_envelope").unwrap()).unwrap();
    let result = dispatch(&bundle, &state, Some(Delivery::Input(envelope)));
    let state = result.state.unwrap();
    let (_, bytes) = encode_aggregate(&bundle, &state)?;
    Ok(Successful {
        bytes,
        audit: None,
        disposition: result.disposition,
        emissions: Some(serde_json::to_value(result.emissions).unwrap()),
        resolver: None,
    })
}

fn assert_result(
    case: &Path,
    vector: &Value,
    result: Result<Successful, determa_state::PersistenceError>,
) -> Result<(), String> {
    let expected = &vector["expect"];
    if expected["result"] == "failure" {
        return match result {
            Err(failure) if failure.code.as_str() == expected["code"].as_str().unwrap() => Ok(()),
            Err(failure) => Err(format!(
                "expected {}, got {}",
                expected["code"].as_str().unwrap(),
                failure.code.as_str()
            )),
            Ok(success) => Err(format!(
                "expected {}, got success with {} bytes",
                expected["code"].as_str().unwrap(),
                success.bytes.len()
            )),
        };
    }
    let success = result.map_err(|failure| failure.to_string())?;
    if let Some(file) = expected.get("exact_bytes_file").and_then(Value::as_str) {
        let expected_bytes = fs::read(case.join(file)).unwrap();
        if success.bytes != expected_bytes {
            let actual: Value = serde_json::from_slice(&success.bytes).unwrap();
            let expected_value: Value = serde_json::from_slice(&expected_bytes).unwrap();
            return Err(format!(
                "exact bytes differ from {file}; semantic_equal={}, actual_runtime_order={:?}, expected_runtime_order={:?}",
                actual == expected_value,
                actual["runtimes"].as_array().unwrap().iter().map(|v| v["runtime_id"].as_str().unwrap()).collect::<Vec<_>>(),
                expected_value["runtimes"].as_array().unwrap().iter().map(|v| v["runtime_id"].as_str().unwrap()).collect::<Vec<_>>()
            ));
        }
    }
    if let Some(file) = expected.get("aggregate_state_file").and_then(Value::as_str) {
        let actual: Value = serde_json::from_slice(&success.bytes).unwrap();
        let expected_value: Value =
            serde_json::from_slice(&fs::read(case.join(file)).unwrap()).unwrap();
        if actual != expected_value {
            return Err(format!("aggregate value differs from {file}"));
        }
    }
    if let Some(disposition) = expected.get("disposition").and_then(Value::as_str) {
        let actual = match success.disposition {
            Some(Disposition::Handled) => "handled",
            Some(Disposition::Unhandled) => "unhandled",
            Some(Disposition::Rejected) => "rejected",
            Some(Disposition::Faulted) => "faulted",
            None => "<none>",
        };
        if actual != disposition {
            return Err(format!("expected disposition {disposition}, got {actual}"));
        }
    }
    compare_file(case, expected, "migration_audit_file", success.audit)?;
    compare_file(case, expected, "emissions_file", success.emissions)?;
    compare_file(case, expected, "artifact_resolver_file", success.resolver)?;
    Ok(())
}

fn compare_file(
    case: &Path,
    expected: &Value,
    member: &str,
    actual: Option<Value>,
) -> Result<(), String> {
    let Some(file) = expected.get(member).and_then(Value::as_str) else {
        return Ok(());
    };
    let expected_value: Value =
        serde_json::from_slice(&fs::read(case.join(file)).unwrap()).unwrap();
    if actual != Some(expected_value) {
        return Err(format!("{member} differs from {file}"));
    }
    Ok(())
}

fn build_resolver(case: &Path, vector: &Value) -> Result<InMemoryDefinitionResolver, String> {
    let mut resolver = InMemoryDefinitionResolver::default();
    if let Some(file) = vector.get("artifact_resolver").and_then(Value::as_str) {
        let fixture: Value = serde_json::from_slice(&fs::read(case.join(file)).unwrap()).unwrap();
        for record in fixture["definitions"].as_array().unwrap() {
            let bundle = load_bundle(
                &fs::read_to_string(case.join(record["bundle_file"].as_str().unwrap())).unwrap(),
            )
            .map_err(|error| error.to_string())?;
            resolver.insert_at(
                record["validated_bundle_fingerprint"].as_str().unwrap(),
                bundle,
                record["trusted"].as_bool().unwrap(),
            );
        }
        for record in fixture["migration_descriptors"].as_array().unwrap() {
            resolver.insert_descriptor(
                record["migration_descriptor_digest"].as_str().unwrap(),
                fs::read(case.join(record["descriptor_file"].as_str().unwrap())).unwrap(),
                record["trusted"].as_bool().unwrap(),
            );
        }
    }
    for file in vector
        .get("definitions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let bundle = load_bundle(&fs::read_to_string(case.join(file.as_str().unwrap())).unwrap())
            .map_err(|error| error.to_string())?;
        resolver.insert(bundle, true);
    }
    for file in vector
        .get("migration_descriptors")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let bytes = fs::read(case.join(file.as_str().unwrap())).unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        resolver.insert_descriptor(
            value["migration_descriptor_digest"].as_str().unwrap(),
            bytes,
            true,
        );
    }
    Ok(resolver)
}

fn request_from_vector(
    vector: &Value,
) -> Result<MigrationRequest, determa_state::PersistenceError> {
    if let Some(request) = vector.get("migration_request") {
        return MigrationRequest::from_json(request);
    }
    Ok(MigrationRequest {
        migration_route: vector["migration_route"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_string())
            .collect(),
        target_validated_bundle_fingerprint: vector["target_validated_bundle_fingerprint"]
            .as_str()
            .unwrap()
            .to_string(),
        maintenance_mode: vector["maintenance_mode"].as_bool().ok_or_else(|| {
            determa_state::PersistenceError::new(
                determa_state::PersistenceErrorCode::InvalidMigrationRequest,
                "maintenance mode is not Boolean",
            )
        })?,
    })
}

fn artifact(case: &Path, vector: &Value, member: &str) -> Result<Vec<u8>, String> {
    let file = vector[member]
        .as_str()
        .ok_or_else(|| format!("{member} is absent"))?;
    fs::read(case.join(file)).map_err(|error| error.to_string())
}

fn resolver_snapshot(case: &Path, resolver: &InMemoryDefinitionResolver) -> Result<Value, String> {
    let files = fs::read_dir(case)
        .map_err(|error| error.to_string())?
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    let mut definitions = Vec::new();
    for (fingerprint, definition) in resolver.definitions() {
        let bundle_file = files
            .iter()
            .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("yaml"))
            .find_map(|path| {
                load_bundle(&fs::read_to_string(path).ok()?)
                    .ok()
                    .filter(|bundle| bundle.normalized == definition.bundle.normalized)
                    .and_then(|_| path.file_name()?.to_str().map(str::to_string))
            })
            .ok_or_else(|| format!("cannot identify bundle file for {fingerprint}"))?;
        definitions.push(json!({
            "validated_bundle_fingerprint": fingerprint,
            "bundle_file": bundle_file,
            "trusted": definition.trusted,
        }));
    }
    let mut descriptors = Vec::new();
    for (digest, descriptor) in resolver.descriptors() {
        let descriptor_value = serde_json::from_slice::<Value>(&descriptor.bytes).ok();
        let descriptor_file = files
            .iter()
            .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("json"))
            .find_map(|path| {
                let value: Value = serde_json::from_slice(&fs::read(path).ok()?).ok()?;
                (Some(&value) == descriptor_value.as_ref())
                    .then(|| path.file_name()?.to_str().map(str::to_string))
                    .flatten()
            })
            .ok_or_else(|| format!("cannot identify descriptor file for {digest}"))?;
        descriptors.push(json!({
            "migration_descriptor_digest": digest,
            "descriptor_file": descriptor_file,
            "trusted": descriptor.trusted,
        }));
    }
    Ok(json!({
        "definitions": definitions,
        "migration_descriptors": descriptors,
    }))
}

fn parse_yaml(source: &str) -> Result<Value, String> {
    let yaml: serde_yaml::Value =
        serde_yaml::from_str(source).map_err(|error| error.to_string())?;
    serde_json::to_value(yaml).map_err(|error| error.to_string())
}
