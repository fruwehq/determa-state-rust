use determa_state::{load_bundle, validate_artifact, ArtifactError, InMemoryDefinitionResolver};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn all_420_manifest_artifacts_receive_applicable_validation() {
    // Artifact validity is intentionally narrower than operation admissibility.
    // Valid operands that a later operation must reject are exercised by the 162
    // operation vectors through the corresponding public operation.
    let suite = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("conformance-suite/conformance");
    let resolver = definition_resolver(&suite);
    let mut manifests = find_named(&suite, "test.yaml");
    manifests.sort();
    let mut count = 0;
    let mut failures = Vec::new();
    for manifest_path in manifests {
        let directory = manifest_path.parent().unwrap();
        let manifest = yaml(&fs::read_to_string(&manifest_path).unwrap());
        let Some(documents) = manifest["artifacts"]["documents"].as_array() else {
            continue;
        };
        for document in documents {
            count += 1;
            let kind = document["kind"].as_str().unwrap();
            let path = directory.join(document["file"].as_str().unwrap());
            let bytes = fs::read(&path).unwrap();
            let expected_valid = document["valid"].as_bool().unwrap();
            let native_inspection_fixture = directory
                .to_string_lossy()
                .contains("profiles/inspection-provider/provider-01-exact-closure")
                && kind == "aggregate_state_v1";
            let validation = if native_inspection_fixture {
                // The seven native provider vectors are conditional until a
                // configured, verified runtime provider is implemented. These
                // two portable snapshots still receive schema and seal checks.
                validate_conditional_inspection_snapshot(&bytes)
            } else {
                validate_artifact(
                    kind,
                    &bytes,
                    &resolver,
                    document["verify_digest"].as_bool().unwrap_or(true),
                )
                .map(|_| ())
            };
            let failure = if expected_valid {
                validation.err()
            } else {
                match validation {
                    Ok(()) => Some(ArtifactError::new(
                        "unexpected_success",
                        "invalid artifact was accepted",
                    )),
                    Err(error) if Some(error.code.as_str()) == document["error"].as_str() => None,
                    Err(error) => Some(error),
                }
            };
            if let Some(error) = failure {
                failures.push(format!(
                    "{} ({kind}) expected valid={expected_valid}, expected code={}: {error}",
                    path.strip_prefix(&suite).unwrap().display(),
                    document["error"].as_str().unwrap_or("none")
                ));
            }
        }
    }
    assert_eq!(count, 420, "artifact manifest entry count changed");
    assert!(
        failures.is_empty(),
        "{} artifact(s) failed validation:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

fn validate_conditional_inspection_snapshot(bytes: &[u8]) -> Result<(), ArtifactError> {
    let value = validate_artifact(
        "json_value",
        bytes,
        &InMemoryDefinitionResolver::default(),
        true,
    )?;
    let schema: Value =
        serde_json::from_str(include_str!("../schema/aggregate-state-v1.schema.json"))
            .expect("bundled aggregate schema parses");
    let validator = jsonschema::validator_for(&schema).expect("bundled aggregate schema compiles");
    validator
        .validate(&value)
        .map_err(|error| ArtifactError::new("invalid_aggregate_state", error.to_string()))?;
    let mut unsigned = value.clone();
    let actual = unsigned["aggregate_state_digest"]
        .as_str()
        .ok_or_else(|| ArtifactError::new("invalid_aggregate_state", "digest is absent"))?
        .to_string();
    unsigned
        .as_object_mut()
        .expect("schema-valid aggregate")
        .remove("aggregate_state_digest");
    let material =
        serde_json_canonicalizer::to_vec(&json!(["determa-aggregate-state-digest-1", unsigned]))
            .map_err(|error| ArtifactError::new("invalid_aggregate_state", error.to_string()))?;
    let expected = format!("sha256:{:x}", Sha256::digest(material));
    if actual != expected {
        return Err(ArtifactError::new(
            "aggregate_state_digest_mismatch",
            "seal differs",
        ));
    }
    Ok(())
}

#[test]
fn resealed_aggregate_with_unavailable_definition_is_rejected() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
        "conformance-suite/conformance/core/117-version1-mailboxes/spawn-isolation-aggregate.json",
    );
    let mut aggregate: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    replace_fingerprints(
        &mut aggregate,
        "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    );
    let mut unsigned = aggregate.clone();
    unsigned
        .as_object_mut()
        .unwrap()
        .remove("aggregate_state_digest");
    let bytes =
        serde_json_canonicalizer::to_vec(&json!(["determa-aggregate-state-digest-1", unsigned]))
            .unwrap();
    aggregate["aggregate_state_digest"] = json!(format!("sha256:{:x}", Sha256::digest(bytes)));
    let source = serde_json_canonicalizer::to_vec(&aggregate).unwrap();

    let error = validate_artifact(
        "aggregate_state_v1",
        &source,
        &InMemoryDefinitionResolver::default(),
        true,
    )
    .unwrap_err();
    assert_eq!(error.code, "source_definition_unavailable", "{error:?}");
}

#[test]
fn resealed_checkpoint_with_unavailable_definition_is_rejected() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
        "conformance-suite/conformance/profiles/execution-checkpoint/checkpoint-07-complete-host-contract/created-checkpoint-v1.json",
    );
    let mut checkpoint: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    assert_eq!(
        checkpoint["operation_receipts"][0]["request_digest"],
        creation_request_digest(&checkpoint)
    );
    replace_fingerprints(
        &mut checkpoint,
        "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    );
    let aggregate = &mut checkpoint["root_record"]["aggregate_state"];
    seal_digest(
        aggregate,
        "aggregate_state_digest",
        "determa-aggregate-state-digest-1",
    );
    checkpoint["operation_receipts"][0]["resulting_aggregate_state_digest"] =
        aggregate["aggregate_state_digest"].clone();
    checkpoint["operation_receipts"][0]["request_digest"] = creation_request_digest(&checkpoint);
    seal_digest(
        &mut checkpoint,
        "execution_checkpoint_digest",
        "determa-execution-checkpoint-digest-1",
    );
    let source = serde_json_canonicalizer::to_vec(&checkpoint).unwrap();
    let error = determa_state::checkpoint::restore(&source, &InMemoryDefinitionResolver::default())
        .unwrap_err();
    assert_eq!(error.code, "invalid_execution_checkpoint", "{error:?}");
    assert!(error.message.contains("required definition is unavailable"));
}

fn creation_request_digest(checkpoint: &Value) -> Value {
    let aggregate = &checkpoint["root_record"]["aggregate_state"];
    let material = json!([
        "determa-creation-request-digest-1",
        "1",
        aggregate["validated_bundle_fingerprint"],
        aggregate["namespace"],
        aggregate["root_machine_id"],
        aggregate["root_machine_version"],
        aggregate["root_instance_id"],
        aggregate["creation_id"],
        ["map", [["external", ["map", []]], ["input", ["map", []]]]]
    ]);
    let bytes = serde_json_canonicalizer::to_vec(&material).unwrap();
    json!(format!("sha256:{:x}", Sha256::digest(bytes)))
}

#[test]
fn resealed_thin_package_with_unavailable_definition_is_rejected() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
        "conformance-suite/conformance/core/120-native-v1-definition-package/package-valid-package-v1.json",
    );
    let mut package: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    package["normalized_definitions"] = json!([]);
    replace_fingerprints(
        &mut package["aggregate_state"],
        "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    );
    seal_digest(
        &mut package["aggregate_state"],
        "aggregate_state_digest",
        "determa-aggregate-state-digest-1",
    );
    let source = serde_json_canonicalizer::to_vec(&package).unwrap();
    let error = determa_state::restore_package(&source, &mut InMemoryDefinitionResolver::default())
        .unwrap_err();
    assert_eq!(error.code, "source_definition_unavailable");
}

fn seal_digest(value: &mut Value, field: &str, domain: &str) {
    let mut unsigned = value.clone();
    unsigned.as_object_mut().unwrap().remove(field);
    let bytes = serde_json_canonicalizer::to_vec(&json!([domain, unsigned])).unwrap();
    value[field] = json!(format!("sha256:{:x}", Sha256::digest(bytes)));
}

fn replace_fingerprints(value: &mut Value, replacement: &str) {
    match value {
        Value::Object(object) => {
            if object.contains_key("validated_bundle_fingerprint") {
                object.insert(
                    "validated_bundle_fingerprint".to_string(),
                    Value::String(replacement.to_string()),
                );
            }
            for child in object.values_mut() {
                replace_fingerprints(child, replacement);
            }
        }
        Value::Array(items) => {
            for item in items {
                replace_fingerprints(item, replacement);
            }
        }
        _ => {}
    }
}

fn definition_resolver(root: &Path) -> InMemoryDefinitionResolver {
    let mut resolver = InMemoryDefinitionResolver::default();
    for path in find_extension(root, "yaml") {
        if let Ok(bundle) = load_bundle(&fs::read_to_string(path).unwrap()) {
            resolver.insert(bundle, true);
        }
    }
    resolver
}

fn find_named(root: &Path, name: &str) -> Vec<PathBuf> {
    walk(root, &|path| {
        path.file_name().and_then(|value| value.to_str()) == Some(name)
    })
}

fn find_extension(root: &Path, extension: &str) -> Vec<PathBuf> {
    walk(root, &|path| {
        path.extension().and_then(|value| value.to_str()) == Some(extension)
    })
}

fn walk(root: &Path, predicate: &dyn Fn(&Path) -> bool) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            paths.extend(walk(&path, predicate));
        } else if predicate(&path) {
            paths.push(path);
        }
    }
    paths
}

fn yaml(source: &str) -> Value {
    serde_json::to_value(serde_yaml::from_str::<serde_yaml::Value>(source).unwrap()).unwrap()
}
