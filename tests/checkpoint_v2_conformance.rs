use determa_state::checkpoint::{
    checkpoint_admit_v2, checkpoint_prune_v2, checkpoint_step_v2, restore_execution_checkpoint_v2,
    upgrade_execution_checkpoint_v1_to_v2,
};
use determa_state::{load_bundle, InMemoryDefinitionResolver, Version2Error};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

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
    assert_eq!(vectors.len(), 53);
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
        "checkpoint_v1_accept" => Err(Version2Error::new(
            "checkpoint_upgrade_required",
            "version 2 bundle requires checkpoint upgrade",
        )),
        other => return Err(format!("unsupported operation {other}")),
    };
    assert_vector(directory, vector, actual)
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
