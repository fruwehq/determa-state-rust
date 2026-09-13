use determa_state::{
    checkpoint, load_bundle, restore_aggregate, restore_package, validate_migration_descriptor,
    InMemoryDefinitionResolver,
};
use jsonschema::{Resource, Validator};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn all_381_manifest_artifacts_receive_full_validation() {
    let suite = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("conformance-suite/conformance");
    let schemas = schemas();
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
        let semantic_rejections = semantic_rejections(&manifest, documents);
        for document in documents {
            count += 1;
            let kind = document["kind"].as_str().unwrap();
            let path = directory.join(document["file"].as_str().unwrap());
            let bytes = fs::read(&path).unwrap();
            let expected_valid = document["valid"].as_bool().unwrap();
            let value = serde_json::from_slice::<Value>(&bytes);
            let validation = value.map_err(|error| error.to_string()).and_then(|value| {
                schemas[kind]
                    .validate(&value)
                    .map_err(|error| error.to_string())?;
                match validate_semantics(kind, &value, &bytes, &resolver) {
                    Ok(()) => Ok(()),
                    Err(error)
                        if expected_valid
                            && semantic_rejections
                                .get(document["file"].as_str().unwrap())
                                .is_some_and(|codes| {
                                    codes
                                        .iter()
                                        .any(|code| error.starts_with(&format!("{code}:")))
                                }) =>
                    {
                        Ok(())
                    }
                    Err(error) => Err(error),
                }
            });
            if validation.is_ok() != expected_valid {
                failures.push(format!(
                    "{} ({kind}) expected valid={expected_valid}: {}",
                    path.strip_prefix(&suite).unwrap().display(),
                    validation
                        .err()
                        .unwrap_or_else(|| "unexpected success".to_string())
                ));
            }
        }
    }
    assert_eq!(count, 381, "artifact manifest entry count changed");
    assert!(
        failures.is_empty(),
        "{} artifact(s) failed validation:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

fn semantic_rejections(
    manifest: &Value,
    documents: &[Value],
) -> BTreeMap<String, BTreeSet<String>> {
    let artifact_files = documents
        .iter()
        .filter_map(|document| document["file"].as_str())
        .collect::<BTreeSet<_>>();
    let mut rejection_codes = BTreeMap::<String, BTreeSet<String>>::new();
    for vector in manifest["version2_vectors"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|vector| vector["expect"]["result"] == "failure")
    {
        let Some(code) = vector["expect"]["code"].as_str() else {
            continue;
        };
        for file in vector
            .as_object()
            .into_iter()
            .flat_map(|members| members.values())
            .filter_map(Value::as_str)
            .filter(|file| artifact_files.contains(file))
        {
            rejection_codes
                .entry(file.to_string())
                .or_default()
                .insert(code.to_string());
        }
    }
    rejection_codes
}

fn validate_semantics(
    kind: &str,
    value: &Value,
    bytes: &[u8],
    resolver: &InMemoryDefinitionResolver,
) -> Result<(), String> {
    match kind {
        "aggregate_state_v2" => restore_aggregate(bytes, resolver)
            .map(|_| ())
            .map_err(|error| error.to_string()),
        "aggregate_state_package_v2" => {
            let mut resolver = resolver.clone();
            restore_package(bytes, &mut resolver)
                .map(|_| ())
                .map_err(|error| error.to_string())
        }
        "migration_descriptor_v2" => validate_migration_descriptor(bytes)
            .map(|_| ())
            .map_err(|error| error.to_string()),
        "execution_checkpoint_v2" => checkpoint::restore(bytes, resolver)
            .map(|_| ())
            .map_err(|error| error.to_string()),
        "durable_host_store_v2" => {
            let checkpoint = serde_json_canonicalizer::to_vec(&value["checkpoint"])
                .map_err(|error| error.to_string())?;
            checkpoint::restore(&checkpoint, resolver)
                .map(|_| ())
                .map_err(|error| error.to_string())
        }
        "core_step_result_v2"
        | "durable_host_call_log_v2"
        | "durable_host_inputs_v2"
        | "durable_host_results_v2"
        | "version2_operation_inputs"
        | "version2_operation_result" => Ok(()),
        other => Err(format!("unrouted artifact kind {other}")),
    }
}

fn schemas() -> BTreeMap<String, Validator> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let sources = [
        (
            "aggregate_state_v2",
            root.join("schema/aggregate-state-v2.schema.json"),
        ),
        (
            "aggregate_state_package_v2",
            root.join("schema/aggregate-state-package-v2.schema.json"),
        ),
        (
            "migration_descriptor_v2",
            root.join("schema/migration-descriptor-v2.schema.json"),
        ),
        (
            "core_step_result_v2",
            root.join("schema/core-step-result-v2.schema.json"),
        ),
        (
            "execution_checkpoint_v2",
            root.join("schema/execution-checkpoint-v2.schema.json"),
        ),
        (
            "durable_host_call_log_v2",
            root.join("conformance-suite/scripts/schemas/durable-host-call-log-v2.schema.json"),
        ),
        (
            "durable_host_inputs_v2",
            root.join("conformance-suite/scripts/schemas/durable-host-inputs-v2.schema.json"),
        ),
        (
            "durable_host_results_v2",
            root.join("conformance-suite/scripts/schemas/durable-host-results-v2.schema.json"),
        ),
        (
            "durable_host_store_v2",
            root.join("conformance-suite/scripts/schemas/durable-host-store-v2.schema.json"),
        ),
        (
            "version2_operation_inputs",
            root.join("conformance-suite/scripts/schemas/version2-operation-inputs.schema.json"),
        ),
        (
            "version2_operation_result",
            root.join("conformance-suite/scripts/schemas/version2-operation-result.schema.json"),
        ),
    ];
    let values = sources
        .iter()
        .map(|(kind, path)| {
            (
                *kind,
                serde_json::from_slice::<Value>(&fs::read(path).unwrap()).unwrap(),
            )
        })
        .collect::<Vec<_>>();
    values
        .iter()
        .map(|(kind, schema)| {
            let own_id = schema["$id"].as_str();
            let mut options = jsonschema::options();
            for (_, resource) in &values {
                let Some(id) = resource["$id"].as_str() else {
                    continue;
                };
                if Some(id) != own_id {
                    options = options.with_resource(
                        id.to_string(),
                        Resource::from_contents(resource.clone()).unwrap(),
                    );
                }
            }
            ((*kind).to_string(), options.build(schema).unwrap())
        })
        .collect()
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
