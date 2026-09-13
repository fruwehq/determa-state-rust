use determa_state::{load_bundle, validate_artifact, ArtifactError, InMemoryDefinitionResolver};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn all_381_manifest_artifacts_receive_full_validation() {
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
            let validation = validate_artifact(
                kind,
                &bytes,
                &resolver,
                document["verify_digest"].as_bool().unwrap_or(true),
            )
            .map(|_| ());
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
    assert_eq!(count, 381, "artifact manifest entry count changed");
    assert!(
        failures.is_empty(),
        "{} artifact(s) failed validation:\n{}",
        failures.len(),
        failures.join("\n")
    );
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
