//! Repository-only exact §12 operation vectors. The crate package excludes this driver.

use determa_state::{
    inspect_candidate, load_bundle, restore_aggregate, InMemoryDefinitionResolver,
    InspectionCapabilities,
};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

fn directory() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("conformance-suite/conformance/core/125-exact-candidate-inspection")
}

fn document(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn pointer<'a>(value: &'a Value, pointer: &str) -> &'a Value {
    value.pointer(pointer).unwrap()
}

fn check_vector(
    directory: &Path,
    vector: &Value,
    transform: impl FnOnce(Value) -> Value,
) -> Result<(), String> {
    let filename = |key: &str| directory.join(vector[key].as_str().unwrap());
    let bundle = load_bundle(&fs::read_to_string(filename("bundle")).unwrap()).unwrap();
    let mut resolver = InMemoryDefinitionResolver::default();
    resolver.insert(bundle, true);
    let before = fs::read(filename("aggregate_before")).unwrap();
    let expected_after = fs::read(filename("aggregate_after")).unwrap();
    let aggregate = restore_aggregate(&before, &resolver).unwrap();
    let snapshot = aggregate.canonical_bytes().unwrap();
    let requests = document(&filename("request_file"));
    let request = pointer(&requests, vector["request_pointer"].as_str().unwrap());
    let request_snapshot = request.clone();
    let expected = document(&filename("outcome_file"));
    let expected = pointer(&expected, vector["outcome_pointer"].as_str().unwrap());
    #[cfg(determa_repository_conformance)]
    let guard_count_before = determa_state::observed_inspection_guards();
    let result = inspect_candidate(
        &aggregate,
        request,
        &resolver,
        InspectionCapabilities {
            safe_semantic_cel: vector["profile"] != "without_safe_semantic",
        },
    )
    .map_err(|error| error.to_string())?;
    #[cfg(determa_repository_conformance)]
    if determa_state::observed_inspection_guards() - guard_count_before
        != vector["expect"]["guard_evaluations"].as_u64().unwrap() as usize
    {
        return Err(format!(
            "{} actual guard call count differs",
            vector["name"]
        ));
    }
    let result = transform(result);
    if result != *expected {
        return Err(format!(
            "{}: actual {result}, expected {expected}",
            vector["name"]
        ));
    }
    if request != &request_snapshot
        || aggregate.canonical_bytes().unwrap() != snapshot
        || before != expected_after
    {
        return Err(format!("{} mutated inspection input", vector["name"]));
    }
    if vector["expect"]["action_invocations"] != 0
        || vector["expect"]["external_calls"] != 0
        || vector["expect"]["emissions"] != 0
    {
        return Err(format!("{} has unsupported effects", vector["name"]));
    }
    Ok(())
}

#[test]
fn all_49_exact_candidate_vectors_call_the_public_operation() {
    let directory = directory();
    let manifest: Value =
        serde_yaml::from_str(&fs::read_to_string(directory.join("test.yaml")).unwrap()).unwrap();
    let vectors = manifest["inspection_vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 49);
    let mut failures = Vec::new();
    for vector in vectors {
        if let Err(error) = check_vector(&directory, vector, |result| result) {
            failures.push(error);
        }
    }
    assert!(
        failures.is_empty(),
        "{} inspection failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn gate_rejects_a_sabotaged_production_outcome() {
    let directory = directory();
    let manifest: Value =
        serde_yaml::from_str(&fs::read_to_string(directory.join("test.yaml")).unwrap()).unwrap();
    let vector = &manifest["inspection_vectors"][0];
    assert!(check_vector(&directory, vector, |_| serde_json::json!({
        "code":"invalid_inspection_request","source_locator":null
    }))
    .is_err());
}
