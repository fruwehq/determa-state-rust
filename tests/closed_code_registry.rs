use determa_state::checkpoint::{
    AdapterErrorCode, CheckpointErrorCode, HostFailureCode, PreAcceptanceFailureCode,
    StoreErrorCode,
};
use determa_state::{
    Disposition, LoadErrorCode, PersistenceErrorCode, CREATION_REJECTION_CODES,
    DISPATCH_REJECTION_CODES, ENGINE_FAULT_CODES,
};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Deserialize)]
struct RegistryVectors {
    categories: Vec<RegistryCategory>,
}

#[derive(Deserialize)]
struct RegistryCategory {
    id: String,
    codes: Vec<String>,
}

fn projected<T>(values: &[T], as_str: impl Fn(&T) -> &'static str) -> BTreeSet<String> {
    values
        .iter()
        .map(|value| as_str(value).to_string())
        .collect()
}

fn strings(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}

#[test]
fn production_exports_match_the_authoritative_registry_exactly() {
    let vectors: RegistryVectors = serde_json::from_str(include_str!(
        "../conformance-suite/conformance/closed-code-registry/vectors.generated.json"
    ))
    .expect("generated closed-code registry vectors parse");
    let expected = vectors
        .categories
        .into_iter()
        .map(|category| (category.id, category.codes.into_iter().collect()))
        .collect::<BTreeMap<String, BTreeSet<String>>>();

    let actual = BTreeMap::from([
        (
            "checkpoint_artifact_failure",
            projected(CheckpointErrorCode::PORTABLE_CODES, |code| code.as_str()),
        ),
        (
            "checkpoint_host_failure",
            projected(HostFailureCode::PORTABLE_CODES, |code| code.as_str()),
        ),
        (
            "checkpoint_pre_acceptance_failure",
            projected(PreAcceptanceFailureCode::PORTABLE_CODES, |code| {
                code.as_str()
            }),
        ),
        ("creation_rejection", strings(CREATION_REJECTION_CODES)),
        ("dispatch_rejection", strings(DISPATCH_REJECTION_CODES)),
        (
            "disposition",
            projected(Disposition::PORTABLE_CODES, |code| code.as_str()),
        ),
        ("engine_fault", strings(ENGINE_FAULT_CODES)),
        (
            "execution_store_adapter_failure",
            projected(AdapterErrorCode::PORTABLE_CODES, |code| code.as_str()),
        ),
        (
            "execution_store_failure",
            projected(StoreErrorCode::PORTABLE_CODES, |code| code.as_str()),
        ),
        (
            "machine_load_failure",
            projected(LoadErrorCode::PORTABLE_CODES, LoadErrorCode::as_str),
        ),
        (
            "persistence_failure",
            projected(PersistenceErrorCode::PORTABLE_CODES, |code| code.as_str()),
        ),
    ]);

    let categories = expected
        .keys()
        .map(String::as_str)
        .chain(actual.keys().copied())
        .collect::<BTreeSet<_>>();
    for category in categories {
        let expected_codes = expected.get(category).cloned().unwrap_or_default();
        let actual_codes = actual.get(category).cloned().unwrap_or_default();
        let missing = expected_codes
            .difference(&actual_codes)
            .cloned()
            .collect::<Vec<_>>();
        let extra = actual_codes
            .difference(&expected_codes)
            .cloned()
            .collect::<Vec<_>>();
        assert!(
            missing.is_empty() && extra.is_empty(),
            "portable code mismatch for {category}: missing={missing:?}, extra={extra:?}"
        );
    }
}

#[test]
fn implementation_and_harness_codes_remain_outside_portable_exports() {
    assert_eq!(
        StoreErrorCode::ExecutionStoreFailure.as_str(),
        "execution_store_failure"
    );
    assert!(!StoreErrorCode::PORTABLE_CODES.contains(&StoreErrorCode::ExecutionStoreFailure));

    assert_eq!(
        LoadErrorCode::StructuralValidation.as_str(),
        "structural_validation"
    );
    assert!(!LoadErrorCode::PORTABLE_CODES.contains(&LoadErrorCode::StructuralValidation));
}
