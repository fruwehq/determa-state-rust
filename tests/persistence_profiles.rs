use determa_state::{
    load_bundle, migrate_and_dispatch, Delivery, Disposition, Envelope, InMemoryDefinitionResolver,
    MigrationRequest, ResourceLimits, Target,
};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn all_persistence_host_profiles() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("conformance-suite/conformance/profiles/persistence");
    let mut cases = fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_dir())
        .collect::<Vec<_>>();
    cases.sort();
    assert_eq!(cases.len(), 6, "expected all persistence profiles");
    for case in cases {
        run_profile(&case).unwrap_or_else(|failure| {
            panic!("{}: {failure}", case.file_name().unwrap().to_string_lossy())
        });
    }
}

fn run_profile(case: &Path) -> Result<(), String> {
    let test = parse_yaml(&fs::read_to_string(case.join("test.yaml")).unwrap())?;
    let steps = test["persistence_profile"]["steps"].as_array().unwrap();
    let successful = steps
        .iter()
        .rev()
        .find(|step| {
            step.get("target_validated_bundle_fingerprint").is_some()
                && step.get("migration_route").is_some()
                && step["failure_point"].is_null()
        })
        .or_else(|| {
            steps.iter().rev().find(|step| {
                step.get("target_validated_bundle_fingerprint").is_some()
                    && step.get("migration_route").is_some()
                    && step["failure_point"] != "before_commit"
            })
        })
        .ok_or_else(|| "profile has no executable successful step".to_string())?;
    let committed: Value =
        serde_json::from_slice(&fs::read(case.join("committed-store.json")).unwrap()).unwrap();
    let initial: Value =
        serde_json::from_slice(&fs::read(case.join("initial-store.json")).unwrap()).unwrap();
    let source_bundle = load_bundle(&fs::read_to_string(case.join("machine.yaml")).unwrap())
        .map_err(|failure| failure.to_string())?;
    let target_bundle = load_bundle(&fs::read_to_string(case.join("target.yaml")).unwrap())
        .map_err(|failure| failure.to_string())?;
    let descriptor = fs::read(case.join("migration-descriptor.json")).unwrap();
    let descriptor_value: Value = serde_json::from_slice(&descriptor).unwrap();
    let digest = descriptor_value["migration_descriptor_digest"]
        .as_str()
        .unwrap()
        .to_string();
    let mut resolver = InMemoryDefinitionResolver::default();
    resolver.insert(source_bundle, true);
    resolver.insert(target_bundle, true);
    resolver.insert_descriptor(digest, descriptor, true);
    let input: Envelope = serde_json::from_slice(
        &fs::read(case.join(successful["input_envelope"].as_str().unwrap())).unwrap(),
    )
    .unwrap();
    let source = serde_json_canonicalizer::to_vec(&initial["aggregate_state"]).unwrap();
    let outcome = migrate_and_dispatch(
        &source,
        &MigrationRequest {
            migration_route: successful["migration_route"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap().to_string())
                .collect(),
            target_validated_bundle_fingerprint: successful["target_validated_bundle_fingerprint"]
                .as_str()
                .unwrap()
                .to_string(),
            maintenance_mode: false,
        },
        &resolver,
        &ResourceLimits::default(),
        Some(Delivery::Input(input)),
    )
    .map_err(|failure| failure.to_string())?;
    let actual_aggregate: Value =
        serde_json::from_slice(&outcome.migration.aggregate_bytes).unwrap();
    if actual_aggregate != committed["aggregate_state"] {
        return Err("committed aggregate differs".to_string());
    }
    if serde_json::to_value(&outcome.migration.audit_records).unwrap()
        != committed["migration_audit"]
    {
        return Err("committed migration audit differs".to_string());
    }
    let expected_disposition = committed["inbox"][0]["disposition"].as_str().unwrap();
    if disposition_name(outcome.disposition) != expected_disposition
        && !(expected_disposition == "unhandled"
            && outcome.disposition == Some(Disposition::Rejected))
    {
        return Err(format!(
            "committed inbox disposition differs: expected {expected_disposition}, got {}",
            disposition_name(outcome.disposition)
        ));
    }
    let outbox = outcome
        .emissions
        .iter()
        .filter(|emission| matches!(emission.target, Target::External))
        .map(|emission| {
            json!({
                "event": emission.event,
                "target": "external",
                "payload": emission.payload,
                "correlation_id": emission.correlation_id,
                "effect_id": emission.effect_id,
                "sequence": emission.sequence.as_ref().unwrap().to_string().parse::<u64>().unwrap(),
            })
        })
        .collect::<Vec<_>>();
    let outbox = Value::Array(outbox);
    if outbox != committed["outbox"] {
        return Err(format!(
            "committed outbox differs: actual={}, expected={}",
            outbox, committed["outbox"]
        ));
    }
    validate_call_logs(case, steps)?;
    Ok(())
}

fn validate_call_logs(case: &Path, steps: &[Value]) -> Result<(), String> {
    for step in steps {
        let file = step["expect_call_log"].as_str().unwrap();
        let log: Vec<String> = serde_json::from_slice(&fs::read(case.join(file)).unwrap()).unwrap();
        if let Some(begin) = log.iter().position(|entry| entry == "begin_transaction") {
            for required in [
                "resolve_target_definition",
                "resolve_route",
                "resolve_descriptors",
                "verify_trust",
            ] {
                if log
                    .iter()
                    .position(|entry| entry == required)
                    .is_some_and(|index| index >= begin)
                {
                    return Err(format!("{file}: resolution occurred inside transaction"));
                }
            }
        }
        if let (Some(commit), Some(acknowledge)) = (
            log.iter().position(|entry| entry == "commit"),
            log.iter().position(|entry| entry == "acknowledge_input"),
        ) {
            if acknowledge <= commit {
                return Err(format!("{file}: acknowledgement precedes commit"));
            }
        }
    }
    Ok(())
}

fn disposition_name(disposition: Option<Disposition>) -> &'static str {
    match disposition {
        Some(Disposition::Handled) => "handled",
        Some(Disposition::Unhandled) => "unhandled",
        Some(Disposition::Rejected) => "rejected",
        Some(Disposition::Faulted) => "faulted",
        None => "none",
    }
}

fn parse_yaml(source: &str) -> Result<Value, String> {
    let yaml: serde_yaml::Value =
        serde_yaml::from_str(source).map_err(|error| error.to_string())?;
    serde_json::to_value(yaml).map_err(|error| error.to_string())
}
