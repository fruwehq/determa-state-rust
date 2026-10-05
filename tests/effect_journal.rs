//! Resolver-backed content pairing; this does not activate native participants.
use determa_state::checkpoint::{restore, ExecutionCheckpoint};
use determa_state::format1::effect_journal::ValidatedEffectJournal;
use determa_state::{load_bundle, InMemoryDefinitionResolver};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::PathBuf;

fn directory() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("conformance-suite/conformance/profiles/committed-native-effects/effect-01-result")
}
fn read(name: &str) -> Value {
    serde_json::from_slice(&std::fs::read(directory().join(name)).unwrap()).unwrap()
}
fn hash(value: &Value) -> String {
    use sha2::{Digest, Sha256};
    format!(
        "sha256:{:x}",
        Sha256::digest(serde_json_canonicalizer::to_vec(value).unwrap())
    )
}
fn seal(journal: &mut Value) {
    journal
        .as_object_mut()
        .unwrap()
        .remove("host_effect_journal_digest");
    journal["host_effect_journal_digest"] = json!(hash(&json!([
        "determa-host-effect-journal-digest-1",
        journal
    ])));
}
fn fixture(
    checkpoint: &str,
) -> (
    ExecutionCheckpoint,
    InMemoryDefinitionResolver,
    BTreeMap<String, Value>,
) {
    let mut resolver = InMemoryDefinitionResolver::default();
    resolver.insert(
        load_bundle(&std::fs::read_to_string(directory().join("machine.yaml")).unwrap()).unwrap(),
        true,
    );
    let checkpoint = restore(&serde_json::to_vec(&read(checkpoint)).unwrap(), &resolver).unwrap();
    let responses = BTreeMap::from([("produce-1".into(), read("data/producer-response.json"))]);
    (checkpoint, resolver, responses)
}
fn valid(
    journal: &Value,
    checkpoint: &ExecutionCheckpoint,
    resolver: &InMemoryDefinitionResolver,
    responses: &BTreeMap<String, Value>,
) -> bool {
    ValidatedEffectJournal::restore(
        &serde_json::to_vec(journal).unwrap(),
        checkpoint,
        "effect-scope-1",
        responses,
        resolver,
    )
    .is_ok()
}

#[test]
fn real_retained_journals_pair_with_exact_checkpoints() {
    for (checkpoint, journal) in [
        ("pending-checkpoint.json", "unclaimed-journal.json"),
        ("pending-checkpoint.json", "leased-journal.json"),
        ("pending-checkpoint.json", "retryable-journal.json"),
        ("pending-checkpoint.json", "ambiguous-journal.json"),
        ("pending-checkpoint.json", "outcome-recorded-journal.json"),
        ("admitted-checkpoint.json", "result-admitted-journal.json"),
        ("confirmed-checkpoint.json", "confirmed-journal.json"),
    ] {
        let (checkpoint, resolver, responses) = fixture(checkpoint);
        let journal = read(&format!("data/{journal}"));
        let restored = ValidatedEffectJournal::restore(
            &serde_json::to_vec(&journal).unwrap(),
            &checkpoint,
            "effect-scope-1",
            &responses,
            &resolver,
        )
        .unwrap();
        assert_eq!(restored.value(), &journal);
        assert_eq!(restored.retained_responses(), &responses);
    }
}

#[test]
fn resealed_missing_retry_evidence_and_multiple_terminal_attempts_refuse() {
    let (checkpoint, resolver, responses) = fixture("pending-checkpoint.json");
    let mut missing = read("data/leased-journal.json");
    missing["effect_records"][0]["invocation_state"] = json!("unclaimed");
    seal(&mut missing);
    assert!(!valid(&missing, &checkpoint, &resolver, &responses));

    for terminal in [
        "succeeded",
        "domain_rejected",
        "terminal_failure",
        "cancelled",
    ] {
        let mut journal = read("data/outcome-recorded-journal.json");
        let record = &mut journal["effect_records"][0];
        record["attempt_records"][0]["report_kind"] = json!(terminal);
        let mut next = record["attempt_records"][0].clone();
        next["attempt_fence"] = json!("2");
        next["report_kind"] = record["outcome"]["kind"].clone();
        next["report_digest"] = json!(hash(&json!([
            "determa-effect-attempt-report-1",
            record["effect_id"],
            record["operation_token"],
            "2",
            record["outcome"]["kind"],
            record["outcome"]["payload"],
            next["reason"]
        ])));
        record["attempt_records"].as_array_mut().unwrap().push(next);
        record["attempt_fence"] = json!("2");
        record["outcome"]["attempt_fence"] = json!("2");
        record["outcome"]["digest"] = json!(hash(&json!([
            "determa-effect-outcome-1",
            record["effect_id"],
            record["operation_token"],
            record["outcome"]["kind"],
            record["outcome"]["payload"],
            "2"
        ])));
        seal(&mut journal);
        assert!(
            !valid(&journal, &checkpoint, &resolver, &responses),
            "{terminal}"
        );
    }
}

#[test]
fn content_hashes_do_not_replace_retained_bodies_or_checkpoint_pair() {
    let (checkpoint, resolver, responses) = fixture("pending-checkpoint.json");
    let original = read("data/leased-journal.json");
    assert!(!valid(&original, &checkpoint, &resolver, &BTreeMap::new()));
    let mut changed = responses.clone();
    changed.get_mut("produce-1").unwrap()["unexpected"] = json!(true);
    assert!(!valid(&original, &checkpoint, &resolver, &changed));
    let mut torn = original.clone();
    torn["checkpoint_revision"] = json!("3");
    seal(&mut torn);
    assert!(!valid(&torn, &checkpoint, &resolver, &responses));
}

#[test]
fn resealed_terminal_state_and_receipt_corruption_refuse() {
    let (checkpoint, resolver, responses) = fixture("admitted-checkpoint.json");
    for mutation in ["receipt", "fence", "cancellation", "state"] {
        let mut journal = read("data/result-admitted-journal.json");
        let record = &mut journal["effect_records"][0];
        match mutation {
            "receipt" => {
                record["admission_receipt"]["request_digest"] =
                    json!(format!("sha256:{}", "0".repeat(64)))
            }
            "fence" => record["attempt_fence"] = json!("2"),
            "cancellation" => {
                record["cancellation"] = json!({"operation_id":"cancel-1","reason":"user_requested","state":"prevented_start"})
            }
            "state" => {
                record["invocation_state"] = json!("unclaimed");
                record["outcome"] = Value::Null;
                record["result_event_id"] = Value::Null;
                record["admission_receipt"] = Value::Null;
            }
            _ => unreachable!(),
        }
        seal(&mut journal);
        assert!(
            !valid(&journal, &checkpoint, &resolver, &responses),
            "{mutation}"
        );
    }
}

#[test]
fn independently_trusted_alternate_root_origin_cannot_replace_actual_root() {
    let (checkpoint, mut resolver, responses) = fixture("pending-checkpoint.json");
    let source = std::fs::read_to_string(directory().join("machine.yaml")).unwrap();
    let alternate = load_bundle(&source.replace(
        "conformance.committed_native_effects",
        "conformance.other_trusted_definition",
    ))
    .unwrap();
    let fingerprint = alternate.fingerprint.clone();
    let namespace = alternate.namespace.clone();
    resolver.insert(alternate, true);
    let mut journal = read("data/leased-journal.json");
    let target = &mut journal["effect_records"][0]["target"];
    target["runtime_incarnation"]["definition"]["validated_bundle_fingerprint"] =
        json!(fingerprint);
    target["runtime_incarnation"]["definition"]["machine"]["namespace"] = json!(namespace);
    target["runtime_id"] = json!(hash(&json!([
        "determa-root-runtime-identity-1",
        "1",
        fingerprint,
        namespace,
        "workflow",
        "1",
        checkpoint.root_instance_id()
    ])));
    seal(&mut journal);
    assert!(!valid(&journal, &checkpoint, &resolver, &responses));
}

#[test]
fn preclaim_cancellation_requires_exact_zero_attempt_outcome() {
    let (checkpoint, resolver, mut responses) = fixture("pending-checkpoint.json");
    responses.insert("cancel-1".into(), read("data/cancel-response.json"));
    let original = read("data/preclaim-cancelled-journal.json");
    assert!(valid(&original, &checkpoint, &resolver, &responses));
    for state in ["unclaimed", "leased", "ambiguous"] {
        let mut journal = original.clone();
        let record = &mut journal["effect_records"][0];
        record["invocation_state"] = json!(state);
        record["outcome"] = Value::Null;
        record["result_event_id"] = Value::Null;
        seal(&mut journal);
        assert!(!valid(&journal, &checkpoint, &resolver, &responses));
    }
}
