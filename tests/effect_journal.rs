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

fn process_input(
    bundle: &determa_state::format1::Bundle,
    checkpoint: &ExecutionCheckpoint,
    resolver: &InMemoryDefinitionResolver,
    event: &str,
) -> ExecutionCheckpoint {
    let runtime = &checkpoint.value()["root_record"]["aggregate_state"]["runtimes"][0];
    let envelope = json!({"event":event,"event_id":event,"cause_id":event,"source":{"host":true},"target":runtime["target_identity"],"payload":["map",[]]});
    let delivery = json!({"delivery_mode":"input","envelope_digest":hash(&json!(["determa-inbox-envelope-digest-1","1",checkpoint.root_instance_id(),"input",envelope])),"envelope":envelope});
    let next = determa_state::checkpoint::process(
        bundle,
        checkpoint,
        delivery,
        "foreground",
        Some(checkpoint.revision()),
        Some(checkpoint.digest()),
    )
    .unwrap();
    restore(&serde_json::to_vec(&next).unwrap(), resolver).unwrap()
}

#[test]
fn historical_component_and_spawned_targets_remain_bound_after_actual_removal() {
    for (case, machine, kind, removal) in [
        ("54-stale-component-target", "owner", "component", "leave"),
        (
            "30-owned-spawn-cancel",
            "order",
            "owned_spawned_instance",
            "cancel_payment",
        ),
    ] {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("conformance-suite/conformance/core")
            .join(case)
            .join("machine.yaml");
        let bundle = load_bundle(&std::fs::read_to_string(path).unwrap()).unwrap();
        let mut source = bundle.normalized.clone();
        source["events"]["native_request"] = json!({"direction":"output","payload":{}});
        let event = &mut source["machines"][0]["root"]["states"]["idle"]["on_events"]["start"];
        if event["action"].is_null() {
            event["action"] = json!([]);
        }
        event["action"]
            .as_array_mut()
            .unwrap()
            .push(json!({"send":{"event":"native_request","to":{"external":true},"payload":{},"correlation_id":"\"lifecycle-op\""}}));
        let bundle = determa_state::format1::load_bundle_from_json(source).unwrap();
        let mut resolver = InMemoryDefinitionResolver::default();
        resolver.insert(bundle.clone(), true);
        let created = determa_state::checkpoint::create(&bundle,machine,"historical-root","creation",&determa_state::Bindings::default(),None,json!({"mode":"permanent","permanent_replay_eligible":true,"pruned_through_receipt_sequence":null,"policy_identifier":null})).unwrap();
        let active = process_input(&bundle, &created, &resolver, "start");
        let child = active.value()["root_record"]["aggregate_state"]["runtimes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|runtime| runtime["identity_origin"]["kind"] == kind)
            .unwrap()
            .clone();
        let mut journal = read("data/unclaimed-journal.json");
        journal["root_instance_id"] = json!("historical-root");
        journal["operation_response_references"] = json!([]);
        let intent = &active.value()["pending_outbox_intents"][0]["intent"];
        let record = &mut journal["effect_records"][0];
        record["effect_id"] = intent["effect_id"].clone();
        record["operation_token"] = intent["correlation_id"].clone();
        record["intent_digest"] = json!(hash(&json!([
            "determa-outbox-intent-digest-1",
            "1",
            "historical-root",
            intent
        ])));
        record["target"] = json!({"root_instance_id":"historical-root","runtime_id":child["runtime_id"],"runtime_incarnation":child["identity_origin"]});
        record["result_mapping"] = json!([{"outcome_kind":"succeeded","event":"start","result_slot":"success","operation_token_location":{"kind":"correlation_id"}}]);
        let removed = process_input(&bundle, &active, &resolver, removal);
        for checkpoint in [&active, &removed] {
            journal["checkpoint_revision"] = json!(checkpoint.revision());
            journal["checkpoint_digest"] = json!(checkpoint.digest());
            seal(&mut journal);
            ValidatedEffectJournal::restore(
                &serde_json::to_vec(&journal).unwrap(),
                checkpoint,
                "effect-scope-1",
                &BTreeMap::new(),
                &resolver,
            )
            .unwrap();
        }
        assert!(
            removed.value()["root_record"]["aggregate_state"]["runtimes"]
                .as_array()
                .unwrap()
                .iter()
                .all(|runtime| runtime["runtime_id"] != child["runtime_id"])
        );
        let origin = &mut journal["effect_records"][0]["target"]["runtime_incarnation"];
        let counter = if kind == "component" {
            "activation_sequence"
        } else {
            "spawn_sequence"
        };
        origin[counter] = json!("999");
        seal(&mut journal);
        assert!(!valid(&journal, &removed, &resolver, &BTreeMap::new()));
    }
}

#[test]
fn retained_admitted_result_survives_actual_root_completion_and_tombstone() {
    let original =
        load_bundle(&std::fs::read_to_string(directory().join("machine.yaml")).unwrap()).unwrap();
    let mut source = original.normalized.clone();
    let mut events = source["machines"][0]["root"]["on_events"].clone();
    events["native_succeeded"] = json!({"transition_to":"done"});
    source["machines"][0]["root"] = json!({"type":"composite","initial":{"transition_to":"working"},"states":{"working":{"on_events":events},"done":{"type":"final"}}});
    let bundle = determa_state::format1::load_bundle_from_json(source).unwrap();
    let mut resolver = InMemoryDefinitionResolver::default();
    resolver.insert(bundle.clone(), true);
    let created = determa_state::checkpoint::create(&bundle,"workflow","completed-root","creation",&determa_state::Bindings::default(),None,json!({"mode":"permanent","permanent_replay_eligible":true,"pruned_through_receipt_sequence":null,"policy_identifier":null})).unwrap();
    let runtime = created.value()["root_record"]["aggregate_state"]["runtimes"][0].clone();
    let invoke = json!({"event":"invoke","event_id":"invoke","cause_id":"invoke","source":{"host":true},"target":runtime["target_identity"],"payload":["map",[["operation_token",["string","business-order-42"]]]]});
    let delivery = json!({"delivery_mode":"input","envelope_digest":hash(&json!(["determa-inbox-envelope-digest-1","1","completed-root","input",invoke])),"envelope":invoke});
    let produced = determa_state::checkpoint::process(
        &bundle,
        &created,
        delivery,
        "foreground",
        Some(created.revision()),
        Some(created.digest()),
    )
    .unwrap();
    let produced = restore(&serde_json::to_vec(&produced).unwrap(), &resolver).unwrap();
    let intent = &produced.value()["pending_outbox_intents"][0]["intent"];
    let mut journal = read("data/outcome-recorded-journal.json");
    journal["root_instance_id"] = json!("completed-root");
    journal["operation_response_references"] = json!([]);
    let record = &mut journal["effect_records"][0];
    record["effect_id"] = intent["effect_id"].clone();
    record["intent_digest"] = json!(hash(&json!([
        "determa-outbox-intent-digest-1",
        "1",
        "completed-root",
        intent
    ])));
    record["target"] = json!({"root_instance_id":"completed-root","runtime_id":runtime["runtime_id"],"runtime_incarnation":runtime["identity_origin"]});
    let outcome = record["outcome"].clone();
    record["outcome"]["digest"] = json!(hash(&json!([
        "determa-effect-outcome-1",
        record["effect_id"],
        record["operation_token"],
        outcome["kind"],
        outcome["payload"],
        outcome["attempt_fence"]
    ])));
    let reason = record["attempt_records"][0]["reason"].clone();
    record["attempt_records"][0]["report_digest"] = json!(hash(&json!([
        "determa-effect-attempt-report-1",
        record["effect_id"],
        record["operation_token"],
        outcome["attempt_fence"],
        outcome["kind"],
        outcome["payload"],
        reason
    ])));
    let result_id = hash(&json!([
        "determa-effect-result-event-1",
        record["effect_id"],
        "success"
    ]));
    record["result_event_id"] = json!(result_id);
    let envelope = json!({"event":"native_succeeded","event_id":result_id,"cause_id":result_id,"source":{"host":true},"target":runtime["target_identity"],"payload":outcome["payload"],"correlation_id":record["operation_token"]});
    let delivery = json!({"delivery_mode":"input","envelope_digest":hash(&json!(["determa-inbox-envelope-digest-1","1","completed-root","input",envelope])),"envelope":envelope});
    let completed = determa_state::checkpoint::process(
        &bundle,
        &produced,
        delivery,
        "foreground",
        Some(produced.revision()),
        Some(produced.digest()),
    )
    .unwrap();
    let completed = restore(&serde_json::to_vec(&completed).unwrap(), &resolver).unwrap();
    assert_eq!(
        completed.value()["root_record"]["aggregate_state"]["runtimes"][0]["status"],
        "completed"
    );
    let record = &mut journal["effect_records"][0];
    record["invocation_state"] = json!("closed");
    record["admission_receipt"] = completed.value()["operation_receipts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|receipt| {
            receipt["operation_kind"] == "acceptance" && receipt["event_id"] == result_id
        })
        .unwrap()
        .clone();
    let terminal = determa_state::checkpoint::terminalize_outbox(
        &completed,
        record["effect_id"].as_str().unwrap(),
        determa_state::checkpoint::TerminalOutboxOutcome::Confirmed,
        Some(completed.revision()),
        Some(completed.digest()),
    )
    .unwrap();
    let terminal = restore(&serde_json::to_vec(&terminal).unwrap(), &resolver).unwrap();
    let tombstone = determa_state::checkpoint::tombstone_root(
        &terminal,
        "tombstone",
        Some(terminal.revision()),
        Some(terminal.digest()),
    )
    .unwrap();
    let tombstone = restore(&serde_json::to_vec(&tombstone).unwrap(), &resolver).unwrap();
    journal["checkpoint_revision"] = json!(tombstone.revision());
    journal["checkpoint_digest"] = json!(tombstone.digest());
    seal(&mut journal);
    ValidatedEffectJournal::restore(
        &serde_json::to_vec(&journal).unwrap(),
        &tombstone,
        "effect-scope-1",
        &BTreeMap::new(),
        &resolver,
    )
    .unwrap();
}
