use determa_state::checkpoint::{
    CheckpointHost, ExecutionStore, FileExecutionStore, MaintenanceMigrationRequest,
    MemoryExecutionStore, MutationGuard, PendingOutboxState, ProcessingRequest, PruneRequest,
    StoreRecord, StoreWriteResult, TerminalOutboxOutcome, TransactionalProcessRequest,
};
#[cfg(feature = "sqlite")]
use determa_state::checkpoint::{DurableStoreMode, SqliteExecutionStore};
use determa_state::{
    load_bundle, Bindings, InMemoryDefinitionResolver, MigrationRequest, ResourceLimits,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn memory_store_runs_the_native_v1_host_contract() {
    let store: Arc<dyn ExecutionStore> = Arc::new(MemoryExecutionStore::new());
    store.initialize_schema().unwrap();
    native_v1_host_contract(store);
}

#[test]
fn empty_checkpoint_admission_is_malformed_without_mutation() {
    let directory = Path::new("conformance-suite/conformance/profiles/execution-checkpoint/checkpoint-01-native-lifecycle");
    let bundle = load_bundle(&fs::read_to_string(directory.join("machine.yaml")).unwrap()).unwrap();
    let mut resolver = InMemoryDefinitionResolver::default();
    resolver.insert(bundle.clone(), true);
    let checkpoint = determa_state::checkpoint::restore(
        &fs::read(directory.join("created-checkpoint-v1.json")).unwrap(),
        &resolver,
    )
    .unwrap();
    assert_eq!(
        determa_state::checkpoint::admit(&bundle, &checkpoint, &[], Some("stale"), Some("stale"),)
            .unwrap_err()
            .code,
        "malformed_delivery"
    );
    let store: Arc<dyn ExecutionStore> = Arc::new(MemoryExecutionStore::new());
    store.initialize_schema().unwrap();
    assert_eq!(
        store
            .insert_if_absent(StoreRecord::from_checkpoint(&checkpoint).unwrap())
            .unwrap(),
        StoreWriteResult::Committed
    );
    let host = CheckpointHost::new(store, Arc::new(resolver));
    assert_eq!(
        host.admit_checkpoint(
            checkpoint.root_instance_id(),
            &[],
            &MutationGuard::new(checkpoint.revision(), checkpoint.digest()),
        )
        .unwrap_err()
        .code,
        "malformed_delivery"
    );
    assert_eq!(
        host.load_checkpoint(checkpoint.root_instance_id())
            .unwrap()
            .unwrap()
            .value(),
        checkpoint.value()
    );
}

#[test]
fn file_store_runs_the_native_v1_host_contract_and_survives_restart() {
    let directory = temporary_path("file-native-v1");
    let store: Arc<dyn ExecutionStore> = Arc::new(FileExecutionStore::new(&directory).unwrap());
    store.initialize_schema().unwrap();
    native_v1_host_contract(store.clone());
    drop(store);
    let reopened = FileExecutionStore::new(&directory).unwrap();
    assert!(reopened.load("server-1").unwrap().is_some());
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn emitted_internal_event_deferral_and_recall_survive_host_restart() {
    let bundle = load_bundle(
        r#"
format: 1
namespace: test.internal_deferred_restart
events:
  release: { direction: input }
  loop: { direction: internal }
machines:
  - machine_id: worker
    root:
      type: composite
      deferred_event_capacity: 4
      initial: { transition_to: busy }
      states:
        busy:
          entry:
            - send: { event: loop, to: { self: true } }
          deferred_events: [loop]
          on_events:
            release: { transition_to: idle }
        idle:
          on_events:
            loop: {}
"#,
    )
    .unwrap();
    let mut resolver = InMemoryDefinitionResolver::default();
    resolver.insert(bundle.clone(), true);
    let resolver = Arc::new(resolver);
    let directory = temporary_path("internal-deferred-restart");
    let retention = json!({"mode":"permanent","permanent_replay_eligible":true,"pruned_through_receipt_sequence":null,"policy_identifier":null});

    let store: Arc<dyn ExecutionStore> = Arc::new(FileExecutionStore::new(&directory).unwrap());
    store.initialize_schema().unwrap();
    let host = CheckpointHost::new(store.clone(), resolver.clone());
    host.create_checkpoint(
        &bundle,
        "worker",
        "internal-restart",
        "create-internal-restart",
        &Bindings::default(),
        None,
        retention,
    )
    .unwrap();
    let created = host.load_checkpoint("internal-restart").unwrap().unwrap();
    let initial = created.value();
    let internal = &initial["root_record"]["aggregate_state"]["runtimes"][0]["ready_mailbox"][0];
    assert_eq!(internal["delivery_mode"], "internal");
    let original_queue = internal["queue_sequence"].clone();
    let deferred = host
        .step_checkpoint(
            "internal-restart",
            &processing_for(initial),
            &MutationGuard::new(created.revision(), created.digest()),
        )
        .unwrap();
    let deferred_entry =
        &deferred["root_record"]["aggregate_state"]["runtimes"][0]["deferred_mailbox"][0];
    assert_ne!(deferred_entry["queue_sequence"], original_queue);
    assert_eq!(deferred_entry["deferral_count"], "1");
    drop(host);
    drop(store);

    let store: Arc<dyn ExecutionStore> = Arc::new(FileExecutionStore::new(&directory).unwrap());
    let host = CheckpointHost::new(store.clone(), resolver.clone());
    let restored = host.load_checkpoint("internal-restart").unwrap().unwrap();
    assert_eq!(restored.value(), &deferred);
    let delivery = named_input_delivery(restored.value(), "release", "release-internal-restart");
    let admitted = host
        .admit_checkpoint(
            "internal-restart",
            &[delivery],
            &MutationGuard::new(restored.revision(), restored.digest()),
        )
        .unwrap();
    let released = host
        .step_checkpoint(
            "internal-restart",
            &processing_for(&admitted),
            &MutationGuard::new(
                admitted["revision"].as_str().unwrap(),
                admitted["execution_checkpoint_digest"].as_str().unwrap(),
            ),
        )
        .unwrap();
    let recalled = &released["root_record"]["aggregate_state"]["runtimes"][0]["ready_mailbox"][0];
    assert_eq!(recalled["delivery_mode"], "internal");
    assert_ne!(recalled["queue_sequence"], deferred_entry["queue_sequence"]);
    drop(host);
    drop(store);
    let store: Arc<dyn ExecutionStore> = Arc::new(FileExecutionStore::new(&directory).unwrap());
    let host = CheckpointHost::new(store, resolver);
    assert_eq!(
        host.load_checkpoint("internal-restart")
            .unwrap()
            .unwrap()
            .value(),
        &released
    );
    let terminal = host
        .step_checkpoint(
            "internal-restart",
            &processing_for(&released),
            &MutationGuard::new(
                released["revision"].as_str().unwrap(),
                released["execution_checkpoint_digest"].as_str().unwrap(),
            ),
        )
        .unwrap();
    let terminal_sequence = terminal["operation_receipts"]
        .as_array()
        .unwrap()
        .last()
        .unwrap()["receipt_sequence"]
        .as_str()
        .unwrap();
    let pruned = host
        .prune_checkpoint(
            "internal-restart",
            &PruneRequest {
                cutoff_receipt_sequence: terminal_sequence.to_string(),
                target_mode: "bounded".to_string(),
                policy_identifier: Some("internal-prune".to_string()),
                dependency_receipt_sequences: Vec::new(),
                dependency_effect_ids: Vec::new(),
            },
            &MutationGuard::new(
                terminal["revision"].as_str().unwrap(),
                terminal["execution_checkpoint_digest"].as_str().unwrap(),
            ),
        )
        .unwrap();
    let event_id = terminal["operation_receipts"][0]["emission_references"][0]["event_id"].clone();
    assert!(pruned["event_identity_tombstones"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["event_id"] == event_id));
    assert_eq!(
        host.load_checkpoint("internal-restart")
            .unwrap()
            .unwrap()
            .value(),
        &pruned
    );
    fs::remove_dir_all(directory).unwrap();
}

#[cfg(feature = "sqlite")]
#[test]
fn permanent_sqlite_retains_internal_event_through_deferral_recall_and_terminalization() {
    let bundle = load_bundle(
        r#"
format: 1
namespace: test.internal_permanent
events:
  release: { direction: input }
  loop: { direction: internal }
machines:
  - machine_id: worker
    root:
      type: composite
      deferred_event_capacity: 4
      initial: { transition_to: busy }
      states:
        busy:
          entry:
            - send: { event: loop, to: { self: true } }
          deferred_events: [loop]
          on_events:
            release: { transition_to: idle }
        idle:
          on_events:
            loop: {}
"#,
    )
    .unwrap();
    let mut resolver = InMemoryDefinitionResolver::default();
    resolver.insert(bundle.clone(), true);
    let resolver = Arc::new(resolver);
    let directory = temporary_path("internal-permanent");
    fs::create_dir_all(&directory).unwrap();
    let path = directory.join("checkpoint.sqlite3");
    let mode = DurableStoreMode::new(
        determa_state::checkpoint::ReceiptRetentionMode::Permanent,
        determa_state::checkpoint::OutboxRetentionMode::Bounded,
    );
    let store: Arc<dyn ExecutionStore> = Arc::new(SqliteExecutionStore::open(&path, mode).unwrap());
    store.initialize_schema().unwrap();
    let host = CheckpointHost::new(store.clone(), resolver.clone());
    host.create_checkpoint(
        &bundle, "worker", "internal-permanent", "create-internal-permanent",
        &Bindings::default(), None,
        json!({"mode":"permanent","permanent_replay_eligible":true,"pruned_through_receipt_sequence":null,"policy_identifier":null}),
    ).unwrap();
    let created = host.load_checkpoint("internal-permanent").unwrap().unwrap();
    host.step_checkpoint(
        "internal-permanent",
        &processing_for(created.value()),
        &MutationGuard::new(created.revision(), created.digest()),
    )
    .unwrap();
    drop(host);
    drop(store);
    let store: Arc<dyn ExecutionStore> = Arc::new(SqliteExecutionStore::open(&path, mode).unwrap());
    let host = CheckpointHost::new(store.clone(), resolver.clone());
    let deferred = host.load_checkpoint("internal-permanent").unwrap().unwrap();
    let delivery = named_input_delivery(deferred.value(), "release", "release-internal-permanent");
    let admitted = host
        .admit_checkpoint(
            "internal-permanent",
            &[delivery],
            &MutationGuard::new(deferred.revision(), deferred.digest()),
        )
        .unwrap();
    let released = host
        .step_checkpoint(
            "internal-permanent",
            &processing_for(&admitted),
            &MutationGuard::new(
                admitted["revision"].as_str().unwrap(),
                admitted["execution_checkpoint_digest"].as_str().unwrap(),
            ),
        )
        .unwrap();
    let internal = &released["root_record"]["aggregate_state"]["runtimes"][0]["ready_mailbox"][0];
    assert_eq!(internal["delivery_mode"], "internal");
    let terminal = host
        .step_checkpoint(
            "internal-permanent",
            &processing_for(&released),
            &MutationGuard::new(
                released["revision"].as_str().unwrap(),
                released["execution_checkpoint_digest"].as_str().unwrap(),
            ),
        )
        .unwrap();
    assert!(terminal["operation_receipts"]
        .as_array()
        .unwrap()
        .iter()
        .any(|receipt| {
            receipt["emission_references"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|reference| reference["kind"] == "internal_terminal")
        }));
    drop(host);
    drop(store);
    let store: Arc<dyn ExecutionStore> = Arc::new(SqliteExecutionStore::open(&path, mode).unwrap());
    let host = CheckpointHost::new(store, resolver);
    assert_eq!(
        host.load_checkpoint("internal-permanent")
            .unwrap()
            .unwrap()
            .value(),
        &terminal
    );
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn checkpoint_restore_rejects_duplicate_and_dangling_producer_references() {
    let root = Path::new("conformance-suite/conformance/profiles/execution-checkpoint");
    let cases = [
        (
            "checkpoint-05-spawned-host-trace",
            "spawned-child-terminal-checkpoint-v1.json",
            "internal_mailbox",
        ),
        (
            "checkpoint-05-spawned-host-trace",
            "spawned-owner-done-checkpoint-v1.json",
            "internal_terminal",
        ),
        (
            "checkpoint-02-native-outbox",
            "pending-checkpoint-v1.json",
            "external_outbox",
        ),
    ];
    for (directory, filename, kind) in cases {
        let directory = root.join(directory);
        let bundle =
            load_bundle(&fs::read_to_string(directory.join("machine.yaml")).unwrap()).unwrap();
        let mut resolver = InMemoryDefinitionResolver::default();
        resolver.insert(bundle, true);
        let source = fs::read(directory.join(filename)).unwrap();
        determa_state::checkpoint::restore(&source, &resolver).unwrap();
        let mut value: Value = serde_json::from_slice(&source).unwrap();
        let refs = value["operation_receipts"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|receipt| {
                receipt["emission_references"]
                    .as_array()
                    .is_some_and(|refs| refs.iter().any(|reference| reference["kind"] == kind))
            })
            .unwrap()["emission_references"]
            .as_array_mut()
            .unwrap();
        let original = refs
            .iter()
            .find(|reference| reference["kind"] == kind)
            .unwrap()
            .clone();
        refs.push(original);
        reseal_checkpoint_digest(&mut value);
        assert!(
            determa_state::checkpoint::restore(&serde_json::to_vec(&value).unwrap(), &resolver)
                .is_err(),
            "duplicate {kind} producer reference restored"
        );
        if kind == "internal_mailbox" {
            let refs = value["operation_receipts"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|receipt| {
                    receipt["emission_references"]
                        .as_array()
                        .is_some_and(|refs| refs.iter().any(|reference| reference["kind"] == kind))
                })
                .unwrap()["emission_references"]
                .as_array_mut()
                .unwrap();
            refs.pop();
            refs.iter_mut()
                .find(|reference| reference["kind"] == kind)
                .unwrap()["event_id"] = json!("phantom-event");
            reseal_checkpoint_digest(&mut value);
            assert!(
                determa_state::checkpoint::restore(&serde_json::to_vec(&value).unwrap(), &resolver)
                    .is_err(),
                "dangling internal producer reference restored"
            );
        }
    }
}

#[test]
fn checkpoint_restore_requires_producer_for_every_retained_outbox_effect() {
    let directory = Path::new(
        "conformance-suite/conformance/profiles/execution-checkpoint/checkpoint-02-native-outbox",
    );
    let bundle = load_bundle(&fs::read_to_string(directory.join("machine.yaml")).unwrap()).unwrap();
    let mut resolver = InMemoryDefinitionResolver::default();
    resolver.insert(bundle, true);
    for filename in [
        "pending-checkpoint-v1.json",
        "terminal-checkpoint-v1.json",
        "effect-tombstone-checkpoint-v1.json",
    ] {
        let source = fs::read(directory.join(filename)).unwrap();
        determa_state::checkpoint::restore(&source, &resolver).unwrap();
        let mut value: Value = serde_json::from_slice(&source).unwrap();
        let references = value["operation_receipts"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|receipt| {
                receipt["emission_references"]
                    .as_array()
                    .is_some_and(|references| {
                        references
                            .iter()
                            .any(|reference| reference["kind"] == "external_outbox")
                    })
            })
            .unwrap()["emission_references"]
            .as_array_mut()
            .unwrap();
        let index = references
            .iter()
            .position(|reference| reference["kind"] == "external_outbox")
            .unwrap();
        references.remove(index);
        reseal_checkpoint_digest(&mut value);
        assert!(
            determa_state::checkpoint::restore(&serde_json::to_vec(&value).unwrap(), &resolver)
                .is_err(),
            "{filename} restored without an effect producer"
        );
    }
}

#[test]
fn pruning_outbox_producer_removes_terminal_evidence_and_protects_pending_work() {
    let directory = Path::new(
        "conformance-suite/conformance/profiles/execution-checkpoint/checkpoint-02-native-outbox",
    );
    let bundle = load_bundle(&fs::read_to_string(directory.join("machine.yaml")).unwrap()).unwrap();
    let mut resolver = InMemoryDefinitionResolver::default();
    resolver.insert(bundle, true);
    let request = PruneRequest {
        cutoff_receipt_sequence: "2".to_string(),
        target_mode: "bounded".to_string(),
        policy_identifier: Some("outbox-prune".to_string()),
        dependency_receipt_sequences: Vec::new(),
        dependency_effect_ids: Vec::new(),
    };
    for filename in [
        "terminal-checkpoint-v1.json",
        "effect-tombstone-checkpoint-v1.json",
    ] {
        let checkpoint = determa_state::checkpoint::restore(
            &fs::read(directory.join(filename)).unwrap(),
            &resolver,
        )
        .unwrap();
        let pruned = determa_state::checkpoint::prune(&checkpoint, &request, None, None).unwrap();
        assert!(
            pruned["terminal_outbox_records"]
                .as_array()
                .unwrap()
                .is_empty(),
            "{filename}"
        );
        assert!(
            pruned["outbox_effect_tombstones"]
                .as_array()
                .unwrap()
                .is_empty(),
            "{filename}"
        );
        assert_eq!(pruned["operation_receipts"].as_array().unwrap().len(), 1);
        determa_state::checkpoint::restore(&serde_json::to_vec(&pruned).unwrap(), &resolver)
            .unwrap();
    }
    let pending = determa_state::checkpoint::restore(
        &fs::read(directory.join("pending-checkpoint-v1.json")).unwrap(),
        &resolver,
    )
    .unwrap();
    assert_eq!(
        determa_state::checkpoint::prune(&pending, &request, None, None)
            .unwrap_err()
            .code,
        "invalid_execution_checkpoint"
    );
}

#[test]
fn checkpoint_restore_rejects_outbox_terminal_sequence_overlap() {
    let directory = Path::new(
        "conformance-suite/conformance/profiles/execution-checkpoint/checkpoint-02-native-outbox",
    );
    let bundle = load_bundle(&fs::read_to_string(directory.join("machine.yaml")).unwrap()).unwrap();
    let mut resolver = InMemoryDefinitionResolver::default();
    resolver.insert(bundle, true);
    let source = fs::read(directory.join("effect-tombstone-checkpoint-v1.json")).unwrap();
    determa_state::checkpoint::restore(&source, &resolver).unwrap();
    let mut value: Value = serde_json::from_slice(&source).unwrap();
    value["outbox_effect_tombstones"][0]["terminal_sequence"] =
        value["terminal_outbox_records"][0]["terminal_sequence"].clone();
    reseal_checkpoint_digest(&mut value);
    let error = determa_state::checkpoint::restore(&serde_json::to_vec(&value).unwrap(), &resolver)
        .unwrap_err();
    assert!(
        error
            .message
            .contains("outbox effect identity or terminal sequence"),
        "{error:?}"
    );

    let source = fs::read(directory.join("terminal-checkpoint-v1.json")).unwrap();
    determa_state::checkpoint::restore(&source, &resolver).unwrap();
    let mut value: Value = serde_json::from_slice(&source).unwrap();
    let terminal_records = value["terminal_outbox_records"].as_array_mut().unwrap();
    let first = terminal_records[0]["terminal_sequence"].clone();
    terminal_records[0]["terminal_sequence"] = terminal_records[1]["terminal_sequence"].clone();
    terminal_records[1]["terminal_sequence"] = first;
    reseal_checkpoint_digest(&mut value);
    let error = determa_state::checkpoint::restore(&serde_json::to_vec(&value).unwrap(), &resolver)
        .unwrap_err();
    assert!(
        error.message.contains("outbox terminal allocation"),
        "{error:?}"
    );
}

#[test]
fn terminal_outbox_records_follow_completion_order_even_when_intents_arrived_earlier() {
    let directory = Path::new(
        "conformance-suite/conformance/profiles/execution-checkpoint/checkpoint-02-native-outbox",
    );
    let bundle = load_bundle(&fs::read_to_string(directory.join("machine.yaml")).unwrap()).unwrap();
    let mut resolver = InMemoryDefinitionResolver::default();
    resolver.insert(bundle, true);
    let checkpoint = determa_state::checkpoint::restore(
        &fs::read(directory.join("pending-checkpoint-v1.json")).unwrap(),
        &resolver,
    )
    .unwrap();
    let effect_ids = checkpoint.value()["pending_outbox_intents"]
        .as_array()
        .unwrap()
        .iter()
        .map(|record| record["intent"]["effect_id"].as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    let store: Arc<dyn ExecutionStore> = Arc::new(MemoryExecutionStore::new());
    store.initialize_schema().unwrap();
    assert_eq!(
        store
            .insert_if_absent(StoreRecord::from_checkpoint(&checkpoint).unwrap())
            .unwrap(),
        StoreWriteResult::Committed
    );
    let host = CheckpointHost::new(store, Arc::new(resolver));
    let mut prior = checkpoint.value().clone();
    for effect_id in [&effect_ids[4], &effect_ids[0]] {
        host.terminalize_outbox(
            checkpoint.root_instance_id(),
            effect_id,
            TerminalOutboxOutcome::Confirmed,
            &MutationGuard::new(
                prior["revision"].as_str().unwrap(),
                prior["execution_checkpoint_digest"].as_str().unwrap(),
            ),
        )
        .unwrap();
        prior = host
            .load_checkpoint(checkpoint.root_instance_id())
            .unwrap()
            .unwrap()
            .value()
            .clone();
    }
    let records = prior["terminal_outbox_records"].as_array().unwrap();
    assert_eq!(records[0]["intent"]["effect_id"], effect_ids[4]);
    assert_eq!(records[1]["intent"]["effect_id"], effect_ids[0]);
    assert_eq!(records[0]["terminal_sequence"], "0");
    assert_eq!(records[1]["terminal_sequence"], "1");
}

#[test]
fn checkpoint_restore_rejects_acceptance_without_live_or_terminal_event() {
    let directory = Path::new("conformance-suite/conformance/profiles/execution-checkpoint/checkpoint-05-spawned-host-trace");
    let bundle = load_bundle(&fs::read_to_string(directory.join("machine.yaml")).unwrap()).unwrap();
    let mut resolver = InMemoryDefinitionResolver::default();
    resolver.insert(bundle, true);
    let source = fs::read(directory.join("spawned-start-pending-checkpoint-v1.json")).unwrap();
    determa_state::checkpoint::restore(&source, &resolver).unwrap();
    let mut value: Value = serde_json::from_slice(&source).unwrap();
    let accepted_event = value["operation_receipts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|receipt| receipt["operation_kind"] == "acceptance")
        .unwrap()["event_id"]
        .clone();
    let aggregate = &mut value["root_record"]["aggregate_state"];
    let ready = aggregate["runtimes"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .flat_map(|runtime| {
            runtime["ready_mailbox"]
                .as_array_mut()
                .into_iter()
                .flatten()
        })
        .find(|entry| entry["envelope"]["event_id"] == accepted_event)
        .unwrap();
    *ready = Value::Null;
    for runtime in aggregate["runtimes"].as_array_mut().unwrap() {
        runtime["ready_mailbox"]
            .as_array_mut()
            .unwrap()
            .retain(|entry| !entry.is_null());
    }
    reseal_aggregate_digest(aggregate);
    reseal_checkpoint_digest(&mut value);
    assert!(
        determa_state::checkpoint::restore(&serde_json::to_vec(&value).unwrap(), &resolver)
            .is_err()
    );
}

#[test]
fn checkpoint_restore_enforces_receipt_chronology_allocation_and_digest() {
    let directory = Path::new("conformance-suite/conformance/profiles/execution-checkpoint/checkpoint-05-spawned-host-trace");
    let bundle = load_bundle(&fs::read_to_string(directory.join("machine.yaml")).unwrap()).unwrap();
    let mut resolver = InMemoryDefinitionResolver::default();
    resolver.insert(bundle, true);
    let source = fs::read(directory.join("spawned-child-terminal-checkpoint-v1.json")).unwrap();
    determa_state::checkpoint::restore(&source, &resolver).unwrap();
    let original: Value = serde_json::from_slice(&source).unwrap();

    let mut chronology = original.clone();
    chronology["operation_receipts"][3]["accepted_revision"] = json!("1");
    reseal_checkpoint_digest(&mut chronology);
    let error =
        determa_state::checkpoint::restore(&serde_json::to_vec(&chronology).unwrap(), &resolver)
            .unwrap_err();
    assert!(error.message.contains("receipt chronology"), "{error:?}");

    let mut digest = original.clone();
    digest["operation_receipts"][5]["resulting_aggregate_state_digest"] =
        json!("sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    reseal_checkpoint_digest(&mut digest);
    let error =
        determa_state::checkpoint::restore(&serde_json::to_vec(&digest).unwrap(), &resolver)
            .unwrap_err();
    assert!(
        error.message.contains("terminal result digest"),
        "{error:?}"
    );

    let mut queue = original;
    queue["operation_receipts"][5]["final_queue_sequence"] = json!("2");
    reseal_checkpoint_digest(&mut queue);
    let error = determa_state::checkpoint::restore(&serde_json::to_vec(&queue).unwrap(), &resolver)
        .unwrap_err();
    assert!(
        error.message.contains("terminal queue allocation"),
        "{error:?}"
    );
}

#[test]
fn checkpoint_restore_enforces_internal_producer_chronology_and_acceptance_owner() {
    let directory = Path::new("conformance-suite/conformance/profiles/execution-checkpoint/checkpoint-05-spawned-host-trace");
    let bundle = load_bundle(&fs::read_to_string(directory.join("machine.yaml")).unwrap()).unwrap();
    let mut resolver = InMemoryDefinitionResolver::default();
    resolver.insert(bundle, true);
    let source = fs::read(directory.join("spawned-owner-done-checkpoint-v1.json")).unwrap();
    determa_state::checkpoint::restore(&source, &resolver).unwrap();
    let original: Value = serde_json::from_slice(&source).unwrap();

    let mut ownership = original.clone();
    ownership["operation_receipts"][5]["emission_references"][0]["acceptance_sequence"] =
        json!("2");
    ownership["operation_receipts"][7]["acceptance_sequence"] = json!("2");
    reseal_checkpoint_digest(&mut ownership);
    let error =
        determa_state::checkpoint::restore(&serde_json::to_vec(&ownership).unwrap(), &resolver)
            .unwrap_err();
    assert!(
        error.message.contains("acceptance allocation owner"),
        "{error:?}"
    );

    let mut chronology = original;
    let reference = chronology["operation_receipts"][5]["emission_references"]
        .as_array_mut()
        .unwrap()
        .remove(0);
    chronology["operation_receipts"][7]["emission_references"]
        .as_array_mut()
        .unwrap()
        .push(reference);
    reseal_checkpoint_digest(&mut chronology);
    let error =
        determa_state::checkpoint::restore(&serde_json::to_vec(&chronology).unwrap(), &resolver)
            .unwrap_err();
    assert!(
        error.message.contains("internal terminal reference"),
        "{error:?}"
    );
}

#[test]
fn tombstone_restore_checks_every_migration_audit_root() {
    let root = Path::new("conformance-suite/conformance/profiles/execution-checkpoint");
    let source = fs::read(
        root.join("checkpoint-07-complete-host-contract/bounded-tombstone-checkpoint-v1.json"),
    )
    .unwrap();
    let resolver = InMemoryDefinitionResolver::default();
    determa_state::checkpoint::restore(&source, &resolver).unwrap();
    let mut value: Value = serde_json::from_slice(&source).unwrap();
    let donor: Value = serde_json::from_slice(
        &fs::read(
            root.join("checkpoint-04-version1-mailboxes/maintenance-sequential-checkpoint-v1.json"),
        )
        .unwrap(),
    )
    .unwrap();
    value["migration_audit_records"]
        .as_array_mut()
        .unwrap()
        .push(donor["migration_audit_records"][0].clone());
    reseal_checkpoint_digest(&mut value);
    let error = determa_state::checkpoint::restore(&serde_json::to_vec(&value).unwrap(), &resolver)
        .unwrap_err();
    assert!(
        error.message.contains("migration audit identity"),
        "{error:?}"
    );

    let mut overlap: Value = serde_json::from_slice(&source).unwrap();
    let terminal_sequence = overlap["operation_receipts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|receipt| receipt["operation_kind"] == "event_terminal")
        .unwrap()["receipt_sequence"]
        .clone();
    overlap["event_identity_tombstones"][0]["terminal_receipt_sequence"] = terminal_sequence;
    reseal_checkpoint_digest(&mut overlap);
    let error =
        determa_state::checkpoint::restore(&serde_json::to_vec(&overlap).unwrap(), &resolver)
            .unwrap_err();
    assert!(
        error.message.contains("event tombstone identity"),
        "{error:?}"
    );
}

fn reseal_aggregate_digest(value: &mut Value) {
    let mut unsigned = value.clone();
    unsigned
        .as_object_mut()
        .unwrap()
        .remove("aggregate_state_digest");
    let bytes =
        serde_json_canonicalizer::to_vec(&json!(["determa-aggregate-state-digest-1", unsigned]))
            .unwrap();
    value["aggregate_state_digest"] = json!(format!("sha256:{:x}", Sha256::digest(bytes)));
}

fn reseal_checkpoint_digest(value: &mut Value) {
    let mut unsigned = value.clone();
    unsigned
        .as_object_mut()
        .unwrap()
        .remove("execution_checkpoint_digest");
    let bytes = serde_json_canonicalizer::to_vec(&json!([
        "determa-execution-checkpoint-digest-1",
        unsigned
    ]))
    .unwrap();
    value["execution_checkpoint_digest"] = json!(format!("sha256:{:x}", Sha256::digest(bytes)));
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_store_runs_the_native_v1_host_contract_and_survives_restart() {
    let directory = temporary_path("sqlite-native-v1");
    fs::create_dir_all(&directory).unwrap();
    let path = directory.join("checkpoints.sqlite3");
    let store: Arc<dyn ExecutionStore> =
        Arc::new(SqliteExecutionStore::open(&path, DurableStoreMode::bounded()).unwrap());
    store.initialize_schema().unwrap();
    native_v1_host_contract(store.clone());
    drop(store);
    let reopened = SqliteExecutionStore::open(&path, DurableStoreMode::bounded()).unwrap();
    assert!(reopened.load("server-1").unwrap().is_some());
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn memory_store_satisfies_compare_and_swap() {
    raw_store_contract(&MemoryExecutionStore::new(), "memory-cas");
}

#[test]
fn file_store_satisfies_compare_and_swap() {
    let directory = temporary_path("file-cas");
    let store = FileExecutionStore::new(&directory).unwrap();
    raw_store_contract(&store, "file-cas");
    fs::remove_dir_all(directory).unwrap();
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_store_satisfies_compare_and_swap() {
    let directory = temporary_path("sqlite-cas");
    fs::create_dir_all(&directory).unwrap();
    let store = SqliteExecutionStore::open(
        directory.join("checkpoints.sqlite3"),
        DurableStoreMode::bounded(),
    )
    .unwrap();
    raw_store_contract(&store, "sqlite-cas");
    fs::remove_dir_all(directory).unwrap();
}

fn native_v1_host_contract(store: Arc<dyn ExecutionStore>) {
    let core = Path::new("conformance-suite/conformance/core/117-version1-mailboxes");
    let bundle = load_bundle(&fs::read_to_string(core.join("machine.yaml")).unwrap()).unwrap();
    let outbox_bundle = load_bundle(
        r#"
format: 1
namespace: test.native_v1_adapter
events:
  published: { direction: output, payload: {} }
machines:
  - machine_id: publisher
    root:
      entry:
        - send: { event: published, to: { external: true }, correlation_id: '"created"' }
"#,
    )
    .unwrap();
    let terminal_bundle = load_bundle(
        r#"
format: 1
namespace: test.native_v1_terminal
machines:
  - machine_id: terminal
    root:
      variables:
        value: { type: int, init: 0 }
      entry:
        - assign: { value: "1 / 0" }
"#,
    )
    .unwrap();
    let mut resolver = InMemoryDefinitionResolver::default();
    resolver.insert(bundle.clone(), true);
    resolver.insert(outbox_bundle.clone(), true);
    resolver.insert(terminal_bundle.clone(), true);
    let host = CheckpointHost::new(store.clone(), Arc::new(resolver));
    let retention = json!({
        "mode": "bounded",
        "permanent_replay_eligible": false,
        "policy_identifier": "native-v1-test",
        "pruned_through_receipt_sequence": null
    });

    let mismatch = host
        .create_checkpoint(
            &bundle,
            "transaction_server",
            "digest-mismatch",
            "create-digest-mismatch",
            &Bindings::default(),
            Some("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            retention.clone(),
        )
        .unwrap_err();
    assert_eq!(mismatch.code, "invalid_execution_checkpoint");
    assert!(store.load("digest-mismatch").unwrap().is_none());

    let created_response = host
        .create_checkpoint(
            &bundle,
            "transaction_server",
            "server-1",
            "create-server-1",
            &Bindings::default(),
            None,
            retention.clone(),
        )
        .unwrap();
    assert_eq!(created_response["result"], "committed");
    assert_eq!(created_response["receipt"]["operation_kind"], "creation");
    let created = host.load_checkpoint("server-1").unwrap().unwrap();
    let inputs: Value =
        serde_json::from_slice(&fs::read(core.join("operation-inputs.json")).unwrap()).unwrap();
    let admitted = host
        .admit_checkpoint(
            "server-1",
            inputs["admit_two"]["deliveries"].as_array().unwrap(),
            &MutationGuard::new(created.revision(), created.digest()),
        )
        .unwrap();
    let admitted_checkpoint = &admitted["checkpoint"];
    let first_processing = processing_for(admitted_checkpoint);
    let stepped = host
        .step_checkpoint(
            "server-1",
            &first_processing,
            &MutationGuard::new(
                admitted_checkpoint["revision"].as_str().unwrap(),
                admitted_checkpoint["execution_checkpoint_digest"]
                    .as_str()
                    .unwrap(),
            ),
        )
        .unwrap();
    let second_processing = processing_for(&stepped);
    let stepped_again = host
        .step_checkpoint(
            "server-1",
            &second_processing,
            &MutationGuard::new(
                stepped["revision"].as_str().unwrap(),
                stepped["execution_checkpoint_digest"].as_str().unwrap(),
            ),
        )
        .unwrap();
    let pruned = host
        .prune_checkpoint(
            "server-1",
            &PruneRequest {
                cutoff_receipt_sequence: "4".to_string(),
                target_mode: "bounded".to_string(),
                policy_identifier: Some("native-v1-test".to_string()),
                dependency_receipt_sequences: Vec::new(),
                dependency_effect_ids: Vec::new(),
            },
            &MutationGuard::new(
                stepped_again["revision"].as_str().unwrap(),
                stepped_again["execution_checkpoint_digest"]
                    .as_str()
                    .unwrap(),
            ),
        )
        .unwrap();
    assert_eq!(
        pruned["replay_retention"]["pruned_through_receipt_sequence"],
        "4"
    );

    let maintenance = MaintenanceMigrationRequest {
        root_instance_id: "server-1".to_string(),
        operation_id: "native-v1-no-op".to_string(),
        source_aggregate_state_digest: pruned["root_record"]["aggregate_state"]
            ["aggregate_state_digest"]
            .as_str()
            .unwrap()
            .to_string(),
        target_validated_bundle_fingerprint: bundle.fingerprint.clone(),
        migration_descriptor_digest_route: Vec::new(),
        maintenance_mode: false,
        supplied_request_digest: None,
        guard: MutationGuard::new(
            pruned["revision"].as_str().unwrap(),
            pruned["execution_checkpoint_digest"].as_str().unwrap(),
        ),
        limits: ResourceLimits::default(),
    };
    let maintained = host.maintenance_migration(&maintenance).unwrap();
    assert_eq!(
        maintained["receipt"]["result_code"],
        "migration_no_operation"
    );
    assert_eq!(
        host.maintenance_migration(&maintenance).unwrap(),
        maintained
    );

    let transactional_created_response = host
        .create_checkpoint(
            &bundle,
            "transaction_server",
            "transactional-process-root",
            "create-transactional-process-root",
            &Bindings::default(),
            None,
            retention.clone(),
        )
        .unwrap();
    assert_eq!(transactional_created_response["result"], "committed");
    let transactional_created = host
        .load_checkpoint("transactional-process-root")
        .unwrap()
        .unwrap();
    let transactional = host
        .transactional_process(
            "transactional-process-root",
            &TransactionalProcessRequest {
                migration: MigrationRequest {
                    migration_route: Vec::new(),
                    target_validated_bundle_fingerprint: bundle.fingerprint.clone(),
                    maintenance_mode: false,
                },
                migration_limits: ResourceLimits::default(),
                delivery: input_delivery(&transactional_created, "transactional-event"),
                processing_mode: "delayed".to_string(),
            },
            &MutationGuard::new(
                transactional_created.revision(),
                transactional_created.digest(),
            ),
        )
        .unwrap();
    assert_eq!(transactional["revision"], "1");
    assert_eq!(transactional["migration_audit_records"], json!([]));
    let terminal_response = host
        .create_checkpoint(
            &terminal_bundle,
            "terminal",
            "terminal-root",
            "create-terminal",
            &Bindings::default(),
            None,
            retention.clone(),
        )
        .unwrap();
    assert_eq!(terminal_response["result"], "committed");
    let terminal = host.load_checkpoint("terminal-root").unwrap().unwrap();
    let tombstoned = host
        .tombstone_root(
            "terminal-root",
            "native-v1-tombstone",
            &MutationGuard::new(terminal.revision(), terminal.digest()),
        )
        .unwrap();
    assert_eq!(tombstoned["result"], "tombstoned");
    assert_eq!(tombstoned["tombstone"]["status"], "tombstone");

    let outbox_response = host
        .create_checkpoint(
            &outbox_bundle,
            "publisher",
            "outbox-root",
            "create-outbox",
            &Bindings::default(),
            None,
            retention,
        )
        .unwrap();
    assert_eq!(outbox_response["result"], "committed");
    let outbox = host.load_checkpoint("outbox-root").unwrap().unwrap();
    let effect_id = outbox.value()["pending_outbox_intents"][0]["intent"]["effect_id"]
        .as_str()
        .unwrap();
    let pending = host
        .update_pending_outbox(
            "outbox-root",
            effect_id,
            PendingOutboxState::RetryableFailure {
                reason_code: "retry".to_string(),
            },
            &MutationGuard::new(outbox.revision(), outbox.digest()),
        )
        .unwrap();
    assert_eq!(pending["result"], "committed");
    assert_eq!(pending["record"]["intent"]["effect_id"], effect_id);
    let pending_checkpoint = host.load_checkpoint("outbox-root").unwrap().unwrap();
    let terminal = host
        .terminalize_outbox(
            "outbox-root",
            effect_id,
            TerminalOutboxOutcome::Confirmed,
            &MutationGuard::new(pending_checkpoint.revision(), pending_checkpoint.digest()),
        )
        .unwrap();
    assert_eq!(terminal["result"], "committed");
    let terminal_checkpoint = host.load_checkpoint("outbox-root").unwrap().unwrap();
    let compacted = host
        .compact_outbox(
            "outbox-root",
            effect_id,
            &MutationGuard::new(terminal_checkpoint.revision(), terminal_checkpoint.digest()),
        )
        .unwrap();
    assert_eq!(compacted["record"]["effect_id"], effect_id);
}

fn input_delivery(
    checkpoint: &determa_state::checkpoint::ExecutionCheckpoint,
    event_id: &str,
) -> Value {
    named_input_delivery(checkpoint.value(), "received", event_id)
}

fn named_input_delivery(checkpoint: &Value, event: &str, event_id: &str) -> Value {
    let envelope = json!({
        "event": event,
        "event_id": event_id,
        "cause_id": event_id,
        "source": {"host": true},
        "target": checkpoint["root_record"]["aggregate_state"]["runtimes"][0]
            ["target_identity"],
        "payload": ["map", []]
    });
    let bytes = serde_json_canonicalizer::to_vec(&json!([
        "determa-inbox-envelope-digest-1",
        "1",
        checkpoint["root_instance_id"],
        "input",
        envelope
    ]))
    .unwrap();
    json!({
        "delivery_mode": "input",
        "envelope": envelope,
        "envelope_digest": format!("sha256:{:x}", Sha256::digest(bytes))
    })
}

fn processing_for(checkpoint: &Value) -> ProcessingRequest {
    let runtime = checkpoint["root_record"]["aggregate_state"]["runtimes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|runtime| !runtime["ready_mailbox"].as_array().unwrap().is_empty())
        .unwrap();
    let entry = &runtime["ready_mailbox"][0];
    ProcessingRequest {
        target_runtime_id: runtime["runtime_id"].as_str().unwrap().to_string(),
        event_id: entry["envelope"]["event_id"].as_str().unwrap().to_string(),
        envelope_digest: entry["envelope_digest"].as_str().unwrap().to_string(),
        acceptance_sequence: entry["acceptance_sequence"].as_str().unwrap().to_string(),
        queue_sequence: entry["queue_sequence"].as_str().unwrap().to_string(),
        processing_mode: "delayed".to_string(),
    }
}

fn raw_store_contract(store: &dyn ExecutionStore, root: &str) {
    store.initialize_schema().unwrap();
    let initial = record(root, "0", 'a');
    assert_eq!(
        store.insert_if_absent(initial.clone()).unwrap(),
        StoreWriteResult::Committed
    );
    assert!(matches!(
        store.insert_if_absent(initial.clone()).unwrap(),
        StoreWriteResult::Conflict(Some(_))
    ));
    let replacement = record(root, "1", 'b');
    assert_eq!(
        store
            .compare_and_swap(
                root,
                &initial.revision,
                &initial.execution_checkpoint_digest,
                replacement.clone(),
            )
            .unwrap(),
        StoreWriteResult::Committed
    );
    assert_eq!(store.load(root).unwrap().unwrap(), replacement);
}

fn record(root: &str, revision: &str, marker: char) -> StoreRecord {
    let digest = format!("sha256:{}", marker.to_string().repeat(64));
    StoreRecord {
        root_instance_id: root.to_string(),
        revision: revision.to_string(),
        execution_checkpoint_digest: digest.clone(),
        bytes: serde_json_canonicalizer::to_vec(&json!({
            "root_instance_id": root,
            "revision": revision,
            "execution_checkpoint_digest": digest
        }))
        .unwrap(),
    }
}

fn temporary_path(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("determa-{label}-{}-{nonce}", std::process::id()))
}
