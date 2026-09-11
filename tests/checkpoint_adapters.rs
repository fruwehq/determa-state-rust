use determa_state::checkpoint::{
    CheckpointHost, ExecutionStore, FileExecutionStore, MaintenanceMigrationRequest,
    MemoryExecutionStore, MutationGuard, PendingOutboxState, StoreRecord, StoreWriteResult,
    TerminalOutboxOutcome,
};
#[cfg(feature = "sqlite")]
use determa_state::checkpoint::{DurableStoreMode, SqliteExecutionStore};
use determa_state::{load_bundle, Bindings, InMemoryDefinitionResolver, ResourceLimits};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn memory_store_runs_the_native_v2_host_contract() {
    let store: Arc<dyn ExecutionStore> = Arc::new(MemoryExecutionStore::new());
    store.initialize_schema().unwrap();
    native_v2_host_contract(store);
}

#[test]
fn file_store_runs_the_native_v2_host_contract_and_survives_restart() {
    let directory = temporary_path("file-native-v2");
    let store: Arc<dyn ExecutionStore> = Arc::new(FileExecutionStore::new(&directory).unwrap());
    store.initialize_schema().unwrap();
    native_v2_host_contract(store.clone());
    drop(store);
    let reopened = FileExecutionStore::new(&directory).unwrap();
    assert!(reopened.load("server-1").unwrap().is_some());
    fs::remove_dir_all(directory).unwrap();
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_store_runs_the_native_v2_host_contract_and_survives_restart() {
    let directory = temporary_path("sqlite-native-v2");
    fs::create_dir_all(&directory).unwrap();
    let path = directory.join("checkpoints.sqlite3");
    let store: Arc<dyn ExecutionStore> =
        Arc::new(SqliteExecutionStore::open(&path, DurableStoreMode::bounded()).unwrap());
    store.initialize_schema().unwrap();
    native_v2_host_contract(store.clone());
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

fn native_v2_host_contract(store: Arc<dyn ExecutionStore>) {
    let core = Path::new("conformance-suite/conformance/core/117-version2-mailboxes");
    let bundle = load_bundle(&fs::read_to_string(core.join("machine.yaml")).unwrap()).unwrap();
    let outbox_bundle = load_bundle(
        r#"
format: 1
namespace: test.native_v2_adapter
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
namespace: test.native_v2_terminal
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
        "policy_identifier": "native-v2-test",
        "pruned_through_receipt_sequence": null
    });

    let mismatch = host
        .create_checkpoint_v2(
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

    let created = host
        .create_checkpoint_v2(
            &bundle,
            "transaction_server",
            "server-1",
            "create-server-1",
            &Bindings::default(),
            None,
            retention.clone(),
        )
        .unwrap();
    let inputs: Value =
        serde_json::from_slice(&fs::read(core.join("operation-inputs.json")).unwrap()).unwrap();
    let admitted = host
        .admit_checkpoint_v2(
            "server-1",
            inputs["admit_two"]["deliveries"].as_array().unwrap(),
            &MutationGuard::new(created.revision(), created.digest()),
        )
        .unwrap();
    let admitted_checkpoint = &admitted["checkpoint"];
    let root_runtime_id = admitted_checkpoint["root_record"]["aggregate_state"]["root_runtime_id"]
        .as_str()
        .unwrap();
    let stepped = host
        .step_checkpoint_v2(
            "server-1",
            root_runtime_id,
            &MutationGuard::new(
                admitted_checkpoint["revision"].as_str().unwrap(),
                admitted_checkpoint["execution_checkpoint_digest"]
                    .as_str()
                    .unwrap(),
            ),
        )
        .unwrap();
    let stepped_again = host
        .step_checkpoint_v2(
            "server-1",
            root_runtime_id,
            &MutationGuard::new(
                stepped["revision"].as_str().unwrap(),
                stepped["execution_checkpoint_digest"].as_str().unwrap(),
            ),
        )
        .unwrap();
    let pruned = host
        .prune_checkpoint_v2(
            "server-1",
            "4",
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
        operation_id: "native-v2-no-op".to_string(),
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
    let maintained = host.maintenance_migration_v2(&maintenance).unwrap();
    assert_eq!(
        maintained["receipt"]["result_code"],
        "migration_no_operation"
    );
    assert_eq!(
        host.maintenance_migration_v2(&maintenance).unwrap(),
        maintained
    );
    let terminal = host
        .create_checkpoint_v2(
            &terminal_bundle,
            "terminal",
            "terminal-root",
            "create-terminal",
            &Bindings::default(),
            None,
            retention.clone(),
        )
        .unwrap();
    let tombstoned = host
        .tombstone_root_v2(
            "terminal-root",
            "native-v2-tombstone",
            &MutationGuard::new(terminal.revision(), terminal.digest()),
        )
        .unwrap();
    assert_eq!(tombstoned["root_record"]["status"], "tombstone");

    let outbox = host
        .create_checkpoint_v2(
            &outbox_bundle,
            "publisher",
            "outbox-root",
            "create-outbox",
            &Bindings::default(),
            None,
            retention,
        )
        .unwrap();
    let effect_id = outbox.value()["pending_outbox_intents"][0]["intent"]["effect_id"]
        .as_str()
        .unwrap();
    let pending = host
        .update_pending_outbox_v2(
            "outbox-root",
            effect_id,
            PendingOutboxState::RetryableFailure {
                reason_code: "retry".to_string(),
            },
            &MutationGuard::new(outbox.revision(), outbox.digest()),
        )
        .unwrap();
    let terminal = host
        .terminalize_outbox_v2(
            "outbox-root",
            effect_id,
            TerminalOutboxOutcome::Confirmed,
            &guard_for(&pending),
        )
        .unwrap();
    let compacted = host
        .compact_outbox_v2("outbox-root", effect_id, &guard_for(&terminal))
        .unwrap();
    assert_eq!(
        compacted["outbox_effect_tombstones"][0]["effect_id"],
        effect_id
    );
}

fn guard_for(value: &Value) -> MutationGuard {
    MutationGuard::new(
        value["revision"].as_str().unwrap(),
        value["execution_checkpoint_digest"].as_str().unwrap(),
    )
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
