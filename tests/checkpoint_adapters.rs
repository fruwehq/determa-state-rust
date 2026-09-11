#[cfg(feature = "sqlite")]
use determa_state::checkpoint::SqliteExecutionStore;
use determa_state::checkpoint::{
    register_bundled_adapters, AdapterRegistry, CheckpointHost, ExecutionCheckpoint,
    ExecutionStore, ExecutionStoreCapability, FileExecutionStore, MaintenanceMigrationRequest,
    MemoryExecutionStore, MutationGuard, PendingOutboxState, StoreRecord, StoreWriteResult,
    TerminalOutboxOutcome,
};
#[cfg(feature = "sqlite")]
use determa_state::checkpoint::{
    DurableStoreMode, HostFeature, HostProfile, OutboxRetentionMode, ReceiptRetentionMode,
};
use determa_state::{load_bundle, Bindings, InMemoryDefinitionResolver, ResourceLimits};
#[cfg(feature = "sqlite")]
use rusqlite::Connection;
use serde_json::json;
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

const CHECKPOINT_PROFILE: &str = "conformance-suite/conformance/profiles/execution-checkpoint";

#[test]
fn memory_store_runs_version2_host_upgrade_and_step_transactionally() {
    let store: Arc<dyn ExecutionStore> = Arc::new(MemoryExecutionStore::new());
    store.initialize_schema().expect("memory initialization");
    version2_host_contract(store);
}

#[test]
fn file_store_runs_version2_host_upgrade_and_step_transactionally() {
    let directory = temporary_path("file-v2-host");
    let store: Arc<dyn ExecutionStore> =
        Arc::new(FileExecutionStore::new(&directory).expect("file store"));
    store.initialize_schema().expect("file schema");
    version2_host_contract(store);
    fs::remove_dir_all(directory).expect("remove temporary file store");
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_store_runs_version2_host_upgrade_and_step_transactionally() {
    let directory = temporary_path("sqlite-v2-host");
    fs::create_dir_all(&directory).expect("SQLite temporary directory");
    let path = directory.join("checkpoints.sqlite3");
    let store: Arc<dyn ExecutionStore> = Arc::new(
        SqliteExecutionStore::open(&path, DurableStoreMode::bounded()).expect("SQLite store"),
    );
    store.initialize_schema().expect("SQLite schema");
    version2_host_contract(store);
    fs::remove_dir_all(directory).expect("remove temporary SQLite store");
}

#[test]
fn memory_store_satisfies_the_shared_cas_contract() {
    let store = MemoryExecutionStore::new();
    store.initialize_schema().expect("memory initialization");
    shared_store_contract(&store, "memory-root");
    assert_eq!(
        store.capabilities(),
        BTreeSet::from([ExecutionStoreCapability::Ephemeral])
    );
}

#[test]
fn file_store_requires_explicit_setup_and_survives_restart() {
    let directory = temporary_path("file-store");
    let store = FileExecutionStore::new(&directory).expect("file store");
    assert!(store.health().is_err());
    store.initialize_schema().expect("file schema");
    shared_store_contract(&store, "file-root");
    drop(store);

    let reopened = FileExecutionStore::new(&directory).expect("reopened file store");
    assert_eq!(
        reopened
            .load("file-root")
            .expect("restart load")
            .expect("persisted record")
            .revision,
        "1"
    );
    assert_eq!(
        reopened.capabilities(),
        BTreeSet::from([ExecutionStoreCapability::RestartPersistent])
    );
    fs::remove_dir_all(directory).expect("remove temporary file store");
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_store_requires_explicit_setup_and_satisfies_the_shared_contract() {
    let directory = temporary_path("sqlite-store");
    fs::create_dir_all(&directory).expect("SQLite temporary directory");
    let path = directory.join("checkpoints.sqlite3");
    let store =
        SqliteExecutionStore::open(&path, DurableStoreMode::bounded()).expect("SQLite store");
    assert!(store.health().is_err());
    store.initialize_schema().expect("SQLite schema");
    shared_store_contract(&store, "sqlite-root");
    drop(store);

    let reopened = SqliteExecutionStore::open(&path, DurableStoreMode::bounded())
        .expect("reopened SQLite store");
    assert_eq!(
        reopened
            .load("sqlite-root")
            .expect("restart load")
            .expect("persisted record")
            .revision,
        "1"
    );
    assert_eq!(
        reopened.capabilities(),
        BTreeSet::from([
            ExecutionStoreCapability::DurableSingleWriter,
            ExecutionStoreCapability::RootIdentityRetention,
        ])
    );
    let raw = rusqlite::Connection::open(&path).expect("raw SQLite connection");
    assert!(
        raw.execute(
            "DELETE FROM determa_execution_checkpoints WHERE root_instance_id = ?1",
            ["sqlite-root"]
        )
        .is_err(),
        "schema trigger must reject physical root deletion"
    );
    raw.execute_batch("DROP TRIGGER determa_execution_checkpoints_no_delete")
        .expect("drop test trigger");
    drop(raw);
    assert!(
        reopened.health().is_err(),
        "health must reject a missing deletion guard"
    );
    drop(reopened);
    fs::remove_dir_all(directory).expect("remove temporary SQLite store");
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_factory_modes_derive_real_profile_capabilities() {
    let directory = temporary_path("sqlite-policy-capabilities");
    fs::create_dir_all(&directory).expect("SQLite temporary directory");
    let strict_path = directory.join("strict.sqlite3");
    let compact_path = directory.join("compact.sqlite3");
    let registry = AdapterRegistry::new();
    register_bundled_adapters(&registry).expect("register bundled adapters");

    let strict_configuration = format!(
        "sqlite:{}#receipt_retention=permanent&outbox_retention=strict",
        strict_path.display()
    );
    let strict = registry
        .resolve(
            &strict_configuration,
            &BTreeSet::from([
                ExecutionStoreCapability::DurableSingleWriter,
                ExecutionStoreCapability::RootIdentityRetention,
                ExecutionStoreCapability::PermanentReceiptRetention,
                ExecutionStoreCapability::PermanentOutboxTerminalRetention,
            ]),
        )
        .expect("strict configured SQLite store");
    strict.initialize_schema().expect("strict SQLite schema");
    strict.health().expect("strict SQLite health");
    let strict_host = CheckpointHost::new(strict, Arc::new(InMemoryDefinitionResolver::default()));
    assert!(strict_host
        .validate_profile(
            HostProfile::ExactlyOnceCommittedProcessing,
            &BTreeSet::from([HostFeature::AtomicCheckpointProcessing]),
            true,
        )
        .is_ok());
    assert!(strict_host
        .validate_profile(
            HostProfile::ExactlyOnceCommittedProcessing,
            &BTreeSet::from([HostFeature::AtomicCheckpointProcessing]),
            false,
        )
        .is_err());
    assert!(strict_host
        .validate_profile(
            HostProfile::StrictDurableOutbox,
            &BTreeSet::from([
                HostFeature::AtomicCheckpointProcessing,
                HostFeature::OutboxWorker,
                HostFeature::TotalOutboxLifecycle,
                HostFeature::RetainUnresolvedOutbox,
            ]),
            true,
        )
        .is_ok());

    let compact_configuration = format!(
        "sqlite:{}#receipt_retention=bounded&outbox_retention=compact",
        compact_path.display()
    );
    let compact = registry
        .resolve(
            &compact_configuration,
            &BTreeSet::from([
                ExecutionStoreCapability::DurableSingleWriter,
                ExecutionStoreCapability::RootIdentityRetention,
                ExecutionStoreCapability::CompactEffectIdentityRetention,
            ]),
        )
        .expect("compact configured SQLite store");
    compact.initialize_schema().expect("compact SQLite schema");
    let compact_host =
        CheckpointHost::new(compact, Arc::new(InMemoryDefinitionResolver::default()));
    assert!(compact_host
        .validate_profile(
            HostProfile::CompactDurableOutbox,
            &BTreeSet::from([
                HostFeature::AtomicCheckpointProcessing,
                HostFeature::OutboxWorker,
                HostFeature::TotalOutboxLifecycle,
                HostFeature::RetainReferencedEffectTombstones,
            ]),
            false,
        )
        .is_ok());

    assert!(registry
        .resolve(
            &format!("sqlite:{}", directory.join("missing.sqlite3").display()),
            &BTreeSet::new(),
        )
        .is_err());
    fs::remove_dir_all(directory).expect("remove temporary SQLite stores");
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_schema_mode_and_policy_transitions_are_enforced() {
    let directory = temporary_path("sqlite-policy-enforcement");
    fs::create_dir_all(&directory).expect("SQLite temporary directory");
    let strict_path = directory.join("strict.sqlite3");
    let strict_mode =
        DurableStoreMode::new(ReceiptRetentionMode::Permanent, OutboxRetentionMode::Strict);
    let strict =
        SqliteExecutionStore::open(&strict_path, strict_mode).expect("strict SQLite store");
    strict.initialize_schema().expect("strict SQLite schema");
    let before = fixture_record("checkpoint-02-outbox-lifecycle/outbox-total-checkpoint.json");
    let compacted = fixture_record("checkpoint-02-outbox-lifecycle/outbox-compact-checkpoint.json");
    assert_eq!(
        strict
            .insert_if_absent(before.clone())
            .expect("strict seed"),
        StoreWriteResult::Committed
    );
    assert!(strict
        .compare_and_swap(
            &before.root_instance_id,
            &before.revision,
            &before.execution_checkpoint_digest,
            compacted.clone(),
        )
        .is_err());

    let mut pruned_checkpoint: ExecutionCheckpoint =
        serde_json::from_slice(&before.bytes).expect("checkpoint fixture");
    pruned_checkpoint.operation_receipts.pop();
    pruned_checkpoint.increment_revision();
    pruned_checkpoint
        .recompute_digest()
        .expect("pruned checkpoint digest");
    let pruned = StoreRecord::from_checkpoint(&pruned_checkpoint).expect("pruned record");
    assert!(strict
        .compare_and_swap(
            &before.root_instance_id,
            &before.revision,
            &before.execution_checkpoint_digest,
            pruned,
        )
        .is_err());

    let mismatched = SqliteExecutionStore::open(
        &strict_path,
        DurableStoreMode::new(ReceiptRetentionMode::Bounded, OutboxRetentionMode::Compact),
    )
    .expect("mismatched SQLite store");
    assert!(mismatched.health().is_err());
    assert!(mismatched.initialize_schema().is_err());

    let compact_path = directory.join("compact.sqlite3");
    let compact_store = SqliteExecutionStore::open(
        &compact_path,
        DurableStoreMode::new(
            ReceiptRetentionMode::Permanent,
            OutboxRetentionMode::Compact,
        ),
    )
    .expect("compact SQLite store");
    compact_store
        .initialize_schema()
        .expect("compact SQLite schema");
    assert_eq!(
        compact_store
            .insert_if_absent(before.clone())
            .expect("compact seed"),
        StoreWriteResult::Committed
    );
    assert_eq!(
        compact_store
            .compare_and_swap(
                &before.root_instance_id,
                &before.revision,
                &before.execution_checkpoint_digest,
                compacted.clone(),
            )
            .expect("valid compaction"),
        StoreWriteResult::Committed
    );
    let mut deleted_checkpoint: ExecutionCheckpoint =
        serde_json::from_slice(&compacted.bytes).expect("compacted checkpoint fixture");
    deleted_checkpoint.outbox_effect_tombstones.clear();
    deleted_checkpoint.increment_revision();
    deleted_checkpoint
        .recompute_digest()
        .expect("deleted tombstone digest");
    let deleted = StoreRecord::from_checkpoint(&deleted_checkpoint).expect("deleted record");
    assert!(compact_store
        .compare_and_swap(
            &compacted.root_instance_id,
            &compacted.revision,
            &compacted.execution_checkpoint_digest,
            deleted,
        )
        .is_err());

    let malformed_path = directory.join("malformed.sqlite3");
    let malformed_connection = Connection::open(&malformed_path).expect("malformed SQLite file");
    malformed_connection
        .execute_batch(
            "
            CREATE TABLE determa_execution_store_metadata (
                singleton INTEGER,
                schema_version INTEGER,
                receipt_retention TEXT,
                outbox_retention TEXT
            );
            INSERT INTO determa_execution_store_metadata
                (singleton, schema_version, receipt_retention, outbox_retention)
            VALUES (1, 1, 'permanent', 'strict');
            CREATE TABLE determa_execution_checkpoints (
                root_instance_id TEXT,
                revision TEXT,
                checkpoint_digest TEXT,
                checkpoint_bytes BLOB
            );
            ",
        )
        .expect("lookalike SQLite schema");
    drop(malformed_connection);
    let malformed =
        SqliteExecutionStore::open(&malformed_path, strict_mode).expect("malformed SQLite store");
    assert!(malformed.initialize_schema().is_err());
    assert!(malformed.health().is_err());

    fs::remove_dir_all(directory).expect("remove temporary SQLite stores");
}

#[test]
fn memory_compare_and_swap_has_one_concurrent_winner() {
    let store: Arc<dyn ExecutionStore> = Arc::new(MemoryExecutionStore::new());
    concurrent_cas_contract(store, "memory-concurrent");
}

#[test]
fn file_compare_and_swap_has_one_concurrent_winner() {
    let directory = temporary_path("file-concurrent");
    let first = Arc::new(FileExecutionStore::new(&directory).expect("first file store"));
    first.initialize_schema().expect("file schema");
    let second = Arc::new(FileExecutionStore::new(&directory).expect("second file store"));
    concurrent_cas_contract_with_stores(first, second, "file-concurrent");
    fs::remove_dir_all(directory).expect("remove temporary file store");
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_compare_and_swap_has_one_concurrent_winner() {
    let directory = temporary_path("sqlite-concurrent");
    fs::create_dir_all(&directory).expect("SQLite temporary directory");
    let path = directory.join("checkpoints.sqlite3");
    let first = Arc::new(
        SqliteExecutionStore::open(&path, DurableStoreMode::bounded()).expect("first SQLite store"),
    );
    first.initialize_schema().expect("SQLite schema");
    let second = Arc::new(
        SqliteExecutionStore::open(&path, DurableStoreMode::bounded())
            .expect("second SQLite store"),
    );
    concurrent_cas_contract_with_stores(first, second, "sqlite-concurrent");
    fs::remove_dir_all(directory).expect("remove temporary SQLite store");
}

#[test]
fn bundled_adapters_use_an_initially_empty_public_registry() {
    let registry = AdapterRegistry::new();
    assert!(registry.identifiers().expect("empty registry").is_empty());
    register_bundled_adapters(&registry).expect("register bundled adapters");
    let identifiers = registry.identifiers().expect("registered identifiers");
    assert!(identifiers.contains(&"memory".to_string()));
    assert!(identifiers.contains(&"file".to_string()));
    #[cfg(feature = "sqlite")]
    assert!(identifiers.contains(&"sqlite".to_string()));
    #[cfg(feature = "postgresql")]
    assert!(identifiers.contains(&"postgresql".to_string()));
    assert!(register_bundled_adapters(&registry).is_err());
}

fn shared_store_contract(store: &dyn ExecutionStore, root_instance_id: &str) {
    let initial = record(root_instance_id, "0", '0');
    assert_eq!(
        store
            .insert_if_absent(initial.clone())
            .expect("initial insert"),
        StoreWriteResult::Committed
    );
    assert_eq!(
        store
            .insert_if_absent(initial.clone())
            .expect("duplicate insert"),
        StoreWriteResult::Conflict(Some(initial.clone()))
    );
    assert_eq!(
        store.load(root_instance_id).expect("load initial"),
        Some(initial.clone())
    );
    assert!(matches!(
        store
            .compare_and_swap(
                root_instance_id,
                "9",
                &initial.execution_checkpoint_digest,
                record(root_instance_id, "1", '1')
            )
            .expect("stale CAS"),
        StoreWriteResult::Conflict(Some(_))
    ));
    let replacement = record(root_instance_id, "1", '1');
    assert_eq!(
        store
            .compare_and_swap(
                root_instance_id,
                "0",
                &initial.execution_checkpoint_digest,
                replacement.clone()
            )
            .expect("successful CAS"),
        StoreWriteResult::Committed
    );
    assert_eq!(
        store.load(root_instance_id).expect("load replacement"),
        Some(replacement)
    );
    assert!(store.health().expect("store health").healthy);
}

fn concurrent_cas_contract(store: Arc<dyn ExecutionStore>, root_instance_id: &str) {
    concurrent_cas_contract_with_stores(store.clone(), store, root_instance_id);
}

fn concurrent_cas_contract_with_stores(
    first: Arc<dyn ExecutionStore>,
    second: Arc<dyn ExecutionStore>,
    root_instance_id: &str,
) {
    first.initialize_schema().expect("store initialization");
    let initial = record(root_instance_id, "0", '0');
    assert_eq!(
        first
            .insert_if_absent(initial.clone())
            .expect("concurrent seed"),
        StoreWriteResult::Committed
    );
    let barrier = Arc::new(Barrier::new(3));
    let root = root_instance_id.to_string();
    let workers = [(first, '1'), (second, '2')]
        .into_iter()
        .map(|(store, marker)| {
            let barrier = barrier.clone();
            let root = root.clone();
            let digest = initial.execution_checkpoint_digest.clone();
            thread::spawn(move || {
                barrier.wait();
                store
                    .compare_and_swap(&root, "0", &digest, record(&root, "1", marker))
                    .expect("concurrent CAS")
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();
    let results = workers
        .into_iter()
        .map(|worker| worker.join().expect("CAS worker"))
        .collect::<Vec<_>>();
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == StoreWriteResult::Committed)
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, StoreWriteResult::Conflict(Some(_))))
            .count(),
        1
    );
}

fn version2_host_contract(store: Arc<dyn ExecutionStore>) {
    let relative = "checkpoint-04-version2-mailboxes/base-checkpoint-v1.json";
    let bytes = fs::read(PathBuf::from(CHECKPOINT_PROFILE).join(relative))
        .expect("version-1 checkpoint fixture");
    let checkpoint: ExecutionCheckpoint =
        serde_json::from_slice(&bytes).expect("typed checkpoint fixture");
    let record = StoreRecord::from_checkpoint(&checkpoint).expect("fixture store record");
    assert_eq!(
        store
            .insert_if_absent(record.clone())
            .expect("version-1 seed"),
        StoreWriteResult::Committed
    );

    let bundle = load_bundle(
        &fs::read_to_string(
            PathBuf::from(CHECKPOINT_PROFILE).join("checkpoint-04-version2-mailboxes/machine.yaml"),
        )
        .expect("version-2 bundle fixture"),
    )
    .expect("version-2 bundle");
    let mut resolver = InMemoryDefinitionResolver::default();
    resolver.insert(bundle.clone(), true);
    let outbox_bundle = load_bundle(
        &fs::read_to_string(
            PathBuf::from(CHECKPOINT_PROFILE)
                .join("checkpoint-04-version2-mailboxes/creation-owned-work-machine.yaml"),
        )
        .expect("version-2 creation outbox bundle fixture"),
    )
    .expect("version-2 creation outbox bundle");
    resolver.insert(outbox_bundle.clone(), true);
    let migration_directory =
        PathBuf::from("conformance-suite/conformance/core/118-version2-persistence");
    let migration_source = load_bundle(
        &fs::read_to_string(migration_directory.join("machine.yaml"))
            .expect("v2 migration source bundle"),
    )
    .expect("load v2 migration source bundle");
    let migration_target = load_bundle(
        &fs::read_to_string(migration_directory.join("target-compatible.yaml"))
            .expect("v2 migration target bundle"),
    )
    .expect("load v2 migration target bundle");
    let migration_target_second = load_bundle(
        &fs::read_to_string(migration_directory.join("target-compatible-second.yaml"))
            .expect("v2 second migration target bundle"),
    )
    .expect("load v2 second migration target bundle");
    let descriptor_bytes = fs::read(migration_directory.join("descriptor-compatible-v2.json"))
        .expect("v2 migration descriptor");
    let descriptor: serde_json::Value = serde_json::from_slice(&descriptor_bytes).unwrap();
    let descriptor_digest = descriptor["migration_descriptor_digest"]
        .as_str()
        .unwrap()
        .to_string();
    let descriptor_second_bytes =
        fs::read(migration_directory.join("descriptor-compatible-second-v2.json"))
            .expect("v2 second migration descriptor");
    let descriptor_second: serde_json::Value =
        serde_json::from_slice(&descriptor_second_bytes).unwrap();
    let descriptor_second_digest = descriptor_second["migration_descriptor_digest"]
        .as_str()
        .unwrap()
        .to_string();
    resolver.insert(migration_source.clone(), true);
    resolver.insert(migration_target.clone(), true);
    resolver.insert(migration_target_second.clone(), true);
    resolver.insert_descriptor(descriptor_digest.clone(), descriptor_bytes, true);
    resolver.insert_descriptor(
        descriptor_second_digest.clone(),
        descriptor_second_bytes,
        true,
    );
    let terminal_bundle = load_bundle(
        r#"
format: 1
namespace: test.v2_terminal
machines:
  - machine_id: terminal
    root:
      variables:
        value: { type: int, init: 0 }
      entry:
        - assign: { value: "1 / 0" }
"#,
    )
    .expect("load v2 terminal bundle");
    resolver.insert(terminal_bundle.clone(), true);
    let host = CheckpointHost::new(store.clone(), Arc::new(resolver));
    let mismatch = host
        .create_checkpoint_v2(
            &bundle,
            "counter",
            "fresh-v2-root",
            "fresh-v2-create",
            &Bindings::default(),
            Some("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            json!({
                "mode": "permanent",
                "permanent_replay_eligible": true,
                "policy_identifier": null,
                "pruned_through_receipt_sequence": null
            }),
        )
        .unwrap_err();
    assert_eq!(mismatch.code, "invalid_execution_checkpoint");
    assert!(store.load("fresh-v2-root").unwrap().is_none());
    let created = host
        .create_checkpoint_v2(
            &bundle,
            "counter",
            "fresh-v2-root",
            "fresh-v2-create",
            &Bindings::default(),
            None,
            json!({
                "mode": "permanent",
                "permanent_replay_eligible": true,
                "policy_identifier": null,
                "pruned_through_receipt_sequence": null
            }),
        )
        .expect("transactional version-2 creation");
    assert_eq!(created.revision(), "0");
    let no_op = host
        .maintenance_migration_v2(&MaintenanceMigrationRequest {
            root_instance_id: created.root_instance_id().to_string(),
            operation_id: "empty-route".to_string(),
            source_aggregate_state_digest: created.value()["root_record"]["aggregate_state"]
                ["aggregate_state_digest"]
                .as_str()
                .unwrap()
                .to_string(),
            target_validated_bundle_fingerprint: bundle.fingerprint.clone(),
            migration_descriptor_digest_route: Vec::new(),
            maintenance_mode: true,
            supplied_request_digest: None,
            guard: MutationGuard::new(created.revision(), created.digest()),
            limits: ResourceLimits::default(),
        })
        .expect("transactional v2 empty-route migration");
    assert_eq!(no_op, *created.value());
    assert!(no_op["migration_audit_records"]
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(
        host.load_checkpoint_v2(created.root_instance_id())
            .unwrap()
            .unwrap()
            .value(),
        created.value()
    );

    let migration = host
        .create_checkpoint_v2(
            &migration_source,
            "transaction_server",
            "migration-v2-root",
            "migration-v2-create",
            &Bindings::default(),
            None,
            json!({
                "mode": "permanent",
                "permanent_replay_eligible": true,
                "policy_identifier": null,
                "pruned_through_receipt_sequence": null
            }),
        )
        .expect("transactional v2 migration source creation");
    let failed = host
        .maintenance_migration_v2(&MaintenanceMigrationRequest {
            root_instance_id: migration.root_instance_id().to_string(),
            operation_id: "failed-migration-operation".to_string(),
            source_aggregate_state_digest: migration.value()["root_record"]["aggregate_state"]
                ["aggregate_state_digest"]
                .as_str()
                .unwrap()
                .to_string(),
            target_validated_bundle_fingerprint: migration_target_second.fingerprint.clone(),
            migration_descriptor_digest_route: vec![
                descriptor_digest.clone(),
                "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                    .to_string(),
            ],
            maintenance_mode: true,
            supplied_request_digest: None,
            guard: MutationGuard::new(migration.revision(), migration.digest()),
            limits: ResourceLimits::default(),
        })
        .unwrap_err();
    assert_eq!(failed.code, "migration_descriptor_not_found");
    assert_eq!(
        host.load_checkpoint_v2(migration.root_instance_id())
            .unwrap()
            .unwrap()
            .value(),
        migration.value()
    );
    let digest_mismatch = host
        .maintenance_migration_v2(&MaintenanceMigrationRequest {
            root_instance_id: migration.root_instance_id().to_string(),
            operation_id: "migration-operation".to_string(),
            source_aggregate_state_digest: migration.value()["root_record"]["aggregate_state"]
                ["aggregate_state_digest"]
                .as_str()
                .unwrap()
                .to_string(),
            target_validated_bundle_fingerprint: migration_target_second.fingerprint.clone(),
            migration_descriptor_digest_route: vec![
                descriptor_digest.clone(),
                descriptor_second_digest.clone(),
            ],
            maintenance_mode: true,
            supplied_request_digest: Some(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
            ),
            guard: MutationGuard::new(migration.revision(), migration.digest()),
            limits: ResourceLimits::default(),
        })
        .unwrap_err();
    assert_eq!(digest_mismatch.code, "invalid_execution_checkpoint");
    assert_eq!(
        host.load_checkpoint_v2(migration.root_instance_id())
            .unwrap()
            .unwrap()
            .value(),
        migration.value()
    );
    let migrated = host
        .maintenance_migration_v2(&MaintenanceMigrationRequest {
            root_instance_id: migration.root_instance_id().to_string(),
            operation_id: "migration-operation".to_string(),
            source_aggregate_state_digest: migration.value()["root_record"]["aggregate_state"]
                ["aggregate_state_digest"]
                .as_str()
                .unwrap()
                .to_string(),
            target_validated_bundle_fingerprint: migration_target_second.fingerprint.clone(),
            migration_descriptor_digest_route: vec![descriptor_digest, descriptor_second_digest],
            maintenance_mode: true,
            supplied_request_digest: None,
            guard: MutationGuard::new(migration.revision(), migration.digest()),
            limits: ResourceLimits::default(),
        })
        .expect("transactional native v2 maintenance migration");
    assert_eq!(migrated["revision"], "1");
    assert_eq!(
        migrated["migration_audit_records"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        migrated["root_record"]["aggregate_state"]["migration_sequence"],
        "2"
    );

    let terminal = host
        .create_checkpoint_v2(
            &terminal_bundle,
            "terminal",
            "terminal-v2-root",
            "terminal-v2-create",
            &Bindings::default(),
            None,
            json!({
                "mode": "permanent",
                "permanent_replay_eligible": true,
                "policy_identifier": null,
                "pruned_through_receipt_sequence": null
            }),
        )
        .expect("transactional v2 terminal creation");
    let tombstoned = host
        .tombstone_root_v2(
            terminal.root_instance_id(),
            "terminal-v2-tombstone",
            &MutationGuard::new(terminal.revision(), terminal.digest()),
        )
        .expect("transactional native v2 root tombstone");
    assert_eq!(tombstoned["root_record"]["status"], "tombstone");

    let outbox = host
        .create_checkpoint_v2(
            &outbox_bundle,
            "external_creator",
            "outbox-v2-root",
            "outbox-v2-create",
            &Bindings::default(),
            None,
            json!({
                "mode": "permanent",
                "permanent_replay_eligible": true,
                "policy_identifier": null,
                "pruned_through_receipt_sequence": null
            }),
        )
        .expect("transactional version-2 outbox creation");
    let effect_id = outbox.value()["pending_outbox_intents"][0]["intent"]["effect_id"]
        .as_str()
        .unwrap();
    let retryable = host
        .update_pending_outbox_v2(
            outbox.root_instance_id(),
            effect_id,
            PendingOutboxState::RetryableFailure {
                reason_code: "temporary".to_string(),
            },
            &MutationGuard::new(outbox.revision(), outbox.digest()),
        )
        .expect("transactional v2 pending outbox update");
    assert_eq!(retryable["revision"], "1");
    assert!(host
        .terminalize_outbox_v2(
            outbox.root_instance_id(),
            effect_id,
            TerminalOutboxOutcome::Confirmed,
            &MutationGuard::new(outbox.revision(), outbox.digest()),
        )
        .is_err());
    let terminal = host
        .terminalize_outbox_v2(
            outbox.root_instance_id(),
            effect_id,
            TerminalOutboxOutcome::Confirmed,
            &MutationGuard::new(
                retryable["revision"].as_str().unwrap(),
                retryable["execution_checkpoint_digest"].as_str().unwrap(),
            ),
        )
        .expect("transactional v2 outbox terminalization");
    assert_eq!(terminal["revision"], "2");
    let compacted = host
        .compact_outbox_v2(
            outbox.root_instance_id(),
            effect_id,
            &MutationGuard::new(
                terminal["revision"].as_str().unwrap(),
                terminal["execution_checkpoint_digest"].as_str().unwrap(),
            ),
        )
        .expect("transactional v2 outbox compaction");
    assert_eq!(compacted["revision"], "3");
    assert_eq!(
        compacted["outbox_effect_tombstones"][0]["effect_id"],
        effect_id
    );

    let upgraded = host
        .upgrade_checkpoint_v1_to_v2(
            &record.root_instance_id,
            &MutationGuard::new(&record.revision, &record.execution_checkpoint_digest),
        )
        .expect("transactional checkpoint upgrade");
    assert_eq!(upgraded.revision(), "4");

    let target_runtime_id = upgraded.value()["root_record"]["aggregate_state"]["root_runtime_id"]
        .as_str()
        .expect("root runtime id");
    let stepped = host
        .step_checkpoint_v2(
            upgraded.root_instance_id(),
            target_runtime_id,
            &MutationGuard::new(upgraded.revision(), upgraded.digest()),
        )
        .expect("transactional checkpoint step");
    assert_eq!(stepped["revision"], "5");
    let operations: serde_json::Value = serde_json::from_slice(
        &fs::read(
            PathBuf::from(CHECKPOINT_PROFILE)
                .join("checkpoint-04-version2-mailboxes/operation-inputs.json"),
        )
        .expect("version-2 operation inputs"),
    )
    .expect("version-2 operation input JSON");
    let admitted = host
        .admit_checkpoint_v2(
            upgraded.root_instance_id(),
            operations["admit"]["deliveries"].as_array().unwrap(),
            &MutationGuard::new(
                stepped["revision"].as_str().unwrap(),
                stepped["execution_checkpoint_digest"].as_str().unwrap(),
            ),
        )
        .expect("transactional checkpoint admission");
    assert_eq!(admitted["revision"], "6");
    let persisted = host
        .load_checkpoint_v2(upgraded.root_instance_id())
        .expect("version-2 reload")
        .expect("persisted version-2 checkpoint");
    assert_eq!(persisted.value(), &admitted);
}

fn record(root_instance_id: &str, revision: &str, marker: char) -> StoreRecord {
    let digest = format!("sha256:{}", marker.to_string().repeat(64));
    let bytes = serde_json_canonicalizer::to_vec(&json!({
        "root_instance_id": root_instance_id,
        "revision": revision,
        "execution_checkpoint_digest": digest
    }))
    .expect("record bytes");
    StoreRecord {
        root_instance_id: root_instance_id.to_string(),
        revision: revision.to_string(),
        execution_checkpoint_digest: digest,
        bytes,
    }
}

#[cfg(feature = "sqlite")]
#[cfg(feature = "sqlite")]
fn fixture_record(relative_path: &str) -> StoreRecord {
    let bytes = fs::read(PathBuf::from(CHECKPOINT_PROFILE).join(relative_path))
        .expect("checkpoint fixture");
    let checkpoint: ExecutionCheckpoint =
        serde_json::from_slice(&bytes).expect("typed checkpoint fixture");
    StoreRecord::from_checkpoint(&checkpoint).expect("fixture store record")
}

fn temporary_path(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::temp_dir().join(format!("determa-{label}-{}-{nonce}", std::process::id()))
}
