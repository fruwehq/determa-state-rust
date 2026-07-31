#![cfg(feature = "postgresql")]

use determa_state::checkpoint::{
    register_bundled_adapters, AdapterRegistry, CheckpointHost, DurableStoreMode, ExecutionStore,
    ExecutionStoreCapability, HostFailureCode, HostFeature, HostProfile, MutationGuard,
    OutboxRetentionMode, PostgresqlExecutionStore, PostgresqlExecutionStoreFactory,
    PostgresqlHostMutation, PostgresqlHostMutationResult, ReceiptRetentionMode, RootRecord,
    StoreError, StoreRecord, StoreWriteResult,
};
use determa_state::{load_bundle, Bindings, Bundle, InMemoryDefinitionResolver};
use postgres::{Client, NoTls};
use serde_json::json;
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

fn checkpoint_profile_directory() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("conformance-suite/conformance/profiles/execution-checkpoint")
}

#[test]
fn postgresql_cas_and_schema_contract() {
    let Some(base_url) = postgresql_url() else {
        return;
    };
    let url = isolated_schema_url(&base_url, "cas");
    let mode = DurableStoreMode::bounded();
    let first = Arc::new(
        PostgresqlExecutionStore::connect_no_tls(&url, mode).expect("PostgreSQL execution store"),
    );
    first.initialize_schema().expect("PostgreSQL schema");
    assert_eq!(
        first.capabilities(),
        BTreeSet::from([
            ExecutionStoreCapability::DurableConcurrent,
            ExecutionStoreCapability::SharedApplicationTransaction,
            ExecutionStoreCapability::RootIdentityRetention,
        ])
    );
    let root = unique_root("cas");
    let initial = record(&root, "0", '0');
    assert_eq!(
        first
            .insert_if_absent(initial.clone())
            .expect("PostgreSQL insert"),
        StoreWriteResult::Committed
    );
    assert!(
        first
            .with_native_transaction(|transaction| {
                transaction
                    .execute(
                        "DELETE FROM determa_execution_checkpoints WHERE root_instance_id = $1",
                        &[&root],
                    )
                    .map_err(pg_store_error)?;
                Ok(())
            })
            .is_err(),
        "schema trigger must reject physical root deletion"
    );

    let second = Arc::new(
        PostgresqlExecutionStore::connect_no_tls(&url, mode).expect("second PostgreSQL store"),
    );
    second.health().expect("second PostgreSQL health");
    let barrier = Arc::new(Barrier::new(3));
    let workers = [(first.clone(), '1'), (second, '2')]
        .into_iter()
        .map(|(store, marker)| {
            let barrier = barrier.clone();
            let root = root.clone();
            let digest = initial.execution_checkpoint_digest.clone();
            thread::spawn(move || {
                barrier.wait();
                store
                    .compare_and_swap(&root, "0", &digest, record(&root, "1", marker))
                    .expect("PostgreSQL CAS")
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();
    let results = workers
        .into_iter()
        .map(|worker| worker.join().expect("PostgreSQL worker"))
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

    let long_root = unique_root("lossless-counter");
    let long_revision = format!("1{}", "0".repeat(1_100));
    let next_long_revision = format!("2{}", "0".repeat(1_100));
    let long_initial = record(&long_root, &long_revision, '4');
    assert_eq!(
        first
            .insert_if_absent(long_initial.clone())
            .expect("lossless counter insert"),
        StoreWriteResult::Committed
    );
    assert_eq!(
        first
            .compare_and_swap(
                &long_root,
                &long_revision,
                &long_initial.execution_checkpoint_digest,
                record(&long_root, &next_long_revision, '5'),
            )
            .expect("lossless counter CAS"),
        StoreWriteResult::Committed
    );
    assert_eq!(
        first
            .load(&long_root)
            .expect("lossless counter load")
            .expect("lossless counter record")
            .revision,
        next_long_revision
    );

    first
        .with_native_transaction(|transaction| {
            transaction
                .batch_execute(
                    "
                    ALTER TABLE determa_execution_checkpoints
                    DROP CONSTRAINT determa_execution_checkpoints_digest_check
                    ",
                )
                .map_err(pg_store_error)
        })
        .expect("remove test digest constraint");
    assert!(
        first.health().is_err(),
        "health must reject a missing checkpoint constraint"
    );
    first
        .with_native_transaction(|transaction| {
            transaction
                .batch_execute(
                    "
                    ALTER TABLE determa_execution_checkpoints
                    ADD CONSTRAINT determa_execution_checkpoints_digest_check
                    CHECK (checkpoint_digest ~ '^sha256:[0-9a-f]{64}$')
                    ",
                )
                .map_err(pg_store_error)
        })
        .expect("restore test digest constraint");
    first.health().expect("restored PostgreSQL health");

    first
        .with_native_transaction(|transaction| {
            transaction
                .batch_execute("DROP TRIGGER determa_execution_checkpoints_no_delete ON determa_execution_checkpoints")
                .map_err(pg_store_error)
        })
        .expect("remove test deletion trigger");
    assert!(
        first.health().is_err(),
        "health must reject a missing deletion guard"
    );
}

#[test]
fn postgresql_factory_modes_drive_capabilities_profiles_and_policy() {
    let Some(base_url) = postgresql_url() else {
        return;
    };
    let strict_url = isolated_schema_url(&base_url, "strict_policy");
    let registry = AdapterRegistry::new();
    assert!(
        registry.identifiers().expect("empty registry").is_empty(),
        "new public registry must remain empty"
    );
    register_bundled_adapters(&registry).expect("register bundled adapters");
    let strict_configuration = configured_url(&strict_url, "permanent", "strict");
    let strict = registry
        .resolve(
            &strict_configuration,
            &BTreeSet::from([
                ExecutionStoreCapability::DurableConcurrent,
                ExecutionStoreCapability::SharedApplicationTransaction,
                ExecutionStoreCapability::RootIdentityRetention,
                ExecutionStoreCapability::PermanentReceiptRetention,
                ExecutionStoreCapability::PermanentOutboxTerminalRetention,
            ]),
        )
        .expect("strict configured PostgreSQL store");
    strict
        .initialize_schema()
        .expect("strict PostgreSQL schema");
    strict.health().expect("strict PostgreSQL health");
    let strict_host = CheckpointHost::new(
        strict.clone(),
        Arc::new(InMemoryDefinitionResolver::default()),
    );
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

    let (total, compact) = outbox_fixture_records();
    assert_eq!(
        strict
            .insert_if_absent(total.clone())
            .expect("strict PostgreSQL seed"),
        StoreWriteResult::Committed
    );
    assert!(
        strict
            .compare_and_swap(
                &total.root_instance_id,
                &total.revision,
                &total.execution_checkpoint_digest,
                compact.clone(),
            )
            .is_err(),
        "strict mode must reject terminal outbox compaction"
    );

    let mismatched = PostgresqlExecutionStore::connect_no_tls(
        &strict_url,
        DurableStoreMode::new(
            ReceiptRetentionMode::Permanent,
            OutboxRetentionMode::Compact,
        ),
    )
    .expect("mismatched PostgreSQL store");
    assert!(
        mismatched.health().is_err(),
        "health must reject a configured mode that differs from schema metadata"
    );
    assert!(
        mismatched.initialize_schema().is_err(),
        "schema setup must not silently change an existing configured mode"
    );

    let compact_url = isolated_schema_url(&base_url, "compact_policy");
    let compact_configuration = configured_url(&compact_url, "permanent", "compact");
    let compact_store = registry
        .resolve(
            &compact_configuration,
            &BTreeSet::from([
                ExecutionStoreCapability::PermanentReceiptRetention,
                ExecutionStoreCapability::CompactEffectIdentityRetention,
            ]),
        )
        .expect("compact configured PostgreSQL store");
    compact_store
        .initialize_schema()
        .expect("compact PostgreSQL schema");
    assert_eq!(
        compact_store
            .insert_if_absent(total.clone())
            .expect("compact PostgreSQL seed"),
        StoreWriteResult::Committed
    );
    assert_eq!(
        compact_store
            .compare_and_swap(
                &total.root_instance_id,
                &total.revision,
                &total.execution_checkpoint_digest,
                compact,
            )
            .expect("compact PostgreSQL transition"),
        StoreWriteResult::Committed
    );

    assert!(
        registry.resolve(&strict_url, &BTreeSet::new()).is_err(),
        "durable public factory must require explicit retention modes"
    );
    assert!(
        registry
            .resolve(
                &configured_url(&compact_url, "bounded", "bounded"),
                &BTreeSet::from([ExecutionStoreCapability::PermanentReceiptRetention]),
            )
            .is_err(),
        "requested capabilities must come from the configured store mode"
    );

    let injected_tls_url = isolated_schema_url(&base_url, "provided_tls");
    let injected_registry = AdapterRegistry::new();
    injected_registry
        .register(
            "postgresql",
            Arc::new(PostgresqlExecutionStoreFactory::with_tls(NoTls)),
        )
        .expect("register caller-provided TLS factory");
    let injected = injected_registry
        .resolve(
            &configured_url_with_tls(&injected_tls_url, "bounded", "bounded", "provided"),
            &BTreeSet::from([ExecutionStoreCapability::DurableConcurrent]),
        )
        .expect("resolve caller-provided TLS connector");
    injected
        .initialize_schema()
        .expect("caller-provided TLS schema");
    injected.health().expect("caller-provided TLS health");
}

#[test]
fn postgresql_host_transaction_commits_and_rolls_back_atomically() {
    let Some(base_url) = postgresql_url() else {
        return;
    };
    let url = isolated_schema_url(&base_url, "host_atomic");
    let mode = DurableStoreMode::new(ReceiptRetentionMode::Permanent, OutboxRetentionMode::Strict);
    let concrete =
        Arc::new(PostgresqlExecutionStore::connect_no_tls(&url, mode).expect("PostgreSQL store"));
    concrete.initialize_schema().expect("PostgreSQL schema");
    concrete
        .with_native_transaction(|transaction| {
            transaction
                .batch_execute(
                    "
                    CREATE TABLE checkpoint_host_application (
                        root_instance_id TEXT PRIMARY KEY,
                        response TEXT NOT NULL
                    );
                    CREATE TABLE checkpoint_host_parent (
                        id INTEGER PRIMARY KEY
                    );
                    CREATE TABLE checkpoint_host_deferred (
                        root_instance_id TEXT PRIMARY KEY,
                        parent_id INTEGER NOT NULL REFERENCES checkpoint_host_parent(id)
                            DEFERRABLE INITIALLY DEFERRED
                    );
                    ",
                )
                .map_err(pg_store_error)
        })
        .expect("application schema");
    let store: Arc<dyn ExecutionStore> = concrete.clone();
    let (host, bundle) = terminal_host(store.clone());

    let committed_root = unique_root("host-commit");
    create_terminal_root(&host, &bundle, &committed_root);
    let committed_guard = checkpoint_guard(store.as_ref(), &committed_root);
    let committed = host
        .with_postgresql_transaction(&committed_root, |transaction| {
            let isolation: String = transaction
                .transaction()
                .query_one("SHOW transaction_isolation", &[])
                .map_err(pg_store_error)?
                .get(0);
            transaction
                .transaction()
                .execute(
                    "
                    INSERT INTO checkpoint_host_application (root_instance_id, response)
                    VALUES ($1, $2)
                    ",
                    &[&committed_root, &"committed"],
                )
                .map_err(pg_store_error)?;
            host.stage_postgresql_mutation(
                transaction,
                PostgresqlHostMutation::TombstoneRoot {
                    root_instance_id: &committed_root,
                    operation_id: "atomic-commit",
                    guard: &committed_guard,
                },
            )?;
            Ok(isolation)
        })
        .expect("host-owned PostgreSQL transaction");
    assert_eq!(committed.application_result, "serializable");
    assert!(matches!(
        committed.host_result,
        PostgresqlHostMutationResult::RootTombstone(_)
    ));
    assert_eq!(application_row_count(&concrete, &committed_root), 1);
    assert!(matches!(
        host.load_checkpoint(&committed_root)
            .expect("committed checkpoint load")
            .expect("committed checkpoint")
            .root_record,
        RootRecord::Tombstone(_)
    ));

    let failed_root = unique_root("host-failed-commit");
    create_terminal_root(&host, &bundle, &failed_root);
    let failed_guard = checkpoint_guard(store.as_ref(), &failed_root);
    let before = store
        .load(&failed_root)
        .expect("pre-failure load")
        .expect("pre-failure checkpoint");
    let failure = host
        .with_postgresql_transaction(&failed_root, |transaction| {
            transaction
                .transaction()
                .execute(
                    "
                    INSERT INTO checkpoint_host_deferred (root_instance_id, parent_id)
                    VALUES ($1, 999)
                    ",
                    &[&failed_root],
                )
                .map_err(pg_store_error)?;
            host.stage_postgresql_mutation(
                transaction,
                PostgresqlHostMutation::TombstoneRoot {
                    root_instance_id: &failed_root,
                    operation_id: "must-rollback",
                    guard: &failed_guard,
                },
            )?;
            Ok("callback completed")
        })
        .expect_err("deferred constraint must fail the database commit");
    assert_eq!(failure.code, HostFailureCode::ExecutionStoreFailure);
    assert_eq!(deferred_row_count(&concrete, &failed_root), 0);
    assert_eq!(
        store
            .load(&failed_root)
            .expect("post-failure load")
            .expect("post-failure checkpoint"),
        before,
        "commit failure must roll back the checkpoint mutation"
    );
}

#[test]
fn postgresql_host_transaction_rejects_cross_root_and_cross_store_use() {
    let Some(base_url) = postgresql_url() else {
        return;
    };
    let url = isolated_schema_url(&base_url, "host_binding");
    let mode = DurableStoreMode::new(ReceiptRetentionMode::Permanent, OutboxRetentionMode::Strict);
    let first_store = Arc::new(
        PostgresqlExecutionStore::connect_no_tls(&url, mode).expect("first PostgreSQL store"),
    );
    first_store.initialize_schema().expect("PostgreSQL schema");
    let first_dyn: Arc<dyn ExecutionStore> = first_store.clone();
    let (first_host, bundle) = terminal_host(first_dyn.clone());
    let second_store = Arc::new(
        PostgresqlExecutionStore::connect_no_tls(&url, mode).expect("second PostgreSQL store"),
    );
    second_store.health().expect("second PostgreSQL health");
    let second_dyn: Arc<dyn ExecutionStore> = second_store;
    let (second_host, _) = terminal_host(second_dyn);

    let first_root = unique_root("bound-first");
    let second_root = unique_root("bound-second");
    create_terminal_root(&first_host, &bundle, &first_root);
    create_terminal_root(&first_host, &bundle, &second_root);
    let first_guard = checkpoint_guard(first_dyn.as_ref(), &first_root);
    let second_guard = checkpoint_guard(first_dyn.as_ref(), &second_root);

    let root_error = first_host
        .with_postgresql_transaction(&first_root, |transaction| {
            first_host.stage_postgresql_mutation(
                transaction,
                PostgresqlHostMutation::TombstoneRoot {
                    root_instance_id: &second_root,
                    operation_id: "wrong-root",
                    guard: &second_guard,
                },
            )
        })
        .expect_err("cross-root transaction use must fail");
    assert_eq!(root_error.code, HostFailureCode::TransactionRootMismatch);

    let store_error = first_host
        .with_postgresql_transaction(&first_root, |transaction| {
            second_host.stage_postgresql_mutation(
                transaction,
                PostgresqlHostMutation::TombstoneRoot {
                    root_instance_id: &first_root,
                    operation_id: "wrong-store",
                    guard: &first_guard,
                },
            )
        })
        .expect_err("cross-store transaction use must fail");
    assert_eq!(store_error.code, HostFailureCode::TransactionStoreMismatch);
    assert!(matches!(
        first_host
            .load_checkpoint(&first_root)
            .expect("bound checkpoint load")
            .expect("bound checkpoint")
            .root_record,
        RootRecord::Retained(_)
    ));
}

fn postgresql_url() -> Option<String> {
    std::env::var("DETERMA_TEST_POSTGRES_URL").ok().or_else(|| {
        eprintln!("DETERMA_TEST_POSTGRES_URL is unset; PostgreSQL integration test skipped");
        None
    })
}

fn isolated_schema_url(base_url: &str, label: &str) -> String {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let schema = format!(
        "determa_checkpoint_{}_{}_{}",
        label,
        std::process::id(),
        nonce
    );
    let mut client = Client::connect(base_url, NoTls).expect("PostgreSQL test administration");
    client
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .expect("isolated PostgreSQL schema");
    let separator = if base_url.contains('?') { '&' } else { '?' };
    format!("{base_url}{separator}options=-c%20search_path%3D{schema}")
}

fn configured_url(url: &str, receipt_retention: &str, outbox_retention: &str) -> String {
    configured_url_with_tls(url, receipt_retention, outbox_retention, "no_tls")
}

fn configured_url_with_tls(
    url: &str,
    receipt_retention: &str,
    outbox_retention: &str,
    tls: &str,
) -> String {
    format!(
        "{url}#receipt_retention={receipt_retention}&outbox_retention={outbox_retention}&tls={tls}"
    )
}

fn terminal_host(
    store: Arc<dyn ExecutionStore>,
) -> (CheckpointHost<InMemoryDefinitionResolver>, Bundle) {
    let bundle = load_bundle(
        &fs::read_to_string(
            checkpoint_profile_directory()
                .join("checkpoint-03-retention-and-root-lifecycle/terminal.yaml"),
        )
        .expect("terminal bundle"),
    )
    .expect("load terminal bundle");
    let mut resolver = InMemoryDefinitionResolver::default();
    assert!(resolver.insert(bundle.clone(), true));
    (CheckpointHost::new(store, Arc::new(resolver)), bundle)
}

fn create_terminal_root(
    host: &CheckpointHost<InMemoryDefinitionResolver>,
    bundle: &Bundle,
    root_instance_id: &str,
) {
    let machine = bundle.machines.get("terminal").expect("terminal machine");
    host.create(determa_state::checkpoint::CreationRequest {
        bundle,
        namespace: &bundle.namespace,
        machine_id: &machine.machine_id,
        machine_version: machine.version,
        root_instance_id,
        creation_id: &format!("{root_instance_id}-creation"),
        bindings: &Bindings::default(),
        supplied_request_digest: None,
    })
    .expect("create terminal root");
}

fn checkpoint_guard(store: &dyn ExecutionStore, root_instance_id: &str) -> MutationGuard {
    let record = store
        .load(root_instance_id)
        .expect("checkpoint load")
        .expect("checkpoint record");
    MutationGuard::new(record.revision, record.execution_checkpoint_digest)
}

fn application_row_count(store: &PostgresqlExecutionStore, root_instance_id: &str) -> i64 {
    store
        .with_native_transaction(|transaction| {
            transaction
                .query_one(
                    "
                    SELECT COUNT(*)
                    FROM checkpoint_host_application
                    WHERE root_instance_id = $1
                    ",
                    &[&root_instance_id],
                )
                .map(|row| row.get(0))
                .map_err(pg_store_error)
        })
        .expect("application row count")
}

fn deferred_row_count(store: &PostgresqlExecutionStore, root_instance_id: &str) -> i64 {
    store
        .with_native_transaction(|transaction| {
            transaction
                .query_one(
                    "
                    SELECT COUNT(*)
                    FROM checkpoint_host_deferred
                    WHERE root_instance_id = $1
                    ",
                    &[&root_instance_id],
                )
                .map(|row| row.get(0))
                .map_err(pg_store_error)
        })
        .expect("deferred row count")
}

fn outbox_fixture_records() -> (StoreRecord, StoreRecord) {
    let directory = checkpoint_profile_directory().join("checkpoint-02-outbox-lifecycle");
    let bundle =
        load_bundle(&fs::read_to_string(directory.join("machine.yaml")).expect("outbox bundle"))
            .expect("load outbox bundle");
    let mut resolver = InMemoryDefinitionResolver::default();
    assert!(resolver.insert(bundle, true));
    let record = |name: &str| {
        let checkpoint = determa_state::checkpoint::restore_execution_checkpoint(
            &fs::read(directory.join(name)).expect("checkpoint fixture"),
            &resolver,
        )
        .expect("restore checkpoint fixture");
        StoreRecord::from_checkpoint(&checkpoint).expect("checkpoint record")
    };
    (
        record("outbox-total-checkpoint.json"),
        record("outbox-compact-checkpoint.json"),
    )
}

fn unique_root(label: &str) -> String {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    format!("postgres-checkpoint-{label}-{}-{nonce}", std::process::id())
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

fn pg_store_error(error: postgres::Error) -> StoreError {
    StoreError::new(error.to_string())
}
