#![cfg(feature = "postgresql")]

use determa_state::checkpoint::{
    register_bundled_adapters, AdapterRegistry, CheckpointHost, DurableStoreMode, ExecutionStore,
    ExecutionStoreCapability, HostFailureCode, HostFeature, HostProfile,
    MaintenanceMigrationRequest, MutationGuard, OutboxRetentionMode, PendingOutboxState,
    PostgresqlExecutionStore, PostgresqlExecutionStoreFactory, PostgresqlHostMutation,
    PostgresqlHostMutationResult, ReceiptRetentionMode, RootRecord, StoreError, StoreRecord,
    StoreWriteResult, TerminalOutboxOutcome,
};
use determa_state::{load_bundle, Bindings, Bundle, InMemoryDefinitionResolver, ResourceLimits};
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
fn postgresql_runs_native_version2_outbox_lifecycle() {
    let Some(base_url) = postgresql_url() else {
        return;
    };
    let url = isolated_schema_url(&base_url, "v2_outbox");
    let store: Arc<dyn ExecutionStore> = Arc::new(
        PostgresqlExecutionStore::connect_no_tls(&url, DurableStoreMode::bounded())
            .expect("PostgreSQL execution store"),
    );
    store.initialize_schema().expect("PostgreSQL schema");
    let bundle = load_bundle(
        &fs::read_to_string(
            checkpoint_profile_directory()
                .join("checkpoint-04-version2-mailboxes/creation-owned-work-machine.yaml"),
        )
        .expect("version-2 outbox bundle"),
    )
    .expect("load version-2 outbox bundle");
    let mut resolver = InMemoryDefinitionResolver::default();
    assert!(resolver.insert(bundle.clone(), true));
    let migration_directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("conformance-suite/conformance/core/118-version2-persistence");
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
    let descriptor_bytes = fs::read(migration_directory.join("descriptor-compatible-v2.json"))
        .expect("v2 migration descriptor");
    let descriptor: serde_json::Value = serde_json::from_slice(&descriptor_bytes).unwrap();
    let descriptor_digest = descriptor["migration_descriptor_digest"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(resolver.insert(migration_source.clone(), true));
    assert!(resolver.insert(migration_target.clone(), true));
    assert!(resolver.insert_descriptor(descriptor_digest.clone(), descriptor_bytes, true));
    let terminal_bundle = load_bundle(
        r#"
format: 1
namespace: test.postgresql_v2_terminal
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
    assert!(resolver.insert(terminal_bundle.clone(), true));
    let host = CheckpointHost::new(store, Arc::new(resolver));
    let root = unique_root("v2-outbox");
    let created = host
        .create_checkpoint_v2(
            &bundle,
            "external_creator",
            &root,
            "create",
            &Bindings::default(),
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            json!({
                "mode": "permanent",
                "permanent_replay_eligible": true,
                "policy_identifier": null,
                "pruned_through_receipt_sequence": null
            }),
        )
        .expect("create native v2 checkpoint");
    let effect_id = created.value()["pending_outbox_intents"][0]["intent"]["effect_id"]
        .as_str()
        .unwrap();
    let guard = MutationGuard::new(created.revision(), created.digest());
    let rollback = host.with_postgresql_transaction(&root, |transaction| {
        host.stage_postgresql_mutation(
            transaction,
            PostgresqlHostMutation::UpdatePendingOutboxV2 {
                root_instance_id: &root,
                effect_id,
                desired: PendingOutboxState::RetryableFailure {
                    reason_code: "temporary".to_string(),
                },
                guard: &guard,
            },
        )?;
        host.stage_postgresql_mutation(
            transaction,
            PostgresqlHostMutation::UpdatePendingOutboxV2 {
                root_instance_id: &root,
                effect_id,
                desired: PendingOutboxState::Ambiguous {
                    reason_code: "unknown".to_string(),
                },
                guard: &guard,
            },
        )
    });
    assert_eq!(
        rollback.unwrap_err().code,
        HostFailureCode::TransactionMutationAlreadyStaged
    );
    let unchanged = host.load_checkpoint_v2(&root).unwrap().unwrap();
    assert_eq!(unchanged.revision(), created.revision());
    assert_eq!(unchanged.digest(), created.digest());

    let pending = host
        .with_postgresql_transaction(&root, |transaction| {
            host.stage_postgresql_mutation(
                transaction,
                PostgresqlHostMutation::UpdatePendingOutboxV2 {
                    root_instance_id: &root,
                    effect_id,
                    desired: PendingOutboxState::Ambiguous {
                        reason_code: "unknown".to_string(),
                    },
                    guard: &guard,
                },
            )
        })
        .expect("transactional native v2 outbox update");
    let PostgresqlHostMutationResult::PendingOutboxV2(pending) = pending.host_result else {
        panic!("unexpected native v2 pending-outbox result")
    };
    let terminal_guard = MutationGuard::new(
        pending["revision"].as_str().unwrap(),
        pending["execution_checkpoint_digest"].as_str().unwrap(),
    );
    let terminal = host
        .with_postgresql_transaction(&root, |transaction| {
            host.stage_postgresql_mutation(
                transaction,
                PostgresqlHostMutation::TerminalizeOutboxV2 {
                    root_instance_id: &root,
                    effect_id,
                    outcome: TerminalOutboxOutcome::Confirmed,
                    guard: &terminal_guard,
                },
            )
        })
        .expect("transactional native v2 outbox terminalization");
    let PostgresqlHostMutationResult::OutboxV2(terminal) = terminal.host_result else {
        panic!("unexpected native v2 terminal-outbox result")
    };
    let compact_guard = MutationGuard::new(
        terminal["revision"].as_str().unwrap(),
        terminal["execution_checkpoint_digest"].as_str().unwrap(),
    );
    let compacted = host
        .with_postgresql_transaction(&root, |transaction| {
            host.stage_postgresql_mutation(
                transaction,
                PostgresqlHostMutation::CompactOutboxV2 {
                    root_instance_id: &root,
                    effect_id,
                    guard: &compact_guard,
                },
            )
        })
        .expect("transactional native v2 outbox compaction");
    let PostgresqlHostMutationResult::CompactedOutboxV2(compacted) = compacted.host_result else {
        panic!("unexpected native v2 compacted-outbox result")
    };
    assert_eq!(compacted["revision"], "3");

    let migration_root = unique_root("v2-migration");
    let migration = host
        .create_checkpoint_v2(
            &migration_source,
            "transaction_server",
            &migration_root,
            "create",
            &Bindings::default(),
            "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            json!({
                "mode": "permanent",
                "permanent_replay_eligible": true,
                "policy_identifier": null,
                "pruned_through_receipt_sequence": null
            }),
        )
        .expect("create native v2 migration checkpoint");
    let migration_request = MaintenanceMigrationRequest {
        root_instance_id: migration_root.clone(),
        operation_id: "migrate".to_string(),
        source_aggregate_state_digest: migration.value()["root_record"]["aggregate_state"]
            ["aggregate_state_digest"]
            .as_str()
            .unwrap()
            .to_string(),
        target_validated_bundle_fingerprint: migration_target.fingerprint.clone(),
        migration_descriptor_digest_route: vec![descriptor_digest],
        maintenance_mode: true,
        supplied_request_digest: None,
        guard: MutationGuard::new(migration.revision(), migration.digest()),
        limits: ResourceLimits::default(),
    };
    let migrated = host
        .with_postgresql_transaction(&migration_root, |transaction| {
            host.stage_postgresql_mutation(
                transaction,
                PostgresqlHostMutation::MaintenanceMigrationV2(&migration_request),
            )
        })
        .expect("transactional native v2 migration");
    let PostgresqlHostMutationResult::MaintenanceMigrationV2(migrated) = migrated.host_result
    else {
        panic!("unexpected native v2 migration result")
    };
    assert_eq!(
        migrated["migration_audit_records"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    let terminal_root = unique_root("v2-terminal");
    let terminal = host
        .create_checkpoint_v2(
            &terminal_bundle,
            "terminal",
            &terminal_root,
            "create",
            &Bindings::default(),
            "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            json!({
                "mode": "permanent",
                "permanent_replay_eligible": true,
                "policy_identifier": null,
                "pruned_through_receipt_sequence": null
            }),
        )
        .expect("create native v2 terminal checkpoint");
    let terminal_guard = MutationGuard::new(terminal.revision(), terminal.digest());
    let tombstoned = host
        .with_postgresql_transaction(&terminal_root, |transaction| {
            host.stage_postgresql_mutation(
                transaction,
                PostgresqlHostMutation::TombstoneRootV2 {
                    root_instance_id: &terminal_root,
                    operation_id: "tombstone",
                    guard: &terminal_guard,
                },
            )
        })
        .expect("transactional native v2 root tombstone");
    let PostgresqlHostMutationResult::RootTombstoneV2(tombstoned) = tombstoned.host_result else {
        panic!("unexpected native v2 root tombstone result")
    };
    assert_eq!(tombstoned["root_record"]["status"], "tombstone");
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
