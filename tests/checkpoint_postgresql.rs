#![cfg(feature = "postgresql")]

use determa_state::checkpoint::{
    CheckpointHost, DurableStoreMode, ExecutionStore, MaintenanceMigrationRequest, MutationGuard,
    PendingOutboxState, PostgresqlExecutionStore, PostgresqlHostMutation,
    PostgresqlHostMutationResult, ProcessingRequest, PruneRequest, StoreError,
    TerminalOutboxOutcome, TransactionalProcessRequest,
};
use determa_state::{
    load_bundle, Bindings, InMemoryDefinitionResolver, MigrationRequest, ResourceLimits,
};
use postgres::{Client, NoTls};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn postgresql_shared_application_transaction_runs_every_native_v2_variant() {
    let Some(base_url) = postgresql_url() else {
        return;
    };
    let url = isolated_schema_url(&base_url, "native_v2");
    let concrete = Arc::new(
        PostgresqlExecutionStore::connect_no_tls(&url, DurableStoreMode::bounded()).unwrap(),
    );
    concrete.initialize_schema().unwrap();
    concrete
        .with_native_transaction(|transaction| {
            transaction
                .batch_execute(
                    "CREATE TABLE application_audit (root_instance_id TEXT, action TEXT)",
                )
                .map_err(pg_error)
        })
        .unwrap();

    let core = Path::new("conformance-suite/conformance/core/117-version2-mailboxes");
    let bundle = load_bundle(&fs::read_to_string(core.join("machine.yaml")).unwrap()).unwrap();
    let outbox_bundle = load_bundle(
        r#"
format: 1
namespace: test.postgresql_native_v2
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
namespace: test.postgresql_native_v2_terminal
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
    let store: Arc<dyn ExecutionStore> = concrete.clone();
    let host = CheckpointHost::new(store.clone(), Arc::new(resolver));
    let bindings = Bindings::default();
    let retention = retention();

    let created = host
        .with_postgresql_transaction("server-1", |transaction| {
            application_row(transaction.transaction(), "server-1", "create")?;
            host.stage_postgresql_mutation(
                transaction,
                PostgresqlHostMutation::Create {
                    bundle: &bundle,
                    machine_id: "transaction_server",
                    root_instance_id: "server-1",
                    creation_id: "create-server-1",
                    bindings: &bindings,
                    supplied_request_digest: None,
                    replay_retention: &retention,
                },
            )
        })
        .unwrap();
    let PostgresqlHostMutationResult::Creation(created) = created.host_result else {
        panic!("unexpected create result")
    };

    let inputs: Value =
        serde_json::from_slice(&fs::read(core.join("operation-inputs.json")).unwrap()).unwrap();
    let create_guard = MutationGuard::new(created.revision(), created.digest());
    let admitted = host
        .with_postgresql_transaction("server-1", |transaction| {
            application_row(transaction.transaction(), "server-1", "admit")?;
            host.stage_postgresql_mutation(
                transaction,
                PostgresqlHostMutation::Admit {
                    root_instance_id: "server-1",
                    deliveries: inputs["admit_two"]["deliveries"].as_array().unwrap(),
                    guard: &create_guard,
                },
            )
        })
        .unwrap();
    let PostgresqlHostMutationResult::Admission(admitted) = admitted.host_result else {
        panic!("unexpected admission result")
    };

    let admitted_checkpoint = &admitted["checkpoint"];
    let first_processing = processing_for(admitted_checkpoint);
    let admission_guard = guard_for(admitted_checkpoint);
    let stepped = host
        .with_postgresql_transaction("server-1", |transaction| {
            application_row(transaction.transaction(), "server-1", "step")?;
            host.stage_postgresql_mutation(
                transaction,
                PostgresqlHostMutation::Step {
                    root_instance_id: "server-1",
                    request: &first_processing,
                    guard: &admission_guard,
                },
            )
        })
        .unwrap();
    let PostgresqlHostMutationResult::Step(stepped) = stepped.host_result else {
        panic!("unexpected step result")
    };

    let step_guard = guard_for(&stepped);
    let second_processing = processing_for(&stepped);
    let stepped_again = host
        .with_postgresql_transaction("server-1", |transaction| {
            application_row(transaction.transaction(), "server-1", "step-again")?;
            host.stage_postgresql_mutation(
                transaction,
                PostgresqlHostMutation::Step {
                    root_instance_id: "server-1",
                    request: &second_processing,
                    guard: &step_guard,
                },
            )
        })
        .unwrap();
    let PostgresqlHostMutationResult::Step(stepped_again) = stepped_again.host_result else {
        panic!("unexpected second step result")
    };
    let step_guard = guard_for(&stepped_again);
    let pruned = host
        .with_postgresql_transaction("server-1", |transaction| {
            application_row(transaction.transaction(), "server-1", "prune")?;
            host.stage_postgresql_mutation(
                transaction,
                PostgresqlHostMutation::Prune {
                    root_instance_id: "server-1",
                    request: &PruneRequest {
                        cutoff_receipt_sequence: "4".to_string(),
                        target_mode: "bounded".to_string(),
                        policy_identifier: Some("postgresql-native-v2-test".to_string()),
                        dependency_receipt_sequences: Vec::new(),
                        dependency_effect_ids: Vec::new(),
                    },
                    guard: &step_guard,
                },
            )
        })
        .unwrap();
    let PostgresqlHostMutationResult::Prune(pruned) = pruned.host_result else {
        panic!("unexpected prune result")
    };

    let maintenance = MaintenanceMigrationRequest {
        root_instance_id: "server-1".to_string(),
        operation_id: "postgresql-no-op".to_string(),
        source_aggregate_state_digest: pruned["root_record"]["aggregate_state"]
            ["aggregate_state_digest"]
            .as_str()
            .unwrap()
            .to_string(),
        target_validated_bundle_fingerprint: bundle.fingerprint.clone(),
        migration_descriptor_digest_route: Vec::new(),
        maintenance_mode: false,
        supplied_request_digest: None,
        guard: guard_for(&pruned),
        limits: ResourceLimits::default(),
    };
    let maintained = host
        .with_postgresql_transaction("server-1", |transaction| {
            application_row(transaction.transaction(), "server-1", "maintenance")?;
            host.stage_postgresql_mutation(
                transaction,
                PostgresqlHostMutation::MaintenanceMigration(&maintenance),
            )
        })
        .unwrap();
    let PostgresqlHostMutationResult::MaintenanceMigration(_maintained) = maintained.host_result
    else {
        panic!("unexpected maintenance result")
    };

    let process_created = create_transaction_root(
        &host,
        &bundle,
        &bindings,
        &retention,
        "process-root",
        "create-process-root",
    );
    let process_delivery = input_delivery(&process_created, "process-event");
    let processed = host
        .with_postgresql_transaction("process-root", |transaction| {
            application_row(transaction.transaction(), "process-root", "process")?;
            host.stage_postgresql_mutation(
                transaction,
                PostgresqlHostMutation::Process {
                    root_instance_id: "process-root",
                    delivery: &process_delivery,
                    processing_mode: "delayed",
                    guard: &MutationGuard::new(
                        process_created.revision(),
                        process_created.digest(),
                    ),
                },
            )
        })
        .unwrap();
    assert!(matches!(
        processed.host_result,
        PostgresqlHostMutationResult::Process(_)
    ));
    assert_eq!(application_count(&concrete, "process"), 1);

    let transactional_created = create_transaction_root(
        &host,
        &bundle,
        &bindings,
        &retention,
        "transactional-process-root",
        "create-transactional-process-root",
    );
    let transactional_delivery = input_delivery(&transactional_created, "transactional-event");
    let transactional_request = TransactionalProcessRequest {
        migration: MigrationRequest {
            migration_route: Vec::new(),
            target_validated_bundle_fingerprint: bundle.fingerprint.clone(),
            maintenance_mode: false,
        },
        migration_limits: ResourceLimits::default(),
        delivery: transactional_delivery,
        processing_mode: "delayed".to_string(),
    };
    let transactional = host
        .with_postgresql_transaction("transactional-process-root", |transaction| {
            application_row(
                transaction.transaction(),
                "transactional-process-root",
                "transactional-process",
            )?;
            host.stage_postgresql_mutation(
                transaction,
                PostgresqlHostMutation::TransactionalProcess {
                    root_instance_id: "transactional-process-root",
                    request: &transactional_request,
                    guard: &MutationGuard::new(
                        transactional_created.revision(),
                        transactional_created.digest(),
                    ),
                },
            )
        })
        .unwrap();
    let PostgresqlHostMutationResult::TransactionalProcess(transactional) =
        transactional.host_result
    else {
        panic!("unexpected transactional process result")
    };
    assert_eq!(transactional["revision"], "1");
    assert_eq!(transactional["migration_audit_records"], json!([]));
    assert_eq!(application_count(&concrete, "transactional-process"), 1);

    let terminal_created = host
        .with_postgresql_transaction("terminal-root", |transaction| {
            application_row(
                transaction.transaction(),
                "terminal-root",
                "create-terminal",
            )?;
            host.stage_postgresql_mutation(
                transaction,
                PostgresqlHostMutation::Create {
                    bundle: &terminal_bundle,
                    machine_id: "terminal",
                    root_instance_id: "terminal-root",
                    creation_id: "create-terminal",
                    bindings: &bindings,
                    supplied_request_digest: None,
                    replay_retention: &retention,
                },
            )
        })
        .unwrap();
    let PostgresqlHostMutationResult::Creation(terminal_created) = terminal_created.host_result
    else {
        panic!("unexpected terminal create result")
    };
    let before_rollback = store.load("terminal-root").unwrap().unwrap();
    let rollback_guard = MutationGuard::new(terminal_created.revision(), terminal_created.digest());
    let rollback = host.with_postgresql_transaction("terminal-root", |transaction| {
        application_row(transaction.transaction(), "terminal-root", "rollback")?;
        host.stage_postgresql_mutation(
            transaction,
            PostgresqlHostMutation::TombstoneRoot {
                root_instance_id: "terminal-root",
                operation_id: "rolled-back-tombstone",
                guard: &rollback_guard,
            },
        )?;
        Err::<(), _>(StoreError::new("force rollback").into())
    });
    assert!(rollback.is_err());
    assert_eq!(
        store.load("terminal-root").unwrap().unwrap(),
        before_rollback
    );
    assert_eq!(application_count(&concrete, "rollback"), 0);

    let terminal_guard = MutationGuard::new(terminal_created.revision(), terminal_created.digest());
    let tombstoned = host
        .with_postgresql_transaction("terminal-root", |transaction| {
            application_row(transaction.transaction(), "terminal-root", "tombstone")?;
            host.stage_postgresql_mutation(
                transaction,
                PostgresqlHostMutation::TombstoneRoot {
                    root_instance_id: "terminal-root",
                    operation_id: "postgresql-tombstone",
                    guard: &terminal_guard,
                },
            )
        })
        .unwrap();
    assert!(matches!(
        tombstoned.host_result,
        PostgresqlHostMutationResult::RootTombstone(_)
    ));

    let outbox_created = host
        .with_postgresql_transaction("outbox-root", |transaction| {
            application_row(transaction.transaction(), "outbox-root", "create-outbox")?;
            host.stage_postgresql_mutation(
                transaction,
                PostgresqlHostMutation::Create {
                    bundle: &outbox_bundle,
                    machine_id: "publisher",
                    root_instance_id: "outbox-root",
                    creation_id: "create-outbox",
                    bindings: &bindings,
                    supplied_request_digest: None,
                    replay_retention: &retention,
                },
            )
        })
        .unwrap();
    let PostgresqlHostMutationResult::Creation(outbox_created) = outbox_created.host_result else {
        panic!("unexpected outbox create result")
    };
    let effect_id = outbox_created.value()["pending_outbox_intents"][0]["intent"]["effect_id"]
        .as_str()
        .unwrap();
    let outbox_create_guard =
        MutationGuard::new(outbox_created.revision(), outbox_created.digest());
    let pending = host
        .with_postgresql_transaction("outbox-root", |transaction| {
            application_row(transaction.transaction(), "outbox-root", "pending")?;
            host.stage_postgresql_mutation(
                transaction,
                PostgresqlHostMutation::UpdatePendingOutbox {
                    root_instance_id: "outbox-root",
                    effect_id,
                    desired: PendingOutboxState::RetryableFailure {
                        reason_code: "retry".to_string(),
                    },
                    guard: &outbox_create_guard,
                },
            )
        })
        .unwrap();
    let PostgresqlHostMutationResult::PendingOutbox(pending) = pending.host_result else {
        panic!("unexpected pending result")
    };
    let pending_guard = guard_for(&pending);
    let terminal = host
        .with_postgresql_transaction("outbox-root", |transaction| {
            application_row(transaction.transaction(), "outbox-root", "terminal")?;
            host.stage_postgresql_mutation(
                transaction,
                PostgresqlHostMutation::TerminalizeOutbox {
                    root_instance_id: "outbox-root",
                    effect_id,
                    outcome: TerminalOutboxOutcome::Confirmed,
                    guard: &pending_guard,
                },
            )
        })
        .unwrap();
    let PostgresqlHostMutationResult::Outbox(terminal) = terminal.host_result else {
        panic!("unexpected terminal result")
    };
    let terminal_guard = guard_for(&terminal);
    let compacted = host
        .with_postgresql_transaction("outbox-root", |transaction| {
            application_row(transaction.transaction(), "outbox-root", "compact")?;
            host.stage_postgresql_mutation(
                transaction,
                PostgresqlHostMutation::CompactOutbox {
                    root_instance_id: "outbox-root",
                    effect_id,
                    guard: &terminal_guard,
                },
            )
        })
        .unwrap();
    assert!(matches!(
        compacted.host_result,
        PostgresqlHostMutationResult::CompactedOutbox(_)
    ));
    assert_eq!(application_count(&concrete, "compact"), 1);
}

fn create_transaction_root(
    host: &CheckpointHost<InMemoryDefinitionResolver>,
    bundle: &determa_state::Bundle,
    bindings: &Bindings,
    retention: &Value,
    root_instance_id: &str,
    creation_id: &str,
) -> determa_state::checkpoint::ExecutionCheckpoint {
    let created = host
        .with_postgresql_transaction(root_instance_id, |transaction| {
            application_row(
                transaction.transaction(),
                root_instance_id,
                "create-process",
            )?;
            host.stage_postgresql_mutation(
                transaction,
                PostgresqlHostMutation::Create {
                    bundle,
                    machine_id: "transaction_server",
                    root_instance_id,
                    creation_id,
                    bindings,
                    supplied_request_digest: None,
                    replay_retention: retention,
                },
            )
        })
        .unwrap();
    let PostgresqlHostMutationResult::Creation(created) = created.host_result else {
        panic!("unexpected process-root creation result")
    };
    *created
}

fn input_delivery(
    checkpoint: &determa_state::checkpoint::ExecutionCheckpoint,
    event_id: &str,
) -> Value {
    let envelope = json!({
        "event": "received",
        "event_id": event_id,
        "cause_id": event_id,
        "source": {"host": true},
        "target": checkpoint.value()["root_record"]["aggregate_state"]["runtimes"][0]
            ["target_identity"],
        "payload": ["map", []]
    });
    let root_instance_id = checkpoint.root_instance_id();
    let bytes = serde_json_canonicalizer::to_vec(&json!([
        "determa-inbox-envelope-digest-2",
        "2",
        root_instance_id,
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

fn retention() -> Value {
    json!({
        "mode": "bounded",
        "permanent_replay_eligible": false,
        "policy_identifier": "postgresql-native-v2-test",
        "pruned_through_receipt_sequence": null
    })
}

fn guard_for(value: &Value) -> MutationGuard {
    MutationGuard::new(
        value["revision"].as_str().unwrap(),
        value["execution_checkpoint_digest"].as_str().unwrap(),
    )
}

fn application_row(
    transaction: &mut postgres::Transaction<'_>,
    root: &str,
    action: &str,
) -> Result<(), determa_state::checkpoint::HostFailure> {
    transaction
        .execute(
            "INSERT INTO application_audit (root_instance_id, action) VALUES ($1, $2)",
            &[&root, &action],
        )
        .map(|_| ())
        .map_err(pg_error)
        .map_err(Into::into)
}

fn application_count(store: &PostgresqlExecutionStore, action: &str) -> i64 {
    store
        .with_native_transaction(|transaction| {
            transaction
                .query_one(
                    "SELECT count(*) FROM application_audit WHERE action = $1",
                    &[&action],
                )
                .map(|row| row.get(0))
                .map_err(pg_error)
        })
        .unwrap()
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
        .unwrap()
        .as_nanos();
    let schema = format!(
        "determa_checkpoint_{label}_{}_{}",
        std::process::id(),
        nonce
    );
    let mut client = Client::connect(base_url, NoTls).unwrap();
    client
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .unwrap();
    let separator = if base_url.contains('?') { '&' } else { '?' };
    format!("{base_url}{separator}options=-c%20search_path%3D{schema}")
}

fn pg_error(error: postgres::Error) -> StoreError {
    StoreError::new(error.to_string())
}
