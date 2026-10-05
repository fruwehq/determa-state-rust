//! Application-owned foreground worker integration; the engine owns no scheduler.
#![cfg(feature = "sqlite")]
use determa_state::checkpoint::{
    CheckpointHost, DurableStoreMode, ExecutionStore, MutationGuard, OutboxRetentionMode,
    PendingOutboxState, ReceiptRetentionMode, SqliteExecutionStore, TerminalOutboxOutcome,
};
use determa_state::{load_bundle, Bindings, InMemoryDefinitionResolver};
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

type Host = CheckpointHost<InMemoryDefinitionResolver>;

// This application worker retains ingress in its own native database and calls
// the public checkpoint/outbox API. Its destination deduplicates effect IDs.
struct ApplicationWorker {
    database: PathBuf,
}
impl ApplicationWorker {
    fn open(database: PathBuf) -> Self {
        let connection = Connection::open(&database).unwrap();
        connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS ingress (id TEXT PRIMARY KEY, body TEXT NOT NULL, acknowledged INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS destination (effect_id TEXT PRIMARY KEY, payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS decisions (effect_id TEXT PRIMARY KEY, outcome TEXT NOT NULL);").unwrap();
        Self { database }
    }
    fn connection(&self) -> Connection {
        let connection = Connection::open(&self.database).unwrap();
        connection.execute_batch("PRAGMA synchronous=FULL").unwrap();
        connection
    }
    fn retain_ingress(&self, id: &str, body: &Value) {
        self.connection()
            .execute(
                "INSERT INTO ingress(id,body) VALUES(?1,?2)",
                params![id, body.to_string()],
            )
            .unwrap();
    }
    fn pending_ingress(&self) -> Vec<(String, Value)> {
        let connection = self.connection();
        let mut statement = connection
            .prepare("SELECT id,body FROM ingress WHERE acknowledged=0 ORDER BY id")
            .unwrap();
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    serde_json::from_str(&row.get::<_, String>(1)?).unwrap(),
                ))
            })
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }
    fn acknowledge(&self, host: &Host, root: &str, id: &str) {
        // A fresh native load must observe the committed admission receipt.
        let checkpoint = host.load_checkpoint(root).unwrap().unwrap();
        assert!(checkpoint.value()["operation_receipts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["event_id"] == id));
        self.connection()
            .execute("UPDATE ingress SET acknowledged=1 WHERE id=?1", [id])
            .unwrap();
    }
    fn finish(
        &self,
        host: &Host,
        root: &str,
        effect: &str,
        outcome: TerminalOutboxOutcome,
        stop_after_destination: bool,
    ) {
        let checkpoint = host.load_checkpoint(root).unwrap().unwrap();
        let pending = checkpoint.value()["pending_outbox_intents"]
            .as_array()
            .unwrap()
            .iter()
            .find(|record| record["intent"]["effect_id"] == effect)
            .unwrap();
        if outcome == TerminalOutboxOutcome::Confirmed {
            self.connection()
                .execute(
                    "INSERT INTO destination VALUES(?1,?2) ON CONFLICT(effect_id) DO NOTHING",
                    params![effect, pending["intent"]["payload"].to_string()],
                )
                .unwrap();
            if stop_after_destination {
                return;
            }
        }
        host.terminalize_outbox(
            root,
            effect,
            outcome.clone(),
            &MutationGuard::new(checkpoint.revision(), checkpoint.digest()),
        )
        .unwrap();
        self.connection()
            .execute(
                "INSERT INTO decisions VALUES(?1,?2)",
                params![effect, serde_json::to_string(&outcome).unwrap()],
            )
            .unwrap();
    }
}

fn temporary(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "determa-worker-{label}-{}-{}.sqlite",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

#[test]
fn actual_worker_preserves_strict_terminal_and_compact_dependency_evidence() {
    let bundle = load_bundle(
        r#"
format: 1
namespace: test.native_worker
events:
  published: { direction: output, payload: {} }
machines:
  - machine_id: publisher
    root:
      entry:
        - send: { event: published, to: { external: true }, correlation_id: '"work"' }
"#,
    )
    .unwrap();
    for mode in [OutboxRetentionMode::Strict, OutboxRetentionMode::Compact] {
        let database = temporary(mode.as_str());
        let native_mode = DurableStoreMode::new(ReceiptRetentionMode::Permanent, mode);
        let store = Arc::new(SqliteExecutionStore::open(&database, native_mode).unwrap());
        store.initialize_schema().unwrap();
        let mut resolver = InMemoryDefinitionResolver::default();
        resolver.insert(bundle.clone(), true);
        let resolver = Arc::new(resolver);
        let host = CheckpointHost::new(store.clone(), resolver.clone());
        let worker_database = temporary("destination");
        let worker = ApplicationWorker::open(worker_database.clone());
        let outcomes = [
            TerminalOutboxOutcome::Confirmed,
            TerminalOutboxOutcome::PermanentlyRejected {
                reason_code: "provider_rejected".into(),
            },
            TerminalOutboxOutcome::OperatorCancelled {
                reason_code: "operator".into(),
            },
            TerminalOutboxOutcome::Discarded {
                reason_code: "policy".into(),
            },
            TerminalOutboxOutcome::DeadLettered {
                reason_code: "quarantine".into(),
            },
        ];
        for (index, outcome) in outcomes.into_iter().enumerate() {
            let root = format!("root-{index}");
            host.create_checkpoint(&bundle, "publisher", &root, &format!("create-{index}"), &Bindings::default(), None,
                json!({"mode":"permanent","permanent_replay_eligible":true,"policy_identifier":null,"pruned_through_receipt_sequence":null})).unwrap();
            let checkpoint = host.load_checkpoint(&root).unwrap().unwrap();
            let effect = checkpoint.value()["pending_outbox_intents"][0]["intent"]["effect_id"]
                .as_str()
                .unwrap()
                .to_owned();
            // No worker may compact unresolved work, even when compact mode is configured.
            let before = store.load(&root).unwrap();
            assert!(host
                .compact_outbox(
                    &root,
                    &effect,
                    &MutationGuard::new(checkpoint.revision(), checkpoint.digest())
                )
                .is_err());
            assert_eq!(store.load(&root).unwrap(), before);
            for state in [
                PendingOutboxState::NotAttempted,
                PendingOutboxState::RetryableFailure {
                    reason_code: "network".into(),
                },
                PendingOutboxState::Ambiguous {
                    reason_code: "acceptance_unknown".into(),
                },
            ] {
                let current = host.load_checkpoint(&root).unwrap().unwrap();
                host.update_pending_outbox(
                    &root,
                    &effect,
                    state,
                    &MutationGuard::new(current.revision(), current.digest()),
                )
                .unwrap();
                let reopened = SqliteExecutionStore::open(&database, native_mode).unwrap();
                assert_eq!(reopened.load(&root).unwrap(), store.load(&root).unwrap());
            }
            if index == 0 {
                worker.finish(&host, &root, &effect, outcome.clone(), true);
                assert_eq!(
                    host.load_checkpoint(&root).unwrap().unwrap().value()["pending_outbox_intents"]
                        .as_array()
                        .unwrap()
                        .len(),
                    1
                );
            }
            let restarted_worker = ApplicationWorker::open(worker_database.clone());
            restarted_worker.finish(&host, &root, &effect, outcome, false);
            let completed = host.load_checkpoint(&root).unwrap().unwrap();
            let terminal_bytes = store.load(&root).unwrap();
            assert_eq!(
                completed.value()["terminal_outbox_records"]
                    .as_array()
                    .unwrap()
                    .len(),
                1
            );
            let compacted = host.compact_outbox(
                &root,
                &effect,
                &MutationGuard::new(completed.revision(), completed.digest()),
            );
            if mode == OutboxRetentionMode::Strict {
                assert!(compacted.is_err());
                assert_eq!(store.load(&root).unwrap(), terminal_bytes);
            } else {
                compacted.unwrap();
                let compact = host.load_checkpoint(&root).unwrap().unwrap();
                assert_eq!(
                    compact.value()["outbox_effect_tombstones"][0]["effect_id"],
                    effect
                );
                assert!(!compact.value()["operation_receipts"]
                    .as_array()
                    .unwrap()
                    .is_empty());
                let mut corrupted = compact.value().clone();
                corrupted["outbox_effect_tombstones"] = json!([]);
                // The producer receipt remains: deleting its effect evidence is forbidden by native store retention.
                let mut replacement = store.load(&root).unwrap().unwrap();
                replacement.bytes = serde_json::to_vec(&corrupted).unwrap();
                assert!(store
                    .compare_and_swap(&root, compact.revision(), compact.digest(), replacement)
                    .unwrap_err()
                    .message
                    .contains("referenced tombstone removal"));
            }
            let reopened = SqliteExecutionStore::open(&database, native_mode).unwrap();
            assert_eq!(reopened.load(&root).unwrap(), store.load(&root).unwrap());
        }
        assert_eq!(
            worker
                .connection()
                .query_row("SELECT COUNT(*) FROM destination", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            worker
                .connection()
                .query_row("SELECT COUNT(*) FROM decisions", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            5
        );
    }
}

#[test]
fn durable_ingress_redelivers_after_commit_before_ack_and_runs_actual_outbox_worker() {
    use sha2::{Digest, Sha256};
    let bundle = load_bundle(
        r#"
format: 1
namespace: test.native_broker_application
events:
  start: { direction: input, payload: {} }
  published: { direction: output, payload: {} }
machines:
  - machine_id: publisher
    root:
      on_events:
        start:
          action:
            - send: { event: published, to: { external: true }, correlation_id: '"work"' }
"#,
    )
    .unwrap();
    let database = temporary("broker-store");
    let mode = DurableStoreMode::new(ReceiptRetentionMode::Permanent, OutboxRetentionMode::Strict);
    let store = Arc::new(SqliteExecutionStore::open(&database, mode).unwrap());
    store.initialize_schema().unwrap();
    let mut resolver = InMemoryDefinitionResolver::default();
    resolver.insert(bundle.clone(), true);
    let resolver = Arc::new(resolver);
    let host = CheckpointHost::new(store.clone(), resolver.clone());
    assert!(host
        .validate_profile(
            determa_state::checkpoint::HostProfile::BrokerIntegrated,
            true
        )
        .is_err());
    host.create_checkpoint(&bundle, "publisher", "broker-root", "create-broker", &Bindings::default(), None,
        json!({"mode":"permanent","permanent_replay_eligible":true,"policy_identifier":null,"pruned_through_receipt_sequence":null})).unwrap();
    let checkpoint = host.load_checkpoint("broker-root").unwrap().unwrap();
    let envelope = json!({"event":"start","event_id":"broker-event","cause_id":"broker-event",
        "source":{"host":true},"target":checkpoint.value()["root_record"]["aggregate_state"]["runtimes"][0]["target_identity"],"payload":["map",[]]});
    let digest = format!(
        "sha256:{:x}",
        Sha256::digest(
            serde_json_canonicalizer::to_vec(&json!([
                "determa-inbox-envelope-digest-1",
                "1",
                "broker-root",
                "input",
                envelope
            ]))
            .unwrap()
        )
    );
    let delivery = json!({"delivery_mode":"input","envelope":envelope,"envelope_digest":digest});
    let worker_database = temporary("broker-ingress");
    let worker = ApplicationWorker::open(worker_database.clone());
    worker.retain_ingress("broker-event", &delivery);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| worker.acknowledge(
            &host,
            "broker-root",
            "broker-event"
        )))
        .is_err()
    );
    assert_eq!(worker.pending_ingress().len(), 1);
    let guard = MutationGuard::new(checkpoint.revision(), checkpoint.digest());
    host.process_checkpoint("broker-root", &delivery, "delayed", &guard)
        .unwrap();
    let committed = store.load("broker-root").unwrap();
    drop(worker); // Simulate loss after native commit and before the broker ack.
    let worker = ApplicationWorker::open(worker_database);
    let reopened = Arc::new(SqliteExecutionStore::open(&database, mode).unwrap());
    let restarted_host = CheckpointHost::new(reopened.clone(), resolver);
    assert_eq!(
        worker.pending_ingress(),
        vec![("broker-event".into(), delivery.clone())]
    );
    restarted_host
        .process_checkpoint("broker-root", &delivery, "delayed", &guard)
        .unwrap();
    assert_eq!(reopened.load("broker-root").unwrap(), committed);
    worker.acknowledge(&restarted_host, "broker-root", "broker-event");
    assert!(worker.pending_ingress().is_empty());
    let ready = restarted_host
        .load_checkpoint("broker-root")
        .unwrap()
        .unwrap();
    assert_eq!(
        ready.value()["pending_outbox_intents"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let effect = ready.value()["pending_outbox_intents"][0]["intent"]["effect_id"]
        .as_str()
        .unwrap();
    worker.finish(
        &restarted_host,
        "broker-root",
        effect,
        TerminalOutboxOutcome::Confirmed,
        false,
    );
    assert_eq!(
        worker
            .connection()
            .query_row("SELECT COUNT(*) FROM destination", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert!(restarted_host
        .load_checkpoint("broker-root")
        .unwrap()
        .unwrap()
        .value()["pending_outbox_intents"]
        .as_array()
        .unwrap()
        .is_empty());
}
