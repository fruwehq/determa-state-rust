#![cfg(feature = "sqlite")]

use determa_state::authority::{
    checkpoint_mutation_bytes, GuardedSqliteExecutionStore, NativeAuthorityInvocation,
    SqliteLocalAuthority,
};
use determa_state::checkpoint::{
    self, CheckpointHost, DurableStoreMode, ExecutionStore, ExecutionStoreCapability,
    MutationGuard, OutboxRetentionMode, ReceiptRetentionMode, SqliteExecutionStore, StoreRecord,
};
use determa_state::{load_bundle, Bindings, InMemoryDefinitionResolver};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[test]
fn production_checkpoint_host_uses_guarded_store_and_survives_restart() {
    let file = path();
    let bundle = load_bundle(
        &json!({"format":1,"namespace":"authority.host.tests",
        "events":{"received":{"direction":"input"}},"machines":[{"machine_id":"counter",
        "root":{"type":"composite","initial":{"transition_to":"waiting"},
            "states":{"waiting":{"on_events":{"received":{}}}}}}]})
        .to_string(),
    )
    .unwrap();
    let mut resolver = InMemoryDefinitionResolver::default();
    resolver.insert(bundle.clone(), true);
    let resolver = Arc::new(resolver);
    let mode = DurableStoreMode::bounded();
    let store = Arc::new(
        GuardedSqliteExecutionStore::open(
            &file,
            mode,
            "scope".to_owned(),
            "owner".to_owned(),
            "local-host".to_owned(),
            resolver.clone(),
        )
        .unwrap(),
    );
    store.initialize_schema().unwrap();
    assert!(store.allocate_scope().unwrap());
    assert!(!store
        .capabilities()
        .contains(&ExecutionStoreCapability::SharedApplicationTransaction));
    let host = CheckpointHost::new(store.clone(), resolver.clone());
    host.create_checkpoint(&bundle, "counter", "root", "create", &Bindings::default(), None,
        json!({"mode":"bounded","permanent_replay_eligible":false,"pruned_through_receipt_sequence":null,"policy_identifier":"test-bounded"})).unwrap();
    let created = host.load_checkpoint("root").unwrap().unwrap();
    let envelope = json!({"event":"received","event_id":"event-A","cause_id":"event-A",
        "source":{"host":true},"target":{"root":{"root_instance_id":"root",
            "root_runtime_id":created.value()["root_record"]["aggregate_state"]["root_runtime_id"]}},
        "payload":["map",[]]});
    let digest = format!(
        "sha256:{:x}",
        Sha256::digest(
            serde_json_canonicalizer::to_vec(&json!([
                "determa-inbox-envelope-digest-1",
                "1",
                "root",
                "input",
                envelope
            ]))
            .unwrap()
        )
    );
    let delivery = json!({"delivery_mode":"input","envelope":envelope,"envelope_digest":digest});
    let admitted = host
        .admit_checkpoint(
            "root",
            &[delivery],
            &MutationGuard::new(created.revision(), created.digest()),
        )
        .unwrap();
    drop(host);
    drop(store);
    let restarted = Arc::new(
        GuardedSqliteExecutionStore::open(
            &file,
            mode,
            "scope".to_owned(),
            "owner".to_owned(),
            "local-host".to_owned(),
            resolver.clone(),
        )
        .unwrap(),
    );
    restarted.initialize_schema().unwrap();
    assert!(!restarted.allocate_scope().unwrap());
    let host = CheckpointHost::new(restarted.clone(), resolver.clone());
    assert_eq!(
        host.load_checkpoint("root").unwrap().unwrap().value(),
        &admitted
    );
    let connection = rusqlite::Connection::open(&file).unwrap();
    let bytes: Vec<u8> = connection
        .query_row("SELECT ledger FROM determa_scope_authority", [], |row| {
            row.get(0)
        })
        .unwrap();
    let ledger: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(ledger["scope_generation"], "2");
    assert_eq!(ledger["receipts"].as_array().unwrap().len(), 2);
    let invalid = StoreRecord {
        root_instance_id: "invalid-root".to_owned(),
        revision: "0".to_owned(),
        execution_checkpoint_digest: format!("sha256:{}", "0".repeat(64)),
        bytes: serde_json_canonicalizer::to_vec(
            &json!({"root_instance_id":"invalid-root", "revision":"0",
            "execution_checkpoint_digest":format!("sha256:{}", "0".repeat(64))}),
        )
        .unwrap(),
    };
    assert!(restarted.insert_if_absent(invalid).is_err());
    let after: Vec<u8> = connection
        .query_row("SELECT ledger FROM determa_scope_authority", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(bytes, after);
    let wrong_owner = GuardedSqliteExecutionStore::open(
        &file,
        mode,
        "scope".to_owned(),
        "owner".to_owned(),
        "other-host".to_owned(),
        resolver.clone(),
    )
    .unwrap();
    assert!(wrong_owner.load("root").is_err());
    let untracked = checkpoint::create(
        &bundle,
        "counter",
        "untracked-root",
        "untracked-create",
        &Bindings::default(),
        None,
        created.value()["replay_retention"].clone(),
    )
    .unwrap();
    let untracked_record = StoreRecord::from_checkpoint(&untracked).unwrap();
    let raw = SqliteExecutionStore::open(&file, mode).unwrap();
    assert_eq!(
        raw.insert_if_absent(untracked_record.clone()).unwrap(),
        checkpoint::StoreWriteResult::Committed
    );
    assert!(restarted.load("root").is_err());
    drop(raw);

    let fresh_file = path();
    let fresh = GuardedSqliteExecutionStore::open(
        &fresh_file,
        mode,
        "fresh".to_owned(),
        "owner".to_owned(),
        "local-host".to_owned(),
        resolver,
    )
    .unwrap();
    fresh.initialize_schema().unwrap();
    let imported = SqliteExecutionStore::open(&fresh_file, mode).unwrap();
    imported.insert_if_absent(untracked_record.clone()).unwrap();
    assert!(fresh.allocate_scope().is_err());
    assert_eq!(
        imported.load("untracked-root").unwrap(),
        Some(untracked_record)
    );
    let bootstrap = rusqlite::Connection::open(&fresh_file).unwrap();
    let allocations: u64 = bootstrap
        .query_row(
            "SELECT COUNT(*) FROM determa_scope_allocations",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(allocations, 0);
    drop(bootstrap);
    drop(imported);
    drop(fresh);
    std::fs::remove_file(fresh_file).unwrap();
    drop(wrong_owner);
    drop(connection);
    drop(host);
    drop(restarted);
    std::fs::remove_file(file).unwrap();
}

fn path() -> std::path::PathBuf {
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "determa-authority-{}-{}.sqlite",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ))
}
fn invocation(principal: &str) -> NativeAuthorityInvocation {
    NativeAuthorityInvocation {
        authenticated_principal: principal.to_owned(),
        authorized_scopes: BTreeSet::from(["scope".to_owned()]),
        operation_rights: BTreeSet::from([
            "read_authority".to_owned(),
            "guarded_commit".to_owned(),
        ]),
    }
}
fn sealed(mut request: Value) -> Value {
    request.as_object_mut().unwrap().remove("request_digest");
    let bytes =
        serde_json_canonicalizer::to_vec(&json!(["determa-host-authority-request-1", request]))
            .unwrap();
    request["request_digest"] = json!(format!("sha256:{:x}", Sha256::digest(bytes)));
    request
}
fn request(operation: &str, identifier: &str, mutation: &[u8]) -> Value {
    sealed(
        json!({"interface": "determa.host_authority", "interface_version": 1,
        "operation": operation, "operation_id": identifier, "scope_identity": "scope",
        "expected_authority_epoch": if operation == "read_authority" { Value::Null } else { json!("0") },
        "expected_scope_generation": if operation == "read_authority" { Value::Null } else { json!("0") },
        "arguments": if operation == "read_authority" { json!({}) } else { json!({"mutation_digest": format!("sha256:{:x}", Sha256::digest(mutation))}) }}),
    )
}

#[test]
fn actual_checkpoint_cas_and_authority_receipt_share_one_native_commit() {
    let file = path();
    let authority = SqliteLocalAuthority::open(&file).unwrap();
    authority.setup_schema().unwrap();
    authority.allocate("scope", "owner", "local-host").unwrap();
    let mode = DurableStoreMode::new(
        ReceiptRetentionMode::Permanent,
        OutboxRetentionMode::Bounded,
    );
    let store = SqliteExecutionStore::open(&file, mode).unwrap();
    store.initialize_schema().unwrap();
    let bundle = load_bundle(
        &json!({"format":1,"namespace":"authority.checkpoint.tests",
        "events":{"received":{"direction":"input"}},"machines":[{"machine_id":"counter",
        "root":{"type":"composite","initial":{"transition_to":"waiting"},
            "states":{"waiting":{"on_events":{"received":{}}}}}}]})
        .to_string(),
    )
    .unwrap();
    let created = checkpoint::create(&bundle,"counter","root","create", &Bindings::default(), None,
        json!({"mode":"permanent","permanent_replay_eligible":true,"pruned_through_receipt_sequence":null,"policy_identifier":null})).unwrap();
    let native = StoreRecord::from_checkpoint(&created).unwrap();
    let mutation = checkpoint_mutation_bytes(&created, None).unwrap();
    let insert = request("guarded_commit", "insert", &mutation);
    let accepted = authority
        .commit_checkpoint(
            &serde_json_canonicalizer::to_vec(&insert).unwrap(),
            &invocation("owner"),
            mode,
            &created,
            None,
        )
        .unwrap();
    assert_eq!(accepted["status"], "accepted");
    assert_eq!(store.load("root").unwrap(), Some(native.clone()));
    assert_eq!(
        authority
            .commit_checkpoint(
                &serde_json_canonicalizer::to_vec(&insert).unwrap(),
                &invocation("owner"),
                mode,
                &created,
                None
            )
            .unwrap(),
        accepted
    );

    let runtime = created.value()["root_record"]["aggregate_state"]["root_runtime_id"].clone();
    let envelope = json!({"event":"received","event_id":"event-A","cause_id":"event-A",
        "source":{"host":true},"target":{"root":{"root_instance_id":"root","root_runtime_id":runtime}},
        "payload":["map",[]]});
    let digest_bytes = serde_json_canonicalizer::to_vec(&json!([
        "determa-inbox-envelope-digest-1",
        "1",
        "root",
        "input",
        envelope
    ]))
    .unwrap();
    let delivery = json!({"delivery_mode":"input","envelope":envelope,
        "envelope_digest":format!("sha256:{:x}",Sha256::digest(digest_bytes))});
    let admitted = checkpoint::admit(
        &bundle,
        &created,
        &[delivery],
        Some(created.revision()),
        Some(created.digest()),
    )
    .unwrap();
    let mut resolver = InMemoryDefinitionResolver::default();
    resolver.insert(bundle, true);
    let restored = checkpoint::restore(
        &serde_json_canonicalizer::to_vec(&admitted).unwrap(),
        &resolver,
    )
    .unwrap();
    let replacement = StoreRecord::from_checkpoint(&restored).unwrap();
    let guard = MutationGuard::new(created.revision(), created.digest());
    let mutation = checkpoint_mutation_bytes(&restored, Some(&guard)).unwrap();
    let mut replace = request("guarded_commit", "replace", &mutation);
    replace["expected_scope_generation"] = json!("1");
    replace = sealed(replace);

    // Unexpected authority schema refuses before either native write.
    let connection = rusqlite::Connection::open(&file).unwrap();
    connection.execute_batch("CREATE TRIGGER injected_native_failure BEFORE INSERT ON determa_authority_mutations BEGIN SELECT RAISE(ABORT, 'injected failure'); END;").unwrap();
    assert_eq!(
        authority
            .commit_checkpoint(
                &serde_json_canonicalizer::to_vec(&replace).unwrap(),
                &invocation("owner"),
                mode,
                &restored,
                Some(&guard)
            )
            .unwrap()["error_code"],
        "host_capability_mismatch"
    );
    assert_eq!(store.load("root").unwrap(), Some(native.clone()));
    connection
        .execute_batch("DROP TRIGGER injected_native_failure;")
        .unwrap();
    connection.execute_batch("CREATE TRIGGER unexpected_checkpoint_writer AFTER UPDATE ON determa_execution_checkpoints BEGIN SELECT RAISE(ABORT, 'unexpected writer'); END;").unwrap();
    assert!(authority
        .commit_checkpoint(
            &serde_json_canonicalizer::to_vec(&replace).unwrap(),
            &invocation("owner"),
            mode,
            &restored,
            Some(&guard)
        )
        .is_err());
    assert_eq!(store.load("root").unwrap(), Some(native.clone()));
    connection
        .execute_batch("DROP TRIGGER unexpected_checkpoint_writer;")
        .unwrap();
    let wrong_guard = MutationGuard::new("999", created.digest());
    let wrong_mutation = checkpoint_mutation_bytes(&restored, Some(&wrong_guard)).unwrap();
    let mut wrong_cas = request("guarded_commit", "wrong-cas", &wrong_mutation);
    wrong_cas["expected_scope_generation"] = json!("1");
    wrong_cas = sealed(wrong_cas);
    assert!(authority
        .commit_checkpoint(
            &serde_json_canonicalizer::to_vec(&wrong_cas).unwrap(),
            &invocation("owner"),
            mode,
            &restored,
            Some(&wrong_guard)
        )
        .is_err());
    assert_eq!(store.load("root").unwrap(), Some(native.clone()));
    assert_eq!(
        perform(
            &authority,
            &request("read_authority", "before-replace", b""),
            "owner",
            None
        )["scope_generation"],
        "1"
    );
    let updated = authority
        .commit_checkpoint(
            &serde_json_canonicalizer::to_vec(&replace).unwrap(),
            &invocation("owner"),
            mode,
            &restored,
            Some(&guard),
        )
        .unwrap();
    assert_eq!(updated["scope_generation"], "2");
    assert_eq!(store.load("root").unwrap(), Some(replacement.clone()));
    assert_eq!(
        perform(
            &authority,
            &request("read_authority", "read", b""),
            "owner",
            None
        )["scope_generation"],
        "2"
    );
    let saved: Vec<u8> = connection
        .query_row("SELECT ledger FROM determa_scope_authority", [], |row| {
            row.get(0)
        })
        .unwrap();
    let mut altered: Value = serde_json::from_slice(&saved).unwrap();
    altered["receipts"][1]
        .as_object_mut()
        .unwrap()
        .remove("native_kind");
    connection
        .execute(
            "UPDATE determa_scope_authority SET ledger=?",
            [serde_json_canonicalizer::to_vec(&altered).unwrap()],
        )
        .unwrap();
    assert_eq!(
        perform(
            &authority,
            &request("read_authority", "erased-binding", b""),
            "owner",
            None
        )["error_code"],
        "host_capability_mismatch"
    );
    connection
        .execute("UPDATE determa_scope_authority SET ledger=?", [saved])
        .unwrap();
    // Even canonical old checkpoint bytes cannot stand for the latest native commit.
    connection.execute("UPDATE determa_execution_checkpoints SET revision=?,checkpoint_digest=?,checkpoint_bytes=? WHERE root_instance_id='root'",
        rusqlite::params![native.revision, native.execution_checkpoint_digest, native.bytes]).unwrap();
    assert_eq!(
        perform(
            &authority,
            &request("read_authority", "tampered-read", b""),
            "owner",
            None
        )["error_code"],
        "host_capability_mismatch"
    );
    assert_eq!(
        authority
            .commit_checkpoint(
                &serde_json_canonicalizer::to_vec(&replace).unwrap(),
                &invocation("owner"),
                mode,
                &restored,
                Some(&guard)
            )
            .unwrap()["error_code"],
        "host_capability_mismatch"
    );
    drop(connection);
    drop(store);
    drop(authority);
    std::fs::remove_file(file).unwrap();
}

#[test]
fn damaged_existing_authority_is_never_reinitialized() {
    for table in ["determa_authority_boundary", "determa_scope_allocations"] {
        let source = path();
        let copied = path();
        let authority = SqliteLocalAuthority::open(&source).unwrap();
        authority.setup_schema().unwrap();
        authority.allocate("scope", "owner", "local-host").unwrap();
        let native = rusqlite::Connection::open(&source).unwrap();
        native
            .execute("VACUUM INTO ?", [copied.to_str().unwrap()])
            .unwrap();
        let damaged = rusqlite::Connection::open(&copied).unwrap();
        damaged.execute(&format!("DROP TABLE {table}"), []).unwrap();
        let before: Vec<u8> = damaged
            .query_row("SELECT ledger FROM determa_scope_authority", [], |row| {
                row.get(0)
            })
            .unwrap();
        let inert = SqliteLocalAuthority::open(&copied).unwrap();
        assert!(inert.setup_schema().is_err());
        let count: u64 = damaged
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE name=?",
                [table],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
        let after: Vec<u8> = damaged
            .query_row("SELECT ledger FROM determa_scope_authority", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(before, after);
        assert_eq!(
            perform(
                &authority,
                &request("read_authority", "read", b""),
                "owner",
                None
            )["status"],
            "accepted"
        );
        drop(inert);
        drop(damaged);
        drop(native);
        drop(authority);
        std::fs::remove_file(source).unwrap();
        std::fs::remove_file(copied).unwrap();
    }
}

#[test]
fn canonical_ledger_or_native_mutation_corruption_refuses_read_replay_and_commit() {
    for corruption in [
        "result", "request", "digest", "scope", "owner", "delete", "bytes",
    ] {
        let file = path();
        let authority = SqliteLocalAuthority::open(&file).unwrap();
        authority.setup_schema().unwrap();
        authority.allocate("scope", "owner", "local-host").unwrap();
        let command = request("guarded_commit", "first", b"native mutation");
        assert_eq!(
            perform(&authority, &command, "owner", Some(b"native mutation"))["status"],
            "accepted"
        );
        let native = rusqlite::Connection::open(&file).unwrap();
        let bytes: Vec<u8> = native
            .query_row("SELECT ledger FROM determa_scope_authority", [], |row| {
                row.get(0)
            })
            .unwrap();
        let mut ledger: Value = serde_json::from_slice(&bytes).unwrap();
        match corruption {
            "result" => ledger["receipts"][0]["result"]["scope_generation"] = json!("999"),
            "request" => ledger["receipts"][0]["request"]["operation_id"] = json!("forged"),
            "digest" => {
                ledger["receipts"][0]["request_digest"] =
                    json!(format!("sha256:{}", "0".repeat(64)))
            }
            "scope" => ledger["scope_identity"] = json!("different"),
            "owner" => ledger["owner_binding"]["owner_principal"] = json!("different"),
            "delete" => {
                native
                    .execute("DELETE FROM determa_authority_mutations", [])
                    .unwrap();
            }
            "bytes" => {
                native
                    .execute(
                        "UPDATE determa_authority_mutations SET mutation=?",
                        [b"forged".as_slice()],
                    )
                    .unwrap();
            }
            _ => unreachable!(),
        }
        native
            .execute(
                "UPDATE determa_scope_authority SET ledger=?",
                [serde_json_canonicalizer::to_vec(&ledger).unwrap()],
            )
            .unwrap();
        let mut next = request("guarded_commit", "next", b"next");
        next["expected_scope_generation"] = json!("1");
        next = sealed(next);
        for (attempt, mutation) in [
            (request("read_authority", "read", b""), None),
            (command.clone(), None),
            (next, Some(b"next".as_slice())),
        ] {
            let result = perform(&authority, &attempt, "owner", mutation);
            assert_eq!(
                result["error_code"], "host_capability_mismatch",
                "{corruption}"
            );
            assert!(result["scope_generation"].is_null(), "{corruption}");
        }
        let count: u64 = native
            .query_row(
                "SELECT COUNT(*) FROM determa_authority_mutations WHERE operation_id='next'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
        drop(native);
        drop(authority);
        std::fs::remove_file(file).unwrap();
    }
}
fn perform(
    authority: &SqliteLocalAuthority,
    request: &Value,
    principal: &str,
    mutation: Option<&[u8]>,
) -> Value {
    authority
        .perform(
            &serde_json_canonicalizer::to_vec(request).unwrap(),
            &invocation(principal),
            mutation,
        )
        .unwrap()
}

#[test]
fn native_commit_and_first_receipt_survive_restart_and_exact_replay() {
    let file = path();
    let authority = SqliteLocalAuthority::open(&file).unwrap();
    authority.setup_schema().unwrap();
    assert!(authority.allocate("scope", "owner", "local-host").unwrap());
    let command = request("guarded_commit", "commit-a", b"native mutation");
    let result = perform(&authority, &command, "owner", Some(b"native mutation"));
    assert_eq!(result["status"], "accepted");
    assert_eq!(result["scope_generation"], "1");
    drop(authority);
    let restarted = SqliteLocalAuthority::open(&file).unwrap();
    assert_eq!(perform(&restarted, &command, "owner", None), result);
    let connection = rusqlite::Connection::open(&file).unwrap();
    let rows: u64 = connection
        .query_row(
            "SELECT COUNT(*) FROM determa_authority_mutations",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(rows, 1);
    let stored: Vec<u8> = connection
        .query_row(
            "SELECT mutation FROM determa_authority_mutations",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(stored, b"native mutation");
    let changed = request("guarded_commit", "commit-a", b"changed mutation");
    assert_eq!(
        perform(&restarted, &changed, "owner", Some(b"changed mutation"))["error_code"],
        "scope_operation_conflict"
    );
    let stale = request("guarded_commit", "commit-b", b"native mutation");
    assert_eq!(
        perform(&restarted, &stale, "owner", Some(b"native mutation"))["error_code"],
        "scope_generation_conflict"
    );
    drop(connection);
    drop(restarted);
    std::fs::remove_file(file).unwrap();
}

#[test]
fn authorized_scope_and_owner_checks_precede_mutation_and_replay_disclosure() {
    let file = path();
    let authority = SqliteLocalAuthority::open(&file).unwrap();
    authority.setup_schema().unwrap();
    authority.allocate("scope", "owner", "local-host").unwrap();
    let command = request("guarded_commit", "commit-a", b"native mutation");
    assert_eq!(
        perform(
            &authority,
            &command,
            "different-owner",
            Some(b"native mutation")
        )["error_code"],
        "stale_scope_authority"
    );
    let mut context = invocation("owner");
    context.authorized_scopes.clear();
    let rejected = authority
        .perform(
            &serde_json_canonicalizer::to_vec(&command).unwrap(),
            &context,
            Some(b"native mutation"),
        )
        .unwrap();
    assert_eq!(rejected["error_code"], "unauthorized_scope");
    assert!(rejected["scope_identity"].is_null());
    assert!(rejected["scope_generation"].is_null());
    let read = request("read_authority", "read-a", b"");
    assert_eq!(
        perform(&authority, &read, "owner", None)["scope_generation"],
        "0"
    );
    drop(authority);
    std::fs::remove_file(file).unwrap();
}

#[test]
fn allocation_evidence_cannot_be_deleted_or_reused_after_ledger_removal() {
    let file = path();
    let authority = SqliteLocalAuthority::open(&file).unwrap();
    authority.setup_schema().unwrap();
    assert!(authority.allocate("scope", "owner", "local-host").unwrap());
    let connection = rusqlite::Connection::open(&file).unwrap();
    assert!(connection
        .execute("DELETE FROM determa_scope_allocations", [])
        .is_err());
    assert!(connection
        .execute(
            "UPDATE determa_scope_allocations SET scope_identity='replacement'",
            []
        )
        .is_err());
    connection
        .execute("DELETE FROM determa_scope_authority", [])
        .unwrap();
    assert!(!authority.allocate("scope", "owner", "local-host").unwrap());
    assert!(!authority
        .allocate("replacement", "owner", "local-host")
        .unwrap());
    drop(connection);
    drop(authority);
    std::fs::remove_file(file).unwrap();
}

#[test]
fn independent_native_sessions_have_one_generation_cas_winner() {
    let file = path();
    let first = SqliteLocalAuthority::open(&file).unwrap();
    first.setup_schema().unwrap();
    first.allocate("scope", "owner", "local-host").unwrap();
    let second = SqliteLocalAuthority::open(&file).unwrap();
    let outcomes = std::thread::scope(|scope| {
        let a = scope.spawn(|| {
            perform(
                &first,
                &request("guarded_commit", "first", b"a"),
                "owner",
                Some(b"a"),
            )
        });
        let b = scope.spawn(|| {
            perform(
                &second,
                &request("guarded_commit", "second", b"b"),
                "owner",
                Some(b"b"),
            )
        });
        vec![a.join().unwrap(), b.join().unwrap()]
    });
    assert_eq!(
        outcomes
            .iter()
            .filter(|x| x["status"] == "accepted")
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|x| x["error_code"] == "scope_generation_conflict")
            .count(),
        1
    );
    drop(first);
    drop(second);
    std::fs::remove_file(file).unwrap();
}

#[test]
fn request_shape_and_native_mutation_digest_refuse_without_a_commit() {
    let file = path();
    let authority = SqliteLocalAuthority::open(&file).unwrap();
    authority.setup_schema().unwrap();
    authority.allocate("scope", "owner", "local-host").unwrap();
    let command = request("guarded_commit", "commit-a", b"expected mutation");
    assert_eq!(
        perform(&authority, &command, "owner", Some(b"different mutation"))["error_code"],
        "invalid_host_request"
    );
    let invalid = authority
        .perform(
            br#"{"interface":"determa.host_authority","interface":"duplicate"}"#,
            &invocation("owner"),
            None,
        )
        .unwrap();
    assert_eq!(invalid["error_code"], "invalid_host_request");
    assert!(invalid["operation"].is_null());
    assert_eq!(
        perform(
            &authority,
            &request("read_authority", "read-a", b""),
            "owner",
            None
        )["scope_generation"],
        "0"
    );
    drop(authority);
    std::fs::remove_file(file).unwrap();
}

#[test]
fn copied_database_is_inactive_even_with_matching_scope_and_owner() {
    let source = path();
    let copied = path();
    let authority = SqliteLocalAuthority::open(&source).unwrap();
    authority.setup_schema().unwrap();
    authority.allocate("scope", "owner", "local-host").unwrap();
    let native = rusqlite::Connection::open(&source).unwrap();
    native
        .execute("VACUUM INTO ?", [copied.to_str().unwrap()])
        .unwrap();
    let inert = SqliteLocalAuthority::open(&copied).unwrap();
    assert!(inert.validate_schema().is_err());
    assert!(inert.setup_schema().is_err());
    let result = perform(
        &inert,
        &request("guarded_commit", "copied-write", b"mutation"),
        "owner",
        Some(b"mutation"),
    );
    assert_eq!(result["error_code"], "host_capability_mismatch");
    assert!(result["scope_generation"].is_null());
    assert_eq!(
        perform(
            &authority,
            &request("read_authority", "read-a", b""),
            "owner",
            None
        )["scope_generation"],
        "0"
    );
    drop(native);
    drop(inert);
    drop(authority);
    std::fs::remove_file(source).unwrap();
    std::fs::remove_file(copied).unwrap();
}

#[test]
fn unexpected_trigger_invalidates_authority_before_native_mutation() {
    let file = path();
    let authority = SqliteLocalAuthority::open(&file).unwrap();
    authority.setup_schema().unwrap();
    authority.allocate("scope", "owner", "local-host").unwrap();
    let connection = rusqlite::Connection::open(&file).unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER extra BEFORE UPDATE ON determa_scope_authority BEGIN SELECT 1; END",
        )
        .unwrap();
    assert_eq!(
        perform(
            &authority,
            &request("guarded_commit", "write", b"mutation"),
            "owner",
            Some(b"mutation")
        )["error_code"],
        "host_capability_mismatch"
    );
    let mutations: u64 = connection
        .query_row(
            "SELECT COUNT(*) FROM determa_authority_mutations",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(mutations, 0);
    drop(connection);
    drop(authority);
    std::fs::remove_file(file).unwrap();
}
