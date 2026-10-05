//! Actual production SQL/transaction cuts; no callback is added to the public API.
use super::*;
use crate::checkpoint::{self, ExecutionStore, SqliteExecutionStore};
use crate::{load_bundle, Bindings, InMemoryDefinitionResolver};
use std::io::{Read, Write};
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

fn checkpoint() -> ExecutionCheckpoint {
    let bundle = load_bundle(
        &json!({"format":1,"namespace":"authority.crash.tests",
        "machines":[{"machine_id":"simple","root":{"type":"composite",
            "initial":{"transition_to":"waiting"},"states":{"waiting":{}}}}]})
        .to_string(),
    )
    .unwrap();
    checkpoint::create(&bundle, "simple", "root", "create", &Bindings::default(), None,
        json!({"mode":"bounded","permanent_replay_eligible":false,"pruned_through_receipt_sequence":null,"policy_identifier":"test-bounded"})).unwrap()
}

fn command(value: &ExecutionCheckpoint) -> (Vec<u8>, Vec<u8>, NativeAuthorityInvocation) {
    let mutation = checkpoint_mutation_bytes(value, None).unwrap();
    let mut request = json!({"interface":"determa.host_authority","interface_version":1,
        "operation":"guarded_commit","operation_id":"create-root","scope_identity":"scope",
        "expected_authority_epoch":"0","expected_scope_generation":"0",
        "arguments":{"mutation_digest":format!("sha256:{:x}", Sha256::digest(&mutation))}});
    request["request_digest"] =
        json!(hash(&json!(["determa-host-authority-request-1", request])).unwrap());
    (
        canonical(&request).unwrap(),
        mutation,
        NativeAuthorityInvocation {
            authenticated_principal: "owner".into(),
            authorized_scopes: BTreeSet::from(["scope".into()]),
            operation_rights: BTreeSet::from(["guarded_commit".into()]),
        },
    )
}

fn fresh() -> (std::path::PathBuf, SqliteLocalAuthority) {
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "determa-authority-crash-{}-{}.sqlite",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let authority = SqliteLocalAuthority::open(&path).unwrap();
    authority.setup_schema().unwrap();
    SqliteExecutionStore::open(&path, DurableStoreMode::bounded())
        .unwrap()
        .initialize_schema()
        .unwrap();
    authority.allocate("scope", "owner", "local-host").unwrap();
    (path, authority)
}

fn ledger(authority: &SqliteLocalAuthority) -> Value {
    let connection = authority.connection.lock().unwrap();
    let bytes: Vec<u8> = connection
        .query_row("SELECT ledger FROM determa_scope_authority", [], |row| {
            row.get(0)
        })
        .unwrap();
    let ledger = strict_json::parse(&bytes).unwrap();
    validate_schema(&connection, &authority.storage_binding).unwrap();
    validate_record(&connection, "scope", &ledger).unwrap();
    ledger
}

#[test]
fn failure_after_actual_checkpoint_staging_rolls_back_checkpoint_and_authority() {
    let (path, authority) = fresh();
    let before = ledger(&authority);
    let value = checkpoint();
    let (request, mutation, caller) = command(&value);
    let record = StoreRecord::from_checkpoint(&value).unwrap();
    let result = authority.perform_native(
        &request,
        &caller,
        Some(&mutation),
        Some("checkpoint"),
        |transaction| {
            apply_checkpoint(transaction, DurableStoreMode::bounded(), &record, None)?;
            assert_eq!(
                crate::checkpoint::load_sqlite_record(transaction, "root").unwrap(),
                Some(record.clone())
            );
            Err(failure("injected failure after actual checkpoint staging"))
        },
    );
    assert!(result.is_err());
    assert_eq!(ledger(&authority), before);
    let store = SqliteExecutionStore::open(&path, DurableStoreMode::bounded()).unwrap();
    assert!(store.load("root").unwrap().is_none());
    let result = authority
        .commit_checkpoint(&request, &caller, DurableStoreMode::bounded(), &value, None)
        .unwrap();
    assert_eq!(result["status"], "accepted");
    assert_eq!(ledger(&authority)["scope_generation"], "1");
    drop(store);
    drop(authority);
    std::fs::remove_file(path).unwrap();
}

fn signal_and_wait(marker: &Path) {
    let mut file = std::fs::File::create(marker).unwrap();
    file.write_all(b"cut reached").unwrap();
    file.sync_all().unwrap();
    loop {
        std::thread::park();
    }
}

#[test]
fn native_crash_child() {
    let Some(path) = std::env::var_os("DETERMA_AUTHORITY_TEST_DATABASE") else {
        return;
    };
    let marker =
        std::path::PathBuf::from(std::env::var_os("DETERMA_AUTHORITY_TEST_MARKER").unwrap());
    let cut = std::env::var("DETERMA_AUTHORITY_TEST_CUT").unwrap();
    let authority = SqliteLocalAuthority::open(std::path::PathBuf::from(path)).unwrap();
    let value = checkpoint();
    let (request, mutation, caller) = command(&value);
    if cut == "staged" {
        let record = StoreRecord::from_checkpoint(&value).unwrap();
        authority
            .perform_native(
                &request,
                &caller,
                Some(&mutation),
                Some("checkpoint"),
                |transaction| {
                    apply_checkpoint(transaction, DurableStoreMode::bounded(), &record, None)?;
                    signal_and_wait(&marker);
                    Ok(())
                },
            )
            .unwrap();
    } else {
        assert_eq!(cut, "committed");
        let result = authority
            .commit_checkpoint(&request, &caller, DurableStoreMode::bounded(), &value, None)
            .unwrap();
        assert_eq!(result["status"], "accepted");
        signal_and_wait(&marker);
    }
}

#[test]
fn sigkill_after_staging_and_after_commit_preserves_atomic_fate_and_retained_replay() {
    for cut in ["staged", "committed"] {
        let (path, authority) = fresh();
        drop(authority);
        let marker = path.with_extension("cut");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "authority::crash_tests::native_crash_child",
                "--nocapture",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .env("DETERMA_AUTHORITY_TEST_DATABASE", &path)
            .env("DETERMA_AUTHORITY_TEST_MARKER", &marker)
            .env("DETERMA_AUTHORITY_TEST_CUT", cut)
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        while !marker.exists() {
            if let Some(status) = child.try_wait().unwrap() {
                let mut diagnostics = String::new();
                child
                    .stderr
                    .take()
                    .unwrap()
                    .read_to_string(&mut diagnostics)
                    .unwrap();
                panic!("child exited before native cut: {status}: {diagnostics}");
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("native cut not reached");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        child.kill().unwrap();
        assert_eq!(child.wait().unwrap().signal(), Some(9));
        let restarted = SqliteLocalAuthority::open(&path).unwrap();
        restarted.setup_schema().unwrap();
        assert!(!restarted.allocate("scope", "owner", "local-host").unwrap());
        let before = ledger(&restarted);
        let value = checkpoint();
        let (request, _, caller) = command(&value);
        let store = SqliteExecutionStore::open(&path, DurableStoreMode::bounded()).unwrap();
        if cut == "staged" {
            assert_eq!(before["scope_generation"], "0");
            assert!(before["receipts"].as_array().unwrap().is_empty());
            assert!(store.load("root").unwrap().is_none());
        } else {
            assert_eq!(before["scope_generation"], "1");
            assert_eq!(
                store.load("root").unwrap().unwrap(),
                StoreRecord::from_checkpoint(&value).unwrap()
            );
        }
        let result = restarted
            .commit_checkpoint(&request, &caller, DurableStoreMode::bounded(), &value, None)
            .unwrap();
        assert_eq!(result["status"], "accepted");
        let after = ledger(&restarted);
        assert_eq!(after["scope_generation"], "1");
        assert_eq!(after["receipts"].as_array().unwrap().len(), 1);
        let replay = restarted
            .commit_checkpoint(&request, &caller, DurableStoreMode::bounded(), &value, None)
            .unwrap();
        assert_eq!(result, replay);
        assert_eq!(ledger(&restarted), after);
        if cut == "committed" {
            assert_eq!(after, before);
        }
        // Restore-validation still succeeds at the surviving native checkpoint.
        let mut resolver = InMemoryDefinitionResolver::default();
        let bundle = load_bundle(
            &json!({"format":1,"namespace":"authority.crash.tests",
            "machines":[{"machine_id":"simple","root":{"type":"composite",
                "initial":{"transition_to":"waiting"},"states":{"waiting":{}}}}]})
            .to_string(),
        )
        .unwrap();
        resolver.insert(bundle, true);
        checkpoint::restore(&store.load("root").unwrap().unwrap().bytes, &resolver).unwrap();
        drop(store);
        drop(restarted);
        std::fs::remove_file(marker).unwrap();
        std::fs::remove_file(path).unwrap();
    }
}
