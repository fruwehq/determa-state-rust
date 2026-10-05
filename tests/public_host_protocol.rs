use determa_state::public_host::{request_digest, validate_message};
use serde_json::Value;
use std::{env, fs, path::PathBuf};

fn spec_root() -> PathBuf {
    env::var_os("DETERMA_SPEC_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("authoritative-spec"))
}

fn conformance_root() -> PathBuf {
    env::var_os("DETERMA_CONFORMANCE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("conformance-suite"))
}

fn fixture(name: &str) -> Value {
    let root = spec_root();
    serde_json::from_slice(&fs::read(root.join("examples/public-host").join(name)).unwrap())
        .unwrap()
}

#[test]
fn complete_public_positive_schema_and_request_hash_matrix() {
    let fixture = fixture("positive-v1.json");
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 33);
    for case in cases {
        validate_message(&case["request"], false).unwrap();
        validate_message(&case["response"], true).unwrap();
        assert_eq!(
            request_digest(&case["request"]).unwrap(),
            case["request_digest"]
        );
        let operand =
            serde_json::json!(["determa-public-host-request-digest-1", "1", case["request"]]);
        assert_eq!(
            String::from_utf8(serde_json_canonicalizer::to_vec(&operand).unwrap()).unwrap(),
            case["request_hash_operand_jcs"]
        );
    }
}

#[test]
fn public_schema_rejects_negative_response_shapes() {
    let fixture = fixture("negative-v1.json");
    for case in fixture["invalid_responses"].as_array().unwrap() {
        if case["expected_error"] == "schema_validation" {
            assert!(
                validate_message(&case["response"], true).is_err(),
                "{}",
                case["name"]
            );
        }
    }
}

#[cfg(feature = "sqlite")]
#[test]
fn local_sqlite_host_executes_exact_public_core_goldens() {
    use determa_state::public_host::SqlitePublicExecutionHost;
    use determa_state::{load_bundle, InMemoryDefinitionResolver};
    use std::collections::BTreeSet;
    let spec = spec_root();
    let conformance = conformance_root();
    let bundle = load_bundle(
        &fs::read_to_string(
            conformance
                .join("conformance/core/119-native-v1-aggregate-integrity/root-machine.yaml"),
        )
        .unwrap(),
    )
    .unwrap();
    let mut resolver = InMemoryDefinitionResolver::default();
    resolver.insert(bundle, true);
    let directory =
        env::temp_dir().join(format!("determa-public-host-core-{}", std::process::id()));
    fs::create_dir_all(&directory).unwrap();
    let host = SqlitePublicExecutionHost::new(
        directory.join("host.db"),
        "scope".into(),
        "binding-local-1".into(),
        BTreeSet::from(["alice".into()]),
        resolver,
    )
    .unwrap();
    host.setup_schema().unwrap();
    let goldens: Value = serde_json::from_slice(
        &fs::read(spec.join("examples/public-host/positive-v1.json")).unwrap(),
    )
    .unwrap();
    let names = [
        "create_committed",
        "read_existing_checkpoint",
        "inspect_absent_target_in_checkpoint",
        "process_empty_mailbox",
        "retained_operation_receipt",
    ];
    let mut observed = 0;
    for case in goldens["cases"].as_array().unwrap() {
        if names.contains(&case["name"].as_str().unwrap()) {
            assert_eq!(
                host.handle(&case["request"], "alice").unwrap(),
                case["response"],
                "{}",
                case["name"]
            );
            observed += 1;
        }
    }
    assert_eq!(observed, names.len());
    drop(host);
    fs::remove_dir_all(directory).unwrap();
}

#[cfg(feature = "sqlite")]
#[test]
fn local_sqlite_host_executes_exact_delivery_goldens() {
    use determa_state::public_host::SqlitePublicExecutionHost;
    use determa_state::{load_bundle, InMemoryDefinitionResolver};
    use std::collections::BTreeSet;
    let spec = spec_root();
    let bundle = load_bundle(
        &fs::read_to_string(spec.join("examples/portable-event-deferral.yaml")).unwrap(),
    )
    .unwrap();
    let goldens = fixture("positive-v1.json");
    for (name, source, initial) in [
        (
            "admit_declared_event",
            "execution-checkpoint-transfer-v1.json",
            "before_admission",
        ),
        (
            "process_unhandled_event",
            "execution-checkpoint-transfer-v1.json",
            "after_admission",
        ),
        (
            "process_deferred_event",
            "queue-placement-checkpoints-v1.json",
            "after_second_admission",
        ),
        (
            "process_recall_event",
            "queue-placement-checkpoints-v1.json",
            "after_received_admission",
        ),
    ] {
        let mut resolver = InMemoryDefinitionResolver::default();
        resolver.insert(bundle.clone(), true);
        let snapshots: Value =
            serde_json::from_slice(&fs::read(spec.join("examples/delivery").join(source)).unwrap())
                .unwrap();
        let checkpoint = &snapshots[initial];
        let bytes = serde_json_canonicalizer::to_vec(checkpoint).unwrap();
        determa_state::checkpoint::restore(&bytes, &resolver).unwrap();
        let directory =
            env::temp_dir().join(format!("determa-public-host-{name}-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("host.db");
        let host = SqlitePublicExecutionHost::new(
            &path,
            "scope".into(),
            "binding-local-1".into(),
            BTreeSet::from(["alice".into()]),
            resolver,
        )
        .unwrap();
        host.setup_schema().unwrap();
        let db = rusqlite::Connection::open(&path).unwrap();
        db.execute(
            "INSERT INTO determa_public_host_checkpoints VALUES (?,?)",
            rusqlite::params![checkpoint["root_instance_id"].as_str().unwrap(), bytes],
        )
        .unwrap();
        drop(db);
        let case = goldens["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == name)
            .unwrap();
        assert_eq!(
            host.handle(&case["request"], "alice").unwrap(),
            case["response"],
            "{name}"
        );
        assert_eq!(
            host.handle(&case["request"], "alice").unwrap(),
            case["response"],
            "{name}: exact replay"
        );
        drop(host);
        fs::remove_dir_all(directory).unwrap();
    }
}

#[cfg(feature = "sqlite")]
#[test]
fn native_local_host_replay_precedes_resolver_and_authorization_precedes_existence() {
    use determa_state::format1::ResolvedDefinition;
    use determa_state::public_host::SqlitePublicExecutionHost;
    use determa_state::{load_bundle, DefinitionResolver, InMemoryDefinitionResolver};
    use std::{
        collections::BTreeSet,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
    };
    struct CountingResolver {
        inner: InMemoryDefinitionResolver,
        calls: Arc<AtomicUsize>,
    }
    impl DefinitionResolver for CountingResolver {
        fn resolve_definition(&self, fingerprint: &str) -> Option<ResolvedDefinition> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.inner.resolve_definition(fingerprint)
        }
    }
    let conformance = conformance_root();
    let bundle = load_bundle(
        &fs::read_to_string(
            conformance
                .join("conformance/core/119-native-v1-aggregate-integrity/root-machine.yaml"),
        )
        .unwrap(),
    )
    .unwrap();
    let mut resolver = InMemoryDefinitionResolver::default();
    resolver.insert(bundle, true);
    let calls = Arc::new(AtomicUsize::new(0));
    let directory =
        env::temp_dir().join(format!("determa-public-host-replay-{}", std::process::id()));
    fs::create_dir_all(&directory).unwrap();
    let path = directory.join("host.db");
    let host = SqlitePublicExecutionHost::new(
        &path,
        "scope".into(),
        "binding-local-1".into(),
        BTreeSet::from(["alice".into()]),
        CountingResolver {
            inner: resolver,
            calls: calls.clone(),
        },
    )
    .unwrap();
    host.setup_schema().unwrap();
    let goldens = fixture("positive-v1.json");
    let cases = goldens["cases"].as_array().unwrap();
    let create = &cases
        .iter()
        .find(|c| c["name"] == "create_committed")
        .unwrap()["request"];
    let first = host.handle(create, "alice").unwrap();
    let first_calls = calls.load(Ordering::SeqCst);
    assert!(first_calls > 0);
    assert_eq!(host.handle(create, "alice").unwrap(), first);
    assert_eq!(calls.load(Ordering::SeqCst), first_calls);
    let mut conflict = create.clone();
    conflict["arguments"]["creation_id"] = serde_json::json!("conflicting");
    assert_eq!(
        host.handle(&conflict, "alice").unwrap()["error"]["code"],
        "operation_id_conflict"
    );
    assert_eq!(calls.load(Ordering::SeqCst), first_calls);
    let read = &cases
        .iter()
        .find(|c| c["name"] == "read_existing_checkpoint")
        .unwrap()["request"];
    let denied = host.handle(read, "outsider").unwrap();
    let mut absent = read.clone();
    absent["target"]["root_instance_id"] = serde_json::json!("absent");
    assert_eq!(host.handle(&absent, "outsider").unwrap(), denied);
    assert_eq!(calls.load(Ordering::SeqCst), first_calls);
    let db = rusqlite::Connection::open(&path).unwrap();
    for sql in [
        "DELETE FROM determa_public_host_responses",
        "UPDATE determa_public_host_responses SET response=X'00'",
        "DELETE FROM determa_public_host_checkpoints",
        "UPDATE determa_public_host_binding SET scope_binding_identity='other'",
    ] {
        assert!(db.execute(sql, []).is_err(), "{sql}");
    }
    db.execute_batch("DROP TRIGGER determa_public_host_responses_forbid_delete")
        .unwrap();
    assert_eq!(
        host.handle(create, "alice").unwrap()["error"]["code"],
        "host_capability_mismatch"
    );
    assert_eq!(calls.load(Ordering::SeqCst), first_calls);
    drop(db);
    drop(host);
    fs::remove_dir_all(directory).unwrap();
}

#[cfg(feature = "sqlite")]
#[test]
fn durable_client_reconciles_lost_response_at_original_binding_after_restart() {
    use determa_state::public_host::{ClientError, EndpointBinding, PublicHostClient};
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;

    let goldens = fixture("positive-v1.json");
    let cases = goldens["cases"].as_array().unwrap();
    let creation = cases
        .iter()
        .find(|c| c["name"] == "create_committed")
        .unwrap();
    let request = creation["request"].clone();
    let saved = creation["response"].clone();
    let directory = env::temp_dir().join(format!(
        "determa-public-client-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&directory).unwrap();
    let path = directory.join("client.db");
    let client = PublicHostClient::new(
        &path,
        BTreeMap::from([(
            "one".into(),
            EndpointBinding {
                endpoint: "original".into(),
                scope_alias: "scope".into(),
            },
        )]),
    )
    .unwrap();
    client.setup_schema().unwrap();
    let mut sent = Vec::new();
    let result = client.submit("one", &request, &mut |endpoint, candidate| {
        sent.push(candidate["operation"].clone());
        assert_eq!(endpoint, "original");
        if candidate["operation"] == "capabilities" {
            let mut profile = json!({"scope_binding_identity":"binding-local-1",
                "supported_operations":["capabilities","create","receipt"],
                "supported_scope_actions":[],"supported_determa_capabilities":[],
                "supported_timer_commands":[],"extension_reports":[],"authority_profile":null,
                "guarantees":{"inspection_structural":false,"inspection_semantic":false,
                    "retained_history":true,"saved_response_replay":true,"deterministic_reexecution":false}});
            let bytes = serde_json_canonicalizer::to_vec(&json!([
                "determa-public-host-profile-1", "1", "binding-local-1", profile])).unwrap();
            profile["profile_digest"] = json!(format!("sha256:{:x}", Sha256::digest(bytes)));
            Ok(json!({"protocol":"determa.execution_host","protocol_version":1,
                "operation_id":candidate["operation_id"],"status":"committed","receipt":null,
                "value":{"operation":"capabilities","result":profile},"error":null}))
        } else {
            assert_eq!(candidate, &request);
            Err(ClientError::Transport("response lost after native commit".into()))
        }
    });
    assert!(matches!(result, Err(ClientError::Transport(_))));
    assert_eq!(sent, vec![json!("capabilities"), json!("create")]);
    drop(client);
    let restarted = PublicHostClient::new(
        &path,
        BTreeMap::from([(
            "one".into(),
            EndpointBinding {
                endpoint: "replacement".into(),
                scope_alias: "other".into(),
            },
        )]),
    )
    .unwrap();
    let operation_id = request["operation_id"].as_str().unwrap();
    let receipt = restarted.receipt(operation_id, "query-original", &mut |endpoint, query| {
        assert_eq!(endpoint, "original");
        assert_eq!(query["scope_binding_identity"], request["scope_binding_identity"]);
        assert_eq!(query["arguments"]["request_digest"], request_digest(&request).unwrap());
        Ok(json!({"protocol":"determa.execution_host","protocol_version":1,
            "operation_id":query["operation_id"],"status":"committed","receipt":null,
            "value":{"operation":"receipt","result":{"saved_response":saved,"retention":"retained"}},"error":null}))
    }).unwrap();
    assert_eq!(receipt["value"]["result"]["saved_response"], saved);
    assert_eq!(
        restarted
            .retry(operation_id, &mut |endpoint, candidate| {
                assert_eq!(endpoint, "original");
                assert_eq!(candidate, &request);
                Ok(saved.clone())
            })
            .unwrap(),
        saved
    );
    assert_eq!(
        restarted
            .retry(operation_id, &mut |_, _| panic!(
                "cached response must avoid transport"
            ))
            .unwrap(),
        saved
    );
    let mut conflict = request.clone();
    conflict["arguments"]["creation_id"] = json!("unequal");
    assert!(matches!(
        restarted.submit("one", &conflict, &mut |_, _| panic!(
            "conflict must avoid transport"
        )),
        Err(ClientError::OperationConflict)
    ));
    let db = rusqlite::Connection::open(&path).unwrap();
    for mutation in [
        "DELETE FROM determa_public_client_requests",
        "UPDATE determa_public_client_requests SET endpoint='replacement'",
        "UPDATE determa_public_client_requests SET request=X'00'",
        "UPDATE determa_public_client_requests SET response=NULL",
    ] {
        assert!(db.execute(mutation, []).is_err(), "{mutation}");
    }
    db.execute_batch("DROP TRIGGER determa_public_client_guard_update")
        .unwrap();
    assert!(restarted
        .retry(operation_id, &mut |_, _| panic!(
            "changed native schema must refuse before transport"
        ))
        .is_err());
    drop(db);
    drop(restarted);
    fs::remove_dir_all(directory).unwrap();
}
