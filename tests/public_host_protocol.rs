use determa_state::public_host::{request_digest, validate_message};
use serde_json::Value;
use std::{env, fs, path::PathBuf};

fn fixture(name: &str) -> Value {
    let root = env::var_os("DETERMA_SPEC_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("authoritative-spec"));
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
    drop(restarted);
    fs::remove_dir_all(directory).unwrap();
}
