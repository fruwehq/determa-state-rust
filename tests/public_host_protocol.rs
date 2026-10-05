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
