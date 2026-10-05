//! Closed public v1 wire validation and named-binding client/host integration.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

pub fn request_digest(request: &Value) -> Result<String, crate::ArtifactError> {
    validate_message(request, false)?;
    hash(&json!([
        "determa-public-host-request-digest-1",
        "1",
        request
    ]))
}

fn hash(value: &Value) -> Result<String, crate::ArtifactError> {
    let bytes = serde_json_canonicalizer::to_vec(value).map_err(|e| error(e.to_string()))?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

fn error(message: impl Into<String>) -> crate::ArtifactError {
    crate::ArtifactError::new("invalid_host_request", message)
}

pub fn validate_message(value: &Value, response: bool) -> Result<(), crate::ArtifactError> {
    static REQUEST: OnceLock<jsonschema::Validator> = OnceLock::new();
    static RESPONSE: OnceLock<jsonschema::Validator> = OnceLock::new();
    let cache = if response { &RESPONSE } else { &REQUEST };
    let validator = cache.get_or_init(|| {
        let resources = [
            (
                "aggregate-state-v1.schema.json",
                include_str!("../schema/aggregate-state-v1.schema.json"),
            ),
            (
                "archive-export-request-v1.schema.json",
                include_str!("../schema/archive-export-request-v1.schema.json"),
            ),
            (
                "archive-import-request-v1.schema.json",
                include_str!("../schema/archive-import-request-v1.schema.json"),
            ),
            (
                "archive-participant-v1.schema.json",
                include_str!("../schema/archive-participant-v1.schema.json"),
            ),
            (
                "archive-result-v1.schema.json",
                include_str!("../schema/archive-result-v1.schema.json"),
            ),
            (
                "archive-v1.schema.json",
                include_str!("../schema/archive-v1.schema.json"),
            ),
            (
                "core-step-result-v1.schema.json",
                include_str!("../schema/core-step-result-v1.schema.json"),
            ),
            (
                "effect-cancellation-request-v1.schema.json",
                include_str!("../schema/effect-cancellation-request-v1.schema.json"),
            ),
            (
                "effect-cancellation-response-v1.schema.json",
                include_str!("../schema/effect-cancellation-response-v1.schema.json"),
            ),
            (
                "effect-result-request-v1.schema.json",
                include_str!("../schema/effect-result-request-v1.schema.json"),
            ),
            (
                "effect-result-response-v1.schema.json",
                include_str!("../schema/effect-result-response-v1.schema.json"),
            ),
            (
                "execution-checkpoint-v1.schema.json",
                include_str!("../schema/execution-checkpoint-v1.schema.json"),
            ),
            (
                "extension-capability-report-v1.schema.json",
                include_str!("../schema/extension-capability-report-v1.schema.json"),
            ),
            (
                "host-authority-operation-v1.schema.json",
                include_str!("../schema/host-authority-operation-v1.schema.json"),
            ),
            (
                "host-authority-profile-report-v1.schema.json",
                include_str!("../schema/host-authority-profile-report-v1.schema.json"),
            ),
            (
                "host-effect-journal-v1.schema.json",
                include_str!("../schema/host-effect-journal-v1.schema.json"),
            ),
            (
                "inspection-v1.schema.json",
                include_str!("../schema/inspection-v1.schema.json"),
            ),
            (
                "migration-descriptor-v1.schema.json",
                include_str!("../schema/migration-descriptor-v1.schema.json"),
            ),
            (
                "provider-reference-v1.schema.json",
                include_str!("../schema/provider-reference-v1.schema.json"),
            ),
            (
                "public-host-request-v1.schema.json",
                include_str!("../schema/public-host-request-v1.schema.json"),
            ),
            (
                "public-host-response-v1.schema.json",
                include_str!("../schema/public-host-response-v1.schema.json"),
            ),
            (
                "recovery-operation-v1.schema.json",
                include_str!("../schema/recovery-operation-v1.schema.json"),
            ),
            (
                "recovery-record-v1.schema.json",
                include_str!("../schema/recovery-record-v1.schema.json"),
            ),
            (
                "timer-helper-operation-v1.schema.json",
                include_str!("../schema/timer-helper-operation-v1.schema.json"),
            ),
        ];
        let mut options = jsonschema::options();
        for (name, source) in resources {
            let parsed: Value = serde_json::from_str(source).expect("pinned schema JSON");
            let resource = jsonschema::Resource::from_contents(parsed.clone())
                .expect("pinned schema resource");
            options = options.with_resource(name.to_owned(), resource.clone());
            options = options.with_resource(
                format!("https://determa.dev/state/schema/{name}"),
                resource.clone(),
            );
            if let Some(id) = parsed["$id"].as_str() {
                options = options.with_resource(id.to_owned(), resource);
            }
        }
        let source = if response {
            include_str!("../schema/public-host-response-v1.schema.json")
        } else {
            include_str!("../schema/public-host-request-v1.schema.json")
        };
        options
            .build(&serde_json::from_str::<Value>(source).expect("pinned public schema"))
            .expect("pinned public schema closure")
    });
    validator.validate(value).map_err(|e| error(e.to_string()))
}
