use super::{restore_aggregate, DefinitionResolver, MigrationArtifactResolver};
use crate::checkpoint;
use jsonschema::Resource;
use serde_json::Value;
use std::collections::BTreeSet;

pub fn validate_contract_artifact(
    kind: &str,
    source: &[u8],
    resolver: &(impl DefinitionResolver + ?Sized),
) -> Result<Value, super::ArtifactError> {
    let value = super::strict_json::parse(source)
        .map_err(|error| invalid_contract(kind, error.to_string()))?;
    let schema = contract_schema(kind).ok_or_else(|| {
        invalid_contract(kind, format!("unsupported contract artifact kind {kind}"))
    })?;
    validate_schema(kind, &value, schema)?;
    validate_embedded_artifacts(&value, resolver, kind)?;
    Ok(value)
}

pub fn validate_artifact(
    kind: &str,
    source: &[u8],
    resolver: &(impl MigrationArtifactResolver + ?Sized),
    verify_digest: bool,
) -> Result<Value, super::ArtifactError> {
    match kind {
        "json_value" => super::strict_json::parse(source)
            .map_err(|error| invalid_contract(kind, error.to_string())),
        "aggregate_state_v1" => super::v1::validate_aggregate_artifact(source, resolver),
        "aggregate_state_package_v1" if verify_digest => {
            let package = super::package::validate_package_artifact_v1(source)?;
            let mut resolver = resolver_to_memory(resolver, &package);
            super::package::restore_package_v1(source, &mut resolver).map(|_| {
                super::strict_json::parse(source).expect("restored package is strict JSON")
            })
        }
        "aggregate_state_package_v1" => super::package::validate_package_artifact_v1(source),
        "migration_descriptor_v1" => super::v1::validate_migration_descriptor_v1(source),
        "execution_checkpoint_v1" => {
            checkpoint::restore(source, resolver).map(|checkpoint| checkpoint.value().clone())
        }
        _ => validate_contract_artifact(kind, source, resolver),
    }
}

fn resolver_to_memory(
    resolver: &(impl MigrationArtifactResolver + ?Sized),
    package: &Value,
) -> super::InMemoryDefinitionResolver {
    fn collect(value: &Value, fingerprints: &mut BTreeSet<String>) {
        match value {
            Value::Object(object) => {
                if let Some(fingerprint) = object
                    .get("validated_bundle_fingerprint")
                    .and_then(Value::as_str)
                {
                    fingerprints.insert(fingerprint.to_string());
                }
                for child in object.values() {
                    collect(child, fingerprints);
                }
            }
            Value::Array(items) => {
                for item in items {
                    collect(item, fingerprints);
                }
            }
            _ => {}
        }
    }
    let mut fingerprints = BTreeSet::new();
    collect(package, &mut fingerprints);
    let mut staged = super::InMemoryDefinitionResolver::default();
    for fingerprint in fingerprints {
        if let Some(existing) = resolver.resolve_definition(&fingerprint) {
            staged.insert_at(fingerprint, existing.bundle, existing.trusted);
        }
    }
    for digest in package["migration_route"]
        .as_array()
        .into_iter()
        .flatten()
        .chain(
            package["migration_descriptors"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|descriptor| &descriptor["migration_descriptor_digest"]),
        )
    {
        if let Some(digest) = digest.as_str() {
            if let Some(existing) = resolver.resolve_migration_descriptor(digest) {
                staged.insert_descriptor(digest, existing.bytes, existing.trusted);
            }
        }
    }
    staged
}

fn validate_schema(kind: &str, value: &Value, schema: &str) -> Result<(), super::ArtifactError> {
    thread_local! {
        static VALIDATORS: std::cell::RefCell<std::collections::HashMap<usize, jsonschema::Validator>> =
            std::cell::RefCell::new(std::collections::HashMap::new());
    }
    VALIDATORS.with(|cache| {
        let mut cache = cache.borrow_mut();
        let validator = cache.entry(schema.as_ptr() as usize).or_insert_with(|| {
            let schema_value: Value =
                serde_json::from_str(schema).expect("bundled contract schema is valid");
            let mut options = jsonschema::options();
            for resource in schema_resources() {
                let parsed: Value =
                    serde_json::from_str(resource).expect("bundled schema resource is valid");
                if let Some(id) = parsed["$id"].as_str() {
                    options = options.with_resource(
                        id.to_string(),
                        Resource::from_contents(parsed).expect("bundled schema resource is valid"),
                    );
                }
            }
            options
                .build(&schema_value)
                .expect("bundled contract schema is valid")
        });
        validator
            .validate(value)
            .map_err(|error| invalid_contract(kind, error.to_string()))
    })
}

/// The pinned journal's mapping definition, without inventing another wire kind.
pub(super) fn validate_effect_result_mapping(value: &Value) -> Result<(), super::ArtifactError> {
    const SCHEMA: &str = r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","$ref":"https://determa.dev/state/schema/host-effect-journal-v1.schema.json#/$defs/resultMapping"}"#;
    validate_schema("host_effect_journal_v1", value, SCHEMA)
}

fn validate_embedded_artifacts(
    value: &Value,
    resolver: &(impl DefinitionResolver + ?Sized),
    contract_kind: &str,
) -> Result<(), super::ArtifactError> {
    match value {
        Value::Object(object) => {
            if object.get("aggregate_state_format").and_then(Value::as_str)
                == Some("determa.aggregate_state")
            {
                let bytes = serde_json_canonicalizer::to_vec(value)
                    .map_err(|error| invalid_contract(contract_kind, error.to_string()))?;
                restore_aggregate(&bytes, resolver)?;
                return Ok(());
            }
            if object
                .get("execution_checkpoint_format")
                .and_then(Value::as_str)
                == Some("determa.execution_checkpoint")
            {
                let bytes = serde_json_canonicalizer::to_vec(value)
                    .map_err(|error| invalid_contract(contract_kind, error.to_string()))?;
                checkpoint::restore(&bytes, resolver)?;
                return Ok(());
            }
            for member in object.values() {
                validate_embedded_artifacts(member, resolver, contract_kind)?;
            }
        }
        Value::Array(items) => {
            for item in items {
                validate_embedded_artifacts(item, resolver, contract_kind)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn contract_schema(kind: &str) -> Option<&'static str> {
    match kind {
        "host_effect_journal_v1" => Some(include_str!(
            "../../schema/host-effect-journal-v1.schema.json"
        )),
        "application_projection_v1" => Some(include_str!(
            "../../schema/application-projection-v1.schema.json"
        )),
        "lossless_delivery_v1" => Some(include_str!(
            "../../schema/lossless-delivery-v1.schema.json"
        )),
        "core_step_result_v1" => Some(include_str!("../../schema/core-step-result-v1.schema.json")),
        "inspection_v1" => Some(include_str!("../../schema/inspection-v1.schema.json")),
        "durable_host_call_log_v1" => Some(include_str!(
            "../../schema/durable-host-call-log-v1.schema.json"
        )),
        "durable_host_inputs_v1" => Some(include_str!(
            "../../schema/durable-host-inputs-v1.schema.json"
        )),
        "durable_host_results_v1" => Some(include_str!(
            "../../schema/durable-host-results-v1.schema.json"
        )),
        "durable_host_responses_v1" => Some(include_str!(
            "../../schema/durable-host-responses-v1.schema.json"
        )),
        "durable_host_store_v1" => Some(include_str!(
            "../../schema/durable-host-store-v1.schema.json"
        )),
        "version1_operation_inputs" => Some(include_str!(
            "../../schema/version1-operation-inputs.schema.json"
        )),
        "version1_operation_result" => Some(include_str!(
            "../../schema/version1-operation-result.schema.json"
        )),
        "version1_operation_failures" => Some(include_str!(
            "../../schema/version1-operation-failures.schema.json"
        )),
        _ => None,
    }
}

fn schema_resources() -> [&'static str; 20] {
    [
        include_str!("../../schema/application-projection-v1.schema.json"),
        include_str!("../../schema/lossless-delivery-v1.schema.json"),
        include_str!("../../schema/delivery-v1.schema.json"),
        include_str!("../../schema/host-effect-journal-v1.schema.json"),
        include_str!("../../schema/aggregate-state-v1.schema.json"),
        include_str!("../../schema/aggregate-state-package-v1.schema.json"),
        include_str!("../../schema/core-step-result-v1.schema.json"),
        include_str!("../../schema/inspection-v1.schema.json"),
        include_str!("../../schema/execution-checkpoint-v1.schema.json"),
        include_str!("../../schema/migration-descriptor-v1.schema.json"),
        include_str!("../../schema/durable-host-call-log-v1.schema.json"),
        include_str!("../../schema/durable-host-inputs-v1.schema.json"),
        include_str!("../../schema/durable-host-results-v1.schema.json"),
        include_str!("../../schema/durable-host-responses-v1.schema.json"),
        include_str!("../../schema/durable-host-store-v1.schema.json"),
        include_str!("../../schema/version1-operation-inputs.schema.json"),
        include_str!("../../schema/version1-operation-result.schema.json"),
        include_str!("../../schema/version1-operation-failures.schema.json"),
        include_str!("../../schema/machine.schema.json"),
        include_str!("../../schema/provider-reference-v1.schema.json"),
    ]
}

fn invalid_contract(kind: &str, message: impl Into<String>) -> super::ArtifactError {
    let code = match kind {
        "core_step_result_v1" => "invalid_core_step_result",
        "inspection_v1" => "invalid_inspection_request",
        "durable_host_call_log_v1" => "invalid_durable_host_call_log_v1",
        "durable_host_inputs_v1" => "invalid_durable_host_inputs_v1",
        "durable_host_results_v1" => "invalid_durable_host_results_v1",
        "durable_host_responses_v1" => "invalid_durable_host_responses_v1",
        "durable_host_store_v1" => "invalid_durable_host_store_v1",
        "version1_operation_inputs" => "invalid_version1_operation_inputs",
        "version1_operation_result" => "invalid_version1_operation_result",
        "version1_operation_failures" => "invalid_version1_operation_failures",
        _ => "invalid_contract_artifact",
    };
    super::ArtifactError::new(code, message)
}
