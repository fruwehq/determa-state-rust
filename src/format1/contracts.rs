use super::{restore_aggregate, DefinitionResolver};
use crate::checkpoint;
use jsonschema::Resource;
use serde_json::Value;

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
    resolver: &(impl DefinitionResolver + ?Sized),
    verify_digest: bool,
) -> Result<Value, super::ArtifactError> {
    match kind {
        "aggregate_state_v2" => super::v2::validate_aggregate_artifact(source),
        "aggregate_state_package_v2" if verify_digest => {
            let mut resolver = resolver_to_memory(resolver);
            super::package::restore_package_v2(source, &mut resolver).map(|_| {
                super::strict_json::parse(source).expect("restored package is strict JSON")
            })
        }
        "aggregate_state_package_v2" => super::package::validate_package_artifact_v2(source),
        "migration_descriptor_v2" => super::v2::validate_migration_descriptor_v2(source),
        "execution_checkpoint_v2" => {
            checkpoint::restore(source, resolver).map(|checkpoint| checkpoint.value().clone())
        }
        _ => validate_contract_artifact(kind, source, resolver),
    }
}

fn resolver_to_memory(
    _resolver: &(impl DefinitionResolver + ?Sized),
) -> super::InMemoryDefinitionResolver {
    super::InMemoryDefinitionResolver::default()
}

fn validate_schema(kind: &str, value: &Value, schema: &str) -> Result<(), super::ArtifactError> {
    let schema_value: Value = serde_json::from_str(schema)
        .map_err(|error| invalid_contract(kind, format!("invalid embedded schema: {error}")))?;
    let mut options = jsonschema::options();
    for resource in schema_resources() {
        let parsed: Value = serde_json::from_str(resource)
            .map_err(|error| invalid_contract(kind, format!("invalid embedded schema: {error}")))?;
        if let Some(id) = parsed["$id"].as_str() {
            options = options.with_resource(
                id.to_string(),
                Resource::from_contents(parsed).map_err(|error| {
                    invalid_contract(kind, format!("invalid schema resource: {error}"))
                })?,
            );
        }
    }
    let validator = options
        .build(&schema_value)
        .map_err(|error| invalid_contract(kind, format!("invalid contract schema: {error}")))?;
    validator
        .validate(value)
        .map_err(|error| invalid_contract(kind, error.to_string()))?;
    Ok(())
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
        "core_step_result_v2" => Some(include_str!("../../schema/core-step-result-v2.schema.json")),
        "durable_host_call_log_v2" => Some(include_str!(
            "../../schema/durable-host-call-log-v2.schema.json"
        )),
        "durable_host_inputs_v2" => Some(include_str!(
            "../../schema/durable-host-inputs-v2.schema.json"
        )),
        "durable_host_results_v2" => Some(include_str!(
            "../../schema/durable-host-results-v2.schema.json"
        )),
        "durable_host_store_v2" => Some(include_str!(
            "../../schema/durable-host-store-v2.schema.json"
        )),
        "version2_operation_inputs" => Some(include_str!(
            "../../schema/version2-operation-inputs.schema.json"
        )),
        "version2_operation_result" => Some(include_str!(
            "../../schema/version2-operation-result.schema.json"
        )),
        _ => None,
    }
}

fn schema_resources() -> [&'static str; 12] {
    [
        include_str!("../../schema/aggregate-state-v2.schema.json"),
        include_str!("../../schema/aggregate-state-package-v2.schema.json"),
        include_str!("../../schema/core-step-result-v2.schema.json"),
        include_str!("../../schema/execution-checkpoint-v2.schema.json"),
        include_str!("../../schema/migration-descriptor-v2.schema.json"),
        include_str!("../../schema/durable-host-call-log-v2.schema.json"),
        include_str!("../../schema/durable-host-inputs-v2.schema.json"),
        include_str!("../../schema/durable-host-results-v2.schema.json"),
        include_str!("../../schema/durable-host-store-v2.schema.json"),
        include_str!("../../schema/version2-operation-inputs.schema.json"),
        include_str!("../../schema/version2-operation-result.schema.json"),
        include_str!("../../schema/machine.schema.json"),
    ]
}

fn invalid_contract(kind: &str, message: impl Into<String>) -> super::ArtifactError {
    let code = match kind {
        "core_step_result_v2" => "invalid_core_step_result",
        "durable_host_call_log_v2" => "invalid_durable_host_call_log_v2",
        "durable_host_inputs_v2" => "invalid_durable_host_inputs_v2",
        "durable_host_results_v2" => "invalid_durable_host_results_v2",
        "durable_host_store_v2" => "invalid_durable_host_store_v2",
        "version2_operation_inputs" => "invalid_version2_operation_inputs",
        "version2_operation_result" => "invalid_version2_operation_result",
        _ => "invalid_contract_artifact",
    };
    super::ArtifactError::new(code, message)
}
