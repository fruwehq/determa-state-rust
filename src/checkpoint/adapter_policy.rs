//! Pure execution-store selection rules shared by the public registry and probes.
//! Declared capabilities are premises here, never operational evidence.

use super::{AdapterError, AdapterErrorCode, ExecutionStoreCapability};
use serde_json::{json, Value};

/// Execute a conditional policy request with no store, factory or operational
/// handle. Used by conformance to observe these shared production decisions.
pub fn conditional_adapter_policy(request: &Value) -> Value {
    fn decide(request: &Value) -> Result<Value, AdapterError> {
        match request["operation"].as_str() {
            Some("checkpoint_register_adapter_v1") => {
                let existing = request["existing_registrations"]
                    .as_array()
                    .ok_or_else(|| invalid("registrations required"))?;
                Ok(
                    json!({"kind":"registration","body":adapter_registration_policy(existing, &request["registration"])?}),
                )
            }
            Some("checkpoint_resolve_adapter_v1") => {
                let registrations = request["registrations"]
                    .as_array()
                    .ok_or_else(|| invalid("registrations required"))?;
                let uri = request["uri"]
                    .as_str()
                    .ok_or_else(|| invalid("URI required"))?;
                Ok(
                    json!({"kind":"resolution","body":adapter_resolution_policy(registrations, uri, request["adapter_identifier"].as_str(), &request["configuration"], &request["requested_capabilities"])?}),
                )
            }
            Some("checkpoint_validate_capabilities_v1") => {
                use super::{hypothetical_host_profile_matches, HostFeature, HostProfile};
                let capabilities = capability_names(&request["store_capabilities"])?
                    .iter()
                    .map(|name| ExecutionStoreCapability::from_name(name).unwrap())
                    .collect();
                let names = request["host_guarantees"]
                    .as_array()
                    .ok_or_else(|| invalid("host guarantees required"))?;
                let features: Option<std::collections::BTreeSet<_>> = names
                    .iter()
                    .map(|name| name.as_str().and_then(HostFeature::from_name))
                    .collect();
                let features = features.ok_or_else(|| invalid("unknown host guarantee"))?;
                let profile = match request["host_profile"].as_str() {
                    Some("durable_embedded_processing") => HostProfile::DurableEmbeddedProcessing,
                    Some("exactly_once_committed_processing") => {
                        HostProfile::ExactlyOnceCommittedProcessing
                    }
                    Some("broker_integrated") => HostProfile::BrokerIntegrated,
                    Some("strict_durable_outbox") => HostProfile::StrictDurableOutbox,
                    Some("compact_durable_outbox") => HostProfile::CompactDurableOutbox,
                    Some("shared_application_transaction") => {
                        HostProfile::SharedApplicationTransaction
                    }
                    _ => return Err(invalid("unknown host profile")),
                };
                if !hypothetical_host_profile_matches(
                    &capabilities,
                    &features,
                    profile,
                    request["retention_mode"] == "permanent",
                ) {
                    return Err(AdapterError::new(
                        AdapterErrorCode::AdapterCapabilityMismatch,
                        "composition premises insufficient",
                    ));
                }
                Ok(json!({"kind":"capability_report","body":{
                    "adapter_identifier":request["adapter_identifier"], "host_profile":request["host_profile"],
                    "host_guarantees":request["host_guarantees"], "retention_mode":request["retention_mode"],
                    "store_capabilities":request["store_capabilities"], "validated":true
                }}))
            }
            _ => Err(invalid("unsupported conditional policy operation")),
        }
    }
    decide(request)
        .unwrap_or_else(|error| json!({"kind":"typed_failure","body":{"code":error.code.as_str()}}))
}

fn invalid(message: &str) -> AdapterError {
    AdapterError::new(AdapterErrorCode::InvalidAdapterConfiguration, message)
}

fn identifier(value: &Value) -> bool {
    value.as_str().is_some_and(|name| {
        let mut bytes = name.bytes();
        bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
            && bytes.all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"+.-".contains(&byte)
            })
    })
}

fn capability_names(value: &Value) -> Result<Vec<&str>, AdapterError> {
    let values = value
        .as_array()
        .ok_or_else(|| invalid("capability list required"))?;
    let names: Vec<_> = values.iter().filter_map(Value::as_str).collect();
    if names.len() != values.len()
        || names
            .iter()
            .any(|name| ExecutionStoreCapability::from_name(name).is_none())
        || names
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != names.len()
    {
        return Err(invalid("invalid capability list"));
    }
    Ok(names)
}

/// Validate a proposed registration without loading code or replacing an entry.
/// The returned metadata grants no configured capability.
pub fn adapter_registration_policy(
    existing: &[Value],
    proposed: &Value,
) -> Result<Value, AdapterError> {
    let fields = proposed
        .as_object()
        .ok_or_else(|| invalid("registration object required"))?;
    if fields.len() != 5
        || !identifier(&proposed["adapter_identifier"])
        || !identifier(&proposed["uri_scheme"])
        || !matches!(proposed["source"].as_str(), Some("bundled" | "third_party"))
        || !fields.contains_key("configuration_schema")
        || !fields.contains_key("capabilities")
    {
        return Err(invalid("invalid registration metadata"));
    }
    capability_names(&proposed["capabilities"])?;
    jsonschema::validator_for(&proposed["configuration_schema"])
        .map_err(|_| invalid("invalid configuration schema"))?;
    if existing.iter().any(|item| {
        item["adapter_identifier"] == proposed["adapter_identifier"]
            || item["uri_scheme"] == proposed["uri_scheme"]
    }) {
        return Err(AdapterError::new(
            AdapterErrorCode::DuplicateAdapterRegistration,
            "adapter already registered",
        ));
    }
    Ok(proposed.clone())
}

/// Resolve explicit premises. Operational callers must independently bind the
/// configured instance and pass its current proved capabilities before use.
pub fn adapter_resolution_policy(
    registrations: &[Value],
    uri: &str,
    requested_identifier: Option<&str>,
    configuration: &Value,
    requested_capabilities: &Value,
) -> Result<Value, AdapterError> {
    let scheme = uri.split_once(':').map(|parts| parts.0).unwrap_or("");
    let registration = registrations
        .iter()
        .find(|entry| {
            entry["uri_scheme"].as_str() == Some(scheme)
                && requested_identifier
                    .is_none_or(|name| entry["adapter_identifier"].as_str() == Some(name))
        })
        .ok_or_else(|| AdapterError::new(AdapterErrorCode::UnknownAdapter, "unknown adapter"))?;
    if !jsonschema::validator_for(&registration["configuration_schema"])
        .is_ok_and(|validator| validator.is_valid(configuration))
    {
        return Err(invalid("invalid adapter configuration"));
    }
    let requested = capability_names(requested_capabilities)?;
    let available = capability_names(&registration["capabilities"])?;
    if !requested.iter().all(|name| available.contains(name)) {
        return Err(AdapterError::new(
            AdapterErrorCode::AdapterCapabilityMismatch,
            "requested capability unavailable",
        ));
    }
    Ok(
        json!({"registration":registration,"configuration":configuration,"requested_capabilities":requested_capabilities}),
    )
}
