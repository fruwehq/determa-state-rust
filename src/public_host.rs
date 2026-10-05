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

/// A deployment endpoint and scope alias; these values never enter a machine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndpointBinding {
    pub endpoint: String,
    pub scope_alias: String,
}

/// A client failure is not a protocol response or proof of rollback.
#[derive(Debug)]
pub enum ClientError {
    Protocol(crate::ArtifactError),
    Storage(String),
    Transport(String),
    BindingUnavailable,
    OperationConflict,
    OutcomeUnknown,
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Protocol(error) => write!(f, "{error}"),
            Self::Storage(error) => write!(f, "client storage failure: {error}"),
            Self::Transport(error) => write!(f, "transport outcome unknown: {error}"),
            Self::BindingUnavailable => f.write_str("binding_unavailable"),
            Self::OperationConflict => f.write_str("operation_id_conflict"),
            Self::OutcomeUnknown => f.write_str("outcome_unknown"),
        }
    }
}
impl std::error::Error for ClientError {}
impl From<crate::ArtifactError> for ClientError {
    fn from(error: crate::ArtifactError) -> Self {
        Self::Protocol(error)
    }
}
#[cfg(feature = "sqlite")]
impl From<rusqlite::Error> for ClientError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Storage(error.to_string())
    }
}

/// Return only complete, correlated public responses with their exact evidence.
fn checked_response(request: &Value, response: &Value) -> Result<(), ClientError> {
    validate_message(response, true)?;
    if response["operation_id"] != request["operation_id"] {
        return Err(error("response operation identity differs").into());
    }
    let receipt = &response["receipt"];
    if response["status"] == "committed" {
        let required = match request["operation"].as_str().unwrap() {
            "create" | "admit" | "effect_result" | "cancel_effect" => true,
            "process" => {
                response["value"]["result"]["core_result"]["disposition"] != "not_runnable"
            }
            _ => false,
        };
        if required && receipt.is_null() {
            return Err(error("committed mutation lacks receipt").into());
        }
    }
    if !receipt.is_null() {
        if receipt["scope_binding_identity"] != request["scope_binding_identity"]
            || receipt["operation_id"] != request["operation_id"]
            || receipt["request_digest"] != request_digest(request)?
        {
            return Err(error("receipt binding differs").into());
        }
        let digest = if receipt["receipt_kind"] == "committed" {
            hash(&json!([
                "determa-public-host-evidence-1",
                "1",
                response["value"]
            ]))?
        } else {
            hash(&json!([
                "determa-public-host-acceptance-evidence-1",
                "1",
                request["scope_binding_identity"],
                request["operation_id"],
                receipt["request_digest"],
                receipt["acceptance_receipt"]
            ]))?
        };
        if receipt["evidence_digest"] != digest {
            return Err(error("receipt digest differs").into());
        }
    }
    if !response["value"].is_null() && response["value"]["operation"] != request["operation"] {
        return Err(error("response operation differs").into());
    }
    if !response["error"].is_null() && response["error"]["operation"] != request["operation"] {
        return Err(error("error operation differs").into());
    }
    if request["operation"] == "capabilities" && response["status"] == "committed" {
        let mut profile = response["value"]["result"].clone();
        let digest = profile
            .as_object_mut()
            .unwrap()
            .remove("profile_digest")
            .unwrap();
        if digest
            != hash(&json!([
                "determa-public-host-profile-1",
                "1",
                profile["scope_binding_identity"],
                profile
            ]))?
        {
            return Err(error("capability profile digest differs").into());
        }
    }
    if request["operation"] == "receipt" && response["status"] == "committed" {
        let saved = &response["value"]["result"]["saved_response"];
        if !saved.is_null() {
            let evidence = &saved["receipt"];
            if saved["operation_id"] != request["arguments"]["queried_operation_id"]
                || (!evidence.is_null()
                    && (evidence["scope_binding_identity"] != request["scope_binding_identity"]
                        || evidence["request_digest"] != request["arguments"]["request_digest"]
                        || evidence["operation_id"] != saved["operation_id"]))
            {
                return Err(error("nested receipt binding differs").into());
            }
        }
    }
    Ok(())
}

#[cfg(feature = "sqlite")]
mod client {
    use super::*;
    use rusqlite::{params, OptionalExtension, TransactionBehavior};
    use std::{
        collections::BTreeMap,
        path::{Path, PathBuf},
    };

    /// Durable exact-request retry uses only its saved endpoint and scope binding.
    pub struct PublicHostClient {
        path: PathBuf,
        bindings: BTreeMap<String, EndpointBinding>,
    }

    impl PublicHostClient {
        pub fn new(
            path: impl AsRef<Path>,
            bindings: BTreeMap<String, EndpointBinding>,
        ) -> Result<Self, ClientError> {
            if path.as_ref().as_os_str().is_empty()
                || path.as_ref() == Path::new(":memory:")
                || bindings
                    .values()
                    .any(|b| b.endpoint.is_empty() || b.scope_alias.is_empty())
            {
                return Err(ClientError::BindingUnavailable);
            }
            Ok(Self {
                path: path.as_ref().to_owned(),
                bindings,
            })
        }

        fn connect(&self) -> Result<rusqlite::Connection, ClientError> {
            let connection = rusqlite::Connection::open(&self.path)?;
            connection.pragma_update(None, "journal_mode", "WAL")?;
            connection.pragma_update(None, "synchronous", "FULL")?;
            Ok(connection)
        }

        pub fn setup_schema(&self) -> Result<(), ClientError> {
            self.connect()?.execute_batch(
                "CREATE TABLE IF NOT EXISTS determa_public_client_requests (
                operation_id TEXT PRIMARY KEY, binding_name TEXT NOT NULL, endpoint TEXT NOT NULL,
                request BLOB NOT NULL, request_digest TEXT NOT NULL, response BLOB)",
            )?;
            Ok(())
        }

        fn send(
            &self,
            endpoint: &str,
            request: &Value,
            transport: &mut impl FnMut(&str, &Value) -> Result<Value, ClientError>,
        ) -> Result<Value, ClientError> {
            let response = transport(endpoint, request)?;
            checked_response(request, &response)?;
            Ok(response)
        }

        pub fn discover(
            &self,
            name: &str,
            operation_id: &str,
            transport: &mut impl FnMut(&str, &Value) -> Result<Value, ClientError>,
        ) -> Result<Value, ClientError> {
            let binding = self
                .bindings
                .get(name)
                .ok_or(ClientError::BindingUnavailable)?;
            let request = json!({"protocol":"determa.execution_host", "protocol_version":1,
                "operation_id":operation_id, "scope_binding_identity":null, "operation":"capabilities",
                "target":{"root_instance_id":null,"runtime_id":null,"runtime_incarnation":null},
                "precondition":null,"arguments":{"scope_alias":binding.scope_alias}});
            validate_message(&request, false)?;
            self.send(&binding.endpoint, &request, transport)
        }

        pub fn submit(
            &self,
            name: &str,
            request: &Value,
            transport: &mut impl FnMut(&str, &Value) -> Result<Value, ClientError>,
        ) -> Result<Value, ClientError> {
            let mut candidate = request.clone();
            let operation_id = request["operation_id"]
                .as_str()
                .filter(|id| !id.is_empty())
                .ok_or_else(|| error("missing operation ID"))?;
            let previous: Option<(String, Vec<u8>)> = self.connect()?.query_row(
                "SELECT binding_name,request FROM determa_public_client_requests WHERE operation_id=?",
                [operation_id], |row| Ok((row.get(0)?,row.get(1)?))).optional()?;
            if let Some((binding_name, bytes)) = previous {
                let saved: Value =
                    serde_json::from_slice(&bytes).map_err(|e| error(e.to_string()))?;
                if candidate["scope_binding_identity"].is_null() {
                    candidate["scope_binding_identity"] = saved["scope_binding_identity"].clone();
                }
                validate_message(&candidate, false)?;
                if binding_name != name
                    || serde_json_canonicalizer::to_vec(&candidate)
                        .map_err(|e| error(e.to_string()))?
                        != bytes
                {
                    return Err(ClientError::OperationConflict);
                }
                return self.retry(operation_id, transport);
            }
            let binding = self
                .bindings
                .get(name)
                .ok_or(ClientError::BindingUnavailable)?;
            let discovery = self.discover(name, &format!("{operation_id}:discovery"), transport)?;
            if discovery["status"] != "committed" {
                return Err(ClientError::BindingUnavailable);
            }
            let profile = &discovery["value"]["result"];
            if !candidate["scope_binding_identity"].is_null()
                && candidate["scope_binding_identity"] != profile["scope_binding_identity"]
            {
                return Err(ClientError::BindingUnavailable);
            }
            candidate["scope_binding_identity"] = profile["scope_binding_identity"].clone();
            validate_message(&candidate, false)?;
            if !profile["supported_operations"]
                .as_array()
                .unwrap()
                .contains(&candidate["operation"])
            {
                return Err(ClientError::Protocol(error("host_capability_mismatch")));
            }
            if ["capabilities", "read", "inspect", "receipt"]
                .contains(&candidate["operation"].as_str().unwrap())
            {
                return self.send(&binding.endpoint, &candidate, transport);
            }
            let mut connection = self.connect()?;
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            transaction.execute(
                "INSERT INTO determa_public_client_requests VALUES (?,?,?,?,?,NULL)",
                params![
                    operation_id,
                    name,
                    binding.endpoint,
                    serde_json_canonicalizer::to_vec(&candidate)
                        .map_err(|e| error(e.to_string()))?,
                    request_digest(&candidate)?
                ],
            )?;
            transaction.commit()?;
            self.retry(operation_id, transport)
        }

        pub fn retry(
            &self,
            operation_id: &str,
            transport: &mut impl FnMut(&str, &Value) -> Result<Value, ClientError>,
        ) -> Result<Value, ClientError> {
            type Saved = (String, Vec<u8>, String, Option<Vec<u8>>);
            let saved: Option<Saved> = self.connect()?.query_row(
                "SELECT endpoint,request,request_digest,response FROM determa_public_client_requests WHERE operation_id=?",
                [operation_id], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?))).optional()?;
            let (endpoint, bytes, digest, response) = saved.ok_or(ClientError::OutcomeUnknown)?;
            let request: Value =
                serde_json::from_slice(&bytes).map_err(|e| error(e.to_string()))?;
            if request_digest(&request)? != digest
                || serde_json_canonicalizer::to_vec(&request).map_err(|e| error(e.to_string()))?
                    != bytes
            {
                return Err(error("invalid saved request").into());
            }
            if let Some(response) = response {
                let response =
                    serde_json::from_slice(&response).map_err(|e| error(e.to_string()))?;
                checked_response(&request, &response)?;
                return Ok(response);
            }
            let response = self.send(&endpoint, &request, transport)?;
            if response["status"] != "pending" {
                self.connect()?.execute("UPDATE determa_public_client_requests SET response=? WHERE operation_id=? AND response IS NULL",
                    params![serde_json_canonicalizer::to_vec(&response).map_err(|e| error(e.to_string()))?,operation_id])?;
            }
            Ok(response)
        }

        /// Query durable evidence at the endpoint pinned before the original mutation.
        pub fn receipt(
            &self,
            operation_id: &str,
            query_operation_id: &str,
            transport: &mut impl FnMut(&str, &Value) -> Result<Value, ClientError>,
        ) -> Result<Value, ClientError> {
            let saved: Option<(String, Vec<u8>, String)> = self.connect()?.query_row(
                "SELECT endpoint,request,request_digest FROM determa_public_client_requests WHERE operation_id=?",
                [operation_id], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?))).optional()?;
            let (endpoint, bytes, digest) = saved.ok_or(ClientError::OutcomeUnknown)?;
            let original: Value =
                serde_json::from_slice(&bytes).map_err(|e| error(e.to_string()))?;
            if request_digest(&original)? != digest
                || serde_json_canonicalizer::to_vec(&original).map_err(|e| error(e.to_string()))?
                    != bytes
            {
                return Err(error("invalid saved request").into());
            }
            let request = json!({"protocol":"determa.execution_host", "protocol_version":1,
                "operation_id":query_operation_id, "scope_binding_identity":original["scope_binding_identity"],
                "operation":"receipt", "target":{"root_instance_id":null,"runtime_id":null,"runtime_incarnation":null},
                "precondition":null,"arguments":{"queried_operation_id":operation_id,"request_digest":digest}});
            validate_message(&request, false)?;
            let response = self.send(&endpoint, &request, transport)?;
            if response["status"] == "committed" {
                let nested = &response["value"]["result"]["saved_response"];
                if !nested.is_null() {
                    checked_response(&original, nested)?;
                }
            }
            Ok(response)
        }
    }
}
#[cfg(feature = "sqlite")]
pub use client::PublicHostClient;

#[cfg(feature = "sqlite")]
mod local;
#[cfg(feature = "sqlite")]
pub use local::SqlitePublicExecutionHost;
