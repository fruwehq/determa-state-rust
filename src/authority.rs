//! Explicit local SQLite scope authority, separate from portable machine state.
//!
//! This implementation checkpoint provides permanent allocation and actual native
//! guarded mutation/receipt commits. Host checkpoint composition, complete frozen
//! inventories, worker fences, relocation and verified registration remain unfinished.
//! No completed authority profile or capability claim is advertised.

use crate::format1::strict_json;
use num_bigint::BigUint;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

const RECORDS: &str = "CREATE TABLE determa_scope_authority (scope_identity TEXT PRIMARY KEY NOT NULL, ledger BLOB NOT NULL)";
const ALLOCATIONS: &str =
    "CREATE TABLE determa_scope_allocations (scope_identity TEXT PRIMARY KEY NOT NULL)";
const MUTATIONS: &str = "CREATE TABLE determa_authority_mutations (scope_identity TEXT NOT NULL, operation_id TEXT NOT NULL, mutation_digest TEXT NOT NULL, mutation BLOB NOT NULL, PRIMARY KEY(scope_identity, operation_id))";
const NO_DELETE: &str = "CREATE TRIGGER determa_scope_allocations_forbid_delete BEFORE DELETE ON determa_scope_allocations BEGIN SELECT RAISE(ABORT, 'scope_allocation_immutable'); END";
const NO_UPDATE: &str = "CREATE TRIGGER determa_scope_allocations_forbid_update BEFORE UPDATE ON determa_scope_allocations BEGIN SELECT RAISE(ABORT, 'scope_allocation_immutable'); END";
const BOUNDARY: &str = "CREATE TABLE determa_authority_boundary (boundary_id INTEGER PRIMARY KEY NOT NULL CHECK(boundary_id=1), storage_binding TEXT NOT NULL)";
const BOUNDARY_NO_UPDATE: &str = "CREATE TRIGGER determa_authority_boundary_forbid_update BEFORE UPDATE ON determa_authority_boundary BEGIN SELECT RAISE(ABORT, 'authority_boundary_immutable'); END";
const BOUNDARY_NO_DELETE: &str = "CREATE TRIGGER determa_authority_boundary_forbid_delete BEFORE DELETE ON determa_authority_boundary BEGIN SELECT RAISE(ABORT, 'authority_boundary_immutable'); END";

#[derive(Debug)]
pub struct AuthorityError(String);

impl std::fmt::Display for AuthorityError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}
impl std::error::Error for AuthorityError {}

fn failure(error: impl std::fmt::Display) -> AuthorityError {
    AuthorityError(error.to_string())
}
fn canonical(value: &Value) -> Result<Vec<u8>, AuthorityError> {
    serde_json_canonicalizer::to_vec(value).map_err(failure)
}
fn hash(value: &Value) -> Result<String, AuthorityError> {
    Ok(format!("sha256:{:x}", Sha256::digest(canonical(value)?)))
}

/// Authentication and rights supplied by trusted native transport/host code.
/// Portable request principal fields never construct this context.
pub struct NativeAuthorityInvocation {
    pub authenticated_principal: String,
    pub authorized_scopes: BTreeSet<String>,
    pub operation_rights: BTreeSet<String>,
}

/// One permanent scope in one configured SQLite authority boundary.
pub struct SqliteLocalAuthority {
    connection: Mutex<Connection>,
    storage_binding: String,
}

impl SqliteLocalAuthority {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AuthorityError> {
        if !path.as_ref().is_absolute() || path.as_ref() == Path::new(":memory:") {
            return Err(failure("a persistent absolute SQLite path is required"));
        }
        let connection = Connection::open(path).map_err(failure)?;
        let storage_binding = connection
            .path()
            .ok_or_else(|| failure("persistent authority path absent"))?;
        let storage_binding = std::fs::canonicalize(storage_binding)
            .map_err(failure)?
            .to_str()
            .ok_or_else(|| failure("authority path must be UTF-8"))?
            .to_owned();
        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;",
            )
            .map_err(failure)?;
        Ok(Self {
            connection: Mutex::new(connection),
            storage_binding,
        })
    }

    pub fn setup_schema(&self) -> Result<(), AuthorityError> {
        let mut connection = self.connection.lock().map_err(failure)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(failure)?;
        for sql in [
            RECORDS,
            ALLOCATIONS,
            MUTATIONS,
            NO_DELETE,
            NO_UPDATE,
            BOUNDARY,
            BOUNDARY_NO_UPDATE,
            BOUNDARY_NO_DELETE,
        ] {
            let explicit = if sql.starts_with("CREATE TABLE") {
                sql.replacen("CREATE TABLE", "CREATE TABLE IF NOT EXISTS", 1)
            } else {
                sql.replacen("CREATE TRIGGER", "CREATE TRIGGER IF NOT EXISTS", 1)
            };
            transaction.execute_batch(&explicit).map_err(failure)?;
        }
        transaction.execute("INSERT INTO determa_authority_boundary VALUES (1,?) ON CONFLICT(boundary_id) DO NOTHING",
                            [&self.storage_binding]).map_err(failure)?;
        validate_schema(&transaction, &self.storage_binding)?;
        transaction.commit().map_err(failure)
    }

    pub fn validate_schema(&self) -> Result<(), AuthorityError> {
        let connection = self.connection.lock().map_err(failure)?;
        validate_schema(&connection, &self.storage_binding)
    }

    /// Allocate trusted ownership once; no imported archive can perform this step.
    pub fn allocate(
        &self,
        scope: &str,
        owner_principal: &str,
        host_binding: &str,
    ) -> Result<bool, AuthorityError> {
        if scope.is_empty() || owner_principal.is_empty() || host_binding.is_empty() {
            return Err(failure("scope, owner and host binding are required"));
        }
        let mut connection = self.connection.lock().map_err(failure)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(failure)?;
        validate_schema(&transaction, &self.storage_binding)?;
        let count: u64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM determa_scope_allocations",
                [],
                |row| row.get(0),
            )
            .map_err(failure)?;
        if count != 0 {
            return Ok(false);
        }
        let owner = json!({"owner_principal": owner_principal, "host_binding": host_binding});
        let record = json!({"scope_identity": scope, "ownership_binding_digest": hash(&owner)?,
            "authority_epoch": "0", "owner_binding": owner, "state": "active",
            "scope_generation": "0", "active_transfer_id": null, "receipts": []});
        transaction
            .execute("INSERT INTO determa_scope_allocations VALUES (?)", [scope])
            .map_err(failure)?;
        transaction
            .execute(
                "INSERT INTO determa_scope_authority VALUES (?,?)",
                params![scope, canonical(&record)?],
            )
            .map_err(failure)?;
        transaction.commit().map_err(failure)?;
        Ok(true)
    }

    /// Execute the exact closed operation. Mutation bytes originate in native host
    /// code; the portable guarded_commit request contains only their digest.
    pub fn perform(
        &self,
        request_bytes: &[u8],
        invocation: &NativeAuthorityInvocation,
        proposed_native_mutation: Option<&[u8]>,
    ) -> Result<Value, AuthorityError> {
        let request = match strict_json::parse(request_bytes) {
            Ok(value) => value,
            Err(_) => return response(None, None, Some("invalid_host_request")),
        };
        let early_error = validate_request(&request)?;
        if let Some(code) = early_error {
            return response(None, None, Some(code));
        }
        let scope = request["scope_identity"].as_str().expect("validated scope");
        let operation = request["operation"].as_str().expect("validated operation");
        if invocation.authenticated_principal.is_empty()
            || !invocation.authorized_scopes.contains(scope)
            || !invocation.operation_rights.contains(operation)
        {
            return response(Some(&request), None, Some("unauthorized_scope"));
        }
        let mut connection = self.connection.lock().map_err(failure)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(failure)?;
        if validate_schema(&transaction, &self.storage_binding).is_err() {
            return response(Some(&request), None, Some("host_capability_mismatch"));
        }
        let bytes: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT ledger FROM determa_scope_authority WHERE scope_identity=?",
                [scope],
                |row| row.get(0),
            )
            .optional()
            .map_err(failure)?;
        let Some(bytes) = bytes else {
            return response(Some(&request), None, Some("unauthorized_scope"));
        };
        let mut record = strict_json::parse(&bytes).map_err(failure)?;
        if canonical(&record)? != bytes {
            return Err(failure("authority ledger is not canonical"));
        }
        if operation != "read_authority" {
            if let Some(receipt) = record["receipts"]
                .as_array()
                .ok_or_else(|| failure("authority receipts absent"))?
                .iter()
                .find(|receipt| receipt["operation_id"] == request["operation_id"])
            {
                if receipt["request_digest"] != request["request_digest"] {
                    return response(
                        Some(&request),
                        Some(&record),
                        Some("scope_operation_conflict"),
                    );
                }
                return Ok(receipt["result"].clone());
            }
        }
        if operation == "read_authority" {
            return response(Some(&request), Some(&record), None);
        }
        if operation != "guarded_commit" {
            // A ledger/schema by itself is not proof of worker, inventory or retirement support.
            return response(
                Some(&request),
                Some(&record),
                Some("host_capability_mismatch"),
            );
        }
        if record["state"] == "transaction_in_doubt" {
            return response(
                Some(&request),
                Some(&record),
                Some("scope_transaction_in_doubt"),
            );
        }
        if request["expected_authority_epoch"] != record["authority_epoch"]
            || record["state"] != "active"
            || record["owner_binding"]["owner_principal"] != invocation.authenticated_principal
        {
            return response(Some(&request), Some(&record), Some("stale_scope_authority"));
        }
        if request["expected_scope_generation"] != record["scope_generation"] {
            return response(
                Some(&request),
                Some(&record),
                Some("scope_generation_conflict"),
            );
        }
        let Some(mutation) = proposed_native_mutation else {
            return response(Some(&request), Some(&record), Some("invalid_host_request"));
        };
        let digest = format!("sha256:{:x}", Sha256::digest(mutation));
        if request["arguments"]["mutation_digest"] != digest {
            return response(Some(&request), Some(&record), Some("invalid_host_request"));
        }
        let generation = record["scope_generation"]
            .as_str()
            .ok_or_else(|| failure("generation absent"))?
            .parse::<BigUint>()
            .map_err(failure)?;
        record["scope_generation"] = json!((generation + BigUint::from(1u8)).to_string());
        let result = response(Some(&request), Some(&record), None)?;
        record["receipts"]
            .as_array_mut()
            .ok_or_else(|| failure("receipts absent"))?
            .push(json!({
            "operation_id": request["operation_id"], "request_digest": request["request_digest"],
            "request": request, "result": result}));
        transaction
            .execute(
                "INSERT INTO determa_authority_mutations VALUES (?,?,?,?)",
                params![
                    scope,
                    request["operation_id"]
                        .as_str()
                        .expect("validated operation id"),
                    digest,
                    mutation
                ],
            )
            .map_err(failure)?;
        transaction
            .execute(
                "UPDATE determa_scope_authority SET ledger=? WHERE scope_identity=?",
                params![canonical(&record)?, scope],
            )
            .map_err(failure)?;
        transaction.commit().map_err(failure)?;
        Ok(result)
    }
}

fn validate_schema(connection: &Connection, storage_binding: &str) -> Result<(), AuthorityError> {
    let journal: String = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .map_err(failure)?;
    let synchronous: u32 = connection
        .query_row("PRAGMA synchronous", [], |row| row.get(0))
        .map_err(failure)?;
    let integrity: String = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(failure)?;
    if journal != "wal" || synchronous != 2 || integrity != "ok" {
        return Err(failure("authority native health mismatch"));
    }
    for (name, expected) in [
        ("determa_scope_authority", RECORDS),
        ("determa_scope_allocations", ALLOCATIONS),
        ("determa_authority_mutations", MUTATIONS),
        ("determa_scope_allocations_forbid_delete", NO_DELETE),
        ("determa_scope_allocations_forbid_update", NO_UPDATE),
        ("determa_authority_boundary", BOUNDARY),
        (
            "determa_authority_boundary_forbid_update",
            BOUNDARY_NO_UPDATE,
        ),
        (
            "determa_authority_boundary_forbid_delete",
            BOUNDARY_NO_DELETE,
        ),
    ] {
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE name=?",
                [name],
                |row| row.get(0),
            )
            .optional()
            .map_err(failure)?;
        if actual.as_deref() != Some(expected) {
            return Err(failure("authority schema mismatch"));
        }
    }
    let count: u64 = connection
        .query_row(
            "SELECT COUNT(*) FROM determa_scope_allocations",
            [],
            |row| row.get(0),
        )
        .map_err(failure)?;
    if count > 1 {
        return Err(failure("authority topology requires one permanent scope"));
    }
    let objects: u64 = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE sql IS NOT NULL AND (tbl_name IN ('determa_scope_authority','determa_scope_allocations','determa_authority_mutations','determa_authority_boundary') OR name LIKE 'determa_scope_%' OR name LIKE 'determa_authority_%')",
        [], |row| row.get(0)).map_err(failure)?;
    if objects != 8 {
        return Err(failure("unexpected authority schema object"));
    }
    let boundary: String = connection
        .query_row(
            "SELECT storage_binding FROM determa_authority_boundary WHERE boundary_id=1",
            [],
            |row| row.get(0),
        )
        .map_err(failure)?;
    if boundary != storage_binding {
        return Err(failure("copied authority boundary is inactive"));
    }
    Ok(())
}

fn validate_request(request: &Value) -> Result<Option<&'static str>, AuthorityError> {
    if !request.is_object() {
        return Ok(Some("invalid_host_request"));
    }
    if request["interface"] != "determa.host_authority" {
        return Ok(Some("unsupported_host_protocol"));
    }
    if request["interface_version"].as_u64() != Some(1) {
        return Ok(Some("unsupported_host_protocol_version"));
    }
    static VALIDATOR: OnceLock<jsonschema::Validator> = OnceLock::new();
    let validator = VALIDATOR.get_or_init(|| {
        let mut schema: Value = serde_json::from_str(include_str!(
            "../schema/host-authority-operation-v1.schema.json"
        ))
        .expect("pinned authority schema");
        schema
            .as_object_mut()
            .expect("schema object")
            .remove("oneOf");
        schema["$ref"] = json!("#/$defs/request");
        jsonschema::validator_for(&schema).expect("valid pinned authority request schema")
    });
    if !validator.is_valid(request) {
        return Ok(Some("invalid_host_request"));
    }
    let mut body = request.clone();
    body.as_object_mut()
        .expect("validated request")
        .remove("request_digest");
    if request["request_digest"] != hash(&json!(["determa-host-authority-request-1", body]))? {
        return Ok(Some("invalid_host_request"));
    }
    Ok(None)
}

fn response(
    request: Option<&Value>,
    record: Option<&Value>,
    error: Option<&str>,
) -> Result<Value, AuthorityError> {
    let visible = if error == Some("unauthorized_scope") {
        None
    } else {
        record
    };
    let mut result = json!({"interface": "determa.host_authority", "interface_version": 1,
        "operation": request.map(|r| &r["operation"]), "operation_id": request.map(|r| &r["operation_id"]),
        "status": if error.is_none() { "accepted" } else { "rejected" },
        "scope_identity": if error == Some("unauthorized_scope") { None } else { request.map(|r| &r["scope_identity"]) },
        "authority_epoch": visible.map(|r| &r["authority_epoch"]), "scope_generation": visible.map(|r| &r["scope_generation"]),
        "state": visible.map(|r| &r["state"]), "evidence_digest": null, "error_code": error, "claim": null});
    if error.is_none() {
        let mut body = result.clone();
        body.as_object_mut()
            .expect("result object")
            .remove("evidence_digest");
        result["evidence_digest"] = json!(hash(&json!([
            "determa-host-authority-evidence-1",
            request.expect("successful request")["request_digest"],
            body
        ]))?);
    }
    Ok(result)
}
