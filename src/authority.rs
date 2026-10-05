//! Explicit local SQLite scope authority, separate from portable machine state.
//!
//! This implementation checkpoint provides permanent allocation and actual native
//! guarded mutation/receipt commits. Host checkpoint composition, complete frozen
//! inventories, worker fences, relocation and verified registration remain unfinished.
//! No completed authority profile or capability claim is advertised.

mod effects;
mod store;
pub use effects::{
    NativeEffectClaimRequest, NativeEffectProductionRequest, NativeEffectRoute,
    NativeEffectWorkerAuthority, SqliteNativeEffectHost,
};
pub use store::GuardedSqliteExecutionStore;

use crate::checkpoint::{DurableStoreMode, ExecutionCheckpoint, MutationGuard, StoreRecord};
use crate::format1::strict_json;
use num_bigint::BigUint;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::{Mutex, OnceLock};

const EFFECT_JOURNALS: &str = "CREATE TABLE determa_authority_effect_journals (root_instance_id TEXT PRIMARY KEY NOT NULL, scope_identity TEXT NOT NULL, document BLOB NOT NULL)";

const RECORDS: &str = "CREATE TABLE determa_scope_authority (scope_identity TEXT PRIMARY KEY NOT NULL, ledger BLOB NOT NULL)";
const ALLOCATIONS: &str =
    "CREATE TABLE determa_scope_allocations (scope_identity TEXT PRIMARY KEY NOT NULL, ownership_binding_digest TEXT NOT NULL, owner_binding BLOB NOT NULL)";
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
                "PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;",
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
        let existing: u64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'",
                [],
                |row| row.get(0),
            )
            .map_err(failure)?;
        if existing != 0 {
            // Existing authority data must retain its original allocation and
            // storage-boundary evidence. Setup never repairs missing evidence.
            validate_schema(&transaction, &self.storage_binding)?;
            return transaction.commit().map_err(failure);
        }
        for sql in [
            RECORDS,
            EFFECT_JOURNALS,
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
        if checkpoint_count(&transaction)?.is_some_and(|count| count != 0) {
            return Err(failure(
                "existing checkpoints cannot acquire fresh authority implicitly",
            ));
        }
        let owner = json!({"owner_principal": owner_principal, "host_binding": host_binding});
        let record = json!({"scope_identity": scope, "ownership_binding_digest": hash(&owner)?,
            "authority_epoch": "0", "owner_binding": owner, "state": "active",
            "scope_generation": "0", "active_transfer_id": null, "receipts": []});
        transaction
            .execute(
                "INSERT INTO determa_scope_allocations VALUES (?,?,?)",
                params![scope, hash(&owner)?, canonical(&owner)?],
            )
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
        self.perform_native(
            request_bytes,
            invocation,
            proposed_native_mutation,
            None,
            |_| Ok(()),
        )
    }

    /// Bind an actual root checkpoint insert or CAS to the authority commit.
    /// The request digest covers `checkpoint_mutation_bytes`; no SQL or native
    /// transaction is supplied through the portable request.
    /// Only a checkpoint returned by validated create/restore APIs is accepted.
    /// Public storage records cannot bypass this boundary, including bounded mode.
    ///
    /// ```compile_fail
    /// use determa_state::authority::{NativeAuthorityInvocation, SqliteLocalAuthority};
    /// use determa_state::checkpoint::{DurableStoreMode, StoreRecord};
    /// fn invalid(authority: &SqliteLocalAuthority, caller: &NativeAuthorityInvocation,
    ///            record: &StoreRecord) {
    ///     authority.commit_checkpoint(b"{}", caller, DurableStoreMode::bounded(), record, None);
    /// }
    /// ```
    pub fn commit_checkpoint(
        &self,
        request_bytes: &[u8],
        invocation: &NativeAuthorityInvocation,
        mode: DurableStoreMode,
        replacement: &ExecutionCheckpoint,
        guard: Option<&MutationGuard>,
    ) -> Result<Value, AuthorityError> {
        let mutation = checkpoint_mutation_bytes(replacement, guard)?;
        let native_record = StoreRecord::from_checkpoint(replacement).map_err(failure)?;
        let replacement = &native_record;
        self.perform_native(
            request_bytes,
            invocation,
            Some(&mutation),
            Some("checkpoint"),
            |transaction| apply_checkpoint(transaction, mode, replacement, guard),
        )
    }

    fn perform_native(
        &self,
        request_bytes: &[u8],
        invocation: &NativeAuthorityInvocation,
        proposed_native_mutation: Option<&[u8]>,
        native_kind: Option<&str>,
        apply: impl FnOnce(&Connection) -> Result<(), AuthorityError>,
    ) -> Result<Value, AuthorityError> {
        self.perform_native_with_final_guard(
            request_bytes,
            invocation,
            proposed_native_mutation,
            native_kind,
            apply,
            || Ok(()),
        )
    }

    fn perform_native_with_final_guard(
        &self,
        request_bytes: &[u8],
        invocation: &NativeAuthorityInvocation,
        proposed_native_mutation: Option<&[u8]>,
        native_kind: Option<&str>,
        apply: impl FnOnce(&Connection) -> Result<(), AuthorityError>,
        final_guard: impl FnOnce() -> Result<(), AuthorityError>,
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
        let mut record = match strict_json::parse(&bytes) {
            Ok(record)
                if canonical(&record)? == bytes
                    && validate_record(&transaction, scope, &record).is_ok() =>
            {
                record
            }
            _ => return response(Some(&request), None, Some("host_capability_mismatch")),
        };
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
        let parsed_native = strict_json::parse(mutation).ok();
        let declared_kind = parsed_native
            .as_ref()
            .and_then(|value| value["native_mutation"].as_str())
            .filter(|kind| {
                matches!(
                    *kind,
                    "checkpoint" | "checkpoint_effect_journal" | "effect_journal"
                )
            });
        if declared_kind != native_kind {
            return response(Some(&request), Some(&record), Some("invalid_host_request"));
        }
        apply(&transaction)?;
        let generation = record["scope_generation"]
            .as_str()
            .ok_or_else(|| failure("generation absent"))?
            .parse::<BigUint>()
            .map_err(failure)?;
        record["scope_generation"] = json!((generation + BigUint::from(1u8)).to_string());
        let result = response(Some(&request), Some(&record), None)?;
        let mut receipt = json!({
            "operation_id": request["operation_id"], "request_digest": request["request_digest"],
            "request": request, "result": result});
        if let Some(kind) = native_kind {
            receipt["native_kind"] = json!(kind);
        }
        record["receipts"]
            .as_array_mut()
            .ok_or_else(|| failure("receipts absent"))?
            .push(receipt);
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
        // No resolver, provider, transport callback or additional staged write
        // may run after this last consuming authorization/clock proof.
        final_guard()?;
        transaction.commit().map_err(failure)?;
        Ok(result)
    }
}

/// Exact native checkpoint mutation identity, including root and CAS preconditions.
/// This host envelope is not added to the portable checkpoint or machine grammar.
pub fn checkpoint_mutation_bytes(
    validated: &ExecutionCheckpoint,
    guard: Option<&MutationGuard>,
) -> Result<Vec<u8>, AuthorityError> {
    let record = StoreRecord::from_checkpoint(validated).map_err(failure)?;
    let checkpoint = strict_json::parse(&record.bytes).map_err(failure)?;
    if canonical(&checkpoint)? != record.bytes
        || checkpoint["root_instance_id"] != record.root_instance_id
        || checkpoint["revision"] != record.revision
        || checkpoint["execution_checkpoint_digest"] != record.execution_checkpoint_digest
    {
        return Err(failure("checkpoint native metadata mismatch"));
    }
    canonical(
        &json!({"native_mutation": "checkpoint", "root_instance_id": record.root_instance_id,
        "expected_revision": guard.map(|g| &g.expected_revision),
        "expected_checkpoint_digest": guard.map(|g| &g.expected_checkpoint_digest),
        "checkpoint": checkpoint}),
    )
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
        ("determa_authority_effect_journals", EFFECT_JOURNALS),
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
    if objects != 9 {
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

fn closed(value: &Value, members: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == members.len() && members.iter().all(|member| object.contains_key(*member))
    })
}

fn validate_record(
    connection: &Connection,
    scope: &str,
    record: &Value,
) -> Result<(), AuthorityError> {
    if !closed(
        record,
        &[
            "scope_identity",
            "ownership_binding_digest",
            "authority_epoch",
            "owner_binding",
            "state",
            "scope_generation",
            "active_transfer_id",
            "receipts",
        ],
    ) || record["scope_identity"] != scope
        || record["authority_epoch"] != "0"
        || !record["active_transfer_id"].is_null()
        || !matches!(
            record["state"].as_str(),
            Some("active" | "transaction_in_doubt")
        )
        || !closed(
            &record["owner_binding"],
            &["owner_principal", "host_binding"],
        )
        || ["owner_principal", "host_binding"].iter().any(|key| {
            record["owner_binding"][key]
                .as_str()
                .is_none_or(str::is_empty)
        })
        || record["ownership_binding_digest"] != hash(&record["owner_binding"])?
    {
        return Err(failure("authority identity/ownership record mismatch"));
    }
    let allocation: Option<(String, Vec<u8>)> = connection
        .query_row(
            "SELECT ownership_binding_digest, owner_binding FROM determa_scope_allocations WHERE scope_identity=?",
            [scope],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(failure)?;
    let Some((digest, owner)) = allocation else {
        return Err(failure("authority permanent allocation absent"));
    };
    if record["ownership_binding_digest"] != digest || canonical(&record["owner_binding"])? != owner
    {
        return Err(failure(
            "authority ownership differs from immutable allocation",
        ));
    }
    let receipts = record["receipts"]
        .as_array()
        .ok_or_else(|| failure("authority receipts must be an array"))?;
    if record["scope_generation"].as_str() != Some(receipts.len().to_string().as_str()) {
        return Err(failure(
            "authority generation does not match complete receipt history",
        ));
    }
    let mutations: u64 = connection
        .query_row(
            "SELECT COUNT(*) FROM determa_authority_mutations",
            [],
            |row| row.get(0),
        )
        .map_err(failure)?;
    if mutations != receipts.len() as u64 {
        return Err(failure("native authority mutation inventory mismatch"));
    }
    let mut identifiers = BTreeSet::new();
    let mut latest_checkpoints: BTreeMap<String, Value> = BTreeMap::new();
    let mut latest_journals: BTreeMap<String, Value> = BTreeMap::new();
    for (index, receipt) in receipts.iter().enumerate() {
        let joint_receipt = receipt["native_kind"] == "checkpoint_effect_journal";
        let checkpoint_receipt = receipt["native_kind"] == "checkpoint" || joint_receipt;
        if !(closed(
            receipt,
            &["operation_id", "request_digest", "request", "result"],
        ) || checkpoint_receipt
            && closed(
                receipt,
                &[
                    "operation_id",
                    "request_digest",
                    "request",
                    "result",
                    "native_kind",
                ],
            ))
        {
            return Err(failure("authority receipt shape mismatch"));
        }
        let request = &receipt["request"];
        if validate_request(request)?.is_some()
            || request["operation"] != "guarded_commit"
            || request["scope_identity"] != scope
            || request["expected_authority_epoch"] != "0"
            || request["expected_scope_generation"].as_str() != Some(index.to_string().as_str())
            || receipt["request_digest"] != request["request_digest"]
            || receipt["operation_id"] != request["operation_id"]
        {
            return Err(failure("authority receipt request binding mismatch"));
        }
        let identifier = receipt["operation_id"]
            .as_str()
            .ok_or_else(|| failure("receipt operation id absent"))?;
        if !identifiers.insert(identifier) {
            return Err(failure("duplicate authority receipt identity"));
        }
        let mut historical = record.clone();
        historical["state"] = json!("active");
        historical["scope_generation"] = json!((index + 1).to_string());
        if receipt["result"] != response(Some(request), Some(&historical), None)? {
            return Err(failure(
                "authority retained result/evidence digest mismatch",
            ));
        }
        let native: Option<(String, Vec<u8>)> = connection.query_row(
            "SELECT mutation_digest,mutation FROM determa_authority_mutations WHERE scope_identity=? AND operation_id=?",
            params![scope, identifier], |row| Ok((row.get(0)?, row.get(1)?))).optional().map_err(failure)?;
        let Some((digest, bytes)) = native else {
            return Err(failure("retained native mutation absent"));
        };
        if request["arguments"]["mutation_digest"] != digest
            || digest != format!("sha256:{:x}", Sha256::digest(&bytes))
        {
            return Err(failure("retained native mutation digest mismatch"));
        }
        let parsed_native = strict_json::parse(&bytes).ok();
        let declared_kind = parsed_native
            .as_ref()
            .and_then(|value| value["native_mutation"].as_str())
            .filter(|kind| {
                matches!(
                    *kind,
                    "checkpoint" | "checkpoint_effect_journal" | "effect_journal"
                )
            });
        if declared_kind != receipt["native_kind"].as_str() {
            return Err(failure("native checkpoint receipt kind binding mismatch"));
        }
        if checkpoint_receipt {
            let mutation = strict_json::parse(&bytes).map_err(failure)?;
            if canonical(&mutation)? != bytes
                || !closed(
                    &mutation,
                    if joint_receipt {
                        &[
                            "native_mutation",
                            "root_instance_id",
                            "expected_revision",
                            "expected_checkpoint_digest",
                            "checkpoint",
                            "effect_document",
                        ]
                    } else {
                        &[
                            "native_mutation",
                            "root_instance_id",
                            "expected_revision",
                            "expected_checkpoint_digest",
                            "checkpoint",
                        ]
                    },
                )
                || mutation["native_mutation"] != receipt["native_kind"]
            {
                return Err(failure("retained checkpoint mutation malformed"));
            }
            let root = mutation["root_instance_id"]
                .as_str()
                .ok_or_else(|| failure("checkpoint root absent"))?;
            if root.is_empty() || mutation["checkpoint"]["root_instance_id"] != root {
                return Err(failure("checkpoint mutation root mismatch"));
            }
            if joint_receipt {
                if let Some(prior_document) = latest_journals.get(root) {
                    let prior_checkpoint = latest_checkpoints
                        .get(root)
                        .ok_or_else(|| failure("prior native checkpoint absent"))?;
                    if mutation["expected_revision"] != prior_checkpoint["revision"]
                        || mutation["expected_checkpoint_digest"]
                            != prior_checkpoint["execution_checkpoint_digest"]
                    {
                        return Err(failure("native joint history guard mismatch"));
                    }
                    validate_native_effect_transition(
                        prior_document,
                        prior_checkpoint,
                        &mutation["effect_document"],
                        &mutation["checkpoint"],
                        scope,
                    )?;
                } else {
                    if !mutation["expected_revision"].is_null()
                        || !mutation["expected_checkpoint_digest"].is_null()
                        || latest_checkpoints.contains_key(root)
                    {
                        return Err(failure(
                            "effect participant must originate in fresh native creation",
                        ));
                    }
                    validate_native_effect_document(
                        &mutation["effect_document"],
                        &mutation["checkpoint"],
                        scope,
                    )?;
                }
                latest_journals.insert(root.to_owned(), mutation["effect_document"].clone());
            } else if latest_journals.contains_key(root) {
                return Err(failure(
                    "plain checkpoint mutation bypasses effect participant",
                ));
            }
            latest_checkpoints.insert(root.to_owned(), mutation["checkpoint"].clone());
        }
    }
    let journal_count: u64 = connection
        .query_row(
            "SELECT COUNT(*) FROM determa_authority_effect_journals",
            [],
            |row| row.get(0),
        )
        .map_err(failure)?;
    if journal_count != latest_journals.len() as u64 {
        return Err(failure("native effect journal inventory mismatch"));
    }
    for (root, document) in latest_journals {
        let actual: Option<(String,Vec<u8>)> = connection.query_row("SELECT scope_identity,document FROM determa_authority_effect_journals WHERE root_instance_id=?",[&root],|row|Ok((row.get(0)?,row.get(1)?))).optional().map_err(failure)?;
        if actual != Some((scope.to_owned(), canonical(&document)?)) {
            return Err(failure(
                "native effect journal differs from committed evidence",
            ));
        }
    }
    if checkpoint_count(connection)?.is_some_and(|count| count != latest_checkpoints.len() as u64) {
        return Err(failure(
            "checkpoint inventory differs from native guarded history",
        ));
    }
    for (root, checkpoint) in latest_checkpoints {
        let actual = crate::checkpoint::load_sqlite_record(connection, &root)
            .map_err(failure)?
            .ok_or_else(|| failure("guarded checkpoint absent"))?;
        if actual.bytes != canonical(&checkpoint)?
            || checkpoint["revision"] != actual.revision
            || checkpoint["execution_checkpoint_digest"] != actual.execution_checkpoint_digest
        {
            return Err(failure(
                "guarded checkpoint no longer matches committed evidence",
            ));
        }
    }
    Ok(())
}

fn checkpoint_count(connection: &Connection) -> Result<Option<u64>, AuthorityError> {
    let exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='determa_execution_checkpoints')",
        [], |row| row.get(0),
    ).map_err(failure)?;
    if exists {
        connection
            .query_row(
                "SELECT COUNT(*) FROM determa_execution_checkpoints",
                [],
                |row| row.get(0),
            )
            .map(Some)
            .map_err(failure)
    } else {
        Ok(None)
    }
}

// Native genesis remains fresh creation. Subsequent joint mutations are limited
// to complete admission/production transitions with immutable prior helper history.
fn validate_native_effect_document(
    document: &Value,
    checkpoint: &Value,
    scope: &str,
) -> Result<(), AuthorityError> {
    if !closed(document, &["journal", "responses", "original_requests"]) {
        return Err(failure("native effect document shape mismatch"));
    }
    let journal = &document["journal"];
    if !closed(
        journal,
        &[
            "host_effect_journal_format",
            "host_effect_journal_schema_version",
            "scope_identity",
            "root_instance_id",
            "checkpoint_revision",
            "checkpoint_digest",
            "journal_revision",
            "effect_records",
            "operation_response_references",
            "host_effect_journal_digest",
        ],
    ) || journal["host_effect_journal_format"] != "determa.host_effect_journal"
        || journal["host_effect_journal_schema_version"] != 1
        || journal["journal_revision"] != "0"
    {
        return Err(failure("fresh native journal shape/version mismatch"));
    }

    let mut unsigned = journal.clone();
    unsigned
        .as_object_mut()
        .ok_or_else(|| failure("native journal absent"))?
        .remove("host_effect_journal_digest");
    if journal["scope_identity"] != scope
        || journal["root_instance_id"] != checkpoint["root_instance_id"]
        || journal["checkpoint_revision"] != checkpoint["revision"]
        || journal["checkpoint_digest"] != checkpoint["execution_checkpoint_digest"]
        || journal["host_effect_journal_digest"]
            != hash(&json!(["determa-host-effect-journal-digest-1", unsigned]))?
    {
        return Err(failure("native checkpoint/effect journal pair mismatch"));
    }
    let bodies = document["responses"]
        .as_object()
        .ok_or_else(|| failure("native responses absent"))?;
    let requests = document["original_requests"]
        .as_object()
        .ok_or_else(|| failure("native original requests absent"))?;
    let references = journal["operation_response_references"]
        .as_array()
        .ok_or_else(|| failure("native response references absent"))?;
    if bodies.len() != 1 || requests.len() != 1 || references.len() != 1 {
        return Err(failure("fresh creation response inventory mismatch"));
    }
    let receipt = &checkpoint["operation_receipts"][0];
    let operation_id = receipt["creation_id"]
        .as_str()
        .ok_or_else(|| failure("actual creation identity absent"))?;
    let body = bodies
        .get(operation_id)
        .ok_or_else(|| failure("actual creation response absent"))?;
    let request = requests
        .get(operation_id)
        .ok_or_else(|| failure("actual creation request absent"))?;
    if request != &json!({"operation_kind":"creation","request_digest":receipt["request_digest"]})
        || !closed(
            body,
            &[
                "checkpoint",
                "creation_receipt",
                "status",
                "emissions",
                "lifecycle_dispositions",
                "fault",
            ],
        )
        || body["checkpoint"] != *checkpoint
        || body["creation_receipt"] != *receipt
        || references[0]["operation_id"] != operation_id
        || references[0]["response_digest"]
            != hash(&json!(["determa-host-operation-response-1", body]))?
    {
        return Err(failure("native creation response/request binding mismatch"));
    }
    Ok(())
}

// Complete admission-only field invariant, without executing a core operation
// during retained-response replay. All other checkpoint/runtime fields are fixed.
fn validate_native_admission_checkpoint_transition(
    prior: &Value,
    candidate: &Value,
    delivery: &Value,
    result: &Value,
) -> Result<(), AuthorityError> {
    if !closed(delivery, &["delivery_mode", "envelope", "envelope_digest"])
        || delivery["delivery_mode"] != "input"
    {
        return Err(failure(
            "native external admission requires exact input delivery",
        ));
    }
    let prior_receipts = prior["operation_receipts"]
        .as_array()
        .ok_or_else(|| failure("prior operation receipts absent"))?;
    if let Some(receipt) = prior_receipts.iter().find(|receipt| {
        receipt["operation_kind"] == "acceptance"
            && receipt["event_id"] == delivery["envelope"]["event_id"]
    }) {
        if candidate != prior
            || result != receipt
            || receipt["request_digest"] != delivery["envelope_digest"]
            || receipt["delivery_mode"] != "input"
        {
            return Err(failure(
                "duplicate native admission changed checkpoint/evidence",
            ));
        }
        return Ok(());
    }
    let mut expected = prior.clone();
    let aggregate = &mut expected["root_record"]["aggregate_state"];
    let acceptance = aggregate["next_acceptance_sequence"].clone();
    let queue = aggregate["next_queue_sequence"].clone();
    let entry = json!({"acceptance_sequence":acceptance,"queue_sequence":queue,
        "delivery_mode":"input","envelope":delivery["envelope"],
        "envelope_digest":delivery["envelope_digest"],"deferral_count":"0"});
    let runtimes = aggregate["runtimes"]
        .as_array_mut()
        .ok_or_else(|| failure("prior runtimes absent"))?;
    let proposed = candidate["root_record"]["aggregate_state"]["runtimes"]
        .as_array()
        .ok_or_else(|| failure("candidate runtimes absent"))?;
    if runtimes.len() != proposed.len() {
        return Err(failure("admission changed runtime inventory"));
    }
    let index = runtimes
        .iter()
        .zip(proposed)
        .position(|(old, new)| old["ready_mailbox"] != new["ready_mailbox"])
        .ok_or_else(|| failure("actual admission queue insertion absent"))?;
    runtimes[index]["ready_mailbox"]
        .as_array_mut()
        .ok_or_else(|| failure("prior ready mailbox absent"))?
        .push(entry);
    for field in ["next_acceptance_sequence", "next_queue_sequence"] {
        aggregate[field] = json!((aggregate[field]
            .as_str()
            .ok_or_else(|| failure("prior queue counter absent"))?
            .parse::<BigUint>()
            .map_err(failure)?
            + BigUint::from(1u8))
        .to_string());
    }
    aggregate
        .as_object_mut()
        .unwrap()
        .remove("aggregate_state_digest");
    aggregate["aggregate_state_digest"] = json!(hash(&json!([
        "determa-aggregate-state-digest-1",
        aggregate
    ]))?);
    expected["revision"] = json!((prior["revision"]
        .as_str()
        .ok_or_else(|| failure("prior revision absent"))?
        .parse::<BigUint>()
        .map_err(failure)?
        + BigUint::from(1u8))
    .to_string());
    expected["next_operation_receipt_sequence"] = json!((prior["next_operation_receipt_sequence"]
        .as_str()
        .ok_or_else(|| failure("prior receipt counter absent"))?
        .parse::<BigUint>()
        .map_err(failure)?
        + BigUint::from(1u8))
    .to_string());
    let receipt = json!({"operation_kind":"acceptance",
        "receipt_sequence":prior["next_operation_receipt_sequence"],
        "event_id":delivery["envelope"]["event_id"],"request_digest":delivery["envelope_digest"],
        "acceptance_sequence":acceptance,"accepted_revision":expected["revision"],"delivery_mode":"input"});
    expected["operation_receipts"]
        .as_array_mut()
        .unwrap()
        .push(receipt);
    expected
        .as_object_mut()
        .unwrap()
        .remove("execution_checkpoint_digest");
    expected["execution_checkpoint_digest"] = json!(hash(&json!([
        "determa-execution-checkpoint-digest-1",
        expected
    ]))?);
    if candidate != &expected || result != candidate {
        return Err(failure(
            "native admission changed unrelated checkpoint state",
        ));
    }
    Ok(())
}

// Admission-only transition: no worker, route, attempt, outcome or result state
// may change. Every previously committed response and caller request is immutable.
// Admission-only transition: no worker, route, attempt, outcome or result state
// may change. Every previously committed response and caller request is immutable.
fn validate_native_effect_transition(
    prior: &Value,
    prior_checkpoint: &Value,
    document: &Value,
    checkpoint: &Value,
    scope: &str,
) -> Result<(), AuthorityError> {
    if !closed(document, &["journal", "responses", "original_requests"]) {
        return Err(failure("native effect document shape mismatch"));
    }
    let journal = &document["journal"];
    let old_journal = &prior["journal"];
    let mut unsigned = journal.clone();
    unsigned
        .as_object_mut()
        .ok_or_else(|| failure("native journal absent"))?
        .remove("host_effect_journal_digest");
    let revision = old_journal["journal_revision"]
        .as_str()
        .ok_or_else(|| failure("prior journal revision absent"))?
        .parse::<BigUint>()
        .map_err(failure)?;
    if journal["scope_identity"] != scope
        || journal["root_instance_id"] != checkpoint["root_instance_id"]
        || checkpoint["root_instance_id"] != prior_checkpoint["root_instance_id"]
        || journal["checkpoint_revision"] != checkpoint["revision"]
        || journal["checkpoint_digest"] != checkpoint["execution_checkpoint_digest"]
        || journal["journal_revision"] != (revision + BigUint::from(1u8)).to_string()
        || journal["host_effect_journal_digest"]
            != hash(&json!(["determa-host-effect-journal-digest-1", unsigned]))?
    {
        return Err(failure("native admission journal transition mismatch"));
    }
    let bodies = document["responses"]
        .as_object()
        .ok_or_else(|| failure("native bodies absent"))?;
    let requests = document["original_requests"]
        .as_object()
        .ok_or_else(|| failure("native requests absent"))?;
    let old_bodies = prior["responses"]
        .as_object()
        .ok_or_else(|| failure("prior native bodies absent"))?;
    let old_requests = prior["original_requests"]
        .as_object()
        .ok_or_else(|| failure("prior native requests absent"))?;
    if bodies.len() != old_bodies.len() + 1
        || requests.len() != bodies.len()
        || old_bodies
            .iter()
            .any(|(id, body)| bodies.get(id) != Some(body))
        || old_requests
            .iter()
            .any(|(id, request)| requests.get(id) != Some(request))
        || requests.keys().any(|id| !bodies.contains_key(id))
    {
        return Err(failure(
            "native response/request immutable inventory mismatch",
        ));
    }
    let references = journal["operation_response_references"]
        .as_array()
        .ok_or_else(|| failure("native response references absent"))?;
    let mut prior_id: Option<&str> = None;
    if references.len() != bodies.len() {
        return Err(failure("native response inventory mismatch"));
    }
    for reference in references {
        let id = reference["operation_id"]
            .as_str()
            .filter(|id| !id.is_empty())
            .ok_or_else(|| failure("native operation identity absent"))?;
        if !closed(reference, &["operation_id", "response_digest"])
            || prior_id.is_some_and(|old| old.as_bytes() >= id.as_bytes())
            || reference["response_digest"]
                != hash(&json!([
                    "determa-host-operation-response-1",
                    bodies
                        .get(id)
                        .ok_or_else(|| failure("native retained response absent"))?
                ]))?
        {
            return Err(failure("native response reference mismatch"));
        }
        prior_id = Some(id);
    }
    let mut expected_journal = old_journal.clone();
    expected_journal["checkpoint_revision"] = checkpoint["revision"].clone();
    expected_journal["checkpoint_digest"] = checkpoint["execution_checkpoint_digest"].clone();
    expected_journal["journal_revision"] = journal["journal_revision"].clone();
    expected_journal["operation_response_references"] = json!(references);
    expected_journal["effect_records"] = journal["effect_records"].clone();
    expected_journal
        .as_object_mut()
        .unwrap()
        .remove("host_effect_journal_digest");
    expected_journal["host_effect_journal_digest"] = json!(hash(&json!([
        "determa-host-effect-journal-digest-1",
        expected_journal
    ]))?);
    if journal != &expected_journal {
        return Err(failure("admission changed immutable journal fields"));
    }
    let (id, body) = bodies
        .iter()
        .find(|(id, _)| !old_bodies.contains_key(*id))
        .ok_or_else(|| failure("new native response absent"))?;
    let request = requests
        .get(id)
        .ok_or_else(|| failure("new native request absent"))?;
    if request["operation_kind"] == "effect_result_admission" {
        return validate_native_effect_result_admission_transition(
            prior,
            prior_checkpoint,
            document,
            checkpoint,
            request,
            body,
        );
    }
    if request["operation_kind"] == "effect_report" {
        return validate_native_effect_report_transition(
            prior,
            prior_checkpoint,
            document,
            checkpoint,
            request,
            body,
        );
    }
    if request["operation_kind"] == "effect_claim" {
        return validate_native_effect_claim_transition(
            prior,
            prior_checkpoint,
            document,
            checkpoint,
            request,
            body,
        );
    }
    if request["operation_kind"] == "produce" {
        return validate_native_effect_production_transition(
            prior,
            prior_checkpoint,
            document,
            checkpoint,
            request,
            body,
        );
    }
    if journal["effect_records"] != old_journal["effect_records"] {
        return Err(failure("admission changed immutable effect records"));
    }
    if !closed(request, &["operation_kind", "root_instance_id", "delivery"])
        || request["operation_kind"] != "admission"
        || request["root_instance_id"] != checkpoint["root_instance_id"]
        || !closed(body, &["kind", "body"])
        || body["kind"] != "admission"
        || !closed(&body["body"], &["checkpoint", "admission_result"])
        || body["body"]["checkpoint"] != *checkpoint
    {
        return Err(failure("native admission response/request kind mismatch"));
    }
    let delivery = &request["delivery"];
    let digest = hash(&json!([
        "determa-inbox-envelope-digest-1",
        "1",
        checkpoint["root_instance_id"],
        delivery["delivery_mode"],
        delivery["envelope"]
    ]))?;
    if delivery["envelope_digest"] != digest {
        return Err(failure(
            "native admission original envelope digest mismatch",
        ));
    }
    let receipt = checkpoint["operation_receipts"]
        .as_array()
        .and_then(|receipts| {
            receipts.iter().find(|receipt| {
                receipt["operation_kind"] == "acceptance"
                    && receipt["event_id"] == delivery["envelope"]["event_id"]
                    && receipt["request_digest"] == digest
                    && receipt["delivery_mode"] == delivery["delivery_mode"]
            })
        })
        .ok_or_else(|| failure("native admission actual receipt absent"))?;
    let result = &body["body"]["admission_result"];
    if result != checkpoint && result != receipt {
        return Err(failure(
            "native admission result differs from actual checkpoint/receipt",
        ));
    }
    validate_native_admission_checkpoint_transition(
        prior_checkpoint,
        checkpoint,
        delivery,
        result,
    )?;
    Ok(())
}

// Retained native processing consistency, not portable replay admissibility. This
// reapplies only checkpoint bookkeeping to the already committed full core result;
// it does not execute author actions or dispatch native destination work on replay.
fn validate_native_effect_production_transition(
    prior: &Value,
    prior_checkpoint: &Value,
    document: &Value,
    checkpoint: &Value,
    request: &Value,
    response: &Value,
) -> Result<(), AuthorityError> {
    if !closed(
        request,
        &[
            "operation_kind",
            "root_instance_id",
            "target_runtime_id",
            "event_id",
            "envelope_digest",
            "acceptance_sequence",
            "queue_sequence",
            "processing_mode",
            "operation_token",
        ],
    ) || request["root_instance_id"] != prior_checkpoint["root_instance_id"]
        || request["operation_token"]
            .as_str()
            .is_none_or(|token| token.is_empty())
        || !matches!(
            request["processing_mode"].as_str(),
            Some("foreground" | "delayed")
        )
        || !closed(response, &["kind", "body"])
        || response["kind"] != "processing"
        || !closed(&response["body"], &["core_result", "receipt"])
    {
        return Err(failure(
            "native production original request/response kind mismatch",
        ));
    }
    let causal = prior_checkpoint["root_record"]["aggregate_state"]["runtimes"]
        .as_array()
        .and_then(|runtimes| {
            runtimes
                .iter()
                .find(|runtime| runtime["runtime_id"] == request["target_runtime_id"])
        })
        .and_then(|runtime| runtime["ready_mailbox"].as_array())
        .and_then(|queue| queue.first())
        .ok_or_else(|| failure("native processing causal ready head absent"))?;
    if causal["envelope"]["event_id"] != request["event_id"]
        || causal["envelope_digest"] != request["envelope_digest"]
        || causal["acceptance_sequence"] != request["acceptance_sequence"]
        || causal["queue_sequence"] != request["queue_sequence"]
    {
        return Err(failure(
            "native processing original causal identity mismatch",
        ));
    }
    let core = &response["body"]["core_result"];
    crate::format1::validate_native_core_step_result(core).map_err(failure)?;
    if !matches!(
        core["disposition"].as_str(),
        Some("handled" | "unhandled" | "faulted" | "deferred")
    ) {
        return Err(failure(
            "native processing did not produce a mutable core result",
        ));
    }
    let receipt = &response["body"]["receipt"];
    let ordinals = if core["disposition"] == "deferred" {
        if !receipt.is_null() {
            return Err(failure("deferred processing cannot claim terminal receipt"));
        }
        Vec::new()
    } else {
        let actual = checkpoint["operation_receipts"]
            .as_array()
            .and_then(|receipts| {
                receipts.iter().find(|item| {
                    item["operation_kind"] == "event_terminal"
                        && item["event_id"] == request["event_id"]
                        && item["committed_revision"] == checkpoint["revision"]
                })
            })
            .ok_or_else(|| failure("native processing actual terminal receipt absent"))?;
        if receipt != actual {
            return Err(failure("native processing returned a different receipt"));
        }
        actual["emission_references"]
            .as_array()
            .ok_or_else(|| failure("native emission references absent"))?
            .iter()
            .map(|reference| {
                reference["emission_index"]
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| failure("native emission ordinal absent"))
            })
            .collect::<Result<Vec<_>, _>>()?
    };
    let expected =
        crate::checkpoint::apply_step_result(prior_checkpoint, causal, core.clone(), ordinals)
            .map_err(failure)?;
    if &expected != checkpoint {
        return Err(failure(
            "native processing checkpoint/result consistency mismatch",
        ));
    }
    let old_records = prior["journal"]["effect_records"]
        .as_array()
        .ok_or_else(|| failure("prior effect records absent"))?;
    let new_records = document["journal"]["effect_records"]
        .as_array()
        .ok_or_else(|| failure("new effect records absent"))?;
    let by_id: BTreeMap<&str, &Value> = new_records
        .iter()
        .map(|record| {
            record["effect_id"]
                .as_str()
                .map(|id| (id, record))
                .ok_or_else(|| failure("native effect identity absent"))
        })
        .collect::<Result<_, _>>()?;
    if by_id.len() != new_records.len()
        || old_records.iter().any(|record| {
            record["effect_id"]
                .as_str()
                .and_then(|id| by_id.get(id).copied())
                != Some(record)
        })
    {
        return Err(failure("production changed immutable prior effect records"));
    }
    let old_ids: BTreeSet<&str> = prior_checkpoint["pending_outbox_intents"]
        .as_array()
        .ok_or_else(|| failure("old pending intents absent"))?
        .iter()
        .chain(
            prior_checkpoint["terminal_outbox_records"]
                .as_array()
                .ok_or_else(|| failure("old terminal intents absent"))?,
        )
        .filter_map(|item| item["intent"]["effect_id"].as_str())
        .chain(
            prior_checkpoint["outbox_effect_tombstones"]
                .as_array()
                .ok_or_else(|| failure("old effect tombstones absent"))?
                .iter()
                .filter_map(|item| item["effect_id"].as_str()),
        )
        .collect();
    let fresh: Vec<&Value> = checkpoint["pending_outbox_intents"]
        .as_array()
        .ok_or_else(|| failure("new pending intents absent"))?
        .iter()
        .filter(|item| {
            item["intent"]["effect_id"]
                .as_str()
                .is_some_and(|id| !old_ids.contains(id))
        })
        .collect();
    if new_records.len() != old_records.len() + fresh.len() {
        return Err(failure(
            "production did not pin exactly the actual new outbox intents",
        ));
    }
    for item in fresh {
        let intent = &item["intent"];
        let id = intent["effect_id"]
            .as_str()
            .ok_or_else(|| failure("new intent identity absent"))?;
        let record = by_id
            .get(id)
            .ok_or_else(|| failure("actual produced intent has no native record"))?;
        if intent["correlation_id"] != request["operation_token"]
            || record["operation_token"] != request["operation_token"]
            || record["intent_digest"]
                != hash(&json!([
                    "determa-outbox-intent-digest-1",
                    "1",
                    checkpoint["root_instance_id"],
                    intent
                ]))?
            || record["attempt_fence"] != "0"
            || record["invocation_state"] != "unclaimed"
            || record["attempt_records"] != json!([])
            || !record["outcome"].is_null()
            || !record["result_event_id"].is_null()
            || !record["admission_receipt"].is_null()
            || !record["cancellation"].is_null()
            || item["delivery_state"] != json!({"status":"not_attempted"})
        {
            return Err(failure("native produced effect pins/state mismatch"));
        }
    }
    Ok(())
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

fn apply_checkpoint(
    transaction: &Connection,
    mode: DurableStoreMode,
    replacement: &StoreRecord,
    guard: Option<&MutationGuard>,
) -> Result<(), AuthorityError> {
    let participant: bool = transaction.query_row("SELECT EXISTS(SELECT 1 FROM determa_authority_effect_journals WHERE root_instance_id=?)",[&replacement.root_instance_id],|row|row.get(0)).map_err(failure)?;
    if participant {
        return Err(failure("effect journal requires a joint native commit"));
    }
    crate::checkpoint::verify_sqlite_schema(transaction, mode).map_err(failure)?;
    let current = crate::checkpoint::load_sqlite_record(transaction, &replacement.root_instance_id)
        .map_err(failure)?;
    match guard {
        None => {
            if current.is_some() {
                return Err(failure("checkpoint_revision_conflict"));
            }
            crate::checkpoint::validate_policy_insert(mode, replacement).map_err(failure)?;
            transaction
                .execute(
                    "INSERT INTO determa_execution_checkpoints VALUES (?,?,?,?)",
                    params![
                        replacement.root_instance_id,
                        replacement.revision,
                        replacement.execution_checkpoint_digest,
                        replacement.bytes
                    ],
                )
                .map_err(failure)?;
        }
        Some(guard) => {
            let current = current.ok_or_else(|| failure("checkpoint_revision_conflict"))?;
            if current.revision != guard.expected_revision
                || current.execution_checkpoint_digest != guard.expected_checkpoint_digest
            {
                return Err(failure("checkpoint_revision_conflict"));
            }
            crate::checkpoint::validate_policy_replacement(mode, &current, replacement)
                .map_err(failure)?;
            let changed = transaction.execute(
            "UPDATE determa_execution_checkpoints SET revision=?,checkpoint_digest=?,checkpoint_bytes=? WHERE root_instance_id=? AND revision=? AND checkpoint_digest=?",
            params![replacement.revision, replacement.execution_checkpoint_digest,
                replacement.bytes, replacement.root_instance_id,
                guard.expected_revision, guard.expected_checkpoint_digest],
        ).map_err(failure)?;
            if changed != 1 {
                return Err(failure("checkpoint_revision_conflict"));
            }
        }
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod crash_tests;
fn validate_native_effect_claim_transition(
    prior: &Value,
    prior_checkpoint: &Value,
    document: &Value,
    checkpoint: &Value,
    request: &Value,
    body: &Value,
) -> Result<(), AuthorityError> {
    if checkpoint != prior_checkpoint
        || !closed(
            request,
            &[
                "operation_kind",
                "root_instance_id",
                "effect_id",
                "worker_principal",
                "scope_authority_epoch",
            ],
        )
        || request["root_instance_id"] != checkpoint["root_instance_id"]
        || request["scope_authority_epoch"] != "0"
        || !closed(body, &["kind", "body"])
        || body["kind"] != "effect_claim"
        || !closed(&body["body"], &["claim"])
    {
        return Err(failure("native effect claim transition malformed"));
    }
    let claim = &body["body"]["claim"];
    if !closed(
        claim,
        &[
            "scope_identity",
            "root_instance_id",
            "work_kind",
            "work_identity",
            "operation_token",
            "scope_authority_epoch",
            "attempt_fence",
            "worker_principal",
            "expires_at",
            "state",
        ],
    ) || claim["scope_identity"] != document["journal"]["scope_identity"]
        || claim["root_instance_id"] != request["root_instance_id"]
        || claim["work_kind"] != "effect"
        || claim["work_identity"] != request["effect_id"]
        || claim["scope_authority_epoch"] != "0"
        || claim["worker_principal"] != request["worker_principal"]
        || claim["worker_principal"].as_str().is_none_or(str::is_empty)
        || claim["state"] != "active"
    {
        return Err(failure("native effect claim identity mismatch"));
    }
    effects::canonical_native_time(&claim["expires_at"])?;
    let mut expected = prior["journal"]["effect_records"].clone();
    let record = expected
        .as_array_mut()
        .ok_or_else(|| failure("prior effects absent"))?
        .iter_mut()
        .find(|record| record["effect_id"] == request["effect_id"])
        .ok_or_else(|| failure("effect_not_outstanding"))?;
    if record["invocation_state"] != "unclaimed"
        || record["attempt_fence"] != "0"
        || !record["attempt_records"]
            .as_array()
            .is_some_and(Vec::is_empty)
        || !record["outcome"].is_null()
        || !record["cancellation"].is_null()
        || claim["operation_token"] != record["operation_token"]
        || !checkpoint["pending_outbox_intents"]
            .as_array()
            .is_some_and(|intents| {
                intents.iter().any(|intent| {
                    intent["intent"]["effect_id"] == request["effect_id"]
                        && intent["delivery_state"] == json!({"status":"not_attempted"})
                })
            })
    {
        return Err(failure("effect_not_outstanding"));
    }
    record["attempt_fence"] = json!("1");
    record["invocation_state"] = json!("leased");
    if claim["attempt_fence"] != "1" || document["journal"]["effect_records"] != expected {
        return Err(failure("native effect claim changed unrelated evidence"));
    }
    Ok(())
}

fn validate_native_effect_report_transition(
    prior: &Value,
    prior_checkpoint: &Value,
    document: &Value,
    checkpoint: &Value,
    request: &Value,
    body: &Value,
) -> Result<(), AuthorityError> {
    if checkpoint != prior_checkpoint
        || !closed(
            request,
            &[
                "operation_kind",
                "root_instance_id",
                "worker_principal",
                "report",
            ],
        )
        || request["root_instance_id"] != checkpoint["root_instance_id"]
        || request["worker_principal"]
            .as_str()
            .is_none_or(str::is_empty)
    {
        return Err(failure("native report transition malformed"));
    }
    let report = &request["report"];
    crate::format1::validate_native_effect_result_request(report).map_err(failure)?;
    let mut expected = prior["journal"]["effect_records"].clone();
    let record = expected
        .as_array_mut()
        .ok_or_else(|| failure("prior effects absent"))?
        .iter_mut()
        .find(|record| record["effect_id"] == report["effect_id"])
        .ok_or_else(|| failure("effect_not_outstanding"))?;
    let claim = effects::current_native_effect_claim(prior, record)?;
    if claim["worker_principal"] != request["worker_principal"] {
        return Err(failure("unauthorized_scope"));
    }
    effects::record_native_effect_report(record, report)?;
    let expected_body = json!({"kind":"effect_report","body":{
        "attempt_report":record["attempt_records"].as_array().unwrap().last().unwrap(),
        "outcome":record["outcome"],"result_event_id":record["result_event_id"]}});
    if document["journal"]["effect_records"] != expected || body != &expected_body {
        return Err(failure("native report changed unrelated evidence"));
    }
    Ok(())
}

fn validate_native_effect_result_admission_transition(
    prior: &Value,
    prior_checkpoint: &Value,
    document: &Value,
    checkpoint: &Value,
    request: &Value,
    body: &Value,
) -> Result<(), AuthorityError> {
    if !closed(
        request,
        &["operation_kind", "root_instance_id", "effect_id"],
    ) || request["root_instance_id"] != checkpoint["root_instance_id"]
        || !closed(body, &["kind", "body"])
        || body["kind"] != "effect_result_admission"
        || !closed(
            &body["body"],
            &[
                "checkpoint",
                "admission_result",
                "delivery",
                "definition_evidence",
                "result_response",
            ],
        )
        || body["body"]["checkpoint"] != *checkpoint
    {
        return Err(failure("native result admission shape mismatch"));
    }
    let mut expected = prior["journal"]["effect_records"].clone();
    let record = expected
        .as_array_mut()
        .ok_or_else(|| failure("prior effects absent"))?
        .iter_mut()
        .find(|record| record["effect_id"] == request["effect_id"])
        .ok_or_else(|| failure("effect_not_outstanding"))?;
    if record["invocation_state"] != "outcome_recorded"
        || record["outcome"].is_null()
        || !record["admission_receipt"].is_null()
    {
        return Err(failure("native result admission requires recorded outcome"));
    }
    let root = checkpoint["root_instance_id"]
        .as_str()
        .ok_or_else(|| failure("native root absent"))?;
    let delivery = crate::format1::effect_journal::native_result_delivery(
        record,
        root,
        &body["body"]["definition_evidence"],
    )
    .map_err(failure)?;
    if body["body"]["delivery"] != delivery {
        return Err(failure(
            "native result envelope differs from immutable pins",
        ));
    }
    validate_native_admission_checkpoint_transition(
        prior_checkpoint,
        checkpoint,
        &delivery,
        &body["body"]["admission_result"],
    )?;
    let receipt = checkpoint["operation_receipts"]
        .as_array()
        .ok_or_else(|| failure("native receipts absent"))?
        .iter()
        .find(|receipt| {
            receipt["operation_kind"] == "acceptance"
                && receipt["event_id"] == record["result_event_id"]
                && receipt["request_digest"] == delivery["envelope_digest"]
                && receipt["delivery_mode"] == "input"
        })
        .ok_or_else(|| failure("native result acceptance receipt absent"))?
        .clone();
    record["admission_receipt"] = receipt;
    record["invocation_state"] = json!("result_admitted");
    let response =
        effects::native_committed_result_response(record, &document["journal"], checkpoint);
    crate::format1::validate_native_effect_result_response(&response).map_err(failure)?;
    if body["body"]["result_response"] != response
        || document["journal"]["effect_records"] != expected
    {
        return Err(failure(
            "native result admission changed unrelated evidence",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod admission_transition_tests {
    use super::*;

    fn fixture() -> (
        Value,
        Value,
        Value,
        crate::format1::InMemoryDefinitionResolver,
    ) {
        let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(
            "conformance-suite/conformance/profiles/committed-native-effects/effect-01-result",
        );
        let bundle =
            crate::load_bundle(&std::fs::read_to_string(directory.join("machine.yaml")).unwrap())
                .unwrap();
        let mut resolver = crate::format1::InMemoryDefinitionResolver::default();
        resolver.insert(bundle.clone(), true);
        let prior = crate::checkpoint::restore(
            &std::fs::read(directory.join("pending-checkpoint.json")).unwrap(),
            &resolver,
        )
        .unwrap();
        let runtime = &prior.value()["root_record"]["aggregate_state"]["runtimes"][0];
        let envelope = json!({"event":"native_cancelled","event_id":"admission-invariant-event",
            "cause_id":"admission-invariant-event","source":{"host":true},"target":runtime["target_identity"],"payload":["map",[]]});
        let digest = hash(&json!([
            "determa-inbox-envelope-digest-1",
            "1",
            prior.root_instance_id(),
            "input",
            envelope
        ]))
        .unwrap();
        let delivery =
            json!({"delivery_mode":"input","envelope":envelope,"envelope_digest":digest});
        let candidate = crate::checkpoint::admit(
            &bundle,
            &prior,
            std::slice::from_ref(&delivery),
            Some(prior.revision()),
            Some(prior.digest()),
        )
        .unwrap();
        (prior.value().clone(), candidate, delivery, resolver)
    }
    fn reseal(checkpoint: &mut Value) {
        let aggregate = &mut checkpoint["root_record"]["aggregate_state"];
        aggregate
            .as_object_mut()
            .unwrap()
            .remove("aggregate_state_digest");
        aggregate["aggregate_state_digest"] =
            json!(hash(&json!(["determa-aggregate-state-digest-1", aggregate])).unwrap());
        checkpoint
            .as_object_mut()
            .unwrap()
            .remove("execution_checkpoint_digest");
        checkpoint["execution_checkpoint_digest"] = json!(hash(&json!([
            "determa-execution-checkpoint-digest-1",
            checkpoint
        ]))
        .unwrap());
    }

    #[test]
    fn actual_core_admission_matches_complete_field_invariant_without_reexecution() {
        let (prior, candidate, delivery, resolver) = fixture();
        crate::checkpoint::restore(&canonical(&candidate).unwrap(), &resolver).unwrap();
        validate_native_admission_checkpoint_transition(&prior, &candidate, &delivery, &candidate)
            .unwrap();
        let acceptance = candidate["operation_receipts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|receipt| {
                receipt["operation_kind"] == "acceptance"
                    && receipt["event_id"] == delivery["envelope"]["event_id"]
            })
            .unwrap();
        validate_native_admission_checkpoint_transition(
            &candidate, &candidate, &delivery, acceptance,
        )
        .unwrap();
        assert!(validate_native_admission_checkpoint_transition(
            &candidate, &candidate, &delivery, &candidate
        )
        .is_err());
    }

    #[test]
    fn matching_receipt_does_not_allow_resealed_unrelated_checkpoint_changes() {
        let (prior, candidate, delivery, resolver) = fixture();
        for mutation in [
            "runtime_counter",
            "deferred_queue",
            "outbox",
            "receipt",
            "queue_counter",
            "root",
            "extra_runtime",
        ] {
            let mut corrupt = candidate.clone();
            match mutation {
                "runtime_counter" => {
                    corrupt["root_record"]["aggregate_state"]["runtimes"][0]
                        ["next_spawn_sequence"] = json!("99")
                }
                "deferred_queue" => {
                    let mut entry = corrupt["root_record"]["aggregate_state"]["runtimes"][0]
                        ["ready_mailbox"][0]
                        .clone();
                    entry["deferral_count"] = json!("1");
                    corrupt["root_record"]["aggregate_state"]["runtimes"][0]["deferred_mailbox"]
                        .as_array_mut()
                        .unwrap()
                        .push(entry);
                }
                "outbox" => {
                    corrupt["pending_outbox_intents"][0]["intent"]["correlation_id"] =
                        json!("substituted-token")
                }
                "receipt" => {
                    corrupt["operation_receipts"][0]["creation_id"] = json!("substituted-creation")
                }
                "queue_counter" => {
                    corrupt["root_record"]["aggregate_state"]["next_queue_sequence"] = json!("99")
                }
                "root" => corrupt["root_record"]["status"] = json!("tombstone"),
                "extra_runtime" => {
                    let extra = corrupt["root_record"]["aggregate_state"]["runtimes"][0].clone();
                    corrupt["root_record"]["aggregate_state"]["runtimes"]
                        .as_array_mut()
                        .unwrap()
                        .push(extra);
                }
                _ => unreachable!(),
            }
            reseal(&mut corrupt);
            if mutation == "runtime_counter" {
                // This is still a valid portable checkpoint. Admission authority
                // must reject the unrelated change even when content restores.
                crate::checkpoint::restore(&canonical(&corrupt).unwrap(), &resolver).unwrap();
            }
            // The actual new acceptance receipt remains present, and the caller's
            // returned body echoes the corrupt checkpoint. Both are insufficient.
            assert!(
                validate_native_admission_checkpoint_transition(
                    &prior, &corrupt, &delivery, &corrupt
                )
                .is_err(),
                "{mutation}"
            );
        }
    }

    #[test]
    fn duplicate_cannot_mutate_runtime_and_extra_delivery_fields_refuse() {
        let (_, candidate, delivery, _) = fixture();
        let acceptance = candidate["operation_receipts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|receipt| {
                receipt["operation_kind"] == "acceptance"
                    && receipt["event_id"] == delivery["envelope"]["event_id"]
            })
            .unwrap();
        let mut corrupt = candidate.clone();
        corrupt["root_record"]["aggregate_state"]["runtimes"][0]["next_spawn_sequence"] =
            json!("99");
        reseal(&mut corrupt);
        assert!(validate_native_admission_checkpoint_transition(
            &candidate, &corrupt, &delivery, acceptance
        )
        .is_err());
        let mut extra = delivery.clone();
        extra["trusted_worker"] = json!(true);
        assert!(validate_native_admission_checkpoint_transition(
            &candidate, &candidate, &extra, acceptance
        )
        .is_err());
    }
}
