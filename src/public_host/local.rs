//! Explicit local SQLite scope with atomic checkpoint and first-response retention.

use super::{checked_response, error, hash, request_digest, validate_message, ClientError};
use crate::checkpoint;
use crate::format1::{Bindings, DefinitionResolver, InspectionCapabilities, TypedValue};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

const OPERATIONS: &[&str] = &[
    "capabilities",
    "create",
    "admit",
    "process",
    "read",
    "inspect",
    "receipt",
];
const TABLES: &[(&str, &str)] = &[
    ("determa_public_host_binding", "singleton INTEGER PRIMARY KEY CHECK(singleton=1), schema_version INTEGER NOT NULL CHECK(schema_version=1), scope_binding_identity TEXT NOT NULL"),
    ("determa_public_host_checkpoints", "root_instance_id TEXT PRIMARY KEY, checkpoint BLOB NOT NULL"),
    ("determa_public_host_responses", "operation_id TEXT PRIMARY KEY, request BLOB NOT NULL, request_digest TEXT NOT NULL, response BLOB NOT NULL"),
];

fn bytes(value: &Value) -> Result<Vec<u8>, ClientError> {
    serde_json_canonicalizer::to_vec(value).map_err(|e| error(e.to_string()).into())
}
fn parse(bytes: &[u8]) -> Result<Value, ClientError> {
    serde_json::from_slice(bytes).map_err(|e| error(e.to_string()).into())
}
fn refusal(code: &str) -> ClientError {
    crate::ArtifactError::new(code, code).into()
}
fn sql_tokens(sql: &str) -> Vec<String> {
    static TOKENS: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    TOKENS
        .get_or_init(|| {
            regex::Regex::new(
                r#"'(?:(?:'')|[^'])*'|"(?:(?:"")|[^"])*"|[A-Za-z_][A-Za-z0-9_]*|[0-9]+|[^\s]"#,
            )
            .unwrap()
        })
        .find_iter(sql)
        .map(|m| {
            if m.as_str().starts_with(['\'', '"']) {
                m.as_str().to_owned()
            } else {
                m.as_str().to_lowercase()
            }
        })
        .collect()
}
fn triggers() -> Vec<(String, String)> {
    let mut result = Vec::new();
    for (table, actions) in [
        (
            "determa_public_host_binding",
            &["INSERT", "UPDATE", "DELETE"][..],
        ),
        ("determa_public_host_checkpoints", &["DELETE"][..]),
        ("determa_public_host_responses", &["UPDATE", "DELETE"][..]),
    ] {
        for action in actions {
            let name = format!("{table}_forbid_{}", action.to_lowercase());
            result.push((name.clone(), format!("CREATE TRIGGER {name} BEFORE {action} ON {table} BEGIN SELECT RAISE(ABORT,'public_host_immutable'); END")));
        }
    }
    result
}

/// Transport adapters authenticate the principal before calling this host.
/// This profile advertises no authority, native effects, timer, archive or recovery provider.
pub struct SqlitePublicExecutionHost<R> {
    path: PathBuf,
    scope_alias: String,
    scope_binding_identity: String,
    authorized_principals: BTreeSet<String>,
    resolver: R,
}

impl<R: DefinitionResolver> SqlitePublicExecutionHost<R> {
    pub fn new(
        path: impl AsRef<Path>,
        scope_alias: String,
        scope_binding_identity: String,
        authorized_principals: BTreeSet<String>,
        resolver: R,
    ) -> Result<Self, ClientError> {
        if path.as_ref().as_os_str().is_empty()
            || path.as_ref() == Path::new(":memory:")
            || scope_alias.is_empty()
            || scope_binding_identity.is_empty()
            || authorized_principals.is_empty()
        {
            return Err(refusal("host_capability_mismatch"));
        }
        Ok(Self {
            path: path.as_ref().to_owned(),
            scope_alias,
            scope_binding_identity,
            authorized_principals,
            resolver,
        })
    }
    fn connect(&self) -> Result<Connection, ClientError> {
        let db = Connection::open(&self.path)?;
        db.pragma_update(None, "journal_mode", "WAL")?;
        db.pragma_update(None, "synchronous", "FULL")?;
        let mode: String = db.pragma_query_value(None, "journal_mode", |r| r.get(0))?;
        let sync: i64 = db.pragma_query_value(None, "synchronous", |r| r.get(0))?;
        if mode != "wal" || sync != 2 {
            return Err(refusal("host_capability_mismatch"));
        }
        Ok(db)
    }
    fn check_tables(db: &Connection) -> Result<(), ClientError> {
        for (name, columns) in TABLES {
            let actual: Option<String> = db
                .query_row(
                    "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
                    [name],
                    |r| r.get(0),
                )
                .optional()?;
            if actual.as_deref().map(sql_tokens)
                != Some(sql_tokens(&format!("CREATE TABLE {name} ({columns})")))
            {
                return Err(refusal("host_capability_mismatch"));
            }
        }
        Ok(())
    }
    fn check_binding(&self, db: &Connection) -> Result<(), ClientError> {
        Self::check_tables(db)?;
        let mut statement = db.prepare("SELECT name,sql FROM sqlite_master WHERE type='trigger' AND tbl_name IN ('determa_public_host_binding','determa_public_host_checkpoints','determa_public_host_responses')")?;
        let actual = statement
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
            .collect::<Result<std::collections::BTreeMap<_, _>, _>>()?;
        let expected = triggers();
        if actual.len() != expected.len()
            || expected
                .iter()
                .any(|(name, sql)| actual.get(name).map(|s| sql_tokens(s)) != Some(sql_tokens(sql)))
        {
            return Err(refusal("host_capability_mismatch"));
        }
        let mut statement = db.prepare("SELECT singleton,schema_version,scope_binding_identity FROM determa_public_host_binding")?;
        let rows = statement
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        if rows != vec![(1, 1, self.scope_binding_identity.clone())] {
            return Err(refusal("binding_unavailable"));
        }
        Ok(())
    }
    pub fn setup_schema(&self) -> Result<(), ClientError> {
        let mut db = self.connect()?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        for (name, columns) in TABLES {
            tx.execute_batch(&format!("CREATE TABLE IF NOT EXISTS {name} ({columns})"))?;
        }
        Self::check_tables(&tx)?;
        let count: i64 = tx.query_row(
            "SELECT COUNT(*) FROM determa_public_host_binding",
            [],
            |r| r.get(0),
        )?;
        if count == 0 {
            tx.execute(
                "INSERT INTO determa_public_host_binding VALUES (1,1,?)",
                [&self.scope_binding_identity],
            )?;
        }
        for (name, sql) in triggers() {
            let exists: i64 = tx.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name=?",
                [&name],
                |r| r.get(0),
            )?;
            if exists == 0 {
                tx.execute_batch(&sql)?;
            }
        }
        self.check_binding(&tx)?;
        tx.commit()?;
        Ok(())
    }
    fn response(request: &Value, result: Value, code: Option<&str>) -> Value {
        json!({"protocol":"determa.execution_host","protocol_version":1,"operation_id":request["operation_id"],
            "status":if code.is_some(){"rejected"}else{"committed"},"receipt":null,
            "value":if code.is_none(){json!({"operation":request["operation"],"result":result})}else{Value::Null},
            "error":code.map(|code|json!({"operation":request["operation"],"code":code}))})
    }
    fn capabilities(&self) -> Result<Value, ClientError> {
        let mut profile = json!({"scope_binding_identity":self.scope_binding_identity,
            "supported_operations":OPERATIONS,"supported_scope_actions":[],"supported_determa_capabilities":[],
            "supported_timer_commands":[],"extension_reports":[],"authority_profile":null,
            "guarantees":{"inspection_structural":true,"inspection_semantic":false,"retained_history":true,
                "saved_response_replay":true,"deterministic_reexecution":false}});
        profile["profile_digest"] = json!(hash(&json!([
            "determa-public-host-profile-1",
            "1",
            self.scope_binding_identity,
            profile
        ]))?);
        Ok(profile)
    }
    pub fn handle(&self, request: &Value, principal: &str) -> Result<Value, ClientError> {
        validate_message(request, false)?;
        if !self.authorized_principals.contains(principal) {
            return Ok(Self::response(
                request,
                Value::Null,
                Some("unauthorized_scope"),
            ));
        }
        let operation = request["operation"].as_str().unwrap();
        let binding = &request["scope_binding_identity"];
        if operation == "capabilities" && binding.is_null() {
            if request["arguments"]["scope_alias"] != self.scope_alias {
                return Ok(Self::response(
                    request,
                    Value::Null,
                    Some("unauthorized_scope"),
                ));
            }
        } else if binding != &self.scope_binding_identity {
            return Ok(Self::response(
                request,
                Value::Null,
                Some("binding_unavailable"),
            ));
        }
        if !OPERATIONS.contains(&operation) {
            return Ok(Self::response(
                request,
                Value::Null,
                Some("host_capability_mismatch"),
            ));
        }
        let target = &request["target"];
        let applicable = match operation {
            "capabilities" => target.as_object().unwrap().values().all(Value::is_null),
            "receipt" => target["runtime_id"].is_null() && target["runtime_incarnation"].is_null(),
            "create" | "admit" | "read" => {
                !target["root_instance_id"].is_null()
                    && target["runtime_id"].is_null()
                    && target["runtime_incarnation"].is_null()
            }
            _ => target.as_object().unwrap().values().all(|v| !v.is_null()),
        };
        if !applicable
            || (["capabilities", "receipt", "create"].contains(&operation)
                && !request["precondition"].is_null())
        {
            return Ok(Self::response(
                request,
                Value::Null,
                Some("invalid_host_request"),
            ));
        }
        match self.transact(request) {
            Err(ClientError::Protocol(failure)) => {
                let response = Self::response(request, Value::Null, Some(&failure.code));
                validate_message(&response, true)?;
                Ok(response)
            }
            other => other,
        }
    }
    fn transact(&self, request: &Value) -> Result<Value, ClientError> {
        let operation = request["operation"].as_str().unwrap();
        let mutation = ["create", "admit", "process"].contains(&operation);
        let digest = request_digest(request)?;
        let request_bytes = bytes(request)?;
        let mut db = self.connect()?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        self.check_binding(&tx)?;
        if mutation {
            let saved: Option<(Vec<u8>,String,Vec<u8>)> = tx.query_row("SELECT request,request_digest,response FROM determa_public_host_responses WHERE operation_id=?", [request["operation_id"].as_str().unwrap()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
            if let Some((prior, prior_digest, response)) = saved {
                if prior != request_bytes || prior_digest != digest {
                    return Err(refusal("operation_id_conflict"));
                }
                let response = parse(&response)?;
                checked_response(request, &response)?;
                return Ok(response);
            }
        }
        let (result, checkpoint, changed) = self.execute(&tx, request)?;
        let mut response = Self::response(request, result, None);
        if mutation && changed {
            response["receipt"] = json!({"scope_binding_identity":self.scope_binding_identity,"operation_id":request["operation_id"],
                "request_digest":digest,"receipt_kind":"committed","acceptance_receipt":null,
                "evidence_digest":hash(&json!(["determa-public-host-evidence-1","1",response["value"]]))?});
        }
        checked_response(request, &response)?;
        if mutation {
            let checkpoint = checkpoint.ok_or_else(|| error("missing mutation checkpoint"))?;
            if changed {
                tx.execute("INSERT INTO determa_public_host_checkpoints VALUES (?,?) ON CONFLICT(root_instance_id) DO UPDATE SET checkpoint=excluded.checkpoint",params![checkpoint["root_instance_id"].as_str().unwrap(),bytes(&checkpoint)?])?;
            }
            tx.execute(
                "INSERT INTO determa_public_host_responses VALUES (?,?,?,?)",
                params![
                    request["operation_id"].as_str().unwrap(),
                    request_bytes,
                    digest,
                    bytes(&response)?
                ],
            )?;
        }
        tx.commit()?;
        Ok(response)
    }
    fn guard(checkpoint: &Value, precondition: &Value) -> Result<(), ClientError> {
        if !precondition.is_null()
            && (checkpoint["revision"] != precondition["revision"]
                || checkpoint["execution_checkpoint_digest"] != precondition["checkpoint_digest"])
        {
            return Err(refusal("checkpoint_conflict"));
        }
        Ok(())
    }
    fn execute(
        &self,
        db: &Connection,
        request: &Value,
    ) -> Result<(Value, Option<Value>, bool), ClientError> {
        let operation = request["operation"].as_str().unwrap();
        let args = &request["arguments"];
        let target = &request["target"];
        if operation == "capabilities" {
            return Ok((self.capabilities()?, None, false));
        }
        if operation == "receipt" {
            let saved: Option<(String,Vec<u8>,Vec<u8>)> = db.query_row("SELECT request_digest,response,request FROM determa_public_host_responses WHERE operation_id=?",[args["queried_operation_id"].as_str().unwrap()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
            let response = if let Some((digest, response, original)) = saved {
                if digest != args["request_digest"] {
                    return Err(refusal("operation_id_conflict"));
                }
                if !target["root_instance_id"].is_null()
                    && parse(&original)?["target"]["root_instance_id"] != target["root_instance_id"]
                {
                    return Err(refusal("invalid_host_request"));
                }
                parse(&response)?
            } else {
                Value::Null
            };
            return Ok((
                json!({"retention":if response.is_null(){"unknown"}else{"retained"},"saved_response":response}),
                None,
                false,
            ));
        }
        let root = target["root_instance_id"].as_str().unwrap();
        let stored: Option<Vec<u8>> = db
            .query_row(
                "SELECT checkpoint FROM determa_public_host_checkpoints WHERE root_instance_id=?",
                [root],
                |r| r.get(0),
            )
            .optional()?;
        if operation == "read" {
            let checkpoint = stored
                .map(|v| checkpoint::restore(&v, &self.resolver).map(|c| c.value().clone()))
                .transpose()?;
            if let Some(c) = &checkpoint {
                Self::guard(c, &request["precondition"])?;
            }
            return Ok((
                json!({"observed_checkpoint_digest":checkpoint.as_ref().map(|c|&c["execution_checkpoint_digest"]),"checkpoint":checkpoint}),
                None,
                false,
            ));
        }
        if operation == "create" {
            if args["root_instance_id"] != root {
                return Err(refusal("invalid_host_request"));
            }
            if let Some(stored) = stored {
                let mut statement =
                    db.prepare("SELECT request,response FROM determa_public_host_responses")?;
                let rows = statement.query_map([], |r| {
                    Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?))
                })?;
                for row in rows {
                    let (prior, response) = row?;
                    let prior = parse(&prior)?;
                    if prior["operation"] == "create" && prior["target"]["root_instance_id"] == root
                    {
                        if prior["arguments"] != *args {
                            return Err(refusal("creation_id_conflict"));
                        }
                        return Ok((
                            parse(&response)?["value"]["result"].clone(),
                            Some(parse(&stored)?),
                            true,
                        ));
                    }
                }
                return Err(refusal("replay_evidence_expired"));
            }
            let resolved = self
                .resolver
                .resolve_definition(args["validated_bundle_fingerprint"].as_str().unwrap())
                .filter(|r| r.trusted)
                .ok_or_else(|| refusal("missing_required_artifact"))?;
            let bundle = resolved.bundle;
            let machine = args["machine_id"].as_str().unwrap();
            if bundle.fingerprint != args["validated_bundle_fingerprint"]
                || bundle.namespace != args["namespace"]
                || bundle
                    .machines
                    .get(machine)
                    .map(|m| m.version.to_string())
                    .as_deref()
                    != args["machine_version"].as_str()
            {
                return Err(refusal("invalid_host_request"));
            }
            let typed: TypedValue = serde_json::from_value(args["bindings"].clone())
                .map_err(|e| error(e.to_string()))?;
            let crate::value::Value::Map(mut bindings) =
                typed.to_value(None).map_err(|e| error(e.to_string()))?
            else {
                return Err(refusal("invalid_host_request"));
            };
            let mut decoded = Bindings::default();
            for (name, destination) in [
                ("input", &mut decoded.input),
                ("external", &mut decoded.external),
            ] {
                if let Some(value) = bindings.remove(name) {
                    let crate::value::Value::Map(value) = value else {
                        return Err(refusal("invalid_host_request"));
                    };
                    *destination = value;
                }
            }
            if !bindings.is_empty() {
                return Err(refusal("invalid_host_request"));
            }
            let (checkpoint, result) = checkpoint::create_with_response(
                &bundle,
                machine,
                root,
                args["creation_id"].as_str().unwrap(),
                &decoded,
                None,
                json!({"mode":"permanent","permanent_replay_eligible":true,"pruned_through_receipt_sequence":null,"policy_identifier":null}),
            )?;
            return Ok((result, Some(checkpoint.value().clone()), true));
        }
        let stored = stored.ok_or_else(|| refusal("invalid_instance_target"))?;
        let checkpoint = checkpoint::restore(&stored, &self.resolver)?;
        let document = checkpoint.value();
        let aggregate = &document["root_record"]["aggregate_state"];
        if aggregate.is_null() {
            return Err(refusal("terminal_root"));
        }
        if operation == "inspect" {
            Self::guard(document, &request["precondition"])?;
            let candidate = &args["candidate"];
            if target["runtime_id"] != candidate["runtime_id"]
                || target["runtime_incarnation"] != candidate["runtime_incarnation"]
            {
                return Err(refusal("invalid_host_request"));
            }
            let native = crate::restore_aggregate(&bytes(aggregate)?, &self.resolver)?;
            let outcome = crate::inspect_candidate(
                &native,
                candidate,
                &self.resolver,
                InspectionCapabilities {
                    safe_semantic_cel: false,
                },
            )?;
            if let Some(code) = outcome["code"].as_str() {
                return Err(refusal(code));
            }
            return Ok((
                json!({"outcome":outcome,"observed_aggregate_state_digest":aggregate["aggregate_state_digest"]}),
                None,
                false,
            ));
        }
        let precondition = &request["precondition"];
        if precondition.is_null() {
            return Err(refusal("invalid_host_request"));
        }
        let resolved = self
            .resolver
            .resolve_definition(aggregate["validated_bundle_fingerprint"].as_str().unwrap())
            .filter(|r| r.trusted)
            .ok_or_else(|| refusal("missing_required_artifact"))?;
        let revision = precondition["revision"].as_str();
        let digest = precondition["checkpoint_digest"].as_str();
        if operation == "admit" {
            let deliveries = args["ordered_deliveries"].as_array().unwrap();
            for delivery in deliveries {
                let destination = delivery["envelope"]["target"]
                    .as_object()
                    .unwrap()
                    .values()
                    .next()
                    .unwrap();
                if destination["root_instance_id"] != root {
                    return Err(refusal("invalid_host_request"));
                }
            }
            let updated =
                checkpoint::admit(&resolved.bundle, &checkpoint, deliveries, revision, digest)?;
            let mut receipts = Vec::new();
            for delivery in deliveries {
                receipts.push(
                    updated["operation_receipts"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|r| {
                            r["operation_kind"] == "acceptance"
                                && r["event_id"] == delivery["envelope"]["event_id"]
                        })
                        .ok_or_else(|| error("missing acceptance receipt"))?
                        .clone(),
                );
            }
            let status = updated["root_record"]["aggregate_state"]["runtimes"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["runtime_id"] == aggregate["root_runtime_id"])
                .unwrap()["status"]
                .clone();
            return Ok((
                json!({"checkpoint":updated,"acceptance_receipts":receipts,"status":status,"accepted":deliveries.iter().map(|d|d["envelope"].clone()).collect::<Vec<_>>()}),
                Some(updated),
                true,
            ));
        }
        let runtime = aggregate["runtimes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["runtime_id"] == target["runtime_id"])
            .ok_or_else(|| refusal("invalid_instance_target"))?;
        if runtime["identity_origin"] != target["runtime_incarnation"] {
            return Err(refusal("invalid_instance_target"));
        }
        Self::guard(document, precondition)?;
        let head = runtime["ready_mailbox"].as_array().unwrap().first();
        if let Some(head) = head {
            let processing = checkpoint::ProcessingRequest {
                target_runtime_id: target["runtime_id"].as_str().unwrap().into(),
                event_id: head["envelope"]["event_id"].as_str().unwrap().into(),
                envelope_digest: head["envelope_digest"].as_str().unwrap().into(),
                acceptance_sequence: head["acceptance_sequence"].as_str().unwrap().into(),
                queue_sequence: head["queue_sequence"].as_str().unwrap().into(),
                processing_mode: "foreground".into(),
            };
            let (updated, core) = checkpoint::checkpoint_step_v1_with_core(
                &resolved.bundle,
                &checkpoint,
                &processing,
                revision,
                digest,
            )?;
            let core = core.ok_or_else(|| error("missing foreground core result"))?;
            let receipt = updated["operation_receipts"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| {
                    r["operation_kind"] == "event_terminal" && r["event_id"] == processing.event_id
                });
            return Ok((
                json!({"checkpoint":updated,"core_result":core,"terminal_receipt":receipt}),
                Some(updated),
                true,
            ));
        }
        let core = json!({"core_step_result_format":"determa.core_step_result","core_step_result_schema_version":1,
            "status":runtime["status"],"disposition":"not_runnable","state":aggregate,"emissions":[],"lifecycle_dispositions":[],"fault":null,"rejection":null});
        Ok((
            json!({"checkpoint":document,"core_result":core,"terminal_receipt":null}),
            Some(document.clone()),
            false,
        ))
    }
}
