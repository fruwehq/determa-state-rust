use super::super::store::{
    parse_durable_store_configuration, validate_policy_insert, validate_policy_replacement,
    AdapterError, AdapterErrorCode, DurableStoreMode, ExecutionStore, ExecutionStoreCapability,
    ExecutionStoreFactory, HealthStatus, StoreError, StoreRecord, StoreWriteResult,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde_json::{json, Map, Value};
use std::any::Any;
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::{Arc, Mutex};

pub struct SqliteExecutionStore {
    connection: Mutex<Connection>,
    mode: DurableStoreMode,
}

impl SqliteExecutionStore {
    pub fn open(path: impl AsRef<Path>, mode: DurableStoreMode) -> Result<Self, StoreError> {
        if !path.as_ref().is_absolute() {
            return Err(StoreError::new("SQLite path must be absolute"));
        }
        let connection = Connection::open(path).map_err(sql_error)?;
        connection
            .execute_batch(
                "
                PRAGMA foreign_keys = ON;
                PRAGMA journal_mode = WAL;
                PRAGMA synchronous = FULL;
                PRAGMA busy_timeout = 5000;
                ",
            )
            .map_err(sql_error)?;
        Ok(Self {
            connection: Mutex::new(connection),
            mode,
        })
    }

    pub fn mode(&self) -> DurableStoreMode {
        self.mode
    }

    fn connection(&self) -> Result<std::sync::MutexGuard<'_, Connection>, StoreError> {
        self.connection
            .lock()
            .map_err(|_| StoreError::new("SQLite connection lock is poisoned"))
    }

    pub(crate) fn with_immediate_transaction<T>(
        &self,
        operation: impl FnOnce(&rusqlite::Transaction<'_>) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_error)?;
        let result = operation(&transaction)?;
        transaction.commit().map_err(sql_error)?;
        Ok(result)
    }

    pub(crate) fn with_controlled_transaction<T>(
        &self,
        operation: impl FnOnce(&rusqlite::Transaction<'_>) -> Result<(T, bool), StoreError>,
    ) -> Result<T, StoreError> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_error)?;
        let (result, commit) = operation(&transaction)?;
        if commit {
            transaction.commit().map_err(sql_error)?;
        } else {
            transaction.rollback().map_err(sql_error)?;
        }
        Ok(result)
    }

    pub fn import_durable_host_snapshot(&self, value: &Value) -> Result<(), StoreError> {
        let checkpoint = value
            .get("checkpoint")
            .ok_or_else(|| StoreError::new("durable host snapshot checkpoint is absent"))?;
        let root_instance_id = checkpoint["root_instance_id"]
            .as_str()
            .ok_or_else(|| StoreError::new("snapshot checkpoint root is absent"))?;
        let record = StoreRecord {
            root_instance_id: root_instance_id.to_string(),
            revision: checkpoint["revision"]
                .as_str()
                .ok_or_else(|| StoreError::new("snapshot checkpoint revision is absent"))?
                .to_string(),
            execution_checkpoint_digest: checkpoint["execution_checkpoint_digest"]
                .as_str()
                .ok_or_else(|| StoreError::new("snapshot checkpoint digest is absent"))?
                .to_string(),
            bytes: serde_json_canonicalizer::to_vec(checkpoint)
                .map_err(|error| StoreError::new(error.to_string()))?,
        };
        validate_policy_insert(self.mode, &record)?;
        self.with_immediate_transaction(|transaction| {
            if load_record(transaction, root_instance_id)?.is_some() {
                return Err(StoreError::new("durable host snapshot root already exists"));
            }
            transaction
                .execute(
                    "INSERT INTO determa_execution_checkpoints
                     (root_instance_id, revision, checkpoint_digest, checkpoint_bytes)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![
                        record.root_instance_id,
                        record.revision,
                        record.execution_checkpoint_digest,
                        record.bytes
                    ],
                )
                .map_err(sql_error)?;
            for inbox in value["inbox"]
                .as_array()
                .ok_or_else(|| StoreError::new("snapshot inbox is not an array"))?
            {
                transaction
                    .execute(
                        "INSERT INTO determa_durable_inbox
                         (root_instance_id, event_id, request_digest, disposition)
                         VALUES (?1, ?2, ?3, ?4)",
                        params![
                            root_instance_id,
                            inbox["event_id"].as_str(),
                            inbox["request_digest"].as_str(),
                            inbox["disposition"].as_str()
                        ],
                    )
                    .map_err(sql_error)?;
            }
            for (key, application_value) in value["application_rows"]
                .as_object()
                .ok_or_else(|| StoreError::new("snapshot application rows are not an object"))?
            {
                transaction
                    .execute(
                        "INSERT INTO determa_durable_application_rows
                         (root_instance_id, row_key, row_value) VALUES (?1, ?2, ?3)",
                        params![root_instance_id, key, canonical_json(application_value)?],
                    )
                    .map_err(sql_error)?;
            }
            if !value["quarantine"].is_null() {
                transaction
                    .execute(
                        "INSERT INTO determa_durable_quarantine
                         (root_instance_id, event_id, reason_code, released)
                         VALUES (?1, ?2, ?3, ?4)",
                        params![
                            root_instance_id,
                            value["quarantine"]["event_id"].as_str(),
                            value["quarantine"]["reason_code"].as_str(),
                            value["quarantine"]["released"].as_bool()
                        ],
                    )
                    .map_err(sql_error)?;
            }
            Ok(())
        })
    }

    pub fn export_durable_host_snapshot(
        &self,
        root_instance_id: &str,
    ) -> Result<Value, StoreError> {
        let connection = self.connection()?;
        durable_snapshot(&connection, root_instance_id)
    }
}

impl ExecutionStore for SqliteExecutionStore {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn capabilities(&self) -> BTreeSet<ExecutionStoreCapability> {
        let mut capabilities = BTreeSet::from([
            ExecutionStoreCapability::DurableSingleWriter,
            ExecutionStoreCapability::RootIdentityRetention,
            ExecutionStoreCapability::SharedApplicationTransaction,
        ]);
        self.mode.add_capabilities(&mut capabilities);
        capabilities
    }

    fn initialize_schema(&self) -> Result<(), StoreError> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_error)?;
        transaction
            .execute_batch(
                "
                CREATE TABLE IF NOT EXISTS determa_execution_store_metadata (
                    singleton INTEGER NOT NULL DEFAULT 1,
                    schema_version INTEGER NOT NULL,
                    receipt_retention TEXT NOT NULL,
                    outbox_retention TEXT NOT NULL,
                    CONSTRAINT determa_execution_store_metadata_primary_key
                        PRIMARY KEY (singleton),
                    CONSTRAINT determa_execution_store_metadata_singleton_check
                        CHECK (singleton = 1),
                    CONSTRAINT determa_execution_store_metadata_version_check
                        CHECK (schema_version = 2),
                    CONSTRAINT determa_execution_store_metadata_receipt_check
                        CHECK (receipt_retention IN ('bounded', 'permanent')),
                    CONSTRAINT determa_execution_store_metadata_outbox_check
                        CHECK (outbox_retention IN ('bounded', 'strict', 'compact'))
                );
                CREATE TABLE IF NOT EXISTS determa_execution_checkpoints (
                    root_instance_id TEXT NOT NULL,
                    revision TEXT NOT NULL,
                    checkpoint_digest TEXT NOT NULL,
                    checkpoint_bytes BLOB NOT NULL,
                    CONSTRAINT determa_execution_checkpoints_primary_key
                        PRIMARY KEY (root_instance_id),
                    CONSTRAINT determa_execution_checkpoints_root_check
                        CHECK (root_instance_id <> ''),
                    CONSTRAINT determa_execution_checkpoints_revision_check
                        CHECK (
                            revision = '0'
                            OR (
                                revision GLOB '[1-9]*'
                                AND revision NOT GLOB '*[^0-9]*'
                            )
                        ),
                    CONSTRAINT determa_execution_checkpoints_digest_check
                        CHECK (
                            length(checkpoint_digest) = 71
                            AND substr(checkpoint_digest, 1, 7) = 'sha256:'
                            AND substr(checkpoint_digest, 8) NOT GLOB '*[^0-9a-f]*'
                        ),
                    CONSTRAINT determa_execution_checkpoints_bytes_check
                        CHECK (length(checkpoint_bytes) > 0)
                );
                CREATE TRIGGER IF NOT EXISTS determa_execution_checkpoints_no_delete
                BEFORE DELETE ON determa_execution_checkpoints
                BEGIN
                    SELECT RAISE(ABORT, 'physical checkpoint deletion is unsupported');
                END;
                CREATE TABLE IF NOT EXISTS determa_durable_inbox (
                    root_instance_id TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    disposition TEXT NOT NULL,
                    PRIMARY KEY (root_instance_id, event_id),
                    CHECK (disposition IN ('committed', 'quarantined'))
                );
                CREATE TABLE IF NOT EXISTS determa_durable_application_rows (
                    root_instance_id TEXT NOT NULL,
                    row_key TEXT NOT NULL,
                    row_value TEXT NOT NULL,
                    PRIMARY KEY (root_instance_id, row_key)
                );
                CREATE TABLE IF NOT EXISTS determa_durable_quarantine (
                    root_instance_id TEXT NOT NULL PRIMARY KEY,
                    event_id TEXT NOT NULL,
                    reason_code TEXT NOT NULL,
                    released INTEGER NOT NULL CHECK (released IN (0, 1))
                );
                ",
            )
            .map_err(sql_error)?;
        transaction
            .execute(
                "
                INSERT OR IGNORE INTO determa_execution_store_metadata
                    (singleton, schema_version, receipt_retention, outbox_retention)
                VALUES (1, 2, ?1, ?2)
                ",
                params![
                    self.mode.receipt_retention.as_str(),
                    self.mode.outbox_retention.as_str()
                ],
            )
            .map_err(sql_error)?;
        verify_schema_contract(&transaction, self.mode)?;
        transaction.commit().map_err(sql_error)
    }

    fn health(&self) -> Result<HealthStatus, StoreError> {
        let connection = self.connection()?;
        verify_schema_contract(&connection, self.mode)?;
        Ok(HealthStatus::healthy(
            "SQLite checkpoint schema, retention mode, and synchronization profile are available",
        ))
    }

    fn load(&self, root_instance_id: &str) -> Result<Option<StoreRecord>, StoreError> {
        self.connection()?
            .query_row(
                "
                SELECT revision, checkpoint_digest, checkpoint_bytes
                FROM determa_execution_checkpoints
                WHERE root_instance_id = ?1
                ",
                [root_instance_id],
                |row| {
                    Ok(StoreRecord {
                        root_instance_id: root_instance_id.to_string(),
                        revision: row.get(0)?,
                        execution_checkpoint_digest: row.get(1)?,
                        bytes: row.get(2)?,
                    })
                },
            )
            .optional()
            .map_err(sql_error)
    }

    fn insert_if_absent(&self, record: StoreRecord) -> Result<StoreWriteResult, StoreError> {
        validate_policy_insert(self.mode, &record)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_error)?;
        let changed = transaction
            .execute(
                "
                INSERT OR IGNORE INTO determa_execution_checkpoints
                    (root_instance_id, revision, checkpoint_digest, checkpoint_bytes)
                VALUES (?1, ?2, ?3, ?4)
                ",
                params![
                    record.root_instance_id,
                    record.revision,
                    record.execution_checkpoint_digest,
                    record.bytes
                ],
            )
            .map_err(sql_error)?;
        if changed == 1 {
            transaction.commit().map_err(sql_error)?;
            return Ok(StoreWriteResult::Committed);
        }
        let current = transaction
            .query_row(
                "
                SELECT revision, checkpoint_digest, checkpoint_bytes
                FROM determa_execution_checkpoints
                WHERE root_instance_id = ?1
                ",
                [&record.root_instance_id],
                |row| {
                    Ok(StoreRecord {
                        root_instance_id: record.root_instance_id.clone(),
                        revision: row.get(0)?,
                        execution_checkpoint_digest: row.get(1)?,
                        bytes: row.get(2)?,
                    })
                },
            )
            .optional()
            .map_err(sql_error)?;
        transaction.commit().map_err(sql_error)?;
        Ok(StoreWriteResult::Conflict(current))
    }

    fn compare_and_swap(
        &self,
        root_instance_id: &str,
        expected_revision: &str,
        expected_checkpoint_digest: &str,
        replacement: StoreRecord,
    ) -> Result<StoreWriteResult, StoreError> {
        if replacement.root_instance_id != root_instance_id {
            return Err(StoreError::new("replacement belongs to another root"));
        }
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_error)?;
        let current = load_record(&transaction, root_instance_id)?;
        let Some(current) = current else {
            transaction.commit().map_err(sql_error)?;
            return Ok(StoreWriteResult::Conflict(None));
        };
        if current.revision != expected_revision
            || current.execution_checkpoint_digest != expected_checkpoint_digest
        {
            transaction.commit().map_err(sql_error)?;
            return Ok(StoreWriteResult::Conflict(Some(current)));
        }
        validate_policy_replacement(self.mode, &current, &replacement)?;
        let changed = transaction
            .execute(
                "
                UPDATE determa_execution_checkpoints
                SET revision = ?1, checkpoint_digest = ?2, checkpoint_bytes = ?3
                WHERE root_instance_id = ?4
                  AND revision = ?5
                  AND checkpoint_digest = ?6
                ",
                params![
                    replacement.revision,
                    replacement.execution_checkpoint_digest,
                    replacement.bytes,
                    root_instance_id,
                    expected_revision,
                    expected_checkpoint_digest
                ],
            )
            .map_err(sql_error)?;
        if changed == 1 {
            transaction.commit().map_err(sql_error)?;
            return Ok(StoreWriteResult::Committed);
        }
        let current = load_record(&transaction, root_instance_id)?;
        transaction.commit().map_err(sql_error)?;
        Ok(StoreWriteResult::Conflict(current))
    }
}

pub struct SqliteExecutionStoreFactory;

impl ExecutionStoreFactory for SqliteExecutionStoreFactory {
    fn create(&self, configuration: &str) -> Result<Arc<dyn ExecutionStore>, AdapterError> {
        let (location, mode) = parse_durable_store_configuration(configuration)?;
        let path = location.strip_prefix("sqlite:").ok_or_else(|| {
            AdapterError::new(
                AdapterErrorCode::InvalidAdapterConfiguration,
                "SQLite configuration must use the sqlite scheme",
            )
        })?;
        if path.is_empty() || path == ":memory:" || !Path::new(path).is_absolute() {
            return Err(AdapterError::new(
                AdapterErrorCode::InvalidAdapterConfiguration,
                "durable SQLite configuration must name an absolute on-disk path",
            ));
        }
        SqliteExecutionStore::open(path, mode)
            .map(|store| Arc::new(store) as Arc<dyn ExecutionStore>)
            .map_err(|error| {
                AdapterError::new(
                    AdapterErrorCode::InvalidAdapterConfiguration,
                    error.to_string(),
                )
            })
    }
}

pub(crate) fn load_record(
    connection: &Connection,
    root_instance_id: &str,
) -> Result<Option<StoreRecord>, StoreError> {
    connection
        .query_row(
            "
            SELECT revision, checkpoint_digest, checkpoint_bytes
            FROM determa_execution_checkpoints
            WHERE root_instance_id = ?1
            ",
            [root_instance_id],
            |row| {
                Ok(StoreRecord {
                    root_instance_id: root_instance_id.to_string(),
                    revision: row.get(0)?,
                    execution_checkpoint_digest: row.get(1)?,
                    bytes: row.get(2)?,
                })
            },
        )
        .optional()
        .map_err(sql_error)
}

fn canonical_json(value: &Value) -> Result<String, StoreError> {
    let bytes = serde_json_canonicalizer::to_vec(value)
        .map_err(|error| StoreError::new(error.to_string()))?;
    String::from_utf8(bytes).map_err(|error| StoreError::new(error.to_string()))
}

fn durable_snapshot(connection: &Connection, root_instance_id: &str) -> Result<Value, StoreError> {
    let checkpoint = load_record(connection, root_instance_id)?
        .ok_or_else(|| StoreError::new("durable host checkpoint is absent"))?;
    let checkpoint: Value = serde_json::from_slice(&checkpoint.bytes)
        .map_err(|error| StoreError::new(error.to_string()))?;
    let mut inbox_statement = connection
        .prepare(
            "SELECT event_id, request_digest, disposition
             FROM determa_durable_inbox
             WHERE root_instance_id = ?1
             ORDER BY rowid",
        )
        .map_err(sql_error)?;
    let inbox = inbox_statement
        .query_map([root_instance_id], |row| {
            Ok(json!({
                "event_id": row.get::<_, String>(0)?,
                "request_digest": row.get::<_, String>(1)?,
                "disposition": row.get::<_, String>(2)?,
            }))
        })
        .map_err(sql_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sql_error)?;
    let mut rows_statement = connection
        .prepare(
            "SELECT row_key, row_value
             FROM determa_durable_application_rows
             WHERE root_instance_id = ?1
             ORDER BY row_key",
        )
        .map_err(sql_error)?;
    let rows = rows_statement
        .query_map([root_instance_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(sql_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sql_error)?;
    let mut application_rows = Map::new();
    for (key, value) in rows {
        application_rows.insert(
            key,
            serde_json::from_str(&value).map_err(|error| StoreError::new(error.to_string()))?,
        );
    }
    let quarantine = connection
        .query_row(
            "SELECT event_id, reason_code, released
             FROM determa_durable_quarantine
             WHERE root_instance_id = ?1",
            [root_instance_id],
            |row| {
                Ok(json!({
                    "event_id": row.get::<_, String>(0)?,
                    "reason_code": row.get::<_, String>(1)?,
                    "released": row.get::<_, bool>(2)?,
                }))
            },
        )
        .optional()
        .map_err(sql_error)?
        .unwrap_or(Value::Null);
    Ok(json!({
        "durable_host_store_format": "determa.durable_host.store",
        "durable_host_store_schema_version": 2,
        "checkpoint": checkpoint,
        "inbox": inbox,
        "application_rows": application_rows,
        "quarantine": quarantine,
    }))
}

fn verify_schema_contract(
    connection: &Connection,
    mode: DurableStoreMode,
) -> Result<(), StoreError> {
    let metadata = connection
        .query_row(
            "
            SELECT schema_version, receipt_retention, outbox_retention
            FROM determa_execution_store_metadata
            WHERE singleton = 1
            ",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .map_err(sql_error)?;
    if metadata
        != (
            2,
            mode.receipt_retention.as_str().to_string(),
            mode.outbox_retention.as_str().to_string(),
        )
    {
        return Err(StoreError::new(
            "SQLite store schema retention mode differs from configured mode",
        ));
    }
    if table_columns(connection, "determa_execution_store_metadata")?
        != [
            "0:singleton:INTEGER:1:1:1",
            "1:schema_version:INTEGER:1::0",
            "2:receipt_retention:TEXT:1::0",
            "3:outbox_retention:TEXT:1::0",
        ]
        || table_columns(connection, "determa_execution_checkpoints")?
            != [
                "0:root_instance_id:TEXT:1::1",
                "1:revision:TEXT:1::0",
                "2:checkpoint_digest:TEXT:1::0",
                "3:checkpoint_bytes:BLOB:1::0",
            ]
    {
        return Err(StoreError::new(
            "SQLite execution-store columns do not match schema version 2",
        ));
    }
    let metadata_schema = schema_sql(connection, "table", "determa_execution_store_metadata")?;
    let checkpoint_schema = schema_sql(connection, "table", "determa_execution_checkpoints")?;
    let trigger_schema = schema_sql(
        connection,
        "trigger",
        "determa_execution_checkpoints_no_delete",
    )?;
    if metadata_schema
        != normalize_sql(
            "
            CREATE TABLE determa_execution_store_metadata (
                singleton INTEGER NOT NULL DEFAULT 1,
                schema_version INTEGER NOT NULL,
                receipt_retention TEXT NOT NULL,
                outbox_retention TEXT NOT NULL,
                CONSTRAINT determa_execution_store_metadata_primary_key
                    PRIMARY KEY (singleton),
                CONSTRAINT determa_execution_store_metadata_singleton_check
                    CHECK (singleton = 1),
                CONSTRAINT determa_execution_store_metadata_version_check
                    CHECK (schema_version = 2),
                CONSTRAINT determa_execution_store_metadata_receipt_check
                    CHECK (receipt_retention IN ('bounded', 'permanent')),
                CONSTRAINT determa_execution_store_metadata_outbox_check
                    CHECK (outbox_retention IN ('bounded', 'strict', 'compact'))
            )
            ",
        )
        || checkpoint_schema
            != normalize_sql(
                "
                CREATE TABLE determa_execution_checkpoints (
                    root_instance_id TEXT NOT NULL,
                    revision TEXT NOT NULL,
                    checkpoint_digest TEXT NOT NULL,
                    checkpoint_bytes BLOB NOT NULL,
                    CONSTRAINT determa_execution_checkpoints_primary_key
                        PRIMARY KEY (root_instance_id),
                    CONSTRAINT determa_execution_checkpoints_root_check
                        CHECK (root_instance_id <> ''),
                    CONSTRAINT determa_execution_checkpoints_revision_check
                        CHECK (
                            revision = '0'
                            OR (
                                revision GLOB '[1-9]*'
                                AND revision NOT GLOB '*[^0-9]*'
                            )
                        ),
                    CONSTRAINT determa_execution_checkpoints_digest_check
                        CHECK (
                            length(checkpoint_digest) = 71
                            AND substr(checkpoint_digest, 1, 7) = 'sha256:'
                            AND substr(checkpoint_digest, 8) NOT GLOB '*[^0-9a-f]*'
                        ),
                    CONSTRAINT determa_execution_checkpoints_bytes_check
                        CHECK (length(checkpoint_bytes) > 0)
                )
                ",
            )
        || trigger_schema
            != normalize_sql(
                "
                CREATE TRIGGER determa_execution_checkpoints_no_delete
                BEFORE DELETE ON determa_execution_checkpoints
                BEGIN
                    SELECT RAISE(ABORT, 'physical checkpoint deletion is unsupported');
                END
                ",
            )
    {
        return Err(StoreError::new(
            "SQLite execution-store constraints or deletion guard do not match schema version 2",
        ));
    }
    let journal_mode: String = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .map_err(sql_error)?;
    let synchronous: i64 = connection
        .query_row("PRAGMA synchronous", [], |row| row.get(0))
        .map_err(sql_error)?;
    let foreign_keys: i64 = connection
        .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
        .map_err(sql_error)?;
    let busy_timeout: i64 = connection
        .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
        .map_err(sql_error)?;
    if !journal_mode.eq_ignore_ascii_case("wal")
        || synchronous != 2
        || foreign_keys != 1
        || busy_timeout < 5_000
    {
        return Err(StoreError::new(
            "SQLite durability pragmas do not match the configured store contract",
        ));
    }
    Ok(())
}

fn table_columns(connection: &Connection, table_name: &str) -> Result<Vec<String>, StoreError> {
    let mut statement = connection
        .prepare(
            "
            SELECT cid, name, type, \"notnull\", dflt_value, pk
            FROM pragma_table_info(?1)
            ORDER BY cid
            ",
        )
        .map_err(sql_error)?;
    let rows = statement
        .query_map([table_name], |row| {
            Ok(format!(
                "{}:{}:{}:{}:{}:{}",
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<String>>(4)?.unwrap_or_default(),
                row.get::<_, i64>(5)?,
            ))
        })
        .map_err(sql_error)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(sql_error)
}

fn schema_sql(
    connection: &Connection,
    object_type: &str,
    object_name: &str,
) -> Result<String, StoreError> {
    connection
        .query_row(
            "
            SELECT sql
            FROM sqlite_master
            WHERE type = ?1 AND name = ?2
            ",
            [object_type, object_name],
            |row| row.get::<_, String>(0),
        )
        .map(|value| normalize_sql(&value))
        .map_err(sql_error)
}

fn normalize_sql(value: &str) -> String {
    value
        .replace("IF NOT EXISTS ", "")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn sql_error(error: rusqlite::Error) -> StoreError {
    StoreError::new(error.to_string())
}
