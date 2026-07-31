use super::super::store::{
    parse_durable_store_configuration, validate_policy_insert, validate_policy_replacement,
    AdapterError, AdapterErrorCode, DurableStoreMode, ExecutionStore, ExecutionStoreCapability,
    ExecutionStoreFactory, HealthStatus, StoreError, StoreRecord, StoreWriteResult,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
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
}

impl ExecutionStore for SqliteExecutionStore {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn capabilities(&self) -> BTreeSet<ExecutionStoreCapability> {
        let mut capabilities = BTreeSet::from([
            ExecutionStoreCapability::DurableSingleWriter,
            ExecutionStoreCapability::RootIdentityRetention,
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
                        CHECK (schema_version = 1),
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
                ",
            )
            .map_err(sql_error)?;
        transaction
            .execute(
                "
                INSERT OR IGNORE INTO determa_execution_store_metadata
                    (singleton, schema_version, receipt_retention, outbox_retention)
                VALUES (1, 1, ?1, ?2)
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

fn load_record(
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
            1,
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
            "SQLite execution-store columns do not match schema version 1",
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
                    CHECK (schema_version = 1),
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
            "SQLite execution-store constraints or deletion guard do not match schema version 1",
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
