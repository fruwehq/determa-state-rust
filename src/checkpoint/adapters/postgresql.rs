use super::super::store::{
    parse_durable_store_configuration_with_options, validate_policy_insert,
    validate_policy_replacement, AdapterError, AdapterErrorCode, DurableStoreMode, ExecutionStore,
    ExecutionStoreCapability, ExecutionStoreFactory, HealthStatus, StoreError, StoreRecord,
    StoreWriteResult,
};
use postgres::tls::{MakeTlsConnect, TlsConnect};
use postgres::{Client, IsolationLevel, NoTls, Socket, Transaction};
use std::any::Any;
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

pub struct PostgresqlExecutionStore {
    client: Mutex<Client>,
    mode: DurableStoreMode,
}

impl PostgresqlExecutionStore {
    pub fn connect_with_tls<T>(
        configuration: &str,
        mode: DurableStoreMode,
        tls: T,
    ) -> Result<Self, StoreError>
    where
        T: MakeTlsConnect<Socket> + Send + 'static,
        T::TlsConnect: Send,
        T::Stream: Send,
        <T::TlsConnect as TlsConnect<Socket>>::Future: Send,
    {
        let client = Client::connect(configuration, tls).map_err(pg_error)?;
        Ok(Self {
            client: Mutex::new(client),
            mode,
        })
    }

    /// Explicit local/testing connection path without transport encryption.
    pub fn connect_no_tls(configuration: &str, mode: DurableStoreMode) -> Result<Self, StoreError> {
        Self::connect_with_tls(configuration, mode, NoTls)
    }

    pub fn mode(&self) -> DurableStoreMode {
        self.mode
    }

    /// Runs low-level application work in a native serializable transaction.
    ///
    /// This does not expose checkpoint mutation. Use
    /// [`CheckpointHost::with_postgresql_transaction`](crate::checkpoint::CheckpointHost::with_postgresql_transaction)
    /// when application work and a host mutation must commit atomically.
    pub fn with_native_transaction<T>(
        &self,
        operation: impl FnOnce(&mut Transaction<'_>) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        let mut client = self
            .client
            .lock()
            .map_err(|_| StoreError::new("PostgreSQL client lock is poisoned"))?;
        let mut transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .start()
            .map_err(pg_error)?;
        let result = operation(&mut transaction)?;
        transaction.commit().map_err(pg_error)?;
        Ok(result)
    }

    pub(crate) fn load_in_transaction(
        transaction: &mut Transaction<'_>,
        root_instance_id: &str,
    ) -> Result<Option<StoreRecord>, StoreError> {
        transaction
            .query_opt(
                "
                SELECT revision::text, checkpoint_digest, checkpoint_bytes
                FROM determa_execution_checkpoints
                WHERE root_instance_id = $1
                FOR UPDATE
                ",
                &[&root_instance_id],
            )
            .map_err(pg_error)
            .map(|row| {
                row.map(|row| StoreRecord {
                    root_instance_id: root_instance_id.to_string(),
                    revision: row.get(0),
                    execution_checkpoint_digest: row.get(1),
                    bytes: row.get(2),
                })
            })
    }

    pub(crate) fn insert_if_absent_in_transaction(
        transaction: &mut Transaction<'_>,
        mode: DurableStoreMode,
        record: &StoreRecord,
    ) -> Result<StoreWriteResult, StoreError> {
        validate_policy_insert(mode, record)?;
        let changed = transaction
            .execute(
                "
                INSERT INTO determa_execution_checkpoints
                    (root_instance_id, revision, checkpoint_digest, checkpoint_bytes)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (root_instance_id) DO NOTHING
                ",
                &[
                    &record.root_instance_id,
                    &record.revision,
                    &record.execution_checkpoint_digest,
                    &record.bytes,
                ],
            )
            .map_err(pg_error)?;
        if changed == 1 {
            return Ok(StoreWriteResult::Committed);
        }
        Self::load_in_transaction(transaction, &record.root_instance_id)
            .map(StoreWriteResult::Conflict)
    }

    pub(crate) fn compare_and_swap_in_transaction(
        transaction: &mut Transaction<'_>,
        mode: DurableStoreMode,
        root_instance_id: &str,
        expected_revision: &str,
        expected_checkpoint_digest: &str,
        replacement: &StoreRecord,
    ) -> Result<StoreWriteResult, StoreError> {
        if replacement.root_instance_id != root_instance_id {
            return Err(StoreError::new("replacement belongs to another root"));
        }
        let current = Self::load_in_transaction(transaction, root_instance_id)?;
        let Some(current) = current else {
            return Ok(StoreWriteResult::Conflict(None));
        };
        if current.revision != expected_revision
            || current.execution_checkpoint_digest != expected_checkpoint_digest
        {
            return Ok(StoreWriteResult::Conflict(Some(current)));
        }
        validate_policy_replacement(mode, &current, replacement)?;
        let changed = transaction
            .execute(
                "
                UPDATE determa_execution_checkpoints
                SET revision = $1,
                    checkpoint_digest = $2,
                    checkpoint_bytes = $3
                WHERE root_instance_id = $4
                  AND revision = $5
                  AND checkpoint_digest = $6
                ",
                &[
                    &replacement.revision,
                    &replacement.execution_checkpoint_digest,
                    &replacement.bytes,
                    &root_instance_id,
                    &expected_revision,
                    &expected_checkpoint_digest,
                ],
            )
            .map_err(pg_error)?;
        if changed == 1 {
            return Ok(StoreWriteResult::Committed);
        }
        Self::load_in_transaction(transaction, root_instance_id).map(StoreWriteResult::Conflict)
    }

    fn client(&self) -> Result<std::sync::MutexGuard<'_, Client>, StoreError> {
        self.client
            .lock()
            .map_err(|_| StoreError::new("PostgreSQL client lock is poisoned"))
    }

    pub(crate) fn with_serializable_transaction<T, E>(
        &self,
        operation: impl FnOnce(&mut Transaction<'_>) -> Result<T, E>,
        map_store_error: impl Fn(StoreError) -> E,
    ) -> Result<T, E> {
        let mut client = self.client().map_err(&map_store_error)?;
        let mut transaction = client
            .build_transaction()
            .isolation_level(IsolationLevel::Serializable)
            .start()
            .map_err(pg_error)
            .map_err(&map_store_error)?;
        let result = operation(&mut transaction)?;
        transaction
            .commit()
            .map_err(pg_error)
            .map_err(map_store_error)?;
        Ok(result)
    }
}

impl ExecutionStore for PostgresqlExecutionStore {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn capabilities(&self) -> BTreeSet<ExecutionStoreCapability> {
        let mut capabilities = BTreeSet::from([
            ExecutionStoreCapability::DurableConcurrent,
            ExecutionStoreCapability::SharedApplicationTransaction,
            ExecutionStoreCapability::RootIdentityRetention,
        ]);
        self.mode.add_capabilities(&mut capabilities);
        capabilities
    }

    fn initialize_schema(&self) -> Result<(), StoreError> {
        let mut client = self.client()?;
        let mut transaction = client.transaction().map_err(pg_error)?;
        transaction
            .batch_execute(
                "
                CREATE TABLE IF NOT EXISTS determa_execution_store_metadata (
                    singleton BOOLEAN NOT NULL DEFAULT TRUE,
                    schema_version INTEGER NOT NULL,
                    receipt_retention TEXT NOT NULL,
                    outbox_retention TEXT NOT NULL,
                    CONSTRAINT determa_execution_store_metadata_primary_key
                        PRIMARY KEY (singleton),
                    CONSTRAINT determa_execution_store_metadata_singleton_check
                        CHECK (singleton),
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
                    checkpoint_bytes BYTEA NOT NULL,
                    CONSTRAINT determa_execution_checkpoints_primary_key
                        PRIMARY KEY (root_instance_id),
                    CONSTRAINT determa_execution_checkpoints_root_check
                        CHECK (root_instance_id <> ''),
                    CONSTRAINT determa_execution_checkpoints_revision_check
                        CHECK (revision ~ '^(0|[1-9][0-9]*)$'),
                    CONSTRAINT determa_execution_checkpoints_digest_check
                        CHECK (checkpoint_digest ~ '^sha256:[0-9a-f]{64}$'),
                    CONSTRAINT determa_execution_checkpoints_bytes_check
                        CHECK (octet_length(checkpoint_bytes) > 0)
                );
                CREATE OR REPLACE FUNCTION determa_reject_checkpoint_delete()
                RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN
                    RAISE EXCEPTION 'physical checkpoint deletion is unsupported';
                END
                $$;
                DROP TRIGGER IF EXISTS determa_execution_checkpoints_no_delete
                    ON determa_execution_checkpoints;
                CREATE TRIGGER determa_execution_checkpoints_no_delete
                BEFORE DELETE ON determa_execution_checkpoints
                FOR EACH ROW EXECUTE FUNCTION determa_reject_checkpoint_delete();
                ",
            )
            .map_err(pg_error)?;
        transaction
            .execute(
                "
                INSERT INTO determa_execution_store_metadata
                    (singleton, schema_version, receipt_retention, outbox_retention)
                VALUES (TRUE, 1, $1, $2)
                ON CONFLICT (singleton) DO NOTHING
                ",
                &[
                    &self.mode.receipt_retention.as_str(),
                    &self.mode.outbox_retention.as_str(),
                ],
            )
            .map_err(pg_error)?;
        verify_schema_contract(&mut transaction, self.mode)?;
        transaction.commit().map_err(pg_error)
    }

    fn health(&self) -> Result<HealthStatus, StoreError> {
        let mut client = self.client()?;
        verify_schema_contract(&mut *client, self.mode)?;
        Ok(HealthStatus::healthy(
            "PostgreSQL checkpoint schema and configured retention mode are available",
        ))
    }

    fn load(&self, root_instance_id: &str) -> Result<Option<StoreRecord>, StoreError> {
        let row = self
            .client()?
            .query_opt(
                "
                SELECT revision::text, checkpoint_digest, checkpoint_bytes
                FROM determa_execution_checkpoints
                WHERE root_instance_id = $1
                ",
                &[&root_instance_id],
            )
            .map_err(pg_error)?;
        Ok(row.map(|row| StoreRecord {
            root_instance_id: root_instance_id.to_string(),
            revision: row.get(0),
            execution_checkpoint_digest: row.get(1),
            bytes: row.get(2),
        }))
    }

    fn insert_if_absent(&self, record: StoreRecord) -> Result<StoreWriteResult, StoreError> {
        let mut client = self.client()?;
        let mut transaction = client.transaction().map_err(pg_error)?;
        let result = Self::insert_if_absent_in_transaction(&mut transaction, self.mode, &record)?;
        transaction.commit().map_err(pg_error)?;
        Ok(result)
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
        let mut client = self.client()?;
        let mut transaction = client.transaction().map_err(pg_error)?;
        let result = Self::compare_and_swap_in_transaction(
            &mut transaction,
            self.mode,
            root_instance_id,
            expected_revision,
            expected_checkpoint_digest,
            &replacement,
        )?;
        transaction.commit().map_err(pg_error)?;
        Ok(result)
    }
}

pub struct PostgresqlExecutionStoreFactory<T = NoTls> {
    tls: T,
    tls_configuration: &'static str,
}

impl PostgresqlExecutionStoreFactory<NoTls> {
    pub fn no_tls() -> Self {
        Self {
            tls: NoTls,
            tls_configuration: "no_tls",
        }
    }
}

impl<T> PostgresqlExecutionStoreFactory<T> {
    /// Creates a factory backed by an application-supplied TLS connector.
    ///
    /// Configurations resolved through this factory use `tls=provided`.
    pub fn with_tls(tls: T) -> Self {
        Self {
            tls,
            tls_configuration: "provided",
        }
    }
}

impl<T> ExecutionStoreFactory for PostgresqlExecutionStoreFactory<T>
where
    T: MakeTlsConnect<Socket> + Clone + Send + Sync + 'static,
    T::TlsConnect: Send,
    T::Stream: Send,
    <T::TlsConnect as TlsConnect<Socket>>::Future: Send,
{
    fn create(&self, configuration: &str) -> Result<Arc<dyn ExecutionStore>, AdapterError> {
        let (location, mode, options) =
            parse_durable_store_configuration_with_options(configuration, &["tls"])?;
        if !location.starts_with("postgresql://") {
            return Err(AdapterError::new(
                AdapterErrorCode::InvalidAdapterConfiguration,
                "PostgreSQL configuration must use a postgresql:// URI",
            ));
        }
        if options.get("tls").map(String::as_str) != Some(self.tls_configuration) {
            return Err(AdapterError::new(
                AdapterErrorCode::InvalidAdapterConfiguration,
                format!(
                    "PostgreSQL configuration must explicitly select tls={}",
                    self.tls_configuration
                ),
            ));
        }
        PostgresqlExecutionStore::connect_with_tls(location, mode, self.tls.clone())
            .map(|store| Arc::new(store) as Arc<dyn ExecutionStore>)
            .map_err(|error| {
                AdapterError::new(
                    AdapterErrorCode::InvalidAdapterConfiguration,
                    error.to_string(),
                )
            })
    }
}

fn verify_schema_contract(
    client: &mut impl postgres::GenericClient,
    mode: DurableStoreMode,
) -> Result<(), StoreError> {
    let metadata_rows = client
        .query(
            "
            SELECT schema_version, receipt_retention, outbox_retention
            FROM determa_execution_store_metadata
            WHERE singleton
            ",
            &[],
        )
        .map_err(pg_error)?;
    if metadata_rows.len() != 1 {
        return Err(StoreError::new(
            "PostgreSQL store metadata must contain exactly one configured row",
        ));
    }
    let row = &metadata_rows[0];
    let metadata = (
        row.get::<_, i32>(0),
        row.get::<_, String>(1),
        row.get::<_, String>(2),
    );
    if metadata
        != (
            1,
            mode.receipt_retention.as_str().to_string(),
            mode.outbox_retention.as_str().to_string(),
        )
    {
        return Err(StoreError::new(
            "PostgreSQL store schema retention mode differs from configured mode",
        ));
    }
    if table_columns(client, "determa_execution_store_metadata")?
        != [
            "singleton:boolean:NO:true",
            "schema_version:integer:NO:",
            "receipt_retention:text:NO:",
            "outbox_retention:text:NO:",
        ]
        || table_columns(client, "determa_execution_checkpoints")?
            != [
                "root_instance_id:text:NO:",
                "revision:text:NO:",
                "checkpoint_digest:text:NO:",
                "checkpoint_bytes:bytea:NO:",
            ]
    {
        return Err(StoreError::new(
            "PostgreSQL execution-store columns do not match schema version 1",
        ));
    }
    if table_constraints(client, "determa_execution_store_metadata")?
        != [
            "determa_execution_store_metadata_outbox_check|c|CHECK (outbox_retention = ANY (ARRAY['bounded', 'strict', 'compact']))",
            "determa_execution_store_metadata_primary_key|p|PRIMARY KEY (singleton)",
            "determa_execution_store_metadata_receipt_check|c|CHECK (receipt_retention = ANY (ARRAY['bounded', 'permanent']))",
            "determa_execution_store_metadata_singleton_check|c|CHECK (singleton)",
            "determa_execution_store_metadata_version_check|c|CHECK (schema_version = 1)",
        ]
        || table_constraints(client, "determa_execution_checkpoints")?
            != [
                "determa_execution_checkpoints_bytes_check|c|CHECK (octet_length(checkpoint_bytes) > 0)",
                "determa_execution_checkpoints_digest_check|c|CHECK (checkpoint_digest ~ '^sha256:[0-9a-f]{64}$')",
                "determa_execution_checkpoints_primary_key|p|PRIMARY KEY (root_instance_id)",
                "determa_execution_checkpoints_revision_check|c|CHECK (revision ~ '^(0|[1-9][0-9]*)$')",
                "determa_execution_checkpoints_root_check|c|CHECK (root_instance_id <> '')",
            ]
    {
        return Err(StoreError::new(
            "PostgreSQL execution-store constraints do not match schema version 1",
        ));
    }
    let triggers = client
        .query(
            "
            SELECT trigger.tgname,
                   trigger.tgenabled::text,
                   (trigger.tgtype & 1) <> 0,
                   (trigger.tgtype & 2) <> 0,
                   (trigger.tgtype & 8) <> 0,
                   procedure.proname,
                   procedure.prosrc
            FROM pg_trigger AS trigger
            JOIN pg_proc AS procedure ON procedure.oid = trigger.tgfoid
            WHERE trigger.tgrelid = 'determa_execution_checkpoints'::regclass
              AND NOT trigger.tgisinternal
            ORDER BY trigger.tgname
            ",
            &[],
        )
        .map_err(pg_error)?;
    if triggers.len() != 1 {
        return Err(StoreError::new(
            "PostgreSQL checkpoint deletion trigger does not match schema version 1",
        ));
    }
    let trigger = &triggers[0];
    let trigger_contract = format!(
        "{}|{}|{}|{}|{}|{}|{}",
        trigger.get::<_, String>(0),
        trigger.get::<_, String>(1),
        trigger.get::<_, bool>(2),
        trigger.get::<_, bool>(3),
        trigger.get::<_, bool>(4),
        trigger.get::<_, String>(5),
        normalize_sql(&trigger.get::<_, String>(6)),
    );
    if trigger_contract
        != "determa_execution_checkpoints_no_delete|O|true|true|true|determa_reject_checkpoint_delete|BEGIN RAISE EXCEPTION 'physical checkpoint deletion is unsupported'; END"
    {
        return Err(StoreError::new(
            "PostgreSQL checkpoint deletion trigger does not match schema version 1",
        ));
    }
    Ok(())
}

fn table_columns(
    client: &mut impl postgres::GenericClient,
    table_name: &str,
) -> Result<Vec<String>, StoreError> {
    client
        .query(
            "
            SELECT column_name, data_type, is_nullable, column_default
            FROM information_schema.columns
            WHERE table_schema = current_schema()
              AND table_name = $1
            ORDER BY ordinal_position
            ",
            &[&table_name],
        )
        .map_err(pg_error)
        .map(|rows| {
            rows.into_iter()
                .map(|row| {
                    format!(
                        "{}:{}:{}:{}",
                        row.get::<_, String>(0),
                        row.get::<_, String>(1),
                        row.get::<_, String>(2),
                        row.get::<_, Option<String>>(3).unwrap_or_default(),
                    )
                })
                .collect()
        })
}

fn table_constraints(
    client: &mut impl postgres::GenericClient,
    table_name: &str,
) -> Result<Vec<String>, StoreError> {
    client
        .query(
            "
            SELECT constraint_record.conname,
                   constraint_record.contype::text,
                   pg_get_constraintdef(constraint_record.oid, TRUE)
            FROM pg_constraint AS constraint_record
            WHERE constraint_record.conrelid =
                  format('%I.%I', current_schema(), $1::text)::regclass
            ORDER BY constraint_record.conname
            ",
            &[&table_name],
        )
        .map_err(pg_error)
        .map(|rows| {
            rows.into_iter()
                .map(|row| {
                    format!(
                        "{}|{}|{}",
                        row.get::<_, String>(0),
                        row.get::<_, String>(1),
                        normalize_postgresql_constraint(&row.get::<_, String>(2)),
                    )
                })
                .collect()
        })
}

fn normalize_postgresql_constraint(value: &str) -> String {
    normalize_sql(&value.replace("::text", ""))
}

fn normalize_sql(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn pg_error(error: postgres::Error) -> StoreError {
    let message = error.as_db_error().map_or_else(
        || error.to_string(),
        |database| format!("{}: {}", database.code().code(), database.message()),
    );
    StoreError::new(message)
}
