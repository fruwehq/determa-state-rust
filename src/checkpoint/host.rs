#[cfg(feature = "postgresql")]
use super::adapters::PostgresqlExecutionStore;
#[cfg(feature = "sqlite")]
use super::adapters::SqliteExecutionStore;
#[cfg(feature = "postgresql")]
use super::store::DurableStoreMode;
use super::store::{
    validate_store_host_profile, AdapterError, AdapterRegistry, ExecutionStore,
    ExecutionStoreCapability, ExecutionStoreFactory, HostFeature, HostProfile, StoreError,
    StoreErrorCode, StoreRecord, StoreWriteResult,
};
use super::types::{
    AdmissionSource, DurableCheckpointExecution, DurableContractExecution, DurableHostResult,
    PendingOutboxState, ProcessingRequest, PruneRequest, ScopedStoreRecord, StoreScope,
    TerminalOutboxOutcome, TransactionalProcessRequest,
};
#[cfg(feature = "sqlite")]
use super::types::{
    DurableFailurePolicy, DurableHostExecution, DurableProcessRequest,
    DurableQuarantineReleaseRequest,
};
use super::v1::{
    checkpoint_admit_v1_with_optional_bundle, checkpoint_compact_outbox,
    checkpoint_maintenance_migration_route, checkpoint_process, checkpoint_process_replay,
    checkpoint_process_with_migration_with_core, checkpoint_prune_v1, checkpoint_step_replay,
    checkpoint_step_v1_with_core, checkpoint_terminalize_outbox, checkpoint_tombstone_root,
    checkpoint_update_pending_outbox, create_execution_checkpoint_v1, creation_request_digest,
    restore_execution_checkpoint, ExecutionCheckpoint,
};
use crate::format1::{
    ArtifactError, Bindings, Bundle, MigrationArtifactResolver, MigrationRequest, ResourceLimits,
};
use serde_json::{json, Value as JsonValue};
use std::collections::BTreeSet;
use std::sync::Arc;

fn caller_checkpoint_response(
    kind: &str,
    returned: &JsonValue,
    core: Option<&JsonValue>,
    admission_ids: &[String],
    changed: bool,
) -> Option<JsonValue> {
    match kind {
        "creation" => Some(json!({"kind":"creation","body":returned})),
        "admission" => {
            let checkpoint = returned.get("checkpoint").unwrap_or(returned);
            let receipts = checkpoint
                .get("operation_receipts")
                .and_then(JsonValue::as_array);
            let members = returned.get("members").and_then(JsonValue::as_array);
            let evidence = admission_ids
                .iter()
                .enumerate()
                .filter_map(|(index, event_id)| {
                    let member = members.and_then(|members| members.get(index));
                    member
                        .and_then(|item| item.get("evidence"))
                        .or_else(|| {
                            receipts.and_then(|items| {
                                items.iter().rev().find(|item| {
                                    item["event_id"] == *event_id
                                        && item["operation_kind"] == "acceptance"
                                })
                            })
                        })
                        .or_else(|| (returned["event_id"] == *event_id).then_some(returned))
                        .cloned()
                })
                .collect::<Vec<_>>();
            Some(json!({"kind":"admission","body":{"evidence":evidence}}))
        }
        "processing" => {
            if core.is_none() {
                return Some(json!({"kind":"retained_receipt","body":returned}));
            }
            let receipt = returned
                .get("operation_receipts")
                .and_then(JsonValue::as_array)
                .and_then(|receipts| {
                    receipts
                        .iter()
                        .rev()
                        .find(|receipt| receipt["operation_kind"] == "event_terminal")
                })
                .or_else(|| (returned["operation_kind"] == "event_terminal").then_some(returned));
            Some(json!({"kind":"processing","body":{"core_result":core,"receipt":receipt}}))
        }
        "host_acknowledgement" => Some(
            json!({"kind":"host_acknowledgement","body":{"result":if changed { "committed" } else { "replayed" }}}),
        ),
        "tombstoned" => Some(
            json!({"kind":"tombstoned","body":{"result":"tombstoned","tombstone":returned.get("tombstone").unwrap_or(&returned["root_record"])}}),
        ),
        "pending_outbox" => Some(json!({"kind":kind,"body":returned})),
        "terminal_outbox" => Some(json!({"kind":kind,"body":returned["record"]})),
        _ => None,
    }
}

fn contract_success(kind: &str, body: JsonValue) -> DurableContractExecution {
    DurableContractExecution {
        result: DurableHostResult::validated(),
        caller_response: json!({"kind":kind,"body":body}),
    }
}

fn contract_failure(code: &str) -> DurableContractExecution {
    DurableContractExecution {
        result: DurableHostResult::validation_rejected(code),
        caller_response: json!({"kind":"typed_failure","body":{"code":code}}),
    }
}

/// Register an adapter and return the exact descriptor retained by the registry.
pub fn execute_adapter_registration(
    registry: &AdapterRegistry,
    descriptor: JsonValue,
    factory: Arc<dyn ExecutionStoreFactory>,
) -> DurableContractExecution {
    match registry.register_descriptor(descriptor, factory) {
        Ok(registered) => contract_success("registration", registered),
        Err(error) => contract_failure(error.code.as_str()),
    }
}

/// Resolve an adapter through its registered factory and return its verified configuration.
pub fn execute_adapter_resolution(
    registry: &AdapterRegistry,
    uri: &str,
    configuration: &JsonValue,
    requested_capabilities: &BTreeSet<ExecutionStoreCapability>,
) -> DurableContractExecution {
    match registry.resolve_descriptor(uri, configuration, requested_capabilities) {
        Ok(registration) => contract_success(
            "resolution",
            json!({
                "registration":registration,
                "configuration":configuration,
                "requested_capabilities": requested_capabilities.iter().map(|capability| capability.as_str()).collect::<Vec<_>>()
            }),
        ),
        Err(error) => contract_failure(error.code.as_str()),
    }
}

#[cfg(feature = "sqlite")]
use rusqlite::{params, OptionalExtension};

trait StoreAccess {
    fn load(&mut self, root_instance_id: &str) -> Result<Option<StoreRecord>, StoreError>;

    fn insert_if_absent(&mut self, record: StoreRecord) -> Result<StoreWriteResult, StoreError>;

    fn compare_and_swap(
        &mut self,
        root_instance_id: &str,
        expected_revision: &str,
        expected_checkpoint_digest: &str,
        replacement: StoreRecord,
    ) -> Result<StoreWriteResult, StoreError>;
}

struct DirectStoreAccess<'a> {
    store: &'a dyn ExecutionStore,
}

impl StoreAccess for DirectStoreAccess<'_> {
    fn load(&mut self, root_instance_id: &str) -> Result<Option<StoreRecord>, StoreError> {
        self.store.load(root_instance_id)
    }

    fn insert_if_absent(&mut self, record: StoreRecord) -> Result<StoreWriteResult, StoreError> {
        self.store.insert_if_absent(record)
    }

    fn compare_and_swap(
        &mut self,
        root_instance_id: &str,
        expected_revision: &str,
        expected_checkpoint_digest: &str,
        replacement: StoreRecord,
    ) -> Result<StoreWriteResult, StoreError> {
        self.store.compare_and_swap(
            root_instance_id,
            expected_revision,
            expected_checkpoint_digest,
            replacement,
        )
    }
}

#[cfg(feature = "postgresql")]
struct PostgresqlTransactionStore<'transaction, 'client> {
    transaction: &'transaction mut postgres::Transaction<'client>,
    mode: DurableStoreMode,
    root_instance_id: &'transaction str,
}

#[cfg(feature = "postgresql")]
impl PostgresqlTransactionStore<'_, '_> {
    fn require_root(&self, root_instance_id: &str) -> Result<(), StoreError> {
        if root_instance_id == self.root_instance_id {
            Ok(())
        } else {
            Err(StoreError::new(
                "PostgreSQL host transaction is bound to another root",
            ))
        }
    }
}

#[cfg(feature = "postgresql")]
impl StoreAccess for PostgresqlTransactionStore<'_, '_> {
    fn load(&mut self, root_instance_id: &str) -> Result<Option<StoreRecord>, StoreError> {
        self.require_root(root_instance_id)?;
        PostgresqlExecutionStore::load_in_transaction(self.transaction, root_instance_id)
    }

    fn insert_if_absent(&mut self, record: StoreRecord) -> Result<StoreWriteResult, StoreError> {
        self.require_root(&record.root_instance_id)?;
        PostgresqlExecutionStore::insert_if_absent_in_transaction(
            self.transaction,
            self.mode,
            &record,
        )
    }

    fn compare_and_swap(
        &mut self,
        root_instance_id: &str,
        expected_revision: &str,
        expected_checkpoint_digest: &str,
        replacement: StoreRecord,
    ) -> Result<StoreWriteResult, StoreError> {
        self.require_root(root_instance_id)?;
        PostgresqlExecutionStore::compare_and_swap_in_transaction(
            self.transaction,
            self.mode,
            root_instance_id,
            expected_revision,
            expected_checkpoint_digest,
            &replacement,
        )
    }
}

#[cfg(feature = "sqlite")]
struct SqliteTransactionStore<'transaction, 'connection> {
    transaction: &'transaction rusqlite::Transaction<'connection>,
    mode: super::store::DurableStoreMode,
    root_instance_id: &'transaction str,
}

#[cfg(feature = "sqlite")]
impl SqliteTransactionStore<'_, '_> {
    fn require_root(&self, root_instance_id: &str) -> Result<(), StoreError> {
        if root_instance_id == self.root_instance_id {
            Ok(())
        } else {
            Err(StoreError::new(
                "SQLite host transaction is bound to another root",
            ))
        }
    }
}

#[cfg(feature = "sqlite")]
impl StoreAccess for SqliteTransactionStore<'_, '_> {
    fn load(&mut self, root_instance_id: &str) -> Result<Option<StoreRecord>, StoreError> {
        self.require_root(root_instance_id)?;
        super::adapters::sqlite::load_record(self.transaction, root_instance_id)
    }

    fn insert_if_absent(&mut self, record: StoreRecord) -> Result<StoreWriteResult, StoreError> {
        self.require_root(&record.root_instance_id)?;
        if super::adapters::sqlite::load_record(self.transaction, &record.root_instance_id)?
            .is_some()
        {
            return Ok(StoreWriteResult::Conflict(
                super::adapters::sqlite::load_record(self.transaction, &record.root_instance_id)?,
            ));
        }
        super::store::validate_policy_insert(self.mode, &record)?;
        self.transaction
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
            .map_err(sqlite_error)?;
        Ok(StoreWriteResult::Committed)
    }

    fn compare_and_swap(
        &mut self,
        root_instance_id: &str,
        expected_revision: &str,
        expected_checkpoint_digest: &str,
        replacement: StoreRecord,
    ) -> Result<StoreWriteResult, StoreError> {
        self.require_root(root_instance_id)?;
        let current = super::adapters::sqlite::load_record(self.transaction, root_instance_id)?;
        let Some(current) = current else {
            return Ok(StoreWriteResult::Conflict(None));
        };
        if current.revision != expected_revision
            || current.execution_checkpoint_digest != expected_checkpoint_digest
        {
            return Ok(StoreWriteResult::Conflict(Some(current)));
        }
        super::store::validate_policy_replacement(self.mode, &current, &replacement)?;
        self.transaction
            .execute(
                "UPDATE determa_execution_checkpoints
                 SET revision = ?1, checkpoint_digest = ?2, checkpoint_bytes = ?3
                 WHERE root_instance_id = ?4",
                params![
                    replacement.revision,
                    replacement.execution_checkpoint_digest,
                    replacement.bytes,
                    root_instance_id
                ],
            )
            .map_err(sqlite_error)?;
        Ok(StoreWriteResult::Committed)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostFailureCode {
    ExecutionStoreFailure,
    CheckpointNotFound,
    CreationRejected,
    EventIdConflict,
    CreationIdConflict,
    OperationIdConflict,
    EffectIdConflict,
    CheckpointRevisionConflict,
    InvalidExecutionCheckpoint,
    PhysicalDeletionUnsupported,
    TransactionStoreMismatch,
    TransactionRootMismatch,
    TransactionMutationAlreadyStaged,
    TransactionMutationRequired,
    InjectedPreCommitFailure,
    ResponseLostAfterCommit,
}

impl HostFailureCode {
    /// Complete checkpoint-host failure set defined by the portable registry.
    pub const PORTABLE_CODES: &'static [Self] = &[
        Self::CreationRejected,
        Self::EventIdConflict,
        Self::CreationIdConflict,
        Self::OperationIdConflict,
        Self::EffectIdConflict,
        Self::CheckpointRevisionConflict,
        Self::InvalidExecutionCheckpoint,
        Self::InjectedPreCommitFailure,
        Self::ResponseLostAfterCommit,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExecutionStoreFailure => "execution_store_failure",
            Self::CheckpointNotFound => "checkpoint_not_found",
            Self::CreationRejected => "creation_rejected",
            Self::EventIdConflict => "event_id_conflict",
            Self::CreationIdConflict => "creation_id_conflict",
            Self::OperationIdConflict => "operation_id_conflict",
            Self::EffectIdConflict => "effect_id_conflict",
            Self::CheckpointRevisionConflict => "checkpoint_revision_conflict",
            Self::InvalidExecutionCheckpoint => "invalid_execution_checkpoint",
            Self::PhysicalDeletionUnsupported => "physical_deletion_unsupported",
            Self::TransactionStoreMismatch => "transaction_store_mismatch",
            Self::TransactionRootMismatch => "transaction_root_mismatch",
            Self::TransactionMutationAlreadyStaged => "transaction_mutation_already_staged",
            Self::TransactionMutationRequired => "transaction_mutation_required",
            Self::InjectedPreCommitFailure => "injected_pre_commit_failure",
            Self::ResponseLostAfterCommit => "response_lost_after_commit",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostFailure {
    pub code: HostFailureCode,
    pub message: String,
}

impl HostFailure {
    fn new(code: HostFailureCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for HostFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for HostFailure {}

impl From<StoreError> for HostFailure {
    fn from(value: StoreError) -> Self {
        let code = match value.code {
            StoreErrorCode::ExecutionStoreFailure => HostFailureCode::ExecutionStoreFailure,
            StoreErrorCode::InjectedPreCommitFailure => HostFailureCode::InjectedPreCommitFailure,
            StoreErrorCode::ResponseLostAfterCommit => HostFailureCode::ResponseLostAfterCommit,
            StoreErrorCode::InvalidStoreScope
            | StoreErrorCode::PermanentProcessingFailure
            | StoreErrorCode::TransientProcessingFailure => HostFailureCode::ExecutionStoreFailure,
        };
        Self::new(code, value.message)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutationGuard {
    pub expected_revision: String,
    pub expected_checkpoint_digest: String,
}

impl MutationGuard {
    pub fn new(
        expected_revision: impl Into<String>,
        expected_checkpoint_digest: impl Into<String>,
    ) -> Self {
        Self {
            expected_revision: expected_revision.into(),
            expected_checkpoint_digest: expected_checkpoint_digest.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MaintenanceMigrationRequest {
    pub root_instance_id: String,
    pub operation_id: String,
    pub source_aggregate_state_digest: String,
    pub target_validated_bundle_fingerprint: String,
    pub migration_descriptor_digest_route: Vec<String>,
    pub maintenance_mode: bool,
    pub supplied_request_digest: Option<String>,
    pub guard: MutationGuard,
    pub limits: ResourceLimits,
}

pub enum DurableCheckpointOperation<'a> {
    Create {
        bundle: &'a Bundle,
        machine_id: &'a str,
        root_instance_id: &'a str,
        creation_id: &'a str,
        bindings: &'a Bindings,
        supplied_request_digest: Option<&'a str>,
        replay_retention: JsonValue,
    },
    Admit {
        root_instance_id: &'a str,
        sources: &'a [AdmissionSource],
        guard: &'a MutationGuard,
    },
    Step {
        root_instance_id: &'a str,
        request: &'a ProcessingRequest,
        guard: &'a MutationGuard,
    },
    UpdatePendingOutbox {
        root_instance_id: &'a str,
        effect_id: &'a str,
        desired: PendingOutboxState,
        guard: &'a MutationGuard,
    },
    TerminalizeOutbox {
        root_instance_id: &'a str,
        effect_id: &'a str,
        outcome: TerminalOutboxOutcome,
        guard: &'a MutationGuard,
    },
    CompactOutbox {
        root_instance_id: &'a str,
        effect_id: &'a str,
        guard: &'a MutationGuard,
    },
    Prune {
        root_instance_id: &'a str,
        request: &'a PruneRequest,
        guard: &'a MutationGuard,
    },
    Tombstone {
        root_instance_id: &'a str,
        operation_id: &'a str,
        guard: &'a MutationGuard,
    },
    DeleteRetainedRecord {
        root_instance_id: &'a str,
        guard: &'a MutationGuard,
    },
}

impl DurableCheckpointOperation<'_> {
    fn root_instance_id(&self) -> &str {
        match self {
            Self::Create {
                root_instance_id, ..
            }
            | Self::Admit {
                root_instance_id, ..
            }
            | Self::Step {
                root_instance_id, ..
            }
            | Self::UpdatePendingOutbox {
                root_instance_id, ..
            }
            | Self::TerminalizeOutbox {
                root_instance_id, ..
            }
            | Self::CompactOutbox {
                root_instance_id, ..
            }
            | Self::Prune {
                root_instance_id, ..
            }
            | Self::Tombstone {
                root_instance_id, ..
            }
            | Self::DeleteRetainedRecord {
                root_instance_id, ..
            } => root_instance_id,
        }
    }

    fn is_core_operation(&self) -> bool {
        matches!(
            self,
            Self::Create { .. } | Self::Admit { .. } | Self::Step { .. }
        )
    }
}

#[cfg(feature = "postgresql")]
pub enum PostgresqlHostMutation<'a> {
    Create {
        bundle: &'a Bundle,
        machine_id: &'a str,
        root_instance_id: &'a str,
        creation_id: &'a str,
        bindings: &'a Bindings,
        supplied_request_digest: Option<&'a str>,
        replay_retention: &'a JsonValue,
    },
    Admit {
        root_instance_id: &'a str,
        deliveries: &'a [JsonValue],
        guard: &'a MutationGuard,
    },
    Step {
        root_instance_id: &'a str,
        request: &'a ProcessingRequest,
        guard: &'a MutationGuard,
    },
    Process {
        root_instance_id: &'a str,
        delivery: &'a JsonValue,
        processing_mode: &'a str,
        guard: &'a MutationGuard,
    },
    TransactionalProcess {
        root_instance_id: &'a str,
        request: &'a TransactionalProcessRequest,
        guard: &'a MutationGuard,
    },
    Prune {
        root_instance_id: &'a str,
        request: &'a PruneRequest,
        guard: &'a MutationGuard,
    },
    MaintenanceMigration(&'a MaintenanceMigrationRequest),
    UpdatePendingOutbox {
        root_instance_id: &'a str,
        effect_id: &'a str,
        desired: PendingOutboxState,
        guard: &'a MutationGuard,
    },
    TerminalizeOutbox {
        root_instance_id: &'a str,
        effect_id: &'a str,
        outcome: TerminalOutboxOutcome,
        guard: &'a MutationGuard,
    },
    CompactOutbox {
        root_instance_id: &'a str,
        effect_id: &'a str,
        guard: &'a MutationGuard,
    },
    TombstoneRoot {
        root_instance_id: &'a str,
        operation_id: &'a str,
        guard: &'a MutationGuard,
    },
}

#[cfg(feature = "postgresql")]
impl PostgresqlHostMutation<'_> {
    fn root_instance_id(&self) -> &str {
        match self {
            Self::Create {
                root_instance_id, ..
            }
            | Self::Admit {
                root_instance_id, ..
            }
            | Self::Step {
                root_instance_id, ..
            }
            | Self::Process {
                root_instance_id, ..
            }
            | Self::TransactionalProcess {
                root_instance_id, ..
            }
            | Self::Prune {
                root_instance_id, ..
            }
            | Self::UpdatePendingOutbox {
                root_instance_id, ..
            }
            | Self::TerminalizeOutbox {
                root_instance_id, ..
            }
            | Self::CompactOutbox {
                root_instance_id, ..
            }
            | Self::TombstoneRoot {
                root_instance_id, ..
            } => root_instance_id,
            Self::MaintenanceMigration(request) => &request.root_instance_id,
        }
    }
}

#[cfg(feature = "postgresql")]
#[derive(Debug, Clone, PartialEq)]
pub enum PostgresqlHostMutationResult {
    Creation(JsonValue),
    Admission(JsonValue),
    Step(JsonValue),
    Process(JsonValue),
    TransactionalProcess(JsonValue),
    Prune(JsonValue),
    MaintenanceMigration(JsonValue),
    PendingOutbox(JsonValue),
    Outbox(JsonValue),
    CompactedOutbox(JsonValue),
    RootTombstone(JsonValue),
}

#[cfg(feature = "postgresql")]
#[derive(Debug, Clone, PartialEq)]
pub struct PostgresqlTransactionOutcome<T> {
    pub application_result: T,
    pub host_result: PostgresqlHostMutationResult,
}

#[cfg(feature = "postgresql")]
pub struct PostgresqlHostTransaction<'transaction, 'client> {
    transaction: &'transaction mut postgres::Transaction<'client>,
    store_identity: usize,
    root_instance_id: String,
    staged_result: Option<PostgresqlHostMutationResult>,
}

#[cfg(feature = "postgresql")]
impl<'client> PostgresqlHostTransaction<'_, 'client> {
    /// Native transaction for application-row work only. Checkpoint mutation is
    /// staged through [`CheckpointHost::stage_postgresql_mutation`].
    pub fn transaction(&mut self) -> &mut postgres::Transaction<'client> {
        self.transaction
    }

    pub fn root_instance_id(&self) -> &str {
        &self.root_instance_id
    }
}

pub struct CheckpointHost<R> {
    store: Arc<dyn ExecutionStore>,
    resolver: Arc<R>,
}

impl<R> CheckpointHost<R>
where
    R: MigrationArtifactResolver + Send + Sync + 'static,
{
    pub fn new(store: Arc<dyn ExecutionStore>, resolver: Arc<R>) -> Self {
        Self { store, resolver }
    }

    pub fn store(&self) -> &Arc<dyn ExecutionStore> {
        &self.store
    }

    pub fn validate_profile(
        &self,
        profile: HostProfile,
        features: &std::collections::BTreeSet<HostFeature>,
        permanent_replay_retention: bool,
    ) -> Result<(), AdapterError> {
        validate_store_host_profile(
            self.store.as_ref(),
            profile,
            features,
            permanent_replay_retention,
        )
    }

    /// Runs application work and exactly one root-bound host mutation in one
    /// PostgreSQL SERIALIZABLE transaction. The staged host result is returned
    /// only after the database commit succeeds.
    #[cfg(feature = "postgresql")]
    pub fn with_postgresql_transaction<T>(
        &self,
        root_instance_id: &str,
        operation: impl FnOnce(&mut PostgresqlHostTransaction<'_, '_>) -> Result<T, HostFailure>,
    ) -> Result<PostgresqlTransactionOutcome<T>, HostFailure> {
        let store = self
            .store
            .as_any()
            .downcast_ref::<PostgresqlExecutionStore>()
            .ok_or_else(|| {
                HostFailure::new(
                    HostFailureCode::TransactionStoreMismatch,
                    "host store is not the PostgreSQL store that owns this transaction",
                )
            })?;
        self.store.health()?;
        let store_identity = self.store_identity();
        let (application_result, host_result) = store.with_serializable_transaction(
            |database_transaction| {
                let mut transaction = PostgresqlHostTransaction {
                    transaction: database_transaction,
                    store_identity,
                    root_instance_id: root_instance_id.to_string(),
                    staged_result: None,
                };
                let application_result = operation(&mut transaction)?;
                let host_result = transaction.staged_result.take().ok_or_else(|| {
                    HostFailure::new(
                        HostFailureCode::TransactionMutationRequired,
                        "PostgreSQL host transaction requires one staged host mutation",
                    )
                })?;
                Ok((application_result, host_result))
            },
            HostFailure::from,
        )?;
        Ok(PostgresqlTransactionOutcome {
            application_result,
            host_result,
        })
    }

    /// Stages one host mutation inside a transaction created by this exact host
    /// store and bound root. Success is intentionally reported as `()` because
    /// the committed host result does not exist until the outer commit succeeds.
    #[cfg(feature = "postgresql")]
    pub fn stage_postgresql_mutation(
        &self,
        transaction: &mut PostgresqlHostTransaction<'_, '_>,
        mutation: PostgresqlHostMutation<'_>,
    ) -> Result<(), HostFailure> {
        if transaction.store_identity != self.store_identity()
            || self
                .store
                .as_any()
                .downcast_ref::<PostgresqlExecutionStore>()
                .is_none()
        {
            return Err(HostFailure::new(
                HostFailureCode::TransactionStoreMismatch,
                "PostgreSQL transaction belongs to another execution store",
            ));
        }
        if mutation.root_instance_id() != transaction.root_instance_id {
            return Err(HostFailure::new(
                HostFailureCode::TransactionRootMismatch,
                "PostgreSQL transaction is bound to another root",
            ));
        }
        if transaction.staged_result.is_some() {
            return Err(HostFailure::new(
                HostFailureCode::TransactionMutationAlreadyStaged,
                "PostgreSQL transaction already contains a host mutation",
            ));
        }
        let mode = self
            .store
            .as_any()
            .downcast_ref::<PostgresqlExecutionStore>()
            .expect("PostgreSQL store identity checked")
            .mode();
        let root_instance_id = transaction.root_instance_id.clone();
        let mut store = PostgresqlTransactionStore {
            transaction: transaction.transaction,
            mode,
            root_instance_id: &root_instance_id,
        };
        let result = match mutation {
            PostgresqlHostMutation::Create {
                bundle,
                machine_id,
                root_instance_id,
                creation_id,
                bindings,
                supplied_request_digest,
                replay_retention,
            } => PostgresqlHostMutationResult::Creation(
                self.create_checkpoint_with_store(
                    &mut store,
                    bundle,
                    machine_id,
                    root_instance_id,
                    creation_id,
                    bindings,
                    supplied_request_digest,
                    replay_retention.clone(),
                )
                .map_err(v1_host_failure)?,
            ),
            PostgresqlHostMutation::Admit {
                root_instance_id,
                deliveries,
                guard,
            } => PostgresqlHostMutationResult::Admission(
                self.admit_checkpoint_with_store(&mut store, root_instance_id, deliveries, guard)
                    .map_err(v1_host_failure)?,
            ),
            PostgresqlHostMutation::Step {
                root_instance_id,
                request,
                guard,
            } => PostgresqlHostMutationResult::Step(
                self.step_checkpoint_with_store(&mut store, root_instance_id, request, guard)
                    .map_err(v1_host_failure)?,
            ),
            PostgresqlHostMutation::Process {
                root_instance_id,
                delivery,
                processing_mode,
                guard,
            } => PostgresqlHostMutationResult::Process(
                self.process_checkpoint_with_store(
                    &mut store,
                    root_instance_id,
                    delivery,
                    processing_mode,
                    guard,
                )
                .map_err(v1_host_failure)?,
            ),
            PostgresqlHostMutation::TransactionalProcess {
                root_instance_id,
                request,
                guard,
            } => PostgresqlHostMutationResult::TransactionalProcess(
                self.transactional_process_with_store(&mut store, root_instance_id, request, guard)
                    .map_err(v1_host_failure)?,
            ),
            PostgresqlHostMutation::Prune {
                root_instance_id,
                request,
                guard,
            } => PostgresqlHostMutationResult::Prune(
                self.prune_checkpoint_with_store(&mut store, root_instance_id, request, guard)
                    .map_err(v1_host_failure)?,
            ),
            PostgresqlHostMutation::MaintenanceMigration(request) => {
                PostgresqlHostMutationResult::MaintenanceMigration(
                    self.maintenance_migration_with_store(&mut store, request)
                        .map_err(v1_host_failure)?,
                )
            }
            PostgresqlHostMutation::UpdatePendingOutbox {
                root_instance_id,
                effect_id,
                desired,
                guard,
            } => PostgresqlHostMutationResult::PendingOutbox(
                self.update_pending_outbox_with_store(
                    &mut store,
                    root_instance_id,
                    effect_id,
                    desired,
                    guard,
                )
                .map_err(v1_host_failure)?,
            ),
            PostgresqlHostMutation::TerminalizeOutbox {
                root_instance_id,
                effect_id,
                outcome,
                guard,
            } => PostgresqlHostMutationResult::Outbox(
                self.terminalize_outbox_with_store(
                    &mut store,
                    root_instance_id,
                    effect_id,
                    outcome,
                    guard,
                )
                .map_err(v1_host_failure)?,
            ),
            PostgresqlHostMutation::CompactOutbox {
                root_instance_id,
                effect_id,
                guard,
            } => PostgresqlHostMutationResult::CompactedOutbox(
                self.compact_outbox_with_store(&mut store, root_instance_id, effect_id, guard)
                    .map_err(v1_host_failure)?,
            ),
            PostgresqlHostMutation::TombstoneRoot {
                root_instance_id,
                operation_id,
                guard,
            } => PostgresqlHostMutationResult::RootTombstone(
                self.tombstone_root_with_store(&mut store, root_instance_id, operation_id, guard)
                    .map_err(v1_host_failure)?,
            ),
        };
        transaction.staged_result = Some(result);
        Ok(())
    }

    #[cfg(feature = "postgresql")]
    fn store_identity(&self) -> usize {
        Arc::as_ptr(&self.store) as *const () as usize
    }

    pub fn load_checkpoint(
        &self,
        root_instance_id: &str,
    ) -> Result<Option<ExecutionCheckpoint>, ArtifactError> {
        self.store
            .load(root_instance_id)
            .map_err(v1_store_error)?
            .map(|record| self.restore_record_v1(record))
            .transpose()
    }

    pub fn injected_store_result(&self) -> DurableHostResult {
        DurableHostResult::validated()
    }

    pub fn injected_store_contract(&self) -> DurableContractExecution {
        contract_success(
            "adapter_reference",
            json!({
                "adapter_identifier":"injected-store",
                "uri":"object://injected-store",
                "configuration":{"instance":"provided"},
                "capabilities":self.store.capabilities().iter().map(|capability| capability.as_str()).collect::<Vec<_>>()
            }),
        )
    }

    pub fn validate_scope_contract(
        &self,
        scope: &StoreScope,
        records: &[ScopedStoreRecord],
        portable_identity: &str,
        effect_id: &str,
    ) -> DurableContractExecution {
        let result = self.validate_scope_operation(scope, records, portable_identity, effect_id);
        if let Some(code) = result.code.as_deref() {
            return contract_failure(code);
        }
        let matched = records
            .iter()
            .find(|record| {
                record.scope_id == scope.scope_id
                    && record.ownership_binding == scope.ownership_binding
                    && record.portable_identity == portable_identity
                    && record.effect_id == effect_id
            })
            .expect("validated scope has a matching record");
        contract_success(
            "scope_record",
            json!({
                "scope_id":matched.scope_id,
                "ownership_binding":matched.ownership_binding,
                "portable_identity":matched.portable_identity,
                "effect_id":matched.effect_id
            }),
        )
    }

    pub fn validate_backup_restore_contract(
        &self,
        source: &[u8],
        trusted_artifact_digests: &[String],
        checkpoint_digests: &[String],
        retention_mode: &str,
    ) -> DurableContractExecution {
        let result = self.validate_backup_restore(
            source,
            trusted_artifact_digests,
            checkpoint_digests,
            retention_mode,
        );
        match result.code.as_deref() {
            Some(code) => contract_failure(code),
            None => contract_success("host_acknowledgement", json!({"result":"validated"})),
        }
    }

    pub fn validate_capabilities_contract(
        &self,
        adapter_identifier: &str,
        profile: HostProfile,
        features: &BTreeSet<HostFeature>,
        configured_store_capabilities: &[String],
        configured_host_guarantees: &[String],
        permanent_replay_retention: bool,
    ) -> DurableContractExecution {
        let actual_store_capabilities = self
            .store
            .capabilities()
            .iter()
            .map(|capability| capability.as_str())
            .collect::<BTreeSet<_>>();
        let actual_host_guarantees = features
            .iter()
            .map(|feature| feature.as_str())
            .collect::<BTreeSet<_>>();
        if configured_store_capabilities
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            != actual_store_capabilities
            || configured_host_guarantees
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
                != actual_host_guarantees
        {
            return contract_failure("adapter_capability_mismatch");
        }
        match validate_store_host_profile(
            self.store.as_ref(),
            profile,
            features,
            permanent_replay_retention,
        ) {
            Ok(()) => contract_success(
                "capability_report",
                json!({
                    "adapter_identifier":adapter_identifier,
                    "host_profile":profile.as_str(),
                    "host_guarantees":configured_host_guarantees,
                    "retention_mode":if permanent_replay_retention {"permanent"} else {"bounded"},
                    "store_capabilities":configured_store_capabilities,
                    "validated":true
                }),
            ),
            Err(error) => contract_failure(error.code.as_str()),
        }
    }

    pub fn validate_scope_operation(
        &self,
        scope: &StoreScope,
        records: &[ScopedStoreRecord],
        portable_identity: &str,
        effect_id: &str,
    ) -> DurableHostResult {
        let matches = records
            .iter()
            .filter(|record| {
                record.scope_id == scope.scope_id
                    && record.ownership_binding == scope.ownership_binding
                    && record.portable_identity == portable_identity
                    && record.effect_id == effect_id
            })
            .count();
        if scope.authorized && matches == 1 {
            DurableHostResult::validated()
        } else {
            DurableHostResult::validation_rejected("invalid_store_scope")
        }
    }

    pub fn validate_backup_restore(
        &self,
        source: &[u8],
        trusted_artifact_digests: &[String],
        checkpoint_digests: &[String],
        retention_mode: &str,
    ) -> DurableHostResult {
        let valid =
            restore_execution_checkpoint(source, self.resolver.as_ref()).is_ok_and(|checkpoint| {
                let retained_definition_is_available = checkpoint.value()["root_record"]["status"]
                    != "retained"
                    || trusted_artifact_digests
                        .iter()
                        .any(|digest| Some(digest.as_str()) == checkpoint.bundle_fingerprint());
                retained_definition_is_available
                    && checkpoint_digests
                        .iter()
                        .any(|digest| digest == checkpoint.digest())
                    && checkpoint.value()["replay_retention"]["mode"] == retention_mode
            });
        if valid {
            DurableHostResult::validated()
        } else {
            DurableHostResult::validation_rejected("invalid_execution_checkpoint")
        }
    }

    pub fn execute_checkpoint_operation(
        &self,
        operation: DurableCheckpointOperation<'_>,
        acknowledge_after_commit: bool,
    ) -> DurableCheckpointExecution {
        let root_instance_id = operation.root_instance_id().to_string();
        let operation_kind = match &operation {
            DurableCheckpointOperation::Create { .. } => "creation",
            DurableCheckpointOperation::Admit { .. } => "admission",
            DurableCheckpointOperation::Step { .. } => "processing",
            DurableCheckpointOperation::Prune { .. } => "host_acknowledgement",
            DurableCheckpointOperation::Tombstone { .. } => "tombstoned",
            DurableCheckpointOperation::UpdatePendingOutbox { .. } => "pending_outbox",
            DurableCheckpointOperation::TerminalizeOutbox { .. } => "terminal_outbox",
            DurableCheckpointOperation::CompactOutbox { .. } => "host_acknowledgement",
            _ => "other",
        };
        let admission_ids = match &operation {
            DurableCheckpointOperation::Admit { sources, .. } => sources
                .iter()
                .filter_map(|source| match source {
                    AdmissionSource::JsonValue(value) => Some(value.clone()),
                    AdmissionSource::Utf8Json(bytes) => {
                        crate::format1::strict_json::parse(bytes).ok()
                    }
                })
                .filter_map(|value| {
                    value
                        .pointer("/envelope/event_id")
                        .and_then(JsonValue::as_str)
                        .map(str::to_string)
                })
                .collect::<Vec<_>>(),
            _ => Vec::new(),
        };
        let before = match self.store.load(&root_instance_id) {
            Ok(record) => record,
            Err(_) => {
                return DurableCheckpointExecution {
                    result: DurableHostResult::new(
                        "rejected",
                        "none",
                        0,
                        false,
                        Some("execution_store_failure"),
                    ),
                    operation_response: None,
                    caller_response: Some(
                        json!({"kind":"typed_failure","body":{"code":"execution_store_failure"}}),
                    ),
                };
            }
        };
        let core_operation = operation.is_core_operation();
        let creation_without_checkpoint =
            matches!(operation, DurableCheckpointOperation::Create { .. }) && before.is_none();
        let mut core_result = None;
        let result: Result<JsonValue, ArtifactError> = match operation {
            DurableCheckpointOperation::Create {
                bundle,
                machine_id,
                root_instance_id,
                creation_id,
                bindings,
                supplied_request_digest,
                replay_retention,
            } => self.create_checkpoint(
                bundle,
                machine_id,
                root_instance_id,
                creation_id,
                bindings,
                supplied_request_digest,
                replay_retention,
            ),
            DurableCheckpointOperation::Admit {
                root_instance_id,
                sources,
                guard,
            } => self.admit_checkpoint_sources(root_instance_id, sources, guard),
            DurableCheckpointOperation::Step {
                root_instance_id,
                request,
                guard,
            } => {
                let mut direct = DirectStoreAccess {
                    store: self.store.as_ref(),
                };
                self.step_checkpoint_with_core(&mut direct, root_instance_id, request, guard)
                    .map(|(checkpoint, core)| {
                        core_result = core;
                        checkpoint
                    })
            }
            DurableCheckpointOperation::UpdatePendingOutbox {
                root_instance_id,
                effect_id,
                desired,
                guard,
            } => self.update_pending_outbox(root_instance_id, effect_id, desired, guard),
            DurableCheckpointOperation::TerminalizeOutbox {
                root_instance_id,
                effect_id,
                outcome,
                guard,
            } => self.terminalize_outbox(root_instance_id, effect_id, outcome, guard),
            DurableCheckpointOperation::CompactOutbox {
                root_instance_id,
                effect_id,
                guard,
            } => self.compact_outbox(root_instance_id, effect_id, guard),
            DurableCheckpointOperation::Prune {
                root_instance_id,
                request,
                guard,
            } => self.prune_checkpoint(root_instance_id, request, guard),
            DurableCheckpointOperation::Tombstone {
                root_instance_id,
                operation_id,
                guard,
            } => self.tombstone_root(root_instance_id, operation_id, guard),
            DurableCheckpointOperation::DeleteRetainedRecord {
                root_instance_id,
                guard,
            } => self
                .delete_retained_record(root_instance_id, guard)
                .map(|()| JsonValue::Null),
        };
        let after = match self.store.load(&root_instance_id) {
            Ok(record) => record,
            Err(_) => {
                return DurableCheckpointExecution {
                    result: DurableHostResult::new(
                        "crashed",
                        "none",
                        u8::from(core_operation),
                        false,
                        Some("execution_store_failure"),
                    ),
                    operation_response: None,
                    caller_response: None,
                };
            }
        };
        let changed = before != after;
        let code = result.as_ref().err().map(|error| error.code.as_str());
        let crashed = matches!(
            code,
            Some("injected_pre_commit_failure" | "response_lost_after_commit")
        );
        let committed = result.is_ok() && changed;
        let replayed = result.is_ok() && !changed;
        let core_calls = u8::from(
            creation_without_checkpoint
                || (core_operation
                    && (committed
                        || matches!(code, Some("injected_pre_commit_failure"))
                        || matches!(code, Some("creation_rejected")))),
        );
        let caller_response = if crashed {
            None
        } else {
            match &result {
                Err(error) => Some(json!({"kind":"typed_failure","body":{"code":error.code}})),
                Ok(value) => caller_checkpoint_response(
                    operation_kind,
                    value,
                    core_result.as_ref(),
                    &admission_ids,
                    changed,
                ),
            }
        };
        DurableCheckpointExecution {
            result: DurableHostResult::new(
                if crashed {
                    "crashed"
                } else if committed {
                    "committed"
                } else if replayed {
                    "replayed"
                } else {
                    "rejected"
                },
                if changed { "atomic" } else { "none" },
                core_calls,
                acknowledge_after_commit
                    && (committed || (replayed && operation_kind != "processing")),
                code,
            ),
            operation_response: result.ok(),
            caller_response,
        }
    }

    #[cfg(feature = "sqlite")]
    pub fn execute_durable_process(
        &self,
        request: &DurableProcessRequest,
    ) -> Result<DurableHostExecution, ArtifactError> {
        let sqlite = self
            .store
            .as_any()
            .downcast_ref::<SqliteExecutionStore>()
            .ok_or_else(|| {
                v1_failure(
                    "invalid_store_scope",
                    "durable process requires the injected SQLite execution store",
                )
            })?;
        let mut calls = vec!["select_scope".to_string(), "resolve_artifacts".to_string()];
        self.resolve_durable_process_artifacts(request)?;
        calls.push("validate_capabilities".to_string());
        validate_store_host_profile(
            sqlite,
            request.profile,
            &request.host_features,
            request.permanent_retention,
        )
        .map_err(|error| ArtifactError::new(error.code.as_str(), error.message))?;

        if request.failure_policy == DurableFailurePolicy::PermanentQuarantine {
            let retained_result = sqlite
                .with_immediate_transaction(|transaction| {
                    let current = super::adapters::sqlite::load_record(
                        transaction,
                        &request.root_instance_id,
                    )?
                    .ok_or_else(|| StoreError::new("checkpoint is absent"))?;
                    let retained = transaction
                        .query_row(
                            "SELECT request_digest, disposition
                             FROM determa_durable_inbox
                             WHERE root_instance_id = ?1 AND event_id = ?2",
                            params![request.root_instance_id, request.event_id],
                            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                        )
                        .optional()
                        .map_err(sqlite_error)?;
                    let quarantine_released = transaction
                        .query_row(
                            "SELECT released FROM determa_durable_quarantine
                             WHERE root_instance_id = ?1 AND event_id = ?2",
                            params![request.root_instance_id, request.event_id],
                            |row| row.get::<_, bool>(0),
                        )
                        .optional()
                        .map_err(sqlite_error)?
                        .unwrap_or(false);
                    if let Some((digest, disposition)) = retained {
                        if disposition != "quarantined" || !quarantine_released {
                            return Ok(Some(if digest == request.envelope_digest {
                                DurableHostResult::new("replayed", "none", 0, true, None)
                            } else {
                                DurableHostResult::new(
                                    "rejected",
                                    "none",
                                    0,
                                    false,
                                    Some("event_id_conflict"),
                                )
                            }));
                        }
                    }
                    validate_durable_guard(&current, &request.guard)?;
                    transaction
                        .execute(
                            "INSERT OR REPLACE INTO determa_durable_inbox
                             (root_instance_id, event_id, request_digest, disposition)
                             VALUES (?1, ?2, ?3, 'quarantined')",
                            params![
                                request.root_instance_id,
                                request.event_id,
                                request.envelope_digest
                            ],
                        )
                        .map_err(sqlite_error)?;
                    transaction
                        .execute(
                            "INSERT OR REPLACE INTO determa_durable_quarantine
                             (root_instance_id, event_id, reason_code, released)
                             VALUES (?1, ?2, 'permanent_processing_failure', 0)",
                            params![request.root_instance_id, request.event_id],
                        )
                        .map_err(sqlite_error)?;
                    Ok(None)
                })
                .map_err(v1_store_error)?;
            if let Some(result) = retained_result {
                let caller_response = Some(
                    json!({"kind":"typed_failure","body":{"code":result.code.as_deref().unwrap_or("event_id_conflict")}}),
                );
                return Ok(DurableHostExecution {
                    result,
                    calls,
                    caller_response,
                });
            }
            calls.push("quarantine".to_string());
            return Ok(DurableHostExecution {
                result: DurableHostResult::new(
                    "quarantined",
                    "atomic",
                    0,
                    false,
                    Some("permanent_processing_failure"),
                ),
                calls,
                caller_response: Some(
                    json!({"kind":"quarantine","body":{"code":"permanent_processing_failure","record":{"event_id":request.event_id,"reason_code":"permanent_processing_failure","released":false}}}),
                ),
            });
        }

        calls.extend([
            "begin_transaction".to_string(),
            "read_checkpoint".to_string(),
            "check_replay".to_string(),
        ]);
        let mut execution = sqlite
            .with_controlled_transaction(|transaction| {
                let current =
                    super::adapters::sqlite::load_record(transaction, &request.root_instance_id)?
                        .ok_or_else(|| StoreError::new("checkpoint is absent"))?;
                let retained = transaction
                    .query_row(
                        "SELECT request_digest, disposition
                         FROM determa_durable_inbox
                         WHERE root_instance_id = ?1 AND event_id = ?2",
                        params![request.root_instance_id, request.event_id],
                        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                    )
                    .optional()
                    .map_err(sqlite_error)?;
                let quarantine_released = transaction
                    .query_row(
                        "SELECT released FROM determa_durable_quarantine
                         WHERE root_instance_id = ?1 AND event_id = ?2",
                        params![request.root_instance_id, request.event_id],
                        |row| row.get::<_, bool>(0),
                    )
                    .optional()
                    .map_err(sqlite_error)?
                    .unwrap_or(false);
                if let Some((digest, disposition)) = retained {
                    if disposition != "quarantined" || !quarantine_released {
                        let result = if digest == request.envelope_digest {
                            DurableHostResult::new("replayed", "none", 0, true, None)
                        } else {
                            DurableHostResult::new(
                                "rejected",
                                "none",
                                0,
                                false,
                                Some("event_id_conflict"),
                            )
                        };
                        return Ok((
                            DurableHostExecution {
                                caller_response: if result.result == "replayed" {
                                    let checkpoint: JsonValue = serde_json::from_slice(&current.bytes)
                                        .map_err(|error| StoreError::new(error.to_string()))?;
                                    let receipt = checkpoint["operation_receipts"]
                                        .as_array()
                                        .and_then(|receipts| receipts.iter().find(|receipt| receipt["operation_kind"] == "event_terminal" && receipt["event_id"] == request.event_id))
                                        .ok_or_else(|| StoreError::new("retained terminal receipt is absent"))?;
                                    Some(json!({"kind":"retained_receipt","body":receipt}))
                                } else {
                                    Some(json!({"kind":"typed_failure","body":{"code":"event_id_conflict"}}))
                                },
                                result,
                                calls: Vec::new(),
                            },
                            true,
                        ));
                    }
                }
                validate_durable_guard(&current, &request.guard)?;
                if request.failure_policy == DurableFailurePolicy::TransientRetry {
                    return Ok((
                        DurableHostExecution {
                            result: DurableHostResult::new(
                                "rejected",
                                "none",
                                0,
                                false,
                                Some("transient_processing_failure"),
                            ),
                            calls: Vec::new(),
                            caller_response: Some(json!({"kind":"typed_failure","body":{"code":"transient_processing_failure"}})),
                        },
                        false,
                    ));
                }

                let mut transactional_store = SqliteTransactionStore {
                    transaction,
                    mode: sqlite.mode(),
                    root_instance_id: &request.root_instance_id,
                };
                let process = TransactionalProcessRequest {
                    delivery: request.delivery.clone(),
                    processing_mode: request.processing_mode.clone(),
                    migration: request.migration.clone(),
                    migration_limits: request.migration_limits.clone(),
                };
                let result = self.transactional_process_with_core(
                    &mut transactional_store,
                    &request.root_instance_id,
                    &process,
                    &request.guard,
                );
                let (checkpoint, core) = match result {
                    Ok(checkpoint) => checkpoint,
                    Err(error) => {
                        return Ok((
                            DurableHostExecution {
                                result: DurableHostResult::new(
                                    "rejected",
                                    "none",
                                    1,
                                    false,
                                    Some(&error.code),
                                ),
                                calls: Vec::new(),
                                caller_response: Some(json!({"kind":"typed_failure","body":{"code":error.code}})),
                            },
                            false,
                        ));
                    }
                };
                transaction
                    .execute(
                        "INSERT OR REPLACE INTO determa_durable_inbox
                         (root_instance_id, event_id, request_digest, disposition)
                         VALUES (?1, ?2, ?3, 'committed')",
                        params![
                            request.root_instance_id,
                            request.event_id,
                            request.envelope_digest
                        ],
                    )
                    .map_err(sqlite_error)?;
                transaction
                    .execute(
                        "DELETE FROM determa_durable_quarantine WHERE root_instance_id = ?1",
                        params![request.root_instance_id],
                    )
                    .map_err(sqlite_error)?;
                for (key, value) in &request.application_writes {
                    let bytes = serde_json_canonicalizer::to_vec(value)
                        .map_err(|error| StoreError::new(error.to_string()))?;
                    let value = String::from_utf8(bytes)
                        .map_err(|error| StoreError::new(error.to_string()))?;
                    transaction
                        .execute(
                            "INSERT OR REPLACE INTO determa_durable_application_rows
                             (root_instance_id, row_key, row_value) VALUES (?1, ?2, ?3)",
                            params![request.root_instance_id, key, value],
                        )
                        .map_err(sqlite_error)?;
                }
                let post_commit_loss =
                    request.failure_policy == DurableFailurePolicy::InjectPostCommitResponseLoss;
                let receipt = checkpoint["operation_receipts"]
                    .as_array()
                    .and_then(|receipts| receipts.iter().rev().find(|receipt| receipt["operation_kind"] == "event_terminal" && receipt["event_id"] == request.event_id));
                let caller_response = if post_commit_loss || request.failure_policy == DurableFailurePolicy::InjectPreCommit {
                    None
                } else {
                    Some(json!({"kind":"persistence_commit","body":{
                        "core_result":core,
                        "receipt":receipt,
                        "migration_audit_records":checkpoint["migration_audit_records"]
                    }}))
                };
                Ok((
                    DurableHostExecution {
                        result: DurableHostResult::new(
                            if post_commit_loss {
                                "crashed"
                            } else {
                                "committed"
                            },
                            "atomic",
                            1,
                            !post_commit_loss,
                            post_commit_loss.then_some("response_lost_after_commit"),
                        ),
                        calls: Vec::new(),
                        caller_response,
                    },
                    request.failure_policy != DurableFailurePolicy::InjectPreCommit,
                ))
            })
            .map_err(v1_store_error)?;

        match execution.result.result.as_str() {
            "replayed" => calls.push("acknowledge".to_string()),
            "rejected"
                if execution.result.code.as_deref() == Some("transient_processing_failure") =>
            {
                calls.push("rollback".to_string());
            }
            "committed" | "crashed" => {
                calls.extend([
                    "call_core".to_string(),
                    "stage_checkpoint".to_string(),
                    "stage_inbox".to_string(),
                    "stage_outbox".to_string(),
                    "stage_audit".to_string(),
                ]);
                if request.failure_policy == DurableFailurePolicy::InjectPreCommit {
                    execution.result = DurableHostResult::new(
                        "crashed",
                        "none",
                        1,
                        false,
                        Some("injected_pre_commit_failure"),
                    );
                    calls.push("rollback".to_string());
                } else {
                    if !request.application_writes.is_empty() {
                        calls.push("stage_application_rows".to_string());
                    }
                    calls.push("commit".to_string());
                    if execution.result.broker_acknowledged {
                        calls.push("acknowledge".to_string());
                    }
                }
            }
            _ => {}
        }
        execution.calls = calls;
        Ok(execution)
    }

    #[cfg(feature = "sqlite")]
    pub fn release_durable_quarantine(
        &self,
        request: &DurableQuarantineReleaseRequest,
    ) -> Result<DurableHostExecution, ArtifactError> {
        let sqlite = self
            .store
            .as_any()
            .downcast_ref::<SqliteExecutionStore>()
            .ok_or_else(|| v1_failure("invalid_store_scope", "SQLite execution store required"))?;
        sqlite
            .with_immediate_transaction(|transaction| {
                let current =
                    super::adapters::sqlite::load_record(transaction, &request.root_instance_id)?
                        .ok_or_else(|| StoreError::new("checkpoint is absent"))?;
                validate_durable_guard(&current, &request.guard)?;
                let retained = transaction
                    .query_row(
                        "SELECT i.request_digest, q.reason_code, q.released
                         FROM determa_durable_inbox i
                         JOIN determa_durable_quarantine q
                           ON q.root_instance_id = i.root_instance_id
                          AND q.event_id = i.event_id
                         WHERE i.root_instance_id = ?1 AND i.event_id = ?2",
                        params![request.root_instance_id, request.event_id],
                        |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, bool>(2)?,
                            ))
                        },
                    )
                    .optional()
                    .map_err(sqlite_error)?;
                let Some((digest, reason, released)) = retained else {
                    return Err(StoreError::new("quarantine identity is absent"));
                };
                if digest != request.envelope_digest
                    || reason != request.reason_code
                    || request.release_authorization.is_empty()
                {
                    return Err(StoreError::new("quarantine release identity is invalid"));
                }
                if !released {
                    transaction
                        .execute(
                            "UPDATE determa_durable_quarantine SET released = 1
                             WHERE root_instance_id = ?1",
                            params![request.root_instance_id],
                        )
                        .map_err(sqlite_error)?;
                }
                Ok(())
            })
            .map_err(v1_store_error)?;
        Ok(DurableHostExecution {
            result: DurableHostResult::new("released", "atomic", 0, false, None),
            caller_response: Some(
                json!({"kind":"host_acknowledgement","body":{"result":"released"}}),
            ),
            calls: vec![
                "select_scope".to_string(),
                "resolve_artifacts".to_string(),
                "validate_capabilities".to_string(),
                "release_quarantine".to_string(),
            ],
        })
    }

    #[cfg(feature = "sqlite")]
    fn resolve_durable_process_artifacts(
        &self,
        request: &DurableProcessRequest,
    ) -> Result<(), ArtifactError> {
        let target = self
            .resolver
            .resolve_definition(&request.migration.target_validated_bundle_fingerprint)
            .ok_or_else(|| v1_failure("source_definition_unavailable", "target unavailable"))?;
        if !target.trusted
            || target.bundle.fingerprint != request.migration.target_validated_bundle_fingerprint
        {
            return Err(v1_failure(
                "definition_not_trusted",
                "target definition is not trusted",
            ));
        }
        for digest in &request.migration.migration_route {
            let descriptor = self
                .resolver
                .resolve_migration_descriptor(digest)
                .ok_or_else(|| {
                    v1_failure("migration_descriptor_not_found", "descriptor unavailable")
                })?;
            if !descriptor.trusted {
                return Err(v1_failure(
                    "migration_descriptor_untrusted",
                    "descriptor is not trusted",
                ));
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_checkpoint(
        &self,
        bundle: &Bundle,
        machine_id: &str,
        root_instance_id: &str,
        creation_id: &str,
        bindings: &Bindings,
        supplied_request_digest: Option<&str>,
        replay_retention: JsonValue,
    ) -> Result<JsonValue, ArtifactError> {
        let mut store = DirectStoreAccess {
            store: self.store.as_ref(),
        };
        self.create_checkpoint_with_store(
            &mut store,
            bundle,
            machine_id,
            root_instance_id,
            creation_id,
            bindings,
            supplied_request_digest,
            replay_retention,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn create_checkpoint_with_store(
        &self,
        store: &mut dyn StoreAccess,
        bundle: &Bundle,
        machine_id: &str,
        root_instance_id: &str,
        creation_id: &str,
        bindings: &Bindings,
        supplied_request_digest: Option<&str>,
        replay_retention: JsonValue,
    ) -> Result<JsonValue, ArtifactError> {
        let request_digest =
            creation_request_digest(bundle, machine_id, root_instance_id, creation_id, bindings)?;
        if let Some(current) = store.load(root_instance_id).map_err(v1_store_error)? {
            return self.replay_or_reject_creation(current, creation_id, &request_digest);
        }
        let candidate = create_execution_checkpoint_v1(
            bundle,
            machine_id,
            root_instance_id,
            creation_id,
            bindings,
            supplied_request_digest,
            replay_retention,
        )
        .map_err(|error| {
            if crate::format1::CreationRejectionCode::PORTABLE_CODES
                .iter()
                .any(|code| code.as_str() == error.code)
            {
                v1_failure("creation_rejected", &error.message)
            } else {
                error
            }
        })?;
        let record = StoreRecord::from_checkpoint(&candidate).map_err(v1_store_error)?;
        match store.insert_if_absent(record).map_err(v1_store_error)? {
            StoreWriteResult::Committed => creation_response(&candidate),
            StoreWriteResult::Conflict(Some(current)) => {
                self.replay_or_reject_creation(current, creation_id, &request_digest)
            }
            StoreWriteResult::Conflict(None) => Err(v1_failure(
                "checkpoint_revision_conflict",
                "checkpoint insertion conflicted",
            )),
        }
    }

    fn replay_or_reject_creation(
        &self,
        current: StoreRecord,
        creation_id: &str,
        request_digest: &str,
    ) -> Result<JsonValue, ArtifactError> {
        let current = self.restore_record_v1(current)?;
        let receipt = current.value()["operation_receipts"]
            .as_array()
            .and_then(|receipts| receipts.first())
            .ok_or_else(|| {
                v1_failure("invalid_execution_checkpoint", "creation receipt is absent")
            })?;
        if receipt["creation_id"].as_str() == Some(creation_id)
            && receipt["request_digest"].as_str() == Some(request_digest)
        {
            Ok(json!({"result": "committed", "receipt": receipt}))
        } else {
            Err(v1_failure(
                "creation_id_conflict",
                "root identity already has different creation evidence",
            ))
        }
    }

    pub fn admit_checkpoint(
        &self,
        root_instance_id: &str,
        deliveries: &[JsonValue],
        guard: &MutationGuard,
    ) -> Result<JsonValue, ArtifactError> {
        let mut store = DirectStoreAccess {
            store: self.store.as_ref(),
        };
        self.admit_checkpoint_with_store(&mut store, root_instance_id, deliveries, guard)
    }

    pub fn admit_checkpoint_sources(
        &self,
        root_instance_id: &str,
        sources: &[AdmissionSource],
        guard: &MutationGuard,
    ) -> Result<JsonValue, ArtifactError> {
        let deliveries = sources
            .iter()
            .map(|source| match source {
                AdmissionSource::JsonValue(value) => Ok(value.clone()),
                AdmissionSource::Utf8Json(source) => crate::format1::strict_json::parse(source)
                    .map_err(|error| ArtifactError::new("malformed_delivery", error.to_string())),
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.admit_checkpoint(root_instance_id, &deliveries, guard)
    }

    fn admit_checkpoint_with_store(
        &self,
        store: &mut dyn StoreAccess,
        root_instance_id: &str,
        deliveries: &[JsonValue],
        guard: &MutationGuard,
    ) -> Result<JsonValue, ArtifactError> {
        let (record, checkpoint) =
            self.require_checkpoint_v1_with_store(store, root_instance_id)?;
        let bundle = checkpoint
            .bundle_fingerprint()
            .map(|_| self.checkpoint_v1_bundle(&checkpoint))
            .transpose()?;
        let result = checkpoint_admit_v1_with_optional_bundle(
            bundle.as_ref(),
            &checkpoint,
            deliveries,
            Some(&guard.expected_revision),
            Some(&guard.expected_checkpoint_digest),
        )?;
        self.commit_v1_result_with_store(store, &record, &result)?;
        Ok(result)
    }

    pub fn step_checkpoint(
        &self,
        root_instance_id: &str,
        request: &ProcessingRequest,
        guard: &MutationGuard,
    ) -> Result<JsonValue, ArtifactError> {
        let mut store = DirectStoreAccess {
            store: self.store.as_ref(),
        };
        self.step_checkpoint_with_store(&mut store, root_instance_id, request, guard)
    }

    fn step_checkpoint_with_store(
        &self,
        store: &mut dyn StoreAccess,
        root_instance_id: &str,
        request: &ProcessingRequest,
        guard: &MutationGuard,
    ) -> Result<JsonValue, ArtifactError> {
        self.step_checkpoint_with_core(store, root_instance_id, request, guard)
            .map(|(checkpoint, _)| checkpoint)
    }

    fn step_checkpoint_with_core(
        &self,
        store: &mut dyn StoreAccess,
        root_instance_id: &str,
        request: &ProcessingRequest,
        guard: &MutationGuard,
    ) -> Result<(JsonValue, Option<JsonValue>), ArtifactError> {
        let (record, checkpoint) =
            self.require_checkpoint_v1_with_store(store, root_instance_id)?;
        if let Some(replay) = checkpoint_step_replay(&checkpoint, request)? {
            return Ok((replay, None));
        }
        let bundle = self.checkpoint_v1_bundle(&checkpoint)?;
        let (result, core) = checkpoint_step_v1_with_core(
            &bundle,
            &checkpoint,
            request,
            Some(&guard.expected_revision),
            Some(&guard.expected_checkpoint_digest),
        )?;
        self.commit_v1_result_with_store(store, &record, &result)?;
        Ok((result, core))
    }

    pub fn process_checkpoint(
        &self,
        root_instance_id: &str,
        delivery: &JsonValue,
        processing_mode: &str,
        guard: &MutationGuard,
    ) -> Result<JsonValue, ArtifactError> {
        let mut store = DirectStoreAccess {
            store: self.store.as_ref(),
        };
        self.process_checkpoint_with_store(
            &mut store,
            root_instance_id,
            delivery,
            processing_mode,
            guard,
        )
    }

    fn process_checkpoint_with_store(
        &self,
        store: &mut dyn StoreAccess,
        root_instance_id: &str,
        delivery: &JsonValue,
        processing_mode: &str,
        guard: &MutationGuard,
    ) -> Result<JsonValue, ArtifactError> {
        let (record, checkpoint) =
            self.require_checkpoint_v1_with_store(store, root_instance_id)?;
        if let Some(replay) = checkpoint_process_replay(&checkpoint, delivery, processing_mode)? {
            return Ok(replay);
        }
        let bundle = self.checkpoint_v1_bundle(&checkpoint)?;
        let result = checkpoint_process(
            &bundle,
            &checkpoint,
            delivery.clone(),
            processing_mode,
            Some(&guard.expected_revision),
            Some(&guard.expected_checkpoint_digest),
        )?;
        self.commit_v1_result_with_store(store, &record, &result)?;
        Ok(result)
    }

    pub fn transactional_process(
        &self,
        root_instance_id: &str,
        request: &TransactionalProcessRequest,
        guard: &MutationGuard,
    ) -> Result<JsonValue, ArtifactError> {
        let mut store = DirectStoreAccess {
            store: self.store.as_ref(),
        };
        self.transactional_process_with_store(&mut store, root_instance_id, request, guard)
    }

    fn transactional_process_with_store(
        &self,
        store: &mut dyn StoreAccess,
        root_instance_id: &str,
        request: &TransactionalProcessRequest,
        guard: &MutationGuard,
    ) -> Result<JsonValue, ArtifactError> {
        self.transactional_process_with_core(store, root_instance_id, request, guard)
            .map(|(checkpoint, _)| checkpoint)
    }

    fn transactional_process_with_core(
        &self,
        store: &mut dyn StoreAccess,
        root_instance_id: &str,
        request: &TransactionalProcessRequest,
        guard: &MutationGuard,
    ) -> Result<(JsonValue, Option<JsonValue>), ArtifactError> {
        let (record, checkpoint) =
            self.require_checkpoint_v1_with_store(store, root_instance_id)?;
        let (result, core) = checkpoint_process_with_migration_with_core(
            &checkpoint,
            &request.migration,
            self.resolver.as_ref(),
            &request.migration_limits,
            request.delivery.clone(),
            &request.processing_mode,
            Some(&guard.expected_revision),
            Some(&guard.expected_checkpoint_digest),
        )?;
        self.commit_v1_result_with_store(store, &record, &result)?;
        Ok((result, core))
    }

    pub fn prune_checkpoint(
        &self,
        root_instance_id: &str,
        request: &PruneRequest,
        guard: &MutationGuard,
    ) -> Result<JsonValue, ArtifactError> {
        let mut store = DirectStoreAccess {
            store: self.store.as_ref(),
        };
        self.prune_checkpoint_with_store(&mut store, root_instance_id, request, guard)
    }

    fn prune_checkpoint_with_store(
        &self,
        store: &mut dyn StoreAccess,
        root_instance_id: &str,
        request: &PruneRequest,
        guard: &MutationGuard,
    ) -> Result<JsonValue, ArtifactError> {
        let (record, checkpoint) =
            self.require_checkpoint_v1_with_store(store, root_instance_id)?;
        let result = checkpoint_prune_v1(
            &checkpoint,
            request,
            Some(&guard.expected_revision),
            Some(&guard.expected_checkpoint_digest),
        )?;
        self.commit_v1_result_with_store(store, &record, &result)?;
        Ok(result)
    }

    pub fn delete_retained_record(
        &self,
        root_instance_id: &str,
        guard: &MutationGuard,
    ) -> Result<(), ArtifactError> {
        let mut store = DirectStoreAccess {
            store: self.store.as_ref(),
        };
        let (_, checkpoint) =
            self.require_checkpoint_v1_with_store(&mut store, root_instance_id)?;
        crate::checkpoint::v1::validate_mutation_guard(
            &checkpoint,
            &guard.expected_revision,
            &guard.expected_checkpoint_digest,
        )?;
        Err(v1_failure(
            "invalid_execution_checkpoint",
            "physical deletion of retained checkpoint evidence is unsupported",
        ))
    }

    pub fn maintenance_migration(
        &self,
        request: &MaintenanceMigrationRequest,
    ) -> Result<JsonValue, ArtifactError> {
        let mut store = DirectStoreAccess {
            store: self.store.as_ref(),
        };
        self.maintenance_migration_with_store(&mut store, request)
    }

    fn maintenance_migration_with_store(
        &self,
        store: &mut dyn StoreAccess,
        request: &MaintenanceMigrationRequest,
    ) -> Result<JsonValue, ArtifactError> {
        if request.operation_id.is_empty() {
            return Err(v1_failure(
                "invalid_execution_checkpoint",
                "v1 maintenance migration requires an operation id",
            ));
        }
        let request_digest = maintenance_request_digest(&request.root_instance_id, request)
            .map_err(|error| ArtifactError::new(error.code.as_str(), error.message))?;
        if request
            .supplied_request_digest
            .as_ref()
            .is_some_and(|supplied| supplied != &request_digest)
        {
            return Err(v1_failure(
                "invalid_execution_checkpoint",
                "supplied maintenance request digest does not match",
            ));
        }
        let (record, checkpoint) =
            self.require_checkpoint_v1_with_store(store, &request.root_instance_id)?;
        if let Some(existing) = checkpoint.value()["operation_receipts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|receipt| {
                receipt["operation_kind"] == "maintenance_migration"
                    && receipt["operation_id"].as_str() == Some(request.operation_id.as_str())
            })
        {
            if existing["request_digest"].as_str() == Some(request_digest.as_str()) {
                return Ok(json!({"result": "committed", "receipt": existing}));
            }
            return Err(v1_failure(
                "operation_id_conflict",
                "maintenance operation id has different content",
            ));
        }
        if checkpoint.revision() != request.guard.expected_revision
            || checkpoint.digest() != request.guard.expected_checkpoint_digest
        {
            return Err(v1_failure(
                "checkpoint_revision_conflict",
                "checkpoint compare-and-swap guard does not match",
            ));
        }
        if checkpoint.value()["root_record"]["status"] == "tombstone" {
            return Err(v1_failure(
                "tombstoned_root",
                "tombstoned root cannot be migrated",
            ));
        }
        if checkpoint.value()["root_record"]["aggregate_state"]["aggregate_state_digest"].as_str()
            != Some(request.source_aggregate_state_digest.as_str())
        {
            return Err(v1_failure(
                "invalid_execution_checkpoint",
                "maintenance source digest differs from checkpoint aggregate",
            ));
        }
        let result = checkpoint_maintenance_migration_route(
            &checkpoint,
            &MigrationRequest {
                migration_route: request.migration_descriptor_digest_route.clone(),
                target_validated_bundle_fingerprint: request
                    .target_validated_bundle_fingerprint
                    .clone(),
                maintenance_mode: request.maintenance_mode,
            },
            &request.operation_id,
            &request_digest,
            self.resolver.as_ref(),
            &request.limits,
            None,
            None,
        )?;
        self.commit_v1_result_with_store(store, &record, &result)?;
        let receipt = result["operation_receipts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|receipt| {
                receipt["operation_kind"] == "maintenance_migration"
                    && receipt["operation_id"].as_str() == Some(request.operation_id.as_str())
            })
            .ok_or_else(|| {
                v1_failure(
                    "invalid_execution_checkpoint",
                    "committed maintenance receipt is absent",
                )
            })?;
        Ok(json!({"result": "committed", "receipt": receipt}))
    }

    pub fn update_pending_outbox(
        &self,
        root_instance_id: &str,
        effect_id: &str,
        desired: PendingOutboxState,
        guard: &MutationGuard,
    ) -> Result<JsonValue, ArtifactError> {
        let mut store = DirectStoreAccess {
            store: self.store.as_ref(),
        };
        self.update_pending_outbox_with_store(
            &mut store,
            root_instance_id,
            effect_id,
            desired,
            guard,
        )
    }

    fn update_pending_outbox_with_store(
        &self,
        store: &mut dyn StoreAccess,
        root_instance_id: &str,
        effect_id: &str,
        desired: PendingOutboxState,
        guard: &MutationGuard,
    ) -> Result<JsonValue, ArtifactError> {
        let (record, checkpoint) =
            self.require_checkpoint_v1_with_store(store, root_instance_id)?;
        let result = checkpoint_update_pending_outbox(
            &checkpoint,
            effect_id,
            desired,
            Some(&guard.expected_revision),
            Some(&guard.expected_checkpoint_digest),
        )?;
        self.commit_v1_result_with_store(store, &record, &result)?;
        let committed = result["pending_outbox_intents"]
            .as_array()
            .and_then(|records| {
                records
                    .iter()
                    .find(|item| item["intent"]["effect_id"].as_str() == Some(effect_id))
            })
            .ok_or_else(|| {
                v1_failure(
                    "invalid_execution_checkpoint",
                    "committed pending outbox record is absent",
                )
            })?;
        Ok(json!({"result": "committed", "record": committed}))
    }

    pub fn terminalize_outbox(
        &self,
        root_instance_id: &str,
        effect_id: &str,
        outcome: TerminalOutboxOutcome,
        guard: &MutationGuard,
    ) -> Result<JsonValue, ArtifactError> {
        let mut store = DirectStoreAccess {
            store: self.store.as_ref(),
        };
        self.terminalize_outbox_with_store(&mut store, root_instance_id, effect_id, outcome, guard)
    }

    fn terminalize_outbox_with_store(
        &self,
        store: &mut dyn StoreAccess,
        root_instance_id: &str,
        effect_id: &str,
        outcome: TerminalOutboxOutcome,
        guard: &MutationGuard,
    ) -> Result<JsonValue, ArtifactError> {
        let (record, checkpoint) =
            self.require_checkpoint_v1_with_store(store, root_instance_id)?;
        let result = checkpoint_terminalize_outbox(
            &checkpoint,
            effect_id,
            outcome,
            Some(&guard.expected_revision),
            Some(&guard.expected_checkpoint_digest),
        )?;
        self.commit_v1_result_with_store(store, &record, &result)?;
        let committed = result["terminal_outbox_records"]
            .as_array()
            .and_then(|records| {
                records
                    .iter()
                    .find(|item| item["intent"]["effect_id"].as_str() == Some(effect_id))
            })
            .or_else(|| {
                result["outbox_effect_tombstones"]
                    .as_array()
                    .and_then(|records| {
                        records
                            .iter()
                            .find(|item| item["effect_id"].as_str() == Some(effect_id))
                    })
            })
            .ok_or_else(|| {
                v1_failure(
                    "invalid_execution_checkpoint",
                    "committed terminal outbox record is absent",
                )
            })?;
        Ok(json!({"result": "committed", "record": committed}))
    }

    pub fn compact_outbox(
        &self,
        root_instance_id: &str,
        effect_id: &str,
        guard: &MutationGuard,
    ) -> Result<JsonValue, ArtifactError> {
        let mut store = DirectStoreAccess {
            store: self.store.as_ref(),
        };
        self.compact_outbox_with_store(&mut store, root_instance_id, effect_id, guard)
    }

    fn compact_outbox_with_store(
        &self,
        store: &mut dyn StoreAccess,
        root_instance_id: &str,
        effect_id: &str,
        guard: &MutationGuard,
    ) -> Result<JsonValue, ArtifactError> {
        let (record, checkpoint) =
            self.require_checkpoint_v1_with_store(store, root_instance_id)?;
        let result = checkpoint_compact_outbox(
            &checkpoint,
            effect_id,
            Some(&guard.expected_revision),
            Some(&guard.expected_checkpoint_digest),
        )?;
        self.commit_v1_result_with_store(store, &record, &result)?;
        let committed = result["outbox_effect_tombstones"]
            .as_array()
            .and_then(|records| {
                records
                    .iter()
                    .find(|item| item["effect_id"].as_str() == Some(effect_id))
            })
            .ok_or_else(|| {
                v1_failure(
                    "invalid_execution_checkpoint",
                    "committed compact outbox record is absent",
                )
            })?;
        Ok(json!({"result": "committed", "record": committed}))
    }

    pub fn tombstone_root(
        &self,
        root_instance_id: &str,
        operation_id: &str,
        guard: &MutationGuard,
    ) -> Result<JsonValue, ArtifactError> {
        let mut store = DirectStoreAccess {
            store: self.store.as_ref(),
        };
        self.tombstone_root_with_store(&mut store, root_instance_id, operation_id, guard)
    }

    fn tombstone_root_with_store(
        &self,
        store: &mut dyn StoreAccess,
        root_instance_id: &str,
        operation_id: &str,
        guard: &MutationGuard,
    ) -> Result<JsonValue, ArtifactError> {
        let (record, checkpoint) =
            self.require_checkpoint_v1_with_store(store, root_instance_id)?;
        let result = checkpoint_tombstone_root(
            &checkpoint,
            operation_id,
            Some(&guard.expected_revision),
            Some(&guard.expected_checkpoint_digest),
        )?;
        self.commit_v1_result_with_store(store, &record, &result)?;
        Ok(json!({
            "result": "tombstoned",
            "tombstone": result["root_record"]
        }))
    }

    fn restore_record_v1(&self, record: StoreRecord) -> Result<ExecutionCheckpoint, ArtifactError> {
        let checkpoint = restore_execution_checkpoint(&record.bytes, self.resolver.as_ref())?;
        if checkpoint.root_instance_id() != record.root_instance_id
            || checkpoint.revision() != record.revision
            || checkpoint.digest() != record.execution_checkpoint_digest
        {
            return Err(v1_failure(
                "invalid_execution_checkpoint",
                "store metadata differs from checkpoint artifact",
            ));
        }
        Ok(checkpoint)
    }

    fn require_checkpoint_v1_with_store(
        &self,
        store: &mut dyn StoreAccess,
        root_instance_id: &str,
    ) -> Result<(StoreRecord, ExecutionCheckpoint), ArtifactError> {
        let record = store
            .load(root_instance_id)
            .map_err(v1_store_error)?
            .ok_or_else(|| {
                v1_failure(
                    "checkpoint_not_found",
                    "execution checkpoint does not exist",
                )
            })?;
        let checkpoint = self.restore_record_v1(record.clone())?;
        Ok((record, checkpoint))
    }

    fn checkpoint_v1_bundle(
        &self,
        checkpoint: &ExecutionCheckpoint,
    ) -> Result<Bundle, ArtifactError> {
        let fingerprint = checkpoint.bundle_fingerprint().ok_or_else(|| {
            v1_failure(
                "terminal_root",
                "terminal checkpoint has no runnable aggregate",
            )
        })?;
        let resolved = self
            .resolver
            .resolve_definition(fingerprint)
            .ok_or_else(|| {
                v1_failure("definition_not_found", "current definition is unavailable")
            })?;
        if !resolved.trusted || resolved.bundle.fingerprint != fingerprint {
            return Err(v1_failure(
                "definition_not_trusted",
                "current definition is not trusted or content-addressed correctly",
            ));
        }
        Ok(resolved.bundle)
    }

    fn commit_v1_result_with_store(
        &self,
        store: &mut dyn StoreAccess,
        current: &StoreRecord,
        result: &JsonValue,
    ) -> Result<(), ArtifactError> {
        let candidate = if result["execution_checkpoint_format"] == "determa.execution_checkpoint" {
            Some(result)
        } else if result["result"] == "batch"
            && result["checkpoint"]["execution_checkpoint_format"] == "determa.execution_checkpoint"
        {
            Some(&result["checkpoint"])
        } else {
            None
        };
        let Some(candidate) = candidate else {
            return Ok(());
        };
        let bytes = crate::format1::v1::canonical_bytes(candidate)?;
        let checkpoint = restore_execution_checkpoint(&bytes, self.resolver.as_ref())?;
        if checkpoint.revision() == current.revision
            && checkpoint.digest() == current.execution_checkpoint_digest
        {
            return Ok(());
        }
        let replacement = StoreRecord::from_checkpoint(&checkpoint).map_err(v1_store_error)?;
        self.commit_record_v1_with_store(store, current, replacement)
    }

    fn commit_record_v1_with_store(
        &self,
        store: &mut dyn StoreAccess,
        current: &StoreRecord,
        replacement: StoreRecord,
    ) -> Result<(), ArtifactError> {
        match store
            .compare_and_swap(
                &current.root_instance_id,
                &current.revision,
                &current.execution_checkpoint_digest,
                replacement,
            )
            .map_err(v1_store_error)?
        {
            StoreWriteResult::Committed => Ok(()),
            StoreWriteResult::Conflict(_) => Err(v1_failure(
                "checkpoint_revision_conflict",
                "checkpoint compare-and-swap conflicted",
            )),
        }
    }
}

fn maintenance_request_digest(
    root_instance_id: &str,
    request: &MaintenanceMigrationRequest,
) -> Result<String, ArtifactError> {
    crate::format1::native::jcs_hash(&json!([
        "determa-maintenance-migration-request-digest-1",
        "1",
        root_instance_id,
        request.operation_id,
        request.source_aggregate_state_digest,
        request.target_validated_bundle_fingerprint,
        request.migration_descriptor_digest_route,
        request.maintenance_mode
    ]))
    .map_err(|error| v1_failure("invalid_execution_checkpoint", &error.to_string()))
}

fn creation_response(checkpoint: &ExecutionCheckpoint) -> Result<JsonValue, ArtifactError> {
    let receipt = checkpoint.value()["operation_receipts"]
        .as_array()
        .and_then(|receipts| receipts.first())
        .filter(|receipt| receipt["operation_kind"] == "creation")
        .ok_or_else(|| {
            v1_failure(
                "invalid_execution_checkpoint",
                "committed creation receipt is absent",
            )
        })?;
    Ok(json!({"result": "committed", "receipt": receipt}))
}

fn v1_store_error(error: StoreError) -> ArtifactError {
    ArtifactError::new(error.code.as_str(), error.message)
}

#[cfg(feature = "sqlite")]
fn validate_durable_guard(record: &StoreRecord, guard: &MutationGuard) -> Result<(), StoreError> {
    if record.revision == guard.expected_revision
        && record.execution_checkpoint_digest == guard.expected_checkpoint_digest
    {
        Ok(())
    } else {
        Err(StoreError::new("checkpoint compare-and-swap guard differs"))
    }
}

#[cfg(feature = "sqlite")]
fn sqlite_error(error: rusqlite::Error) -> StoreError {
    StoreError::new(error.to_string())
}

#[cfg(feature = "postgresql")]
fn v1_host_failure(error: ArtifactError) -> HostFailure {
    HostFailure::new(
        HostFailureCode::InvalidExecutionCheckpoint,
        format!("{}: {}", error.code, error.message),
    )
}

fn v1_failure(code: &str, message: &str) -> ArtifactError {
    ArtifactError::new(code, message)
}
