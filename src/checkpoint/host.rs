#[cfg(feature = "postgresql")]
use super::adapters::PostgresqlExecutionStore;
#[cfg(feature = "postgresql")]
use super::store::DurableStoreMode;
use super::store::{
    validate_store_host_profile, AdapterError, ExecutionStore, HostFeature, HostProfile,
    StoreError, StoreErrorCode, StoreRecord, StoreWriteResult,
};
use super::types::{PendingOutboxState, TerminalOutboxOutcome};
use super::v2::{
    checkpoint_admit_v2_with_optional_bundle, checkpoint_compact_outbox_v2,
    checkpoint_maintenance_migration_v2_route, checkpoint_prune_v2, checkpoint_step_v2,
    checkpoint_terminalize_outbox_v2, checkpoint_tombstone_root_v2,
    checkpoint_update_pending_outbox_v2, create_execution_checkpoint_v2,
    creation_request_digest_v2, restore_execution_checkpoint_v2, ExecutionCheckpointV2,
};
use crate::format1::{
    Bindings, Bundle, MigrationArtifactResolver, MigrationRequest, ResourceLimits, Version2Error,
};
use serde_json::{json, Value as JsonValue};
use std::sync::Arc;

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
        target_runtime_id: &'a str,
        guard: &'a MutationGuard,
    },
    Prune {
        root_instance_id: &'a str,
        cutoff_receipt_sequence: &'a str,
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
    Creation(Box<ExecutionCheckpointV2>),
    Admission(JsonValue),
    Step(JsonValue),
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
            } => PostgresqlHostMutationResult::Creation(Box::new(
                self.create_checkpoint_v2_with_store(
                    &mut store,
                    bundle,
                    machine_id,
                    root_instance_id,
                    creation_id,
                    bindings,
                    supplied_request_digest,
                    replay_retention.clone(),
                )
                .map_err(v2_host_failure)?,
            )),
            PostgresqlHostMutation::Admit {
                root_instance_id,
                deliveries,
                guard,
            } => PostgresqlHostMutationResult::Admission(
                self.admit_checkpoint_v2_with_store(
                    &mut store,
                    root_instance_id,
                    deliveries,
                    guard,
                )
                .map_err(v2_host_failure)?,
            ),
            PostgresqlHostMutation::Step {
                root_instance_id,
                target_runtime_id,
                guard,
            } => PostgresqlHostMutationResult::Step(
                self.step_checkpoint_v2_with_store(
                    &mut store,
                    root_instance_id,
                    target_runtime_id,
                    guard,
                )
                .map_err(v2_host_failure)?,
            ),
            PostgresqlHostMutation::Prune {
                root_instance_id,
                cutoff_receipt_sequence,
                guard,
            } => PostgresqlHostMutationResult::Prune(
                self.prune_checkpoint_v2_with_store(
                    &mut store,
                    root_instance_id,
                    cutoff_receipt_sequence,
                    guard,
                )
                .map_err(v2_host_failure)?,
            ),
            PostgresqlHostMutation::MaintenanceMigration(request) => {
                PostgresqlHostMutationResult::MaintenanceMigration(
                    self.maintenance_migration_v2_with_store(&mut store, request)
                        .map_err(v2_host_failure)?,
                )
            }
            PostgresqlHostMutation::UpdatePendingOutbox {
                root_instance_id,
                effect_id,
                desired,
                guard,
            } => PostgresqlHostMutationResult::PendingOutbox(
                self.update_pending_outbox_v2_with_store(
                    &mut store,
                    root_instance_id,
                    effect_id,
                    desired,
                    guard,
                )
                .map_err(v2_host_failure)?,
            ),
            PostgresqlHostMutation::TerminalizeOutbox {
                root_instance_id,
                effect_id,
                outcome,
                guard,
            } => PostgresqlHostMutationResult::Outbox(
                self.terminalize_outbox_v2_with_store(
                    &mut store,
                    root_instance_id,
                    effect_id,
                    outcome,
                    guard,
                )
                .map_err(v2_host_failure)?,
            ),
            PostgresqlHostMutation::CompactOutbox {
                root_instance_id,
                effect_id,
                guard,
            } => PostgresqlHostMutationResult::CompactedOutbox(
                self.compact_outbox_v2_with_store(&mut store, root_instance_id, effect_id, guard)
                    .map_err(v2_host_failure)?,
            ),
            PostgresqlHostMutation::TombstoneRoot {
                root_instance_id,
                operation_id,
                guard,
            } => PostgresqlHostMutationResult::RootTombstone(
                self.tombstone_root_v2_with_store(
                    &mut store,
                    root_instance_id,
                    operation_id,
                    guard,
                )
                .map_err(v2_host_failure)?,
            ),
        };
        transaction.staged_result = Some(result);
        Ok(())
    }

    #[cfg(feature = "postgresql")]
    fn store_identity(&self) -> usize {
        Arc::as_ptr(&self.store) as *const () as usize
    }

    pub fn load_checkpoint_v2(
        &self,
        root_instance_id: &str,
    ) -> Result<Option<ExecutionCheckpointV2>, Version2Error> {
        self.store
            .load(root_instance_id)
            .map_err(v2_store_error)?
            .map(|record| self.restore_record_v2(record))
            .transpose()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_checkpoint_v2(
        &self,
        bundle: &Bundle,
        machine_id: &str,
        root_instance_id: &str,
        creation_id: &str,
        bindings: &Bindings,
        supplied_request_digest: Option<&str>,
        replay_retention: JsonValue,
    ) -> Result<ExecutionCheckpointV2, Version2Error> {
        let mut store = DirectStoreAccess {
            store: self.store.as_ref(),
        };
        self.create_checkpoint_v2_with_store(
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
    fn create_checkpoint_v2_with_store(
        &self,
        store: &mut dyn StoreAccess,
        bundle: &Bundle,
        machine_id: &str,
        root_instance_id: &str,
        creation_id: &str,
        bindings: &Bindings,
        supplied_request_digest: Option<&str>,
        replay_retention: JsonValue,
    ) -> Result<ExecutionCheckpointV2, Version2Error> {
        let request_digest = creation_request_digest_v2(
            bundle,
            machine_id,
            root_instance_id,
            creation_id,
            bindings,
        )?;
        let candidate = create_execution_checkpoint_v2(
            bundle,
            machine_id,
            root_instance_id,
            creation_id,
            bindings,
            supplied_request_digest,
            replay_retention,
        )?;
        let record = StoreRecord::from_checkpoint_v2(&candidate).map_err(v2_store_error)?;
        match store.insert_if_absent(record).map_err(v2_store_error)? {
            StoreWriteResult::Committed => Ok(candidate),
            StoreWriteResult::Conflict(Some(current)) => {
                let current = self.restore_record_v2(current)?;
                let receipt = current.value()["operation_receipts"]
                    .as_array()
                    .and_then(|receipts| receipts.first())
                    .ok_or_else(|| {
                        v2_failure("invalid_execution_checkpoint", "creation receipt is absent")
                    })?;
                if receipt["creation_id"].as_str() == Some(creation_id)
                    && receipt["request_digest"].as_str() == Some(request_digest.as_str())
                {
                    Ok(current)
                } else {
                    Err(v2_failure(
                        "creation_id_conflict",
                        "root identity already has different creation evidence",
                    ))
                }
            }
            StoreWriteResult::Conflict(None) => Err(v2_failure(
                "checkpoint_revision_conflict",
                "checkpoint insertion conflicted",
            )),
        }
    }

    pub fn admit_checkpoint_v2(
        &self,
        root_instance_id: &str,
        deliveries: &[JsonValue],
        guard: &MutationGuard,
    ) -> Result<JsonValue, Version2Error> {
        let mut store = DirectStoreAccess {
            store: self.store.as_ref(),
        };
        self.admit_checkpoint_v2_with_store(&mut store, root_instance_id, deliveries, guard)
    }

    fn admit_checkpoint_v2_with_store(
        &self,
        store: &mut dyn StoreAccess,
        root_instance_id: &str,
        deliveries: &[JsonValue],
        guard: &MutationGuard,
    ) -> Result<JsonValue, Version2Error> {
        let (record, checkpoint) =
            self.require_checkpoint_v2_with_store(store, root_instance_id)?;
        let bundle = checkpoint
            .bundle_fingerprint()
            .map(|_| self.checkpoint_v2_bundle(&checkpoint))
            .transpose()?;
        let result = checkpoint_admit_v2_with_optional_bundle(
            bundle.as_ref(),
            &checkpoint,
            deliveries,
            Some(&guard.expected_revision),
            Some(&guard.expected_checkpoint_digest),
        )?;
        self.commit_v2_result_with_store(store, &record, &result)?;
        Ok(result)
    }

    pub fn step_checkpoint_v2(
        &self,
        root_instance_id: &str,
        target_runtime_id: &str,
        guard: &MutationGuard,
    ) -> Result<JsonValue, Version2Error> {
        let mut store = DirectStoreAccess {
            store: self.store.as_ref(),
        };
        self.step_checkpoint_v2_with_store(&mut store, root_instance_id, target_runtime_id, guard)
    }

    fn step_checkpoint_v2_with_store(
        &self,
        store: &mut dyn StoreAccess,
        root_instance_id: &str,
        target_runtime_id: &str,
        guard: &MutationGuard,
    ) -> Result<JsonValue, Version2Error> {
        let (record, checkpoint) =
            self.require_checkpoint_v2_with_store(store, root_instance_id)?;
        let bundle = self.checkpoint_v2_bundle(&checkpoint)?;
        let result = checkpoint_step_v2(
            &bundle,
            &checkpoint,
            target_runtime_id,
            Some(&guard.expected_revision),
            Some(&guard.expected_checkpoint_digest),
        )?;
        self.commit_v2_result_with_store(store, &record, &result)?;
        Ok(result)
    }

    pub fn prune_checkpoint_v2(
        &self,
        root_instance_id: &str,
        cutoff_receipt_sequence: &str,
        guard: &MutationGuard,
    ) -> Result<JsonValue, Version2Error> {
        let mut store = DirectStoreAccess {
            store: self.store.as_ref(),
        };
        self.prune_checkpoint_v2_with_store(
            &mut store,
            root_instance_id,
            cutoff_receipt_sequence,
            guard,
        )
    }

    fn prune_checkpoint_v2_with_store(
        &self,
        store: &mut dyn StoreAccess,
        root_instance_id: &str,
        cutoff_receipt_sequence: &str,
        guard: &MutationGuard,
    ) -> Result<JsonValue, Version2Error> {
        let (record, checkpoint) =
            self.require_checkpoint_v2_with_store(store, root_instance_id)?;
        let result = checkpoint_prune_v2(
            &checkpoint,
            cutoff_receipt_sequence,
            Some(&guard.expected_revision),
            Some(&guard.expected_checkpoint_digest),
        )?;
        self.commit_v2_result_with_store(store, &record, &result)?;
        Ok(result)
    }

    pub fn maintenance_migration_v2(
        &self,
        request: &MaintenanceMigrationRequest,
    ) -> Result<JsonValue, Version2Error> {
        let mut store = DirectStoreAccess {
            store: self.store.as_ref(),
        };
        self.maintenance_migration_v2_with_store(&mut store, request)
    }

    fn maintenance_migration_v2_with_store(
        &self,
        store: &mut dyn StoreAccess,
        request: &MaintenanceMigrationRequest,
    ) -> Result<JsonValue, Version2Error> {
        if request.operation_id.is_empty() {
            return Err(v2_failure(
                "invalid_execution_checkpoint",
                "v2 maintenance migration requires an operation id",
            ));
        }
        let request_digest = maintenance_request_digest(&request.root_instance_id, request)
            .map_err(|error| Version2Error::new(error.code.as_str(), error.message))?;
        if request
            .supplied_request_digest
            .as_ref()
            .is_some_and(|supplied| supplied != &request_digest)
        {
            return Err(v2_failure(
                "invalid_execution_checkpoint",
                "supplied maintenance request digest does not match",
            ));
        }
        let (record, checkpoint) =
            self.require_checkpoint_v2_with_store(store, &request.root_instance_id)?;
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
            return Err(v2_failure(
                "operation_id_conflict",
                "maintenance operation id has different content",
            ));
        }
        if checkpoint.revision() != request.guard.expected_revision
            || checkpoint.digest() != request.guard.expected_checkpoint_digest
        {
            return Err(v2_failure(
                "checkpoint_revision_conflict",
                "checkpoint compare-and-swap guard does not match",
            ));
        }
        if checkpoint.value()["root_record"]["status"] == "tombstone" {
            return Err(v2_failure(
                "tombstoned_root",
                "tombstoned root cannot be migrated",
            ));
        }
        if checkpoint.value()["root_record"]["aggregate_state"]["aggregate_state_digest"].as_str()
            != Some(request.source_aggregate_state_digest.as_str())
        {
            return Err(v2_failure(
                "invalid_execution_checkpoint",
                "maintenance source digest differs from checkpoint aggregate",
            ));
        }
        let result = checkpoint_maintenance_migration_v2_route(
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
        self.commit_v2_result_with_store(store, &record, &result)?;
        let receipt = result["operation_receipts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|receipt| {
                receipt["operation_kind"] == "maintenance_migration"
                    && receipt["operation_id"].as_str() == Some(request.operation_id.as_str())
            })
            .ok_or_else(|| {
                v2_failure(
                    "invalid_execution_checkpoint",
                    "committed maintenance receipt is absent",
                )
            })?;
        Ok(json!({"result": "committed", "receipt": receipt}))
    }

    pub fn update_pending_outbox_v2(
        &self,
        root_instance_id: &str,
        effect_id: &str,
        desired: PendingOutboxState,
        guard: &MutationGuard,
    ) -> Result<JsonValue, Version2Error> {
        let mut store = DirectStoreAccess {
            store: self.store.as_ref(),
        };
        self.update_pending_outbox_v2_with_store(
            &mut store,
            root_instance_id,
            effect_id,
            desired,
            guard,
        )
    }

    fn update_pending_outbox_v2_with_store(
        &self,
        store: &mut dyn StoreAccess,
        root_instance_id: &str,
        effect_id: &str,
        desired: PendingOutboxState,
        guard: &MutationGuard,
    ) -> Result<JsonValue, Version2Error> {
        let (record, checkpoint) =
            self.require_checkpoint_v2_with_store(store, root_instance_id)?;
        let result = checkpoint_update_pending_outbox_v2(
            &checkpoint,
            effect_id,
            desired,
            Some(&guard.expected_revision),
            Some(&guard.expected_checkpoint_digest),
        )?;
        self.commit_v2_result_with_store(store, &record, &result)?;
        Ok(result)
    }

    pub fn terminalize_outbox_v2(
        &self,
        root_instance_id: &str,
        effect_id: &str,
        outcome: TerminalOutboxOutcome,
        guard: &MutationGuard,
    ) -> Result<JsonValue, Version2Error> {
        let mut store = DirectStoreAccess {
            store: self.store.as_ref(),
        };
        self.terminalize_outbox_v2_with_store(
            &mut store,
            root_instance_id,
            effect_id,
            outcome,
            guard,
        )
    }

    fn terminalize_outbox_v2_with_store(
        &self,
        store: &mut dyn StoreAccess,
        root_instance_id: &str,
        effect_id: &str,
        outcome: TerminalOutboxOutcome,
        guard: &MutationGuard,
    ) -> Result<JsonValue, Version2Error> {
        let (record, checkpoint) =
            self.require_checkpoint_v2_with_store(store, root_instance_id)?;
        let result = checkpoint_terminalize_outbox_v2(
            &checkpoint,
            effect_id,
            outcome,
            Some(&guard.expected_revision),
            Some(&guard.expected_checkpoint_digest),
        )?;
        self.commit_v2_result_with_store(store, &record, &result)?;
        Ok(result)
    }

    pub fn compact_outbox_v2(
        &self,
        root_instance_id: &str,
        effect_id: &str,
        guard: &MutationGuard,
    ) -> Result<JsonValue, Version2Error> {
        let mut store = DirectStoreAccess {
            store: self.store.as_ref(),
        };
        self.compact_outbox_v2_with_store(&mut store, root_instance_id, effect_id, guard)
    }

    fn compact_outbox_v2_with_store(
        &self,
        store: &mut dyn StoreAccess,
        root_instance_id: &str,
        effect_id: &str,
        guard: &MutationGuard,
    ) -> Result<JsonValue, Version2Error> {
        let (record, checkpoint) =
            self.require_checkpoint_v2_with_store(store, root_instance_id)?;
        let result = checkpoint_compact_outbox_v2(
            &checkpoint,
            effect_id,
            Some(&guard.expected_revision),
            Some(&guard.expected_checkpoint_digest),
        )?;
        self.commit_v2_result_with_store(store, &record, &result)?;
        Ok(result)
    }

    pub fn tombstone_root_v2(
        &self,
        root_instance_id: &str,
        operation_id: &str,
        guard: &MutationGuard,
    ) -> Result<JsonValue, Version2Error> {
        let mut store = DirectStoreAccess {
            store: self.store.as_ref(),
        };
        self.tombstone_root_v2_with_store(&mut store, root_instance_id, operation_id, guard)
    }

    fn tombstone_root_v2_with_store(
        &self,
        store: &mut dyn StoreAccess,
        root_instance_id: &str,
        operation_id: &str,
        guard: &MutationGuard,
    ) -> Result<JsonValue, Version2Error> {
        let (record, checkpoint) =
            self.require_checkpoint_v2_with_store(store, root_instance_id)?;
        let result = checkpoint_tombstone_root_v2(
            &checkpoint,
            operation_id,
            Some(&guard.expected_revision),
            Some(&guard.expected_checkpoint_digest),
        )?;
        self.commit_v2_result_with_store(store, &record, &result)?;
        Ok(result)
    }

    fn restore_record_v2(
        &self,
        record: StoreRecord,
    ) -> Result<ExecutionCheckpointV2, Version2Error> {
        let checkpoint = restore_execution_checkpoint_v2(&record.bytes, self.resolver.as_ref())?;
        if checkpoint.root_instance_id() != record.root_instance_id
            || checkpoint.revision() != record.revision
            || checkpoint.digest() != record.execution_checkpoint_digest
        {
            return Err(v2_failure(
                "invalid_execution_checkpoint",
                "store metadata differs from checkpoint artifact",
            ));
        }
        Ok(checkpoint)
    }

    fn require_checkpoint_v2_with_store(
        &self,
        store: &mut dyn StoreAccess,
        root_instance_id: &str,
    ) -> Result<(StoreRecord, ExecutionCheckpointV2), Version2Error> {
        let record = store
            .load(root_instance_id)
            .map_err(v2_store_error)?
            .ok_or_else(|| {
                v2_failure(
                    "checkpoint_not_found",
                    "execution checkpoint does not exist",
                )
            })?;
        let checkpoint = self.restore_record_v2(record.clone())?;
        Ok((record, checkpoint))
    }

    fn checkpoint_v2_bundle(
        &self,
        checkpoint: &ExecutionCheckpointV2,
    ) -> Result<Bundle, Version2Error> {
        let fingerprint = checkpoint.bundle_fingerprint().ok_or_else(|| {
            v2_failure(
                "terminal_root",
                "terminal checkpoint has no runnable aggregate",
            )
        })?;
        let resolved = self
            .resolver
            .resolve_definition(fingerprint)
            .ok_or_else(|| {
                v2_failure("definition_not_found", "current definition is unavailable")
            })?;
        if !resolved.trusted || resolved.bundle.fingerprint != fingerprint {
            return Err(v2_failure(
                "definition_not_trusted",
                "current definition is not trusted or content-addressed correctly",
            ));
        }
        Ok(resolved.bundle)
    }

    fn commit_v2_result_with_store(
        &self,
        store: &mut dyn StoreAccess,
        current: &StoreRecord,
        result: &JsonValue,
    ) -> Result<(), Version2Error> {
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
        let bytes = crate::format1::v2::canonical_bytes(candidate)?;
        let checkpoint = restore_execution_checkpoint_v2(&bytes, self.resolver.as_ref())?;
        if checkpoint.revision() == current.revision
            && checkpoint.digest() == current.execution_checkpoint_digest
        {
            return Ok(());
        }
        let replacement = StoreRecord::from_checkpoint_v2(&checkpoint).map_err(v2_store_error)?;
        self.commit_record_v2_with_store(store, current, replacement)
    }

    fn commit_record_v2_with_store(
        &self,
        store: &mut dyn StoreAccess,
        current: &StoreRecord,
        replacement: StoreRecord,
    ) -> Result<(), Version2Error> {
        match store
            .compare_and_swap(
                &current.root_instance_id,
                &current.revision,
                &current.execution_checkpoint_digest,
                replacement,
            )
            .map_err(v2_store_error)?
        {
            StoreWriteResult::Committed => Ok(()),
            StoreWriteResult::Conflict(_) => Err(v2_failure(
                "checkpoint_revision_conflict",
                "checkpoint compare-and-swap conflicted",
            )),
        }
    }
}

fn maintenance_request_digest(
    root_instance_id: &str,
    request: &MaintenanceMigrationRequest,
) -> Result<String, Version2Error> {
    crate::format1::wire::jcs_hash(&json!([
        "determa-maintenance-migration-request-digest-2",
        "2",
        root_instance_id,
        request.operation_id,
        request.source_aggregate_state_digest,
        request.target_validated_bundle_fingerprint,
        request.migration_descriptor_digest_route,
        request.maintenance_mode
    ]))
    .map_err(|error| v2_failure("invalid_execution_checkpoint", &error.to_string()))
}

fn v2_store_error(error: StoreError) -> Version2Error {
    Version2Error::new(error.code.as_str(), error.message)
}

#[cfg(feature = "postgresql")]
fn v2_host_failure(error: Version2Error) -> HostFailure {
    HostFailure::new(
        HostFailureCode::InvalidExecutionCheckpoint,
        format!("{}: {}", error.code, error.message),
    )
}

fn v2_failure(code: &str, message: &str) -> Version2Error {
    Version2Error::new(code, message)
}
