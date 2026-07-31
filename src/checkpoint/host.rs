#[cfg(feature = "postgresql")]
use super::adapters::PostgresqlExecutionStore;
#[cfg(feature = "postgresql")]
use super::store::DurableStoreMode;
use super::store::{
    validate_store_host_profile, AdapterError, ExecutionStore, HostFeature, HostProfile,
    StoreError, StoreErrorCode, StoreRecord, StoreWriteResult,
};
use super::wire::{
    envelope_digest, hash_tagged, outbox_intent_digest, AcceptanceResult, CheckpointFault,
    CommittedDeliveryResult, CommittedResultKind, CreationOperationKind, CreationReceipt,
    DeliveryMode, DeliveryOperationKind, DeliveryOrigin, DeliveryOutcome, DeliveryReceipt,
    EmissionReference, ExecutionCheckpoint, MaintenanceMigrationOperationKind,
    MaintenanceMigrationReceipt, MaintenanceMigrationResultCode, NotAcceptedResult,
    NotAcceptedResultKind, OperationReceipt, OutboxEffectTombstone, OutboxIntent, OutboxRecord,
    PendingAcceptanceResult, PendingAcceptanceResultKind, PendingDelivery, PendingOutboxIntent,
    PendingOutboxState, PortableEnvelope, PreAcceptanceFailure, PreAcceptanceFailureCode,
    ReplayRetention, RetainedRootRecord, RetainedRootStatus, RootRecord, RootTombstone,
    RootTombstoneStatus, TerminalOutboxOutcome, TerminalOutboxRecord, TerminalRootStatus,
};
use crate::format1::{
    create, dispatch, encode_aggregate, migrate_aggregate, AggregateState, Bindings, Bundle,
    Counter, Delivery, Disposition, Emission, MigrationArtifactResolver, MigrationRequest,
    ResourceLimits, ResultStatus, RuntimeStatus, TypedValue,
};
use crate::Value;
use serde_json::{json, Value as JsonValue};
use std::collections::BTreeMap;
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

pub struct CreationRequest<'a> {
    pub bundle: &'a Bundle,
    pub namespace: &'a str,
    pub machine_id: &'a str,
    pub machine_version: i64,
    pub root_instance_id: &'a str,
    pub creation_id: &'a str,
    pub bindings: &'a Bindings,
    pub supplied_request_digest: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct DeliveryRequest {
    pub checkpoint_root_instance_id: String,
    pub candidate: JsonValue,
    pub guard: MutationGuard,
}

#[derive(Debug, Clone)]
pub struct ProcessingMigration {
    pub request: MigrationRequest,
    pub limits: ResourceLimits,
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
    Create(CreationRequest<'a>),
    AcceptDelivery(DeliveryRequest),
    ForegroundProcessDelivery {
        request: DeliveryRequest,
        migration: Option<&'a ProcessingMigration>,
    },
    ProcessPendingDelivery {
        request: DeliveryRequest,
        migration: Option<&'a ProcessingMigration>,
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
    DeleteOutboxRecord {
        root_instance_id: &'a str,
        effect_id: &'a str,
        guard: &'a MutationGuard,
    },
    UpdateReplayRetention {
        root_instance_id: &'a str,
        target: ReplayRetention,
        guard: &'a MutationGuard,
    },
    TombstoneRoot {
        root_instance_id: &'a str,
        operation_id: &'a str,
        guard: &'a MutationGuard,
    },
    DeleteCheckpoint {
        root_instance_id: &'a str,
        guard: &'a MutationGuard,
    },
}

#[cfg(feature = "postgresql")]
impl PostgresqlHostMutation<'_> {
    fn root_instance_id(&self) -> &str {
        match self {
            Self::Create(request) => request.root_instance_id,
            Self::AcceptDelivery(request)
            | Self::ForegroundProcessDelivery { request, .. }
            | Self::ProcessPendingDelivery { request, .. } => &request.checkpoint_root_instance_id,
            Self::MaintenanceMigration(request) => &request.root_instance_id,
            Self::UpdatePendingOutbox {
                root_instance_id, ..
            }
            | Self::TerminalizeOutbox {
                root_instance_id, ..
            }
            | Self::CompactOutbox {
                root_instance_id, ..
            }
            | Self::DeleteOutboxRecord {
                root_instance_id, ..
            }
            | Self::UpdateReplayRetention {
                root_instance_id, ..
            }
            | Self::TombstoneRoot {
                root_instance_id, ..
            }
            | Self::DeleteCheckpoint {
                root_instance_id, ..
            } => root_instance_id,
        }
    }
}

#[cfg(feature = "postgresql")]
#[derive(Debug, Clone, PartialEq)]
pub enum PostgresqlHostMutationResult {
    Creation(CreationReceipt),
    Acceptance(AcceptanceResult),
    Delivery(DeliveryReceipt),
    MaintenanceMigration(MaintenanceMigrationReceipt),
    PendingOutbox(PendingOutboxIntent),
    Outbox(OutboxRecord),
    CompactedOutbox(OutboxEffectTombstone),
    OutboxRecordDeleted,
    ReplayRetention(ReplayRetention),
    RootTombstone(RootTombstone),
    CheckpointDeleted,
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
            PostgresqlHostMutation::Create(request) => {
                PostgresqlHostMutationResult::Creation(self.create_with_store(&mut store, request)?)
            }
            PostgresqlHostMutation::AcceptDelivery(request) => {
                PostgresqlHostMutationResult::Acceptance(
                    self.accept_delivery_with_store(&mut store, request)?,
                )
            }
            PostgresqlHostMutation::ForegroundProcessDelivery { request, migration } => {
                PostgresqlHostMutationResult::Delivery(
                    self.foreground_process_delivery_with_store(&mut store, request, migration)?,
                )
            }
            PostgresqlHostMutation::ProcessPendingDelivery { request, migration } => {
                PostgresqlHostMutationResult::Delivery(
                    self.process_pending_delivery_with_store(&mut store, request, migration)?,
                )
            }
            PostgresqlHostMutation::MaintenanceMigration(request) => {
                PostgresqlHostMutationResult::MaintenanceMigration(
                    self.maintenance_migration_with_store(&mut store, request)?,
                )
            }
            PostgresqlHostMutation::UpdatePendingOutbox {
                root_instance_id,
                effect_id,
                desired,
                guard,
            } => {
                PostgresqlHostMutationResult::PendingOutbox(self.update_pending_outbox_with_store(
                    &mut store,
                    root_instance_id,
                    effect_id,
                    desired,
                    guard,
                )?)
            }
            PostgresqlHostMutation::TerminalizeOutbox {
                root_instance_id,
                effect_id,
                outcome,
                guard,
            } => PostgresqlHostMutationResult::Outbox(self.terminalize_outbox_with_store(
                &mut store,
                root_instance_id,
                effect_id,
                outcome,
                guard,
            )?),
            PostgresqlHostMutation::CompactOutbox {
                root_instance_id,
                effect_id,
                guard,
            } => PostgresqlHostMutationResult::CompactedOutbox(self.compact_outbox_with_store(
                &mut store,
                root_instance_id,
                effect_id,
                guard,
            )?),
            PostgresqlHostMutation::DeleteOutboxRecord {
                root_instance_id,
                effect_id,
                guard,
            } => {
                self.delete_outbox_record_with_store(
                    &mut store,
                    root_instance_id,
                    effect_id,
                    guard,
                )?;
                PostgresqlHostMutationResult::OutboxRecordDeleted
            }
            PostgresqlHostMutation::UpdateReplayRetention {
                root_instance_id,
                target,
                guard,
            } => PostgresqlHostMutationResult::ReplayRetention(
                self.update_replay_retention_with_store(
                    &mut store,
                    root_instance_id,
                    target,
                    guard,
                )?,
            ),
            PostgresqlHostMutation::TombstoneRoot {
                root_instance_id,
                operation_id,
                guard,
            } => PostgresqlHostMutationResult::RootTombstone(self.tombstone_root_with_store(
                &mut store,
                root_instance_id,
                operation_id,
                guard,
            )?),
            PostgresqlHostMutation::DeleteCheckpoint {
                root_instance_id,
                guard,
            } => {
                self.delete_checkpoint_with_store(&mut store, root_instance_id, guard)?;
                PostgresqlHostMutationResult::CheckpointDeleted
            }
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
    ) -> Result<Option<ExecutionCheckpoint>, HostFailure> {
        let mut store = DirectStoreAccess {
            store: self.store.as_ref(),
        };
        self.load_checkpoint_with_store(&mut store, root_instance_id)
    }

    fn load_checkpoint_with_store(
        &self,
        store: &mut dyn StoreAccess,
        root_instance_id: &str,
    ) -> Result<Option<ExecutionCheckpoint>, HostFailure> {
        store
            .load(root_instance_id)?
            .map(|record| self.restore_record(record))
            .transpose()
    }

    pub fn create(&self, request: CreationRequest<'_>) -> Result<CreationReceipt, HostFailure> {
        let mut store = DirectStoreAccess {
            store: self.store.as_ref(),
        };
        self.create_with_store(&mut store, request)
    }

    fn create_with_store(
        &self,
        store: &mut dyn StoreAccess,
        request: CreationRequest<'_>,
    ) -> Result<CreationReceipt, HostFailure> {
        let request_digest = creation_request_digest(&request)?;
        if let Some(supplied) = request.supplied_request_digest {
            if supplied != request_digest {
                return Err(HostFailure::new(
                    HostFailureCode::InvalidExecutionCheckpoint,
                    "supplied creation request digest does not match",
                ));
            }
        }
        if let Some(current) = self.load_checkpoint_with_store(store, request.root_instance_id)? {
            return replay_creation(&current, request.creation_id, &request_digest);
        }
        if request.namespace != request.bundle.namespace
            || request
                .bundle
                .machines
                .get(request.machine_id)
                .is_some_and(|machine| machine.version != request.machine_version)
        {
            return Err(HostFailure::new(
                HostFailureCode::CreationRejected,
                "creation metadata does not match the validated bundle",
            ));
        }
        let result = create(
            request.bundle,
            request.machine_id,
            request.root_instance_id,
            request.creation_id,
            request.bindings,
        );
        let Some(state) = result.state else {
            return Err(HostFailure::new(
                HostFailureCode::CreationRejected,
                result
                    .rejection
                    .map(|value| value.code)
                    .unwrap_or_else(|| "core rejected creation".to_string()),
            ));
        };
        let (aggregate, _) = encode_aggregate(request.bundle, &state)
            .map_err(|error| invalid_host(error.to_string()))?;
        let status = result_status_to_runtime(result.status)?;
        let mut checkpoint = ExecutionCheckpoint {
            execution_checkpoint_format: "determa.execution_checkpoint".to_string(),
            execution_checkpoint_schema_version: 1,
            root_instance_id: request.root_instance_id.to_string(),
            revision: Counter::zero(),
            root_record: RootRecord::Retained(RetainedRootRecord {
                status: RetainedRootStatus::Retained,
                aggregate_state: aggregate.clone(),
            }),
            replay_retention: ReplayRetention::permanent(),
            next_delivery_sequence: Counter::zero(),
            pending_deliveries: Vec::new(),
            next_operation_receipt_sequence: Counter::from(1_u64),
            operation_receipts: Vec::new(),
            pending_outbox_intents: Vec::new(),
            next_outbox_terminal_sequence: Counter::zero(),
            terminal_outbox_records: Vec::new(),
            outbox_effect_tombstones: Vec::new(),
            migration_audit_records: Vec::new(),
            execution_checkpoint_digest: String::new(),
        };
        let mut receipt = CreationReceipt {
            operation_kind: CreationOperationKind::Creation,
            receipt_sequence: Counter::zero(),
            creation_id: request.creation_id.to_string(),
            request_digest,
            committed_revision: Counter::zero(),
            resulting_aggregate_state_digest: aggregate.aggregate_state_digest,
            status,
            fault: result.fault.as_ref().map(CheckpointFault::from),
            emission_references: Vec::new(),
        };
        receipt.emission_references = append_emissions(
            &mut checkpoint,
            &receipt.receipt_sequence,
            &receipt.committed_revision,
            &result.emissions,
        )?;
        checkpoint
            .operation_receipts
            .push(OperationReceipt::Creation(receipt.clone()));
        checkpoint
            .recompute_digest()
            .map_err(|error| invalid_host(error.to_string()))?;
        checkpoint
            .validate_for_persistence(self.resolver.as_ref())
            .map_err(|error| invalid_host(error.to_string()))?;
        let record = StoreRecord::from_checkpoint(&checkpoint)?;
        match store.insert_if_absent(record)? {
            StoreWriteResult::Committed => Ok(receipt),
            StoreWriteResult::Conflict(Some(current)) => {
                let current = self.restore_record(current)?;
                replay_creation(&current, request.creation_id, &receipt.request_digest)
            }
            StoreWriteResult::Conflict(None) => Err(revision_conflict()),
        }
    }

    pub fn accept_delivery(
        &self,
        request: DeliveryRequest,
    ) -> Result<AcceptanceResult, HostFailure> {
        let mut store = DirectStoreAccess {
            store: self.store.as_ref(),
        };
        self.accept_delivery_with_store(&mut store, request)
    }

    fn accept_delivery_with_store(
        &self,
        store: &mut dyn StoreAccess,
        request: DeliveryRequest,
    ) -> Result<AcceptanceResult, HostFailure> {
        let current = self.require_checkpoint(store, &request.checkpoint_root_instance_id)?;
        let parsed = match parse_delivery_candidate(&request.candidate, &current.root_instance_id) {
            Ok(value) => value,
            Err(code) => return Ok(not_accepted(code)),
        };
        let replay = delivery_replay(&current, &parsed.envelope.event_id, &parsed.envelope_digest)?;
        if let Some(replay) = replay {
            return Ok(replay);
        }
        if matches!(current.root_record, RootRecord::Tombstone(_)) {
            return Ok(not_accepted(PreAcceptanceFailureCode::TombstonedRoot));
        }
        let parsed = match parsed.validate() {
            Ok(value) => value,
            Err(code) => return Ok(not_accepted(code)),
        };
        check_guard(&current, &request.guard)?;
        let mut candidate = current.clone();
        candidate.increment_revision();
        let delivery_sequence = candidate.next_delivery_sequence.allocate();
        let accepted_revision = candidate.revision.clone();
        candidate.pending_deliveries.push(PendingDelivery {
            delivery_sequence: delivery_sequence.clone(),
            accepted_revision: accepted_revision.clone(),
            delivery_mode: parsed.delivery_mode,
            origin: parsed.origin,
            envelope: parsed.envelope.clone(),
            envelope_digest: parsed.envelope_digest,
        });
        candidate
            .recompute_digest()
            .map_err(|error| invalid_host(error.to_string()))?;
        self.commit_candidate(store, &current, &candidate)?;
        Ok(AcceptanceResult::Pending(PendingAcceptanceResult {
            result: PendingAcceptanceResultKind::Pending,
            event_id: parsed.envelope.event_id,
            delivery_sequence,
            accepted_revision,
        }))
    }

    pub fn foreground_process_delivery(
        &self,
        request: DeliveryRequest,
        migration: Option<&ProcessingMigration>,
    ) -> Result<DeliveryReceipt, HostFailure> {
        let mut store = DirectStoreAccess {
            store: self.store.as_ref(),
        };
        self.foreground_process_delivery_with_store(&mut store, request, migration)
    }

    fn foreground_process_delivery_with_store(
        &self,
        store: &mut dyn StoreAccess,
        request: DeliveryRequest,
        migration: Option<&ProcessingMigration>,
    ) -> Result<DeliveryReceipt, HostFailure> {
        let current = self.require_checkpoint(store, &request.checkpoint_root_instance_id)?;
        let parsed = parse_delivery_candidate(&request.candidate, &current.root_instance_id)
            .map_err(|code| {
                HostFailure::new(preaccept_failure_code(code), "delivery was not accepted")
            })?;
        let replay = delivery_replay(&current, &parsed.envelope.event_id, &parsed.envelope_digest)?;
        if let Some(replay) = replay {
            return acceptance_receipt(replay);
        }
        if matches!(current.root_record, RootRecord::Tombstone(_)) {
            return Err(HostFailure::new(
                HostFailureCode::InvalidExecutionCheckpoint,
                "tombstoned root cannot process a delivery",
            ));
        }
        let parsed = parsed.validate().map_err(|code| {
            HostFailure::new(preaccept_failure_code(code), "delivery was not accepted")
        })?;
        check_guard(&current, &request.guard)?;
        let accepted_delivery_sequence = current.next_delivery_sequence.clone();
        self.process_delivery(
            store,
            ProcessDeliveryRequest {
                current,
                parsed,
                accepted_delivery_sequence,
                accepted_revision: None,
                foreground: true,
                migration,
            },
        )
    }

    pub fn process_pending_delivery(
        &self,
        request: DeliveryRequest,
        migration: Option<&ProcessingMigration>,
    ) -> Result<DeliveryReceipt, HostFailure> {
        let mut store = DirectStoreAccess {
            store: self.store.as_ref(),
        };
        self.process_pending_delivery_with_store(&mut store, request, migration)
    }

    fn process_pending_delivery_with_store(
        &self,
        store: &mut dyn StoreAccess,
        request: DeliveryRequest,
        migration: Option<&ProcessingMigration>,
    ) -> Result<DeliveryReceipt, HostFailure> {
        let current = self.require_checkpoint(store, &request.checkpoint_root_instance_id)?;
        let parsed = parse_delivery_candidate(&request.candidate, &current.root_instance_id)
            .map_err(|code| {
                HostFailure::new(
                    preaccept_failure_code(code),
                    "pending delivery request is invalid",
                )
            })?;
        if let Some(receipt) =
            committed_delivery_replay(&current, &parsed.envelope.event_id, &parsed.envelope_digest)?
        {
            return Ok(receipt);
        }
        let pending = current
            .pending_deliveries
            .iter()
            .find(|pending| pending.envelope.event_id == parsed.envelope.event_id)
            .cloned()
            .ok_or_else(|| {
                HostFailure::new(
                    HostFailureCode::EventIdConflict,
                    "pending delivery identity is absent",
                )
            })?;
        if pending.envelope_digest != parsed.envelope_digest {
            return Err(HostFailure::new(
                HostFailureCode::EventIdConflict,
                "pending event id has different content",
            ));
        }
        check_guard(&current, &request.guard)?;
        self.process_delivery(
            store,
            ProcessDeliveryRequest {
                current,
                parsed: ParsedDelivery {
                    delivery_mode: pending.delivery_mode,
                    origin: pending.origin.clone(),
                    envelope: pending.envelope.clone(),
                    envelope_digest: pending.envelope_digest.clone(),
                },
                accepted_delivery_sequence: pending.delivery_sequence,
                accepted_revision: Some(pending.accepted_revision),
                foreground: false,
                migration,
            },
        )
    }

    pub fn maintenance_migration(
        &self,
        request: &MaintenanceMigrationRequest,
    ) -> Result<MaintenanceMigrationReceipt, HostFailure> {
        let mut store = DirectStoreAccess {
            store: self.store.as_ref(),
        };
        self.maintenance_migration_with_store(&mut store, request)
    }

    fn maintenance_migration_with_store(
        &self,
        store: &mut dyn StoreAccess,
        request: &MaintenanceMigrationRequest,
    ) -> Result<MaintenanceMigrationReceipt, HostFailure> {
        if request.operation_id.is_empty() {
            return Err(invalid_host("maintenance operation id is empty"));
        }
        let current = self.require_checkpoint(store, &request.root_instance_id)?;
        let request_digest = maintenance_request_digest(&request.root_instance_id, request)?;
        if request
            .supplied_request_digest
            .as_ref()
            .is_some_and(|value| value != &request_digest)
        {
            return Err(invalid_host(
                "supplied maintenance request digest does not match",
            ));
        }
        if let Some(existing) = current.operation_receipts.iter().find_map(|receipt| {
            let OperationReceipt::MaintenanceMigration(value) = receipt else {
                return None;
            };
            (value.operation_id == request.operation_id).then_some(value)
        }) {
            if existing.request_digest == request_digest {
                return Ok(existing.clone());
            }
            return Err(HostFailure::new(
                HostFailureCode::OperationIdConflict,
                "maintenance operation id has different content",
            ));
        }
        check_guard(&current, &request.guard)?;
        let RootRecord::Retained(root) = &current.root_record else {
            return Err(invalid_host("tombstoned root cannot be migrated"));
        };
        if root.aggregate_state.aggregate_state_digest != request.source_aggregate_state_digest {
            return Err(invalid_host(
                "maintenance source digest differs from checkpoint aggregate",
            ));
        }
        let source = root
            .aggregate_state
            .canonical_bytes()
            .map_err(|error| invalid_host(error.to_string()))?;
        let migration_request = MigrationRequest {
            migration_route: request.migration_descriptor_digest_route.clone(),
            target_validated_bundle_fingerprint: request
                .target_validated_bundle_fingerprint
                .clone(),
            maintenance_mode: request.maintenance_mode,
        };
        let outcome = migrate_aggregate(
            &source,
            &migration_request,
            self.resolver.as_ref(),
            &request.limits,
        )
        .map_err(|error| invalid_host(error.to_string()))?;
        let mut candidate = current.clone();
        candidate.increment_revision();
        let receipt_sequence = candidate.next_operation_receipt_sequence.allocate();
        let audit_sequences = outcome
            .audit_records
            .iter()
            .map(|record| Counter::from_decimal(&record.migration_sequence).map_err(invalid_host))
            .collect::<Result<Vec<_>, _>>()?;
        let result_code = if audit_sequences.is_empty() {
            MaintenanceMigrationResultCode::MigrationNoOperation
        } else {
            MaintenanceMigrationResultCode::MigrationApplied
        };
        let receipt = MaintenanceMigrationReceipt {
            operation_kind: MaintenanceMigrationOperationKind::MaintenanceMigration,
            receipt_sequence,
            operation_id: request.operation_id.clone(),
            request_digest,
            committed_revision: candidate.revision.clone(),
            source_aggregate_state_digest: request.source_aggregate_state_digest.clone(),
            resulting_aggregate_state_digest: outcome
                .aggregate_envelope
                .aggregate_state_digest
                .clone(),
            migration_sequences: audit_sequences,
            result_code,
        };
        let RootRecord::Retained(candidate_root) = &mut candidate.root_record else {
            unreachable!("retained root checked");
        };
        candidate_root.aggregate_state = outcome.aggregate_envelope;
        candidate
            .migration_audit_records
            .extend(outcome.audit_records);
        candidate
            .operation_receipts
            .push(OperationReceipt::MaintenanceMigration(receipt.clone()));
        candidate
            .recompute_digest()
            .map_err(|error| invalid_host(error.to_string()))?;
        self.commit_candidate(store, &current, &candidate)?;
        Ok(receipt)
    }

    pub fn update_pending_outbox(
        &self,
        root_instance_id: &str,
        effect_id: &str,
        desired: PendingOutboxState,
        guard: &MutationGuard,
    ) -> Result<PendingOutboxIntent, HostFailure> {
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
    ) -> Result<PendingOutboxIntent, HostFailure> {
        let current = self.require_checkpoint(store, root_instance_id)?;
        let existing = current
            .pending_outbox_intents
            .iter()
            .find(|value| value.intent.effect_id == effect_id)
            .cloned();
        let Some(existing) = existing else {
            return Err(HostFailure::new(
                HostFailureCode::EffectIdConflict,
                "effect is not pending",
            ));
        };
        if existing.delivery_state == desired {
            return Ok(existing);
        }
        check_guard(&current, guard)?;
        let mut candidate = current.clone();
        candidate.increment_revision();
        let record = candidate
            .pending_outbox_intents
            .iter_mut()
            .find(|value| value.intent.effect_id == effect_id)
            .expect("pending record cloned");
        record.delivery_state = desired;
        record.state_revision = candidate.revision.clone();
        let response = record.clone();
        candidate
            .recompute_digest()
            .map_err(|error| invalid_host(error.to_string()))?;
        self.commit_candidate(store, &current, &candidate)?;
        Ok(response)
    }

    pub fn terminalize_outbox(
        &self,
        root_instance_id: &str,
        effect_id: &str,
        outcome: TerminalOutboxOutcome,
        guard: &MutationGuard,
    ) -> Result<OutboxRecord, HostFailure> {
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
    ) -> Result<OutboxRecord, HostFailure> {
        let current = self.require_checkpoint(store, root_instance_id)?;
        if let Some(record) = current
            .terminal_outbox_records
            .iter()
            .find(|value| value.intent.effect_id == effect_id)
        {
            return if record.outcome == outcome {
                Ok(OutboxRecord::Terminal(record.clone()))
            } else {
                Err(effect_conflict())
            };
        }
        if let Some(record) = current
            .outbox_effect_tombstones
            .iter()
            .find(|value| value.effect_id == effect_id)
        {
            return if record.outcome == outcome {
                Ok(OutboxRecord::Tombstone(record.clone()))
            } else {
                Err(effect_conflict())
            };
        }
        check_guard(&current, guard)?;
        let mut candidate = current.clone();
        let Some(index) = candidate
            .pending_outbox_intents
            .iter()
            .position(|value| value.intent.effect_id == effect_id)
        else {
            return Err(effect_conflict());
        };
        candidate.increment_revision();
        let pending = candidate.pending_outbox_intents.remove(index);
        let record = TerminalOutboxRecord {
            terminal_sequence: candidate.next_outbox_terminal_sequence.allocate(),
            intent: pending.intent,
            committed_revision: candidate.revision.clone(),
            outcome,
        };
        candidate.terminal_outbox_records.push(record.clone());
        candidate
            .recompute_digest()
            .map_err(|error| invalid_host(error.to_string()))?;
        self.commit_candidate(store, &current, &candidate)?;
        Ok(OutboxRecord::Terminal(record))
    }

    pub fn compact_outbox(
        &self,
        root_instance_id: &str,
        effect_id: &str,
        guard: &MutationGuard,
    ) -> Result<OutboxEffectTombstone, HostFailure> {
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
    ) -> Result<OutboxEffectTombstone, HostFailure> {
        let current = self.require_checkpoint(store, root_instance_id)?;
        if let Some(record) = current
            .outbox_effect_tombstones
            .iter()
            .find(|value| value.effect_id == effect_id)
        {
            return Ok(record.clone());
        }
        check_guard(&current, guard)?;
        let mut candidate = current.clone();
        let Some(index) = candidate
            .terminal_outbox_records
            .iter()
            .position(|value| value.intent.effect_id == effect_id)
        else {
            return Err(effect_conflict());
        };
        candidate.increment_revision();
        let terminal = candidate.terminal_outbox_records.remove(index);
        let tombstone = OutboxEffectTombstone {
            terminal_sequence: terminal.terminal_sequence,
            effect_id: terminal.intent.effect_id.clone(),
            intent_digest: outbox_intent_digest(&candidate.root_instance_id, &terminal.intent)
                .map_err(|error| invalid_host(error.to_string()))?,
            committed_revision: terminal.committed_revision,
            outcome: terminal.outcome,
        };
        candidate.outbox_effect_tombstones.push(tombstone.clone());
        candidate
            .outbox_effect_tombstones
            .sort_by(|left, right| left.terminal_sequence.cmp(&right.terminal_sequence));
        candidate
            .recompute_digest()
            .map_err(|error| invalid_host(error.to_string()))?;
        self.commit_candidate(store, &current, &candidate)?;
        Ok(tombstone)
    }

    pub fn delete_outbox_record(
        &self,
        root_instance_id: &str,
        effect_id: &str,
        guard: &MutationGuard,
    ) -> Result<(), HostFailure> {
        let mut store = DirectStoreAccess {
            store: self.store.as_ref(),
        };
        self.delete_outbox_record_with_store(&mut store, root_instance_id, effect_id, guard)
    }

    fn delete_outbox_record_with_store(
        &self,
        store: &mut dyn StoreAccess,
        root_instance_id: &str,
        effect_id: &str,
        guard: &MutationGuard,
    ) -> Result<(), HostFailure> {
        let current = self.require_checkpoint(store, root_instance_id)?;
        if current.operation_receipts.iter().any(|receipt| {
            receipt.emission_references().iter().any(|reference| {
                matches!(
                    reference,
                    EmissionReference::ExternalOutbox {
                        effect_id: referenced,
                        ..
                    } if referenced == effect_id
                )
            })
        }) {
            return Err(invalid_host(
                "retained operation receipt still references effect",
            ));
        }
        check_guard(&current, guard)?;
        let mut candidate = current.clone();
        let terminal_index = candidate
            .terminal_outbox_records
            .iter()
            .position(|value| value.intent.effect_id == effect_id);
        let tombstone_index = candidate
            .outbox_effect_tombstones
            .iter()
            .position(|value| value.effect_id == effect_id);
        if terminal_index.is_none() && tombstone_index.is_none() {
            return Err(effect_conflict());
        }
        candidate.increment_revision();
        if let Some(index) = terminal_index {
            candidate.terminal_outbox_records.remove(index);
        }
        if let Some(index) = tombstone_index {
            candidate.outbox_effect_tombstones.remove(index);
        }
        candidate
            .recompute_digest()
            .map_err(|error| invalid_host(error.to_string()))?;
        self.commit_candidate(store, &current, &candidate)
    }

    pub fn update_replay_retention(
        &self,
        root_instance_id: &str,
        target: ReplayRetention,
        guard: &MutationGuard,
    ) -> Result<ReplayRetention, HostFailure> {
        let mut store = DirectStoreAccess {
            store: self.store.as_ref(),
        };
        self.update_replay_retention_with_store(&mut store, root_instance_id, target, guard)
    }

    fn update_replay_retention_with_store(
        &self,
        store: &mut dyn StoreAccess,
        root_instance_id: &str,
        target: ReplayRetention,
        guard: &MutationGuard,
    ) -> Result<ReplayRetention, HostFailure> {
        let current = self.require_checkpoint(store, root_instance_id)?;
        if current.replay_retention == target {
            return Ok(target);
        }
        if matches!(current.replay_retention, ReplayRetention::Bounded(_))
            && matches!(target, ReplayRetention::Permanent(_))
        {
            return Err(invalid_host(
                "bounded replay retention cannot return to permanent",
            ));
        }
        check_guard(&current, guard)?;
        let ReplayRetention::Bounded(target_bounded) = &target else {
            return Err(invalid_host("unsupported replay retention transition"));
        };
        if target_bounded.permanent_replay_eligible || target_bounded.policy_identifier.is_empty() {
            return Err(invalid_host("invalid bounded retention target"));
        }
        let current_cutoff = current.replay_retention.cutoff();
        if current_cutoff
            .zip(target_bounded.pruned_through_receipt_sequence.as_ref())
            .is_some_and(|(current, target)| target < current)
        {
            return Err(invalid_host("bounded replay cutoff cannot decrease"));
        }
        let mut candidate = current.clone();
        if let Some(cutoff) = &target_bounded.pruned_through_receipt_sequence {
            for receipt in candidate.operation_receipts.iter().skip(1) {
                if receipt.receipt_sequence() <= cutoff {
                    continue;
                }
                if let OperationReceipt::Delivery(delivery) = receipt {
                    if let DeliveryOrigin::InternalEmission(origin) = &delivery.origin {
                        if &origin.producing_receipt_sequence <= cutoff {
                            return Err(invalid_host(
                                "retained internal delivery depends on pruned producer",
                            ));
                        }
                    }
                }
            }
            for pending in &candidate.pending_deliveries {
                if let DeliveryOrigin::InternalEmission(origin) = &pending.origin {
                    if &origin.producing_receipt_sequence <= cutoff {
                        return Err(invalid_host(
                            "pending internal delivery depends on pruned producer",
                        ));
                    }
                }
            }
            candidate.operation_receipts.retain(|receipt| {
                receipt.receipt_sequence() == &Counter::zero()
                    || receipt.receipt_sequence() > cutoff
            });
        }
        candidate.increment_revision();
        candidate.replay_retention = target.clone();
        candidate
            .recompute_digest()
            .map_err(|error| invalid_host(error.to_string()))?;
        self.commit_candidate(store, &current, &candidate)?;
        Ok(target)
    }

    pub fn tombstone_root(
        &self,
        root_instance_id: &str,
        operation_id: &str,
        guard: &MutationGuard,
    ) -> Result<RootTombstone, HostFailure> {
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
    ) -> Result<RootTombstone, HostFailure> {
        if operation_id.is_empty() {
            return Err(invalid_host("tombstone operation id is empty"));
        }
        let current = self.require_checkpoint(store, root_instance_id)?;
        if let RootRecord::Tombstone(tombstone) = &current.root_record {
            return if tombstone.tombstone_operation_id == operation_id {
                Ok(tombstone.clone())
            } else {
                Err(HostFailure::new(
                    HostFailureCode::OperationIdConflict,
                    "root was tombstoned by another operation",
                ))
            };
        }
        check_guard(&current, guard)?;
        if !current.pending_deliveries.is_empty() || !current.pending_outbox_intents.is_empty() {
            return Err(invalid_host("root has unresolved pending work"));
        }
        let RootRecord::Retained(root) = &current.root_record else {
            unreachable!("tombstone replay handled");
        };
        let root_runtime = root
            .aggregate_state
            .runtimes
            .iter()
            .find(|runtime| runtime.runtime_id == root.aggregate_state.root_runtime_id)
            .ok_or_else(|| invalid_host("aggregate root runtime is absent"))?;
        let terminal_status = match root_runtime.status {
            RuntimeStatus::Completed => TerminalRootStatus::Completed,
            RuntimeStatus::Faulted => TerminalRootStatus::Faulted,
            RuntimeStatus::Running => {
                return Err(invalid_host("running aggregate cannot be tombstoned"));
            }
        };
        let tombstone = RootTombstone {
            status: RootTombstoneStatus::Tombstone,
            root_runtime_id: root.aggregate_state.root_runtime_id.clone(),
            creation_id: root.aggregate_state.creation_id.clone(),
            terminal_status,
            final_aggregate_state_digest: root.aggregate_state.aggregate_state_digest.clone(),
            tombstone_operation_id: operation_id.to_string(),
        };
        let mut candidate = current.clone();
        candidate.increment_revision();
        candidate.root_record = RootRecord::Tombstone(tombstone.clone());
        candidate
            .recompute_digest()
            .map_err(|error| invalid_host(error.to_string()))?;
        self.commit_candidate(store, &current, &candidate)?;
        Ok(tombstone)
    }

    pub fn delete_checkpoint(
        &self,
        root_instance_id: &str,
        guard: &MutationGuard,
    ) -> Result<(), HostFailure> {
        let mut store = DirectStoreAccess {
            store: self.store.as_ref(),
        };
        self.delete_checkpoint_with_store(&mut store, root_instance_id, guard)
    }

    fn delete_checkpoint_with_store(
        &self,
        _store: &mut dyn StoreAccess,
        _root_instance_id: &str,
        _guard: &MutationGuard,
    ) -> Result<(), HostFailure> {
        Err(HostFailure::new(
            HostFailureCode::PhysicalDeletionUnsupported,
            "checkpoint and root identity deletion is unsupported",
        ))
    }

    fn process_delivery(
        &self,
        store: &mut dyn StoreAccess,
        request: ProcessDeliveryRequest<'_>,
    ) -> Result<DeliveryReceipt, HostFailure> {
        let ProcessDeliveryRequest {
            current,
            parsed,
            accepted_delivery_sequence,
            accepted_revision,
            foreground,
            migration,
        } = request;
        let RootRecord::Retained(root) = &current.root_record else {
            return Err(invalid_host("tombstoned root cannot dispatch"));
        };
        let aggregate_bytes = root
            .aggregate_state
            .canonical_bytes()
            .map_err(|error| invalid_host(error.to_string()))?;
        let aggregate = crate::format1::restore_aggregate(&aggregate_bytes, self.resolver.as_ref())
            .map_err(|error| invalid_host(error.to_string()))?;
        let core_delivery = match parsed.delivery_mode {
            DeliveryMode::Input => Delivery::Input(
                parsed
                    .envelope
                    .to_core_envelope()
                    .map_err(|error| invalid_host(error.to_string()))?,
            ),
            DeliveryMode::Internal => Delivery::Internal(
                parsed
                    .envelope
                    .to_core_envelope()
                    .map_err(|error| invalid_host(error.to_string()))?,
            ),
        };
        let processed = if let Some(migration) = migration {
            let outcome = crate::format1::migrate_and_dispatch(
                &aggregate_bytes,
                &migration.request,
                self.resolver.as_ref(),
                &migration.limits,
                Some(core_delivery),
            )
            .map_err(|error| invalid_host(error.to_string()))?;
            let status = outcome.migration.aggregate.root.status;
            ProcessedCore {
                aggregate: outcome.migration.aggregate,
                aggregate_envelope: outcome.migration.aggregate_envelope,
                status,
                disposition: outcome
                    .disposition
                    .ok_or_else(|| invalid_host("dispatch disposition is absent"))?,
                emissions: outcome.emissions,
                fault: outcome.fault,
                rejection: outcome.rejection,
                audit_records: outcome.migration.audit_records,
            }
        } else {
            let definition = self
                .resolver
                .resolve_definition(&aggregate.validated_bundle_fingerprint)
                .ok_or_else(|| invalid_host("current definition is unavailable"))?;
            if !definition.trusted {
                return Err(invalid_host("current definition is untrusted"));
            }
            let result = dispatch(&definition.bundle, &aggregate, Some(core_delivery));
            let state = result
                .state
                .ok_or_else(|| invalid_host("dispatch did not return aggregate state"))?;
            let (aggregate_envelope, _) = encode_aggregate(&definition.bundle, &state)
                .map_err(|error| invalid_host(error.to_string()))?;
            ProcessedCore {
                status: state.root.status,
                aggregate: state,
                aggregate_envelope,
                disposition: result
                    .disposition
                    .ok_or_else(|| invalid_host("dispatch disposition is absent"))?,
                emissions: result.emissions,
                fault: result.fault,
                rejection: result.rejection,
                audit_records: Vec::new(),
            }
        };
        let mut candidate = current.clone();
        candidate.increment_revision();
        if foreground {
            candidate.next_delivery_sequence.allocate();
        } else {
            let position = candidate
                .pending_deliveries
                .iter()
                .position(|pending| {
                    pending.delivery_sequence == accepted_delivery_sequence
                        && pending.envelope.event_id == parsed.envelope.event_id
                })
                .ok_or_else(|| invalid_host("pending delivery disappeared"))?;
            candidate.pending_deliveries.remove(position);
        }
        let receipt_sequence = candidate.next_operation_receipt_sequence.allocate();
        let committed_revision = candidate.revision.clone();
        let accepted_revision = accepted_revision.unwrap_or_else(|| committed_revision.clone());
        let outcome = DeliveryOutcome {
            status: processed.status,
            disposition: processed.disposition,
            fault: processed.fault.as_ref().map(CheckpointFault::from),
            rejection: processed
                .rejection
                .map(|value| super::wire::CheckpointRejection { code: value.code }),
        };
        let mut receipt = DeliveryReceipt {
            operation_kind: DeliveryOperationKind::Delivery,
            receipt_sequence,
            event_id: parsed.envelope.event_id,
            request_digest: parsed.envelope_digest,
            accepted_delivery_sequence,
            accepted_revision,
            delivery_mode: parsed.delivery_mode,
            origin: parsed.origin,
            committed_revision,
            resulting_aggregate_state_digest: processed
                .aggregate_envelope
                .aggregate_state_digest
                .clone(),
            outcome,
            emission_references: Vec::new(),
        };
        let RootRecord::Retained(candidate_root) = &mut candidate.root_record else {
            unreachable!("retained root checked");
        };
        candidate_root.aggregate_state = processed.aggregate_envelope;
        candidate
            .migration_audit_records
            .extend(processed.audit_records);
        receipt.emission_references = append_emissions(
            &mut candidate,
            &receipt.receipt_sequence,
            &receipt.committed_revision,
            &processed.emissions,
        )?;
        candidate
            .operation_receipts
            .push(OperationReceipt::Delivery(receipt.clone()));
        candidate
            .recompute_digest()
            .map_err(|error| invalid_host(error.to_string()))?;
        self.commit_candidate(store, &current, &candidate)?;
        drop(processed.aggregate);
        Ok(receipt)
    }

    fn commit_candidate(
        &self,
        store: &mut dyn StoreAccess,
        current: &ExecutionCheckpoint,
        candidate: &ExecutionCheckpoint,
    ) -> Result<(), HostFailure> {
        candidate
            .validate_for_persistence(self.resolver.as_ref())
            .map_err(|error| invalid_host(error.to_string()))?;
        let replacement = StoreRecord::from_checkpoint(candidate)?;
        match store.compare_and_swap(
            &current.root_instance_id,
            &current.revision.to_string(),
            &current.execution_checkpoint_digest,
            replacement,
        )? {
            StoreWriteResult::Committed => Ok(()),
            StoreWriteResult::Conflict(_) => Err(revision_conflict()),
        }
    }

    fn require_checkpoint(
        &self,
        store: &mut dyn StoreAccess,
        root_instance_id: &str,
    ) -> Result<ExecutionCheckpoint, HostFailure> {
        self.load_checkpoint_with_store(store, root_instance_id)?
            .ok_or_else(|| {
                HostFailure::new(
                    HostFailureCode::CheckpointNotFound,
                    "execution checkpoint does not exist",
                )
            })
    }

    fn restore_record(&self, record: StoreRecord) -> Result<ExecutionCheckpoint, HostFailure> {
        let checkpoint =
            super::wire::restore_execution_checkpoint(&record.bytes, self.resolver.as_ref())
                .map_err(|error| invalid_host(error.to_string()))?;
        if checkpoint.root_instance_id != record.root_instance_id
            || checkpoint.revision.to_string() != record.revision
            || checkpoint.execution_checkpoint_digest != record.execution_checkpoint_digest
        {
            return Err(invalid_host(
                "store metadata differs from checkpoint artifact",
            ));
        }
        Ok(checkpoint)
    }
}

struct ProcessedCore {
    aggregate: AggregateState,
    aggregate_envelope: crate::format1::AggregateEnvelope,
    status: RuntimeStatus,
    disposition: Disposition,
    emissions: Vec<Emission>,
    fault: Option<crate::format1::FaultRecord>,
    rejection: Option<crate::format1::Rejection>,
    audit_records: Vec<crate::format1::MigrationAuditRecord>,
}

#[derive(Debug, Clone)]
struct ParsedDeliveryCandidate {
    delivery_mode: String,
    origin: JsonValue,
    envelope: PortableEnvelope,
    envelope_digest: String,
    supplied_envelope_digest: Option<JsonValue>,
}

impl ParsedDeliveryCandidate {
    fn validate(self) -> Result<ParsedDelivery, PreAcceptanceFailureCode> {
        let delivery_mode = match self.delivery_mode.as_str() {
            "input" => DeliveryMode::Input,
            "internal" => DeliveryMode::Internal,
            _ => return Err(PreAcceptanceFailureCode::InvalidDeliveryMode),
        };
        let origin: DeliveryOrigin = serde_json::from_value(self.origin)
            .map_err(|_| PreAcceptanceFailureCode::InvalidDeliveryOrigin)?;
        if !matches!(
            (delivery_mode, &origin),
            (DeliveryMode::Input, DeliveryOrigin::HostInput(_))
                | (DeliveryMode::Internal, DeliveryOrigin::InternalEmission(_))
        ) {
            return Err(PreAcceptanceFailureCode::InvalidDeliveryOrigin);
        }
        if let Some(supplied) = self.supplied_envelope_digest {
            let Some(supplied) = supplied.as_str() else {
                return Err(PreAcceptanceFailureCode::MalformedDelivery);
            };
            if supplied != self.envelope_digest {
                return Err(PreAcceptanceFailureCode::DeliveryDigestMismatch);
            }
        }
        Ok(ParsedDelivery {
            delivery_mode,
            origin,
            envelope: self.envelope,
            envelope_digest: self.envelope_digest,
        })
    }
}

#[derive(Debug, Clone)]
struct ParsedDelivery {
    delivery_mode: DeliveryMode,
    origin: DeliveryOrigin,
    envelope: PortableEnvelope,
    envelope_digest: String,
}

struct ProcessDeliveryRequest<'a> {
    current: ExecutionCheckpoint,
    parsed: ParsedDelivery,
    accepted_delivery_sequence: Counter,
    accepted_revision: Option<Counter>,
    foreground: bool,
    migration: Option<&'a ProcessingMigration>,
}

fn parse_delivery_candidate(
    candidate: &JsonValue,
    checkpoint_root_instance_id: &str,
) -> Result<ParsedDeliveryCandidate, PreAcceptanceFailureCode> {
    let object = candidate
        .as_object()
        .ok_or(PreAcceptanceFailureCode::MalformedDelivery)?;
    if object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "root_instance_id" | "delivery_mode" | "origin" | "envelope" | "envelope_digest"
        )
    }) {
        return Err(PreAcceptanceFailureCode::MalformedDelivery);
    }
    let root_instance_id = object
        .get("root_instance_id")
        .and_then(JsonValue::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(PreAcceptanceFailureCode::MalformedDelivery)?;
    if root_instance_id != checkpoint_root_instance_id {
        return Err(PreAcceptanceFailureCode::WrongRoot);
    }
    let delivery_mode = object
        .get("delivery_mode")
        .and_then(JsonValue::as_str)
        .ok_or(PreAcceptanceFailureCode::MalformedDelivery)?
        .to_owned();
    let origin = object
        .get("origin")
        .cloned()
        .ok_or(PreAcceptanceFailureCode::MalformedDelivery)?;
    let envelope: PortableEnvelope = serde_json::from_value(
        object
            .get("envelope")
            .cloned()
            .ok_or(PreAcceptanceFailureCode::MalformedDelivery)?,
    )
    .map_err(|_| PreAcceptanceFailureCode::MalformedDelivery)?;
    if envelope.root_instance_id() != Some(checkpoint_root_instance_id) {
        return Err(PreAcceptanceFailureCode::WrongRoot);
    }
    if envelope.event_id.is_empty()
        || !valid_checkpoint_event_name(&envelope.event)
        || envelope
            .correlation_id
            .as_ref()
            .is_some_and(String::is_empty)
        || !matches!(envelope.payload, TypedValue::Map(_))
    {
        return Err(PreAcceptanceFailureCode::MalformedDelivery);
    }
    let computed = crate::checkpoint::wire::envelope_digest_for_mode(
        root_instance_id,
        &delivery_mode,
        &envelope,
    )
    .map_err(|_| PreAcceptanceFailureCode::MalformedDelivery)?;
    Ok(ParsedDeliveryCandidate {
        delivery_mode,
        origin,
        envelope,
        envelope_digest: computed,
        supplied_envelope_digest: object.get("envelope_digest").cloned(),
    })
}

fn delivery_replay(
    checkpoint: &ExecutionCheckpoint,
    event_id: &str,
    envelope_digest: &str,
) -> Result<Option<AcceptanceResult>, HostFailure> {
    if let Some(pending) = checkpoint
        .pending_deliveries
        .iter()
        .find(|pending| pending.envelope.event_id == event_id)
    {
        if pending.envelope_digest != envelope_digest {
            return Ok(Some(not_accepted(
                PreAcceptanceFailureCode::EventIdConflict,
            )));
        }
        return Ok(Some(AcceptanceResult::Pending(PendingAcceptanceResult {
            result: PendingAcceptanceResultKind::Pending,
            event_id: pending.envelope.event_id.clone(),
            delivery_sequence: pending.delivery_sequence.clone(),
            accepted_revision: pending.accepted_revision.clone(),
        })));
    }
    match committed_delivery_replay(checkpoint, event_id, envelope_digest) {
        Ok(value) => Ok(value.map(|receipt| {
            AcceptanceResult::Committed(CommittedDeliveryResult {
                result: CommittedResultKind::Committed,
                receipt,
            })
        })),
        Err(error) if error.code == HostFailureCode::EventIdConflict => Ok(Some(not_accepted(
            PreAcceptanceFailureCode::EventIdConflict,
        ))),
        Err(error) => Err(error),
    }
}

fn committed_delivery_replay(
    checkpoint: &ExecutionCheckpoint,
    event_id: &str,
    envelope_digest: &str,
) -> Result<Option<DeliveryReceipt>, HostFailure> {
    let existing = checkpoint
        .operation_receipts
        .iter()
        .find_map(|receipt| match receipt {
            OperationReceipt::Delivery(value) if value.event_id == event_id => Some(value),
            _ => None,
        });
    let Some(existing) = existing else {
        return Ok(None);
    };
    if existing.request_digest != envelope_digest {
        return Err(HostFailure::new(
            HostFailureCode::EventIdConflict,
            "committed event id has different content",
        ));
    }
    Ok(Some(existing.clone()))
}

fn valid_checkpoint_event_name(value: &str) -> bool {
    matches!(
        value,
        "determa.component_completed"
            | "determa.component_failed"
            | "determa.spawned_instance_failed"
    ) || valid_checkpoint_identifier(value)
}

fn valid_checkpoint_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z' | b'A'..=b'Z' | b'_'))
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn replay_creation(
    checkpoint: &ExecutionCheckpoint,
    creation_id: &str,
    request_digest: &str,
) -> Result<CreationReceipt, HostFailure> {
    let Some(OperationReceipt::Creation(receipt)) = checkpoint.operation_receipts.first() else {
        return Err(invalid_host("checkpoint creation receipt is absent"));
    };
    if receipt.creation_id == creation_id && receipt.request_digest == request_digest {
        Ok(receipt.clone())
    } else {
        Err(HostFailure::new(
            HostFailureCode::CreationIdConflict,
            "root identity is already reserved by another creation request",
        ))
    }
}

fn creation_request_digest(request: &CreationRequest<'_>) -> Result<String, HostFailure> {
    let bindings = Value::Map(BTreeMap::from([
        (
            "external".to_string(),
            Value::Map(request.bindings.external.clone()),
        ),
        (
            "input".to_string(),
            Value::Map(request.bindings.input.clone()),
        ),
    ]));
    let typed = TypedValue::from_value(&bindings);
    hash_tagged(json!([
        "determa-creation-request-digest-1",
        "1",
        request.bundle.fingerprint,
        request.namespace,
        request.machine_id,
        request.machine_version.to_string(),
        request.root_instance_id,
        request.creation_id,
        typed
    ]))
    .map_err(|error| invalid_host(error.to_string()))
}

fn maintenance_request_digest(
    root_instance_id: &str,
    request: &MaintenanceMigrationRequest,
) -> Result<String, HostFailure> {
    hash_tagged(json!([
        "determa-maintenance-migration-request-digest-1",
        "1",
        root_instance_id,
        request.operation_id,
        request.source_aggregate_state_digest,
        request.target_validated_bundle_fingerprint,
        request.migration_descriptor_digest_route,
        request.maintenance_mode
    ]))
    .map_err(|error| invalid_host(error.to_string()))
}

fn append_emissions(
    checkpoint: &mut ExecutionCheckpoint,
    producing_receipt_sequence: &Counter,
    committed_revision: &Counter,
    emissions: &[Emission],
) -> Result<Vec<EmissionReference>, HostFailure> {
    let mut references = Vec::with_capacity(emissions.len());
    for (index, emission) in emissions.iter().enumerate() {
        let emission_index = Counter::from(index);
        match &emission.target {
            crate::format1::Target::External => {
                let effect_id = emission
                    .effect_id
                    .clone()
                    .ok_or_else(|| invalid_host("external emission has no effect id"))?;
                let sequence = emission
                    .sequence
                    .clone()
                    .ok_or_else(|| invalid_host("external emission has no output sequence"))?;
                checkpoint.pending_outbox_intents.push(PendingOutboxIntent {
                    intent: OutboxIntent {
                        effect_id: effect_id.clone(),
                        sequence,
                        event: emission.event.clone(),
                        payload: TypedValue::from_value(&Value::Map(emission.payload.clone())),
                        correlation_id: emission.correlation_id.clone(),
                    },
                    state_revision: committed_revision.clone(),
                    delivery_state: PendingOutboxState::NotAttempted,
                });
                references.push(EmissionReference::ExternalOutbox {
                    emission_index,
                    effect_id,
                });
            }
            _ => {
                let envelope = emission
                    .envelope()
                    .ok_or_else(|| invalid_host("internal emission has no event id"))?;
                let portable = PortableEnvelope {
                    event: envelope.event,
                    event_id: envelope.event_id.clone(),
                    target: envelope.target,
                    payload: TypedValue::from_value(&Value::Map(envelope.payload)),
                    correlation_id: envelope.correlation_id,
                };
                let delivery_sequence = checkpoint.next_delivery_sequence.allocate();
                let digest = envelope_digest(
                    &checkpoint.root_instance_id,
                    DeliveryMode::Internal,
                    &portable,
                )
                .map_err(|error| invalid_host(error.to_string()))?;
                checkpoint.pending_deliveries.push(PendingDelivery {
                    delivery_sequence: delivery_sequence.clone(),
                    accepted_revision: committed_revision.clone(),
                    delivery_mode: DeliveryMode::Internal,
                    origin: DeliveryOrigin::internal(
                        producing_receipt_sequence.clone(),
                        emission_index.clone(),
                    ),
                    envelope: portable,
                    envelope_digest: digest,
                });
                references.push(EmissionReference::InternalDelivery {
                    emission_index,
                    event_id: envelope.event_id,
                    delivery_sequence,
                });
            }
        }
    }
    checkpoint
        .pending_outbox_intents
        .sort_by(|left, right| left.intent.sequence.cmp(&right.intent.sequence));
    Ok(references)
}

fn result_status_to_runtime(status: ResultStatus) -> Result<RuntimeStatus, HostFailure> {
    match status {
        ResultStatus::Running => Ok(RuntimeStatus::Running),
        ResultStatus::Completed => Ok(RuntimeStatus::Completed),
        ResultStatus::Faulted => Ok(RuntimeStatus::Faulted),
        ResultStatus::Rejected => Err(HostFailure::new(
            HostFailureCode::CreationRejected,
            "core rejected creation",
        )),
    }
}

fn check_guard(checkpoint: &ExecutionCheckpoint, guard: &MutationGuard) -> Result<(), HostFailure> {
    if checkpoint.revision.to_string() != guard.expected_revision
        || checkpoint.execution_checkpoint_digest != guard.expected_checkpoint_digest
    {
        Err(revision_conflict())
    } else {
        Ok(())
    }
}

fn acceptance_receipt(result: AcceptanceResult) -> Result<DeliveryReceipt, HostFailure> {
    match result {
        AcceptanceResult::Committed(value) => Ok(value.receipt),
        AcceptanceResult::Pending(_) => Err(HostFailure::new(
            HostFailureCode::EventIdConflict,
            "event is already pending",
        )),
        AcceptanceResult::NotAccepted(value) => Err(HostFailure::new(
            preaccept_failure_code(value.failure.code),
            "delivery was not accepted",
        )),
    }
}

fn not_accepted(code: PreAcceptanceFailureCode) -> AcceptanceResult {
    AcceptanceResult::NotAccepted(NotAcceptedResult {
        result: NotAcceptedResultKind::NotAccepted,
        failure: PreAcceptanceFailure { code },
    })
}

fn preaccept_failure_code(code: PreAcceptanceFailureCode) -> HostFailureCode {
    match code {
        PreAcceptanceFailureCode::EventIdConflict => HostFailureCode::EventIdConflict,
        _ => HostFailureCode::InvalidExecutionCheckpoint,
    }
}

fn effect_conflict() -> HostFailure {
    HostFailure::new(
        HostFailureCode::EffectIdConflict,
        "effect identity has a different or unavailable outbox record",
    )
}

fn revision_conflict() -> HostFailure {
    HostFailure::new(
        HostFailureCode::CheckpointRevisionConflict,
        "checkpoint revision or digest changed",
    )
}

fn invalid_host(message: impl Into<String>) -> HostFailure {
    HostFailure::new(HostFailureCode::InvalidExecutionCheckpoint, message)
}
