//! Optional synchronous host for portable execution checkpoints.
//!
//! This module wraps the pure format-1 operations without changing their API or
//! semantics. Stores are injected directly as trait objects or resolved through
//! an explicitly populated public registry.

mod adapters;
mod host;
mod store;
mod v2;
mod wire;

pub use adapters::{
    register_bundled_adapters, FileExecutionStore, FileExecutionStoreFactory, MemoryExecutionStore,
    MemoryExecutionStoreFactory,
};
#[cfg(feature = "postgresql")]
pub use adapters::{PostgresqlExecutionStore, PostgresqlExecutionStoreFactory};
#[cfg(feature = "sqlite")]
pub use adapters::{SqliteExecutionStore, SqliteExecutionStoreFactory};
pub use host::{
    CheckpointHost, CreationRequest, DeliveryRequest, HostFailure, HostFailureCode,
    MaintenanceMigrationRequest, MutationGuard, ProcessingMigration,
};
#[cfg(feature = "postgresql")]
pub use host::{
    PostgresqlHostMutation, PostgresqlHostMutationResult, PostgresqlHostTransaction,
    PostgresqlTransactionOutcome,
};
pub use store::{
    validate_store_host_profile, AdapterError, AdapterErrorCode, AdapterRegistry, DurableStoreMode,
    ExecutionStore, ExecutionStoreCapability, ExecutionStoreFactory, HealthStatus, HostFeature,
    HostProfile, OutboxRetentionMode, ReceiptRetentionMode, StoreError, StoreErrorCode,
    StoreRecord, StoreWriteResult,
};
pub use v2::{
    checkpoint_admit_v2, checkpoint_compact_outbox_v2, checkpoint_maintenance_migration_v2,
    checkpoint_prune_v2, checkpoint_step_v2, checkpoint_terminalize_outbox_v2,
    checkpoint_tombstone_root_v2, checkpoint_update_pending_outbox_v2,
    create_execution_checkpoint_v2, creation_request_digest_v2, restore_execution_checkpoint_v2,
    upgrade_execution_checkpoint_v1_to_v2, ExecutionCheckpointV2,
};
pub use wire::{
    restore_execution_checkpoint, validate_outbox_compaction, AcceptanceResult, BoundedReplayMode,
    BoundedReplayRetention, CheckpointError, CheckpointErrorCode, CheckpointFault,
    CheckpointRejection, CommittedDeliveryResult, CommittedResultKind, CreationOperationKind,
    CreationReceipt, DeliveryMode, DeliveryOperationKind, DeliveryOrigin, DeliveryOutcome,
    DeliveryReceipt, EmissionReference, ExecutionCheckpoint, HostInputOrigin, HostInputOriginKind,
    InternalEmissionOrigin, InternalEmissionOriginKind, MaintenanceMigrationOperationKind,
    MaintenanceMigrationReceipt, MaintenanceMigrationResultCode, NotAcceptedResult,
    NotAcceptedResultKind, OperationReceipt, OutboxEffectTombstone, OutboxIntent, OutboxRecord,
    PendingAcceptanceResult, PendingAcceptanceResultKind, PendingDelivery, PendingOutboxIntent,
    PendingOutboxState, PermanentReplayMode, PermanentReplayRetention, PortableEnvelope,
    PreAcceptanceFailure, PreAcceptanceFailureCode, ReplayRetention, RetainedRootRecord,
    RetainedRootStatus, RootRecord, RootTombstone, RootTombstoneStatus, TerminalOutboxOutcome,
    TerminalOutboxRecord, TerminalRootStatus,
};
