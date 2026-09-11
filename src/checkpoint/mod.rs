//! Optional synchronous host for portable execution checkpoints.
//!
//! This module wraps the pure format-1 operations without changing their API or
//! semantics. Stores are injected directly as trait objects or resolved through
//! an explicitly populated public registry.

mod adapters;
mod host;
mod store;
mod types;
mod v2;

pub use adapters::{
    register_bundled_adapters, FileExecutionStore, FileExecutionStoreFactory, MemoryExecutionStore,
    MemoryExecutionStoreFactory,
};
#[cfg(feature = "postgresql")]
pub use adapters::{PostgresqlExecutionStore, PostgresqlExecutionStoreFactory};
#[cfg(feature = "sqlite")]
pub use adapters::{SqliteExecutionStore, SqliteExecutionStoreFactory};
pub use host::{
    CheckpointHost, HostFailure, HostFailureCode, MaintenanceMigrationRequest, MutationGuard,
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
pub use types::{
    AdmissionSource, CheckpointErrorCode, OutboxIntent, PendingOutboxState,
    PreAcceptanceFailureCode, ProcessingRequest, PruneRequest, TerminalOutboxOutcome,
    TransactionalProcessRequest,
};
pub use v2::{
    checkpoint_admit_v2 as admit, checkpoint_compact_outbox as compact_outbox,
    checkpoint_process as process, checkpoint_process_with_migration as process_with_migration,
    checkpoint_prune_v2 as prune, checkpoint_step_v2 as step,
    checkpoint_terminalize_outbox as terminalize_outbox,
    checkpoint_tombstone_root as tombstone_root,
    checkpoint_update_pending_outbox as update_pending_outbox,
    create_execution_checkpoint_v2 as create, creation_request_digest,
    restore_execution_checkpoint as restore, ExecutionCheckpoint,
};
