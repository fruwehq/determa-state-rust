//! Optional synchronous host for portable execution checkpoints.
//!
//! This module wraps the pure format-1 operations without changing their API or
//! semantics. Stores are injected directly for weak operations or configured
//! through the public extension registry for verified durable operations.

mod adapter_policy;
mod adapters;
mod host;
mod store;
mod types;
mod v1;

#[cfg(feature = "sqlite")]
pub(crate) use adapters::sqlite::{
    load_record as load_sqlite_record, verify_schema_contract as verify_sqlite_schema,
};
#[cfg(feature = "sqlite")]
pub(crate) use store::{validate_policy_insert, validate_policy_replacement};

#[cfg(feature = "sqlite")]
pub(crate) use v1::{checkpoint_step_v1_with_core, create_with_response};

pub use adapter_policy::{
    adapter_registration_policy, adapter_resolution_policy, conditional_adapter_policy,
};

pub use adapters::{
    FileExecutionStore, FileExecutionStoreFactory, MemoryExecutionStore,
    MemoryExecutionStoreFactory,
};
#[cfg(feature = "postgresql")]
pub use adapters::{PostgresqlExecutionStore, PostgresqlExecutionStoreFactory};
#[cfg(feature = "sqlite")]
pub use adapters::{SqliteExecutionStore, SqliteExecutionStoreFactory};
pub use host::{
    CheckpointHost, DurableCheckpointOperation, HostFailure, HostFailureCode,
    MaintenanceMigrationRequest, MutationGuard,
};
#[cfg(feature = "postgresql")]
pub use host::{
    PostgresqlHostMutation, PostgresqlHostMutationResult, PostgresqlHostTransaction,
    PostgresqlTransactionOutcome,
};
pub use store::{
    hypothetical_host_profile_matches, AdapterError, AdapterErrorCode, DurableStoreMode,
    ExecutionStore, ExecutionStoreCapability, ExecutionStoreFactory, HealthStatus, HostFeature,
    HostProfile, OutboxRetentionMode, ReceiptRetentionMode, StoreError, StoreErrorCode,
    StoreRecord, StoreWriteResult,
};
pub use types::{
    AdmissionSource, CheckpointErrorCode, DurableCheckpointExecution, DurableContractExecution,
    DurableFailurePolicy, DurableHostExecution, DurableHostResult, DurableProcessRequest,
    DurableQuarantineReleaseRequest, OutboxIntent, PendingOutboxState, PreAcceptanceFailureCode,
    ProcessingRequest, PruneRequest, ScopedStoreRecord, StoreScope, TerminalOutboxOutcome,
    TransactionalProcessRequest,
};
pub use v1::{
    checkpoint_admit_v1 as admit, checkpoint_compact_outbox as compact_outbox,
    checkpoint_process as process, checkpoint_process_with_migration as process_with_migration,
    checkpoint_prune_v1 as prune, checkpoint_step_v1 as step,
    checkpoint_terminalize_outbox as terminalize_outbox,
    checkpoint_tombstone_root as tombstone_root,
    checkpoint_update_pending_outbox as update_pending_outbox,
    create_execution_checkpoint_v1 as create, creation_request_digest,
    restore_execution_checkpoint as restore, ExecutionCheckpoint,
};
