//! Rust implementation of the portable Determa State `format: 1` core and
//! optional synchronous execution-checkpoint host.
//!
//! The core is a pure foreground transform. [`format1::create`] creates one root
//! ownership aggregate and [`format1::dispatch`] applies one caller-owned envelope.
//! Queueing and timers remain host profiles. Portable aggregate persistence and
//! definition migration are exposed as pure format-1 operations.

pub mod checkpoint;
pub mod cli;
pub mod format1;
pub mod value;

/// Exact normative specification revision implemented by this crate.
pub const FORMAT_1_SPECIFICATION_COMMIT: &str = "7782671b56165a59caa61a65c29fefc63105ebf8";

/// Exact core conformance revision exercised by this crate.
pub const FORMAT_1_CONFORMANCE_COMMIT: &str = "d6a45d31614ee25de20476ed93f10e14997d882c";

pub use format1::{
    create, decode_selected_migration_descriptor, dispatch, encode_aggregate, load_bundle,
    load_bundle_from_json, migrate_aggregate, migrate_and_dispatch, restore_aggregate,
    restore_package, restore_package_and_migrate, AggregateEnvelope, AggregateState, Bindings,
    Bundle, CoreResult, Counter, CreationRejectionCode, DefinitionResolver, Delivery,
    DispatchRejectionCode, Disposition, Emission, EngineFaultCode, Envelope, FaultRecord,
    InMemoryDefinitionResolver, LoadError, LoadErrorCode, MigrationArtifactResolver,
    MigrationAuditRecord, MigrationDispatchOutcome, MigrationOutcome, MigrationRequest,
    PersistenceError, PersistenceErrorCode, Rejection, ResourceLimits, RestoredPackage,
    ResultStatus, RuntimeStatus, Target, TypedValue, CREATION_REJECTION_CODES,
    DISPATCH_REJECTION_CODES, ENGINE_FAULT_CODES,
};
pub use value::{string_from_utf16, InstanceReference, InvalidUnicodeString, Value};
