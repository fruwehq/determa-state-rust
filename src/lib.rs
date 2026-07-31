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
pub const FORMAT_1_SPECIFICATION_COMMIT: &str = "318ef1f16ae024770090bd338c8b70056df2855b";

/// Exact core conformance revision exercised by this crate.
pub const FORMAT_1_CONFORMANCE_COMMIT: &str = "86cb08a98267371b96b8f4908409aee022e4b4fe";

pub use format1::{
    create, dispatch, encode_aggregate, load_bundle, load_bundle_from_json, migrate_aggregate,
    migrate_and_dispatch, restore_aggregate, restore_package, restore_package_and_migrate,
    AggregateEnvelope, AggregateState, Bindings, Bundle, CoreResult, Counter, DefinitionResolver,
    Delivery, Disposition, Emission, Envelope, FaultRecord, InMemoryDefinitionResolver, LoadError,
    LoadErrorCode, MigrationArtifactResolver, MigrationAuditRecord, MigrationDispatchOutcome,
    MigrationOutcome, MigrationRequest, PersistenceError, PersistenceErrorCode, Rejection,
    ResourceLimits, RestoredPackage, ResultStatus, RuntimeStatus, Target, TypedValue,
};
pub use value::{string_from_utf16, InstanceReference, InvalidUnicodeString, Value};
