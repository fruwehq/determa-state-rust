//! Rust implementation of the portable Determa State `format: 1` core.
//!
//! The core is a pure foreground transform. [`format1::create`] creates one root
//! ownership aggregate and [`format1::dispatch`] applies one caller-owned envelope.
//! Queueing and timers remain host profiles. Portable aggregate persistence and
//! definition migration are exposed as pure format-1 operations.

pub mod cli;
pub mod format1;
pub mod value;

/// Exact normative specification revision implemented by this crate.
pub const FORMAT_1_SPECIFICATION_COMMIT: &str = "1502a58a780d837e05bfacb37680dfc92e3488b5";

/// Exact core conformance revision exercised by this crate.
pub const FORMAT_1_CONFORMANCE_COMMIT: &str = "707a49ce01c6f57f673c1959cdfe078bc8d0fc9a";

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
