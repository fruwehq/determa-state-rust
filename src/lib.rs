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
pub const FORMAT_1_SPECIFICATION_COMMIT: &str = "3f2dc4217971d5c6598436b19e415c53ec095dfe";

/// Exact core conformance revision exercised by this crate.
pub const FORMAT_1_CONFORMANCE_COMMIT: &str = "e72f72396fae44cbee323bf988d86966235dbd16";

pub use format1::step_v2;
pub use format1::{
    admit_v2, create, create_v2, dispatch, load_bundle, load_bundle_from_json,
    migrate_aggregate_v2, migrate_aggregate_v2_route, restore_aggregate_v2, restore_package_v2,
    AdmissionDelivery, AggregateState, Bindings, Bundle, CoreResult, Counter,
    CreationRejectionCode, DefinitionResolver, Delivery, DispatchRejectionCode, Disposition,
    Emission, EngineFaultCode, Envelope, FaultRecord, InMemoryDefinitionResolver, LoadError,
    LoadErrorCode, MigrationArtifactResolver, MigrationRequest, PersistenceError,
    PersistenceErrorCode, QueueBearingAggregate, QueueEnvelope, Rejection, ResourceLimits,
    RestoredPackageV2, ResultStatus, RuntimeStatus, Target, TypedValue, Version2Error,
    CREATION_REJECTION_CODES, DISPATCH_REJECTION_CODES, ENGINE_FAULT_CODES,
};
pub use value::{string_from_utf16, InstanceReference, InvalidUnicodeString, Value};
