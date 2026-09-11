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
pub const FORMAT_1_SPECIFICATION_COMMIT: &str = "2e33036563cb966b07124197db672159b4b7e1f4";

/// Exact core conformance revision exercised by this crate.
pub const FORMAT_1_CONFORMANCE_COMMIT: &str = "531468c59c7a2dc32f5cbe92cfabf89805d27f6a";

pub use format1::step_v2;
pub use format1::{
    admit_v2, create, create_v2, decode_selected_migration_descriptor, dispatch,
    downgrade_aggregate_v2_to_v1, encode_aggregate, load_bundle, load_bundle_from_json,
    migrate_aggregate, migrate_aggregate_v2, migrate_aggregate_v2_route, migrate_and_dispatch,
    restore_aggregate, restore_aggregate_v2, restore_package, restore_package_and_migrate,
    restore_package_v2, upgrade_aggregate_v1_to_v2, AdmissionDelivery, AggregateEnvelope,
    AggregateState, Bindings, Bundle, CoreResult, Counter, CreationRejectionCode,
    DefinitionResolver, Delivery, DispatchRejectionCode, Disposition, Emission, EngineFaultCode,
    Envelope, FaultRecord, InMemoryDefinitionResolver, LoadError, LoadErrorCode,
    MigrationArtifactResolver, MigrationAuditRecord, MigrationDispatchOutcome, MigrationOutcome,
    MigrationRequest, PersistenceError, PersistenceErrorCode, QueueBearingAggregate, QueueEnvelope,
    Rejection, ResourceLimits, RestoredPackage, RestoredPackageV2, ResultStatus, RuntimeStatus,
    Target, TypedValue, Version2Error, CREATION_REJECTION_CODES, DISPATCH_REJECTION_CODES,
    ENGINE_FAULT_CODES,
};
pub use value::{string_from_utf16, InstanceReference, InvalidUnicodeString, Value};
