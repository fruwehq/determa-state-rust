//! Rust implementation of the portable Determa State `format: 1` core and
//! optional synchronous execution-checkpoint host.
//!
//! The core is a pure queue-bearing foreground transform. [`format1::create`] creates
//! one root ownership aggregate, [`format1::admit`] accepts caller-owned deliveries,
//! and [`format1::step`] processes ready work. Timers remain host profiles. Portable
//! aggregate persistence and definition migration are exposed as pure format-1
//! operations.

pub mod checkpoint;
pub mod cli;
pub mod format1;
pub mod value;

/// Exact normative specification revision implemented by this crate.
pub const FORMAT_1_SPECIFICATION_COMMIT: &str = "6796b554b976627c68fc746ec5629629aaf2b38e";

/// Exact core conformance revision exercised by this crate.
pub const FORMAT_1_CONFORMANCE_COMMIT: &str = "a586417292d0a5cac8d07e1164669688c407a7e1";

pub use format1::{
    admit, create, load_bundle, load_bundle_from_json, migrate_aggregate, migrate_aggregate_route,
    restore_aggregate, restore_package, step, validate_artifact, validate_contract_artifact,
    validate_migration_descriptor, AdmissionDelivery, Aggregate, ArtifactError, Bindings, Bundle,
    Counter, CreationRejectionCode, DefinitionResolver, DispatchRejectionCode, Disposition,
    EngineFaultCode, InMemoryDefinitionResolver, LoadError, LoadErrorCode,
    MigrationArtifactResolver, MigrationRequest, PersistenceError, PersistenceErrorCode,
    QueueEnvelope, ResourceLimits, RestoredPackage, Target, TypedValue,
};
pub use value::{string_from_utf16, InstanceReference, InvalidUnicodeString, Value};
