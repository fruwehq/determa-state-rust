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
pub const FORMAT_1_SPECIFICATION_COMMIT: &str = "ee38796d5e38e67e350a06548fd50faa530cbb12";

/// Exact core conformance revision exercised by this crate.
pub const FORMAT_1_CONFORMANCE_COMMIT: &str = "99a4d9ad5256f7330e75b06d48f340cc7239a40d";

pub use format1::{
    admit, create, load_bundle, load_bundle_from_json, migrate_aggregate, migrate_aggregate_route,
    restore_aggregate, restore_package, step, Aggregate, ArtifactError, Bindings, Bundle, Counter,
    CreationRejectionCode, DefinitionResolver, Delivery, DispatchRejectionCode, Disposition,
    EngineFaultCode, Envelope, InMemoryDefinitionResolver, LoadError, LoadErrorCode,
    MigrationArtifactResolver, MigrationRequest, PersistenceError, PersistenceErrorCode,
    ResourceLimits, RestoredPackage, Target, TypedValue, CREATION_REJECTION_CODES,
    DISPATCH_REJECTION_CODES, ENGINE_FAULT_CODES,
};
pub use value::{string_from_utf16, InstanceReference, InvalidUnicodeString, Value};
