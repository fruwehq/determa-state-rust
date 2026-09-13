mod cel;
mod compile;
mod counter;
mod migration;
mod model;
pub(crate) mod native;
mod package;
mod persistence;
mod runtime;
mod source;
pub(crate) mod strict_json;
pub(crate) mod v2;

pub use compile::{Bundle, SemanticError};
pub use counter::Counter;
pub use migration::{MigrationRequest, ResourceLimits};
pub use model::{Bindings, DefinitionBinding, IdentityOrigin, MachineIdentity, Target};
pub use native::{PersistenceError, PersistenceErrorCode, TypedValue};
pub use package::{restore_package_v2 as restore_package, RestoredPackageV2 as RestoredPackage};
pub use persistence::{
    DefinitionResolver, InMemoryDefinitionResolver, MigrationArtifactResolver, ResolvedDefinition,
    ResolvedMigrationDescriptor,
};
pub use runtime::{
    CreationRejectionCode, DispatchRejectionCode, Disposition, EngineFaultCode,
    NativeAggregate as Aggregate,
};
pub use source::{load_bundle, load_bundle_from_json, parse_document, LoadError, LoadErrorCode};
pub use v2::{
    admit_v2 as admit, create_v2 as create, migrate_aggregate_v2 as migrate_aggregate,
    migrate_aggregate_v2_route as migrate_aggregate_route,
    restore_aggregate_v2 as restore_aggregate, step_v2 as step,
    validate_migration_descriptor_v2 as validate_migration_descriptor,
    AdmissionDelivery as Delivery, QueueEnvelope as Envelope, Version2Error as ArtifactError,
};
