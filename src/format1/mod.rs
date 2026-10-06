mod cel;
mod compile;
mod contracts;
mod counter;
pub mod effect_journal;
mod inspection;
mod inspection_cel;
pub(crate) mod migration;
mod model;
pub(crate) mod native;
mod package;
mod persistence;
pub mod providers;
mod runtime;
#[cfg(all(test, determa_repository_conformance))]
mod runtime_conformance;
mod source;
pub(crate) mod strict_json;
pub(crate) mod v1;

pub use compile::{Bundle, SemanticError};
pub use contracts::{validate_artifact, validate_contract_artifact};
pub use counter::Counter;
pub use inspection::{
    inspect_candidate, InspectionCapabilities, InspectionDispositionCode, InspectionFailureCode,
    InspectionReasonCode,
};
#[cfg(determa_repository_conformance)]
pub use inspection_cel::observed_inspection_guards;
pub use migration::{MigrationRequest, ResourceLimits};
pub use model::{Bindings, DefinitionBinding, IdentityOrigin, MachineIdentity, Target};
pub use native::{PersistenceError, PersistenceErrorCode, TypedValue};
pub use package::{restore_package_v1 as restore_package, RestoredPackageV1 as RestoredPackage};
pub use persistence::{
    DefinitionResolver, InMemoryDefinitionResolver, MigrationArtifactResolver, ResolvedDefinition,
    ResolvedMigrationDescriptor,
};
pub use providers::compile_language_source;
pub use runtime::{
    CreationRejectionCode, DispatchRejectionCode, Disposition, EngineFaultCode,
    NativeAggregate as Aggregate,
};
pub use source::{
    load_bundle, load_bundle_from_json, load_bundle_with_providers, parse_document, LoadError,
    LoadErrorCode,
};
pub use v1::{
    admit_v1 as admit, create_v1 as create, migrate_aggregate_v1 as migrate_aggregate,
    migrate_aggregate_v1_route as migrate_aggregate_route,
    restore_aggregate_v1 as restore_aggregate, step_v1 as step,
    validate_migration_descriptor_v1 as validate_migration_descriptor, AdmissionDelivery,
    QueueEnvelope, Version1Error as ArtifactError,
};

#[cfg(feature = "sqlite")]
pub(crate) use contracts::validate_native_core_step_result;

#[cfg(feature = "sqlite")]
pub(crate) use contracts::validate_native_effect_result_request;

#[cfg(feature = "sqlite")]
pub(crate) use contracts::validate_native_effect_result_response;

#[cfg(feature = "sqlite")]
pub(crate) use contracts::{
    validate_native_effect_cancellation_request, validate_native_effect_cancellation_response,
};
