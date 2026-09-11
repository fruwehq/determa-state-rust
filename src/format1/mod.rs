mod cel;
mod compile;
mod counter;
mod migration;
mod model;
mod package;
mod persistence;
mod runtime;
mod source;
pub(crate) mod strict_json;
pub(crate) mod v2;
pub(crate) mod wire;

pub use compile::{Bundle, SemanticError};
pub use counter::Counter;
pub use migration::{
    aggregate_shape_fingerprint, decode_selected_migration_descriptor, migrate_aggregate,
    migrate_and_dispatch, MigrationAuditRecord, MigrationDispatchOutcome, MigrationOutcome,
    MigrationRequest, ResourceLimits,
};
pub use model::{
    Bindings, DefinitionBinding, Delivery, Envelope, IdentityOrigin, MachineIdentity, Target,
};
pub use package::{
    restore_package, restore_package_and_migrate, restore_package_v2, RestoredPackage,
    RestoredPackageV2,
};
pub use persistence::{
    DefinitionResolver, InMemoryDefinitionResolver, MigrationArtifactResolver, ResolvedDefinition,
    ResolvedMigrationDescriptor,
};
pub use runtime::{
    create, dispatch, AggregateState, ComponentRuntime, CoreResult, CreationRejectionCode,
    DispatchRejectionCode, Disposition, Emission, EngineFaultCode, FaultRecord, OwnedRuntime,
    Rejection, ResultStatus, RuntimeRelation, RuntimeState, RuntimeStatus, VariableSlot,
    CREATION_REJECTION_CODES, DISPATCH_REJECTION_CODES, ENGINE_FAULT_CODES,
};
pub use source::{load_bundle, load_bundle_from_json, parse_document, LoadError, LoadErrorCode};
pub use v2::{
    admit_v2, create_v2, downgrade_aggregate_v2_to_v1, migrate_aggregate_v2, restore_aggregate_v2,
    step_v2, upgrade_aggregate_v1_to_v2, AdmissionDelivery, QueueBearingAggregate, QueueEnvelope,
    Version2Error,
};
pub use wire::{
    encode_aggregate, restore_aggregate, AggregateEnvelope, PersistenceError, PersistenceErrorCode,
    TypedValue,
};
