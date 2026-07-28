//! Rust implementation of the portable Determa State `format: 1` core.
//!
//! The core is a pure foreground transform. [`format1::create`] creates one root
//! ownership aggregate and [`format1::dispatch`] applies one caller-owned envelope.
//! Queueing, persistence, timers, migration, and CLI wire formats are host profiles,
//! not portable core behavior.

pub mod cli;
pub mod format1;
pub mod value;

/// Exact normative specification revision implemented by this crate.
pub const FORMAT_1_SPECIFICATION_COMMIT: &str = "03771fac569a47b82f27891cd3700d4d1d876f8b";

/// Exact core conformance revision exercised by this crate.
pub const FORMAT_1_CONFORMANCE_COMMIT: &str = "409bbdc6c2d4a4e9d50ddb1d994c5f5cd7d97762";

pub use format1::{
    create, dispatch, load_bundle, load_bundle_from_json, AggregateState, Bindings, Bundle,
    CoreResult, Delivery, Disposition, Emission, Envelope, FaultRecord, LoadError, LoadErrorCode,
    Rejection, ResultStatus, RuntimeStatus, Target,
};
pub use value::{InstanceReference, Value};
