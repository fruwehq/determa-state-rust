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
pub const FORMAT_1_SPECIFICATION_COMMIT: &str = "4bd4d9588d11b75d376380b6120676a056a4bc45";

/// Exact core conformance revision exercised by this crate.
pub const FORMAT_1_CONFORMANCE_COMMIT: &str = "ffbc65cbce49733803119a7dabf02a9727819ba8";

pub use format1::{
    create, dispatch, load_bundle, load_bundle_from_json, AggregateState, Bindings, Bundle,
    CoreResult, Counter, Delivery, Disposition, Emission, Envelope, FaultRecord, LoadError,
    LoadErrorCode, Rejection, ResultStatus, RuntimeStatus, Target,
};
pub use value::{string_from_utf16, InstanceReference, InvalidUnicodeString, Value};
