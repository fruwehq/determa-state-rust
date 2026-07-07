//! Determa State — a Rust implementation of the Determa State statechart engine.
//!
//! Implements Determa State spec **v0.0.6**. Correctness is defined by the language-agnostic
//! conformance suite at <https://github.com/fruwehq/determa-state-conformance> (pinned at
//! tag `v0.0.6`). See `SPEC.md` in the spec repository for the normative text.
//!
//! This crate exposes an embeddable library API (SPEC §2) and a standard `determa-state` //! CLI (`src/bin/determa_state.rs`, SPEC §13).
//!
//! # Example
//! ```
//! use determa_state::{build_machine, load_machines};
//! let docs = load_machines(include_str!("../examples/minimal.yaml"))
//!     .expect("minimal.yaml parses");
//! let (valid, _errs) = determa_state::validate(&docs, &[]);
//! assert!(valid);
//! let _machine = build_machine(&docs[0]).expect("builds");
//! ```
//!
//! Machines can also be built in code from a native value (no YAML text), e.g.
//! with the `serde_json::json!` macro:
//! ```
//! use determa_state::{build_machine, load_machine_from_value};
//! use serde_json::json;
//! let raw = load_machine_from_value(json!({
//!     "id": "ping",
//!     "top": {"initial": {"transition_to": "up"}, "states": {"up": {}}}
//! })).expect("parses");
//! let _machine = build_machine(&raw).expect("builds");
//! ```

pub mod cel;
pub mod cli;
pub mod export;
pub mod loader;
pub mod machine;
pub mod model;
pub mod runtime;
pub mod store;
pub mod validate;
pub mod value;

pub use loader::{load_contract, load_machine_from_value, load_machines, load_machines_from_values, LoadError};
pub use validate::{validate, Contract};

pub use machine::{build as build_machine, resolve_definitions, Machine, NodeId, Scope};
pub use runtime::{Engine, Mode, RunResult, Snapshot, Status, StepRecord};
pub use value::Value;
