//! harel — a Rust implementation of the harel statechart engine.
//!
//! Implements harel spec **v0.0.2**. Correctness is defined by the language-agnostic
//! conformance suite at <https://github.com/fruwehq/harel-conformance> (pinned at
//! tag `v0.0.2`). See `SPEC.md` in the spec repository for the normative text.
//!
//! This crate exposes an embeddable library API (SPEC §2) and a standard `harel`
//! CLI (`src/bin/harel.rs`, SPEC §13).
//!
//! # Example
//! ```
//! use harel::{build_machine, load_machines};
//! let docs = load_machines(include_str!("../examples/minimal.yaml"))
//!     .expect("minimal.yaml parses");
//! let (valid, _errs) = harel::validate(&docs, &[]);
//! assert!(valid);
//! let _machine = build_machine(&docs[0]).expect("builds");
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

pub use loader::{load_contract, load_machines, LoadError};
pub use validate::{validate, Contract};

pub use machine::{build as build_machine, resolve_definitions, Machine, NodeId, Scope};
pub use runtime::{Engine, Mode, RunResult, Snapshot, Status, StepRecord};
pub use value::Value;
