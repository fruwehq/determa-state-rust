# Determa State for Rust

Rust implementation of the portable [Determa State](https://github.com/fruwehq/determa-state-spec)
`format: 1` core.

Repository metadata prepares synchronized version `0.1.0`. This branch is validated
against the merged `0.1.0` metadata revisions at these exact normative inputs:

- specification commit `c1635d74e6a216301a8986d37be8ce7e7111dfd7`;
- conformance commit `600523ca08c3b8a6ee790439a32dc4ce47f71b95`.

Until the coordinated `v0.1.0` tag publishes, the latest crate on crates.io remains
version `0.0.7`.

Correctness is defined by the language-agnostic conformance suite. The Rust integration
tests run all 110 format-1 core cases, 105 portable persistence vectors, and 12 steps
across the six persistence host profiles.

## Implemented core

- Strict format-1 YAML 1.2 and JSON loading, schema validation, semantic validation,
  portable scalar rules, and normalized bundle fingerprints.
- Multiple machines per bundle, shared and private events, typed payloads and
  variables, and the portable CEL profile.
- Hierarchical dispatch, ordered guards, internal/local/unmarked transitions, choices,
  history, entry/exit actions, final states, and `stop`.
- Isolated synchronous components with explicit routing.
- Owned spawned instances, nominal references, cancellation, completion, failure
  propagation, and deterministic lifecycle cleanup.
- Pure `create` and `dispatch` operations with deterministic runtime, cause, event, and
  external-effect identities.
- Portable aggregate serialization and restoration with strict typed values, canonical
  JSON, content-addressed definitions, and self-contained aggregate packages.
- Resolver-backed compatible and transforming definition migration, exact route
  execution, resource limits, audit records, and atomic migration-and-dispatch.
- Inspection through the returned logical aggregate state, result disposition, fault,
  rejection, configuration, variables, components, owned instances, and emissions.

The portable core does not own queues, broker acknowledgement, timers, package imports,
or a background scheduler. Hosts provide artifact storage, resolver trust policy,
transaction boundaries, and transport integration around the pure state and migration
operations. The command-line binary currently provides bundle validation only; it does
not claim a portable CLI execution profile.

## Build and test

```sh
git submodule update --init
cargo build --release
cargo test
cargo clippy --all-targets -- -D warnings
```

The submodule must resolve to
`600523ca08c3b8a6ee790439a32dc4ce47f71b95`. CI also checks that all bundled schemas
are identical to the schemas at specification commit
`c1635d74e6a216301a8986d37be8ce7e7111dfd7`. These exact merged commits are the
authoritative release inputs; tag publication is a later coordinated release operation.

## Library

```rust
use determa_state::{
    create, dispatch, load_bundle, Bindings, Delivery, Envelope, Target, Value,
};
use std::collections::BTreeMap;

let source = std::fs::read_to_string("examples/minimal.yaml")?;
let bundle = load_bundle(&source)?;
let created = create(
    &bundle,
    "turnstile",
    "turnstile-1",
    "create-1",
    &Bindings::default(),
);
let state = created.state.expect("creation succeeds");

let result = dispatch(
    &bundle,
    &state,
    Some(Delivery::Input(Envelope {
        event: "coin".to_string(),
        event_id: "input-1".to_string(),
        target: Target::Root {
            root_instance_id: state.root_instance_id.clone(),
            root_runtime_id: state.root.runtime_id.clone(),
        },
        payload: BTreeMap::from([("amount".to_string(), Value::Int(100))]),
        correlation_id: None,
    })),
);

assert_eq!(
    result.state.expect("dispatch succeeds").root.config(),
    vec!["unlocked"]
);
# Ok::<(), Box<dyn std::error::Error>>(())
```

Input and internal envelopes are caller-owned. Internal emissions may be delivered back
through `dispatch` explicitly. External emissions are deterministic output intents for
the host to persist and deliver.

## CLI

```sh
cargo run -- validate examples/minimal.yaml
cargo run -- --version
```

## License

MIT. See [LICENSE](LICENSE).
