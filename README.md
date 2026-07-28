# Determa State for Rust

Rust implementation of the portable [Determa State](https://github.com/fruwehq/determa-state-spec)
`format: 1` core.

Repository metadata targets synchronized version `0.0.7` using these normative inputs:

- specification commit `09c717a40c75b99612e54d764b5f1bdfa4b94f96`;
- conformance commit `74e477087fd31561600aacf652cccae571a5ea9a`.

Until the coordinated `v0.0.7` tag publishes, the latest crate on crates.io remains
version `0.0.6`.

Correctness is defined by the language-agnostic conformance suite. The Rust integration
test runs every one of its 88 core cases.

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
- Inspection through the returned logical aggregate state, result disposition, fault,
  rejection, configuration, variables, components, owned instances, and emissions.

The portable core does not own queues, persistence, broker acknowledgement, timers,
snapshots, definition migration, package imports, or a background scheduler. A host may
build those profiles around the pure state boundary. The command-line binary currently
provides bundle validation only; it does not claim a portable CLI execution profile.

## Build and test

```sh
git submodule update --init
cargo build --release
cargo test
cargo clippy --all-targets -- -D warnings
```

The submodule must resolve to
`74e477087fd31561600aacf652cccae571a5ea9a`. CI also checks that the bundled schema is
identical to the schema at specification commit
`09c717a40c75b99612e54d764b5f1bdfa4b94f96`.

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
