# Determa State for Rust

Rust implementation of the portable [Determa State](https://github.com/fruwehq/determa-state-spec)
`format: 1` core with an optional synchronous portable execution-checkpoint host.

Repository metadata prepares synchronized version `0.2.0`. The latest published crate
remains `0.1.0` until the coordinated `v0.2.0` tag runs the release workflow. This
branch is validated against the merged `0.2.0` metadata revisions at these exact
normative inputs:

- specification commit `2e33036563cb966b07124197db672159b4b7e1f4`;
- conformance commit `531468c59c7a2dc32f5cbe92cfabf89805d27f6a`.

Correctness is defined by the language-agnostic conformance suite. The Rust integration
tests run all 114 format-1 core cases, 108 version-1 and 15 version-2 portable
persistence vectors, and 12 steps
across the six persistence host profiles. The execution-checkpoint integration test
runs all 99 version-1 and 53 version-2 host vectors. The version-2 harnesses cover 106
vectors and 143 artifacts in total.

## Implemented core

- Strict format-1 YAML 1.2 and JSON loading, schema validation, semantic validation,
  portable scalar rules, and normalized bundle fingerprints.
- Multiple machines per bundle, shared and private events, typed payloads and
  variables, and the portable CEL profile.
- Hierarchical dispatch, ordered guards, internal/local/unmarked transitions, choices,
  history, entry/exit actions, final states, UML event deferral, and `stop`.
- Isolated synchronous components with explicit routing.
- Owned spawned instances, nominal references, cancellation, completion, failure
  propagation, and deterministic lifecycle cleanup.
- Pure `create` and `dispatch` operations with deterministic runtime, cause, event, and
  external-effect identities.
- Portable aggregate serialization and restoration with strict typed values, canonical
  JSON, content-addressed definitions, queue-bearing version-2 artifacts, and
  self-contained aggregate packages.
- Resolver-backed compatible and transforming definition migration, exact route
  execution, resource limits, audit records, and atomic migration-and-dispatch.
- Strict execution-checkpoint Serde types, canonical digests, semantic restoration,
  operation receipts, durable pending delivery, outbox lifecycle, bounded retention,
  migration audit, root tombstones, and revision/digest compare-and-swap.
- Direct execution-store trait-object injection and an initially empty public adapter
  registry. Bundled adapters use only the same public registration route available to
  third-party factories.
- Default `memory`, `file`, and bundled-SQLite adapters plus optional PostgreSQL,
  with explicit durable receipt/outbox modes and schema-contract health checks.
- Inspection through the returned logical aggregate state, result disposition, fault,
  rejection, configuration, variables, components, owned instances, and emissions.
- Immutable `PORTABLE_CODES` slices on public closed-code enums, including
  `CreationRejectionCode`, `DispatchRejectionCode`, and `EngineFaultCode`, plus
  `CREATION_REJECTION_CODES`, `DISPATCH_REJECTION_CODES`, and `ENGINE_FAULT_CODES` for
  compatibility with the existing string-slice API.

The portable core remains a pure foreground transform and does not own queues, broker
acknowledgement, timers, package imports, or a background scheduler. The optional host
persists SPEC section 17 state around those unchanged operations. Broker adapters,
workers, transport integration, and application response data remain application
concerns. The command-line binary still provides bundle validation only.

## Build and test

The minimum supported Rust version (MSRV) is `1.86`. CI verifies the locked default and
all-features dependency graph with that toolchain, including PostgreSQL compile and test
coverage. Stable Rust remains the toolchain for formatting and clippy.

```sh
git submodule update --init
cargo +1.86.0 build --release --locked --all-features
cargo +1.86.0 test --locked --all-features
cargo clippy --locked --all-features --all-targets -- -D warnings
```

The submodule must resolve to
`531468c59c7a2dc32f5cbe92cfabf89805d27f6a`. CI also checks that all bundled schemas
are identical to the schemas at specification commit
`2e33036563cb966b07124197db672159b4b7e1f4`. These exact merged commits are the
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

## Execution-checkpoint host

The host accepts an `Arc<dyn ExecutionStore>` directly. No registry, URI, or discovery
is required:

```rust
use determa_state::checkpoint::{CheckpointHost, ExecutionStore, MemoryExecutionStore};
use determa_state::InMemoryDefinitionResolver;
use std::sync::Arc;

let store: Arc<dyn ExecutionStore> = Arc::new(MemoryExecutionStore::new());
store.initialize_schema()?;
let resolver = Arc::new(InMemoryDefinitionResolver::default());
let host = CheckpointHost::new(store, resolver);
# let _ = host;
# Ok::<(), Box<dyn std::error::Error>>(())
```

URI resolution is opt-in and generic. A new `AdapterRegistry` is empty;
`register_bundled_adapters` registers compiled built-ins through its public `register`
method. Generic resolution extracts only the lowercase URI scheme. Each factory owns
configuration validation and capability evaluation.

Storage setup is explicit:

- `memory:` is ephemeral and advertises only `ephemeral`;
- `file:/absolute/directory` uses locking and atomic replacement and advertises only
  `restart_persistent`;
- `sqlite:/absolute/database.sqlite3#receipt_retention=permanent&outbox_retention=strict`
  uses bundled SQLite, WAL, `synchronous=FULL`, immediate write transactions, and
  derives retention capabilities from the configured mode;
- `postgresql://...#receipt_retention=permanent&outbox_retention=strict&tls=no_tls`
  is the explicit local no-TLS bundled PostgreSQL route available with
  `--features postgresql`.

Durable factories reject configurations without
`receipt_retention=bounded|permanent` and
`outbox_retention=bounded|strict|compact`. The chosen mode is persisted in schema
metadata, checked by `health`, advertised as store capabilities, and enforced on each
insert or replacement. `PostgresqlExecutionStore::connect_with_tls` and
`PostgresqlExecutionStoreFactory::with_tls` accept a caller-provided
`postgres::tls::MakeTlsConnect` implementation; a secure connector configuration uses
`tls=provided`. `connect_no_tls` and the bundled `tls=no_tls` factory remain explicit
local/testing choices.

For shared application and checkpoint atomicity, use
`CheckpointHost::with_postgresql_transaction`. Its callback receives the native
transaction for application SQL and accepts exactly one root-bound checkpoint mutation
through `CheckpointHost::stage_postgresql_mutation`. The host uses `SERIALIZABLE`,
rejects cross-store/cross-root handles, rolls both parts back on failure, and returns
the committed host result only after commit succeeds. Native version-2 creation,
upgrade, admission, step, maintenance migration, pruning, outbox lifecycle, and root
tombstone mutations use this same shared transaction API. The store's lower-level
native transaction callback does not run host operations.

Call `initialize_schema` deliberately before file or database use. Adapters never
silently migrate schema. The execution-store trait has no checkpoint deletion method;
SQLite and PostgreSQL schemas also reject direct row deletion.

PostgreSQL integration tests use `DETERMA_TEST_POSTGRES_URL`; retention and TLS
factory fragments are appended by the tests:

```sh
DETERMA_TEST_POSTGRES_URL=postgresql://postgres:postgres@localhost/determa \
  cargo test --features postgresql --test checkpoint_postgresql
```

## CLI

```sh
cargo run -- validate examples/minimal.yaml
cargo run -- --version
```

## License

MIT. See [LICENSE](LICENSE).
