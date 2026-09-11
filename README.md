# Determa State for Rust

Rust implementation of the portable [Determa State](https://github.com/fruwehq/determa-state-spec)
`format: 1` core with an optional synchronous portable execution-checkpoint host.

Repository metadata prepares synchronized version `0.2.0`. The latest published crate
remains `0.1.0` until the coordinated `v0.2.0` tag runs the release workflow. This
branch is validated against the merged `0.2.0` metadata revisions at these exact
normative inputs:

- specification commit `ee38796d5e38e67e350a06548fd50faa530cbb12`;
- conformance commit `99a4d9ad5256f7330e75b06d48f340cc7239a40d`.

Correctness is defined by the language-agnostic conformance suite. The Rust integration
tests run all 162 applicable native artifact/checkpoint schema-v2 core vectors and all
138 durable-host vectors. Durable host profiles remain
optional host contracts; memory, file, SQLite, and PostgreSQL tests exercise the
implemented transactional host surface.

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
- Pure queue-bearing `create`, `admit`, and `step` operations with deterministic
  runtime, cause, event, and external-effect identities.
- Portable aggregate serialization and restoration with strict typed values, canonical
  JSON, content-addressed definitions, sole schema-v2 artifacts, and
  self-contained aggregate packages.
- Resolver-backed compatible and transforming definition migration, exact route
  execution, resource limits, and ordered audit records.
- Strict execution-checkpoint Serde types, canonical digests, semantic restoration,
  operation receipts, durable pending delivery, outbox lifecycle, bounded retention,
  migration audit, root tombstones, and revision/digest compare-and-swap.
- Direct execution-store trait-object injection and an initially empty public adapter
  registry. Bundled adapters use only the same public registration route available to
  third-party factories.
- Default `memory`, `file`, and bundled-SQLite adapters plus optional PostgreSQL,
  with explicit durable receipt/outbox modes and schema-contract health checks.
- Inspection through the returned native aggregate and core-step JSON values.
- Immutable `PORTABLE_CODES` slices on public closed-code enums, including
  `CreationRejectionCode`, `DispatchRejectionCode`, and `EngineFaultCode`.

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
`99a4d9ad5256f7330e75b06d48f340cc7239a40d`. CI also checks that all bundled schemas
are identical to the schemas at specification commit
`ee38796d5e38e67e350a06548fd50faa530cbb12`. These exact merged commits are the
authoritative release inputs; tag publication is a later coordinated release operation.

## Library

```rust
use determa_state::{create, load_bundle, Bindings};

let source = std::fs::read_to_string("examples/minimal.yaml")?;
let bundle = load_bundle(&source)?;
let aggregate = create(
    &bundle,
    "turnstile",
    "turnstile-1",
    "create-1",
    &Bindings::default(),
)?;

assert_eq!(aggregate.value()["aggregate_state_schema_version"], 2);
# Ok::<(), Box<dyn std::error::Error>>(())
```

Input and internal envelopes are caller-owned. `admit` retains accepted work in the
aggregate and `step` processes one ready event. External emissions are deterministic
output intents for the host to persist and deliver.

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
the committed host result only after commit succeeds. Native schema-v2 creation,
admission, step, maintenance migration, pruning, outbox lifecycle, and root
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
