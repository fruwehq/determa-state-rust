# Determa State for Rust

Rust implementation of the portable [Determa State](https://github.com/fruwehq/determa-state-spec)
`format: 1` core with an optional synchronous portable execution-checkpoint host.

Repository metadata prepares synchronized version `0.3.0` after the `v0.2.0` release.
This version adds portable runtime-local event deferral, the sole current schema-v1
aggregate artifacts, and durable checkpoint coverage. The implementation is validated against
these exact normative inputs:

- specification commit `77c0a2e60cd0771a6d44ae170a079ddd51d7d9f0`;
- conformance commit `dc84ed81ea36a5f2140181a97660477a14347ccc`.

Correctness is defined by the language-agnostic conformance suite. The Rust integration
tests run all 75 mailbox-neutral runtime traces through the shared private RTC kernel,
all 162 applicable native artifact/checkpoint schema-v1 core vectors, and all 142
durable-host vectors, all 49 exact candidate inspection vectors, plus semantic validation
of all 487 declared artifact documents, 47 extension negotiation vectors and
all seven configured native guard-provider inspection vectors. The pinned suite
also defines 52 runtime-provider vectors; complete production adapter coverage is
unfinished in this draft implementation checkpoint.
Durable host profiles remain optional host contracts; memory, file, SQLite, and
PostgreSQL tests exercise the implemented transactional host surface.

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
- Pure queue-bearing `create`, `admit`, and `step` operations over one native aggregate
  model that owns runtime mailboxes and their allocation counters, with deterministic
  runtime, cause, event, and external-effect identities.
- Read-only `inspect_candidate` over an exact runtime incarnation and normalized
  candidate envelope. Structural inspection reports ordered possible dispositions;
  configured semantic inspection evaluates reached CEL guards with portable fuel.
- Portable aggregate serialization and restoration with strict typed values, canonical
  JSON, content-addressed definitions, sole schema-v1 artifacts, and
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
  with explicit durable receipt/outbox modes, schema-contract health checks, and a
  SQLite native transaction spanning checkpoint, inbox, quarantine, and application rows.
- Inspection through the returned native aggregate and core-step JSON values.
- Immutable `PORTABLE_CODES` slices on public closed-code enums, including
  `CreationRejectionCode`, `DispatchRejectionCode`, and `EngineFaultCode`.

The portable core remains a pure foreground transform. Its aggregate owns only the
portable runtime mailboxes; it owns no broker queue, acknowledgement, timer, package
import, or background scheduler. The optional host
persists SPEC section 17 state around those unchanged operations. Broker adapters,
workers, transport integration, and application response data remain application
concerns. The command-line binary still provides bundle validation only.

With the `sqlite` feature, `public_host::PublicHostClient` retains complete version-1
mutation requests and their original endpoint in an explicitly initialized SQLite
journal. Named `EndpointBinding` values supply deployment endpoints and scope aliases;
the injected transport authenticates requests outside their JSON. Discovery pins an
immutable scope identity before new work. `retry` and `receipt` use the saved endpoint
after restart or alias changes. A transport failure leaves the outcome unknown.

`public_host::SqlitePublicExecutionHost` implements capabilities, create, admit,
process, read, structural inspect and receipt for one local authenticated scope.
Call `setup_schema` explicitly. Native schema and retention guards are verified;
checkpoint and complete first public response commit in one SQLite transaction.
Authorization precedes root/receipt lookup, and equal mutations replay before
definition resolution or core execution. This profile advertises no authority,
native effects, timer, archive or recovery provider.

## Build and test

The minimum supported Rust version (MSRV) is `1.86`. CI verifies the locked default and
all-features dependency graph with that toolchain, including PostgreSQL compile and test
coverage. Stable Rust remains the toolchain for formatting and clippy.
The lockfile pins `chacha20` `0.10.2` because `0.10.1` was yanked; this
allows clean consumers to resolve the optional PostgreSQL dependency graph.

```sh
git submodule update --init
cargo +1.86.0 build --release --locked --all-features
cargo +1.86.0 test --locked --all-features
cargo clippy --locked --all-features --all-targets -- -D warnings
```

The submodule must resolve to
`dc84ed81ea36a5f2140181a97660477a14347ccc`. CI also checks that all bundled schemas
are identical to the schemas at specification commit
`77c0a2e60cd0771a6d44ae170a079ddd51d7d9f0`. These exact reviewed public commits are
the current implementation inputs; tag publication is a later coordinated release operation.

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

assert_eq!(aggregate.value()["aggregate_state_schema_version"], 1);
# Ok::<(), Box<dyn std::error::Error>>(())
```

Input and internal envelopes are caller-owned. `admit` retains accepted work in the
aggregate and `step` processes one ready event. External emissions are deterministic
output intents for the host to persist and deliver.

`inspect_candidate(&aggregate, &request, &resolver, InspectionCapabilities::default())`
accepts the closed six-member request in `schema/inspection-v1.schema.json` and returns
the exact closed outcome or `{code, source_locator}` operation failure. The resolver
must trust every definition retained by the aggregate. Use
`InspectionCapabilities { safe_semantic_cel: false }` when a host does not offer
bounded semantic inspection. Neither mode admits the candidate or changes queues,
receipts, counters, or the supplied aggregate.

All seven native provider inspection vectors run through a separately verified
`inspect_guard` entrypoint. Their portable aggregates restore through the actual
provider-backed definition resolver. All 52 exact-source runtime-provider vectors
also run through production loading, creation, step, inspection, source compilation,
restoration and durable checkpoint commit/replay operations. The repository-only
adapter records compiler stages and emission indexes with
`RUSTFLAGS="--cfg determa_repository_conformance"`; these observations do not add
members to portable results or artifacts. Full release gates and independent review
remain required before the final release claim.

`compile_language_source` compiles only executable grammar slots through explicitly
installed exact-source compilers, then strictly loads the generated format-1 bundle.
Every successful `Bundle.source_compilation` retains sealed version-1 source and
manifest artifacts, even without a supplied manifest. The evidence discloses the
historical source capability profile independently of generated runtime guarantees.
Generated CEL definitions restore without an installed compiler.

## Public extensions

`extensions::ExtensionRegistry` implements the version-1 public boundary for all eleven
extension categories. It starts empty. A host registers an exact descriptor and factory
with `register` or directly supplies a provider with `inject`; both paths validate the
same closed reference, category, interface version, and capability vocabulary. Host-owned
configuration is validated before an instance opens. `capabilities`, `health`, `report`,
`negotiate`, and `evaluate_profile` operate on that exact configured instance. Unknown
references, changed versions or digests, unhealthy instances, and missing guarantees
fail before the host invokes a core or checkpoint operation. URI schemes are only hints.

The host installs a `HostVerifier` to bind a factory and provider to its trusted loaded
source and dependency closure. Its operational proof checks the configured native
instance and current topology. A verified source with no operational proof remains
usable with an empty effective claim set. The registry combines guarantees across all
participants and treats unresolved external I/O as a hazard that requires explicit
weak-profile opt-in. Provider reports and configuration flags cannot supply proof.
The common boundary does not execute guards/actions or infer authority from a store.

`extensions::bundled_store_registry()` registers memory, file, and enabled SQLite and
PostgreSQL stores through this same public path. Their executable closure digest is
derived from compiled crate source and the lockfile, and the bundled verifier binds
the exact private factory/provider and native store instance before reporting current
store capabilities and health. `bundled_store_registry_with_verifier` delegates other
installed providers to a host verifier in the same registry. A host obtains a
`VerifiedExecutionStore` through `configure_execution_store`, initializes SQL schemas
explicitly, and passes that binding to `CheckpointHost::from_verified` before a
durable profile or native durable process. Third-party Rust providers implement
`ExtensionProvider` and `ExtensionFactory`; the host supplies its trusted
`HostVerifier` for their source and operational proofs. The generic
registry cannot attest arbitrary installed Rust binaries by inspecting trait-object
types or self-reported health.

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

The public `ExtensionRegistry` binds a provider reference, registered factory,
configuration, native instance, current health, and host-verified capabilities.
`bundled_store_registry` registers compiled stores through this same path. A
directly injected `ExecutionStore` remains useful for weak operations;
`CheckpointHost::from_verified` is required before validating a durable host
profile or running a durable process. Hosts install their own trusted verifier
for third-party source and operational evidence.

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
the committed host result only after commit succeeds. An ingress acknowledgement
result requires a source-verified transport adapter that actually acknowledges the
committed operation and passes the host's operational proof; a Boolean argument
cannot assert it. Native schema-v1 creation,
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
cargo run --bin determa-state -- validate examples/minimal.yaml
cargo run --bin determa-state -- --version
```

## License

MIT. See [LICENSE](LICENSE).
