# AGENTS.md - determa-state-rust

Guidance for coding agents working in this repository.

## Repository role

This repository is the Rust implementation of the portable Determa State core and its
optional synchronous execution-checkpoint host. The crate is `determa-state`, the
library module is `determa_state`, and the binary is published as `determa-state` plus
the `determa-state-rust` launcher-selection alias.

Repository metadata prepares the synchronized State `0.3.0` release after the
`v0.2.0` tag.

The current draft is validated against these exact immutable inputs:

- specification: `77c0a2e60cd0771a6d44ae170a079ddd51d7d9f0`;
- conformance: `dc84ed81ea36a5f2140181a97660477a14347ccc`.

The conformance suite is the arbiter of behavior. These exact reviewed public commits are
the current implementation inputs; tag publication is a later coordinated release operation.
Never invent a release tag or weaken an exact revision check.

## Layout

- `schema/`: exact normative format-1 machine, aggregate, migration, package, and
  execution-checkpoint schemas.
- `src/format1/`: loader, semantic compiler, CEL profile, pure runtime, portable
  persistence, definition resolvers, aggregate packages, and migration.
- `src/checkpoint/`: strict checkpoint wire model, synchronous host, public execution
  store registry, capability profiles, and bundled adapters.
- `src/value.rs`: portable values and nominal instance references.
- `src/cli.rs`: nonportable validation utility only.
- `tests/native_v1_conformance.rs`: driver for all 162 applicable native schema-v1
  aggregate, migration, package, and execution-checkpoint vectors.
- `src/format1/runtime_conformance.rs`: repository-only driver for all 75 mailbox-neutral
  runtime traces through the private RTC kernel shared by the sole queue-bearing public API;
  it is explicitly configured by CI and excluded from the published crate.
- `tests/artifact_manifest.rs`: schema and semantic routing gate for all 487 declared
  conformance artifact documents. Operation admissibility is checked separately by
  the native schema-v1 vectors through public operations.
- `tests/inspection_conformance.rs`: all 49 mandatory exact-target inspection vectors
  through the production operation. Seven native provider vectors execute through separately verified provider
  capabilities.
- `tests/runtime_provider_conformance.rs`: all 52 exact-source runtime-provider vectors
  through production operations, with repository observations enabled by
  `RUSTFLAGS="--cfg determa_repository_conformance"`.
- `tests/durable_host_conformance.rs`: production-host driver for all 142 optional
  durable-host vectors, including SQLite shared transactions.
- `tests/checkpoint_adapters.rs`: shared memory/file/SQLite setup, restart, and CAS
  contracts.
- `tests/checkpoint_postgresql.rs`: optional PostgreSQL exact-schema, retention-mode,
  unbounded-counter CAS, TLS-factory, and host-owned shared-transaction contract.
- `conformance-suite/`: pinned `determa-state-conformance` submodule.

## Working rules

- One issue to one branch to one pull request, squash-merged with linear history.
- No assistant attribution in commits, pull requests, comments, or documentation.
- Behavior changes start in the specification and conformance suite. Do not add engine
  behavior that conflicts with either.
- Keep synchronized State SemVer unchanged unless the coordinated release explicitly
  changes it.
- Do not restore aliases for unpublished grammar.
- Do not expose host-profile assumptions as portable core behavior.

## Gates

```sh
git submodule update --init
test "$(git -C conformance-suite rev-parse HEAD)" = \
  "dc84ed81ea36a5f2140181a97660477a14347ccc"
cargo +1.86.0 build --release --locked --all-features
cargo +1.86.0 test --locked --all-features
cargo clippy --locked --all-features --all-targets -- -D warnings
```

The declared MSRV is Rust `1.86`. CI must keep the locked default and all-features graph,
including PostgreSQL, buildable and testable with that toolchain.

CI runs all 162 applicable native schema-v1 core vectors, all 142 durable-host vectors,
and all 487 declared artifact documents.
It also checks every local schema byte-for-byte against the exact specification commit
and runs the optional PostgreSQL adapter against a service.

## Boundaries

The portable API exposes only queue-bearing schema-v1 create, admission, step,
serialization/restoration, package restoration, and definition migration operations.
It also exposes read-only exact candidate inspection with bounded CEL guard evaluation.
The optional synchronous host wraps those unchanged
operations with portable checkpoint transactions. It owns no broker, timer, worker,
daemon, socket, subprocess protocol, package imports, or scheduling. Execution stores
must be directly injected or explicitly registered; database schema setup is explicit,
and durable-host profiles remain optional host contracts. The CLI currently validates
bundles only.

## Releases

Do not tag casually. A synchronized State release coordinates the specification,
conformance suite, Python engine, and Rust engine. crates.io publishing uses the
repository release workflow and its configured trusted publishing path.
