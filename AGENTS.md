# AGENTS.md - determa-state-rust

Guidance for coding agents working in this repository.

## Repository role

This repository is the Rust implementation of the portable Determa State core and its
optional synchronous execution-checkpoint host. The crate is `determa-state`, the
library module is `determa_state`, and the binary is published as `determa-state` plus
the `determa-state-rust` launcher-selection alias.

Repository metadata prepares the synchronized State `0.2.0` release. The latest
published crate remains `0.1.0` until the coordinated `v0.2.0` tag runs the release
workflow.

The current draft is validated against the merged `0.2.0` metadata revisions at these
exact immutable inputs:

- specification: `ee38796d5e38e67e350a06548fd50faa530cbb12`;
- conformance: `99a4d9ad5256f7330e75b06d48f340cc7239a40d`.

The conformance suite is the arbiter of behavior. These exact merged commits are the
authoritative release inputs; tag publication is a later coordinated release operation.
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
- `tests/native_v2_conformance.rs`: driver for all 162 applicable native schema-v2
  aggregate, migration, package, and execution-checkpoint vectors.
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
  "99a4d9ad5256f7330e75b06d48f340cc7239a40d"
cargo +1.86.0 build --release --locked --all-features
cargo +1.86.0 test --locked --all-features
cargo clippy --locked --all-features --all-targets -- -D warnings
```

The declared MSRV is Rust `1.86`. CI must keep the locked default and all-features graph,
including PostgreSQL, buildable and testable with that toolchain.

CI runs all 162 applicable native schema-v2 core vectors and all 138 durable-host
vectors.
It also checks every local schema byte-for-byte against the exact specification commit
and runs the optional PostgreSQL adapter against a service.

## Boundaries

The portable API exposes only queue-bearing schema-v2 create, admission, step,
serialization/restoration, package restoration, and definition migration operations.
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
