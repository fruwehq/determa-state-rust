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

- specification: `e22f9db295d632f3f46a9d1260c63b5af92efa7e`;
- conformance: `8f6a4d9101fd6554e9a51da72ca48160368d4e83`.

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
- `tests/core_conformance.rs`: driver for all 114 `conformance/core` cases.
- `tests/persistence_conformance.rs`: driver for all 108 persistence vectors.
- `tests/persistence_profiles.rs`: driver for all six persistence host profiles.
- `tests/checkpoint_conformance.rs`: driver for all 102 version-1 execution-checkpoint vectors.
- `tests/checkpoint_v2_conformance.rs`: driver for all 60 queue-bearing checkpoint vectors.
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
  "8f6a4d9101fd6554e9a51da72ca48160368d4e83"
cargo +1.86.0 build --release --locked --all-features
cargo +1.86.0 test --locked --all-features
cargo clippy --locked --all-features --all-targets -- -D warnings
```

The declared MSRV is Rust `1.86`. CI must keep the locked default and all-features graph,
including PostgreSQL, buildable and testable with that toolchain.

CI runs the complete 114-case core suite, all 108 version-1 and 15 version-2
persistence vectors, all 12 persistence-profile steps, and all 162 execution-checkpoint
vectors. The version-2 harnesses cover 113 vectors and 164 artifacts in total. It also checks
every local schema byte-for-byte against the exact specification commit and runs the
optional PostgreSQL adapter against a service.

## Boundaries

The portable API exposes pure foreground create/dispatch, aggregate
serialization/restoration, package restoration, definition migration, and
migration-and-dispatch operations. The optional synchronous host wraps those unchanged
operations with portable checkpoint transactions. It owns no broker, timer, worker,
daemon, socket, subprocess protocol, package imports, or scheduling. Execution stores
must be directly injected or explicitly registered; database schema setup is explicit,
and schema-version-1 root/checkpoint deletion is unsupported. The CLI currently
validates bundles only.

## Releases

Do not tag casually. A synchronized State release coordinates the specification,
conformance suite, Python engine, and Rust engine. crates.io publishing uses the
repository release workflow and its configured trusted publishing path.
