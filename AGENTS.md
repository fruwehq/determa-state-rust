# AGENTS.md - determa-state-rust

Guidance for coding agents working in this repository.

## Repository role

This repository is the Rust implementation of the portable Determa State core. The
crate is `determa-state`, the library module is `determa_state`, and the binary is
published as `determa-state` plus the `determa-state-rust` launcher-selection alias.

Repository metadata prepares the synchronized State `0.1.0` release. The latest
published crate remains `0.0.7` until the coordinated `v0.1.0` tag runs the release
workflow.

The current draft remains validated at these exact immutable inputs until the real
upstream `v0.1.0` tags exist:

- specification: `1502a58a780d837e05bfacb37680dfc92e3488b5`;
- conformance: `707a49ce01c6f57f673c1959cdfe078bc8d0fc9a`.

The conformance suite is the arbiter of behavior.

Before this release-preparation branch is marked ready or merged, replace those
temporary pins with the commits referenced by the verified specification and
conformance `v0.1.0` tags, update the schemas and conformance gitlink as required, and
rerun every gate. Never invent a release tag or weaken an exact revision check.

## Layout

- `schema/`: exact normative format-1 machine, aggregate, migration, and package schemas.
- `src/format1/`: loader, semantic compiler, CEL profile, pure runtime, portable
  persistence, definition resolvers, aggregate packages, and migration.
- `src/value.rs`: portable values and nominal instance references.
- `src/cli.rs`: nonportable validation utility only.
- `tests/core_conformance.rs`: driver for all 110 `conformance/core` cases.
- `tests/persistence_conformance.rs`: driver for all 105 persistence vectors.
- `tests/persistence_profiles.rs`: driver for all six persistence host profiles.
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
  "707a49ce01c6f57f673c1959cdfe078bc8d0fc9a"
cargo build --release
cargo test
cargo clippy --all-targets -- -D warnings
```

CI runs the complete 110-case core suite, all 105 persistence vectors, and all 12
persistence-profile steps. It also checks every local schema byte-for-byte against the
exact specification commit.

## Boundaries

The portable API exposes pure foreground create/dispatch, aggregate
serialization/restoration, package restoration, definition migration, and
migration-and-dispatch operations. Queue ownership, timers, package imports, broker
adapters, scheduling, storage, trust policy, and host transactions remain separate host
or future profiles. The CLI currently validates bundles only.

## Releases

Do not tag casually. A synchronized State release coordinates the specification,
conformance suite, Python engine, and Rust engine. crates.io publishing uses the
repository release workflow and its configured trusted publishing path.
