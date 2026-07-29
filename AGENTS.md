# AGENTS.md - determa-state-rust

Guidance for coding agents working in this repository.

## Repository role

This repository is the Rust implementation of the portable Determa State core. The
crate is `determa-state`, the library module is `determa_state`, and the binary is
published as `determa-state` plus the `determa-state-rust` launcher-selection alias.

Repository metadata prepares the synchronized State `0.1.0` release. The latest
published crate remains `0.0.7` until the coordinated `v0.1.0` tag runs the release
workflow.

The current draft is validated against the merged `0.1.0` metadata revisions at these
exact immutable inputs:

- specification: `c1635d74e6a216301a8986d37be8ce7e7111dfd7`;
- conformance: `600523ca08c3b8a6ee790439a32dc4ce47f71b95`.

The conformance suite is the arbiter of behavior. These exact merged commits are the
authoritative release inputs; tag publication is a later coordinated release operation.
Never invent a release tag or weaken an exact revision check.

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
  "600523ca08c3b8a6ee790439a32dc4ce47f71b95"
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
