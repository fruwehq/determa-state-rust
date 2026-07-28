# AGENTS.md - determa-state-rust

Guidance for coding agents working in this repository.

## Repository role

This repository is the Rust implementation of the portable Determa State core. The
crate is `determa-state`, the library module is `determa_state`, and the binary is
published as `determa-state` plus the `determa-state-rust` launcher-selection alias.

Repository metadata targets the synchronized State `0.0.7` release. The latest
published crate remains `0.0.6` until the coordinated `v0.0.7` tag runs the release
workflow.

The current implementation target is format 1 at these immutable inputs:

- specification: `09c717a40c75b99612e54d764b5f1bdfa4b94f96`;
- conformance: `74e477087fd31561600aacf652cccae571a5ea9a`.

The conformance suite is the arbiter of behavior.

## Layout

- `schema/machine.schema.json`: exact normative format-1 schema.
- `src/format1/`: loader, semantic compiler, CEL profile, and pure runtime.
- `src/value.rs`: portable values and nominal instance references.
- `src/cli.rs`: nonportable validation utility only.
- `tests/core_conformance.rs`: driver for all 88 `conformance/core` cases.
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
  "74e477087fd31561600aacf652cccae571a5ea9a"
cargo build --release
cargo test
cargo clippy --all-targets -- -D warnings
```

`cargo test --test core_conformance -- --nocapture` runs the complete 88-case core suite.
CI additionally checks the local schema byte-for-byte against the exact specification
commit.

## Boundaries

The portable API is a pure foreground `create`/`dispatch` state transform. Queue
ownership, persistence, timers, snapshots, definition migration/hot-swap, package
imports, broker adapters, and scheduling are separate host or future profiles. The CLI
currently validates bundles only.

## Releases

Do not tag casually. A synchronized State release coordinates the specification,
conformance suite, Python engine, and Rust engine. crates.io publishing uses the
repository release workflow and its configured trusted publishing path.
