# AGENTS.md — determa-state-rust

Guidance for AI/coding agents working in this repository. (Tool-agnostic; not specific to any one assistant.)

## What this repo is
The **Rust implementation** of Determa State. Crate **`determa-state`**, library module
**`determa_state`**; the binary `src/bin/determa_state.rs` is published as **two** names —
`determa-state` (canonical) and `determa-state-rust` (for explicit implementation
selection). It is correct **iff** it passes the conformance suite.

Layout:
- `src/` — library (`lib.rs`, `model.rs`, `validate.rs`, `runtime/`, `cel.rs`, `store.rs`, …) + the CLI (`cli.rs`, `bin/`).
- `tests/` — Rust tests, incl. `conformance.rs` (drives the suite) plus `meta.rs`, `native_values.rs`.
- `conformance-suite/` — a **git submodule** of `determa-state-conformance`.
- `.github/workflows/` — `ci.yml` (gate) and `release.yml` (tag/dispatch → crates.io).

## Determa in one paragraph
**Determa** is a family for defining/running well-specified, verifiable behavior. **Determa
State** is a language-agnostic **statechart engine** (Harel/UML lineage, PSiCC RTC): one
YAML/JSON machine runs identically under any implementation, validated against a shared
conformance suite. Guards/action values are **CEL**, evaluated here via the
**`cel-interpreter`** crate (cel-rust). An umbrella `determa` launcher dispatches
`determa <product> …` → `determa-<product>` on PATH.

## Repositories (org `fruwehq`, local folders `~/src/personal/`)
| Repo | Role |
|---|---|
| determa-state-spec | normative prose spec + schema. No CI. |
| determa-state-conformance | the conformance suite (arbiter). No CI. |
| determa-state-python | Python impl — `determa-state` / `determa.state`. |
| **determa-state-rust** (this) | Rust impl — crate `determa-state`. |
| determa | umbrella launcher (`python/`, `rust/`, `node/`). |

## Working rules (every Determa repo)
- **One issue → one PR**, branch → PR → **squash-merge**, linear history, resolve threads; `main` is protected and **requires branches be up-to-date** (serialize merges: update-branch re-runs CI).
- **No AI/assistant attribution** anywhere (commits, PRs, comments, docs).
- **Conformance-first:** spec text → conformance case → this impl. Stay in lockstep with the Python impl on all conformance-covered behavior (extensions beyond the suite are allowed, but must not change core semantics).
- **Synchronized SemVer** with spec + python (currently **0.0.6**); bump `Cargo.toml`.
- **No abbreviations** in JSON output / public identifiers (`definition` not `def`). Kept for now: `config`, machine-keywords (`esvs`, …), snapshot `def_id`/`def_version`, `spawn.def`.

## Gates (run before requesting review)
```sh
git submodule update --init
cargo build --release
cargo test                # unit + doc + engine conformance
# CLI conformance (black box), pinning the suite at the spec tag:
(cd conformance-suite && git fetch --tags && git checkout v<VERSION>)
python3 conformance-suite/conformance/run_cli.py --cmd "$(pwd)/target/release/determa-state"
```
CI jobs: **"build + engine conformance + unit tests"** and **"black-box CLI conformance (SPEC §13.6)"**; both **force-pin** the submodule to `v<VERSION>`.

**Gotchas specific to this repo:**
- **CI does NOT run clippy**, and `main` currently carries ~37 pre-existing `clippy` warnings (rustc ≥ 1.95). Keep *new* code clippy-clean (`cargo clippy --all-targets -- -D warnings` on your diff), but expect the baseline to be noisy.
- Serde structs use `#[serde(deny_unknown_fields)]` — a new machine key requires updating the corresponding struct(s) or loading fails.
- The recorded `conformance-suite` submodule SHA may lag the spec tag; CI force-pins the tag and the published crate **excludes** the submodule, so it's cosmetic — but bump it to the tag when doing a release.

## Releasing
Tag `vX.Y.Z` (or `workflow_dispatch`) → `release.yml` runs `cargo publish` using the
`CARGO_REGISTRY_TOKEN` org secret. After a spec release: bump `Cargo.toml`, re-pin the
submodule + `ci.yml` to the new `v` tag.

## Pointers
- Library API (SPEC §2): `build_machine`, `load_machines`, `load_machine_from_value` (from a native `serde_json::Value`), `validate`, `Engine`. Spec: `determa-state-spec/SPEC.md`.
