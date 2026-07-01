# harel-rust

A Rust implementation of the [harel](https://github.com/fruwehq/harel) statechart
engine.

**Implements harel spec v0.0.2.** Correctness is defined by the language-agnostic
conformance suite at [`fruwehq/harel-conformance`](https://github.com/fruwehq/harel-conformance)
(pinned at tag `v0.0.2` as a submodule under `conformance-suite/`); this engine is
correct iff it passes every case.

## What is harel?

harel is a language-agnostic statechart format: a machine is declared once in YAML
and run by an implementation in any language, with all implementations held
accountable by a shared conformance suite. It follows the run-to-completion and
hierarchical-state-machine semantics of Miro Samek's *Practical Statecharts in
C/C++* (PSiCC) — the outermost state is `top` — and keeps the vocabulary of
`cns_statemachine` (`top`, `esvs`, `on_events`, `transition_to`, `defer`, `publish`)
while replacing raw guards/actions with [CEL](https://cel.dev/) and a small
structured action set.

This crate provides:

- **Full statechart semantics** (SPEC §5): hierarchy with LCA exit/entry, run-to-
  completion, internal/local/external transitions, orthogonal regions + `done`,
  shallow/deep history, choice pseudostates, `defer`red events, and timers over a
  virtual clock.
- **Extended state (`esvs`)** declared *inside* states, hierarchically scoped with
  shadowing (§4.4), plus `external` esvs driven by the reserved `env` event and the
  `refresh` action (§5.4).
- **Guards in CEL** and a structured action set (`assign`/`publish`/`refresh`/
  `spawn`/`stop`) whose computed values are CEL (§6).
- **Active objects** — each instance owns an event queue; instances are spawned
  dynamically with deterministic ids and communicate only by publishing events
  (directed or by subscription/scope) over a pluggable bus (§5.7).
- **Faults** via the reserved `error` event with atomic step rollback and a
  dead-letter (§5.10).
- **Versioned definitions + safe-point migration** (§10).
- **Snapshot/restore** and a passive per-step **Observer** (§8).
- **Mermaid** export (§12).
- An embeddable **library API** (§2) and the standard **`harel` CLI** (§13): all
  commands, exit codes, normative `--json` shapes, `--store file:`/`mem:`/`sqlite:`,
  batch/streaming `run`, and the §14 `mode`/`inject`/`step`/`inspect` verbs.

## Build

```sh
cargo build --release
# the binary is target/release/harel
```

## Run the conformance suite

```sh
git submodule update --init              # conformance-suite @ v0.0.2

# engine cases (SPEC §9)
cargo test --test conformance -- --nocapture

# black-box CLI cases (SPEC §13.6)
python3 conformance-suite/conformance/run_cli.py --cmd "$(pwd)/target/release/harel"
```

Both are wired into CI (`.github/workflows/ci.yml`), which fetches the suite at tag
`v0.0.2` and fails the build on any regression.

## CLI

```sh
harel new t1 examples/minimal.yaml
harel send t1 coin --payload amount=100 --json
harel state t1 --json
harel list --json
harel validate examples/full.yaml
harel export examples/full.yaml
```

`--store <spec>` selects a backend: `file:<dir>` (default, portable snapshot files),
`mem:` (ephemeral, in-process), or `sqlite:<path>`. See `harel --help`.

## Library

```rust,ignore
use harel::{build_machine, load_machines, Engine, Value};
use std::collections::BTreeMap;

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let docs = load_machines(include_str!("../examples/minimal.yaml"))?;
let machine = build_machine(&docs[0]).map_err(|e| format!("{e:?}"))?;
let mut engine = Engine::new();
engine.register(machine);
engine.create_root("t1", "turnstile", None, &BTreeMap::new())?;
engine.send("t1", "coin", Value::Map(
    [("amount".to_string(), Value::Int(100))].into_iter().collect()
))?;
let view = engine.state_view("t1")?;
assert_eq!(view.config, vec!["unlocked".to_string()]);
# Ok(()) }
```

## Status

Pre-1.0 (`0.0.x`), tracking the synchronized harel spec/conformance version.

## License

MIT — see [LICENSE](LICENSE).
