//! Per-state / machine `meta` is opaque and inert (SPEC §4.1/§4.5): it is parsed
//! and exposed on the model but has no effect on dispatch, validation, or
//! snapshots. A machine with `meta:` must load and run identically to one without.

use determa_state::value::Value;
use determa_state::{load_machines, resolve_definitions, Engine};
use std::collections::BTreeMap;

const WITH_META: &str = "id: turnstile
meta:
  author: storm
  tags: [vending, hardware]
events:
  coin: { payload: { amount: { type: int, required: true } } }
  push: {}
top:
  meta: { kind: root }
  esvs:
    fare: { type: int, init: 50 }
  initial: { transition_to: locked }
  states:
    locked:
      meta: { ui: { color: red, hint: \"insert coin\" } }
      on_events:
        coin: { transition_to: unlocked, guard: \"event.payload.amount >= fare\" }
    unlocked:
      on_events:
        push: { transition_to: locked }
";

const WITHOUT_META: &str = "id: turnstile
events:
  coin: { payload: { amount: { type: int, required: true } } }
  push: {}
top:
  esvs:
    fare: { type: int, init: 50 }
  initial: { transition_to: locked }
  states:
    locked:
      on_events:
        coin: { transition_to: unlocked, guard: \"event.payload.amount >= fare\" }
    unlocked:
      on_events:
        push: { transition_to: locked }
";

fn run(src: &str) -> (Engine, Value, Value) {
    let docs = load_machines(src).expect("parses");
    let machines = resolve_definitions(&docs).expect("builds");
    let machine_meta = machines[0].meta.clone();
    // locate the `locked` state's meta
    let locked_meta = machines[0]
        .states
        .iter()
        .find(|s| s.id == "locked")
        .expect("locked state")
        .meta
        .clone();
    let mut engine = Engine::new();
    for m in machines {
        engine.register(m);
    }
    engine
        .create_root("t", "turnstile", None, &BTreeMap::new())
        .expect("create_root");
    let payload = Value::Map([("amount".to_string(), Value::Int(100))].into_iter().collect());
    engine.send("t", "coin", payload).expect("send");
    (engine, machine_meta, locked_meta)
}

#[test]
fn meta_loads_and_runs_identically() {
    let (with, _, _) = run(WITH_META);
    let (without, _, _) = run(WITHOUT_META);
    // identical runtime behavior — meta has no effect on dispatch
    let a = with.state_view("t").unwrap();
    let b = without.state_view("t").unwrap();
    assert_eq!(a.config, b.config);
    assert_eq!(a.config, vec!["unlocked".to_string()]);
    assert_eq!(a.esvs, b.esvs);
}

#[test]
fn meta_is_exposed_on_the_model() {
    let (_, machine_meta, locked_meta) = run(WITH_META);
    // machine-level meta is an opaque map, preserved verbatim
    let mm = match machine_meta {
        Value::Map(m) => m,
        other => panic!("machine meta must be a map, got {other:?}"),
    };
    assert_eq!(mm.get("author"), Some(&Value::Str("storm".into())));
    assert_eq!(
        mm.get("tags"),
        Some(&Value::List(vec![Value::Str("vending".into()), Value::Str("hardware".into())]))
    );
    // state-level meta is exposed too, including nested maps
    let lm = match locked_meta {
        Value::Map(m) => m,
        other => panic!("state meta must be a map, got {other:?}"),
    };
    match lm.get("ui") {
        Some(Value::Map(ui)) => assert_eq!(ui.get("color"), Some(&Value::Str("red".into()))),
        other => panic!("nested ui meta missing/wrong: {other:?}"),
    }
}

#[test]
fn meta_absent_defaults_to_empty_map() {
    let (_, machine_meta, locked_meta) = run(WITHOUT_META);
    assert_eq!(machine_meta, Value::Map(BTreeMap::new()));
    assert_eq!(locked_meta, Value::Map(BTreeMap::new()));
}
