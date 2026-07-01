//! Values crossing the engine boundary are canonical native/JSON values (SPEC §5.1).
//!
//! A value produced by a guard/action language is coerced to the variable's declared
//! `type` and stored as a canonical `Value` — no engine- or guard-language-internal
//! wrapper type may surface through resolved esvs, snapshots, or `--json`. This
//! mirrors the reference `test_native_values` suite.

use harel::value::Value;
use harel::{load_machines, resolve_definitions, Engine};
use std::collections::BTreeMap;

const TYPES: &str = "id: types
events:
  go: {}
top:
  esvs:
    i: { type: int, init: 0 }
    f: { type: float, init: 0.0 }
    b: { type: bool, init: false }
    s: { type: string, init: \"\" }
    m: { type: map, init: {} }
    l: { type: list, init: [] }
  initial: { transition_to: a }
  states:
    a:
      on_events:
        go:
          action:
            - { assign: { i: \"1 + 2\" } }
            - { assign: { f: \"1.5 + 0.5\" } }
            - { assign: { b: \"true\" } }
            - { assign: { s: \"'a' + 'b'\" } }
            - { assign: { m: \"{'k': 2}\" } }
            - { assign: { l: \"[1, 2, 3]\" } }
";

fn run() -> Engine {
    let docs = load_machines(TYPES).expect("parses");
    let machines = resolve_definitions(&docs).expect("builds");
    let mut engine = Engine::new();
    for m in machines {
        engine.register(m);
    }
    engine
        .create_root("r", "types", None, &BTreeMap::new())
        .expect("create_root");
    engine.send("r", "go", Value::Null).expect("send");
    engine
}

#[test]
fn cel_assignments_are_canonical_values() {
    let engine = run();
    let esvs = engine.state_view("r").expect("state").esvs;
    // every esv kind is stored as its canonical Value variant with the coerced value
    assert!(matches!(esvs.get("i"), Some(Value::Int(3))), "i = {:?}", esvs.get("i"));
    assert!(matches!(esvs.get("f"), Some(Value::Float(_))), "f = {:?}", esvs.get("f"));
    assert_eq!(esvs.get("f"), Some(&Value::Float(2.0)));
    assert!(matches!(esvs.get("b"), Some(Value::Bool(true))), "b = {:?}", esvs.get("b"));
    assert!(matches!(esvs.get("s"), Some(Value::Str(_))), "s = {:?}", esvs.get("s"));
    assert_eq!(esvs.get("s"), Some(&Value::Str("ab".into())));
    assert!(matches!(esvs.get("m"), Some(Value::Map(_))), "m = {:?}", esvs.get("m"));
    assert!(matches!(esvs.get("l"), Some(Value::List(_))), "l = {:?}", esvs.get("l"));
    // nested values inside containers are canonical too (no wrappers)
    if let Some(Value::Map(m)) = esvs.get("m") {
        assert_eq!(m.get("k"), Some(&Value::Int(2)));
    }
    if let Some(Value::List(l)) = esvs.get("l") {
        assert!(l.iter().all(|x| matches!(x, Value::Int(_))));
        assert_eq!(l, &vec![Value::Int(1), Value::Int(2), Value::Int(3)]);
    }
}

#[test]
fn snapshot_contains_only_json_representable_values() {
    let engine = run();
    let snap = engine.snapshot("r").expect("snapshot");
    // every boundary value is plain JSON-serializable (no wrapper types exist in
    // `Value`, so the whole snapshot must round-trip cleanly)
    let json = serde_json::to_string(&snap).expect("snapshot is JSON-serializable");
    assert!(json.contains("\"top::i\":3"));
    assert!(json.contains("\"top::s\":\"ab\""));
    // and the resolved value is canonical
    assert_eq!(snap.esvs.get("top::i"), Some(&Value::Int(3)));
}

#[test]
fn assign_coerces_int_to_declared_float() {
    // a CEL int result assigned to a float-typed esv is stored as a canonical float
    let src = "id: coerce
events: { go: {} }
top:
  esvs:
    f: { type: float, init: 0.0 }
  initial: { transition_to: a }
  states:
    a:
      on_events:
        go:
          action: [ { assign: { f: \"3\" } } ]
";
    let docs = load_machines(src).expect("parses");
    let machines = resolve_definitions(&docs).expect("builds");
    let mut engine = Engine::new();
    for m in machines {
        engine.register(m);
    }
    engine.create_root("r", "coerce", None, &BTreeMap::new()).unwrap();
    engine.send("r", "go", Value::Null).unwrap();
    let esvs = engine.state_view("r").unwrap().esvs;
    assert_eq!(esvs.get("f"), Some(&Value::Float(3.0)));
}

