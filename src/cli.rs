//! The standard `harel` CLI (SPEC §13). A thin wrapper over the library [`Engine`]
//! that persists state through a pluggable store (§13.1). Commands, exit codes, and
//! the `--json` output shapes are normative.

use crate::machine::parse_duration;
use crate::runtime::{Mode, RunResult, Status, StepRecord};
use crate::store::{open, Store, StoreData, StoreSpec};
use crate::value::Value;
use crate::{build_machine, load_machines, validate, Engine};
use std::collections::BTreeMap;
use std::io::{Read, Write};

// exit codes (§13.2)
const EXIT_OK: i32 = 0;
const EXIT_USAGE: i32 = 2;
const EXIT_VALIDATION: i32 = 3;
const EXIT_NOT_FOUND: i32 = 4;
const EXIT_FAULTED: i32 = 5;
const EXIT_OTHER: i32 = 1;

struct CmdOut {
    exit: i32,
    json: Option<Value>,
    text: Option<String>,
}

impl CmdOut {
    fn json(exit: i32, v: Value) -> CmdOut {
        CmdOut { exit, json: Some(v), text: None }
    }
    fn text(exit: i32, s: String) -> CmdOut {
        CmdOut { exit, json: None, text: Some(s) }
    }
    fn ok() -> CmdOut {
        CmdOut { exit: EXIT_OK, json: None, text: None }
    }
}

/// Entry point used by the `harel` binary.
pub fn run(args: Vec<String>) -> i32 {
    let mut store_spec = StoreSpec::File(default_store_dir());
    let mut json = false;
    let mut positional: Vec<String> = Vec::new();
    let mut iter = args.into_iter().skip(1).peekable();
    while let Some(a) = iter.next() {
        match a.as_str() {
            "--help" | "-h" => {
                print_help();
                return EXIT_OK;
            }
            "--version" => {
                println!("harel 0.0.2 (implements harel spec v0.0.2)");
                return EXIT_OK;
            }
            "--json" => json = true,
            "--store" => match iter.next() {
                Some(s) => store_spec = StoreSpec::parse(&s),
                None => return err_exit(EXIT_USAGE, "--store requires an argument"),
            },
            _ if a.starts_with("--store=") => {
                store_spec = StoreSpec::parse(&a["--store=".len()..]);
            }
            _ => positional.push(a),
        }
    }

    if positional.is_empty() {
        print_help();
        return EXIT_USAGE;
    }

    let cmd = positional[0].as_str();
    if cmd == "run" {
        return run_batch(&store_spec, &positional[1..]);
    }

    let store = open(&store_spec);
    let mut data = store.load();
    let mut engine = build_engine(&data);
    let out = dispatch(&mut engine, &mut data, &positional);
    // persist (defs may have grown via `new`)
    persist(&*store, &mut data, &engine);
    emit(out, json)
}

fn default_store_dir() -> std::path::PathBuf {
    if let Ok(s) = std::env::var("HAREL_STORE") {
        return std::path::PathBuf::from(s);
    }
    std::path::PathBuf::from("./.harel")
}

fn err_exit(code: i32, msg: &str) -> i32 {
    eprintln!("{msg}");
    code
}

fn print_help() {
    println!(
        "harel — statechart engine CLI (spec v0.0.2)\n\
         usage: harel [--store <spec>] [--json] <command> [args]\n\
         commands: validate, export, new, send, advance, env, state, list, snapshot,\n\
                   restore, mode, inject, step, inspect, run"
    );
}

// ---------------------------------------------------------------------------
// engine <-> store

fn build_engine(data: &StoreData) -> Engine {
    let mut eng = Engine::new();
    for yaml in &data.defs {
        if let Ok(docs) = load_machines(yaml) {
            for raw in &docs {
                if let Ok(m) = build_machine(raw) {
                    eng.register(m);
                }
            }
        }
    }
    for snap in data.instances.clone() {
        let _ = eng.restore(snap);
    }
    eng.clock = data.clock;
    eng.mode = data.mode();
    eng
}

fn persist(store: &dyn Store, data: &mut StoreData, engine: &Engine) {
    let mut snaps = Vec::new();
    for lv in engine.list_view() {
        if let Ok(s) = engine.snapshot(&lv.id) {
            snaps.push(s);
        }
    }
    data.instances = snaps;
    data.clock = engine.clock;
    data.mode = match engine.mode {
        Mode::Auto => "auto",
        Mode::Manual => "manual",
    }
    .to_string();
    store.save(data);
}

// ---------------------------------------------------------------------------
// dispatch a single command

fn dispatch(engine: &mut Engine, data: &mut StoreData, args: &[String]) -> CmdOut {
    let cmd = args[0].as_str();
    let rest = &args[1..];
    match cmd {
        "validate" => cmd_validate(rest),
        "export" => cmd_export(rest),
        "new" => cmd_new(engine, data, rest),
        "send" => cmd_send(engine, rest, false),
        "advance" => cmd_advance(engine, rest),
        "env" => cmd_env(engine, rest),
        "state" => cmd_state(engine, rest),
        "list" => cmd_list(engine),
        "snapshot" => cmd_snapshot(engine, rest),
        "restore" => cmd_restore(engine, rest),
        "mode" => cmd_mode(engine, rest),
        "inject" => cmd_send(engine, rest, true),
        "step" => cmd_step(engine, rest),
        "inspect" => cmd_inspect(engine, rest),
        other => CmdOut::text(EXIT_USAGE, format!("unknown command '{other}'")),
    }
}

// ----- helpers -----

fn status_str(s: Status) -> &'static str {
    match s {
        Status::Active => "active",
        Status::Faulted => "faulted",
        Status::Terminated => "terminated",
    }
}

fn state_json(engine: &Engine, id: &str) -> Option<Value> {
    match engine.state_view(id) {
        Ok(v) => Some(state_value(&v)),
        Err(_) => None,
    }
}

fn state_value(v: &crate::runtime::StateView) -> Value {
    let mut m = BTreeMap::new();
    m.insert("instance".to_string(), Value::Str(v.instance.clone()));
    m.insert("def".to_string(), Value::Str(v.def.clone()));
    m.insert("status".to_string(), Value::Str(status_str(v.status).to_string()));
    m.insert("config".to_string(), Value::List(v.config.iter().map(|s| Value::Str(s.clone())).collect()));
    m.insert("esvs".to_string(), Value::Map(v.esvs.clone()));
    Value::Map(m)
}

fn read_file(path: &str) -> Result<String, CmdOut> {
    std::fs::read_to_string(path).map_err(|e| CmdOut::text(EXIT_OTHER, format!("{e}")))
}

/// Parse --payload / --external / --changed style flags.
struct Flags {
    payload_pairs: Vec<(String, String)>,
    payload_json: Option<String>,
    external_pairs: Vec<(String, String)>,
    changed_pairs: Vec<(String, String)>,
    positional: Vec<String>,
    steps: Option<String>,
}

fn parse_flags(args: &[String]) -> Flags {
    let mut f = Flags {
        payload_pairs: Vec::new(),
        payload_json: None,
        external_pairs: Vec::new(),
        changed_pairs: Vec::new(),
        positional: Vec::new(),
        steps: None,
    };
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        match a.as_str() {
            "--payload" if i + 1 < args.len() => {
                if let Some((k, v)) = split_eq(&args[i + 1]) {
                    f.payload_pairs.push((k, v));
                }
                i += 2;
            }
            "--payload-json" if i + 1 < args.len() => {
                f.payload_json = Some(args[i + 1].clone());
                i += 2;
            }
            "--external" if i + 1 < args.len() => {
                if let Some((k, v)) = split_eq(&args[i + 1]) {
                    f.external_pairs.push((k, v));
                }
                i += 2;
            }
            "--changed" if i + 1 < args.len() => {
                for part in args[i + 1].split(',') {
                    if let Some((k, v)) = split_eq(part) {
                        f.changed_pairs.push((k, v));
                    }
                }
                i += 2;
            }
            "--steps" if i + 1 < args.len() => {
                f.steps = Some(args[i + 1].clone());
                i += 2;
            }
            _ if a.starts_with("--payload=") => {
                if let Some((k, v)) = split_eq(&a["--payload=".len()..]) {
                    f.payload_pairs.push((k, v));
                }
                i += 1;
            }
            _ => {
                f.positional.push(a.clone());
                i += 1;
            }
        }
    }
    f
}

fn split_eq(s: &str) -> Option<(String, String)> {
    let idx = s.find('=')?;
    Some((s[..idx].to_string(), s[idx + 1..].to_string()))
}

fn coerce_str(s: &str, ty: Option<&str>) -> Value {
    match ty {
        Some("int") => s.parse::<i64>().map(Value::Int).unwrap_or(Value::Str(s.to_string())),
        Some("float") => s.parse::<f64>().map(Value::Float).unwrap_or(Value::Str(s.to_string())),
        Some("bool") => match s {
            "true" => Value::Bool(true),
            "false" => Value::Bool(false),
            _ => Value::Str(s.to_string()),
        },
        _ => {
            // YAML-ish scalar inference for bare values
            if let Ok(i) = s.parse::<i64>() {
                Value::Int(i)
            } else if s == "true" {
                Value::Bool(true)
            } else if s == "false" {
                Value::Bool(false)
            } else if s == "null" {
                Value::Null
            } else {
                Value::Str(s.to_string())
            }
        }
    }
}

fn event_field_type(engine: &Engine, inst: &str, etype: &str, field: &str) -> Option<String> {
    let inst = engine.instance(inst).ok()?;
    let m = engine.defs.get(&(inst.def_id.clone(), inst.def_version))?;
    m.events.get(etype).and_then(|d| d.payload.iter().find(|(n, _)| n == field).map(|(_, f)| f.ty.clone()))
}

fn esv_type(engine: &Engine, inst: &str, name: &str) -> Option<String> {
    let inst = engine.instance(inst).ok()?;
    let m = engine.defs.get(&(inst.def_id.clone(), inst.def_version))?;
    m.get(m.top).esvs.iter().find(|(n, _)| n == name).map(|(_, d)| d.ty.clone())
}

fn build_payload(engine: &Engine, inst: &str, etype: &str, f: &Flags) -> Result<Value, CmdOut> {
    if let Some(j) = &f.payload_json {
        let v: serde_json::Value = serde_json::from_str(j)
            .map_err(|e| CmdOut::text(EXIT_VALIDATION, format!("invalid --payload-json: {e}")))?;
        return Ok(Value::from_json(&v));
    }
    if f.payload_pairs.is_empty() {
        return Ok(Value::Null);
    }
    let mut m = BTreeMap::new();
    for (k, v) in &f.payload_pairs {
        let ty = event_field_type(engine, inst, etype, k);
        m.insert(k.clone(), coerce_str(v, ty.as_deref()));
    }
    Ok(Value::Map(m))
}

// ----- commands -----

fn cmd_validate(args: &[String]) -> CmdOut {
    let path = match args.first() {
        Some(p) => p,
        None => return CmdOut::text(EXIT_USAGE, "validate <machine.yaml>".into()),
    };
    let src = match read_file(path) {
        Ok(s) => s,
        Err(c) => return c,
    };
    let docs = match load_machines(&src) {
        Ok(d) => d,
        Err(errs) => {
            return validate_result(false, errs.into_iter().map(|e| (e.path, e.message)).collect());
        }
    };
    let (valid, errs) = validate(&docs, &[]);
    validate_result(valid, errs.into_iter().map(|e| (e.path, e.message)).collect())
}

fn validate_result(valid: bool, errs: Vec<(String, String)>) -> CmdOut {
    let mut m = BTreeMap::new();
    m.insert("valid".to_string(), Value::Bool(valid));
    let err_list: Vec<Value> = errs
        .into_iter()
        .map(|(path, message)| {
            Value::Map(
                [("path".to_string(), Value::Str(path)), ("message".to_string(), Value::Str(message))]
                    .into_iter()
                    .collect(),
            )
        })
        .collect();
    m.insert("errors".to_string(), Value::List(err_list));
    let exit = if valid { EXIT_OK } else { EXIT_VALIDATION };
    CmdOut::json(exit, Value::Map(m))
}

fn cmd_export(args: &[String]) -> CmdOut {
    let path = match args.iter().find(|a| !a.starts_with("--")) {
        Some(p) => p,
        None => return CmdOut::text(EXIT_USAGE, "export <machine.yaml>".into()),
    };
    let src = match read_file(path) {
        Ok(s) => s,
        Err(c) => return c,
    };
    let docs = match load_machines(&src) {
        Ok(d) => d,
        Err(e) => return CmdOut::text(EXIT_VALIDATION, format!("{e:?}")),
    };
    let m = match build_machine(&docs[0]) {
        Ok(m) => m,
        Err(e) => return CmdOut::text(EXIT_VALIDATION, format!("{e:?}")),
    };
    let mermaid = crate::export::mermaid(&m);
    CmdOut::text(EXIT_OK, mermaid)
}

fn cmd_new(engine: &mut Engine, data: &mut StoreData, args: &[String]) -> CmdOut {
    let f = parse_flags(args);
    let pos = &f.positional;
    if pos.len() < 2 {
        return CmdOut::text(EXIT_USAGE, "new <id> <machine.yaml> [--external k=v]".into());
    }
    let id = &pos[0];
    let path = &pos[1];
    if engine.instances.contains_key(id) {
        return CmdOut::text(EXIT_USAGE, format!("instance '{id}' already exists"));
    }
    let src = match read_file(path) {
        Ok(s) => s,
        Err(c) => return c,
    };
    let docs = match load_machines(&src) {
        Ok(d) => d,
        Err(e) => return CmdOut::text(EXIT_VALIDATION, format!("{e:?}")),
    };
    let (valid, errs) = validate(&docs, &[]);
    if !valid {
        return validate_result(false, errs.into_iter().map(|e| (e.path, e.message)).collect());
    }
    // register all docs, remember the root def
    data.defs.push(src);
    let root_def = docs[0].id.clone();
    let root_ver = docs[0].version.unwrap_or(1);
    for raw in &docs {
        if let Ok(m) = build_machine(raw) {
            engine.register(m);
        }
    }
    // external esvs
    let mut external = BTreeMap::new();
    for (k, v) in &f.external_pairs {
        let ty = esv_type(engine, id, k);
        external.insert(k.clone(), coerce_str(v, ty.as_deref()));
    }
    if let Err(e) = engine.create_root(id, &root_def, Some(root_ver), &external) {
        return CmdOut::text(EXIT_OTHER, format!("{e:?}"));
    }
    match state_json(engine, id) {
        Some(v) => fault_exit(engine, id, CmdOut::json(EXIT_OK, v)),
        None => CmdOut::text(EXIT_NOT_FOUND, format!("instance '{id}' not found")),
    }
}

fn cmd_send(engine: &mut Engine, args: &[String], inject: bool) -> CmdOut {
    let f = parse_flags(args);
    let pos = &f.positional;
    if pos.len() < 2 {
        return CmdOut::text(EXIT_USAGE, "<instance> <event> [--payload k=v]".into());
    }
    let id = &pos[0];
    let etype = &pos[1];
    if !engine.instances.contains_key(id) {
        return CmdOut::text(EXIT_NOT_FOUND, format!("instance '{id}' not found"));
    }
    let payload = match build_payload(engine, id, etype, &f) {
        Ok(p) => p,
        Err(c) => return c,
    };
    let mut run_result: Option<RunResult> = None;
    if inject {
        let accepted = match engine.inject(id, etype, payload) {
            Ok(a) => a,
            Err(e) => return CmdOut::text(EXIT_OTHER, format!("{e:?}")),
        };
        if !accepted {
            return CmdOut::text(EXIT_VALIDATION, format!("event '{etype}' rejected"));
        }
    } else {
        let accepted = engine.validate_event(id, etype, &payload).is_ok();
        if !accepted {
            return CmdOut::text(EXIT_VALIDATION, format!("event '{etype}' rejected"));
        }
        let run = match engine.send(id, etype, payload) {
            Ok(r) => r,
            Err(e) => return CmdOut::text(EXIT_OTHER, format!("{e:?}")),
        };
        run_result = Some(run);
    }
    let mut v = match state_json(engine, id) {
        Some(v) => v,
        None => return CmdOut::text(EXIT_NOT_FOUND, format!("instance '{id}' not found")),
    };
    if !inject {
        if let Value::Map(m) = &mut v {
            let published = run_result
                .map(|r| r.published.into_iter().map(Value::Str).collect::<Vec<_>>())
                .unwrap_or_default();
            m.insert("published".to_string(), Value::List(published));
        }
    }
    fault_exit(engine, id, CmdOut::json(EXIT_OK, v))
}

/// If the addressed instance ended up faulted, override the exit code to 5.
fn fault_exit(engine: &Engine, id: &str, out: CmdOut) -> CmdOut {
    if let Ok(inst) = engine.instance(id) {
        if inst.status == Status::Faulted && out.exit == EXIT_OK {
            return CmdOut { exit: EXIT_FAULTED, ..out };
        }
    }
    out
}

fn cmd_advance(engine: &mut Engine, args: &[String]) -> CmdOut {
    let dur = match args.first() {
        Some(d) => d,
        None => return CmdOut::text(EXIT_USAGE, "advance <duration>".into()),
    };
    let ms = match parse_duration(dur) {
        Ok(m) => m,
        Err(e) => return CmdOut::text(EXIT_USAGE, e),
    };
    if let Err(e) = engine.advance(ms) {
        return CmdOut::text(EXIT_OTHER, format!("{e:?}"));
    }
    // print root state if present, else empty object
    if engine.instances.contains_key("root") {
        match state_json(engine, "root") {
            Some(v) => return CmdOut::json(EXIT_OK, v),
            None => {}
        }
    }
    CmdOut::json(EXIT_OK, Value::Map(BTreeMap::new()))
}

fn cmd_env(engine: &mut Engine, args: &[String]) -> CmdOut {
    let f = parse_flags(args);
    let id = match f.positional.first() {
        Some(i) => i,
        None => return CmdOut::text(EXIT_USAGE, "env <instance> --changed k=v,...".into()),
    };
    if !engine.instances.contains_key(id) {
        return CmdOut::text(EXIT_NOT_FOUND, format!("instance '{id}' not found"));
    }
    let mut changed = BTreeMap::new();
    for (k, v) in &f.changed_pairs {
        let ty = esv_type(engine, id, k);
        changed.insert(k.clone(), coerce_str(v, ty.as_deref()));
    }
    if let Err(e) = engine.env_change(id, changed) {
        return CmdOut::text(EXIT_OTHER, format!("{e:?}"));
    }
    match state_json(engine, id) {
        Some(v) => fault_exit(engine, id, CmdOut::json(EXIT_OK, v)),
        None => CmdOut::text(EXIT_NOT_FOUND, format!("instance '{id}' not found")),
    }
}

fn cmd_state(engine: &Engine, args: &[String]) -> CmdOut {
    let id = match args.first() {
        Some(i) => i,
        None => return CmdOut::text(EXIT_USAGE, "state <instance>".into()),
    };
    match state_json(engine, id) {
        Some(v) => CmdOut::json(EXIT_OK, v),
        None => CmdOut::text(EXIT_NOT_FOUND, format!("instance '{id}' not found")),
    }
}

fn cmd_list(engine: &Engine) -> CmdOut {
    let list: Vec<Value> = engine
        .list_view()
        .into_iter()
        .map(|lv| {
            let mut m = BTreeMap::new();
            m.insert("id".to_string(), Value::Str(lv.id));
            m.insert("def".to_string(), Value::Str(lv.def));
            m.insert("parent".to_string(), lv.parent.map(Value::Str).unwrap_or(Value::Null));
            m.insert("status".to_string(), Value::Str(status_str(lv.status).to_string()));
            m.insert("config".to_string(), Value::List(lv.config.into_iter().map(Value::Str).collect()));
            Value::Map(m)
        })
        .collect();
    CmdOut::json(EXIT_OK, Value::List(list))
}

fn cmd_snapshot(engine: &Engine, args: &[String]) -> CmdOut {
    let id = match args.first() {
        Some(i) => i,
        None => return CmdOut::text(EXIT_USAGE, "snapshot <instance>".into()),
    };
    match engine.snapshot(id) {
        Ok(s) => {
            let json = serde_json::to_string(&s).unwrap_or_default();
            let v: serde_json::Value = serde_json::from_str(&json).unwrap_or_default();
            CmdOut::json(EXIT_OK, Value::from_json(&v))
        }
        Err(e) => CmdOut::text(EXIT_NOT_FOUND, format!("{e:?}")),
    }
}

fn cmd_restore(engine: &mut Engine, args: &[String]) -> CmdOut {
    let path = match args.first() {
        Some(p) => p,
        None => return CmdOut::text(EXIT_USAGE, "restore <snapshot.json>".into()),
    };
    let src = match read_file(path) {
        Ok(s) => s,
        Err(c) => return c,
    };
    let v: serde_json::Value = match serde_json::from_str(&src) {
        Ok(v) => v,
        Err(e) => return CmdOut::text(EXIT_VALIDATION, format!("invalid snapshot: {e}")),
    };
    // snapshot must reference a registered def
    let def_id = v.get("def_id").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let ver = v.get("def_version").and_then(|x| x.as_i64()).unwrap_or(1);
    if !engine.defs.contains_key(&(def_id.clone(), ver)) {
        return CmdOut::text(EXIT_NOT_FOUND, format!("definition '{def_id}@{ver}' not registered"));
    }
    let snap: crate::runtime::Snapshot = serde_json::from_value(v).unwrap();
    let id = snap.id.clone();
    if let Err(e) = engine.restore(snap) {
        return CmdOut::text(EXIT_OTHER, format!("{e:?}"));
    }
    match state_json(engine, &id) {
        Some(v) => CmdOut::json(EXIT_OK, v),
        None => CmdOut::ok(),
    }
}

fn cmd_mode(engine: &mut Engine, args: &[String]) -> CmdOut {
    if let Some(m) = args.first() {
        let mode = match m.as_str() {
            "auto" => Mode::Auto,
            "manual" => Mode::Manual,
            _ => return CmdOut::text(EXIT_USAGE, "mode [auto|manual]".into()),
        };
        engine.set_mode(mode);
    }
    let mut map = BTreeMap::new();
    map.insert(
        "mode".to_string(),
        Value::Str(if engine.mode == Mode::Manual { "manual" } else { "auto" }.to_string()),
    );
    CmdOut::json(EXIT_OK, Value::Map(map))
}

fn cmd_step(engine: &mut Engine, args: &[String]) -> CmdOut {
    let f = parse_flags(args);
    let id = match f.positional.first() {
        Some(i) => i,
        None => return CmdOut::text(EXIT_USAGE, "step <instance> [--steps N]".into()),
    };
    if !engine.instances.contains_key(id) {
        return CmdOut::text(EXIT_NOT_FOUND, format!("instance '{id}' not found"));
    }
    let n: usize = f
        .steps
        .as_deref()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let records = match engine.step(id, n) {
        Ok(r) => r,
        Err(e) => return CmdOut::text(EXIT_OTHER, format!("{e:?}")),
    };
    let mut v = match state_json(engine, id) {
        Some(v) => v,
        None => return CmdOut::text(EXIT_NOT_FOUND, format!("instance '{id}' not found")),
    };
    let steps: Vec<Value> = records.iter().map(step_record_value).collect();
    if let Value::Map(m) = &mut v {
        m.insert("steps".to_string(), Value::List(steps));
    }
    fault_exit(engine, id, CmdOut::json(EXIT_OK, v))
}

fn step_record_value(r: &StepRecord) -> Value {
    let mut m = BTreeMap::new();
    m.insert("event".to_string(), Value::Str(r.event.clone()));
    m.insert(
        "transition".to_string(),
        r.transition.clone().map(Value::Str).unwrap_or(Value::Null),
    );
    m.insert("entered".to_string(), Value::List(r.entered.iter().map(|s| Value::Str(s.clone())).collect()));
    m.insert("exited".to_string(), Value::List(r.exited.iter().map(|s| Value::Str(s.clone())).collect()));
    m.insert("published".to_string(), Value::List(r.published.iter().map(|s| Value::Str(s.clone())).collect()));
    m.insert("spawned".to_string(), Value::List(r.spawned.iter().map(|s| Value::Str(s.clone())).collect()));
    m.insert("faulted".to_string(), Value::Bool(r.faulted));
    Value::Map(m)
}

fn cmd_inspect(engine: &Engine, args: &[String]) -> CmdOut {
    let id = match args.first() {
        Some(i) => i,
        None => return CmdOut::text(EXIT_USAGE, "inspect <instance>".into()),
    };
    let v = match engine.inspect_view(id) {
        Ok(v) => v,
        Err(e) => return CmdOut::text(EXIT_NOT_FOUND, format!("{e:?}")),
    };
    let mut m = BTreeMap::new();
    m.insert("instance".to_string(), Value::Str(v.instance));
    m.insert("status".to_string(), Value::Str(status_str(v.status).to_string()));
    m.insert("config".to_string(), Value::List(v.config.into_iter().map(Value::Str).collect()));
    m.insert("esvs".to_string(), Value::Map(v.esvs));
    m.insert(
        "queue".to_string(),
        Value::List(v.queue.into_iter().map(event_obj).collect()),
    );
    m.insert(
        "deferred".to_string(),
        Value::List(v.deferred.into_iter().map(event_obj).collect()),
    );
    m.insert(
        "timers".to_string(),
        Value::List(
            v.timers
                .into_iter()
                .map(|t| {
                    Value::Map(
                        [("state".to_string(), Value::Str(t.state.to_string())), ("due".to_string(), Value::Int(t.due as i64))]
                            .into_iter()
                            .collect(),
                    )
                })
                .collect(),
        ),
    );
    m.insert(
        "history".to_string(),
        Value::Map(v.history.into_iter().map(|(k, v)| (k, Value::Str(v))).collect()),
    );
    m.insert(
        "dead_letter".to_string(),
        Value::List(v.dead_letter.into_iter().map(|d| Value::Str(d.event.etype)).collect()),
    );
    CmdOut::json(EXIT_OK, Value::Map(m))
}

fn event_obj(e: crate::runtime::QueuedEvent) -> Value {
    let mut m = BTreeMap::new();
    m.insert("type".to_string(), Value::Str(e.etype));
    if !matches!(e.payload, Value::Null) {
        m.insert("payload".to_string(), e.payload);
    }
    Value::Map(m)
}

// ---------------------------------------------------------------------------
// batch / streaming mode (§13.7)

fn run_batch(store_spec: &StoreSpec, args: &[String]) -> i32 {
    // `run -` reads NDJSON argv lines from stdin; `-` optional.
    let _ = args;
    let store = open(store_spec);
    let mut data = store.load();
    let mut engine = build_engine(&data);
    let mut first_nonzero = 0;

    let mut stdin = String::new();
    if std::io::stdin().read_to_string(&mut stdin).is_err() {
        return EXIT_OTHER;
    }
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    for line in stdin.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let argv: Vec<String> = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => {
                let _ = write_line(&mut out, batch_obj(false, EXIT_USAGE, Value::Null, "invalid NDJSON line"));
                if first_nonzero == 0 {
                    first_nonzero = EXIT_USAGE;
                }
                continue;
            }
        };
        if argv.is_empty() {
            continue;
        }
        let r = dispatch(&mut engine, &mut data, &argv);
        let ok = r.exit == EXIT_OK;
        let err_text = r.text.clone().unwrap_or_default();
        let result = if let Some(j) = r.json {
            j
        } else if let Some(t) = r.text {
            Value::Str(t)
        } else {
            Value::Null
        };
        let obj = if ok {
            batch_obj(true, EXIT_OK, result, "")
        } else {
            batch_obj(false, r.exit, Value::Null, &err_text)
        };
        let _ = write_line(&mut out, obj);
        if r.exit != EXIT_OK && first_nonzero == 0 {
            first_nonzero = r.exit;
        }
        let _ = result;
    }
    // persist final state
    persist(&*store, &mut data, &engine);
    let _ = out.flush();
    first_nonzero
}

fn batch_obj(ok: bool, exit: i32, result: Value, err: &str) -> String {
    let mut m = BTreeMap::new();
    m.insert("ok".to_string(), Value::Bool(ok));
    m.insert("exit".to_string(), Value::Int(exit as i64));
    m.insert("result".to_string(), result);
    if !ok {
        let mut e = BTreeMap::new();
        e.insert("message".to_string(), Value::Str(err.to_string()));
        m.insert("error".to_string(), Value::Map(e));
    } else {
        m.insert("error".to_string(), Value::Null);
    }
    serde_json::to_string(&Value::Map(m).to_json()).unwrap_or_default()
}

fn write_line<W: Write>(w: &mut W, s: String) -> std::io::Result<()> {
    writeln!(w, "{s}")
}

// ---------------------------------------------------------------------------
// emit

fn emit(out: CmdOut, json: bool) -> i32 {
    let exit = out.exit;
    match (out.json, out.text) {
        (Some(v), _) => {
            println!("{}", serde_json::to_string_pretty(&v.to_json()).unwrap_or_default());
        }
        (None, Some(t)) => {
            // for validate (which has both json shape and text fallback) prefer json
            if json {
                println!("{t}");
            } else {
                println!("{t}");
            }
        }
        (None, None) => {}
    }
    exit
}

// silence unused warning for RunResult import path
#[allow(unused_imports)]
use crate::machine::Machine as _Machine;
