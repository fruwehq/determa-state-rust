//! Guard / action-value evaluation via the [Common Expression Language][cel]
//! (SPEC §6), backed by the [`cel-interpreter`][crate] crate (cel-rust).
//!
//! Determa State mandates CEL so a guard means the same thing in every runtime. This module
//! is a thin adapter: it builds a CEL context from the Determa State scope (in-scope `esvs`
//! + `event.payload.*` + the intrinsics `id`/`parent`/`state`), converts between
//! Determa State's [`Value`] and CEL values, and maps CEL runtime errors onto [`CelError`]
//! (which the runtime treats as an action fault, SPEC §5.10). Boundary values stay
//! canonical native/JSON (§5.1): every CEL result is normalized back to a [`Value`].
//!
//! [cel]: https://cel.dev/

use crate::value::Value;
use cel_interpreter::objects::{Key, Map as CelMap, Value as CelValue};
use cel_interpreter::{Context, ExecutionError, Program};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CelError {
    DivByZero,
    Type(String),
    Other(String),
}

impl std::fmt::Display for CelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CelError::DivByZero => write!(f, "division by zero"),
            CelError::Type(m) => write!(f, "type error: {m}"),
            CelError::Other(m) => write!(f, "{m}"),
        }
    }
}
impl std::error::Error for CelError {}

/// A CEL environment: the bindings visible to a guard / action value (resolved
/// in-scope `esvs` plus the `event`/`id`/`parent` intrinsics).
#[derive(Debug, Clone, Default)]
pub struct Env {
    pub bindings: BTreeMap<String, Value>,
}

impl Env {
    pub fn new() -> Self {
        Self {
            bindings: BTreeMap::new(),
        }
    }
    pub fn with(mut self, k: impl Into<String>, v: Value) -> Self {
        self.bindings.insert(k.into(), v);
        self
    }
    pub fn get(&self, k: &str) -> Option<&Value> {
        self.bindings.get(k)
    }
}

/// Evaluate a CEL expression, returning its value as a canonical Determa State [`Value`].
pub fn eval(src: &str, env: &Env) -> Result<Value, CelError> {
    let program = Program::compile(src)
        .map_err(|e| CelError::Other(format!("CEL parse error: {e}")))?;
    let mut ctx = Context::default();
    for (k, v) in &env.bindings {
        let _ = ctx.add_variable(k.clone(), to_cel(v));
    }
    let result = program.execute(&ctx).map_err(map_exec_error)?;
    Ok(from_cel(&result))
}

/// Evaluate a CEL expression as a boolean guard.
pub fn eval_bool(src: &str, env: &Env) -> Result<bool, CelError> {
    match eval(src, env)? {
        Value::Bool(b) => Ok(b),
        other => Ok(other.truthy()),
    }
}

fn map_exec_error(e: ExecutionError) -> CelError {
    match e {
        ExecutionError::DivisionByZero(_) | ExecutionError::RemainderByZero(_) => CelError::DivByZero,
        ExecutionError::UnexpectedType { .. } => CelError::Type(e.to_string()),
        other => CelError::Other(other.to_string()),
    }
}

// --- value conversion ------------------------------------------------------

/// Convert a Determa State [`Value`] into a CEL value for context binding.
fn to_cel(v: &Value) -> CelValue {
    match v {
        Value::Null => CelValue::Null,
        Value::Bool(b) => CelValue::Bool(*b),
        Value::Int(i) => CelValue::Int(*i),
        Value::Float(f) => CelValue::Float(*f),
        Value::Str(s) => CelValue::String(Arc::new(s.clone())),
        Value::List(l) => {
            CelValue::List(Arc::new(l.iter().map(to_cel).collect()))
        }
        Value::Map(m) => {
            let mut hm: HashMap<String, CelValue> = HashMap::new();
            for (k, vv) in m {
                hm.insert(k.clone(), to_cel(vv));
            }
            CelValue::Map(CelMap::from(hm))
        }
    }
}

/// Normalize a CEL result back into a canonical Determa State [`Value`] (§5.1).
fn from_cel(v: &CelValue) -> Value {
    match v {
        CelValue::Null => Value::Null,
        CelValue::Bool(b) => Value::Bool(*b),
        CelValue::Int(i) => Value::Int(*i),
        CelValue::UInt(u) => Value::Int(*u as i64),
        CelValue::Float(f) => Value::Float(*f),
        CelValue::String(s) => Value::Str(s.as_ref().clone()),
        CelValue::List(l) => Value::List(l.iter().map(from_cel).collect()),
        CelValue::Map(m) => {
            let mut out = BTreeMap::new();
            for (k, vv) in m.map.iter() {
                out.insert(key_to_string(k), from_cel(vv));
            }
            Value::Map(out)
        }
        // Bytes/Duration/Timestamp/Function have no Determa State value type; surface as null.
        CelValue::Bytes(_) | CelValue::Duration(_) | CelValue::Timestamp(_) | CelValue::Function(..) => {
            Value::Null
        }
    }
}

fn key_to_string(k: &Key) -> String {
    match k {
        Key::String(s) => s.as_ref().clone(),
        Key::Int(i) => i.to_string(),
        Key::Bool(b) => b.to_string(),
        other => format!("{other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> Env {
        Env::new()
            .with("x", Value::Int(10))
            .with(
                "event",
                Value::Map(
                    [(
                        "payload".to_string(),
                        Value::Map([("n".to_string(), Value::Int(5))].into_iter().collect()),
                    )]
                    .into_iter()
                    .collect(),
                ),
            )
            .with("s", Value::Str("hello".into()))
            .with("items", Value::List(vec![Value::Int(1), Value::Int(2), Value::Int(3)]))
    }

    #[test]
    fn basics() {
        assert_eq!(eval("1 + 2", &Env::new()).unwrap(), Value::Int(3));
        assert_eq!(eval("x + 5", &env()).unwrap(), Value::Int(15));
        assert_eq!(eval("event.payload.n > 3", &env()).unwrap(), Value::Bool(true));
        assert_eq!(eval("event.payload.n > 10", &env()).unwrap(), Value::Bool(false));
        assert_eq!(eval("s + '!' == \"hello!\"", &env()).unwrap(), Value::Bool(true));
        assert_eq!(eval("'a' in ['a','b']", &Env::new()).unwrap(), Value::Bool(true));
    }

    #[test]
    fn div_zero() {
        assert!(matches!(eval("10 / 0", &Env::new()), Err(CelError::DivByZero)));
    }

    #[test]
    fn list_concat_and_map_literal() {
        assert_eq!(
            eval("[1,2] + ['c']", &Env::new()).unwrap(),
            Value::List(vec![Value::Int(1), Value::Int(2), Value::Str("c".into())])
        );
        let m = eval("{'k': 2}", &Env::new()).unwrap();
        assert_eq!(m, Value::Map([("k".to_string(), Value::Int(2))].into_iter().collect()));
    }

    // --- CEL features beyond the old hand-rolled subset ---

    #[test]
    fn ternary() {
        assert_eq!(eval("x > 0 ? 1 : 2", &env()).unwrap(), Value::Int(1));
        let e = Env::new().with("x", Value::Int(-3));
        assert_eq!(eval("x > 0 ? 1 : 2", &e).unwrap(), Value::Int(2));
    }

    #[test]
    fn exists_macro() {
        assert_eq!(eval("items.exists(i, i > 2)", &env()).unwrap(), Value::Bool(true));
        assert_eq!(eval("items.exists(i, i > 9)", &env()).unwrap(), Value::Bool(false));
        assert_eq!(eval("items.all(i, i > 0)", &env()).unwrap(), Value::Bool(true));
    }

    #[test]
    fn functions() {
        assert_eq!(eval("size(items)", &env()).unwrap(), Value::Int(3));
        assert_eq!(eval("s.contains(\"ell\")", &env()).unwrap(), Value::Bool(true));
        assert_eq!(eval("s.startsWith(\"he\")", &env()).unwrap(), Value::Bool(true));
    }
}
