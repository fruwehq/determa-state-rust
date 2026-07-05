//! The dynamic value type used for esvs, event payloads, and CEL evaluation.
//!
//! Maps keep sorted keys for deterministic JSON serialization (conformance compares
//! JSON structurally, so key order is irrelevant, but stable output helps humans).

use std::collections::BTreeMap;

/// A Determa State runtime value. Mirrors the esv/payload `type` set (§4.4) plus `null`.
///
/// `Value` serializes as its **canonical JSON/native form** (an `Int(3)` is `3`, a
/// `Bool(true)` is `true`, …), never as a tagged enum — so no engine-internal wrapper
/// type leaks across any boundary (library, snapshot §8, CLI `--json` §13.4, observer
/// §8) per SPEC §5.1.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    List(Vec<Value>),
    Map(BTreeMap<String, Value>),
}

impl Value {
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Null => "null",
            Value::Bool(_) => "bool",
            Value::Int(_) => "int",
            Value::Float(_) => "float",
            Value::Str(_) => "string",
            Value::List(_) => "list",
            Value::Map(_) => "map",
        }
    }

    /// Is this value concretely of the declared esv/payload `type`?
    /// `null` satisfies any type (an unset variable / optional payload field).
    pub fn matches_type(&self, ty: &str) -> bool {
        match (self, ty) {
            (Value::Null, _) => true,
            (Value::Bool(_), "bool") => true,
            (Value::Int(_), "int") => true,
            (Value::Float(_), "float") => true,
            (Value::Str(_), "string") => true,
            (Value::List(_), "list") => true,
            (Value::Map(_), "map") => true,
            _ => false,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn truthy(&self) -> bool {
        match self {
            Value::Bool(b) => *b,
            Value::Null => false,
            Value::Int(i) => *i != 0,
            Value::Float(f) => *f != 0.0,
            Value::Str(s) => !s.is_empty(),
            Value::List(l) => !l.is_empty(),
            Value::Map(m) => !m.is_empty(),
        }
    }

    pub fn as_str_value(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Coerce a value to a declared type for assignment / payload delivery.
    /// Returns None if the value is not coercible (used to reject bad payloads).
    pub fn coerce_to(&self, ty: &str) -> Option<Value> {
        match (self, ty) {
            (Value::Null, _) => Some(Value::Null),
            (Value::Bool(b), "bool") => Some(Value::Bool(*b)),
            (Value::Int(i), "int") => Some(Value::Int(*i)),
            (Value::Float(f), "float") => Some(Value::Float(*f)),
            (Value::Str(s), "string") => Some(Value::Str(s.clone())),
            (Value::List(l), "list") => Some(Value::List(l.clone())),
            (Value::Map(m), "map") => Some(Value::Map(m.clone())),
            // int literal used where float is declared
            (Value::Int(i), "float") => Some(Value::Float(*i as f64)),
            // numeric strings are NOT coerced (only CLI --payload k=v does string coercion)
            _ => None,
        }
    }
}

// Canonical JSON/native (de)serialization (SPEC §5.1): a Value is its underlying
// JSON value, never a tagged wrapper.
impl serde::Serialize for Value {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.to_json().serialize(s)
    }
}

impl<'de> serde::Deserialize<'de> for Value {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        serde_json::Value::deserialize(d).map(|j| Value::from_json(&j))
    }
}

impl Value {
    pub fn from_yaml(v: &serde_yaml::Value) -> Value {
        use serde_yaml::Value::*;
        match v {
            Null => Value::Null,
            Bool(b) => Value::Bool(*b),
            Number(n) => {
                if let Some(i) = n.as_i64() {
                    Value::Int(i)
                } else if let Some(u) = n.as_u64() {
                    Value::Int(u as i64)
                } else {
                    Value::Float(n.as_f64().unwrap_or(f64::NAN))
                }
            }
            String(s) => Value::Str(s.clone()),
            Sequence(seq) => Value::List(seq.iter().map(Value::from_yaml).collect()),
            Mapping(m) => {
                let mut map = BTreeMap::new();
                for (k, v) in m {
                    let key = match k {
                        String(s) => s.clone(),
                        Bool(b) => b.to_string(),
                        Number(n) => n.to_string(),
                        Null => "null".to_string(),
                        _ => continue,
                    };
                    map.insert(key, Value::from_yaml(v));
                }
                Value::Map(map)
            }
            Tagged(t) => Value::from_yaml(&t.value),
        }
    }

    pub fn to_json(&self) -> serde_json::Value {
        match self {
            Value::Null => serde_json::Value::Null,
            Value::Bool(b) => serde_json::Value::Bool(*b),
            Value::Int(i) => serde_json::Value::Number((*i as i64).into()),
            Value::Float(f) => serde_json::Number::from_f64(*f)
                .map(serde_json::Value::Number)
                .unwrap_or(serde_json::Value::Null),
            Value::Str(s) => serde_json::Value::String(s.clone()),
            Value::List(l) => serde_json::Value::Array(l.iter().map(Value::to_json).collect()),
            Value::Map(m) => {
                let mut o = serde_json::Map::new();
                for (k, v) in m {
                    o.insert(k.clone(), v.to_json());
                }
                serde_json::Value::Object(o)
            }
        }
    }

    pub fn from_json(v: &serde_json::Value) -> Value {
        match v {
            serde_json::Value::Null => Value::Null,
            serde_json::Value::Bool(b) => Value::Bool(*b),
            serde_json::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    Value::Int(i)
                } else if let Some(u) = n.as_u64() {
                    Value::Int(u as i64)
                } else {
                    Value::Float(n.as_f64().unwrap_or(f64::NAN))
                }
            }
            serde_json::Value::String(s) => Value::Str(s.clone()),
            serde_json::Value::Array(a) => {
                Value::List(a.iter().map(Value::from_json).collect())
            }
            serde_json::Value::Object(o) => {
                let mut m = BTreeMap::new();
                for (k, v) in o {
                    m.insert(k.clone(), Value::from_json(v));
                }
                Value::Map(m)
            }
        }
    }
}

/// Build a single-field map, common for payloads.
pub fn map1(k: &str, v: Value) -> Value {
    let mut m = BTreeMap::new();
    m.insert(k.to_string(), v);
    Value::Map(m)
}
