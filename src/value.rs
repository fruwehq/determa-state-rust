use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct InstanceReference {
    pub root_instance_id: String,
    pub instance_id: String,
    pub machine_id: String,
    pub machine_version: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    String(String),
    List(Vec<Value>),
    Map(BTreeMap<String, Value>),
    InstanceReference(InstanceReference),
}

impl Value {
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::Bool(_) => "bool",
            Self::Int(_) => "int",
            Self::Float(_) => "float",
            Self::String(_) => "string",
            Self::List(_) => "list",
            Self::Map(_) => "map",
            Self::InstanceReference(_) => "instance_reference",
        }
    }

    pub fn matches_type(&self, declared_type: &str) -> bool {
        matches!(
            (self, declared_type),
            (Self::Bool(_), "bool")
                | (Self::Int(_), "int")
                | (Self::Float(_), "float")
                | (Self::String(_), "string")
                | (Self::List(_), "list")
                | (Self::Map(_), "map")
                | (Self::InstanceReference(_), "instance_reference")
        )
    }

    pub fn normalize_for_type(&self, declared_type: &str) -> Option<Self> {
        match (self, declared_type) {
            (Self::Int(value), "float") => Some(Self::Float(*value as f64)),
            _ if self.matches_type(declared_type) => Some(self.clone()),
            _ => None,
        }
    }

    pub fn from_json(value: &serde_json::Value) -> Result<Self, String> {
        match value {
            serde_json::Value::Null => Ok(Self::Null),
            serde_json::Value::Bool(value) => Ok(Self::Bool(*value)),
            serde_json::Value::Number(value) => {
                if let Some(integer) = value.as_i64() {
                    Ok(Self::Int(integer))
                } else {
                    let float = value
                        .as_f64()
                        .ok_or_else(|| "numeric value is not representable".to_string())?;
                    if !float.is_finite() {
                        return Err("numeric value is not finite".to_string());
                    }
                    Ok(Self::Float(if float == 0.0 { 0.0 } else { float }))
                }
            }
            serde_json::Value::String(value) => {
                if value
                    .chars()
                    .any(|character| (0xD800..=0xDFFF).contains(&(character as u32)))
                {
                    return Err("invalid Unicode scalar".to_string());
                }
                Ok(Self::String(value.clone()))
            }
            serde_json::Value::Array(values) => values
                .iter()
                .map(Self::from_json)
                .collect::<Result<Vec<_>, _>>()
                .map(Self::List),
            serde_json::Value::Object(values) => values
                .iter()
                .map(|(key, value)| Ok((key.clone(), Self::from_json(value)?)))
                .collect::<Result<BTreeMap<_, _>, String>>()
                .map(Self::Map),
        }
    }

    pub fn to_json(&self) -> serde_json::Value {
        match self {
            Self::Null => serde_json::Value::Null,
            Self::Bool(value) => serde_json::Value::Bool(*value),
            Self::Int(value) => serde_json::Value::Number((*value).into()),
            Self::Float(value) => serde_json::Number::from_f64(*value)
                .map(serde_json::Value::Number)
                .unwrap_or(serde_json::Value::Null),
            Self::String(value) => serde_json::Value::String(value.clone()),
            Self::List(values) => {
                serde_json::Value::Array(values.iter().map(Self::to_json).collect())
            }
            Self::Map(values) => serde_json::Value::Object(
                values
                    .iter()
                    .map(|(key, value)| (key.clone(), value.to_json()))
                    .collect(),
            ),
            Self::InstanceReference(reference) => {
                serde_json::to_value(reference).expect("instance references always serialize")
            }
        }
    }

    pub fn as_map(&self) -> Option<&BTreeMap<String, Self>> {
        match self {
            Self::Map(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_string(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }
}

impl Serialize for Value {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_json().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Value {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        Self::from_json(&value).map_err(serde::de::Error::custom)
    }
}
