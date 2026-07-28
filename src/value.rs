use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidUnicodeString;

impl std::fmt::Display for InvalidUnicodeString {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("UTF-16 input contains an unpaired surrogate")
    }
}

impl std::error::Error for InvalidUnicodeString {}

pub fn string_from_utf16(units: &[u16]) -> Result<String, InvalidUnicodeString> {
    String::from_utf16(units).map_err(|_| InvalidUnicodeString)
}

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
            _ if self.matches_type(declared_type) => self.normalize_portable(),
            _ => None,
        }
    }

    pub fn normalize_portable(&self) -> Option<Self> {
        match self {
            Self::Float(value) if value.is_finite() => {
                Some(Self::Float(if *value == 0.0 { 0.0 } else { *value }))
            }
            Self::Float(_) => None,
            Self::List(values) => values
                .iter()
                .map(Self::normalize_portable)
                .collect::<Option<Vec<_>>>()
                .map(Self::List),
            Self::Map(values) => values
                .iter()
                .map(|(key, value)| Some((key.clone(), value.normalize_portable()?)))
                .collect::<Option<BTreeMap<_, _>>>()
                .map(Self::Map),
            _ => Some(self.clone()),
        }
    }

    pub fn is_canonical_portable(&self) -> bool {
        match self {
            Self::Float(value) => value.is_finite() && (*value != 0.0 || value.is_sign_positive()),
            Self::List(values) => values.iter().all(Self::is_canonical_portable),
            Self::Map(values) => values.values().all(Self::is_canonical_portable),
            _ => true,
        }
    }

    pub fn from_json(value: &serde_json::Value) -> Result<Self, String> {
        match value {
            serde_json::Value::Null => Ok(Self::Null),
            serde_json::Value::Bool(value) => Ok(Self::Bool(*value)),
            serde_json::Value::Number(value) => {
                if let Some(integer) = value.as_i64() {
                    Ok(Self::Int(integer))
                } else if value.as_u64().is_some() {
                    Err("integer is outside the signed 64-bit domain".to_string())
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

#[cfg(test)]
mod tests {
    use super::Value;
    use std::collections::BTreeMap;

    #[test]
    fn native_values_reject_unsigned_overflow_and_preserve_numeric_types() {
        let nested = serde_json::json!({
            "items": [0]
        });
        let mut nested = nested;
        nested["items"][0] = serde_json::Value::Number(serde_json::Number::from(u64::MAX));
        assert!(Value::from_json(&nested).is_err());
        assert_eq!(
            Value::from_json(&serde_json::json!(1)).unwrap(),
            Value::Int(1)
        );
        assert_eq!(
            Value::from_json(&serde_json::json!(1.0)).unwrap(),
            Value::Float(1.0)
        );
        assert!(Value::Float(f64::INFINITY)
            .normalize_for_type("float")
            .is_none());
        assert_eq!(
            Value::Float(-0.0).normalize_for_type("float"),
            Some(Value::Float(0.0))
        );
        let nested = Value::Map(BTreeMap::from([(
            "values".to_string(),
            Value::List(vec![Value::Float(-0.0), Value::Int(1)]),
        )]));
        let normalized = nested.normalize_for_type("map").unwrap();
        let Value::Map(normalized) = normalized else {
            panic!("expected normalized map");
        };
        let Value::List(values) = &normalized["values"] else {
            panic!("expected normalized list");
        };
        assert!(
            matches!(values[0], Value::Float(value) if value == 0.0 && value.is_sign_positive())
        );
        assert_eq!(values[1], Value::Int(1));
        assert!(Value::List(vec![Value::Float(f64::NAN)])
            .normalize_for_type("list")
            .is_none());
    }
}
