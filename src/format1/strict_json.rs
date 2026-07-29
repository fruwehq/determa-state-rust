use serde::de::{DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::collections::BTreeSet;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StrictJsonErrorCode {
    InvalidUtf8,
    DuplicateKey,
    InvalidNumber,
    InvalidJson,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StrictJsonError {
    pub code: StrictJsonErrorCode,
    pub message: String,
}

impl fmt::Display for StrictJsonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for StrictJsonError {}

pub(crate) fn parse(source: &[u8]) -> Result<Value, StrictJsonError> {
    let source = std::str::from_utf8(source).map_err(|error| StrictJsonError {
        code: StrictJsonErrorCode::InvalidUtf8,
        message: error.to_string(),
    })?;
    let mut deserializer = serde_json::Deserializer::from_str(source);
    let value = StrictValueSeed
        .deserialize(&mut deserializer)
        .map_err(classify_error)?;
    deserializer.end().map_err(classify_error)?;
    Ok(value)
}

fn classify_error(error: serde_json::Error) -> StrictJsonError {
    let message = error.to_string();
    let code = if message.contains("duplicate object member") {
        StrictJsonErrorCode::DuplicateKey
    } else if message.contains("outside the signed 64-bit domain")
        || message.contains("non-finite number")
    {
        StrictJsonErrorCode::InvalidNumber
    } else {
        StrictJsonErrorCode::InvalidJson
    };
    StrictJsonError { code, message }
}

struct StrictValueSeed;

impl<'de> DeserializeSeed<'de> for StrictValueSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a strict JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let value = i64::try_from(value)
            .map_err(|_| E::custom("integer is outside the signed 64-bit domain"))?;
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if !value.is_finite() {
            return Err(E::custom("non-finite number"));
        }
        Number::from_f64(if value == 0.0 { 0.0 } else { value })
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(Value::String(value.to_string()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A>(self, mut values: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut output = Vec::new();
        while let Some(value) = values.next_element_seed(StrictValueSeed)? {
            output.push(value);
        }
        Ok(Value::Array(output))
    }

    fn visit_map<A>(self, mut values: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut output = Map::new();
        let mut names = BTreeSet::new();
        while let Some(name) = values.next_key::<String>()? {
            if !names.insert(name.clone()) {
                return Err(A::Error::custom(format!(
                    "duplicate object member {name:?}"
                )));
            }
            let value = values.next_value_seed(StrictValueSeed)?;
            output.insert(name, value);
        }
        Ok(Value::Object(output))
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct JsonStatistics {
    pub depth: usize,
    pub maximum_map_members: usize,
    pub maximum_list_members: usize,
    pub maximum_string_bytes: usize,
}

pub(crate) fn statistics(value: &Value) -> JsonStatistics {
    fn visit(value: &Value, depth: usize, output: &mut JsonStatistics) {
        output.depth = output.depth.max(depth);
        match value {
            Value::String(value) => {
                output.maximum_string_bytes = output.maximum_string_bytes.max(value.len());
            }
            Value::Array(values) => {
                output.maximum_list_members = output.maximum_list_members.max(values.len());
                for value in values {
                    visit(value, depth + 1, output);
                }
            }
            Value::Object(values) => {
                output.maximum_map_members = output.maximum_map_members.max(values.len());
                for (name, value) in values {
                    output.maximum_string_bytes = output.maximum_string_bytes.max(name.len());
                    visit(value, depth + 1, output);
                }
            }
            _ => {}
        }
    }

    let mut output = JsonStatistics::default();
    visit(value, 1, &mut output);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_duplicate_names_and_unsigned_overflow() {
        assert_eq!(
            parse(br#"{"value":1,"value":2}"#).unwrap_err().code,
            StrictJsonErrorCode::DuplicateKey
        );
        assert_eq!(
            parse(b"18446744073709551615").unwrap_err().code,
            StrictJsonErrorCode::InvalidNumber
        );
    }

    #[test]
    fn records_recursive_resource_dimensions() {
        let value = parse(br#"{"values":["four",{"key":true}]}"#).unwrap();
        assert_eq!(
            statistics(&value),
            JsonStatistics {
                depth: 4,
                maximum_map_members: 1,
                maximum_list_members: 2,
                maximum_string_bytes: 6,
            }
        );
    }
}
