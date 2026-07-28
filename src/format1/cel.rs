use super::compile::SemanticError;
use super::source::LoadErrorCode;
use crate::value::Value;
use cel_interpreter::objects::{Key, Map as CelMap, Value as CelValue};
use cel_interpreter::{Context, ExecutionError, Program};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

#[derive(Debug, Clone, Default)]
pub struct Environment {
    pub values: BTreeMap<String, Value>,
}

#[derive(Debug, Clone)]
pub struct EvaluationError(pub String);

impl std::fmt::Display for EvaluationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

pub fn validate_profile(expression: &str, pointer: &str) -> Result<(), SemanticError> {
    Program::compile(expression).map_err(|error| SemanticError {
        code: LoadErrorCode::CelProfileError,
        path: pointer.to_string(),
        message: format!("CEL parse error: {error}"),
    })?;

    let compact = expression.replace(char::is_whitespace, "");
    let forbidden = [
        "now(",
        ".all(",
        ".exists(",
        ".exists_one(",
        ".map(",
        ".filter(",
        "int(",
        "uint(",
        "bytes(",
        "duration(",
        "timestamp(",
        "event.event_id",
        "event.event",
        "event.target",
        "event.correlation_id",
    ];
    if forbidden.iter().any(|needle| compact.contains(needle))
        || (compact.contains("owner.") && !compact.contains("owner.variables."))
        || mixed_numeric_operator(&compact)
    {
        return Err(SemanticError {
            code: LoadErrorCode::CelProfileError,
            path: pointer.to_string(),
            message: "expression uses behavior outside the portable CEL profile".to_string(),
        });
    }
    Ok(())
}

fn mixed_numeric_operator(expression: &str) -> bool {
    let patterns = [
        "1==1.0", "1.0==1", "1!=1.0", "1.0!=1", "1<1.0", "1.0<1", "1<=1.0", "1.0<=1", "1>1.0",
        "1.0>1", "1>=1.0", "1.0>=1",
    ];
    patterns.iter().any(|pattern| expression.contains(pattern))
}

pub fn evaluate(expression: &str, environment: &Environment) -> Result<Value, EvaluationError> {
    let expression = expression.trim();
    if expression.chars().enumerate().all(|(index, character)| {
        character == '_'
            || character.is_ascii_alphanumeric() && (index > 0 || !character.is_ascii_digit())
    }) {
        if let Some(value) = environment.values.get(expression) {
            return Ok(value.clone());
        }
    }
    if let Some(argument) = expression
        .strip_prefix("size(")
        .and_then(|value| value.strip_suffix(')'))
    {
        return match evaluate(argument, environment)? {
            Value::String(value) => i64::try_from(value.chars().count())
                .map(Value::Int)
                .map_err(|_| EvaluationError("size is outside signed 64-bit range".to_string())),
            Value::List(value) => i64::try_from(value.len())
                .map(Value::Int)
                .map_err(|_| EvaluationError("size is outside signed 64-bit range".to_string())),
            Value::Map(value) => i64::try_from(value.len())
                .map(Value::Int)
                .map_err(|_| EvaluationError("size is outside signed 64-bit range".to_string())),
            _ => Err(EvaluationError(
                "size requires a string, list, or map".to_string(),
            )),
        };
    }
    if let Some((left, operator, right)) = split_top_level_logical(expression) {
        let left = evaluate(left, environment);
        let right = evaluate(right, environment);
        return match (operator, left, right) {
            ("&&", Ok(Value::Bool(false)), _) | ("&&", _, Ok(Value::Bool(false))) => {
                Ok(Value::Bool(false))
            }
            ("&&", Ok(Value::Bool(true)), Ok(Value::Bool(value))) => Ok(Value::Bool(value)),
            ("||", Ok(Value::Bool(true)), _) | ("||", _, Ok(Value::Bool(true))) => {
                Ok(Value::Bool(true))
            }
            ("||", Ok(Value::Bool(false)), Ok(Value::Bool(value))) => Ok(Value::Bool(value)),
            (_, Err(error), _) | (_, _, Err(error)) => Err(error),
            _ => Err(EvaluationError(
                "logical operands must be Boolean".to_string(),
            )),
        };
    }
    let program =
        Program::compile(expression).map_err(|error| EvaluationError(error.to_string()))?;
    let mut context = Context::default();
    for (name, value) in &environment.values {
        context
            .add_variable(name.clone(), to_cel(value))
            .map_err(|error| EvaluationError(error.to_string()))?;
    }
    let value = program
        .execute(&context)
        .map_err(|error| EvaluationError(map_execution_error(error)))?;
    from_cel(&value)
}

fn split_top_level_logical(expression: &str) -> Option<(&str, &str, &str)> {
    let bytes = expression.as_bytes();
    let mut depth = 0_i32;
    let mut quote = None;
    let mut escaped = false;
    let mut index = 0;
    while index + 1 < bytes.len() {
        let character = bytes[index] as char;
        if let Some(delimiter) = quote {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == delimiter {
                quote = None;
            }
            index += 1;
            continue;
        }
        match character {
            '\'' | '"' => quote = Some(character),
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            '&' if depth == 0 && bytes[index + 1] == b'&' => {
                return Some((
                    expression[..index].trim(),
                    "&&",
                    expression[index + 2..].trim(),
                ))
            }
            '|' if depth == 0 && bytes[index + 1] == b'|' => {
                return Some((
                    expression[..index].trim(),
                    "||",
                    expression[index + 2..].trim(),
                ))
            }
            _ => {}
        }
        index += 1;
    }
    None
}

pub fn evaluate_boolean(
    expression: &str,
    environment: &Environment,
) -> Result<bool, EvaluationError> {
    match evaluate(expression, environment)? {
        Value::Bool(value) => Ok(value),
        value => Err(EvaluationError(format!(
            "guard returned {}, expected bool",
            value.type_name()
        ))),
    }
}

fn map_execution_error(error: ExecutionError) -> String {
    match error {
        ExecutionError::DivisionByZero(_) => "division by zero".to_string(),
        ExecutionError::RemainderByZero(_) => "remainder by zero".to_string(),
        other => other.to_string(),
    }
}

fn to_cel(value: &Value) -> CelValue {
    match value {
        Value::Null => CelValue::Null,
        Value::Bool(value) => CelValue::Bool(*value),
        Value::Int(value) => CelValue::Int(*value),
        Value::Float(value) => CelValue::Float(*value),
        Value::String(value) => CelValue::String(Arc::new(value.clone())),
        Value::List(values) => {
            CelValue::List(Arc::new(values.iter().map(to_cel).collect::<Vec<_>>()))
        }
        Value::Map(values) => {
            let map = values
                .iter()
                .map(|(name, value)| (name.clone(), to_cel(value)))
                .collect::<HashMap<_, _>>();
            CelValue::Map(CelMap::from(map))
        }
        Value::InstanceReference(reference) => {
            let value = serde_json::to_value(reference).expect("reference serializes");
            let Value::Map(values) = Value::from_json(&value).expect("reference is a value") else {
                unreachable!()
            };
            to_cel(&Value::Map(values))
        }
    }
}

fn from_cel(value: &CelValue) -> Result<Value, EvaluationError> {
    match value {
        CelValue::Null => Ok(Value::Null),
        CelValue::Bool(value) => Ok(Value::Bool(*value)),
        CelValue::Int(value) => Ok(Value::Int(*value)),
        CelValue::UInt(value) => i64::try_from(*value)
            .map(Value::Int)
            .map_err(|_| EvaluationError("integer result is outside signed 64-bit range".into())),
        CelValue::Float(value) if value.is_finite() => {
            Ok(Value::Float(if *value == 0.0 { 0.0 } else { *value }))
        }
        CelValue::Float(_) => Err(EvaluationError(
            "floating-point result is not finite".to_string(),
        )),
        CelValue::String(value) => Ok(Value::String(value.as_ref().clone())),
        CelValue::List(values) => values
            .iter()
            .map(from_cel)
            .collect::<Result<Vec<_>, _>>()
            .map(Value::List),
        CelValue::Map(values) => {
            let mut output = BTreeMap::new();
            for (key, value) in values.map.iter() {
                let Key::String(key) = key else {
                    return Err(EvaluationError(
                        "portable CEL maps require string keys".to_string(),
                    ));
                };
                output.insert(key.as_ref().clone(), from_cel(value)?);
            }
            Ok(Value::Map(output))
        }
        _ => Err(EvaluationError(
            "CEL result type is outside the portable profile".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn portable_integer_division_and_remainder() {
        assert_eq!(
            evaluate("-7 / 3", &Environment::default()).unwrap(),
            Value::Int(-2)
        );
        assert_eq!(
            evaluate("-7 % 3", &Environment::default()).unwrap(),
            Value::Int(-1)
        );
    }

    #[test]
    fn strict_guard_type() {
        assert!(evaluate_boolean("1", &Environment::default()).is_err());
    }
}
