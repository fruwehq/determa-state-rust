use super::compile::{compile_bundle, Bundle};
use regex::Regex;
use serde_yaml::Value as YamlValue;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadErrorCode {
    DuplicateKey,
    NonStringMapKey,
    UnsupportedYamlFeature,
    UnsupportedFormat,
    NonJsonValue,
    InvalidUnicode,
    InvalidNumericSyntax,
    InvalidBooleanSyntax,
    InvalidNullSyntax,
    NumericValueOutOfRange,
    StructuralValidation,
    SemanticValidation,
    CelProfileError,
    InvalidBinding,
    DestroyedVariableWrite,
    DestroyedReferenceBinding,
    RootReentry,
    RootLocalTransition,
}

impl LoadErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DuplicateKey => "duplicate_key",
            Self::NonStringMapKey => "non_string_map_key",
            Self::UnsupportedYamlFeature => "unsupported_yaml_feature",
            Self::UnsupportedFormat => "unsupported_format",
            Self::NonJsonValue => "non_json_value",
            Self::InvalidUnicode => "invalid_unicode",
            Self::InvalidNumericSyntax => "invalid_numeric_syntax",
            Self::InvalidBooleanSyntax => "invalid_boolean_syntax",
            Self::InvalidNullSyntax => "invalid_null_syntax",
            Self::NumericValueOutOfRange => "numeric_value_out_of_range",
            Self::StructuralValidation => "structural_validation",
            Self::SemanticValidation => "semantic_validation",
            Self::CelProfileError => "cel_profile_error",
            Self::InvalidBinding => "invalid_binding",
            Self::DestroyedVariableWrite => "destroyed_variable_write",
            Self::DestroyedReferenceBinding => "destroyed_reference_binding",
            Self::RootReentry => "root_reentry",
            Self::RootLocalTransition => "root_local_transition",
        }
    }
}

#[derive(Debug, Clone)]
pub struct LoadError {
    pub code: LoadErrorCode,
    pub path: String,
    pub message: String,
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{} at {}: {}",
            self.code.as_str(),
            self.path,
            self.message
        )
    }
}

impl std::error::Error for LoadError {}

pub fn load_bundle(source: &str) -> Result<Bundle, LoadError> {
    let value = parse_document(source)?;
    load_bundle_from_json(value)
}

pub fn load_bundle_from_json(value: serde_json::Value) -> Result<Bundle, LoadError> {
    validate_unicode(&value)?;
    validate_format(&value)?;
    validate_schema(&value)?;
    compile_bundle(value).map_err(|error| LoadError {
        code: error.code,
        path: error.path,
        message: error.message,
    })
}

pub fn parse_document(source: &str) -> Result<serde_json::Value, LoadError> {
    lexical_checks(source)?;
    let yaml: YamlValue = serde_yaml::from_str(source).map_err(|error| {
        let message = error.to_string();
        let code = if message.contains("duplicate key") || message.contains("duplicate entry") {
            LoadErrorCode::DuplicateKey
        } else {
            LoadErrorCode::NonJsonValue
        };
        LoadError {
            code,
            path: source_location(&error),
            message,
        }
    })?;
    yaml_to_json(&yaml, "")
}

fn validate_format(value: &serde_json::Value) -> Result<(), LoadError> {
    if value.get("format").and_then(serde_json::Value::as_i64) == Some(1) {
        return Ok(());
    }
    Err(LoadError {
        code: LoadErrorCode::UnsupportedFormat,
        path: "/format".to_string(),
        message: "the document must use the integer format identifier 1".to_string(),
    })
}

fn source_location(error: &serde_yaml::Error) -> String {
    error
        .location()
        .map(|location| format!("line {}, column {}", location.line(), location.column()))
        .unwrap_or_else(|| "/".to_string())
}

fn lexical_checks(source: &str) -> Result<(), LoadError> {
    if source.contains("\\uD800")
        || source.contains("\\ud800")
        || source.contains("\\uDFFF")
        || source.contains("\\udfff")
    {
        return source_error(
            LoadErrorCode::InvalidUnicode,
            "source contains an unpaired Unicode surrogate escape",
        );
    }

    let json_number = Regex::new(r"^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$")
        .expect("constant regex");
    let numeric_candidate = Regex::new(r"^[+-]?(?:[0-9][0-9A-Za-z_.+-]*|\.[0-9][0-9A-Za-z_+-]*)$")
        .expect("constant regex");

    let lines = source.lines().collect::<Vec<_>>();
    for (line_index, line) in lines.iter().enumerate() {
        let mut token = String::new();
        let mut quote = None;
        let mut escaped = false;
        let mut tokens = Vec::new();
        for character in line.chars() {
            if let Some(delimiter) = quote {
                if delimiter == '"' && escaped {
                    escaped = false;
                    continue;
                }
                if delimiter == '"' && character == '\\' {
                    escaped = true;
                    continue;
                }
                if character == delimiter {
                    quote = None;
                }
                continue;
            }
            match character {
                '#' => break,
                '\'' | '"' => {
                    if !token.is_empty() {
                        tokens.push(std::mem::take(&mut token));
                    }
                    quote = Some(character);
                }
                ':' | ',' | '[' | ']' | '{' | '}' | ' ' | '\t' => {
                    if !token.is_empty() {
                        tokens.push(std::mem::take(&mut token));
                    }
                }
                _ => token.push(character),
            }
        }
        if !token.is_empty() {
            tokens.push(token);
        }

        for token in tokens {
            if (token.starts_with('&') && token != "&&")
                || token.starts_with('*')
                || (token.starts_with('!') && token != "!=")
            {
                return Err(LoadError {
                    code: LoadErrorCode::UnsupportedYamlFeature,
                    path: format!("line {}", line_index + 1),
                    message: format!("unsupported YAML token {token:?}"),
                });
            }
            if matches!(token.as_str(), "True" | "TRUE" | "False" | "FALSE") {
                return Err(LoadError {
                    code: LoadErrorCode::InvalidBooleanSyntax,
                    path: format!("line {}", line_index + 1),
                    message: format!("noncanonical Boolean scalar {token:?}"),
                });
            }
            if matches!(token.as_str(), "Null" | "NULL" | "~") {
                return Err(LoadError {
                    code: LoadErrorCode::InvalidNullSyntax,
                    path: format!("line {}", line_index + 1),
                    message: format!("noncanonical null scalar {token:?}"),
                });
            }
            let lower = token.to_ascii_lowercase();
            if (numeric_candidate.is_match(&token)
                || matches!(
                    lower.as_str(),
                    ".inf" | "+.inf" | "-.inf" | ".nan" | "+.nan" | "-.nan"
                ))
                && token != "-"
                && !json_number.is_match(&token)
            {
                return Err(LoadError {
                    code: LoadErrorCode::InvalidNumericSyntax,
                    path: format!("line {}", line_index + 1),
                    message: format!("non-JSON numeric scalar {token:?}"),
                });
            }
            if json_number.is_match(&token)
                && (token.contains('.') || token.contains('e') || token.contains('E'))
                && token.parse::<f64>().is_ok_and(|value| !value.is_finite())
            {
                return Err(LoadError {
                    code: LoadErrorCode::NumericValueOutOfRange,
                    path: format!("line {}", line_index + 1),
                    message: format!("numeric scalar {token:?} is outside binary64 range"),
                });
            }
        }

        let content = line.split('#').next().unwrap_or_default();
        let trimmed = content.trim_end();
        if trimmed.ends_with(':') {
            let indentation = content.len() - content.trim_start().len();
            let has_nested_value = lines[line_index + 1..]
                .iter()
                .map(|line| line.split('#').next().unwrap_or_default())
                .find(|line| !line.trim().is_empty())
                .is_some_and(|next| {
                    let next_indentation = next.len() - next.trim_start().len();
                    next_indentation > indentation
                });
            if !has_nested_value {
                return Err(LoadError {
                    code: LoadErrorCode::InvalidNullSyntax,
                    path: format!("line {}", line_index + 1),
                    message: "empty YAML scalar is not portable null".to_string(),
                });
            }
        }
    }
    Ok(())
}

fn source_error<T>(code: LoadErrorCode, message: &str) -> Result<T, LoadError> {
    Err(LoadError {
        code,
        path: "/".to_string(),
        message: message.to_string(),
    })
}

fn yaml_to_json(value: &YamlValue, path: &str) -> Result<serde_json::Value, LoadError> {
    match value {
        YamlValue::Null => Ok(serde_json::Value::Null),
        YamlValue::Bool(value) => Ok(serde_json::Value::Bool(*value)),
        YamlValue::Number(value) => {
            if value.is_i64() {
                let integer = value.as_i64().expect("i64 number");
                Ok(serde_json::Value::Number(integer.into()))
            } else if value.is_u64() {
                let unsigned = value.as_u64().expect("u64 number");
                let integer = i64::try_from(unsigned).map_err(|_| LoadError {
                    code: LoadErrorCode::NumericValueOutOfRange,
                    path: path.to_string(),
                    message: "integer is outside signed 64-bit range".to_string(),
                })?;
                Ok(serde_json::Value::Number(integer.into()))
            } else {
                let float = value.as_f64().ok_or_else(|| LoadError {
                    code: LoadErrorCode::NonJsonValue,
                    path: path.to_string(),
                    message: "numeric value is not representable".to_string(),
                })?;
                if !float.is_finite() {
                    return source_error(
                        LoadErrorCode::NumericValueOutOfRange,
                        "floating-point value is not finite",
                    );
                }
                Ok(serde_json::Value::Number(
                    serde_json::Number::from_f64(if float == 0.0 { 0.0 } else { float })
                        .expect("finite float"),
                ))
            }
        }
        YamlValue::String(value) => Ok(serde_json::Value::String(value.clone())),
        YamlValue::Sequence(values) => values
            .iter()
            .enumerate()
            .map(|(index, value)| yaml_to_json(value, &format!("{path}/{index}")))
            .collect::<Result<Vec<_>, _>>()
            .map(serde_json::Value::Array),
        YamlValue::Mapping(values) => {
            let mut output = serde_json::Map::new();
            for (key, value) in values {
                let key = key.as_str().ok_or_else(|| LoadError {
                    code: LoadErrorCode::NonStringMapKey,
                    path: path.to_string(),
                    message: "mapping keys must be strings".to_string(),
                })?;
                let child_path = format!("{path}/{}", escape_pointer(key));
                output.insert(key.to_string(), yaml_to_json(value, &child_path)?);
            }
            Ok(serde_json::Value::Object(output))
        }
        YamlValue::Tagged(_) => source_error(
            LoadErrorCode::UnsupportedYamlFeature,
            "tagged YAML values are unsupported",
        ),
    }
}

fn validate_unicode(value: &serde_json::Value) -> Result<(), LoadError> {
    match value {
        serde_json::Value::String(value)
            if value
                .chars()
                .any(|character| (0xD800..=0xDFFF).contains(&(character as u32))) =>
        {
            return source_error(LoadErrorCode::InvalidUnicode, "invalid Unicode scalar");
        }
        serde_json::Value::String(_) => {}
        serde_json::Value::Array(values) => {
            for value in values {
                validate_unicode(value)?;
            }
        }
        serde_json::Value::Object(values) => {
            for (key, value) in values {
                validate_unicode(&serde_json::Value::String(key.clone()))?;
                validate_unicode(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_schema(value: &serde_json::Value) -> Result<(), LoadError> {
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../schema/machine.schema.json"))
            .expect("bundled format-1 schema is valid JSON");
    let validator = jsonschema::validator_for(&schema).expect("bundled schema compiles");
    if let Some(error) = validator.iter_errors(value).next() {
        return Err(LoadError {
            code: LoadErrorCode::StructuralValidation,
            path: error.instance_path.to_string(),
            message: error.to_string(),
        });
    }
    Ok(())
}

pub(crate) fn escape_pointer(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}
