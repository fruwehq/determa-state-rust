use super::compile::{compile_bundle, Bundle};
use regex::Regex;
use yaml_rust2::parser::{MarkedEventReceiver, Parser};
use yaml_rust2::scanner::{Marker, TScalarStyle};
use yaml_rust2::{Event, Yaml, YamlLoader};

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
    validate_numeric_domain(&value, "")?;
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
    let documents = YamlLoader::load_from_str(source).map_err(|error| {
        let message = error.to_string();
        let code = if message.contains("duplicate key")
            || message.contains("duplicated key")
            || message.contains("duplicate entry")
        {
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
    if documents.len() != 1 {
        return source_error(
            LoadErrorCode::NonJsonValue,
            "a bundle source must contain exactly one YAML document",
        );
    }
    yaml_to_json(&documents[0], "")
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

fn source_location(error: &yaml_rust2::ScanError) -> String {
    format!(
        "line {}, column {}",
        error.marker().line(),
        error.marker().col() + 1
    )
}

fn lexical_checks(source: &str) -> Result<(), LoadError> {
    let mut receiver = PortableScalarReceiver::default();
    Parser::new_from_str(source)
        .load(&mut receiver, true)
        .map_err(|error| {
            let message = error.to_string();
            LoadError {
                code: if message.contains("invalid Unicode character escape code") {
                    LoadErrorCode::InvalidUnicode
                } else {
                    LoadErrorCode::NonJsonValue
                },
                path: source_location(&error),
                message,
            }
        })?;
    if let Some(error) = receiver.error {
        Err(error)
    } else if receiver.document_count != 1 {
        source_error(
            LoadErrorCode::NonJsonValue,
            "a bundle source must contain exactly one YAML document",
        )
    } else {
        Ok(())
    }
}

#[derive(Default)]
struct PortableScalarReceiver {
    document_count: usize,
    error: Option<LoadError>,
}

impl MarkedEventReceiver for PortableScalarReceiver {
    fn on_event(&mut self, event: Event, marker: Marker) {
        if self.error.is_some() {
            return;
        }
        match event {
            Event::DocumentStart => self.document_count += 1,
            Event::Alias(_) => self.reject(
                LoadErrorCode::UnsupportedYamlFeature,
                marker,
                "YAML aliases are unsupported",
            ),
            Event::SequenceStart(anchor, tag) | Event::MappingStart(anchor, tag)
                if anchor != 0 || tag.is_some() =>
            {
                self.reject(
                    LoadErrorCode::UnsupportedYamlFeature,
                    marker,
                    "YAML anchors and explicit tags are unsupported",
                );
            }
            Event::Scalar(value, style, anchor, tag) => {
                if anchor != 0 || tag.is_some() {
                    self.reject(
                        LoadErrorCode::UnsupportedYamlFeature,
                        marker,
                        "YAML anchors and explicit tags are unsupported",
                    );
                } else if style == TScalarStyle::Plain {
                    if let Err((code, message)) = classify_plain_scalar(&value) {
                        self.reject(code, marker, &message);
                    }
                }
            }
            _ => {}
        }
    }
}

impl PortableScalarReceiver {
    fn reject(&mut self, code: LoadErrorCode, marker: Marker, message: &str) {
        self.error = Some(LoadError {
            code,
            path: format!("line {}, column {}", marker.line(), marker.col() + 1),
            message: message.to_string(),
        });
    }
}

fn classify_plain_scalar(value: &str) -> Result<(), (LoadErrorCode, String)> {
    if value.is_empty() || matches!(value, "Null" | "NULL" | "~") {
        return Err((
            LoadErrorCode::InvalidNullSyntax,
            format!("noncanonical null scalar {value:?}"),
        ));
    }
    if matches!(value, "True" | "TRUE" | "False" | "FALSE") {
        return Err((
            LoadErrorCode::InvalidBooleanSyntax,
            format!("noncanonical Boolean scalar {value:?}"),
        ));
    }
    let json_number = Regex::new(r"^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$")
        .expect("constant regex");
    if json_number.is_match(value) {
        let valid = if value.contains('.') || value.contains('e') || value.contains('E') {
            value.parse::<f64>().is_ok_and(f64::is_finite)
        } else {
            value.parse::<i64>().is_ok()
        };
        if valid {
            return Ok(());
        }
        return Err((
            LoadErrorCode::NumericValueOutOfRange,
            format!("numeric scalar {value:?} is outside the portable numeric domain"),
        ));
    }
    let underscore_free = value.replace('_', "");
    let unsigned = value.strip_prefix(['+', '-']).unwrap_or(value);
    if matches!(Yaml::from_str(value), Yaml::Integer(_) | Yaml::Real(_))
        || value.contains('_') && json_number.is_match(&underscore_free)
        || unsigned.starts_with("0x")
        || unsigned.starts_with("0o")
    {
        return Err((
            LoadErrorCode::InvalidNumericSyntax,
            format!("non-JSON numeric scalar {value:?}"),
        ));
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

fn yaml_to_json(value: &Yaml, path: &str) -> Result<serde_json::Value, LoadError> {
    match value {
        Yaml::Null => Ok(serde_json::Value::Null),
        Yaml::Boolean(value) => Ok(serde_json::Value::Bool(*value)),
        Yaml::Integer(value) => Ok(serde_json::Value::Number((*value).into())),
        Yaml::Real(value) => {
            let float = value.parse::<f64>().map_err(|_| LoadError {
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
        Yaml::String(value) => Ok(serde_json::Value::String(value.clone())),
        Yaml::Array(values) => values
            .iter()
            .enumerate()
            .map(|(index, value)| yaml_to_json(value, &format!("{path}/{index}")))
            .collect::<Result<Vec<_>, _>>()
            .map(serde_json::Value::Array),
        Yaml::Hash(values) => {
            let mut output = serde_json::Map::new();
            for (key, value) in values {
                let Yaml::String(key) = key else {
                    return Err(LoadError {
                        code: LoadErrorCode::NonStringMapKey,
                        path: path.to_string(),
                        message: "mapping keys must be strings".to_string(),
                    });
                };
                let child_path = format!("{path}/{}", escape_pointer(key));
                output.insert(key.to_string(), yaml_to_json(value, &child_path)?);
            }
            Ok(serde_json::Value::Object(output))
        }
        Yaml::Alias(_) | Yaml::BadValue => source_error(
            LoadErrorCode::NonJsonValue,
            "YAML value is outside the portable JSON-compatible tree",
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

fn validate_numeric_domain(value: &serde_json::Value, path: &str) -> Result<(), LoadError> {
    match value {
        serde_json::Value::Number(number) => {
            if number.as_i64().is_some() {
                return Ok(());
            }
            if number.as_u64().is_some() {
                return Err(LoadError {
                    code: LoadErrorCode::NumericValueOutOfRange,
                    path: path.to_string(),
                    message: "integer is outside the signed 64-bit domain".to_string(),
                });
            }
            if number.as_f64().is_some_and(f64::is_finite) {
                return Ok(());
            }
            return Err(LoadError {
                code: LoadErrorCode::NumericValueOutOfRange,
                path: path.to_string(),
                message: "number is outside the finite binary64 domain".to_string(),
            });
        }
        serde_json::Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                validate_numeric_domain(value, &format!("{path}/{index}"))?;
            }
        }
        serde_json::Value::Object(values) => {
            for (name, value) in values {
                validate_numeric_domain(value, &format!("{path}/{}", escape_pointer(name)))?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle_with_meta(value: &str) -> String {
        format!(
            "format: 1\nnamespace: parser.test\nmeta:\n  value: {value}\nmachines:\n  - machine_id: probe\n    root: {{}}\n"
        )
    }

    #[test]
    fn plain_numeric_prefix_string_is_not_overclassified() {
        let bundle = load_bundle(&bundle_with_meta("1alpha")).unwrap();
        assert_eq!(bundle.normalized["meta"]["value"], "1alpha");
    }

    #[test]
    fn empty_sequence_member_is_nonportable_null() {
        let source = "format: 1\nnamespace: parser.empty\nmeta:\n  values:\n    -\nmachines:\n  - machine_id: probe\n    root: {}\n";
        assert_eq!(
            load_bundle(source).unwrap_err().code,
            LoadErrorCode::InvalidNullSyntax
        );
    }

    #[test]
    fn every_unpaired_surrogate_range_is_rejected_but_quoted_text_is_not() {
        for escape in ["D800", "DBFF", "DC00", "DFFF"] {
            let source = bundle_with_meta(&format!("\"\\u{escape}\""));
            assert_eq!(
                load_bundle(&source).unwrap_err().code,
                LoadErrorCode::InvalidUnicode
            );
        }
        let source = bundle_with_meta("'\\uD800'");
        assert_eq!(
            load_bundle(&source).unwrap().normalized["meta"]["value"],
            "\\uD800"
        );
        let source = bundle_with_meta("'\"\\uD800\"'");
        assert_eq!(
            load_bundle(&source).unwrap().normalized["meta"]["value"],
            "\"\\uD800\""
        );
        let source = "format: 1\nnamespace: parser.literal\nmeta:\n  value: |\n    \"\\uD800\"\nmachines:\n  - machine_id: probe\n    root: {}\n";
        assert_eq!(
            load_bundle(source).unwrap().normalized["meta"]["value"],
            "\"\\uD800\"\n"
        );
    }

    #[test]
    fn quoted_scalar_forms_remain_strings() {
        for value in ["'True'", "'null'", "'0x10'", "'+1'", "'1.0'"] {
            assert!(load_bundle(&bundle_with_meta(value)).is_ok(), "{value}");
        }
    }

    #[test]
    fn aliases_tags_and_duplicate_keys_are_rejected_before_normalization() {
        let alias = "format: 1\nnamespace: parser.alias\nmeta: &meta { value: 1 }\nother: *meta\nmachines:\n  - machine_id: probe\n    root: {}\n";
        assert_eq!(
            load_bundle(alias).unwrap_err().code,
            LoadErrorCode::UnsupportedYamlFeature
        );
        let tag = bundle_with_meta("!!str 1");
        assert_eq!(
            load_bundle(&tag).unwrap_err().code,
            LoadErrorCode::UnsupportedYamlFeature
        );
        let duplicate = "format: 1\nnamespace: parser.duplicate\nmeta: one\nmeta: two\nmachines:\n  - machine_id: probe\n    root: {}\n";
        assert_eq!(
            load_bundle(duplicate).unwrap_err().code,
            LoadErrorCode::DuplicateKey
        );
    }

    #[test]
    fn native_json_rejects_nested_unsigned_overflow() {
        let mut value = serde_json::json!({
            "format": 1,
            "namespace": "native.overflow",
            "meta": {"nested": {"value": 0}},
            "machines": [{"machine_id": "probe", "root": {}}]
        });
        value["meta"]["nested"]["value"] =
            serde_json::Value::Number(serde_json::Number::from(u64::MAX));
        assert_eq!(
            load_bundle_from_json(value).unwrap_err().code,
            LoadErrorCode::NumericValueOutOfRange
        );
    }

    #[test]
    fn native_json_preserves_integer_and_double_fingerprint_types() {
        let integer = load_bundle_from_json(serde_json::json!({
            "format": 1,
            "namespace": "native.types",
            "meta": {"value": 1},
            "machines": [{"machine_id": "probe", "root": {}}]
        }))
        .unwrap();
        let floating = load_bundle_from_json(serde_json::json!({
            "format": 1,
            "namespace": "native.types",
            "meta": {"value": 1.0},
            "machines": [{"machine_id": "probe", "root": {}}]
        }))
        .unwrap();
        assert_ne!(integer.fingerprint, floating.fingerprint);
    }
}
