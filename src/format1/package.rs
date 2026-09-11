use super::migration::{migrate_aggregate, MigrationOutcome, MigrationRequest, ResourceLimits};
use super::persistence::InMemoryDefinitionResolver;
use super::source::load_bundle_from_json;
use super::wire::{
    canonical_bytes, parse_aggregate_envelope, restore_aggregate, AggregateEnvelope,
    PersistenceError, PersistenceErrorCode, TypedValue,
};
use serde_json::Value as JsonValue;
use std::collections::BTreeSet;

#[derive(Debug, Clone)]
pub struct RestoredPackage {
    pub aggregate_envelope: AggregateEnvelope,
    pub aggregate_bytes: Vec<u8>,
    pub aggregate: super::runtime::AggregateState,
    pub migration_route: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RestoredPackageV2 {
    pub aggregate: super::v2::QueueBearingAggregate,
    pub migration_route: Vec<String>,
}

pub fn restore_package_v2(
    source: &[u8],
    resolver: &mut InMemoryDefinitionResolver,
) -> Result<RestoredPackageV2, super::v2::Version2Error> {
    let value =
        super::strict_json::parse(source).map_err(|error| invalid_package_v2(error.to_string()))?;
    if value["aggregate_state_package_format"] != "determa.aggregate_state_package" {
        return Err(super::v2::Version2Error::new(
            "unsupported_aggregate_state_package_format",
            "unsupported aggregate-state package format",
        ));
    }
    if value["aggregate_state_package_schema_version"] != 2 {
        return Err(super::v2::Version2Error::new(
            "unsupported_aggregate_state_package_schema_version",
            "unsupported aggregate-state package schema version",
        ));
    }
    super::v2::validate_v2_schema(
        &value,
        include_str!("../../schema/aggregate-state-package-v2.schema.json"),
        &[
            (
                "https://determa.dev/state/schema/aggregate-state-package.schema.json",
                include_str!("../../schema/aggregate-state-package.schema.json"),
            ),
            (
                "https://determa.dev/state/schema/aggregate-state.schema.json",
                include_str!("../../schema/aggregate-state.schema.json"),
            ),
            (
                "https://determa.dev/state/schema/aggregate-state-v2.schema.json",
                include_str!("../../schema/aggregate-state-v2.schema.json"),
            ),
            (
                "https://determa.dev/state/schema/migration-descriptor.schema.json",
                include_str!("../../schema/migration-descriptor.schema.json"),
            ),
            (
                "https://determa.dev/state/schema/migration-descriptor-v2.schema.json",
                include_str!("../../schema/migration-descriptor-v2.schema.json"),
            ),
        ],
        "invalid_aggregate_state_package",
    )?;
    load_definition_attachments(&value, resolver)?;
    let mut descriptors = BTreeSet::new();
    for descriptor in value["migration_descriptors"].as_array().unwrap() {
        let bytes = super::v2::canonical_bytes(descriptor)?;
        let decoded = super::v2::decode_descriptor_v2(&bytes)?;
        let digest = decoded["migration_descriptor_digest"].as_str().unwrap();
        if !descriptors.insert(digest.to_string()) {
            return Err(invalid_package_v2(
                "migration descriptor attachment is duplicated",
            ));
        }
        if let Some(existing) = resolver.descriptor(digest) {
            if existing.bytes != bytes {
                return Err(invalid_package_v2(
                    "attached descriptor collides with resolver content",
                ));
            }
        } else {
            resolver.insert_descriptor(digest, bytes, true);
        }
    }
    let route = value["migration_route"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item.as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    if route.iter().collect::<BTreeSet<_>>().len() != route.len()
        || route.iter().any(|digest| !descriptors.contains(digest))
    {
        return Err(invalid_package_v2(
            "migration route is not closed over attachments",
        ));
    }
    let aggregate = super::v2::restore_aggregate_v2(
        &super::v2::canonical_bytes(&value["aggregate_state"])?,
        resolver,
    )?;
    Ok(RestoredPackageV2 {
        aggregate,
        migration_route: route,
    })
}

fn load_definition_attachments(
    value: &JsonValue,
    resolver: &mut InMemoryDefinitionResolver,
) -> Result<(), super::v2::Version2Error> {
    let mut fingerprints = BTreeSet::new();
    for attachment in value["normalized_definitions"].as_array().unwrap() {
        let fingerprint = attachment["validated_bundle_fingerprint"].as_str().unwrap();
        if !fingerprints.insert(fingerprint.to_string()) {
            return Err(invalid_package_v2("definition attachment is duplicated"));
        }
        let typed: TypedValue = serde_json::from_value(attachment["normalized_bundle"].clone())
            .map_err(|error| invalid_package_v2(error.to_string()))?;
        let normalized =
            typed_to_plain_json(&typed).map_err(|error| invalid_package_v2(error.message))?;
        let bundle = load_bundle_from_json(normalized)
            .map_err(|error| invalid_package_v2(error.to_string()))?;
        if bundle.fingerprint != fingerprint {
            return Err(super::v2::Version2Error::new(
                "definition_fingerprint_mismatch",
                "attached definition fingerprint does not match content",
            ));
        }
        if let Some(existing) = resolver.get(fingerprint) {
            if existing.bundle.normalized != bundle.normalized {
                return Err(super::v2::Version2Error::new(
                    "definition_fingerprint_mismatch",
                    "attached definition collides with resolver content",
                ));
            }
        } else {
            resolver.insert(bundle, true);
        }
    }
    Ok(())
}

fn invalid_package_v2(message: impl Into<String>) -> super::v2::Version2Error {
    super::v2::Version2Error::new("invalid_aggregate_state_package", message)
}

pub fn restore_package(
    source: &[u8],
    resolver: &mut InMemoryDefinitionResolver,
) -> Result<RestoredPackage, PersistenceError> {
    let value = super::strict_json::parse(source)
        .map_err(|failure| invalid_package(failure.to_string()))?;
    let object = value
        .as_object()
        .ok_or_else(|| invalid_package("aggregate-state package must be an object"))?;
    match object.get("aggregate_state_package_format") {
        Some(JsonValue::String(value)) if value == "determa.aggregate_state_package" => {}
        _ => {
            return Err(PersistenceError::new(
                PersistenceErrorCode::UnsupportedAggregateStatePackageFormat,
                "unsupported aggregate-state package format",
            ));
        }
    }
    match object.get("aggregate_state_package_schema_version") {
        Some(JsonValue::Number(value)) if value.as_i64() == Some(1) => {}
        _ => {
            return Err(PersistenceError::new(
                PersistenceErrorCode::UnsupportedAggregateStatePackageSchemaVersion,
                "unsupported aggregate-state package schema version",
            ));
        }
    }
    let expected = BTreeSet::from([
        "aggregate_state",
        "aggregate_state_package_format",
        "aggregate_state_package_schema_version",
        "migration_descriptors",
        "migration_route",
        "normalized_definitions",
    ]);
    if object.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected {
        return Err(invalid_package("package members are not closed"));
    }
    let definitions = object["normalized_definitions"]
        .as_array()
        .ok_or_else(|| invalid_package("normalized_definitions must be an array"))?;
    let mut package_definition_keys = BTreeSet::new();
    for attachment in definitions {
        let attachment = attachment
            .as_object()
            .ok_or_else(|| invalid_package("definition attachment must be an object"))?;
        if attachment
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            != BTreeSet::from(["normalized_bundle", "validated_bundle_fingerprint"])
        {
            return Err(invalid_package(
                "definition attachment members are not closed",
            ));
        }
        let fingerprint = attachment["validated_bundle_fingerprint"]
            .as_str()
            .ok_or_else(|| invalid_package("definition fingerprint must be a string"))?;
        if !package_definition_keys.insert(fingerprint.to_string()) {
            return Err(invalid_package("definition attachment is duplicated"));
        }
        let typed: TypedValue = serde_json::from_value(attachment["normalized_bundle"].clone())
            .map_err(|failure| invalid_package(failure.to_string()))?;
        let normalized = typed_to_plain_json(&typed)?;
        let bundle = load_bundle_from_json(normalized)
            .map_err(|failure| invalid_package(failure.to_string()))?;
        if bundle.fingerprint != fingerprint {
            return Err(PersistenceError::new(
                PersistenceErrorCode::DefinitionFingerprintMismatch,
                "attached definition fingerprint does not match content",
            ));
        }
        if let Some(existing) = resolver.get(fingerprint) {
            if existing.bundle.normalized != bundle.normalized {
                return Err(PersistenceError::new(
                    PersistenceErrorCode::DefinitionFingerprintMismatch,
                    "attached definition collides with resolver content",
                ));
            }
        } else {
            resolver.insert(bundle, true);
        }
    }
    let descriptors = object["migration_descriptors"]
        .as_array()
        .ok_or_else(|| invalid_package("migration_descriptors must be an array"))?;
    let mut package_descriptor_keys = BTreeSet::new();
    for descriptor in descriptors {
        let digest = descriptor
            .get("migration_descriptor_digest")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| invalid_package("descriptor digest must be a string"))?;
        if !package_descriptor_keys.insert(digest.to_string()) {
            return Err(invalid_package(
                "migration descriptor attachment is duplicated",
            ));
        }
        let bytes =
            canonical_bytes(descriptor).map_err(|failure| invalid_package(failure.to_string()))?;
        if let Some(existing) = resolver.descriptor(digest) {
            let existing_value = super::strict_json::parse(&existing.bytes)
                .map_err(|failure| invalid_package(failure.to_string()))?;
            if existing_value != *descriptor {
                return Err(PersistenceError::new(
                    PersistenceErrorCode::InvalidAggregateStatePackage,
                    "attached descriptor collides with resolver content",
                ));
            }
        } else {
            resolver.insert_descriptor(digest, bytes, true);
        }
    }
    let route = object["migration_route"]
        .as_array()
        .ok_or_else(|| invalid_package("migration_route must be an array"))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| invalid_package("migration route digest must be a string"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if route.iter().collect::<BTreeSet<_>>().len() != route.len() {
        return Err(invalid_package(
            "migration route contains duplicate digests",
        ));
    }
    let aggregate_bytes = canonical_bytes(&object["aggregate_state"])
        .map_err(|failure| invalid_package(failure.to_string()))?;
    let (aggregate_envelope, _) = parse_aggregate_envelope(&aggregate_bytes)?;
    let aggregate = restore_aggregate(&aggregate_bytes, resolver)?;
    Ok(RestoredPackage {
        aggregate_envelope,
        aggregate_bytes,
        aggregate,
        migration_route: route,
    })
}

pub fn restore_package_and_migrate(
    source: &[u8],
    resolver: &mut InMemoryDefinitionResolver,
    target_validated_bundle_fingerprint: String,
    maintenance_mode: bool,
    limits: &ResourceLimits,
) -> Result<MigrationOutcome, PersistenceError> {
    let restored = restore_package(source, resolver)?;
    migrate_aggregate(
        &restored.aggregate_bytes,
        &MigrationRequest {
            migration_route: restored.migration_route,
            target_validated_bundle_fingerprint,
            maintenance_mode,
        },
        resolver,
        limits,
    )
}

fn typed_to_plain_json(value: &TypedValue) -> Result<JsonValue, PersistenceError> {
    Ok(match value {
        TypedValue::Null => JsonValue::Null,
        TypedValue::Boolean(value) => JsonValue::Bool(*value),
        TypedValue::String(value) => JsonValue::String(value.clone()),
        TypedValue::Integer(value) => JsonValue::Number((*value).into()),
        TypedValue::Float(value) => serde_json::Number::from_f64(*value)
            .map(JsonValue::Number)
            .ok_or_else(|| invalid_package("typed definition float is nonfinite"))?,
        TypedValue::List(values) => JsonValue::Array(
            values
                .iter()
                .map(typed_to_plain_json)
                .collect::<Result<Vec<_>, _>>()?,
        ),
        TypedValue::Map(values) => JsonValue::Object(
            values
                .iter()
                .map(|(key, value)| Ok((key.clone(), typed_to_plain_json(value)?)))
                .collect::<Result<serde_json::Map<_, _>, PersistenceError>>()?,
        ),
    })
}

fn invalid_package(message: impl Into<String>) -> PersistenceError {
    PersistenceError::new(PersistenceErrorCode::InvalidAggregateStatePackage, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restores_normative_self_contained_package() {
        let directory = "conformance-suite/conformance/core/97-aggregate-package-attachments";
        let mut resolver = InMemoryDefinitionResolver::default();
        let restored = restore_package(
            &std::fs::read(format!("{directory}/valid-package.json")).unwrap(),
            &mut resolver,
        )
        .unwrap();
        assert_eq!(
            restored.aggregate_bytes,
            std::fs::read(format!("{directory}/source-aggregate-state.canonical.json")).unwrap()
        );
    }

    #[test]
    fn package_attachments_drive_migration() {
        let directory = "conformance-suite/conformance/core/97-aggregate-package-attachments";
        let mut resolver = InMemoryDefinitionResolver::default();
        let expected: JsonValue = serde_json::from_slice(
            &std::fs::read(format!("{directory}/expected-aggregate-state.json")).unwrap(),
        )
        .unwrap();
        let result = restore_package_and_migrate(
            &std::fs::read(format!("{directory}/valid-package.json")).unwrap(),
            &mut resolver,
            expected["validated_bundle_fingerprint"]
                .as_str()
                .unwrap()
                .to_string(),
            false,
            &ResourceLimits::default(),
        )
        .unwrap();
        assert_eq!(
            result.aggregate_bytes,
            std::fs::read(format!(
                "{directory}/expected-aggregate-state.canonical.json"
            ))
            .unwrap()
        );
    }
}
