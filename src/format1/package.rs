use super::persistence::InMemoryDefinitionResolver;
use super::source::load_bundle_from_json;
use super::wire::TypedValue;
use serde_json::Value as JsonValue;
use std::collections::BTreeSet;

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
                "https://determa.dev/state/schema/aggregate-state-v2.schema.json",
                include_str!("../../schema/aggregate-state-v2.schema.json"),
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
        let normalized = typed_to_plain_json(&typed)?;
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

fn typed_to_plain_json(value: &TypedValue) -> Result<JsonValue, super::v2::Version2Error> {
    Ok(match value {
        TypedValue::Null => JsonValue::Null,
        TypedValue::Boolean(value) => JsonValue::Bool(*value),
        TypedValue::String(value) => JsonValue::String(value.clone()),
        TypedValue::Integer(value) => JsonValue::Number((*value).into()),
        TypedValue::Float(value) => serde_json::Number::from_f64(*value)
            .map(JsonValue::Number)
            .ok_or_else(|| invalid_package_v2("typed definition float is nonfinite"))?,
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
                .collect::<Result<serde_json::Map<_, _>, super::v2::Version2Error>>()?,
        ),
    })
}
