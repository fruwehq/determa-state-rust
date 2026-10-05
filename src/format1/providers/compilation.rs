//! Exact optional source compilation; generated definitions restore without compilers.
use super::super::compile::{hash_json, typed_projection};
use super::*;

fn failed() -> Version1Error {
    Version1Error::new(
        "language_compilation_failed",
        "invalid source, replacement or provenance",
    )
}
fn claims_template() -> Value {
    json!({"deterministic":true,"pure":true,"portable":true,"semantically_introspectable":true,"process_contained":true,"external_io_capable":false})
}
impl RuntimeProviderRegistry {
    pub fn register_compiler(
        &mut self,
        reference: Value,
        provider: Arc<dyn NativeRuntimeProvider>,
        closure: SourceClosure,
    ) -> ProviderResult<()> {
        let key = reference_key(&reference)?;
        if self
            .0
            .entries
            .contains_key(&("compiler".into(), key.clone()))
        {
            return Err(Version1Error::new(
                "duplicate_extension_registration",
                "compiler already installed",
            ));
        }
        closure.verify()?;
        let descriptor = json!({"kind":"compiler","binding":{
            "provider_reference":reference,"source_digest":closure.manifest_digest()?,
            "dependencies":[],"capabilities":claims_template()}});
        let (common, configured) = guarded(|| {
            common::configure(
                &descriptor,
                provider.clone(),
                closure.clone(),
                self.0.verifier.clone(),
            )
        })?;
        let entry = Entry {
            descriptor,
            provider,
            closure,
            common,
            configured,
        };
        self.verify_entry(&entry)?;
        Arc::get_mut(&mut self.0)
            .ok_or_else(unavailable)?
            .entries
            .insert(("compiler".into(), key), entry);
        Ok(())
    }
    fn compiler_binding(&self, reference: &Value) -> ProviderResult<&Value> {
        let key = reference_key(reference)?;
        let entry = self
            .0
            .entries
            .get(&("compiler".into(), key))
            .ok_or_else(unavailable)?;
        if entry.descriptor["binding"]["provider_reference"] != *reference {
            return Err(unavailable());
        }
        Ok(&entry.descriptor["binding"])
    }
    pub fn compiler_capabilities(
        &self,
        reference: &Value,
    ) -> ProviderResult<BTreeMap<String, bool>> {
        self.capabilities("compiler", self.compiler_binding(reference)?)
    }
    fn check_compiler(&self, reference: &Value) -> ProviderResult<()> {
        self.select("compiler", self.compiler_binding(reference)?)
            .map(|_| ())
    }
    fn compile_region(&self, reference: &Value, source: &str) -> ProviderResult<Value> {
        let (entry, _) = self.select("compiler", self.compiler_binding(reference)?)?;
        guarded(|| entry.provider.compile_region(source)).map_err(|_| failed())
    }
}
fn artifact(value: &Value, schema: &str, format: &str) -> ProviderResult<()> {
    crate::value::Value::from_json(value).map_err(|_| failed())?;
    super::super::source::validate_runtime_schema(value, schema, "language_compilation_failed")?;
    if value["artifact_digest"]
        != hash_json(json!([format, "1", typed_projection(&value["content"])]))
    {
        return Err(failed());
    }
    Ok(())
}
fn reference_order(reference: &Value) -> ProviderResult<String> {
    Ok(format!(
        "{}\0{}",
        reference_key(reference)?,
        reference["content_digest"].as_str().ok_or_else(failed)?
    ))
}
fn tokens(locator: &str) -> ProviderResult<Vec<String>> {
    if !locator.starts_with('/') {
        return Err(failed());
    }
    locator[1..]
        .split('/')
        .map(|part| {
            let decoded = part.replace("~1", "/").replace("~0", "~");
            if decoded.replace('~', "~0").replace('/', "~1") != part {
                return Err(failed());
            }
            Ok(decoded)
        })
        .collect()
}
fn slot_mut<'a>(document: &'a mut Value, path: &[String]) -> ProviderResult<&'a mut Value> {
    let mut slot = document;
    for token in path {
        slot = if slot.is_array() {
            if token.is_empty()
                || (token.len() > 1 && token.starts_with('0'))
                || !token.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(failed());
            }
            slot.get_mut(token.parse::<usize>().map_err(|_| failed())?)
                .ok_or_else(failed)?
        } else {
            slot.get_mut(token).ok_or_else(failed)?
        };
    }
    Ok(slot)
}
/// Compile bounded, disjoint source regions into a strictly validated format-1 bundle.
/// A manifest is checked against exact source, compiler closure, output and guarantees.
pub fn compile_language_source(
    source: &Value,
    registry: RuntimeProviderRegistry,
    manifest: Option<&Value>,
    maximum_compilation_steps: usize,
) -> ProviderResult<Bundle> {
    artifact(
        source,
        include_str!("../../../schema/language-source-v1.schema.json"),
        "determa.language_source",
    )?;
    let content = &source["content"];
    let regions = content["regions"].as_array().ok_or_else(failed)?;
    let locations = regions
        .iter()
        .map(|region| tokens(region["locator"].as_str().ok_or_else(failed)?))
        .collect::<ProviderResult<Vec<_>>>()?;
    for (index, left) in locations.iter().enumerate() {
        if locations[index + 1..]
            .iter()
            .any(|right| left.starts_with(right) || right.starts_with(left))
        {
            return Err(failed());
        }
    }
    let mut closure_keys = BTreeSet::new();
    let mut prior = None;
    for dependency in content["dependencies"].as_array().ok_or_else(failed)? {
        let ordered = reference_order(dependency)?;
        if prior.as_ref().is_some_and(|key| key >= &ordered) {
            return Err(failed());
        }
        prior = Some(ordered.clone());
        closure_keys.insert(ordered);
        let closure = registry
            .0
            .dependencies
            .get(&reference_key(dependency)?)
            .ok_or_else(unavailable)?;
        closure.verify()?;
        if closure.digest()? != dependency["content_digest"] {
            return Err(unavailable());
        }
    }
    let mut generated = content["template"].clone();
    for (path, region) in locations.iter().zip(regions) {
        let slot = slot_mut(&mut generated, path)?;
        let name = path.last().ok_or_else(failed)?.as_str();
        let valid = match region["kind"].as_str() {
            Some("guard") => name == "guard" && slot.is_string(),
            Some("actions") => matches!(name, "action" | "entry" | "exit") && slot.is_array(),
            _ => false,
        };
        if !valid {
            return Err(failed());
        }
        registry.check_compiler(&region["provider_reference"])?;
        closure_keys.insert(reference_order(&region["provider_reference"])?);
    }
    for (index, (path, region)) in locations.iter().zip(regions).enumerate() {
        if index >= maximum_compilation_steps {
            return Err(Version1Error::new(
                "language_compilation_limit_exceeded",
                "source compilation budget exhausted",
            ));
        }
        *slot_mut(&mut generated, path)? = registry.compile_region(
            &region["provider_reference"],
            region["source"].as_str().ok_or_else(failed)?,
        )?;
    }
    let bundle = super::super::source::load_bundle_with_providers(
        &generated.to_string(),
        registry.clone(),
        &BTreeSet::new(),
    )
    .map_err(|_| failed())?;
    if let Some(manifest) = manifest {
        artifact(
            manifest,
            include_str!("../../../schema/compilation-manifest-v1.schema.json"),
            "determa.compilation_manifest",
        )?;
        let record = &manifest["content"];
        let recorded_keys = record["compiler_providers"]
            .as_array()
            .ok_or_else(failed)?
            .iter()
            .map(reference_order)
            .collect::<ProviderResult<Vec<_>>>()?;
        let mut effective = registry.effective_capabilities(&bundle.normalized)?;
        for region in regions {
            for (name, claim) in registry.compiler_capabilities(&region["provider_reference"])? {
                let value = effective.get_mut(&name).ok_or_else(failed)?;
                if name == "external_io_capable" {
                    *value |= claim;
                } else {
                    *value &= claim;
                }
            }
        }
        if record["source_artifact_digest"] != source["artifact_digest"]
            || recorded_keys != closure_keys.into_iter().collect::<Vec<_>>()
            || record["generated_validated_bundle_fingerprint"] != bundle.fingerprint
            || record["source_capabilities"]
                != serde_json::to_value(effective).map_err(|_| failed())?
        {
            return Err(failed());
        }
    }
    Ok(bundle)
}
