//! Exact, host-installed native evaluators. Provider objects never enter portable state.
use super::compile::{Bundle, ComponentDefinition, Machine};
use super::model::Guard;
use super::v1::Version1Error;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::any::Any;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, PathBuf};
use std::sync::Arc;

mod common;
mod compilation;
pub use compilation::compile_language_source;

pub type ProviderResult<T> = Result<T, Version1Error>;

/// Host policy independently binds the installed native object to reviewed code and
/// configured capabilities. A provider's own descriptor is never this proof.
pub trait RuntimeProviderVerifier: Send + Sync {
    fn verify(
        &self,
        provider: &dyn NativeRuntimeProvider,
        descriptor: &Value,
        closure: &SourceClosure,
    ) -> ProviderResult<BTreeSet<String>>;
    fn inspection_state(&self, provider: &dyn NativeRuntimeProvider) -> ProviderResult<Vec<u8>>;
}

pub trait NativeRuntimeProvider: Any + Send + Sync {
    fn as_any(&self) -> &dyn Any;
    fn health(&self) -> bool;
    fn evaluate_guard(&self, _snapshot: &Value) -> ProviderResult<Value> {
        Err(unavailable())
    }
    fn evaluate_actions(&self, _snapshot: &Value) -> ProviderResult<Value> {
        Err(unavailable())
    }
    fn compile_region(&self, _source: &str) -> ProviderResult<Value> {
        Err(unavailable())
    }
    fn inspect_guard(
        &self,
        _snapshot: &Value,
        _guards: usize,
        _steps: usize,
    ) -> ProviderResult<(bool, usize, usize)> {
        Err(unavailable())
    }
}

#[derive(Debug, Clone)]
pub struct SourceClosure {
    pub root: PathBuf,
    pub paths: Vec<String>,
    pub manifest: String,
    pub domain: Vec<u8>,
}
impl SourceClosure {
    fn read(&self, name: &str) -> ProviderResult<Vec<u8>> {
        let relative = std::path::Path::new(name);
        if name.is_empty()
            || relative.is_absolute()
            || relative
                .components()
                .any(|p| !matches!(p, Component::Normal(_)))
        {
            return Err(unavailable());
        }
        let root = self.root.canonicalize().map_err(|_| unavailable())?;
        let mut selected = root.clone();
        for part in relative.components() {
            selected.push(part);
            if selected
                .symlink_metadata()
                .map_err(|_| unavailable())?
                .file_type()
                .is_symlink()
            {
                return Err(unavailable());
            }
        }
        if !selected
            .canonicalize()
            .map_err(|_| unavailable())?
            .starts_with(root)
        {
            return Err(unavailable());
        }
        std::fs::read(selected).map_err(|_| unavailable())
    }
    pub fn digest(&self) -> ProviderResult<String> {
        if self.paths.is_empty()
            || self.paths.contains(&self.manifest)
            || self.paths.iter().collect::<BTreeSet<_>>().len() != self.paths.len()
        {
            return Err(unavailable());
        }
        let mut hash = Sha256::new();
        hash.update(&self.domain);
        for path in &self.paths {
            let bytes = self.read(path)?;
            hash.update((path.len() as u64).to_be_bytes());
            hash.update(path.as_bytes());
            hash.update((bytes.len() as u64).to_be_bytes());
            hash.update(bytes);
        }
        Ok(format!("sha256:{:x}", hash.finalize()))
    }
    pub fn manifest_digest(&self) -> ProviderResult<String> {
        Ok(format!(
            "sha256:{:x}",
            Sha256::digest(self.read(&self.manifest)?)
        ))
    }
    pub fn verify(&self) -> ProviderResult<()> {
        let manifest =
            super::strict_json::parse(&self.read(&self.manifest)?).map_err(|_| unavailable())?;
        let files = manifest["files"].as_array().ok_or_else(unavailable)?;
        if files.len() != self.paths.len() {
            return Err(unavailable());
        }
        for (file, path) in files.iter().zip(&self.paths) {
            if file["path"] != *path
                || file["sha256"] != format!("sha256:{:x}", Sha256::digest(self.read(path)?))
            {
                return Err(unavailable());
            }
        }
        self.digest()?;
        Ok(())
    }
}

struct Entry {
    descriptor: Value,
    provider: Arc<dyn NativeRuntimeProvider>,
    closure: SourceClosure,
    common: Arc<crate::extensions::ExtensionRegistry>,
    configured: crate::extensions::ConfiguredExtension,
}
struct Registry {
    entries: BTreeMap<(String, String), Entry>,
    dependencies: BTreeMap<String, SourceClosure>,
    verifier: Arc<dyn RuntimeProviderVerifier>,
}
#[derive(Clone)]
pub struct RuntimeProviderRegistry(Arc<Registry>, BTreeSet<String>);
impl std::fmt::Debug for RuntimeProviderRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuntimeProviderRegistry")
            .field("installed", &self.0.entries.len())
            .finish()
    }
}
impl PartialEq for RuntimeProviderRegistry {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0) && self.1 == other.1
    }
}
fn reference_key(reference: &Value) -> ProviderResult<String> {
    super::source::validate_provider_reference(reference)?;
    Ok(format!(
        "{}\0{}",
        reference["identifier"].as_str().unwrap(),
        reference["version"].as_str().unwrap()
    ))
}
fn unavailable() -> Version1Error {
    Version1Error::new(
        "runtime_provider_unavailable",
        "exact configured runtime closure is unavailable",
    )
}
fn guarded<T>(call: impl FnOnce() -> ProviderResult<T>) -> ProviderResult<T> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(call))
        .map_err(|_| Version1Error::new("runtime_provider_failure", "native provider panicked"))?
}
impl RuntimeProviderRegistry {
    pub fn new(verifier: Arc<dyn RuntimeProviderVerifier>) -> Self {
        Self(
            Arc::new(Registry {
                entries: BTreeMap::new(),
                dependencies: BTreeMap::new(),
                verifier,
            }),
            BTreeSet::new(),
        )
    }
    pub fn register_dependency(
        &mut self,
        reference: Value,
        closure: SourceClosure,
    ) -> ProviderResult<()> {
        let key = reference_key(&reference)?;
        if self.0.dependencies.contains_key(&key) {
            return Err(Version1Error::new(
                "duplicate_extension_registration",
                "dependency already installed",
            ));
        }
        closure.verify()?;
        if closure.digest()? != reference["content_digest"] {
            return Err(unavailable());
        }
        let registry = Arc::get_mut(&mut self.0).ok_or_else(unavailable)?;
        if registry.dependencies.contains_key(&key) {
            return Err(Version1Error::new(
                "duplicate_extension_registration",
                "dependency already installed",
            ));
        }
        registry.dependencies.insert(key, closure);
        Ok(())
    }
    pub fn register(
        &mut self,
        descriptor: Value,
        provider: Arc<dyn NativeRuntimeProvider>,
        closure: SourceClosure,
    ) -> ProviderResult<()> {
        super::source::validate_runtime_descriptor(&descriptor)?;
        let key = reference_key(&descriptor["binding"]["provider_reference"])?;
        if self
            .0
            .entries
            .contains_key(&("runtime_provider".into(), key.clone()))
        {
            return Err(Version1Error::new(
                "duplicate_extension_registration",
                "provider already installed",
            ));
        }
        closure.verify()?;
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
        let registry = Arc::get_mut(&mut self.0).ok_or_else(unavailable)?;
        if registry
            .entries
            .contains_key(&("runtime_provider".into(), key.clone()))
        {
            return Err(Version1Error::new(
                "duplicate_extension_registration",
                "provider already installed",
            ));
        }
        registry
            .entries
            .insert(("runtime_provider".into(), key), entry);
        Ok(())
    }
    fn verify_entry(&self, entry: &Entry) -> ProviderResult<BTreeSet<String>> {
        let binding = &entry.descriptor["binding"];
        entry.closure.verify()?;
        if entry.closure.digest()? != binding["provider_reference"]["content_digest"] {
            return Err(unavailable());
        }
        if let Some(source) = binding.get("source") {
            let source = source.as_str().ok_or_else(unavailable)?;
            if format!("sha256:{:x}", Sha256::digest(source.as_bytes())) != binding["source_digest"]
            {
                return Err(unavailable());
            }
        } else if entry.closure.manifest_digest()? != binding["source_digest"] {
            return Err(unavailable());
        }
        let mut previous = None;
        for reference in binding["dependencies"].as_array().ok_or_else(unavailable)? {
            let key = reference_key(reference)?;
            let full = format!("{}\0{}", key, reference["content_digest"].as_str().unwrap());
            if previous.as_ref().is_some_and(|p| p >= &full) {
                return Err(unavailable());
            }
            previous = Some(full);
            let closure = self.0.dependencies.get(&key).ok_or_else(unavailable)?;
            closure.verify()?;
            if closure.digest()? != reference["content_digest"] {
                return Err(unavailable());
            }
        }
        if !guarded(|| Ok(entry.provider.health()))? {
            return Err(unavailable());
        }
        guarded(|| {
            let report = entry
                .common
                .report(&entry.configured)
                .map_err(|error| Version1Error::new(error.code.as_str(), error.message))?;
            if report["health"] != "healthy" {
                return Err(unavailable());
            }
            if entry.descriptor["kind"] == "compiler" {
                return self.0.verifier.verify(
                    entry.provider.as_ref(),
                    &entry.descriptor,
                    &entry.closure,
                );
            }
            Ok(report["claims"]
                .as_array()
                .unwrap()
                .iter()
                .map(|claim| claim.as_str().unwrap().to_owned())
                .collect())
        })
    }
    fn select(&self, kind: &str, binding: &Value) -> ProviderResult<(&Entry, BTreeSet<String>)> {
        let key = reference_key(&binding["provider_reference"])?;
        let entry = self
            .0
            .entries
            .get(&(
                (if kind == "compiler" {
                    "compiler"
                } else {
                    "runtime_provider"
                })
                .into(),
                key,
            ))
            .ok_or_else(unavailable)?;
        if entry.descriptor != json!({"kind":kind,"binding":binding}) {
            return Err(unavailable());
        }
        Ok((entry, self.verify_entry(entry)?))
    }
    pub fn capabilities(
        &self,
        kind: &str,
        binding: &Value,
    ) -> ProviderResult<BTreeMap<String, bool>> {
        let (_, proven) = self.select(kind, binding)?;
        let mut capabilities = BTreeMap::new();
        for (name, value) in binding["capabilities"]
            .as_object()
            .ok_or_else(unavailable)?
        {
            capabilities.insert(
                name.clone(),
                value == &Value::Bool(true) && proven.contains(name),
            );
        }
        capabilities.insert(
            "external_io_capable".into(),
            !proven.contains("pure") || capabilities.get("external_io_capable") == Some(&true),
        );
        Ok(capabilities)
    }
    pub fn resolve_definition(&self, document: &Value) -> ProviderResult<()> {
        visit_bindings(document, &mut |kind, binding| {
            self.select(kind, binding).map(|_| ())
        })
    }
    pub fn effective_capabilities(
        &self,
        document: &Value,
    ) -> ProviderResult<BTreeMap<String, bool>> {
        let mut result = BTreeMap::from([
            ("deterministic".into(), true),
            ("pure".into(), true),
            ("portable".into(), true),
            ("semantically_introspectable".into(), true),
            ("process_contained".into(), true),
            ("external_io_capable".into(), false),
        ]);
        visit_bindings(document, &mut |kind, binding| {
            for (name, proved) in self.capabilities(kind, binding)? {
                if name == "external_io_capable" {
                    *result.entry(name).or_default() |= proved;
                } else {
                    *result.entry(name).or_default() &= proved;
                }
            }
            Ok(())
        })?;
        Ok(result)
    }
    pub(crate) fn invoke_guard(&self, binding: &Value, snapshot: &Value) -> ProviderResult<bool> {
        let (entry, _) = self.select("guard", binding)?;
        guarded(|| entry.provider.evaluate_guard(snapshot))?
            .as_bool()
            .ok_or_else(|| {
                Version1Error::new(
                    "runtime_provider_output_invalid",
                    "guard did not return a Boolean",
                )
            })
    }
    pub(crate) fn invoke_actions(
        &self,
        binding: &Value,
        snapshot: &Value,
    ) -> ProviderResult<Vec<Value>> {
        let (entry, _) = self.select("actions", binding)?;
        let output = guarded(|| entry.provider.evaluate_actions(snapshot))?;
        super::source::validate_runtime_output(&output)?;
        Ok(output["actions"].as_array().unwrap().clone())
    }
    pub(crate) fn can_inspect(&self, binding: &Value) -> ProviderResult<bool> {
        Ok(self
            .capabilities("guard", binding)?
            .get("semantically_introspectable")
            == Some(&true))
    }
    pub(crate) fn inspect(
        &self,
        binding: &Value,
        snapshot: &Value,
        guards: usize,
        steps: usize,
    ) -> ProviderResult<(bool, usize)> {
        if !self.can_inspect(binding)? {
            return Err(Version1Error::new(
                "inspection_capability_unavailable",
                "unproved inspector",
            ));
        }
        let (entry, _) = self.select("guard", binding)?;
        let before = guarded(|| self.0.verifier.inspection_state(entry.provider.as_ref()))?;
        let (value, charged, spent) =
            guarded(|| entry.provider.inspect_guard(snapshot, guards, steps))?;
        let after = guarded(|| self.0.verifier.inspection_state(entry.provider.as_ref()))?;
        if before != after || charged != 1 || charged > guards || spent > steps {
            return Err(Version1Error::new(
                "inspection_guard_failure",
                "inspector mutated or exceeded its budget",
            ));
        }
        Ok((value, spent))
    }
}
fn executable_slots(document: &Value) -> BTreeMap<Vec<String>, &'static str> {
    fn at(path: &[String], name: &str) -> Vec<String> {
        let mut result = path.to_vec();
        result.push(name.to_owned());
        result
    }
    fn transition(value: &Value, path: &[String], slots: &mut BTreeMap<Vec<String>, &'static str>) {
        if let Some(items) = value.as_array() {
            for (index, item) in items.iter().enumerate() {
                transition(item, &at(path, &index.to_string()), slots);
            }
        } else if value.is_object() {
            if value.get("guard").is_some() {
                slots.insert(at(path, "guard"), "guard");
            }
            if value.get("action").is_some() {
                slots.insert(at(path, "action"), "actions");
            }
        }
    }
    fn state(value: &Value, path: &[String], slots: &mut BTreeMap<Vec<String>, &'static str>) {
        if !value.is_object() {
            return;
        }
        for name in ["entry", "exit"] {
            if value.get(name).is_some() {
                slots.insert(at(path, name), "actions");
            }
        }
        for name in ["initial", "choice"] {
            transition(&value[name], &at(path, name), slots);
        }
        if let Some(handlers) = value["on_events"].as_object() {
            for (name, handler) in handlers {
                transition(handler, &at(&at(path, "on_events"), name), slots);
            }
        }
        if let Some(children) = value["states"].as_object() {
            for (name, child) in children {
                state(child, &at(&at(path, "states"), name), slots);
            }
        }
        if let Some(components) = value["components"].as_array() {
            for (index, component) in components.iter().enumerate() {
                if let Some(root) = component.get("root") {
                    state(
                        root,
                        &at(&at(&at(path, "components"), &index.to_string()), "root"),
                        slots,
                    );
                }
            }
        }
    }
    let mut slots = BTreeMap::new();
    if let Some(machines) = document["machines"].as_array() {
        for (index, machine) in machines.iter().enumerate() {
            state(
                &machine["root"],
                &["machines".to_owned(), index.to_string(), "root".to_owned()],
                &mut slots,
            );
        }
    }
    slots
}
fn visit_bindings(
    document: &Value,
    call: &mut impl FnMut(&str, &Value) -> ProviderResult<()>,
) -> ProviderResult<()> {
    for (path, kind) in executable_slots(document) {
        let value = path.iter().fold(document, |value, token| {
            if let Some(items) = value.as_array() {
                &items[token.parse::<usize>().expect("grammar array index")]
            } else {
                &value[token]
            }
        });
        if kind == "guard" {
            if let Some(binding) = value.get("provider") {
                call(kind, binding)?;
            }
        } else if let Some(items) = value.as_array() {
            for action in items {
                if let Some(binding) = action.get("provider_actions") {
                    call(kind, binding)?;
                }
            }
        }
    }
    Ok(())
}
pub(crate) fn requires_providers(value: &Value) -> bool {
    let mut found = false;
    let _ = visit_bindings(value, &mut |_, _| {
        found = true;
        Ok(())
    });
    found
}
pub(crate) fn activate(
    bundle: &mut Bundle,
    mut registry: RuntimeProviderRegistry,
    required: &BTreeSet<String>,
) -> ProviderResult<()> {
    registry.1 = required.clone();
    registry.resolve_definition(&bundle.normalized)?;
    let report = registry.effective_capabilities(&bundle.normalized)?;
    if required.iter().any(|name| report.get(name) != Some(&true)) {
        return Err(Version1Error::new(
            "extension_capability_mismatch",
            "required runtime guarantees are not proved",
        ));
    }
    fn attach(machine: &mut Machine, registry: &RuntimeProviderRegistry) {
        machine.runtime_providers = Some(registry.clone());
        for state in machine.states.values_mut() {
            for component in &mut state.components {
                if let ComponentDefinition::Inline(machine) = &mut component.definition {
                    attach(machine, registry);
                }
            }
        }
    }
    for machine in bundle.machines.values_mut() {
        attach(machine, &registry);
    }
    Ok(())
}
pub(crate) fn check_bundle(bundle: &Bundle) -> ProviderResult<()> {
    if !requires_providers(&bundle.normalized) {
        return Ok(());
    }
    let registry = bundle
        .machines
        .values()
        .next()
        .and_then(|m| m.runtime_providers.as_ref())
        .ok_or_else(unavailable)?;
    registry.resolve_definition(&bundle.normalized)?;
    let report = registry.effective_capabilities(&bundle.normalized)?;
    if registry
        .1
        .iter()
        .any(|name| report.get(name) != Some(&true))
    {
        return Err(Version1Error::new(
            "extension_capability_mismatch",
            "required runtime guarantees are no longer proved",
        ));
    }
    Ok(())
}
pub(crate) fn guard(
    runtime: &super::runtime::RuntimeState,
    scope: &str,
    binding: &Guard,
    envelope: Option<&super::model::Envelope>,
) -> ProviderResult<bool> {
    match binding {
        Guard::Cel(source) => super::cel::evaluate_boolean(
            source,
            &super::runtime::action_environment(runtime, scope, envelope),
        )
        .map_err(|_| Version1Error::new("guard_fault", "CEL guard failed")),
        Guard::Provider { provider } => runtime
            .definition
            .runtime_providers
            .as_ref()
            .ok_or_else(unavailable)?
            .invoke_guard(
                provider,
                &super::runtime::provider_snapshot(runtime, scope, envelope, provider, None),
            ),
    }
}
