//! Public version-1 extension discovery and configured capability negotiation.
//!
//! This is an in-process host boundary, not a portable plugin ABI. A provider's
//! claims are candidates; only independently verified, healthy instance claims
//! become effective. Hosts must install their own source and operational verifier.
use jsonschema::Validator;
use serde_json::{json, Value};
use std::any::Any;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtensionErrorCode {
    DuplicateExtensionRegistration,
    UnknownExtension,
    ExtensionIdentityMismatch,
    InvalidExtensionDescriptor,
    InvalidExtensionConfiguration,
    ExtensionCapabilityMismatch,
}
impl ExtensionErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DuplicateExtensionRegistration => "duplicate_extension_registration",
            Self::UnknownExtension => "unknown_extension",
            Self::ExtensionIdentityMismatch => "extension_identity_mismatch",
            Self::InvalidExtensionDescriptor => "invalid_extension_descriptor",
            Self::InvalidExtensionConfiguration => "invalid_extension_configuration",
            Self::ExtensionCapabilityMismatch => "extension_capability_mismatch",
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionError {
    pub code: ExtensionErrorCode,
    pub message: String,
}
impl ExtensionError {
    fn new(code: ExtensionErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}
impl std::fmt::Display for ExtensionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for ExtensionError {}

pub type ExtensionInstance = Arc<dyn Any + Send + Sync>;
type Instance = ExtensionInstance;
/// A configured provider. Configuration belongs to the host and must not be taken
/// from machine documents or unauthenticated input.
pub trait ExtensionProvider: Send + Sync {
    fn descriptor(&self) -> Value;
    fn validate_configuration(&self, configuration: &Value) -> Result<Instance, ExtensionError>;
    fn instance_id(&self, instance: &Instance) -> Result<String, ExtensionError>;
    fn capabilities(&self, instance: &Instance) -> Result<Vec<String>, ExtensionError>;
    fn health(&self, instance: &Instance) -> Result<String, ExtensionError>;
}
pub trait ExtensionFactory: Send + Sync {
    fn create(&self) -> Result<Arc<dyn ExtensionProvider>, ExtensionError>;
}
/// Implement in trusted host code after binding the actual loaded factory,
/// executable closure, dependency versions, configuration and native instance.
/// A provider's descriptor, callback, type ID or report alone is never proof.
/// Return false when source identity cannot be established. `prove_claims` may
/// return only claims independently exercised for this exact instance/topology.
pub trait HostVerifier: Send + Sync {
    /// Independently established host guarantees for composition.
    fn host_guarantees(&self) -> BTreeMap<String, bool> {
        BTreeMap::new()
    }
    /// Host-owned operational feature proof for this exact configured instance.
    fn prove_host_features(
        &self,
        _descriptor: &Value,
        _configuration: &Value,
        _instance: &Instance,
        _context: &str,
    ) -> BTreeSet<String> {
        BTreeSet::new()
    }
    /// Independently prove that this exact ingress acknowledgement completed.
    fn prove_ingress_acknowledgement(
        &self,
        _descriptor: &Value,
        _configuration: &Value,
        _instance: &Instance,
        _root_instance_id: &str,
        _operation: &str,
    ) -> bool {
        false
    }
    /// Check the factory's loaded executable closure before calling `create`.
    fn verify_factory(&self, descriptor: &Value, factory: &Arc<dyn ExtensionFactory>) -> bool;
    fn verify_source(
        &self,
        descriptor: &Value,
        factory: &Arc<dyn ExtensionFactory>,
        provider: &Arc<dyn ExtensionProvider>,
    ) -> bool;
    fn prove_claims(
        &self,
        descriptor: &Value,
        configuration: &Value,
        instance: &Instance,
        health: &str,
        candidates: &[String],
    ) -> BTreeSet<String>;
}
struct Entry {
    descriptor: Value,
    factory: Arc<dyn ExtensionFactory>,
    injected: Option<Arc<dyn ExtensionProvider>>,
}
type ResolvedEntry = (
    Value,
    Arc<dyn ExtensionFactory>,
    Option<Arc<dyn ExtensionProvider>>,
);
/// A handle can only be constructed by the registry that created its native instance.
#[derive(Clone)]
pub struct ConfiguredExtension {
    registry: Arc<()>,
    descriptor: Value,
    configuration: Value,
    provider: Arc<dyn ExtensionProvider>,
    instance: Instance,
}
/// A store bound to one registry, loaded provider, configuration and native object.
/// Call `current_capabilities` immediately before a strong host operation.
pub struct VerifiedExecutionStore {
    registry: Arc<ExtensionRegistry>,
    configured: ConfiguredExtension,
    store: Arc<dyn crate::checkpoint::ExecutionStore>,
}
/// One host-owned ingress acknowledgement operation. Returning success means
/// the adapter actually completed its acknowledgement for this operation.
pub trait IngressAcknowledger: Send + Sync {
    fn acknowledge(&self, root_instance_id: &str, operation: &str) -> Result<(), ExtensionError>;
}

pub struct VerifiedIngressAcknowledger {
    registry: Arc<ExtensionRegistry>,
    configured: ConfiguredExtension,
    adapter: Arc<dyn IngressAcknowledger>,
}
impl VerifiedIngressAcknowledger {
    pub fn acknowledge(&self, root_instance_id: &str, operation: &str) -> bool {
        let native_is_bound = self
            .registry
            .native_instance(&self.configured)
            .ok()
            .and_then(|native| {
                native
                    .downcast_ref::<Arc<dyn IngressAcknowledger>>()
                    .cloned()
            })
            .is_some_and(|adapter| Arc::ptr_eq(&adapter, &self.adapter));
        if !native_is_bound
            || !self
                .registry
                .report(&self.configured)
                .is_ok_and(|report| report["health"] == "healthy")
            || self
                .adapter
                .acknowledge(root_instance_id, operation)
                .is_err()
        {
            return false;
        }
        self.registry
            .report(&self.configured)
            .is_ok_and(|report| report["health"] == "healthy")
            && self.registry.verifier.as_ref().is_some_and(|verifier| {
                verifier.prove_ingress_acknowledgement(
                    &self.configured.descriptor,
                    &self.configured.configuration,
                    &self.configured.instance,
                    root_instance_id,
                    operation,
                )
            })
    }
}
impl VerifiedExecutionStore {
    pub fn store(&self) -> Arc<dyn crate::checkpoint::ExecutionStore> {
        self.store.clone()
    }
    pub fn current_capabilities(
        &self,
    ) -> Result<BTreeSet<crate::checkpoint::ExecutionStoreCapability>, ExtensionError> {
        let report = self.registry.report(&self.configured)?;
        if report["health"] != "healthy" {
            return Err(ExtensionError::new(
                ExtensionErrorCode::ExtensionCapabilityMismatch,
                "store is not healthy",
            ));
        }
        Ok(report["claims"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .filter_map(crate::checkpoint::ExecutionStoreCapability::from_name)
            .collect())
    }
    pub(crate) fn current_host_features(
        &self,
        context: &str,
    ) -> Result<BTreeSet<crate::checkpoint::HostFeature>, ExtensionError> {
        let report = self.registry.report(&self.configured)?;
        if report["health"] != "healthy" {
            return Err(ExtensionError::new(
                ExtensionErrorCode::ExtensionCapabilityMismatch,
                "store is not healthy",
            ));
        }
        let names = self
            .registry
            .verifier
            .as_ref()
            .map(|v| {
                v.prove_host_features(
                    &self.configured.descriptor,
                    &self.configured.configuration,
                    &self.configured.instance,
                    context,
                )
            })
            .unwrap_or_default();
        Ok(names
            .iter()
            .filter_map(|name| crate::checkpoint::HostFeature::from_name(name))
            .collect())
    }
}
/// One host-owned profile request. A caller must establish authorization before
/// supplying its configuration and invoking an operation with the result.
pub struct ProfileRequest<'a> {
    pub configurations: &'a [(String, Value, Value)],
    pub requirements: &'a [Value],
    pub compose: bool,
    pub projection: &'a [String],
    pub requested_profile: Option<&'a str>,
    pub weak_profile_opt_in: bool,
}
#[derive(Default)]
pub struct ExtensionRegistry {
    entries: RwLock<BTreeMap<(String, String, String), Entry>>,
    store_adapters: RwLock<BTreeMap<String, (Value, Value)>>,
    token: Arc<()>,
    verifier: Option<Arc<dyn HostVerifier>>,
}
impl ExtensionRegistry {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with_verifier(verifier: Arc<dyn HostVerifier>) -> Self {
        Self {
            verifier: Some(verifier),
            ..Self::default()
        }
    }
    pub fn descriptors(&self) -> Result<Vec<Value>, ExtensionError> {
        Ok(self
            .entries
            .read()
            .map_err(|_| lock_error())?
            .values()
            .map(|e| e.descriptor.clone())
            .collect())
    }
    pub fn register(
        &self,
        descriptor: Value,
        factory: Arc<dyn ExtensionFactory>,
    ) -> Result<(), ExtensionError> {
        self.register_entry(descriptor, factory, None)
    }
    /// Associate an ordinary URI lookup key with an exact public store provider.
    /// Metadata is selection policy only; effective claims come from the native instance.
    pub fn register_store_adapter(
        &self,
        registration: Value,
        descriptor: Value,
        factory: Arc<dyn ExtensionFactory>,
    ) -> Result<Value, crate::checkpoint::AdapterError> {
        use crate::checkpoint::{adapter_registration_policy, AdapterError, AdapterErrorCode};
        if descriptor["category"] != "execution_store" {
            return Err(AdapterError::new(
                AdapterErrorCode::InvalidAdapterConfiguration,
                "not an execution-store provider",
            ));
        }
        let mut entries = self
            .store_adapters
            .write()
            .map_err(|_| adapter_error(lock_error()))?;
        let existing: Vec<_> = entries.values().map(|entry| entry.0.clone()).collect();
        let checked = adapter_registration_policy(&existing, &registration)?;
        self.register(descriptor.clone(), factory)
            .map_err(adapter_error)?;
        entries.insert(
            checked["uri_scheme"].as_str().unwrap().to_owned(),
            (checked.clone(), descriptor),
        );
        Ok(checked)
    }

    /// Select a provider generically, configure it through the public verified
    /// path, and evaluate requested capabilities against current native proof.
    pub fn resolve_execution_store(
        self: &Arc<Self>,
        uri: &str,
        adapter_identifier: Option<&str>,
        configuration: &Value,
        requested_capabilities: &Value,
    ) -> Result<VerifiedExecutionStore, crate::checkpoint::AdapterError> {
        use crate::checkpoint::adapter_resolution_policy;
        let (registration, descriptor) = {
            let entries = self
                .store_adapters
                .read()
                .map_err(|_| adapter_error(lock_error()))?;
            let registrations: Vec<_> = entries.values().map(|entry| entry.0.clone()).collect();
            let decision = adapter_resolution_policy(
                &registrations,
                uri,
                adapter_identifier,
                configuration,
                &json!([]),
            )?;
            let entry = entries
                .get(decision["registration"]["uri_scheme"].as_str().unwrap())
                .unwrap();
            entry.clone()
        };
        let verified = self
            .configure_execution_store(&descriptor, configuration)
            .map_err(adapter_error)?;
        let mut proved = registration;
        proved["capabilities"] = json!(verified
            .current_capabilities()
            .map_err(adapter_error)?
            .iter()
            .map(|capability| capability.as_str())
            .collect::<Vec<_>>());
        adapter_resolution_policy(
            &[proved],
            uri,
            adapter_identifier,
            configuration,
            requested_capabilities,
        )?;
        Ok(verified)
    }
    fn register_entry(
        &self,
        descriptor: Value,
        factory: Arc<dyn ExtensionFactory>,
        injected: Option<Arc<dyn ExtensionProvider>>,
    ) -> Result<(), ExtensionError> {
        check(
            "descriptor",
            &descriptor,
            ExtensionErrorCode::InvalidExtensionDescriptor,
        )?;
        let key = key(&descriptor);
        let mut entries = self.entries.write().map_err(|_| lock_error())?;
        if entries.contains_key(&key) {
            return Err(ExtensionError::new(
                ExtensionErrorCode::DuplicateExtensionRegistration,
                "provider already registered",
            ));
        }
        entries.insert(
            key,
            Entry {
                descriptor,
                factory,
                injected,
            },
        );
        Ok(())
    }
    pub fn register_bytes(
        &self,
        bytes: &[u8],
        factory: Arc<dyn ExtensionFactory>,
    ) -> Result<(), ExtensionError> {
        let descriptor = crate::format1::strict_json::parse(bytes).map_err(|_| {
            ExtensionError::new(
                ExtensionErrorCode::InvalidExtensionDescriptor,
                "invalid descriptor JSON",
            )
        })?;
        self.register(descriptor, factory)
    }
    pub fn inject(
        &self,
        descriptor: Value,
        provider: Arc<dyn ExtensionProvider>,
    ) -> Result<(), ExtensionError> {
        self.register_entry(
            descriptor,
            Arc::new(InjectedFactory(provider.clone())),
            Some(provider),
        )
    }
    fn entry(&self, category: &str, reference: &Value) -> Result<ResolvedEntry, ExtensionError> {
        check(
            "reference",
            reference,
            ExtensionErrorCode::InvalidExtensionDescriptor,
        )?;
        let entries = self.entries.read().map_err(|_| lock_error())?;
        let key = (
            category.to_owned(),
            reference["identifier"].as_str().unwrap().to_owned(),
            reference["version"].as_str().unwrap().to_owned(),
        );
        if let Some(e) = entries.get(&key) {
            if e.descriptor["provider_reference"] != *reference {
                return Err(ExtensionError::new(
                    ExtensionErrorCode::ExtensionIdentityMismatch,
                    "provider digest differs",
                ));
            }
            return Ok((e.descriptor.clone(), e.factory.clone(), e.injected.clone()));
        }
        let code = if entries.keys().any(|k| k.0 == category && k.1 == key.1) {
            ExtensionErrorCode::ExtensionIdentityMismatch
        } else {
            ExtensionErrorCode::UnknownExtension
        };
        Err(ExtensionError::new(code, "provider reference unavailable"))
    }
    pub fn validate_configuration(
        &self,
        descriptor: &Value,
        configuration: &Value,
    ) -> Result<ConfiguredExtension, ExtensionError> {
        check(
            "descriptor",
            descriptor,
            ExtensionErrorCode::InvalidExtensionDescriptor,
        )?;
        let (registered, factory, injected) = self.entry(
            descriptor["category"].as_str().unwrap(),
            &descriptor["provider_reference"],
        )?;
        if registered != *descriptor {
            return Err(ExtensionError::new(
                ExtensionErrorCode::ExtensionIdentityMismatch,
                "descriptor differs",
            ));
        }
        if !configuration.is_object()
            || !valid_json(configuration)
            || !configuration["instance_id"]
                .as_str()
                .is_some_and(valid_identifier)
        {
            return Err(ExtensionError::new(
                ExtensionErrorCode::InvalidExtensionConfiguration,
                "invalid host configuration",
            ));
        }
        let verifier = self.verifier.as_ref().ok_or_else(|| {
            ExtensionError::new(
                ExtensionErrorCode::ExtensionIdentityMismatch,
                "host source verifier unavailable",
            )
        })?;
        if injected.is_none() && !verifier.verify_factory(&registered, &factory) {
            return Err(ExtensionError::new(
                ExtensionErrorCode::ExtensionIdentityMismatch,
                "factory executable closure unverified",
            ));
        }
        let provider = if let Some(provider) = injected {
            provider
        } else {
            factory.create()?
        };
        if !verifier.verify_source(&registered, &factory, &provider) {
            return Err(ExtensionError::new(
                ExtensionErrorCode::ExtensionIdentityMismatch,
                "loaded executable closure unverified",
            ));
        }
        let actual_descriptor = provider.descriptor();
        check(
            "descriptor",
            &actual_descriptor,
            ExtensionErrorCode::InvalidExtensionDescriptor,
        )?;
        if actual_descriptor != registered {
            return Err(ExtensionError::new(
                ExtensionErrorCode::ExtensionIdentityMismatch,
                "loaded provider descriptor differs",
            ));
        }
        let instance = provider.validate_configuration(configuration)?;
        if provider.instance_id(&instance)? != configuration["instance_id"] {
            return Err(ExtensionError::new(
                ExtensionErrorCode::InvalidExtensionConfiguration,
                "configured native instance differs",
            ));
        }
        Ok(ConfiguredExtension {
            registry: self.token.clone(),
            descriptor: registered,
            configuration: configuration.clone(),
            provider,
            instance,
        })
    }
    fn bound(
        &self,
        configured: &ConfiguredExtension,
    ) -> Result<(Value, Arc<dyn ExtensionFactory>), ExtensionError> {
        if !Arc::ptr_eq(&self.token, &configured.registry) {
            return Err(ExtensionError::new(
                ExtensionErrorCode::ExtensionIdentityMismatch,
                "foreign instance",
            ));
        }
        let (descriptor, factory, injected) = self.entry(
            configured.descriptor["category"].as_str().unwrap(),
            &configured.descriptor["provider_reference"],
        )?;
        if descriptor != configured.descriptor
            || (injected.is_none()
                && !self
                    .verifier
                    .as_ref()
                    .is_some_and(|v| v.verify_factory(&descriptor, &factory)))
            || !self
                .verifier
                .as_ref()
                .is_some_and(|v| v.verify_source(&descriptor, &factory, &configured.provider))
        {
            return Err(ExtensionError::new(
                ExtensionErrorCode::ExtensionIdentityMismatch,
                "source changed",
            ));
        }
        if configured.provider.descriptor() != descriptor {
            return Err(ExtensionError::new(
                ExtensionErrorCode::ExtensionIdentityMismatch,
                "provider descriptor changed",
            ));
        }
        if configured.provider.instance_id(&configured.instance)?
            != configured.configuration["instance_id"]
        {
            return Err(ExtensionError::new(
                ExtensionErrorCode::InvalidExtensionConfiguration,
                "native instance changed",
            ));
        }
        Ok((descriptor, factory))
    }
    pub fn capabilities(
        &self,
        configured: &ConfiguredExtension,
    ) -> Result<Vec<String>, ExtensionError> {
        self.bound(configured)?;
        configured.provider.capabilities(&configured.instance)
    }
    /// Return the bound native object for the category-specific host path.
    /// The host must negotiate required claims immediately before use.
    pub fn native_instance(
        &self,
        configured: &ConfiguredExtension,
    ) -> Result<ExtensionInstance, ExtensionError> {
        self.bound(configured)?;
        Ok(configured.instance.clone())
    }
    /// Access a bundled store configured through the same public registry.
    pub fn bundled_execution_store(
        &self,
        configured: &ConfiguredExtension,
    ) -> Result<Arc<dyn crate::checkpoint::ExecutionStore>, ExtensionError> {
        let instance = self.native_instance(configured)?;
        Ok(instance
            .downcast_ref::<BundledStoreInstance>()
            .ok_or_else(|| {
                ExtensionError::new(
                    ExtensionErrorCode::ExtensionIdentityMismatch,
                    "not a bundled execution store",
                )
            })?
            .store
            .clone())
    }
    /// Configure a native execution store through the verified public path.
    /// Third-party providers return an `Arc<dyn ExecutionStore>` as their native
    /// instance; bundled stores use their private bound instance wrapper.
    pub fn configure_execution_store(
        self: &Arc<Self>,
        descriptor: &Value,
        configuration: &Value,
    ) -> Result<VerifiedExecutionStore, ExtensionError> {
        let configured = self.validate_configuration(descriptor, configuration)?;
        if descriptor["category"] != "execution_store" {
            return Err(ExtensionError::new(
                ExtensionErrorCode::ExtensionIdentityMismatch,
                "provider is not an execution store",
            ));
        }
        let native = self.native_instance(&configured)?;
        let store = if let Some(bundle) = native.downcast_ref::<BundledStoreInstance>() {
            bundle.store.clone()
        } else if let Some(store) =
            native.downcast_ref::<Arc<dyn crate::checkpoint::ExecutionStore>>()
        {
            store.clone()
        } else {
            return Err(ExtensionError::new(
                ExtensionErrorCode::ExtensionIdentityMismatch,
                "provider did not bind a native execution store",
            ));
        };
        Ok(VerifiedExecutionStore {
            registry: self.clone(),
            configured,
            store,
        })
    }
    pub fn configure_ingress_acknowledger(
        self: &Arc<Self>,
        descriptor: &Value,
        configuration: &Value,
    ) -> Result<VerifiedIngressAcknowledger, ExtensionError> {
        if descriptor["category"] != "transport" {
            return Err(ExtensionError::new(
                ExtensionErrorCode::ExtensionIdentityMismatch,
                "ingress acknowledgement requires a transport provider",
            ));
        }
        let configured = self.validate_configuration(descriptor, configuration)?;
        let native = self.native_instance(&configured)?;
        let adapter = native
            .downcast_ref::<Arc<dyn IngressAcknowledger>>()
            .cloned()
            .ok_or_else(|| {
                ExtensionError::new(
                    ExtensionErrorCode::ExtensionIdentityMismatch,
                    "provider did not bind a native ingress acknowledger",
                )
            })?;
        Ok(VerifiedIngressAcknowledger {
            registry: self.clone(),
            configured,
            adapter,
        })
    }
    pub fn health(&self, configured: &ConfiguredExtension) -> Result<String, ExtensionError> {
        self.bound(configured)?;
        configured.provider.health(&configured.instance)
    }
    pub fn report(&self, configured: &ConfiguredExtension) -> Result<Value, ExtensionError> {
        let (descriptor, _) = self.bound(configured)?;
        let candidates = self.capabilities(configured)?;
        let health = self.health(configured)?;
        let candidate = json!({"category": descriptor["category"], "provider_reference": descriptor["provider_reference"], "instance_id": configured.configuration["instance_id"], "health": health, "claims": candidates});
        check(
            "report",
            &candidate,
            ExtensionErrorCode::InvalidExtensionConfiguration,
        )?;
        let supported: BTreeSet<&str> = descriptor["supported_capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        if !candidates.iter().all(|c| supported.contains(c.as_str())) {
            return Err(ExtensionError::new(
                ExtensionErrorCode::InvalidExtensionConfiguration,
                "undeclared claim",
            ));
        }
        let proven = self
            .verifier
            .as_ref()
            .map(|v| {
                v.prove_claims(
                    &descriptor,
                    &configured.configuration,
                    &configured.instance,
                    &health,
                    &candidates,
                )
            })
            .unwrap_or_default();
        let claims: Vec<_> = candidates
            .into_iter()
            .filter(|c| {
                health == "healthy"
                    && proven.contains(c)
                    && !(c == "pure"
                        && candidate["claims"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .any(|v| v == "external_io_capable"))
            })
            .collect();
        Ok(
            json!({"category": descriptor["category"], "provider_reference": descriptor["provider_reference"], "instance_id": configured.configuration["instance_id"], "health": health, "claims": claims}),
        )
    }
    fn require(&self, report: &Value, requirement: &Value) -> Result<(), ExtensionError> {
        check(
            "requirement",
            requirement,
            ExtensionErrorCode::InvalidExtensionDescriptor,
        )?;
        self.entry(
            requirement["category"].as_str().unwrap(),
            &requirement["provider_reference"],
        )?;
        if report["category"] != requirement["category"]
            || report["provider_reference"] != requirement["provider_reference"]
            || report["instance_id"] != requirement["instance_id"]
            || report["health"] != "healthy"
            || !report["claims"]
                .as_array()
                .is_some_and(|a| a.contains(&requirement["capability"]))
        {
            return Err(ExtensionError::new(
                ExtensionErrorCode::ExtensionCapabilityMismatch,
                "required capability unproved",
            ));
        }
        Ok(())
    }
    pub fn negotiate(
        &self,
        descriptor: &Value,
        configuration: &Value,
        requirement: Option<&Value>,
    ) -> Result<Value, ExtensionError> {
        let configured = self.validate_configuration(descriptor, configuration)?;
        let report = self.report(&configured)?;
        if let Some(requirement) = requirement {
            self.require(&report, requirement)?;
        }
        Ok(report)
    }
    /// Resolve every participant and requirement before a host operation mutates state.
    pub fn evaluate_profile(&self, request: ProfileRequest<'_>) -> Result<Value, ExtensionError> {
        let ProfileRequest {
            configurations,
            requirements,
            compose,
            projection,
            requested_profile,
            weak_profile_opt_in,
        } = request;
        for requirement in requirements {
            check(
                "requirement",
                requirement,
                ExtensionErrorCode::InvalidExtensionDescriptor,
            )?;
        }
        let mut reports = Vec::new();
        for (category, reference, configuration) in configurations {
            let (descriptor, _, _) = self.entry(category, reference)?;
            reports.push(self.negotiate(&descriptor, configuration, None)?);
        }
        if reports.iter().any(|r| r["health"] != "healthy") {
            return Err(ExtensionError::new(
                ExtensionErrorCode::ExtensionCapabilityMismatch,
                "unhealthy participant",
            ));
        }
        for requirement in requirements {
            self.entry(
                requirement["category"].as_str().unwrap(),
                &requirement["provider_reference"],
            )?;
            if !reports.iter().any(|r| self.require(r, requirement).is_ok()) {
                return Err(ExtensionError::new(
                    ExtensionErrorCode::ExtensionCapabilityMismatch,
                    "profile requirement unproved",
                ));
            }
        }
        let mut effective = serde_json::Map::new();
        if compose {
            let host_guarantees = self
                .verifier
                .as_ref()
                .map(|v| v.host_guarantees())
                .unwrap_or_default();
            let full = compose_capabilities(&reports, &host_guarantees);
            if full["weak_profile_opt_in_required"] && !weak_profile_opt_in {
                return Err(ExtensionError::new(
                    ExtensionErrorCode::ExtensionCapabilityMismatch,
                    "weak profile requires opt-in",
                ));
            }
            if let Some(requested) = requested_profile {
                let valid = if requested == "automatic_retry_without_external_io" {
                    !full["external_io_capable"] && full["pure"] && full["deterministic"]
                } else {
                    *full.get(requested).ok_or_else(|| {
                        ExtensionError::new(
                            ExtensionErrorCode::InvalidExtensionConfiguration,
                            "unknown profile",
                        )
                    })?
                };
                if !valid {
                    return Err(ExtensionError::new(
                        ExtensionErrorCode::ExtensionCapabilityMismatch,
                        "requested guarantee unproved",
                    ));
                }
            }
            for name in projection {
                let value = full.get(name).ok_or_else(|| {
                    ExtensionError::new(
                        ExtensionErrorCode::InvalidExtensionConfiguration,
                        "unknown projection",
                    )
                })?;
                effective.insert(name.clone(), json!(value));
            }
        } else if requested_profile.is_some() {
            return Err(ExtensionError::new(
                ExtensionErrorCode::InvalidExtensionConfiguration,
                "composition required",
            ));
        }
        Ok(json!({"status": "accepted", "reports": reports, "effective": effective}))
    }
}
struct InjectedFactory(Arc<dyn ExtensionProvider>);
impl ExtensionFactory for InjectedFactory {
    fn create(&self) -> Result<Arc<dyn ExtensionProvider>, ExtensionError> {
        Ok(self.0.clone())
    }
}
fn adapter_error(error: ExtensionError) -> crate::checkpoint::AdapterError {
    use crate::checkpoint::{AdapterError, AdapterErrorCode};
    let code = match error.code {
        ExtensionErrorCode::DuplicateExtensionRegistration => {
            AdapterErrorCode::DuplicateAdapterRegistration
        }
        ExtensionErrorCode::UnknownExtension => AdapterErrorCode::UnknownAdapter,
        ExtensionErrorCode::InvalidExtensionDescriptor
        | ExtensionErrorCode::InvalidExtensionConfiguration => {
            AdapterErrorCode::InvalidAdapterConfiguration
        }
        ExtensionErrorCode::ExtensionIdentityMismatch
        | ExtensionErrorCode::ExtensionCapabilityMismatch => {
            AdapterErrorCode::AdapterCapabilityMismatch
        }
    };
    AdapterError::new(code, error.to_string())
}

fn lock_error() -> ExtensionError {
    ExtensionError::new(
        ExtensionErrorCode::InvalidExtensionConfiguration,
        "registry lock poisoned",
    )
}
fn key(descriptor: &Value) -> (String, String, String) {
    (
        descriptor["category"].as_str().unwrap().into(),
        descriptor["provider_reference"]["identifier"]
            .as_str()
            .unwrap()
            .into(),
        descriptor["provider_reference"]["version"]
            .as_str()
            .unwrap()
            .into(),
    )
}
fn check(name: &str, document: &Value, code: ExtensionErrorCode) -> Result<(), ExtensionError> {
    let schema = match name {
        "descriptor" => include_str!("../schema/extension-descriptor-v1.schema.json"),
        "reference" => include_str!("../schema/provider-reference-v1.schema.json"),
        "report" => include_str!("../schema/extension-capability-report-v1.schema.json"),
        "requirement" => include_str!("../schema/extension-capability-requirement-v1.schema.json"),
        _ => unreachable!(),
    };
    let schema: Value = serde_json::from_str(schema).expect("bundled schema");
    let validator: Validator = jsonschema::validator_for(&schema).expect("bundled schema compiles");
    validator
        .validate(document)
        .map_err(|e| ExtensionError::new(code, e.to_string()))
}
fn valid_identifier(s: &str) -> bool {
    let mut bytes = s.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
}
fn valid_json(value: &Value) -> bool {
    match value {
        Value::Null | Value::Bool(_) | Value::String(_) | Value::Number(_) => true,
        Value::Array(a) => a.iter().all(valid_json),
        Value::Object(o) => o.values().all(valid_json),
    }
}
/// All participants and host policy must prove each guarantee. Unknown I/O is a hazard.
fn compose_capabilities(
    reports: &[Value],
    host_guarantees: &BTreeMap<String, bool>,
) -> BTreeMap<String, bool> {
    let mut result = BTreeMap::new();
    for name in [
        "deterministic",
        "pure",
        "portable",
        "semantically_introspectable",
        "process_contained",
    ] {
        result.insert(
            name.into(),
            host_guarantees.get(name) == Some(&true)
                && reports.iter().all(|r| {
                    r["health"] == "healthy"
                        && r["claims"]
                            .as_array()
                            .is_some_and(|a| a.contains(&json!(name)))
                }),
        );
    }
    let hazard = reports.iter().any(|r| {
        r["health"] != "healthy"
            || r["claims"].as_array().is_none_or(|a| {
                a.contains(&json!("external_io_capable")) || !a.contains(&json!("pure"))
            })
    });
    result.insert("external_io_capable".into(), hazard);
    result.insert(
        "weak_profile_opt_in_required".into(),
        hazard
            || [
                "deterministic",
                "pure",
                "portable",
                "semantically_introspectable",
                "process_contained",
            ]
            .iter()
            .any(|n| result.get(*n) != Some(&true)),
    );
    result
}

/// Host-controlled registry preloaded through the ordinary public registration path
/// with the compiled memory, file, and feature-enabled SQL stores.
pub fn bundled_store_registry() -> Result<ExtensionRegistry, ExtensionError> {
    create_bundled_store_registry(None)
}
/// Register bundled stores while delegating other installed providers to the
/// host's trusted verifier in the same public registry.
pub fn bundled_store_registry_with_verifier(
    verifier: Arc<dyn HostVerifier>,
) -> Result<ExtensionRegistry, ExtensionError> {
    create_bundled_store_registry(Some(verifier))
}
fn create_bundled_store_registry(
    external: Option<Arc<dyn HostVerifier>>,
) -> Result<ExtensionRegistry, ExtensionError> {
    let verifier = Arc::new(BundledStoreVerifier {
        bindings: RwLock::new(BTreeMap::new()),
        external,
    });
    let registry = ExtensionRegistry::with_verifier(verifier.clone());
    for name in bundled_store_names() {
        let provider: Arc<dyn ExtensionProvider> = Arc::new(BundledStoreProvider { name });
        let factory: Arc<dyn ExtensionFactory> = Arc::new(InjectedFactory(provider.clone()));
        let descriptor = bundled_store_descriptor(name);
        verifier.bind(name, factory.clone(), provider)?;
        registry.register_store_adapter(json!({
            "adapter_identifier":name,"uri_scheme":name,"source":"bundled",
            "configuration_schema":{"type":"object","properties":{"instance_id":{"type":"string"},"uri":{"type":"string"}},"required":["instance_id","uri"],"additionalProperties":false},
            "capabilities":descriptor["supported_capabilities"]
        }), descriptor, factory).map_err(|error| ExtensionError::new(ExtensionErrorCode::InvalidExtensionDescriptor, error.to_string()))?;
    }
    Ok(registry)
}
fn bundled_store_names() -> Vec<&'static str> {
    #[allow(unused_mut)]
    let mut names = vec!["memory", "file"];
    #[cfg(feature = "sqlite")]
    names.push("sqlite");
    #[cfg(feature = "postgresql")]
    names.push("postgresql");
    names
}
fn bundled_store_digest() -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"determa-rust-bundled-store-closure-1\0");
    // These bytes are compiled into the artifact. The lockfile pins dependency
    // versions; the host trusts the installed crate build and its own policy.
    for bytes in [
        include_bytes!("extensions.rs").as_slice(),
        include_bytes!("checkpoint/store.rs"),
        include_bytes!("checkpoint/adapters/memory.rs"),
        include_bytes!("checkpoint/adapters/file.rs"),
        include_bytes!("../Cargo.lock"),
    ] {
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }
    #[cfg(feature = "sqlite")]
    {
        let bytes = include_bytes!("checkpoint/adapters/sqlite.rs");
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }
    #[cfg(feature = "postgresql")]
    {
        let bytes = include_bytes!("checkpoint/adapters/postgresql.rs");
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }
    format!("sha256:{:x}", hasher.finalize())
}
fn bundled_store_descriptor(name: &str) -> Value {
    let mut caps = match name {
        "memory" => vec!["ephemeral"],
        "file" => vec!["restart_persistent"],
        "sqlite" => vec![
            "durable_single_writer",
            "root_identity_retention",
            "shared_application_transaction",
        ],
        "postgresql" => vec![
            "durable_concurrent",
            "root_identity_retention",
            "shared_application_transaction",
        ],
        _ => unreachable!(),
    };
    if name == "sqlite" || name == "postgresql" {
        caps.extend([
            "permanent_receipt_retention",
            "permanent_outbox_terminal_retention",
            "compact_effect_identity_retention",
        ]);
    }
    json!({"category":"execution_store", "provider_reference":{"identifier":format!("determa.{name}"),"version":env!("CARGO_PKG_VERSION"),"content_digest":bundled_store_digest()}, "interface_version":1,"supported_capabilities":caps})
}
struct BundledStoreProvider {
    name: &'static str,
}
struct BundledStoreInstance {
    instance_id: String,
    store: Arc<dyn crate::checkpoint::ExecutionStore>,
}
impl ExtensionProvider for BundledStoreProvider {
    fn descriptor(&self) -> Value {
        bundled_store_descriptor(self.name)
    }
    fn validate_configuration(&self, configuration: &Value) -> Result<Instance, ExtensionError> {
        let o = configuration.as_object().ok_or_else(invalid_config)?;
        if o.len() != 2 || !o.contains_key("instance_id") || !o.contains_key("uri") {
            return Err(invalid_config());
        }
        let instance_id = o["instance_id"]
            .as_str()
            .filter(|s| valid_identifier(s))
            .ok_or_else(invalid_config)?;
        let uri = o["uri"].as_str().ok_or_else(invalid_config)?;
        if uri.split_once(':').map(|x| x.0) != Some(self.name) {
            return Err(invalid_config());
        }
        use crate::checkpoint::{
            ExecutionStoreFactory, FileExecutionStoreFactory, MemoryExecutionStoreFactory,
        };
        let store = match self.name {
            "memory" => MemoryExecutionStoreFactory.create(uri),
            "file" => FileExecutionStoreFactory.create(uri),
            #[cfg(feature = "sqlite")]
            "sqlite" => crate::checkpoint::SqliteExecutionStoreFactory.create(uri),
            #[cfg(feature = "postgresql")]
            "postgresql" => {
                crate::checkpoint::PostgresqlExecutionStoreFactory::no_tls().create(uri)
            }
            _ => unreachable!(),
        }
        .map_err(|_| invalid_config())?;
        Ok(Arc::new(BundledStoreInstance {
            instance_id: instance_id.into(),
            store,
        }))
    }
    fn instance_id(&self, instance: &Instance) -> Result<String, ExtensionError> {
        Ok(instance
            .downcast_ref::<BundledStoreInstance>()
            .ok_or_else(invalid_config)?
            .instance_id
            .clone())
    }
    fn capabilities(&self, instance: &Instance) -> Result<Vec<String>, ExtensionError> {
        let store = &instance
            .downcast_ref::<BundledStoreInstance>()
            .ok_or_else(invalid_config)?
            .store;
        Ok(store
            .capabilities()
            .into_iter()
            .map(|c| c.as_str().into())
            .collect())
    }
    fn health(&self, instance: &Instance) -> Result<String, ExtensionError> {
        let store = &instance
            .downcast_ref::<BundledStoreInstance>()
            .ok_or_else(invalid_config)?
            .store;
        Ok(if store.health().is_ok_and(|h| h.healthy) {
            "healthy"
        } else {
            "unavailable"
        }
        .into())
    }
}
fn invalid_config() -> ExtensionError {
    ExtensionError::new(
        ExtensionErrorCode::InvalidExtensionConfiguration,
        "invalid configured extension",
    )
}
struct BundledStoreVerifier {
    bindings: RwLock<BTreeMap<String, BundledBinding>>,
    external: Option<Arc<dyn HostVerifier>>,
}
type BundledBinding = (Arc<dyn ExtensionFactory>, Arc<dyn ExtensionProvider>);
impl BundledStoreVerifier {
    fn is_bundled(descriptor: &Value) -> bool {
        descriptor["provider_reference"]["identifier"]
            .as_str()
            .and_then(|s| s.strip_prefix("determa."))
            .is_some_and(|name| bundled_store_names().contains(&name))
    }
    fn bind(
        &self,
        name: &str,
        factory: Arc<dyn ExtensionFactory>,
        provider: Arc<dyn ExtensionProvider>,
    ) -> Result<(), ExtensionError> {
        self.bindings
            .write()
            .map_err(|_| lock_error())?
            .insert(name.into(), (factory, provider));
        Ok(())
    }
}
impl HostVerifier for BundledStoreVerifier {
    fn host_guarantees(&self) -> BTreeMap<String, bool> {
        self.external
            .as_ref()
            .map_or_else(BTreeMap::new, |v| v.host_guarantees())
    }
    fn prove_ingress_acknowledgement(
        &self,
        descriptor: &Value,
        configuration: &Value,
        instance: &Instance,
        root_instance_id: &str,
        operation: &str,
    ) -> bool {
        !Self::is_bundled(descriptor)
            && self.external.as_ref().is_some_and(|v| {
                v.prove_ingress_acknowledgement(
                    descriptor,
                    configuration,
                    instance,
                    root_instance_id,
                    operation,
                )
            })
    }
    fn prove_host_features(
        &self,
        descriptor: &Value,
        _configuration: &Value,
        instance: &Instance,
        context: &str,
    ) -> BTreeSet<String> {
        if !Self::is_bundled(descriptor) {
            return self.external.as_ref().map_or_else(BTreeSet::new, |v| {
                v.prove_host_features(descriptor, _configuration, instance, context)
            });
        }
        let Some(native) = instance.downcast_ref::<BundledStoreInstance>() else {
            return BTreeSet::new();
        };
        let Some(name) = descriptor["provider_reference"]["identifier"]
            .as_str()
            .and_then(|s| s.strip_prefix("determa."))
        else {
            return BTreeSet::new();
        };
        if !bundled_store_names().contains(&name)
            || descriptor != &bundled_store_descriptor(name)
            || !native.store.health().is_ok_and(|h| h.healthy)
        {
            return BTreeSet::new();
        }
        let durable = match name {
            #[cfg(feature = "sqlite")]
            "sqlite" => native
                .store
                .as_any()
                .is::<crate::checkpoint::SqliteExecutionStore>(),
            #[cfg(feature = "postgresql")]
            "postgresql" => native
                .store
                .as_any()
                .is::<crate::checkpoint::PostgresqlExecutionStore>(),
            _ => false,
        };
        let mut features = BTreeSet::new();
        if durable {
            features.insert("atomic_accept_process".into());
        }
        if durable && context == "native_shared_transaction" {
            features.insert("native_shared_transaction_used".into());
        }
        features
    }
    fn verify_factory(&self, descriptor: &Value, factory: &Arc<dyn ExtensionFactory>) -> bool {
        if !Self::is_bundled(descriptor) {
            return self
                .external
                .as_ref()
                .is_some_and(|v| v.verify_factory(descriptor, factory));
        }
        if descriptor["category"] != "execution_store"
            || descriptor["provider_reference"]["content_digest"] != bundled_store_digest()
        {
            return false;
        }
        let Some(name) = descriptor["provider_reference"]["identifier"]
            .as_str()
            .and_then(|s| s.strip_prefix("determa."))
        else {
            return false;
        };
        self.bindings
            .read()
            .ok()
            .and_then(|bindings| bindings.get(name).map(|(f, _)| Arc::ptr_eq(f, factory)))
            .unwrap_or(false)
    }
    fn verify_source(
        &self,
        descriptor: &Value,
        factory: &Arc<dyn ExtensionFactory>,
        provider: &Arc<dyn ExtensionProvider>,
    ) -> bool {
        if !Self::is_bundled(descriptor) {
            return self
                .external
                .as_ref()
                .is_some_and(|v| v.verify_source(descriptor, factory, provider));
        }
        if descriptor["category"] != "execution_store"
            || descriptor["provider_reference"]["content_digest"] != bundled_store_digest()
        {
            return false;
        }
        let Some(name) = descriptor["provider_reference"]["identifier"]
            .as_str()
            .and_then(|s| s.strip_prefix("determa."))
        else {
            return false;
        };
        self.bindings
            .read()
            .ok()
            .and_then(|bindings| {
                bindings
                    .get(name)
                    .map(|(f, p)| Arc::ptr_eq(f, factory) && Arc::ptr_eq(p, provider))
            })
            .unwrap_or(false)
    }
    fn prove_claims(
        &self,
        descriptor: &Value,
        _configuration: &Value,
        instance: &Instance,
        health: &str,
        candidates: &[String],
    ) -> BTreeSet<String> {
        if !Self::is_bundled(descriptor) {
            return self.external.as_ref().map_or_else(BTreeSet::new, |v| {
                v.prove_claims(descriptor, _configuration, instance, health, candidates)
            });
        }
        if health != "healthy" {
            return BTreeSet::new();
        }
        let Some(name) = descriptor["provider_reference"]["identifier"]
            .as_str()
            .and_then(|s| s.strip_prefix("determa."))
        else {
            return BTreeSet::new();
        };
        let Some(native) = instance.downcast_ref::<BundledStoreInstance>() else {
            return BTreeSet::new();
        };
        let exact_type = match name {
            "memory" => native
                .store
                .as_any()
                .is::<crate::checkpoint::MemoryExecutionStore>(),
            "file" => native
                .store
                .as_any()
                .is::<crate::checkpoint::FileExecutionStore>(),
            #[cfg(feature = "sqlite")]
            "sqlite" => native
                .store
                .as_any()
                .is::<crate::checkpoint::SqliteExecutionStore>(),
            #[cfg(feature = "postgresql")]
            "postgresql" => native
                .store
                .as_any()
                .is::<crate::checkpoint::PostgresqlExecutionStore>(),
            _ => false,
        };
        if !exact_type || !native.store.health().is_ok_and(|h| h.healthy) {
            return BTreeSet::new();
        }
        let actual: BTreeSet<_> = native
            .store
            .capabilities()
            .into_iter()
            .map(|c| c.as_str().to_string())
            .collect();
        candidates
            .iter()
            .filter(|c| actual.contains(*c))
            .cloned()
            .collect()
    }
}
