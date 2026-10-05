//! Adapt native slots through the same public registration/configuration boundary.
use super::{NativeRuntimeProvider, ProviderResult, RuntimeProviderVerifier, SourceClosure};
use crate::extensions::{
    ConfiguredExtension, ExtensionError, ExtensionErrorCode, ExtensionFactory, ExtensionInstance,
    ExtensionProvider, ExtensionRegistry, HostVerifier,
};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::sync::Arc;

struct NativeInstance {
    provider: Arc<dyn NativeRuntimeProvider>,
    id: String,
}
struct Provider {
    descriptor: Value,
    native: Arc<dyn NativeRuntimeProvider>,
}
fn invalid() -> ExtensionError {
    ExtensionError {
        code: ExtensionErrorCode::InvalidExtensionConfiguration,
        message: "invalid native provider configuration".into(),
    }
}
impl ExtensionProvider for Provider {
    fn descriptor(&self) -> Value {
        self.descriptor.clone()
    }
    fn validate_configuration(
        &self,
        configuration: &Value,
    ) -> Result<ExtensionInstance, ExtensionError> {
        if configuration != &json!({"instance_id":"runtime-slot"}) {
            return Err(invalid());
        }
        Ok(Arc::new(NativeInstance {
            provider: self.native.clone(),
            id: "runtime-slot".into(),
        }))
    }
    fn instance_id(&self, instance: &ExtensionInstance) -> Result<String, ExtensionError> {
        instance
            .downcast_ref::<NativeInstance>()
            .map(|instance| instance.id.clone())
            .ok_or_else(invalid)
    }
    fn capabilities(&self, instance: &ExtensionInstance) -> Result<Vec<String>, ExtensionError> {
        self.instance_id(instance)?;
        Ok(self.descriptor["supported_capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .map(|name| name.as_str().unwrap().to_owned())
            .collect())
    }
    fn health(&self, instance: &ExtensionInstance) -> Result<String, ExtensionError> {
        let instance = instance
            .downcast_ref::<NativeInstance>()
            .ok_or_else(invalid)?;
        Ok(if instance.provider.health() {
            "healthy"
        } else {
            "unavailable"
        }
        .into())
    }
}
struct Factory(Arc<dyn ExtensionProvider>);
impl ExtensionFactory for Factory {
    fn create(&self) -> Result<Arc<dyn ExtensionProvider>, ExtensionError> {
        Ok(self.0.clone())
    }
}
struct Verifier {
    factory: Arc<dyn ExtensionFactory>,
    provider: Arc<dyn ExtensionProvider>,
    native: Arc<dyn NativeRuntimeProvider>,
    runtime_descriptor: Value,
    common_descriptor: Value,
    closure: SourceClosure,
    policy: Arc<dyn RuntimeProviderVerifier>,
}
impl Verifier {
    fn current(&self) -> bool {
        self.closure.verify().is_ok()
            && self.closure.digest().ok().as_deref()
                == self.runtime_descriptor["binding"]["provider_reference"]["content_digest"]
                    .as_str()
            && self
                .policy
                .verify(
                    self.native.as_ref(),
                    &self.runtime_descriptor,
                    &self.closure,
                )
                .is_ok()
    }
}
impl HostVerifier for Verifier {
    fn verify_factory(&self, descriptor: &Value, factory: &Arc<dyn ExtensionFactory>) -> bool {
        descriptor == &self.common_descriptor
            && Arc::ptr_eq(factory, &self.factory)
            && self.current()
    }
    fn verify_source(
        &self,
        descriptor: &Value,
        factory: &Arc<dyn ExtensionFactory>,
        provider: &Arc<dyn ExtensionProvider>,
    ) -> bool {
        self.verify_factory(descriptor, factory) && Arc::ptr_eq(provider, &self.provider)
    }
    fn prove_claims(
        &self,
        descriptor: &Value,
        configuration: &Value,
        instance: &ExtensionInstance,
        health: &str,
        candidates: &[String],
    ) -> BTreeSet<String> {
        let Some(instance) = instance.downcast_ref::<NativeInstance>() else {
            return BTreeSet::new();
        };
        if descriptor != &self.common_descriptor
            || configuration != &json!({"instance_id":"runtime-slot"})
            || health != "healthy"
            || instance.id != "runtime-slot"
            || !Arc::ptr_eq(&instance.provider, &self.native)
            || !self.current()
        {
            return BTreeSet::new();
        }
        let proved = self
            .policy
            .verify(
                self.native.as_ref(),
                &self.runtime_descriptor,
                &self.closure,
            )
            .unwrap_or_default();
        candidates
            .iter()
            .filter(|name| proved.contains(*name))
            .cloned()
            .collect()
    }
}
pub(super) fn configure(
    descriptor: &Value,
    native: Arc<dyn NativeRuntimeProvider>,
    closure: SourceClosure,
    policy: Arc<dyn RuntimeProviderVerifier>,
) -> ProviderResult<(Arc<ExtensionRegistry>, ConfiguredExtension)> {
    let mut capabilities: Vec<_> = descriptor["binding"]["capabilities"]
        .as_object()
        .unwrap()
        .iter()
        .filter(|(_, value)| value == &&Value::Bool(true))
        .map(|(name, _)| name.clone())
        .collect();
    let category = if descriptor["kind"] == "compiler" {
        // Compiler operational guarantees are independently verified source claims;
        // the common compiler category currently advertises no capabilities.
        capabilities.clear();
        "compiler"
    } else {
        "runtime_provider"
    };
    let common_descriptor = json!({"category":category,"provider_reference":descriptor["binding"]["provider_reference"],"interface_version":1,"supported_capabilities":capabilities});
    let provider: Arc<dyn ExtensionProvider> = Arc::new(Provider {
        descriptor: common_descriptor.clone(),
        native: native.clone(),
    });
    let factory: Arc<dyn ExtensionFactory> = Arc::new(Factory(provider.clone()));
    let common = Arc::new(ExtensionRegistry::with_verifier(Arc::new(Verifier {
        factory: factory.clone(),
        provider,
        native,
        runtime_descriptor: descriptor.clone(),
        common_descriptor: common_descriptor.clone(),
        closure,
        policy,
    })));
    let map = |error: ExtensionError| super::Version1Error::new(error.code.as_str(), error.message);
    common
        .register(common_descriptor.clone(), factory)
        .map_err(map)?;
    let configured = common
        .validate_configuration(&common_descriptor, &json!({"instance_id":"runtime-slot"}))
        .map_err(map)?;
    Ok((common, configured))
}
