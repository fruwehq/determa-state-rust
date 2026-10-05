use determa_state::checkpoint::{
    AdapterErrorCode, ExecutionStore, ExecutionStoreCapability, MemoryExecutionStore,
};
use determa_state::extensions::{
    bundled_store_registry, ExtensionError, ExtensionFactory, ExtensionInstance, ExtensionProvider,
    ExtensionRegistry, HostVerifier,
};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};

struct Provider {
    descriptor: Value,
    store: Arc<dyn ExecutionStore>,
    healthy: Arc<AtomicBool>,
}
impl ExtensionProvider for Provider {
    fn descriptor(&self) -> Value {
        self.descriptor.clone()
    }
    fn validate_configuration(&self, _: &Value) -> Result<ExtensionInstance, ExtensionError> {
        Ok(Arc::new(self.store.clone()))
    }
    fn instance_id(&self, _: &ExtensionInstance) -> Result<String, ExtensionError> {
        Ok("native-memory".into())
    }
    fn capabilities(&self, _: &ExtensionInstance) -> Result<Vec<String>, ExtensionError> {
        // Deliberately overstate a candidate: the verifier must not promote it.
        Ok(vec!["ephemeral".into(), "durable_concurrent".into()])
    }
    fn health(&self, _: &ExtensionInstance) -> Result<String, ExtensionError> {
        Ok(if self.healthy.load(Ordering::SeqCst) {
            "healthy"
        } else {
            "unavailable"
        }
        .into())
    }
}
struct Factory(Arc<dyn ExtensionProvider>, Arc<AtomicUsize>);
impl ExtensionFactory for Factory {
    fn create(&self) -> Result<Arc<dyn ExtensionProvider>, ExtensionError> {
        self.1.fetch_add(1, Ordering::SeqCst);
        Ok(self.0.clone())
    }
}
struct Verifier {
    factory: Arc<dyn ExtensionFactory>,
    provider: Arc<dyn ExtensionProvider>,
    store: Arc<dyn ExecutionStore>,
}
impl HostVerifier for Verifier {
    fn verify_factory(&self, _: &Value, factory: &Arc<dyn ExtensionFactory>) -> bool {
        Arc::ptr_eq(factory, &self.factory)
    }
    fn verify_source(
        &self,
        _: &Value,
        factory: &Arc<dyn ExtensionFactory>,
        provider: &Arc<dyn ExtensionProvider>,
    ) -> bool {
        Arc::ptr_eq(factory, &self.factory) && Arc::ptr_eq(provider, &self.provider)
    }
    fn prove_claims(
        &self,
        _: &Value,
        configuration: &Value,
        instance: &ExtensionInstance,
        health: &str,
        _: &[String],
    ) -> BTreeSet<String> {
        if health != "healthy"
            || configuration != &json!({"instance_id":"native-memory"})
            || !instance
                .downcast_ref::<Arc<dyn ExecutionStore>>()
                .is_some_and(|store| Arc::ptr_eq(store, &self.store))
        {
            return BTreeSet::new();
        }
        self.store
            .capabilities()
            .iter()
            .map(|capability| capability.as_str().into())
            .collect()
    }
}

#[test]
fn generic_vendor_selection_uses_native_proof_and_preserves_first_registration() {
    let descriptor = json!({"category":"execution_store","provider_reference":{"identifier":"test.vendor-memory","version":"1.0.0","content_digest":format!("sha256:{}", "a".repeat(64))},"interface_version":1,"supported_capabilities":["ephemeral","durable_concurrent"]});
    let registration = json!({"adapter_identifier":"vendor-memory","uri_scheme":"vendor+https","source":"third_party","configuration_schema":{"type":"object","properties":{"instance_id":{"const":"native-memory"}},"required":["instance_id"],"additionalProperties":false},"capabilities":["ephemeral","durable_concurrent"]});
    let store: Arc<dyn ExecutionStore> = Arc::new(MemoryExecutionStore::new());
    let healthy = Arc::new(AtomicBool::new(true));
    let provider: Arc<dyn ExtensionProvider> = Arc::new(Provider {
        descriptor: descriptor.clone(),
        store: store.clone(),
        healthy: healthy.clone(),
    });
    let calls = Arc::new(AtomicUsize::new(0));
    let factory: Arc<dyn ExtensionFactory> = Arc::new(Factory(provider.clone(), calls.clone()));
    let registry = Arc::new(ExtensionRegistry::with_verifier(Arc::new(Verifier {
        factory: factory.clone(),
        provider,
        store: store.clone(),
    })));
    let mut invalid_registration = registration.clone();
    invalid_registration["configuration_schema"] = json!(true);
    assert_eq!(
        registry
            .register_store_adapter(invalid_registration, descriptor.clone(), factory.clone())
            .unwrap_err()
            .code,
        AdapterErrorCode::InvalidAdapterConfiguration
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    registry
        .register_store_adapter(registration.clone(), descriptor.clone(), factory.clone())
        .unwrap();
    assert_eq!(
        registry
            .register_store_adapter(registration, descriptor, factory)
            .unwrap_err()
            .code,
        AdapterErrorCode::DuplicateAdapterRegistration
    );
    let configuration = json!({"instance_id":"native-memory"});
    assert_eq!(
        registry
            .resolve_execution_store("unknown://store", None, &configuration, &json!([]))
            .err()
            .unwrap()
            .code,
        AdapterErrorCode::UnknownAdapter
    );
    assert_eq!(
        registry
            .resolve_execution_store(
                "vendor+https://store",
                None,
                &json!({"instance_id":7}),
                &json!([])
            )
            .err()
            .unwrap()
            .code,
        AdapterErrorCode::InvalidAdapterConfiguration
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let binding = registry
        .resolve_execution_store(
            "vendor+https://store",
            Some("vendor-memory"),
            &configuration,
            &json!(["ephemeral"]),
        )
        .unwrap();
    assert!(Arc::ptr_eq(&binding.store(), &store));
    assert_eq!(
        binding.current_capabilities().unwrap(),
        BTreeSet::from([ExecutionStoreCapability::Ephemeral])
    );
    assert_eq!(
        registry
            .resolve_execution_store(
                "vendor+https://store",
                None,
                &configuration,
                &json!(["durable_concurrent"])
            )
            .err()
            .unwrap()
            .code,
        AdapterErrorCode::AdapterCapabilityMismatch
    );
    healthy.store(false, Ordering::SeqCst);
    assert!(binding.current_capabilities().is_err());
    assert_eq!(
        registry
            .resolve_execution_store(
                "vendor+https://store",
                None,
                &configuration,
                &json!(["ephemeral"])
            )
            .err()
            .unwrap()
            .code,
        AdapterErrorCode::AdapterCapabilityMismatch
    );
}

#[test]
fn bundled_uri_selection_uses_the_same_public_registry_and_native_memory_claim() {
    let registry = Arc::new(bundled_store_registry().unwrap());
    let configuration = json!({"instance_id":"memory-native","uri":"memory:"});
    let binding = registry
        .resolve_execution_store(
            "memory:",
            Some("memory"),
            &configuration,
            &json!(["ephemeral"]),
        )
        .unwrap();
    assert_eq!(
        binding.current_capabilities().unwrap(),
        BTreeSet::from([ExecutionStoreCapability::Ephemeral])
    );
    assert_eq!(
        registry
            .resolve_execution_store("memory:", Some("file"), &configuration, &json!([]))
            .err()
            .unwrap()
            .code,
        AdapterErrorCode::UnknownAdapter
    );
    assert_eq!(
        registry
            .resolve_execution_store(
                "memory:",
                None,
                &configuration,
                &json!(["durable_single_writer"])
            )
            .err()
            .unwrap()
            .code,
        AdapterErrorCode::AdapterCapabilityMismatch
    );
}

#[derive(Default)]
struct ObservedRoots {
    inner: MemoryExecutionStore,
    accesses: AtomicUsize,
}
impl ExecutionStore for ObservedRoots {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn capabilities(&self) -> BTreeSet<ExecutionStoreCapability> {
        self.inner.capabilities()
    }
    fn initialize_schema(&self) -> Result<(), determa_state::checkpoint::StoreError> {
        self.inner.initialize_schema()
    }
    fn health(
        &self,
    ) -> Result<determa_state::checkpoint::HealthStatus, determa_state::checkpoint::StoreError>
    {
        self.inner.health()
    }
    fn load(
        &self,
        root: &str,
    ) -> Result<Option<determa_state::checkpoint::StoreRecord>, determa_state::checkpoint::StoreError>
    {
        self.accesses.fetch_add(1, Ordering::SeqCst);
        self.inner.load(root)
    }
    fn insert_if_absent(
        &self,
        record: determa_state::checkpoint::StoreRecord,
    ) -> Result<determa_state::checkpoint::StoreWriteResult, determa_state::checkpoint::StoreError>
    {
        self.accesses.fetch_add(1, Ordering::SeqCst);
        self.inner.insert_if_absent(record)
    }
    fn compare_and_swap(
        &self,
        root: &str,
        revision: &str,
        digest: &str,
        record: determa_state::checkpoint::StoreRecord,
    ) -> Result<determa_state::checkpoint::StoreWriteResult, determa_state::checkpoint::StoreError>
    {
        self.accesses.fetch_add(1, Ordering::SeqCst);
        self.inner.compare_and_swap(root, revision, digest, record)
    }
}

#[test]
fn substituted_factory_and_copied_claims_fail_before_observed_root_access() {
    use determa_state::checkpoint::{CheckpointHost, HostProfile};
    let descriptor = json!({"category":"execution_store","provider_reference":{"identifier":"test.observed-memory","version":"1.0.0","content_digest":format!("sha256:{}", "a".repeat(64))},"interface_version":1,"supported_capabilities":["ephemeral","durable_concurrent"]});
    let observed = Arc::new(ObservedRoots::default());
    observed.load("observer-self-check").unwrap();
    assert_eq!(observed.accesses.swap(0, Ordering::SeqCst), 1);
    let store: Arc<dyn ExecutionStore> = observed.clone();
    let provider: Arc<dyn ExtensionProvider> = Arc::new(Provider {
        descriptor: descriptor.clone(),
        store: store.clone(),
        healthy: Arc::new(AtomicBool::new(true)),
    });
    let calls = Arc::new(AtomicUsize::new(0));
    let factory: Arc<dyn ExtensionFactory> = Arc::new(Factory(provider.clone(), calls.clone()));
    let verifier = Arc::new(Verifier {
        factory: factory.clone(),
        provider: provider.clone(),
        store,
    });
    let wrong_factory: Arc<dyn ExtensionFactory> = Arc::new(Factory(provider, calls.clone()));
    let untrusted = Arc::new(ExtensionRegistry::with_verifier(verifier.clone()));
    untrusted
        .register(descriptor.clone(), wrong_factory)
        .unwrap();
    // Identical descriptor and digest do not identify the trusted compiled factory.
    assert!(untrusted
        .configure_execution_store(&descriptor, &json!({"instance_id":"native-memory"}))
        .is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(observed.accesses.load(Ordering::SeqCst), 0);

    let registry = Arc::new(ExtensionRegistry::with_verifier(verifier));
    registry.register(descriptor.clone(), factory).unwrap();
    let binding = registry
        .configure_execution_store(&descriptor, &json!({"instance_id":"native-memory"}))
        .unwrap();
    let host = CheckpointHost::from_verified(
        binding,
        Arc::new(determa_state::InMemoryDefinitionResolver::default()),
    );
    for caller_claims in [
        vec!["durable_concurrent".into()],
        vec!["verified".into(), "trusted".into()],
    ] {
        let returned = host.validate_capabilities_contract(
            "observed-memory",
            HostProfile::ExactlyOnceCommittedProcessing,
            &BTreeSet::new(),
            &caller_claims,
            &[],
            true,
        );
        assert_eq!(
            returned.result.code.as_deref(),
            Some("adapter_capability_mismatch")
        );
        assert_eq!(observed.accesses.load(Ordering::SeqCst), 0);
    }
}
