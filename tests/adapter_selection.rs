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
        Ok(self.descriptor["supported_capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_owned())
            .collect())
    }
    fn health(&self, _: &ExtensionInstance) -> Result<String, ExtensionError> {
        Ok(if self.healthy.load(Ordering::SeqCst)
            && self.store.health().is_ok_and(|health| health.healthy)
        {
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
    fn prove_host_features(
        &self,
        descriptor: &Value,
        configuration: &Value,
        instance: &ExtensionInstance,
        context: &str,
    ) -> BTreeSet<String> {
        // This observer is installed around the real native PostgreSQL store
        // and the production CheckpointHost already exercised by native gates.
        if descriptor["provider_reference"]["identifier"] == "test.observed-postgresql"
            && context == "general"
            && configuration == &json!({"instance_id":"native-memory"})
            && instance
                .downcast_ref::<Arc<dyn ExecutionStore>>()
                .is_some_and(|store| Arc::ptr_eq(store, &self.store))
            && self.store.health().is_ok_and(|health| health.healthy)
        {
            BTreeSet::from(["atomic_accept_process".into()])
        } else {
            BTreeSet::new()
        }
    }
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
struct ObservedRoots<T = MemoryExecutionStore> {
    inner: T,
    accesses: AtomicUsize,
}
impl<T: ExecutionStore + 'static> ExecutionStore for ObservedRoots<T> {
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
    let observed: Arc<ObservedRoots> = Arc::new(ObservedRoots::default());
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

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_native_schema_changes_invalidate_a_previously_verified_host() {
    use determa_state::checkpoint::{CheckpointHost, HostProfile};
    let registry = Arc::new(bundled_store_registry().unwrap());
    let path = std::env::temp_dir().join(format!(
        "determa-native-health-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let uri = format!(
        "sqlite:{}#receipt_retention=bounded&outbox_retention=bounded",
        path.display()
    );
    let config = json!({"instance_id":"sqlite-native","uri":uri});
    let descriptor = registry
        .descriptors()
        .unwrap()
        .into_iter()
        .find(|descriptor| descriptor["provider_reference"]["identifier"] == "determa.sqlite")
        .unwrap();
    let configured = registry
        .validate_configuration(&descriptor, &config)
        .unwrap();
    registry
        .bundled_execution_store(&configured)
        .unwrap()
        .initialize_schema()
        .unwrap();
    let binding = registry
        .resolve_execution_store(&uri, Some("sqlite"), &config, &json!([]))
        .unwrap();
    assert!(binding
        .current_capabilities()
        .unwrap()
        .contains(&ExecutionStoreCapability::DurableSingleWriter));
    let host = CheckpointHost::from_verified(
        binding,
        Arc::new(determa_state::InMemoryDefinitionResolver::default()),
    );
    assert!(host
        .validate_profile(HostProfile::DurableEmbeddedProcessing, false)
        .is_ok());
    assert_eq!(
        host.validate_profile(HostProfile::ExactlyOnceCommittedProcessing, true)
            .unwrap_err()
            .code,
        AdapterErrorCode::AdapterCapabilityMismatch
    );
    let native = rusqlite::Connection::open(&path).unwrap();
    let journal: String = native
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .unwrap();
    assert_eq!(journal, "wal");
    native
        .execute(
            "ALTER TABLE determa_execution_checkpoints ADD COLUMN unexpected TEXT",
            [],
        )
        .unwrap();
    assert_eq!(
        host.validate_profile(HostProfile::DurableEmbeddedProcessing, false)
            .unwrap_err()
            .code,
        AdapterErrorCode::AdapterCapabilityMismatch
    );
    let roots: i64 = native
        .query_row(
            "SELECT COUNT(*) FROM determa_execution_checkpoints",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(roots, 0);
    for invalid in [
        "sqlite::memory:#receipt_retention=bounded&outbox_retention=bounded",
        "sqlite:relative.sqlite#receipt_retention=bounded&outbox_retention=bounded",
        "sqlite:/tmp/not-created.sqlite#receipt_retention=bounded&outbox_retention=bounded&synchronous=off",
    ] {
        let config = json!({"instance_id":"bad","uri":invalid});
        assert!(registry
            .resolve_execution_store(
                invalid,
                Some("sqlite"),
                &config,
                &json!(["durable_single_writer"])
            )
            .is_err());
    }
}

#[cfg(feature = "postgresql")]
#[test]
fn incompatible_live_postgresql_health_refuses_public_host_before_root_access() {
    use determa_state::checkpoint::{
        CheckpointHost, DurableStoreMode, HostProfile, PostgresqlExecutionStore,
    };
    let Ok(base_url) = std::env::var("DETERMA_TEST_POSTGRES_URL") else {
        return;
    };
    let schema = format!(
        "determa_observed_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let mut native = postgres::Client::connect(&base_url, postgres::NoTls).unwrap();
    native
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .unwrap();
    let separator = if base_url.contains('?') { '&' } else { '?' };
    let url = format!("{base_url}{separator}options=-c%20search_path%3D{schema}");
    let concrete =
        PostgresqlExecutionStore::connect_no_tls(&url, DurableStoreMode::bounded()).unwrap();
    concrete.initialize_schema().unwrap();
    let observed = Arc::new(ObservedRoots {
        inner: concrete,
        accesses: AtomicUsize::new(0),
    });
    observed.load("observer-self-check").unwrap();
    assert_eq!(observed.accesses.swap(0, Ordering::SeqCst), 1);
    let store: Arc<dyn ExecutionStore> = observed.clone();
    let descriptor = json!({"category":"execution_store","provider_reference":{"identifier":"test.observed-postgresql","version":"1.0.0","content_digest":format!("sha256:{}", "b".repeat(64))},"interface_version":1,"supported_capabilities":["ephemeral","durable_concurrent","root_identity_retention"]});
    // The trusted test verifier binds this compiled provider to this precise
    // observed native store. Its health comes from the real PostgreSQL session.
    let provider: Arc<dyn ExtensionProvider> = Arc::new(Provider {
        descriptor: descriptor.clone(),
        store: store.clone(),
        healthy: Arc::new(AtomicBool::new(true)),
    });
    let factory: Arc<dyn ExtensionFactory> =
        Arc::new(Factory(provider.clone(), Arc::new(AtomicUsize::new(0))));
    let registry = Arc::new(ExtensionRegistry::with_verifier(Arc::new(Verifier {
        factory: factory.clone(),
        provider,
        store,
    })));
    registry.register(descriptor.clone(), factory).unwrap();
    let binding = registry
        .configure_execution_store(&descriptor, &json!({"instance_id":"native-memory"}))
        .unwrap();
    let host = CheckpointHost::from_verified(
        binding,
        Arc::new(determa_state::InMemoryDefinitionResolver::default()),
    );
    assert!(host
        .validate_profile(HostProfile::DurableEmbeddedProcessing, false)
        .is_ok());
    assert_eq!(observed.accesses.load(Ordering::SeqCst), 0);
    native
        .batch_execute(&format!(
            "ALTER TABLE {schema}.determa_execution_checkpoints ADD COLUMN unexpected TEXT"
        ))
        .unwrap();
    assert_eq!(
        host.validate_profile(HostProfile::DurableEmbeddedProcessing, false)
            .unwrap_err()
            .code,
        AdapterErrorCode::AdapterCapabilityMismatch
    );
    assert_eq!(observed.accesses.load(Ordering::SeqCst), 0);
}
