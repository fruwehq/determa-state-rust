//! Normative common-rule vectors exercised through the production registry API.
//! `hypothetical_verification` is a test-only host proof premise, never a
//! production input or provider assertion.
use determa_state::extensions::{
    ExtensionError, ExtensionErrorCode, ExtensionFactory, ExtensionProvider, ExtensionRegistry,
    HostVerifier, ProfileRequest,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::any::Any;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

type Instance = Arc<dyn Any + Send + Sync>;
struct TestProvider(Value);
impl ExtensionProvider for TestProvider {
    fn descriptor(&self) -> Value {
        self.0.clone()
    }
    fn validate_configuration(&self, configuration: &Value) -> Result<Instance, ExtensionError> {
        let o = configuration.as_object().ok_or_else(invalid_config)?;
        if o.len() != 3
            || !o.contains_key("instance_id")
            || !o.contains_key("claims")
            || !o.contains_key("health")
        {
            return Err(invalid_config());
        }
        Ok(Arc::new(configuration.clone()))
    }
    fn instance_id(&self, instance: &Instance) -> Result<String, ExtensionError> {
        Ok(instance
            .downcast_ref::<Value>()
            .and_then(|v| v["instance_id"].as_str())
            .ok_or_else(invalid_config)?
            .into())
    }
    fn capabilities(&self, instance: &Instance) -> Result<Vec<String>, ExtensionError> {
        instance
            .downcast_ref::<Value>()
            .and_then(|v| v["claims"].as_array())
            .ok_or_else(invalid_config)?
            .iter()
            .map(|v| v.as_str().map(str::to_owned).ok_or_else(invalid_config))
            .collect::<Result<_, _>>()
    }
    fn health(&self, instance: &Instance) -> Result<String, ExtensionError> {
        Ok(instance
            .downcast_ref::<Value>()
            .and_then(|v| v["health"].as_str())
            .ok_or_else(invalid_config)?
            .into())
    }
}
fn invalid_config() -> ExtensionError {
    ExtensionError {
        code: ExtensionErrorCode::InvalidExtensionConfiguration,
        message: "invalid test configuration".into(),
    }
}
struct TestFactory(Value);
impl ExtensionFactory for TestFactory {
    fn create(&self) -> Result<Arc<dyn ExtensionProvider>, ExtensionError> {
        Ok(Arc::new(TestProvider(self.0.clone())))
    }
}
struct PremiseVerifier {
    proofs: Vec<Value>,
    host: BTreeMap<String, bool>,
}
impl HostVerifier for PremiseVerifier {
    fn verify_factory(&self, _descriptor: &Value, _factory: &Arc<dyn ExtensionFactory>) -> bool {
        true
    }
    fn host_guarantees(&self) -> BTreeMap<String, bool> {
        self.host.clone()
    }
    fn verify_source(
        &self,
        _descriptor: &Value,
        _factory: &Arc<dyn ExtensionFactory>,
        _provider: &Arc<dyn ExtensionProvider>,
    ) -> bool {
        true
    }
    fn prove_claims(
        &self,
        descriptor: &Value,
        configuration: &Value,
        _instance: &Instance,
        _health: &str,
        _candidates: &[String],
    ) -> BTreeSet<String> {
        let bytes = serde_json::to_vec(configuration).unwrap();
        let digest = format!("sha256:{:x}", Sha256::digest(bytes));
        self.proofs
            .iter()
            .find(|p| {
                p["category"] == descriptor["category"]
                    && p["provider_reference"] == descriptor["provider_reference"]
                    && p["instance_id"] == configuration["instance_id"]
                    && p["configuration_digest"] == digest
            })
            .and_then(|p| p["claims"].as_array())
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect()
    }
}
#[test]
fn all_common_extension_vectors() {
    let manifest: Value = serde_json::from_str(include_str!(
        "../conformance-suite/conformance/profiles/extension-negotiation/vectors.generated.json"
    ))
    .unwrap();
    assert_eq!(manifest["vectors"].as_array().unwrap().len(), 26);
    for vector in manifest["vectors"].as_array().unwrap() {
        let proofs = vector["hypothetical_verification"]["proofs"]
            .as_array()
            .unwrap()
            .clone();
        let host: BTreeMap<String, bool> =
            serde_json::from_value(vector["hypothetical_verification"]["host_guarantees"].clone())
                .unwrap();
        let registry = ExtensionRegistry::with_verifier(Arc::new(PremiseVerifier { proofs, host }));
        let execute = || -> Result<Value, ExtensionError> {
            for (index, descriptor) in vector["registrations"]
                .as_array()
                .unwrap()
                .iter()
                .enumerate()
            {
                let bytes = vector["registration_bytes"][index]
                    .as_str()
                    .unwrap()
                    .as_bytes();
                assert_eq!(serde_json::from_slice::<Value>(bytes).unwrap(), *descriptor);
                registry.register_bytes(bytes, Arc::new(TestFactory(descriptor.clone())))?;
            }
            let configs = vector["configurations"]
                .as_array()
                .unwrap()
                .iter()
                .map(|c| {
                    (
                        c["category"].as_str().unwrap().into(),
                        c["provider_reference"].clone(),
                        c["configuration"].clone(),
                    )
                })
                .collect::<Vec<_>>();
            let requirements = vector["requirements"].as_array().unwrap().clone();
            let operation = &vector["operation"];
            let projection = operation["projection"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_owned())
                .collect::<Vec<_>>();
            registry.evaluate_profile(ProfileRequest {
                configurations: &configs,
                requirements: &requirements,
                compose: operation["kind"] == "compose",
                projection: &projection,
                requested_profile: operation["requested_profile"].as_str(),
                weak_profile_opt_in: vector["hypothetical_verification"]["weak_profile_opt_in"]
                    == true,
            })
        };
        let observed = match execute() {
            Ok(value) => value,
            Err(error) => json!({"status":"rejected", "code":error.code.as_str()}),
        };
        assert_eq!(observed, vector["expected"], "{}", vector["id"]);
        assert_eq!(vector["expected_core_mutations"], 0);
    }
}

#[path = "../conformance-suite/conformance/profiles/extension-negotiation/provider/test_provider.rs"]
#[rustfmt::skip]
mod source_provider;

struct PublicSourceProvider(Value);
fn public_descriptor(registration: &Value, digest: &str) -> Value {
    if let Some(items) = registration.as_array() {
        return items[0].clone();
    }
    if registration.is_object() {
        return registration.clone();
    }
    json!({"category":"execution_store","provider_reference":{"identifier":"conformance.provider","version":"1.0.0","content_digest":digest},"interface_version":1,"supported_capabilities":["durable_single_writer"]})
}
impl ExtensionProvider for PublicSourceProvider {
    fn descriptor(&self) -> Value {
        self.0.clone()
    }
    fn validate_configuration(&self, configuration: &Value) -> Result<Instance, ExtensionError> {
        let obj = configuration.as_object().ok_or_else(invalid_config)?;
        if obj.len() != 3
            || !obj.contains_key("instance_id")
            || !obj.contains_key("claims")
            || !obj.contains_key("health")
        {
            return Err(invalid_config());
        }
        let typed = source_provider::Configuration {
            instance_id: obj["instance_id"]
                .as_str()
                .ok_or_else(invalid_config)?
                .into(),
            claims: obj["claims"]
                .as_array()
                .ok_or_else(invalid_config)?
                .iter()
                .map(|v| v.as_str().map(str::to_owned).ok_or_else(invalid_config))
                .collect::<Result<_, _>>()?,
            health: obj["health"].as_str().ok_or_else(invalid_config)?.into(),
        };
        Ok(Arc::new(
            source_provider::validate_configuration(&typed).map_err(|_| invalid_config())?,
        ))
    }
    fn instance_id(&self, instance: &Instance) -> Result<String, ExtensionError> {
        Ok(instance
            .downcast_ref::<source_provider::Configuration>()
            .ok_or_else(invalid_config)?
            .instance_id
            .clone())
    }
    fn capabilities(&self, instance: &Instance) -> Result<Vec<String>, ExtensionError> {
        Ok(source_provider::capabilities(
            instance
                .downcast_ref::<source_provider::Configuration>()
                .ok_or_else(invalid_config)?,
        ))
    }
    fn health(&self, instance: &Instance) -> Result<String, ExtensionError> {
        Ok(source_provider::health(
            instance
                .downcast_ref::<source_provider::Configuration>()
                .ok_or_else(invalid_config)?,
        ))
    }
}
struct PublicSourceFactory(Arc<dyn ExtensionProvider>);
impl ExtensionFactory for PublicSourceFactory {
    fn create(&self) -> Result<Arc<dyn ExtensionProvider>, ExtensionError> {
        Ok(self.0.clone())
    }
}
struct PublicSourceVerifier {
    digest: String,
    provider: Arc<dyn ExtensionProvider>,
    factory: Mutex<Option<Arc<dyn ExtensionFactory>>>,
}
impl HostVerifier for PublicSourceVerifier {
    fn verify_factory(&self, descriptor: &Value, factory: &Arc<dyn ExtensionFactory>) -> bool {
        descriptor["provider_reference"]["content_digest"] == self.digest
            && self
                .factory
                .lock()
                .unwrap()
                .as_ref()
                .is_some_and(|known| Arc::ptr_eq(known, factory))
    }
    fn verify_source(
        &self,
        descriptor: &Value,
        _factory: &Arc<dyn ExtensionFactory>,
        provider: &Arc<dyn ExtensionProvider>,
    ) -> bool {
        descriptor["provider_reference"]["content_digest"] == self.digest
            && Arc::ptr_eq(provider, &self.provider)
    }
    fn prove_claims(
        &self,
        _descriptor: &Value,
        _configuration: &Value,
        _instance: &Instance,
        _health: &str,
        _candidates: &[String],
    ) -> BTreeSet<String> {
        BTreeSet::new()
    }
}
fn public_source_digest() -> String {
    let mut digest = Sha256::new();
    digest.update(b"determa-test-provider-closure-1\0");
    let files: [(&str, &[u8]);2] = [
        ("provider/test_provider.py", include_bytes!("../conformance-suite/conformance/profiles/extension-negotiation/provider/test_provider.py")),
        ("provider/test_provider.rs", include_bytes!("../conformance-suite/conformance/profiles/extension-negotiation/provider/test_provider.rs")),
    ];
    for (relative, compiled) in files {
        let path = format!(
            "{}/conformance-suite/conformance/profiles/extension-negotiation/{}",
            env!("CARGO_MANIFEST_DIR"),
            relative
        );
        assert_eq!(
            std::fs::read(path).unwrap(),
            compiled,
            "loaded source changed since compilation"
        );
        digest.update((relative.len() as u64).to_be_bytes());
        digest.update(relative.as_bytes());
        digest.update((compiled.len() as u64).to_be_bytes());
        digest.update(compiled);
    }
    format!("sha256:{:x}", digest.finalize())
}
fn observed_result<T>(
    result: Result<T, ExtensionError>,
    success: impl FnOnce(T) -> Value,
) -> Value {
    match result {
        Ok(value) => success(value),
        Err(error) => json!({"status":"rejected","code":error.code.as_str()}),
    }
}
#[test]
fn all_public_extension_vectors_use_compiled_provider() {
    let manifest: Value = serde_json::from_str(include_str!(
        "../conformance-suite/conformance/profiles/extension-negotiation/vectors.generated.json"
    ))
    .unwrap();
    assert_eq!(manifest["public_vectors"].as_array().unwrap().len(), 21);
    let digest = public_source_digest();
    assert_eq!(digest, manifest["provider_closure"]["content_digest"]);
    for vector in manifest["public_vectors"].as_array().unwrap() {
        let provider: Arc<dyn ExtensionProvider> = Arc::new(PublicSourceProvider(
            public_descriptor(&vector["registration"], &digest),
        ));
        let verifier = Arc::new(PublicSourceVerifier {
            digest: digest.clone(),
            provider: provider.clone(),
            factory: Mutex::new(None),
        });
        let registry = ExtensionRegistry::with_verifier(verifier.clone());
        let mut stages = Vec::new();
        let mut final_decision = json!({"status":"accepted"});
        let register_bytes = vector["registration_bytes"].as_array().unwrap();
        for bytes in register_bytes {
            let operation = if vector["installation"] == "direct_injection" {
                "direct_injection"
            } else {
                "register"
            };
            let input = bytes.as_str().unwrap();
            let result = if operation == "direct_injection" {
                registry.inject(serde_json::from_str(input).unwrap(), provider.clone())
            } else {
                let factory: Arc<dyn ExtensionFactory> =
                    Arc::new(PublicSourceFactory(provider.clone()));
                *verifier.factory.lock().unwrap() = Some(factory.clone());
                registry.register_bytes(input.as_bytes(), factory)
            };
            let output = observed_result(result, |_| json!({"status":"accepted","value":null}));
            stages.push(json!({"operation":operation,"input":input,"output":output}));
            if output["status"] == "rejected" {
                final_decision = output;
                break;
            }
        }
        if final_decision["status"] != "rejected" && !vector["configuration"].is_null() {
            let descriptor = &vector["registration"];
            let configuration = &vector["configuration"];
            let configured = registry.validate_configuration(descriptor, configuration);
            let (output, configured) = match configured {
                Ok(handle) => (json!({"status":"accepted","value":null}), Some(handle)),
                Err(error) => (
                    json!({"status":"rejected","code":error.code.as_str()}),
                    None,
                ),
            };
            stages.push(
                json!({"operation":"validate_configuration","input":configuration,"output":output}),
            );
            if let Some(handle) = configured {
                let claims = registry.capabilities(&handle).unwrap();
                stages.push(json!({"operation":"capabilities","input":configuration["instance_id"],"output":claims}));
                let health = registry.health(&handle).unwrap();
                stages.push(json!({"operation":"health","input":configuration["instance_id"],"output":health}));
            } else {
                final_decision = output;
            }
        }
        if final_decision["status"] != "rejected" {
            let requirement = &vector["requirement"];
            let result = if vector["configuration"].is_null() {
                registry
                    .evaluate_profile(ProfileRequest {
                        configurations: &[],
                        requirements: std::slice::from_ref(requirement),
                        compose: false,
                        projection: &[],
                        requested_profile: None,
                        weak_profile_opt_in: false,
                    })
                    .map(|_| json!({"status":"accepted"}))
            } else {
                registry
                    .negotiate(
                        &vector["registration"],
                        &vector["configuration"],
                        if requirement.is_null() {
                            None
                        } else {
                            Some(requirement)
                        },
                    )
                    .map(|report| json!({"status":"accepted","report":report}))
            };
            final_decision = observed_result(result, |v| v);
            stages.push(json!({"operation":"negotiate","input":{"requirement":requirement,"lookup_uri":vector["lookup_uri"]},"output":final_decision}));
        }
        assert_eq!(
            json!(stages),
            vector["expected_stages"],
            "stages: {}",
            vector["id"]
        );
        assert_eq!(
            final_decision, vector["expected"],
            "decision: {}",
            vector["id"]
        );
        assert_eq!(vector["expected_core_mutations"], 0);
    }
}

#[test]
fn bundled_stores_are_bound_to_public_registration_and_current_native_health() {
    let registry = determa_state::extensions::bundled_store_registry().unwrap();
    let descriptors = registry.descriptors().unwrap();
    let names = descriptors
        .iter()
        .map(|d| d["provider_reference"]["identifier"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert!(names.contains("determa.memory"));
    assert!(names.contains("determa.file"));
    #[cfg(feature = "sqlite")]
    assert!(names.contains("determa.sqlite"));
    #[cfg(feature = "postgresql")]
    assert!(names.contains("determa.postgresql"));
    let memory = descriptors
        .iter()
        .find(|d| d["provider_reference"]["identifier"] == "determa.memory")
        .unwrap();
    let config = json!({"instance_id":"primary","uri":"memory:"});
    let requirement = json!({"category":"execution_store","provider_reference":memory["provider_reference"],"instance_id":"primary","capability":"ephemeral"});
    let handle = registry.validate_configuration(memory, &config).unwrap();
    assert_eq!(registry.capabilities(&handle).unwrap(), vec!["ephemeral"]);
    assert_eq!(registry.health(&handle).unwrap(), "healthy");
    let store = registry.bundled_execution_store(&handle).unwrap();
    assert!(store
        .as_any()
        .is::<determa_state::checkpoint::MemoryExecutionStore>());
    assert_eq!(
        registry
            .negotiate(memory, &config, Some(&requirement))
            .unwrap()["claims"],
        json!(["ephemeral"])
    );
    let foreign = determa_state::extensions::bundled_store_registry().unwrap();
    assert_eq!(
        foreign.native_instance(&handle).err().unwrap().code,
        ExtensionErrorCode::ExtensionIdentityMismatch
    );
    let wrong_config = json!({"instance_id":"primary","uri":"file:/tmp/unrelated"});
    assert_eq!(
        registry
            .validate_configuration(memory, &wrong_config)
            .err()
            .unwrap()
            .code,
        ExtensionErrorCode::InvalidExtensionConfiguration
    );
    let wrong_requirement = json!({"category":"execution_store","provider_reference":memory["provider_reference"],"instance_id":"other","capability":"ephemeral"});
    assert_eq!(
        registry
            .negotiate(memory, &config, Some(&wrong_requirement))
            .err()
            .unwrap()
            .code,
        ExtensionErrorCode::ExtensionCapabilityMismatch
    );
    let mut clone = memory.clone();
    clone["provider_reference"]["content_digest"] = json!(format!("sha256:{}", "f".repeat(64)));
    assert_eq!(
        registry
            .validate_configuration(&clone, &config)
            .err()
            .unwrap()
            .code,
        ExtensionErrorCode::ExtensionIdentityMismatch
    );
}

#[test]
fn verified_but_unproved_provider_remains_usable_without_capability_claims() {
    let manifest: Value = serde_json::from_str(include_str!(
        "../conformance-suite/conformance/profiles/extension-negotiation/vectors.generated.json"
    ))
    .unwrap();
    let descriptor = manifest["public_vectors"][0]["registration"].clone();
    let configuration = manifest["public_vectors"][0]["configuration"].clone();
    let provider: Arc<dyn ExtensionProvider> = Arc::new(PublicSourceProvider(descriptor.clone()));
    let registry = ExtensionRegistry::with_verifier(Arc::new(PublicSourceVerifier {
        digest: public_source_digest(),
        provider: provider.clone(),
        factory: Mutex::new(None),
    }));
    registry.inject(descriptor.clone(), provider).unwrap();
    let handle = registry
        .validate_configuration(&descriptor, &configuration)
        .unwrap();
    assert!(registry
        .native_instance(&handle)
        .unwrap()
        .downcast_ref::<source_provider::Configuration>()
        .is_some());
    assert_eq!(registry.report(&handle).unwrap()["claims"], json!([]));
    let required = json!({"category":"execution_store","provider_reference":descriptor["provider_reference"],"instance_id":"primary","capability":"durable_single_writer"});
    assert_eq!(
        registry
            .negotiate(&descriptor, &configuration, Some(&required))
            .err()
            .unwrap()
            .code,
        ExtensionErrorCode::ExtensionCapabilityMismatch
    );
    let untrusted = ExtensionRegistry::new();
    untrusted
        .inject(
            descriptor.clone(),
            Arc::new(PublicSourceProvider(descriptor.clone())),
        )
        .unwrap();
    assert_eq!(
        untrusted
            .validate_configuration(&descriptor, &configuration)
            .err()
            .unwrap()
            .code,
        ExtensionErrorCode::ExtensionIdentityMismatch
    );
}

/// Adapter used by the official process runner. Inputs contain no case IDs or
/// expected observations; all decisions come from the public registry.
pub fn observe_extension_profile(request: &Value) -> Value {
    let input = &request["input"];
    if request["mode"] == "common_rule" {
        let proofs = input["hypothetical_verification"]["proofs"]
            .as_array()
            .unwrap()
            .clone();
        let host: BTreeMap<String, bool> =
            serde_json::from_value(input["hypothetical_verification"]["host_guarantees"].clone())
                .unwrap();
        let registry = ExtensionRegistry::with_verifier(Arc::new(PremiseVerifier { proofs, host }));
        let decision = (|| -> Result<Value, ExtensionError> {
            for bytes in input["registration_bytes"].as_array().unwrap() {
                let descriptor: Value = serde_json::from_str(bytes.as_str().unwrap()).unwrap();
                registry.register_bytes(
                    bytes.as_str().unwrap().as_bytes(),
                    Arc::new(TestFactory(descriptor)),
                )?;
            }
            let configs = input["configurations"]
                .as_array()
                .unwrap()
                .iter()
                .map(|c| {
                    (
                        c["category"].as_str().unwrap().into(),
                        c["provider_reference"].clone(),
                        c["configuration"].clone(),
                    )
                })
                .collect::<Vec<_>>();
            let requirements = input["requirements"].as_array().unwrap().clone();
            let projection = input["operation"]["projection"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_owned())
                .collect::<Vec<_>>();
            registry.evaluate_profile(ProfileRequest {
                configurations: &configs,
                requirements: &requirements,
                compose: input["operation"]["kind"] == "compose",
                projection: &projection,
                requested_profile: input["operation"]["requested_profile"].as_str(),
                weak_profile_opt_in: input["hypothetical_verification"]["weak_profile_opt_in"]
                    == true,
            })
        })();
        return json!({"decision":observed_result(decision,|v|v),"core_mutations":0});
    }
    let digest = public_source_digest();
    assert_eq!(digest, request["provider_closure"]["content_digest"]);
    let provider: Arc<dyn ExtensionProvider> = Arc::new(PublicSourceProvider(public_descriptor(
        &input["registration"],
        &digest,
    )));
    let verifier = Arc::new(PublicSourceVerifier {
        digest: digest.clone(),
        provider: provider.clone(),
        factory: Mutex::new(None),
    });
    let registry = ExtensionRegistry::with_verifier(verifier.clone());
    let mut stages = Vec::new();
    let mut decision = json!({"status":"accepted"});
    for bytes in input["registration_bytes"].as_array().unwrap() {
        let operation = if input["installation"] == "direct_injection" {
            "direct_injection"
        } else {
            "register"
        };
        let input_bytes = bytes.as_str().unwrap();
        let result = if operation == "direct_injection" {
            registry.inject(serde_json::from_str(input_bytes).unwrap(), provider.clone())
        } else {
            let factory: Arc<dyn ExtensionFactory> =
                Arc::new(PublicSourceFactory(provider.clone()));
            *verifier.factory.lock().unwrap() = Some(factory.clone());
            registry.register_bytes(input_bytes.as_bytes(), factory)
        };
        let output = observed_result(result, |_| json!({"status":"accepted","value":null}));
        stages.push(json!({"operation":operation,"input":input_bytes,"output":output}));
        if output["status"] == "rejected" {
            decision = output;
            break;
        }
    }
    if decision["status"] != "rejected" && !input["configuration"].is_null() {
        let configuration = &input["configuration"];
        let result = registry.validate_configuration(&input["registration"], configuration);
        let (output, handle) = match result {
            Ok(h) => (json!({"status":"accepted","value":null}), Some(h)),
            Err(e) => (json!({"status":"rejected","code":e.code.as_str()}), None),
        };
        stages.push(
            json!({"operation":"validate_configuration","input":configuration,"output":output}),
        );
        if let Some(handle) = handle {
            let claims = registry.capabilities(&handle).unwrap();
            stages.push(json!({"operation":"capabilities","input":configuration["instance_id"],"output":claims}));
            let health = registry.health(&handle).unwrap();
            stages.push(
                json!({"operation":"health","input":configuration["instance_id"],"output":health}),
            );
        } else {
            decision = output;
        }
    }
    if decision["status"] != "rejected" {
        let requirement = &input["requirement"];
        let result = if input["configuration"].is_null() {
            registry
                .evaluate_profile(ProfileRequest {
                    configurations: &[],
                    requirements: std::slice::from_ref(requirement),
                    compose: false,
                    projection: &[],
                    requested_profile: None,
                    weak_profile_opt_in: false,
                })
                .map(|_| json!({"status":"accepted"}))
        } else {
            registry
                .negotiate(
                    &input["registration"],
                    &input["configuration"],
                    if requirement.is_null() {
                        None
                    } else {
                        Some(requirement)
                    },
                )
                .map(|report| json!({"status":"accepted","report":report}))
        };
        decision = observed_result(result, |v| v);
        stages.push(json!({"operation":"negotiate","input":{"requirement":requirement,"lookup_uri":input["lookup_uri"]},"output":decision}));
    }
    json!({"decision":decision,"core_mutations":0,"stages":stages,"loaded_source":"provider/test_provider.rs","loaded_closure_digest":digest})
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_claims_follow_the_configured_native_schema_and_health() {
    let registry = determa_state::extensions::bundled_store_registry().unwrap();
    let descriptor = registry
        .descriptors()
        .unwrap()
        .into_iter()
        .find(|d| d["provider_reference"]["identifier"] == "determa.sqlite")
        .unwrap();
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "determa-extension-{}-{unique}.db",
        std::process::id()
    ));
    let uri = format!(
        "sqlite:{}#receipt_retention=bounded&outbox_retention=bounded",
        path.display()
    );
    let config = json!({"instance_id":"primary","uri":uri});
    let requirement = json!({"category":"execution_store","provider_reference":descriptor["provider_reference"],"instance_id":"primary","capability":"durable_single_writer"});
    let handle = registry
        .validate_configuration(&descriptor, &config)
        .unwrap();
    assert_eq!(registry.health(&handle).unwrap(), "unavailable");
    assert_eq!(
        registry
            .negotiate(&descriptor, &config, Some(&requirement))
            .err()
            .unwrap()
            .code,
        ExtensionErrorCode::ExtensionCapabilityMismatch
    );
    let store = registry.bundled_execution_store(&handle).unwrap();
    store.initialize_schema().unwrap();
    assert_eq!(registry.health(&handle).unwrap(), "healthy");
    assert!(registry.report(&handle).unwrap()["claims"]
        .as_array()
        .unwrap()
        .contains(&json!("durable_single_writer")));
    let strict = json!({"instance_id":"primary","uri":format!("sqlite:{}#receipt_retention=permanent&outbox_retention=strict",path.display())});
    let changed = registry.validate_configuration(&descriptor, &strict);
    if let Ok(changed) = changed {
        assert_eq!(registry.health(&changed).unwrap(), "unavailable");
    }
    std::fs::remove_file(path).unwrap();
}

#[cfg(feature = "postgresql")]
#[test]
fn postgresql_claims_use_the_current_native_connection_when_available() {
    let Ok(url) = std::env::var("DETERMA_TEST_POSTGRES_URL") else {
        return;
    };
    let registry = determa_state::extensions::bundled_store_registry().unwrap();
    let descriptor = registry
        .descriptors()
        .unwrap()
        .into_iter()
        .find(|d| d["provider_reference"]["identifier"] == "determa.postgresql")
        .unwrap();
    let config = json!({"instance_id":"primary","uri":format!("{url}#receipt_retention=bounded&outbox_retention=bounded&tls=no_tls")});
    let handle = registry
        .validate_configuration(&descriptor, &config)
        .unwrap();
    let store = registry.bundled_execution_store(&handle).unwrap();
    store.initialize_schema().unwrap();
    assert_eq!(registry.health(&handle).unwrap(), "healthy");
    assert!(registry.report(&handle).unwrap()["claims"]
        .as_array()
        .unwrap()
        .contains(&json!("durable_concurrent")));
}

#[cfg(test)]
struct RejectingVerifier;
#[cfg(test)]
impl HostVerifier for RejectingVerifier {
    fn verify_factory(&self, _descriptor: &Value, _factory: &Arc<dyn ExtensionFactory>) -> bool {
        false
    }
    fn verify_source(
        &self,
        _descriptor: &Value,
        _factory: &Arc<dyn ExtensionFactory>,
        _provider: &Arc<dyn ExtensionProvider>,
    ) -> bool {
        false
    }
    fn prove_claims(
        &self,
        _descriptor: &Value,
        _configuration: &Value,
        _instance: &Instance,
        _health: &str,
        _candidates: &[String],
    ) -> BTreeSet<String> {
        BTreeSet::new()
    }
}
#[cfg(test)]
struct CountingFactory(Arc<std::sync::atomic::AtomicUsize>, Value);
#[cfg(test)]
impl ExtensionFactory for CountingFactory {
    fn create(&self) -> Result<Arc<dyn ExtensionProvider>, ExtensionError> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(Arc::new(PublicSourceProvider(self.1.clone())))
    }
}
#[test]
fn source_verified_provider_without_operational_proof_has_no_effective_claims() {
    let manifest: Value = serde_json::from_str(include_str!(
        "../conformance-suite/conformance/profiles/extension-negotiation/vectors.generated.json"
    ))
    .unwrap();
    let descriptor = manifest["public_vectors"][0]["registration"].clone();
    let config = manifest["public_vectors"][0]["configuration"].clone();
    let provider: Arc<dyn ExtensionProvider> = Arc::new(PublicSourceProvider(descriptor.clone()));
    let unverified = ExtensionRegistry::new();
    unverified
        .inject(descriptor.clone(), provider.clone())
        .unwrap();
    assert_eq!(
        unverified
            .validate_configuration(&descriptor, &config)
            .err()
            .unwrap()
            .code,
        ExtensionErrorCode::ExtensionIdentityMismatch
    );
    let registry = ExtensionRegistry::with_verifier(Arc::new(PublicSourceVerifier {
        digest: public_source_digest(),
        provider: provider.clone(),
        factory: Mutex::new(None),
    }));
    registry.inject(descriptor.clone(), provider).unwrap();
    let configured = registry
        .validate_configuration(&descriptor, &config)
        .unwrap();
    assert!(registry.native_instance(&configured).is_ok());
    let report = registry.report(&configured).unwrap();
    assert_eq!(report["health"], config["health"]);
    assert_eq!(report["claims"], json!([]));
}

#[test]
fn bundled_and_third_party_providers_share_one_public_registry() {
    let manifest: Value = serde_json::from_str(include_str!(
        "../conformance-suite/conformance/profiles/extension-negotiation/vectors.generated.json"
    ))
    .unwrap();
    let descriptor = manifest["public_vectors"][0]["registration"].clone();
    let configuration = manifest["public_vectors"][0]["configuration"].clone();
    let provider: Arc<dyn ExtensionProvider> = Arc::new(PublicSourceProvider(descriptor.clone()));
    let factory: Arc<dyn ExtensionFactory> = Arc::new(PublicSourceFactory(provider.clone()));
    let verifier = Arc::new(PublicSourceVerifier {
        digest: public_source_digest(),
        provider,
        factory: Mutex::new(Some(factory.clone())),
    });
    let registry =
        determa_state::extensions::bundled_store_registry_with_verifier(verifier).unwrap();
    registry.register(descriptor.clone(), factory).unwrap();
    let third_party = registry
        .validate_configuration(&descriptor, &configuration)
        .unwrap();
    assert!(registry.native_instance(&third_party).is_ok());
    assert_eq!(registry.report(&third_party).unwrap()["claims"], json!([]));
    let memory = registry
        .descriptors()
        .unwrap()
        .into_iter()
        .find(|item| item["provider_reference"]["identifier"] == "determa.memory")
        .unwrap();
    let configured = registry
        .validate_configuration(&memory, &json!({"instance_id":"memory","uri":"memory:"}))
        .unwrap();
    let store = registry.bundled_execution_store(&configured).unwrap();
    store.initialize_schema().unwrap();
    assert_eq!(
        registry.report(&configured).unwrap()["claims"],
        json!(["ephemeral"])
    );
}
#[test]
fn source_verification_precedes_factory_execution_and_injected_provider_calls() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let manifest: Value = serde_json::from_str(include_str!(
        "../conformance-suite/conformance/profiles/extension-negotiation/vectors.generated.json"
    ))
    .unwrap();
    let descriptor = manifest["public_vectors"][0]["registration"].clone();
    let config = manifest["public_vectors"][0]["configuration"].clone();
    let created = Arc::new(AtomicUsize::new(0));
    let registry = ExtensionRegistry::with_verifier(Arc::new(RejectingVerifier));
    registry
        .register(
            descriptor.clone(),
            Arc::new(CountingFactory(created.clone(), descriptor.clone())),
        )
        .unwrap();
    assert_eq!(
        registry
            .validate_configuration(&descriptor, &config)
            .err()
            .unwrap()
            .code,
        ExtensionErrorCode::ExtensionIdentityMismatch
    );
    assert_eq!(created.load(Ordering::SeqCst), 0);
    let injected = ExtensionRegistry::with_verifier(Arc::new(RejectingVerifier));
    injected
        .inject(
            descriptor.clone(),
            Arc::new(PublicSourceProvider(descriptor.clone())),
        )
        .unwrap();
    assert_eq!(
        injected
            .validate_configuration(&descriptor, &config)
            .err()
            .unwrap()
            .code,
        ExtensionErrorCode::ExtensionIdentityMismatch
    );
}

#[cfg(test)]
struct MutableInstanceProvider(Arc<Mutex<String>>, Value);
#[cfg(test)]
impl ExtensionProvider for MutableInstanceProvider {
    fn descriptor(&self) -> Value {
        self.1.clone()
    }
    fn validate_configuration(&self, _configuration: &Value) -> Result<Instance, ExtensionError> {
        Ok(Arc::new(self.0.clone()))
    }
    fn instance_id(&self, instance: &Instance) -> Result<String, ExtensionError> {
        Ok(instance
            .downcast_ref::<Arc<Mutex<String>>>()
            .ok_or_else(invalid_config)?
            .lock()
            .unwrap()
            .clone())
    }
    fn capabilities(&self, _instance: &Instance) -> Result<Vec<String>, ExtensionError> {
        Ok(vec!["durable_single_writer".into()])
    }
    fn health(&self, _instance: &Instance) -> Result<String, ExtensionError> {
        Ok("healthy".into())
    }
}
#[cfg(test)]
struct ChangingSourceVerifier {
    provider: Arc<dyn ExtensionProvider>,
    allowed: Arc<std::sync::atomic::AtomicBool>,
}
#[cfg(test)]
impl HostVerifier for ChangingSourceVerifier {
    fn verify_factory(&self, _: &Value, _: &Arc<dyn ExtensionFactory>) -> bool {
        false
    }
    fn verify_source(
        &self,
        _: &Value,
        _: &Arc<dyn ExtensionFactory>,
        provider: &Arc<dyn ExtensionProvider>,
    ) -> bool {
        Arc::ptr_eq(&self.provider, provider)
            && self.allowed.load(std::sync::atomic::Ordering::SeqCst)
    }
    fn prove_claims(
        &self,
        _: &Value,
        _: &Value,
        _: &Instance,
        _: &str,
        _: &[String],
    ) -> BTreeSet<String> {
        BTreeSet::from(["durable_single_writer".into()])
    }
}
#[test]
fn source_and_native_instance_mutations_invalidate_bound_handles() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let manifest: Value = serde_json::from_str(include_str!(
        "../conformance-suite/conformance/profiles/extension-negotiation/vectors.generated.json"
    ))
    .unwrap();
    let descriptor = manifest["public_vectors"][0]["registration"].clone();
    let config = manifest["public_vectors"][0]["configuration"].clone();
    let state = Arc::new(Mutex::new("primary".to_owned()));
    let provider: Arc<dyn ExtensionProvider> =
        Arc::new(MutableInstanceProvider(state.clone(), descriptor.clone()));
    let allowed = Arc::new(AtomicBool::new(true));
    let registry = ExtensionRegistry::with_verifier(Arc::new(ChangingSourceVerifier {
        provider: provider.clone(),
        allowed: allowed.clone(),
    }));
    registry.inject(descriptor.clone(), provider).unwrap();
    let handle = registry
        .validate_configuration(&descriptor, &config)
        .unwrap();
    assert_eq!(
        registry.report(&handle).unwrap()["claims"],
        json!(["durable_single_writer"])
    );
    *state.lock().unwrap() = "clone".into();
    assert_eq!(
        registry.report(&handle).err().unwrap().code,
        ExtensionErrorCode::InvalidExtensionConfiguration
    );
    *state.lock().unwrap() = "primary".into();
    allowed.store(false, Ordering::SeqCst);
    assert_eq!(
        registry.report(&handle).err().unwrap().code,
        ExtensionErrorCode::ExtensionIdentityMismatch
    );
}

#[test]
fn file_store_claim_requires_initialized_native_schema() {
    let registry = determa_state::extensions::bundled_store_registry().unwrap();
    let descriptor = registry
        .descriptors()
        .unwrap()
        .into_iter()
        .find(|d| d["provider_reference"]["identifier"] == "determa.file")
        .unwrap();
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "determa-extension-file-{}-{unique}",
        std::process::id()
    ));
    let config = json!({"instance_id":"primary","uri":format!("file:{}",path.display())});
    let handle = registry
        .validate_configuration(&descriptor, &config)
        .unwrap();
    assert_eq!(registry.health(&handle).unwrap(), "unavailable");
    let store = registry.bundled_execution_store(&handle).unwrap();
    store.initialize_schema().unwrap();
    assert_eq!(registry.health(&handle).unwrap(), "healthy");
    assert_eq!(
        registry.report(&handle).unwrap()["claims"],
        json!(["restart_persistent"])
    );
    std::fs::remove_dir_all(path).unwrap();
}

#[cfg(feature = "sqlite")]
#[test]
fn strong_host_profile_requires_bound_source_instance_health_and_host_proof() {
    use determa_state::checkpoint::{CheckpointHost, HostProfile};
    let registry = Arc::new(determa_state::extensions::bundled_store_registry().unwrap());
    let descriptor = registry
        .descriptors()
        .unwrap()
        .into_iter()
        .find(|d| d["provider_reference"]["identifier"] == "determa.sqlite")
        .unwrap();
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "determa-verified-host-{}-{unique}.db",
        std::process::id()
    ));
    let config = json!({"instance_id":"primary","uri":format!("sqlite:{}#receipt_retention=bounded&outbox_retention=bounded",path.display())});
    let verified = registry
        .configure_execution_store(&descriptor, &config)
        .unwrap();
    let raw = verified.store();
    let weak: CheckpointHost<determa_state::InMemoryDefinitionResolver> = CheckpointHost::new(
        raw.clone(),
        Arc::new(determa_state::InMemoryDefinitionResolver::default()),
    );
    assert_eq!(
        weak.validate_profile(HostProfile::DurableEmbeddedProcessing, false)
            .err()
            .unwrap()
            .code
            .as_str(),
        "adapter_capability_mismatch"
    );
    let strong: CheckpointHost<determa_state::InMemoryDefinitionResolver> =
        CheckpointHost::from_verified(
            verified,
            Arc::new(determa_state::InMemoryDefinitionResolver::default()),
        );
    assert_eq!(
        strong
            .validate_profile(HostProfile::DurableEmbeddedProcessing, false)
            .err()
            .unwrap()
            .code
            .as_str(),
        "adapter_capability_mismatch"
    );
    raw.initialize_schema().unwrap();
    strong
        .validate_profile(HostProfile::DurableEmbeddedProcessing, false)
        .unwrap();
    assert_eq!(
        strong
            .validate_profile(HostProfile::BrokerIntegrated, false)
            .err()
            .unwrap()
            .code
            .as_str(),
        "adapter_capability_mismatch"
    );
    assert_eq!(
        strong
            .validate_profile(HostProfile::SharedApplicationTransaction, false)
            .err()
            .unwrap()
            .code
            .as_str(),
        "adapter_capability_mismatch"
    );
    std::fs::remove_file(path).unwrap();
}
