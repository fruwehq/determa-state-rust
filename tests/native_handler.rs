//! Actual registry-bound native calls; proof callbacks authenticate exact loaded
//! objects and independently retained scoped destination evidence.
use determa_state::extensions::*;
use determa_state::format1::TypedValue;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};

fn hash(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}
fn descriptor() -> Value {
    json!({"category":"native_handler","interface_version":1,
        "provider_reference":{"identifier":"example.native-handler","version":"1.0.0",
            "content_digest":hash('a')},"supported_capabilities":["durable_effect_results"]})
}
fn rejected() -> ExtensionError {
    ExtensionError {
        code: ExtensionErrorCode::ExtensionIdentityMismatch,
        message: "native test binding refused".into(),
    }
}
struct Destination {
    binding: Mutex<String>,
    calls: AtomicUsize,
    receipts: Mutex<BTreeMap<(String, String), Value>>,
    unhealthy_after_call: AtomicBool,
    healthy: AtomicBool,
    bad_result: AtomicBool,
}
impl NativeHandler for Destination {
    fn destination_binding_digest(&self) -> Result<String, ExtensionError> {
        Ok(self.binding.lock().unwrap().clone())
    }
    fn invoke(
        &self,
        payload: &TypedValue,
        metadata: &NativeHandlerMetadata<'_>,
        attempt: &NativeHandlerAttempt<'_>,
    ) -> Result<NativeHandlerReport, ExtensionError> {
        struct SdkCredential(String);
        let sdk_credential =
            SdkCredential(String::from_utf8(metadata.credential.to_vec()).unwrap());
        assert_eq!(sdk_credential.0, "secret");
        self.calls.fetch_add(1, Ordering::SeqCst);
        // Native SDK state is kept inside this method. Only typed portable output
        // and independent retained destination receipts leave the native boundary.
        let receipt = json!({"accepted":true,"fence":attempt.attempt_fence,
            "request":serde_json::to_value(payload).unwrap()});
        self.receipts.lock().unwrap().insert(
            (metadata.scope_identity.into(), metadata.effect_id.into()),
            receipt,
        );
        if self.unhealthy_after_call.load(Ordering::SeqCst) {
            self.healthy.store(false, Ordering::SeqCst);
        }
        Ok(NativeHandlerReport {
            kind: NativeHandlerReportKind::Succeeded,
            payload: if self.bad_result.load(Ordering::SeqCst) {
                TypedValue::Float(f64::INFINITY)
            } else {
                TypedValue::String("accepted".into())
            },
            reason: None,
        })
    }
}
struct Provider {
    native: Arc<dyn NativeHandler>,
    destination: Arc<Destination>,
}
impl ExtensionProvider for Provider {
    fn descriptor(&self) -> Value {
        descriptor()
    }
    fn validate_configuration(
        &self,
        configuration: &Value,
    ) -> Result<ExtensionInstance, ExtensionError> {
        if configuration["instance_id"] != "destination-one" {
            return Err(rejected());
        }
        Ok(Arc::new(self.native.clone()))
    }
    fn instance_id(&self, _: &ExtensionInstance) -> Result<String, ExtensionError> {
        Ok("destination-one".into())
    }
    fn capabilities(&self, _: &ExtensionInstance) -> Result<Vec<String>, ExtensionError> {
        // This declaration deliberately receives no operational claim proof.
        Ok(vec!["durable_effect_results".into()])
    }
    fn health(&self, _: &ExtensionInstance) -> Result<String, ExtensionError> {
        Ok(if self.destination.healthy.load(Ordering::SeqCst) {
            "healthy"
        } else {
            "unavailable"
        }
        .into())
    }
}
struct Factory(Arc<dyn ExtensionProvider>, AtomicUsize);
impl ExtensionFactory for Factory {
    fn create(&self) -> Result<Arc<dyn ExtensionProvider>, ExtensionError> {
        self.1.fetch_add(1, Ordering::SeqCst);
        Ok(self.0.clone())
    }
}
struct Verifier {
    factory: Arc<dyn ExtensionFactory>,
    provider: Arc<dyn ExtensionProvider>,
    native: Arc<dyn NativeHandler>,
    destination: Arc<Destination>,
    source_valid: AtomicBool,
    proof_enabled: AtomicBool,
}
impl HostVerifier for Verifier {
    fn verify_factory(&self, actual: &Value, factory: &Arc<dyn ExtensionFactory>) -> bool {
        actual == &descriptor()
            && Arc::ptr_eq(factory, &self.factory)
            && self.source_valid.load(Ordering::SeqCst)
    }
    fn verify_source(
        &self,
        actual: &Value,
        factory: &Arc<dyn ExtensionFactory>,
        provider: &Arc<dyn ExtensionProvider>,
    ) -> bool {
        self.verify_factory(actual, factory) && Arc::ptr_eq(provider, &self.provider)
    }
    fn prove_claims(
        &self,
        _: &Value,
        _: &Value,
        _: &ExtensionInstance,
        _: &str,
        _: &[String],
    ) -> BTreeSet<String> {
        BTreeSet::new()
    }
    fn prove_native_destination_deduplication(
        &self,
        _: &Value,
        configuration: &Value,
        instance: &ExtensionInstance,
        evidence: &NativeDeduplicationEvidence<'_>,
    ) -> bool {
        self.proof_enabled.load(Ordering::SeqCst)
            && configuration["destination_binding_digest"] == evidence.destination_binding_digest
            && instance
                .downcast_ref::<Arc<dyn NativeHandler>>()
                .is_some_and(|native| Arc::ptr_eq(native, &self.native))
            && self
                .destination
                .receipts
                .lock()
                .unwrap()
                .get(&(evidence.scope_identity.into(), evidence.effect_id.into()))
                == Some(evidence.evidence)
    }
}
struct Fixture {
    registry: Arc<ExtensionRegistry>,
    destination: Arc<Destination>,
    verifier: Arc<Verifier>,
    factory: Arc<Factory>,
}
impl Fixture {
    fn new() -> Self {
        let destination = Arc::new(Destination {
            binding: Mutex::new(hash('b')),
            calls: AtomicUsize::new(0),
            receipts: Mutex::new(BTreeMap::new()),
            unhealthy_after_call: AtomicBool::new(false),
            healthy: AtomicBool::new(true),
            bad_result: AtomicBool::new(false),
        });
        let native: Arc<dyn NativeHandler> = destination.clone();
        let provider: Arc<dyn ExtensionProvider> = Arc::new(Provider {
            native: native.clone(),
            destination: destination.clone(),
        });
        let factory = Arc::new(Factory(provider.clone(), AtomicUsize::new(0)));
        let verifier = Arc::new(Verifier {
            factory: factory.clone(),
            provider,
            native,
            destination: destination.clone(),
            source_valid: AtomicBool::new(true),
            proof_enabled: AtomicBool::new(true),
        });
        let registry = Arc::new(ExtensionRegistry::with_verifier(verifier.clone()));
        registry.register(descriptor(), factory.clone()).unwrap();
        Self {
            registry,
            destination,
            verifier,
            factory,
        }
    }
    fn handler(&self) -> VerifiedNativeHandler {
        self.registry
            .configure_native_handler(&descriptor(), &configuration())
            .unwrap()
    }
    fn invoke(
        &self,
        handler: &VerifiedNativeHandler,
        payload: &TypedValue,
    ) -> Result<NativeHandlerReport, ExtensionError> {
        handler.invoke(
            payload,
            &NativeHandlerMetadata {
                scope_identity: "scope-one",
                effect_id: &hash('c'),
                operation_token: "order-42",
                destination_binding_digest: &hash('b'),
                route_configuration_generation: "7",
                handler_reference: &descriptor()["provider_reference"],
                credential: b"secret",
            },
            &NativeHandlerAttempt { attempt_fence: "1" },
        )
    }
}
fn configuration() -> Value {
    json!({"instance_id":"destination-one","destination_binding_digest":hash('b')})
}

#[test]
fn actual_native_invocation_retains_scoped_evidence_without_promoting_claims() {
    let fixture = Fixture::new();
    let handler = fixture.handler();
    let report = fixture.invoke(&handler, &TypedValue::Integer(42)).unwrap();
    assert_eq!(report.kind, NativeHandlerReportKind::Succeeded);
    assert_eq!(report.payload, TypedValue::String("accepted".into()));
    assert_eq!(fixture.destination.calls.load(Ordering::SeqCst), 1);
    let configured = fixture
        .registry
        .validate_configuration(&descriptor(), &configuration())
        .unwrap();
    assert_eq!(
        fixture.registry.report(&configured).unwrap()["claims"],
        json!([])
    );
    let receipt =
        fixture.destination.receipts.lock().unwrap()[&("scope-one".into(), hash('c'))].clone();
    let reference = descriptor()["provider_reference"].clone();
    let mut evidence = NativeDeduplicationEvidence {
        scope_identity: "scope-one",
        effect_id: &hash('c'),
        destination_binding_digest: &hash('b'),
        evidence: &receipt,
    };
    handler
        .verify_deduplication_evidence(&reference, &evidence)
        .unwrap();
    evidence.scope_identity = "other-scope";
    assert!(handler
        .verify_deduplication_evidence(&reference, &evidence)
        .is_err());
    evidence.scope_identity = "scope-one";
    let other_effect = hash('d');
    let original_effect = hash('c');
    let invented_receipt = json!({"accepted":true});
    evidence.effect_id = &other_effect;
    assert!(handler
        .verify_deduplication_evidence(&reference, &evidence)
        .is_err());
    evidence.effect_id = &original_effect;
    evidence.evidence = &invented_receipt;
    assert!(handler
        .verify_deduplication_evidence(&reference, &evidence)
        .is_err());
    evidence.evidence = &receipt;
    fixture
        .verifier
        .proof_enabled
        .store(false, Ordering::SeqCst);
    assert!(handler
        .verify_deduplication_evidence(&reference, &evidence)
        .is_err());
}

#[test]
fn changed_source_or_destination_refuses_before_any_call() {
    let fixture = Fixture::new();
    let handler = fixture.handler();
    fixture.verifier.source_valid.store(false, Ordering::SeqCst);
    assert!(fixture.invoke(&handler, &TypedValue::Null).is_err());
    assert!(fixture
        .registry
        .configure_native_handler(&descriptor(), &configuration())
        .is_err());
    // Verification of a changed factory occurs before its create method.
    assert_eq!(fixture.factory.1.load(Ordering::SeqCst), 1);
    fixture.verifier.source_valid.store(true, Ordering::SeqCst);
    *fixture.destination.binding.lock().unwrap() = hash('d');
    assert!(fixture.invoke(&handler, &TypedValue::Null).is_err());
    assert_eq!(fixture.destination.calls.load(Ordering::SeqCst), 0);
    assert!(handler
        .verify(&descriptor()["provider_reference"], &hash('d'))
        .is_err());
    let mut reference = descriptor()["provider_reference"].clone();
    reference["content_digest"] = json!(hash('d'));
    assert!(handler.verify(&reference, &hash('b')).is_err());
}

#[test]
fn nonportable_input_refuses_without_call_and_bad_output_retains_possible_acceptance() {
    let fixture = Fixture::new();
    let handler = fixture.handler();
    for invalid in [
        TypedValue::Float(f64::NAN),
        TypedValue::Map(vec![
            ("duplicate".into(), TypedValue::Integer(1)),
            ("duplicate".into(), TypedValue::Integer(2)),
        ]),
        TypedValue::Map(vec![
            ("z".into(), TypedValue::Null),
            ("a".into(), TypedValue::Null),
        ]),
    ] {
        assert!(fixture.invoke(&handler, &invalid).is_err());
    }
    assert_eq!(fixture.destination.calls.load(Ordering::SeqCst), 0);
    fixture.destination.bad_result.store(true, Ordering::SeqCst);
    assert!(fixture.invoke(&handler, &TypedValue::Null).is_err());
    assert_eq!(fixture.destination.calls.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.destination.receipts.lock().unwrap().len(), 1);
}

#[test]
fn health_loss_during_actual_call_does_not_erase_acceptance_or_allow_hidden_retry() {
    let fixture = Fixture::new();
    let handler = fixture.handler();
    fixture
        .destination
        .unhealthy_after_call
        .store(true, Ordering::SeqCst);
    assert!(fixture.invoke(&handler, &TypedValue::Null).is_err());
    assert_eq!(fixture.destination.receipts.lock().unwrap().len(), 1);
    assert_eq!(fixture.destination.calls.load(Ordering::SeqCst), 1);
    assert!(fixture.invoke(&handler, &TypedValue::Null).is_err());
    assert_eq!(fixture.destination.calls.load(Ordering::SeqCst), 1);
}
