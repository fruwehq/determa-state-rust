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
    binding_checks: AtomicUsize,
    fail_binding_at: AtomicUsize,
    staged_marker: Mutex<Option<std::path::PathBuf>>,
}
impl NativeHandler for Destination {
    fn destination_binding_digest(&self) -> Result<String, ExtensionError> {
        let check = self.binding_checks.fetch_add(1, Ordering::SeqCst) + 1;
        if check == self.fail_binding_at.load(Ordering::SeqCst) {
            if let Some(marker) = self.staged_marker.lock().unwrap().as_ref() {
                std::fs::write(marker, b"actual joint writes staged").unwrap();
                std::thread::sleep(std::time::Duration::from_secs(60));
            }
            self.healthy.store(false, Ordering::SeqCst);
        }
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
            binding_checks: AtomicUsize::new(0),
            fail_binding_at: AtomicUsize::new(usize::MAX),
            staged_marker: Mutex::new(None),
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

#[cfg(feature = "sqlite")]
struct EffectTestDirectory(std::path::PathBuf);
#[cfg(feature = "sqlite")]
impl EffectTestDirectory {
    fn new() -> Self {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "determa-effect-creation-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}
#[cfg(feature = "sqlite")]
impl Drop for EffectTestDirectory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

#[cfg(feature = "sqlite")]
fn effect_bundle() -> determa_state::format1::Bundle {
    determa_state::load_bundle(
        r#"
format: 1
namespace: tests.native_effect_creation
events:
  native_request:
    direction: output
    payload: {}
  native_succeeded:
    direction: input
    payload:
      provider_reference: { type: string, required: true }
  native_cancelled:
    direction: input
    payload: {}
machines:
  - machine_id: workflow
    version: 1
    root:
      type: simple
      entry:
        - send:
            event: native_request
            to: { external: true }
            payload: {}
            correlation_id: '"creation-business-token"'
      on_events:
        native_succeeded: {}
        native_cancelled: {}
"#,
    )
    .unwrap()
}

#[cfg(feature = "sqlite")]
fn effect_route() -> determa_state::authority::NativeEffectRoute {
    determa_state::authority::NativeEffectRoute {
        generation: "7".into(),
        handler_reference: descriptor()["provider_reference"].clone(),
        destination_binding_digest: hash('b'),
        result_mapping: json!([
            {"outcome_kind":"succeeded","event":"native_succeeded","result_slot":"success","operation_token_location":{"kind":"correlation_id"}},
            {"outcome_kind":"cancelled","event":"native_cancelled","result_slot":"cancelled","operation_token_location":{"kind":"correlation_id"}}
        ]),
        idempotency_policy: "reconcile_before_retry".into(),
    }
}

#[cfg(feature = "sqlite")]
fn effect_resolver(
    bundle: &determa_state::format1::Bundle,
) -> Arc<determa_state::InMemoryDefinitionResolver> {
    let mut resolver = determa_state::InMemoryDefinitionResolver::default();
    resolver.insert(bundle.clone(), true);
    Arc::new(resolver)
}

#[cfg(feature = "sqlite")]
fn effect_host(
    path: &std::path::Path,
    resolver: Arc<determa_state::InMemoryDefinitionResolver>,
    fixture: &Fixture,
) -> determa_state::authority::SqliteNativeEffectHost<determa_state::InMemoryDefinitionResolver> {
    determa_state::authority::SqliteNativeEffectHost::open(
        path,
        "scope-one".into(),
        "owner".into(),
        "host-one".into(),
        resolver,
        effect_route(),
        fixture.handler(),
    )
    .unwrap()
}

#[cfg(feature = "sqlite")]
fn native_snapshot(path: &std::path::Path) -> (Value, Value, Value) {
    let connection = rusqlite::Connection::open(path).unwrap();
    let checkpoint: Vec<u8> = connection.query_row("SELECT checkpoint_bytes FROM determa_execution_checkpoints WHERE root_instance_id='root'",[],|row|row.get(0)).unwrap();
    let journal: Vec<u8> = connection
        .query_row(
            "SELECT document FROM determa_authority_effect_journals WHERE root_instance_id='root'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let ledger: Vec<u8> = connection
        .query_row(
            "SELECT ledger FROM determa_scope_authority WHERE scope_identity='scope-one'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    (
        serde_json::from_slice(&checkpoint).unwrap(),
        serde_json::from_slice(&journal).unwrap(),
        serde_json::from_slice(&ledger).unwrap(),
    )
}

#[cfg(feature = "sqlite")]
#[test]
fn actual_native_effect_creation_commits_pair_and_exact_replay_before_current_handler_health() {
    let directory = EffectTestDirectory::new();
    let path = directory.path().join("authority.sqlite");
    let fixture = Fixture::new();
    let bundle = effect_bundle();
    let resolver = effect_resolver(&bundle);
    let host = effect_host(&path, resolver, &fixture);
    host.setup_schema().unwrap();
    assert!(host.allocate_scope().unwrap());
    let first = host
        .create(
            &bundle,
            "workflow",
            "root",
            "create-root",
            &determa_state::Bindings::default(),
        )
        .unwrap();
    let (checkpoint, document, ledger) = native_snapshot(&path);
    assert_eq!(
        document["journal"]["checkpoint_digest"],
        checkpoint["execution_checkpoint_digest"]
    );
    assert_eq!(
        document["journal"]["effect_records"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(document["responses"]["create-root"], first);
    assert_eq!(ledger["scope_generation"], "1");
    assert_eq!(ledger["receipts"].as_array().unwrap().len(), 1);
    assert_eq!(
        ledger["receipts"][0]["native_kind"],
        "checkpoint_effect_journal"
    );
    fixture.destination.healthy.store(false, Ordering::SeqCst);
    assert_eq!(
        host.create(
            &bundle,
            "workflow",
            "root",
            "create-root",
            &determa_state::Bindings::default()
        )
        .unwrap(),
        first
    );
    assert_eq!(native_snapshot(&path), (checkpoint, document, ledger));
    assert!(host
        .create(
            &bundle,
            "workflow",
            "new-root",
            "create-new",
            &determa_state::Bindings::default()
        )
        .is_err());
    assert_eq!(fixture.destination.calls.load(Ordering::SeqCst), 0);
}

#[cfg(feature = "sqlite")]
#[test]
fn reopened_actual_effect_creation_retains_response_and_refuses_changed_identity() {
    let directory = EffectTestDirectory::new();
    let path = directory.path().join("authority.sqlite");
    let fixture = Fixture::new();
    let bundle = effect_bundle();
    let resolver = effect_resolver(&bundle);
    let host = effect_host(&path, resolver.clone(), &fixture);
    host.setup_schema().unwrap();
    host.allocate_scope().unwrap();
    let first = host
        .create(
            &bundle,
            "workflow",
            "root",
            "create-root",
            &determa_state::Bindings::default(),
        )
        .unwrap();
    let before = native_snapshot(&path);
    drop(host);
    let reopened = effect_host(&path, resolver, &fixture);
    reopened.setup_schema().unwrap();
    assert!(!reopened.allocate_scope().unwrap());
    assert_eq!(
        reopened
            .create(
                &bundle,
                "workflow",
                "root",
                "create-root",
                &determa_state::Bindings::default()
            )
            .unwrap(),
        first
    );
    assert!(reopened
        .create(
            &bundle,
            "workflow",
            "root",
            "another-creation",
            &determa_state::Bindings::default()
        )
        .is_err());
    let changed = determa_state::load_bundle(
        &serde_yaml::to_string(&bundle.normalized)
            .unwrap()
            .replace("tests.native_effect_creation", "tests.alternate_creation"),
    )
    .unwrap();
    assert!(reopened
        .create(
            &changed,
            "workflow",
            "root",
            "create-root",
            &determa_state::Bindings::default()
        )
        .is_err());
    assert_eq!(native_snapshot(&path), before);
}

#[cfg(feature = "sqlite")]
#[test]
fn actual_effect_evidence_loss_and_substitution_refuse_without_setup_repair() {
    for damage in ["row", "table", "body"] {
        let directory = EffectTestDirectory::new();
        let path = directory.path().join("authority.sqlite");
        let fixture = Fixture::new();
        let bundle = effect_bundle();
        let host = effect_host(&path, effect_resolver(&bundle), &fixture);
        host.setup_schema().unwrap();
        host.allocate_scope().unwrap();
        host.create(
            &bundle,
            "workflow",
            "root",
            "create-root",
            &determa_state::Bindings::default(),
        )
        .unwrap();
        let connection = rusqlite::Connection::open(&path).unwrap();
        match damage {
            "row" => {
                connection
                    .execute("DELETE FROM determa_authority_effect_journals", [])
                    .unwrap();
            }
            "table" => {
                connection
                    .execute("DROP TABLE determa_authority_effect_journals", [])
                    .unwrap();
            }
            "body" => {
                let mut document = native_snapshot(&path).1;
                document["responses"]["create-root"]["status"] = json!("faulted");
                connection
                    .execute(
                        "UPDATE determa_authority_effect_journals SET document=?",
                        [serde_json_canonicalizer::to_vec(&document).unwrap()],
                    )
                    .unwrap();
            }
            _ => unreachable!(),
        }
        assert!(
            host.create(
                &bundle,
                "workflow",
                "root",
                "create-root",
                &determa_state::Bindings::default()
            )
            .is_err(),
            "{damage}"
        );
        if damage == "table" {
            assert!(host.setup_schema().is_err());
        }
        assert_eq!(fixture.destination.calls.load(Ordering::SeqCst), 0);
    }
}

#[cfg(feature = "sqlite")]
#[test]
fn ordinary_checkpoint_writer_cannot_tear_a_native_effect_pair() {
    use determa_state::checkpoint::ExecutionStore;
    let directory = EffectTestDirectory::new();
    let path = directory.path().join("authority.sqlite");
    let fixture = Fixture::new();
    let bundle = effect_bundle();
    let resolver = effect_resolver(&bundle);
    let host = effect_host(&path, resolver.clone(), &fixture);
    host.setup_schema().unwrap();
    host.allocate_scope().unwrap();
    host.create(
        &bundle,
        "workflow",
        "root",
        "create-root",
        &determa_state::Bindings::default(),
    )
    .unwrap();
    let before = native_snapshot(&path);
    let checkpoint = determa_state::checkpoint::restore(
        &serde_json::to_vec(&before.0).unwrap(),
        resolver.as_ref(),
    )
    .unwrap();
    let runtime = &checkpoint.value()["root_record"]["aggregate_state"]["runtimes"][0];
    let envelope = json!({"event":"native_cancelled","event_id":"app-input","cause_id":"app-input","source":{"host":true},"target":runtime["target_identity"],"payload":["map",[]]});
    use sha2::{Digest, Sha256};
    let digest = format!(
        "sha256:{:x}",
        Sha256::digest(
            serde_json_canonicalizer::to_vec(&json!([
                "determa-inbox-envelope-digest-1",
                "1",
                "root",
                "input",
                envelope
            ]))
            .unwrap()
        )
    );
    let delivery = json!({"delivery_mode":"input","envelope":envelope,"envelope_digest":digest});
    let candidate = determa_state::checkpoint::admit(
        &bundle,
        &checkpoint,
        &[delivery],
        Some(checkpoint.revision()),
        Some(checkpoint.digest()),
    )
    .unwrap();
    let candidate = determa_state::checkpoint::restore(
        &serde_json::to_vec(&candidate).unwrap(),
        resolver.as_ref(),
    )
    .unwrap();
    let store = determa_state::authority::GuardedSqliteExecutionStore::open(
        &path,
        determa_state::checkpoint::DurableStoreMode::new(
            determa_state::checkpoint::ReceiptRetentionMode::Permanent,
            determa_state::checkpoint::OutboxRetentionMode::Strict,
        ),
        "scope-one".into(),
        "owner".into(),
        "host-one".into(),
        resolver,
    )
    .unwrap();
    let error = store
        .compare_and_swap(
            "root",
            checkpoint.revision(),
            checkpoint.digest(),
            determa_state::checkpoint::StoreRecord::from_checkpoint(&candidate).unwrap(),
        )
        .unwrap_err();
    assert!(error.to_string().contains("joint native commit"));
    assert_eq!(native_snapshot(&path), before);
}

#[cfg(feature = "sqlite")]
#[test]
fn caller_supplied_joint_mutation_tag_cannot_activate_a_participant() {
    use sha2::{Digest, Sha256};
    let directory = EffectTestDirectory::new();
    let path = directory.path().join("authority.sqlite");
    let fixture = Fixture::new();
    let bundle = effect_bundle();
    let host = effect_host(&path, effect_resolver(&bundle), &fixture);
    host.setup_schema().unwrap();
    host.allocate_scope().unwrap();
    host.create(
        &bundle,
        "workflow",
        "root",
        "create-root",
        &determa_state::Bindings::default(),
    )
    .unwrap();
    let before = native_snapshot(&path);
    let authority = determa_state::authority::SqliteLocalAuthority::open(&path).unwrap();
    let caller = determa_state::authority::NativeAuthorityInvocation {
        authenticated_principal: "owner".into(),
        authorized_scopes: BTreeSet::from(["scope-one".into()]),
        operation_rights: BTreeSet::from(["guarded_commit".into()]),
    };
    for kind in ["checkpoint_effect_journal", "effect_journal"] {
        let mutation = serde_json_canonicalizer::to_vec(&json!({"native_mutation":kind})).unwrap();
        let mut request = json!({"interface":"determa.host_authority","interface_version":1,"operation":"guarded_commit","operation_id":"spoofed-role","scope_identity":"scope-one","expected_authority_epoch":"0","expected_scope_generation":"1","arguments":{"mutation_digest":format!("sha256:{:x}",Sha256::digest(&mutation))}});
        request["request_digest"] = json!(format!(
            "sha256:{:x}",
            Sha256::digest(
                serde_json_canonicalizer::to_vec(&json!([
                    "determa-host-authority-request-1",
                    request
                ]))
                .unwrap()
            )
        ));
        let response = authority
            .perform(
                &serde_json_canonicalizer::to_vec(&request).unwrap(),
                &caller,
                Some(&mutation),
            )
            .unwrap();
        assert_eq!(response["error_code"], "invalid_host_request");
        assert_eq!(native_snapshot(&path), before);
    }
}

#[cfg(feature = "sqlite")]
#[test]
fn health_failure_after_actual_joint_staging_rolls_back_every_write() {
    let directory = EffectTestDirectory::new();
    let path = directory.path().join("authority.sqlite");
    let fixture = Fixture::new();
    let bundle = effect_bundle();
    let host = effect_host(&path, effect_resolver(&bundle), &fixture);
    host.setup_schema().unwrap();
    host.allocate_scope().unwrap();
    fixture
        .destination
        .binding_checks
        .store(0, Ordering::SeqCst);
    fixture
        .destination
        .fail_binding_at
        .store(2, Ordering::SeqCst);
    assert!(host
        .create(
            &bundle,
            "workflow",
            "root",
            "create-root",
            &determa_state::Bindings::default()
        )
        .is_err());
    let connection = rusqlite::Connection::open(&path).unwrap();
    for table in [
        "determa_execution_checkpoints",
        "determa_authority_effect_journals",
        "determa_authority_mutations",
    ] {
        let count: u64 = connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0, "{table}");
    }
    let ledger: Vec<u8> = connection
        .query_row("SELECT ledger FROM determa_scope_authority", [], |row| {
            row.get(0)
        })
        .unwrap();
    let ledger: Value = serde_json::from_slice(&ledger).unwrap();
    assert_eq!(ledger["scope_generation"], "0");
    assert_eq!(ledger["receipts"], json!([]));
    assert_eq!(fixture.destination.binding_checks.load(Ordering::SeqCst), 2);
    fixture
        .destination
        .fail_binding_at
        .store(usize::MAX, Ordering::SeqCst);
    fixture.destination.healthy.store(true, Ordering::SeqCst);
    host.create(
        &bundle,
        "workflow",
        "root",
        "create-root",
        &determa_state::Bindings::default(),
    )
    .unwrap();
    assert_eq!(native_snapshot(&path).2["scope_generation"], "1");
}

#[cfg(feature = "sqlite")]
#[test]
fn inconsistent_caller_bundle_metadata_refuses_before_native_creation() {
    let directory = EffectTestDirectory::new();
    let path = directory.path().join("authority.sqlite");
    let fixture = Fixture::new();
    let bundle = effect_bundle();
    let host = effect_host(&path, effect_resolver(&bundle), &fixture);
    host.setup_schema().unwrap();
    host.allocate_scope().unwrap();
    for changed in ["namespace", "normalized"] {
        let mut caller_bundle = bundle.clone();
        if changed == "namespace" {
            caller_bundle.namespace = "substituted.namespace".into();
        } else {
            caller_bundle.normalized["namespace"] = json!("substituted.namespace");
        }
        assert!(host
            .create(
                &caller_bundle,
                "workflow",
                "root",
                "create-root",
                &determa_state::Bindings::default()
            )
            .is_err());
        let connection = rusqlite::Connection::open(&path).unwrap();
        let count: u64 = connection
            .query_row(
                "SELECT COUNT(*) FROM determa_execution_checkpoints",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
        assert_eq!(fixture.destination.calls.load(Ordering::SeqCst), 0);
    }
}

#[cfg(feature = "sqlite")]
#[test]
fn complete_result_route_refuses_before_core_even_without_initial_emissions() {
    for emits in [true, false] {
        for invalid in [
            "extra_field",
            "outcome",
            "duplicate_kind",
            "duplicate_slot",
            "missing_event",
            "output_event",
            "missing_token_field",
            "wrong_token_type",
        ] {
            let directory = EffectTestDirectory::new();
            let path = directory.path().join("authority.sqlite");
            let fixture = Fixture::new();
            let mut source = effect_bundle().normalized;
            if !emits {
                source["machines"][0]["root"]
                    .as_object_mut()
                    .unwrap()
                    .remove("entry");
            }
            source["events"]["native_succeeded"]["payload"]["number"] =
                json!({"type":"int","required":false});
            let bundle = determa_state::format1::load_bundle_from_json(source).unwrap();
            let mut route = effect_route();
            match invalid {
                "extra_field" => route.result_mapping[0]["unexpected"] = json!(true),
                "outcome" => route.result_mapping[0]["outcome_kind"] = json!("invented_outcome"),
                "duplicate_kind" => route.result_mapping[1]["outcome_kind"] = json!("succeeded"),
                "duplicate_slot" => route.result_mapping[1]["result_slot"] = json!("success"),
                "missing_event" => route.result_mapping[0]["event"] = json!("undeclared"),
                "output_event" => route.result_mapping[0]["event"] = json!("native_request"),
                "missing_token_field" => {
                    route.result_mapping[0]["operation_token_location"] =
                        json!({"kind":"payload","pointer":"/missing"})
                }
                "wrong_token_type" => {
                    route.result_mapping[0]["operation_token_location"] =
                        json!({"kind":"payload","pointer":"/number"})
                }
                _ => unreachable!(),
            }
            let host = determa_state::authority::SqliteNativeEffectHost::open(
                &path,
                "scope-one".into(),
                "owner".into(),
                "host-one".into(),
                effect_resolver(&bundle),
                route,
                fixture.handler(),
            )
            .unwrap();
            host.setup_schema().unwrap();
            host.allocate_scope().unwrap();
            fixture
                .destination
                .binding_checks
                .store(0, Ordering::SeqCst);
            assert!(
                host.create(
                    &bundle,
                    "workflow",
                    "root",
                    "create-root",
                    &determa_state::Bindings::default()
                )
                .is_err(),
                "{emits}/{invalid}"
            );
            assert_eq!(
                fixture.destination.binding_checks.load(Ordering::SeqCst),
                0,
                "{emits}/{invalid}"
            );
            let connection = rusqlite::Connection::open(&path).unwrap();
            let count: u64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM determa_execution_checkpoints",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 0, "{emits}/{invalid}");
        }
    }
}

#[cfg(all(feature = "sqlite", unix))]
#[test]
fn native_effect_creation_crash_child() {
    let Some(cut) = std::env::var_os("DETERMA_NATIVE_EFFECT_TEST_CUT") else {
        return;
    };
    let path =
        std::path::PathBuf::from(std::env::var_os("DETERMA_NATIVE_EFFECT_TEST_PATH").unwrap());
    let marker =
        std::path::PathBuf::from(std::env::var_os("DETERMA_NATIVE_EFFECT_TEST_MARKER").unwrap());
    let fixture = Fixture::new();
    let bundle = effect_bundle();
    let host = effect_host(&path, effect_resolver(&bundle), &fixture);
    host.setup_schema().unwrap();
    host.allocate_scope().unwrap();
    if cut == "staged" {
        fixture
            .destination
            .binding_checks
            .store(0, Ordering::SeqCst);
        fixture
            .destination
            .fail_binding_at
            .store(2, Ordering::SeqCst);
        *fixture.destination.staged_marker.lock().unwrap() = Some(marker.clone());
    } else {
        assert_eq!(cut, "committed");
    }
    host.create(
        &bundle,
        "workflow",
        "root",
        "create-root",
        &determa_state::Bindings::default(),
    )
    .unwrap();
    std::fs::write(
        marker,
        b"actual joint commit completed before transport response",
    )
    .unwrap();
    std::thread::sleep(std::time::Duration::from_secs(60));
}

#[cfg(all(feature = "sqlite", unix))]
#[test]
fn real_sigkill_before_and_after_joint_commit_reopens_with_exact_fate() {
    for cut in ["staged", "committed"] {
        let directory = EffectTestDirectory::new();
        let path = directory.path().join("authority.sqlite");
        let marker = directory.path().join("cut-marker");
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "native_effect_creation_crash_child",
                "--nocapture",
            ])
            .env("DETERMA_NATIVE_EFFECT_TEST_CUT", cut)
            .env("DETERMA_NATIVE_EFFECT_TEST_PATH", &path)
            .env("DETERMA_NATIVE_EFFECT_TEST_MARKER", &marker)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::inherit())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while !marker.exists() && std::time::Instant::now() < deadline {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let staged = marker.exists();
        let _ = child.kill();
        let status = child.wait().unwrap();
        assert!(staged, "actual {cut} cut was never reached");
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(9));
        let connection = rusqlite::Connection::open(&path).unwrap();
        for table in [
            "determa_execution_checkpoints",
            "determa_authority_effect_journals",
            "determa_authority_mutations",
        ] {
            let count: u64 = connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, u64::from(cut == "committed"), "{cut}/{table}");
        }
        let prior = if cut == "committed" {
            Some(native_snapshot(&path))
        } else {
            None
        };
        let fixture = Fixture::new();
        let bundle = effect_bundle();
        let reopened = effect_host(&path, effect_resolver(&bundle), &fixture);
        reopened.setup_schema().unwrap();
        assert!(!reopened.allocate_scope().unwrap());
        let first = reopened
            .create(
                &bundle,
                "workflow",
                "root",
                "create-root",
                &determa_state::Bindings::default(),
            )
            .unwrap();
        let after = native_snapshot(&path);
        assert_eq!(after.2["scope_generation"], "1");
        assert_eq!(after.2["receipts"].as_array().unwrap().len(), 1);
        assert_eq!(after.1["responses"]["create-root"], first);
        if let Some(prior) = prior {
            assert_eq!(after, prior);
        }
        assert_eq!(fixture.destination.calls.load(Ordering::SeqCst), 0);
    }
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
#[cfg(feature = "sqlite")]
fn external_effect_delivery(checkpoint: &Value, event_id: &str) -> Value {
    let runtime = &checkpoint["root_record"]["aggregate_state"]["runtimes"][0];
    let envelope = json!({"event":"native_cancelled","event_id":event_id,"cause_id":event_id,
        "source":{"host":true},"target":runtime["target_identity"],"payload":["map",[]]});
    let digest = {
        use sha2::{Digest, Sha256};
        format!(
            "sha256:{:x}",
            Sha256::digest(
                serde_json_canonicalizer::to_vec(&json!([
                    "determa-inbox-envelope-digest-1",
                    "1",
                    checkpoint["root_instance_id"],
                    "input",
                    envelope
                ]))
                .unwrap()
            )
        )
    };
    json!({"delivery_mode":"input","envelope":envelope,"envelope_digest":digest})
}

#[cfg(feature = "sqlite")]
fn effect_guard(checkpoint: &Value) -> determa_state::checkpoint::MutationGuard {
    determa_state::checkpoint::MutationGuard {
        expected_revision: checkpoint["revision"].as_str().unwrap().into(),
        expected_checkpoint_digest: checkpoint["execution_checkpoint_digest"]
            .as_str()
            .unwrap()
            .into(),
    }
}

#[cfg(feature = "sqlite")]
#[test]
fn actual_external_admission_commits_joint_history_and_preserves_original_creation_replay() {
    let directory = EffectTestDirectory::new();
    let path = directory.path().join("authority.sqlite");
    let fixture = Fixture::new();
    let bundle = effect_bundle();
    let resolver = effect_resolver(&bundle);
    let host = effect_host(&path, resolver.clone(), &fixture);
    host.setup_schema().unwrap();
    host.allocate_scope().unwrap();
    let creation = host
        .create(
            &bundle,
            "workflow",
            "root",
            "create-root",
            &determa_state::Bindings::default(),
        )
        .unwrap();
    let (prior, prior_document, _) = native_snapshot(&path);
    let delivery = external_effect_delivery(&prior, "external-event-1");
    fixture.destination.healthy.store(false, Ordering::SeqCst);
    fixture
        .destination
        .binding_checks
        .store(0, Ordering::SeqCst);
    let first = host
        .admit("root", "admit-1", &delivery, &effect_guard(&prior))
        .unwrap();
    let (current, document, ledger) = native_snapshot(&path);
    assert_eq!(current["revision"], "1");
    assert_eq!(document["journal"]["journal_revision"], "1");
    assert_eq!(
        document["journal"]["checkpoint_digest"],
        current["execution_checkpoint_digest"]
    );
    assert_eq!(
        document["journal"]["effect_records"],
        prior_document["journal"]["effect_records"]
    );
    assert_eq!(document["responses"]["create-root"], creation);
    assert_eq!(document["responses"]["admit-1"], first);
    assert_eq!(ledger["scope_generation"], "2");
    assert_eq!(ledger["receipts"].as_array().unwrap().len(), 2);
    assert_eq!(fixture.destination.binding_checks.load(Ordering::SeqCst), 0);
    // Exact named replay ignores current CAS, performs no native invocation and
    // retains the original response rather than returning a newer checkpoint.
    assert_eq!(
        host.admit("root", "admit-1", &delivery, &effect_guard(&prior))
            .unwrap(),
        first
    );
    assert_eq!(
        host.create(
            &bundle,
            "workflow",
            "root",
            "create-root",
            &determa_state::Bindings::default()
        )
        .unwrap(),
        creation
    );
    assert_eq!(
        native_snapshot(&path),
        (current.clone(), document.clone(), ledger.clone())
    );
    fixture.destination.healthy.store(true, Ordering::SeqCst);
    drop(host);
    let reopened = effect_host(&path, resolver, &fixture);
    assert_eq!(
        reopened
            .admit("root", "admit-1", &delivery, &effect_guard(&prior))
            .unwrap(),
        first
    );
    assert_eq!(native_snapshot(&path), (current, document, ledger));
}

#[cfg(feature = "sqlite")]
#[test]
fn duplicate_external_delivery_has_unchanged_checkpoint_and_a_new_exact_native_response() {
    let directory = EffectTestDirectory::new();
    let path = directory.path().join("authority.sqlite");
    let fixture = Fixture::new();
    let bundle = effect_bundle();
    let host = effect_host(&path, effect_resolver(&bundle), &fixture);
    host.setup_schema().unwrap();
    host.allocate_scope().unwrap();
    host.create(
        &bundle,
        "workflow",
        "root",
        "create-root",
        &determa_state::Bindings::default(),
    )
    .unwrap();
    let (prior, _, _) = native_snapshot(&path);
    let delivery = external_effect_delivery(&prior, "external-event-1");
    host.admit("root", "admit-1", &delivery, &effect_guard(&prior))
        .unwrap();
    let (current, _, _) = native_snapshot(&path);
    let duplicate = host
        .admit("root", "admit-2", &delivery, &effect_guard(&current))
        .unwrap();
    let (unchanged, document, ledger) = native_snapshot(&path);
    assert_eq!(unchanged, current);
    assert_eq!(document["journal"]["journal_revision"], "2");
    assert_eq!(ledger["scope_generation"], "3");
    assert_eq!(
        duplicate["body"]["admission_result"]["operation_kind"],
        "acceptance"
    );
    let snapshot = native_snapshot(&path);
    assert_eq!(
        host.admit("root", "admit-2", &delivery, &effect_guard(&prior))
            .unwrap(),
        duplicate
    );
    assert_eq!(native_snapshot(&path), snapshot);
}

#[cfg(feature = "sqlite")]
#[test]
fn changed_original_or_new_stale_guard_refuses_without_tearing_native_pair() {
    let directory = EffectTestDirectory::new();
    let path = directory.path().join("authority.sqlite");
    let fixture = Fixture::new();
    let bundle = effect_bundle();
    let host = effect_host(&path, effect_resolver(&bundle), &fixture);
    host.setup_schema().unwrap();
    host.allocate_scope().unwrap();
    host.create(
        &bundle,
        "workflow",
        "root",
        "create-root",
        &determa_state::Bindings::default(),
    )
    .unwrap();
    let (prior, _, _) = native_snapshot(&path);
    let delivery = external_effect_delivery(&prior, "external-event-1");
    host.admit("root", "admit-1", &delivery, &effect_guard(&prior))
        .unwrap();
    let snapshot = native_snapshot(&path);
    let changed = external_effect_delivery(&prior, "external-event-2");
    assert!(host
        .admit("root", "admit-1", &changed, &effect_guard(&prior))
        .is_err());
    assert!(host
        .admit("root", "admit-new", &changed, &effect_guard(&prior))
        .is_err());
    assert!(host
        .admit(
            "root",
            "admit-duplicate-stale",
            &delivery,
            &effect_guard(&prior)
        )
        .is_err());
    assert!(host
        .admit("root", "create-root", &delivery, &effect_guard(&prior))
        .is_err());
    assert_eq!(native_snapshot(&path), snapshot);
}
#[cfg(feature = "sqlite")]
fn publish_admission_cut_marker(path: &std::path::Path, bytes: &[u8]) {
    let pending = path.with_extension("pending");
    std::fs::write(&pending, bytes).unwrap();
    std::fs::File::open(&pending).unwrap().sync_all().unwrap();
    std::fs::rename(pending, path).unwrap();
}

#[cfg(feature = "sqlite")]
struct AdmissionStageResolver {
    bundle: determa_state::format1::Bundle,
    path: std::path::PathBuf,
    armed: std::sync::atomic::AtomicBool,
    stage_checks: std::sync::atomic::AtomicUsize,
    marker: Option<std::path::PathBuf>,
}
#[cfg(feature = "sqlite")]
impl determa_state::DefinitionResolver for AdmissionStageResolver {
    fn resolve_definition(
        &self,
        fingerprint: &str,
    ) -> Option<determa_state::format1::ResolvedDefinition> {
        if fingerprint != self.bundle.fingerprint {
            return None;
        }
        if self.armed.load(Ordering::SeqCst) {
            // A separate actual native connection detects the host's writer lock.
            // It never changes rows. Deferred read snapshots permit this probe;
            // BEGIN IMMEDIATE held by the actual staged update makes it busy.
            let connection = rusqlite::Connection::open(&self.path).unwrap();
            connection.busy_timeout(std::time::Duration::ZERO).unwrap();
            match connection.execute_batch("BEGIN IMMEDIATE; ROLLBACK") {
                Ok(()) => {}
                Err(rusqlite::Error::SqliteFailure(error, _))
                    if matches!(
                        error.code,
                        rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
                    ) =>
                {
                    self.stage_checks.fetch_add(1, Ordering::SeqCst);
                    if let Some(marker) = &self.marker {
                        publish_admission_cut_marker(marker,b"actual native admission holds writer transaction before source recheck");
                        std::thread::sleep(std::time::Duration::from_secs(60));
                    }
                    return None;
                }
                Err(error) => panic!("unexpected native admission stage probe: {error}"),
            }
        }
        Some(determa_state::format1::ResolvedDefinition {
            bundle: self.bundle.clone(),
            trusted: true,
        })
    }
}
#[cfg(feature = "sqlite")]
fn admission_stage_host(
    path: &std::path::Path,
    resolver: Arc<AdmissionStageResolver>,
    fixture: &Fixture,
) -> determa_state::authority::SqliteNativeEffectHost<AdmissionStageResolver> {
    determa_state::authority::SqliteNativeEffectHost::open(
        path,
        "scope-one".into(),
        "owner".into(),
        "host-one".into(),
        resolver,
        effect_route(),
        fixture.handler(),
    )
    .unwrap()
}
#[cfg(feature = "sqlite")]
#[test]
fn actual_source_loss_after_admission_sql_staging_rolls_back_checkpoint_journal_and_receipt() {
    let directory = EffectTestDirectory::new();
    let path = directory.path().join("authority.sqlite");
    let fixture = Fixture::new();
    let bundle = effect_bundle();
    let resolver = Arc::new(AdmissionStageResolver {
        bundle: bundle.clone(),
        path: path.clone(),
        armed: std::sync::atomic::AtomicBool::new(false),
        stage_checks: std::sync::atomic::AtomicUsize::new(0),
        marker: None,
    });
    let host = admission_stage_host(&path, resolver.clone(), &fixture);
    host.setup_schema().unwrap();
    host.allocate_scope().unwrap();
    host.create(
        &bundle,
        "workflow",
        "root",
        "create-root",
        &determa_state::Bindings::default(),
    )
    .unwrap();
    let snapshot = native_snapshot(&path);
    let delivery = external_effect_delivery(&snapshot.0, "external-event-1");
    resolver.armed.store(true, Ordering::SeqCst);
    assert!(host
        .admit("root", "admit-1", &delivery, &effect_guard(&snapshot.0))
        .is_err());
    assert_eq!(resolver.stage_checks.load(Ordering::SeqCst), 1);
    assert_eq!(native_snapshot(&path), snapshot);
    resolver.armed.store(false, Ordering::SeqCst);
    host.admit("root", "admit-1", &delivery, &effect_guard(&snapshot.0))
        .unwrap();
    assert_eq!(native_snapshot(&path).2["scope_generation"], "2");
}

#[cfg(all(feature = "sqlite", unix))]
#[test]
fn native_admission_crash_child() {
    let Some(cut) = std::env::var_os("DETERMA_NATIVE_ADMISSION_TEST_CUT") else {
        return;
    };
    let path =
        std::path::PathBuf::from(std::env::var_os("DETERMA_NATIVE_ADMISSION_TEST_PATH").unwrap());
    let marker =
        std::path::PathBuf::from(std::env::var_os("DETERMA_NATIVE_ADMISSION_TEST_MARKER").unwrap());
    let fixture = Fixture::new();
    let bundle = effect_bundle();
    let resolver = Arc::new(AdmissionStageResolver {
        bundle: bundle.clone(),
        path: path.clone(),
        armed: std::sync::atomic::AtomicBool::new(false),
        stage_checks: std::sync::atomic::AtomicUsize::new(0),
        marker: if cut == "staged" {
            Some(marker.clone())
        } else {
            None
        },
    });
    let host = admission_stage_host(&path, resolver.clone(), &fixture);
    host.setup_schema().unwrap();
    host.allocate_scope().unwrap();
    host.create(
        &bundle,
        "workflow",
        "root",
        "create-root",
        &determa_state::Bindings::default(),
    )
    .unwrap();
    let snapshot = native_snapshot(&path);
    let delivery = external_effect_delivery(&snapshot.0, "external-event-1");
    if cut == "staged" {
        resolver.armed.store(true, Ordering::SeqCst);
    } else {
        assert_eq!(cut, "committed");
    }
    let response = host
        .admit("root", "admit-1", &delivery, &effect_guard(&snapshot.0))
        .unwrap();
    publish_admission_cut_marker(&marker, &serde_json::to_vec(&response).unwrap());
    std::thread::sleep(std::time::Duration::from_secs(60));
}
#[cfg(all(feature = "sqlite", unix))]
#[test]
fn real_sigkill_admission_before_and_after_commit_reopens_exact_native_pair() {
    for cut in ["staged", "committed"] {
        let directory = EffectTestDirectory::new();
        let path = directory.path().join("authority.sqlite");
        let marker = directory.path().join("cut-marker");
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "native_admission_crash_child", "--nocapture"])
            .env("DETERMA_NATIVE_ADMISSION_TEST_CUT", cut)
            .env("DETERMA_NATIVE_ADMISSION_TEST_PATH", &path)
            .env("DETERMA_NATIVE_ADMISSION_TEST_MARKER", &marker)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::inherit())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while !marker.exists() && std::time::Instant::now() < deadline {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let reached = marker.exists();
        let _ = child.kill();
        let status = child.wait().unwrap();
        assert!(reached, "actual admission {cut} cut not reached");
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(9));
        let (checkpoint, document, ledger) = native_snapshot(&path);
        assert_eq!(
            checkpoint["revision"],
            if cut == "committed" { "1" } else { "0" }
        );
        assert_eq!(
            document["journal"]["journal_revision"],
            checkpoint["revision"]
        );
        assert_eq!(
            ledger["scope_generation"],
            if cut == "committed" { "2" } else { "1" }
        );
        assert_eq!(
            document["responses"].get("admit-1").is_some(),
            cut == "committed"
        );
        let fixture = Fixture::new();
        let bundle = effect_bundle();
        let host = effect_host(&path, effect_resolver(&bundle), &fixture);
        let creation = host
            .create(
                &bundle,
                "workflow",
                "root",
                "create-root",
                &determa_state::Bindings::default(),
            )
            .unwrap();
        let delivery = external_effect_delivery(&creation["checkpoint"], "external-event-1");
        let response = host
            .admit(
                "root",
                "admit-1",
                &delivery,
                &effect_guard(&creation["checkpoint"]),
            )
            .unwrap();
        if cut == "committed" {
            assert_eq!(
                response,
                serde_json::from_slice::<Value>(&std::fs::read(&marker).unwrap()).unwrap()
            );
        }
        let snapshot = native_snapshot(&path);
        assert_eq!(snapshot.2["scope_generation"], "2");
        assert_eq!(
            host.admit(
                "root",
                "admit-1",
                &delivery,
                &effect_guard(&creation["checkpoint"])
            )
            .unwrap(),
            response
        );
        assert_eq!(native_snapshot(&path), snapshot);
    }
}
#[cfg(feature = "sqlite")]
struct PausedAdmissionResolver {
    bundle: determa_state::format1::Bundle,
    signal: std::sync::Mutex<Option<std::sync::mpsc::Sender<()>>>,
    released: std::sync::Mutex<bool>,
    wake: std::sync::Condvar,
}
#[cfg(feature = "sqlite")]
impl determa_state::DefinitionResolver for PausedAdmissionResolver {
    fn resolve_definition(
        &self,
        fingerprint: &str,
    ) -> Option<determa_state::format1::ResolvedDefinition> {
        if fingerprint != self.bundle.fingerprint {
            return None;
        }
        if let Some(signal) = self.signal.lock().unwrap().take() {
            signal.send(()).unwrap();
            let released = self.released.lock().unwrap();
            let (released, timeout) = self
                .wake
                .wait_timeout_while(released, std::time::Duration::from_secs(20), |released| {
                    !*released
                })
                .unwrap();
            assert!(
                *released && !timeout.timed_out(),
                "native snapshot release not received"
            );
        }
        Some(determa_state::format1::ResolvedDefinition {
            bundle: self.bundle.clone(),
            trusted: true,
        })
    }
}
#[cfg(feature = "sqlite")]
#[test]
fn genuine_journal_only_race_refuses_stale_helper_while_checkpoint_guard_still_matches() {
    let directory = EffectTestDirectory::new();
    let path = directory.path().join("authority.sqlite");
    let fixture = Fixture::new();
    let bundle = effect_bundle();
    let host = effect_host(&path, effect_resolver(&bundle), &fixture);
    host.setup_schema().unwrap();
    host.allocate_scope().unwrap();
    host.create(
        &bundle,
        "workflow",
        "root",
        "create-root",
        &determa_state::Bindings::default(),
    )
    .unwrap();
    let (prior, _, _) = native_snapshot(&path);
    let delivery = external_effect_delivery(&prior, "external-event-1");
    host.admit("root", "admit-1", &delivery, &effect_guard(&prior))
        .unwrap();
    let (current, _, _) = native_snapshot(&path);
    let (signal, receiver) = std::sync::mpsc::channel();
    let resolver = Arc::new(PausedAdmissionResolver {
        bundle: bundle.clone(),
        signal: std::sync::Mutex::new(Some(signal)),
        released: std::sync::Mutex::new(false),
        wake: std::sync::Condvar::new(),
    });
    let loser = determa_state::authority::SqliteNativeEffectHost::open(
        &path,
        "scope-one".into(),
        "owner".into(),
        "host-one".into(),
        resolver.clone(),
        effect_route(),
        fixture.handler(),
    )
    .unwrap();
    let loser_delivery = delivery.clone();
    let loser_guard = effect_guard(&current);
    let thread = std::thread::spawn(move || {
        loser.admit("root", "loser-duplicate", &loser_delivery, &loser_guard)
    });
    // The losing operation has read its exact document and checkpoint bytes into
    // one Deferred snapshot before its first resolver-backed restoration call.
    let pinned = receiver.recv_timeout(std::time::Duration::from_secs(20));
    if pinned.is_err() {
        *resolver.released.lock().unwrap() = true;
        resolver.wake.notify_all();
        let _ = thread.join();
        panic!("loser did not pin its old native snapshot");
    }
    let winner = host.admit(
        "root",
        "winner-duplicate",
        &delivery,
        &effect_guard(&current),
    );
    *resolver.released.lock().unwrap() = true;
    resolver.wake.notify_all();
    let lost = thread.join().unwrap();
    winner.unwrap();
    let error = lost.expect_err("old helper update overwrote first response inventory");
    assert!(
        error
            .to_string()
            .contains("effect_journal_revision_conflict"),
        "{error}"
    );
    let (unchanged, document, ledger) = native_snapshot(&path);
    assert_eq!(unchanged, current);
    assert_eq!(ledger["scope_generation"], "3");
    assert_eq!(document["journal"]["journal_revision"], "2");
    assert!(document["responses"].get("winner-duplicate").is_some());
    assert!(document["responses"].get("loser-duplicate").is_none());
}
