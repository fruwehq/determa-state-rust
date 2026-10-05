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
