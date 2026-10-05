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
#[cfg(feature = "sqlite")]
fn production_bundle() -> determa_state::format1::Bundle {
    determa_state::load_bundle(
        r#"
format: 1
namespace: tests.native_effect_production
events:
  invoke: { direction: input, payload: {} }
  native_request: { direction: output, payload: {} }
  native_succeeded:
    direction: input
    payload:
      provider_reference: { type: string, required: true }
  native_cancelled: { direction: input, payload: {} }
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
        invoke:
          action:
            - send:
                event: native_request
                to: { external: true }
                payload: {}
                correlation_id: '"production-business-token"'
            - send:
                event: native_request
                to: { external: true }
                payload: {}
                correlation_id: '"production-business-token"'
        native_succeeded: {}
        native_cancelled: {}
"#,
    )
    .unwrap()
}
#[cfg(feature = "sqlite")]
fn production_delivery(checkpoint: &Value, event_id: &str) -> Value {
    let mut delivery = external_effect_delivery(checkpoint, event_id);
    delivery["envelope"]["event"] = json!("invoke");
    use sha2::{Digest, Sha256};
    delivery["envelope_digest"] = json!(format!(
        "sha256:{:x}",
        Sha256::digest(
            serde_json_canonicalizer::to_vec(&json!([
                "determa-inbox-envelope-digest-1",
                "1",
                checkpoint["root_instance_id"],
                "input",
                delivery["envelope"]
            ]))
            .unwrap()
        )
    ));
    delivery
}
#[cfg(feature = "sqlite")]
fn production_request(
    checkpoint: &Value,
) -> determa_state::authority::NativeEffectProductionRequest {
    let runtime = &checkpoint["root_record"]["aggregate_state"]["runtimes"][0];
    let ready = &runtime["ready_mailbox"][0];
    determa_state::authority::NativeEffectProductionRequest {
        processing_request: determa_state::checkpoint::ProcessingRequest {
            target_runtime_id: runtime["runtime_id"].as_str().unwrap().into(),
            event_id: ready["envelope"]["event_id"].as_str().unwrap().into(),
            envelope_digest: ready["envelope_digest"].as_str().unwrap().into(),
            acceptance_sequence: ready["acceptance_sequence"].as_str().unwrap().into(),
            queue_sequence: ready["queue_sequence"].as_str().unwrap().into(),
            processing_mode: "foreground".into(),
        },
        operation_token: "production-business-token".into(),
        route_configuration_generation: "7".into(),
        guard: effect_guard(checkpoint),
    }
}
#[cfg(feature = "sqlite")]
#[test]
fn actual_native_producer_pins_all_real_emissions_and_replays_full_response_before_health_and_cas()
{
    let directory = EffectTestDirectory::new();
    let path = directory.path().join("authority.sqlite");
    let fixture = Fixture::new();
    let bundle = production_bundle();
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
    let (initial, initial_doc, _) = native_snapshot(&path);
    let delivery = production_delivery(&initial, "invoke-1");
    host.admit("root", "admit-1", &delivery, &effect_guard(&initial))
        .unwrap();
    let (admitted, _, _) = native_snapshot(&path);
    let mut request = production_request(&admitted);
    let first = host.produce("root", "produce-1", &request).unwrap();
    assert_eq!(first["kind"], "processing");
    assert_eq!(
        first["body"]["core_result"]["emissions"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let (current, document, ledger) = native_snapshot(&path);
    assert_eq!(
        current["pending_outbox_intents"].as_array().unwrap().len(),
        3
    );
    assert_eq!(
        document["journal"]["effect_records"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    let old_record = &initial_doc["journal"]["effect_records"][0];
    assert!(document["journal"]["effect_records"]
        .as_array()
        .unwrap()
        .contains(old_record));
    assert_eq!(document["responses"]["produce-1"], first);
    assert_eq!(ledger["scope_generation"], "3");
    assert_eq!(fixture.destination.calls.load(Ordering::SeqCst), 0);
    fixture.destination.healthy.store(false, Ordering::SeqCst);
    fixture
        .destination
        .binding_checks
        .store(0, Ordering::SeqCst);
    request.guard = effect_guard(&initial);
    request.route_configuration_generation = "999".into();
    assert_eq!(host.produce("root", "produce-1", &request).unwrap(), first);
    assert_eq!(fixture.destination.binding_checks.load(Ordering::SeqCst), 0);
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
    request.operation_token = "changed-business-token".into();
    assert!(host.produce("root", "produce-1", &request).is_err());
    fixture.destination.healthy.store(true, Ordering::SeqCst);
    drop(host);
    let reopened = effect_host(&path, resolver, &fixture);
    request.operation_token = "production-business-token".into();
    assert_eq!(
        reopened.produce("root", "produce-1", &request).unwrap(),
        first
    );
    assert_eq!(native_snapshot(&path), (current, document, ledger));
}
#[cfg(feature = "sqlite")]
#[test]
fn actual_producer_poststage_health_loss_rolls_back_effects_checkpoint_and_native_receipt() {
    let directory = EffectTestDirectory::new();
    let path = directory.path().join("authority.sqlite");
    let fixture = Fixture::new();
    let bundle = production_bundle();
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
    let (initial, _, _) = native_snapshot(&path);
    let delivery = production_delivery(&initial, "invoke-1");
    host.admit("root", "admit-1", &delivery, &effect_guard(&initial))
        .unwrap();
    let snapshot = native_snapshot(&path);
    let request = production_request(&snapshot.0);
    fixture
        .destination
        .binding_checks
        .store(0, Ordering::SeqCst);
    fixture
        .destination
        .fail_binding_at
        .store(2, Ordering::SeqCst);
    assert!(host.produce("root", "produce-1", &request).is_err());
    assert_eq!(fixture.destination.binding_checks.load(Ordering::SeqCst), 2);
    assert_eq!(native_snapshot(&path), snapshot);
    assert_eq!(fixture.destination.calls.load(Ordering::SeqCst), 0);
    fixture
        .destination
        .fail_binding_at
        .store(0, Ordering::SeqCst);
    fixture.destination.healthy.store(true, Ordering::SeqCst);
    host.produce("root", "produce-1", &request).unwrap();
    assert_eq!(native_snapshot(&path).2["scope_generation"], "3");
}
#[cfg(feature = "sqlite")]
#[test]
fn producer_wrong_token_generation_or_named_terminal_reuse_never_writes_helper_state() {
    let directory = EffectTestDirectory::new();
    let path = directory.path().join("authority.sqlite");
    let fixture = Fixture::new();
    let bundle = production_bundle();
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
    let (initial, _, _) = native_snapshot(&path);
    host.admit(
        "root",
        "admit-1",
        &production_delivery(&initial, "invoke-1"),
        &effect_guard(&initial),
    )
    .unwrap();
    let snapshot = native_snapshot(&path);
    let mut request = production_request(&snapshot.0);
    request.route_configuration_generation = "8".into();
    assert!(host.produce("root", "produce-1", &request).is_err());
    request.route_configuration_generation = "7".into();
    request.operation_token = "different-token".into();
    assert!(host.produce("root", "produce-1", &request).is_err());
    assert_eq!(native_snapshot(&path), snapshot);
    request.operation_token = "production-business-token".into();
    host.produce("root", "produce-1", &request).unwrap();
    let finished = native_snapshot(&path);
    assert!(host
        .produce("root", "another-operation-id", &request)
        .is_err());
    assert_eq!(native_snapshot(&path), finished);
}
#[cfg(feature = "sqlite")]
#[test]
fn native_producer_zero_emissions_and_deferral_retain_complete_actual_responses() {
    for deferred in [false, true] {
        let directory = EffectTestDirectory::new();
        let path = directory.path().join("authority.sqlite");
        let fixture = Fixture::new();
        let bundle = if deferred {
            let mut source = production_bundle().normalized.clone();
            source["machines"][0]["root"]["on_events"]
                .as_object_mut()
                .unwrap()
                .remove("invoke");
            source["machines"][0]["root"]["deferred_events"] = json!(["invoke"]);
            determa_state::load_bundle(&serde_json::to_string(&source).unwrap()).unwrap()
        } else {
            production_bundle()
        };
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
        let (initial, _, _) = native_snapshot(&path);
        let delivery = if deferred {
            production_delivery(&initial, "invoke-1")
        } else {
            external_effect_delivery(&initial, "zero-1")
        };
        host.admit("root", "admit-1", &delivery, &effect_guard(&initial))
            .unwrap();
        let (admitted, _, _) = native_snapshot(&path);
        let request = production_request(&admitted);
        let first = host.produce("root", "produce-1", &request).unwrap();
        let snapshot = native_snapshot(&path);
        assert_eq!(
            snapshot.1["journal"]["effect_records"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert!(first["body"]["core_result"]["emissions"]
            .as_array()
            .unwrap()
            .is_empty());
        assert_eq!(
            first["body"]["core_result"]["disposition"],
            if deferred { "deferred" } else { "handled" }
        );
        assert_eq!(first["body"]["receipt"].is_null(), deferred);
        if deferred {
            assert_eq!(
                snapshot.0["root_record"]["aggregate_state"]["runtimes"][0]["deferred_mailbox"]
                    .as_array()
                    .unwrap()
                    .len(),
                1
            );
        }
        fixture.destination.healthy.store(false, Ordering::SeqCst);
        assert_eq!(host.produce("root", "produce-1", &request).unwrap(), first);
        assert_eq!(native_snapshot(&path), snapshot);
        assert_eq!(fixture.destination.calls.load(Ordering::SeqCst), 0);
    }
}

#[cfg(all(feature = "sqlite", unix))]
#[test]
fn native_producer_crash_child() {
    let Some(cut) = std::env::var_os("DETERMA_NATIVE_PRODUCER_TEST_CUT") else {
        return;
    };
    let path =
        std::path::PathBuf::from(std::env::var_os("DETERMA_NATIVE_PRODUCER_TEST_PATH").unwrap());
    let marker =
        std::path::PathBuf::from(std::env::var_os("DETERMA_NATIVE_PRODUCER_TEST_MARKER").unwrap());
    let fixture = Fixture::new();
    let bundle = production_bundle();
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
    let (initial, _, _) = native_snapshot(&path);
    host.admit(
        "root",
        "admit-1",
        &production_delivery(&initial, "invoke-1"),
        &effect_guard(&initial),
    )
    .unwrap();
    let request = production_request(&native_snapshot(&path).0);
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
    let response = host.produce("root", "produce-1", &request).unwrap();
    publish_admission_cut_marker(&marker, &serde_json::to_vec(&response).unwrap());
    std::thread::sleep(std::time::Duration::from_secs(60));
}
#[cfg(all(feature = "sqlite", unix))]
#[test]
fn real_sigkill_producer_before_and_after_commit_preserves_all_actual_intents_and_first_response() {
    for cut in ["staged", "committed"] {
        let directory = EffectTestDirectory::new();
        let path = directory.path().join("authority.sqlite");
        let marker = directory.path().join("cut-marker");
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "native_producer_crash_child", "--nocapture"])
            .env("DETERMA_NATIVE_PRODUCER_TEST_CUT", cut)
            .env("DETERMA_NATIVE_PRODUCER_TEST_PATH", &path)
            .env("DETERMA_NATIVE_PRODUCER_TEST_MARKER", &marker)
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
        assert!(reached, "actualproducer{cut}cut not reached");
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(9));
        let (checkpoint, document, ledger) = native_snapshot(&path);
        assert_eq!(
            checkpoint["revision"],
            if cut == "committed" { "2" } else { "1" }
        );
        assert_eq!(
            document["journal"]["journal_revision"],
            checkpoint["revision"]
        );
        assert_eq!(
            ledger["scope_generation"],
            if cut == "committed" { "3" } else { "2" }
        );
        assert_eq!(
            document["journal"]["effect_records"]
                .as_array()
                .unwrap()
                .len(),
            if cut == "committed" { 3 } else { 1 }
        );
        let fixture = Fixture::new();
        let bundle = production_bundle();
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
        let admitted = host
            .admit(
                "root",
                "admit-1",
                &production_delivery(&creation["checkpoint"], "invoke-1"),
                &effect_guard(&creation["checkpoint"]),
            )
            .unwrap();
        let request = production_request(&admitted["body"]["checkpoint"]);
        let first = host.produce("root", "produce-1", &request).unwrap();
        if cut == "committed" {
            assert_eq!(
                first,
                serde_json::from_slice::<Value>(&std::fs::read(&marker).unwrap()).unwrap()
            );
        }
        let snapshot = native_snapshot(&path);
        assert_eq!(snapshot.2["scope_generation"], "3");
        assert_eq!(
            snapshot.1["journal"]["effect_records"]
                .as_array()
                .unwrap()
                .len(),
            3
        );
        assert_eq!(host.produce("root", "produce-1", &request).unwrap(), first);
        assert_eq!(native_snapshot(&path), snapshot);
        assert_eq!(fixture.destination.calls.load(Ordering::SeqCst), 0);
    }
}

#[cfg(feature = "sqlite")]
#[path = "support/runtime_provider.rs"]
mod effect_runtime_fixture;

#[cfg(feature = "sqlite")]
struct EffectRuntimeVerifier {
    valid: AtomicBool,
    checks: AtomicUsize,
}
#[cfg(feature = "sqlite")]
impl determa_state::format1::providers::RuntimeProviderVerifier for EffectRuntimeVerifier {
    fn verify(
        &self,
        provider: &dyn determa_state::format1::providers::NativeRuntimeProvider,
        descriptor: &Value,
        closure: &determa_state::format1::providers::SourceClosure,
    ) -> determa_state::format1::providers::ProviderResult<BTreeSet<String>> {
        self.checks.fetch_add(1, Ordering::SeqCst);
        if !self.valid.load(Ordering::SeqCst) {
            return Err(determa_state::ArtifactError::new(
                "runtime_provider_unavailable",
                "revoked native binding",
            ));
        }
        effect_runtime_fixture::Verifier {
            trusted: true,
            weak_compiler: false,
        }
        .verify(provider, descriptor, closure)
    }
    fn inspection_state(
        &self,
        provider: &dyn determa_state::format1::providers::NativeRuntimeProvider,
    ) -> determa_state::format1::providers::ProviderResult<Vec<u8>> {
        effect_runtime_fixture::Verifier {
            trusted: true,
            weak_compiler: false,
        }
        .inspection_state(provider)
    }
}
#[cfg(feature = "sqlite")]
struct EffectRuntimeResolver {
    bundle: determa_state::format1::Bundle,
    path: std::path::PathBuf,
    verifier: Arc<EffectRuntimeVerifier>,
    available: AtomicBool,
    revoke_at_stage: AtomicBool,
    calls: AtomicUsize,
    staged: AtomicUsize,
    claim_authority: Mutex<Option<Arc<EffectWorkerAuthority>>>,
    claim_cut: AtomicUsize,
}
#[cfg(feature = "sqlite")]
impl determa_state::DefinitionResolver for EffectRuntimeResolver {
    fn resolve_definition(
        &self,
        fingerprint: &str,
    ) -> Option<determa_state::format1::ResolvedDefinition> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if !self.available.load(Ordering::SeqCst) || fingerprint != self.bundle.fingerprint {
            return None;
        }
        if self.revoke_at_stage.load(Ordering::SeqCst) {
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
                    self.staged.fetch_add(1, Ordering::SeqCst);
                    self.verifier.valid.store(false, Ordering::SeqCst);
                }
                Err(error) => panic!("unexpected native stage probe: {error}"),
            }
        }
        if self.claim_cut.load(Ordering::SeqCst) != 0 {
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
                    self.staged.fetch_add(1, Ordering::SeqCst);
                    let authority = self.claim_authority.lock().unwrap();
                    let authority = authority.as_ref().unwrap();
                    match self.claim_cut.load(Ordering::SeqCst) {
                        1 => authority.now.store(20, Ordering::SeqCst),
                        2 => authority.authorized.store(false, Ordering::SeqCst),
                        _ => authority.fail_clock.store(true, Ordering::SeqCst),
                    }
                }
                Err(error) => panic!("unexpected final claim resolver probe: {error}"),
            }
        }
        Some(determa_state::format1::ResolvedDefinition {
            bundle: self.bundle.clone(),
            trusted: true,
        })
    }
}
#[cfg(feature = "sqlite")]
fn runtime_effect_resolver(path: &std::path::Path) -> Arc<EffectRuntimeResolver> {
    use determa_state::format1::providers::{RuntimeProviderRegistry, SourceClosure};
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("conformance-suite/conformance/profiles/runtime-provider/provider-01-exact-source");
    let safe: Value =
        serde_yaml::from_str(&std::fs::read_to_string(root.join("machine-safe.yaml")).unwrap())
            .unwrap();
    let binding = safe["machines"][0]["root"]["states"]["pending"]["on_events"]["submit"]["guard"]
        ["provider"]
        .clone();
    let closure = SourceClosure {
        root,
        paths: vec![
            "provider/test_provider.py".into(),
            "provider/test_provider.rs".into(),
        ],
        manifest: "provider-closure.json".into(),
        domain: b"determa-test-runtime-provider-closure-1\0".to_vec(),
    };
    let verifier = Arc::new(EffectRuntimeVerifier {
        valid: AtomicBool::new(true),
        checks: AtomicUsize::new(0),
    });
    let mut registry = RuntimeProviderRegistry::new(verifier.clone());
    for dependency in binding["dependencies"].as_array().unwrap() {
        registry
            .register_dependency(dependency.clone(), closure.clone())
            .unwrap();
    }
    registry
        .register(
            json!({"kind":"guard","binding":binding}),
            Arc::new(effect_runtime_fixture::RuntimeFixture::new(json!({}))),
            closure,
        )
        .unwrap();
    let mut document = production_bundle().normalized.clone();
    document["machines"][0]["root"]["on_events"]["native_succeeded"]["guard"] =
        json!({"provider":binding});
    let bundle = determa_state::load_bundle_with_providers(
        &serde_yaml::to_string(&document).unwrap(),
        registry,
        &BTreeSet::new(),
    )
    .unwrap();
    Arc::new(EffectRuntimeResolver {
        bundle,
        path: path.into(),
        verifier,
        available: AtomicBool::new(true),
        revoke_at_stage: AtomicBool::new(false),
        calls: AtomicUsize::new(0),
        staged: AtomicUsize::new(0),
        claim_authority: Mutex::new(None),
        claim_cut: AtomicUsize::new(0),
    })
}
#[cfg(feature = "sqlite")]
fn runtime_effect_host(
    path: &std::path::Path,
    resolver: Arc<EffectRuntimeResolver>,
    fixture: &Fixture,
) -> determa_state::authority::SqliteNativeEffectHost<EffectRuntimeResolver> {
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
fn native_runtime_binding_revoked_after_sql_staging_rolls_back_each_effect_operation() {
    for operation in ["creation", "admission", "production"] {
        let directory = EffectTestDirectory::new();
        let path = directory.path().join("authority.sqlite");
        let fixture = Fixture::new();
        let resolver = runtime_effect_resolver(&path);
        let host = runtime_effect_host(&path, resolver.clone(), &fixture);
        host.setup_schema().unwrap();
        host.allocate_scope().unwrap();
        if operation != "creation" {
            host.create(
                &resolver.bundle,
                "workflow",
                "root",
                "create-root",
                &determa_state::Bindings::default(),
            )
            .unwrap();
        }
        let mut delivery = Value::Null;
        if operation != "creation" {
            let (checkpoint, _, _) = native_snapshot(&path);
            delivery = production_delivery(&checkpoint, "invoke-1");
            if operation == "production" {
                host.admit("root", "admit-1", &delivery, &effect_guard(&checkpoint))
                    .unwrap();
            }
        }
        let prior = if operation == "creation" {
            None
        } else {
            Some(native_snapshot(&path))
        };
        resolver.revoke_at_stage.store(true, Ordering::SeqCst);
        let result = match operation {
            "creation" => host.create(
                &resolver.bundle,
                "workflow",
                "root",
                "create-root",
                &determa_state::Bindings::default(),
            ),
            "admission" => host.admit(
                "root",
                "admit-1",
                &delivery,
                &effect_guard(&prior.as_ref().unwrap().0),
            ),
            _ => host.produce(
                "root",
                "produce-1",
                &production_request(&prior.as_ref().unwrap().0),
            ),
        };
        assert!(result.is_err(), "revocation must refuse {operation}");
        assert_eq!(resolver.staged.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.destination.calls.load(Ordering::SeqCst), 0);
        if let Some(prior) = prior {
            assert_eq!(native_snapshot(&path), prior);
        } else {
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
                assert_eq!(count, 0);
            }
        }
    }
}
#[cfg(feature = "sqlite")]
#[test]
fn retained_native_responses_replay_without_resolver_or_revoked_runtime_provider() {
    let directory = EffectTestDirectory::new();
    let path = directory.path().join("authority.sqlite");
    let fixture = Fixture::new();
    let resolver = runtime_effect_resolver(&path);
    let host = runtime_effect_host(&path, resolver.clone(), &fixture);
    host.setup_schema().unwrap();
    host.allocate_scope().unwrap();
    let creation = host
        .create(
            &resolver.bundle,
            "workflow",
            "root",
            "create-root",
            &determa_state::Bindings::default(),
        )
        .unwrap();
    let (checkpoint, _, _) = native_snapshot(&path);
    let delivery = production_delivery(&checkpoint, "invoke-1");
    let admission = host
        .admit("root", "admit-1", &delivery, &effect_guard(&checkpoint))
        .unwrap();
    let (admitted, _, _) = native_snapshot(&path);
    let request = production_request(&admitted);
    let production = host.produce("root", "produce-1", &request).unwrap();
    let prior = native_snapshot(&path);
    resolver.available.store(false, Ordering::SeqCst);
    resolver.verifier.valid.store(false, Ordering::SeqCst);
    resolver.calls.store(0, Ordering::SeqCst);
    resolver.verifier.checks.store(0, Ordering::SeqCst);
    assert_eq!(
        host.create(
            &resolver.bundle,
            "workflow",
            "root",
            "create-root",
            &determa_state::Bindings::default()
        )
        .unwrap(),
        creation
    );
    assert_eq!(
        host.admit("root", "admit-1", &delivery, &effect_guard(&checkpoint))
            .unwrap(),
        admission
    );
    assert_eq!(
        host.produce("root", "produce-1", &request).unwrap(),
        production
    );
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
    assert_eq!(resolver.verifier.checks.load(Ordering::SeqCst), 0);
    assert_eq!(native_snapshot(&path), prior);
    assert!(host.produce("root", "new-produce", &request).is_err());
    assert!(resolver.calls.load(Ordering::SeqCst) > 0);
}

#[cfg(feature = "sqlite")]
struct EffectWorkerAuthority {
    report_right: AtomicBool,
    lease_duration: std::sync::atomic::AtomicI64,
    path: std::path::PathBuf,
    now: std::sync::atomic::AtomicI64,
    authorized: AtomicBool,
    principal: Mutex<String>,
    fail_clock: AtomicBool,
    revoke_at_stage: AtomicBool,
    expire_at_stage: AtomicBool,
    staged: AtomicUsize,
}
#[cfg(feature = "sqlite")]
impl determa_state::authority::NativeEffectWorkerAuthority for EffectWorkerAuthority {
    fn authenticate(
        &self,
        credential: &[u8],
    ) -> Result<determa_state::authority::NativeAuthorityInvocation, String> {
        if credential != b"private-native-credential" || !self.authorized.load(Ordering::SeqCst) {
            return Err("unauthorized_scope".into());
        }
        if self.revoke_at_stage.load(Ordering::SeqCst)
            || self.expire_at_stage.load(Ordering::SeqCst)
        {
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
                    self.staged.fetch_add(1, Ordering::SeqCst);
                    if self.revoke_at_stage.load(Ordering::SeqCst) {
                        return Err("unauthorized_scope".into());
                    }
                    self.now.store(20, Ordering::SeqCst);
                }
                Err(error) => panic!("unexpected native claim probe: {error}"),
            }
        }
        Ok(determa_state::authority::NativeAuthorityInvocation {
            authenticated_principal: self.principal.lock().unwrap().clone(),
            authorized_scopes: BTreeSet::from(["scope-one".into()]),
            operation_rights: if self.report_right.load(Ordering::SeqCst) {
                BTreeSet::from(["claim_effect".into(), "submit_effect_result".into()])
            } else {
                BTreeSet::from(["claim_effect".into()])
            },
        })
    }
    fn lease_duration_ns(&self) -> Result<i64, String> {
        Ok(self.lease_duration.load(Ordering::SeqCst))
    }
    fn trusted_now(&self) -> Result<i64, String> {
        if self.fail_clock.load(Ordering::SeqCst) {
            return Err("clock_unavailable".into());
        }
        Ok(self.now.load(Ordering::SeqCst))
    }
}
#[cfg(feature = "sqlite")]
fn effect_worker_authority(path: &std::path::Path) -> Arc<EffectWorkerAuthority> {
    Arc::new(EffectWorkerAuthority {
        report_right: AtomicBool::new(true),
        lease_duration: std::sync::atomic::AtomicI64::new(10),
        path: path.into(),
        now: std::sync::atomic::AtomicI64::new(10),
        authorized: AtomicBool::new(true),
        principal: Mutex::new("worker-one".into()),
        fail_clock: AtomicBool::new(false),
        revoke_at_stage: AtomicBool::new(false),
        expire_at_stage: AtomicBool::new(false),
        staged: AtomicUsize::new(0),
    })
}
#[cfg(feature = "sqlite")]
#[test]
fn actual_authenticated_effect_claim_commits_fence_before_dispatch_and_replays_after_expiry() {
    let directory = EffectTestDirectory::new();
    let path = directory.path().join("authority.sqlite");
    let fixture = Fixture::new();
    let bundle = effect_bundle();
    let authority = effect_worker_authority(&path);
    let host = effect_host(&path, effect_resolver(&bundle), &fixture)
        .with_worker_authority(authority.clone());
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
    let prior = native_snapshot(&path);
    let request = determa_state::authority::NativeEffectClaimRequest {
        effect_id: prior.1["journal"]["effect_records"][0]["effect_id"]
            .as_str()
            .unwrap()
            .into(),
    };
    assert!(host.claim("root", "claim-1", &request, b"wrong").is_err());
    assert_eq!(native_snapshot(&path), prior);
    let first = host
        .claim("root", "claim-1", &request, b"private-native-credential")
        .unwrap();
    let schema: Value =
        serde_json::from_str(include_str!("../schema/host-effect-claim-v1.schema.json")).unwrap();
    jsonschema::validator_for(&schema)
        .unwrap()
        .validate(&first["body"]["claim"])
        .unwrap();
    let after = native_snapshot(&path);
    assert_eq!(after.0, prior.0);
    assert_eq!(after.2["scope_generation"], "2");
    assert_eq!(
        after.1["journal"]["effect_records"][0]["invocation_state"],
        "leased"
    );
    assert_eq!(
        after.1["journal"]["effect_records"][0]["attempt_fence"],
        "1"
    );
    assert_eq!(fixture.destination.calls.load(Ordering::SeqCst), 0);
    assert!(!serde_json_canonicalizer::to_vec(&after.1)
        .unwrap()
        .windows(b"private-native-credential".len())
        .any(|part| part == b"private-native-credential"));
    authority.now.store(20, Ordering::SeqCst);
    authority.fail_clock.store(true, Ordering::SeqCst);
    assert_eq!(
        host.claim("root", "claim-1", &request, b"private-native-credential")
            .unwrap(),
        first
    );
    assert!(host
        .claim("root", "claim-2", &request, b"private-native-credential")
        .is_err());
    *authority.principal.lock().unwrap() = "worker-two".into();
    assert!(host
        .claim("root", "claim-1", &request, b"private-native-credential")
        .is_err());
    *authority.principal.lock().unwrap() = "worker-one".into();
    authority.authorized.store(false, Ordering::SeqCst);
    assert!(host
        .claim("root", "claim-1", &request, b"private-native-credential")
        .is_err());
    assert_eq!(native_snapshot(&path), after);
}
#[cfg(feature = "sqlite")]
#[test]
fn actual_effect_claim_rechecks_authorization_and_expiry_after_sql_staging() {
    for revoke in [false, true] {
        let directory = EffectTestDirectory::new();
        let path = directory.path().join("authority.sqlite");
        let fixture = Fixture::new();
        let bundle = effect_bundle();
        let authority = effect_worker_authority(&path);
        let host = effect_host(&path, effect_resolver(&bundle), &fixture)
            .with_worker_authority(authority.clone());
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
        let prior = native_snapshot(&path);
        let request = determa_state::authority::NativeEffectClaimRequest {
            effect_id: prior.1["journal"]["effect_records"][0]["effect_id"]
                .as_str()
                .unwrap()
                .into(),
        };
        authority.revoke_at_stage.store(revoke, Ordering::SeqCst);
        authority.expire_at_stage.store(!revoke, Ordering::SeqCst);
        assert!(host
            .claim("root", "claim-1", &request, b"private-native-credential")
            .is_err());
        assert_eq!(authority.staged.load(Ordering::SeqCst), 1);
        assert_eq!(native_snapshot(&path), prior);
        assert_eq!(fixture.destination.calls.load(Ordering::SeqCst), 0);
    }
}

#[cfg(all(feature = "sqlite", unix))]
#[test]
fn native_effect_claim_crash_child() {
    let Some(cut) = std::env::var_os("DETERMA_NATIVE_CLAIM_TEST_CUT") else {
        return;
    };
    let path =
        std::path::PathBuf::from(std::env::var_os("DETERMA_NATIVE_CLAIM_TEST_PATH").unwrap());
    let marker =
        std::path::PathBuf::from(std::env::var_os("DETERMA_NATIVE_CLAIM_TEST_MARKER").unwrap());
    let fixture = Fixture::new();
    let bundle = effect_bundle();
    let host = effect_host(&path, effect_resolver(&bundle), &fixture)
        .with_worker_authority(effect_worker_authority(&path));
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
    let request = determa_state::authority::NativeEffectClaimRequest {
        effect_id: snapshot.1["journal"]["effect_records"][0]["effect_id"]
            .as_str()
            .unwrap()
            .into(),
    };
    if cut == "staged" {
        fixture
            .destination
            .binding_checks
            .store(0, Ordering::SeqCst);
        fixture
            .destination
            .fail_binding_at
            .store(1, Ordering::SeqCst);
        *fixture.destination.staged_marker.lock().unwrap() = Some(marker.clone());
    } else {
        assert_eq!(cut, "committed");
    }
    let response = host
        .claim("root", "claim-1", &request, b"private-native-credential")
        .unwrap();
    publish_admission_cut_marker(&marker, &serde_json::to_vec(&response).unwrap());
    std::thread::sleep(std::time::Duration::from_secs(60));
}
#[cfg(all(feature = "sqlite", unix))]
#[test]
fn real_sigkill_claim_before_and_after_commit_preserves_exact_fence_and_first_response() {
    for cut in ["staged", "committed"] {
        let directory = EffectTestDirectory::new();
        let path = directory.path().join("authority.sqlite");
        let marker = directory.path().join("cut-marker");
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "native_effect_claim_crash_child", "--nocapture"])
            .env("DETERMA_NATIVE_CLAIM_TEST_CUT", cut)
            .env("DETERMA_NATIVE_CLAIM_TEST_PATH", &path)
            .env("DETERMA_NATIVE_CLAIM_TEST_MARKER", &marker)
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
        assert!(reached, "native claim {cut} cut not reached");
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(9));
        let prior = native_snapshot(&path);
        assert_eq!(prior.0["revision"], "0");
        assert_eq!(
            prior.2["scope_generation"],
            if cut == "committed" { "2" } else { "1" }
        );
        assert_eq!(
            prior.1["journal"]["effect_records"][0]["attempt_fence"],
            if cut == "committed" { "1" } else { "0" }
        );
        let fixture = Fixture::new();
        let bundle = effect_bundle();
        let host = effect_host(&path, effect_resolver(&bundle), &fixture)
            .with_worker_authority(effect_worker_authority(&path));
        let request = determa_state::authority::NativeEffectClaimRequest {
            effect_id: prior.1["journal"]["effect_records"][0]["effect_id"]
                .as_str()
                .unwrap()
                .into(),
        };
        let first = host
            .claim("root", "claim-1", &request, b"private-native-credential")
            .unwrap();
        if cut == "committed" {
            assert_eq!(
                first,
                serde_json::from_slice::<Value>(&std::fs::read(&marker).unwrap()).unwrap()
            );
        }
        let after = native_snapshot(&path);
        assert_eq!(after.2["scope_generation"], "2");
        assert_eq!(
            host.claim("root", "claim-1", &request, b"private-native-credential")
                .unwrap(),
            first
        );
        assert_eq!(native_snapshot(&path), after);
        assert_eq!(fixture.destination.calls.load(Ordering::SeqCst), 0);
    }
}

#[cfg(feature = "sqlite")]
#[test]
fn final_staged_resolver_cannot_expire_or_revoke_the_native_claim_before_commit() {
    for cut in [1, 2, 3] {
        let directory = EffectTestDirectory::new();
        let path = directory.path().join("authority.sqlite");
        let fixture = Fixture::new();
        let resolver = runtime_effect_resolver(&path);
        let authority = effect_worker_authority(&path);
        let host = runtime_effect_host(&path, resolver.clone(), &fixture)
            .with_worker_authority(authority.clone());
        host.setup_schema().unwrap();
        host.allocate_scope().unwrap();
        host.create(
            &resolver.bundle,
            "workflow",
            "root",
            "create-root",
            &determa_state::Bindings::default(),
        )
        .unwrap();
        let prior = native_snapshot(&path);
        let request = determa_state::authority::NativeEffectClaimRequest {
            effect_id: prior.1["journal"]["effect_records"][0]["effect_id"]
                .as_str()
                .unwrap()
                .into(),
        };
        *resolver.claim_authority.lock().unwrap() = Some(authority);
        resolver.claim_cut.store(cut, Ordering::SeqCst);
        assert!(host
            .claim("root", "claim-1", &request, b"private-native-credential")
            .is_err());
        assert_eq!(resolver.staged.load(Ordering::SeqCst), 1);
        assert_eq!(native_snapshot(&path), prior);
        assert_eq!(fixture.destination.calls.load(Ordering::SeqCst), 0);
    }
}
#[cfg(feature = "sqlite")]
#[test]
fn native_claim_host_policy_rejects_invalid_duration_and_overflow_without_mutation() {
    let directory = EffectTestDirectory::new();
    let path = directory.path().join("authority.sqlite");
    let fixture = Fixture::new();
    let bundle = effect_bundle();
    let authority = effect_worker_authority(&path);
    let host = effect_host(&path, effect_resolver(&bundle), &fixture)
        .with_worker_authority(authority.clone());
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
    let prior = native_snapshot(&path);
    let request = determa_state::authority::NativeEffectClaimRequest {
        effect_id: prior.1["journal"]["effect_records"][0]["effect_id"]
            .as_str()
            .unwrap()
            .into(),
    };
    for duration in [0, -1, i64::MAX] {
        authority.lease_duration.store(duration, Ordering::SeqCst);
        assert!(host
            .claim("root", "claim-1", &request, b"private-native-credential")
            .is_err());
        assert_eq!(native_snapshot(&path), prior);
    }
    authority.lease_duration.store(10, Ordering::SeqCst);
    let first = host
        .claim("root", "claim-1", &request, b"private-native-credential")
        .unwrap();
    assert_eq!(first["body"]["claim"]["expires_at"], "20");
    authority.lease_duration.store(-1, Ordering::SeqCst);
    authority.now.store(i64::MAX, Ordering::SeqCst);
    assert_eq!(
        host.claim("root", "claim-1", &request, b"private-native-credential")
            .unwrap(),
        first
    );
}

#[cfg(feature = "sqlite")]
fn native_result_request(document: &Value, kind: &str) -> Value {
    let record = &document["journal"]["effect_records"][0];
    json!({"effect_id":record["effect_id"],"operation_token":record["operation_token"],
        "attempt_fence":record["attempt_fence"],"outcome_kind":kind,
        "payload":if kind == "succeeded" { json!(["map", [["provider_reference", ["string", "native-receipt-1"]]]]) } else { json!(["map",[]]) }})
}
#[cfg(feature = "sqlite")]
#[test]
fn authenticated_native_reports_commit_immutable_outcomes_or_ambiguity_without_admitting_results() {
    for kind in ["succeeded", "cancelled", "ambiguous"] {
        let directory = EffectTestDirectory::new();
        let path = directory.path().join("authority.sqlite");
        let fixture = Fixture::new();
        let bundle = effect_bundle();
        let resolver = effect_resolver(&bundle);
        let authority = effect_worker_authority(&path);
        let host =
            effect_host(&path, resolver.clone(), &fixture).with_worker_authority(authority.clone());
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
        let initial = native_snapshot(&path);
        let claim_request = determa_state::authority::NativeEffectClaimRequest {
            effect_id: initial.1["journal"]["effect_records"][0]["effect_id"]
                .as_str()
                .unwrap()
                .into(),
        };
        host.claim(
            "root",
            "claim-1",
            &claim_request,
            b"private-native-credential",
        )
        .unwrap();
        let prior = native_snapshot(&path);
        let request = native_result_request(&prior.1, kind);
        let first = host
            .record_result("root", "report-1", &request, b"private-native-credential")
            .unwrap();
        let after = native_snapshot(&path);
        assert_eq!(after.0, prior.0);
        assert_eq!(after.2["scope_generation"], "3");
        assert_eq!(
            after.1["journal"]["effect_records"][0]["attempt_records"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            after.1["journal"]["effect_records"][0]["invocation_state"],
            if kind == "ambiguous" {
                "ambiguous"
            } else {
                "outcome_recorded"
            }
        );
        assert!(after.1["journal"]["effect_records"][0]["admission_receipt"].is_null());
        assert_eq!(
            after.1["journal"]["effect_records"][0]["outcome"].is_null(),
            kind == "ambiguous"
        );
        assert_eq!(fixture.destination.calls.load(Ordering::SeqCst), 0);
        authority.now.store(20, Ordering::SeqCst);
        authority.fail_clock.store(true, Ordering::SeqCst);
        assert_eq!(
            host.record_result("root", "report-1", &request, b"private-native-credential")
                .unwrap(),
            first
        );
        let mut changed = request.clone();
        changed["payload"] = json!(["map", [["other", ["string", "changed"]]]]);
        assert!(host
            .record_result("root", "report-1", &changed, b"private-native-credential")
            .is_err());
        assert_eq!(native_snapshot(&path), after);
        drop(host);
        let reopened = effect_host(&path, resolver, &fixture).with_worker_authority(authority);
        assert_eq!(
            reopened
                .record_result("root", "report-1", &request, b"private-native-credential")
                .unwrap(),
            first
        );
        assert_eq!(native_snapshot(&path), after);
    }
}
#[cfg(feature = "sqlite")]
#[test]
fn native_result_refusals_never_allocate_reports_or_change_the_checkpoint() {
    let directory = EffectTestDirectory::new();
    let path = directory.path().join("authority.sqlite");
    let fixture = Fixture::new();
    let bundle = effect_bundle();
    let authority = effect_worker_authority(&path);
    let host = effect_host(&path, effect_resolver(&bundle), &fixture)
        .with_worker_authority(authority.clone());
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
    let initial = native_snapshot(&path);
    let before_claim = native_result_request(&initial.1, "succeeded");
    assert!(host
        .record_result(
            "root",
            "report-1",
            &before_claim,
            b"private-native-credential"
        )
        .is_err());
    assert_eq!(native_snapshot(&path), initial);
    host.claim(
        "root",
        "claim-1",
        &determa_state::authority::NativeEffectClaimRequest {
            effect_id: before_claim["effect_id"].as_str().unwrap().into(),
        },
        b"private-native-credential",
    )
    .unwrap();
    let prior = native_snapshot(&path);
    let request = native_result_request(&prior.1, "succeeded");
    for field in [
        "operation_token",
        "attempt_fence",
        "outcome_kind",
        "payload",
        "extra",
    ] {
        let mut wrong = request.clone();
        wrong[field] = match field {
            "attempt_fence" => json!("0"),
            "outcome_kind" => json!("retryable_failure"),
            "payload" => json!(["map", []]),
            _ => json!("wrong"),
        };
        assert!(host
            .record_result("root", "report-1", &wrong, b"private-native-credential")
            .is_err());
        assert_eq!(native_snapshot(&path), prior);
    }
    for payload in [
        json!([
            "map",
            [
                ["duplicate", ["string", "a"]],
                ["duplicate", ["string", "b"]]
            ]
        ]),
        json!(["map", [["z", ["string", "a"]], ["a", ["string", "b"]]]]),
    ] {
        let mut wrong = request.clone();
        wrong["outcome_kind"] = json!("ambiguous");
        wrong["payload"] = payload;
        assert!(host
            .record_result("root", "report-1", &wrong, b"private-native-credential")
            .is_err());
        assert_eq!(native_snapshot(&path), prior);
    }
    authority.report_right.store(false, Ordering::SeqCst);
    assert!(host
        .record_result("root", "report-1", &request, b"private-native-credential")
        .is_err());
    authority.report_right.store(true, Ordering::SeqCst);
    *authority.principal.lock().unwrap() = "worker-two".into();
    assert!(host
        .record_result("root", "report-1", &request, b"private-native-credential")
        .is_err());
    *authority.principal.lock().unwrap() = "worker-one".into();
    authority.now.store(20, Ordering::SeqCst);
    assert!(host
        .record_result("root", "report-1", &request, b"private-native-credential")
        .is_err());
    assert_eq!(native_snapshot(&path), prior);
}
#[cfg(feature = "sqlite")]
#[test]
fn actual_result_report_rechecks_final_authentication_and_clock_after_provider_callbacks() {
    for cut in [1, 2, 3] {
        let directory = EffectTestDirectory::new();
        let path = directory.path().join("authority.sqlite");
        let fixture = Fixture::new();
        let resolver = runtime_effect_resolver(&path);
        let authority = effect_worker_authority(&path);
        let host = runtime_effect_host(&path, resolver.clone(), &fixture)
            .with_worker_authority(authority.clone());
        host.setup_schema().unwrap();
        host.allocate_scope().unwrap();
        host.create(
            &resolver.bundle,
            "workflow",
            "root",
            "create-root",
            &determa_state::Bindings::default(),
        )
        .unwrap();
        let initial = native_snapshot(&path);
        host.claim(
            "root",
            "claim-1",
            &determa_state::authority::NativeEffectClaimRequest {
                effect_id: initial.1["journal"]["effect_records"][0]["effect_id"]
                    .as_str()
                    .unwrap()
                    .into(),
            },
            b"private-native-credential",
        )
        .unwrap();
        let prior = native_snapshot(&path);
        let request = native_result_request(&prior.1, "succeeded");
        *resolver.claim_authority.lock().unwrap() = Some(authority);
        resolver.claim_cut.store(cut, Ordering::SeqCst);
        assert!(host
            .record_result("root", "report-1", &request, b"private-native-credential")
            .is_err());
        assert_eq!(resolver.staged.load(Ordering::SeqCst), 1);
        assert_eq!(native_snapshot(&path), prior);
        assert_eq!(fixture.destination.calls.load(Ordering::SeqCst), 0);
    }
}

#[cfg(all(feature = "sqlite", unix))]
#[test]
fn native_effect_outcome_crash_child() {
    let Some(cut) = std::env::var_os("DETERMA_NATIVE_OUTCOME_TEST_CUT") else {
        return;
    };
    let path =
        std::path::PathBuf::from(std::env::var_os("DETERMA_NATIVE_OUTCOME_TEST_PATH").unwrap());
    let marker =
        std::path::PathBuf::from(std::env::var_os("DETERMA_NATIVE_OUTCOME_TEST_MARKER").unwrap());
    let fixture = Fixture::new();
    let bundle = effect_bundle();
    let host = effect_host(&path, effect_resolver(&bundle), &fixture)
        .with_worker_authority(effect_worker_authority(&path));
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
    host.claim(
        "root",
        "claim-1",
        &determa_state::authority::NativeEffectClaimRequest {
            effect_id: snapshot.1["journal"]["effect_records"][0]["effect_id"]
                .as_str()
                .unwrap()
                .into(),
        },
        b"private-native-credential",
    )
    .unwrap();
    let request = native_result_request(&native_snapshot(&path).1, "succeeded");
    if cut == "staged" {
        fixture
            .destination
            .binding_checks
            .store(0, Ordering::SeqCst);
        fixture
            .destination
            .fail_binding_at
            .store(1, Ordering::SeqCst);
        *fixture.destination.staged_marker.lock().unwrap() = Some(marker.clone());
    } else {
        assert_eq!(cut, "committed");
    }
    let response = host
        .record_result("root", "report-1", &request, b"private-native-credential")
        .unwrap();
    publish_admission_cut_marker(&marker, &serde_json::to_vec(&response).unwrap());
    std::thread::sleep(std::time::Duration::from_secs(60));
}
#[cfg(all(feature = "sqlite", unix))]
#[test]
fn real_sigkill_outcome_before_and_after_commit_preserves_immutable_report_and_first_response() {
    for cut in ["staged", "committed"] {
        let directory = EffectTestDirectory::new();
        let path = directory.path().join("authority.sqlite");
        let marker = directory.path().join("cut-marker");
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "native_effect_outcome_crash_child",
                "--nocapture",
            ])
            .env("DETERMA_NATIVE_OUTCOME_TEST_CUT", cut)
            .env("DETERMA_NATIVE_OUTCOME_TEST_PATH", &path)
            .env("DETERMA_NATIVE_OUTCOME_TEST_MARKER", &marker)
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
        assert!(reached, "native outcome {cut} cut not reached");
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(9));
        let prior = native_snapshot(&path);
        assert_eq!(prior.0["revision"], "0");
        assert_eq!(
            prior.2["scope_generation"],
            if cut == "committed" { "3" } else { "2" }
        );
        assert_eq!(
            prior.1["journal"]["effect_records"][0]["outcome"].is_null(),
            cut != "committed"
        );
        let fixture = Fixture::new();
        let bundle = effect_bundle();
        let host = effect_host(&path, effect_resolver(&bundle), &fixture)
            .with_worker_authority(effect_worker_authority(&path));
        let request = native_result_request(&prior.1, "succeeded");
        let first = host
            .record_result("root", "report-1", &request, b"private-native-credential")
            .unwrap();
        if cut == "committed" {
            assert_eq!(
                first,
                serde_json::from_slice::<Value>(&std::fs::read(&marker).unwrap()).unwrap()
            );
        }
        let after = native_snapshot(&path);
        assert_eq!(after.2["scope_generation"], "3");
        assert_eq!(
            host.record_result("root", "report-1", &request, b"private-native-credential")
                .unwrap(),
            first
        );
        assert_eq!(native_snapshot(&path), after);
        assert_eq!(fixture.destination.calls.load(Ordering::SeqCst), 0);
    }
}

#[cfg(feature = "sqlite")]
#[test]
fn new_native_report_refuses_a_replacement_handle_and_keeps_the_original_route_pin() {
    let directory = EffectTestDirectory::new();
    let path = directory.path().join("authority.sqlite");
    let fixture = Fixture::new();
    let bundle = effect_bundle();
    let resolver = effect_resolver(&bundle);
    let authority = effect_worker_authority(&path);
    let host =
        effect_host(&path, resolver.clone(), &fixture).with_worker_authority(authority.clone());
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
    let initial = native_snapshot(&path);
    host.claim(
        "root",
        "claim-1",
        &determa_state::authority::NativeEffectClaimRequest {
            effect_id: initial.1["journal"]["effect_records"][0]["effect_id"]
                .as_str()
                .unwrap()
                .into(),
        },
        b"private-native-credential",
    )
    .unwrap();
    let prior = native_snapshot(&path);
    let request = native_result_request(&prior.1, "succeeded");
    drop(host);
    let replacement = Fixture::new();
    *replacement.destination.binding.lock().unwrap() = hash('d');
    let mut configuration = configuration();
    configuration["destination_binding_digest"] = json!(hash('d'));
    let replacement_handler = replacement
        .registry
        .configure_native_handler(&descriptor(), &configuration)
        .unwrap();
    let mut route = effect_route();
    route.destination_binding_digest = hash('d');
    let host = determa_state::authority::SqliteNativeEffectHost::open(
        &path,
        "scope-one".into(),
        "owner".into(),
        "host-one".into(),
        resolver.clone(),
        route,
        replacement_handler,
    )
    .unwrap()
    .with_worker_authority(authority.clone());
    assert!(host
        .record_result("root", "report-1", &request, b"private-native-credential")
        .is_err());
    assert_eq!(native_snapshot(&path), prior);
    assert_eq!(replacement.destination.calls.load(Ordering::SeqCst), 0);
    drop(host);
    let mut changed_route = effect_route();
    changed_route.generation = "999".into();
    changed_route.result_mapping[0]["event"] = json!("undeclared_replacement_event");
    changed_route.result_mapping[0]["result_slot"] = json!("replacement-slot");
    let host = determa_state::authority::SqliteNativeEffectHost::open(
        &path,
        "scope-one".into(),
        "owner".into(),
        "host-one".into(),
        resolver,
        changed_route,
        fixture.handler(),
    )
    .unwrap()
    .with_worker_authority(authority);
    let first = host
        .record_result("root", "report-1", &request, b"private-native-credential")
        .unwrap();
    let after = native_snapshot(&path);
    assert_eq!(
        after.1["journal"]["effect_records"][0]["result_mapping"],
        prior.1["journal"]["effect_records"][0]["result_mapping"]
    );
    use sha2::{Digest, Sha256};
    let expected = format!(
        "sha256:{:x}",
        Sha256::digest(
            serde_json_canonicalizer::to_vec(&json!([
                "determa-effect-result-event-1",
                request["effect_id"],
                "success"
            ]))
            .unwrap()
        )
    );
    assert_eq!(first["body"]["result_event_id"], expected);
}
