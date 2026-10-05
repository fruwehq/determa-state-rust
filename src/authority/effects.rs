//! Native creation, external admission and production over the authority's SQLite transaction.
//! First authenticated claims only; no imported participant activation, complete
//! worker/effects profile, archive or recovery claim.

use super::{canonical, failure, hash, AuthorityError, GuardedSqliteExecutionStore};
use crate::checkpoint::{self, DurableStoreMode, ExecutionStore};
use crate::extensions::VerifiedNativeHandler;
use crate::format1::effect_journal::ValidatedEffectJournal;
use crate::format1::{Bindings, Bundle, DefinitionResolver};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

/// Immutable native route configuration. A reference or destination digest alone
/// is not a handler: construction also requires the actual verified loaded handle.
pub struct NativeEffectRoute {
    pub generation: String,
    pub handler_reference: Value,
    pub destination_binding_digest: String,
    pub result_mapping: Value,
    pub idempotency_policy: String,
}

/// Owner-local production arguments; these fields grant no worker authority.
pub struct NativeEffectProductionRequest {
    pub processing_request: checkpoint::ProcessingRequest,
    pub operation_token: String,
    pub route_configuration_generation: String,
    pub guard: checkpoint::MutationGuard,
}

/// Trusted host-installed transport authentication and signed-nanosecond clock.
/// Portable principal fields and handler objects cannot construct worker rights.
pub trait NativeEffectWorkerAuthority: Send + Sync {
    fn authenticate(&self, credential: &[u8]) -> Result<super::NativeAuthorityInvocation, String>;
    fn trusted_now(&self) -> Result<i64, String>;
    /// Positive bounded host lease duration in nanoseconds; never worker input.
    fn lease_duration_ns(&self) -> Result<i64, String>;
}

pub struct NativeEffectClaimRequest {
    pub effect_id: String,
}

pub(super) fn canonical_native_time(value: &Value) -> Result<i64, AuthorityError> {
    let text = value
        .as_str()
        .ok_or_else(|| failure("native time absent"))?;
    let parsed: i64 = text.parse().map_err(failure)?;
    if parsed.to_string() != text {
        return Err(failure("noncanonical native time"));
    }
    Ok(parsed)
}

pub struct SqliteNativeEffectHost<R> {
    store: GuardedSqliteExecutionStore<R>,
    resolver: Arc<R>,
    scope: String,
    route: NativeEffectRoute,
    handler: VerifiedNativeHandler,
    worker_authority: Option<Arc<dyn NativeEffectWorkerAuthority>>,
}

impl<R: DefinitionResolver + Send + Sync + 'static> SqliteNativeEffectHost<R> {
    pub fn open(
        path: impl AsRef<Path>,
        scope: String,
        owner: String,
        host_binding: String,
        resolver: Arc<R>,
        route: NativeEffectRoute,
        handler: VerifiedNativeHandler,
    ) -> Result<Self, AuthorityError> {
        let generation_valid = route.generation == "0"
            || (!route.generation.is_empty()
                && !route.generation.starts_with('0')
                && route.generation.bytes().all(|byte| byte.is_ascii_digit()));
        if !generation_valid
            || !route.result_mapping.is_array()
            || !matches!(
                route.idempotency_policy.as_str(),
                "destination_deduplicates" | "reconcile_before_retry"
            )
        {
            return Err(failure("invalid native route configuration"));
        }
        handler
            .verify(&route.handler_reference, &route.destination_binding_digest)
            .map_err(failure)?;
        Ok(Self {
            store: GuardedSqliteExecutionStore::open(
                path,
                DurableStoreMode::new(
                    checkpoint::ReceiptRetentionMode::Permanent,
                    checkpoint::OutboxRetentionMode::Strict,
                ),
                scope.clone(),
                owner,
                host_binding,
                resolver.clone(),
            )
            .map_err(failure)?,
            resolver,
            scope,
            route,
            handler,
            worker_authority: None,
        })
    }

    /// Configure an actual trusted native authority, never a portable credential.
    pub fn with_worker_authority(
        mut self,
        authority: Arc<dyn NativeEffectWorkerAuthority>,
    ) -> Self {
        self.worker_authority = Some(authority);
        self
    }

    /// Explicit setup never repairs an already allocated participant's evidence.
    pub fn setup_schema(&self) -> Result<(), AuthorityError> {
        self.store.initialize_schema().map_err(failure)
    }

    pub fn allocate_scope(&self) -> Result<bool, AuthorityError> {
        self.store.allocate_scope().map_err(failure)
    }

    /// Create from actual compiled source, never from an imported checkpoint or
    /// journal. Exact first response, checkpoint, helper role and authority receipt
    /// become durable in one BEGIN IMMEDIATE transaction before returning.
    pub fn create(
        &self,
        bundle: &Bundle,
        machine_id: &str,
        root: &str,
        creation_id: &str,
        bindings: &Bindings,
    ) -> Result<Value, AuthorityError> {
        let request_digest =
            checkpoint::creation_request_digest(bundle, machine_id, root, creation_id, bindings)
                .map_err(failure)?;
        let original_request = json!({"operation_kind":"creation","request_digest":request_digest});
        if let Some(saved) = self
            .store
            .native_effect_replay(root, creation_id, &original_request)
            .map_err(failure)?
        {
            return Ok(saved);
        }
        let resolved = self
            .resolver
            .resolve_definition(&bundle.fingerprint)
            .ok_or_else(|| failure("native creation definition unavailable"))?;
        if !resolved.trusted
            || resolved.bundle.fingerprint != bundle.fingerprint
            || resolved.bundle.normalized != bundle.normalized
            || checkpoint::creation_request_digest(
                &resolved.bundle,
                machine_id,
                root,
                creation_id,
                bindings,
            )
            .map_err(failure)?
                != request_digest
        {
            return Err(failure("native creation definition identity mismatch"));
        }
        // Caller bundle fields cannot substitute executable compiled structures.
        // The configured trusted resolver supplies the actual source to execute.
        let bundle = &resolved.bundle;
        crate::format1::effect_journal::validate_route_mapping(
            bundle,
            machine_id,
            &self.route.result_mapping,
        )
        .map_err(failure)?;
        self.handler
            .verify(
                &self.route.handler_reference,
                &self.route.destination_binding_digest,
            )
            .map_err(failure)?;
        let (checkpoint, response) = checkpoint::create_with_response(bundle, machine_id, root, creation_id, bindings, (None, None), json!({"mode":"permanent","permanent_replay_eligible":true,"pruned_through_receipt_sequence":null,"policy_identifier":null})).map_err(failure)?;
        let runtime = checkpoint.value()["root_record"]["aggregate_state"]["runtimes"]
            .as_array()
            .and_then(|runtimes| {
                runtimes
                    .iter()
                    .find(|runtime| runtime["identity_origin"]["kind"] == "root")
            })
            .ok_or_else(|| failure("actual created root runtime absent"))?;
        let target = json!({"root_instance_id":root,"runtime_id":runtime["runtime_id"],"runtime_incarnation":runtime["identity_origin"]});
        let mut records = Vec::new();
        for item in checkpoint.value()["pending_outbox_intents"]
            .as_array()
            .ok_or_else(|| failure("actual created outbox absent"))?
        {
            let intent = &item["intent"];
            let token = intent["correlation_id"]
                .as_str()
                .filter(|token| !token.is_empty())
                .ok_or_else(|| failure("effect business token absent"))?;
            records.push(json!({"effect_id":intent["effect_id"],"operation_token":token,
                "intent_digest":hash(&json!(["determa-outbox-intent-digest-1","1",root,intent]))?,
                "handler_reference":self.route.handler_reference,"destination_binding_digest":self.route.destination_binding_digest,
                "route_configuration_generation":self.route.generation,"result_mapping":self.route.result_mapping,
                "target":target,"idempotency_policy":self.route.idempotency_policy,
                "attempt_fence":"0","attempt_records":[],"invocation_state":"unclaimed",
                "outcome":null,"result_event_id":null,"admission_receipt":null,"cancellation":null}));
        }
        records.sort_by(|left, right| {
            left["effect_id"]
                .as_str()
                .unwrap()
                .as_bytes()
                .cmp(right["effect_id"].as_str().unwrap().as_bytes())
        });
        let responses = BTreeMap::from([(creation_id.to_owned(), response.clone())]);
        let mut journal = json!({"host_effect_journal_format":"determa.host_effect_journal","host_effect_journal_schema_version":1,
            "scope_identity":self.scope,"root_instance_id":root,"checkpoint_revision":checkpoint.revision(),"checkpoint_digest":checkpoint.digest(),"journal_revision":"0",
            "effect_records":records,"operation_response_references":[{"operation_id":creation_id,"response_digest":hash(&json!(["determa-host-operation-response-1",response]))?}]});
        journal["host_effect_journal_digest"] = json!(hash(&json!([
            "determa-host-effect-journal-digest-1",
            journal
        ]))?);
        let validated = ValidatedEffectJournal::restore(
            &canonical(&journal)?,
            &checkpoint,
            &self.scope,
            &responses,
            self.resolver.as_ref(),
        )
        .map_err(failure)?;
        let document = json!({"journal":validated.value(),"responses":responses,"original_requests":{creation_id:original_request}});
        self.store
            .insert_native_effect_checkpoint(&checkpoint, &document, || {
                let current = self
                    .resolver
                    .resolve_definition(&bundle.fingerprint)
                    .ok_or_else(|| failure("native creation source unavailable at commit"))?;
                if !current.trusted
                    || current.bundle.fingerprint != bundle.fingerprint
                    || current.bundle.normalized != bundle.normalized
                {
                    return Err(failure("native creation source changed at commit"));
                }
                crate::format1::providers::check_bundle(&current.bundle).map_err(failure)?;
                crate::format1::effect_journal::validate_route_mapping(
                    &current.bundle,
                    machine_id,
                    &self.route.result_mapping,
                )
                .map_err(failure)?;
                self.handler
                    .verify(
                        &self.route.handler_reference,
                        &self.route.destination_binding_digest,
                    )
                    .map_err(failure)
            })
            .map_err(failure)?;
        Ok(response)
    }
    /// Admit one exact external delivery while preserving the native effect
    /// participant. This owner-local API is not a public protocol endpoint, worker
    /// credential, effect result submission or imported journal activation.
    pub fn admit(
        &self,
        root: &str,
        operation_id: &str,
        delivery: &Value,
        guard: &checkpoint::MutationGuard,
    ) -> Result<Value, AuthorityError> {
        if delivery["delivery_mode"] != "input" {
            return Err(failure("native external admission requires input mode"));
        }
        if operation_id.is_empty() {
            return Err(failure("operation identity absent"));
        }
        let original_request =
            json!({"operation_kind":"admission","root_instance_id":root,"delivery":delivery});
        if let Some(saved) = self
            .store
            .native_effect_replay(root, operation_id, &original_request)
            .map_err(failure)?
        {
            return Ok(saved);
        }
        let (original_checkpoint, mut document) =
            self.store.native_effect_snapshot(root).map_err(failure)?;
        let fingerprint = original_checkpoint
            .bundle_fingerprint()
            .ok_or_else(|| failure("native admission definition absent"))?;
        let resolved = self
            .resolver
            .resolve_definition(fingerprint)
            .ok_or_else(|| failure("native admission definition unavailable"))?;
        if !resolved.trusted || resolved.bundle.fingerprint != fingerprint {
            return Err(failure("native admission definition not trusted"));
        }
        let result = checkpoint::admit(
            &resolved.bundle,
            &original_checkpoint,
            std::slice::from_ref(delivery),
            Some(&guard.expected_revision),
            Some(&guard.expected_checkpoint_digest),
        )
        .map_err(failure)?;
        let candidate_value = if result.get("execution_checkpoint_format").is_some() {
            result.clone()
        } else if result.get("checkpoint").is_some() {
            result["checkpoint"].clone()
        } else {
            original_checkpoint.value().clone()
        };
        let candidate = checkpoint::restore(&canonical(&candidate_value)?, self.resolver.as_ref())
            .map_err(failure)?;
        // Portable duplicate-event admission may return its existing receipt before
        // CAS. A NEW named host operation still requires the current native guard.
        if original_checkpoint.revision() != guard.expected_revision
            || original_checkpoint.digest() != guard.expected_checkpoint_digest
        {
            return Err(failure("checkpoint_revision_conflict"));
        }
        let prior_document = document.clone();
        let response = json!({"kind":"admission","body":{"checkpoint":candidate.value(),"admission_result":result}});
        document["responses"][operation_id] = response.clone();
        document["original_requests"][operation_id] = original_request;
        let journal = &mut document["journal"];
        let revision = journal["journal_revision"]
            .as_str()
            .ok_or_else(|| failure("native journal revision absent"))?
            .parse::<num_bigint::BigUint>()
            .map_err(failure)?;
        journal["journal_revision"] =
            json!((revision + num_bigint::BigUint::from(1u8)).to_string());
        journal["checkpoint_revision"] = json!(candidate.revision());
        journal["checkpoint_digest"] = json!(candidate.digest());
        journal["operation_response_references"].as_array_mut().ok_or_else(||failure("native references absent"))?
            .push(json!({"operation_id":operation_id,"response_digest":hash(&json!(["determa-host-operation-response-1",response]))?}));
        journal["operation_response_references"]
            .as_array_mut()
            .unwrap()
            .sort_by(|left, right| {
                left["operation_id"]
                    .as_str()
                    .unwrap()
                    .as_bytes()
                    .cmp(right["operation_id"].as_str().unwrap().as_bytes())
            });
        journal
            .as_object_mut()
            .unwrap()
            .remove("host_effect_journal_digest");
        journal["host_effect_journal_digest"] = json!(hash(&json!([
            "determa-host-effect-journal-digest-1",
            journal
        ]))?);
        self.store
            .update_native_effect_checkpoint(
                &original_checkpoint,
                &prior_document,
                &candidate,
                &document,
                || {
                    // Recheck the source after actual SQL staging, before native commit.
                    let current =
                        self.resolver
                            .resolve_definition(fingerprint)
                            .ok_or_else(|| {
                                failure("native admission definition unavailable at commit")
                            })?;
                    if !current.trusted
                        || current.bundle.fingerprint != fingerprint
                        || current.bundle.normalized != resolved.bundle.normalized
                    {
                        return Err(failure("native admission definition changed at commit"));
                    }
                    crate::format1::providers::check_bundle(&current.bundle).map_err(failure)
                },
            )
            .map_err(failure)?;
        Ok(response)
    }
    /// Process the actual selected ready event and pin its real external intents.
    /// Native destination invocation remains a later separately fenced operation.
    pub fn produce(
        &self,
        root: &str,
        operation_id: &str,
        production: &NativeEffectProductionRequest,
    ) -> Result<Value, AuthorityError> {
        if operation_id.is_empty() || production.operation_token.is_empty() {
            return Err(failure("native production identity/token absent"));
        }
        let request = &production.processing_request;
        let original_request = json!({"operation_kind":"produce","root_instance_id":root,
            "target_runtime_id":request.target_runtime_id,"event_id":request.event_id,
            "envelope_digest":request.envelope_digest,"acceptance_sequence":request.acceptance_sequence,
            "queue_sequence":request.queue_sequence,"processing_mode":request.processing_mode,
            "operation_token":production.operation_token});
        if let Some(saved) = self
            .store
            .native_effect_replay(root, operation_id, &original_request)
            .map_err(failure)?
        {
            return Ok(saved);
        }
        let (original_checkpoint, mut document) =
            self.store.native_effect_snapshot(root).map_err(failure)?;
        if production.route_configuration_generation != self.route.generation {
            return Err(failure("scope_generation_conflict"));
        }
        let fingerprint = original_checkpoint
            .bundle_fingerprint()
            .ok_or_else(|| failure("native producer definition absent"))?;
        let resolved = self
            .resolver
            .resolve_definition(fingerprint)
            .ok_or_else(|| failure("native producer definition unavailable"))?;
        if !resolved.trusted || resolved.bundle.fingerprint != fingerprint {
            return Err(failure("native producer definition not trusted"));
        }
        let root_runtime = original_checkpoint.value()["root_record"]["aggregate_state"]
            ["runtimes"]
            .as_array()
            .and_then(|runtimes| {
                runtimes
                    .iter()
                    .find(|runtime| runtime["identity_origin"]["kind"] == "root")
            })
            .ok_or_else(|| failure("native result root runtime absent"))?;
        let machine_id = root_runtime["current_definition"]["machine"]["machine_id"]
            .as_str()
            .ok_or_else(|| failure("native result root definition absent"))?;
        crate::format1::effect_journal::validate_route_mapping(
            &resolved.bundle,
            machine_id,
            &self.route.result_mapping,
        )
        .map_err(failure)?;
        self.handler
            .verify(
                &self.route.handler_reference,
                &self.route.destination_binding_digest,
            )
            .map_err(failure)?;
        let (candidate_value, core) = checkpoint::checkpoint_step_v1_with_core(
            &resolved.bundle,
            &original_checkpoint,
            request,
            Some(&production.guard.expected_revision),
            Some(&production.guard.expected_checkpoint_digest),
        )
        .map_err(failure)?;
        let core = core.ok_or_else(|| failure("named native producer replay evidence absent"))?;
        let candidate = checkpoint::restore(&canonical(&candidate_value)?, self.resolver.as_ref())
            .map_err(failure)?;
        let receipt = if core["disposition"] == "deferred" {
            Value::Null
        } else {
            candidate.value()["operation_receipts"]
                .as_array()
                .and_then(|receipts| {
                    receipts.iter().find(|receipt| {
                        receipt["operation_kind"] == "event_terminal"
                            && receipt["event_id"] == request.event_id
                            && receipt["committed_revision"] == candidate.revision()
                    })
                })
                .cloned()
                .ok_or_else(|| failure("actual native producer terminal receipt absent"))?
        };
        let response = json!({"kind":"processing","body":{"core_result":core,"receipt":receipt}});
        let prior_document = document.clone();
        let target = json!({"root_instance_id":root,"runtime_id":root_runtime["runtime_id"],"runtime_incarnation":root_runtime["identity_origin"]});
        let old_ids: std::collections::BTreeSet<&str> = original_checkpoint.value()
            ["pending_outbox_intents"]
            .as_array()
            .unwrap()
            .iter()
            .chain(
                original_checkpoint.value()["terminal_outbox_records"]
                    .as_array()
                    .unwrap(),
            )
            .filter_map(|item| item["intent"]["effect_id"].as_str())
            .chain(
                original_checkpoint.value()["outbox_effect_tombstones"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter_map(|item| item["effect_id"].as_str()),
            )
            .collect();
        let records = document["journal"]["effect_records"]
            .as_array_mut()
            .ok_or_else(|| failure("native records absent"))?;
        for item in candidate.value()["pending_outbox_intents"]
            .as_array()
            .unwrap()
        {
            let intent = &item["intent"];
            if old_ids.contains(intent["effect_id"].as_str().unwrap()) {
                continue;
            }
            if intent["correlation_id"] != production.operation_token {
                return Err(failure("native produced business token mismatch"));
            }
            records.push(json!({"effect_id":intent["effect_id"],"operation_token":production.operation_token,
                "intent_digest":hash(&json!(["determa-outbox-intent-digest-1","1",root,intent]))?,
                "handler_reference":self.route.handler_reference,"destination_binding_digest":self.route.destination_binding_digest,
                "route_configuration_generation":self.route.generation,"result_mapping":self.route.result_mapping,
                "target":target,"idempotency_policy":self.route.idempotency_policy,"attempt_fence":"0","attempt_records":[],
                "invocation_state":"unclaimed","outcome":null,"result_event_id":null,"admission_receipt":null,"cancellation":null}));
        }
        records.sort_by(|left, right| {
            left["effect_id"]
                .as_str()
                .unwrap()
                .as_bytes()
                .cmp(right["effect_id"].as_str().unwrap().as_bytes())
        });
        document["responses"][operation_id] = response.clone();
        document["original_requests"][operation_id] = original_request;
        let journal = &mut document["journal"];
        let revision = journal["journal_revision"]
            .as_str()
            .unwrap()
            .parse::<num_bigint::BigUint>()
            .map_err(failure)?;
        journal["journal_revision"] =
            json!((revision + num_bigint::BigUint::from(1u8)).to_string());
        journal["checkpoint_revision"] = json!(candidate.revision());
        journal["checkpoint_digest"] = json!(candidate.digest());
        journal["operation_response_references"]
            .as_array_mut()
            .unwrap()
            .push(json!({"operation_id":operation_id,
            "response_digest":hash(&json!(["determa-host-operation-response-1",response]))?}));
        journal["operation_response_references"]
            .as_array_mut()
            .unwrap()
            .sort_by(|left, right| {
                left["operation_id"]
                    .as_str()
                    .unwrap()
                    .as_bytes()
                    .cmp(right["operation_id"].as_str().unwrap().as_bytes())
            });
        journal
            .as_object_mut()
            .unwrap()
            .remove("host_effect_journal_digest");
        journal["host_effect_journal_digest"] = json!(hash(&json!([
            "determa-host-effect-journal-digest-1",
            journal
        ]))?);
        self.store
            .update_native_effect_checkpoint(
                &original_checkpoint,
                &prior_document,
                &candidate,
                &document,
                || {
                    let current = self
                        .resolver
                        .resolve_definition(fingerprint)
                        .ok_or_else(|| failure("native producer source unavailable at commit"))?;
                    if !current.trusted
                        || current.bundle.fingerprint != fingerprint
                        || current.bundle.normalized != resolved.bundle.normalized
                    {
                        return Err(failure("native producer source changed at commit"));
                    }
                    crate::format1::providers::check_bundle(&current.bundle).map_err(failure)?;
                    crate::format1::effect_journal::validate_route_mapping(
                        &current.bundle,
                        machine_id,
                        &self.route.result_mapping,
                    )
                    .map_err(failure)?;
                    self.handler
                        .verify(
                            &self.route.handler_reference,
                            &self.route.destination_binding_digest,
                        )
                        .map_err(failure)
                },
            )
            .map_err(failure)?;
        Ok(response)
    }
    /// First claim only: retries, expiry recovery and reconciliation are separate
    /// operations and cannot be inferred from an absent result or provider claim.
    /// A retained active-shaped reply is historical evidence, never renewed rights.
    pub fn claim(
        &self,
        root: &str,
        operation_id: &str,
        request: &NativeEffectClaimRequest,
        credential: &[u8],
    ) -> Result<Value, AuthorityError> {
        if operation_id.is_empty() {
            return Err(failure("native claim identity absent"));
        }
        let authority = self
            .worker_authority
            .as_ref()
            .ok_or_else(|| failure("native worker authority absent"))?;
        let caller = authority.authenticate(credential).map_err(failure)?;
        if caller.authenticated_principal.is_empty()
            || !caller.authorized_scopes.contains(&self.scope)
            || !caller.operation_rights.contains("claim_effect")
        {
            return Err(failure("unauthorized_scope"));
        }
        let original = json!({"operation_kind":"effect_claim","root_instance_id":root,
            "effect_id":request.effect_id,"worker_principal":caller.authenticated_principal,
            "scope_authority_epoch":"0"});
        if let Some(saved) = self
            .store
            .native_effect_replay(root, operation_id, &original)
            .map_err(failure)?
        {
            return Ok(saved);
        }
        let duration = authority.lease_duration_ns().map_err(failure)?;
        if duration <= 0 {
            return Err(failure("invalid native lease policy"));
        }
        let expiry = authority
            .trusted_now()
            .map_err(failure)?
            .checked_add(duration)
            .ok_or_else(|| failure("native lease time overflow"))?;
        let (checkpoint, mut document) =
            self.store.native_effect_snapshot(root).map_err(failure)?;
        let fingerprint = checkpoint
            .bundle_fingerprint()
            .ok_or_else(|| failure("native definition absent"))?;
        let resolved = self
            .resolver
            .resolve_definition(fingerprint)
            .ok_or_else(|| failure("native definition unavailable"))?;
        if !resolved.trusted || resolved.bundle.fingerprint != fingerprint {
            return Err(failure("native definition not trusted"));
        }
        let prior = document.clone();
        let record = document["journal"]["effect_records"]
            .as_array_mut()
            .ok_or_else(|| failure("native effects absent"))?
            .iter_mut()
            .find(|record| record["effect_id"] == request.effect_id)
            .ok_or_else(|| failure("effect_not_outstanding"))?;
        if record["invocation_state"] != "unclaimed" || record["attempt_fence"] != "0" {
            return Err(failure("effect_not_outstanding"));
        }
        if record["handler_reference"] != self.route.handler_reference
            || record["destination_binding_digest"] != self.route.destination_binding_digest
            || record["route_configuration_generation"] != self.route.generation
            || record["result_mapping"] != self.route.result_mapping
        {
            return Err(failure("scope_generation_conflict"));
        }
        let claim = json!({"scope_identity":self.scope,"root_instance_id":root,"work_kind":"effect",
            "work_identity":request.effect_id,"operation_token":record["operation_token"],
            "scope_authority_epoch":"0","attempt_fence":"1","worker_principal":caller.authenticated_principal,
            "expires_at":expiry.to_string(),"state":"active"});
        record["attempt_fence"] = json!("1");
        record["invocation_state"] = json!("leased");
        let response = json!({"kind":"effect_claim","body":{"claim":claim}});
        retain_native_effect_response(&mut document, operation_id, &original, &response)?;
        self.store
            .update_native_effect_checkpoint_with_final_guard(
                &checkpoint,
                &prior,
                &checkpoint,
                &document,
                || {
                    let fingerprint = checkpoint
                        .bundle_fingerprint()
                        .ok_or_else(|| failure("native definition absent"))?;
                    let current_bundle = self
                        .resolver
                        .resolve_definition(fingerprint)
                        .ok_or_else(|| failure("native definition unavailable"))?;
                    if !current_bundle.trusted
                        || current_bundle.bundle.fingerprint != fingerprint
                        || current_bundle.bundle.normalized != resolved.bundle.normalized
                    {
                        return Err(failure("native definition changed at commit"));
                    }
                    crate::format1::providers::check_bundle(&current_bundle.bundle)
                        .map_err(failure)?;
                    self.handler
                        .verify(
                            &self.route.handler_reference,
                            &self.route.destination_binding_digest,
                        )
                        .map_err(failure)
                },
                || {
                    let current = authority.authenticate(credential).map_err(failure)?;
                    if current.authenticated_principal != caller.authenticated_principal
                        || !current.authorized_scopes.contains(&self.scope)
                        || !current.operation_rights.contains("claim_effect")
                    {
                        return Err(failure("unauthorized_scope"));
                    }
                    if authority.trusted_now().map_err(failure)? >= expiry {
                        return Err(failure("stale_attempt_fence"));
                    }
                    Ok(())
                },
            )
            .map_err(failure)?;
        Ok(response)
    }
    /// Owner-local durable report stage, not a completed public result response.
    /// Terminal outcomes are committed before a separate result-admission stage.
    pub fn record_result(
        &self,
        root: &str,
        operation_id: &str,
        report: &Value,
        credential: &[u8],
    ) -> Result<Value, AuthorityError> {
        if operation_id.is_empty() {
            return Err(failure("native report identity absent"));
        }
        let authority = self
            .worker_authority
            .as_ref()
            .ok_or_else(|| failure("native worker authority absent"))?;
        let caller = authority.authenticate(credential).map_err(failure)?;
        if caller.authenticated_principal.is_empty()
            || !caller.authorized_scopes.contains(&self.scope)
            || !caller.operation_rights.contains("submit_effect_result")
        {
            return Err(failure("unauthorized_scope"));
        }
        crate::format1::validate_native_effect_result_request(report).map_err(failure)?;
        let original = json!({"operation_kind":"effect_report","root_instance_id":root,
            "worker_principal":caller.authenticated_principal,"report":report});
        if let Some(saved) = self
            .store
            .native_effect_replay(root, operation_id, &original)
            .map_err(failure)?
        {
            return Ok(saved);
        }
        let (checkpoint, mut document) =
            self.store.native_effect_snapshot(root).map_err(failure)?;
        let prior = document.clone();
        let selected = document["journal"]["effect_records"]
            .as_array()
            .unwrap()
            .iter()
            .find(|record| record["effect_id"] == report["effect_id"])
            .ok_or_else(|| failure("effect_not_outstanding"))?;
        let claim = current_native_effect_claim(&document, selected)?.clone();
        let pinned_reference = selected["handler_reference"].clone();
        let pinned_destination = selected["destination_binding_digest"]
            .as_str()
            .ok_or_else(|| failure("pinned destination absent"))?
            .to_owned();
        if claim["worker_principal"] != caller.authenticated_principal
            || claim["scope_identity"] != self.scope
        {
            return Err(failure("unauthorized_scope"));
        }
        let expiry = canonical_native_time(&claim["expires_at"])?;
        if authority.trusted_now().map_err(failure)? >= expiry {
            return Err(failure("stale_attempt_fence"));
        }
        let fingerprint = checkpoint
            .bundle_fingerprint()
            .ok_or_else(|| failure("native definition absent"))?;
        let resolved = self
            .resolver
            .resolve_definition(fingerprint)
            .ok_or_else(|| failure("native definition unavailable"))?;
        if !resolved.trusted || resolved.bundle.fingerprint != fingerprint {
            return Err(failure("native definition not trusted"));
        }
        let record = document["journal"]["effect_records"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|record| record["effect_id"] == report["effect_id"])
            .unwrap();
        record_native_effect_report(record, report)?;
        let response = json!({"kind":"effect_report","body":{
            "attempt_report":record["attempt_records"].as_array().unwrap().last().unwrap(),
            "outcome":record["outcome"],"result_event_id":record["result_event_id"]}});
        retain_native_effect_response(&mut document, operation_id, &original, &response)?;
        self.store
            .update_native_effect_checkpoint_with_final_guard(
                &checkpoint,
                &prior,
                &checkpoint,
                &document,
                || {
                    let current = self
                        .resolver
                        .resolve_definition(fingerprint)
                        .ok_or_else(|| failure("native definition unavailable at commit"))?;
                    if !current.trusted
                        || current.bundle.fingerprint != fingerprint
                        || current.bundle.normalized != resolved.bundle.normalized
                    {
                        return Err(failure("native definition changed at commit"));
                    }
                    crate::format1::providers::check_bundle(&current.bundle).map_err(failure)?;
                    self.handler
                        .verify(&pinned_reference, &pinned_destination)
                        .map_err(failure)
                },
                || {
                    let current = authority.authenticate(credential).map_err(failure)?;
                    if current.authenticated_principal != caller.authenticated_principal
                        || !current.authorized_scopes.contains(&self.scope)
                        || !current.operation_rights.contains("submit_effect_result")
                    {
                        return Err(failure("unauthorized_scope"));
                    }
                    if authority.trusted_now().map_err(failure)? >= expiry {
                        return Err(failure("stale_attempt_fence"));
                    }
                    Ok(())
                },
            )
            .map_err(failure)?;
        Ok(response)
    }
    /// Host-local dispatch of one issued claim. A durable start marker is committed
    /// before external I/O; historical starts never authorize a second call.
    /// Native writer exclusion spans the consuming check and entire provider call.
    /// Providers must bound I/O and must not reenter this SQLite authority.
    /// This is not the complete public dispatch protocol or an automatic retry.
    pub fn dispatch_claimed(
        &self,
        root: &str,
        effect_id: &str,
        worker_credential: &[u8],
        handler_credential: &[u8],
    ) -> Result<Value, AuthorityError> {
        let authority = self
            .worker_authority
            .as_ref()
            .ok_or_else(|| failure("native worker authority absent"))?;
        let caller = authority.authenticate(worker_credential).map_err(failure)?;
        let authorize = || -> Result<(), AuthorityError> {
            let current = authority.authenticate(worker_credential).map_err(failure)?;
            if current.authenticated_principal != caller.authenticated_principal
                || current.authenticated_principal.is_empty()
                || !current.authorized_scopes.contains(&self.scope)
                || !current.operation_rights.contains("dispatch_effect")
                || !current.operation_rights.contains("submit_effect_result")
            {
                return Err(failure("unauthorized_scope"));
            }
            Ok(())
        };
        authorize()?;
        let (checkpoint, mut document) =
            self.store.native_effect_snapshot(root).map_err(failure)?;
        let prior = document.clone();
        let record = document["journal"]["effect_records"]
            .as_array()
            .unwrap()
            .iter()
            .find(|record| record["effect_id"] == effect_id)
            .ok_or_else(|| failure("effect_not_outstanding"))?
            .clone();
        let claim = current_native_effect_claim(&document, &record)?.clone();
        if record["invocation_state"] != "leased"
            || !record["cancellation"].is_null()
            || claim["worker_principal"] != caller.authenticated_principal
            || claim["scope_identity"] != self.scope
        {
            return Err(failure("effect_not_outstanding"));
        }
        let expiry = canonical_native_time(&claim["expires_at"])?;
        let guard = || -> Result<(), AuthorityError> {
            authorize()?;
            if authority.trusted_now().map_err(failure)? >= expiry {
                return Err(failure("stale_attempt_fence"));
            }
            Ok(())
        };
        guard()?;
        let start_id = hash(&json!([
            "determa-native-invocation-start-1",
            self.scope,
            root,
            effect_id,
            record["attempt_fence"]
        ]))?;
        if document["responses"].get(&start_id).is_some() {
            return Err(failure(
                "native invocation already started; reconciliation required",
            ));
        }
        let fingerprint = checkpoint
            .bundle_fingerprint()
            .ok_or_else(|| failure("native definition absent"))?;
        let resolved = self
            .resolver
            .resolve_definition(fingerprint)
            .ok_or_else(|| failure("native definition unavailable"))?;
        if !resolved.trusted || resolved.bundle.fingerprint != fingerprint {
            return Err(failure("native definition not trusted"));
        }
        let intent = checkpoint.value()["pending_outbox_intents"]
            .as_array()
            .unwrap()
            .iter()
            .find(|intent| intent["intent"]["effect_id"] == effect_id)
            .ok_or_else(|| failure("committed dispatch intent absent"))?["intent"]
            .clone();
        let payload: crate::format1::TypedValue =
            serde_json::from_value(intent["payload"].clone()).map_err(failure)?;
        let destination = record["destination_binding_digest"].as_str().unwrap();
        let check_source = || -> Result<(), AuthorityError> {
            let current = self
                .resolver
                .resolve_definition(fingerprint)
                .ok_or_else(|| failure("native dispatch source unavailable"))?;
            if !current.trusted
                || current.bundle.fingerprint != fingerprint
                || current.bundle.normalized != resolved.bundle.normalized
            {
                return Err(failure("native dispatch source changed"));
            }
            crate::format1::providers::check_bundle(&current.bundle).map_err(failure)?;
            self.handler
                .verify(&record["handler_reference"], destination)
                .map_err(failure)
        };
        let original = json!({"operation_kind":"effect_invocation_start","root_instance_id":root,
            "effect_id":effect_id,"attempt_fence":record["attempt_fence"],"worker_principal":caller.authenticated_principal});
        let response = json!({"kind":"effect_invocation_start","body":{"claim":claim}});
        retain_native_effect_response(&mut document, &start_id, &original, &response)?;
        let fresh = self
            .store
            .update_native_effect_checkpoint_with_final_guard(
                &checkpoint,
                &prior,
                &checkpoint,
                &document,
                check_source,
                guard,
            )
            .map_err(failure)?;
        if !fresh {
            return Err(failure(
                "native invocation start was replayed; no call permission",
            ));
        }
        // A subsequent call, restart or competing worker sees the retained start and
        // cannot reach this point. Errors here retain uncertainty, never safe retry.
        check_source()?;
        let metadata = crate::extensions::NativeHandlerMetadata {
            scope_identity: &self.scope,
            effect_id,
            operation_token: record["operation_token"].as_str().unwrap(),
            destination_binding_digest: destination,
            route_configuration_generation: record["route_configuration_generation"]
                .as_str()
                .unwrap(),
            handler_reference: &record["handler_reference"],
            credential: handler_credential,
        };
        let report = self.store.with_native_effect_call(root, |latest_checkpoint, latest_document| {
            if latest_document["journal"]["effect_records"].as_array().unwrap().iter().find(|item| item["effect_id"] == effect_id) != Some(&record)
                || latest_document["original_requests"].get(&start_id) != Some(&original)
                || !latest_checkpoint["pending_outbox_intents"].as_array().unwrap().iter().any(|item| item["intent"] == intent && item["delivery_state"] == json!({"status":"not_attempted"})) {
                return Err(failure("native invocation changed before call"));
            }
            check_source()?;
            self.handler.invoke_with_guard(&payload, &metadata,
                &crate::extensions::NativeHandlerAttempt {attempt_fence:record["attempt_fence"].as_str().unwrap()},
                || guard().map_err(|error| crate::extensions::ExtensionError {
                    code:crate::extensions::ExtensionErrorCode::ExtensionIdentityMismatch,message:error.to_string(),
                })).map_err(failure)
        }).map_err(failure)?;
        use crate::extensions::NativeHandlerReportKind as Kind;
        let kind = match report.kind {
            Kind::Succeeded => "succeeded",
            Kind::DomainRejected => "domain_rejected",
            Kind::TerminalFailure => "terminal_failure",
            Kind::Cancelled => "cancelled",
            // A provider assertion cannot establish independent safe retry evidence.
            Kind::RetryableFailure | Kind::Ambiguous => "ambiguous",
        };
        let result = json!({"effect_id":effect_id,"operation_token":record["operation_token"],
            "attempt_fence":record["attempt_fence"],"outcome_kind":kind,
            "payload":serde_json::to_value(report.payload).map_err(failure)?});
        let report_id = hash(&json!([
            "determa-native-invocation-report-1",
            self.scope,
            root,
            effect_id,
            record["attempt_fence"]
        ]))?;
        self.record_result(root, &report_id, &result, worker_credential)
    }

    /// Owner-local retirement of an expired claim, preserving unknown provider fate.
    /// This does not issue retry permission or invoke the native handler.
    pub fn recover_expired_claim(
        &self,
        root: &str,
        operation_id: &str,
        effect_id: &str,
        guard: &checkpoint::MutationGuard,
    ) -> Result<Value, AuthorityError> {
        if operation_id.is_empty() {
            return Err(failure("native recovery identity absent"));
        }
        let original = json!({"operation_kind":"effect_expiry_recovery",
            "root_instance_id":root,"effect_id":effect_id});
        if let Some(saved) = self
            .store
            .native_effect_replay(root, operation_id, &original)
            .map_err(failure)?
        {
            return Ok(saved);
        }
        let authority = self
            .worker_authority
            .as_ref()
            .ok_or_else(|| failure("native trusted clock absent"))?;
        let observed_now = authority.trusted_now().map_err(failure)?;
        let (checkpoint, mut document) =
            self.store.native_effect_snapshot(root).map_err(failure)?;
        if checkpoint.revision() != guard.expected_revision
            || checkpoint.digest() != guard.expected_checkpoint_digest
        {
            return Err(failure("checkpoint_revision_conflict"));
        }
        let prior = document.clone();
        let record = document["journal"]["effect_records"]
            .as_array()
            .unwrap()
            .iter()
            .find(|record| record["effect_id"] == effect_id)
            .ok_or_else(|| failure("effect_not_outstanding"))?;
        let claim = current_native_effect_claim(&document, record)?.clone();
        let expiry = canonical_native_time(&claim["expires_at"])?;
        if observed_now < expiry {
            return Err(failure("native claim has not expired"));
        }
        let response = expire_native_effect_claim(&mut document, effect_id, &claim, observed_now)?;
        retain_native_effect_response(&mut document, operation_id, &original, &response)?;
        self.store
            .update_native_effect_checkpoint_with_final_guard(
                &checkpoint,
                &prior,
                &checkpoint,
                &document,
                || Ok(()),
                || {
                    if authority.trusted_now().map_err(failure)? < observed_now {
                        return Err(failure("native recovery clock regressed"));
                    }
                    Ok(())
                },
            )
            .map_err(failure)?;
        Ok(response)
    }

    /// Owner-authorized recovery of a retained terminal outcome. This operation
    /// never invokes a provider or requires the expired original worker claim.
    pub fn admit_recorded_result(
        &self,
        root: &str,
        operation_id: &str,
        effect_id: &str,
        guard: &checkpoint::MutationGuard,
    ) -> Result<Value, AuthorityError> {
        if operation_id.is_empty() {
            return Err(failure("native result admission identity absent"));
        }
        let original = json!({"operation_kind":"effect_result_admission","root_instance_id":root,"effect_id":effect_id});
        if let Some(saved) = self
            .store
            .native_effect_replay(root, operation_id, &original)
            .map_err(failure)?
        {
            return Ok(saved);
        }
        let (original_checkpoint, mut document) =
            self.store.native_effect_snapshot(root).map_err(failure)?;
        let prior = document.clone();
        let record = document["journal"]["effect_records"]
            .as_array()
            .unwrap()
            .iter()
            .find(|record| record["effect_id"] == effect_id)
            .ok_or_else(|| failure("effect_not_outstanding"))?;
        if record["invocation_state"] != "outcome_recorded" || record["outcome"].is_null() {
            return Err(failure("native result admission requires recorded outcome"));
        }
        let pinned_fingerprint = record["target"]["runtime_incarnation"]["definition"]
            ["validated_bundle_fingerprint"]
            .as_str()
            .ok_or_else(|| failure("native result definition absent"))?
            .to_owned();
        let pinned = self
            .resolver
            .resolve_definition(&pinned_fingerprint)
            .ok_or_else(|| failure("native result definition unavailable"))?;
        if !pinned.trusted || pinned.bundle.fingerprint != pinned_fingerprint {
            return Err(failure("native result definition not trusted"));
        }
        let evidence = crate::format1::effect_journal::native_definition_evidence(&pinned.bundle);
        let delivery =
            crate::format1::effect_journal::native_result_delivery(record, root, &evidence)
                .map_err(failure)?;
        let current_fingerprint = original_checkpoint
            .bundle_fingerprint()
            .ok_or_else(|| failure("native active definition absent"))?;
        let current = self
            .resolver
            .resolve_definition(current_fingerprint)
            .ok_or_else(|| failure("native active definition unavailable"))?;
        if !current.trusted || current.bundle.fingerprint != current_fingerprint {
            return Err(failure("native active definition not trusted"));
        }
        let result = checkpoint::admit(
            &current.bundle,
            &original_checkpoint,
            std::slice::from_ref(&delivery),
            Some(&guard.expected_revision),
            Some(&guard.expected_checkpoint_digest),
        )
        .map_err(failure)?;
        let candidate_value = if result.get("execution_checkpoint_format").is_some() {
            result.clone()
        } else {
            original_checkpoint.value().clone()
        };
        let candidate = checkpoint::restore(&canonical(&candidate_value)?, self.resolver.as_ref())
            .map_err(failure)?;
        if original_checkpoint.revision() != guard.expected_revision
            || original_checkpoint.digest() != guard.expected_checkpoint_digest
        {
            return Err(failure("checkpoint_revision_conflict"));
        }
        let receipt = candidate.value()["operation_receipts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|receipt| {
                receipt["operation_kind"] == "acceptance"
                    && receipt["event_id"] == record["result_event_id"]
                    && receipt["request_digest"] == delivery["envelope_digest"]
                    && receipt["delivery_mode"] == "input"
            })
            .ok_or_else(|| failure("native result acceptance absent"))?
            .clone();
        let record = document["journal"]["effect_records"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|record| record["effect_id"] == effect_id)
            .unwrap();
        record["admission_receipt"] = receipt;
        record["invocation_state"] = json!("result_admitted");
        let journal = &mut document["journal"];
        journal["checkpoint_revision"] = json!(candidate.revision());
        journal["checkpoint_digest"] = json!(candidate.digest());
        // retain_native_effect_response advances exactly one journal revision.
        let next_revision: num_bigint::BigUint = journal["journal_revision"]
            .as_str()
            .unwrap()
            .parse()
            .map_err(failure)?;
        let mut response_journal = journal.clone();
        response_journal["journal_revision"] =
            json!((next_revision + num_bigint::BigUint::from(1u8)).to_string());
        let updated = response_journal["effect_records"]
            .as_array()
            .unwrap()
            .iter()
            .find(|record| record["effect_id"] == effect_id)
            .unwrap();
        let response = json!({"kind":"effect_result_admission","body":{"checkpoint":candidate.value(),
            "admission_result":result,"delivery":delivery,"definition_evidence":evidence,
            "result_response":native_committed_result_response(updated, &response_journal, candidate.value())}});
        crate::format1::validate_native_effect_result_response(
            &response["body"]["result_response"],
        )
        .map_err(failure)?;
        retain_native_effect_response(&mut document, operation_id, &original, &response)?;
        self.store
            .update_native_effect_checkpoint(
                &original_checkpoint,
                &prior,
                &candidate,
                &document,
                || {
                    for (fingerprint, expected) in [
                        (pinned_fingerprint.as_str(), &pinned.bundle),
                        (current_fingerprint, &current.bundle),
                    ] {
                        let resolved = self
                            .resolver
                            .resolve_definition(fingerprint)
                            .ok_or_else(|| failure("native result source unavailable at commit"))?;
                        if !resolved.trusted
                            || resolved.bundle.fingerprint != fingerprint
                            || resolved.bundle.normalized != expected.normalized
                        {
                            return Err(failure("native result source changed at commit"));
                        }
                        crate::format1::providers::check_bundle(&resolved.bundle)
                            .map_err(failure)?;
                    }
                    Ok(())
                },
            )
            .map_err(failure)?;
        Ok(response)
    }
}

fn retain_native_effect_response(
    document: &mut Value,
    operation_id: &str,
    request: &Value,
    response: &Value,
) -> Result<(), AuthorityError> {
    document["responses"][operation_id] = response.clone();
    document["original_requests"][operation_id] = request.clone();
    let journal = &mut document["journal"];
    let revision: num_bigint::BigUint = journal["journal_revision"]
        .as_str()
        .ok_or_else(|| failure("native journal revision absent"))?
        .parse()
        .map_err(failure)?;
    journal["journal_revision"] = json!((revision + num_bigint::BigUint::from(1u8)).to_string());
    let references = journal["operation_response_references"]
        .as_array_mut()
        .ok_or_else(|| failure("native references absent"))?;
    references.push(json!({"operation_id":operation_id,"response_digest":hash(&json!(["determa-host-operation-response-1",response]))?}));
    references.sort_by(|left, right| {
        left["operation_id"]
            .as_str()
            .unwrap()
            .as_bytes()
            .cmp(right["operation_id"].as_str().unwrap().as_bytes())
    });
    journal
        .as_object_mut()
        .unwrap()
        .remove("host_effect_journal_digest");
    journal["host_effect_journal_digest"] = json!(hash(&json!([
        "determa-host-effect-journal-digest-1",
        journal
    ]))?);
    Ok(())
}

// Only native committed helper history supplies this current claim. Historic
// replayed response bodies are never caller credentials or renewed lease rights.
pub(super) fn current_native_effect_claim<'a>(
    document: &'a Value,
    record: &Value,
) -> Result<&'a Value, AuthorityError> {
    let mut matches = document["responses"]
        .as_object()
        .ok_or_else(|| failure("native responses absent"))?
        .values()
        .filter(|response| response["kind"] == "effect_claim")
        .map(|response| &response["body"]["claim"])
        .filter(|claim| {
            claim["work_identity"] == record["effect_id"]
                && claim["attempt_fence"] == record["attempt_fence"]
        });
    let claim = matches
        .next()
        .ok_or_else(|| failure("stale_attempt_fence"))?;
    if matches.next().is_some()
        || claim["state"] != "active"
        || claim["scope_authority_epoch"] != "0"
        || claim["operation_token"] != record["operation_token"]
    {
        return Err(failure("stale_attempt_fence"));
    }
    Ok(claim)
}

pub(super) fn expire_native_effect_claim(
    document: &mut Value,
    effect_id: &str,
    claim: &Value,
    observed_now: i64,
) -> Result<Value, AuthorityError> {
    let record = document["journal"]["effect_records"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|record| record["effect_id"] == effect_id)
        .ok_or_else(|| failure("effect_not_outstanding"))?;
    if record["invocation_state"] != "leased"
        || claim["work_identity"] != effect_id
        || claim["attempt_fence"] != record["attempt_fence"]
        || claim["operation_token"] != record["operation_token"]
        || observed_now < canonical_native_time(&claim["expires_at"])?
    {
        return Err(failure(
            "native expiry recovery requires expired current claim",
        ));
    }
    let report = json!({"effect_id":effect_id,"operation_token":record["operation_token"],
        "attempt_fence":record["attempt_fence"],"outcome_kind":"ambiguous","payload":["map",[]]});
    record_native_effect_report(record, &report)?;
    let mut expired = claim.clone();
    expired["state"] = json!("expired");
    Ok(
        json!({"kind":"effect_expiry_recovery","body":{"claim":expired,
        "trusted_now":observed_now.to_string(),
        "attempt_report":record["attempt_records"].as_array().unwrap().last().unwrap()}}),
    )
}

pub(super) fn record_native_effect_report(
    record: &mut Value,
    request: &Value,
) -> Result<(), AuthorityError> {
    if record["invocation_state"] != "leased"
        || record["attempt_fence"] != request["attempt_fence"]
        || record["operation_token"] != request["operation_token"]
        || record["effect_id"] != request["effect_id"]
    {
        return Err(failure("effect_not_outstanding"));
    }
    let kind = request["outcome_kind"]
        .as_str()
        .ok_or_else(|| failure("native report kind absent"))?;
    if kind == "retryable_failure" {
        // A worker's assertion is not independent no-call or deduplication proof.
        return Err(failure("native safe retry evidence absent"));
    }
    let reason = if kind == "ambiguous" {
        json!("provider_acceptance_unknown")
    } else {
        Value::Null
    };
    let report = json!({"attempt_fence":request["attempt_fence"],"report_kind":kind,"reason":reason,
        "report_digest":hash(&json!(["determa-effect-attempt-report-1",record["effect_id"],record["operation_token"],
            request["attempt_fence"],kind,request["payload"],reason]))?});
    let reports = record["attempt_records"]
        .as_array_mut()
        .ok_or_else(|| failure("native attempt history absent"))?;
    if reports
        .iter()
        .any(|report| report["attempt_fence"] == request["attempt_fence"])
        || !record["outcome"].is_null()
    {
        return Err(failure("effect_result_conflict"));
    }
    record["attempt_records"]
        .as_array_mut()
        .unwrap()
        .push(report);
    if kind == "ambiguous" {
        record["invocation_state"] = json!("ambiguous");
    } else {
        let mapping = record["result_mapping"]
            .as_array()
            .unwrap()
            .iter()
            .find(|mapping| mapping["outcome_kind"] == kind)
            .ok_or_else(|| failure("native result mapping absent"))?;
        let event_id = hash(&json!([
            "determa-effect-result-event-1",
            record["effect_id"],
            mapping["result_slot"]
        ]))?;
        record["outcome"] = json!({"kind":kind,"payload":request["payload"],"attempt_fence":request["attempt_fence"],
            "digest":hash(&json!(["determa-effect-outcome-1",record["effect_id"],record["operation_token"],kind,
                request["payload"],request["attempt_fence"]]))?});
        record["result_event_id"] = json!(event_id);
        record["invocation_state"] = json!("outcome_recorded");
    }
    Ok(())
}

pub(super) fn native_committed_result_response(
    record: &Value,
    journal: &Value,
    checkpoint: &Value,
) -> Value {
    json!({"status":"committed","effect_id":record["effect_id"],"attempt_fence":record["attempt_fence"],
        "attempt_report":null,"outcome":record["outcome"],"result_event_id":record["result_event_id"],
        "admission_receipt":record["admission_receipt"],"checkpoint_revision":checkpoint["revision"],
        "journal_revision":journal["journal_revision"],"error_code":null})
}
