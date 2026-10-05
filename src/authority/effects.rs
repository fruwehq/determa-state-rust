//! Fresh native effect production over the authority's actual SQLite transaction.
//! No imported checkpoint/journal activation, worker, archive or recovery claim.

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

pub struct SqliteNativeEffectHost<R> {
    store: GuardedSqliteExecutionStore<R>,
    resolver: Arc<R>,
    scope: String,
    route: NativeEffectRoute,
    handler: VerifiedNativeHandler,
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
        })
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
            .native_effect_creation_replay(root, creation_id, &original_request)
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
}
