//! Real memory-store commit, rejected CAS, and retained-receipt replay.
use super::{counts, delivery_digest, provider, stage, state};
use determa_state::checkpoint::{
    CheckpointHost, DurableCheckpointOperation, ExecutionStore, ExecutionStoreCapability,
    HealthStatus, MemoryExecutionStore, MutationGuard, ProcessingRequest, StoreError, StoreRecord,
    StoreWriteResult,
};
use determa_state::format1::providers::ProviderResult;
use determa_state::{ArtifactError, Bindings, Bundle, InMemoryDefinitionResolver, QueueEnvelope};
use serde_json::{json, Value};
use std::{
    any::Any,
    collections::BTreeSet,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
};

struct ConflictStore {
    inner: MemoryExecutionStore,
    conflict: AtomicBool,
    attempts: AtomicUsize,
}
impl ExecutionStore for ConflictStore {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn capabilities(&self) -> BTreeSet<ExecutionStoreCapability> {
        self.inner.capabilities()
    }
    fn initialize_schema(&self) -> Result<(), StoreError> {
        self.inner.initialize_schema()
    }
    fn health(&self) -> Result<HealthStatus, StoreError> {
        self.inner.health()
    }
    fn load(&self, id: &str) -> Result<Option<StoreRecord>, StoreError> {
        self.inner.load(id)
    }
    fn insert_if_absent(&self, record: StoreRecord) -> Result<StoreWriteResult, StoreError> {
        self.inner.insert_if_absent(record)
    }
    fn compare_and_swap(
        &self,
        id: &str,
        revision: &str,
        digest: &str,
        record: StoreRecord,
    ) -> Result<StoreWriteResult, StoreError> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        if self.conflict.load(Ordering::SeqCst) {
            return Ok(StoreWriteResult::Conflict(self.inner.load(id)?));
        }
        self.inner.compare_and_swap(id, revision, digest, record)
    }
}
fn failed() -> ArtifactError {
    ArtifactError::new(
        "runtime_adapter_observation_failed",
        "production host evidence inconsistent",
    )
}
pub fn run(
    bundle: &Bundle,
    providers: &[Arc<provider::RuntimeFixture>],
    request: &Value,
    observation: &mut Value,
) -> ProviderResult<()> {
    let creation = &request["setup"]["create_request"];
    let root = creation["root_instance_id"].as_str().unwrap();
    let store = Arc::new(ConflictStore {
        inner: MemoryExecutionStore::new(),
        conflict: AtomicBool::new(false),
        attempts: AtomicUsize::new(0),
    });
    store.initialize_schema().map_err(|_| failed())?;
    let mut resolver = InMemoryDefinitionResolver::default();
    resolver.insert(bundle.clone(), true);
    let host = CheckpointHost::new(store.clone(), Arc::new(resolver));
    let created = host.execute_checkpoint_operation(DurableCheckpointOperation::Create {
        bundle,machine_id:creation["machine_id"].as_str().unwrap(),root_instance_id:root,
        creation_id:creation["creation_id"].as_str().unwrap(),bindings:&Bindings::default(),supplied_request_digest:None,
        replay_retention:json!({"mode":"permanent","permanent_replay_eligible":true,"pruned_through_receipt_sequence":null,"policy_identifier":null}),
    });
    if created.result.result != "committed" {
        return Err(failed());
    }
    stage(observation, "create");
    let created = host.load_checkpoint(root)?.ok_or_else(failed)?;
    let envelope: QueueEnvelope =
        serde_json::from_value(request["setup"]["envelope"].clone()).unwrap();
    let delivery = json!({"delivery_mode":"input","envelope_digest":delivery_digest(root,&envelope),"envelope":envelope});
    host.admit_checkpoint(
        root,
        &[delivery],
        &MutationGuard::new(created.revision(), created.digest()),
    )?;
    stage(observation, "admit");
    let admitted = host.load_checkpoint(root)?.ok_or_else(failed)?;
    let aggregate = &admitted.value()["root_record"]["aggregate_state"];
    observation["state_before"] = state(aggregate);
    observation["state_after"] = observation["state_before"].clone();
    let runtime = aggregate["runtimes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|runtime| runtime["runtime_id"] == request["setup"]["target_runtime_id"])
        .unwrap();
    let entry = &runtime["ready_mailbox"][0];
    let processing = ProcessingRequest {
        target_runtime_id: runtime["runtime_id"].as_str().unwrap().into(),
        event_id: entry["envelope"]["event_id"].as_str().unwrap().into(),
        envelope_digest: entry["envelope_digest"].as_str().unwrap().into(),
        acceptance_sequence: entry["acceptance_sequence"].as_str().unwrap().into(),
        queue_sequence: entry["queue_sequence"].as_str().unwrap().into(),
        processing_mode: "delayed".into(),
    };
    let guard = MutationGuard::new(admitted.revision(), admitted.digest());
    store.conflict.store(
        request["arguments"]["cas_conflict"] == true,
        Ordering::SeqCst,
    );
    store.attempts.store(0, Ordering::SeqCst);
    stage(observation, "evaluate_cel");
    let first = host.execute_checkpoint_operation(DurableCheckpointOperation::Step {
        root_instance_id: root,
        request: &processing,
        guard: &guard,
    });
    counts(observation, providers);
    if observation["calls"]["guard"].as_u64().unwrap() > 0 {
        stage(observation, "evaluate_guard");
    }
    if observation["calls"]["actions"].as_u64().unwrap() > 0 {
        stage(observation, "evaluate_actions");
        stage(observation, "validate_output");
    }
    if store.attempts.load(Ordering::SeqCst) != 1 {
        return Err(failed());
    }
    stage(observation, "compare_and_swap");
    let committed = host.load_checkpoint(root)?.ok_or_else(failed)?;
    if let Some(code) = first.result.code {
        if code != "checkpoint_revision_conflict"
            || admitted.canonical_bytes()? != committed.canonical_bytes()?
        {
            return Err(failed());
        }
        observation["result"] = json!("uncommitted");
        observation["code"] = json!("compare_and_swap_conflict");
        return Ok(());
    }
    stage(observation, "commit");
    observation["state_after"] = state(&committed.value()["root_record"]["aggregate_state"]);
    let response = first.caller_response.ok_or_else(failed)?;
    let receipt = &response["body"]["receipt"];
    let emissions = response["body"]["core_result"]["emissions"]
        .as_array()
        .ok_or_else(failed)?;
    let references = receipt["emission_references"]
        .as_array()
        .ok_or_else(failed)?;
    observation["value"] = json!({"accepted":observation["state_after"]["variables"]["accepted"],"emissions":emissions.len(),
        "checkpoint_revision":committed.revision(),"retained_effect_references":references,"pending_outbox_entries":committed.value()["pending_outbox_intents"],
        "emission_identities":emissions.iter().map(|item| json!({"effect_id":item["effect_id"],"sequence":item["sequence"],
            "emission_index":references.iter().find(|reference| reference["effect_id"] == item["effect_id"]).unwrap()["emission_index"]})).collect::<Vec<_>>()});
    let provider_before: Vec<_> = providers
        .iter()
        .map(|provider| provider.observation())
        .collect();
    let replay = host.execute_checkpoint_operation(DurableCheckpointOperation::Step {
        root_instance_id: root,
        request: &processing,
        guard: &guard,
    });
    let after = host.load_checkpoint(root)?.ok_or_else(failed)?;
    observation["value"]["replay_receipt_equal"] =
        json!(replay.caller_response.ok_or_else(failed)?["body"] == *receipt);
    observation["value"]["replay_checkpoint_unchanged"] =
        json!(committed.canonical_bytes()? == after.canonical_bytes()?);
    observation["value"]["replay_provider_calls_unchanged"] = json!(
        provider_before
            == providers
                .iter()
                .map(|provider| provider.observation())
                .collect::<Vec<_>>()
    );
    stage(observation, "replay");
    observation["result"] = if receipt["outcome"]["disposition"] == "handled" {
        json!("handled_now")
    } else {
        receipt["outcome"]["disposition"].clone()
    };
    observation["determa_state_committed"] = json!(true);
    Ok(())
}
