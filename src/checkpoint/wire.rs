use crate::format1::{
    AggregateEnvelope, Counter, DefinitionResolver, Disposition, FaultRecord, MigrationAuditRecord,
    RuntimeStatus, Target, TypedValue,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointErrorCode {
    UnsupportedExecutionCheckpointFormat,
    UnsupportedExecutionCheckpointSchemaVersion,
    InvalidExecutionCheckpoint,
    ExecutionCheckpointDigestMismatch,
}

impl CheckpointErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedExecutionCheckpointFormat => "unsupported_execution_checkpoint_format",
            Self::UnsupportedExecutionCheckpointSchemaVersion => {
                "unsupported_execution_checkpoint_schema_version"
            }
            Self::InvalidExecutionCheckpoint => "invalid_execution_checkpoint",
            Self::ExecutionCheckpointDigestMismatch => "execution_checkpoint_digest_mismatch",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointError {
    pub code: CheckpointErrorCode,
    pub message: String,
}

impl CheckpointError {
    pub fn new(code: CheckpointErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for CheckpointError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for CheckpointError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointFault {
    pub definition_fingerprint: String,
    pub runtime_id: String,
    pub cause_id: String,
    pub code: String,
    pub step_sequence: Counter,
    pub source_locator: String,
}

impl From<&FaultRecord> for CheckpointFault {
    fn from(value: &FaultRecord) -> Self {
        Self {
            definition_fingerprint: value.definition_fingerprint.clone(),
            runtime_id: value.runtime_id.clone(),
            cause_id: value.cause_id.clone(),
            code: value.code.clone(),
            step_sequence: value.step_sequence.clone(),
            source_locator: value.source_locator.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryMode {
    Input,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortableEnvelope {
    pub event: String,
    pub event_id: String,
    pub target: Target,
    pub payload: TypedValue,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
}

impl PortableEnvelope {
    pub fn root_instance_id(&self) -> Option<&str> {
        match &self.target {
            Target::Root {
                root_instance_id, ..
            }
            | Target::Component {
                root_instance_id, ..
            } => Some(root_instance_id),
            Target::SpawnedInstance(reference) => Some(&reference.root_instance_id),
            Target::External => None,
        }
    }

    pub fn to_core_envelope(&self) -> Result<crate::format1::Envelope, CheckpointError> {
        let payload = self
            .payload
            .to_value(None)
            .map_err(|error| invalid(error.to_string()))?;
        let crate::Value::Map(payload) = payload else {
            return Err(invalid("delivery payload must be a typed map"));
        };
        Ok(crate::format1::Envelope {
            event: self.event.clone(),
            event_id: self.event_id.clone(),
            target: self.target.clone(),
            payload,
            correlation_id: self.correlation_id.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostInputOrigin {
    pub kind: HostInputOriginKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostInputOriginKind {
    HostInput,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InternalEmissionOrigin {
    pub kind: InternalEmissionOriginKind,
    pub producing_receipt_sequence: Counter,
    pub emission_index: Counter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InternalEmissionOriginKind {
    InternalEmission,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DeliveryOrigin {
    HostInput(HostInputOrigin),
    InternalEmission(InternalEmissionOrigin),
}

impl DeliveryOrigin {
    pub fn host_input() -> Self {
        Self::HostInput(HostInputOrigin {
            kind: HostInputOriginKind::HostInput,
        })
    }

    pub fn internal(producing_receipt_sequence: Counter, emission_index: Counter) -> Self {
        Self::InternalEmission(InternalEmissionOrigin {
            kind: InternalEmissionOriginKind::InternalEmission,
            producing_receipt_sequence,
            emission_index,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingDelivery {
    pub delivery_sequence: Counter,
    pub accepted_revision: Counter,
    pub delivery_mode: DeliveryMode,
    pub origin: DeliveryOrigin,
    pub envelope: PortableEnvelope,
    pub envelope_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EmissionReference {
    InternalDelivery {
        emission_index: Counter,
        event_id: String,
        delivery_sequence: Counter,
    },
    ExternalOutbox {
        emission_index: Counter,
        effect_id: String,
    },
}

impl EmissionReference {
    pub fn emission_index(&self) -> &Counter {
        match self {
            Self::InternalDelivery { emission_index, .. }
            | Self::ExternalOutbox { emission_index, .. } => emission_index,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointRejection {
    pub code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryOutcome {
    pub status: RuntimeStatus,
    pub disposition: Disposition,
    pub fault: Option<CheckpointFault>,
    pub rejection: Option<CheckpointRejection>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreationReceipt {
    pub operation_kind: CreationOperationKind,
    pub receipt_sequence: Counter,
    pub creation_id: String,
    pub request_digest: String,
    pub committed_revision: Counter,
    pub resulting_aggregate_state_digest: String,
    pub status: RuntimeStatus,
    pub fault: Option<CheckpointFault>,
    pub emission_references: Vec<EmissionReference>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CreationOperationKind {
    Creation,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryReceipt {
    pub operation_kind: DeliveryOperationKind,
    pub receipt_sequence: Counter,
    pub event_id: String,
    pub request_digest: String,
    pub accepted_delivery_sequence: Counter,
    pub accepted_revision: Counter,
    pub delivery_mode: DeliveryMode,
    pub origin: DeliveryOrigin,
    pub committed_revision: Counter,
    pub resulting_aggregate_state_digest: String,
    pub outcome: DeliveryOutcome,
    pub emission_references: Vec<EmissionReference>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryOperationKind {
    Delivery,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceMigrationReceipt {
    pub operation_kind: MaintenanceMigrationOperationKind,
    pub receipt_sequence: Counter,
    pub operation_id: String,
    pub request_digest: String,
    pub committed_revision: Counter,
    pub source_aggregate_state_digest: String,
    pub resulting_aggregate_state_digest: String,
    pub migration_sequences: Vec<Counter>,
    pub result_code: MaintenanceMigrationResultCode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaintenanceMigrationOperationKind {
    MaintenanceMigration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaintenanceMigrationResultCode {
    MigrationApplied,
    MigrationNoOperation,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OperationReceipt {
    Creation(CreationReceipt),
    Delivery(DeliveryReceipt),
    MaintenanceMigration(MaintenanceMigrationReceipt),
}

impl OperationReceipt {
    pub fn receipt_sequence(&self) -> &Counter {
        match self {
            Self::Creation(value) => &value.receipt_sequence,
            Self::Delivery(value) => &value.receipt_sequence,
            Self::MaintenanceMigration(value) => &value.receipt_sequence,
        }
    }

    pub fn committed_revision(&self) -> &Counter {
        match self {
            Self::Creation(value) => &value.committed_revision,
            Self::Delivery(value) => &value.committed_revision,
            Self::MaintenanceMigration(value) => &value.committed_revision,
        }
    }

    pub fn resulting_aggregate_state_digest(&self) -> &str {
        match self {
            Self::Creation(value) => &value.resulting_aggregate_state_digest,
            Self::Delivery(value) => &value.resulting_aggregate_state_digest,
            Self::MaintenanceMigration(value) => &value.resulting_aggregate_state_digest,
        }
    }

    pub fn emission_references(&self) -> &[EmissionReference] {
        match self {
            Self::Creation(value) => &value.emission_references,
            Self::Delivery(value) => &value.emission_references,
            Self::MaintenanceMigration(_) => &[],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutboxIntent {
    pub effect_id: String,
    pub sequence: Counter,
    pub event: String,
    pub payload: TypedValue,
    pub correlation_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum PendingOutboxState {
    NotAttempted,
    RetryableFailure { reason_code: String },
    Ambiguous { reason_code: String },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingOutboxIntent {
    pub intent: OutboxIntent,
    pub state_revision: Counter,
    pub delivery_state: PendingOutboxState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum TerminalOutboxOutcome {
    Confirmed,
    PermanentlyRejected { reason_code: String },
    OperatorCancelled { reason_code: String },
    Discarded { reason_code: String },
    DeadLettered { reason_code: String },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalOutboxRecord {
    pub terminal_sequence: Counter,
    pub intent: OutboxIntent,
    pub committed_revision: Counter,
    pub outcome: TerminalOutboxOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutboxEffectTombstone {
    pub terminal_sequence: Counter,
    pub effect_id: String,
    pub intent_digest: String,
    pub committed_revision: Counter,
    pub outcome: TerminalOutboxOutcome,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OutboxRecord {
    Pending(PendingOutboxIntent),
    Terminal(TerminalOutboxRecord),
    Tombstone(OutboxEffectTombstone),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedRootRecord {
    pub status: RetainedRootStatus,
    pub aggregate_state: AggregateEnvelope,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetainedRootStatus {
    Retained,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootTombstone {
    pub status: RootTombstoneStatus,
    pub root_runtime_id: String,
    pub creation_id: String,
    pub terminal_status: TerminalRootStatus,
    pub final_aggregate_state_digest: String,
    pub tombstone_operation_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RootTombstoneStatus {
    Tombstone,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalRootStatus {
    Completed,
    Faulted,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)] // Keep public wire alternatives direct and schema-shaped.
pub enum RootRecord {
    Retained(RetainedRootRecord),
    Tombstone(RootTombstone),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PermanentReplayRetention {
    pub mode: PermanentReplayMode,
    pub permanent_replay_eligible: bool,
    pub pruned_through_receipt_sequence: Option<Counter>,
    pub policy_identifier: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermanentReplayMode {
    Permanent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundedReplayRetention {
    pub mode: BoundedReplayMode,
    pub permanent_replay_eligible: bool,
    pub pruned_through_receipt_sequence: Option<Counter>,
    pub policy_identifier: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundedReplayMode {
    Bounded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ReplayRetention {
    Permanent(PermanentReplayRetention),
    Bounded(BoundedReplayRetention),
}

impl ReplayRetention {
    pub fn permanent() -> Self {
        Self::Permanent(PermanentReplayRetention {
            mode: PermanentReplayMode::Permanent,
            permanent_replay_eligible: true,
            pruned_through_receipt_sequence: None,
            policy_identifier: None,
        })
    }

    pub fn cutoff(&self) -> Option<&Counter> {
        match self {
            Self::Permanent(_) => None,
            Self::Bounded(value) => value.pruned_through_receipt_sequence.as_ref(),
        }
    }

    pub fn is_permanent(&self) -> bool {
        matches!(self, Self::Permanent(_))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionCheckpoint {
    pub execution_checkpoint_format: String,
    pub execution_checkpoint_schema_version: i64,
    pub root_instance_id: String,
    pub revision: Counter,
    pub root_record: RootRecord,
    pub replay_retention: ReplayRetention,
    pub next_delivery_sequence: Counter,
    pub pending_deliveries: Vec<PendingDelivery>,
    pub next_operation_receipt_sequence: Counter,
    pub operation_receipts: Vec<OperationReceipt>,
    pub pending_outbox_intents: Vec<PendingOutboxIntent>,
    pub next_outbox_terminal_sequence: Counter,
    pub terminal_outbox_records: Vec<TerminalOutboxRecord>,
    pub outbox_effect_tombstones: Vec<OutboxEffectTombstone>,
    pub migration_audit_records: Vec<MigrationAuditRecord>,
    pub execution_checkpoint_digest: String,
}

impl ExecutionCheckpoint {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CheckpointError> {
        serde_json_canonicalizer::to_vec(self).map_err(|error| invalid(error.to_string()))
    }

    /// Validates the complete closed JSON representation and every semantic
    /// invariant required before a checkpoint candidate is persisted.
    pub fn validate_for_persistence(
        &self,
        resolver: &(impl DefinitionResolver + ?Sized),
    ) -> Result<(), CheckpointError> {
        let value = serde_json::to_value(self).map_err(|error| invalid(error.to_string()))?;
        validate_checkpoint_schema(&value)?;
        self.validate_semantics(resolver)
    }

    pub fn recompute_digest(&mut self) -> Result<(), CheckpointError> {
        let mut value = serde_json::to_value(&*self).map_err(|error| invalid(error.to_string()))?;
        value
            .as_object_mut()
            .ok_or_else(|| invalid("checkpoint must serialize as an object"))?
            .remove("execution_checkpoint_digest");
        self.execution_checkpoint_digest =
            hash_tagged(json!(["determa-execution-checkpoint-digest-1", value]))?;
        Ok(())
    }

    pub fn increment_revision(&mut self) {
        self.revision.allocate();
    }

    pub fn retained_aggregate(&self) -> Option<&AggregateEnvelope> {
        match &self.root_record {
            RootRecord::Retained(value) => Some(&value.aggregate_state),
            RootRecord::Tombstone(_) => None,
        }
    }

    pub fn validate_semantics(
        &self,
        resolver: &(impl DefinitionResolver + ?Sized),
    ) -> Result<(), CheckpointError> {
        match &self.root_record {
            RootRecord::Retained(record) => {
                let bytes = record
                    .aggregate_state
                    .canonical_bytes()
                    .map_err(|error| invalid(error.to_string()))?;
                crate::format1::restore_aggregate(&bytes, resolver)
                    .map_err(|error| invalid(error.to_string()))?;
                if record.aggregate_state.root_instance_id != self.root_instance_id {
                    return Err(invalid("retained aggregate belongs to another root"));
                }
            }
            RootRecord::Tombstone(_) => {
                if !self.pending_deliveries.is_empty() || !self.pending_outbox_intents.is_empty() {
                    return Err(invalid("tombstoned root retains pending work"));
                }
            }
        }
        self.validate_receipts()?;
        self.validate_deliveries()?;
        self.validate_outbox()?;
        self.validate_migration_audit()?;
        self.validate_root_record()?;
        Ok(())
    }

    fn validate_receipts(&self) -> Result<(), CheckpointError> {
        let Some(OperationReceipt::Creation(creation)) = self.operation_receipts.first() else {
            return Err(invalid("creation receipt must be first"));
        };
        if creation.receipt_sequence != Counter::zero()
            || creation.committed_revision != Counter::zero()
        {
            return Err(invalid(
                "creation receipt must be sequence and revision zero",
            ));
        }
        if creation.creation_id.is_empty() {
            return Err(invalid("creation id is empty"));
        }
        ensure_strict_order(
            self.operation_receipts
                .iter()
                .map(OperationReceipt::receipt_sequence),
            "operation receipts",
        )?;
        ensure_strict_order(
            self.operation_receipts
                .iter()
                .map(OperationReceipt::committed_revision),
            "receipt commit revisions",
        )?;
        let zero = Counter::zero();
        for receipt in &self.operation_receipts {
            if receipt.receipt_sequence() >= &self.next_operation_receipt_sequence {
                return Err(invalid("receipt sequence reaches its next counter"));
            }
            if receipt.committed_revision() > &self.revision {
                return Err(invalid("receipt commit revision is in the future"));
            }
            let references = receipt.emission_references();
            for (index, reference) in references.iter().enumerate() {
                if reference.emission_index() != &Counter::from(index) {
                    return Err(invalid("emission indexes are not contiguous"));
                }
            }
            match receipt {
                OperationReceipt::Creation(value) => {
                    if value.receipt_sequence != zero {
                        return Err(invalid("multiple creation receipts are not allowed"));
                    }
                }
                OperationReceipt::Delivery(value) => {
                    if value.accepted_revision > value.committed_revision {
                        return Err(invalid("delivery acceptance follows its commit"));
                    }
                    if value.accepted_revision == value.committed_revision
                        && (!matches!(value.delivery_mode, DeliveryMode::Input)
                            || !matches!(value.origin, DeliveryOrigin::HostInput(_)))
                    {
                        return Err(invalid(
                            "only foreground host input may share acceptance and commit revision",
                        ));
                    }
                    validate_outcome(&value.outcome, value.emission_references.is_empty())?;
                }
                OperationReceipt::MaintenanceMigration(value) => {
                    ensure_strict_order(
                        value.migration_sequences.iter(),
                        "maintenance migration sequences",
                    )?;
                    match value.result_code {
                        MaintenanceMigrationResultCode::MigrationApplied
                            if value.migration_sequences.is_empty() =>
                        {
                            return Err(invalid("applied migration has no audit sequence"));
                        }
                        MaintenanceMigrationResultCode::MigrationNoOperation
                            if !value.migration_sequences.is_empty()
                                || value.source_aggregate_state_digest
                                    != value.resulting_aggregate_state_digest =>
                        {
                            return Err(invalid("no-operation migration receipt is inconsistent"));
                        }
                        _ => {}
                    }
                }
            }
        }

        let cutoff = self.replay_retention.cutoff();
        let expected_start = cutoff
            .cloned()
            .map(|mut value| {
                value.allocate();
                value
            })
            .unwrap_or_else(|| Counter::from(1_u64));
        let retained_non_creation = self.operation_receipts.iter().skip(1);
        let mut expected = expected_start;
        for receipt in retained_non_creation {
            if receipt.receipt_sequence() != &expected {
                return Err(invalid("receipt retention contains an unattested gap"));
            }
            expected.allocate();
        }
        if expected != self.next_operation_receipt_sequence {
            return Err(invalid(
                "next receipt sequence does not follow retained horizon",
            ));
        }

        match &self.replay_retention {
            ReplayRetention::Permanent(value) => {
                if !value.permanent_replay_eligible
                    || value.pruned_through_receipt_sequence.is_some()
                    || value.policy_identifier.is_some()
                {
                    return Err(invalid("permanent replay retention is inconsistent"));
                }
            }
            ReplayRetention::Bounded(value) => {
                if value.permanent_replay_eligible || value.policy_identifier.is_empty() {
                    return Err(invalid("bounded replay retention is inconsistent"));
                }
                if value
                    .pruned_through_receipt_sequence
                    .as_ref()
                    .is_some_and(|cutoff| cutoff == &Counter::zero())
                {
                    return Err(invalid("bounded cutoff must be positive"));
                }
            }
        }
        Ok(())
    }

    fn validate_deliveries(&self) -> Result<(), CheckpointError> {
        ensure_strict_order(
            self.pending_deliveries
                .iter()
                .map(|value| &value.delivery_sequence),
            "pending deliveries",
        )?;
        let mut event_ids = BTreeSet::new();
        let mut delivery_sequences = BTreeSet::new();
        let receipts = self
            .operation_receipts
            .iter()
            .filter_map(|receipt| match receipt {
                OperationReceipt::Delivery(value) => Some(value),
                _ => None,
            })
            .collect::<Vec<_>>();
        for pending in &self.pending_deliveries {
            if pending.delivery_sequence >= self.next_delivery_sequence
                || pending.accepted_revision > self.revision
            {
                return Err(invalid("pending delivery counters are inconsistent"));
            }
            validate_mode_origin(pending.delivery_mode, &pending.origin)?;
            validate_envelope_root(&pending.envelope, &self.root_instance_id)?;
            if envelope_digest(
                &self.root_instance_id,
                pending.delivery_mode,
                &pending.envelope,
            )? != pending.envelope_digest
            {
                return Err(invalid("pending delivery digest mismatch"));
            }
            if !event_ids.insert(pending.envelope.event_id.clone())
                || !delivery_sequences.insert(pending.delivery_sequence.clone())
            {
                return Err(invalid("duplicate pending delivery identity"));
            }
            self.validate_internal_origin(
                &pending.origin,
                pending.accepted_revision.clone(),
                &pending.envelope.event_id,
                &pending.delivery_sequence,
            )?;
        }
        for receipt in receipts {
            validate_mode_origin(receipt.delivery_mode, &receipt.origin)?;
            if receipt.accepted_delivery_sequence >= self.next_delivery_sequence {
                return Err(invalid("delivery receipt sequence reaches next counter"));
            }
            if !event_ids.insert(receipt.event_id.clone())
                || !delivery_sequences.insert(receipt.accepted_delivery_sequence.clone())
            {
                return Err(invalid(
                    "delivery identity overlaps pending or committed work",
                ));
            }
            self.validate_internal_origin(
                &receipt.origin,
                receipt.accepted_revision.clone(),
                &receipt.event_id,
                &receipt.accepted_delivery_sequence,
            )?;
        }
        if self.replay_retention.is_permanent() {
            let mut expected = Counter::zero();
            for sequence in delivery_sequences {
                if sequence != expected {
                    return Err(invalid("permanent delivery allocation contains a gap"));
                }
                expected.allocate();
            }
            if expected != self.next_delivery_sequence {
                return Err(invalid(
                    "next delivery sequence contains an unallocated gap",
                ));
            }
        }
        for receipt in &self.operation_receipts {
            for reference in receipt.emission_references() {
                if let EmissionReference::InternalDelivery {
                    event_id,
                    delivery_sequence,
                    ..
                } = reference
                {
                    let pending_match = self.pending_deliveries.iter().any(|pending| {
                        &pending.delivery_sequence == delivery_sequence
                            && &pending.envelope.event_id == event_id
                    });
                    let receipt_match = self.operation_receipts.iter().any(|candidate| {
                        matches!(
                            candidate,
                            OperationReceipt::Delivery(delivery)
                                if &delivery.accepted_delivery_sequence == delivery_sequence
                                    && &delivery.event_id == event_id
                        )
                    });
                    if !pending_match && !receipt_match && self.replay_retention.is_permanent() {
                        return Err(invalid("internal emission reference is dangling"));
                    }
                }
            }
        }
        Ok(())
    }

    fn validate_internal_origin(
        &self,
        origin: &DeliveryOrigin,
        accepted_revision: Counter,
        event_id: &str,
        delivery_sequence: &Counter,
    ) -> Result<(), CheckpointError> {
        let DeliveryOrigin::InternalEmission(origin) = origin else {
            return Ok(());
        };
        let producer = self
            .operation_receipts
            .iter()
            .find(|receipt| receipt.receipt_sequence() == &origin.producing_receipt_sequence)
            .ok_or_else(|| invalid("internal origin producer is absent"))?;
        if producer.committed_revision() != &accepted_revision {
            return Err(invalid(
                "internal delivery acceptance revision differs from producer commit",
            ));
        }
        let index = counter_to_usize(&origin.emission_index)?;
        let Some(EmissionReference::InternalDelivery {
            event_id: referenced_event_id,
            delivery_sequence: referenced_delivery_sequence,
            ..
        }) = producer.emission_references().get(index)
        else {
            return Err(invalid(
                "internal origin does not name a producer reference",
            ));
        };
        if referenced_event_id != event_id || referenced_delivery_sequence != delivery_sequence {
            return Err(invalid(
                "internal origin differs from its producer reference",
            ));
        }
        Ok(())
    }

    fn validate_outbox(&self) -> Result<(), CheckpointError> {
        ensure_strict_order(
            self.pending_outbox_intents
                .iter()
                .map(|value| &value.intent.sequence),
            "pending outbox intents",
        )?;
        ensure_strict_order(
            self.terminal_outbox_records
                .iter()
                .map(|value| &value.terminal_sequence),
            "terminal outbox records",
        )?;
        ensure_strict_order(
            self.outbox_effect_tombstones
                .iter()
                .map(|value| &value.terminal_sequence),
            "outbox effect tombstones",
        )?;
        let producers = self.external_effect_producers()?;
        let mut effects = BTreeSet::new();
        let mut terminal_sequences = BTreeSet::new();
        for pending in &self.pending_outbox_intents {
            validate_typed_map(&pending.intent.payload)?;
            let producer_revision = producers.get(&pending.intent.effect_id);
            if self.replay_retention.is_permanent() && producer_revision.is_none() {
                return Err(invalid("pending outbox intent has no producer"));
            }
            if pending.state_revision > self.revision
                || producer_revision.is_some_and(|revision| revision > &pending.state_revision)
                || !effects.insert(pending.intent.effect_id.clone())
            {
                return Err(invalid("pending outbox state is inconsistent"));
            }
        }
        for terminal in &self.terminal_outbox_records {
            validate_typed_map(&terminal.intent.payload)?;
            let producer_revision = producers.get(&terminal.intent.effect_id);
            if self.replay_retention.is_permanent() && producer_revision.is_none() {
                return Err(invalid("terminal outbox record has no producer"));
            }
            if terminal.committed_revision > self.revision
                || producer_revision.is_some_and(|revision| revision > &terminal.committed_revision)
                || terminal.terminal_sequence >= self.next_outbox_terminal_sequence
                || !effects.insert(terminal.intent.effect_id.clone())
                || !terminal_sequences.insert(terminal.terminal_sequence.clone())
            {
                return Err(invalid("terminal outbox record is inconsistent"));
            }
        }
        for tombstone in &self.outbox_effect_tombstones {
            let producer_revision = producers.get(&tombstone.effect_id);
            if self.replay_retention.is_permanent() && producer_revision.is_none() {
                return Err(invalid("outbox effect tombstone has no producer"));
            }
            if tombstone.committed_revision > self.revision
                || producer_revision
                    .is_some_and(|revision| revision > &tombstone.committed_revision)
                || tombstone.terminal_sequence >= self.next_outbox_terminal_sequence
                || !effects.insert(tombstone.effect_id.clone())
                || !terminal_sequences.insert(tombstone.terminal_sequence.clone())
            {
                return Err(invalid("outbox effect tombstone is inconsistent"));
            }
        }
        for effect_id in producers.keys() {
            if !effects.contains(effect_id) && self.replay_retention.is_permanent() {
                return Err(invalid("external emission reference is dangling"));
            }
        }
        Ok(())
    }

    fn external_effect_producers(&self) -> Result<BTreeMap<String, Counter>, CheckpointError> {
        let mut producers = BTreeMap::new();
        for receipt in &self.operation_receipts {
            for reference in receipt.emission_references() {
                if let EmissionReference::ExternalOutbox { effect_id, .. } = reference {
                    if producers
                        .insert(effect_id.clone(), receipt.committed_revision().clone())
                        .is_some()
                    {
                        return Err(invalid("effect id has multiple producers"));
                    }
                }
            }
        }
        Ok(producers)
    }

    fn validate_migration_audit(&self) -> Result<(), CheckpointError> {
        let ordered_sequences = self
            .migration_audit_records
            .iter()
            .map(|value| Counter::from_decimal(&value.migration_sequence).map_err(invalid))
            .collect::<Result<Vec<_>, _>>()?;
        ensure_strict_order(ordered_sequences.iter(), "migration audit records")?;
        let mut audits = BTreeMap::new();
        for (audit, sequence) in self
            .migration_audit_records
            .iter()
            .zip(ordered_sequences.iter())
        {
            if audit.root_instance_id != self.root_instance_id {
                return Err(invalid("migration audit belongs to another root"));
            }
            if audits.insert(sequence.clone(), audit).is_some() {
                return Err(invalid("duplicate migration audit sequence"));
            }
        }
        let mut maintenance_references = BTreeMap::new();
        for receipt in &self.operation_receipts {
            if let OperationReceipt::MaintenanceMigration(receipt) = receipt {
                for sequence in &receipt.migration_sequences {
                    if !audits.contains_key(sequence) {
                        return Err(invalid("migration receipt references absent audit"));
                    }
                    if maintenance_references
                        .insert(sequence.clone(), receipt.receipt_sequence.clone())
                        .is_some()
                    {
                        return Err(invalid("migration audit has multiple receipt references"));
                    }
                }
            }
        }
        if self.replay_retention.is_permanent() {
            self.validate_permanent_migration_evidence(&audits, &maintenance_references)?;
        }
        Ok(())
    }

    fn validate_permanent_migration_evidence(
        &self,
        audits: &BTreeMap<Counter, &MigrationAuditRecord>,
        maintenance_references: &BTreeMap<Counter, Counter>,
    ) -> Result<(), CheckpointError> {
        let mut remaining = audits.iter().peekable();
        let mut prior_digest = self
            .operation_receipts
            .first()
            .expect("creation receipt validated")
            .resulting_aggregate_state_digest();
        for receipt in self.operation_receipts.iter().skip(1) {
            match receipt {
                OperationReceipt::MaintenanceMigration(maintenance) => {
                    for sequence in &maintenance.migration_sequences {
                        let Some((next_sequence, audit)) = remaining.next() else {
                            return Err(invalid("migration receipt evidence is absent"));
                        };
                        if next_sequence != sequence
                            || audit.source_aggregate_state_digest != prior_digest
                        {
                            return Err(invalid(
                                "maintenance migration evidence is not commit ordered",
                            ));
                        }
                        prior_digest = &audit.target_aggregate_state_digest;
                    }
                    if prior_digest != maintenance.resulting_aggregate_state_digest {
                        return Err(invalid(
                            "maintenance receipt differs from its migration evidence",
                        ));
                    }
                }
                OperationReceipt::Delivery(delivery) => {
                    while let Some((sequence, audit)) = remaining.peek().copied() {
                        if maintenance_references.contains_key(sequence)
                            || audit.source_aggregate_state_digest != prior_digest
                        {
                            break;
                        }
                        prior_digest = &audit.target_aggregate_state_digest;
                        remaining.next();
                    }
                    prior_digest = &delivery.resulting_aggregate_state_digest;
                }
                OperationReceipt::Creation(_) => {
                    return Err(invalid("multiple creation receipts are not allowed"));
                }
            }
        }
        if remaining.next().is_some() {
            return Err(invalid(
                "migration audit has no retained operation evidence",
            ));
        }
        Ok(())
    }

    fn validate_root_record(&self) -> Result<(), CheckpointError> {
        let creation = match &self.operation_receipts[0] {
            OperationReceipt::Creation(value) => value,
            _ => unreachable!("validated first receipt"),
        };
        match &self.root_record {
            RootRecord::Retained(record) => {
                if record.aggregate_state.creation_id != creation.creation_id {
                    return Err(invalid(
                        "aggregate creation id differs from creation receipt",
                    ));
                }
                if self.latest_aggregate_evidence().is_some_and(|receipt| {
                    receipt.resulting_aggregate_state_digest()
                        != record.aggregate_state.aggregate_state_digest
                }) {
                    return Err(invalid(
                        "current aggregate digest differs from latest operation receipt",
                    ));
                }
                let root_runtime = record
                    .aggregate_state
                    .runtimes
                    .iter()
                    .find(|runtime| runtime.runtime_id == record.aggregate_state.root_runtime_id)
                    .ok_or_else(|| invalid("aggregate root runtime is absent"))?;
                if self
                    .latest_status_evidence()
                    .is_some_and(|status| status != root_runtime.status)
                {
                    return Err(invalid(
                        "aggregate root status differs from latest operation receipt",
                    ));
                }
            }
            RootRecord::Tombstone(tombstone) => {
                if tombstone.creation_id != creation.creation_id {
                    return Err(invalid(
                        "tombstone creation id differs from creation receipt",
                    ));
                }
                if self.latest_aggregate_evidence().is_some_and(|receipt| {
                    receipt.resulting_aggregate_state_digest()
                        != tombstone.final_aggregate_state_digest
                }) {
                    return Err(invalid(
                        "tombstone final digest differs from latest retained aggregate evidence",
                    ));
                }
                if self.latest_status_evidence().is_some_and(|status| {
                    !matches!(
                        (status, tombstone.terminal_status),
                        (RuntimeStatus::Completed, TerminalRootStatus::Completed)
                            | (RuntimeStatus::Faulted, TerminalRootStatus::Faulted)
                    )
                }) {
                    return Err(invalid(
                        "tombstone terminal status differs from latest operation receipt",
                    ));
                }
                if tombstone.tombstone_operation_id.is_empty() {
                    return Err(invalid("tombstone operation id is empty"));
                }
            }
        }
        Ok(())
    }

    fn latest_aggregate_evidence(&self) -> Option<&OperationReceipt> {
        let latest = self.operation_receipts.last()?;
        if latest.receipt_sequence() == &Counter::zero() && self.replay_retention.cutoff().is_some()
        {
            None
        } else {
            Some(latest)
        }
    }

    fn latest_status_evidence(&self) -> Option<RuntimeStatus> {
        let receipt = self.operation_receipts.iter().rev().find(|receipt| {
            matches!(
                receipt,
                OperationReceipt::Creation(_) | OperationReceipt::Delivery(_)
            )
        })?;
        if receipt.receipt_sequence() == &Counter::zero()
            && self.replay_retention.cutoff().is_some()
        {
            return None;
        }
        match receipt {
            OperationReceipt::Creation(value) => Some(value.status),
            OperationReceipt::Delivery(value) => Some(value.outcome.status),
            OperationReceipt::MaintenanceMigration(_) => unreachable!("filtered above"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreAcceptanceFailure {
    pub code: PreAcceptanceFailureCode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreAcceptanceFailureCode {
    MalformedDelivery,
    WrongRoot,
    InvalidDeliveryMode,
    InvalidDeliveryOrigin,
    DeliveryDigestMismatch,
    EventIdConflict,
    TombstonedRoot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotAcceptedResult {
    pub result: NotAcceptedResultKind,
    pub failure: PreAcceptanceFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotAcceptedResultKind {
    NotAccepted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingAcceptanceResult {
    pub result: PendingAcceptanceResultKind,
    pub event_id: String,
    pub delivery_sequence: Counter,
    pub accepted_revision: Counter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingAcceptanceResultKind {
    Pending,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommittedDeliveryResult {
    pub result: CommittedResultKind,
    pub receipt: DeliveryReceipt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommittedResultKind {
    Committed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)] // Keep public result alternatives direct and schema-shaped.
pub enum AcceptanceResult {
    Pending(PendingAcceptanceResult),
    Committed(CommittedDeliveryResult),
    NotAccepted(NotAcceptedResult),
}

pub fn restore_execution_checkpoint(
    source: &[u8],
    resolver: &(impl DefinitionResolver + ?Sized),
) -> Result<ExecutionCheckpoint, CheckpointError> {
    let value =
        crate::format1::strict_json::parse(source).map_err(|error| invalid(error.to_string()))?;
    let object = value
        .as_object()
        .ok_or_else(|| unsupported_format("checkpoint must be an object"))?;
    match object.get("execution_checkpoint_format") {
        Some(JsonValue::String(value)) if value == "determa.execution_checkpoint" => {}
        _ => return Err(unsupported_format("unsupported checkpoint format")),
    }
    match object.get("execution_checkpoint_schema_version") {
        Some(JsonValue::Number(value)) if value.as_i64() == Some(1) => {}
        _ => {
            return Err(CheckpointError::new(
                CheckpointErrorCode::UnsupportedExecutionCheckpointSchemaVersion,
                "unsupported checkpoint schema version",
            ));
        }
    }
    validate_checkpoint_schema(&value)?;
    let checkpoint: ExecutionCheckpoint =
        serde_json::from_value(value.clone()).map_err(|error| invalid(error.to_string()))?;
    if let RootRecord::Retained(record) = &checkpoint.root_record {
        let aggregate = record
            .aggregate_state
            .canonical_bytes()
            .map_err(|error| invalid(error.to_string()))?;
        crate::format1::restore_aggregate(&aggregate, resolver)
            .map_err(|error| invalid(error.to_string()))?;
    }
    let mut without_digest = value;
    without_digest
        .as_object_mut()
        .expect("checkpoint object checked")
        .remove("execution_checkpoint_digest");
    let digest = hash_tagged(json!([
        "determa-execution-checkpoint-digest-1",
        without_digest
    ]))?;
    if digest != checkpoint.execution_checkpoint_digest {
        return Err(CheckpointError::new(
            CheckpointErrorCode::ExecutionCheckpointDigestMismatch,
            "execution checkpoint digest does not match",
        ));
    }
    checkpoint.validate_semantics(resolver)?;
    Ok(checkpoint)
}

/// Validates the context-dependent evidence retained by one outbox compaction.
///
/// Both checkpoint values are semantically validated here. Callers starting from
/// bytes should restore them first to verify schema and canonical digests. The
/// synchronous host owns the remaining mutation and compare-and-swap invariants.
pub fn validate_outbox_compaction(
    before: &ExecutionCheckpoint,
    after: &ExecutionCheckpoint,
    effect_id: &str,
    resolver: &(impl DefinitionResolver + ?Sized),
) -> Result<(), CheckpointError> {
    before.validate_semantics(resolver)?;
    after.validate_semantics(resolver)?;
    if before.root_instance_id != after.root_instance_id {
        return Err(invalid("outbox compaction changes root identity"));
    }
    let terminal = before
        .terminal_outbox_records
        .iter()
        .find(|record| record.intent.effect_id == effect_id)
        .ok_or_else(|| invalid("outbox compaction source record is absent"))?;
    let tombstone = after
        .outbox_effect_tombstones
        .iter()
        .find(|record| record.effect_id == effect_id)
        .ok_or_else(|| invalid("outbox compaction tombstone is absent"))?;
    if terminal.terminal_sequence != tombstone.terminal_sequence
        || terminal.committed_revision != tombstone.committed_revision
        || terminal.outcome != tombstone.outcome
        || outbox_intent_digest(&before.root_instance_id, &terminal.intent)?
            != tombstone.intent_digest
    {
        return Err(invalid(
            "outbox compaction tombstone differs from the complete original intent",
        ));
    }
    Ok(())
}

pub(crate) fn envelope_digest(
    root_instance_id: &str,
    delivery_mode: DeliveryMode,
    envelope: &PortableEnvelope,
) -> Result<String, CheckpointError> {
    envelope_digest_for_mode(
        root_instance_id,
        match delivery_mode {
            DeliveryMode::Input => "input",
            DeliveryMode::Internal => "internal",
        },
        envelope,
    )
}

pub(crate) fn envelope_digest_for_mode(
    root_instance_id: &str,
    delivery_mode: &str,
    envelope: &PortableEnvelope,
) -> Result<String, CheckpointError> {
    hash_tagged(json!([
        "determa-inbox-envelope-digest-1",
        "1",
        root_instance_id,
        delivery_mode,
        envelope
    ]))
}

pub(crate) fn outbox_intent_digest(
    root_instance_id: &str,
    intent: &OutboxIntent,
) -> Result<String, CheckpointError> {
    hash_tagged(json!([
        "determa-outbox-intent-digest-1",
        "1",
        root_instance_id,
        intent
    ]))
}

pub(crate) fn hash_tagged(value: JsonValue) -> Result<String, CheckpointError> {
    let bytes =
        serde_json_canonicalizer::to_vec(&value).map_err(|error| invalid(error.to_string()))?;
    let digest = Sha256::digest(bytes);
    Ok(format!("sha256:{digest:x}"))
}

fn validate_checkpoint_schema(value: &JsonValue) -> Result<(), CheckpointError> {
    let schema: JsonValue = serde_json::from_str(include_str!(
        "../../schema/execution-checkpoint.schema.json"
    ))
    .expect("bundled checkpoint schema is valid");
    let aggregate_schema: JsonValue =
        serde_json::from_str(include_str!("../../schema/aggregate-state.schema.json"))
            .expect("bundled aggregate schema is valid");
    let aggregate_resource = jsonschema::Resource::from_contents(aggregate_schema)
        .map_err(|error| invalid(error.to_string()))?;
    let validator = jsonschema::options()
        .with_resource(
            "https://determa.dev/state/schema/aggregate-state.schema.json",
            aggregate_resource,
        )
        .build(&schema)
        .map_err(|error| invalid(error.to_string()))?;
    if let Some(error) = validator.iter_errors(value).next() {
        return Err(invalid(error.to_string()));
    }
    Ok(())
}

fn validate_mode_origin(
    mode: DeliveryMode,
    origin: &DeliveryOrigin,
) -> Result<(), CheckpointError> {
    if matches!(
        (mode, origin),
        (DeliveryMode::Input, DeliveryOrigin::HostInput(_))
            | (DeliveryMode::Internal, DeliveryOrigin::InternalEmission(_))
    ) {
        Ok(())
    } else {
        Err(invalid("delivery mode and origin are inconsistent"))
    }
}

fn validate_envelope_root(
    envelope: &PortableEnvelope,
    root_instance_id: &str,
) -> Result<(), CheckpointError> {
    if envelope.event_id.is_empty()
        || envelope.root_instance_id() != Some(root_instance_id)
        || matches!(envelope.target, Target::External)
    {
        return Err(invalid(
            "delivery envelope does not belong to checkpoint root",
        ));
    }
    validate_typed_map(&envelope.payload)
}

fn validate_typed_map(value: &TypedValue) -> Result<(), CheckpointError> {
    if matches!(value, TypedValue::Map(_)) {
        Ok(())
    } else {
        Err(invalid("portable payload is not a typed map"))
    }
}

fn validate_outcome(outcome: &DeliveryOutcome, no_emissions: bool) -> Result<(), CheckpointError> {
    match outcome.disposition {
        Disposition::Handled => {}
        Disposition::Unhandled => {
            if outcome.status != RuntimeStatus::Running
                || outcome.fault.is_some()
                || outcome.rejection.is_some()
                || !no_emissions
            {
                return Err(invalid("unhandled outcome is inconsistent"));
            }
        }
        Disposition::Rejected => {
            if outcome.rejection.is_none() || !no_emissions {
                return Err(invalid("rejected outcome is inconsistent"));
            }
            if outcome.status == RuntimeStatus::Faulted {
                if outcome.fault.is_none() {
                    return Err(invalid("faulted rejected outcome lacks root fault"));
                }
            } else if outcome.fault.is_some() {
                return Err(invalid("non-faulted rejected outcome carries a fault"));
            }
        }
        Disposition::Faulted => {
            if outcome.status != RuntimeStatus::Faulted
                || outcome.fault.is_none()
                || outcome.rejection.is_some()
            {
                return Err(invalid("faulted outcome is inconsistent"));
            }
        }
    }
    Ok(())
}

fn ensure_strict_order<'a, T, I>(values: I, label: &str) -> Result<(), CheckpointError>
where
    T: Ord + 'a,
    I: IntoIterator<Item = &'a T>,
{
    let mut previous: Option<&T> = None;
    for value in values {
        if previous.is_some_and(|previous| previous >= value) {
            return Err(invalid(format!("{label} are not strictly ordered")));
        }
        previous = Some(value);
    }
    Ok(())
}

fn counter_to_usize(value: &Counter) -> Result<usize, CheckpointError> {
    value
        .to_string()
        .parse()
        .map_err(|_| invalid("counter is outside platform usize"))
}

fn unsupported_format(message: impl Into<String>) -> CheckpointError {
    CheckpointError::new(
        CheckpointErrorCode::UnsupportedExecutionCheckpointFormat,
        message,
    )
}

fn invalid(message: impl Into<String>) -> CheckpointError {
    CheckpointError::new(CheckpointErrorCode::InvalidExecutionCheckpoint, message)
}
