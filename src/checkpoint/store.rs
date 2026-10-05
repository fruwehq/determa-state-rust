#[cfg(any(test, feature = "sqlite", feature = "postgresql"))]
use serde_json::json;
use serde_json::Value;
#[cfg(any(feature = "sqlite", feature = "postgresql"))]
use sha2::{Digest, Sha256};
use std::any::Any;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ExecutionStoreCapability {
    Ephemeral,
    RestartPersistent,
    DurableSingleWriter,
    DurableConcurrent,
    SharedApplicationTransaction,
    PermanentReceiptRetention,
    RootIdentityRetention,
    PermanentOutboxTerminalRetention,
    CompactEffectIdentityRetention,
}

impl ExecutionStoreCapability {
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "ephemeral" => Some(Self::Ephemeral),
            "restart_persistent" => Some(Self::RestartPersistent),
            "durable_single_writer" => Some(Self::DurableSingleWriter),
            "durable_concurrent" => Some(Self::DurableConcurrent),
            "shared_application_transaction" => Some(Self::SharedApplicationTransaction),
            "permanent_receipt_retention" => Some(Self::PermanentReceiptRetention),
            "root_identity_retention" => Some(Self::RootIdentityRetention),
            "permanent_outbox_terminal_retention" => Some(Self::PermanentOutboxTerminalRetention),
            "compact_effect_identity_retention" => Some(Self::CompactEffectIdentityRetention),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ephemeral => "ephemeral",
            Self::RestartPersistent => "restart_persistent",
            Self::DurableSingleWriter => "durable_single_writer",
            Self::DurableConcurrent => "durable_concurrent",
            Self::SharedApplicationTransaction => "shared_application_transaction",
            Self::PermanentReceiptRetention => "permanent_receipt_retention",
            Self::RootIdentityRetention => "root_identity_retention",
            Self::PermanentOutboxTerminalRetention => "permanent_outbox_terminal_retention",
            Self::CompactEffectIdentityRetention => "compact_effect_identity_retention",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptRetentionMode {
    Bounded,
    Permanent,
}

impl ReceiptRetentionMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bounded => "bounded",
            Self::Permanent => "permanent",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboxRetentionMode {
    Bounded,
    Strict,
    Compact,
}

impl OutboxRetentionMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bounded => "bounded",
            Self::Strict => "strict",
            Self::Compact => "compact",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DurableStoreMode {
    pub receipt_retention: ReceiptRetentionMode,
    pub outbox_retention: OutboxRetentionMode,
}

impl DurableStoreMode {
    pub const fn new(
        receipt_retention: ReceiptRetentionMode,
        outbox_retention: OutboxRetentionMode,
    ) -> Self {
        Self {
            receipt_retention,
            outbox_retention,
        }
    }

    pub const fn bounded() -> Self {
        Self::new(ReceiptRetentionMode::Bounded, OutboxRetentionMode::Bounded)
    }

    pub fn add_capabilities(self, capabilities: &mut BTreeSet<ExecutionStoreCapability>) {
        if self.receipt_retention == ReceiptRetentionMode::Permanent {
            capabilities.insert(ExecutionStoreCapability::PermanentReceiptRetention);
        }
        match self.outbox_retention {
            OutboxRetentionMode::Bounded => {}
            OutboxRetentionMode::Strict => {
                capabilities.insert(ExecutionStoreCapability::PermanentOutboxTerminalRetention);
            }
            OutboxRetentionMode::Compact => {
                capabilities.insert(ExecutionStoreCapability::CompactEffectIdentityRetention);
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreRecord {
    pub root_instance_id: String,
    pub revision: String,
    pub execution_checkpoint_digest: String,
    pub bytes: Vec<u8>,
}

impl StoreRecord {
    pub fn from_checkpoint(
        checkpoint: &super::v1::ExecutionCheckpoint,
    ) -> Result<Self, StoreError> {
        Ok(Self {
            root_instance_id: checkpoint.root_instance_id().to_string(),
            revision: checkpoint.revision().to_string(),
            execution_checkpoint_digest: checkpoint.digest().to_string(),
            bytes: checkpoint
                .canonical_bytes()
                .map_err(|error| StoreError::new(error.to_string()))?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreWriteResult {
    Committed,
    Conflict(Option<StoreRecord>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreError {
    pub code: StoreErrorCode,
    pub message: String,
}

impl StoreError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            code: StoreErrorCode::ExecutionStoreFailure,
            message: message.into(),
        }
    }

    pub fn injected_pre_commit(message: impl Into<String>) -> Self {
        Self {
            code: StoreErrorCode::InjectedPreCommitFailure,
            message: message.into(),
        }
    }

    pub fn response_lost_after_commit(message: impl Into<String>) -> Self {
        Self {
            code: StoreErrorCode::ResponseLostAfterCommit,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreErrorCode {
    ExecutionStoreFailure,
    InjectedPreCommitFailure,
    InvalidStoreScope,
    PermanentProcessingFailure,
    ResponseLostAfterCommit,
    TransientProcessingFailure,
}

impl StoreErrorCode {
    /// Complete execution-store failure set defined by the portable registry.
    ///
    /// `ExecutionStoreFailure` remains available for implementation failures but
    /// is intentionally not a portable execution-store failure code.
    pub const PORTABLE_CODES: &'static [Self] = &[
        Self::InjectedPreCommitFailure,
        Self::InvalidStoreScope,
        Self::PermanentProcessingFailure,
        Self::ResponseLostAfterCommit,
        Self::TransientProcessingFailure,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExecutionStoreFailure => "execution_store_failure",
            Self::InjectedPreCommitFailure => "injected_pre_commit_failure",
            Self::InvalidStoreScope => "invalid_store_scope",
            Self::PermanentProcessingFailure => "permanent_processing_failure",
            Self::ResponseLostAfterCommit => "response_lost_after_commit",
            Self::TransientProcessingFailure => "transient_processing_failure",
        }
    }
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for StoreError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthStatus {
    pub healthy: bool,
    pub detail: String,
}

impl HealthStatus {
    pub fn healthy(detail: impl Into<String>) -> Self {
        Self {
            healthy: true,
            detail: detail.into(),
        }
    }
}

/// Atomic checkpoint storage primitive.
///
/// The trait intentionally has no delete method. Root identity tombstones cannot
/// be physically removed through this API.
pub trait ExecutionStore: Send + Sync + Any {
    fn as_any(&self) -> &dyn Any;

    fn capabilities(&self) -> BTreeSet<ExecutionStoreCapability>;

    /// Explicitly creates or migrates adapter-owned storage.
    fn initialize_schema(&self) -> Result<(), StoreError>;

    fn health(&self) -> Result<HealthStatus, StoreError>;

    fn load(&self, root_instance_id: &str) -> Result<Option<StoreRecord>, StoreError>;

    fn insert_if_absent(&self, record: StoreRecord) -> Result<StoreWriteResult, StoreError>;

    fn compare_and_swap(
        &self,
        root_instance_id: &str,
        expected_revision: &str,
        expected_checkpoint_digest: &str,
        replacement: StoreRecord,
    ) -> Result<StoreWriteResult, StoreError>;
}

pub trait ExecutionStoreFactory: Send + Sync {
    fn create(&self, configuration: &str) -> Result<Arc<dyn ExecutionStore>, AdapterError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterErrorCode {
    DuplicateAdapterRegistration,
    UnknownAdapter,
    InvalidAdapterConfiguration,
    AdapterCapabilityMismatch,
}

impl AdapterErrorCode {
    /// Complete execution-store adapter failure set defined by the portable registry.
    pub const PORTABLE_CODES: &'static [Self] = &[
        Self::DuplicateAdapterRegistration,
        Self::UnknownAdapter,
        Self::InvalidAdapterConfiguration,
        Self::AdapterCapabilityMismatch,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::DuplicateAdapterRegistration => "duplicate_adapter_registration",
            Self::UnknownAdapter => "unknown_adapter",
            Self::InvalidAdapterConfiguration => "invalid_adapter_configuration",
            Self::AdapterCapabilityMismatch => "adapter_capability_mismatch",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterError {
    pub code: AdapterErrorCode,
    pub message: String,
}

impl AdapterError {
    pub fn new(code: AdapterErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for AdapterError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for AdapterError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostProfile {
    DurableEmbeddedProcessing,
    ExactlyOnceCommittedProcessing,
    BrokerIntegrated,
    StrictDurableOutbox,
    CompactDurableOutbox,
    SharedApplicationTransaction,
}

impl HostProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DurableEmbeddedProcessing => "durable_embedded_processing",
            Self::ExactlyOnceCommittedProcessing => "exactly_once_committed_processing",
            Self::BrokerIntegrated => "broker_integrated",
            Self::StrictDurableOutbox => "strict_durable_outbox",
            Self::CompactDurableOutbox => "compact_durable_outbox",
            Self::SharedApplicationTransaction => "shared_application_transaction",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HostFeature {
    AtomicCheckpointProcessing,
    AcknowledgeAfterCheckpointCommit,
    DurableRedelivery,
    OutboxWorker,
    TotalOutboxLifecycle,
    RetainUnresolvedOutbox,
    RetainReferencedEffectTombstones,
    NativeSharedApplicationTransaction,
}

impl HostFeature {
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "atomic_accept_process" => Some(Self::AtomicCheckpointProcessing),
            "ingress_ack_after_commit" => Some(Self::AcknowledgeAfterCheckpointCommit),
            "durable_redelivery" => Some(Self::DurableRedelivery),
            "outbox_worker" => Some(Self::OutboxWorker),
            "total_outbox_lifecycle" => Some(Self::TotalOutboxLifecycle),
            "retain_unresolved_outbox" => Some(Self::RetainUnresolvedOutbox),
            "retain_receipt_references" => Some(Self::RetainReferencedEffectTombstones),
            "native_shared_transaction_used" => Some(Self::NativeSharedApplicationTransaction),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AtomicCheckpointProcessing => "atomic_accept_process",
            Self::AcknowledgeAfterCheckpointCommit => "ingress_ack_after_commit",
            Self::DurableRedelivery => "durable_redelivery",
            Self::OutboxWorker => "outbox_worker",
            Self::TotalOutboxLifecycle => "total_outbox_lifecycle",
            Self::RetainUnresolvedOutbox => "retain_unresolved_outbox",
            Self::RetainReferencedEffectTombstones => "retain_receipt_references",
            Self::NativeSharedApplicationTransaction => "native_shared_transaction_used",
        }
    }
}

pub(crate) fn validate_store_host_profile(
    verified: &crate::extensions::VerifiedExecutionStore,
    profile: HostProfile,
    permanent_replay_retention: bool,
    context: &str,
) -> Result<(), AdapterError> {
    let capabilities = verified.current_capabilities().map_err(|error| {
        AdapterError::new(
            AdapterErrorCode::AdapterCapabilityMismatch,
            error.to_string(),
        )
    })?;
    let features = verified.current_host_features(context).map_err(|error| {
        AdapterError::new(
            AdapterErrorCode::AdapterCapabilityMismatch,
            error.to_string(),
        )
    })?;
    if hypothetical_host_profile_matches(
        &capabilities,
        &features,
        profile,
        permanent_replay_retention,
    ) {
        Ok(())
    } else {
        Err(AdapterError::new(
            AdapterErrorCode::AdapterCapabilityMismatch,
            "store and host composition does not satisfy the requested profile",
        ))
    }
}

/// Evaluate explicit composition premises without certifying any provider or host.
/// This pure predicate is useful for conformance vectors whose input guarantees
/// are hypotheses. Operational callers must use `CheckpointHost::validate_profile`.
#[doc(hidden)]
pub fn hypothetical_host_profile_matches(
    capabilities: &BTreeSet<ExecutionStoreCapability>,
    features: &BTreeSet<HostFeature>,
    profile: HostProfile,
    permanent_replay_retention: bool,
) -> bool {
    let durable = capabilities.contains(&ExecutionStoreCapability::DurableSingleWriter)
        || capabilities.contains(&ExecutionStoreCapability::DurableConcurrent);
    let root_retained = capabilities.contains(&ExecutionStoreCapability::RootIdentityRetention);
    let atomic = features.contains(&HostFeature::AtomicCheckpointProcessing);
    match profile {
        HostProfile::DurableEmbeddedProcessing => durable && root_retained && atomic,
        HostProfile::ExactlyOnceCommittedProcessing => {
            durable
                && root_retained
                && atomic
                && permanent_replay_retention
                && capabilities.contains(&ExecutionStoreCapability::PermanentReceiptRetention)
        }
        HostProfile::BrokerIntegrated => {
            durable
                && root_retained
                && atomic
                && features.contains(&HostFeature::AcknowledgeAfterCheckpointCommit)
                && features.contains(&HostFeature::DurableRedelivery)
                && features.contains(&HostFeature::OutboxWorker)
        }
        HostProfile::StrictDurableOutbox => {
            durable
                && root_retained
                && capabilities
                    .contains(&ExecutionStoreCapability::PermanentOutboxTerminalRetention)
                && features.contains(&HostFeature::OutboxWorker)
                && features.contains(&HostFeature::TotalOutboxLifecycle)
                && features.contains(&HostFeature::RetainUnresolvedOutbox)
        }
        HostProfile::CompactDurableOutbox => {
            durable
                && root_retained
                && capabilities.contains(&ExecutionStoreCapability::CompactEffectIdentityRetention)
                && features.contains(&HostFeature::OutboxWorker)
                && features.contains(&HostFeature::TotalOutboxLifecycle)
                && features.contains(&HostFeature::RetainReferencedEffectTombstones)
        }
        HostProfile::SharedApplicationTransaction => {
            durable
                && root_retained
                && capabilities.contains(&ExecutionStoreCapability::SharedApplicationTransaction)
                && features.contains(&HostFeature::NativeSharedApplicationTransaction)
        }
    }
}

#[cfg(feature = "sqlite")]
pub(crate) fn parse_durable_store_configuration(
    configuration: &str,
) -> Result<(&str, DurableStoreMode), AdapterError> {
    let (location, mode, adapter_options) =
        parse_durable_store_configuration_with_options(configuration, &[])?;
    debug_assert!(adapter_options.is_empty());
    Ok((location, mode))
}

#[cfg(any(feature = "sqlite", feature = "postgresql"))]
pub(crate) fn parse_durable_store_configuration_with_options<'a>(
    configuration: &'a str,
    allowed_options: &[&str],
) -> Result<(&'a str, DurableStoreMode, BTreeMap<String, String>), AdapterError> {
    let Some((location, options)) = configuration.rsplit_once('#') else {
        return Err(AdapterError::new(
            AdapterErrorCode::InvalidAdapterConfiguration,
            "durable adapter configuration requires explicit receipt_retention and outbox_retention options",
        ));
    };
    if location.is_empty() || options.is_empty() {
        return Err(AdapterError::new(
            AdapterErrorCode::InvalidAdapterConfiguration,
            "durable adapter location and retention options must be non-empty",
        ));
    }
    let mut receipt_retention = None;
    let mut outbox_retention = None;
    let mut adapter_options = BTreeMap::new();
    for option in options.split('&') {
        let Some((name, value)) = option.split_once('=') else {
            return Err(AdapterError::new(
                AdapterErrorCode::InvalidAdapterConfiguration,
                "durable adapter option must be a name=value pair",
            ));
        };
        match name {
            "receipt_retention" if receipt_retention.is_none() => {
                receipt_retention = Some(match value {
                    "bounded" => ReceiptRetentionMode::Bounded,
                    "permanent" => ReceiptRetentionMode::Permanent,
                    _ => {
                        return Err(AdapterError::new(
                            AdapterErrorCode::InvalidAdapterConfiguration,
                            "receipt_retention must be bounded or permanent",
                        ));
                    }
                });
            }
            "outbox_retention" if outbox_retention.is_none() => {
                outbox_retention = Some(match value {
                    "bounded" => OutboxRetentionMode::Bounded,
                    "strict" => OutboxRetentionMode::Strict,
                    "compact" => OutboxRetentionMode::Compact,
                    _ => {
                        return Err(AdapterError::new(
                            AdapterErrorCode::InvalidAdapterConfiguration,
                            "outbox_retention must be bounded, strict, or compact",
                        ));
                    }
                });
            }
            "receipt_retention" | "outbox_retention" => {
                return Err(AdapterError::new(
                    AdapterErrorCode::InvalidAdapterConfiguration,
                    format!("duplicate durable adapter option {name}"),
                ));
            }
            _ if allowed_options.contains(&name) => {
                if value.is_empty() {
                    return Err(AdapterError::new(
                        AdapterErrorCode::InvalidAdapterConfiguration,
                        format!("durable adapter option {name} must be non-empty"),
                    ));
                }
                if adapter_options
                    .insert(name.to_string(), value.to_string())
                    .is_some()
                {
                    return Err(AdapterError::new(
                        AdapterErrorCode::InvalidAdapterConfiguration,
                        format!("duplicate durable adapter option {name}"),
                    ));
                }
            }
            _ => {
                return Err(AdapterError::new(
                    AdapterErrorCode::InvalidAdapterConfiguration,
                    format!("unknown durable adapter option {name}"),
                ));
            }
        }
    }
    let Some(receipt_retention) = receipt_retention else {
        return Err(AdapterError::new(
            AdapterErrorCode::InvalidAdapterConfiguration,
            "receipt_retention option is required",
        ));
    };
    let Some(outbox_retention) = outbox_retention else {
        return Err(AdapterError::new(
            AdapterErrorCode::InvalidAdapterConfiguration,
            "outbox_retention option is required",
        ));
    };
    Ok((
        location,
        DurableStoreMode::new(receipt_retention, outbox_retention),
        adapter_options,
    ))
}

#[cfg(any(feature = "sqlite", feature = "postgresql"))]
pub(crate) fn validate_policy_insert(
    mode: DurableStoreMode,
    record: &StoreRecord,
) -> Result<(), StoreError> {
    if mode == DurableStoreMode::bounded() {
        return Ok(());
    }
    let checkpoint = policy_checkpoint(record)?;
    validate_policy_candidate(mode, &checkpoint)
}

#[cfg(any(feature = "sqlite", feature = "postgresql"))]
pub(crate) fn validate_policy_replacement(
    mode: DurableStoreMode,
    current: &StoreRecord,
    replacement: &StoreRecord,
) -> Result<(), StoreError> {
    if mode == DurableStoreMode::bounded() {
        return Ok(());
    }
    let before = policy_checkpoint(current)?;
    let after = policy_checkpoint(replacement)?;
    validate_policy_candidate(mode, &after)?;
    let before_receipts = before["operation_receipts"].as_array().unwrap();
    let after_receipts = after["operation_receipts"].as_array().unwrap();
    if mode.receipt_retention == ReceiptRetentionMode::Permanent
        && (after_receipts.len() < before_receipts.len()
            || before_receipts
                .iter()
                .zip(after_receipts)
                .any(|(prior, next)| !retained_receipt_evolves(prior, next, &before, &after)))
    {
        return Err(StoreError::new(
            "permanent receipt retention forbids receipt removal or replacement",
        ));
    }
    match mode.outbox_retention {
        OutboxRetentionMode::Bounded => {}
        OutboxRetentionMode::Strict => {
            for terminal in before["terminal_outbox_records"].as_array().unwrap() {
                if !after["terminal_outbox_records"]
                    .as_array()
                    .unwrap()
                    .contains(terminal)
                {
                    return Err(StoreError::new(
                        "strict outbox retention forbids terminal record removal or compaction",
                    ));
                }
            }
        }
        OutboxRetentionMode::Compact => {
            validate_compact_retention_transition(&before, &after)?;
        }
    }
    Ok(())
}

#[cfg(any(feature = "sqlite", feature = "postgresql"))]
fn retained_receipt_evolves(
    prior: &Value,
    next: &Value,
    before: &Value,
    checkpoint: &Value,
) -> bool {
    if prior == next {
        return true;
    }
    let mut prior_body = prior.clone();
    let mut next_body = next.clone();
    let prior_refs = prior_body
        .as_object_mut()
        .and_then(|body| body.remove("emission_references"));
    let next_refs = next_body
        .as_object_mut()
        .and_then(|body| body.remove("emission_references"));
    if prior_body != next_body {
        return false;
    }
    let (Some(prior_refs), Some(next_refs)) = (
        prior_refs.and_then(|refs| refs.as_array().cloned()),
        next_refs.and_then(|refs| refs.as_array().cloned()),
    ) else {
        return false;
    };
    prior_refs.len() == next_refs.len()
        && prior_refs.iter().zip(&next_refs).all(|(prior, next)| {
            if prior == next {
                return true;
            }
            if prior["kind"] != "internal_mailbox" {
                return false;
            }
            let mut old = prior.clone();
            let mut updated = next.clone();
            old.as_object_mut().unwrap().remove("kind");
            updated.as_object_mut().unwrap().remove("kind");
            old.as_object_mut().unwrap().remove("queue_sequence");
            updated.as_object_mut().unwrap().remove("queue_sequence");
            if next["kind"] == "internal_mailbox" && old == updated {
                let queue_advanced = prior["queue_sequence"]
                    .as_str()
                    .and_then(|value| crate::format1::Counter::from_decimal(value).ok())
                    .zip(
                        next["queue_sequence"]
                            .as_str()
                            .and_then(|value| crate::format1::Counter::from_decimal(value).ok()),
                    )
                    .is_some_and(|(prior, next)| {
                        before["root_record"]["aggregate_state"]["next_queue_sequence"]
                            .as_str()
                            .and_then(|value| crate::format1::Counter::from_decimal(value).ok())
                            .is_some_and(|floor| next > prior && next >= floor)
                    });
                return queue_advanced
                    && checkpoint["root_record"]["aggregate_state"]["runtimes"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .flat_map(|runtime| {
                            ["ready_mailbox", "deferred_mailbox"]
                                .into_iter()
                                .flat_map(|field| runtime[field].as_array().into_iter().flatten())
                        })
                        .filter(|entry| {
                            entry["delivery_mode"] == "internal"
                                && entry["envelope"]["event_id"] == next["event_id"]
                                && entry["acceptance_sequence"] == next["acceptance_sequence"]
                                && entry["queue_sequence"] == next["queue_sequence"]
                        })
                        .count()
                        == 1;
            }
            if next["kind"] == "internal_terminal" {
                let terminal = updated
                    .as_object_mut()
                    .unwrap()
                    .remove("terminal_receipt_sequence");
                let terminal_is_new = terminal
                    .as_ref()
                    .and_then(Value::as_str)
                    .and_then(|value| crate::format1::Counter::from_decimal(value).ok())
                    .zip(
                        prior_body["receipt_sequence"]
                            .as_str()
                            .and_then(|value| crate::format1::Counter::from_decimal(value).ok()),
                    )
                    .is_some_and(|(terminal, producer)| {
                        before["next_operation_receipt_sequence"]
                            .as_str()
                            .and_then(|value| crate::format1::Counter::from_decimal(value).ok())
                            .is_some_and(|floor| terminal > producer && terminal >= floor)
                    });
                return old == updated
                    && terminal_is_new
                    && terminal.is_some_and(|sequence| {
                        checkpoint["operation_receipts"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .filter(|receipt| {
                                receipt["operation_kind"] == "event_terminal"
                                    && receipt["receipt_sequence"] == sequence
                                    && receipt["event_id"] == next["event_id"]
                                    && receipt["acceptance_sequence"] == next["acceptance_sequence"]
                            })
                            .count()
                            == 1
                    });
            }
            false
        })
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgresql")))]
mod retention_transition_tests {
    use super::retained_receipt_evolves;
    use serde_json::json;

    #[test]
    fn permanent_receipts_allow_only_attested_internal_reference_evolution() {
        let prior = json!({"operation_kind":"creation","receipt_sequence":"0","emission_references":[{"kind":"internal_mailbox","emission_index":"0","event_id":"event-a","acceptance_sequence":"0","queue_sequence":"1"}]});
        let before = json!({"next_operation_receipt_sequence":"1","root_record":{"aggregate_state":{"next_queue_sequence":"2"}}});
        let mut next = prior.clone();
        next["emission_references"][0]["queue_sequence"] = json!("2");
        let mut after = json!({"root_record":{"aggregate_state":{"runtimes":[{"ready_mailbox":[],"deferred_mailbox":[{"delivery_mode":"internal","envelope":{"event_id":"event-a"},"acceptance_sequence":"0","queue_sequence":"2"}]}]}},"operation_receipts":[]});
        assert!(retained_receipt_evolves(&prior, &next, &before, &after));
        next["emission_references"][0]["event_id"] = json!("event-b");
        assert!(!retained_receipt_evolves(&prior, &next, &before, &after));
        next["emission_references"][0]["event_id"] = json!("event-a");
        next["emission_references"][0]["queue_sequence"] = json!("0");
        assert!(!retained_receipt_evolves(&prior, &next, &before, &after));
        next["emission_references"][0]["queue_sequence"] = json!("2");
        after["root_record"]["aggregate_state"]["runtimes"][0]["deferred_mailbox"][0]
            ["delivery_mode"] = json!("input");
        assert!(!retained_receipt_evolves(&prior, &next, &before, &after));
        after["root_record"]["aggregate_state"]["runtimes"][0]["deferred_mailbox"][0]
            ["delivery_mode"] = json!("internal");
        next["emission_references"][0] = json!({"kind":"internal_terminal","emission_index":"0","event_id":"event-a","acceptance_sequence":"0","terminal_receipt_sequence":"1"});
        after["operation_receipts"] = json!([{"operation_kind":"event_terminal","receipt_sequence":"1","event_id":"event-a","acceptance_sequence":"0"}]);
        assert!(retained_receipt_evolves(&prior, &next, &before, &after));
        after["operation_receipts"][0]["event_id"] = json!("event-b");
        assert!(!retained_receipt_evolves(&prior, &next, &before, &after));
    }
}

#[cfg(any(feature = "sqlite", feature = "postgresql"))]
fn policy_checkpoint(record: &StoreRecord) -> Result<Value, StoreError> {
    serde_json::from_slice(&record.bytes)
        .map_err(|error| StoreError::new(format!("checkpoint policy validation failed: {error}")))
}

#[cfg(any(feature = "sqlite", feature = "postgresql"))]
fn validate_policy_candidate(mode: DurableStoreMode, checkpoint: &Value) -> Result<(), StoreError> {
    if mode.receipt_retention == ReceiptRetentionMode::Permanent
        && checkpoint["replay_retention"]["mode"] != "permanent"
    {
        return Err(StoreError::new(
            "permanent receipt retention requires permanent checkpoint replay retention",
        ));
    }
    if mode.outbox_retention == OutboxRetentionMode::Strict
        && !checkpoint["outbox_effect_tombstones"]
            .as_array()
            .is_some_and(Vec::is_empty)
    {
        return Err(StoreError::new(
            "strict outbox retention forbids compact effect tombstones",
        ));
    }
    Ok(())
}

#[cfg(any(feature = "sqlite", feature = "postgresql"))]
fn validate_compact_retention_transition(before: &Value, after: &Value) -> Result<(), StoreError> {
    for tombstone in before["outbox_effect_tombstones"].as_array().unwrap() {
        let effect_id = tombstone["effect_id"].as_str().unwrap();
        if receipt_references_effect(after, effect_id)
            && !after["outbox_effect_tombstones"]
                .as_array()
                .unwrap()
                .contains(tombstone)
        {
            return Err(StoreError::new(
                "compact outbox retention forbids referenced tombstone removal",
            ));
        }
    }
    for terminal in before["terminal_outbox_records"].as_array().unwrap() {
        let effect_id = terminal["intent"]["effect_id"].as_str().unwrap();
        if !receipt_references_effect(after, effect_id)
            || after["terminal_outbox_records"]
                .as_array()
                .unwrap()
                .contains(terminal)
        {
            continue;
        }
        let retained_tombstone = after["outbox_effect_tombstones"]
            .as_array()
            .unwrap()
            .iter()
            .find(|value| value["effect_id"].as_str() == Some(effect_id));
        if !retained_tombstone.is_some_and(|tombstone| {
            compact_tombstone_matches(before, terminal, tombstone).unwrap_or(false)
        }) {
            return Err(StoreError::new(
                "compact outbox retention requires full intent or matching tombstone evidence",
            ));
        }
    }
    Ok(())
}

#[cfg(any(feature = "sqlite", feature = "postgresql"))]
fn compact_tombstone_matches(
    checkpoint: &Value,
    terminal: &Value,
    tombstone: &Value,
) -> Result<bool, StoreError> {
    Ok(
        terminal["terminal_sequence"] == tombstone["terminal_sequence"]
            && terminal["intent"]["effect_id"] == tombstone["effect_id"]
            && terminal["committed_revision"] == tombstone["committed_revision"]
            && terminal["outcome"] == tombstone["outcome"]
            && outbox_intent_digest(&checkpoint["root_instance_id"], &terminal["intent"])?
                == tombstone["intent_digest"],
    )
}

#[cfg(any(feature = "sqlite", feature = "postgresql"))]
fn receipt_references_effect(checkpoint: &Value, effect_id: &str) -> bool {
    checkpoint["operation_receipts"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|receipt| receipt["emission_references"].as_array())
        .flatten()
        .any(|reference| {
            reference["kind"] == "external_outbox"
                && reference["effect_id"].as_str() == Some(effect_id)
        })
}
#[cfg(any(feature = "sqlite", feature = "postgresql"))]
fn outbox_intent_digest(root_instance_id: &Value, intent: &Value) -> Result<Value, StoreError> {
    let bytes = serde_json_canonicalizer::to_vec(&json!([
        "determa-outbox-intent-digest-1",
        "1",
        root_instance_id,
        intent
    ]))
    .map_err(|error| StoreError::new(error.to_string()))?;
    Ok(Value::String(format!("sha256:{:x}", Sha256::digest(bytes))))
}
