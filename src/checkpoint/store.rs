#[cfg(any(feature = "sqlite", feature = "postgresql"))]
use serde_json::{json, Value};
#[cfg(any(feature = "sqlite", feature = "postgresql"))]
use sha2::{Digest, Sha256};
use std::any::Any;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, RwLock};

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
        checkpoint: &super::v2::ExecutionCheckpoint,
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

/// Public execution-store registry. A new registry is intentionally empty.
#[derive(Default)]
pub struct AdapterRegistry {
    factories: RwLock<BTreeMap<String, Arc<dyn ExecutionStoreFactory>>>,
}

impl AdapterRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(
        &self,
        identifier: &str,
        factory: Arc<dyn ExecutionStoreFactory>,
    ) -> Result<(), AdapterError> {
        if !valid_identifier(identifier) {
            return Err(AdapterError::new(
                AdapterErrorCode::InvalidAdapterConfiguration,
                "adapter identifier must be a lowercase URI scheme",
            ));
        }
        let mut factories = self.factories.write().map_err(|_| registry_poisoned())?;
        if factories.contains_key(identifier) {
            return Err(AdapterError::new(
                AdapterErrorCode::DuplicateAdapterRegistration,
                format!("adapter {identifier} is already registered"),
            ));
        }
        factories.insert(identifier.to_string(), factory);
        Ok(())
    }

    pub fn identifiers(&self) -> Result<Vec<String>, AdapterError> {
        let factories = self.factories.read().map_err(|_| registry_poisoned())?;
        Ok(factories.keys().cloned().collect())
    }

    pub fn resolve(
        &self,
        configuration: &str,
        requested_capabilities: &BTreeSet<ExecutionStoreCapability>,
    ) -> Result<Arc<dyn ExecutionStore>, AdapterError> {
        let identifier = extract_scheme(configuration)?;
        let factory = {
            let factories = self.factories.read().map_err(|_| registry_poisoned())?;
            factories.get(identifier).cloned().ok_or_else(|| {
                AdapterError::new(
                    AdapterErrorCode::UnknownAdapter,
                    format!("adapter {identifier} is not registered"),
                )
            })?
        };
        // The factory validates configuration before capability evaluation.
        let store = factory.create(configuration)?;
        let capabilities = store.capabilities();
        if !requested_capabilities.is_subset(&capabilities) {
            return Err(AdapterError::new(
                AdapterErrorCode::AdapterCapabilityMismatch,
                "configured store does not provide every requested capability",
            ));
        }
        Ok(store)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostProfile {
    DurableEmbeddedProcessing,
    ExactlyOnceCommittedProcessing,
    BrokerIntegrated,
    StrictDurableOutbox,
    CompactDurableOutbox,
    SharedApplicationTransaction,
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

pub fn validate_store_host_profile(
    store: &dyn ExecutionStore,
    profile: HostProfile,
    features: &BTreeSet<HostFeature>,
    permanent_replay_retention: bool,
) -> Result<(), AdapterError> {
    let capabilities = store.capabilities();
    let durable = capabilities.contains(&ExecutionStoreCapability::DurableSingleWriter)
        || capabilities.contains(&ExecutionStoreCapability::DurableConcurrent);
    let root_retained = capabilities.contains(&ExecutionStoreCapability::RootIdentityRetention);
    let atomic = features.contains(&HostFeature::AtomicCheckpointProcessing);
    let valid = match profile {
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
    };
    if valid {
        Ok(())
    } else {
        Err(AdapterError::new(
            AdapterErrorCode::AdapterCapabilityMismatch,
            "store and host composition does not satisfy the requested profile",
        ))
    }
}

#[cfg(any(feature = "sqlite", feature = "postgresql"))]
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
            || after_receipts[..before_receipts.len()] != *before_receipts)
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
        "determa-outbox-intent-digest-2",
        "2",
        root_instance_id,
        intent
    ]))
    .map_err(|error| StoreError::new(error.to_string()))?;
    Ok(Value::String(format!("sha256:{:x}", Sha256::digest(bytes))))
}

fn extract_scheme(configuration: &str) -> Result<&str, AdapterError> {
    let Some((scheme, _)) = configuration.split_once(':') else {
        return Err(AdapterError::new(
            AdapterErrorCode::InvalidAdapterConfiguration,
            "adapter configuration has no URI scheme",
        ));
    };
    if !valid_identifier(scheme) {
        return Err(AdapterError::new(
            AdapterErrorCode::InvalidAdapterConfiguration,
            "adapter configuration has an invalid URI scheme",
        ));
    }
    Ok(scheme)
}

fn valid_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(first) if first.is_ascii_lowercase())
        && bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'+' | b'.' | b'-')
        })
}

fn registry_poisoned() -> AdapterError {
    AdapterError::new(
        AdapterErrorCode::InvalidAdapterConfiguration,
        "adapter registry lock is poisoned",
    )
}
