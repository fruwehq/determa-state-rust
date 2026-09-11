use crate::format1::{Counter, MigrationRequest, ResourceLimits, TypedValue};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq)]
pub enum AdmissionSource {
    Utf8Json(Vec<u8>),
    JsonValue(Value),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessingRequest {
    pub target_runtime_id: String,
    pub event_id: String,
    pub envelope_digest: String,
    pub acceptance_sequence: String,
    pub queue_sequence: String,
    pub processing_mode: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PruneRequest {
    pub cutoff_receipt_sequence: String,
    pub target_mode: String,
    pub policy_identifier: Option<String>,
    pub dependency_receipt_sequences: Vec<String>,
    pub dependency_effect_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TransactionalProcessRequest {
    pub delivery: Value,
    pub processing_mode: String,
    pub migration: MigrationRequest,
    pub migration_limits: ResourceLimits,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointErrorCode {
    ExecutionCheckpointDigestMismatch,
    InvalidExecutionCheckpoint,
    UnsupportedExecutionCheckpointFormat,
    UnsupportedExecutionCheckpointSchemaVersion,
}

impl CheckpointErrorCode {
    pub const PORTABLE_CODES: &'static [Self] = &[
        Self::ExecutionCheckpointDigestMismatch,
        Self::InvalidExecutionCheckpoint,
        Self::UnsupportedExecutionCheckpointFormat,
        Self::UnsupportedExecutionCheckpointSchemaVersion,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExecutionCheckpointDigestMismatch => "execution_checkpoint_digest_mismatch",
            Self::InvalidExecutionCheckpoint => "invalid_execution_checkpoint",
            Self::UnsupportedExecutionCheckpointFormat => "unsupported_execution_checkpoint_format",
            Self::UnsupportedExecutionCheckpointSchemaVersion => {
                "unsupported_execution_checkpoint_schema_version"
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreAcceptanceFailureCode {
    DeliveryDigestMismatch,
    DuplicateEventIdInBatch,
    EventIdConflict,
    InactiveComponentTarget,
    InvalidCorrelation,
    InvalidDeliveryMode,
    InvalidDeliverySource,
    InvalidEvent,
    InvalidInstanceTarget,
    InvalidPayload,
    MalformedDelivery,
    TerminalRoot,
    TombstonedRoot,
    WrongRoot,
}

impl PreAcceptanceFailureCode {
    pub const PORTABLE_CODES: &'static [Self] = &[
        Self::DeliveryDigestMismatch,
        Self::DuplicateEventIdInBatch,
        Self::EventIdConflict,
        Self::InactiveComponentTarget,
        Self::InvalidCorrelation,
        Self::InvalidDeliveryMode,
        Self::InvalidDeliverySource,
        Self::InvalidEvent,
        Self::InvalidInstanceTarget,
        Self::InvalidPayload,
        Self::MalformedDelivery,
        Self::TerminalRoot,
        Self::TombstonedRoot,
        Self::WrongRoot,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::DeliveryDigestMismatch => "delivery_digest_mismatch",
            Self::DuplicateEventIdInBatch => "duplicate_event_id_in_batch",
            Self::EventIdConflict => "event_id_conflict",
            Self::InactiveComponentTarget => "inactive_component_target",
            Self::InvalidCorrelation => "invalid_correlation",
            Self::InvalidDeliveryMode => "invalid_delivery_mode",
            Self::InvalidDeliverySource => "invalid_delivery_source",
            Self::InvalidEvent => "invalid_event",
            Self::InvalidInstanceTarget => "invalid_instance_target",
            Self::InvalidPayload => "invalid_payload",
            Self::MalformedDelivery => "malformed_delivery",
            Self::TerminalRoot => "terminal_root",
            Self::TombstonedRoot => "tombstoned_root",
            Self::WrongRoot => "wrong_root",
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum TerminalOutboxOutcome {
    Confirmed,
    PermanentlyRejected { reason_code: String },
    OperatorCancelled { reason_code: String },
    Discarded { reason_code: String },
    DeadLettered { reason_code: String },
}
