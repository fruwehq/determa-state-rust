//! Bound native invocation only. This is not a worker claim or a durable effect
//! host; authority, committed-intent selection and atomic journal writes belong
//! to the host. A transport/handler error never proves that no external call ran.

use super::{ConfiguredExtension, ExtensionError, ExtensionErrorCode, ExtensionRegistry};
use crate::format1::TypedValue;
use serde_json::Value;
use std::sync::Arc;

/// Host-owned metadata borrowed unchanged for one invocation. Credentials stay
/// outside typed payloads, checkpoint bytes and journal digests. Credential bytes
/// cannot carry a downcastable host transaction; construct SDK objects internally.
/// Trusted installation must also exclude captured host mutation capabilities;
/// an in-process native handler is not isolated by this interface alone.
pub struct NativeHandlerMetadata<'a> {
    pub scope_identity: &'a str,
    pub effect_id: &'a str,
    pub operation_token: &'a str,
    pub destination_binding_digest: &'a str,
    pub route_configuration_generation: &'a str,
    pub handler_reference: &'a Value,
    pub credential: &'a [u8],
}

pub struct NativeHandlerAttempt<'a> {
    pub attempt_fence: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeHandlerReportKind {
    Succeeded,
    DomainRejected,
    RetryableFailure,
    TerminalFailure,
    Cancelled,
    Ambiguous,
}

/// A candidate report. In particular, RetryableFailure does not itself authorize
/// retry; the host must independently establish safe retry and retain its evidence.
pub struct NativeHandlerReport {
    pub kind: NativeHandlerReportKind,
    pub payload: TypedValue,
    pub reason: Option<String>,
}

/// Native objects created internally by the handler never cross this interface.
/// An extension provider binds an Arc<dyn NativeHandler> as its native instance.
pub trait NativeHandler: Send + Sync {
    fn destination_binding_digest(&self) -> Result<String, ExtensionError>;
    fn invoke(
        &self,
        payload: &TypedValue,
        metadata: &NativeHandlerMetadata<'_>,
        attempt: &NativeHandlerAttempt<'_>,
    ) -> Result<NativeHandlerReport, ExtensionError>;
}

/// External evidence is independently authenticated against the native destination.
/// This context cannot be substituted with an effect from another logical scope.
pub struct NativeDeduplicationEvidence<'a> {
    pub scope_identity: &'a str,
    pub effect_id: &'a str,
    pub destination_binding_digest: &'a str,
    pub evidence: &'a Value,
}

/// Only the registry can construct this exact source/configuration/native binding.
pub struct VerifiedNativeHandler {
    registry: Arc<ExtensionRegistry>,
    configured: ConfiguredExtension,
    adapter: Arc<dyn NativeHandler>,
    destination: String,
}

fn mismatch(message: impl Into<String>) -> ExtensionError {
    ExtensionError::new(ExtensionErrorCode::ExtensionCapabilityMismatch, message)
}

fn digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    })
}

fn decimal(value: &str) -> bool {
    value == "0"
        || (!value.is_empty()
            && !value.starts_with('0')
            && value.bytes().all(|byte| byte.is_ascii_digit()))
}

fn portable(payload: &TypedValue) -> Result<(), ExtensionError> {
    // TypedValue has public variants. Deserialize its projection to enforce
    // canonical map ordering/uniqueness and float spellings, not just convert a
    // map into a BTreeMap (which would silently collapse duplicate keys).
    let wire = serde_json::to_value(payload).map_err(|error| mismatch(error.to_string()))?;
    let normalized: TypedValue =
        serde_json::from_value(wire).map_err(|error| mismatch(error.to_string()))?;
    if normalized != *payload {
        return Err(mismatch("noncanonical typed handler payload"));
    }
    payload
        .to_value(None)
        .map_err(|error| mismatch(error.to_string()))?;
    Ok(())
}

impl ExtensionRegistry {
    pub fn configure_native_handler(
        self: &Arc<Self>,
        descriptor: &Value,
        configuration: &Value,
    ) -> Result<VerifiedNativeHandler, ExtensionError> {
        if descriptor["category"] != "native_handler" {
            return Err(mismatch(
                "native invocation requires a native_handler provider",
            ));
        }
        let destination = configuration["destination_binding_digest"]
            .as_str()
            .filter(|destination| digest(destination))
            .ok_or_else(|| mismatch("exact destination binding is required"))?
            .to_owned();
        let configured = self.validate_configuration(descriptor, configuration)?;
        let native = self.native_instance(&configured)?;
        let adapter = native
            .downcast_ref::<Arc<dyn NativeHandler>>()
            .cloned()
            .ok_or_else(|| mismatch("provider did not bind a native handler"))?;
        let handler = VerifiedNativeHandler {
            registry: self.clone(),
            configured,
            adapter,
            destination,
        };
        handler.verify(&descriptor["provider_reference"], &handler.destination)?;
        Ok(handler)
    }
}

impl VerifiedNativeHandler {
    pub fn verify(&self, reference: &Value, destination: &str) -> Result<(), ExtensionError> {
        let native = self.registry.native_instance(&self.configured)?;
        let bound = native
            .downcast_ref::<Arc<dyn NativeHandler>>()
            .is_some_and(|adapter| Arc::ptr_eq(adapter, &self.adapter));
        if !bound
            || reference != &self.configured.descriptor["provider_reference"]
            || destination != self.destination
            || self.adapter.destination_binding_digest()? != self.destination
            || self.registry.report(&self.configured)?["health"] != "healthy"
        {
            return Err(mismatch(
                "native handler source, destination or health changed",
            ));
        }
        Ok(())
    }

    /// Called by a trusted host only after its committed-intent, worker and scope
    /// authorization checks. This handle grants none of those rights. An error
    /// after invocation is ambiguous, never permission to retry automatically.
    pub fn invoke(
        &self,
        payload: &TypedValue,
        metadata: &NativeHandlerMetadata<'_>,
        attempt: &NativeHandlerAttempt<'_>,
    ) -> Result<NativeHandlerReport, ExtensionError> {
        self.invoke_with_guard(payload, metadata, attempt, || Ok(()))
    }

    /// The host rechecks live rights after all pre-call provider verification.
    /// This callback adds no rights to the verified handler handle.
    pub(crate) fn invoke_with_guard(
        &self,
        payload: &TypedValue,
        metadata: &NativeHandlerMetadata<'_>,
        attempt: &NativeHandlerAttempt<'_>,
        guard: impl FnOnce() -> Result<(), ExtensionError>,
    ) -> Result<NativeHandlerReport, ExtensionError> {
        if metadata.scope_identity.is_empty()
            || metadata.operation_token.is_empty()
            || !digest(metadata.effect_id)
            || !decimal(metadata.route_configuration_generation)
            || !decimal(attempt.attempt_fence)
            || attempt.attempt_fence == "0"
        {
            return Err(mismatch("invalid native invocation identity"));
        }
        portable(payload)?;
        self.verify(
            metadata.handler_reference,
            metadata.destination_binding_digest,
        )?;
        guard()?;
        let report = self.adapter.invoke(payload, metadata, attempt)?;
        // Source/health changes during an external call cannot turn its candidate
        // result into an authorized host outcome or erase possible acceptance.
        self.verify(
            metadata.handler_reference,
            metadata.destination_binding_digest,
        )?;
        portable(&report.payload)?;
        if report
            .reason
            .as_ref()
            .is_some_and(|reason| reason.is_empty())
        {
            return Err(mismatch("handler reason must be a stable nonempty code"));
        }
        Ok(report)
    }

    pub fn verify_deduplication_evidence(
        &self,
        reference: &Value,
        evidence: &NativeDeduplicationEvidence<'_>,
    ) -> Result<(), ExtensionError> {
        if evidence.scope_identity.is_empty() || !digest(evidence.effect_id) {
            return Err(mismatch("invalid scoped destination evidence"));
        }
        self.verify(reference, evidence.destination_binding_digest)?;
        if !self.registry.verifier.as_ref().is_some_and(|verifier| {
            verifier.prove_native_destination_deduplication(
                &self.configured.descriptor,
                &self.configured.configuration,
                &self.configured.instance,
                evidence,
            )
        }) {
            return Err(mismatch("native destination deduplication is unproved"));
        }
        self.verify(reference, evidence.destination_binding_digest)
    }
}
