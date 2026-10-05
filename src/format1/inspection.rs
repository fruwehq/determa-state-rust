//! Exact, read-only candidate inspection of one restored format-1 aggregate.

use super::compile::{Bundle, State};
use super::inspection_cel::{self, InspectionEvaluationError};
use super::native::jcs_hash;
use super::persistence::DefinitionResolver;
use super::runtime::{
    action_environment, runtime_by_id, validate_delivery_for_admission, visible_variables,
    NativeAggregate, RuntimeState, RuntimeStatus,
};
use super::v1::{
    core_delivery, restore_aggregate_v1, validate_source, validate_v1_schema, AdmissionDelivery,
    QueueEnvelope, Version1Error,
};
use crate::value::Value;
use serde_json::{json, Value as JsonValue};
use std::collections::{BTreeMap, BTreeSet};

const REQUEST_SCHEMA: &str = r#"{
  "$ref":"https://determa.dev/state/schema/inspection-v1.schema.json#/$defs/request"
}"#;
const INSPECTION_SCHEMA: &str = include_str!("../../schema/inspection-v1.schema.json");
const AGGREGATE_SCHEMA: &str = include_str!("../../schema/aggregate-state-v1.schema.json");
const RESOURCES: &[(&str, &str)] = &[
    (
        "https://determa.dev/state/schema/inspection-v1.schema.json",
        INSPECTION_SCHEMA,
    ),
    (
        "https://determa.dev/state/schema/aggregate-state-v1.schema.json",
        AGGREGATE_SCHEMA,
    ),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InspectionCapabilities {
    /// A configured, independently bounded portable CEL guard inspector is available.
    pub safe_semantic_cel: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InspectionDispositionCode {
    HandledNow,
    Deferred,
    Unhandled,
    Invalid,
}

impl InspectionDispositionCode {
    pub const PORTABLE_CODES: &'static [Self] = &[
        Self::HandledNow,
        Self::Deferred,
        Self::Unhandled,
        Self::Invalid,
    ];
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HandledNow => "handled_now",
            Self::Deferred => "deferred",
            Self::Unhandled => "unhandled",
            Self::Invalid => "invalid",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InspectionFailureCode {
    InvalidInspectionRequest,
    InspectionCapabilityUnavailable,
    InspectionGuardFailure,
    InspectionLimitExceeded,
}

impl InspectionFailureCode {
    pub const PORTABLE_CODES: &'static [Self] = &[
        Self::InvalidInspectionRequest,
        Self::InspectionCapabilityUnavailable,
        Self::InspectionGuardFailure,
        Self::InspectionLimitExceeded,
    ];
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidInspectionRequest => "invalid_inspection_request",
            Self::InspectionCapabilityUnavailable => "inspection_capability_unavailable",
            Self::InspectionGuardFailure => "inspection_guard_failure",
            Self::InspectionLimitExceeded => "inspection_limit_exceeded",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InspectionReasonCode {
    TargetNotFound,
    TargetIncarnationMismatch,
    InvalidEnvelope,
    RuntimeInactive,
}

impl InspectionReasonCode {
    pub const PORTABLE_CODES: &'static [Self] = &[
        Self::TargetNotFound,
        Self::TargetIncarnationMismatch,
        Self::InvalidEnvelope,
        Self::RuntimeInactive,
    ];
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TargetNotFound => "target_not_found",
            Self::TargetIncarnationMismatch => "target_incarnation_mismatch",
            Self::InvalidEnvelope => "invalid_envelope",
            Self::RuntimeInactive => "runtime_inactive",
        }
    }
}

impl Default for InspectionCapabilities {
    fn default() -> Self {
        Self {
            safe_semantic_cel: true,
        }
    }
}

fn failure(code: &str, locator: Option<&str>) -> JsonValue {
    json!({"code":code,"source_locator":locator})
}

fn outcome(
    request: &JsonValue,
    fingerprint: &str,
    possibilities: &[&str],
    reason: Option<&str>,
    levels: &[JsonValue],
    evidence: &[JsonValue],
) -> JsonValue {
    json!({
        "aggregate_state_digest":request["aggregate_state_digest"],
        "definition_fingerprint":fingerprint,
        "runtime_id":request["runtime_id"],
        "runtime_incarnation":request["runtime_incarnation"],
        "classification":if possibilities.len()==1 {"definitive"} else {"conditional"},
        "possible_dispositions":possibilities,
        "disposition":if possibilities.len()==1 {Some(possibilities[0])} else {None},
        "reason":reason,
        "levels":levels,
        "guard_evidence":evidence
    })
}

fn limits(request: &JsonValue) -> Option<(usize, usize)> {
    if request["mode"] == "structural" {
        return request["limits"].is_null().then_some((0, 0));
    }
    let guard = request["limits"]["maximum_guard_evaluations"].as_str()?;
    let steps = request["limits"]["maximum_evaluation_steps"].as_str()?;
    if guard.len() > 2 || steps.len() > 7 {
        return None;
    }
    let guard = guard.parse::<usize>().ok()?;
    let steps = steps.parse::<usize>().ok()?;
    (guard <= 64 && steps <= 1_000_000).then_some((guard, steps))
}

fn branch(
    state: &State,
    event: &str,
    index: usize,
    fingerprint: &str,
    bundle: &Bundle,
) -> Result<JsonValue, Version1Error> {
    let transition = &state.handlers[event][index];
    let Some(locator) = transition.guard_pointer.as_deref() else {
        return Ok(
            json!({"branch_index":index.to_string(),"guard_locator":null,
            "guard_binding_digest":null}),
        );
    };
    let guard = bundle.normalized.pointer(locator).ok_or_else(|| {
        Version1Error::new("invalid_aggregate_state", "guard pointer is unresolved")
    })?;
    let typed = typed_guard(guard)?;
    let digest = jcs_hash(&json!([
        "determa-guard-binding-1",
        fingerprint,
        locator,
        typed
    ]))
    .map_err(|error| Version1Error::new("invalid_aggregate_state", error.to_string()))?;
    Ok(
        json!({"branch_index":index.to_string(),"guard_locator":locator,
        "guard_binding_digest":digest}),
    )
}

fn typed_guard(guard: &JsonValue) -> Result<JsonValue, Version1Error> {
    match guard {
        JsonValue::Null => Ok(json!(["null", null])),
        JsonValue::Bool(value) => Ok(json!(["boolean", value])),
        JsonValue::String(value) => Ok(json!(["string", value])),
        JsonValue::Number(value) if value.is_i64() => Ok(json!(["integer", value.as_i64()])),
        JsonValue::Number(value) => Ok(json!(["float", value.as_f64()])),
        JsonValue::Array(items) => Ok(json!([
            "list",
            items
                .iter()
                .map(typed_guard)
                .collect::<Result<Vec<_>, _>>()?
        ])),
        JsonValue::Object(items) => Ok(json!([
            "map",
            items
                .iter()
                .map(|(key, value)| Ok(json!([key, typed_guard(value)?])))
                .collect::<Result<Vec<_>, Version1Error>>()?
        ])),
    }
}

fn active_levels(runtime: &RuntimeState) -> Vec<&State> {
    let mut leaves = runtime.config();
    if leaves.is_empty() && runtime.active.contains("root") {
        leaves.push("root".to_string());
    }
    leaves.sort_by_key(|path| std::cmp::Reverse(path.split('/').count()));
    let mut seen = BTreeSet::new();
    let mut states = Vec::new();
    for leaf in leaves {
        let mut cursor = Some(leaf);
        while let Some(path) = cursor {
            let state = &runtime.definition.states[&path];
            if seen.insert(path) {
                states.push(state);
            }
            cursor = state.parent.clone();
        }
    }
    states
}

fn structural(levels: &[JsonValue]) -> Vec<&'static str> {
    let mut possibilities = BTreeSet::new();
    let mut can_fall_through = true;
    for level in levels {
        if !can_fall_through {
            break;
        }
        let branches = level["handler_branches"]
            .as_array()
            .expect("built branch list");
        if !branches.is_empty() {
            possibilities.insert("handled_now");
            if branches.iter().any(|item| item["guard_locator"].is_null()) {
                can_fall_through = false;
            }
        }
        if can_fall_through && level["defers"] == true {
            possibilities.insert("deferred");
            can_fall_through = false;
        }
    }
    if can_fall_through {
        possibilities.insert("unhandled");
    }
    ["handled_now", "deferred", "unhandled"]
        .into_iter()
        .filter(|value| possibilities.contains(value))
        .collect()
}

fn snapshot_units(envelope: &QueueEnvelope, variables: &BTreeMap<String, Value>) -> usize {
    // The envelope is normalized portable data. Its payload is a typed projection,
    // so count the decoded payload rather than the array tags used on the wire.
    let mut plain = serde_json::to_value(envelope).expect("validated queue envelope");
    if let Ok(decoded) = envelope.payload.to_value(None) {
        plain["payload"] = serde_json::to_value(decoded).expect("portable payload value");
    }
    inspection_cel::json_units(&plain)
        + variables
            .values()
            .map(inspection_cel::value_units)
            .sum::<usize>()
}

/// Inspect a candidate without admitting, dispatching, or mutating its aggregate.
///
/// Closed operation failures are returned as values. Invalid aggregate artifacts
/// retain the normal artifact error channel used by `restore_aggregate`.
pub fn inspect_candidate(
    aggregate: &NativeAggregate,
    request: &JsonValue,
    resolver: &(impl DefinitionResolver + ?Sized),
    capabilities: InspectionCapabilities,
) -> Result<JsonValue, Version1Error> {
    if validate_v1_schema(
        request,
        REQUEST_SCHEMA,
        RESOURCES,
        "invalid_inspection_request",
    )
    .is_err()
        || limits(request).is_none()
    {
        return Ok(failure("invalid_inspection_request", None));
    }
    let aggregate = restore_aggregate_v1(&aggregate.canonical_bytes()?, resolver)?;
    if request["aggregate_state_digest"] != aggregate.document["aggregate_state_digest"] {
        return Ok(failure("invalid_inspection_request", None));
    }
    let root_fingerprint = aggregate
        .root
        .current_definition
        .validated_bundle_fingerprint
        .as_str();
    let runtime_id = request["runtime_id"]
        .as_str()
        .expect("validated runtime ID");
    let Some(runtime) = runtime_by_id(&aggregate.root, runtime_id) else {
        return Ok(outcome(
            request,
            root_fingerprint,
            &["invalid"],
            Some("target_not_found"),
            &[],
            &[],
        ));
    };
    let fingerprint = runtime
        .current_definition
        .validated_bundle_fingerprint
        .as_str();
    let runtime_wire = aggregate.document["runtimes"]
        .as_array()
        .expect("restored runtimes")
        .iter()
        .find(|item| item["runtime_id"] == runtime_id)
        .expect("restored runtime record");
    if runtime_wire["identity_origin"] != request["runtime_incarnation"] {
        return Ok(outcome(
            request,
            root_fingerprint,
            &["invalid"],
            Some("target_incarnation_mismatch"),
            &[],
            &[],
        ));
    }
    if runtime.status != RuntimeStatus::Running {
        return Ok(outcome(
            request,
            fingerprint,
            &["invalid"],
            Some("runtime_inactive"),
            &[],
            &[],
        ));
    }
    let envelope: QueueEnvelope = serde_json::from_value(request["envelope"].clone())
        .expect("request schema validates envelope");
    let delivery = AdmissionDelivery {
        delivery_mode: if envelope.source == json!({"host":true}) {
            "input".to_string()
        } else {
            "internal".to_string()
        },
        envelope: envelope.clone(),
        envelope_digest: String::new(),
    };
    let bundle = resolver.resolve_definition(fingerprint).ok_or_else(|| {
        Version1Error::new(
            "source_definition_unavailable",
            "runtime definition unavailable",
        )
    })?;
    if !bundle.trusted || bundle.bundle.fingerprint != fingerprint {
        return Err(Version1Error::new(
            "source_definition_untrusted",
            "runtime definition untrusted",
        ));
    }
    let valid = runtime_wire["target_identity"] == envelope.target
        && validate_source(&delivery, &aggregate.document).is_ok()
        && core_delivery(&delivery).ok().is_some_and(|core| {
            validate_delivery_for_admission(&bundle.bundle, &aggregate, &core).is_ok()
        });
    if !valid {
        return Ok(outcome(
            request,
            fingerprint,
            &["invalid"],
            Some("invalid_envelope"),
            &[],
            &[],
        ));
    }
    let states = active_levels(runtime);
    let mut levels = Vec::with_capacity(states.len());
    for state in &states {
        let branches = (0..state.handlers.get(&envelope.event).map_or(0, Vec::len))
            .map(|index| branch(state, &envelope.event, index, fingerprint, &bundle.bundle))
            .collect::<Result<Vec<_>, _>>()?;
        levels.push(json!({"state_id":state.pointer,"handler_branches":branches,
            "defers":state.deferred_events.iter().any(|event| event==&envelope.event)}));
    }
    if request["mode"] == "structural" {
        return Ok(outcome(
            request,
            fingerprint,
            &structural(&levels),
            None,
            &levels,
            &[],
        ));
    }
    if !capabilities.safe_semantic_cel {
        return Ok(failure("inspection_capability_unavailable", None));
    }
    // Resolve every potentially reached native guard before evaluating any CEL.
    for transition in states
        .iter()
        .flat_map(|state| state.handlers.get(&envelope.event).into_iter().flatten())
    {
        if let Some(super::model::Guard::Provider { provider }) = &transition.guard {
            let available = runtime
                .definition
                .runtime_providers
                .as_ref()
                .is_some_and(|registry| registry.can_inspect(provider).unwrap_or(false));
            if !available {
                return Ok(failure("inspection_capability_unavailable", None));
            }
        }
    }
    let (mut guard_limit, mut step_limit) = limits(request).expect("validated limits");
    let mut evidence = Vec::new();
    for (state, level) in states.iter().zip(&levels) {
        if let Some(branches) = state.handlers.get(&envelope.event) {
            for (index, transition) in branches.iter().enumerate() {
                let Some(guard) = transition.guard.as_ref() else {
                    return Ok(outcome(
                        request,
                        fingerprint,
                        &["handled_now"],
                        None,
                        &levels,
                        &evidence,
                    ));
                };
                let info = &level["handler_branches"][index];
                let locator = info["guard_locator"].as_str().expect("guard locator");
                if guard_limit == 0 {
                    return Ok(failure("inspection_limit_exceeded", Some(locator)));
                }
                guard_limit -= 1;
                let variables = visible_variables(runtime, &state.path);
                let snapshot = snapshot_units(&envelope, &variables);
                let core = core_delivery(&delivery).expect("validated delivery");
                let core_envelope = match core {
                    super::model::Delivery::Input(envelope)
                    | super::model::Delivery::Internal(envelope) => envelope,
                };
                let environment = action_environment(runtime, &state.path, Some(&core_envelope));
                let value = match guard {
                    super::model::Guard::Cel(source) => match inspection_cel::safe_evaluate(
                        source,
                        &environment.values,
                        step_limit,
                        snapshot,
                    ) {
                        Ok((value, spent)) => {
                            step_limit -= spent;
                            value
                        }
                        Err(InspectionEvaluationError::Limit) => {
                            return Ok(failure("inspection_limit_exceeded", Some(locator)))
                        }
                        Err(InspectionEvaluationError::Guard) => {
                            return Ok(failure("inspection_guard_failure", Some(locator)))
                        }
                    },
                    super::model::Guard::Provider { provider } => {
                        let registry = runtime
                            .definition
                            .runtime_providers
                            .as_ref()
                            .expect("preflight registry");
                        let snapshot = super::runtime::provider_snapshot(
                            runtime,
                            &state.path,
                            Some(&core_envelope),
                            provider,
                        );
                        match registry.inspect(provider, &snapshot, guard_limit + 1, step_limit) {
                            Ok((value, spent)) => {
                                step_limit -= spent;
                                value
                            }
                            Err(error) if error.code == "inspection_limit_exceeded" => {
                                return Ok(failure("inspection_limit_exceeded", Some(locator)))
                            }
                            Err(_) => {
                                return Ok(failure("inspection_guard_failure", Some(locator)))
                            }
                        }
                    }
                };
                evidence.push(
                    json!({"state_id":state.pointer,"branch_index":info["branch_index"],
                    "guard_locator":info["guard_locator"],
                    "guard_binding_digest":info["guard_binding_digest"],"value":value}),
                );
                if value {
                    return Ok(outcome(
                        request,
                        fingerprint,
                        &["handled_now"],
                        None,
                        &levels,
                        &evidence,
                    ));
                }
            }
        }
        if level["defers"] == true {
            return Ok(outcome(
                request,
                fingerprint,
                &["deferred"],
                None,
                &levels,
                &evidence,
            ));
        }
    }
    Ok(outcome(
        request,
        fingerprint,
        &["unhandled"],
        None,
        &levels,
        &evidence,
    ))
}
