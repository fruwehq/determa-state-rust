use determa_state::{
    create, dispatch, load_bundle, AggregateState, Bindings, CoreResult, Delivery, Disposition,
    Emission, Envelope, ResultStatus, RuntimeStatus, Target, Value,
};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

fn core_directory() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("conformance-suite")
        .join("conformance")
        .join("core")
}

#[test]
fn all_format_1_core_cases() {
    let mut cases = fs::read_dir(core_directory())
        .expect("conformance submodule is initialized")
        .map(|entry| entry.expect("case entry").path())
        .filter(|path| path.is_dir())
        .collect::<Vec<_>>();
    cases.sort();
    assert_eq!(cases.len(), 75, "expected the complete merged core suite");
    let mut failures = Vec::new();
    for case in cases {
        if let Err(error) = run_case(&case) {
            failures.push(format!(
                "{}: {error}",
                case.file_name().unwrap().to_string_lossy()
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} core case(s) failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

fn run_case(case: &Path) -> Result<(), String> {
    let test = parse_yaml(&fs::read_to_string(case.join("test.yaml")).map_err(display)?)?;
    let test = test
        .as_object()
        .ok_or_else(|| "test.yaml is not a map".to_string())?;
    if let Some(static_assertion) = test.get("static") {
        run_static_documents(case, static_assertion)?;
        if test
            .get("steps")
            .and_then(serde_json::Value::as_array)
            .is_none_or(Vec::is_empty)
            && test.get("create").is_none()
            && test.get("load").is_none()
        {
            return Ok(());
        }
    }
    let machine_path = case.join("machine.yaml");
    if !machine_path.exists() {
        return Ok(());
    }
    let source = fs::read_to_string(&machine_path).map_err(display)?;
    let bundle = load_bundle(&source).map_err(|error| format!("load: {error}"))?;
    if test
        .get("load")
        .and_then(|value| value.get("valid"))
        .and_then(serde_json::Value::as_bool)
        == Some(false)
    {
        return Err("primary bundle unexpectedly loaded".to_string());
    }
    let case_name = case.file_name().unwrap().to_string_lossy();
    let create_spec = test.get("create").and_then(serde_json::Value::as_object);
    let root_instance_id = create_spec
        .and_then(|create| create.get("root_instance_id"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| format!("conformance:{case_name}:root"));
    let creation_id = create_spec
        .and_then(|create| create.get("creation_id"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| format!("conformance:{case_name}:create"));
    if contains_invalid_unicode(create_spec.and_then(|create| create.get("root_instance_id"))) {
        let expected = create_spec
            .and_then(|create| create.get("expect"))
            .ok_or_else(|| "invalid-Unicode create lacks expectation".to_string())?;
        if expected
            .get("rejection")
            .and_then(|value| value.get("code"))
            .and_then(serde_json::Value::as_str)
            != Some("invalid_creation_request")
        {
            return Err("invalid-Unicode create expectation is inconsistent".to_string());
        }
        return Ok(());
    }
    let bindings = create_spec
        .and_then(|create| create.get("bindings"))
        .map(bindings_from_json)
        .transpose()?
        .unwrap_or_default();
    let machine_id = bundle
        .machine_order
        .first()
        .ok_or_else(|| "bundle has no root machine".to_string())?;
    let mut result = create(
        &bundle,
        machine_id,
        &root_instance_id,
        &creation_id,
        &bindings,
    );
    if let Some(expect) = create_spec.and_then(|create| create.get("expect")) {
        check_result(&result, expect, None)?;
    }
    if result.status == ResultStatus::Rejected {
        return Ok(());
    }
    let mut state = result
        .state
        .take()
        .ok_or_else(|| "creation returned no state".to_string())?;
    let mut captures: BTreeMap<String, Vec<Emission>> = BTreeMap::new();
    let steps = test
        .get("steps")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    for (step_index, step) in steps.iter().enumerate() {
        let step = step
            .as_object()
            .ok_or_else(|| format!("step {step_index} is not a map"))?;
        let (step_result, supplied_envelope) = if let Some(send) = step.get("send") {
            let send = send
                .as_object()
                .ok_or_else(|| format!("step {step_index} send is not a map"))?;
            if contains_invalid_unicode(send.get("payload")) {
                let expect = step
                    .get("expect")
                    .ok_or_else(|| "invalid-Unicode dispatch lacks expectation".to_string())?;
                if expect
                    .get("rejection")
                    .and_then(|value| value.get("code"))
                    .and_then(serde_json::Value::as_str)
                    != Some("invalid_payload")
                {
                    return Err("invalid-Unicode dispatch expectation is inconsistent".to_string());
                }
                continue;
            }
            let target = if let Some(variable) = send
                .get("bound_instance")
                .and_then(serde_json::Value::as_str)
            {
                let value = state
                    .root
                    .visible_variables()
                    .get(variable)
                    .cloned()
                    .ok_or_else(|| format!("missing bound variable {variable}"))?;
                let Value::InstanceReference(reference) = value else {
                    return Err(format!("{variable} is not an instance reference"));
                };
                Target::SpawnedInstance(reference)
            } else {
                Target::Root {
                    root_instance_id: state.root_instance_id.clone(),
                    root_runtime_id: state.root.runtime_id.clone(),
                }
            };
            let event = send
                .get("event")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| "send.event is missing".to_string())?
                .to_string();
            let event_id = send
                .get("event_id")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| format!("conformance:{case_name}:step:{step_index}:input"));
            let payload = send
                .get("payload")
                .map(value_map)
                .transpose()?
                .unwrap_or_default();
            let envelope = Envelope {
                event,
                event_id,
                target,
                payload,
                correlation_id: send
                    .get("correlation_id")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string),
            };
            let dispatch_bundle =
                if let Some(relative) = send.get("bundle").and_then(serde_json::Value::as_str) {
                    let source = fs::read_to_string(case.join(relative)).map_err(display)?;
                    load_bundle(&source).map_err(|error| format!("alternate bundle: {error}"))?
                } else {
                    bundle.clone()
                };
            (
                dispatch(
                    &dispatch_bundle,
                    &state,
                    Some(Delivery::Input(envelope.clone())),
                ),
                Some(envelope),
            )
        } else if let Some(deliver) = step.get("deliver") {
            let deliver = deliver
                .as_object()
                .ok_or_else(|| "deliver is not a map".to_string())?;
            let name = deliver
                .get("captured")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| "deliver.captured is missing".to_string())?;
            let index = deliver
                .get("index")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| "deliver.index is missing".to_string())?
                as usize;
            let emission = captures
                .get(name)
                .and_then(|emissions| emissions.get(index))
                .ok_or_else(|| format!("capture {name}[{index}] is missing"))?;
            let envelope = emission
                .envelope()
                .ok_or_else(|| "cannot deliver an external intent".to_string())?;
            (
                dispatch(&bundle, &state, Some(Delivery::Internal(envelope.clone()))),
                Some(envelope),
            )
        } else {
            return Err(format!("step {step_index} has no send or deliver"));
        };
        if let Some(expect) = step.get("expect") {
            check_result(&step_result, expect, supplied_envelope.as_ref())
                .map_err(|error| format!("step {step_index}: {error}"))?;
        }
        if let Some(name) = step
            .get("capture_emissions_as")
            .and_then(serde_json::Value::as_str)
        {
            captures.insert(name.to_string(), step_result.emissions.clone());
        }
        state = step_result
            .state
            .ok_or_else(|| format!("step {step_index} returned no state"))?;
    }
    Ok(())
}

fn run_static_documents(case: &Path, assertion: &serde_json::Value) -> Result<(), String> {
    let documents = assertion
        .get("documents")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_else(|| vec![assertion.clone()]);
    for entry in documents {
        let file = entry
            .get("file")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("machine.yaml");
        let expected_valid = entry
            .get("valid")
            .and_then(serde_json::Value::as_bool)
            .ok_or_else(|| format!("{file}: missing static.valid"))?;
        let expected_error = entry.get("error").and_then(serde_json::Value::as_str);
        let source = fs::read_to_string(case.join(file)).map_err(display)?;
        match load_bundle(&source) {
            Ok(_) if expected_valid => {}
            Ok(_) => return Err(format!("{file}: expected {expected_error:?}, loaded")),
            Err(error) if !expected_valid && Some(error.code.as_str()) == expected_error => {}
            Err(error) if expected_valid => {
                return Err(format!("{file}: expected valid, got {error}"))
            }
            Err(error) => {
                return Err(format!(
                    "{file}: expected {expected_error:?}, got {} ({error})",
                    error.code.as_str()
                ))
            }
        }
    }
    Ok(())
}

fn check_result(
    result: &CoreResult,
    expected: &serde_json::Value,
    _supplied_envelope: Option<&Envelope>,
) -> Result<(), String> {
    let expected = expected
        .as_object()
        .ok_or_else(|| "expect is not a map".to_string())?;
    if let Some(status) = expected.get("status").and_then(serde_json::Value::as_str) {
        let actual = match result.status {
            ResultStatus::Running => "running",
            ResultStatus::Completed => "completed",
            ResultStatus::Faulted => "faulted",
            ResultStatus::Rejected => "rejected",
        };
        if actual != status {
            return Err(format!(
                "status {actual:?} != {status:?}; fault={:?} rejection={:?}",
                result.fault, result.rejection
            ));
        }
    }
    if let Some(disposition) = expected
        .get("disposition")
        .and_then(serde_json::Value::as_str)
    {
        let actual = result.disposition.map(|value| match value {
            Disposition::Handled => "handled",
            Disposition::Unhandled => "unhandled",
            Disposition::Rejected => "rejected",
            Disposition::Faulted => "faulted",
        });
        if actual != Some(disposition) {
            return Err(format!(
                "disposition {actual:?} != {disposition:?}; fault={:?} rejection={:?}",
                result.fault, result.rejection
            ));
        }
    }
    if expected
        .get("state")
        .is_some_and(serde_json::Value::is_null)
        && result.state.is_some()
    {
        return Err("expected null state".to_string());
    }
    if let Some(rejection) = expected.get("rejection") {
        if rejection.is_null() {
            if result.rejection.is_some() {
                return Err(format!("unexpected rejection {:?}", result.rejection));
            }
        } else {
            let code = rejection
                .get("code")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| "expected rejection lacks code".to_string())?;
            if result.rejection.as_ref().map(|value| value.code.as_str()) != Some(code) {
                return Err(format!("rejection {:?} != {code:?}", result.rejection));
            }
        }
    }
    if let Some(fault) = expected.get("fault") {
        if fault.is_null() {
            if result.fault.is_some() {
                return Err(format!("unexpected fault {:?}", result.fault));
            }
        } else {
            let actual = result
                .fault
                .as_ref()
                .ok_or_else(|| "expected fault is absent".to_string())?;
            compare_fault(actual, fault)?;
        }
    }
    let Some(state) = result.state.as_ref() else {
        return check_emissions(result, expected, None);
    };
    if let Some(config) = expected.get("config") {
        let expected = string_list(config)?;
        if state.root.config() != expected {
            return Err(format!(
                "config {:?} != {:?}",
                state.root.config(),
                expected
            ));
        }
    }
    if let Some(variables) = expected.get("variables") {
        compare_variable_map(&state.root.visible_variables(), variables, &state.root)?;
    }
    if let Some(history) = expected.get("history") {
        let actual = state
            .root
            .history
            .iter()
            .map(|(key, value)| {
                (
                    if key == "root" {
                        "$root".to_string()
                    } else {
                        key.clone()
                    },
                    value.clone(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let expected = history
            .as_object()
            .ok_or_else(|| "history expectation is not a map".to_string())?;
        if actual.len() != expected.len() {
            return Err(format!(
                "history keys {:?} != {:?}",
                actual.keys(),
                expected.keys()
            ));
        }
        for (key, expected) in expected {
            let actual = actual
                .get(key)
                .ok_or_else(|| format!("missing history slot {key}"))?;
            if expected.is_null() {
                if actual.is_some() {
                    return Err(format!("history {key} is populated"));
                }
            } else if actual.as_ref() != Some(&string_list(expected)?) {
                return Err(format!("history {key} {actual:?} != {expected:?}"));
            }
        }
    }
    if let Some(components) = expected.get("components") {
        compare_components(state, components)?;
    }
    if let Some(owned) = expected.get("owned_instances") {
        compare_owned(state, owned)?;
    }
    check_emissions(result, expected, Some(state))
}

fn check_emissions(
    result: &CoreResult,
    expected: &serde_json::Map<String, serde_json::Value>,
    state: Option<&AggregateState>,
) -> Result<(), String> {
    let Some(expected) = expected.get("emissions") else {
        return Ok(());
    };
    let expected = expected
        .as_array()
        .ok_or_else(|| "emissions expectation is not a list".to_string())?;
    if result.emissions.len() != expected.len() {
        return Err(format!(
            "emission count {} != {}: {:?}",
            result.emissions.len(),
            expected.len(),
            result.emissions
        ));
    }
    for (index, (actual, expected)) in result.emissions.iter().zip(expected).enumerate() {
        let expected = expected
            .as_object()
            .ok_or_else(|| format!("emission {index} expectation is not a map"))?;
        if let Some(event) = expected.get("event").and_then(serde_json::Value::as_str) {
            if actual.event != event {
                return Err(format!(
                    "emission {index} event {:?} != {event:?}",
                    actual.event
                ));
            }
        }
        if let Some(correlation) = expected
            .get("correlation_id")
            .and_then(serde_json::Value::as_str)
        {
            if actual.correlation_id.as_deref() != Some(correlation) {
                return Err(format!(
                    "emission {index} correlation {:?} != {correlation:?}",
                    actual.correlation_id
                ));
            }
        }
        if let Some(payload) = expected.get("payload") {
            compare_partial_map(&actual.payload, payload, None)?;
        }
        if let Some(target) = expected.get("target") {
            compare_target(&actual.target, target, state)?;
        }
        if let Some(effect_id) = expected
            .get("effect_id")
            .and_then(serde_json::Value::as_str)
        {
            if actual.effect_id.as_deref() != Some(effect_id) {
                return Err(format!("emission {index} effect_id mismatch"));
            }
        }
        if let Some(sequence) = expected.get("sequence").and_then(serde_json::Value::as_u64) {
            if actual.sequence != Some(sequence) {
                return Err(format!("emission {index} sequence mismatch"));
            }
        }
    }
    Ok(())
}

fn compare_components(state: &AggregateState, expected: &serde_json::Value) -> Result<(), String> {
    let expected = expected
        .as_object()
        .ok_or_else(|| "components expectation is not a map".to_string())?;
    if state.root.components.len() != expected.len() {
        return Err(format!(
            "component ids {:?} != {:?}",
            state
                .root
                .components
                .iter()
                .map(|component| &component.component_id)
                .collect::<Vec<_>>(),
            expected.keys().collect::<Vec<_>>()
        ));
    }
    for (component_id, expected) in expected {
        let component = state
            .root
            .components
            .iter()
            .find(|component| &component.component_id == component_id)
            .ok_or_else(|| format!("missing component {component_id}"))?;
        compare_runtime(&component.runtime, expected)?;
    }
    Ok(())
}

fn compare_owned(state: &AggregateState, expected: &serde_json::Value) -> Result<(), String> {
    let expected = expected
        .as_array()
        .ok_or_else(|| "owned_instances expectation is not a list".to_string())?;
    if state.root.owned_instances.len() != expected.len() {
        return Err(format!(
            "owned count {} != {}; root status={:?} fault={:?}",
            state.root.owned_instances.len(),
            expected.len(),
            state.root.status,
            state.root.fault
        ));
    }
    for expected in expected {
        let expected = expected
            .as_object()
            .ok_or_else(|| "owned member is not a map".to_string())?;
        let sequence = expected
            .get("key")
            .and_then(|key| key.get("spawn_sequence"))
            .and_then(serde_json::Value::as_u64)
            .or_else(|| {
                expected
                    .get("key")
                    .and_then(|key| key.get("bound_instance"))
                    .and_then(serde_json::Value::as_str)
                    .and_then(|name| match state.root.visible_variables().get(name) {
                        Some(Value::InstanceReference(reference)) => state
                            .root
                            .owned_instances
                            .iter()
                            .find(|owned| owned.reference == *reference)
                            .map(|owned| owned.spawn_sequence),
                        _ => None,
                    })
            })
            .ok_or_else(|| "owned key does not resolve".to_string())?;
        let owned = state
            .root
            .owned_instances
            .iter()
            .find(|owned| owned.spawn_sequence == sequence)
            .ok_or_else(|| format!("missing owned sequence {sequence}"))?;
        if let Some(machine_id) = expected
            .get("machine_id")
            .and_then(serde_json::Value::as_str)
        {
            if owned.runtime.machine_id != machine_id {
                return Err(format!(
                    "owned machine {:?} != {machine_id:?}",
                    owned.runtime.machine_id
                ));
            }
        }
        compare_runtime(&owned.runtime, &serde_json::Value::Object(expected.clone()))?;
    }
    Ok(())
}

fn compare_runtime(
    runtime: &determa_state::format1::RuntimeState,
    expected: &serde_json::Value,
) -> Result<(), String> {
    let expected = expected
        .as_object()
        .ok_or_else(|| "runtime expectation is not a map".to_string())?;
    if let Some(status) = expected.get("status").and_then(serde_json::Value::as_str) {
        let actual = match runtime.status {
            RuntimeStatus::Running => "running",
            RuntimeStatus::Completed => "completed",
            RuntimeStatus::Faulted => "faulted",
        };
        if actual != status {
            return Err(format!("runtime status {actual:?} != {status:?}"));
        }
    }
    if let Some(config) = expected.get("config") {
        let expected = string_list(config)?;
        if runtime.config() != expected {
            return Err(format!(
                "runtime config {:?} != {expected:?}",
                runtime.config()
            ));
        }
    }
    if let Some(variables) = expected.get("variables") {
        compare_variable_map(&runtime.visible_variables(), variables, runtime)?;
    }
    if let Some(components) = expected.get("components") {
        let expected = components
            .as_object()
            .ok_or_else(|| "nested components is not a map".to_string())?;
        if runtime.components.len() != expected.len() {
            return Err("nested component membership mismatch".to_string());
        }
    }
    if let Some(owned) = expected.get("owned_instances") {
        let expected = owned
            .as_array()
            .ok_or_else(|| "nested owned is not a list".to_string())?;
        if runtime.owned_instances.len() != expected.len() {
            return Err("nested owned membership mismatch".to_string());
        }
    }
    Ok(())
}

fn compare_variable_map(
    actual: &BTreeMap<String, Value>,
    expected: &serde_json::Value,
    runtime: &determa_state::format1::RuntimeState,
) -> Result<(), String> {
    let expected = expected
        .as_object()
        .ok_or_else(|| "variables expectation is not a map".to_string())?;
    for (name, expected) in expected {
        let actual = actual
            .get(name)
            .ok_or_else(|| format!("missing variable {name}; actual {actual:?}"))?;
        compare_value(actual, expected, Some(runtime))
            .map_err(|error| format!("variable {name}: {error}"))?;
    }
    Ok(())
}

fn compare_partial_map(
    actual: &BTreeMap<String, Value>,
    expected: &serde_json::Value,
    runtime: Option<&determa_state::format1::RuntimeState>,
) -> Result<(), String> {
    let expected = expected
        .as_object()
        .ok_or_else(|| "expected value is not a map".to_string())?;
    for (name, expected) in expected {
        let actual = actual
            .get(name)
            .ok_or_else(|| format!("missing map field {name}"))?;
        compare_value(actual, expected, runtime)
            .map_err(|error| format!("map field {name}: {error}"))?;
    }
    Ok(())
}

fn compare_value(
    actual: &Value,
    expected: &serde_json::Value,
    runtime: Option<&determa_state::format1::RuntimeState>,
) -> Result<(), String> {
    if let Some(reference_expectation) = expected.get("instance_reference") {
        let Value::InstanceReference(reference) = actual else {
            return Err(format!("actual {actual:?} is not an instance reference"));
        };
        if let Some(machine_id) = reference_expectation
            .get("machine_id")
            .and_then(serde_json::Value::as_str)
        {
            if reference.machine_id != machine_id {
                return Err("instance machine_id mismatch".to_string());
            }
        }
        if let Some(targetable) = reference_expectation
            .get("targetable")
            .and_then(serde_json::Value::as_bool)
        {
            let actual_targetable = runtime
                .filter(|runtime| runtime.status == RuntimeStatus::Running)
                .and_then(|runtime| find_reference(runtime, &reference.instance_id))
                .is_some_and(|runtime| runtime.status == RuntimeStatus::Running);
            if actual_targetable != targetable {
                return Err(format!(
                    "instance targetable {actual_targetable} != {targetable}"
                ));
            }
        }
        return Ok(());
    }
    match (actual, expected) {
        (Value::Null, serde_json::Value::Null) => Ok(()),
        (Value::Bool(actual), serde_json::Value::Bool(expected)) if actual == expected => Ok(()),
        (Value::Int(actual), serde_json::Value::Number(expected))
            if expected.as_i64() == Some(*actual) =>
        {
            Ok(())
        }
        (Value::Float(actual), serde_json::Value::Number(expected))
            if expected.as_f64() == Some(*actual) && expected.as_i64().is_none() =>
        {
            Ok(())
        }
        (Value::String(actual), serde_json::Value::String(expected)) if actual == expected => {
            Ok(())
        }
        (Value::List(actual), serde_json::Value::Array(expected)) => {
            if actual.len() != expected.len() {
                return Err(format!(
                    "list length {} != {}",
                    actual.len(),
                    expected.len()
                ));
            }
            for (actual, expected) in actual.iter().zip(expected) {
                compare_value(actual, expected, runtime)?;
            }
            Ok(())
        }
        (Value::Map(actual), serde_json::Value::Object(_)) => {
            compare_partial_map(actual, expected, runtime)
        }
        _ => Err(format!("actual {actual:?} != expected {expected:?}")),
    }
}

fn compare_target(
    actual: &Target,
    expected: &serde_json::Value,
    state: Option<&AggregateState>,
) -> Result<(), String> {
    if expected.as_str() == Some("external") {
        return matches!(actual, Target::External)
            .then_some(())
            .ok_or_else(|| format!("target {actual:?} is not external"));
    }
    if expected.as_str() == Some("owner") || expected.as_str() == Some("root") {
        return matches!(actual, Target::Root { .. })
            .then_some(())
            .ok_or_else(|| format!("target {actual:?} is not root/owner"));
    }
    if let Some(component_id) = expected
        .get("component")
        .and_then(serde_json::Value::as_str)
    {
        return matches!(
            actual,
            Target::Component { component_id: actual, .. } if actual == component_id
        )
        .then_some(())
        .ok_or_else(|| format!("target {actual:?} is not component {component_id}"));
    }
    if let Some(variable) = expected
        .get("bound_instance")
        .and_then(serde_json::Value::as_str)
    {
        let reference = state
            .and_then(|state| state.root.visible_variables().get(variable).cloned())
            .ok_or_else(|| format!("missing reference variable {variable}"))?;
        let Value::InstanceReference(reference) = reference else {
            return Err(format!("{variable} is not a reference"));
        };
        return matches!(actual, Target::SpawnedInstance(actual) if actual == &reference)
            .then_some(())
            .ok_or_else(|| format!("target {actual:?} != bound {reference:?}"));
    }
    Err(format!("unsupported target expectation {expected:?}"))
}

fn compare_fault(
    actual: &determa_state::FaultRecord,
    expected: &serde_json::Value,
) -> Result<(), String> {
    if let Some(code) = expected.get("code").and_then(serde_json::Value::as_str) {
        if actual.code != code {
            return Err(format!("fault code {:?} != {code:?}", actual.code));
        }
    }
    if let Some(locator) = expected
        .get("source_locator")
        .and_then(serde_json::Value::as_str)
    {
        if actual.source_locator != locator {
            return Err(format!(
                "fault locator {:?} != {locator:?}",
                actual.source_locator
            ));
        }
    }
    if let Some(cause_id) = expected.get("cause_id").and_then(serde_json::Value::as_str) {
        if actual.cause_id != cause_id {
            return Err(format!("fault cause {:?} != {cause_id:?}", actual.cause_id));
        }
    }
    if let Some(sequence) = expected
        .get("step_sequence")
        .and_then(serde_json::Value::as_u64)
    {
        if actual.step_sequence != sequence {
            return Err(format!("fault step {} != {sequence}", actual.step_sequence));
        }
    }
    Ok(())
}

fn find_reference<'a>(
    runtime: &'a determa_state::format1::RuntimeState,
    instance_id: &str,
) -> Option<&'a determa_state::format1::RuntimeState> {
    for owned in &runtime.owned_instances {
        if owned.reference.instance_id == instance_id {
            return Some(&owned.runtime);
        }
        if let Some(found) = find_reference(&owned.runtime, instance_id) {
            return Some(found);
        }
    }
    for component in &runtime.components {
        if let Some(found) = find_reference(&component.runtime, instance_id) {
            return Some(found);
        }
    }
    None
}

fn parse_yaml(source: &str) -> Result<serde_json::Value, String> {
    let value: serde_yaml::Value = serde_yaml::from_str(source).map_err(display)?;
    serde_json::to_value(value).map_err(display)
}

fn bindings_from_json(value: &serde_json::Value) -> Result<Bindings, String> {
    Ok(Bindings {
        input: value
            .get("input")
            .map(value_map)
            .transpose()?
            .unwrap_or_default(),
        external: value
            .get("external")
            .map(value_map)
            .transpose()?
            .unwrap_or_default(),
    })
}

fn value_map(value: &serde_json::Value) -> Result<BTreeMap<String, Value>, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "value is not a map".to_string())?;
    object
        .iter()
        .map(|(name, value)| Ok((name.clone(), Value::from_json(value)?)))
        .collect()
}

fn string_list(value: &serde_json::Value) -> Result<Vec<String>, String> {
    value
        .as_array()
        .ok_or_else(|| "expected string list".to_string())?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| "expected string".to_string())
        })
        .collect()
}

fn contains_invalid_unicode(value: Option<&serde_json::Value>) -> bool {
    let Some(value) = value else {
        return false;
    };
    match value {
        serde_json::Value::Object(values) => {
            values.get("invalid_unicode_scalar").is_some()
                || values
                    .values()
                    .any(|value| contains_invalid_unicode(Some(value)))
        }
        serde_json::Value::Array(values) => values
            .iter()
            .any(|value| contains_invalid_unicode(Some(value))),
        _ => false,
    }
}

fn display(error: impl std::fmt::Display) -> String {
    error.to_string()
}
