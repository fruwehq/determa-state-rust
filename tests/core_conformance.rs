use determa_state::{
    create, dispatch, load_bundle, string_from_utf16, AggregateState, Bindings, CoreResult,
    Counter, Delivery, Disposition, Emission, Envelope, ResultStatus, RuntimeStatus, Target, Value,
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
    assert_eq!(cases.len(), 110, "expected the complete merged core suite");
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
        assert_invalid_unicode_boundary(
            create_spec.and_then(|create| create.get("root_instance_id")),
        )?;
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
        check_result(&result, expect, None, None)?;
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
        let caller_state = state.clone();
        let step = step
            .as_object()
            .ok_or_else(|| format!("step {step_index} is not a map"))?;
        let (step_result, supplied_envelope, supplied_state) = if let Some(send) = step.get("send")
        {
            let send = send
                .as_object()
                .ok_or_else(|| format!("step {step_index} send is not a map"))?;
            if contains_invalid_unicode(send.get("payload")) {
                assert_invalid_unicode_boundary(send.get("payload"))?;
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
                if expect
                    .get("caller_still_owns_input")
                    .and_then(serde_json::Value::as_bool)
                    != Some(true)
                {
                    return Err("invalid-Unicode dispatch must assert caller ownership".to_string());
                }
                if !aggregate_exact_equal(&state, &caller_state) {
                    return Err("invalid-Unicode boundary mutated prior state".to_string());
                }
                continue;
            }
            let target =
                resolve_driver_target(&state, &serde_json::Value::Object(send.clone()), true)?;
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
                state.clone(),
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
            let mut envelope = emission
                .envelope()
                .ok_or_else(|| "cannot deliver an external intent".to_string())?;
            if let Some(replace) = deliver.get("replace") {
                apply_envelope_replacement(&mut envelope, replace, &state)?;
            }
            (
                dispatch(&bundle, &state, Some(Delivery::Internal(envelope.clone()))),
                Some(envelope),
                state.clone(),
            )
        } else if let Some(inspect) = step.get("inspect") {
            let mut corrupted = state.clone();
            apply_prior_state_corruption(&mut corrupted, inspect)?;
            (dispatch(&bundle, &corrupted, None), None, corrupted)
        } else {
            return Err(format!(
                "step {step_index} has no send, deliver, or inspect"
            ));
        };
        if !aggregate_exact_equal(&state, &caller_state) {
            return Err(format!(
                "step {step_index}: dispatch mutated the caller's prior state"
            ));
        }
        if let Some(expect) = step.get("expect") {
            check_result(
                &step_result,
                expect,
                supplied_envelope.as_ref(),
                Some(&supplied_state),
            )
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

fn resolve_driver_target(
    state: &AggregateState,
    selector: &serde_json::Value,
    default_root: bool,
) -> Result<Target, String> {
    if selector.as_str() == Some("root") {
        return Ok(runtime_target(state, &state.root));
    }
    if let Some(variable) = selector
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
        return Ok(Target::SpawnedInstance(reference));
    }
    if let Some(component_id) = selector
        .get("component")
        .and_then(serde_json::Value::as_str)
    {
        let mut matches = Vec::new();
        collect_components(&state.root, component_id, &mut matches);
        return match matches.as_slice() {
            [component] => Ok(runtime_target(state, &component.runtime)),
            [] => Err(format!("component {component_id} is not retained")),
            _ => Err(format!("component {component_id} is ambiguous")),
        };
    }
    if default_root {
        Ok(runtime_target(state, &state.root))
    } else {
        Err(format!("unsupported target selector {selector:?}"))
    }
}

fn collect_components<'a>(
    runtime: &'a determa_state::format1::RuntimeState,
    component_id: &str,
    matches: &mut Vec<&'a determa_state::format1::ComponentRuntime>,
) {
    for component in &runtime.components {
        if component.component_id == component_id {
            matches.push(component);
        }
        collect_components(&component.runtime, component_id, matches);
    }
    for owned in &runtime.owned_instances {
        collect_components(&owned.runtime, component_id, matches);
    }
}

fn apply_envelope_replacement(
    envelope: &mut Envelope,
    replacement: &serde_json::Value,
    state: &AggregateState,
) -> Result<(), String> {
    let replacement = replacement
        .as_object()
        .ok_or_else(|| "deliver.replace is not a map".to_string())?;
    if replacement.is_empty() {
        return Err("deliver.replace must not be empty".to_string());
    }
    if let Some(field) = replacement.keys().find(|field| {
        !matches!(
            field.as_str(),
            "payload" | "target" | "spawned_instance_reference"
        )
    }) {
        return Err(format!("unsupported deliver.replace field {field}"));
    }
    if let Some(payload) = replacement.get("payload") {
        envelope.payload = value_map(payload)?;
    }
    if let Some(target) = replacement.get("target") {
        envelope.target = resolve_driver_target(state, target, false)?;
    }
    if let Some(fields) = replacement.get("spawned_instance_reference") {
        let Target::SpawnedInstance(reference) = &mut envelope.target else {
            return Err(
                "spawned_instance_reference replacement requires a spawned target".to_string(),
            );
        };
        let fields = fields
            .as_object()
            .ok_or_else(|| "spawned_instance_reference is not a map".to_string())?;
        if fields.is_empty() {
            return Err("spawned_instance_reference replacement is empty".to_string());
        }
        for (name, value) in fields {
            match name.as_str() {
                "root_instance_id" => {
                    reference.root_instance_id = required_string(value, name)?.to_string()
                }
                "instance_id" => reference.instance_id = required_string(value, name)?.to_string(),
                "machine_id" => reference.machine_id = required_string(value, name)?.to_string(),
                "machine_version" => {
                    reference.machine_version = value
                        .as_i64()
                        .ok_or_else(|| "machine_version replacement is not an int".to_string())?
                }
                _ => return Err(format!("unsupported spawned reference field {name}")),
            }
        }
    }
    Ok(())
}

fn required_string<'a>(value: &'a serde_json::Value, name: &str) -> Result<&'a str, String> {
    value
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{name} replacement is not a non-empty string"))
}

fn apply_prior_state_corruption(
    state: &mut AggregateState,
    inspect: &serde_json::Value,
) -> Result<(), String> {
    let corruption = inspect
        .get("corrupt_prior_state")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| "unsupported inspect operation".to_string())?;
    if corruption
        .get("runtime")
        .and_then(serde_json::Value::as_str)
        != Some("root")
    {
        return Err("only root prior-state corruption is supported".to_string());
    }
    let variable = corruption
        .get("variable")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "corrupt_prior_state.variable is missing".to_string())?;
    let slot = state
        .root
        .variables
        .values_mut()
        .filter(|slot| slot.name == variable)
        .max_by_key(|slot| slot.declaration_path.split('.').count())
        .ok_or_else(|| format!("visible variable {variable} is missing"))?;
    let path = corruption
        .get("path")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "corrupt_prior_state.path is not a list".to_string())?;
    if path.is_empty() {
        return Err("corrupt_prior_state.path is empty".to_string());
    }
    let replacement = value_from_fixture(
        corruption
            .get("value")
            .ok_or_else(|| "corrupt_prior_state.value is missing".to_string())?,
    )?;
    replace_nested_value(&mut slot.value, path, replacement)
}

fn replace_nested_value(
    current: &mut Value,
    path: &[serde_json::Value],
    replacement: Value,
) -> Result<(), String> {
    let Some((head, tail)) = path.split_first() else {
        *current = replacement;
        return Ok(());
    };
    match (current, head) {
        (Value::Map(values), serde_json::Value::String(key)) => {
            let child = values
                .get_mut(key)
                .ok_or_else(|| format!("corrupt path map key {key} is missing"))?;
            replace_nested_value(child, tail, replacement)
        }
        (Value::List(values), serde_json::Value::Number(index)) => {
            let index = index
                .as_u64()
                .and_then(|index| usize::try_from(index).ok())
                .ok_or_else(|| "corrupt path index is invalid".to_string())?;
            let child = values
                .get_mut(index)
                .ok_or_else(|| format!("corrupt path list index {index} is missing"))?;
            replace_nested_value(child, tail, replacement)
        }
        _ => Err("corrupt path cannot traverse the selected value".to_string()),
    }
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
    supplied_envelope: Option<&Envelope>,
    prior_state: Option<&AggregateState>,
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
    if expected
        .get("caller_still_owns_input")
        .and_then(serde_json::Value::as_bool)
        == Some(true)
    {
        supplied_envelope
            .ok_or_else(|| "caller ownership asserted without a supplied envelope".to_string())?;
        prior_state.ok_or_else(|| "caller ownership asserted without prior state".to_string())?;
        if !matches!(
            result.disposition,
            Some(Disposition::Rejected | Disposition::Faulted)
        ) {
            return Err(
                "caller input ownership asserted for a non-rejected, non-faulted dispatch"
                    .to_string(),
            );
        }
    }
    if expected
        .get("caller_still_owns_state")
        .and_then(serde_json::Value::as_bool)
        == Some(true)
    {
        let prior = prior_state
            .ok_or_else(|| "caller state ownership asserted without prior state".to_string())?;
        if !result
            .state
            .as_ref()
            .is_some_and(|state| aggregate_exact_equal(state, prior))
        {
            return Err("dispatch did not return the exact caller-owned prior state".to_string());
        }
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
            if let (Some(actual), Some(prior)) = (result.state.as_ref(), prior_state) {
                if !aggregate_exact_equal(actual, prior) {
                    return Err("rejection changed the prior aggregate state".to_string());
                }
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
        if let Some(event_id) = expected.get("event_id").and_then(serde_json::Value::as_str) {
            if actual.event_id.as_deref() != Some(event_id) {
                return Err(format!(
                    "emission {index} event_id {:?} != {event_id:?}",
                    actual.event_id
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
            compare_target(
                &actual.target,
                target,
                state,
                Some(&actual.emitting_runtime_id),
                actual.emitting_owner_runtime_id.as_deref(),
            )?;
        }
        if let Some(effect_id) = expected
            .get("effect_id")
            .and_then(serde_json::Value::as_str)
        {
            if actual.effect_id.as_deref() != Some(effect_id) {
                return Err(format!("emission {index} effect_id mismatch"));
            }
        }
        if let Some(sequence) = expected.get("sequence") {
            let sequence = counter_from_json(sequence)?;
            if actual.sequence.as_ref() != Some(&sequence) {
                return Err(format!("emission {index} sequence mismatch"));
            }
        }
    }
    Ok(())
}

fn compare_components(state: &AggregateState, expected: &serde_json::Value) -> Result<(), String> {
    compare_runtime_components(&state.root, expected, state)
}

fn compare_owned(state: &AggregateState, expected: &serde_json::Value) -> Result<(), String> {
    let expected = expected
        .as_array()
        .ok_or_else(|| "owned_instances expectation is not a list".to_string())?;
    let mut actual = Vec::new();
    collect_owned(&state.root, &mut actual);
    actual.sort_by(|left, right| {
        relation_owner_runtime_id(&left.runtime.relation)
            .cmp(&relation_owner_runtime_id(&right.runtime.relation))
            .then_with(|| left.spawn_sequence.cmp(&right.spawn_sequence))
    });
    if actual.len() != expected.len() {
        return Err(format!(
            "owned count {} != {}; root status={:?} fault={:?}",
            actual.len(),
            expected.len(),
            state.root.status,
            state.root.fault
        ));
    }
    for (index, expected) in expected.iter().enumerate() {
        let expected = expected
            .as_object()
            .ok_or_else(|| "owned member is not a map".to_string())?;
        let key = expected
            .get("key")
            .ok_or_else(|| "owned member lacks key".to_string())?;
        let owned = resolve_owned_key(state, &actual, key)?;
        if !std::ptr::eq(owned, actual[index]) {
            return Err(format!(
                "owned member {index} is out of canonical owner/sequence order"
            ));
        }
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
        compare_runtime(
            &owned.runtime,
            &serde_json::Value::Object(expected.clone()),
            state,
        )?;
    }
    Ok(())
}

fn compare_runtime(
    runtime: &determa_state::format1::RuntimeState,
    expected: &serde_json::Value,
    aggregate: &AggregateState,
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
    if let Some(history) = expected.get("history") {
        compare_history(runtime, history)?;
    }
    if let Some(components) = expected.get("components") {
        compare_runtime_components(runtime, components, aggregate)?;
    }
    if let Some(owned) = expected.get("owned_instances") {
        compare_runtime_owned(runtime, owned, aggregate)?;
    }
    Ok(())
}

fn compare_runtime_components(
    runtime: &determa_state::format1::RuntimeState,
    expected: &serde_json::Value,
    aggregate: &AggregateState,
) -> Result<(), String> {
    let expected = expected
        .as_object()
        .ok_or_else(|| "components expectation is not a map".to_string())?;
    if runtime.components.len() != expected.len() {
        return Err(format!(
            "component ids {:?} != {:?}",
            runtime
                .components
                .iter()
                .map(|component| &component.component_id)
                .collect::<Vec<_>>(),
            expected.keys().collect::<Vec<_>>()
        ));
    }
    for (component_id, expected) in expected {
        let component = runtime
            .components
            .iter()
            .find(|component| &component.component_id == component_id)
            .ok_or_else(|| format!("missing component {component_id}"))?;
        compare_runtime(&component.runtime, expected, aggregate)?;
    }
    Ok(())
}

fn compare_runtime_owned(
    runtime: &determa_state::format1::RuntimeState,
    expected: &serde_json::Value,
    aggregate: &AggregateState,
) -> Result<(), String> {
    let expected = expected
        .as_array()
        .ok_or_else(|| "nested owned_instances expectation is not a list".to_string())?;
    if runtime.owned_instances.len() != expected.len() {
        return Err(format!(
            "owned sequences {:?} != {} expected member(s)",
            runtime
                .owned_instances
                .iter()
                .map(|owned| owned.spawn_sequence.to_string())
                .collect::<Vec<_>>(),
            expected.len()
        ));
    }
    for expected in expected {
        let expected_map = expected
            .as_object()
            .ok_or_else(|| "nested owned member is not a map".to_string())?;
        let key = expected_map
            .get("key")
            .ok_or_else(|| "nested owned member lacks key".to_string())?;
        let owned = resolve_direct_owned_key(aggregate, runtime, key)?;
        if let Some(machine_id) = expected_map
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
        compare_runtime(&owned.runtime, expected, aggregate)?;
    }
    Ok(())
}

fn compare_history(
    runtime: &determa_state::format1::RuntimeState,
    expected: &serde_json::Value,
) -> Result<(), String> {
    let actual = runtime
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
    let expected = expected
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
    Ok(())
}

fn collect_owned<'a>(
    runtime: &'a determa_state::format1::RuntimeState,
    collected: &mut Vec<&'a determa_state::format1::OwnedRuntime>,
) {
    for component in &runtime.components {
        collect_owned(&component.runtime, collected);
    }
    for owned in &runtime.owned_instances {
        collected.push(owned);
        collect_owned(&owned.runtime, collected);
    }
}

fn resolve_owned_key<'a>(
    state: &AggregateState,
    actual: &[&'a determa_state::format1::OwnedRuntime],
    key: &serde_json::Value,
) -> Result<&'a determa_state::format1::OwnedRuntime, String> {
    if let Some(variable) = key
        .get("bound_instance")
        .and_then(serde_json::Value::as_str)
    {
        let Value::InstanceReference(reference) = state
            .root
            .visible_variables()
            .get(variable)
            .cloned()
            .ok_or_else(|| format!("missing bound variable {variable}"))?
        else {
            return Err(format!("{variable} is not an instance reference"));
        };
        let matches = actual
            .iter()
            .copied()
            .filter(|owned| owned.reference == reference)
            .collect::<Vec<_>>();
        return match matches.as_slice() {
            [owned] => Ok(*owned),
            [] => Err(format!(
                "bound variable {variable} resolves to no retained child"
            )),
            _ => Err(format!("bound variable {variable} resolves ambiguously")),
        };
    }
    let owner = key
        .get("owner")
        .ok_or_else(|| "owned key lacks owner".to_string())?;
    let owner_runtime_id = resolve_runtime_notation(state, owner)?;
    let sequence = counter_from_json(
        key.get("spawn_sequence")
            .ok_or_else(|| "owned key lacks spawn_sequence".to_string())?,
    )?;
    actual
        .iter()
        .copied()
        .find(|owned| {
            relation_owner_runtime_id(&owned.runtime.relation) == Some(owner_runtime_id.as_str())
                && owned.spawn_sequence == sequence
        })
        .ok_or_else(|| {
            format!(
                "missing owned key ({owner_runtime_id}, {})",
                sequence.canonical_decimal()
            )
        })
}

fn resolve_direct_owned_key<'a>(
    state: &AggregateState,
    owner: &'a determa_state::format1::RuntimeState,
    key: &serde_json::Value,
) -> Result<&'a determa_state::format1::OwnedRuntime, String> {
    let actual = owner.owned_instances.iter().collect::<Vec<_>>();
    resolve_owned_key(state, &actual, key).and_then(|owned| {
        (relation_owner_runtime_id(&owned.runtime.relation) == Some(owner.runtime_id.as_str()))
            .then_some(owned)
            .ok_or_else(|| "nested owned key names a different owner".to_string())
    })
}

fn resolve_runtime_notation(
    state: &AggregateState,
    notation: &serde_json::Value,
) -> Result<String, String> {
    if notation.as_str() == Some("root") {
        return Ok(state.root.runtime_id.clone());
    }
    if let Some(variable) = notation
        .get("bound_instance")
        .and_then(serde_json::Value::as_str)
    {
        let Value::InstanceReference(reference) = state
            .root
            .visible_variables()
            .get(variable)
            .cloned()
            .ok_or_else(|| format!("missing bound variable {variable}"))?
        else {
            return Err(format!("{variable} is not an instance reference"));
        };
        return Ok(reference.instance_id);
    }
    Err(format!("unsupported runtime notation {notation:?}"))
}

fn find_runtime_by_id<'a>(
    runtime: &'a determa_state::format1::RuntimeState,
    runtime_id: &str,
) -> Option<&'a determa_state::format1::RuntimeState> {
    if runtime.runtime_id == runtime_id {
        return Some(runtime);
    }
    for component in &runtime.components {
        if let Some(found) = find_runtime_by_id(&component.runtime, runtime_id) {
            return Some(found);
        }
    }
    for owned in &runtime.owned_instances {
        if let Some(found) = find_runtime_by_id(&owned.runtime, runtime_id) {
            return Some(found);
        }
    }
    None
}

fn relation_owner_runtime_id(relation: &determa_state::format1::RuntimeRelation) -> Option<&str> {
    match relation {
        determa_state::format1::RuntimeRelation::Root => None,
        determa_state::format1::RuntimeRelation::Component {
            owner_runtime_id, ..
        }
        | determa_state::format1::RuntimeRelation::Spawned {
            owner_runtime_id, ..
        } => Some(owner_runtime_id),
    }
}

fn runtime_target(
    state: &AggregateState,
    runtime: &determa_state::format1::RuntimeState,
) -> Target {
    match &runtime.relation {
        determa_state::format1::RuntimeRelation::Root => Target::Root {
            root_instance_id: state.root_instance_id.clone(),
            root_runtime_id: runtime.runtime_id.clone(),
        },
        determa_state::format1::RuntimeRelation::Spawned { reference, .. } => {
            Target::SpawnedInstance(reference.clone())
        }
        determa_state::format1::RuntimeRelation::Component {
            owner_runtime_id,
            component_id,
            activation_sequence,
            ..
        } => Target::Component {
            root_instance_id: state.root_instance_id.clone(),
            owner_runtime_id: owner_runtime_id.clone(),
            component_id: component_id.clone(),
            component_runtime_id: runtime.runtime_id.clone(),
            activation_sequence: activation_sequence.clone(),
        },
    }
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
    if expected
        .get("normalized_double")
        .and_then(serde_json::Value::as_str)
        == Some("positive_zero")
    {
        return match actual {
            Value::Float(value) if *value == 0.0 && value.is_sign_positive() => Ok(()),
            _ => Err(format!("actual {actual:?} is not normalized positive zero")),
        };
    }
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
                .and_then(|runtime| find_reference(runtime, reference))
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
    emitting_runtime_id: Option<&str>,
    emitting_owner_runtime_id: Option<&str>,
) -> Result<(), String> {
    if expected.as_str() == Some("external") {
        return matches!(actual, Target::External)
            .then_some(())
            .ok_or_else(|| format!("target {actual:?} is not external"));
    }
    let state = state.ok_or_else(|| "target assertion requires aggregate state".to_string())?;
    if expected.as_str() == Some("root") {
        let expected = runtime_target(state, &state.root);
        return (actual == &expected)
            .then_some(())
            .ok_or_else(|| format!("target {actual:?} != root {expected:?}"));
    }
    if expected.as_str() == Some("owner") {
        let emitter_id = emitting_runtime_id
            .ok_or_else(|| "owner target lacks emitting runtime identity".to_string())?;
        let owner_id = find_runtime_by_id(&state.root, emitter_id)
            .and_then(|emitter| {
                relation_owner_runtime_id(&emitter.relation).or(Some(emitter.runtime_id.as_str()))
            })
            .or(emitting_owner_runtime_id)
            .ok_or_else(|| "emission has no owner runtime identity".to_string())?;
        let owner = find_runtime_by_id(&state.root, owner_id)
            .ok_or_else(|| format!("owner runtime {owner_id} is absent"))?;
        let expected = runtime_target(state, owner);
        return (actual == &expected)
            .then_some(())
            .ok_or_else(|| format!("target {actual:?} != owner {expected:?}"));
    }
    if let Some(component_id) = expected
        .get("component")
        .and_then(serde_json::Value::as_str)
    {
        let emitter = find_runtime_by_id(
            &state.root,
            emitting_runtime_id
                .ok_or_else(|| "component target lacks emitting runtime identity".to_string())?,
        )
        .ok_or_else(|| "emitting runtime is absent from aggregate".to_string())?;
        let component = emitter
            .components
            .iter()
            .find(|component| component.component_id == component_id)
            .ok_or_else(|| {
                format!(
                    "component {component_id} is not owned by {}",
                    emitter.runtime_id
                )
            })?;
        let expanded = runtime_target(state, &component.runtime);
        return (actual == &expanded)
            .then_some(())
            .ok_or_else(|| format!("target {actual:?} != component {expanded:?}"));
    }
    if let Some(variable) = expected
        .get("bound_instance")
        .and_then(serde_json::Value::as_str)
    {
        let emitter = find_runtime_by_id(
            &state.root,
            emitting_runtime_id
                .ok_or_else(|| "bound target lacks emitting runtime identity".to_string())?,
        )
        .ok_or_else(|| "emitting runtime is absent from aggregate".to_string())?;
        let reference = emitter
            .visible_variables()
            .get(variable)
            .cloned()
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
    if let Some(sequence) = expected.get("step_sequence") {
        let sequence = counter_from_json(sequence)?;
        if actual.step_sequence != sequence {
            return Err(format!("fault step {} != {sequence}", actual.step_sequence));
        }
    }
    Ok(())
}

fn find_reference<'a>(
    runtime: &'a determa_state::format1::RuntimeState,
    reference: &determa_state::InstanceReference,
) -> Option<&'a determa_state::format1::RuntimeState> {
    for owned in &runtime.owned_instances {
        if owned.reference == *reference {
            return Some(&owned.runtime);
        }
        if let Some(found) = find_reference(&owned.runtime, reference) {
            return Some(found);
        }
    }
    for component in &runtime.components {
        if let Some(found) = find_reference(&component.runtime, reference) {
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
        .map(|(name, value)| Ok((name.clone(), value_from_fixture(value)?)))
        .collect()
}

fn value_from_fixture(value: &serde_json::Value) -> Result<Value, String> {
    if let Some(marker) = value
        .as_object()
        .filter(|object| object.len() == 1)
        .and_then(|object| object.get("non_finite_double"))
        .and_then(serde_json::Value::as_str)
    {
        return match marker {
            "nan" => Ok(Value::Float(f64::NAN)),
            "positive_infinity" => Ok(Value::Float(f64::INFINITY)),
            "negative_infinity" => Ok(Value::Float(f64::NEG_INFINITY)),
            _ => Err(format!("unsupported non_finite_double marker {marker:?}")),
        };
    }
    match value {
        serde_json::Value::Array(values) => values
            .iter()
            .map(value_from_fixture)
            .collect::<Result<Vec<_>, _>>()
            .map(Value::List),
        serde_json::Value::Object(values) => values
            .iter()
            .map(|(key, value)| Ok((key.clone(), value_from_fixture(value)?)))
            .collect::<Result<BTreeMap<_, _>, String>>()
            .map(Value::Map),
        _ => Value::from_json(value),
    }
}

fn aggregate_exact_equal(left: &AggregateState, right: &AggregateState) -> bool {
    if !runtime_values_exact_equal(&left.root, &right.root) {
        return false;
    }
    let mut left = left.clone();
    let mut right = right.clone();
    scrub_runtime_values(&mut left.root);
    scrub_runtime_values(&mut right.root);
    left == right
}

fn runtime_values_exact_equal(
    left: &determa_state::format1::RuntimeState,
    right: &determa_state::format1::RuntimeState,
) -> bool {
    left.variables.len() == right.variables.len()
        && left.variables.iter().all(|(key, left)| {
            right
                .variables
                .get(key)
                .is_some_and(|right| value_exact_equal(&left.value, &right.value))
        })
        && left.components.len() == right.components.len()
        && left
            .components
            .iter()
            .zip(&right.components)
            .all(|(left, right)| runtime_values_exact_equal(&left.runtime, &right.runtime))
        && left.owned_instances.len() == right.owned_instances.len()
        && left
            .owned_instances
            .iter()
            .zip(&right.owned_instances)
            .all(|(left, right)| runtime_values_exact_equal(&left.runtime, &right.runtime))
}

fn scrub_runtime_values(runtime: &mut determa_state::format1::RuntimeState) {
    for slot in runtime.variables.values_mut() {
        slot.value = Value::Null;
    }
    for component in &mut runtime.components {
        scrub_runtime_values(&mut component.runtime);
    }
    for owned in &mut runtime.owned_instances {
        scrub_runtime_values(&mut owned.runtime);
    }
}

fn value_exact_equal(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Float(left), Value::Float(right)) => left.to_bits() == right.to_bits(),
        (Value::List(left), Value::List(right)) => {
            left.len() == right.len()
                && left
                    .iter()
                    .zip(right)
                    .all(|(left, right)| value_exact_equal(left, right))
        }
        (Value::Map(left), Value::Map(right)) => {
            left.len() == right.len()
                && left.iter().all(|(key, left)| {
                    right
                        .get(key)
                        .is_some_and(|right| value_exact_equal(left, right))
                })
        }
        _ => left == right,
    }
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

fn counter_from_json(value: &serde_json::Value) -> Result<Counter, String> {
    if let Some(value) = value.as_str() {
        return Counter::from_decimal(value);
    }
    if let Some(value) = value.as_u64() {
        return Counter::from_decimal(&value.to_string());
    }
    Err(format!(
        "expected non-negative integer counter, got {value:?}"
    ))
}

fn assert_invalid_unicode_boundary(value: Option<&serde_json::Value>) -> Result<(), String> {
    fn marker(value: &serde_json::Value) -> Option<u16> {
        match value {
            serde_json::Value::Object(values) => {
                if let Some(value) = values
                    .get("invalid_unicode_scalar")
                    .and_then(serde_json::Value::as_str)
                {
                    return u16::from_str_radix(value, 16).ok();
                }
                values.values().find_map(marker)
            }
            serde_json::Value::Array(values) => values.iter().find_map(marker),
            _ => None,
        }
    }
    let scalar = value
        .and_then(marker)
        .ok_or_else(|| "invalid Unicode marker is absent or malformed".to_string())?;
    if string_from_utf16(&[scalar]).is_ok() {
        return Err(format!(
            "Rust UTF-16 boundary accepted unpaired surrogate U+{scalar:04X}"
        ));
    }
    Ok(())
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

#[test]
fn envelope_replacement_applies_all_fields_in_documented_order() {
    let bundle = load_bundle(
        r#"
format: 1
namespace: test.driver_replacement
machines:
  - machine_id: owner
    root:
      type: composite
      variables:
        child:
          type: instance_reference
          machine_id: worker
          nullable: true
          init: null
      entry:
        - spawn: { machine_id: worker, bind_to: child }
      initial: { transition_to: active }
      states:
        active: {}
  - machine_id: worker
    root: {}
"#,
    )
    .expect("focused driver bundle loads");
    let state = create(
        &bundle,
        "owner",
        "owner-1",
        "create-1",
        &Bindings::default(),
    )
    .state
    .expect("focused driver aggregate is created");
    let Value::InstanceReference(original_reference) = state
        .root
        .visible_variables()
        .get("child")
        .cloned()
        .expect("spawn binds child")
    else {
        panic!("child binding is not an instance reference");
    };
    let mut envelope = Envelope {
        event: "probe".to_string(),
        event_id: "probe-1".to_string(),
        target: runtime_target(&state, &state.root),
        payload: BTreeMap::from([("old".to_string(), Value::Bool(true))]),
        correlation_id: None,
    };

    apply_envelope_replacement(
        &mut envelope,
        &serde_json::json!({
            "payload": { "replacement": "applied" },
            "target": { "bound_instance": "child" },
            "spawned_instance_reference": { "instance_id": "tampered-child" }
        }),
        &state,
    )
    .expect("multi-field replacement succeeds");

    assert_eq!(
        envelope.payload,
        BTreeMap::from([(
            "replacement".to_string(),
            Value::String("applied".to_string())
        )])
    );
    let Target::SpawnedInstance(reference) = envelope.target else {
        panic!("target replacement did not select the spawned instance");
    };
    assert_eq!(
        reference.root_instance_id,
        original_reference.root_instance_id
    );
    assert_eq!(reference.machine_id, original_reference.machine_id);
    assert_eq!(
        reference.machine_version,
        original_reference.machine_version
    );
    assert_eq!(reference.instance_id, "tampered-child");
}
