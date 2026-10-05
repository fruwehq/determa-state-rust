//! Actual production operations for the optional exact-source runtime profile.
#[path = "support/runtime_provider_host.rs"]
mod host;
#[path = "support/runtime_provider.rs"]
mod provider;
use determa_state::format1::providers::{ProviderResult, RuntimeProviderRegistry, SourceClosure};
use determa_state::{
    admit, create, inspect_candidate, load_bundle_with_providers, restore_aggregate, step,
    AdmissionDelivery, ArtifactError, Bindings, InMemoryDefinitionResolver, InspectionCapabilities,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, path::Path, sync::Arc};

fn unavailable() -> ArtifactError {
    ArtifactError::new(
        "runtime_provider_unavailable",
        "exact configured closure unavailable",
    )
}
fn empty() -> Value {
    json!({"stages":[],"result":"rejected","code":null,"value":null,
    "calls":{"guard":0,"actions":0,"inspect_guard":0,"compile_region":0,"external":0},
    "irreversible_side_effects":0,"external_effects":[],"determa_state_committed":false,
    "effective_capabilities":null,"state_before":null,"state_after":null})
}
fn stage(observation: &mut Value, value: &str) {
    observation["stages"]
        .as_array_mut()
        .unwrap()
        .push(json!(value));
}
fn bindings(document: &Value) -> Vec<(String, Value)> {
    fn actions(value: &Value, result: &mut Vec<(String, Value)>) {
        if let Some(items) = value.as_array() {
            for action in items {
                if let Some(binding) = action.get("provider_actions") {
                    result.push(("actions".into(), binding.clone()));
                }
            }
        }
    }
    fn transition(value: &Value, result: &mut Vec<(String, Value)>) {
        if let Some(items) = value.as_array() {
            for item in items {
                transition(item, result);
            }
        } else {
            if let Some(binding) = value.get("guard").and_then(|value| value.get("provider")) {
                result.push(("guard".into(), binding.clone()));
            }
            actions(&value["action"], result);
        }
    }
    fn state(value: &Value, result: &mut Vec<(String, Value)>) {
        actions(&value["entry"], result);
        actions(&value["exit"], result);
        transition(&value["initial"], result);
        transition(&value["choice"], result);
        if let Some(handlers) = value["on_events"].as_object() {
            for handler in handlers.values() {
                transition(handler, result);
            }
        }
        if let Some(children) = value["states"].as_object() {
            for child in children.values() {
                state(child, result);
            }
        }
        if let Some(components) = value["components"].as_array() {
            for component in components {
                if let Some(root) = component.get("root") {
                    state(root, result);
                }
            }
        }
    }
    let mut result = Vec::new();
    if let Some(machines) = document["machines"].as_array() {
        for machine in machines {
            state(&machine["root"], &mut result);
        }
    }
    result
}
fn installed(
    payload: &Value,
    document: &Value,
    loaded: &mut Value,
) -> ProviderResult<(RuntimeProviderRegistry, Vec<Arc<provider::RuntimeFixture>>)> {
    let request = &payload["request"];
    let installed = &request["installed"];
    let root = Path::new(payload["profile_root"].as_str().unwrap());
    let closure = SourceClosure {
        root: root.into(),
        paths: vec![
            "provider/test_provider.py".into(),
            "provider/test_provider.rs".into(),
        ],
        manifest: "provider-closure.json".into(),
        domain: b"determa-test-runtime-provider-closure-1\0".to_vec(),
    };
    closure.verify()?;
    if installed["trusted"] != true
        || installed["closure_digest"] != closure.digest()?
        || installed["source_digest"] != closure.manifest_digest()?
    {
        return Err(unavailable());
    }
    let discovered = bindings(document);
    let references = installed["providers"].as_array().ok_or_else(unavailable)?;
    for (_, binding) in &discovered {
        if !references.contains(&binding["provider_reference"])
            || binding["provider_reference"]["content_digest"] != closure.digest()?
        {
            return Err(unavailable());
        }
        for dependency in binding["dependencies"].as_array().ok_or_else(unavailable)? {
            if !references.contains(dependency)
                || dependency["content_digest"] != closure.digest()?
            {
                return Err(unavailable());
            }
        }
    }
    let mut registry = RuntimeProviderRegistry::new(Arc::new(provider::Verifier {
        trusted: true,
        weak_compiler: false,
    }));
    let mut dependencies = BTreeSet::new();
    for (_, binding) in &discovered {
        for dependency in binding["dependencies"].as_array().unwrap() {
            if dependencies.insert(dependency.to_string()) {
                registry.register_dependency(dependency.clone(), closure.clone())?;
            }
        }
    }
    let mut registered = BTreeSet::new();
    let mut providers = Vec::new();
    for (kind, binding) in discovered {
        if !registered.insert((kind.clone(), binding["provider_reference"].to_string())) {
            continue;
        }
        let provider = Arc::new(provider::RuntimeFixture::new(request["arguments"].clone()));
        registry.register(
            json!({"kind":kind,"binding":binding}),
            provider.clone(),
            closure.clone(),
        )?;
        providers.push(provider);
    }
    if !references.is_empty() {
        let bytes =
            std::fs::read(root.join("provider/test_provider.rs")).map_err(|_| unavailable())?;
        if bytes != include_bytes!("../conformance-suite/conformance/profiles/runtime-provider/provider-01-exact-source/provider/test_provider.rs") { return Err(unavailable()); }
        loaded["provider/test_provider.rs"] = json!(format!("sha256:{:x}", Sha256::digest(bytes)));
    }
    Ok((registry, providers))
}
fn counts(observation: &mut Value, providers: &[Arc<provider::RuntimeFixture>]) {
    for provider in providers {
        let data = provider.observation();
        for name in ["guard", "actions", "external"] {
            let count = observation["calls"][name].as_u64().unwrap() + data[name].as_u64().unwrap();
            observation["calls"][name] = json!(count);
        }
        observation["irreversible_side_effects"] = json!(
            observation["irreversible_side_effects"].as_u64().unwrap()
                + data["irreversible_side_effects"].as_u64().unwrap()
        );
        observation["external_effects"]
            .as_array_mut()
            .unwrap()
            .extend(data["external_effects"].as_array().unwrap().clone());
    }
}
fn state(aggregate: &Value) -> Value {
    let root = aggregate["runtimes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|runtime| runtime["runtime_id"] == aggregate["root_runtime_id"])
        .unwrap();
    let mut variables = json!({});
    for variable in root["variables"].as_array().unwrap() {
        variables[variable["variable_declaration_pointer"]
            .as_str()
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap()] = variable["value"].clone();
    }
    json!({"status":root["status"],"active_leaf":root["active_leaf_state_definition_pointers"].as_array().unwrap().last(),
        "variables":variables,"ready_mailbox_length":root["ready_mailbox"].as_array().unwrap().len(),
        "deferred_mailbox_length":root["deferred_mailbox"].as_array().unwrap().len(),
        "output_count":aggregate["next_output_sequence"].as_str().unwrap().parse::<u64>().unwrap()})
}
fn component_states(aggregate: &Value) -> Value {
    let mut result = json!({});
    for runtime in aggregate["runtimes"].as_array().unwrap() {
        if let Some(id) = runtime["target_identity"]["component"]["component_id"].as_str() {
            let mut child = aggregate.clone();
            child["root_runtime_id"] = runtime["runtime_id"].clone();
            let mut observed = state(&child);
            observed.as_object_mut().unwrap().remove("active_leaf");
            observed.as_object_mut().unwrap().remove("output_count");
            result[id] = observed;
        }
    }
    result
}
fn component<'a>(aggregate: &'a Value, id: &str) -> &'a Value {
    aggregate["runtimes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|runtime| runtime["target_identity"]["component"]["component_id"] == id)
        .unwrap()
}
fn child_variables(aggregate: &Value, child: &Value) -> Value {
    let mut projected = aggregate.clone();
    projected["root_runtime_id"] = child["runtime_id"].clone();
    state(&projected)["variables"].clone()
}
pub fn observe_runtime_profile(payload: &Value) -> Value {
    #[cfg(determa_repository_conformance)]
    if payload["request"]["operation"] == "compile" {
        return observe_compilation(payload);
    }
    let request = &payload["request"];
    let root = Path::new(payload["profile_root"].as_str().unwrap());
    let closure = SourceClosure {
        root: root.into(),
        paths: vec![
            "provider/test_provider.py".into(),
            "provider/test_provider.rs".into(),
        ],
        manifest: "provider-closure.json".into(),
        domain: b"determa-test-runtime-provider-closure-1\0".to_vec(),
    };
    let mut observation = empty();
    let mut loaded = json!({});
    let result = (|| -> ProviderResult<()> {
        stage(
            &mut observation,
            if request["operation"] == "restore" {
                "resolve_runtime_closure"
            } else {
                "resolve_closure"
            },
        );
        let source = std::fs::read_to_string(root.join(request["bundle"].as_str().unwrap()))
            .map_err(|_| unavailable())?;
        let document: Value = serde_yaml::from_str(&source).map_err(|_| unavailable())?;
        let (registry, providers) = installed(payload, &document, &mut loaded)?;
        let required =
            if request["operation"] == "load" && request["arguments"]["opt_in_weak"] == false {
                [
                    "deterministic",
                    "pure",
                    "portable",
                    "semantically_introspectable",
                    "process_contained",
                ]
                .into_iter()
                .map(str::to_owned)
                .collect()
            } else {
                BTreeSet::new()
            };
        if request["operation"] == "load" {
            stage(&mut observation, "verify_capabilities");
        }
        let bundle = load_bundle_with_providers(&source, registry.clone(), &required).inspect_err(
            |error| {
                if request["operation"] == "load"
                    && !matches!(
                        error.code.as_str(),
                        "runtime_provider_unavailable"
                            | "extension_capability_mismatch"
                            | "invalid_extension_descriptor"
                    )
                {
                    observation["stages"].as_array_mut().unwrap().pop();
                    stage(&mut observation, "load");
                }
            },
        )?;
        observation["effective_capabilities"] =
            serde_json::to_value(registry.effective_capabilities(&bundle.normalized)?).unwrap();
        if request["operation"] == "load" {
            stage(&mut observation, "load");
            observation["result"] = json!("accepted");
            return Ok(());
        }
        if request["operation"] == "host_commit" {
            return host::run(&bundle, &providers, request, &mut observation);
        }
        if request["operation"] == "restore" {
            if bundle.fingerprint
                != request["arguments"]["definition_fingerprint"]
                    .as_str()
                    .unwrap()
            {
                return Err(unavailable());
            }
            let aggregate = create(
                &bundle,
                document["machines"][0]["machine_id"].as_str().unwrap(),
                "restore-root",
                "restore-create",
                &Bindings::default(),
            )?;
            let mut resolver = InMemoryDefinitionResolver::default();
            resolver.insert(bundle.clone(), true);
            restore_aggregate(&aggregate.canonical_bytes()?, &resolver)?;
            stage(&mut observation, "restore");
            observation["result"] = json!("accepted");
            counts(&mut observation, &providers);
            return Ok(());
        }
        #[cfg(determa_repository_conformance)]
        if request["operation"] == "create" {
            let creation = &request["setup"]["create_request"];
            let result = determa_state::format1::providers::repository_create_with_evidence(
                &bundle,
                creation["machine_id"].as_str().unwrap(),
                creation["root_instance_id"].as_str().unwrap(),
                creation["creation_id"].as_str().unwrap(),
            )?;
            stage(&mut observation, "create");
            counts(&mut observation, &providers);
            if observation["calls"]["actions"].as_u64().unwrap() > 0 {
                stage(&mut observation, "evaluate_actions");
                stage(&mut observation, "validate_output");
            }
            observation["state_after"] = state(&result["state"]);
            observation["result"] = result["status"].clone();
            if !result["fault"].is_null() {
                observation["code"] = result["fault"]["code"].clone();
                observation["value"] = json!({"boundary_code":"runtime_provider_output_invalid","source_locator":result["fault"]["source_locator"],"emissions":result["emissions"].as_array().unwrap().len(),"status":result["status"]});
            }
            return Ok(());
        }
        if request["operation"] != "step" && request["operation"] != "inspect" {
            return Err(ArtifactError::new(
                "runtime_adapter_operation_unfinished",
                "remaining draft driver operation",
            ));
        }
        let setup = &request["setup"];
        let creation = &setup["create_request"];
        let mut aggregate = create(
            &bundle,
            creation["machine_id"].as_str().unwrap(),
            creation["root_instance_id"].as_str().unwrap(),
            creation["creation_id"].as_str().unwrap(),
            &Bindings::default(),
        )?;
        stage(&mut observation, "create");
        if request["operation"] == "inspect" {
            observation["state_before"] = state(aggregate.value());
            observation["state_after"] = state(aggregate.value());
            let arguments = &request["arguments"];
            let mode = arguments["mode"].as_str().unwrap();
            let root_runtime = aggregate.value()["runtimes"]
                .as_array()
                .unwrap()
                .iter()
                .find(|runtime| runtime["runtime_id"] == aggregate.value()["root_runtime_id"])
                .unwrap();
            let mut envelope = setup["envelope"].clone();
            if let Some(approved) = arguments.get("approved") {
                envelope["payload"] = json!(["map", [["approved", ["boolean", approved]]]]);
            }
            let inspection = json!({"mode":mode,"aggregate_state_digest":aggregate.value()["aggregate_state_digest"],
                "runtime_id":root_runtime["runtime_id"],"runtime_incarnation":root_runtime["identity_origin"],"envelope":envelope,
                "limits":if mode == "structural" { Value::Null } else { json!({"maximum_guard_evaluations":arguments["maximum_guard_evaluations"].as_u64().unwrap().to_string(),
                "maximum_evaluation_steps":arguments["maximum_evaluation_steps"].as_u64().unwrap().to_string()}) }});
            let mut resolver = InMemoryDefinitionResolver::default();
            resolver.insert(bundle.clone(), true);
            stage(
                &mut observation,
                if mode == "semantic" {
                    "preflight_inspection"
                } else {
                    "structural_inspection"
                },
            );
            let outcome = inspect_candidate(
                &aggregate,
                &inspection,
                &resolver,
                InspectionCapabilities::default(),
            )?;
            let invocations: usize = providers
                .iter()
                .map(|provider| {
                    provider
                        .inspections
                        .load(std::sync::atomic::Ordering::SeqCst)
                })
                .sum();
            observation["calls"]["inspect_guard"] = json!(invocations);
            if invocations > 0 {
                stage(&mut observation, "invoke_inspect_guard");
            }
            if let Some(code) = outcome.get("code") {
                observation["code"] = code.clone();
            } else {
                observation["result"] = json!("accepted");
                observation["value"] = json!({"classification":outcome["classification"]});
                if mode == "semantic" {
                    observation["value"]["disposition"] = outcome["disposition"].clone();
                    observation["value"]["fuel"] = arguments["maximum_evaluation_steps"].clone();
                }
            }
            return Ok(());
        }
        let envelope: determa_state::QueueEnvelope =
            serde_json::from_value(setup["envelope"].clone()).unwrap();
        let delivery = AdmissionDelivery {
            delivery_mode: "input".into(),
            envelope,
            envelope_digest: setup["envelope_digest"].as_str().unwrap_or("").into(),
        };
        // Request setup carries an envelope; derive its normative admission digest.
        let delivery = AdmissionDelivery {
            envelope_digest: delivery_digest(
                creation["root_instance_id"].as_str().unwrap(),
                &delivery.envelope,
            ),
            ..delivery
        };
        let admitted = admit(&bundle, &aggregate, &[delivery])?;
        let mut resolver = InMemoryDefinitionResolver::default();
        resolver.insert(bundle.clone(), true);
        aggregate = restore_aggregate(
            &serde_json_canonicalizer::to_vec(&admitted["state"]).unwrap(),
            &resolver,
        )?;
        stage(&mut observation, "admit");
        observation["state_before"] = state(aggregate.value());
        stage(&mut observation, "evaluate_cel");
        #[cfg(not(determa_repository_conformance))]
        let processed = step(
            &bundle,
            &aggregate,
            setup["target_runtime_id"].as_str().unwrap(),
        )?;
        #[cfg(determa_repository_conformance)]
        let (processed, indexes) = determa_state::format1::providers::repository_step_with_indexes(
            &bundle,
            &aggregate,
            setup["target_runtime_id"].as_str().unwrap(),
        )?;
        counts(&mut observation, &providers);
        if observation["calls"]["guard"].as_u64().unwrap() > 0 {
            stage(&mut observation, "evaluate_guard");
        }
        if observation["calls"]["actions"].as_u64().unwrap() > 0 {
            stage(&mut observation, "evaluate_actions");
            if request["arguments"]["action_fail"] != true {
                stage(&mut observation, "validate_output");
            }
        }
        if processed["disposition"] == "faulted" {
            observation["result"] = json!("faulted");
            observation["code"] = processed["fault"]["code"].clone();
            observation["state_after"] = observation["state_before"].clone();
            if request["arguments"].get("environment_send").is_some() {
                observation["value"] = json!({"source_locator":processed["fault"]["source_locator"],
                    "component_states_before":component_states(aggregate.value()),
                    "component_states_after":component_states(&processed["state"])});
            }
            if request["arguments"]["invalid_output"] == true
                || request["arguments"]["destroyed_write"] == true
            {
                observation["value"] = json!({"boundary_code":"runtime_provider_output_invalid"});
                if request["arguments"]["destroyed_write"] == true {
                    observation["value"]["source_locator"] =
                        processed["fault"]["source_locator"].clone();
                }
            }
        } else {
            stage(&mut observation, "commit");
            observation["determa_state_committed"] = json!(true);
            observation["result"] = if processed["disposition"] == "handled" {
                json!("handled_now")
            } else {
                processed["disposition"].clone()
            };
            observation["state_after"] = state(&processed["state"]);
            observation["value"] =
                json!({"emissions":processed["emissions"].as_array().unwrap().len()});
            if let Some(accepted) = observation["state_after"]["variables"]
                .get("accepted")
                .cloned()
            {
                observation["value"]["accepted"] = accepted;
            }
            if observation["state_after"]["status"] == "completed" {
                observation["value"]["status"] = json!("completed");
                observation["value"]["exit_correlation"] =
                    processed["emissions"].as_array().unwrap().last().unwrap()["correlation_id"]
                        .clone();
            }
            if request["arguments"].get("environment_send").is_some() {
                let before = component(aggregate.value(), "replica");
                let after = component(&processed["state"], "replica");
                let internal = processed["emissions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|item| item["kind"] == "internal_mailbox")
                    .unwrap();
                let envelope = &after["ready_mailbox"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|item| item["envelope"]["event_id"] == internal["event_id"])
                    .unwrap()["envelope"];
                observation["value"]["forwarded_event"] = json!({"event":envelope["event"],"payload":envelope["payload"],"component_id":"replica"});
                observation["value"]["component_variables_before"] =
                    child_variables(aggregate.value(), before);
                observation["value"]["component_ready_before_delivery"] =
                    json!(after["ready_mailbox"].as_array().unwrap().len());
                let owner_result = restore_aggregate(
                    &serde_json_canonicalizer::to_vec(&processed["state"]).unwrap(),
                    &resolver,
                )?;
                let delivered = step(
                    &bundle,
                    &owner_result,
                    after["runtime_id"].as_str().unwrap(),
                )?;
                stage(&mut observation, "deliver_env");
                let refreshed = component(&delivered["state"], "replica");
                observation["value"]["component_variables_after"] =
                    child_variables(&delivered["state"], refreshed);
                observation["value"]["component_ready_after_delivery"] =
                    json!(refreshed["ready_mailbox"].as_array().unwrap().len());
            }
            #[cfg(determa_repository_conformance)]
            if request["arguments"]["repeat_send"] == true
                || request["arguments"]["mixed_send"] == true
            {
                observation["value"]["emission_identities"] = json!(processed["emissions"].as_array().unwrap().iter().zip(&indexes).map(|(item,index)| {
                    if item.get("kind").is_some() { json!({"event_id":item["event_id"],"emission_index":item["emission_index"],"acceptance_sequence":item["acceptance_sequence"],"queue_sequence":item["queue_sequence"]}) }
                    else { json!({"effect_id":item["effect_id"],"sequence":item["sequence"],"emission_index":index}) }
                }).collect::<Vec<_>>());
            }
            if request["arguments"]["capture_snapshot"] == true {
                for provider in &providers {
                    let captured = provider.observation();
                    for key in ["guard_snapshot", "action_snapshot"] {
                        if !captured[key].is_null() {
                            observation["value"][key] = captured[key].clone();
                        }
                    }
                }
            }
        }
        Ok(())
    })();
    if let Err(error) = result {
        eprintln!("production error: {}: {}", error.code, error.message);
        observation["code"] = json!(error.code);
    }
    json!({"observation":observation,"loaded_source":loaded,"loaded_closure_digest":closure.digest().unwrap()})
}
#[cfg(determa_repository_conformance)]
fn observe_compilation(payload: &Value) -> Value {
    use determa_state::format1::providers::take_compilation_stages;
    use determa_state::{compile_language_source, load_bundle};
    use std::sync::atomic::{AtomicUsize, Ordering};
    fn typed(value: &Value) -> Value {
        match value {
            Value::Null => json!(["null"]),
            Value::Bool(v) => json!(["boolean", v]),
            Value::String(v) => json!(["string", v]),
            Value::Number(v) => json!(["integer", v.to_string()]),
            Value::Array(v) => json!(["list", v.iter().map(typed).collect::<Vec<_>>()]),
            Value::Object(v) => json!([
                "map",
                v.iter()
                    .map(|(k, v)| json!([k, typed(v)]))
                    .collect::<Vec<_>>()
            ]),
        }
    }
    fn seal(value: &mut Value) {
        value["artifact_digest"] = json!(format!(
            "sha256:{:x}",
            Sha256::digest(
                serde_json_canonicalizer::to_vec(&json!([
                    value["artifact_format"],
                    "1",
                    typed(&value["content"])
                ]))
                .unwrap()
            )
        ));
    }
    let request = &payload["request"];
    let args = &request["arguments"];
    let root = Path::new(payload["profile_root"].as_str().unwrap());
    let closure = SourceClosure {
        root: root.into(),
        paths: vec![
            "provider/test_provider.py".into(),
            "provider/test_provider.rs".into(),
        ],
        manifest: "provider-closure.json".into(),
        domain: b"determa-test-runtime-provider-closure-1\0".to_vec(),
    };
    let mut observation = empty();
    let mut loaded = json!({});
    let compiler = Arc::new(provider::CompilerFixture {
        calls: AtomicUsize::new(0),
    });
    take_compilation_stages();
    let result = (|| -> ProviderResult<()> {
        let mut source: Value = serde_json::from_slice(
            &std::fs::read(root.join(args["source_file"].as_str().unwrap())).unwrap(),
        )
        .unwrap();
        if let Some(value) = args.get("source_override") {
            source["content"]["regions"][0]["source"] = value.clone();
            seal(&mut source);
        }
        if let Some(slot) = args.get("invalid_slot") {
            if slot == "metadata_guard" {
                source["content"]["template"]["meta"] = json!({"guard":"true"});
                source["content"]["regions"][0]["locator"] = json!("/meta/guard");
            } else {
                source["content"]["template"]["machines"][0]["root"]["variables"] =
                    json!({"data":{"type":"map","init":{"action":[]}}});
                source["content"]["regions"][0]["locator"] =
                    json!("/machines/0/root/variables/data/init/action");
                source["content"]["regions"][0]["kind"] = json!("actions");
            }
            seal(&mut source);
        }
        if let Some(value) = args.get("source_digest_override") {
            source["artifact_digest"] = value.clone();
        }
        // The same production preflight runs with an empty registry: valid source
        // reaches resolution but cannot invoke any compiler before host installation.
        let preflight = compile_language_source(
            &source,
            RuntimeProviderRegistry::new(Arc::new(provider::Verifier {
                trusted: true,
                weak_compiler: false,
            })),
            None,
            1000,
        );
        observation["stages"] = json!(take_compilation_stages());
        if let Err(error) = preflight {
            if error.code != "runtime_provider_unavailable" {
                return Err(error);
            }
        }
        closure.verify()?;
        let installed = &request["installed"];
        if installed["trusted"] != true
            || installed["closure_digest"] != closure.digest()?
            || installed["source_digest"] != closure.manifest_digest()?
        {
            return Err(unavailable());
        }
        let references = installed["providers"].as_array().ok_or_else(unavailable)?;
        let mut registry = RuntimeProviderRegistry::new(Arc::new(provider::Verifier {
            trusted: true,
            weak_compiler: args["weak_compiler"] == true,
        }));
        for dependency in source["content"]["dependencies"].as_array().unwrap() {
            if !references.contains(dependency)
                || dependency["content_digest"] != closure.digest()?
            {
                return Err(unavailable());
            }
            registry.register_dependency(dependency.clone(), closure.clone())?;
        }
        for region in source["content"]["regions"].as_array().unwrap() {
            let reference = &region["provider_reference"];
            if !references.contains(reference) || reference["content_digest"] != closure.digest()? {
                return Err(unavailable());
            }
            registry.register_compiler(reference.clone(), compiler.clone(), closure.clone())?;
        }
        loaded["provider/test_provider.rs"] = json!(format!(
            "sha256:{:x}",
            Sha256::digest(std::fs::read(root.join("provider/test_provider.rs")).unwrap())
        ));
        let mut manifest = args.get("manifest_file").map(|file| {
            serde_json::from_slice::<Value>(
                &std::fs::read(root.join(file.as_str().unwrap())).unwrap(),
            )
            .unwrap()
        });
        if let Some(value) = args.get("manifest_fingerprint_override") {
            let manifest = manifest.as_mut().unwrap();
            manifest["content"]["generated_validated_bundle_fingerprint"] = value.clone();
            seal(manifest);
        }
        let compiled = compile_language_source(
            &source,
            registry,
            manifest.as_ref(),
            args["maximum_compilation_steps"].as_u64().unwrap_or(1000) as usize,
        );
        observation["stages"] = json!(take_compilation_stages());
        let bundle = compiled?;
        if let Some(file) = args.get("generated_bundle_file") {
            let supplied =
                load_bundle(&std::fs::read_to_string(root.join(file.as_str().unwrap())).unwrap())
                    .map_err(|error| ArtifactError::new(error.code.as_str(), error.message))?;
            if supplied.fingerprint != bundle.fingerprint {
                return Err(ArtifactError::new(
                    "language_compilation_failed",
                    "generated bundle mismatch",
                ));
            }
        }
        let evidence = &bundle.source_compilation.as_ref().unwrap()["manifest"]["content"];
        observation["effective_capabilities"] = evidence["source_capabilities"].clone();
        observation["result"] = json!("accepted");
        observation["value"] = json!({"generated_guard":bundle.normalized["machines"][0]["root"]["states"]["pending"]["on_events"]["submit"]["guard"]});
        if args["without_manifest"] == true && args["weak_compiler"] == true {
            let generated = load_bundle(&bundle.normalized.to_string())
                .map_err(|error| ArtifactError::new(error.code.as_str(), error.message))?;
            let aggregate = create(
                &generated,
                "order",
                "compiled-restore-root",
                "compiled-create",
                &Bindings::default(),
            )?;
            let mut resolver = InMemoryDefinitionResolver::default();
            resolver.insert(generated.clone(), true);
            let before = compiler.calls.load(Ordering::SeqCst);
            let restored = restore_aggregate(&aggregate.canonical_bytes()?, &resolver)?;
            let registry = RuntimeProviderRegistry::new(Arc::new(provider::Verifier {
                trusted: true,
                weak_compiler: false,
            }));
            for key in [
                "source_artifact_digest",
                "compiler_providers",
                "generated_validated_bundle_fingerprint",
            ] {
                observation["value"][key] = evidence[key].clone();
            }
            observation["value"]["generated_runtime_capabilities"] =
                json!(registry.effective_capabilities(&generated.normalized)?);
            // Resolve the actual restored definition before measuring its capabilities.
            let fingerprint = restored.value()["validated_bundle_fingerprint"]
                .as_str()
                .unwrap();
            if fingerprint != generated.fingerprint {
                return Err(unavailable());
            }
            observation["value"]["restored_runtime_capabilities"] =
                json!(registry.effective_capabilities(&generated.normalized)?);
            observation["value"]["restore_compiler_calls"] =
                json!(compiler.calls.load(Ordering::SeqCst) - before);
        }
        Ok(())
    })();
    observation["calls"]["compile_region"] = json!(compiler.calls.load(Ordering::SeqCst));
    if let Err(error) = result {
        observation["code"] = json!(error.code);
    }
    json!({"observation":observation,"loaded_source":loaded,"loaded_closure_digest":closure.digest().unwrap()})
}
fn delivery_digest(root: &str, envelope: &determa_state::QueueEnvelope) -> String {
    let projection = json!([
        "determa-inbox-envelope-digest-1",
        "1",
        root,
        "input",
        envelope
    ]);
    format!(
        "sha256:{:x}",
        Sha256::digest(serde_json_canonicalizer::to_vec(&projection).unwrap())
    )
}

#[test]
fn production_driver_runtime_operation_vectors() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("conformance-suite/conformance/profiles/runtime-provider/provider-01-exact-source");
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(root.join("vectors.generated.json")).unwrap())
            .unwrap();
    let mut tested = 0;
    for vector in manifest["vectors"].as_array().unwrap() {
        let request = &vector["request"];
        let args = &request["arguments"];
        let selected = ["load", "inspect", "restore"]
            .iter()
            .any(|operation| request["operation"] == *operation)
            || request["operation"] == "step"
                && ["repeat_send", "mixed_send"]
                    .iter()
                    .all(|key| args.get(key).is_none());
        #[cfg(determa_repository_conformance)]
        let selected = selected
            || ["step", "compile", "create", "host_commit"]
                .iter()
                .any(|operation| request["operation"] == *operation);
        if !selected {
            continue;
        }
        let observed = observe_runtime_profile(&json!({"request":request,"profile_root":root,
            "source_files":manifest["source_files"],"source_closure_file":manifest["source_closure_file"]}));
        assert_eq!(
            observed["observation"], vector["expected"],
            "{}",
            vector["name"]
        );
        tested += 1;
    }
    #[cfg(not(determa_repository_conformance))]
    assert_eq!(tested, 36);
    #[cfg(determa_repository_conformance)]
    assert_eq!(tested, 52);
}
