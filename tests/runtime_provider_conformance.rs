//! Actual production operations for the optional exact-source runtime profile.
#[path = "support/runtime_provider.rs"]
mod provider;
use determa_state::format1::providers::{ProviderResult, RuntimeProviderRegistry, SourceClosure};
use determa_state::{
    admit, create, load_bundle_with_providers, restore_aggregate, step, AdmissionDelivery,
    ArtifactError, Bindings, InMemoryDefinitionResolver,
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
    if !providers.is_empty() {
        let bytes =
            std::fs::read(root.join("provider/test_provider.rs")).map_err(|_| unavailable())?;
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
pub fn observe_runtime_profile(payload: &Value) -> Value {
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
        stage(&mut observation, "resolve_closure");
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
        if request["operation"] != "step" {
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
        let processed = step(
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
            if request["arguments"]["invalid_output"] == true {
                observation["value"] = json!({"boundary_code":"runtime_provider_output_invalid"});
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
            observation["value"] = json!({"emissions":processed["emissions"].as_array().unwrap().len(),
                "accepted":observation["state_after"]["variables"]["accepted"]});
        }
        Ok(())
    })();
    if let Err(error) = result {
        eprintln!("production error: {}: {}", error.code, error.message);
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
fn production_driver_load_and_basic_step_vectors() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("conformance-suite/conformance/profiles/runtime-provider/provider-01-exact-source");
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(root.join("vectors.generated.json")).unwrap())
            .unwrap();
    let mut tested = 0;
    for vector in manifest["vectors"].as_array().unwrap() {
        let request = &vector["request"];
        let args = &request["arguments"];
        let selected = request["operation"] == "load"
            || request["operation"] == "step"
                && request["bundle"] == "machine.yaml"
                && [
                    "repeat_send",
                    "mixed_send",
                    "destroyed_write",
                    "capture_snapshot",
                    "environment_send",
                ]
                .iter()
                .all(|key| args.get(key).is_none());
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
    assert_eq!(tested, 13);
}
