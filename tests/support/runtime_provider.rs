//! Repository host binding for the exact conformance fixture, with independent proof.
use determa_state::format1::providers::{
    NativeRuntimeProvider, ProviderResult, RuntimeProviderVerifier, SourceClosure,
};
use determa_state::ArtifactError;
use serde_json::{json, Value};
use std::{
    any::Any,
    collections::BTreeSet,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    },
};
#[allow(dead_code)]
mod fixture {
    include!("../../conformance-suite/conformance/profiles/runtime-provider/provider-01-exact-source/provider/test_provider.rs");
}
fn error(code: &str) -> ArtifactError {
    ArtifactError::new(code, "runtime fixture")
}
fn approved(snapshot: &Value) -> ProviderResult<bool> {
    snapshot["event"]["payload"][1]
        .as_array()
        .and_then(|entries| entries.iter().find(|entry| entry[0] == "approved"))
        .and_then(|entry| entry[1][1].as_bool())
        .ok_or_else(|| error("guard_fault"))
}
pub struct RuntimeFixture {
    state: Mutex<fixture::Provider>,
    options: Value,
    pub inspections: AtomicUsize,
}
impl RuntimeFixture {
    pub fn new(options: Value) -> Self {
        Self {
            state: Mutex::new(fixture::Provider::default()),
            options,
            inspections: AtomicUsize::new(0),
        }
    }
    fn flag(&self, name: &str) -> bool {
        self.options[name].as_bool().unwrap_or(false)
    }
    pub fn observation(&self) -> Value {
        let state = self.state.lock().unwrap();
        json!({"guard":state.guard_calls,"actions":state.action_calls,
            "external":state.external_calls,"irreversible_side_effects":state.irreversible_effects,
            "external_effects":state.external_effect_log.iter().map(|_| json!({
                "effect_id":"fixture-io-1","kind":"external_write","phase":"before_commit"})).collect::<Vec<_>>(),
            "guard_snapshot":state.guard_snapshot.as_ref().map(|bytes| serde_json::from_str::<Value>(bytes).unwrap()),
            "action_snapshot":state.action_snapshot.as_ref().map(|bytes| serde_json::from_str::<Value>(bytes).unwrap())})
    }
    fn state_bytes(&self) -> Vec<u8> {
        format!("{:?}", self.state.lock().unwrap()).into_bytes()
    }
}
impl NativeRuntimeProvider for RuntimeFixture {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn health(&self) -> bool {
        true
    }
    fn evaluate_guard(&self, snapshot: &Value) -> ProviderResult<Value> {
        self.state
            .lock()
            .unwrap()
            .evaluate_guard_snapshot(
                &snapshot.to_string(),
                approved(snapshot)?,
                self.options["guard_override"].as_bool(),
                self.flag("guard_external_io"),
                false,
            )
            .map(|value| json!(value))
            .map_err(error)
    }
    fn evaluate_actions(&self, snapshot: &Value) -> ProviderResult<Value> {
        let mut state = self.state.lock().unwrap();
        state.action_snapshot = Some(snapshot.to_string());
        let output = if let Some(mode) = self.options["environment_send"].as_str() {
            state.evaluate_actions_environment(mode)
        } else if self.flag("mixed_send") {
            state.evaluate_actions_mixed(
                self.flag("invalid_output"),
                self.flag("action_fail"),
                self.flag("action_external_io"),
                true,
            )
        } else {
            state.evaluate_actions_repeated(
                self.flag("invalid_output"),
                self.flag("action_fail"),
                self.flag("action_external_io"),
                self.flag("repeat_send"),
            )
        }
        .map_err(error)?;
        serde_json::from_str(&output).map_err(|_| error("runtime_provider_output_invalid"))
    }
    fn inspect_guard(
        &self,
        snapshot: &Value,
        guards: usize,
        steps: usize,
    ) -> ProviderResult<(bool, usize, usize)> {
        self.inspections.fetch_add(1, Ordering::SeqCst);
        self.state
            .lock()
            .unwrap()
            .inspect_guard(approved(snapshot)?, guards as u64, steps as u64)
            .map(|(value, guards, steps)| (value, guards as usize, steps as usize))
            .map_err(error)
    }
}
pub struct CompilerFixture {
    pub calls: AtomicUsize,
}
impl NativeRuntimeProvider for CompilerFixture {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn health(&self) -> bool {
        true
    }
    fn compile_region(&self, source: &str) -> ProviderResult<Value> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        fixture::compile_region(source)
            .map(|value| json!(value))
            .map_err(error)
    }
}
pub struct Verifier {
    pub trusted: bool,
    pub weak_compiler: bool,
}
impl RuntimeProviderVerifier for Verifier {
    fn verify(
        &self,
        provider: &dyn NativeRuntimeProvider,
        descriptor: &Value,
        closure: &SourceClosure,
    ) -> ProviderResult<BTreeSet<String>> {
        let compiled = include_bytes!("../../conformance-suite/conformance/profiles/runtime-provider/provider-01-exact-source/provider/test_provider.rs");
        let selected = std::fs::read(closure.root.join("provider/test_provider.rs"))
            .map_err(|_| error("runtime_provider_unavailable"))?;
        if !self.trusted || selected != compiled {
            return Err(error("runtime_provider_unavailable"));
        }
        let identifier = descriptor["binding"]["provider_reference"]["identifier"].as_str();
        let claims = if provider.as_any().is::<RuntimeFixture>() {
            let configured = provider.as_any().downcast_ref::<RuntimeFixture>().unwrap();
            if matches!(
                identifier,
                Some("example.native-safe" | "example.native-safe-actions")
            ) && (configured.flag("guard_external_io")
                || configured.flag("action_external_io")
                || configured.options["guard_override"].as_bool().is_some())
            {
                return Err(error("runtime_provider_unavailable"));
            }
            match identifier {
                Some("example.native-safe" | "example.native-safe-actions") => vec![
                    "deterministic",
                    "pure",
                    "semantically_introspectable",
                    "process_contained",
                ],
                Some("example.native-review" | "example.native-actions") => vec![],
                _ => return Err(error("runtime_provider_unavailable")),
            }
        } else if provider.as_any().is::<CompilerFixture>()
            && identifier == Some("example.guard-compiler")
        {
            if self.weak_compiler {
                vec![]
            } else {
                vec![
                    "deterministic",
                    "pure",
                    "portable",
                    "semantically_introspectable",
                ]
            }
        } else {
            return Err(error("runtime_provider_unavailable"));
        };
        Ok(claims.into_iter().map(str::to_owned).collect())
    }
    fn inspection_state(&self, provider: &dyn NativeRuntimeProvider) -> ProviderResult<Vec<u8>> {
        provider
            .as_any()
            .downcast_ref::<RuntimeFixture>()
            .map(RuntimeFixture::state_bytes)
            .ok_or_else(|| error("runtime_provider_unavailable"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use determa_state::format1::providers::RuntimeProviderRegistry;
    #[test]
    fn safe_proof_rejects_io_and_inspection_divergence_before_invocation() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
            "conformance-suite/conformance/profiles/runtime-provider/provider-01-exact-source",
        );
        let document: Value =
            serde_yaml::from_str(&std::fs::read_to_string(root.join("machine-safe.yaml")).unwrap())
                .unwrap();
        let handler = &document["machines"][0]["root"]["states"]["pending"]["on_events"]["submit"];
        let closure = SourceClosure {
            root,
            paths: vec![
                "provider/test_provider.py".into(),
                "provider/test_provider.rs".into(),
            ],
            manifest: "provider-closure.json".into(),
            domain: b"determa-test-runtime-provider-closure-1\0".to_vec(),
        };
        for options in [
            json!({"guard_external_io":true}),
            json!({"action_external_io":true}),
            json!({"guard_override":true}),
            json!({"guard_override":false}),
        ] {
            for (kind, binding) in [
                ("guard", &handler["guard"]["provider"]),
                ("actions", &handler["action"][0]["provider_actions"]),
            ] {
                let fixture = std::sync::Arc::new(RuntimeFixture::new(options.clone()));
                let mut registry = RuntimeProviderRegistry::new(std::sync::Arc::new(Verifier {
                    trusted: true,
                    weak_compiler: false,
                }));
                for dependency in binding["dependencies"].as_array().unwrap() {
                    registry
                        .register_dependency(dependency.clone(), closure.clone())
                        .unwrap();
                }
                let descriptor = json!({"kind":kind,"binding":binding});
                let proof = Verifier {
                    trusted: true,
                    weak_compiler: false,
                }
                .verify(fixture.as_ref(), &descriptor, &closure)
                .unwrap_err();
                assert_eq!(proof.code, "runtime_provider_unavailable");
                let error = registry
                    .register(descriptor, fixture.clone(), closure.clone())
                    .unwrap_err();
                assert_eq!(error.code, "extension_identity_mismatch");
                let observed = fixture.observation();
                for counter in ["guard", "actions", "external", "irreversible_side_effects"] {
                    assert_eq!(observed[counter], 0);
                }
                assert_eq!(fixture.inspections.load(Ordering::SeqCst), 0);
            }
        }
    }
}
