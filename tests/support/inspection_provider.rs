use determa_state::format1::providers::{
    NativeRuntimeProvider, ProviderResult, RuntimeProviderRegistry, RuntimeProviderVerifier,
    SourceClosure,
};
use determa_state::{load_bundle_with_providers, ArtifactError, Bundle};
use serde_json::{json, Value};
use std::any::Any;
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

mod native {
    include!("../../conformance-suite/conformance/profiles/inspection-provider/provider-01-exact-closure/provider/test_provider.rs");
}
pub struct Safe {
    state: Mutex<native::SafeGuard>,
    pub inspections: AtomicUsize,
}
pub struct Unsafe {
    state: Mutex<native::UnsafeGuard>,
}
impl NativeRuntimeProvider for Safe {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn health(&self) -> bool {
        true
    }
    fn evaluate_guard(&self, _: &Value) -> ProviderResult<Value> {
        Ok(json!(self.state.lock().unwrap().evaluate()))
    }
    fn inspect_guard(
        &self,
        _: &Value,
        guards: usize,
        steps: usize,
    ) -> ProviderResult<(bool, usize, usize)> {
        self.inspections.fetch_add(1, Ordering::SeqCst);
        self.state
            .lock()
            .unwrap()
            .inspect_guard(guards as u64, steps as u64)
            .map(|(v, g, s)| (v, g as usize, s as usize))
            .map_err(|code| ArtifactError::new(code, "fixture budget"))
    }
}
impl NativeRuntimeProvider for Unsafe {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn health(&self) -> bool {
        true
    }
    fn evaluate_guard(&self, _: &Value) -> ProviderResult<Value> {
        Ok(json!(self.state.lock().unwrap().evaluate()))
    }
}
struct Verifier;
impl RuntimeProviderVerifier for Verifier {
    fn verify(
        &self,
        provider: &dyn NativeRuntimeProvider,
        descriptor: &Value,
        closure: &SourceClosure,
    ) -> ProviderResult<BTreeSet<String>> {
        let expected=include_bytes!("../../conformance-suite/conformance/profiles/inspection-provider/provider-01-exact-closure/provider/test_provider.rs");
        let selected =
            std::fs::read(closure.root.join("provider/test_provider.rs")).map_err(|_| {
                ArtifactError::new("runtime_provider_unavailable", "source unavailable")
            })?;
        if selected != expected {
            return Err(ArtifactError::new(
                "runtime_provider_unavailable",
                "compiled code differs",
            ));
        }
        let id = descriptor["binding"]["provider_reference"]["identifier"].as_str();
        if provider.as_any().is::<Safe>() && id == Some("example.inspection-safe") {
            Ok([
                "deterministic",
                "pure",
                "semantically_introspectable",
                "process_contained",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect())
        } else if provider.as_any().is::<Unsafe>() && id == Some("example.inspection-unsafe") {
            Ok(BTreeSet::new())
        } else {
            Err(ArtifactError::new(
                "runtime_provider_unavailable",
                "unbound native implementation",
            ))
        }
    }
    fn inspection_state(&self, provider: &dyn NativeRuntimeProvider) -> ProviderResult<Vec<u8>> {
        let pair = if let Some(safe) = provider.as_any().downcast_ref::<Safe>() {
            let s = safe.state.lock().unwrap();
            (s.ordinary_calls, s.external_calls)
        } else if let Some(unsafe_) = provider.as_any().downcast_ref::<Unsafe>() {
            let s = unsafe_.state.lock().unwrap();
            (s.ordinary_calls, s.external_calls)
        } else {
            return Err(ArtifactError::new(
                "runtime_provider_unavailable",
                "unbound native implementation",
            ));
        };
        Ok(format!("{}:{}", pair.0, pair.1).into_bytes())
    }
}
pub fn bundle(directory: &Path) -> (Bundle, Arc<Safe>, Arc<Unsafe>) {
    let safe = Arc::new(Safe {
        state: Mutex::new(native::SafeGuard {
            ordinary_calls: 0,
            external_calls: 0,
        }),
        inspections: AtomicUsize::new(0),
    });
    let unsafe_ = Arc::new(Unsafe {
        state: Mutex::new(native::UnsafeGuard {
            ordinary_calls: 0,
            external_calls: 0,
        }),
    });
    let mut registry = RuntimeProviderRegistry::new(Arc::new(Verifier));
    let closure = SourceClosure {
        root: directory.into(),
        paths: vec![
            "provider/test_provider.py".into(),
            "provider/test_provider.rs".into(),
        ],
        manifest: "provider-closure.json".into(),
        domain: b"determa-test-inspection-provider-closure-1\0".to_vec(),
    };
    let source = std::fs::read_to_string(directory.join("machine.yaml")).unwrap();
    let document: Value = serde_yaml::from_str(&source).unwrap();
    for event in ["safe", "unsafe"] {
        let binding = &document["machines"][0]["root"]["states"]["waiting"]["on_events"][event]
            ["guard"]["provider"];
        let provider: Arc<dyn NativeRuntimeProvider> = if event == "safe" {
            safe.clone()
        } else {
            unsafe_.clone()
        };
        registry
            .register(
                json!({"kind":"guard","binding":binding}),
                provider,
                closure.clone(),
            )
            .unwrap();
    }
    let bundle = load_bundle_with_providers(&source, registry, &BTreeSet::new()).unwrap();
    (bundle, safe, unsafe_)
}
pub fn assert_unchanged(safe: &Safe, unsafe_: &Unsafe) {
    let safe = safe.state.lock().unwrap();
    let unsafe_ = unsafe_.state.lock().unwrap();
    assert_eq!(
        (
            safe.ordinary_calls,
            safe.external_calls,
            unsafe_.ordinary_calls,
            unsafe_.external_calls
        ),
        (0, 0, 0, 0)
    );
}
