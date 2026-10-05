use determa_state::format1::providers::{
    NativeRuntimeProvider, ProviderResult, RuntimeProviderRegistry, RuntimeProviderVerifier,
    SourceClosure,
};
use determa_state::{
    compile_language_source, create, load_bundle, restore_aggregate, ArtifactError, Bindings,
    InMemoryDefinitionResolver,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    any::Any,
    collections::BTreeSet,
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

#[allow(dead_code)]
mod fixture {
    include!("../conformance-suite/conformance/profiles/runtime-provider/provider-01-exact-source/provider/test_provider.rs");
}
struct Compiler {
    calls: AtomicUsize,
}
impl NativeRuntimeProvider for Compiler {
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
            .map_err(|code| ArtifactError::new(code, "fixture compilation"))
    }
}
struct Verifier {
    weak: bool,
}
impl RuntimeProviderVerifier for Verifier {
    fn inspection_state(&self, provider: &dyn NativeRuntimeProvider) -> ProviderResult<Vec<u8>> {
        let compiler = provider
            .as_any()
            .downcast_ref::<Compiler>()
            .ok_or_else(|| {
                ArtifactError::new("runtime_provider_unavailable", "unbound compiler")
            })?;
        Ok(compiler.calls.load(Ordering::SeqCst).to_be_bytes().to_vec())
    }
    fn verify(
        &self,
        provider: &dyn NativeRuntimeProvider,
        descriptor: &Value,
        closure: &SourceClosure,
    ) -> ProviderResult<BTreeSet<String>> {
        let compiled = include_bytes!("../conformance-suite/conformance/profiles/runtime-provider/provider-01-exact-source/provider/test_provider.rs");
        let selected =
            std::fs::read(closure.root.join("provider/test_provider.rs")).map_err(|_| {
                ArtifactError::new("runtime_provider_unavailable", "source unavailable")
            })?;
        if !provider.as_any().is::<Compiler>()
            || selected != compiled
            || descriptor["binding"]["provider_reference"]["identifier"] != "example.guard-compiler"
        {
            return Err(ArtifactError::new(
                "runtime_provider_unavailable",
                "unbound compiled entrypoint",
            ));
        }
        Ok(if self.weak {
            BTreeSet::new()
        } else {
            [
                "deterministic",
                "pure",
                "portable",
                "semantically_introspectable",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect()
        })
    }
}
fn installed(weak: bool) -> (RuntimeProviderRegistry, Value, Arc<Compiler>) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("conformance-suite/conformance/profiles/runtime-provider/provider-01-exact-source");
    let source: Value =
        serde_json::from_slice(&std::fs::read(root.join("source-package.json")).unwrap()).unwrap();
    let closure = SourceClosure {
        root,
        paths: vec![
            "provider/test_provider.py".into(),
            "provider/test_provider.rs".into(),
        ],
        manifest: "provider-closure.json".into(),
        domain: b"determa-test-runtime-provider-closure-1\0".to_vec(),
    };
    let provider = Arc::new(Compiler {
        calls: AtomicUsize::new(0),
    });
    let mut registry = RuntimeProviderRegistry::new(Arc::new(Verifier { weak }));
    registry
        .register_dependency(
            source["content"]["dependencies"][0].clone(),
            closure.clone(),
        )
        .unwrap();
    registry
        .register_compiler(
            source["content"]["regions"][0]["provider_reference"].clone(),
            provider.clone(),
            closure,
        )
        .unwrap();
    (registry, source, provider)
}
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
                .map(|(key, value)| json!([key, typed(value)]))
                .collect::<Vec<_>>()
        ]),
    }
}
fn seal(source: &mut Value) {
    let bytes = serde_json_canonicalizer::to_vec(&json!([
        source["artifact_format"],
        "1",
        typed(&source["content"])
    ]))
    .unwrap();
    source["artifact_digest"] = json!(format!("sha256:{:x}", Sha256::digest(bytes)));
}
#[test]
fn inert_source_slots_fail_before_any_compiler_invocation() {
    for metadata in [true, false] {
        let (registry, mut source, provider) = installed(false);
        if metadata {
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
        let error = compile_language_source(&source, registry, None, 100).unwrap_err();
        assert_eq!(error.code, "language_compilation_failed");
        assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
    }
}
#[test]
fn compilation_always_retains_source_guarantees_and_generated_core_restores() {
    for weak in [false, true] {
        let (registry, source, provider) = installed(weak);
        let bundle = compile_language_source(&source, registry, None, 100).unwrap();
        let evidence = bundle.source_compilation.as_ref().unwrap();
        assert_eq!(evidence["source"], source);
        let record = &evidence["manifest"]["content"];
        assert_eq!(record["source_artifact_digest"], source["artifact_digest"]);
        assert_eq!(
            record["generated_validated_bundle_fingerprint"],
            bundle.fingerprint
        );
        assert_eq!(record["source_capabilities"]["pure"], !weak);
        assert_eq!(record["source_capabilities"]["external_io_capable"], weak);
        let generated = load_bundle(&bundle.normalized.to_string()).unwrap();
        assert!(generated.source_compilation.is_none());
        let aggregate = create(
            &generated,
            "order",
            "compiled-root",
            "compiled-create",
            &Bindings::default(),
        )
        .unwrap();
        let mut resolver = InMemoryDefinitionResolver::default();
        resolver.insert(generated, true);
        let restored = restore_aggregate(&aggregate.canonical_bytes().unwrap(), &resolver).unwrap();
        assert_eq!(restored.value(), aggregate.value());
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn supplied_manifest_matches_computed_evidence_after_one_compilation() {
    let (registry, source, provider) = installed(false);
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("conformance-suite/conformance/profiles/runtime-provider/provider-01-exact-source/source-manifest.json");
    let mut manifest: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let bundle = compile_language_source(&source, registry.clone(), Some(&manifest), 100).unwrap();
    assert_eq!(
        bundle.source_compilation.as_ref().unwrap()["manifest"],
        manifest
    );
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    manifest["content"]["generated_validated_bundle_fingerprint"] =
        json!(format!("sha256:{}", "0".repeat(64)));
    seal(&mut manifest);
    assert_eq!(
        compile_language_source(&source, registry, Some(&manifest), 100)
            .unwrap_err()
            .code,
        "language_compilation_failed"
    );
    assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
}
