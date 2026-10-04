use determa_state::{
    admit, create, inspect_candidate, load_bundle, restore_aggregate, step, AdmissionDelivery,
    Bindings, InMemoryDefinitionResolver, InspectionCapabilities, QueueEnvelope, TypedValue,
    FORMAT_1_CONFORMANCE_COMMIT, FORMAT_1_SPECIFICATION_COMMIT,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::process::Command;

const MINIMAL: &str = r#"
format: 1
namespace: test.public_api
events:
  coin:
    direction: input
    payload:
      amount: { type: int, required: true }
machines:
  - machine_id: turnstile
    root:
      type: composite
      initial: { transition_to: locked }
      states:
        locked:
          on_events:
            coin:
              guard: event.payload.amount >= 100
              transition_to: unlocked
        unlocked: {}
"#;

#[test]
fn published_inspection_api_uses_exact_runtime_and_guard_identity() {
    let bundle = load_bundle(MINIMAL).unwrap();
    let aggregate = create(
        &bundle,
        "turnstile",
        "turnstile-1",
        "create-1",
        &Bindings::default(),
    )
    .unwrap();
    let runtime = &aggregate.value()["runtimes"][0];
    let request = json!({
        "mode":"semantic",
        "aggregate_state_digest":aggregate.value()["aggregate_state_digest"],
        "runtime_id":runtime["runtime_id"],
        "runtime_incarnation":runtime["identity_origin"],
        "envelope":{
            "event":"coin","event_id":"candidate-1","cause_id":"candidate-1",
            "source":{"host":true},"target":runtime["target_identity"],
            "payload":["map",[["amount",["integer","100"]]]]
        },
        "limits":{"maximum_guard_evaluations":"1","maximum_evaluation_steps":"100"}
    });
    let mut resolver = InMemoryDefinitionResolver::default();
    resolver.insert(bundle, true);
    let before = aggregate.canonical_bytes().unwrap();
    let result = inspect_candidate(
        &aggregate,
        &request,
        &resolver,
        InspectionCapabilities::default(),
    )
    .unwrap();
    assert_eq!(result["disposition"], "handled_now", "{result}");
    assert_eq!(result["guard_evidence"][0]["value"], true);
    assert_eq!(
        result["guard_evidence"][0]["guard_locator"],
        "/machines/0/root/states/locked/on_events/coin/guard"
    );
    assert_eq!(aggregate.canonical_bytes().unwrap(), before);
}

#[test]
fn queue_bearing_public_operations_create_admit_step_and_restore() {
    let bundle = load_bundle(MINIMAL).expect("bundle loads");
    let aggregate = create(
        &bundle,
        "turnstile",
        "turnstile-1",
        "create-1",
        &Bindings::default(),
    )
    .expect("queue-bearing aggregate is created");
    let root_target = aggregate.value()["runtimes"][0]["target_identity"].clone();
    let root_runtime_id = aggregate.value()["runtimes"][0]["runtime_id"]
        .as_str()
        .unwrap()
        .to_string();
    let envelope = QueueEnvelope {
        event: "coin".to_string(),
        event_id: "coin-1".to_string(),
        cause_id: "coin-1".to_string(),
        source: json!({"host": true}),
        target: root_target,
        payload: TypedValue::Map(vec![("amount".to_string(), TypedValue::Integer(100))]),
        correlation_id: None,
    };
    let envelope_digest = inbox_digest("turnstile-1", "input", &envelope);
    let admitted = admit(
        &bundle,
        &aggregate,
        &[AdmissionDelivery {
            delivery_mode: "input".to_string(),
            envelope,
            envelope_digest,
        }],
    )
    .expect("delivery is admitted");
    let mut resolver = InMemoryDefinitionResolver::default();
    resolver.insert(bundle.clone(), true);
    let admitted = restore_aggregate(
        &serde_json_canonicalizer::to_vec(&admitted["state"]).unwrap(),
        &resolver,
    )
    .expect("admitted aggregate restores");
    let processed = step(&bundle, &admitted, &root_runtime_id).expect("ready work is processed");

    assert_eq!(processed["core_step_result_schema_version"], 1);
    assert_eq!(processed["disposition"], "handled");
    assert_eq!(
        processed["state"]["runtimes"][0]["active_leaf_state_definition_pointers"],
        json!(["/machines/0/root/states/unlocked"])
    );
}

#[test]
fn machine_format_identity_and_obsolete_grammar_are_rejected() {
    for source in [
        "namespace: test.missing\nmachines: []\n",
        "format: \"1\"\nnamespace: test.string\nmachines: []\n",
        "format: 2\nnamespace: test.future\nmachines: []\n",
    ] {
        assert_eq!(
            load_bundle(source)
                .expect_err("format must fail")
                .code
                .as_str(),
            "unsupported_format"
        );
    }
    let obsolete = "format: 1\nid: turnstile\ntop: {}\n";
    assert_eq!(
        load_bundle(obsolete)
            .expect_err("obsolete grammar must fail")
            .code
            .as_str(),
        "structural_validation"
    );
}

#[test]
fn examples_and_revision_metadata_are_current() {
    load_bundle(include_str!("../examples/minimal.yaml")).expect("minimal example loads");
    load_bundle(include_str!("../examples/full.yaml")).expect("full example loads");
    assert_eq!(
        FORMAT_1_SPECIFICATION_COMMIT,
        "6bd25e3fcdf068af861aa289903a8489bd8f0139"
    );
    assert_eq!(
        FORMAT_1_CONFORMANCE_COMMIT,
        "c0e101c86bd71068669df3cd2250d4fec24ff74d"
    );
}

#[test]
fn command_line_surface_is_validation_only_for_both_executable_names() {
    for binary in [
        env!("CARGO_BIN_EXE_determa-state"),
        env!("CARGO_BIN_EXE_determa-state-rust"),
    ] {
        let version = Command::new(binary)
            .arg("--version")
            .output()
            .expect("version command runs");
        assert!(version.status.success());
        assert_eq!(
            String::from_utf8(version.stdout).expect("UTF-8 output"),
            "determa-state 0.3.0\n"
        );

        let validation = Command::new(binary)
            .args(["validate", "examples/minimal.yaml"])
            .output()
            .expect("validation command runs");
        assert!(validation.status.success());
        assert_eq!(
            String::from_utf8(validation.stdout).expect("UTF-8 output"),
            "valid\n"
        );
    }
}

fn inbox_digest(root_instance_id: &str, delivery_mode: &str, envelope: &QueueEnvelope) -> String {
    let bytes = serde_json_canonicalizer::to_vec(&json!([
        "determa-inbox-envelope-digest-1",
        "1",
        root_instance_id,
        delivery_mode,
        envelope
    ]))
    .unwrap();
    format!("sha256:{:x}", Sha256::digest(bytes))
}
