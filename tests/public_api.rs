use determa_state::{
    admit, create, load_bundle, restore_aggregate, step, Bindings, Delivery, Envelope,
    InMemoryDefinitionResolver, TypedValue, FORMAT_1_CONFORMANCE_COMMIT,
    FORMAT_1_SPECIFICATION_COMMIT,
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
    let envelope = Envelope {
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
        &[Delivery {
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

    assert_eq!(processed["core_step_result_schema_version"], 2);
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
        "ee38796d5e38e67e350a06548fd50faa530cbb12"
    );
    assert_eq!(
        FORMAT_1_CONFORMANCE_COMMIT,
        "99a4d9ad5256f7330e75b06d48f340cc7239a40d"
    );
}

#[test]
fn command_line_surface_is_validation_only_and_aliases_match() {
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
            "determa-state 0.2.0\n"
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

fn inbox_digest(root_instance_id: &str, delivery_mode: &str, envelope: &Envelope) -> String {
    let bytes = serde_json_canonicalizer::to_vec(&json!([
        "determa-inbox-envelope-digest-2",
        "2",
        root_instance_id,
        delivery_mode,
        envelope
    ]))
    .unwrap();
    format!("sha256:{:x}", Sha256::digest(bytes))
}
