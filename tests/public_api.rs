use determa_state::{
    create, dispatch, load_bundle, Bindings, Delivery, Disposition, Envelope, ResultStatus, Target,
    Value, FORMAT_1_CONFORMANCE_COMMIT, FORMAT_1_SPECIFICATION_COMMIT,
};
use std::collections::BTreeMap;
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

fn root_target(state: &determa_state::AggregateState) -> Target {
    Target::Root {
        root_instance_id: state.root_instance_id.clone(),
        root_runtime_id: state.root.runtime_id.clone(),
    }
}

#[test]
fn pure_dispatch_keeps_prior_state_and_is_retry_deterministic() {
    let bundle = load_bundle(MINIMAL).expect("bundle loads");
    let created = create(
        &bundle,
        "turnstile",
        "turnstile-1",
        "create-1",
        &Bindings::default(),
    );
    let prior = created.state.expect("creation returns state");
    let delivery = Delivery::Input(Envelope {
        event: "coin".to_string(),
        event_id: "coin-1".to_string(),
        target: root_target(&prior),
        payload: BTreeMap::from([("amount".to_string(), Value::Int(100))]),
        correlation_id: None,
    });

    let first = dispatch(&bundle, &prior, Some(delivery.clone()));
    let retry = dispatch(&bundle, &prior, Some(delivery));

    assert_eq!(prior.root.config(), vec!["locked"]);
    assert_eq!(
        first.state.as_ref().expect("state").root.config(),
        vec!["unlocked"]
    );
    assert_eq!(first.status, ResultStatus::Running);
    assert_eq!(first.disposition, Some(Disposition::Handled));
    assert_eq!(
        first
            .state
            .as_ref()
            .expect("state")
            .next_logical_step_sequence,
        retry
            .state
            .as_ref()
            .expect("state")
            .next_logical_step_sequence
    );
    assert_eq!(first.emissions, retry.emissions);
}

#[test]
fn prior_state_is_bound_to_the_normalized_bundle_fingerprint() {
    let bundle = load_bundle(MINIMAL).expect("bundle loads");
    let state = create(
        &bundle,
        "turnstile",
        "turnstile-1",
        "create-1",
        &Bindings::default(),
    )
    .state
    .expect("creation returns state");
    let changed = load_bundle(&MINIMAL.replace("test.public_api", "test.changed"))
        .expect("changed bundle loads");
    let result = dispatch(&changed, &state, None);

    assert_eq!(result.disposition, Some(Disposition::Rejected));
    assert_eq!(
        result.rejection.as_ref().map(|value| value.code.as_str()),
        Some("incompatible_bundle")
    );
    assert_eq!(
        result.state.expect("prior state is returned").root.config(),
        vec!["locked"]
    );
}

#[test]
fn obsolete_unpublished_grammar_is_not_accepted() {
    let error = load_bundle(
        r#"
format: 1
id: turnstile
top:
  esvs:
    count: { type: int, init: 0 }
"#,
    )
    .expect_err("obsolete aliases must fail");

    assert_eq!(error.code.as_str(), "structural_validation");
}

#[test]
fn format_identity_is_rejected_before_schema_validation() {
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
}

#[test]
fn malformed_prior_state_precedes_fingerprint_mismatch() {
    let bundle = load_bundle(MINIMAL).expect("bundle loads");
    let mut state = create(
        &bundle,
        "turnstile",
        "turnstile-1",
        "create-1",
        &Bindings::default(),
    )
    .state
    .expect("creation returns state");
    state.root_instance_id.clear();
    let changed = load_bundle(&MINIMAL.replace("test.public_api", "test.changed"))
        .expect("changed bundle loads");

    let result = dispatch(&changed, &state, None);
    assert_eq!(
        result.rejection.as_ref().map(|value| value.code.as_str()),
        Some("invalid_prior_state")
    );
}

#[test]
fn examples_and_revision_metadata_are_current() {
    load_bundle(include_str!("../examples/minimal.yaml")).expect("minimal example loads");
    load_bundle(include_str!("../examples/full.yaml")).expect("full example loads");
    assert_eq!(
        FORMAT_1_SPECIFICATION_COMMIT,
        "03771fac569a47b82f27891cd3700d4d1d876f8b"
    );
    assert_eq!(
        FORMAT_1_CONFORMANCE_COMMIT,
        "409bbdc6c2d4a4e9d50ddb1d994c5f5cd7d97762"
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
            "determa-state 0.0.6\n"
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
