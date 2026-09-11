use determa_state::{
    create, decode_selected_migration_descriptor, dispatch, load_bundle, Bindings, Counter,
    CreationRejectionCode, Delivery, DispatchRejectionCode, Disposition, EngineFaultCode, Envelope,
    PersistenceErrorCode, ResultStatus, Target, Value, CREATION_REJECTION_CODES,
    DISPATCH_REJECTION_CODES, ENGINE_FAULT_CODES, FORMAT_1_CONFORMANCE_COMMIT,
    FORMAT_1_SPECIFICATION_COMMIT,
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

const NESTED_RUNTIME: &str = r#"
format: 1
namespace: test.nested_runtime
events:
  start: { direction: input }
  explode: { direction: input }
  cancel_parent: { direction: input }
  pulse: { direction: input }
  pong: { direction: internal }
machines:
  - machine_id: owner
    root:
      type: composite
      variables:
        parent_reference:
          type: instance_reference
          machine_id: parent
          nullable: true
          init: null
      initial: { transition_to: idle }
      states:
        idle:
          on_events:
            start:
              action:
                - spawn:
                    machine_id: parent
                    bind_to: parent_reference
            cancel_parent:
              action:
                - cancel: { instance: "parent_reference" }
            done:
              action:
                - cancel: { instance: "event.payload.instance" }
  - machine_id: parent
    root:
      type: composite
      variables:
        child_reference:
          type: instance_reference
          machine_id: child
          nullable: true
          init: null
        sibling_reference:
          type: instance_reference
          machine_id: child
          nullable: true
          init: null
        value: { type: int, init: 1 }
      entry:
        - spawn:
            machine_id: child
            bind_to: child_reference
        - spawn:
            machine_id: child
            bind_to: sibling_reference
      initial: { transition_to: running }
      states:
        running:
          on_events:
            explode:
              action:
                - assign: { value: "value / 0" }
            done:
              action:
                - cancel: { instance: "event.payload.instance" }
  - machine_id: child
    root:
      type: composite
      initial: { transition_to: running }
      states:
        running:
          on_events:
            pulse:
              action:
                - send:
                    event: pong
                    to: { owner: true }
            done:
              action:
                - cancel: { instance: "event.payload.instance" }
"#;

const OUTPUT_COUNTER: &str = r#"
format: 1
namespace: test.output_counter
events:
  begin:
    direction: input
    payload:
      request_id: { type: string, required: true }
  work_requested:
    direction: output
machines:
  - machine_id: output
    root:
      type: composite
      initial: { transition_to: ready }
      states:
        ready:
          on_events:
            begin:
              action:
                - send:
                    event: work_requested
                    to: { external: true }
                    correlation_id: "event.payload.request_id"
"#;

fn root_target(state: &determa_state::AggregateState) -> Target {
    Target::Root {
        root_instance_id: state.root_instance_id.clone(),
        root_runtime_id: state.root.runtime_id.clone(),
    }
}

fn spawned_done_payload(reference: &determa_state::InstanceReference) -> BTreeMap<String, Value> {
    BTreeMap::from([
        (
            "relationship".to_string(),
            Value::String("spawned_instance".to_string()),
        ),
        (
            "instance".to_string(),
            Value::InstanceReference(reference.clone()),
        ),
        (
            "instance_id".to_string(),
            Value::String(reference.instance_id.clone()),
        ),
        (
            "machine_id".to_string(),
            Value::String(reference.machine_id.clone()),
        ),
        (
            "machine_version".to_string(),
            Value::Int(reference.machine_version),
        ),
    ])
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
fn recursively_rejects_malformed_nested_runtime_state() {
    let bundle = load_bundle(NESTED_RUNTIME).expect("bundle loads");
    let created = create(
        &bundle,
        "owner",
        "nested-1",
        "create-nested-1",
        &Bindings::default(),
    );
    let initial = created.state.expect("creation returns state");
    let started = dispatch(
        &bundle,
        &initial,
        Some(Delivery::Input(Envelope {
            event: "start".to_string(),
            event_id: "start-1".to_string(),
            target: root_target(&initial),
            payload: BTreeMap::new(),
            correlation_id: None,
        })),
    )
    .state
    .expect("spawn returns state");
    let mut mutations = Vec::new();

    let mut runtime_id = started.clone();
    runtime_id.root.owned_instances[0].runtime.owned_instances[0]
        .runtime
        .runtime_id = "tampered".to_string();
    mutations.push(runtime_id);

    let mut relation = started.clone();
    if let determa_state::format1::RuntimeRelation::Spawned {
        owner_runtime_id, ..
    } = &mut relation.root.owned_instances[0].runtime.owned_instances[0]
        .runtime
        .relation
    {
        *owner_runtime_id = relation.root.runtime_id.clone();
    }
    mutations.push(relation);

    let mut activation = started.clone();
    activation.root.owned_instances[0]
        .runtime
        .active_state_activation_sequence
        .insert(
            "running".to_string(),
            Counter::from_decimal("18446744073709551616").unwrap(),
        );
    mutations.push(activation);

    let mut completed_root_with_descendants = started.clone();
    completed_root_with_descendants.root.status = determa_state::RuntimeStatus::Completed;
    completed_root_with_descendants.root.active.clear();
    completed_root_with_descendants.root.variables.clear();
    completed_root_with_descendants
        .root
        .active_state_activation_sequence
        .clear();
    mutations.push(completed_root_with_descendants);

    let mut completed_spawn_retained = started.clone();
    let completed = &mut completed_spawn_retained.root.owned_instances[0]
        .runtime
        .owned_instances[0]
        .runtime;
    completed.status = determa_state::RuntimeStatus::Completed;
    completed.active.clear();
    completed.variables.clear();
    completed.components.clear();
    completed.owned_instances.clear();
    completed.active_state_activation_sequence.clear();
    mutations.push(completed_spawn_retained);

    let parent_reference = started.root.owned_instances[0].reference.clone();
    let faulted = dispatch(
        &bundle,
        &started,
        Some(Delivery::Input(Envelope {
            event: "explode".to_string(),
            event_id: "fault-mutation-1".to_string(),
            target: Target::SpawnedInstance(parent_reference),
            payload: BTreeMap::new(),
            correlation_id: None,
        })),
    )
    .state
    .expect("fault returns state");
    for mutation in ["code", "locator", "sequence"] {
        let mut malformed = faulted.clone();
        let next_sequence = malformed.next_logical_step_sequence.clone();
        let fault = malformed.root.owned_instances[0]
            .runtime
            .fault
            .as_mut()
            .expect("parent has fault");
        match mutation {
            "code" => fault.code = "domain_failure".to_string(),
            "locator" => fault.source_locator = "system:not-a-fault-locator".to_string(),
            "sequence" => {
                fault.step_sequence = next_sequence;
            }
            _ => unreachable!(),
        }
        mutations.push(malformed);
    }

    for malformed in mutations {
        let result = dispatch(&bundle, &malformed, None);
        assert_eq!(
            result.rejection.as_ref().map(|value| value.code.as_str()),
            Some("invalid_prior_state")
        );
        assert_eq!(result.state.as_ref(), Some(&malformed));
        assert!(result.emissions.is_empty());
    }
}

#[test]
fn retained_faulted_subtree_blocks_ingress_but_owner_can_cancel_it() {
    let bundle = load_bundle(NESTED_RUNTIME).expect("bundle loads");
    let initial = create(
        &bundle,
        "owner",
        "nested-2",
        "create-nested-2",
        &Bindings::default(),
    )
    .state
    .expect("creation returns state");
    let spawned = dispatch(
        &bundle,
        &initial,
        Some(Delivery::Input(Envelope {
            event: "start".to_string(),
            event_id: "start-2".to_string(),
            target: root_target(&initial),
            payload: BTreeMap::new(),
            correlation_id: None,
        })),
    )
    .state
    .expect("spawn returns state");
    let parent_reference = match spawned.root.visible_variables()["parent_reference"].clone() {
        Value::InstanceReference(reference) => reference,
        value => panic!("unexpected parent reference {value:?}"),
    };
    let child_reference = spawned.root.owned_instances[0].runtime.owned_instances[0]
        .reference
        .clone();
    let child_pulse = dispatch(
        &bundle,
        &spawned,
        Some(Delivery::Input(Envelope {
            event: "pulse".to_string(),
            event_id: "pulse-before-fault-2".to_string(),
            target: Target::SpawnedInstance(child_reference),
            payload: BTreeMap::new(),
            correlation_id: None,
        })),
    );
    assert_eq!(
        child_pulse.emissions[0].target,
        Target::SpawnedInstance(parent_reference.clone())
    );
    let spawned = child_pulse.state.expect("child pulse returns state");
    let faulted = dispatch(
        &bundle,
        &spawned,
        Some(Delivery::Input(Envelope {
            event: "explode".to_string(),
            event_id: "explode-2".to_string(),
            target: Target::SpawnedInstance(parent_reference),
            payload: BTreeMap::new(),
            correlation_id: None,
        })),
    )
    .state
    .expect("fault returns state");
    assert_eq!(
        faulted.root.owned_instances[0].runtime.status,
        determa_state::RuntimeStatus::Faulted
    );
    let child_reference = faulted.root.owned_instances[0].runtime.owned_instances[0]
        .reference
        .clone();
    assert_eq!(
        faulted.root.owned_instances[0].runtime.owned_instances[0]
            .runtime
            .status,
        determa_state::RuntimeStatus::Running
    );

    let rejected = dispatch(
        &bundle,
        &faulted,
        Some(Delivery::Input(Envelope {
            event: "pulse".to_string(),
            event_id: "pulse-2".to_string(),
            target: Target::SpawnedInstance(child_reference),
            payload: BTreeMap::new(),
            correlation_id: None,
        })),
    );
    assert_eq!(
        rejected
            .rejection
            .as_ref()
            .map(|rejection| rejection.code.as_str()),
        Some("invalid_instance_target")
    );
    assert_eq!(rejected.state.as_ref(), Some(&faulted));

    let cancelled = dispatch(
        &bundle,
        &faulted,
        Some(Delivery::Input(Envelope {
            event: "cancel_parent".to_string(),
            event_id: "cancel-parent-2".to_string(),
            target: root_target(&faulted),
            payload: BTreeMap::new(),
            correlation_id: None,
        })),
    );
    assert_eq!(cancelled.status, ResultStatus::Running);
    assert!(cancelled
        .state
        .expect("cancel returns state")
        .root
        .owned_instances
        .is_empty());
}

#[test]
fn cancel_is_confined_to_the_executing_runtime_ownership_subtree() {
    let bundle = load_bundle(NESTED_RUNTIME).expect("bundle loads");
    let initial = create(
        &bundle,
        "owner",
        "ownership-1",
        "create-ownership-1",
        &Bindings::default(),
    )
    .state
    .expect("creation returns state");
    let spawned = dispatch(
        &bundle,
        &initial,
        Some(Delivery::Input(Envelope {
            event: "start".to_string(),
            event_id: "ownership-start-1".to_string(),
            target: root_target(&initial),
            payload: BTreeMap::new(),
            correlation_id: None,
        })),
    )
    .state
    .expect("spawn returns state");
    let parent = spawned.root.owned_instances[0].reference.clone();
    let child = spawned.root.owned_instances[0].runtime.owned_instances[0]
        .reference
        .clone();
    let sibling = spawned.root.owned_instances[0].runtime.owned_instances[1]
        .reference
        .clone();

    let sibling_noop = dispatch(
        &bundle,
        &spawned,
        Some(Delivery::Internal(Envelope {
            event: "done".to_string(),
            event_id: "cancel-sibling-1".to_string(),
            target: Target::SpawnedInstance(child.clone()),
            payload: spawned_done_payload(&sibling),
            correlation_id: None,
        })),
    );
    assert_eq!(sibling_noop.disposition, Some(Disposition::Handled));
    let after_sibling = sibling_noop.state.expect("sibling no-op returns state");
    assert_eq!(
        after_sibling.root.owned_instances[0]
            .runtime
            .owned_instances
            .len(),
        2
    );

    let ancestor_noop = dispatch(
        &bundle,
        &after_sibling,
        Some(Delivery::Internal(Envelope {
            event: "done".to_string(),
            event_id: "cancel-ancestor-1".to_string(),
            target: Target::SpawnedInstance(child.clone()),
            payload: spawned_done_payload(&parent),
            correlation_id: None,
        })),
    );
    assert_eq!(ancestor_noop.disposition, Some(Disposition::Handled));
    let after_ancestor = ancestor_noop.state.expect("ancestor no-op returns state");
    assert_eq!(
        after_ancestor.root.owned_instances[0]
            .runtime
            .owned_instances
            .len(),
        2
    );

    let transitive = dispatch(
        &bundle,
        &after_ancestor,
        Some(Delivery::Internal(Envelope {
            event: "done".to_string(),
            event_id: "cancel-transitive-1".to_string(),
            target: root_target(&after_ancestor),
            payload: spawned_done_payload(&child),
            correlation_id: None,
        })),
    );
    assert_eq!(transitive.disposition, Some(Disposition::Handled));
    let state = transitive.state.expect("transitive cancel returns state");
    assert_eq!(state.root.owned_instances.len(), 1);
    assert_eq!(
        state.root.owned_instances[0].runtime.owned_instances.len(),
        1
    );
    assert_eq!(
        state.root.owned_instances[0].runtime.owned_instances[0].reference,
        sibling
    );
}

#[test]
fn runtime_counter_allocations_continue_beyond_u64() {
    let bundle = load_bundle(OUTPUT_COUNTER).expect("bundle loads");
    let mut prior = create(
        &bundle,
        "output",
        "counter-1",
        "create-counter-1",
        &Bindings::default(),
    )
    .state
    .expect("creation returns state");
    prior.next_logical_step_sequence = Counter::from_decimal("18446744073709551616").unwrap();
    prior.next_output_sequence = Counter::from_decimal("18446744073709551616").unwrap();
    let result = dispatch(
        &bundle,
        &prior,
        Some(Delivery::Input(Envelope {
            event: "begin".to_string(),
            event_id: "begin-counter-1".to_string(),
            target: root_target(&prior),
            payload: BTreeMap::from([(
                "request_id".to_string(),
                Value::String("request-counter-1".to_string()),
            )]),
            correlation_id: None,
        })),
    );
    let state = result.state.expect("dispatch returns state");
    assert_eq!(
        state.next_logical_step_sequence,
        Counter::from_decimal("18446744073709551617").unwrap()
    );
    assert_eq!(
        state.next_output_sequence,
        Counter::from_decimal("18446744073709551617").unwrap()
    );
    assert_eq!(
        result.emissions[0].sequence,
        Some(Counter::from_decimal("18446744073709551616").unwrap())
    );

    let spawn_bundle = load_bundle(NESTED_RUNTIME).expect("spawn bundle loads");
    let mut spawn_prior = create(
        &spawn_bundle,
        "owner",
        "counter-2",
        "create-counter-2",
        &Bindings::default(),
    )
    .state
    .expect("creation returns state");
    spawn_prior.root.next_spawn_sequence = Counter::from_decimal("18446744073709551616").unwrap();
    let spawned = dispatch(
        &spawn_bundle,
        &spawn_prior,
        Some(Delivery::Input(Envelope {
            event: "start".to_string(),
            event_id: "start-counter-2".to_string(),
            target: root_target(&spawn_prior),
            payload: BTreeMap::new(),
            correlation_id: None,
        })),
    )
    .state
    .expect("spawn returns state");
    assert_eq!(
        spawned.root.owned_instances[0].spawn_sequence,
        Counter::from_decimal("18446744073709551616").unwrap()
    );
    assert_eq!(
        spawned.root.next_spawn_sequence,
        Counter::from_decimal("18446744073709551617").unwrap()
    );
}

#[test]
fn examples_and_revision_metadata_are_current() {
    load_bundle(include_str!("../examples/minimal.yaml")).expect("minimal example loads");
    load_bundle(include_str!("../examples/full.yaml")).expect("full example loads");
    assert_eq!(
        FORMAT_1_SPECIFICATION_COMMIT,
        "2e33036563cb966b07124197db672159b4b7e1f4"
    );
    assert_eq!(
        FORMAT_1_CONFORMANCE_COMMIT,
        "531468c59c7a2dc32f5cbe92cfabf89805d27f6a"
    );
}

#[test]
fn runtime_closed_code_exports_are_public_and_compatible() {
    assert_eq!(
        CreationRejectionCode::PORTABLE_CODES
            .iter()
            .map(|code| code.as_str())
            .collect::<Vec<_>>(),
        CREATION_REJECTION_CODES
    );
    assert_eq!(
        DispatchRejectionCode::PORTABLE_CODES
            .iter()
            .map(|code| code.as_str())
            .collect::<Vec<_>>(),
        DISPATCH_REJECTION_CODES
    );
    assert_eq!(
        EngineFaultCode::PORTABLE_CODES
            .iter()
            .map(|code| code.as_str())
            .collect::<Vec<_>>(),
        ENGINE_FAULT_CODES
    );
}

#[test]
fn selected_migration_descriptor_decoder_rejects_legacy_bytes() {
    let source = std::fs::read(
        "conformance-suite/conformance/core/113-migration-failure-completeness/legacy-0.0.6-snapshot.json",
    )
    .expect("legacy fixture is available");
    assert_eq!(
        decode_selected_migration_descriptor(&source)
            .expect_err("legacy descriptor must be rejected")
            .code,
        PersistenceErrorCode::UnsupportedMigrationDescriptorFormat,
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
