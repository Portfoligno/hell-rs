use std::sync::Arc;

use hell_builtins::BuiltinId;
use hell_testkit::{
    CoverageEvent, DifferentialCase, LogicalTraceEvent, ObligationTraceEvent, SemanticObservation,
    committed_differential_cases, reviewed_runtime_failure_causality_for_integration,
};

fn case(id: &str) -> DifferentialCase {
    committed_differential_cases()
        .into_iter()
        .find(|case| case.id.as_ref() == id)
        .unwrap_or_else(|| panic!("missing committed case {id}"))
}

fn builtin(name: &str) -> BuiltinId {
    hell_builtins::lookup(name)
        .unwrap_or_else(|| panic!("missing builtin {name}"))
        .id
}

fn force_boundary(
    builtin: BuiltinId,
    argument: u16,
    outcome: &str,
    error_code: Option<&str>,
) -> [LogicalTraceEvent; 2] {
    [
        LogicalTraceEvent::ForceBuiltinArgument { builtin, argument },
        LogicalTraceEvent::CompleteThunk {
            label: Arc::from("reviewed-boundary"),
            outcome: Arc::from(outcome),
            error_code: error_code.map(Arc::from),
        },
    ]
}

fn obligation(
    builtin: BuiltinId,
    sequence: u64,
    parent_sequence: Option<u64>,
    outcome: &str,
    nested_adapters: u64,
) -> ObligationTraceEvent {
    ObligationTraceEvent {
        builtin,
        instance_target: None,
        instance_premises: Vec::new(),
        owner_task: None,
        sequence,
        parent_sequence,
        outcome: Arc::from(outcome),
        nested_adapters,
        materialized_before: 0,
        materialized_after: 0,
        callbacks: Vec::new(),
        comparators: Vec::new(),
    }
}

fn failed_print_effect(print: BuiltinId) -> Vec<LogicalTraceEvent> {
    ["started", "failed"]
        .into_iter()
        .map(|effect| LogicalTraceEvent::HostEffect {
            builtin: print,
            owner_task: None,
            sequence: 1,
            parent_sequence: None,
            effect: Arc::from(effect),
        })
        .collect()
}

fn assert_take_failure_causality(case: &DifferentialCase, take_semantic: &SemanticObservation) {
    assert!(reviewed_runtime_failure_causality_for_integration(
        case,
        take_semantic,
    ));

    let mut severed = take_semantic.clone();
    severed.obligation_trace[1].parent_sequence = None;
    assert!(!reviewed_runtime_failure_causality_for_integration(
        case, &severed,
    ));

    let mut completed_print = take_semantic.clone();
    if let LogicalTraceEvent::HostEffect { effect, .. } = &mut completed_print.effect_trace[1] {
        *effect = Arc::from("completed");
    }
    assert!(!reviewed_runtime_failure_causality_for_integration(
        case,
        &completed_print,
    ));

    let mut missing_lazy_observation = take_semantic.clone();
    missing_lazy_observation.force_trace.truncate(2);
    assert!(!reviewed_runtime_failure_causality_for_integration(
        case,
        &missing_lazy_observation,
    ));

    let mut relabelled_lazy_observation = take_semantic.clone();
    if let LogicalTraceEvent::CompleteThunk { outcome, .. } =
        &mut relabelled_lazy_observation.force_trace[3]
    {
        *outcome = Arc::from("value");
    }
    assert!(!reviewed_runtime_failure_causality_for_integration(
        case,
        &relabelled_lazy_observation,
    ));
}

#[test]
fn exact_runtime_failure_causal_shapes_admit_only_the_reviewed_failures() {
    let singleton_case = case("runtime-typed-map-singleton-key-strict");
    let singleton = builtin("Map.singleton");
    let mut singleton_semantic = SemanticObservation {
        force_trace: force_boundary(singleton, 0, "error", Some("H0901"))
            .into_iter()
            .chain(force_boundary(singleton, 1, "not-forced", None))
            .collect(),
        ..SemanticObservation::default()
    };
    assert!(reviewed_runtime_failure_causality_for_integration(
        &singleton_case,
        &singleton_semantic,
    ));
    if let LogicalTraceEvent::CompleteThunk { error_code, .. } =
        &mut singleton_semantic.force_trace[1]
    {
        *error_code = Some(Arc::from("H0902"));
    }
    assert!(!reviewed_runtime_failure_causality_for_integration(
        &singleton_case,
        &singleton_semantic,
    ));

    let cycle_case = case("list-cycle-boundary-empty-input");
    let cycle = builtin("List.cycle");
    let expected_cycle_result = cycle_case
        .claim_evidence
        .as_ref()
        .and_then(|descriptor| {
            descriptor
                .semantic_targets
                .iter()
                .find(|target| target.builtin.as_ref() == "List.cycle")
        })
        .and_then(|target| target.expected_typed_result_sha256)
        .expect("List.cycle failure result digest");
    let mut cycle_semantic = SemanticObservation {
        typed_result_sha256: Some(expected_cycle_result),
        typed_result_builtin: Some(cycle),
        coverage: vec![CoverageEvent::EnteredAdapter(cycle)],
        force_trace: force_boundary(cycle, 0, "value", None).into(),
        ..SemanticObservation::default()
    };
    assert!(reviewed_runtime_failure_causality_for_integration(
        &cycle_case,
        &cycle_semantic,
    ));
    cycle_semantic.typed_result_sha256 = None;
    assert!(!reviewed_runtime_failure_causality_for_integration(
        &cycle_case,
        &cycle_semantic,
    ));

    let take = builtin("List.take");
    let error = builtin("Error.error");
    let print = builtin("IO.print");
    let take_semantic = SemanticObservation {
        force_trace: force_boundary(take, 0, "value", None)
            .into_iter()
            .chain(force_boundary(take, 1, "not-forced", None))
            .collect(),
        effect_trace: failed_print_effect(print),
        obligation_trace: vec![
            obligation(take, 1, None, "alias", 1),
            obligation(error, 2, Some(1), "error", 0),
        ],
        coverage: vec![
            CoverageEvent::EnteredAdapter(take),
            CoverageEvent::EnteredAdapter(error),
            CoverageEvent::EnteredAdapter(print),
        ],
        ..SemanticObservation::default()
    };
    for id in [
        "list-take-boundary-bottom-after-demanded-prefix",
        "runtime-interaction-list-laziness-error",
    ] {
        let case = case(id);
        assert_take_failure_causality(&case, &take_semantic);
    }
}

#[cfg(feature = "compat-tracing")]
#[test]
fn production_traces_satisfy_the_exact_runtime_failure_causality() {
    let directory = std::env::temp_dir().join(format!(
        "hell-runtime-failure-causality-{}",
        std::process::id()
    ));
    let _already_absent = std::fs::remove_dir_all(&directory);
    std::fs::create_dir(&directory).expect("create runtime-failure trace directory");
    for id in [
        "runtime-typed-map-singleton-key-strict",
        "list-cycle-boundary-empty-input",
        "list-take-boundary-bottom-after-demanded-prefix",
        "runtime-interaction-list-laziness-error",
    ] {
        let case = case(id);
        let program = hell_compiler::compile_source(
            &mut hell_compiler::CompilerSession::upstream(),
            case.id.to_string(),
            case.source.to_string(),
        )
        .unwrap_or_else(|error| panic!("{} did not compile: {error:?}", case.id));
        let trace = directory.join(format!("{}.json", case.id));
        let context = hell_runtime::RuntimeContext::new(Vec::new(), Vec::<u8>::new());
        let outcome = if id == "list-cycle-boundary-empty-input" {
            hell_runtime::run_main_with_semantic_trace_target(
                program,
                context,
                &trace,
                builtin("List.cycle"),
            )
        } else {
            hell_runtime::run_main_with_semantic_trace(program, context, &trace)
        };
        assert!(outcome.is_err(), "{} unexpectedly completed", case.id);
        let semantic = hell_testkit::parse_semantic_trace(
            &std::fs::read(&trace).expect("read runtime-failure semantic trace"),
        )
        .unwrap_or_else(|error| panic!("{} trace did not parse: {error}", case.id));
        assert!(
            reviewed_runtime_failure_causality_for_integration(&case, &semantic),
            "{} live semantic causality was rejected: {semantic:#?}",
            case.id,
        );
    }
    std::fs::remove_dir_all(directory).expect("remove runtime-failure trace directory");
}
