use hell_compiler::{CompilerSession, compile_source};
use hell_testkit::{committed_differential_cases, generated_typed_cases};

#[test]
fn character_collection_descriptors_bind_haskell_string_output_shapes() {
    let cases = committed_differential_cases();
    for (case_id, stdout) in [
        ("runtime-ord-list-list-sort-char-empty-input", "\"\"\n"),
        ("runtime-ord-list-list-sort-char-singleton-input", "\"a\"\n"),
        (
            "runtime-ord-list-list-sort-char-finite-input",
            "\"a\\946\\946\"\n",
        ),
        ("runtime-ord-list-list-nubord-char-empty-input", "\"\"\n"),
        (
            "runtime-ord-list-list-nubord-char-singleton-input",
            "\"a\"\n",
        ),
        (
            "runtime-ord-list-list-nubord-char-finite-input",
            "\"\\946a\"\n",
        ),
        ("runtime-ord-list-list-sorton-char-empty-input", "[]\n"),
        (
            "runtime-ord-list-list-sorton-char-singleton-input",
            "[('a',\"only\")]\n",
        ),
        (
            "runtime-ord-list-list-sorton-char-finite-input",
            "[('a',\"middle\"),('\\946',\"first\"),('\\946',\"last\")]\n",
        ),
        ("runtime-eq-list-group-char-empty-input", "[]\n"),
        (
            "runtime-eq-list-group-char-singleton-input",
            "[\"\\946\"]\n",
        ),
        (
            "runtime-eq-list-group-char-finite-input",
            "[\"\\946\\946\",\"a\",\"\\946\"]\n",
        ),
    ] {
        let case = cases
            .iter()
            .find(|case| case.id.as_ref() == case_id)
            .unwrap_or_else(|| panic!("missing reviewed character collection case {case_id}"));
        let expected = hell_testkit::raw_presentation_sha256(stdout.as_bytes(), b"");
        assert!(
            case.claim_evidence
                .as_ref()
                .expect("reviewed character collection descriptor")
                .semantic_targets
                .iter()
                .any(|target| target.expected_raw_presentation_sha256 == Some(expected)),
            "{case_id} raw output shape drifted from {stdout:?}",
        );
    }
}

#[test]
fn reviewed_haskell_string_literal_is_bound_to_pinned_escape_bytes() {
    for (code_points, expected) in [
        (Vec::new(), "\"\""),
        (vec![u32::from('"')], "\"\\\"\""),
        (vec![u32::from('\\')], "\"\\\\\""),
        (vec![0], "\"\\NUL\""),
        (vec![14, u32::from('H')], "\"\\SO\\&H\""),
        (vec![127], "\"\\DEL\""),
        (vec![946, u32::from('1')], "\"\\946\\&1\""),
    ] {
        assert_eq!(
            hell_testkit::reviewed_haskell_string_literal(&code_points).unwrap(),
            expected,
        );
    }
    assert!(hell_testkit::reviewed_haskell_string_literal(&[0xd800]).is_err());
}

#[test]
fn options_parser_short_functor_descriptors_bind_the_exact_oracle_stderr() {
    let expected = hell_testkit::raw_presentation_sha256(
        b"",
        b"Missing: --name ARG\n\nUsage: hell --name ARG\n",
    );
    let cases = committed_differential_cases();
    for case_id in [
        "runtime-typed-functor-fmap-parser-short",
        "runtime-typed-functor-operator-parser-short",
    ] {
        let case = cases
            .iter()
            .find(|case| case.id.as_ref() == case_id)
            .unwrap_or_else(|| panic!("missing reviewed Options.Parser short case {case_id}"));
        let target = &case
            .claim_evidence
            .as_ref()
            .expect("reviewed Options.Parser descriptor")
            .semantic_targets[0];
        assert_eq!(target.expected_raw_presentation_sha256, Some(expected));
        assert!(!case.expected_runtime_completion);
        assert!(case.arguments.is_empty());
    }
}

#[test]
fn options_parser_applicative_failures_bind_ordered_oracle_stderr() {
    let cases = committed_differential_cases();
    for (case_id, stderr) in [
        (
            "runtime-typed-applicative-apply-parser-absent",
            "Missing: --function ARG --value ARG\n\nUsage: hell --function ARG --value ARG\n",
        ),
        (
            "runtime-typed-applicative-apply-parser-consumed-missing",
            "Missing: --value ARG\n\nUsage: hell --function ARG --value ARG\n",
        ),
        (
            "runtime-typed-applicative-apply-flipped-parser-absent",
            "Missing: --value ARG --function ARG\n\nUsage: hell --value ARG --function ARG\n",
        ),
        (
            "runtime-typed-applicative-apply-flipped-parser-consumed-missing",
            "Missing: --function ARG\n\nUsage: hell --value ARG --function ARG\n",
        ),
    ] {
        let case = cases
            .iter()
            .find(|case| case.id.as_ref() == case_id)
            .unwrap_or_else(|| panic!("missing reviewed Options.Parser case {case_id}"));
        let target = &case.claim_evidence.as_ref().unwrap().semantic_targets[0];
        assert_eq!(
            target.expected_raw_presentation_sha256,
            Some(hell_testkit::raw_presentation_sha256(
                b"",
                stderr.as_bytes()
            )),
            "{case_id} diagnostic authority drifted"
        );
        assert!(!case.expected_runtime_completion);
    }
}

#[test]
fn committed_and_generated_differential_sources_compile() {
    let mut session = CompilerSession::upstream();
    for case in committed_differential_cases() {
        let result = compile_source(&mut session, case.id.to_string(), case.source.to_string());
        if case.id.strip_prefix("check-negative-").is_some() {
            assert!(result.is_err(), "{} unexpectedly compiled", case.id);
        } else {
            result.unwrap_or_else(|diagnostics| {
                let excerpts = diagnostics
                    .0
                    .iter()
                    .filter_map(|diagnostic| diagnostic.span)
                    .filter_map(|span| {
                        let start = usize::try_from(span.start).ok()?.saturating_sub(40);
                        let end = usize::try_from(span.end)
                            .ok()?
                            .saturating_add(40)
                            .min(case.source.len());
                        case.source.get(start..end)
                    })
                    .collect::<Vec<_>>();
                panic!(
                    "{} did not compile: {diagnostics:#?}; source excerpts: {excerpts:#?}",
                    case.id
                )
            });
        }
    }
    for case in generated_typed_cases(0x4845_4c4c_2026, 1_024) {
        compile_source(&mut session, case.id.to_string(), case.source.to_string())
            .unwrap_or_else(|diagnostics| panic!("{} did not compile: {diagnostics:#?}", case.id));
    }
}

#[test]
fn catalog_constrains_every_polymorphic_process_reference() {
    let cases = hell_testkit::committed_differential_cases();
    let catalog = cases
        .iter()
        .find(|case| case.id.as_ref() == "public-builtin-catalog-reachability")
        .expect("public builtin catalog case");
    let references = [
        "Process.setStdout Process.nullStream $ Process.proc \"catalog\" []",
        "Process.proc \"catalog\" []",
        "Process.runProcess $ Process.proc \"catalog\" []",
        "Process.runProcess_ $ Process.proc \"catalog\" []",
        "Process.setEnv [] $ Process.proc \"catalog\" []",
        "Process.setStderr Process.nullStream $ Process.proc \"catalog\" []",
        "Process.setStdin Process.nullStream $ Process.proc \"catalog\" []",
        "Process.setWorkingDir \".\" $ Process.proc \"catalog\" []",
        "Process.setStdout (Process.useHandleClose IO.stdout) $ Process.proc \"catalog\" []",
        "Process.setStdout (Process.useHandleOpen IO.stdout) $ Process.proc \"catalog\" []",
    ];
    for reference in references {
        assert!(
            catalog
                .source
                .lines()
                .any(|line| line.ends_with(&format!(" = {reference}"))),
            "catalog lacks constrained Process reference: {reference}"
        );
    }
    let process_builtin_count = hell_builtins::registry()
        .iter()
        .filter(|spec| spec.name.starts_with("Process."))
        .count();
    let constrained_probe_count = catalog
        .source
        .lines()
        .filter_map(|line| line.split_once(" = ").map(|(_, reference)| reference))
        .filter(|reference| references.contains(reference))
        .count();
    assert_eq!(process_builtin_count, 11);
    assert_eq!(constrained_probe_count, process_builtin_count);
}

#[cfg(feature = "compat-tracing")]
#[test]
fn catalog_reachability_is_observed_by_the_real_compiler() {
    let case = committed_differential_cases()
        .into_iter()
        .find(|case| case.id.as_ref() == "public-builtin-catalog-reachability")
        .expect("catalog reachability case");
    let program = compile_source(
        &mut CompilerSession::upstream(),
        case.id.to_string(),
        case.source.to_string(),
    )
    .expect("catalog reachability source compiles");
    let expected = hell_builtins::registry()
        .iter()
        .map(|spec| spec.id)
        .collect::<Vec<_>>();
    let evidence = program.executable().compiler_evidence();
    let observed = evidence
        .resolved
        .iter()
        .copied()
        .collect::<std::collections::HashSet<_>>();
    let missing = hell_builtins::registry()
        .iter()
        .filter(|spec| !observed.contains(&spec.id))
        .map(|spec| spec.name)
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "unresolved catalog builtins: {missing:?}"
    );
    assert_eq!(evidence.parsed, expected);
    assert_eq!(evidence.resolved, expected);
}

#[cfg(feature = "compat-tracing")]
#[test]
fn collection_case_proves_only_its_declared_non_callback_obligations() {
    let case = committed_differential_cases()
        .into_iter()
        .find(|case| case.id.as_ref() == "runtime-collections-obligation-closure")
        .expect("collection obligation case");
    let program = compile_source(
        &mut CompilerSession::upstream(),
        case.id.to_string(),
        case.source.to_string(),
    )
    .expect("collection obligation source compiles");
    let directory = std::env::temp_dir().join(format!(
        "hell-runtime-obligations-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("collection")
    ));
    let _already_absent = std::fs::remove_dir_all(&directory);
    std::fs::create_dir(&directory).expect("create obligation trace directory");
    let trace_path = directory.join("semantic-trace.json");
    hell_runtime::run_main_with_semantic_trace(
        program,
        hell_runtime::RuntimeContext::new(Vec::new(), Vec::<u8>::new()),
        &trace_path,
    )
    .expect("collection obligation source runs");
    let trace = std::fs::read_to_string(&trace_path).expect("read obligation trace");
    let descriptor = case.claim_evidence.as_ref().expect("collection descriptor");
    assert!(descriptor.semantic_targets.iter().all(|target| {
        target
            .obligations
            .iter()
            .all(|obligation| !matches!(obligation.0.as_ref(), "callback-order" | "typed-result"))
    }));
    hell_testkit::validate_runtime_obligation_trace(&trace, &case)
        .expect("collection trace satisfies only the exact declared obligations");
    std::fs::remove_dir_all(directory).expect("remove obligation trace directory");
}

#[cfg(feature = "compat-tracing")]
#[test]
fn core_data_obligation_cases_run_with_target_scoped_traces() {
    let mut cases = committed_differential_cases()
        .into_iter()
        .filter(|case| {
            case.id.starts_with("runtime-typed-")
                || matches!(
                    case.id.as_ref(),
                    "runtime-core-data-obligation-closure"
                        | "runtime-functional-data-obligation-closure"
                )
        })
        .collect::<Vec<_>>();
    assert!(
        cases
            .iter()
            .any(|case| case.id.starts_with("runtime-typed-"))
    );
    let directory =
        std::env::temp_dir().join(format!("hell-core-data-obligations-{}", std::process::id()));
    let _already_absent = std::fs::remove_dir_all(&directory);
    std::fs::create_dir(&directory).expect("create core data trace directory");
    let helper = std::path::Path::new(env!("CARGO_BIN_EXE_hell-test-helper"));
    hell_testkit::bind_process_helper_directory(
        &mut cases,
        helper.parent().expect("test helper has a parent directory"),
    )
    .expect("bind process helper for typed corpus");
    for case in cases {
        let program = compile_source(
            &mut CompilerSession::upstream(),
            case.id.to_string(),
            case.source.to_string(),
        )
        .expect("core data obligation source compiles");
        let case_directory = directory.join(case.id.as_ref());
        std::fs::create_dir(&case_directory).expect("create per-case runtime sandbox");
        let trace_path = case_directory.join("semantic-trace.json");
        let typed_targets = case
            .claim_evidence
            .iter()
            .flat_map(|descriptor| &descriptor.semantic_targets)
            .filter(|target| {
                target
                    .obligations
                    .iter()
                    .any(|obligation| obligation.0.as_ref() == "typed-result")
            })
            .map(|target| {
                (
                    hell_builtins::lookup(&target.builtin).unwrap().id,
                    target.expected_instance_target.clone(),
                )
            })
            .collect::<Vec<_>>();
        let context = typed_case_runtime_context(&case, &case_directory);
        let outcome = match typed_targets.as_slice() {
            [] => hell_runtime::run_main_with_semantic_trace(program, context, &trace_path),
            [(target, Some(instance))] => {
                hell_runtime::run_main_with_semantic_trace_target_instance(
                    program,
                    context,
                    &trace_path,
                    *target,
                    instance.clone(),
                )
            }
            [(target, None)] => hell_runtime::run_main_with_semantic_trace_target(
                program,
                context,
                &trace_path,
                *target,
            ),
            _ => panic!("{} has multiple typed targets", case.id),
        };
        assert_eq!(
            outcome.is_ok(),
            case.expected_runtime_completion,
            "{} returned the wrong reviewed runtime outcome: {outcome:?}",
            case.id
        );
        let trace = std::fs::read_to_string(&trace_path).unwrap_or_else(|error| {
            panic!(
                "{} did not retain a core data trace after {outcome:?}: {error}",
                case.id
            )
        });
        hell_testkit::validate_runtime_obligation_trace(&trace, &case)
            .unwrap_or_else(|error| panic!("{} trace was incomplete: {error}", case.id));
    }
    std::fs::remove_dir_all(directory).expect("remove core data trace directory");
}

#[cfg(feature = "compat-tracing")]
#[test]
fn singleton_whnf_failures_are_pre_adapter_and_mutation_closed() {
    use hell_testkit::{CoverageEvent, LogicalTraceEvent};

    let cases = committed_differential_cases();
    let directory = std::env::temp_dir().join(format!(
        "hell-singleton-whnf-failures-{}",
        std::process::id()
    ));
    let _already_absent = std::fs::remove_dir_all(&directory);
    std::fs::create_dir(&directory).expect("create singleton WHNF trace directory");
    for (case_id, builtin_name, lazy_value) in [
        (
            "runtime-typed-map-singleton-key-strict",
            "Map.singleton",
            true,
        ),
        (
            "runtime-typed-set-singleton-element-strict",
            "Set.singleton",
            false,
        ),
    ] {
        let case = cases
            .iter()
            .find(|case| case.id.as_ref() == case_id)
            .unwrap_or_else(|| panic!("missing strict singleton case {case_id}"));
        assert_singleton_force_only_target(case);

        let program = compile_source(
            &mut CompilerSession::upstream(),
            case.id.to_string(),
            case.source.to_string(),
        )
        .unwrap_or_else(|error| panic!("{case_id} did not compile: {error:?}"));
        let case_directory = directory.join(case_id);
        std::fs::create_dir(&case_directory).expect("create strict singleton case directory");
        let trace_path = case_directory.join("semantic-trace.json");
        let error = hell_runtime::run_main_with_semantic_trace(
            program,
            typed_case_runtime_context(case, &case_directory),
            &trace_path,
        )
        .expect_err("demanded singleton bottom must fail");
        assert_eq!(error.code, "H0901");
        let trace = std::fs::read_to_string(&trace_path).expect("read strict singleton trace");
        hell_testkit::validate_runtime_obligation_trace(&trace, case)
            .unwrap_or_else(|error| panic!("{case_id} trace was incomplete: {error}"));
        let semantic = hell_testkit::parse_semantic_trace(trace.as_bytes())
            .unwrap_or_else(|error| panic!("{case_id} trace was malformed: {error}"));
        let builtin = hell_builtins::lookup(builtin_name).unwrap().id;
        assert!(
            !semantic
                .coverage
                .contains(&CoverageEvent::EnteredAdapter(builtin))
        );
        assert!(
            semantic
                .obligation_trace
                .iter()
                .all(|event| event.builtin != builtin)
        );
        let boundaries = semantic
            .force_trace
            .chunks_exact(2)
            .filter_map(|events| match events {
                [
                    LogicalTraceEvent::ForceBuiltinArgument {
                        builtin: observed,
                        argument,
                    },
                    LogicalTraceEvent::CompleteThunk {
                        label,
                        outcome,
                        error_code,
                    },
                ] if *observed == builtin => Some((
                    *argument,
                    label.as_ref(),
                    outcome.as_ref(),
                    error_code.as_deref(),
                )),
                _ => None,
            })
            .collect::<Vec<_>>();
        let expected = if lazy_value {
            vec![
                (0, "whnf-force-failed", "error", Some("H0901")),
                (1, "lazy-adapter-entry", "not-forced", None),
                (1, "lazy-adapter-exit", "not-forced", None),
            ]
        } else {
            vec![(0, "whnf-force-failed", "error", Some("H0901"))]
        };
        assert_eq!(boundaries, expected, "{case_id} force boundary trace");
        assert_singleton_whnf_trace_mutants(case, &trace, lazy_value);
    }
    std::fs::remove_dir_all(directory).expect("remove singleton WHNF trace directory");
}

#[cfg(feature = "compat-tracing")]
fn assert_singleton_force_only_target(case: &hell_testkit::DifferentialCase) {
    let target = case
        .claim_evidence
        .as_ref()
        .unwrap()
        .semantic_targets
        .first()
        .expect("strict singleton target");
    assert_eq!(target.causal_signal, hell_testkit::CausalSignal::ForceTrace);
    assert!(target.expected_whnf_argument_failure_sha256.is_some());
    assert!(target.expected_instance_target.is_none());
    assert!(target.expected_instance_premises.is_empty());
    assert!(target.expected_comparator_trace_sha256.is_none());
    assert!(target.expected_typed_result_sha256.is_none());
}

#[cfg(feature = "compat-tracing")]
fn assert_singleton_whnf_trace_mutants(
    case: &hell_testkit::DifferentialCase,
    trace: &str,
    lazy_value: bool,
) {
    let failed = forced_argument_object(trace, "whnf-force-failed");
    let without_failed = if trace.contains(&format!("{failed}, ")) {
        trace.replacen(&format!("{failed}, "), "", 1)
    } else {
        trace.replacen(&format!(", {failed}"), "", 1)
    };
    assert!(hell_testkit::validate_runtime_obligation_trace(&without_failed, case).is_err());
    for (from, to) in [
        (
            "\"argument\": 0, \"boundaryClass\": \"whnf-force-failed\"",
            "\"argument\": 1, \"boundaryClass\": \"whnf-force-failed\"",
        ),
        ("whnf-force-failed", "whnf-force-complete"),
        (
            "\"outcome\": \"error\", \"errorCode\": \"H0901\"",
            "\"outcome\": \"value\", \"errorCode\": \"H0901\"",
        ),
        ("\"errorCode\": \"H0901\"", "\"errorCode\": \"H0902\""),
    ] {
        assert!(trace.contains(from), "{} mutation precondition", case.id);
        let changed = trace.replacen(from, to, 1);
        assert!(hell_testkit::validate_runtime_obligation_trace(&changed, case).is_err());
    }
    let extra = trace.replacen(&failed, &format!("{failed}, {failed}"), 1);
    assert!(hell_testkit::validate_runtime_obligation_trace(&extra, case).is_err());
    if lazy_value {
        let lazy = forced_argument_object(trace, "lazy-adapter-entry");
        let reordered = trace
            .replacen(&failed, "__WHNF_FAILURE__", 1)
            .replacen(&lazy, &failed, 1)
            .replacen("__WHNF_FAILURE__", &lazy, 1);
        assert!(hell_testkit::validate_runtime_obligation_trace(&reordered, case).is_err());
        let forced_value = trace.replacen(
            "\"boundaryClass\": \"lazy-adapter-exit\", \"outcome\": \"not-forced\"",
            "\"boundaryClass\": \"lazy-adapter-exit\", \"outcome\": \"value\"",
            1,
        );
        assert_ne!(forced_value, trace);
        assert!(hell_testkit::validate_runtime_obligation_trace(&forced_value, case).is_err());
    }
}

#[cfg(feature = "compat-tracing")]
fn forced_argument_object(trace: &str, boundary: &str) -> String {
    let needle = format!("\"boundaryClass\": \"{boundary}\"");
    let position = trace
        .find(&needle)
        .unwrap_or_else(|| panic!("missing forced boundary {boundary}"));
    let start = trace[..position]
        .rfind('{')
        .expect("forced boundary object starts");
    let end = position
        + trace[position..]
            .find('}')
            .expect("forced boundary object ends")
        + 1;
    trace[start..end].to_owned()
}

#[cfg(feature = "compat-tracing")]
#[test]
fn nonproductive_many_cases_bind_lazy_origin_and_timeout_cancellation() {
    let cases = committed_differential_cases();
    let directory = std::env::temp_dir().join(format!(
        "hell-nonproductive-many-traces-{}",
        std::process::id()
    ));
    let _already_absent = std::fs::remove_dir_all(&directory);
    std::fs::create_dir(&directory).expect("create nonproductive trace directory");
    for (case_id, instance, origin_boundary) in [
        (
            "runtime-typed-alternative-many-maybe-nonproductive",
            "Maybe",
            "nonproductive-repeat",
        ),
        (
            "runtime-typed-alternative-many-parser-nonproductive",
            "Options.Parser",
            "nonproductive-parser-node",
        ),
    ] {
        let case = cases
            .iter()
            .find(|case| case.id.as_ref() == case_id)
            .unwrap_or_else(|| panic!("missing nonproductive case {case_id}"));
        let case_directory = directory.join(case_id);
        std::fs::create_dir(&case_directory).expect("create nonproductive case directory");
        verify_nonproductive_many_case(case, &case_directory, instance, origin_boundary);
    }
    std::fs::remove_dir_all(directory).expect("remove nonproductive trace directory");
}

#[cfg(feature = "compat-tracing")]
fn verify_nonproductive_many_case(
    case: &hell_testkit::DifferentialCase,
    directory: &std::path::Path,
    instance: &str,
    origin_boundary: &str,
) {
    let trace = run_canonical_nonproductive_trace(case, directory);
    let semantic = hell_testkit::parse_semantic_trace(&trace)
        .unwrap_or_else(|error| panic!("{} trace was invalid: {error}", case.id));
    let trace_text = std::str::from_utf8(&trace).unwrap();
    hell_testkit::validate_runtime_obligation_trace(trace_text, case)
        .unwrap_or_else(|error| panic!("{} descriptor rejected its trace: {error}", case.id));
    let task = assert_nonproductive_task_and_effects(case, &semantic, instance);
    assert_nonproductive_origin(case, &semantic, instance, origin_boundary, task);
    assert_nonproductive_descriptor_mutations(case, trace_text, instance);
    assert_nonproductive_trace_mutations(case, trace_text, origin_boundary);
}

#[cfg(feature = "compat-tracing")]
fn run_canonical_nonproductive_trace(
    case: &hell_testkit::DifferentialCase,
    directory: &std::path::Path,
) -> Vec<u8> {
    let run = |name: &str| {
        let program = compile_source(
            &mut CompilerSession::upstream(),
            case.id.to_string(),
            case.source.to_string(),
        )
        .unwrap_or_else(|error| panic!("{} did not compile: {error:?}", case.id));
        let trace_path = directory.join(name);
        hell_runtime::run_main_with_semantic_trace(
            program,
            typed_case_runtime_context(case, directory),
            &trace_path,
        )
        .unwrap_or_else(|error| panic!("{} did not complete: {error:?}", case.id));
        std::fs::read(trace_path).expect("read nonproductive semantic trace")
    };
    let trace = run("semantic-trace.json");
    let repeated = run("semantic-trace-repeat.json");
    assert_eq!(
        trace, repeated,
        "{} semantic trace is not canonical across timeout task runs",
        case.id
    );
    trace
}

#[cfg(feature = "compat-tracing")]
fn assert_nonproductive_task_and_effects(
    case: &hell_testkit::DifferentialCase,
    semantic: &hell_testkit::SemanticObservation,
    instance: &str,
) -> u64 {
    use hell_testkit::LogicalTraceEvent;

    let timeout = hell_builtins::lookup("Timeout.timeout").unwrap().id;
    let exec_parser = hell_builtins::lookup("Options.execParser").unwrap().id;
    let timeout_tasks = semantic
        .task_trace
        .iter()
        .filter_map(|event| match event {
            LogicalTraceEvent::TaskEvent {
                task,
                builtin,
                event,
            } if *builtin == timeout => Some((*task, event.as_ref())),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(timeout_tasks.len(), 2, "{} task count", case.id);
    assert_eq!(
        timeout_tasks[0].0, timeout_tasks[1].0,
        "{} task id",
        case.id
    );
    assert_eq!(
        timeout_tasks
            .iter()
            .map(|(_, event)| *event)
            .collect::<Vec<_>>(),
        ["started", "cancelled"],
        "{} timeout lifecycle",
        case.id
    );
    let task = timeout_tasks[0].0;
    let lifecycle = |builtin| {
        semantic
            .effect_trace
            .iter()
            .filter_map(|event| match event {
                LogicalTraceEvent::HostEffect {
                    builtin: observed,
                    owner_task,
                    effect,
                    ..
                } if *observed == builtin => Some((*owner_task, effect.as_ref())),
                _ => None,
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(
        lifecycle(timeout),
        [(None, "started"), (None, "completed")],
        "{} outer timeout effect",
        case.id
    );
    if instance == "Options.Parser" {
        assert_eq!(
            lifecycle(exec_parser),
            [(Some(task), "started"), (Some(task), "cancelled")],
            "{} parser cancellation effect",
            case.id
        );
    }
    task
}

#[cfg(feature = "compat-tracing")]
fn assert_nonproductive_origin(
    case: &hell_testkit::DifferentialCase,
    semantic: &hell_testkit::SemanticObservation,
    instance: &str,
    origin_boundary: &str,
    task: u64,
) {
    use hell_testkit::LogicalTraceEvent;

    let alternative = hell_builtins::lookup("Alternative.many").unwrap().id;
    let traversal = hell_builtins::lookup("Monad.forM_").unwrap().id;
    let alternative_event = semantic
        .obligation_trace
        .iter()
        .find(|event| {
            event.builtin == alternative
                && event.instance_target.as_deref() == Some(instance)
                && event.owner_task == Some(task)
        })
        .unwrap_or_else(|| panic!("{} lacks instance-scoped Alternative.many", case.id));
    assert_eq!(alternative_event.outcome.as_ref(), "value");
    if instance == "Maybe" {
        let traversal_event = semantic
            .obligation_trace
            .iter()
            .find(|event| {
                event.builtin == traversal
                    && event.instance_target.as_deref() == Some("IO")
                    && event.owner_task == Some(task)
            })
            .expect("Maybe case lacks IO traversal evidence");
        assert_eq!(traversal_event.outcome.as_ref(), "error");
        assert!(alternative_event.sequence < traversal_event.sequence);
    }
    let boundaries = semantic
        .force_trace
        .chunks_exact(2)
        .filter_map(|events| match events {
            [
                LogicalTraceEvent::ForceBuiltinArgument { builtin, argument },
                LogicalTraceEvent::CompleteThunk { label, .. },
            ] if *builtin == alternative
                && *argument == 0
                && label.starts_with("nonproductive-") =>
            {
                Some(label.as_ref())
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        boundaries,
        [
            origin_boundary,
            "nonproductive-pending",
            "nonproductive-cancelled"
        ],
        "{} nonproductive lifecycle",
        case.id
    );
    assert!(
        semantic.resource_trace.is_empty(),
        "{} leaked resources",
        case.id
    );
}

#[cfg(feature = "compat-tracing")]
fn assert_nonproductive_descriptor_mutations(
    case: &hell_testkit::DifferentialCase,
    trace: &str,
    instance: &str,
) {
    let mut wrong_digest = case.clone();
    let target = wrong_digest
        .claim_evidence
        .as_mut()
        .unwrap()
        .semantic_targets
        .iter_mut()
        .find(|target| target.builtin.as_ref() == "Alternative.many")
        .unwrap();
    target.expected_nonproductive_trace_sha256 =
        Some(hell_testkit::sha256_bytes(b"wrong nonproductive trace"));
    assert!(hell_testkit::validate_runtime_obligation_trace(trace, &wrong_digest).is_err());

    let mut wrong_instance = case.clone();
    let target = wrong_instance
        .claim_evidence
        .as_mut()
        .unwrap()
        .semantic_targets
        .iter_mut()
        .find(|target| target.builtin.as_ref() == "Alternative.many")
        .unwrap();
    target.expected_instance_target = Some(if instance == "Maybe" {
        "Options.Parser".into()
    } else {
        "Maybe".into()
    });
    assert!(hell_testkit::validate_runtime_obligation_trace(trace, &wrong_instance).is_err());
}

#[cfg(feature = "compat-tracing")]
fn assert_nonproductive_trace_mutations(
    case: &hell_testkit::DifferentialCase,
    trace: &str,
    origin_boundary: &str,
) {
    for (from, to) in [
        ("nonproductive-pending", origin_boundary),
        ("nonproductive-cancelled", "nonproductive-pending"),
        (
            "\"boundaryClass\": \"nonproductive-pending\", \"outcome\": \"value\"",
            "\"boundaryClass\": \"nonproductive-pending\", \"outcome\": \"not-forced\"",
        ),
    ] {
        assert!(trace.contains(from), "{} mutation precondition", case.id);
        let mutated = trace.replacen(from, to, 1);
        assert_ne!(mutated, trace, "{} mutation changed no bytes", case.id);
        assert!(hell_testkit::validate_runtime_obligation_trace(&mutated, case).is_err());
    }
    let reordered = trace
        .replacen("nonproductive-pending", "nonproductive-placeholder", 1)
        .replacen("nonproductive-cancelled", "nonproductive-pending", 1)
        .replacen("nonproductive-placeholder", "nonproductive-cancelled", 1);
    assert!(hell_testkit::validate_runtime_obligation_trace(&reordered, case).is_err());
    let pending = trace
        .find("\"boundaryClass\": \"nonproductive-pending\"")
        .expect("pending boundary exists");
    let start = trace[..pending].rfind('{').expect("pending object starts");
    let end = pending + trace[pending..].find('}').expect("pending object ends") + 1;
    let object = &trace[start..end];
    let extra = trace.replacen(object, &format!("{object}, {object}"), 1);
    assert_ne!(extra, trace);
    assert!(hell_testkit::validate_runtime_obligation_trace(&extra, case).is_err());
}

#[cfg(feature = "compat-tracing")]
#[test]
fn recursive_ord_set_equal_trace_selects_the_reviewed_instance() {
    let case = committed_differential_cases()
        .into_iter()
        .find(|case| case.id.as_ref() == "runtime-typed-ord-lt-set-equal")
        .expect("reviewed recursive Ord Set case");
    let program = compile_source(
        &mut CompilerSession::upstream(),
        case.id.to_string(),
        case.source.to_string(),
    )
    .expect("recursive Ord Set source compiles");
    let directory = std::env::temp_dir().join(format!(
        "hell-ord-set-instance-trace-{}",
        std::process::id()
    ));
    let _already_absent = std::fs::remove_dir_all(&directory);
    std::fs::create_dir(&directory).expect("create recursive Ord trace directory");
    let trace_path = directory.join("semantic-trace.json");
    hell_runtime::run_main_with_semantic_trace_target_instance(
        program,
        hell_runtime::RuntimeContext::new(Vec::new(), Vec::<u8>::new()),
        &trace_path,
        hell_builtins::lookup("Ord.lt").unwrap().id,
        "Set".into(),
    )
    .expect("instance-scoped recursive Ord trace runs");
    let trace = std::fs::read_to_string(&trace_path).expect("read recursive Ord trace");
    hell_testkit::validate_runtime_obligation_trace(&trace, &case)
        .expect("recursive Ord trace satisfies its reviewed descriptor");
    std::fs::remove_dir_all(directory).expect("remove recursive Ord trace directory");
}

#[cfg(feature = "compat-tracing")]
fn typed_case_runtime_context(
    case: &hell_testkit::DifferentialCase,
    sandbox: &std::path::Path,
) -> hell_runtime::RuntimeContext {
    let arguments = if case.environment_profile == hell_testkit::EnvironmentProfile::ProcessCapable
    {
        let helper = case
            .process_helper_directory
            .as_ref()
            .expect("process-capable typed case has a helper directory")
            .join(format!("hell-test-helper{}", std::env::consts::EXE_SUFFIX));
        vec![std::sync::Arc::<str>::from(
            helper.to_str().expect("helper path is UTF-8"),
        )]
    } else {
        case.arguments
            .iter()
            .map(|argument| {
                std::sync::Arc::<str>::from(argument.to_str().expect("committed argument is UTF-8"))
            })
            .collect()
    };
    let environment = case
        .environment
        .iter()
        .map(|(name, value)| {
            (
                std::sync::Arc::<str>::from(
                    name.to_str().expect("committed environment name is UTF-8"),
                ),
                std::sync::Arc::<str>::from(
                    value
                        .to_str()
                        .expect("committed environment value is UTF-8"),
                ),
            )
        })
        .collect();
    hell_runtime::RuntimeContext::with_host_capabilities(
        arguments,
        environment,
        Vec::<u8>::new(),
        sandbox.to_path_buf(),
        true,
        true,
    )
    .with_stdin(std::io::Cursor::new(case.stdin.clone()))
}

#[cfg(feature = "compat-tracing")]
#[test]
fn list_take_boundary_classes_execute_with_target_scoped_traces() {
    let cases = committed_differential_cases()
        .into_iter()
        .filter(|case| case.id.starts_with("list-take-boundary-"))
        .collect::<Vec<_>>();
    assert_eq!(cases.len(), 8);
    let directory =
        std::env::temp_dir().join(format!("hell-list-take-boundaries-{}", std::process::id()));
    let _already_absent = std::fs::remove_dir_all(&directory);
    std::fs::create_dir(&directory).expect("create boundary trace directory");
    for case in cases {
        let program = compile_source(
            &mut CompilerSession::upstream(),
            case.id.to_string(),
            case.source.to_string(),
        )
        .expect("List.take boundary source compiles");
        let trace_path = directory.join(format!("{}.json", case.id));
        let outcome = hell_runtime::run_main_with_semantic_trace(
            program,
            hell_runtime::RuntimeContext::new(Vec::new(), Vec::<u8>::new()),
            &trace_path,
        );
        if case.id.ends_with("bottom-after-demanded-prefix") {
            assert!(
                outcome.is_err(),
                "{} must force the retained bottom",
                case.id
            );
        } else {
            outcome.unwrap_or_else(|error| panic!("{} did not run: {error}", case.id));
        }
        let trace = std::fs::read_to_string(&trace_path).expect("read boundary trace");
        hell_testkit::validate_runtime_obligation_trace(&trace, &case)
            .unwrap_or_else(|error| panic!("{} trace was incomplete: {error}", case.id));
    }
    std::fs::remove_dir_all(directory).expect("remove boundary trace directory");
}

#[cfg(feature = "compat-tracing")]
#[test]
fn committed_runtime_interactions_execute_every_declared_participant() {
    let cases = committed_differential_cases()
        .into_iter()
        .filter(|case| case.id.starts_with("runtime-interaction-"))
        .collect::<Vec<_>>();
    assert!(!cases.is_empty());
    let directory =
        std::env::temp_dir().join(format!("hell-runtime-interactions-{}", std::process::id()));
    let _already_absent = std::fs::remove_dir_all(&directory);
    std::fs::create_dir(&directory).expect("create interaction trace directory");
    for case in cases {
        let program = compile_source(
            &mut CompilerSession::upstream(),
            case.id.to_string(),
            case.source.to_string(),
        )
        .expect("runtime interaction source compiles");
        let trace_path = directory.join(format!("{}.json", case.id));
        let arguments =
            if case.environment_profile == hell_testkit::EnvironmentProfile::ProcessCapable {
                vec![std::sync::Arc::<str>::from(env!(
                    "CARGO_BIN_EXE_hell-test-helper"
                ))]
            } else {
                case.arguments
                    .iter()
                    .map(|argument| {
                        std::sync::Arc::<str>::from(
                            argument.to_str().expect("committed argument is UTF-8"),
                        )
                    })
                    .collect()
            };
        let context =
            if case.environment_profile == hell_testkit::EnvironmentProfile::ProcessCapable {
                hell_runtime::RuntimeContext::with_host_capabilities(
                    arguments,
                    Vec::new(),
                    Vec::<u8>::new(),
                    directory.clone(),
                    true,
                    true,
                )
            } else {
                hell_runtime::RuntimeContext::new(arguments, Vec::<u8>::new())
            };
        let outcome = hell_runtime::run_main_with_semantic_trace(program, context, &trace_path);
        if case.id.ends_with("list-laziness-error") {
            assert!(
                outcome.is_err(),
                "{} must force the interaction bottom",
                case.id
            );
        } else {
            outcome.unwrap_or_else(|error| panic!("{} did not run: {error}", case.id));
        }
        let trace = std::fs::read_to_string(&trace_path).expect("read interaction trace");
        hell_testkit::validate_runtime_obligation_trace(&trace, &case)
            .unwrap_or_else(|error| panic!("{} trace was incomplete: {error}", case.id));
    }
    std::fs::remove_dir_all(directory).expect("remove interaction trace directory");
}

#[cfg(feature = "compat-tracing")]
#[test]
fn actual_composite_typed_result_round_trips_and_binds_element_order() {
    let source = "main = IO.print $ Bool.bool (1,2) (3,4) Bool.True\n";
    let program = compile_source(
        &mut CompilerSession::upstream(),
        "composite-typed-result",
        source,
    )
    .expect("composite typed result compiles");
    let directory = std::env::temp_dir().join(format!(
        "hell-composite-typed-result-{}",
        std::process::id()
    ));
    let _already_absent = std::fs::remove_dir_all(&directory);
    std::fs::create_dir(&directory).expect("create composite trace directory");
    let trace_path = directory.join("trace.json");
    hell_runtime::run_main_with_semantic_trace(
        program,
        hell_runtime::RuntimeContext::new(Vec::new(), Vec::<u8>::new()),
        &trace_path,
    )
    .expect("composite typed result runs");
    let trace = std::fs::read_to_string(&trace_path).expect("read composite trace");
    let original = hell_testkit::parse_semantic_trace(trace.as_bytes())
        .expect("producer composite schema is accepted");
    let reversed = trace.replace(
        "{\"type\":\"Tuple\",\"elements\":[{\"type\":\"Int\",\"value\":\"3\"},{\"type\":\"Int\",\"value\":\"4\"}]}",
        "{\"type\":\"Tuple\",\"elements\":[{\"type\":\"Int\",\"value\":\"4\"},{\"type\":\"Int\",\"value\":\"3\"}]}",
    );
    assert_ne!(
        trace, reversed,
        "typed tuple substitution fixture did not match"
    );
    let reversed = hell_testkit::parse_semantic_trace(reversed.as_bytes())
        .expect("reordered tuple remains structurally typed");
    assert_ne!(original.typed_result_sha256, reversed.typed_result_sha256);
    std::fs::remove_dir_all(directory).expect("remove composite trace directory");
}

#[cfg(feature = "compat-tracing")]
#[test]
fn actual_map_list_and_force_error_fingerprints_round_trip() {
    for (name, source, marker, succeeds) in [
        (
            "map",
            "main = IO.print $ Map.size $ Bool.bool (Map.fromList [(2,\"b\"),(1,\"a\")]) (Map.fromList []) Bool.False\n",
            "\"type\":\"Map\"",
            true,
        ),
        (
            "list",
            "main = IO.print $ List.length $ Bool.bool [1,2] [3] Bool.False\n",
            "\"terminationHex\":\"6e696c\"",
            true,
        ),
        (
            "force-error",
            "main = IO.print $ Bool.bool 1 (Error.error \"typed-bottom\" :: Int) Bool.True\n",
            "\"outcome\":\"error\",\"code\":\"H0901\"",
            false,
        ),
    ] {
        let trace = actual_typed_trace(name, source, succeeds);
        assert!(
            trace.contains(marker),
            "{name} trace omitted {marker}: {trace}"
        );
        hell_testkit::parse_semantic_trace(trace.as_bytes())
            .unwrap_or_else(|error| panic!("{name} typed trace was rejected: {error}"));
    }
}

#[cfg(feature = "compat-tracing")]
#[test]
fn typed_result_is_attributed_to_the_actual_map_adapter() {
    let source = "main = IO.print $ Map.size $ Map.fromList [(2,\"b\"),(1,\"a\")]\n";
    let program = compile_source(
        &mut CompilerSession::upstream(),
        "map-adapter-typed-result",
        source,
    )
    .expect("Map.fromList typed source compiles");
    let target = hell_builtins::lookup("Map.fromList").expect("Map.fromList registry entry");
    let directory = std::env::temp_dir().join(format!(
        "hell-map-adapter-typed-result-{}",
        std::process::id()
    ));
    let _already_absent = std::fs::remove_dir_all(&directory);
    std::fs::create_dir(&directory).expect("create target trace directory");
    let trace_path = directory.join("trace.json");
    hell_runtime::run_main_with_semantic_trace_target(
        program,
        hell_runtime::RuntimeContext::new(Vec::new(), Vec::<u8>::new()),
        &trace_path,
        target.id,
    )
    .expect("Map.fromList typed source runs");
    let trace = std::fs::read(&trace_path).expect("read target trace");
    let semantic = hell_testkit::parse_semantic_trace(&trace)
        .expect("target-attributed typed trace is canonical");
    assert_eq!(semantic.typed_result_builtin, Some(target.id));
    assert!(
        semantic
            .typed_result_canonical
            .as_deref()
            .is_some_and(|value| value.contains("\"type\":\"Map\""))
    );
    std::fs::remove_dir_all(directory).expect("remove target trace directory");
}

#[cfg(feature = "compat-tracing")]
#[test]
fn repeated_typed_result_target_invocation_is_rejected() {
    let source = concat!(
        "main = do\n",
        "  IO.print $ Map.size $ Map.fromList [(1,\"a\")]\n",
        "  IO.print $ Map.size $ Map.fromList [(2,\"b\")]\n",
    );
    let program = compile_source(
        &mut CompilerSession::upstream(),
        "repeated-map-adapter-typed-result",
        source,
    )
    .expect("repeated Map.fromList source compiles");
    let target = hell_builtins::lookup("Map.fromList").expect("Map.fromList registry entry");
    let directory = std::env::temp_dir().join(format!(
        "hell-repeated-map-adapter-typed-result-{}",
        std::process::id()
    ));
    let _already_absent = std::fs::remove_dir_all(&directory);
    std::fs::create_dir(&directory).expect("create repeated target trace directory");
    let trace_path = directory.join("trace.json");
    let error = hell_runtime::run_main_with_semantic_trace_target(
        program,
        hell_runtime::RuntimeContext::new(Vec::new(), Vec::<u8>::new()),
        &trace_path,
        target.id,
    )
    .expect_err("repeated typed-result target must fail closed");
    assert_eq!(
        error.message.as_ref(),
        "typed-result target must be invoked exactly once"
    );
    std::fs::remove_dir_all(directory).expect("remove repeated target trace directory");
}

#[cfg(feature = "compat-tracing")]
#[test]
fn dynamically_reused_typed_result_target_invocation_is_rejected() {
    let source = concat!(
        "build = \\entries -> Map.fromList entries\n",
        "main = do\n",
        "  IO.print $ Map.size $ Main.build [(1,\"a\")]\n",
        "  IO.print $ Map.size $ Main.build [(2,\"b\")]\n",
    );
    let program = compile_source(
        &mut CompilerSession::upstream(),
        "dynamically-reused-map-adapter-typed-result",
        source,
    )
    .expect("dynamically reused Map.fromList source compiles");
    let target = hell_builtins::lookup("Map.fromList").expect("Map.fromList registry entry");
    let directory = std::env::temp_dir().join(format!(
        "hell-dynamically-reused-map-adapter-typed-result-{}",
        std::process::id()
    ));
    let _already_absent = std::fs::remove_dir_all(&directory);
    std::fs::create_dir(&directory).expect("create dynamically reused target trace directory");
    let trace_path = directory.join("trace.json");
    let error = hell_runtime::run_main_with_semantic_trace_target(
        program,
        hell_runtime::RuntimeContext::new(Vec::new(), Vec::<u8>::new()),
        &trace_path,
        target.id,
    )
    .expect_err("dynamically reused typed-result target must fail closed");
    assert_eq!(
        error.message.as_ref(),
        "typed-result target must be invoked exactly once"
    );
    std::fs::remove_dir_all(directory).expect("remove dynamically reused target trace directory");
}

#[cfg(feature = "compat-tracing")]
#[test]
fn actual_constructor_adapters_emit_target_attributed_composites() {
    for (name, builtin, source, marker) in [
        (
            "maybe",
            "Maybe.Just",
            "main = IO.print $ Maybe.maybe 0 Function.id $ Maybe.Just 7\n",
            "\"type\":\"Maybe\"",
        ),
        (
            "either",
            "Either.Left",
            "main = IO.print $ Either.either Function.id Function.id (Either.Left 7 :: Either Int Int)\n",
            "\"type\":\"PrimitiveVariant\"",
        ),
        (
            "set",
            "Set.fromList",
            "main = IO.print $ Set.toList $ Set.fromList [2,1]\n",
            "\"type\":\"Set\"",
        ),
        (
            "vector",
            "Vector.fromList",
            "main = IO.print $ Vector.toList $ Vector.fromList [1,2]\n",
            "\"type\":\"Vector\"",
        ),
    ] {
        let program = compile_source(
            &mut CompilerSession::upstream(),
            format!("actual-constructor-{name}"),
            source,
        )
        .unwrap_or_else(|error| panic!("{name} source failed: {error:?}"));
        let target = hell_builtins::lookup(builtin).unwrap();
        let directory = std::env::temp_dir().join(format!(
            "hell-actual-constructor-{name}-{}",
            std::process::id()
        ));
        let _already_absent = std::fs::remove_dir_all(&directory);
        std::fs::create_dir(&directory).unwrap();
        let trace_path = directory.join("trace.json");
        hell_runtime::run_main_with_semantic_trace_target(
            program,
            hell_runtime::RuntimeContext::new(Vec::new(), Vec::<u8>::new()),
            &trace_path,
            target.id,
        )
        .unwrap_or_else(|error| panic!("{name} runtime failed: {error}"));
        let semantic = hell_testkit::parse_semantic_trace(&std::fs::read(&trace_path).unwrap())
            .unwrap_or_else(|error| panic!("{name} trace failed: {error}"));
        assert_eq!(semantic.typed_result_builtin, Some(target.id));
        assert!(
            semantic
                .typed_result_canonical
                .as_deref()
                .is_some_and(|value| value.contains(marker)),
            "{name} omitted {marker}"
        );
        std::fs::remove_dir_all(directory).unwrap();
    }
}

#[cfg(feature = "compat-tracing")]
fn actual_typed_trace(name: &str, source: &str, succeeds: bool) -> String {
    let program = compile_source(
        &mut CompilerSession::upstream(),
        format!("actual-typed-{name}"),
        source,
    )
    .unwrap_or_else(|error| panic!("{name} typed source did not compile: {error:?}"));
    let directory =
        std::env::temp_dir().join(format!("hell-actual-typed-{name}-{}", std::process::id()));
    let _already_absent = std::fs::remove_dir_all(&directory);
    std::fs::create_dir(&directory).expect("create typed trace directory");
    let trace_path = directory.join("trace.json");
    let outcome = hell_runtime::run_main_with_semantic_trace(
        program,
        hell_runtime::RuntimeContext::new(Vec::new(), Vec::<u8>::new()),
        &trace_path,
    );
    assert_eq!(outcome.is_ok(), succeeds, "{name} returned wrong outcome");
    let trace = std::fs::read_to_string(&trace_path).expect("read typed trace");
    std::fs::remove_dir_all(directory).expect("remove typed trace directory");
    trace
}

fn failure_observations(
    case: &hell_testkit::DifferentialCase,
    builtin: hell_builtins::BuiltinId,
) -> (hell_testkit::Observation, hell_testkit::Observation) {
    use std::path::PathBuf;
    use std::sync::Arc;

    use hell_builtins::NormalizerId;
    use hell_testkit::{
        BoundedCapture, CoverageEvent, DifferentialMode, ExecutableIdentity, ExecutableRole,
        LogicalTraceEvent, ProcessStatus, ResourceAudit, SemanticObservation, sha256_bytes,
    };

    let identity = |role| ExecutableIdentity {
        path: PathBuf::from(match role {
            ExecutableRole::Oracle => "/oracle/hell",
            ExecutableRole::Candidate => "/candidate/hell",
        }),
        sha256: sha256_bytes(match role {
            ExecutableRole::Oracle => b"oracle",
            ExecutableRole::Candidate => b"candidate",
        }),
        reported_version: Arc::from(hell_builtins::LANGUAGE_VERSION),
        build_info: None,
        role,
        assurance_epoch_sha256: Some(sha256_bytes(b"epoch")),
        acquisition_receipt_id: None,
        acquisition_receipt_sha256: None,
        acquisition_attestation_sha256: None,
    };
    let observation = |role, stderr: &[u8], semantic| hell_testkit::Observation {
        identity: identity(role),
        case_id: Arc::clone(&case.id),
        environment_profile: case.environment_profile,
        process_helper_sha256: case.process_helper_sha256,
        mode: DifferentialMode::Run,
        status: ProcessStatus {
            success: false,
            code: Some(1),
        },
        stdout: BoundedCapture::from_bytes(Vec::new()),
        raw_stderr: BoundedCapture::from_bytes(stderr.to_vec()),
        claim_input_stderr: BoundedCapture::from_bytes(stderr.to_vec()),
        stderr: BoundedCapture::from_bytes(stderr.to_vec()),
        normalizer_sandbox: PathBuf::from("/sandbox"),
        normalizer_script: PathBuf::from("/sandbox/main.hell"),
        timed_out: false,
        diagnostic: None,
        filesystem: Vec::new(),
        harness_normalizers: vec![NormalizerId::DiagnosticSandboxPathV1],
        claim_normalizers: Vec::new(),
        resource_audit: Some(ResourceAudit::default()),
        semantic,
    };
    let semantic = SemanticObservation {
        coverage: vec![CoverageEvent::EnteredAdapter(builtin)],
        effect_trace: vec![
            LogicalTraceEvent::HostEffect {
                builtin,
                owner_task: None,
                sequence: 1,
                parent_sequence: None,
                effect: Arc::from("started"),
            },
            LogicalTraceEvent::HostEffect {
                builtin,
                owner_task: None,
                sequence: 1,
                parent_sequence: None,
                effect: Arc::from("failed"),
            },
        ],
        ..SemanticObservation::default()
    };
    (
        observation(ExecutableRole::Oracle, b"oracle failure\n", None),
        observation(
            ExecutableRole::Candidate,
            b"candidate failure\n",
            Some(semantic),
        ),
    )
}

fn assert_projected(
    case: &hell_testkit::DifferentialCase,
    oracle: &hell_testkit::Observation,
    candidate: &hell_testkit::Observation,
) {
    let (projection, mismatches) = hell_testkit::compare_case_observations(case, oracle, candidate);
    assert!(matches!(
        projection,
        hell_testkit::DifferentialComparisonProjection::ReviewedRuntimeFailureStderr { .. }
    ));
    assert!(mismatches.is_empty());
}

fn assert_reviewed_adapter_failure_cases(cases: &[hell_testkit::DifferentialCase]) {
    use std::sync::Arc;

    use hell_builtins::CompatibilityDimension;
    use hell_testkit::LogicalTraceEvent;

    for case_id in [
        "runtime-process-run-failure",
        "runtime-process-run-checked-failure",
        "runtime-typed-async-race-left-fails",
        "runtime-typed-async-race-right-fails",
        "runtime-typed-async-concurrently-left-fails",
        "runtime-typed-async-concurrently-right-fails",
    ] {
        let case = cases
            .iter()
            .find(|candidate| candidate.id.as_ref() == case_id)
            .unwrap_or_else(|| panic!("missing reviewed adapter failure case {case_id}"));
        let name = case
            .claim_evidence
            .as_ref()
            .unwrap()
            .semantic_targets
            .iter()
            .find(|target| target.dimension == CompatibilityDimension::PureRuntime)
            .unwrap()
            .builtin
            .as_ref();
        let builtin = hell_builtins::lookup(name).unwrap().id;
        let (oracle, mut candidate) = failure_observations(case, builtin);
        if case_id.starts_with("runtime-typed-async-") {
            let failed = u64::from(case_id.contains("right-fails"));
            candidate.semantic.as_mut().unwrap().task_trace = vec![
                LogicalTraceEvent::TaskEvent {
                    task: 0,
                    builtin,
                    event: Arc::from("started"),
                },
                LogicalTraceEvent::TaskEvent {
                    task: 0,
                    builtin,
                    event: Arc::from(if failed == 0 { "failed" } else { "cancelled" }),
                },
                LogicalTraceEvent::TaskEvent {
                    task: 1,
                    builtin,
                    event: Arc::from("started"),
                },
                LogicalTraceEvent::TaskEvent {
                    task: 1,
                    builtin,
                    event: Arc::from(if failed == 1 { "failed" } else { "cancelled" }),
                },
            ];
        }
        assert_projected(case, &oracle, &candidate);
    }
}

fn assert_reviewed_success_case_coherence(cases: &[hell_testkit::DifferentialCase]) {
    use std::sync::Arc;

    use hell_builtins::CompatibilityDimension;

    for (case_id, builtin) in [
        ("runtime-process-run-success", "Process.runProcess"),
        ("runtime-process-run-checked-success", "Process.runProcess_"),
        ("runtime-process-run-nonzero", "Process.runProcess"),
        ("runtime-interaction-timeout-process", "Process.runProcess_"),
        (
            "runtime-interaction-cwd-child-process",
            "Process.runProcess_",
        ),
        ("runtime-typed-async-race-left-completes", "Async.race"),
        ("runtime-typed-async-race-right-completes", "Async.race"),
        (
            "runtime-typed-async-concurrently-left-completes-first",
            "Async.concurrently",
        ),
        (
            "runtime-typed-async-concurrently-right-completes-first",
            "Async.concurrently",
        ),
        ("runtime-interaction-race-temporary-resource", "Async.race"),
    ] {
        let case = cases
            .iter()
            .find(|case| case.id.as_ref() == case_id)
            .unwrap();
        let targets = &case.claim_evidence.as_ref().unwrap().semantic_targets;
        let mut success = targets.iter().filter(|target| {
            target.dimension == CompatibilityDimension::PureRuntime
                && target.builtin.as_ref() == builtin
                && target
                    .obligations
                    .iter()
                    .any(|obligation| obligation.0.as_ref() == "adapter-success")
        });
        let target = success
            .next()
            .unwrap_or_else(|| panic!("{case_id} lacks adapter-success"));
        assert!(
            success.next().is_none(),
            "{case_id} has ambiguous success targets"
        );
        assert!(
            target
                .obligations
                .iter()
                .all(|item| item.0.as_ref() != "adapter-failure")
        );
    }
    let mut contradictory = cases.to_vec();
    let target = contradictory
        .iter_mut()
        .find(|case| case.id.as_ref() == "runtime-process-run-checked-success")
        .and_then(|case| case.claim_evidence.as_mut())
        .and_then(|descriptor| {
            descriptor.semantic_targets.iter_mut().find(|target| {
                target.dimension == CompatibilityDimension::PureRuntime
                    && target.builtin.as_ref() == "Process.runProcess_"
            })
        })
        .unwrap();
    target
        .obligations
        .push(hell_testkit::ObligationId(Arc::from("adapter-failure")));
    assert!(hell_testkit::validate_evidence_catalog(&contradictory).is_err());
}

fn assert_projection_exact(
    label: &str,
    case: &hell_testkit::DifferentialCase,
    oracle: &hell_testkit::Observation,
    candidate: &hell_testkit::Observation,
) {
    let (projection, mismatches) = hell_testkit::compare_case_observations(case, oracle, candidate);
    assert_eq!(
        projection,
        hell_testkit::DifferentialComparisonProjection::Exact,
        "{label}"
    );
    assert!(!mismatches.is_empty(), "{label} became fail-open");
}

fn assert_projection_authority_mutations(
    case: &hell_testkit::DifferentialCase,
    oracle: &hell_testkit::Observation,
    candidate: &hell_testkit::Observation,
) {
    assert_projection_scope_mutations(case, oracle, candidate);
    assert_projection_obligation_mutations(case, oracle, candidate);
}

fn assert_projection_scope_mutations(
    case: &hell_testkit::DifferentialCase,
    oracle: &hell_testkit::Observation,
    candidate: &hell_testkit::Observation,
) {
    use hell_builtins::CompatibilityDimension;
    use std::sync::Arc;

    let mut changed = case.clone();
    changed.expected_runtime_completion = true;
    assert_projection_exact("success authority", &changed, oracle, candidate);
    let mut changed = case.clone();
    changed.mode = hell_testkit::DifferentialMode::Check;
    assert_projection_exact("check mode", &changed, oracle, candidate);
    let mut changed = case.clone();
    changed.claim_evidence.as_mut().unwrap().review_statement = Arc::from("");
    assert_projection_exact("review authority", &changed, oracle, candidate);
    let mut changed = case.clone();
    changed
        .claim_evidence
        .as_mut()
        .unwrap()
        .targets
        .push(hell_testkit::EvidenceTarget {
            builtin: Arc::from("Text.readFile"),
            dimension: CompatibilityDimension::Presentation,
        });
    assert_projection_exact("presentation scope", &changed, oracle, candidate);
    let mut changed = case.clone();
    let mut target = changed.claim_evidence.as_ref().unwrap().semantic_targets[0].clone();
    target.dimension = CompatibilityDimension::Presentation;
    target.causal_signal = hell_testkit::CausalSignal::PresentationField;
    changed
        .claim_evidence
        .as_mut()
        .unwrap()
        .semantic_targets
        .push(target);
    assert_projection_exact("descriptor-v8 presentation", &changed, oracle, candidate);
    let mut changed = case.clone();
    changed.claim_evidence.as_mut().unwrap().semantic_targets[0].expected_raw_presentation_sha256 =
        Some(hell_testkit::sha256_bytes(b"raw"));
    assert_projection_exact("raw presentation expectation", &changed, oracle, candidate);
}

fn assert_projection_obligation_mutations(
    case: &hell_testkit::DifferentialCase,
    oracle: &hell_testkit::Observation,
    candidate: &hell_testkit::Observation,
) {
    use hell_builtins::CompatibilityDimension;
    use std::sync::Arc;

    for (dimension, obligation, replacement) in [
        (CompatibilityDimension::Effects, "effect-failure", None),
        (CompatibilityDimension::Effects, "effect-ordering", None),
        (
            CompatibilityDimension::Effects,
            "effect-success",
            Some("effect-success"),
        ),
        (CompatibilityDimension::PureRuntime, "adapter-failure", None),
        (
            CompatibilityDimension::PureRuntime,
            "adapter-success",
            Some("adapter-success"),
        ),
    ] {
        let mut changed = case.clone();
        let target = changed
            .claim_evidence
            .as_mut()
            .unwrap()
            .semantic_targets
            .iter_mut()
            .find(|target| target.dimension == dimension)
            .unwrap();
        if let Some(replacement) = replacement {
            target
                .obligations
                .push(hell_testkit::ObligationId(Arc::from(replacement)));
        } else {
            target
                .obligations
                .retain(|item| item.0.as_ref() != obligation);
        }
        assert_projection_exact(obligation, &changed, oracle, candidate);
    }
}

fn assert_projection_observation_mutations(
    case: &hell_testkit::DifferentialCase,
    oracle: &hell_testkit::Observation,
    candidate: &hell_testkit::Observation,
    builtin: hell_builtins::BuiltinId,
) {
    assert_projection_process_mutations(case, oracle, candidate);
    assert_projection_semantic_mutations(case, oracle, candidate, builtin);
}

fn assert_projection_process_mutations(
    case: &hell_testkit::DifferentialCase,
    oracle: &hell_testkit::Observation,
    candidate: &hell_testkit::Observation,
) {
    use hell_testkit::{BoundedCapture, FilesystemEntry, FilesystemEntryKind};
    use std::path::PathBuf;
    use std::sync::Arc;

    let mut changed = oracle.clone();
    changed.timed_out = true;
    assert_projection_exact("timeout", case, &changed, candidate);
    let mut changed = candidate.clone();
    changed.status.code = Some(2);
    assert_projection_exact("status", case, oracle, &changed);
    let mut changed = candidate.clone();
    changed.status.success = true;
    changed.status.code = Some(0);
    assert_projection_exact("successful status", case, oracle, &changed);
    let mut changed = candidate.clone();
    changed.stdout = BoundedCapture::from_bytes(b"unexpected".to_vec());
    assert_projection_exact("stdout", case, oracle, &changed);
    let mut changed = candidate.clone();
    changed.filesystem.push(FilesystemEntry {
        relative_path: PathBuf::from("unexpected"),
        kind: FilesystemEntryKind::File,
        contents: Vec::new(),
        size: 0,
        sha256: Some(hell_testkit::sha256_bytes(&[])),
        truncated: false,
    });
    assert_projection_exact("filesystem", case, oracle, &changed);
    let mut changed = candidate.clone();
    changed.stderr.truncated = true;
    changed.stderr.complete = None;
    assert_projection_exact("truncated stderr", case, oracle, &changed);
    let mut changed = candidate.clone();
    changed.case_id = Arc::from("another-case");
    assert_projection_exact("case identity", case, oracle, &changed);
}

fn assert_projection_semantic_mutations(
    case: &hell_testkit::DifferentialCase,
    oracle: &hell_testkit::Observation,
    candidate: &hell_testkit::Observation,
    builtin: hell_builtins::BuiltinId,
) {
    use hell_testkit::{CoverageEvent, LogicalTraceEvent};
    use std::sync::Arc;

    let mut changed = candidate.clone();
    changed.semantic = None;
    assert_projection_exact("missing semantic", case, oracle, &changed);
    let mut changed = candidate.clone();
    changed.semantic.as_mut().unwrap().coverage.clear();
    assert_projection_exact("missing adapter", case, oracle, &changed);
    let mut changed = candidate.clone();
    let wrong = hell_builtins::lookup("Text.writeFile").unwrap().id;
    changed.semantic.as_mut().unwrap().coverage = vec![CoverageEvent::EnteredAdapter(wrong)];
    for event in &mut changed.semantic.as_mut().unwrap().effect_trace {
        if let LogicalTraceEvent::HostEffect { builtin, .. } = event {
            *builtin = wrong;
        }
    }
    assert_projection_exact("wrong builtin", case, oracle, &changed);
    let mut changed = candidate.clone();
    if let LogicalTraceEvent::HostEffect { effect, .. } =
        &mut changed.semantic.as_mut().unwrap().effect_trace[1]
    {
        *effect = Arc::from("completed");
    }
    assert_projection_exact("failed lifecycle", case, oracle, &changed);
    let mut changed = candidate.clone();
    changed
        .semantic
        .as_mut()
        .unwrap()
        .effect_trace
        .push(LogicalTraceEvent::HostEffect {
            builtin,
            owner_task: None,
            sequence: 2,
            parent_sequence: None,
            effect: Arc::from("started"),
        });
    assert_projection_exact("extra lifecycle", case, oracle, &changed);
}

#[test]
fn reviewed_runtime_failure_stderr_projection_is_explicit_and_fail_closed() {
    use std::sync::Arc;

    use hell_builtins::CompatibilityDimension;
    use hell_testkit::{
        CausalSignal, DifferentialComparisonProjection, DifferentialMode,
        compare_case_observations, validate_evidence_catalog,
    };

    let mut cases = committed_differential_cases();
    let case_index = cases
        .iter()
        .position(|case| case.id.as_ref() == "runtime-typed-io-text-readfile-failure")
        .expect("reviewed Text.readFile failure case");
    let case = cases[case_index].clone();
    let descriptor = case.claim_evidence.as_ref().expect("reviewed descriptor");
    assert!(!case.expected_runtime_completion);
    assert_eq!(case.mode, DifferentialMode::Run);
    assert!(
        descriptor
            .targets
            .iter()
            .all(|target| target.dimension != CompatibilityDimension::Presentation)
    );
    assert!(
        descriptor
            .semantic_targets
            .iter()
            .all(|target| target.dimension != CompatibilityDimension::Presentation)
    );
    let effect = descriptor
        .semantic_targets
        .iter()
        .find(|target| target.dimension == CompatibilityDimension::Effects)
        .expect("failure effect target");
    assert_eq!(effect.causal_signal, CausalSignal::EffectEvent);
    assert!(
        effect
            .obligations
            .iter()
            .any(|obligation| obligation.0.as_ref() == "effect-failure")
    );
    assert!(
        effect
            .obligations
            .iter()
            .any(|obligation| obligation.0.as_ref() == "effect-ordering")
    );
    let builtin = hell_builtins::lookup("Text.readFile").unwrap().id;
    let (oracle, candidate) = failure_observations(&case, builtin);
    assert_projected(&case, &oracle, &candidate);

    assert_reviewed_adapter_failure_cases(&cases);
    assert_reviewed_success_case_coherence(&cases);

    assert_projection_authority_mutations(&case, &oracle, &candidate);
    assert_projection_observation_mutations(&case, &oracle, &candidate, builtin);

    cases[case_index]
        .claim_evidence
        .as_mut()
        .unwrap()
        .targets
        .push(hell_testkit::EvidenceTarget {
            builtin: Arc::from("Text.readFile"),
            dimension: CompatibilityDimension::Presentation,
        });
    assert!(validate_evidence_catalog(&cases).is_err());

    let strict = hell_testkit::DifferentialCase::default();
    let (projection, mismatches) = compare_case_observations(&strict, &oracle, &candidate);
    assert_eq!(projection, DifferentialComparisonProjection::Exact);
    assert!(!mismatches.is_empty());
}

#[cfg(feature = "compat-tracing")]
fn projected_failure_report(
    case: &hell_testkit::DifferentialCase,
    root: &std::path::Path,
    semantic: hell_testkit::SemanticObservation,
) -> hell_testkit::DifferentialReport {
    use std::path::PathBuf;
    use std::sync::Arc;

    use hell_builtins::NormalizerId;
    use hell_testkit::{
        BoundedCapture, DifferentialMode, ExecutableIdentity, ExecutableRole, Observation,
        ProcessStatus, ResourceAudit, compare_case_observations, sha256_bytes,
    };

    let observation = |role, stderr: &[u8], semantic| Observation {
        identity: ExecutableIdentity {
            path: PathBuf::from(match role {
                ExecutableRole::Oracle => "/oracle/hell",
                ExecutableRole::Candidate => "/candidate/hell",
            }),
            sha256: sha256_bytes(match role {
                ExecutableRole::Oracle => b"oracle",
                ExecutableRole::Candidate => b"candidate",
            }),
            reported_version: Arc::from(hell_builtins::LANGUAGE_VERSION),
            build_info: None,
            role,
            assurance_epoch_sha256: Some(sha256_bytes(b"epoch")),
            acquisition_receipt_id: None,
            acquisition_receipt_sha256: None,
            acquisition_attestation_sha256: None,
        },
        case_id: Arc::clone(&case.id),
        environment_profile: case.environment_profile,
        process_helper_sha256: case.process_helper_sha256,
        mode: DifferentialMode::Run,
        status: ProcessStatus {
            success: false,
            code: Some(1),
        },
        stdout: BoundedCapture::from_bytes(Vec::new()),
        raw_stderr: BoundedCapture::from_bytes(stderr.to_vec()),
        claim_input_stderr: BoundedCapture::from_bytes(stderr.to_vec()),
        stderr: BoundedCapture::from_bytes(stderr.to_vec()),
        normalizer_sandbox: root.join("sandbox"),
        normalizer_script: root.join("sandbox/main.hell"),
        timed_out: false,
        diagnostic: None,
        filesystem: Vec::new(),
        harness_normalizers: vec![NormalizerId::DiagnosticSandboxPathV1],
        claim_normalizers: Vec::new(),
        resource_audit: (role == ExecutableRole::Candidate).then(ResourceAudit::default),
        semantic,
    };
    let oracle = observation(
        ExecutableRole::Oracle,
        concat!(
            "hell: Uncaught exception ",
            "ghc-internal:GHC.Internal.IO.Exception.IOException:\n\n",
            "missing-parent/file.txt: withBinaryFile: does not exist (No such file or directory)\n\n",
            "HasCallStack backtrace:\n",
            "  throwIO, called at libraries/ghc-internal/src/GHC/Internal/IO.hs:123:4 ",
            "in ghc-internal:GHC.Internal.IO\n",
        )
        .as_bytes(),
        None,
    );
    let candidate = observation(
        ExecutableRole::Candidate,
        b"hell: missing-parent/file.txt: withBinaryFile: does not exist (No such file or directory)\n",
        Some(semantic),
    );
    let (comparison_projection, mismatches) = compare_case_observations(case, &oracle, &candidate);
    hell_testkit::DifferentialReport {
        oracle,
        candidate,
        comparison_projection,
        mismatches,
    }
}

#[cfg(feature = "compat-tracing")]
fn assert_runtime_failure_comparison_rejected(
    label: &str,
    case: &hell_testkit::DifferentialCase,
    oracle: &hell_testkit::Observation,
    candidate: &hell_testkit::Observation,
    expected_reason: Option<hell_testkit::RuntimeFailureProjectionRejectionReason>,
) {
    use hell_testkit::{DifferentialComparisonProjection, MismatchKind, compare_case_observations};

    let (projection, mismatches) = compare_case_observations(case, oracle, candidate);
    assert_eq!(
        projection,
        DifferentialComparisonProjection::Exact,
        "{label} retained a strict projection",
    );
    assert_eq!(mismatches.len(), 1, "{label} mismatch inventory");
    assert_eq!(mismatches[0].kind, MismatchKind::Stderr, "{label}");
    assert_eq!(
        hell_testkit::runtime_failure_projection_rejection(case, oracle, candidate)
            .map(|rejection| rejection.reason),
        expected_reason,
        "{label} diagnostic reason",
    );
}

#[cfg(feature = "compat-tracing")]
fn assert_oracle_frame_rejection_reasons(
    case: &hell_testkit::DifferentialCase,
    report: &hell_testkit::DifferentialReport,
) {
    use hell_testkit::{BoundedCapture, RuntimeFailureProjectionRejectionReason as Reason};

    let oracle_text = || String::from_utf8(report.oracle.stderr.complete.clone().unwrap()).unwrap();
    let mut changed = report.oracle.clone();
    changed.stderr = BoundedCapture::from_bytes(
        oracle_text()
            .replace("  throwIO, called at", "  injected, called at")
            .into_bytes(),
    );
    assert_runtime_failure_comparison_rejected(
        "oracle frame function",
        case,
        &changed,
        &report.candidate,
        Some(Reason::OracleFrameFunction),
    );

    let mut changed = report.oracle.clone();
    let mut stderr = report.oracle.stderr.complete.clone().unwrap();
    assert_eq!(stderr.pop(), Some(b'\n'));
    changed.stderr = BoundedCapture::from_bytes(stderr);
    assert_runtime_failure_comparison_rejected(
        "oracle frame terminal newline",
        case,
        &changed,
        &report.candidate,
        Some(Reason::OracleFrameTerminalNewline),
    );

    let mut changed = report.oracle.clone();
    changed.stderr = BoundedCapture::from_bytes(
        oracle_text()
            .replace("GHC/Internal/IO.hs", "Unrelated/Injected.hs")
            .into_bytes(),
    );
    assert_runtime_failure_comparison_rejected(
        "oracle frame origin",
        case,
        &changed,
        &report.candidate,
        Some(Reason::OracleFrameOrigin),
    );
}

#[cfg(feature = "compat-tracing")]
fn assert_direct_runtime_failure_exception_comparison_is_fail_closed(
    case: &hell_testkit::DifferentialCase,
    report: &hell_testkit::DifferentialReport,
) {
    use std::sync::Arc;

    use hell_testkit::{
        BoundedCapture, DifferentialComparisonProjection, LogicalTraceEvent,
        compare_case_observations,
    };

    let (projection, mismatches) =
        compare_case_observations(case, &report.oracle, &report.candidate);
    assert!(matches!(
        projection,
        DifferentialComparisonProjection::ReviewedRuntimeFailureExceptionStderr { .. }
    ));
    assert!(mismatches.is_empty());

    let mut changed = report.oracle.clone();
    changed.stderr = BoundedCapture::from_bytes(
        String::from_utf8(report.oracle.stderr.complete.clone().unwrap())
            .unwrap()
            .replace(
                "GHC.Internal.IO.Exception.IOException",
                "GHC.Internal.Exception.ErrorCall",
            )
            .into_bytes(),
    );
    assert_runtime_failure_comparison_rejected(
        "oracle family",
        case,
        &changed,
        &report.candidate,
        Some(hell_testkit::RuntimeFailureProjectionRejectionReason::OracleExceptionFamily),
    );

    assert_oracle_frame_rejection_reasons(case, report);

    let mut changed = report.candidate.clone();
    changed.stderr = BoundedCapture::from_bytes(
        String::from_utf8(report.candidate.stderr.complete.clone().unwrap())
            .unwrap()
            .replace("missing-parent/file.txt", "substituted/file.txt")
            .into_bytes(),
    );
    assert_runtime_failure_comparison_rejected(
        "candidate payload",
        case,
        &report.oracle,
        &changed,
        Some(hell_testkit::RuntimeFailureProjectionRejectionReason::PayloadMismatch),
    );

    let mut changed = report.candidate.clone();
    for event in &mut changed
        .semantic
        .as_mut()
        .expect("candidate semantic evidence")
        .effect_trace
    {
        if let LogicalTraceEvent::HostEffect { effect, .. } = event
            && effect.as_ref() == "failed"
        {
            *effect = Arc::from("completed");
        }
    }
    assert_runtime_failure_comparison_rejected(
        "candidate causality",
        case,
        &report.oracle,
        &changed,
        Some(hell_testkit::RuntimeFailureProjectionRejectionReason::SemanticCausality),
    );

    let mut changed = report.candidate.clone();
    changed.semantic = None;
    assert_runtime_failure_comparison_rejected(
        "missing candidate semantic evidence",
        case,
        &report.oracle,
        &changed,
        Some(hell_testkit::RuntimeFailureProjectionRejectionReason::MissingCandidateSemantic),
    );

    assert_runtime_failure_descriptor_rejections(case, report);
}

#[cfg(feature = "compat-tracing")]
fn assert_runtime_failure_descriptor_rejections(
    case: &hell_testkit::DifferentialCase,
    report: &hell_testkit::DifferentialReport,
) {
    use std::sync::Arc;

    use hell_builtins::CompatibilityDimension;
    use hell_testkit::EvidenceTarget;

    let mut contaminated = case.clone();
    contaminated
        .claim_evidence
        .as_mut()
        .unwrap()
        .targets
        .push(EvidenceTarget {
            builtin: Arc::from("Text.writeFile"),
            dimension: CompatibilityDimension::Presentation,
        });
    assert_runtime_failure_comparison_rejected(
        "strict descriptor contamination",
        &contaminated,
        &report.oracle,
        &report.candidate,
        Some(hell_testkit::RuntimeFailureProjectionRejectionReason::DescriptorTable),
    );

    assert_runtime_failure_comparison_rejected(
        "non-reviewed case",
        &hell_testkit::DifferentialCase::default(),
        &report.oracle,
        &report.candidate,
        None,
    );
}

#[cfg(feature = "compat-tracing")]
fn assert_strict_projection_rejects_legacy_substitution(
    root: &std::path::Path,
    case: &hell_testkit::DifferentialCase,
    report: &hell_testkit::DifferentialReport,
) {
    use hell_testkit::{DifferentialComparisonProjection, retain_observation_bundle};

    let mut forged = report.clone();
    forged.comparison_projection = DifferentialComparisonProjection::ReviewedRuntimeFailureStderr {
        oracle_sha256: forged.oracle.stderr.sha256,
        candidate_sha256: forged.candidate.stderr.sha256,
        oracle_bytes: forged.oracle.stderr.total_bytes,
        candidate_bytes: forged.candidate.stderr.total_bytes,
    };
    let error = retain_observation_bundle(&root.join("legacy-forged"), case, &forged).unwrap_err();
    assert!(error.to_string().contains("projection disagrees"));
}

#[cfg(feature = "compat-tracing")]
fn assert_strict_projection_manifest(bundle: &std::path::Path) {
    let projection = std::fs::read_to_string(bundle.join("comparison-projection.json")).unwrap();
    assert!(projection.contains("reviewed-runtime-failure-exception-stderr-out-of-scope"));
    let manifest = std::fs::read_to_string(bundle.join("bundle-manifest.json")).unwrap();
    assert!(manifest.contains("comparison-projection.json"));
}

#[cfg(feature = "compat-tracing")]
#[test]
fn retained_runtime_failure_projection_is_manifest_bound_and_recomputed() {
    use hell_testkit::{
        DifferentialComparisonProjection, RetainedObservationClassification,
        retain_observation_bundle, verify_observation_bundle_for_case,
    };

    let case = committed_differential_cases()
        .into_iter()
        .find(|case| case.id.as_ref() == "runtime-typed-io-text-writefile-failure")
        .expect("reviewed Text.writeFile failure case");
    let root = std::env::temp_dir().join(format!(
        "hell-reviewed-failure-projection-{}",
        std::process::id()
    ));
    let _already_absent = std::fs::remove_dir_all(&root);
    std::fs::create_dir(&root).unwrap();
    let trace = root.join("semantic-trace.json");
    let program = compile_source(
        &mut CompilerSession::upstream(),
        case.id.to_string(),
        case.source.to_string(),
    )
    .unwrap();
    let outcome = hell_runtime::run_main_with_semantic_trace(
        program,
        hell_runtime::RuntimeContext::with_host(
            Vec::new(),
            Vec::new(),
            Vec::<u8>::new(),
            root.clone(),
            true,
        ),
        &trace,
    );
    assert!(outcome.is_err());
    let semantic = hell_testkit::parse_semantic_trace(&std::fs::read(&trace).unwrap()).unwrap();
    std::fs::remove_file(trace).unwrap();

    let report = projected_failure_report(&case, &root, semantic);
    assert!(matches!(
        report.comparison_projection,
        DifferentialComparisonProjection::ReviewedRuntimeFailureExceptionStderr { .. }
    ));
    assert!(report.mismatches.is_empty());
    assert_direct_runtime_failure_exception_comparison_is_fail_closed(&case, &report);
    let mut causal_forged = report.clone();
    for event in &mut causal_forged
        .candidate
        .semantic
        .as_mut()
        .expect("candidate semantic evidence")
        .effect_trace
    {
        if let hell_testkit::LogicalTraceEvent::HostEffect { effect, .. } = event
            && effect.as_ref() == "failed"
        {
            *effect = "completed".into();
        }
    }
    let (forged_projection, _) = hell_testkit::compare_case_observations(
        &case,
        &causal_forged.oracle,
        &causal_forged.candidate,
    );
    assert_eq!(forged_projection, DifferentialComparisonProjection::Exact);
    let bundle = retain_observation_bundle(&root.join("evidence"), &case, &report).unwrap();
    verify_observation_bundle_for_case(&bundle, &case).unwrap();
    let classification =
        hell_testkit::classify_retained_observation_bundle(&bundle, &case).unwrap();
    assert!(matches!(
        classification,
        RetainedObservationClassification::ProjectedRuntimeFailureStderr { ref raw_mismatches }
            if raw_mismatches.len() == 1
    ));
    assert_strict_projection_manifest(&bundle);

    assert_strict_projection_rejects_legacy_substitution(&root, &case, &report);

    let mut forged = report;
    forged.candidate.semantic = None;
    let (exception_family, payload_sha256) = match &forged.comparison_projection {
        DifferentialComparisonProjection::ReviewedRuntimeFailureExceptionStderr {
            exception_family,
            payload_sha256,
            ..
        } => (*exception_family, *payload_sha256),
        DifferentialComparisonProjection::Exact
        | DifferentialComparisonProjection::ReviewedRuntimeFailureStderr { .. }
        | DifferentialComparisonProjection::ReviewedWindowsPresentation { .. } => {
            panic!("strict reviewed projection disappeared")
        }
    };
    forged.comparison_projection =
        DifferentialComparisonProjection::ReviewedRuntimeFailureExceptionStderr {
            exception_family,
            payload_sha256,
            oracle_sha256: forged.oracle.stderr.sha256,
            candidate_sha256: forged.candidate.stderr.sha256,
            oracle_bytes: forged.oracle.stderr.total_bytes,
            candidate_bytes: forged.candidate.stderr.total_bytes,
        };
    let forged_root = root.join("forged");
    let error = retain_observation_bundle(&forged_root, &case, &forged).unwrap_err();
    assert!(error.to_string().contains("projection disagrees"));
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(feature = "compat-tracing")]
fn assert_async_projection_mutations(
    case: &hell_testkit::DifferentialCase,
    root: &std::path::Path,
    report: &hell_testkit::DifferentialReport,
    builtin: hell_builtins::BuiltinId,
) {
    let mutations = async_semantic_projection_mutations(report, builtin)
        .into_iter()
        .chain(async_process_projection_mutations(report));
    for (label, changed) in mutations {
        let error = hell_testkit::retain_observation_bundle(&root.join(label), case, &changed)
            .expect_err("stale projected Async evidence became admissible");
        assert!(
            error.to_string().contains("projection disagrees")
                || error.to_string().contains("semantic"),
            "{}/{label}: {error}",
            case.id
        );
    }
}

#[cfg(feature = "compat-tracing")]
fn async_semantic_projection_mutations(
    report: &hell_testkit::DifferentialReport,
    builtin: hell_builtins::BuiltinId,
) -> Vec<(&'static str, hell_testkit::DifferentialReport)> {
    use hell_testkit::{CoverageEvent, LogicalTraceEvent};
    use std::sync::Arc;

    let mut mutations = Vec::new();
    let mut changed = report.clone();
    changed
        .candidate
        .semantic
        .as_mut()
        .unwrap()
        .coverage
        .retain(|event| *event != CoverageEvent::EnteredAdapter(builtin));
    mutations.push(("adapter-entry", changed));
    let mut changed = report.clone();
    changed
        .candidate
        .semantic
        .as_mut()
        .unwrap()
        .effect_trace
        .retain(|event| {
            !matches!(event, LogicalTraceEvent::HostEffect { builtin: observed, effect, .. }
            if *observed == builtin && effect.as_ref() == "failed")
        });
    mutations.push(("effect-failed", changed));
    let mut changed = report.clone();
    let effects = &mut changed.candidate.semantic.as_mut().unwrap().effect_trace;
    let indices = effects
        .iter()
        .enumerate()
        .filter_map(|(index, event)| {
            matches!(event, LogicalTraceEvent::HostEffect { builtin: observed, .. }
            if *observed == builtin)
            .then_some(index)
        })
        .collect::<Vec<_>>();
    assert_eq!(indices.len(), 2);
    effects.swap(indices[0], indices[1]);
    mutations.push(("effect-order", changed));
    let mut changed = report.clone();
    let failed = changed
        .candidate
        .semantic
        .as_mut()
        .unwrap()
        .task_trace
        .iter_mut()
        .find(|event| {
            matches!(event, LogicalTraceEvent::TaskEvent { event, .. }
            if event.as_ref() == "failed")
        })
        .unwrap();
    if let LogicalTraceEvent::TaskEvent { event, .. } = failed {
        *event = Arc::from("completed");
    }
    mutations.push(("task-terminal", changed));
    let mut changed = report.clone();
    changed
        .candidate
        .semantic
        .as_mut()
        .unwrap()
        .task_trace
        .retain(|event| {
            !matches!(event, LogicalTraceEvent::TaskEvent { event, .. }
            if event.as_ref() == "cancelled")
        });
    mutations.push(("task-cancellation", changed));
    let mut changed = report.clone();
    changed
        .candidate
        .semantic
        .as_mut()
        .unwrap()
        .task_trace
        .swap(0, 1);
    mutations.push(("task-order", changed));
    mutations
}

#[cfg(feature = "compat-tracing")]
fn async_process_projection_mutations(
    report: &hell_testkit::DifferentialReport,
) -> Vec<(&'static str, hell_testkit::DifferentialReport)> {
    use hell_testkit::{BoundedCapture, FilesystemEntry, FilesystemEntryKind, ProcessStatus};
    use std::path::PathBuf;

    let mut mutations = Vec::new();
    let mut changed = report.clone();
    changed.candidate.status = ProcessStatus {
        success: true,
        code: Some(0),
    };
    mutations.push(("status", changed));
    let mut changed = report.clone();
    changed.candidate.stdout = BoundedCapture::from_bytes(b"forged\n".to_vec());
    mutations.push(("stdout", changed));
    let mut changed = report.clone();
    changed.candidate.filesystem.push(FilesystemEntry {
        relative_path: PathBuf::from("forged"),
        kind: FilesystemEntryKind::File,
        contents: Vec::new(),
        size: 0,
        sha256: Some(hell_testkit::sha256_bytes(&[])),
        truncated: false,
    });
    mutations.push(("filesystem", changed));
    let mut changed = report.clone();
    changed.candidate.stderr.truncated = true;
    changed.candidate.stderr.complete = None;
    mutations.push(("truncation", changed));
    let mut changed = report.clone();
    changed.candidate.semantic = None;
    mutations.push(("semantic", changed));
    mutations
}

#[cfg(feature = "compat-tracing")]
#[test]
fn retained_async_failure_projections_bind_actual_adapter_effect_and_task_evidence() {
    use std::sync::Arc;

    use hell_builtins::CompatibilityDimension;
    use hell_testkit::{
        DifferentialComparisonProjection, RetainedObservationClassification,
        retain_observation_bundle, verify_observation_bundle_for_case,
    };

    let cases = committed_differential_cases();
    let root = std::env::temp_dir().join(format!(
        "hell-retained-async-failure-projections-{}",
        std::process::id()
    ));
    let _already_absent = std::fs::remove_dir_all(&root);
    std::fs::create_dir(&root).unwrap();

    for case_id in [
        "runtime-typed-async-race-left-fails",
        "runtime-typed-async-race-right-fails",
        "runtime-typed-async-concurrently-left-fails",
        "runtime-typed-async-concurrently-right-fails",
    ] {
        let case = cases
            .iter()
            .find(|candidate| candidate.id.as_ref() == case_id)
            .unwrap_or_else(|| panic!("missing reviewed Async failure case {case_id}"));
        let case_root = root.join(case_id);
        std::fs::create_dir(&case_root).unwrap();
        let trace_path = case_root.join("semantic-trace.json");
        let program = compile_source(
            &mut CompilerSession::upstream(),
            case.id.to_string(),
            case.source.to_string(),
        )
        .unwrap_or_else(|error| panic!("{case_id} did not compile: {error:?}"));
        let outcome = hell_runtime::run_main_with_semantic_trace(
            program,
            hell_runtime::RuntimeContext::with_host(
                Vec::new(),
                Vec::new(),
                Vec::<u8>::new(),
                case_root.clone(),
                true,
            ),
            &trace_path,
        );
        assert!(outcome.is_err(), "{case_id} unexpectedly completed");
        let semantic =
            hell_testkit::parse_semantic_trace(&std::fs::read(&trace_path).unwrap()).unwrap();
        std::fs::remove_file(trace_path).unwrap();
        let builtin_name = case
            .claim_evidence
            .as_ref()
            .unwrap()
            .semantic_targets
            .iter()
            .find(|target| target.dimension == CompatibilityDimension::PureRuntime)
            .unwrap()
            .builtin
            .as_ref();
        let builtin = hell_builtins::lookup(builtin_name).unwrap().id;

        let report = projected_failure_report(case, &case_root, semantic);
        assert!(matches!(
            report.comparison_projection,
            DifferentialComparisonProjection::ReviewedRuntimeFailureStderr { .. }
        ));
        assert!(report.mismatches.is_empty());
        let bundle = retain_observation_bundle(&case_root.join("evidence"), case, &report).unwrap();
        verify_observation_bundle_for_case(&bundle, case).unwrap();
        let classification =
            hell_testkit::classify_retained_observation_bundle(&bundle, case).unwrap();
        assert!(matches!(
            classification,
            RetainedObservationClassification::ProjectedRuntimeFailureStderr {
                ref raw_mismatches
            } if raw_mismatches.len() == 1
        ));

        assert_async_projection_mutations(case, &case_root, &report, builtin);

        let mut presentation = case.clone();
        presentation
            .claim_evidence
            .as_mut()
            .unwrap()
            .targets
            .push(hell_testkit::EvidenceTarget {
                builtin: Arc::from(builtin_name),
                dimension: CompatibilityDimension::Presentation,
            });
        assert!(verify_observation_bundle_for_case(&bundle, &presentation).is_err());
    }

    std::fs::remove_dir_all(root).unwrap();
}
