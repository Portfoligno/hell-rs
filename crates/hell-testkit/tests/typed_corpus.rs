use hell_compiler::{CompilerSession, compile_source};
use hell_testkit::{committed_differential_cases, generated_typed_cases};

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
            .map(|target| hell_builtins::lookup(&target.builtin).unwrap().id)
            .collect::<Vec<_>>();
        let context = typed_case_runtime_context(&case, &case_directory);
        let outcome = match typed_targets.as_slice() {
            [] => hell_runtime::run_main_with_semantic_trace(program, context, &trace_path),
            [target] => hell_runtime::run_main_with_semantic_trace_target(
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
        } else if case.id.ends_with("http-stream-disconnect") {
            let error = outcome.expect_err("HTTP disconnect must terminate the response stream");
            assert_eq!(error.code, "H0908");
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
