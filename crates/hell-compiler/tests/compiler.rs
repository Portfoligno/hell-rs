use hell_compiler::{CompilerSession, Limit, compile_source};

fn check(source: &str) -> Result<hell_core::VerifiedProgram, hell_compiler::DiagnosticBundle> {
    compile_source(&mut CompilerSession::default(), "test.hell", source)
}

#[test]
fn requires_exact_main_io_unit() {
    let error = check("main = Int.plus 1 2\n").unwrap_err();
    assert!(error.0.iter().any(|diagnostic| diagnostic.code == "H0702"));
}

#[test]
fn global_templates_are_instantiated_per_use() {
    check(
        "id = \\x -> x\nmain = do\n  IO.pure (Main.id 1)\n  IO.pure (Main.id \"text\")\n  IO.pure ()\n",
    )
    .unwrap();
}

#[test]
fn unreachable_type_mismatch_is_not_inferred() {
    check("bad = Int.plus \"wrong\" 1\nmain = IO.pure ()\n").unwrap();
}

#[test]
fn unreachable_unknown_name_and_cycle_are_rejected() {
    assert!(check("bad = Nope.missing\nmain = IO.pure ()\n").is_err());
    assert!(check("loop = Main.loop\nmain = IO.pure ()\n").is_err());
}

#[test]
fn missing_show_instance_is_a_static_error() {
    let error = check("main = IO.print ((\\x -> x) :: Int -> Int)\n").unwrap_err();
    assert!(error.0.iter().any(|diagnostic| diagnostic.code == "H0507"));
}

#[test]
fn pinned_show_instances_include_pairs_but_not_larger_tuples() {
    check("main = IO.print (1, 2)\n").unwrap();
    let error = check("main = IO.print (1, 2, 3)\n").unwrap_err();
    assert!(error.0.iter().any(|diagnostic| diagnostic.code == "H0507"));
}

#[test]
fn tuple_pattern_projects_each_component() {
    check("main = Text.putStrLn ((\\(x, y) -> y) (1, \"ok\"))\n").unwrap();
}

#[test]
fn record_construction_and_intrinsics_reach_verified_core() {
    check(
        "data Person = Person { name :: Text, age :: Int }\n\
         main = Text.putStrLn $ Record.get @\"name\" @Text \
         Main.Person { age = 23, name = \"Chris\" }\n",
    )
    .unwrap();
    check(
        "data Person = Person { name :: Text, age :: Int }\n\
         person = Main.Person { age = 23, name = \"Chris\" }\n\
         main = Text.putStrLn (Record.get @\"name\" Main.person)\n",
    )
    .unwrap();
    check(
        "data Person = Person { name :: Text, age :: Int }\n\
         person = Main.Person { age = 23, name = \"Chris\" }\n\
         changed = Record.modify @\"name\" Text.reverse (Record.set @\"age\" 24 Main.person)\n\
         main = Text.putStrLn (Record.get @\"name\" Main.changed)\n",
    )
    .unwrap();
}

#[test]
fn nested_record_get_preserves_field_type_ambiguity() {
    let error = check(concat!(
        "data Address = Address { line1 :: Text }\n",
        "data Person = Person { address :: Main.Address }\n",
        "person = Main.Person { address = Main.Address { line1 = \"home\" } }\n",
        "main = Text.putStrLn (Record.get @\"line1\" ",
        "(Record.get @\"address\" Main.person))\n",
    ))
    .unwrap_err();
    assert!(
        error.0.iter().any(|diagnostic| diagnostic.code == "H0602"),
        "unexpected diagnostics: {error:?}"
    );
    check(concat!(
        "data Address = Address { line1 :: Text }\n",
        "data Person = Person { address :: Main.Address }\n",
        "person = Main.Person { address = Main.Address { line1 = \"home\" } }\n",
        "main = Text.putStrLn $ Record.get @\"line1\" $ ",
        "Record.get @\"address\" @Main.Address Main.person\n",
    ))
    .unwrap();
}

#[test]
fn record_construction_reports_duplicate_missing_and_unexpected_fields() {
    for (source, code) in [
        (
            "data Pair = Pair { left :: Int, right :: Int }\n\
             pair = Main.Pair { left = 1, left = 2, right = 3 }\n\
             main = IO.pure ()\n",
            "H0603",
        ),
        (
            "data Pair = Pair { left :: Int, right :: Int }\n\
             main = IO.pure (Main.Pair { left = 1 })\n",
            "H0604",
        ),
        (
            "data Pair = Pair { left :: Int, right :: Int }\n\
             main = IO.pure (Main.Pair { left = 1, right = 2, middle = 3 })\n",
            "H0605",
        ),
    ] {
        let error = check(source).unwrap_err();
        assert!(
            error.0.iter().any(|diagnostic| diagnostic.code == code),
            "expected {code}, got {error:?}"
        );
    }
}

#[test]
fn generic_record_construction_fallback_accepts_maybe_just() {
    check("main = do\n  IO.pure (Maybe.Just { x = 1 })\n  IO.pure ()\n").unwrap();
}

#[test]
fn list_traversal_aliases_are_available_in_both_namespaces() {
    check(concat!(
        "main = do\n",
        "  Monad.mapM_ IO.print [1, 2]\n",
        "  IO.forM_ [3, 4] IO.print\n",
    ))
    .unwrap();
}

#[test]
fn user_sum_construction_and_exhaustive_case_reach_verified_core() {
    check(
        "data Answer = No | Yes Text\n\
         answer = Main.Yes \"ok\"\n\
         main = case Main.answer of\n\
           No -> IO.pure ()\n\
           Yes message -> Text.putStrLn message\n",
    )
    .unwrap();
}

#[test]
fn user_case_preserves_the_canonical_prefix_wildcard_quirk() {
    check(
        "data Choice = C | A | B\n\
         choice = Main.B\n\
         main = case Main.choice of\n\
           A -> IO.pure ()\n\
           _ -> IO.pure ()\n",
    )
    .unwrap();
    let error = check(
        "data Choice = C | A | B\n\
         choice = Main.B\n\
         main = case Main.choice of\n\
           B -> IO.pure ()\n\
           _ -> IO.pure ()\n",
    )
    .unwrap_err();
    assert!(error.0.iter().any(|diagnostic| diagnostic.code == "H0502"));
}

#[test]
fn bool_primitive_case_lowers_through_the_lazy_eliminator() {
    check(
        "main = case Bool.True of\n\
           Bool.False -> IO.pure ()\n\
           Bool.True -> IO.pure ()\n",
    )
    .unwrap();
    check(
        "main = case Maybe.Just \"ok\" of\n\
           Maybe.Nothing -> IO.pure ()\n\
           Maybe.Just value -> Text.putStrLn value\n",
    )
    .unwrap();
}

#[test]
fn remaining_primitive_case_families_reach_verified_core() {
    for source in [
        "main = case Either.Left \"ok\" of\n\
           Either.Left value -> Text.putStrLn value\n\
           Either.Right code -> Error.error (Int.show code)\n",
        "main = case Exit.ExitSuccess of\n\
           Exit.ExitSuccess -> IO.pure ()\n\
           Exit.ExitFailure code -> Error.error (Int.show code)\n",
        "main = case These.That \"ok\" of\n\
           These.This code -> Error.error (Int.show code)\n\
           These.That value -> Text.putStrLn value\n\
           These.These code value -> Error.error value\n",
        "main = case Json.Number 1.5 of\n\
           Json.Null -> IO.pure ()\n\
           Json.Bool flag -> IO.print flag\n\
           Json.String value -> Text.putStrLn value\n\
           Json.Number number -> IO.print number\n\
           Json.Array values -> Error.error \"array\"\n\
           Json.Object object -> Error.error \"object\"\n",
    ] {
        check(source).unwrap();
    }
}

#[test]
fn every_remaining_primitive_constructor_reaches_verified_core() {
    check(
        "main = do\n\
           IO.pure (Either.Right \"ok\" :: Either Int Text)\n\
           IO.pure Exit.ExitSuccess\n\
           IO.pure (Exit.ExitFailure 1)\n\
           IO.pure (These.This 1 :: These Int Text)\n\
           IO.pure (These.That \"ok\" :: These Int Text)\n\
           IO.pure (These.These 1 \"ok\")\n\
           IO.pure Json.Null\n\
           IO.pure (Json.Bool Bool.True)\n\
           IO.pure (Json.String \"ok\")\n\
           IO.pure (Json.Number 1.5)\n\
           IO.pure (Json.Array (Error.error \"unused\" :: Vector Value))\n\
           IO.pure (Json.Object (Error.error \"unused\" :: Map Text Value))\n\
           IO.pure ()\n",
    )
    .unwrap();
}

#[test]
fn primitive_case_family_arity_and_coverage_errors_are_preserved() {
    for (source, code) in [
        (
            "main = case Either.Left 1 of\n\
               Either.Left value -> IO.pure ()\n\
               Maybe.Nothing -> IO.pure ()\n",
            "H0614",
        ),
        (
            "main = case These.These 1 2 of\n\
               These.This value -> IO.pure ()\n\
               These.That value -> IO.pure ()\n\
               These.These value -> IO.pure ()\n",
            "H0611",
        ),
        (
            "main = case Json.Null of\n\
               Json.Null -> IO.pure ()\n",
            "H0615",
        ),
    ] {
        let error = check(source).unwrap_err();
        assert!(
            error.0.iter().any(|diagnostic| diagnostic.code == code),
            "expected {code}, got {error:?}"
        );
    }
}

#[test]
fn data_declaration_duplicates_and_cycles_are_rejected() {
    for (source, code) in [
        (
            "data Bad = Bad { value :: Int, value :: Text }\nmain = IO.pure ()\n",
            "H0304",
        ),
        (
            "data Left = Left { right :: Main.Right }\n\
             data Right = Right { left :: Main.Left }\n\
             main = IO.pure ()\n",
            "H0311",
        ),
        (
            "data First = Same { value :: Int }\n\
             data Second = Same { value :: Int }\n\
             main = IO.pure ()\n",
            "H0303",
        ),
    ] {
        let error = check(source).unwrap_err();
        assert!(
            error.0.iter().any(|diagnostic| diagnostic.code == code),
            "expected {code}, got {error:?}"
        );
    }
}

#[test]
fn concurrency_primitives_reach_verified_core_at_their_public_types() {
    for source in [
        "main = Concurrent.threadDelay 0\n",
        "main = do\n  Timeout.timeout 1 (IO.pure 1)\n  IO.pure ()\n",
        "main = do\n  Async.concurrently (IO.pure 1) (IO.pure \"right\")\n  IO.pure ()\n",
        "main = do\n  Async.race (IO.pure 1) (IO.pure \"right\")\n  IO.pure ()\n",
        "main = do\n  Async.pooledMapConcurrently (\\value -> IO.pure value) [1]\n  IO.pure ()\n",
        "main = do\n  Async.pooledForConcurrently [1] (\\value -> IO.pure value)\n  IO.pure ()\n",
        "main = Async.pooledMapConcurrently_ (\\_ -> IO.pure ()) [1]\n",
        "main = Async.pooledForConcurrently_ [1] (\\_ -> IO.pure ())\n",
    ] {
        check(source).unwrap();
    }
}

#[test]
fn upstream_compilation_removes_sandbox_caps_and_stats_are_opt_in() {
    let source = "main = IO.pure ()\n";
    let mut session = CompilerSession::upstream();
    assert_eq!(
        session.config.profile,
        hell_compiler::CompilerProfile::Upstream
    );
    assert_eq!(session.config.limits.max_expansion_depth, None);
    assert_eq!(session.config.limits.max_elaborated_nodes, None);
    assert_eq!(session.config.limits.source_bytes, Limit::Unlimited);
    assert_eq!(session.config.limits.tokens, Limit::Unlimited);
    assert_eq!(session.config.limits.syntax_nodes, Limit::Unlimited);
    assert_eq!(session.config.limits.nesting, Limit::Unlimited);
    assert_eq!(session.config.limits.type_constraints, Limit::Unlimited);
    assert_eq!(session.config.limits.core_nodes, Limit::Unlimited);
    compile_source(&mut session, "stats-disabled.hell", source).unwrap();
    assert!(session.stats.timings.is_empty());
    assert_eq!(session.stats.parsed_declarations, 0);
    assert_eq!(session.stats.elaborated_nodes, 0);
    assert_eq!(session.stats.global_expansions, 0);

    session.enable_stats();
    compile_source(&mut session, "stats-enabled.hell", source).unwrap();
    assert!(!session.stats.timings.is_empty());
    assert_ne!(session.stats.parsed_declarations, 0);
    assert_ne!(session.stats.elaborated_nodes, 0);
    assert_ne!(session.stats.global_expansions, 0);
}

#[test]
fn compiler_resource_limits_report_operation_profile_and_amounts() {
    let cases = [
        (
            "source",
            Limit::At(1),
            Limit::Unlimited,
            Limit::Unlimited,
            Limit::Unlimited,
        ),
        (
            "syntax",
            Limit::Unlimited,
            Limit::Unlimited,
            Limit::At(1),
            Limit::Unlimited,
        ),
        (
            "constraints",
            Limit::Unlimited,
            Limit::Unlimited,
            Limit::Unlimited,
            Limit::At(0),
        ),
        (
            "core",
            Limit::Unlimited,
            Limit::Unlimited,
            Limit::Unlimited,
            Limit::Unlimited,
        ),
    ];
    for (label, source_bytes, tokens, syntax_nodes, type_constraints) in cases {
        let mut session = CompilerSession::default();
        session.config.limits.source_bytes = source_bytes;
        session.config.limits.tokens = tokens;
        session.config.limits.syntax_nodes = syntax_nodes;
        session.config.limits.type_constraints = type_constraints;
        if label == "core" {
            session.config.limits.core_nodes = Limit::At(0);
        }
        let error = compile_source(
            &mut session,
            format!("{label}-limit.hell"),
            "main = IO.pure ()\n",
        )
        .unwrap_err();
        assert_eq!(error.0.len(), 1, "{label}: {error:?}");
        assert_eq!(error.0[0].code, "H0802", "{label}: {error:?}");
        let message = error.0[0].message.as_ref();
        assert!(message.contains("operation="), "{label}: {message}");
        assert!(message.contains("profile=sandboxed"), "{label}: {message}");
        assert!(message.contains("configured="), "{label}: {message}");
        assert!(message.contains("observed="), "{label}: {message}");
    }

    let mut token_session = CompilerSession::default();
    token_session.config.limits.tokens = Limit::At(1);
    let error = compile_source(
        &mut token_session,
        "token-limit.hell",
        "main = IO.pure ()\n",
    )
    .unwrap_err();
    assert_eq!(error.0[0].code, "H0802");
    assert!(error.0[0].message.contains("operation=parse_tokens"));
}

#[test]
fn upstream_compiles_deep_application_and_lambda_spines_on_the_calling_stack() {
    const APPLICATION_DEPTH: usize = 2_048;
    const LAMBDA_DEPTH: usize = 4_096;
    let mut session = CompilerSession::upstream();
    let applications = format!(
        "main = IO.pure ({}(){})\n",
        "Function.id (".repeat(APPLICATION_DEPTH),
        ")".repeat(APPLICATION_DEPTH)
    );
    compile_source(&mut session, "deep-applications.hell", applications).unwrap();

    let lambdas = format!(
        "deep = {}()\nmain = IO.pure (Main.deep {})\n",
        "\\_ -> ".repeat(LAMBDA_DEPTH),
        "() ".repeat(LAMBDA_DEPTH)
    );
    compile_source(&mut session, "deep-lambdas.hell", lambdas).unwrap();
}

#[test]
fn deep_static_failure_remains_a_structured_compiler_diagnostic() {
    const DEPTH: usize = 2_048;
    let mut session = CompilerSession::upstream();
    let source = format!(
        "main = IO.pure ({}Missing.value{})\n",
        "Function.id (".repeat(DEPTH),
        ")".repeat(DEPTH)
    );
    let error = compile_source(&mut session, "deep-static-error.hell", source).unwrap_err();
    assert_eq!(
        error
            .0
            .iter()
            .filter(|diagnostic| diagnostic.code == "H0403")
            .count(),
        1
    );
}

#[test]
fn global_alias_expansion_is_iterative_and_keeps_the_sandbox_budget() {
    use std::fmt::Write as _;

    const DEPTH: usize = 2_048;
    let mut source = String::new();
    writeln!(source, "alias0 = IO.pure ()").unwrap();
    for index in 1..DEPTH {
        writeln!(source, "alias{index} = Main.alias{}", index - 1).unwrap();
    }
    writeln!(source, "main = Main.alias{}", DEPTH - 1).unwrap();

    compile_source(
        &mut CompilerSession::upstream(),
        "deep-global-aliases.hell",
        source.as_str(),
    )
    .unwrap();
    let error = compile_source(
        &mut CompilerSession::default(),
        "bounded-global-aliases.hell",
        source,
    )
    .unwrap_err();
    assert_eq!(
        error
            .0
            .iter()
            .filter(|diagnostic| diagnostic.code == "H0407")
            .count(),
        1
    );
}

#[test]
fn deep_list_inference_and_class_resolution_are_iterative() {
    const DEPTH: usize = 2_048;
    let source = format!(
        "main = IO.print {}1{}\n",
        "[".repeat(DEPTH),
        "]".repeat(DEPTH)
    );
    compile_source(
        &mut CompilerSession::upstream(),
        "deep-list-instance.hell",
        source,
    )
    .unwrap();
}

#[test]
fn deep_case_and_record_elaboration_use_heap_worklists() {
    use std::fmt::Write as _;

    const DEPTH: usize = 2_048;
    let cases = format!(
        "main = {}IO.pure (){}\n",
        "case Bool.True of { Bool.False -> IO.pure (); Bool.True -> ".repeat(DEPTH),
        " }".repeat(DEPTH)
    );
    compile_source(&mut CompilerSession::upstream(), "deep-cases.hell", cases).unwrap();

    let mut records = String::new();
    writeln!(records, "data R0 = R0 {{ value :: Int }}").unwrap();
    for index in 1..DEPTH {
        writeln!(
            records,
            "data R{index} = R{index} {{ value :: Main.R{} }}",
            index - 1
        )
        .unwrap();
    }
    records.push_str("main = do { IO.pure (");
    for index in (0..DEPTH).rev() {
        write!(records, "Main.R{index} {{ value = ").unwrap();
    }
    records.push('1');
    records.push_str(&" }".repeat(DEPTH));
    records.push_str("); IO.pure () }\n");
    compile_source(
        &mut CompilerSession::upstream(),
        "deep-records.hell",
        records,
    )
    .unwrap();
}

#[test]
fn deep_case_binder_scopes_use_heap_worklists() {
    const DEPTH: usize = 2_048;
    let source = format!(
        "main = case Maybe.Just 1 of {{ Maybe.Nothing -> IO.pure (); Maybe.Just value -> {}IO.print value{}\n",
        "case Maybe.Just value of { Maybe.Nothing -> IO.pure (); Maybe.Just value -> "
            .repeat(DEPTH - 1),
        " }".repeat(DEPTH)
    );
    compile_source(
        &mut CompilerSession::upstream(),
        "deep-bound-cases.hell",
        source,
    )
    .unwrap();
}

#[test]
fn deep_case_failure_is_structured() {
    const DEPTH: usize = 2_048;
    let source = format!(
        "main = {}Missing.value{}\n",
        "case Bool.True of { Bool.False -> IO.pure (); Bool.True -> ".repeat(DEPTH),
        " }".repeat(DEPTH)
    );
    let error = compile_source(
        &mut CompilerSession::upstream(),
        "deep-case-error.hell",
        source,
    )
    .unwrap_err();
    assert_eq!(
        error
            .0
            .iter()
            .filter(|diagnostic| diagnostic.code == "H0403")
            .count(),
        1
    );
}

fn mixed_io_expression(depth: usize, leaf: &str) -> String {
    let mut source = String::from("main = ");
    let mut suffixes = Vec::with_capacity(depth);
    for index in 0..depth {
        let (prefix, suffix) = match index % 5 {
            0 => ("if Bool.True then ", " else IO.pure ()"),
            1 => ("do { ", " }"),
            2 => ("(", " :: IO ())"),
            3 => ("do { IO.pure (1, 2); ", " }"),
            _ => ("do { IO.pure [1]; ", " }"),
        };
        source.push_str(prefix);
        suffixes.push(suffix);
    }
    source.push_str(leaf);
    for suffix in suffixes.into_iter().rev() {
        source.push_str(suffix);
    }
    source.push('\n');
    source
}

#[test]
fn deep_if_tuple_do_annotation_and_mixed_inference_is_iterative() {
    const DEPTH: usize = 2_048;
    let nested_if = format!(
        "main = {}IO.pure (){}\n",
        "if Bool.True then ".repeat(DEPTH),
        " else IO.pure ()".repeat(DEPTH)
    );
    compile_source(&mut CompilerSession::upstream(), "deep-if.hell", nested_if).unwrap();

    let tuple = format!(
        "main = do {{ IO.pure ({}(){}); IO.pure () }}\n",
        "1, (".repeat(DEPTH),
        ")".repeat(DEPTH)
    );
    compile_source(&mut CompilerSession::upstream(), "deep-tuple.hell", tuple).unwrap();

    compile_source(
        &mut CompilerSession::upstream(),
        "deep-mixed.hell",
        mixed_io_expression(DEPTH, "IO.pure ()"),
    )
    .unwrap();
}

#[test]
fn deep_mixed_inference_failure_is_structured() {
    const DEPTH: usize = 2_048;
    let error = compile_source(
        &mut CompilerSession::upstream(),
        "deep-mixed-error.hell",
        mixed_io_expression(DEPTH, "Missing.value"),
    )
    .unwrap_err();
    assert_eq!(
        error
            .0
            .iter()
            .filter(|diagnostic| diagnostic.code == "H0403")
            .count(),
        1
    );
}

#[test]
fn deep_do_let_and_bind_scopes_use_heap_worklists() {
    const DEPTH: usize = 1_024;
    let mut source = String::from("main = do { let value = 1; ");
    for index in 1..DEPTH {
        if index % 2 == 0 {
            source.push_str("do { let value = value; ");
        } else {
            source.push_str("do { value <- IO.pure value; ");
        }
    }
    source.push_str("IO.print value");
    source.push_str(&" }".repeat(DEPTH));
    source.push('\n');
    compile_source(
        &mut CompilerSession::upstream(),
        "deep-do-scopes.hell",
        source,
    )
    .unwrap();
}
