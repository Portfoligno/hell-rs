use hell_compiler::{CompilerSession, compile_source};

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
