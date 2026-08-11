use hell_builtins::{InstanceResolution, TypeClass};
use hell_compiler::{CompilerSession, compile_source};
use hell_core::CoreKind;

fn compile(source: &str) -> Result<(), hell_compiler::DiagnosticBundle> {
    compile_source(&mut CompilerSession::default(), "instances.hell", source).map(|_| ())
}

#[test]
fn compiler_retains_nested_branching_and_duplicate_sibling_evidence_plans() {
    let program = compile_source(
        &mut CompilerSession::default(),
        "instance-plans.hell",
        concat!(
            "main = IO.print ",
            "(Either.Left (Maybe.Just 1) :: Either (Maybe Int) (Int, Int))\n",
        ),
    )
    .expect("nested registered evidence should resolve");
    let executable = program.executable();
    let print = hell_builtins::lookup("IO.print").unwrap().id;
    let evidence = executable
        .nodes()
        .iter()
        .find_map(|node| match node.kind {
            CoreKind::Builtin {
                builtin,
                evidence: Some(evidence),
            } if builtin == print => Some(evidence),
            _ => None,
        })
        .expect("IO.print retains its Show evidence");
    assert_eq!(evidence.class, TypeClass::Show);
    let plans = executable.instance_evidence_plans();
    let root = &plans[evidence.plan.0 as usize];
    assert_eq!(
        executable.types().display(root.head),
        "Either (Maybe Int) ((,) Int Int)"
    );
    assert_eq!(root.resolution, InstanceResolution::Entail(2));
    let maybe = &plans[root.premises[0].0 as usize];
    let tuple = &plans[root.premises[1].0 as usize];
    assert_eq!(executable.types().display(maybe.head), "Maybe Int");
    assert_eq!(maybe.resolution, InstanceResolution::Entail(1));
    assert_eq!(executable.types().display(tuple.head), "(,) Int Int");
    assert_eq!(tuple.resolution, InstanceResolution::Entail(2));
    assert_eq!(maybe.premises[0], tuple.premises[0]);
    assert_eq!(tuple.premises[0], tuple.premises[1]);
    let integer = &plans[tuple.premises[0].0 as usize];
    assert_eq!(executable.types().display(integer.head), "Int");
    assert_eq!(integer.resolution, InstanceResolution::Direct(0));
}

#[test]
fn recursive_show_eq_and_ord_evidence_comes_from_the_instance_manifest() {
    compile(concat!(
        "main = do\n",
        "  IO.print [Either.Left (Maybe.Just 1), Either.Right (Maybe.Just \"x\")]\n",
        "  IO.print $ Eq.eq [Either.Left (Maybe.Just 1)] [Either.Right (Maybe.Just \"x\")]\n",
        "  IO.print $ Ord.lt [(Maybe.Just 1, \"a\")] [(Maybe.Just 2, \"b\")]\n",
    ))
    .expect("nested registered evidence should resolve");
}

#[test]
fn direct_parameterized_heads_do_not_invent_recursive_premises() {
    compile(concat!(
        "main = do\n",
        "  IO.pure $ (Either.Left (IO.pure ()) <> Either.Left (IO.pure ()) :: Either (IO ()) Text)\n",
        "  IO.pure ()\n",
    ))
    .expect("Semigroup Either is direct in both parameters");
}

#[test]
fn entailed_and_missing_instances_are_rejected_at_the_outer_use() {
    for source in [
        "main = IO.print (IO.pure ())\n",
        "main = IO.print $ Eq.eq [IO.pure ()] [IO.pure ()]\n",
        "main = IO.print $ Ord.lt [IO.pure ()] [IO.pure ()]\n",
        "main = do\n  IO.pure $ Maybe.Just (IO.pure ()) <> Maybe.Nothing\n  IO.pure ()\n",
    ] {
        let diagnostics = compile(source).expect_err("missing recursive evidence should fail");
        assert_eq!(diagnostics.0[0].code, "H0507", "{diagnostics:?}");
    }
}

#[test]
fn higher_kinded_class_heads_resolve_from_the_same_manifest() {
    compile(concat!(
        "main = do\n",
        "  IO.print $ Functor.fmap Int.show (Maybe.Just 1)\n",
        "  IO.print $ Applicative.pure @Maybe 2\n",
        "  IO.print $ Alternative.optional (Maybe.Just 3)\n",
        "  IO.print $ Monad.bind (Either.Right 4 :: Either Text Int)\n",
        "    (\\x -> Monad.return @Int @(Either Text) x)\n",
        "  Text.putStrLn $ CI.foldedCase $ CI.mk \"ABC\"\n",
    ))
    .expect("registered higher-kinded and FoldCase evidence should resolve");
}

#[test]
fn absent_higher_kinded_and_fold_case_heads_are_static_errors() {
    for source in [
        "main = do\n  let value = Functor.fmap Function.id (Vector.fromList [1])\n  IO.pure ()\n",
        "main = do\n  let value = Applicative.pure @Vector 1\n  IO.pure ()\n",
        "main = do\n  let value = Monad.return @Int @Vector 1\n  IO.pure ()\n",
        "main = do\n  let value = Alternative.optional (Either.Right 1 :: Either Text Int)\n  IO.pure ()\n",
        "main = do\n  let value = CI.mk 1\n  IO.pure ()\n",
    ] {
        let diagnostics = compile(source).expect_err("absent manifest head should fail");
        assert_eq!(diagnostics.0[0].code, "H0507", "{diagnostics:?}");
    }
}
