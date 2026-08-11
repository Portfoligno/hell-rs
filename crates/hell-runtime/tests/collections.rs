use std::io::Write;
#[cfg(feature = "mutation-testing")]
use std::process::{Command, ExitStatus};
use std::sync::{Arc, Mutex};

use hell_compiler::{CompilerSession, compile_source};
use hell_runtime::{RuntimeContext, run_main};

#[derive(Clone)]
struct SharedWriter(Arc<Mutex<Vec<u8>>>);

impl Write for SharedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn run(source: &str) -> String {
    let program = compile_source(&mut CompilerSession::default(), "collections.hell", source)
        .expect("collection source compiles");
    let bytes = Arc::new(Mutex::new(Vec::new()));
    run_main(
        program,
        RuntimeContext::new(Vec::new(), SharedWriter(Arc::clone(&bytes))),
    )
    .unwrap();
    String::from_utf8(bytes.lock().unwrap().clone()).unwrap()
}

#[test]
fn map_operations_preserve_key_order_duplicate_bias_and_callback_order() {
    assert_eq!(
        run(concat!(
            "base = Map.fromList [(3, \"c\"), (1, \"old\"), (2, \"b\"), (1, \"a\")]\n",
            "main = do\n",
            "  IO.print $ Map.toList Main.base\n",
            "  IO.print $ Map.lookup 2 Main.base\n",
            "  IO.print $ Map.lookup 9 Main.base\n",
            "  IO.print $ Map.toList $ Map.insert 0 \"z\" Main.base\n",
            "  IO.print $ Map.toList $ Map.delete 2 Main.base\n",
            "  IO.print $ Map.toList $ Map.singleton 4 \"d\"\n",
            "  IO.print $ Map.size Main.base\n",
            "  IO.print $ Map.toList $ Map.filter (Text.eq \"a\") Main.base\n",
            "  IO.print $ Map.toList $ Map.filterWithKey (\\key _ -> Ord.lt key 3) Main.base\n",
            "  IO.print $ Map.any (Text.eq \"b\") Main.base\n",
            "  IO.print $ Map.all (\\_ -> Bool.True) Main.base\n",
            "  IO.print $ Map.toList $ Map.insertWith (\\new old -> new <> old)\n",
            "    2 \"N\" Main.base\n",
            "  IO.print $ Map.toList $ Map.adjust Text.toUpper 3 Main.base\n",
            "  IO.print $ Map.toList $ Map.unionWith (\\left right -> left <> right)\n",
            "    Main.base (Map.fromList [(2, \"R\"), (4, \"d\")])\n",
            "  IO.print $ Map.toList $ Map.map Text.toUpper Main.base\n",
            "  IO.print $ Map.keys Main.base\n",
            "  IO.print $ Map.elems Main.base\n",
        )),
        concat!(
            "[(1,\"a\"),(2,\"b\"),(3,\"c\")]\n",
            "Just \"b\"\n",
            "Nothing\n",
            "[(0,\"z\"),(1,\"a\"),(2,\"b\"),(3,\"c\")]\n",
            "[(1,\"a\"),(3,\"c\")]\n",
            "[(4,\"d\")]\n",
            "3\n",
            "[(1,\"a\")]\n",
            "[(1,\"a\"),(2,\"b\")]\n",
            "True\n",
            "True\n",
            "[(1,\"a\"),(2,\"Nb\"),(3,\"c\")]\n",
            "[(1,\"a\"),(2,\"b\"),(3,\"C\")]\n",
            "[(1,\"a\"),(2,\"bR\"),(3,\"c\"),(4,\"d\")]\n",
            "[(1,\"A\"),(2,\"B\"),(3,\"C\")]\n",
            "[1,2,3]\n",
            "[\"a\",\"b\",\"c\"]\n",
        )
    );
}

#[test]
fn map_from_list_consumes_ord_comparators_and_preserves_unordered_fallback() {
    assert_eq!(
        run(concat!(
            "main = do\n",
            "  IO.print $ Map.toList $ Map.fromList [(1,\"a\"),(2,\"b\")]\n",
            "  IO.print $ Map.size $ Map.fromList [(1,\"old\"),(1,\"new\")]\n",
        )),
        "[(1,\"a\"),(2,\"b\")]\n1\n"
    );
}

#[cfg(not(feature = "compat-tracing"))]
#[test]
fn map_from_list_preserves_nan_unordered_fallback() {
    assert_eq!(
        run(concat!(
            "nan = case Double.readMaybe \"NaN\" of { Maybe.Just value -> value; Maybe.Nothing -> 0.0 }\n",
            "main = IO.print $ Map.size $ Map.fromList [(Main.nan,\"first\"),(Main.nan,\"last\")]\n",
        )),
        "2\n"
    );
}

#[test]
fn map_size_balancing_matches_pinned_nan_routing() {
    assert_eq!(
        run(concat!(
            "nan = Maybe.maybe (Error.error \"nan\") Function.id $ Double.readMaybe \"NaN\"\n",
            "base = Map.fromList [(Main.nan,\"nan\"),(1.0,\"one\"),(2.0,\"two\"),",
            "(3.0,\"three\"),(4.0,\"four\"),(5.0,\"five\")]\n",
            "main = do\n",
            "  IO.print $ Map.toList Main.base\n",
            "  IO.print $ Map.lookup Main.nan Main.base\n",
            "  IO.print $ Map.lookup 1.0 Main.base\n",
            "  IO.print $ Map.lookup 2.0 Main.base\n",
            "  IO.print $ Map.lookup 3.0 Main.base\n",
            "  IO.print $ Map.lookup 4.0 Main.base\n",
            "  IO.print $ Map.lookup 5.0 Main.base\n",
            "  IO.print $ Map.toList $ Map.delete 3.0 Main.base\n",
            "  IO.print $ Map.toList $ Map.insert 0.0 \"zero\" Main.base\n",
        )),
        concat!(
            "[(NaN,\"nan\"),(1.0,\"one\"),(2.0,\"two\"),(3.0,\"three\"),",
            "(4.0,\"four\"),(5.0,\"five\")]\n",
            "Nothing\n",
            "Just \"one\"\n",
            "Just \"two\"\n",
            "Just \"three\"\n",
            "Just \"four\"\n",
            "Just \"five\"\n",
            "[(NaN,\"nan\"),(1.0,\"one\"),(2.0,\"two\"),(4.0,\"four\"),",
            "(5.0,\"five\")]\n",
            "[(NaN,\"nan\"),(0.0,\"zero\"),(1.0,\"one\"),(2.0,\"two\"),",
            "(3.0,\"three\"),(4.0,\"four\"),(5.0,\"five\")]\n",
        )
    );
}

#[test]
fn map_builder_matches_pinned_long_nan_routing() {
    assert_eq!(
        run(concat!(
            "nan = Maybe.maybe (Error.error \"nan\") Function.id $ Double.readMaybe \"NaN\"\n",
            "base = Map.fromList [(1.0,\"one\"),(2.0,\"two\"),(3.0,\"three\"),",
            "(Main.nan,\"nan-a\"),(4.0,\"four\"),(5.0,\"five\"),",
            "(Main.nan,\"nan-b\"),(6.0,\"six\"),(0.0,\"zero\")]\n",
            "main = do\n",
            "  IO.print $ Map.toList Main.base\n",
            "  IO.print $ Map.lookup Main.nan Main.base\n",
            "  IO.print $ Map.lookup 0.0 Main.base\n",
            "  IO.print $ Map.lookup 3.0 Main.base\n",
            "  IO.print $ Map.lookup 6.0 Main.base\n",
            "  IO.print $ Map.toList $ Map.delete Main.nan Main.base\n",
            "  IO.print $ Map.toList $ Map.delete 3.0 Main.base\n",
            "  IO.print $ Map.toList $ Map.insert Main.nan \"nan-c\" Main.base\n",
            "  IO.print $ Map.toList $ Map.insert 2.5 \"middle\" Main.base\n",
        )),
        concat!(
            "[(1.0,\"one\"),(2.0,\"two\"),(3.0,\"three\"),(NaN,\"nan-a\"),",
            "(0.0,\"zero\"),(4.0,\"four\"),(5.0,\"five\"),(NaN,\"nan-b\"),",
            "(6.0,\"six\")]\n",
            "Nothing\n",
            "Just \"zero\"\n",
            "Nothing\n",
            "Just \"six\"\n",
            "[(1.0,\"one\"),(2.0,\"two\"),(3.0,\"three\"),(NaN,\"nan-a\"),",
            "(0.0,\"zero\"),(4.0,\"four\"),(5.0,\"five\"),(NaN,\"nan-b\"),",
            "(6.0,\"six\")]\n",
            "[(1.0,\"one\"),(2.0,\"two\"),(3.0,\"three\"),(NaN,\"nan-a\"),",
            "(0.0,\"zero\"),(4.0,\"four\"),(5.0,\"five\"),(NaN,\"nan-b\"),",
            "(6.0,\"six\")]\n",
            "[(1.0,\"one\"),(2.0,\"two\"),(3.0,\"three\"),(NaN,\"nan-a\"),",
            "(0.0,\"zero\"),(4.0,\"four\"),(5.0,\"five\"),(NaN,\"nan-b\"),",
            "(6.0,\"six\"),(NaN,\"nan-c\")]\n",
            "[(1.0,\"one\"),(2.0,\"two\"),(3.0,\"three\"),(NaN,\"nan-a\"),",
            "(0.0,\"zero\"),(2.5,\"middle\"),(4.0,\"four\"),(5.0,\"five\"),",
            "(NaN,\"nan-b\"),(6.0,\"six\")]\n",
        )
    );
}

#[cfg(feature = "mutation-testing")]
fn run_map_comparator_test(mutant: Option<&str>) -> ExitStatus {
    let mut command = Command::new(std::env::current_exe().expect("collections test executable"));
    command
        .arg("map_from_list_consumes_ord_comparators_and_preserves_unordered_fallback")
        .arg("--exact")
        .env_remove("HELL_ASSURANCE_MUTANT_ID");
    if let Some(mutant) = mutant {
        command.env("HELL_ASSURANCE_MUTANT_ID", mutant);
    }
    command.status().expect("nested collections test runs")
}

#[cfg(feature = "mutation-testing")]
#[test]
fn map_ordering_test_detects_comparator_substitution() {
    assert!(run_map_comparator_test(None).success());
    assert!(
        !run_map_comparator_test(Some("ordering-comparator-constant-true")).success(),
        "constant comparator survived Map.fromList ordering evidence"
    );
}

#[test]
fn map_callbacks_are_lazy_when_their_result_is_unneeded() {
    assert_eq!(
        run(concat!(
            "base = Map.fromList [(1, \"first\"), (2, Error.error \"late value\")]\n",
            "main = do\n",
            "  IO.print $ Map.lookup 9 Main.base\n",
            "  IO.print $ Map.size $ Map.insertWith (Error.error \"unused combine\")\n",
            "    3 \"new\" Main.base\n",
            "  IO.print $ Map.size $ Map.adjust (Error.error \"unused adjust\") 9 Main.base\n",
            "  IO.print $ Map.any (\\value -> if Text.eq value \"first\"\n",
            "    then Bool.True else Error.error \"late predicate\") Main.base\n",
        )),
        "Nothing\n3\n2\nTrue\n"
    );
}

#[test]
fn set_operations_are_sorted_deduplicated_and_have_structural_instances() {
    assert_eq!(
        run(concat!(
            "base = Set.fromList [3, 1, 2, 1]\n",
            "other = Set.fromList [2, 4]\n",
            "main = do\n",
            "  IO.print $ Set.toList Main.base\n",
            "  IO.print $ Set.toList $ Set.insert 0 Main.base\n",
            "  IO.print $ Set.member 2 Main.base\n",
            "  IO.print $ Set.member 9 Main.base\n",
            "  IO.print $ Set.toList $ Set.delete 2 Main.base\n",
            "  IO.print $ Set.toList $ Set.union Main.base Main.other\n",
            "  IO.print $ Set.toList $ Set.difference Main.base Main.other\n",
            "  IO.print $ Set.toList $ Set.intersection Main.base Main.other\n",
            "  IO.print $ Set.size Main.base\n",
            "  IO.print $ Set.singleton 5\n",
            "  IO.print $ Eq.eq Main.base (Set.fromList [2, 3, 1])\n",
            "  IO.print $ Ord.lt (Set.fromList [1, 2]) (Set.fromList [1, 3])\n",
        )),
        concat!(
            "[1,2,3]\n",
            "[0,1,2,3]\n",
            "True\n",
            "False\n",
            "[1,3]\n",
            "[1,2,3,4]\n",
            "[1,3]\n",
            "[2]\n",
            "3\n",
            "fromList [5]\n",
            "True\n",
            "True\n",
        )
    );
}

#[test]
fn vector_and_exit_code_ordering_are_lexicographic_and_constructor_sensitive() {
    assert_eq!(
        run(concat!(
            "main = do\n",
            "  IO.print $ Ord.lt (Vector.fromList [1,2]) (Vector.fromList [1,3])\n",
            "  IO.print $ Ord.gt (Vector.fromList [1,3]) (Vector.fromList [1,2])\n",
            "  IO.print $ Ord.lt Exit.ExitSuccess (Exit.ExitFailure 1)\n",
            "  IO.print $ Ord.gt (Exit.ExitFailure 2) (Exit.ExitFailure 1)\n",
        )),
        "True\nTrue\nTrue\nTrue\n"
    );
}
