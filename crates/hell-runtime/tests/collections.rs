use std::io::Write;
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
