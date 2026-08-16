use std::io::Write;
use std::sync::{Arc, Mutex};

use hell_compiler::{CompilerSession, compile_source};
use hell_runtime::{
    RuntimeContext, RuntimeErrorKind, RuntimeErrorPresentation, RuntimeResult, run_main,
};

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
    let program = compile_source(&mut CompilerSession::default(), "lists.hell", source).unwrap();
    let bytes = Arc::new(Mutex::new(Vec::new()));
    run_main(
        program,
        RuntimeContext::new(Vec::new(), SharedWriter(Arc::clone(&bytes))),
    )
    .unwrap();
    String::from_utf8(bytes.lock().unwrap().clone()).unwrap()
}

fn run_result(source: &str) -> (RuntimeResult<()>, String) {
    let program = compile_source(&mut CompilerSession::default(), "lists.hell", source).unwrap();
    let bytes = Arc::new(Mutex::new(Vec::new()));
    let result = run_main(
        program,
        RuntimeContext::new(Vec::new(), SharedWriter(Arc::clone(&bytes))),
    );
    let output = String::from_utf8(bytes.lock().unwrap().clone()).unwrap();
    (result, output)
}

#[test]
fn cycle_empty_uses_the_pinned_base_origin_without_changing_user_error_identity() {
    let expected = concat!(
        "hell: Prelude.cycle: empty list\n",
        "CallStack (from HasCallStack):\n",
        "  error, called at libraries/base/GHC/List.hs:2004:3 in base:GHC.List\n",
        "  errorEmptyList, called at libraries/base/GHC/List.hs:972:27 in base:GHC.List\n",
        "  cycle, called at src/Hell.hs:1953:4 in main:Main",
    );
    for source in [
        "main = IO.print $ List.take 1 $ List.cycle ([] :: [Int])\n",
        "main = IO.print $ List.take 1 $ List.cycle $ List.drop 1 [1]\n",
    ] {
        let (result, output) = run_result(source);
        let error = result.expect_err("forcing an empty cycle must fail");
        assert!(output.is_empty());
        assert_eq!(error.code, "H0901");
        assert_eq!(error.kind, RuntimeErrorKind::UserError);
        assert_eq!(error.message.as_ref(), "List.cycle: empty list");
        assert_eq!(
            error.presentation,
            Some(RuntimeErrorPresentation::ListCycleEmpty)
        );
        assert_eq!(error.to_string(), expected);
    }

    assert_eq!(
        run(concat!(
            "main = do\n",
            "  IO.print $ List.take 3 $ List.cycle [7]\n",
            "  IO.print $ List.take 5 $ List.cycle [1,2]\n",
        )),
        "[7,7,7]\n[1,2,1,2,1]\n"
    );
}

#[test]
fn predicates_searches_and_spine_operations_match_the_pinned_list_surface() {
    let source = concat!(
        "main = do\n",
        "  IO.print $ List.all (\\x -> Bool.not $ Int.eq x 0) [1,2,3]\n",
        "  IO.print $ List.any (Int.eq 2) [0,2,0]\n",
        "  IO.print $ List.concat [[1,2],[],[3]]\n",
        "  IO.print $ List.dropWhile (Int.eq 0) [0,0,1,0]\n",
        "  IO.print $ List.elem 2 [1,2,3]\n",
        "  IO.print $ List.notElem 4 [1,2,3]\n",
        "  IO.print $ List.elemIndex 2 [1,2,2]\n",
        "  IO.print $ List.elemIndices 2 [2,1,2,2]\n",
        "  IO.print $ List.filter (\\x -> Bool.not $ Int.eq x 0) [0,1,0,2]\n",
        "  IO.print $ List.find (Int.eq 2) [1,2,3]\n",
        "  IO.print $ List.findIndex (Int.eq 2) [1,2,3]\n",
        "  IO.print $ List.findIndices (Int.eq 2) [2,1,2]\n",
        "  IO.print $ List.isPrefixOf [1,2] [1,2,3]\n",
        "  IO.print $ List.isSubsequenceOf [1,3] [1,2,3]\n",
        "  IO.print $ List.null ([] :: [Int])\n",
        "  IO.print $ List.takeWhile (\\x -> Bool.not $ Int.eq x 0) [1,2,0,3]\n",
        "  IO.print $ List.uncons [1,2]\n",
        "  IO.print $ List.zipWith Int.plus [1,2] [10,20,30]\n",
    );
    assert_eq!(
        run(source),
        concat!(
            "True\n",
            "True\n",
            "[1,2,3]\n",
            "[1,0]\n",
            "True\n",
            "True\n",
            "Just 1\n",
            "[0,2,3]\n",
            "[1,2]\n",
            "Just 2\n",
            "Just 1\n",
            "[0,2]\n",
            "True\n",
            "True\n",
            "True\n",
            "[1,2]\n",
            "Just (1,[2])\n",
            "[11,22]\n",
        )
    );
}

#[test]
fn repeat_filter_concat_and_drop_remain_productive_on_infinite_spines() {
    assert_eq!(
        run(concat!(
            "main = do\n",
            "  IO.print $ List.take 3 $ List.drop 2 $ List.repeat 7\n",
            "  IO.print $ List.take 3 $ List.filter (\\x -> Bool.True) $ List.repeat 1\n",
            "  IO.print $ List.take 4 $ List.concat [[1,2], List.repeat 3]\n",
            "  IO.print $ List.isPrefixOf ([] :: [Int]) (Error.error \"boom\" :: [Int])\n",
            "  IO.print $ List.zipWith Int.plus [] (Error.error \"boom\" :: [Int])\n",
            "  IO.print $ List.foldr (\\x _ -> x) (Error.error \"boom\" :: Int) $ List.repeat 1\n",
        )),
        "[7,7,7]\n[1,1,1]\n[1,2,3,3]\nTrue\n[]\n1\n"
    );
}

#[test]
fn structural_combinators_match_the_oracle_order_and_accumulator_quirks() {
    let source = concat!(
        "main = do\n",
        "  IO.print $ List.break (Int.eq 0) [1,0,2]\n",
        "  IO.print $ List.span (\\x -> Bool.not $ Int.eq x 0) [1,0,2]\n",
        "  IO.print $ List.concatMap (\\x -> [x,x]) [1,2]\n",
        "  IO.print $ List.take 5 $ List.cycle [1,2]\n",
        "  IO.print $ List.deleteBy Int.eq 2 [1,2,2]\n",
        "  IO.print $ List.dropWhileEnd (Int.eq 0) [0,1,0,0]\n",
        "  IO.print $ List.foldr Int.plus 0 [1,2,3]\n",
        "  IO.print $ List.group [1,1,2,1]\n",
        "  IO.print $ List.groupBy Int.eq [1,1,2,1]\n",
        "  IO.print $ List.inits [1,2]\n",
        "  IO.print $ List.intercalate [0] [[1],[2,3]]\n",
        "  IO.print $ List.intersperse 0 [1,2,3]\n",
        "  IO.print $ List.isInfixOf [2,3] [1,2,3]\n",
        "  IO.print $ List.isSuffixOf [2,3] [1,2,3]\n",
        "  IO.print $ List.mapAccumL (\\acc x -> (Int.plus acc x, acc)) 0 [1,2,3]\n",
        "  IO.print $ List.nubOrd [2,1,2,1,3]\n",
        "  IO.print $ List.partition (\\x -> Bool.not $ Int.eq x 0) [0,1,0,2]\n",
        "  IO.print $ List.permutations [1,2,3]\n",
        "  IO.print $ List.scanl' Int.plus 0 [1,2,3]\n",
        "  IO.print $ List.scanr Int.plus 0 [1,2,3]\n",
        "  IO.print $ List.sort [3,1,2,1]\n",
        "  IO.print $ List.splitAt 2 [1,2,3]\n",
        "  IO.print $ List.subsequences [1,2]\n",
        "  IO.print $ List.tails [1,2]\n",
        "  IO.print $ List.transpose [[1,2],[3],[4,5]]\n",
        "  IO.print $ List.unfoldr (\\x -> if Int.eq x 3 then Maybe.Nothing else Maybe.Just (x, Int.plus x 1)) 0\n",
    );
    assert_eq!(
        run(source),
        concat!(
            "([1],[0,2])\n",
            "([1],[0,2])\n",
            "[1,1,2,2]\n",
            "[1,2,1,2,1]\n",
            "[1,2]\n",
            "[0,1]\n",
            "6\n",
            "[[1,1],[2],[1]]\n",
            "[[1,1],[2],[1]]\n",
            "[[],[1],[1,2]]\n",
            "[1,0,2,3]\n",
            "[1,0,2,0,3]\n",
            "True\n",
            "True\n",
            "(6,[0,1,3])\n",
            "[2,1,3]\n",
            "([1,2],[0,0])\n",
            "[[1,2,3],[2,1,3],[3,2,1],[2,3,1],[3,1,2],[1,3,2]]\n",
            "[0,1,3,6]\n",
            "[6,5,3,0]\n",
            "[1,1,2,3]\n",
            "([1,2],[3])\n",
            "[[],[1],[2],[1,2]]\n",
            "[[1,2],[2],[]]\n",
            "[[1,3,4],[2,5]]\n",
            "[0,1,2]\n",
        )
    );
}

#[test]
fn nan_sorting_matches_the_reviewed_native_oracle_merge_algorithm() {
    let source = concat!(
        "nan = Maybe.maybe (Error.error \"nan\") Function.id $ Double.readMaybe \"NaN\"\n",
        "main = do\n",
        "  IO.print $ List.sort [Main.nan,1.25]\n",
        "  IO.print $ List.sort [1.25,Main.nan]\n",
        "  IO.print $ List.sort [Main.nan,1.25,Main.nan,1.75]\n",
        "  IO.print $ List.sortOn (\\(key, payload) -> key) ",
        "[(Main.nan,\"item-0\"),(1.25,\"item-1\"),(Main.nan,\"item-2\"),(1.75,\"item-3\")]\n",
    );
    let expected = match hell_builtins::native_oracle_list_sort() {
        hell_builtins::NativeOracleListSort::Ghc98Base419TwoWay => concat!(
            "[1.25,NaN]\n",
            "[NaN,1.25]\n",
            "[1.75,NaN,1.25,NaN]\n",
            "[(1.75,\"item-3\"),(NaN,\"item-2\"),(1.25,\"item-1\"),(NaN,\"item-0\")]\n",
        ),
        hell_builtins::NativeOracleListSort::Ghc912Base421FourWay => concat!(
            "[NaN,1.25]\n",
            "[1.25,NaN]\n",
            "[NaN,1.25,NaN,1.75]\n",
            "[(1.25,\"item-1\"),(1.75,\"item-3\"),(NaN,\"item-2\"),(NaN,\"item-0\")]\n",
        ),
    };
    assert_eq!(run(source), expected);
}

#[test]
fn shared_splits_and_combinatorial_producers_are_productive() {
    let source = concat!(
        "main = do\n",
        "  let (spanPrefix, _spanSuffix) = List.span (\\_ -> Bool.True) $ List.repeat 1\n",
        "  IO.print $ List.take 5 spanPrefix\n",
        "  let (_selected, rejected) = List.partition (\\_ -> Bool.False) $ List.repeat 2\n",
        "  IO.print $ List.take 5 rejected\n",
        "  IO.print $ List.take 1 $ List.map (List.take 5) $ List.group $ List.repeat 3\n",
        "  IO.print $ List.take 5 $ List.dropWhileEnd (Int.eq 0) $ List.repeat 4\n",
        "  IO.print $ List.take 3 $ List.nubOrd $ List.cycle [1,2,3]\n",
        "  IO.print $ List.take 1 $ List.scanr (\\x _ -> x) (Error.error \"seed\" :: Int) $ List.repeat 5\n",
        "  IO.print $ List.length $ List.take 1 $ List.subsequences (Error.error \"subsequences input\" :: [Int])\n",
        "  IO.print $ List.take 6 $ List.map (List.take 3) $ List.subsequences $ List.cycle [1,2,3]\n",
        "  IO.print $ List.length $ List.take 1 $ List.permutations (Error.error \"permutations input\" :: [Int])\n",
        "  IO.print $ List.take 6 $ List.map (List.take 3) $ List.permutations $ List.cycle [1,2,3]\n",
        "  IO.print $ List.take 1 $ List.map (List.take 5) $ List.transpose $ List.repeat [6,7]\n",
    );
    assert_eq!(
        run(source),
        concat!(
            "[1,1,1,1,1]\n",
            "[2,2,2,2,2]\n",
            "[[3,3,3,3,3]]\n",
            "[4,4,4,4,4]\n",
            "[1,2,3]\n",
            "[5]\n",
            "1\n",
            "[[],[1],[2],[1,2],[3],[1,3]]\n",
            "1\n",
            "[[1,2,3],[2,1,3],[3,2,1],[2,3,1],[3,1,2],[1,3,2]]\n",
            "[[6,6,6,6,6]]\n",
        )
    );
}
