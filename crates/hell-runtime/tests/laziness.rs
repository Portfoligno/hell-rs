use std::io::Write;
#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;
#[cfg(feature = "mutation-testing")]
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};
#[cfg(feature = "mutation-testing")]
use std::time::Duration;

use hell_compiler::{CompilerSession, compile_source};
use hell_runtime::{
    RuntimeContext, RuntimeDirectoryOperation, RuntimeError, RuntimeErrorKind,
    RuntimeErrorPresentation, RuntimeFileOperation, run_main,
};

#[cfg(target_os = "linux")]
const COPY_FILE_MISSING_PRESENTATION: &str = concat!(
    "hell: missing/source.txt: copyFile:atomicCopyFileContents:",
    "withReplacementFile:",
    "copyFileToHandle:openFileWithCloseOnExec: does not exist (No such file or directory)",
);
#[cfg(not(target_os = "linux"))]
const COPY_FILE_MISSING_PRESENTATION: &str = concat!(
    "hell: missing/source.txt: copyFile:atomicCopyFileContents:",
    "withReplacementFile:",
    "copyFileToHandle:openFdAt: does not exist (No such file or directory)",
);

#[cfg(target_os = "linux")]
const COPY_FILE_ALTERNATE_MISSING_PRESENTATION: &str = concat!(
    "hell: other-missing/other-source: copyFile:atomicCopyFileContents:",
    "withReplacementFile:",
    "copyFileToHandle:openFileWithCloseOnExec: does not exist (No such file or directory)",
);
#[cfg(not(target_os = "linux"))]
const COPY_FILE_ALTERNATE_MISSING_PRESENTATION: &str = concat!(
    "hell: other-missing/other-source: copyFile:atomicCopyFileContents:",
    "withReplacementFile:",
    "copyFileToHandle:openFdAt: does not exist (No such file or directory)",
);

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
    let program = compile_source(&mut CompilerSession::default(), "test.hell", source).unwrap();
    let bytes = Arc::new(Mutex::new(Vec::new()));
    run_main(
        program,
        RuntimeContext::new(Vec::new(), SharedWriter(Arc::clone(&bytes))),
    )
    .unwrap();
    let output = bytes.lock().unwrap().clone();
    String::from_utf8(output).unwrap()
}

fn run_with_input(source: &str, input: Vec<u8>) -> Vec<u8> {
    let program = compile_source(&mut CompilerSession::default(), "test.hell", source).unwrap();
    let bytes = Arc::new(Mutex::new(Vec::new()));
    let context = RuntimeContext::new(Vec::new(), SharedWriter(Arc::clone(&bytes)))
        .with_stdin(std::io::Cursor::new(input));
    run_main(program, context).unwrap();
    bytes.lock().unwrap().clone()
}

fn run_with_input_error(source: &str, input: Vec<u8>) -> Arc<RuntimeError> {
    let program = compile_source(&mut CompilerSession::default(), "test.hell", source).unwrap();
    let context =
        RuntimeContext::new(Vec::new(), Vec::<u8>::new()).with_stdin(std::io::Cursor::new(input));
    run_main(program, context).unwrap_err()
}

fn run_in(source: &str, cwd: PathBuf, allow_filesystem: bool) -> Result<String, String> {
    run_in_with_args(source, Vec::new(), cwd, allow_filesystem)
}

fn run_in_error(source: &str, cwd: PathBuf) -> Arc<RuntimeError> {
    let program = compile_source(&mut CompilerSession::default(), "test.hell", source).unwrap();
    run_main(
        program,
        RuntimeContext::with_host(Vec::new(), Vec::new(), Vec::<u8>::new(), cwd, true),
    )
    .unwrap_err()
}

fn run_in_with_args(
    source: &str,
    arguments: Vec<Arc<str>>,
    cwd: PathBuf,
    allow_filesystem: bool,
) -> Result<String, String> {
    let program = compile_source(&mut CompilerSession::default(), "test.hell", source).unwrap();
    let bytes = Arc::new(Mutex::new(Vec::new()));
    run_main(
        program,
        RuntimeContext::with_host(
            arguments,
            Vec::new(),
            SharedWriter(Arc::clone(&bytes)),
            cwd,
            allow_filesystem,
        ),
    )
    .map_err(|error| error.to_string())?;
    let output = bytes.lock().unwrap().clone();
    String::from_utf8(output).map_err(|error| error.to_string())
}

fn run_error(source: &str) -> Arc<RuntimeError> {
    let program = compile_source(&mut CompilerSession::default(), "test.hell", source).unwrap();
    run_main(program, RuntimeContext::new(Vec::new(), Vec::<u8>::new())).unwrap_err()
}

#[test]
fn show_text_and_character_match_pinned_haskell_literal_escaping() {
    let source = r#"main = do
  IO.print ("A\"\\\a\b\f\n\r\t\v\0\1\14H\127\946\&1" :: Text)
  IO.print ('\'' :: Char)
  IO.print ('\\' :: Char)
  IO.print ('\0' :: Char)
  IO.print ('\14' :: Char)
  IO.print ('\127' :: Char)
  IO.print ('\946' :: Char)
  IO.print (["aβ"] :: [Text])
  IO.print $ Maybe.Just "aβ"
  IO.print $ Json.String "aβ"
  IO.print $ CI.mk "AΒ"
  IO.print (Text.unpack "" :: [Char])
  IO.print (['\0','\14','H','\127','\946','1'] :: [Char])
  IO.print ([Text.unpack "", Text.unpack "aβ"] :: [[Char]])
  IO.print ([1,2] :: [Int])
  Text.putStrLn $ Show.show $ Text.unpack "aβ"
  Text.putStrLn $ Show.show ([1,2] :: [Int])
  IO.print (Maybe.Just (Text.unpack "aβ") :: Maybe [Char])
  IO.print (Either.Left (Text.unpack "aβ") :: Either [Char] Int)
  IO.print (Either.Right (Text.unpack "") :: Either Int [Char])
  IO.print ((Text.unpack "", Text.unpack "aβ") :: ([Char], [Char]))
  IO.print (Vector.fromList [Text.unpack "", Text.unpack "aβ"] :: Vector [Char])
  IO.print (Set.fromList [Text.unpack "aβ", Text.unpack ""] :: Set [Char])
  IO.print (Tree.Node (Text.unpack "") [Tree.Node (Text.unpack "aβ") []] :: Tree [Char])
"#;
    assert_eq!(
        run(source),
        concat!(
            r#""A\"\\\a\b\f\n\r\t\v\NUL\SOH\SO\&H\DEL\946\&1""#,
            "\n",
            r#"'\''"#,
            "\n",
            r#"'\\'"#,
            "\n",
            r#"'\NUL'"#,
            "\n",
            r#"'\SO'"#,
            "\n",
            r#"'\DEL'"#,
            "\n",
            r#"'\946'"#,
            "\n",
            r#"["a\946"]"#,
            "\n",
            r#"Just "a\946""#,
            "\n",
            r#"String "a\946""#,
            "\n",
            r#""A\914""#,
            "\n",
            "\"\"",
            "\n",
            r#""\NUL\SO\&H\DEL\946\&1""#,
            "\n",
            r#"["","a\946"]"#,
            "\n",
            "[1,2]\n",
            r#""a\946""#,
            "\n",
            "[1,2]\n",
            r#"Just "a\946""#,
            "\n",
            r#"Left "a\946""#,
            "\n",
            r#"Right """#,
            "\n",
            r#"("","a\946")"#,
            "\n",
            r#"["","a\946"]"#,
            "\n",
            r#"fromList ["","a\946"]"#,
            "\n",
            r#"Node {rootLabel = "", subForest = [Node {rootLabel = "a\946", subForest = []}]}"#,
            "\n",
        )
    );
}

#[test]
fn show_numeric_and_constructor_precedence_matches_the_pinned_oracle() {
    let source = r"negativeInt = Int.subtract 1 0
negativeInteger = Int.toInteger Main.negativeInt
negativeDouble = Double.fromInt Main.negativeInt
negativeZero = Double.mult Main.negativeDouble 0.0
infinity = Double.plus 1.7976931348623157e308 1.7976931348623157e308
negativeInfinity = Double.mult Main.negativeDouble Main.infinity
nan = Double.subtract Main.infinity Main.infinity
main = do
  IO.print Main.negativeInt
  IO.print (Maybe.Just Main.negativeInt :: Maybe Int)
  IO.print (Either.Left Main.negativeInt :: Either Int Text)
  IO.print $ Exit.ExitFailure Main.negativeInt
  IO.print ([Main.negativeInt] :: [Int])
  IO.print ((Main.negativeInt, Main.negativeInt) :: (Int, Int))
  IO.print (Maybe.Just (Maybe.Just Main.negativeInt) :: Maybe (Maybe Int))
  IO.print (Maybe.Just Main.negativeInteger :: Maybe Integer)
  IO.print (Maybe.Just Main.negativeDouble :: Maybe Double)
  IO.print (Maybe.Just Main.negativeZero :: Maybe Double)
  IO.print (Maybe.Just Main.negativeInfinity :: Maybe Double)
  IO.print (Maybe.Just Main.nan :: Maybe Double)
  IO.print (Maybe.Just 1 :: Maybe Int)
  IO.print (Maybe.Just 1.0 :: Maybe Double)
  IO.print $ Json.Number Main.negativeDouble
  IO.print (Tree.Node Main.negativeInt [] :: Tree Int)
  IO.print (Maybe.Just (Tree.Node Main.negativeInt [] :: Tree Int) :: Maybe (Tree Int))
";
    assert_eq!(
        run(source),
        concat!(
            "-1\n",
            "Just (-1)\n",
            "Left (-1)\n",
            "ExitFailure (-1)\n",
            "[-1]\n",
            "(-1,-1)\n",
            "Just (Just (-1))\n",
            "Just (-1)\n",
            "Just (-1.0)\n",
            "Just (-0.0)\n",
            "Just (-Infinity)\n",
            "Just NaN\n",
            "Just 1\n",
            "Just 1.0\n",
            "Number (-1.0)\n",
            "Node {rootLabel = -1, subForest = []}\n",
            "Just (Node {rootLabel = -1, subForest = []})\n",
        )
    );
}

#[test]
fn show_byte_string_matches_pinned_char8_literal_escaping() {
    let source = r"main = do
  empty <- ByteString.hGet IO.stdin 0
  ascii <- ByteString.hGet IO.stdin 3
  quoted <- ByteString.hGet IO.stdin 2
  controls <- ByteString.hGet IO.stdin 11
  numericGap <- ByteString.hGet IO.stdin 2
  utf8 <- ByteString.hGet IO.stdin 3
  invalid <- ByteString.hGet IO.stdin 4
  Text.putStrLn $ Show.show empty
  IO.print ascii
  IO.print quoted
  IO.print controls
  IO.print numericGap
  IO.print utf8
  IO.print invalid
  IO.print ([utf8] :: [ByteString])
  IO.print (Maybe.Just utf8 :: Maybe ByteString)
  IO.print (Either.Left utf8 :: Either ByteString Int)
  IO.print ((empty, utf8) :: (ByteString, ByteString))
  IO.print (Vector.fromList [empty, utf8] :: Vector ByteString)
  IO.print (Set.fromList [utf8, empty] :: Set ByteString)
  IO.print (CI.mk utf8 :: CI ByteString)
";
    let input = vec![
        b'a', b'b', b'c', b'"', b'\\', 0, 7, 8, 12, 10, 13, 9, 11, 14, b'H', 127, 206, b'1', b'a',
        206, 178, 255, b'A', 254, b'B',
    ];
    assert_eq!(
        run_with_input(source, input),
        concat!(
            "\"\"\n",
            "\"abc\"\n",
            "\"\\\"\\\\\"\n",
            r#""\NUL\a\b\f\n\r\t\v\SO\&H\DEL""#,
            "\n",
            r#""\206\&1""#,
            "\n",
            r#""a\206\178""#,
            "\n",
            r#""\255A\254B""#,
            "\n",
            r#"["a\206\178"]"#,
            "\n",
            r#"Just "a\206\178""#,
            "\n",
            r#"Left "a\206\178""#,
            "\n",
            r#"("","a\206\178")"#,
            "\n",
            r#"["","a\206\178"]"#,
            "\n",
            r#"fromList ["","a\206\178"]"#,
            "\n",
            r#""a\206\178""#,
            "\n",
        )
        .as_bytes()
    );
}

#[test]
fn ci_fold_case_preserves_text_unicode_and_uses_pinned_latin1_bytes() {
    let source = concat!(
        "main = do\n",
        "  bytes <- ByteString.getContents\n",
        "  ByteString.hPutStr IO.stdout $ CI.foldedCase $ CI.mk bytes\n",
        "  Text.putStrLn $ CI.foldedCase $ CI.mk \"AΒ\"\n",
    );
    let input = vec![
        0x00, b'A', b'Z', b'a', b'z', 0x80, 0x92, 0xc0, 0xc1, 0xd6, 0xd7, 0xd8, 0xde, 0xdf, 0xff,
        0xce,
    ];
    let mut expected = vec![
        0x00, b'a', b'z', b'a', b'z', 0x80, 0x92, 0xe0, 0xe1, 0xf6, 0xd7, 0xf8, 0xfe, 0xdf, 0xff,
        0xee,
    ];
    expected.extend_from_slice("aβ\n".as_bytes());
    assert_eq!(run_with_input(source, input), expected);
}

#[test]
fn show_builder_matches_pinned_lazy_byte_string_literal_escaping() {
    let source = r"main = do
  empty <- ByteString.hGet IO.stdin 0
  utf8 <- ByteString.hGet IO.stdin 3
  invalid <- ByteString.hGet IO.stdin 4
  let emptyBuilder = Builder.byteString empty
  let utf8Builder = Builder.byteString utf8
  let invalidBuilder = Builder.byteString invalid
  Text.putStrLn $ Show.show emptyBuilder
  IO.print utf8Builder
  IO.print invalidBuilder
  IO.print ([utf8Builder] :: [Builder])
  IO.print (Maybe.Just invalidBuilder :: Maybe Builder)
  IO.print $ utf8Builder <> invalidBuilder
";
    assert_eq!(
        run_with_input(source, vec![b'a', 206, 178, 255, b'A', 254, b'B']),
        concat!(
            "\"\"\n",
            r#""a\206\178""#,
            "\n",
            r#""\255A\254B""#,
            "\n",
            r#"["a\206\178"]"#,
            "\n",
            r#"Just "\255A\254B""#,
            "\n",
            r#""a\206\178\255A\254B""#,
            "\n",
        )
        .as_bytes()
    );
}

#[test]
fn show_set_char_uses_the_pinned_character_list_representation() {
    let source = r"main = do
  IO.print (Set.singleton '\946' :: Set Char)
  IO.print (Set.fromList ([] :: [Char]) :: Set Char)
  IO.print (Set.fromList ['\946','a'] :: Set Char)
  IO.print (Set.fromList ['\0','\14','H','\127'] :: Set Char)
  IO.print (Maybe.Just (Set.singleton '\946' :: Set Char))
  IO.print (Set.singleton 1 :: Set Int)
";
    assert_eq!(
        run(source),
        concat!(
            "fromList \"\\946\"\n",
            "fromList \"\"\n",
            "fromList \"a\\946\"\n",
            "fromList \"\\NUL\\SO\\&H\\DEL\"\n",
            "Just (fromList \"\\946\")\n",
            "fromList [1]\n",
        )
    );
}

fn process_fixture_arguments() -> Vec<Arc<str>> {
    vec![Arc::from(env!(
        "CARGO_BIN_EXE_hell-runtime-process-fixture"
    ))]
}

#[test]
fn wildcard_parameter_still_occupies_a_lazy_environment_slot() {
    assert_eq!(
        run("main = IO.print $ (\\x _ -> x) 1 (Error.error \"boom\" :: Int)\n"),
        "1\n"
    );
}

#[test]
fn io_pure_does_not_force_an_ignored_result() {
    assert_eq!(
        run(concat!(
            "main = do\n",
            "  _ <- IO.pure (Error.error \"undemanded pure\" :: Int)\n",
            "  Text.putStr \"after\"\n",
        )),
        "after"
    );
}

#[cfg(feature = "mutation-testing")]
fn run_io_pure_laziness_test(mutant: Option<&str>) -> Output {
    let mut command = Command::new(std::env::current_exe().expect("laziness test executable"));
    command
        .arg("io_pure_does_not_force_an_ignored_result")
        .arg("--exact");
    if let Some(mutant) = mutant {
        command
            .args(["--skip", "__hell_mutant", "--skip"])
            .arg(mutant);
    }
    let output = hell_testkit::run_supervised_command(&mut command, &[], Duration::from_secs(30))
        .expect("supervise nested laziness test");
    assert!(
        !output.timed_out,
        "nested laziness test exceeded its deadline"
    );
    Output {
        status: output.status,
        stdout: output.stdout.complete.expect("stdout capture is complete"),
        stderr: output.stderr.complete.expect("stderr capture is complete"),
    }
}

#[cfg(feature = "mutation-testing")]
#[test]
fn io_pure_eager_force_mutant_is_detected() {
    let baseline = run_io_pure_laziness_test(None);
    assert!(
        baseline.status.success(),
        "baseline laziness probe failed: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&baseline.stdout),
        String::from_utf8_lossy(&baseline.stderr)
    );
    let mutant = run_io_pure_laziness_test(Some("io-pure-force-argument"));
    assert!(
        !mutant.status.success(),
        "eager IO.pure mutant unexpectedly survived: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&mutant.stdout),
        String::from_utf8_lossy(&mutant.stderr)
    );
}

#[test]
fn unselected_bool_branch_is_not_forced() {
    assert_eq!(
        run("main = IO.print $ Bool.bool 1 (Error.error \"boom\" :: Int) Bool.False\n"),
        "1\n"
    );
}

#[test]
fn singleton_constructors_force_keys_but_preserve_map_value_laziness() {
    let map_key = run_error(concat!(
        "main = IO.print $ Map.size $ Map.singleton ",
        "(Error.error \"singleton key forced\" :: Int) \"value\"\n",
    ));
    assert_eq!(map_key.code, "H0901");
    assert_eq!(map_key.kind, RuntimeErrorKind::UserError);
    assert_eq!(map_key.message.as_ref(), "singleton key forced");
    assert_eq!(
        map_key.to_string(),
        concat!(
            "hell: singleton key forced\n",
            "CallStack (from HasCallStack):\n",
            "  error, called at src/Hell.hs:1953:4 in main:Main",
        )
    );
    assert_eq!(
        run(concat!(
            "main = IO.print $ Map.size $ Map.singleton (1 :: Int) ",
            "(Error.error \"singleton value forced\" :: Text)\n",
        )),
        "1\n"
    );
    let set_element = run_error(concat!(
        "main = IO.print $ Set.size $ Set.singleton ",
        "(Error.error \"singleton element forced\" :: Int)\n",
    ));
    assert_eq!(set_element.kind, RuntimeErrorKind::UserError);
    assert_eq!(set_element.message.as_ref(), "singleton element forced");
}

#[test]
fn strict_iterate_forces_one_successor_ahead_and_no_deeper() {
    assert_eq!(
        run(concat!(
            "step = \\x -> if Int.eq x 7 then 8 else ",
            "Error.error \"undemanded-iterate-deeper-tail\"\n",
            "main = IO.print $ List.take 1 $ List.iterate' Main.step 7\n",
        )),
        "[7]\n"
    );
    let immediate = run_error(concat!(
        "main = IO.print $ List.take 1 $ ",
        "List.iterate' (\\_ -> Error.error \"strict-iterate-tail\") 7\n",
    ));
    assert_eq!(immediate.kind, RuntimeErrorKind::UserError);
    assert_eq!(immediate.message.as_ref(), "strict-iterate-tail");
    let fourth = run_error(concat!(
        "step = \\x -> if Int.eq x 0 then 1 else if Int.eq x 1 then 2 else ",
        "if Int.eq x 2 then 3 else Error.error \"fourth-successor-forced\"\n",
        "main = IO.print $ List.take 4 $ List.iterate' Main.step 0\n",
    ));
    assert_eq!(fourth.kind, RuntimeErrorKind::UserError);
    assert_eq!(fourth.message.as_ref(), "fourth-successor-forced");
}

#[test]
fn infinite_iterate_is_consumed_productively() {
    assert_eq!(
        run("main = IO.print $ List.take 5 $ List.iterate' (Int.plus 1) 0\n"),
        "[0,1,2,3,4]\n"
    );
}

#[test]
fn acyclic_fix_unfolding_produces_an_infinite_list_productively() {
    assert_eq!(
        run("main = IO.print $ List.take 5 $ Function.fix (List.cons 1)\n"),
        "[1,1,1,1,1]\n"
    );
}

#[test]
fn curried_guest_results_support_overapplication() {
    assert_eq!(
        run("main = IO.print $ (\\x -> \\y -> Int.plus x y) 20 22\n"),
        "42\n"
    );
    assert_eq!(
        run("main = IO.print $ Function.id (\\x -> Int.plus x 1) 41\n"),
        "42\n"
    );
}

#[test]
fn strict_native_demand_preserves_the_oracle_argument_order() {
    let error = run_error(
        "main = IO.print $ Int.subtract (Error.error \"first\" :: Int) \
         (Error.error \"second\" :: Int)\n",
    );
    assert_eq!(error.message.as_ref(), "second");
}

#[test]
fn double_show_keeps_haskell_integral_decimal_spelling() {
    assert_eq!(run("main = IO.print 0.0\n"), "0.0\n");
}

#[test]
fn numeric_readers_and_double_formatters_match_the_pinned_surface() {
    assert_eq!(
        run(concat!(
            "main = do\n",
            "  IO.print $ Int.readMaybe \"123\"\n",
            "  IO.print $ Double.readMaybe \"123.456\"\n",
            "  Text.putStrLn $ Double.show 123.0\n",
            "  Text.putStrLn $ Double.showEFloat Maybe.Nothing 123.0 \"\"\n",
            "  Text.putStrLn $ Double.showEFloat (Maybe.Just 3) 123456789.123456789 \"\"\n",
            "  Text.putStrLn $ Double.showFFloat (Maybe.Just 3) 123456789.0 \"\"\n",
        )),
        concat!(
            "Just 123\n",
            "Just 123.456\n",
            "123.0\n",
            "1.23e2\n",
            "1.235e8\n",
            "123456789.000\n",
        )
    );
}

#[test]
fn integer_arithmetic_is_unbounded_and_int_conversion_wraps() {
    assert_eq!(
        run(concat!(
            "main = do\n",
            "  let large = Integer.plus\n",
            "        (Int.toInteger 9223372036854775807)\n",
            "        (Int.toInteger 9223372036854775807)\n",
            "  IO.print large\n",
            "  IO.print $ Int.fromInteger large\n",
            "  IO.print $ Integer.mult large large\n",
            "  IO.print $ Integer.readMaybe \"-123456789012345678901234567890\"\n",
        )),
        concat!(
            "18446744073709551614\n",
            "-2\n",
            "340282366920938463389587631136930004996\n",
            "Just (-123456789012345678901234567890)\n",
        )
    );
}

#[test]
fn vector_and_map_list_conversions_preserve_order_and_map_last_wins() {
    assert_eq!(
        run(concat!(
            "main = do\n",
            "  IO.print $ Vector.toList $ Vector.fromList [1, 2, 3]\n",
            "  IO.print $ Map.toList $ Map.fromList\n",
            "    [(2, \"two\"), (1, \"old\"), (1, \"new\")]\n",
        )),
        "[1,2,3]\n[(1,\"new\"),(2,\"two\")]\n"
    );
}

#[test]
fn pure_text_adapters_preserve_unicode_and_optional_results() {
    assert_eq!(
        run(concat!(
            "main = do\n",
            "  IO.print $ Text.breakOn \"β\" \"aβc\"\n",
            "  IO.print $ Text.stripPrefix \"pre\" \"prefix\"\n",
            "  IO.print $ Text.stripSuffix \"fix\" \"prefix\"\n",
            "  IO.print $ Text.splitOn \"::\" \"a::b::\"\n",
            "  IO.print $ Text.lines \"a\\nb\\n\"\n",
            "  Text.putStrLn $ Text.pack $ Text.unpack \"héλ\"\n",
            "  Text.putStrLn $ Text.takeEnd 2 \"aβλ\"\n",
            "  Text.putStrLn $ Text.dropEnd 2 \"aβλ\"\n",
            "  Text.putStrLn $ Text.unwords $ Text.words \"  a  β \"\n",
        )),
        concat!(
            "(\"a\",\"\\946c\")\n",
            "Just \"fix\"\n",
            "Just \"pre\"\n",
            "[\"a\",\"b\",\"\"]\n",
            "[\"a\",\"b\"]\n",
            "héλ\n",
            "βλ\n",
            "a\n",
            "a β\n",
        )
    );
}

#[test]
fn text_files_and_directory_operations_use_the_logical_cwd_and_capability() {
    let directory = std::env::temp_dir().join(format!("hell-rs-filesystem-{}", std::process::id()));
    let _already_absent = std::fs::remove_dir_all(&directory);
    std::fs::create_dir(&directory).unwrap();
    let source = concat!(
        "main = do\n",
        "  Text.writeFile \"hello.txt\" \"Hello, \"\n",
        "  Text.appendFile \"hello.txt\" \"World!\"\n",
        "  text <- Text.readFile \"hello.txt\"\n",
        "  Text.putStrLn text\n",
        "  size <- Directory.getFileSize \"hello.txt\"\n",
        "  IO.print size\n",
        "  Directory.createDirectory \"nested\"\n",
        "  exists <- Directory.doesDirectoryExist \"nested\"\n",
        "  IO.print exists\n",
        "  current <- Directory.getCurrentDirectory\n",
        "  Directory.setCurrentDirectory current\n",
        "  Directory.removeDirectory \"nested\"\n",
        "  Directory.removeFile \"hello.txt\"\n",
    );
    assert_eq!(
        run_in(source, directory.clone(), true).unwrap(),
        "Hello, World!\n13\nTrue\n"
    );
    assert!(
        run_in(
            "main = do\n  text <- Text.readFile \"blocked\"\n  Text.putStrLn text\n",
            directory.clone(),
            false,
        )
        .unwrap_err()
        .contains("H0903")
    );
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn sandboxed_policy_still_denies_current_directory_access() {
    let program = compile_source(
        &mut CompilerSession::default(),
        "sandboxed-current-directory.hell",
        "main = do\n  current <- Directory.getCurrentDirectory\n  Text.putStr current\n",
    )
    .unwrap();
    let context = RuntimeContext::with_host(
        Vec::new(),
        Vec::new(),
        Vec::<u8>::new(),
        std::env::temp_dir(),
        true,
    )
    .with_policy(hell_runtime::policy::RuntimePolicy::sandboxed());
    let error = run_main(program, context).unwrap_err();
    assert_eq!(error.code, "H0903");
    assert_eq!(error.kind, RuntimeErrorKind::Io);
    assert_eq!(
        error.message.as_ref(),
        "Directory.getCurrentDirectory: filesystem capability is disabled"
    );
    assert_eq!(error.presentation, None);
}

#[test]
fn directory_existence_predicates_collapse_post_admission_metadata_errors() {
    let directory =
        std::env::temp_dir().join(format!("hell-rs-existence-errors-{}", std::process::id()));
    let _already_absent = std::fs::remove_dir_all(&directory);
    std::fs::create_dir(&directory).unwrap();
    std::fs::write(directory.join("leaf"), b"not a directory").unwrap();
    assert_eq!(
        run_in(
            concat!(
                "main = do\n",
                "  invalidDirectory <- Directory.doesDirectoryExist \"\\0\"\n",
                "  invalidFile <- Directory.doesFileExist \"\\0\"\n",
                "  missingDirectory <- Directory.doesDirectoryExist \"missing\"\n",
                "  missingFile <- Directory.doesFileExist \"missing\"\n",
                "  notDirectoryDirectory <- Directory.doesDirectoryExist \"leaf/child\"\n",
                "  notDirectoryFile <- Directory.doesFileExist \"leaf/child\"\n",
                "  IO.print invalidDirectory\n",
                "  IO.print invalidFile\n",
                "  IO.print missingDirectory\n",
                "  IO.print missingFile\n",
                "  IO.print notDirectoryDirectory\n",
                "  IO.print notDirectoryFile\n",
            ),
            directory.clone(),
            true,
        )
        .unwrap(),
        "False\nFalse\nFalse\nFalse\nFalse\nFalse\n"
    );
    let symlink_error = run_in_error(
        "main = do\n  _ <- Directory.pathIsSymbolicLink \"missing\"\n  IO.pure ()\n",
        directory.clone(),
    );
    assert_eq!(symlink_error.code, "H0903");
    assert_eq!(symlink_error.kind, RuntimeErrorKind::Io);
    assert!(
        symlink_error
            .message
            .starts_with("Directory.pathIsSymbolicLink: ")
    );
    std::fs::remove_dir_all(directory).unwrap();
}

#[cfg(unix)]
#[test]
fn directory_existence_predicates_collapse_permission_denied_metadata_errors() {
    use std::os::unix::fs::PermissionsExt as _;

    let directory =
        std::env::temp_dir().join(format!("hell-rs-existence-denied-{}", std::process::id()));
    let _already_absent = std::fs::remove_dir_all(&directory);
    let denied = directory.join("denied");
    std::fs::create_dir_all(&denied).unwrap();
    std::fs::set_permissions(&denied, std::fs::Permissions::from_mode(0o0)).unwrap();
    assert_eq!(
        run_in(
            concat!(
                "main = do\n",
                "  deniedDirectory <- Directory.doesDirectoryExist \"denied/child\"\n",
                "  deniedFile <- Directory.doesFileExist \"denied/child\"\n",
                "  IO.print deniedDirectory\n",
                "  IO.print deniedFile\n",
            ),
            directory.clone(),
            true,
        )
        .unwrap(),
        "False\nFalse\n"
    );
    let symlink_error = run_in_error(
        "main = do\n  _ <- Directory.pathIsSymbolicLink \"denied/child\"\n  IO.pure ()\n",
        directory.clone(),
    );
    assert_eq!(symlink_error.code, "H0903");
    assert_eq!(symlink_error.kind, RuntimeErrorKind::Io);
    std::fs::set_permissions(&denied, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn missing_file_diagnostics_bind_guest_path_operation_and_typed_not_found() {
    let directory =
        std::env::temp_dir().join(format!("hell-rs-missing-files-{}", std::process::id()));
    let _already_absent = std::fs::remove_dir_all(&directory);
    std::fs::create_dir(&directory).unwrap();
    for (source, operation, path, presentation_operation) in [
        (
            "main = Text.writeFile \"missing-parent/file.txt\" \"x\"\n",
            "Text.writeFile",
            "missing-parent/file.txt",
            RuntimeFileOperation::WithBinaryFile,
        ),
        (
            "main = Text.appendFile \"other-parent/other.txt\" \"x\"\n",
            "Text.appendFile",
            "other-parent/other.txt",
            RuntimeFileOperation::WithBinaryFile,
        ),
        (
            concat!(
                "main = ByteString.writeFile \"missing-parent/file.bin\" $ ",
                "Text.encodeUtf8 \"x\"\n",
            ),
            "ByteString.writeFile",
            "missing-parent/file.bin",
            RuntimeFileOperation::WithBinaryFile,
        ),
        (
            concat!(
                "main = do\n",
                "  output <- ByteString.readFile \"missing.bin\"\n",
                "  ByteString.hPutStr IO.stdout output\n",
            ),
            "ByteString.readFile",
            "missing.bin",
            RuntimeFileOperation::WithBinaryFile,
        ),
        (
            concat!(
                "main = do\n",
                "  handle <- IO.openFile \"missing.txt\" IO.ReadMode\n",
                "  IO.pure ()\n",
            ),
            "IO.openFile",
            "missing.txt",
            RuntimeFileOperation::OpenFile,
        ),
    ] {
        let error = run_in_error(source, directory.clone());
        assert_eq!(error.code, "H0903");
        assert_eq!(error.kind, RuntimeErrorKind::Io);
        assert!(error.message.starts_with(&format!("{operation}: ")));
        assert_eq!(
            error.presentation,
            Some(RuntimeErrorPresentation::FileNotFound {
                path: Arc::from(path),
                operation: presentation_operation,
            })
        );
        let rendered_operation = match presentation_operation {
            RuntimeFileOperation::WithBinaryFile => "withBinaryFile",
            RuntimeFileOperation::OpenFile => "openFile",
        };
        assert_eq!(
            error.to_string(),
            format!(
                "hell: {path}: {rendered_operation}: does not exist \
                 (No such file or directory)"
            )
        );
    }

    let other_error = run_in_error("main = Text.writeFile \".\" \"x\"\n", directory.clone());
    assert_eq!(other_error.code, "H0903");
    assert_eq!(other_error.kind, RuntimeErrorKind::Io);
    assert_eq!(other_error.presentation, None);
    assert!(
        other_error
            .to_string()
            .starts_with("H0903: Text.writeFile: ")
    );
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn missing_environment_diagnostics_bind_the_requested_name_and_keep_successes_unchanged() {
    let directory = std::env::temp_dir();
    for name in ["MISSING_REVIEWED_ENV", "SECOND_REVIEWED_MISSING_NAME"] {
        let source =
            format!("main = do\n  value <- Environment.getEnv {name:?}\n  Text.putStr value\n");
        let error = run_in_error(&source, directory.clone());
        assert_eq!(error.code, "H0903");
        assert_eq!(error.kind, RuntimeErrorKind::Io);
        assert_eq!(
            error.message.as_ref(),
            format!("environment variable `{name}` is not set")
        );
        assert_eq!(
            error.presentation,
            Some(RuntimeErrorPresentation::EnvironmentVariableNotFound {
                name: Arc::from(name),
            })
        );
        assert_eq!(
            error.to_string(),
            format!("hell: {name}: getEnv: does not exist (no environment variable)")
        );
    }

    let source = concat!(
        "main = do\n",
        "  value <- Environment.getEnv \"REVIEWED_ENV\"\n",
        "  Text.putStrLn value\n",
        "  values <- Environment.getEnvironment\n",
        "  Monad.forM_ values \\(name, item) ->\n",
        "    Text.putStrLn $ Text.concat [name, \"=\", item]\n",
    );
    let program =
        compile_source(&mut CompilerSession::default(), "environment.hell", source).unwrap();
    let bytes = Arc::new(Mutex::new(Vec::new()));
    let context = RuntimeContext::with_host(
        Vec::new(),
        vec![
            (Arc::from("REVIEWED_ENV"), Arc::from("bound")),
            (Arc::from("SECOND"), Arc::from("two")),
        ],
        SharedWriter(Arc::clone(&bytes)),
        directory,
        true,
    );
    run_main(program, context).unwrap();
    assert_eq!(
        bytes.lock().unwrap().as_slice(),
        b"bound\nREVIEWED_ENV=bound\nSECOND=two\n"
    );
}

fn observed_directory_error(source: &str, label: &str) -> Arc<RuntimeError> {
    let directory = std::env::temp_dir().join(format!(
        "hell-rs-directory-error-{label}-{}",
        std::process::id()
    ));
    let _already_absent = std::fs::remove_dir_all(&directory);
    std::fs::create_dir(&directory).unwrap();
    let error = run_in_error(source, directory.clone());
    std::fs::remove_dir_all(directory).unwrap();
    error
}

fn assert_directory_error(
    label: &str,
    source: &str,
    internal_operation: &str,
    operation: RuntimeDirectoryOperation,
    path: &str,
    target: Option<&str>,
    rendered: &str,
) {
    let error = observed_directory_error(source, label);
    assert_eq!(error.code, "H0903");
    assert_eq!(error.kind, RuntimeErrorKind::Io);
    assert!(
        error
            .message
            .starts_with(&format!("{internal_operation}: "))
    );
    assert_eq!(
        error.presentation,
        Some(RuntimeErrorPresentation::DirectoryOperation {
            operation,
            path: Arc::from(path),
            target: target.map(Arc::from),
        })
    );
    assert_eq!(error.to_string(), rendered);
}

#[test]
fn directory_os_errors_match_the_pinned_operation_and_guest_path_presentations() {
    for (label, source, internal, operation, path, target, rendered) in [
        (
            // A source in a missing directory still fails on Windows.  A
            // directly missing source is the reviewed directory 1.3.8.1
            // Windows empty-pair postcondition and is covered separately.
            "copy-missing-parent",
            "main = Directory.copyFile \"missing/source.txt\" \"target.txt\"\n",
            "Directory.copyFile",
            RuntimeDirectoryOperation::CopyFile,
            "missing/source.txt",
            Some("target.txt"),
            COPY_FILE_MISSING_PRESENTATION,
        ),
        (
            "create",
            "main = Directory.createDirectory \".\"\n",
            "Directory.createDirectory",
            RuntimeDirectoryOperation::CreateDirectory,
            ".",
            None,
            "hell: .: createDirectory: already exists (File exists)",
        ),
        (
            "create-if-missing",
            "main = Directory.createDirectoryIfMissing Bool.False \"missing/created\"\n",
            "Directory.createDirectoryIfMissing",
            RuntimeDirectoryOperation::CreateDirectoryIfMissing,
            "missing/created",
            None,
            concat!(
                "hell: missing/created: createDirectory: does not exist ",
                "(No such file or directory)",
            ),
        ),
        (
            "size",
            "main = do { _ <- Directory.getFileSize \"missing.txt\"; IO.pure () }\n",
            "Directory.getFileSize",
            RuntimeDirectoryOperation::GetFileSize,
            "missing.txt",
            None,
            concat!(
                "hell: missing.txt: getFileSize:getFileStatus: does not exist ",
                "(No such file or directory)",
            ),
        ),
        (
            "remove-file",
            "main = Directory.removeFile \"missing.txt\"\n",
            "Directory.removeFile",
            RuntimeDirectoryOperation::RemoveFile,
            "missing.txt",
            None,
            "hell: missing.txt: removeLink: does not exist (No such file or directory)",
        ),
        (
            "rename",
            "main = Directory.renameFile \"missing.txt\" \"target.txt\"\n",
            "Directory.renameFile",
            RuntimeDirectoryOperation::RenameFile,
            "missing.txt",
            Some("target.txt"),
            concat!(
                "hell: renameFile:renamePath:rename 'missing.txt' to 'target.txt': ",
                "does not exist (No such file or directory)",
            ),
        ),
        (
            "list",
            "main = do { _ <- Directory.listDirectory \"missing\"; IO.pure () }\n",
            "Directory.listDirectory",
            RuntimeDirectoryOperation::ListDirectory,
            "missing",
            None,
            concat!(
                "hell: missing: getDirectoryContents:openDirStream: does not exist ",
                "(No such file or directory)",
            ),
        ),
        (
            "remove-directory",
            "main = Directory.removeDirectory \"missing\"\n",
            "Directory.removeDirectory",
            RuntimeDirectoryOperation::RemoveDirectory,
            "missing",
            None,
            "hell: missing: removeDirectory: does not exist (No such file or directory)",
        ),
    ] {
        assert_directory_error(label, source, internal, operation, path, target, rendered);
    }
}

#[test]
fn set_current_directory_error_uses_the_pinned_guest_path_presentation() {
    assert_directory_error(
        "set-current",
        "main = Directory.setCurrentDirectory \"missing\"\n",
        "Directory.setCurrentDirectory",
        RuntimeDirectoryOperation::SetCurrentDirectory,
        "missing",
        None,
        concat!(
            "hell: missing: changeWorkingDirectory: does not exist ",
            "(No such file or directory)",
        ),
    );
}

#[cfg(windows)]
#[test]
fn windows_missing_source_copy_file_retains_the_pinned_empty_pair_postcondition() {
    let directory = std::env::temp_dir().join(format!(
        "hell-rs-windows-copy-missing-{}",
        std::process::id()
    ));
    let _already_absent = std::fs::remove_dir_all(&directory);
    std::fs::create_dir(&directory).unwrap();

    assert_eq!(
        run_in(
            "main = Directory.copyFile \"missing.txt\" \"target.txt\"\n",
            directory.clone(),
            true,
        )
        .unwrap(),
        ""
    );
    let source = std::fs::metadata(directory.join("missing.txt")).unwrap();
    let target = std::fs::metadata(directory.join("target.txt")).unwrap();
    assert!(source.is_file());
    assert!(target.is_file());
    assert_eq!(source.len(), 0);
    assert_eq!(target.len(), 0);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn directory_error_presentations_are_dynamic_and_other_error_kinds_remain_generic() {
    for (label, source, internal, operation, path, target, rendered) in [
        (
            // Keep the alternate-path proof outside the reviewed Windows
            // missing-source success postcondition.
            "copy-alternate-missing-parent",
            "main = Directory.copyFile \"other-missing/other-source\" \"other-target\"\n",
            "Directory.copyFile",
            RuntimeDirectoryOperation::CopyFile,
            "other-missing/other-source",
            Some("other-target"),
            COPY_FILE_ALTERNATE_MISSING_PRESENTATION,
        ),
        (
            "create-alternate",
            concat!(
                "main = do\n",
                "  Directory.createDirectory \"already-there\"\n",
                "  Directory.createDirectory \"already-there\"\n",
            ),
            "Directory.createDirectory",
            RuntimeDirectoryOperation::CreateDirectory,
            "already-there",
            None,
            "hell: already-there: createDirectory: already exists (File exists)",
        ),
        (
            "rename-alternate",
            "main = Directory.renameFile \"other-source\" \"other-target\"\n",
            "Directory.renameFile",
            RuntimeDirectoryOperation::RenameFile,
            "other-source",
            Some("other-target"),
            concat!(
                "hell: renameFile:renamePath:rename 'other-source' to 'other-target': ",
                "does not exist (No such file or directory)",
            ),
        ),
        (
            "list-alternate",
            "main = do { _ <- Directory.listDirectory \"other-directory\"; IO.pure () }\n",
            "Directory.listDirectory",
            RuntimeDirectoryOperation::ListDirectory,
            "other-directory",
            None,
            concat!(
                "hell: other-directory: getDirectoryContents:openDirStream: does not exist ",
                "(No such file or directory)",
            ),
        ),
    ] {
        assert_directory_error(label, source, internal, operation, path, target, rendered);
    }

    for (label, source) in [
        (
            "copy-wrong-kind",
            concat!(
                "main = do\n",
                "  Text.writeFile \"source.txt\" \"x\"\n",
                "  Directory.copyFile \"source.txt\" \".\"\n",
            ),
        ),
        (
            "remove-wrong-kind",
            concat!(
                "main = do\n",
                "  Directory.createDirectory \"nonempty\"\n",
                "  Text.writeFile \"nonempty/value\" \"x\"\n",
                "  Directory.removeDirectory \"nonempty\"\n",
            ),
        ),
        (
            "invalid-path",
            "main = do { _ <- Directory.getFileSize \"\\0\"; IO.pure () }\n",
        ),
    ] {
        let error = observed_directory_error(source, label);
        assert_eq!(error.code, "H0903");
        assert_eq!(error.kind, RuntimeErrorKind::Io);
        assert_eq!(error.presentation, None);
        assert!(error.to_string().starts_with("H0903: Directory."));
    }
}

#[test]
fn process_descriptions_execute_fresh_with_capture_streams_and_capabilities() {
    let directory = std::env::temp_dir().join(format!("hell-rs-process-{}", std::process::id()));
    let _already_absent = std::fs::remove_dir_all(&directory);
    std::fs::create_dir(&directory).unwrap();
    let source = concat!(
        "main = do\n",
        "  helpers <- Environment.getArgs\n",
        "  Monad.forM_ helpers \\helper -> do\n",
        "    let process = Process.proc helper [\"emit\", \"hello\", \"error\"]\n",
        "    (out, err) <- Text.readProcess_ process\n",
        "    Text.hPutStr IO.stdout out\n",
        "    Text.hPutStr IO.stdout err\n",
        "    (freshOut, freshErr) <- Text.readProcess_ process\n",
        "    Text.hPutStr IO.stdout freshOut\n",
        "    Text.hPutStr IO.stdout freshErr\n",
        "    (env, envErr) <- Text.readProcess_ $\n",
        "      Process.setEnv [(\"PATH\", \"world\")] $\n",
        "      Process.proc helper [\"environment-path\"]\n",
        "    Text.hPutStr IO.stdout env\n",
        "    Text.hPutStr IO.stdout envErr\n",
        "    (code, exitOut, exitErr) <- ByteString.readProcess\n",
        "      (Process.proc helper [\"exit\", \"7\"])\n",
        "    ByteString.hPutStr IO.stdout exitOut\n",
        "    ByteString.hPutStr IO.stdout exitErr\n",
        "    Exit.exitCode (Text.putStrLn \"success\") IO.print code\n",
        "    Process.runProcess_ $ Process.setStdout Process.nullStream $\n",
        "      Process.proc helper [\"emit\", \"hidden\", \"\"]\n",
    );
    assert_eq!(
        run_in_with_args(source, process_fixture_arguments(), directory.clone(), true,).unwrap(),
        "helloerrorhelloerrorworld7\n"
    );

    let program = compile_source(
        &mut CompilerSession::default(),
        "test.hell",
        concat!(
            "main = do\n",
            "  helpers <- Environment.getArgs\n",
            "  Monad.forM_ helpers \\helper ->\n",
            "    Process.runProcess_ (Process.proc helper [\"exit\", \"0\"])\n",
        ),
    )
    .unwrap();
    let error = run_main(
        program,
        RuntimeContext::with_host_capabilities(
            process_fixture_arguments(),
            Vec::new(),
            Vec::<u8>::new(),
            directory.clone(),
            true,
            false,
        ),
    )
    .unwrap_err();
    assert_eq!(error.code, "H0903");
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn missing_process_diagnostics_bind_guest_command_and_typed_spawn_failure() {
    let directory =
        std::env::temp_dir().join(format!("hell-rs-missing-process-{}", std::process::id()));
    let _already_absent = std::fs::remove_dir_all(&directory);
    std::fs::create_dir(&directory).unwrap();
    for (builtin, binding) in [
        ("ByteString.readProcess", "(_exit, _stdout, _stderr)"),
        ("ByteString.readProcess_", "(_stdout, _stderr)"),
        ("ByteString.readProcessStdout_", "_stdout"),
    ] {
        let source = format!(
            "main = do\n  {binding} <- {builtin} $ \
             Process.proc \"missing-hell-test-helper\" []\n  IO.pure ()\n"
        );
        let error = run_in_error(&source, directory.clone());
        assert_eq!(error.code, "H0903");
        assert_eq!(error.kind, RuntimeErrorKind::Io);
        assert!(error.message.starts_with("readProcess: "));
        assert!(error.message.contains("captured parent PATH"));
        assert_eq!(
            error.presentation,
            Some(RuntimeErrorPresentation::ProcessNotFound {
                command: Arc::from("missing-hell-test-helper"),
            })
        );
        #[cfg(unix)]
        assert_eq!(
            error.to_string(),
            concat!(
                "hell: missing-hell-test-helper: startProcess: posix_spawnp: ",
                "does not exist (No such file or directory)",
            )
        );
    }

    let non_executable = directory.join("not-executable");
    std::fs::write(&non_executable, b"not an executable\n").unwrap();
    let error = run_in_error(
        concat!(
            "main = do\n",
            "  _exit <- Process.runProcess $ Process.proc \"./not-executable\" []\n",
            "  IO.pure ()\n",
        ),
        directory.clone(),
    );
    assert_eq!(error.code, "H0903");
    assert_eq!(error.kind, RuntimeErrorKind::Io);
    assert_eq!(error.presentation, None);
    assert!(error.to_string().starts_with("H0903: Process.runProcess: "));
    std::fs::remove_dir_all(directory).unwrap();
}

#[cfg(unix)]
struct ProcessPathFixture {
    directory: PathBuf,
    first: PathBuf,
    second: PathBuf,
    current_test: PathBuf,
    path: String,
}

#[cfg(unix)]
impl ProcessPathFixture {
    fn new(label: &str) -> Self {
        let directory = std::env::temp_dir().join(format!(
            "hell-rs-process-path-{label}-{}",
            std::process::id()
        ));
        let _already_absent = std::fs::remove_dir_all(&directory);
        let first = directory.join("first");
        let second = directory.join("second");
        std::fs::create_dir_all(&first).unwrap();
        std::fs::create_dir_all(&second).unwrap();
        let path = std::env::join_paths([&first, &second])
            .unwrap()
            .into_string()
            .unwrap();
        Self {
            directory,
            first,
            second,
            current_test: std::env::current_exe().unwrap(),
            path,
        }
    }
}

#[cfg(unix)]
impl Drop for ProcessPathFixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.directory).unwrap();
    }
}

#[cfg(unix)]
fn run_process_path_source(
    fixture: &ProcessPathFixture,
    source: &str,
    environment: Vec<(Arc<str>, Arc<str>)>,
) -> Result<(), Arc<RuntimeError>> {
    let program =
        compile_source(&mut CompilerSession::default(), "process-path.hell", source).unwrap();
    run_main(
        program,
        RuntimeContext::with_host(
            Vec::new(),
            environment,
            Vec::<u8>::new(),
            fixture.directory.clone(),
            true,
        ),
    )
}

#[cfg(unix)]
fn process_path_child_source(command: &str, child_test: &str, child_environment: &str) -> String {
    format!(
        concat!(
            "main = Process.runProcess_ $\n",
            "  Process.setStdout Process.nullStream $\n",
            "  Process.setStderr Process.nullStream $\n",
            "  Process.setEnv {child_environment} $\n",
            "  Process.proc {command:?} [{child_test:?},\"--exact\",\"--ignored\"]\n",
        ),
        command = command,
        child_test = child_test,
        child_environment = child_environment,
    )
}

#[cfg(unix)]
#[test]
fn process_set_env_resolves_bare_commands_from_captured_parent_path() {
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = ProcessPathFixture::new("selection");
    let first_match = "first-match-helper";
    std::fs::copy(&fixture.current_test, fixture.first.join(first_match)).unwrap();
    std::fs::copy("/usr/bin/false", fixture.second.join(first_match)).unwrap();

    let skip_non_executable = "skip-non-executable-helper";
    let rejected = fixture.first.join(skip_non_executable);
    std::fs::write(&rejected, b"not executable\n").unwrap();
    let mut permissions = std::fs::metadata(&rejected).unwrap().permissions();
    permissions.set_mode(0o001);
    std::fs::set_permissions(&rejected, permissions).unwrap();
    std::fs::copy(
        &fixture.current_test,
        fixture.second.join(skip_non_executable),
    )
    .unwrap();

    let relative = fixture.directory.join("relative-helper");
    std::fs::copy(&fixture.current_test, &relative).unwrap();
    let mut permissions = std::fs::metadata(&relative).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&relative, permissions).unwrap();

    for command in [first_match, skip_non_executable, "./relative-helper"] {
        let source = process_path_child_source(
            command,
            "process_path_child_observes_exact_replacement_environment",
            "[(\"LC_ALL\",\"C\")]",
        );
        run_process_path_source(
            &fixture,
            &source,
            vec![(Arc::from("PATH"), Arc::from(fixture.path.as_str()))],
        )
        .unwrap();
    }

    let canonical_target = fixture.first.join("canonical-target");
    std::fs::copy(&fixture.current_test, &canonical_target).unwrap();
    std::os::unix::fs::symlink(&canonical_target, fixture.first.join("symlink-helper")).unwrap();
    let source = process_path_child_source(
        "symlink-helper",
        "process_path_child_observes_canonical_executable",
        "[(\"LC_ALL\",\"C\")]",
    );
    run_process_path_source(
        &fixture,
        &source,
        vec![(Arc::from("PATH"), Arc::from(fixture.path.as_str()))],
    )
    .unwrap();
}

#[cfg(unix)]
#[test]
fn process_set_env_path_search_is_explicit_and_cannot_use_the_child_environment() {
    let fixture = ProcessPathFixture::new("scope");
    for (path_value, command, target) in [
        (
            std::env::join_paths([Path::new(""), fixture.second.as_path()])
                .unwrap()
                .into_string()
                .unwrap(),
            "empty-entry-helper",
            fixture.directory.join("empty-entry-helper"),
        ),
        (
            "relative-bin".to_owned(),
            "relative-entry-helper",
            fixture.directory.join("relative-bin/relative-entry-helper"),
        ),
    ] {
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::copy(&fixture.current_test, target).unwrap();
        let source = process_path_child_source(
            command,
            "process_path_child_observes_exact_replacement_environment",
            "[(\"LC_ALL\",\"C\")]",
        );
        run_process_path_source(
            &fixture,
            &source,
            vec![(Arc::from("PATH"), Arc::from(path_value))],
        )
        .unwrap();
    }

    std::fs::create_dir(fixture.first.join("directory-helper")).unwrap();
    let source = concat!(
        "main = Process.runProcess_ $ Process.setEnv [(\"LC_ALL\",\"C\")] $\n",
        "  Process.proc \"directory-helper\" []\n",
    );
    let error = run_process_path_source(
        &fixture,
        source,
        vec![(Arc::from("PATH"), Arc::from(fixture.path.as_str()))],
    )
    .unwrap_err();
    assert_eq!(
        error.presentation,
        Some(RuntimeErrorPresentation::ProcessNotFound {
            command: Arc::from("directory-helper"),
        })
    );

    let rescued = "replacement-path-must-not-rescue-helper";
    std::fs::copy(&fixture.current_test, fixture.second.join(rescued)).unwrap();
    let child_environment = format!(
        "[(\"LC_ALL\",\"C\"),(\"PATH\",{:?})]",
        fixture.second.to_string_lossy()
    );
    let source = process_path_child_source(
        rescued,
        "process_path_child_observes_exact_replacement_environment",
        &child_environment,
    );
    for captured_environment in [
        Vec::new(),
        vec![(
            Arc::from("PATH"),
            Arc::from(fixture.first.to_string_lossy().as_ref()),
        )],
    ] {
        let error = run_process_path_source(&fixture, &source, captured_environment).unwrap_err();
        assert_eq!(
            error.presentation,
            Some(RuntimeErrorPresentation::ProcessNotFound {
                command: Arc::from(rescued),
            })
        );
        assert!(error.message.contains("captured parent PATH"));
    }
}

#[cfg(unix)]
#[test]
#[ignore = "executed only as the child of the captured-PATH process regression"]
fn process_path_child_observes_exact_replacement_environment() {
    assert_eq!(
        std::env::var_os("LC_ALL").as_deref(),
        Some(std::ffi::OsStr::new("C"))
    );
    assert_eq!(std::env::var_os("PATH"), None);
}

#[cfg(unix)]
#[test]
#[ignore = "executed only through a canonicalized captured-PATH symlink"]
fn process_path_child_observes_canonical_executable() {
    assert_eq!(
        std::env::current_exe()
            .unwrap()
            .file_name()
            .and_then(std::ffi::OsStr::to_str),
        Some("canonical-target")
    );
    assert_eq!(
        std::env::var_os("LC_ALL").as_deref(),
        Some(std::ffi::OsStr::new("C"))
    );
    assert_eq!(std::env::var_os("PATH"), None);
}

#[cfg(windows)]
#[test]
fn process_set_env_path_search_never_selects_batch_scripts() {
    let directory =
        std::env::temp_dir().join(format!("hell-rs-process-path-{}", std::process::id()));
    let _already_absent = std::fs::remove_dir_all(&directory);
    let first = directory.join("first");
    let second = directory.join("second");
    std::fs::create_dir_all(&first).unwrap();
    std::fs::create_dir_all(&second).unwrap();
    std::fs::write(first.join("native-helper.bat"), b"not executed\r\n").unwrap();
    std::fs::write(first.join("native-helper.cmd"), b"not executed\r\n").unwrap();
    std::fs::copy(
        std::env::current_exe().unwrap(),
        second.join("native-helper.exe"),
    )
    .unwrap();
    let path = std::env::join_paths([&first, &second])
        .unwrap()
        .into_string()
        .unwrap();
    let source = concat!(
        "main = Process.runProcess_ $\n",
        "  Process.setStdout Process.nullStream $\n",
        "  Process.setStderr Process.nullStream $\n",
        "  Process.setEnv [(\"LC_ALL\",\"C\")] $\n",
        "  Process.proc \"native-helper\" ",
        "[\"process_path_child_observes_exact_replacement_environment\",",
        "\"--exact\",\"--ignored\"]\n",
    );
    let program =
        compile_source(&mut CompilerSession::default(), "process-path.hell", source).unwrap();
    let context = RuntimeContext::with_host(
        Vec::new(),
        vec![
            (Arc::from("PATH"), Arc::from(path.as_str())),
            (Arc::from("PATHEXT"), Arc::from(".BAT;.CMD;.EXE;.COM")),
        ],
        Vec::<u8>::new(),
        directory.clone(),
        true,
    );
    run_main(program, context).unwrap();

    std::fs::remove_file(second.join("native-helper.exe")).unwrap();
    let program =
        compile_source(&mut CompilerSession::default(), "process-path.hell", source).unwrap();
    let context = RuntimeContext::with_host(
        Vec::new(),
        vec![
            (Arc::from("PATH"), Arc::from(path.as_str())),
            (Arc::from("PATHEXT"), Arc::from(".BAT;.CMD")),
        ],
        Vec::<u8>::new(),
        directory.clone(),
        true,
    );
    let error = run_main(program, context).unwrap_err();
    assert_eq!(error.kind, RuntimeErrorKind::Io);
    assert_eq!(
        error.presentation,
        Some(RuntimeErrorPresentation::ProcessNotFound {
            command: Arc::from("native-helper"),
        })
    );
    assert!(error.message.contains("captured parent PATH"));

    for command in ["first/native-helper.bat", "first/native-helper.cmd"] {
        let source = format!(
            concat!(
                "main = Process.runProcess_ $\n",
                "  Process.setEnv [(\"LC_ALL\",\"C\")] $\n",
                "  Process.proc {command:?} []\n",
            ),
            command = command,
        );
        let program = compile_source(
            &mut CompilerSession::default(),
            "process-path.hell",
            source.as_str(),
        )
        .unwrap();
        let context = RuntimeContext::with_host(
            Vec::new(),
            vec![(Arc::from("PATH"), Arc::from(path.as_str()))],
            Vec::<u8>::new(),
            directory.clone(),
            true,
        );
        let error = run_main(program, context).unwrap_err();
        assert_eq!(error.kind, RuntimeErrorKind::Io);
        assert_eq!(error.presentation, None);
        assert!(error.message.contains("is not a native COM/EXE executable"));
    }
    std::fs::remove_dir_all(directory).unwrap();
}

#[cfg(windows)]
#[test]
#[ignore = "executed only as the child of the captured-PATH process regression"]
fn process_path_child_observes_exact_replacement_environment() {
    assert_eq!(
        std::env::var_os("LC_ALL").as_deref(),
        Some(std::ffi::OsStr::new("C"))
    );
    assert_eq!(std::env::var_os("PATH"), None);
}

#[test]
fn process_timeout_terminates_the_entire_descendant_tree() {
    let directory =
        std::env::temp_dir().join(format!("hell-rs-process-tree-{}", std::process::id()));
    let _already_absent = std::fs::remove_dir_all(&directory);
    std::fs::create_dir(&directory).unwrap();
    let source = concat!(
        "main = do\n",
        "  helpers <- Environment.getArgs\n",
        "  Monad.forM_ helpers \\helper -> do\n",
        "    _result <- Timeout.timeout 100000 $ Process.runProcess_ $\n",
        "      Process.setStdout Process.nullStream $\n",
        "      Process.setStderr Process.nullStream $\n",
        "      Process.proc helper [\"spawn-grandchild\", \"grandchild-marker\"]\n",
        "    Concurrent.threadDelay 600000\n",
    );
    assert_eq!(
        run_in_with_args(source, process_fixture_arguments(), directory.clone(), true).unwrap(),
        ""
    );
    assert!(!directory.join("grandchild-marker").exists());
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn process_capture_closes_descendants_after_the_leader_exits() {
    let directory =
        std::env::temp_dir().join(format!("hell-rs-process-exit-tree-{}", std::process::id()));
    let _already_absent = std::fs::remove_dir_all(&directory);
    std::fs::create_dir(&directory).unwrap();
    let source = concat!(
        "main = do\n",
        "  helpers <- Environment.getArgs\n",
        "  Monad.forM_ helpers \\helper -> do\n",
        "    _result <- ByteString.readProcess $\n",
        "      Process.proc helper [\"spawn-grandchild-exit\", \"grandchild-marker\"]\n",
        "    Concurrent.threadDelay 600000\n",
    );
    assert_eq!(
        run_in_with_args(source, process_fixture_arguments(), directory.clone(), true).unwrap(),
        ""
    );
    assert!(!directory.join("grandchild-marker").exists());
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn buffering_modes_and_null_handle_reads_are_real_io_actions() {
    assert_eq!(
        run(concat!(
            "main = do\n",
            "  IO.hSetBuffering IO.stdout IO.NoBuffering\n",
            "  Text.putStr \"unbuffered\"\n",
            "  IO.hSetBuffering IO.stdout IO.LineBuffering\n",
            "  bytes <- ByteString.hGet IO.stdin 4\n",
            "  ByteString.hPutStr IO.stdout bytes\n",
            "  Text.putStrLn \"-done\"\n",
        )),
        "unbuffered-done\n"
    );
}

#[test]
fn standard_input_actions_share_an_injectable_byte_stream_without_utf8_loss() {
    let text_get_line = concat!(
        "main = do\n",
        "  line <- Text.getLine\n",
        "  Text.putStr line\n",
    );
    assert_eq!(run_with_input(text_get_line, b"line\n".to_vec()), b"line");
    assert_eq!(
        run_with_input(
            concat!(
                "main = do\n",
                "  line <- Text.getLine\n",
                "  rest <- Text.getContents\n",
                "  Text.putStrLn line\n",
                "  Text.putStr rest\n",
            ),
            "first\r\nsecond λ".as_bytes().to_vec(),
        ),
        "first\r\nsecond λ".as_bytes()
    );
    assert_eq!(
        run_with_input(text_get_line, b"bare carriage return\r".to_vec()),
        b"bare carriage return\r"
    );
    assert_eq!(
        run_with_input(text_get_line, b"unterminated".to_vec()),
        b"unterminated"
    );
    let empty_error = run_with_input_error(text_get_line, Vec::new());
    assert_eq!(empty_error.code, "H0903");
    assert_eq!(empty_error.kind, RuntimeErrorKind::Io);
    assert_eq!(empty_error.message.as_ref(), "Text.getLine: end of input");
    assert_eq!(
        empty_error.to_string(),
        "hell: <stdin>: Data.ByteString.hGetLine: end of file"
    );
    let invalid_utf8_error = run_with_input_error(text_get_line, vec![0xff, b'\n']);
    assert_eq!(invalid_utf8_error.code, "H0903");
    assert_eq!(invalid_utf8_error.kind, RuntimeErrorKind::Io);
    assert_eq!(
        invalid_utf8_error.message.as_ref(),
        "Text.getLine: invalid UTF-8 at byte 0"
    );
    assert_eq!(
        invalid_utf8_error.to_string(),
        "hell: Cannot decode byte '\\xff': Data.Text.Encoding: Invalid UTF-8 stream"
    );

    assert_eq!(
        run_with_input(
            concat!(
                "main = do\n",
                "  contents <- Text.getContents\n",
                "  Text.putStr contents\n",
            ),
            b"text\r\ncontents\r".to_vec(),
        ),
        b"text\r\ncontents\r"
    );
    assert_eq!(
        run_with_input(
            concat!(
                "main = do\n",
                "  prefix <- ByteString.hGet IO.stdin 3\n",
                "  suffix <- ByteString.getContents\n",
                "  ByteString.hPutStr IO.stdout prefix\n",
                "  ByteString.hPutStr IO.stdout suffix\n",
            ),
            vec![0, 0xff, b'X', b'Y', b'\n'],
        ),
        [0, 0xff, b'X', b'Y', b'\n']
    );
    assert_eq!(
        run_with_input(
            "main = ByteString.interact Function.id\n",
            vec![0x00, 0xff, b'X', 0xce],
        ),
        [0x00, 0xff, b'X', 0xce]
    );
    assert_eq!(
        run_with_input(
            "main = Text.interact Text.toUpper\n",
            "aλ".as_bytes().to_vec(),
        ),
        "AΛ".as_bytes()
    );
}

#[test]
fn text_input_utf8_diagnostics_retain_io_identity_and_report_the_first_invalid_byte() {
    let decode = concat!(
        "main = do\n",
        "  bytes <- ByteString.getContents\n",
        "  IO.print $ Text.decodeUtf8 bytes\n",
    );
    let decode_error = run_with_input_error(decode, vec![0x80]);
    assert_eq!(decode_error.code, "H0903");
    assert_eq!(decode_error.kind, RuntimeErrorKind::Io);
    assert_eq!(
        decode_error.message.as_ref(),
        "Text.decodeUtf8: invalid UTF-8 at byte 0"
    );
    assert_eq!(
        decode_error.to_string(),
        "hell: Cannot decode byte '\\x80': Data.Text.Encoding: Invalid UTF-8 stream"
    );

    let get_contents = concat!(
        "main = do\n",
        "  text <- Text.getContents\n",
        "  Text.putStr text\n",
    );
    let truncated_error = run_with_input_error(get_contents, vec![b'a', 0xce]);
    assert_eq!(truncated_error.code, "H0903");
    assert_eq!(truncated_error.kind, RuntimeErrorKind::Io);
    assert_eq!(
        truncated_error.message.as_ref(),
        "Text.getContents: invalid UTF-8 at byte 1"
    );
    assert_eq!(
        truncated_error.to_string(),
        "hell: Cannot decode byte '\\xce': Data.Text.Encoding: Invalid UTF-8 stream"
    );
    let invalid_continuation_error = run_with_input_error(get_contents, vec![0xc2, b'A']);
    assert_eq!(
        invalid_continuation_error.to_string(),
        "hell: Cannot decode byte '\\xc2': Data.Text.Encoding: Invalid UTF-8 stream"
    );

    let interact_error = run_with_input_error("main = Text.interact Text.toUpper\n", vec![0xff]);
    assert_eq!(interact_error.code, "H0903");
    assert_eq!(interact_error.kind, RuntimeErrorKind::Io);
    assert_eq!(
        interact_error.to_string(),
        "H0903: Text.interact: input is not valid UTF-8 at byte 0"
    );
}

#[test]
fn json_codec_round_trips_raw_byte_files_with_sorted_object_keys() {
    let directory = std::env::temp_dir().join(format!("hell-rs-json-{}", std::process::id()));
    let _already_absent = std::fs::remove_dir_all(&directory);
    std::fs::create_dir(&directory).unwrap();
    let source = concat!(
        "main = do\n",
        "  ByteString.writeFile \"value.json\" $ Json.encode $ Json.Object $\n",
        "    Map.fromList [(\"name\", Json.String \"λ\"), (\"age\", Json.Number 99.125)]\n",
        "  bytes <- ByteString.readFile \"value.json\"\n",
        "  ByteString.hPutStr IO.stdout bytes\n",
        "  Text.putStrLn \"\"\n",
        "  Text.putStrLn $ Maybe.maybe \"bad\"\n",
        "    (Json.value \"null\" (\\flag -> \"bool\") (\\text -> text)\n",
        "      (\\number -> \"number\") (\\array -> \"array\") (\\object -> \"object\"))\n",
        "    (Json.decode bytes)\n",
        "  Directory.removeFile \"value.json\"\n",
    );
    assert_eq!(
        run_in(source, directory.clone(), true).unwrap(),
        "{\"age\":99.125,\"name\":\"λ\"}\nobject\n"
    );
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn scoped_temp_resources_and_explicit_file_handles_cleanup_and_preserve_bytes() {
    let directory = std::env::temp_dir().join(format!("hell-rs-open-file-{}", std::process::id()));
    let _already_absent = std::fs::remove_dir_all(&directory);
    std::fs::create_dir(&directory).unwrap();
    let source = concat!(
        "main = do\n",
        "  handle <- IO.openFile \"out.txt\" IO.WriteMode\n",
        "  Text.hPutStr handle \"hello λ\"\n",
        "  IO.hClose handle\n",
        "  IO.hClose handle\n",
        "  contents <- Text.readFile \"out.txt\"\n",
        "  Text.putStrLn contents\n",
        "  Temp.withSystemTempDirectory \"hell-rs-scope\" \\path ->\n",
        "    Text.putStrLn path\n",
        "  Temp.withSystemTempFile \"hell-rs-scope\" \\path tempHandle -> do\n",
        "    ByteString.hPutStr tempHandle (Text.encodeUtf8 \"raw λ\")\n",
        "    Text.putStrLn path\n",
        "  helpers <- Environment.getArgs\n",
        "  Monad.forM_ helpers \\helper ->\n",
        "    Temp.withSystemTempFile \"hell-rs-process\" \\path processHandle -> do\n",
        "      let process = Process.setStdout (Process.useHandleClose processHandle) $\n",
        "            Process.proc helper [\"emit\", \"redirected\", \"\"]\n",
        "      Text.putStrLn path\n",
        "      Process.runProcess_ process\n",
        "      IO.hClose processHandle\n",
        "      redirected <- Text.readFile path\n",
        "      Text.putStrLn redirected\n",
        "  Directory.removeFile \"out.txt\"\n",
    );
    let output =
        run_in_with_args(source, process_fixture_arguments(), directory.clone(), true).unwrap();
    let mut lines = output.lines();
    assert_eq!(lines.next(), Some("hello λ"));
    let temp_directory = PathBuf::from(lines.next().unwrap());
    let temp_file = PathBuf::from(lines.next().unwrap());
    let process_temp_file = PathBuf::from(lines.next().unwrap());
    assert_eq!(lines.next(), Some("redirected"));
    assert_eq!(lines.next(), None);
    assert!(!temp_directory.exists());
    assert!(!temp_file.exists());
    assert!(!process_temp_file.exists());
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn scoped_temporary_resources_are_deleted_before_runtime_completion() {
    let directory =
        std::env::temp_dir().join(format!("hell-rs-temp-cleanup-{}", std::process::id()));
    let _already_absent = std::fs::remove_dir_all(&directory);
    std::fs::create_dir(&directory).unwrap();
    let source = concat!(
        "main = do\n",
        "  Temp.withSystemTempDirectory \"hell-rs-cleanup-directory\" \\path ->\n",
        "    Text.putStrLn path\n",
        "  Temp.withSystemTempFile \"hell-rs-cleanup-file\" \\path handle -> do\n",
        "    Text.hPutStr handle \"retained bytes\"\n",
        "    Text.putStrLn path\n",
    );
    let output = run_in(source, directory.clone(), true).unwrap();
    let paths = output.lines().map(PathBuf::from).collect::<Vec<_>>();
    assert_eq!(paths.len(), 2);
    let retained = paths.iter().filter(|path| path.exists()).count();
    for path in &paths {
        if path.is_dir() {
            let _removed = std::fs::remove_dir_all(path);
        } else {
            let _removed = std::fs::remove_file(path);
        }
    }
    std::fs::remove_dir_all(directory).unwrap();
    assert_eq!(
        retained, 0,
        "scoped temporary resources leaked after runtime completion"
    );
}

#[test]
fn records_user_cases_and_maybe_cases_execute_selected_values() {
    assert_eq!(
        run("data Person = Person { name :: Text, age :: Int }\n\
             main = Text.putStrLn (Record.get @\"name\" @Text \
             Main.Person { age = 23, name = \"Chris\" })\n"),
        "Chris\n"
    );
    assert_eq!(
        run("data Answer = No | Yes Text\n\
             main = case Main.Yes \"selected\" of\n\
               No -> Error.error \"wrong branch\"\n\
               Yes value -> Text.putStrLn value\n"),
        "selected\n"
    );
    assert_eq!(
        run("main = case Maybe.Just \"just\" of\n\
               Maybe.Nothing -> Error.error \"wrong branch\"\n\
               Maybe.Just value -> Text.putStrLn value\n"),
        "just\n"
    );
}

#[test]
fn either_case_selects_left_and_keeps_right_lazy() {
    assert_eq!(
        run("main = case Either.Left \"selected\" of\n\
               Either.Left value -> Text.putStrLn value\n\
               Either.Right code -> Error.error (Int.show code)\n"),
        "selected\n"
    );
}

#[test]
fn exit_case_selects_failure_and_binds_its_code() {
    assert_eq!(
        run("main = case Exit.ExitFailure 23 of\n\
               Exit.ExitSuccess -> Error.error \"wrong branch\"\n\
               Exit.ExitFailure code -> IO.print code\n"),
        "23\n"
    );
}

#[test]
fn these_case_binds_both_payloads_in_source_order() {
    assert_eq!(
        run("main = case These.These 20 22 of\n\
               These.This left -> Error.error \"wrong branch\"\n\
               These.That right -> Error.error \"wrong branch\"\n\
               These.These left right -> IO.print (Int.plus left right)\n"),
        "42\n"
    );
}

#[test]
fn json_case_selects_string_without_forcing_other_handlers() {
    assert_eq!(
        run("main = case Json.String \"selected\" of\n\
               Json.Null -> Error.error \"wrong null branch\"\n\
               Json.Bool flag -> Error.error \"wrong bool branch\"\n\
               Json.String value -> Text.putStrLn value\n\
               Json.Number number -> Error.error \"wrong number branch\"\n\
               Json.Array values -> Error.error \"wrong array branch\"\n\
               Json.Object object -> Error.error \"wrong object branch\"\n"),
        "selected\n"
    );
    assert_eq!(
        run(
            "main = case Json.Array (Error.error \"unused payload\" :: Vector Value) of\n\
               Json.Array values -> Text.putStrLn \"array\"\n\
               _ -> Error.error \"wrong branch\"\n"
        ),
        "array\n"
    );
    assert_eq!(
        run(
            "main = case Json.Object (Error.error \"unused payload\" :: Map Text Value) of\n\
               Json.Object object -> Text.putStrLn \"object\"\n\
               _ -> Error.error \"wrong branch\"\n"
        ),
        "object\n"
    );
}

#[test]
fn primitive_case_wildcard_expands_in_constructor_order() {
    assert_eq!(
        run("main = case Json.Null of\n\
               Json.String value -> Error.error value\n\
               _ -> Text.putStrLn \"fallback\"\n"),
        "fallback\n"
    );
}

#[test]
fn deeply_nested_forcing_uses_the_heap_backed_machine_stack() {
    let mut source = String::from("main = IO.print $ ");
    for _ in 0..180 {
        source.push_str("Function.id $ ");
    }
    source.push_str("1\n");

    assert_eq!(run(&source), "1\n");

    let mut strict_source = String::from("main = IO.print $ ");
    for _ in 0..180 {
        strict_source.push_str("Int.plus 1 $ ");
    }
    strict_source.push_str("0\n");
    assert_eq!(run(&strict_source), "180\n");
}
