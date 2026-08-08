use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use hell_compiler::{CompilerSession, compile_source};
use hell_runtime::{RuntimeContext, RuntimeError, run_main};

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

fn run_in(source: &str, cwd: PathBuf, allow_filesystem: bool) -> Result<String, String> {
    run_in_with_args(source, Vec::new(), cwd, allow_filesystem)
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
fn unselected_bool_branch_is_not_forced() {
    assert_eq!(
        run("main = IO.print $ Bool.bool 1 (Error.error \"boom\" :: Int) Bool.False\n"),
        "1\n"
    );
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
            "Just -123456789012345678901234567890\n",
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
            "(\"a\",\"βc\")\n",
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
fn buffering_modes_and_null_handle_reads_are_real_io_actions() {
    assert_eq!(
        run(concat!(
            "main = do\n",
            "  IO.hSetBuffering IO.stdout IO.NoBuffering\n",
            "  Text.putStr \"unbuffered\"\n",
            "  IO.hSetBuffering IO.stdout IO.LineBuffering\n",
            "  bytes <- ByteString.hGet Process.nullStream 4\n",
            "  ByteString.hPutStr IO.stdout bytes\n",
            "  Text.putStrLn \"-done\"\n",
        )),
        "unbuffered-done\n"
    );
}

#[test]
fn standard_input_actions_share_an_injectable_byte_stream_without_utf8_loss() {
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
        "first\nsecond λ".as_bytes()
    );
    assert_eq!(
        run_with_input(
            "main = ByteString.interact Function.id\n",
            vec![0, 0xff, b'X'],
        ),
        [0, 0xff, b'X']
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
