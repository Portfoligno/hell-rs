use std::io::Write;
use std::sync::{Arc, Mutex};

use hell_compiler::{CompilerSession, compile_source};
use hell_runtime::{RuntimeContext, RuntimeError, RuntimeErrorKind, run_main};

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

fn run(source: &str, arguments: &[&str]) -> (Result<(), String>, String) {
    let (result, stdout, _stderr) = run_with_streams(source, arguments);
    (result.map_err(|error| error.to_string()), stdout)
}

fn run_with_streams(
    source: &str,
    arguments: &[&str],
) -> (Result<(), Arc<RuntimeError>>, String, String) {
    let program = compile_source(&mut CompilerSession::default(), "applicative.hell", source)
        .map_err(|error| error.to_string())
        .unwrap();
    let stdout = Arc::new(Mutex::new(Vec::new()));
    let stderr = Arc::new(Mutex::new(Vec::new()));
    let context = RuntimeContext::new(
        arguments.iter().copied().map(Arc::<str>::from).collect(),
        SharedWriter(Arc::clone(&stdout)),
    )
    .with_stderr(SharedWriter(Arc::clone(&stderr)));
    let result = run_main(program, context);
    let stdout = String::from_utf8(stdout.lock().unwrap().clone()).unwrap();
    let stderr = String::from_utf8(stderr.lock().unwrap().clone()).unwrap();
    (result, stdout, stderr)
}

#[test]
fn flipped_apply_is_value_major_for_list_and_tree() {
    let source = concat!(
        "main = do\n",
        "  IO.print $ ([Int.plus 10, Int.mult 2] <*> [1,2] :: [Int])\n",
        "  IO.print $ ([1,2] <**> [Int.plus 10, Int.mult 2] :: [Int])\n",
        "  IO.print $ Tree.flatten $ ((Tree.Node (Int.plus 10) [Tree.Node (Int.mult 2) []]) <*> (Tree.Node 1 [Tree.Node 2 []]) :: Tree Int)\n",
        "  IO.print $ Tree.flatten $ ((Tree.Node 1 [Tree.Node 2 []]) <**> (Tree.Node (Int.plus 10) [Tree.Node (Int.mult 2) []]) :: Tree Int)\n",
    );
    let (result, output) = run(source, &[]);
    result.unwrap();
    assert_eq!(
        output,
        "[11,12,2,4]\n[11,2,12,4]\n[11,12,2,4]\n[11,2,12,4]\n"
    );
}

#[test]
fn apply_short_circuits_in_the_operator_specific_outer_order() {
    let source = concat!(
        "main = do\n",
        "  IO.print ((Maybe.Nothing :: Maybe (Int -> Int)) <*> (Error.error \"argument\" :: Maybe Int))\n",
        "  IO.print ((Maybe.Nothing :: Maybe Int) <**> (Error.error \"function\" :: Maybe (Int -> Int)))\n",
        "  IO.print ((Either.Left \"function\" :: Either Text (Int -> Int)) <*> (Error.error \"argument\" :: Either Text Int))\n",
        "  IO.print ((Either.Left \"argument\" :: Either Text Int) <**> (Error.error \"function\" :: Either Text (Int -> Int)))\n",
        "  IO.print (([] :: [Int -> Int]) <*> (Error.error \"argument\" :: [Int]))\n",
        "  IO.print (([] :: [Int]) <**> (Error.error \"function\" :: [Int -> Int]))\n",
    );
    let (result, output) = run(source, &[]);
    result.unwrap();
    assert_eq!(
        output,
        "Nothing\nNothing\nLeft \"function\"\nLeft \"argument\"\n[]\n[]\n"
    );
}

#[test]
fn io_and_parser_apply_preserve_operator_specific_order_and_failure() {
    let io = concat!(
        "function = do { Text.putStr \"f\"; IO.pure (Int.plus 10) }\n",
        "argument = do { Text.putStr \"a\"; IO.pure 1 }\n",
        "main = do\n",
        "  first <- Main.function <*> Main.argument\n",
        "  IO.print first\n",
        "  second <- Main.argument <**> Main.function\n",
        "  IO.print second\n",
    );
    let (result, output) = run(io, &[]);
    result.unwrap();
    assert_eq!(output, "fa11\naf11\n");

    let parser = concat!(
        "function = (\\delta value -> Int.plus (Text.length delta) (Text.length value)) <$> Options.strOption (Option.long \"function\")\n",
        "value = Options.strOption (Option.long \"value\")\n",
        "parser = Main.value <**> Main.function\n",
        "main = do\n",
        "  result <- Options.execParser $ Options.info Main.parser Options.fullDesc\n",
        "  IO.print result\n",
    );
    let (result, output) = run(parser, &["--value", "abc", "--function", "xy"]);
    result.unwrap();
    assert_eq!(output, "5\n");
    let (result, stdout, stderr) = run_with_streams(parser, &["--function", "xy"]);
    assert_eq!(result.unwrap_err().kind, RuntimeErrorKind::Exit(1));
    assert!(stdout.is_empty());
    assert_eq!(
        stderr,
        "Missing: --value ARG\n\nUsage: hell --value ARG --function ARG\n"
    );
    let (result, stdout, stderr) = run_with_streams(parser, &[]);
    assert_eq!(result.unwrap_err().kind, RuntimeErrorKind::Exit(1));
    assert!(stdout.is_empty());
    assert_eq!(
        stderr,
        concat!(
            "Missing: --value ARG --function ARG\n\n",
            "Usage: hell --value ARG --function ARG\n",
        )
    );
}
