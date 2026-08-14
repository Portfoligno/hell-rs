use std::io::Write;
use std::sync::{Arc, Mutex};

use hell_compiler::{CompilerSession, compile_source};
use hell_runtime::{RuntimeContext, RuntimeErrorKind, run_main};

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

fn run(source: &str, arguments: &[&str]) -> (Result<(), Arc<hell_runtime::RuntimeError>>, String) {
    let (result, stdout, _stderr) = run_with_streams(source, arguments);
    (result, stdout)
}

fn run_with_streams(
    source: &str,
    arguments: &[&str],
) -> (Result<(), Arc<hell_runtime::RuntimeError>>, String, String) {
    let program = compile_source(&mut CompilerSession::default(), "options.hell", source).unwrap();
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

fn assert_option_error(source: &str, arguments: &[&str], expected: &str) {
    let (result, stdout, stderr) = run_with_streams(source, arguments);
    assert_eq!(result.unwrap_err().kind, RuntimeErrorKind::Exit(1));
    assert!(stdout.is_empty());
    assert_eq!(stderr, expected);
}

fn required_application_source(operator: &str) -> String {
    let operation = if operator == "<**>" {
        "Main.value <**> Main.function"
    } else {
        "Main.function <*> Main.value"
    };
    format!(
        concat!(
            "function = (\\delta value -> Text.concat [delta, value]) <$> ",
            "Options.strOption (Option.long \"function\")\n",
            "value = Options.strOption (Option.long \"value\")\n",
            "parser = {operation}\n",
            "main = do {{ _ <- Options.execParser $ Options.info Main.parser ",
            "Options.fullDesc; IO.pure () }}\n",
        ),
        operation = operation,
    )
}

#[test]
fn options_plan_preserves_occurrences_interspersal_and_double_dash() {
    let source = concat!(
        "parser = (\\names item verbose -> (names,item,verbose))\n",
        "  <$> Alternative.many (Options.strOption (Option.long \"name\"))\n",
        "  <*> Options.strArgument (Argument.metavar \"ITEM\")\n",
        "  <*> Options.switch (Flag.long \"verbose\")\n",
        "main = do\n",
        "  parsed <- Options.execParser $ Options.info Main.parser Options.fullDesc\n",
        "  let (names,item,verbose) = parsed\n",
        "  IO.print names\n",
        "  Text.putStrLn item\n",
        "  IO.print verbose\n",
    );
    let (result, output) = run(
        source,
        &["--name", "one", "target", "--name=two", "--verbose"],
    );
    result.unwrap();
    assert_eq!(output, "[\"one\",\"two\"]\ntarget\nTrue\n");

    let positional = concat!(
        "main = do\n",
        "  value <- Options.execParser $ Options.info\n",
        "    (Options.strArgument (Argument.metavar \"VALUE\")) Options.fullDesc\n",
        "  Text.putStrLn value\n",
    );
    let (result, output) = run(positional, &["--", "--literal"]);
    result.unwrap();
    assert_eq!(output, "--literal\n");
}

#[test]
fn malformed_present_options_do_not_fall_through_optional_or_many() {
    let optional = concat!(
        "main = do\n",
        "  value <- Options.execParser $ Options.info\n",
        "    (Alternative.optional $ Options.strOption (Option.long \"name\"))\n",
        "    Options.fullDesc\n",
        "  IO.print value\n",
    );
    let (result, output, stderr) = run_with_streams(optional, &["--name"]);
    let error = result.unwrap_err();
    assert_eq!(error.kind, RuntimeErrorKind::Exit(1));
    assert_eq!(
        stderr,
        "The option `--name` expects an argument.\n\nUsage: hell [--name ARG]\n"
    );
    assert!(output.is_empty());

    let repeated = concat!(
        "main = do\n",
        "  value <- Options.execParser $ Options.info\n",
        "    (Options.strOption (Option.long \"name\")) Options.fullDesc\n",
        "  Text.putStrLn value\n",
    );
    let (result, output, stderr) = run_with_streams(repeated, &["--name=one", "--name=two"]);
    let error = result.unwrap_err();
    assert_eq!(error.kind, RuntimeErrorKind::Exit(1));
    assert_eq!(
        stderr,
        "Invalid option `--name'\n\nUsage: hell --name ARG\n"
    );
    assert!(output.is_empty());

    let composed_modifiers = concat!(
        "main = do\n",
        "  enabled <- Options.execParser $ Options.info\n",
        "    (Options.switch (Flag.long \"one\" <> Flag.long \"two\") <**> Options.helper) Options.fullDesc\n",
        "  IO.print enabled\n",
    );
    let (result, output) = run(composed_modifiers, &["--two"]);
    result.unwrap();
    assert_eq!(output, "True\n");
    let (result, output) = run(composed_modifiers, &["--help"]);
    assert_eq!(result.unwrap_err().kind, RuntimeErrorKind::Exit(0));
    assert!(output.contains("--one|--two"));

    let later_default = concat!(
        "main = do\n",
        "  value <- Options.execParser $ Options.info\n",
        "    (Options.strOption (Option.long \"name\" <> Option.value \"first\" <> Option.value \"second\"))\n",
        "    Options.fullDesc\n",
        "  Text.putStrLn value\n",
    );
    let (result, output) = run(later_default, &[]);
    result.unwrap();
    assert_eq!(output, "second\n");
}

#[test]
fn options_diagnostics_and_help_match_the_pinned_oracle() {
    let required = concat!(
        "parser = Options.strOption (Option.long \"name\") <**> Options.helper\n",
        "main = do\n",
        "  _ <- Options.execParser $ Options.info Main.parser Options.fullDesc\n",
        "  IO.pure ()\n",
    );
    for (arguments, expected) in [
        (
            Vec::<&str>::new(),
            "Missing: --name ARG\n\nUsage: hell --name ARG\n",
        ),
        (
            vec!["--name"],
            "The option `--name` expects an argument.\n\nUsage: hell --name ARG\n",
        ),
        (
            vec!["--unknown"],
            "Invalid option `--unknown'\n\nUsage: hell --name ARG\n",
        ),
    ] {
        let (result, stdout, stderr) = run_with_streams(required, &arguments);
        assert_eq!(result.unwrap_err().kind, RuntimeErrorKind::Exit(1));
        assert!(stdout.is_empty());
        assert_eq!(stderr, expected);
    }
    let (result, stdout, stderr) = run_with_streams(required, &["--help"]);
    assert_eq!(result.unwrap_err().kind, RuntimeErrorKind::Exit(0));
    assert_eq!(
        stdout,
        concat!(
            "Usage: hell --name ARG\n\n",
            "Available options:\n",
            "  -h,--help                Show this help text\n",
        )
    );
    assert!(stderr.is_empty());

    let composed = concat!(
        "parser = (\\names optional required -> (names,optional,required))\n",
        "  <$> Alternative.many (Options.strOption (Option.long \"name\"))\n",
        "  <*> Alternative.optional (Options.strOption (Option.long \"tag\"))\n",
        "  <*> Options.strArgument (Argument.metavar \"FILE\")\n",
        "main = do\n",
        "  _ <- Options.execParser $ Options.info (Main.parser <**> Options.helper) Options.fullDesc\n",
        "  IO.pure ()\n",
    );
    let (result, stdout, stderr) = run_with_streams(composed, &["--help"]);
    assert_eq!(result.unwrap_err().kind, RuntimeErrorKind::Exit(0));
    assert_eq!(
        stdout,
        concat!(
            "Usage: hell [--name ARG] [--tag ARG] FILE\n\n",
            "Available options:\n",
            "  -h,--help                Show this help text\n",
        )
    );
    assert!(stderr.is_empty());

    let command = concat!(
        "add = Options.strArgument (Argument.metavar \"FILE\" <> Argument.help \"File to add\")\n",
        "parser = Options.hsubparser $ Options.command \"add\"\n",
        "  (Options.info (Main.add <**> Options.helper) (Options.progDesc \"Add a file\"))\n",
        "main = do\n",
        "  _ <- Options.execParser $ Options.info (Main.parser <**> Options.helper) Options.fullDesc\n",
        "  IO.pure ()\n",
    );
    let (result, stdout, stderr) = run_with_streams(command, &["add", "--help"]);
    assert_eq!(result.unwrap_err().kind, RuntimeErrorKind::Exit(0));
    assert_eq!(
        stdout,
        concat!(
            "Usage: hell add FILE\n\n",
            "  Add a file\n\n",
            "Available options:\n",
            "  FILE                     File to add\n",
            "  -h,--help                Show this help text\n",
            "  -h,--help                Show this help text\n",
        )
    );
    assert!(stderr.is_empty());
    let (result, stdout, stderr) = run_with_streams(command, &["add"]);
    assert_eq!(result.unwrap_err().kind, RuntimeErrorKind::Exit(1));
    assert!(stdout.is_empty());
    assert_eq!(
        stderr,
        "Missing: FILE\n\nUsage: hell add FILE\n\n  Add a file\n"
    );
}

#[test]
fn command_diagnostics_retain_the_parser_context_that_owns_the_error() {
    let commands = concat!(
        "parser = Options.hsubparser $\n",
        "  Options.command \"run\" (Options.info (Applicative.pure \"ran\") Options.fullDesc) <>\n",
        "  Options.command \"stop\" (Options.info (Applicative.pure \"stopped\") Options.fullDesc)\n",
        "main = do\n",
        "  _ <- Options.execParser $ Options.info Main.parser Options.fullDesc\n",
        "  IO.pure ()\n",
    );
    for (arguments, unexpected) in [(&["run", "run"][..], "run"), (&["run", "stop"][..], "stop")] {
        assert_option_error(
            commands,
            arguments,
            &format!("Invalid argument `{unexpected}'\n\nUsage: hell COMMAND\n"),
        );
    }
    assert_option_error(
        commands,
        &["run", "extra"],
        "Invalid argument `extra'\n\nUsage: hell run\n",
    );

    let child_option = concat!(
        "child = Options.strOption (Option.long \"name\")\n",
        "parser = Options.hsubparser $ Options.command \"run\"\n",
        "  (Options.info Main.child Options.fullDesc)\n",
        "main = do\n",
        "  _ <- Options.execParser $ Options.info Main.parser Options.fullDesc\n",
        "  IO.pure ()\n",
    );
    assert_option_error(
        child_option,
        &["run", "--unknown"],
        "Invalid option `--unknown'\n\nUsage: hell run --name ARG\n",
    );
    assert_option_error(
        child_option,
        &["run"],
        "Missing: --name ARG\n\nUsage: hell run --name ARG\n",
    );
    assert_option_error(
        child_option,
        &["run", "--name"],
        "The option `--name` expects an argument.\n\nUsage: hell run --name ARG\n",
    );
}

#[test]
fn option_alias_help_is_canonical_in_pinned_lexical_order() {
    for (modifiers, expected) in [
        (
            "Flag.long \"zeta\" <> Flag.long \"alpha\"",
            "--alpha|--zeta",
        ),
        (
            "Flag.long \"alpha\" <> Flag.long \"zeta\"",
            "--alpha|--zeta",
        ),
        (
            "Flag.long \"one\" <> Flag.long \"two\" <> Flag.long \"three\"",
            "--one|--three|--two",
        ),
    ] {
        let source = format!(
            concat!(
                "parser = Options.switch ({modifiers}) <**> Options.helper\n",
                "main = do {{ _ <- Options.execParser $ Options.info Main.parser ",
                "Options.fullDesc; IO.pure () }}\n",
            ),
            modifiers = modifiers,
        );
        let (result, stdout, stderr) = run_with_streams(&source, &["--help"]);
        assert_eq!(result.unwrap_err().kind, RuntimeErrorKind::Exit(0));
        assert_eq!(
            stdout,
            format!(
                "Usage: hell [{expected}]\n\nAvailable options:\n  \
                 -h,--help                Show this help text\n"
            )
        );
        assert!(stderr.is_empty());
    }
}

#[test]
fn required_applications_accumulate_missing_fields_in_surface_order() {
    let apply = required_application_source("<*>");
    for (arguments, missing) in [
        (&[][..], "--function ARG --value ARG"),
        (&["--function", "f"][..], "--value ARG"),
        (&["--value", "v"][..], "--function ARG"),
    ] {
        assert_option_error(
            &apply,
            arguments,
            &format!("Missing: {missing}\n\nUsage: hell --function ARG --value ARG\n"),
        );
    }
    let flipped = required_application_source("<**>");
    for (arguments, missing) in [
        (&[][..], "--value ARG --function ARG"),
        (&["--function", "f"][..], "--value ARG"),
        (&["--value", "v"][..], "--function ARG"),
    ] {
        assert_option_error(
            &flipped,
            arguments,
            &format!("Missing: {missing}\n\nUsage: hell --value ARG --function ARG\n"),
        );
    }
}

#[test]
fn nested_and_positional_missing_fields_retain_order_and_duplicates() {
    let three = concat!(
        "required = (\\first second third -> Text.concat [first, second, third])\n",
        "  <$> Options.strOption (Option.long \"first\")\n",
        "  <*> Options.strOption (Option.long \"second\")\n",
        "  <*> Options.strOption (Option.long \"third\")\n",
        "parser = Alternative.optional Main.required\n",
        "main = do { _ <- Options.execParser $ Options.info Main.parser ",
        "Options.fullDesc; IO.pure () }\n",
    );
    assert_option_error(
        three,
        &["--first", "x"],
        concat!(
            "Missing: --second ARG --third ARG\n\n",
            "Usage: hell [--first ARG --second ARG --third ARG]\n",
        ),
    );
    assert_option_error(
        three,
        &["--second", "x"],
        concat!(
            "Missing: --first ARG --third ARG\n\n",
            "Usage: hell [--first ARG --second ARG --third ARG]\n",
        ),
    );
    let option_position = concat!(
        "parser = (\\name file -> Text.concat [name, file])\n",
        "  <$> Options.strOption (Option.long \"name\")\n",
        "  <*> Options.strArgument (Argument.metavar \"FILE\")\n",
        "main = do { _ <- Options.execParser $ Options.info Main.parser ",
        "Options.fullDesc; IO.pure () }\n",
    );
    assert_option_error(
        option_position,
        &[],
        "Missing: --name ARG FILE\n\nUsage: hell --name ARG FILE\n",
    );
    let repeated = concat!(
        "parser = (\\first second -> Text.concat [first, second])\n",
        "  <$> Options.strArgument (Argument.metavar \"ARG\")\n",
        "  <*> Options.strArgument (Argument.metavar \"ARG\")\n",
        "main = do { _ <- Options.execParser $ Options.info Main.parser ",
        "Options.fullDesc; IO.pure () }\n",
    );
    assert_option_error(repeated, &[], "Missing: ARG ARG\n\nUsage: hell ARG ARG\n");
}

#[test]
fn optional_default_and_switch_nodes_do_not_add_missing_fields() {
    let source = concat!(
        "parser = (\\optional defaulted switched required -> required)\n",
        "  <$> Alternative.optional (Options.strOption (Option.long \"tag\"))\n",
        "  <*> Options.strOption (Option.long \"name\" <> Option.value \"default\")\n",
        "  <*> Options.switch (Flag.long \"flag\")\n",
        "  <*> Options.strOption (Option.long \"required\")\n",
        "main = do { _ <- Options.execParser $ Options.info Main.parser ",
        "Options.fullDesc; IO.pure () }\n",
    );
    assert_option_error(
        source,
        &[],
        concat!(
            "Missing: --required ARG\n\n",
            "Usage: hell [--tag ARG] [--name ARG] [--flag] --required ARG\n",
        ),
    );
}

#[test]
fn timeout_cancels_zero_consumption_many_instead_of_raising_a_parser_error() {
    let source = concat!(
        "parser = Alternative.many $ Applicative.pure \"value\"\n",
        "main = do\n",
        "  result <- Timeout.timeout 100000 $ ",
        "Options.execParser $ Options.info Main.parser Options.fullDesc\n",
        "  Maybe.maybe (Text.putStr \"timeout\") ",
        "(\\values -> IO.print $ List.length values) result\n",
    );
    let (result, output) = run(source, &[]);
    result.unwrap();
    assert_eq!(output, "timeout");
}

#[test]
fn helper_short_circuits_required_fields_at_root_and_in_commands() {
    let root = concat!(
        "parser = Options.strArgument (Argument.metavar \"FILE\" <> Argument.help \"Input file\")\n",
        "main = do\n",
        "  _value <- Options.execParser $ Options.info (Main.parser <**> Options.helper)\n",
        "    (Options.header \"Example header\" <> Options.progDesc \"Example description\")\n",
        "  Text.putStrLn \"ran\"\n",
    );
    let (result, output) = run(root, &["--help"]);
    let error = result.unwrap_err();
    assert_eq!(error.kind, RuntimeErrorKind::Exit(0));
    assert!(output.contains("Example header"));
    assert!(output.contains("Example description"));
    assert!(output.contains("FILE"));
    assert!(output.contains("--help"));
    assert!(!output.contains("ran"));

    let command = concat!(
        "add = Options.strArgument (Argument.metavar \"FILE\" <> Argument.help \"File to add\")\n",
        "parser = Options.hsubparser $ Options.command \"add\"\n",
        "  (Options.info Main.add (Options.progDesc \"Add a file\"))\n",
        "main = do\n",
        "  _value <- Options.execParser $ Options.info (Main.parser <**> Options.helper) Options.fullDesc\n",
        "  Text.putStrLn \"ran\"\n",
    );
    let (result, output) = run(command, &["add", "--help"]);
    let error = result.unwrap_err();
    assert_eq!(error.kind, RuntimeErrorKind::Exit(0));
    assert!(output.contains("Add a file"));
    assert!(output.contains("FILE"));
    assert!(output.contains("--help"));
    assert!(!output.contains("ran"));
}
