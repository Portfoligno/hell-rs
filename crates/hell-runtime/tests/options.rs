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
    let program = compile_source(&mut CompilerSession::default(), "options.hell", source).unwrap();
    let bytes = Arc::new(Mutex::new(Vec::new()));
    let context = RuntimeContext::new(
        arguments.iter().copied().map(Arc::<str>::from).collect(),
        SharedWriter(Arc::clone(&bytes)),
    );
    let result = run_main(program, context);
    let output = String::from_utf8(bytes.lock().unwrap().clone()).unwrap();
    (result, output)
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
    let (result, output) = run(optional, &["--name"]);
    let error = result.unwrap_err();
    assert_eq!(error.kind, RuntimeErrorKind::UserError);
    assert!(error.message.contains("requires an argument"));
    assert!(output.is_empty());

    let repeated = concat!(
        "main = do\n",
        "  value <- Options.execParser $ Options.info\n",
        "    (Options.strOption (Option.long \"name\")) Options.fullDesc\n",
        "  Text.putStrLn value\n",
    );
    let (result, output) = run(repeated, &["--name=one", "--name=two"]);
    let error = result.unwrap_err();
    assert_eq!(error.kind, RuntimeErrorKind::UserError);
    assert!(error.message.contains("unexpected repeated option"));
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
