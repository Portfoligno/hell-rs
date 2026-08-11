use std::io::Write;
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
    let program = compile_source(&mut CompilerSession::default(), "numeric.hell", source)
        .expect("numeric source compiles");
    let bytes = Arc::new(Mutex::new(Vec::new()));
    run_main(
        program,
        RuntimeContext::new(Vec::new(), SharedWriter(Arc::clone(&bytes))),
    )
    .expect("numeric program runs");
    String::from_utf8(bytes.lock().unwrap().clone()).expect("numeric output is UTF-8")
}

#[test]
fn int_subtract_preserves_operand_order_and_wrapping_boundary() {
    assert_eq!(
        run(concat!(
            "main = do\n",
            "  IO.print $ Int.subtract 9 4\n",
            "  IO.print $ Int.subtract 9223372036854775807 ",
            "(Int.subtract 0 2)\n",
        )),
        "-5\n-9223372036854775805\n"
    );
}

#[test]
fn numeric_equality_distinguishes_values_and_nan() {
    assert_eq!(
        run(concat!(
            "main = do\n",
            "  IO.print $ Int.eq 1 2\n",
            "  IO.print $ Double.eq 1.0 2.0\n",
            "  IO.print $ Text.eq \"a\" \"b\"\n",
            "  IO.print $ Eq.eq 1 2\n",
            "  IO.print $ Ord.lt 2 1\n",
            "  IO.print $ Ord.gt 1 2\n",
            "  IO.print $ List.all (Int.eq 1) [1,2]\n",
            "  IO.print $ Text.all (Eq.eq 'a') \"aβ\"\n",
            "  let infinity = Double.plus 1.7976931348623157e308 1.7976931348623157e308\n",
            "  let notANumber = Double.subtract infinity infinity\n",
            "  IO.print $ Double.eq notANumber notANumber\n",
        )),
        "False\nFalse\nFalse\nFalse\nFalse\nFalse\nFalse\nFalse\nFalse\n"
    );
}

fn run_equality_partition_test(mutant: Option<&str>) -> ExitStatus {
    let mut command = Command::new(std::env::current_exe().expect("numeric test executable"));
    command
        .arg("numeric_equality_distinguishes_values_and_nan")
        .arg("--exact")
        .env_remove("HELL_ASSURANCE_MUTANT_ID");
    if let Some(mutant) = mutant {
        command.env("HELL_ASSURANCE_MUTANT_ID", mutant);
    }
    command.status().expect("nested numeric test runs")
}

#[test]
fn comparator_constant_true_mutants_are_detected() {
    assert!(run_equality_partition_test(None).success());
    for mutant in [
        "int-equality-constant-true",
        "double-equality-constant-true",
        "text-equality-constant-true",
        "generic-equality-constant-true",
        "ordering-comparator-constant-true",
        "all-constant-true",
    ] {
        assert!(
            !run_equality_partition_test(Some(mutant)).success(),
            "constant-true mutant {mutant} survived"
        );
    }
}
