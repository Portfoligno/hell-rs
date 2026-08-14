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
fn int_read_maybe_uses_pinned_twos_complement_modular_conversion() {
    assert_eq!(
        run(concat!(
            "main = do\n",
            "  IO.print $ Int.readMaybe \" +42 \"\n",
            "  IO.print $ Int.readMaybe \"-9223372036854775808\"\n",
            "  IO.print $ Int.readMaybe \"9223372036854775807\"\n",
            "  IO.print $ Int.readMaybe \"9223372036854775808\"\n",
            "  IO.print $ Int.readMaybe \"-9223372036854775809\"\n",
            "  IO.print $ Int.readMaybe \"18446744073709551616\"\n",
            "  IO.print $ Int.readMaybe \"18446744073709551617\"\n",
            "  IO.print $ Int.readMaybe \"-18446744073709551616\"\n",
            "  IO.print $ Int.readMaybe \"-18446744073709551617\"\n",
            "  IO.print $ Int.readMaybe \"123456789012345678901234567890\"\n",
            "  IO.print $ Int.readMaybe \"-123456789012345678901234567890\"\n",
            "  IO.print $ Int.readMaybe \"not-an-int\"\n",
        )),
        concat!(
            "Just 42\n",
            "Just (-9223372036854775808)\n",
            "Just 9223372036854775807\n",
            "Just (-9223372036854775808)\n",
            "Just 9223372036854775807\n",
            "Just 0\n",
            "Just 1\n",
            "Just 0\n",
            "Just (-1)\n",
            "Just (-4362896299872285998)\n",
            "Just 4362896299872285998\n",
            "Nothing\n",
        )
    );
}

#[test]
fn show_f_float_rounds_the_shortest_decimal_like_the_pinned_oracle() {
    const MAX_FIXED_TWO: &str = concat!(
        "1797693134862315700000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "00000000000000000000000000000000000000000000000000000.00",
    );
    assert_eq!(
        run(concat!(
            "f0 = \\value -> Text.putStrLn $ Double.showFFloat (Maybe.Just 0) value \"\"\n",
            "f2 = \\value -> Text.putStrLn $ Double.showFFloat (Maybe.Just 2) value \"\"\n",
            "f17 = \\value -> Text.putStrLn $ Double.showFFloat (Maybe.Just 17) value \"\"\n",
            "read = \\text -> Maybe.maybe (Error.error \"parse\") Function.id $ Double.readMaybe text\n",
            "main = do\n",
            "  Main.f2 2.675\n",
            "  Main.f2 1.005\n",
            "  Main.f2 9.995\n",
            "  Main.f2 $ Main.read \"-2.675\"\n",
            "  Main.f2 $ Main.read \"-1.005\"\n",
            "  Main.f2 $ Main.read \"-9.995\"\n",
            "  Main.f2 0.0009995\n",
            "  Main.f0 2.5\n",
            "  Main.f0 3.5\n",
            "  Main.f2 1e20\n",
            "  Main.f2 1e-20\n",
            "  Main.f17 5e-324\n",
            "  Main.f2 $ Main.read \"-0.0\"\n",
            "  Main.f2 $ Main.read \"Infinity\"\n",
            "  Main.f2 $ Main.read \"-Infinity\"\n",
            "  Main.f2 $ Main.read \"NaN\"\n",
            "  Main.f2 1.7976931348623157e308\n",
            "  Main.f2 $ Double.mult (Double.fromInt $ Int.subtract 1 0) ",
            "1.7976931348623157e308\n",
        )),
        format!(
            concat!(
                "2.68\n",
                "1.00\n",
                "10.00\n",
                "-2.68\n",
                "-1.00\n",
                "-10.00\n",
                "0.00\n",
                "2\n",
                "4\n",
                "100000000000000000000.00\n",
                "0.00\n",
                "0.00000000000000000\n",
                "-0.00\n",
                "Infinity\n",
                "-Infinity\n",
                "NaN\n",
                "{maximum}\n",
                "-{maximum}\n",
            ),
            maximum = MAX_FIXED_TWO,
        )
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
        .arg("--exact");
    if let Some(mutant) = mutant {
        command
            .args(["--skip", "__hell_mutant", "--skip"])
            .arg(mutant);
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
