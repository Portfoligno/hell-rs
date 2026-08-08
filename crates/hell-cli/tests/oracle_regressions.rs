use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new(label: &str, source: &str) -> Self {
        let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "hell-rs-oracle-{}-{sequence}-{label}.hell",
            std::process::id()
        ));
        fs::write(&path, source).expect("write temporary Hell fixture");
        Self(path)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn hell() -> Command {
    Command::new(env!("CARGO_BIN_EXE_hell"))
}

fn run_source(label: &str, source: &str) -> Output {
    let fixture = Fixture::new(label, source);
    hell().arg(&fixture.0).output().expect("run hell")
}

fn check_source(label: &str, source: &str) -> Output {
    let fixture = Fixture::new(label, source);
    hell()
        .arg("--check")
        .arg(&fixture.0)
        .output()
        .expect("check Hell source")
}

fn assert_success(output: &Output, expected_stdout: &[u8]) {
    assert!(
        output.status.success(),
        "unexpected failure: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, expected_stdout);
    assert!(
        output.stderr.is_empty(),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_diagnostic(output: &Output, code: &str) {
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(code), "expected {code}, got: {stderr}");
}

#[test]
fn pinned_version_and_hello_world_match_the_oracle() {
    let version = hell().arg("--version").output().expect("run --version");
    assert_success(&version, b"2026-05-29\n");

    assert_success(
        &run_source("hello", "main = Text.putStrLn \"hello\"\n"),
        b"hello\n",
    );
}

#[test]
fn call_by_need_matches_the_oracle_on_unused_bottoms_and_infinite_lists() {
    let cases = [
        (
            "lazy-bool",
            "main = IO.print $ Bool.bool 1 (Error.error \"boom\") Bool.False\n",
            &b"1\n"[..],
        ),
        (
            "lazy-lambda",
            "main = IO.print $ (\\x _ -> x) 1 (Error.error \"boom\" :: Int)\n",
            &b"1\n"[..],
        ),
        (
            "lazy-io-pure",
            "main = do\n  IO.pure (Error.error \"unused\" :: Int)\n  Text.putStrLn \"ok\"\n",
            &b"ok\n"[..],
        ),
        (
            "infinite-take",
            "main = IO.print $ List.take 5 $ List.iterate' (Int.plus 1) 0\n",
            &b"[0,1,2,3,4]\n"[..],
        ),
    ];

    for (label, source, expected) in cases {
        assert_success(&run_source(label, source), expected);
    }
}

#[test]
fn global_expansion_and_reachability_match_the_oracle() {
    assert_success(
        &run_source(
            "global-reuse",
            "printOne = \\x -> Text.putStrLn (Show.show x)\n\nmain = do\n  Main.printOne 1\n  Main.printOne \"text\"\n",
        ),
        b"1\n\"text\"\n",
    );

    assert_success(
        &check_source(
            "unreachable-type-error",
            "bad = Int.plus Bool.True 1\n\nmain = IO.pure ()\n",
        ),
        b"",
    );

    assert_diagnostic(
        &check_source(
            "unreachable-unknown",
            "bad = Unknown.missing\n\nmain = IO.pure ()\n",
        ),
        "H0403",
    );
    assert_diagnostic(
        &check_source("unreachable-cycle", "bad = Main.bad\n\nmain = IO.pure ()\n"),
        "H0310",
    );
}

#[test]
fn local_monomorphism_and_entry_point_rules_are_enforced() {
    assert_diagnostic(
        &check_source(
            "local-reuse",
            "main = do\n  let printOne = \\x -> Text.putStrLn (Show.show x)\n  printOne 1\n  printOne \"text\"\n",
        ),
        "H0502",
    );
    assert_diagnostic(
        &check_source("missing-main", "value = IO.pure ()\n"),
        "H0701",
    );
    assert_diagnostic(
        &check_source("wrong-main", "main = Text.length \"hello\"\n"),
        "H0702",
    );
    assert_diagnostic(
        &check_source("unqualified-global", "value = IO.pure ()\n\nmain = value\n"),
        "H0401",
    );
}

#[test]
fn records_and_generic_record_construction_match_the_oracle() {
    assert_success(
        &run_source(
            "record-get",
            "data Person = Person { name :: Text, age :: Int }\n\nmain = Text.putStrLn $ Record.get @\"name\" @Text Main.Person { age = 23, name = \"Chris\" }\n",
        ),
        b"Chris\n",
    );

    assert_success(
        &check_source(
            "generic-record-fallback",
            "main = do\n  IO.pure (Maybe.Just { x = 1 })\n  IO.pure ()\n",
        ),
        b"",
    );
}

#[test]
fn user_and_primitive_case_validation_matches_the_oracle() {
    assert_success(
        &run_source(
            "canonical-prefix-case",
            "data Choice = A | B | C\n\nchoose = \\value -> case value of\n  A -> 1\n  _ -> 2\n\nmain = IO.print $ Main.choose Main.C\n",
        ),
        b"2\n",
    );

    assert_diagnostic(
        &check_source(
            "non-prefix-case",
            "data Choice = A | B | C\n\nchoose = \\value -> case value of\n  B -> 1\n  _ -> 2\n\nmain = IO.print $ Main.choose Main.C\n",
        ),
        "H0502",
    );

    assert_diagnostic(
        &check_source(
            "non-exhaustive-primitive-case",
            "main = case Maybe.Just 1 of\n  Maybe.Just value -> IO.print value\n",
        ),
        "H0615",
    );
}

#[test]
fn shebang_preserves_original_error_line() {
    let output = check_source(
        "shebang-line",
        "#!/usr/bin/env hell\n\nmain = Missing.value\n",
    );
    assert_diagnostic(&output, "H0403");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(":3:"), "expected original line 3: {stderr}");
}

#[test]
fn deep_valid_source_hits_the_structured_parser_limit() {
    const DEPTH: usize = 2_048;
    let source = format!(
        "main = IO.pure {}(){}\n",
        "Function.id (".repeat(DEPTH),
        ")".repeat(DEPTH)
    );
    let output = check_source("deep-applications", &source);
    assert_diagnostic(&output, "H0801");
}
