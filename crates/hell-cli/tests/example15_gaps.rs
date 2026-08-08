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
            "hell-rs-example15-{}-{sequence}-{label}.hell",
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

fn run_source(label: &str, source: &str, environment: &[(&str, &str)]) -> Output {
    let fixture = Fixture::new(label, source);
    let mut command = Command::new(env!("CARGO_BIN_EXE_hell"));
    command.env_clear().args([fixture.0.as_os_str()]);
    for (name, value) in environment {
        command.env(name, value);
    }
    command.output().expect("run hell")
}

fn check_source(label: &str, source: &str) -> Output {
    let fixture = Fixture::new(label, source);
    Command::new(env!("CARGO_BIN_EXE_hell"))
        .env_clear()
        .args(["--check".as_ref(), fixture.0.as_os_str()])
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

#[test]
fn process_environment_is_visible_to_get_environment_and_lookup() {
    let source = concat!(
        "main = do\n",
        "  env <- Environment.getEnvironment\n",
        "  Maybe.maybe\n",
        "    (Text.putStrLn \"missing\")\n",
        "    Text.putStrLn\n",
        "    (List.lookup \"HOME\" env)\n",
    );
    assert_success(
        &run_source("get-environment", source, &[("HOME", "/oracle-home")]),
        b"/oracle-home\n",
    );
}

#[test]
fn get_env_reads_the_process_environment_and_reports_missing_names() {
    let source = "main = do\n  home <- Environment.getEnv \"HOME\"\n  Text.putStrLn home\n";
    assert_success(
        &run_source("get-env", source, &[("HOME", "/direct-home")]),
        b"/direct-home\n",
    );

    let missing = run_source("missing-env", source, &[]);
    assert_eq!(missing.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&missing.stderr);
    assert!(stderr.contains("H0903"), "expected H0903, got: {stderr}");
    assert!(
        stderr.contains("HOME"),
        "expected variable name, got: {stderr}"
    );
}

#[test]
fn lookup_returns_the_first_match_without_forcing_later_values() {
    let source = concat!(
        "main = IO.print $ List.lookup \"HOME\"\n",
        "  [(\"OTHER\", \"x\"), (\"HOME\", \"expected\"),\n",
        "   (\"HOME\", Error.error \"boom\" :: Text)]\n",
    );
    assert_success(&run_source("lookup", source, &[]), b"Just \"expected\"\n");
}

#[test]
fn semigroup_append_covers_example15_maybe_and_lazy_list_and_text() {
    let source = concat!(
        "main = do\n",
        "  IO.print $ Maybe.Just [1] <> Maybe.Nothing\n",
        "  IO.print $ Maybe.Just [1] <> Maybe.Just [2]\n",
        "  IO.print $ List.take 3 $ [1, 2] <> List.iterate' (Int.plus 1) 0\n",
        "  Text.putStrLn $ \"left\" <> \"right\"\n",
    );
    assert_success(
        &run_source("semigroup", source, &[]),
        b"Just [1]\nJust [1,2]\n[1,2,0]\nleftright\n",
    );
}

#[test]
fn semigroup_resolution_rejects_types_without_an_instance() {
    let output = check_source("no-semigroup", "main = IO.print $ 1 <> 2\n");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("H0507"), "expected H0507, got: {stderr}");
    assert!(
        stderr.contains("Semigroup") && stderr.contains("Int"),
        "expected the unsatisfied instance, got: {stderr}"
    );
}

#[test]
fn upstream_type_class_example_runs_end_to_end() {
    let source = concat!(
        "main = do\n",
        "  Text.putStrLn (Show.show 123)\n",
        "  Text.putStrLn (Show.show Bool.True)\n",
        "  Text.putStrLn $ Show.show $ Eq.eq 1 1\n",
        "  Text.putStrLn $ Show.show $ Eq.eq (1,1) (1,1)\n",
        "  Text.putStrLn $ Show.show $ Eq.eq [Maybe.Just 1] [Maybe.Just 2]\n",
        "  Text.putStrLn $ Show.show $ Eq.eq [Either.Left 1] [Either.Right \"abc\"]\n",
        "  IO.print [Maybe.Just 1, Maybe.Nothing]\n",
        "  IO.print $ Maybe.Just [1] <> Maybe.Nothing\n",
        "  IO.print $ [Either.Left (Maybe.Just 1), Either.Right (Maybe.Just \"abc\"), Either.Left Maybe.Nothing]\n",
        "  IO.print [Maybe.Just (1, 2), Maybe.Nothing]\n",
        "  env <- Environment.getEnvironment\n",
        "  Maybe.maybe\n",
        "    (Text.putStrLn \"Seems the environment variable is not there.\")\n",
        "    (\\path -> Text.putStrLn (Text.concat [\"HOME is \", path]))\n",
        "    (List.lookup \"HOME\" env)\n",
    );
    assert_success(
        &run_source("type-classes", source, &[("HOME", "/example-home")]),
        concat!(
            "123\n",
            "True\n",
            "True\n",
            "True\n",
            "False\n",
            "False\n",
            "[Just 1,Nothing]\n",
            "Just [1]\n",
            "[Left (Just 1),Right (Just \"abc\"),Left Nothing]\n",
            "[Just (1,2),Nothing]\n",
            "HOME is /example-home\n",
        )
        .as_bytes(),
    );
}

#[test]
fn recursive_ordering_and_either_semigroup_follow_registered_instances() {
    let source = concat!(
        "main = do\n",
        "  IO.print $ Ord.lt [1,2] [1,3]\n",
        "  IO.print $ Ord.lt (Maybe.Just 1) (Maybe.Just 2)\n",
        "  IO.print $ Ord.lt (Either.Left 9) (Either.Right \"a\")\n",
        "  IO.print $ Ord.lt (1,\"a\") (1,\"b\")\n",
        "  IO.print $ (Either.Left \"a\" <> Either.Left \"b\" :: Either Text Int)\n",
        "  IO.print $ (Either.Left \"a\" <> Either.Right 1 :: Either Text Int)\n",
        "  IO.print $ (Either.Right 1 <> Error.error \"boom\" :: Either Text Int)\n",
    );
    assert_success(
        &run_source("recursive-instances", source, &[]),
        b"True\nTrue\nTrue\nTrue\nLeft \"b\"\nRight 1\nRight 1\n",
    );

    let rejected = check_source(
        "nested-no-ord",
        "main = IO.print $ Ord.lt [IO.pure ()] [IO.pure ()]\n",
    );
    assert_eq!(rejected.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&rejected.stderr);
    assert!(stderr.contains("H0507"), "expected H0507, got: {stderr}");
    assert!(
        stderr.contains("Ord"),
        "expected Ord evidence, got: {stderr}"
    );
}

#[test]
fn composite_show_payloads_use_constructor_application_precedence() {
    let source = concat!(
        "main = do\n",
        "  IO.print $ Maybe.Just (Maybe.Just 1)\n",
        "  IO.print $ (Either.Left (Maybe.Just 1) :: Either (Maybe Int) Text)\n",
        "  IO.print $ (Either.Left [1,2] :: Either [Int] Text)\n",
    );
    assert_success(
        &run_source("show-precedence", source, &[]),
        b"Just (Just 1)\nLeft (Just 1)\nLeft [1,2]\n",
    );
}
