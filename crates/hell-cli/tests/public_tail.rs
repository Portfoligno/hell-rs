use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new(label: &str, source: &str) -> Self {
        let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "hell-rs-public-tail-{}-{sequence}-{label}.hell",
            std::process::id()
        ));
        fs::write(&path, source).expect("write temporary Hell fixture");
        Self(path)
    }

    fn run(&self, arguments: &[&str]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_hell"));
        command.env_clear().arg(&self.0).args(arguments);
        supervised_output(&mut command)
    }
}

fn supervised_output(command: &mut Command) -> Output {
    let output = hell_testkit::run_supervised_command(command, &[], Duration::from_secs(30))
        .expect("supervise Hell fixture");
    assert!(!output.timed_out, "Hell fixture exceeded its deadline");
    Output {
        status: output.status,
        stdout: output.stdout.complete.expect("stdout capture is complete"),
        stderr: output.stderr.complete.expect("stderr capture is complete"),
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn assert_success(output: &Output, expected_stdout: &[u8]) {
    assert!(
        output.status.success(),
        "unexpected failure: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, expected_stdout);
    assert!(output.stderr.is_empty());
}

#[test]
fn record_maybe_tuple_and_tree_tail_matches_the_upstream_oracle() {
    let source = concat!(
        "data Person = Person { age :: Int, name :: Text }\n",
        "main = do\n",
        "  let person = Main.Person { age = 1, name = \"Ada\" }\n",
        "  IO.print $ Record.get @\"age\" @Int person\n",
        "  IO.print $ Record.get @\"age\" @Int $ Record.set @\"age\" @Int 4 person\n",
        "  IO.print $ Record.get @\"age\" @Int $ Record.modify @\"age\" @Int (Int.plus 2) person\n",
        "  IO.print $ Maybe.listToMaybe [1, Error.error \"tail\"]\n",
        "  IO.print $ Maybe.mapMaybe\n",
        "    (\\x -> if Eq.eq x 2 then Maybe.Nothing else Maybe.Just (Int.mult x 10))\n",
        "    [1,2,3]\n",
        "  let (a,b,c) = (1, \"two\", Bool.True)\n",
        "  IO.print a\n",
        "  Text.putStrLn b\n",
        "  IO.print c\n",
        "  let (d,e,f,g) = (1,2,3,4)\n",
        "  IO.print $ Int.plus d $ Int.plus e $ Int.plus f g\n",
        "  IO.print $ Tree.unfoldTree\n",
        "    (\\n -> (n, if Eq.eq n 0 then [] else [Int.subtract 1 n])) 2\n",
    );
    assert_success(
        &Fixture::new("values", source).run(&[]),
        concat!(
            "1\n",
            "4\n",
            "3\n",
            "Just 1\n",
            "[10,30]\n",
            "1\n",
            "two\n",
            "True\n",
            "10\n",
            "Node {rootLabel = 2, subForest = [Node {rootLabel = 1, ",
            "subForest = [Node {rootLabel = 0, subForest = []}]}]}\n",
        )
        .as_bytes(),
    );
}

#[test]
fn option_flags_and_default_modifiers_match_the_upstream_oracle() {
    let source = concat!(
        "main = do\n",
        "  values <- Options.execParser $ Options.info\n",
        "    ((\\a b c d -> (a,b,c,d))\n",
        "      <$> Options.flag \"off\" \"on\" (Flag.long \"mode\")\n",
        "      <*> Options.flag' \"seen\" (Flag.long \"required\")\n",
        "      <*> Options.strOption (Option.long \"name\" <> Option.value \"default\")\n",
        "      <*> Options.strArgument (Argument.value \"fallback\"))\n",
        "    Options.fullDesc\n",
        "  let (a,b,c,d) = values\n",
        "  Text.putStrLn a\n",
        "  Text.putStrLn b\n",
        "  Text.putStrLn c\n",
        "  Text.putStrLn d\n",
    );
    assert_success(
        &Fixture::new("options", source).run(&["--mode", "--required"]),
        b"on\nseen\ndefault\nfallback\n",
    );
}

#[test]
fn exit_actions_preserve_status_and_die_stderr() {
    let success = Fixture::new(
        "exit-success",
        "main = (Exit.exitWith Exit.ExitSuccess :: IO ())\n",
    )
    .run(&[]);
    assert_success(&success, b"");

    let failure = Fixture::new(
        "exit-failure",
        "main = (Exit.exitWith (Exit.ExitFailure 7) :: IO ())\n",
    )
    .run(&[]);
    assert_eq!(failure.status.code(), Some(7));
    assert!(failure.stdout.is_empty());
    assert!(failure.stderr.is_empty());

    let die = Fixture::new("die", "main = (Exit.die \"fatal\" :: IO ())\n").run(&[]);
    assert_eq!(die.status.code(), Some(1));
    assert!(die.stdout.is_empty());
    assert_eq!(die.stderr, b"fatal\n");
}
