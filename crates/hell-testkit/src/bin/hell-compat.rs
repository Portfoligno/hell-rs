use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use hell_testkit::{ClassifiedMismatch, DifferentialCase, differential, release_gate};

fn main() {
    let mut arguments = std::env::args_os().skip(1);
    let Some(oracle) = arguments.next() else {
        usage();
    };
    let Some(candidate) = arguments.next() else {
        usage();
    };
    if arguments.next().is_some() {
        usage();
    }
    let oracle = PathBuf::from(oracle);
    let candidate = PathBuf::from(candidate);
    let cases = cases();
    let mut mismatches = Vec::new();
    for (name, case) in &cases {
        let report = differential(&oracle, &candidate, case).unwrap_or_else(|error| {
            eprintln!("compatibility case `{name}` could not run: {error}");
            std::process::exit(2);
        });
        for mismatch in report.mismatches {
            eprintln!("compatibility mismatch in `{name}`: {:?}", mismatch.kind);
            mismatches.push(ClassifiedMismatch {
                mismatch,
                classification: None,
                explanation: Arc::from(""),
            });
        }
    }
    let gate = release_gate(cases.len(), cases.len(), &mismatches);
    if !gate.passed() {
        eprintln!(
            "compatibility gate failed: {} case(s), {} unexplained mismatch(es), {} Rust bug mismatch(es)",
            gate.cases_run, gate.unexplained_mismatches, gate.rust_bug_mismatches
        );
        std::process::exit(1);
    }
    println!(
        "compatibility gate passed: {} deterministic cases",
        gate.cases_run
    );
}

fn usage() -> ! {
    eprintln!("usage: hell-compat ORACLE CANDIDATE");
    std::process::exit(2);
}

fn cases() -> Vec<(&'static str, DifferentialCase)> {
    let timeout = Duration::from_secs(5);
    vec![
        (
            "hello",
            DifferentialCase {
                source: Arc::from("main = Text.putStrLn \"hello\"\n"),
                timeout,
                ..DifferentialCase::default()
            },
        ),
        (
            "lazy-bottom",
            DifferentialCase {
                source: Arc::from(
                    "main = IO.print $ Bool.bool 1 (Error.error \"boom\") Bool.False\n",
                ),
                timeout,
                ..DifferentialCase::default()
            },
        ),
        (
            "recursive-instances",
            DifferentialCase {
                source: Arc::from(concat!(
                    "main = do\n",
                    "  IO.print [Either.Left (Maybe.Just 1), Either.Right (Maybe.Just \"x\")]\n",
                    "  IO.print $ Eq.eq [Maybe.Just 1] [Maybe.Just 2]\n",
                )),
                timeout,
                ..DifferentialCase::default()
            },
        ),
        (
            "environment-lookup",
            DifferentialCase {
                source: Arc::from(concat!(
                    "main = do\n",
                    "  env <- Environment.getEnvironment\n",
                    "  Maybe.maybe (Text.putStrLn \"missing\") Text.putStrLn (List.lookup \"HOME\" env)\n",
                )),
                environment: vec![(OsString::from("HOME"), OsString::from("/compat-home"))],
                timeout,
                ..DifferentialCase::default()
            },
        ),
        (
            "higher-kinded-classes",
            DifferentialCase {
                source: Arc::from(concat!(
                    "main = do\n",
                    "  IO.print $ Functor.fmap (\\x -> Int.plus x 1) (Maybe.Just 1)\n",
                    "  IO.print (Applicative.pure 2 :: Maybe Int)\n",
                    "  IO.print $ Alternative.optional (Maybe.Just 3)\n",
                    "  IO.print $ List.sortOn (\\(key, value) -> key) [(2, \"b\"), (1, \"a\")]\n",
                    "  IO.print $ List.mapAccumR (\\acc x -> (Int.plus acc x, acc)) 0 [1,2,3]\n",
                    "  Text.putStrLn $ CI.foldedCase $ CI.mk \"AbC\"\n",
                )),
                timeout,
                ..DifferentialCase::default()
            },
        ),
        (
            "tree-classes",
            DifferentialCase {
                source: Arc::from(concat!(
                    "main = do\n",
                    "  let tree = Tree.Node 1 [Tree.Node 2 []]\n",
                    "  IO.print $ Tree.map (\\x -> Int.plus x 1) tree\n",
                    "  IO.print $ Monad.mapM (\\x -> Tree.Node x []) [1,2]\n",
                )),
                timeout,
                ..DifferentialCase::default()
            },
        ),
        (
            "options-applicative",
            DifferentialCase {
                source: Arc::from(concat!(
                    "data Opts = Opts { quiet :: Bool, filePath :: Maybe Text }\n",
                    "options = (\\quiet path -> Main.Opts { quiet = quiet, filePath = path })\n",
                    "  <$> Options.switch (Flag.long \"quiet\" <> Flag.help \"Be quiet?\")\n",
                    "  <*> (Alternative.optional $ Options.strOption\n",
                    "    (Option.long \"path\" <> Option.help \"Export path\"))\n",
                    "main = do\n",
                    "  opts <- Options.execParser\n",
                    "    (Options.info (Main.options <**> Options.helper) Options.fullDesc)\n",
                    "  Text.putStrLn $ Maybe.maybe \"missing\" Function.id\n",
                    "    (Record.get @\"filePath\" opts)\n",
                    "  Text.putStrLn $ Show.show @Bool $ Record.get @\"quiet\" opts\n",
                )),
                arguments: vec![
                    OsString::from("--quiet"),
                    OsString::from("--path"),
                    OsString::from("sample.txt"),
                ],
                timeout,
                ..DifferentialCase::default()
            },
        ),
    ]
}
