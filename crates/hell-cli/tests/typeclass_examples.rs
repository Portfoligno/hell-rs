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
            "hell-rs-typeclass-{}-{sequence}-{label}.hell",
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
    run_source_with_args(label, source, environment, &[])
}

fn run_source_with_args(
    label: &str,
    source: &str,
    environment: &[(&str, &str)],
    arguments: &[&str],
) -> Output {
    let fixture = Fixture::new(label, source);
    let mut command = Command::new(env!("CARGO_BIN_EXE_hell"));
    command.env_clear().arg(&fixture.0).args(arguments);
    for (name, value) in environment {
        command.env(name, value);
    }
    command.output().expect("run Hell fixture")
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
fn maybe_and_either_monads_and_functor_match_upstream_example_18() {
    let source = concat!(
        "main = do\n",
        "  env <- Environment.getEnvironment\n",
        "  Maybe.maybe (Text.putStrLn \"Oops!\") Text.putStrLn\n",
        "    (do path <- List.lookup \"PATH\" env\n",
        "        home <- Functor.fmap Text.reverse $ List.lookup \"HOME\" env\n",
        "        Monad.return (Text.concat [path, \" and \", home]))\n",
        "  Either.either Text.putStrLn Text.putStrLn\n",
        "    (do x <- Main.parse \"foo\"\n",
        "        y <- Main.parse \"foo\"\n",
        "        Monad.return (Text.concat [x,y]))\n",
        "parse = \\s -> if Eq.eq s \"foo\"\n",
        "  then Either.Right \"foooo :-)\" else Either.Left \"oh noes!\"\n",
    );
    assert_success(
        &run_source(
            "monads",
            source,
            &[("PATH", "/bin"), ("HOME", "/home/test")],
        ),
        b"/bin and tset/emoh/\nfoooo :-)foooo :-)\n",
    );
}

#[test]
fn tree_constructor_map_and_fold_match_upstream_example_28() {
    let source = concat!(
        "main = do\n",
        "  let tree = Tree.Node \"1\" [\n",
        "        Tree.Node \"1.a\" [],\n",
        "        Tree.Node \"1.b\" [Tree.Node \"1.b.x\" []]]\n",
        "  let tree' = Tree.map (\\a -> (a, Text.length a)) tree\n",
        "  Tree.foldTree\n",
        "    (\\(a, len) children -> do\n",
        "      Text.putStr \"(\"\n",
        "      Text.putStr a\n",
        "      Text.putStr \" \"\n",
        "      Text.putStr $ Show.show len\n",
        "      Monad.forM_ children (\\m -> do Text.putStr \" \"; m)\n",
        "      Text.putStr \")\")\n",
        "    tree'\n",
    );
    assert_success(
        &run_source("trees", source, &[]),
        b"(1 1 (1.a 3) (1.b 3 (1.b.x 5)))",
    );
}

#[test]
fn sort_on_and_generic_for_m_execute_the_example_19_typeclass_slice() {
    let source = concat!(
        "main = do\n",
        "  values <- Monad.forM\n",
        "    (List.sortOn (\\(key, value) -> key) [(2, \"b\"), (1, \"a\")])\n",
        "    (\\(key, value) -> IO.pure value)\n",
        "  Text.putStrLn (Text.concat values)\n",
    );
    assert_success(&run_source("sort-for-m", source, &[]), b"ab\n");
}

#[test]
fn map_accum_r_preserves_the_pinned_upstream_map_accum_l_quirk() {
    let source = concat!(
        "main = IO.print $ List.mapAccumR\n",
        "  (\\acc x -> (Int.plus acc x, acc)) 0 [1,2,3]\n",
    );
    assert_success(&run_source("map-accum-r", source, &[]), b"(6,[0,1,3])\n");
}

#[test]
fn options_applicative_and_optional_match_upstream_example_32() {
    let source = concat!(
        "data Opts = Opts { quiet :: Bool, filePath :: Maybe Text }\n",
        "options =\n",
        "  (\\quiet path -> Main.Opts { quiet = quiet, filePath = path })\n",
        "    <$> Options.switch (Flag.long \"quiet\" <> Flag.help \"Be quiet?\")\n",
        "    <*> (Alternative.optional $ Options.strOption\n",
        "      (Option.long \"path\" <> Option.help \"The filepath to export\"))\n",
        "main = do\n",
        "  opts <- Options.execParser\n",
        "    (Options.info (Main.options <**> Options.helper) Options.fullDesc)\n",
        "  Text.putStrLn $ Maybe.maybe \"No file path\" Function.id\n",
        "    (Record.get @\"filePath\" opts)\n",
        "  Text.putStrLn $ Show.show @Bool $ Record.get @\"quiet\" opts\n",
    );
    assert_success(
        &run_source_with_args("options", source, &[], &["--quiet", "--path", "sample.txt"]),
        b"sample.txt\nTrue\n",
    );
}

#[test]
fn command_parser_and_option_mod_semigroup_match_upstream_example_41() {
    let source = concat!(
        "data Command = Add Text | Remove Text | List\n",
        "parseAdd = Main.Add <$> Options.strArgument\n",
        "  (Argument.metavar \"FILE\" <> Argument.help \"File to add\")\n",
        "parseRemove = Main.Remove <$> Options.strArgument\n",
        "  (Argument.metavar \"FILE\" <> Argument.help \"File to remove\")\n",
        "parseList = Applicative.pure Main.List\n",
        "cmdParser = Options.hsubparser\n",
        "  (Options.command \"add\" (Options.info Main.parseAdd (Options.progDesc \"Add\"))\n",
        "   <> Options.command \"remove\" (Options.info Main.parseRemove Options.fullDesc)\n",
        "   <> Options.command \"list\" (Options.info Main.parseList Options.fullDesc))\n",
        "main = do\n",
        "  cmd <- Options.execParser\n",
        "    (Options.info (Main.cmdParser <**> Options.helper) Options.fullDesc)\n",
        "  case cmd of\n",
        "    Add file -> Text.putStrLn $ \"Adding \" <> file\n",
        "    Remove file -> Text.putStrLn $ \"Removing \" <> file\n",
        "    List -> Text.putStrLn \"Listing files\"\n",
    );
    assert_success(
        &run_source_with_args("commands", source, &[], &["add", "sample.txt"]),
        b"Adding sample.txt\n",
    );
}

#[test]
fn remaining_manifest_class_adapters_execute_without_decorative_entries() {
    let source = concat!(
        "main = do\n",
        "  Text.putStrLn $ CI.foldedCase $ CI.mk \"AbC\"\n",
        "  IO.print $ Ord.gt 2 1\n",
        "  IO.print $ Alternative.many (Maybe.Nothing :: Maybe Int)\n",
        "  IO.print $ Monad.mapM (\\x -> Maybe.Just x) [1,2]\n",
        "  IO.print $ Monad.mapM (\\x -> Tree.Node x []) [1,2]\n",
        "  IO.print $ Monad.sequence [Maybe.Just 3, Maybe.Just 4]\n",
        "  Maybe.maybe (Text.putStrLn \"bad\") (\\x -> Text.putStrLn \"when\")\n",
        "    (Monad.when Bool.False (Maybe.Just ()))\n",
        "  let tree = Tree.Node \"root\" [Tree.Node \"leaf\" []]\n",
        "  IO.print $ Tree.flatten tree\n",
        "  IO.print $ Tree.levels tree\n",
        "  _ <- Options.execParser\n",
        "    (Options.info (Applicative.pure ()) (Options.header \"header\"))\n",
        "  IO.pure ()\n",
    );
    assert_success(
        &run_source("remaining-classes", source, &[]),
        b"abc\nTrue\nJust []\nJust [1,2]\nNode {rootLabel = [1,2], subForest = []}\nJust [3,4]\nwhen\n[\"root\",\"leaf\"]\n[[\"root\"],[\"leaf\"]]\n",
    );
}
