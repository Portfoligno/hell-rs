use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hell_compiler::{CompilerSession, compile_source};
use hell_runtime::{RuntimeContext, RuntimeError, run_main};

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

fn run_result(source: &str) -> (Result<(), Arc<RuntimeError>>, String) {
    let program = compile_source(&mut CompilerSession::default(), "concurrency.hell", source)
        .expect("concurrency source compiles");
    let bytes = Arc::new(Mutex::new(Vec::new()));
    let result = run_main(
        program,
        RuntimeContext::new(Vec::new(), SharedWriter(Arc::clone(&bytes))),
    );
    let output = String::from_utf8(bytes.lock().unwrap().clone()).unwrap();
    (result, output)
}

fn run(source: &str) -> String {
    let (result, output) = run_result(source);
    result.unwrap();
    output
}

#[test]
fn thread_delay_and_timeout_cover_nonpositive_and_success_paths() {
    assert_eq!(run("main = Concurrent.threadDelay 0\n"), "");
    assert_eq!(
        run("main = Concurrent.threadDelay (Int.subtract 1 0)\n"),
        ""
    );
    assert_eq!(
        run("main = Monad.bind \
             (Timeout.timeout 0 (Error.error \"unused\" :: IO Int)) \
             (Maybe.maybe (Text.putStrLn \"none\") \
             (\\_ -> Text.putStrLn \"some\"))\n"),
        "none\n"
    );
    assert_eq!(
        run("main = Monad.bind (Timeout.timeout 100000 (IO.pure 1)) \
             (Maybe.maybe (Text.putStrLn \"none\") (\\value -> IO.print value))\n"),
        "1\n"
    );
    assert_eq!(
        run("main = Monad.bind \
             (Timeout.timeout (Int.subtract 1 0) (IO.pure 2)) \
             (Maybe.maybe (Text.putStrLn \"none\") (\\value -> IO.print value))\n"),
        "2\n"
    );
}

#[test]
fn concurrently_returns_results_in_left_right_order() {
    assert_eq!(
        run(concat!(
            "left = do\n",
            "  Concurrent.threadDelay 20000\n",
            "  IO.pure 1\n",
            "right = do\n",
            "  Concurrent.threadDelay 1000\n",
            "  IO.pure 2\n",
            "main = Monad.bind (Async.concurrently Main.left Main.right) IO.print\n",
        )),
        "(1,2)\n"
    );
}

#[test]
fn race_tags_the_first_completion_with_its_side() {
    let started = Instant::now();
    assert_eq!(
        run(concat!(
            "left = do\n",
            "  Concurrent.threadDelay 5000000\n",
            "  IO.pure \"left\"\n",
            "right = do\n",
            "  Concurrent.threadDelay 1000\n",
            "  IO.pure \"right\"\n",
            "main = Monad.bind (Async.race Main.left Main.right) (\\result -> ",
            "case result of\n",
            "  Either.Left value -> Text.putStrLn value\n",
            "  Either.Right value -> Text.putStrLn value)\n",
        )),
        "right\n"
    );
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn pooled_map_runs_bounded_jobs_but_preserves_input_order() {
    assert_eq!(
        run(concat!(
            "work = \\value -> do\n",
            "  Concurrent.threadDelay (Int.mult value 1000)\n",
            "  IO.pure value\n",
            "main = Monad.bind ",
            "(Async.pooledMapConcurrently Main.work [3, 1, 2]) IO.print\n",
        )),
        "[3,1,2]\n"
    );
    assert_eq!(
        run("main = Async.pooledForConcurrently_ [1, 2, 3] \
               (\\value -> IO.pure ())\n"),
        ""
    );
}

#[test]
fn pooled_worker_count_has_a_public_execution_override() {
    let source = concat!(
        "work = \\value -> IO.pure value\n",
        "main = Monad.bind ",
        "(Async.pooledMapConcurrently Main.work [1, 2, 3]) IO.print\n",
    );
    let program = compile_source(&mut CompilerSession::default(), "pool-limit.hell", source)
        .expect("pooled source compiles");
    let bytes = Arc::new(Mutex::new(Vec::new()));
    let context = RuntimeContext::new(Vec::new(), SharedWriter(Arc::clone(&bytes)))
        .with_max_concurrent_actions(1);
    run_main(program, context).unwrap();
    assert_eq!(
        String::from_utf8(bytes.lock().unwrap().clone()).unwrap(),
        "[1,2,3]\n"
    );
}

#[test]
fn a_right_hand_failure_is_not_replaced_by_peer_cancellation() {
    let started = Instant::now();
    let (result, output) = run_result(concat!(
        "waiting = do\n",
        "  Concurrent.threadDelay 5000000\n",
        "  IO.pure 1\n",
        "failing = Error.error \"right boom\" :: IO Int\n",
        "main = do\n",
        "  Async.concurrently Main.waiting Main.failing\n",
        "  IO.pure ()\n",
    ));
    let error = result.unwrap_err();
    assert_eq!(error.message.as_ref(), "right boom");
    assert_eq!(output, "");
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn timeout_cancels_a_delay_and_returns_nothing_promptly() {
    let started = Instant::now();
    assert_eq!(
        run("main = Monad.bind \
               (Timeout.timeout 1000 (Concurrent.threadDelay 5000000)) \
               (Maybe.maybe (Text.putStrLn \"none\") \
               (\\_ -> Text.putStrLn \"some\"))\n"),
        "none\n"
    );
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn timeout_cancels_nonproductive_many_without_losing_lazy_maybe_prefixes() {
    assert_eq!(
        run(concat!(
            "main = IO.print $ Maybe.maybe [] (List.take 3) $ ",
            "Alternative.many (Maybe.Just 1 :: Maybe Int)\n",
        )),
        "[1,1,1]\n"
    );

    let started = Instant::now();
    assert_eq!(
        run(concat!(
            "main = do\n",
            "  result <- Timeout.timeout 100000 $ ",
            "Maybe.maybe (IO.pure ()) ",
            "(\\values -> Monad.forM_ values (\\_ -> IO.pure ())) $ ",
            "Alternative.many (Maybe.Just 1 :: Maybe Int)\n",
            "  Maybe.maybe (Text.putStr \"timeout\") ",
            "(\\_ -> Text.putStr \"completed\") result\n",
        )),
        "timeout"
    );
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[cfg(feature = "compat-tracing")]
#[test]
fn shared_nonproductive_many_consumers_are_trace_canonical_and_semantically_equal() {
    let source = concat!(
        "values = Maybe.maybe [] (\\items -> items) $ ",
        "Alternative.many (Maybe.Just 1 :: Maybe Int)\n",
        "work = Timeout.timeout 100000 $ ",
        "Monad.forM_ Main.values (\\_ -> IO.pure ())\n",
        "main = do\n",
        "  (left, right) <- Async.concurrently Main.work Main.work\n",
        "  Maybe.maybe (Text.putStr \"timeout\") ",
        "(\\_ -> Text.putStr \"completed\") left\n",
        "  Maybe.maybe (Text.putStr \"timeout\") ",
        "(\\_ -> Text.putStr \"completed\") right\n",
    );
    let directory = std::env::temp_dir().join(format!(
        "hell-shared-nonproductive-traces-{}",
        std::process::id()
    ));
    let _already_absent = std::fs::remove_dir_all(&directory);
    std::fs::create_dir(&directory).expect("create shared nonproductive trace directory");
    let mut baseline = None;
    for iteration in 0..64 {
        let program = compile_source(
            &mut CompilerSession::default(),
            "shared-nonproductive.hell",
            source,
        )
        .expect("shared nonproductive source compiles");
        let trace = directory.join(format!("semantic-trace-{iteration}.json"));
        let output = Arc::new(Mutex::new(Vec::new()));
        hell_runtime::run_main_with_semantic_trace(
            program,
            RuntimeContext::new(Vec::new(), SharedWriter(Arc::clone(&output))),
            &trace,
        )
        .expect("shared nonproductive consumers complete under guest timeouts");
        assert_eq!(
            *output.lock().expect("shared nonproductive output lock"),
            b"timeouttimeout",
            "shared consumers changed their guest-visible result"
        );
        let bytes = std::fs::read(&trace).expect("read shared nonproductive trace");
        let rendered = std::str::from_utf8(&bytes).expect("semantic trace is UTF-8 JSON");
        let maybe = hell_builtins::lookup("Maybe.maybe")
            .expect("Maybe.maybe builtin")
            .id
            .0;
        let put_str = hell_builtins::lookup("Text.putStr")
            .expect("Text.putStr builtin")
            .id
            .0;
        for (maybe_sequence, put_sequence) in [(4, 5), (6, 7)] {
            assert!(
                rendered.contains(&format!(
                    "\"builtinId\": {maybe}, \"ownerTaskId\": null, \"sequence\": {maybe_sequence}, \"parentSequence\": null, \"instanceTarget\": null, \"instancePremises\": [], \"outcome\": \"alias\", \"nestedAdapters\": 1"
                )),
                "root Maybe.maybe selection lost its one exact nested adapter"
            );
            assert!(
                rendered.contains(&format!(
                    "\"builtinId\": {put_str}, \"ownerTaskId\": null, \"sequence\": {put_sequence}, \"parentSequence\": {maybe_sequence}"
                )),
                "Text.putStr was detached from or cross-linked across Maybe.maybe selections"
            );
        }
        if let Some(expected) = &baseline {
            assert_eq!(bytes, *expected, "concurrent trace bytes changed");
        } else {
            baseline = Some(bytes);
        }
    }
    std::fs::remove_dir_all(directory).expect("remove shared nonproductive trace directory");
}
