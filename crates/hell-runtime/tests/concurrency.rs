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
