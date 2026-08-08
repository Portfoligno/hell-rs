use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use hell_platform::{SupervisedChild, WaitOutcome};
use hell_testkit::run_supervised_command;

fn helper() -> &'static str {
    env!("CARGO_BIN_EXE_hell-test-helper")
}

#[test]
fn hostile_dual_stream_output_is_bounded_and_fully_digested() {
    let bytes = 100 * 1024 * 1024;
    let mut command = Command::new(helper());
    command
        .arg("emit")
        .arg("--stdout-bytes")
        .arg(bytes.to_string())
        .arg("--stderr-bytes")
        .arg(bytes.to_string());
    let output = run_supervised_command(&mut command, &[], Duration::from_secs(20))
        .expect("capture hostile output");
    assert!(output.status.success());
    assert!(!output.timed_out);
    assert_eq!(output.stdout.total_bytes, bytes);
    assert_eq!(output.stderr.total_bytes, bytes);
    assert!(output.stdout.truncated);
    assert!(output.stderr.truncated);
    assert_eq!(output.stdout.prefix.len(), 256 * 1024);
    assert_eq!(output.stdout.suffix.len(), 256 * 1024);
    assert!(output.stdout.complete.is_none());
}

#[test]
fn exited_leader_cannot_leave_descendant_capture_pipes_open() {
    let marker = std::env::temp_dir().join(format!(
        "hell-testkit-pipe-descendant-{}-{}.marker",
        std::process::id(),
        std::thread::current().name().unwrap_or("unnamed")
    ));
    let _ = std::fs::remove_file(&marker);
    let mut command = Command::new(helper());
    command
        .arg("spawn-grandchild-and-exit")
        .arg("500")
        .arg(&marker);
    let started = Instant::now();
    let output = run_supervised_command(&mut command, &[], Duration::from_secs(2))
        .expect("capture process with an inherited descendant pipe");
    assert!(output.status.success());
    assert!(started.elapsed() < Duration::from_secs(1));
    std::thread::sleep(Duration::from_millis(650));
    assert!(!marker.exists(), "pipe-holding descendant escaped cleanup");
}

#[test]
fn timeout_kills_the_descendant_tree() {
    let marker = std::env::temp_dir().join(format!(
        "hell-testkit-descendant-{}-{}.marker",
        std::process::id(),
        std::thread::current().name().unwrap_or("unnamed")
    ));
    let _ = std::fs::remove_file(&marker);
    let mut command = Command::new(helper());
    command
        .arg("spawn-grandchild")
        .arg("500")
        .arg(&marker)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = SupervisedChild::spawn(&mut command).expect("spawn process tree");
    let deadline = Instant::now() + Duration::from_millis(100);
    assert!(matches!(
        child.wait_until(deadline).expect("poll process tree"),
        WaitOutcome::DeadlineExpired
    ));
    let (_, termination) = child.terminate().expect("terminate process tree");
    assert!(termination.forced);
    assert!(termination.reaped);
    std::thread::sleep(Duration::from_millis(650));
    assert!(!marker.exists(), "grandchild escaped its process tree");
}
