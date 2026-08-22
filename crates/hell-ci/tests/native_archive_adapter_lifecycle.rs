#![cfg(unix)]

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        for _ in 0..32 {
            let sequence = FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "hell-ci-native-archive-adapter-lifecycle-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&root) {
                Ok(()) => return Self { root },
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("adapter lifecycle fixture must be created: {error}"),
            }
        }
        panic!("adapter lifecycle fixture allocation exhausted its collision bound");
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn run(command: &mut Command) -> hell_testkit::SupervisedOutput {
    let output = hell_testkit::run_supervised_command(command, &[], Duration::from_secs(30))
        .expect("native archive adapter lifecycle verifier must execute");
    assert!(
        !output.timed_out,
        "native archive adapter lifecycle verifier timed out"
    );
    assert!(
        output
            .phase_timings
            .iter()
            .any(|phase| phase.name == "quiescence-complete")
    );
    assert_eq!(
        output.phase_timings.last().map(|phase| phase.name),
        Some("stdin-joined")
    );
    output
}

fn stderr(output: &hell_testkit::SupervisedOutput) -> String {
    String::from_utf8_lossy(
        output
            .stderr
            .complete
            .as_deref()
            .unwrap_or(&output.stderr.prefix),
    )
    .into_owned()
}

#[test]
fn explicit_adapter_close_cleans_partial_and_failed_initialization_without_late_drop() {
    let fixture = Fixture::new();
    let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
    command
        .arg("__verify-native-archive-adapter-cleanup")
        .arg(&fixture.root);
    let output = run(&mut command);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        fs::read_dir(&fixture.root)
            .expect("adapter lifecycle fixture must remain readable")
            .next()
            .is_none(),
        "explicit adapter cleanup must leave its retained parent empty"
    );
}
