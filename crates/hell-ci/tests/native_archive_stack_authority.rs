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
                "hell-ci-native-archive-stack-authority-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&root) {
                Ok(()) => return Self { root },
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("Stack archive authority fixture must be created: {error}"),
            }
        }
        panic!("Stack archive authority fixture allocation exhausted its collision bound");
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn stack_package_source_cwd_is_separate_from_its_archive_write_authority() {
    let fixture = Fixture::new();
    let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
    command
        .arg("__verify-native-archive-adapter-cleanup")
        .arg(&fixture.root);
    let output = hell_testkit::run_supervised_command(&mut command, &[], Duration::from_mins(10))
        .expect("native Stack archive authority verifier must execute");
    assert!(
        !output.timed_out,
        "native Stack archive authority verifier timed out"
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
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(
            output
                .stderr
                .complete
                .as_deref()
                .expect("stderr must fit the bounded complete capture")
        )
    );
}

#[cfg(target_os = "macos")]
#[test]
fn restricted_candidate_uses_only_the_sealed_archive_broker_capability() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
    command.arg("__verify-posix-candidate-target-authority");
    let output = hell_testkit::run_supervised_command(&mut command, &[], Duration::from_mins(10))
        .expect("typed archive broker production verifier must execute");
    assert!(
        output.status.success() && !output.timed_out,
        "typed archive broker production verifier failed: stdout={}, stderr={}",
        String::from_utf8_lossy(
            output
                .stdout
                .complete
                .as_deref()
                .unwrap_or(&output.stdout.prefix),
        ),
        String::from_utf8_lossy(
            output
                .stderr
                .complete
                .as_deref()
                .unwrap_or(&output.stderr.prefix),
        ),
    );
}
