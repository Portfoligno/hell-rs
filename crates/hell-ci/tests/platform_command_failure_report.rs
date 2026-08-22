#![cfg(any(unix, windows))]

use std::process::Command;
use std::time::Duration;

#[test]
fn deterministic_command_failure_persists_typed_bounded_evidence() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
    command.arg("__verify-platform-command-failure-report");
    let output = hell_testkit::run_supervised_command(&mut command, &[], Duration::from_secs(45))
        .expect("platform command-failure report verifier must execute");
    assert!(
        output.status.success() && !output.timed_out,
        "platform command-failure report verifier failed: stdout={}, stderr={}",
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
