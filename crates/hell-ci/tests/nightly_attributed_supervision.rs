#![cfg(unix)]

use std::process::Command;
use std::time::Duration;

#[test]
fn nightly_attributed_supervision_preserves_typed_cleanup_and_no_live_descendant() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
    command.arg("__verify-nightly-attributed-supervision");
    let output = hell_testkit::run_supervised_command(&mut command, &[], Duration::from_secs(15))
        .expect("nightly attributed supervision verifier must execute");
    assert!(
        output.status.success() && !output.timed_out,
        "nightly attributed supervision verifier failed: stdout={}, stderr={}",
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

#[test]
fn nightly_status_failure_preserves_the_causal_failed_case() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
    command.arg("__verify-nightly-failed-case-attribution");
    let output = hell_testkit::run_supervised_command(&mut command, &[], Duration::from_secs(15))
        .expect("nightly failed-case attribution verifier must execute");
    assert!(
        output.status.success() && !output.timed_out,
        "nightly failed-case attribution verifier failed: stdout={}, stderr={}",
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
