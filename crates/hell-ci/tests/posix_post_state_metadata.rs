#![cfg(unix)]

use std::process::Command;
use std::time::Duration;

fn run(command: &mut Command) -> hell_testkit::SupervisedOutput {
    let output = hell_testkit::run_supervised_command(command, &[], Duration::from_secs(30))
        .expect("POSIX post-state metadata verifier must execute");
    assert!(
        !output.timed_out,
        "POSIX post-state metadata verifier timed out"
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
fn posix_post_state_validators_require_exact_uid_gid_mode_and_link_count() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
    command.arg("__verify-posix-post-state-metadata");
    let output = run(&mut command);
    assert!(output.status.success(), "{}", stderr(&output));
}
