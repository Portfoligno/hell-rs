#![cfg(unix)]

use std::process::Command;
use std::time::Duration;

fn run(command: &mut Command) -> hell_testkit::SupervisedOutput {
    let output = hell_testkit::run_supervised_command(command, &[], Duration::from_secs(30))
        .expect("standard tool resolver verifier must execute");
    assert!(
        !output.timed_out,
        "standard tool resolver verifier timed out"
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
fn standard_tool_authorities_bind_nonwritable_parents_and_reject_drift() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
    command.arg("__verify-standard-tool-resolver");
    let output = run(&mut command);
    assert!(output.status.success(), "{}", stderr(&output));
}
