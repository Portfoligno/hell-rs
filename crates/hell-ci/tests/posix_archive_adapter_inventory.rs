#![cfg(unix)]

use std::process::Command;
use std::time::Duration;

fn run(command: &mut Command) -> hell_testkit::SupervisedOutput {
    let output = hell_testkit::run_supervised_command(command, &[], Duration::from_mins(10))
        .expect("POSIX archive adapter inventory verifier must execute");
    assert!(
        !output.timed_out,
        "POSIX archive adapter inventory verifier timed out"
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
fn stack_runtime_state_is_disjoint_from_the_closed_toolchain_authority() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
    command.arg("__verify-posix-archive-adapter-transition");
    let output = run(&mut command);
    assert!(output.status.success(), "{}", stderr(&output));
}
