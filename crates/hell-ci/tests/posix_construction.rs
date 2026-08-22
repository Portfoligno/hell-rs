#[cfg(unix)]
use std::process::Command;
#[cfg(unix)]
use std::time::Duration;

#[cfg(unix)]
fn hell_ci() -> Command {
    Command::new(env!("CARGO_BIN_EXE_hell-ci"))
}

#[cfg(unix)]
fn run(command: &mut Command, context: &str) -> hell_testkit::SupervisedOutput {
    let output = hell_testkit::run_supervised_command(command, &[], Duration::from_secs(30))
        .unwrap_or_else(|error| panic!("{context} must execute: {error}"));
    assert!(!output.timed_out, "{context} timed out");
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

#[cfg(unix)]
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

#[cfg(unix)]
#[test]
fn candidate_environment_and_sandbox_use_privileged_exact_construction() {
    let mut command = hell_ci();
    command.arg("__verify-posix-candidate-environment-construction");
    let output = run(&mut command, "POSIX candidate construction verification");
    assert!(output.status.success(), "{}", stderr(&output));
}

#[cfg(target_os = "macos")]
#[test]
fn staged_native_authorities_strip_and_reject_access_control_lists() {
    let mut command = hell_ci();
    command.arg("__verify-staged-native-acl-policy");
    let output = run(&mut command, "staged native ACL verification");
    assert!(output.status.success(), "{}", stderr(&output));
}
