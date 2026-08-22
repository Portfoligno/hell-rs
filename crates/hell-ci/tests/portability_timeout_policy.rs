use std::process::Command;
use std::time::Duration;

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
fn portability_deadline_retains_exact_cleanup_and_reporting_reserve() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
    command.arg("__verify-portability-timeout-policy");
    let output = run(&mut command, "portability deadline verifier");
    assert!(output.status.success(), "{}", stderr(&output));
}

#[cfg(unix)]
#[test]
fn portability_deadline_relays_attribution_and_reaps_the_process_tree() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
    command.arg("__verify-portability-supervision");
    let output = run(&mut command, "portability supervision verifier");
    assert!(output.status.success(), "{}", stderr(&output));
}
