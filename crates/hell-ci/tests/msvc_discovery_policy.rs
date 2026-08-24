use std::process::Command;
use std::time::{Duration, Instant};

const PRIMARY_TIMEOUT: Duration = Duration::from_mins(2);
const COMPLETION_RESERVE: Duration = Duration::from_secs(30);

fn run_verifier(argument: &str, primary_timeout: Duration) -> hell_testkit::SupervisedOutput {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
    command.arg(argument);
    let Some(execution_deadline) = Instant::now().checked_add(primary_timeout) else {
        panic!("MSVC discovery policy execution deadline overflowed");
    };
    let Some(completion_deadline) = execution_deadline.checked_add(COMPLETION_RESERVE) else {
        panic!("MSVC discovery policy completion deadline overflowed");
    };
    let output = hell_testkit::run_supervised_command_until(
        &mut command,
        &[],
        execution_deadline,
        completion_deadline,
        None,
    )
    .expect("MSVC discovery policy verifier must execute and complete");
    for expected in ["quiescence-complete", "stdout-joined", "stderr-joined"] {
        assert!(
            output
                .phase_timings
                .iter()
                .any(|phase| phase.name == expected),
            "MSVC discovery policy verifier lacks terminal phase {expected}"
        );
    }
    assert_eq!(
        output.phase_timings.last().map(|phase| phase.name),
        Some("stdin-joined"),
        "MSVC discovery policy verifier lacks a terminal I/O receipt"
    );
    output
}

#[test]
fn msvc_fixture_enforces_typed_binding_parsing_and_substitution_policy() {
    let output = run_verifier("__verify-msvc-discovery-policy", PRIMARY_TIMEOUT);
    assert!(
        output.status.success() && !output.timed_out,
        "{}",
        String::from_utf8_lossy(
            output
                .stderr
                .complete
                .as_deref()
                .unwrap_or(&output.stderr.prefix)
        )
    );
}

#[test]
fn msvc_primary_deadline_expiry_retains_cleanup_and_terminal_reserve() {
    let output = run_verifier(
        "__verify-msvc-discovery-primary-deadline",
        Duration::from_secs(10),
    );
    assert!(
        output.status.success() && !output.timed_out,
        "expired primary verifier did not finish inside its reserved cleanup envelope: {}",
        String::from_utf8_lossy(
            output
                .stderr
                .complete
                .as_deref()
                .unwrap_or(&output.stderr.prefix)
        )
    );
    if let Some(termination) = output.termination {
        assert!(
            termination.reaped,
            "expired primary verifier termination receipt lacks leader reaping"
        );
    }
}
