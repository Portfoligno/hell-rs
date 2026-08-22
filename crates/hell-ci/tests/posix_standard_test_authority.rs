#[cfg(unix)]
use std::process::Command;
#[cfg(unix)]
use std::time::Duration;

#[cfg(unix)]
#[test]
fn candidate_home_probe_binds_the_platforms_exact_standard_test_executable() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
    command.arg("__verify-posix-candidate-home-test-authority");
    let output = hell_testkit::run_supervised_command(&mut command, &[], Duration::from_mins(10))
        .expect("POSIX candidate home test authority verification must execute");
    assert!(
        !output.timed_out,
        "POSIX candidate home test authority verification timed out"
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
