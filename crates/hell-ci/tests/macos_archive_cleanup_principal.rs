#![cfg(target_os = "macos")]

use std::process::Command;
use std::time::Duration;

#[test]
fn candidate_owned_archive_tree_transitions_to_trusted_cleanup_authority() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
    command.arg("__verify-macos-archive-cleanup-principal");
    let output = hell_testkit::run_supervised_command(&mut command, &[], Duration::from_mins(10))
        .expect("macOS archive cleanup principal verifier must launch");
    assert!(
        !output.timed_out,
        "macOS archive cleanup principal verifier timed out"
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
        "macOS archive cleanup principal verifier failed: stdout={} stderr={}",
        String::from_utf8_lossy(
            output
                .stdout
                .complete
                .as_deref()
                .expect("stdout must fit the bounded complete capture")
        ),
        String::from_utf8_lossy(
            output
                .stderr
                .complete
                .as_deref()
                .expect("stderr must fit the bounded complete capture")
        )
    );
}
