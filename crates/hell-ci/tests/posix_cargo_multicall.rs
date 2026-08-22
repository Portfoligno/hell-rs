#[cfg(unix)]
use std::process::Command;
#[cfg(unix)]
use std::time::Duration;

#[cfg(unix)]
#[test]
fn cargo_multicall_preserves_typed_argv0_and_rejects_alias_substitution() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
    command.arg("__verify-cargo-multicall-argv");
    let output = hell_testkit::run_supervised_command(&mut command, &[], Duration::from_mins(10))
        .expect("Cargo multicall argv verification must execute");
    assert!(!output.timed_out, "Cargo multicall verification timed out");
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
        String::from_utf8_lossy(&output.stderr.retained_bytes())
    );
}
