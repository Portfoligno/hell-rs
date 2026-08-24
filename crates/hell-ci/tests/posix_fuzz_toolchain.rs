#![cfg(unix)]

use std::process::Command;
use std::time::Duration;

#[test]
fn cargo_fuzz_probes_and_campaigns_receive_the_manifest_toolchain() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
    command.arg("__verify-fuzz-toolchain-command");
    let output = hell_testkit::run_supervised_command(&mut command, &[], Duration::from_secs(30))
        .expect("fuzz toolchain command verification must execute");
    assert!(!output.timed_out, "fuzz command verification timed out");
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
