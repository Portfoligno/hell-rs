#![cfg(windows)]

use std::process::Command;
use std::time::Duration;

#[test]
fn restricted_cargo_and_git_inventory_use_exact_windows_authorities() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
    command.arg("__verify-windows-candidate-target-authority");
    let output =
        hell_testkit::run_supervised_command(&mut command, &[], Duration::from_secs(11 * 60))
            .expect("Windows candidate target verifier must launch");
    assert!(
        output.status.success() && !output.timed_out,
        "Windows candidate target verifier failed: stdout={} stderr={}",
        String::from_utf8_lossy(
            output
                .stdout
                .complete
                .as_deref()
                .unwrap_or(&output.stdout.prefix),
        ),
        String::from_utf8_lossy(
            output
                .stderr
                .complete
                .as_deref()
                .unwrap_or(&output.stderr.prefix),
        ),
    );
}
