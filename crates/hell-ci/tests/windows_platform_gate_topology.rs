#![cfg(windows)]

use std::process::Command;

#[test]
fn windows_release_build_and_binary_receipt_precede_conformance() {
    let output = Command::new(env!("CARGO_BIN_EXE_hell-ci"))
        .arg("__verify-windows-platform-gate-topology")
        .output()
        .expect("Windows platform gate topology verification must execute");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
