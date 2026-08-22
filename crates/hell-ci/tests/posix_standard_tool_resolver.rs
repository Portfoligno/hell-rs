#![cfg(unix)]

use std::process::Command;

#[test]
fn standard_tool_authorities_bind_nonwritable_parents_and_reject_drift() {
    let output = Command::new(env!("CARGO_BIN_EXE_hell-ci"))
        .arg("__verify-standard-tool-resolver")
        .output()
        .expect("standard tool resolver verifier must execute");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
