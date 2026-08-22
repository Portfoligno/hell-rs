#![cfg(unix)]

use std::process::Command;

#[test]
fn stack_runtime_state_is_disjoint_from_the_closed_toolchain_authority() {
    let output = Command::new(env!("CARGO_BIN_EXE_hell-ci"))
        .arg("__verify-posix-archive-adapter-transition")
        .output()
        .expect("POSIX archive adapter inventory verifier must execute");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
