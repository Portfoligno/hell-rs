#![cfg(windows)]

use std::process::Command;

#[test]
fn windows_final_output_uses_the_exact_base_inventory() {
    let output = Command::new(env!("CARGO_BIN_EXE_hell-ci"))
        .arg("__verify-windows-final-platform-inventory")
        .output()
        .expect("Windows final platform inventory verifier must execute");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
