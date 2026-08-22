#![cfg(target_os = "macos")]

use std::process::Command;

#[test]
fn candidate_owned_archive_tree_transitions_to_trusted_cleanup_authority() {
    let output = Command::new(env!("CARGO_BIN_EXE_hell-ci"))
        .arg("__verify-macos-archive-cleanup-principal")
        .output()
        .expect("macOS archive cleanup principal verifier must launch");

    assert!(
        output.status.success(),
        "macOS archive cleanup principal verifier failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
