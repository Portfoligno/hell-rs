#![cfg(unix)]

use std::process::Command;

#[test]
fn posix_post_state_validators_require_exact_uid_gid_mode_and_link_count() {
    let output = Command::new(env!("CARGO_BIN_EXE_hell-ci"))
        .arg("__verify-posix-post-state-metadata")
        .output()
        .expect("POSIX post-state metadata verifier must execute");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
