#[cfg(unix)]
use std::process::Command;

#[cfg(unix)]
#[test]
fn cargo_multicall_preserves_typed_argv0_and_rejects_alias_substitution() {
    let output = Command::new(env!("CARGO_BIN_EXE_hell-ci"))
        .arg("__verify-cargo-multicall-argv")
        .output()
        .expect("Cargo multicall argv verification must execute");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
