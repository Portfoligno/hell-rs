#[cfg(unix)]
use std::process::Command;

#[cfg(unix)]
#[test]
fn process_authorities_normalize_merged_usr_and_reject_receipt_drift() {
    let output = Command::new(env!("CARGO_BIN_EXE_hell-ci"))
        .arg("__verify-posix-process-authority")
        .output()
        .expect("POSIX process authority verification must execute");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
