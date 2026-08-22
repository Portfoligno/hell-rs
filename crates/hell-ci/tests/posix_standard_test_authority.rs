#[cfg(unix)]
use std::process::Command;

#[cfg(unix)]
#[test]
fn candidate_home_probe_binds_the_platforms_exact_standard_test_executable() {
    let output = Command::new(env!("CARGO_BIN_EXE_hell-ci"))
        .arg("__verify-posix-candidate-home-test-authority")
        .output()
        .expect("POSIX candidate home test authority verification must execute");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
