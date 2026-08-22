#[cfg(unix)]
use std::process::Command;

#[cfg(unix)]
fn hell_ci() -> Command {
    Command::new(env!("CARGO_BIN_EXE_hell-ci"))
}

#[cfg(unix)]
#[test]
fn candidate_environment_and_sandbox_use_privileged_exact_construction() {
    let output = hell_ci()
        .arg("__verify-posix-candidate-environment-construction")
        .output()
        .expect("POSIX candidate construction verification must execute");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(target_os = "macos")]
#[test]
fn staged_native_authorities_strip_and_reject_access_control_lists() {
    let output = hell_ci()
        .arg("__verify-staged-native-acl-policy")
        .output()
        .expect("staged native ACL verification must execute");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
