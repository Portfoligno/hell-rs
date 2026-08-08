use std::process::Command;

fn hell() -> Command {
    Command::new(env!("CARGO_BIN_EXE_hell"))
}

#[test]
fn version_is_the_exact_language_baseline() {
    let output = hell().arg("--version").output().unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"2026-05-29\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn unknown_host_option_is_a_usage_error() {
    let output = hell().arg("--not-a-host-option").output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("unknown option"));
}
