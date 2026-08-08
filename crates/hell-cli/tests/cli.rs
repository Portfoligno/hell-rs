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
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("Invalid option"));
}

#[test]
fn help_and_no_arguments_match_the_upstream_entry_points() {
    let help = hell().arg("--help").output().unwrap();
    assert!(help.status.success());
    assert_eq!(
        String::from_utf8(help.stdout).unwrap(),
        concat!(
            "hell - A Haskell-driven scripting language\n\n",
            "Usage: hell [FILE | --check FILE | --version]\n\n",
            "  Runs and typechecks Hell scripts\n\n",
            "Available options:\n",
            "  FILE                     Run the given .hell file\n",
            "  --check FILE             Typecheck the given .hell file\n",
            "  --version                Print the version\n",
            "  -h,--help                Show this help text\n",
        )
    );
    assert!(help.stderr.is_empty());

    let no_arguments = hell().output().unwrap();
    assert!(no_arguments.status.success());
    assert_eq!(no_arguments.stdout, b"2026-05-29\n");
    assert!(no_arguments.stderr.is_empty());
}

#[test]
fn build_info_records_compiler_and_runtime_policy() {
    let output = hell().arg("--build-info").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("compiler policy CompilerConfig"));
    assert!(stdout.contains("source commit "));
    assert!(stdout.contains("compatibility evidence schema 1"));
    assert!(stdout.contains("profile: Upstream"));
    assert!(stdout.contains("max_expansion_depth: None"));
    assert!(stdout.contains("runtime policy RuntimePolicy"));
    assert!(stdout.contains("id: \"upstream\""));
    assert!(stdout.contains("limits: RuntimeLimits"));
    assert!(output.stderr.is_empty());
}
