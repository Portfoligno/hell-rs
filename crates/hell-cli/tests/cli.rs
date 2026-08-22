use std::process::{Command, Output};
use std::time::Duration;

fn hell() -> Command {
    Command::new(env!("CARGO_BIN_EXE_hell"))
}

fn run(command: &mut Command) -> Output {
    let output = hell_testkit::run_supervised_command(command, &[], Duration::from_secs(30))
        .expect("supervise hell command");
    assert!(!output.timed_out, "hell command exceeded its deadline");
    Output {
        status: output.status,
        stdout: output.stdout.complete.expect("stdout capture is complete"),
        stderr: output.stderr.complete.expect("stderr capture is complete"),
    }
}

#[test]
fn version_is_the_exact_language_baseline() {
    let output = run(hell().arg("--version"));
    assert!(output.status.success());
    assert_eq!(output.stdout, b"2026-05-29\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn unknown_host_option_is_a_usage_error() {
    let output = run(hell().arg("--not-a-host-option"));
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("Invalid option"));
}

#[test]
fn help_and_no_arguments_match_the_upstream_entry_points() {
    let help = run(hell().arg("--help"));
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

    let no_arguments = run(&mut hell());
    assert!(no_arguments.status.success());
    assert_eq!(no_arguments.stdout, b"2026-05-29\n");
    assert!(no_arguments.stderr.is_empty());
}

#[test]
fn build_info_records_compiler_and_runtime_policy() {
    let output = run(hell().arg("--build-info"));
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("compiler policy CompilerConfig"));
    assert!(stdout.contains("compatibility evidence schema 2"));
    assert!(stdout.contains(&format!(
        "compat tracing enabled {}",
        cfg!(feature = "compat-tracing")
    )));
    assert!(stdout.contains("profile: Upstream"));
    assert!(stdout.contains("max_expansion_depth: None"));
    assert!(stdout.contains("runtime policy RuntimePolicy"));
    assert!(stdout.contains("id: \"upstream\""));
    assert!(stdout.contains("limits: RuntimeLimits"));
    assert!(output.stderr.is_empty());
}
