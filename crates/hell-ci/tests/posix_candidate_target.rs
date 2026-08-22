#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt as _;
#[cfg(unix)]
use std::process::Command;
#[cfg(unix)]
use std::time::Duration;

#[cfg(unix)]
fn run(command: &mut Command, context: &str) -> hell_testkit::SupervisedOutput {
    let output = hell_testkit::run_supervised_command(command, &[], Duration::from_secs(30))
        .unwrap_or_else(|error| panic!("{context} must execute: {error}"));
    assert!(!output.timed_out, "{context} timed out");
    assert!(
        output
            .phase_timings
            .iter()
            .any(|phase| phase.name == "quiescence-complete")
    );
    assert_eq!(
        output.phase_timings.last().map(|phase| phase.name),
        Some("stdin-joined")
    );
    output
}

#[cfg(unix)]
fn stderr(output: &hell_testkit::SupervisedOutput) -> String {
    String::from_utf8_lossy(
        output
            .stderr
            .complete
            .as_deref()
            .unwrap_or(&output.stderr.prefix),
    )
    .into_owned()
}

#[cfg(unix)]
#[test]
fn candidate_receipt_consumer_accepts_exact_driver_identity_and_rejects_mutation() {
    let executable = fs::canonicalize(env!("CARGO_BIN_EXE_hell-ci"))
        .expect("POSIX driver receipt executable must canonicalize");
    let metadata = fs::metadata(&executable).expect("POSIX driver receipt must be inspectable");
    let digest = hell_testkit::sha256_file(&executable)
        .expect("POSIX driver receipt executable must be hashable");
    let arguments = [
        "posix-driver-receipt-v1".into(),
        executable.as_os_str().to_owned(),
        metadata.dev().to_string().into(),
        metadata.ino().to_string().into(),
        metadata.uid().to_string().into(),
        metadata.gid().to_string().into(),
        (metadata.mode() & 0o7777).to_string().into(),
        digest.hex().into(),
        "fixture".into(),
    ];
    let mut command = Command::new(&executable);
    command
        .arg("__verify-posix-candidate-driver-receipt")
        .args(&arguments);
    let output = run(&mut command, "POSIX candidate receipt verification");
    assert!(output.status.success(), "{}", stderr(&output));
    let mut mutated = arguments;
    mutated[3] = metadata.ino().wrapping_add(1).to_string().into();
    let mut command = Command::new(&executable);
    command
        .arg("__verify-posix-candidate-driver-receipt")
        .args(mutated);
    let rejected = run(&mut command, "mutated POSIX candidate receipt verification");
    assert!(!rejected.status.success());
    assert!(stderr(&rejected).contains("lacks its driver-owned pre-candidate receipt"));
}

#[cfg(unix)]
#[test]
fn native_cargo_without_a_staged_compiler_is_rejected() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
    command.arg("__verify-posix-native-cargo-rejection");
    let output = run(&mut command, "POSIX native Cargo rejection verification");
    assert!(output.status.success(), "{}", stderr(&output));
}

#[cfg(unix)]
#[test]
fn rustc_environment_is_exact_without_path_or_wrapper_fallback() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
    command.arg("__verify-posix-rustc-environment");
    let output = run(&mut command, "POSIX Rust compiler environment verification");
    assert!(output.status.success(), "{}", stderr(&output));
}

#[cfg(unix)]
#[test]
fn expired_identity_query_deadline_rejects_before_launch() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
    command.arg("__verify-posix-identity-query-deadline");
    let output = run(&mut command, "POSIX identity query deadline verification");
    assert!(output.status.success(), "{}", stderr(&output));
}

#[cfg(unix)]
#[test]
fn candidate_target_remover_is_bounded_and_preserves_external_authorities() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
    command.arg("__verify-posix-candidate-target-remover");
    let output = run(&mut command, "POSIX candidate target remover verification");
    assert!(output.status.success(), "{}", stderr(&output));
}

#[cfg(unix)]
#[test]
fn principal_cleanup_requires_quiescence_then_root_then_user_absence() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
    command.arg("__verify-posix-principal-cleanup-order");
    let output = run(&mut command, "POSIX principal cleanup order verification");
    assert!(output.status.success(), "{}", stderr(&output));
}
