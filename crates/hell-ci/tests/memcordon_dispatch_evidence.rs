use std::fs;
use std::path::PathBuf;
use std::process::{Command, ExitCode};
use std::time::Duration;

fn fixture(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("hell-operation-{name}-{}", std::process::id()));
    fs::create_dir(&path).unwrap();
    path
}

#[cfg(unix)]
#[test]
fn blocked_fuzz_diagnostic_is_retained_without_success_payload() {
    let root = fixture("blocked-fuzz");
    let work = root.join("work");
    let evidence = root.join("evidence");
    fs::create_dir_all(work.join("ci-out")).unwrap();
    fs::create_dir(&evidence).unwrap();
    let bytes = br#"{"schemaVersion":1,"state":"blocked","diagnosticCode":"fuzz.tool.resolve","diagnosticMessage":"missing protected tool"}"#;
    fs::write(work.join("ci-out/fuzz-smoke.json"), bytes).unwrap();
    hell_ci::operation_evidence::retain_blocked_fuzz_report(&work, &evidence).unwrap();
    assert_eq!(
        fs::read(evidence.join("diagnostics/fuzz-smoke.json")).unwrap(),
        bytes
    );
    assert!(!work.join("ci-out/fuzz-corpora").exists());
    assert!(!work.join("ci-out/fuzz-artifacts").exists());
    fs::remove_dir_all(&root).unwrap();
}

#[cfg(unix)]
#[test]
fn fuzz_diagnostic_retention_rejects_links_and_success_claims() {
    let root = fixture("blocked-fuzz-rejection");
    let work = root.join("work");
    let evidence = root.join("evidence");
    fs::create_dir_all(work.join("ci-out")).unwrap();
    fs::create_dir(&evidence).unwrap();
    let report = work.join("ci-out/fuzz-smoke.json");
    fs::write(&report, br#"{"schemaVersion":1,"state":"passed","diagnosticCode":"forged","diagnosticMessage":"incomplete"}"#).unwrap();
    assert!(hell_ci::operation_evidence::retain_blocked_fuzz_report(&work, &evidence).is_err());
    fs::remove_file(&report).unwrap();
    std::os::unix::fs::symlink(root.join("absent"), &report).unwrap();
    assert!(hell_ci::operation_evidence::retain_blocked_fuzz_report(&work, &evidence).is_err());
    assert!(!evidence.join("diagnostics").exists());
    fs::remove_dir_all(&root).unwrap();
}

#[cfg(unix)]
#[test]
fn explicit_root_dispatch_does_not_rediscover_ambient_cwd() {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.args(["--exact", "missing_cwd_dispatch_fixture", "--ignored"]);
    let output =
        hell_testkit::run_supervised_command(&mut command, &[], Duration::from_secs(10)).unwrap();
    assert!(output.status.success() && !output.timed_out, "{output:?}");
}

#[cfg(unix)]
#[test]
#[ignore = "isolated cwd fixture launched by explicit_root_dispatch_does_not_rediscover_ambient_cwd"]
fn missing_cwd_dispatch_fixture() {
    let root = fs::canonicalize(env!("CARGO_MANIFEST_DIR")).unwrap();
    let cwd = fixture("missing-cwd");
    std::env::set_current_dir(&cwd).unwrap();
    fs::remove_dir(&cwd).unwrap();
    assert!(std::env::current_dir().is_err());
    for (command, expected) in [
        ("fuzz", ExitCode::FAILURE),
        ("mutation", ExitCode::from(10)),
    ] {
        assert_eq!(
            hell_ci::dispatch_public_cli_at_root(
                vec![command.into(), "invalid-operation".into()],
                &root
            ),
            expected
        );
    }
}

#[test]
fn nonzero_operation_retains_streams_without_candidate_outputs() {
    let root = fixture("streams");
    let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
    command.arg("invalid-operation-evidence-fixture");
    let output =
        hell_testkit::run_supervised_command(&mut command, &[], Duration::from_secs(10)).unwrap();
    assert!(!output.status.success());
    let retained = root.join("streams").join("fuzz");
    hell_ci::operation_evidence::retain(&retained, &output).unwrap();
    assert_eq!(
        fs::read(retained.join("stderr/complete")).unwrap(),
        output.stderr.complete.as_ref().unwrap().as_slice()
    );
    let receipt: serde_json::Value =
        serde_json::from_slice(&fs::read(retained.join("capture.json")).unwrap()).unwrap();
    assert_eq!(receipt["stderr"]["sha256"], output.stderr.sha256.hex());
    assert_eq!(receipt["exit_code"], output.status.code().unwrap());
    assert!(!root.join("ci-out").exists());
    assert!(hell_ci::operation_evidence::failure("fuzz", &output).contains("returned"));
    assert!(hell_ci::operation_evidence::retain(&retained, &output).is_err());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn nested_regression_diagnostics_preserve_bytes_and_survive_stdout_failure() {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    hell_ci::operation_evidence::forward_nested_capture(
        b"cargo output\0",
        b"cargo error\xff",
        &mut stdout,
        &mut stderr,
    )
    .unwrap();
    assert_eq!(stdout, b"cargo output\0");
    assert_eq!(stderr, b"cargo error\xff");
    let mut full = [];
    let mut diagnostic = Vec::new();
    assert!(
        hell_ci::operation_evidence::forward_nested_capture(
            b"cannot fit",
            b"original cargo failure",
            &mut full.as_mut_slice(),
            &mut diagnostic
        )
        .is_err()
    );
    assert_eq!(diagnostic, b"original cargo failure");
}
