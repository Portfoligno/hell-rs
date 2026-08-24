use std::process::Command;
use std::time::Duration;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CaptureReceipt {
    schema_version: u64,
    state: String,
    cleanup_id: u64,
    reaped: bool,
    candidate_quiescence_complete: bool,
    stdout_bytes: u64,
    stdout_sha256: String,
    stderr_bytes: u64,
    stderr_sha256: String,
    phase_timings: Vec<String>,
}

#[test]
fn ambient_candidate_capture_retains_evidence_without_relaying_streams() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
    command.arg("__verify-ambient-candidate-command-capture");
    let output = hell_testkit::run_supervised_command(&mut command, &[], Duration::from_secs(30))
        .expect("ambient-candidate capture verifier must execute");
    assert!(
        output.status.success() && !output.timed_out,
        "ambient-candidate capture verifier failed: status={:?},timedOut={},stdoutBytes={},stderrBytes={},stdout={:?},stderr={:?}",
        output.status.code(),
        output.timed_out,
        output.stdout.total_bytes,
        output.stderr.total_bytes,
        output.stdout.complete,
        output.stderr.complete,
    );
    let receipt: CaptureReceipt = serde_json::from_slice(
        output
            .stdout
            .complete
            .as_deref()
            .expect("capture verifier receipt must be complete"),
    )
    .expect("capture verifier receipt must be typed JSON");
    assert_eq!(receipt.schema_version, 1);
    assert_eq!(receipt.state, "verified");
    assert_ne!(receipt.cleanup_id, 0);
    assert!(receipt.reaped);
    assert!(!receipt.candidate_quiescence_complete);
    assert_eq!(
        receipt.stdout_bytes,
        u64::try_from(b"ambient-candidate-captured-stdout\n".len()).expect("stdout length")
    );
    assert_eq!(
        receipt.stdout_sha256,
        hell_testkit::sha256_bytes(b"ambient-candidate-captured-stdout\n").hex()
    );
    assert_eq!(
        receipt.stderr_bytes,
        u64::try_from(b"ambient-candidate-captured-stderr\n".len()).expect("stderr length")
    );
    assert_eq!(
        receipt.stderr_sha256,
        hell_testkit::sha256_bytes(b"ambient-candidate-captured-stderr\n").hex()
    );
    assert_eq!(
        receipt.phase_timings,
        [
            "quiescence-complete",
            "stdout-joined",
            "stderr-joined",
            "stdin-joined",
        ]
    );
    assert_eq!(output.stderr.total_bytes, 0);
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
}
