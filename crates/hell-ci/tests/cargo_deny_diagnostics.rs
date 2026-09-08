#![cfg(unix)]

use std::ffi::OsString;
use std::fs;
use std::os::unix::process::ExitStatusExt as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use hell_ci::{
    CargoDenyDiagnosticPhase, CargoDenyDiagnostics, CommandResult, CommandTerminationResult,
};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "hell-cargo-deny-diagnostics-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("memcordon")).unwrap();
        Self(fs::canonicalize(root).unwrap())
    }

    fn receipt(&self, name: &str) -> serde_json::Value {
        serde_json::from_slice(
            &fs::read(self.0.join("memcordon/trusted-cargo-deny").join(name)).unwrap(),
        )
        .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn result(status: i32, timed_out: bool, stdout: Vec<u8>, stderr: Vec<u8>) -> CommandResult {
    CommandResult {
        status: std::process::ExitStatus::from_raw(status << 8),
        duration: Duration::from_millis(10),
        timed_out,
        stdout_bytes: stdout.len().try_into().unwrap(),
        stderr_bytes: stderr.len().try_into().unwrap(),
        stdout_sha256: hell_testkit::sha256_bytes(&stdout),
        stderr_sha256: hell_testkit::sha256_bytes(&stderr),
        stdout,
        stderr,
        stdout_truncated: false,
        stderr_truncated: false,
        termination: CommandTerminationResult {
            cleanup_id: None,
            forced: timed_out,
            reaped: true,
            candidate_quiescence_complete: true,
        },
        phase_timings: Vec::new(),
    }
}

#[test]
fn failed_authority_check_retains_both_streams_and_original_status() {
    let fixture = Fixture::new();
    let authority = CargoDenyDiagnostics::reserve(&fixture.0).unwrap();
    let captured = result(
        6,
        false,
        b"policy stdout\n".to_vec(),
        b"policy stderr\n".to_vec(),
    );
    let arguments = [OsString::from("check"), OsString::from("advisories")];
    assert_eq!(
        authority
            .record(CargoDenyDiagnosticPhase::Seed, &arguments, &captured)
            .unwrap_err(),
        "trusted cargo-deny authority checks failed with status 6"
    );
    let receipt = fixture.receipt("seed.json");
    assert_eq!(receipt["statusCode"], 6);
    assert_eq!(receipt["timedOut"], false);
    assert_eq!(receipt["stdoutDetail"], "policy stdout\n");
    assert_eq!(receipt["stderrDetail"], "policy stderr\n");
    assert_eq!(
        receipt["arguments"],
        serde_json::json!(["check", "advisories"])
    );
    assert_eq!(fs::read_dir(&fixture.0).unwrap().count(), 1);
}

#[test]
fn timed_out_authority_check_retains_timeout_even_with_zero_exit() {
    let fixture = Fixture::new();
    let authority = CargoDenyDiagnostics::reserve(&fixture.0).unwrap();
    let captured = result(0, true, Vec::new(), b"deadline\n".to_vec());
    assert!(
        authority
            .record(CargoDenyDiagnosticPhase::Seed, &[], &captured)
            .is_err()
    );
    let receipt = fixture.receipt("seed.json");
    assert_eq!(receipt["state"], "failed");
    assert_eq!(receipt["timedOut"], true);
}

#[test]
fn successful_authority_checks_use_distinct_non_overwriting_phase_receipts() {
    let fixture = Fixture::new();
    let authority = CargoDenyDiagnostics::reserve(&fixture.0).unwrap();
    let captured = result(0, false, b"policy passed\n".to_vec(), Vec::new());
    authority
        .record(CargoDenyDiagnosticPhase::Seed, &[], &captured)
        .unwrap();
    authority
        .record(CargoDenyDiagnosticPhase::FinalHome, &[], &captured)
        .unwrap();
    assert_eq!(fixture.receipt("seed.json")["state"], "passed");
    assert_eq!(fixture.receipt("final-home.json")["state"], "passed");
    assert!(
        authority
            .record(CargoDenyDiagnosticPhase::Seed, &[], &captured)
            .is_err()
    );
}

#[test]
fn large_captures_keep_bounded_details_and_full_stream_hashes() {
    let fixture = Fixture::new();
    let authority = CargoDenyDiagnostics::reserve(&fixture.0).unwrap();
    let mut captured = result(6, false, b"out".repeat(32_000), b"err".repeat(32_000));
    captured.stdout_truncated = true;
    captured.stderr_truncated = true;
    assert!(
        authority
            .record(CargoDenyDiagnosticPhase::Seed, &[], &captured)
            .is_err()
    );
    let receipt = fixture.receipt("seed.json");
    for stream in ["stdout", "stderr"] {
        let object = receipt.as_object().unwrap();
        let detail = object
            .get(&format!("{stream}Detail"))
            .unwrap()
            .as_str()
            .unwrap();
        assert!(detail.len() < 4096);
        assert_eq!(object.get(&format!("{stream}Truncated")).unwrap(), true);
        assert_eq!(
            object.get(&format!("{stream}DetailTruncated")).unwrap(),
            true
        );
    }
    assert_eq!(receipt["stdoutSha256"], captured.stdout_sha256.hex());
    assert_eq!(receipt["stderrSha256"], captured.stderr_sha256.hex());
    assert_eq!(receipt["stdoutBytes"], captured.stdout_bytes);
    assert_eq!(
        receipt["diagnosticStreams"]["stderr"]["captureTruncated"],
        true
    );
    assert_eq!(
        receipt["diagnosticStreams"]["stderr"]["retentionTruncated"],
        false
    );
    assert_eq!(receipt["diagnosticStreams"]["stderr"]["complete"], false);
}

#[test]
fn full_diagnostic_preserves_middle_omitted_from_generic_preview() {
    let fixture = Fixture::new();
    let authority = CargoDenyDiagnostics::reserve(&fixture.0).unwrap();
    let mut stderr = vec![b'x'; 4771];
    let marker = b"license-specific-middle-diagnostic";
    let middle = stderr.len() / 2;
    stderr[middle..middle + marker.len()].copy_from_slice(marker);
    let captured = result(6, false, Vec::new(), stderr.clone());
    assert!(
        authority
            .record(CargoDenyDiagnosticPhase::Seed, &[], &captured)
            .is_err()
    );
    let receipt = fixture.receipt("seed.json");
    assert_eq!(receipt["stderrDetailTruncated"], true);
    let stream = &receipt["diagnosticStreams"]["stderr"];
    assert_eq!(stream["complete"], true);
    assert_eq!(stream["retentionTruncated"], false);
    let retained = fs::read(
        fixture
            .0
            .join("memcordon/trusted-cargo-deny")
            .join(stream["path"].as_str().unwrap()),
    )
    .unwrap();
    assert_eq!(retained, stderr);
    assert_eq!(stream["retainedSha256"], captured.stderr_sha256.hex());
    assert_eq!(stream["originalSha256"], stream["retainedSha256"]);
}

#[test]
fn over_budget_diagnostics_explicitly_bind_prefix_suffix_and_omission() {
    let fixture = Fixture::new();
    let authority = CargoDenyDiagnostics::reserve(&fixture.0).unwrap();
    authority
        .record(
            CargoDenyDiagnosticPhase::Seed,
            &[],
            &result(0, false, Vec::new(), Vec::new()),
        )
        .unwrap();
    let limit = usize::try_from(
        fixture.receipt("seed.json")["diagnosticStreams"]["limitBytes"]
            .as_u64()
            .unwrap(),
    )
    .unwrap();
    let bytes = (0..limit * 2)
        .map(|index| index.to_le_bytes()[0])
        .collect::<Vec<_>>();
    let captured = result(6, false, bytes.clone(), Vec::new());
    assert!(
        authority
            .record(CargoDenyDiagnosticPhase::FinalHome, &[], &captured)
            .is_err()
    );
    let receipt = fixture.receipt("final-home.json");
    let stream = &receipt["diagnosticStreams"]["stdout"];
    let retained = fs::read(
        fixture
            .0
            .join("memcordon/trusted-cargo-deny/final-home.stdout.bin"),
    )
    .unwrap();
    assert_eq!(retained.len(), limit);
    assert_eq!(stream["retentionTruncated"], true);
    assert_eq!(stream["captureTruncated"], false);
    assert_eq!(stream["complete"], false);
    assert_eq!(stream["omittedCapturedBytes"], limit as u64);
    assert_eq!(stream["layout"], "captured-prefix-suffix");
    assert_eq!(
        stream["retainedSha256"],
        hell_testkit::sha256_bytes(&retained).hex()
    );
    let prefix = usize::try_from(stream["prefixBytes"].as_u64().unwrap()).unwrap();
    let suffix = usize::try_from(stream["suffixBytes"].as_u64().unwrap()).unwrap();
    assert_eq!(&retained[..prefix], &bytes[..prefix]);
    assert_eq!(&retained[prefix..], &bytes[bytes.len() - suffix..]);
}

#[test]
fn stream_artifacts_preserve_invalid_utf8_and_empty_output_exactly() {
    let fixture = Fixture::new();
    let authority = CargoDenyDiagnostics::reserve(&fixture.0).unwrap();
    let bytes = vec![0, 0xff, 0xfe, b'\n'];
    authority
        .record(
            CargoDenyDiagnosticPhase::Seed,
            &[],
            &result(0, false, bytes.clone(), Vec::new()),
        )
        .unwrap();
    assert_eq!(
        fs::read(
            fixture
                .0
                .join("memcordon/trusted-cargo-deny/seed.stdout.bin")
        )
        .unwrap(),
        bytes
    );
    assert!(
        fs::read(
            fixture
                .0
                .join("memcordon/trusted-cargo-deny/seed.stderr.bin")
        )
        .unwrap()
        .is_empty()
    );
    let receipt = fixture.receipt("seed.json");
    assert_eq!(receipt["diagnosticStreams"]["stdout"]["complete"], true);
    assert_eq!(receipt["diagnosticStreams"]["stderr"]["complete"], true);
    assert_eq!(receipt["diagnosticStreams"]["stderr"]["retainedBytes"], 0);
}

#[test]
fn retention_failure_preserves_primary_and_rejects_changed_output_authority() {
    let fixture = Fixture::new();
    let authority = CargoDenyDiagnostics::reserve(&fixture.0).unwrap();
    let directory = fixture.0.join("memcordon/trusted-cargo-deny");
    fs::remove_dir(&directory).unwrap();
    fs::write(&directory, b"wrong kind\n").unwrap();
    let captured = result(6, false, Vec::new(), b"primary\n".to_vec());
    let error = authority
        .record(CargoDenyDiagnosticPhase::Seed, &[], &captured)
        .unwrap_err();
    assert!(error.starts_with("trusted cargo-deny authority checks failed with status 6; additionally, cannot retain trusted cargo-deny diagnostics:"));
}
