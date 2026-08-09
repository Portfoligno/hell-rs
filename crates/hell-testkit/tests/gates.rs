use std::sync::Arc;
use std::time::Duration;

use hell_testkit::{
    ClassifiedMismatch, DeterministicBytes, DeterministicUtf8, DifferentialCase,
    DifferentialMismatch, Digest, DivergenceClass, EnvironmentProfile, ExecutableRole,
    MismatchKind, differential, release_gate, verify_executable,
};

#[test]
fn deterministic_corpus_is_reproducible_and_bounded() {
    let left = DeterministicBytes::new(0x5eed, 128, 192).collect::<Vec<_>>();
    let right = DeterministicBytes::new(0x5eed, 128, 192).collect::<Vec<_>>();
    assert_eq!(left, right);
    assert_eq!(left.len(), 128);
    assert!(left.iter().all(|bytes| bytes.len() <= 192));
    assert!(left.iter().any(Vec::is_empty));
    assert!(left.iter().any(|bytes| !bytes.is_empty()));

    let utf8 = DeterministicUtf8::new(0x5eed, 128, 192).collect::<Vec<_>>();
    assert_eq!(utf8.len(), 128);
    assert!(utf8.iter().all(|text| text.len() <= 192));
}

#[test]
fn process_capable_profile_requires_and_accepts_a_typed_helper_contract() {
    let executable = std::path::PathBuf::from(env!("CARGO_BIN_EXE_hell-test-helper"));
    let missing = DifferentialCase {
        source: Arc::from("--version"),
        environment_profile: EnvironmentProfile::ProcessCapable,
        ..DifferentialCase::default()
    };
    let error = differential(&executable, &executable, &missing)
        .expect_err("missing typed helper directory must fail closed");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);

    let helper_directory =
        std::env::temp_dir().join(format!("hell-process-capable-{}", std::process::id()));
    std::fs::create_dir_all(&helper_directory).unwrap();
    let case = DifferentialCase {
        source: Arc::from("--version"),
        environment_profile: EnvironmentProfile::ProcessCapable,
        process_helper_directory: Some(helper_directory.clone()),
        ..DifferentialCase::default()
    };
    let report = differential(&executable, &executable, &case).unwrap();
    assert!(report.agrees());
    std::fs::remove_dir(helper_directory).unwrap();
}

#[test]
fn wrong_digest_is_rejected_before_executable_is_invoked() {
    let helper = std::path::Path::new(env!("CARGO_BIN_EXE_hell-test-helper"));
    let copied = std::env::temp_dir().join(format!("must-not-run-{}", std::process::id()));
    let mut marker = copied.as_os_str().to_os_string();
    marker.push(".invoked");
    let marker = std::path::PathBuf::from(marker);
    let _ = std::fs::remove_file(&copied);
    let _ = std::fs::remove_file(&marker);
    std::fs::copy(helper, &copied).expect("copy helper executable");
    let result = verify_executable(
        &copied,
        ExecutableRole::Oracle,
        Some(Digest([0; 32])),
        "hell-test-helper-1",
    );
    assert!(result.is_err());
    assert!(!marker.exists(), "wrong-digest executable was invoked");
    std::fs::remove_file(copied).expect("remove copied helper");
}

#[test]
fn identical_processes_pass_the_isolated_differential_gate() {
    let executable = std::path::PathBuf::from(env!("CARGO_BIN_EXE_hell-test-helper"));
    let case = DifferentialCase {
        source: Arc::from("--version"),
        timeout: Duration::from_secs(2),
        ..DifferentialCase::default()
    };
    let report = differential(&executable, &executable, &case).expect("run isolated processes");
    assert!(report.agrees(), "unexpected mismatch: {report:#?}");
    assert!(!report.oracle.timed_out);
}

#[test]
fn release_gate_requires_volume_and_explanations() {
    let mismatch = DifferentialMismatch {
        kind: MismatchKind::Stdout,
        oracle: b"oracle".to_vec(),
        candidate: b"candidate".to_vec(),
    };
    let unexplained = ClassifiedMismatch {
        mismatch: mismatch.clone(),
        classification: None,
        explanation: Arc::from(""),
    };
    assert!(!release_gate(99, 100, &[]).passed());
    assert!(!release_gate(100, 100, &[unexplained]).passed());

    let explained = ClassifiedMismatch {
        mismatch: mismatch.clone(),
        classification: Some(DivergenceClass::DeliberateDivergence),
        explanation: Arc::from("reviewed compatibility boundary"),
    };
    assert!(release_gate(100, 100, &[explained]).passed());

    let rust_bug = ClassifiedMismatch {
        mismatch,
        classification: Some(DivergenceClass::RustBug),
        explanation: Arc::from("confirmed candidate defect"),
    };
    let report = release_gate(100, 100, &[rust_bug]);
    assert_eq!(report.rust_bug_mismatches, 1);
    assert!(!report.passed());
}

#[test]
fn pending_review_blocks_promotion_without_failing_collection() {
    let report = hell_testkit::evaluate_release_gate(
        &hell_testkit::ReleaseGateInput {
            differential_observations: 1_024,
            candidate_stress_cases: 1_024,
            harness_failures: 0,
            unexpected_timeouts: 0,
            mismatches: &[],
            stale_exact_claims: 0,
            missing_evidence_references: 2_840,
            required_platform_skips: 2,
            leaked_resources: 0,
            dependency_failures: 0,
        },
        1_024,
    );
    assert!(report.collection_passed());
    assert!(!report.promotion_ready());
    assert!(
        !report.passed(),
        "the promotion gate must remain fail-closed"
    );
}
