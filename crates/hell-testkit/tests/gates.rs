use std::sync::Arc;
use std::time::Duration;

use hell_testkit::{
    ClassifiedMismatch, DeterministicBytes, DeterministicUtf8, DifferentialCase,
    DifferentialMismatch, DifferentialMode, Digest, DivergenceClass, EnvironmentProfile,
    ExecutableRole, MismatchKind, OutputNormalization, committed_differential_cases, differential,
    differential_batch_with_identities, differential_inventory_sha256, inspect_executable,
    release_gate, representative_differential_sample, verify_executable,
};

#[test]
fn differential_inventory_digest_binds_every_semantic_case_field() {
    let first = DifferentialCase {
        id: Arc::from("first"),
        source: Arc::from("Main.main = 1"),
        arguments: vec!["--first".into()],
        environment: vec![("FIRST".into(), "one".into())],
        stdin: b"input".to_vec(),
        timeout: Duration::from_millis(123),
        normalization: OutputNormalization {
            stderr_replacements: vec![(b"left".to_vec(), b"right".to_vec())],
            normalize_path_separators: true,
        },
        environment_profile: EnvironmentProfile::Minimal,
        mode: DifferentialMode::Check,
        expected_runtime_completion: false,
        ..DifferentialCase::default()
    };
    let second = DifferentialCase {
        id: Arc::from("second"),
        source: Arc::from("Main.main = 2"),
        ..DifferentialCase::default()
    };
    let digest = differential_inventory_sha256(&[first.clone(), second.clone()]).unwrap();
    assert_eq!(
        digest,
        differential_inventory_sha256(&[first.clone(), second.clone()]).unwrap()
    );
    assert_ne!(
        digest,
        differential_inventory_sha256(&[second.clone(), first.clone()]).unwrap()
    );
    let baseline = differential_inventory_sha256(std::slice::from_ref(&first)).unwrap();
    let assert_mutation = |mutated: DifferentialCase| {
        assert_ne!(baseline, differential_inventory_sha256(&[mutated]).unwrap());
    };
    let mut mutated = first.clone();
    mutated.id = Arc::from("mutated");
    assert_mutation(mutated);
    let mut mutated = first.clone();
    mutated.source = Arc::from("Main.main = 3");
    assert_mutation(mutated);
    let mut mutated = first.clone();
    mutated.arguments.push("--second".into());
    assert_mutation(mutated);
    let mut mutated = first.clone();
    mutated.environment.push(("SECOND".into(), "two".into()));
    assert_mutation(mutated);
    let mut mutated = first.clone();
    mutated.stdin.push(b'!');
    assert_mutation(mutated);
    let mut mutated = first.clone();
    mutated.timeout += Duration::from_nanos(1);
    assert_mutation(mutated);
    let mut mutated = first.clone();
    mutated.normalization.stderr_replacements[0].1.push(b'!');
    assert_mutation(mutated);
    let mut mutated = first.clone();
    mutated.normalization.normalize_path_separators = false;
    assert_mutation(mutated);
    let mut mutated = first.clone();
    mutated.environment_profile = EnvironmentProfile::Explicit;
    assert_mutation(mutated);
    let mut mutated = first.clone();
    mutated.mode = DifferentialMode::Run;
    assert_mutation(mutated);
    let mut mutated = first.clone();
    mutated.expected_runtime_completion = true;
    assert_mutation(mutated);

    let mut descriptor_case = committed_differential_cases()
        .into_iter()
        .find(|case| case.claim_evidence.is_some())
        .unwrap();
    let descriptor_digest =
        differential_inventory_sha256(std::slice::from_ref(&descriptor_case)).unwrap();
    descriptor_case
        .claim_evidence
        .as_mut()
        .unwrap()
        .review_statement = Arc::from("mutated review");
    assert_ne!(
        descriptor_digest,
        differential_inventory_sha256(&[descriptor_case]).unwrap()
    );

    let mut logical_helper = first;
    logical_helper.environment_profile = EnvironmentProfile::ProcessCapable;
    logical_helper.process_helper_directory = Some("/ephemeral/one".into());
    logical_helper.process_helper_sha256 = Some(Digest([1; 32]));
    let helper_digest =
        differential_inventory_sha256(std::slice::from_ref(&logical_helper)).unwrap();
    logical_helper.process_helper_directory = Some("/ephemeral/two".into());
    logical_helper.process_helper_sha256 = Some(Digest([2; 32]));
    assert_eq!(
        helper_digest,
        differential_inventory_sha256(&[logical_helper]).unwrap(),
        "the logical helper role is inventory-bound while its executable is separately identity-bound"
    );
}

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
fn missing_candidate_audit_preserves_child_status_and_stderr() {
    let executable = std::path::PathBuf::from(env!("CARGO_BIN_EXE_hell-test-helper"));
    let case = DifferentialCase {
        source: Arc::from("fail-before-audit"),
        timeout: Duration::from_secs(2),
        ..DifferentialCase::default()
    };
    let error = differential(&executable, &executable, &case)
        .expect_err("candidate fixture must omit its audit");
    let message = error.to_string();
    assert!(message.contains("after status Some(2), timed out false"));
    assert!(message.contains("child stderr: fixture failed before retaining audit"));
}

#[test]
fn bounded_differential_batch_retains_order_timing_and_cleanup() {
    let executable = std::path::Path::new(env!("CARGO_BIN_EXE_hell-test-helper"));
    let oracle = inspect_executable(executable, ExecutableRole::Oracle).unwrap();
    let candidate = inspect_executable(executable, ExecutableRole::Candidate).unwrap();
    let cases = ["batch-order-a", "batch-order-b", "batch-order-c"].map(|id| DifferentialCase {
        id: Arc::from(id),
        source: Arc::from("ordinary-fixture"),
        timeout: Duration::from_secs(2),
        ..DifferentialCase::default()
    });
    let batch = differential_batch_with_identities(&oracle, &candidate, &cases, 2).unwrap();
    assert_eq!(batch.timing.case_count, cases.len());
    assert_eq!(batch.timing.completed_count, cases.len());
    assert_eq!(batch.timing.worker_count, 2);
    assert!(batch.timing.wall > Duration::ZERO);
    assert!(batch.timing.oracle_process_sum > Duration::ZERO);
    assert!(batch.timing.candidate_process_sum > Duration::ZERO);
    assert_eq!(
        batch
            .reports
            .iter()
            .map(|report| report.oracle.case_id.as_ref())
            .collect::<Vec<_>>(),
        ["batch-order-a", "batch-order-b", "batch-order-c"]
    );
    for report in &batch.reports {
        assert!(!report.oracle.normalizer_sandbox.exists());
        assert!(!report.candidate.normalizer_sandbox.exists());
        assert_eq!(report.oracle.identity, oracle);
        assert_eq!(report.candidate.identity, candidate);
    }
}

#[test]
fn bounded_differential_batch_reports_lowest_authoritative_failure() {
    let executable = std::path::Path::new(env!("CARGO_BIN_EXE_hell-test-helper"));
    let oracle = inspect_executable(executable, ExecutableRole::Oracle).unwrap();
    let candidate = inspect_executable(executable, ExecutableRole::Candidate).unwrap();
    let cases = [
        DifferentialCase {
            id: Arc::from("slow-low-index"),
            source: Arc::from("fail-before-audit-slow"),
            timeout: Duration::from_secs(2),
            ..DifferentialCase::default()
        },
        DifferentialCase {
            id: Arc::from("fast-high-index"),
            source: Arc::from("fail-before-audit"),
            timeout: Duration::from_secs(2),
            ..DifferentialCase::default()
        },
    ];
    let failure = differential_batch_with_identities(&oracle, &candidate, &cases, 2)
        .expect_err("both cases fail after the higher index finishes first");
    assert_eq!(failure.case_index, Some(0));
    assert_eq!(failure.case_id.as_deref(), Some("slow-low-index"));
    assert!(failure.detail.contains("status Some(2), timed out false"));
}

#[test]
fn differential_batch_rejects_workers_above_the_fixed_cap() {
    let executable = std::path::Path::new(env!("CARGO_BIN_EXE_hell-test-helper"));
    let oracle = inspect_executable(executable, ExecutableRole::Oracle).unwrap();
    let candidate = inspect_executable(executable, ExecutableRole::Candidate).unwrap();
    let failure =
        differential_batch_with_identities(&oracle, &candidate, &[DifferentialCase::default()], 5)
            .expect_err("five workers exceed the fixed cap on every host");
    assert_eq!(failure.case_index, None);
    assert!(failure.detail.contains("exceeds exact bound"));
}

#[test]
fn representative_differential_sample_is_bounded_ordered_and_deterministic() {
    let authoritative = hell_testkit::committed_differential_cases();
    assert!(representative_differential_sample(&authoritative, 31).is_err());
    assert!(representative_differential_sample(&authoritative, 257).is_err());
    let left = representative_differential_sample(&authoritative, 64).unwrap();
    let right = representative_differential_sample(&authoritative, 64).unwrap();
    assert_eq!(
        left.cases
            .iter()
            .map(|case| case.id.as_ref())
            .collect::<Vec<_>>(),
        right
            .cases
            .iter()
            .map(|case| case.id.as_ref())
            .collect::<Vec<_>>()
    );
    assert_eq!(left.inventory_count, authoritative.len());
    assert_eq!(left.inventory_sha256, right.inventory_sha256);
    assert_eq!(left.selected_indices, right.selected_indices);
    assert_eq!(left.cases.len(), 64);
    assert_eq!(left.selected_indices.first(), Some(&0));
    assert!(
        left.selected_indices
            .windows(2)
            .all(|indices| indices[0] < indices[1])
    );
    assert_eq!(
        left.selected_indices.last(),
        Some(&(authoritative.len() - 1))
    );
    assert_eq!(
        left.cases.first().unwrap().id,
        authoritative.first().unwrap().id
    );
    assert_eq!(
        left.cases.last().unwrap().id,
        authoritative.last().unwrap().id
    );
    assert!(
        left.selected_indices
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    );
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
