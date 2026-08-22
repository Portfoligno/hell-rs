use std::path::PathBuf;
use std::sync::Arc;

use hell_builtins::NormalizerId;
use hell_testkit::{
    BoundedCapture, DifferentialMode, ExecutableIdentity, ExecutableRole, Observation,
    ProcessStatus, RuntimeFailureOraclePayloadSelection, RuntimeFailurePayloadRelationship,
    committed_differential_cases, runtime_failure_payload_diagnostic, sha256_bytes,
};

fn observation(
    case: &hell_testkit::DifferentialCase,
    role: ExecutableRole,
    stderr: &[u8],
) -> Observation {
    Observation {
        identity: ExecutableIdentity {
            path: PathBuf::from(match role {
                ExecutableRole::Oracle => "/oracle/hell",
                ExecutableRole::Candidate => "/candidate/hell",
            }),
            sha256: sha256_bytes(match role {
                ExecutableRole::Oracle => b"oracle",
                ExecutableRole::Candidate => b"candidate",
            }),
            reported_version: Arc::from(hell_builtins::LANGUAGE_VERSION),
            build_info: None,
            role,
            assurance_epoch_sha256: Some(sha256_bytes(b"epoch")),
            acquisition_receipt_id: None,
            acquisition_receipt_sha256: None,
            acquisition_attestation_sha256: None,
        },
        case_id: Arc::clone(&case.id),
        environment_profile: case.environment_profile,
        process_helper_sha256: case.process_helper_sha256,
        mode: DifferentialMode::Run,
        status: ProcessStatus {
            success: false,
            code: Some(1),
        },
        stdout: BoundedCapture::from_bytes(Vec::new()),
        raw_stderr: BoundedCapture::from_bytes(stderr.to_vec()),
        claim_input_stderr: BoundedCapture::from_bytes(stderr.to_vec()),
        stderr: BoundedCapture::from_bytes(stderr.to_vec()),
        normalizer_sandbox: PathBuf::from("/sandbox"),
        normalizer_script: PathBuf::from("/sandbox/main.hell"),
        timed_out: false,
        diagnostic: None,
        filesystem: Vec::new(),
        harness_normalizers: vec![NormalizerId::DiagnosticSandboxPathV1],
        claim_normalizers: Vec::new(),
        resource_audit: None,
        semantic: None,
    }
}

fn reviewed_copy_file_observation(
    case: &hell_testkit::DifferentialCase,
    role: ExecutableRole,
    stderr: &[u8],
    semantic: Option<hell_testkit::SemanticObservation>,
) -> Observation {
    let mut observation = observation(case, role, stderr);
    observation.resource_audit = Some(hell_testkit::ResourceAudit::default());
    observation.semantic = semantic;
    observation
}

#[test]
fn copy_file_payload_mismatch_reports_bounded_outer_handling_and_candidate_components() {
    let case = committed_differential_cases()
        .into_iter()
        .find(|case| case.id.as_ref() == "runtime-directory-copy-file-failure")
        .expect("committed Directory.copyFile failure case");
    let outer = "missing/source.txt: copyFile:outer-detail";
    let handling = "missing/source.txt: outer-detail";
    let oracle_stderr = format!(
        concat!(
            "hell: Uncaught exception ",
            "ghc-internal:GHC.Internal.IO.Exception.IOException:\n\n",
            "{outer}\n\nWhile handling {handling}\n\n",
        ),
        outer = outer,
        handling = handling,
    );
    let candidate_payload = "missing/source.txt: copyFile:candidate-detail";
    let candidate_stderr = format!("hell: {candidate_payload}\n");
    let oracle = observation(&case, ExecutableRole::Oracle, oracle_stderr.as_bytes());
    let candidate = observation(
        &case,
        ExecutableRole::Candidate,
        candidate_stderr.as_bytes(),
    );

    let diagnostic = runtime_failure_payload_diagnostic(&case, &oracle, &candidate)
        .expect("valid distinct payloads must retain bounded diagnostic components");
    assert_eq!(
        diagnostic.mismatch_field,
        "oracle-selected-payload-vs-candidate-payload"
    );
    assert_eq!(diagnostic.handling_projection, "after-path-prefix");
    assert_eq!(
        diagnostic.oracle_selection,
        RuntimeFailureOraclePayloadSelection::Outer
    );
    assert_eq!(
        diagnostic.relationship,
        RuntimeFailurePayloadRelationship::Distinct
    );
    assert_eq!(diagnostic.oracle_outer.utf8_prefix, outer);
    assert_eq!(
        diagnostic
            .oracle_handling
            .as_ref()
            .expect("handling component")
            .utf8_prefix,
        handling
    );
    assert_eq!(diagnostic.oracle_selected, diagnostic.oracle_outer);
    assert_eq!(diagnostic.candidate.utf8_prefix, candidate_payload);
    assert!(!diagnostic.oracle_outer.prefix_truncated);
    assert!(!diagnostic.candidate.prefix_truncated);

    let malformed_oracle = observation(
        &case,
        ExecutableRole::Oracle,
        oracle_stderr
            .replace(handling, "substituted/handling")
            .as_bytes(),
    );
    assert!(runtime_failure_payload_diagnostic(&case, &malformed_oracle, &candidate).is_none());
}

#[test]
fn linux_copy_file_payload_projects_exact_oracle_leaf_and_rejects_near_miss() {
    use hell_testkit::{
        CoverageEvent, DifferentialComparisonProjection, LogicalTraceEvent,
        RuntimeFailureProjectionRejectionReason, SemanticObservation, compare_case_observations,
        runtime_failure_projection_rejection,
    };

    let case = committed_differential_cases()
        .into_iter()
        .find(|case| case.id.as_ref() == "runtime-directory-copy-file-failure")
        .expect("committed Directory.copyFile failure case");
    let builtin = hell_builtins::lookup("Directory.copyFile")
        .expect("Directory.copyFile builtin")
        .id;
    let semantic = SemanticObservation {
        coverage: vec![CoverageEvent::EnteredAdapter(builtin)],
        effect_trace: ["started", "failed"]
            .into_iter()
            .map(|effect| LogicalTraceEvent::HostEffect {
                builtin,
                owner_task: None,
                sequence: 1,
                parent_sequence: None,
                effect: Arc::from(effect),
            })
            .collect(),
        ..SemanticObservation::default()
    };
    let outer = concat!(
        "missing/source.txt: copyFile:atomicCopyFileContents:withReplacementFile:",
        "copyFileToHandle:openFileWithCloseOnExec: does not exist ",
        "(No such file or directory)",
    );
    let handling = concat!(
        "missing/source.txt: atomicCopyFileContents:withReplacementFile:",
        "copyFileToHandle:openFileWithCloseOnExec: does not exist ",
        "(No such file or directory)",
    );
    let oracle_stderr = format!(
        concat!(
            "hell: Uncaught exception ",
            "ghc-internal:GHC.Internal.IO.Exception.IOException:\n\n",
            "{outer}\n\nWhile handling {handling}\n\n",
        ),
        outer = outer,
        handling = handling,
    );
    let candidate_stderr = format!("hell: {outer}\n");
    assert_eq!(
        sha256_bytes(outer.as_bytes()).hex(),
        "3b7f1b0efca4e9b501f40dad6586ecc5759bc0743866be2f6a289ac7325ad777"
    );
    let oracle = reviewed_copy_file_observation(
        &case,
        ExecutableRole::Oracle,
        oracle_stderr.as_bytes(),
        None,
    );
    let candidate = reviewed_copy_file_observation(
        &case,
        ExecutableRole::Candidate,
        candidate_stderr.as_bytes(),
        Some(semantic),
    );

    let (projection, mismatches) = compare_case_observations(&case, &oracle, &candidate);
    assert_eq!(
        projection,
        DifferentialComparisonProjection::ReviewedRuntimeFailureExceptionStderr {
            exception_family: hell_testkit::RuntimeFailureExceptionFamily::IOException,
            payload_sha256: sha256_bytes(outer.as_bytes()),
            oracle_sha256: oracle.stderr.sha256,
            candidate_sha256: candidate.stderr.sha256,
            oracle_bytes: oracle.stderr.total_bytes,
            candidate_bytes: candidate.stderr.total_bytes,
        }
    );
    assert!(mismatches.is_empty());

    let mut near_miss = candidate.clone();
    near_miss.stderr = BoundedCapture::from_bytes(
        candidate_stderr
            .replace("openFileWithCloseOnExec", "openFdAt")
            .into_bytes(),
    );
    let (projection, mismatches) = compare_case_observations(&case, &oracle, &near_miss);
    assert_eq!(projection, DifferentialComparisonProjection::Exact);
    assert_eq!(mismatches.len(), 1);
    assert_eq!(
        runtime_failure_projection_rejection(&case, &oracle, &near_miss)
            .expect("near-miss payload rejection")
            .reason,
        RuntimeFailureProjectionRejectionReason::PayloadMismatch,
    );
}
