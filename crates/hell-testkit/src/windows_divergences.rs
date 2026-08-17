//! Exact reviewed Windows process-lifecycle divergence authority.
//!
//! These records deliberately do not normalize ordinary output.  They retain
//! both sides and admit only a complete, exact mismatch fingerprint when the
//! pinned native oracle has a reviewed Windows process-lifecycle divergence.

use super::{DifferentialComparisonProjection, DifferentialMismatch, Digest, MismatchKind};

#[cfg(windows)]
use super::DifferentialCase;

#[cfg(windows)]
use hell_builtins::ClaimPlatform;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WindowsDivergenceAuthority {
    pub(crate) case_id: &'static str,
    pub(crate) builtin: &'static str,
    pub(crate) mismatch_sha256: &'static str,
    pub(crate) mismatch_kinds: &'static [MismatchKind],
    pub(crate) rationale: &'static str,
}

const WINDOWS_DIVERGENCE_AUTHORITIES: &[WindowsDivergenceAuthority] = &[
    WindowsDivergenceAuthority {
        case_id: "runtime-typed-thread-delay-forced-argument-failure",
        builtin: "Concurrent.threadDelay",
        mismatch_sha256: "9ea41783a7bd7d7505b62fc603c027d547f0b2590459baa688a68c1ed51afa48",
        mismatch_kinds: &[MismatchKind::Timeout, MismatchKind::Stderr],
        rationale: concat!(
            "The pinned GHC 9.8.2 Windows oracle renders the same ErrorCall, ",
            "but its process remains past the reviewed five-second deadline; the ",
            "candidate preserves the reviewed prompt failure lifecycle.",
        ),
    },
    WindowsDivergenceAuthority {
        case_id: "runtime-interaction-timeout-process",
        builtin: "Timeout.timeout",
        mismatch_sha256: "536f5d413d57fb66294475eae66f1bd0222d79a5f69e240d1c6fec095812481e",
        mismatch_kinds: &[MismatchKind::Timeout, MismatchKind::ExitStatus],
        rationale: concat!(
            "The pinned Windows System.Timeout cannot interrupt the blocking ",
            "typed-process wait before the sleeping child exits, while candidate ",
            "cancellation terminates the complete descendant tree as required by ",
            "its retained regression.",
        ),
    },
];

pub(crate) fn retained_authority(
    case_id: &str,
    builtin: &str,
    mismatch_sha256: &str,
) -> Option<&'static WindowsDivergenceAuthority> {
    let authority = WINDOWS_DIVERGENCE_AUTHORITIES.iter().find(|authority| {
        authority.case_id == case_id
            && authority.builtin == builtin
            && authority.mismatch_sha256 == mismatch_sha256
    })?;
    Some(authority)
}

pub(crate) fn retained_windows_divergence_projection(
    case_id: &str,
    mismatches: &[DifferentialMismatch],
) -> Option<DifferentialComparisonProjection> {
    let authority = WINDOWS_DIVERGENCE_AUTHORITIES
        .iter()
        .find(|authority| authority.case_id == case_id)?;
    let observed_kinds = mismatches
        .iter()
        .map(|mismatch| mismatch.kind)
        .collect::<Vec<_>>();
    if observed_kinds != authority.mismatch_kinds
        || differential_mismatch_fingerprint(case_id, mismatches).hex() != authority.mismatch_sha256
    {
        return None;
    }
    Some(
        DifferentialComparisonProjection::ReviewedWindowsDivergence {
            case_id: authority.case_id,
            builtin: authority.builtin,
            mismatch_sha256: differential_mismatch_fingerprint(case_id, mismatches),
            mismatch_kinds: authority.mismatch_kinds,
            rationale: authority.rationale,
        },
    )
}

#[cfg(windows)]
fn observations_are_bound(
    case: &DifferentialCase,
    oracle: &super::Observation,
    candidate: &super::Observation,
) -> bool {
    oracle.identity.role == super::ExecutableRole::Oracle
        && candidate.identity.role == super::ExecutableRole::Candidate
        && oracle.case_id == case.id
        && candidate.case_id == case.id
        && oracle.environment_profile == case.environment_profile
        && candidate.environment_profile == case.environment_profile
        && oracle.process_helper_sha256 == case.process_helper_sha256
        && candidate.process_helper_sha256 == case.process_helper_sha256
        && oracle.harness_normalizers == super::applied_harness_normalizers()
        && candidate.harness_normalizers == super::applied_harness_normalizers()
        && oracle.claim_normalizers == super::applied_claim_normalizers(case)
        && candidate.claim_normalizers == super::applied_claim_normalizers(case)
        && oracle.mode == candidate.mode
}

#[cfg(windows)]
pub(crate) fn reviewed_windows_divergence_projection(
    platform: ClaimPlatform,
    case: &DifferentialCase,
    oracle: &super::Observation,
    candidate: &super::Observation,
    mismatches: &[DifferentialMismatch],
) -> Option<DifferentialComparisonProjection> {
    if platform != ClaimPlatform::Windows
        || case.mode != super::DifferentialMode::Run
        || !observations_are_bound(case, oracle, candidate)
    {
        return None;
    }
    let authority = WINDOWS_DIVERGENCE_AUTHORITIES
        .iter()
        .find(|authority| authority.case_id == case.id.as_ref())?;
    let projection = retained_windows_divergence_projection(case.id.as_ref(), mismatches)?;
    if !case.claim_evidence.as_ref().is_some_and(|descriptor| {
        descriptor.semantic_targets.iter().any(|target| {
            target.builtin.as_ref() == authority.builtin
                && target
                    .platforms
                    .iter()
                    .any(|platform| *platform == ClaimPlatform::Windows)
        })
    }) || oracle.timed_out == candidate.timed_out
        || oracle.status.success
        || !candidate.semantic.is_some()
        || !super::applied_claim_normalizers(case).is_empty()
    {
        return None;
    }
    Some(projection)
}

fn differential_mismatch_fingerprint(case_id: &str, mismatches: &[DifferentialMismatch]) -> Digest {
    super::sha256_bytes(differential_mismatch_fingerprint_document(case_id, mismatches).as_bytes())
}

fn differential_mismatch_fingerprint_document(
    case_id: &str,
    mismatches: &[DifferentialMismatch],
) -> String {
    let mut summary = String::from("{\n  \"schemaVersion\": 1,\n  \"mismatches\": [");
    for (index, mismatch) in mismatches.iter().enumerate() {
        if index != 0 {
            summary.push_str(", ");
        }
        summary.push_str("{\"category\": ");
        super::artifact::push_json_string(&mut summary, mismatch_kind_name(mismatch.kind));
        summary.push_str(", \"oracleSha256\": ");
        super::artifact::push_json_string(
            &mut summary,
            &super::sha256_bytes(&mismatch.oracle).hex(),
        );
        summary.push_str(", \"candidateSha256\": ");
        super::artifact::push_json_string(
            &mut summary,
            &super::sha256_bytes(&mismatch.candidate).hex(),
        );
        summary.push('}');
    }
    summary.push_str("]\n}\n");

    let mut document = String::from("{\n  \"schemaVersion\": 1,\n  \"caseId\": ");
    super::artifact::push_json_string(&mut document, case_id);
    document.push_str(",\n  \"normalizers\": [],\n  \"raw\": ");
    super::artifact::push_json_string(
        &mut document,
        &super::sha256_bytes(summary.as_bytes()).hex(),
    );
    document.push_str(",\n  \"normalized\": ");
    super::artifact::push_json_string(
        &mut document,
        &super::sha256_bytes(summary.as_bytes()).hex(),
    );
    document.push_str("\n}\n");
    document
}

fn mismatch_kind_name(kind: MismatchKind) -> &'static str {
    match kind {
        MismatchKind::Timeout => "timeout",
        MismatchKind::ExitStatus => "exit-status",
        MismatchKind::Stdout => "stdout",
        MismatchKind::Stderr => "stderr",
        MismatchKind::Diagnostic => "diagnostic",
        MismatchKind::Filesystem => "filesystem",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mismatch(kind: MismatchKind, oracle: &[u8], candidate: &[u8]) -> DifferentialMismatch {
        DifferentialMismatch {
            kind,
            oracle: oracle.to_vec(),
            candidate: candidate.to_vec(),
        }
    }

    #[test]
    fn windows_divergence_fingerprints_bind_the_hosted_artifact_exactly() {
        let thread_delay = vec![
            mismatch(MismatchKind::Timeout, &[1], &[0]),
            mismatch(
                MismatchKind::Stderr,
                b"hell.exe: reviewed delay failure\r\nCallStack (from HasCallStack):\r\n  error, called at src\\Hell.hs:1953:4 in main:Main\r\n",
                b"hell: reviewed delay failure\nCallStack (from HasCallStack):\n  error, called at src/Hell.hs:1953:4 in main:Main\n",
            ),
        ];
        let timeout_process = vec![
            mismatch(MismatchKind::Timeout, &[1], &[0]),
            mismatch(
                MismatchKind::ExitStatus,
                b"ProcessStatus { success: false, code: Some(1) }",
                b"ProcessStatus { success: true, code: Some(0) }",
            ),
        ];
        let observed = [
            (
                "runtime-typed-thread-delay-forced-argument-failure",
                thread_delay,
            ),
            ("runtime-interaction-timeout-process", timeout_process),
        ];
        for (authority, (case_id, mismatches)) in
            WINDOWS_DIVERGENCE_AUTHORITIES.iter().zip(observed)
        {
            let document = differential_mismatch_fingerprint_document(case_id, &mismatches);
            let fingerprint = differential_mismatch_fingerprint(case_id, &mismatches);
            assert_eq!(fingerprint.hex(), authority.mismatch_sha256, "{document}");
        }
    }

    #[test]
    fn each_windows_divergence_has_a_distinct_complete_review() {
        let mut case_ids = Vec::new();
        for authority in WINDOWS_DIVERGENCE_AUTHORITIES {
            assert!(!authority.rationale.is_empty());
            assert!(!authority.mismatch_kinds.is_empty());
            assert!(authority.mismatch_sha256.len().is_multiple_of(2));
            case_ids.push(authority.case_id);
        }
        case_ids.sort_unstable();
        case_ids.dedup();
        assert_eq!(case_ids.len(), WINDOWS_DIVERGENCE_AUTHORITIES.len());
    }
}
