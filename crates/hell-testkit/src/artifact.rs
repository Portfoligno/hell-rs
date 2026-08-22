//! Durable, structured differential evidence and mismatch replay bundles.

use std::ffi::OsStr;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::{
    BoundedCapture, CaseReviewState, CausalSignal, ClaimEvidenceDescriptor,
    CollectionBlackBoxShard, CollectionBundleFacts, CollectionCompletion,
    CollectionSourceAuthority, CollectionVerifiedProviderRoot, CoverageEvent, DifferentialCase,
    DifferentialMode, DifferentialReport, Digest, EvidenceTarget, EvidenceTargetV2,
    ExecutableIdentity, LogicalTraceEvent, NormalizerId, Observation,
    PresentationShadowNormalizerId, ResourceAudit, RuntimePlatformShard, RuntimePlatformTarget,
    VerifiedProfileObservation, applied_claim_normalizers, applied_harness_normalizers,
    normalized_presentation_shadow_sha256, raw_presentation_sha256, sha256_bytes, sha256_file,
};

type RetainedSemanticBoundary = (
    hell_builtins::BuiltinId,
    u16,
    String,
    String,
    Option<String>,
);

/// Identity facts rederived from one retained explicit-profile observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetainedVerifiedProfileFacts {
    pub profile: hell_builtins::ExecutionProfile,
    pub executable_sha256: Digest,
    pub source_sha256: Digest,
    pub execution_input_sha256: Digest,
    pub invocation_sha256: Digest,
    pub observation_sha256: Digest,
    pub package_sha256: Digest,
}

/// Hashes the exact canonical execution-input document for one differential
/// case without executing either subject.
///
/// # Errors
///
/// Returns an error when an argument or environment value is noncanonical.
pub fn case_execution_input_sha256(case: &DifferentialCase) -> std::io::Result<Digest> {
    Ok(sha256_bytes(execution_input_json(case)?.as_bytes()))
}

/// Hashes the complete canonical committed-case descriptor without executing it.
#[must_use]
pub fn case_descriptor_sha256(case: &DifferentialCase) -> Digest {
    sha256_bytes(case_descriptor(case).as_bytes())
}

/// Encodes the exact bounded comparison observation consumed by trusted
/// release-conformance derivation.
///
/// # Errors
///
/// Returns an error rather than serializing truncated captures, timeouts, or
/// process states that cannot be represented without information loss.
pub fn canonical_conformance_observation_json(
    observation: &Observation,
) -> std::io::Result<Vec<u8>> {
    if observation.stdout.truncated || observation.stderr.truncated {
        return Err(std::io::Error::other(
            "conformance observation capture is truncated",
        ));
    }
    let stdout = observation
        .stdout
        .complete
        .as_deref()
        .ok_or_else(|| std::io::Error::other("conformance stdout is incomplete"))?;
    let stderr = observation
        .stderr
        .complete
        .as_deref()
        .ok_or_else(|| std::io::Error::other("conformance stderr is incomplete"))?;
    let raw_stderr = observation
        .raw_stderr
        .complete
        .as_deref()
        .ok_or_else(|| std::io::Error::other("conformance raw stderr is incomplete"))?;
    if observation.filesystem.iter().any(|entry| entry.truncated) {
        return Err(std::io::Error::other(
            "conformance filesystem observation is truncated",
        ));
    }
    let executable = observation
        .identity
        .path
        .to_str()
        .ok_or_else(|| std::io::Error::other("normalizer executable path is not UTF-8"))?;
    let mut output = String::from("{\"diagnostic\":");
    push_json_string(&mut output, &format!("{:?}", observation.diagnostic));
    output.push_str(",\"exit\":{");
    match observation.status.code {
        Some(code) if code >= 0 => {
            output.push_str("\"kind\":\"code\",\"value\":");
            write!(output, "{code}").expect("writing to String cannot fail");
        }
        Some(code) => {
            output.push_str("\"kind\":\"signal\",\"value\":");
            push_json_string(&mut output, &format!("platform-status-{code}"));
        }
        None => {
            output.push_str("\"kind\":\"signal\",\"value\":\"unknown-signal\"");
        }
    }
    output.push_str("},\"filesystem\":");
    push_json_string(&mut output, &format!("{:?}", observation.filesystem));
    output.push_str(",\"mode\":");
    push_json_string(&mut output, &format!("{:?}", observation.mode));
    output.push_str(",\"normalizerContext\":{\"executable\":");
    push_json_string(&mut output, executable);
    output.push_str(",\"sandbox\":");
    push_json_string(
        &mut output,
        observation.normalizer_sandbox.to_string_lossy().as_ref(),
    );
    output.push_str(",\"script\":");
    push_json_string(
        &mut output,
        observation.normalizer_script.to_string_lossy().as_ref(),
    );
    output.push('}');
    push_conformance_capture(&mut output, "rawStderr", raw_stderr);
    output.push_str(",\"resourceAudit\":");
    push_json_string(&mut output, &format!("{:?}", observation.resource_audit));
    output.push_str(",\"schemaVersion\":4,\"semanticTrace\":[");
    if observation.semantic.is_some() {
        push_json_string(&mut output, &conformance_semantic_document(observation)?);
    }
    output.push(']');
    output.push_str(",\"statusSuccess\":");
    output.push_str(if observation.status.success {
        "true"
    } else {
        "false"
    });
    push_conformance_capture(&mut output, "stderr", stderr);
    push_conformance_capture(&mut output, "stdout", stdout);
    output.push_str(",\"termination\":\"");
    output.push_str(if observation.timed_out {
        "timed-out"
    } else if observation.status.code.is_some_and(|code| code >= 0) {
        "exited"
    } else {
        "signaled"
    });
    output.push_str("\"}\n");
    if observation.timed_out {
        return Err(std::io::Error::other("conformance observation timed out"));
    }
    Ok(output.into_bytes())
}

/// Replays the exact production harness and reviewed claim-normalizer closure
/// over raw stderr retained by a conformance observation.
///
/// # Errors
///
/// Returns an error for an unauthorized/reordered closure or a non-idempotent
/// production normalizer pass.
pub fn replay_conformance_stderr(
    raw_stderr: &[u8],
    executable: &Path,
    sandbox: &Path,
    script: &Path,
    case: &DifferentialCase,
    normalizers: &[NormalizerId],
) -> std::io::Result<Vec<u8>> {
    if normalizers != applied_claim_normalizers(case) {
        return Err(std::io::Error::other(
            "conformance normalizer closure differs from the reviewed case",
        ));
    }
    let mut output = crate::diagnostic_sandbox_path_v1(raw_stderr, executable, sandbox, script);
    for (from, to) in &case.normalization.stderr_replacements {
        output = crate::replace_all(&output, from, to);
    }
    for normalizer in normalizers {
        let passes = crate::apply_retained_normalizer_twice(crate::RetainedNormalizerInput {
            normalizer: *normalizer,
            observation: &output,
            executable,
            sandbox,
            script,
        });
        if passes.first_pass != passes.second_pass {
            return Err(std::io::Error::other(
                "conformance normalizer is not idempotent",
            ));
        }
        output = passes.first_pass;
    }
    Ok(output)
}

fn conformance_semantic_document(observation: &Observation) -> std::io::Result<String> {
    let mut output = String::from("{\n  \"schemaVersion\": 1");
    push_semantic_json(&mut output, observation);
    output.push_str(",\n  \"semanticTypedResultHex\": ");
    if let Some(canonical) = observation
        .semantic
        .as_ref()
        .and_then(|semantic| semantic.typed_result_canonical.as_deref())
    {
        crate::validate_canonical_typed_value(canonical)?;
        push_json_string(&mut output, &crate::encode_callback_result(canonical));
    } else {
        output.push_str("null");
    }
    let stdout = observation
        .stdout
        .complete
        .as_deref()
        .ok_or_else(|| std::io::Error::other("conformance stdout is incomplete"))?;
    let raw_stderr = observation
        .raw_stderr
        .complete
        .as_deref()
        .ok_or_else(|| std::io::Error::other("conformance raw stderr is incomplete"))?;
    output.push_str(",\n  \"rawPresentationSha256\": \"");
    output.push_str(&raw_presentation_sha256(stdout, raw_stderr).hex());
    output.push('"');
    output.push_str(",\n  \"normalizedPresentationLineEndingsSha256\": ");
    match normalized_presentation_shadow_sha256(
        PresentationShadowNormalizerId::LineEndingsV1,
        stdout,
        raw_stderr,
    ) {
        Ok(digest) => {
            output.push('"');
            output.push_str(&digest.hex());
            output.push('"');
        }
        Err(_) => output.push_str("null"),
    }
    output.push_str(",\n  \"resourceAuditFailures\": ");
    write!(
        output,
        "{}",
        observation
            .resource_audit
            .as_ref()
            .map_or(usize::MAX, ResourceAudit::failure_count)
    )
    .expect("writing to String cannot fail");
    push_status_json(&mut output, observation);
    output.push_str("\n}\n");
    Ok(output)
}

/// Replays one exact reviewed runtime obligation from the canonical
/// semantic document retained inside a release-conformance observation.
///
/// The document contains raw typed trace facts, not a producer verdict.  This
/// function reparses those facts, validates their causal structure and exact
/// descriptor expectations, and then runs the same obligation-specific
/// validator used by retained differential bundles.
///
/// # Errors
///
/// Returns an error for an unknown/ambiguous target, malformed or forged
/// semantic facts, a descriptor mismatch, or an obligation without a trusted
/// in-memory validator.
#[allow(clippy::too_many_lines)]
pub fn validate_conformance_semantic_obligation(
    document: &str,
    case: &DifferentialCase,
    builtin_name: &str,
    dimension: hell_builtins::CompatibilityDimension,
    obligation: &str,
) -> std::io::Result<()> {
    validate_conformance_semantic_document_shape(document)?;
    let descriptor = case
        .claim_evidence
        .as_ref()
        .ok_or_else(|| std::io::Error::other("conformance case has no reviewed descriptor"))?;
    crate::validate_case_descriptor(case, descriptor).map_err(std::io::Error::other)?;
    crate::validate_legacy_targets(case, descriptor).map_err(std::io::Error::other)?;
    crate::validate_semantic_targets(case, descriptor).map_err(std::io::Error::other)?;
    crate::validate_callback_contracts(case, descriptor).map_err(std::io::Error::other)?;
    let mut targets = descriptor.semantic_targets.iter().filter(|target| {
        target.builtin.as_ref() == builtin_name
            && target.dimension == dimension
            && target
                .obligations
                .iter()
                .any(|value| value.0.as_ref() == obligation)
    });
    let target = targets.next().ok_or_else(|| {
        std::io::Error::other("reviewed descriptor does not authorize the exact obligation")
    })?;
    if targets.next().is_some() {
        return Err(std::io::Error::other(
            "reviewed descriptor ambiguously authorizes the obligation",
        ));
    }
    let builtin = hell_builtins::lookup(builtin_name)
        .ok_or_else(|| std::io::Error::other("conformance target builtin disappeared"))?;
    let observed = parse_semantic_coverage(document)?;
    let typed_result = parse_optional_digest_field(document, "semanticTypedResultSha256")?;
    let typed_result_builtin = parse_optional_u16_field(document, "semanticTypedResultBuiltinId")?;
    validate_conformance_typed_result(document, typed_result, typed_result_builtin)?;
    let boundaries = parse_semantic_boundaries(document)?;
    let event_order = parse_semantic_event_order(document)?;
    let effect_trace = parse_semantic_effect_trace(document)?;
    let task_trace = parse_semantic_task_trace(document)?;
    let resource_trace = parse_semantic_resource_trace(document)?;
    let obligation_trace = parse_semantic_obligation_trace(document)?;
    let conformance_facts = ConformanceObservationFacts {
        raw_presentation_sha256: parse_required_digest_field(document, "rawPresentationSha256")?,
        normalized_line_endings_sha256: parse_optional_digest_field(
            document,
            "normalizedPresentationLineEndingsSha256",
        )?,
        resource_audit_failures: parse_canonical_u64_field(document, "resourceAuditFailures")?,
    };
    validate_task_causality(&task_trace, &observed)?;
    validate_obligation_causality(&obligation_trace, &task_trace)?;
    validate_nested_ord_comparator_evidence(&obligation_trace)?;
    validate_force_only_target(target, builtin.id, &observed, &obligation_trace)?;
    validate_effect_causality(&effect_trace, &task_trace, &observed)?;
    if event_order.is_empty() {
        return Err(std::io::Error::other("semantic event order is empty"));
    }
    validate_semantic_event_classes(
        &event_order,
        &observed,
        typed_result.is_some(),
        boundaries.len(),
        obligation_trace.len(),
    )?;
    validate_expected_instance_target(target, builtin.id, &obligation_trace)?;
    validate_expected_comparator_trace(target, builtin.id, &obligation_trace)?;
    validate_exact_lazy_adapter_entry_target(target, builtin, &boundaries, &obligation_trace)?;
    validate_runtime_scope_binding(
        case,
        target,
        document,
        &observed,
        &obligation_trace,
        Path::new(""),
        Some(&conformance_facts),
    )?;
    if !target_has_causal_signal(target.causal_signal, builtin.id, &observed)? {
        return Err(std::io::Error::other(
            "candidate observation lacks exact target causal evidence",
        ));
    }
    if let Some(expected) = target.expected_typed_result_sha256
        && (typed_result != Some(expected) || typed_result_builtin != Some(builtin.id.0))
    {
        return Err(std::io::Error::other(
            "candidate typed result differs from the reviewed expectation",
        ));
    }
    validate_expected_lazy_argument_exit(target, builtin.id, &boundaries)?;
    validate_expected_whnf_argument_failure(target, builtin.id, &boundaries)?;
    validate_expected_nonproductive_trace(target, builtin.id, &boundaries)?;
    validate_expected_single_task_lifecycle(target, builtin.id, &task_trace, &effect_trace)?;
    validate_expected_task_trace(target, builtin.id, &task_trace)?;
    if let Some(expected) = target.expected_process_status_sha256 {
        let (success, code) = parse_observation_process_status(document)?;
        if crate::process_status_sha256(success, code) != expected {
            return Err(std::io::Error::other(
                "candidate process status differs from the reviewed expectation",
            ));
        }
    }
    validate_expected_single_effect_lifecycle(target, builtin.id, &effect_trace)?;
    validate_obligation_semantics(
        obligation,
        dimension,
        builtin.id,
        document,
        Path::new(""),
        &observed,
        &effect_trace,
        &task_trace,
        &resource_trace,
        &obligation_trace,
        typed_result,
        typed_result_builtin,
        &boundaries,
        &target.platforms,
        target.expected_raw_presentation_sha256,
        target.expected_presentation_shadow_normalizer,
        target.expected_normalized_presentation_sha256,
        Some(&conformance_facts),
    )?;
    validate_retained_callback_contracts(descriptor, &obligation_trace)
}

fn validate_conformance_semantic_document_shape(document: &str) -> std::io::Result<()> {
    const FIELDS: [&str; 17] = [
        "schemaVersion",
        "semanticCoverage",
        "semanticTypedResultSha256",
        "semanticTypedResultBuiltinId",
        "semanticBoundaries",
        "semanticObligationTrace",
        "semanticEventOrder",
        "semanticEffectTrace",
        "semanticTaskTrace",
        "semanticResourceTrace",
        "semanticTypedResultHex",
        "rawPresentationSha256",
        "normalizedPresentationLineEndingsSha256",
        "resourceAuditFailures",
        "status",
        "timedOut",
        "diagnostic",
    ];
    let lines = document.lines().collect::<Vec<_>>();
    if lines.first() != Some(&"{") || lines.last() != Some(&"}") || lines.len() != FIELDS.len() + 2
    {
        return Err(std::io::Error::other(
            "conformance semantic document has an unsupported shape",
        ));
    }
    for (line, field) in lines[1..lines.len() - 1].iter().zip(FIELDS) {
        if !line.starts_with(&format!("  \"{field}\": ")) {
            return Err(std::io::Error::other(
                "conformance semantic document fields are missing or reordered",
            ));
        }
    }
    if lines[1] != "  \"schemaVersion\": 1," {
        return Err(std::io::Error::other(
            "conformance semantic document schema is unsupported",
        ));
    }
    Ok(())
}

fn validate_conformance_typed_result(
    document: &str,
    digest: Option<Digest>,
    builtin: Option<u16>,
) -> std::io::Result<()> {
    let value = exact_observation_field(document, "semanticTypedResultHex")?;
    match (digest, builtin, value) {
        (None, None, "null") => Ok(()),
        (Some(expected), Some(_), value) => {
            let encoded = value
                .strip_prefix('"')
                .and_then(|value| value.strip_suffix('"'))
                .ok_or_else(|| std::io::Error::other("typed result hex is malformed"))?;
            let bytes = crate::decode_canonical_hex(encoded)
                .ok_or_else(|| std::io::Error::other("typed result hex is noncanonical"))?;
            let canonical = std::str::from_utf8(&bytes)
                .map_err(|_| std::io::Error::other("typed result is not UTF-8"))?;
            crate::validate_canonical_typed_value(canonical)?;
            if sha256_bytes(canonical.as_bytes()) != expected {
                return Err(std::io::Error::other(
                    "typed result digest does not bind its canonical value",
                ));
            }
            Ok(())
        }
        _ => Err(std::io::Error::other(
            "typed result retained identity is incomplete",
        )),
    }
}

fn push_conformance_capture(output: &mut String, field: &str, bytes: &[u8]) {
    output.push_str(",\"");
    output.push_str(field);
    output.push_str("\":{\"encoding\":\"base64\",\"value\":\"");
    push_base64(output, bytes);
    output.push_str("\"}");
}

fn push_base64(output: &mut String, bytes: &[u8]) {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        output.push(char::from(TABLE[usize::from(first >> 2)]));
        output.push(char::from(
            TABLE[usize::from(((first & 0x03) << 4) | (second >> 4))],
        ));
        output.push(if chunk.len() > 1 {
            char::from(TABLE[usize::from(((second & 0x0f) << 2) | (third >> 6))])
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            char::from(TABLE[usize::from(third & 0x3f)])
        } else {
            '='
        });
    }
}

/// Retains one candidate observation under one explicit compiler/runtime profile.
///
/// # Errors
///
/// Returns an error for an existing directory, inconsistent case/profile or
/// executable identities, noncanonical inputs, or an invalid observation.
pub fn retain_verified_profile_observation(
    directory: &Path,
    case: &DifferentialCase,
    verified: &VerifiedProfileObservation,
) -> std::io::Result<RetainedVerifiedProfileFacts> {
    validate_case_id(&case.id)?;
    if verified.observation.identity.role != crate::ExecutableRole::Candidate
        || verified.observation.identity.sha256 != verified.executable_sha256
        || verified.observation.case_id != case.id
    {
        return Err(std::io::Error::other(
            "verified profile observation identity differs from its retained case",
        ));
    }
    let parent = directory
        .parent()
        .ok_or_else(|| std::io::Error::other("profile observation has no parent directory"))?;
    fs::create_dir_all(parent)?;
    fs::create_dir(directory)?;
    write_atomic(&directory.join("main.hell"), case.source.as_bytes())?;
    write_atomic(&directory.join("stdin.bin"), &case.stdin)?;
    write_atomic(
        &directory.join("execution-input.json"),
        execution_input_json(case)?.as_bytes(),
    )?;
    write_atomic(
        &directory.join("case.toml"),
        case_descriptor(case).as_bytes(),
    )?;
    write_observation(directory, "candidate", &verified.observation)?;
    retain_process_helper(directory, case)?;
    let observation_sha256 = sha256_file(&directory.join("candidate").join("observation.json"))?;
    write_atomic(
        &directory.join("profile-observation.json"),
        profile_observation_json(
            verified.profile,
            verified.executable_sha256,
            verified.source_sha256,
            verified.execution_input_sha256,
            verified.invocation_sha256,
            observation_sha256,
        )
        .as_bytes(),
    )?;
    write_profile_manifest(directory)?;
    verify_retained_profile_observation(
        directory,
        case,
        &verified.observation.identity,
        verified.profile,
    )
}

/// Revalidates one retained explicit-profile observation and returns its facts.
///
/// # Errors
///
/// Returns an error for a noncanonical package, substituted executable/profile,
/// changed execution input, malformed observation, or retained resource leak.
pub fn verify_retained_profile_observation(
    directory: &Path,
    case: &DifferentialCase,
    expected_identity: &ExecutableIdentity,
    expected_profile: hell_builtins::ExecutionProfile,
) -> std::io::Result<RetainedVerifiedProfileFacts> {
    if expected_identity.role != crate::ExecutableRole::Candidate {
        return Err(std::io::Error::other(
            "profile observation verifier requires a candidate identity",
        ));
    }
    verify_retained_profile_observation_identity(
        directory,
        case,
        &identity_json(expected_identity),
        expected_identity.sha256,
        expected_profile,
    )
}

/// Revalidates a retained profile observation against the exact candidate
/// identity already retained in an upstream differential bundle.
///
/// # Errors
///
/// Returns an error when either package is invalid or the executable identity,
/// case bytes, or explicit profile is substituted.
pub fn verify_retained_profile_observation_against_bundle(
    directory: &Path,
    case: &DifferentialCase,
    upstream_bundle: &Path,
    expected_profile: hell_builtins::ExecutionProfile,
) -> std::io::Result<RetainedVerifiedProfileFacts> {
    let mut upstream_case = case.clone();
    let descriptor = upstream_case
        .claim_evidence
        .as_mut()
        .ok_or_else(|| std::io::Error::other("profile replay case is not reviewed"))?;
    descriptor.profile = hell_builtins::ExecutionProfile::Upstream;
    verify_observation_bundle_for_case(upstream_bundle, &upstream_case)?;
    let document = fs::read_to_string(upstream_bundle.join("candidate").join("observation.json"))?;
    let identity = observation_identity_json(&document)?;
    let (executable_sha256, _) = exact_candidate_identity(&document)?;
    verify_retained_profile_observation_identity(
        directory,
        case,
        identity,
        executable_sha256,
        expected_profile,
    )
}

/// Classifies one fully verified candidate profile observation against the
/// oracle side of its exact upstream differential bundle.
///
/// # Errors
///
/// Returns an error when either retained package fails strict replay or when
/// undeclared normalization would be required for equality.
pub fn classify_retained_profile_observation_against_oracle(
    directory: &Path,
    case: &DifferentialCase,
    upstream_bundle: &Path,
    expected_profile: hell_builtins::ExecutionProfile,
) -> std::io::Result<RetainedObservationClassification> {
    verify_retained_profile_observation_against_bundle(
        directory,
        case,
        upstream_bundle,
        expected_profile,
    )?;
    classify_retained_candidate_against_oracle(directory, case, upstream_bundle)
}

/// Classifies an explicitly different rebuilt candidate executable against
/// the oracle from an exact upstream bundle.
///
/// Unlike [`classify_retained_profile_observation_against_oracle`], this API
/// intentionally permits the candidate executable identity to differ from the
/// upstream candidate. It still requires the exact expected prototype digest,
/// assurance epoch, reviewed case source/input, and explicit execution profile.
///
/// # Errors
///
/// Returns an error when either package is invalid, the alternate executable
/// digest or epoch is substituted, or undeclared normalization is required.
pub fn classify_retained_alternate_executable_observation_against_oracle(
    directory: &Path,
    case: &DifferentialCase,
    upstream_bundle: &Path,
    expected_profile: hell_builtins::ExecutionProfile,
    expected_prototype_sha256: Digest,
) -> std::io::Result<RetainedObservationClassification> {
    verify_retained_alternate_executable_observation_against_bundle(
        directory,
        case,
        upstream_bundle,
        expected_profile,
        expected_prototype_sha256,
    )?;
    classify_retained_candidate_against_oracle(directory, case, upstream_bundle)
}

/// Revalidates an explicitly different rebuilt candidate against the exact
/// case/input/epoch authority of an upstream differential bundle.
///
/// # Errors
///
/// Returns an error for an invalid package, a reused upstream executable/path,
/// or a substituted prototype digest, epoch, case, input, or profile.
pub fn verify_retained_alternate_executable_observation_against_bundle(
    directory: &Path,
    case: &DifferentialCase,
    upstream_bundle: &Path,
    expected_profile: hell_builtins::ExecutionProfile,
    expected_prototype_sha256: Digest,
) -> std::io::Result<RetainedVerifiedProfileFacts> {
    let mut upstream_case = case.clone();
    let descriptor = upstream_case
        .claim_evidence
        .as_mut()
        .ok_or_else(|| std::io::Error::other("prototype replay case is not reviewed"))?;
    descriptor.profile = hell_builtins::ExecutionProfile::Upstream;
    verify_observation_bundle_for_case(upstream_bundle, &upstream_case)?;

    let upstream_document =
        fs::read_to_string(upstream_bundle.join("candidate").join("observation.json"))?;
    let upstream_identity = observation_identity_json(&upstream_document)?;
    let (upstream_sha256, upstream_epoch) = exact_candidate_identity(&upstream_document)?;
    let alternate_document =
        fs::read_to_string(directory.join("candidate").join("observation.json"))?;
    let alternate_identity = observation_identity_json(&alternate_document)?;
    let (alternate_sha256, alternate_epoch) = exact_candidate_identity(&alternate_document)?;
    if alternate_sha256 != expected_prototype_sha256
        || alternate_sha256 == upstream_sha256
        || alternate_epoch != upstream_epoch
        || candidate_identity_path(alternate_identity)?
            == candidate_identity_path(upstream_identity)?
    {
        return Err(std::io::Error::other(
            "prototype executable identity is not distinct or differs from the experiment authority",
        ));
    }
    verify_retained_profile_observation_identity(
        directory,
        case,
        alternate_identity,
        expected_prototype_sha256,
        expected_profile,
    )
}

fn candidate_identity_path(identity: &str) -> std::io::Result<&str> {
    identity
        .lines()
        .nth(3)
        .and_then(|line| line.strip_prefix("  \"path\": \""))
        .and_then(|path| path.strip_suffix("\","))
        .filter(|path| !path.is_empty())
        .ok_or_else(|| std::io::Error::other("candidate identity path is not canonical"))
}

fn classify_retained_candidate_against_oracle(
    directory: &Path,
    case: &DifferentialCase,
    upstream_bundle: &Path,
) -> std::io::Result<RetainedObservationClassification> {
    let oracle = upstream_bundle.join("oracle");
    let candidate = directory.join("candidate");
    let raw_mismatches = raw_mismatch_facts_between(&oracle, &candidate)?;
    let normalized_mismatches = recompute_mismatch_sides_between(&oracle, &candidate)?
        .into_iter()
        .map(|side| side.fact)
        .collect::<Vec<_>>();
    let normalizers = applied_claim_normalizers(case);
    let fingerprint_sha256 = mismatch_fingerprint(
        &case.id,
        &normalizers,
        &raw_mismatches,
        &normalized_mismatches,
    );
    if normalized_mismatches.is_empty() {
        if raw_mismatches.is_empty() {
            Ok(RetainedObservationClassification::Exact)
        } else if normalizers.is_empty() {
            Err(std::io::Error::other(
                "profile equality differs before undeclared claim normalization",
            ))
        } else {
            Ok(RetainedObservationClassification::Normalized {
                normalizers,
                raw_mismatches,
                fingerprint_sha256,
            })
        }
    } else {
        Ok(RetainedObservationClassification::Mismatch {
            raw_mismatches,
            normalized_mismatches,
            fingerprint_sha256,
        })
    }
}

fn verify_retained_profile_observation_identity(
    directory: &Path,
    case: &DifferentialCase,
    expected_identity_json: &str,
    expected_executable_sha256: Digest,
    expected_profile: hell_builtins::ExecutionProfile,
) -> std::io::Result<RetainedVerifiedProfileFacts> {
    if case
        .claim_evidence
        .as_ref()
        .map(|descriptor| descriptor.profile)
        != Some(expected_profile)
    {
        return Err(std::io::Error::other(
            "retained profile requires an exactly matching reviewed descriptor",
        ));
    }
    let package_sha256 = verify_profile_manifest(directory)?;
    let execution_input = execution_input_json(case)?;
    let source_sha256 = sha256_bytes(case.source.as_bytes());
    let execution_input_sha256 = sha256_bytes(execution_input.as_bytes());
    let invocation_sha256 = verified_profile_invocation_sha256(
        expected_profile,
        expected_executable_sha256,
        source_sha256,
        execution_input_sha256,
    );
    let observation_path = directory.join("candidate").join("observation.json");
    let observation_sha256 = sha256_file(&observation_path)?;
    if fs::read_to_string(directory.join("profile-observation.json"))?
        != profile_observation_json(
            expected_profile,
            expected_executable_sha256,
            source_sha256,
            execution_input_sha256,
            invocation_sha256,
            observation_sha256,
        )
        || fs::read(directory.join("main.hell"))? != case.source.as_bytes()
        || fs::read(directory.join("stdin.bin"))? != case.stdin
        || fs::read_to_string(directory.join("execution-input.json"))? != execution_input
        || fs::read_to_string(directory.join("case.toml"))? != case_descriptor(case)
    {
        return Err(std::io::Error::other(
            "retained profile observation differs from its exact case identity",
        ));
    }
    let document = fs::read_to_string(&observation_path)?;
    verify_profile_inventory(directory, case, &document)?;
    let identity_prefix = format!("{{\n  \"identity\": {}", expected_identity_json.trim());
    if !document
        .strip_prefix(&identity_prefix)
        .is_some_and(|remainder| remainder.starts_with(",\n"))
        || exact_observation_field(&document, "caseId")? != format!("\"{}\"", case.id).as_str()
        || exact_observation_field(&document, "mode")? != format!("\"{:?}\"", case.mode).as_str()
        || exact_observation_field(&document, "environmentProfile")?
            != format!("\"{:?}\"", case.environment_profile).as_str()
    {
        return Err(std::io::Error::other(
            "retained profile observation metadata is substituted",
        ));
    }
    let helper = case.process_helper_sha256;
    validate_observation_metadata(&observation_path, case, helper, true)?;
    observation_comparison_fields(&document)?;
    if case.mode == DifferentialMode::Run {
        let audit = fs::read_to_string(directory.join("candidate").join("resource-audit.json"))?;
        if audit != resource_audit_json(&ResourceAudit::default()) {
            return Err(std::io::Error::other(
                "retained profile observation reports leaked resources",
            ));
        }
    }
    Ok(RetainedVerifiedProfileFacts {
        profile: expected_profile,
        executable_sha256: expected_executable_sha256,
        source_sha256,
        execution_input_sha256,
        invocation_sha256,
        observation_sha256,
        package_sha256,
    })
}

fn observation_identity_json(document: &str) -> std::io::Result<&str> {
    document
        .strip_prefix("{\n  \"identity\": ")
        .and_then(|document| document.split_once(",\n  \"caseId\": "))
        .map(|(identity, _)| identity)
        .ok_or_else(|| std::io::Error::other("candidate observation identity is malformed"))
}

fn verify_profile_inventory(
    directory: &Path,
    case: &DifferentialCase,
    observation: &str,
) -> std::io::Result<()> {
    let mut expected = vec![
        "candidate/normalizer-context.json".to_owned(),
        "candidate/observation.json".to_owned(),
        "candidate/stderr.bin".to_owned(),
        "candidate/stderr.claim-input.bin".to_owned(),
        "candidate/stderr.raw.bin".to_owned(),
        "candidate/stdout.bin".to_owned(),
        "case.toml".to_owned(),
        "execution-input.json".to_owned(),
        "main.hell".to_owned(),
        "profile-manifest.json".to_owned(),
        "profile-manifest.sha256".to_owned(),
        "profile-observation.json".to_owned(),
        "stdin.bin".to_owned(),
    ];
    if case.mode == DifferentialMode::Run {
        expected.push("candidate/resource-audit.json".to_owned());
    }
    if parse_optional_digest_field(observation, "semanticTypedResultSha256")?.is_some() {
        expected.push("candidate/semantic-typed-result.json".to_owned());
    }
    if case.environment_profile == crate::EnvironmentProfile::ProcessCapable {
        expected.push(format!(
            "process-helper/hell-test-helper{}",
            std::env::consts::EXE_SUFFIX
        ));
    }
    expected.sort();
    if collect_bundle_files(directory)? != expected {
        return Err(std::io::Error::other(
            "profile observation package has an unknown or missing path",
        ));
    }
    Ok(())
}

/// Retains all raw observations and a structured, shell-free replay contract.
///
/// # Errors
///
/// Returns an error when the case identifier is unsafe or any artifact cannot
/// be created. Existing case directories are rejected so a stale schema can
/// never be interpreted as a fresh observation.
pub fn retain_mismatch_bundle(
    root: &Path,
    case: &DifferentialCase,
    report: &DifferentialReport,
) -> std::io::Result<PathBuf> {
    retain_observation_bundle(root, case, report)
}

/// Retains one complete oracle/candidate observation pair and replay contract.
///
/// # Errors
///
/// Returns an error when the case identifier is unsafe or an evidence artifact
/// cannot be written atomically.
pub fn retain_observation_bundle(
    root: &Path,
    case: &DifferentialCase,
    report: &DifferentialReport,
) -> std::io::Result<PathBuf> {
    validate_case_id(&case.id)?;
    let directory = root.join(case.id.as_ref());
    fs::create_dir_all(root)?;
    fs::create_dir(&directory)?;
    write_atomic(&directory.join("main.hell"), case.source.as_bytes())?;
    write_atomic(&directory.join("stdin.bin"), &case.stdin)?;
    write_atomic(
        &directory.join("execution-input.json"),
        execution_input_json(case)?.as_bytes(),
    )?;
    write_atomic(
        &directory.join("case.toml"),
        case_descriptor(case).as_bytes(),
    )?;
    write_atomic(
        &directory.join("replay.json"),
        replay_descriptor(case, report).as_bytes(),
    )?;
    write_observation(&directory, "oracle", &report.oracle)?;
    write_observation(&directory, "candidate", &report.candidate)?;
    write_atomic(
        &directory.join("filesystem.diff"),
        format!(
            "oracle: {:#?}\ncandidate: {:#?}\n",
            report.oracle.filesystem, report.candidate.filesystem
        )
        .as_bytes(),
    )?;
    write_atomic(
        &directory.join("normalized.diff"),
        format!("{:#?}\n", report.mismatches).as_bytes(),
    )?;
    let (comparison_projection, mismatch_sides) =
        recompute_projected_mismatch_sides(&directory, case)?;
    if comparison_projection != report.comparison_projection {
        return Err(std::io::Error::other(
            "differential comparison projection disagrees with retained observations",
        ));
    }
    write_atomic(
        &directory.join("comparison-projection.json"),
        comparison_projection_json(&comparison_projection).as_bytes(),
    )?;
    let declared_categories = report
        .mismatches
        .iter()
        .map(|mismatch| mismatch.kind)
        .collect::<Vec<_>>();
    let observed_categories = mismatch_sides
        .iter()
        .map(|side| side.fact.category)
        .collect::<Vec<_>>();
    if declared_categories != observed_categories {
        return Err(std::io::Error::other(
            "differential mismatch vector disagrees with retained observations",
        ));
    }
    let mismatch_facts = mismatch_sides
        .iter()
        .map(|side| side.fact.clone())
        .collect::<Vec<_>>();
    write_atomic(
        &directory.join("mismatch-summary.json"),
        mismatch_summary_json(&mismatch_facts).as_bytes(),
    )?;
    retain_mismatch_fact_bytes(&directory, &mismatch_sides)?;
    retain_process_helper(&directory, case)?;
    let epoch = report
        .candidate
        .identity
        .assurance_epoch_sha256
        .ok_or_else(|| std::io::Error::other("candidate observation has no assurance epoch"))?;
    write_bundle_manifest(&directory, case, epoch)?;
    Ok(directory)
}

/// Retains a regression mismatch and derives its complete proposed reviewed
/// descriptor from the oracle observation rather than cloning candidate or
/// caller-selected target semantics.
///
/// The input case must be non-claim-eligible. The returned case preserves its
/// exact execution inputs while binding oracle-derived targets, typed/raw
/// expectations, and callback contracts to the minimized source.
///
/// # Errors
///
/// Returns an error when the initial bundle is not exact, the oracle does not
/// retain canonical semantic evidence, or the derived descriptor cannot be
/// replayed against the oracle side.
pub fn retain_reviewed_regression_bundle(
    root: &Path,
    case: &DifferentialCase,
    report: &DifferentialReport,
    review_statement: &str,
) -> std::io::Result<(PathBuf, DifferentialCase)> {
    if case.claim_evidence.is_some() || review_statement.is_empty() || report.mismatches.is_empty()
    {
        return Err(std::io::Error::other(
            "regression descriptor derivation requires an ineligible case and review statement",
        ));
    }
    let directory = retain_observation_bundle(root, case, report)?;
    verify_observation_bundle_for_case(&directory, case)?;
    let reviewed = derive_regression_case_from_oracle(&directory, case, review_statement)?;
    write_atomic(
        &directory.join("case.toml"),
        case_descriptor(&reviewed).as_bytes(),
    )?;
    write_atomic(
        &directory.join("replay.json"),
        replay_descriptor(&reviewed, report).as_bytes(),
    )?;
    fs::remove_file(directory.join("bundle-manifest.json"))?;
    fs::remove_file(directory.join("bundle-manifest.sha256"))?;
    let epoch = report
        .candidate
        .identity
        .assurance_epoch_sha256
        .ok_or_else(|| std::io::Error::other("candidate observation has no assurance epoch"))?;
    write_bundle_manifest(&directory, &reviewed, epoch)?;
    verify_regression_observation_bundle_for_case(&directory, &reviewed)?;
    Ok((directory, reviewed))
}

/// Reconstructs the complete reviewed minimized-case descriptor solely from
/// committed oracle evidence and exact execution inputs.
///
/// # Errors
///
/// Returns an error when the bundle identity/source/input differs from the
/// supplied minimized case or the reconstructed descriptor does not exactly
/// replay against the retained oracle.
pub fn reviewed_regression_case_from_bundle(
    directory: &Path,
    case: &DifferentialCase,
    review_statement: &str,
) -> std::io::Result<DifferentialCase> {
    verify_observation_bundle(directory)?;
    let manifest = fs::read_to_string(directory.join("bundle-manifest.json"))?;
    let identity = bundle_manifest_identity(&manifest)?;
    if identity.case_id != case.id.as_ref()
        || fs::read(directory.join("main.hell"))? != case.source.as_bytes()
        || fs::read(directory.join("stdin.bin"))? != case.stdin
        || fs::read_to_string(directory.join("execution-input.json"))?
            != execution_input_json(case)?
    {
        return Err(std::io::Error::other(
            "regression bundle differs from minimized execution inputs",
        ));
    }
    let reviewed = derive_regression_case_from_oracle(directory, case, review_statement)?;
    verify_regression_observation_bundle_for_case(directory, &reviewed)?;
    Ok(reviewed)
}

fn derive_regression_case_from_oracle(
    directory: &Path,
    case: &DifferentialCase,
    review_statement: &str,
) -> std::io::Result<DifferentialCase> {
    let observation_directory = directory.join("candidate");
    let oracle_directory = directory.join("oracle");
    let document = fs::read_to_string(observation_directory.join("observation.json"))?;
    let observed = parse_semantic_coverage(&document)?;
    let typed_result = parse_optional_digest_field(&document, "semanticTypedResultSha256")?;
    let typed_builtin = parse_optional_u16_field(&document, "semanticTypedResultBuiltinId")?;
    let boundaries = parse_semantic_boundaries(&document)?;
    let effect_trace = parse_semantic_effect_trace(&document)?;
    let task_trace = parse_semantic_task_trace(&document)?;
    let resource_trace = parse_semantic_resource_trace(&document)?;
    let obligation_trace = parse_semantic_obligation_trace(&document)?;
    let candidate_raw = raw_presentation_sha256(
        &fs::read(observation_directory.join("stdout.bin"))?,
        &fs::read(observation_directory.join("stderr.raw.bin"))?,
    );
    let oracle_raw = raw_presentation_sha256(
        &fs::read(oracle_directory.join("stdout.bin"))?,
        &fs::read(oracle_directory.join("stderr.raw.bin"))?,
    );
    let mut semantic_targets = Vec::new();
    for cell in crate::applicable_runtime_obligation_cells() {
        let builtin = hell_builtins::lookup(&cell.builtin)
            .ok_or_else(|| std::io::Error::other("oracle regression builtin disappeared"))?;
        if !target_has_causal_signal(cell.causal_signal, builtin.id, &observed).unwrap_or(false) {
            continue;
        }
        let obligations = cell
            .obligations
            .iter()
            .filter(|obligation| obligation.0.as_ref() != "callback-order")
            .filter(|obligation| {
                validate_obligation_semantics(
                    obligation.0.as_ref(),
                    cell.dimension,
                    builtin.id,
                    &document,
                    &observation_directory,
                    &observed,
                    &effect_trace,
                    &task_trace,
                    &resource_trace,
                    &obligation_trace,
                    typed_result,
                    typed_builtin,
                    &boundaries,
                    &cell.platforms,
                    Some(candidate_raw),
                    None,
                    None,
                    None,
                )
                .is_ok()
            })
            .cloned()
            .collect::<Vec<_>>();
        let observed_obligations = obligations
            .iter()
            .map(|obligation| Arc::clone(&obligation.0))
            .collect::<std::collections::BTreeSet<_>>();
        let required_obligations = cell
            .obligations
            .iter()
            .map(|obligation| Arc::clone(&obligation.0))
            .collect::<std::collections::BTreeSet<_>>();
        if observed_obligations != required_obligations {
            continue;
        }
        let mut target = EvidenceTargetV2::new(
            Arc::clone(&cell.builtin),
            cell.dimension,
            obligations,
            cell.causal_signal,
            cell.platforms,
        );
        target.expected_raw_presentation_sha256 = Some(oracle_raw);
        semantic_targets.push(target);
    }
    reviewed_regression_case(case, review_statement, semantic_targets)
}

fn reviewed_regression_case(
    case: &DifferentialCase,
    review_statement: &str,
    mut semantic_targets: Vec<EvidenceTargetV2>,
) -> std::io::Result<DifferentialCase> {
    semantic_targets.sort_by(|left, right| {
        left.builtin
            .cmp(&right.builtin)
            .then_with(|| left.dimension.as_str().cmp(right.dimension.as_str()))
    });
    if semantic_targets.is_empty() {
        return Err(std::io::Error::other(
            "regression oracle reached no claim target",
        ));
    }
    let targets = semantic_targets
        .iter()
        .map(|target| EvidenceTarget::new(Arc::clone(&target.builtin), target.dimension))
        .collect();
    let mut reviewed = case.clone();
    reviewed.claim_evidence = Some(ClaimEvidenceDescriptor {
        schema_version: 8,
        profile: hell_builtins::ExecutionProfile::Upstream,
        harness_normalizers: applied_harness_normalizers(),
        claim_normalizers: applied_claim_normalizers(case),
        targets,
        semantic_targets,
        callback_contracts: Vec::new(),
        review_state: CaseReviewState::Reviewed,
        review_statement: review_statement.into(),
        source_sha256: sha256_bytes(case.source.as_bytes()),
    });
    Ok(reviewed)
}

fn retain_process_helper(directory: &Path, case: &DifferentialCase) -> std::io::Result<()> {
    if case.environment_profile != crate::EnvironmentProfile::ProcessCapable {
        if case.process_helper_directory.is_some() || case.process_helper_sha256.is_some() {
            return Err(std::io::Error::other(
                "non-process case carries a process helper identity",
            ));
        }
        return Ok(());
    }
    let source_directory = case
        .process_helper_directory
        .as_ref()
        .ok_or_else(|| std::io::Error::other("process case has no helper directory"))?;
    let expected_digest = case
        .process_helper_sha256
        .ok_or_else(|| std::io::Error::other("process case has no helper digest"))?;
    let file_name = format!("hell-test-helper{}", std::env::consts::EXE_SUFFIX);
    let source = source_directory.join(&file_name);
    if sha256_file(&source)? != expected_digest {
        return Err(std::io::Error::other(
            "process helper changed after its execution identity was bound",
        ));
    }
    let retained_directory = directory.join("process-helper");
    fs::create_dir(&retained_directory)?;
    let retained = retained_directory.join(file_name);
    fs::copy(source, &retained)?;
    if sha256_file(&retained)? != expected_digest {
        return Err(std::io::Error::other(
            "retained process helper differs from the executed helper",
        ));
    }
    Ok(())
}

/// Verifies a schema-v4 bundle manifest, its digest record, the exact portable
/// file inventory, and every retained file digest.
///
/// # Errors
///
/// Returns an error for malformed manifests, legacy/extra/missing paths, or a
/// digest mismatch.
pub fn verify_observation_bundle(directory: &Path) -> std::io::Result<Digest> {
    let manifest_path = directory.join("bundle-manifest.json");
    let manifest = fs::read_to_string(&manifest_path)?;
    let (identity, declared) = parse_bundle_manifest(&manifest)?;
    for (relative, digest) in &declared {
        let observed = sha256_file(&directory.join(relative))?.hex();
        if observed != *digest {
            return Err(std::io::Error::other(format!(
                "bundle file digest mismatch for {relative}"
            )));
        }
    }
    verify_retained_process_helper(
        directory,
        identity.process_helper_path,
        identity.process_helper_sha256,
    )?;
    verify_retained_mismatch_summary_schema(directory)?;
    let manifest_digest = sha256_bytes(manifest.as_bytes());
    let candidate_observation =
        fs::read_to_string(directory.join("candidate").join("observation.json"))?;
    let (_, candidate_epoch) = exact_candidate_identity(&candidate_observation)?;
    if candidate_epoch != identity.epoch {
        return Err(std::io::Error::other(
            "candidate observation identity does not match bundle assurance epoch",
        ));
    }
    verify_bundle_manifest_digest_record(directory, manifest_digest)?;
    let mut observed = collect_bundle_files(directory)?;
    observed.retain(|path| {
        !matches!(
            path.as_str(),
            "bundle-manifest.json" | "bundle-manifest.sha256"
        )
    });
    let declared_paths = declared
        .iter()
        .map(|(path, _)| path.clone())
        .collect::<Vec<_>>();
    if observed != declared_paths {
        return Err(std::io::Error::other(
            "bundle contains an extra, missing, or non-canonical file",
        ));
    }
    Ok(manifest_digest)
}

/// Admits the exact canonical schema-v4 observation-bundle manifest without
/// dereferencing its retained file inventory.
///
/// # Errors
///
/// Returns an error for invalid UTF-8, malformed identities, nonportable paths,
/// duplicate files, invalid digests, or noncanonical/unknown fields.
pub fn verify_observation_bundle_manifest_bytes(bytes: &[u8]) -> std::io::Result<()> {
    let document = std::str::from_utf8(bytes)
        .map_err(|_| std::io::Error::other("bundle manifest is not canonical UTF-8"))?;
    parse_bundle_manifest(document).map(|_| ())
}

/// Parses a canonical schema-v4 observation-bundle manifest and returns its
/// exact ordered portable path/digest inventory without dereferencing paths.
///
/// # Errors
///
/// Returns an error for invalid UTF-8, a malformed/noncanonical manifest,
/// a nonportable path, or an invalid digest.
pub fn verified_observation_bundle_manifest_files(
    bytes: &[u8],
) -> std::io::Result<Vec<(String, Digest)>> {
    let document = std::str::from_utf8(bytes)
        .map_err(|_| std::io::Error::other("bundle manifest is not canonical UTF-8"))?;
    parse_bundle_manifest(document).and_then(|(_, files)| {
        files
            .into_iter()
            .map(|(path, digest)| {
                Digest::from_hex(&digest)
                    .map(|digest| (path, digest))
                    .map_err(std::io::Error::other)
            })
            .collect()
    })
}

fn parse_bundle_manifest(
    manifest: &str,
) -> std::io::Result<(BundleManifestIdentity<'_>, Vec<(String, String)>)> {
    let identity = bundle_manifest_identity(manifest)?;
    let mut lines = manifest.lines();
    for _ in 0..7 {
        lines.next();
    }
    if lines.next() != Some("  \"files\": {") {
        return Err(std::io::Error::other(
            "bundle manifest file map is malformed",
        ));
    }
    let mut declared = Vec::new();
    loop {
        let line = lines
            .next()
            .ok_or_else(|| std::io::Error::other("bundle file map is unterminated"))?;
        if line == "  }" {
            break;
        }
        let line = line
            .strip_prefix("    ")
            .ok_or_else(|| std::io::Error::other("malformed bundle file indentation"))?;
        let line = line.strip_suffix(',').unwrap_or(line);
        let (quoted_path, quoted_digest) = line
            .split_once(": ")
            .ok_or_else(|| std::io::Error::other("malformed bundle file entry"))?;
        let relative = unquote_simple(quoted_path)
            .ok_or_else(|| std::io::Error::other("malformed bundle file path"))?;
        let digest = unquote_simple(quoted_digest)
            .ok_or_else(|| std::io::Error::other("malformed bundle file digest"))?;
        validate_portable_bundle_path(relative)?;
        if declared.iter().any(|(path, _)| path == relative) {
            return Err(std::io::Error::other("duplicate bundle file path"));
        }
        if Digest::from_hex(digest).is_err() || digest.bytes().any(|byte| byte.is_ascii_uppercase())
        {
            return Err(std::io::Error::other("invalid bundle file digest"));
        }
        declared.push((relative.to_owned(), digest.to_owned()));
    }
    if lines.next() != Some("}") || lines.next().is_some() || declared.is_empty() {
        return Err(std::io::Error::other("bundle file inventory is incomplete"));
    }
    if manifest
        != canonical_bundle_manifest(
            identity.case_id,
            identity.epoch,
            identity.profile,
            identity.process_helper_path,
            identity.process_helper_sha256,
            &declared,
        )
    {
        return Err(std::io::Error::other(
            "bundle manifest is not canonical or contains unknown fields",
        ));
    }
    Ok((identity, declared))
}

fn verify_retained_mismatch_summary_schema(directory: &Path) -> std::io::Result<()> {
    let document = fs::read_to_string(directory.join("mismatch-summary.json"))?;
    let facts = parse_mismatch_summary(&document)?;
    verify_mismatch_fact_bytes(directory, &facts)?;
    let projection_document = fs::read_to_string(directory.join("comparison-projection.json"))?;
    let projection = parse_comparison_projection_json(&projection_document)?;
    if matches!(projection, crate::DifferentialComparisonProjection::Exact) {
        let recomputed = recompute_mismatch_sides(directory)?
            .into_iter()
            .map(|side| side.fact)
            .collect::<Vec<_>>();
        if recomputed != facts {
            return Err(std::io::Error::other(
                "retained mismatch summary omits or substitutes an observation difference",
            ));
        }
    }
    Ok(())
}

fn verify_bundle_manifest_digest_record(
    directory: &Path,
    manifest_digest: Digest,
) -> std::io::Result<()> {
    let digest_record = fs::read_to_string(directory.join("bundle-manifest.sha256"))?;
    let expected_record = format!("{}  bundle-manifest.json\n", manifest_digest.hex());
    if digest_record != expected_record {
        return Err(std::io::Error::other(
            "observation bundle manifest digest record is invalid",
        ));
    }
    Ok(())
}

fn verify_retained_process_helper(
    directory: &Path,
    path: Option<&str>,
    sha256: Option<Digest>,
) -> std::io::Result<()> {
    match (path, sha256) {
        (Some(path), Some(expected)) => {
            validate_portable_bundle_path(path)?;
            if !path.starts_with("process-helper/")
                || sha256_file(&directory.join(Path::new(path)))? != expected
            {
                return Err(std::io::Error::other(
                    "retained process helper does not match its manifest identity",
                ));
            }
        }
        (None, None) => {}
        _ => {
            return Err(std::io::Error::other(
                "bundle process helper identity is incomplete",
            ));
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct BundleManifestIdentity<'a> {
    case_id: &'a str,
    epoch: Digest,
    profile: &'a str,
    process_helper_path: Option<&'a str>,
    process_helper_sha256: Option<Digest>,
}

fn bundle_manifest_identity(document: &str) -> std::io::Result<BundleManifestIdentity<'_>> {
    let mut lines = document.lines();
    if lines.next() != Some("{") || lines.next() != Some("  \"schemaVersion\": 5,") {
        return Err(std::io::Error::other("bundle manifest schema is malformed"));
    }
    let case_id = exact_quoted_manifest_line(lines.next(), "caseId")?;
    validate_case_id(case_id)?;
    let epoch = exact_quoted_manifest_line(lines.next(), "assuranceEpochSha256")?;
    let epoch = Digest::from_hex(epoch)
        .map_err(|_| std::io::Error::other("bundle manifest assurance epoch is malformed"))?;
    let profile = exact_quoted_manifest_line(lines.next(), "profile")?;
    if !matches!(profile, "upstream" | "sandboxed" | "ineligible") {
        return Err(std::io::Error::other(
            "bundle manifest profile is malformed",
        ));
    }
    let helper_path = exact_optional_manifest_line(lines.next(), "processHelperPath")?;
    let helper_sha256 = exact_optional_manifest_line(lines.next(), "processHelperSha256")?
        .map(Digest::from_hex)
        .transpose()
        .map_err(|_| std::io::Error::other("bundle process helper digest is malformed"))?;
    Ok(BundleManifestIdentity {
        case_id,
        epoch,
        profile,
        process_helper_path: helper_path,
        process_helper_sha256: helper_sha256,
    })
}

fn exact_optional_manifest_line<'a>(
    line: Option<&'a str>,
    field: &str,
) -> std::io::Result<Option<&'a str>> {
    let line = line
        .and_then(|line| line.strip_suffix(','))
        .ok_or_else(|| std::io::Error::other(format!("bundle manifest {field} is malformed")))?;
    let prefix = format!("  \"{field}\": ");
    let value = line
        .strip_prefix(&prefix)
        .ok_or_else(|| std::io::Error::other(format!("bundle manifest {field} is malformed")))?;
    if value == "null" {
        Ok(None)
    } else {
        unquote_simple(value)
            .map(Some)
            .ok_or_else(|| std::io::Error::other(format!("bundle manifest {field} is malformed")))
    }
}

fn exact_quoted_manifest_line<'a>(line: Option<&'a str>, field: &str) -> std::io::Result<&'a str> {
    let prefix = format!("  \"{field}\": \"");
    line.and_then(|line| line.strip_prefix(&prefix))
        .and_then(|line| line.strip_suffix("\","))
        .ok_or_else(|| std::io::Error::other(format!("bundle manifest {field} is malformed")))
}

fn canonical_bundle_manifest(
    case_id: &str,
    epoch: Digest,
    profile: &str,
    process_helper_path: Option<&str>,
    process_helper_sha256: Option<Digest>,
    files: &[(String, String)],
) -> String {
    let mut output = String::from("{\n  \"schemaVersion\": 5,\n  \"caseId\": ");
    push_json_string(&mut output, case_id);
    output.push_str(",\n  \"assuranceEpochSha256\": ");
    push_json_string(&mut output, &epoch.hex());
    output.push_str(",\n  \"profile\": ");
    push_json_string(&mut output, profile);
    output.push_str(",\n  \"processHelperPath\": ");
    if let Some(path) = process_helper_path {
        push_json_string(&mut output, path);
    } else {
        output.push_str("null");
    }
    output.push_str(",\n  \"processHelperSha256\": ");
    if let Some(digest) = process_helper_sha256 {
        push_json_string(&mut output, &digest.hex());
    } else {
        output.push_str("null");
    }
    output.push_str(",\n  \"files\": {\n");
    for (index, (path, digest)) in files.iter().enumerate() {
        output.push_str("    ");
        push_json_string(&mut output, path);
        output.push_str(": ");
        push_json_string(&mut output, digest);
        if index + 1 != files.len() {
            output.push(',');
        }
        output.push('\n');
    }
    output.push_str("  }\n}\n");
    output
}

/// Verifies a retained bundle and binds its source and case descriptor to the
/// current committed case catalog.
///
/// # Errors
///
/// Returns an error when the bundle is invalid or its reviewed case metadata
/// differs from the current source.
pub fn verify_observation_bundle_for_case(
    directory: &Path,
    case: &DifferentialCase,
) -> std::io::Result<Digest> {
    verify_observation_bundle_case_bytes(directory, case, false)
}

/// Verifies a retained regression mismatch against the exact reviewed oracle
/// descriptor while deliberately not requiring the known-regressed candidate
/// to satisfy that expected descriptor.
///
/// # Errors
///
/// Returns an error when the bundle, case bytes, oracle claim semantics, or
/// candidate observation metadata is not exact canonical evidence.
pub fn verify_regression_observation_bundle_for_case(
    directory: &Path,
    case: &DifferentialCase,
) -> std::io::Result<Digest> {
    if case.claim_evidence.is_none() {
        return Err(std::io::Error::other(
            "regression bundle requires a reviewed oracle descriptor",
        ));
    }
    verify_observation_bundle_case_bytes(directory, case, true)
}

fn verify_observation_bundle_case_bytes(
    directory: &Path,
    case: &DifferentialCase,
    regression_oracle: bool,
) -> std::io::Result<Digest> {
    let digest = verify_observation_bundle(directory)?;
    let manifest = fs::read_to_string(directory.join("bundle-manifest.json"))?;
    let manifest_identity = bundle_manifest_identity(&manifest)?;
    let expected_profile = case
        .claim_evidence
        .as_ref()
        .map_or("ineligible", |descriptor| match descriptor.profile {
            hell_builtins::ExecutionProfile::Upstream => "upstream",
            hell_builtins::ExecutionProfile::Sandboxed => "sandboxed",
        });
    if manifest_identity.case_id != case.id.as_ref()
        || manifest_identity.profile != expected_profile
    {
        return Err(std::io::Error::other(
            "bundle manifest case or profile differs from the committed descriptor",
        ));
    }
    if (case.environment_profile == crate::EnvironmentProfile::ProcessCapable)
        != manifest_identity.process_helper_sha256.is_some()
    {
        return Err(std::io::Error::other(
            "bundle process helper identity differs from the committed environment profile",
        ));
    }
    if fs::read(directory.join("main.hell"))? != case.source.as_bytes()
        || fs::read(directory.join("stdin.bin"))? != case.stdin
        || fs::read_to_string(directory.join("execution-input.json"))?
            != execution_input_json(case)?
        || fs::read_to_string(directory.join("case.toml"))? != case_descriptor(case)
    {
        return Err(std::io::Error::other(
            "observation bundle case descriptor differs from the committed catalog",
        ));
    }
    validate_observation_metadata(
        &directory.join("oracle").join("observation.json"),
        case,
        manifest_identity.process_helper_sha256,
        false,
    )?;
    validate_observation_metadata(
        &directory.join("candidate").join("observation.json"),
        case,
        manifest_identity.process_helper_sha256,
        !regression_oracle,
    )?;
    verify_case_comparison_projection(directory, case)?;
    if regression_oracle {
        validate_regression_claim_sources(directory, case)?;
    }
    if case.mode == DifferentialMode::Run {
        let audit = fs::read_to_string(directory.join("candidate").join("resource-audit.json"))?;
        if audit != resource_audit_json(&ResourceAudit::default()) {
            return Err(std::io::Error::other(
                "candidate resource audit is malformed or reports retained resources",
            ));
        }
    }
    Ok(digest)
}

fn verify_case_comparison_projection(
    directory: &Path,
    case: &DifferentialCase,
) -> std::io::Result<()> {
    let retained = fs::read_to_string(directory.join("comparison-projection.json"))?;
    let retained = parse_comparison_projection_json(&retained)?;
    let (recomputed, mismatch_sides) = recompute_projected_mismatch_sides(directory, case)?;
    if retained != recomputed {
        return Err(std::io::Error::other(
            "retained comparison projection is not derived from current case authority and evidence",
        ));
    }
    let summary = fs::read_to_string(directory.join("mismatch-summary.json"))?;
    let facts = parse_mismatch_summary(&summary)?;
    let recomputed_facts = mismatch_sides
        .iter()
        .map(|side| side.fact.clone())
        .collect::<Vec<_>>();
    if facts != recomputed_facts {
        return Err(std::io::Error::other(
            "retained mismatch summary omits or substitutes an in-scope observation difference",
        ));
    }
    if matches!(
        &retained,
        crate::DifferentialComparisonProjection::ReviewedRuntimeFailureStderr { .. }
            | crate::DifferentialComparisonProjection::ReviewedRuntimeFailureExceptionStderr { .. }
    ) {
        let raw = raw_mismatch_facts(directory)?;
        if raw.len() != 1 || raw[0].category != crate::MismatchKind::Stderr {
            return Err(std::io::Error::other(
                "reviewed failure projection does not retain exactly one raw stderr difference",
            ));
        }
    }
    if let crate::DifferentialComparisonProjection::ReviewedWindowsPresentation {
        platform,
        field,
        ..
    } = retained
    {
        let raw = raw_mismatch_facts(directory)?;
        if platform != hell_builtins::ClaimPlatform::Windows
            || raw.len() != 1
            || raw[0].category != field.mismatch_kind()
        {
            return Err(std::io::Error::other(
                "reviewed Windows projection does not retain its exact target and raw field",
            ));
        }
    }
    Ok(())
}

fn validate_regression_claim_sources(
    directory: &Path,
    case: &DifferentialCase,
) -> std::io::Result<()> {
    let descriptor = case
        .claim_evidence
        .as_ref()
        .ok_or_else(|| std::io::Error::other("regression descriptor disappeared"))?;
    let mut causal_descriptor = descriptor.clone();
    for target in &mut causal_descriptor.semantic_targets {
        target.expected_typed_result_sha256 = None;
        target.expected_raw_presentation_sha256 = None;
        target.expected_presentation_shadow_normalizer = None;
        target.expected_normalized_presentation_sha256 = None;
        target.expected_lazy_argument_exit_sha256 = None;
        target.expected_whnf_argument_failure_sha256 = None;
        target.expected_nonproductive_trace_sha256 = None;
        target.expected_single_task_lifecycle_sha256 = None;
        target.expected_task_trace_sha256 = None;
        target.expected_process_status_sha256 = None;
        target.expected_single_effect_lifecycle_sha256 = None;
        target.expected_comparator_trace_sha256 = None;
        target.obligations.retain(|obligation| {
            !matches!(
                obligation.0.as_ref(),
                "raw-observation" | "normalized-shadow-diff"
            )
        });
    }
    let candidate = fs::read_to_string(directory.join("candidate/observation.json"))?;
    validate_claim_semantics(
        &candidate,
        case,
        &causal_descriptor,
        &directory.join("candidate"),
    )?;
    for target in &descriptor.semantic_targets {
        if target.expected_typed_result_sha256.is_some() {
            return Err(std::io::Error::other(
                "regression typed expectation lacks independent oracle semantic evidence",
            ));
        }
        if !validate_raw_presentation(
            &directory.join("oracle"),
            target.expected_raw_presentation_sha256,
            None,
        )? {
            return Err(std::io::Error::other(format!(
                "regression oracle raw expectation differs for {:?}/{:?}",
                target.builtin, target.dimension
            )));
        }
    }
    Ok(())
}

/// Strict, per-side outcome facts rederived from a verified retained bundle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetainedSideOutcomeFacts {
    pub timed_out: bool,
    pub status_success: bool,
    pub resource_failures: usize,
    pub effect_failures: usize,
}

/// Strict bilateral outcome facts for surveillance and summary replay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetainedBundleOutcomeFacts {
    pub oracle: RetainedSideOutcomeFacts,
    pub candidate: RetainedSideOutcomeFacts,
}

/// One runtime claim cell and the exact obligations satisfied by a retained
/// candidate trace, independently of a caller-selected descriptor subset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetainedReachedClaimTarget {
    pub builtin: Arc<str>,
    pub dimension: hell_builtins::CompatibilityDimension,
    pub obligations: Vec<crate::ObligationId>,
}

/// Rederives every reached runtime claim cell and satisfied obligation from a
/// fully verified retained candidate observation.
///
/// # Errors
///
/// Returns an error when the bundle or any semantic trace component is not
/// exact canonical evidence.
pub fn retained_reached_claim_targets(
    directory: &Path,
    case: &DifferentialCase,
) -> std::io::Result<Vec<RetainedReachedClaimTarget>> {
    verify_observation_bundle_for_case(directory, case)?;
    retained_reached_claim_targets_for_side(directory, "candidate")
}

/// Rederives every claim target causally reached by the compat-tracing
/// candidate side of an exact retained regression mismatch. Expected raw
/// behavior remains independently bound to the oracle side.
///
/// # Errors
///
/// Returns an error when the regression bundle or causal claim evidence is
/// malformed, incomplete, or differs from its reviewed descriptor.
pub fn retained_regression_reached_claim_targets(
    directory: &Path,
    case: &DifferentialCase,
) -> std::io::Result<Vec<RetainedReachedClaimTarget>> {
    verify_regression_observation_bundle_for_case(directory, case)?;
    retained_reached_claim_targets_for_side(directory, "candidate")
}

/// Returns only the complete oracle-expected target descriptors eligible for
/// protected regression review, while the broader reached-target API remains
/// available for the explicit non-claim inventory.
///
/// # Errors
///
/// Returns an error when any reviewed descriptor target is absent from the
/// exact compat-tracing reach inventory or lacks its full authority obligations.
pub fn retained_regression_reviewed_claim_targets(
    directory: &Path,
    case: &DifferentialCase,
) -> std::io::Result<Vec<RetainedReachedClaimTarget>> {
    let reached = retained_regression_reached_claim_targets(directory, case)?;
    let descriptor = case
        .claim_evidence
        .as_ref()
        .ok_or_else(|| std::io::Error::other("regression descriptor disappeared"))?;
    let mut reviewed = Vec::new();
    for target in &descriptor.semantic_targets {
        let reached = reached
            .iter()
            .find(|reached| {
                reached.builtin == target.builtin && reached.dimension == target.dimension
            })
            .ok_or_else(|| std::io::Error::other("reviewed regression target was not reached"))?;
        if reached.obligations != target.obligations {
            return Err(std::io::Error::other(
                "reviewed regression obligations differ from causal evidence",
            ));
        }
        reviewed.push(reached.clone());
    }
    Ok(reviewed)
}

fn retained_reached_claim_targets_for_side(
    directory: &Path,
    side: &str,
) -> std::io::Result<Vec<RetainedReachedClaimTarget>> {
    let observation_directory = directory.join(side);
    let document = fs::read_to_string(observation_directory.join("observation.json"))?;
    let observed = parse_semantic_coverage(&document)?;
    let typed_result = parse_optional_digest_field(&document, "semanticTypedResultSha256")?;
    let typed_result_builtin = parse_optional_u16_field(&document, "semanticTypedResultBuiltinId")?;
    let boundaries = parse_semantic_boundaries(&document)?;
    let effect_trace = parse_semantic_effect_trace(&document)?;
    let task_trace = parse_semantic_task_trace(&document)?;
    let resource_trace = parse_semantic_resource_trace(&document)?;
    let obligation_trace = parse_semantic_obligation_trace(&document)?;
    let mut reached = Vec::new();
    for cell in crate::applicable_runtime_obligation_cells() {
        let builtin = hell_builtins::lookup(&cell.builtin)
            .ok_or_else(|| std::io::Error::other("runtime claim builtin disappeared"))?;
        if !target_has_causal_signal(cell.causal_signal, builtin.id, &observed).unwrap_or(false) {
            continue;
        }
        let obligations = cell
            .obligations
            .iter()
            .filter(|obligation| {
                validate_obligation_semantics(
                    obligation.0.as_ref(),
                    cell.dimension,
                    builtin.id,
                    &document,
                    &observation_directory,
                    &observed,
                    &effect_trace,
                    &task_trace,
                    &resource_trace,
                    &obligation_trace,
                    typed_result,
                    typed_result_builtin,
                    &boundaries,
                    &cell.platforms,
                    None,
                    None,
                    None,
                    None,
                )
                .is_ok()
            })
            .cloned()
            .collect::<Vec<_>>();
        reached.push(RetainedReachedClaimTarget {
            builtin: cell.builtin,
            dimension: cell.dimension,
            obligations,
        });
    }
    reached.sort_by(|left, right| {
        left.builtin
            .cmp(&right.builtin)
            .then_with(|| left.dimension.as_str().cmp(right.dimension.as_str()))
            .then_with(|| {
                left.obligations
                    .iter()
                    .map(|value| value.0.as_ref())
                    .cmp(right.obligations.iter().map(|value| value.0.as_ref()))
            })
    });
    Ok(reached)
}

/// Revalidates a retained observation bundle and derives bilateral timeout,
/// status, resource, and failed-effect counters from the exact retained bytes.
///
/// # Errors
///
/// Returns an error when bundle verification or any retained typed parser fails.
pub fn retained_bundle_outcome_facts(
    directory: &Path,
    case: &DifferentialCase,
) -> std::io::Result<RetainedBundleOutcomeFacts> {
    verify_observation_bundle_for_case(directory, case)?;
    retained_bundle_outcome_facts_from_verified(directory)
}

fn retained_bundle_outcome_facts_from_verified(
    directory: &Path,
) -> std::io::Result<RetainedBundleOutcomeFacts> {
    let side = |name: &str| -> std::io::Result<RetainedSideOutcomeFacts> {
        let side = directory.join(name);
        let observation = fs::read_to_string(side.join("observation.json"))?;
        let comparison = observation_comparison_fields(&observation)?;
        let effect_failures = parse_semantic_effect_trace(&observation)?
            .iter()
            .filter(|event| event.lifecycle == "failed")
            .count();
        let resource_path = side.join("resource-audit.json");
        let resource_failures = if resource_path.is_file() {
            crate::parse_resource_audit(&fs::read(resource_path)?)?.failure_count()
        } else {
            0
        };
        Ok(RetainedSideOutcomeFacts {
            timed_out: comparison.timed_out,
            status_success: parse_observation_success(&observation)?,
            resource_failures,
            effect_failures,
        })
    };
    Ok(RetainedBundleOutcomeFacts {
        oracle: side("oracle")?,
        candidate: side("candidate")?,
    })
}

/// Revalidates one retained bundle and derives its exact runtime platform
/// closure record from the committed descriptor and causal trace.
///
/// # Errors
///
/// Returns an error when the bundle, descriptor, epoch, or target-scoped
/// semantic evidence is missing, malformed, or inconsistent.
pub fn runtime_platform_shard_for_bundle(
    directory: &Path,
    case: &DifferentialCase,
    platform: hell_builtins::ClaimPlatform,
    candidate_source_sha256: Digest,
    expected_candidate_executable_sha256: Digest,
) -> std::io::Result<Option<RuntimePlatformShard>> {
    let bundle_sha256 = verify_observation_bundle_for_case(directory, case)?;
    runtime_platform_shard_from_verified_bundle(
        directory,
        case,
        platform,
        candidate_source_sha256,
        expected_candidate_executable_sha256,
        bundle_sha256,
    )
}

fn runtime_platform_shard_from_verified_bundle(
    directory: &Path,
    case: &DifferentialCase,
    platform: hell_builtins::ClaimPlatform,
    candidate_source_sha256: Digest,
    expected_candidate_executable_sha256: Digest,
    bundle_sha256: Digest,
) -> std::io::Result<Option<RuntimePlatformShard>> {
    let descriptor = case
        .claim_evidence
        .as_ref()
        .ok_or_else(|| std::io::Error::other("runtime platform case has no descriptor"))?;
    let target_definitions = descriptor
        .semantic_targets
        .iter()
        .filter(|target| {
            runtime_causal_signal(target.causal_signal)
                && [
                    hell_builtins::ClaimPlatform::Linux,
                    hell_builtins::ClaimPlatform::MacOs,
                    hell_builtins::ClaimPlatform::Windows,
                ]
                .iter()
                .all(|required| {
                    target
                        .platforms
                        .contains(&hell_builtins::ClaimPlatform::All)
                        || target.platforms.contains(required)
                })
        })
        .collect::<Vec<_>>();
    if target_definitions.is_empty() {
        return Ok(None);
    }
    let observation = fs::read_to_string(directory.join("candidate").join("observation.json"))?;
    let (candidate_executable_sha256, assurance_epoch_sha256) =
        exact_candidate_identity(&observation)?;
    if candidate_executable_sha256 != expected_candidate_executable_sha256 {
        return Err(std::io::Error::other(
            "candidate observation executable differs from its native shard identity",
        ));
    }
    let obligation_trace_sha256 = semantic_obligation_trace_sha256(&observation)?;
    let manifest = fs::read_to_string(directory.join("bundle-manifest.json"))?;
    let process_helper_sha256 = bundle_manifest_identity(&manifest)?.process_helper_sha256;
    let targets = target_definitions
        .into_iter()
        .map(|target| RuntimePlatformTarget {
            builtin: Arc::clone(&target.builtin),
            dimension: target.dimension,
            obligation_trace_sha256,
        })
        .collect::<Vec<_>>();
    Ok(Some(RuntimePlatformShard {
        platform,
        case_id: Arc::clone(&case.id),
        source_sha256: sha256_file(&directory.join("main.hell"))?,
        candidate_source_sha256,
        assurance_epoch_sha256,
        descriptor_sha256: sha256_file(&directory.join("case.toml"))?,
        candidate_executable_sha256,
        process_helper_sha256,
        bundle_sha256,
        targets,
    }))
}

/// Rederives one collection black-box shard from a verified bilateral bundle.
///
/// `provider` must itself come from the provider-authenticated artifact and
/// exact-attempt selection verifier. This function rehashes every bundle-side
/// field and joins it to those provider facts; it does not authenticate a
/// hand-authored provider record on its own.
///
/// # Errors
///
/// Returns an error when the bundle, exact reviewed collection case,
/// executable identities, acquisition roots, raw/status observations,
/// candidate typed/comparator evidence, or provider platform join differs.
pub fn collection_black_box_shard_for_bundle(
    directory: &Path,
    case: &DifferentialCase,
    source: &CollectionSourceAuthority,
    provider: &CollectionVerifiedProviderRoot,
) -> std::io::Result<CollectionBlackBoxShard> {
    let bundle_sha256 = verify_observation_bundle_for_case(directory, case)?;
    let case = crate::collection_authority::reviewed_collection_case(source, case)
        .map_err(std::io::Error::other)?;
    if provider.platform == hell_builtins::ClaimPlatform::All {
        return Err(std::io::Error::other(
            "collection provider root cannot use aggregate platform All",
        ));
    }
    let oracle_directory = directory.join("oracle");
    let candidate_directory = directory.join("candidate");
    let oracle_document = fs::read_to_string(oracle_directory.join("observation.json"))?;
    let candidate_document = fs::read_to_string(candidate_directory.join("observation.json"))?;
    let oracle_identity = exact_oracle_identity(&oracle_document)?;
    let (candidate_executable_sha256, _) = exact_candidate_identity(&candidate_document)?;
    if oracle_identity.executable != provider.oracle_executable_sha256
        || oracle_identity.acquisition_receipt != Some(provider.oracle_acquisition_receipt_sha256)
        || oracle_identity.acquisition_attestation
            != Some(provider.oracle_provider_attestation_sha256)
        || candidate_executable_sha256 != provider.candidate_executable_sha256
    {
        return Err(std::io::Error::other(
            "collection retained executable/acquisition identity differs from provider root",
        ));
    }
    let (oracle_success, oracle_code) = parse_observation_process_status(&oracle_document)?;
    let (candidate_success, candidate_code) =
        parse_observation_process_status(&candidate_document)?;
    Ok(CollectionBlackBoxShard {
        platform: provider.platform,
        oracle_subject: provider.oracle_subject,
        oracle_source_commit: Arc::clone(&provider.oracle_source_commit),
        oracle_executable_sha256: provider.oracle_executable_sha256,
        oracle_acquisition_receipt_sha256: Some(provider.oracle_acquisition_receipt_sha256),
        oracle_provider_attestation_sha256: Some(provider.oracle_provider_attestation_sha256),
        provider_repository_id: provider.provider_repository_id,
        provider_run_id: provider.provider_run_id,
        provider_run_attempt: provider.provider_run_attempt,
        provider_artifact_id: provider.provider_artifact_id,
        provider_workflow_ref: Arc::clone(&provider.provider_workflow_ref),
        provider_event: Arc::clone(&provider.provider_event),
        provider_candidate_subject_sha256: provider.provider_candidate_subject_sha256,
        oracle_build_record_sha256: provider.oracle_build_record_sha256,
        dependency_authority: provider.dependency_authority,
        bundle_sha256,
        oracle_observation_sha256: sha256_bytes(oracle_document.as_bytes()),
        candidate_observation_sha256: sha256_bytes(candidate_document.as_bytes()),
        oracle_stdout_sha256: sha256_file(&oracle_directory.join("stdout.bin"))?,
        oracle_stderr_sha256: sha256_file(&oracle_directory.join("stderr.raw.bin"))?,
        oracle_status_sha256: crate::process_status_sha256(oracle_success, oracle_code),
        candidate_stdout_sha256: sha256_file(&candidate_directory.join("stdout.bin"))?,
        candidate_stderr_sha256: sha256_file(&candidate_directory.join("stderr.raw.bin"))?,
        candidate_status_sha256: crate::process_status_sha256(candidate_success, candidate_code),
        candidate_typed_result_sha256: parse_optional_digest_field(
            &candidate_document,
            "semanticTypedResultSha256",
        )?,
        candidate_comparator_trace_sha256: case.comparator_contract_sha256,
        oracle_completion: completion(oracle_success),
        candidate_completion: completion(candidate_success),
        candidate_source_commit: Arc::clone(&provider.candidate_source_commit),
        candidate_executable_sha256,
        case,
    })
}

/// Rederives the candidate/oracle observation facts from one exact reviewed
/// collection bundle without accepting provider facts from the caller.
///
/// Provider/API/ZIP authentication remains the responsibility of the offline
/// campaign importer. This parser supplies only facts that are cryptographically
/// bound to the already verified observation bundle.
///
/// # Errors
///
/// Returns an error when the bundle or reviewed case authority is invalid.
pub fn collection_bundle_facts(
    directory: &Path,
    case: &DifferentialCase,
    source: &CollectionSourceAuthority,
) -> std::io::Result<CollectionBundleFacts> {
    let bundle_sha256 = verify_observation_bundle_for_case(directory, case)?;
    let case = crate::collection_authority::reviewed_collection_case(source, case)
        .map_err(std::io::Error::other)?;
    let oracle_directory = directory.join("oracle");
    let candidate_directory = directory.join("candidate");
    let oracle_document = fs::read_to_string(oracle_directory.join("observation.json"))?;
    let candidate_document = fs::read_to_string(candidate_directory.join("observation.json"))?;
    let oracle_identity = exact_oracle_identity(&oracle_document)?;
    let (candidate_executable_sha256, _) = exact_candidate_identity(&candidate_document)?;
    let (oracle_success, oracle_code) = parse_observation_process_status(&oracle_document)?;
    let (candidate_success, candidate_code) =
        parse_observation_process_status(&candidate_document)?;
    let candidate_comparator_trace_sha256 = case.comparator_contract_sha256;
    Ok(CollectionBundleFacts {
        case,
        bundle_sha256,
        oracle_observation_sha256: sha256_bytes(oracle_document.as_bytes()),
        candidate_observation_sha256: sha256_bytes(candidate_document.as_bytes()),
        oracle_stdout_sha256: sha256_file(&oracle_directory.join("stdout.bin"))?,
        oracle_stderr_sha256: sha256_file(&oracle_directory.join("stderr.raw.bin"))?,
        oracle_status_sha256: crate::process_status_sha256(oracle_success, oracle_code),
        candidate_stdout_sha256: sha256_file(&candidate_directory.join("stdout.bin"))?,
        candidate_stderr_sha256: sha256_file(&candidate_directory.join("stderr.raw.bin"))?,
        candidate_status_sha256: crate::process_status_sha256(candidate_success, candidate_code),
        candidate_typed_result_sha256: parse_optional_digest_field(
            &candidate_document,
            "semanticTypedResultSha256",
        )?,
        candidate_comparator_trace_sha256,
        oracle_completion: completion(oracle_success),
        candidate_completion: completion(candidate_success),
        oracle_executable_sha256: oracle_identity.executable,
        oracle_acquisition_receipt_sha256: oracle_identity.acquisition_receipt,
        oracle_acquisition_attestation_sha256: oracle_identity.acquisition_attestation,
        candidate_executable_sha256,
    })
}

#[derive(Clone, Copy)]
struct RetainedOracleIdentity {
    executable: Digest,
    acquisition_receipt: Option<Digest>,
    acquisition_attestation: Option<Digest>,
}

fn exact_oracle_identity(document: &str) -> std::io::Result<RetainedOracleIdentity> {
    let mut lines = document.lines();
    for expected in [
        "{",
        "  \"identity\": {",
        "  \"schemaVersion\": 3,",
        "  \"role\": \"Oracle\",",
    ] {
        if lines.next() != Some(expected) {
            return Err(std::io::Error::other(
                "oracle observation identity prefix is noncanonical",
            ));
        }
    }
    exact_identity_string_line(lines.next(), "path", true)?;
    let executable_sha256 = exact_identity_digest_line(lines.next(), "sha256")?;
    exact_identity_string_line(lines.next(), "reportedVersion", true)?;
    exact_identity_digest_line(lines.next(), "assuranceEpochSha256")?;
    let acquisition_receipt_id =
        exact_optional_identity_string_line(lines.next(), "acquisitionReceiptId")?;
    let acquisition_receipt_sha256 =
        exact_optional_identity_digest_line(lines.next(), "acquisitionReceiptSha256")?;
    let acquisition_attestation_sha256 =
        exact_optional_identity_digest_line(lines.next(), "acquisitionAttestationSha256")?;
    if acquisition_receipt_id.is_some() != acquisition_receipt_sha256.is_some() {
        return Err(std::io::Error::other(
            "oracle acquisition receipt ID and digest presence differ",
        ));
    }
    let build_info = lines
        .next()
        .and_then(|line| line.strip_prefix("  \"buildInfo\": "))
        .ok_or_else(|| std::io::Error::other("oracle build info is malformed"))?;
    if build_info != "null" && !canonical_json_string_array(build_info) {
        return Err(std::io::Error::other("oracle build info is noncanonical"));
    }
    if lines.next() != Some("},") {
        return Err(std::io::Error::other(
            "oracle observation identity has unknown or missing fields",
        ));
    }
    Ok(RetainedOracleIdentity {
        executable: executable_sha256,
        acquisition_receipt: acquisition_receipt_sha256,
        acquisition_attestation: acquisition_attestation_sha256,
    })
}

fn completion(success: bool) -> CollectionCompletion {
    if success {
        CollectionCompletion::Success
    } else {
        CollectionCompletion::Failure
    }
}

fn exact_candidate_identity(document: &str) -> std::io::Result<(Digest, Digest)> {
    let mut lines = document.lines();
    let expected = [
        "{",
        "  \"identity\": {",
        "  \"schemaVersion\": 3,",
        "  \"role\": \"Candidate\",",
    ];
    for expected in expected {
        if lines.next() != Some(expected) {
            return Err(std::io::Error::other(
                "candidate observation identity prefix is not canonical",
            ));
        }
    }
    exact_identity_string_line(lines.next(), "path", true)?;
    let sha256 = exact_identity_digest_line(lines.next(), "sha256")?;
    exact_identity_string_line(lines.next(), "reportedVersion", true)?;
    let epoch = exact_identity_digest_line(lines.next(), "assuranceEpochSha256")?;
    for field in [
        "acquisitionReceiptId",
        "acquisitionReceiptSha256",
        "acquisitionAttestationSha256",
    ] {
        if lines.next() != Some(format!("  \"{field}\": null,").as_str()) {
            return Err(std::io::Error::other(
                "candidate identity carries unexpected acquisition fields",
            ));
        }
    }
    let build_info = lines
        .next()
        .and_then(|line| line.strip_prefix("  \"buildInfo\": "))
        .ok_or_else(|| std::io::Error::other("candidate identity build info is malformed"))?;
    if build_info != "null" && !canonical_json_string_array(build_info) {
        return Err(std::io::Error::other(
            "candidate identity build info is malformed",
        ));
    }
    if lines.next() != Some("},") {
        return Err(std::io::Error::other(
            "candidate observation identity has unknown or missing fields",
        ));
    }
    Ok((sha256, epoch))
}

fn exact_identity_digest_line(line: Option<&str>, field: &str) -> std::io::Result<Digest> {
    let prefix = format!("  \"{field}\": \"");
    let value = line
        .and_then(|line| line.strip_prefix(&prefix))
        .and_then(|line| line.strip_suffix("\","))
        .ok_or_else(|| std::io::Error::other(format!("candidate identity {field} is malformed")))?;
    let digest = Digest::from_hex(value).map_err(std::io::Error::other)?;
    if digest.hex() != value {
        return Err(std::io::Error::other(format!(
            "candidate identity {field} is noncanonical"
        )));
    }
    Ok(digest)
}

fn exact_optional_identity_digest_line(
    line: Option<&str>,
    field: &str,
) -> std::io::Result<Option<Digest>> {
    if line == Some(format!("  \"{field}\": null,").as_str()) {
        return Ok(None);
    }
    exact_identity_digest_line(line, field).map(Some)
}

fn exact_optional_identity_string_line(
    line: Option<&str>,
    field: &str,
) -> std::io::Result<Option<()>> {
    if line == Some(format!("  \"{field}\": null,").as_str()) {
        return Ok(None);
    }
    exact_identity_string_line(line, field, true).map(Some)
}

fn exact_identity_string_line(line: Option<&str>, field: &str, comma: bool) -> std::io::Result<()> {
    let prefix = format!("  \"{field}\": \"");
    let suffix = if comma { "\"," } else { "\"" };
    let encoded = line
        .and_then(|line| line.strip_prefix(&prefix))
        .and_then(|line| line.strip_suffix(suffix))
        .ok_or_else(|| std::io::Error::other(format!("candidate identity {field} is malformed")))?;
    canonical_json_string_contents(encoded)
        .then_some(())
        .ok_or_else(|| std::io::Error::other(format!("candidate identity {field} is noncanonical")))
}

fn canonical_json_string_array(value: &str) -> bool {
    let Some(mut contents) = value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
    else {
        return false;
    };
    if contents.is_empty() {
        return true;
    }
    loop {
        let Some(quoted) = contents.strip_prefix('"') else {
            return false;
        };
        let Some(end) = canonical_json_string_end(quoted) else {
            return false;
        };
        if !canonical_json_string_contents(&quoted[..end]) {
            return false;
        }
        contents = &quoted[end + 1..];
        if contents.is_empty() {
            return true;
        }
        let Some(next) = contents.strip_prefix(", ") else {
            return false;
        };
        contents = next;
    }
}

fn canonical_json_string_end(value: &str) -> Option<usize> {
    let mut escaped = false;
    for (index, character) in value.char_indices() {
        if escaped {
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == '"' {
            return Some(index);
        }
    }
    None
}

fn canonical_json_string_contents(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'"' | 0..=0x1f => return false,
            b'\\' => {
                let Some(escape) = bytes.get(index + 1).copied() else {
                    return false;
                };
                match escape {
                    b'"' | b'\\' | b'n' | b'r' | b't' => index += 2,
                    b'u' => {
                        let Some(hex) = bytes.get(index + 2..index + 6) else {
                            return false;
                        };
                        let Ok(hex) = std::str::from_utf8(hex) else {
                            return false;
                        };
                        let Ok(code) = u8::from_str_radix(hex, 16) else {
                            return false;
                        };
                        if code > 0x1f || matches!(code, b'\n' | b'\r' | b'\t') {
                            return false;
                        }
                        if format!("{code:04x}") != hex {
                            return false;
                        }
                        index += 6;
                    }
                    _ => return false,
                }
            }
            _ => index += 1,
        }
    }
    true
}

fn runtime_causal_signal(signal: CausalSignal) -> bool {
    matches!(
        signal,
        CausalSignal::RuntimeAdapter
            | CausalSignal::RuntimeAdapterAndForceTrace
            | CausalSignal::ForceTrace
            | CausalSignal::EffectEvent
            | CausalSignal::TaskAndCancellation
            | CausalSignal::PresentationField
            | CausalSignal::ResourceLifecycle
    )
}

fn semantic_obligation_trace_sha256(document: &str) -> std::io::Result<Digest> {
    let prefix = "  \"semanticObligationTrace\": [";
    let mut values = document
        .lines()
        .filter_map(|line| line.strip_prefix(prefix));
    let value = values
        .next()
        .and_then(|line| line.strip_suffix("],"))
        .ok_or_else(|| std::io::Error::other("semantic obligation trace is malformed"))?;
    if value.is_empty() || values.next().is_some() {
        return Err(std::io::Error::other(
            "semantic obligation trace is empty or repeated",
        ));
    }
    Ok(sha256_bytes(value.as_bytes()))
}

/// Mechanically classified equality of the retained candidate/oracle pair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObservationEquivalence {
    /// Harness-normalized, pre-claim-normalizer observations are identical.
    Exact,
    /// The declared typed claim normalizers are required for equality.
    Normalized(Vec<NormalizerId>),
    /// A reviewed failing runtime case differs only in host error prose that
    /// is outside every declared Presentation target.
    ReviewedRuntimeFailureStderr(Vec<RetainedMismatchFact>),
    /// One exact Windows upstream presentation dialect differs while every
    /// non-stream observation and target-scoped semantic cause agrees.
    ReviewedWindowsPresentation(crate::WindowsPresentationField, Vec<RetainedMismatchFact>),
    /// A complete reviewed Windows process-lifecycle divergence is retained
    /// with both exact sides and its committed mismatch fingerprint.
    ReviewedWindowsDivergence(Vec<RetainedMismatchFact>),
}

/// One canonical retained mismatch category and its bounded side digests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetainedMismatchFact {
    pub category: crate::MismatchKind,
    pub oracle_sha256: Digest,
    pub candidate_sha256: Digest,
}

/// Strict mechanical classification of a retained observation bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RetainedObservationClassification {
    Exact,
    ProjectedRuntimeFailureStderr {
        raw_mismatches: Vec<RetainedMismatchFact>,
    },
    ProjectedWindowsPresentation {
        field: crate::WindowsPresentationField,
        raw_mismatches: Vec<RetainedMismatchFact>,
    },
    ProjectedWindowsDivergence {
        raw_mismatches: Vec<RetainedMismatchFact>,
    },
    Normalized {
        normalizers: Vec<NormalizerId>,
        raw_mismatches: Vec<RetainedMismatchFact>,
        fingerprint_sha256: Digest,
    },
    Mismatch {
        raw_mismatches: Vec<RetainedMismatchFact>,
        normalized_mismatches: Vec<RetainedMismatchFact>,
        fingerprint_sha256: Digest,
    },
}

fn projected_windows_divergence(
    raw_mismatches: Vec<RetainedMismatchFact>,
    mismatch_kinds: &[crate::MismatchKind],
) -> std::io::Result<RetainedObservationClassification> {
    let observed_kinds = raw_mismatches
        .iter()
        .map(|mismatch| mismatch.category)
        .collect::<Vec<_>>();
    if observed_kinds != mismatch_kinds {
        return Err(std::io::Error::other(
            "reviewed Windows divergence lacks its exact raw mismatch fields",
        ));
    }
    Ok(RetainedObservationClassification::ProjectedWindowsDivergence { raw_mismatches })
}

/// Strictly classifies exact, normalized, or mismatching retained evidence.
///
/// A `Mismatch` remains an observation fact, not an acceptance decision. Its
/// canonical fingerprint and typed categories are intended to be bound by a
/// separately authorized divergence review.
///
/// # Errors
///
/// Returns an error when bundle identity, inventory, case source, mismatch
/// schema, or retained side digests are malformed or inconsistent.
pub fn classify_retained_observation_bundle(
    directory: &Path,
    case: &DifferentialCase,
) -> std::io::Result<RetainedObservationClassification> {
    verify_observation_bundle_for_case(directory, case)?;
    let raw_mismatches = raw_mismatch_facts(directory)?;
    let summary = fs::read_to_string(directory.join("mismatch-summary.json"))?;
    let normalized_mismatches = parse_mismatch_summary(&summary)?;
    verify_mismatch_fact_bytes(directory, &normalized_mismatches)?;
    let (projection, recomputed) = recompute_projected_mismatch_sides(directory, case)?;
    let recomputed = recomputed
        .into_iter()
        .map(|side| side.fact)
        .collect::<Vec<_>>();
    if recomputed != normalized_mismatches {
        return Err(std::io::Error::other(
            "retained mismatch summary omits or substitutes an observation difference",
        ));
    }
    let normalizers = applied_claim_normalizers(case);
    let fingerprint_sha256 = mismatch_fingerprint(
        &case.id,
        &normalizers,
        &raw_mismatches,
        &normalized_mismatches,
    );
    if normalized_mismatches.is_empty()
        && matches!(
            &projection,
            crate::DifferentialComparisonProjection::ReviewedRuntimeFailureStderr { .. }
                | crate::DifferentialComparisonProjection::ReviewedRuntimeFailureExceptionStderr { .. }
        )
    {
        if raw_mismatches.len() != 1 || raw_mismatches[0].category != crate::MismatchKind::Stderr {
            return Err(std::io::Error::other(
                "reviewed failure projection lacks its retained raw stderr difference",
            ));
        }
        Ok(RetainedObservationClassification::ProjectedRuntimeFailureStderr { raw_mismatches })
    } else if normalized_mismatches.is_empty()
        && matches!(
            &projection,
            crate::DifferentialComparisonProjection::ReviewedWindowsPresentation { .. }
        )
    {
        let crate::DifferentialComparisonProjection::ReviewedWindowsPresentation {
            platform,
            field,
            ..
        } = projection
        else {
            unreachable!("projection variant was matched above")
        };
        if platform != hell_builtins::ClaimPlatform::Windows
            || raw_mismatches.len() != 1
            || raw_mismatches[0].category != field.mismatch_kind()
        {
            return Err(std::io::Error::other(
                "reviewed Windows projection lacks its exact target and raw field",
            ));
        }
        Ok(
            RetainedObservationClassification::ProjectedWindowsPresentation {
                field,
                raw_mismatches,
            },
        )
    } else if normalized_mismatches.is_empty()
        && matches!(
            &projection,
            crate::DifferentialComparisonProjection::ReviewedWindowsDivergence { .. }
        )
    {
        let crate::DifferentialComparisonProjection::ReviewedWindowsDivergence {
            mismatch_kinds,
            ..
        } = projection
        else {
            unreachable!("projection variant was matched above")
        };
        projected_windows_divergence(raw_mismatches, mismatch_kinds)
    } else if normalized_mismatches.is_empty() {
        if raw_mismatches.is_empty() {
            Ok(RetainedObservationClassification::Exact)
        } else if normalizers.is_empty() {
            Err(std::io::Error::other(
                "retained equality differs before undeclared claim normalization",
            ))
        } else {
            Ok(RetainedObservationClassification::Normalized {
                normalizers,
                raw_mismatches,
                fingerprint_sha256,
            })
        }
    } else {
        Ok(RetainedObservationClassification::Mismatch {
            raw_mismatches,
            normalized_mismatches,
            fingerprint_sha256,
        })
    }
}

struct RetainedMismatchSide {
    fact: RetainedMismatchFact,
    oracle: Vec<u8>,
    candidate: Vec<u8>,
}

struct ObservationComparisonFields<'a> {
    mode: &'a str,
    timed_out: bool,
    status: &'a str,
    diagnostic: &'a str,
    filesystem: &'a str,
}

fn recompute_mismatch_sides(directory: &Path) -> std::io::Result<Vec<RetainedMismatchSide>> {
    recompute_mismatch_sides_between(&directory.join("oracle"), &directory.join("candidate"))
}

fn recompute_projected_mismatch_sides(
    directory: &Path,
    case: &DifferentialCase,
) -> std::io::Result<(
    crate::DifferentialComparisonProjection,
    Vec<RetainedMismatchSide>,
)> {
    let mut mismatches = recompute_mismatch_sides(directory)?;
    let authority = mismatches
        .iter()
        .map(|mismatch| {
            Ok((
                mismatch.fact.category,
                mismatch.fact.oracle_sha256,
                mismatch.fact.candidate_sha256,
                u64::try_from(mismatch.oracle.len()).map_err(|_| {
                    std::io::Error::other("retained oracle presentation is too large")
                })?,
                u64::try_from(mismatch.candidate.len()).map_err(|_| {
                    std::io::Error::other("retained candidate presentation is too large")
                })?,
            ))
        })
        .collect::<std::io::Result<Vec<_>>>()?;
    let raw_projection_mismatches = mismatches
        .iter()
        .map(|mismatch| crate::DifferentialMismatch {
            kind: mismatch.fact.category,
            oracle: mismatch.oracle.clone(),
            candidate: mismatch.candidate.clone(),
        })
        .collect::<Vec<_>>();
    let projection = match crate::windows_divergences::retained_windows_divergence_projection(
        &case.id,
        &raw_projection_mismatches,
    ) {
        Some(reviewed) => reviewed,
        None => match crate::windows_presentation::retained_windows_presentation_projection(
            case, &authority,
        ) {
            Some(reviewed) => reviewed,
            None => retained_runtime_failure_stderr_projection(directory, case)?,
        },
    };
    let projected_field = match &projection {
        crate::DifferentialComparisonProjection::ReviewedRuntimeFailureStderr { .. }
        | crate::DifferentialComparisonProjection::ReviewedRuntimeFailureExceptionStderr {
            ..
        } => Some(crate::MismatchKind::Stderr),
        crate::DifferentialComparisonProjection::ReviewedWindowsPresentation { field, .. } => {
            Some(field.mismatch_kind())
        }
        crate::DifferentialComparisonProjection::ReviewedWindowsDivergence { .. }
        | crate::DifferentialComparisonProjection::Exact => None,
    };
    if let Some(field) = projected_field {
        mismatches.retain(|mismatch| mismatch.fact.category != field);
    }
    Ok((projection, mismatches))
}

fn retained_runtime_failure_stderr_projection(
    directory: &Path,
    case: &DifferentialCase,
) -> std::io::Result<crate::DifferentialComparisonProjection> {
    if crate::has_runtime_failure_presentation_authority(&case.id) {
        return retained_runtime_failure_exception_stderr_projection(directory, case);
    }
    retained_legacy_runtime_failure_stderr_projection(directory, case)
}

fn retained_runtime_failure_exception_stderr_projection(
    directory: &Path,
    case: &DifferentialCase,
) -> std::io::Result<crate::DifferentialComparisonProjection> {
    let Some(authority) = crate::reviewed_runtime_failure_presentation_authority(case) else {
        return Ok(crate::DifferentialComparisonProjection::Exact);
    };
    let oracle_directory = directory.join("oracle");
    let candidate_directory = directory.join("candidate");
    let oracle_document = fs::read_to_string(oracle_directory.join("observation.json"))?;
    let candidate_document = fs::read_to_string(candidate_directory.join("observation.json"))?;
    let oracle = observation_comparison_fields(&oracle_document)?;
    let candidate = observation_comparison_fields(&candidate_document)?;
    if oracle.mode != "Run"
        || candidate.mode != "Run"
        || oracle.timed_out
        || candidate.timed_out
        || observation_status_success(oracle.status)?
        || observation_status_success(candidate.status)?
        || oracle.status != candidate.status
        || oracle.filesystem != candidate.filesystem
        || fs::read(oracle_directory.join("stdout.bin"))?
            != fs::read(candidate_directory.join("stdout.bin"))?
    {
        return Ok(crate::DifferentialComparisonProjection::Exact);
    }
    let oracle_stderr = fs::read(oracle_directory.join("stderr.bin"))?;
    let candidate_stderr = fs::read(candidate_directory.join("stderr.bin"))?;
    let (oracle_bytes, oracle_sha256, oracle_truncated) =
        observation_capture_summary(&oracle_document, "stderr")?;
    let (candidate_bytes, candidate_sha256, candidate_truncated) =
        observation_capture_summary(&candidate_document, "stderr")?;
    if oracle_truncated || candidate_truncated {
        return Ok(crate::DifferentialComparisonProjection::Exact);
    }
    if u64::try_from(oracle_stderr.len()).unwrap_or(u64::MAX) != oracle_bytes
        || u64::try_from(candidate_stderr.len()).unwrap_or(u64::MAX) != candidate_bytes
        || sha256_bytes(&oracle_stderr) != oracle_sha256
        || sha256_bytes(&candidate_stderr) != candidate_sha256
    {
        return Err(std::io::Error::other(
            "retained stderr bytes disagree with their observation identity",
        ));
    }
    if oracle_stderr == candidate_stderr {
        return Ok(crate::DifferentialComparisonProjection::Exact);
    }
    if !retained_runtime_failure_causality(
        &candidate_directory,
        case,
        authority,
        &candidate_document,
    )? {
        return Ok(crate::DifferentialComparisonProjection::Exact);
    }
    let Some(payload_sha256) = crate::reviewed_runtime_failure_payload_sha256(
        authority,
        &oracle_stderr,
        &candidate_stderr,
    ) else {
        return Ok(crate::DifferentialComparisonProjection::Exact);
    };
    Ok(
        crate::DifferentialComparisonProjection::ReviewedRuntimeFailureExceptionStderr {
            exception_family: authority.family,
            payload_sha256,
            oracle_sha256,
            candidate_sha256,
            oracle_bytes,
            candidate_bytes,
        },
    )
}

fn retained_legacy_runtime_failure_stderr_projection(
    directory: &Path,
    case: &DifferentialCase,
) -> std::io::Result<crate::DifferentialComparisonProjection> {
    let Some(builtin) = crate::reviewed_legacy_runtime_failure_stderr_builtin(case) else {
        return Ok(crate::DifferentialComparisonProjection::Exact);
    };
    let oracle_directory = directory.join("oracle");
    let candidate_directory = directory.join("candidate");
    let oracle_document = fs::read_to_string(oracle_directory.join("observation.json"))?;
    let candidate_document = fs::read_to_string(candidate_directory.join("observation.json"))?;
    let oracle = observation_comparison_fields(&oracle_document)?;
    let candidate = observation_comparison_fields(&candidate_document)?;
    if oracle.mode != "Run"
        || candidate.mode != "Run"
        || oracle.timed_out
        || candidate.timed_out
        || observation_status_success(oracle.status)?
        || observation_status_success(candidate.status)?
        || oracle.status != candidate.status
        || oracle.filesystem != candidate.filesystem
        || fs::read(oracle_directory.join("stdout.bin"))?
            != fs::read(candidate_directory.join("stdout.bin"))?
    {
        return Ok(crate::DifferentialComparisonProjection::Exact);
    }
    let oracle_stderr = fs::read(oracle_directory.join("stderr.bin"))?;
    let candidate_stderr = fs::read(candidate_directory.join("stderr.bin"))?;
    let (oracle_bytes, oracle_sha256, oracle_truncated) =
        observation_capture_summary(&oracle_document, "stderr")?;
    let (candidate_bytes, candidate_sha256, candidate_truncated) =
        observation_capture_summary(&candidate_document, "stderr")?;
    if oracle_truncated || candidate_truncated {
        return Ok(crate::DifferentialComparisonProjection::Exact);
    }
    if u64::try_from(oracle_stderr.len()).unwrap_or(u64::MAX) != oracle_bytes
        || u64::try_from(candidate_stderr.len()).unwrap_or(u64::MAX) != candidate_bytes
        || sha256_bytes(&oracle_stderr) != oracle_sha256
        || sha256_bytes(&candidate_stderr) != candidate_sha256
    {
        return Err(std::io::Error::other(
            "retained stderr bytes disagree with their observation identity",
        ));
    }
    if oracle_stderr == candidate_stderr
        || !parse_semantic_coverage(&candidate_document)?
            .contains(&CoverageEvent::EnteredAdapter(builtin))
    {
        return Ok(crate::DifferentialComparisonProjection::Exact);
    }
    let expected_task_trace = crate::reviewed_runtime_failure_expected_task_trace(case, builtin)
        .map_err(|()| std::io::Error::other("reviewed failure task authority is inconsistent"))?;
    if let Some(expected) = expected_task_trace {
        let mut tasks = Vec::<u64>::new();
        let mut events = Vec::new();
        for (task, event_builtin, event) in parse_semantic_task_trace(&candidate_document)? {
            if event_builtin != builtin {
                continue;
            }
            let index = tasks
                .iter()
                .position(|candidate| *candidate == task)
                .unwrap_or_else(|| {
                    tasks.push(task);
                    tasks.len() - 1
                });
            events.push((index, event));
        }
        if crate::task_trace_sha256(events.iter().map(|(task, event)| (*task, event.as_str())))
            != expected
        {
            return Ok(crate::DifferentialComparisonProjection::Exact);
        }
    }
    let effects = parse_semantic_effect_trace(&candidate_document)?
        .into_iter()
        .filter(|event| event.builtin == builtin)
        .collect::<Vec<_>>();
    if effects.len() != 2
        || effects[0].owner_task != effects[1].owner_task
        || effects[0].sequence != effects[1].sequence
        || effects[0].parent_sequence != effects[1].parent_sequence
        || effects[0].lifecycle != "started"
        || effects[1].lifecycle != "failed"
    {
        return Ok(crate::DifferentialComparisonProjection::Exact);
    }
    Ok(
        crate::DifferentialComparisonProjection::ReviewedRuntimeFailureStderr {
            oracle_sha256,
            candidate_sha256,
            oracle_bytes,
            candidate_bytes,
        },
    )
}

fn retained_runtime_failure_causality(
    observation_directory: &Path,
    case: &DifferentialCase,
    authority: crate::RuntimeFailurePresentationAuthority,
    document: &str,
) -> std::io::Result<bool> {
    if crate::runtime_failure_mutant_active("runtime-failure-causal-authority") {
        return Ok(true);
    }
    let Some(target) = crate::runtime_failure_target(case, authority) else {
        return Ok(false);
    };
    let coverage = parse_semantic_coverage(document)?;
    let task_trace = parse_semantic_task_trace(document)?;
    if validate_expected_task_trace(target, authority.builtin, &task_trace).is_err() {
        return Ok(false);
    }
    let effect_trace = parse_semantic_effect_trace(document)?;
    if authority.dimension == hell_builtins::CompatibilityDimension::Effects {
        let effects = effect_trace
            .iter()
            .filter(|event| event.builtin == authority.builtin)
            .collect::<Vec<_>>();
        return Ok(
            coverage.contains(&CoverageEvent::EnteredAdapter(authority.builtin))
                && effects.len() == 2
                && effects[0].owner_task == effects[1].owner_task
                && effects[0].sequence == effects[1].sequence
                && effects[0].parent_sequence == effects[1].parent_sequence
                && effects[0].lifecycle == "started"
                && effects[1].lifecycle == "failed",
        );
    }

    let typed_result = parse_optional_digest_field(document, "semanticTypedResultSha256")?;
    let typed_result_builtin = parse_optional_u16_field(document, "semanticTypedResultBuiltinId")?;
    let boundaries = parse_semantic_boundaries(document)?;
    let resource_trace = parse_semantic_resource_trace(document)?;
    let obligation_trace = parse_semantic_obligation_trace(document)?;
    Ok(validate_obligation_semantics(
        authority.obligation,
        authority.dimension,
        authority.builtin,
        document,
        observation_directory,
        &coverage,
        &effect_trace,
        &task_trace,
        &resource_trace,
        &obligation_trace,
        typed_result,
        typed_result_builtin,
        &boundaries,
        &target.platforms,
        target.expected_raw_presentation_sha256,
        target.expected_presentation_shadow_normalizer,
        target.expected_normalized_presentation_sha256,
        None,
    )
    .is_ok())
}

fn observation_status_success(status: &str) -> std::io::Result<bool> {
    status
        .strip_prefix("{\"success\": ")
        .and_then(|status| status.split_once(", \"code\": "))
        .and_then(|(success, _)| match success {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        })
        .ok_or_else(|| std::io::Error::other("observation status success is malformed"))
}

fn observation_capture_summary(
    document: &str,
    field: &str,
) -> std::io::Result<(u64, Digest, bool)> {
    let value = exact_observation_field(document, field)?;
    let (total_bytes, value) = value
        .strip_prefix("{\"totalBytes\": ")
        .and_then(|value| value.split_once(", \"sha256\": \""))
        .ok_or_else(|| std::io::Error::other("observation capture is malformed"))?;
    let (sha256, truncated) = value
        .split_once("\", \"truncated\": ")
        .and_then(|(sha256, truncated)| {
            truncated
                .strip_suffix('}')
                .map(|truncated| (sha256, truncated))
        })
        .ok_or_else(|| std::io::Error::other("observation capture is malformed"))?;
    let total_bytes = total_bytes
        .parse::<u64>()
        .ok()
        .filter(|parsed| parsed.to_string() == total_bytes)
        .ok_or_else(|| std::io::Error::other("observation capture size is noncanonical"))?;
    let sha256 = Digest::from_hex(sha256).map_err(std::io::Error::other)?;
    let truncated = match truncated {
        "true" => true,
        "false" => false,
        _ => {
            return Err(std::io::Error::other(
                "observation capture truncation is malformed",
            ));
        }
    };
    Ok((total_bytes, sha256, truncated))
}

fn recompute_mismatch_sides_between(
    oracle_directory: &Path,
    candidate_directory: &Path,
) -> std::io::Result<Vec<RetainedMismatchSide>> {
    let oracle_document = fs::read_to_string(oracle_directory.join("observation.json"))?;
    let candidate_document = fs::read_to_string(candidate_directory.join("observation.json"))?;
    let oracle = observation_comparison_fields(&oracle_document)?;
    let candidate = observation_comparison_fields(&candidate_document)?;
    if oracle.mode != candidate.mode {
        return Err(std::io::Error::other(
            "oracle and candidate observation modes disagree",
        ));
    }
    let mut mismatches = Vec::new();
    push_retained_mismatch(
        &mut mismatches,
        crate::MismatchKind::Timeout,
        vec![u8::from(oracle.timed_out)],
        vec![u8::from(candidate.timed_out)],
    );
    push_retained_mismatch(
        &mut mismatches,
        crate::MismatchKind::ExitStatus,
        oracle.status.as_bytes().to_vec(),
        candidate.status.as_bytes().to_vec(),
    );
    push_retained_file_mismatch(
        &mut mismatches,
        oracle_directory,
        candidate_directory,
        crate::MismatchKind::Stdout,
        "stdout.bin",
    )?;
    if oracle.mode == "Check" {
        push_retained_mismatch(
            &mut mismatches,
            crate::MismatchKind::Diagnostic,
            oracle.diagnostic.as_bytes().to_vec(),
            candidate.diagnostic.as_bytes().to_vec(),
        );
    } else {
        push_retained_file_mismatch(
            &mut mismatches,
            oracle_directory,
            candidate_directory,
            crate::MismatchKind::Stderr,
            "stderr.bin",
        )?;
    }
    push_retained_mismatch(
        &mut mismatches,
        crate::MismatchKind::Filesystem,
        oracle.filesystem.as_bytes().to_vec(),
        candidate.filesystem.as_bytes().to_vec(),
    );
    Ok(mismatches)
}

fn push_retained_file_mismatch(
    mismatches: &mut Vec<RetainedMismatchSide>,
    oracle_directory: &Path,
    candidate_directory: &Path,
    category: crate::MismatchKind,
    file: &str,
) -> std::io::Result<()> {
    push_retained_mismatch(
        mismatches,
        category,
        fs::read(oracle_directory.join(file))?,
        fs::read(candidate_directory.join(file))?,
    );
    Ok(())
}

fn push_retained_mismatch(
    mismatches: &mut Vec<RetainedMismatchSide>,
    category: crate::MismatchKind,
    oracle: Vec<u8>,
    candidate: Vec<u8>,
) {
    if oracle != candidate {
        mismatches.push(RetainedMismatchSide {
            fact: RetainedMismatchFact {
                category,
                oracle_sha256: sha256_bytes(&oracle),
                candidate_sha256: sha256_bytes(&candidate),
            },
            oracle,
            candidate,
        });
    }
}

fn observation_comparison_fields(
    document: &str,
) -> std::io::Result<ObservationComparisonFields<'_>> {
    let mode = exact_observation_field(document, "mode")?;
    let mode = unquote_simple(mode)
        .filter(|mode| matches!(*mode, "Check" | "Run"))
        .ok_or_else(|| std::io::Error::other("observation mode is malformed"))?;
    let timed_out = match exact_observation_field(document, "timedOut")? {
        "true" => true,
        "false" => false,
        _ => return Err(std::io::Error::other("observation timeout is malformed")),
    };
    let status = exact_observation_field(document, "status")?;
    validate_status_value(status)?;
    let diagnostic = exact_observation_field(document, "diagnostic")?;
    validate_diagnostic_value(diagnostic)?;
    let filesystem = exact_observation_field(document, "filesystem")?;
    validate_filesystem_value(filesystem)?;
    Ok(ObservationComparisonFields {
        mode,
        timed_out,
        status,
        diagnostic,
        filesystem,
    })
}

fn exact_observation_field<'a>(document: &'a str, field: &str) -> std::io::Result<&'a str> {
    let prefix = format!("  \"{field}\": ");
    let mut values = document
        .lines()
        .filter_map(|line| line.strip_prefix(&prefix));
    let value = values
        .next()
        .map(|value| value.strip_suffix(',').unwrap_or(value))
        .ok_or_else(|| std::io::Error::other(format!("observation {field} is missing")))?;
    if values.next().is_some() {
        return Err(std::io::Error::other(format!(
            "observation {field} is repeated"
        )));
    }
    Ok(value)
}

fn validate_status_value(value: &str) -> std::io::Result<()> {
    let (success, code) = value
        .strip_prefix("{\"success\": ")
        .and_then(|value| value.strip_suffix('}'))
        .and_then(|value| value.split_once(", \"code\": "))
        .ok_or_else(|| std::io::Error::other("observation status is malformed"))?;
    if !matches!(success, "true" | "false")
        || (code != "null"
            && code.parse::<i32>().ok().map(|parsed| parsed.to_string()) != Some(code.to_owned()))
    {
        return Err(std::io::Error::other("observation status is noncanonical"));
    }
    Ok(())
}

fn validate_diagnostic_value(value: &str) -> std::io::Result<()> {
    if value == "null" {
        return Ok(());
    }
    let (phase, identity) = value
        .strip_prefix("{\"phase\": \"")
        .and_then(|value| value.strip_suffix('}'))
        .and_then(|value| value.split_once("\", \"code\": \""))
        .ok_or_else(|| std::io::Error::other("observation diagnostic is malformed"))?;
    let (code, identity) = identity
        .split_once("\", \"category\": \"")
        .ok_or_else(|| std::io::Error::other("observation diagnostic is malformed"))?;
    let (category, identity) = identity
        .split_once("\", \"protectedMessage\": \"")
        .ok_or_else(|| std::io::Error::other("observation diagnostic is malformed"))?;
    let (protected_message, coordinates) = identity
        .split_once("\", \"line\": ")
        .ok_or_else(|| std::io::Error::other("observation diagnostic is malformed"))?;
    let (line, column) = coordinates
        .split_once(", \"column\": ")
        .ok_or_else(|| std::io::Error::other("observation diagnostic is malformed"))?;
    if !matches!(
        (phase, code, category, protected_message),
        ("Parse", "H0200", "Syntax", "syntax-error")
            | (
                "StaticSemantics",
                "H0402",
                "NameResolution",
                "unresolved-name"
            )
    ) || !canonical_positive_usize(line)
        || !canonical_positive_usize(column)
    {
        return Err(std::io::Error::other(
            "observation diagnostic is noncanonical",
        ));
    }
    Ok(())
}

fn canonical_positive_usize(value: &str) -> bool {
    value
        .parse::<usize>()
        .ok()
        .filter(|parsed| *parsed != 0)
        .is_some_and(|parsed| parsed.to_string() == value)
}

fn validate_filesystem_value(value: &str) -> std::io::Result<()> {
    let body = value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .ok_or_else(|| std::io::Error::other("observation filesystem is malformed"))?;
    let entries = crate::split_canonical_array(body)
        .ok_or_else(|| std::io::Error::other("observation filesystem array is malformed"))?;
    let mut previous_path = None;
    for entry in entries {
        let fields = entry
            .strip_prefix("{\"path\": ")
            .and_then(|entry| entry.strip_suffix('}'))
            .ok_or_else(|| std::io::Error::other("filesystem entry is malformed"))?;
        let (path, fields) = crate::split_top_level_once(fields, ", \"kind\": ")
            .ok_or_else(|| std::io::Error::other("filesystem path is malformed"))?;
        let path_contents = path
            .strip_prefix('"')
            .and_then(|path| path.strip_suffix('"'))
            .filter(|path| canonical_json_string_contents(path))
            .ok_or_else(|| std::io::Error::other("filesystem path is noncanonical"))?;
        if previous_path.is_some_and(|previous| previous >= path_contents) {
            return Err(std::io::Error::other(
                "filesystem paths are duplicated or unordered",
            ));
        }
        previous_path = Some(path_contents);
        let (kind, fields) = crate::split_top_level_once(fields, ", \"size\": ")
            .ok_or_else(|| std::io::Error::other("filesystem kind is malformed"))?;
        if !matches!(kind, "\"Directory\"" | "\"File\"" | "\"SymbolicLink\"") {
            return Err(std::io::Error::other("filesystem kind is unknown"));
        }
        let (size, fields) = crate::split_top_level_once(fields, ", \"sha256\": ")
            .ok_or_else(|| std::io::Error::other("filesystem size is malformed"))?;
        if size
            .parse::<u64>()
            .ok()
            .is_none_or(|parsed| parsed.to_string() != size)
        {
            return Err(std::io::Error::other("filesystem size is noncanonical"));
        }
        let (sha256, fields) = crate::split_top_level_once(fields, ", \"truncated\": ")
            .ok_or_else(|| std::io::Error::other("filesystem digest is malformed"))?;
        if sha256 != "null"
            && sha256
                .strip_prefix('"')
                .and_then(|sha256| sha256.strip_suffix('"'))
                .and_then(|sha256| Digest::from_hex(sha256).ok())
                .is_none()
        {
            return Err(std::io::Error::other("filesystem digest is noncanonical"));
        }
        let (truncated, contents) = crate::split_top_level_once(fields, ", \"retainedContents\": ")
            .ok_or_else(|| std::io::Error::other("filesystem contents are malformed"))?;
        if !matches!(truncated, "true" | "false") || !canonical_byte_array(contents) {
            return Err(std::io::Error::other(
                "filesystem truncation or contents are noncanonical",
            ));
        }
    }
    Ok(())
}

fn canonical_byte_array(value: &str) -> bool {
    value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .is_some_and(|contents| {
            contents.is_empty()
                || contents.split(", ").all(|byte| {
                    byte.parse::<u8>()
                        .ok()
                        .is_some_and(|parsed| parsed.to_string() == byte)
                })
        })
}

fn retain_mismatch_fact_bytes(
    directory: &Path,
    mismatches: &[RetainedMismatchSide],
) -> std::io::Result<()> {
    if mismatches.is_empty() {
        return Ok(());
    }
    let mismatch_directory = directory.join("mismatches");
    fs::create_dir(&mismatch_directory)?;
    for mismatch in mismatches {
        let category = mismatch_kind_name(mismatch.fact.category);
        write_atomic(
            &mismatch_directory.join(format!("{category}.oracle.bin")),
            &mismatch.oracle,
        )?;
        write_atomic(
            &mismatch_directory.join(format!("{category}.candidate.bin")),
            &mismatch.candidate,
        )?;
    }
    Ok(())
}

fn verify_mismatch_fact_bytes(
    directory: &Path,
    facts: &[RetainedMismatchFact],
) -> std::io::Result<()> {
    let mismatch_directory = directory.join("mismatches");
    for fact in facts {
        let category = mismatch_kind_name(fact.category);
        if sha256_file(&mismatch_directory.join(format!("{category}.oracle.bin")))?
            != fact.oracle_sha256
            || sha256_file(&mismatch_directory.join(format!("{category}.candidate.bin")))?
                != fact.candidate_sha256
        {
            return Err(std::io::Error::other(
                "mismatch fact differs from its retained side bytes",
            ));
        }
    }
    Ok(())
}

fn raw_mismatch_facts(directory: &Path) -> std::io::Result<Vec<RetainedMismatchFact>> {
    raw_mismatch_facts_between(&directory.join("oracle"), &directory.join("candidate"))
}

fn raw_mismatch_facts_between(
    oracle_directory: &Path,
    candidate_directory: &Path,
) -> std::io::Result<Vec<RetainedMismatchFact>> {
    let mut facts = Vec::new();
    for (category, file) in [
        (crate::MismatchKind::Stdout, "stdout.bin"),
        (crate::MismatchKind::Stderr, "stderr.claim-input.bin"),
    ] {
        let oracle = fs::read(oracle_directory.join(file))?;
        let candidate = fs::read(candidate_directory.join(file))?;
        if oracle != candidate {
            facts.push(RetainedMismatchFact {
                category,
                oracle_sha256: sha256_bytes(&oracle),
                candidate_sha256: sha256_bytes(&candidate),
            });
        }
    }
    Ok(facts)
}

fn mismatch_summary_json(facts: &[RetainedMismatchFact]) -> String {
    let mut output = String::from("{\n  \"schemaVersion\": 1,\n  \"mismatches\": [");
    for (index, fact) in facts.iter().enumerate() {
        if index != 0 {
            output.push_str(", ");
        }
        output.push_str("{\"category\": ");
        push_json_string(&mut output, mismatch_kind_name(fact.category));
        output.push_str(", \"oracleSha256\": ");
        push_json_string(&mut output, &fact.oracle_sha256.hex());
        output.push_str(", \"candidateSha256\": ");
        push_json_string(&mut output, &fact.candidate_sha256.hex());
        output.push('}');
    }
    output.push_str("]\n}\n");
    output
}

fn comparison_projection_json(projection: &crate::DifferentialComparisonProjection) -> String {
    match projection {
        crate::DifferentialComparisonProjection::Exact => concat!(
            "{\n",
            "  \"schemaVersion\": 1,\n",
            "  \"kind\": \"exact\"\n",
            "}\n"
        )
        .to_owned(),
        crate::DifferentialComparisonProjection::ReviewedRuntimeFailureStderr {
            oracle_sha256,
            candidate_sha256,
            oracle_bytes,
            candidate_bytes,
        } => format!(
            concat!(
                "{{\n",
                "  \"schemaVersion\": 1,\n",
                "  \"kind\": \"reviewed-runtime-failure-stderr-out-of-scope\",\n",
                "  \"field\": \"stderr\",\n",
                "  \"oracleSha256\": \"{}\",\n",
                "  \"candidateSha256\": \"{}\",\n",
                "  \"oracleBytes\": {},\n",
                "  \"candidateBytes\": {}\n",
                "}}\n"
            ),
            oracle_sha256.hex(),
            candidate_sha256.hex(),
            oracle_bytes,
            candidate_bytes,
        ),
        crate::DifferentialComparisonProjection::ReviewedRuntimeFailureExceptionStderr {
            exception_family,
            payload_sha256,
            oracle_sha256,
            candidate_sha256,
            oracle_bytes,
            candidate_bytes,
        } => format!(
            concat!(
                "{{\n",
                "  \"schemaVersion\": 2,\n",
                "  \"kind\": \"reviewed-runtime-failure-exception-stderr-out-of-scope\",\n",
                "  \"field\": \"stderr\",\n",
                "  \"exceptionFamily\": \"{}\",\n",
                "  \"payloadSha256\": \"{}\",\n",
                "  \"oracleSha256\": \"{}\",\n",
                "  \"candidateSha256\": \"{}\",\n",
                "  \"oracleBytes\": {},\n",
                "  \"candidateBytes\": {}\n",
                "}}\n"
            ),
            exception_family.descriptor_name(),
            payload_sha256.hex(),
            oracle_sha256.hex(),
            candidate_sha256.hex(),
            oracle_bytes,
            candidate_bytes,
        ),
        crate::DifferentialComparisonProjection::ReviewedWindowsPresentation {
            platform,
            field,
            oracle_sha256,
            candidate_sha256,
            oracle_bytes,
            candidate_bytes,
        } => format!(
            concat!(
                "{{\n",
                "  \"schemaVersion\": 3,\n",
                "  \"kind\": \"reviewed-windows-presentation-out-of-scope\",\n",
                "  \"platform\": \"{}\",\n",
                "  \"field\": \"{}\",\n",
                "  \"oracleSha256\": \"{}\",\n",
                "  \"candidateSha256\": \"{}\",\n",
                "  \"oracleBytes\": {},\n",
                "  \"candidateBytes\": {}\n",
                "}}\n"
            ),
            match platform {
                hell_builtins::ClaimPlatform::Windows => "Windows",
                hell_builtins::ClaimPlatform::All => "All",
                hell_builtins::ClaimPlatform::Linux => "Linux",
                hell_builtins::ClaimPlatform::MacOs => "MacOs",
            },
            field.descriptor_name(),
            oracle_sha256.hex(),
            candidate_sha256.hex(),
            oracle_bytes,
            candidate_bytes,
        ),
        crate::DifferentialComparisonProjection::ReviewedWindowsDivergence {
            case_id,
            builtin,
            mismatch_sha256,
            mismatch_kinds: _,
            rationale,
        } => windows_divergence_projection_json(case_id, builtin, mismatch_sha256, rationale),
    }
}

fn windows_divergence_projection_json(
    case_id: &str,
    builtin: &str,
    mismatch_sha256: &Digest,
    rationale: &str,
) -> String {
    let mut rationale_json = String::new();
    push_json_string(&mut rationale_json, rationale);
    format!(
        concat!(
            "{{\n",
            "  \"schemaVersion\": 4,\n",
            "  \"kind\": \"reviewed-windows-divergence\",\n",
            "  \"caseId\": \"{}\",\n",
            "  \"builtin\": \"{}\",\n",
            "  \"mismatchSha256\": \"{}\",\n",
            "  \"rationale\": {}\n",
            "}}\n"
        ),
        case_id,
        builtin,
        mismatch_sha256.hex(),
        rationale_json,
    )
}

fn parse_windows_comparison_projection_json(
    document: &str,
) -> Option<std::io::Result<crate::DifferentialComparisonProjection>> {
    if !document.starts_with(concat!(
        "{\n",
        "  \"schemaVersion\": 3,\n",
        "  \"kind\": \"reviewed-windows-presentation-out-of-scope\",\n"
    )) {
        return None;
    }
    Some((|| {
        let mut lines = document.lines();
        if lines.next() != Some("{")
            || lines.next() != Some("  \"schemaVersion\": 3,")
            || lines.next() != Some("  \"kind\": \"reviewed-windows-presentation-out-of-scope\",")
            || lines.next() != Some("  \"platform\": \"Windows\",")
        {
            return Err(std::io::Error::other(
                "Windows comparison projection target is malformed",
            ));
        }
        let field = match lines.next() {
            Some("  \"field\": \"stdout\",") => crate::WindowsPresentationField::Stdout,
            Some("  \"field\": \"stderr\",") => crate::WindowsPresentationField::Stderr,
            _ => {
                return Err(std::io::Error::other(
                    "Windows comparison projection field is malformed",
                ));
            }
        };
        let oracle_sha256 = projection_digest_line(lines.next(), "oracleSha256")?;
        let candidate_sha256 = projection_digest_line(lines.next(), "candidateSha256")?;
        let oracle_bytes = projection_u64_line(lines.next(), "oracleBytes")?;
        let candidate_bytes = projection_u64_line(lines.next(), "candidateBytes")?;
        if lines.next() != Some("}") || lines.next().is_some() {
            return Err(std::io::Error::other(
                "Windows comparison projection has unknown fields",
            ));
        }
        let projection = crate::DifferentialComparisonProjection::ReviewedWindowsPresentation {
            platform: hell_builtins::ClaimPlatform::Windows,
            field,
            oracle_sha256,
            candidate_sha256,
            oracle_bytes,
            candidate_bytes,
        };
        if comparison_projection_json(&projection) != document {
            return Err(std::io::Error::other(
                "Windows comparison projection is noncanonical",
            ));
        }
        Ok(projection)
    })())
}

fn parse_windows_divergence_projection_json(
    document: &str,
) -> Option<std::io::Result<crate::DifferentialComparisonProjection>> {
    if !document.starts_with(concat!(
        "{\n",
        "  \"schemaVersion\": 4,\n",
        "  \"kind\": \"reviewed-windows-divergence\",\n"
    )) {
        return None;
    }
    Some((|| {
        let mut lines = document.lines();
        if lines.next() != Some("{")
            || lines.next() != Some("  \"schemaVersion\": 4,")
            || lines.next() != Some("  \"kind\": \"reviewed-windows-divergence\",")
        {
            return Err(std::io::Error::other(
                "Windows divergence projection schema is malformed",
            ));
        }
        let case_id = projection_text_line(lines.next(), "caseId")?;
        let builtin = projection_text_line(lines.next(), "builtin")?;
        let mismatch_sha256 = projection_digest_line(lines.next(), "mismatchSha256")?;
        let rationale = projection_text_line(lines.next(), "rationale")?;
        if lines.next() != Some("}") || lines.next().is_some() {
            return Err(std::io::Error::other(
                "Windows divergence projection has unknown fields",
            ));
        }
        let authority = crate::windows_divergences::retained_authority(
            &case_id,
            &builtin,
            &mismatch_sha256.hex(),
        )
        .ok_or_else(|| {
            std::io::Error::other("Windows divergence projection is not an exact reviewed record")
        })?;
        if rationale != authority.rationale {
            return Err(std::io::Error::other(
                "Windows divergence projection rationale differs from review",
            ));
        }
        let projection = crate::DifferentialComparisonProjection::ReviewedWindowsDivergence {
            case_id: authority.case_id,
            builtin: authority.builtin,
            mismatch_sha256,
            mismatch_kinds: authority.mismatch_kinds,
            rationale: authority.rationale,
        };
        if comparison_projection_json(&projection) != document {
            return Err(std::io::Error::other(
                "Windows divergence projection is noncanonical",
            ));
        }
        Ok(projection)
    })())
}

fn parse_comparison_projection_json(
    document: &str,
) -> std::io::Result<crate::DifferentialComparisonProjection> {
    let exact = crate::DifferentialComparisonProjection::Exact;
    if document == comparison_projection_json(&exact) {
        return Ok(exact);
    }
    if let Some(divergence) = parse_windows_divergence_projection_json(document) {
        return divergence;
    }
    if let Some(windows) = parse_windows_comparison_projection_json(document) {
        return windows;
    }
    let mut legacy_lines = document.lines();
    if legacy_lines.next() == Some("{")
        && legacy_lines.next() == Some("  \"schemaVersion\": 1,")
        && legacy_lines.next()
            == Some("  \"kind\": \"reviewed-runtime-failure-stderr-out-of-scope\",")
        && legacy_lines.next() == Some("  \"field\": \"stderr\",")
    {
        let oracle_sha256 = projection_digest_line(legacy_lines.next(), "oracleSha256")?;
        let candidate_sha256 = projection_digest_line(legacy_lines.next(), "candidateSha256")?;
        let oracle_bytes = projection_u64_line(legacy_lines.next(), "oracleBytes")?;
        let candidate_bytes = projection_u64_line(legacy_lines.next(), "candidateBytes")?;
        if legacy_lines.next() != Some("}") || legacy_lines.next().is_some() {
            return Err(std::io::Error::other(
                "comparison projection has unknown fields",
            ));
        }
        let projection = crate::DifferentialComparisonProjection::ReviewedRuntimeFailureStderr {
            oracle_sha256,
            candidate_sha256,
            oracle_bytes,
            candidate_bytes,
        };
        if comparison_projection_json(&projection) != document {
            return Err(std::io::Error::other(
                "comparison projection is noncanonical",
            ));
        }
        return Ok(projection);
    }
    let mut lines = document.lines();
    if lines.next() != Some("{")
        || lines.next() != Some("  \"schemaVersion\": 2,")
        || lines.next()
            != Some("  \"kind\": \"reviewed-runtime-failure-exception-stderr-out-of-scope\",")
        || lines.next() != Some("  \"field\": \"stderr\",")
    {
        return Err(std::io::Error::other(
            "comparison projection schema is malformed",
        ));
    }
    let exception_family = match lines.next() {
        Some("  \"exceptionFamily\": \"unicode-exception\",") => {
            crate::RuntimeFailureExceptionFamily::UnicodeException
        }
        Some("  \"exceptionFamily\": \"io-exception\",") => {
            crate::RuntimeFailureExceptionFamily::IOException
        }
        Some("  \"exceptionFamily\": \"error-call\",") => {
            crate::RuntimeFailureExceptionFamily::ErrorCall
        }
        _ => {
            return Err(std::io::Error::other(
                "comparison projection exception family is malformed",
            ));
        }
    };
    let payload_sha256 = projection_digest_line(lines.next(), "payloadSha256")?;
    let oracle_sha256 = projection_digest_line(lines.next(), "oracleSha256")?;
    let candidate_sha256 = projection_digest_line(lines.next(), "candidateSha256")?;
    let oracle_bytes = projection_u64_line(lines.next(), "oracleBytes")?;
    let candidate_bytes = projection_u64_line(lines.next(), "candidateBytes")?;
    if lines.next() != Some("}") || lines.next().is_some() {
        return Err(std::io::Error::other(
            "comparison projection has unknown fields",
        ));
    }
    let projection =
        crate::DifferentialComparisonProjection::ReviewedRuntimeFailureExceptionStderr {
            exception_family,
            payload_sha256,
            oracle_sha256,
            candidate_sha256,
            oracle_bytes,
            candidate_bytes,
        };
    if comparison_projection_json(&projection) != document {
        return Err(std::io::Error::other(
            "comparison projection is noncanonical",
        ));
    }
    Ok(projection)
}

fn projection_digest_line(line: Option<&str>, field: &str) -> std::io::Result<Digest> {
    let prefix = format!("  \"{field}\": \"");
    let value = line
        .and_then(|line| line.strip_suffix(','))
        .and_then(|line| line.strip_prefix(&prefix))
        .and_then(|line| line.strip_suffix('"'))
        .ok_or_else(|| std::io::Error::other("comparison projection digest is malformed"))?;
    Digest::from_hex(value).map_err(std::io::Error::other)
}

fn projection_text_line(line: Option<&str>, field: &str) -> std::io::Result<String> {
    let prefix = format!("  \"{field}\": \"");
    line.map(|line| line.strip_suffix(',').unwrap_or(line))
        .and_then(|line| line.strip_prefix(&prefix))
        .and_then(|line| line.strip_suffix('"'))
        .map(str::to_owned)
        .ok_or_else(|| std::io::Error::other("comparison projection text is malformed"))
}

fn projection_u64_line(line: Option<&str>, field: &str) -> std::io::Result<u64> {
    let prefix = format!("  \"{field}\": ");
    let value = line
        .map(|line| line.strip_suffix(',').unwrap_or(line))
        .and_then(|line| line.strip_prefix(&prefix))
        .ok_or_else(|| std::io::Error::other("comparison projection size is malformed"))?;
    value
        .parse::<u64>()
        .ok()
        .filter(|parsed| parsed.to_string() == value)
        .ok_or_else(|| std::io::Error::other("comparison projection size is noncanonical"))
}

fn parse_mismatch_summary(document: &str) -> std::io::Result<Vec<RetainedMismatchFact>> {
    let mut lines = document.lines();
    if lines.next() != Some("{") || lines.next() != Some("  \"schemaVersion\": 1,") {
        return Err(std::io::Error::other(
            "mismatch summary schema is malformed",
        ));
    }
    let encoded = lines
        .next()
        .and_then(|line| line.strip_prefix("  \"mismatches\": ["))
        .and_then(|line| line.strip_suffix(']'))
        .ok_or_else(|| std::io::Error::other("mismatch summary array is malformed"))?;
    if lines.next() != Some("}") || lines.next().is_some() {
        return Err(std::io::Error::other("mismatch summary has unknown fields"));
    }
    let facts = if encoded.is_empty() {
        Vec::new()
    } else {
        encoded
            .split("}, {")
            .map(parse_mismatch_fact)
            .collect::<std::io::Result<Vec<_>>>()?
    };
    if facts.iter().enumerate().any(|(index, fact)| {
        facts[..index]
            .iter()
            .any(|prior| mismatch_kind_index(prior.category) >= mismatch_kind_index(fact.category))
    }) || mismatch_summary_json(&facts) != document
    {
        return Err(std::io::Error::other(
            "mismatch summary is duplicated, unordered, or non-canonical",
        ));
    }
    Ok(facts)
}

fn parse_mismatch_fact(encoded: &str) -> std::io::Result<RetainedMismatchFact> {
    let encoded = encoded.strip_prefix('{').unwrap_or(encoded);
    let encoded = encoded.strip_suffix('}').unwrap_or(encoded);
    let (category, encoded) = encoded
        .strip_prefix("\"category\": \"")
        .and_then(|value| value.split_once("\", \"oracleSha256\": \""))
        .ok_or_else(|| std::io::Error::other("mismatch fact category is malformed"))?;
    let (oracle, candidate) = encoded
        .split_once("\", \"candidateSha256\": \"")
        .and_then(|(oracle, candidate)| {
            candidate
                .strip_suffix('"')
                .map(|candidate| (oracle, candidate))
        })
        .ok_or_else(|| std::io::Error::other("mismatch fact digests are malformed"))?;
    Ok(RetainedMismatchFact {
        category: parse_mismatch_kind(category)?,
        oracle_sha256: Digest::from_hex(oracle).map_err(std::io::Error::other)?,
        candidate_sha256: Digest::from_hex(candidate).map_err(std::io::Error::other)?,
    })
}

fn mismatch_fingerprint(
    case_id: &str,
    normalizers: &[NormalizerId],
    raw: &[RetainedMismatchFact],
    normalized: &[RetainedMismatchFact],
) -> Digest {
    let mut document = String::from("{\n  \"schemaVersion\": 1,\n  \"caseId\": ");
    push_json_string(&mut document, case_id);
    document.push_str(",\n  \"normalizers\": ");
    push_json_normalizers(&mut document, normalizers);
    document.push_str(",\n  \"raw\": ");
    push_json_string(
        &mut document,
        &sha256_bytes(mismatch_summary_json(raw).as_bytes()).hex(),
    );
    document.push_str(",\n  \"normalized\": ");
    push_json_string(
        &mut document,
        &sha256_bytes(mismatch_summary_json(normalized).as_bytes()).hex(),
    );
    document.push_str("\n}\n");
    sha256_bytes(document.as_bytes())
}

fn mismatch_kind_name(kind: crate::MismatchKind) -> &'static str {
    match kind {
        crate::MismatchKind::Timeout => "timeout",
        crate::MismatchKind::ExitStatus => "exit-status",
        crate::MismatchKind::Stdout => "stdout",
        crate::MismatchKind::Stderr => "stderr",
        crate::MismatchKind::Diagnostic => "diagnostic",
        crate::MismatchKind::Filesystem => "filesystem",
    }
}

fn parse_mismatch_kind(value: &str) -> std::io::Result<crate::MismatchKind> {
    match value {
        "timeout" => Ok(crate::MismatchKind::Timeout),
        "exit-status" => Ok(crate::MismatchKind::ExitStatus),
        "stdout" => Ok(crate::MismatchKind::Stdout),
        "stderr" => Ok(crate::MismatchKind::Stderr),
        "diagnostic" => Ok(crate::MismatchKind::Diagnostic),
        "filesystem" => Ok(crate::MismatchKind::Filesystem),
        _ => Err(std::io::Error::other("mismatch category is unknown")),
    }
}

fn mismatch_kind_index(kind: crate::MismatchKind) -> usize {
    match kind {
        crate::MismatchKind::Timeout => 0,
        crate::MismatchKind::ExitStatus => 1,
        crate::MismatchKind::Stdout => 2,
        crate::MismatchKind::Stderr => 3,
        crate::MismatchKind::Diagnostic => 4,
        crate::MismatchKind::Filesystem => 5,
    }
}

/// Verifies a bundle and derives whether equality is raw or normalizer-dependent.
///
/// # Errors
///
/// Returns an error when the bundle is invalid, the retained differential has
/// mismatches, or equality depends on an undeclared claim normalizer.
pub fn classify_observation_bundle_for_case(
    directory: &Path,
    case: &DifferentialCase,
) -> std::io::Result<ObservationEquivalence> {
    match classify_retained_observation_bundle(directory, case)? {
        RetainedObservationClassification::Exact => Ok(ObservationEquivalence::Exact),
        RetainedObservationClassification::ProjectedRuntimeFailureStderr { raw_mismatches } => Ok(
            ObservationEquivalence::ReviewedRuntimeFailureStderr(raw_mismatches),
        ),
        RetainedObservationClassification::ProjectedWindowsPresentation {
            field,
            raw_mismatches,
        } => Ok(ObservationEquivalence::ReviewedWindowsPresentation(
            field,
            raw_mismatches,
        )),
        RetainedObservationClassification::ProjectedWindowsDivergence { raw_mismatches } => Ok(
            ObservationEquivalence::ReviewedWindowsDivergence(raw_mismatches),
        ),
        RetainedObservationClassification::Normalized { normalizers, .. } => {
            Ok(ObservationEquivalence::Normalized(normalizers))
        }
        RetainedObservationClassification::Mismatch { .. } => Err(std::io::Error::other(
            "retained candidate/oracle comparison contains mismatches",
        )),
    }
}

fn validate_observation_metadata(
    path: &Path,
    case: &DifferentialCase,
    process_helper_sha256: Option<Digest>,
    validate_claim: bool,
) -> std::io::Result<()> {
    let document = fs::read_to_string(path)?;
    if parse_optional_digest_field(&document, "processHelperSha256")? != process_helper_sha256 {
        return Err(std::io::Error::other(
            "observation process helper differs from the retained helper identity",
        ));
    }
    let mut harness = String::from("  \"harnessNormalizers\": ");
    push_json_normalizers(&mut harness, &applied_harness_normalizers());
    harness.push(',');
    let mut claim = String::from("  \"claimNormalizers\": ");
    push_json_normalizers(&mut claim, &applied_claim_normalizers(case));
    claim.push(',');
    for expected in [harness, claim] {
        if document.lines().filter(|line| *line == expected).count() != 1 {
            return Err(std::io::Error::other(format!(
                "observation metadata in {} disagrees with the committed normalizers",
                path.display()
            )));
        }
    }
    let observation_directory = path
        .parent()
        .ok_or_else(|| std::io::Error::other("observation path has no directory"))?;
    validate_retained_typed_result(
        observation_directory,
        parse_optional_digest_field(&document, "semanticTypedResultSha256")?,
        parse_optional_u16_field(&document, "semanticTypedResultBuiltinId")?,
    )?;
    if validate_claim && let Some(descriptor) = &case.claim_evidence {
        validate_claim_semantics(&document, case, descriptor, observation_directory)?;
    }
    Ok(())
}

fn validate_claim_semantics(
    document: &str,
    case: &DifferentialCase,
    descriptor: &ClaimEvidenceDescriptor,
    observation_directory: &Path,
) -> std::io::Result<()> {
    let observed = parse_semantic_coverage(document)?;
    let typed_result = parse_optional_digest_field(document, "semanticTypedResultSha256")?;
    let typed_result_builtin = parse_optional_u16_field(document, "semanticTypedResultBuiltinId")?;
    let boundaries = parse_semantic_boundaries(document)?;
    let event_order = parse_semantic_event_order(document)?;
    let effect_trace = parse_semantic_effect_trace(document)?;
    let task_trace = parse_semantic_task_trace(document)?;
    let resource_trace = parse_semantic_resource_trace(document)?;
    let obligation_trace = parse_semantic_obligation_trace(document)?;
    validate_task_causality(&task_trace, &observed)?;
    validate_obligation_causality(&obligation_trace, &task_trace)?;
    validate_nested_ord_comparator_evidence(&obligation_trace)?;
    validate_effect_causality(&effect_trace, &task_trace, &observed)?;
    if event_order.is_empty() {
        return Err(std::io::Error::other("semantic event order is empty"));
    }
    validate_semantic_event_classes(
        &event_order,
        &observed,
        typed_result.is_some(),
        boundaries.len(),
        obligation_trace.len(),
    )?;
    for target in &descriptor.semantic_targets {
        let builtin = hell_builtins::lookup(&target.builtin)
            .ok_or_else(|| std::io::Error::other("semantic target builtin disappeared"))?;
        validate_expected_instance_target(target, builtin.id, &obligation_trace)?;
        validate_expected_comparator_trace(target, builtin.id, &obligation_trace)?;
        validate_exact_lazy_adapter_entry_target(target, builtin, &boundaries, &obligation_trace)?;
        validate_runtime_scope_binding(
            case,
            target,
            document,
            &observed,
            &obligation_trace,
            observation_directory,
            None,
        )?;
        if !target_has_causal_signal(target.causal_signal, builtin.id, &observed)? {
            return Err(std::io::Error::other(format!(
                "candidate observation lacks causal evidence for {:?}/{:?}",
                target.builtin, target.dimension
            )));
        }
        validate_retained_target_expectations(
            target,
            builtin.id,
            typed_result,
            typed_result_builtin,
            observation_directory,
            &obligation_trace,
            &effect_trace,
        )?;
        validate_force_only_target(target, builtin.id, &observed, &obligation_trace)?;
        validate_expected_lazy_argument_exit(target, builtin.id, &boundaries)?;
        validate_expected_whnf_argument_failure(target, builtin.id, &boundaries)?;
        validate_expected_nonproductive_trace(target, builtin.id, &boundaries)?;
        validate_expected_single_task_lifecycle(target, builtin.id, &task_trace, &effect_trace)?;
        validate_expected_task_trace(target, builtin.id, &task_trace)?;
        if let Some(expected) = target.expected_process_status_sha256 {
            let (success, code) = parse_observation_process_status(document)?;
            if crate::process_status_sha256(success, code) != expected {
                return Err(std::io::Error::other(format!(
                    "retained process status disagrees for {:?}/{:?}",
                    target.builtin, target.dimension
                )));
            }
        }
        validate_expected_single_effect_lifecycle(target, builtin.id, &effect_trace)?;
        for obligation in &target.obligations {
            validate_obligation_semantics(
                obligation.0.as_ref(),
                target.dimension,
                builtin.id,
                document,
                observation_directory,
                &observed,
                &effect_trace,
                &task_trace,
                &resource_trace,
                &obligation_trace,
                typed_result,
                typed_result_builtin,
                &boundaries,
                &target.platforms,
                target.expected_raw_presentation_sha256,
                target.expected_presentation_shadow_normalizer,
                target.expected_normalized_presentation_sha256,
                None,
            )?;
        }
    }
    validate_retained_callback_contracts(descriptor, &obligation_trace)?;
    Ok(())
}

fn validate_nested_ord_comparator_evidence(
    events: &[crate::ObligationTraceEvent],
) -> std::io::Result<()> {
    let less = hell_builtins::lookup("Ord.lt")
        .expect("Ord.lt remains registry-backed")
        .id;
    let greater = hell_builtins::lookup("Ord.gt")
        .expect("Ord.gt remains registry-backed")
        .id;
    for parent in events.iter().filter(|event| {
        crate::runtime_obligations::collection_comparator_sensitive(
            hell_builtins::registry()[usize::from(event.builtin.0)].name,
        )
    }) {
        let parent_name = hell_builtins::registry()[usize::from(parent.builtin.0)].name;
        let mut direct_children = events
            .iter()
            .filter(|event| {
                event.owner_task == parent.owner_task
                    && event.parent_sequence == Some(parent.sequence)
                    && matches!(event.builtin, child_builtin if child_builtin == less || child_builtin == greater)
            })
            .collect::<Vec<_>>();
        direct_children.sort_by_key(|event| event.sequence);
        let mut selected_ordinals = std::collections::BTreeSet::new();
        let mut comparators = Vec::new();
        let mut previous_ordinal = 0;
        for (ordinal, observation) in parent.comparators.iter().enumerate() {
            let expected = u64::try_from(ordinal)
                .map_err(|_| std::io::Error::other("direct comparator count exceeds u64"))?
                .saturating_add(1);
            let child_index = usize::try_from(observation.direct_child_ordinal.saturating_sub(1))
                .map_err(|_| {
                std::io::Error::other("direct comparator ordinal exceeds usize")
            })?;
            let child = direct_children.get(child_index).ok_or_else(|| {
                std::io::Error::other("direct comparator child ordinal is missing")
            })?;
            if observation.invocation != expected
                || observation.direct_child_ordinal <= previous_ordinal
                || !selected_ordinals.insert(observation.direct_child_ordinal)
                || !matches!(child.builtin, child_builtin if child_builtin == less || child_builtin == greater)
                || observation.comparator != child.builtin
                || observation.outcome != child.outcome
                || !matches!(
                    observation.canonical_result.as_ref(),
                    "{\"type\":\"Bool\",\"value\":true}" | "{\"type\":\"Bool\",\"value\":false}"
                )
            {
                return Err(std::io::Error::other(
                    "direct Ord comparator observation disagrees with its child",
                ));
            }
            previous_ordinal = observation.direct_child_ordinal;
            comparators.push(*child);
        }
        let direct_ordinals = direct_children
            .iter()
            .enumerate()
            .map(|(index, _)| {
                u64::try_from(index)
                    .map(|index| index.saturating_add(1))
                    .map_err(|_| std::io::Error::other("direct comparator count exceeds u64"))
            })
            .collect::<std::io::Result<std::collections::BTreeSet<_>>>()?;
        if selected_ordinals != direct_ordinals {
            return Err(std::io::Error::other(
                "direct Ord child is missing exact comparator authority",
            ));
        }
        let mut fallback_insert = !parent_name.ends_with(".fromList");
        for (index, comparator) in comparators.iter().enumerate() {
            if comparator.instance_target != parent.instance_target
                || comparator.instance_premises != parent.instance_premises
            {
                return Err(std::io::Error::other(
                    "nested Ord comparator instance evidence disagrees with its collection parent",
                ));
            }
            if comparator.outcome.as_ref() != "value" {
                return Err(std::io::Error::other(
                    "nested Ord comparator did not retain a value outcome",
                ));
            }
            if comparator.builtin == less {
                fallback_insert = true;
            }
            let invalid_order = fallback_insert
                && comparator.builtin == greater
                && (index == 0 || comparators[index - 1].builtin != less);
            if invalid_order {
                return Err(std::io::Error::other(
                    "nested Ord.gt did not follow its Ord.lt probe",
                ));
            }
        }
    }
    Ok(())
}

fn validate_force_only_target(
    target: &crate::EvidenceTargetV2,
    builtin: hell_builtins::BuiltinId,
    observed: &[CoverageEvent],
    obligation_trace: &[crate::ObligationTraceEvent],
) -> std::io::Result<()> {
    if target.causal_signal != CausalSignal::ForceTrace {
        return Ok(());
    }
    if observed.contains(&CoverageEvent::EnteredAdapter(builtin))
        || obligation_trace
            .iter()
            .any(|event| event.builtin == builtin)
        || target.expected_instance_target.is_some()
        || !target.expected_instance_premises.is_empty()
        || target.expected_comparator_trace_sha256.is_some()
        || target.expected_typed_result_sha256.is_some()
    {
        return Err(target_expectation_error(target, "pre-adapter force trace"));
    }
    Ok(())
}

fn validate_retained_target_expectations(
    target: &crate::EvidenceTargetV2,
    builtin: hell_builtins::BuiltinId,
    typed_result: Option<Digest>,
    typed_result_builtin: Option<u16>,
    observation_directory: &Path,
    obligation_trace: &[crate::ObligationTraceEvent],
    effect_trace: &[RetainedEffectEvent],
) -> std::io::Result<()> {
    if let Some(expected) = target.expected_typed_result_sha256
        && (typed_result != Some(expected) || typed_result_builtin != Some(builtin.0))
    {
        return Err(std::io::Error::other(format!(
            "retained typed result disagrees for {:?}/{:?}: expected {expected:?}, observed {typed_result:?}/{typed_result_builtin:?}",
            target.builtin, target.dimension
        )));
    }
    if target.expected_raw_presentation_sha256.is_some()
        && !validate_raw_presentation(
            observation_directory,
            target.expected_raw_presentation_sha256,
            None,
        )?
    {
        return Err(target_expectation_error(
            target,
            "candidate raw observation",
        ));
    }
    if target.expected_normalized_presentation_sha256.is_some()
        && !validate_normalized_presentation_shadow(
            observation_directory,
            target.expected_presentation_shadow_normalizer,
            target.expected_normalized_presentation_sha256,
            None,
        )?
    {
        return Err(target_expectation_error(
            target,
            "candidate normalized presentation shadow",
        ));
    }
    validate_presentation_dependency(target, builtin, obligation_trace, effect_trace)
}

fn target_expectation_error(target: &crate::EvidenceTargetV2, label: &str) -> std::io::Error {
    std::io::Error::other(format!(
        "{label} disagrees for {:?}/{:?}",
        target.builtin, target.dimension
    ))
}

fn validate_exact_lazy_adapter_entry_target(
    target: &crate::EvidenceTargetV2,
    builtin: &hell_builtins::BuiltinSpec,
    boundaries: &[(
        hell_builtins::BuiltinId,
        u16,
        String,
        String,
        Option<String>,
    )],
    obligation_trace: &[crate::ObligationTraceEvent],
) -> std::io::Result<()> {
    if target.dimension != hell_builtins::CompatibilityDimension::PureRuntime
        || !builtin.demand.contains(&hell_builtins::Demand::Lazy)
    {
        return Ok(());
    }
    let invocation_count = if target.causal_signal == CausalSignal::ForceTrace {
        1
    } else {
        obligation_trace
            .iter()
            .filter(|event| event.builtin == builtin.id)
            .count()
    };
    if exact_lazy_adapter_entry_states(builtin.id, boundaries, invocation_count) {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "retained lazy adapter-entry states disagree for {:?}/{:?}",
            target.builtin, target.dimension
        )))
    }
}

fn validate_expected_instance_target(
    target: &crate::EvidenceTargetV2,
    builtin: hell_builtins::BuiltinId,
    obligation_trace: &[crate::ObligationTraceEvent],
) -> std::io::Result<()> {
    let Some(expected) = target.expected_instance_target.as_deref() else {
        return Ok(());
    };
    let matching = obligation_trace
        .iter()
        .filter(|event| event.builtin == builtin)
        .collect::<Vec<_>>();
    let permitted_nested = target
        .expected_instance_premises
        .iter()
        .map(|premise| premise.target.as_ref())
        .collect::<std::collections::BTreeSet<_>>();
    let expected_events = matching
        .iter()
        .filter(|event| event.instance_target.as_deref() == Some(expected))
        .collect::<Vec<_>>();
    if expected_events.is_empty()
        || expected_events
            .iter()
            .any(|event| event.instance_premises != target.expected_instance_premises)
        || matching.iter().any(|event| {
            event
                .instance_target
                .as_deref()
                .is_none_or(|instance| instance != expected && !permitted_nested.contains(instance))
        })
    {
        return Err(std::io::Error::other(format!(
            "retained instance target disagrees for {:?}/{:?}",
            target.builtin, target.dimension
        )));
    }
    Ok(())
}

fn validate_expected_comparator_trace(
    target: &crate::EvidenceTargetV2,
    builtin: hell_builtins::BuiltinId,
    events: &[crate::ObligationTraceEvent],
) -> std::io::Result<()> {
    let Some(expected) = target.expected_comparator_trace_sha256 else {
        return Ok(());
    };
    let instance_target = target
        .expected_instance_target
        .as_deref()
        .ok_or_else(|| std::io::Error::other("comparator trace has no retained instance root"))?;
    let mut parents = events
        .iter()
        .filter(|event| event.builtin == builtin)
        .collect::<Vec<_>>();
    parents.sort_by_key(|event| (event.owner_task, event.sequence));
    let mut records = Vec::new();
    for (parent_index, parent) in parents.iter().enumerate() {
        let parent_invocation = u64::try_from(parent_index)
            .map_err(|_| std::io::Error::other("comparator parent count exceeds u64"))?
            .saturating_add(1);
        let mut children = events
            .iter()
            .filter(|child| {
                child.owner_task == parent.owner_task
                    && child.parent_sequence == Some(parent.sequence)
                    && matches!(
                        hell_builtins::registry()[usize::from(child.builtin.0)].name,
                        "Ord.lt" | "Ord.gt"
                    )
            })
            .collect::<Vec<_>>();
        children.sort_by_key(|child| child.sequence);
        let mut selected_ordinals = std::collections::BTreeSet::new();
        for comparison in &parent.comparators {
            let child_index = usize::try_from(comparison.direct_child_ordinal.saturating_sub(1))
                .map_err(|_| std::io::Error::other("comparator child ordinal exceeds usize"))?;
            let child = children
                .get(child_index)
                .ok_or_else(|| std::io::Error::other("comparator child ordinal is missing"))?;
            if comparison.comparator != child.builtin {
                return Err(std::io::Error::other(
                    "comparator record builtin disagrees with direct child",
                ));
            }
            if !selected_ordinals.insert(comparison.direct_child_ordinal) {
                return Err(std::io::Error::other(
                    "comparator child ordinal is duplicated",
                ));
            }
            let result = match comparison.canonical_result.as_ref() {
                "{\"type\":\"Bool\",\"value\":true}" => true,
                "{\"type\":\"Bool\",\"value\":false}" => false,
                _ => {
                    return Err(std::io::Error::other(
                        "comparator result is not canonical Bool",
                    ));
                }
            };
            records.push(crate::ComparatorTraceContract {
                parent_invocation,
                direct_child_ordinal: comparison.direct_child_ordinal,
                comparator_ordinal: comparison.invocation,
                comparator: Arc::from(hell_builtins::registry()[usize::from(child.builtin.0)].name),
                canonical_left: Arc::clone(&comparison.canonical_left),
                canonical_right: Arc::clone(&comparison.canonical_right),
                result,
                outcome: Arc::clone(&comparison.outcome),
            });
        }
    }
    let parent_count = u64::try_from(parents.len())
        .map_err(|_| std::io::Error::other("comparator parent count exceeds u64"))?;
    let actual = crate::comparator_trace_sha256(
        &target.builtin,
        parent_count,
        instance_target,
        &target.expected_instance_premises,
        &records,
    );
    if actual != expected {
        return Err(std::io::Error::other(format!(
            "{}; expected {}, observed {} from {records:?}",
            target_expectation_error(target, "retained comparator trace"),
            expected.hex(),
            actual.hex(),
        )));
    }
    Ok(())
}

fn validate_expected_lazy_argument_exit(
    target: &crate::EvidenceTargetV2,
    builtin: hell_builtins::BuiltinId,
    boundaries: &[(
        hell_builtins::BuiltinId,
        u16,
        String,
        String,
        Option<String>,
    )],
) -> std::io::Result<()> {
    let Some(expected) = target.expected_lazy_argument_exit_sha256 else {
        return Ok(());
    };
    let states = boundaries
        .iter()
        .filter(|(id, _, class, _, _)| *id == builtin && class == "lazy-adapter-exit")
        .map(|(_, argument, _, outcome, _)| (*argument, outcome.as_str()))
        .collect::<Vec<_>>();
    if states.is_empty() || crate::lazy_argument_exit_sha256(states) != expected {
        return Err(std::io::Error::other(format!(
            "retained lazy argument exit states disagree for {:?}/{:?}",
            target.builtin, target.dimension
        )));
    }
    Ok(())
}

fn validate_expected_whnf_argument_failure(
    target: &crate::EvidenceTargetV2,
    builtin: hell_builtins::BuiltinId,
    boundaries: &[(
        hell_builtins::BuiltinId,
        u16,
        String,
        String,
        Option<String>,
    )],
) -> std::io::Result<()> {
    let Some(expected) = target.expected_whnf_argument_failure_sha256 else {
        return Ok(());
    };
    let failures = boundaries
        .iter()
        .filter(|(id, _, class, _, _)| *id == builtin && class == "whnf-force-failed")
        .map(|(_, argument, _, outcome, error_code)| {
            (
                *argument,
                outcome.as_str(),
                error_code.as_deref().unwrap_or_default(),
            )
        })
        .collect::<Vec<_>>();
    if failures.is_empty() || crate::whnf_argument_failure_sha256(failures) != expected {
        return Err(std::io::Error::other(format!(
            "retained WHNF argument failure disagrees for {:?}/{:?}",
            target.builtin, target.dimension
        )));
    }
    Ok(())
}

fn validate_expected_nonproductive_trace(
    target: &crate::EvidenceTargetV2,
    builtin: hell_builtins::BuiltinId,
    boundaries: &[(
        hell_builtins::BuiltinId,
        u16,
        String,
        String,
        Option<String>,
    )],
) -> std::io::Result<()> {
    let Some(expected) = target.expected_nonproductive_trace_sha256 else {
        return Ok(());
    };
    let events = boundaries
        .iter()
        .filter(|(id, argument, class, _, _)| {
            *id == builtin && *argument == 0 && class.starts_with("nonproductive-")
        })
        .map(|(_, _, class, outcome, _)| (class.as_str(), outcome.as_str()))
        .collect::<Vec<_>>();
    if events.is_empty() || crate::nonproductive_trace_sha256(events) != expected {
        return Err(std::io::Error::other(format!(
            "retained nonproductive trace disagrees for {:?}/{:?}",
            target.builtin, target.dimension
        )));
    }
    Ok(())
}

fn validate_expected_single_task_lifecycle(
    target: &crate::EvidenceTargetV2,
    builtin: hell_builtins::BuiltinId,
    task_trace: &[(u64, hell_builtins::BuiltinId, String)],
    effect_trace: &[RetainedEffectEvent],
) -> std::io::Result<()> {
    let Some(expected) = target.expected_single_task_lifecycle_sha256 else {
        return Ok(());
    };
    let matching = task_trace
        .iter()
        .filter(|entry| entry.1 == builtin)
        .map(|entry| (entry.0, entry.2.as_str()))
        .collect::<Vec<_>>();
    let task = matching
        .first()
        .map(|entry| entry.0)
        .ok_or_else(|| std::io::Error::other("expected target task lifecycle is absent"))?;
    if matching.iter().any(|entry| entry.0 != task)
        || crate::single_task_lifecycle_sha256(matching.iter().map(|entry| entry.1)) != expected
    {
        return Err(std::io::Error::other(
            "target task lifecycle differs from its exact reviewed sequence",
        ));
    }
    let terminal = matching
        .last()
        .map(|entry| entry.1)
        .ok_or_else(|| std::io::Error::other("target task lifecycle is empty"))?;
    let expected_effect = expected_effect_terminal_for_task(builtin, terminal)?;
    if !effect_trace
        .iter()
        .any(|entry| entry.builtin == builtin && entry.lifecycle == expected_effect)
    {
        return Err(std::io::Error::other(
            "target task terminal disagrees with its host effect outcome",
        ));
    }
    Ok(())
}

fn expected_effect_terminal_for_task(
    builtin: hell_builtins::BuiltinId,
    task_terminal: &str,
) -> std::io::Result<&'static str> {
    let builtin_name = hell_builtins::registry()
        .iter()
        .find(|spec| spec.id == builtin)
        .map(|spec| spec.name);
    match (task_terminal, builtin_name) {
        ("completed", _) | ("cancelled", Some("Timeout.timeout")) => Ok("completed"),
        ("failed", _) => Ok("failed"),
        ("cancelled", Some("Concurrent.threadDelay")) => Ok("cancelled"),
        ("cancelled", _) => Err(std::io::Error::other(
            "target task cancellation has no reviewed effect correlation",
        )),
        _ => Err(std::io::Error::other(
            "target task lifecycle lacks an exact terminal",
        )),
    }
}

fn validate_expected_task_trace(
    target: &crate::EvidenceTargetV2,
    builtin: hell_builtins::BuiltinId,
    task_trace: &[(u64, hell_builtins::BuiltinId, String)],
) -> std::io::Result<()> {
    let Some(expected) = target.expected_task_trace_sha256 else {
        return Ok(());
    };
    let mut tasks = Vec::<u64>::new();
    let mut events = Vec::new();
    for (task, event_builtin, event) in task_trace {
        if *event_builtin != builtin {
            continue;
        }
        let index = tasks
            .iter()
            .position(|entry| *entry == *task)
            .unwrap_or_else(|| {
                tasks.push(*task);
                tasks.len() - 1
            });
        events.push((index, event.as_str()));
    }
    let actual = crate::task_trace_sha256(events);
    if actual != expected {
        return Err(std::io::Error::other(
            "target task trace differs from its exact reviewed global sequence",
        ));
    }
    Ok(())
}

fn parse_observation_process_status(document: &str) -> std::io::Result<(bool, Option<i32>)> {
    let status = exact_observation_field(document, "status")?;
    validate_status_value(status)?;
    let (success, code) = status
        .strip_prefix("{\"success\": ")
        .and_then(|value| value.strip_suffix('}'))
        .and_then(|value| value.split_once(", \"code\": "))
        .ok_or_else(|| std::io::Error::other("observation status is malformed"))?;
    let success = match success {
        "true" => true,
        "false" => false,
        _ => return Err(std::io::Error::other("observation status is malformed")),
    };
    let code = if code == "null" {
        None
    } else {
        Some(
            code.parse::<i32>()
                .map_err(|_| std::io::Error::other("observation status code is malformed"))?,
        )
    };
    Ok((success, code))
}

fn validate_expected_single_effect_lifecycle(
    target: &crate::EvidenceTargetV2,
    builtin: hell_builtins::BuiltinId,
    effect_trace: &[RetainedEffectEvent],
) -> std::io::Result<()> {
    let Some(expected) = target.expected_single_effect_lifecycle_sha256 else {
        return Ok(());
    };
    let matching = effect_trace
        .iter()
        .filter(|event| event.builtin == builtin)
        .collect::<Vec<_>>();
    let sequence = matching
        .first()
        .map(|event| event.sequence)
        .ok_or_else(|| std::io::Error::other("expected target effect lifecycle is absent"))?;
    if matching.iter().any(|event| event.sequence != sequence)
        || crate::single_effect_lifecycle_sha256(
            matching.iter().map(|event| event.lifecycle.as_str()),
        ) != expected
    {
        return Err(std::io::Error::other(
            "target effect lifecycle differs from its exact reviewed sequence",
        ));
    }
    Ok(())
}

fn validate_retained_callback_contracts(
    descriptor: &ClaimEvidenceDescriptor,
    events: &[crate::ObligationTraceEvent],
) -> std::io::Result<()> {
    for event in events {
        let spec = hell_builtins::registry()
            .iter()
            .find(|spec| spec.id == event.builtin)
            .ok_or_else(|| std::io::Error::other("callback target disappeared"))?;
        for callback in &event.callbacks {
            if !crate::runtime_obligations::callback_identity_allowed(
                spec.name,
                callback.callback_argument,
                &callback.branch,
            ) {
                return Err(std::io::Error::other(format!(
                    "retained callback identity is invalid for {:?}: argument {} branch {:?}",
                    spec.name, callback.callback_argument, callback.branch
                )));
            }
        }
    }
    for contract in &descriptor.callback_contracts {
        let builtin = hell_builtins::lookup(&contract.builtin)
            .ok_or_else(|| std::io::Error::other("callback contract target disappeared"))?
            .id;
        let mut matching_events = events
            .iter()
            .filter(|event| event.builtin == builtin)
            .collect::<Vec<_>>();
        matching_events.sort_by_key(|event| (event.owner_task, event.sequence));
        let callbacks = matching_events
            .into_iter()
            .flat_map(|event| &event.callbacks)
            .collect::<Vec<_>>();
        if callbacks.len() != contract.invocations.len() {
            return Err(std::io::Error::other(format!(
                "retained callback cardinality disagrees for {:?}",
                contract.builtin
            )));
        }
        for (actual, expected) in callbacks.into_iter().zip(&contract.invocations) {
            let arguments = actual
                .canonical_arguments
                .iter()
                .map(|argument| sha256_bytes(argument.as_bytes()))
                .collect::<Vec<_>>();
            if actual.callback_argument != expected.callback_argument
                || actual.branch != expected.branch
                || actual.outcome != expected.outcome
                || arguments != expected.canonical_argument_sha256
                || sha256_bytes(actual.canonical_result.as_bytes())
                    != expected.canonical_result_sha256
            {
                return Err(std::io::Error::other(format!(
                    "retained callback contract disagrees for {:?}",
                    contract.builtin
                )));
            }
        }
    }
    Ok(())
}

fn validate_retained_typed_result(
    observation_directory: &Path,
    digest: Option<Digest>,
    builtin: Option<u16>,
) -> std::io::Result<()> {
    let path = observation_directory.join("semantic-typed-result.json");
    match (digest, builtin) {
        (None, None) if !path.exists() => Ok(()),
        (Some(digest), Some(_)) => {
            let retained = fs::read_to_string(&path)?;
            let canonical = retained.strip_suffix('\n').ok_or_else(|| {
                std::io::Error::other("retained typed result lacks one trailing newline")
            })?;
            if canonical.contains('\n') {
                return Err(std::io::Error::other(
                    "retained typed result contains trailing or embedded content",
                ));
            }
            crate::validate_canonical_typed_value(canonical)?;
            if sha256_bytes(canonical.as_bytes()) != digest {
                return Err(std::io::Error::other(
                    "retained typed result digest does not match canonical bytes",
                ));
            }
            Ok(())
        }
        _ => Err(std::io::Error::other(
            "retained typed result identity is incomplete or unexpected",
        )),
    }
}

fn validate_runtime_scope_binding(
    case: &DifferentialCase,
    target: &crate::EvidenceTargetV2,
    document: &str,
    observed: &[CoverageEvent],
    obligation_trace: &[crate::ObligationTraceEvent],
    observation_directory: &Path,
    conformance_facts: Option<&ConformanceObservationFacts>,
) -> std::io::Result<()> {
    if target.boundary_classes.len() > 1 {
        return Err(std::io::Error::other(
            "one retained runtime case cannot conflate boundary classes",
        ));
    }
    for boundary in &target.boundary_classes {
        validate_runtime_boundary_binding(
            case,
            target,
            boundary,
            document,
            observed,
            obligation_trace,
            observation_directory,
            conformance_facts,
        )?;
    }
    for interaction in &target.interaction_obligations {
        validate_runtime_interaction_binding(case, interaction, observed, obligation_trace)?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_runtime_boundary_binding(
    case: &DifferentialCase,
    target: &crate::EvidenceTargetV2,
    boundary: &str,
    document: &str,
    observed: &[CoverageEvent],
    obligation_trace: &[crate::ObligationTraceEvent],
    observation_directory: &Path,
    conformance_facts: Option<&ConformanceObservationFacts>,
) -> std::io::Result<()> {
    let builtin_case = match target.builtin.as_ref() {
        "Options.flag'" => "options-flag-prime".to_owned(),
        "Text.readProcess_" => "text-readprocess-checked".to_owned(),
        "Text.readProcessStdout_" => "text-readprocess-stdout-checked".to_owned(),
        "ByteString.readProcess_" => "bytestring-readprocess-checked".to_owned(),
        "ByteString.readProcessStdout_" => "bytestring-readprocess-stdout-checked".to_owned(),
        builtin => builtin
            .to_ascii_lowercase()
            .replace('.', "-")
            .replace('\'', ""),
    };
    let ordinary_case = format!("{builtin_case}-boundary-{boundary}");
    let scoped_case = if target.builtin.as_ref() == "CI.mk"
        && target.expected_instance_target.as_deref() == Some("ByteString")
    {
        Some(format!("ci-mk-bytestring-boundary-{boundary}"))
    } else {
        ord_list_boundary_case_id(target, boundary)
            .or_else(|| ord_set_boundary_case_id(target, boundary))
            .or_else(|| ord_map_boundary_case_id(target, boundary))
            .or_else(|| eq_list_boundary_case_id(target, boundary))
    };
    if case.id.as_ref() != ordinary_case && scoped_case.as_deref() != Some(case.id.as_ref()) {
        return Err(std::io::Error::other(
            "runtime boundary identity is not bound to its dedicated case",
        ));
    }
    let builtin = hell_builtins::lookup(&target.builtin)
        .ok_or_else(|| std::io::Error::other("runtime boundary builtin disappeared"))?;
    if !observed
        .iter()
        .any(|event| matches!(event, CoverageEvent::EnteredAdapter(id) if *id == builtin.id))
    {
        return Err(std::io::Error::other(
            "runtime boundary case did not enter its target adapter",
        ));
    }
    let matching = obligation_trace
        .iter()
        .filter(|event| event.builtin == builtin.id)
        .collect::<Vec<_>>();
    let success = parse_observation_success(document)?;
    let outcome_matches = match runtime_boundary_outcome(&target.builtin, boundary)? {
        RuntimeBoundaryOutcome::Value => {
            success
                && matching
                    .iter()
                    .any(|event| event.outcome.as_ref() != "error")
        }
        RuntimeBoundaryOutcome::TargetValueWithFailure => {
            let exec_parser = hell_builtins::lookup("Options.execParser")
                .expect("Options.execParser remains registry-backed")
                .id;
            !success
                && matching
                    .iter()
                    .any(|event| event.outcome.as_ref() != "error")
                && parse_semantic_effect_trace(document)?
                    .iter()
                    .any(|event| event.builtin == exec_parser && event.lifecycle == "failed")
        }
        RuntimeBoundaryOutcome::Error => {
            let adapter_failed = matching.iter().any(|event| {
                event.outcome.as_ref() == "error"
                    || adapter_has_error_descendant(event, obligation_trace)
            });
            let effect_failed = !adapter_failed
                && parse_semantic_effect_trace(document)?
                    .iter()
                    .any(|event| event.builtin == builtin.id && event.lifecycle == "failed");
            let typed_result_failed = target.expected_typed_result_sha256.is_some_and(|expected| {
                parse_optional_digest_field(document, "semanticTypedResultSha256")
                    .is_ok_and(|observed| observed == Some(expected))
            });
            !success && (adapter_failed || effect_failed || typed_result_failed)
        }
    };
    if !outcome_matches {
        return Err(std::io::Error::other(
            "runtime boundary retained the wrong typed outcome",
        ));
    }
    validate_runtime_boundary_outputs(target, document, observation_directory, conformance_facts)
}

fn validate_runtime_boundary_outputs(
    target: &crate::EvidenceTargetV2,
    document: &str,
    observation_directory: &Path,
    conformance_facts: Option<&ConformanceObservationFacts>,
) -> std::io::Result<()> {
    if let Some(expected) = target.expected_typed_result_sha256 {
        let observed = parse_optional_digest_field(document, "semanticTypedResultSha256")?
            .ok_or_else(|| {
                std::io::Error::other("runtime boundary has no retained typed result")
            })?;
        if observed != expected {
            return Err(std::io::Error::other(
                "runtime boundary typed result differs from its reviewed expectation",
            ));
        }
    }
    if target.expected_raw_presentation_sha256.is_some()
        && !validate_raw_presentation(
            observation_directory,
            target.expected_raw_presentation_sha256,
            conformance_facts,
        )?
    {
        return Err(std::io::Error::other(
            "runtime boundary raw result differs from its reviewed expectation",
        ));
    }
    Ok(())
}

fn eq_list_boundary_case_id(target: &crate::EvidenceTargetV2, boundary: &str) -> Option<String> {
    let builtin = matches!(
        target.builtin.as_ref(),
        "List.lookup"
            | "List.elem"
            | "List.notElem"
            | "List.elemIndex"
            | "List.elemIndices"
            | "List.group"
            | "List.isInfixOf"
            | "List.isPrefixOf"
            | "List.isSubsequenceOf"
            | "List.isSuffixOf"
    )
    .then(|| {
        target
            .builtin
            .trim_start_matches("List.")
            .to_ascii_lowercase()
    })?;
    let instance = match target.expected_instance_target.as_deref()? {
        "Bool" => "bool",
        "ByteString" => "byte-string",
        "CI" => "ci",
        "Char" => "char",
        "Double" => "double",
        "ExitCode" => "exit-code",
        "Int" => "int",
        "Integer" => "integer",
        "Text" => "text",
        "Day" => "day",
        "DayOfWeek" => "day-of-week",
        "TimeOfDay" => "time-of-day",
        "UTCTime" => "utc-time",
        "(,)" => "tuple",
        "Either" => "either",
        "Maybe" => "maybe",
        "Set" => "set",
        "Tree" => "tree",
        "Vector" => "vector",
        "[]" => "list",
        _ => return None,
    };
    Some(format!("runtime-eq-list-{builtin}-{instance}-{boundary}"))
}

fn ord_list_boundary_case_id(target: &crate::EvidenceTargetV2, boundary: &str) -> Option<String> {
    let builtin = match target.builtin.as_ref() {
        "List.sort" => "list-sort",
        "List.sortOn" => "list-sorton",
        "List.nubOrd" => "list-nubord",
        _ => return None,
    };
    let instance = ord_instance_slug(target)?;
    Some(format!("runtime-ord-list-{builtin}-{instance}-{boundary}"))
}

fn ord_map_boundary_case_id(target: &crate::EvidenceTargetV2, boundary: &str) -> Option<String> {
    let builtin = match target.builtin.as_ref() {
        "Map.fromList" => "fromlist",
        "Map.lookup" => "lookup",
        "Map.insert" => "insert",
        "Map.delete" => "delete",
        "Map.insertWith" => "insertwith",
        "Map.adjust" => "adjust",
        "Map.unionWith" => "unionwith",
        _ => return None,
    };
    let instance = ord_instance_slug(target)?;
    Some(format!("runtime-ord-map-{builtin}-{instance}-{boundary}"))
}

fn ord_set_boundary_case_id(target: &crate::EvidenceTargetV2, boundary: &str) -> Option<String> {
    let builtin = match target.builtin.as_ref() {
        "Set.fromList" => "fromlist",
        "Set.insert" => "insert",
        "Set.member" => "member",
        "Set.delete" => "delete",
        "Set.union" => "union",
        "Set.difference" => "difference",
        "Set.intersection" => "intersection",
        _ => return None,
    };
    let instance = ord_instance_slug(target)?;
    Some(format!("runtime-ord-set-{builtin}-{instance}-{boundary}"))
}

fn ord_instance_slug(target: &crate::EvidenceTargetV2) -> Option<&'static str> {
    match target.expected_instance_target.as_deref()? {
        "Bool" => "bool",
        "ByteString" => "byte-string",
        "CI" => "ci",
        "Char" => "char",
        "Double" => "double",
        "ExitCode" => "exit-code",
        "Int" => "int",
        "Integer" => "integer",
        "Text" => "text",
        "Day" => "day",
        "DayOfWeek" => "day-of-week",
        "TimeOfDay" => "time-of-day",
        "UTCTime" => "utc-time",
        "(,)" => "tuple",
        "Either" => "either",
        "Maybe" => "maybe",
        "Set" => "set",
        "Tree" => "tree",
        "Vector" => "vector",
        "[]" => "list",
        _ => return None,
    }
    .into()
}

fn validate_runtime_interaction_binding(
    case: &DifferentialCase,
    interaction: &str,
    observed: &[CoverageEvent],
    obligation_trace: &[crate::ObligationTraceEvent],
) -> std::io::Result<()> {
    if case.id.as_ref() != format!("runtime-interaction-{interaction}") {
        return Err(std::io::Error::other(
            "runtime interaction identity is not bound to its dedicated case",
        ));
    }
    let requirement = crate::mandatory_runtime_interactions()
        .into_iter()
        .find(|requirement| requirement.id.as_ref() == interaction)
        .ok_or_else(|| std::io::Error::other("runtime interaction disappeared"))?;
    for participant in requirement.builtins {
        let participant = hell_builtins::lookup(&participant)
            .ok_or_else(|| std::io::Error::other("runtime interaction participant disappeared"))?;
        if !observed.iter().any(
            |event| matches!(event, CoverageEvent::EnteredAdapter(id) if *id == participant.id),
        ) {
            return Err(std::io::Error::other(
                "runtime interaction case did not enter every participant adapter",
            ));
        }
    }
    if interaction == "map-ordering-custom-ord" {
        validate_map_ordering_dependency(obligation_trace)?;
    }
    Ok(())
}

fn validate_map_ordering_dependency(
    obligation_trace: &[crate::ObligationTraceEvent],
) -> std::io::Result<()> {
    let map = hell_builtins::lookup("Map.fromList")
        .expect("Map.fromList is registry-backed")
        .id;
    let parents = obligation_trace
        .iter()
        .filter(|event| {
            event.builtin == map
                && event.instance_target.as_deref() == Some("Int")
                && event.outcome.as_ref() == "value"
        })
        .collect::<Vec<_>>();
    let [parent] = parents.as_slice() else {
        return Err(std::io::Error::other(
            "map ordering interaction lacks one exact successful Int Map.fromList adapter",
        ));
    };
    for comparator in ["Ord.lt", "Ord.gt"] {
        let comparator = hell_builtins::lookup(comparator)
            .expect("Ord comparator is registry-backed")
            .id;
        let children = obligation_trace
            .iter()
            .filter(|event| {
                event.builtin == comparator
                    && event.instance_target.as_deref() == Some("Int")
                    && event.owner_task == parent.owner_task
                    && event.parent_sequence == Some(parent.sequence)
                    && event.outcome.as_ref() == "value"
            })
            .count();
        if children != 1 {
            return Err(std::io::Error::other(
                "map ordering interaction lacks one exact causally delegated Ord comparator",
            ));
        }
    }
    Ok(())
}

fn adapter_has_error_descendant(
    ancestor: &crate::ObligationTraceEvent,
    events: &[crate::ObligationTraceEvent],
) -> bool {
    let mut frontier = vec![ancestor.sequence];
    let mut visited = std::collections::BTreeSet::new();
    while let Some(parent) = frontier.pop() {
        if !visited.insert(parent) {
            return false;
        }
        for child in events.iter().filter(|event| {
            event.owner_task == ancestor.owner_task && event.parent_sequence == Some(parent)
        }) {
            if child.outcome.as_ref() == "error" {
                return true;
            }
            frontier.push(child.sequence);
        }
    }
    false
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RuntimeBoundaryOutcome {
    Value,
    TargetValueWithFailure,
    Error,
}

fn runtime_boundary_outcome(
    builtin: &str,
    boundary: &str,
) -> std::io::Result<RuntimeBoundaryOutcome> {
    if (builtin == "Options.strOption" && matches!(boundary, "absent-option" | "malformed-option"))
        || (builtin == "Options.strArgument"
            && matches!(
                boundary,
                "absent-option" | "repeated-option" | "malformed-option"
            ))
        || (builtin == "Options.switch"
            && matches!(boundary, "repeated-option" | "malformed-option"))
        || (builtin == "Options.flag" && matches!(boundary, "repeated-option" | "malformed-option"))
        || (builtin == "Options.flag'"
            && matches!(
                boundary,
                "absent-option" | "repeated-option" | "malformed-option"
            ))
        || (matches!(builtin, "Flag.long" | "Flag.help")
            && matches!(boundary, "repeated-option" | "malformed-option"))
        || (matches!(builtin, "Option.long" | "Option.help")
            && matches!(boundary, "absent-option" | "malformed-option"))
        || (matches!(builtin, "Argument.metavar" | "Argument.help")
            && matches!(
                boundary,
                "absent-option" | "repeated-option" | "malformed-option"
            ))
        || (matches!(builtin, "Option.value" | "Argument.value")
            && matches!(boundary, "repeated-option" | "malformed-option"))
        || (matches!(
            builtin,
            "Options.header"
                | "Options.progDesc"
                | "Options.helper"
                | "Options.info"
                | "Options.fullDesc"
        ) && matches!(boundary, "repeated-option" | "malformed-option"))
        || (matches!(builtin, "Options.command" | "Options.hsubparser")
            && matches!(
                boundary,
                "absent-option" | "repeated-option" | "malformed-option"
            ))
    {
        Ok(RuntimeBoundaryOutcome::TargetValueWithFailure)
    } else if boundary == "bottom-after-demanded-prefix"
        || matches!(boundary, "absent-option" | "malformed-option")
            && builtin == "Options.execParser"
        || boundary == "invalid-encoding"
            && matches!(
                builtin,
                "Text.decodeUtf8"
                    | "Text.getContents"
                    | "Text.getLine"
                    | "Text.readFile"
                    | "Text.interact"
                    | "Text.readProcess"
                    | "Text.readProcess_"
                    | "Text.readProcessStdout_"
            )
        || boundary == "empty-input" && builtin == "Text.getLine"
        || boundary == "empty-input" && builtin == "List.cycle"
    {
        Ok(RuntimeBoundaryOutcome::Error)
    } else if crate::mandatory_runtime_boundaries()
        .iter()
        .any(|requirement| requirement.class.as_ref() == boundary)
    {
        Ok(RuntimeBoundaryOutcome::Value)
    } else {
        Err(std::io::Error::other(
            "runtime boundary outcome is not authoritative",
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RetainedEffectEvent {
    builtin: hell_builtins::BuiltinId,
    owner_task: Option<u64>,
    sequence: u64,
    parent_sequence: Option<u64>,
    lifecycle: String,
}

type RetainedResourceEvent = (u64, hell_builtins::BuiltinId, Option<u64>, String);

fn validate_task_causality(
    tasks: &[(u64, hell_builtins::BuiltinId, String)],
    coverage: &[CoverageEvent],
) -> std::io::Result<()> {
    use std::collections::BTreeMap;

    let mut lifecycles = BTreeMap::<u64, Vec<&(u64, hell_builtins::BuiltinId, String)>>::new();
    let mut trace_events = BTreeMap::<(u16, &str), usize>::new();
    for event in tasks {
        lifecycles.entry(event.0).or_default().push(event);
        *trace_events
            .entry((event.1.0, event.2.as_str()))
            .or_default() += 1;
    }
    let task_count = u64::try_from(lifecycles.len())
        .map_err(|_| std::io::Error::other("semantic task count exceeds u64"))?;
    if !lifecycles.keys().copied().eq(1..=task_count) {
        return Err(std::io::Error::other(
            "semantic task IDs are not exact contiguous canonical identities",
        ));
    }
    for lifecycle in lifecycles.values() {
        if lifecycle.len() != 2
            || lifecycle[0].2 != "started"
            || !matches!(
                lifecycle[1].2.as_str(),
                "completed" | "failed" | "cancelled"
            )
            || lifecycle[0].1 != lifecycle[1].1
        {
            return Err(std::io::Error::other(
                "semantic task is not one same-builtin start-to-terminal pair",
            ));
        }
    }
    let mut coverage_events = BTreeMap::<(u16, &str), usize>::new();
    for event in coverage {
        if let CoverageEvent::TaskEvent(builtin, lifecycle) = event {
            *coverage_events
                .entry((builtin.0, lifecycle.as_ref()))
                .or_default() += 1;
        }
    }
    if trace_events != coverage_events {
        return Err(std::io::Error::other(
            "semantic task trace is not exactly joined to task coverage",
        ));
    }
    Ok(())
}

fn validate_effect_causality(
    events: &[RetainedEffectEvent],
    tasks: &[(u64, hell_builtins::BuiltinId, String)],
    coverage: &[CoverageEvent],
) -> std::io::Result<()> {
    use std::collections::{BTreeMap, BTreeSet};

    let task_ids = tasks.iter().map(|event| event.0).collect::<BTreeSet<_>>();
    let mut invocations = BTreeMap::<(Option<u64>, u64), Vec<&RetainedEffectEvent>>::new();
    for event in events {
        if event
            .owner_task
            .is_some_and(|owner| !task_ids.contains(&owner))
        {
            return Err(std::io::Error::other(
                "semantic effect owner is not a retained task",
            ));
        }
        if !coverage.iter().any(|coverage| {
            matches!(coverage, CoverageEvent::ExecutedEffect(builtin, lifecycle)
                if *builtin == event.builtin && lifecycle.as_ref() == event.lifecycle)
        }) {
            return Err(std::io::Error::other(
                "semantic effect is not joined to coverage",
            ));
        }
        invocations
            .entry((event.owner_task, event.sequence))
            .or_default()
            .push(event);
    }
    let mut sequences = BTreeMap::<Option<u64>, BTreeSet<u64>>::new();
    for ((owner, sequence), lifecycle) in &invocations {
        if lifecycle.len() != 2
            || lifecycle[0].lifecycle != "started"
            || !matches!(
                lifecycle[1].lifecycle.as_str(),
                "completed" | "failed" | "cancelled"
            )
            || lifecycle[0].builtin != lifecycle[1].builtin
            || lifecycle[0].parent_sequence != lifecycle[1].parent_sequence
        {
            return Err(std::io::Error::other(
                "semantic effect is not an exact start-to-terminal pair",
            ));
        }
        sequences.entry(*owner).or_default().insert(*sequence);
        if let Some(parent) = lifecycle[0].parent_sequence
            && !invocations.contains_key(&(*owner, parent))
        {
            return Err(std::io::Error::other(
                "semantic effect causal parent is missing",
            ));
        }
    }
    for owner_sequences in sequences.values() {
        let last = u64::try_from(owner_sequences.len())
            .map_err(|_| std::io::Error::other("semantic effect count exceeds u64"))?;
        if !owner_sequences.iter().copied().eq(1..=last) {
            return Err(std::io::Error::other(
                "semantic effect sequences are not contiguous",
            ));
        }
    }
    Ok(())
}

fn validate_obligation_causality(
    events: &[crate::ObligationTraceEvent],
    tasks: &[(u64, hell_builtins::BuiltinId, String)],
) -> std::io::Result<()> {
    use std::collections::{BTreeMap, BTreeSet};

    let task_ids = tasks.iter().map(|event| event.0).collect::<BTreeSet<_>>();
    let identities = events
        .iter()
        .map(|event| ((event.owner_task, event.sequence), event))
        .collect::<BTreeMap<_, _>>();
    if identities.len() != events.len() {
        return Err(std::io::Error::other(
            "semantic obligation causal identity is duplicated",
        ));
    }
    let mut child_counts = BTreeMap::<(Option<u64>, u64), u64>::new();
    let mut owner_sequences = BTreeMap::<Option<u64>, BTreeSet<u64>>::new();
    for event in events {
        if event
            .owner_task
            .is_some_and(|owner| !task_ids.contains(&owner))
        {
            return Err(std::io::Error::other(
                "semantic obligation owner is not a retained task",
            ));
        }
        owner_sequences
            .entry(event.owner_task)
            .or_default()
            .insert(event.sequence);
        if let Some(parent) = event.parent_sequence {
            let identity = (event.owner_task, parent);
            if !identities.contains_key(&identity) {
                return Err(std::io::Error::other(
                    "semantic obligation causal parent is missing",
                ));
            }
            child_counts
                .entry(identity)
                .and_modify(|count| *count = count.saturating_add(1))
                .or_insert(1);
        }
    }
    for sequences in owner_sequences.values() {
        let end = u64::try_from(sequences.len())
            .map_err(|_| std::io::Error::other("semantic obligation count exceeds u64"))?;
        if !sequences.iter().copied().eq(1..=end) {
            return Err(std::io::Error::other(
                "semantic obligation sequences are not contiguous",
            ));
        }
    }
    for event in events {
        let children = child_counts
            .get(&(event.owner_task, event.sequence))
            .copied()
            .unwrap_or(0);
        if children != event.nested_adapters {
            return Err(std::io::Error::other(
                "semantic obligation nested count does not match causal children",
            ));
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct ConformanceObservationFacts {
    raw_presentation_sha256: Digest,
    normalized_line_endings_sha256: Option<Digest>,
    resource_audit_failures: u64,
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn validate_obligation_semantics(
    obligation: &str,
    dimension: hell_builtins::CompatibilityDimension,
    builtin: hell_builtins::BuiltinId,
    document: &str,
    observation_directory: &Path,
    observed: &[CoverageEvent],
    effect_trace: &[RetainedEffectEvent],
    task_trace: &[(u64, hell_builtins::BuiltinId, String)],
    resource_trace: &[(u64, hell_builtins::BuiltinId, Option<u64>, String)],
    obligation_trace: &[crate::ObligationTraceEvent],
    typed_result: Option<Digest>,
    typed_result_builtin: Option<u16>,
    boundaries: &[(
        hell_builtins::BuiltinId,
        u16,
        String,
        String,
        Option<String>,
    )],
    platforms: &[hell_builtins::ClaimPlatform],
    expected_raw_presentation_sha256: Option<Digest>,
    expected_presentation_shadow_normalizer: Option<PresentationShadowNormalizerId>,
    expected_normalized_presentation_sha256: Option<Digest>,
    conformance_facts: Option<&ConformanceObservationFacts>,
) -> std::io::Result<()> {
    use hell_builtins::CompatibilityDimension;
    let effect = |lifecycle: &str| {
        effect_trace
            .iter()
            .any(|event| event.builtin == builtin && event.lifecycle == lifecycle)
    };
    let presentation = || {
        observed.iter().any(|event| {
            matches!(event, CoverageEvent::PresentedField(id, value) if *id == builtin && value.as_ref() == "rendered-output")
        })
    };
    let tasks = task_trace
        .iter()
        .filter(|event| event.1 == builtin)
        .collect::<Vec<_>>();
    let resources = resource_trace
        .iter()
        .filter(|event| event.1 == builtin)
        .collect::<Vec<_>>();
    let adapter_events = obligation_trace
        .iter()
        .filter(|event| event.builtin == builtin)
        .collect::<Vec<_>>();
    let entered = observed.contains(&CoverageEvent::EnteredAdapter(builtin));
    let success = parse_observation_success(document)?;
    let result_force_failed = typed_adapter_result_is_force_error(
        document,
        observation_directory,
        typed_result,
        typed_result_builtin,
        builtin,
    )?;
    let satisfied = if dimension == CompatibilityDimension::PureRuntime {
        let flags = u8::from(success)
            | (u8::from(entered) << 1)
            | (u8::from(effect("started")) << 2)
            | (u8::from(typed_result.is_some() && typed_result_builtin == Some(builtin.0)) << 3)
            | (u8::from(effect("failed")) << 4)
            | (u8::from(result_force_failed) << 5);
        evaluate_pure_runtime_obligation(obligation, flags, &adapter_events, boundaries, builtin)
    } else {
        match (dimension, obligation) {
            (CompatibilityDimension::Effects, "effect-success") => success && effect("completed"),
            (CompatibilityDimension::Effects, "effect-failure") => !success && effect("failed"),
            (CompatibilityDimension::Effects, "effect-cancellation") => {
                success && effect("cancelled")
            }
            (CompatibilityDimension::Effects, "effect-ordering") => {
                effect("started")
                    && (effect("completed") || effect("failed") || effect("cancelled"))
            }
            (CompatibilityDimension::Concurrency, "task-lifecycle") => {
                complete_task_lifecycle(&tasks)
            }
            (CompatibilityDimension::Concurrency, "race-cancellation") => {
                complete_task_lifecycle(&tasks) && tasks.iter().any(|event| event.2 == "cancelled")
            }
            (CompatibilityDimension::Concurrency, "scope-cleanup") => {
                complete_task_lifecycle(&tasks)
                    && zero_resource_audit(observation_directory, conformance_facts)?
            }
            (CompatibilityDimension::Presentation, obligation) => validate_presentation_obligation(
                obligation,
                presentation(),
                observation_directory,
                expected_raw_presentation_sha256,
                expected_presentation_shadow_normalizer,
                expected_normalized_presentation_sha256,
                conformance_facts,
            )?,
            (CompatibilityDimension::Platform, "three-platform-observation") => {
                required_platforms_present(platforms)
            }
            (CompatibilityDimension::ResourceBehavior, "bounded-materialization") => {
                let exact_singleton = hell_builtins::registry()
                    .iter()
                    .find(|spec| spec.id == builtin)
                    .is_some_and(|spec| matches!(spec.name, "Map.singleton" | "Set.singleton"));
                let materialization = if exact_singleton {
                    adapter_events.iter().any(|event| {
                        event.materialized_before == 0 && event.materialized_after == 0
                    })
                } else {
                    adapter_events
                        .iter()
                        .any(|event| event.materialized_after >= event.materialized_before)
                };
                success
                    && entered
                    && materialization
                    && zero_resource_audit(observation_directory, conformance_facts)?
            }
            (CompatibilityDimension::ResourceBehavior, "resource-audit") => {
                entered && zero_resource_audit(observation_directory, conformance_facts)?
            }
            (CompatibilityDimension::ResourceBehavior, "cleanup-trace") => {
                if hell_builtins::registry()
                    .iter()
                    .find(|spec| spec.id == builtin)
                    .is_some_and(|spec| spec.name.starts_with("Async."))
                {
                    complete_task_lifecycle(&tasks)
                        && zero_resource_audit(observation_directory, conformance_facts)?
                } else {
                    target_resource_lifecycle(
                        builtin,
                        &resources,
                        observation_directory,
                        conformance_facts,
                    )?
                }
            }
            _ => false,
        }
    };
    if satisfied {
        Ok(())
    } else {
        let builtin_name = hell_builtins::registry()[usize::from(builtin.0)].name;
        Err(std::io::Error::other(format!(
            "{dimension:?} obligation {obligation} for {builtin_name} lacks target-scoped semantic evidence"
        )))
    }
}

fn typed_adapter_result_is_force_error(
    document: &str,
    observation_directory: &Path,
    digest: Option<Digest>,
    typed_builtin: Option<u16>,
    builtin: hell_builtins::BuiltinId,
) -> std::io::Result<bool> {
    if digest.is_none() || typed_builtin != Some(builtin.0) {
        return Ok(false);
    }
    let canonical = if observation_directory.as_os_str().is_empty() {
        let encoded = exact_observation_field(document, "semanticTypedResultHex")?
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .ok_or_else(|| std::io::Error::other("typed result hex is malformed"))?;
        String::from_utf8(
            crate::decode_canonical_hex(encoded)
                .ok_or_else(|| std::io::Error::other("typed result hex is noncanonical"))?,
        )
        .map_err(|_| std::io::Error::other("typed result is not UTF-8"))?
    } else {
        fs::read_to_string(observation_directory.join("semantic-typed-result.json"))?
            .strip_suffix('\n')
            .ok_or_else(|| {
                std::io::Error::other("retained typed result lacks one trailing newline")
            })?
            .to_owned()
    };
    crate::validate_canonical_typed_value(&canonical)?;
    if Some(sha256_bytes(canonical.as_bytes())) != digest {
        return Err(std::io::Error::other(
            "typed adapter result bytes disagree with their digest",
        ));
    }
    Ok(canonical.starts_with(concat!(
        "{\"type\":\"TypedResult\",\"argument\":0,",
        "\"boundary\":\"adapter-result\",\"value\":",
        "{\"type\":\"ForceBoundary\",\"outcome\":\"error\",\"code\":\"",
    )))
}

fn validate_presentation_obligation(
    obligation: &str,
    presented: bool,
    observation_directory: &Path,
    expected_raw: Option<Digest>,
    normalizer: Option<PresentationShadowNormalizerId>,
    expected_shadow: Option<Digest>,
    conformance_facts: Option<&ConformanceObservationFacts>,
) -> std::io::Result<bool> {
    if !presented {
        return Ok(false);
    }
    match obligation {
        "raw-observation" => {
            validate_raw_presentation(observation_directory, expected_raw, conformance_facts)
        }
        "normalized-shadow-diff" => validate_normalized_presentation_shadow(
            observation_directory,
            normalizer,
            expected_shadow,
            conformance_facts,
        ),
        _ => Ok(false),
    }
}

fn validate_raw_presentation(
    observation_directory: &Path,
    expected: Option<Digest>,
    conformance_facts: Option<&ConformanceObservationFacts>,
) -> std::io::Result<bool> {
    let Some(expected) = expected else {
        return Ok(false);
    };
    if let Some(facts) = conformance_facts {
        return Ok(facts.raw_presentation_sha256 == expected);
    }
    let bundle = observation_directory
        .parent()
        .ok_or_else(|| std::io::Error::other("observation has no bundle parent"))?;
    let directories = if observation_directory.file_name() == Some(OsStr::new("oracle")) {
        vec![observation_directory.to_path_buf()]
    } else {
        vec![observation_directory.to_path_buf(), bundle.join("oracle")]
    };
    for directory in directories {
        let stdout = fs::read(directory.join("stdout.bin"))?;
        let stderr = fs::read(directory.join("stderr.raw.bin"))?;
        if crate::raw_presentation_sha256(&stdout, &stderr) != expected {
            return Ok(false);
        }
    }
    Ok(true)
}

fn validate_normalized_presentation_shadow(
    observation_directory: &Path,
    normalizer: Option<PresentationShadowNormalizerId>,
    expected: Option<Digest>,
    conformance_facts: Option<&ConformanceObservationFacts>,
) -> std::io::Result<bool> {
    let (Some(normalizer), Some(expected)) = (normalizer, expected) else {
        return Ok(false);
    };
    if let Some(facts) = conformance_facts {
        return Ok(match normalizer {
            PresentationShadowNormalizerId::LineEndingsV1 => {
                facts.normalized_line_endings_sha256 == Some(expected)
            }
        });
    }
    let bundle = observation_directory
        .parent()
        .ok_or_else(|| std::io::Error::other("observation has no bundle parent"))?;
    let directories = if observation_directory.file_name() == Some(OsStr::new("oracle")) {
        vec![observation_directory.to_path_buf()]
    } else {
        vec![observation_directory.to_path_buf(), bundle.join("oracle")]
    };
    for directory in directories {
        let stdout = fs::read(directory.join("stdout.bin"))?;
        let stderr = fs::read(directory.join("stderr.raw.bin"))?;
        let actual = normalized_presentation_shadow_sha256(normalizer, &stdout, &stderr)
            .map_err(std::io::Error::other)?;
        if actual != expected {
            return Ok(false);
        }
    }
    Ok(true)
}

fn validate_options_presentation_dependency(
    target: &crate::EvidenceTargetV2,
    builtin: hell_builtins::BuiltinId,
    obligation_trace: &[crate::ObligationTraceEvent],
    effect_trace: &[RetainedEffectEvent],
) -> std::io::Result<()> {
    if target.expected_normalized_presentation_sha256.is_none() {
        return Ok(());
    }
    let exec_parser = hell_builtins::lookup("Options.execParser")
        .expect("Options.execParser remains registry-backed")
        .id;
    let target_event = exactly_one_adapter_event(obligation_trace, builtin, "presentation target")?;
    let sink_event = exactly_one_adapter_event(obligation_trace, exec_parser, "presentation sink")?;
    if target_event.owner_task != sink_event.owner_task {
        return Err(std::io::Error::other(
            "Options presentation target and sink have different owners",
        ));
    }
    let expected_target_outcome = if builtin == exec_parser {
        "io-action"
    } else {
        "value"
    };
    if target_event.outcome.as_ref() != expected_target_outcome
        || sink_event.outcome.as_ref() != "io-action"
    {
        return Err(std::io::Error::other(
            "Options presentation target or sink has the wrong adapter outcome",
        ));
    }
    validate_adapter_ancestry(target_event, sink_event, obligation_trace)?;
    validate_options_sink_effect(sink_event, exec_parser, effect_trace)
}

fn validate_presentation_dependency(
    target: &crate::EvidenceTargetV2,
    builtin: hell_builtins::BuiltinId,
    obligation_trace: &[crate::ObligationTraceEvent],
    effect_trace: &[RetainedEffectEvent],
) -> std::io::Result<()> {
    if target.expected_normalized_presentation_sha256.is_none() {
        return Ok(());
    }
    let name = hell_builtins::registry()[usize::from(builtin.0)].name;
    if name.starts_with("Options.") {
        return validate_options_presentation_dependency(
            target,
            builtin,
            obligation_trace,
            effect_trace,
        );
    }
    match name {
        "Show.show" => {
            validate_show_presentation_dependency(target, builtin, obligation_trace, effect_trace)
        }
        "IO.print" => {
            validate_print_presentation_dependency(builtin, obligation_trace, effect_trace)
        }
        _ => Err(std::io::Error::other(
            "normalized presentation target has no retained sink dependency",
        )),
    }
}

fn validate_show_presentation_dependency(
    target: &crate::EvidenceTargetV2,
    builtin: hell_builtins::BuiltinId,
    obligation_trace: &[crate::ObligationTraceEvent],
    effect_trace: &[RetainedEffectEvent],
) -> std::io::Result<()> {
    let sink = hell_builtins::lookup("Text.putStrLn")
        .expect("Text.putStrLn remains registry-backed")
        .id;
    let target_event = exactly_one_adapter_event(obligation_trace, builtin, "Show.show target")?;
    let sink_event = exactly_one_adapter_event(obligation_trace, sink, "Text.putStrLn sink")?;
    if target_event.owner_task != sink_event.owner_task
        || target_event.outcome.as_ref() != "value"
        || sink_event.outcome.as_ref() != "io-action"
    {
        return Err(std::io::Error::other(
            "Show.show target and Text.putStrLn sink disagree",
        ));
    }
    validate_show_value_flow(target, target_event, sink_event, obligation_trace)?;
    validate_completed_presentation_sink_effect(sink_event, sink, effect_trace)
}

fn validate_show_value_flow(
    expected: &crate::EvidenceTargetV2,
    target: &crate::ObligationTraceEvent,
    sink: &crate::ObligationTraceEvent,
    events: &[crate::ObligationTraceEvent],
) -> std::io::Result<()> {
    let apply = hell_builtins::lookup("$")
        .expect("$ remains registry-backed")
        .id;
    let inner = adapter_parent_event(target, events, "Show.show value producer")?;
    let outer = adapter_parent_event(sink, events, "Text.putStrLn value consumer")?;
    if inner.builtin != apply || outer.builtin != apply || inner.sequence == outer.sequence {
        return Err(std::io::Error::other(
            "Show.show presentation lacks two distinct Function.$ flow adapters",
        ));
    }
    let inner_callback = exact_value_callback(inner, "Show.show producer")?;
    let outer_callback = exact_value_callback(outer, "Text.putStrLn consumer")?;
    let typed = format!(
        "{{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",\"value\":{}}}",
        inner_callback.canonical_result,
    );
    if outer_callback.canonical_arguments.as_slice()
        != [Arc::clone(&inner_callback.canonical_result)]
        || outer_callback.canonical_result.as_ref() != "{\"type\":\"IoAction\"}"
        || expected.expected_typed_result_sha256 != Some(sha256_bytes(typed.as_bytes()))
    {
        return Err(std::io::Error::other(
            "Show.show result does not exactly feed Text.putStrLn",
        ));
    }
    Ok(())
}

fn adapter_parent_event<'a>(
    event: &crate::ObligationTraceEvent,
    events: &'a [crate::ObligationTraceEvent],
    label: &str,
) -> std::io::Result<&'a crate::ObligationTraceEvent> {
    let parent = event
        .parent_sequence
        .ok_or_else(|| std::io::Error::other(format!("{label} has no adapter parent")))?;
    let mut matching = events.iter().filter(|candidate| {
        candidate.owner_task == event.owner_task && candidate.sequence == parent
    });
    let parent = matching
        .next()
        .ok_or_else(|| std::io::Error::other(format!("{label} parent is absent")))?;
    if matching.next().is_some() {
        return Err(std::io::Error::other(format!(
            "{label} parent is ambiguous"
        )));
    }
    Ok(parent)
}

fn exact_value_callback<'a>(
    event: &'a crate::ObligationTraceEvent,
    label: &str,
) -> std::io::Result<&'a crate::CallbackTraceEvent> {
    let [callback] = event.callbacks.as_slice() else {
        return Err(std::io::Error::other(format!(
            "{label} lacks one exact callback"
        )));
    };
    if callback.invocation != 1
        || callback.callback_argument != 0
        || callback.branch.as_ref() != "function"
        || callback.outcome.as_ref() != "value"
    {
        return Err(std::io::Error::other(format!(
            "{label} callback identity disagrees"
        )));
    }
    Ok(callback)
}

fn validate_print_presentation_dependency(
    builtin: hell_builtins::BuiltinId,
    obligation_trace: &[crate::ObligationTraceEvent],
    effect_trace: &[RetainedEffectEvent],
) -> std::io::Result<()> {
    let target = exactly_one_adapter_event(obligation_trace, builtin, "IO.print target")?;
    let show = hell_builtins::lookup("Show.show")
        .expect("Show.show remains registry-backed")
        .id;
    if target.outcome.as_ref() != "io-action"
        || obligation_trace.iter().any(|event| event.builtin == show)
    {
        return Err(std::io::Error::other(
            "IO.print presentation is not a direct Show instance consumer",
        ));
    }
    validate_completed_presentation_sink_effect(target, builtin, effect_trace)
}

fn validate_completed_presentation_sink_effect(
    sink: &crate::ObligationTraceEvent,
    builtin: hell_builtins::BuiltinId,
    effect_trace: &[RetainedEffectEvent],
) -> std::io::Result<()> {
    let matching = effect_trace
        .iter()
        .filter(|event| event.builtin == builtin && event.owner_task == sink.owner_task)
        .collect::<Vec<_>>();
    if matching.len() != 2
        || matching[0].sequence != matching[1].sequence
        || matching[0].lifecycle != "started"
        || matching[1].lifecycle != "completed"
    {
        return Err(std::io::Error::other(
            "presentation sink lacks its exact completed effect lifecycle",
        ));
    }
    Ok(())
}

fn exactly_one_adapter_event<'a>(
    events: &'a [crate::ObligationTraceEvent],
    builtin: hell_builtins::BuiltinId,
    label: &str,
) -> std::io::Result<&'a crate::ObligationTraceEvent> {
    let mut matching = events.iter().filter(|event| event.builtin == builtin);
    let event = matching
        .next()
        .ok_or_else(|| std::io::Error::other(format!("{label} adapter is absent")))?;
    if matching.next().is_some() {
        return Err(std::io::Error::other(format!(
            "{label} adapter is not unique"
        )));
    }
    Ok(event)
}

fn validate_adapter_ancestry(
    target: &crate::ObligationTraceEvent,
    sink: &crate::ObligationTraceEvent,
    events: &[crate::ObligationTraceEvent],
) -> std::io::Result<()> {
    let mut current = target;
    for _ in 0..events.len() {
        if current.sequence == sink.sequence && current.owner_task == sink.owner_task {
            return Ok(());
        }
        let parent = current.parent_sequence.ok_or_else(|| {
            std::io::Error::other("Options presentation target is not consumed by execParser")
        })?;
        let mut matching = events
            .iter()
            .filter(|event| event.owner_task == current.owner_task && event.sequence == parent);
        current = matching.next().ok_or_else(|| {
            std::io::Error::other("Options presentation ancestry references an absent adapter")
        })?;
        if matching.next().is_some() || current.outcome.as_ref() == "error" {
            return Err(std::io::Error::other(
                "Options presentation ancestry is ambiguous or failed",
            ));
        }
    }
    Err(std::io::Error::other(
        "Options presentation ancestry contains a cycle",
    ))
}

fn validate_options_sink_effect(
    sink: &crate::ObligationTraceEvent,
    exec_parser: hell_builtins::BuiltinId,
    effect_trace: &[RetainedEffectEvent],
) -> std::io::Result<()> {
    let matching = effect_trace
        .iter()
        .filter(|event| event.builtin == exec_parser && event.owner_task == sink.owner_task)
        .collect::<Vec<_>>();
    if matching.len() != 2
        || matching[0].sequence != matching[1].sequence
        || matching[0].lifecycle != "started"
        || matching[1].lifecycle != "failed"
    {
        return Err(std::io::Error::other(
            "Options.execParser help sink lacks its exact started/Exit(0) lifecycle",
        ));
    }
    Ok(())
}

struct PureRuntimeFacts<'a> {
    flags: u8,
    events: &'a [&'a crate::ObligationTraceEvent],
    boundaries: [bool; 6],
}

fn evaluate_pure_runtime_obligation(
    obligation: &str,
    flags: u8,
    events: &[&crate::ObligationTraceEvent],
    boundaries: &[(
        hell_builtins::BuiltinId,
        u16,
        String,
        String,
        Option<String>,
    )],
    builtin: hell_builtins::BuiltinId,
) -> bool {
    let pre_adapter_whnf_failure = flags & 0b10 == 0
        && events.is_empty()
        && boundaries
            .iter()
            .any(|(id, _, class, outcome, error_code)| {
                *id == builtin
                    && class == "whnf-force-failed"
                    && outcome == "error"
                    && error_code.is_some()
            });
    if obligation == "whnf-failure-boundary" {
        return flags & 0b01 == 0 && pre_adapter_whnf_failure;
    }
    if obligation == "lazy-boundary" && pre_adapter_whnf_failure {
        return exact_lazy_adapter_entry_states(builtin, boundaries, 1);
    }
    pure_runtime_obligation_satisfied(
        obligation,
        &PureRuntimeFacts {
            flags,
            events,
            boundaries: [
                exact_lazy_adapter_entry_states(builtin, boundaries, events.len()),
                exact_demand_argument_states(
                    builtin,
                    boundaries,
                    hell_builtins::Demand::Whnf,
                    "whnf-force-complete",
                ),
                false,
                exact_conditional_branch_partition(builtin, boundaries),
                exact_conditional_branch_partition(builtin, boundaries),
                exact_demand_argument_states(
                    builtin,
                    boundaries,
                    hell_builtins::Demand::OnIoExecution,
                    "io-execution-complete",
                ),
            ],
        },
    )
}

fn exact_demand_argument_states(
    builtin: hell_builtins::BuiltinId,
    boundaries: &[(
        hell_builtins::BuiltinId,
        u16,
        String,
        String,
        Option<String>,
    )],
    demand: hell_builtins::Demand,
    class: &str,
) -> bool {
    let expected = hell_builtins::registry()[usize::from(builtin.0)]
        .demand
        .iter()
        .enumerate()
        .filter(|(_, observed)| **observed == demand)
        .map(|(index, _)| u16::try_from(index).expect("builtin arity fits u16"))
        .collect::<Vec<_>>();
    let observed = boundaries
        .iter()
        .filter(|(id, _, observed_class, _, _)| *id == builtin && observed_class == class)
        .collect::<Vec<_>>();
    !expected.is_empty()
        && observed.len() == expected.len()
        && expected.iter().all(|argument| {
            observed
                .iter()
                .any(|(_, observed, _, _, _)| observed == argument)
        })
        && observed.iter().all(|(_, argument, _, outcome, _)| {
            expected.contains(argument)
                && match demand {
                    hell_builtins::Demand::OnIoExecution => {
                        matches!(outcome.as_str(), "value" | "error")
                    }
                    _ => outcome == "value",
                }
        })
}

fn exact_conditional_branch_partition(
    builtin: hell_builtins::BuiltinId,
    boundaries: &[(
        hell_builtins::BuiltinId,
        u16,
        String,
        String,
        Option<String>,
    )],
) -> bool {
    let expected = hell_builtins::registry()[usize::from(builtin.0)]
        .demand
        .iter()
        .enumerate()
        .filter(|(_, demand)| **demand == hell_builtins::Demand::Lazy)
        .map(|(index, _)| u16::try_from(index).expect("builtin arity fits u16"))
        .collect::<Vec<_>>();
    let observed = boundaries
        .iter()
        .filter(|(id, _, class, _, _)| *id == builtin && class == "conditional-branch")
        .collect::<Vec<_>>();
    expected.len() == 2
        && observed.len() == 2
        && observed
            .iter()
            .filter(|(_, _, _, outcome, _)| outcome == "value")
            .count()
            == 1
        && observed
            .iter()
            .filter(|(_, _, _, outcome, _)| outcome == "not-forced")
            .count()
            == 1
        && expected.iter().all(|argument| {
            observed
                .iter()
                .any(|(_, observed, _, _, _)| observed == argument)
        })
        && observed
            .iter()
            .all(|(_, argument, _, _, _)| expected.contains(argument))
}

fn exact_lazy_adapter_entry_states(
    builtin: hell_builtins::BuiltinId,
    boundaries: &[(
        hell_builtins::BuiltinId,
        u16,
        String,
        String,
        Option<String>,
    )],
    invocation_count: usize,
) -> bool {
    let spec = &hell_builtins::registry()[usize::from(builtin.0)];
    let expected = spec
        .demand
        .iter()
        .enumerate()
        .filter(|(_, demand)| **demand == hell_builtins::Demand::Lazy)
        .map(|(index, _)| u16::try_from(index).expect("builtin arity fits u16"))
        .collect::<Vec<_>>();
    let observed = boundaries
        .iter()
        .filter(|(id, _, class, _, _)| *id == builtin && class == "lazy-adapter-entry")
        .collect::<Vec<_>>();
    !expected.is_empty()
        && invocation_count != 0
        && observed.len() == expected.len().saturating_mul(invocation_count)
        && expected.iter().all(|argument| {
            observed
                .iter()
                .filter(|(_, observed, _, _, _)| observed == argument)
                .count()
                == invocation_count
        })
        && observed.iter().all(|(_, argument, _, outcome, _)| {
            expected.contains(argument) && outcome == "not-forced"
        })
}

fn pure_runtime_obligation_satisfied(obligation: &str, facts: &PureRuntimeFacts<'_>) -> bool {
    let success = facts.flags & 1 != 0;
    let entered = facts.flags & 2 != 0;
    let effect_started = facts.flags & 4 != 0;
    let typed_result_matches = facts.flags & 8 != 0;
    let effect_failed = facts.flags & 16 != 0;
    let result_force_failed = facts.flags & 32 != 0;
    let events = facts.events;
    let boundaries = facts.boundaries;
    match obligation {
        "adapter-success" => {
            entered && events.iter().any(|event| event.outcome.as_ref() != "error")
        }
        "adapter-failure" => {
            !success
                && entered
                && (effect_failed || events.iter().any(|event| event.outcome.as_ref() == "error"))
        }
        "result-force-failure" => {
            !success
                && entered
                && result_force_failed
                && events.len() == 1
                && events[0].outcome.as_ref() == "alias"
        }
        "lazy-boundary" => boundaries[0],
        "whnf-boundary" => boundaries[1],
        "deep-boundary" => boundaries[2],
        "conditional-selected" => boundaries[3],
        "conditional-unselected" => boundaries[4],
        "io-execution-boundary" => boundaries[5] && effect_started,
        "typed-result" => typed_result_matches,
        // The exact source-reviewed callback contract is compared after the
        // generic obligation pass, including legitimate zero-call boundaries.
        "callback-order" => entered,
        "collection-interaction"
        | "constructor-eliminator"
        | "numeric-boundary"
        | "parser-composition" => success && entered && !events.is_empty(),
        "encoding-boundary" => entered && !events.is_empty(),
        _ => false,
    }
}

fn required_platforms_present(platforms: &[hell_builtins::ClaimPlatform]) -> bool {
    use hell_builtins::ClaimPlatform;
    [
        ClaimPlatform::Linux,
        ClaimPlatform::MacOs,
        ClaimPlatform::Windows,
    ]
    .iter()
    .all(|platform| platforms.contains(platform))
}

fn complete_task_lifecycle(events: &[&(u64, hell_builtins::BuiltinId, String)]) -> bool {
    let mut states = std::collections::BTreeMap::new();
    for (task, _, lifecycle) in events {
        match lifecycle.as_str() {
            "started" if !states.contains_key(task) => {
                states.insert(*task, false);
            }
            "completed" | "failed" | "cancelled" if states.get(task) == Some(&false) => {
                states.insert(*task, true);
            }
            _ => return false,
        }
    }
    !states.is_empty() && states.values().all(|terminal| *terminal)
}

fn complete_resource_lifecycle(
    events: &[&(u64, hell_builtins::BuiltinId, Option<u64>, String)],
) -> bool {
    let mut states = std::collections::BTreeMap::new();
    for (resource, _, _, lifecycle) in events {
        match lifecycle.as_str() {
            "acquire" if !states.contains_key(resource) => {
                states.insert(*resource, false);
            }
            "transfer" | "cleanup-failure" if states.get(resource) == Some(&false) => {}
            "close" | "cancel" if states.get(resource) == Some(&false) => {
                states.insert(*resource, true);
            }
            _ => return false,
        }
    }
    !states.is_empty() && states.values().all(|terminal| *terminal)
}

fn target_resource_lifecycle(
    builtin: hell_builtins::BuiltinId,
    events: &[&(u64, hell_builtins::BuiltinId, Option<u64>, String)],
    observation_directory: &Path,
    conformance_facts: Option<&ConformanceObservationFacts>,
) -> std::io::Result<bool> {
    let builtin_name = hell_builtins::registry()
        .get(usize::from(builtin.0))
        .filter(|spec| spec.id == builtin)
        .map(|spec| spec.name)
        .ok_or_else(|| std::io::Error::other("resource trace builtin is unknown"))?;
    let exact_segment = match builtin_name {
        "IO.openFile" => events.len() == 1 && events[0].3 == "acquire",
        "IO.hClose" | "Process.useHandleClose" => events.len() == 1 && events[0].3 == "close",
        _ => return Ok(complete_resource_lifecycle(events)),
    };
    Ok(exact_segment && zero_resource_audit(observation_directory, conformance_facts)?)
}

fn zero_resource_audit(
    directory: &Path,
    conformance_facts: Option<&ConformanceObservationFacts>,
) -> std::io::Result<bool> {
    if let Some(facts) = conformance_facts {
        return Ok(facts.resource_audit_failures == 0);
    }
    let audit = fs::read_to_string(directory.join("resource-audit.json"))?;
    Ok(audit == resource_audit_json(&ResourceAudit::default()))
}

fn target_has_causal_signal(
    signal: CausalSignal,
    builtin: hell_builtins::BuiltinId,
    observed: &[CoverageEvent],
) -> std::io::Result<bool> {
    Ok(match signal {
        CausalSignal::ParsedBuiltin => observed.contains(&CoverageEvent::ParsedBuiltin(builtin)),
        CausalSignal::ResolvedBuiltin => {
            observed.contains(&CoverageEvent::ResolvedBuiltin(builtin))
        }
        CausalSignal::SpecializedBuiltin => {
            observed.contains(&CoverageEvent::SpecializedBuiltin(builtin))
        }
        CausalSignal::RuntimeAdapter => observed.contains(&CoverageEvent::EnteredAdapter(builtin)),
        CausalSignal::RuntimeAdapterAndForceTrace => {
            if !observed.contains(&CoverageEvent::EnteredAdapter(builtin)) {
                return Err(std::io::Error::other("candidate never entered the adapter"));
            }
            observed.iter().any(
                |event| matches!(event, CoverageEvent::ForcedArgument(id, _) if *id == builtin),
            )
        }
        CausalSignal::ForceTrace => observed
            .iter()
            .any(|event| matches!(event, CoverageEvent::ForcedArgument(id, _) if *id == builtin)),
        CausalSignal::EffectEvent => observed
            .iter()
            .any(|event| matches!(event, CoverageEvent::ExecutedEffect(id, _) if *id == builtin)),
        CausalSignal::TaskAndCancellation => observed
            .iter()
            .any(|event| matches!(event, CoverageEvent::TaskEvent(id, _) if *id == builtin)),
        CausalSignal::PresentationField => observed
            .iter()
            .any(|event| matches!(event, CoverageEvent::PresentedField(id, _) if *id == builtin)),
        CausalSignal::ResourceLifecycle => observed
            .iter()
            .any(|event| matches!(event, CoverageEvent::AcquiredResource(id, _) if *id == builtin)),
    })
}

fn parse_semantic_task_trace(
    document: &str,
) -> std::io::Result<Vec<(u64, hell_builtins::BuiltinId, String)>> {
    semantic_trace_array(document, "semanticTaskTrace")?
        .map(|encoded| {
            let encoded = encoded
                .strip_prefix("\"taskId\": ")
                .and_then(|value| value.split_once(", \"builtinId\": "))
                .and_then(|(task, value)| {
                    value
                        .split_once(", \"event\": \"")
                        .map(|(builtin, event)| (task, builtin, event))
                })
                .and_then(|(task, builtin, event)| {
                    event.strip_suffix('"').map(|event| (task, builtin, event))
                })
                .ok_or_else(|| std::io::Error::other("semantic task trace item is malformed"))?;
            let task = nonzero_trace_id(encoded.0, "task")?;
            let builtin = trace_builtin_id(encoded.1, "task")?;
            if !matches!(encoded.2, "started" | "completed" | "failed" | "cancelled") {
                return Err(std::io::Error::other("semantic task lifecycle is unknown"));
            }
            Ok((task, builtin, encoded.2.to_owned()))
        })
        .collect()
}

fn parse_semantic_effect_trace(document: &str) -> std::io::Result<Vec<RetainedEffectEvent>> {
    semantic_trace_array(document, "semanticEffectTrace")?
        .map(|encoded| {
            let (builtin, encoded) = encoded
                .strip_prefix("\"builtinId\": ")
                .and_then(|value| value.split_once(", \"ownerTaskId\": "))
                .ok_or_else(|| std::io::Error::other("semantic effect is malformed"))?;
            let (owner, encoded) = encoded
                .split_once(", \"sequence\": ")
                .ok_or_else(|| std::io::Error::other("semantic effect is malformed"))?;
            let (sequence, encoded) = encoded
                .split_once(", \"parentSequence\": ")
                .ok_or_else(|| std::io::Error::other("semantic effect is malformed"))?;
            let (parent, lifecycle) = encoded
                .split_once(", \"effect\": \"")
                .and_then(|(parent, lifecycle)| {
                    lifecycle
                        .strip_suffix('"')
                        .map(|lifecycle| (parent, lifecycle))
                })
                .ok_or_else(|| std::io::Error::other("semantic effect is malformed"))?;
            if !matches!(lifecycle, "started" | "completed" | "failed" | "cancelled") {
                return Err(std::io::Error::other(
                    "semantic effect lifecycle is unknown",
                ));
            }
            let builtin = trace_builtin_id(builtin, "effect")?;
            let owner_task = parse_optional_positive_u64(owner, "semantic effect owner")?;
            let sequence = parse_positive_u64(sequence, "semantic effect sequence")?;
            let parent_sequence = parse_optional_positive_u64(parent, "semantic effect parent")?;
            if parent_sequence.is_some_and(|parent| parent >= sequence) {
                return Err(std::io::Error::other(
                    "semantic effect parent does not precede its child",
                ));
            }
            Ok(RetainedEffectEvent {
                builtin,
                owner_task,
                sequence,
                parent_sequence,
                lifecycle: lifecycle.to_owned(),
            })
        })
        .collect()
}

fn parse_semantic_resource_trace(document: &str) -> std::io::Result<Vec<RetainedResourceEvent>> {
    semantic_trace_array(document, "semanticResourceTrace")?
        .map(|encoded| {
            let (resource, encoded) = encoded
                .strip_prefix("\"resourceId\": ")
                .and_then(|value| value.split_once(", \"builtinId\": "))
                .ok_or_else(|| {
                    std::io::Error::other("semantic resource trace item is malformed")
                })?;
            let (builtin, encoded) =
                encoded.split_once(", \"ownerTaskId\": ").ok_or_else(|| {
                    std::io::Error::other("semantic resource trace item is malformed")
                })?;
            let (owner, event) = encoded
                .split_once(", \"event\": \"")
                .and_then(|(owner, event)| event.strip_suffix('"').map(|event| (owner, event)))
                .ok_or_else(|| {
                    std::io::Error::other("semantic resource trace item is malformed")
                })?;
            let resource = nonzero_trace_id(resource, "resource")?;
            let builtin = trace_builtin_id(builtin, "resource")?;
            let owner = if owner == "null" {
                None
            } else {
                Some(nonzero_trace_id(owner, "resource owner")?)
            };
            if !matches!(
                event,
                "acquire" | "transfer" | "cancel" | "close" | "cleanup-failure"
            ) {
                return Err(std::io::Error::other(
                    "semantic resource lifecycle is unknown",
                ));
            }
            Ok((resource, builtin, owner, event.to_owned()))
        })
        .collect()
}

fn parse_semantic_obligation_trace(
    document: &str,
) -> std::io::Result<Vec<crate::ObligationTraceEvent>> {
    semantic_trace_array(document, "semanticObligationTrace")?
        .map(|encoded| {
            let (builtin, encoded) = encoded
                .strip_prefix("\"builtinId\": ")
                .and_then(|value| value.split_once(", \"ownerTaskId\": "))
                .ok_or_else(|| std::io::Error::other("semantic obligation is malformed"))?;
            let (owner, encoded) = encoded
                .split_once(", \"sequence\": ")
                .ok_or_else(|| std::io::Error::other("semantic obligation is malformed"))?;
            let (sequence, encoded) = encoded
                .split_once(", \"parentSequence\": ")
                .ok_or_else(|| std::io::Error::other("semantic obligation is malformed"))?;
            let (parent, encoded) = encoded
                .split_once(", \"instanceTarget\": ")
                .ok_or_else(|| std::io::Error::other("semantic obligation is malformed"))?;
            let (instance_target, encoded) = encoded
                .split_once(", \"instancePremises\": [")
                .ok_or_else(|| std::io::Error::other("semantic obligation is malformed"))?;
            let (instance_premises, encoded) = encoded
                .split_once("], \"outcome\": \"")
                .ok_or_else(|| std::io::Error::other("semantic premises are malformed"))?;
            let (outcome, encoded) = encoded
                .split_once("\", \"nestedAdapters\": ")
                .ok_or_else(|| std::io::Error::other("semantic obligation is malformed"))?;
            let (nested, encoded) = encoded
                .split_once(", \"materializedBefore\": ")
                .ok_or_else(|| std::io::Error::other("semantic obligation is malformed"))?;
            let (before, encoded) = encoded
                .split_once(", \"materializedAfter\": ")
                .ok_or_else(|| std::io::Error::other("semantic obligation is malformed"))?;
            let (after, invocations) = encoded
                .split_once(", \"callbackInvocations\": [")
                .ok_or_else(|| std::io::Error::other("semantic callbacks are malformed"))?;
            let (callbacks, comparators) = invocations
                .split_once("], \"comparatorInvocations\": [")
                .and_then(|(callbacks, comparators)| {
                    comparators
                        .strip_suffix(']')
                        .map(|comparators| (callbacks, comparators))
                })
                .ok_or_else(|| std::io::Error::other("semantic comparators are malformed"))?;
            if !matches!(outcome, "alias" | "error" | "io-action" | "value") {
                return Err(std::io::Error::other(
                    "semantic obligation outcome is unknown",
                ));
            }
            let builtin = trace_builtin_id(builtin, "obligation")?;
            let instance_target = crate::parse_instance_target(instance_target, builtin)?;
            let instance_premises = crate::parse_instance_premises(
                instance_premises,
                builtin,
                instance_target.as_deref(),
            )?;
            let nested = nested
                .parse::<u64>()
                .map_err(|_| std::io::Error::other("nested adapter count is malformed"))?;
            let before = before
                .parse::<u64>()
                .map_err(|_| std::io::Error::other("materialization start is malformed"))?;
            let after = after
                .parse::<u64>()
                .map_err(|_| std::io::Error::other("materialization end is malformed"))?;
            if after < before {
                return Err(std::io::Error::other(
                    "semantic materialization counter moved backwards",
                ));
            }
            let owner_task = parse_optional_positive_u64(owner, "semantic obligation owner")?;
            let sequence = parse_positive_u64(sequence, "semantic obligation sequence")?;
            let parent_sequence =
                parse_optional_positive_u64(parent, "semantic obligation parent")?;
            if parent_sequence.is_some_and(|parent| parent >= sequence) {
                return Err(std::io::Error::other(
                    "semantic obligation parent does not precede its child",
                ));
            }
            Ok(crate::ObligationTraceEvent {
                builtin,
                instance_target,
                instance_premises,
                owner_task,
                sequence,
                parent_sequence,
                outcome: outcome.into(),
                nested_adapters: nested,
                materialized_before: before,
                materialized_after: after,
                callbacks: crate::parse_retained_callback_invocations(callbacks)?,
                comparators: crate::parse_retained_comparator_invocations(comparators)?,
            })
        })
        .collect()
}

fn parse_positive_u64(value: &str, label: &str) -> std::io::Result<u64> {
    value
        .parse::<u64>()
        .ok()
        .filter(|value| *value != 0)
        .ok_or_else(|| std::io::Error::other(format!("{label} is malformed")))
}

fn parse_optional_positive_u64(value: &str, label: &str) -> std::io::Result<Option<u64>> {
    if value == "null" {
        Ok(None)
    } else {
        parse_positive_u64(value, label).map(Some)
    }
}

fn semantic_trace_array<'a>(
    document: &'a str,
    field: &str,
) -> std::io::Result<impl Iterator<Item = &'a str>> {
    let prefix = format!("  \"{field}\": [");
    let mut lines = document
        .lines()
        .filter_map(|line| line.strip_prefix(&prefix));
    let line = lines
        .next()
        .and_then(|line| line.strip_suffix("],"))
        .ok_or_else(|| std::io::Error::other(format!("{field} is missing or malformed")))?;
    if lines.next().is_some() {
        return Err(std::io::Error::other(format!("{field} is repeated")));
    }
    Ok(line
        .split("}, {")
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            let entry = entry.strip_prefix('{').unwrap_or(entry);
            entry.strip_suffix('}').unwrap_or(entry)
        }))
}

fn nonzero_trace_id(encoded: &str, label: &str) -> std::io::Result<u64> {
    encoded
        .parse::<u64>()
        .ok()
        .filter(|id| *id != 0)
        .ok_or_else(|| std::io::Error::other(format!("semantic {label} ID is malformed")))
}

fn trace_builtin_id(encoded: &str, label: &str) -> std::io::Result<hell_builtins::BuiltinId> {
    let id = encoded
        .parse::<u16>()
        .ok()
        .filter(|id| usize::from(*id) < hell_builtins::registry().len())
        .ok_or_else(|| std::io::Error::other(format!("semantic {label} builtin is malformed")))?;
    Ok(hell_builtins::BuiltinId(id))
}

fn parse_semantic_event_order(document: &str) -> std::io::Result<Vec<(u64, String)>> {
    let prefix = "  \"semanticEventOrder\": [";
    let mut lines = document
        .lines()
        .filter_map(|line| line.strip_prefix(prefix));
    let line = lines
        .next()
        .and_then(|line| line.strip_suffix("],"))
        .ok_or_else(|| std::io::Error::other("semantic event order is missing or malformed"))?;
    if lines.next().is_some() {
        return Err(std::io::Error::other("semantic event order is repeated"));
    }
    if line.is_empty() {
        return Ok(Vec::new());
    }
    line.split("}, {")
        .enumerate()
        .map(|(index, entry)| {
            let entry = entry.strip_prefix('{').unwrap_or(entry);
            let entry = entry.strip_suffix('}').unwrap_or(entry);
            let (event, kind) = entry
                .strip_prefix("\"eventId\": ")
                .and_then(|entry| entry.split_once(", \"kind\": \""))
                .and_then(|(event, kind)| kind.strip_suffix('"').map(|kind| (event, kind)))
                .ok_or_else(|| std::io::Error::other("semantic event-order item is malformed"))?;
            let event = event
                .parse::<u64>()
                .map_err(|_| std::io::Error::other("semantic event ID is malformed"))?;
            let expected = u64::try_from(index)
                .map_err(|_| std::io::Error::other("semantic event count exceeds u64"))?
                .saturating_add(1);
            if event != expected || semantic_event_kind_index(kind).is_none() {
                return Err(std::io::Error::other(
                    "semantic event order is missing, duplicate, or unknown",
                ));
            }
            Ok((event, kind.to_owned()))
        })
        .collect()
}

const SEMANTIC_EVENT_KINDS: [&str; 11] = [
    "parsed-builtin",
    "resolved-builtin",
    "specialized-builtin",
    "entered-adapter",
    "forced-argument",
    "typed-result",
    "effect-event",
    "task-event",
    "presentation-field",
    "resource-event",
    "obligation-event",
];

fn semantic_event_kind_index(kind: &str) -> Option<usize> {
    SEMANTIC_EVENT_KINDS
        .iter()
        .position(|candidate| *candidate == kind)
}

fn validate_semantic_event_classes(
    order: &[(u64, String)],
    coverage: &[CoverageEvent],
    has_typed_result: bool,
    forced_boundaries: usize,
    obligation_events: usize,
) -> std::io::Result<()> {
    let mut expected = [0_usize; SEMANTIC_EVENT_KINDS.len()];
    for event in coverage {
        expected[match event {
            CoverageEvent::ParsedBuiltin(_) => 0,
            CoverageEvent::ResolvedBuiltin(_) => 1,
            CoverageEvent::SpecializedBuiltin(_) => 2,
            CoverageEvent::EnteredAdapter(_) => 3,
            CoverageEvent::ForcedArgument(_, _) => 4,
            CoverageEvent::ExecutedEffect(_, _) => 6,
            CoverageEvent::TaskEvent(_, _) => 7,
            CoverageEvent::PresentedField(_, _) => 8,
            CoverageEvent::AcquiredResource(_, _) => 9,
        }] += 1;
    }
    expected[4] = forced_boundaries;
    expected[5] = usize::from(has_typed_result);
    expected[10] = obligation_events;
    let mut observed = [0_usize; SEMANTIC_EVENT_KINDS.len()];
    let mut reached = [false; 4];
    for (_, kind) in order {
        let index = semantic_event_kind_index(kind)
            .ok_or_else(|| std::io::Error::other("semantic event class is unknown"))?;
        match index {
            0 => reached[0] = true,
            1 if reached[0] => reached[1] = true,
            2 if reached[1] => reached[2] = true,
            3 if reached[2] => reached[3] = true,
            4..=10 if reached[3] => {}
            _ => {
                return Err(std::io::Error::other(
                    "semantic causal phases are out of order",
                ));
            }
        }
        observed[index] += 1;
    }
    if observed != expected {
        return Err(std::io::Error::other(
            "semantic event order does not exactly cover the retained causal evidence",
        ));
    }
    Ok(())
}

fn parse_optional_u16_field(document: &str, field: &str) -> std::io::Result<Option<u16>> {
    let prefix = format!("  \"{field}\": ");
    let mut values = document
        .lines()
        .filter_map(|line| line.strip_prefix(&prefix));
    let value = values
        .next()
        .and_then(|line| line.strip_suffix(','))
        .ok_or_else(|| std::io::Error::other(format!("{field} is missing or malformed")))?;
    if values.next().is_some() {
        return Err(std::io::Error::other(format!("{field} is repeated")));
    }
    if value == "null" {
        return Ok(None);
    }
    value
        .parse::<u16>()
        .map(Some)
        .map_err(|_| std::io::Error::other(format!("{field} is not a builtin ID")))
}

fn parse_semantic_boundaries(document: &str) -> std::io::Result<Vec<RetainedSemanticBoundary>> {
    let prefix = "  \"semanticBoundaries\": [";
    let mut lines = document
        .lines()
        .filter_map(|line| line.strip_prefix(prefix));
    let line = lines
        .next()
        .and_then(|line| line.strip_suffix("],"))
        .ok_or_else(|| std::io::Error::other("semantic boundaries are missing or malformed"))?;
    if lines.next().is_some() {
        return Err(std::io::Error::other("semantic boundaries are repeated"));
    }
    if line.is_empty() {
        return Ok(Vec::new());
    }
    line.split("}, {")
        .map(|entry| {
            let entry = entry.strip_prefix('{').unwrap_or(entry);
            let entry = entry.strip_suffix('}').unwrap_or(entry);
            let (builtin, entry) = entry
                .strip_prefix("\"builtinId\": ")
                .and_then(|entry| entry.split_once(", \"argument\": "))
                .ok_or_else(|| std::io::Error::other("semantic boundary is malformed"))?;
            let (argument, entry) = entry
                .split_once(", \"class\": \"")
                .ok_or_else(|| std::io::Error::other("semantic boundary is malformed"))?;
            let (class, outcome_fields) = entry
                .split_once("\", \"outcome\": \"")
                .ok_or_else(|| std::io::Error::other("semantic boundary is malformed"))?;
            let (outcome, error_code) = if let Some((outcome, error_code)) =
                outcome_fields.split_once("\", \"errorCode\": \"")
            {
                let error_code = error_code
                    .strip_suffix('"')
                    .ok_or_else(|| std::io::Error::other("semantic boundary is malformed"))?;
                (outcome, Some(error_code))
            } else {
                (
                    outcome_fields
                        .strip_suffix('"')
                        .ok_or_else(|| std::io::Error::other("semantic boundary is malformed"))?,
                    None,
                )
            };
            let builtin = builtin
                .parse::<u16>()
                .map_err(|_| std::io::Error::other("semantic boundary builtin is malformed"))?;
            let argument = argument
                .parse::<u16>()
                .map_err(|_| std::io::Error::other("semantic boundary argument is malformed"))?;
            Ok((
                hell_builtins::BuiltinId(builtin),
                argument,
                class.to_owned(),
                outcome.to_owned(),
                error_code.map(str::to_owned),
            ))
        })
        .collect()
}

fn parse_observation_success(document: &str) -> std::io::Result<bool> {
    let prefix = "  \"status\": {\"success\": ";
    let mut values = document
        .lines()
        .filter_map(|line| line.strip_prefix(prefix));
    let value = values
        .next()
        .ok_or_else(|| std::io::Error::other("observation status is missing"))?;
    if values.next().is_some() {
        return Err(std::io::Error::other("observation status is repeated"));
    }
    match value.split_once(',').map(|pair| pair.0) {
        Some("true") => Ok(true),
        Some("false") => Ok(false),
        _ => Err(std::io::Error::other("observation status is malformed")),
    }
}

fn parse_optional_digest_field(document: &str, field: &str) -> std::io::Result<Option<Digest>> {
    let prefix = format!("  \"{field}\": ");
    let mut values = document
        .lines()
        .filter_map(|line| line.strip_prefix(&prefix));
    let value = values
        .next()
        .and_then(|line| line.strip_suffix(','))
        .ok_or_else(|| std::io::Error::other(format!("{field} is missing or malformed")))?;
    if values.next().is_some() {
        return Err(std::io::Error::other(format!("{field} is repeated")));
    }
    if value == "null" {
        return Ok(None);
    }
    let value = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .ok_or_else(|| std::io::Error::other(format!("{field} is not a digest string")))?;
    Digest::from_hex(value)
        .map(Some)
        .map_err(|error| std::io::Error::other(format!("invalid {field}: {error}")))
}

fn parse_required_digest_field(document: &str, field: &str) -> std::io::Result<Digest> {
    parse_optional_digest_field(document, field)?
        .ok_or_else(|| std::io::Error::other(format!("{field} must not be null")))
}

fn parse_canonical_u64_field(document: &str, field: &str) -> std::io::Result<u64> {
    let value = exact_observation_field(document, field)?;
    value
        .parse::<u64>()
        .ok()
        .filter(|parsed| parsed.to_string() == value)
        .ok_or_else(|| std::io::Error::other(format!("{field} is not a canonical integer")))
}

fn parse_semantic_coverage(document: &str) -> std::io::Result<Vec<CoverageEvent>> {
    let prefix = "  \"semanticCoverage\": [";
    let mut lines = document
        .lines()
        .filter_map(|line| line.strip_prefix(prefix));
    let line = lines
        .next()
        .and_then(|line| line.strip_suffix("],"))
        .ok_or_else(|| std::io::Error::other("semantic coverage field is missing or malformed"))?;
    if lines.next().is_some() {
        return Err(std::io::Error::other(
            "observation repeats the semantic coverage field",
        ));
    }
    if line.is_empty() {
        return Ok(Vec::new());
    }
    let mut events = Vec::new();
    for encoded in line.split("}, {") {
        let event = parse_coverage_event(encoded)?;
        events.push(event);
    }
    Ok(events)
}

fn parse_coverage_event(encoded: &str) -> std::io::Result<CoverageEvent> {
    let encoded = encoded.strip_prefix('{').unwrap_or(encoded);
    let encoded = encoded.strip_suffix('}').unwrap_or(encoded);
    let kinds = [
        "parsed-builtin",
        "resolved-builtin",
        "specialized-builtin",
        "entered-adapter",
        "forced-argument",
        "executed-effect",
        "task-event",
        "acquired-resource",
        "presented-field",
    ];
    let (kind, raw) = kinds
        .into_iter()
        .find_map(|kind| {
            encoded
                .strip_prefix(&format!("\"kind\": \"{kind}\", \"builtinId\": "))
                .map(|raw| (kind, raw))
        })
        .ok_or_else(|| {
            std::io::Error::other(format!(
                "semantic coverage event has unknown fields or kind: {encoded}"
            ))
        })?;
    let detailed = matches!(
        kind,
        "forced-argument"
            | "executed-effect"
            | "task-event"
            | "acquired-resource"
            | "presented-field"
    );
    let (raw_id, detail) = if detailed {
        let (id, detail) = raw
            .split_once(", \"detail\": ")
            .ok_or_else(|| std::io::Error::other("semantic event lacks detail"))?;
        let detail = detail
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .filter(|value| !value.is_empty())
            .ok_or_else(|| std::io::Error::other("semantic event detail is malformed"))?;
        (id, Some(detail))
    } else {
        (raw, None)
    };
    let id = raw_id
        .parse::<u16>()
        .map_err(|_| std::io::Error::other("semantic coverage builtin ID is malformed"))?;
    if usize::from(id) >= hell_builtins::registry().len() {
        return Err(std::io::Error::other(
            "semantic coverage builtin ID is unknown",
        ));
    }
    let builtin = hell_builtins::BuiltinId(id);
    Ok(match kind {
        "parsed-builtin" => CoverageEvent::ParsedBuiltin(builtin),
        "resolved-builtin" => CoverageEvent::ResolvedBuiltin(builtin),
        "specialized-builtin" => CoverageEvent::SpecializedBuiltin(builtin),
        "entered-adapter" => CoverageEvent::EnteredAdapter(builtin),
        "forced-argument" => CoverageEvent::ForcedArgument(
            builtin,
            detail
                .and_then(|value| value.parse::<u16>().ok())
                .ok_or_else(|| std::io::Error::other("forced argument is malformed"))?,
        ),
        "executed-effect" => CoverageEvent::ExecutedEffect(builtin, detail.unwrap().into()),
        "task-event" => CoverageEvent::TaskEvent(builtin, detail.unwrap().into()),
        "acquired-resource" => CoverageEvent::AcquiredResource(builtin, detail.unwrap().into()),
        "presented-field" => CoverageEvent::PresentedField(builtin, detail.unwrap().into()),
        _ => unreachable!("kind came from the exact list"),
    })
}

/// Environment variables whose values may influence a native evidence shard.
///
/// The retained record contains only the names and domain-separated value
/// digests. It never retains the values themselves.
pub const NATIVE_BUILD_ENVIRONMENT_NAMES: [&str; 11] = [
    "CARGO_BUILD_TARGET",
    "CARGO_INCREMENTAL",
    "CARGO_PROFILE",
    "CI",
    "GITHUB_ACTIONS",
    "ImageOS",
    "ImageVersion",
    "RUNNER_ARCH",
    "RUNNER_ENVIRONMENT",
    "RUNNER_OS",
    "RUSTFLAGS",
];

/// Inputs used to build one canonical native execution-environment identity.
pub struct NativeExecutionEnvironmentInputs<'a> {
    pub runner_kind: &'a str,
    pub runner_os: &'a str,
    pub runner_arch: &'a str,
    pub image_os: &'a str,
    pub image_version: &'a str,
    pub collected_at: &'a str,
    pub rust_toolchain_selection_sha256: Digest,
    pub rustc_identity: &'a str,
    pub rustc_executable_sha256: Digest,
    pub rustc_executable_path_sha256: Digest,
    pub cargo_identity: &'a str,
    pub environment_values: &'a [Option<&'a str>; NATIVE_BUILD_ENVIRONMENT_NAMES.len()],
}

/// Canonical execution-environment evidence for one native shard.
pub struct NativeExecutionEnvironment {
    pub runner_kind: Arc<str>,
    pub runner_os: Arc<str>,
    pub runner_arch: Arc<str>,
    pub image_os: Arc<str>,
    pub image_version: Arc<str>,
    pub rustc_identity: Arc<str>,
    pub cargo_identity: Arc<str>,
    pub collected_at: Arc<str>,
    pub runner_image_identity_sha256: Digest,
    pub rust_toolchain_sha256: Digest,
    pub build_environment_sha256: Digest,
    rust_toolchain_selection_sha256: Digest,
    rustc_verbose_sha256: Digest,
    rustc_executable_sha256: Digest,
    rustc_executable_path_sha256: Digest,
    cargo_version_sha256: Digest,
    environment_present: [bool; NATIVE_BUILD_ENVIRONMENT_NAMES.len()],
    environment_value_sha256: [Digest; NATIVE_BUILD_ENVIRONMENT_NAMES.len()],
}

/// Facts independently rederived from a retained native environment record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetainedNativeEnvironmentFacts {
    pub runner_kind: String,
    pub runner_os: String,
    pub runner_arch: String,
    pub image_os: String,
    pub image_version: String,
    pub rustc_identity: String,
    pub cargo_identity: String,
    pub collected_at: String,
    pub runner_image_identity_sha256: Digest,
    pub rust_toolchain_sha256: Digest,
    pub rust_toolchain_selection_sha256: Digest,
    pub rustc_verbose_sha256: Digest,
    pub rustc_executable_sha256: Digest,
    pub rustc_executable_path_sha256: Digest,
    pub cargo_version_sha256: Digest,
    pub build_environment_sha256: Digest,
    pub environment_variables: Vec<RetainedEnvironmentVariableFact>,
}

/// One allowlisted environment variable retained as presence plus value hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetainedEnvironmentVariableFact {
    pub name: &'static str,
    pub present: bool,
    pub value_sha256: Digest,
}

impl NativeExecutionEnvironment {
    /// Builds the canonical environment identity without retaining environment
    /// values.
    #[must_use]
    pub fn new(inputs: &NativeExecutionEnvironmentInputs<'_>) -> Self {
        let runner_kind = Arc::from(inputs.runner_kind);
        let runner_os = Arc::from(inputs.runner_os);
        let runner_arch = Arc::from(inputs.runner_arch);
        let image_os = Arc::from(inputs.image_os);
        let image_version = Arc::from(inputs.image_version);
        let rustc_identity = Arc::from(inputs.rustc_identity);
        let cargo_identity = Arc::from(inputs.cargo_identity);
        let collected_at = Arc::from(inputs.collected_at);
        let environment_value_sha256 = std::array::from_fn(|index| {
            native_environment_value_sha256(
                NATIVE_BUILD_ENVIRONMENT_NAMES[index],
                inputs.environment_values[index],
            )
        });
        let environment_present =
            std::array::from_fn(|index| inputs.environment_values[index].is_some());
        let runner_image_identity_sha256 = native_string_identity_sha256(
            b"hell-native-runner-image-v1\0",
            &[inputs.runner_kind, inputs.image_os, inputs.image_version],
        );
        let build_environment_sha256 = native_environment_aggregate_sha256(
            b"hell-native-build-environment-v1\0",
            &environment_value_sha256,
        );
        let rustc_verbose_sha256 = native_tool_stdout_sha256(inputs.rustc_identity);
        let cargo_version_sha256 = native_tool_stdout_sha256(inputs.cargo_identity);
        let rust_toolchain_sha256 = native_environment_aggregate_sha256(
            b"hell-native-rust-toolchain-v1\0",
            &[
                inputs.rust_toolchain_selection_sha256,
                rustc_verbose_sha256,
                inputs.rustc_executable_sha256,
                inputs.rustc_executable_path_sha256,
                cargo_version_sha256,
            ],
        );
        Self {
            runner_kind,
            runner_os,
            runner_arch,
            image_os,
            image_version,
            rustc_identity,
            cargo_identity,
            collected_at,
            runner_image_identity_sha256,
            rust_toolchain_sha256,
            build_environment_sha256,
            rust_toolchain_selection_sha256: inputs.rust_toolchain_selection_sha256,
            rustc_verbose_sha256,
            rustc_executable_sha256: inputs.rustc_executable_sha256,
            rustc_executable_path_sha256: inputs.rustc_executable_path_sha256,
            cargo_version_sha256,
            environment_present,
            environment_value_sha256,
        }
    }
}

fn native_string_identity_sha256(domain: &[u8], values: &[&str]) -> Digest {
    let mut bytes = domain.to_vec();
    for value in values {
        bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
        bytes.extend_from_slice(value.as_bytes());
    }
    sha256_bytes(&bytes)
}

fn native_tool_stdout_sha256(identity: &str) -> Digest {
    let mut output = identity.replace(" | ", "\n").into_bytes();
    output.push(b'\n');
    sha256_bytes(&output)
}

fn native_environment_value_sha256(name: &str, value: Option<&str>) -> Digest {
    let mut bytes = b"hell-native-environment-value-v1\0".to_vec();
    bytes.extend_from_slice(name.as_bytes());
    bytes.push(0);
    if let Some(value) = value {
        bytes.push(1);
        bytes.extend_from_slice(value.as_bytes());
    } else {
        bytes.push(0);
    }
    sha256_bytes(&bytes)
}

fn native_environment_aggregate_sha256(domain: &[u8], values: &[Digest]) -> Digest {
    let mut bytes = domain.to_vec();
    for value in values {
        bytes.extend_from_slice(&value.0);
    }
    sha256_bytes(&bytes)
}

fn native_environment_json(environment: &NativeExecutionEnvironment) -> String {
    let mut output = String::from("{\n  \"schemaVersion\": 1,\n  \"runnerKind\": ");
    push_json_string(&mut output, &environment.runner_kind);
    output.push_str(",\n  \"runnerOs\": ");
    push_json_string(&mut output, &environment.runner_os);
    output.push_str(",\n  \"runnerArch\": ");
    push_json_string(&mut output, &environment.runner_arch);
    output.push_str(",\n  \"imageOs\": ");
    push_json_string(&mut output, &environment.image_os);
    output.push_str(",\n  \"imageVersion\": ");
    push_json_string(&mut output, &environment.image_version);
    output.push_str(",\n  \"collectedAt\": ");
    push_json_string(&mut output, &environment.collected_at);
    output.push_str(",\n  \"runnerImageIdentitySha256\": ");
    push_json_string(&mut output, &environment.runner_image_identity_sha256.hex());
    output.push_str(",\n  \"rustToolchainSha256\": ");
    push_json_string(&mut output, &environment.rust_toolchain_sha256.hex());
    output.push_str(",\n  \"rustToolchainSelectionSha256\": ");
    push_json_string(
        &mut output,
        &environment.rust_toolchain_selection_sha256.hex(),
    );
    output.push_str(",\n  \"rustcIdentity\": ");
    push_json_string(&mut output, &environment.rustc_identity);
    output.push_str(",\n  \"rustcVerboseSha256\": ");
    push_json_string(&mut output, &environment.rustc_verbose_sha256.hex());
    output.push_str(",\n  \"rustcExecutableSha256\": ");
    push_json_string(&mut output, &environment.rustc_executable_sha256.hex());
    output.push_str(",\n  \"rustcExecutablePathSha256\": ");
    push_json_string(&mut output, &environment.rustc_executable_path_sha256.hex());
    output.push_str(",\n  \"cargoIdentity\": ");
    push_json_string(&mut output, &environment.cargo_identity);
    output.push_str(",\n  \"cargoVersionSha256\": ");
    push_json_string(&mut output, &environment.cargo_version_sha256.hex());
    output.push_str(",\n  \"environmentValueSha256\": [");
    for (index, ((name, present), digest)) in NATIVE_BUILD_ENVIRONMENT_NAMES
        .iter()
        .zip(environment.environment_present)
        .zip(environment.environment_value_sha256)
        .enumerate()
    {
        if index != 0 {
            output.push_str(", ");
        }
        let state = if present { "present" } else { "absent" };
        push_json_string(&mut output, &format!("{name}={state}={}", digest.hex()));
    }
    output.push_str("],\n  \"buildEnvironmentSha256\": ");
    push_json_string(&mut output, &environment.build_environment_sha256.hex());
    output.push_str("\n}\n");
    output
}

/// Writes the canonical hash-only native execution-environment record.
///
/// # Errors
///
/// Returns an I/O error when the record cannot be retained.
pub fn write_native_environment_record(
    root: &Path,
    environment: &NativeExecutionEnvironment,
) -> std::io::Result<()> {
    write_atomic(
        &root.join("native-environment.json"),
        native_environment_json(environment).as_bytes(),
    )
}

/// Strictly parses and rederives one retained native environment record.
///
/// # Errors
///
/// Returns an error for a missing, noncanonical, extra, reordered, malformed,
/// or internally inconsistent record.
pub fn verify_retained_native_environment(
    root: &Path,
) -> std::io::Result<RetainedNativeEnvironmentFacts> {
    let document = fs::read_to_string(root.join("native-environment.json"))?;
    let lines = document.lines().collect::<Vec<_>>();
    if lines.len() != 20
        || lines[0] != "{"
        || lines[1] != "  \"schemaVersion\": 1,"
        || lines[19] != "}"
        || !document.ends_with("}\n")
    {
        return Err(std::io::Error::other(
            "native environment record has a noncanonical outer schema",
        ));
    }
    let runner_kind = native_environment_string(lines[2], "runnerKind", true)?;
    let runner_os = native_environment_string(lines[3], "runnerOs", true)?;
    let runner_arch = native_environment_string(lines[4], "runnerArch", true)?;
    let image_os = native_environment_string(lines[5], "imageOs", true)?;
    let image_version = native_environment_string(lines[6], "imageVersion", true)?;
    let collected_at = native_environment_string(lines[7], "collectedAt", true)?;
    let runner_image = native_environment_digest(lines[8], "runnerImageIdentitySha256", true)?;
    let rust_toolchain = native_environment_digest(lines[9], "rustToolchainSha256", true)?;
    let rust_toolchain_selection =
        native_environment_digest(lines[10], "rustToolchainSelectionSha256", true)?;
    let rustc_identity = native_environment_string(lines[11], "rustcIdentity", true)?;
    let rustc_verbose = native_environment_digest(lines[12], "rustcVerboseSha256", true)?;
    let rustc_executable = native_environment_digest(lines[13], "rustcExecutableSha256", true)?;
    let rustc_executable_path =
        native_environment_digest(lines[14], "rustcExecutablePathSha256", true)?;
    let cargo_identity = native_environment_string(lines[15], "cargoIdentity", true)?;
    let cargo_version = native_environment_digest(lines[16], "cargoVersionSha256", true)?;
    let encoded_values = lines[17]
        .strip_prefix("  \"environmentValueSha256\": [")
        .and_then(|value| value.strip_suffix("],"))
        .ok_or_else(|| {
            std::io::Error::other("native environment value digests are noncanonical")
        })?;
    let (values, environment_variables) = parse_native_environment_values(encoded_values)?;
    let build_environment = native_environment_digest(lines[18], "buildEnvironmentSha256", false)?;
    let expected_image = native_string_identity_sha256(
        b"hell-native-runner-image-v1\0",
        &[&runner_kind, &image_os, &image_version],
    );
    let expected_environment =
        native_environment_aggregate_sha256(b"hell-native-build-environment-v1\0", &values);
    let expected_toolchain = native_environment_aggregate_sha256(
        b"hell-native-rust-toolchain-v1\0",
        &[
            rust_toolchain_selection,
            rustc_verbose,
            rustc_executable,
            rustc_executable_path,
            cargo_version,
        ],
    );
    let expected_rustc = native_tool_stdout_sha256(&rustc_identity);
    let expected_cargo = native_tool_stdout_sha256(&cargo_identity);
    if runner_image != expected_image
        || rust_toolchain != expected_toolchain
        || rustc_verbose != expected_rustc
        || cargo_version != expected_cargo
        || build_environment != expected_environment
    {
        return Err(std::io::Error::other(
            "native environment aggregate digests disagree with retained value digests",
        ));
    }
    validate_native_runner_environment(
        &runner_kind,
        &runner_os,
        &runner_arch,
        &image_os,
        &image_version,
        &environment_variables,
    )?;
    Ok(RetainedNativeEnvironmentFacts {
        runner_kind,
        runner_os,
        runner_arch,
        image_os,
        image_version,
        rustc_identity,
        cargo_identity,
        collected_at,
        runner_image_identity_sha256: runner_image,
        rust_toolchain_sha256: rust_toolchain,
        rust_toolchain_selection_sha256: rust_toolchain_selection,
        rustc_verbose_sha256: rustc_verbose,
        rustc_executable_sha256: rustc_executable,
        rustc_executable_path_sha256: rustc_executable_path,
        cargo_version_sha256: cargo_version,
        build_environment_sha256: build_environment,
        environment_variables,
    })
}

fn parse_native_environment_values(
    encoded_values: &str,
) -> std::io::Result<(Vec<Digest>, Vec<RetainedEnvironmentVariableFact>)> {
    let mut values = Vec::with_capacity(NATIVE_BUILD_ENVIRONMENT_NAMES.len());
    let mut facts = Vec::with_capacity(NATIVE_BUILD_ENVIRONMENT_NAMES.len());
    for (index, encoded) in encoded_values.split(", ").enumerate() {
        let name = NATIVE_BUILD_ENVIRONMENT_NAMES.get(index).ok_or_else(|| {
            std::io::Error::other("native environment record has extra value digests")
        })?;
        let value = encoded
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .and_then(|value| value.strip_prefix(&format!("{name}=")))
            .ok_or_else(|| {
                std::io::Error::other("native environment value digest order is noncanonical")
            })?;
        let (state, encoded_digest) = value
            .split_once('=')
            .ok_or_else(|| std::io::Error::other("native environment value state is malformed"))?;
        let present = match state {
            "present" => true,
            "absent" => false,
            _ => {
                return Err(std::io::Error::other(
                    "native environment value state is unknown",
                ));
            }
        };
        let digest = Digest::from_hex(encoded_digest).map_err(std::io::Error::other)?;
        if digest.hex() != encoded_digest {
            return Err(std::io::Error::other(
                "native environment value digest is not canonical lowercase hexadecimal",
            ));
        }
        if !present && digest != native_environment_value_sha256(name, None) {
            return Err(std::io::Error::other(
                "absent native environment value has a noncanonical digest",
            ));
        }
        values.push(digest);
        facts.push(RetainedEnvironmentVariableFact {
            name,
            present,
            value_sha256: digest,
        });
    }
    if values.len() != NATIVE_BUILD_ENVIRONMENT_NAMES.len() {
        return Err(std::io::Error::other(
            "native environment record is missing value digests",
        ));
    }
    Ok((values, facts))
}

fn validate_native_runner_environment(
    runner_kind: &str,
    runner_os: &str,
    runner_arch: &str,
    image_os: &str,
    image_version: &str,
    variables: &[RetainedEnvironmentVariableFact],
) -> std::io::Result<()> {
    let exact_present = |index: usize, name: &str, value: &str| {
        variables[index].present
            && variables[index].value_sha256 == native_environment_value_sha256(name, Some(value))
    };
    match runner_kind {
        "github-actions" => {
            if !exact_present(4, "GITHUB_ACTIONS", "true")
                || !exact_present(5, "ImageOS", image_os)
                || !exact_present(6, "ImageVersion", image_version)
                || !exact_present(7, "RUNNER_ARCH", runner_arch)
                || !exact_present(9, "RUNNER_OS", runner_os)
            {
                return Err(std::io::Error::other(
                    "GitHub Actions native environment lacks exact runner identity values",
                ));
            }
        }
        "local" => {
            if variables[4].present || image_os != "not-reported" || image_version != "not-reported"
            {
                return Err(std::io::Error::other(
                    "local native environment has contradictory GitHub image identity",
                ));
            }
        }
        _ => return Err(std::io::Error::other("native runner kind is unknown")),
    }
    Ok(())
}

fn native_environment_string(line: &str, name: &str, comma: bool) -> std::io::Result<String> {
    let prefix = format!("  \"{name}\": \"");
    let suffix = if comma { "\"," } else { "\"" };
    let value = line
        .strip_prefix(&prefix)
        .and_then(|value| value.strip_suffix(suffix))
        .ok_or_else(|| {
            std::io::Error::other(format!("native environment field {name} is malformed"))
        })?;
    if value.is_empty() || value.chars().any(char::is_control) || value.contains(['"', '\\']) {
        return Err(std::io::Error::other(format!(
            "native environment field {name} is not a canonical atom"
        )));
    }
    Ok(value.to_owned())
}

fn native_environment_digest(line: &str, name: &str, comma: bool) -> std::io::Result<Digest> {
    let encoded = native_environment_string(line, name, comma)?;
    let digest = Digest::from_hex(&encoded).map_err(std::io::Error::other)?;
    (digest.hex() == encoded)
        .then_some(digest)
        .ok_or_else(|| std::io::Error::other("native environment digest is noncanonical"))
}

/// Inputs recorded in one nightly evidence summary.
pub struct EvidenceSummary<'a> {
    pub native_environment: &'a NativeExecutionEnvironment,
    pub oracle: &'a ExecutableIdentity,
    pub candidate: &'a ExecutableIdentity,
    pub assurance_epoch_sha256: crate::Digest,
    pub corpus_seed: u64,
    pub committed_observations: usize,
    pub generated_observations: usize,
    pub corpus_sha256: crate::Digest,
    pub reviewed_committed_corpus_sha256: crate::Digest,
    pub generated_stress_corpus_sha256: crate::Digest,
    pub promotion_policy_sha256: crate::Digest,
    pub reviewed_corpus_catalog_sha256: crate::Digest,
    pub promotion_review_sha256: crate::Digest,
    pub mismatches: usize,
    pub reviewed_expected_divergences: usize,
    pub unexpected_timeouts: usize,
    pub stale_exact_claims: usize,
    pub irrelevant_claim_references: usize,
    pub profile_evidence_mismatches: usize,
    pub platform_evidence_mismatches: usize,
    pub normalizer_evidence_mismatches: usize,
    pub failed_claim_observations: usize,
    pub missing_evidence_references: usize,
    pub unverified_out_of_scope_claims: usize,
    pub required_profiles: &'a [hell_builtins::ExecutionProfile],
    pub compatibility_snapshot_sha256: crate::Digest,
    pub claim_evidence_index_sha256: crate::Digest,
    pub dependency_lock_sha256: crate::Digest,
    pub dependency_policy_attestation_sha256: crate::Digest,
    pub expected_mismatch_manifest_sha256: crate::Digest,
    pub repository_policy_passed: bool,
    pub required_platform_skips: usize,
    pub leaked_resources: usize,
    pub dependency_failures: usize,
    pub promotion_ready: bool,
}

/// Writes a digested run summary and the two verified executable identities.
///
/// # Errors
///
/// Returns an I/O error if an evidence file cannot be written.
#[allow(clippy::too_many_lines)]
pub fn write_evidence_summary(root: &Path, evidence: &EvidenceSummary<'_>) -> std::io::Result<()> {
    fs::create_dir_all(root)?;
    let shard_root = root.join("evidence").join("shards");
    fs::create_dir_all(&shard_root)?;
    write_atomic(
        &root.join("oracle-identity.json"),
        identity_json(evidence.oracle).as_bytes(),
    )?;
    write_atomic(
        &root.join("candidate-identity.json"),
        identity_json(evidence.candidate).as_bytes(),
    )?;
    write_native_environment_record(root, evidence.native_environment)?;
    let mut summary = String::from(
        "{\n  \"schemaVersion\": 3,\n  \"shardIndex\": 0,\n  \"shardCount\": 1,\n  \"observationBundleSchemaVersion\": 5,\n  \"claimIndexSchemaVersion\": 3,\n  \"oracleRecordSchemaVersion\": 2,\n  \"platform\": ",
    );
    push_json_string(
        &mut summary,
        &format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
    );
    summary.push_str(",\n  \"runnerOs\": ");
    push_json_string(&mut summary, &evidence.native_environment.runner_os);
    summary.push_str(",\n  \"runnerArch\": ");
    push_json_string(&mut summary, &evidence.native_environment.runner_arch);
    summary.push_str(",\n  \"collectedAt\": ");
    push_json_string(&mut summary, &evidence.native_environment.collected_at);
    summary.push_str(",\n  \"runnerImageIdentitySha256\": ");
    push_json_string(
        &mut summary,
        &evidence
            .native_environment
            .runner_image_identity_sha256
            .hex(),
    );
    summary.push_str(",\n  \"rustToolchainSha256\": ");
    push_json_string(
        &mut summary,
        &evidence.native_environment.rust_toolchain_sha256.hex(),
    );
    summary.push_str(",\n  \"buildEnvironmentSha256\": ");
    push_json_string(
        &mut summary,
        &evidence.native_environment.build_environment_sha256.hex(),
    );
    summary.push_str(",\n  \"oracleSha256\": ");
    push_json_string(&mut summary, &evidence.oracle.sha256.hex());
    summary.push_str(",\n  \"oracleAcquisitionReceiptId\": ");
    if let Some(receipt) = &evidence.oracle.acquisition_receipt_id {
        push_json_string(&mut summary, receipt);
    } else {
        summary.push_str("null");
    }
    summary.push_str(",\n  \"oracleAcquisitionReceiptSha256\": ");
    if let Some(receipt) = evidence.oracle.acquisition_receipt_sha256 {
        push_json_string(&mut summary, &receipt.hex());
    } else {
        summary.push_str("null");
    }
    summary.push_str(",\n  \"oracleAcquisitionAttestationSha256\": ");
    if let Some(attestation) = evidence.oracle.acquisition_attestation_sha256 {
        push_json_string(&mut summary, &attestation.hex());
    } else {
        summary.push_str("null");
    }
    summary.push_str(",\n  \"candidateSha256\": ");
    push_json_string(&mut summary, &evidence.candidate.sha256.hex());
    summary.push_str(",\n  \"assuranceEpochSha256\": ");
    push_json_string(&mut summary, &evidence.assurance_epoch_sha256.hex());
    summary.push_str(",\n  \"corpusSeed\": ");
    write!(summary, "{}", evidence.corpus_seed).expect("writing to String cannot fail");
    summary.push_str(",\n  \"committedDifferentialObservations\": ");
    write!(summary, "{}", evidence.committed_observations).expect("writing to String cannot fail");
    summary.push_str(",\n  \"generatedDifferentialObservations\": ");
    write!(summary, "{}", evidence.generated_observations).expect("writing to String cannot fail");
    summary.push_str(",\n  \"corpusSha256\": ");
    push_json_string(&mut summary, &evidence.corpus_sha256.hex());
    summary.push_str(",\n  \"reviewedCommittedCorpusSha256\": ");
    push_json_string(
        &mut summary,
        &evidence.reviewed_committed_corpus_sha256.hex(),
    );
    summary.push_str(",\n  \"generatedStressCorpusSha256\": ");
    push_json_string(&mut summary, &evidence.generated_stress_corpus_sha256.hex());
    summary.push_str(",\n  \"promotionPolicySha256\": ");
    push_json_string(&mut summary, &evidence.promotion_policy_sha256.hex());
    summary.push_str(",\n  \"reviewedCorpusCatalogSha256\": ");
    push_json_string(&mut summary, &evidence.reviewed_corpus_catalog_sha256.hex());
    summary.push_str(",\n  \"promotionReviewSha256\": ");
    push_json_string(&mut summary, &evidence.promotion_review_sha256.hex());
    summary.push_str(",\n  \"mismatches\": ");
    write!(summary, "{}", evidence.mismatches).expect("writing to String cannot fail");
    summary.push_str(",\n  \"reviewedExpectedDivergences\": ");
    write!(summary, "{}", evidence.reviewed_expected_divergences)
        .expect("writing to String cannot fail");
    summary.push_str(",\n  \"unexpectedTimeouts\": ");
    write!(summary, "{}", evidence.unexpected_timeouts).expect("writing to String cannot fail");
    summary.push_str(",\n  \"staleExactClaims\": ");
    write!(summary, "{}", evidence.stale_exact_claims).expect("writing to String cannot fail");
    summary.push_str(",\n  \"irrelevantClaimReferences\": ");
    write!(summary, "{}", evidence.irrelevant_claim_references)
        .expect("writing to String cannot fail");
    summary.push_str(",\n  \"profileEvidenceMismatches\": ");
    write!(summary, "{}", evidence.profile_evidence_mismatches)
        .expect("writing to String cannot fail");
    summary.push_str(",\n  \"platformEvidenceMismatches\": ");
    write!(summary, "{}", evidence.platform_evidence_mismatches)
        .expect("writing to String cannot fail");
    summary.push_str(",\n  \"normalizerEvidenceMismatches\": ");
    write!(summary, "{}", evidence.normalizer_evidence_mismatches)
        .expect("writing to String cannot fail");
    summary.push_str(",\n  \"failedClaimObservations\": ");
    write!(summary, "{}", evidence.failed_claim_observations)
        .expect("writing to String cannot fail");
    summary.push_str(",\n  \"missingEvidenceReferences\": ");
    write!(summary, "{}", evidence.missing_evidence_references)
        .expect("writing to String cannot fail");
    summary.push_str(",\n  \"unverifiedOutOfScopeClaims\": ");
    write!(summary, "{}", evidence.unverified_out_of_scope_claims)
        .expect("writing to String cannot fail");
    summary.push_str(",\n  \"requiredProfiles\": [");
    for (index, profile) in evidence.required_profiles.iter().enumerate() {
        if index != 0 {
            summary.push_str(", ");
        }
        push_json_string(&mut summary, profile.as_str());
    }
    summary.push(']');
    summary.push_str(",\n  \"compatibilitySnapshotSha256\": ");
    push_json_string(&mut summary, &evidence.compatibility_snapshot_sha256.hex());
    summary.push_str(",\n  \"claimEvidenceIndexSha256\": ");
    push_json_string(&mut summary, &evidence.claim_evidence_index_sha256.hex());
    summary.push_str(",\n  \"dependencyLockSha256\": ");
    push_json_string(&mut summary, &evidence.dependency_lock_sha256.hex());
    summary.push_str(",\n  \"dependencyPolicyAttestationSha256\": ");
    push_json_string(
        &mut summary,
        &evidence.dependency_policy_attestation_sha256.hex(),
    );
    summary.push_str(",\n  \"expectedMismatchManifestSha256\": ");
    push_json_string(
        &mut summary,
        &evidence.expected_mismatch_manifest_sha256.hex(),
    );
    summary.push_str(",\n  \"repositoryPolicyPassed\": ");
    summary.push_str(if evidence.repository_policy_passed {
        "true"
    } else {
        "false"
    });
    summary.push_str(",\n  \"requiredPlatformSkips\": ");
    write!(summary, "{}", evidence.required_platform_skips).expect("writing to String cannot fail");
    summary.push_str(",\n  \"leakedResources\": ");
    write!(summary, "{}", evidence.leaked_resources).expect("writing to String cannot fail");
    summary.push_str(",\n  \"dependencyFailures\": ");
    write!(summary, "{}", evidence.dependency_failures).expect("writing to String cannot fail");
    summary.push_str(",\n  \"promotionReady\": ");
    summary.push_str(if evidence.promotion_ready {
        "true"
    } else {
        "false"
    });
    summary.push_str("\n}\n");
    let digest = sha256_bytes(summary.as_bytes()).hex();
    write_atomic(&root.join("summary.json"), summary.as_bytes())?;
    write_atomic(
        &shard_root.join("shard-0000-of-0001.json"),
        summary.as_bytes(),
    )?;
    write_atomic(
        &shard_root.join("shard-0000-of-0001.sha256"),
        format!("{digest}  shard-0000-of-0001.json\n").as_bytes(),
    )?;
    write_atomic(
        &root.join("summary.sha256"),
        format!("{digest}  summary.json\n").as_bytes(),
    )
}

fn validate_case_id(id: &str) -> std::io::Result<()> {
    hell_builtins::validate_case_id(id)
        .then_some(())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("unsafe differential case identifier {id:?}"),
            )
        })
}

pub(crate) fn case_descriptor(case: &DifferentialCase) -> String {
    let runtime_failure_authority = crate::reviewed_runtime_failure_presentation_authority(case);
    let mut output = if runtime_failure_authority.is_some() {
        String::from("schema_version = 9\nid = ")
    } else {
        String::from("schema_version = 8\nid = ")
    };
    push_toml_string(&mut output, &case.id);
    output.push_str("\nmode = ");
    push_toml_string(&mut output, &format!("{:?}", case.mode));
    output.push_str("\nenvironment_profile = ");
    push_toml_string(&mut output, &format!("{:?}", case.environment_profile));
    if case.environment_profile == crate::EnvironmentProfile::ProcessCapable {
        output.push_str("\nprocess_helper = ");
        push_toml_string(&mut output, "hell-test-helper-v1");
    }
    output.push_str("\ntimeout_millis = ");
    writeln!(output, "{}", case.timeout.as_millis()).expect("writing to String cannot fail");
    output.push_str("expected_runtime_completion = ");
    output.push_str(if case.expected_runtime_completion {
        "true\n"
    } else {
        "false\n"
    });
    if let Some(authority) = runtime_failure_authority {
        output.push_str("runtime_failure_exception_family = ");
        push_toml_string(&mut output, authority.family.descriptor_name());
        output.push_str("\nruntime_failure_builtin = ");
        push_toml_string(&mut output, authority.builtin_name);
        output.push_str("\nruntime_failure_dimension = ");
        push_toml_string(&mut output, authority.dimension.as_str());
        output.push_str("\nruntime_failure_obligation = ");
        push_toml_string(&mut output, authority.obligation);
        output.push_str("\nruntime_failure_while_handling = ");
        output.push_str(
            if authority.while_handling == crate::RuntimeFailureHandlingProjection::None {
                "false\n"
            } else {
                "true\n"
            },
        );
    }
    output.push_str("stdin_sha256 = ");
    push_toml_string(&mut output, &sha256_bytes(&case.stdin).hex());
    output.push_str("\nexecution_input_sha256 = ");
    push_toml_string(
        &mut output,
        &sha256_bytes(
            execution_input_json(case)
                .expect("committed execution inputs are canonical UTF-8")
                .as_bytes(),
        )
        .hex(),
    );
    output.push('\n');
    output.push_str("claim_evidence_eligible = ");
    output.push_str(if case.claim_evidence.is_some() {
        "true\n"
    } else {
        "false\n"
    });
    output.push_str("execution_profile = ");
    match &case.claim_evidence {
        Some(descriptor) => push_toml_string(
            &mut output,
            match descriptor.profile {
                hell_builtins::ExecutionProfile::Upstream => "upstream",
                hell_builtins::ExecutionProfile::Sandboxed => "sandboxed",
            },
        ),
        None => push_toml_string(&mut output, "ineligible"),
    }
    output.push_str("\nharness_normalizers = ");
    push_normalizer_array(&mut output, &applied_harness_normalizers());
    output.push_str("\nclaim_normalizers = ");
    push_normalizer_array(&mut output, &applied_claim_normalizers(case));
    output.push('\n');
    if let Some(descriptor) = &case.claim_evidence {
        push_claim_evidence_descriptor(&mut output, descriptor);
    }
    output
}

fn push_claim_evidence_descriptor(output: &mut String, descriptor: &ClaimEvidenceDescriptor) {
    output.push_str("review_state = \"reviewed\"\nreview_statement = ");
    push_toml_string(output, &descriptor.review_statement);
    output.push_str("\nsource_sha256 = ");
    push_toml_string(output, &descriptor.source_sha256.hex());
    output.push('\n');
    for target in &descriptor.targets {
        output.push_str("\n[[targets]]\nbuiltin = ");
        push_toml_string(output, &target.builtin);
        output.push_str("\ndimension = ");
        push_toml_string(output, target.dimension.as_str());
        output.push('\n');
    }
    for target in &descriptor.semantic_targets {
        push_semantic_target_descriptor(output, target);
    }
    for contract in &descriptor.callback_contracts {
        push_callback_contract_descriptor(output, contract);
    }
}

fn push_semantic_target_descriptor(output: &mut String, target: &crate::EvidenceTargetV2) {
    output.push_str("\n[[semantic_targets]]\nbuiltin = ");
    push_toml_string(output, &target.builtin);
    output.push_str("\nexpected_instance_target = ");
    push_toml_string(
        output,
        target
            .expected_instance_target
            .as_deref()
            .unwrap_or_default(),
    );
    output.push_str("\nexpected_instance_premises = [");
    for (index, premise) in target.expected_instance_premises.iter().enumerate() {
        if index != 0 {
            output.push_str(", ");
        }
        push_toml_string(
            output,
            &format!("{}/{}", premise.target, premise.premise_count),
        );
    }
    output.push(']');
    output.push_str("\ndimension = ");
    push_toml_string(output, target.dimension.as_str());
    output.push_str("\ncausal_signal = ");
    push_toml_string(output, causal_signal_name(target.causal_signal));
    output.push_str("\nobligations = [");
    push_toml_values(
        output,
        target.obligations.iter().map(|value| value.0.as_ref()),
    );
    output.push_str("]\nplatforms = [");
    push_toml_values(
        output,
        target.platforms.iter().map(|value| match value {
            hell_builtins::ClaimPlatform::All => "All",
            hell_builtins::ClaimPlatform::Linux => "Linux",
            hell_builtins::ClaimPlatform::MacOs => "MacOs",
            hell_builtins::ClaimPlatform::Windows => "Windows",
        }),
    );
    output.push_str("]\nboundary_classes = [");
    push_toml_values(output, target.boundary_classes.iter().map(AsRef::as_ref));
    output.push_str("]\ninteraction_obligations = [");
    push_toml_values(
        output,
        target.interaction_obligations.iter().map(AsRef::as_ref),
    );
    output.push_str("]\nexpected_typed_result_sha256 = ");
    if let Some(digest) = target.expected_typed_result_sha256 {
        push_toml_string(output, &digest.hex());
    } else {
        push_toml_string(output, "");
    }
    push_presentation_target_descriptor(output, target);
    push_runtime_target_digests(output, target);
    output.push('\n');
}

fn push_runtime_target_digests(output: &mut String, target: &crate::EvidenceTargetV2) {
    output.push_str("\nexpected_lazy_argument_exit_sha256 = ");
    if let Some(digest) = target.expected_lazy_argument_exit_sha256 {
        push_toml_string(output, &digest.hex());
    } else {
        push_toml_string(output, "");
    }
    output.push_str("\nexpected_whnf_argument_failure_sha256 = ");
    if let Some(digest) = target.expected_whnf_argument_failure_sha256 {
        push_toml_string(output, &digest.hex());
    } else {
        push_toml_string(output, "");
    }
    output.push_str("\nexpected_nonproductive_trace_sha256 = ");
    if let Some(digest) = target.expected_nonproductive_trace_sha256 {
        push_toml_string(output, &digest.hex());
    } else {
        push_toml_string(output, "");
    }
    output.push_str("\nexpected_single_task_lifecycle_sha256 = ");
    if let Some(digest) = target.expected_single_task_lifecycle_sha256 {
        push_toml_string(output, &digest.hex());
    } else {
        push_toml_string(output, "");
    }
    output.push_str("\nexpected_task_trace_sha256 = ");
    if let Some(digest) = target.expected_task_trace_sha256 {
        push_toml_string(output, &digest.hex());
    } else {
        push_toml_string(output, "");
    }
    output.push_str("\nexpected_process_status_sha256 = ");
    if let Some(digest) = target.expected_process_status_sha256 {
        push_toml_string(output, &digest.hex());
    } else {
        push_toml_string(output, "");
    }
    output.push_str("\nexpected_single_effect_lifecycle_sha256 = ");
    if let Some(digest) = target.expected_single_effect_lifecycle_sha256 {
        push_toml_string(output, &digest.hex());
    } else {
        push_toml_string(output, "");
    }
    output.push_str("\nexpected_comparator_trace_sha256 = ");
    if let Some(digest) = target.expected_comparator_trace_sha256 {
        push_toml_string(output, &digest.hex());
    } else {
        push_toml_string(output, "");
    }
}

fn push_presentation_target_descriptor(output: &mut String, target: &crate::EvidenceTargetV2) {
    output.push_str("\nexpected_raw_presentation_sha256 = ");
    if let Some(digest) = target.expected_raw_presentation_sha256 {
        push_toml_string(output, &digest.hex());
    } else {
        push_toml_string(output, "");
    }
    output.push_str("\nexpected_presentation_shadow_normalizer = ");
    push_toml_string(
        output,
        target
            .expected_presentation_shadow_normalizer
            .map(PresentationShadowNormalizerId::as_str)
            .unwrap_or_default(),
    );
    output.push_str("\nexpected_normalized_presentation_sha256 = ");
    if let Some(digest) = target.expected_normalized_presentation_sha256 {
        push_toml_string(output, &digest.hex());
    } else {
        push_toml_string(output, "");
    }
}

fn push_toml_values<T: AsRef<str>>(output: &mut String, values: impl Iterator<Item = T>) {
    for (index, value) in values.enumerate() {
        if index != 0 {
            output.push_str(", ");
        }
        push_toml_string(output, value.as_ref());
    }
}

fn push_callback_contract_descriptor(output: &mut String, contract: &crate::CallbackContract) {
    output.push_str("\n[[callback_contracts]]\nbuiltin = ");
    push_toml_string(output, &contract.builtin);
    output.push('\n');
    for invocation in &contract.invocations {
        output.push_str("[[callback_contracts.invocations]]\ncallback_argument = ");
        write!(output, "{}", invocation.callback_argument).expect("writing to String cannot fail");
        output.push_str("\nbranch = ");
        push_toml_string(output, &invocation.branch);
        output.push_str("\ncanonical_argument_sha256 = [");
        push_toml_values(
            output,
            invocation
                .canonical_argument_sha256
                .iter()
                .copied()
                .map(Digest::hex),
        );
        output.push_str("]\noutcome = ");
        push_toml_string(output, &invocation.outcome);
        output.push_str("\ncanonical_result_sha256 = ");
        push_toml_string(output, &invocation.canonical_result_sha256.hex());
        output.push('\n');
    }
}

fn causal_signal_name(signal: CausalSignal) -> &'static str {
    match signal {
        CausalSignal::ParsedBuiltin => "parsed-builtin",
        CausalSignal::ResolvedBuiltin => "resolved-builtin",
        CausalSignal::SpecializedBuiltin => "specialized-builtin",
        CausalSignal::RuntimeAdapter => "runtime-adapter",
        CausalSignal::RuntimeAdapterAndForceTrace => "runtime-adapter-and-force-trace",
        CausalSignal::ForceTrace => "force-trace",
        CausalSignal::EffectEvent => "effect-event",
        CausalSignal::TaskAndCancellation => "task-and-cancellation",
        CausalSignal::PresentationField => "presentation-field",
        CausalSignal::ResourceLifecycle => "resource-lifecycle",
    }
}

fn push_normalizer_array(output: &mut String, normalizers: &[NormalizerId]) {
    output.push('[');
    for (index, normalizer) in normalizers.iter().enumerate() {
        if index != 0 {
            output.push_str(", ");
        }
        push_toml_string(output, normalizer.as_str());
    }
    output.push(']');
}

fn replay_descriptor(case: &DifferentialCase, report: &DifferentialReport) -> String {
    let mut output = String::from("{\n  \"schemaVersion\": 1,\n  \"caseId\": ");
    push_json_string(&mut output, &case.id);
    output.push_str(",\n  \"source\": \"main.hell\",\n  \"executionInput\": {\"path\": \"execution-input.json\", \"sha256\": ");
    push_json_string(
        &mut output,
        &sha256_bytes(
            execution_input_json(case)
                .expect("committed execution inputs are canonical UTF-8")
                .as_bytes(),
        )
        .hex(),
    );
    output.push_str("},\n  \"arguments\": [");
    for (index, argument) in case.arguments.iter().enumerate() {
        if index != 0 {
            output.push_str(", ");
        }
        push_os_json_string(&mut output, argument);
    }
    output.push_str("],\n  \"mode\": ");
    push_json_string(&mut output, &format!("{:?}", case.mode));
    output.push_str(",\n  \"environmentProfile\": ");
    push_json_string(&mut output, &format!("{:?}", case.environment_profile));
    output.push_str(",\n  \"inheritsHostEnvironment\": ");
    output.push_str(
        if case.environment_profile == crate::EnvironmentProfile::NativePlatform {
            "true"
        } else {
            "false"
        },
    );
    output.push_str(",\n  \"environmentKeys\": [");
    for (index, (key, _)) in case.environment.iter().enumerate() {
        if index != 0 {
            output.push_str(", ");
        }
        push_os_json_string(&mut output, key);
    }
    output.push_str("],\n  \"oracle\": {\"path\": ");
    push_os_json_string(&mut output, report.oracle.identity.path.as_os_str());
    output.push_str(", \"sha256\": ");
    push_json_string(&mut output, &report.oracle.identity.sha256.hex());
    output.push_str("},\n  \"candidate\": {\"path\": ");
    push_os_json_string(&mut output, report.candidate.identity.path.as_os_str());
    output.push_str(", \"sha256\": ");
    push_json_string(&mut output, &report.candidate.identity.sha256.hex());
    output.push_str("}\n}\n");
    output
}

pub(crate) fn execution_input_json(case: &DifferentialCase) -> std::io::Result<String> {
    let mut output = String::from("{\n  \"schemaVersion\": 1,\n  \"environmentProfile\": ");
    push_json_string(&mut output, &format!("{:?}", case.environment_profile));
    output.push_str(",\n  \"arguments\": [");
    for (index, argument) in case.arguments.iter().enumerate() {
        if index != 0 {
            output.push_str(", ");
        }
        let argument = argument
            .to_str()
            .ok_or_else(|| std::io::Error::other("execution argument is not canonical UTF-8"))?;
        push_json_string(&mut output, argument);
    }
    output.push_str("],\n  \"environment\": [");
    for (index, (name, value)) in case.environment.iter().enumerate() {
        if index != 0 {
            output.push_str(", ");
        }
        let name = name
            .to_str()
            .ok_or_else(|| std::io::Error::other("environment name is not canonical UTF-8"))?;
        let value = value
            .to_str()
            .ok_or_else(|| std::io::Error::other("environment value is not canonical UTF-8"))?;
        output.push_str("{\"name\":");
        push_json_string(&mut output, name);
        output.push_str(",\"value\":");
        push_json_string(&mut output, value);
        output.push('}');
    }
    output.push_str("],\n  \"stdin\": {\"path\": \"stdin.bin\", \"size\": ");
    write!(output, "{}", case.stdin.len()).expect("writing to String cannot fail");
    output.push_str(", \"sha256\": ");
    push_json_string(&mut output, &sha256_bytes(&case.stdin).hex());
    output.push_str("},\n  \"processHelperSha256\": ");
    if let Some(digest) = case.process_helper_sha256 {
        push_json_string(&mut output, &digest.hex());
    } else {
        output.push_str("null");
    }
    output.push_str("\n}\n");
    Ok(output)
}

pub(crate) fn verified_profile_invocation_sha256(
    profile: hell_builtins::ExecutionProfile,
    executable_sha256: Digest,
    source_sha256: Digest,
    execution_input_sha256: Digest,
) -> Digest {
    sha256_bytes(
        format!(
            "verified-executable-profile-observation-v1\nprofile={}\nexecutableSha256={}\nsourceSha256={}\nexecutionInputSha256={}\n",
            profile.as_str(),
            executable_sha256.hex(),
            source_sha256.hex(),
            execution_input_sha256.hex(),
        )
        .as_bytes(),
    )
}

fn profile_observation_json(
    profile: hell_builtins::ExecutionProfile,
    executable_sha256: Digest,
    source_sha256: Digest,
    execution_input_sha256: Digest,
    invocation_sha256: Digest,
    observation_sha256: Digest,
) -> String {
    format!(
        concat!(
            "{{\n",
            "  \"schemaVersion\": 1,\n",
            "  \"profile\": \"{}\",\n",
            "  \"executableSha256\": \"{}\",\n",
            "  \"sourceSha256\": \"{}\",\n",
            "  \"executionInputSha256\": \"{}\",\n",
            "  \"invocationSha256\": \"{}\",\n",
            "  \"observationSha256\": \"{}\"\n",
            "}}\n"
        ),
        profile.as_str(),
        executable_sha256.hex(),
        source_sha256.hex(),
        execution_input_sha256.hex(),
        invocation_sha256.hex(),
        observation_sha256.hex(),
    )
}

fn write_profile_manifest(directory: &Path) -> std::io::Result<()> {
    let files = collect_bundle_files(directory)?;
    let manifest = profile_manifest_json(directory, &files)?;
    let digest = sha256_bytes(manifest.as_bytes());
    write_atomic(
        &directory.join("profile-manifest.json"),
        manifest.as_bytes(),
    )?;
    write_atomic(
        &directory.join("profile-manifest.sha256"),
        format!("{}  profile-manifest.json\n", digest.hex()).as_bytes(),
    )
}

fn verify_profile_manifest(directory: &Path) -> std::io::Result<Digest> {
    let mut files = collect_bundle_files(directory)?;
    let manifest_path = "profile-manifest.json";
    let digest_path = "profile-manifest.sha256";
    if files
        .iter()
        .filter(|path| path.as_str() == manifest_path)
        .count()
        != 1
        || files
            .iter()
            .filter(|path| path.as_str() == digest_path)
            .count()
            != 1
    {
        return Err(std::io::Error::other(
            "profile observation manifest files are missing or repeated",
        ));
    }
    files.retain(|path| path != manifest_path && path != digest_path);
    let manifest = fs::read_to_string(directory.join(manifest_path))?;
    if manifest != profile_manifest_json(directory, &files)? {
        return Err(std::io::Error::other(
            "profile observation manifest is noncanonical or substituted",
        ));
    }
    let digest = sha256_bytes(manifest.as_bytes());
    if fs::read_to_string(directory.join(digest_path))?
        != format!("{}  profile-manifest.json\n", digest.hex())
    {
        return Err(std::io::Error::other(
            "profile observation manifest digest is malformed",
        ));
    }
    Ok(digest)
}

fn profile_manifest_json(directory: &Path, files: &[String]) -> std::io::Result<String> {
    let required = [
        "candidate/normalizer-context.json",
        "candidate/observation.json",
        "candidate/stderr.bin",
        "candidate/stderr.claim-input.bin",
        "candidate/stderr.raw.bin",
        "candidate/stdout.bin",
        "case.toml",
        "execution-input.json",
        "main.hell",
        "profile-observation.json",
        "stdin.bin",
    ];
    if required
        .iter()
        .any(|required| !files.iter().any(|path| path == required))
    {
        return Err(std::io::Error::other(
            "profile observation package omits required evidence",
        ));
    }
    let mut output = String::from("{\n  \"schemaVersion\": 1,\n  \"files\": {\n");
    for (index, path) in files.iter().enumerate() {
        output.push_str("    ");
        push_json_string(&mut output, path);
        output.push_str(": ");
        push_json_string(&mut output, &sha256_file(&directory.join(path))?.hex());
        if index + 1 != files.len() {
            output.push(',');
        }
        output.push('\n');
    }
    output.push_str("  }\n}\n");
    Ok(output)
}

fn write_observation(root: &Path, name: &str, observation: &Observation) -> std::io::Result<()> {
    let directory = root.join(name);
    fs::create_dir(&directory)?;
    write_atomic(
        &directory.join("observation.json"),
        observation_json(observation).as_bytes(),
    )?;
    write_capture(&directory, "stdout", &observation.stdout)?;
    write_capture(&directory, "stderr.raw", &observation.raw_stderr)?;
    write_capture(
        &directory,
        "stderr.claim-input",
        &observation.claim_input_stderr,
    )?;
    write_capture(&directory, "stderr", &observation.stderr)?;
    write_atomic(
        &directory.join("normalizer-context.json"),
        normalizer_context_json(observation)?.as_bytes(),
    )?;
    if let Some(semantic) = &observation.semantic {
        let complete_typed_identity = usize::from(semantic.typed_result_canonical.is_some())
            + usize::from(semantic.typed_result_sha256.is_some())
            + usize::from(semantic.typed_result_builtin.is_some());
        if !matches!(complete_typed_identity, 0 | 3) {
            return Err(std::io::Error::other(
                "typed result retained identity is incomplete",
            ));
        }
    }
    if let Some(semantic) = &observation.semantic
        && let Some(canonical) = &semantic.typed_result_canonical
    {
        crate::validate_canonical_typed_value(canonical)?;
        if semantic.typed_result_sha256 != Some(sha256_bytes(canonical.as_bytes()))
            || semantic.typed_result_builtin.is_none()
        {
            return Err(std::io::Error::other(
                "typed result bytes disagree with semantic typed identity",
            ));
        }
        let mut retained = canonical.to_string();
        retained.push('\n');
        write_atomic(
            &directory.join("semantic-typed-result.json"),
            retained.as_bytes(),
        )?;
    }
    if let Some(audit) = &observation.resource_audit {
        write_atomic(
            &directory.join("resource-audit.json"),
            resource_audit_json(audit).as_bytes(),
        )?;
    }
    Ok(())
}

fn normalizer_context_json(observation: &Observation) -> std::io::Result<String> {
    let executable = observation
        .identity
        .path
        .to_str()
        .ok_or_else(|| std::io::Error::other("normalizer executable path is not UTF-8"))?;
    let sandbox = observation
        .normalizer_sandbox
        .to_str()
        .ok_or_else(|| std::io::Error::other("normalizer sandbox path is not UTF-8"))?;
    let script = observation
        .normalizer_script
        .to_str()
        .ok_or_else(|| std::io::Error::other("normalizer script path is not UTF-8"))?;
    let mut output = String::from("{\n  \"schemaVersion\": 2,\n  \"executablePath\": ");
    push_json_string(&mut output, executable);
    output.push_str(",\n  \"sandboxPath\": ");
    push_json_string(&mut output, sandbox);
    output.push_str(",\n  \"scriptPath\": ");
    push_json_string(&mut output, script);
    output.push_str("\n}\n");
    Ok(output)
}

fn write_capture(root: &Path, stream: &str, capture: &BoundedCapture) -> std::io::Result<()> {
    write_atomic(
        &root.join(format!("{stream}.bin")),
        &capture.mismatch_bytes(),
    )
}

fn observation_json(observation: &Observation) -> String {
    let mut output = String::from("{\n  \"identity\": ");
    output.push_str(identity_json(&observation.identity).trim());
    output.push_str(",\n  \"caseId\": ");
    push_json_string(&mut output, &observation.case_id);
    output.push_str(",\n  \"environmentProfile\": ");
    push_json_string(
        &mut output,
        &format!("{:?}", observation.environment_profile),
    );
    output.push_str(",\n  \"processHelperSha256\": ");
    if let Some(digest) = observation.process_helper_sha256 {
        push_json_string(&mut output, &digest.hex());
    } else {
        output.push_str("null");
    }
    output.push_str(",\n  \"mode\": ");
    push_json_string(&mut output, &format!("{:?}", observation.mode));
    output.push_str(",\n  \"harnessNormalizers\": ");
    push_json_normalizers(&mut output, &observation.harness_normalizers);
    output.push_str(",\n  \"claimNormalizers\": ");
    push_json_normalizers(&mut output, &observation.claim_normalizers);
    push_semantic_json(&mut output, observation);
    push_status_json(&mut output, observation);
    push_capture_json(&mut output, "stdout", &observation.stdout);
    push_capture_json(&mut output, "stderr", &observation.stderr);
    push_filesystem_json(&mut output, observation);
    output.push_str("\n}\n");
    output
}

fn push_semantic_json(output: &mut String, observation: &Observation) {
    output.push_str(",\n  \"semanticCoverage\": [");
    if let Some(semantic) = &observation.semantic {
        for (index, event) in semantic.coverage.iter().enumerate() {
            if index != 0 {
                output.push_str(", ");
            }
            let (kind, builtin, detail) = coverage_event_fields(event);
            output.push_str("{\"kind\": ");
            push_json_string(output, kind);
            output.push_str(", \"builtinId\": ");
            write!(output, "{}", builtin.0).expect("writing to String cannot fail");
            if let Some(detail) = detail {
                output.push_str(", \"detail\": ");
                push_json_string(output, &detail);
            }
            output.push('}');
        }
    }
    output.push(']');
    push_semantic_results(output, observation);
    push_semantic_obligations(output, observation);
}

fn push_semantic_results(output: &mut String, observation: &Observation) {
    output.push_str(",\n  \"semanticTypedResultSha256\": ");
    if let Some(digest) = observation
        .semantic
        .as_ref()
        .and_then(|semantic| semantic.typed_result_sha256)
    {
        push_json_string(output, &digest.hex());
    } else {
        output.push_str("null");
    }
    output.push_str(",\n  \"semanticTypedResultBuiltinId\": ");
    if let Some(builtin) = observation
        .semantic
        .as_ref()
        .and_then(|semantic| semantic.typed_result_builtin)
    {
        write!(output, "{}", builtin.0).expect("writing to String cannot fail");
    } else {
        output.push_str("null");
    }
    output.push_str(",\n  \"semanticBoundaries\": [");
    if let Some(semantic) = &observation.semantic {
        let mut index = 0;
        for events in semantic.force_trace.chunks_exact(2) {
            if let [
                LogicalTraceEvent::ForceBuiltinArgument { builtin, argument },
                LogicalTraceEvent::CompleteThunk {
                    label,
                    outcome,
                    error_code,
                },
            ] = events
            {
                if index != 0 {
                    output.push_str(", ");
                }
                write!(
                    output,
                    "{{\"builtinId\": {}, \"argument\": {argument}, \"class\": ",
                    builtin.0
                )
                .expect("writing to String cannot fail");
                push_json_string(output, label);
                output.push_str(", \"outcome\": ");
                push_json_string(output, outcome);
                if let Some(error_code) = error_code {
                    output.push_str(", \"errorCode\": ");
                    push_json_string(output, error_code);
                }
                output.push('}');
                index += 1;
            }
        }
    }
    output.push(']');
}

fn push_semantic_obligations(output: &mut String, observation: &Observation) {
    output.push_str(",\n  \"semanticObligationTrace\": [");
    if let Some(semantic) = &observation.semantic {
        for (index, event) in semantic.obligation_trace.iter().enumerate() {
            if index != 0 {
                output.push_str(", ");
            }
            write!(
                output,
                "{{\"builtinId\": {}, \"ownerTaskId\": {}, \"sequence\": {}, \"parentSequence\": {}, \"instanceTarget\": ",
                event.builtin.0,
                event.owner_task.map_or_else(|| "null".to_owned(), |task| task.to_string()),
                event.sequence,
                event.parent_sequence.map_or_else(|| "null".to_owned(), |sequence| sequence.to_string())
            )
            .expect("writing to String cannot fail");
            if let Some(instance_target) = &event.instance_target {
                push_json_string(output, instance_target);
            } else {
                output.push_str("null");
            }
            output.push_str(", \"instancePremises\": [");
            for (premise_index, premise) in event.instance_premises.iter().enumerate() {
                if premise_index != 0 {
                    output.push(',');
                }
                output.push_str("{\"target\":");
                push_json_string(output, &premise.target);
                write!(output, ",\"premiseCount\":{}}}", premise.premise_count)
                    .expect("writing to String cannot fail");
            }
            output.push(']');
            output.push_str(", \"outcome\": ");
            push_json_string(output, &event.outcome);
            write!(
                output,
                ", \"nestedAdapters\": {}, \"materializedBefore\": {}, \"materializedAfter\": {}, \"callbackInvocations\": [",
                event.nested_adapters, event.materialized_before, event.materialized_after
            )
            .expect("writing to String cannot fail");
            for (callback_index, callback) in event.callbacks.iter().enumerate() {
                if callback_index != 0 {
                    output.push(',');
                }
                let canonical_result_hex =
                    crate::encode_callback_result(&callback.canonical_result);
                write!(
                    output,
                    "{{\"invocation\":{},\"callbackArgument\":{},\"branch\":",
                    callback.invocation, callback.callback_argument
                )
                .expect("writing to String cannot fail");
                push_json_string(output, &callback.branch);
                output.push_str(",\"canonicalArgumentHex\":[");
                for (argument_index, argument) in callback.canonical_arguments.iter().enumerate() {
                    if argument_index != 0 {
                        output.push(',');
                    }
                    push_json_string(output, &crate::encode_callback_result(argument));
                }
                output.push(']');
                output.push_str(",\"outcome\":");
                push_json_string(output, &callback.outcome);
                write!(
                    output,
                    ",\"canonicalResultHex\":\"{canonical_result_hex}\"}}"
                )
                .expect("writing to String cannot fail");
            }
            output.push_str("], \"comparatorInvocations\": [");
            push_comparator_invocations(output, &event.comparators);
            output.push_str("]}");
        }
    }
    output.push(']');
    output.push_str(",\n  \"semanticEventOrder\": [");
    if let Some(semantic) = &observation.semantic {
        for (index, (event_id, kind)) in semantic.causal_event_order.iter().enumerate() {
            if index != 0 {
                output.push_str(", ");
            }
            write!(output, "{{\"eventId\": {event_id}, \"kind\": ")
                .expect("writing to String cannot fail");
            push_json_string(output, kind);
            output.push('}');
        }
    }
    output.push(']');
    push_semantic_lifecycle_json(output, observation);
}

fn push_comparator_invocations(output: &mut String, comparisons: &[crate::ComparatorTraceEvent]) {
    for (index, comparison) in comparisons.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        write!(
            output,
            "{{\"invocation\":{},\"directChildOrdinal\":{},\"comparatorBuiltinId\":{},\"canonicalLeftHex\":\"{}\",\"canonicalRightHex\":\"{}\",\"outcome\":",
            comparison.invocation,
            comparison.direct_child_ordinal,
            comparison.comparator.0,
            crate::encode_callback_result(&comparison.canonical_left),
            crate::encode_callback_result(&comparison.canonical_right),
        )
        .expect("writing to String cannot fail");
        push_json_string(output, &comparison.outcome);
        write!(
            output,
            ",\"canonicalResultHex\":\"{}\"}}",
            crate::encode_callback_result(&comparison.canonical_result),
        )
        .expect("writing to String cannot fail");
    }
}

fn push_semantic_lifecycle_json(output: &mut String, observation: &Observation) {
    output.push_str(",\n  \"semanticEffectTrace\": [");
    if let Some(semantic) = &observation.semantic {
        let mut first = true;
        for event in &semantic.effect_trace {
            if let LogicalTraceEvent::HostEffect {
                builtin,
                owner_task,
                sequence,
                parent_sequence,
                effect,
            } = event
            {
                if !first {
                    output.push_str(", ");
                }
                first = false;
                write!(
                    output,
                    "{{\"builtinId\": {}, \"ownerTaskId\": {}, \"sequence\": {sequence}, \"parentSequence\": {}, \"effect\": ",
                    builtin.0,
                    owner_task.map_or_else(|| "null".to_owned(), |task| task.to_string()),
                    parent_sequence
                        .map_or_else(|| "null".to_owned(), |parent| parent.to_string())
                )
                .expect("writing to String cannot fail");
                push_json_string(output, effect);
                output.push('}');
            }
        }
    }
    output.push(']');
    output.push_str(",\n  \"semanticTaskTrace\": [");
    if let Some(semantic) = &observation.semantic {
        let mut first = true;
        for event in &semantic.task_trace {
            if let LogicalTraceEvent::TaskEvent {
                task,
                builtin,
                event,
            } = event
            {
                if !first {
                    output.push_str(", ");
                }
                first = false;
                write!(
                    output,
                    "{{\"taskId\": {task}, \"builtinId\": {}, \"event\": ",
                    builtin.0
                )
                .expect("writing to String cannot fail");
                push_json_string(output, event);
                output.push('}');
            }
        }
    }
    output.push(']');
    output.push_str(",\n  \"semanticResourceTrace\": [");
    if let Some(semantic) = &observation.semantic {
        let mut first = true;
        for event in &semantic.resource_trace {
            if let LogicalTraceEvent::ResourceEvent {
                resource,
                builtin,
                owner_task,
                event,
            } = event
            {
                if !first {
                    output.push_str(", ");
                }
                first = false;
                let owner = owner_task.map_or_else(|| "null".to_owned(), |task| task.to_string());
                write!(
                    output,
                    "{{\"resourceId\": {resource}, \"builtinId\": {}, \"ownerTaskId\": {owner}, \"event\": ",
                    builtin.0
                )
                .expect("writing to String cannot fail");
                push_json_string(
                    output,
                    match event {
                        crate::ResourceEventKind::Acquire => "acquire",
                        crate::ResourceEventKind::Transfer => "transfer",
                        crate::ResourceEventKind::Cancel => "cancel",
                        crate::ResourceEventKind::Close => "close",
                        crate::ResourceEventKind::CleanupFailure => "cleanup-failure",
                    },
                );
                output.push('}');
            }
        }
    }
    output.push(']');
}

fn push_status_json(output: &mut String, observation: &Observation) {
    output.push_str(",\n  \"status\": {\"success\": ");
    output.push_str(if observation.status.success {
        "true"
    } else {
        "false"
    });
    output.push_str(", \"code\": ");
    if let Some(code) = observation.status.code {
        write!(output, "{code}").expect("writing to String cannot fail");
    } else {
        output.push_str("null");
    }
    output.push_str("},\n  \"timedOut\": ");
    output.push_str(if observation.timed_out {
        "true"
    } else {
        "false"
    });
    output.push_str(",\n  \"diagnostic\": ");
    if let Some(diagnostic) = &observation.diagnostic {
        output.push_str("{\"phase\": ");
        push_json_string(output, &format!("{:?}", diagnostic.phase));
        output.push_str(", \"code\": ");
        push_json_string(output, &diagnostic.code);
        output.push_str(", \"category\": ");
        push_json_string(output, &format!("{:?}", diagnostic.category));
        output.push_str(", \"protectedMessage\": ");
        push_json_string(output, &diagnostic.protected_message);
        output.push_str(", \"line\": ");
        write!(output, "{}", diagnostic.line).expect("writing to String cannot fail");
        output.push_str(", \"column\": ");
        write!(output, "{}", diagnostic.column).expect("writing to String cannot fail");
        output.push('}');
    } else {
        output.push_str("null");
    }
}

fn push_filesystem_json(output: &mut String, observation: &Observation) {
    output.push_str(",\n  \"filesystem\": [");
    for (index, entry) in observation.filesystem.iter().enumerate() {
        if index != 0 {
            output.push_str(", ");
        }
        output.push_str("{\"path\": ");
        push_os_json_string(output, entry.relative_path.as_os_str());
        output.push_str(", \"kind\": ");
        push_json_string(output, &format!("{:?}", entry.kind));
        output.push_str(", \"size\": ");
        write!(output, "{}", entry.size).expect("writing to String cannot fail");
        output.push_str(", \"sha256\": ");
        if let Some(digest) = entry.sha256 {
            push_json_string(output, &digest.hex());
        } else {
            output.push_str("null");
        }
        output.push_str(", \"truncated\": ");
        output.push_str(if entry.truncated { "true" } else { "false" });
        output.push_str(", \"retainedContents\": [");
        for (byte_index, byte) in entry.contents.iter().enumerate() {
            if byte_index != 0 {
                output.push_str(", ");
            }
            write!(output, "{byte}").expect("writing to String cannot fail");
        }
        output.push_str("]}");
    }
    output.push(']');
}

fn coverage_event_fields(
    event: &CoverageEvent,
) -> (&'static str, hell_builtins::BuiltinId, Option<String>) {
    match event {
        CoverageEvent::ParsedBuiltin(id) => ("parsed-builtin", *id, None),
        CoverageEvent::ResolvedBuiltin(id) => ("resolved-builtin", *id, None),
        CoverageEvent::SpecializedBuiltin(id) => ("specialized-builtin", *id, None),
        CoverageEvent::EnteredAdapter(id) => ("entered-adapter", *id, None),
        CoverageEvent::ForcedArgument(id, argument) => {
            ("forced-argument", *id, Some(argument.to_string()))
        }
        CoverageEvent::ExecutedEffect(id, effect) => {
            ("executed-effect", *id, Some(effect.to_string()))
        }
        CoverageEvent::TaskEvent(id, event) => ("task-event", *id, Some(event.to_string())),
        CoverageEvent::AcquiredResource(id, resource) => {
            ("acquired-resource", *id, Some(resource.to_string()))
        }
        CoverageEvent::PresentedField(id, field) => {
            ("presented-field", *id, Some(field.to_string()))
        }
    }
}

fn push_json_normalizers(output: &mut String, normalizers: &[NormalizerId]) {
    output.push('[');
    for (index, normalizer) in normalizers.iter().enumerate() {
        if index != 0 {
            output.push_str(", ");
        }
        push_json_string(output, normalizer.as_str());
    }
    output.push(']');
}

fn resource_audit_json(audit: &ResourceAudit) -> String {
    format!(
        concat!(
            "{{\n",
            "  \"schemaVersion\": 1,\n",
            "  \"tasks\": {},\n",
            "  \"handles\": {},\n",
            "  \"processes\": {},\n",
            "  \"httpBodies\": {},\n",
            "  \"temporaryResources\": {},\n",
            "  \"cleanupFailures\": {}\n",
            "}}\n"
        ),
        audit.tasks,
        audit.handles,
        audit.processes,
        audit.http_bodies,
        audit.temporary_resources,
        audit.cleanup_failures,
    )
}

fn write_bundle_manifest(
    directory: &Path,
    case: &DifferentialCase,
    assurance_epoch_sha256: Digest,
) -> std::io::Result<()> {
    let observed = collect_bundle_files(directory)?;
    let mut expected = vec![
        "candidate/observation.json".to_owned(),
        "candidate/normalizer-context.json".to_owned(),
        "candidate/stderr.claim-input.bin".to_owned(),
        "candidate/stderr.bin".to_owned(),
        "candidate/stderr.raw.bin".to_owned(),
        "candidate/stdout.bin".to_owned(),
        "case.toml".to_owned(),
        "comparison-projection.json".to_owned(),
        "execution-input.json".to_owned(),
        "filesystem.diff".to_owned(),
        "main.hell".to_owned(),
        "mismatch-summary.json".to_owned(),
        "normalized.diff".to_owned(),
        "oracle/observation.json".to_owned(),
        "oracle/normalizer-context.json".to_owned(),
        "oracle/stderr.claim-input.bin".to_owned(),
        "oracle/stderr.bin".to_owned(),
        "oracle/stderr.raw.bin".to_owned(),
        "oracle/stdout.bin".to_owned(),
        "replay.json".to_owned(),
        "stdin.bin".to_owned(),
    ];
    if case.mode == DifferentialMode::Run {
        expected.push("candidate/resource-audit.json".to_owned());
    }
    for role in ["candidate", "oracle"] {
        let relative = format!("{role}/semantic-typed-result.json");
        if directory
            .join(role)
            .join("semantic-typed-result.json")
            .is_file()
        {
            expected.push(relative);
        }
    }
    let mismatch_summary = fs::read_to_string(directory.join("mismatch-summary.json"))?;
    for fact in parse_mismatch_summary(&mismatch_summary)? {
        let category = mismatch_kind_name(fact.category);
        expected.push(format!("mismatches/{category}.candidate.bin"));
        expected.push(format!("mismatches/{category}.oracle.bin"));
    }
    let process_helper = if case.environment_profile == crate::EnvironmentProfile::ProcessCapable {
        let digest = case
            .process_helper_sha256
            .ok_or_else(|| std::io::Error::other("process case has no helper digest"))?;
        let relative = format!(
            "process-helper/hell-test-helper{}",
            std::env::consts::EXE_SUFFIX
        );
        expected.push(relative.clone());
        Some((relative, digest))
    } else {
        None
    };
    expected.sort();
    if observed != expected {
        return Err(std::io::Error::other(format!(
            "observation bundle file inventory is not schema v4: {observed:?}"
        )));
    }
    let profile = case
        .claim_evidence
        .as_ref()
        .map_or("ineligible", |descriptor| match descriptor.profile {
            hell_builtins::ExecutionProfile::Upstream => "upstream",
            hell_builtins::ExecutionProfile::Sandboxed => "sandboxed",
        });
    let declared = observed
        .iter()
        .map(|relative| {
            Ok((
                relative.clone(),
                sha256_file(&directory.join(Path::new(relative)))?.hex(),
            ))
        })
        .collect::<std::io::Result<Vec<_>>>()?;
    let manifest = canonical_bundle_manifest(
        &case.id,
        assurance_epoch_sha256,
        profile,
        process_helper.as_ref().map(|(path, _)| path.as_str()),
        process_helper.as_ref().map(|(_, digest)| *digest),
        &declared,
    );
    let digest = sha256_bytes(manifest.as_bytes()).hex();
    write_atomic(&directory.join("bundle-manifest.json"), manifest.as_bytes())?;
    write_atomic(
        &directory.join("bundle-manifest.sha256"),
        format!("{digest}  bundle-manifest.json\n").as_bytes(),
    )?;
    verify_observation_bundle(directory)?;
    Ok(())
}

fn collect_bundle_files(directory: &Path) -> std::io::Result<Vec<String>> {
    let mut files = Vec::new();
    collect_bundle_files_at(directory, directory, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_bundle_files_at(
    root: &Path,
    directory: &Path,
    files: &mut Vec<String>,
) -> std::io::Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            return Err(std::io::Error::other("bundle contains a symbolic link"));
        }
        if file_type.is_dir() {
            collect_bundle_files_at(root, &entry.path(), files)?;
        } else if file_type.is_file() {
            let relative = entry
                .path()
                .strip_prefix(root)
                .map_err(|_| std::io::Error::other("bundle path escaped its root"))?
                .to_string_lossy()
                .replace(std::path::MAIN_SEPARATOR, "/");
            validate_portable_bundle_path(&relative)?;
            files.push(relative);
        } else {
            return Err(std::io::Error::other("bundle contains a non-regular file"));
        }
    }
    Ok(())
}

fn validate_portable_bundle_path(relative: &str) -> std::io::Result<()> {
    let valid = !relative.is_empty()
        && !relative.starts_with('/')
        && !relative.contains('\\')
        && relative
            .split('/')
            .all(|component| !component.is_empty() && !matches!(component, "." | ".."));
    valid
        .then_some(())
        .ok_or_else(|| std::io::Error::other(format!("invalid portable bundle path {relative:?}")))
}

fn unquote_simple(value: &str) -> Option<&str> {
    value.strip_prefix('"')?.strip_suffix('"')
}

fn push_capture_json(output: &mut String, name: &str, capture: &BoundedCapture) {
    output.push_str(",\n  ");
    push_json_string(output, name);
    output.push_str(": {\"totalBytes\": ");
    write!(output, "{}", capture.total_bytes).expect("writing to String cannot fail");
    output.push_str(", \"sha256\": ");
    push_json_string(output, &capture.sha256.hex());
    output.push_str(", \"truncated\": ");
    output.push_str(if capture.truncated { "true" } else { "false" });
    output.push('}');
}

fn identity_json(identity: &ExecutableIdentity) -> String {
    let mut output = String::from("{\n  \"schemaVersion\": 3,\n  \"role\": ");
    push_json_string(&mut output, &format!("{:?}", identity.role));
    output.push_str(",\n  \"path\": ");
    push_os_json_string(&mut output, identity.path.as_os_str());
    output.push_str(",\n  \"sha256\": ");
    push_json_string(&mut output, &identity.sha256.hex());
    output.push_str(",\n  \"reportedVersion\": ");
    push_json_string(&mut output, &identity.reported_version);
    output.push_str(",\n  \"assuranceEpochSha256\": ");
    if let Some(epoch) = identity.assurance_epoch_sha256 {
        push_json_string(&mut output, &epoch.hex());
    } else {
        output.push_str("null");
    }
    output.push_str(",\n  \"acquisitionReceiptId\": ");
    if let Some(receipt) = &identity.acquisition_receipt_id {
        push_json_string(&mut output, receipt);
    } else {
        output.push_str("null");
    }
    output.push_str(",\n  \"acquisitionReceiptSha256\": ");
    if let Some(receipt) = identity.acquisition_receipt_sha256 {
        push_json_string(&mut output, &receipt.hex());
    } else {
        output.push_str("null");
    }
    output.push_str(",\n  \"acquisitionAttestationSha256\": ");
    if let Some(attestation) = identity.acquisition_attestation_sha256 {
        push_json_string(&mut output, &attestation.hex());
    } else {
        output.push_str("null");
    }
    output.push_str(",\n  \"buildInfo\": ");
    if let Some(build_info) = &identity.build_info {
        output.push('[');
        for (index, line) in build_info.lines.iter().enumerate() {
            if index != 0 {
                output.push_str(", ");
            }
            push_json_string(&mut output, line);
        }
        output.push(']');
    } else {
        output.push_str("null");
    }
    output.push_str("\n}\n");
    output
}

fn write_atomic(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let mut temporary = path.as_os_str().to_os_string();
    temporary.push(".tmp");
    let temporary = PathBuf::from(temporary);
    fs::write(&temporary, contents)?;
    fs::rename(temporary, path)
}

fn push_os_json_string(output: &mut String, value: &OsStr) {
    push_json_string(output, &value.to_string_lossy());
}

pub(crate) fn push_json_string(output: &mut String, value: &str) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            value if value <= '\u{1f}' => {
                write!(output, "\\u{:04x}", u32::from(value))
                    .expect("writing to String cannot fail");
            }
            value => output.push(value),
        }
    }
    output.push('"');
}

fn push_toml_string(output: &mut String, value: &str) {
    push_json_string(output, value);
}

#[cfg(feature = "compat-tracing")]
fn runtime_case_expects_failure(case: &DifferentialCase) -> bool {
    !case.expected_runtime_completion
        || runtime_descriptor_expects_failure(case)
        || case.id.ends_with("list-laziness-error")
        || case.id.as_ref() == "runtime-parser-observable-flag-help"
        || case.id.as_ref() == "runtime-parser-observable-option-help"
        || case.id.as_ref() == "runtime-parser-observable-argument-metavar"
        || case.id.as_ref() == "runtime-parser-observable-argument-help"
        || case.id.as_ref() == "runtime-parser-observable-options-header"
        || case.id.as_ref() == "runtime-parser-observable-options-progdesc"
        || case.id.as_ref() == "runtime-parser-observable-options-helper"
        || case.id.as_ref() == "runtime-typed-io-bytestring-writefile-failure"
        || case.id.as_ref() == "runtime-typed-io-text-writefile-failure"
        || case.id.as_ref() == "runtime-typed-io-text-appendfile-failure"
        || case.id.as_ref() == "runtime-typed-io-text-readfile-failure"
        || case.id.as_ref() == "runtime-typed-io-bytestring-readfile-failure"
        || case.id.as_ref() == "runtime-typed-io-bytestring-readprocess-failure"
        || case.id.as_ref() == "runtime-typed-io-bytestring-readprocess-checked-failure"
        || case.id.as_ref() == "runtime-typed-io-bytestring-readprocess-stdout-checked-failure"
        || case.id.as_ref() == "runtime-typed-thread-delay-forced-argument-failure"
        || case.id.as_ref() == "runtime-typed-timeout-positive-action-failure"
        || case.id.as_ref() == "runtime-typed-async-race-left-fails"
        || case.id.as_ref() == "runtime-typed-async-race-right-fails"
        || case.id.as_ref() == "runtime-typed-async-concurrently-left-fails"
        || case.id.as_ref() == "runtime-typed-async-concurrently-right-fails"
        || case.id.as_ref() == "runtime-typed-exit-die"
        || case.id.as_ref() == "runtime-typed-exit-with-failure"
        || case.id.as_ref() == "runtime-typed-exit-with-success"
        || case.id.as_ref() == "runtime-typed-alternative-optional-parser-partial"
        || case.id.as_ref() == "runtime-typed-alternative-many-parser-partial"
        || case.id.as_ref() == "runtime-environment-get-env-missing"
        || (case.id.starts_with("runtime-directory-") && case.id.ends_with("-failure"))
        || (case.id.starts_with("runtime-io-") && case.id.ends_with("-failure"))
        || (case.id.starts_with("runtime-process-") && case.id.ends_with("-failure"))
        || (case.id.starts_with("runtime-temp-") && case.id.ends_with("-failure"))
        || matches!(
            case.id.as_ref(),
            "list-cycle-boundary-empty-input"
                | "text-decodeutf8-boundary-invalid-encoding"
                | "text-getcontents-boundary-invalid-encoding"
                | "text-getline-boundary-empty-input"
                | "text-getline-boundary-invalid-encoding"
                | "text-readfile-boundary-invalid-encoding"
                | "text-interact-boundary-invalid-encoding"
                | "text-readprocess-boundary-invalid-encoding"
                | "text-readprocess-checked-boundary-invalid-encoding"
                | "text-readprocess-stdout-checked-boundary-invalid-encoding"
                | "options-execparser-boundary-absent-option"
                | "options-execparser-boundary-malformed-option"
                | "options-stroption-boundary-absent-option"
                | "options-stroption-boundary-malformed-option"
                | "options-strargument-boundary-absent-option"
                | "options-strargument-boundary-repeated-option"
                | "options-strargument-boundary-malformed-option"
                | "options-switch-boundary-repeated-option"
                | "options-switch-boundary-malformed-option"
                | "options-flag-boundary-repeated-option"
                | "options-flag-boundary-malformed-option"
                | "options-flag-prime-boundary-absent-option"
                | "options-flag-prime-boundary-repeated-option"
                | "options-flag-prime-boundary-malformed-option"
                | "flag-long-boundary-repeated-option"
                | "flag-long-boundary-malformed-option"
                | "flag-help-boundary-repeated-option"
                | "flag-help-boundary-malformed-option"
                | "option-long-boundary-absent-option"
                | "option-long-boundary-malformed-option"
                | "option-help-boundary-absent-option"
                | "option-help-boundary-malformed-option"
                | "argument-metavar-boundary-absent-option"
                | "argument-metavar-boundary-repeated-option"
                | "argument-metavar-boundary-malformed-option"
                | "argument-help-boundary-absent-option"
                | "argument-help-boundary-repeated-option"
                | "argument-help-boundary-malformed-option"
                | "option-value-boundary-repeated-option"
                | "option-value-boundary-malformed-option"
                | "argument-value-boundary-repeated-option"
                | "argument-value-boundary-malformed-option"
                | "options-header-boundary-repeated-option"
                | "options-header-boundary-malformed-option"
                | "options-progdesc-boundary-repeated-option"
                | "options-progdesc-boundary-malformed-option"
                | "options-helper-boundary-repeated-option"
                | "options-helper-boundary-malformed-option"
                | "options-info-boundary-repeated-option"
                | "options-info-boundary-malformed-option"
                | "options-fulldesc-boundary-repeated-option"
                | "options-fulldesc-boundary-malformed-option"
                | "options-command-boundary-absent-option"
                | "options-command-boundary-repeated-option"
                | "options-command-boundary-malformed-option"
                | "options-hsubparser-boundary-absent-option"
                | "options-hsubparser-boundary-repeated-option"
                | "options-hsubparser-boundary-malformed-option"
        )
}

#[cfg(feature = "compat-tracing")]
fn runtime_descriptor_expects_failure(case: &DifferentialCase) -> bool {
    case.claim_evidence.as_ref().is_some_and(|descriptor| {
        descriptor.semantic_targets.iter().any(|target| {
            target.expected_process_status_sha256
                == Some(crate::process_status_sha256(false, Some(1)))
        })
    })
}

#[cfg(feature = "compat-tracing")]
fn run_core_data_production_bundle_case<Execute>(
    root: &Path,
    case: &DifferentialCase,
    index: usize,
    case_count: usize,
    execute: &mut Execute,
) -> std::io::Result<()>
where
    Execute: FnMut(&DifferentialCase, &Path) -> std::io::Result<(bool, DifferentialReport)>,
{
    eprintln!(
        "core-data-bundle case start: {}/{} {:?}",
        index.saturating_add(1),
        case_count,
        case.id
    );
    let execution_root = root.join(case.id.as_ref());
    fs::create_dir_all(&execution_root)?;
    let expected_targets = case
        .claim_evidence
        .as_ref()
        .ok_or_else(|| std::io::Error::other("core data case has no descriptor"))?
        .semantic_targets
        .len();
    let (runtime_success, retained) = execute(case, &execution_root)?;
    if runtime_success == runtime_case_expects_failure(case) {
        return Err(std::io::Error::other(format!(
            "{} runtime completion differs from its descriptor",
            case.id
        )));
    }
    let status = retained.candidate.status.clone();
    let directory = retain_observation_bundle(&root.join("evidence"), case, &retained)?;
    let bundle_sha256 = verify_observation_bundle_for_case(&directory, case)?;
    let outcome = retained_bundle_outcome_facts_from_verified(&directory)?;
    if outcome.oracle.timed_out
        || outcome.candidate.timed_out
        || outcome.candidate.status_success != status.success
        || outcome.candidate.resource_failures != 0
    {
        return Err(std::io::Error::other(format!(
            "{} retained outcome facts differ from runtime execution",
            case.id
        )));
    }
    let shard = runtime_platform_shard_from_verified_bundle(
        &directory,
        case,
        hell_builtins::ClaimPlatform::Linux,
        sha256_bytes(b"candidate-source"),
        retained.candidate.identity.sha256,
        bundle_sha256,
    )?
    .ok_or_else(|| std::io::Error::other("core data case produced no platform shard"))?;
    if shard.targets.len() != expected_targets {
        return Err(std::io::Error::other(format!(
            "{} platform shard target count differs from its descriptor",
            case.id
        )));
    }
    eprintln!(
        "core-data-bundle case done: {}/{} {:?}",
        index.saturating_add(1),
        case_count,
        case.id
    );
    Ok(())
}

/// Executes every committed core-data obligation through the production
/// retention, verification, outcome, and runtime-platform bundle gates.
///
/// Work is assigned by authoritative case index modulo the repository's
/// bounded differential worker limit. Every case is joined and accounted for
/// before the lowest indexed error is returned.
///
/// # Errors
///
/// Returns an error when no eligible case exists, an indexed worker result is
/// missing, case execution fails, a retained bundle is invalid, or a derived
/// fact differs from the runtime observation.
#[cfg(feature = "compat-tracing")]
pub fn run_core_data_production_bundle_gate<MakeWorker, Execute>(
    cases: &[DifferentialCase],
    make_worker: MakeWorker,
) -> std::io::Result<()>
where
    MakeWorker: Fn() -> Execute + Sync,
    Execute: FnMut(&DifferentialCase, &Path) -> std::io::Result<(bool, DifferentialReport)> + Send,
{
    static NEXT_ROOT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    if !cases
        .iter()
        .any(|case| case.id.starts_with("runtime-typed-"))
    {
        return Err(std::io::Error::other(
            "core data catalog has no typed runtime case",
        ));
    }
    let case_count = cases.len();
    let worker_count = crate::differential_worker_limit().min(case_count);
    if worker_count == 0 {
        return Err(std::io::Error::other("core data catalog is empty"));
    }
    let nonce = NEXT_ROOT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "hell-testkit-core-data-bundle-{}-{nonce}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root)?;
    let mut outcomes = std::thread::scope(|scope| {
        let mut workers = Vec::with_capacity(worker_count);
        for shard_index in 0..worker_count {
            let cases = &cases;
            let root = &root;
            let make_worker = &make_worker;
            workers.push(scope.spawn(move || {
                let mut execute = make_worker();
                (shard_index..case_count)
                    .step_by(worker_count)
                    .map(|index| {
                        (
                            index,
                            run_core_data_production_bundle_case(
                                root,
                                &cases[index],
                                index,
                                case_count,
                                &mut execute,
                            ),
                        )
                    })
                    .collect::<Vec<_>>()
            }));
        }
        workers
            .into_iter()
            .flat_map(|worker| {
                worker
                    .join()
                    .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
            })
            .collect::<Vec<_>>()
    });
    outcomes.sort_by_key(|(index, _)| *index);
    let outcome_count = outcomes.len();
    let mut failure = None;
    for (expected_index, (actual_index, result)) in outcomes.into_iter().enumerate() {
        if actual_index != expected_index {
            failure = Some(std::io::Error::other(format!(
                "core data shard result index {actual_index} differs from {expected_index}"
            )));
            break;
        }
        if let Err(error) = result {
            failure = Some(std::io::Error::other(format!(
                "{} core data bundle failed: {error}",
                cases[actual_index].id
            )));
            break;
        }
    }
    if failure.is_none() && outcome_count != case_count {
        failure = Some(std::io::Error::other(
            "core data shards did not account for every committed case",
        ));
    }
    let cleanup = fs::remove_dir_all(&root);
    if let Some(error) = failure {
        return Err(error);
    }
    cleanup
}

#[cfg(test)]
mod tests {
    use super::*;

    fn portable_temp_component(label: &str) -> String {
        const STEM_BYTES: usize = 32;

        let mut stem = label
            .bytes()
            .take(STEM_BYTES)
            .map(|byte| {
                if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_') {
                    char::from(byte)
                } else {
                    '-'
                }
            })
            .collect::<String>();
        if stem.is_empty() {
            stem.push_str("label");
        }
        format!("{stem}-{}", sha256_bytes(label.as_bytes()).hex())
    }

    fn root(name: &str) -> PathBuf {
        static NEXT_ROOT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let nonce = NEXT_ROOT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let component = portable_temp_component(name);
        let root = std::env::temp_dir().join(format!(
            "hell-testkit-promotion-{component}-{}-{nonce}",
            std::process::id(),
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        root
    }

    #[test]
    fn portable_temp_components_bind_adversarial_windows_labels_without_aliasing() {
        let labels = [
            "",
            ".",
            "..",
            "<$>",
            "<*>",
            "<**>",
            "<>",
            "a:b",
            "a/b",
            "a\\b",
            "a?b",
            "a*b",
            "a\"b",
            "a|b",
            "trailing.",
            "trailing ",
            "CON",
            "con",
            "NUL.txt",
            "COM1",
            "LPT9.log",
            "\0control",
            "日本語",
        ];
        let components = labels
            .iter()
            .map(|label| portable_temp_component(label))
            .collect::<Vec<_>>();
        for (label, component) in labels.iter().zip(&components) {
            assert_eq!(*component, portable_temp_component(label));
            assert!(component.len() <= 32 + 1 + 64);
            assert!(
                component
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            );
            assert!(!component.ends_with(['.', ' ']));
        }
        assert_eq!(
            components
                .iter()
                .map(|component| component.to_ascii_lowercase())
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            labels.len()
        );
    }

    fn observation(role: crate::ExecutableRole) -> Observation {
        Observation {
            identity: ExecutableIdentity {
                path: PathBuf::from(match role {
                    crate::ExecutableRole::Oracle => "oracle-hell",
                    crate::ExecutableRole::Candidate => "candidate-hell",
                }),
                sha256: sha256_bytes(match role {
                    crate::ExecutableRole::Oracle => b"oracle",
                    crate::ExecutableRole::Candidate => b"candidate",
                }),
                reported_version: "2026-05-29".into(),
                build_info: None,
                role,
                assurance_epoch_sha256: Some(sha256_bytes(b"epoch")),
                acquisition_receipt_id: (role == crate::ExecutableRole::Oracle)
                    .then(|| std::sync::Arc::from("github-release:17:23")),
                acquisition_receipt_sha256: (role == crate::ExecutableRole::Oracle)
                    .then(|| sha256_bytes(b"acquisition")),
                acquisition_attestation_sha256: (role == crate::ExecutableRole::Oracle)
                    .then(|| sha256_bytes(b"acquisition-attestation")),
            },
            case_id: "layout".into(),
            environment_profile: crate::EnvironmentProfile::Explicit,
            process_helper_sha256: None,
            mode: DifferentialMode::Run,
            status: crate::ProcessStatus {
                success: true,
                code: Some(0),
            },
            stdout: BoundedCapture::from_bytes(b"ok\n".to_vec()),
            raw_stderr: BoundedCapture::from_bytes(Vec::new()),
            claim_input_stderr: BoundedCapture::from_bytes(Vec::new()),
            stderr: BoundedCapture::from_bytes(Vec::new()),
            normalizer_sandbox: PathBuf::from("sandbox"),
            normalizer_script: PathBuf::from("sandbox").join("main.hell"),
            timed_out: false,
            diagnostic: None,
            filesystem: Vec::new(),
            harness_normalizers: vec![NormalizerId::DiagnosticSandboxPathV1],
            claim_normalizers: Vec::new(),
            resource_audit: (role == crate::ExecutableRole::Candidate).then(ResourceAudit::default),
            semantic: None,
        }
    }

    fn report() -> DifferentialReport {
        DifferentialReport {
            oracle: observation(crate::ExecutableRole::Oracle),
            candidate: observation(crate::ExecutableRole::Candidate),
            comparison_projection: crate::DifferentialComparisonProjection::Exact,
            mismatches: Vec::new(),
        }
    }

    #[test]
    fn reviewed_windows_divergence_projection_round_trips_exactly() {
        for (case_id, builtin, mismatch_sha256) in [
            (
                "runtime-typed-thread-delay-forced-argument-failure",
                "Concurrent.threadDelay",
                "9ea41783a7bd7d7505b62fc603c027d547f0b2590459baa688a68c1ed51afa48",
            ),
            (
                "runtime-interaction-timeout-process",
                "Timeout.timeout",
                "536f5d413d57fb66294475eae66f1bd0222d79a5f69e240d1c6fec095812481e",
            ),
        ] {
            let authority =
                crate::windows_divergences::retained_authority(case_id, builtin, mismatch_sha256)
                    .expect("reviewed Windows divergence authority");
            let projection = crate::DifferentialComparisonProjection::ReviewedWindowsDivergence {
                case_id,
                builtin,
                mismatch_sha256: Digest::from_hex(mismatch_sha256).unwrap(),
                mismatch_kinds: authority.mismatch_kinds,
                rationale: authority.rationale,
            };
            let document = comparison_projection_json(&projection);
            assert_eq!(
                parse_comparison_projection_json(&document).unwrap(),
                projection
            );
        }
    }

    #[test]
    fn conformance_observation_retains_nonstream_comparison_state() {
        let baseline = observation(crate::ExecutableRole::Candidate);
        let baseline_bytes = canonical_conformance_observation_json(&baseline).unwrap();
        let mut diagnostic = baseline.clone();
        diagnostic.diagnostic = Some(crate::DiagnosticObservation {
            phase: crate::DiagnosticPhase::Parse,
            code: "H0200".into(),
            category: crate::DiagnosticCategory::Syntax,
            protected_message: "syntax-error".into(),
            line: 1,
            column: 1,
        });
        assert_ne!(
            baseline_bytes,
            canonical_conformance_observation_json(&diagnostic).unwrap()
        );
        let mut filesystem = baseline.clone();
        filesystem.filesystem.push(crate::FilesystemEntry {
            relative_path: PathBuf::from("result.bin"),
            kind: crate::FilesystemEntryKind::File,
            contents: b"result".to_vec(),
            size: 6,
            sha256: Some(sha256_bytes(b"result")),
            truncated: false,
        });
        assert_ne!(
            baseline_bytes,
            canonical_conformance_observation_json(&filesystem).unwrap()
        );
        let mut raw = baseline;
        raw.raw_stderr = BoundedCapture::from_bytes(b"producer-only raw difference".to_vec());
        assert_ne!(
            baseline_bytes,
            canonical_conformance_observation_json(&raw).unwrap()
        );
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn conformance_semantic_document_replays_reviewed_bool_obligations() {
        let case = crate::committed_differential_cases()
            .into_iter()
            .find(|case| case.id.as_ref() == "bool-ordinary-success")
            .unwrap();
        let root = root("conformance-semantic-bool");
        let (_, status, semantic, stdout, stderr) =
            execute_runtime_interaction_with_status(&case, &root);
        let mut observed = observation(crate::ExecutableRole::Candidate);
        observed.case_id = Arc::clone(&case.id);
        observed.status = status;
        observed.stdout = BoundedCapture::from_bytes(stdout);
        observed.raw_stderr = BoundedCapture::from_bytes(stderr.clone());
        observed.claim_input_stderr = BoundedCapture::from_bytes(stderr.clone());
        observed.stderr = BoundedCapture::from_bytes(stderr);
        observed.semantic = Some(semantic);
        let document = conformance_semantic_document(&observed).unwrap();
        let target = case
            .claim_evidence
            .as_ref()
            .unwrap()
            .semantic_targets
            .iter()
            .find(|target| target.builtin.as_ref() == "Bool.bool")
            .unwrap();
        for obligation in &target.obligations {
            validate_conformance_semantic_obligation(
                &document,
                &case,
                "Bool.bool",
                hell_builtins::CompatibilityDimension::PureRuntime,
                &obligation.0,
            )
            .unwrap();
        }
        let forged = document.replacen(
            "\"semanticTypedResultSha256\": \"",
            "\"semanticTypedResultSha256\": \"0",
            1,
        );
        assert!(
            validate_conformance_semantic_obligation(
                &forged,
                &case,
                "Bool.bool",
                hell_builtins::CompatibilityDimension::PureRuntime,
                &target.obligations[0].0,
            )
            .is_err()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn conformance_semantic_document_replays_each_runtime_dimension() {
        let dimensions = [
            hell_builtins::CompatibilityDimension::PureRuntime,
            hell_builtins::CompatibilityDimension::Effects,
            hell_builtins::CompatibilityDimension::Concurrency,
            hell_builtins::CompatibilityDimension::Presentation,
            hell_builtins::CompatibilityDimension::Platform,
            hell_builtins::CompatibilityDimension::ResourceBehavior,
        ];
        let cases = crate::committed_differential_cases();
        for dimension in dimensions {
            let (case, target) = cases
                .iter()
                .find_map(|case| {
                    (case.environment_profile != crate::EnvironmentProfile::ProcessCapable)
                        .then(|| {
                            case.claim_evidence.as_ref().and_then(|descriptor| {
                                descriptor
                                    .semantic_targets
                                    .iter()
                                    .find(|target| target.dimension == dimension)
                                    .map(|target| (case, target))
                            })
                        })
                        .flatten()
                })
                .unwrap_or_else(|| panic!("no executable reviewed case for {dimension:?}"));
            let case_root = root(&format!("conformance-semantic-{dimension:?}"));
            let (_, status, semantic, stdout, stderr) =
                execute_runtime_interaction_with_status(case, &case_root);
            let mut observed = observation(crate::ExecutableRole::Candidate);
            observed.case_id = Arc::clone(&case.id);
            observed.status = status;
            observed.stdout = BoundedCapture::from_bytes(stdout);
            observed.raw_stderr = BoundedCapture::from_bytes(stderr.clone());
            observed.claim_input_stderr = BoundedCapture::from_bytes(stderr.clone());
            observed.stderr = BoundedCapture::from_bytes(stderr);
            observed.semantic = Some(semantic);
            observed.resource_audit = Some(ResourceAudit::default());
            let document = conformance_semantic_document(&observed).unwrap();
            for obligation in &target.obligations {
                validate_conformance_semantic_obligation(
                    &document,
                    case,
                    &target.builtin,
                    dimension,
                    &obligation.0,
                )
                .unwrap_or_else(|error| {
                    panic!(
                        "{}/{dimension:?}/{} did not replay: {error}",
                        target.builtin, obligation.0
                    )
                });
            }
            if dimension == hell_builtins::CompatibilityDimension::Presentation {
                let forged = document.replacen(
                    "\"rawPresentationSha256\": \"",
                    "\"rawPresentationSha256\": \"0",
                    1,
                );
                assert!(
                    validate_conformance_semantic_obligation(
                        &forged,
                        case,
                        &target.builtin,
                        dimension,
                        &target.obligations[0].0,
                    )
                    .is_err(),
                    "presentation descriptor accepted forged raw bytes"
                );
            }
            fs::remove_dir_all(case_root).unwrap();
        }
    }

    #[test]
    fn rejects_case_ids_that_can_escape_the_artifact_root() {
        assert!(validate_case_id("json-number-large").is_ok());
        assert!(validate_case_id("../outside").is_err());
        assert!(validate_case_id("Uppercase").is_err());
    }

    #[test]
    fn writes_the_layout_consumed_by_the_claim_evidence_index() {
        let root = root("layout");
        let case = DifferentialCase {
            id: "layout".into(),
            ..DifferentialCase::default()
        };
        let directory = retain_observation_bundle(&root, &case, &report()).unwrap();
        for relative in [
            "oracle/observation.json",
            "oracle/stdout.bin",
            "oracle/stderr.bin",
            "candidate/observation.json",
            "candidate/stdout.bin",
            "candidate/stderr.bin",
            "candidate/resource-audit.json",
            "bundle-manifest.json",
            "bundle-manifest.sha256",
        ] {
            assert!(directory.join(relative).is_file(), "missing {relative}");
        }
        assert!(!directory.join("oracle.json").exists());
        assert!(!directory.join("candidate.json").exists());
        verify_observation_bundle_for_case(&directory, &case).unwrap();
        let manifest = fs::read_to_string(directory.join("bundle-manifest.json")).unwrap();
        assert!(!manifest.contains('\\'));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn bundle_manifest_rejects_duplicate_extra_wrong_type_and_epoch_substitutions() {
        for (name, mutate) in [
            (
                "duplicate",
                fn_mutate_manifest_duplicate as fn(&str) -> String,
            ),
            ("extra", fn_mutate_manifest_extra as fn(&str) -> String),
            (
                "wrong-type",
                fn_mutate_manifest_wrong_type as fn(&str) -> String,
            ),
            ("epoch", fn_mutate_manifest_epoch as fn(&str) -> String),
        ] {
            let root = root(name);
            let case = DifferentialCase {
                id: name.into(),
                ..DifferentialCase::default()
            };
            let directory = retain_observation_bundle(&root, &case, &report()).unwrap();
            let manifest_path = directory.join("bundle-manifest.json");
            let mutated = mutate(&fs::read_to_string(&manifest_path).unwrap());
            fs::write(&manifest_path, &mutated).unwrap();
            fs::write(
                directory.join("bundle-manifest.sha256"),
                format!(
                    "{}  bundle-manifest.json\n",
                    sha256_bytes(mutated.as_bytes()).hex()
                ),
            )
            .unwrap();
            assert!(verify_observation_bundle(&directory).is_err(), "{name}");
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn case_profile_and_candidate_identity_substitutions_fail_after_rehash() {
        for (name, original, replacement) in [
            (
                "case-id",
                "\"caseId\": \"case-id\"",
                "\"caseId\": \"other-case\"",
            ),
            (
                "profile-id",
                "\"profile\": \"ineligible\"",
                "\"profile\": \"upstream\"",
            ),
        ] {
            let root = root(name);
            let case = DifferentialCase {
                id: name.into(),
                ..DifferentialCase::default()
            };
            let directory = retain_observation_bundle(&root, &case, &report()).unwrap();
            let manifest_path = directory.join("bundle-manifest.json");
            let manifest = fs::read_to_string(&manifest_path).unwrap();
            let substituted = manifest.replace(original, replacement);
            assert_ne!(manifest, substituted);
            fs::write(&manifest_path, &substituted).unwrap();
            rewrite_manifest_digest(&directory, &substituted);
            assert!(verify_observation_bundle_for_case(&directory, &case).is_err());
            fs::remove_dir_all(root).unwrap();
        }

        let root = root("candidate-identity");
        let case = DifferentialCase {
            id: "candidate-identity".into(),
            ..DifferentialCase::default()
        };
        let directory = retain_observation_bundle(&root, &case, &report()).unwrap();
        let observation_path = directory.join("candidate").join("observation.json");
        let observation = fs::read_to_string(&observation_path).unwrap();
        let substituted = observation.replace("candidate-hell", "\\u0063andidate-hell");
        assert_ne!(observation, substituted);
        fs::write(&observation_path, &substituted).unwrap();
        rewrite_bundle_file_digest(&directory, "candidate/observation.json");
        assert!(verify_observation_bundle_for_case(&directory, &case).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn process_helper_swap_fails_after_the_bundle_inventory_is_rehashed() {
        let root = root("process-helper-swap");
        fs::create_dir_all(&root).unwrap();
        let helper_directory = root.join("helper-bin");
        fs::create_dir(&helper_directory).unwrap();
        let helper_name = format!("hell-test-helper{}", std::env::consts::EXE_SUFFIX);
        let helper = helper_directory.join(&helper_name);
        fs::write(&helper, b"trusted process fixture\n").unwrap();
        let helper_sha256 = sha256_file(&helper).unwrap();
        let mut case = DifferentialCase {
            id: "process-helper-swap".into(),
            environment_profile: crate::EnvironmentProfile::ProcessCapable,
            process_helper_directory: Some(helper_directory),
            process_helper_sha256: Some(helper_sha256),
            ..DifferentialCase::default()
        };
        let mut report = report();
        for observation in [&mut report.oracle, &mut report.candidate] {
            observation.case_id = Arc::clone(&case.id);
            observation.environment_profile = case.environment_profile;
            observation.process_helper_sha256 = Some(helper_sha256);
        }
        let directory = retain_observation_bundle(&root, &case, &report).unwrap();
        verify_observation_bundle_for_case(&directory, &case).unwrap();
        let relative = format!("process-helper/{helper_name}");
        fs::write(
            directory.join("process-helper").join(helper_name),
            b"swapped fixture\n",
        )
        .unwrap();
        rewrite_bundle_file_digest(&directory, &relative);
        assert!(verify_observation_bundle_for_case(&directory, &case).is_err());
        case.process_helper_sha256 = Some(sha256_bytes(b"swapped fixture\n"));
        assert!(verify_observation_bundle_for_case(&directory, &case).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn retained_mismatch_classification_binds_typed_side_digests_and_fingerprint() {
        let root = root("typed-mismatch");
        let case = DifferentialCase {
            id: "typed-mismatch".into(),
            ..DifferentialCase::default()
        };
        let mut retained = report();
        retained.oracle.case_id = Arc::clone(&case.id);
        retained.candidate.case_id = Arc::clone(&case.id);
        retained.oracle.stdout = BoundedCapture::from_bytes(b"oracle\n".to_vec());
        retained.candidate.stdout = BoundedCapture::from_bytes(b"candidate\n".to_vec());
        retained.mismatches = vec![crate::DifferentialMismatch {
            kind: crate::MismatchKind::Stdout,
            oracle: b"oracle\n".to_vec(),
            candidate: b"candidate\n".to_vec(),
        }];
        let directory = retain_observation_bundle(&root, &case, &retained).unwrap();
        let classification = classify_retained_observation_bundle(&directory, &case).unwrap();
        let RetainedObservationClassification::Mismatch {
            raw_mismatches,
            normalized_mismatches,
            fingerprint_sha256,
        } = classification
        else {
            panic!("retained mismatch was accepted as equality");
        };
        assert_eq!(raw_mismatches, normalized_mismatches);
        assert_eq!(raw_mismatches.len(), 1);
        assert_ne!(fingerprint_sha256, Digest::default());
        let summary_path = directory.join("mismatch-summary.json");
        let summary = fs::read_to_string(&summary_path).unwrap();
        let forged = summary.replace(
            &sha256_bytes(b"candidate\n").hex(),
            &sha256_bytes(b"forged\n").hex(),
        );
        assert_ne!(summary, forged);
        fs::write(&summary_path, forged).unwrap();
        rewrite_bundle_file_digest(&directory, "mismatch-summary.json");
        assert!(classify_retained_observation_bundle(&directory, &case).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn retained_mismatch_classification_rejects_every_rehashed_category_omission() {
        for category in [
            crate::MismatchKind::Timeout,
            crate::MismatchKind::ExitStatus,
            crate::MismatchKind::Stdout,
            crate::MismatchKind::Stderr,
            crate::MismatchKind::Diagnostic,
            crate::MismatchKind::Filesystem,
        ] {
            let name = mismatch_kind_name(category);
            let root = root(name);
            let mut case = DifferentialCase {
                id: Arc::from(name),
                ..DifferentialCase::default()
            };
            let mut retained = mismatch_report(category, &case);
            if category == crate::MismatchKind::Diagnostic {
                case.mode = DifferentialMode::Check;
                retained.oracle.mode = DifferentialMode::Check;
                retained.candidate.mode = DifferentialMode::Check;
                retained.oracle.resource_audit = None;
                retained.candidate.resource_audit = None;
            }
            let directory = retain_observation_bundle(&root, &case, &retained).unwrap();
            assert!(matches!(
                classify_retained_observation_bundle(&directory, &case).unwrap(),
                RetainedObservationClassification::Mismatch { .. }
            ));
            fs::write(
                directory.join("mismatch-summary.json"),
                mismatch_summary_json(&[]),
            )
            .unwrap();
            rewrite_bundle_file_digest(&directory, "mismatch-summary.json");
            fs::remove_dir_all(directory.join("mismatches")).unwrap();
            rewrite_bundle_inventory_without_prefix(&directory, "mismatches/");
            assert!(
                classify_retained_observation_bundle(&directory, &case).is_err(),
                "{name} omission was accepted"
            );
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn retained_check_diagnostic_binds_code_category_and_protected_message() {
        let case = DifferentialCase {
            id: "diagnostic-identity".into(),
            mode: crate::DifferentialMode::Check,
            ..DifferentialCase::default()
        };
        let diagnostic = crate::DiagnosticObservation {
            phase: crate::DiagnosticPhase::Parse,
            code: "H0200".into(),
            category: crate::DiagnosticCategory::Syntax,
            protected_message: "syntax-error".into(),
            line: 1,
            column: 1,
        };
        let mut retained = report();
        for observation in [&mut retained.oracle, &mut retained.candidate] {
            observation.case_id = Arc::clone(&case.id);
            observation.mode = crate::DifferentialMode::Check;
            observation.diagnostic = Some(diagnostic.clone());
            observation.resource_audit = None;
        }
        retained.mismatches = crate::compare(&retained.oracle, &retained.candidate);
        assert!(retained.mismatches.is_empty());
        for (name, original, replacement) in [
            ("code", "\"code\": \"H0200\"", "\"code\": \"H0402\""),
            (
                "category",
                "\"category\": \"Syntax\"",
                "\"category\": \"NameResolution\"",
            ),
            (
                "message",
                "\"protectedMessage\": \"syntax-error\"",
                "\"protectedMessage\": \"unresolved-name\"",
            ),
        ] {
            let root = root(&format!("diagnostic-{name}"));
            let directory = retain_observation_bundle(&root, &case, &retained).unwrap();
            let candidate = directory.join("candidate").join("observation.json");
            let document = fs::read_to_string(&candidate).unwrap();
            fs::write(&candidate, document.replace(original, replacement)).unwrap();
            rewrite_bundle_file_digest(&directory, "candidate/observation.json");
            assert!(classify_retained_observation_bundle(&directory, &case).is_err());
            fs::remove_dir_all(root).unwrap();
        }
    }

    fn mismatch_report(
        category: crate::MismatchKind,
        case: &DifferentialCase,
    ) -> DifferentialReport {
        let mut retained = report();
        retained.oracle.case_id = Arc::clone(&case.id);
        retained.candidate.case_id = Arc::clone(&case.id);
        match category {
            crate::MismatchKind::Timeout => retained.candidate.timed_out = true,
            crate::MismatchKind::ExitStatus => retained.candidate.status.success = false,
            crate::MismatchKind::Stdout => {
                retained.candidate.stdout = BoundedCapture::from_bytes(b"candidate\n".to_vec());
            }
            crate::MismatchKind::Stderr => {
                retained.candidate.stderr = BoundedCapture::from_bytes(b"candidate\n".to_vec());
            }
            crate::MismatchKind::Diagnostic => {
                retained.candidate.diagnostic = Some(crate::DiagnosticObservation {
                    phase: crate::DiagnosticPhase::Parse,
                    code: "H0200".into(),
                    category: crate::DiagnosticCategory::Syntax,
                    protected_message: "syntax-error".into(),
                    line: 1,
                    column: 1,
                });
            }
            crate::MismatchKind::Filesystem => {
                retained.candidate.filesystem = vec![crate::FilesystemEntry {
                    relative_path: PathBuf::from("candidate-entry"),
                    kind: crate::FilesystemEntryKind::File,
                    contents: b"candidate\n".to_vec(),
                    size: u64::try_from(b"candidate\n".len()).unwrap(),
                    sha256: Some(sha256_bytes(b"candidate\n")),
                    truncated: false,
                }];
            }
        }
        retained.mismatches = vec![crate::DifferentialMismatch {
            kind: category,
            oracle: b"oracle-side".to_vec(),
            candidate: b"candidate-side".to_vec(),
        }];
        retained
    }

    fn rewrite_bundle_file_digest(directory: &Path, relative: &str) {
        let manifest_path = directory.join("bundle-manifest.json");
        let manifest = fs::read_to_string(&manifest_path).unwrap();
        let line_prefix = format!("    \"{relative}\": \"");
        let old = manifest
            .lines()
            .find(|line| line.starts_with(&line_prefix))
            .and_then(|line| line.strip_prefix(&line_prefix))
            .and_then(|line| line.strip_suffix("\",").or_else(|| line.strip_suffix('"')))
            .unwrap();
        let new = sha256_file(&directory.join(relative)).unwrap().hex();
        let manifest = manifest.replace(old, &new);
        fs::write(&manifest_path, &manifest).unwrap();
        rewrite_manifest_digest(directory, &manifest);
    }

    fn rewrite_bundle_inventory_without_prefix(directory: &Path, prefix: &str) {
        let manifest_path = directory.join("bundle-manifest.json");
        let line_prefix = format!("    \"{prefix}");
        let manifest = fs::read_to_string(&manifest_path)
            .unwrap()
            .lines()
            .filter(|line| !line.starts_with(&line_prefix))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        fs::write(&manifest_path, &manifest).unwrap();
        rewrite_manifest_digest(directory, &manifest);
    }

    fn rewrite_manifest_digest(directory: &Path, manifest: &str) {
        fs::write(
            directory.join("bundle-manifest.sha256"),
            format!(
                "{}  bundle-manifest.json\n",
                sha256_bytes(manifest.as_bytes()).hex()
            ),
        )
        .unwrap();
    }

    fn fn_mutate_manifest_duplicate(document: &str) -> String {
        document.replace(
            "  \"profile\": \"ineligible\",\n",
            "  \"profile\": \"ineligible\",\n  \"profile\": \"ineligible\",\n",
        )
    }

    fn fn_mutate_manifest_extra(document: &str) -> String {
        document.replace(
            "  \"files\": {\n",
            "  \"unexpected\": true,\n  \"files\": {\n",
        )
    }

    fn fn_mutate_manifest_wrong_type(document: &str) -> String {
        document.replace("  \"schemaVersion\": 5,", "  \"schemaVersion\": \"5\",")
    }

    fn fn_mutate_manifest_epoch(document: &str) -> String {
        let original = sha256_bytes(b"epoch").hex();
        document.replace(&original, &sha256_bytes(b"forged-epoch").hex())
    }

    #[test]
    fn bundle_manifest_rejects_tampering_and_extra_files() {
        let root = root("tamper");
        let case = DifferentialCase {
            id: "layout".into(),
            ..DifferentialCase::default()
        };
        let directory = retain_observation_bundle(&root, &case, &report()).unwrap();
        fs::write(directory.join("main.hell"), b"tampered\n").unwrap();
        assert!(verify_observation_bundle(&directory).is_err());
        fs::write(directory.join("main.hell"), case.source.as_bytes()).unwrap();
        fs::write(directory.join("extra.bin"), b"extra").unwrap();
        assert!(verify_observation_bundle(&directory).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn semantic_fuzz_target_bundle_manifest_calls_the_exact_production_verifier() {
        let root = root("bundle-manifest-semantic-fuzz");
        let case = DifferentialCase {
            id: "bundle-manifest-semantic-fuzz".into(),
            ..DifferentialCase::default()
        };
        let mut retained = report();
        retained.oracle.case_id = Arc::clone(&case.id);
        retained.candidate.case_id = Arc::clone(&case.id);
        let directory = retain_observation_bundle(&root, &case, &retained).unwrap();
        let manifest_path = directory.join("bundle-manifest.json");
        let canonical = fs::read(&manifest_path).unwrap();
        assert!(verify_observation_bundle(&directory).is_ok());
        for index in (0..canonical.len()).step_by(canonical.len().div_ceil(256)) {
            let mut mutated = canonical.clone();
            mutated[index] = 0;
            fs::write(&manifest_path, &mutated).unwrap();
            rewrite_manifest_digest(&directory, std::str::from_utf8(&mutated).unwrap());
            let outcome = std::panic::catch_unwind(|| verify_observation_bundle(&directory));
            assert!(outcome.is_ok(), "bundle verifier panicked at byte {index}");
            assert!(
                outcome.unwrap().is_err(),
                "bundle verifier accepted a NUL at byte {index}"
            );
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn old_flat_layout_is_rejected_instead_of_reused() {
        let root = root("flat");
        let directory = root.join("layout");
        fs::create_dir(&directory).unwrap();
        fs::write(directory.join("oracle.json"), b"{}\n").unwrap();
        let case = DifferentialCase {
            id: "layout".into(),
            ..DifferentialCase::default()
        };
        assert!(retain_observation_bundle(&root, &case, &report()).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn semantic_revalidation_rejects_rehashed_normalizer_and_resource_tampering() {
        for (name, relative, original, replacement) in [
            (
                "normalizer",
                "candidate/observation.json",
                "\"harnessNormalizers\": [\"diagnostic-sandbox-path-v1\"]",
                "\"harnessNormalizers\": []",
            ),
            (
                "resource",
                "candidate/resource-audit.json",
                "\"handles\": 0",
                "\"handles\": 1",
            ),
        ] {
            let root = root(name);
            let case = DifferentialCase {
                id: "layout".into(),
                ..DifferentialCase::default()
            };
            let directory = retain_observation_bundle(&root, &case, &report()).unwrap();
            let path = directory.join(relative);
            let contents = fs::read_to_string(&path).unwrap();
            fs::write(&path, contents.replace(original, replacement)).unwrap();
            fs::remove_file(directory.join("bundle-manifest.json")).unwrap();
            fs::remove_file(directory.join("bundle-manifest.sha256")).unwrap();
            write_bundle_manifest(&directory, &case, sha256_bytes(b"epoch")).unwrap();
            assert!(verify_observation_bundle(&directory).is_ok());
            assert!(verify_observation_bundle_for_case(&directory, &case).is_err());
            fs::remove_dir_all(root).unwrap();
        }
    }

    fn claim_eligible_case() -> DifferentialCase {
        let source = DifferentialCase::default().source;
        let builtin = hell_builtins::registry()[0];
        DifferentialCase {
            id: "layout".into(),
            source: source.clone(),
            claim_evidence: Some(ClaimEvidenceDescriptor {
                schema_version: 8,
                profile: hell_builtins::ExecutionProfile::Upstream,
                harness_normalizers: vec![NormalizerId::DiagnosticSandboxPathV1],
                claim_normalizers: Vec::new(),
                targets: vec![crate::EvidenceTarget::new(
                    builtin.name,
                    hell_builtins::CompatibilityDimension::ResourceBehavior,
                )],
                semantic_targets: vec![crate::EvidenceTargetV2::new(
                    builtin.name,
                    hell_builtins::CompatibilityDimension::ResourceBehavior,
                    vec![crate::ObligationId("cleanup-trace".into())],
                    CausalSignal::ResourceLifecycle,
                    vec![hell_builtins::ClaimPlatform::All],
                )],
                callback_contracts: Vec::new(),
                review_state: crate::CaseReviewState::Reviewed,
                review_statement: "full-trace-review".into(),
                source_sha256: sha256_bytes(source.as_bytes()),
            }),
            ..DifferentialCase::default()
        }
    }

    fn full_trace_report() -> DifferentialReport {
        let mut report = report();
        let builtin = hell_builtins::registry()[0].id;
        let typed_result = "{\"type\":\"Bool\",\"value\":true}";
        report.candidate.semantic = Some(crate::SemanticObservation {
            typed_result_sha256: Some(sha256_bytes(typed_result.as_bytes())),
            typed_result_builtin: Some(builtin),
            typed_result_canonical: Some(typed_result.into()),
            causal_event_order: full_trace_causal_order(),
            force_trace: vec![
                LogicalTraceEvent::ForceBuiltinArgument {
                    builtin,
                    argument: 0,
                },
                LogicalTraceEvent::CompleteThunk {
                    label: "conditional-selection".into(),
                    outcome: "value".into(),
                    error_code: None,
                },
            ],
            effect_trace: vec![
                LogicalTraceEvent::HostEffect {
                    builtin,
                    owner_task: Some(1),
                    sequence: 1,
                    parent_sequence: None,
                    effect: "started".into(),
                },
                LogicalTraceEvent::HostEffect {
                    builtin,
                    owner_task: Some(1),
                    sequence: 1,
                    parent_sequence: None,
                    effect: "completed".into(),
                },
            ],
            task_trace: vec![
                LogicalTraceEvent::TaskEvent {
                    task: 1,
                    builtin,
                    event: "started".into(),
                },
                LogicalTraceEvent::TaskEvent {
                    task: 1,
                    builtin,
                    event: "completed".into(),
                },
            ],
            resource_trace: vec![
                LogicalTraceEvent::ResourceEvent {
                    resource: 1,
                    builtin,
                    owner_task: Some(1),
                    event: crate::ResourceEventKind::Acquire,
                },
                LogicalTraceEvent::ResourceEvent {
                    resource: 1,
                    builtin,
                    owner_task: Some(1),
                    event: crate::ResourceEventKind::Close,
                },
            ],
            obligation_trace: vec![crate::ObligationTraceEvent {
                builtin,
                instance_target: None,
                instance_premises: Vec::new(),
                owner_task: Some(1),
                sequence: 1,
                parent_sequence: None,
                outcome: "value".into(),
                nested_adapters: 0,
                materialized_before: 0,
                materialized_after: 1,
                callbacks: Vec::new(),
                comparators: Vec::new(),
            }],
            coverage: full_trace_coverage(builtin),
        });
        report
    }

    fn full_trace_causal_order() -> Vec<(u64, Arc<str>)> {
        [
            "parsed-builtin",
            "resolved-builtin",
            "specialized-builtin",
            "entered-adapter",
            "forced-argument",
            "typed-result",
            "effect-event",
            "effect-event",
            "task-event",
            "task-event",
            "presentation-field",
            "resource-event",
            "resource-event",
            "obligation-event",
        ]
        .into_iter()
        .enumerate()
        .map(|(index, kind)| (u64::try_from(index + 1).unwrap(), Arc::from(kind)))
        .collect()
    }

    #[test]
    fn regression_descriptor_is_oracle_derived_retained_and_replayed() {
        let root = root("regression-oracle-descriptor");
        let case = DifferentialCase {
            id: "layout".into(),
            source: "main = IO.print True\n".into(),
            ..DifferentialCase::default()
        };
        let mut retained = full_trace_report();
        retained.oracle.stdout = BoundedCapture::from_bytes(b"oracle\n".to_vec());
        retained.candidate.stdout = BoundedCapture::from_bytes(b"candidate\n".to_vec());
        retained.mismatches = crate::compare(&retained.oracle, &retained.candidate);
        let (directory, reviewed) = retain_reviewed_regression_bundle(
            &root,
            &case,
            &retained,
            "reviewed oracle-derived regression descriptor",
        )
        .unwrap();
        verify_regression_observation_bundle_for_case(&directory, &reviewed).unwrap();
        let reconstructed = reviewed_regression_case_from_bundle(
            &directory,
            &case,
            "reviewed oracle-derived regression descriptor",
        )
        .unwrap();
        assert_eq!(reconstructed.claim_evidence, reviewed.claim_evidence);
        let descriptor_path = directory.join("case.toml");
        let descriptor = fs::read_to_string(&descriptor_path).unwrap();
        assert!(descriptor.contains("[[semantic_targets]]"));
        assert!(descriptor.contains("expected_typed_result_sha256"));
        fs::write(
            &descriptor_path,
            descriptor.replace(
                "reviewed oracle-derived regression descriptor",
                "substituted regression descriptor",
            ),
        )
        .unwrap();
        rewrite_bundle_file_digest(&directory, "case.toml");
        assert!(verify_regression_observation_bundle_for_case(&directory, &reviewed).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    fn full_trace_coverage(builtin: hell_builtins::BuiltinId) -> Vec<CoverageEvent> {
        vec![
            CoverageEvent::ParsedBuiltin(builtin),
            CoverageEvent::ResolvedBuiltin(builtin),
            CoverageEvent::SpecializedBuiltin(builtin),
            CoverageEvent::EnteredAdapter(builtin),
            CoverageEvent::ForcedArgument(builtin, 0),
            CoverageEvent::ExecutedEffect(builtin, "started".into()),
            CoverageEvent::ExecutedEffect(builtin, "completed".into()),
            CoverageEvent::TaskEvent(builtin, "started".into()),
            CoverageEvent::TaskEvent(builtin, "completed".into()),
            CoverageEvent::PresentedField(builtin, "rendered-output".into()),
            CoverageEvent::AcquiredResource(builtin, "acquire".into()),
            CoverageEvent::AcquiredResource(builtin, "close".into()),
        ]
    }

    #[test]
    fn claim_eligible_bundle_revalidates_every_trace_v3_causal_class() {
        let root = root("full-trace");
        let case = claim_eligible_case();
        let directory = retain_observation_bundle(&root, &case, &full_trace_report()).unwrap();
        verify_observation_bundle_for_case(&directory, &case).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    fn verified_profile_fixture(
        case: &DifferentialCase,
        observation: Observation,
    ) -> VerifiedProfileObservation {
        let source_sha256 = sha256_bytes(case.source.as_bytes());
        let execution_input_sha256 = sha256_bytes(execution_input_json(case).unwrap().as_bytes());
        let executable_sha256 = observation.identity.sha256;
        let profile = case.claim_evidence.as_ref().unwrap().profile;
        VerifiedProfileObservation {
            profile,
            executable_sha256,
            source_sha256,
            execution_input_sha256,
            invocation_sha256: verified_profile_invocation_sha256(
                profile,
                executable_sha256,
                source_sha256,
                execution_input_sha256,
            ),
            observation,
        }
    }

    fn rehash_profile_package(directory: &Path) {
        fs::remove_file(directory.join("profile-manifest.json")).unwrap();
        fs::remove_file(directory.join("profile-manifest.sha256")).unwrap();
        write_profile_manifest(directory).unwrap();
    }

    #[test]
    fn retained_profile_observation_round_trips_and_rejects_rehashed_substitutions() {
        let case = claim_eligible_case();
        let candidate = full_trace_report().candidate;
        let verified = verified_profile_fixture(&case, candidate.clone());
        assert_profile_roundtrip(&case, &verified);
        assert_profile_identity_substitutions(&case, &candidate, &verified);
        assert_profile_observation_substitution(&case, &candidate, &verified);
        assert_profile_inventory_substitutions(&case, &candidate, &verified);
    }

    #[test]
    fn retained_alternate_executable_is_distinct_and_bound_to_upstream_authority() {
        let case = claim_eligible_case();
        let root = root("alternate-executable");
        let report = full_trace_report();
        let bundle = retain_observation_bundle(&root.join("upstream"), &case, &report).unwrap();
        let prototype_sha256 = sha256_bytes(b"prototype executable");
        let mut prototype = report.candidate.clone();
        prototype.identity.path = PathBuf::from("prototype-hell");
        prototype.identity.sha256 = prototype_sha256;
        let verified = verified_profile_fixture(&case, prototype);
        let directory = root.join("prototype");
        let retained = retain_verified_profile_observation(&directory, &case, &verified).unwrap();
        assert_eq!(
            verify_retained_alternate_executable_observation_against_bundle(
                &directory,
                &case,
                &bundle,
                hell_builtins::ExecutionProfile::Upstream,
                prototype_sha256,
            )
            .unwrap(),
            retained
        );
        assert_eq!(
            classify_retained_alternate_executable_observation_against_oracle(
                &directory,
                &case,
                &bundle,
                hell_builtins::ExecutionProfile::Upstream,
                prototype_sha256,
            )
            .unwrap(),
            RetainedObservationClassification::Exact
        );
        assert!(
            verify_retained_profile_observation_against_bundle(
                &directory,
                &case,
                &bundle,
                hell_builtins::ExecutionProfile::Upstream,
            )
            .is_err()
        );
        assert!(
            verify_retained_alternate_executable_observation_against_bundle(
                &directory,
                &case,
                &bundle,
                hell_builtins::ExecutionProfile::Upstream,
                sha256_bytes(b"substituted prototype"),
            )
            .is_err()
        );

        let mut substituted_input = case.clone();
        substituted_input.stdin = b"substituted input".to_vec();
        assert!(
            verify_retained_alternate_executable_observation_against_bundle(
                &directory,
                &substituted_input,
                &bundle,
                hell_builtins::ExecutionProfile::Upstream,
                prototype_sha256,
            )
            .is_err()
        );

        let reused_path = root.join("reused-path");
        let mut reused = verified.clone();
        reused.observation.identity.path = report.candidate.identity.path.clone();
        retain_verified_profile_observation(&reused_path, &case, &reused).unwrap();
        assert!(
            verify_retained_alternate_executable_observation_against_bundle(
                &reused_path,
                &case,
                &bundle,
                hell_builtins::ExecutionProfile::Upstream,
                prototype_sha256,
            )
            .is_err()
        );

        fs::write(
            bundle.join("oracle").join("stdout.bin"),
            b"substituted oracle",
        )
        .unwrap();
        fs::remove_file(bundle.join("bundle-manifest.json")).unwrap();
        fs::remove_file(bundle.join("bundle-manifest.sha256")).unwrap();
        assert!(write_bundle_manifest(&bundle, &case, sha256_bytes(b"epoch")).is_err());
        assert!(
            classify_retained_alternate_executable_observation_against_oracle(
                &directory,
                &case,
                &bundle,
                hell_builtins::ExecutionProfile::Upstream,
                prototype_sha256,
            )
            .is_err()
        );
        fs::remove_dir_all(root).unwrap();
    }

    fn assert_profile_roundtrip(case: &DifferentialCase, verified: &VerifiedProfileObservation) {
        let roundtrip_root = root("profile-roundtrip");
        let bundle =
            retain_observation_bundle(&roundtrip_root.join("upstream"), case, &full_trace_report())
                .unwrap();
        let directory = roundtrip_root.join("profile");
        let retained = retain_verified_profile_observation(&directory, case, verified).unwrap();
        assert_eq!(retained.profile, hell_builtins::ExecutionProfile::Upstream);
        assert_eq!(
            verify_retained_profile_observation_against_bundle(
                &directory,
                case,
                &bundle,
                hell_builtins::ExecutionProfile::Upstream,
            )
            .unwrap(),
            retained
        );
        assert_eq!(
            classify_retained_profile_observation_against_oracle(
                &directory,
                case,
                &bundle,
                hell_builtins::ExecutionProfile::Upstream,
            )
            .unwrap(),
            RetainedObservationClassification::Exact
        );
        fs::remove_dir_all(roundtrip_root).unwrap();
    }

    fn assert_profile_identity_substitutions(
        case: &DifferentialCase,
        candidate: &Observation,
        verified: &VerifiedProfileObservation,
    ) {
        for (name, field, replacement) in [
            (
                "profile",
                "\"profile\": \"upstream\"".to_owned(),
                "\"profile\": \"sandboxed\"".to_owned(),
            ),
            (
                "executable",
                verified.executable_sha256.hex(),
                sha256_bytes(b"other executable").hex(),
            ),
            (
                "source",
                verified.source_sha256.hex(),
                sha256_bytes(b"other source").hex(),
            ),
            (
                "execution-input",
                verified.execution_input_sha256.hex(),
                sha256_bytes(b"other input").hex(),
            ),
            (
                "invocation",
                verified.invocation_sha256.hex(),
                sha256_bytes(b"other invocation").hex(),
            ),
        ] {
            let root = root(name);
            let directory = root.join("profile");
            retain_verified_profile_observation(&directory, case, verified).unwrap();
            let profile = directory.join("profile-observation.json");
            let document = fs::read_to_string(&profile).unwrap();
            let substituted = document.replacen(&field, &replacement, 1);
            assert_ne!(document, substituted, "{name}");
            fs::write(profile, substituted).unwrap();
            rehash_profile_package(&directory);
            assert!(
                verify_retained_profile_observation(
                    &directory,
                    case,
                    &candidate.identity,
                    hell_builtins::ExecutionProfile::Upstream,
                )
                .is_err(),
                "{name}"
            );
            fs::remove_dir_all(root).unwrap();
        }
    }

    fn assert_profile_observation_substitution(
        case: &DifferentialCase,
        candidate: &Observation,
        verified: &VerifiedProfileObservation,
    ) {
        let observation_root = root("profile-observation");
        let directory = observation_root.join("profile");
        retain_verified_profile_observation(&directory, case, verified).unwrap();
        let observation = directory.join("candidate").join("observation.json");
        let document = fs::read_to_string(&observation).unwrap();
        fs::write(
            &observation,
            document.replace("candidate-hell", "other-hell"),
        )
        .unwrap();
        let profile = directory.join("profile-observation.json");
        let old_observation = verified_profile_fixture(case, candidate.clone());
        let old_digest = sha256_bytes(observation_json(&old_observation.observation).as_bytes());
        let new_digest = sha256_file(&observation).unwrap();
        let profile_document = fs::read_to_string(&profile).unwrap();
        fs::write(
            &profile,
            profile_document.replace(&old_digest.hex(), &new_digest.hex()),
        )
        .unwrap();
        rehash_profile_package(&directory);
        assert!(
            verify_retained_profile_observation(
                &directory,
                case,
                &candidate.identity,
                hell_builtins::ExecutionProfile::Upstream,
            )
            .is_err()
        );
        fs::remove_dir_all(observation_root).unwrap();
    }

    fn assert_profile_inventory_substitutions(
        case: &DifferentialCase,
        candidate: &Observation,
        verified: &VerifiedProfileObservation,
    ) {
        for name in ["missing", "extra"] {
            let root = root(name);
            let directory = root.join("profile");
            retain_verified_profile_observation(&directory, case, verified).unwrap();
            if name == "missing" {
                fs::remove_file(directory.join("candidate").join("stdout.bin")).unwrap();
            } else {
                fs::write(directory.join("unexpected.bin"), b"extra").unwrap();
            }
            assert!(
                verify_retained_profile_observation(
                    &directory,
                    case,
                    &candidate.identity,
                    hell_builtins::ExecutionProfile::Upstream,
                )
                .is_err(),
                "{name}"
            );
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn runtime_scope_binding_rejects_wrong_case_missing_participants_and_conflation() {
        let list_take = hell_builtins::lookup("List.take").unwrap();
        let boundary = crate::EvidenceTargetV2::new(
            list_take.name,
            hell_builtins::CompatibilityDimension::PureRuntime,
            vec![crate::ObligationId("adapter-success".into())],
            CausalSignal::RuntimeAdapter,
            vec![hell_builtins::ClaimPlatform::Linux],
        )
        .with_runtime_scope(["zero-count"], std::iter::empty::<&str>());
        let matching = DifferentialCase {
            id: "list-take-boundary-zero-count".into(),
            ..DifferentialCase::default()
        };
        let entered = [CoverageEvent::EnteredAdapter(list_take.id)];
        let value_event = crate::ObligationTraceEvent {
            builtin: list_take.id,
            instance_target: None,
            instance_premises: Vec::new(),
            owner_task: None,
            sequence: 1,
            parent_sequence: None,
            outcome: "value".into(),
            nested_adapters: 0,
            materialized_before: 0,
            materialized_after: 0,
            callbacks: Vec::new(),
            comparators: Vec::new(),
        };
        let success = "  \"status\": {\"success\": true,\n";
        validate_runtime_scope_binding(
            &matching,
            &boundary,
            success,
            &entered,
            std::slice::from_ref(&value_event),
            Path::new("."),
            None,
        )
        .unwrap();
        let wrong_case = DifferentialCase {
            id: "list-take-boundary-negative-count".into(),
            ..DifferentialCase::default()
        };
        assert!(
            validate_runtime_scope_binding(
                &wrong_case,
                &boundary,
                success,
                &entered,
                std::slice::from_ref(&value_event),
                Path::new("."),
                None,
            )
            .is_err()
        );
        assert!(
            validate_runtime_scope_binding(
                &matching,
                &boundary,
                success,
                &[],
                std::slice::from_ref(&value_event),
                Path::new("."),
                None,
            )
            .is_err()
        );
        assert!(
            validate_runtime_scope_binding(
                &matching,
                &boundary,
                "  \"status\": {\"success\": false,\n",
                &entered,
                std::slice::from_ref(&value_event),
                Path::new("."),
                None,
            )
            .is_err()
        );

        let conflated = boundary
            .clone()
            .with_runtime_scope(["zero-count", "negative-count"], std::iter::empty::<&str>());
        assert!(
            validate_runtime_scope_binding(
                &matching,
                &conflated,
                success,
                &entered,
                std::slice::from_ref(&value_event),
                Path::new("."),
                None,
            )
            .is_err()
        );
    }

    #[test]
    fn runtime_scope_binding_requires_every_interaction_participant() {
        let interaction = crate::mandatory_runtime_interactions()
            .into_iter()
            .find(|requirement| requirement.id.as_ref() == "list-laziness-error")
            .unwrap();
        let interaction_case = DifferentialCase {
            id: "runtime-interaction-list-laziness-error".into(),
            ..DifferentialCase::default()
        };
        let participant = crate::EvidenceTargetV2::new(
            "List.take",
            hell_builtins::CompatibilityDimension::PureRuntime,
            vec![crate::ObligationId("adapter-success".into())],
            CausalSignal::RuntimeAdapter,
            vec![hell_builtins::ClaimPlatform::Linux],
        )
        .with_runtime_scope(std::iter::empty::<&str>(), [interaction.id]);
        let participants = interaction
            .builtins
            .iter()
            .map(|builtin| {
                CoverageEvent::EnteredAdapter(hell_builtins::lookup(builtin).unwrap().id)
            })
            .collect::<Vec<_>>();
        validate_runtime_scope_binding(
            &interaction_case,
            &participant,
            "",
            &participants,
            &[],
            Path::new("."),
            None,
        )
        .unwrap();
        assert!(
            validate_runtime_scope_binding(
                &interaction_case,
                &participant,
                "",
                &participants[..1],
                &[],
                Path::new("."),
                None,
            )
            .is_err()
        );
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn http_stream_interaction_rejects_target_omission_and_resource_audit_substitution() {
        let mut cases = crate::committed_differential_cases();
        bind_test_process_helpers(&mut cases);
        let case = runtime_case(&cases, "runtime-interaction-http-stream-disconnect");
        let source_root = root("http-stream-target-omission-source");
        let (success, mut semantic, stdout) =
            execute_runtime_interaction_with_stdout(case, &source_root);
        assert!(success);
        let response_stream = hell_builtins::lookup("Http.responseStream")
            .expect("HTTP stream target")
            .id;
        semantic.coverage.retain(|event| {
            !matches!(event, CoverageEvent::EnteredAdapter(builtin) if *builtin == response_stream)
        });
        assert_rehashed_runtime_semantic_rejected(
            case,
            semantic,
            &stdout,
            false,
            "http-stream-target-omission",
        );
        fs::remove_dir_all(source_root).unwrap();

        let (bundle_root, directory) = retain_executed_runtime_case(case, "http-resource-audit");
        verify_observation_bundle_for_case(&directory, case).expect("HTTP interaction baseline");
        let forged = resource_audit_json(&ResourceAudit {
            http_bodies: 1,
            ..ResourceAudit::default()
        });
        fs::write(directory.join("candidate/resource-audit.json"), &forged).unwrap();
        rehash_runtime_bundle(&directory, case);
        assert!(verify_observation_bundle_for_case(&directory, case).is_err());
        fs::remove_dir_all(bundle_root).unwrap();
    }

    #[test]
    fn runtime_boundary_rejects_relabelled_typed_result_expectation() {
        let builtin = hell_builtins::lookup("Double.plus").unwrap();
        let canonical = "{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",\"value\":{\"type\":\"Double\",\"ieee754Bits\":\"0000000000000000\"}}";
        let target = crate::EvidenceTargetV2::new(
            builtin.name,
            hell_builtins::CompatibilityDimension::PureRuntime,
            vec![crate::ObligationId("typed-result".into())],
            CausalSignal::RuntimeAdapter,
            vec![hell_builtins::ClaimPlatform::Linux],
        )
        .with_runtime_scope(["zero-value"], std::iter::empty::<&str>())
        .with_expected_typed_result(canonical);
        let case = DifferentialCase {
            id: "double-plus-boundary-zero-value".into(),
            ..DifferentialCase::default()
        };
        let event = crate::ObligationTraceEvent {
            builtin: builtin.id,
            instance_target: None,
            instance_premises: Vec::new(),
            owner_task: None,
            sequence: 1,
            parent_sequence: None,
            outcome: "value".into(),
            nested_adapters: 0,
            materialized_before: 0,
            materialized_after: 0,
            callbacks: Vec::new(),
            comparators: Vec::new(),
        };
        let document = format!(
            "  \"status\": {{\"success\": true,\n  \"semanticTypedResultSha256\": \"{}\",\n",
            sha256_bytes(canonical.as_bytes()).hex()
        );
        validate_runtime_scope_binding(
            &case,
            &target,
            &document,
            &[CoverageEvent::EnteredAdapter(builtin.id)],
            std::slice::from_ref(&event),
            Path::new("."),
            None,
        )
        .unwrap();
        let relabelled = document.replace(
            &sha256_bytes(canonical.as_bytes()).hex(),
            &sha256_bytes(b"positive-value").hex(),
        );
        assert!(
            validate_runtime_scope_binding(
                &case,
                &target,
                &relabelled,
                &[CoverageEvent::EnteredAdapter(builtin.id)],
                std::slice::from_ref(&event),
                Path::new("."),
                None,
            )
            .is_err()
        );
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn demanded_bottom_boundary_round_trips_through_the_production_bundle_gate() {
        let case = crate::committed_differential_cases()
            .into_iter()
            .find(|case| case.id.as_ref() == "list-take-boundary-bottom-after-demanded-prefix")
            .unwrap();
        let program = hell_compiler::compile_source(
            &mut hell_compiler::CompilerSession::upstream(),
            case.id.to_string(),
            case.source.to_string(),
        )
        .expect("demanded-bottom boundary compiles");
        let root = root("demanded-bottom-boundary");
        let trace = root.join("trace.json");
        let outcome = hell_runtime::run_main_with_semantic_trace(
            program,
            hell_runtime::RuntimeContext::new(Vec::new(), Vec::<u8>::new()),
            &trace,
        );
        assert!(outcome.is_err());
        let trace_bytes = fs::read(&trace).unwrap();
        let semantic = crate::parse_semantic_trace(&trace_bytes).unwrap_or_else(|error| {
            panic!(
                "demanded-bottom semantic trace was invalid: {error}; {}",
                String::from_utf8_lossy(&trace_bytes)
            )
        });
        let mut retained = report();
        for observation in [&mut retained.oracle, &mut retained.candidate] {
            observation.case_id = std::sync::Arc::clone(&case.id);
            observation.status = crate::ProcessStatus {
                success: false,
                code: Some(1),
            };
        }
        retained.candidate.semantic = Some(semantic);
        let evidence = root.join("evidence");
        let directory = retain_observation_bundle(&evidence, &case, &retained).unwrap();
        verify_observation_bundle_for_case(&directory, &case).unwrap();

        let observation_path = directory.join("candidate").join("observation.json");
        let observation = fs::read_to_string(&observation_path).unwrap();
        fs::write(
            &observation_path,
            observation.replace("\"outcome\": \"error\"", "\"outcome\": \"value\""),
        )
        .unwrap();
        fs::remove_file(directory.join("bundle-manifest.json")).unwrap();
        fs::remove_file(directory.join("bundle-manifest.sha256")).unwrap();
        write_bundle_manifest(&directory, &case, sha256_bytes(b"epoch")).unwrap();
        assert!(verify_observation_bundle_for_case(&directory, &case).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn invalid_utf8_boundary_round_trips_through_the_production_bundle_gate() {
        let case = crate::committed_differential_cases()
            .into_iter()
            .find(|case| case.id.as_ref() == "text-decodeutf8-boundary-invalid-encoding")
            .expect("committed Text.decodeUtf8 invalid-encoding case");
        assert_eq!(case.stdin, [0xff, b'A']);
        let root = root("text-decodeutf8-invalid-boundary");
        let (success, semantic, stdout) = execute_runtime_interaction_with_stdout(&case, &root);
        assert!(!success);
        assert!(stdout.is_empty());

        let mut retained = report();
        for observation in [&mut retained.oracle, &mut retained.candidate] {
            observation.case_id = std::sync::Arc::clone(&case.id);
            observation.status = crate::ProcessStatus {
                success: false,
                code: Some(1),
            };
            observation.stdout = BoundedCapture::from_bytes(stdout.clone());
        }
        retained.candidate.semantic = Some(semantic);
        let evidence = root.join("evidence");
        let directory = retain_observation_bundle(&evidence, &case, &retained).unwrap();
        verify_observation_bundle_for_case(&directory, &case).unwrap();

        let observation_path = directory.join("candidate").join("observation.json");
        let observation = fs::read_to_string(&observation_path).unwrap();
        assert!(observation.contains("\"outcome\": \"error\""));
        fs::write(
            &observation_path,
            observation.replace("\"outcome\": \"error\"", "\"outcome\": \"value\""),
        )
        .unwrap();
        fs::remove_file(directory.join("bundle-manifest.json")).unwrap();
        fs::remove_file(directory.join("bundle-manifest.sha256")).unwrap();
        write_bundle_manifest(&directory, &case, sha256_bytes(b"epoch")).unwrap();
        assert!(verify_observation_bundle_for_case(&directory, &case).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn deferred_invalid_utf8_effect_failure_is_required_after_rehash() {
        let case = crate::committed_differential_cases()
            .into_iter()
            .find(|case| case.id.as_ref() == "text-getcontents-boundary-invalid-encoding")
            .expect("committed Text.getContents invalid-encoding case");
        let root = root("text-getcontents-invalid-effect");
        let (success, semantic, stdout) = execute_runtime_interaction_with_stdout(&case, &root);
        assert!(!success);
        assert!(stdout.is_empty());
        let mut retained = report();
        for observation in [&mut retained.oracle, &mut retained.candidate] {
            observation.case_id = Arc::clone(&case.id);
            observation.status = crate::ProcessStatus {
                success: false,
                code: Some(1),
            };
            observation.stdout = BoundedCapture::from_bytes(stdout.clone());
        }
        retained.candidate.semantic = Some(semantic);
        let directory =
            retain_observation_bundle(&root.join("evidence"), &case, &retained).unwrap();
        verify_observation_bundle_for_case(&directory, &case).unwrap();

        let observation_path = directory.join("candidate").join("observation.json");
        let observation = fs::read_to_string(&observation_path).unwrap();
        assert!(observation.contains("\"effect\": \"failed\""));
        fs::write(
            &observation_path,
            observation.replace("\"effect\": \"failed\"", "\"effect\": \"completed\""),
        )
        .unwrap();
        fs::remove_file(directory.join("bundle-manifest.json")).unwrap();
        fs::remove_file(directory.join("bundle-manifest.sha256")).unwrap();
        write_bundle_manifest(&directory, &case, sha256_bytes(b"epoch")).unwrap();
        assert!(verify_observation_bundle_for_case(&directory, &case).is_err());
        fs::remove_dir_all(root).unwrap();
    }
    #[cfg(feature = "compat-tracing")]
    #[derive(Clone, Default)]
    struct SharedOutput(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    #[cfg(feature = "compat-tracing")]
    impl std::io::Write for SharedOutput {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .map_err(|_| std::io::Error::other("shared output mutex was poisoned"))?
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[cfg(feature = "compat-tracing")]
    impl SharedOutput {
        fn bytes(&self) -> Vec<u8> {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn execute_runtime_interaction(
        case: &crate::DifferentialCase,
        root: &Path,
    ) -> (bool, crate::SemanticObservation) {
        let (success, semantic, _) = execute_runtime_interaction_with_stdout(case, root);
        (success, semantic)
    }

    #[cfg(feature = "compat-tracing")]
    fn execute_runtime_interaction_with_stdout(
        case: &crate::DifferentialCase,
        root: &Path,
    ) -> (bool, crate::SemanticObservation, Vec<u8>) {
        let (runtime_success, _, semantic, stdout, _) =
            execute_runtime_interaction_with_status(case, root);
        (runtime_success, semantic, stdout)
    }

    #[cfg(feature = "compat-tracing")]
    fn execute_runtime_interaction_with_status(
        case: &crate::DifferentialCase,
        root: &Path,
    ) -> (
        bool,
        crate::ProcessStatus,
        crate::SemanticObservation,
        Vec<u8>,
        Vec<u8>,
    ) {
        let profile = case
            .claim_evidence
            .as_ref()
            .map_or(hell_builtins::ExecutionProfile::Upstream, |descriptor| {
                descriptor.profile
            });
        let mut compiler = match profile {
            hell_builtins::ExecutionProfile::Upstream => hell_compiler::CompilerSession::upstream(),
            hell_builtins::ExecutionProfile::Sandboxed => hell_compiler::CompilerSession::default(),
        };
        let program = hell_compiler::compile_source(
            &mut compiler,
            case.id.to_string(),
            case.source.to_string(),
        )
        .unwrap_or_else(|error| {
            panic!("{} runtime interaction did not compile: {error:?}", case.id)
        });
        let trace = root.join(format!("{}.json", case.id));
        let arguments = runtime_interaction_arguments(case);
        let stdout = SharedOutput::default();
        let stderr = SharedOutput::default();
        let environment = runtime_interaction_environment(case);
        let mut context = hell_runtime::RuntimeContext::with_host_capabilities(
            arguments,
            environment,
            stdout.clone(),
            root.to_path_buf(),
            true,
            true,
        );
        if profile == hell_builtins::ExecutionProfile::Sandboxed {
            context = context.with_policy(hell_runtime::policy::RuntimePolicy::sandboxed());
        }
        let context = context
            .with_stdin(std::io::Cursor::new(case.stdin.clone()))
            .with_stderr(stderr.clone());
        let typed_target = crate::typed_result_target(case)
            .unwrap_or_else(|error| panic!("{} typed-result target is invalid: {error}", case.id));
        let outcome = if let Some(target) = typed_target {
            if let Some(instance) = target.instance {
                hell_runtime::run_main_with_semantic_trace_target_instance(
                    program,
                    context,
                    &trace,
                    target.builtin,
                    instance,
                )
            } else {
                hell_runtime::run_main_with_semantic_trace_target(
                    program,
                    context,
                    &trace,
                    target.builtin,
                )
            }
        } else {
            hell_runtime::run_main_with_semantic_trace(program, context, &trace)
        };
        retain_runtime_error_presentation(&outcome, &stderr);
        let status = match &outcome {
            Ok(()) => crate::ProcessStatus {
                success: true,
                code: Some(0),
            },
            Err(error) => match error.kind {
                hell_runtime::RuntimeErrorKind::Exit(code) => crate::ProcessStatus {
                    success: code == 0,
                    code: Some(code),
                },
                _ => crate::ProcessStatus {
                    success: false,
                    code: Some(1),
                },
            },
        };
        let runtime_success = outcome.is_ok();
        let expected_failure = runtime_case_expects_failure(case);
        assert_eq!(
            runtime_success, !expected_failure,
            "{}: {outcome:?}",
            case.id
        );
        let trace_bytes = fs::read(&trace).unwrap_or_else(|error| {
            panic!(
                "{} did not retain its semantic trace ({error}): {outcome:?}",
                case.id
            )
        });
        let semantic = crate::parse_semantic_trace(&trace_bytes)
            .unwrap_or_else(|error| panic!("{} has an invalid semantic trace: {error}", case.id));
        assert_http_disconnect_trace(case, &semantic);
        (
            runtime_success,
            status,
            semantic,
            stdout.bytes(),
            stderr.bytes(),
        )
    }

    #[cfg(feature = "compat-tracing")]
    fn retain_runtime_error_presentation(
        outcome: &hell_runtime::RuntimeResult<()>,
        stderr: &SharedOutput,
    ) {
        let Err(error) = outcome else {
            return;
        };
        if matches!(error.kind, hell_runtime::RuntimeErrorKind::Exit(_)) {
            return;
        }
        let mut retained_stderr = stderr.clone();
        std::io::Write::write_all(&mut retained_stderr, format!("{error}\n").as_bytes())
            .expect("retain runtime error presentation");
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_http_disconnect_trace(
        case: &crate::DifferentialCase,
        semantic: &crate::SemanticObservation,
    ) {
        if !case.id.ends_with("http-stream-disconnect") {
            return;
        }
        let http_run = hell_builtins::lookup("Http.run")
            .expect("HTTP interaction target")
            .id;
        assert!(semantic.task_trace.iter().any(|event| matches!(
            event,
            crate::LogicalTraceEvent::TaskEvent { event, .. } if event.as_ref() == "cancelled"
        )));
        assert!(semantic.effect_trace.iter().any(|event| matches!(
            event,
            crate::LogicalTraceEvent::HostEffect { builtin, effect, .. }
                if *builtin == http_run && effect.as_ref() == "completed"
        )));
        assert!(!semantic.effect_trace.iter().any(|event| matches!(
            event,
            crate::LogicalTraceEvent::HostEffect { builtin, effect, .. }
                if *builtin == http_run && effect.as_ref() == "failed"
        )));
    }

    #[cfg(feature = "compat-tracing")]
    fn runtime_interaction_arguments(case: &crate::DifferentialCase) -> Vec<std::sync::Arc<str>> {
        if case.environment_profile == crate::EnvironmentProfile::ProcessCapable {
            let helper = case
                .process_helper_directory
                .as_ref()
                .expect("process-capable case has a helper directory")
                .join(format!("hell-test-helper{}", std::env::consts::EXE_SUFFIX));
            return vec![std::sync::Arc::<str>::from(
                helper.to_str().expect("helper path is UTF-8"),
            )];
        }
        case.arguments
            .iter()
            .map(|argument| {
                std::sync::Arc::<str>::from(argument.to_str().expect("committed argument is UTF-8"))
            })
            .collect()
    }

    #[cfg(feature = "compat-tracing")]
    fn runtime_interaction_environment(
        case: &crate::DifferentialCase,
    ) -> Vec<(std::sync::Arc<str>, std::sync::Arc<str>)> {
        case.environment
            .iter()
            .map(|(name, value)| {
                (
                    std::sync::Arc::<str>::from(
                        name.to_str().expect("committed environment name is UTF-8"),
                    ),
                    std::sync::Arc::<str>::from(
                        value
                            .to_str()
                            .expect("committed environment value is UTF-8"),
                    ),
                )
            })
            .collect()
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_runtime_typed_substitution_rejected(
        case_id: &str,
        original: &str,
        replacement: &str,
    ) {
        let mut case = crate::committed_differential_cases()
            .into_iter()
            .find(|case| case.id.as_ref() == case_id)
            .unwrap_or_else(|| panic!("missing typed case {case_id}"));
        if case.environment_profile == crate::EnvironmentProfile::ProcessCapable {
            bind_test_process_helpers(std::slice::from_mut(&mut case));
        }
        let root = root(case_id);
        let (success, status, semantic, stdout, stderr) =
            execute_runtime_interaction_with_status(&case, &root);
        assert_eq!(success, !runtime_case_expects_failure(&case));
        let mut retained = report();
        for observation in [&mut retained.oracle, &mut retained.candidate] {
            observation.case_id = case.id.clone();
            observation.environment_profile = case.environment_profile;
            observation.process_helper_sha256 = case.process_helper_sha256;
            observation.stdout = BoundedCapture::from_bytes(stdout.clone());
            observation.raw_stderr = BoundedCapture::from_bytes(stderr.clone());
            observation.claim_input_stderr = BoundedCapture::from_bytes(stderr.clone());
            observation.stderr = BoundedCapture::from_bytes(stderr.clone());
            observation.status = status.clone();
        }
        retained.candidate.semantic = Some(semantic);
        let directory =
            retain_observation_bundle(&root.join("evidence"), &case, &retained).unwrap();
        verify_observation_bundle_for_case(&directory, &case).unwrap();
        let path = directory
            .join("candidate")
            .join("semantic-typed-result.json");
        let typed = fs::read_to_string(&path).unwrap_or_else(|error| {
            panic!(
                "typed result for {case_id} was not retained at {}: {error}",
                path.display()
            )
        });
        assert!(
            typed.contains(original),
            "typed substitution source was not present"
        );
        assert!(
            !typed.contains(replacement),
            "typed substitution replacement was already present"
        );
        let substituted = typed.replace(original, replacement);
        assert_ne!(typed, substituted, "typed substitution did not match");
        fs::write(path, substituted).unwrap();
        fs::remove_file(directory.join("bundle-manifest.json")).unwrap();
        fs::remove_file(directory.join("bundle-manifest.sha256")).unwrap();
        write_bundle_manifest(&directory, &case, sha256_bytes(b"epoch")).unwrap();
        assert!(verify_observation_bundle_for_case(&directory, &case).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn retained_process_builder_fields_reject_rehashed_substitutions() {
        for (case_id, original, replacement) in [
            (
                "runtime-typed-process-proc",
                "\"commandHex\":\"68656c6c2d746573742d68656c706572\"",
                "\"commandHex\":\"72656c6162656c6c65642d68656c706572\"",
            ),
            (
                "runtime-typed-process-set-stdin",
                "\"stdin\":{\"type\":\"Handle\",\"kind\":\"null\"}",
                "\"stdin\":{\"type\":\"Handle\",\"kind\":\"stdin\"}",
            ),
            (
                "runtime-typed-process-set-stdout",
                "\"stdout\":{\"type\":\"Handle\",\"kind\":\"null\"}",
                "\"stdout\":{\"type\":\"Handle\",\"kind\":\"stdout\"}",
            ),
            (
                "runtime-typed-process-set-stderr",
                "\"stderr\":{\"type\":\"Handle\",\"kind\":\"null\"}",
                "\"stderr\":{\"type\":\"Handle\",\"kind\":\"stderr\"}",
            ),
            (
                "runtime-typed-process-set-working-dir",
                "\"workingDirectoryHex\":\"72657669657765642d637764\"",
                "\"workingDirectoryHex\":\"6f746865722d637764\"",
            ),
            (
                "runtime-typed-process-set-env",
                "\"environment\":[{\"nameHex\":\"4c435f414c4c\",\"valueHex\":\"43\"}]",
                "\"environment\":[{\"nameHex\":\"4c435f414c4c\",\"valueHex\":\"504f534958\"}]",
            ),
        ] {
            assert_runtime_typed_substitution_rejected(case_id, original, replacement);
        }
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn retained_environment_observations_reject_value_and_failure_substitutions() {
        let cases = crate::committed_differential_cases();
        for (case_id, forged) in [
            ("runtime-environment-get-args", b"alpha\ngamma\n".as_slice()),
            ("runtime-environment-get-env", b"forged".as_slice()),
            (
                "runtime-environment-get-environment",
                b"SECOND=two\nFIRST=one\n".as_slice(),
            ),
        ] {
            let case = cases
                .iter()
                .find(|case| case.id.as_ref() == case_id)
                .expect("environment case");
            let (root, directory) = retain_executed_runtime_case(case, case_id);
            for role in ["candidate", "oracle"] {
                fs::write(directory.join(role).join("stdout.bin"), forged).unwrap();
            }
            rehash_runtime_bundle(&directory, case);
            assert!(verify_observation_bundle_for_case(&directory, case).is_err());
            fs::remove_dir_all(root).unwrap();
        }
        assert_runtime_failed_effect_substitution_rejected(
            &cases,
            "runtime-environment-get-env-missing",
        );
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn retained_directory_operations_reject_postcondition_and_failure_substitutions() {
        let cases = crate::committed_differential_cases();
        for (case_id, forged) in [
            ("runtime-directory-copy-file-success", b"abd".as_slice()),
            (
                "runtime-directory-create-directory-success",
                b"False\n".as_slice(),
            ),
            (
                "runtime-directory-create-directory-if-missing-success",
                b"False\n".as_slice(),
            ),
            ("runtime-directory-get-file-size-success", b"4\n".as_slice()),
            (
                "runtime-directory-remove-file-success",
                b"True\n".as_slice(),
            ),
            ("runtime-directory-rename-file-success", b"abd".as_slice()),
            (
                "runtime-directory-list-directory-success",
                b"[]\n".as_slice(),
            ),
            (
                "runtime-directory-remove-directory-success",
                b"True\n".as_slice(),
            ),
            (
                "runtime-directory-set-current-directory-success",
                b"False\n".as_slice(),
            ),
            ("runtime-directory-exists-true", b"False\n".as_slice()),
            ("runtime-directory-exists-false", b"True\n".as_slice()),
            ("runtime-file-exists-true", b"False\n".as_slice()),
            ("runtime-file-exists-false", b"True\n".as_slice()),
            ("runtime-current-directory-roundtrip", b"forged".as_slice()),
            (
                "runtime-current-directory-upstream-available",
                b"forged".as_slice(),
            ),
            (
                "runtime-directory-exists-invalid-path-false",
                b"True\n".as_slice(),
            ),
            (
                "runtime-directory-file-exists-invalid-path-false",
                b"True\n".as_slice(),
            ),
            (
                "runtime-directory-get-home-platform-fallback",
                b"True\n".as_slice(),
            ),
        ] {
            let case = cases
                .iter()
                .find(|case| case.id.as_ref() == case_id)
                .unwrap_or_else(|| panic!("missing directory success case {case_id}"));
            let (root, directory) = retain_executed_runtime_case(case, case_id);
            for role in ["candidate", "oracle"] {
                fs::write(directory.join(role).join("stdout.bin"), forged).unwrap();
            }
            rehash_runtime_bundle(&directory, case);
            assert!(verify_observation_bundle_for_case(&directory, case).is_err());
            fs::remove_dir_all(root).unwrap();
        }
        for case_id in [
            "runtime-directory-copy-file-failure",
            "runtime-directory-create-directory-failure",
            "runtime-directory-create-directory-if-missing-failure",
            "runtime-directory-get-file-size-failure",
            "runtime-directory-remove-file-failure",
            "runtime-directory-rename-file-failure",
            "runtime-directory-list-directory-failure",
            "runtime-directory-remove-directory-failure",
            "runtime-directory-set-current-directory-failure",
        ] {
            assert_runtime_failed_effect_substitution_rejected(&cases, case_id);
        }
        let available = cases
            .iter()
            .find(|case| case.id.as_ref() == "runtime-current-directory-upstream-available")
            .expect("upstream current-directory availability case");
        assert_rehashed_process_status_substitution_rejected(
            available,
            "current-directory-available-status",
            (true, 0),
            (false, 1),
        );
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn retained_platform_native_home_directory_rejects_role_substitution() {
        let cases = crate::committed_differential_cases();
        for (case_id, forged) in [
            ("runtime-directory-get-home-home-a", b"forged-a".as_slice()),
            ("runtime-directory-get-home-home-b", b"forged-b".as_slice()),
        ] {
            let case = cases
                .iter()
                .find(|case| case.id.as_ref() == case_id)
                .unwrap_or_else(|| panic!("missing platform-native home case {case_id}"));
            let descriptor = case
                .claim_evidence
                .as_ref()
                .unwrap_or_else(|| panic!("missing platform-native home authority for {case_id}"));
            assert_eq!(
                descriptor.review_statement.as_ref(),
                "runtime-home-directory-platform-native-oracle-review-v1",
                "wrong platform-native home authority for {case_id}"
            );
            assert!(
                descriptor
                    .semantic_targets
                    .iter()
                    .all(|target| target.expected_raw_presentation_sha256.is_none()),
                "platform-native home case unexpectedly fixed raw bytes for {case_id}"
            );

            let (root, directory) = retain_executed_runtime_case(case, case_id);
            let candidate_stdout = fs::read(directory.join("candidate/stdout.bin")).unwrap();
            let oracle_stdout = fs::read(directory.join("oracle/stdout.bin")).unwrap();
            assert_eq!(
                candidate_stdout, oracle_stdout,
                "platform-native home baseline differs for {case_id}"
            );
            assert_ne!(
                candidate_stdout.as_slice(),
                forged,
                "platform-native home substitution is ineffective for {case_id}"
            );
            fs::write(directory.join("candidate/stdout.bin"), forged).unwrap();
            rewrite_bundle_file_digest(&directory, "candidate/stdout.bin");
            assert!(
                verify_observation_bundle_for_case(&directory, case).is_err(),
                "platform-native home role substitution was accepted for {case_id}"
            );
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn current_directory_availability_rejects_rehashed_profile_substitution() {
        let cases = crate::committed_differential_cases();
        let case = cases
            .iter()
            .find(|case| case.id.as_ref() == "runtime-current-directory-upstream-available")
            .expect("upstream current-directory availability case");
        assert_eq!(
            case.claim_evidence.as_ref().unwrap().profile,
            hell_builtins::ExecutionProfile::Upstream
        );
        let (root, directory) =
            retain_executed_runtime_case(case, "current-directory-available-profile");
        let descriptor = directory.join("case.toml");
        let document = fs::read_to_string(&descriptor).unwrap();
        let substituted = document.replace(
            "execution_profile = \"upstream\"",
            "execution_profile = \"sandboxed\"",
        );
        assert_ne!(document, substituted, "profile substitution did not match");
        fs::write(descriptor, substituted).unwrap();
        rehash_runtime_bundle(&directory, case);
        assert!(verify_observation_bundle_for_case(&directory, case).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn retained_io_operations_reject_output_and_failure_substitutions() {
        let cases = crate::committed_differential_cases();
        for (case_id, forged) in [
            ("runtime-io-print-success", b"43\n".as_slice()),
            ("runtime-io-open-file-success", b"abd".as_slice()),
            ("runtime-io-close-success", b"open".as_slice()),
            ("runtime-io-pure-success", b"41\n".as_slice()),
            ("runtime-io-pure-text", b"forged\n".as_slice()),
            ("runtime-io-pure-ignored-bottom", b"before".as_slice()),
            ("runtime-io-buffering-block", b"1\npending".as_slice()),
            ("runtime-io-buffering-line", b"5\nline\npending".as_slice()),
            ("runtime-io-buffering-none", b"0\npending".as_slice()),
        ] {
            let case = cases
                .iter()
                .find(|case| case.id.as_ref() == case_id)
                .unwrap_or_else(|| panic!("missing IO success case {case_id}"));
            let (root, directory) = retain_executed_runtime_case(case, case_id);
            for role in ["candidate", "oracle"] {
                fs::write(directory.join(role).join("stdout.bin"), forged).unwrap();
            }
            rehash_runtime_bundle(&directory, case);
            assert!(verify_observation_bundle_for_case(&directory, case).is_err());
            fs::remove_dir_all(root).unwrap();
        }
        let close = cases
            .iter()
            .find(|case| case.id.as_ref() == "runtime-io-close-success")
            .expect("IO.hClose success case");
        let (root, directory) = retain_executed_runtime_case(close, "io-close-resource-event");
        let observation = directory.join("candidate").join("observation.json");
        let document = fs::read_to_string(&observation).unwrap();
        let substituted = document.replacen("\"event\": \"close\"", "\"event\": \"transfer\"", 1);
        assert_ne!(
            document, substituted,
            "close resource mutation did not match"
        );
        fs::write(observation, substituted).unwrap();
        rehash_runtime_bundle(&directory, close);
        assert!(verify_observation_bundle_for_case(&directory, close).is_err());
        fs::remove_dir_all(root).unwrap();
        for class in ["lazy-adapter-entry", "lazy-adapter-exit"] {
            assert_lazy_state_substitution_rejected(
                &cases,
                "runtime-io-pure-ignored-bottom",
                "IO.pure",
                class,
            );
        }
        assert_runtime_failed_effect_substitution_rejected(&cases, "runtime-io-open-file-failure");
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn function_identity_rejects_rehashed_type_raw_and_lazy_exit_substitutions() {
        let cases = crate::committed_differential_cases();
        assert_runtime_typed_substitution_rejected(
            "runtime-function-id-int",
            "\"value\":\"42\"",
            "\"value\":\"41\"",
        );
        assert_runtime_typed_substitution_rejected(
            "runtime-function-id-text",
            "\"utf8Hex\":\"61ceb2\"",
            "\"utf8Hex\":\"666f72676564\"",
        );
        for (case_id, forged) in [
            ("runtime-function-id-int", b"41\n".as_slice()),
            ("runtime-function-id-text", b"forged\n".as_slice()),
        ] {
            let case = runtime_case(&cases, case_id);
            let (root, directory) = retain_executed_runtime_case(case, case_id);
            for role in ["candidate", "oracle"] {
                fs::write(directory.join(role).join("stdout.bin"), forged).unwrap();
            }
            rehash_runtime_bundle(&directory, case);
            assert!(verify_observation_bundle_for_case(&directory, case).is_err());
            fs::remove_dir_all(root).unwrap();
            for class in ["lazy-adapter-entry", "lazy-adapter-exit"] {
                assert_lazy_state_substitution_rejected(&cases, case_id, "Function.id", class);
            }
        }
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn collection_lazy_entry_state_substitution_is_rejected() {
        let cases = crate::committed_differential_cases();
        assert_lazy_state_substitution_rejected(
            &cases,
            "runtime-typed-list-all",
            "List.all",
            "lazy-adapter-entry",
        );
        assert_demand_state_duplicate_rejected(
            &cases,
            "runtime-typed-list-all",
            "List.all",
            0,
            "lazy-adapter-entry",
            "not-forced",
        );
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn whnf_and_io_execution_state_duplicates_are_rejected() {
        let cases = crate::committed_differential_cases();
        assert_demand_state_duplicate_rejected(
            &cases,
            "runtime-typed-int-plus",
            "Int.plus",
            0,
            "whnf-force-complete",
            "value",
        );
        assert_demand_state_duplicate_rejected(
            &cases,
            "runtime-typed-timeout-positive-completed",
            "Timeout.timeout",
            0,
            "io-execution-complete",
            "value",
        );
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_lazy_state_substitution_rejected(
        cases: &[crate::DifferentialCase],
        case_id: &str,
        builtin: &str,
        class: &str,
    ) {
        let case = runtime_case(cases, case_id);
        let (root, directory) = retain_executed_runtime_case(case, case_id);
        let observation = directory.join("candidate/observation.json");
        let document = fs::read_to_string(&observation).unwrap();
        let spec = hell_builtins::lookup(builtin).expect("lazy adapter-exit target");
        let builtin = spec.id.0;
        let (argument, outcome) = parse_semantic_boundaries(&document)
            .expect("retained semantic boundaries parse")
            .iter()
            .find_map(|(id, argument, observed_class, outcome, _)| {
                (*id == spec.id && observed_class == class).then_some((*argument, outcome.clone()))
            })
            .unwrap_or_else(|| panic!("{case_id}/{builtin} retains no {class} state"));
        let replacement_outcome = if outcome == "not-forced" {
            "value"
        } else {
            "not-forced"
        };
        let original = format!(
            "\"builtinId\": {builtin}, \"argument\": {argument}, \"class\": \"{class}\", \"outcome\": \"{outcome}\""
        );
        let replacement = format!(
            "\"builtinId\": {builtin}, \"argument\": {argument}, \"class\": \"{class}\", \"outcome\": \"{replacement_outcome}\""
        );
        let changed = document.replacen(&original, &replacement, 1);
        assert_ne!(document, changed, "lazy state mutation did not match");
        fs::write(observation, changed).unwrap();
        rehash_runtime_bundle(&directory, case);
        assert!(verify_observation_bundle_for_case(&directory, case).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_demand_argument_state_substitution_rejected(
        cases: &[crate::DifferentialCase],
        case_id: &str,
        builtin: &str,
        argument: u16,
        class: &str,
    ) {
        let case = runtime_case(cases, case_id);
        let (root, directory) = retain_executed_runtime_case(case, case_id);
        let observation = directory.join("candidate/observation.json");
        let document = fs::read_to_string(&observation).unwrap();
        let spec = hell_builtins::lookup(builtin).expect("demand boundary target");
        let outcome = parse_semantic_boundaries(&document)
            .expect("retained semantic boundaries parse")
            .iter()
            .find_map(|(id, observed_argument, observed_class, outcome, _)| {
                (*id == spec.id && *observed_argument == argument && observed_class == class)
                    .then_some(outcome.clone())
            })
            .unwrap_or_else(|| {
                panic!("{case_id}/{builtin} retains no argument {argument}/{class} state")
            });
        let replacement_outcome = if outcome == "not-forced" {
            "value"
        } else {
            "not-forced"
        };
        let original = format!(
            "\"builtinId\": {}, \"argument\": {argument}, \"class\": \"{class}\", \"outcome\": \"{outcome}\"",
            spec.id.0
        );
        let replacement = format!(
            "\"builtinId\": {}, \"argument\": {argument}, \"class\": \"{class}\", \"outcome\": \"{replacement_outcome}\"",
            spec.id.0
        );
        let changed = document.replacen(&original, &replacement, 1);
        assert_ne!(document, changed, "demand state mutation did not match");
        fs::write(observation, changed).unwrap();
        rehash_runtime_bundle(&directory, case);
        assert!(
            verify_observation_bundle_for_case(&directory, case).is_err(),
            "{case_id}/{builtin} accepted a mutated argument {argument}/{class} demand state"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_demand_state_duplicate_rejected(
        cases: &[crate::DifferentialCase],
        case_id: &str,
        builtin: &str,
        argument: u16,
        class: &str,
        outcome: &str,
    ) {
        let case = runtime_case(cases, case_id);
        let (root, directory) = retain_executed_runtime_case(case, case_id);
        let builtin = hell_builtins::lookup(builtin)
            .expect("demand boundary target")
            .id
            .0;
        let original = format!(
            "{{\"builtinId\": {builtin}, \"argument\": {argument}, \"class\": \"{class}\", \"outcome\": \"{outcome}\"}}"
        );
        let duplicate = format!("{original},{original}");
        let observation = directory.join("candidate").join("observation.json");
        let document = fs::read_to_string(&observation).unwrap();
        let changed = document.replacen(&original, &duplicate, 1);
        assert_ne!(document, changed, "demand state duplicate did not match");
        fs::write(observation, changed).unwrap();
        rehash_runtime_bundle(&directory, case);
        assert!(verify_observation_bundle_for_case(&directory, case).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn byte_string_io_operations_reject_rehashed_raw_substitutions() {
        let cases = crate::committed_differential_cases();
        for (case_id, forged) in [
            ("runtime-bytestring-get-contents-io", &[0xff, b'B'][..]),
            ("runtime-bytestring-hget-io", b"ac".as_slice()),
            ("runtime-bytestring-hputstr-io", "aγ".as_bytes()),
        ] {
            let case = cases
                .iter()
                .find(|case| case.id.as_ref() == case_id)
                .unwrap_or_else(|| panic!("missing ByteString IO case {case_id}"));
            let (root, directory) = retain_executed_runtime_case(case, case_id);
            for role in ["candidate", "oracle"] {
                fs::write(directory.join(role).join("stdout.bin"), forged).unwrap();
            }
            rehash_runtime_bundle(&directory, case);
            assert!(verify_observation_bundle_for_case(&directory, case).is_err());
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn io_traversals_reject_rehashed_order_and_failure_substitutions() {
        let cases = crate::committed_differential_cases();
        let source_root = root("io-traversal-callbacks");
        assert_multi_call_callback_cases(
            &cases,
            &source_root,
            &[
                ("runtime-io-mapm-success", "IO.mapM_", "io-mapm"),
                ("runtime-io-form-success", "IO.forM_", "io-form"),
            ],
        );
        fs::remove_dir_all(source_root).unwrap();
        for (success_id, failure_id) in [
            ("runtime-io-mapm-success", "runtime-io-mapm-failure"),
            ("runtime-io-form-success", "runtime-io-form-failure"),
        ] {
            let case = cases
                .iter()
                .find(|case| case.id.as_ref() == success_id)
                .expect("IO traversal success case");
            let (root, directory) = retain_executed_runtime_case(case, success_id);
            for role in ["candidate", "oracle"] {
                fs::write(directory.join(role).join("stdout.bin"), b"2\n1\n").unwrap();
            }
            rehash_runtime_bundle(&directory, case);
            assert!(verify_observation_bundle_for_case(&directory, case).is_err());
            fs::remove_dir_all(root).unwrap();
            assert_runtime_failed_effect_substitution_rejected(&cases, failure_id);
        }
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn temp_operations_reject_rehashed_output_failure_and_cleanup_substitutions() {
        let cases = crate::committed_differential_cases();
        for (case_id, forged) in [
            ("runtime-temp-directory-success", b"abd".as_slice()),
            ("runtime-temp-file-success", b"forged".as_slice()),
        ] {
            let case = cases
                .iter()
                .find(|case| case.id.as_ref() == case_id)
                .unwrap_or_else(|| panic!("missing temp success case {case_id}"));
            let (root, directory) = retain_executed_runtime_case(case, case_id);
            for role in ["candidate", "oracle"] {
                fs::write(directory.join(role).join("stdout.bin"), forged).unwrap();
            }
            rehash_runtime_bundle(&directory, case);
            assert!(verify_observation_bundle_for_case(&directory, case).is_err());
            fs::remove_dir_all(root).unwrap();
        }
        let directory_case = cases
            .iter()
            .find(|case| case.id.as_ref() == "runtime-temp-directory-success")
            .expect("temp directory success case");
        let (root, directory) = retain_executed_runtime_case(directory_case, "temp-cleanup-event");
        let observation = directory.join("candidate").join("observation.json");
        let document = fs::read_to_string(&observation).unwrap();
        let substituted = document.replacen("\"event\": \"close\"", "\"event\": \"transfer\"", 1);
        assert_ne!(document, substituted, "temp cleanup mutation did not match");
        fs::write(observation, substituted).unwrap();
        rehash_runtime_bundle(&directory, directory_case);
        assert!(verify_observation_bundle_for_case(&directory, directory_case).is_err());
        fs::remove_dir_all(root).unwrap();
        for case_id in [
            "runtime-temp-directory-failure",
            "runtime-temp-file-failure",
        ] {
            assert_runtime_failed_effect_substitution_rejected(&cases, case_id);
        }
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn result_force_failure_requires_one_exact_lazy_adapter_result() {
        let builtin = hell_builtins::lookup("List.cycle")
            .expect("List.cycle builtin")
            .id;
        let event = |outcome: &'static str| crate::ObligationTraceEvent {
            builtin,
            instance_target: None,
            instance_premises: Vec::new(),
            owner_task: None,
            sequence: 1,
            parent_sequence: None,
            outcome: Arc::from(outcome),
            nested_adapters: 0,
            materialized_before: 0,
            materialized_after: 0,
            callbacks: Vec::new(),
            comparators: Vec::new(),
        };
        let alias = event("alias");
        let flags = 0b10 | 0b10_0000;
        let one = [&alias];
        let one_facts = PureRuntimeFacts {
            flags,
            events: &one,
            boundaries: [false; 6],
        };
        assert!(pure_runtime_obligation_satisfied(
            "result-force-failure",
            &one_facts,
        ));
        assert!(!pure_runtime_obligation_satisfied(
            "result-force-failure",
            &PureRuntimeFacts {
                flags,
                events: &[],
                boundaries: [false; 6],
            },
        ));
        let duplicate = [&alias, &alias];
        assert!(!pure_runtime_obligation_satisfied(
            "result-force-failure",
            &PureRuntimeFacts {
                flags,
                events: &duplicate,
                boundaries: [false; 6],
            },
        ));
        for wrong in [event("value"), event("error")] {
            let wrong_events = [&wrong];
            assert!(!pure_runtime_obligation_satisfied(
                "result-force-failure",
                &PureRuntimeFacts {
                    flags,
                    events: &wrong_events,
                    boundaries: [false; 6],
                },
            ));
        }
        assert!(!pure_runtime_obligation_satisfied(
            "result-force-failure",
            &PureRuntimeFacts {
                flags: flags | 1,
                events: &[&alias],
                boundaries: [false; 6],
            },
        ));
        assert!(!pure_runtime_obligation_satisfied(
            "result-force-failure",
            &PureRuntimeFacts {
                flags: 0b10,
                events: &[&alias],
                boundaries: [false; 6],
            },
        ));
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn list_cycle_empty_rejects_rehashed_failure_presentation_status_and_adapter_mutants() {
        let cases = crate::committed_differential_cases();
        let case = runtime_case(&cases, "list-cycle-boundary-empty-input");

        for (name, replacement) in [
            ("missing-stderr", b"".as_slice()),
            ("wrong-stderr", b"hell: forged cycle failure\n".as_slice()),
        ] {
            let (root, directory) = retain_executed_runtime_case(case, name);
            for role in ["candidate", "oracle"] {
                fs::write(directory.join(role).join("stderr.raw.bin"), replacement).unwrap();
            }
            rehash_runtime_bundle(&directory, case);
            assert!(verify_observation_bundle_for_case(&directory, case).is_err());
            fs::remove_dir_all(root).unwrap();
        }

        assert_rehashed_process_status_substitution_rejected(
            case,
            "list-cycle-wrong-status",
            (false, 1),
            (true, 0),
        );

        for (name, replacement) in [("value-outcome", "value"), ("error-outcome", "error")] {
            let (root, directory) = retain_executed_runtime_case(case, name);
            let path = directory.join("candidate").join("observation.json");
            let document = fs::read_to_string(&path).unwrap();
            let trace = document
                .find("\"semanticObligationTrace\": [")
                .expect("semantic obligation trace");
            let builtin = hell_builtins::lookup("List.cycle")
                .expect("List.cycle builtin")
                .id
                .0;
            let event = document[trace..]
                .find(&format!("{{\"builtinId\": {builtin}, "))
                .map(|offset| trace + offset)
                .expect("List.cycle adapter event");
            let outcome = document[event..]
                .find("\"outcome\": \"alias\"")
                .map(|offset| event + offset)
                .expect("List.cycle lazy result adapter");
            let end = outcome + "\"outcome\": \"alias\"".len();
            let mut changed = document.clone();
            changed.replace_range(outcome..end, &format!("\"outcome\": \"{replacement}\""));
            fs::write(path, changed).unwrap();
            rehash_runtime_bundle(&directory, case);
            assert!(verify_observation_bundle_for_case(&directory, case).is_err());
            fs::remove_dir_all(root).unwrap();
        }

        let (root, directory) = retain_executed_runtime_case(case, "missing-adapter-target");
        let path = directory.join("candidate").join("observation.json");
        let document = fs::read_to_string(&path).unwrap();
        let trace = document
            .find("\"semanticObligationTrace\": [")
            .expect("semantic obligation trace");
        let cycle = hell_builtins::lookup("List.cycle")
            .expect("List.cycle builtin")
            .id
            .0;
        let take = hell_builtins::lookup("List.take")
            .expect("List.take builtin")
            .id
            .0;
        let event = document[trace..]
            .find(&format!("{{\"builtinId\": {cycle}, "))
            .map(|offset| trace + offset)
            .expect("List.cycle adapter event");
        let end = event + format!("{{\"builtinId\": {cycle}").len();
        let mut changed = document.clone();
        changed.replace_range(event..end, &format!("{{\"builtinId\": {take}"));
        fs::write(path, changed).unwrap();
        rehash_runtime_bundle(&directory, case);
        assert!(verify_observation_bundle_for_case(&directory, case).is_err());
        fs::remove_dir_all(root).unwrap();

        let (root, directory) = retain_executed_runtime_case(case, "duplicate-adapter-target");
        let path = directory.join("candidate").join("observation.json");
        let document = fs::read_to_string(&path).unwrap();
        let trace = document
            .find("\"semanticObligationTrace\": [")
            .expect("semantic obligation trace");
        let cycle = hell_builtins::lookup("List.cycle")
            .expect("List.cycle builtin")
            .id
            .0;
        let event = document[trace..]
            .find(&format!("{{\"builtinId\": {cycle}, "))
            .map(|offset| trace + offset)
            .expect("List.cycle adapter event");
        let event_end = document[event..]
            .find("}],\n  \"semanticEventOrder\"")
            .map(|offset| event + offset + 1)
            .expect("List.cycle adapter event end");
        let duplicate = document[event..event_end].to_owned();
        let mut changed = document.clone();
        changed.insert_str(event_end, &format!(", {duplicate}"));
        fs::write(path, changed).unwrap();
        rehash_runtime_bundle(&directory, case);
        assert!(verify_observation_bundle_for_case(&directory, case).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn list_cycle_empty_rejects_coherent_typed_result_identity_and_shape_mutants() {
        let cases = crate::committed_differential_cases();
        let case = runtime_case(&cases, "list-cycle-boundary-empty-input");
        for (name, original, replacement) in [
            ("argument", "\"argument\":0", "\"argument\":1"),
            (
                "boundary",
                "\"boundary\":\"adapter-result\"",
                "\"boundary\":\"conditional-selected\"",
            ),
            ("code", "\"code\":\"H0901\"", "\"code\":\"H0902\""),
            (
                "outcome",
                "{\"type\":\"ForceBoundary\",\"outcome\":\"error\",\"code\":\"H0901\"}",
                "{\"type\":\"ForceBoundary\",\"outcome\":\"not-forced\"}",
            ),
        ] {
            let (root, directory) = retain_executed_runtime_case(case, name);
            let typed_path = directory
                .join("candidate")
                .join("semantic-typed-result.json");
            let typed = fs::read_to_string(&typed_path).unwrap();
            let changed = typed.replacen(original, replacement, 1);
            assert_ne!(typed, changed, "typed result mutation did not match");
            fs::write(&typed_path, &changed).unwrap();
            let old_digest = sha256_bytes(typed.trim_end().as_bytes()).hex();
            let new_digest = sha256_bytes(changed.trim_end().as_bytes()).hex();
            let observation = directory.join("candidate").join("observation.json");
            let document = fs::read_to_string(&observation).unwrap();
            let changed_document = document.replacen(&old_digest, &new_digest, 1);
            assert_ne!(
                document, changed_document,
                "typed digest mutation did not match"
            );
            fs::write(observation, changed_document).unwrap();
            rehash_runtime_bundle(&directory, case);
            assert!(verify_observation_bundle_for_case(&directory, case).is_err());
            fs::remove_dir_all(root).unwrap();
        }

        let (root, directory) = retain_executed_runtime_case(case, "typed-builtin");
        let observation = directory.join("candidate").join("observation.json");
        let document = fs::read_to_string(&observation).unwrap();
        let cycle = hell_builtins::lookup("List.cycle")
            .expect("List.cycle builtin")
            .id
            .0;
        let take = hell_builtins::lookup("List.take")
            .expect("List.take builtin")
            .id
            .0;
        let changed = document.replacen(
            &format!("\"semanticTypedResultBuiltinId\": {cycle}"),
            &format!("\"semanticTypedResultBuiltinId\": {take}"),
            1,
        );
        assert_ne!(document, changed, "typed builtin mutation did not match");
        fs::write(observation, changed).unwrap();
        rehash_runtime_bundle(&directory, case);
        assert!(verify_observation_bundle_for_case(&directory, case).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn retained_integer_and_unicode_text_substitutions_are_rejected_after_rehash() {
        assert_runtime_typed_substitution_rejected(
            "list-cycle-boundary-empty-input",
            "\"code\":\"H0901\"",
            "\"code\":\"H0902\"",
        );
        assert_runtime_typed_substitution_rejected(
            "list-cycle-boundary-finite-input",
            "\"type\":\"Int\",\"value\":\"2\"",
            "\"type\":\"Int\",\"value\":\"3\"",
        );
        assert_runtime_typed_substitution_rejected(
            "runtime-typed-integer-plus",
            "\"type\":\"Integer\",\"value\":\"42\"",
            "\"type\":\"Integer\",\"value\":\"43\"",
        );
        assert_runtime_typed_substitution_rejected(
            "runtime-typed-text-to-upper",
            "\"type\":\"Text\",\"utf8Hex\":\"41ce92\"",
            "\"type\":\"Text\",\"utf8Hex\":\"41ce91\"",
        );
        assert_runtime_typed_substitution_rejected(
            "runtime-typed-ci-mk",
            "\"folded\":{\"type\":\"Text\",\"utf8Hex\":\"616263\"}",
            "\"folded\":{\"type\":\"Text\",\"utf8Hex\":\"616264\"}",
        );
        assert_runtime_typed_substitution_rejected(
            "runtime-typed-builder-byte-string",
            "\"type\":\"Builder\",\"hex\":\"61ceb2\"",
            "\"type\":\"Builder\",\"hex\":\"61ceb3\"",
        );
        assert_runtime_typed_substitution_rejected(
            "json-string-boundary-unicode",
            "\"type\":\"Text\",\"utf8Hex\":\"ceb2\"",
            "\"type\":\"Text\",\"utf8Hex\":\"ceb3\"",
        );
        assert_runtime_typed_substitution_rejected(
            "json-encode-boundary-ascii",
            "\"type\":\"ByteString\",\"hex\":\"2261626322\"",
            "\"type\":\"ByteString\",\"hex\":\"2261626422\"",
        );
        assert_runtime_typed_substitution_rejected(
            "json-decode-boundary-unicode",
            "\"type\":\"Text\",\"utf8Hex\":\"ceb2\"",
            "\"type\":\"Text\",\"utf8Hex\":\"ceb3\"",
        );
        assert_runtime_typed_substitution_rejected(
            "tree-flatten-boundary-finite-input",
            "\"type\":\"Int\",\"value\":\"3\"",
            "\"type\":\"Int\",\"value\":\"4\"",
        );
        assert_runtime_typed_substitution_rejected(
            "tree-levels-boundary-finite-input",
            "\"type\":\"Int\",\"value\":\"3\"",
            "\"type\":\"Int\",\"value\":\"4\"",
        );
        assert_runtime_typed_substitution_rejected(
            "tree-map-boundary-finite-input",
            "\"type\":\"Int\",\"value\":\"4\"",
            "\"type\":\"Int\",\"value\":\"5\"",
        );
        assert_runtime_typed_substitution_rejected(
            "tree-node-boundary-finite-input",
            "\"type\":\"Int\",\"value\":\"3\"",
            "\"type\":\"Int\",\"value\":\"4\"",
        );
        assert_runtime_typed_substitution_rejected(
            "runtime-typed-double-plus",
            "\"type\":\"Double\",\"ieee754Bits\":\"4010000000000000\"",
            "\"type\":\"Double\",\"ieee754Bits\":\"4010000000000001\"",
        );
        assert_runtime_typed_substitution_rejected(
            "double-eq-boundary-overflow",
            "\"type\":\"Bool\",\"value\":false",
            "\"type\":\"Bool\",\"value\":true",
        );
        assert_runtime_typed_substitution_rejected(
            "double-show-boundary-overflow",
            "\"type\":\"Text\",\"utf8Hex\":\"496e66696e697479\"",
            "\"type\":\"Text\",\"utf8Hex\":\"496e66696e697478\"",
        );
        assert_runtime_typed_substitution_rejected(
            "double-showefloat-boundary-minimum-value",
            "\"type\":\"Text\",\"utf8Hex\":\"2d312e383065333038\"",
            "\"type\":\"Text\",\"utf8Hex\":\"2d312e383165333038\"",
        );
        assert_runtime_typed_substitution_rejected(
            "double-showffloat-boundary-minimum-value",
            "\"type\":\"Text\",\"utf8Hex\":\"2d313739",
            "\"type\":\"Text\",\"utf8Hex\":\"2d323739",
        );
        assert_runtime_typed_substitution_rejected(
            "options-fulldesc-boundary-present-option",
            "\"fullDescription\":true",
            "\"fullDescription\":false",
        );
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn retained_execution_input_substitution_is_rejected_after_rehash() {
        let case = crate::committed_differential_cases()
            .into_iter()
            .find(|case| case.id.as_ref() == "ci-mk-boundary-invalid-encoding")
            .expect("committed invalid-byte CI case");
        assert_eq!(case.stdin, [0xff, b'A']);
        let root = root("retained-execution-input");
        let (success, semantic) = execute_runtime_interaction(&case, &root);
        assert!(success);
        let mut retained = report();
        for observation in [&mut retained.oracle, &mut retained.candidate] {
            observation.case_id = case.id.clone();
        }
        retained.candidate.semantic = Some(semantic);
        let directory =
            retain_observation_bundle(&root.join("evidence"), &case, &retained).unwrap();
        verify_observation_bundle_for_case(&directory, &case).unwrap();
        fs::write(directory.join("stdin.bin"), [0xff, b'B']).unwrap();
        fs::remove_file(directory.join("bundle-manifest.json")).unwrap();
        fs::remove_file(directory.join("bundle-manifest.sha256")).unwrap();
        write_bundle_manifest(&directory, &case, sha256_bytes(b"epoch")).unwrap();
        assert!(verify_observation_bundle_for_case(&directory, &case).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn retain_executed_runtime_case(
        case: &crate::DifferentialCase,
        name: &str,
    ) -> (PathBuf, PathBuf) {
        let (root, directory) = retain_executed_runtime_case_unverified(case, name);
        verify_observation_bundle_for_case(&directory, case)
            .unwrap_or_else(|error| panic!("failed to verify {name}: {error}"));
        (root, directory)
    }

    #[cfg(feature = "compat-tracing")]
    fn retain_executed_runtime_case_unverified(
        case: &crate::DifferentialCase,
        name: &str,
    ) -> (PathBuf, PathBuf) {
        let root = root(name);
        let (_, status, semantic, stdout, stderr) =
            execute_runtime_interaction_with_status(case, &root);
        let mut retained = report();
        for observation in [&mut retained.oracle, &mut retained.candidate] {
            observation.case_id = Arc::clone(&case.id);
            observation.environment_profile = case.environment_profile;
            observation.process_helper_sha256 = case.process_helper_sha256;
            observation.stdout = BoundedCapture::from_bytes(stdout.clone());
            observation.raw_stderr = BoundedCapture::from_bytes(stderr.clone());
            observation.claim_input_stderr = BoundedCapture::from_bytes(stderr.clone());
            observation.stderr = BoundedCapture::from_bytes(stderr.clone());
            observation.status = status.clone();
        }
        retained.candidate.semantic = Some(semantic);
        let directory = retain_observation_bundle(&root.join("evidence"), case, &retained)
            .unwrap_or_else(|error| panic!("failed to retain {name}: {error}"));
        (root, directory)
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn collection_black_box_bundle_parser_joins_retained_bytes_to_opaque_provider_facts() {
        let case = crate::corpus::runtime_ord_map_cases()
            .into_iter()
            .find(|case| case.id.as_ref() == "runtime-ord-map-lookup-int-finite-input")
            .expect("reviewed Map lookup case");
        let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let source = crate::verify_collection_source_authority(&repository)
            .expect("retained collection source authority");
        let (bundle_root, directory) = retain_executed_runtime_case(&case, "collection-shard");
        let provider = CollectionVerifiedProviderRoot {
            platform: hell_builtins::ClaimPlatform::Linux,
            oracle_subject: crate::CollectionOracleSubject::LinuxSignedReleaseResultOnly,
            oracle_source_commit: Arc::from("d4d028609ed46a560c62caea8c70e7e91d1afd29"),
            oracle_executable_sha256: sha256_bytes(b"oracle"),
            oracle_acquisition_receipt_sha256: sha256_bytes(b"acquisition"),
            oracle_provider_attestation_sha256: sha256_bytes(b"acquisition-attestation"),
            provider_repository_id: 41,
            provider_run_id: 42,
            provider_run_attempt: 1,
            provider_artifact_id: 43,
            provider_workflow_ref: Arc::from(
                "owner/repository/.github/workflows/nightly.yml@refs/heads/main",
            ),
            provider_event: Arc::from("workflow_dispatch"),
            provider_candidate_subject_sha256: sha256_bytes(b"candidate subject"),
            candidate_source_commit: Arc::from("cccccccccccccccccccccccccccccccccccccccc"),
            candidate_executable_sha256: sha256_bytes(b"candidate"),
            oracle_build_record_sha256: None,
            dependency_authority: crate::CollectionDependencyAuthority::UnknownResultOnly,
        };
        let shard = collection_black_box_shard_for_bundle(&directory, &case, &source, &provider)
            .expect("derive collection black-box shard from retained bundle");
        assert_eq!(shard.case.case_id, case.id);
        assert_eq!(shard.platform, hell_builtins::ClaimPlatform::Linux);
        assert_eq!(
            shard.candidate_source_commit,
            provider.candidate_source_commit
        );
        assert_eq!(
            shard.candidate_executable_sha256,
            provider.candidate_executable_sha256
        );
        assert_eq!(shard.oracle_stdout_sha256, shard.candidate_stdout_sha256);
        assert_eq!(shard.oracle_stderr_sha256, shard.candidate_stderr_sha256);
        assert_eq!(shard.oracle_status_sha256, shard.candidate_status_sha256);
        assert_eq!(
            shard.candidate_comparator_trace_sha256,
            shard.case.comparator_contract_sha256
        );

        for mutate in [
            |root: &mut CollectionVerifiedProviderRoot| {
                root.oracle_executable_sha256 = sha256_bytes(b"wrong oracle");
            },
            |root: &mut CollectionVerifiedProviderRoot| {
                root.oracle_acquisition_receipt_sha256 = sha256_bytes(b"wrong receipt");
            },
            |root: &mut CollectionVerifiedProviderRoot| {
                root.oracle_provider_attestation_sha256 = sha256_bytes(b"wrong attestation");
            },
            |root: &mut CollectionVerifiedProviderRoot| {
                root.candidate_executable_sha256 = sha256_bytes(b"wrong candidate");
            },
        ] {
            let mut changed = provider.clone();
            mutate(&mut changed);
            assert!(
                collection_black_box_shard_for_bundle(&directory, &case, &source, &changed)
                    .is_err()
            );
        }

        let wrong_case = crate::corpus::runtime_ord_map_cases()
            .into_iter()
            .find(|candidate| candidate.id != case.id)
            .expect("different reviewed Map case");
        assert!(
            collection_black_box_shard_for_bundle(&directory, &wrong_case, &source, &provider)
                .is_err()
        );

        for (relative, replacement) in [
            ("oracle/stdout.bin", b"forged oracle stdout\n".as_slice()),
            (
                "candidate/stdout.bin",
                b"forged candidate stdout\n".as_slice(),
            ),
        ] {
            let (mutation_root, mutation) =
                retain_executed_runtime_case(&case, "collection-shard-raw-mutant");
            fs::write(mutation.join(relative), replacement).unwrap();
            rewrite_bundle_file_digest(&mutation, relative);
            assert!(
                collection_black_box_shard_for_bundle(&mutation, &case, &source, &provider)
                    .is_err()
            );
            fs::remove_dir_all(mutation_root).unwrap();
        }
        fs::remove_dir_all(bundle_root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn bind_test_process_helpers(cases: &mut [crate::DifferentialCase]) {
        let executable = std::env::current_exe().expect("current test executable");
        let directory = executable
            .parent()
            .and_then(Path::parent)
            .expect("test helper sibling directory");
        crate::bind_process_helper_directory(cases, directory).expect("bind process test helper");
    }

    #[cfg(feature = "compat-tracing")]
    fn rehash_runtime_bundle(directory: &Path, case: &crate::DifferentialCase) {
        fs::remove_file(directory.join("bundle-manifest.json")).unwrap();
        fs::remove_file(directory.join("bundle-manifest.sha256")).unwrap();
        write_bundle_manifest(directory, case, sha256_bytes(b"epoch")).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn options_presentation_shadow_executes_every_public_composition_target() {
        let cases = crate::committed_differential_cases();
        let selected = cases
            .iter()
            .filter(|case| case.id.starts_with("runtime-options-presentation-"))
            .collect::<Vec<_>>();
        assert_eq!(selected.len(), 13);
        for case in selected {
            let (root, _) = retain_executed_runtime_case(
                case,
                &format!("options-presentation-baseline-{}", case.id),
            );
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn options_presentation_shadow_rejects_raw_normalized_status_input_and_target_mutants() {
        let cases = crate::committed_differential_cases();
        let case = runtime_case(&cases, "runtime-options-presentation-switch");
        assert_options_presentation_expectation_rejected(
            case,
            "options-shadow-raw",
            |target, stdout| {
                let mut crlf = Vec::with_capacity(stdout.len() * 2);
                for byte in stdout {
                    if *byte == b'\n' {
                        crlf.extend_from_slice(b"\r\n");
                    } else {
                        crlf.push(*byte);
                    }
                }
                target.expected_raw_presentation_sha256 =
                    Some(crate::raw_presentation_sha256(&crlf, b""));
                assert_eq!(
                    target.expected_normalized_presentation_sha256,
                    Some(
                        crate::normalized_presentation_shadow_sha256(
                            crate::PresentationShadowNormalizerId::LineEndingsV1,
                            &crlf,
                            b"",
                        )
                        .unwrap()
                    )
                );
            },
        );
        assert_options_presentation_expectation_rejected(
            case,
            "options-shadow-normalized",
            |target, stdout| {
                let mut changed = stdout.to_vec();
                changed.extend_from_slice(b"shadow-only");
                target.expected_normalized_presentation_sha256 = Some(
                    crate::normalized_presentation_shadow_sha256(
                        crate::PresentationShadowNormalizerId::LineEndingsV1,
                        &changed,
                        b"",
                    )
                    .unwrap(),
                );
            },
        );
        assert_options_presentation_expectation_rejected(
            case,
            "options-shadow-status",
            |target, _| {
                target.expected_process_status_sha256 =
                    Some(crate::process_status_sha256(false, Some(1)));
            },
        );

        let mut argv = case.clone();
        argv.arguments = vec!["--unknown".into()];
        assert_options_presentation_case_rejected(&argv, "options-shadow-argv");

        let mut target = case.clone();
        let descriptor = target.claim_evidence.as_mut().unwrap();
        descriptor.targets[0].builtin = Arc::from("Options.info");
        descriptor.semantic_targets[0].builtin = Arc::from("Options.info");
        assert!(crate::validate_evidence_catalog(&[target]).is_err());

        assert_options_presentation_semantic_mutant_rejected(
            case,
            "options-shadow-parent-removed",
            |semantic| {
                mutate_options_target_parent(semantic, "Options.switch", None);
            },
        );
        assert_options_presentation_semantic_mutant_rejected(
            case,
            "options-shadow-parent-reparented",
            |semantic| {
                mutate_options_target_parent(semantic, "Options.switch", Some(1));
            },
        );
        assert_options_presentation_semantic_mutant_rejected(
            case,
            "options-shadow-dead-target",
            mutate_options_target_to_disconnected_adapter,
        );
        assert_options_presentation_semantic_mutant_rejected(
            case,
            "options-shadow-sink-terminal",
            mutate_options_sink_terminal,
        );
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_options_presentation_semantic_mutant_rejected(
        case: &crate::DifferentialCase,
        name: &str,
        mutate: impl FnOnce(&mut crate::SemanticObservation),
    ) {
        let root = root(name);
        let (_, status, mut semantic, stdout, stderr) =
            execute_runtime_interaction_with_status(case, &root);
        validate_options_dependency_for_test(case, &semantic)
            .expect("executed Options dependency baseline");
        mutate(&mut semantic);
        assert!(
            validate_options_dependency_for_test(case, &semantic).is_err(),
            "Options dependency mutant {name} did not exercise the causal gate"
        );
        assert_options_presentation_observation_rejected(
            case, &root, &status, semantic, &stdout, &stderr,
        );
    }

    #[cfg(feature = "compat-tracing")]
    fn validate_options_dependency_for_test(
        case: &crate::DifferentialCase,
        semantic: &crate::SemanticObservation,
    ) -> std::io::Result<()> {
        let target = &case.claim_evidence.as_ref().unwrap().semantic_targets[0];
        let builtin = hell_builtins::lookup(&target.builtin).unwrap().id;
        let effects = semantic
            .effect_trace
            .iter()
            .filter_map(|event| match event {
                crate::LogicalTraceEvent::HostEffect {
                    builtin,
                    owner_task,
                    sequence,
                    parent_sequence,
                    effect,
                } => Some(RetainedEffectEvent {
                    builtin: *builtin,
                    owner_task: *owner_task,
                    sequence: *sequence,
                    parent_sequence: *parent_sequence,
                    lifecycle: effect.to_string(),
                }),
                _ => None,
            })
            .collect::<Vec<_>>();
        validate_options_presentation_dependency(
            target,
            builtin,
            &semantic.obligation_trace,
            &effects,
        )
    }

    #[cfg(feature = "compat-tracing")]
    fn mutate_options_target_parent(
        semantic: &mut crate::SemanticObservation,
        builtin: &str,
        replacement: Option<u64>,
    ) {
        let builtin = hell_builtins::lookup(builtin).expect("Options target").id;
        semantic
            .obligation_trace
            .iter_mut()
            .find(|event| event.builtin == builtin)
            .expect("Options target event")
            .parent_sequence = replacement;
        recompute_nested_adapter_counts(&mut semantic.obligation_trace);
    }

    #[cfg(feature = "compat-tracing")]
    fn recompute_nested_adapter_counts(events: &mut [crate::ObligationTraceEvent]) {
        let parents = events
            .iter()
            .filter_map(|event| {
                event
                    .parent_sequence
                    .map(|parent| (event.owner_task, parent))
            })
            .collect::<Vec<_>>();
        for event in events {
            event.nested_adapters = parents
                .iter()
                .filter(|(owner, sequence)| {
                    *owner == event.owner_task && *sequence == event.sequence
                })
                .count() as u64;
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn mutate_options_target_to_disconnected_adapter(semantic: &mut crate::SemanticObservation) {
        let target = hell_builtins::lookup("Options.switch").unwrap().id;
        let unrelated = hell_builtins::lookup("Monad.return").unwrap().id;
        let target_index = semantic
            .obligation_trace
            .iter()
            .position(|event| event.builtin == target)
            .expect("connected Options target");
        let disconnected_index = semantic
            .obligation_trace
            .iter()
            .position(|event| event.parent_sequence.is_none() && event.builtin != target)
            .expect("disconnected unrelated adapter");
        semantic.obligation_trace[target_index].builtin = unrelated;
        semantic.obligation_trace[target_index].instance_target = Some(Arc::from("IO"));
        semantic.obligation_trace[target_index].outcome = Arc::from("io-action");
        semantic.obligation_trace[disconnected_index].builtin = target;
        semantic.obligation_trace[disconnected_index].instance_target = None;
        semantic.obligation_trace[disconnected_index]
            .instance_premises
            .clear();
        semantic.obligation_trace[disconnected_index].outcome = Arc::from("value");
    }

    #[cfg(feature = "compat-tracing")]
    fn mutate_options_sink_terminal(semantic: &mut crate::SemanticObservation) {
        let exec_parser = hell_builtins::lookup("Options.execParser").unwrap().id;
        for event in &mut semantic.effect_trace {
            if let crate::LogicalTraceEvent::HostEffect {
                builtin, effect, ..
            } = event
                && *builtin == exec_parser
                && effect.as_ref() == "failed"
            {
                *effect = Arc::from("completed");
            }
        }
        for event in &mut semantic.coverage {
            if let crate::CoverageEvent::ExecutedEffect(builtin, effect) = event
                && *builtin == exec_parser
                && effect.as_ref() == "failed"
            {
                *effect = Arc::from("completed");
            }
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_options_presentation_expectation_rejected(
        case: &crate::DifferentialCase,
        name: &str,
        mutate: impl FnOnce(&mut crate::EvidenceTargetV2, &[u8]),
    ) {
        let root = root(name);
        let (_, status, semantic, stdout, stderr) =
            execute_runtime_interaction_with_status(case, &root);
        let mut mutant = case.clone();
        mutate(
            &mut mutant.claim_evidence.as_mut().unwrap().semantic_targets[0],
            &stdout,
        );
        assert_options_presentation_observation_rejected(
            &mutant, &root, &status, semantic, &stdout, &stderr,
        );
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_options_presentation_case_rejected(case: &crate::DifferentialCase, name: &str) {
        let root = root(name);
        let (_, status, semantic, stdout, stderr) =
            execute_runtime_interaction_with_status(case, &root);
        assert_options_presentation_observation_rejected(
            case, &root, &status, semantic, &stdout, &stderr,
        );
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_options_presentation_observation_rejected(
        case: &crate::DifferentialCase,
        root: &Path,
        status: &crate::ProcessStatus,
        semantic: crate::SemanticObservation,
        stdout: &[u8],
        stderr: &[u8],
    ) {
        let mut retained = report();
        for observation in [&mut retained.oracle, &mut retained.candidate] {
            observation.case_id = Arc::clone(&case.id);
            observation.stdout = BoundedCapture::from_bytes(stdout.to_vec());
            observation.raw_stderr = BoundedCapture::from_bytes(stderr.to_vec());
            observation.claim_input_stderr = BoundedCapture::from_bytes(stderr.to_vec());
            observation.stderr = BoundedCapture::from_bytes(stderr.to_vec());
            observation.status = status.clone();
        }
        retained.candidate.semantic = Some(semantic);
        let directory = retain_observation_bundle(&root.join("evidence"), case, &retained)
            .expect("retain coherent Options Presentation mutant");
        assert!(verify_observation_bundle_for_case(&directory, case).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn options_presentation_shadow_wire_fields_and_regression_clone_are_exact() {
        let cases = crate::committed_differential_cases();
        let case = runtime_case(&cases, "runtime-options-presentation-switch");
        let (root, directory) = retain_executed_runtime_case(case, "options-shadow-wire");
        validate_regression_claim_sources(&directory, case)
            .expect("causal regression clone strips both Presentation output obligations");
        let path = directory.join("case.toml");
        let original = fs::read_to_string(&path).unwrap();
        for (name, changed) in options_presentation_wire_mutants(&original) {
            assert_ne!(changed, original, "wire mutant {name} did not change");
            fs::write(&path, changed).unwrap();
            rehash_runtime_bundle(&directory, case);
            assert!(
                verify_observation_bundle_for_case(&directory, case).is_err(),
                "wire mutant {name} was accepted"
            );
            fs::write(&path, &original).unwrap();
            rehash_runtime_bundle(&directory, case);
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn options_presentation_wire_mutants(original: &str) -> Vec<(&'static str, String)> {
        vec![
            (
                "old-schema",
                original.replacen("schema_version = 8", "schema_version = 7", 1),
            ),
            (
                "missing-normalizer",
                original.replace(
                    "expected_presentation_shadow_normalizer = \"presentation-line-endings-v1\"\n",
                    "",
                ),
            ),
            (
                "missing-digest",
                remove_toml_line(original, "expected_normalized_presentation_sha256"),
            ),
            (
                "unknown-normalizer",
                original.replace(
                    "presentation-line-endings-v1",
                    "presentation-line-endings-v2",
                ),
            ),
            (
                "substituted-digest",
                substitute_toml_digest(original, "expected_normalized_presentation_sha256"),
            ),
            (
                "extra-normalizer",
                original.replacen(
                    "expected_presentation_shadow_normalizer = \"presentation-line-endings-v1\"\n",
                    concat!(
                        "expected_presentation_shadow_normalizer = \"presentation-line-endings-v1\"\n",
                        "expected_presentation_shadow_normalizer = \"presentation-line-endings-v1\"\n",
                    ),
                    1,
                ),
            ),
        ]
    }

    #[cfg(feature = "compat-tracing")]
    fn remove_toml_line(original: &str, key: &str) -> String {
        let prefix = format!("{key} = ");
        original.lines().fold(String::new(), |mut output, line| {
            if !line.starts_with(&prefix) {
                writeln!(output, "{line}").expect("writing to String cannot fail");
            }
            output
        })
    }

    #[cfg(feature = "compat-tracing")]
    fn substitute_toml_digest(original: &str, key: &str) -> String {
        let prefix = format!("{key} = \"");
        let start = original.find(&prefix).expect("digest field") + prefix.len();
        let end = start + 64;
        let mut changed = original.to_owned();
        changed.replace_range(start..end, &"0".repeat(64));
        changed
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn exec_parser_boundaries_reject_rehashed_outcome_raw_and_argv_substitutions() {
        let cases = crate::committed_differential_cases();
        assert_parser_group_substitutions_rejected(
            &cases,
            &["options-execparser", "options-stroption"],
            &["absent-option", "malformed-option"],
            &["present-option", "repeated-option", "end-of-options"],
            &[
                ("present-option", "\"alpha\"", "\"beta\""),
                (
                    "repeated-option",
                    "[\"--name\", \"one\", \"--name\", \"two\"]",
                    "[\"--name\", \"two\", \"--name\", \"one\"]",
                ),
            ],
        );
        assert_parser_group_substitutions_rejected(
            &cases,
            &["options-strargument", "argument-metavar", "argument-help"],
            &["absent-option", "repeated-option", "malformed-option"],
            &["present-option", "end-of-options"],
            &[
                ("present-option", "\"alpha\"", "\"beta\""),
                (
                    "repeated-option",
                    "[\"one\", \"two\"]",
                    "[\"two\", \"one\"]",
                ),
            ],
        );
        assert_parser_group_substitutions_rejected(
            &cases,
            &["options-switch", "options-flag", "flag-long", "flag-help"],
            &["repeated-option", "malformed-option"],
            &["absent-option", "present-option", "end-of-options"],
            &[
                ("present-option", "[\"--verbose\"]", "[\"--other\"]"),
                (
                    "repeated-option",
                    "[\"--verbose\", \"--verbose\"]",
                    "[\"--verbose\", \"--other\"]",
                ),
            ],
        );
        assert_parser_group_substitutions_rejected(
            &cases,
            &["options-flag-prime"],
            &["absent-option", "repeated-option", "malformed-option"],
            &["present-option", "end-of-options"],
            &[
                ("present-option", "[\"--verbose\"]", "[\"--other\"]"),
                (
                    "repeated-option",
                    "[\"--verbose\", \"--verbose\"]",
                    "[\"--verbose\", \"--other\"]",
                ),
            ],
        );
        assert_parser_group_substitutions_rejected(
            &cases,
            &["option-long", "option-help"],
            &["absent-option", "malformed-option"],
            &["present-option", "repeated-option", "end-of-options"],
            &[
                ("present-option", "\"alpha\"", "\"beta\""),
                (
                    "repeated-option",
                    "[\"--name\", \"one\", \"--name\", \"two\"]",
                    "[\"--name\", \"two\", \"--name\", \"one\"]",
                ),
            ],
        );
        assert_default_and_metadata_parser_substitutions_rejected(&cases);
        assert_all_observable_parser_help_substitutions_rejected(&cases);
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_default_and_metadata_parser_substitutions_rejected(
        cases: &[crate::DifferentialCase],
    ) {
        assert_parser_group_substitutions_rejected(
            cases,
            &["option-value"],
            &["repeated-option", "malformed-option"],
            &["absent-option", "present-option", "end-of-options"],
            &[
                ("present-option", "\"alpha\"", "\"beta\""),
                (
                    "repeated-option",
                    "[\"--name\", \"one\", \"--name\", \"two\"]",
                    "[\"--name\", \"two\", \"--name\", \"one\"]",
                ),
            ],
        );
        assert_parser_group_substitutions_rejected(
            cases,
            &["argument-value"],
            &["repeated-option", "malformed-option"],
            &["absent-option", "present-option", "end-of-options"],
            &[
                ("present-option", "\"alpha\"", "\"beta\""),
                (
                    "repeated-option",
                    "[\"one\", \"two\"]",
                    "[\"two\", \"one\"]",
                ),
            ],
        );
        assert_parser_group_substitutions_rejected(
            cases,
            &[
                "options-header",
                "options-progdesc",
                "options-helper",
                "options-info",
                "options-fulldesc",
            ],
            &["repeated-option", "malformed-option"],
            &["absent-option", "present-option", "end-of-options"],
            &[
                ("present-option", "[\"--verbose\"]", "[\"--other\"]"),
                (
                    "repeated-option",
                    "[\"--verbose\", \"--verbose\"]",
                    "[\"--verbose\", \"--other\"]",
                ),
            ],
        );
        assert_parser_group_substitutions_rejected(
            cases,
            &["options-command", "options-hsubparser"],
            &["absent-option", "repeated-option", "malformed-option"],
            &["present-option", "end-of-options"],
            &[
                ("present-option", "[\"run\"]", "[\"other\"]"),
                (
                    "repeated-option",
                    "[\"run\", \"run\"]",
                    "[\"run\", \"other\"]",
                ),
            ],
        );
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_all_observable_parser_help_substitutions_rejected(cases: &[crate::DifferentialCase]) {
        for (case_id, reviewed_help) in [
            ("runtime-parser-observable-flag-help", "verbosity"),
            ("runtime-parser-observable-option-help", "chosen name"),
            ("runtime-parser-observable-argument-metavar", "ITEM"),
            ("runtime-parser-observable-argument-help", "chosen item"),
            (
                "runtime-parser-observable-options-header",
                "reviewed header",
            ),
            (
                "runtime-parser-observable-options-progdesc",
                "reviewed description",
            ),
            (
                "runtime-parser-observable-options-helper",
                "Show this help text",
            ),
        ] {
            assert_observable_parser_help_substitution_rejected(cases, case_id, reviewed_help);
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_parser_group_substitutions_rejected(
        cases: &[crate::DifferentialCase],
        prefixes: &[&str],
        failure_boundaries: &[&str],
        raw_boundaries: &[&str],
        argv_mutations: &[(&str, &str, &str)],
    ) {
        for &prefix in prefixes {
            assert_parser_failure_substitutions_rejected(cases, prefix, failure_boundaries);
            assert_parser_raw_substitutions_rejected(cases, prefix, raw_boundaries);
            assert_parser_argv_substitutions_rejected(cases, prefix, argv_mutations);
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_observable_parser_help_substitution_rejected(
        cases: &[crate::DifferentialCase],
        case_id: &str,
        reviewed_help: &str,
    ) {
        let case = cases
            .iter()
            .find(|case| case.id.as_ref() == case_id)
            .expect("observable parser help case");
        let root_name = format!("{case_id}-substitution");
        let (root, directory) = retain_executed_runtime_case(case, &root_name);
        for role in ["candidate", "oracle"] {
            let stdout = directory.join(role).join("stdout.bin");
            let document = fs::read_to_string(&stdout).unwrap();
            let substituted = document.replace(reviewed_help, "forged-help");
            assert_ne!(document, substituted, "help text mutation did not match");
            fs::write(stdout, substituted).unwrap();
        }
        rehash_runtime_bundle(&directory, case);
        assert!(verify_observation_bundle_for_case(&directory, case).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_parser_failure_substitutions_rejected(
        cases: &[crate::DifferentialCase],
        prefix: &str,
        boundaries: &[&str],
    ) {
        for &boundary in boundaries {
            let case = cases
                .iter()
                .find(|case| case.id.as_ref() == format!("{prefix}-boundary-{boundary}"))
                .expect("parser failure boundary");
            let (root, directory) =
                retain_executed_runtime_case(case, &format!("{prefix}-{boundary}"));
            let observation = directory.join("candidate").join("observation.json");
            let document = fs::read_to_string(&observation).unwrap();
            let substituted = document.replace("\"failed\"", "\"completed\"");
            assert_ne!(
                document, substituted,
                "{boundary} failure mutation did not match"
            );
            fs::write(observation, substituted).unwrap();
            rehash_runtime_bundle(&directory, case);
            assert!(verify_observation_bundle_for_case(&directory, case).is_err());
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_parser_raw_substitutions_rejected(
        cases: &[crate::DifferentialCase],
        prefix: &str,
        boundaries: &[&str],
    ) {
        for &boundary in boundaries {
            let case = cases
                .iter()
                .find(|case| case.id.as_ref() == format!("{prefix}-boundary-{boundary}"))
                .expect("parser success boundary");
            let (root, directory) =
                retain_executed_runtime_case(case, &format!("{prefix}-{boundary}"));
            for role in ["candidate", "oracle"] {
                fs::write(directory.join(role).join("stdout.bin"), b"forged\n").unwrap();
            }
            rehash_runtime_bundle(&directory, case);
            assert!(verify_observation_bundle_for_case(&directory, case).is_err());
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_parser_argv_substitutions_rejected(
        cases: &[crate::DifferentialCase],
        prefix: &str,
        mutations: &[(&str, &str, &str)],
    ) {
        for &(boundary, original, replacement) in mutations {
            let case = cases
                .iter()
                .find(|case| case.id.as_ref() == format!("{prefix}-boundary-{boundary}"))
                .expect("parser argv boundary");
            let (root, directory) =
                retain_executed_runtime_case(case, &format!("{prefix}-argv-{boundary}"));
            let input = directory.join("execution-input.json");
            let document = fs::read_to_string(&input).unwrap();
            let substituted = document.replace(original, replacement);
            assert_ne!(
                document, substituted,
                "{boundary} argv mutation did not match"
            );
            fs::write(input, substituted).unwrap();
            rehash_runtime_bundle(&directory, case);
            assert!(verify_observation_bundle_for_case(&directory, case).is_err());
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn raw_presentation_rejects_equal_candidate_and_oracle_byte_substitutions() {
        let case = crate::committed_differential_cases()
            .into_iter()
            .find(|case| case.id.as_ref() == "text-all-boundary-unicode")
            .expect("Text.all presentation case");
        let source_root = root("raw-presentation-source");
        let (success, semantic, stdout) =
            execute_runtime_interaction_with_stdout(&case, &source_root);
        assert!(success);
        assert_eq!(stdout, b"False\n");

        for (name, forged_stdout, forged_stderr) in [
            ("stdout", b"True\n".as_slice(), b"".as_slice()),
            ("stderr", b"False\n".as_slice(), b"forged".as_slice()),
        ] {
            let root = root(&format!("raw-presentation-{name}"));
            let mut retained = report();
            for observation in [&mut retained.oracle, &mut retained.candidate] {
                observation.case_id = Arc::clone(&case.id);
                observation.stdout = crate::BoundedCapture::from_bytes(forged_stdout.to_vec());
                observation.raw_stderr = crate::BoundedCapture::from_bytes(forged_stderr.to_vec());
            }
            retained.candidate.semantic = Some(semantic.clone());
            let directory =
                retain_observation_bundle(&root.join("evidence"), &case, &retained).unwrap();
            assert!(verify_observation_bundle_for_case(&directory, &case).is_err());
            fs::remove_dir_all(root).unwrap();
        }
        fs::remove_dir_all(source_root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn json_value_rejects_rehashed_branch_payload_result_and_raw_substitutions() {
        let cases = crate::committed_differential_cases();
        for branch in ["null", "bool", "string", "number", "array", "object"] {
            let case_id = format!("runtime-json-value-{branch}");
            let case = cases
                .iter()
                .find(|case| case.id.as_ref() == case_id)
                .unwrap_or_else(|| panic!("missing Json.value branch case {case_id}"));
            assert_json_value_callback_substitutions_rejected(case, branch);
            assert_json_value_raw_substitution_rejected(case, branch);
        }
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn record_get_and_set_reject_rehashed_field_result_and_raw_substitutions() {
        for (case_id, original, replacement) in [
            (
                "runtime-record-get-age",
                "\"value\":\"41\"",
                "\"value\":\"42\"",
            ),
            (
                "runtime-record-get-name",
                "\"utf8Hex\":\"416461\"",
                "\"utf8Hex\":\"4772616365\"",
            ),
            (
                "runtime-record-get-lazy-other-field",
                "\"value\":\"42\"",
                "\"value\":\"43\"",
            ),
            (
                "runtime-record-set-age",
                "\"value\":\"42\"",
                "\"value\":\"43\"",
            ),
            (
                "runtime-record-set-age",
                "\"constructorHex\":\"506572736f6e\"",
                "\"constructorHex\":\"506572736f6f\"",
            ),
            (
                "runtime-record-set-name",
                "\"utf8Hex\":\"4772616365\"",
                "\"utf8Hex\":\"416461\"",
            ),
            (
                "runtime-record-set-lazy-other-field",
                "\"outcome\":\"not-forced\"",
                "\"outcome\":\"in-progress\"",
            ),
            (
                "runtime-record-modify-age",
                "\"value\":\"42\"",
                "\"value\":\"44\"",
            ),
            (
                "runtime-record-modify-name",
                "\"utf8Hex\":\"414441\"",
                "\"utf8Hex\":\"4772616365\"",
            ),
            (
                "runtime-record-modify-lazy-other-field",
                "\"value\":\"43\"",
                "\"value\":\"44\"",
            ),
            (
                "runtime-record-modify-undemanded-callback",
                "\"outcome\":\"not-forced\"",
                "\"outcome\":\"in-progress\"",
            ),
        ] {
            assert_runtime_typed_substitution_rejected(case_id, original, replacement);
        }

        let cases = crate::committed_differential_cases();
        for case in cases.iter().filter(|case| {
            case.id.starts_with("runtime-record-get-")
                || case.id.starts_with("runtime-record-set-")
                || case.id.starts_with("runtime-record-modify-")
        }) {
            let (root, directory) = retain_executed_runtime_case(case, &case.id);
            for role in ["candidate", "oracle"] {
                fs::write(directory.join(role).join("stdout.bin"), b"forged\n").unwrap();
            }
            rehash_runtime_bundle(&directory, case);
            assert!(verify_observation_bundle_for_case(&directory, case).is_err());
            fs::remove_dir_all(root).unwrap();
        }
        for case_id in [
            "runtime-record-modify-age",
            "runtime-record-modify-name",
            "runtime-record-modify-lazy-other-field",
        ] {
            let case = cases
                .iter()
                .find(|case| case.id.as_ref() == case_id)
                .expect("Record.modify callback case");
            let root = root(case_id);
            let (_, semantic) = execute_runtime_interaction(case, &root);
            let mut omitted = semantic.clone();
            callback_events_mut(&mut omitted, "Record.modify").clear();
            assert_rehashed_callback_semantic_rejected(case, omitted, case_id);
            let mut changed = semantic;
            let callback = &mut callback_events_mut(&mut changed, "Record.modify")[0];
            callback.canonical_arguments[0] = Arc::from("{\"type\":\"Int\",\"value\":\"9\"}");
            callback.canonical_result =
                Arc::from("{\"type\":\"Text\",\"utf8Hex\":\"666f72676564\"}");
            assert_rehashed_callback_semantic_rejected(case, changed, case_id);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn tuple_constructors_reject_rehashed_arity_value_lazy_and_raw_substitutions() {
        let cases = crate::committed_differential_cases();
        for (case_id, builtin) in [
            ("runtime-tuple-two-lazy", "Tuple.(,)"),
            ("runtime-tuple-three-lazy", "Tuple.(,,)"),
            ("runtime-tuple-four-lazy", "Tuple.(,,,)"),
        ] {
            assert_runtime_typed_substitution_rejected(
                case_id,
                "\"value\":\"1\"",
                "\"value\":\"9\"",
            );
            assert_runtime_typed_substitution_rejected(
                case_id,
                "\"outcome\":\"not-forced\"",
                "\"outcome\":\"in-progress\"",
            );
            let case = cases
                .iter()
                .find(|case| case.id.as_ref() == case_id)
                .expect("tuple constructor case");
            let (root, directory) = retain_executed_runtime_case(case, case_id);
            for role in ["candidate", "oracle"] {
                fs::write(directory.join(role).join("stdout.bin"), b"9\n").unwrap();
            }
            rehash_runtime_bundle(&directory, case);
            assert!(verify_observation_bundle_for_case(&directory, case).is_err());
            fs::remove_dir_all(root).unwrap();
            for class in ["lazy-adapter-entry", "lazy-adapter-exit"] {
                assert_lazy_state_substitution_rejected(&cases, case_id, builtin, class);
            }
        }
        for (case_id, original, replacement) in [
            (
                "runtime-tuple-two-forced",
                "\"utf8Hex\":\"74776f\"",
                "\"utf8Hex\":\"666f72676564\"",
            ),
            (
                "runtime-tuple-three-forced",
                "\"value\":true",
                "\"value\":false",
            ),
            (
                "runtime-tuple-four-forced",
                "\"value\":\"4\"",
                "\"value\":\"8\"",
            ),
            (
                "runtime-tuple-two-forced",
                "\"elements\":[{\"type\":\"Int\",\"value\":\"1\"},{\"type\":\"Text\",\"utf8Hex\":\"74776f\"}]",
                "\"elements\":[{\"type\":\"Text\",\"utf8Hex\":\"74776f\"},{\"type\":\"Int\",\"value\":\"1\"}]",
            ),
            (
                "runtime-tuple-three-forced",
                "\"elements\":[{\"type\":\"Int\",\"value\":\"1\"},{\"type\":\"Text\",\"utf8Hex\":\"74776f\"},{\"type\":\"Bool\",\"value\":true}]",
                "\"elements\":[{\"type\":\"Bool\",\"value\":true},{\"type\":\"Text\",\"utf8Hex\":\"74776f\"},{\"type\":\"Int\",\"value\":\"1\"}]",
            ),
            (
                "runtime-tuple-four-forced",
                "\"elements\":[{\"type\":\"Int\",\"value\":\"1\"},{\"type\":\"Text\",\"utf8Hex\":\"74776f\"},{\"type\":\"Bool\",\"value\":true},{\"type\":\"Int\",\"value\":\"4\"}]",
                "\"elements\":[{\"type\":\"Int\",\"value\":\"4\"},{\"type\":\"Bool\",\"value\":true},{\"type\":\"Text\",\"utf8Hex\":\"74776f\"},{\"type\":\"Int\",\"value\":\"1\"}]",
            ),
        ] {
            assert_runtime_typed_substitution_rejected(case_id, original, replacement);
        }
        for case_id in [
            "runtime-tuple-two-forced",
            "runtime-tuple-three-forced",
            "runtime-tuple-four-forced",
        ] {
            let case = runtime_case(&cases, case_id);
            let (root, directory) = retain_executed_runtime_case(case, case_id);
            for role in ["candidate", "oracle"] {
                fs::write(directory.join(role).join("stdout.bin"), b"forged\n").unwrap();
            }
            rehash_runtime_bundle(&directory, case);
            assert!(verify_observation_bundle_for_case(&directory, case).is_err());
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn thread_delay_rejects_rehashed_timing_effect_and_task_substitutions() {
        let cases = crate::committed_differential_cases();
        assert_thread_delay_completed_substitutions_rejected(&cases);
        assert_thread_delay_timeout_substitutions_rejected(&cases);
        assert_thread_delay_failure_substitutions_rejected(&cases);
    }

    #[test]
    fn task_terminal_effect_correlation_is_closed_world() {
        let thread_delay = hell_builtins::lookup("Concurrent.threadDelay").unwrap().id;
        let timeout = hell_builtins::lookup("Timeout.timeout").unwrap().id;
        let async_race = hell_builtins::lookup("Async.race").unwrap().id;
        assert_eq!(
            expected_effect_terminal_for_task(thread_delay, "completed").unwrap(),
            "completed"
        );
        assert_eq!(
            expected_effect_terminal_for_task(thread_delay, "failed").unwrap(),
            "failed"
        );
        assert_eq!(
            expected_effect_terminal_for_task(thread_delay, "cancelled").unwrap(),
            "cancelled"
        );
        assert_eq!(
            expected_effect_terminal_for_task(timeout, "cancelled").unwrap(),
            "completed"
        );
        assert!(expected_effect_terminal_for_task(async_race, "cancelled").is_err());
        assert!(
            expected_effect_terminal_for_task(hell_builtins::BuiltinId(u16::MAX), "cancelled")
                .is_err()
        );
        assert!(expected_effect_terminal_for_task(thread_delay, "started").is_err());

        assert_cancelled_task_effect_correlations(thread_delay, timeout);
        assert_exact_cancelled_effect_cardinality(thread_delay);
        assert_cancelled_task_cardinality(thread_delay);
    }

    fn lifecycle_task_trace(
        builtin: hell_builtins::BuiltinId,
        terminal: &str,
    ) -> Vec<(u64, hell_builtins::BuiltinId, String)> {
        vec![
            (1, builtin, "started".to_owned()),
            (1, builtin, terminal.to_owned()),
        ]
    }

    fn lifecycle_effect_trace(
        builtin: hell_builtins::BuiltinId,
        terminal: &str,
    ) -> Vec<RetainedEffectEvent> {
        ["started", terminal]
            .into_iter()
            .map(|lifecycle| RetainedEffectEvent {
                builtin,
                owner_task: Some(1),
                sequence: 1,
                parent_sequence: None,
                lifecycle: lifecycle.to_owned(),
            })
            .collect()
    }

    fn lifecycle_coverage(
        builtin: hell_builtins::BuiltinId,
        task_terminal: &str,
        effect_terminal: &str,
    ) -> Vec<CoverageEvent> {
        vec![
            CoverageEvent::TaskEvent(builtin, Arc::from("started")),
            CoverageEvent::TaskEvent(builtin, Arc::from(task_terminal)),
            CoverageEvent::ExecutedEffect(builtin, Arc::from("started")),
            CoverageEvent::ExecutedEffect(builtin, Arc::from(effect_terminal)),
        ]
    }

    fn cancelled_task_target(builtin_name: &str) -> crate::EvidenceTargetV2 {
        let mut target = crate::EvidenceTargetV2::new(
            builtin_name,
            hell_builtins::CompatibilityDimension::PureRuntime,
            Vec::new(),
            crate::CausalSignal::RuntimeAdapter,
            vec![hell_builtins::ClaimPlatform::All],
        );
        target.expected_single_task_lifecycle_sha256 = Some(crate::single_task_lifecycle_sha256([
            "started",
            "cancelled",
        ]));
        target
    }

    fn assert_cancelled_task_effect_correlations(
        thread_delay: hell_builtins::BuiltinId,
        timeout: hell_builtins::BuiltinId,
    ) {
        for (builtin, name, expectations) in [
            (
                thread_delay,
                "Concurrent.threadDelay",
                [("cancelled", true), ("failed", false), ("completed", false)],
            ),
            (
                timeout,
                "Timeout.timeout",
                [("completed", true), ("cancelled", false), ("failed", false)],
            ),
        ] {
            let target = cancelled_task_target(name);
            for (effect_terminal, expected_success) in expectations {
                let tasks = lifecycle_task_trace(builtin, "cancelled");
                let effects = lifecycle_effect_trace(builtin, effect_terminal);
                let joined = lifecycle_coverage(builtin, "cancelled", effect_terminal);
                validate_task_causality(&tasks, &joined).unwrap();
                validate_effect_causality(&effects, &tasks, &joined).unwrap();
                assert_eq!(
                    validate_expected_single_task_lifecycle(&target, builtin, &tasks, &effects)
                        .is_ok(),
                    expected_success,
                    "{name} cancelled task/effect={effect_terminal}"
                );
            }
        }
        let target = cancelled_task_target("Concurrent.threadDelay");
        let tasks = lifecycle_task_trace(thread_delay, "completed");
        let effects = lifecycle_effect_trace(thread_delay, "cancelled");
        let joined = lifecycle_coverage(thread_delay, "completed", "cancelled");
        validate_task_causality(&tasks, &joined).unwrap();
        validate_effect_causality(&effects, &tasks, &joined).unwrap();
        assert!(
            validate_expected_single_task_lifecycle(&target, thread_delay, &tasks, &effects)
                .is_err()
        );
    }

    fn assert_exact_cancelled_effect_cardinality(thread_delay: hell_builtins::BuiltinId) {
        let mut target = cancelled_task_target("Concurrent.threadDelay");
        target.expected_single_effect_lifecycle_sha256 =
            Some(crate::single_effect_lifecycle_sha256([
                "started",
                "cancelled",
            ]));
        let tasks = lifecycle_task_trace(thread_delay, "cancelled");
        let effects = lifecycle_effect_trace(thread_delay, "cancelled");
        assert!(validate_expected_single_effect_lifecycle(&target, thread_delay, &effects).is_ok());
        let mut extra_effects = effects.clone();
        extra_effects.extend(
            lifecycle_effect_trace(thread_delay, "cancelled")
                .into_iter()
                .map(|mut event| {
                    event.sequence = 2;
                    event
                }),
        );
        let mut coverage = lifecycle_coverage(thread_delay, "cancelled", "cancelled");
        coverage.extend([
            CoverageEvent::ExecutedEffect(thread_delay, Arc::from("started")),
            CoverageEvent::ExecutedEffect(thread_delay, Arc::from("cancelled")),
        ]);
        validate_effect_causality(&extra_effects, &tasks, &coverage).unwrap();
        assert!(
            validate_expected_single_effect_lifecycle(&target, thread_delay, &extra_effects)
                .is_err()
        );
        let missing_effect = vec![RetainedEffectEvent {
            builtin: thread_delay,
            owner_task: Some(1),
            sequence: 1,
            parent_sequence: None,
            lifecycle: "started".to_owned(),
        }];
        let missing_coverage = vec![CoverageEvent::ExecutedEffect(
            thread_delay,
            Arc::from("started"),
        )];
        assert!(validate_effect_causality(&missing_effect, &tasks, &missing_coverage).is_err());
    }

    fn assert_cancelled_task_cardinality(thread_delay: hell_builtins::BuiltinId) {
        let missing_task = vec![(1, thread_delay, "started".to_owned())];
        let missing_coverage = vec![CoverageEvent::TaskEvent(thread_delay, Arc::from("started"))];
        assert!(validate_task_causality(&missing_task, &missing_coverage).is_err());
        let mut extra_task = lifecycle_task_trace(thread_delay, "cancelled");
        extra_task.push((1, thread_delay, "cancelled".to_owned()));
        let mut extra_coverage = lifecycle_coverage(thread_delay, "cancelled", "cancelled");
        extra_coverage.push(CoverageEvent::TaskEvent(
            thread_delay,
            Arc::from("cancelled"),
        ));
        assert!(validate_task_causality(&extra_task, &extra_coverage).is_err());
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn timeout_rejects_rehashed_branch_raw_status_effect_and_task_substitutions() {
        let cases = crate::committed_differential_cases();
        for case_id in [
            "runtime-typed-timeout-zero-no-force",
            "runtime-typed-timeout-negative-completed",
            "runtime-typed-timeout-positive-completed",
            "runtime-typed-timeout-positive-expired",
        ] {
            let case = runtime_case(&cases, case_id);
            assert_rehashed_process_status_substitution_rejected(
                case,
                &format!("{case_id}-status"),
                (true, 0),
                (false, 1),
            );
            let (root, directory) = retain_executed_runtime_case(case, case_id);
            for role in ["candidate", "oracle"] {
                fs::write(directory.join(role).join("stdout.bin"), b"forged\n").unwrap();
            }
            rehash_runtime_bundle(&directory, case);
            assert!(verify_observation_bundle_for_case(&directory, case).is_err());
            fs::remove_dir_all(root).unwrap();
        }

        let failure = runtime_case(&cases, "runtime-typed-timeout-positive-action-failure");
        assert_rehashed_process_status_substitution_rejected(
            failure,
            "timeout-action-failure-status",
            (false, 1),
            (true, 0),
        );
        assert_timeout_lifecycle_substitutions_rejected(&cases);
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn async_race_rejects_rehashed_side_raw_status_effect_and_global_task_substitutions() {
        let cases = crate::committed_differential_cases();
        for case_id in [
            "runtime-typed-async-race-left-completes",
            "runtime-typed-async-race-right-completes",
        ] {
            let case = runtime_case(&cases, case_id);
            assert_rehashed_process_status_substitution_rejected(
                case,
                &format!("{case_id}-status"),
                (true, 0),
                (false, 1),
            );
            let (root, directory) = retain_executed_runtime_case(case, case_id);
            for role in ["candidate", "oracle"] {
                fs::write(directory.join(role).join("stdout.bin"), b"forged\n").unwrap();
            }
            rehash_runtime_bundle(&directory, case);
            assert!(verify_observation_bundle_for_case(&directory, case).is_err());
            fs::remove_dir_all(root).unwrap();
        }
        for case_id in [
            "runtime-typed-async-race-left-fails",
            "runtime-typed-async-race-right-fails",
        ] {
            assert_rehashed_process_status_substitution_rejected(
                runtime_case(&cases, case_id),
                &format!("{case_id}-status"),
                (false, 1),
                (true, 0),
            );
        }
        assert_async_pair_trace_substitutions_rejected(
            &cases,
            "Async.race",
            &[
                ("runtime-typed-async-race-left-completes", true),
                ("runtime-typed-async-race-right-completes", true),
                ("runtime-typed-async-race-left-fails", false),
                ("runtime-typed-async-race-right-fails", false),
            ],
        );
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn async_concurrently_rejects_rehashed_raw_status_effect_and_global_task_substitutions() {
        let cases = crate::committed_differential_cases();
        for case_id in [
            "runtime-typed-async-concurrently-left-completes-first",
            "runtime-typed-async-concurrently-right-completes-first",
        ] {
            let case = runtime_case(&cases, case_id);
            assert_rehashed_process_status_substitution_rejected(
                case,
                &format!("{case_id}-status"),
                (true, 0),
                (false, 1),
            );
            let (root, directory) = retain_executed_runtime_case(case, case_id);
            for role in ["candidate", "oracle"] {
                fs::write(directory.join(role).join("stdout.bin"), b"forged\n").unwrap();
            }
            rehash_runtime_bundle(&directory, case);
            assert!(verify_observation_bundle_for_case(&directory, case).is_err());
            fs::remove_dir_all(root).unwrap();
        }
        for case_id in [
            "runtime-typed-async-concurrently-left-fails",
            "runtime-typed-async-concurrently-right-fails",
        ] {
            assert_rehashed_process_status_substitution_rejected(
                runtime_case(&cases, case_id),
                &format!("{case_id}-status"),
                (false, 1),
                (true, 0),
            );
        }
        assert_async_pair_trace_substitutions_rejected(
            &cases,
            "Async.concurrently",
            &[
                (
                    "runtime-typed-async-concurrently-left-completes-first",
                    true,
                ),
                (
                    "runtime-typed-async-concurrently-right-completes-first",
                    true,
                ),
                ("runtime-typed-async-concurrently-left-fails", false),
                ("runtime-typed-async-concurrently-right-fails", false),
            ],
        );
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_async_pair_trace_substitutions_rejected(
        cases: &[crate::DifferentialCase],
        builtin: &str,
        definitions: &[(&str, bool)],
    ) {
        for &(case_id, success) in definitions {
            let case = runtime_case(cases, case_id);
            let trace_root = root(&format!("{case_id}-trace"));
            let (actual_success, semantic, stdout) =
                execute_runtime_interaction_with_stdout(case, &trace_root);
            assert_eq!(actual_success, success);
            assert_async_pair_semantic_mutations_rejected(
                case, &semantic, &stdout, success, builtin,
            );
            fs::remove_dir_all(trace_root).unwrap();
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_async_pair_semantic_mutations_rejected(
        case: &crate::DifferentialCase,
        semantic: &crate::SemanticObservation,
        stdout: &[u8],
        success: bool,
        builtin: &str,
    ) {
        let (effect, other_effect) = if success {
            ("completed", "failed")
        } else {
            ("failed", "completed")
        };
        let mut changed_effect = semantic.clone();
        mutate_target_effect(&mut changed_effect, builtin, effect, other_effect);
        assert_rehashed_runtime_semantic_rejected(
            case,
            changed_effect,
            stdout,
            success,
            &format!("{}-effect", case.id),
        );
        let mut reordered = semantic.clone();
        let terminals = target_task_terminal_indices(&reordered, builtin);
        reordered.task_trace.swap(terminals[0], terminals[1]);
        assert_rehashed_runtime_semantic_rejected(
            case,
            reordered,
            stdout,
            success,
            &format!("{}-task-order", case.id),
        );
        let mut swapped_tasks = semantic.clone();
        swap_target_terminal_task_ids(&mut swapped_tasks, builtin);
        assert_rehashed_runtime_semantic_rejected(
            case,
            swapped_tasks,
            stdout,
            success,
            &format!("{}-task-ordinal", case.id),
        );
        let mut aliased_builtin = semantic.clone();
        inject_task_builtin_alias_pair(&mut aliased_builtin, builtin, "Concurrent.threadDelay");
        assert_rehashed_runtime_semantic_rejected(
            case,
            aliased_builtin,
            stdout,
            success,
            &format!("{}-cross-builtin-task", case.id),
        );
        let mut relabeled_task = semantic.clone();
        relabel_target_task(&mut relabeled_task, builtin, 999);
        assert_rehashed_runtime_semantic_rejected(
            case,
            relabeled_task,
            stdout,
            success,
            &format!("{}-task-id-relabel", case.id),
        );
    }

    #[cfg(feature = "compat-tracing")]
    fn inject_task_builtin_alias_pair(
        semantic: &mut crate::SemanticObservation,
        target: &str,
        replacement: &str,
    ) {
        let target = hell_builtins::lookup(target).expect("task target").id;
        let replacement = hell_builtins::lookup(replacement)
            .expect("replacement task builtin")
            .id;
        let task = semantic
            .task_trace
            .iter()
            .find_map(|event| match event {
                crate::LogicalTraceEvent::TaskEvent {
                    task,
                    builtin,
                    event,
                } if *builtin == target && event.as_ref() == "started" => Some(*task),
                _ => None,
            })
            .expect("target task start");
        semantic
            .task_trace
            .extend(
                ["started", "completed"].map(|event| crate::LogicalTraceEvent::TaskEvent {
                    task,
                    builtin: replacement,
                    event: Arc::from(event),
                }),
            );
    }

    #[cfg(feature = "compat-tracing")]
    fn relabel_target_task(
        semantic: &mut crate::SemanticObservation,
        target: &str,
        replacement: u64,
    ) {
        let target = hell_builtins::lookup(target).expect("task target").id;
        let original = semantic
            .task_trace
            .iter()
            .find_map(|event| match event {
                crate::LogicalTraceEvent::TaskEvent {
                    task,
                    builtin,
                    event,
                } if *builtin == target && event.as_ref() == "started" => Some(*task),
                _ => None,
            })
            .expect("target task start");
        for event in &mut semantic.task_trace {
            if let crate::LogicalTraceEvent::TaskEvent { task, .. } = event
                && *task == original
            {
                *task = replacement;
            }
        }
        for event in &mut semantic.effect_trace {
            if let crate::LogicalTraceEvent::HostEffect { owner_task, .. } = event
                && *owner_task == Some(original)
            {
                *owner_task = Some(replacement);
            }
        }
        for event in &mut semantic.resource_trace {
            if let crate::LogicalTraceEvent::ResourceEvent { owner_task, .. } = event
                && *owner_task == Some(original)
            {
                *owner_task = Some(replacement);
            }
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn target_task_terminal_indices(
        semantic: &crate::SemanticObservation,
        builtin: &str,
    ) -> Vec<usize> {
        let builtin = hell_builtins::lookup(builtin).expect("task target").id;
        let indices = semantic
            .task_trace
            .iter()
            .enumerate()
            .filter_map(|(index, event)| match event {
                crate::LogicalTraceEvent::TaskEvent {
                    builtin: id, event, ..
                } if *id == builtin && event.as_ref() != "started" => Some(index),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(indices.len(), 2, "pair target has two task terminals");
        indices
    }

    #[cfg(feature = "compat-tracing")]
    fn swap_target_terminal_task_ids(semantic: &mut crate::SemanticObservation, builtin: &str) {
        let indices = target_task_terminal_indices(semantic, builtin);
        let task_ids = indices
            .iter()
            .map(|index| match &semantic.task_trace[*index] {
                crate::LogicalTraceEvent::TaskEvent { task, .. } => *task,
                _ => unreachable!("terminal index is a task event"),
            })
            .collect::<Vec<_>>();
        for (index, task) in indices.into_iter().zip(task_ids.into_iter().rev()) {
            let crate::LogicalTraceEvent::TaskEvent {
                task: retained_task,
                ..
            } = &mut semantic.task_trace[index]
            else {
                unreachable!("terminal index is a task event")
            };
            *retained_task = task;
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_timeout_lifecycle_substitutions_rejected(cases: &[crate::DifferentialCase]) {
        for (case_id, success, terminal, other_terminals, effect, other_effect) in [
            (
                "runtime-typed-timeout-positive-completed",
                true,
                "completed",
                ["cancelled", "failed"],
                "completed",
                "failed",
            ),
            (
                "runtime-typed-timeout-positive-expired",
                true,
                "cancelled",
                ["completed", "failed"],
                "completed",
                "failed",
            ),
            (
                "runtime-typed-timeout-positive-action-failure",
                false,
                "failed",
                ["completed", "cancelled"],
                "failed",
                "completed",
            ),
        ] {
            let case = runtime_case(cases, case_id);
            let trace_root = root(&format!("{case_id}-lifecycle"));
            let (actual_success, semantic, stdout) =
                execute_runtime_interaction_with_stdout(case, &trace_root);
            assert_eq!(actual_success, success);
            let mut changed_effect = semantic.clone();
            mutate_target_effect(&mut changed_effect, "Timeout.timeout", effect, other_effect);
            assert_rehashed_runtime_semantic_rejected(
                case,
                changed_effect,
                &stdout,
                success,
                &format!("{case_id}-effect"),
            );
            let timeout = hell_builtins::lookup("Timeout.timeout").unwrap().id;
            let mut missing_effect = semantic.clone();
            missing_effect.effect_trace.retain(|event| {
                !matches!(event, crate::LogicalTraceEvent::HostEffect { builtin, effect: retained, .. }
                    if *builtin == timeout && retained.as_ref() == effect)
            });
            assert_rehashed_runtime_semantic_rejected(
                case,
                missing_effect,
                &stdout,
                success,
                &format!("{case_id}-effect-missing"),
            );
            for replacement in other_terminals {
                let mut changed_task = semantic.clone();
                mutate_target_task(&mut changed_task, "Timeout.timeout", terminal, replacement);
                assert_rehashed_runtime_semantic_rejected(
                    case,
                    changed_task,
                    &stdout,
                    success,
                    &format!("{case_id}-task-{replacement}"),
                );
            }
            fs::remove_dir_all(trace_root).unwrap();
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn runtime_case<'a>(
        cases: &'a [crate::DifferentialCase],
        case_id: &str,
    ) -> &'a crate::DifferentialCase {
        cases
            .iter()
            .find(|case| case.id.as_ref() == case_id)
            .unwrap_or_else(|| panic!("missing runtime case {case_id}"))
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_thread_delay_completed_substitutions_rejected(cases: &[crate::DifferentialCase]) {
        let completed = cases
            .iter()
            .find(|case| case.id.as_ref() == "runtime-typed-thread-delay-completed")
            .expect("committed completed thread delay");
        let completed_root = root("thread-delay-completed-trace");
        let (success, semantic, stdout) =
            execute_runtime_interaction_with_stdout(completed, &completed_root);
        assert!(success);
        let mut changed_effect = semantic.clone();
        mutate_target_effect(
            &mut changed_effect,
            "Concurrent.threadDelay",
            "completed",
            "failed",
        );
        assert_rehashed_runtime_semantic_rejected(
            completed,
            changed_effect,
            &stdout,
            true,
            "thread-delay-completed-effect",
        );
        for terminal in ["cancelled", "failed"] {
            let mut changed_task = semantic.clone();
            mutate_target_task(
                &mut changed_task,
                "Concurrent.threadDelay",
                "completed",
                terminal,
            );
            assert_rehashed_runtime_semantic_rejected(
                completed,
                changed_task,
                &stdout,
                true,
                &format!("thread-delay-completed-task-{terminal}"),
            );
        }
        fs::remove_dir_all(completed_root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_thread_delay_timeout_substitutions_rejected(cases: &[crate::DifferentialCase]) {
        let timeout = cases
            .iter()
            .find(|case| case.id.as_ref() == "runtime-typed-thread-delay-timeout")
            .expect("committed timed out thread delay");
        let (timeout_root, directory) =
            retain_executed_runtime_case(timeout, "thread-delay-timing");
        for role in ["candidate", "oracle"] {
            fs::write(directory.join(role).join("stdout.bin"), b"True\n").unwrap();
        }
        rehash_runtime_bundle(&directory, timeout);
        assert!(verify_observation_bundle_for_case(&directory, timeout).is_err());
        fs::remove_dir_all(timeout_root).unwrap();
        let timeout_trace_root = root("thread-delay-timeout-trace");
        let (success, semantic, stdout) =
            execute_runtime_interaction_with_stdout(timeout, &timeout_trace_root);
        assert!(success);
        assert_thread_delay_timeout_terminal_substitutions_rejected(timeout, &semantic, &stdout);
        assert_thread_delay_timeout_extra_substitutions_rejected(timeout, &semantic, &stdout);
        fs::remove_dir_all(timeout_trace_root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_thread_delay_timeout_terminal_substitutions_rejected(
        timeout: &crate::DifferentialCase,
        semantic: &crate::SemanticObservation,
        stdout: &[u8],
    ) {
        for replacement in ["failed", "completed"] {
            let mut changed_effect = semantic.clone();
            mutate_target_effect(
                &mut changed_effect,
                "Concurrent.threadDelay",
                "cancelled",
                replacement,
            );
            assert_rehashed_runtime_semantic_rejected(
                timeout,
                changed_effect,
                stdout,
                true,
                &format!("thread-delay-timeout-effect-{replacement}"),
            );
        }
        let thread_delay = hell_builtins::lookup("Concurrent.threadDelay").unwrap().id;
        let mut missing_effect = semantic.clone();
        missing_effect.effect_trace.retain(|event| {
            !matches!(event, crate::LogicalTraceEvent::HostEffect { builtin, effect, .. }
                if *builtin == thread_delay && effect.as_ref() == "cancelled")
        });
        let missing_effect_coverage = missing_effect
            .coverage
            .iter()
            .position(|event| {
                matches!(event, crate::CoverageEvent::ExecutedEffect(builtin, effect)
                    if *builtin == thread_delay && effect.as_ref() == "cancelled")
            })
            .expect("threadDelay cancelled effect coverage");
        missing_effect.coverage.remove(missing_effect_coverage);
        assert_rehashed_runtime_semantic_rejected(
            timeout,
            missing_effect,
            stdout,
            true,
            "thread-delay-timeout-effect-missing",
        );
        let mut changed_task = semantic.clone();
        mutate_target_task(
            &mut changed_task,
            "Concurrent.threadDelay",
            "cancelled",
            "completed",
        );
        assert_rehashed_runtime_semantic_rejected(
            timeout,
            changed_task,
            stdout,
            true,
            "thread-delay-timeout-task-completed",
        );
        let mut missing_task = semantic.clone();
        missing_task.task_trace.retain(|event| {
            !matches!(event, crate::LogicalTraceEvent::TaskEvent { builtin, event, .. }
                if *builtin == thread_delay && event.as_ref() == "cancelled")
        });
        let missing_task_coverage = missing_task
            .coverage
            .iter()
            .position(|event| {
                matches!(event, crate::CoverageEvent::TaskEvent(builtin, event)
                    if *builtin == thread_delay && event.as_ref() == "cancelled")
            })
            .expect("threadDelay cancelled task coverage");
        missing_task.coverage.remove(missing_task_coverage);
        assert_rehashed_runtime_semantic_rejected(
            timeout,
            missing_task,
            stdout,
            true,
            "thread-delay-timeout-task-missing",
        );
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_thread_delay_timeout_extra_substitutions_rejected(
        timeout: &crate::DifferentialCase,
        semantic: &crate::SemanticObservation,
        stdout: &[u8],
    ) {
        let thread_delay = hell_builtins::lookup("Concurrent.threadDelay").unwrap().id;
        let mut extra_task = semantic.clone();
        let terminal = extra_task
            .task_trace
            .iter()
            .find(|event| {
                matches!(event, crate::LogicalTraceEvent::TaskEvent { builtin, event, .. }
                    if *builtin == thread_delay && event.as_ref() == "cancelled")
            })
            .expect("threadDelay cancelled task")
            .clone();
        extra_task.task_trace.push(terminal);
        extra_task.coverage.push(crate::CoverageEvent::TaskEvent(
            thread_delay,
            Arc::from("cancelled"),
        ));
        assert_rehashed_runtime_semantic_rejected(
            timeout,
            extra_task,
            stdout,
            true,
            "thread-delay-timeout-task-extra",
        );
        let mut extra_effect = semantic.clone();
        let next_sequence = extra_effect
            .effect_trace
            .iter()
            .filter_map(|event| match event {
                crate::LogicalTraceEvent::HostEffect {
                    builtin, sequence, ..
                } if *builtin == thread_delay => Some(*sequence),
                _ => None,
            })
            .max()
            .expect("threadDelay effect sequence")
            .saturating_add(1);
        let duplicated = extra_effect
            .effect_trace
            .iter()
            .filter_map(|event| match event {
                crate::LogicalTraceEvent::HostEffect {
                    builtin,
                    owner_task,
                    parent_sequence,
                    effect,
                    ..
                } if *builtin == thread_delay => Some(crate::LogicalTraceEvent::HostEffect {
                    builtin: *builtin,
                    owner_task: *owner_task,
                    sequence: next_sequence,
                    parent_sequence: *parent_sequence,
                    effect: Arc::clone(effect),
                }),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(duplicated.len(), 2);
        extra_effect.effect_trace.extend(duplicated);
        extra_effect.coverage.extend([
            crate::CoverageEvent::ExecutedEffect(thread_delay, Arc::from("started")),
            crate::CoverageEvent::ExecutedEffect(thread_delay, Arc::from("cancelled")),
        ]);
        assert_rehashed_runtime_semantic_rejected(
            timeout,
            extra_effect,
            stdout,
            true,
            "thread-delay-timeout-effect-extra",
        );
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_thread_delay_failure_substitutions_rejected(cases: &[crate::DifferentialCase]) {
        let failed = cases
            .iter()
            .find(|case| case.id.as_ref() == "runtime-typed-thread-delay-forced-argument-failure")
            .expect("committed failed thread delay");
        let failed_root = root("thread-delay-failed-trace");
        let (success, mut semantic, stdout) =
            execute_runtime_interaction_with_stdout(failed, &failed_root);
        assert!(!success);
        let mut changed_effect = semantic.clone();
        mutate_target_effect(
            &mut changed_effect,
            "Concurrent.threadDelay",
            "failed",
            "completed",
        );
        assert_rehashed_runtime_semantic_rejected(
            failed,
            changed_effect,
            &stdout,
            false,
            "thread-delay-failed-effect",
        );
        mutate_target_task(
            &mut semantic,
            "Concurrent.threadDelay",
            "failed",
            "cancelled",
        );
        assert_rehashed_runtime_semantic_rejected(
            failed,
            semantic,
            &stdout,
            false,
            "thread-delay-failed-task-cancelled",
        );
        fs::remove_dir_all(failed_root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn exit_actions_reject_rehashed_status_raw_and_effect_substitutions() {
        let cases = crate::committed_differential_cases();
        for (case_id, success, code, forged_success, forged_code) in [
            ("runtime-typed-exit-die", false, 1, false, 2),
            ("runtime-typed-exit-with-failure", false, 23, false, 22),
            ("runtime-typed-exit-with-success", true, 0, false, 23),
        ] {
            let case = cases
                .iter()
                .find(|case| case.id.as_ref() == case_id)
                .expect("committed exit action case");
            let (root, directory) = retain_executed_runtime_case(case, case_id);
            for role in ["candidate", "oracle"] {
                let path = directory.join(role).join("observation.json");
                let document = fs::read_to_string(&path).unwrap();
                let original = format!("\"status\": {{\"success\": {success}, \"code\": {code}}}");
                let replacement = format!(
                    "\"status\": {{\"success\": {forged_success}, \"code\": {forged_code}}}"
                );
                let changed = document.replace(&original, &replacement);
                assert_ne!(document, changed, "exit status substitution did not match");
                fs::write(path, changed).unwrap();
            }
            rehash_runtime_bundle(&directory, case);
            assert!(verify_observation_bundle_for_case(&directory, case).is_err());
            fs::remove_dir_all(root).unwrap();

            let (root, directory) =
                retain_executed_runtime_case(case, &format!("{case_id}-effect"));
            let path = directory.join("candidate").join("observation.json");
            let document = fs::read_to_string(&path).unwrap();
            let changed =
                document.replacen("\"effect\": \"failed\"", "\"effect\": \"completed\"", 1);
            assert_ne!(document, changed, "exit effect substitution did not match");
            fs::write(path, changed).unwrap();
            rehash_runtime_bundle(&directory, case);
            assert!(verify_observation_bundle_for_case(&directory, case).is_err());
            fs::remove_dir_all(root).unwrap();
        }

        let die = cases
            .iter()
            .find(|case| case.id.as_ref() == "runtime-typed-exit-die")
            .expect("committed Exit.die case");
        let (root, directory) = retain_executed_runtime_case(die, "exit-die-raw");
        for role in ["candidate", "oracle"] {
            fs::write(
                directory.join(role).join("stderr.raw.bin"),
                b"forged exit\n",
            )
            .unwrap();
        }
        rehash_runtime_bundle(&directory, die);
        assert!(verify_observation_bundle_for_case(&directory, die).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_rehashed_process_status_substitution_rejected(
        case: &crate::DifferentialCase,
        name: &str,
        original: (bool, i32),
        replacement: (bool, i32),
    ) {
        let (root, directory) = retain_executed_runtime_case(case, name);
        for role in ["candidate", "oracle"] {
            let path = directory.join(role).join("observation.json");
            let document = fs::read_to_string(&path).unwrap();
            let changed = document.replace(
                &format!(
                    "\"status\": {{\"success\": {}, \"code\": {}}}",
                    original.0, original.1
                ),
                &format!(
                    "\"status\": {{\"success\": {}, \"code\": {}}}",
                    replacement.0, replacement.1
                ),
            );
            assert_ne!(document, changed, "status mutation did not match");
            fs::write(path, changed).unwrap();
        }
        rehash_runtime_bundle(&directory, case);
        assert!(verify_observation_bundle_for_case(&directory, case).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn mutate_target_effect(
        semantic: &mut crate::SemanticObservation,
        builtin: &str,
        original: &str,
        replacement: &str,
    ) {
        let builtin = hell_builtins::lookup(builtin)
            .expect("runtime effect target")
            .id;
        let event = semantic
            .effect_trace
            .iter_mut()
            .find(|event| {
                matches!(event, crate::LogicalTraceEvent::HostEffect { builtin: id, effect, .. }
                    if *id == builtin && effect.as_ref() == original)
            })
            .expect("target effect event");
        let crate::LogicalTraceEvent::HostEffect { effect, .. } = event else {
            unreachable!("matched target effect event")
        };
        *effect = Arc::from(replacement);
        let coverage = semantic
            .coverage
            .iter_mut()
            .find(|event| {
                matches!(event, crate::CoverageEvent::ExecutedEffect(id, lifecycle)
                    if *id == builtin && lifecycle.as_ref() == original)
            })
            .expect("target effect coverage event");
        let crate::CoverageEvent::ExecutedEffect(_, lifecycle) = coverage else {
            unreachable!("matched target effect coverage event")
        };
        *lifecycle = Arc::from(replacement);
    }

    #[cfg(feature = "compat-tracing")]
    fn mutate_target_task(
        semantic: &mut crate::SemanticObservation,
        builtin: &str,
        original: &str,
        replacement: &str,
    ) {
        let builtin = hell_builtins::lookup(builtin)
            .expect("runtime task target")
            .id;
        let event = semantic
            .task_trace
            .iter_mut()
            .find(|event| {
                matches!(event, crate::LogicalTraceEvent::TaskEvent { builtin: id, event, .. }
                    if *id == builtin && event.as_ref() == original)
            })
            .expect("target task event");
        let crate::LogicalTraceEvent::TaskEvent { event, .. } = event else {
            unreachable!("matched target task event")
        };
        *event = Arc::from(replacement);
        let coverage = semantic
            .coverage
            .iter_mut()
            .find(|coverage| {
                matches!(coverage, crate::CoverageEvent::TaskEvent(id, lifecycle)
                    if *id == builtin && lifecycle.as_ref() == original)
            })
            .expect("target task coverage event");
        let crate::CoverageEvent::TaskEvent(_, lifecycle) = coverage else {
            unreachable!("matched target task coverage event")
        };
        *lifecycle = Arc::from(replacement);
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_rehashed_runtime_semantic_rejected(
        case: &crate::DifferentialCase,
        semantic: crate::SemanticObservation,
        stdout: &[u8],
        success: bool,
        name: &str,
    ) {
        let root = root(name);
        let mut retained = report();
        for observation in [&mut retained.oracle, &mut retained.candidate] {
            observation.case_id = Arc::clone(&case.id);
            observation.environment_profile = case.environment_profile;
            observation.process_helper_sha256 = case.process_helper_sha256;
            observation.stdout = BoundedCapture::from_bytes(stdout.to_vec());
            observation.status = crate::ProcessStatus {
                success,
                code: Some(i32::from(!success)),
            };
        }
        retained.candidate.semantic = Some(semantic);
        let directory = retain_observation_bundle(&root.join("evidence"), case, &retained)
            .expect("retain rehashed runtime semantic mutant");
        assert!(
            verify_observation_bundle_for_case(&directory, case).is_err(),
            "rehashed runtime semantic mutant {name} was accepted"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn resolved_instance_target_rejects_wire_descriptor_and_same_class_substitutions() {
        let cases = crate::committed_differential_cases();
        assert_existing_instance_substitutions(&cases);
        assert_functor_instance_substitutions(&cases);
        assert_eq_instance_substitutions(&cases);

        assert_descriptor_instance_field_is_schema_bound(runtime_case(
            &cases,
            "runtime-typed-alternative-optional-maybe-just",
        ));
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_existing_instance_substitutions(cases: &[crate::DifferentialCase]) {
        for (case_id, expected, substituted) in [
            (
                "runtime-typed-alternative-optional-maybe-just",
                "Maybe",
                "Options.Parser",
            ),
            (
                "runtime-typed-alternative-optional-parser-present",
                "Options.Parser",
                "Maybe",
            ),
            ("ci-mk-boundary-ascii", "Text", "ByteString"),
            ("ci-mk-boundary-invalid-encoding", "ByteString", "Text"),
            ("runtime-interaction-map-ordering-custom-ord", "Int", "Text"),
            ("runtime-typed-monad-return-io", "IO", "Maybe"),
            ("runtime-typed-monad-return-maybe", "Maybe", "IO"),
            ("runtime-typed-monad-return-list", "[]", "Tree"),
            ("runtime-typed-monad-return-tree", "Tree", "Either"),
            ("runtime-typed-monad-return-either", "Either", "Maybe"),
            ("runtime-typed-monad-when-io-selected", "IO", "Maybe"),
            ("runtime-typed-monad-when-maybe-selected", "Maybe", "IO"),
            ("runtime-typed-monad-when-list-selected", "[]", "Tree"),
            ("runtime-typed-monad-when-tree-selected", "Tree", "Either"),
            (
                "runtime-typed-monad-when-either-selected",
                "Either",
                "Maybe",
            ),
            ("runtime-typed-monad-then-io-success", "IO", "Maybe"),
            ("runtime-typed-monad-then-maybe-success", "Maybe", "IO"),
            ("runtime-typed-monad-then-list-success", "[]", "Tree"),
            ("runtime-typed-monad-then-tree-simple", "Tree", "Either"),
            ("runtime-typed-monad-then-either-success", "Either", "Maybe"),
            ("runtime-typed-monad-bind-io-success", "IO", "Maybe"),
            ("runtime-typed-monad-bind-maybe-success", "Maybe", "IO"),
            ("runtime-typed-monad-bind-list-success", "[]", "Tree"),
            ("runtime-typed-monad-bind-tree-simple", "Tree", "Either"),
            ("runtime-typed-monad-bind-either-success", "Either", "Maybe"),
            ("runtime-typed-monad-sequence-io-finite", "IO", "Maybe"),
            ("runtime-typed-monad-sequence-maybe-finite", "Maybe", "IO"),
            ("runtime-typed-monad-sequence-list-finite", "[]", "Tree"),
            ("runtime-typed-monad-sequence-tree-finite", "Tree", "Either"),
            (
                "runtime-typed-monad-sequence-either-finite",
                "Either",
                "Maybe",
            ),
            ("runtime-typed-monad-mapm-io-finite", "IO", "Maybe"),
            ("runtime-typed-monad-mapm-maybe-finite", "Maybe", "IO"),
            ("runtime-typed-monad-mapm-list-finite", "[]", "Tree"),
            ("runtime-typed-monad-mapm-tree-finite", "Tree", "Either"),
            ("runtime-typed-monad-mapm-either-finite", "Either", "Maybe"),
            ("runtime-typed-monad-form-io-finite", "IO", "Maybe"),
            ("runtime-typed-monad-form-maybe-finite", "Maybe", "IO"),
            ("runtime-typed-monad-form-list-finite", "[]", "Tree"),
            ("runtime-typed-monad-form-tree-finite", "Tree", "Either"),
            ("runtime-typed-monad-form-either-finite", "Either", "Maybe"),
            ("runtime-typed-monad-mapm-discard-io-finite", "IO", "Maybe"),
            (
                "runtime-typed-monad-mapm-discard-maybe-finite",
                "Maybe",
                "IO",
            ),
            ("runtime-typed-monad-mapm-discard-list-finite", "[]", "Tree"),
            (
                "runtime-typed-monad-mapm-discard-tree-finite",
                "Tree",
                "Either",
            ),
            (
                "runtime-typed-monad-mapm-discard-either-finite",
                "Either",
                "Maybe",
            ),
            ("runtime-typed-monad-form-discard-io-finite", "IO", "Maybe"),
            (
                "runtime-typed-monad-form-discard-maybe-finite",
                "Maybe",
                "IO",
            ),
            ("runtime-typed-monad-form-discard-list-finite", "[]", "Tree"),
            (
                "runtime-typed-monad-form-discard-tree-finite",
                "Tree",
                "Either",
            ),
            (
                "runtime-typed-monad-form-discard-either-finite",
                "Either",
                "Maybe",
            ),
        ] {
            assert_resolved_instance_substitution(cases, case_id, expected, substituted);
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_functor_instance_substitutions(cases: &[crate::DifferentialCase]) {
        for (case_id, expected, substituted) in [
            ("runtime-typed-functor-fmap-list-mapped", "[]", "Tree"),
            ("runtime-typed-functor-fmap-io-mapped", "IO", "Maybe"),
            (
                "runtime-typed-functor-fmap-parser-mapped",
                "Options.Parser",
                "IO",
            ),
            ("runtime-typed-functor-fmap-tree-mapped", "Tree", "[]"),
            ("runtime-typed-functor-fmap-maybe-mapped", "Maybe", "Either"),
            (
                "runtime-typed-functor-fmap-either-mapped",
                "Either",
                "Maybe",
            ),
            ("runtime-typed-functor-fmap-pair-mapped", "(,)", "Tree"),
            ("runtime-typed-functor-operator-list-mapped", "[]", "Tree"),
            ("runtime-typed-functor-operator-io-mapped", "IO", "Maybe"),
            (
                "runtime-typed-functor-operator-parser-mapped",
                "Options.Parser",
                "IO",
            ),
            ("runtime-typed-functor-operator-tree-mapped", "Tree", "[]"),
            (
                "runtime-typed-functor-operator-maybe-mapped",
                "Maybe",
                "Either",
            ),
            (
                "runtime-typed-functor-operator-either-mapped",
                "Either",
                "Maybe",
            ),
            ("runtime-typed-functor-operator-pair-mapped", "(,)", "Tree"),
        ] {
            assert_resolved_instance_substitution(cases, case_id, expected, substituted);
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_eq_instance_substitutions(cases: &[crate::DifferentialCase]) {
        for (case_id, expected, substituted) in [
            ("runtime-typed-eq-bool-equal", "Bool", "Int"),
            ("runtime-typed-eq-byte-string-equal", "ByteString", "Text"),
            ("runtime-typed-eq-ci-equal", "CI", "Maybe"),
            ("runtime-typed-eq-char-equal", "Char", "Text"),
            ("runtime-typed-eq-day-equal", "Day", "UTCTime"),
            ("runtime-typed-eq-day-of-week-equal", "DayOfWeek", "Day"),
            ("runtime-typed-eq-double-equal", "Double", "Int"),
            ("runtime-typed-eq-either-equal", "Either", "(,)"),
            ("runtime-typed-eq-exit-code-equal", "ExitCode", "Int"),
            ("runtime-typed-eq-int-equal", "Int", "Integer"),
            ("runtime-typed-eq-integer-equal", "Integer", "Int"),
            ("runtime-typed-eq-list-equal", "[]", "Vector"),
            ("runtime-typed-eq-maybe-equal", "Maybe", "Set"),
            ("runtime-typed-eq-set-equal", "Set", "Vector"),
            ("runtime-typed-eq-text-equal", "Text", "ByteString"),
            ("runtime-typed-eq-time-of-day-equal", "TimeOfDay", "UTCTime"),
            ("runtime-typed-eq-tree-equal", "Tree", "Vector"),
            ("runtime-typed-eq-tuple-equal", "(,)", "Either"),
            ("runtime-typed-eq-utc-time-equal", "UTCTime", "Day"),
            ("runtime-typed-eq-vector-equal", "Vector", "[]"),
        ] {
            assert_resolved_instance_substitution(cases, case_id, expected, substituted);
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_resolved_instance_substitution(
        cases: &[crate::DifferentialCase],
        case_id: &str,
        expected: &str,
        substituted: &str,
    ) {
        let case = runtime_case(cases, case_id);
        let source_root = root(&format!("instance-target-source-{expected}"));
        let (success, mut semantic, stdout) =
            execute_runtime_interaction_with_stdout(case, &source_root);
        assert!(success);
        let target_builtin = case
            .claim_evidence
            .as_ref()
            .and_then(|descriptor| {
                descriptor
                    .semantic_targets
                    .iter()
                    .find(|target| target.expected_instance_target.as_deref() == Some(expected))
            })
            .expect("case has an instance-bound target")
            .builtin
            .as_ref();
        let builtin = hell_builtins::lookup(target_builtin)
            .expect("instance-bound builtin remains registry-backed")
            .id;
        let event = semantic
            .obligation_trace
            .iter_mut()
            .find(|event| {
                event.builtin == builtin && event.instance_target.as_deref() == Some(expected)
            })
            .expect("resolved instance-bound event");
        assert_eq!(event.instance_target.as_deref(), Some(expected));
        event.instance_target = Some(Arc::from(substituted));
        assert_rehashed_runtime_semantic_rejected(
            case,
            semantic,
            &stdout,
            true,
            &format!("instance-target-{expected}-to-{substituted}"),
        );

        let trace_path = source_root.join(format!("{}.json", case.id));
        let trace = fs::read_to_string(&trace_path).expect("retained runtime trace");
        assert!(crate::parse_semantic_trace(trace.as_bytes()).is_ok());
        let old_schema = trace.replace("\"schemaVersion\": 10", "\"schemaVersion\": 9");
        assert!(crate::parse_semantic_trace(old_schema.as_bytes()).is_err());
        let field = format!(", \"instanceTarget\": \"{expected}\"");
        let missing = trace.replace(&field, "");
        assert_ne!(missing, trace);
        assert!(crate::parse_semantic_trace(missing.as_bytes()).is_err());
        fs::remove_dir_all(source_root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn monad_return_rejects_rehashed_constructor_raw_and_lazy_substitutions() {
        for case_id in [
            "runtime-typed-monad-return-maybe",
            "runtime-typed-monad-return-list",
            "runtime-typed-monad-return-tree",
            "runtime-typed-monad-return-either",
        ] {
            assert_runtime_typed_substitution_rejected(
                case_id,
                "\"value\":\"42\"",
                "\"value\":\"41\"",
            );
        }

        let cases = crate::committed_differential_cases();
        for case_id in [
            "runtime-typed-monad-return-io",
            "runtime-typed-monad-return-tree",
        ] {
            let case = runtime_case(&cases, case_id);
            let (root, directory) = retain_executed_runtime_case(case, case_id);
            for role in ["candidate", "oracle"] {
                fs::write(directory.join(role).join("stdout.bin"), b"forged\n").unwrap();
            }
            rehash_runtime_bundle(&directory, case);
            assert!(verify_observation_bundle_for_case(&directory, case).is_err());
            fs::remove_dir_all(root).unwrap();
        }

        for (case_id, class) in [
            ("runtime-typed-monad-return-io", "lazy-adapter-entry"),
            ("runtime-typed-monad-return-io", "lazy-adapter-exit"),
            ("runtime-typed-monad-return-either", "lazy-adapter-exit"),
        ] {
            assert_lazy_state_substitution_rejected(&cases, case_id, "Monad.return", class);
        }
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn monad_when_rejects_rehashed_branch_type_raw_and_lazy_substitutions() {
        for (case_id, original, replacement) in [
            (
                "runtime-typed-monad-when-maybe-selected",
                "\"payload\":null",
                "\"payload\":{\"type\":\"Unit\",\"value\":null}",
            ),
            (
                "runtime-typed-monad-when-list-unselected",
                "\"elements\":[{\"type\":\"Unit\",\"value\":null}]",
                "\"elements\":[]",
            ),
            (
                "runtime-typed-monad-when-tree-selected",
                "\"outcome\":\"not-forced\"",
                "\"outcome\":\"value\"",
            ),
            (
                "runtime-typed-monad-when-either-unselected",
                "\"constructor\":\"Right\"",
                "\"constructor\":\"Left\"",
            ),
        ] {
            assert_runtime_typed_substitution_rejected(case_id, original, replacement);
        }

        let cases = crate::committed_differential_cases();
        for instance in ["io", "maybe", "list", "tree", "either"] {
            for branch in ["selected", "unselected"] {
                let case_id = format!("runtime-typed-monad-when-{instance}-{branch}");
                let case = runtime_case(&cases, &case_id);
                let (root, directory) = retain_executed_runtime_case(case, &case_id);
                for role in ["candidate", "oracle"] {
                    fs::write(directory.join(role).join("stdout.bin"), b"forged\n").unwrap();
                }
                rehash_runtime_bundle(&directory, case);
                assert!(verify_observation_bundle_for_case(&directory, case).is_err());
                fs::remove_dir_all(root).unwrap();
            }
        }

        for (case_id, class) in [
            ("runtime-typed-monad-when-io-selected", "lazy-adapter-exit"),
            (
                "runtime-typed-monad-when-io-unselected",
                "lazy-adapter-entry",
            ),
            (
                "runtime-typed-monad-when-either-unselected",
                "lazy-adapter-exit",
            ),
        ] {
            assert_lazy_state_substitution_rejected(&cases, case_id, "Monad.when", class);
        }
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn monad_then_rejects_rehashed_sequence_type_raw_status_and_lazy_substitutions() {
        for (case_id, original, replacement) in [
            (
                "runtime-typed-monad-then-maybe-success",
                "\"value\":\"2\"",
                "\"value\":\"3\"",
            ),
            (
                "runtime-typed-monad-then-either-short-circuit",
                "\"constructor\":\"Left\"",
                "\"constructor\":\"Right\"",
            ),
            (
                "runtime-typed-monad-then-tree-branching",
                "\"value\":\"22\"",
                "\"value\":\"23\"",
            ),
        ] {
            assert_runtime_typed_substitution_rejected(case_id, original, replacement);
        }

        let cases = crate::committed_differential_cases();
        for (instance, branches) in [
            ("io", ["success", "short-circuit"]),
            ("maybe", ["success", "short-circuit"]),
            ("list", ["success", "short-circuit"]),
            ("tree", ["simple", "branching"]),
            ("either", ["success", "short-circuit"]),
        ] {
            for branch in branches {
                let case_id = format!("runtime-typed-monad-then-{instance}-{branch}");
                let case = runtime_case(&cases, &case_id);
                let (root, directory) = retain_executed_runtime_case(case, &case_id);
                for role in ["candidate", "oracle"] {
                    fs::write(directory.join(role).join("stdout.bin"), b"forged\n").unwrap();
                }
                rehash_runtime_bundle(&directory, case);
                assert!(verify_observation_bundle_for_case(&directory, case).is_err());
                fs::remove_dir_all(root).unwrap();
            }
        }

        for case_id in [
            "runtime-typed-monad-then-io-short-circuit",
            "runtime-typed-monad-then-list-short-circuit",
            "runtime-typed-monad-then-tree-branching",
        ] {
            assert_lazy_state_substitution_rejected(
                &cases,
                case_id,
                "Monad.then",
                "lazy-adapter-entry",
            );
        }
        assert_rehashed_process_status_substitution_rejected(
            runtime_case(&cases, "runtime-typed-monad-then-io-short-circuit"),
            "monad-then-io-status",
            (false, 1),
            (true, 0),
        );
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn monad_bind_rejects_rehashed_callback_type_raw_status_and_lazy_substitutions() {
        for (case_id, original, replacement) in [
            (
                "runtime-typed-monad-bind-maybe-success",
                "\"value\":\"3\"",
                "\"value\":\"4\"",
            ),
            (
                "runtime-typed-monad-bind-either-short-circuit",
                "\"constructor\":\"Left\"",
                "\"constructor\":\"Right\"",
            ),
            (
                "runtime-typed-monad-bind-tree-branching",
                "\"value\":\"21\"",
                "\"value\":\"22\"",
            ),
        ] {
            assert_runtime_typed_substitution_rejected(case_id, original, replacement);
        }

        let cases = crate::committed_differential_cases();
        assert_monad_bind_raw_substitutions_rejected(&cases);
        assert_monad_bind_callback_substitutions_rejected(&cases);
        for case_id in [
            "runtime-typed-monad-bind-io-short-circuit",
            "runtime-typed-monad-bind-list-short-circuit",
            "runtime-typed-monad-bind-tree-branching",
        ] {
            assert_lazy_state_substitution_rejected(
                &cases,
                case_id,
                "Monad.bind",
                "lazy-adapter-entry",
            );
        }
        assert_rehashed_process_status_substitution_rejected(
            runtime_case(&cases, "runtime-typed-monad-bind-io-short-circuit"),
            "monad-bind-io-status",
            (false, 1),
            (true, 0),
        );
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_monad_bind_raw_substitutions_rejected(cases: &[crate::DifferentialCase]) {
        for (instance, branches) in [
            ("io", ["success", "short-circuit"]),
            ("maybe", ["success", "short-circuit"]),
            ("list", ["success", "short-circuit"]),
            ("tree", ["simple", "branching"]),
            ("either", ["success", "short-circuit"]),
        ] {
            for branch in branches {
                let case_id = format!("runtime-typed-monad-bind-{instance}-{branch}");
                let case = runtime_case(cases, &case_id);
                let (root, directory) = retain_executed_runtime_case(case, &case_id);
                for role in ["candidate", "oracle"] {
                    fs::write(directory.join(role).join("stdout.bin"), b"forged\n").unwrap();
                }
                rehash_runtime_bundle(&directory, case);
                assert!(verify_observation_bundle_for_case(&directory, case).is_err());
                fs::remove_dir_all(root).unwrap();
            }
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_monad_bind_callback_substitutions_rejected(cases: &[crate::DifferentialCase]) {
        for case_id in [
            "runtime-typed-monad-bind-io-success",
            "runtime-typed-monad-bind-maybe-success",
            "runtime-typed-monad-bind-tree-simple",
            "runtime-typed-monad-bind-either-success",
        ] {
            assert_monad_bind_one_callback_mutations(runtime_case(cases, case_id));
        }
        for case_id in [
            "runtime-typed-monad-bind-list-success",
            "runtime-typed-monad-bind-tree-branching",
        ] {
            let source_root = root(&format!("{case_id}-callback-source"));
            assert_multi_call_callback_contract(
                runtime_case(cases, case_id),
                "Monad.bind",
                case_id,
                &source_root,
            );
            fs::remove_dir_all(source_root).unwrap();
        }
        for (success_id, short_id, process_success) in [
            (
                "runtime-typed-monad-bind-io-success",
                "runtime-typed-monad-bind-io-short-circuit",
                false,
            ),
            (
                "runtime-typed-monad-bind-maybe-success",
                "runtime-typed-monad-bind-maybe-short-circuit",
                true,
            ),
            (
                "runtime-typed-monad-bind-list-success",
                "runtime-typed-monad-bind-list-short-circuit",
                true,
            ),
            (
                "runtime-typed-monad-bind-either-success",
                "runtime-typed-monad-bind-either-short-circuit",
                true,
            ),
        ] {
            assert_monad_bind_injected_callback_rejected(
                runtime_case(cases, success_id),
                runtime_case(cases, short_id),
                process_success,
            );
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_monad_bind_one_callback_mutations(case: &crate::DifferentialCase) {
        let source_root = root(&format!("{}-callback-source", case.id));
        let (success, semantic, stdout) =
            execute_runtime_interaction_with_stdout(case, &source_root);
        assert!(success);
        let mut baseline = semantic.clone();
        let callbacks = callback_events_mut(&mut baseline, "Monad.bind");
        assert_eq!(callbacks.len(), 1);

        let mut omitted = semantic.clone();
        callback_events_mut(&mut omitted, "Monad.bind").clear();
        assert_monad_bind_callback_mutant(case, omitted, &stdout, "omitted");

        let mut duplicated = semantic.clone();
        let callbacks = callback_events_mut(&mut duplicated, "Monad.bind");
        let mut duplicate = callbacks[0].clone();
        duplicate.invocation = 2;
        callbacks.push(duplicate);
        assert_monad_bind_callback_mutant(case, duplicated, &stdout, "duplicated");

        let mut argument = semantic.clone();
        callback_events_mut(&mut argument, "Monad.bind")[0].canonical_arguments[0] =
            Arc::from("{\"type\":\"Int\",\"value\":\"9\"}");
        assert_monad_bind_callback_mutant(case, argument, &stdout, "argument");

        let mut result = semantic;
        callback_events_mut(&mut result, "Monad.bind")[0].canonical_result =
            Arc::from("{\"type\":\"Int\",\"value\":\"9\"}");
        assert_monad_bind_callback_mutant(case, result, &stdout, "result");
        fs::remove_dir_all(source_root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_monad_bind_callback_mutant(
        case: &crate::DifferentialCase,
        semantic: crate::SemanticObservation,
        stdout: &[u8],
        label: &str,
    ) {
        assert_rehashed_runtime_semantic_rejected(
            case,
            semantic,
            stdout,
            true,
            &format!("{}-callback-{label}", case.id),
        );
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_monad_bind_injected_callback_rejected(
        success_case: &crate::DifferentialCase,
        short_case: &crate::DifferentialCase,
        process_success: bool,
    ) {
        let success_root = root(&format!("{}-callback-source", success_case.id));
        let (_, mut success_semantic, _) =
            execute_runtime_interaction_with_stdout(success_case, &success_root);
        let injected = callback_events_mut(&mut success_semantic, "Monad.bind")[0].clone();
        fs::remove_dir_all(success_root).unwrap();

        let short_root = root(&format!("{}-callback-source", short_case.id));
        let (_, mut short_semantic, stdout) =
            execute_runtime_interaction_with_stdout(short_case, &short_root);
        let callbacks = callback_events_mut(&mut short_semantic, "Monad.bind");
        assert!(callbacks.is_empty());
        callbacks.push(injected);
        assert_rehashed_runtime_semantic_rejected(
            short_case,
            short_semantic,
            &stdout,
            process_success,
            &format!("{}-callback-injected", short_case.id),
        );
        fs::remove_dir_all(short_root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn monad_sequence_rejects_rehashed_type_raw_status_and_lazy_substitutions() {
        for (case_id, original, replacement) in [
            (
                "runtime-typed-monad-sequence-maybe-finite",
                "\"value\":\"2\"",
                "\"value\":\"3\"",
            ),
            (
                "runtime-typed-monad-sequence-either-short-circuit",
                "\"constructor\":\"Left\"",
                "\"constructor\":\"Right\"",
            ),
            (
                "runtime-typed-monad-sequence-list-finite",
                "\"value\":\"8\"",
                "\"value\":\"9\"",
            ),
            (
                "runtime-typed-monad-sequence-tree-finite",
                "2276616c7565223a223232227d",
                "2276616c7565223a223233227d",
            ),
        ] {
            assert_runtime_typed_substitution_rejected(case_id, original, replacement);
        }

        let cases = crate::committed_differential_cases();
        for (instance, branches) in [
            ("io", ["finite", "short-circuit"]),
            ("maybe", ["finite", "short-circuit"]),
            ("list", ["finite", "empty"]),
            ("tree", ["finite", "empty"]),
            ("either", ["finite", "short-circuit"]),
        ] {
            for branch in branches {
                let case_id = format!("runtime-typed-monad-sequence-{instance}-{branch}");
                let case = runtime_case(&cases, &case_id);
                let (root, directory) = retain_executed_runtime_case(case, &case_id);
                for role in ["candidate", "oracle"] {
                    fs::write(directory.join(role).join("stdout.bin"), b"forged\n").unwrap();
                }
                rehash_runtime_bundle(&directory, case);
                assert!(verify_observation_bundle_for_case(&directory, case).is_err());
                fs::remove_dir_all(root).unwrap();
            }
        }

        for case_id in [
            "runtime-typed-monad-sequence-io-short-circuit",
            "runtime-typed-monad-sequence-list-empty",
            "runtime-typed-monad-sequence-tree-empty",
        ] {
            assert_lazy_state_substitution_rejected(
                &cases,
                case_id,
                "Monad.sequence",
                "lazy-adapter-entry",
            );
        }
        assert_rehashed_process_status_substitution_rejected(
            runtime_case(&cases, "runtime-typed-monad-sequence-io-short-circuit"),
            "monad-sequence-io-status",
            (false, 1),
            (true, 0),
        );
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn monad_traversals_reject_rehashed_instance_callback_value_and_demand_substitutions() {
        let cases = crate::committed_differential_cases();
        assert_monad_traversal_callback_substitutions(&cases);
        assert_monad_traversal_value_and_raw_substitutions(&cases);
        assert_monad_traversal_demand_and_status_substitutions(&cases);
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_monad_traversal_callback_substitutions(cases: &[crate::DifferentialCase]) {
        for (builtin, slug) in monad_traversal_builtins() {
            for instance in ["io", "maybe", "list", "tree", "either"] {
                let case_id = format!("runtime-typed-{slug}-{instance}-finite");
                let root = root(&format!("{case_id}-callback-source"));
                assert_multi_call_callback_contract(
                    runtime_case(cases, &case_id),
                    builtin,
                    &case_id,
                    &root,
                );
                fs::remove_dir_all(root).unwrap();
            }
            for instance in ["io", "maybe", "either"] {
                let case_id = format!("runtime-typed-{slug}-{instance}-short-circuit");
                assert_one_call_traversal_callback(runtime_case(cases, &case_id), builtin);
            }
            for instance in ["list", "tree"] {
                let finite = format!("runtime-typed-{slug}-{instance}-finite");
                let empty = format!("runtime-typed-{slug}-{instance}-empty");
                assert_zero_call_traversal_callback(
                    runtime_case(cases, &finite),
                    runtime_case(cases, &empty),
                    builtin,
                );
            }
            assert_traversal_callback_argument_index(
                runtime_case(cases, &format!("runtime-typed-{slug}-maybe-finite")),
                builtin,
            );
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_one_call_traversal_callback(case: &crate::DifferentialCase, builtin: &str) {
        let source_root = root(&format!("{}-one-callback", case.id));
        let (_, semantic) = execute_runtime_interaction(case, &source_root);
        assert_eq!(callback_events_mut(&mut semantic.clone(), builtin).len(), 1);
        for label in ["omitted", "duplicated", "argument", "result"] {
            let mut mutant = semantic.clone();
            let callbacks = callback_events_mut(&mut mutant, builtin);
            match label {
                "omitted" => callbacks.clear(),
                "duplicated" => {
                    let mut duplicate = callbacks[0].clone();
                    duplicate.invocation = 2;
                    callbacks.push(duplicate);
                }
                "argument" => {
                    callbacks[0].canonical_arguments[0] =
                        Arc::from("{\"type\":\"Int\",\"value\":\"9\"}");
                }
                "result" => {
                    callbacks[0].canonical_result = Arc::from("{\"type\":\"Int\",\"value\":\"9\"}");
                }
                _ => unreachable!("one-call mutation labels are closed"),
            }
            assert_rehashed_callback_semantic_rejected(
                case,
                mutant,
                &format!("{}-callback-{label}", case.id),
            );
        }
        fs::remove_dir_all(source_root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_zero_call_traversal_callback(
        finite: &crate::DifferentialCase,
        empty: &crate::DifferentialCase,
        builtin: &str,
    ) {
        let finite_root = root(&format!("{}-callback-source", finite.id));
        let (_, mut source) = execute_runtime_interaction(finite, &finite_root);
        let injected = callback_events_mut(&mut source, builtin)[0].clone();
        fs::remove_dir_all(finite_root).unwrap();
        let empty_root = root(&format!("{}-callback-empty", empty.id));
        let (_, mut semantic) = execute_runtime_interaction(empty, &empty_root);
        assert!(callback_events_mut(&mut semantic, builtin).is_empty());
        callback_events_mut(&mut semantic, builtin).push(injected);
        assert_rehashed_callback_semantic_rejected(
            empty,
            semantic,
            &format!("{}-callback-injected", empty.id),
        );
        fs::remove_dir_all(empty_root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_traversal_callback_argument_index(case: &crate::DifferentialCase, builtin: &str) {
        let root = root(&format!("{}-callback-index", case.id));
        let (_, mut semantic) = execute_runtime_interaction(case, &root);
        let callback = &mut callback_events_mut(&mut semantic, builtin)[0];
        callback.callback_argument = u16::from(callback.callback_argument == 0);
        assert_rehashed_callback_semantic_rejected(
            case,
            semantic,
            &format!("{}-callback-index", case.id),
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_monad_traversal_value_and_raw_substitutions(cases: &[crate::DifferentialCase]) {
        for (case_id, original, replacement) in [
            (
                "runtime-typed-monad-mapm-maybe-finite",
                "\"value\":\"12\"",
                "\"value\":\"13\"",
            ),
            (
                "runtime-typed-monad-form-either-short-circuit",
                "\"constructor\":\"Left\"",
                "\"constructor\":\"Right\"",
            ),
            (
                "runtime-typed-monad-mapm-list-finite",
                "\"value\":\"12\"",
                "\"value\":\"13\"",
            ),
            (
                "runtime-typed-monad-form-tree-finite",
                "2276616c7565223a223232227d",
                "2276616c7565223a223233227d",
            ),
            (
                "runtime-typed-monad-mapm-discard-tree-finite",
                "\"outcome\":\"not-forced\"",
                "\"outcome\":\"value\"",
            ),
        ] {
            assert_runtime_typed_substitution_rejected(case_id, original, replacement);
        }
        for (builtin, slug) in monad_traversal_builtins() {
            for (instance, branches) in [
                ("io", ["finite", "short-circuit"]),
                ("maybe", ["finite", "short-circuit"]),
                ("list", ["finite", "empty"]),
                ("tree", ["finite", "empty"]),
                ("either", ["finite", "short-circuit"]),
            ] {
                for branch in branches {
                    let case_id = format!("runtime-typed-{slug}-{instance}-{branch}");
                    let case = runtime_case(cases, &case_id);
                    let (root, directory) = retain_executed_runtime_case(case, &case_id);
                    for role in ["candidate", "oracle"] {
                        fs::write(directory.join(role).join("stdout.bin"), b"forged\n").unwrap();
                    }
                    rehash_runtime_bundle(&directory, case);
                    assert!(
                        verify_observation_bundle_for_case(&directory, case).is_err(),
                        "{builtin} accepted a raw substitution for {case_id}"
                    );
                    fs::remove_dir_all(root).unwrap();
                }
            }
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_monad_traversal_demand_and_status_substitutions(cases: &[crate::DifferentialCase]) {
        for (builtin, slug) in monad_traversal_builtins() {
            for (instance, branch) in [
                ("io", "finite"),
                ("list", "empty"),
                ("tree", "finite"),
                ("tree", "empty"),
            ] {
                let case_id = format!("runtime-typed-{slug}-{instance}-{branch}");
                for class in ["lazy-adapter-entry", "lazy-adapter-exit"] {
                    assert_lazy_state_substitution_rejected(cases, &case_id, builtin, class);
                }
            }
            assert_rehashed_process_status_substitution_rejected(
                runtime_case(cases, &format!("runtime-typed-{slug}-io-short-circuit")),
                &format!("{slug}-io-status"),
                (false, 1),
                (true, 0),
            );
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn monad_traversal_builtins() -> [(&'static str, &'static str); 4] {
        [
            ("Monad.mapM", "monad-mapm"),
            ("Monad.forM", "monad-form"),
            ("Monad.mapM_", "monad-mapm-discard"),
            ("Monad.forM_", "monad-form-discard"),
        ]
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn functor_adapters_reject_rehashed_target_callback_value_and_demand_substitutions() {
        let cases = crate::committed_differential_cases();
        assert_functor_callback_substitutions(&cases);
        assert_functor_value_raw_and_demand_substitutions(&cases);
        assert_functor_target_substitutions(&cases);
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_functor_callback_substitutions(cases: &[crate::DifferentialCase]) {
        for (builtin, slug) in [("Functor.fmap", "fmap"), ("<$>", "operator")] {
            for instance in ["list", "tree"] {
                let case_id = format!("runtime-typed-functor-{slug}-{instance}-mapped");
                let source_root = root(&format!("{case_id}-callbacks"));
                assert_multi_call_callback_contract(
                    runtime_case(cases, &case_id),
                    builtin,
                    &case_id,
                    &source_root,
                );
                fs::remove_dir_all(source_root).unwrap();
            }
            for instance in ["io", "parser", "maybe", "either", "pair"] {
                let case_id = format!("runtime-typed-functor-{slug}-{instance}-mapped");
                assert_one_call_traversal_callback(runtime_case(cases, &case_id), builtin);
            }
            let tree = format!("runtime-typed-functor-{slug}-tree-short");
            assert_one_call_traversal_callback(runtime_case(cases, &tree), builtin);
            for instance in ["list", "io", "parser", "maybe", "either", "pair"] {
                let mapped = format!("runtime-typed-functor-{slug}-{instance}-mapped");
                let short = format!("runtime-typed-functor-{slug}-{instance}-short");
                assert_zero_call_traversal_callback(
                    runtime_case(cases, &mapped),
                    runtime_case(cases, &short),
                    builtin,
                );
            }
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_functor_value_raw_and_demand_substitutions(cases: &[crate::DifferentialCase]) {
        for (builtin, slug) in [("Functor.fmap", "fmap"), ("<$>", "operator")] {
            for instance in ["list", "io", "tree", "maybe", "either", "pair"] {
                for path in ["mapped", "short"] {
                    let case_id = format!("runtime-typed-functor-{slug}-{instance}-{path}");
                    assert_functor_typed_substitution(runtime_case(cases, &case_id), builtin);
                }
            }
            for instance in ["list", "io", "parser", "tree", "maybe", "either", "pair"] {
                for path in ["mapped", "short"] {
                    let case_id = format!("runtime-typed-functor-{slug}-{instance}-{path}");
                    assert_runtime_raw_substitution(runtime_case(cases, &case_id), &case_id);
                }
                let short = format!("runtime-typed-functor-{slug}-{instance}-short");
                for class in ["lazy-adapter-entry", "lazy-adapter-exit"] {
                    assert_lazy_state_substitution_rejected(cases, &short, builtin, class);
                }
            }
            for instance in ["io", "parser"] {
                let case_id = format!("runtime-typed-functor-{slug}-{instance}-short");
                assert_rehashed_process_status_substitution_rejected(
                    runtime_case(cases, &case_id),
                    &format!("{case_id}-status"),
                    (false, 1),
                    (true, 0),
                );
            }
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_functor_typed_substitution(case: &crate::DifferentialCase, builtin: &str) {
        let source_root = root(&format!("{}-typed-source", case.id));
        let (success, mut semantic, stdout) =
            execute_runtime_interaction_with_stdout(case, &source_root);
        let forged: Arc<str> = Arc::from(concat!(
            "{\"type\":\"TypedResult\",\"argument\":0,",
            "\"boundary\":\"adapter-result\",",
            "\"value\":{\"type\":\"Int\",\"value\":\"999\"}}"
        ));
        assert!(semantic.typed_result_canonical.is_some());
        semantic.typed_result_sha256 = Some(sha256_bytes(forged.as_bytes()));
        semantic.typed_result_canonical = Some(forged);
        assert_rehashed_runtime_semantic_rejected(
            case,
            semantic,
            &stdout,
            success,
            &format!("{}-{builtin}-typed", case.id),
        );
        fs::remove_dir_all(source_root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_runtime_raw_substitution(case: &crate::DifferentialCase, name: &str) {
        let (root, directory) = retain_executed_runtime_case(case, name);
        for role in ["candidate", "oracle"] {
            fs::write(directory.join(role).join("stdout.bin"), b"forged\n").unwrap();
        }
        rehash_runtime_bundle(&directory, case);
        assert!(
            verify_observation_bundle_for_case(&directory, case).is_err(),
            "{name} accepted a raw substitution"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_functor_target_substitutions(cases: &[crate::DifferentialCase]) {
        for (case_id, original, replacement) in [
            (
                "runtime-typed-functor-fmap-maybe-mapped",
                "Functor.fmap",
                "<$>",
            ),
            (
                "runtime-typed-functor-operator-maybe-mapped",
                "<$>",
                "Functor.fmap",
            ),
        ] {
            let case = runtime_case(cases, case_id);
            let source_root = root(&format!("{case_id}-target-source"));
            let (success, mut semantic, stdout) =
                execute_runtime_interaction_with_stdout(case, &source_root);
            let original = hell_builtins::lookup(original).unwrap().id;
            let replacement = hell_builtins::lookup(replacement).unwrap().id;
            semantic
                .obligation_trace
                .iter_mut()
                .find(|event| event.builtin == original)
                .expect("Functor target event")
                .builtin = replacement;
            assert_rehashed_runtime_semantic_rejected(
                case,
                semantic,
                &stdout,
                success,
                &format!("{case_id}-target-substitution"),
            );
            fs::remove_dir_all(source_root).unwrap();
        }
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn map_ordering_interaction_rejects_rehashed_comparator_dependency_substitutions() {
        let cases = crate::committed_differential_cases();
        let case = runtime_case(&cases, "runtime-interaction-map-ordering-custom-ord");
        let source_root = root("map-ordering-dependency-source");
        let (success, semantic, stdout) =
            execute_runtime_interaction_with_stdout(case, &source_root);
        assert!(success);
        let map = hell_builtins::lookup("Map.fromList").unwrap().id;
        let less = hell_builtins::lookup("Ord.lt").unwrap().id;
        let map_event = semantic
            .obligation_trace
            .iter()
            .find(|event| event.builtin == map)
            .expect("Map.fromList target event");
        let less_index = semantic
            .obligation_trace
            .iter()
            .position(|event| {
                event.builtin == less
                    && event.owner_task == map_event.owner_task
                    && event.parent_sequence == Some(map_event.sequence)
            })
            .expect("causally delegated Ord.lt event");
        let map_index = semantic
            .obligation_trace
            .iter()
            .position(|event| event.builtin == map)
            .expect("Map.fromList target event index");

        let mut ordinal = semantic.clone();
        ordinal.obligation_trace[map_index].comparators[0].direct_child_ordinal = 2;
        assert_rehashed_runtime_semantic_rejected(
            case,
            ordinal,
            &stdout,
            true,
            "map-ordering-comparator-child-ordinal",
        );

        let mut non_ord = semantic.clone();
        non_ord.obligation_trace[map_index].comparators[0].comparator =
            hell_builtins::lookup("$").unwrap().id;
        assert_rehashed_runtime_semantic_rejected(
            case,
            non_ord,
            &stdout,
            true,
            "map-ordering-comparator-non-ord-child",
        );

        let mut unmarked_ord = semantic.clone();
        let mut injected = unmarked_ord.obligation_trace[less_index].clone();
        injected.sequence = unmarked_ord
            .obligation_trace
            .iter()
            .map(|event| event.sequence)
            .max()
            .unwrap()
            .saturating_add(1);
        injected.parent_sequence = Some(unmarked_ord.obligation_trace[map_index].sequence);
        unmarked_ord.obligation_trace[map_index].nested_adapters = unmarked_ord.obligation_trace
            [map_index]
            .nested_adapters
            .saturating_add(1);
        unmarked_ord.obligation_trace.push(injected);
        assert_rehashed_runtime_semantic_rejected(
            case,
            unmarked_ord,
            &stdout,
            true,
            "map-ordering-unmarked-direct-ord-child",
        );

        let mut parent = semantic.clone();
        parent.obligation_trace[less_index].parent_sequence = None;
        assert_rehashed_runtime_semantic_rejected(
            case,
            parent,
            &stdout,
            true,
            "map-ordering-comparator-parent",
        );

        let mut instance = semantic.clone();
        instance.obligation_trace[less_index].instance_target = Some(Arc::from("Text"));
        assert_rehashed_runtime_semantic_rejected(
            case,
            instance,
            &stdout,
            true,
            "map-ordering-comparator-instance",
        );

        let mut outcome = semantic;
        outcome.obligation_trace[less_index].outcome = Arc::from("error");
        assert_rehashed_runtime_semantic_rejected(
            case,
            outcome,
            &stdout,
            true,
            "map-ordering-comparator-outcome",
        );
        fs::remove_dir_all(source_root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn semantic_fuzz_target_observation_trace_calls_the_exact_production_decoder() {
        let cases = crate::committed_differential_cases();
        let case = runtime_case(&cases, "runtime-typed-alternative-optional-maybe-just");
        let source_root = root("semantic-trace-fuzz");
        let (success, _, _) = execute_runtime_interaction_with_stdout(case, &source_root);
        assert!(success);
        let trace = fs::read(source_root.join(format!("{}.json", case.id))).unwrap();
        assert!(crate::parse_semantic_trace(&trace).is_ok());
        for index in (0..trace.len()).step_by(trace.len().div_ceil(256)) {
            let mut mutated = trace.clone();
            mutated[index] = 0;
            let outcome = std::panic::catch_unwind(|| crate::parse_semantic_trace(&mutated));
            assert!(outcome.is_ok(), "semantic trace parser panicked at {index}");
            assert!(
                outcome.unwrap().is_err(),
                "semantic trace parser accepted a NUL at {index}"
            );
        }
        fs::remove_dir_all(source_root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_descriptor_instance_field_is_schema_bound(case: &crate::DifferentialCase) {
        for (name, mutate) in [
            (
                "descriptor-v6-with-instance",
                (|descriptor: String| {
                    descriptor.replacen("schema_version = 8", "schema_version = 7", 1)
                }) as fn(String) -> String,
            ),
            ("descriptor-v7-missing-instance", |descriptor: String| {
                descriptor.replace("expected_instance_target = \"Maybe\"\n", "")
            }),
            ("descriptor-v7-missing-premises", |descriptor: String| {
                descriptor.replace("expected_instance_premises = []\n", "")
            }),
            (
                "descriptor-v7-extra-direct-premise",
                |descriptor: String| {
                    descriptor.replacen(
                        "expected_instance_premises = []",
                        "expected_instance_premises = [\"Int/0\"]",
                        1,
                    )
                },
            ),
        ] {
            let (root, directory) = retain_executed_runtime_case(case, name);
            let path = directory.join("case.toml");
            let descriptor = fs::read_to_string(&path).expect("retained descriptor");
            assert!(descriptor.starts_with("schema_version = 8\n"));
            assert!(descriptor.contains("expected_instance_target = \"Maybe\"\n"));
            assert!(descriptor.contains("expected_instance_premises = []\n"));
            let changed = mutate(descriptor.clone());
            assert_ne!(changed, descriptor);
            fs::write(&path, changed).expect("write descriptor mutant");
            rewrite_bundle_file_digest(&directory, "case.toml");
            assert!(verify_observation_bundle_for_case(&directory, case).is_err());
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn retained_case_binds_the_reviewed_runtime_completion_expectation() {
        let cases = crate::committed_differential_cases();
        let case = runtime_case(&cases, "runtime-typed-alternative-optional-maybe-just");
        assert!(case.expected_runtime_completion);
        let (root, directory) = retain_executed_runtime_case(case, "runtime-completion-binding");
        let path = directory.join("case.toml");
        let descriptor = fs::read_to_string(&path).unwrap();
        let changed = descriptor.replacen(
            "expected_runtime_completion = true",
            "expected_runtime_completion = false",
            1,
        );
        assert_ne!(changed, descriptor);
        fs::write(&path, changed).unwrap();
        rewrite_bundle_file_digest(&directory, "case.toml");
        assert!(verify_observation_bundle_for_case(&directory, case).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn retained_recursive_instance_preorder_rejects_every_trace_and_wire_substitution() {
        let cases = crate::committed_differential_cases();
        let mut case = runtime_case(&cases, "runtime-io-print-success").clone();
        let source = concat!(
            "main = IO.print ",
            "(Either.Left (Maybe.Just 1) :: Either (Maybe Int) (Int, Int))\n",
        );
        case.id = Arc::from("recursive-instance-premise-trace");
        case.source = Arc::from(source);
        let expected = vec![
            crate::InstancePremiseEvidence {
                target: Arc::from("Maybe"),
                premise_count: 1,
            },
            crate::InstancePremiseEvidence {
                target: Arc::from("Int"),
                premise_count: 0,
            },
            crate::InstancePremiseEvidence {
                target: Arc::from("(,)"),
                premise_count: 2,
            },
            crate::InstancePremiseEvidence {
                target: Arc::from("Int"),
                premise_count: 0,
            },
            crate::InstancePremiseEvidence {
                target: Arc::from("Int"),
                premise_count: 0,
            },
        ];
        {
            let descriptor = case.claim_evidence.as_mut().expect("IO.print descriptor");
            descriptor.source_sha256 = crate::sha256_bytes(source.as_bytes());
            for target in &mut descriptor.semantic_targets {
                target.expected_instance_target = Some(Arc::from("Either"));
                target.expected_instance_premises.clone_from(&expected);
            }
        }

        let trace_root = root("recursive-instance-premise-trace");
        let (success, semantic, _) = execute_runtime_interaction_with_stdout(&case, &trace_root);
        assert!(success);
        let builtin = hell_builtins::lookup("IO.print").unwrap().id;
        let descriptor = case.claim_evidence.as_ref().expect("IO.print descriptor");
        for target in &descriptor.semantic_targets {
            validate_expected_instance_target(target, builtin, &semantic.obligation_trace)
                .expect("compiler-produced recursive premise preorder matches the descriptor");
        }

        let matching = semantic
            .obligation_trace
            .iter()
            .enumerate()
            .filter_map(|(index, event)| (event.builtin == builtin).then_some(index))
            .collect::<Vec<_>>();
        assert!(!matching.is_empty());
        let target = &descriptor.semantic_targets[0];
        for index in matching {
            for (name, mutate) in [
                (
                    "omitted",
                    (|premises: &mut Vec<crate::InstancePremiseEvidence>| {
                        premises.pop();
                    }) as fn(&mut Vec<crate::InstancePremiseEvidence>),
                ),
                ("extra", |premises| {
                    premises.push(crate::InstancePremiseEvidence {
                        target: Arc::from("Text"),
                        premise_count: 0,
                    });
                }),
                ("reordered", |premises| premises.swap(0, 1)),
                ("leaf-substituted", |premises| {
                    premises.last_mut().unwrap().target = Arc::from("Text");
                }),
                ("count-substituted", |premises| {
                    premises.last_mut().unwrap().premise_count = 1;
                }),
            ] {
                let mut changed = semantic.obligation_trace.clone();
                mutate(&mut changed[index].instance_premises);
                assert!(
                    validate_expected_instance_target(target, builtin, &changed).is_err(),
                    "retained verifier accepted {name} premise evidence at event {index}"
                );
            }
        }

        let trace_path = trace_root.join(format!("{}.json", case.id));
        let trace = fs::read_to_string(&trace_path).unwrap();
        let old_schema = trace.replacen("\"schemaVersion\": 10", "\"schemaVersion\": 9", 1);
        assert!(crate::parse_semantic_trace(old_schema.as_bytes()).is_err());
        let missing_premises = trace.replacen("\"instancePremises\": [", "\"premises\": [", 1);
        assert!(crate::parse_semantic_trace(missing_premises.as_bytes()).is_err());
        fs::remove_dir_all(trace_root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn retained_eq_matrix_executes_every_reviewed_instance_and_shape_path() {
        let cases = crate::committed_differential_cases();
        let eq_cases = cases
            .iter()
            .filter(|case| {
                case.id.starts_with("runtime-typed-eq-")
                    && case.claim_evidence.as_ref().is_some_and(|descriptor| {
                        descriptor.semantic_targets.iter().any(|target| {
                            target.builtin.as_ref() == "Eq.eq"
                                && target.expected_instance_target.is_some()
                        })
                    })
            })
            .collect::<Vec<_>>();
        assert_eq!(eq_cases.len(), 64);
        for case in eq_cases {
            let name = format!("retained-{}", case.id);
            let (root, _) = retain_executed_runtime_case(case, &name);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn retained_eq_matrix_rejects_instance_result_transport_and_demand_substitutions() {
        let cases = crate::committed_differential_cases();
        assert_eq_instance_plan_substitutions(&cases);
        assert_eq_result_transport_and_demand_substitutions(&cases);
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn retained_eq_list_boundary_matrix_executes_every_reviewed_instance_and_path() {
        let cases = crate::committed_differential_cases();
        let eq_list_cases = cases
            .iter()
            .filter(|case| case.id.starts_with("runtime-eq-list-"))
            .collect::<Vec<_>>();
        assert_eq!(eq_list_cases.len(), 920);
        for case in eq_list_cases {
            let name = format!("retained-{}", case.id);
            let (root, _) = retain_executed_runtime_case(case, &name);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn retained_eq_list_boundary_matrix_rejects_scope_result_and_demand_substitutions() {
        let cases = crate::committed_differential_cases();
        assert_eq_list_instance_substitutions(&cases);
        assert_eq_list_plan_substitutions(&cases);
        assert_eq_list_transport_substitutions(&cases);
        assert_eq_list_demand_substitutions(&cases);
        assert_eq_list_boundary_substitutions(&cases);
    }

    #[cfg(feature = "compat-tracing")]
    fn eq_list_targets() -> [(&'static str, &'static str); 10] {
        [
            ("lookup", "List.lookup"),
            ("elem", "List.elem"),
            ("notelem", "List.notElem"),
            ("elemindex", "List.elemIndex"),
            ("elemindices", "List.elemIndices"),
            ("group", "List.group"),
            ("isinfixof", "List.isInfixOf"),
            ("isprefixof", "List.isPrefixOf"),
            ("issubsequenceof", "List.isSubsequenceOf"),
            ("issuffixof", "List.isSuffixOf"),
        ]
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_eq_list_instance_substitutions(cases: &[crate::DifferentialCase]) {
        for (slug, _) in eq_list_targets() {
            for (instance, expected, substituted) in singleton_instance_substitutions() {
                assert_resolved_instance_substitution(
                    cases,
                    &format!("runtime-eq-list-{slug}-{instance}-singleton-input"),
                    expected,
                    substituted,
                );
            }
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_eq_list_plan_substitutions(cases: &[crate::DifferentialCase]) {
        let replacements = eq_list_targets().map(|(_, builtin)| {
            hell_builtins::lookup(builtin)
                .expect("Eq/List target remains registry-backed")
                .id
        });
        for (index, (slug, builtin)) in eq_list_targets().into_iter().enumerate() {
            let case_id = format!("runtime-eq-list-{slug}-either-finite-input");
            let case = runtime_case(cases, &case_id);
            let source_root = root(&format!("{case_id}-plan-source"));
            let (success, semantic, stdout) =
                execute_runtime_interaction_with_stdout(case, &source_root);
            assert!(success);
            let builtin_id = hell_builtins::lookup(builtin).unwrap().id;
            assert_eq_list_premise_mutants(case, &semantic, &stdout, builtin_id, slug);

            let mut changed = semantic;
            changed
                .obligation_trace
                .iter_mut()
                .find(|event| event.builtin == builtin_id)
                .expect("Eq/List target event")
                .builtin = replacements[(index + 1) % replacements.len()];
            assert_rehashed_runtime_semantic_rejected(
                case,
                changed,
                &stdout,
                true,
                &format!("{case_id}-target"),
            );
            fs::remove_dir_all(source_root).unwrap();
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_eq_list_premise_mutants(
        case: &crate::DifferentialCase,
        semantic: &crate::SemanticObservation,
        stdout: &[u8],
        builtin: hell_builtins::BuiltinId,
        slug: &str,
    ) {
        for (name, mutate) in [
            (
                "root",
                (|event: &mut crate::ObligationTraceEvent| {
                    event.instance_target = Some(Arc::from("(,)"));
                }) as fn(&mut crate::ObligationTraceEvent),
            ),
            ("premise-omitted", |event| {
                event.instance_premises.pop();
            }),
            ("premise-extra", |event| {
                event
                    .instance_premises
                    .push(crate::InstancePremiseEvidence {
                        target: Arc::from("Bool"),
                        premise_count: 0,
                    });
            }),
            ("premise-reordered", |event| {
                event.instance_premises.swap(0, 1);
            }),
            ("premise-substituted", |event| {
                event.instance_premises[1].target = Arc::from("Bool");
            }),
            ("premise-count", |event| {
                event.instance_premises[1].premise_count = 1;
            }),
        ] {
            let mut changed = semantic.clone();
            mutate(
                changed
                    .obligation_trace
                    .iter_mut()
                    .find(|event| event.builtin == builtin)
                    .expect("Eq/List premise event"),
            );
            assert_rehashed_runtime_semantic_rejected(
                case,
                changed,
                stdout,
                true,
                &format!("eq-list-{slug}-{name}"),
            );
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_eq_list_transport_substitutions(cases: &[crate::DifferentialCase]) {
        for (case_id, original, replacement) in [
            (
                "runtime-eq-list-lookup-int-finite-input",
                "63686f73656e",
                "666f72676564",
            ),
            (
                "runtime-eq-list-elem-int-finite-input",
                "\"value\":true",
                "\"value\":false",
            ),
            (
                "runtime-eq-list-notelem-int-finite-input",
                "\"value\":false",
                "\"value\":true",
            ),
            (
                "runtime-eq-list-elemindex-int-finite-input",
                "\"value\":\"1\"",
                "\"value\":\"0\"",
            ),
            (
                "runtime-eq-list-elemindices-int-finite-input",
                "\"value\":\"3\"",
                "\"value\":\"2\"",
            ),
            (
                "runtime-eq-list-group-int-finite-input",
                "\"value\":\"42\"",
                "\"value\":\"43\"",
            ),
            (
                "runtime-eq-list-isinfixof-int-finite-input",
                "\"value\":true",
                "\"value\":false",
            ),
            (
                "runtime-eq-list-isprefixof-int-finite-input",
                "\"value\":true",
                "\"value\":false",
            ),
            (
                "runtime-eq-list-issubsequenceof-int-finite-input",
                "\"value\":true",
                "\"value\":false",
            ),
            (
                "runtime-eq-list-issuffixof-int-finite-input",
                "\"value\":true",
                "\"value\":false",
            ),
        ] {
            assert_runtime_typed_substitution_rejected(case_id, original, replacement);
            let case = runtime_case(cases, case_id);
            assert_runtime_raw_substitution(case, &format!("{case_id}-raw"));
            assert_rehashed_process_status_substitution_rejected(
                case,
                &format!("{case_id}-status"),
                (true, 0),
                (false, 1),
            );
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_eq_list_demand_substitutions(cases: &[crate::DifferentialCase]) {
        for (slug, builtin, classes) in [
            (
                "lookup",
                "List.lookup",
                &[(0, "lazy-adapter-entry"), (1, "whnf-force-complete")][..],
            ),
            (
                "elem",
                "List.elem",
                &[(0, "lazy-adapter-entry"), (1, "whnf-force-complete")],
            ),
            (
                "notelem",
                "List.notElem",
                &[(0, "lazy-adapter-entry"), (1, "whnf-force-complete")],
            ),
            (
                "elemindex",
                "List.elemIndex",
                &[(0, "lazy-adapter-entry"), (1, "whnf-force-complete")],
            ),
            (
                "elemindices",
                "List.elemIndices",
                &[(0, "lazy-adapter-entry"), (1, "whnf-force-complete")],
            ),
            ("group", "List.group", &[(0, "whnf-force-complete")]),
            (
                "isinfixof",
                "List.isInfixOf",
                &[(0, "lazy-adapter-entry"), (1, "lazy-adapter-entry")],
            ),
            (
                "isprefixof",
                "List.isPrefixOf",
                &[(0, "lazy-adapter-entry"), (1, "lazy-adapter-entry")],
            ),
            (
                "issubsequenceof",
                "List.isSubsequenceOf",
                &[(0, "lazy-adapter-entry"), (1, "lazy-adapter-entry")],
            ),
            (
                "issuffixof",
                "List.isSuffixOf",
                &[(0, "lazy-adapter-entry"), (1, "lazy-adapter-entry")],
            ),
        ] {
            let case_id = format!("runtime-eq-list-{slug}-int-finite-input");
            for (argument, class) in classes {
                assert_demand_argument_state_substitution_rejected(
                    cases, &case_id, builtin, *argument, class,
                );
            }
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_eq_list_boundary_substitutions(cases: &[crate::DifferentialCase]) {
        for (slug, _) in eq_list_targets() {
            let case_id = format!("runtime-eq-list-{slug}-int-finite-input");
            let case = runtime_case(cases, &case_id);
            let (root, directory) =
                retain_executed_runtime_case(case, &format!("{case_id}-boundary"));
            let path = directory.join("case.toml");
            let document = fs::read_to_string(&path).unwrap();
            let changed = document.replacen("\"finite-input\"", "\"singleton-input\"", 1);
            assert_ne!(
                changed, document,
                "{case_id} boundary mutation did not match"
            );
            fs::write(&path, changed).unwrap();
            rewrite_bundle_file_digest(&directory, "case.toml");
            assert!(verify_observation_bundle_for_case(&directory, case).is_err());
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_eq_instance_plan_substitutions(cases: &[crate::DifferentialCase]) {
        let case = runtime_case(cases, "runtime-typed-eq-either-payload");
        let source_root = root("eq-instance-plan-substitution-source");
        let (success, semantic, stdout) =
            execute_runtime_interaction_with_stdout(case, &source_root);
        assert!(success);
        let builtin = hell_builtins::lookup("Eq.eq").unwrap().id;
        for (name, mutate) in [
            (
                "root",
                (|event: &mut crate::ObligationTraceEvent| {
                    event.instance_target = Some(Arc::from("(,)"));
                }) as fn(&mut crate::ObligationTraceEvent),
            ),
            ("premise-omitted", |event| {
                event.instance_premises.pop();
            }),
            ("premise-extra", |event| {
                event
                    .instance_premises
                    .push(crate::InstancePremiseEvidence {
                        target: Arc::from("Bool"),
                        premise_count: 0,
                    });
            }),
            ("premise-reordered", |event| {
                event.instance_premises.swap(0, 1);
            }),
            ("premise-substituted", |event| {
                event.instance_premises[1].target = Arc::from("Bool");
            }),
            ("premise-count", |event| {
                event.instance_premises[1].premise_count = 1;
            }),
        ] {
            let mut changed = semantic.clone();
            mutate(
                changed
                    .obligation_trace
                    .iter_mut()
                    .find(|event| event.builtin == builtin)
                    .expect("Eq.eq trace event"),
            );
            assert_rehashed_runtime_semantic_rejected(
                case,
                changed,
                &stdout,
                true,
                &format!("eq-{name}"),
            );
        }

        let mut cross_builtin = semantic;
        cross_builtin
            .obligation_trace
            .iter_mut()
            .find(|event| event.builtin == builtin)
            .expect("Eq.eq trace event")
            .builtin = hell_builtins::lookup("Ord.lt").unwrap().id;
        assert_rehashed_runtime_semantic_rejected(
            case,
            cross_builtin,
            &stdout,
            true,
            "eq-to-ord-target",
        );
        fs::remove_dir_all(source_root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_eq_result_transport_and_demand_substitutions(cases: &[crate::DifferentialCase]) {
        for (case_id, forged_result) in [
            ("runtime-typed-eq-tree-equal", false),
            ("runtime-typed-eq-tree-child", true),
        ] {
            assert_eq_boolean_substitution(runtime_case(cases, case_id), forged_result);
            assert_runtime_raw_substitution(
                runtime_case(cases, case_id),
                &format!("{case_id}-raw"),
            );
        }
        let equal = runtime_case(cases, "runtime-typed-eq-tree-equal");
        assert_rehashed_process_status_substitution_rejected(
            equal,
            "eq-status",
            (true, 0),
            (false, 1),
        );
        for argument in [0, 1] {
            assert_demand_argument_state_substitution_rejected(
                cases,
                "runtime-typed-eq-tuple-early-mismatch",
                "Eq.eq",
                argument,
                "whnf-force-complete",
            );
        }

        let invalid = runtime_case(cases, "runtime-typed-eq-byte-string-invalid-equal");
        let (root, directory) = retain_executed_runtime_case(invalid, "eq-invalid-input");
        fs::write(directory.join("stdin.bin"), [0xff, b'A', 0xff, b'B']).unwrap();
        rehash_runtime_bundle(&directory, invalid);
        assert!(verify_observation_bundle_for_case(&directory, invalid).is_err());
        fs::remove_dir_all(root).unwrap();
        assert_eq_injected_callback_rejected(cases);
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_eq_boolean_substitution(case: &crate::DifferentialCase, forged_result: bool) {
        let source_root = root(&format!("{}-result-substitution", case.id));
        let (success, mut semantic, stdout) =
            execute_runtime_interaction_with_stdout(case, &source_root);
        assert!(success);
        let forged: Arc<str> = Arc::from(format!(
            "{{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",\"value\":{{\"type\":\"Bool\",\"value\":{forged_result}}}}}"
        ));
        semantic.typed_result_sha256 = Some(crate::sha256_bytes(forged.as_bytes()));
        semantic.typed_result_canonical = Some(forged);
        assert_rehashed_runtime_semantic_rejected(
            case,
            semantic,
            &stdout,
            true,
            &format!("{}-typed-result", case.id),
        );
        fs::remove_dir_all(source_root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_eq_injected_callback_rejected(cases: &[crate::DifferentialCase]) {
        let callback_case = runtime_case(cases, "runtime-typed-functor-fmap-maybe-mapped");
        let callback_root = root("eq-callback-source");
        let (_, mut callback_semantic) = execute_runtime_interaction(callback_case, &callback_root);
        let injected = callback_events_mut(&mut callback_semantic, "Functor.fmap")[0].clone();
        fs::remove_dir_all(callback_root).unwrap();

        let case = runtime_case(cases, "runtime-typed-eq-maybe-nothing-equal");
        let source_root = root("eq-callback-injection");
        let (success, mut semantic, stdout) =
            execute_runtime_interaction_with_stdout(case, &source_root);
        assert!(callback_events_mut(&mut semantic, "Eq.eq").is_empty());
        callback_events_mut(&mut semantic, "Eq.eq").push(injected);
        assert_rehashed_runtime_semantic_rejected(
            case,
            semantic,
            &stdout,
            success,
            "eq-callback-injected",
        );
        fs::remove_dir_all(source_root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn retained_ord_matrix_executes_every_reviewed_instance_and_ordering_path() {
        let cases = crate::committed_differential_cases();
        let ord_cases = cases
            .iter()
            .filter(|case| {
                case.id.starts_with("runtime-typed-ord-")
                    && case.claim_evidence.as_ref().is_some_and(|descriptor| {
                        descriptor.semantic_targets.iter().any(|target| {
                            matches!(target.builtin.as_ref(), "Ord.lt" | "Ord.gt")
                                && target.expected_instance_target.is_some()
                        })
                    })
            })
            .collect::<Vec<_>>();
        assert_eq!(ord_cases.len(), 144);
        for case in ord_cases {
            let name = format!("retained-{}", case.id);
            let (root, _) = retain_executed_runtime_case(case, &name);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn retained_singleton_constructor_matrix_executes_every_ord_scope_and_strictness_path() {
        let cases = crate::committed_differential_cases();
        let singleton_cases = cases
            .iter()
            .filter(|case| {
                case.id.starts_with("runtime-typed-map-singleton-")
                    || case.id.starts_with("runtime-typed-set-singleton-")
            })
            .collect::<Vec<_>>();
        assert_eq!(singleton_cases.len(), 43);
        for case in singleton_cases {
            let name = format!("retained-{}", case.id);
            let (root, _) = retain_executed_runtime_case(case, &name);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn retained_singleton_constructors_reject_scope_transport_demand_and_resource_mutants() {
        let cases = crate::committed_differential_cases();
        assert_singleton_instance_mutants(&cases);
        assert_singleton_premise_mutants(&cases);
        assert_singleton_target_and_transport_mutants(&cases);
        assert_singleton_demand_mutants(&cases);
        assert_singleton_resource_and_platform_mutants(&cases);
    }

    #[cfg(feature = "compat-tracing")]
    fn singleton_instance_substitutions() -> [(&'static str, &'static str, &'static str); 20] {
        [
            ("bool", "Bool", "Int"),
            ("byte-string", "ByteString", "Text"),
            ("char", "Char", "Text"),
            ("day", "Day", "UTCTime"),
            ("day-of-week", "DayOfWeek", "Day"),
            ("double", "Double", "Int"),
            ("exit-code", "ExitCode", "Int"),
            ("int", "Int", "Integer"),
            ("integer", "Integer", "Int"),
            ("text", "Text", "ByteString"),
            ("time-of-day", "TimeOfDay", "UTCTime"),
            ("utc-time", "UTCTime", "Day"),
            ("tuple", "(,)", "Either"),
            ("ci", "CI", "Maybe"),
            ("either", "Either", "(,)"),
            ("maybe", "Maybe", "Set"),
            ("set", "Set", "Vector"),
            ("tree", "Tree", "Vector"),
            ("vector", "Vector", "[]"),
            ("list", "[]", "Vector"),
        ]
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_singleton_instance_mutants(cases: &[crate::DifferentialCase]) {
        for builtin in ["map-singleton", "set-singleton"] {
            for (slug, expected, substituted) in singleton_instance_substitutions() {
                assert_resolved_instance_substitution(
                    cases,
                    &format!("runtime-typed-{builtin}-{slug}"),
                    expected,
                    substituted,
                );
            }
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_singleton_premise_mutants(cases: &[crate::DifferentialCase]) {
        for builtin in ["map-singleton", "set-singleton"] {
            for slug in [
                "ci", "either", "list", "maybe", "set", "tree", "tuple", "vector",
            ] {
                let case_id = format!("runtime-typed-{builtin}-{slug}");
                let case = runtime_case(cases, &case_id);
                let source_root = root(&format!("{case_id}-premise-source"));
                let (success, mut semantic, stdout) =
                    execute_runtime_interaction_with_stdout(case, &source_root);
                let target = singleton_obligation_event_mut(&mut semantic, builtin);
                assert!(!target.instance_premises.is_empty());
                target.instance_premises.pop();
                assert_rehashed_runtime_semantic_rejected(
                    case,
                    semantic,
                    &stdout,
                    success,
                    &format!("{case_id}-premise-omitted"),
                );
                fs::remove_dir_all(source_root).unwrap();
            }
        }
        for builtin in ["map-singleton", "set-singleton"] {
            assert_singleton_branching_premise_mutants(cases, builtin);
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_singleton_branching_premise_mutants(
        cases: &[crate::DifferentialCase],
        builtin: &str,
    ) {
        let case_id = format!("runtime-typed-{builtin}-either");
        let case = runtime_case(cases, &case_id);
        let source_root = root(&format!("{case_id}-premise-structure"));
        let (success, semantic, stdout) =
            execute_runtime_interaction_with_stdout(case, &source_root);
        for (name, mutate) in [
            (
                "extra",
                (|event: &mut crate::ObligationTraceEvent| {
                    event
                        .instance_premises
                        .push(crate::InstancePremiseEvidence {
                            target: Arc::from("Bool"),
                            premise_count: 0,
                        });
                }) as fn(&mut crate::ObligationTraceEvent),
            ),
            ("reordered", |event| event.instance_premises.swap(0, 1)),
            ("substituted", |event| {
                event.instance_premises[1].target = Arc::from("Bool");
            }),
            ("count", |event| {
                event.instance_premises[1].premise_count = 1;
            }),
        ] {
            let mut changed = semantic.clone();
            mutate(singleton_obligation_event_mut(&mut changed, builtin));
            assert_rehashed_runtime_semantic_rejected(
                case,
                changed,
                &stdout,
                success,
                &format!("{case_id}-premise-{name}"),
            );
        }
        fs::remove_dir_all(source_root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn singleton_obligation_event_mut<'a>(
        semantic: &'a mut crate::SemanticObservation,
        builtin: &str,
    ) -> &'a mut crate::ObligationTraceEvent {
        let builtin = singleton_builtin_name(builtin);
        let builtin = hell_builtins::lookup(builtin)
            .expect("singleton target is registry-backed")
            .id;
        semantic
            .obligation_trace
            .iter_mut()
            .find(|event| event.builtin == builtin)
            .expect("singleton obligation event")
    }

    #[cfg(feature = "compat-tracing")]
    fn singleton_builtin_name(slug: &str) -> &'static str {
        match slug {
            "map-singleton" => "Map.singleton",
            "set-singleton" => "Set.singleton",
            _ => panic!("unknown singleton builtin slug {slug}"),
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_singleton_target_and_transport_mutants(cases: &[crate::DifferentialCase]) {
        for (case_id, original, replacement) in [
            (
                "runtime-typed-map-singleton-key-strict",
                "Map.singleton",
                "Set.singleton",
            ),
            (
                "runtime-typed-map-singleton-value-nonforce",
                "Map.singleton",
                "Set.singleton",
            ),
            (
                "runtime-typed-set-singleton-element-strict",
                "Set.singleton",
                "Map.singleton",
            ),
        ] {
            assert_singleton_target_mutant(cases, case_id, original, replacement);
        }
        let map = runtime_case(cases, "runtime-typed-map-singleton-int");
        assert_singleton_typed_mutant(
            map,
            "{\"key\":{\"type\":\"Int\",\"value\":\"-42\"},\"value\":{\"type\":\"Text\",\"utf8Hex\":\"7061796c6f61642d696e74\"}}",
            "{\"key\":{\"type\":\"Text\",\"utf8Hex\":\"7061796c6f61642d696e74\"},\"value\":{\"type\":\"Int\",\"value\":\"-42\"}}",
        );
        assert_singleton_typed_mutant(
            runtime_case(cases, "runtime-typed-set-singleton-int"),
            "{\"type\":\"Int\",\"value\":\"-42\"}",
            "{\"type\":\"Int\",\"value\":\"-41\"}",
        );
        for builtin in ["map-singleton", "set-singleton"] {
            for (slug, _, _) in singleton_instance_substitutions() {
                let case_id = format!("runtime-typed-{builtin}-{slug}");
                assert_runtime_raw_substitution(
                    runtime_case(cases, &case_id),
                    &format!("{case_id}-raw"),
                );
            }
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_singleton_target_mutant(
        cases: &[crate::DifferentialCase],
        case_id: &str,
        original: &str,
        replacement: &str,
    ) {
        let case = runtime_case(cases, case_id);
        let source_root = root(&format!("{case_id}-target"));
        let (success, mut semantic, stdout) =
            execute_runtime_interaction_with_stdout(case, &source_root);
        let original = hell_builtins::lookup(original).unwrap().id;
        let replacement = hell_builtins::lookup(replacement).unwrap().id;
        if let Some(event) = semantic
            .obligation_trace
            .iter_mut()
            .find(|event| event.builtin == original)
        {
            event.builtin = replacement;
        } else {
            let mut changed = false;
            for event in &mut semantic.force_trace {
                if let LogicalTraceEvent::ForceBuiltinArgument { builtin, .. } = event
                    && *builtin == original
                {
                    *builtin = replacement;
                    changed = true;
                }
            }
            assert!(changed, "singleton force-only target event");
        }
        assert_rehashed_runtime_semantic_rejected(
            case,
            semantic,
            &stdout,
            success,
            &format!("{case_id}-target"),
        );
        fs::remove_dir_all(source_root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_singleton_typed_mutant(
        case: &crate::DifferentialCase,
        original: &str,
        replacement: &str,
    ) {
        let source_root = root(&format!("{}-typed", case.id));
        let (success, mut semantic, stdout) =
            execute_runtime_interaction_with_stdout(case, &source_root);
        let canonical = semantic
            .typed_result_canonical
            .as_ref()
            .unwrap()
            .to_string();
        let changed = canonical.replacen(original, replacement, 1);
        assert_ne!(changed, canonical);
        let changed: Arc<str> = Arc::from(changed);
        semantic.typed_result_sha256 = Some(sha256_bytes(changed.as_bytes()));
        semantic.typed_result_canonical = Some(changed);
        assert_rehashed_runtime_semantic_rejected(
            case,
            semantic,
            &stdout,
            success,
            &format!("{}-typed", case.id),
        );
        fs::remove_dir_all(source_root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_singleton_demand_mutants(cases: &[crate::DifferentialCase]) {
        for class in ["lazy-adapter-entry", "lazy-adapter-exit"] {
            assert_demand_argument_state_substitution_rejected(
                cases,
                "runtime-typed-map-singleton-value-nonforce",
                "Map.singleton",
                1,
                class,
            );
            assert_demand_argument_state_substitution_rejected(
                cases,
                "runtime-typed-map-singleton-key-strict",
                "Map.singleton",
                1,
                class,
            );
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_singleton_resource_and_platform_mutants(cases: &[crate::DifferentialCase]) {
        for (case_id, builtin) in [
            ("runtime-typed-map-singleton-int", "map-singleton"),
            ("runtime-typed-set-singleton-int", "set-singleton"),
        ] {
            let case = runtime_case(cases, case_id);
            assert_singleton_materialization_mutants(case, builtin);
            assert_singleton_resource_audit_mutant(case);
            assert_singleton_three_platform_shards(case, builtin);
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_singleton_materialization_mutants(case: &crate::DifferentialCase, builtin: &str) {
        let source_root = root(&format!("{}-materialization", case.id));
        let (success, semantic, stdout) =
            execute_runtime_interaction_with_stdout(case, &source_root);
        for after in [1, u64::MAX] {
            let mut changed = semantic.clone();
            singleton_obligation_event_mut(&mut changed, builtin).materialized_after = after;
            assert_rehashed_runtime_semantic_rejected(
                case,
                changed,
                &stdout,
                success,
                &format!("{}-materialized-{after}", case.id),
            );
        }
        let mut duplicated = semantic;
        let mut duplicate = singleton_obligation_event_mut(&mut duplicated, builtin).clone();
        duplicate.sequence = duplicated
            .obligation_trace
            .iter()
            .map(|event| event.sequence)
            .max()
            .unwrap()
            .saturating_add(1);
        duplicated.obligation_trace.push(duplicate);
        assert_rehashed_runtime_semantic_rejected(
            case,
            duplicated,
            &stdout,
            success,
            &format!("{}-duplicate-target", case.id),
        );
        fs::remove_dir_all(source_root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_singleton_resource_audit_mutant(case: &crate::DifferentialCase) {
        let (root, directory) =
            retain_executed_runtime_case(case, &format!("{}-resource", case.id));
        let forged = resource_audit_json(&ResourceAudit {
            handles: 1,
            ..ResourceAudit::default()
        });
        fs::write(directory.join("candidate/resource-audit.json"), forged).unwrap();
        rehash_runtime_bundle(&directory, case);
        assert!(verify_observation_bundle_for_case(&directory, case).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_singleton_three_platform_shards(case: &crate::DifferentialCase, builtin: &str) {
        let (root, directory) =
            retain_executed_runtime_case(case, &format!("{}-platforms", case.id));
        let observation = fs::read_to_string(directory.join("candidate/observation.json")).unwrap();
        let (candidate_executable_sha256, _) = exact_candidate_identity(&observation).unwrap();
        let expected_builtin = singleton_builtin_name(builtin);
        for platform in [
            hell_builtins::ClaimPlatform::Linux,
            hell_builtins::ClaimPlatform::MacOs,
            hell_builtins::ClaimPlatform::Windows,
        ] {
            let shard = runtime_platform_shard_for_bundle(
                &directory,
                case,
                platform,
                sha256_bytes(b"singleton-candidate-source"),
                candidate_executable_sha256,
            )
            .unwrap()
            .expect("singleton case produces a platform shard");
            assert_eq!(shard.platform, platform);
            assert!(shard.targets.iter().any(|target| {
                target.builtin.as_ref() == expected_builtin
                    && target.dimension == hell_builtins::CompatibilityDimension::Platform
            }));
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn retained_ord_matrix_rejects_instance_target_result_and_demand_substitutions() {
        let cases = crate::committed_differential_cases();
        assert_ord_instance_substitutions(&cases);
        assert_ord_plan_and_target_substitutions(&cases);
        assert_ord_result_transport_and_demand_substitutions(&cases);
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_ord_instance_substitutions(cases: &[crate::DifferentialCase]) {
        let substitutions = [
            ("bool", "Bool", "Int"),
            ("byte-string", "ByteString", "Text"),
            ("ci", "CI", "Maybe"),
            ("char", "Char", "Text"),
            ("day", "Day", "UTCTime"),
            ("day-of-week", "DayOfWeek", "Day"),
            ("double", "Double", "Int"),
            ("either", "Either", "(,)"),
            ("exit-code", "ExitCode", "Int"),
            ("int", "Int", "Integer"),
            ("integer", "Integer", "Int"),
            ("list", "[]", "Vector"),
            ("maybe", "Maybe", "Set"),
            ("set", "Set", "Vector"),
            ("text", "Text", "ByteString"),
            ("time-of-day", "TimeOfDay", "UTCTime"),
            ("tree", "Tree", "Vector"),
            ("tuple", "(,)", "Either"),
            ("utc-time", "UTCTime", "Day"),
            ("vector", "Vector", "[]"),
        ];
        for builtin in ["lt", "gt"] {
            for (instance, expected, substituted) in substitutions {
                assert_resolved_instance_substitution(
                    cases,
                    &format!("runtime-typed-ord-{builtin}-{instance}-ordered"),
                    expected,
                    substituted,
                );
            }
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_ord_plan_and_target_substitutions(cases: &[crate::DifferentialCase]) {
        for (builtin, replacement, slug) in [("Ord.lt", "Ord.gt", "lt"), ("Ord.gt", "Ord.lt", "gt")]
        {
            let case_id = format!("runtime-typed-ord-{slug}-either-ordered");
            let case = runtime_case(cases, &case_id);
            let source_root = root(&format!("{case_id}-plan-source"));
            let (success, semantic, stdout) =
                execute_runtime_interaction_with_stdout(case, &source_root);
            assert!(success);
            let target = hell_builtins::lookup(builtin).unwrap().id;
            for (name, mutate) in [
                (
                    "root",
                    (|event: &mut crate::ObligationTraceEvent| {
                        event.instance_target = Some(Arc::from("(,)"));
                    }) as fn(&mut crate::ObligationTraceEvent),
                ),
                ("premise-omitted", |event| {
                    event.instance_premises.pop();
                }),
                ("premise-extra", |event| {
                    event
                        .instance_premises
                        .push(crate::InstancePremiseEvidence {
                            target: Arc::from("Bool"),
                            premise_count: 0,
                        });
                }),
                ("premise-reordered", |event| {
                    event.instance_premises.swap(0, 1);
                }),
                ("premise-substituted", |event| {
                    event.instance_premises[1].target = Arc::from("Bool");
                }),
                ("premise-count", |event| {
                    event.instance_premises[1].premise_count = 1;
                }),
            ] {
                let mut changed = semantic.clone();
                mutate(
                    changed
                        .obligation_trace
                        .iter_mut()
                        .find(|event| event.builtin == target)
                        .expect("Ord target event"),
                );
                assert_rehashed_runtime_semantic_rejected(
                    case,
                    changed,
                    &stdout,
                    true,
                    &format!("{case_id}-{name}"),
                );
            }
            let mut changed = semantic;
            changed
                .obligation_trace
                .iter_mut()
                .find(|event| event.builtin == target)
                .expect("Ord target event")
                .builtin = hell_builtins::lookup(replacement).unwrap().id;
            assert_rehashed_runtime_semantic_rejected(
                case,
                changed,
                &stdout,
                true,
                &format!("{case_id}-target"),
            );
            fs::remove_dir_all(source_root).unwrap();
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_ord_result_transport_and_demand_substitutions(cases: &[crate::DifferentialCase]) {
        for (builtin, slug) in [("Ord.lt", "lt"), ("Ord.gt", "gt")] {
            for (path, forged) in [("ordered", false), ("equal", true)] {
                let case_id = format!("runtime-typed-ord-{slug}-tree-{path}");
                let case = runtime_case(cases, &case_id);
                assert_eq_boolean_substitution(case, forged);
                assert_runtime_raw_substitution(case, &format!("{case_id}-raw"));
            }
            let case_id = format!("runtime-typed-ord-{slug}-tuple-first-field-bottom-tail");
            for argument in [0, 1] {
                assert_demand_argument_state_substitution_rejected(
                    cases,
                    &case_id,
                    builtin,
                    argument,
                    "whnf-force-complete",
                );
            }
            assert_rehashed_process_status_substitution_rejected(
                runtime_case(cases, &case_id),
                &format!("{case_id}-status"),
                (true, 0),
                (false, 1),
            );

            let invalid_id = format!("runtime-typed-ord-{slug}-byte-string-invalid-bytes");
            let invalid = runtime_case(cases, &invalid_id);
            let (root, directory) = retain_executed_runtime_case(invalid, &invalid_id);
            fs::write(directory.join("stdin.bin"), [0xff, b'A', 0xff, b'C']).unwrap();
            rehash_runtime_bundle(&directory, invalid);
            assert!(verify_observation_bundle_for_case(&directory, invalid).is_err());
            fs::remove_dir_all(root).unwrap();
        }
        assert_ord_injected_callback_rejected(cases);
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_ord_injected_callback_rejected(cases: &[crate::DifferentialCase]) {
        let callback_case = runtime_case(cases, "runtime-typed-functor-fmap-maybe-mapped");
        let callback_root = root("ord-callback-source");
        let (_, mut callback_semantic) = execute_runtime_interaction(callback_case, &callback_root);
        let injected = callback_events_mut(&mut callback_semantic, "Functor.fmap")[0].clone();
        fs::remove_dir_all(callback_root).unwrap();

        let case = runtime_case(cases, "runtime-typed-ord-lt-maybe-equal");
        let source_root = root("ord-callback-injection");
        let (success, mut semantic, stdout) =
            execute_runtime_interaction_with_stdout(case, &source_root);
        assert!(callback_events_mut(&mut semantic, "Ord.lt").is_empty());
        callback_events_mut(&mut semantic, "Ord.lt").push(injected);
        assert_rehashed_runtime_semantic_rejected(
            case,
            semantic,
            &stdout,
            success,
            "ord-callback-injected",
        );
        fs::remove_dir_all(source_root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn retained_show_matrix_executes_every_manifest_scope_for_show_and_print() {
        let cases = crate::committed_differential_cases();
        let show_cases = cases
            .iter()
            .filter(|case| case.id.starts_with("runtime-show-"))
            .collect::<Vec<_>>();
        let scopes = hell_builtins::instances()
            .iter()
            .filter(|instance| instance.class == hell_builtins::TypeClass::Show)
            .map(|instance| instance.target)
            .collect::<std::collections::BTreeSet<_>>();
        for builtin in ["show-show", "io-print"] {
            let observed = show_cases
                .iter()
                .filter(|case| case.id.starts_with(&format!("runtime-show-{builtin}-")))
                .flat_map(|case| {
                    case.claim_evidence
                        .as_ref()
                        .unwrap()
                        .semantic_targets
                        .iter()
                        .filter_map(|target| target.expected_instance_target.as_deref())
                })
                .collect::<std::collections::BTreeSet<_>>();
            assert_eq!(observed, scopes, "{builtin} Show scopes are incomplete");
        }
        for case in show_cases {
            let name = format!("retained-{}", case.id);
            let (root, _) = retain_executed_runtime_case(case, &name);
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn retained_show_matrix_rejects_instance_result_transport_and_effect_substitutions() {
        let cases = crate::committed_differential_cases();
        assert_show_instance_substitutions(&cases);
        assert_show_same_class_root_substitutions(&cases);
        assert_show_result_and_transport_substitutions(&cases);
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn retained_show_presentation_rejects_shadow_flow_and_input_substitutions() {
        let cases = crate::committed_differential_cases();
        assert_show_shadow_substitutions(&cases);
        assert_show_value_flow_substitutions(&cases);
        assert_print_direct_show_and_effect_substitutions(&cases);
        assert_show_arbitrary_byte_input_substitutions(&cases);
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_show_instance_substitutions(cases: &[crate::DifferentialCase]) {
        for (case_id, builtin_name) in [
            ("runtime-show-show-show-either-left", "Show.show"),
            ("runtime-show-io-print-either-left", "IO.print"),
        ] {
            assert_show_instance_substitutions_for_builtin(cases, case_id, builtin_name);
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_show_instance_substitutions_for_builtin(
        cases: &[crate::DifferentialCase],
        case_id: &str,
        builtin_name: &str,
    ) {
        let case = runtime_case(cases, case_id);
        let source_root = root(&format!("{}-instance-substitution-source", case.id));
        let (success, semantic, stdout) =
            execute_runtime_interaction_with_stdout(case, &source_root);
        assert!(success);
        let builtin = hell_builtins::lookup(builtin_name).unwrap().id;
        for (name, mutate) in [
            (
                "root",
                (|event: &mut crate::ObligationTraceEvent| {
                    event.instance_target = Some(Arc::from("(,)"));
                }) as fn(&mut crate::ObligationTraceEvent),
            ),
            ("premise-omitted", |event| {
                event.instance_premises.pop();
            }),
            ("premise-extra", |event| {
                event
                    .instance_premises
                    .push(crate::InstancePremiseEvidence {
                        target: Arc::from("Bool"),
                        premise_count: 0,
                    });
            }),
            ("premise-reordered", |event| {
                event.instance_premises.swap(0, 1);
            }),
            ("premise-substituted", |event| {
                event.instance_premises[1].target = Arc::from("Bool");
            }),
            ("premise-count", |event| {
                event.instance_premises[1].premise_count = 1;
            }),
        ] {
            let mut changed = semantic.clone();
            mutate(
                changed
                    .obligation_trace
                    .iter_mut()
                    .find(|event| event.builtin == builtin)
                    .expect("Show.show trace event"),
            );
            assert_rehashed_runtime_semantic_rejected(
                case,
                changed,
                &stdout,
                true,
                &format!("show-{name}"),
            );
        }
        fs::remove_dir_all(source_root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_show_same_class_root_substitutions(cases: &[crate::DifferentialCase]) {
        let expected = hell_builtins::instances()
            .iter()
            .filter(|instance| instance.class == hell_builtins::TypeClass::Show)
            .map(|instance| instance.target)
            .collect::<std::collections::BTreeSet<_>>();
        for builtin_name in ["Show.show", "IO.print"] {
            let mut selected = std::collections::BTreeMap::new();
            for case in cases
                .iter()
                .filter(|case| case.id.starts_with("runtime-show-"))
            {
                let Some(target) = case.claim_evidence.as_ref().and_then(|descriptor| {
                    descriptor.semantic_targets.iter().find(|target| {
                        target.builtin.as_ref() == builtin_name
                            && target.dimension
                                == hell_builtins::CompatibilityDimension::Presentation
                    })
                }) else {
                    continue;
                };
                selected
                    .entry(target.expected_instance_target.as_deref().unwrap())
                    .or_insert(case);
            }
            assert_eq!(
                selected
                    .keys()
                    .copied()
                    .collect::<std::collections::BTreeSet<_>>(),
                expected
            );
            let builtin = hell_builtins::lookup(builtin_name).unwrap().id;
            for (root_target, case) in selected {
                let source_root = root(&format!("{}-same-class", case.id));
                let (success, mut semantic, stdout) =
                    execute_runtime_interaction_with_stdout(case, &source_root);
                assert!(success);
                let event = show_event_mut(&mut semantic, builtin);
                event.instance_target = Some(Arc::from(if root_target == "Bool" {
                    "Int"
                } else {
                    "Bool"
                }));
                event.instance_premises.clear();
                assert_rehashed_runtime_semantic_rejected(
                    case,
                    semantic,
                    &stdout,
                    true,
                    &format!("{}-{root_target}-same-class", case.id),
                );
                fs::remove_dir_all(source_root).unwrap();
            }
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_show_shadow_substitutions(cases: &[crate::DifferentialCase]) {
        let case = runtime_case(cases, "runtime-show-show-show-text-escaping");
        let mut wrong_digest = case.clone();
        show_presentation_target_mut(&mut wrong_digest).expected_normalized_presentation_sha256 =
            Some(sha256_bytes(b"forged Show presentation shadow"));
        let (root, directory) =
            retain_executed_runtime_case_unverified(&wrong_digest, "show-shadow-digest");
        assert!(verify_observation_bundle_for_case(&directory, &wrong_digest).is_err());
        fs::remove_dir_all(root).unwrap();

        let mut missing_normalizer = case.clone();
        show_presentation_target_mut(&mut missing_normalizer)
            .expected_presentation_shadow_normalizer = None;
        assert!(crate::validate_evidence_catalog(&[missing_normalizer]).is_err());
    }

    #[cfg(feature = "compat-tracing")]
    fn show_presentation_target_mut(
        case: &mut crate::DifferentialCase,
    ) -> &mut crate::EvidenceTargetV2 {
        case.claim_evidence
            .as_mut()
            .unwrap()
            .semantic_targets
            .iter_mut()
            .find(|target| target.dimension == hell_builtins::CompatibilityDimension::Presentation)
            .expect("Show case has a Presentation target")
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_show_value_flow_substitutions(cases: &[crate::DifferentialCase]) {
        let case = runtime_case(cases, "runtime-show-show-show-text-escaping");
        let source_root = root("show-value-flow-source");
        let (success, semantic, stdout) =
            execute_runtime_interaction_with_stdout(case, &source_root);
        assert!(success);
        let show = hell_builtins::lookup("Show.show").unwrap().id;
        let sink = hell_builtins::lookup("Text.putStrLn").unwrap().id;

        let mut missing_target_parent = semantic.clone();
        show_event_mut(&mut missing_target_parent, show).parent_sequence = None;
        assert_show_flow_mutant(case, missing_target_parent, &stdout, "show-parent-omitted");

        let mut missing_sink_parent = semantic.clone();
        show_event_mut(&mut missing_sink_parent, sink).parent_sequence = None;
        assert_show_flow_mutant(
            case,
            missing_sink_parent,
            &stdout,
            "show-sink-parent-omitted",
        );

        let mut reparented = semantic.clone();
        let sink_parent = show_event_mut(&mut reparented, sink).parent_sequence;
        show_event_mut(&mut reparented, show).parent_sequence = sink_parent;
        assert_show_flow_mutant(case, reparented, &stdout, "show-parent-replaced");

        let mut disconnected = semantic.clone();
        let forged: Arc<str> = Arc::from("{\"type\":\"Text\",\"utf8Hex\":\"666f72676564\"}");
        let inner_parent = show_event_mut(&mut disconnected, show)
            .parent_sequence
            .unwrap();
        let outer_parent = show_event_mut(&mut disconnected, sink)
            .parent_sequence
            .unwrap();
        let inner = disconnected
            .obligation_trace
            .iter_mut()
            .find(|event| event.sequence == inner_parent)
            .unwrap();
        inner.callbacks[0].canonical_result = Arc::clone(&forged);
        let outer = disconnected
            .obligation_trace
            .iter_mut()
            .find(|event| event.sequence == outer_parent)
            .unwrap();
        outer.callbacks[0].canonical_arguments[0] = forged;
        assert_show_flow_mutant(case, disconnected, &stdout, "show-value-disconnected");

        let mut failed_sink = semantic;
        mutate_target_effect(&mut failed_sink, "Text.putStrLn", "completed", "failed");
        assert_show_flow_mutant(case, failed_sink, &stdout, "show-sink-effect-failed");
        fs::remove_dir_all(source_root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn show_event_mut(
        semantic: &mut crate::SemanticObservation,
        builtin: hell_builtins::BuiltinId,
    ) -> &mut crate::ObligationTraceEvent {
        semantic
            .obligation_trace
            .iter_mut()
            .find(|event| event.builtin == builtin)
            .expect("Show flow adapter event")
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_show_flow_mutant(
        case: &crate::DifferentialCase,
        semantic: crate::SemanticObservation,
        stdout: &[u8],
        name: &str,
    ) {
        assert!(validate_show_dependency_for_test(case, &semantic).is_err());
        assert_rehashed_runtime_semantic_rejected(case, semantic, stdout, true, name);
    }

    #[cfg(feature = "compat-tracing")]
    fn validate_show_dependency_for_test(
        case: &crate::DifferentialCase,
        semantic: &crate::SemanticObservation,
    ) -> std::io::Result<()> {
        let target = case
            .claim_evidence
            .as_ref()
            .unwrap()
            .semantic_targets
            .iter()
            .find(|target| target.dimension == hell_builtins::CompatibilityDimension::Presentation)
            .unwrap();
        let builtin = hell_builtins::lookup(&target.builtin).unwrap().id;
        let effects = retained_effects_for_test(semantic);
        validate_presentation_dependency(target, builtin, &semantic.obligation_trace, &effects)
    }

    #[cfg(feature = "compat-tracing")]
    fn retained_effects_for_test(
        semantic: &crate::SemanticObservation,
    ) -> Vec<RetainedEffectEvent> {
        semantic
            .effect_trace
            .iter()
            .filter_map(|event| match event {
                crate::LogicalTraceEvent::HostEffect {
                    builtin,
                    owner_task,
                    sequence,
                    parent_sequence,
                    effect,
                } => Some(RetainedEffectEvent {
                    builtin: *builtin,
                    owner_task: *owner_task,
                    sequence: *sequence,
                    parent_sequence: *parent_sequence,
                    lifecycle: effect.to_string(),
                }),
                _ => None,
            })
            .collect()
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_print_direct_show_and_effect_substitutions(cases: &[crate::DifferentialCase]) {
        let case = runtime_case(cases, "runtime-show-io-print-text-escaping");
        let source_root = root("print-direct-show-source");
        let (success, semantic, stdout) =
            execute_runtime_interaction_with_stdout(case, &source_root);
        assert!(success);
        let print = hell_builtins::lookup("IO.print").unwrap().id;
        let show = hell_builtins::lookup("Show.show").unwrap().id;
        let mut injected = semantic.clone();
        let mut event = show_event_mut(&mut injected, print).clone();
        event.builtin = show;
        event.sequence = injected
            .obligation_trace
            .iter()
            .map(|event| event.sequence)
            .max()
            .unwrap()
            + 1;
        event.outcome = Arc::from("value");
        injected.obligation_trace.push(event);
        assert_show_flow_mutant(case, injected, &stdout, "print-injected-show");

        let mut failed = semantic;
        mutate_target_effect(&mut failed, "IO.print", "completed", "failed");
        assert_show_flow_mutant(case, failed, &stdout, "print-effect-failed");
        fs::remove_dir_all(source_root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_show_arbitrary_byte_input_substitutions(cases: &[crate::DifferentialCase]) {
        for case_id in [
            "runtime-show-show-show-builder-arbitrary-bytes",
            "runtime-show-io-print-byte-string-arbitrary-bytes",
        ] {
            let case = runtime_case(cases, case_id);
            let (root, directory) = retain_executed_runtime_case(case, case_id);
            fs::write(directory.join("stdin.bin"), [0xff, 0x41, 0xfe, 0x43]).unwrap();
            rehash_runtime_bundle(&directory, case);
            assert!(verify_observation_bundle_for_case(&directory, case).is_err());
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_show_result_and_transport_substitutions(cases: &[crate::DifferentialCase]) {
        let show = runtime_case(cases, "runtime-show-show-show-value-object");
        assert_show_typed_result_substitution(show);
        assert_show_raw_substitution(show, "show-raw");
        assert_rehashed_process_status_substitution_rejected(
            show,
            "show-status",
            (true, 0),
            (false, 1),
        );

        let print = runtime_case(cases, "runtime-show-io-print-maybe-just");
        assert_show_typed_result_substitution(print);
        assert_show_raw_substitution(print, "print-raw");
        assert_show_print_effect_and_target_substitution(print);
        assert_show_print_resource_substitution(print);
        assert_rehashed_process_status_substitution_rejected(
            print,
            "print-status",
            (true, 0),
            (false, 1),
        );
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_show_typed_result_substitution(case: &crate::DifferentialCase) {
        let source_root = root(&format!("{}-typed-source", case.id));
        let (success, mut semantic, stdout) =
            execute_runtime_interaction_with_stdout(case, &source_root);
        assert!(success);
        let forged: Arc<str> = Arc::from(concat!(
            "{\"type\":\"TypedResult\",\"argument\":0,",
            "\"boundary\":\"adapter-result\",",
            "\"value\":{\"type\":\"Unit\",\"value\":null}}",
        ));
        semantic.typed_result_sha256 = Some(crate::sha256_bytes(forged.as_bytes()));
        semantic.typed_result_canonical = Some(forged);
        assert_rehashed_runtime_semantic_rejected(
            case,
            semantic,
            &stdout,
            true,
            &format!("{}-typed", case.id),
        );
        fs::remove_dir_all(source_root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_show_raw_substitution(case: &crate::DifferentialCase, name: &str) {
        let (bundle_root, directory) = retain_executed_runtime_case(case, name);
        for role in ["candidate", "oracle"] {
            fs::write(directory.join(role).join("stdout.bin"), b"forged\n").unwrap();
        }
        rehash_runtime_bundle(&directory, case);
        assert!(verify_observation_bundle_for_case(&directory, case).is_err());
        fs::remove_dir_all(bundle_root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_show_print_effect_and_target_substitution(case: &crate::DifferentialCase) {
        let source_root = root("print-effect-substitution-source");
        let (success, semantic, stdout) =
            execute_runtime_interaction_with_stdout(case, &source_root);
        assert!(success);
        let mut effect = semantic.clone();
        mutate_target_effect(&mut effect, "IO.print", "completed", "failed");
        assert_rehashed_runtime_semantic_rejected(case, effect, &stdout, true, "print-effect");

        let print = hell_builtins::lookup("IO.print").unwrap().id;
        let mut cross_builtin = semantic;
        cross_builtin
            .obligation_trace
            .iter_mut()
            .find(|event| event.builtin == print)
            .expect("IO.print trace event")
            .builtin = hell_builtins::lookup("Show.show").unwrap().id;
        assert_rehashed_runtime_semantic_rejected(
            case,
            cross_builtin,
            &stdout,
            true,
            "print-to-show-target",
        );
        fs::remove_dir_all(source_root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_show_print_resource_substitution(case: &crate::DifferentialCase) {
        let (bundle_root, directory) =
            retain_executed_runtime_case(case, "print-resource-substitution");
        let forged = resource_audit_json(&ResourceAudit {
            handles: 1,
            ..ResourceAudit::default()
        });
        fs::write(directory.join("candidate/resource-audit.json"), forged).unwrap();
        rehash_runtime_bundle(&directory, case);
        assert!(verify_observation_bundle_for_case(&directory, case).is_err());
        fs::remove_dir_all(bundle_root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn resolved_instance_target_rejects_omission_extra_and_cross_builtin_mutants() {
        let cases = crate::committed_differential_cases();
        let case = runtime_case(&cases, "runtime-typed-alternative-optional-maybe-just");
        let source_root = root("instance-target-structural-source");
        let (success, semantic, stdout) =
            execute_runtime_interaction_with_stdout(case, &source_root);
        assert!(success);
        let alternative = hell_builtins::lookup("Alternative.optional").unwrap().id;

        let mut omitted = semantic.clone();
        omitted
            .obligation_trace
            .iter_mut()
            .find(|event| event.builtin == alternative)
            .unwrap()
            .instance_target = None;
        assert_rehashed_runtime_semantic_rejected(
            case,
            omitted,
            &stdout,
            true,
            "instance-target-omitted",
        );

        let mut cross_builtin = semantic;
        cross_builtin
            .obligation_trace
            .iter_mut()
            .find(|event| event.builtin == alternative)
            .unwrap()
            .builtin = hell_builtins::lookup("Monad.bind").unwrap().id;
        assert_rehashed_runtime_semantic_rejected(
            case,
            cross_builtin,
            &stdout,
            true,
            "instance-target-cross-builtin",
        );

        let trace = fs::read_to_string(source_root.join(format!("{}.json", case.id))).unwrap();
        let extra = trace.replacen(
            "\"instanceTarget\": \"Maybe\"",
            "\"instanceTarget\": \"Maybe\", \"decorative\": true",
            1,
        );
        assert_ne!(extra, trace);
        assert!(crate::parse_semantic_trace(extra.as_bytes()).is_err());
        fs::remove_dir_all(source_root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_json_value_callback_substitutions_rejected(
        case: &crate::DifferentialCase,
        branch: &str,
    ) {
        let source_root = root(&format!("json-value-{branch}-source"));
        let (success, semantic) = execute_runtime_interaction(case, &source_root);
        assert!(success);

        let mut omitted = semantic.clone();
        callback_events_mut(&mut omitted, "Json.value").clear();
        assert_rehashed_callback_semantic_rejected(
            case,
            omitted,
            &format!("json-value-{branch}-omitted"),
        );

        let mut duplicated = semantic.clone();
        let callbacks = callback_events_mut(&mut duplicated, "Json.value");
        let mut duplicate = callbacks[0].clone();
        duplicate.invocation = 2;
        callbacks.push(duplicate);
        assert_rehashed_callback_semantic_rejected(
            case,
            duplicated,
            &format!("json-value-{branch}-duplicated"),
        );

        let mut changed = semantic;
        let callback = &mut callback_events_mut(&mut changed, "Json.value")[0];
        callback.branch = Arc::from("forged");
        callback.canonical_result = Arc::from("{\"type\":\"Text\",\"utf8Hex\":\"666f72676564\"}");
        if let Some(argument) = callback.canonical_arguments.first_mut() {
            *argument = Arc::from("{\"type\":\"Int\",\"value\":\"9\"}");
        }
        assert_rehashed_callback_semantic_rejected(
            case,
            changed,
            &format!("json-value-{branch}-metadata"),
        );
        fs::remove_dir_all(source_root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_json_value_raw_substitution_rejected(case: &crate::DifferentialCase, branch: &str) {
        let (root, directory) = retain_executed_runtime_case(case, branch);
        for role in ["candidate", "oracle"] {
            fs::write(directory.join(role).join("stdout.bin"), b"forged").unwrap();
        }
        rehash_runtime_bundle(&directory, case);
        assert!(verify_observation_bundle_for_case(&directory, case).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn raw_byte_boundary_rejects_equal_rehashed_output_substitution() {
        let case = crate::committed_differential_cases()
            .into_iter()
            .find(|case| case.id.as_ref() == "bytestring-hget-boundary-invalid-encoding")
            .expect("committed ByteString.hGet invalid-byte case");
        let root = root("raw-byte-boundary-substitution");
        let (success, semantic, stdout) = execute_runtime_interaction_with_stdout(&case, &root);
        assert!(success);
        assert_eq!(stdout, [0xff, b'A']);
        let mut retained = report();
        for observation in [&mut retained.oracle, &mut retained.candidate] {
            observation.case_id = Arc::clone(&case.id);
            observation.stdout = BoundedCapture::from_bytes(vec![0xff, b'B']);
        }
        retained.candidate.semantic = Some(semantic);
        let directory =
            retain_observation_bundle(&root.join("evidence"), &case, &retained).unwrap();
        assert!(verify_observation_bundle_for_case(&directory, &case).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn byte_string_write_file_rejects_rehashed_output_and_failure_substitutions() {
        let cases = crate::committed_differential_cases();
        let invalid = cases
            .iter()
            .find(|case| case.id.as_ref() == "bytestring-writefile-boundary-invalid-encoding")
            .expect("committed ByteString.writeFile invalid-byte case");
        let (root, directory) = retain_executed_runtime_case(invalid, "writefile-invalid-output");
        for role in ["candidate", "oracle"] {
            fs::write(directory.join(role).join("stdout.bin"), [0xff, b'B']).unwrap();
        }
        rehash_runtime_bundle(&directory, invalid);
        assert!(verify_observation_bundle_for_case(&directory, invalid).is_err());
        fs::remove_dir_all(root).unwrap();

        let failure = cases
            .iter()
            .find(|case| case.id.as_ref() == "runtime-typed-io-bytestring-writefile-failure")
            .expect("committed ByteString.writeFile failure case");
        let (root, directory) = retain_executed_runtime_case(failure, "writefile-failure-effect");
        let observation = directory.join("candidate").join("observation.json");
        let document = fs::read_to_string(&observation).unwrap();
        let substituted =
            document.replacen("\"effect\": \"failed\"", "\"effect\": \"completed\"", 1);
        assert_ne!(
            document, substituted,
            "failed effect mutation did not match"
        );
        fs::write(observation, substituted).unwrap();
        rehash_runtime_bundle(&directory, failure);
        assert!(verify_observation_bundle_for_case(&directory, failure).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn text_file_writers_reject_rehashed_output_and_failure_substitutions() {
        let cases = crate::committed_differential_cases();
        for prefix in ["text-writefile", "text-appendfile"] {
            let unicode_id = format!("{prefix}-boundary-unicode");
            let unicode = cases
                .iter()
                .find(|case| case.id.as_ref() == unicode_id)
                .expect("committed Text file-writer Unicode case");
            let (root, directory) = retain_executed_runtime_case(unicode, &unicode_id);
            for role in ["candidate", "oracle"] {
                fs::write(directory.join(role).join("stdout.bin"), "aγ").unwrap();
            }
            rehash_runtime_bundle(&directory, unicode);
            assert!(verify_observation_bundle_for_case(&directory, unicode).is_err());
            fs::remove_dir_all(root).unwrap();

            let failure_id = format!("runtime-typed-io-{prefix}-failure");
            let failure = cases
                .iter()
                .find(|case| case.id.as_ref() == failure_id)
                .expect("committed Text file-writer failure case");
            let (root, directory) = retain_executed_runtime_case(failure, &failure_id);
            let observation = directory.join("candidate").join("observation.json");
            let document = fs::read_to_string(&observation).unwrap();
            let substituted =
                document.replacen("\"effect\": \"failed\"", "\"effect\": \"completed\"", 1);
            assert_ne!(
                document, substituted,
                "failed effect mutation did not match"
            );
            fs::write(observation, substituted).unwrap();
            rehash_runtime_bundle(&directory, failure);
            assert!(verify_observation_bundle_for_case(&directory, failure).is_err());
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn file_readers_reject_rehashed_raw_and_failure_substitutions() {
        let cases = crate::committed_differential_cases();
        let invalid_bytes = cases
            .iter()
            .find(|case| case.id.as_ref() == "bytestring-readfile-boundary-invalid-encoding")
            .expect("committed ByteString.readFile invalid-byte case");
        let (root, directory) =
            retain_executed_runtime_case(invalid_bytes, "readfile-invalid-output");
        for role in ["candidate", "oracle"] {
            fs::write(directory.join(role).join("stdout.bin"), [0xff, b'B']).unwrap();
        }
        rehash_runtime_bundle(&directory, invalid_bytes);
        assert!(verify_observation_bundle_for_case(&directory, invalid_bytes).is_err());
        fs::remove_dir_all(root).unwrap();

        for case_id in [
            "text-readfile-boundary-invalid-encoding",
            "runtime-typed-io-text-readfile-failure",
            "runtime-typed-io-bytestring-readfile-failure",
        ] {
            assert_runtime_failed_effect_substitution_rejected(&cases, case_id);
        }
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn interact_boundaries_reject_rehashed_raw_and_failure_substitutions() {
        let cases = crate::committed_differential_cases();
        for (case_id, forged) in [
            ("text-interact-boundary-unicode", "AΓ".as_bytes()),
            (
                "bytestring-interact-boundary-invalid-encoding",
                &[0xff, b'B'],
            ),
        ] {
            let case = cases
                .iter()
                .find(|case| case.id.as_ref() == case_id)
                .unwrap_or_else(|| panic!("missing interact case {case_id}"));
            let (root, directory) = retain_executed_runtime_case(case, case_id);
            for role in ["candidate", "oracle"] {
                fs::write(directory.join(role).join("stdout.bin"), forged).unwrap();
            }
            rehash_runtime_bundle(&directory, case);
            assert!(verify_observation_bundle_for_case(&directory, case).is_err());
            fs::remove_dir_all(root).unwrap();
        }
        assert_runtime_failed_effect_substitution_rejected(
            &cases,
            "text-interact-boundary-invalid-encoding",
        );
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn process_boundaries_reject_rehashed_raw_failure_and_helper_substitutions() {
        let mut cases = crate::committed_differential_cases();
        bind_test_process_helpers(&mut cases);
        for (case_id, forged) in [
            ("text-readprocess-boundary-unicode", "forged".as_bytes()),
            (
                "bytestring-readprocess-stdout-checked-boundary-invalid-encoding",
                &[0xff, b'B'],
            ),
            ("text-setstdin-boundary-unicode", "forged".as_bytes()),
        ] {
            let case = cases
                .iter()
                .find(|case| case.id.as_ref() == case_id)
                .unwrap_or_else(|| panic!("missing process boundary {case_id}"));
            let (root, directory) = retain_executed_runtime_case(case, case_id);
            for role in ["candidate", "oracle"] {
                fs::write(directory.join(role).join("stdout.bin"), forged).unwrap();
            }
            rehash_runtime_bundle(&directory, case);
            assert!(verify_observation_bundle_for_case(&directory, case).is_err());
            fs::remove_dir_all(root).unwrap();
        }
        for case_id in [
            "text-readprocess-boundary-invalid-encoding",
            "text-readprocess-checked-boundary-invalid-encoding",
            "text-readprocess-stdout-checked-boundary-invalid-encoding",
            "runtime-typed-io-bytestring-readprocess-failure",
            "runtime-typed-io-bytestring-readprocess-checked-failure",
            "runtime-typed-io-bytestring-readprocess-stdout-checked-failure",
        ] {
            assert_runtime_failed_effect_substitution_rejected(&cases, case_id);
        }
        assert_process_helper_digest_substitution_rejected(&cases);
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn process_execution_rejects_rehashed_output_and_failure_substitutions() {
        let mut cases = crate::committed_differential_cases();
        bind_test_process_helpers(&mut cases);
        for (case_id, forged) in [
            ("runtime-process-run-success", b"BExitSuccess\n".as_slice()),
            ("runtime-process-run-checked-success", b"B".as_slice()),
            ("runtime-process-run-nonzero", b"ExitSuccess\n".as_slice()),
            ("runtime-process-use-handle-open", b"A".as_slice()),
            ("runtime-process-use-handle-close", b"B".as_slice()),
        ] {
            let case = cases
                .iter()
                .find(|case| case.id.as_ref() == case_id)
                .unwrap_or_else(|| panic!("missing process execution case {case_id}"));
            let (root, directory) = retain_executed_runtime_case(case, case_id);
            for role in ["candidate", "oracle"] {
                fs::write(directory.join(role).join("stdout.bin"), forged).unwrap();
            }
            rehash_runtime_bundle(&directory, case);
            assert!(verify_observation_bundle_for_case(&directory, case).is_err());
            fs::remove_dir_all(root).unwrap();
        }
        assert_runtime_typed_substitution_rejected(
            "runtime-process-use-handle-close",
            "\"closeAfterProcess\":true",
            "\"closeAfterProcess\":false",
        );
        let close = cases
            .iter()
            .find(|case| case.id.as_ref() == "runtime-process-use-handle-close")
            .expect("Process.useHandleClose execution case");
        let (root, directory) = retain_executed_runtime_case(close, "process-handle-close-event");
        let observation = directory.join("candidate").join("observation.json");
        let document = fs::read_to_string(&observation).unwrap();
        let substituted = document.replacen("\"event\": \"close\"", "\"event\": \"transfer\"", 1);
        assert_ne!(
            document, substituted,
            "process close mutation did not match"
        );
        fs::write(observation, substituted).unwrap();
        rehash_runtime_bundle(&directory, close);
        assert!(verify_observation_bundle_for_case(&directory, close).is_err());
        fs::remove_dir_all(root).unwrap();
        for case_id in [
            "runtime-process-run-failure",
            "runtime-process-run-checked-failure",
        ] {
            assert_runtime_failed_effect_substitution_rejected(&cases, case_id);
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_process_helper_digest_substitution_rejected(cases: &[crate::DifferentialCase]) {
        let case = cases
            .iter()
            .find(|case| case.id.as_ref() == "text-setstdin-boundary-ascii")
            .expect("process-helper-bound boundary case");
        let (root, directory) = retain_executed_runtime_case(case, "process-helper-substitution");
        let input = directory.join("execution-input.json");
        let document = fs::read_to_string(&input).unwrap();
        let digest = case
            .process_helper_sha256
            .expect("bound helper digest")
            .hex();
        let substituted = document.replace(&digest, &"00".repeat(digest.len() / 2));
        assert_ne!(
            document, substituted,
            "helper digest mutation did not match"
        );
        fs::write(input, substituted).unwrap();
        rehash_runtime_bundle(&directory, case);
        assert!(verify_observation_bundle_for_case(&directory, case).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_runtime_failed_effect_substitution_rejected(
        cases: &[crate::DifferentialCase],
        case_id: &str,
    ) {
        let case = cases
            .iter()
            .find(|case| case.id.as_ref() == case_id)
            .unwrap_or_else(|| panic!("missing failed runtime case {case_id}"));
        let (root, directory) = retain_executed_runtime_case(case, case_id);
        let observation = directory.join("candidate").join("observation.json");
        let document = fs::read_to_string(&observation).unwrap();
        let substituted =
            document.replacen("\"effect\": \"failed\"", "\"effect\": \"completed\"", 1);
        assert_ne!(
            document, substituted,
            "failed effect mutation did not match"
        );
        fs::write(observation, substituted).unwrap();
        rehash_runtime_bundle(&directory, case);
        assert!(verify_observation_bundle_for_case(&directory, case).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn executable_interactions_round_trip_through_the_production_bundle_gate() {
        let mut cases = crate::committed_differential_cases()
            .into_iter()
            .filter(|case| case.id.starts_with("runtime-interaction-"))
            .collect::<Vec<_>>();
        assert!(!cases.is_empty());
        let test_executable = std::env::current_exe().unwrap();
        let helper_directory = test_executable.parent().unwrap().parent().unwrap();
        crate::bind_process_helper_directory(&mut cases, helper_directory).unwrap();
        let root = root("runtime-interaction-bundles");
        fs::create_dir_all(&root).unwrap();
        let evidence = root.join("evidence");
        for case in cases {
            let (success, semantic, stdout) = execute_runtime_interaction_with_stdout(&case, &root);
            let mut retained = report();
            for observation in [&mut retained.oracle, &mut retained.candidate] {
                observation.case_id = std::sync::Arc::clone(&case.id);
                observation.environment_profile = case.environment_profile;
                observation.process_helper_sha256 = case.process_helper_sha256;
                observation.status = crate::ProcessStatus {
                    success,
                    code: Some(i32::from(!success)),
                };
                observation.stdout = BoundedCapture::from_bytes(stdout.clone());
            }
            retained.candidate.semantic = Some(semantic);
            let directory = retain_observation_bundle(&evidence, &case, &retained).unwrap();
            verify_observation_bundle_for_case(&directory, &case)
                .unwrap_or_else(|error| panic!("{} bundle was incomplete: {error}", case.id));
            let platform = runtime_platform_shard_for_bundle(
                &directory,
                &case,
                hell_builtins::ClaimPlatform::Linux,
                sha256_bytes(b"candidate-source"),
                retained.candidate.identity.sha256,
            )
            .unwrap_or_else(|error| panic!("{} platform shard was invalid: {error}", case.id))
            .unwrap_or_else(|| panic!("{} omitted its runtime platform shard", case.id));
            assert_eq!(platform.case_id, case.id);
            assert!(!platform.targets.is_empty());
            assert!(
                runtime_platform_shard_for_bundle(
                    &directory,
                    &case,
                    hell_builtins::ClaimPlatform::Linux,
                    sha256_bytes(b"candidate-source"),
                    sha256_bytes(b"forged-candidate-executable"),
                )
                .is_err(),
                "{} accepted a relabeled candidate executable digest",
                case.id
            );
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn callback_identity_order_branch_outcome_and_result_substitutions_are_rejected() {
        let case = crate::committed_differential_cases()
            .into_iter()
            .find(|case| case.id.as_ref() == "runtime-typed-maybe-eliminate")
            .expect("typed Maybe eliminator case");
        let result_two = crate::encode_callback_result("{\"type\":\"Int\",\"value\":\"2\"}");
        let result_three = crate::encode_callback_result("{\"type\":\"Int\",\"value\":\"3\"}");
        for (name, original, replacement) in [
            ("invocation", "\"invocation\":1", "\"invocation\":2"),
            (
                "argument",
                "\"callbackArgument\":1",
                "\"callbackArgument\":0",
            ),
            ("branch", "\"branch\":\"just\"", "\"branch\":\"nothing\""),
            ("outcome", "\"outcome\":\"value\"", "\"outcome\":\"error\""),
            ("result", result_two.as_str(), result_three.as_str()),
        ] {
            let root = root(&format!("callback-{name}"));
            fs::create_dir_all(&root).unwrap();
            let (success, semantic) = execute_runtime_interaction(&case, &root);
            assert!(success);
            let mut retained = report();
            for observation in [&mut retained.oracle, &mut retained.candidate] {
                observation.case_id = std::sync::Arc::clone(&case.id);
            }
            retained.candidate.semantic = Some(semantic);
            let directory = retain_observation_bundle(&root.join("evidence"), &case, &retained)
                .expect("retain callback observation bundle");
            let observation = directory.join("candidate").join("observation.json");
            let document = fs::read_to_string(&observation).unwrap();
            let mutated = document.replace(original, replacement);
            assert_ne!(document, mutated, "{name} mutation did not match");
            fs::write(&observation, mutated).unwrap();
            fs::remove_file(directory.join("bundle-manifest.json")).unwrap();
            fs::remove_file(directory.join("bundle-manifest.sha256")).unwrap();
            write_bundle_manifest(&directory, &case, sha256_bytes(b"epoch")).unwrap();
            assert!(
                verify_observation_bundle_for_case(&directory, &case).is_err(),
                "rehashed callback {name} mutation was accepted"
            );
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn callback_events_mut<'a>(
        semantic: &'a mut crate::SemanticObservation,
        builtin: &str,
    ) -> &'a mut Vec<crate::CallbackTraceEvent> {
        let builtin = hell_builtins::lookup(builtin)
            .unwrap_or_else(|| panic!("missing callback target {builtin}"))
            .id;
        &mut semantic
            .obligation_trace
            .iter_mut()
            .find(|event| event.builtin == builtin)
            .unwrap_or_else(|| panic!("missing retained callback event for {builtin:?}"))
            .callbacks
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn function_operators_reject_rehashed_callback_and_raw_substitutions() {
        let cases = crate::committed_differential_cases();
        for (case_id, builtin) in [
            ("runtime-typed-function-apply-operator", "$"),
            ("runtime-typed-function-compose-operator", "."),
            ("runtime-typed-function-apply-operator-lazy", "$"),
            ("runtime-typed-function-apply-operator-text", "$"),
            ("runtime-typed-function-compose-operator-lazy", "."),
            ("runtime-typed-function-compose-operator-heterogeneous", "."),
        ] {
            assert_function_operator_mutations(runtime_case(&cases, case_id), builtin);
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_function_operator_mutations(case: &crate::DifferentialCase, builtin: &str) {
        let source_root = root(&format!("{}-source", case.id));
        let (success, semantic, stdout) =
            execute_runtime_interaction_with_stdout(case, &source_root);
        assert!(success);
        fs::remove_dir_all(source_root).unwrap();

        let (bundle_root, directory) = retain_executed_runtime_case(case, case.id.as_ref());
        verify_observation_bundle_for_case(&directory, case)
            .expect("function operator baseline bundle");
        for role in ["candidate", "oracle"] {
            fs::write(directory.join(role).join("stdout.bin"), b"forged\n").unwrap();
        }
        rehash_runtime_bundle(&directory, case);
        assert!(verify_observation_bundle_for_case(&directory, case).is_err());
        fs::remove_dir_all(bundle_root).unwrap();

        let mut omitted = semantic.clone();
        callback_events_mut(&mut omitted, builtin).remove(0);
        assert_rehashed_runtime_semantic_rejected(
            case,
            omitted,
            &stdout,
            true,
            &format!("{}-callback-omitted", case.id),
        );

        let mut duplicated = semantic.clone();
        let callbacks = callback_events_mut(&mut duplicated, builtin);
        callbacks.push(callbacks[0].clone());
        assert_rehashed_runtime_semantic_rejected(
            case,
            duplicated,
            &stdout,
            true,
            &format!("{}-callback-duplicated", case.id),
        );

        if case.id.as_ref() == "runtime-typed-function-compose-operator" {
            let mut reordered = semantic.clone();
            callback_events_mut(&mut reordered, builtin).swap(0, 1);
            assert_rehashed_runtime_semantic_rejected(
                case,
                reordered,
                &stdout,
                true,
                &format!("{}-callback-reordered", case.id),
            );
        }

        let mut changed_argument = semantic.clone();
        callback_events_mut(&mut changed_argument, builtin)[0].canonical_arguments[0] =
            Arc::from("{\"type\":\"Int\",\"value\":\"9\"}");
        assert_rehashed_runtime_semantic_rejected(
            case,
            changed_argument,
            &stdout,
            true,
            &format!("{}-callback-argument", case.id),
        );

        let mut changed_result = semantic;
        callback_events_mut(&mut changed_result, builtin)[0].canonical_result =
            Arc::from("{\"type\":\"Int\",\"value\":\"9\"}");
        assert_rehashed_runtime_semantic_rejected(
            case,
            changed_result,
            &stdout,
            true,
            &format!("{}-callback-result", case.id),
        );
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_rehashed_callback_semantic_rejected(
        case: &crate::DifferentialCase,
        semantic: crate::SemanticObservation,
        name: &str,
    ) {
        let baseline_root = root(&format!("{name}-baseline"));
        let (_, status, baseline, stdout, stderr) =
            execute_runtime_interaction_with_status(case, &baseline_root);
        let baseline_directory = retain_runtime_semantic_observation(
            &baseline_root,
            case,
            baseline,
            &status,
            &stdout,
            &stderr,
        );
        verify_observation_bundle_for_case(&baseline_directory, case)
            .unwrap_or_else(|error| panic!("executed callback baseline {name} failed: {error}"));
        fs::remove_dir_all(baseline_root).unwrap();

        let root = root(name);
        let directory =
            retain_runtime_semantic_observation(&root, case, semantic, &status, &stdout, &stderr);
        assert!(
            verify_observation_bundle_for_case(&directory, case).is_err(),
            "rehashed callback semantic mutant {name} was accepted"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn retain_runtime_semantic_observation(
        root: &Path,
        case: &crate::DifferentialCase,
        semantic: crate::SemanticObservation,
        status: &crate::ProcessStatus,
        stdout: &[u8],
        stderr: &[u8],
    ) -> PathBuf {
        let mut retained = report();
        for observation in [&mut retained.oracle, &mut retained.candidate] {
            observation.case_id = Arc::clone(&case.id);
            observation.environment_profile = case.environment_profile;
            observation.process_helper_sha256 = case.process_helper_sha256;
            observation.stdout = BoundedCapture::from_bytes(stdout.to_vec());
            observation.raw_stderr = BoundedCapture::from_bytes(stderr.to_vec());
            observation.claim_input_stderr = BoundedCapture::from_bytes(stderr.to_vec());
            observation.stderr = BoundedCapture::from_bytes(stderr.to_vec());
            observation.status = status.clone();
        }
        retained.candidate.semantic = Some(semantic);
        retain_observation_bundle(&root.join("evidence"), case, &retained)
            .expect("retain runtime callback observation")
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_multi_call_callback_contract(
        case: &crate::DifferentialCase,
        builtin: &str,
        label: &str,
        source_root: &Path,
    ) {
        let (success, semantic) = execute_runtime_interaction(case, source_root);
        assert!(success);
        let invocation_count = callback_events_mut(&mut semantic.clone(), builtin).len();
        assert!(invocation_count >= 2);

        let mut omitted = semantic.clone();
        callback_events_mut(&mut omitted, builtin).pop();
        assert_rehashed_callback_semantic_rejected(
            case,
            omitted,
            &format!("callback-{label}-omitted"),
        );

        let mut duplicated = semantic.clone();
        let callbacks = callback_events_mut(&mut duplicated, builtin);
        let mut duplicate = callbacks
            .last()
            .expect("callback contract is nonempty")
            .clone();
        duplicate.invocation = u64::try_from(invocation_count).unwrap().saturating_add(1);
        callbacks.push(duplicate);
        assert_rehashed_callback_semantic_rejected(
            case,
            duplicated,
            &format!("callback-{label}-duplicated"),
        );

        let mut reordered = semantic.clone();
        let callbacks = callback_events_mut(&mut reordered, builtin);
        callbacks.swap(0, 1);
        callbacks[0].invocation = 1;
        callbacks[1].invocation = 2;
        assert_rehashed_callback_semantic_rejected(
            case,
            reordered,
            &format!("callback-{label}-reordered"),
        );

        let mut changed_argument = semantic.clone();
        callback_events_mut(&mut changed_argument, builtin)[0].canonical_arguments[0] =
            Arc::from("{\"type\":\"Int\",\"value\":\"9\"}");
        assert_rehashed_callback_semantic_rejected(
            case,
            changed_argument,
            &format!("callback-{label}-argument"),
        );

        let mut changed_result = semantic;
        callback_events_mut(&mut changed_result, builtin)[0].canonical_result =
            Arc::from("{\"type\":\"Int\",\"value\":\"9\"}");
        assert_rehashed_callback_semantic_rejected(
            case,
            changed_result,
            &format!("callback-{label}-result"),
        );

        let (_, mut changed_result) = execute_runtime_interaction(case, source_root);
        callback_events_mut(&mut changed_result, builtin)[0].canonical_result =
            Arc::from("{\"type\":\"Int\",\"value\":\"9\"}");
        assert_rehashed_callback_semantic_rejected(
            case,
            changed_result,
            &format!("callback-{label}-result"),
        );
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_fix_callback_duplicate_is_rejected(
        cases: &[crate::DifferentialCase],
        source_root: &Path,
    ) {
        let case = cases
            .iter()
            .find(|case| case.id.as_ref() == "runtime-typed-fix")
            .expect("typed Function.fix case");
        let (success, mut semantic) = execute_runtime_interaction(case, source_root);
        assert!(success);
        let callbacks = callback_events_mut(&mut semantic, "Function.fix");
        let mut duplicate = callbacks[0].clone();
        duplicate.invocation = 2;
        callbacks.push(duplicate);
        assert_rehashed_callback_semantic_rejected(case, semantic, "callback-fix-duplicated");
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_multi_call_callback_cases(
        cases: &[crate::DifferentialCase],
        source_root: &Path,
        definitions: &[(&str, &str, &str)],
    ) {
        for &(case_id, builtin, label) in definitions {
            let case = cases
                .iter()
                .find(|case| case.id.as_ref() == case_id)
                .unwrap_or_else(|| panic!("missing typed callback case {case_id}"));
            assert_multi_call_callback_contract(case, builtin, label, source_root);
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn finish_multi_call_callback_test(cases: &[crate::DifferentialCase], source_root: PathBuf) {
        assert_fix_callback_duplicate_is_rejected(cases, &source_root);
        fs::remove_dir_all(source_root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn multi_call_callback_contract_rejects_omission_duplication_reorder_and_argument_mutation() {
        let cases = crate::committed_differential_cases();
        let source_root = root("callback-contract-source");
        assert_multi_call_callback_cases(
            &cases,
            &source_root,
            &[
                (
                    "runtime-typed-maybe-map-maybe",
                    "Maybe.mapMaybe",
                    "maybe-map",
                ),
                ("runtime-typed-list-map", "List.map", "list-map"),
                ("runtime-typed-list-all", "List.all", "list-all"),
                ("runtime-typed-list-any", "List.any", "list-any"),
                (
                    "runtime-typed-list-drop-while",
                    "List.dropWhile",
                    "list-drop-while",
                ),
                ("runtime-typed-list-find", "List.find", "list-find"),
                (
                    "runtime-typed-list-find-index",
                    "List.findIndex",
                    "list-find-index",
                ),
                (
                    "runtime-typed-list-find-indices",
                    "List.findIndices",
                    "list-find-indices",
                ),
                ("runtime-typed-list-filter", "List.filter", "list-filter"),
                ("runtime-typed-list-break", "List.break", "list-break"),
                ("runtime-typed-list-span", "List.span", "list-span"),
                (
                    "runtime-typed-list-take-while",
                    "List.takeWhile",
                    "list-take-while",
                ),
                (
                    "runtime-typed-list-partition",
                    "List.partition",
                    "list-partition",
                ),
                ("text-any-boundary-unicode", "Text.any", "text-any-unicode"),
                (
                    "text-filter-boundary-unicode",
                    "Text.filter",
                    "text-filter-unicode",
                ),
            ],
        );

        finish_multi_call_callback_test(&cases, source_root);
    }

    #[cfg(feature = "compat-tracing")]
    const LIST_TREE_MULTI_CALL_CASES: &[(&str, &str, &str)] = &[
        (
            "list-zipwith-boundary-finite-input",
            "List.zipWith",
            "list-zip-with",
        ),
        (
            "list-concatmap-boundary-finite-input",
            "List.concatMap",
            "list-concat-map",
        ),
        (
            "list-deleteby-boundary-finite-input",
            "List.deleteBy",
            "list-delete-by",
        ),
        (
            "list-dropwhileend-boundary-finite-input",
            "List.dropWhileEnd",
            "list-drop-while-end",
        ),
        (
            "list-sorton-boundary-finite-input",
            "List.sortOn",
            "list-sort-on",
        ),
        (
            "list-groupby-boundary-finite-input",
            "List.groupBy",
            "list-group-by",
        ),
        (
            "runtime-typed-list-unfoldr-exact",
            "List.unfoldr",
            "list-unfoldr",
        ),
        (
            "runtime-list-iterate-finite-prefix",
            "List.iterate'",
            "list-iterate",
        ),
        (
            "list-foldl-boundary-finite-input",
            "List.foldl'",
            "list-foldl",
        ),
        (
            "list-foldr-boundary-finite-input",
            "List.foldr",
            "list-foldr",
        ),
        (
            "list-scanl-boundary-finite-input",
            "List.scanl'",
            "list-scanl",
        ),
        (
            "list-scanr-boundary-finite-input",
            "List.scanr",
            "list-scanr",
        ),
        (
            "list-mapaccuml-boundary-finite-input",
            "List.mapAccumL",
            "list-map-accum-l",
        ),
        (
            "list-mapaccumr-boundary-finite-input",
            "List.mapAccumR",
            "list-map-accum-r",
        ),
        ("tree-map-boundary-finite-input", "Tree.map", "tree-map"),
        (
            "tree-foldtree-boundary-finite-input",
            "Tree.foldTree",
            "tree-fold-tree",
        ),
        (
            "runtime-typed-tree-unfold-exact",
            "Tree.unfoldTree",
            "tree-unfold-tree",
        ),
    ];

    #[cfg(feature = "compat-tracing")]
    const MAP_MULTI_CALL_CASES: &[(&str, &str, &str)] = &[
        ("map-all-boundary-finite-input", "Map.all", "map-all"),
        ("map-any-boundary-finite-input", "Map.any", "map-any"),
        (
            "map-filter-boundary-finite-input",
            "Map.filter",
            "map-filter",
        ),
        (
            "map-filterwithkey-boundary-finite-input",
            "Map.filterWithKey",
            "map-filter-with-key",
        ),
        ("map-map-boundary-finite-input", "Map.map", "map-map"),
    ];

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn boundary_callback_contracts_reject_rehashed_multi_call_mutations() {
        let cases = crate::committed_differential_cases();
        let source_root = root("boundary-callback-contract-source");
        assert_multi_call_callback_cases(&cases, &source_root, LIST_TREE_MULTI_CALL_CASES);
        assert_multi_call_callback_cases(&cases, &source_root, MAP_MULTI_CALL_CASES);
        fs::remove_dir_all(source_root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn callback_boundary_contract_rejects_injected_and_omitted_calls_after_rehash() {
        let cases = crate::committed_differential_cases();
        let empty = cases
            .iter()
            .find(|case| case.id.as_ref() == "list-map-boundary-empty-input")
            .expect("empty List.map boundary case");
        let singleton = cases
            .iter()
            .find(|case| case.id.as_ref() == "list-map-boundary-singleton-input")
            .expect("singleton List.map boundary case");
        let source_root = root("callback-boundary-source");
        let (empty_success, mut empty_semantic) = execute_runtime_interaction(empty, &source_root);
        let (singleton_success, mut singleton_semantic) =
            execute_runtime_interaction(singleton, &source_root);
        assert!(empty_success && singleton_success);
        let singleton_callback = callback_events_mut(&mut singleton_semantic, "List.map")
            .pop()
            .expect("singleton boundary invokes its callback once");
        assert!(callback_events_mut(&mut empty_semantic, "List.map").is_empty());
        callback_events_mut(&mut empty_semantic, "List.map").push(singleton_callback);
        assert_rehashed_callback_semantic_rejected(
            empty,
            empty_semantic,
            "callback-boundary-injected",
        );
        assert_rehashed_callback_semantic_rejected(
            singleton,
            singleton_semantic,
            "callback-boundary-omitted",
        );
        fs::remove_dir_all(source_root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn iterate_lazy_prefix_binds_one_callback_and_rejects_rehashed_mutations() {
        let cases = crate::committed_differential_cases();
        let finite = cases
            .iter()
            .find(|case| case.id.as_ref() == "runtime-list-iterate-finite-prefix")
            .expect("finite List.iterate' case");
        let lazy = cases
            .iter()
            .find(|case| case.id.as_ref() == "runtime-list-iterate-undemanded-tail")
            .expect("lazy List.iterate' case");
        let source_root = root("list-iterate-lazy-callback-source");
        let (bundle_root, directory) =
            retain_executed_runtime_case(lazy, "list-iterate-lazy-callback-baseline");
        verify_observation_bundle_for_case(&directory, lazy)
            .expect("reviewed lazy iterate baseline bundle");
        fs::remove_dir_all(bundle_root).unwrap();

        let (finite_success, finite_semantic) = execute_runtime_interaction(finite, &source_root);
        let (lazy_success, lazy_semantic) = execute_runtime_interaction(lazy, &source_root);
        assert!(finite_success && lazy_success);
        let callbacks = callback_events_mut(&mut lazy_semantic.clone(), "List.iterate'").clone();
        assert_eq!(callbacks.len(), 1);
        assert_eq!(
            callbacks[0].canonical_arguments[0].as_ref(),
            "{\"type\":\"Int\",\"value\":\"7\"}"
        );
        assert_eq!(
            callbacks[0].canonical_result.as_ref(),
            "{\"type\":\"Int\",\"value\":\"8\"}"
        );

        let mut omitted = lazy_semantic.clone();
        callback_events_mut(&mut omitted, "List.iterate'").clear();
        assert_rehashed_callback_semantic_rejected(
            lazy,
            omitted,
            "list-iterate-lazy-callback-omitted",
        );

        let mut wrong_argument = lazy_semantic.clone();
        callback_events_mut(&mut wrong_argument, "List.iterate'")[0].canonical_arguments[0] =
            Arc::from("{\"type\":\"Int\",\"value\":\"6\"}");
        assert_rehashed_callback_semantic_rejected(
            lazy,
            wrong_argument,
            "list-iterate-lazy-callback-argument",
        );

        let mut wrong_result = lazy_semantic.clone();
        callback_events_mut(&mut wrong_result, "List.iterate'")[0].canonical_result =
            Arc::from("{\"type\":\"Int\",\"value\":\"9\"}");
        assert_rehashed_callback_semantic_rejected(
            lazy,
            wrong_result,
            "list-iterate-lazy-callback-result",
        );

        let mut extra = lazy_semantic.clone();
        let callbacks = callback_events_mut(&mut extra, "List.iterate'");
        let mut duplicate = callbacks[0].clone();
        duplicate.invocation = 2;
        callbacks.push(duplicate);
        assert_rehashed_callback_semantic_rejected(lazy, extra, "list-iterate-lazy-callback-extra");

        let mut wrong_callback = lazy_semantic;
        callback_events_mut(&mut wrong_callback, "List.iterate'")[0] =
            callback_events_mut(&mut finite_semantic.clone(), "List.iterate'")[0].clone();
        assert_rehashed_callback_semantic_rejected(
            lazy,
            wrong_callback,
            "list-iterate-lazy-callback-finite-substitution",
        );

        let mut reordered = finite_semantic;
        let callbacks = callback_events_mut(&mut reordered, "List.iterate'");
        callbacks.swap(0, 1);
        callbacks[0].invocation = 1;
        callbacks[1].invocation = 2;
        assert_rehashed_callback_semantic_rejected(
            finite,
            reordered,
            "list-iterate-finite-callback-order",
        );
        fs::remove_dir_all(source_root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn callback_argument_order_substitutions_are_rejected_after_rehash() {
        let cases = crate::committed_differential_cases();
        let source_root = root("map-collision-callback-source");
        for (case_id, builtin, label) in [
            (
                "map-insertwith-boundary-finite-input",
                "Map.insertWith",
                "insert-with",
            ),
            (
                "map-unionwith-boundary-finite-input",
                "Map.unionWith",
                "union-with",
            ),
            (
                "list-deleteby-boundary-finite-input",
                "List.deleteBy",
                "delete-by",
            ),
        ] {
            let case = cases
                .iter()
                .find(|case| case.id.as_ref() == case_id)
                .unwrap_or_else(|| panic!("missing callback order case {case_id}"));
            let (success, mut semantic) = execute_runtime_interaction(case, &source_root);
            assert!(success);
            let callbacks = callback_events_mut(&mut semantic, builtin);
            assert!(!callbacks.is_empty());
            let callback = callbacks
                .iter_mut()
                .find(|callback| {
                    callback.canonical_arguments.len() == 2
                        && callback.canonical_arguments[0] != callback.canonical_arguments[1]
                })
                .expect("argument-order test needs one asymmetric callback");
            callback.canonical_arguments.swap(0, 1);
            assert_rehashed_callback_semantic_rejected(
                case,
                semantic,
                &format!("callback-{label}-argument-order"),
            );
        }
        fs::remove_dir_all(source_root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn retained_typed_map_order_and_list_termination_substitutions_are_rejected() {
        for (name, source, original, replacement) in [
            (
                "typed-map-order",
                "main = IO.print $ Map.size $ Bool.bool (Map.fromList [(2,\"b\"),(1,\"a\")]) (Map.fromList []) Bool.False\n",
                "",
                "",
            ),
            (
                "typed-list-termination",
                "main = IO.print $ List.length $ Bool.bool [1,2] [3] Bool.False\n",
                "\"terminationHex\":\"6e696c\"",
                "\"terminationHex\":\"6e6f742d666f72636564\"",
            ),
        ] {
            let case = typed_result_case(name, source);
            let program = hell_compiler::compile_source(
                &mut hell_compiler::CompilerSession::upstream(),
                name,
                source,
            )
            .unwrap();
            let root = root(name);
            let trace = root.join("trace.json");
            hell_runtime::run_main_with_semantic_trace(
                program,
                hell_runtime::RuntimeContext::new(Vec::new(), Vec::<u8>::new()),
                &trace,
            )
            .unwrap();
            let semantic = crate::parse_semantic_trace(&fs::read(&trace).unwrap()).unwrap();
            let mut retained = report();
            retained.candidate.case_id = case.id.clone();
            retained.candidate.semantic = Some(semantic);
            let evidence = root.join("evidence");
            let directory = retain_observation_bundle(&evidence, &case, &retained).unwrap();
            verify_observation_bundle_for_case(&directory, &case).unwrap();
            let path = directory
                .join("candidate")
                .join("semantic-typed-result.json");
            let typed = fs::read_to_string(&path).unwrap();
            let substituted = if name == "typed-map-order" {
                let map_start = typed.find("{\"type\":\"Map\"").unwrap();
                let map = &typed[map_start..typed.len().saturating_sub(2)];
                let body = map
                    .strip_prefix("{\"type\":\"Map\",\"entries\":[")
                    .and_then(|value| value.strip_suffix("]}"))
                    .unwrap();
                let entries = crate::split_canonical_array(body).unwrap();
                assert_eq!(entries.len(), 2);
                let reordered = format!(
                    "{{\"type\":\"Map\",\"entries\":[{},{}]}}",
                    entries[1], entries[0]
                );
                typed.replacen(map, &reordered, 1)
            } else {
                typed.replace(original, replacement)
            };
            assert_ne!(typed, substituted, "{name} substitution did not match");
            fs::write(path, substituted).unwrap();
            fs::remove_file(directory.join("bundle-manifest.json")).unwrap();
            fs::remove_file(directory.join("bundle-manifest.sha256")).unwrap();
            write_bundle_manifest(&directory, &case, sha256_bytes(b"epoch")).unwrap();
            assert!(verify_observation_bundle_for_case(&directory, &case).is_err());
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn retained_runtime_enum_substitution_is_rejected_after_rehash() {
        let case = crate::committed_differential_cases()
            .into_iter()
            .find(|case| case.id.as_ref() == "runtime-typed-io-no-buffering")
            .expect("NoBuffering typed case");
        let root = root("runtime-enum-substitution");
        let (success, semantic) = execute_runtime_interaction(&case, &root);
        assert!(success);
        let mut retained = report();
        retained.candidate.case_id = case.id.clone();
        retained.candidate.semantic = Some(semantic);
        let directory =
            retain_observation_bundle(&root.join("evidence"), &case, &retained).unwrap();
        verify_observation_bundle_for_case(&directory, &case).unwrap();
        let path = directory
            .join("candidate")
            .join("semantic-typed-result.json");
        let typed = fs::read_to_string(&path).unwrap();
        let substituted = typed.replace(
            "\"type\":\"BufferMode\",\"value\":\"none\"",
            "\"type\":\"BufferMode\",\"value\":\"invalid\"",
        );
        assert_ne!(typed, substituted);
        fs::write(path, substituted).unwrap();
        fs::remove_file(directory.join("bundle-manifest.json")).unwrap();
        fs::remove_file(directory.join("bundle-manifest.sha256")).unwrap();
        write_bundle_manifest(&directory, &case, sha256_bytes(b"epoch")).unwrap();
        assert!(verify_observation_bundle_for_case(&directory, &case).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn retained_runtime_handle_substitution_is_rejected_after_rehash() {
        let case = crate::committed_differential_cases()
            .into_iter()
            .find(|case| case.id.as_ref() == "runtime-typed-io-stdout")
            .expect("stdout typed case");
        let root = root("runtime-handle-substitution");
        let (success, semantic) = execute_runtime_interaction(&case, &root);
        assert!(success);
        let mut retained = report();
        retained.candidate.case_id = case.id.clone();
        retained.candidate.semantic = Some(semantic);
        let directory =
            retain_observation_bundle(&root.join("evidence"), &case, &retained).unwrap();
        verify_observation_bundle_for_case(&directory, &case).unwrap();
        let path = directory
            .join("candidate")
            .join("semantic-typed-result.json");
        let typed = fs::read_to_string(&path).unwrap();
        let substituted = typed.replace(
            "\"type\":\"Handle\",\"kind\":\"stdout\"",
            "\"type\":\"Handle\",\"kind\":\"stdin\"",
        );
        assert_ne!(typed, substituted);
        fs::write(path, substituted).unwrap();
        fs::remove_file(directory.join("bundle-manifest.json")).unwrap();
        fs::remove_file(directory.join("bundle-manifest.sha256")).unwrap();
        write_bundle_manifest(&directory, &case, sha256_bytes(b"epoch")).unwrap();
        assert!(verify_observation_bundle_for_case(&directory, &case).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn retained_json_constructor_arity_substitution_is_rejected_after_rehash() {
        let case = crate::committed_differential_cases()
            .into_iter()
            .find(|case| case.id.as_ref() == "runtime-typed-json-bool")
            .expect("JSON Bool typed case");
        let root = root("runtime-json-arity-substitution");
        let (success, semantic, stdout) = execute_runtime_interaction_with_stdout(&case, &root);
        assert!(success);
        assert_eq!(stdout, b"true");
        let mut retained = report();
        for observation in [&mut retained.oracle, &mut retained.candidate] {
            observation.case_id = Arc::clone(&case.id);
            observation.stdout = crate::BoundedCapture::from_bytes(stdout.clone());
        }
        retained.candidate.semantic = Some(semantic);
        let directory =
            retain_observation_bundle(&root.join("evidence"), &case, &retained).unwrap();
        verify_observation_bundle_for_case(&directory, &case).unwrap();
        let path = directory
            .join("candidate")
            .join("semantic-typed-result.json");
        let typed = fs::read_to_string(&path).unwrap();
        let substituted = typed.replace(
            "\"constructor\":\"Bool\",\"payloads\":[{\"type\":\"Bool\",\"value\":true}]",
            "\"constructor\":\"Bool\",\"payloads\":[]",
        );
        assert_ne!(typed, substituted);
        fs::write(path, substituted).unwrap();
        fs::remove_file(directory.join("bundle-manifest.json")).unwrap();
        fs::remove_file(directory.join("bundle-manifest.sha256")).unwrap();
        write_bundle_manifest(&directory, &case, sha256_bytes(b"epoch")).unwrap();
        assert!(verify_observation_bundle_for_case(&directory, &case).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn retained_bottom_is_bound_to_the_selected_argument_boundary() {
        let name = "typed-force-boundary";
        let source =
            "main = IO.print $ Bool.bool 1 (Error.error \"typed-bottom\" :: Int) Bool.True\n";
        let case = typed_result_case(name, source);
        let program = hell_compiler::compile_source(
            &mut hell_compiler::CompilerSession::upstream(),
            name,
            source,
        )
        .unwrap();
        let root = root(name);
        let trace = root.join("trace.json");
        let outcome = hell_runtime::run_main_with_semantic_trace(
            program,
            hell_runtime::RuntimeContext::new(Vec::new(), Vec::<u8>::new()),
            &trace,
        );
        assert!(outcome.is_err());
        let semantic = crate::parse_semantic_trace(&fs::read(&trace).unwrap()).unwrap();
        let mut retained = report();
        retained.candidate.case_id = case.id.clone();
        retained.candidate.status = crate::ProcessStatus {
            success: false,
            code: Some(1),
        };
        retained.candidate.semantic = Some(semantic);
        retained.mismatches = crate::compare(&retained.oracle, &retained.candidate);
        let directory =
            retain_observation_bundle(&root.join("evidence"), &case, &retained).unwrap();
        verify_observation_bundle_for_case(&directory, &case).unwrap();
        let path = directory
            .join("candidate")
            .join("semantic-typed-result.json");
        let typed = fs::read_to_string(&path).unwrap();
        assert!(typed.contains("\"argument\":1,\"boundary\":\"conditional-selected\""));
        fs::write(&path, typed.replace("\"argument\":1", "\"argument\":0")).unwrap();
        fs::remove_file(directory.join("bundle-manifest.json")).unwrap();
        fs::remove_file(directory.join("bundle-manifest.sha256")).unwrap();
        write_bundle_manifest(&directory, &case, sha256_bytes(b"epoch")).unwrap();
        assert!(verify_observation_bundle_for_case(&directory, &case).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn typed_result_case(name: &str, source: &str) -> DifferentialCase {
        let builtin = hell_builtins::lookup("Bool.bool").unwrap();
        DifferentialCase {
            id: name.into(),
            source: source.into(),
            claim_evidence: Some(ClaimEvidenceDescriptor {
                schema_version: 8,
                profile: hell_builtins::ExecutionProfile::Upstream,
                harness_normalizers: vec![NormalizerId::DiagnosticSandboxPathV1],
                claim_normalizers: Vec::new(),
                targets: vec![crate::EvidenceTarget::new(
                    builtin.name,
                    hell_builtins::CompatibilityDimension::PureRuntime,
                )],
                semantic_targets: vec![crate::EvidenceTargetV2::new(
                    builtin.name,
                    hell_builtins::CompatibilityDimension::PureRuntime,
                    vec![crate::ObligationId("typed-result".into())],
                    CausalSignal::RuntimeAdapterAndForceTrace,
                    vec![hell_builtins::ClaimPlatform::All],
                )],
                callback_contracts: Vec::new(),
                review_state: crate::CaseReviewState::Reviewed,
                review_statement: "typed-composite-retention-review-v1".into(),
                source_sha256: sha256_bytes(source.as_bytes()),
            }),
            ..DifferentialCase::default()
        }
    }

    #[test]
    fn claim_eligible_bundle_rejects_rehashed_causal_order_and_class_mutants() {
        for (name, original, replacement) in [
            (
                "phase-order",
                "\"eventId\": 1, \"kind\": \"parsed-builtin\"}, {\"eventId\": 2, \"kind\": \"resolved-builtin\"",
                "\"eventId\": 1, \"kind\": \"resolved-builtin\"}, {\"eventId\": 2, \"kind\": \"parsed-builtin\"",
            ),
            (
                "class-substitution",
                "\"eventId\": 12, \"kind\": \"resource-event\"",
                "\"eventId\": 12, \"kind\": \"task-event\"",
            ),
        ] {
            let root = root(name);
            let case = claim_eligible_case();
            let directory = retain_observation_bundle(&root, &case, &full_trace_report()).unwrap();
            let path = directory.join("candidate").join("observation.json");
            let contents = fs::read_to_string(&path).unwrap();
            assert!(contents.contains(original));
            fs::write(&path, contents.replacen(original, replacement, 1)).unwrap();
            fs::remove_file(directory.join("bundle-manifest.json")).unwrap();
            fs::remove_file(directory.join("bundle-manifest.sha256")).unwrap();
            write_bundle_manifest(&directory, &case, sha256_bytes(b"epoch")).unwrap();
            assert!(verify_observation_bundle_for_case(&directory, &case).is_err());
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn claim_bundle_rejects_rehashed_effect_schema_and_causality_substitutions() {
        for (name, original, replacement, replace_all) in [
            (
                "effect-schema",
                "\"semanticEffectTrace\"",
                "\"semanticEffectTraceForged\"",
                false,
            ),
            (
                "effect-owner",
                "\"ownerTaskId\": 1",
                "\"ownerTaskId\": 2",
                false,
            ),
            (
                "effect-pair",
                "\"sequence\": 1, \"parentSequence\": null, \"effect\": \"completed\"",
                "\"sequence\": 2, \"parentSequence\": null, \"effect\": \"completed\"",
                false,
            ),
            (
                "effect-parent",
                "\"sequence\": 1, \"parentSequence\": null",
                "\"sequence\": 1, \"parentSequence\": 1",
                false,
            ),
            (
                "effect-gap",
                "\"sequence\": 1, \"parentSequence\": null",
                "\"sequence\": 3, \"parentSequence\": null",
                true,
            ),
        ] {
            let root = root(name);
            let case = claim_eligible_case();
            let directory = retain_observation_bundle(&root, &case, &full_trace_report()).unwrap();
            let path = directory.join("candidate").join("observation.json");
            let contents = fs::read_to_string(&path).unwrap();
            assert!(contents.contains(original));
            let forged = if replace_all {
                contents.replace(original, replacement)
            } else {
                contents.replacen(original, replacement, 1)
            };
            fs::write(&path, forged).unwrap();
            fs::remove_file(directory.join("bundle-manifest.json")).unwrap();
            fs::remove_file(directory.join("bundle-manifest.sha256")).unwrap();
            write_bundle_manifest(&directory, &case, sha256_bytes(b"epoch")).unwrap();
            assert!(verify_observation_bundle(&directory).is_ok());
            assert!(verify_observation_bundle_for_case(&directory, &case).is_err());
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn retained_applicative_matrix_executes_every_direct_instance_and_path() {
        let cases = crate::committed_differential_cases();
        let applicative = cases
            .iter()
            .filter(|case| case.id.starts_with("runtime-typed-applicative-"))
            .collect::<Vec<_>>();
        assert!(!applicative.is_empty());
        for case in applicative {
            let (root, _) = retain_executed_runtime_case(case, case.id.as_ref());
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn retained_applicative_matrix_rejects_callback_value_transport_and_target_mutants() {
        let cases = crate::committed_differential_cases();
        assert_applicative_callback_mutants(&cases);
        assert_applicative_pure_mutants(&cases);
        assert_applicative_value_transport_mutants(&cases);
        assert_applicative_instance_mutants(&cases);
        assert_applicative_target_mutants(&cases);
        assert_applicative_argv_mutants(&cases);
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_applicative_callback_mutants(cases: &[crate::DifferentialCase]) {
        for (builtin, slug) in [("<*>", "apply"), ("<**>", "apply-flipped")] {
            for instance in ["list", "tree"] {
                let path = if instance == "list" {
                    "cartesian"
                } else {
                    "branching"
                };
                let id = format!("runtime-typed-applicative-{slug}-{instance}-{path}");
                let source_root = root(&format!("{id}-callbacks"));
                assert_multi_call_callback_contract(
                    runtime_case(cases, &id),
                    builtin,
                    &id,
                    &source_root,
                );
                fs::remove_dir_all(source_root).unwrap();
            }
            for (instance, path) in [
                ("io", "ordered"),
                ("maybe", "success"),
                ("either", "success"),
                ("parser", "present"),
            ] {
                let id = format!("runtime-typed-applicative-{slug}-{instance}-{path}");
                assert_one_call_traversal_callback(runtime_case(cases, &id), builtin);
            }
            for (finite, empty) in [
                ("io-ordered", "io-short"),
                ("maybe-success", "maybe-short"),
                ("either-success", "either-short"),
                ("list-cartesian", "list-short"),
                ("parser-present", "parser-absent"),
                ("parser-present", "parser-consumed-missing"),
            ] {
                assert_zero_call_traversal_callback(
                    runtime_case(cases, &format!("runtime-typed-applicative-{slug}-{finite}")),
                    runtime_case(cases, &format!("runtime-typed-applicative-{slug}-{empty}")),
                    builtin,
                );
            }
            assert_traversal_callback_argument_index(
                runtime_case(
                    cases,
                    &format!("runtime-typed-applicative-{slug}-maybe-success"),
                ),
                builtin,
            );
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_applicative_pure_mutants(cases: &[crate::DifferentialCase]) {
        for instance in ["io", "maybe", "list", "tree", "either"] {
            let id = format!("runtime-typed-applicative-pure-{instance}-value");
            assert_functor_typed_substitution(runtime_case(cases, &id), "Applicative.pure");
        }
        for instance in ["io", "maybe", "list", "tree", "parser", "either"] {
            let value = format!("runtime-typed-applicative-pure-{instance}-value");
            assert_runtime_raw_substitution(runtime_case(cases, &value), &format!("{value}-raw"));
            let lazy = format!("runtime-typed-applicative-pure-{instance}-lazy");
            for class in ["lazy-adapter-entry", "lazy-adapter-exit"] {
                assert_lazy_state_substitution_rejected(cases, &lazy, "Applicative.pure", class);
            }
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_applicative_value_transport_mutants(cases: &[crate::DifferentialCase]) {
        for (builtin, slug) in [("<*>", "apply"), ("<**>", "apply-flipped")] {
            for (instance, path) in [
                ("io", "ordered"),
                ("maybe", "success"),
                ("either", "success"),
                ("list", "cartesian"),
                ("tree", "branching"),
                ("maybe", "short"),
                ("either", "short"),
                ("list", "short"),
            ] {
                let id = format!("runtime-typed-applicative-{slug}-{instance}-{path}");
                let case = runtime_case(cases, &id);
                assert_functor_typed_substitution(case, builtin);
                assert_runtime_raw_substitution(case, &format!("{id}-raw"));
            }
            let parser = format!("runtime-typed-applicative-{slug}-parser-present");
            assert_runtime_raw_substitution(runtime_case(cases, &parser), &format!("{parser}-raw"));
            for instance_path in [
                "io-short",
                "maybe-short",
                "either-short",
                "list-short",
                "tree-branching",
                "parser-absent",
                "parser-consumed-missing",
            ] {
                let id = format!("runtime-typed-applicative-{slug}-{instance_path}");
                for class in ["lazy-adapter-entry", "lazy-adapter-exit"] {
                    assert_lazy_state_substitution_rejected(cases, &id, builtin, class);
                }
            }
            for path in ["io-short", "parser-absent", "parser-consumed-missing"] {
                let id = format!("runtime-typed-applicative-{slug}-{path}");
                assert_rehashed_process_status_substitution_rejected(
                    runtime_case(cases, &id),
                    &format!("{id}-status"),
                    (false, 1),
                    (true, 0),
                );
            }
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_applicative_instance_mutants(cases: &[crate::DifferentialCase]) {
        let substitutions = [
            ("io", "IO", "Maybe"),
            ("maybe", "Maybe", "[]"),
            ("list", "[]", "Tree"),
            ("tree", "Tree", "Options.Parser"),
            ("parser", "Options.Parser", "Either"),
            ("either", "Either", "IO"),
        ];
        for (builtin, slug) in [
            ("Applicative.pure", "pure"),
            ("<*>", "apply"),
            ("<**>", "apply-flipped"),
        ] {
            for (instance, original, replacement) in substitutions {
                let path = applicative_representative_path(slug, instance);
                let id = format!("runtime-typed-applicative-{slug}-{instance}-{path}");
                assert_applicative_instance_substitution(
                    runtime_case(cases, &id),
                    builtin,
                    original,
                    replacement,
                );
            }
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn applicative_representative_path(slug: &str, instance: &str) -> &'static str {
        if slug == "pure" {
            return "value";
        }
        match instance {
            "io" => "ordered",
            "maybe" | "either" => "success",
            "list" => "cartesian",
            "tree" => "branching",
            "parser" => "present",
            _ => unreachable!("Applicative instance inventory is closed"),
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_applicative_instance_substitution(
        case: &crate::DifferentialCase,
        builtin: &str,
        original: &str,
        replacement: &str,
    ) {
        let source_root = root(&format!("{}-instance", case.id));
        let (success, mut semantic, stdout) =
            execute_runtime_interaction_with_stdout(case, &source_root);
        let target = hell_builtins::lookup(builtin).unwrap().id;
        let event = semantic
            .obligation_trace
            .iter_mut()
            .find(|event| event.builtin == target)
            .expect("Applicative target event");
        assert_eq!(event.instance_target.as_deref(), Some(original));
        event.instance_target = Some(Arc::from(replacement));
        assert_rehashed_runtime_semantic_rejected(
            case,
            semantic,
            &stdout,
            success,
            &format!("{}-instance-{replacement}", case.id),
        );
        fs::remove_dir_all(source_root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_applicative_target_mutants(cases: &[crate::DifferentialCase]) {
        for (case_id, builtin, replacement) in [
            (
                "runtime-typed-applicative-pure-maybe-value",
                "Applicative.pure",
                "<*>",
            ),
            ("runtime-typed-applicative-apply-maybe-short", "<*>", "<**>"),
            (
                "runtime-typed-applicative-apply-flipped-maybe-short",
                "<**>",
                "<*>",
            ),
        ] {
            let case = runtime_case(cases, case_id);
            let source_root = root(&format!("{case_id}-target"));
            let (success, mut semantic, stdout) =
                execute_runtime_interaction_with_stdout(case, &source_root);
            let target = hell_builtins::lookup(builtin).unwrap().id;
            semantic
                .obligation_trace
                .iter_mut()
                .find(|event| event.builtin == target)
                .expect("Applicative target event")
                .builtin = hell_builtins::lookup(replacement).unwrap().id;
            assert_rehashed_runtime_semantic_rejected(
                case,
                semantic,
                &stdout,
                success,
                &format!("{case_id}-target-{replacement}"),
            );
            fs::remove_dir_all(source_root).unwrap();
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_applicative_argv_mutants(cases: &[crate::DifferentialCase]) {
        for slug in ["apply", "apply-flipped"] {
            let id = format!("runtime-typed-applicative-{slug}-parser-present");
            let parser = runtime_case(cases, &id);
            assert_applicative_argv_mutant(parser, &id, "relabel", |document| {
                document.replacen("abc", "forged", 1)
            });
            assert_applicative_argv_mutant(parser, &id, "reorder", |document| {
                document.replacen(
                    "[\"--value\", \"abc\", \"--function\", \"xy\"]",
                    "[\"--function\", \"xy\", \"--value\", \"abc\"]",
                    1,
                )
            });

            let consumed_id = format!("runtime-typed-applicative-{slug}-parser-consumed-missing");
            let consumed = runtime_case(cases, &consumed_id);
            let (from, to) = if slug == "apply" {
                ("[\"--function\", \"xy\"]", "[\"--value\", \"abc\"]")
            } else {
                ("[\"--value\", \"abc\"]", "[\"--function\", \"xy\"]")
            };
            assert_applicative_argv_mutant(consumed, &consumed_id, "consumed-side", |document| {
                document.replacen(from, to, 1)
            });
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_applicative_argv_mutant(
        parser: &crate::DifferentialCase,
        id: &str,
        label: &str,
        mutate: impl FnOnce(&str) -> String,
    ) {
        let (bundle_root, directory) =
            retain_executed_runtime_case(parser, &format!("{id}-argv-{label}"));
        let input = directory.join("execution-input.json");
        let document = fs::read_to_string(&input).unwrap();
        let changed = mutate(&document);
        assert_ne!(changed, document);
        fs::write(input, changed).unwrap();
        rehash_runtime_bundle(&directory, parser);
        assert!(verify_observation_bundle_for_case(&directory, parser).is_err());
        fs::remove_dir_all(bundle_root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn retained_semigroup_matrix_executes_every_manifest_scope_and_path() {
        let cases = crate::committed_differential_cases();
        let semigroup = cases
            .iter()
            .filter(|case| case.id.starts_with("runtime-typed-semigroup-"))
            .collect::<Vec<_>>();
        assert!(!semigroup.is_empty());
        for case in semigroup {
            let (root, _) = retain_executed_runtime_case(case, case.id.as_ref());
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn retained_semigroup_matrix_rejects_root_premise_value_raw_and_demand_substitutions() {
        let cases = crate::committed_differential_cases();
        assert_semigroup_instance_and_target_mutants(&cases);
        assert_semigroup_premise_mutants(&cases);
        assert_semigroup_value_and_raw_mutants(&cases);
        assert_semigroup_input_and_outcome_mutants(&cases);
        assert_semigroup_demand_mutants(&cases);
    }

    #[cfg(feature = "compat-tracing")]
    fn semigroup_representatives() -> [(&'static str, &'static str, &'static str); 8] {
        [
            ("runtime-typed-semigroup-text-ordered", "Text", "Builder"),
            (
                "runtime-typed-semigroup-builder-ordered",
                "Builder",
                "Vector",
            ),
            ("runtime-typed-semigroup-vector-ordered", "Vector", "[]"),
            ("runtime-typed-semigroup-list-ordered", "[]", "Either"),
            (
                "runtime-typed-semigroup-either-left-right",
                "Either",
                "Options.Mod",
            ),
            (
                "runtime-typed-semigroup-options-mod-left-right",
                "Options.Mod",
                "Options.InfoMod",
            ),
            (
                "runtime-typed-semigroup-options-info-mod-right-precedence",
                "Options.InfoMod",
                "Maybe",
            ),
            (
                "runtime-typed-semigroup-maybe-text-just-combine",
                "Maybe",
                "Text",
            ),
        ]
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_semigroup_instance_and_target_mutants(cases: &[crate::DifferentialCase]) {
        let builtin = hell_builtins::lookup("<>").unwrap().id;
        for (case_id, original, replacement) in semigroup_representatives() {
            let case = runtime_case(cases, case_id);
            let source_root = root(&format!("{case_id}-instance"));
            let (success, mut semantic, stdout) =
                execute_runtime_interaction_with_stdout(case, &source_root);
            let event = semantic
                .obligation_trace
                .iter_mut()
                .find(|event| event.builtin == builtin)
                .expect("Semigroup target event");
            assert_eq!(event.instance_target.as_deref(), Some(original));
            event.instance_target = Some(Arc::from(replacement));
            assert_rehashed_runtime_semantic_rejected(
                case,
                semantic,
                &stdout,
                success,
                &format!("{case_id}-instance-{replacement}"),
            );
            fs::remove_dir_all(source_root).unwrap();
        }

        let case_id = "runtime-typed-semigroup-text-left-empty";
        let case = runtime_case(cases, case_id);
        let source_root = root(&format!("{case_id}-target"));
        let (success, mut semantic, stdout) =
            execute_runtime_interaction_with_stdout(case, &source_root);
        semantic
            .obligation_trace
            .iter_mut()
            .find(|event| event.builtin == builtin)
            .expect("Semigroup target event")
            .builtin = hell_builtins::lookup("Eq.eq").unwrap().id;
        assert_rehashed_runtime_semantic_rejected(
            case,
            semantic,
            &stdout,
            success,
            "semigroup-target-eq",
        );
        fs::remove_dir_all(source_root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_semigroup_premise_mutants(cases: &[crate::DifferentialCase]) {
        let case_id = "runtime-typed-semigroup-maybe-text-just-combine";
        let case = runtime_case(cases, case_id);
        let source_root = root(&format!("{case_id}-premises"));
        let (success, semantic, stdout) =
            execute_runtime_interaction_with_stdout(case, &source_root);
        let builtin = hell_builtins::lookup("<>").unwrap().id;
        for (label, mutate) in [
            (
                "omitted",
                (|premises: &mut Vec<crate::InstancePremiseEvidence>| premises.clear())
                    as fn(&mut Vec<crate::InstancePremiseEvidence>),
            ),
            ("extra", |premises| {
                premises.push(crate::InstancePremiseEvidence {
                    target: Arc::from("Text"),
                    premise_count: 0,
                });
            }),
            ("substituted", |premises| {
                premises[0].target = Arc::from("Int");
            }),
            ("count", |premises| premises[0].premise_count = 1),
        ] {
            let mut mutant = semantic.clone();
            let event = mutant
                .obligation_trace
                .iter_mut()
                .find(|event| event.builtin == builtin)
                .expect("Semigroup Maybe target event");
            assert_eq!(event.instance_target.as_deref(), Some("Maybe"));
            mutate(&mut event.instance_premises);
            assert_rehashed_runtime_semantic_rejected(
                case,
                mutant,
                &stdout,
                success,
                &format!("{case_id}-premise-{label}"),
            );
        }
        fs::remove_dir_all(source_root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_semigroup_value_and_raw_mutants(cases: &[crate::DifferentialCase]) {
        for (case_id, _, _) in semigroup_representatives() {
            let case = runtime_case(cases, case_id);
            assert_functor_typed_substitution(case, "<>");
            assert_runtime_raw_substitution(case, &format!("{case_id}-raw"));
        }
        for case_id in [
            "runtime-typed-semigroup-text-unicode",
            "runtime-typed-semigroup-builder-arbitrary-bytes",
            "runtime-typed-semigroup-list-left-empty",
            "runtime-typed-semigroup-list-right-empty",
            "runtime-typed-semigroup-list-lazy-tail",
            "runtime-typed-semigroup-either-left-left",
            "runtime-typed-semigroup-either-right-left",
            "runtime-typed-semigroup-either-right-nonforce",
            "runtime-typed-semigroup-options-mod-right-left",
            "runtime-typed-semigroup-options-info-mod-reversed-precedence",
            "runtime-typed-semigroup-options-info-mod-full-description",
            "runtime-typed-semigroup-maybe-text-nothing-left",
            "runtime-typed-semigroup-maybe-text-nothing-right",
        ] {
            assert_runtime_raw_substitution(
                runtime_case(cases, case_id),
                &format!("{case_id}-path-raw"),
            );
        }
        assert_semigroup_structural_typed_mutants(cases);
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_semigroup_structural_typed_mutants(cases: &[crate::DifferentialCase]) {
        for (case_id, label, original, replacement) in [
            (
                "runtime-typed-semigroup-list-ordered",
                "tail-payload",
                "2276616c7565223a223422",
                "2276616c7565223a223522",
            ),
            (
                "runtime-typed-semigroup-list-ordered",
                "tail-termination",
                "366536393663",
                "3665366637343264363636663732363336353634",
            ),
            (
                "runtime-typed-semigroup-options-mod-left-right",
                "modifier-order",
                concat!(
                    "{\"kind\":\"long\",\"textHex\":\"6f6e65\"},",
                    "{\"kind\":\"long\",\"textHex\":\"74776f\"}"
                ),
                concat!(
                    "{\"kind\":\"long\",\"textHex\":\"74776f\"},",
                    "{\"kind\":\"long\",\"textHex\":\"6f6e65\"}"
                ),
            ),
            (
                "runtime-typed-semigroup-options-info-mod-right-precedence",
                "header",
                "\"headerHex\":\"7269676874\"",
                "\"headerHex\":\"6c656674\"",
            ),
            (
                "runtime-typed-semigroup-options-info-mod-full-description",
                "full-description",
                "\"fullDescription\":true",
                "\"fullDescription\":false",
            ),
            (
                "runtime-typed-semigroup-maybe-text-just-combine",
                "combined-payload",
                "\"utf8Hex\":\"6c6566747269676874\"",
                "\"utf8Hex\":\"6c65667477726f6e67\"",
            ),
            (
                "runtime-typed-semigroup-builder-arbitrary-bytes",
                "arbitrary-byte",
                "\"hex\":\"ff41fe42\"",
                "\"hex\":\"ff41fe43\"",
            ),
        ] {
            assert_semigroup_structural_typed_mutant(
                runtime_case(cases, case_id),
                label,
                original,
                replacement,
            );
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_semigroup_structural_typed_mutant(
        case: &crate::DifferentialCase,
        label: &str,
        original: &str,
        replacement: &str,
    ) {
        let source_root = root(&format!("{}-typed-{label}", case.id));
        let (success, mut semantic, stdout) =
            execute_runtime_interaction_with_stdout(case, &source_root);
        let canonical = semantic
            .typed_result_canonical
            .as_ref()
            .expect("Semigroup typed result")
            .to_string();
        let changed = canonical.replacen(original, replacement, 1);
        assert_ne!(
            changed, canonical,
            "{} {label} mutation did not match",
            case.id
        );
        let changed: Arc<str> = Arc::from(changed);
        semantic.typed_result_sha256 = Some(sha256_bytes(changed.as_bytes()));
        semantic.typed_result_canonical = Some(changed);
        assert_rehashed_runtime_semantic_rejected(
            case,
            semantic,
            &stdout,
            success,
            &format!("{}-typed-{label}", case.id),
        );
        fs::remove_dir_all(source_root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_semigroup_input_and_outcome_mutants(cases: &[crate::DifferentialCase]) {
        assert_semigroup_stdin_mutant(cases);
        for case_id in [
            "runtime-typed-semigroup-options-mod-left-right",
            "runtime-typed-semigroup-options-mod-right-left",
            "runtime-typed-semigroup-options-info-mod-right-precedence",
            "runtime-typed-semigroup-options-info-mod-reversed-precedence",
            "runtime-typed-semigroup-options-info-mod-full-description",
        ] {
            let case = runtime_case(cases, case_id);
            assert_semigroup_argv_mutant(case);
            assert_semigroup_completion_mutant(case, false, true);
            assert_rehashed_process_status_substitution_rejected(
                case,
                &format!("{case_id}-status"),
                (true, 0),
                (false, 1),
            );
        }
        let ordinary = runtime_case(cases, "runtime-typed-semigroup-text-ordered");
        assert_semigroup_completion_mutant(ordinary, true, false);
        assert_rehashed_process_status_substitution_rejected(
            ordinary,
            "semigroup-ordinary-status",
            (true, 0),
            (false, 1),
        );
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_semigroup_stdin_mutant(cases: &[crate::DifferentialCase]) {
        let case = runtime_case(cases, "runtime-typed-semigroup-builder-arbitrary-bytes");
        let (root, directory) = retain_executed_runtime_case(case, "semigroup-builder-stdin");
        fs::write(directory.join("stdin.bin"), [0xff, b'A', 0xfe, b'C']).unwrap();
        rehash_runtime_bundle(&directory, case);
        assert!(verify_observation_bundle_for_case(&directory, case).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_semigroup_argv_mutant(case: &crate::DifferentialCase) {
        let (root, directory) = retain_executed_runtime_case(case, &format!("{}-argv", case.id));
        let path = directory.join("execution-input.json");
        let document = fs::read_to_string(&path).unwrap();
        let changed = document.replacen("[\"--help\"]", "[\"--flag\",\"--help\"]", 1);
        assert_ne!(changed, document, "{} argv mutation did not match", case.id);
        fs::write(path, changed).unwrap();
        rehash_runtime_bundle(&directory, case);
        assert!(verify_observation_bundle_for_case(&directory, case).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_semigroup_completion_mutant(
        case: &crate::DifferentialCase,
        original: bool,
        replacement: bool,
    ) {
        let (root, directory) =
            retain_executed_runtime_case(case, &format!("{}-completion", case.id));
        let path = directory.join("case.toml");
        let document = fs::read_to_string(&path).unwrap();
        let changed = document.replacen(
            &format!("expected_runtime_completion = {original}"),
            &format!("expected_runtime_completion = {replacement}"),
            1,
        );
        assert_ne!(
            changed, document,
            "{} completion mutation did not match",
            case.id
        );
        fs::write(path, changed).unwrap();
        rewrite_bundle_file_digest(&directory, "case.toml");
        assert!(verify_observation_bundle_for_case(&directory, case).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_semigroup_demand_mutants(cases: &[crate::DifferentialCase]) {
        for case in cases
            .iter()
            .filter(|case| case.id.starts_with("runtime-typed-semigroup-"))
        {
            for class in ["lazy-adapter-entry", "lazy-adapter-exit"] {
                assert_lazy_state_substitution_rejected(cases, &case.id, "<>", class);
            }
        }
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn retained_async_pooled_matrix_executes_every_target_and_path() {
        let cases = crate::corpus::runtime_async_pooled_cases();
        let pooled = cases.iter().collect::<Vec<_>>();
        assert_eq!(pooled.len(), 12);
        for case in &pooled {
            let (root, _) = retain_executed_runtime_case(case, case.id.as_ref());
            fs::remove_dir_all(root).unwrap();
        }
        let failures = pooled
            .into_iter()
            .filter(|case| case.id.ends_with("-failure"))
            .collect::<Vec<_>>();
        assert_eq!(failures.len(), 4);
        for case in failures {
            for (suffix, replacement) in [
                ("missing-stderr", &b""[..]),
                ("wrong-stderr", &b"hell: forged pooled failure\n"[..]),
            ] {
                let (root, directory) =
                    retain_executed_runtime_case(case, &format!("{}-{suffix}", case.id));
                for role in ["candidate", "oracle"] {
                    fs::write(directory.join(role).join("stderr.raw.bin"), replacement).unwrap();
                }
                rehash_runtime_bundle(&directory, case);
                assert!(
                    verify_observation_bundle_for_case(&directory, case).is_err(),
                    "{} accepted {suffix}",
                    case.id
                );
                fs::remove_dir_all(root).unwrap();
            }
        }
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn retained_ord_list_matrix_executes_every_instance_and_reviewed_path() {
        let cases = crate::corpus::runtime_ord_list_boundary_cases();
        let selected = cases.iter().collect::<Vec<_>>();
        assert_eq!(selected.len(), 223);
        assert!(
            selected
                .iter()
                .any(|case| case.id.ends_with("-double-nan-finite"))
        );
        for case in selected {
            let (root, _) = retain_executed_runtime_case(case, case.id.as_ref());
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn retained_ord_set_matrix_executes_every_instance_and_reviewed_path() {
        let cases = crate::corpus::runtime_ord_set_cases();
        assert_eq!(cases.len(), 479);
        for case in &cases {
            let (root, _) = retain_executed_runtime_case(case, case.id.as_ref());
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn retained_ord_set_boundary_matrix_executes_every_instance_and_boundary() {
        let cases = crate::corpus::runtime_ord_set_boundary_cases();
        assert_eq!(cases.len(), 420);
        for case in &cases {
            let (root, _) = retain_executed_runtime_case(case, case.id.as_ref());
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn retained_ord_set_matrix_rejects_scope_transport_demand_and_boundary_mutants() {
        let cases = crate::corpus::runtime_ord_set_cases();
        assert_ord_set_instance_mutants(&cases);
        assert_ord_set_premise_and_target_mutants(&cases);
        assert_ord_set_transport_and_source_mutants(&cases);
        assert_ord_set_demand_and_boundary_mutants(&cases);
        assert_ord_set_comparator_protocol_mutants(&cases);
    }

    #[cfg(feature = "compat-tracing")]
    fn ord_set_targets() -> [(&'static str, &'static str); 7] {
        [
            ("fromlist", "Set.fromList"),
            ("insert", "Set.insert"),
            ("member", "Set.member"),
            ("delete", "Set.delete"),
            ("union", "Set.union"),
            ("difference", "Set.difference"),
            ("intersection", "Set.intersection"),
        ]
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_ord_set_instance_mutants(cases: &[crate::DifferentialCase]) {
        for (builtin_slug, _) in ord_set_targets() {
            for (instance, expected, substituted) in singleton_instance_substitutions() {
                assert_resolved_instance_substitution(
                    cases,
                    &format!("runtime-ord-set-{builtin_slug}-{instance}-singleton-input"),
                    expected,
                    substituted,
                );
            }
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn ord_set_event_mut<'a>(
        semantic: &'a mut crate::SemanticObservation,
        builtin: &str,
    ) -> &'a mut crate::ObligationTraceEvent {
        let builtin = hell_builtins::lookup(builtin)
            .expect("Ord/Set target remains registry-backed")
            .id;
        semantic
            .obligation_trace
            .iter_mut()
            .find(|event| event.builtin == builtin)
            .expect("Ord/Set obligation event")
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_ord_set_premise_and_target_mutants(cases: &[crate::DifferentialCase]) {
        for (builtin_slug, builtin) in ord_set_targets() {
            for instance in [
                "ci", "either", "maybe", "set", "tree", "tuple", "vector", "list",
            ] {
                let case_id = format!("runtime-ord-set-{builtin_slug}-{instance}-finite-input");
                let case = runtime_case(cases, &case_id);
                let source_root = root(&format!("{case_id}-premise"));
                let (success, mut semantic, stdout) =
                    execute_runtime_interaction_with_stdout(case, &source_root);
                ord_set_event_mut(&mut semantic, builtin)
                    .instance_premises
                    .pop();
                assert_rehashed_runtime_semantic_rejected(
                    case,
                    semantic,
                    &stdout,
                    success,
                    &format!("{case_id}-premise-omitted"),
                );
                fs::remove_dir_all(source_root).unwrap();
            }
            assert_ord_set_branching_premise_mutants(cases, builtin_slug, builtin);
        }
        assert_ord_set_target_mutants(cases);
        assert_ord_set_nested_comparator_mutants(cases);
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_ord_set_branching_premise_mutants(
        cases: &[crate::DifferentialCase],
        builtin_slug: &str,
        builtin: &str,
    ) {
        let case_id = format!("runtime-ord-set-{builtin_slug}-either-finite-input");
        let case = runtime_case(cases, &case_id);
        let source_root = root(&format!("{case_id}-premise-structure"));
        let (success, semantic, stdout) =
            execute_runtime_interaction_with_stdout(case, &source_root);
        for (name, mutate) in [
            (
                "extra",
                (|event: &mut crate::ObligationTraceEvent| {
                    event
                        .instance_premises
                        .push(crate::InstancePremiseEvidence {
                            target: Arc::from("Bool"),
                            premise_count: 0,
                        });
                }) as fn(&mut crate::ObligationTraceEvent),
            ),
            ("reordered", |event| event.instance_premises.swap(0, 1)),
            ("substituted", |event| {
                event.instance_premises[1].target = Arc::from("Bool");
            }),
            ("count", |event| {
                event.instance_premises[1].premise_count = 1;
            }),
        ] {
            let mut changed = semantic.clone();
            mutate(ord_set_event_mut(&mut changed, builtin));
            assert_rehashed_runtime_semantic_rejected(
                case,
                changed,
                &stdout,
                success,
                &format!("{case_id}-premise-{name}"),
            );
        }
        fs::remove_dir_all(source_root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_ord_set_target_mutants(cases: &[crate::DifferentialCase]) {
        let targets = ord_set_targets();
        for (index, (slug, builtin)) in targets.into_iter().enumerate() {
            let case_id = format!("runtime-ord-set-{slug}-int-empty-input");
            let case = runtime_case(cases, &case_id);
            let source_root = root(&format!("{case_id}-target"));
            let (success, mut semantic, stdout) =
                execute_runtime_interaction_with_stdout(case, &source_root);
            ord_set_event_mut(&mut semantic, builtin).builtin =
                hell_builtins::lookup(targets[(index + 1) % targets.len()].1)
                    .unwrap()
                    .id;
            assert_rehashed_runtime_semantic_rejected(
                case,
                semantic,
                &stdout,
                success,
                &format!("{case_id}-target"),
            );
            fs::remove_dir_all(source_root).unwrap();
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_ord_set_nested_comparator_mutants(cases: &[crate::DifferentialCase]) {
        let case = runtime_case(cases, "runtime-ord-set-insert-maybe-finite-input");
        let source_root = root("ord-set-nested-comparator");
        let (success, semantic, stdout) =
            execute_runtime_interaction_with_stdout(case, &source_root);
        let parent = hell_builtins::lookup("Set.insert").unwrap().id;
        let less = hell_builtins::lookup("Ord.lt").unwrap().id;
        let greater = hell_builtins::lookup("Ord.gt").unwrap().id;
        let parent_sequence = semantic
            .obligation_trace
            .iter()
            .find(|event| event.builtin == parent)
            .expect("Set.insert parent event")
            .sequence;
        let comparator_index = |builtin| {
            semantic
                .obligation_trace
                .iter()
                .position(|event| {
                    event.builtin == builtin && event.parent_sequence == Some(parent_sequence)
                })
                .expect("nested Ord comparator event")
        };
        let less_index = comparator_index(less);
        let greater_index = comparator_index(greater);
        for name in [
            "parent",
            "instance",
            "premise",
            "outcome",
            "owner",
            "order",
            "omitted",
            "duplicated",
        ] {
            let mut changed = semantic.clone();
            let trace = &mut changed.obligation_trace;
            match name {
                "parent" => trace[less_index].parent_sequence = None,
                "instance" => {
                    trace[less_index].instance_target = Some(Arc::from("Text"));
                }
                "premise" => {
                    trace[less_index].instance_premises.pop();
                }
                "outcome" => trace[less_index].outcome = Arc::from("error"),
                "owner" => trace[less_index].owner_task = Some(u64::MAX),
                "order" => {
                    let less_sequence = trace[less_index].sequence;
                    trace[less_index].sequence = trace[greater_index].sequence;
                    trace[greater_index].sequence = less_sequence;
                }
                "omitted" => {
                    trace.remove(less_index);
                }
                "duplicated" => trace.push(trace[less_index].clone()),
                _ => unreachable!("nested comparator mutant inventory is exact"),
            }
            assert_rehashed_runtime_semantic_rejected(
                case,
                changed,
                &stdout,
                success,
                &format!("ord-set-nested-comparator-{name}"),
            );
        }
        fs::remove_dir_all(source_root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_ord_set_comparator_protocol_mutants(cases: &[crate::DifferentialCase]) {
        let case = runtime_case(cases, "runtime-ord-set-fromlist-double-create-chunk-1");
        let source_root = root("ord-set-comparator-protocol");
        let (success, semantic, stdout) =
            execute_runtime_interaction_with_stdout(case, &source_root);
        for name in [
            "omit",
            "duplicate",
            "reorder",
            "relabel",
            "left",
            "right",
            "result",
            "outcome",
            "invocation",
            "child-ordinal",
            "malformed-result",
        ] {
            let mut changed = semantic.clone();
            let parent = changed
                .obligation_trace
                .iter_mut()
                .find(|event| event.builtin == hell_builtins::lookup("Set.fromList").unwrap().id)
                .expect("Set.fromList comparator parent");
            match name {
                "omit" => {
                    parent.comparators.remove(0);
                }
                "duplicate" => parent.comparators.push(parent.comparators[0].clone()),
                "reorder" => parent.comparators.swap(0, 1),
                "relabel" => {
                    let less = hell_builtins::lookup("Ord.lt").unwrap().id;
                    let greater = hell_builtins::lookup("Ord.gt").unwrap().id;
                    parent.comparators[0].comparator = if parent.comparators[0].comparator == less {
                        greater
                    } else {
                        less
                    };
                }
                "left" => {
                    parent.comparators[0].canonical_left =
                        Arc::from("{\"type\":\"Int\",\"value\":\"99\"}");
                }
                "right" => {
                    parent.comparators[0].canonical_right =
                        Arc::from("{\"type\":\"Int\",\"value\":\"99\"}");
                }
                "result" => {
                    parent.comparators[0].canonical_result = Arc::from(
                        if parent.comparators[0].canonical_result.ends_with("true}") {
                            "{\"type\":\"Bool\",\"value\":false}"
                        } else {
                            "{\"type\":\"Bool\",\"value\":true}"
                        },
                    );
                }
                "malformed-result" => {
                    parent.comparators[0].canonical_result =
                        Arc::from("{\"type\":\"Int\",\"value\":\"1\"}");
                }
                "outcome" => parent.comparators[0].outcome = Arc::from("error"),
                "invocation" => parent.comparators[0].invocation += 1,
                "child-ordinal" => parent.comparators[0].direct_child_ordinal += 1,
                _ => unreachable!("Set comparator mutant inventory is exact"),
            }
            assert_rehashed_runtime_semantic_rejected(
                case,
                changed,
                &stdout,
                success,
                &format!("ord-set-comparator-{name}"),
            );
        }
        assert_ord_set_coherent_child_record_mutant(case, &semantic, &stdout, success);
        assert_ord_set_comparator_digest_mutant(case);
        fs::remove_dir_all(source_root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_ord_set_coherent_child_record_mutant(
        case: &crate::DifferentialCase,
        semantic: &crate::SemanticObservation,
        stdout: &[u8],
        success: bool,
    ) {
        let mut changed = semantic.clone();
        let parent_index = changed
            .obligation_trace
            .iter()
            .position(|event| event.builtin == hell_builtins::lookup("Set.fromList").unwrap().id)
            .expect("Set.fromList comparator parent");
        let parent_sequence = changed.obligation_trace[parent_index].sequence;
        let child_sequence =
            changed.obligation_trace[parent_index].comparators[0].direct_child_ordinal;
        let child_index = changed
            .obligation_trace
            .iter()
            .enumerate()
            .filter(|(_, event)| event.parent_sequence == Some(parent_sequence))
            .filter(|(_, event)| {
                matches!(
                    hell_builtins::registry()[usize::from(event.builtin.0)].name,
                    "Ord.lt" | "Ord.gt"
                )
            })
            .nth(usize::try_from(child_sequence - 1).unwrap())
            .map(|(index, _)| index)
            .expect("recorded comparator child exists");
        let less = hell_builtins::lookup("Ord.lt").unwrap().id;
        let greater = hell_builtins::lookup("Ord.gt").unwrap().id;
        let original = changed.obligation_trace[parent_index].comparators[0].comparator;
        let replacement = if original == less { greater } else { less };
        assert_ne!(original, replacement);
        changed.obligation_trace[parent_index].comparators[0].comparator = replacement;
        changed.obligation_trace[child_index].builtin = replacement;
        assert_rehashed_runtime_semantic_rejected(
            case,
            changed,
            stdout,
            success,
            "ord-set-comparator-coherent-child-record",
        );
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_ord_set_comparator_digest_mutant(case: &crate::DifferentialCase) {
        let mut changed = case.clone();
        changed.claim_evidence.as_mut().unwrap().semantic_targets[0]
            .expected_comparator_trace_sha256 = Some(crate::sha256_bytes(b"substituted"));
        let (root, directory) =
            retain_executed_runtime_case_unverified(&changed, "ord-set-comparator-digest");
        assert!(verify_observation_bundle_for_case(&directory, &changed).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_ord_set_transport_and_source_mutants(cases: &[crate::DifferentialCase]) {
        for (slug, _) in ord_set_targets() {
            let case_id = format!("runtime-ord-set-{slug}-int-finite-input");
            let case = runtime_case(cases, &case_id);
            assert_ord_set_typed_mutant(case);
            assert_runtime_raw_substitution(case, &format!("{case_id}-raw"));
            assert_rehashed_process_status_substitution_rejected(
                case,
                &format!("{case_id}-status"),
                (true, 0),
                (false, 1),
            );
            assert_ord_set_source_mutant(case);
        }
        let identity_case = runtime_case(
            cases,
            "runtime-ord-set-difference-double-disjoint-size-preserved-member-outcome",
        );
        assert_runtime_raw_substitution(identity_case, "ord-set-difference-identity-raw");
        assert_rehashed_process_status_substitution_rejected(
            identity_case,
            "ord-set-difference-identity-status",
            (true, 0),
            (false, 1),
        );
        assert_ord_set_multiplicity_and_order_mutants(cases);
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_ord_set_typed_mutant(case: &crate::DifferentialCase) {
        let source_root = root(&format!("{}-typed", case.id));
        let (success, mut semantic, stdout) =
            execute_runtime_interaction_with_stdout(case, &source_root);
        let canonical = semantic
            .typed_result_canonical
            .as_ref()
            .expect("Ord/Set typed result")
            .to_string();
        let changed = if canonical.contains("\"type\":\"Bool\",\"value\":true") {
            canonical.replacen(
                "\"type\":\"Bool\",\"value\":true",
                "\"type\":\"Bool\",\"value\":false",
                1,
            )
        } else if canonical.contains("\"value\":\"1\"") {
            canonical.replacen("\"value\":\"1\"", "\"value\":\"2\"", 1)
        } else {
            canonical.replacen("\"value\":\"3\"", "\"value\":\"2\"", 1)
        };
        assert_ne!(changed, canonical, "{} typed mutation matched", case.id);
        let changed: Arc<str> = Arc::from(changed);
        semantic.typed_result_sha256 = Some(sha256_bytes(changed.as_bytes()));
        semantic.typed_result_canonical = Some(changed);
        assert_rehashed_runtime_semantic_rejected(
            case,
            semantic,
            &stdout,
            success,
            &format!("{}-typed", case.id),
        );
        fs::remove_dir_all(source_root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_ord_set_multiplicity_and_order_mutants(cases: &[crate::DifferentialCase]) {
        let case = runtime_case(cases, "runtime-ord-set-union-int-finite-input");
        let source_root = root("ord-set-typed-structure");
        let (success, semantic, stdout) =
            execute_runtime_interaction_with_stdout(case, &source_root);
        let original = concat!(
            "{\"type\":\"Set\",\"elements\":[",
            "{\"type\":\"Int\",\"value\":\"1\"},",
            "{\"type\":\"Int\",\"value\":\"3\"}]}"
        );
        for (name, replacement) in [
            (
                "duplicate",
                concat!(
                    "{\"type\":\"Set\",\"elements\":[",
                    "{\"type\":\"Int\",\"value\":\"1\"},",
                    "{\"type\":\"Int\",\"value\":\"1\"},",
                    "{\"type\":\"Int\",\"value\":\"3\"}]}"
                ),
            ),
            (
                "omitted",
                "{\"type\":\"Set\",\"elements\":[{\"type\":\"Int\",\"value\":\"1\"}]}",
            ),
            (
                "reordered",
                concat!(
                    "{\"type\":\"Set\",\"elements\":[",
                    "{\"type\":\"Int\",\"value\":\"3\"},",
                    "{\"type\":\"Int\",\"value\":\"1\"}]}"
                ),
            ),
        ] {
            let mut changed = semantic.clone();
            let canonical = changed
                .typed_result_canonical
                .as_ref()
                .expect("Ord/Set typed result")
                .replace(original, replacement);
            assert_ne!(
                canonical,
                changed.typed_result_canonical.as_deref().unwrap(),
                "Ord/Set {name} mutation matched"
            );
            let canonical: Arc<str> = Arc::from(canonical);
            changed.typed_result_sha256 = Some(sha256_bytes(canonical.as_bytes()));
            changed.typed_result_canonical = Some(canonical);
            assert_rehashed_runtime_semantic_rejected(
                case,
                changed,
                &stdout,
                success,
                &format!("ord-set-typed-{name}"),
            );
        }
        fs::remove_dir_all(source_root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_ord_set_source_mutant(case: &crate::DifferentialCase) {
        let (root, directory) = retain_executed_runtime_case(case, &format!("{}-source", case.id));
        let source = directory.join("main.hell");
        let mut document = fs::read_to_string(&source).unwrap();
        document.push('\n');
        fs::write(source, document).unwrap();
        rehash_runtime_bundle(&directory, case);
        assert!(verify_observation_bundle_for_case(&directory, case).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_ord_set_demand_and_boundary_mutants(cases: &[crate::DifferentialCase]) {
        for (slug, builtin, arguments) in [
            (
                "fromlist",
                "Set.fromList",
                &[(0, "whnf-force-complete")][..],
            ),
            (
                "insert",
                "Set.insert",
                &[(0, "lazy-adapter-entry"), (1, "whnf-force-complete")][..],
            ),
            (
                "member",
                "Set.member",
                &[(0, "lazy-adapter-entry"), (1, "whnf-force-complete")][..],
            ),
            (
                "delete",
                "Set.delete",
                &[(0, "lazy-adapter-entry"), (1, "whnf-force-complete")][..],
            ),
            (
                "union",
                "Set.union",
                &[(0, "whnf-force-complete"), (1, "whnf-force-complete")][..],
            ),
            (
                "difference",
                "Set.difference",
                &[(0, "whnf-force-complete"), (1, "whnf-force-complete")][..],
            ),
            (
                "intersection",
                "Set.intersection",
                &[(0, "whnf-force-complete"), (1, "whnf-force-complete")][..],
            ),
        ] {
            let case_id = format!("runtime-ord-set-{slug}-int-finite-input");
            for (argument, class) in arguments {
                assert_demand_argument_state_substitution_rejected(
                    cases, &case_id, builtin, *argument, class,
                );
            }
            assert_ord_set_boundary_mutant(runtime_case(cases, &case_id));
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_ord_set_boundary_mutant(case: &crate::DifferentialCase) {
        let (root, directory) =
            retain_executed_runtime_case(case, &format!("{}-boundary", case.id));
        let path = directory.join("case.toml");
        let document = fs::read_to_string(&path).unwrap();
        let changed = document.replacen("\"finite-input\"", "\"singleton-input\"", 1);
        assert_ne!(changed, document);
        fs::write(&path, changed).unwrap();
        rewrite_bundle_file_digest(&directory, "case.toml");
        assert!(verify_observation_bundle_for_case(&directory, case).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn retained_ord_map_matrix_executes_every_instance_and_reviewed_path() {
        let cases = crate::corpus::runtime_ord_map_cases();
        assert_eq!(cases.len(), 712);
        for case in &cases {
            let (root, _) = retain_executed_runtime_case(case, case.id.as_ref());
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn retained_ord_map_matrix_rejects_scope_callback_transport_and_boundary_mutants() {
        let cases = crate::corpus::runtime_ord_map_cases();
        assert_ord_map_instance_mutants(&cases);
        assert_ord_map_premise_target_and_nested_ord_mutants(&cases);
        assert_ord_map_callback_mutants(&cases);
        assert_ord_map_transport_and_structure_mutants(&cases);
        assert_ord_map_demand_and_boundary_mutants(&cases);
    }

    #[cfg(feature = "compat-tracing")]
    fn ord_map_targets() -> [(&'static str, &'static str); 7] {
        [
            ("fromlist", "Map.fromList"),
            ("lookup", "Map.lookup"),
            ("insert", "Map.insert"),
            ("delete", "Map.delete"),
            ("insertwith", "Map.insertWith"),
            ("adjust", "Map.adjust"),
            ("unionwith", "Map.unionWith"),
        ]
    }

    #[cfg(feature = "compat-tracing")]
    type OrdMapDemandTarget = (&'static str, &'static str, &'static [(u16, &'static str)]);

    #[cfg(feature = "compat-tracing")]
    fn assert_ord_map_instance_mutants(cases: &[crate::DifferentialCase]) {
        for (builtin_slug, _) in ord_map_targets() {
            for (instance, expected, substituted) in singleton_instance_substitutions() {
                assert_resolved_instance_substitution(
                    cases,
                    &format!("runtime-ord-map-{builtin_slug}-{instance}-singleton-input"),
                    expected,
                    substituted,
                );
            }
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn ord_map_event_mut<'a>(
        semantic: &'a mut crate::SemanticObservation,
        builtin: &str,
    ) -> &'a mut crate::ObligationTraceEvent {
        let builtin = hell_builtins::lookup(builtin)
            .expect("Ord/Map target remains registry-backed")
            .id;
        semantic
            .obligation_trace
            .iter_mut()
            .find(|event| event.builtin == builtin)
            .expect("Ord/Map obligation event")
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_ord_map_premise_target_and_nested_ord_mutants(cases: &[crate::DifferentialCase]) {
        for (builtin_slug, builtin) in ord_map_targets() {
            for instance in [
                "ci", "either", "maybe", "set", "tree", "tuple", "vector", "list",
            ] {
                let case_id = format!("runtime-ord-map-{builtin_slug}-{instance}-finite-input");
                let case = runtime_case(cases, &case_id);
                let source_root = root(&format!("{case_id}-premise"));
                let (success, mut semantic, stdout) =
                    execute_runtime_interaction_with_stdout(case, &source_root);
                ord_map_event_mut(&mut semantic, builtin)
                    .instance_premises
                    .pop();
                assert_rehashed_runtime_semantic_rejected(
                    case,
                    semantic,
                    &stdout,
                    success,
                    &format!("{case_id}-premise-omitted"),
                );
                fs::remove_dir_all(source_root).unwrap();
            }
            assert_ord_map_branching_premise_mutants(cases, builtin_slug, builtin);
        }
        assert_ord_map_target_mutants(cases);
        assert_ord_map_nested_comparator_mutants(cases);
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_ord_map_branching_premise_mutants(
        cases: &[crate::DifferentialCase],
        builtin_slug: &str,
        builtin: &str,
    ) {
        let case_id = format!("runtime-ord-map-{builtin_slug}-either-finite-input");
        let case = runtime_case(cases, &case_id);
        let source_root = root(&format!("{case_id}-premise-structure"));
        let (success, semantic, stdout) =
            execute_runtime_interaction_with_stdout(case, &source_root);
        for (name, mutate) in [
            (
                "extra",
                (|event: &mut crate::ObligationTraceEvent| {
                    event
                        .instance_premises
                        .push(crate::InstancePremiseEvidence {
                            target: Arc::from("Bool"),
                            premise_count: 0,
                        });
                }) as fn(&mut crate::ObligationTraceEvent),
            ),
            ("reordered", |event| event.instance_premises.swap(0, 1)),
            ("substituted", |event| {
                event.instance_premises[1].target = Arc::from("Bool");
            }),
            ("count", |event| {
                event.instance_premises[1].premise_count = 1;
            }),
        ] {
            let mut changed = semantic.clone();
            mutate(ord_map_event_mut(&mut changed, builtin));
            assert_rehashed_runtime_semantic_rejected(
                case,
                changed,
                &stdout,
                success,
                &format!("{case_id}-premise-{name}"),
            );
        }
        fs::remove_dir_all(source_root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_ord_map_target_mutants(cases: &[crate::DifferentialCase]) {
        let targets = ord_map_targets();
        for (index, (slug, builtin)) in targets.into_iter().enumerate() {
            let case_id = format!("runtime-ord-map-{slug}-int-empty-input");
            let case = runtime_case(cases, &case_id);
            let source_root = root(&format!("{case_id}-target"));
            let (success, mut semantic, stdout) =
                execute_runtime_interaction_with_stdout(case, &source_root);
            ord_map_event_mut(&mut semantic, builtin).builtin =
                hell_builtins::lookup(targets[(index + 1) % targets.len()].1)
                    .unwrap()
                    .id;
            assert_rehashed_runtime_semantic_rejected(
                case,
                semantic,
                &stdout,
                success,
                &format!("{case_id}-target"),
            );
            fs::remove_dir_all(source_root).unwrap();
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_ord_map_nested_comparator_mutants(cases: &[crate::DifferentialCase]) {
        let case = runtime_case(cases, "runtime-ord-map-fromlist-int-finite-input");
        let source_root = root("ord-map-nested-comparator");
        let (success, semantic, stdout) =
            execute_runtime_interaction_with_stdout(case, &source_root);
        let map = hell_builtins::lookup("Map.fromList").unwrap().id;
        let less = hell_builtins::lookup("Ord.lt").unwrap().id;
        let greater = hell_builtins::lookup("Ord.gt").unwrap().id;
        let parent = semantic
            .obligation_trace
            .iter()
            .find(|event| event.builtin == map)
            .expect("Map.fromList target event");
        let child_index = semantic
            .obligation_trace
            .iter()
            .position(|event| {
                matches!(event.builtin, id if id == less || id == greater)
                    && event.owner_task == parent.owner_task
                    && event.parent_sequence == Some(parent.sequence)
            })
            .expect("Map.fromList delegates to an Ord comparator");
        for (name, mutate) in [
            (
                "reparented",
                (|event: &mut crate::ObligationTraceEvent| event.parent_sequence = None)
                    as fn(&mut crate::ObligationTraceEvent),
            ),
            ("instance", |event| {
                event.instance_target = Some(Arc::from("Text"));
            }),
            ("outcome", |event| event.outcome = Arc::from("error")),
        ] {
            let mut changed = semantic.clone();
            mutate(&mut changed.obligation_trace[child_index]);
            assert_rehashed_runtime_semantic_rejected(
                case,
                changed,
                &stdout,
                success,
                &format!("ord-map-nested-{name}"),
            );
        }
        assert_ord_map_comparator_record_mutants(
            case,
            &semantic,
            &stdout,
            success,
            child_index,
            less,
        );
        let mut omitted = semantic;
        omitted.obligation_trace.remove(child_index);
        assert_rehashed_runtime_semantic_rejected(
            case,
            omitted,
            &stdout,
            success,
            "ord-map-nested-omitted",
        );
        fs::remove_dir_all(source_root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_ord_map_comparator_record_mutants(
        case: &crate::DifferentialCase,
        semantic: &crate::SemanticObservation,
        stdout: &[u8],
        success: bool,
        child_index: usize,
        less: hell_builtins::BuiltinId,
    ) {
        for name in [
            "record-ordinal",
            "record-invocation",
            "record-builtin",
            "record-left",
            "record-right",
            "record-result",
            "record-outcome",
            "record-omitted",
            "record-duplicated",
            "record-reordered",
            "coherent-builtin-relabel",
        ] {
            let mut changed = semantic.clone();
            let event = ord_map_event_mut(&mut changed, "Map.fromList");
            match name {
                "record-ordinal" => event.comparators[0].direct_child_ordinal = 2,
                "record-invocation" => event.comparators[0].invocation = 2,
                "record-builtin" => event.comparators[0].comparator = less,
                "record-left" => {
                    event.comparators[0].canonical_left =
                        Arc::from("{\"type\":\"Int\",\"value\":\"99\"}");
                }
                "record-right" => {
                    event.comparators[0].canonical_right =
                        Arc::from("{\"type\":\"Int\",\"value\":\"99\"}");
                }
                "record-result" => {
                    event.comparators[0].canonical_result =
                        Arc::from("{\"type\":\"Bool\",\"value\":false}");
                }
                "record-outcome" => event.comparators[0].outcome = Arc::from("error"),
                "record-omitted" => {
                    event.comparators.remove(0);
                }
                "record-duplicated" => {
                    event.comparators.push(event.comparators[0].clone());
                }
                "record-reordered" => event.comparators.swap(0, 1),
                "coherent-builtin-relabel" => {
                    event.comparators[0].comparator = less;
                    changed.obligation_trace[child_index].builtin = less;
                }
                _ => unreachable!("Ord/Map comparator record mutant inventory is exact"),
            }
            assert_rehashed_runtime_semantic_rejected(
                case,
                changed,
                stdout,
                success,
                &format!("ord-map-nested-{name}"),
            );
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_ord_map_callback_mutants(cases: &[crate::DifferentialCase]) {
        for (slug, builtin) in [
            ("insertwith", "Map.insertWith"),
            ("adjust", "Map.adjust"),
            ("unionwith", "Map.unionWith"),
        ] {
            let one_id = format!("runtime-ord-map-{slug}-int-singleton-input");
            assert_ord_map_one_callback_mutants(runtime_case(cases, &one_id), builtin);
        }
        assert_multi_call_callback_contract(
            runtime_case(cases, "runtime-ord-map-unionwith-int-multi-collision"),
            "Map.unionWith",
            "ord-map-union-multi",
            &root("ord-map-union-multi-source"),
        );
        assert_ord_map_zero_callback_injections(cases);
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_ord_map_one_callback_mutants(case: &crate::DifferentialCase, builtin: &str) {
        let source_root = root(&format!("{}-callback", case.id));
        let (success, semantic, stdout) =
            execute_runtime_interaction_with_stdout(case, &source_root);
        assert_eq!(callback_events_mut(&mut semantic.clone(), builtin).len(), 1);
        for (name, mutate) in [
            (
                "omitted",
                (|events: &mut Vec<crate::CallbackTraceEvent>| events.clear())
                    as fn(&mut Vec<crate::CallbackTraceEvent>),
            ),
            ("duplicated", |events| events.push(events[0].clone())),
            ("argument", |events| {
                events[0].canonical_arguments[0] =
                    Arc::from("{\"type\":\"Text\",\"utf8Hex\":\"78\"}");
            }),
            ("result", |events| {
                events[0].canonical_result = Arc::from("{\"type\":\"Text\",\"utf8Hex\":\"78\"}");
            }),
        ] {
            let mut changed = semantic.clone();
            mutate(callback_events_mut(&mut changed, builtin));
            assert_rehashed_runtime_semantic_rejected(
                case,
                changed,
                &stdout,
                success,
                &format!("{}-callback-{name}", case.id),
            );
        }
        fs::remove_dir_all(source_root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_ord_map_zero_callback_injections(cases: &[crate::DifferentialCase]) {
        for (slug, builtin, source_id, zero_paths) in [
            (
                "insertwith",
                "Map.insertWith",
                "runtime-ord-map-insertwith-int-singleton-input",
                &[
                    "runtime-ord-map-insertwith-int-empty-input",
                    "runtime-ord-map-insertwith-int-nonempty-absent",
                    "runtime-ord-map-insertwith-int-nonempty-absent-left",
                    "runtime-ord-map-insertwith-int-callback-result-nonforce",
                ][..],
            ),
            (
                "adjust",
                "Map.adjust",
                "runtime-ord-map-adjust-int-singleton-input",
                &[
                    "runtime-ord-map-adjust-int-empty-input",
                    "runtime-ord-map-adjust-int-nonempty-miss",
                    "runtime-ord-map-adjust-int-nonempty-miss-left",
                    "runtime-ord-map-adjust-int-callback-result-nonforce",
                ][..],
            ),
            (
                "unionwith",
                "Map.unionWith",
                "runtime-ord-map-unionwith-int-singleton-input",
                &[
                    "runtime-ord-map-unionwith-int-empty-input",
                    "runtime-ord-map-unionwith-int-nonempty-disjoint",
                    "runtime-ord-map-unionwith-int-multi-disjoint",
                    "runtime-ord-map-unionwith-int-callback-result-nonforce",
                ][..],
            ),
        ] {
            let source_case = runtime_case(cases, source_id);
            let source_root = root(&format!("ord-map-{slug}-callback-source"));
            let (_, mut source) = execute_runtime_interaction(source_case, &source_root);
            let injected = callback_events_mut(&mut source, builtin)[0].clone();
            fs::remove_dir_all(source_root).unwrap();
            for case_id in zero_paths {
                let case = runtime_case(cases, case_id);
                let target_root = root(&format!("{case_id}-callback-injected"));
                let (success, mut semantic, stdout) =
                    execute_runtime_interaction_with_stdout(case, &target_root);
                assert!(callback_events_mut(&mut semantic, builtin).is_empty());
                callback_events_mut(&mut semantic, builtin).push(injected.clone());
                assert_rehashed_runtime_semantic_rejected(
                    case,
                    semantic,
                    &stdout,
                    success,
                    &format!("{case_id}-callback-injected"),
                );
                fs::remove_dir_all(target_root).unwrap();
            }
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_ord_map_transport_and_structure_mutants(cases: &[crate::DifferentialCase]) {
        for (slug, _) in ord_map_targets() {
            let case_id = format!("runtime-ord-map-{slug}-int-finite-input");
            let case = runtime_case(cases, &case_id);
            assert_ord_map_typed_mutant(case);
            assert_runtime_raw_substitution(case, &format!("{case_id}-raw"));
            assert_rehashed_process_status_substitution_rejected(
                case,
                &format!("{case_id}-status"),
                (true, 0),
                (false, 1),
            );
            assert_ord_set_source_mutant(case);
        }
        assert_ord_map_entry_sequence_mutants(cases);
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_ord_map_typed_mutant(case: &crate::DifferentialCase) {
        let source_root = root(&format!("{}-typed", case.id));
        let (success, mut semantic, stdout) =
            execute_runtime_interaction_with_stdout(case, &source_root);
        let canonical = semantic
            .typed_result_canonical
            .as_ref()
            .expect("Ord/Map typed result")
            .to_string();
        let marker = "\"utf8Hex\":\"";
        let start = canonical
            .find(marker)
            .map(|index| index + marker.len())
            .expect("Ord/Map finite result carries a Text value");
        let end = canonical[start..]
            .find('"')
            .map(|index| start + index)
            .expect("Ord/Map Text value terminates");
        let mut changed = canonical.clone();
        changed.replace_range(start..end, "78");
        assert_ne!(changed, canonical, "{} typed mutation matched", case.id);
        let changed: Arc<str> = Arc::from(changed);
        semantic.typed_result_sha256 = Some(sha256_bytes(changed.as_bytes()));
        semantic.typed_result_canonical = Some(changed);
        assert_rehashed_runtime_semantic_rejected(
            case,
            semantic,
            &stdout,
            success,
            &format!("{}-typed", case.id),
        );
        fs::remove_dir_all(source_root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_ord_map_entry_sequence_mutants(cases: &[crate::DifferentialCase]) {
        let case = runtime_case(cases, "runtime-ord-map-fromlist-double-create-chunk-1");
        let source_root = root("ord-map-entry-sequence");
        let (success, semantic, stdout) =
            execute_runtime_interaction_with_stdout(case, &source_root);
        let nan = concat!(
            "{\"key\":{\"type\":\"Double\",\"ieee754Bits\":\"7ff8000000000000\"},",
            "\"value\":{\"type\":\"Text\",\"utf8Hex\":\"6e61\"}}"
        );
        let zero = concat!(
            "{\"key\":{\"type\":\"Double\",\"ieee754Bits\":\"0000000000000000\"},",
            "\"value\":{\"type\":\"Text\",\"utf8Hex\":\"30\"}}"
        );
        for (name, original, replacement) in [
            ("duplicate", nan.to_owned(), format!("{nan},{nan}")),
            ("omitted", format!("{nan},{zero}"), zero.to_owned()),
            (
                "reordered",
                format!("{nan},{zero}"),
                format!("{zero},{nan}"),
            ),
            (
                "key",
                "\"ieee754Bits\":\"7ff8000000000000\"".to_owned(),
                "\"ieee754Bits\":\"7ff0000000000000\"".to_owned(),
            ),
            (
                "value",
                "\"utf8Hex\":\"6e61\"".to_owned(),
                "\"utf8Hex\":\"7878\"".to_owned(),
            ),
        ] {
            let mut changed = semantic.clone();
            let canonical = changed
                .typed_result_canonical
                .as_ref()
                .expect("Ord/Map typed result")
                .replacen(&original, &replacement, 1);
            assert_ne!(
                canonical,
                changed.typed_result_canonical.as_deref().unwrap(),
                "Ord/Map {name} mutation matched"
            );
            let canonical: Arc<str> = Arc::from(canonical);
            changed.typed_result_sha256 = Some(sha256_bytes(canonical.as_bytes()));
            changed.typed_result_canonical = Some(canonical);
            assert_rehashed_runtime_semantic_rejected(
                case,
                changed,
                &stdout,
                success,
                &format!("ord-map-entry-{name}"),
            );
        }
        fs::remove_dir_all(source_root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_ord_map_demand_and_boundary_mutants(cases: &[crate::DifferentialCase]) {
        for (slug, builtin, arguments) in ord_map_demand_targets() {
            let case_id = format!("runtime-ord-map-{slug}-int-finite-input");
            for (argument, class) in arguments {
                assert_demand_argument_state_substitution_rejected(
                    cases, &case_id, builtin, *argument, class,
                );
            }
            assert_ord_set_boundary_mutant(runtime_case(cases, &case_id));
        }
        for (case_id, builtin, arguments) in [
            (
                "runtime-ord-map-insert-int-values-nonforce",
                "Map.insert",
                &[0, 1][..],
            ),
            (
                "runtime-ord-map-insertwith-int-callback-result-nonforce",
                "Map.insertWith",
                &[0, 1, 2][..],
            ),
            (
                "runtime-ord-map-adjust-int-callback-result-nonforce",
                "Map.adjust",
                &[0, 1][..],
            ),
            (
                "runtime-ord-map-unionwith-int-callback-result-nonforce",
                "Map.unionWith",
                &[0][..],
            ),
        ] {
            for argument in arguments {
                assert_demand_argument_state_substitution_rejected(
                    cases,
                    case_id,
                    builtin,
                    *argument,
                    "lazy-adapter-exit",
                );
            }
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn ord_map_demand_targets() -> [OrdMapDemandTarget; 7] {
        [
            ("fromlist", "Map.fromList", &[(0, "whnf-force-complete")]),
            (
                "lookup",
                "Map.lookup",
                &[(0, "lazy-adapter-entry"), (1, "whnf-force-complete")],
            ),
            (
                "insert",
                "Map.insert",
                &[
                    (0, "lazy-adapter-entry"),
                    (1, "lazy-adapter-entry"),
                    (2, "whnf-force-complete"),
                ],
            ),
            (
                "delete",
                "Map.delete",
                &[(0, "lazy-adapter-entry"), (1, "whnf-force-complete")],
            ),
            (
                "insertwith",
                "Map.insertWith",
                &[
                    (0, "lazy-adapter-entry"),
                    (1, "lazy-adapter-entry"),
                    (2, "lazy-adapter-entry"),
                    (3, "whnf-force-complete"),
                ],
            ),
            (
                "adjust",
                "Map.adjust",
                &[
                    (0, "lazy-adapter-entry"),
                    (1, "lazy-adapter-entry"),
                    (2, "whnf-force-complete"),
                ],
            ),
            (
                "unionwith",
                "Map.unionWith",
                &[
                    (0, "lazy-adapter-entry"),
                    (1, "whnf-force-complete"),
                    (2, "whnf-force-complete"),
                ],
            ),
        ]
    }

    #[cfg(feature = "compat-tracing")]
    #[test]
    fn retained_ord_list_matrix_rejects_scope_callback_transport_and_boundary_mutants() {
        let cases = crate::corpus::runtime_ord_list_boundary_cases();
        assert_ord_list_instance_mutants(&cases);
        assert_ord_list_premise_and_target_mutants(&cases);
        assert_ord_list_callback_mutants(&cases);
        assert_ord_list_transport_and_input_mutants(&cases);
        assert_ord_list_demand_and_boundary_mutants(&cases);
    }

    #[cfg(feature = "compat-tracing")]
    fn ord_list_targets() -> [(&'static str, &'static str); 3] {
        [
            ("list-sort", "List.sort"),
            ("list-nubord", "List.nubOrd"),
            ("list-sorton", "List.sortOn"),
        ]
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_ord_list_instance_mutants(cases: &[crate::DifferentialCase]) {
        for (builtin_slug, _) in ord_list_targets() {
            for (instance, expected, substituted) in singleton_instance_substitutions() {
                assert_resolved_instance_substitution(
                    cases,
                    &format!("runtime-ord-list-{builtin_slug}-{instance}-singleton-input"),
                    expected,
                    substituted,
                );
            }
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn ord_list_event_mut<'a>(
        semantic: &'a mut crate::SemanticObservation,
        builtin: &str,
    ) -> &'a mut crate::ObligationTraceEvent {
        let builtin = hell_builtins::lookup(builtin)
            .expect("Ord/List target remains registry-backed")
            .id;
        semantic
            .obligation_trace
            .iter_mut()
            .find(|event| event.builtin == builtin)
            .expect("Ord/List obligation event")
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_ord_list_premise_and_target_mutants(cases: &[crate::DifferentialCase]) {
        for (builtin_slug, builtin) in ord_list_targets() {
            for instance in [
                "ci", "either", "maybe", "set", "tree", "tuple", "vector", "list",
            ] {
                let case_id = format!("runtime-ord-list-{builtin_slug}-{instance}-finite-input");
                let case = runtime_case(cases, &case_id);
                let source_root = root(&format!("{case_id}-premise"));
                let (success, mut semantic, stdout) =
                    execute_runtime_interaction_with_stdout(case, &source_root);
                ord_list_event_mut(&mut semantic, builtin)
                    .instance_premises
                    .pop();
                assert_rehashed_runtime_semantic_rejected(
                    case,
                    semantic,
                    &stdout,
                    success,
                    &format!("{case_id}-premise-omitted"),
                );
                fs::remove_dir_all(source_root).unwrap();
            }
            assert_ord_list_branching_premise_mutants(cases, builtin_slug, builtin);
        }
        assert_ord_list_target_mutants(cases);
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_ord_list_branching_premise_mutants(
        cases: &[crate::DifferentialCase],
        builtin_slug: &str,
        builtin: &str,
    ) {
        let case_id = format!("runtime-ord-list-{builtin_slug}-either-finite-input");
        let case = runtime_case(cases, &case_id);
        let source_root = root(&format!("{case_id}-premise-structure"));
        let (success, semantic, stdout) =
            execute_runtime_interaction_with_stdout(case, &source_root);
        for (name, mutate) in [
            (
                "extra",
                (|event: &mut crate::ObligationTraceEvent| {
                    event
                        .instance_premises
                        .push(crate::InstancePremiseEvidence {
                            target: Arc::from("Bool"),
                            premise_count: 0,
                        });
                }) as fn(&mut crate::ObligationTraceEvent),
            ),
            ("reordered", |event| event.instance_premises.swap(0, 1)),
            ("substituted", |event| {
                event.instance_premises[1].target = Arc::from("Bool");
            }),
            ("count", |event| {
                event.instance_premises[1].premise_count = 1;
            }),
        ] {
            let mut changed = semantic.clone();
            mutate(ord_list_event_mut(&mut changed, builtin));
            assert_rehashed_runtime_semantic_rejected(
                case,
                changed,
                &stdout,
                success,
                &format!("{case_id}-premise-{name}"),
            );
        }
        fs::remove_dir_all(source_root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_ord_list_target_mutants(cases: &[crate::DifferentialCase]) {
        let targets = ord_list_targets();
        for (index, (slug, builtin)) in targets.into_iter().enumerate() {
            let case_id = format!("runtime-ord-list-{slug}-int-empty-input");
            let case = runtime_case(cases, &case_id);
            let source_root = root(&format!("{case_id}-target"));
            let (success, mut semantic, stdout) =
                execute_runtime_interaction_with_stdout(case, &source_root);
            ord_list_event_mut(&mut semantic, builtin).builtin =
                hell_builtins::lookup(targets[(index + 1) % targets.len()].1)
                    .unwrap()
                    .id;
            assert_rehashed_runtime_semantic_rejected(
                case,
                semantic,
                &stdout,
                success,
                &format!("{case_id}-target"),
            );
            fs::remove_dir_all(source_root).unwrap();
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_ord_list_callback_mutants(cases: &[crate::DifferentialCase]) {
        let finite = runtime_case(cases, "runtime-ord-list-list-sorton-int-finite-input");
        let source_root = root("ord-list-callback-finite");
        let (success, semantic, stdout) =
            execute_runtime_interaction_with_stdout(finite, &source_root);
        let callbacks = callback_events_mut(&mut semantic.clone(), "List.sortOn").len();
        assert_eq!(callbacks, 3);
        for (name, mutate) in [
            (
                "omitted",
                (|events: &mut Vec<crate::CallbackTraceEvent>| {
                    events.remove(0);
                }) as fn(&mut Vec<crate::CallbackTraceEvent>),
            ),
            ("duplicated", |events| events.push(events[0].clone())),
            ("reordered", |events| events.swap(0, 1)),
            ("argument", |events| {
                events[0].canonical_arguments[0] = events[1].canonical_arguments[0].clone();
            }),
            ("result", |events| {
                events[0].canonical_result = events[1].canonical_result.clone();
            }),
        ] {
            let mut changed = semantic.clone();
            mutate(callback_events_mut(&mut changed, "List.sortOn"));
            assert_rehashed_runtime_semantic_rejected(
                finite,
                changed,
                &stdout,
                success,
                &format!("ord-list-callback-{name}"),
            );
        }
        for path in ["empty-input", "singleton-input"] {
            assert_ord_list_zero_callback_injection(cases, path, &semantic);
        }
        fs::remove_dir_all(source_root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_ord_list_zero_callback_injection(
        cases: &[crate::DifferentialCase],
        path: &str,
        callback_source: &crate::SemanticObservation,
    ) {
        let case_id = format!("runtime-ord-list-list-sorton-int-{path}");
        let case = runtime_case(cases, &case_id);
        let source_root = root(&format!("{case_id}-callback-injected"));
        let (success, mut semantic, stdout) =
            execute_runtime_interaction_with_stdout(case, &source_root);
        assert!(callback_events_mut(&mut semantic, "List.sortOn").is_empty());
        let injected = callback_events_mut(&mut callback_source.clone(), "List.sortOn")[0].clone();
        callback_events_mut(&mut semantic, "List.sortOn").push(injected);
        assert_rehashed_runtime_semantic_rejected(
            case,
            semantic,
            &stdout,
            success,
            &format!("{case_id}-callback-injected"),
        );
        fs::remove_dir_all(source_root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_ord_list_transport_and_input_mutants(cases: &[crate::DifferentialCase]) {
        for (slug, _) in ord_list_targets() {
            let case_id = format!("runtime-ord-list-{slug}-int-finite-input");
            let case = runtime_case(cases, &case_id);
            assert_ord_list_typed_mutant(case);
            assert_runtime_raw_substitution(case, &format!("{case_id}-raw"));
            assert_rehashed_process_status_substitution_rejected(
                case,
                &format!("{case_id}-status"),
                (true, 0),
                (false, 1),
            );
            let invalid_id = format!("runtime-ord-list-{slug}-byte-string-invalid-bytes");
            let invalid = runtime_case(cases, &invalid_id);
            let (root, directory) = retain_executed_runtime_case(invalid, &invalid_id);
            fs::write(
                directory.join("stdin.bin"),
                [0xff, 0x41, 0xfe, 0x43, 0xff, 0x41],
            )
            .unwrap();
            rehash_runtime_bundle(&directory, invalid);
            assert!(verify_observation_bundle_for_case(&directory, invalid).is_err());
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_ord_list_typed_mutant(case: &crate::DifferentialCase) {
        let source_root = root(&format!("{}-typed", case.id));
        let (success, mut semantic, stdout) =
            execute_runtime_interaction_with_stdout(case, &source_root);
        let canonical = semantic
            .typed_result_canonical
            .as_ref()
            .unwrap()
            .to_string();
        let changed = canonical.replacen("\"value\":\"1\"", "\"value\":\"2\"", 1);
        assert_ne!(changed, canonical);
        let changed: Arc<str> = Arc::from(changed);
        semantic.typed_result_sha256 = Some(sha256_bytes(changed.as_bytes()));
        semantic.typed_result_canonical = Some(changed);
        assert_rehashed_runtime_semantic_rejected(
            case,
            semantic,
            &stdout,
            success,
            &format!("{}-typed", case.id),
        );
        fs::remove_dir_all(source_root).unwrap();
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_ord_list_demand_and_boundary_mutants(cases: &[crate::DifferentialCase]) {
        for (slug, builtin, arguments) in [
            ("list-sort", "List.sort", &[(0, "whnf-force-complete")][..]),
            (
                "list-nubord",
                "List.nubOrd",
                &[(0, "whnf-force-complete")][..],
            ),
            (
                "list-sorton",
                "List.sortOn",
                &[(0, "lazy-adapter-entry"), (1, "whnf-force-complete")][..],
            ),
        ] {
            let case_id = format!("runtime-ord-list-{slug}-int-finite-input");
            for (argument, class) in arguments {
                assert_demand_argument_state_substitution_rejected(
                    cases, &case_id, builtin, *argument, class,
                );
            }
            assert_ord_list_boundary_mutant(runtime_case(cases, &case_id));
        }
    }

    #[cfg(feature = "compat-tracing")]
    fn assert_ord_list_boundary_mutant(case: &crate::DifferentialCase) {
        let (root, directory) =
            retain_executed_runtime_case(case, &format!("{}-boundary", case.id));
        let path = directory.join("case.toml");
        let document = fs::read_to_string(&path).unwrap();
        let changed = document.replacen("\"finite-input\"", "\"singleton-input\"", 1);
        assert_ne!(changed, document);
        fs::write(&path, changed).unwrap();
        rewrite_bundle_file_digest(&directory, "case.toml");
        assert!(verify_observation_bundle_for_case(&directory, case).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
