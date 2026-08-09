//! Durable, structured differential evidence and mismatch replay bundles.

use std::ffi::OsStr;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use crate::{
    BoundedCapture, DifferentialCase, DifferentialMode, DifferentialReport, Digest,
    ExecutableIdentity, NormalizerId, Observation, ResourceAudit, applied_claim_normalizers,
    applied_harness_normalizers, sha256_bytes, sha256_file,
};

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
    write_bundle_manifest(&directory, case)?;
    Ok(directory)
}

/// Verifies a schema-v2 bundle manifest, its digest record, the exact portable
/// file inventory, and every retained file digest.
///
/// # Errors
///
/// Returns an error for malformed manifests, legacy/extra/missing paths, or a
/// digest mismatch.
pub fn verify_observation_bundle(directory: &Path) -> std::io::Result<Digest> {
    let manifest_path = directory.join("bundle-manifest.json");
    let manifest = fs::read_to_string(&manifest_path)?;
    if !manifest.starts_with("{\n  \"schemaVersion\": 2,\n") || !manifest.ends_with("\n}\n") {
        return Err(std::io::Error::other(
            "observation bundle manifest has an unsupported schema",
        ));
    }
    let manifest_digest = sha256_bytes(manifest.as_bytes());
    let digest_record = fs::read_to_string(directory.join("bundle-manifest.sha256"))?;
    let expected_record = format!("{}  bundle-manifest.json\n", manifest_digest.hex());
    if digest_record != expected_record {
        return Err(std::io::Error::other(
            "observation bundle manifest digest record is invalid",
        ));
    }
    let mut declared = Vec::new();
    let mut in_files = false;
    for line in manifest.lines() {
        let line = line.trim();
        if line == "\"files\": {" {
            in_files = true;
            continue;
        }
        if in_files && line == "}" {
            in_files = false;
            continue;
        }
        if !in_files {
            continue;
        }
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
        let observed = sha256_file(&directory.join(relative))?.hex();
        if observed != digest {
            return Err(std::io::Error::other(format!(
                "bundle file digest mismatch for {relative}"
            )));
        }
        declared.push((relative.to_owned(), digest.to_owned()));
    }
    if in_files || declared.is_empty() {
        return Err(std::io::Error::other("bundle file inventory is incomplete"));
    }
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
    let digest = verify_observation_bundle(directory)?;
    if fs::read(directory.join("main.hell"))? != case.source.as_bytes()
        || fs::read_to_string(directory.join("case.toml"))? != case_descriptor(case)
    {
        return Err(std::io::Error::other(
            "observation bundle case descriptor differs from the committed catalog",
        ));
    }
    validate_observation_metadata(&directory.join("oracle/observation.json"), case)?;
    validate_observation_metadata(&directory.join("candidate/observation.json"), case)?;
    if case.mode == DifferentialMode::Run {
        let audit = fs::read_to_string(directory.join("candidate/resource-audit.json"))?;
        if audit != resource_audit_json(&ResourceAudit::default()) {
            return Err(std::io::Error::other(
                "candidate resource audit is malformed or reports retained resources",
            ));
        }
    }
    Ok(digest)
}

fn validate_observation_metadata(path: &Path, case: &DifferentialCase) -> std::io::Result<()> {
    let document = fs::read_to_string(path)?;
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
    Ok(())
}

/// Inputs recorded in one nightly evidence summary.
pub struct EvidenceSummary<'a> {
    pub oracle: &'a ExecutableIdentity,
    pub candidate: &'a ExecutableIdentity,
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
    let shard_root = root.join("evidence/shards");
    fs::create_dir_all(&shard_root)?;
    write_atomic(
        &root.join("oracle-identity.json"),
        identity_json(evidence.oracle).as_bytes(),
    )?;
    write_atomic(
        &root.join("candidate-identity.json"),
        identity_json(evidence.candidate).as_bytes(),
    )?;
    let mut summary = String::from(
        "{\n  \"schemaVersion\": 2,\n  \"shardIndex\": 0,\n  \"shardCount\": 1,\n  \"observationBundleSchemaVersion\": 2,\n  \"claimIndexSchemaVersion\": 2,\n  \"oracleRecordSchemaVersion\": 2,\n  \"platform\": ",
    );
    push_json_string(
        &mut summary,
        &format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
    );
    summary.push_str(",\n  \"oracleSha256\": ");
    push_json_string(&mut summary, &evidence.oracle.sha256.hex());
    summary.push_str(",\n  \"candidateSha256\": ");
    push_json_string(&mut summary, &evidence.candidate.sha256.hex());
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

fn case_descriptor(case: &DifferentialCase) -> String {
    let mut output = String::from("schema_version = 2\nid = ");
    push_toml_string(&mut output, &case.id);
    output.push_str("\nmode = ");
    push_toml_string(&mut output, &format!("{:?}", case.mode));
    output.push_str("\nenvironment_profile = ");
    push_toml_string(&mut output, &format!("{:?}", case.environment_profile));
    if let Some(directory) = &case.process_helper_directory {
        output.push_str("\nprocess_helper_directory = ");
        push_toml_string(&mut output, &directory.to_string_lossy());
    }
    output.push_str("\ntimeout_millis = ");
    writeln!(output, "{}", case.timeout.as_millis()).expect("writing to String cannot fail");
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
        for target in &descriptor.targets {
            output.push_str("\n[[targets]]\nbuiltin = ");
            push_toml_string(&mut output, &target.builtin);
            output.push_str("\ndimension = ");
            push_toml_string(&mut output, target.dimension.as_str());
            output.push('\n');
        }
    }
    output
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
    output.push_str(",\n  \"source\": \"main.hell\",\n  \"arguments\": [");
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

fn write_observation(root: &Path, name: &str, observation: &Observation) -> std::io::Result<()> {
    let directory = root.join(name);
    fs::create_dir(&directory)?;
    write_atomic(
        &directory.join("observation.json"),
        observation_json(observation).as_bytes(),
    )?;
    write_capture(&directory, "stdout", &observation.stdout)?;
    write_capture(&directory, "stderr", &observation.stderr)?;
    if let Some(audit) = &observation.resource_audit {
        write_atomic(
            &directory.join("resource-audit.json"),
            resource_audit_json(audit).as_bytes(),
        )?;
    }
    Ok(())
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
    output.push_str(",\n  \"mode\": ");
    push_json_string(&mut output, &format!("{:?}", observation.mode));
    output.push_str(",\n  \"harnessNormalizers\": ");
    push_json_normalizers(&mut output, &observation.harness_normalizers);
    output.push_str(",\n  \"claimNormalizers\": ");
    push_json_normalizers(&mut output, &observation.claim_normalizers);
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
        push_json_string(&mut output, &format!("{:?}", diagnostic.phase));
        output.push_str(", \"line\": ");
        write!(output, "{}", diagnostic.line).expect("writing to String cannot fail");
        output.push_str(", \"column\": ");
        write!(output, "{}", diagnostic.column).expect("writing to String cannot fail");
        output.push('}');
    } else {
        output.push_str("null");
    }
    push_capture_json(&mut output, "stdout", &observation.stdout);
    push_capture_json(&mut output, "stderr", &observation.stderr);
    output.push_str(",\n  \"filesystem\": [");
    for (index, entry) in observation.filesystem.iter().enumerate() {
        if index != 0 {
            output.push_str(", ");
        }
        output.push_str("{\"path\": ");
        push_os_json_string(&mut output, entry.relative_path.as_os_str());
        output.push_str(", \"kind\": ");
        push_json_string(&mut output, &format!("{:?}", entry.kind));
        output.push_str(", \"size\": ");
        write!(output, "{}", entry.size).expect("writing to String cannot fail");
        output.push_str(", \"sha256\": ");
        if let Some(digest) = entry.sha256 {
            push_json_string(&mut output, &digest.hex());
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
    output.push_str("\n}\n");
    output
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

fn write_bundle_manifest(directory: &Path, case: &DifferentialCase) -> std::io::Result<()> {
    let observed = collect_bundle_files(directory)?;
    let mut expected = vec![
        "candidate/observation.json".to_owned(),
        "candidate/stderr.bin".to_owned(),
        "candidate/stdout.bin".to_owned(),
        "case.toml".to_owned(),
        "filesystem.diff".to_owned(),
        "main.hell".to_owned(),
        "normalized.diff".to_owned(),
        "oracle/observation.json".to_owned(),
        "oracle/stderr.bin".to_owned(),
        "oracle/stdout.bin".to_owned(),
        "replay.json".to_owned(),
    ];
    if case.mode == DifferentialMode::Run {
        expected.push("candidate/resource-audit.json".to_owned());
        expected.sort();
    }
    if observed != expected {
        return Err(std::io::Error::other(format!(
            "observation bundle file inventory is not schema v2: {observed:?}"
        )));
    }
    let mut manifest = String::from("{\n  \"schemaVersion\": 2,\n  \"caseId\": ");
    push_json_string(&mut manifest, &case.id);
    manifest.push_str(",\n  \"profile\": ");
    let profile = case
        .claim_evidence
        .as_ref()
        .map_or("ineligible", |descriptor| match descriptor.profile {
            hell_builtins::ExecutionProfile::Upstream => "upstream",
            hell_builtins::ExecutionProfile::Sandboxed => "sandboxed",
        });
    push_json_string(&mut manifest, profile);
    manifest.push_str(",\n  \"files\": {\n");
    for (index, relative) in observed.iter().enumerate() {
        manifest.push_str("    ");
        push_json_string(&mut manifest, relative);
        manifest.push_str(": ");
        push_json_string(
            &mut manifest,
            &sha256_file(&directory.join(relative))?.hex(),
        );
        if index + 1 != observed.len() {
            manifest.push(',');
        }
        manifest.push('\n');
    }
    manifest.push_str("  }\n}\n");
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
    let mut output = String::from("{\n  \"schemaVersion\": 1,\n  \"role\": ");
    push_json_string(&mut output, &format!("{:?}", identity.role));
    output.push_str(",\n  \"path\": ");
    push_os_json_string(&mut output, identity.path.as_os_str());
    output.push_str(",\n  \"sha256\": ");
    push_json_string(&mut output, &identity.sha256.hex());
    output.push_str(",\n  \"reportedVersion\": ");
    push_json_string(&mut output, &identity.reported_version);
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

fn push_json_string(output: &mut String, value: &str) {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn root(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "hell-testkit-promotion-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        root
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
            },
            case_id: "layout".into(),
            environment_profile: crate::EnvironmentProfile::Explicit,
            mode: DifferentialMode::Run,
            status: crate::ProcessStatus {
                success: true,
                code: Some(0),
            },
            stdout: BoundedCapture::from_bytes(b"ok\n".to_vec()),
            stderr: BoundedCapture::from_bytes(Vec::new()),
            timed_out: false,
            diagnostic: None,
            filesystem: Vec::new(),
            harness_normalizers: vec![NormalizerId::DiagnosticSandboxPathV1],
            claim_normalizers: Vec::new(),
            resource_audit: (role == crate::ExecutableRole::Candidate).then(ResourceAudit::default),
        }
    }

    fn report() -> DifferentialReport {
        DifferentialReport {
            oracle: observation(crate::ExecutableRole::Oracle),
            candidate: observation(crate::ExecutableRole::Candidate),
            mismatches: Vec::new(),
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
            write_bundle_manifest(&directory, &case).unwrap();
            assert!(verify_observation_bundle(&directory).is_ok());
            assert!(verify_observation_bundle_for_case(&directory, &case).is_err());
            fs::remove_dir_all(root).unwrap();
        }
    }
}
