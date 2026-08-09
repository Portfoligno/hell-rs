//! Durable, structured differential evidence and mismatch replay bundles.

use std::ffi::OsStr;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use crate::{
    BoundedCapture, DifferentialCase, DifferentialReport, ExecutableIdentity, Observation,
    sha256_bytes,
};

/// Retains all raw observations and a structured, shell-free replay contract.
///
/// # Errors
///
/// Returns an error when the case identifier is unsafe or any artifact cannot
/// be created. Existing files for the same case are replaced atomically where
/// the host filesystem permits it.
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
    fs::create_dir_all(&directory)?;
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
    Ok(directory)
}

/// Inputs recorded in one nightly evidence summary.
pub struct EvidenceSummary<'a> {
    pub oracle: &'a ExecutableIdentity,
    pub candidate: &'a ExecutableIdentity,
    pub corpus_seed: u64,
    pub committed_observations: usize,
    pub generated_observations: usize,
    pub corpus_sha256: crate::Digest,
    pub mismatches: usize,
    pub unexpected_timeouts: usize,
    pub stale_exact_claims: usize,
    pub missing_evidence_references: usize,
    pub compatibility_snapshot_sha256: crate::Digest,
    pub claim_evidence_index_sha256: crate::Digest,
    pub dependency_lock_sha256: crate::Digest,
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
        "{\n  \"schemaVersion\": 1,\n  \"shardIndex\": 0,\n  \"shardCount\": 1,\n  \"platform\": ",
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
    summary.push_str(",\n  \"mismatches\": ");
    write!(summary, "{}", evidence.mismatches).expect("writing to String cannot fail");
    summary.push_str(",\n  \"unexpectedTimeouts\": ");
    write!(summary, "{}", evidence.unexpected_timeouts).expect("writing to String cannot fail");
    summary.push_str(",\n  \"staleExactClaims\": ");
    write!(summary, "{}", evidence.stale_exact_claims).expect("writing to String cannot fail");
    summary.push_str(",\n  \"missingEvidenceReferences\": ");
    write!(summary, "{}", evidence.missing_evidence_references)
        .expect("writing to String cannot fail");
    summary.push_str(",\n  \"compatibilitySnapshotSha256\": ");
    push_json_string(&mut summary, &evidence.compatibility_snapshot_sha256.hex());
    summary.push_str(",\n  \"claimEvidenceIndexSha256\": ");
    push_json_string(&mut summary, &evidence.claim_evidence_index_sha256.hex());
    summary.push_str(",\n  \"dependencyLockSha256\": ");
    push_json_string(&mut summary, &evidence.dependency_lock_sha256.hex());
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
    let valid = !id.is_empty()
        && !id.starts_with('-')
        && !id.ends_with('-')
        && id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    valid.then_some(()).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("unsafe differential case identifier {id:?}"),
        )
    })
}

fn case_descriptor(case: &DifferentialCase) -> String {
    let mut output = String::from("schema_version = 1\nid = ");
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
    output
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
    write_atomic(
        &root.join(format!("{name}.json")),
        observation_json(observation).as_bytes(),
    )?;
    write_capture(root, name, "stdout", &observation.stdout)?;
    write_capture(root, name, "stderr", &observation.stderr)
}

fn write_capture(
    root: &Path,
    executable: &str,
    stream: &str,
    capture: &BoundedCapture,
) -> std::io::Result<()> {
    write_atomic(
        &root.join(format!("{executable}.{stream}.bin")),
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

    #[test]
    fn rejects_case_ids_that_can_escape_the_artifact_root() {
        assert!(validate_case_id("json-number-large").is_ok());
        assert!(validate_case_id("../outside").is_err());
        assert!(validate_case_id("Uppercase").is_err());
    }
}
