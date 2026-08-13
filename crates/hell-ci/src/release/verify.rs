use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::json::{JsonValue, canonical_json_bytes, json_member, require_exact_json_keys};

use super::archive;
use super::manifest::{read_json, read_regular, write_json};
use super::schema::{PLATFORMS, ReleasePlan, number, object, string};

const ATTESTATIONS: [&str; 2] = [
    "github-provenance.sigstore.json",
    "github-release-gate.sigstore.json",
];

pub(crate) fn bundle(
    plan_path: PathBuf,
    conformance_plan_path: PathBuf,
    input: PathBuf,
    report: PathBuf,
) -> Result<String, String> {
    verify_bundle(
        &plan_path,
        Some(&conformance_plan_path),
        &input,
        &report,
        false,
        true,
    )
}

pub(super) fn technical_bundle(
    plan_path: PathBuf,
    conformance_plan_path: PathBuf,
    input: PathBuf,
    report: PathBuf,
) -> Result<String, String> {
    verify_bundle(
        &plan_path,
        Some(&conformance_plan_path),
        &input,
        &report,
        false,
        false,
    )
}

pub(crate) fn publication_bundle(
    plan_path: PathBuf,
    input: PathBuf,
    report: PathBuf,
) -> Result<String, String> {
    verify_bundle(&plan_path, None, &input, &report, true, false)
}

fn verify_bundle(
    plan_path: &Path,
    external_conformance_plan: Option<&PathBuf>,
    input: &Path,
    report: &Path,
    with_attestations: bool,
    verify_remote: bool,
) -> Result<String, String> {
    let plan = ReleasePlan::parse(&read_json(plan_path)?)?;
    require_real_directory(input)?;
    let bundled_plan_bytes = read_regular(&input.join("conformance-plan.json"))?;
    if let Some(path) = external_conformance_plan
        && !conformance_plan_bytes_match(&read_regular(path)?, &bundled_plan_bytes)
    {
        return Err("bundled conformance plan differs from trusted plan artifact".to_owned());
    }
    let conformance = crate::conformance::ConformancePlan::parse(&read_json(
        &input.join("conformance-plan.json"),
    )?)?;
    super::assemble::validate_conformance_binding(&plan, &conformance)?;
    let required_subjects = required_subjects(&plan);
    let subjects = parse_subjects(&read_regular(&input.join("SUBJECTS.sha256"))?)?;
    if subjects.keys().cloned().collect::<BTreeSet<_>>() != required_subjects {
        return Err("SUBJECTS.sha256 exact set differs".to_owned());
    }
    let mut top_level = required_subjects.clone();
    top_level.insert("SUBJECTS.sha256".to_owned());
    top_level.insert("release-gate.json".to_owned());
    if with_attestations {
        top_level.extend(ATTESTATIONS.iter().map(|name| (*name).to_owned()));
    }
    if directory_entries(input)? != top_level {
        return Err("release bundle top-level exact set differs".to_owned());
    }
    for name in &top_level {
        require_real_file(&input.join(name))?;
    }
    for (name, digest) in &subjects {
        if hell_testkit::sha256_bytes(&read_regular(&input.join(name))?).hex() != *digest {
            return Err(format!("release subject {name:?} digest differs"));
        }
    }
    let mut packaged_executables = BTreeMap::new();
    for platform in PLATFORMS {
        let archive_path = input.join(format!("hell-v{}-{}.tar.gz", plan.version, platform.id()));
        archive::verify(
            &archive_path,
            platform,
            &plan.version,
            plan.source_date_epoch,
        )?;
        let extraction_root =
            report.with_file_name(format!(".publisher-extract-{}", platform.id()));
        if extraction_root.exists() {
            return Err("publisher extraction staging path already exists".to_owned());
        }
        let executable = archive::extract_binary(
            &archive_path,
            platform,
            &plan.version,
            plan.source_date_epoch,
            &extraction_root,
        )?;
        let digest = hell_testkit::sha256_file(&executable)
            .map_err(|error| format!("cannot hash packaged executable: {error}"))?
            .hex();
        std::fs::remove_dir_all(&extraction_root)
            .map_err(|error| format!("cannot remove publisher extraction staging: {error}"))?;
        packaged_executables.insert(
            crate::conformance::ConformancePlatform::parse(platform.id())?,
            digest,
        );
    }
    verify_dependency_subject(input, &plan)?;
    super::assemble::verify_mutation_report(&input.join("mutation-report.json"), &plan)?;

    let evidence_path = input.join("conformance-evidence.tar.gz");
    let evidence_bytes = read_regular(&evidence_path)?;
    let evidence_sha256 = hell_testkit::sha256_bytes(&evidence_bytes).hex();
    let members = archive::read_evidence(&evidence_path, plan.source_date_epoch)?;
    if members.get("conformance-plan.json") != Some(&bundled_plan_bytes) {
        return Err("evidence archive conformance plan differs from bundle".to_owned());
    }
    let retained_inventory = members
        .get("source-inventory.json")
        .ok_or_else(|| "evidence archive lacks source inventory".to_owned())?;
    if hell_testkit::sha256_bytes(retained_inventory).hex() != plan.source_inventory_sha256 {
        return Err("evidence source inventory differs from release plan".to_owned());
    }
    let trusted_value = parse_member_json(&members, "trusted-conformance-inputs.json")?;
    let trusted = crate::conformance::parse_trusted_inputs(&trusted_value)?;
    if trusted.aggregate_sha256 != conformance.trusted_inputs_sha256 {
        return Err("evidence archive trusted inputs differ from conformance plan".to_owned());
    }
    let trusted_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let rebuilt = crate::conformance::build_trusted_inputs(
        &trusted_root,
        &trusted_root,
        &plan.resolution.workflow_sha,
    )?;
    if canonical_json_bytes(&rebuilt.manifest)? != members["trusted-conformance-inputs.json"] {
        return Err("evidence trusted inputs differ from publisher checkout".to_owned());
    }
    let mut manifests = Vec::new();
    for platform in crate::conformance::ConformancePlatform::ALL {
        let path = format!("platform-manifests/{}.json", platform.as_str());
        let manifest =
            crate::conformance::EvidenceManifest::parse(&parse_member_json(&members, &path)?)?;
        if manifest.platform != platform {
            return Err("platform manifest identity differs from archive path".to_owned());
        }
        if packaged_executables.get(&platform) != Some(&manifest.candidate_executable_sha256) {
            return Err("packaged executable differs from evidence manifest identity".to_owned());
        }
        manifests.push(manifest);
    }
    let bindings =
        crate::conformance::TrustedEvidenceBindings::from_manifests(&conformance, &manifests)?;
    let repository = crate::conformance::EvidenceRepository::from_archive_members(
        &manifests,
        &members,
        &bindings,
        &conformance,
    )?;
    let partition = crate::conformance::independently_reconstruct_partition(
        &conformance,
        &crate::conformance::canonical_universe()?,
        &repository,
        &bindings,
    )?;
    let reconstructed_report =
        crate::conformance::conformance_report(&conformance, &partition, &evidence_sha256)?;
    let reconstructed_report_bytes = canonical_json_bytes(&reconstructed_report)?;
    if reconstructed_report_bytes != read_regular(&input.join("conformance-report.json"))? {
        return Err("conformance report differs from independent reconstruction".to_owned());
    }
    let report_sha256 = json_member(reconstructed_report.object()?, "reportSha256")?
        .string()?
        .to_owned();
    let reconstructed_acceptance = crate::conformance::ConformanceAcceptance::derive(
        &conformance,
        &partition,
        evidence_sha256.clone(),
        report_sha256.clone(),
    )?;
    let producer_acceptance = crate::conformance::ConformanceAcceptance::parse(&read_json(
        &input.join("conformance-acceptance.json"),
    )?)?;
    if !acceptance_bytes_match(
        &canonical_json_bytes(&producer_acceptance.json())?,
        &canonical_json_bytes(&reconstructed_acceptance.json())?,
    ) {
        return Err("producer acceptance differs from independent reconstruction".to_owned());
    }
    if !reconstructed_acceptance.admitted {
        return Err("publisher independently reconstructed a blocking partition".to_owned());
    }
    let required = u64::try_from(
        conformance
            .cells
            .iter()
            .filter(|cell| {
                matches!(
                    cell.scope,
                    crate::conformance::ScopeDisposition::Required { .. }
                )
            })
            .count(),
    )
    .map_err(|_| "required cell count overflow")?;
    let expected_html =
        super::assemble::conformance_html(&plan, &reconstructed_acceptance, required);
    if read_regular(&input.join("conformance-report.html"))? != expected_html.as_bytes() {
        return Err("conformance HTML differs from trusted static rendering".to_owned());
    }
    let expected_notes = super::assemble::release_notes(&plan, &reconstructed_acceptance, required);
    if read_regular(&input.join("release-notes.md"))? != expected_notes.as_bytes() {
        return Err("release notes differ from reconstructed partition".to_owned());
    }
    verify_release_manifest(
        input,
        &plan,
        &conformance,
        &reconstructed_acceptance,
        required,
        &evidence_sha256,
        &report_sha256,
    )?;
    verify_release_gate(
        input,
        &plan,
        &conformance,
        &reconstructed_acceptance,
        &evidence_sha256,
        &report_sha256,
    )?;
    if verify_remote {
        verify_remote_stability(&plan)?;
    }
    write_json(
        report,
        &object([
            (
                "conformanceAcceptanceSha256",
                string(&reconstructed_acceptance.decision_sha256),
            ),
            ("conformancePlanSha256", string(&conformance.plan_sha256)),
            ("planSha256", string(&plan.plan_sha256)),
            ("schemaVersion", number(2)),
            ("state", string("bundle-independently-verified")),
        ]),
    )?;
    Ok("independently reconstructed and verified exact release bundle".to_owned())
}

fn verify_remote_stability(plan: &ReleasePlan) -> Result<(), String> {
    let client = super::github::GitHubClient::from_environment()?;
    if client.branch_head(
        &plan.resolution.repository,
        &plan.resolution.candidate_branch,
    )? != plan.resolution.candidate_sha
    {
        return Err("candidate branch moved before release attestation".to_owned());
    }
    if client
        .tag_commit(&plan.resolution.repository, &plan.tag)?
        .is_some()
    {
        return Err("release tag exists before release attestation".to_owned());
    }
    Ok(())
}

fn required_subjects(plan: &ReleasePlan) -> BTreeSet<String> {
    let mut required = BTreeSet::from([
        "conformance-acceptance.json".to_owned(),
        "conformance-evidence.tar.gz".to_owned(),
        "conformance-plan.json".to_owned(),
        "conformance-report.html".to_owned(),
        "conformance-report.json".to_owned(),
        "dependency-policy.json".to_owned(),
        "mutation-report.json".to_owned(),
        "release-manifest.json".to_owned(),
        "release-notes.md".to_owned(),
        format!("hell-v{}-linux-x86_64.tar.gz", plan.version),
        format!("hell-v{}-macos-aarch64.tar.gz", plan.version),
        format!("hell-v{}-windows-x86_64.tar.gz", plan.version),
    ]);
    if crate::conformance::mutant_active("conformance-evidence-asset-omitted") {
        required.remove("conformance-evidence.tar.gz");
    }
    required
}

fn conformance_plan_bytes_match(trusted: &[u8], bundled: &[u8]) -> bool {
    crate::conformance::mutant_active("conformance-plan-digest-not-bound") || trusted == bundled
}

fn acceptance_bytes_match(producer: &[u8], reconstructed: &[u8]) -> bool {
    crate::conformance::mutant_active("publisher-trusts-acceptance-json")
        || producer == reconstructed
}

fn conformance_digests_match(
    fields: &BTreeMap<String, JsonValue>,
    plan_sha256: &str,
    acceptance_sha256: &str,
    evidence_sha256: &str,
    report_sha256: &str,
) -> Result<bool, String> {
    if crate::conformance::mutant_active("release-gate-conformance-digest-omitted") {
        return Ok(true);
    }
    Ok(
        json_member(fields, "conformancePlanSha256")?.string()? == plan_sha256
            && json_member(fields, "conformanceEvidenceSha256")?.string()? == evidence_sha256
            && json_member(fields, "conformanceReportSha256")?.string()? == report_sha256
            && json_member(fields, "conformanceAcceptanceSha256")?.string()? == acceptance_sha256,
    )
}

fn release_manifest_matches(actual: &JsonValue, expected: &JsonValue) -> bool {
    crate::conformance::mutant_active("legacy-bounded-policy-accepted") || actual == expected
}

fn verify_release_manifest(
    input: &Path,
    _plan: &ReleasePlan,
    conformance: &crate::conformance::ConformancePlan,
    acceptance: &crate::conformance::ConformanceAcceptance,
    required: u64,
    evidence_sha256: &str,
    report_sha256: &str,
) -> Result<(), String> {
    let expected = object([
        ("candidateCodeExecutedInPublisher", JsonValue::Bool(false)),
        (
            "conformance",
            super::assemble::conformance_summary(
                conformance,
                acceptance,
                required,
                evidence_sha256,
                report_sha256,
                &acceptance.decision_sha256,
            ),
        ),
        ("externalCustody", JsonValue::Bool(false)),
        ("githubArtifactAttestations", JsonValue::Bool(true)),
        ("githubImmutableReleaseRequired", JsonValue::Bool(true)),
        ("independentProviderAcquisition", JsonValue::Bool(false)),
        (
            "platforms",
            JsonValue::Array(
                PLATFORMS
                    .iter()
                    .map(|platform| string(platform.id()))
                    .collect(),
            ),
        ),
        ("schemaVersion", number(2)),
        ("sshSignatures", JsonValue::Bool(false)),
    ]);
    let actual = read_json(&input.join("release-manifest.json"))?;
    if !release_manifest_matches(&actual, &expected) {
        return Err("release manifest differs from exact v2 conformance disclosure".to_owned());
    }
    Ok(())
}

fn verify_release_gate(
    input: &Path,
    plan: &ReleasePlan,
    conformance: &crate::conformance::ConformancePlan,
    acceptance: &crate::conformance::ConformanceAcceptance,
    evidence_sha256: &str,
    report_sha256: &str,
) -> Result<(), String> {
    let subjects_bytes = read_regular(&input.join("SUBJECTS.sha256"))?;
    let gate = read_json(&input.join("release-gate.json"))?;
    let fields = gate.object()?;
    require_exact_json_keys(
        fields,
        &[
            "candidateCodeExecutedInPublisher",
            "candidateSha",
            "conformanceAcceptanceSha256",
            "conformanceCounts",
            "conformanceEvidenceSha256",
            "conformancePlanSha256",
            "conformanceReportSha256",
            "conformanceStandard",
            "releaseGateSha256",
            "releasePlanSha256",
            "repository",
            "runAttempt",
            "runId",
            "schemaVersion",
            "state",
            "subjectsSha256",
            "tag",
            "version",
            "workflowSha",
        ],
    )?;
    let stated = json_member(fields, "releaseGateSha256")?
        .string()?
        .to_owned();
    let mut without = fields.clone();
    without.remove("releaseGateSha256");
    if stated
        != hell_testkit::sha256_bytes(&canonical_json_bytes(&JsonValue::Object(without))?).hex()
        || json_member(fields, "schemaVersion")?.number()? != 2
        || json_member(fields, "state")?.string()? != "admitted"
        || json_member(fields, "repository")?.string()? != plan.resolution.repository
        || json_member(fields, "candidateSha")?.string()? != plan.resolution.candidate_sha
        || json_member(fields, "workflowSha")?.string()? != plan.resolution.workflow_sha
        || json_member(fields, "runId")?.number()? != plan.resolution.run_id
        || json_member(fields, "runAttempt")?.number()? != plan.resolution.run_attempt
        || json_member(fields, "version")?.string()? != plan.version
        || json_member(fields, "tag")?.string()? != plan.tag
        || json_member(fields, "releasePlanSha256")?.string()? != plan.plan_sha256
        || json_member(fields, "conformanceStandard")?.string()? != conformance.standard
        || !conformance_digests_match(
            fields,
            &conformance.plan_sha256,
            &acceptance.decision_sha256,
            evidence_sha256,
            report_sha256,
        )?
        || json_member(fields, "conformanceCounts")? != &super::assemble::gate_counts(acceptance)
        || json_member(fields, "subjectsSha256")?.string()?
            != hell_testkit::sha256_bytes(&subjects_bytes).hex()
        || json_member(fields, "candidateCodeExecutedInPublisher")?.boolean()?
    {
        return Err("release gate differs from exact v2 reconstructed decision".to_owned());
    }
    Ok(())
}

fn parse_member_json(members: &BTreeMap<String, Vec<u8>>, path: &str) -> Result<JsonValue, String> {
    let bytes = members
        .get(path)
        .ok_or_else(|| format!("evidence archive lacks {path:?}"))?;
    let text = std::str::from_utf8(bytes)
        .map_err(|_| format!("evidence archive member {path:?} is not UTF-8"))?;
    let value = crate::json::parse_json(text)?;
    if canonical_json_bytes(&value)? != *bytes {
        return Err(format!("evidence archive member {path:?} is not canonical"));
    }
    Ok(value)
}

fn verify_dependency_subject(input: &Path, plan: &ReleasePlan) -> Result<(), String> {
    let value = read_json(&input.join("dependency-policy.json"))?;
    let fields = value.object()?;
    require_exact_json_keys(
        fields,
        &[
            "candidateSourceCommit",
            "cargoLockSha256",
            "denyPolicySha256",
            "result",
            "schemaVersion",
            "workflow",
        ],
    )?;
    if json_member(fields, "candidateSourceCommit")?.string()? != plan.resolution.candidate_sha
        || json_member(fields, "denyPolicySha256")?.string()?
            != hell_testkit::sha256_bytes(include_bytes!("../../../../deny.toml")).hex()
        || json_member(fields, "result")?.string()? != "passed"
        || json_member(fields, "workflow")?.string()? != "release.yml"
    {
        return Err("dependency subject differs from trusted release policy".to_owned());
    }
    super::schema::require_digest(
        json_member(fields, "cargoLockSha256")?.string()?,
        "Cargo.lock digest",
    )
}

fn parse_subjects(bytes: &[u8]) -> Result<BTreeMap<String, String>, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "SUBJECTS.sha256 is not UTF-8".to_owned())?;
    if !text.ends_with('\n') {
        return Err("SUBJECTS.sha256 has no trailing newline".to_owned());
    }
    let mut subjects = BTreeMap::new();
    for line in text.lines() {
        let (digest, name) = line
            .split_once("  ")
            .ok_or_else(|| "SUBJECTS.sha256 line is malformed".to_owned())?;
        super::schema::require_digest(digest, "subject digest")?;
        if name.is_empty()
            || name.contains(['/', '\\'])
            || name == "release-gate.json"
            || subjects
                .insert(name.to_owned(), digest.to_owned())
                .is_some()
        {
            return Err("SUBJECTS.sha256 contains unsafe, cyclic, or duplicate name".to_owned());
        }
    }
    Ok(subjects)
}

fn directory_entries(path: &Path) -> Result<BTreeSet<String>, String> {
    std::fs::read_dir(path)
        .map_err(|error| format!("cannot enumerate release bundle: {error}"))?
        .map(|entry| {
            entry
                .map_err(|error| format!("cannot inspect release bundle: {error}"))?
                .file_name()
                .into_string()
                .map_err(|_| "release bundle entry is not UTF-8".to_owned())
        })
        .collect()
}

fn require_real_directory(path: &Path) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect directory {path:?}: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "release bundle path is not a real directory: {path:?}"
        ));
    }
    Ok(())
}

fn require_real_file(path: &Path) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect file {path:?}: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!("release bundle path is not a real file: {path:?}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> ReleasePlan {
        ReleasePlan {
            resolution: super::super::schema::Resolution {
                repository: "o/r".into(),
                repository_id: 1,
                default_branch: "main".into(),
                candidate_branch: "release".into(),
                candidate_sha: "a".repeat(40),
                actor: "actor".into(),
                actor_id: 2,
                run_id: 3,
                run_attempt: 1,
                workflow_ref: "o/r/.github/workflows/release.yml@refs/heads/main".into(),
                workflow_sha: "b".repeat(40),
            },
            version: "1.0.0".into(),
            tag: "v1.0.0".into(),
            prerelease: false,
            source_date_epoch: 1,
            release_evaluation_instant: "2026-08-13T00:00:00Z".into(),
            source_inventory_sha256: "c".repeat(64),
            build_inputs_sha256: "d".repeat(64),
            policy_sha256: "e".repeat(64),
            trusted_conformance_inputs_sha256: "f".repeat(64),
            conformance_plan_sha256: "1".repeat(64),
            conformance_standard: crate::conformance::RELEASE_STANDARD.into(),
            changelog_sha256: "2".repeat(64),
            commit_author: "A <a@example.test>".into(),
            commit_committer: "C <c@example.test>".into(),
            plan_sha256: "3".repeat(64),
        }
    }

    #[test]
    fn release_gate_is_cycle_safely_excluded_from_subjects() {
        assert!(
            parse_subjects(&format!("{}  release-gate.json\n", "a".repeat(64)).into_bytes())
                .is_err()
        );
    }

    #[test]
    fn exact_conformance_asset_set_is_required() {
        assert!(required_subjects(&plan()).contains("conformance-evidence.tar.gz"));
    }

    #[test]
    fn conformance_plan_digest_is_bound() {
        assert!(!conformance_plan_bytes_match(b"trusted\n", b"candidate\n"));
    }

    #[test]
    fn publisher_reconstructs_instead_of_trusting_acceptance() {
        assert!(!acceptance_bytes_match(b"producer\n", b"reconstructed\n"));
    }

    #[test]
    fn release_gate_binds_conformance_digests() {
        let fields = BTreeMap::from([
            (
                "conformanceAcceptanceSha256".to_owned(),
                string(&"a".repeat(64)),
            ),
            (
                "conformanceEvidenceSha256".to_owned(),
                string(&"b".repeat(64)),
            ),
            ("conformancePlanSha256".to_owned(), string(&"c".repeat(64))),
            (
                "conformanceReportSha256".to_owned(),
                string(&"d".repeat(64)),
            ),
        ]);
        assert!(
            !conformance_digests_match(
                &fields,
                &"e".repeat(64),
                &"a".repeat(64),
                &"b".repeat(64),
                &"d".repeat(64),
            )
            .unwrap()
        );
    }

    #[test]
    fn legacy_bounded_bundle_is_rejected() {
        let legacy = object([("profile", string("bounded")), ("schemaVersion", number(1))]);
        let expected = object([("schemaVersion", number(2))]);
        assert!(!release_manifest_matches(&legacy, &expected));
    }
}
