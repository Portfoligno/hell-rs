use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::json::{JsonValue, canonical_json_bytes, json_member, require_exact_json_keys};

use super::archive;
use super::decision::VerifierDecision;
use super::manifest::{read_json, read_regular, write_json};
use super::schema::{PLATFORMS, ReleasePlan, number, object, string};

const ATTESTATIONS: [&str; 2] = [
    "github-provenance.sigstore.json",
    "github-release-gate.sigstore.json",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BundleKind {
    Technical,
    Publication,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct GovernanceReceiptDigests {
    pub(super) resolve: String,
    pub(super) post_assembly: String,
    pub(super) pre_attestation: String,
}

pub(crate) fn bundle(
    plan_path: PathBuf,
    conformance_plan_path: PathBuf,
    input: PathBuf,
    report: PathBuf,
    protocol_projection: PathBuf,
) -> Result<String, String> {
    let plan_path = plan_path.into_boxed_path();
    let conformance_plan_path = conformance_plan_path.into_boxed_path();
    let input = input.into_boxed_path();
    let report = report.into_boxed_path();
    let protocol_projection = protocol_projection.into_boxed_path();
    let decision = report.with_file_name("primary-verifier-decision.json");
    let protocol_sha256 = super::decision::protocol_sha256_from_projection(&protocol_projection)?;
    verify_bundle(&BundleVerification {
        plan_path: &plan_path,
        external_conformance_plan: Some(&conformance_plan_path),
        input: &input,
        report: &report,
        decision_output: Some(&decision),
        protocol_sha256: Some(&protocol_sha256),
        governance_receipts: None,
        kind: BundleKind::Technical,
    })
}

pub(super) fn technical_bundle(
    plan_path: PathBuf,
    conformance_plan_path: PathBuf,
    input: PathBuf,
    report: PathBuf,
) -> Result<String, String> {
    let plan_path = plan_path.into_boxed_path();
    let conformance_plan_path = conformance_plan_path.into_boxed_path();
    let input = input.into_boxed_path();
    let report = report.into_boxed_path();
    verify_bundle(&BundleVerification {
        plan_path: &plan_path,
        external_conformance_plan: Some(&conformance_plan_path),
        input: &input,
        report: &report,
        decision_output: None,
        protocol_sha256: None,
        governance_receipts: None,
        kind: BundleKind::Technical,
    })
}

pub(super) fn technical_bundle_with_decision(
    plan_path: PathBuf,
    conformance_plan_path: PathBuf,
    input: PathBuf,
    report: PathBuf,
    decision: PathBuf,
    protocol_sha256: String,
    governance_receipts: GovernanceReceiptDigests,
) -> Result<String, String> {
    let plan_path = plan_path.into_boxed_path();
    let conformance_plan_path = conformance_plan_path.into_boxed_path();
    let input = input.into_boxed_path();
    let report = report.into_boxed_path();
    let decision = decision.into_boxed_path();
    let protocol_sha256 = protocol_sha256.into_boxed_str();
    let governance_receipts = Box::new(governance_receipts);
    let result = verify_bundle(&BundleVerification {
        plan_path: &plan_path,
        external_conformance_plan: Some(&conformance_plan_path),
        input: &input,
        report: &report,
        decision_output: Some(&decision),
        protocol_sha256: Some(&protocol_sha256),
        governance_receipts: Some(&governance_receipts),
        kind: BundleKind::Technical,
    });
    if let Err(primary) = result {
        let diagnostic = diagnose_technical_input(&plan_path, &conformance_plan_path, &input);
        let persist = write_json(
            &report,
            &object([
                ("admitted", JsonValue::Bool(false)),
                ("diagnosticCode", string(diagnostic)),
                ("implementation", string("hell-ci")),
                ("schemaVersion", number(1)),
                ("state", string("blocked")),
            ]),
        );
        return match persist {
            Ok(_) => Err(primary),
            Err(persist) => Err(format!(
                "{primary}; additionally, cannot persist typed primary rejection: {persist}"
            )),
        };
    }
    result
}

fn diagnose_technical_input(
    plan_path: &Path,
    conformance_plan_path: &Path,
    input: &Path,
) -> &'static str {
    let Ok(plan_bytes) = read_regular(plan_path) else {
        return "release.input.plan";
    };
    let Ok(plan_text) = std::str::from_utf8(&plan_bytes) else {
        return "release.json.invalid";
    };
    let plan_value = match crate::json::parse_json_classified(plan_text) {
        Ok(value) => value,
        Err(error) => return error.code,
    };
    if canonical_json_bytes(&plan_value).ok().as_deref() != Some(plan_bytes.as_slice()) {
        return "release.json.noncanonical";
    }
    if plan_value
        .object()
        .ok()
        .and_then(|fields| fields.get("schemaVersion"))
        .and_then(|value| value.number().ok())
        != Some(2)
    {
        return "release.protocol.downgrade";
    }
    let Ok(plan) = ReleasePlan::parse(&plan_value) else {
        return "release.json.unknown-field";
    };
    let Ok(conformance_bytes) = read_regular(conformance_plan_path) else {
        return "release.input.conformance-plan";
    };
    let Ok(conformance_text) = std::str::from_utf8(&conformance_bytes) else {
        return "release.json.invalid";
    };
    let conformance = match crate::json::parse_json_classified(conformance_text) {
        Ok(value) => value,
        Err(error) => return error.code,
    };
    if canonical_json_bytes(&conformance).ok().as_deref() != Some(conformance_bytes.as_slice()) {
        return "release.json.noncanonical";
    }
    let Ok(fields) = conformance.object() else {
        return "release.json.unknown-field";
    };
    if let Ok(Some(diagnostic)) = classify_exemption_violation(&conformance, &plan) {
        return diagnostic;
    }
    if json_member(fields, "candidateSha")
        .and_then(JsonValue::string)
        .ok()
        != Some(plan.resolution.candidate_sha.as_str())
    {
        return "release.binding.candidate-sha";
    }
    if json_member(fields, "workflowSha")
        .and_then(JsonValue::string)
        .ok()
        != Some(plan.resolution.workflow_sha.as_str())
    {
        return "release.binding.workflow-sha";
    }
    if json_member(fields, "sourceInventorySha256")
        .and_then(JsonValue::string)
        .ok()
        != Some(plan.source_inventory_sha256.as_str())
    {
        return "release.binding.source-inventory";
    }
    diagnose_bundle_contents(input, &plan, &conformance)
}

fn diagnose_bundle_contents(
    input: &Path,
    plan: &ReleasePlan,
    conformance: &JsonValue,
) -> &'static str {
    if let Some(diagnostic) = diagnose_subject_bindings(input, plan) {
        return diagnostic;
    }
    diagnose_evidence_bindings(input, plan, conformance)
}

fn diagnose_subject_bindings(input: &Path, plan: &ReleasePlan) -> Option<&'static str> {
    let expected_subjects = required_subjects(plan);
    let Ok(subject_bytes) = read_regular(&input.join("SUBJECTS.sha256")) else {
        return Some("release.subject.missing");
    };
    let Ok(subjects) = parse_subjects(&subject_bytes) else {
        return Some("release.subject.missing");
    };
    let observed_subjects = subjects.keys().cloned().collect::<BTreeSet<_>>();
    if expected_subjects
        .difference(&observed_subjects)
        .next()
        .is_some()
    {
        return Some("release.subject.missing");
    }
    if observed_subjects != expected_subjects {
        return Some("release.subject.extra");
    }
    let mut expected_inventory = expected_subjects;
    expected_inventory.insert("SUBJECTS.sha256".to_owned());
    expected_inventory.insert("release-gate.json".to_owned());
    if directory_entries(input).ok().as_ref() != Some(&expected_inventory) {
        return Some("release.subject.extra");
    }
    let subject_digest = hell_testkit::sha256_bytes(&subject_bytes).hex();
    if let Ok(gate) = read_json(&input.join("release-gate.json"))
        && let Ok(fields) = gate.object()
    {
        if json_member(fields, "subjectsSha256")
            .and_then(JsonValue::string)
            .ok()
            != Some(subject_digest.as_str())
        {
            return Some("release.binding.subject-manifest");
        }
        if json_member(fields, "governanceProfileSha256")
            .and_then(JsonValue::string)
            .ok()
            != Some(plan.governance_profile_sha256.as_str())
        {
            return Some("release.binding.governance-profile");
        }
    }
    let trusted_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    if super::native_environment::verify_set(
        &input.join("native-environment-set.json"),
        &trusted_root.join("ci/external-inputs.toml"),
    )
    .is_err()
    {
        return Some("release.binding.native-environment");
    }
    None
}

fn diagnose_evidence_bindings(
    input: &Path,
    plan: &ReleasePlan,
    conformance: &JsonValue,
) -> &'static str {
    if read_json(&input.join("conformance-report.json"))
        .and_then(|value| require_report_count_coverage(&value))
        .is_err()
    {
        return "release.ledger.forged-count";
    }
    let evidence = input.join("conformance-evidence.tar.gz");
    if let Some(diagnostic) = archive::evidence_diagnostic(&evidence, plan.source_date_epoch) {
        return diagnostic;
    }
    if evidence_case_binding_differs(&evidence, plan.source_date_epoch, conformance)
        .unwrap_or(false)
    {
        return "release.evidence.case";
    }
    if let Ok(Some(diagnostic)) = evidence_observation_diagnostic(&evidence, plan.source_date_epoch)
    {
        return diagnostic;
    }
    if let Ok(Some(diagnostic)) =
        evidence_ledger_inventory_diagnostic(&evidence, plan.source_date_epoch, conformance)
    {
        return diagnostic;
    }
    "release.primary-verifier-rejected"
}

fn classify_exemption_violation(
    conformance: &JsonValue,
    plan: &ReleasePlan,
) -> Result<Option<&'static str>, String> {
    let fields = conformance.object()?;
    let evaluation = json_member(fields, "releaseEvaluationInstant")?.string()?;
    let evaluation_date = evaluation
        .split_once('T')
        .ok_or_else(|| "conformance evaluation instant lacks date".to_owned())?
        .0;
    for cell in json_member(fields, "cells")?.array()? {
        let cell = cell.object()?;
        let exemptions = json_member(cell, "exemptions")?.array()?;
        if exemptions.is_empty() {
            continue;
        }
        if evaluation != plan.release_evaluation_instant {
            return Ok(Some("release.exemption.evaluation-instant"));
        }
        let exemption = exemptions[0].object()?;
        let obligation_id = json_member(exemption, "obligationId")?.string()?;
        let targets_obligation =
            json_member(cell, "obligations")?
                .array()?
                .iter()
                .any(|obligation| {
                    obligation
                        .object()
                        .ok()
                        .and_then(|fields| fields.get("id"))
                        .and_then(|value| value.string().ok())
                        == Some(obligation_id)
                });
        if json_member(exemption, "candidateSha")?.string()? != plan.resolution.candidate_sha
            || json_member(exemption, "standard")?.string()?
                != json_member(fields, "standard")?.string()?
            || json_member(exemption, "baseline")?.string()?
                != json_member(fields, "baseline")?.string()?
            || json_member(exemption, "cell")? != json_member(cell, "key")?
            || !targets_obligation
        {
            return Ok(Some("release.exemption.selector"));
        }
        if json_member(exemption, "expiresOn")?.string()? <= evaluation_date {
            return Ok(Some("release.exemption.expired"));
        }
    }
    Ok(None)
}

fn evidence_observation_diagnostic(
    archive_path: &Path,
    source_date_epoch: u64,
) -> Result<Option<&'static str>, String> {
    let members = archive::read_evidence(archive_path, source_date_epoch)?;
    for platform in ["linux-x86_64", "macos-aarch64", "windows-x86_64"] {
        let manifest_path = format!("platform-manifests/{platform}.json");
        let manifest = parse_canonical_member(
            members
                .get(&manifest_path)
                .ok_or_else(|| format!("evidence archive lacks {manifest_path}"))?,
        )?;
        let fields = manifest.object()?;
        let declared = json_member(fields, "observations")?
            .array()?
            .iter()
            .map(|member| {
                Ok(json_member(member.object()?, "sha256")?
                    .string()?
                    .to_owned())
            })
            .collect::<Result<BTreeSet<_>, String>>()?;
        let mut referenced = BTreeSet::new();
        for class in ["records", "exploratoryRecords"] {
            for member in json_member(fields, class)?.array()? {
                let id = json_member(member.object()?, "id")?.string()?;
                let record = parse_canonical_member(
                    members
                        .get(&format!("records/{id}.json"))
                        .ok_or_else(|| "evidence record is absent".to_owned())?,
                )?;
                for name in ["candidateObservationSha256", "oracleObservationSha256"] {
                    referenced.insert(json_member(record.object()?, name)?.string()?.to_owned());
                }
            }
        }
        if declared != referenced {
            return Ok(Some("release.evidence.unused"));
        }
        for digest in referenced {
            let observation = parse_canonical_member(
                members
                    .get(&format!("observations/{digest}.json"))
                    .ok_or_else(|| "evidence observation is absent".to_owned())?,
            )?;
            if json_member(observation.object()?, "diagnostic")?.string()?
                == "release-vector-contradictory-evidence"
            {
                return Ok(Some("release.evidence.contradictory"));
            }
        }
    }
    Ok(None)
}

fn evidence_ledger_inventory_diagnostic(
    archive_path: &Path,
    source_date_epoch: u64,
    conformance: &JsonValue,
) -> Result<Option<&'static str>, String> {
    let members = archive::read_evidence(archive_path, source_date_epoch)?;
    let mut targets = BTreeSet::new();
    let mut observed_count = 0_u64;
    for platform in ["linux-x86_64", "macos-aarch64", "windows-x86_64"] {
        let manifest_path = format!("platform-manifests/{platform}.json");
        let manifest_bytes = members
            .get(&manifest_path)
            .ok_or_else(|| format!("evidence archive lacks {manifest_path}"))?;
        let manifest = parse_canonical_member(manifest_bytes)?;
        for member in json_member(manifest.object()?, "records")?.array()? {
            let id = json_member(member.object()?, "id")?.string()?;
            let record = parse_canonical_member(
                members
                    .get(&format!("records/{id}.json"))
                    .ok_or_else(|| "manifest-declared evidence record is absent".to_owned())?,
            )?;
            let fields = record.object()?;
            let target = crate::json::canonical_json_bytes(&object([
                ("caseId", json_member(fields, "caseId")?.clone()),
                ("cellKey", json_member(fields, "cellKey")?.clone()),
                ("obligationId", json_member(fields, "obligationId")?.clone()),
            ]))?;
            if !targets.insert(target) {
                return Ok(Some("release.ledger.duplicate-cell"));
            }
            observed_count = observed_count
                .checked_add(1)
                .ok_or_else(|| "evidence record count overflow".to_owned())?;
        }
    }
    let mut expected_count = 0_u64;
    for cell in json_member(conformance.object()?, "cells")?.array()? {
        let cell = cell.object()?;
        let platform = json_member(json_member(cell, "key")?.object()?, "platform")?.string()?;
        for obligation in json_member(cell, "obligations")?.array()? {
            let obligation = obligation.object()?;
            let strategy = json_member(obligation, "strategy")?.string()?;
            let producer = match strategy {
                "native-oracle" | "committed-differential-corpus" => platform,
                "portable-static" | "structural-invariant" => "linux-x86_64",
                "cross-platform-relation" => continue,
                _ => return Err("unknown evidence strategy in conformance plan".to_owned()),
            };
            if !matches!(
                producer,
                "linux-x86_64" | "macos-aarch64" | "windows-x86_64"
            ) {
                return Err("evidence strategy producer is invalid".to_owned());
            }
            expected_count = expected_count
                .checked_add(
                    u64::try_from(json_member(obligation, "caseIds")?.array()?.len())
                        .map_err(|_| "evidence case count overflow".to_owned())?,
                )
                .ok_or_else(|| "expected evidence count overflow".to_owned())?;
        }
    }
    if observed_count < expected_count {
        return Ok(Some("release.ledger.missing-cell"));
    }
    Ok(None)
}

fn parse_canonical_member(bytes: &[u8]) -> Result<JsonValue, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "evidence JSON is not UTF-8".to_owned())?;
    let value = crate::json::parse_json(text)?;
    if canonical_json_bytes(&value)? != bytes {
        return Err("evidence JSON is not canonical".to_owned());
    }
    Ok(value)
}

fn evidence_case_binding_differs(
    archive_path: &Path,
    source_date_epoch: u64,
    conformance: &JsonValue,
) -> Result<bool, String> {
    let members = archive::read_evidence(archive_path, source_date_epoch)?;
    let conformance_fields = conformance.object()?;
    let planned_cells = json_member(conformance_fields, "cells")?.array()?;
    for (path, bytes) in &members {
        if !path.starts_with("records/ev-") {
            continue;
        }
        let text =
            std::str::from_utf8(bytes).map_err(|_| "evidence record is not UTF-8".to_owned())?;
        let record = crate::json::parse_json(text)?;
        let fields = record.object()?;
        let record_cell = json_member(fields, "cellKey")?;
        let obligation_id = json_member(fields, "obligationId")?.string()?;
        let case_id = json_member(fields, "caseId")?.string()?;
        let descriptor = json_member(fields, "descriptorSha256")?.string()?;
        let planned = planned_cells.iter().find(|cell| {
            cell.object().ok().and_then(|fields| fields.get("key")) == Some(record_cell)
        });
        let Some(planned) = planned else {
            return Ok(true);
        };
        let obligations = json_member(planned.object()?, "obligations")?.array()?;
        let planned_descriptor = obligations.iter().find_map(|obligation| {
            let fields = obligation.object().ok()?;
            (fields.get("id")?.string().ok()? == obligation_id)
                .then(|| fields.get("caseDescriptorSha256"))
                .flatten()
                .and_then(|value| value.object().ok())
                .and_then(|descriptors| descriptors.get(case_id))
                .and_then(|value| value.string().ok())
        });
        if planned_descriptor != Some(descriptor) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn require_report_count_coverage(value: &JsonValue) -> Result<(), String> {
    let fields = value.object()?;
    let partition = json_member(fields, "partition")?.object()?;
    let mut total = 0_u64;
    for name in [
        "blockedInvalidEvidence",
        "blockedMismatch",
        "blockedMissingEvidence",
        "excluded",
        "exempted",
        "notApplicable",
        "verifiedExact",
        "verifiedNormalized",
        "verifiedPlatformEquivalent",
    ] {
        total = total
            .checked_add(json_member(partition, name)?.number()?)
            .ok_or_else(|| "conformance report count overflow".to_owned())?;
    }
    let cells = u64::try_from(json_member(fields, "cells")?.array()?.len())
        .map_err(|_| "conformance report cell count overflow".to_owned())?;
    if total != cells {
        return Err("conformance report counts do not cover cells".to_owned());
    }
    Ok(())
}

pub(crate) fn publication_bundle(
    plan_path: PathBuf,
    input: PathBuf,
    report: PathBuf,
) -> Result<String, String> {
    let plan_path = plan_path.into_boxed_path();
    let input = input.into_boxed_path();
    let report = report.into_boxed_path();
    verify_bundle(&BundleVerification {
        plan_path: &plan_path,
        external_conformance_plan: None,
        input: &input,
        report: &report,
        decision_output: None,
        protocol_sha256: None,
        governance_receipts: None,
        kind: BundleKind::Publication,
    })
}

struct BundleVerification<'a> {
    plan_path: &'a Path,
    external_conformance_plan: Option<&'a Path>,
    input: &'a Path,
    report: &'a Path,
    decision_output: Option<&'a Path>,
    protocol_sha256: Option<&'a str>,
    governance_receipts: Option<&'a GovernanceReceiptDigests>,
    kind: BundleKind,
}

fn verify_bundle(options: &BundleVerification<'_>) -> Result<String, String> {
    let report = options.report;
    let decision_output = options.decision_output;
    let protocol_sha256 = options.protocol_sha256;
    let governance_receipts = options.governance_receipts;
    let inventory = verify_bundle_inventory(options)?;
    let plan = &inventory.plan;
    let conformance = &inventory.conformance;
    let subjects_bytes = &inventory.subjects_bytes;

    let BundleReconstruction {
        acceptance: reconstructed_acceptance,
        obligation_rules_sha256,
        native_environment_set_sha256,
        cell_ledger_bytes,
        release_gate_sha256,
    } = reconstruct_bundle(options, &inventory)?;
    if let Some(path) = decision_output {
        let governance_receipts = governance_receipts
            .ok_or_else(|| "primary decision requires bound governance receipts".to_owned())?;
        let required_cell_count = reconstructed_acceptance
            .counts
            .verified()
            .checked_add(reconstructed_acceptance.counts.exempted)
            .and_then(|count| count.checked_add(reconstructed_acceptance.counts.blocked()))
            .ok_or_else(|| "primary verifier required cell count overflow".to_owned())?;
        let decision = VerifierDecision {
            implementation: "hell-ci".to_owned(),
            protocol_version: super::decision::ADMISSION_PROTOCOL_VERSION.to_owned(),
            protocol_sha256: protocol_sha256
                .ok_or_else(|| "primary decision requires bound protocol inputs".to_owned())?
                .to_owned(),
            candidate_sha: plan.resolution.candidate_sha.clone(),
            workflow_sha: plan.resolution.workflow_sha.clone(),
            release_plan_sha256: plan.plan_sha256.clone(),
            conformance_plan_sha256: conformance.plan_sha256.clone(),
            source_inventory_sha256: plan.source_inventory_sha256.clone(),
            trusted_inputs_sha256: plan.trusted_conformance_inputs_sha256.clone(),
            obligation_rules_sha256,
            governance_declaration_sha256: plan.governance_declaration_sha256.clone(),
            governance_profile_sha256: plan.governance_profile_sha256.clone(),
            governance_resolve_sha256: governance_receipts.resolve.clone(),
            governance_post_assembly_sha256: governance_receipts.post_assembly.clone(),
            governance_pre_attestation_sha256: governance_receipts.pre_attestation.clone(),
            residual_assumption_set_sha256: plan.residual_assumption_set_sha256.clone(),
            external_inputs_sha256: plan.external_inputs_sha256.clone(),
            native_environment_set_sha256,
            cell_ledger_sha256: super::decision::domain_digest(
                "cell-ledger",
                1,
                &cell_ledger_bytes,
            ),
            subject_manifest_sha256: hell_testkit::sha256_bytes(subjects_bytes).hex(),
            release_gate_sha256,
            required_cell_count,
            verified_cell_count: reconstructed_acceptance.counts.verified(),
            exempted_cell_count: reconstructed_acceptance.counts.exempted,
            blocked_cell_count: reconstructed_acceptance.counts.blocked(),
            admitted: reconstructed_acceptance.admitted,
        };
        if path.exists() {
            return Err("primary verifier decision output already exists".to_owned());
        }
        write_json(path, &decision.json())?;
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

struct VerifiedBundleInventory {
    plan: ReleasePlan,
    conformance: crate::conformance::ConformancePlan,
    bundled_plan_bytes: Vec<u8>,
    subjects_bytes: Vec<u8>,
    packaged_executables: BTreeMap<crate::conformance::ConformancePlatform, String>,
}

struct VerifiedEvidenceArchive {
    evidence_sha256: String,
    members: BTreeMap<String, Vec<u8>>,
    manifests: Vec<crate::conformance::EvidenceManifest>,
}

fn verify_evidence_archive(
    input: &Path,
    inventory: &VerifiedBundleInventory,
) -> Result<VerifiedEvidenceArchive, String> {
    let evidence_path = input.join("conformance-evidence.tar.gz");
    let evidence_bytes = read_regular(&evidence_path)?;
    let evidence_sha256 = hell_testkit::sha256_bytes(&evidence_bytes).hex();
    let members = archive::read_evidence(&evidence_path, inventory.plan.source_date_epoch)?;
    if members.get("conformance-plan.json") != Some(&inventory.bundled_plan_bytes) {
        return Err("evidence archive conformance plan differs from bundle".to_owned());
    }
    let retained_inventory = members
        .get("source-inventory.json")
        .ok_or_else(|| "evidence archive lacks source inventory".to_owned())?;
    if hell_testkit::sha256_bytes(retained_inventory).hex()
        != inventory.plan.source_inventory_sha256
    {
        return Err("evidence source inventory differs from release plan".to_owned());
    }
    let trusted_value = parse_member_json(&members, "trusted-conformance-inputs.json")?;
    let trusted = crate::conformance::parse_trusted_inputs(&trusted_value)?;
    if trusted.aggregate_sha256 != inventory.conformance.trusted_inputs_sha256 {
        return Err("evidence archive trusted inputs differ from conformance plan".to_owned());
    }
    let trusted_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let rebuilt = crate::conformance::build_trusted_inputs(
        &trusted_root,
        &trusted_root,
        &inventory.plan.resolution.workflow_sha,
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
        if inventory.packaged_executables.get(&platform)
            != Some(&manifest.candidate_executable_sha256)
        {
            return Err("packaged executable differs from evidence manifest identity".to_owned());
        }
        manifests.push(manifest);
    }
    Ok(VerifiedEvidenceArchive {
        evidence_sha256,
        members,
        manifests,
    })
}

struct BundleReconstruction {
    acceptance: crate::conformance::ConformanceAcceptance,
    obligation_rules_sha256: String,
    native_environment_set_sha256: String,
    cell_ledger_bytes: Vec<u8>,
    release_gate_sha256: String,
}

fn reconstruct_bundle(
    options: &BundleVerification<'_>,
    inventory: &VerifiedBundleInventory,
) -> Result<BundleReconstruction, String> {
    let evidence = verify_evidence_archive(options.input, inventory)?;
    let bindings = crate::conformance::TrustedEvidenceBindings::from_manifests(
        &inventory.conformance,
        &evidence.manifests,
    )?;
    let repository = crate::conformance::EvidenceRepository::from_archive_members(
        &evidence.manifests,
        &evidence.members,
        &bindings,
        &inventory.conformance,
    )?;
    let partition = crate::conformance::independently_reconstruct_partition(
        &inventory.conformance,
        &crate::conformance::canonical_universe()?,
        &repository,
        &bindings,
    )?;
    let report = crate::conformance::conformance_report(
        &inventory.conformance,
        &partition,
        &evidence.evidence_sha256,
    )?;
    if canonical_json_bytes(&report)?
        != read_regular(&options.input.join("conformance-report.json"))?
    {
        return Err("conformance report differs from independent reconstruction".to_owned());
    }
    let report_sha256 = json_member(report.object()?, "reportSha256")?
        .string()?
        .to_owned();
    let acceptance = crate::conformance::ConformanceAcceptance::derive(
        &inventory.conformance,
        &partition,
        evidence.evidence_sha256.clone(),
        report_sha256.clone(),
    )?;
    verify_reconstructed_outputs(options.input, inventory, &acceptance)?;
    let trusted_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let native_environment_set_sha256 = super::native_environment::verify_set(
        &options.input.join("native-environment-set.json"),
        &trusted_root.join("ci/external-inputs.toml"),
    )?;
    verify_release_manifest(
        options.input,
        &inventory.conformance,
        &acceptance,
        required_cell_count(&inventory.conformance)?,
        &evidence.evidence_sha256,
        &report_sha256,
        &native_environment_set_sha256,
    )?;
    verify_release_gate(
        options.input,
        &inventory.plan,
        &inventory.conformance,
        &acceptance,
        &evidence.evidence_sha256,
        &report_sha256,
        &native_environment_set_sha256,
    )?;
    let obligation_rules_sha256 = hell_testkit::sha256_bytes(&canonical_json_bytes(&read_json(
        &trusted_root.join("compat/release-obligation-rules-v1.json"),
    )?)?)
    .hex();
    let cell_ledger_bytes = canonical_json_bytes(json_member(report.object()?, "cells")?)?;
    let release_gate = read_json(&options.input.join("release-gate.json"))?;
    let release_gate_sha256 = json_member(release_gate.object()?, "releaseGateSha256")?
        .string()?
        .to_owned();
    Ok(BundleReconstruction {
        acceptance,
        obligation_rules_sha256,
        native_environment_set_sha256,
        cell_ledger_bytes,
        release_gate_sha256,
    })
}

fn required_cell_count(conformance: &crate::conformance::ConformancePlan) -> Result<u64, String> {
    u64::try_from(
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
    .map_err(|_| "required cell count overflow".to_owned())
}

fn verify_reconstructed_outputs(
    input: &Path,
    inventory: &VerifiedBundleInventory,
    acceptance: &crate::conformance::ConformanceAcceptance,
) -> Result<(), String> {
    let producer_acceptance = crate::conformance::ConformanceAcceptance::parse(&read_json(
        &input.join("conformance-acceptance.json"),
    )?)?;
    if !acceptance_bytes_match(
        &canonical_json_bytes(&producer_acceptance.json())?,
        &canonical_json_bytes(&acceptance.json())?,
    ) {
        return Err("producer acceptance differs from independent reconstruction".to_owned());
    }
    if !acceptance.admitted {
        return Err("publisher independently reconstructed a blocking partition".to_owned());
    }
    let required = required_cell_count(&inventory.conformance)?;
    let expected_html = super::assemble::conformance_html(&inventory.plan, acceptance, required);
    if read_regular(&input.join("conformance-report.html"))? != expected_html.as_bytes() {
        return Err("conformance HTML differs from trusted static rendering".to_owned());
    }
    let expected_notes = super::assemble::release_notes(&inventory.plan, acceptance, required);
    if read_regular(&input.join("release-notes.md"))? != expected_notes.as_bytes() {
        return Err("release notes differ from reconstructed partition".to_owned());
    }
    Ok(())
}

fn verify_bundle_inventory(
    options: &BundleVerification<'_>,
) -> Result<VerifiedBundleInventory, String> {
    let plan = ReleasePlan::parse(&read_json(options.plan_path)?)?;
    require_real_directory(options.input)?;
    let bundled_plan_bytes = read_regular(&options.input.join("conformance-plan.json"))?;
    if let Some(path) = options.external_conformance_plan
        && !conformance_plan_bytes_match(&read_regular(path)?, &bundled_plan_bytes)
    {
        return Err("bundled conformance plan differs from trusted plan artifact".to_owned());
    }
    let conformance = crate::conformance::ConformancePlan::parse(&read_json(
        &options.input.join("conformance-plan.json"),
    )?)?;
    super::assemble::validate_conformance_binding(&plan, &conformance)?;
    let required_subjects = required_subjects(&plan);
    let subjects_bytes = read_regular(&options.input.join("SUBJECTS.sha256"))?;
    let subjects = parse_subjects(&subjects_bytes)?;
    validate_subject_inventory(&subjects, &required_subjects)?;
    let mut top_level = required_subjects.clone();
    top_level.insert("SUBJECTS.sha256".to_owned());
    top_level.insert("release-gate.json".to_owned());
    if options.kind == BundleKind::Publication {
        top_level.extend(ATTESTATIONS.iter().map(|name| (*name).to_owned()));
    }
    if directory_entries(options.input)? != top_level {
        return Err("release bundle top-level exact set differs".to_owned());
    }
    for name in &top_level {
        require_real_file(&options.input.join(name))?;
    }
    for (name, digest) in &subjects {
        if hell_testkit::sha256_bytes(&read_regular(&options.input.join(name))?).hex() != *digest {
            return Err(format!("release subject {name} digest differs"));
        }
    }
    let mut packaged_executables = BTreeMap::new();
    for platform in PLATFORMS {
        let archive_path =
            options
                .input
                .join(format!("hell-v{}-{}.tar.gz", plan.version, platform.id()));
        archive::verify(
            &archive_path,
            platform,
            &plan.version,
            plan.source_date_epoch,
        )?;
        let extraction_root = options
            .report
            .with_file_name(format!(".publisher-extract-{}", platform.id()));
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
    verify_dependency_subject(options.input, &plan)?;
    super::assemble::verify_mutation_report(&options.input.join("mutation-report.json"), &plan)?;
    Ok(VerifiedBundleInventory {
        plan,
        conformance,
        bundled_plan_bytes,
        subjects_bytes,
        packaged_executables,
    })
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
        "native-environment-set.json".to_owned(),
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
    conformance: &crate::conformance::ConformancePlan,
    acceptance: &crate::conformance::ConformanceAcceptance,
    required: u64,
    evidence_sha256: &str,
    report_sha256: &str,
    native_environment_set_sha256: &str,
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
            "nativeEnvironmentSetSha256",
            string(native_environment_set_sha256),
        ),
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
    native_environment_set_sha256: &str,
) -> Result<(), String> {
    let subjects_bytes = read_regular(&input.join("SUBJECTS.sha256"))?;
    let gate = read_json(&input.join("release-gate.json"))?;
    fuzz_parse_release_gate(&gate)?;
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
            "externalInputsSha256",
            "governanceDeclarationSha256",
            "governanceProfileSha256",
            "nativeEnvironmentSetSha256",
            "releaseGateSha256",
            "releasePlanSha256",
            "repository",
            "residualAssumptionSetSha256",
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
        || json_member(fields, "externalInputsSha256")?.string()? != plan.external_inputs_sha256
        || json_member(fields, "governanceDeclarationSha256")?.string()?
            != plan.governance_declaration_sha256
        || json_member(fields, "governanceProfileSha256")?.string()?
            != plan.governance_profile_sha256
        || json_member(fields, "residualAssumptionSetSha256")?.string()?
            != plan.residual_assumption_set_sha256
        || json_member(fields, "nativeEnvironmentSetSha256")?.string()?
            != native_environment_set_sha256
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

pub(crate) fn fuzz_parse_release_gate(gate: &JsonValue) -> Result<(), String> {
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
            "externalInputsSha256",
            "governanceDeclarationSha256",
            "governanceProfileSha256",
            "nativeEnvironmentSetSha256",
            "releaseGateSha256",
            "releasePlanSha256",
            "repository",
            "residualAssumptionSetSha256",
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
    if json_member(fields, "schemaVersion")?.number()? != 2
        || json_member(fields, "state")?.string()? != "admitted"
        || json_member(fields, "candidateCodeExecutedInPublisher")?.boolean()?
    {
        return Err("release gate state or schema is invalid".to_owned());
    }
    super::schema::require_sha(
        json_member(fields, "candidateSha")?.string()?,
        "candidate SHA",
    )?;
    super::schema::require_sha(
        json_member(fields, "workflowSha")?.string()?,
        "workflow SHA",
    )?;
    for name in [
        "conformanceAcceptanceSha256",
        "conformanceEvidenceSha256",
        "conformancePlanSha256",
        "conformanceReportSha256",
        "externalInputsSha256",
        "governanceDeclarationSha256",
        "governanceProfileSha256",
        "nativeEnvironmentSetSha256",
        "releaseGateSha256",
        "releasePlanSha256",
        "residualAssumptionSetSha256",
        "subjectsSha256",
    ] {
        super::schema::require_digest(json_member(fields, name)?.string()?, name)?;
    }
    for name in ["conformanceStandard", "repository", "tag", "version"] {
        if json_member(fields, name)?.string()?.is_empty() {
            return Err(format!("release gate field {name} is empty"));
        }
    }
    json_member(fields, "runId")?.number()?;
    json_member(fields, "runAttempt")?.number()?;
    let counts = json_member(fields, "conformanceCounts")?.object()?;
    require_exact_json_keys(
        counts,
        &[
            "blocked",
            "excluded",
            "exempted",
            "notApplicable",
            "unclassifiedMismatches",
            "verified",
        ],
    )?;
    for value in counts.values() {
        value.number()?;
    }
    let stated = json_member(fields, "releaseGateSha256")?.string()?;
    let mut without = fields.clone();
    without.remove("releaseGateSha256");
    if stated
        != hell_testkit::sha256_bytes(&canonical_json_bytes(&JsonValue::Object(without))?).hex()
    {
        return Err("release gate self-digest mismatch".to_owned());
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

fn validate_subject_inventory(
    subjects: &BTreeMap<String, String>,
    required: &BTreeSet<String>,
) -> Result<(), String> {
    if !crate::mutation::active("ignore-subject")
        && subjects.keys().cloned().collect::<BTreeSet<_>>() != *required
    {
        return Err("SUBJECTS.sha256 exact set differs".to_owned());
    }
    Ok(())
}

pub(crate) fn assurance_omitted_subject() -> Result<(), String> {
    let retained = "hell-linux.tar.gz";
    let omitted = "hell-windows.zip";
    let retained_digest = hell_testkit::sha256_bytes(b"retained subject bytes").hex();
    let subjects = parse_subjects(format!("{retained_digest}  {retained}\n").as_bytes())?;
    validate_subject_inventory(
        &subjects,
        &BTreeSet::from([retained.to_owned(), omitted.to_owned()]),
    )
}

pub(crate) fn fuzz_parse_subjects(bytes: &[u8]) -> Result<(), String> {
    parse_subjects(bytes).map(|_| ())
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
        .map_err(|error| format!("cannot inspect directory {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "release bundle path is not a real directory: {}",
            path.display()
        ));
    }
    Ok(())
}

fn require_real_file(path: &Path) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect file {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "release bundle path is not a real file: {}",
            path.display()
        ));
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
            governance_declaration_sha256: "4".repeat(64),
            governance_profile_sha256: "5".repeat(64),
            residual_assumption_set_sha256: "6".repeat(64),
            external_inputs_sha256: "7".repeat(64),
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
