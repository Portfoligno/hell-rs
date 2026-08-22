use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::json::{JsonValue, canonical_json_bytes, json_member, require_exact_json_keys};

use super::archive;
use super::manifest::{read_json, read_regular, write_atomic, write_json};
use super::schema::{
    PLATFORMS, ReleasePlan, ReleasePlatform, expected_gates, number, object, string,
};
use super::verify;

pub(crate) fn run(
    plan_path: PathBuf,
    conformance_plan_path: PathBuf,
    input: PathBuf,
    output: PathBuf,
    report: PathBuf,
) -> Result<String, String> {
    run_with_verification(plan_path, conformance_plan_path, input, output, report)
}

pub(crate) fn run_readiness(
    plan_path: PathBuf,
    conformance_plan_path: PathBuf,
    input: PathBuf,
    output: PathBuf,
    report: PathBuf,
) -> Result<String, String> {
    run_with_verification(plan_path, conformance_plan_path, input, output, report)
}

fn run_with_verification(
    plan_path: PathBuf,
    conformance_plan_path: PathBuf,
    input: PathBuf,
    output: PathBuf,
    report: PathBuf,
) -> Result<String, String> {
    let input = input.into_boxed_path();
    let report = report.into_boxed_path();
    let AssemblyInputs {
        plan,
        conformance_plan,
        trusted_input_bytes,
        source_inventory_bytes,
    } = load_assembly_inputs(&plan_path, &conformance_plan_path)?;
    if output.exists() {
        return Err("release bundle output already exists".to_owned());
    }
    require_platform_roots(&input)?;
    let native_environment = assemble_native_environment_set(&input, &report, &plan)?;

    let evidence_members = BTreeMap::from([
        (
            "conformance-plan.json".to_owned(),
            read_regular(&conformance_plan_path)?,
        ),
        (
            "trusted-conformance-inputs.json".to_owned(),
            trusted_input_bytes,
        ),
        (
            "source-inventory.json".to_owned(),
            source_inventory_bytes.clone(),
        ),
    ]);
    let platform_evidence = collect_platform_evidence(
        &input,
        &report,
        &plan,
        &conformance_plan,
        &source_inventory_bytes,
        evidence_members,
    )?;
    let artifacts =
        derive_conformance_artifacts(&report, &plan, &conformance_plan, platform_evidence)?;
    let mut bundle = install_conformance_subjects(
        &output,
        &input,
        &conformance_plan_path,
        &plan,
        &conformance_plan,
        native_environment,
        artifacts,
    )?;
    write_release_metadata(&output, &plan, &conformance_plan, &mut bundle)?;

    let verification_report = report.with_file_name("release-assembly-verification.json");
    verify::technical_bundle(
        plan_path,
        conformance_plan_path,
        output,
        verification_report,
    )?;
    Ok("assembled independently admitted three-platform release bundle".to_owned())
}

struct ConformanceArtifacts {
    report: JsonValue,
    acceptance: crate::conformance::ConformanceAcceptance,
    evidence_bytes: Vec<u8>,
    evidence_sha256: String,
    report_sha256: String,
    archives: BTreeMap<String, Vec<u8>>,
}

fn derive_conformance_artifacts(
    report_path: &Path,
    plan: &ReleasePlan,
    conformance_plan: &crate::conformance::ConformancePlan,
    evidence: PlatformEvidence,
) -> Result<ConformanceArtifacts, String> {
    let bindings = crate::conformance::TrustedEvidenceBindings::from_manifests(
        conformance_plan,
        &evidence.manifests,
    )?;
    let evidence_path =
        report_path.with_file_name(format!(".conformance-evidence-{}.tar.gz", plan.plan_sha256));
    if evidence_path.exists() {
        return Err("assembly evidence staging path already exists".to_owned());
    }
    let evidence_sha256 = archive::create_evidence(
        &evidence_path,
        plan.source_date_epoch,
        &evidence.evidence_members,
    )?;
    let reparsed_members = archive::read_evidence(&evidence_path, plan.source_date_epoch)?;
    let repository = crate::conformance::EvidenceRepository::from_archive_members(
        &evidence.manifests,
        &reparsed_members,
        &bindings,
        conformance_plan,
    )?;
    let partition = crate::conformance::derive_partition(
        conformance_plan,
        &crate::conformance::canonical_universe()?,
        &repository,
        &bindings,
    )?;
    let report =
        crate::conformance::conformance_report(conformance_plan, &partition, &evidence_sha256)?;
    let report_sha256 = json_member(report.object()?, "reportSha256")?
        .string()?
        .to_owned();
    let acceptance = crate::conformance::ConformanceAcceptance::derive(
        conformance_plan,
        &partition,
        evidence_sha256.clone(),
        report_sha256.clone(),
    )?;
    write_json(report_path, &report)?;
    if !acceptance.admitted {
        fs::remove_file(&evidence_path)
            .map_err(|error| format!("cannot remove blocked evidence staging file: {error}"))?;
        return Err("conformance partition contains blocking or unclassified cells".to_owned());
    }
    let evidence_bytes = read_regular(&evidence_path)?;
    fs::remove_file(&evidence_path)
        .map_err(|error| format!("cannot remove evidence staging file: {error}"))?;
    Ok(ConformanceArtifacts {
        report,
        acceptance,
        evidence_bytes,
        evidence_sha256,
        report_sha256,
        archives: evidence.archives,
    })
}

struct InstalledBundle {
    subjects: BTreeMap<String, String>,
    acceptance: crate::conformance::ConformanceAcceptance,
    required_cells: u64,
    evidence_sha256: String,
    report_sha256: String,
    native_environment_sha256: String,
}

fn install_conformance_subjects(
    output: &Path,
    input: &Path,
    conformance_plan_path: &Path,
    plan: &ReleasePlan,
    conformance_plan: &crate::conformance::ConformancePlan,
    native_environment: NativeEnvironmentAssembly,
    artifacts: ConformanceArtifacts,
) -> Result<InstalledBundle, String> {
    fs::create_dir(output)
        .map_err(|error| format!("cannot create exact release bundle: {error}"))?;
    let mut subjects = BTreeMap::new();
    for (name, bytes) in artifacts.archives {
        install_subject(output, &mut subjects, &name, &bytes)?;
    }
    install_subject(
        output,
        &mut subjects,
        "conformance-plan.json",
        &read_regular(conformance_plan_path)?,
    )?;
    install_subject(
        output,
        &mut subjects,
        "conformance-report.json",
        &canonical_json_bytes(&artifacts.report)?,
    )?;
    let required_cells = conformance_plan
        .cells
        .iter()
        .filter(|cell| {
            matches!(
                cell.scope,
                crate::conformance::ScopeDisposition::Required { .. }
            )
        })
        .count();
    let required_cells =
        u64::try_from(required_cells).map_err(|_| "required cell count overflow")?;
    let counts = &artifacts.acceptance.counts;
    if counts.verified().saturating_add(counts.exempted) != required_cells || counts.blocked() != 0
    {
        return Err("admitted partition does not cover every required cell".to_owned());
    }
    let html = conformance_html(plan, &artifacts.acceptance, required_cells);
    install_subject(
        output,
        &mut subjects,
        "conformance-report.html",
        html.as_bytes(),
    )?;
    install_subject(
        output,
        &mut subjects,
        "conformance-acceptance.json",
        &canonical_json_bytes(&artifacts.acceptance.json())?,
    )?;
    install_subject(
        output,
        &mut subjects,
        "conformance-evidence.tar.gz",
        &artifacts.evidence_bytes,
    )?;
    install_subject(
        output,
        &mut subjects,
        "native-environment-set.json",
        &read_regular(&native_environment.path)?,
    )?;
    fs::remove_file(&native_environment.path)
        .map_err(|error| format!("cannot clean native environment set staging: {error}"))?;
    for name in ["dependency-policy.json", "mutation-report.json"] {
        let bytes = read_regular(&input.join(ReleasePlatform::LinuxX86_64.id()).join(name))?;
        install_subject(output, &mut subjects, name, &bytes)?;
    }
    verify_mutation_report(&output.join("mutation-report.json"), plan)?;
    Ok(InstalledBundle {
        subjects,
        acceptance: artifacts.acceptance,
        required_cells,
        evidence_sha256: artifacts.evidence_sha256,
        report_sha256: artifacts.report_sha256,
        native_environment_sha256: native_environment.sha256,
    })
}

fn write_release_metadata(
    output: &Path,
    plan: &ReleasePlan,
    conformance_plan: &crate::conformance::ConformancePlan,
    bundle: &mut InstalledBundle,
) -> Result<(), String> {
    let acceptance_sha256 = bundle.acceptance.decision_sha256.clone();
    let conformance = conformance_summary(
        conformance_plan,
        &bundle.acceptance,
        bundle.required_cells,
        &bundle.evidence_sha256,
        &bundle.report_sha256,
        &acceptance_sha256,
    );
    let release_manifest = object([
        ("candidateCodeExecutedInPublisher", JsonValue::Bool(false)),
        ("conformance", conformance),
        ("externalCustody", JsonValue::Bool(false)),
        ("githubArtifactAttestations", JsonValue::Bool(true)),
        ("githubImmutableReleaseRequired", JsonValue::Bool(true)),
        ("independentProviderAcquisition", JsonValue::Bool(false)),
        (
            "nativeEnvironmentSetSha256",
            string(&bundle.native_environment_sha256),
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
    install_subject(
        output,
        &mut bundle.subjects,
        "release-manifest.json",
        &canonical_json_bytes(&release_manifest)?,
    )?;
    let notes = release_notes(plan, &bundle.acceptance, bundle.required_cells);
    install_subject(
        output,
        &mut bundle.subjects,
        "release-notes.md",
        notes.as_bytes(),
    )?;
    let mut subject_text = String::new();
    for (name, digest) in &bundle.subjects {
        subject_text.push_str(digest);
        subject_text.push_str("  ");
        subject_text.push_str(name);
        subject_text.push('\n');
    }
    write_atomic(&output.join("SUBJECTS.sha256"), subject_text.as_bytes())?;
    let subjects_sha256 = hell_testkit::sha256_bytes(subject_text.as_bytes()).hex();
    write_release_gate(
        output,
        plan,
        conformance_plan,
        bundle,
        &acceptance_sha256,
        &subjects_sha256,
    )
}

fn write_release_gate(
    output: &Path,
    plan: &ReleasePlan,
    conformance_plan: &crate::conformance::ConformancePlan,
    bundle: &InstalledBundle,
    acceptance_sha256: &str,
    subjects_sha256: &str,
) -> Result<(), String> {
    let gate_without_digest = object([
        ("candidateCodeExecutedInPublisher", JsonValue::Bool(false)),
        ("candidateSha", string(&plan.resolution.candidate_sha)),
        ("conformanceAcceptanceSha256", string(acceptance_sha256)),
        ("conformanceCounts", gate_counts(&bundle.acceptance)),
        ("conformanceEvidenceSha256", string(&bundle.evidence_sha256)),
        (
            "conformancePlanSha256",
            string(&conformance_plan.plan_sha256),
        ),
        ("conformanceReportSha256", string(&bundle.report_sha256)),
        ("conformanceStandard", string(&conformance_plan.standard)),
        ("externalInputsSha256", string(&plan.external_inputs_sha256)),
        (
            "governanceDeclarationSha256",
            string(&plan.governance_declaration_sha256),
        ),
        (
            "governanceProfileSha256",
            string(&plan.governance_profile_sha256),
        ),
        (
            "nativeEnvironmentSetSha256",
            string(&bundle.native_environment_sha256),
        ),
        ("releasePlanSha256", string(&plan.plan_sha256)),
        ("repository", string(&plan.resolution.repository)),
        (
            "residualAssumptionSetSha256",
            string(&plan.residual_assumption_set_sha256),
        ),
        ("runAttempt", number(plan.resolution.run_attempt)),
        ("runId", number(plan.resolution.run_id)),
        ("schemaVersion", number(2)),
        ("state", string("admitted")),
        ("subjectsSha256", string(subjects_sha256)),
        ("tag", string(&plan.tag)),
        ("version", string(&plan.version)),
        ("workflowSha", string(&plan.resolution.workflow_sha)),
    ]);
    let gate_sha256 =
        hell_testkit::sha256_bytes(&canonical_json_bytes(&gate_without_digest)?).hex();
    let mut gate_fields = gate_without_digest.object()?.clone();
    gate_fields.insert("releaseGateSha256".to_owned(), string(&gate_sha256));
    write_json(
        &output.join("release-gate.json"),
        &JsonValue::Object(gate_fields),
    )?;
    Ok(())
}

struct AssemblyInputs {
    plan: ReleasePlan,
    conformance_plan: crate::conformance::ConformancePlan,
    trusted_input_bytes: Vec<u8>,
    source_inventory_bytes: Vec<u8>,
}

fn load_assembly_inputs(
    plan_path: &Path,
    conformance_plan_path: &Path,
) -> Result<AssemblyInputs, String> {
    let plan = ReleasePlan::parse(&read_json(plan_path)?)?;
    let conformance_plan =
        crate::conformance::ConformancePlan::parse(&read_json(conformance_plan_path)?)?;
    validate_conformance_binding(&plan, &conformance_plan)?;
    let artifact_root = conformance_plan_path
        .parent()
        .ok_or_else(|| "conformance plan has no artifact root".to_owned())?;
    let trusted_input_path = artifact_root.join("trusted-conformance-inputs.json");
    let trusted_input_bytes = read_regular(&trusted_input_path)?;
    let source_inventory_bytes = read_regular(&artifact_root.join("source-inventory.json"))?;
    if hell_testkit::sha256_bytes(&source_inventory_bytes).hex() != plan.source_inventory_sha256 {
        return Err("plan artifact source inventory digest differs".to_owned());
    }
    let trusted_inputs =
        crate::conformance::parse_trusted_inputs(&read_json(&trusted_input_path)?)?;
    if trusted_inputs.aggregate_sha256 != plan.trusted_conformance_inputs_sha256 {
        return Err("trusted conformance input digest differs from release plan".to_owned());
    }
    let trusted_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let rebuilt = crate::conformance::build_trusted_inputs(
        &trusted_root,
        &trusted_root,
        &plan.resolution.workflow_sha,
    )?;
    if canonical_json_bytes(&rebuilt.manifest)? != trusted_input_bytes {
        return Err("plan artifact trusted inputs differ from assembly checkout".to_owned());
    }
    Ok(AssemblyInputs {
        plan,
        conformance_plan,
        trusted_input_bytes,
        source_inventory_bytes,
    })
}

struct NativeEnvironmentAssembly {
    path: PathBuf,
    sha256: String,
}

fn assemble_native_environment_set(
    input: &Path,
    report: &Path,
    plan: &ReleasePlan,
) -> Result<NativeEnvironmentAssembly, String> {
    let trusted_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let receipt_staging =
        report.with_file_name(format!(".native-environment-receipts-{}", plan.plan_sha256));
    let set_staging =
        report.with_file_name(format!(".native-environment-set-{}.json", plan.plan_sha256));
    if receipt_staging.exists() || set_staging.exists() {
        return Err("native environment assembly staging already exists".to_owned());
    }
    fs::create_dir(&receipt_staging)
        .map_err(|error| format!("cannot create native environment staging: {error}"))?;
    for platform in PLATFORMS {
        let platform_staging = receipt_staging.join(platform.id());
        fs::create_dir(&platform_staging).map_err(|error| {
            format!("cannot create native environment platform staging: {error}")
        })?;
        write_atomic(
            &platform_staging.join("native-environment.json"),
            &read_regular(&input.join(platform.id()).join("native-environment.json"))?,
        )?;
    }
    let external_inputs = trusted_root.join("ci/external-inputs.toml");
    super::native_environment::assemble_set(&receipt_staging, &external_inputs, &set_staging)?;
    let sha256 = super::native_environment::verify_set(&set_staging, &external_inputs)?;
    fs::remove_dir_all(&receipt_staging)
        .map_err(|error| format!("cannot clean native environment receipt staging: {error}"))?;
    Ok(NativeEnvironmentAssembly {
        path: set_staging,
        sha256,
    })
}

struct PlatformEvidence {
    evidence_members: BTreeMap<String, Vec<u8>>,
    manifests: Vec<crate::conformance::EvidenceManifest>,
    archives: BTreeMap<String, Vec<u8>>,
}

fn collect_platform_evidence(
    input: &Path,
    report: &Path,
    plan: &ReleasePlan,
    conformance_plan: &crate::conformance::ConformancePlan,
    source_inventory_bytes: &[u8],
    mut evidence_members: BTreeMap<String, Vec<u8>>,
) -> Result<PlatformEvidence, String> {
    let mut manifests = Vec::new();
    let mut archives = BTreeMap::new();
    for platform in PLATFORMS {
        let root = input.join(platform.id());
        verify_platform_inventory(&root, platform, &plan.version)?;
        if read_regular(&root.join("source-inventory.json"))? != source_inventory_bytes {
            return Err(format!(
                "{} source inventory differs from trusted plan artifact",
                platform.id()
            ));
        }
        let report_value = verify_platform_report(
            &root.join("platform-report.json"),
            plan,
            conformance_plan,
            platform,
        )?;
        let manifest_path = root.join("conformance-evidence-manifest.json");
        let manifest_bytes = read_regular(&manifest_path)?;
        let manifest = crate::conformance::EvidenceManifest::parse(&read_json(&manifest_path)?)?;
        validate_platform_manifest(&manifest, plan, conformance_plan, platform)?;
        copy_manifest_members(&root, &manifest, &mut evidence_members)?;
        evidence_members.insert(
            format!("platform-manifests/{}.json", platform.id()),
            manifest_bytes,
        );
        require_report_manifest_identity(&report_value, &manifest, &root, platform)?;
        let archive_name = format!("hell-v{}-{}.tar.gz", plan.version, platform.id());
        let bytes =
            verify_platform_archive(report, plan, platform, &root, &archive_name, &manifest)?;
        let report_fields = report_value.object()?;
        if json_member(report_fields, "archiveSha256")?.string()?
            != hell_testkit::sha256_bytes(&bytes).hex()
        {
            return Err(format!(
                "{} archive digest differs from platform report",
                platform.id()
            ));
        }
        archives.insert(archive_name, bytes);
        manifests.push(manifest);
    }
    Ok(PlatformEvidence {
        evidence_members,
        manifests,
        archives,
    })
}

fn require_report_manifest_identity(
    report: &JsonValue,
    manifest: &crate::conformance::EvidenceManifest,
    root: &Path,
    platform: ReleasePlatform,
) -> Result<(), String> {
    let gate = json_member(
        json_member(report.object()?, "evidence")?.object()?,
        "conformance-evidence",
    )?
    .object()?;
    if json_member(gate, "candidateExecutableSha256")?.string()?
        != manifest.candidate_executable_sha256
        || oracle_binding(root)? != manifest.oracle
    {
        return Err(format!(
            "{} platform identity differs between report and evidence manifest",
            platform.id()
        ));
    }
    Ok(())
}

fn verify_platform_archive(
    report: &Path,
    plan: &ReleasePlan,
    platform: ReleasePlatform,
    root: &Path,
    archive_name: &str,
    manifest: &crate::conformance::EvidenceManifest,
) -> Result<Vec<u8>, String> {
    let archive_path = root.join("archive").join(archive_name);
    archive::verify(
        &archive_path,
        platform,
        &plan.version,
        plan.source_date_epoch,
    )?;
    let extraction_root = report.with_file_name(format!(".platform-extract-{}", platform.id()));
    if extraction_root.exists() {
        return Err("platform archive extraction staging path already exists".to_owned());
    }
    let executable = archive::extract_binary(
        &archive_path,
        platform,
        &plan.version,
        plan.source_date_epoch,
        &extraction_root,
    )?;
    let executable_sha256 = hell_testkit::sha256_file(&executable)
        .map_err(|error| format!("cannot hash packaged executable: {error}"))?
        .hex();
    fs::remove_dir_all(&extraction_root)
        .map_err(|error| format!("cannot remove archive extraction staging: {error}"))?;
    if executable_sha256 != manifest.candidate_executable_sha256 {
        return Err(format!(
            "{} packaged executable differs from evidence identity",
            platform.id()
        ));
    }
    read_regular(&archive_path)
}

pub(super) fn validate_conformance_binding(
    plan: &ReleasePlan,
    conformance: &crate::conformance::ConformancePlan,
) -> Result<(), String> {
    if conformance.plan_sha256 != plan.conformance_plan_sha256
        || conformance.candidate_sha != plan.resolution.candidate_sha
        || conformance.workflow_sha != plan.resolution.workflow_sha
        || conformance.release_evaluation_instant != plan.release_evaluation_instant
        || conformance.trusted_inputs_sha256 != plan.trusted_conformance_inputs_sha256
        || conformance.source_inventory_sha256 != plan.source_inventory_sha256
        || conformance.standard != plan.conformance_standard
    {
        return Err("conformance plan binding differs from release plan".to_owned());
    }
    Ok(())
}

fn validate_platform_manifest(
    manifest: &crate::conformance::EvidenceManifest,
    plan: &ReleasePlan,
    conformance: &crate::conformance::ConformancePlan,
    platform: ReleasePlatform,
) -> Result<(), String> {
    let conformance_platform = crate::conformance::ConformancePlatform::parse(platform.id())?;
    if manifest.platform != conformance_platform
        || manifest.candidate_sha != plan.resolution.candidate_sha
        || manifest.release_plan_sha256 != plan.plan_sha256
        || manifest.conformance_plan_sha256 != conformance.plan_sha256
        || manifest.assigned_obligations
            != crate::conformance::assigned_obligation_count(conformance, conformance_platform)?
    {
        return Err(format!(
            "{} evidence manifest binding differs",
            platform.id()
        ));
    }
    Ok(())
}

fn copy_manifest_members(
    root: &Path,
    manifest: &crate::conformance::EvidenceManifest,
    archive_members: &mut BTreeMap<String, Vec<u8>>,
) -> Result<(), String> {
    for member in manifest
        .records
        .iter()
        .chain(&manifest.exploratory_records)
        .chain(&manifest.observations)
    {
        let bytes = read_regular(&root.join(&member.path))?;
        if hell_testkit::sha256_bytes(&bytes).hex() != member.sha256 {
            return Err(format!("evidence member {:?} digest differs", member.path));
        }
        let archive_path = member
            .path
            .strip_prefix("conformance-evidence/")
            .map(|tail| format!("records/{tail}"))
            .or_else(|| {
                member
                    .path
                    .strip_prefix("conformance-observations/")
                    .map(|tail| format!("observations/{tail}"))
            })
            .ok_or_else(|| "platform evidence path has an unknown class".to_owned())?;
        match archive_members.entry(archive_path) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(bytes);
            }
            std::collections::btree_map::Entry::Occupied(entry) if entry.get() == &bytes => {}
            std::collections::btree_map::Entry::Occupied(_) => {
                return Err("platform evidence path has contradictory bytes".to_owned());
            }
        }
    }
    Ok(())
}

fn oracle_binding(root: &Path) -> Result<crate::conformance::OracleBinding, String> {
    let value = read_json(&root.join("oracle-report.json"))?;
    let fields = value.object()?;
    require_exact_json_keys(
        fields,
        &[
            "commit",
            "executableSha256",
            "repository",
            "schemaVersion",
            "sourceSha256",
            "state",
        ],
    )?;
    if json_member(fields, "schemaVersion")?.number()? != 2
        || json_member(fields, "state")?.string()? != "verified"
    {
        return Err("oracle report is not a verified v2 report".to_owned());
    }
    Ok(crate::conformance::OracleBinding {
        repository: json_member(fields, "repository")?.string()?.to_owned(),
        commit: json_member(fields, "commit")?.string()?.to_owned(),
        executable_sha256: json_member(fields, "executableSha256")?
            .string()?
            .to_owned(),
        source_sha256: json_member(fields, "sourceSha256")?.string()?.to_owned(),
    })
}

pub(crate) fn verify_platform_report(
    path: &Path,
    plan: &ReleasePlan,
    conformance: &crate::conformance::ConformancePlan,
    platform: ReleasePlatform,
) -> Result<JsonValue, String> {
    let value = read_json(path)?;
    fuzz_parse_platform_report(&value)?;
    let fields = value.object()?;
    require_exact_json_keys(
        fields,
        &[
            "archiveName",
            "archiveSha256",
            "assignedObligationCount",
            "buildInputsSha256",
            "candidateSha",
            "conformancePlanSha256",
            "conformanceStandard",
            "evidence",
            "evidenceManifestSha256",
            "externalInputsSha256",
            "exploratoryObservationCount",
            "gates",
            "imageOS",
            "imageVersion",
            "nativeEnvironmentSha256",
            "planSha256",
            "platform",
            "producedEvidenceRecordCount",
            "runAttempt",
            "runId",
            "schemaVersion",
            "state",
            "tag",
            "toolIdentities",
            "trustedConformanceInputsSha256",
            "unclassifiedMismatchCount",
            "version",
            "workflowSha",
        ],
    )?;
    require_platform_report_binding(fields, plan, conformance, platform)?;
    let artifact_root = path
        .parent()
        .ok_or_else(|| "platform report has no artifact root".to_owned())?;
    require_platform_report_evidence(fields, artifact_root, plan, conformance, platform)?;
    require_platform_report_gates(fields, platform)?;
    Ok(value)
}

fn require_platform_report_binding(
    fields: &BTreeMap<String, JsonValue>,
    plan: &ReleasePlan,
    conformance: &crate::conformance::ConformancePlan,
    platform: ReleasePlatform,
) -> Result<(), String> {
    if json_member(fields, "schemaVersion")?.number()? != 2
        || json_member(fields, "state")?.string()? != "passed"
        || json_member(fields, "platform")?.string()? != platform.id()
        || json_member(fields, "candidateSha")?.string()? != plan.resolution.candidate_sha
        || json_member(fields, "workflowSha")?.string()? != plan.resolution.workflow_sha
        || json_member(fields, "planSha256")?.string()? != plan.plan_sha256
        || json_member(fields, "conformancePlanSha256")?.string()? != conformance.plan_sha256
        || json_member(fields, "trustedConformanceInputsSha256")?.string()?
            != conformance.trusted_inputs_sha256
        || json_member(fields, "conformanceStandard")?.string()? != conformance.standard
        || json_member(fields, "buildInputsSha256")?.string()? != plan.build_inputs_sha256
        || json_member(fields, "externalInputsSha256")?.string()? != plan.external_inputs_sha256
        || json_member(fields, "archiveName")?.string()?
            != format!("hell-v{}-{}.tar.gz", plan.version, platform.id())
        || json_member(fields, "version")?.string()? != plan.version
        || json_member(fields, "tag")?.string()? != plan.tag
        || json_member(fields, "runId")?.number()? != plan.resolution.run_id
        || json_member(fields, "runAttempt")?.number()? != plan.resolution.run_attempt
        || json_member(fields, "unclassifiedMismatchCount")?.number()? != 0
    {
        return Err(format!(
            "{} platform report is not exactly plan-bound",
            platform.id()
        ));
    }
    Ok(())
}

fn require_platform_report_evidence(
    fields: &BTreeMap<String, JsonValue>,
    artifact_root: &Path,
    plan: &ReleasePlan,
    conformance: &crate::conformance::ConformancePlan,
    platform: ReleasePlatform,
) -> Result<(), String> {
    let evidence_manifest = crate::conformance::EvidenceManifest::parse(&read_json(
        &artifact_root.join("conformance-evidence-manifest.json"),
    )?)?;
    let conformance_platform = crate::conformance::ConformancePlatform::parse(platform.id())?;
    if json_member(fields, "assignedObligationCount")?.number()?
        != crate::conformance::assigned_obligation_count(conformance, conformance_platform)?
        || json_member(fields, "producedEvidenceRecordCount")?.number()?
            != evidence_manifest.produced_records
    {
        return Err(format!(
            "{} platform report evidence counts are forged",
            platform.id()
        ));
    }
    if json_member(fields, "nativeEnvironmentSha256")?.string()?
        != super::native_environment::verify_receipt(
            &artifact_root.join("native-environment.json"),
            platform,
            &plan.external_inputs_sha256,
        )?
    {
        return Err(format!(
            "{} native environment receipt differs from platform report",
            platform.id()
        ));
    }
    Ok(())
}

fn require_platform_report_gates(
    fields: &BTreeMap<String, JsonValue>,
    platform: ReleasePlatform,
) -> Result<(), String> {
    let gates = json_member(fields, "gates")?.array()?;
    let evidence = json_member(fields, "evidence")?.object()?;
    let expected = expected_gates(platform);
    if gates.len() != expected.len()
        || evidence.keys().map(String::as_str).collect::<BTreeSet<_>>()
            != expected.iter().copied().collect()
    {
        return Err(format!("{} platform gate exact set differs", platform.id()));
    }
    for (gate, expected_name) in gates.iter().zip(expected) {
        let gate = gate.object()?;
        require_exact_json_keys(gate, &["name", "passed"])?;
        if json_member(gate, "name")?.string()? != *expected_name
            || !json_member(gate, "passed")?.boolean()?
        {
            return Err(format!("{} gate {expected_name} failed", platform.id()));
        }
        let state =
            json_member(json_member(evidence, expected_name)?.object()?, "state")?.string()?;
        if state
            != if *expected_name == "conformance-evidence" {
                "collected"
            } else {
                "passed"
            }
        {
            return Err(format!(
                "{} gate evidence {expected_name} failed",
                platform.id()
            ));
        }
    }
    Ok(())
}

pub(crate) fn fuzz_parse_platform_report(value: &JsonValue) -> Result<(), String> {
    let fields = value.object()?;
    require_exact_json_keys(
        fields,
        &[
            "archiveName",
            "archiveSha256",
            "assignedObligationCount",
            "buildInputsSha256",
            "candidateSha",
            "conformancePlanSha256",
            "conformanceStandard",
            "evidence",
            "evidenceManifestSha256",
            "externalInputsSha256",
            "exploratoryObservationCount",
            "gates",
            "imageOS",
            "imageVersion",
            "nativeEnvironmentSha256",
            "planSha256",
            "platform",
            "producedEvidenceRecordCount",
            "runAttempt",
            "runId",
            "schemaVersion",
            "state",
            "tag",
            "toolIdentities",
            "trustedConformanceInputsSha256",
            "unclassifiedMismatchCount",
            "version",
            "workflowSha",
        ],
    )?;
    let platform = fuzz_validate_platform_report_fields(fields)?;
    fuzz_validate_platform_report_gates(fields, platform)
}

fn fuzz_validate_platform_report_fields(
    fields: &BTreeMap<String, JsonValue>,
) -> Result<ReleasePlatform, String> {
    if json_member(fields, "schemaVersion")?.number()? != 2
        || json_member(fields, "state")?.string()? != "passed"
    {
        return Err("unsupported or non-passing platform report".to_owned());
    }
    let platform = ReleasePlatform::parse(json_member(fields, "platform")?.string()?)?;
    for name in [
        "archiveSha256",
        "buildInputsSha256",
        "conformancePlanSha256",
        "evidenceManifestSha256",
        "externalInputsSha256",
        "nativeEnvironmentSha256",
        "planSha256",
        "trustedConformanceInputsSha256",
    ] {
        super::schema::require_digest(json_member(fields, name)?.string()?, name)?;
    }
    for name in ["candidateSha", "workflowSha"] {
        super::schema::require_sha(json_member(fields, name)?.string()?, name)?;
    }
    for name in [
        "archiveName",
        "conformanceStandard",
        "imageOS",
        "imageVersion",
        "tag",
        "version",
    ] {
        if json_member(fields, name)?.string()?.is_empty() {
            return Err(format!("platform report field {name} is empty"));
        }
    }
    for name in [
        "assignedObligationCount",
        "exploratoryObservationCount",
        "producedEvidenceRecordCount",
        "runAttempt",
        "runId",
        "unclassifiedMismatchCount",
    ] {
        json_member(fields, name)?.number()?;
    }
    Ok(platform)
}

fn fuzz_validate_platform_report_gates(
    fields: &BTreeMap<String, JsonValue>,
    platform: ReleasePlatform,
) -> Result<(), String> {
    let expected = expected_gates(platform);
    let gates = json_member(fields, "gates")?.array()?;
    let evidence = json_member(fields, "evidence")?.object()?;
    if gates.len() != expected.len()
        || evidence.keys().map(String::as_str).collect::<BTreeSet<_>>()
            != expected.iter().copied().collect()
    {
        return Err("platform report gate inventory differs".to_owned());
    }
    for (gate, name) in gates.iter().zip(expected) {
        let gate = gate.object()?;
        require_exact_json_keys(gate, &["name", "passed"])?;
        if json_member(gate, "name")?.string()? != *name
            || !json_member(gate, "passed")?.boolean()?
        {
            return Err("platform report contains a failed or reordered gate".to_owned());
        }
        json_member(evidence, name)?.object()?;
    }
    let tools = json_member(fields, "toolIdentities")?.object()?;
    if tools.is_empty() {
        return Err("platform report tool identity inventory is empty".to_owned());
    }
    for identity in tools.values() {
        super::schema::require_digest(identity.string()?, "platform tool identity")?;
    }
    Ok(())
}

fn verify_platform_inventory(
    root: &Path,
    platform: ReleasePlatform,
    version: &str,
) -> Result<(), String> {
    require_real_directory(root)?;
    let mut expected = BTreeSet::from([
        "archive",
        "archive-manifest.json",
        "conformance-evidence",
        "conformance-evidence-manifest.json",
        "conformance-observations",
        "native-environment.json",
        "oracle-report.json",
        "package-report.json",
        "platform-report.json",
        "source-inventory.json",
    ]);
    if platform == ReleasePlatform::LinuxX86_64 {
        expected.insert("dependency-policy.json");
        expected.insert("mutation-report.json");
    }
    if directory_entries(root)? != expected.iter().map(|name| (*name).to_owned()).collect() {
        return Err(format!(
            "{} platform result exact set differs",
            platform.id()
        ));
    }
    for name in [
        "archive",
        "conformance-evidence",
        "conformance-observations",
    ] {
        require_real_directory(&root.join(name))?;
    }
    let archive_name = format!("hell-v{version}-{}.tar.gz", platform.id());
    if directory_entries(&root.join("archive"))? != BTreeSet::from([archive_name]) {
        return Err(format!("{} archive exact set differs", platform.id()));
    }
    Ok(())
}

fn require_platform_roots(input: &Path) -> Result<(), String> {
    require_real_directory(input)?;
    let expected = PLATFORMS
        .iter()
        .map(|platform| platform.id().to_owned())
        .collect();
    if directory_entries(input)? != expected {
        return Err("platform artifact exact root set differs".to_owned());
    }
    Ok(())
}

fn directory_entries(path: &Path) -> Result<BTreeSet<String>, String> {
    fs::read_dir(path)
        .map_err(|error| format!("cannot enumerate {}: {error}", path.display()))?
        .map(|entry| {
            entry
                .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?
                .file_name()
                .into_string()
                .map_err(|_| format!("{} contains a non-UTF-8 name", path.display()))
        })
        .collect()
}

fn require_real_directory(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!("{} is not a real directory", path.display()));
    }
    Ok(())
}

fn install_subject(
    output: &Path,
    subjects: &mut BTreeMap<String, String>,
    name: &str,
    bytes: &[u8],
) -> Result<(), String> {
    if name.contains(['/', '\\']) || subjects.contains_key(name) {
        return Err("release subject name is unsafe or duplicated".to_owned());
    }
    write_atomic(&output.join(name), bytes)?;
    subjects.insert(name.to_owned(), hell_testkit::sha256_bytes(bytes).hex());
    Ok(())
}

pub(super) fn conformance_summary(
    plan: &crate::conformance::ConformancePlan,
    acceptance: &crate::conformance::ConformanceAcceptance,
    required: u64,
    evidence: &str,
    report: &str,
    acceptance_sha256: &str,
) -> JsonValue {
    object([
        ("acceptanceSha256", string(acceptance_sha256)),
        ("admitted", JsonValue::Bool(acceptance.admitted)),
        ("blockedCells", number(acceptance.counts.blocked())),
        ("evidenceArchiveSha256", string(evidence)),
        ("excludedCells", number(acceptance.counts.excluded)),
        ("exemptedCells", number(acceptance.counts.exempted)),
        (
            "notApplicableCells",
            number(acceptance.counts.not_applicable),
        ),
        ("planSha256", string(&plan.plan_sha256)),
        ("reportSha256", string(report)),
        ("requiredCells", number(required)),
        ("standard", string(&plan.standard)),
        ("trustedInputsSha256", string(&plan.trusted_inputs_sha256)),
        (
            "unclassifiedMismatches",
            number(acceptance.unclassified_mismatch_count),
        ),
        ("verifiedCells", number(acceptance.counts.verified())),
    ])
}

pub(super) fn gate_counts(acceptance: &crate::conformance::ConformanceAcceptance) -> JsonValue {
    object([
        ("blocked", number(acceptance.counts.blocked())),
        ("excluded", number(acceptance.counts.excluded)),
        ("exempted", number(acceptance.counts.exempted)),
        ("notApplicable", number(acceptance.counts.not_applicable)),
        (
            "unclassifiedMismatches",
            number(acceptance.unclassified_mismatch_count),
        ),
        ("verified", number(acceptance.counts.verified())),
    ])
}

pub(super) fn release_notes(
    plan: &ReleasePlan,
    acceptance: &crate::conformance::ConformanceAcceptance,
    required: u64,
) -> String {
    let exemption = if acceptance.counts.exempted == 0 {
        "Every required cell was verified.".to_owned()
    } else {
        format!(
            "{} required cells were admitted by exact reviewed exemptions and are not reported as verified.",
            acceptance.counts.exempted
        )
    };
    format!(
        "# {}\n\nRelease of `{}` from `{}`.\n\n## Conformance\n\nThis release was evaluated against `{}` for Linux x86-64, macOS ARM64, and Windows x86-64.\n\n- Required cells: {}\n- Verified cells: {}\n- Exact reviewed exemptions: {}\n- Not applicable cells: {}\n- Excluded cells: {}\n- Blocking cells: {}\n- Unclassified generated mismatches: {}\n\n{} See `conformance-report.json`, `conformance-acceptance.json`, and `conformance-evidence.tar.gz` for the exact decision.\n",
        plan.tag,
        plan.version,
        plan.resolution.candidate_sha,
        plan.conformance_standard,
        required,
        acceptance.counts.verified(),
        acceptance.counts.exempted,
        acceptance.counts.not_applicable,
        acceptance.counts.excluded,
        acceptance.counts.blocked(),
        acceptance.unclassified_mismatch_count,
        exemption,
    )
}

pub(super) fn conformance_html(
    plan: &ReleasePlan,
    acceptance: &crate::conformance::ConformanceAcceptance,
    required: u64,
) -> String {
    format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>hell-rs conformance</title></head><body><main><h1>Conformance report</h1><dl><dt>Candidate</dt><dd><code>{}</code></dd><dt>Standard</dt><dd><code>{}</code></dd><dt>Required</dt><dd>{}</dd><dt>Verified</dt><dd>{}</dd><dt>Exempted</dt><dd>{}</dd><dt>Not applicable</dt><dd>{}</dd><dt>Excluded</dt><dd>{}</dd><dt>Blocked</dt><dd>{}</dd><dt>Unclassified mismatches</dt><dd>{}</dd></dl><p>The canonical machine-readable decision is in <code>conformance-report.json</code>.</p></main></body></html>\n",
        html_escape(&plan.resolution.candidate_sha),
        html_escape(&plan.conformance_standard),
        required,
        acceptance.counts.verified(),
        acceptance.counts.exempted,
        acceptance.counts.not_applicable,
        acceptance.counts.excluded,
        acceptance.counts.blocked(),
        acceptance.unclassified_mismatch_count,
    )
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub(super) fn verify_mutation_report(path: &Path, plan: &ReleasePlan) -> Result<(), String> {
    let value = read_json(path)?;
    let fields = value.object()?;
    require_exact_json_keys(
        fields,
        &[
            "candidateSha",
            "catalogSha256",
            "detected",
            "mutants",
            "required",
            "schemaVersion",
            "state",
        ],
    )?;
    let required = crate::mutation::trusted_required_mutant_ids()?;
    let ids = json_member(fields, "mutants")?
        .array()?
        .iter()
        .map(|mutant| {
            let fields = mutant.object()?;
            if !json_member(fields, "detected")?.boolean()?
                || json_member(fields, "strategy")?.string()? != "baseline-pass-mutant-fail"
            {
                return Err("mutation record was not detected by the exact harness".to_owned());
            }
            Ok(json_member(fields, "id")?.string()?.to_owned())
        })
        .collect::<Result<BTreeSet<_>, String>>()?;
    let required_count = u64::try_from(required.len()).map_err(|_| "mutation count overflow")?;
    if ids != required
        || json_member(fields, "candidateSha")?.string()? != plan.resolution.candidate_sha
        || json_member(fields, "catalogSha256")?.string()?
            != hell_testkit::sha256_bytes(include_bytes!("../../../../compat/mutants.toml")).hex()
        || json_member(fields, "required")?.number()? != required_count
        || json_member(fields, "detected")?.number()? != required_count
        || json_member(fields, "state")?.string()? != "passed"
    {
        return Err("mutation report differs from the trusted required catalog".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::schema::Resolution;
    use super::*;
    use crate::json::canonical_json_bytes;

    fn plan() -> ReleasePlan {
        ReleasePlan {
            resolution: Resolution {
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
            trusted_conformance_inputs_sha256: "1".repeat(64),
            conformance_plan_sha256: "2".repeat(64),
            conformance_standard: crate::conformance::RELEASE_STANDARD.into(),
            changelog_sha256: "3".repeat(64),
            commit_author: "A <a@example.test>".into(),
            commit_committer: "C <c@example.test>".into(),
            plan_sha256: "f".repeat(64),
        }
    }

    #[derive(Default)]
    struct AcceptanceFixtureCounts {
        verified_exact: u64,
        verified_normalized: u64,
        verified_platform_equivalent: u64,
        not_applicable: u64,
        excluded: u64,
        exempted: u64,
        blocked_missing_evidence: u64,
        blocked_mismatch: u64,
        blocked_invalid_evidence: u64,
    }

    fn acceptance(
        counts: &AcceptanceFixtureCounts,
        unclassified: u64,
    ) -> Result<crate::conformance::ConformanceAcceptance, String> {
        let admitted = counts.blocked_missing_evidence == 0
            && counts.blocked_mismatch == 0
            && counts.blocked_invalid_evidence == 0
            && unclassified == 0;
        let without_digest = object([
            ("admitted", JsonValue::Bool(admitted)),
            ("candidateSha", string(&"a".repeat(40))),
            ("conformancePlanSha256", string(&"2".repeat(64))),
            ("evidenceArchiveSha256", string(&"4".repeat(64))),
            (
                "partition",
                object([
                    (
                        "blockedInvalidEvidence",
                        number(counts.blocked_invalid_evidence),
                    ),
                    ("blockedMismatch", number(counts.blocked_mismatch)),
                    (
                        "blockedMissingEvidence",
                        number(counts.blocked_missing_evidence),
                    ),
                    ("excluded", number(counts.excluded)),
                    ("exempted", number(counts.exempted)),
                    ("notApplicable", number(counts.not_applicable)),
                    ("verifiedExact", number(counts.verified_exact)),
                    ("verifiedNormalized", number(counts.verified_normalized)),
                    (
                        "verifiedPlatformEquivalent",
                        number(counts.verified_platform_equivalent),
                    ),
                ]),
            ),
            ("reportSha256", string(&"5".repeat(64))),
            ("schemaVersion", number(1)),
            ("standard", string(crate::conformance::RELEASE_STANDARD)),
            ("unclassifiedMismatchCount", number(unclassified)),
        ]);
        let digest = hell_testkit::sha256_bytes(&canonical_json_bytes(&without_digest)?).hex();
        let mut fields = without_digest.object()?.clone();
        fields.insert("decisionSha256".into(), string(&digest));
        crate::conformance::ConformanceAcceptance::parse(&JsonValue::Object(fields))
    }

    #[test]
    fn integrated_acceptance_matrix_is_fail_closed_and_deterministic() {
        let accepted = acceptance(
            &AcceptanceFixtureCounts {
                verified_exact: 8,
                not_applicable: 2,
                excluded: 4,
                exempted: 1,
                ..Default::default()
            },
            0,
        )
        .unwrap();
        assert!(accepted.admitted);
        assert_eq!(accepted.counts.verified(), 8);
        assert_eq!(accepted.counts.not_applicable, 2);
        assert_eq!(accepted.counts.excluded, 4);
        assert_eq!(accepted.counts.exempted, 1);
        let notes = release_notes(&plan(), &accepted, 9);
        assert_eq!(notes, release_notes(&plan(), &accepted, 9));
        assert_eq!(
            conformance_html(&plan(), &accepted, 9),
            conformance_html(&plan(), &accepted, 9)
        );

        for (name, result) in [
            (
                "missing-cell",
                acceptance(
                    &AcceptanceFixtureCounts {
                        blocked_missing_evidence: 1,
                        ..Default::default()
                    },
                    0,
                ),
            ),
            (
                "generated-mismatch",
                acceptance(
                    &AcceptanceFixtureCounts {
                        blocked_mismatch: 1,
                        ..Default::default()
                    },
                    0,
                ),
            ),
            (
                "invalid-evidence",
                acceptance(
                    &AcceptanceFixtureCounts {
                        blocked_invalid_evidence: 1,
                        ..Default::default()
                    },
                    0,
                ),
            ),
            (
                "unclassified-generated",
                acceptance(&AcceptanceFixtureCounts::default(), 1),
            ),
        ] {
            let decision = result.unwrap();
            assert!(!decision.admitted, "{name} was admitted");
        }
    }

    #[test]
    fn assembly_rejects_platform_substitution_and_candidate_authored_duplicates() {
        let root = std::env::temp_dir().join(format!(
            "hell-assembly-matrix-{}-{}",
            std::process::id(),
            crate::test_thread_name_component(std::thread::current().name())
        ));
        std::fs::create_dir(&root).unwrap();
        for platform in PLATFORMS {
            std::fs::create_dir(root.join(platform.id())).unwrap();
        }
        assert!(require_platform_roots(&root).is_ok());
        std::fs::rename(
            root.join(ReleasePlatform::MacosAarch64.id()),
            root.join("macos-native-substitution"),
        )
        .unwrap();
        assert!(require_platform_roots(&root).is_err());

        let output = root.join("subjects");
        std::fs::create_dir(&output).unwrap();
        let mut subjects = BTreeMap::new();
        install_subject(
            &output,
            &mut subjects,
            "release-manifest.json",
            b"trusted\n",
        )
        .unwrap();
        assert!(
            install_subject(
                &output,
                &mut subjects,
                "release-manifest.json",
                b"candidate-authored\n"
            )
            .is_err()
        );
        assert!(install_subject(&output, &mut subjects, "../report.json", b"x").is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
