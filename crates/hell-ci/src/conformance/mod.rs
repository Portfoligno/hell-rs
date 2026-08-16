//! Fail-closed release-conformance contracts.
//!
//! Evidence producers can describe only observations and their bindings.  The
//! final ledger is derived here, in trusted automation, and reconstructed by a
//! separate verifier before publication.

mod derive;
mod evidence;
mod exemptions;
mod inputs;
mod key;
mod ledger;
mod verify;

use std::ffi::OsString;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

pub(crate) use derive::derive_partition;
pub(crate) use evidence::{
    CaseSource, EXPLORATORY_GENERATOR_COUNT, EXPLORATORY_GENERATOR_SEED,
    EXPLORATORY_GENERATOR_VERSION, EvidenceManifest, EvidenceManifestInput, EvidenceMember,
    EvidenceRecord, EvidenceRepository, EvidenceTarget, ExploratoryRecord, Observation,
    OracleBinding, TrustedEvidenceBindings, assigned_obligation_count,
};
pub(crate) use exemptions::parse_release_exemptions;
pub(crate) use inputs::{build_trusted_inputs, parse_trusted_inputs};
pub(crate) use key::{CellKey, ConformancePlatform, ProfileId};
pub(crate) use ledger::conformance_report;
pub(crate) use ledger::validate_utc_instant;
pub(crate) use ledger::{
    Blocker, ConformanceAcceptance, ConformancePlan, DerivedPartition, EvidenceStrategy,
    ExemptionKind, FailureClass, FinalDisposition, PlannedCell, PlannedExemption,
    PlannedObligation, ScopeDisposition, VerificationMode,
};
pub(crate) use verify::independently_reconstruct_partition;

/// The first named, fail-closed release standard.
pub(crate) const RELEASE_STANDARD: &str = "upstream-release-v1";
pub(crate) const GENERATED_AGREEMENT_MAY_VERIFY: bool = false;
pub(crate) const GENERATED_MISMATCH_BLOCKS: bool = true;

pub(crate) fn recognizes(arguments: &[OsString]) -> bool {
    arguments
        .first()
        .is_some_and(|argument| argument == "conformance")
}

pub(crate) fn run_cli(arguments: &[OsString]) -> Result<String, String> {
    match arguments.get(1).and_then(|value| value.to_str()) {
        Some("audit") => run_audit_cli(arguments),
        Some("generate-requirements") => run_generate_requirements_cli(arguments),
        _ => Err(conformance_usage()),
    }
}

fn run_audit_cli(arguments: &[OsString]) -> Result<String, String> {
    let mut candidate_root = None;
    let mut output = None;
    let mut index = 2;
    while index < arguments.len() {
        let flag = arguments[index]
            .to_str()
            .ok_or_else(|| "conformance audit option must be UTF-8".to_owned())?;
        let value = arguments
            .get(index + 1)
            .ok_or_else(|| format!("{flag} requires PATH"))?;
        match flag {
            "--candidate-root" if candidate_root.is_none() => {
                candidate_root = Some(PathBuf::from(value));
            }
            "--output" if output.is_none() => output = Some(PathBuf::from(value)),
            "--candidate-root" | "--output" => {
                return Err(format!("{flag} was provided more than once"));
            }
            _ => return Err(format!("unknown conformance audit option {flag:?}")),
        }
        index += 2;
    }
    audit(
        candidate_root.ok_or_else(conformance_audit_usage)?,
        output.ok_or_else(conformance_audit_usage)?,
    )
}

fn run_generate_requirements_cli(arguments: &[OsString]) -> Result<String, String> {
    if arguments.get(2).and_then(|value| value.to_str()) != Some("--output") || arguments.len() != 4
    {
        return Err(conformance_usage());
    }
    let output = PathBuf::from(&arguments[3]);
    let (document, summary) = generated_requirements_catalog()?;
    crate::release::manifest::write_atomic(&output, document.as_bytes())?;
    Ok(format!(
        "wrote {} descriptor-authorized cells from {} reviewed cases ({} conflicting cells omitted) to {}",
        summary.mapped_cells,
        summary.referenced_cases,
        summary.conflicting_cells,
        output.display()
    ))
}

fn conformance_audit_usage() -> String {
    "usage: hell-ci conformance audit --candidate-root PATH --output PATH".to_owned()
}

fn conformance_usage() -> String {
    format!(
        "{}; or: hell-ci conformance generate-requirements --output PATH",
        conformance_audit_usage()
    )
}

fn audit(candidate_root: PathBuf, output: PathBuf) -> Result<String, String> {
    let candidate_root = std::fs::canonicalize(&candidate_root).map_err(|error| {
        format!(
            "cannot canonicalize conformance audit root {}: {error}",
            candidate_root.display()
        )
    })?;
    let control_summary = require_audit_control_inputs(&candidate_root)?;
    let requirements = hell_builtins::compatibility_requirements();
    hell_builtins::validate_compatibility_requirements(requirements)
        .map_err(|error| format!("invalid compatibility requirement catalog: {error:?}"))?;
    let cases = hell_testkit::committed_differential_cases();
    hell_testkit::validate_evidence_catalog(&cases)
        .map_err(|error| format!("invalid committed conformance case catalog: {error}"))?;
    let case_ids = cases
        .iter()
        .map(|case| case.id.as_ref())
        .collect::<std::collections::BTreeSet<_>>();
    let mut referenced = std::collections::BTreeSet::new();
    let mut required_cells = 0_u64;
    let mut excluded_cells = 0_u64;
    let mut missing_mappings = 0_u64;
    let mut missing_obligation_mappings = 0_u64;
    let mut missing_committed_case_mappings = 0_u64;
    let mut unavailable_validators = 0_u64;
    let mut unavailable_normalizers = 0_u64;
    let mut mapped_obligations = 0_u64;
    for requirement in requirements {
        for dimension in &requirement.dimensions {
            for profile in ProfileId::ALL {
                for platform in ConformancePlatform::ALL {
                    if profile == ProfileId::Sandboxed {
                        excluded_cells += 1;
                        continue;
                    }
                    required_cells += 1;
                    let scope = dimension
                        .scopes
                        .iter()
                        .find(|scope| audit_scope_matches(scope, profile, platform))
                        .ok_or_else(|| "requirement scope disappeared during audit".to_owned())?;
                    if scope.obligations.is_empty() {
                        missing_obligation_mappings += 1;
                    }
                    if scope.evidence.is_empty() {
                        missing_committed_case_mappings += 1;
                    }
                    if scope.obligations.is_empty() || scope.evidence.is_empty() {
                        missing_mappings += 1;
                    }
                    if scope
                        .normalizers
                        .iter()
                        .any(|normalizer| !normalizer_replay_available(*normalizer))
                    {
                        unavailable_normalizers += 1;
                    }
                    for reference in scope.evidence {
                        let parsed = hell_builtins::parse_differential_reference(reference)
                            .map_err(|_| format!("invalid differential reference {reference:?}"))?;
                        if !case_ids.contains(parsed.case_id) {
                            return Err(format!(
                                "requirement references stale case {:?}",
                                parsed.case_id
                            ));
                        }
                        referenced.insert(parsed.case_id);
                    }
                    for obligation in scope.obligations {
                        mapped_obligations += 1;
                        let unavailable = !semantic_validator_available(dimension.dimension)
                            || scope.evidence.iter().all(|reference| {
                                hell_builtins::parse_differential_reference(reference)
                                    .ok()
                                    .and_then(|reference| {
                                        cases
                                            .iter()
                                            .find(|case| case.id.as_ref() == reference.case_id)
                                    })
                                    .is_none_or(|case| {
                                        !case_authorizes(
                                            case,
                                            &CellKey::new(
                                                hell_builtins::registry()
                                                    [usize::from(requirement.builtin.0)]
                                                .name,
                                                dimension.dimension,
                                                profile,
                                                platform,
                                            )
                                            .expect("registry builtin produces a safe key"),
                                            obligation,
                                            &scope
                                                .normalizers
                                                .iter()
                                                .map(|value| value.as_str().to_owned())
                                                .collect::<Vec<_>>(),
                                        )
                                    })
                            });
                        if unavailable {
                            unavailable_validators += 1;
                        }
                    }
                }
            }
        }
    }
    let stale_cases = cases
        .iter()
        .filter(|case| case.claim_evidence.is_some() && !referenced.contains(case.id.as_ref()))
        .map(|case| case.id.to_string())
        .collect::<Vec<_>>();
    let total_cells =
        u64::try_from(canonical_universe()?.len()).map_err(|_| "audit universe count overflow")?;
    // This command deliberately consumes no candidate evidence. Its projected
    // partition must therefore classify every Required cell as missing rather
    // than adding overlapping catalog diagnostics as if they were cells.
    let blocked_cells_projected = required_cells;
    let projected_partition = crate::release::schema::object([
        (
            "blockedMissingEvidence",
            crate::release::schema::number(blocked_cells_projected),
        ),
        ("blockedMismatch", crate::release::schema::number(0)),
        ("blockedInvalid", crate::release::schema::number(0)),
        ("excluded", crate::release::schema::number(excluded_cells)),
        ("exempted", crate::release::schema::number(0)),
        ("notApplicable", crate::release::schema::number(0)),
        ("verified", crate::release::schema::number(0)),
        ("verifiedNormalized", crate::release::schema::number(0)),
    ]);
    let report = crate::release::schema::object([
        (
            "auditState",
            crate::release::schema::string("nonrelease-review-required"),
        ),
        (
            "blockedCellsProjected",
            crate::release::schema::number(blocked_cells_projected),
        ),
        (
            "excludedCells",
            crate::release::schema::number(excluded_cells),
        ),
        (
            "divergenceDefinitionsWithoutExactReleaseActivation",
            crate::release::schema::number(
                control_summary.divergence_definitions_without_activation,
            ),
        ),
        (
            "exemptionExpiryWarnings",
            crate::release::schema::number(control_summary.exemption_expiry_warnings),
        ),
        (
            "mappedObligations",
            crate::release::schema::number(mapped_obligations),
        ),
        (
            "missingMappings",
            crate::release::schema::number(missing_mappings),
        ),
        (
            "missingCommittedCaseMappings",
            crate::release::schema::number(missing_committed_case_mappings),
        ),
        (
            "missingObligationMappings",
            crate::release::schema::number(missing_obligation_mappings),
        ),
        ("notApplicableCells", crate::release::schema::number(0)),
        ("projectedPartition", projected_partition),
        (
            "requiredCells",
            crate::release::schema::number(required_cells),
        ),
        (
            "releaseExemptions",
            crate::release::schema::number(control_summary.release_exemptions),
        ),
        ("schemaVersion", crate::release::schema::number(1)),
        (
            "staleUnreferencedCases",
            crate::release::schema::number(
                u64::try_from(stale_cases.len()).map_err(|_| "stale case count overflow")?,
            ),
        ),
        (
            "staleUnreferencedCaseIds",
            crate::json::JsonValue::Array(
                stale_cases
                    .iter()
                    .map(|case_id| crate::release::schema::string(case_id))
                    .collect(),
            ),
        ),
        ("standard", crate::release::schema::string(RELEASE_STANDARD)),
        ("totalCells", crate::release::schema::number(total_cells)),
        (
            "unavailableNormalizers",
            crate::release::schema::number(unavailable_normalizers),
        ),
        (
            "unavailableValidators",
            crate::release::schema::number(unavailable_validators),
        ),
        ("verifiedCellsProjected", crate::release::schema::number(0)),
    ]);
    let path = if output.extension().is_some() {
        output
    } else {
        output.join("conformance-audit.json")
    };
    crate::release::manifest::write_json(&path, &report)?;
    Ok(format!(
        "wrote nonrelease conformance audit with {blocked_cells_projected} projected blockers to {}",
        path.display()
    ))
}

const fn semantic_validator_available(dimension: hell_builtins::CompatibilityDimension) -> bool {
    matches!(
        dimension,
        hell_builtins::CompatibilityDimension::PureRuntime
            | hell_builtins::CompatibilityDimension::Effects
            | hell_builtins::CompatibilityDimension::Concurrency
            | hell_builtins::CompatibilityDimension::Presentation
            | hell_builtins::CompatibilityDimension::Platform
            | hell_builtins::CompatibilityDimension::ResourceBehavior
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GeneratedMapping {
    evidence: Vec<String>,
    normalizers: Vec<String>,
    obligations: Vec<String>,
}

#[derive(Default)]
struct GeneratedMappingCandidates {
    evidence: std::collections::BTreeSet<String>,
    obligations: std::collections::BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, Default)]
struct GeneratedRequirementsSummary {
    mapped_cells: u64,
    referenced_cases: u64,
    conflicting_cells: u64,
}

fn generated_requirements_catalog() -> Result<(String, GeneratedRequirementsSummary), String> {
    let cases = hell_testkit::committed_differential_cases();
    hell_testkit::validate_evidence_catalog(&cases)
        .map_err(|error| format!("invalid committed conformance case catalog: {error}"))?;
    let case_order = cases
        .iter()
        .enumerate()
        .map(|(index, case)| (case.id.to_string(), index))
        .collect::<std::collections::BTreeMap<_, _>>();
    let semantic_obligations = hell_testkit::applicable_runtime_obligation_cells()
        .into_iter()
        .map(|cell| {
            (
                (cell.builtin.to_string(), cell.dimension.as_str()),
                cell.obligations
                    .into_iter()
                    .map(|obligation| obligation.0.to_string())
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let portable_obligations = hell_testkit::portable_native_oracle_obligation_cells()
        .into_iter()
        .map(|cell| {
            (
                (cell.builtin.to_string(), cell.dimension.as_str()),
                cell.obligations
                    .into_iter()
                    .map(|obligation| obligation.0.to_string())
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut candidates = std::collections::BTreeMap::<
        (u16, usize, ConformancePlatform),
        std::collections::BTreeMap<Vec<String>, GeneratedMappingCandidates>,
    >::new();
    for case in &cases {
        let Some(descriptor) = &case.claim_evidence else {
            continue;
        };
        if descriptor.profile != hell_builtins::ExecutionProfile::Upstream {
            continue;
        }
        let normalizers = descriptor
            .claim_normalizers
            .iter()
            .map(|normalizer| normalizer.as_str().to_owned())
            .collect::<Vec<_>>();
        for target in &descriptor.semantic_targets {
            if !semantic_validator_available(target.dimension) {
                continue;
            }
            let builtin = hell_builtins::lookup(&target.builtin)
                .ok_or_else(|| format!("reviewed case {} targets an unknown builtin", case.id))?;
            let dimension = hell_builtins::CompatibilityDimension::ALL
                .iter()
                .position(|dimension| *dimension == target.dimension)
                .ok_or_else(|| "reviewed target dimension is not canonical".to_owned())?;
            for platform in ConformancePlatform::ALL {
                if !target_supports_platform(&target.platforms, platform) {
                    continue;
                }
                let group = candidates
                    .entry((builtin.id.0, dimension, platform))
                    .or_default()
                    .entry(normalizers.clone())
                    .or_default();
                group.evidence.insert(case.id.to_string());
                group.obligations.extend(
                    target
                        .obligations
                        .iter()
                        .map(|obligation| obligation.0.to_string()),
                );
            }
        }
    }

    let mut mappings = std::collections::BTreeMap::new();
    let mut conflicting_cells = 0_u64;
    for ((builtin_id, dimension_index, platform), groups) in candidates {
        let builtin = hell_builtins::registry()
            .get(usize::from(builtin_id))
            .ok_or_else(|| "reviewed mapping builtin disappeared".to_owned())?;
        let dimension = hell_builtins::CompatibilityDimension::ALL[dimension_index];
        let portable_expected = portable_obligations
            .get(&(builtin.name.to_owned(), dimension.as_str()))
            .ok_or_else(|| {
                format!(
                    "reviewed mapping has no registry obligation authority for {}/{}",
                    builtin.name,
                    dimension.as_str()
                )
            })?;
        let semantic_expected = semantic_obligations
            .get(&(builtin.name.to_owned(), dimension.as_str()))
            .ok_or_else(|| {
                format!(
                    "reviewed mapping has no semantic obligation authority for {}/{}",
                    builtin.name,
                    dimension.as_str()
                )
            })?;
        if groups
            .values()
            .any(|group| portable_failure_gap_is_stale(builtin.name, dimension, &group.obligations))
        {
            return Err(format!(
                "portable native-oracle failure gap for {}/{} is stale because reviewed failure evidence now exists",
                builtin.name,
                dimension.as_str()
            ));
        }
        let complete = groups
            .into_iter()
            .filter_map(|(normalizers, group)| {
                portable_expected
                    .iter()
                    .all(|obligation| group.obligations.contains(obligation))
                    .then(|| GeneratedMapping {
                        evidence: group.evidence.into_iter().collect(),
                        normalizers,
                        obligations: semantic_expected.clone(),
                    })
            })
            .collect::<Vec<_>>();
        if let [mapping] = complete.as_slice() {
            let mut mapping = mapping.clone();
            mapping
                .evidence
                .sort_by_key(|case_id| case_order.get(case_id).copied().unwrap_or(usize::MAX));
            mappings.insert((builtin_id, dimension_index, platform), mapping);
        } else if complete.len() > 1 {
            conflicting_cells = conflicting_cells.saturating_add(1);
        }
    }

    let mut output = String::new();
    output.push_str("schema_version = 3\n");
    writeln!(output, "baseline = {:?}", hell_builtins::LANGUAGE_VERSION)
        .expect("writing to String cannot fail");
    output.push_str("registry = \"compat/builtin-registry.json\"\n");
    write_toml_string_array(
        &mut output,
        "dimensions",
        &hell_builtins::CompatibilityDimension::ALL
            .iter()
            .map(|dimension| dimension.as_str().to_owned())
            .collect::<Vec<_>>(),
    );
    output.push_str("\n[default_requirement]\n");
    write_requirement_scope(
        &mut output,
        &["upstream", "sandboxed"],
        &["linux-x86_64", "macos-aarch64", "windows-x86_64"],
        "catalog-default-review-required",
        "committed-differential-corpus",
        &[],
        &[],
        &[],
        "No release evidence mapping has been approved for this cell.",
        "compatibility",
    );

    let mut referenced = std::collections::BTreeSet::new();
    let mut mapped_cells = 0_u64;
    for builtin in hell_builtins::registry() {
        for (dimension_index, dimension) in hell_builtins::CompatibilityDimension::ALL
            .iter()
            .enumerate()
        {
            let platform_mappings = ConformancePlatform::ALL
                .iter()
                .filter_map(|platform| {
                    mappings
                        .get(&(builtin.id.0, dimension_index, *platform))
                        .map(|mapping| (*platform, mapping.clone()))
                })
                .collect::<Vec<_>>();
            if platform_mappings.is_empty() {
                continue;
            }
            output.push_str("\n[[overrides]]\n");
            writeln!(output, "builtin = {:?}", builtin.name)
                .expect("writing to String cannot fail");
            write_toml_string_array(&mut output, "dimensions", &[dimension.as_str().to_owned()]);

            let mut emitted = std::collections::BTreeSet::new();
            for (_, mapping) in &platform_mappings {
                if !emitted.insert((
                    mapping.evidence.clone(),
                    mapping.normalizers.clone(),
                    mapping.obligations.clone(),
                )) {
                    continue;
                }
                let platforms = platform_mappings
                    .iter()
                    .filter(|(_, candidate)| candidate == mapping)
                    .map(|(platform, _)| platform.as_str())
                    .collect::<Vec<_>>();
                output.push_str("\n[[overrides.scopes]]\n");
                let evidence = mapping
                    .evidence
                    .iter()
                    .map(|case_id| {
                        referenced.insert(case_id.clone());
                        format!("differential:{case_id}")
                    })
                    .collect::<Vec<_>>();
                let portable_failure_gap = hell_testkit::portable_native_oracle_failure_unavailable(
                    builtin.name,
                    *dimension,
                );
                let (applicability_rule, rationale, review_group) = if portable_failure_gap {
                    (
                        "portable-native-oracle-host-failure-unavailable",
                        "The operation remains semantically fallible, but no deterministic portable native-oracle failure trigger exists; available success/order evidence is mapped while effect-failure remains missing and release-blocking.",
                        "portable-native-oracle-host-failure-gap",
                    )
                } else {
                    (
                        "descriptor-v8-reviewed-runtime-target",
                        "Mechanically projected from exact reviewed descriptor-v8 targets and registry-derived obligations.",
                        "descriptor-v8-runtime-authority",
                    )
                };
                write_requirement_scope(
                    &mut output,
                    &["upstream"],
                    &platforms,
                    applicability_rule,
                    "native-oracle",
                    &evidence,
                    &mapping.normalizers,
                    &mapping.obligations,
                    rationale,
                    review_group,
                );
                mapped_cells = mapped_cells.saturating_add(
                    u64::try_from(platforms.len()).map_err(|_| "mapped platform count overflow")?,
                );
            }
            let missing = ConformancePlatform::ALL
                .iter()
                .filter(|platform| {
                    !platform_mappings
                        .iter()
                        .any(|(mapped, _)| mapped == *platform)
                })
                .map(|platform| platform.as_str())
                .collect::<Vec<_>>();
            if !missing.is_empty() {
                output.push_str("\n[[overrides.scopes]]\n");
                write_requirement_scope(
                    &mut output,
                    &["upstream"],
                    &missing,
                    "catalog-default-review-required",
                    "committed-differential-corpus",
                    &[],
                    &[],
                    &[],
                    "No complete descriptor-authorized evidence mapping exists for this platform cell.",
                    "compatibility",
                );
            }
            output.push_str("\n[[overrides.scopes]]\n");
            write_requirement_scope(
                &mut output,
                &["sandboxed"],
                &["linux-x86_64", "macos-aarch64", "windows-x86_64"],
                "sandboxed-profile-review-required",
                "committed-differential-corpus",
                &[],
                &[],
                &[],
                "The sandboxed profile is outside upstream-release-v1 and has no approved release evidence mapping.",
                "compatibility",
            );
        }
    }
    Ok((
        output,
        GeneratedRequirementsSummary {
            mapped_cells,
            referenced_cases: u64::try_from(referenced.len())
                .map_err(|_| "referenced case count overflow")?,
            conflicting_cells,
        },
    ))
}

fn portable_failure_gap_is_stale(
    builtin: &str,
    dimension: hell_builtins::CompatibilityDimension,
    observed: &std::collections::BTreeSet<String>,
) -> bool {
    hell_testkit::portable_native_oracle_failure_unavailable(builtin, dimension)
        && observed.contains("effect-failure")
}

fn target_supports_platform(
    platforms: &[hell_builtins::ClaimPlatform],
    platform: ConformancePlatform,
) -> bool {
    platforms.iter().any(|candidate| {
        matches!(
            (candidate, platform),
            (hell_builtins::ClaimPlatform::All, _)
                | (
                    hell_builtins::ClaimPlatform::Linux,
                    ConformancePlatform::LinuxX86_64
                )
                | (
                    hell_builtins::ClaimPlatform::MacOs,
                    ConformancePlatform::MacosAarch64
                )
                | (
                    hell_builtins::ClaimPlatform::Windows,
                    ConformancePlatform::WindowsX86_64
                )
        )
    })
}

#[allow(clippy::too_many_arguments)]
fn write_requirement_scope(
    output: &mut String,
    profiles: &[&str],
    platforms: &[&str],
    applicability_rule: &str,
    evidence_strategy: &str,
    evidence: &[String],
    normalizers: &[String],
    obligations: &[String],
    rationale: &str,
    review_group: &str,
) {
    write_toml_string_array(
        output,
        "profiles",
        &profiles
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>(),
    );
    write_toml_string_array(
        output,
        "platforms",
        &platforms
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>(),
    );
    writeln!(output, "applicability_rule = {applicability_rule:?}")
        .expect("writing to String cannot fail");
    writeln!(output, "evidence_strategy = {evidence_strategy:?}")
        .expect("writing to String cannot fail");
    write_toml_string_array(output, "evidence", evidence);
    write_toml_string_array(output, "normalizers", normalizers);
    write_toml_string_array(output, "obligations", obligations);
    writeln!(output, "rationale = {rationale:?}").expect("writing to String cannot fail");
    output.push_str("tracking_issue = \"COMPAT-EVIDENCE\"\n");
    writeln!(output, "review_group = {review_group:?}").expect("writing to String cannot fail");
}

fn write_toml_string_array(output: &mut String, key: &str, values: &[String]) {
    if values.is_empty() {
        writeln!(output, "{key} = []").expect("writing to String cannot fail");
        return;
    }
    writeln!(output, "{key} = [").expect("writing to String cannot fail");
    for value in values {
        writeln!(output, "  {value:?},").expect("writing to String cannot fail");
    }
    output.push_str("]\n");
}

const fn normalizer_replay_available(normalizer: hell_builtins::NormalizerId) -> bool {
    matches!(
        normalizer,
        hell_builtins::NormalizerId::DiagnosticSandboxPathV1
            | hell_builtins::NormalizerId::DiagnosticPathSeparatorV1
    )
}

struct AuditControlSummary {
    divergence_definitions_without_activation: u64,
    exemption_expiry_warnings: u64,
    release_exemptions: u64,
}

fn require_audit_control_inputs(root: &Path) -> Result<AuditControlSummary, String> {
    let controls: [(&str, &[u8]); 9] = [
        (
            ".github/release/conformance-exemptions.toml",
            include_bytes!("../../../../.github/release/conformance-exemptions.toml"),
        ),
        (
            "compat/builtin-registry.json",
            include_bytes!("../../../../compat/builtin-registry.json"),
        ),
        (
            "compat/claim-rules.toml",
            include_bytes!("../../../../compat/claim-rules.toml"),
        ),
        (
            "compat/corpus-obligations.toml",
            include_bytes!("../../../../compat/corpus-obligations.toml"),
        ),
        (
            "compat/divergences.toml",
            include_bytes!("../../../../compat/divergences.toml"),
        ),
        (
            "compat/expected-mismatches.toml",
            include_bytes!("../../../../compat/expected-mismatches.toml"),
        ),
        (
            "compat/normalizers.toml",
            include_bytes!("../../../../compat/normalizers.toml"),
        ),
        (
            "compat/requirements/2026-05-29.toml",
            include_bytes!("../../../../compat/requirements/2026-05-29.toml"),
        ),
        (
            "release-policy.toml",
            include_bytes!("../../../../release-policy.toml"),
        ),
    ];
    let mut observed = std::collections::BTreeMap::new();
    for (relative, compiled) in controls {
        let candidate = crate::release::manifest::read_regular(&root.join(relative))?;
        if candidate != compiled {
            return Err(format!(
                "audit control input {relative} differs from the catalog compiled into hell-ci"
            ));
        }
        observed.insert(relative, candidate);
    }
    inputs::verify_registry_manifest(&observed["compat/builtin-registry.json"])?;
    let exemptions =
        parse_release_exemptions(&observed[".github/release/conformance-exemptions.toml"])?;
    let today = current_utc_date()?;
    let exemption_expiry_warnings = exemptions
        .iter()
        .filter(|exemption| exemption.expires_on <= today)
        .count();
    let expected = std::str::from_utf8(&observed["compat/expected-mismatches.toml"])
        .map_err(|_| "expected mismatch catalog is not UTF-8".to_owned())?;
    let mut expected = crate::strict_toml::assignments(expected)?;
    if crate::strict_toml::take(&mut expected, "schema_version")? != "1"
        || crate::strict_toml::string(&crate::strict_toml::take(&mut expected, "baseline")?)?
            != "2026-05-29"
    {
        return Err("expected mismatch catalog header differs".to_owned());
    }
    let definitions =
        crate::strict_toml::string_array(&crate::strict_toml::take(&mut expected, "entries")?)?;
    if !expected.is_empty() {
        return Err("expected mismatch catalog has unknown fields".to_owned());
    }
    let activated = exemptions
        .iter()
        .filter_map(|exemption| exemption.expected_mismatch_sha256.as_deref())
        .collect::<std::collections::BTreeSet<_>>();
    let divergence_definitions_without_activation = definitions
        .iter()
        .filter(|definition| !activated.contains(definition.as_str()))
        .count();
    Ok(AuditControlSummary {
        divergence_definitions_without_activation: u64::try_from(
            divergence_definitions_without_activation,
        )
        .map_err(|_| "divergence definition count overflow")?,
        exemption_expiry_warnings: u64::try_from(exemption_expiry_warnings)
            .map_err(|_| "exemption warning count overflow")?,
        release_exemptions: u64::try_from(exemptions.len())
            .map_err(|_| "release exemption count overflow")?,
    })
}

pub(crate) fn audit_controls(root: &Path) -> Result<(), String> {
    require_audit_control_inputs(root).map(|_| ())
}

fn current_utc_date() -> Result<String, String> {
    const SECONDS_PER_DAY: u64 = 24 * 60 * 60;
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "system time precedes the Unix epoch")?
        .as_secs();
    let days = i64::try_from(seconds / SECONDS_PER_DAY)
        .map_err(|_| "system date exceeds the supported range")?;
    // Proleptic Gregorian conversion from days since the Unix epoch. This is
    // diagnostic clock use only; release expiry uses the trusted run instant.
    let shifted = days
        .checked_add(719_468)
        .ok_or_else(|| "system date exceeds the supported range".to_owned())?;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    let year = u64::try_from(year).map_err(|_| "system date year is negative")?;
    let month = u64::try_from(month).map_err(|_| "system date month is negative")?;
    let day = u64::try_from(day).map_err(|_| "system date day is negative")?;
    const YEAR_PATTERN: &str = "YYYY";
    const MONTH_PATTERN: &str = "MM";
    const DAY_PATTERN: &str = "DD";
    let date = format!(
        "{year:0year_width$}-{month:0month_width$}-{day:0day_width$}",
        year_width = YEAR_PATTERN.len(),
        month_width = MONTH_PATTERN.len(),
        day_width = DAY_PATTERN.len(),
    );
    ledger::validate_date(&date)?;
    Ok(date)
}

fn audit_scope_matches(
    scope: &hell_builtins::ScopedRequirement,
    profile: ProfileId,
    platform: ConformancePlatform,
) -> bool {
    scope.profiles.iter().any(|value| {
        matches!(
            (value, profile),
            (
                hell_builtins::ExecutionProfile::Upstream,
                ProfileId::Upstream
            ) | (
                hell_builtins::ExecutionProfile::Sandboxed,
                ProfileId::Sandboxed
            )
        )
    }) && scope.platforms.iter().any(|value| {
        matches!(
            (value, platform),
            (
                hell_builtins::RequirementPlatform::LinuxX86_64,
                ConformancePlatform::LinuxX86_64
            ) | (
                hell_builtins::RequirementPlatform::MacosAarch64,
                ConformancePlatform::MacosAarch64
            ) | (
                hell_builtins::RequirementPlatform::WindowsX86_64,
                ConformancePlatform::WindowsX86_64
            )
        )
    })
}

pub(crate) fn mutant_active(id: &str) -> bool {
    crate::mutation::active(id)
}

pub(crate) fn build_release_conformance_plan(
    candidate_sha: &str,
    workflow_sha: &str,
    release_evaluation_instant: &str,
    trusted_inputs_sha256: &str,
    source_inventory_sha256: &str,
    exemptions: Vec<PlannedExemption>,
) -> Result<ConformancePlan, String> {
    let requirements = hell_builtins::compatibility_requirements();
    hell_builtins::validate_compatibility_requirements(requirements)
        .map_err(|error| format!("invalid compatibility requirement catalog: {error:?}"))?;
    let mut exemption_by_cell = std::collections::BTreeMap::new();
    for exemption in exemptions {
        if exemption_by_cell
            .insert(exemption.cell.clone(), exemption)
            .is_some()
        {
            return Err("multiple release exemptions target one cell".to_owned());
        }
    }
    let committed_cases = hell_testkit::committed_differential_cases()
        .into_iter()
        .map(|case| (case.id.to_string(), case))
        .collect::<std::collections::BTreeMap<_, _>>();
    hell_testkit::validate_evidence_catalog(&committed_cases.values().cloned().collect::<Vec<_>>())
        .map_err(|error| format!("invalid committed conformance case catalog: {error}"))?;
    let mut cells = Vec::with_capacity(17_040);
    for requirement in requirements {
        let builtin = hell_builtins::registry()
            .get(usize::from(requirement.builtin.0))
            .ok_or_else(|| "requirement builtin is absent from registry".to_owned())?;
        for dimension in &requirement.dimensions {
            for profile in ProfileId::ALL {
                for platform in ConformancePlatform::ALL {
                    let scope = dimension
                        .scopes
                        .iter()
                        .find(|scope| {
                            scope.profiles.iter().any(|value| {
                                matches!(
                                    (value, profile),
                                    (
                                        hell_builtins::ExecutionProfile::Upstream,
                                        ProfileId::Upstream
                                    ) | (
                                        hell_builtins::ExecutionProfile::Sandboxed,
                                        ProfileId::Sandboxed
                                    )
                                )
                            }) && scope.platforms.iter().any(|value| {
                                matches!(
                                    (value, platform),
                                    (
                                        hell_builtins::RequirementPlatform::LinuxX86_64,
                                        ConformancePlatform::LinuxX86_64
                                    ) | (
                                        hell_builtins::RequirementPlatform::MacosAarch64,
                                        ConformancePlatform::MacosAarch64
                                    ) | (
                                        hell_builtins::RequirementPlatform::WindowsX86_64,
                                        ConformancePlatform::WindowsX86_64
                                    )
                                )
                            })
                        })
                        .ok_or_else(|| {
                            format!(
                                "requirement scope is missing for {} {} {} {}",
                                builtin.name,
                                dimension.dimension.as_str(),
                                profile.as_str(),
                                platform.as_str()
                            )
                        })?;
                    let key = CellKey::new(builtin.name, dimension.dimension, profile, platform)?;
                    let (disposition, obligations) = if profile == ProfileId::Sandboxed {
                        (
                            ScopeDisposition::Excluded {
                                scope_id: "upstream-release-v1-sandboxed".to_owned(),
                                rationale: "The sandboxed profile is outside upstream-release-v1."
                                    .to_owned(),
                            },
                            Vec::new(),
                        )
                    } else {
                        let obligation_ids = if scope.obligations.is_empty() {
                            vec!["unmapped-release-evidence"]
                        } else {
                            scope.obligations.to_vec()
                        };
                        let strategy = match scope.strategy {
                            hell_builtins::RequirementStrategy::NativeOracle => {
                                EvidenceStrategy::NativeOracle
                            }
                            hell_builtins::RequirementStrategy::PortableStatic => {
                                EvidenceStrategy::PortableStatic
                            }
                            hell_builtins::RequirementStrategy::StructuralInvariant => {
                                EvidenceStrategy::StructuralInvariant
                            }
                            hell_builtins::RequirementStrategy::CommittedDifferentialCorpus => {
                                EvidenceStrategy::CommittedDifferentialCorpus
                            }
                            hell_builtins::RequirementStrategy::CrossPlatformRelation => {
                                EvidenceStrategy::CrossPlatformRelation
                            }
                        };
                        let normalizers = scope
                            .normalizers
                            .iter()
                            .map(|normalizer| normalizer.as_str().to_owned())
                            .collect::<Vec<_>>();
                        let referenced_cases = scope
                            .evidence
                            .iter()
                            .map(|reference| {
                                let case_id =
                                    hell_builtins::parse_differential_reference(reference)
                                        .map_err(|_| {
                                            format!("invalid differential reference {reference:?}")
                                        })?
                                        .case_id;
                                let case = committed_cases.get(case_id).ok_or_else(|| {
                                    format!(
                                        "requirement references unknown committed case {case_id:?}"
                                    )
                                })?;
                                Ok(((*case_id).to_owned(), case))
                            })
                            .collect::<Result<Vec<_>, String>>()?;
                        for (case_id, case) in &referenced_cases {
                            if !obligation_ids.iter().any(|obligation| {
                                case_authorizes(case, &key, obligation, &normalizers)
                            }) {
                                return Err(format!(
                                    "requirement case {case_id:?} does not authorize any declared obligation for {key}"
                                ));
                            }
                        }
                        (
                            ScopeDisposition::Required {
                                decision_id: scope.applicability_rule.to_owned(),
                            },
                            obligation_ids
                                .into_iter()
                                .map(|id| {
                                    let cases = referenced_cases
                                        .iter()
                                        .filter(|(_, case)| {
                                            case_authorizes(case, &key, id, &normalizers)
                                        })
                                        .map(|(case_id, case)| {
                                            (
                                                case_id.clone(),
                                                hell_testkit::case_descriptor_sha256(case).hex(),
                                            )
                                        })
                                        .collect::<std::collections::BTreeMap<_, _>>();
                                    PlannedObligation {
                                        id: id.to_owned(),
                                        strategy,
                                        case_ids: referenced_cases
                                            .iter()
                                            .filter(|(_, case)| {
                                                case_authorizes(case, &key, id, &normalizers)
                                            })
                                            .map(|(case_id, _)| case_id.clone())
                                            .collect(),
                                        case_descriptor_sha256: cases,
                                        allowed_normalizers: normalizers.clone(),
                                    }
                                })
                                .collect(),
                        )
                    };
                    let exemption = exemption_by_cell.remove(&key);
                    cells.push(PlannedCell {
                        key,
                        scope: disposition,
                        obligations,
                        exemption,
                    });
                }
            }
        }
    }
    if !exemption_by_cell.is_empty() {
        return Err("release exemption targets a cell outside the canonical universe".to_owned());
    }
    let mut plan = ConformancePlan {
        standard: RELEASE_STANDARD.to_owned(),
        candidate_sha: candidate_sha.to_owned(),
        workflow_sha: workflow_sha.to_owned(),
        release_evaluation_instant: release_evaluation_instant.to_owned(),
        trusted_inputs_sha256: trusted_inputs_sha256.to_owned(),
        source_inventory_sha256: source_inventory_sha256.to_owned(),
        baseline: requirements
            .first()
            .ok_or_else(|| "requirement catalog is empty".to_owned())?
            .baseline
            .to_owned(),
        exploratory_generator_version: EXPLORATORY_GENERATOR_VERSION.to_owned(),
        exploratory_generator_seed: EXPLORATORY_GENERATOR_SEED,
        exploratory_generator_count_per_platform: u64::try_from(EXPLORATORY_GENERATOR_COUNT)
            .map_err(|_| "exploratory generator count overflow")?,
        generated_agreement_may_verify: GENERATED_AGREEMENT_MAY_VERIFY,
        generated_mismatch_blocks: GENERATED_MISMATCH_BLOCKS,
        cells,
        plan_sha256: String::new(),
    };
    plan.plan_sha256 = hell_testkit::sha256_bytes(&crate::json::canonical_json_bytes(
        &plan.json_without_digest(),
    )?)
    .hex();
    plan.validate(&canonical_universe()?)?;
    validate_plan_case_authority(&plan)?;
    Ok(plan)
}

fn case_authorizes(
    case: &hell_testkit::DifferentialCase,
    key: &CellKey,
    obligation: &str,
    normalizers: &[String],
) -> bool {
    let Some(descriptor) = &case.claim_evidence else {
        return false;
    };
    let profile_matches = matches!(
        (descriptor.profile, key.profile),
        (
            hell_builtins::ExecutionProfile::Upstream,
            ProfileId::Upstream
        ) | (
            hell_builtins::ExecutionProfile::Sandboxed,
            ProfileId::Sandboxed
        )
    );
    let normalizers_match = descriptor
        .claim_normalizers
        .iter()
        .map(|value| value.as_str())
        .eq(normalizers.iter().map(String::as_str));
    profile_matches
        && normalizers_match
        && descriptor.semantic_targets.iter().any(|target| {
            target.builtin.as_ref() == key.builtin
                && target.dimension == key.dimension
                && target
                    .obligations
                    .iter()
                    .any(|value| value.0.as_ref() == obligation)
                && target.platforms.iter().any(|platform| {
                    matches!(
                        (platform, key.platform),
                        (hell_builtins::ClaimPlatform::All, _)
                            | (
                                hell_builtins::ClaimPlatform::Linux,
                                ConformancePlatform::LinuxX86_64
                            )
                            | (
                                hell_builtins::ClaimPlatform::MacOs,
                                ConformancePlatform::MacosAarch64
                            )
                            | (
                                hell_builtins::ClaimPlatform::Windows,
                                ConformancePlatform::WindowsX86_64
                            )
                    )
                })
        })
}

pub(crate) fn validate_plan_case_authority(plan: &ConformancePlan) -> Result<(), String> {
    let committed = hell_testkit::committed_differential_cases()
        .into_iter()
        .map(|case| (case.id.to_string(), case))
        .collect::<std::collections::BTreeMap<_, _>>();
    for cell in &plan.cells {
        for obligation in &cell.obligations {
            for case_id in &obligation.case_ids {
                let case = committed.get(case_id).ok_or_else(|| {
                    format!("planned case {case_id:?} is absent from the trusted case catalog")
                })?;
                let descriptor = case.claim_evidence.as_ref().ok_or_else(|| {
                    format!("planned case {case_id:?} has no reviewed claim descriptor")
                })?;
                let profile_matches = matches!(
                    (descriptor.profile, cell.key.profile),
                    (
                        hell_builtins::ExecutionProfile::Upstream,
                        ProfileId::Upstream
                    ) | (
                        hell_builtins::ExecutionProfile::Sandboxed,
                        ProfileId::Sandboxed
                    )
                );
                let target_matches = descriptor.semantic_targets.iter().any(|target| {
                    target.builtin.as_ref() == cell.key.builtin
                        && target.dimension == cell.key.dimension
                        && target
                            .obligations
                            .iter()
                            .any(|value| value.0.as_ref() == obligation.id)
                        && target.platforms.iter().any(|platform| {
                            matches!(
                                (platform, cell.key.platform),
                                (hell_builtins::ClaimPlatform::All, _)
                                    | (
                                        hell_builtins::ClaimPlatform::Linux,
                                        ConformancePlatform::LinuxX86_64
                                    )
                                    | (
                                        hell_builtins::ClaimPlatform::MacOs,
                                        ConformancePlatform::MacosAarch64
                                    )
                                    | (
                                        hell_builtins::ClaimPlatform::Windows,
                                        ConformancePlatform::WindowsX86_64
                                    )
                            )
                        })
                });
                if !profile_matches || !target_matches {
                    return Err(format!(
                        "planned case {case_id:?} does not authorize {}/{}/{}/{}/{}",
                        cell.key.builtin,
                        cell.key.dimension.as_str(),
                        cell.key.profile.as_str(),
                        cell.key.platform.as_str(),
                        obligation.id
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Constructs the exact registry × dimension × profile × platform universe.
pub(crate) fn canonical_universe() -> Result<Vec<CellKey>, String> {
    let mut cells = Vec::new();
    for builtin in hell_builtins::registry() {
        for dimension in hell_builtins::CompatibilityDimension::ALL {
            for profile in ProfileId::ALL {
                for platform in ConformancePlatform::ALL {
                    cells.push(CellKey::new(builtin.name, dimension, profile, platform)?);
                }
            }
        }
    }
    Ok(cells)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonrelease_audit_projects_an_exact_disjoint_partition() {
        let candidate_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("hell-ci crate is below the workspace root");
        let output = std::env::temp_dir().join(format!(
            "hell-conformance-audit-{}-{}.json",
            std::process::id(),
            crate::test_thread_name_component(std::thread::current().name())
        ));
        let message = audit(candidate_root.to_owned(), output.clone()).unwrap();
        assert!(message.contains("8520 projected blockers"));
        let document = std::fs::read_to_string(&output).unwrap();
        let report = crate::json::parse_json(&document).unwrap();
        let report = report.object().unwrap();
        assert_eq!(
            crate::json::json_member(report, "auditState")
                .unwrap()
                .string()
                .unwrap(),
            "nonrelease-review-required"
        );
        assert_eq!(
            crate::json::json_member(report, "totalCells")
                .unwrap()
                .number()
                .unwrap(),
            17_040
        );
        let partition = crate::json::json_member(report, "projectedPartition")
            .unwrap()
            .object()
            .unwrap();
        let projected_total = [
            "blockedInvalid",
            "blockedMismatch",
            "blockedMissingEvidence",
            "excluded",
            "exempted",
            "notApplicable",
            "verified",
            "verifiedNormalized",
        ]
        .into_iter()
        .map(|key| {
            crate::json::json_member(partition, key)
                .unwrap()
                .number()
                .unwrap()
        })
        .sum::<u64>();
        assert_eq!(projected_total, 17_040);
        std::fs::remove_file(output).unwrap();
    }

    #[test]
    fn descriptor_mapping_generation_is_deterministic_complete_and_reviewable() {
        let (first, summary) = generated_requirements_catalog().unwrap();
        let (second, repeated) = generated_requirements_catalog().unwrap();
        assert_eq!(first, second);
        assert_eq!(summary.mapped_cells, 2_265);
        assert_eq!(summary.referenced_cases, 2_644);
        assert_eq!(summary.conflicting_cells, 0);
        assert_eq!(summary.mapped_cells, repeated.mapped_cells);
        assert_eq!(summary.referenced_cases, repeated.referenced_cases);
        assert_eq!(summary.conflicting_cells, repeated.conflicting_cells);
        assert_eq!(
            first.as_bytes(),
            include_bytes!("../../../../compat/requirements/2026-05-29.toml")
        );
        hell_builtins::validate_compatibility_requirements(
            hell_builtins::compatibility_requirements(),
        )
        .unwrap();
        assert!(first.contains("builtin = \"List.all\"\n"));
        assert!(first.contains("  \"three-platform-observation\",\n"));
        assert!(first.contains("  \"effect-success\",\n"));
        assert!(first.contains("  \"task-lifecycle\",\n"));
        assert!(first.contains("  \"raw-observation\",\n"));
        assert!(first.contains("  \"resource-audit\",\n"));
        assert_eq!(
            first
                .matches("applicability_rule = \"portable-native-oracle-host-failure-unavailable\"")
                .count(),
            2
        );
        assert!(first.contains("differential:runtime-current-directory-upstream-available"));
        assert!(first.contains("differential:runtime-directory-get-home-platform-fallback"));
        assert!(!first.contains("runtime-current-directory-sandbox-denied"));
    }

    #[test]
    fn portable_directory_failure_gaps_retain_full_blocking_obligations() {
        let plan = build_release_conformance_plan(
            &"a".repeat(40),
            &"b".repeat(40),
            "2026-08-13T00:00:00Z",
            &"c".repeat(64),
            &"d".repeat(64),
            Vec::new(),
        )
        .unwrap();
        for builtin in [
            "Directory.getCurrentDirectory",
            "Directory.getHomeDirectory",
        ] {
            for platform in ConformancePlatform::ALL {
                let cell = plan
                    .cells
                    .iter()
                    .find(|cell| {
                        cell.key.builtin == builtin
                            && cell.key.dimension == hell_builtins::CompatibilityDimension::Effects
                            && cell.key.profile == ProfileId::Upstream
                            && cell.key.platform == platform
                    })
                    .unwrap_or_else(|| panic!("missing portable failure-gap cell {builtin}"));
                assert_eq!(
                    cell.scope,
                    ScopeDisposition::Required {
                        decision_id: "portable-native-oracle-host-failure-unavailable".to_owned(),
                    }
                );
                let obligation = |id: &str| {
                    cell.obligations
                        .iter()
                        .find(|obligation| obligation.id == id)
                        .unwrap_or_else(|| panic!("missing {builtin} obligation {id}"))
                };
                assert!(!obligation("effect-success").case_ids.is_empty());
                assert!(!obligation("effect-ordering").case_ids.is_empty());
                assert!(obligation("effect-failure").case_ids.is_empty());
            }
        }
    }

    #[test]
    fn home_directory_environment_probes_authorize_the_exact_windows_plan_obligations() {
        let plan = build_release_conformance_plan(
            &"a".repeat(40),
            &"b".repeat(40),
            "2026-08-13T00:00:00Z",
            &"c".repeat(64),
            &"d".repeat(64),
            Vec::new(),
        )
        .unwrap();
        for (dimension, obligations) in [
            (
                hell_builtins::CompatibilityDimension::PureRuntime,
                &["adapter-success"][..],
            ),
            (
                hell_builtins::CompatibilityDimension::Effects,
                &["effect-success", "effect-ordering"][..],
            ),
            (
                hell_builtins::CompatibilityDimension::Platform,
                &["three-platform-observation"][..],
            ),
            (
                hell_builtins::CompatibilityDimension::ResourceBehavior,
                &["resource-audit"][..],
            ),
        ] {
            let cell = plan
                .cells
                .iter()
                .find(|cell| {
                    cell.key.builtin == "Directory.getHomeDirectory"
                        && cell.key.dimension == dimension
                        && cell.key.profile == ProfileId::Upstream
                        && cell.key.platform == ConformancePlatform::WindowsX86_64
                })
                .expect("Windows home-directory plan cell");
            for obligation in obligations {
                let case_ids = &cell
                    .obligations
                    .iter()
                    .find(|planned| planned.id == *obligation)
                    .unwrap_or_else(|| panic!("missing home-directory obligation {obligation}"))
                    .case_ids;
                for case_id in [
                    "runtime-directory-get-home-home-a",
                    "runtime-directory-get-home-home-b",
                ] {
                    assert!(
                        case_ids.iter().any(|candidate| candidate == case_id),
                        "{obligation}: {case_id}"
                    );
                }
            }
        }
    }

    #[test]
    fn future_portable_directory_failure_evidence_makes_the_gap_marker_stale() {
        let failure = std::collections::BTreeSet::from(["effect-failure".to_owned()]);
        let success = std::collections::BTreeSet::from(["effect-success".to_owned()]);
        for builtin in [
            "Directory.getCurrentDirectory",
            "Directory.getHomeDirectory",
        ] {
            assert!(portable_failure_gap_is_stale(
                builtin,
                hell_builtins::CompatibilityDimension::Effects,
                &failure
            ));
            assert!(!portable_failure_gap_is_stale(
                builtin,
                hell_builtins::CompatibilityDimension::Effects,
                &success
            ));
        }
        assert!(!portable_failure_gap_is_stale(
            "Directory.setCurrentDirectory",
            hell_builtins::CompatibilityDimension::Effects,
            &failure
        ));
    }

    #[test]
    fn reviewed_registry_expands_to_exact_release_universe() {
        let universe = canonical_universe().unwrap();
        assert_eq!(hell_builtins::registry().len(), 355);
        assert_eq!(universe.len(), 17_040);
        assert_eq!(
            universe.first().unwrap().builtin,
            hell_builtins::registry()[0].name
        );
        assert_eq!(
            universe.last().unwrap().builtin,
            hell_builtins::registry().last().unwrap().name
        );
    }

    #[test]
    fn release_plan_materializes_every_cell_fail_closed() {
        let plan = build_release_conformance_plan(
            &"a".repeat(40),
            &"b".repeat(40),
            "2026-08-13T00:00:00Z",
            &"c".repeat(64),
            &"d".repeat(64),
            Vec::new(),
        )
        .unwrap();
        assert_eq!(plan.cells.len(), 17_040);
        assert_eq!(
            plan.cells
                .iter()
                .filter(|cell| matches!(cell.scope, ScopeDisposition::Required { .. }))
                .count(),
            8_520
        );
        assert!(
            plan.cells
                .iter()
                .filter(|cell| matches!(cell.scope, ScopeDisposition::Required { .. }))
                .all(|cell| !cell.obligations.is_empty())
        );
        let mut omitted = plan.clone();
        omitted.cells.pop();
        assert!(omitted.validate(&canonical_universe().unwrap()).is_err());
        let candidate_executable_sha256 = ConformancePlatform::ALL
            .into_iter()
            .map(|platform| (platform, "e".repeat(64)))
            .collect();
        let oracle = ConformancePlatform::ALL
            .into_iter()
            .map(|platform| {
                (
                    platform,
                    OracleBinding {
                        repository: "chrisdone/hell".to_owned(),
                        commit: "f".repeat(40),
                        executable_sha256: "6".repeat(64),
                        source_sha256: "7".repeat(64),
                    },
                )
            })
            .collect();
        let trusted = TrustedEvidenceBindings::from_platform_identities(
            "8".repeat(64),
            &plan,
            candidate_executable_sha256,
            oracle,
        )
        .unwrap();
        let partition = derive_partition(
            &plan,
            &canonical_universe().unwrap(),
            &EvidenceRepository::default(),
            &trusted,
        )
        .unwrap();
        let counts = partition.counts().unwrap();
        assert_eq!(counts.blocked_missing_evidence, 8_520);
        assert_eq!(counts.excluded, 8_520);
        assert_eq!(counts.total(), 17_040);
    }

    #[test]
    fn committed_case_descriptor_cannot_authorize_an_unrelated_cell() {
        let case = hell_testkit::committed_differential_cases()
            .into_iter()
            .find(|case| {
                case.claim_evidence.as_ref().is_some_and(|descriptor| {
                    descriptor.semantic_targets.iter().any(|target| {
                        !target.obligations.is_empty() && !target.platforms.is_empty()
                    })
                })
            })
            .unwrap();
        let descriptor = case.claim_evidence.as_ref().unwrap();
        let target = descriptor
            .semantic_targets
            .iter()
            .find(|target| !target.obligations.is_empty() && !target.platforms.is_empty())
            .unwrap();
        let wrong_builtin = hell_builtins::registry()
            .iter()
            .find(|builtin| builtin.name != target.builtin.as_ref())
            .unwrap()
            .name;
        let platform = match target.platforms[0] {
            hell_builtins::ClaimPlatform::All | hell_builtins::ClaimPlatform::Linux => {
                ConformancePlatform::LinuxX86_64
            }
            hell_builtins::ClaimPlatform::MacOs => ConformancePlatform::MacosAarch64,
            hell_builtins::ClaimPlatform::Windows => ConformancePlatform::WindowsX86_64,
        };
        let profile = match descriptor.profile {
            hell_builtins::ExecutionProfile::Upstream => ProfileId::Upstream,
            hell_builtins::ExecutionProfile::Sandboxed => ProfileId::Sandboxed,
        };
        let plan = ConformancePlan {
            standard: RELEASE_STANDARD.to_owned(),
            candidate_sha: "a".repeat(40),
            workflow_sha: "b".repeat(40),
            release_evaluation_instant: "2026-08-13T00:00:00Z".to_owned(),
            trusted_inputs_sha256: "c".repeat(64),
            source_inventory_sha256: "d".repeat(64),
            baseline: "2026-05-29".to_owned(),
            exploratory_generator_version: EXPLORATORY_GENERATOR_VERSION.to_owned(),
            exploratory_generator_seed: EXPLORATORY_GENERATOR_SEED,
            exploratory_generator_count_per_platform: 32,
            generated_agreement_may_verify: GENERATED_AGREEMENT_MAY_VERIFY,
            generated_mismatch_blocks: GENERATED_MISMATCH_BLOCKS,
            cells: vec![PlannedCell {
                key: CellKey::new(wrong_builtin, target.dimension, profile, platform).unwrap(),
                scope: ScopeDisposition::Required {
                    decision_id: "applicable".to_owned(),
                },
                obligations: vec![PlannedObligation {
                    id: target.obligations[0].0.to_string(),
                    strategy: EvidenceStrategy::NativeOracle,
                    case_ids: vec![case.id.to_string()],
                    case_descriptor_sha256: std::collections::BTreeMap::from([(
                        case.id.to_string(),
                        hell_testkit::case_descriptor_sha256(&case).hex(),
                    )]),
                    allowed_normalizers: Vec::new(),
                }],
                exemption: None,
            }],
            plan_sha256: "e".repeat(64),
        };
        assert!(validate_plan_case_authority(&plan).is_err());
    }
}
