use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use hell_builtins::{ClaimStatus, CompatibilityDimension, ExecutionProfile};
use hell_compiler::{CompilerConfig, CompilerSession};
use hell_source::{SourceMap, SourceName};
use hell_testkit::{
    ClassifiedMismatch, CollectionBlackBoxShard, CollectionDependencyAuthority,
    CollectionNativeBuildAuthority, CollectionOracleSubject, DeterministicBytes, DeterministicUtf8,
    DifferentialCase, Digest, DivergenceClass, EvidenceSummary, ExecutableIdentity, ExecutableRole,
    GeneratedCase, NATIVE_BUILD_ENVIRONMENT_NAMES, NativeExecutionEnvironment,
    NativeExecutionEnvironmentInputs, ReleaseGateInput, ReleaseGateReport, RuntimePlatformShard,
    bind_process_helper_directory, collection_bundle_facts, committed_differential_cases,
    differential_with_identities, evaluate_release_gate, generated_typed_cases,
    observe_verified_executable_profile, retain_mismatch_bundle, retain_observation_bundle,
    retain_verified_profile_observation, reviewed_collection_cases,
    runtime_platform_shard_for_bundle, sha256_bytes, sha256_file,
    validate_collection_black_box_structure, validate_evidence_catalog,
    validate_runtime_obligation_coverage, validate_runtime_platform_set,
    verify_collection_source_authority, verify_executable, verify_observation_bundle_for_case,
    verify_retained_native_environment, write_evidence_summary,
};

use crate::command::{CommandResult, CommandSpec};
use crate::fixtures;
use crate::oracle_record;
use crate::policy;
use crate::promotion_policy;
use crate::report::Report;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureKind {
    Policy,
    Child,
    Fixture,
    Io,
}

#[derive(Debug)]
struct SuiteFailure {
    kind: FailureKind,
    detail: String,
}

impl SuiteFailure {
    fn fixture(detail: impl Into<String>) -> Self {
        Self {
            kind: FailureKind::Fixture,
            detail: detail.into(),
        }
    }

    fn io(action: &str, path: &Path, error: &std::io::Error) -> Self {
        Self {
            kind: FailureKind::Io,
            detail: format!("cannot {action} {}: {error}", path.display()),
        }
    }
}

pub fn policy_suite(root: &Path, report: &mut Report) -> Result<(), FailureKind> {
    let started = Instant::now();
    let result = policy::check_repository(root)
        .and_then(|()| {
            hell_builtins::validate_compatibility_claims(hell_builtins::compatibility_claims())
                .map_err(|error| format!("compatibility claims are invalid: {error:?}"))
        })
        .and_then(|()| promotion_policy::load(root).map(|_| ()))
        .and_then(|()| promotion_policy::load_review(root).map(|_| ()))
        .and_then(|()| oracle_record::load_all(root).map(|_| ()))
        .and_then(|()| {
            let path = root.join("compat").join("upstream-2026-05-29.json");
            let expected = fs::read_to_string(&path)
                .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
            hell_docgen::verify_compatibility_snapshot(&expected).map_err(|mismatch| {
                format!(
                    "compatibility snapshot is stale at byte {}",
                    mismatch.first_differing_byte
                )
            })
        });
    let passed = result.is_ok();
    report.check("repository-policy", started.elapsed(), result);
    passed.then_some(()).ok_or(FailureKind::Policy)
}

/// Writes a dependency-policy success attestation after the pinned external
/// dependency gate has completed successfully.
pub fn dependency_attestation(
    root: &Path,
    output: &Path,
    report: &mut Report,
) -> Result<(), FailureKind> {
    let started = Instant::now();
    let result = (|| {
        let source_commit = std::env::var("HELL_SOURCE_COMMIT")
            .map_err(|_| "HELL_SOURCE_COMMIT is required for dependency attestation".to_owned())?;
        promotion_policy::require_git_sha(&source_commit, "dependency attestation source commit")?;
        let cargo_lock = root.join("Cargo.lock");
        let lock_sha256 = sha256_file(&cargo_lock)
            .map_err(|error| format!("cannot hash {}: {error}", cargo_lock.display()))?;
        let contents = dependency_attestation_json(&source_commit, lock_sha256);
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
        }
        fs::write(output, contents.as_bytes())
            .map_err(|error| format!("cannot write {}: {error}", output.display()))?;
        let digest = sha256_bytes(contents.as_bytes()).hex();
        let digest_path = output.with_extension("sha256");
        let name = output
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| "dependency attestation output name must be UTF-8".to_owned())?;
        fs::write(&digest_path, format!("{digest}  {name}\n"))
            .map_err(|error| format!("cannot write {}: {error}", digest_path.display()))
    })();
    let passed = result.is_ok();
    report.check("dependency-attestation", started.elapsed(), result);
    passed.then_some(()).ok_or(FailureKind::Fixture)
}

/// Emits a deterministic reviewer worklist without modifying claim source.
#[allow(clippy::too_many_lines)]
pub fn promotion_worklist(
    root: &Path,
    output: &Path,
    profile: &str,
    format: &str,
    only: &str,
    group_by: &str,
    report: &mut Report,
) -> Result<(), FailureKind> {
    let started = Instant::now();
    let result = (|| {
        if profile != "upstream" {
            return Err(format!(
                "unsupported promotion worklist profile {profile:?}"
            ));
        }
        let policy = promotion_policy::load(root)?;
        if policy.required_profiles != [hell_builtins::ExecutionProfile::Upstream] {
            return Err("promotion worklist profile disagrees with policy".to_owned());
        }
        let headers = [
            "builtin_id",
            "builtin",
            "visibility",
            "scheme",
            "arity",
            "implementation",
            "semantic_family",
            "effect_kind",
            "capabilities",
            "source_reachability",
            "dimension",
            "profile",
            "required_platform_cells",
            "current_status",
            "applicability_rule",
            "applicability_result",
            "applicability_confidence",
            "proposed_status",
            "required_obligations",
            "satisfied_obligations",
            "missing_obligations",
            "evidence_references",
            "normalizers",
            "normalizer_audit_status",
            "divergence_id",
            "catalog_target_exists",
            "resolved_builtin_observed",
            "runtime_adapter_observed",
            "effect_event_observed",
            "resource_event_observed",
            "observed_on_linux",
            "observed_on_macos",
            "observed_on_windows",
            "boundary_classes_covered",
            "boundary_classes_required",
            "mutation_score",
            "residual_risk_tier",
            "review_group",
            "rationale",
            "issue",
            "review_decision",
            "reviewer_notes",
        ];
        let committed = hell_testkit::committed_differential_cases();
        let mut rows = Vec::<Vec<String>>::new();
        for (spec, claim) in hell_builtins::registry()
            .iter()
            .zip(hell_builtins::compatibility_claims())
        {
            for dimension in &claim.dimensions {
                for scope in dimension.scopes.iter().filter(|scope| {
                    scope
                        .profiles
                        .contains(&hell_builtins::ExecutionProfile::Upstream)
                }) {
                    let platforms = scope
                        .platforms
                        .iter()
                        .map(|platform| claim_platform_name(*platform))
                        .collect::<Vec<_>>()
                        .join(";");
                    let mut evidence = scope
                        .evidence
                        .iter()
                        .map(|reference| (*reference).to_owned())
                        .collect::<BTreeSet<_>>();
                    let normalizers = scope
                        .normalizers
                        .iter()
                        .map(|normalizer| normalizer.as_str())
                        .collect::<Vec<_>>()
                        .join(";");
                    let (_, applicability_result, applicability_confidence) =
                        worklist_applicability(spec, dimension.dimension);
                    let applicability_rule = scope.applicability_rule;
                    let required_obligations = if scope.obligations.is_empty() {
                        worklist_obligations(dimension.dimension)
                    } else {
                        scope.obligations.join(";")
                    };
                    let semantic_targets = committed
                        .iter()
                        .flat_map(|case| {
                            case.claim_evidence.iter().flat_map(move |descriptor| {
                                descriptor
                                    .semantic_targets
                                    .iter()
                                    .filter_map(move |target| {
                                        (target.builtin.as_ref() == spec.name
                                            && target.dimension == dimension.dimension)
                                            .then_some((case.id.as_ref(), target))
                                    })
                            })
                        })
                        .collect::<Vec<_>>();
                    let observed_obligations = semantic_targets
                        .iter()
                        .flat_map(|(_, target)| {
                            target
                                .obligations
                                .iter()
                                .map(|obligation| obligation.0.as_ref())
                        })
                        .collect::<BTreeSet<_>>();
                    let catalog_target_exists = !semantic_targets.is_empty()
                        && scope
                            .obligations
                            .iter()
                            .all(|obligation| observed_obligations.contains(obligation));
                    for (case_id, _) in &semantic_targets {
                        evidence.insert(format!("case:{case_id}@not-collected"));
                    }
                    let evidence = evidence.into_iter().collect::<Vec<_>>().join(";");
                    let metadata = spec.assurance_metadata();
                    let capabilities = metadata
                        .capabilities
                        .iter()
                        .map(|capability| format!("{capability:?}").to_ascii_lowercase())
                        .collect::<Vec<_>>()
                        .join(";");
                    let fields = vec![
                        spec.id.0.to_string(),
                        spec.name.to_owned(),
                        format!("{:?}", spec.visibility),
                        spec.scheme.unwrap_or_default().to_owned(),
                        spec.arity.to_string(),
                        spec.implementation.unwrap_or_default().to_owned(),
                        metadata.semantic_family.to_owned(),
                        format!("{:?}", metadata.effect_kind).to_ascii_lowercase(),
                        capabilities,
                        format!("{:?}", metadata.source_reachability).to_ascii_lowercase(),
                        dimension.dimension.as_str().to_owned(),
                        profile.to_owned(),
                        platforms,
                        claim_status_name(scope.status).to_owned(),
                        applicability_rule.to_owned(),
                        applicability_result.to_owned(),
                        applicability_confidence.to_owned(),
                        "unverified".to_owned(),
                        required_obligations.clone(),
                        String::new(),
                        required_obligations,
                        evidence,
                        normalizers,
                        "review-required".to_owned(),
                        String::new(),
                        catalog_target_exists.to_string(),
                        "not-collected".to_owned(),
                        "not-collected".to_owned(),
                        "not-collected".to_owned(),
                        "not-collected".to_owned(),
                        "not-collected".to_owned(),
                        "not-collected".to_owned(),
                        "not-collected".to_owned(),
                        "0".to_owned(),
                        worklist_boundary_requirement(dimension.dimension).to_owned(),
                        "not-collected".to_owned(),
                        "unacceptable".to_owned(),
                        scope.review_group.unwrap_or_default().to_owned(),
                        scope.rationale.unwrap_or_default().to_owned(),
                        scope.issue.unwrap_or_default().to_owned(),
                        "pending".to_owned(),
                        String::new(),
                    ];
                    rows.push(fields);
                }
            }
        }
        let applicability_index = headers
            .iter()
            .position(|header| *header == "applicability_result")
            .ok_or_else(|| "worklist lacks applicability_result".to_owned())?;
        if only == "ambiguous" {
            rows.retain(|row| row[applicability_index] == "ambiguous-needs-review");
        } else if only != "all" {
            return Err(format!("unsupported promotion worklist filter {only:?}"));
        }
        let review_group_index = headers
            .iter()
            .position(|header| *header == "review_group")
            .ok_or_else(|| "worklist lacks review_group".to_owned())?;
        if !matches!(group_by, "builtin" | "assurance-equivalence") {
            return Err(format!(
                "unsupported promotion worklist grouping {group_by:?}"
            ));
        }
        rows.sort_by(|left, right| {
            let grouping = if group_by == "assurance-equivalence" {
                left[review_group_index].cmp(&right[review_group_index])
            } else {
                std::cmp::Ordering::Equal
            };
            grouping.then_with(|| {
                left[0]
                    .parse::<u16>()
                    .unwrap_or(u16::MAX)
                    .cmp(&right[0].parse::<u16>().unwrap_or(u16::MAX))
                    .then_with(|| {
                        worklist_dimension_order(&left[10])
                            .cmp(&worklist_dimension_order(&right[10]))
                    })
                    .then_with(|| left[11].cmp(&right[11]))
                    .then_with(|| left[12].cmp(&right[12]))
            })
        });
        let contents = match format {
            "csv" => worklist_csv(&headers, &rows),
            "json" => worklist_json(&headers, &rows),
            "html" => worklist_html(&headers, &rows),
            value => return Err(format!("unsupported promotion worklist format {value:?}")),
        };
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
        }
        fs::write(output, contents)
            .map_err(|error| format!("cannot write {}: {error}", output.display()))
    })();
    let passed = result.is_ok();
    report.check("promotion-worklist", started.elapsed(), result);
    passed.then_some(()).ok_or(FailureKind::Fixture)
}

fn worklist_applicability(
    spec: &hell_builtins::BuiltinSpec,
    dimension: hell_builtins::CompatibilityDimension,
) -> (&'static str, &'static str, &'static str) {
    use hell_builtins::assurance_catalogs as catalog;
    use hell_builtins::{AssuranceCapability, AssuranceSensitivity, EffectKind};
    let metadata = spec.assurance_metadata();
    match dimension {
        hell_builtins::CompatibilityDimension::Parse
            if spec.visibility == hell_builtins::Visibility::Public =>
        {
            (
                "parse-public-source-name",
                catalog::PUBLIC_PARSE_DECISION,
                "mechanical",
            )
        }
        hell_builtins::CompatibilityDimension::StaticSemantics => (
            "static-registry-participation",
            catalog::STATIC_SEMANTICS_DECISION,
            "mechanical",
        ),
        hell_builtins::CompatibilityDimension::PureRuntime if spec.implementation.is_some() => (
            "implemented-runtime-adapter",
            catalog::PURE_RUNTIME_DECISION,
            "family-default",
        ),
        hell_builtins::CompatibilityDimension::Effects
            if metadata.effect_kind == EffectKind::Io =>
        {
            (
                "effect-family-default",
                catalog::EFFECTS_DECISION,
                "family-default",
            )
        }
        hell_builtins::CompatibilityDimension::Concurrency
            if metadata
                .capabilities
                .contains(&AssuranceCapability::Concurrency) =>
        {
            (
                "concurrency-family-default",
                catalog::CONCURRENCY_DECISION,
                "family-default",
            )
        }
        hell_builtins::CompatibilityDimension::Presentation
            if metadata
                .sensitivities
                .contains(&AssuranceSensitivity::Presentation) =>
        {
            (
                "presentation-family-default",
                catalog::PRESENTATION_DECISION,
                "family-default",
            )
        }
        hell_builtins::CompatibilityDimension::Platform
            if metadata
                .sensitivities
                .contains(&AssuranceSensitivity::Platform) =>
        {
            (
                "platform-family-default",
                catalog::PLATFORM_DECISION,
                "family-default",
            )
        }
        hell_builtins::CompatibilityDimension::ResourceBehavior
            if metadata
                .sensitivities
                .contains(&AssuranceSensitivity::Resource) =>
        {
            (
                "resource-family-default",
                catalog::RESOURCE_DECISION,
                "family-default",
            )
        }
        _ => (
            "human-scope-review",
            catalog::DEFAULT_APPLICABILITY_DECISION,
            "heuristic",
        ),
    }
}

fn worklist_obligations(dimension: hell_builtins::CompatibilityDimension) -> String {
    use hell_builtins::assurance_catalogs as catalog;
    let obligations: &[&str] = match dimension {
        hell_builtins::CompatibilityDimension::Parse => &["source-or-generated-syntax-path"],
        hell_builtins::CompatibilityDimension::StaticSemantics => &["resolved-typed-builtin-id"],
        hell_builtins::CompatibilityDimension::PureRuntime => catalog::PURE_RUNTIME_OBLIGATIONS,
        hell_builtins::CompatibilityDimension::Effects => catalog::EFFECT_OBLIGATIONS,
        hell_builtins::CompatibilityDimension::Concurrency => catalog::CONCURRENCY_OBLIGATIONS,
        hell_builtins::CompatibilityDimension::Presentation => catalog::PRESENTATION_OBLIGATIONS,
        hell_builtins::CompatibilityDimension::Platform => catalog::PLATFORM_OBLIGATIONS,
        hell_builtins::CompatibilityDimension::ResourceBehavior => catalog::RESOURCE_OBLIGATIONS,
    };
    obligations.join(";")
}

fn worklist_boundary_requirement(dimension: hell_builtins::CompatibilityDimension) -> &'static str {
    match dimension {
        hell_builtins::CompatibilityDimension::PureRuntime
        | hell_builtins::CompatibilityDimension::Effects
        | hell_builtins::CompatibilityDimension::Concurrency
        | hell_builtins::CompatibilityDimension::ResourceBehavior => "review-required",
        _ => "family-policy",
    }
}

fn worklist_dimension_order(value: &str) -> usize {
    hell_builtins::CompatibilityDimension::ALL
        .iter()
        .position(|dimension| dimension.as_str() == value)
        .unwrap_or(usize::MAX)
}

fn worklist_csv(headers: &[&str], rows: &[Vec<String>]) -> String {
    let mut output = headers.join(",");
    output.push('\n');
    for row in rows {
        output.push_str(
            &row.iter()
                .map(|field| crate::worklist_encoding::csv_field(field))
                .collect::<Vec<_>>()
                .join(","),
        );
        output.push('\n');
    }
    output
}

fn worklist_json(headers: &[&str], rows: &[Vec<String>]) -> String {
    let mut output = String::from("{\n  \"schemaVersion\": 2,\n  \"rows\": [");
    for (row_index, row) in rows.iter().enumerate() {
        if row_index != 0 {
            output.push(',');
        }
        output.push_str("\n    {");
        for (field_index, (header, field)) in headers.iter().zip(row).enumerate() {
            if field_index != 0 {
                output.push(',');
            }
            output.push_str("\n      ");
            write!(
                output,
                "{}: {}",
                crate::worklist_encoding::json_field(header),
                crate::worklist_encoding::json_field(field)
            )
            .expect("writing to String cannot fail");
        }
        output.push_str("\n    }");
    }
    output.push_str("\n  ]\n}\n");
    output
}

fn worklist_html(headers: &[&str], rows: &[Vec<String>]) -> String {
    let mut output = String::from(
        "<!doctype html>\n<meta charset=\"utf-8\">\n<title>Promotion worklist v2</title>\n<h1>Promotion worklist v2</h1>\n<p>Offline, read-only review view. Decisions must be signed outside this page.</p>\n<table><thead><tr>",
    );
    for header in headers {
        output.push_str("<th>");
        output.push_str(&crate::worklist_encoding::html_escape(header));
        output.push_str("</th>");
    }
    output.push_str("</tr></thead><tbody>\n");
    for row in rows {
        output.push_str("<tr>");
        for field in row {
            output.push_str("<td>");
            output.push_str(&crate::worklist_encoding::html_escape(field));
            output.push_str("</td>");
        }
        output.push_str("</tr>\n");
    }
    output.push_str("</tbody></table>\n");
    output
}

fn dependency_attestation_json(source_commit: &str, cargo_lock_sha256: Digest) -> String {
    format!(
        concat!(
            "{{\n",
            "  \"schemaVersion\": 1,\n",
            "  \"workflow\": \"nightly.yml\",\n",
            "  \"candidateSourceCommit\": {:?},\n",
            "  \"cargoLockSha256\": {:?},\n",
            "  \"result\": \"passed\"\n",
            "}}\n"
        ),
        source_commit,
        cargo_lock_sha256.hex(),
    )
}

fn retain_dependency_attestation(
    _root: &Path,
    input: &Path,
    artifact_root: &Path,
    dependency_lock_sha256: Digest,
    candidate: &ExecutableIdentity,
) -> Result<Digest, SuiteFailure> {
    let candidate_source_commit = candidate
        .build_info
        .as_ref()
        .and_then(|build_info| {
            build_info
                .lines
                .iter()
                .find_map(|line| line.strip_prefix("source commit "))
        })
        .ok_or_else(|| SuiteFailure::fixture("candidate has no source commit for attestation"))?;
    let expected = dependency_attestation_json(candidate_source_commit, dependency_lock_sha256);
    let observed = evidence_io(
        "read dependency policy attestation",
        input,
        fs::read_to_string(input),
    )?;
    if observed != expected {
        return Err(SuiteFailure::fixture(format!(
            "dependency policy attestation {} does not match the candidate and Cargo.lock",
            input.display()
        )));
    }
    let digest = sha256_bytes(observed.as_bytes());
    let digest_path = input.with_extension("sha256");
    let input_name = input
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| SuiteFailure::fixture("dependency attestation name is not UTF-8"))?;
    let expected_digest = format!("{}  {input_name}\n", digest.hex());
    let observed_digest = evidence_io(
        "read dependency policy attestation digest",
        &digest_path,
        fs::read_to_string(&digest_path),
    )?;
    if observed_digest != expected_digest {
        return Err(SuiteFailure::fixture(format!(
            "dependency policy attestation digest {} is invalid",
            digest_path.display()
        )));
    }
    let retained = artifact_root
        .join("evidence")
        .join("dependency-policy-attestation.json");
    let retained_digest = artifact_root
        .join("evidence")
        .join("dependency-policy-attestation.sha256");
    if let Some(parent) = retained.parent() {
        evidence_io(
            "create dependency attestation evidence directory",
            parent,
            fs::create_dir_all(parent),
        )?;
    }
    evidence_io(
        "retain dependency policy attestation",
        &retained,
        fs::write(&retained, observed.as_bytes()),
    )?;
    evidence_io(
        "retain dependency policy attestation digest",
        &retained_digest,
        fs::write(
            &retained_digest,
            format!("{}  dependency-policy-attestation.json\n", digest.hex()),
        ),
    )?;
    Ok(digest)
}

pub fn verify(root: &Path, report: &mut Report, failures: &Path) -> Result<(), FailureKind> {
    policy_suite(root, report)?;
    if !run_command(
        root,
        report,
        failures,
        "format",
        cargo(Duration::from_mins(5), ["fmt", "--all", "--", "--check"]),
    ) {
        return Err(FailureKind::Child);
    }
    if !run_command(
        root,
        report,
        failures,
        "clippy",
        cargo(
            Duration::from_mins(15),
            [
                "clippy",
                "--workspace",
                "--all-targets",
                "--all-features",
                "--locked",
                "--profile",
                "ci",
                "--",
                "-D",
                "warnings",
            ],
        ),
    ) {
        return Err(FailureKind::Child);
    }
    if !workspace_tests(root, report, failures, "ci") {
        return Err(FailureKind::Child);
    }
    if !build_candidate(root, report, failures, "ci", false) {
        return Err(FailureKind::Child);
    }
    run_fixture_gates(root, report, failures, "ci")
}

pub fn portability(root: &Path, report: &mut Report, failures: &Path) -> Result<(), FailureKind> {
    if !workspace_tests(root, report, failures, "ci") {
        return Err(FailureKind::Child);
    }
    if !build_candidate(root, report, failures, "ci", false) {
        return Err(FailureKind::Child);
    }
    run_fixture_gates(root, report, failures, "ci")
}

fn run_nightly_prerequisites(
    root: &Path,
    report: &mut Report,
    failures: &Path,
) -> Result<(), FailureKind> {
    policy_suite(root, report)?;
    if !workspace_tests(root, report, failures, "release") {
        return Err(FailureKind::Child);
    }
    if !build_candidate(root, report, failures, "release", true) {
        return Err(FailureKind::Child);
    }
    run_fixture_gates(root, report, failures, "release")?;

    for repetition in 1..=3 {
        if !run_command(
            root,
            report,
            failures,
            &format!("runtime-effects-repetition-{repetition}"),
            cargo(
                Duration::from_mins(15),
                [
                    "test",
                    "--release",
                    "--package",
                    "hell-runtime",
                    "--all-targets",
                    "--locked",
                    "--",
                    "--test-threads",
                    "1",
                ],
            ),
        ) {
            return Err(FailureKind::Child);
        }
    }
    Ok(())
}

pub fn nightly(
    root: &Path,
    report: &mut Report,
    failures: &Path,
    oracle: &Path,
    oracle_sha256: Digest,
    dependency_attestation: &Path,
) -> Result<(), FailureKind> {
    nightly_with_acquisition(
        root,
        report,
        failures,
        oracle,
        oracle_sha256,
        dependency_attestation,
        true,
    )
}

pub fn nightly_exploratory(
    root: &Path,
    report: &mut Report,
    failures: &Path,
    oracle: &Path,
    oracle_sha256: Digest,
    dependency_attestation: &Path,
) -> Result<(), FailureKind> {
    if !exploratory_admission() {
        report.check(
            "exploratory-admission",
            std::time::Duration::ZERO,
            Err("unsigned acquisition is allowed only for a non-main push or an exact main-controlled active-surveillance subject run and is never promotion evidence".to_owned()),
        );
        return Err(FailureKind::Policy);
    }
    nightly_with_acquisition(
        root,
        report,
        failures,
        oracle,
        oracle_sha256,
        dependency_attestation,
        false,
    )
}

fn exploratory_admission() -> bool {
    std::env::var("GITHUB_EVENT_NAME").as_deref() == Ok("push")
        && std::env::var("GITHUB_REF").as_deref() != Ok("refs/heads/main")
}

pub fn nightly_surveillance_subject(
    root: &Path,
    report: &mut Report,
    failures: &Path,
    oracle: &Path,
    oracle_sha256: Digest,
    dependency_attestation: &Path,
) -> Result<(), FailureKind> {
    let admitted = crate::assurance::trusted_surveillance_subject_identity(
        std::env::var("GITHUB_EVENT_NAME")
            .as_deref()
            .unwrap_or_default(),
        std::env::var("GITHUB_REF").as_deref().unwrap_or_default(),
        std::env::var("GITHUB_WORKFLOW_REF")
            .as_deref()
            .unwrap_or_default(),
    );
    report.check(
        "surveillance-subject-admission",
        std::time::Duration::ZERO,
        admitted
            .then_some(())
            .ok_or_else(|| "active subject execution is not controlled by the trusted main surveillance workflow".to_owned()),
    );
    if !admitted {
        return Err(FailureKind::Policy);
    }
    nightly_with_acquisition(
        root,
        report,
        failures,
        oracle,
        oracle_sha256,
        dependency_attestation,
        false,
    )
}

fn nightly_with_acquisition(
    root: &Path,
    report: &mut Report,
    failures: &Path,
    oracle: &Path,
    oracle_sha256: Digest,
    dependency_attestation: &Path,
    require_signed_acquisition: bool,
) -> Result<(), FailureKind> {
    run_nightly_prerequisites(root, report, failures)?;
    let identities = nightly_identities_with_acquisition(
        root,
        report,
        oracle,
        oracle_sha256,
        require_signed_acquisition,
    )?;

    let started = Instant::now();
    let differential = checked_suite_result(
        report,
        "differential-evidence",
        started,
        run_differential_corpus(root, &identities, failures, dependency_attestation),
    )?;
    let unacceptable_mismatches = unacceptable_mismatch_count(&differential.mismatches);
    report.check(
        "committed-and-generated-differential",
        started.elapsed(),
        (unacceptable_mismatches == 0).then_some(()).ok_or_else(|| {
            format!("{unacceptable_mismatches} unacceptable differential mismatch(es)")
        }),
    );
    let stress_observations = run_deterministic_stress(report, failures)?;

    let runtime_complete = if require_signed_acquisition {
        check_runtime_promotion_completeness(report)
    } else {
        report.check(
            "exploratory-nonpromotion-scope",
            std::time::Duration::ZERO,
            Ok(()),
        );
        runtime_promotion_completeness().is_ok()
    };

    let started = Instant::now();
    let gate = evaluate_release_gate(
        &ReleaseGateInput {
            differential_observations: differential.committed_observations
                + differential.generated_observations,
            candidate_stress_cases: stress_observations,
            harness_failures: differential.harness_failures,
            unexpected_timeouts: differential.unexpected_timeouts,
            mismatches: &differential.mismatches,
            stale_exact_claims: differential.stale_exact_claims,
            missing_evidence_references: missing_claim_evidence(),
            required_platform_skips: required_platform_skips(root),
            leaked_resources: differential.resource_failures,
            dependency_failures: differential.dependency_failures,
        },
        1_024,
    );
    let exploratory_passed = gate.harness_failures == 0
        && gate.unexpected_timeouts == 0
        && gate.unexplained_mismatches == 0
        && gate.rust_bug_mismatches == 0
        && gate.leaked_resources == 0
        && gate.dependency_failures == 0;
    let collection_result = if runtime_complete {
        gate.collection_passed()
            .then_some(())
            .ok_or_else(|| evidence_collection_failure(&gate, stress_observations))
    } else if !require_signed_acquisition && exploratory_passed {
        Ok(())
    } else {
        Err("runtime obligation corpus is incomplete for promotion".to_owned())
    };
    let collection_passed = collection_result.is_ok();
    report.check(
        "evidence-collection-gate",
        started.elapsed(),
        collection_result,
    );
    collection_passed.then_some(()).ok_or(FailureKind::Fixture)
}

fn nightly_identities_with_acquisition(
    root: &Path,
    report: &mut Report,
    oracle: &Path,
    oracle_sha256: Digest,
    require_signed_acquisition: bool,
) -> Result<NightlyIdentities, FailureKind> {
    let started = Instant::now();
    let ci_out = root.join("ci-out");
    let provider = ci_out.join("linux-release-provider.json");
    let receipt = ci_out.join("linux-release-oracle-receipt.json");
    let attestation = ci_out.join("linux-release-oracle-acquisition.dsse.json");
    let acquisition = if require_signed_acquisition {
        crate::assurance::verify_linux_release_acquisition(
            oracle,
            &provider,
            &receipt,
            &attestation,
        )
    } else {
        crate::release_oracle::verify_acquisition(oracle, &provider, &receipt)
    }
    .map_err(|detail| {
        report.check("release-oracle-acquisition", started.elapsed(), Err(detail));
        FailureKind::Fixture
    })?;
    report.check("release-oracle-acquisition", started.elapsed(), Ok(()));
    let mut identities =
        verify_nightly_identities(root, oracle, oracle_sha256).map_err(|detail| {
            report.check("executable-identities", started.elapsed(), Err(detail));
            FailureKind::Fixture
        })?;
    identities.oracle.acquisition_receipt_id = Some(acquisition.receipt_id.into());
    identities.oracle.acquisition_receipt_sha256 = Some(acquisition.receipt_sha256);
    identities.oracle.acquisition_attestation_sha256 = if require_signed_acquisition {
        Some(sha256_file(&attestation).map_err(|error| {
            report.check(
                "release-oracle-acquisition",
                started.elapsed(),
                Err(format!(
                    "cannot hash Linux acquisition attestation: {error}"
                )),
            );
            FailureKind::Io
        })?)
    } else {
        None
    };
    report.check("executable-identities", started.elapsed(), Ok(()));
    Ok(identities)
}

fn evidence_collection_failure(gate: &ReleaseGateReport, stress_observations: usize) -> String {
    format!(
        "evidence collection failed: differential={}, candidate-stress={}, harness={}, timeouts={}, unexplained={}, rust bugs={}, stale claims={}, leaks={}, dependency failures={}",
        gate.differential_observations,
        stress_observations,
        gate.harness_failures,
        gate.unexpected_timeouts,
        gate.unexplained_mismatches,
        gate.rust_bug_mismatches,
        gate.stale_exact_claims,
        gate.leaked_resources,
        gate.dependency_failures,
    )
}

fn run_deterministic_stress(report: &mut Report, failures: &Path) -> Result<usize, FailureKind> {
    let started = Instant::now();
    let stress = deterministic_stress(failures);
    let observations = stress.as_ref().copied().unwrap_or_default();
    let passed = stress.is_ok();
    report.check(
        "deterministic-stress",
        started.elapsed(),
        stress.map(|_| ()),
    );
    passed.then_some(observations).ok_or(FailureKind::Fixture)
}

/// Builds a pinned upstream oracle from source and emits one native evidence shard.
#[allow(clippy::too_many_lines)]
pub fn native_oracle_shard(
    root: &Path,
    report: &mut Report,
    failures: &Path,
    source: &Path,
    platform: &str,
    dependency_attestation: &Path,
) -> Result<(), FailureKind> {
    const SOURCE_COMMIT: &str = "8e952cf9de4ab25d7716982a9ca234f9bdcf1bff";
    policy_suite(root, report)?;
    let source_identity = observed_command(
        root,
        report,
        failures,
        "oracle-source-identity",
        CommandSpec::new("git", Duration::from_mins(1))
            .arguments(["rev-parse", "HEAD"])
            .current_directory(source),
    )?;
    let observed_commit = String::from_utf8(source_identity.stdout).map_err(|error| {
        report.check(
            "oracle-source-commit",
            Duration::ZERO,
            Err(format!(
                "upstream source commit from {} is not UTF-8: {error}",
                source.display()
            )),
        );
        FailureKind::Fixture
    })?;
    if observed_commit.trim() != SOURCE_COMMIT {
        report.check(
            "oracle-source-commit",
            Duration::ZERO,
            Err(format!(
                "expected upstream source {SOURCE_COMMIT}, observed {}",
                observed_commit.trim()
            )),
        );
        return Err(FailureKind::Fixture);
    }
    report.check("oracle-source-commit", Duration::ZERO, Ok(()));

    let source_tree_identity = observed_command(
        root,
        report,
        failures,
        "oracle-source-tree-identity",
        CommandSpec::new("git", Duration::from_mins(1))
            .arguments(["rev-parse", "HEAD^{tree}"])
            .current_directory(source),
    )?;

    let stack_yaml = source.join("stack.yaml");
    let stack_lock = source.join("stack.yaml.lock");
    let stack_identity = observed_command(
        root,
        report,
        failures,
        "oracle-stack-identity",
        CommandSpec::new("stack", Duration::from_mins(1)).argument("--numeric-version"),
    )?;
    let artifact_root = failures.parent().unwrap_or_else(|| Path::new("."));
    let oracle_directory = artifact_root.join("oracle").join(platform);
    let started = Instant::now();
    io_or_report(
        report,
        "oracle-output-directory",
        started,
        "create oracle output directory",
        &oracle_directory,
        fs::create_dir_all(&oracle_directory),
    )?;
    let build = observed_command(
        root,
        report,
        failures,
        "oracle-source-build",
        stack_oracle_build_command(&stack_yaml, &oracle_directory),
    )?;
    let compiler_identity = observed_command(
        root,
        report,
        failures,
        "oracle-compiler-identity",
        CommandSpec::new("stack", Duration::from_mins(5))
            .argument("--stack-yaml")
            .argument(stack_yaml.as_os_str())
            .arguments(["exec", "--", "ghc", "--info"]),
    )?;
    let dependency_identity = observed_command(
        root,
        report,
        failures,
        "oracle-dependency-identity",
        CommandSpec::new("stack", Duration::from_mins(5))
            .argument("--stack-yaml")
            .argument(stack_yaml.as_os_str())
            .arguments(["ls", "dependencies"]),
    )?;
    let executable_name = if cfg!(windows) { "hell.exe" } else { "hell" };
    let oracle = oracle_directory.join(executable_name);
    let started = Instant::now();
    let oracle_sha256 = io_or_report(
        report,
        "oracle-binary-digest",
        started,
        "hash oracle binary",
        &oracle,
        sha256_file(&oracle),
    )?;
    let started = Instant::now();
    let resolver = io_or_report(
        report,
        "oracle-resolver-lock-read",
        started,
        "read oracle resolver lock",
        &stack_lock,
        fs::read(&stack_lock),
    )?;
    let started = Instant::now();
    checked_suite_result(
        report,
        "oracle-build-provenance",
        started,
        write_oracle_build_record(
            artifact_root,
            platform,
            SOURCE_COMMIT,
            &source_tree_identity,
            &resolver,
            oracle_sha256,
            &stack_identity,
            &compiler_identity,
            &dependency_identity,
            &build,
        ),
    )?;

    if !build_candidate(root, report, failures, "release", true) {
        return Err(FailureKind::Child);
    }
    let started = Instant::now();
    let identities = checked_suite_result(
        report,
        "oracle-identities",
        started,
        verify_nightly_identities(root, &oracle, oracle_sha256).map_err(SuiteFailure::fixture),
    )?;
    let started = Instant::now();
    let differential = checked_suite_result(
        report,
        "native-differential-evidence",
        started,
        run_differential_corpus(root, &identities, failures, dependency_attestation),
    )?;
    let runtime_complete = check_runtime_promotion_completeness(report);
    let unacceptable_mismatches = unacceptable_mismatch_count(&differential.mismatches);
    let passed = runtime_complete
        && differential.harness_failures == 0
        && differential.unexpected_timeouts == 0
        && unacceptable_mismatches == 0
        && differential.stale_exact_claims == 0
        && differential.resource_failures == 0;
    report.check(
        "native-oracle-differential-shard",
        Duration::ZERO,
        passed.then_some(()).ok_or_else(|| {
            format!(
                "harness={}, timeouts={}, unacceptableMismatches={}, staleExactClaims={}, resourceFailures={}",
                differential.harness_failures,
                differential.unexpected_timeouts,
                unacceptable_mismatches,
                differential.stale_exact_claims,
                differential.resource_failures
            )
        }),
    );
    passed.then_some(()).ok_or(FailureKind::Fixture)
}

/// Verifies the identities and content digests of required native shards.
#[allow(clippy::too_many_lines)]
pub fn merge_native_shards(
    root: &Path,
    input: &Path,
    report: &mut Report,
) -> Result<(), FailureKind> {
    validate_and_merge_native_shards(root, input, report, false)
}

/// Runs only the dormant collection campaign against already built and
/// verified oracle/candidate executables. It emits no compatibility claim or
/// coverage output.
pub(crate) fn collection_authority_collect(
    root: &Path,
    oracle: &Path,
    oracle_sha256: Digest,
    candidate_executable: &Path,
    candidate_commit: &str,
    platform: &str,
    output: &Path,
) -> Result<(), String> {
    let trusted = collection_trusted_harness(root)?;
    let mut identities = verify_collection_identities(
        oracle,
        oracle_sha256,
        candidate_executable,
        candidate_commit,
    )?;
    match platform {
        "linux-amd64" => {
            let ci_out = root.join("ci-out");
            let receipt = ci_out.join("linux-release-oracle-receipt.json");
            let attestation = ci_out.join("linux-release-oracle-acquisition.dsse.json");
            let acquisition = crate::assurance::verify_linux_release_acquisition(
                oracle,
                &ci_out.join("linux-release-provider.json"),
                &receipt,
                &attestation,
            )?;
            identities.oracle.acquisition_receipt_id = Some(acquisition.receipt_id.into());
            identities.oracle.acquisition_receipt_sha256 = Some(acquisition.receipt_sha256);
            identities.oracle.acquisition_attestation_sha256 =
                Some(sha256_file(&attestation).map_err(|error| {
                    format!("cannot hash Linux acquisition attestation: {error}")
                })?);
            retain_linux_collection_acquisition(
                output,
                oracle,
                &ci_out.join("linux-release-provider.json"),
                &receipt,
                &attestation,
            )?;
        }
        "macos-arm64" | "windows-amd64" => {
            let build_path = output.join(format!("oracle-build-{platform}.json"));
            let build = fs::read_to_string(&build_path)
                .map_err(|error| format!("cannot read native collection build record: {error}"))?;
            let provenance = output.join("oracle-provenance").join(platform);
            let verified = verify_oracle_build_record(
                &build,
                platform,
                "8e952cf9de4ab25d7716982a9ca234f9bdcf1bff",
                &provenance,
            )?;
            verify_collection_native_dependency_identity(&provenance)?;
            if verified != oracle_sha256.hex() {
                return Err("native collection oracle differs from its exact build record".into());
            }
        }
        _ => {
            return Err(format!(
                "unknown collection authority platform {platform:?}"
            ));
        }
    }
    retain_collection_trusted_harness(root, output, &trusted)?;
    run_collection_campaign(root, &identities, &trusted, platform, output)
        .map_err(|error| error.detail)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CollectionTrustedHarness {
    source_commit: String,
    hell_ci_path: PathBuf,
    hell_ci_sha256: Digest,
    process_helper_path: PathBuf,
    process_helper_sha256: Digest,
    source_manifest_sha256: Digest,
    reviewed_model_sha256: Digest,
}

fn collection_trusted_harness(root: &Path) -> Result<CollectionTrustedHarness, String> {
    verify_collection_source_authority(root).map_err(|error| error.to_string())?;
    let source_commit = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["rev-parse", "HEAD"])
        .output()
        .map_err(|error| format!("cannot inspect collection harness source commit: {error}"))?;
    if !source_commit.status.success() {
        return Err("cannot inspect collection harness source commit".to_owned());
    }
    let source_commit = String::from_utf8(source_commit.stdout)
        .map_err(|_| "collection harness source commit is not UTF-8".to_owned())?
        .trim()
        .to_owned();
    require_collection_git_sha(&source_commit, "trusted harness source commit")?;
    let tracked_status = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["status", "--porcelain", "--untracked-files=no"])
        .output()
        .map_err(|error| format!("cannot inspect collection harness tracked files: {error}"))?;
    if !tracked_status.status.success() || !tracked_status.stdout.is_empty() {
        return Err("collection trusted harness checkout has modified tracked files".to_owned());
    }
    let hell_ci_path = std::env::current_exe()
        .map_err(|error| format!("cannot locate trusted collection driver: {error}"))?;
    let process_helper_path = hell_ci_path
        .parent()
        .ok_or_else(|| "trusted collection driver has no parent directory".to_owned())?
        .join(format!("hell-test-helper{}", std::env::consts::EXE_SUFFIX));
    let hell_ci_sha256 = sha256_file(&hell_ci_path)
        .map_err(|error| format!("cannot hash trusted collection driver: {error}"))?;
    let process_helper_sha256 = sha256_file(&process_helper_path)
        .map_err(|error| format!("cannot hash trusted collection process helper: {error}"))?;
    let source_manifest_sha256 = sha256_file(
        &root.join("compat/oracle-sources/collection-source-authority.tsv"),
    )
    .map_err(|error| format!("cannot hash collection source authority manifest: {error}"))?;
    let reviewed_model_sha256 = sha256_file(&root.join("crates/hell-testkit/src/reviewed_set.rs"))
        .map_err(|error| format!("cannot hash trusted collection reviewed model: {error}"))?;
    Ok(CollectionTrustedHarness {
        source_commit,
        hell_ci_path,
        hell_ci_sha256,
        process_helper_path,
        process_helper_sha256,
        source_manifest_sha256,
        reviewed_model_sha256,
    })
}

fn require_collection_git_sha(value: &str, label: &str) -> Result<(), String> {
    if value.len() != 40 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("collection {label} is not an exact Git commit"));
    }
    Ok(())
}

fn verify_collection_identities(
    oracle: &Path,
    oracle_sha256: Digest,
    candidate_executable: &Path,
    candidate_commit: &str,
) -> Result<NightlyIdentities, String> {
    require_collection_git_sha(candidate_commit, "candidate commit")?;
    let oracle = verify_executable(
        oracle,
        ExecutableRole::Oracle,
        Some(oracle_sha256),
        hell_builtins::LANGUAGE_VERSION,
    )
    .map_err(|error| format!("oracle identity verification failed: {error}"))?;
    let candidate = verify_executable(
        candidate_executable,
        ExecutableRole::Candidate,
        None,
        hell_builtins::LANGUAGE_VERSION,
    )
    .map_err(|error| format!("candidate identity verification failed: {error}"))?;
    validate_collection_candidate_identity(&candidate, candidate_commit)?;
    Ok(NightlyIdentities { oracle, candidate })
}

fn validate_collection_candidate_identity(
    candidate: &ExecutableIdentity,
    candidate_commit: &str,
) -> Result<(), String> {
    require_collection_git_sha(candidate_commit, "candidate commit")?;
    let observed_commit = candidate
        .build_info
        .as_ref()
        .and_then(|build| {
            build
                .lines
                .iter()
                .find_map(|line| line.strip_prefix("source commit "))
        })
        .ok_or_else(|| "candidate build info has no source commit".to_owned())?;
    if observed_commit != candidate_commit {
        return Err("candidate executable source commit differs from explicit subject".to_owned());
    }
    if !candidate.build_info.as_ref().is_some_and(|build| {
        build
            .lines
            .iter()
            .any(|line| line.as_ref() == "compatibility evidence schema 1")
    }) {
        return Err("candidate build info has no compatibility evidence schema".to_owned());
    }
    Ok(())
}

fn retain_collection_trusted_harness(
    root: &Path,
    output: &Path,
    trusted: &CollectionTrustedHarness,
) -> Result<(), String> {
    let retained = output.join("trusted-harness");
    fs::create_dir_all(&retained)
        .map_err(|error| format!("cannot create retained collection harness: {error}"))?;
    for (source, name, digest) in [
        (&trusted.hell_ci_path, "hell-ci", trusted.hell_ci_sha256),
        (
            &trusted.process_helper_path,
            "hell-test-helper",
            trusted.process_helper_sha256,
        ),
        (
            &root.join("compat/oracle-sources/collection-source-authority.tsv"),
            "collection-source-authority.tsv",
            trusted.source_manifest_sha256,
        ),
        (
            &root.join("crates/hell-testkit/src/reviewed_set.rs"),
            "reviewed_set.rs",
            trusted.reviewed_model_sha256,
        ),
    ] {
        let destination = retained.join(name);
        fs::copy(source, &destination)
            .map_err(|error| format!("cannot retain trusted collection harness file: {error}"))?;
        if sha256_file(&destination)
            .map_err(|error| format!("cannot hash retained collection harness file: {error}"))?
            != digest
        {
            return Err("retained collection harness file changed while copied".to_owned());
        }
    }
    Ok(())
}

fn retain_linux_collection_acquisition(
    output: &Path,
    oracle: &Path,
    provider: &Path,
    receipt: &Path,
    attestation: &Path,
) -> Result<(), String> {
    let oracle_directory = output.join("oracle/linux-amd64");
    let provenance = output.join("oracle-provenance/linux-amd64");
    fs::create_dir_all(&oracle_directory)
        .and_then(|()| fs::create_dir_all(&provenance))
        .map_err(|error| format!("cannot create retained Linux acquisition package: {error}"))?;
    for (source, destination) in [
        (oracle, oracle_directory.join("hell")),
        (provider, provenance.join("linux-release-provider.json")),
        (
            receipt,
            provenance.join("linux-release-oracle-receipt.json"),
        ),
        (
            attestation,
            provenance.join("linux-release-oracle-acquisition.dsse.json"),
        ),
    ] {
        fs::copy(source, &destination).map_err(|error| {
            format!(
                "cannot retain Linux acquisition byte {}: {error}",
                source.display()
            )
        })?;
    }
    crate::assurance::verify_linux_release_acquisition(
        &oracle_directory.join("hell"),
        &provenance.join("linux-release-provider.json"),
        &provenance.join("linux-release-oracle-receipt.json"),
        &provenance.join("linux-release-oracle-acquisition.dsse.json"),
    )?;
    Ok(())
}

/// Builds only the pinned native oracle and retains its exact build streams;
/// it does not run ordinary compatibility or promotion gates.
pub(crate) fn collection_authority_build_native(
    source: &Path,
    platform: &str,
    output: &Path,
) -> Result<PathBuf, String> {
    let expected_host = match platform {
        "macos-arm64" => ("macos", "aarch64"),
        "windows-amd64" => ("windows", "x86_64"),
        _ => return Err("collection native build requires macos-arm64 or windows-amd64".into()),
    };
    if (std::env::consts::OS, std::env::consts::ARCH) != expected_host {
        return Err("collection native build platform differs from the actual host".into());
    }
    let commit = run_collection_command(
        &CommandSpec::new("git", Duration::from_mins(1))
            .arguments(["rev-parse", "HEAD"])
            .current_directory(source),
    )?;
    if commit.stdout != b"8e952cf9de4ab25d7716982a9ca234f9bdcf1bff\n" {
        return Err("collection native oracle source commit is not exact".into());
    }
    let source_tree = run_collection_command(
        &CommandSpec::new("git", Duration::from_mins(1))
            .arguments(["rev-parse", "HEAD^{tree}"])
            .current_directory(source),
    )?;
    let stack_yaml = source.join("stack.yaml");
    let stack = run_collection_command(
        &CommandSpec::new("stack", Duration::from_mins(1)).argument("--numeric-version"),
    )?;
    let oracle_directory = output.join("oracle").join(platform);
    fs::create_dir_all(&oracle_directory)
        .map_err(|error| format!("cannot create collection oracle directory: {error}"))?;
    let build =
        run_collection_command(&stack_oracle_build_command(&stack_yaml, &oracle_directory))?;
    let compiler = run_collection_command(
        &CommandSpec::new("stack", Duration::from_mins(5))
            .argument("--stack-yaml")
            .argument(stack_yaml.as_os_str())
            .arguments(["exec", "--", "ghc", "--info"]),
    )?;
    let dependencies = run_collection_command(
        &CommandSpec::new("stack", Duration::from_mins(5))
            .argument("--stack-yaml")
            .argument(stack_yaml.as_os_str())
            .arguments(["ls", "dependencies"]),
    )?;
    let executable = oracle_directory.join(if cfg!(windows) { "hell.exe" } else { "hell" });
    let binary = sha256_file(&executable)
        .map_err(|error| format!("cannot hash collection native oracle: {error}"))?;
    let resolver = fs::read(source.join("stack.yaml.lock"))
        .map_err(|error| format!("cannot read collection native resolver lock: {error}"))?;
    write_oracle_build_record(
        output,
        platform,
        "8e952cf9de4ab25d7716982a9ca234f9bdcf1bff",
        &source_tree,
        &resolver,
        binary,
        &stack,
        &compiler,
        &dependencies,
        &build,
    )
    .map_err(|error| error.detail)?;
    verify_collection_native_dependency_identity(&output.join("oracle-provenance").join(platform))?;
    Ok(executable)
}

fn run_collection_command(command: &CommandSpec) -> Result<CommandResult, String> {
    let result = command
        .run()
        .map_err(|error| format!("cannot execute {}: {error}", command.display_program()))?;
    if !result.status.success() || result.timed_out {
        return Err(format!(
            "collection authority command {} failed with {}",
            command.display_program(),
            result.status
        ));
    }
    Ok(result)
}

/// Rederives and writes the canonical provider subject for one exact dormant
/// Map712/Set479 campaign shard.
pub(crate) fn collection_authority_subject(
    root: &Path,
    input: &Path,
    platform: &str,
    output: &Path,
) -> Result<(), String> {
    let subject = collection_authority_subject_document(root, input, platform)?;
    write_collection_subject(output, &subject)
}

fn collection_authority_subject_document(
    root: &Path,
    input: &Path,
    platform: &str,
) -> Result<String, String> {
    let claim_platform = match platform {
        "linux-amd64" => hell_builtins::ClaimPlatform::Linux,
        "macos-arm64" => hell_builtins::ClaimPlatform::MacOs,
        "windows-amd64" => hell_builtins::ClaimPlatform::Windows,
        _ => {
            return Err(format!(
                "unknown collection authority platform {platform:?}"
            ));
        }
    };
    verify_collection_source_authority(root).map_err(|error| error.to_string())?;
    let campaign = input.join("collection-evidence");
    let trusted = retained_collection_trusted_harness(root, input, &campaign)?;
    let (expected, observed) = validate_collection_observations(&campaign, claim_platform)?;
    let (inventory_sha256, tree_sha256) = validate_collection_inventory(&campaign, &expected)?;

    let candidate_executable = observed
        .candidate_executable
        .ok_or_else(|| "collection subject lacks candidate executable identity".to_owned())?;
    let oracle_executable = observed
        .oracle_executable
        .ok_or_else(|| "collection subject lacks oracle executable".to_owned())?;
    let campaign_expectation = CollectionCampaignExpectation {
        platform,
        candidate_executable: &candidate_executable,
        oracle_executable: &oracle_executable,
        trusted: &trusted,
        inventory: &inventory_sha256,
        receipt: observed.receipt.as_deref(),
        attestation: observed.attestation.as_deref(),
    };
    let candidate_commit = validate_collection_campaign_manifest(&campaign, &campaign_expectation)?;
    let authority = collection_subject_oracle_authority(
        input,
        platform,
        claim_platform,
        &oracle_executable,
        observed.receipt,
        observed.attestation,
    )?;
    let source_manifest_sha256 =
        sha256_file(&root.join("compat/oracle-sources/collection-source-authority.tsv"))
            .map_err(|error| format!("cannot hash collection source manifest: {error}"))?
            .hex();
    Ok(render_collection_subject(&CollectionSubjectDocument {
        platform,
        trusted: &trusted,
        candidate_commit: &candidate_commit,
        candidate_executable: &candidate_executable,
        oracle_subject: authority.subject,
        oracle_source_commit: authority.source_commit,
        oracle_executable: &oracle_executable,
        receipt: authority.receipt,
        attestation: authority.attestation,
        build_record: authority.build_record,
        source_manifest: &source_manifest_sha256,
        inventory: &inventory_sha256,
        tree: &tree_sha256,
    }))
}

fn retained_collection_trusted_harness(
    root: &Path,
    input: &Path,
    campaign: &Path,
) -> Result<CollectionTrustedHarness, String> {
    verify_collection_source_authority(root).map_err(|error| error.to_string())?;
    let campaign_document = fs::read_to_string(campaign.join("campaign.json"))
        .map_err(|error| format!("cannot read collection campaign manifest: {error}"))?;
    let source_commit = json_string_field(&campaign_document, "trustedHarnessSourceCommit")
        .ok_or_else(|| "collection campaign lacks trusted harness source commit".to_owned())?
        .to_owned();
    require_collection_git_sha(&source_commit, "trusted harness source commit")?;
    let retained = input.join("trusted-harness");
    let expected_names = BTreeSet::from([
        "collection-source-authority.tsv".to_owned(),
        "hell-ci".to_owned(),
        "hell-test-helper".to_owned(),
        "reviewed_set.rs".to_owned(),
    ]);
    let observed_names = fs::read_dir(&retained)
        .map_err(|error| format!("cannot enumerate retained collection harness: {error}"))?
        .map(|entry| {
            entry
                .map_err(|error| format!("cannot enumerate retained collection harness: {error}"))
                .and_then(|entry| {
                    entry
                        .file_name()
                        .into_string()
                        .map_err(|_| "retained collection harness filename is not UTF-8".to_owned())
                })
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if observed_names != expected_names {
        return Err("retained collection harness inventory is missing or extra".to_owned());
    }
    let hell_ci_path = retained.join("hell-ci");
    let process_helper_path = retained.join("hell-test-helper");
    let retained_manifest = retained.join("collection-source-authority.tsv");
    let retained_model = retained.join("reviewed_set.rs");
    let source_manifest_sha256 = sha256_file(&retained_manifest)
        .map_err(|error| format!("cannot hash retained source manifest: {error}"))?;
    let reviewed_model_sha256 = sha256_file(&retained_model)
        .map_err(|error| format!("cannot hash retained reviewed model: {error}"))?;
    if fs::read(&retained_manifest)
        .map_err(|error| format!("cannot read retained source manifest: {error}"))?
        != fs::read(root.join("compat/oracle-sources/collection-source-authority.tsv"))
            .map_err(|error| format!("cannot read trusted source manifest: {error}"))?
        || fs::read(&retained_model)
            .map_err(|error| format!("cannot read retained reviewed model: {error}"))?
            != fs::read(root.join("crates/hell-testkit/src/reviewed_set.rs"))
                .map_err(|error| format!("cannot read trusted reviewed model: {error}"))?
    {
        return Err(
            "retained collection model/source manifest differs from trusted provider root"
                .to_owned(),
        );
    }
    Ok(CollectionTrustedHarness {
        source_commit,
        hell_ci_sha256: sha256_file(&hell_ci_path)
            .map_err(|error| format!("cannot hash retained collection driver: {error}"))?,
        hell_ci_path,
        process_helper_sha256: sha256_file(&process_helper_path)
            .map_err(|error| format!("cannot hash retained collection helper: {error}"))?,
        process_helper_path,
        source_manifest_sha256,
        reviewed_model_sha256,
    })
}

struct CollectionSubjectOracleAuthority {
    subject: &'static str,
    source_commit: &'static str,
    build_record: Option<String>,
    receipt: Option<String>,
    attestation: Option<String>,
}

fn collection_subject_oracle_authority(
    input: &Path,
    platform: &str,
    claim_platform: hell_builtins::ClaimPlatform,
    oracle_executable: &str,
    receipt: Option<String>,
    attestation: Option<String>,
) -> Result<CollectionSubjectOracleAuthority, String> {
    if claim_platform == hell_builtins::ClaimPlatform::Linux {
        if oracle_executable != "5ccc78e62200eb5aea8b9da9161334c61848d0d3e7de2f270929920cfbf357c9" {
            return Err("Linux collection subject uses the wrong signed release asset".into());
        }
        let provenance = input.join("oracle-provenance/linux-amd64");
        let retained_oracle = input.join("oracle/linux-amd64/hell");
        let acquisition = crate::assurance::verify_linux_release_acquisition(
            &retained_oracle,
            &provenance.join("linux-release-provider.json"),
            &provenance.join("linux-release-oracle-receipt.json"),
            &provenance.join("linux-release-oracle-acquisition.dsse.json"),
        )?;
        let retained_attestation =
            sha256_file(&provenance.join("linux-release-oracle-acquisition.dsse.json"))
                .map_err(|error| format!("cannot hash retained Linux attestation: {error}"))?
                .hex();
        if acquisition.receipt_sha256.hex() != receipt.as_deref().unwrap_or_default()
            || retained_attestation != attestation.as_deref().unwrap_or_default()
            || sha256_file(&retained_oracle)
                .map_err(|error| format!("cannot hash retained Linux oracle: {error}"))?
                .hex()
                != oracle_executable
        {
            return Err(
                "retained Linux acquisition package differs from campaign observations".into(),
            );
        }
        return Ok(CollectionSubjectOracleAuthority {
            subject: "linux-signed-release-result-only",
            source_commit: "d4d028609ed46a560c62caea8c70e7e91d1afd29",
            build_record: None,
            receipt,
            attestation,
        });
    }
    let build_path = input.join(format!("oracle-build-{platform}.json"));
    let build_document = fs::read_to_string(&build_path)
        .map_err(|error| format!("cannot read collection native build record: {error}"))?;
    let provenance = input.join("oracle-provenance").join(platform);
    let verified = verify_oracle_build_record(
        &build_document,
        platform,
        "8e952cf9de4ab25d7716982a9ca234f9bdcf1bff",
        &provenance,
    )?;
    verify_collection_native_dependency_identity(&provenance)?;
    if verified != oracle_executable {
        return Err("collection native build binary differs from observations".into());
    }
    Ok(CollectionSubjectOracleAuthority {
        subject: "native-source-build-reported-containers-version",
        source_commit: "8e952cf9de4ab25d7716982a9ca234f9bdcf1bff",
        build_record: Some(sha256_bytes(build_document.as_bytes()).hex()),
        receipt: None,
        attestation: None,
    })
}

struct CollectionSubjectDocument<'a> {
    platform: &'a str,
    trusted: &'a CollectionTrustedHarness,
    candidate_commit: &'a str,
    candidate_executable: &'a str,
    oracle_subject: &'a str,
    oracle_source_commit: &'a str,
    oracle_executable: &'a str,
    receipt: Option<String>,
    attestation: Option<String>,
    build_record: Option<String>,
    source_manifest: &'a str,
    inventory: &'a str,
    tree: &'a str,
}

fn write_collection_subject(output: &Path, subject: &str) -> Result<(), String> {
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("cannot create collection subject output: {error}"))?;
    }
    fs::write(output, subject.as_bytes())
        .map_err(|error| format!("cannot write collection provider subject: {error}"))?;
    fs::write(
        output.with_extension("json.sha256"),
        format!(
            "{}  {}\n",
            sha256_bytes(subject.as_bytes()).hex(),
            output
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .ok_or_else(|| "collection subject filename is not UTF-8".to_owned())?
        ),
    )
    .map_err(|error| format!("cannot write collection provider subject digest: {error}"))
}

fn render_collection_subject(document: &CollectionSubjectDocument<'_>) -> String {
    let nullable = |value: &Option<String>| {
        value
            .as_ref()
            .map_or_else(|| "null".to_owned(), |value| format!("{value:?}"))
    };
    let subject = format!(
        concat!(
            "{{\n  \"schemaVersion\": 2,\n",
            "  \"domain\": \"hell-collection-provider-subject-v2\",\n",
            "  \"platform\": {platform:?},\n",
            "  \"trustedHarnessSourceCommit\": {trusted_source_commit:?},\n",
            "  \"trustedHellCiExecutableSha256\": {trusted_hell_ci:?},\n",
            "  \"trustedProcessHelperSha256\": {trusted_helper:?},\n",
            "  \"trustedReviewedModelSha256\": {trusted_model:?},\n",
            "  \"candidateCommit\": {candidate_commit:?},\n",
            "  \"candidateExecutableSha256\": {candidate_executable:?},\n",
            "  \"oracleSubject\": {oracle_subject:?},\n",
            "  \"oracleSourceCommit\": {oracle_source_commit:?},\n",
            "  \"oracleExecutableSha256\": {oracle_executable:?},\n",
            "  \"oracleAcquisitionReceiptSha256\": {receipt},\n",
            "  \"oracleAcquisitionAttestationSha256\": {attestation},\n",
            "  \"oracleBuildRecordSha256\": {build_record},\n",
            "  \"sourceAuthorityManifestSha256\": {source_manifest_sha256:?},\n",
            "  \"caseCount\": 1191,\n",
            "  \"inventoryPath\": \"collection-evidence/inventory.tsv\",\n",
            "  \"inventorySha256\": {inventory_sha256:?},\n",
            "  \"campaignTreePath\": \"collection-evidence/observations\",\n",
            "  \"campaignTreeSha256\": {tree_sha256:?}\n}}\n"
        ),
        platform = document.platform,
        trusted_source_commit = document.trusted.source_commit,
        trusted_hell_ci = document.trusted.hell_ci_sha256.hex(),
        trusted_helper = document.trusted.process_helper_sha256.hex(),
        trusted_model = document.trusted.reviewed_model_sha256.hex(),
        candidate_commit = document.candidate_commit,
        candidate_executable = document.candidate_executable,
        oracle_subject = document.oracle_subject,
        oracle_source_commit = document.oracle_source_commit,
        oracle_executable = document.oracle_executable,
        receipt = nullable(&document.receipt),
        attestation = nullable(&document.attestation),
        build_record = nullable(&document.build_record),
        source_manifest_sha256 = document.source_manifest,
        inventory_sha256 = document.inventory,
        tree_sha256 = document.tree,
    );
    subject
}

/// Replays the exact three provider-selected collection artifacts and writes
/// the canonical campaign report used as the merge attestation subject.
pub(crate) fn collection_authority_verify(
    root: &Path,
    input: &Path,
    provider_root: &Path,
    report: &Path,
) -> Result<(), String> {
    let source = verify_collection_source_authority(root).map_err(|error| error.to_string())?;
    let mut cases = reviewed_collection_cases()?;
    bind_runtime_process_helper(&mut cases)?;
    let mut providers = Vec::new();
    for platform in ["linux-amd64", "macos-arm64", "windows-amd64"] {
        let shard = input.join(platform);
        let provider = crate::assurance::verify_collection_provider_artifact(
            root,
            provider_root,
            &shard,
            platform,
        )?;
        let expected_subject = collection_authority_subject_document(root, &shard, platform)?;
        let subject_path = shard.join("collection-evidence/provider-subject.json");
        let subject = fs::read_to_string(&subject_path)
            .map_err(|error| format!("cannot read collection provider subject: {error}"))?;
        let digest_record = fs::read_to_string(subject_path.with_extension("json.sha256"))
            .map_err(|error| format!("cannot read collection provider subject digest: {error}"))?;
        validate_collection_trusted_provider_head(&subject, &provider.provider_head_commit)?;
        if subject != expected_subject
            || sha256_bytes(subject.as_bytes()) != provider.provider_subject_sha256
            || digest_record
                != format!(
                    "{}  provider-subject.json\n",
                    provider.provider_subject_sha256.hex()
                )
        {
            return Err(
                "collection provider subject differs from independently rederived campaign bytes"
                    .to_owned(),
            );
        }
        providers.push((provider, subject));
    }
    validate_collection_campaign_coherence(&providers)?;
    let campaign_subject_sha256 = collection_campaign_subject_sha256(&providers);
    let mut shards = Vec::with_capacity(cases.len() * providers.len());
    for (provider, subject) in &providers {
        let platform = collection_claim_platform(&provider.platform)?;
        let observation_root = input
            .join(&provider.platform)
            .join("collection-evidence/observations");
        for case in &cases {
            let facts =
                collection_bundle_facts(&observation_root.join(case.id.as_ref()), case, &source)
                    .map_err(|error| {
                        format!("cannot derive collection bundle {}: {error}", case.id)
                    })?;
            shards.push(collection_shard_from_facts(
                platform,
                provider,
                subject,
                campaign_subject_sha256,
                facts,
            )?);
        }
    }
    let source_manifest = shards
        .first()
        .map(|shard| shard.case.source_authority_manifest_sha256)
        .ok_or_else(|| "collection campaign contains no cases".to_owned())?;
    let native_builds = collection_native_build_authorities(input, &providers, source_manifest)?;
    validate_collection_black_box_structure(&source, &native_builds, &shards)?;
    let document = collection_authority_report(
        source_manifest,
        &providers,
        campaign_subject_sha256,
        &shards,
    );
    if let Some(parent) = report.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("cannot create collection report directory: {error}"))?;
    }
    fs::write(report, document.as_bytes())
        .map_err(|error| format!("cannot write collection authority report: {error}"))?;
    fs::write(
        report.with_extension("json.sha256"),
        format!(
            "{}  {}\n",
            sha256_bytes(document.as_bytes()).hex(),
            report
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .ok_or_else(|| "collection report filename is not UTF-8".to_owned())?
        ),
    )
    .map_err(|error| format!("cannot write collection authority report digest: {error}"))
}

fn validate_collection_trusted_provider_head(
    subject: &str,
    provider_head: &str,
) -> Result<(), String> {
    require_collection_git_sha(provider_head, "authenticated provider head")?;
    if json_string_field(subject, "trustedHarnessSourceCommit") != Some(provider_head) {
        return Err(
            "collection trusted harness source differs from authenticated provider head".to_owned(),
        );
    }
    Ok(())
}

fn validate_collection_campaign_coherence(
    providers: &[(crate::assurance::VerifiedCollectionProviderArtifact, String)],
) -> Result<(), String> {
    let [first, rest @ ..] = providers else {
        return Err("collection campaign has no authenticated provider roots".to_owned());
    };
    if providers.len() != 3
        || rest.iter().any(|(provider, _)| {
            provider.repository_id != first.0.repository_id
                || provider.run_id != first.0.run_id
                || provider.run_attempt != first.0.run_attempt
                || provider.workflow_ref != first.0.workflow_ref
                || provider.event != first.0.event
                || provider.provider_head_commit != first.0.provider_head_commit
                || provider.candidate_commit != first.0.candidate_commit
                || provider.observed_at != first.0.observed_at
                || provider.artifact_api_sha256 != first.0.artifact_api_sha256
                || provider.job_api_sha256 != first.0.job_api_sha256
                || provider.run_api_sha256 != first.0.run_api_sha256
                || provider.workflow_sha256 != first.0.workflow_sha256
        })
    {
        return Err("collection provider artifacts do not form one exact campaign".to_owned());
    }
    Ok(())
}

fn collection_campaign_subject_sha256(
    providers: &[(crate::assurance::VerifiedCollectionProviderArtifact, String)],
) -> Digest {
    let mut bytes = b"hell-collection-campaign-provider-root-v1\0".to_vec();
    for (provider, _) in providers {
        for field in [
            provider.selection_sha256,
            provider.artifact_api_sha256,
            provider.job_api_sha256,
            provider.run_api_sha256,
            provider.workflow_sha256,
            provider.archive_sha256,
            provider.tree_sha256,
            provider.provider_subject_sha256,
        ] {
            bytes.extend_from_slice(field.hex().as_bytes());
        }
    }
    sha256_bytes(&bytes)
}

fn collection_shard_from_facts(
    platform: hell_builtins::ClaimPlatform,
    provider: &crate::assurance::VerifiedCollectionProviderArtifact,
    subject: &str,
    campaign_subject_sha256: Digest,
    facts: hell_testkit::CollectionBundleFacts,
) -> Result<CollectionBlackBoxShard, String> {
    let native = platform != hell_builtins::ClaimPlatform::Linux;
    let subject_oracle = json_string_field(subject, "oracleExecutableSha256")
        .and_then(|value| Digest::from_hex(value).ok())
        .ok_or_else(|| "collection subject oracle executable is malformed".to_owned())?;
    let subject_candidate = json_string_field(subject, "candidateExecutableSha256")
        .and_then(|value| Digest::from_hex(value).ok())
        .ok_or_else(|| "collection subject candidate executable is malformed".to_owned())?;
    if subject_oracle != facts.oracle_executable_sha256
        || subject_candidate != facts.candidate_executable_sha256
        || json_string_field(subject, "candidateCommit") != Some(provider.candidate_commit.as_str())
    {
        return Err("collection subject executable/candidate differs from observation".to_owned());
    }
    let build_record = json_string_field(subject, "oracleBuildRecordSha256")
        .map(Digest::from_hex)
        .transpose()
        .map_err(str::to_owned)?;
    if native != build_record.is_some() {
        return Err("collection native build record applicability is invalid".to_owned());
    }
    Ok(CollectionBlackBoxShard {
        platform,
        case: facts.case,
        oracle_subject: if native {
            CollectionOracleSubject::NativeSourceBuild
        } else {
            CollectionOracleSubject::LinuxSignedReleaseResultOnly
        },
        oracle_source_commit: if native {
            "8e952cf9de4ab25d7716982a9ca234f9bdcf1bff".into()
        } else {
            "d4d028609ed46a560c62caea8c70e7e91d1afd29".into()
        },
        oracle_executable_sha256: facts.oracle_executable_sha256,
        oracle_acquisition_receipt_sha256: facts.oracle_acquisition_receipt_sha256,
        oracle_provider_attestation_sha256: facts.oracle_acquisition_attestation_sha256,
        provider_repository_id: provider.repository_id,
        provider_run_id: provider.run_id,
        provider_run_attempt: provider.run_attempt,
        provider_artifact_id: provider.artifact_id,
        provider_workflow_ref: provider.workflow_ref.clone().into(),
        provider_event: provider.event.clone().into(),
        provider_candidate_subject_sha256: campaign_subject_sha256,
        oracle_build_record_sha256: build_record,
        dependency_authority: if native {
            CollectionDependencyAuthority::ReportedVersionNoExactSource
        } else {
            CollectionDependencyAuthority::UnknownResultOnly
        },
        bundle_sha256: facts.bundle_sha256,
        oracle_observation_sha256: facts.oracle_observation_sha256,
        candidate_observation_sha256: facts.candidate_observation_sha256,
        oracle_stdout_sha256: facts.oracle_stdout_sha256,
        oracle_stderr_sha256: facts.oracle_stderr_sha256,
        oracle_status_sha256: facts.oracle_status_sha256,
        candidate_stdout_sha256: facts.candidate_stdout_sha256,
        candidate_stderr_sha256: facts.candidate_stderr_sha256,
        candidate_status_sha256: facts.candidate_status_sha256,
        candidate_typed_result_sha256: facts.candidate_typed_result_sha256,
        candidate_comparator_trace_sha256: facts.candidate_comparator_trace_sha256,
        oracle_completion: facts.oracle_completion,
        candidate_completion: facts.candidate_completion,
        candidate_source_commit: provider.candidate_commit.clone().into(),
        candidate_executable_sha256: facts.candidate_executable_sha256,
    })
}

fn collection_native_build_authorities(
    input: &Path,
    providers: &[(crate::assurance::VerifiedCollectionProviderArtifact, String)],
    source_manifest: Digest,
) -> Result<Vec<CollectionNativeBuildAuthority>, String> {
    providers
        .iter()
        .filter(|(provider, _)| provider.platform != "linux-amd64")
        .map(|(provider, subject)| {
            let platform = collection_claim_platform(&provider.platform)?;
            let record = input
                .join(&provider.platform)
                .join(format!("oracle-build-{}.json", provider.platform));
            let build_record_sha256 = sha256_file(&record)
                .map_err(|error| format!("cannot hash collection native build record: {error}"))?;
            let build_record_hex = build_record_sha256.hex();
            if json_string_field(subject, "oracleBuildRecordSha256")
                != Some(build_record_hex.as_str())
            {
                return Err("collection subject native build record digest differs".to_owned());
            }
            let oracle_executable_sha256 = json_string_field(subject, "oracleExecutableSha256")
                .and_then(|value| Digest::from_hex(value).ok())
                .ok_or_else(|| "collection native executable digest is malformed".to_owned())?;
            Ok(CollectionNativeBuildAuthority {
                platform,
                source_commit: "8e952cf9de4ab25d7716982a9ca234f9bdcf1bff".into(),
                stack_version: "3.11.1".into(),
                resolver_lock_sha256: Digest::from_hex(
                    "119cff36de1117edfb6098fd9688f9dad843c716d874d02dce49ecdc0dcfb61a",
                )
                .map_err(str::to_owned)?,
                ghc_version: "9.8.2".into(),
                containers_version: "0.6.8".into(),
                cabal_revision_sha256: Digest::from_hex(
                    "bb2bec1bbc6b39a7c97cd95e056a5698ec45beb5d8feb6caae12af64e4bd823c",
                )
                .map_err(str::to_owned)?,
                oracle_executable_sha256,
                build_record_sha256,
                source_authority_manifest_sha256: source_manifest,
            })
        })
        .collect()
}

fn collection_claim_platform(platform: &str) -> Result<hell_builtins::ClaimPlatform, String> {
    match platform {
        "linux-amd64" => Ok(hell_builtins::ClaimPlatform::Linux),
        "macos-arm64" => Ok(hell_builtins::ClaimPlatform::MacOs),
        "windows-amd64" => Ok(hell_builtins::ClaimPlatform::Windows),
        _ => Err("collection authority platform is unknown".to_owned()),
    }
}

fn collection_platform_name(platform: hell_builtins::ClaimPlatform) -> &'static str {
    match platform {
        hell_builtins::ClaimPlatform::Linux => "linux-amd64",
        hell_builtins::ClaimPlatform::MacOs => "macos-arm64",
        hell_builtins::ClaimPlatform::Windows => "windows-amd64",
        hell_builtins::ClaimPlatform::All => "all",
    }
}

fn collection_authority_report(
    source_manifest: Digest,
    providers: &[(crate::assurance::VerifiedCollectionProviderArtifact, String)],
    campaign_subject_sha256: Digest,
    shards: &[CollectionBlackBoxShard],
) -> String {
    let first = &providers[0].0;
    let mut shard_records = String::new();
    for shard in shards {
        writeln!(
            shard_records,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            shard.case.case_id,
            collection_platform_name(shard.platform),
            shard.bundle_sha256.hex(),
            shard.oracle_observation_sha256.hex(),
            shard.candidate_observation_sha256.hex(),
            shard.oracle_stdout_sha256.hex(),
            shard.oracle_stderr_sha256.hex(),
            shard.oracle_status_sha256.hex(),
            shard.candidate_stdout_sha256.hex(),
            shard.candidate_stderr_sha256.hex(),
            shard.candidate_status_sha256.hex(),
            shard.candidate_comparator_trace_sha256.hex(),
        )
        .expect("writing to String cannot fail");
    }
    format!(
        concat!(
            "{{\n  \"schemaVersion\": 1,\n",
            "  \"domain\": \"hell-collection-campaign-verification-v1\",\n",
            "  \"promotionAuthority\": false,\n",
            "  \"durableCustodyComplete\": false,\n",
            "  \"sourceAuthorityManifestSha256\": {source:?},\n",
            "  \"repositoryId\": {repository},\n",
            "  \"providerRunId\": {run},\n",
            "  \"providerRunAttempt\": {attempt},\n",
            "  \"providerHeadCommit\": {provider_head:?},\n",
            "  \"candidateCommit\": {candidate:?},\n",
            "  \"workflowRef\": {workflow:?},\n",
            "  \"event\": {event:?},\n",
            "  \"caseCount\": 1191,\n",
            "  \"platformCount\": 3,\n",
            "  \"shardCount\": 3573,\n",
            "  \"campaignProviderSubjectSha256\": {campaign:?},\n",
            "  \"shardRecordSetSha256\": {shards:?}\n}}\n"
        ),
        source = source_manifest.hex(),
        repository = first.repository_id,
        run = first.run_id,
        attempt = first.run_attempt,
        provider_head = first.provider_head_commit,
        candidate = first.candidate_commit,
        workflow = first.workflow_ref,
        event = first.event,
        campaign = campaign_subject_sha256.hex(),
        shards = sha256_bytes(shard_records.as_bytes()).hex(),
    )
}

fn bind_exact_subject_field(
    bound: &mut Option<String>,
    observed: Option<&str>,
    label: &str,
) -> Result<(), String> {
    let observed = observed.ok_or_else(|| format!("collection subject lacks {label}"))?;
    Digest::from_hex(observed).map_err(|_| format!("collection subject {label} is malformed"))?;
    if let Some(bound) = bound {
        if bound != observed {
            return Err(format!("collection subject {label} drifts by case"));
        }
    } else {
        *bound = Some(observed.to_owned());
    }
    Ok(())
}

#[derive(Default)]
struct CollectionObservedIdentities {
    candidate_executable: Option<String>,
    oracle_executable: Option<String>,
    receipt: Option<String>,
    attestation: Option<String>,
}

fn validate_collection_observations(
    campaign: &Path,
    platform: hell_builtins::ClaimPlatform,
) -> Result<(BTreeMap<String, String>, CollectionObservedIdentities), String> {
    for forbidden in ["claim-index.json", "claim-coverage.json", "coverage.json"] {
        if campaign.join(forbidden).exists() {
            return Err(
                "dormant collection campaign emitted forbidden claim/coverage output".into(),
            );
        }
    }
    let observations = campaign.join("observations");
    let mut cases = reviewed_collection_cases()?;
    bind_runtime_process_helper(&mut cases)?;
    let mut expected = BTreeMap::new();
    let mut identities = CollectionObservedIdentities::default();
    for case in cases {
        let directory = observations.join(case.id.as_ref());
        let bundle = verify_observation_bundle_for_case(&directory, &case)
            .map_err(|error| format!("invalid collection bundle {}: {error}", case.id))?;
        if expected.insert(case.id.to_string(), bundle.hex()).is_some() {
            return Err("dormant collection campaign repeats a case ID".into());
        }
        let oracle = fs::read_to_string(directory.join("oracle/observation.json"))
            .map_err(|error| format!("cannot read collection oracle observation: {error}"))?;
        let candidate = fs::read_to_string(directory.join("candidate/observation.json"))
            .map_err(|error| format!("cannot read collection candidate observation: {error}"))?;
        bind_exact_subject_field(
            &mut identities.oracle_executable,
            json_string_field(&oracle, "sha256"),
            "oracle executable",
        )?;
        bind_exact_subject_field(
            &mut identities.candidate_executable,
            json_string_field(&candidate, "sha256"),
            "candidate executable",
        )?;
        if platform == hell_builtins::ClaimPlatform::Linux {
            bind_exact_subject_field(
                &mut identities.receipt,
                json_string_field(&oracle, "acquisitionReceiptSha256"),
                "Linux acquisition receipt",
            )?;
            bind_exact_subject_field(
                &mut identities.attestation,
                json_string_field(&oracle, "acquisitionAttestationSha256"),
                "Linux acquisition attestation",
            )?;
        }
    }
    if expected.len() != hell_testkit::COLLECTION_CASE_AUTHORITY_COUNT {
        return Err("dormant collection campaign is not exact Map712/Set479".into());
    }
    Ok((expected, identities))
}

fn validate_collection_inventory(
    campaign: &Path,
    expected: &BTreeMap<String, String>,
) -> Result<(String, String), String> {
    let inventory = fs::read_to_string(campaign.join("inventory.tsv"))
        .map_err(|error| format!("cannot read collection inventory: {error}"))?;
    let expected_inventory = expected
        .iter()
        .fold(String::new(), |mut output, (case, digest)| {
            writeln!(output, "{case}\t{digest}").expect("writing to String cannot fail");
            output
        });
    if inventory != expected_inventory {
        return Err("collection inventory differs from exact retained bundle bytes".into());
    }
    let inventory_sha256 = sha256_bytes(inventory.as_bytes()).hex();
    let inventory_record = fs::read_to_string(campaign.join("inventory.sha256"))
        .map_err(|error| format!("cannot read collection inventory digest: {error}"))?;
    if inventory_record != format!("{inventory_sha256}  inventory.tsv\n") {
        return Err("collection inventory digest record is invalid".into());
    }
    let observations = campaign.join("observations");
    let observed_ids = fs::read_dir(&observations)
        .map_err(|error| format!("cannot enumerate collection observations: {error}"))?
        .map(|entry| {
            entry
                .map_err(|error| format!("cannot enumerate collection observations: {error}"))
                .and_then(|entry| {
                    entry
                        .file_name()
                        .into_string()
                        .map_err(|_| "collection observation case ID is not UTF-8".to_owned())
                })
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if observed_ids != expected.keys().cloned().collect() {
        return Err("collection observation tree has missing or extra case directories".into());
    }
    Ok((
        inventory_sha256,
        crate::assurance::record_digest(&observations)?,
    ))
}

struct CollectionCampaignExpectation<'a> {
    platform: &'a str,
    candidate_executable: &'a str,
    oracle_executable: &'a str,
    trusted: &'a CollectionTrustedHarness,
    inventory: &'a str,
    receipt: Option<&'a str>,
    attestation: Option<&'a str>,
}

struct CollectionCampaignManifest<'a> {
    candidate_commit: &'a str,
    expected: &'a CollectionCampaignExpectation<'a>,
}

fn validate_collection_campaign_manifest(
    campaign: &Path,
    expected: &CollectionCampaignExpectation<'_>,
) -> Result<String, String> {
    let path = campaign.join("campaign.json");
    let document = fs::read_to_string(&path)
        .map_err(|error| format!("cannot read collection campaign manifest: {error}"))?;
    let candidate_commit = json_string_field(&document, "candidateSourceCommit")
        .filter(|value| value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| "collection campaign candidate commit is malformed".to_owned())?;
    let expected_document = collection_campaign_manifest_document(&CollectionCampaignManifest {
        candidate_commit,
        expected,
    });
    if document != expected_document {
        return Err("collection campaign manifest is noncanonical or substituted".into());
    }
    let digest = fs::read_to_string(campaign.join("campaign.json.sha256"))
        .map_err(|error| format!("cannot read collection campaign manifest digest: {error}"))?;
    if digest
        != format!(
            "{}  campaign.json\n",
            sha256_bytes(document.as_bytes()).hex()
        )
    {
        return Err("collection campaign manifest digest is invalid".into());
    }
    Ok(candidate_commit.to_owned())
}

fn collection_campaign_manifest_document(document: &CollectionCampaignManifest<'_>) -> String {
    let expected = document.expected;
    let nullable =
        |value: Option<&str>| value.map_or_else(|| "null".to_owned(), |value| format!("{value:?}"));
    format!(
        concat!(
            "{{\n  \"schemaVersion\": 2,\n",
            "  \"domain\": \"hell-dormant-collection-campaign-v2\",\n",
            "  \"platform\": {platform:?},\n",
            "  \"caseCount\": 1191,\n",
            "  \"trustedHarnessSourceCommit\": {trusted_source_commit:?},\n",
            "  \"trustedHellCiExecutableSha256\": {trusted_hell_ci:?},\n",
            "  \"trustedProcessHelperSha256\": {trusted_helper:?},\n",
            "  \"trustedReviewedModelSha256\": {trusted_model:?},\n",
            "  \"sourceAuthorityManifestSha256\": {trusted_manifest:?},\n",
            "  \"candidateSourceCommit\": {candidate_commit:?},\n",
            "  \"candidateExecutableSha256\": {candidate_executable:?},\n",
            "  \"oracleExecutableSha256\": {oracle_executable:?},\n",
            "  \"oracleAcquisitionReceiptSha256\": {},\n",
            "  \"oracleAcquisitionAttestationSha256\": {},\n",
            "  \"inventorySha256\": {inventory:?}\n}}\n"
        ),
        nullable(expected.receipt),
        nullable(expected.attestation),
        platform = expected.platform,
        trusted_source_commit = expected.trusted.source_commit,
        trusted_hell_ci = expected.trusted.hell_ci_sha256.hex(),
        trusted_helper = expected.trusted.process_helper_sha256.hex(),
        trusted_model = expected.trusted.reviewed_model_sha256.hex(),
        trusted_manifest = expected.trusted.source_manifest_sha256.hex(),
        candidate_commit = document.candidate_commit,
        candidate_executable = expected.candidate_executable,
        oracle_executable = expected.oracle_executable,
        inventory = expected.inventory,
    )
}

/// Revalidates every native shard and applies the fail-closed promotion gate.
pub fn promotion_gate(
    root: &Path,
    input: &Path,
    explain: bool,
    report: &mut Report,
) -> Result<(), FailureKind> {
    let started = Instant::now();
    let retained_manifest = read_digested_merged_manifest(input).and_then(|manifest| {
        (json_usize_field(&manifest, "validatedShardCount") == Some(3))
            .then_some(())
            .ok_or_else(|| "retained manifest does not bind three validated shards".to_owned())
    });
    let retained_manifest_passed = retained_manifest.is_ok();
    report.check(
        "retained-merged-manifest",
        started.elapsed(),
        retained_manifest,
    );
    if !retained_manifest_passed {
        return Err(FailureKind::Fixture);
    }
    if explain {
        let explanation = explain_merged_promotion(input);
        report.check("promotion-gate-explain", started.elapsed(), explanation);
    }
    validate_and_merge_native_shards(root, input, report, true)
}

fn explain_merged_promotion(input: &Path) -> Result<(), String> {
    let manifest = read_digested_merged_manifest(input)?;
    let mut failures = Vec::new();
    for (field, expected) in [
        ("validatedShardCount", 3),
        ("missingClaimEvidence", 0),
        ("requiredPlatformSkips", 0),
        ("irrelevantClaimReferences", 0),
        ("profileEvidenceMismatches", 0),
        ("platformEvidenceMismatches", 0),
        ("normalizerEvidenceMismatches", 0),
        ("invalidApplicabilityClaims", 0),
        ("invalidPlatformRecords", 0),
        ("platformProvenanceMismatches", 0),
    ] {
        let observed = json_usize_field(&manifest, field);
        if observed != Some(expected) {
            failures.push(format!("{field}={observed:?}, expected {expected}"));
        }
    }
    let field = "platformEvidenceComplete";
    let observed = json_bool_field(&manifest, field);
    if observed != Some(true) {
        failures.push(format!("{field}={observed:?}, expected true"));
    }
    if json_string_array_field(&manifest, "requiredProfiles") != Some(vec!["upstream"])
        || json_usize_field(&manifest, "unverifiedOutOfScopeClaims").is_none()
        || json_usize_field(&manifest, "reviewedExpectedDivergences").is_none()
    {
        failures.push("promotion scope visibility fields are missing or invalid".to_owned());
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

#[allow(clippy::too_many_lines)]
fn validate_and_merge_native_shards(
    root: &Path,
    input: &Path,
    report: &mut Report,
    require_promotion: bool,
) -> Result<(), FailureKind> {
    const SHARDS: [(&str, &str, bool); 3] = [
        ("linux-amd64", "linux-x86_64", false),
        ("macos-arm64", "macos-aarch64", true),
        ("windows-amd64", "windows-x86_64", true),
    ];
    const SOURCE_COMMIT: &str = "8e952cf9de4ab25d7716982a9ca234f9bdcf1bff";
    let started = Instant::now();
    verify_collection_source_authority(root).map_err(|error| {
        report.check(
            "collection-reviewed-source-authority",
            started.elapsed(),
            Err(error.to_string()),
        );
        FailureKind::Fixture
    })?;
    report.check(
        "collection-reviewed-source-authority",
        started.elapsed(),
        Ok(()),
    );
    let promotion_policy = promotion_policy::load(root).map_err(|detail| {
        report.check("promotion-policy", started.elapsed(), Err(detail));
        FailureKind::Fixture
    })?;
    report.check("promotion-policy", started.elapsed(), Ok(()));
    let review = promotion_policy::load_review(root).map_err(|detail| {
        report.check("promotion-review", started.elapsed(), Err(detail));
        FailureKind::Fixture
    })?;
    report.check("promotion-review", started.elapsed(), Ok(()));
    let oracle_records = oracle_record::load_all(root).map_err(|detail| {
        report.check("reviewed-oracle-records", started.elapsed(), Err(detail));
        FailureKind::Fixture
    })?;
    report.check("reviewed-oracle-records", started.elapsed(), Ok(()));
    let mut merged = String::from("{\n  \"schemaVersion\": 3,\n  \"shards\": [\n");
    let mut candidate_source_commit = None::<String>;
    let mut compatibility_snapshot_sha256 = None::<String>;
    let mut common_summary_fields = BTreeMap::<String, String>::new();
    let expected_missing_claims = missing_claim_evidence();
    let expected_platform_skips = required_platform_skips(root);
    let expected_out_of_scope_claims =
        unverified_out_of_scope_claims(&promotion_policy.required_profiles);
    let current_dependency_lock_sha256 =
        sha256_file(&root.join("Cargo.lock")).map_err(|error| {
            report.check(
                "merge-current-source-identities",
                started.elapsed(),
                Err(format!("cannot hash Cargo.lock: {error}")),
            );
            FailureKind::Io
        })?;
    let current_rust_toolchain_selection_sha256 = sha256_file(&root.join("rust-toolchain.toml"))
        .map_err(|error| {
            report.check(
                "merge-current-source-identities",
                started.elapsed(),
                Err(format!("cannot hash rust-toolchain.toml: {error}")),
            );
            FailureKind::Io
        })?;
    let (_, current_assurance_epoch) = crate::assurance::epoch(root).map_err(|detail| {
        report.check(
            "merge-current-source-identities",
            started.elapsed(),
            Err(detail),
        );
        FailureKind::Fixture
    })?;
    let current_catalog = reviewed_corpus_catalog_json(&committed_differential_cases());
    let current_catalog_sha256 = sha256_bytes(current_catalog.as_bytes()).hex();
    let expected_corpus = current_corpus_identity();
    let mut reviewed_expected_divergences = 0_usize;
    let mut validated_shards = 0_usize;
    let mut linux_acquisition = None::<(crate::release_oracle::AcquisitionIdentity, Digest)>;
    let mut runtime_platform_shards = BTreeMap::<String, Vec<RuntimePlatformShard>>::new();
    for (index, (label, host_platform, source_built)) in SHARDS.iter().enumerate() {
        let directory = input.join(label);
        let summary_path = directory.join("summary.json");
        let summary = io_or_report(
            report,
            format!("merge-{label}"),
            started,
            "read",
            &summary_path,
            fs::read_to_string(&summary_path),
        )?;
        let summary_digest = verify_retained_native_summary(&directory).map_err(|detail| {
            merge_fixture_failure(report, label, started, &summary_path, detail)
        })?;
        let native_environment =
            verify_retained_native_environment(&directory).map_err(|error| {
                merge_fixture_failure(
                    report,
                    label,
                    started,
                    &directory.join("native-environment.json"),
                    error.to_string(),
                )
            })?;
        if native_environment.rust_toolchain_selection_sha256
            != current_rust_toolchain_selection_sha256
        {
            return Err(merge_fixture_failure(
                report,
                label,
                started,
                &directory.join("native-environment.json"),
                "native shard used a different rust-toolchain.toml selection",
            ));
        }
        let parsed_summary = StrictNativeSummary::parse(&summary).map_err(|detail| {
            merge_fixture_failure(report, label, started, &summary_path, detail)
        })?;
        if parsed_summary.string("platform") != Some(host_platform) {
            return Err(merge_fixture_failure(
                report,
                label,
                started,
                &summary_path,
                format!("expected platform identity {host_platform}"),
            ));
        }
        for field in [
            "mismatches",
            "unexpectedTimeouts",
            "staleExactClaims",
            "irrelevantClaimReferences",
            "profileEvidenceMismatches",
            "platformEvidenceMismatches",
            "normalizerEvidenceMismatches",
            "failedClaimObservations",
            "leakedResources",
            "dependencyFailures",
        ] {
            if parsed_summary.usize(field) != Some(0) {
                return Err(merge_fixture_failure(
                    report,
                    label,
                    started,
                    &summary_path,
                    format!("field {field} is missing, malformed, or nonzero"),
                ));
            }
        }
        let missing_claims = parsed_summary.usize("missingEvidenceReferences");
        if missing_claims != Some(expected_missing_claims) {
            return Err(merge_fixture_failure(
                report,
                label,
                started,
                &summary_path,
                format!(
                    "field missingEvidenceReferences is {missing_claims:?}; expected {expected_missing_claims}"
                ),
            ));
        }
        if parsed_summary.usize("unverifiedOutOfScopeClaims") != Some(expected_out_of_scope_claims)
            || parsed_summary.string_array("requiredProfiles") != Some(&["upstream".to_owned()][..])
        {
            return Err(merge_fixture_failure(
                report,
                label,
                started,
                &summary_path,
                "promotion profile scope or out-of-scope count is invalid",
            ));
        }
        let shard_expected_divergences = parsed_summary
            .usize("reviewedExpectedDivergences")
            .ok_or_else(|| {
                merge_fixture_failure(
                    report,
                    label,
                    started,
                    &summary_path,
                    "reviewedExpectedDivergences is missing or malformed",
                )
            })?;
        reviewed_expected_divergences =
            reviewed_expected_divergences.saturating_add(shard_expected_divergences);
        let platform_skips = parsed_summary.usize("requiredPlatformSkips");
        if platform_skips != Some(expected_platform_skips) {
            return Err(merge_fixture_failure(
                report,
                label,
                started,
                &summary_path,
                format!(
                    "field requiredPlatformSkips is {platform_skips:?}; expected {expected_platform_skips}"
                ),
            ));
        }
        if parsed_summary.boolean("promotionReady") != Some(false) {
            return Err(merge_fixture_failure(
                report,
                label,
                started,
                &summary_path,
                "field promotionReady must be false until global validation",
            ));
        }
        if parsed_summary.boolean("repositoryPolicyPassed") != Some(true) {
            return Err(merge_fixture_failure(
                report,
                label,
                started,
                &summary_path,
                "field repositoryPolicyPassed must be true",
            ));
        }
        for (field, expected) in [
            ("schemaVersion", 3),
            ("shardIndex", 0),
            ("shardCount", 1),
            ("observationBundleSchemaVersion", 4),
            ("claimIndexSchemaVersion", 3),
            ("oracleRecordSchemaVersion", 2),
        ] {
            if parsed_summary.usize(field) != Some(expected) {
                return Err(merge_fixture_failure(
                    report,
                    label,
                    started,
                    &summary_path,
                    format!("field {field} must be schema version {expected}"),
                ));
            }
        }
        if validate_current_corpus_summary(&parsed_summary, &expected_corpus).is_err() {
            return Err(merge_fixture_failure(
                report,
                label,
                started,
                &summary_path,
                "retained corpus seed, exact counts, or regenerated corpus digests disagree with the current generator",
            ));
        }
        let claim_index = directory.join("evidence").join("claim-index.json");
        let claim_index_contents = io_or_report(
            report,
            format!("merge-{label}"),
            started,
            "read claim evidence index",
            &claim_index,
            fs::read_to_string(&claim_index),
        )?;
        let parsed_claim_index =
            StrictClaimIndex::parse(&claim_index_contents).map_err(|detail| {
                merge_fixture_failure(report, label, started, &claim_index, detail)
            })?;
        let claim_index_digest = io_or_report(
            report,
            format!("merge-{label}"),
            started,
            "hash claim evidence index",
            &claim_index,
            sha256_file(&claim_index),
        )?;
        if parsed_summary.string("claimEvidenceIndexSha256")
            != Some(claim_index_digest.hex().as_str())
        {
            return Err(merge_fixture_failure(
                report,
                label,
                started,
                &summary_path,
                format!(
                    "field claimEvidenceIndexSha256 does not bind {}",
                    claim_index.display()
                ),
            ));
        }
        if parsed_claim_index.schema_version != 3
            || parsed_claim_index.profile != "upstream"
            || parsed_claim_index.platform != *label
        {
            return Err(merge_fixture_failure(
                report,
                label,
                started,
                &claim_index,
                "claim evidence index schema/profile/platform is invalid",
            ));
        }
        if parsed_claim_index.assurance_epoch_sha256 != current_assurance_epoch.hex() {
            return Err(merge_fixture_failure(
                report,
                label,
                started,
                &claim_index,
                "claim evidence index does not bind the current assurance epoch",
            ));
        }
        let shard_candidate_sha256 = parsed_claim_index.candidate_sha256.as_str();
        Digest::from_hex(shard_candidate_sha256).map_err(|_| {
            merge_fixture_failure(
                report,
                label,
                started,
                &claim_index,
                "claim index candidateSha256 is malformed",
            )
        })?;
        if parsed_summary.string("candidateSha256") != Some(shard_candidate_sha256) {
            return Err(merge_fixture_failure(
                report,
                label,
                started,
                &summary_path,
                "summary candidateSha256 does not match the claim index",
            ));
        }
        if [
            parsed_claim_index.missing_bundles,
            parsed_claim_index.irrelevant_references,
            parsed_claim_index.profile_mismatches,
            parsed_claim_index.platform_mismatches,
            parsed_claim_index.normalizer_mismatches,
            parsed_claim_index.failed_observations,
        ]
        .into_iter()
        .any(|count| count != 0)
        {
            return Err(merge_fixture_failure(
                report,
                label,
                started,
                &claim_index,
                "claim index retains a nonzero validation counter",
            ));
        }
        let platform_runtime_shards = validate_claim_index_contents(
            &claim_index_contents,
            &directory.join("evidence").join("observations"),
            label,
        )
        .map_err(|detail| merge_fixture_failure(report, label, started, &claim_index, detail))?;
        for shard in platform_runtime_shards {
            runtime_platform_shards
                .entry(shard.case_id.to_string())
                .or_default()
                .push(shard);
        }
        for (field, observed, expected) in [
            (
                "candidateSourceCommit",
                parsed_claim_index.candidate_source_commit.as_str(),
                &mut candidate_source_commit,
            ),
            (
                "compatibilitySnapshotSha256",
                parsed_claim_index.compatibility_snapshot_sha256.as_str(),
                &mut compatibility_snapshot_sha256,
            ),
        ] {
            if field == "compatibilitySnapshotSha256"
                && parsed_summary.string(field) != Some(observed)
            {
                return Err(merge_fixture_failure(
                    report,
                    label,
                    started,
                    &summary_path,
                    "summary compatibility snapshot digest does not match the claim index",
                ));
            }
            if let Some(expected) = expected {
                if expected != observed {
                    return Err(merge_fixture_failure(
                        report,
                        label,
                        started,
                        &claim_index,
                        format!("field {field} disagrees with an earlier native shard"),
                    ));
                }
            } else {
                *expected = Some(observed.to_owned());
            }
        }
        for (field, observed) in [
            (
                "promotionPolicySha256",
                parsed_claim_index.promotion_policy_sha256.as_str(),
            ),
            (
                "reviewedCorpusCatalogSha256",
                parsed_claim_index.reviewed_corpus_catalog_sha256.as_str(),
            ),
        ] {
            if field == "promotionPolicySha256" && observed != promotion_policy.sha256.hex() {
                return Err(merge_fixture_failure(
                    report,
                    label,
                    started,
                    &claim_index,
                    "claim index does not bind the committed promotion policy",
                ));
            }
            if field == "reviewedCorpusCatalogSha256"
                && parsed_summary.string(field) != Some(observed)
            {
                return Err(merge_fixture_failure(
                    report,
                    label,
                    started,
                    &summary_path,
                    "summary reviewed corpus catalog digest does not match the claim index",
                ));
            }
            bind_common_field(&mut common_summary_fields, field, observed).map_err(|detail| {
                merge_fixture_failure(report, label, started, &claim_index, detail)
            })?;
        }
        for field in [
            "assuranceEpochSha256",
            "promotionPolicySha256",
            "reviewedCorpusCatalogSha256",
            "promotionReviewSha256",
            "dependencyLockSha256",
            "dependencyPolicyAttestationSha256",
            "expectedMismatchManifestSha256",
        ] {
            let observed = parsed_summary.string(field).ok_or_else(|| {
                merge_fixture_failure(
                    report,
                    label,
                    started,
                    &summary_path,
                    format!("summary field {field} is missing or is not a string"),
                )
            })?;
            bind_common_field(&mut common_summary_fields, field, observed).map_err(|detail| {
                merge_fixture_failure(report, label, started, &summary_path, detail)
            })?;
        }
        if common_summary_fields.get("assuranceEpochSha256") != Some(&current_assurance_epoch.hex())
        {
            return Err(merge_fixture_failure(
                report,
                label,
                started,
                &summary_path,
                "native shard summary does not bind the current assurance epoch",
            ));
        }
        for identity_name in ["oracle-identity.json", "candidate-identity.json"] {
            let identity_path = directory.join(identity_name);
            let identity = io_or_report(
                report,
                format!("merge-{label}"),
                started,
                "read epoch-bound executable identity",
                &identity_path,
                fs::read_to_string(&identity_path),
            )?;
            let parsed_identity = StrictExecutableIdentity::parse(&identity).map_err(|detail| {
                merge_fixture_failure(report, label, started, &identity_path, detail)
            })?;
            let expected_role = if identity_name == "candidate-identity.json" {
                "Candidate"
            } else {
                "Oracle"
            };
            if validate_executable_identity_semantics(
                &parsed_identity,
                expected_role,
                label,
                &parsed_claim_index.candidate_source_commit,
                &current_assurance_epoch.hex(),
            )
            .is_err()
            {
                return Err(merge_fixture_failure(
                    report,
                    label,
                    started,
                    &identity_path,
                    "executable identity role/path/version/build-info/epoch is invalid",
                ));
            }
            Digest::from_hex(&parsed_identity.sha256).map_err(|_| {
                merge_fixture_failure(
                    report,
                    label,
                    started,
                    &identity_path,
                    "executable identity sha256 is malformed",
                )
            })?;
            let summary_digest_field = if identity_name == "candidate-identity.json" {
                "candidateSha256"
            } else {
                "oracleSha256"
            };
            if parsed_summary.string(summary_digest_field) != Some(parsed_identity.sha256.as_str())
            {
                return Err(merge_fixture_failure(
                    report,
                    label,
                    started,
                    &identity_path,
                    format!(
                        "executable identity sha256 does not match summary field {summary_digest_field}"
                    ),
                ));
            }
            let claim_identity_sha256 = if identity_name == "candidate-identity.json" {
                shard_candidate_sha256
            } else {
                parsed_claim_index.oracle_sha256.as_str()
            };
            if parsed_identity.sha256 != claim_identity_sha256 {
                return Err(merge_fixture_failure(
                    report,
                    label,
                    started,
                    &identity_path,
                    format!(
                        "{expected_role} identity does not match claim-index executable digest"
                    ),
                ));
            }
            let linux_oracle = !source_built && identity_name == "oracle-identity.json";
            if !linux_oracle
                && (parsed_identity.acquisition_receipt_id.is_some()
                    || parsed_identity.acquisition_receipt_sha256.is_some()
                    || parsed_identity.acquisition_attestation_sha256.is_some())
            {
                return Err(merge_fixture_failure(
                    report,
                    label,
                    started,
                    &identity_path,
                    "only the Linux release oracle may bind an acquisition receipt",
                ));
            }
        }
        let catalog = directory
            .join("evidence")
            .join("reviewed-corpus-catalog.json");
        let catalog_contents = io_or_report(
            report,
            format!("merge-{label}"),
            started,
            "read reviewed corpus catalog",
            &catalog,
            fs::read_to_string(&catalog),
        )?;
        if catalog_contents != current_catalog
            || common_summary_fields.get("reviewedCorpusCatalogSha256")
                != Some(&current_catalog_sha256)
        {
            return Err(merge_fixture_failure(
                report,
                label,
                started,
                &catalog,
                "reviewed corpus catalog does not match the committed case source",
            ));
        }
        let attestation = directory
            .join("evidence")
            .join("dependency-policy-attestation.json");
        let attestation_contents = io_or_report(
            report,
            format!("merge-{label}"),
            started,
            "read dependency policy attestation",
            &attestation,
            fs::read_to_string(&attestation),
        )?;
        let Some(candidate_commit) = candidate_source_commit.as_deref() else {
            return Err(merge_fixture_failure(
                report,
                label,
                started,
                &attestation,
                "candidate source commit is unavailable for dependency attestation",
            ));
        };
        let expected_attestation =
            dependency_attestation_json(candidate_commit, current_dependency_lock_sha256);
        if attestation_contents != expected_attestation {
            return Err(merge_fixture_failure(
                report,
                label,
                started,
                &attestation,
                "dependency policy attestation does not match candidate source and Cargo.lock",
            ));
        }
        let attestation_digest = sha256_bytes(attestation_contents.as_bytes()).hex();
        if common_summary_fields.get("dependencyPolicyAttestationSha256")
            != Some(&attestation_digest)
        {
            return Err(merge_fixture_failure(
                report,
                label,
                started,
                &attestation,
                "dependency policy attestation digest is not bound consistently",
            ));
        }
        let attestation_digest_path = directory
            .join("evidence")
            .join("dependency-policy-attestation.sha256");
        let attestation_digest_record = io_or_report(
            report,
            format!("merge-{label}"),
            started,
            "read dependency policy attestation digest",
            &attestation_digest_path,
            fs::read_to_string(&attestation_digest_path),
        )?;
        if attestation_digest_record
            != format!("{attestation_digest}  dependency-policy-attestation.json\n")
        {
            return Err(merge_fixture_failure(
                report,
                label,
                started,
                &attestation_digest_path,
                "dependency policy attestation digest record is invalid",
            ));
        }
        if *source_built {
            if parsed_summary
                .string("oracleAcquisitionReceiptId")
                .is_some()
                || parsed_summary
                    .string("oracleAcquisitionReceiptSha256")
                    .is_some()
                || parsed_summary
                    .string("oracleAcquisitionAttestationSha256")
                    .is_some()
            {
                return Err(merge_fixture_failure(
                    report,
                    label,
                    started,
                    &summary_path,
                    "source-built oracle summary carries Linux acquisition identity fields",
                ));
            }
            let build_path = directory.join(format!("oracle-build-{label}.json"));
            let build = io_or_report(
                report,
                format!("merge-{label}"),
                started,
                "read oracle build record",
                &build_path,
                fs::read_to_string(&build_path),
            )?;
            let build_digest = sha256_bytes(build.as_bytes()).hex();
            let build_digest_path = directory.join(format!("oracle-build-{label}.sha256"));
            let recorded_build_digest = io_or_report(
                report,
                format!("merge-{label}"),
                started,
                "read oracle build record digest",
                &build_digest_path,
                fs::read_to_string(&build_digest_path),
            )?;
            if recorded_build_digest != format!("{build_digest}  oracle-build-{label}.json\n") {
                return Err(merge_fixture_failure(
                    report,
                    label,
                    started,
                    &build_digest_path,
                    format!("digest does not bind {}", build_path.display()),
                ));
            }
            let provenance = directory.join("oracle-provenance").join(label);
            let verified_binary_sha256 =
                verify_oracle_build_record(&build, label, SOURCE_COMMIT, &provenance).map_err(
                    |detail| merge_fixture_failure(report, label, started, &build_path, detail),
                )?;
            verify_collection_native_dependency_identity(&provenance).map_err(|detail| {
                merge_fixture_failure(report, label, started, &build_path, detail)
            })?;
            if !build.contains(&format!("\"platform\": \"{label}\""))
                || !build.contains(&format!("\"sourceCommit\": \"{SOURCE_COMMIT}\""))
            {
                return Err(merge_fixture_failure(
                    report,
                    label,
                    started,
                    &build_path,
                    format!(
                        "platform or sourceCommit field does not match {label}/{SOURCE_COMMIT}"
                    ),
                ));
            }
            for (field, relative) in [
                ("sourceTreeStdoutRetainedSha256", "source-tree.stdout"),
                ("resolverSha256", "resolver.lock"),
                ("platformIdentitySha256", "platform.txt"),
                ("stackStdoutRetainedSha256", "stack.stdout"),
                ("compilerStdoutRetainedSha256", "compiler.stdout"),
                ("dependencyStdoutRetainedSha256", "dependencies.stdout"),
                ("buildStdoutRetainedSha256", "build.stdout"),
                ("buildStderrRetainedSha256", "build.stderr"),
            ] {
                let expected = required_merge_string_field(
                    report,
                    label,
                    started,
                    &build_path,
                    &build,
                    field,
                )?;
                let provenance_path = provenance.join(relative);
                let observed = io_or_report(
                    report,
                    format!("merge-{label}"),
                    started,
                    "hash oracle provenance artifact",
                    &provenance_path,
                    sha256_file(&provenance_path),
                )?
                .hex();
                if expected != observed {
                    return Err(merge_fixture_failure(
                        report,
                        label,
                        started,
                        &build_path,
                        format!("field {field} does not match {}", provenance_path.display()),
                    ));
                }
            }
            let executable_name = if label.starts_with("windows-") {
                "hell.exe"
            } else {
                "hell"
            };
            let expected = required_merge_string_field(
                report,
                label,
                started,
                &build_path,
                &build,
                "binarySha256",
            )?;
            if expected != verified_binary_sha256 {
                return Err(merge_fixture_failure(
                    report,
                    label,
                    started,
                    &build_path,
                    "strict oracle build record binary digest disagrees with legacy projection",
                ));
            }
            let oracle_binary = directory.join("oracle").join(label).join(executable_name);
            let observed = io_or_report(
                report,
                format!("merge-{label}"),
                started,
                "hash oracle binary",
                &oracle_binary,
                sha256_file(&oracle_binary),
            )?
            .hex();
            if expected != observed
                || parsed_summary.string("oracleSha256") != Some(observed.as_str())
            {
                return Err(merge_fixture_failure(
                    report,
                    label,
                    started,
                    &build_path,
                    format!(
                        "field binarySha256 does not match {}",
                        oracle_binary.display()
                    ),
                ));
            }
        } else {
            if parsed_summary.string("oracleSha256")
                != Some("5ccc78e62200eb5aea8b9da9161334c61848d0d3e7de2f270929920cfbf357c9")
            {
                return Err(merge_fixture_failure(
                    report,
                    label,
                    started,
                    &summary_path,
                    "field oracleSha256 does not match the reviewed Linux oracle",
                ));
            }
            let attestation_path = directory.join("linux-release-oracle-acquisition.dsse.json");
            let acquisition = crate::assurance::verify_linux_release_acquisition(
                &directory.join("linux-release-oracle"),
                &directory.join("linux-release-provider.json"),
                &directory.join("linux-release-oracle-receipt.json"),
                &attestation_path,
            )
            .map_err(|detail| {
                merge_fixture_failure(report, label, started, &summary_path, detail)
            })?;
            let oracle_identity_path = directory.join("oracle-identity.json");
            let oracle_identity = fs::read_to_string(&oracle_identity_path).map_err(|error| {
                merge_fixture_failure(
                    report,
                    label,
                    started,
                    &oracle_identity_path,
                    format!("cannot reread Linux oracle identity: {error}"),
                )
            })?;
            let attestation_sha256 = sha256_file(&attestation_path).map_err(|error| {
                merge_fixture_failure(
                    report,
                    label,
                    started,
                    &attestation_path,
                    format!("cannot hash Linux acquisition attestation: {error}"),
                )
            })?;
            if parsed_summary.string("oracleAcquisitionReceiptId")
                != Some(acquisition.receipt_id.as_str())
                || parsed_summary.string("oracleAcquisitionReceiptSha256")
                    != Some(acquisition.receipt_sha256.hex().as_str())
                || json_string_field(&oracle_identity, "acquisitionReceiptId")
                    != Some(acquisition.receipt_id.as_str())
                || json_string_field(&oracle_identity, "acquisitionReceiptSha256")
                    != Some(acquisition.receipt_sha256.hex().as_str())
            {
                return Err(merge_fixture_failure(
                    report,
                    label,
                    started,
                    &oracle_identity_path,
                    "Linux acquisition receipt identity is not joined through shard evidence",
                ));
            }
            if parsed_summary.string("oracleAcquisitionAttestationSha256")
                != Some(attestation_sha256.hex().as_str())
                || json_string_field(&oracle_identity, "acquisitionAttestationSha256")
                    != Some(attestation_sha256.hex().as_str())
            {
                return Err(merge_fixture_failure(
                    report,
                    label,
                    started,
                    &oracle_identity_path,
                    "Linux acquisition attestation is not joined through shard evidence",
                ));
            }
            linux_acquisition = Some((acquisition, attestation_sha256));
        }
        if index != 0 {
            merged.push_str(",\n");
        }
        merged.push_str("    { \"platform\": \"");
        merged.push_str(label);
        merged.push_str("\", \"summarySha256\": \"");
        merged.push_str(&summary_digest.hex());
        merged.push_str("\" }");
        validated_shards = validated_shards.saturating_add(1);
    }
    for (field, expected) in [
        ("assuranceEpochSha256", current_assurance_epoch.hex()),
        ("promotionPolicySha256", promotion_policy.sha256.hex()),
        ("promotionReviewSha256", review.sha256.hex()),
        ("dependencyLockSha256", current_dependency_lock_sha256.hex()),
        (
            "expectedMismatchManifestSha256",
            sha256_file(&root.join("compat").join("expected-mismatches.toml"))
                .map_err(|error| {
                    report.check(
                        "merge-current-source-identities",
                        started.elapsed(),
                        Err(format!("cannot hash expected mismatch manifest: {error}")),
                    );
                    FailureKind::Io
                })?
                .hex(),
        ),
    ] {
        if common_summary_fields.get(field) != Some(&expected) {
            return Err(merge_fixture_failure(
                report,
                "common",
                started,
                root,
                format!("field {field} does not match the current reviewed source"),
            ));
        }
    }
    let current_snapshot = sha256_file(&root.join("compat").join("upstream-2026-05-29.json"))
        .map_err(|error| {
            report.check(
                "merge-current-source-identities",
                started.elapsed(),
                Err(format!("cannot hash compatibility snapshot: {error}")),
            );
            FailureKind::Io
        })?
        .hex();
    if compatibility_snapshot_sha256.as_deref() != Some(current_snapshot.as_str()) {
        return Err(merge_fixture_failure(
            report,
            "common",
            started,
            root,
            "compatibility snapshot does not match current reviewed source",
        ));
    }
    let expected_runtime_cases = committed_differential_cases()
        .into_iter()
        .filter(|case| {
            case.claim_evidence.as_ref().is_some_and(|descriptor| {
                descriptor.semantic_targets.iter().any(|target| {
                    [
                        hell_builtins::ClaimPlatform::Linux,
                        hell_builtins::ClaimPlatform::MacOs,
                        hell_builtins::ClaimPlatform::Windows,
                    ]
                    .iter()
                    .all(|platform| {
                        target
                            .platforms
                            .contains(&hell_builtins::ClaimPlatform::All)
                            || target.platforms.contains(platform)
                    }) && matches!(
                        target.causal_signal,
                        hell_testkit::CausalSignal::RuntimeAdapter
                            | hell_testkit::CausalSignal::RuntimeAdapterAndForceTrace
                            | hell_testkit::CausalSignal::EffectEvent
                            | hell_testkit::CausalSignal::TaskAndCancellation
                            | hell_testkit::CausalSignal::PresentationField
                            | hell_testkit::CausalSignal::ResourceLifecycle
                    )
                })
            })
        })
        .map(|case| case.id.to_string())
        .collect::<BTreeSet<_>>();
    if runtime_platform_shards
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>()
        != expected_runtime_cases
    {
        return Err(merge_fixture_failure(
            report,
            "runtime-platform-set",
            started,
            input,
            "retained runtime platform case set is incomplete",
        ));
    }
    for (case_id, shards) in &runtime_platform_shards {
        validate_runtime_platform_set(shards).map_err(|detail| {
            merge_fixture_failure(
                report,
                "runtime-platform-set",
                started,
                input,
                format!("runtime case {case_id:?} is not closed: {detail}"),
            )
        })?;
    }
    report.check("merge-current-source-identities", started.elapsed(), Ok(()));
    let platform_evidence_complete = validated_shards == SHARDS.len();
    let platform_state = oracle_record::validate_against_shards(&oracle_records, input);
    let platform_evidence_complete = platform_evidence_complete && platform_state.complete();
    let review_ready = review.require_accepted().is_ok();
    merged.push_str("\n  ],\n  \"validatedShardCount\": ");
    write!(merged, "{validated_shards}").expect("writing to String cannot fail");
    merged.push_str(",\n  \"requiredShardCount\": 3");
    merged.push_str(",\n  \"assuranceEpochSha256\": ");
    write!(merged, "{:?}", current_assurance_epoch.hex()).expect("writing to String cannot fail");
    let (linux_acquisition, linux_attestation_sha256) = linux_acquisition.ok_or_else(|| {
        merge_fixture_failure(
            report,
            "linux-amd64",
            started,
            input,
            "Linux release acquisition was not revalidated",
        )
    })?;
    merged.push_str(",\n  \"linuxOracleAcquisitionReceiptId\": ");
    write!(merged, "{:?}", linux_acquisition.receipt_id).expect("writing to String cannot fail");
    merged.push_str(",\n  \"linuxOracleAcquisitionReceiptSha256\": ");
    write!(merged, "{:?}", linux_acquisition.receipt_sha256.hex())
        .expect("writing to String cannot fail");
    merged.push_str(",\n  \"linuxOracleAcquisitionAttestationSha256\": ");
    write!(merged, "{:?}", linux_attestation_sha256.hex()).expect("writing to String cannot fail");
    merged.push_str(",\n  \"promotionReady\": ");
    merged.push_str(if native_merge_promotion_ready() {
        "true"
    } else {
        "false"
    });
    merged.push_str(",\n  \"missingClaimEvidence\": ");
    merged.push_str(&expected_missing_claims.to_string());
    merged.push_str(",\n  \"unverifiedOutOfScopeClaims\": ");
    merged.push_str(&expected_out_of_scope_claims.to_string());
    merged.push_str(",\n  \"requiredProfiles\": [\"upstream\"]");
    merged.push_str(",\n  \"reviewedExpectedDivergences\": ");
    merged.push_str(&reviewed_expected_divergences.to_string());
    merged.push_str(",\n  \"irrelevantClaimReferences\": 0");
    merged.push_str(",\n  \"profileEvidenceMismatches\": 0");
    merged.push_str(",\n  \"platformEvidenceMismatches\": 0");
    merged.push_str(",\n  \"normalizerEvidenceMismatches\": 0");
    merged.push_str(",\n  \"failedClaimObservations\": 0");
    merged.push_str(",\n  \"invalidApplicabilityClaims\": 0");
    merged.push_str(",\n  \"requiredPlatformSkips\": ");
    merged.push_str(&expected_platform_skips.to_string());
    merged.push_str(",\n  \"platformEvidenceComplete\": ");
    merged.push_str(if platform_evidence_complete {
        "true"
    } else {
        "false"
    });
    merged.push_str(",\n  \"invalidPlatformRecords\": ");
    merged.push_str(&platform_state.invalid_records.to_string());
    merged.push_str(",\n  \"platformProvenanceMismatches\": ");
    merged.push_str(&platform_state.provenance_mismatches.to_string());
    merged.push_str(",\n  \"reviewAccepted\": ");
    merged.push_str(if review_ready { "true" } else { "false" });
    merged.push_str(",\n  \"promotionPolicySha256\": \"");
    merged.push_str(&promotion_policy.sha256.hex());
    merged.push('"');
    merged.push_str(",\n  \"promotionReviewSha256\": \"");
    merged.push_str(&review.sha256.hex());
    merged.push('"');
    if let Some(value) = common_summary_fields.get("reviewedCorpusCatalogSha256") {
        merged.push_str(",\n  \"reviewedCorpusCatalogSha256\": \"");
        merged.push_str(value);
        merged.push('"');
    }
    if let Some(value) = compatibility_snapshot_sha256.as_deref() {
        merged.push_str(",\n  \"compatibilitySnapshotSha256\": \"");
        merged.push_str(value);
        merged.push('"');
    }
    if let Some(value) = candidate_source_commit.as_deref() {
        merged.push_str(",\n  \"candidateSourceCommit\": \"");
        merged.push_str(value);
        merged.push('"');
    }
    merged.push_str("\n}\n");
    if require_promotion {
        let retained = read_digested_merged_manifest(input).map_err(|detail| {
            report.check("promotion-gate-read-only", started.elapsed(), Err(detail));
            FailureKind::Fixture
        })?;
        if retained != merged {
            report.check(
                "promotion-gate-read-only",
                started.elapsed(),
                Err("retained merged manifest differs from revalidated shard state".to_owned()),
            );
            return Err(FailureKind::Fixture);
        }
        report.check("promotion-gate-read-only", started.elapsed(), Ok(()));
        let result = validate_merged_mechanical(input);
        let passed = result.is_ok();
        report.check("promotion-gate", started.elapsed(), result);
        passed.then_some(()).ok_or(FailureKind::Fixture)
    } else {
        io_or_report(
            report,
            "merged-manifest-retention",
            started,
            "create merged manifest directory",
            input,
            fs::create_dir_all(input),
        )?;
        let merged_path = input.join("merged-native-shards.json");
        io_or_report(
            report,
            "merged-manifest-retention",
            started,
            "write merged manifest",
            &merged_path,
            fs::write(&merged_path, merged.as_bytes()),
        )?;
        let merged_digest = sha256_bytes(merged.as_bytes()).hex();
        let merged_digest_path = input.join("merged-native-shards.sha256");
        io_or_report(
            report,
            "merged-manifest-retention",
            started,
            "write merged manifest digest",
            &merged_digest_path,
            fs::write(
                &merged_digest_path,
                format!("{merged_digest}  merged-native-shards.json\n"),
            ),
        )?;
        report.check("merge-native-shards", started.elapsed(), Ok(()));
        Ok(())
    }
}

const NATIVE_CORPUS_SEED: u64 = 0x4845_4c4c_2026;
const NATIVE_GENERATED_CASES: usize = 1_024;

#[derive(Clone, Copy)]
enum SummaryFieldKind {
    Number,
    String,
    OptionalString,
    Boolean,
    StringArray,
}

const NATIVE_SUMMARY_FIELDS: &[(&str, SummaryFieldKind)] = &[
    ("schemaVersion", SummaryFieldKind::Number),
    ("shardIndex", SummaryFieldKind::Number),
    ("shardCount", SummaryFieldKind::Number),
    ("observationBundleSchemaVersion", SummaryFieldKind::Number),
    ("claimIndexSchemaVersion", SummaryFieldKind::Number),
    ("oracleRecordSchemaVersion", SummaryFieldKind::Number),
    ("platform", SummaryFieldKind::String),
    ("runnerOs", SummaryFieldKind::String),
    ("runnerArch", SummaryFieldKind::String),
    ("collectedAt", SummaryFieldKind::String),
    ("runnerImageIdentitySha256", SummaryFieldKind::String),
    ("rustToolchainSha256", SummaryFieldKind::String),
    ("buildEnvironmentSha256", SummaryFieldKind::String),
    ("oracleSha256", SummaryFieldKind::String),
    (
        "oracleAcquisitionReceiptId",
        SummaryFieldKind::OptionalString,
    ),
    (
        "oracleAcquisitionReceiptSha256",
        SummaryFieldKind::OptionalString,
    ),
    (
        "oracleAcquisitionAttestationSha256",
        SummaryFieldKind::OptionalString,
    ),
    ("candidateSha256", SummaryFieldKind::String),
    ("assuranceEpochSha256", SummaryFieldKind::String),
    ("corpusSeed", SummaryFieldKind::Number),
    (
        "committedDifferentialObservations",
        SummaryFieldKind::Number,
    ),
    (
        "generatedDifferentialObservations",
        SummaryFieldKind::Number,
    ),
    ("corpusSha256", SummaryFieldKind::String),
    ("reviewedCommittedCorpusSha256", SummaryFieldKind::String),
    ("generatedStressCorpusSha256", SummaryFieldKind::String),
    ("promotionPolicySha256", SummaryFieldKind::String),
    ("reviewedCorpusCatalogSha256", SummaryFieldKind::String),
    ("promotionReviewSha256", SummaryFieldKind::String),
    ("mismatches", SummaryFieldKind::Number),
    ("reviewedExpectedDivergences", SummaryFieldKind::Number),
    ("unexpectedTimeouts", SummaryFieldKind::Number),
    ("staleExactClaims", SummaryFieldKind::Number),
    ("irrelevantClaimReferences", SummaryFieldKind::Number),
    ("profileEvidenceMismatches", SummaryFieldKind::Number),
    ("platformEvidenceMismatches", SummaryFieldKind::Number),
    ("normalizerEvidenceMismatches", SummaryFieldKind::Number),
    ("failedClaimObservations", SummaryFieldKind::Number),
    ("missingEvidenceReferences", SummaryFieldKind::Number),
    ("unverifiedOutOfScopeClaims", SummaryFieldKind::Number),
    ("requiredProfiles", SummaryFieldKind::StringArray),
    ("compatibilitySnapshotSha256", SummaryFieldKind::String),
    ("claimEvidenceIndexSha256", SummaryFieldKind::String),
    ("dependencyLockSha256", SummaryFieldKind::String),
    (
        "dependencyPolicyAttestationSha256",
        SummaryFieldKind::String,
    ),
    ("expectedMismatchManifestSha256", SummaryFieldKind::String),
    ("repositoryPolicyPassed", SummaryFieldKind::Boolean),
    ("requiredPlatformSkips", SummaryFieldKind::Number),
    ("leakedResources", SummaryFieldKind::Number),
    ("dependencyFailures", SummaryFieldKind::Number),
    ("promotionReady", SummaryFieldKind::Boolean),
];

#[derive(Clone, Debug, PartialEq, Eq)]
enum SummaryFieldValue {
    Number(u64),
    String(String),
    OptionalString(Option<String>),
    Boolean(bool),
    StringArray(Vec<String>),
}

struct StrictNativeSummary {
    fields: BTreeMap<&'static str, SummaryFieldValue>,
}

impl StrictNativeSummary {
    fn parse(document: &str) -> Result<Self, String> {
        let mut lines = document.lines();
        if lines.next() != Some("{") {
            return Err("native summary must start with the canonical object opener".into());
        }
        let mut fields = BTreeMap::new();
        for (index, (name, kind)) in NATIVE_SUMMARY_FIELDS.iter().copied().enumerate() {
            let line = lines
                .next()
                .ok_or_else(|| format!("native summary is missing field {name}"))?;
            let prefix = format!("  \"{name}\": ");
            let encoded = line
                .strip_prefix(&prefix)
                .ok_or_else(|| format!("native summary field {name} is out of order or missing"))?;
            let encoded = if index + 1 == NATIVE_SUMMARY_FIELDS.len() {
                encoded
            } else {
                encoded.strip_suffix(',').ok_or_else(|| {
                    format!("native summary field {name} lacks its canonical separator")
                })?
            };
            let value = parse_summary_field(name, kind, encoded)?;
            fields.insert(name, value);
        }
        if lines.next() != Some("}") || lines.next().is_some() || !document.ends_with("}\n") {
            return Err("native summary has extra fields or noncanonical trailing bytes".into());
        }
        Ok(Self { fields })
    }

    fn u64(&self, name: &str) -> Option<u64> {
        match self.fields.get(name)? {
            SummaryFieldValue::Number(value) => Some(*value),
            _ => None,
        }
    }

    fn usize(&self, name: &str) -> Option<usize> {
        usize::try_from(self.u64(name)?).ok()
    }

    fn string(&self, name: &str) -> Option<&str> {
        match self.fields.get(name)? {
            SummaryFieldValue::String(value) | SummaryFieldValue::OptionalString(Some(value)) => {
                Some(value)
            }
            _ => None,
        }
    }

    fn boolean(&self, name: &str) -> Option<bool> {
        match self.fields.get(name)? {
            SummaryFieldValue::Boolean(value) => Some(*value),
            _ => None,
        }
    }

    fn string_array(&self, name: &str) -> Option<&[String]> {
        match self.fields.get(name)? {
            SummaryFieldValue::StringArray(values) => Some(values),
            _ => None,
        }
    }
}

fn parse_summary_field(
    name: &str,
    kind: SummaryFieldKind,
    encoded: &str,
) -> Result<SummaryFieldValue, String> {
    let malformed = || format!("native summary field {name} is malformed or noncanonical");
    match kind {
        SummaryFieldKind::Number => {
            let value = encoded.parse::<u64>().map_err(|_| malformed())?;
            (value.to_string() == encoded)
                .then_some(SummaryFieldValue::Number(value))
                .ok_or_else(malformed)
        }
        SummaryFieldKind::String => parse_summary_string(encoded)
            .map(SummaryFieldValue::String)
            .ok_or_else(malformed),
        SummaryFieldKind::OptionalString => {
            if encoded == "null" {
                Ok(SummaryFieldValue::OptionalString(None))
            } else {
                parse_summary_string(encoded)
                    .map(|value| SummaryFieldValue::OptionalString(Some(value)))
                    .ok_or_else(malformed)
            }
        }
        SummaryFieldKind::Boolean => match encoded {
            "true" => Ok(SummaryFieldValue::Boolean(true)),
            "false" => Ok(SummaryFieldValue::Boolean(false)),
            _ => Err(malformed()),
        },
        SummaryFieldKind::StringArray => parse_summary_string_array(encoded)
            .map(SummaryFieldValue::StringArray)
            .ok_or_else(malformed),
    }
}

fn parse_summary_string(encoded: &str) -> Option<String> {
    let value = encoded.strip_prefix('"')?.strip_suffix('"')?;
    let mut decoded = String::new();
    let mut characters = value.chars();
    while let Some(character) = characters.next() {
        if character != '\\' {
            if character == '"' || character.is_control() {
                return None;
            }
            decoded.push(character);
            continue;
        }
        match characters.next()? {
            '"' => decoded.push('"'),
            '\\' => decoded.push('\\'),
            'n' => decoded.push('\n'),
            'r' => decoded.push('\r'),
            't' => decoded.push('\t'),
            'u' => {
                let digits = [
                    characters.next()?,
                    characters.next()?,
                    characters.next()?,
                    characters.next()?,
                ];
                let digits = digits.into_iter().collect::<String>();
                decoded.push(char::from_u32(u32::from_str_radix(&digits, 16).ok()?)?);
            }
            _ => return None,
        }
    }
    (summary_json_string(&decoded) == encoded).then_some(decoded)
}

fn summary_json_string(value: &str) -> String {
    let mut encoded = String::from("\"");
    for character in value.chars() {
        match character {
            '"' => encoded.push_str("\\\""),
            '\\' => encoded.push_str("\\\\"),
            '\n' => encoded.push_str("\\n"),
            '\r' => encoded.push_str("\\r"),
            '\t' => encoded.push_str("\\t"),
            value if value <= '\u{1f}' => {
                write!(encoded, "\\u{:04x}", u32::from(value))
                    .expect("writing to String cannot fail");
            }
            value => encoded.push(value),
        }
    }
    encoded.push('"');
    encoded
}

fn parse_summary_string_array(encoded: &str) -> Option<Vec<String>> {
    let inner = encoded.strip_prefix('[')?.strip_suffix(']')?;
    if inner.is_empty() {
        return Some(Vec::new());
    }
    inner
        .split(", ")
        .map(parse_summary_string)
        .collect::<Option<Vec<_>>>()
}

#[derive(Clone, Debug)]
struct StrictExecutableIdentity {
    schema_version: usize,
    role: String,
    path: String,
    sha256: String,
    reported_version: String,
    assurance_epoch_sha256: Option<String>,
    acquisition_receipt_id: Option<String>,
    acquisition_receipt_sha256: Option<String>,
    acquisition_attestation_sha256: Option<String>,
    build_info: Option<Vec<String>>,
}

#[derive(Debug)]
struct StrictClaimIndex {
    schema_version: usize,
    compatibility_snapshot_sha256: String,
    assurance_epoch_sha256: String,
    promotion_policy_sha256: String,
    reviewed_corpus_catalog_sha256: String,
    oracle_sha256: String,
    candidate_sha256: String,
    candidate_source_commit: String,
    platform: String,
    profile: String,
    indexed_entries: usize,
    missing_bundles: usize,
    irrelevant_references: usize,
    profile_mismatches: usize,
    platform_mismatches: usize,
    normalizer_mismatches: usize,
    failed_observations: usize,
    entries: Vec<String>,
}

impl StrictClaimIndex {
    fn parse(document: &str) -> Result<Self, String> {
        const FIELDS: [(&str, SummaryFieldKind); 17] = [
            ("schemaVersion", SummaryFieldKind::Number),
            ("compatibilitySnapshotSha256", SummaryFieldKind::String),
            ("assuranceEpochSha256", SummaryFieldKind::String),
            ("promotionPolicySha256", SummaryFieldKind::String),
            ("reviewedCorpusCatalogSha256", SummaryFieldKind::String),
            ("oracleSha256", SummaryFieldKind::String),
            ("candidateSha256", SummaryFieldKind::String),
            ("candidateSourceCommit", SummaryFieldKind::String),
            ("platform", SummaryFieldKind::String),
            ("profile", SummaryFieldKind::String),
            ("indexedEntries", SummaryFieldKind::Number),
            ("missingBundles", SummaryFieldKind::Number),
            ("irrelevantReferences", SummaryFieldKind::Number),
            ("profileMismatches", SummaryFieldKind::Number),
            ("platformMismatches", SummaryFieldKind::Number),
            ("normalizerMismatches", SummaryFieldKind::Number),
            ("failedObservations", SummaryFieldKind::Number),
        ];
        let mut lines = document.lines().peekable();
        if lines.next() != Some("{") {
            return Err("claim index lacks canonical object opener".to_owned());
        }
        let mut values = BTreeMap::new();
        for (name, kind) in FIELDS {
            let line = lines
                .next()
                .ok_or_else(|| format!("claim index is missing field {name}"))?;
            let prefix = format!("  \"{name}\": ");
            let encoded = line
                .strip_prefix(&prefix)
                .and_then(|value| value.strip_suffix(','))
                .ok_or_else(|| format!("claim index field {name} is out of order"))?;
            values.insert(name, parse_summary_field(name, kind, encoded)?);
        }
        if lines.next() != Some("  \"entries\": [") {
            return Err("claim index entries field is missing or out of order".to_owned());
        }
        let entries = parse_strict_claim_entries(&mut lines)?;
        if lines.next() != Some("}") || lines.next().is_some() || !document.ends_with("}\n") {
            return Err("claim index has extra fields or trailing bytes".to_owned());
        }
        let number = |name| match values.get(name) {
            Some(SummaryFieldValue::Number(value)) => usize::try_from(*value).ok(),
            _ => None,
        };
        let string = |name| match values.get(name) {
            Some(SummaryFieldValue::String(value)) => Some(value.clone()),
            _ => None,
        };
        Ok(Self {
            schema_version: number("schemaVersion")
                .ok_or_else(|| "claim index schema version is malformed".to_owned())?,
            compatibility_snapshot_sha256: string("compatibilitySnapshotSha256")
                .ok_or_else(|| "claim index compatibility snapshot is malformed".to_owned())?,
            assurance_epoch_sha256: string("assuranceEpochSha256")
                .ok_or_else(|| "claim index assurance epoch is malformed".to_owned())?,
            promotion_policy_sha256: string("promotionPolicySha256")
                .ok_or_else(|| "claim index promotion policy is malformed".to_owned())?,
            reviewed_corpus_catalog_sha256: string("reviewedCorpusCatalogSha256")
                .ok_or_else(|| "claim index reviewed corpus catalog is malformed".to_owned())?,
            oracle_sha256: string("oracleSha256")
                .ok_or_else(|| "claim index oracle digest is malformed".to_owned())?,
            candidate_sha256: string("candidateSha256")
                .ok_or_else(|| "claim index candidate digest is malformed".to_owned())?,
            candidate_source_commit: string("candidateSourceCommit")
                .ok_or_else(|| "claim index candidate source commit is malformed".to_owned())?,
            platform: string("platform")
                .ok_or_else(|| "claim index platform is malformed".to_owned())?,
            profile: string("profile")
                .ok_or_else(|| "claim index profile is malformed".to_owned())?,
            indexed_entries: number("indexedEntries")
                .ok_or_else(|| "claim index entry count is malformed".to_owned())?,
            missing_bundles: number("missingBundles")
                .ok_or_else(|| "claim index missing bundle count is malformed".to_owned())?,
            irrelevant_references: number("irrelevantReferences")
                .ok_or_else(|| "claim index irrelevant reference count is malformed".to_owned())?,
            profile_mismatches: number("profileMismatches")
                .ok_or_else(|| "claim index profile mismatch count is malformed".to_owned())?,
            platform_mismatches: number("platformMismatches")
                .ok_or_else(|| "claim index platform mismatch count is malformed".to_owned())?,
            normalizer_mismatches: number("normalizerMismatches")
                .ok_or_else(|| "claim index normalizer mismatch count is malformed".to_owned())?,
            failed_observations: number("failedObservations")
                .ok_or_else(|| "claim index failed observation count is malformed".to_owned())?,
            entries,
        })
    }
}

fn parse_strict_claim_entries(
    lines: &mut std::iter::Peekable<std::str::Lines<'_>>,
) -> Result<Vec<String>, String> {
    let mut entries = Vec::new();
    loop {
        let line = lines
            .next()
            .ok_or_else(|| "claim index entries array is unterminated".to_owned())?;
        if line == "  ]" {
            return Ok(entries);
        }
        let encoded = line
            .strip_prefix("    ")
            .ok_or_else(|| "claim index entry has noncanonical indentation".to_owned())?;
        let last = lines.peek().copied() == Some("  ]");
        let canonical = if last {
            if encoded.ends_with(',') {
                return Err("claim index final entry has a trailing separator".to_owned());
            }
            encoded
        } else {
            encoded
                .strip_suffix(',')
                .ok_or_else(|| "claim index entry lacks a canonical separator".to_owned())?
        };
        entries.push(canonical.to_owned());
    }
}

impl StrictExecutableIdentity {
    fn parse(document: &str) -> Result<Self, String> {
        const FIELDS: [(&str, SummaryFieldKind); 10] = [
            ("schemaVersion", SummaryFieldKind::Number),
            ("role", SummaryFieldKind::String),
            ("path", SummaryFieldKind::String),
            ("sha256", SummaryFieldKind::String),
            ("reportedVersion", SummaryFieldKind::String),
            ("assuranceEpochSha256", SummaryFieldKind::OptionalString),
            ("acquisitionReceiptId", SummaryFieldKind::OptionalString),
            ("acquisitionReceiptSha256", SummaryFieldKind::OptionalString),
            (
                "acquisitionAttestationSha256",
                SummaryFieldKind::OptionalString,
            ),
            ("buildInfo", SummaryFieldKind::StringArray),
        ];
        let mut lines = document.lines();
        if lines.next() != Some("{") {
            return Err("executable identity lacks canonical object opener".into());
        }
        let mut values = BTreeMap::new();
        for (index, (name, kind)) in FIELDS.into_iter().enumerate() {
            let line = lines
                .next()
                .ok_or_else(|| format!("executable identity is missing field {name}"))?;
            let prefix = format!("  \"{name}\": ");
            let encoded = line
                .strip_prefix(&prefix)
                .ok_or_else(|| format!("executable identity field {name} is out of order"))?;
            let encoded = if index + 1 == FIELDS.len() {
                encoded
            } else {
                encoded.strip_suffix(',').ok_or_else(|| {
                    format!("executable identity field {name} lacks canonical separator")
                })?
            };
            let value = if name == "buildInfo" && encoded == "null" {
                SummaryFieldValue::OptionalString(None)
            } else {
                parse_summary_field(name, kind, encoded)?
            };
            values.insert(name, value);
        }
        if lines.next() != Some("}") || lines.next().is_some() || !document.ends_with("}\n") {
            return Err("executable identity has extra fields or trailing bytes".into());
        }
        let number = |name| match values.get(name) {
            Some(SummaryFieldValue::Number(value)) => usize::try_from(*value).ok(),
            _ => None,
        };
        let string = |name| match values.get(name) {
            Some(SummaryFieldValue::String(value)) => Some(value.clone()),
            _ => None,
        };
        let optional = |name| match values.get(name) {
            Some(SummaryFieldValue::OptionalString(value)) => Some(value.clone()),
            _ => None,
        };
        let string_array = |name| match values.get(name) {
            Some(SummaryFieldValue::StringArray(value)) => Some(Some(value.clone())),
            Some(SummaryFieldValue::OptionalString(None)) => Some(None),
            _ => None,
        };
        Ok(Self {
            schema_version: number("schemaVersion")
                .ok_or_else(|| "executable identity schema version is malformed".to_owned())?,
            role: string("role")
                .ok_or_else(|| "executable identity role is malformed".to_owned())?,
            path: string("path")
                .ok_or_else(|| "executable identity path is malformed".to_owned())?,
            sha256: string("sha256")
                .ok_or_else(|| "executable identity digest is malformed".to_owned())?,
            reported_version: string("reportedVersion")
                .ok_or_else(|| "executable identity version is malformed".to_owned())?,
            assurance_epoch_sha256: optional("assuranceEpochSha256")
                .ok_or_else(|| "executable identity epoch is malformed".to_owned())?,
            acquisition_receipt_id: optional("acquisitionReceiptId")
                .ok_or_else(|| "executable identity receipt ID is malformed".to_owned())?,
            acquisition_receipt_sha256: optional("acquisitionReceiptSha256")
                .ok_or_else(|| "executable identity receipt digest is malformed".to_owned())?,
            acquisition_attestation_sha256: optional("acquisitionAttestationSha256")
                .ok_or_else(|| "executable identity attestation is malformed".to_owned())?,
            build_info: string_array("buildInfo")
                .ok_or_else(|| "executable identity build info is malformed".to_owned())?,
        })
    }
}

fn expected_candidate_build_info(source_commit: &str) -> Vec<String> {
    vec![
        format!("hell-rs {}", env!("CARGO_PKG_VERSION")),
        format!("language baseline {}", hell_builtins::LANGUAGE_VERSION),
        format!("upstream {}", hell_builtins::UPSTREAM_COMMIT),
        format!("source commit {source_commit}"),
        "compatibility evidence schema 1".to_owned(),
        format!(
            "compiler policy {:?}",
            hell_compiler::CompilerConfig::upstream()
        ),
        format!(
            "runtime policy {:?}",
            hell_runtime::policy::RuntimePolicy::upstream()
        ),
    ]
}

fn canonical_identity_path(path: &str, platform: &str) -> bool {
    if path.is_empty() || path.chars().any(char::is_control) {
        return false;
    }
    let executable = if platform == "windows-amd64" {
        "hell.exe"
    } else {
        "hell"
    };
    if platform == "windows-amd64" {
        let bytes = path.as_bytes();
        bytes.len() > executable.len() + 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && bytes[2] == b'\\'
            && !path.contains('/')
            && !path.contains("\\.\\")
            && !path.contains("\\..\\")
            && path
                .strip_suffix(executable)
                .is_some_and(|prefix| prefix.ends_with('\\'))
    } else {
        let parsed = Path::new(path);
        parsed.is_absolute()
            && parsed.file_name().and_then(std::ffi::OsStr::to_str) == Some(executable)
            && !parsed.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::CurDir | std::path::Component::ParentDir
                )
            })
    }
}

fn validate_executable_identity_semantics(
    identity: &StrictExecutableIdentity,
    expected_role: &str,
    platform: &str,
    candidate_source_commit: &str,
    assurance_epoch_sha256: &str,
) -> Result<(), String> {
    let build_info_valid = if expected_role == "Candidate" {
        identity.build_info.as_ref()
            == Some(&expected_candidate_build_info(candidate_source_commit))
    } else {
        identity.build_info.is_none()
    };
    if identity.schema_version != 3
        || identity.role != expected_role
        || !canonical_identity_path(&identity.path, platform)
        || identity.reported_version != hell_builtins::LANGUAGE_VERSION
        || !build_info_valid
        || identity.assurance_epoch_sha256.as_deref() != Some(assurance_epoch_sha256)
    {
        return Err("executable identity role/path/version/build-info/epoch is invalid".to_owned());
    }
    Ok(())
}

struct CurrentCorpusIdentity {
    seed: u64,
    committed_count: usize,
    generated_count: usize,
    corpus_sha256: Digest,
    reviewed_committed_corpus_sha256: Digest,
    generated_stress_corpus_sha256: Digest,
}

const ORACLE_BUILD_WARNING_POLICY: &str =
    include_str!("../../../compat/oracle-build-warning-policy.toml");

struct OracleBuildWarningPolicy {
    sha256: Digest,
    fail_patterns: Vec<String>,
    review_patterns: Vec<String>,
}

#[derive(Clone, Copy)]
struct OracleBuildWarningIdentity {
    fail_count: u64,
    review_count: u64,
    findings_sha256: Digest,
}

fn oracle_build_warning_policy() -> Result<OracleBuildWarningPolicy, String> {
    const REQUIRED_FAIL: [&str; 3] = [
        "using an unpinned source",
        "ignoring lock file",
        "falling back to system package",
    ];
    const REQUIRED_REVIEW: [&str; 1] = ["warning:"];
    let mut values = crate::strict_toml::assignments(ORACLE_BUILD_WARNING_POLICY)?;
    let schema =
        crate::strict_toml::unsigned(&crate::strict_toml::take(&mut values, "schema_version")?)?;
    let fail_patterns =
        crate::strict_toml::string_array(&crate::strict_toml::take(&mut values, "fail_patterns")?)?;
    let review_patterns = crate::strict_toml::string_array(&crate::strict_toml::take(
        &mut values,
        "review_patterns",
    )?)?;
    crate::strict_toml::finish(&values)?;
    if schema != 1 || fail_patterns != REQUIRED_FAIL || review_patterns != REQUIRED_REVIEW {
        return Err("oracle build warning policy is not the reviewed exact schema".to_owned());
    }
    Ok(OracleBuildWarningPolicy {
        sha256: sha256_bytes(ORACLE_BUILD_WARNING_POLICY.as_bytes()),
        fail_patterns,
        review_patterns,
    })
}

fn verify_oracle_build_record(
    document: &str,
    platform: &str,
    source_commit: &str,
    provenance: &Path,
) -> Result<String, String> {
    let mut expected = vec![
        ("schemaVersion".to_owned(), SummaryFieldKind::Number),
        ("platform".to_owned(), SummaryFieldKind::String),
        ("sourceCommit".to_owned(), SummaryFieldKind::String),
        ("resolverSha256".to_owned(), SummaryFieldKind::String),
        ("binarySha256".to_owned(), SummaryFieldKind::String),
        (
            "platformIdentitySha256".to_owned(),
            SummaryFieldKind::String,
        ),
        ("warningPolicySha256".to_owned(), SummaryFieldKind::String),
        ("failPatternCount".to_owned(), SummaryFieldKind::Number),
        ("reviewPatternCount".to_owned(), SummaryFieldKind::Number),
        ("warningFindingsSha256".to_owned(), SummaryFieldKind::String),
    ];
    for prefix in ["sourceTree", "stack", "compiler", "dependency", "build"] {
        for stream in ["Stdout", "Stderr"] {
            expected.extend([
                (format!("{prefix}{stream}Sha256"), SummaryFieldKind::String),
                (
                    format!("{prefix}{stream}RetainedSha256"),
                    SummaryFieldKind::String,
                ),
                (format!("{prefix}{stream}Bytes"), SummaryFieldKind::Number),
                (
                    format!("{prefix}{stream}RetainedCompletely"),
                    SummaryFieldKind::Boolean,
                ),
            ]);
        }
    }
    let mut lines = document.lines();
    if lines.next() != Some("{") {
        return Err("oracle build record lacks canonical object opener".into());
    }
    let mut values = BTreeMap::<String, SummaryFieldValue>::new();
    for (index, (name, kind)) in expected.iter().enumerate() {
        let line = lines
            .next()
            .ok_or_else(|| format!("oracle build record is missing field {name}"))?;
        let prefix = format!("  \"{name}\": ");
        let encoded = line
            .strip_prefix(&prefix)
            .ok_or_else(|| format!("oracle build record field {name} is out of order"))?;
        let encoded = if index + 1 == expected.len() {
            encoded
        } else {
            encoded.strip_suffix(',').ok_or_else(|| {
                format!("oracle build record field {name} lacks canonical separator")
            })?
        };
        values.insert(name.clone(), parse_summary_field(name, *kind, encoded)?);
    }
    if lines.next() != Some("}") || lines.next().is_some() || !document.ends_with("}\n") {
        return Err("oracle build record has extra fields or trailing bytes".into());
    }
    let string = |name: &str| match values.get(name) {
        Some(SummaryFieldValue::String(value)) => Some(value.as_str()),
        _ => None,
    };
    let number = |name: &str| match values.get(name) {
        Some(SummaryFieldValue::Number(value)) => Some(*value),
        _ => None,
    };
    if number("schemaVersion") != Some(3)
        || string("platform") != Some(platform)
        || string("sourceCommit") != Some(source_commit)
    {
        return Err("oracle build record identity is invalid".into());
    }
    for (field, relative) in [
        ("resolverSha256", "resolver.lock"),
        ("platformIdentitySha256", "platform.txt"),
    ] {
        let path = provenance.join(relative);
        let observed = sha256_file(&path)
            .map_err(|error| format!("cannot hash {}: {error}", path.display()))?;
        if string(field) != Some(observed.hex().as_str()) {
            return Err(format!(
                "oracle build field {field} disagrees with {}",
                path.display()
            ));
        }
    }
    verify_oracle_build_streams(&values, provenance)?;
    verify_oracle_build_warnings(&values, provenance)?;
    string("binarySha256")
        .map(str::to_owned)
        .ok_or_else(|| "oracle build record binary digest is malformed".to_owned())
}

fn verify_collection_native_dependency_identity(provenance: &Path) -> Result<(), String> {
    const RESOLVER_LOCK_SHA256: &str =
        "119cff36de1117edfb6098fd9688f9dad843c716d874d02dce49ecdc0dcfb61a";
    let resolver = provenance.join("resolver.lock");
    if sha256_file(&resolver)
        .map_err(|error| format!("cannot hash {}: {error}", resolver.display()))?
        .hex()
        != RESOLVER_LOCK_SHA256
    {
        return Err("collection native build used a different Stack resolver lock".into());
    }
    let stack = retained_utf8(provenance, "stack.stdout")?;
    if stack.trim_end_matches(['\r', '\n']) != "3.11.1" {
        return Err("collection native build did not retain exact Stack 3.11.1 identity".into());
    }
    let compiler = retained_utf8(provenance, "compiler.stdout")?;
    let project_versions = compiler
        .match_indices("(\"Project version\",\"")
        .collect::<Vec<_>>();
    if project_versions.len() != 1 || !compiler.contains("(\"Project version\",\"9.8.2\")") {
        return Err("collection native build did not retain exact GHC 9.8.2 identity".into());
    }
    let dependencies = retained_utf8(provenance, "dependencies.stdout")?;
    let containers = dependencies
        .lines()
        .filter(|line| line.split_ascii_whitespace().next() == Some("containers"))
        .collect::<Vec<_>>();
    if containers != ["containers 0.6.8"] {
        return Err(
            "collection native build did not report exactly one containers 0.6.8 dependency".into(),
        );
    }
    Ok(())
}

fn retained_utf8(provenance: &Path, relative: &str) -> Result<String, String> {
    let path = provenance.join(relative);
    let bytes = fs::read(&path).map_err(|error| {
        format!(
            "cannot read retained build stream {}: {error}",
            path.display()
        )
    })?;
    String::from_utf8(bytes)
        .map_err(|_| format!("retained build stream {relative} is not canonical UTF-8"))
}

fn verify_oracle_build_warnings(
    values: &BTreeMap<String, SummaryFieldValue>,
    provenance: &Path,
) -> Result<(), String> {
    let string = |name: &str| match values.get(name) {
        Some(SummaryFieldValue::String(value)) => Some(value.as_str()),
        _ => None,
    };
    let number = |name: &str| match values.get(name) {
        Some(SummaryFieldValue::Number(value)) => Some(*value),
        _ => None,
    };
    let policy = oracle_build_warning_policy()?;
    let warnings = retained_oracle_warning_identity(provenance, &policy)?;
    if string("warningPolicySha256") != Some(policy.sha256.hex().as_str())
        || number("failPatternCount") != Some(warnings.fail_count)
        || number("reviewPatternCount") != Some(warnings.review_count)
        || string("warningFindingsSha256") != Some(warnings.findings_sha256.hex().as_str())
        || warnings.fail_count != 0
        || warnings.review_count != 0
    {
        return Err(
            "oracle build warnings are substituted or require an explicit reviewed disposition"
                .to_owned(),
        );
    }
    Ok(())
}

fn verify_oracle_build_streams(
    values: &BTreeMap<String, SummaryFieldValue>,
    provenance: &Path,
) -> Result<(), String> {
    let string = |name: &str| match values.get(name) {
        Some(SummaryFieldValue::String(value)) => Some(value.as_str()),
        _ => None,
    };
    let number = |name: &str| match values.get(name) {
        Some(SummaryFieldValue::Number(value)) => Some(*value),
        _ => None,
    };
    let boolean = |name: &str| match values.get(name) {
        Some(SummaryFieldValue::Boolean(value)) => Some(*value),
        _ => None,
    };
    for (prefix, file_prefix) in [
        ("sourceTree", "source-tree"),
        ("stack", "stack"),
        ("compiler", "compiler"),
        ("dependency", "dependencies"),
        ("build", "build"),
    ] {
        for (stream, extension) in [("Stdout", "stdout"), ("Stderr", "stderr")] {
            let path = provenance.join(format!("{file_prefix}.{extension}"));
            let retained = sha256_file(&path)
                .map_err(|error| format!("cannot hash {}: {error}", path.display()))?;
            let length = fs::metadata(&path)
                .map_err(|error| format!("cannot stat {}: {error}", path.display()))?
                .len();
            if string(&format!("{prefix}{stream}Sha256")) != Some(retained.hex().as_str())
                || string(&format!("{prefix}{stream}RetainedSha256"))
                    != Some(retained.hex().as_str())
                || number(&format!("{prefix}{stream}Bytes")) != Some(length)
                || boolean(&format!("{prefix}{stream}RetainedCompletely")) != Some(true)
            {
                return Err(format!(
                    "oracle build stream {file_prefix}.{extension} is truncated or disagrees with retained bytes"
                ));
            }
        }
    }
    Ok(())
}

fn retained_oracle_warning_identity(
    provenance: &Path,
    policy: &OracleBuildWarningPolicy,
) -> Result<OracleBuildWarningIdentity, String> {
    let mut streams = Vec::new();
    for (command, file_prefix) in [
        ("sourceTree", "source-tree"),
        ("stack", "stack"),
        ("compiler", "compiler"),
        ("dependency", "dependencies"),
        ("build", "build"),
    ] {
        for extension in ["stdout", "stderr"] {
            let path = provenance.join(format!("{file_prefix}.{extension}"));
            let bytes = fs::read(&path)
                .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
            streams.push((command, extension, bytes));
        }
    }
    Ok(oracle_warning_identity(
        streams
            .iter()
            .map(|(command, stream, bytes)| (*command, *stream, bytes.as_slice())),
        policy,
    ))
}

fn oracle_warning_identity<'a>(
    streams: impl IntoIterator<Item = (&'a str, &'a str, &'a [u8])>,
    policy: &OracleBuildWarningPolicy,
) -> OracleBuildWarningIdentity {
    let mut fail_count = 0_u64;
    let mut review_count = 0_u64;
    let mut canonical = Vec::new();
    for (command, stream, bytes) in streams {
        for line in bytes.split(|byte| *byte == b'\n') {
            let classification = if policy
                .fail_patterns
                .iter()
                .any(|pattern| contains_ascii_case_insensitive(line, pattern.as_bytes()))
            {
                fail_count = fail_count.saturating_add(1);
                Some(b"fail".as_slice())
            } else if policy
                .review_patterns
                .iter()
                .any(|pattern| contains_ascii_case_insensitive(line, pattern.as_bytes()))
            {
                review_count = review_count.saturating_add(1);
                Some(b"review".as_slice())
            } else {
                None
            };
            if let Some(classification) = classification {
                canonical.extend_from_slice(classification);
                canonical.push(0);
                canonical.extend_from_slice(command.as_bytes());
                canonical.push(0);
                canonical.extend_from_slice(stream.as_bytes());
                canonical.push(0);
                canonical.extend_from_slice(line);
                canonical.push(b'\n');
            }
        }
    }
    OracleBuildWarningIdentity {
        fail_count,
        review_count,
        findings_sha256: sha256_bytes(&canonical),
    }
}

fn contains_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

fn current_corpus_identity() -> CurrentCorpusIdentity {
    let committed = committed_differential_cases();
    let generated = generated_typed_cases(NATIVE_CORPUS_SEED, NATIVE_GENERATED_CASES);
    let mut corpus = Vec::new();
    let mut committed_bytes = Vec::new();
    for case in &committed {
        corpus.extend_from_slice(case.id.as_bytes());
        corpus.push(0);
        corpus.extend_from_slice(case.source.as_bytes());
        committed_bytes.extend_from_slice(case.id.as_bytes());
        committed_bytes.push(0);
        committed_bytes.extend_from_slice(case.source.as_bytes());
    }
    let mut generated_bytes = Vec::new();
    for case in &generated {
        corpus.extend_from_slice(case.id.as_bytes());
        corpus.extend_from_slice(&case.ast_sha256.0);
        generated_bytes.extend_from_slice(case.id.as_bytes());
        generated_bytes.extend_from_slice(&case.ast_sha256.0);
    }
    CurrentCorpusIdentity {
        seed: NATIVE_CORPUS_SEED,
        committed_count: committed.len(),
        generated_count: generated.len(),
        corpus_sha256: sha256_bytes(&corpus),
        reviewed_committed_corpus_sha256: sha256_bytes(&committed_bytes),
        generated_stress_corpus_sha256: sha256_bytes(&generated_bytes),
    }
}

fn validate_current_corpus_summary(
    summary: &StrictNativeSummary,
    expected: &CurrentCorpusIdentity,
) -> Result<(), String> {
    if summary.u64("corpusSeed") != Some(expected.seed)
        || summary.usize("generatedDifferentialObservations") != Some(expected.generated_count)
        || summary.usize("committedDifferentialObservations") != Some(expected.committed_count)
        || summary.string("corpusSha256") != Some(expected.corpus_sha256.hex().as_str())
        || summary.string("reviewedCommittedCorpusSha256")
            != Some(expected.reviewed_committed_corpus_sha256.hex().as_str())
        || summary.string("generatedStressCorpusSha256")
            != Some(expected.generated_stress_corpus_sha256.hex().as_str())
    {
        return Err(
            "retained corpus seed, exact counts, or regenerated corpus digests disagree with the current generator"
                .to_owned(),
        );
    }
    Ok(())
}

fn validate_native_environment_summary(
    directory: &Path,
    summary: &StrictNativeSummary,
) -> Result<(), String> {
    let facts = verify_retained_native_environment(directory)
        .map_err(|error| format!("retained native environment is invalid: {error}"))?;
    crate::custody_ops::validate_utc_timestamp(&facts.collected_at)?;
    if summary.string("runnerOs") != Some(facts.runner_os.as_str())
        || summary.string("runnerArch") != Some(facts.runner_arch.as_str())
        || summary.string("collectedAt") != Some(facts.collected_at.as_str())
        || summary.string("runnerImageIdentitySha256")
            != Some(facts.runner_image_identity_sha256.hex().as_str())
        || summary.string("rustToolchainSha256") != Some(facts.rust_toolchain_sha256.hex().as_str())
        || summary.string("buildEnvironmentSha256")
            != Some(facts.build_environment_sha256.hex().as_str())
    {
        return Err(
            "native summary environment facts disagree with native-environment.json".to_owned(),
        );
    }
    let platform = summary
        .string("platform")
        .ok_or_else(|| "native summary platform is missing".to_owned())?;
    let matches_platform = match platform {
        "linux-x86_64" => {
            matches!(facts.runner_os.as_str(), "Linux" | "linux")
                && matches!(facts.runner_arch.as_str(), "X64" | "x86_64" | "AMD64")
        }
        "macos-aarch64" => {
            matches!(facts.runner_os.as_str(), "macOS" | "macos")
                && matches!(facts.runner_arch.as_str(), "ARM64" | "aarch64")
        }
        "windows-x86_64" => {
            matches!(facts.runner_os.as_str(), "Windows" | "windows")
                && matches!(facts.runner_arch.as_str(), "X64" | "x86_64" | "AMD64")
        }
        _ => false,
    };
    if !matches_platform {
        return Err("native runner OS/architecture disagrees with shard platform".to_owned());
    }
    Ok(())
}

/// Strictly replays the canonical summary and deterministic corpus identity
/// retained by one native differential shard.
///
/// # Errors
///
/// Returns an error for any schema, key-order, type, digest-record, seed,
/// count, committed-corpus, or generated-corpus substitution.
pub fn verify_retained_native_summary(directory: &Path) -> Result<Digest, String> {
    let (parsed, digest) = verify_retained_native_summary_document(directory)?;
    validate_current_corpus_summary(&parsed, &current_corpus_identity())?;
    validate_native_environment_summary(directory, &parsed)?;
    Ok(digest)
}

fn verify_retained_native_summary_document(
    directory: &Path,
) -> Result<(StrictNativeSummary, Digest), String> {
    let summary_path = directory.join("summary.json");
    let summary = fs::read_to_string(&summary_path)
        .map_err(|error| format!("cannot read {}: {error}", summary_path.display()))?;
    let parsed = StrictNativeSummary::parse(&summary)?;
    let digest = sha256_bytes(summary.as_bytes());
    let digest_path = directory.join("summary.sha256");
    let recorded = fs::read_to_string(&digest_path)
        .map_err(|error| format!("cannot read {}: {error}", digest_path.display()))?;
    let expected = format!("{}  summary.json\n", digest.hex());
    if recorded != expected {
        return Err(format!(
            "native summary digest record {} is noncanonical or does not match summary.json",
            digest_path.display()
        ));
    }
    Ok((parsed, digest))
}

/// Replays the exact Linux surveillance bundle set through the current parser.
pub(crate) fn verify_retained_linux_surveillance_shard(
    directory: &Path,
    active_root: &Path,
    candidate: &str,
    epoch: &str,
) -> Result<Digest, String> {
    let (parsed, summary_digest) = verify_retained_native_summary_document(directory)?;
    let promoted = active_root.join("approved-proposal").join("linux-amd64");
    let (promoted_summary, _) = verify_retained_native_summary_document(&promoted)?;
    validate_native_environment_summary(directory, &parsed)?;
    validate_native_environment_summary(&promoted, &promoted_summary)?;
    let claim_index_path = directory.join("evidence").join("claim-index.json");
    let claim_index = fs::read_to_string(&claim_index_path)
        .map_err(|error| format!("cannot read retained claim index: {error}"))?;
    let parsed_claim_index = StrictClaimIndex::parse(&claim_index)?;
    let claim_index_digest = sha256_file(&claim_index_path)
        .map_err(|error| format!("cannot hash retained claim index: {error}"))?
        .hex();
    if parsed.string("platform") != Some("linux-x86_64")
        || parsed.string("claimEvidenceIndexSha256") != Some(claim_index_digest.as_str())
        || json_string_field(&claim_index, "candidateSourceCommit") != Some(candidate)
        || json_string_field(&claim_index, "assuranceEpochSha256") != Some(epoch)
        || json_string_field(&claim_index, "platform") != Some("linux-amd64")
        || json_string_field(&claim_index, "profile") != Some("upstream")
    {
        return Err("retained surveillance shard identity is inconsistent".to_owned());
    }
    verify_surveillance_authority_bindings(
        &parsed,
        &promoted_summary,
        &parsed_claim_index,
        &StrictClaimIndex::parse(
            &fs::read_to_string(promoted.join("evidence").join("claim-index.json"))
                .map_err(|error| format!("cannot read promoted Linux claim index: {error}"))?,
        )?,
        candidate,
        epoch,
    )?;
    verify_surveillance_dependency_attestation(directory, &parsed, candidate)?;
    validate_claim_index_contents(
        &claim_index,
        &directory.join("evidence").join("observations"),
        "linux-amd64",
    )?;
    verify_exact_surveillance_bundle_set(directory, active_root, candidate, epoch, &parsed)?;
    verify_surveillance_claim_counters(&parsed, &parsed_claim_index)?;
    Ok(summary_digest)
}

fn verify_surveillance_authority_bindings(
    observed: &StrictNativeSummary,
    promoted: &StrictNativeSummary,
    observed_claim: &StrictClaimIndex,
    promoted_claim: &StrictClaimIndex,
    candidate: &str,
    epoch: &str,
) -> Result<(), String> {
    for field in [
        "oracleSha256",
        "oracleAcquisitionReceiptId",
        "oracleAcquisitionReceiptSha256",
        "oracleAcquisitionAttestationSha256",
        "candidateSha256",
        "assuranceEpochSha256",
        "corpusSeed",
        "committedDifferentialObservations",
        "generatedDifferentialObservations",
        "corpusSha256",
        "reviewedCommittedCorpusSha256",
        "generatedStressCorpusSha256",
        "promotionPolicySha256",
        "reviewedCorpusCatalogSha256",
        "promotionReviewSha256",
        "requiredProfiles",
        "compatibilitySnapshotSha256",
        "dependencyLockSha256",
        "expectedMismatchManifestSha256",
        "requiredPlatformSkips",
    ] {
        if observed.fields.get(field) != promoted.fields.get(field) {
            return Err(format!(
                "surveillance summary authority field {field} differs from immutable promotion"
            ));
        }
    }
    if observed_claim.candidate_source_commit != candidate
        || promoted_claim.candidate_source_commit != candidate
        || observed_claim.assurance_epoch_sha256 != epoch
        || promoted_claim.assurance_epoch_sha256 != epoch
    {
        return Err("surveillance claim authority has a stale candidate or epoch".to_owned());
    }
    for (field, observed, promoted, summary) in [
        (
            "compatibilitySnapshotSha256",
            observed_claim.compatibility_snapshot_sha256.as_str(),
            promoted_claim.compatibility_snapshot_sha256.as_str(),
            observed.string("compatibilitySnapshotSha256"),
        ),
        (
            "promotionPolicySha256",
            observed_claim.promotion_policy_sha256.as_str(),
            promoted_claim.promotion_policy_sha256.as_str(),
            observed.string("promotionPolicySha256"),
        ),
        (
            "reviewedCorpusCatalogSha256",
            observed_claim.reviewed_corpus_catalog_sha256.as_str(),
            promoted_claim.reviewed_corpus_catalog_sha256.as_str(),
            observed.string("reviewedCorpusCatalogSha256"),
        ),
        (
            "oracleSha256",
            observed_claim.oracle_sha256.as_str(),
            promoted_claim.oracle_sha256.as_str(),
            observed.string("oracleSha256"),
        ),
        (
            "candidateSha256",
            observed_claim.candidate_sha256.as_str(),
            promoted_claim.candidate_sha256.as_str(),
            observed.string("candidateSha256"),
        ),
    ] {
        if observed != promoted || summary != Some(observed) {
            return Err(format!(
                "surveillance claim authority field {field} is not exactly promotion-bound"
            ));
        }
    }
    Ok(())
}

fn verify_surveillance_dependency_attestation(
    directory: &Path,
    summary: &StrictNativeSummary,
    candidate: &str,
) -> Result<(), String> {
    let lock = summary
        .string("dependencyLockSha256")
        .ok_or_else(|| "surveillance dependency lock digest is missing".to_owned())?;
    let expected =
        dependency_attestation_json(candidate, Digest::from_hex(lock).map_err(str::to_owned)?);
    let path = directory
        .join("evidence")
        .join("dependency-policy-attestation.json");
    let observed = fs::read_to_string(&path)
        .map_err(|error| format!("cannot read retained dependency attestation: {error}"))?;
    let digest = sha256_bytes(observed.as_bytes());
    let digest_record = fs::read_to_string(path.with_extension("sha256"))
        .map_err(|error| format!("cannot read retained dependency digest: {error}"))?;
    if observed != expected
        || digest_record != format!("{}  dependency-policy-attestation.json\n", digest.hex())
        || summary.string("dependencyPolicyAttestationSha256") != Some(digest.hex().as_str())
        || summary.usize("dependencyFailures") != Some(0)
    {
        return Err("retained dependency attestation or failure count is invalid".to_owned());
    }
    Ok(())
}

fn verify_surveillance_claim_counters(
    summary: &StrictNativeSummary,
    claim: &StrictClaimIndex,
) -> Result<(), String> {
    let stale = claim
        .missing_bundles
        .saturating_add(claim.irrelevant_references)
        .saturating_add(claim.profile_mismatches)
        .saturating_add(claim.platform_mismatches)
        .saturating_add(claim.normalizer_mismatches)
        .saturating_add(claim.failed_observations);
    for (field, expected) in [
        ("staleExactClaims", stale),
        ("missingEvidenceReferences", claim.missing_bundles),
        ("irrelevantClaimReferences", claim.irrelevant_references),
        ("profileEvidenceMismatches", claim.profile_mismatches),
        ("platformEvidenceMismatches", claim.platform_mismatches),
        ("normalizerEvidenceMismatches", claim.normalizer_mismatches),
        ("failedClaimObservations", claim.failed_observations),
    ] {
        if summary.usize(field) != Some(expected) {
            return Err(format!(
                "surveillance summary field {field} differs from the strict claim index"
            ));
        }
    }
    if claim.indexed_entries != claim.entries.len() {
        return Err("surveillance claim index count differs from its exact entries".to_owned());
    }
    Ok(())
}

fn verify_exact_surveillance_bundle_set(
    directory: &Path,
    active_root: &Path,
    candidate: &str,
    epoch: &str,
    summary: &StrictNativeSummary,
) -> Result<(), String> {
    let observations = directory.join("evidence").join("observations");
    let mut committed = committed_differential_cases();
    bind_runtime_process_helper(&mut committed)?;
    let generated = generated_typed_cases(NATIVE_CORPUS_SEED, NATIVE_GENERATED_CASES);
    let mut expected = BTreeSet::new();
    let mut replay = RetainedReplay {
        unexpected_timeouts: 0,
        resource_failures: 0,
        accepted_divergence_ids: BTreeSet::new(),
        active_root,
        candidate,
        epoch,
    };
    for case in &committed {
        expected.insert(case.id.to_string());
        accumulate_retained_case(&observations.join(case.id.as_ref()), case, &mut replay)?;
    }
    for generated_case in &generated {
        let case = DifferentialCase {
            id: std::sync::Arc::clone(&generated_case.id),
            source: std::sync::Arc::clone(&generated_case.source),
            timeout: Duration::from_secs(5),
            ..DifferentialCase::default()
        };
        expected.insert(case.id.to_string());
        accumulate_retained_case(&observations.join(case.id.as_ref()), &case, &mut replay)
            .map_err(|error| {
                format!("retained generated case {:?} is invalid: {error}", case.id)
            })?;
    }
    let mut observed = BTreeSet::new();
    for entry in fs::read_dir(&observations)
        .map_err(|error| format!("cannot enumerate retained observation bundles: {error}"))?
    {
        let entry = entry.map_err(|error| format!("cannot inspect retained bundle: {error}"))?;
        let file_type = entry
            .file_type()
            .map_err(|error| format!("cannot inspect retained bundle type: {error}"))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "retained bundle directory name is not UTF-8".to_owned())?;
        if !file_type.is_dir() || !observed.insert(name) {
            return Err("retained observation inventory is malformed or duplicated".to_owned());
        }
    }
    if observed != expected {
        return Err("retained observation inventory has missing or extra cases".to_owned());
    }
    let expected_divergence_ids =
        crate::assurance::active_accepted_divergence_ids(active_root, candidate, epoch)?;
    if replay.accepted_divergence_ids != expected_divergence_ids {
        return Err(
            "active Linux accepted divergence set differs from current retained mismatches"
                .to_owned(),
        );
    }
    if summary.usize("unexpectedTimeouts") != Some(replay.unexpected_timeouts)
        || summary.usize("leakedResources") != Some(replay.resource_failures)
        || summary.usize("mismatches") != Some(0)
        || summary.usize("reviewedExpectedDivergences")
            != Some(replay.accepted_divergence_ids.len())
    {
        return Err(
            "retained surveillance summary counters differ from replayed bundle facts".to_owned(),
        );
    }
    Ok(())
}

struct RetainedReplay<'a> {
    unexpected_timeouts: usize,
    resource_failures: usize,
    accepted_divergence_ids: BTreeSet<String>,
    active_root: &'a Path,
    candidate: &'a str,
    epoch: &'a str,
}

fn accumulate_retained_case(
    directory: &Path,
    case: &DifferentialCase,
    replay: &mut RetainedReplay<'_>,
) -> Result<(), String> {
    let classification = hell_testkit::classify_retained_observation_bundle(directory, case)
        .map_err(|error| {
            format!(
                "retained case {:?} classification is invalid: {error}",
                case.id
            )
        })?;
    if let hell_testkit::RetainedObservationClassification::Mismatch {
        raw_mismatches,
        normalized_mismatches,
        fingerprint_sha256,
    } = &classification
    {
        let divergence_id = crate::assurance::verify_active_accepted_divergence(
            replay.active_root,
            replay.candidate,
            replay.epoch,
            case.id.as_ref(),
            raw_mismatches,
            normalized_mismatches,
            fingerprint_sha256,
        )?;
        if !replay.accepted_divergence_ids.insert(divergence_id) {
            return Err(format!(
                "retained case {:?} reuses an accepted divergence identity",
                case.id
            ));
        }
    }
    let facts = hell_testkit::retained_bundle_outcome_facts(directory, case)
        .map_err(|error| format!("retained case {:?} outcome is invalid: {error}", case.id))?;
    replay.unexpected_timeouts = replay.unexpected_timeouts.saturating_add(usize::from(
        facts.oracle.timed_out || facts.candidate.timed_out,
    ));
    replay.resource_failures = replay
        .resource_failures
        .saturating_add(facts.candidate.resource_failures);
    if facts.oracle.effect_failures != 0
        || facts.candidate.effect_failures != 0
        || (case.mode == hell_testkit::DifferentialMode::Run
            && (!facts.oracle.status_success || !facts.candidate.status_success))
    {
        return Err(format!(
            "retained case {:?} has bilateral failed status or effect evidence",
            case.id
        ));
    }
    Ok(())
}

const fn native_merge_promotion_ready() -> bool {
    false
}

fn validate_merged_mechanical(input: &Path) -> Result<(), String> {
    let manifest = read_digested_merged_manifest(input)?;
    for (field, expected) in [
        ("schemaVersion", 3),
        ("validatedShardCount", 3),
        ("missingClaimEvidence", 0),
        ("requiredPlatformSkips", 0),
        ("irrelevantClaimReferences", 0),
        ("profileEvidenceMismatches", 0),
        ("platformEvidenceMismatches", 0),
        ("normalizerEvidenceMismatches", 0),
        ("invalidApplicabilityClaims", 0),
        ("invalidPlatformRecords", 0),
        ("platformProvenanceMismatches", 0),
    ] {
        if json_usize_field(&manifest, field) != Some(expected) {
            return Err(format!("merged mechanical field {field} is not {expected}"));
        }
    }
    if json_bool_field(&manifest, "platformEvidenceComplete") != Some(true) {
        return Err("merged native platform evidence is incomplete".to_owned());
    }
    Ok(())
}

fn bind_common_field(
    fields: &mut BTreeMap<String, String>,
    field: &str,
    observed: &str,
) -> Result<(), String> {
    if let Some(expected) = fields.get(field) {
        if expected != observed {
            return Err(format!(
                "field {field} disagrees with an earlier native shard"
            ));
        }
    } else {
        fields.insert(field.to_owned(), observed.to_owned());
    }
    Ok(())
}

pub(crate) fn bind_runtime_process_helper(cases: &mut [DifferentialCase]) -> Result<(), String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("cannot locate the assurance driver: {error}"))?;
    let directory = executable
        .parent()
        .ok_or_else(|| "assurance driver path has no parent".to_owned())?;
    let mut candidates = vec![directory.to_path_buf()];
    if directory.file_name().is_some_and(|name| name == "deps")
        && let Some(profile_directory) = directory.parent()
    {
        candidates.push(profile_directory.to_path_buf());
    }
    let mut errors = Vec::new();
    for candidate in candidates {
        match bind_process_helper_directory(cases, &candidate) {
            Ok(_) => return Ok(()),
            Err(error) => errors.push(error),
        }
    }
    Err(format!(
        "cannot bind the versioned process evidence fixture: {}",
        errors.join("; ")
    ))
}

#[allow(clippy::too_many_lines)]
fn validate_claim_index_contents(
    document: &str,
    observation_root: &Path,
    platform: &str,
) -> Result<Vec<RuntimePlatformShard>, String> {
    let parsed = StrictClaimIndex::parse(document)?;
    let claim_platform = match platform {
        "linux-amd64" => hell_builtins::ClaimPlatform::Linux,
        "macos-arm64" => hell_builtins::ClaimPlatform::MacOs,
        "windows-amd64" => hell_builtins::ClaimPlatform::Windows,
        _ => return Err(format!("unknown claim-index platform {platform:?}")),
    };
    if parsed.schema_version != 3 || parsed.platform != platform || parsed.profile != "upstream" {
        return Err("claim index schema/profile/platform is invalid".to_owned());
    }
    if [
        parsed.missing_bundles,
        parsed.irrelevant_references,
        parsed.profile_mismatches,
        parsed.platform_mismatches,
        parsed.normalizer_mismatches,
        parsed.failed_observations,
    ]
    .into_iter()
    .any(|count| count != 0)
    {
        return Err("claim index retains a nonzero validation counter".to_owned());
    }
    let candidate_source_sha256 = sha256_bytes(parsed.candidate_source_commit.as_bytes());
    let candidate_executable_sha256 =
        Digest::from_hex(&parsed.candidate_sha256).map_err(str::to_owned)?;
    let mut committed = committed_differential_cases();
    bind_runtime_process_helper(&mut committed)?;
    validate_runtime_obligation_coverage(&committed)?;
    let mut runtime_shards = BTreeMap::<String, RuntimePlatformShard>::new();
    let mut expected = Vec::<String>::new();
    for (spec, claim) in hell_builtins::registry()
        .iter()
        .zip(hell_builtins::compatibility_claims())
    {
        for dimension in &claim.dimensions {
            for scope in dimension.scopes {
                if !scope
                    .profiles
                    .contains(&hell_builtins::ExecutionProfile::Upstream)
                    || !(scope.platforms.contains(&hell_builtins::ClaimPlatform::All)
                        || scope.platforms.contains(&claim_platform))
                    || scope.status == ClaimStatus::Unverified
                {
                    continue;
                }
                if scope.status == ClaimStatus::NotApplicable {
                    expected.push(format!(
                        "{}\0{}\0not-applicable\0",
                        spec.name,
                        dimension.dimension.as_str()
                    ));
                    continue;
                }
                for reference in scope.evidence {
                    let case_id = hell_builtins::parse_differential_reference(reference)
                        .map_err(|_| format!("invalid claim reference {reference:?}"))?
                        .case_id;
                    let case = committed
                        .iter()
                        .find(|case| case.id.as_ref() == case_id)
                        .ok_or_else(|| {
                            format!("claim references non-committed case {case_id:?}")
                        })?;
                    let descriptor = case.claim_evidence.as_ref().ok_or_else(|| {
                        format!("claim references ineligible committed case {case_id:?}")
                    })?;
                    if descriptor.profile != hell_builtins::ExecutionProfile::Upstream
                        || descriptor.claim_normalizers != scope.normalizers
                        || !descriptor.targets.iter().any(|target| {
                            target.builtin.as_ref() == spec.name
                                && target.dimension == dimension.dimension
                        })
                    {
                        return Err(format!(
                            "committed case {case_id:?} does not bind claim {}/{}",
                            spec.name,
                            dimension.dimension.as_str()
                        ));
                    }
                    expected.push(format!(
                        "{}\0{}\0{}\0{}",
                        spec.name,
                        dimension.dimension.as_str(),
                        claim_status_name(scope.status),
                        reference
                    ));
                }
            }
        }
    }
    expected.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    let mut observed = Vec::<String>::new();
    for line in &parsed.entries {
        if !line.starts_with("{ \"builtin\": ") {
            return Err("claim index contains a malformed or unexpected entry".to_owned());
        }
        let builtin = inline_json_string(line, "builtin")
            .ok_or_else(|| "claim index entry lacks builtin".to_owned())?;
        let dimension = inline_json_string(line, "dimension")
            .ok_or_else(|| "claim index entry lacks dimension".to_owned())?;
        let status = inline_json_string(line, "status")
            .ok_or_else(|| "claim index entry lacks status".to_owned())?;
        if inline_json_string(line, "profile") != Some("upstream")
            || inline_json_string(line, "platform") != Some(platform)
        {
            return Err("claim index entry has the wrong profile or platform".to_owned());
        }
        let reference = inline_json_string(line, "reference");
        let key = format!(
            "{builtin}\0{dimension}\0{status}\0{}",
            reference.unwrap_or_default()
        );
        if let Some(reference) = reference {
            let case_id = hell_builtins::parse_differential_reference(reference)
                .map_err(|_| format!("claim index has invalid reference {reference:?}"))?
                .case_id;
            let case = committed
                .iter()
                .find(|case| case.id.as_ref() == case_id)
                .ok_or_else(|| format!("claim index case {case_id:?} is not committed"))?;
            let spec = hell_builtins::lookup(builtin)
                .ok_or_else(|| format!("claim index builtin {builtin:?} is unknown"))?;
            let claim = hell_builtins::compatibility_claim(spec.id)
                .ok_or_else(|| format!("claim index builtin {builtin:?} has no claim"))?;
            let dimension_value = CompatibilityDimension::ALL
                .into_iter()
                .find(|candidate| candidate.as_str() == dimension)
                .ok_or_else(|| format!("claim index dimension {dimension:?} is unknown"))?;
            let scope = claim
                .dimensions
                .iter()
                .find(|candidate| candidate.dimension == dimension_value)
                .and_then(|dimension| {
                    dimension.scopes.iter().find(|scope| {
                        claim_status_name(scope.status) == status
                            && scope.evidence.contains(&reference)
                            && scope
                                .profiles
                                .contains(&hell_builtins::ExecutionProfile::Upstream)
                    })
                })
                .ok_or_else(|| "claim index entry has no exact source claim scope".to_owned())?;
            if inline_json_bool(line, "targetDeclared") != Some(true)
                || inline_json_string_array(line, "harnessNormalizers")?
                    != ["diagnostic-sandbox-path-v1"]
                || inline_json_string_array(line, "claimNormalizers")?
                    != scope
                        .normalizers
                        .iter()
                        .map(|normalizer| normalizer.as_str())
                        .collect::<Vec<_>>()
                || inline_json_string_array(line, "claimPlatforms")?
                    != scope
                        .platforms
                        .iter()
                        .map(|platform| claim_platform_name(*platform))
                        .collect::<Vec<_>>()
            {
                return Err(
                    "claim index target, normalizer, or platform metadata disagrees with source"
                        .to_owned(),
                );
            }
            let directory = observation_root.join(case_id);
            let digest = verify_observation_bundle_for_case(&directory, case)
                .map_err(|error| format!("invalid bundle for {case_id}: {error}"))?;
            let runtime_shard = runtime_platform_shard_for_bundle(
                &directory,
                case,
                claim_platform,
                candidate_source_sha256,
                candidate_executable_sha256,
            )
            .map_err(|error| format!("invalid runtime platform bundle for {case_id}: {error}"))?;
            insert_runtime_shard(&mut runtime_shards, case_id, runtime_shard)?;
            if inline_json_string(line, "bundleManifestSha256") != Some(digest.hex().as_str()) {
                return Err(format!(
                    "claim index bundle digest for {case_id:?} does not match retained bytes"
                ));
            }
            let mut file_fields = String::new();
            for relative in [
                "main.hell",
                "case.toml",
                "oracle/observation.json",
                "candidate/observation.json",
            ] {
                let observed_digest = sha256_file(&directory.join(relative))
                    .map_err(|error| format!("cannot hash bundle file {relative}: {error}"))?
                    .hex();
                if inline_json_string(line, relative) != Some(observed_digest.as_str()) {
                    return Err(format!(
                        "claim index bundleFiles digest for {relative} is invalid"
                    ));
                }
                if !file_fields.is_empty() {
                    file_fields.push_str(", ");
                }
                write!(file_fields, "{relative:?}: {observed_digest:?}")
                    .expect("writing to String cannot fail");
            }
            let claim_normalizers = scope
                .normalizers
                .iter()
                .map(|normalizer| format!("{:?}", normalizer.as_str()))
                .collect::<Vec<_>>()
                .join(", ");
            let claim_platforms = scope
                .platforms
                .iter()
                .map(|platform| format!("{:?}", claim_platform_name(*platform)))
                .collect::<Vec<_>>()
                .join(", ");
            let canonical = format!(
                concat!(
                    "{{ \"builtin\": {:?}, \"dimension\": {:?}, \"status\": {:?}, ",
                    "\"profile\": \"upstream\", \"platform\": {:?}, ",
                    "\"claimPlatforms\": [{}], \"reference\": {:?}, ",
                    "\"targetDeclared\": true, \"harnessNormalizers\": [\"diagnostic-sandbox-path-v1\"], ",
                    "\"claimNormalizers\": [{}], \"bundleManifestSha256\": {:?}, ",
                    "\"bundleFiles\": {{ {} }} }}"
                ),
                builtin,
                dimension,
                status,
                platform,
                claim_platforms,
                reference,
                claim_normalizers,
                digest.hex(),
                file_fields,
            );
            if line != &canonical {
                return Err("claim index entry is not canonical or has extra fields".to_owned());
            }
        } else if status != "not-applicable" {
            return Err("evidence-bearing claim index entry lacks a reference".to_owned());
        } else {
            let spec = hell_builtins::lookup(builtin)
                .ok_or_else(|| format!("applicability builtin {builtin:?} is unknown"))?;
            let claim = hell_builtins::compatibility_claim(spec.id)
                .ok_or_else(|| format!("applicability builtin {builtin:?} has no claim"))?;
            let rationale = claim
                .dimensions
                .iter()
                .find(|candidate| candidate.dimension.as_str() == dimension)
                .and_then(|dimension| {
                    dimension
                        .scopes
                        .iter()
                        .find(|scope| scope.status == ClaimStatus::NotApplicable)
                })
                .and_then(|scope| scope.rationale)
                .ok_or_else(|| "applicability entry has no source rationale".to_owned())?;
            if inline_json_string(line, "rationale") != Some(rationale) {
                return Err("applicability rationale differs from source".to_owned());
            }
            let canonical = format!(
                "{{ \"builtin\": {builtin:?}, \"dimension\": {dimension:?}, \"status\": \"not-applicable\", \"profile\": \"upstream\", \"platform\": {platform:?}, \"rationale\": {rationale:?} }}"
            );
            if line != &canonical {
                return Err("applicability entry is not canonical or has extra fields".to_owned());
            }
        }
        observed.push(key);
    }
    if observed
        .windows(2)
        .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
    {
        return Err("claim index entries are duplicated or non-canonical".to_owned());
    }
    if parsed.indexed_entries != observed.len() {
        return Err("claim index entry count is inconsistent".to_owned());
    }
    if observed != expected {
        return Err("claim index does not cover the exact required claim scope".to_owned());
    }
    for case in &committed {
        if case.claim_evidence.is_none() {
            continue;
        }
        let directory = observation_root.join(case.id.as_ref());
        if let Some(runtime_shard) = runtime_platform_shard_for_bundle(
            &directory,
            case,
            claim_platform,
            candidate_source_sha256,
            candidate_executable_sha256,
        )
        .map_err(|error| {
            format!(
                "invalid mandatory runtime platform bundle for {:?}: {error}",
                case.id
            )
        })? {
            runtime_shards.insert(case.id.to_string(), runtime_shard);
        }
    }
    Ok(runtime_shards.into_values().collect())
}

fn insert_runtime_shard(
    shards: &mut BTreeMap<String, RuntimePlatformShard>,
    case_id: &str,
    shard: Option<RuntimePlatformShard>,
) -> Result<(), String> {
    let Some(shard) = shard else {
        return Ok(());
    };
    if shards
        .insert(case_id.to_owned(), shard.clone())
        .is_some_and(|prior| prior != shard)
    {
        return Err(format!(
            "claim index derives inconsistent runtime shard records for {case_id:?}"
        ));
    }
    Ok(())
}

fn inline_json_string<'a>(line: &'a str, field: &str) -> Option<&'a str> {
    let prefix = format!("\"{field}\": \"");
    let start = line.find(&prefix)?.saturating_add(prefix.len());
    let remainder = line.get(start..)?;
    let end = remainder.find('"')?;
    remainder.get(..end)
}

fn inline_json_bool(line: &str, field: &str) -> Option<bool> {
    let prefix = format!("\"{field}\": ");
    let start = line.find(&prefix)?.saturating_add(prefix.len());
    let remainder = line.get(start..)?;
    if remainder.starts_with("true") {
        Some(true)
    } else if remainder.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

fn inline_json_string_array<'a>(line: &'a str, field: &str) -> Result<Vec<&'a str>, String> {
    let prefix = format!("\"{field}\": [");
    let start = line
        .find(&prefix)
        .map(|index| index.saturating_add(prefix.len()))
        .ok_or_else(|| format!("claim index entry lacks array field {field}"))?;
    let remainder = line
        .get(start..)
        .ok_or_else(|| format!("claim index array field {field} is malformed"))?;
    let end = remainder
        .find(']')
        .ok_or_else(|| format!("claim index array field {field} is unterminated"))?;
    let inner = remainder[..end].trim();
    if inner.is_empty() {
        return Ok(Vec::new());
    }
    inner
        .split(',')
        .map(|item| {
            item.trim()
                .strip_prefix('"')
                .and_then(|item| item.strip_suffix('"'))
                .ok_or_else(|| format!("claim index array field {field} has a malformed item"))
        })
        .collect()
}

fn read_digested_merged_manifest(input: &Path) -> Result<String, String> {
    let manifest_path = input.join("merged-native-shards.json");
    let manifest = fs::read_to_string(&manifest_path)
        .map_err(|error| format!("cannot read merged manifest: {error}"))?;
    let digest_record = fs::read_to_string(input.join("merged-native-shards.sha256"))
        .map_err(|error| format!("cannot read merged manifest digest: {error}"))?;
    let recorded_digest = digest_record
        .split_whitespace()
        .next()
        .ok_or_else(|| "merged manifest digest is empty".to_owned())?;
    if recorded_digest != sha256_bytes(manifest.as_bytes()).hex() {
        return Err("merged manifest digest is invalid".to_owned());
    }
    Ok(manifest)
}

fn json_string_field<'a>(document: &'a str, field: &str) -> Option<&'a str> {
    let prefix = format!("\"{field}\": \"");
    document.lines().find_map(|line| {
        line.trim()
            .strip_prefix(&prefix)
            .and_then(|value| value.strip_suffix("\","))
            .or_else(|| {
                line.trim()
                    .strip_prefix(&prefix)
                    .and_then(|value| value.strip_suffix('"'))
            })
    })
}

fn json_string_array_field<'a>(document: &'a str, field: &str) -> Option<Vec<&'a str>> {
    let prefix = format!("\"{field}\": [");
    let mut matching = document.lines().filter_map(|line| {
        let value = line.trim().strip_prefix(&prefix)?;
        let value = value.strip_suffix(',').unwrap_or(value).strip_suffix(']')?;
        if value.trim().is_empty() {
            return Some(Vec::new());
        }
        value
            .split(',')
            .map(|item| {
                item.trim()
                    .strip_prefix('"')
                    .and_then(|item| item.strip_suffix('"'))
            })
            .collect::<Option<Vec<_>>>()
    });
    let value = matching.next()?;
    matching.next().is_none().then_some(value)
}

fn json_usize_field(document: &str, field: &str) -> Option<usize> {
    let prefix = format!("\"{field}\": ");
    document.lines().find_map(|line| {
        line.trim()
            .strip_prefix(&prefix)
            .and_then(|value| value.strip_suffix(',').unwrap_or(value).parse().ok())
    })
}

fn json_bool_field(document: &str, field: &str) -> Option<bool> {
    let prefix = format!("\"{field}\": ");
    document.lines().find_map(|line| {
        line.trim().strip_prefix(&prefix).and_then(|value| {
            match value.strip_suffix(',').unwrap_or(value) {
                "true" => Some(true),
                "false" => Some(false),
                _ => None,
            }
        })
    })
}

fn merge_fixture_failure(
    report: &mut Report,
    label: &str,
    started: Instant,
    path: &Path,
    detail: impl Into<String>,
) -> FailureKind {
    report.check(
        format!("merge-{label}"),
        started.elapsed(),
        Err(format!("{}: {}", path.display(), detail.into())),
    );
    FailureKind::Fixture
}

fn required_merge_string_field<'a>(
    report: &mut Report,
    label: &str,
    started: Instant,
    path: &Path,
    document: &'a str,
    field: &str,
) -> Result<&'a str, FailureKind> {
    json_string_field(document, field).ok_or_else(|| {
        merge_fixture_failure(
            report,
            label,
            started,
            path,
            format!("missing or malformed string field {field}"),
        )
    })
}

fn stack_oracle_build_command(stack_yaml: &Path, oracle_directory: &Path) -> CommandSpec {
    CommandSpec::new("stack", Duration::from_mins(45))
        .argument("--stack-yaml")
        .argument(stack_yaml.as_os_str())
        .arguments(["--lock-file", "error-on-write"])
        .arguments(["build", "--install-ghc", "--copy-bins"])
        .argument("--local-bin-path")
        .argument(oracle_directory.as_os_str())
}

fn io_or_report<T>(
    report: &mut Report,
    name: impl Into<String>,
    started: Instant,
    action: &str,
    path: &Path,
    result: std::io::Result<T>,
) -> Result<T, FailureKind> {
    result.map_err(|error| {
        report.check(
            name,
            started.elapsed(),
            Err(SuiteFailure::io(action, path, &error).detail),
        );
        FailureKind::Io
    })
}

fn evidence_io<T>(
    action: &str,
    path: &Path,
    result: std::io::Result<T>,
) -> Result<T, SuiteFailure> {
    result.map_err(|error| SuiteFailure::io(action, path, &error))
}

fn checked_suite_result<T>(
    report: &mut Report,
    name: &str,
    started: Instant,
    result: Result<T, SuiteFailure>,
) -> Result<T, FailureKind> {
    match result {
        Ok(value) => {
            report.check(name, started.elapsed(), Ok(()));
            Ok(value)
        }
        Err(failure) => {
            report.check(name, started.elapsed(), Err(failure.detail));
            Err(failure.kind)
        }
    }
}

fn observed_command(
    root: &Path,
    report: &mut Report,
    failures: &Path,
    name: &str,
    command: CommandSpec,
) -> Result<CommandResult, FailureKind> {
    let command = if command.current_directory.is_some() {
        command
    } else {
        command.current_directory(root)
    };
    let started = Instant::now();
    match command.run() {
        Ok(result) if result.status.success() && !result.timed_out => {
            report.check(name, started.elapsed(), Ok(()));
            Ok(result)
        }
        Ok(result) => {
            let _ = fs::create_dir_all(failures);
            let _ = fs::write(failures.join(format!("{name}.stdout")), &result.stdout);
            let _ = fs::write(failures.join(format!("{name}.stderr")), &result.stderr);
            report.check(
                name,
                started.elapsed(),
                Err(format!("command failed with {}", result.status)),
            );
            Err(FailureKind::Child)
        }
        Err(error) => {
            report.check(name, started.elapsed(), Err(error.to_string()));
            Err(FailureKind::Io)
        }
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn write_oracle_build_record(
    artifact_root: &Path,
    platform: &str,
    source_commit: &str,
    source_tree: &CommandResult,
    resolver: &[u8],
    binary_sha256: Digest,
    stack: &CommandResult,
    compiler: &CommandResult,
    dependencies: &CommandResult,
    build: &CommandResult,
) -> Result<(), SuiteFailure> {
    let provenance = artifact_root.join("oracle-provenance").join(platform);
    evidence_io(
        "create oracle provenance directory",
        &provenance,
        fs::create_dir_all(&provenance),
    )?;
    let platform_identity = format!(
        "platform={platform}\nos={}\narch={}\n",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    let platform_path = provenance.join("platform.txt");
    evidence_io(
        "write oracle platform identity",
        &platform_path,
        fs::write(&platform_path, platform_identity.as_bytes()),
    )?;
    let resolver_path = provenance.join("resolver.lock");
    evidence_io(
        "write oracle resolver lock",
        &resolver_path,
        fs::write(&resolver_path, resolver),
    )?;
    for (name, command) in [
        ("source-tree", source_tree),
        ("stack", stack),
        ("compiler", compiler),
        ("dependencies", dependencies),
        ("build", build),
    ] {
        let stdout_path = provenance.join(format!("{name}.stdout"));
        evidence_io(
            "write oracle command stdout",
            &stdout_path,
            fs::write(&stdout_path, &command.stdout),
        )?;
        let stderr_path = provenance.join(format!("{name}.stderr"));
        evidence_io(
            "write oracle command stderr",
            &stderr_path,
            fs::write(&stderr_path, &command.stderr),
        )?;
    }
    let commands = [
        ("sourceTree", source_tree),
        ("stack", stack),
        ("compiler", compiler),
        ("dependency", dependencies),
        ("build", build),
    ];
    let warning_policy = oracle_build_warning_policy().map_err(SuiteFailure::fixture)?;
    let warnings = command_oracle_warning_identity(&commands, &warning_policy);
    let record = oracle_build_record_json(
        platform,
        source_commit,
        sha256_bytes(resolver),
        binary_sha256,
        sha256_bytes(platform_identity.as_bytes()),
        &warning_policy,
        commands,
    );
    let path = artifact_root.join(format!("oracle-build-{platform}.json"));
    evidence_io(
        "write oracle build record",
        &path,
        fs::write(&path, record.as_bytes()),
    )?;
    let digest = sha256_bytes(record.as_bytes()).hex();
    let digest_path = artifact_root.join(format!("oracle-build-{platform}.sha256"));
    evidence_io(
        "write oracle build record digest",
        &digest_path,
        fs::write(
            &digest_path,
            format!("{digest}  oracle-build-{platform}.json\n"),
        ),
    )?;
    if warnings.fail_count != 0 || warnings.review_count != 0 {
        return Err(SuiteFailure::fixture(format!(
            "oracle build retained {} fail-pattern and {} review-pattern lines without an explicit reviewed disposition",
            warnings.fail_count, warnings.review_count,
        )));
    }
    Ok(())
}

fn oracle_build_record_json<const N: usize>(
    platform: &str,
    source_commit: &str,
    resolver_sha256: Digest,
    binary_sha256: Digest,
    platform_identity_sha256: Digest,
    warning_policy: &OracleBuildWarningPolicy,
    commands: [(&str, &CommandResult); N],
) -> String {
    let warnings = command_oracle_warning_identity(&commands, warning_policy);
    let mut fields = vec![
        "\"schemaVersion\": 3".to_owned(),
        format!("\"platform\": {platform:?}"),
        format!("\"sourceCommit\": {source_commit:?}"),
        format!("\"resolverSha256\": {:?}", resolver_sha256.hex()),
        format!("\"binarySha256\": {:?}", binary_sha256.hex()),
        format!(
            "\"platformIdentitySha256\": {:?}",
            platform_identity_sha256.hex()
        ),
        format!("\"warningPolicySha256\": {:?}", warning_policy.sha256.hex()),
        format!("\"failPatternCount\": {}", warnings.fail_count),
        format!("\"reviewPatternCount\": {}", warnings.review_count),
        format!(
            "\"warningFindingsSha256\": {:?}",
            warnings.findings_sha256.hex()
        ),
    ];
    for (prefix, command) in commands {
        push_oracle_stream_fields(&mut fields, prefix, "Stdout", command, true);
        push_oracle_stream_fields(&mut fields, prefix, "Stderr", command, false);
    }
    format!("{{\n  {}\n}}\n", fields.join(",\n  "))
}

fn command_oracle_warning_identity(
    commands: &[(&str, &CommandResult)],
    policy: &OracleBuildWarningPolicy,
) -> OracleBuildWarningIdentity {
    let mut streams = Vec::with_capacity(commands.len().saturating_mul(2));
    for (command, result) in commands {
        streams.push((*command, "stdout", result.stdout.as_slice()));
        streams.push((*command, "stderr", result.stderr.as_slice()));
    }
    oracle_warning_identity(streams, policy)
}

fn push_oracle_stream_fields(
    fields: &mut Vec<String>,
    prefix: &str,
    stream: &str,
    command: &CommandResult,
    stdout: bool,
) {
    let (original, retained, bytes, truncated) = if stdout {
        (
            command.stdout_sha256,
            sha256_bytes(&command.stdout),
            command.stdout_bytes,
            command.stdout_truncated,
        )
    } else {
        (
            command.stderr_sha256,
            sha256_bytes(&command.stderr),
            command.stderr_bytes,
            command.stderr_truncated,
        )
    };
    fields.push(format!("\"{prefix}{stream}Sha256\": {:?}", original.hex()));
    fields.push(format!(
        "\"{prefix}{stream}RetainedSha256\": {:?}",
        retained.hex()
    ));
    fields.push(format!("\"{prefix}{stream}Bytes\": {bytes}"));
    fields.push(format!(
        "\"{prefix}{stream}RetainedCompletely\": {}",
        !truncated
    ));
}

pub fn examples(
    root: &Path,
    report: &mut Report,
    failures: &Path,
    profile: &str,
) -> Result<(), FailureKind> {
    fixtures::profile_argument(profile).map_err(|detail| {
        report.check("profile", Duration::ZERO, Err(detail));
        FailureKind::Fixture
    })?;
    if !build_candidate(root, report, failures, profile, false) {
        return Err(FailureKind::Child);
    }
    run_fixture_gates(root, report, failures, profile)
}

fn workspace_tests(root: &Path, report: &mut Report, failures: &Path, profile: &str) -> bool {
    let release = profile == "release";
    let mut target_arguments = vec!["test"];
    if release {
        target_arguments.push("--release");
    }
    target_arguments.extend(["--workspace", "--all-targets", "--all-features", "--locked"]);
    if !release {
        target_arguments.extend(["--profile", "ci"]);
    }
    if !run_command(
        root,
        report,
        failures,
        "workspace-tests",
        cargo(Duration::from_mins(20), target_arguments),
    ) {
        return false;
    }

    let mut doc_arguments = vec!["test"];
    if release {
        doc_arguments.push("--release");
    }
    doc_arguments.extend(["--workspace", "--doc", "--all-features", "--locked"]);
    if !release {
        doc_arguments.extend(["--profile", "ci"]);
    }
    run_command(
        root,
        report,
        failures,
        "documentation-tests",
        cargo(Duration::from_mins(15), doc_arguments),
    )
}

fn build_candidate(
    root: &Path,
    report: &mut Report,
    failures: &Path,
    profile: &str,
    compat_tracing: bool,
) -> bool {
    let mut arguments = vec!["build"];
    if profile == "release" {
        arguments.push("--release");
    }
    arguments.extend(["--package", "hell-cli", "--bin", "hell", "--locked"]);
    if compat_tracing {
        arguments.extend(["--features", "hell-cli/compat-tracing"]);
    }
    if profile != "release" {
        arguments.extend(["--profile", profile]);
    }
    run_command(
        root,
        report,
        failures,
        "build-candidate",
        cargo(Duration::from_mins(15), arguments),
    )
}

fn run_fixture_gates(
    root: &Path,
    report: &mut Report,
    failures: &Path,
    profile: &str,
) -> Result<(), FailureKind> {
    fixtures::timed_check(report, root);
    if !report.passed() {
        return Err(FailureKind::Fixture);
    }
    if let Err(detail) = fixtures::run_examples(root, profile, report, failures) {
        let kind = if detail.starts_with("cannot run example-") {
            FailureKind::Child
        } else if detail.starts_with("cannot ") {
            FailureKind::Io
        } else {
            FailureKind::Fixture
        };
        report.check("examples", Duration::ZERO, Err(detail));
        return Err(kind);
    }
    if report.has_failed_command() {
        Err(FailureKind::Child)
    } else {
        report.passed().then_some(()).ok_or(FailureKind::Fixture)
    }
}

fn cargo<'a>(timeout: Duration, arguments: impl IntoIterator<Item = &'a str>) -> CommandSpec {
    CommandSpec::new("cargo", timeout).arguments(arguments)
}

fn run_command(
    root: &Path,
    report: &mut Report,
    failures: &Path,
    name: &str,
    command: CommandSpec,
) -> bool {
    let command = if command.current_directory.is_some() {
        command
    } else {
        command.current_directory(root)
    };
    match command.run() {
        Ok(result) => {
            let passed = result.status.success() && !result.timed_out;
            if !passed {
                let _ = fs::create_dir_all(failures);
                let _ = fs::write(failures.join(format!("{name}.stdout")), &result.stdout);
                let _ = fs::write(failures.join(format!("{name}.stderr")), &result.stderr);
            }
            report.command(name, &command, &result);
            passed
        }
        Err(error) => {
            report.check(
                name,
                Duration::ZERO,
                Err(format!(
                    "could not execute {}: {error}",
                    command.display_program()
                )),
            );
            false
        }
    }
}

fn deterministic_stress(failures_directory: &Path) -> Result<usize, String> {
    const SEEDS: [u64; 2] = [0xc0de_2026, 0x5eed_2026];
    const FAILURE_CAP: usize = 32;
    let mut observations = 0;
    let mut failures = Vec::new();
    'seeds: for seed in SEEDS {
        for (index, bytes) in DeterministicBytes::new(seed, 4_096, 4_096).enumerate() {
            observations += 1;
            let outcome = catch_unwind(AssertUnwindSafe(|| {
                let mut sources = SourceMap::new();
                let _ = sources.add_bytes(
                    SourceName::Virtual(format!("bytes-{seed}-{index}").into()),
                    bytes.clone(),
                );
            }));
            if outcome.is_err() && failures.len() < FAILURE_CAP {
                fs::create_dir_all(failures_directory)
                    .map_err(|error| format!("cannot create stress failure directory: {error}"))?;
                fs::write(
                    failures_directory.join(format!("stress-bytes-{seed}-{index}.input")),
                    bytes,
                )
                .map_err(|error| format!("cannot write stress failure input: {error}"))?;
                failures.push(format!("seed {seed}, case {index}, phase source-bytes"));
                if failures.len() >= FAILURE_CAP {
                    break 'seeds;
                }
            }
        }
        for (index, text) in DeterministicUtf8::new(seed, 4_096, 4_096).enumerate() {
            observations += 1;
            let outcome = catch_unwind(AssertUnwindSafe(|| {
                let mut sources = SourceMap::new();
                let source = sources.add_text(format!("utf8-{seed}-{index}"), text.clone());
                let _ = hell_syntax::parse(&source);
                let mut config = CompilerConfig::deterministic_test();
                config.limits.max_expansion_depth = Some(64);
                config.limits.max_elaborated_nodes = Some(65_536);
                let mut compiler = CompilerSession {
                    config,
                    ..CompilerSession::default()
                };
                let _ = hell_compiler::compile_source(
                    &mut compiler,
                    format!("utf8-{seed}-{index}"),
                    source.text.clone(),
                );
            }));
            if outcome.is_err() && failures.len() < FAILURE_CAP {
                fs::create_dir_all(failures_directory)
                    .map_err(|error| format!("cannot create stress failure directory: {error}"))?;
                fs::write(
                    failures_directory.join(format!("stress-utf8-{seed}-{index}.input")),
                    text.as_bytes(),
                )
                .map_err(|error| format!("cannot write stress failure input: {error}"))?;
                failures.push(format!("seed {seed}, case {index}, phase parse-compile"));
                if failures.len() >= FAILURE_CAP {
                    break 'seeds;
                }
            }
        }
    }
    if failures.is_empty() {
        Ok(observations)
    } else {
        Err(format!(
            "deterministic stress panicked in {} cases: {}",
            failures.len(),
            failures.join("; ")
        ))
    }
}

struct NightlyIdentities {
    oracle: ExecutableIdentity,
    candidate: ExecutableIdentity,
}

struct DifferentialCorpusResult {
    committed_observations: usize,
    generated_observations: usize,
    harness_failures: usize,
    unexpected_timeouts: usize,
    mismatches: Vec<ClassifiedMismatch>,
    stale_exact_claims: usize,
    resource_failures: usize,
    dependency_failures: usize,
}

fn unacceptable_mismatch_count(mismatches: &[ClassifiedMismatch]) -> usize {
    mismatches
        .iter()
        .filter(|mismatch| {
            mismatch.classification != Some(DivergenceClass::DeliberateDivergence)
                || mismatch.explanation.trim().is_empty()
        })
        .count()
}

#[derive(Clone, Copy, Debug, Default)]
struct CaseOutcome {
    timed_out: bool,
    agrees: bool,
    reviewed_deliberate_divergence: bool,
    resource_failures: usize,
}

fn verify_nightly_identities(
    root: &Path,
    oracle: &Path,
    oracle_sha256: Digest,
) -> Result<NightlyIdentities, String> {
    let executable_name = if cfg!(windows) { "hell.exe" } else { "hell" };
    let candidate = root.join("target").join("release").join(executable_name);
    let oracle = verify_executable(
        oracle,
        ExecutableRole::Oracle,
        Some(oracle_sha256),
        hell_builtins::LANGUAGE_VERSION,
    )
    .map_err(|error| format!("oracle identity verification failed: {error}"))?;
    let candidate = verify_executable(
        &candidate,
        ExecutableRole::Candidate,
        None,
        hell_builtins::LANGUAGE_VERSION,
    )
    .map_err(|error| format!("candidate identity verification failed: {error}"))?;
    let build_info = candidate
        .build_info
        .as_ref()
        .ok_or_else(|| "candidate identity has no build-info payload".to_owned())?;
    let source_commit = build_info
        .lines
        .iter()
        .find_map(|line| line.strip_prefix("source commit "))
        .ok_or_else(|| "candidate build info has no source commit".to_owned())?;
    if source_commit == "unavailable" || source_commit.is_empty() {
        return Err("candidate build info source commit is unavailable".to_owned());
    }
    if !build_info
        .lines
        .iter()
        .any(|line| line.as_ref() == "compatibility evidence schema 1")
    {
        return Err("candidate build info has no compatibility evidence schema".to_owned());
    }
    Ok(NightlyIdentities { oracle, candidate })
}

fn native_execution_environment(root: &Path) -> Result<NativeExecutionEnvironment, SuiteFailure> {
    let owned_values = native_environment_values()?;
    let value = |name: &str| {
        let index = NATIVE_BUILD_ENVIRONMENT_NAMES
            .iter()
            .position(|candidate| *candidate == name)
            .expect("requested native environment name is allowlisted");
        owned_values[index].as_deref()
    };
    let github_actions = value("GITHUB_ACTIONS") == Some("true");
    if github_actions
        && ["ImageOS", "ImageVersion", "RUNNER_ARCH", "RUNNER_OS"]
            .into_iter()
            .any(|name| value(name).is_none_or(str::is_empty))
    {
        return Err(SuiteFailure::fixture(
            "GitHub Actions native evidence lacks exact runner image or platform identity",
        ));
    }
    let runner_os = value("RUNNER_OS").unwrap_or(std::env::consts::OS);
    let runner_arch = value("RUNNER_ARCH").unwrap_or(std::env::consts::ARCH);
    let runner_kind = if github_actions {
        "github-actions"
    } else {
        "local"
    };
    let image_os = if github_actions {
        value("ImageOS").expect("GitHub image OS was validated")
    } else {
        "not-reported"
    };
    let image_version = if github_actions {
        value("ImageVersion").expect("GitHub image version was validated")
    } else {
        "not-reported"
    };
    let collected_at =
        crate::custody_ops::current_utc_timestamp().map_err(SuiteFailure::fixture)?;
    let rust_toolchain_selection_sha256 =
        sha256_file(&root.join("rust-toolchain.toml")).map_err(|error| {
            SuiteFailure::fixture(format!("cannot hash rust-toolchain.toml: {error}"))
        })?;
    let rustc_verbose = native_tool_output("rustc", &["--version", "--verbose"])?;
    let cargo_version = native_tool_output("cargo", &["--version", "--verbose"])?;
    let rustc_identity = canonical_native_tool_identity(&rustc_verbose, "rustc")?;
    let cargo_identity = canonical_native_tool_identity(&cargo_version, "cargo")?;
    let sysroot = native_tool_output("rustc", &["--print", "sysroot"])?;
    let sysroot = std::str::from_utf8(&sysroot)
        .map_err(|_| SuiteFailure::fixture("rustc sysroot output is not UTF-8"))?
        .strip_suffix('\n')
        .ok_or_else(|| SuiteFailure::fixture("rustc sysroot output is noncanonical"))?;
    if sysroot.is_empty() || sysroot.contains('\n') || sysroot.contains('\r') {
        return Err(SuiteFailure::fixture(
            "rustc sysroot output is not one canonical path",
        ));
    }
    let rustc_name = if cfg!(windows) { "rustc.exe" } else { "rustc" };
    let rustc_path = Path::new(sysroot).join("bin").join(rustc_name);
    let canonical_rustc_path = fs::canonicalize(&rustc_path).map_err(|error| {
        SuiteFailure::fixture(format!(
            "cannot resolve actual rustc executable {}: {error}",
            rustc_path.display()
        ))
    })?;
    let rustc_executable_sha256 = sha256_file(&canonical_rustc_path).map_err(|error| {
        SuiteFailure::fixture(format!(
            "cannot hash actual rustc executable {}: {error}",
            canonical_rustc_path.display()
        ))
    })?;
    let rustc_path = canonical_rustc_path.to_str().ok_or_else(|| {
        SuiteFailure::fixture("actual rustc executable path is not canonical UTF-8")
    })?;
    let mut rustc_path_identity = b"hell-native-rustc-path-v1\0".to_vec();
    rustc_path_identity.extend_from_slice(rustc_path.as_bytes());
    let environment_values = owned_values.each_ref().map(Option::as_deref);
    Ok(NativeExecutionEnvironment::new(
        &NativeExecutionEnvironmentInputs {
            runner_kind,
            runner_os,
            runner_arch,
            image_os,
            image_version,
            collected_at: &collected_at,
            rust_toolchain_selection_sha256,
            rustc_identity: &rustc_identity,
            rustc_executable_sha256,
            rustc_executable_path_sha256: sha256_bytes(&rustc_path_identity),
            cargo_identity: &cargo_identity,
            environment_values: &environment_values,
        },
    ))
}

fn native_environment_values()
-> Result<[Option<String>; NATIVE_BUILD_ENVIRONMENT_NAMES.len()], SuiteFailure> {
    let mut owned_values = Vec::with_capacity(NATIVE_BUILD_ENVIRONMENT_NAMES.len());
    for name in NATIVE_BUILD_ENVIRONMENT_NAMES {
        let value = match std::env::var_os(name) {
            Some(value) => Some(
                value
                    .into_string()
                    .map_err(|_| SuiteFailure::fixture(format!("{name} is not UTF-8")))?,
            ),
            None => None,
        };
        owned_values.push(value);
    }
    owned_values
        .try_into()
        .map_err(|_| SuiteFailure::fixture("native environment allowlist is inconsistent"))
}

fn canonical_native_tool_identity(output: &[u8], program: &str) -> Result<String, SuiteFailure> {
    let output = std::str::from_utf8(output)
        .map_err(|_| SuiteFailure::fixture(format!("{program} identity is not UTF-8")))?
        .strip_suffix('\n')
        .ok_or_else(|| SuiteFailure::fixture(format!("{program} identity lacks final newline")))?;
    if output.is_empty()
        || output.contains('\r')
        || output
            .lines()
            .any(|line| line.is_empty() || line.contains(" | "))
    {
        return Err(SuiteFailure::fixture(format!(
            "{program} identity is not canonical line-oriented output"
        )));
    }
    Ok(output.lines().collect::<Vec<_>>().join(" | "))
}

fn native_tool_output(program: &str, arguments: &[&str]) -> Result<Vec<u8>, SuiteFailure> {
    let output = Command::new(program)
        .args(arguments)
        .output()
        .map_err(|error| SuiteFailure::fixture(format!("cannot execute {program}: {error}")))?;
    if !output.status.success() || !output.stderr.is_empty() || output.stdout.is_empty() {
        return Err(SuiteFailure::fixture(format!(
            "{program} identity probe failed or emitted a noncanonical stream"
        )));
    }
    Ok(output.stdout)
}

#[allow(clippy::too_many_lines)]
fn run_differential_corpus(
    root: &Path,
    identities: &NightlyIdentities,
    failures: &Path,
    dependency_attestation: &Path,
) -> Result<DifferentialCorpusResult, SuiteFailure> {
    let native_environment = native_execution_environment(root)?;
    let (_, assurance_epoch_sha256) =
        crate::assurance::epoch(root).map_err(SuiteFailure::fixture)?;
    let mut identities = NightlyIdentities {
        oracle: identities.oracle.clone(),
        candidate: identities.candidate.clone(),
    };
    identities.oracle.assurance_epoch_sha256 = Some(assurance_epoch_sha256);
    identities.candidate.assurance_epoch_sha256 = Some(assurance_epoch_sha256);
    let identities = &identities;
    let artifact_root = failures.parent().unwrap_or_else(|| Path::new("."));
    let mismatch_root = artifact_root.join("mismatches");
    let observation_root = artifact_root.join("evidence").join("observations");
    let mut corpus_bytes = Vec::new();
    let mut committed_corpus_bytes = Vec::new();
    let mut generated_corpus_bytes = Vec::new();
    let mut generated_mismatch_ids = Vec::new();
    let mut committed = committed_differential_cases();
    bind_runtime_process_helper(&mut committed).map_err(SuiteFailure::fixture)?;
    validate_exploratory_corpus(&committed).map_err(SuiteFailure::fixture)?;
    let generated = generated_typed_cases(NATIVE_CORPUS_SEED, NATIVE_GENERATED_CASES);
    let expected_mismatches = load_expected_mismatches(root, identities)?;
    let mut mismatches = Vec::new();
    let mut unexpected_timeouts = 0;
    let mut resource_failures = 0_usize;
    let mut committed_outcomes = BTreeMap::new();
    for case in &committed {
        corpus_bytes.extend_from_slice(case.id.as_bytes());
        corpus_bytes.push(0);
        corpus_bytes.extend_from_slice(case.source.as_bytes());
        committed_corpus_bytes.extend_from_slice(case.id.as_bytes());
        committed_corpus_bytes.push(0);
        committed_corpus_bytes.extend_from_slice(case.source.as_bytes());
        let outcome = compare_case(
            identities,
            case,
            failures,
            &mismatch_root,
            &observation_root,
            &mut mismatches,
            &expected_mismatches,
        )?;
        unexpected_timeouts += usize::from(outcome.timed_out);
        resource_failures = resource_failures.saturating_add(outcome.resource_failures);
        committed_outcomes.insert(case.id.to_string(), outcome);
    }
    for generated_case in &generated {
        corpus_bytes.extend_from_slice(generated_case.id.as_bytes());
        corpus_bytes.extend_from_slice(&generated_case.ast_sha256.0);
        generated_corpus_bytes.extend_from_slice(generated_case.id.as_bytes());
        generated_corpus_bytes.extend_from_slice(&generated_case.ast_sha256.0);
        let case = DifferentialCase {
            id: std::sync::Arc::clone(&generated_case.id),
            source: std::sync::Arc::clone(&generated_case.source),
            timeout: Duration::from_secs(5),
            ..DifferentialCase::default()
        };
        let outcome = compare_case(
            identities,
            &case,
            failures,
            &mismatch_root,
            &observation_root,
            &mut mismatches,
            &expected_mismatches,
        )?;
        if !outcome.agrees {
            retain_generated_regression_proposal(artifact_root, generated_case, identities)?;
            generated_mismatch_ids.push(generated_case.id.to_string());
        }
        unexpected_timeouts += usize::from(outcome.timed_out);
        resource_failures = resource_failures.saturating_add(outcome.resource_failures);
    }
    let corpus_sha256 = sha256_bytes(&corpus_bytes);
    let reviewed_committed_corpus_sha256 = sha256_bytes(&committed_corpus_bytes);
    let generated_stress_corpus_sha256 = sha256_bytes(&generated_corpus_bytes);
    write_generated_regression_inventory(
        artifact_root,
        &generated_mismatch_ids,
        generated.len(),
        generated_stress_corpus_sha256,
    )?;
    let reviewed_corpus_catalog_sha256 = write_reviewed_corpus_catalog(artifact_root, &committed)?;
    let promotion_policy = promotion_policy::load(root).map_err(SuiteFailure::fixture)?;
    let promotion_review = promotion_policy::load_review(root).map_err(SuiteFailure::fixture)?;
    let compatibility_snapshot = root.join("compat").join("upstream-2026-05-29.json");
    let compatibility_snapshot_sha256 = evidence_io(
        "hash compatibility snapshot",
        &compatibility_snapshot,
        sha256_file(&compatibility_snapshot),
    )?;
    let dependency_lock = root.join("Cargo.lock");
    let dependency_lock_sha256 = evidence_io(
        "hash Cargo dependency lock",
        &dependency_lock,
        sha256_file(&dependency_lock),
    )?;
    let dependency_policy_attestation_sha256 = retain_dependency_attestation(
        root,
        dependency_attestation,
        artifact_root,
        dependency_lock_sha256,
        &identities.candidate,
    )?;
    let expected_mismatch_manifest = root.join("compat").join("expected-mismatches.toml");
    let expected_mismatch_manifest_sha256 = evidence_io(
        "hash expected mismatch manifest",
        &expected_mismatch_manifest,
        sha256_file(&expected_mismatch_manifest),
    )?;
    let platform_skips = required_platform_skips(root);
    let leaked_resources = resource_failures;
    let dependency_failures = 0;
    let missing_evidence_references = missing_claim_evidence();
    let unverified_out_of_scope_claims =
        unverified_out_of_scope_claims(&promotion_policy.required_profiles);
    let reviewed_expected_divergences = mismatches
        .iter()
        .filter(|mismatch| {
            mismatch.classification == Some(DivergenceClass::DeliberateDivergence)
                && !mismatch.explanation.trim().is_empty()
        })
        .count();
    let unacceptable_mismatches = mismatches
        .len()
        .saturating_sub(reviewed_expected_divergences);
    let claim_index = write_claim_evidence_index(
        artifact_root,
        assurance_epoch_sha256,
        compatibility_snapshot_sha256,
        promotion_policy.sha256,
        reviewed_corpus_catalog_sha256,
        &identities.oracle,
        &identities.candidate,
        &committed,
        &committed_outcomes,
    )?;
    let stale_exact_claims = claim_index.stale();
    evidence_io(
        "retain evidence summary and executable identities under",
        artifact_root,
        write_evidence_summary(
            artifact_root,
            &EvidenceSummary {
                native_environment: &native_environment,
                oracle: &identities.oracle,
                candidate: &identities.candidate,
                assurance_epoch_sha256,
                corpus_seed: NATIVE_CORPUS_SEED,
                committed_observations: committed.len(),
                generated_observations: generated.len(),
                corpus_sha256,
                reviewed_committed_corpus_sha256,
                generated_stress_corpus_sha256,
                promotion_policy_sha256: promotion_policy.sha256,
                reviewed_corpus_catalog_sha256,
                promotion_review_sha256: promotion_review.sha256,
                mismatches: unacceptable_mismatches,
                reviewed_expected_divergences,
                unexpected_timeouts,
                stale_exact_claims,
                irrelevant_claim_references: claim_index.irrelevant_references,
                profile_evidence_mismatches: claim_index.profile_mismatches,
                platform_evidence_mismatches: claim_index.platform_mismatches,
                normalizer_evidence_mismatches: claim_index.normalizer_mismatches,
                failed_claim_observations: claim_index.failed_observations,
                missing_evidence_references,
                unverified_out_of_scope_claims,
                required_profiles: &promotion_policy.required_profiles,
                compatibility_snapshot_sha256,
                claim_evidence_index_sha256: claim_index.sha256,
                dependency_lock_sha256,
                dependency_policy_attestation_sha256,
                expected_mismatch_manifest_sha256,
                repository_policy_passed: true,
                required_platform_skips: platform_skips,
                leaked_resources,
                dependency_failures,
                promotion_ready: false,
            },
        ),
    )?;
    Ok(DifferentialCorpusResult {
        committed_observations: committed.len(),
        generated_observations: generated.len(),
        harness_failures: 0,
        unexpected_timeouts,
        mismatches,
        stale_exact_claims,
        resource_failures,
        dependency_failures,
    })
}

fn run_collection_campaign(
    root: &Path,
    identities: &NightlyIdentities,
    trusted: &CollectionTrustedHarness,
    platform: &str,
    artifact_root: &Path,
) -> Result<(), SuiteFailure> {
    let campaign_root = artifact_root.join("collection-evidence");
    if campaign_root.exists() {
        return Err(SuiteFailure::fixture(
            "collection campaign output already exists and cannot be overlaid",
        ));
    }
    let observation_root = campaign_root.join("observations");
    evidence_io(
        "create exact dormant collection observation root",
        &observation_root,
        fs::create_dir_all(&observation_root),
    )?;
    let mut cases = reviewed_collection_cases().map_err(SuiteFailure::fixture)?;
    bind_runtime_process_helper(&mut cases).map_err(SuiteFailure::fixture)?;
    if cases.len() != hell_testkit::COLLECTION_CASE_AUTHORITY_COUNT {
        return Err(SuiteFailure::fixture(
            "collection campaign no longer has exact dormant Map712/Set479 inventory",
        ));
    }
    let (_, assurance_epoch_sha256) =
        crate::assurance::epoch(root).map_err(SuiteFailure::fixture)?;
    let mut identities = NightlyIdentities {
        oracle: identities.oracle.clone(),
        candidate: identities.candidate.clone(),
    };
    identities.oracle.assurance_epoch_sha256 = Some(assurance_epoch_sha256);
    identities.candidate.assurance_epoch_sha256 = Some(assurance_epoch_sha256);
    let inventory = execute_collection_campaign_cases(&identities, &cases, &observation_root)?;
    write_collection_campaign_inventory(&campaign_root, &inventory)?;
    write_collection_campaign_manifest(platform, &campaign_root, &identities, trusted, &inventory)
}

fn execute_collection_campaign_cases(
    identities: &NightlyIdentities,
    cases: &[DifferentialCase],
    observation_root: &Path,
) -> Result<Vec<(String, Digest)>, SuiteFailure> {
    let mut inventory = Vec::with_capacity(cases.len());
    for case in cases {
        let report = differential_with_identities(&identities.oracle, &identities.candidate, case)
            .map_err(|error| {
                SuiteFailure::fixture(format!(
                    "collection campaign case {} could not execute: {error}",
                    case.id
                ))
            })?;
        if !report.mismatches.is_empty() || report.oracle.timed_out || report.candidate.timed_out {
            return Err(SuiteFailure::fixture(format!(
                "collection campaign case {} did not match as exact black-box evidence",
                case.id
            )));
        }
        let directory = evidence_io(
            &format!("retain exact collection campaign case {} at", case.id),
            &observation_root.join(case.id.as_ref()),
            retain_observation_bundle(observation_root, case, &report),
        )?;
        let bundle = verify_observation_bundle_for_case(&directory, case).map_err(|error| {
            SuiteFailure::fixture(format!(
                "collection campaign case {} retained an invalid bundle: {error}",
                case.id
            ))
        })?;
        inventory.push((case.id.to_string(), bundle));
    }
    inventory.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
    if inventory.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(SuiteFailure::fixture(
            "collection campaign inventory contains duplicate case IDs",
        ));
    }
    Ok(inventory)
}

fn write_collection_campaign_inventory(
    campaign_root: &Path,
    inventory: &[(String, Digest)],
) -> Result<(), SuiteFailure> {
    let mut document = String::new();
    for (case_id, bundle) in inventory {
        writeln!(document, "{case_id}\t{}", bundle.hex()).expect("writing to String cannot fail");
    }
    let inventory_path = campaign_root.join("inventory.tsv");
    evidence_io(
        "write exact collection campaign inventory",
        &inventory_path,
        fs::write(&inventory_path, document.as_bytes()),
    )?;
    evidence_io(
        "write exact collection campaign inventory digest",
        &campaign_root.join("inventory.sha256"),
        fs::write(
            campaign_root.join("inventory.sha256"),
            format!(
                "{}  inventory.tsv\n",
                sha256_bytes(document.as_bytes()).hex()
            ),
        ),
    )
}

fn write_collection_campaign_manifest(
    platform: &str,
    campaign_root: &Path,
    identities: &NightlyIdentities,
    trusted: &CollectionTrustedHarness,
    inventory: &[(String, Digest)],
) -> Result<(), SuiteFailure> {
    let candidate_commit = identities
        .candidate
        .build_info
        .as_ref()
        .and_then(|build| {
            build
                .lines
                .iter()
                .find_map(|line| line.strip_prefix("source commit "))
        })
        .ok_or_else(|| SuiteFailure::fixture("collection candidate source commit is absent"))?;
    let receipt = identities
        .oracle
        .acquisition_receipt_sha256
        .map(Digest::hex);
    let attestation = identities
        .oracle
        .acquisition_attestation_sha256
        .map(Digest::hex);
    let candidate_executable = identities.candidate.sha256.hex();
    let oracle_executable = identities.oracle.sha256.hex();
    let inventory = collection_inventory_digest(inventory);
    let expected = CollectionCampaignExpectation {
        platform,
        candidate_executable: &candidate_executable,
        oracle_executable: &oracle_executable,
        trusted,
        inventory: &inventory,
        receipt: receipt.as_deref(),
        attestation: attestation.as_deref(),
    };
    let manifest = collection_campaign_manifest_document(&CollectionCampaignManifest {
        candidate_commit,
        expected: &expected,
    });
    evidence_io(
        "write exact collection campaign manifest",
        &campaign_root.join("campaign.json"),
        fs::write(campaign_root.join("campaign.json"), manifest.as_bytes()),
    )?;
    evidence_io(
        "write exact collection campaign manifest digest",
        &campaign_root.join("campaign.json.sha256"),
        fs::write(
            campaign_root.join("campaign.json.sha256"),
            format!(
                "{}  campaign.json\n",
                sha256_bytes(manifest.as_bytes()).hex()
            ),
        ),
    )
}

fn collection_inventory_digest(inventory: &[(String, Digest)]) -> String {
    let mut document = String::new();
    for (case_id, bundle) in inventory {
        writeln!(document, "{case_id}\t{}", bundle.hex()).expect("writing to String cannot fail");
    }
    sha256_bytes(document.as_bytes()).hex()
}

fn runtime_promotion_completeness() -> Result<(), String> {
    let mut committed = committed_differential_cases();
    bind_runtime_process_helper(&mut committed)?;
    validate_runtime_obligation_coverage(&committed)
}

fn retain_generated_regression_proposal(
    artifact_root: &Path,
    generated: &GeneratedCase,
    identities: &NightlyIdentities,
) -> Result<(), SuiteFailure> {
    let directory = artifact_root
        .join("mismatches")
        .join("proposed-regressions");
    evidence_io(
        "create generated regression proposal directory",
        &directory,
        fs::create_dir_all(&directory),
    )?;
    let path = directory.join(format!("{}.json", generated.id));
    let source_sha256 = sha256_bytes(generated.source.as_bytes()).hex();
    let document = format!(
        concat!(
            "{{\n",
            "  \"schemaVersion\": 1,\n",
            "  \"caseId\": {:?},\n",
            "  \"seed\": {},\n",
            "  \"astSha256\": {:?},\n",
            "  \"sourceSha256\": {:?},\n",
            "  \"resultType\": {:?},\n",
            "  \"mismatchBundlePath\": {:?},\n",
            "  \"minimizationStatus\": \"pending\",\n",
            "  \"shrinkPlan\": {:?},\n",
            "  \"reviewState\": \"unreviewed\",\n",
            "  \"claimEligible\": false\n",
            "}}\n"
        ),
        generated.id,
        generated.seed,
        generated.ast_sha256.hex(),
        source_sha256,
        format!("{:?}", generated.result_type),
        format!("mismatches/{}", generated.id),
        generated.shrink_description,
    );
    evidence_io(
        "retain generated regression proposal",
        &path,
        fs::write(&path, document.as_bytes()),
    )?;
    let subject = directory.join(generated.id.as_ref());
    evidence_io(
        "create generated regression subject",
        &subject,
        fs::create_dir(&subject),
    )?;
    evidence_io(
        "retain generated regression program",
        &subject.join("program.hell"),
        fs::write(subject.join("program.hell"), generated.source.as_bytes()),
    )?;
    evidence_io(
        "retain generated regression oracle",
        &subject.join("oracle"),
        fs::copy(&identities.oracle.path, subject.join("oracle")).map(|_| ()),
    )?;
    evidence_io(
        "retain generated regression candidate",
        &subject.join("candidate"),
        fs::copy(&identities.candidate.path, subject.join("candidate")).map(|_| ()),
    )
}

fn write_generated_regression_inventory(
    artifact_root: &Path,
    mismatch_ids: &[String],
    generated_count: usize,
    generated_corpus_sha256: Digest,
) -> Result<(), SuiteFailure> {
    if !mismatch_ids.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(SuiteFailure::fixture(
            "generated regression mismatch inventory is not canonical",
        ));
    }
    let mut document = format!(
        concat!(
            "{{\n  \"schemaVersion\": 1,\n",
            "  \"corpusSeed\": {},\n",
            "  \"generatedObservationCount\": {},\n",
            "  \"generatedStressCorpusSha256\": \"{}\",\n",
            "  \"caseIds\": ["
        ),
        NATIVE_CORPUS_SEED,
        generated_count,
        generated_corpus_sha256.hex(),
    );
    for (index, case_id) in mismatch_ids.iter().enumerate() {
        if index != 0 {
            document.push(',');
        }
        write!(document, "\n    \"{case_id}\"")
            .expect("writing generated regression inventory cannot fail");
    }
    document.push_str("\n  ]\n}\n");
    let digest = sha256_bytes(document.as_bytes());
    let path = artifact_root.join("generated-regression-inventory.json");
    evidence_io(
        "retain generated regression inventory",
        &path,
        fs::write(&path, document.as_bytes()),
    )?;
    let digest_path = artifact_root.join("generated-regression-inventory.sha256");
    evidence_io(
        "retain generated regression inventory digest",
        &digest_path,
        fs::write(
            &digest_path,
            format!("{}  generated-regression-inventory.json\n", digest.hex()),
        ),
    )
}

fn validate_exploratory_corpus(cases: &[DifferentialCase]) -> Result<(), String> {
    validate_evidence_catalog(cases)
}

fn check_runtime_promotion_completeness(report: &mut Report) -> bool {
    let started = Instant::now();
    let result = runtime_promotion_completeness();
    let complete = result.is_ok();
    report.check("runtime-promotion-completeness", started.elapsed(), result);
    complete
}

fn write_reviewed_corpus_catalog(
    artifact_root: &Path,
    committed: &[DifferentialCase],
) -> Result<Digest, SuiteFailure> {
    let path = artifact_root
        .join("evidence")
        .join("reviewed-corpus-catalog.json");
    let output = reviewed_corpus_catalog_json(committed);
    if let Some(parent) = path.parent() {
        evidence_io(
            "create reviewed corpus catalog directory",
            parent,
            fs::create_dir_all(parent),
        )?;
    }
    evidence_io(
        "write reviewed corpus catalog",
        &path,
        fs::write(&path, output.as_bytes()),
    )?;
    evidence_io("hash reviewed corpus catalog", &path, sha256_file(&path))
}

fn reviewed_corpus_catalog_json(committed: &[DifferentialCase]) -> String {
    let mut output = String::from(
        "{\n  \"schemaVersion\": 1,\n  \"generatedCasesEligible\": false,\n  \"cases\": [",
    );
    for (index, case) in committed.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        output.push_str("\n    { \"id\": ");
        write!(output, "{:?}", case.id).expect("writing to String cannot fail");
        output.push_str(", \"sourceSha256\": ");
        write!(output, "{:?}", sha256_bytes(case.source.as_bytes()).hex())
            .expect("writing to String cannot fail");
        output.push_str(", \"claimEvidenceEligible\": ");
        output.push_str(if case.claim_evidence.is_some() {
            "true"
        } else {
            "false"
        });
        output.push_str(", \"reviewState\": ");
        match &case.claim_evidence {
            Some(_) => output.push_str("\"reviewed\""),
            None => output.push_str("null"),
        }
        output.push_str(", \"reviewStatement\": ");
        match &case.claim_evidence {
            Some(descriptor) => write!(output, "{:?}", descriptor.review_statement)
                .expect("writing to String cannot fail"),
            None => output.push_str("null"),
        }
        output.push_str(", \"profile\": ");
        match &case.claim_evidence {
            Some(descriptor) => write!(
                output,
                "{:?}",
                match descriptor.profile {
                    hell_builtins::ExecutionProfile::Upstream => "upstream",
                    hell_builtins::ExecutionProfile::Sandboxed => "sandboxed",
                }
            )
            .expect("writing to String cannot fail"),
            None => output.push_str("null"),
        }
        output.push_str(", \"targets\": [");
        if let Some(descriptor) = &case.claim_evidence {
            let mut targets = descriptor.targets.iter().collect::<Vec<_>>();
            targets.sort_by(|left, right| {
                (left.builtin.as_bytes(), left.dimension.as_str().as_bytes()).cmp(&(
                    right.builtin.as_bytes(),
                    right.dimension.as_str().as_bytes(),
                ))
            });
            for (target_index, target) in targets.iter().enumerate() {
                if target_index != 0 {
                    output.push_str(", ");
                }
                write!(
                    output,
                    "{{ \"builtin\": {:?}, \"dimension\": {:?} }}",
                    target.builtin,
                    target.dimension.as_str()
                )
                .expect("writing to String cannot fail");
            }
        }
        output.push_str("] }");
    }
    output.push_str("\n  ]\n}\n");
    output
}

#[derive(Clone, Copy, Debug, Default)]
struct ClaimEvidenceIndexResult {
    sha256: Digest,
    indexed_entries: usize,
    missing_bundles: usize,
    irrelevant_references: usize,
    profile_mismatches: usize,
    platform_mismatches: usize,
    normalizer_mismatches: usize,
    failed_observations: usize,
}

impl ClaimEvidenceIndexResult {
    fn stale(self) -> usize {
        self.missing_bundles
            .saturating_add(self.irrelevant_references)
            .saturating_add(self.profile_mismatches)
            .saturating_add(self.platform_mismatches)
            .saturating_add(self.normalizer_mismatches)
            .saturating_add(self.failed_observations)
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn write_claim_evidence_index(
    artifact_root: &Path,
    assurance_epoch_sha256: Digest,
    compatibility_snapshot_sha256: Digest,
    promotion_policy_sha256: Digest,
    reviewed_corpus_catalog_sha256: Digest,
    oracle: &ExecutableIdentity,
    candidate: &ExecutableIdentity,
    committed: &[DifferentialCase],
    outcomes: &BTreeMap<String, CaseOutcome>,
) -> Result<ClaimEvidenceIndexResult, SuiteFailure> {
    let observations = artifact_root.join("evidence").join("observations");
    let index_path = artifact_root.join("evidence").join("claim-index.json");
    let candidate_source_commit = candidate
        .build_info
        .as_ref()
        .and_then(|build_info| {
            build_info
                .lines
                .iter()
                .find_map(|line| line.strip_prefix("source commit "))
        })
        .ok_or_else(|| {
            SuiteFailure::fixture(format!(
                "candidate identity {} has no source commit for claim evidence index {}",
                candidate.path.display(),
                index_path.display()
            ))
        })?;
    let platform = current_evidence_platform();
    let claim_platform = current_claim_platform();
    let mut result = ClaimEvidenceIndexResult::default();
    let mut entries = Vec::<(String, String)>::new();
    for claim in hell_builtins::compatibility_claims() {
        let builtin = hell_builtins::registry()
            .get(usize::from(claim.builtin.0))
            .ok_or_else(|| {
                SuiteFailure::fixture(format!(
                    "claim evidence index {} references missing builtin registry index {}",
                    index_path.display(),
                    claim.builtin.0
                ))
            })?;
        for dimension in &claim.dimensions {
            for scope in dimension.scopes {
                if !scope
                    .profiles
                    .contains(&hell_builtins::ExecutionProfile::Upstream)
                {
                    continue;
                }
                let applies_here = claim_platform.is_some_and(|platform| {
                    scope.platforms.contains(&hell_builtins::ClaimPlatform::All)
                        || scope.platforms.contains(&platform)
                });
                if !applies_here {
                    continue;
                }
                if scope.status == ClaimStatus::Unverified {
                    continue;
                }
                if scope.status == ClaimStatus::NotApplicable {
                    let key = format!(
                        "{}\0{}\0upstream\0{}\0",
                        builtin.name,
                        dimension.dimension.as_str(),
                        platform
                    );
                    entries.push((
                        key,
                        format!(
                            "{{ \"builtin\": {:?}, \"dimension\": {:?}, \"status\": \"not-applicable\", \"profile\": \"upstream\", \"platform\": {:?}, \"rationale\": {:?} }}",
                            builtin.name,
                            dimension.dimension.as_str(),
                            platform,
                            scope.rationale.unwrap_or_default(),
                        ),
                    ));
                    continue;
                }
                if scope.evidence.is_empty() {
                    result.missing_bundles = result.missing_bundles.saturating_add(1);
                    continue;
                }
                for reference in scope.evidence {
                    let Ok(parsed_reference) =
                        hell_builtins::parse_differential_reference(reference)
                    else {
                        result.irrelevant_references =
                            result.irrelevant_references.saturating_add(1);
                        continue;
                    };
                    let case_id = parsed_reference.case_id;
                    let Some(case) = committed.iter().find(|case| case.id.as_ref() == case_id)
                    else {
                        result.irrelevant_references =
                            result.irrelevant_references.saturating_add(1);
                        continue;
                    };
                    let Some(descriptor) = &case.claim_evidence else {
                        result.irrelevant_references =
                            result.irrelevant_references.saturating_add(1);
                        continue;
                    };
                    if !descriptor.targets.iter().any(|target| {
                        target.builtin.as_ref() == builtin.name
                            && target.dimension == dimension.dimension
                    }) {
                        result.irrelevant_references =
                            result.irrelevant_references.saturating_add(1);
                        continue;
                    }
                    if descriptor.profile != hell_builtins::ExecutionProfile::Upstream {
                        result.profile_mismatches = result.profile_mismatches.saturating_add(1);
                        continue;
                    }
                    if descriptor.claim_normalizers != scope.normalizers {
                        result.normalizer_mismatches =
                            result.normalizer_mismatches.saturating_add(1);
                        continue;
                    }
                    let Some(outcome) = outcomes.get(case_id) else {
                        result.missing_bundles = result.missing_bundles.saturating_add(1);
                        continue;
                    };
                    if !outcome_supports_claim_status(*outcome, scope.status)
                        || outcome.timed_out
                        || outcome.resource_failures != 0
                    {
                        result.failed_observations = result.failed_observations.saturating_add(1);
                        continue;
                    }
                    let directory = observations.join(case_id);
                    let Ok(bundle_manifest_sha256) =
                        verify_observation_bundle_for_case(&directory, case)
                    else {
                        result.missing_bundles = result.missing_bundles.saturating_add(1);
                        continue;
                    };
                    let required_files = [
                        "main.hell",
                        "case.toml",
                        "oracle/observation.json",
                        "candidate/observation.json",
                    ];
                    let mut file_fields = String::new();
                    let mut files_valid = true;
                    for (index, relative) in required_files.iter().enumerate() {
                        let Ok(digest) = sha256_file(&directory.join(relative)) else {
                            files_valid = false;
                            break;
                        };
                        if index != 0 {
                            file_fields.push_str(", ");
                        }
                        write!(file_fields, "{relative:?}: {:?}", digest.hex())
                            .expect("writing to String cannot fail");
                    }
                    if !files_valid {
                        result.missing_bundles = result.missing_bundles.saturating_add(1);
                        continue;
                    }
                    let normalizers = scope
                        .normalizers
                        .iter()
                        .map(|normalizer| format!("{:?}", normalizer.as_str()))
                        .collect::<Vec<_>>()
                        .join(", ");
                    let claim_platforms = scope
                        .platforms
                        .iter()
                        .map(|platform| format!("{:?}", claim_platform_name(*platform)))
                        .collect::<Vec<_>>()
                        .join(", ");
                    let status = claim_status_name(scope.status);
                    let entry = format!(
                        concat!(
                            "{{ \"builtin\": {:?}, \"dimension\": {:?}, \"status\": {:?}, ",
                            "\"profile\": \"upstream\", \"platform\": {:?}, ",
                            "\"claimPlatforms\": [{}], \"reference\": {:?}, ",
                            "\"targetDeclared\": true, \"harnessNormalizers\": [\"diagnostic-sandbox-path-v1\"], ",
                            "\"claimNormalizers\": [{}], \"bundleManifestSha256\": {:?}, ",
                            "\"bundleFiles\": {{ {} }} }}"
                        ),
                        builtin.name,
                        dimension.dimension.as_str(),
                        status,
                        platform,
                        claim_platforms,
                        reference,
                        normalizers,
                        bundle_manifest_sha256.hex(),
                        file_fields,
                    );
                    let key = format!(
                        "{}\0{}\0upstream\0{}\0{}",
                        builtin.name,
                        dimension.dimension.as_str(),
                        platform,
                        reference
                    );
                    entries.push((key, entry));
                }
            }
        }
    }
    entries.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
    result.indexed_entries = entries.len();
    let mut output = format!(
        concat!(
            "{{\n  \"schemaVersion\": 3,\n",
            "  \"compatibilitySnapshotSha256\": {:?},\n",
            "  \"assuranceEpochSha256\": {:?},\n",
            "  \"promotionPolicySha256\": {:?},\n",
            "  \"reviewedCorpusCatalogSha256\": {:?},\n",
            "  \"oracleSha256\": {:?},\n",
            "  \"candidateSha256\": {:?},\n",
            "  \"candidateSourceCommit\": {:?},\n",
            "  \"platform\": {:?},\n",
            "  \"profile\": \"upstream\",\n",
            "  \"indexedEntries\": {},\n",
            "  \"missingBundles\": {},\n",
            "  \"irrelevantReferences\": {},\n",
            "  \"profileMismatches\": {},\n",
            "  \"platformMismatches\": {},\n",
            "  \"normalizerMismatches\": {},\n",
            "  \"failedObservations\": {},\n",
            "  \"entries\": ["
        ),
        compatibility_snapshot_sha256.hex(),
        assurance_epoch_sha256.hex(),
        promotion_policy_sha256.hex(),
        reviewed_corpus_catalog_sha256.hex(),
        oracle.sha256.hex(),
        candidate.sha256.hex(),
        candidate_source_commit,
        platform,
        result.indexed_entries,
        result.missing_bundles,
        result.irrelevant_references,
        result.profile_mismatches,
        result.platform_mismatches,
        result.normalizer_mismatches,
        result.failed_observations,
    );
    for (index, (_, entry)) in entries.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        output.push_str("\n    ");
        output.push_str(entry);
    }
    output.push_str("\n  ]\n}\n");
    if let Some(parent) = index_path.parent() {
        evidence_io(
            "create claim evidence index directory",
            parent,
            fs::create_dir_all(parent),
        )?;
    }
    evidence_io(
        "write claim evidence index",
        &index_path,
        fs::write(&index_path, output.as_bytes()),
    )?;
    result.sha256 = evidence_io(
        "hash claim evidence index",
        &index_path,
        sha256_file(&index_path),
    )?;
    Ok(result)
}

fn outcome_supports_claim_status(outcome: CaseOutcome, status: ClaimStatus) -> bool {
    if status == ClaimStatus::DeliberateDivergence {
        outcome.reviewed_deliberate_divergence
    } else {
        outcome.agrees
    }
}

fn current_evidence_platform() -> String {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "linux-amd64".to_owned(),
        ("macos", "aarch64") => "macos-arm64".to_owned(),
        ("windows", "x86_64") => "windows-amd64".to_owned(),
        (os, arch) => format!("{os}-{arch}"),
    }
}

fn current_claim_platform() -> Option<hell_builtins::ClaimPlatform> {
    match std::env::consts::OS {
        "linux" => Some(hell_builtins::ClaimPlatform::Linux),
        "macos" => Some(hell_builtins::ClaimPlatform::MacOs),
        "windows" => Some(hell_builtins::ClaimPlatform::Windows),
        _ => None,
    }
}

const fn claim_platform_name(platform: hell_builtins::ClaimPlatform) -> &'static str {
    match platform {
        hell_builtins::ClaimPlatform::All => "all",
        hell_builtins::ClaimPlatform::Linux => "linux",
        hell_builtins::ClaimPlatform::MacOs => "macos",
        hell_builtins::ClaimPlatform::Windows => "windows",
    }
}

const fn claim_status_name(status: ClaimStatus) -> &'static str {
    match status {
        ClaimStatus::Exact => "exact",
        ClaimStatus::Normalized => "normalized",
        ClaimStatus::PlatformDependent => "platform-dependent",
        ClaimStatus::DeliberateDivergence => "deliberate-divergence",
        ClaimStatus::Unverified => "unverified",
        ClaimStatus::NotApplicable => "not-applicable",
    }
}

fn load_expected_mismatches(
    root: &Path,
    identities: &NightlyIdentities,
) -> Result<BTreeMap<String, String>, SuiteFailure> {
    let path = root.join("compat").join("expected-mismatches.toml");
    let document = evidence_io(
        "read expected mismatch manifest",
        &path,
        fs::read_to_string(&path),
    )?;
    parse_expected_mismatches(&document, identities).map_err(SuiteFailure::fixture)
}

fn parse_expected_mismatches(
    document: &str,
    identities: &NightlyIdentities,
) -> Result<BTreeMap<String, String>, String> {
    const ENTRY_MARKER: &str = "[[entry]]";
    let mut documents = document.split(ENTRY_MARKER);
    let header = documents.next().unwrap_or_default();
    let has_entries = document.contains(ENTRY_MARKER);
    let mut header_values = crate::strict_toml::assignments(header)?;
    if crate::strict_toml::unsigned(&crate::strict_toml::take(
        &mut header_values,
        "schema_version",
    )?)? != 1
        || crate::strict_toml::string(&crate::strict_toml::take(&mut header_values, "baseline")?)?
            != hell_builtins::LANGUAGE_VERSION
    {
        return Err("expected mismatch manifest schema or baseline is invalid".to_owned());
    }
    if has_entries {
        crate::strict_toml::finish(&header_values)?;
    } else {
        let entries = crate::strict_toml::string_array(&crate::strict_toml::take(
            &mut header_values,
            "entries",
        )?)?;
        if !entries.is_empty() {
            return Err("expected mismatch entries must use typed entry tables".to_owned());
        }
        crate::strict_toml::finish(&header_values)?;
        return Ok(BTreeMap::new());
    }
    let mut catalog = BTreeMap::new();
    for raw_entry in documents {
        let mut raw_values = crate::strict_toml::assignments(raw_entry)?;
        let required = [
            "case",
            "classification",
            "claim",
            "dimension",
            "platform",
            "profile",
            "oracle_sha256",
            "candidate_sha256",
            "expires",
            "rationale",
        ];
        let mut values = BTreeMap::new();
        for key in required {
            let value =
                crate::strict_toml::string(&crate::strict_toml::take(&mut raw_values, key)?)?;
            values.insert(key, value);
        }
        crate::strict_toml::finish(&raw_values)?;
        let case_id = values["case"].as_str();
        validate_expected_mismatch_expiry(&values["expires"])?;
        if !hell_builtins::validate_case_id(case_id)
            || values["classification"] != "deliberate-divergence"
            || values["profile"] != "upstream"
            || values["platform"] != current_evidence_platform()
            || values["oracle_sha256"] != identities.oracle.sha256.hex()
            || values["candidate_sha256"] != identities.candidate.sha256.hex()
            || values["rationale"].is_empty()
        {
            return Err(format!(
                "expected mismatch entry for {case_id:?} has invalid classification or identity"
            ));
        }
        let builtin = hell_builtins::lookup(&values["claim"]).ok_or_else(|| {
            format!(
                "expected mismatch entry names unknown claim {:?}",
                values["claim"]
            )
        })?;
        let claim = hell_builtins::compatibility_claim(builtin.id)
            .ok_or_else(|| "expected mismatch claim is missing".to_owned())?;
        let valid_claim = claim.dimensions.iter().any(|dimension| {
            dimension.dimension.as_str() == values["dimension"]
                && dimension.scopes.iter().any(|scope| {
                    scope.status == ClaimStatus::DeliberateDivergence
                        && scope.evidence.iter().any(|reference| {
                            hell_builtins::parse_differential_reference(reference)
                                .is_ok_and(|reference| reference.case_id == case_id)
                        })
                })
        });
        if !valid_claim {
            return Err(format!(
                "expected mismatch entry for {case_id:?} is not bound to a deliberate-divergence claim"
            ));
        }
        if catalog
            .insert(case_id.to_owned(), values["rationale"].clone())
            .is_some()
        {
            return Err(format!("expected mismatch case {case_id:?} is duplicated"));
        }
    }
    Ok(catalog)
}

fn validate_expected_mismatch_expiry(value: &str) -> Result<(), String> {
    let components = value
        .split('-')
        .map(|component| {
            component
                .parse::<u32>()
                .map_err(|_| "expected mismatch expiry must use YYYY-MM-DD".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let [year, month, day] = components.as_slice() else {
        return Err("expected mismatch expiry must use YYYY-MM-DD".to_owned());
    };
    let maximum_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 400 == 0 || year % 4 == 0 && year % 100 != 0 => 29,
        2 => 28,
        _ => return Err("expected mismatch expiry has an invalid month".to_owned()),
    };
    if *year < 1970 || *day == 0 || *day > maximum_day {
        return Err("expected mismatch expiry is not a valid future date".to_owned());
    }
    let expiry_days = days_since_unix_epoch(*year, *month, *day);
    let today_days = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "system clock predates the Unix epoch".to_owned())?
        .as_secs()
        / 86_400;
    if expiry_days < today_days {
        return Err(format!("expected mismatch waiver expired on {value}"));
    }
    Ok(())
}

fn days_since_unix_epoch(year: u32, month: u32, day: u32) -> u64 {
    let year = i64::from(year) - i64::from(month <= 2);
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let shifted_month = i64::from(month) + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    u64::try_from(era * 146_097 + day_of_era - 719_468).unwrap_or_default()
}

fn compare_case(
    identities: &NightlyIdentities,
    case: &DifferentialCase,
    failures: &Path,
    mismatch_root: &Path,
    observation_root: &Path,
    mismatches: &mut Vec<ClassifiedMismatch>,
    expected_mismatches: &BTreeMap<String, String>,
) -> Result<CaseOutcome, SuiteFailure> {
    const FAILURE_CAP: usize = 32;
    let comparison = differential_with_identities(&identities.oracle, &identities.candidate, case)
        .map_err(|error| {
            let failure_path = failures.join(format!("{}.harness.txt", case.id));
            let retention = fs::create_dir_all(failures)
                .and_then(|()| fs::write(&failure_path, error.to_string()));
            let retention_detail = retention.err().map_or_else(String::new, |io_error| {
                format!(
                    "; cannot retain harness failure {}: {io_error}",
                    failure_path.display()
                )
            });
            SuiteFailure::fixture(format!(
                "differential comparison failed for case {}: {error}{retention_detail}",
                case.id
            ))
        })?;
    let observation_path = observation_root.join(case.id.as_ref());
    evidence_io(
        &format!("retain differential observation for case {} at", case.id),
        &observation_path,
        retain_observation_bundle(observation_root, case, &comparison),
    )?;
    if !comparison.mismatches.is_empty() && case.claim_evidence.is_some() {
        retain_divergence_profile_observations(identities, case, observation_root)?;
    }
    if !comparison.mismatches.is_empty() && mismatches.len() < FAILURE_CAP {
        let mismatch_path = mismatch_root.join(case.id.as_ref());
        evidence_io(
            &format!("retain differential mismatch for case {} at", case.id),
            &mismatch_path,
            retain_mismatch_bundle(mismatch_root, case, &comparison),
        )?;
    }
    let explanation = expected_mismatches.get(case.id.as_ref());
    let outcome = CaseOutcome {
        timed_out: comparison.oracle.timed_out || comparison.candidate.timed_out,
        agrees: comparison.agrees(),
        reviewed_deliberate_divergence: !comparison.mismatches.is_empty()
            && explanation.is_some_and(|value| !value.trim().is_empty()),
        resource_failures: comparison
            .candidate
            .resource_audit
            .as_ref()
            .map_or(0, hell_testkit::ResourceAudit::failure_count),
    };
    for mismatch in comparison.mismatches {
        mismatches.push(ClassifiedMismatch {
            mismatch,
            classification: explanation.map(|_| DivergenceClass::DeliberateDivergence),
            explanation: explanation.map_or_else(|| "".into(), |value| value.clone().into()),
        });
    }
    Ok(outcome)
}

fn retain_divergence_profile_observations(
    identities: &NightlyIdentities,
    case: &DifferentialCase,
    observation_root: &Path,
) -> Result<(), SuiteFailure> {
    let artifact_root = observation_root
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| SuiteFailure::fixture("observation root has no native artifact root"))?;
    let profile_root = artifact_root
        .join("divergence-objective")
        .join(case.id.as_ref())
        .join("profiles");
    for profile in [ExecutionProfile::Upstream, ExecutionProfile::Sandboxed] {
        let mut profile_case = case.clone();
        let descriptor = profile_case
            .claim_evidence
            .as_mut()
            .ok_or_else(|| SuiteFailure::fixture("profile experiment case is not reviewed"))?;
        descriptor.profile = profile;
        let verified =
            observe_verified_executable_profile(&identities.candidate, &profile_case, profile)
                .map_err(|error| {
                    SuiteFailure::fixture(format!(
                        "cannot observe case {:?} under {} profile: {error}",
                        case.id,
                        profile.as_str()
                    ))
                })?;
        let directory = profile_root.join(profile.as_str());
        retain_verified_profile_observation(&directory, &profile_case, &verified).map_err(
            |error| {
                SuiteFailure::fixture(format!(
                    "cannot retain case {:?} under {} profile: {error}",
                    case.id,
                    profile.as_str()
                ))
            },
        )?;
    }
    Ok(())
}

fn missing_claim_evidence() -> usize {
    hell_builtins::compatibility_claims()
        .iter()
        .flat_map(|claim| claim.dimensions.iter())
        .flat_map(|dimension| dimension.scopes.iter())
        .filter(|scope| {
            scope
                .profiles
                .contains(&hell_builtins::ExecutionProfile::Upstream)
        })
        .filter(|scope| {
            scope.status == ClaimStatus::Unverified
                || !matches!(scope.status, ClaimStatus::NotApplicable) && scope.evidence.is_empty()
        })
        .count()
}

fn unverified_out_of_scope_claims(required_profiles: &[hell_builtins::ExecutionProfile]) -> usize {
    hell_builtins::compatibility_claims()
        .iter()
        .flat_map(|claim| claim.dimensions.iter())
        .flat_map(|dimension| dimension.scopes.iter())
        .filter(|scope| scope.status == ClaimStatus::Unverified)
        .flat_map(|scope| scope.profiles.iter())
        .filter(|profile| !required_profiles.contains(profile))
        .count()
}

fn required_platform_skips(root: &Path) -> usize {
    oracle_record::load_all(root).map_or(promotion_policy::RequiredPlatform::ALL.len(), |records| {
        oracle_record::state_without_shards(&records).unavailable
    })
}

pub fn failures_directory(report_path: &Path) -> PathBuf {
    report_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("failures")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use hell_testkit::write_native_environment_record;

    use super::*;

    static SANDBOX_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

    struct TestSandbox {
        path: PathBuf,
    }

    impl TestSandbox {
        fn create(name: &str) -> Self {
            let sequence = SANDBOX_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "hell-ci-suite-{name}-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self { path }
        }
    }

    impl Drop for TestSandbox {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn repository_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
    }

    fn test_native_environment(root: &Path) -> NativeExecutionEnvironment {
        let values = [
            None,
            None,
            Some("release"),
            Some("true"),
            Some("true"),
            Some("ubuntu24"),
            Some("20260801.1"),
            Some("X64"),
            Some("github-hosted"),
            Some("Linux"),
            None,
        ];
        NativeExecutionEnvironment::new(&NativeExecutionEnvironmentInputs {
            runner_kind: "github-actions",
            runner_os: "Linux",
            runner_arch: "X64",
            image_os: "ubuntu24",
            image_version: "20260801.1",
            collected_at: "2026-08-10T00:00:00Z",
            rust_toolchain_selection_sha256: sha256_file(&root.join("rust-toolchain.toml"))
                .unwrap(),
            rustc_identity: "rustc 1.97.1 | binary: rustc | commit-hash: test | host: x86_64-unknown-linux-gnu",
            rustc_executable_sha256: sha256_bytes(b"rustc-executable"),
            rustc_executable_path_sha256: sha256_bytes(b"rustc-path"),
            cargo_identity: "cargo 1.97.1 | release: 1.97.1 | host: x86_64-unknown-linux-gnu",
            environment_values: &values,
        })
    }

    fn linux_summary(root: &Path, claim_index_sha256: &str) -> String {
        let assurance_epoch = crate::assurance::epoch(root).unwrap().1.hex();
        let corpus = current_corpus_identity();
        let environment = test_native_environment(root);
        format!(
            concat!(
                "{{\n",
                "  \"schemaVersion\": 3,\n",
                "  \"shardIndex\": 0,\n",
                "  \"shardCount\": 1,\n",
                "  \"observationBundleSchemaVersion\": 4,\n",
                "  \"claimIndexSchemaVersion\": 3,\n",
                "  \"oracleRecordSchemaVersion\": 2,\n",
                "  \"platform\": \"linux-x86_64\",\n",
                "  \"runnerOs\": \"{}\",\n",
                "  \"runnerArch\": \"{}\",\n",
                "  \"collectedAt\": \"{}\",\n",
                "  \"runnerImageIdentitySha256\": \"{}\",\n",
                "  \"rustToolchainSha256\": \"{}\",\n",
                "  \"buildEnvironmentSha256\": \"{}\",\n",
                "  \"oracleSha256\": \"5ccc78e62200eb5aea8b9da9161334c61848d0d3e7de2f270929920cfbf357c9\",\n",
                "  \"oracleAcquisitionReceiptId\": null,\n",
                "  \"oracleAcquisitionReceiptSha256\": null,\n",
                "  \"oracleAcquisitionAttestationSha256\": null,\n",
                "  \"candidateSha256\": \"{}\",\n",
                "  \"assuranceEpochSha256\": \"{}\",\n",
                "  \"corpusSeed\": {},\n",
                "  \"committedDifferentialObservations\": {},\n",
                "  \"generatedDifferentialObservations\": {},\n",
                "  \"corpusSha256\": \"{}\",\n",
                "  \"reviewedCommittedCorpusSha256\": \"{}\",\n",
                "  \"generatedStressCorpusSha256\": \"{}\",\n",
                "  \"promotionPolicySha256\": \"{}\",\n",
                "  \"reviewedCorpusCatalogSha256\": \"catalog\",\n",
                "  \"promotionReviewSha256\": \"review\",\n",
                "  \"mismatches\": 0,\n",
                "  \"reviewedExpectedDivergences\": 0,\n",
                "  \"unexpectedTimeouts\": 0,\n",
                "  \"staleExactClaims\": 0,\n",
                "  \"irrelevantClaimReferences\": 0,\n",
                "  \"profileEvidenceMismatches\": 0,\n",
                "  \"platformEvidenceMismatches\": 0,\n",
                "  \"normalizerEvidenceMismatches\": 0,\n",
                "  \"failedClaimObservations\": 0,\n",
                "  \"missingEvidenceReferences\": {},\n",
                "  \"unverifiedOutOfScopeClaims\": {},\n",
                "  \"requiredProfiles\": [\"upstream\"],\n",
                "  \"compatibilitySnapshotSha256\": \"snapshot\",\n",
                "  \"claimEvidenceIndexSha256\": \"{}\",\n",
                "  \"dependencyLockSha256\": \"lock\",\n",
                "  \"dependencyPolicyAttestationSha256\": \"attestation\",\n",
                "  \"expectedMismatchManifestSha256\": \"mismatches\",\n",
                "  \"repositoryPolicyPassed\": true,\n",
                "  \"requiredPlatformSkips\": {},\n",
                "  \"leakedResources\": 0,\n",
                "  \"dependencyFailures\": 0,\n",
                "  \"promotionReady\": false\n",
                "}}\n"
            ),
            environment.runner_os,
            environment.runner_arch,
            environment.collected_at,
            environment.runner_image_identity_sha256.hex(),
            environment.rust_toolchain_sha256.hex(),
            environment.build_environment_sha256.hex(),
            sha256_bytes(b"candidate").hex(),
            assurance_epoch,
            corpus.seed,
            corpus.committed_count,
            corpus.generated_count,
            corpus.corpus_sha256.hex(),
            corpus.reviewed_committed_corpus_sha256.hex(),
            corpus.generated_stress_corpus_sha256.hex(),
            hell_builtins::PROMOTION_POLICY_SHA256,
            missing_claim_evidence(),
            unverified_out_of_scope_claims(&[hell_builtins::ExecutionProfile::Upstream]),
            claim_index_sha256,
            required_platform_skips(root),
        )
    }

    fn write_linux_summary(root: &Path, input: &Path, claim_index_sha256: &str) -> PathBuf {
        let directory = input.join("linux-amd64");
        fs::create_dir_all(&directory).unwrap();
        write_native_environment_record(&directory, &test_native_environment(root)).unwrap();
        let summary = linux_summary(root, claim_index_sha256);
        fs::write(directory.join("summary.json"), &summary).unwrap();
        let digest = sha256_bytes(summary.as_bytes()).hex();
        fs::write(
            directory.join("summary.sha256"),
            format!("{digest}  summary.json\n"),
        )
        .unwrap();
        directory
    }

    #[test]
    fn native_summary_rejects_extra_duplicate_and_regenerated_corpus_substitutions() {
        let summary = linux_summary(&repository_root(), "claim-index");
        let expected = current_corpus_identity();
        let parsed = StrictNativeSummary::parse(&summary).unwrap();
        validate_current_corpus_summary(&parsed, &expected).unwrap();
        let sandbox = TestSandbox::create("strict-native-summary");
        write_test_native_summary(&sandbox.path, &summary);
        verify_retained_native_summary(&sandbox.path).unwrap();

        let extra = summary.replace(
            "  \"promotionReady\": false\n}\n",
            "  \"promotionReady\": false,\n  \"extra\": 0\n}\n",
        );
        assert!(StrictNativeSummary::parse(&extra).is_err());
        let duplicate = summary.replace(
            "  \"schemaVersion\": 3,\n",
            "  \"schemaVersion\": 3,\n  \"schemaVersion\": 3,\n",
        );
        assert!(StrictNativeSummary::parse(&duplicate).is_err());
        for structural in [&extra, &duplicate] {
            write_test_native_summary(&sandbox.path, structural);
            assert!(verify_retained_native_summary(&sandbox.path).is_err());
        }

        for substituted in [
            summary.replace(
                &format!("  \"corpusSeed\": {},", expected.seed),
                &format!("  \"corpusSeed\": {},", expected.seed + 1),
            ),
            summary.replace(
                &format!(
                    "  \"generatedDifferentialObservations\": {},",
                    expected.generated_count
                ),
                "  \"generatedDifferentialObservations\": 1023,",
            ),
            summary.replace(
                &expected.generated_stress_corpus_sha256.hex(),
                &sha256_bytes(b"forged generated corpus").hex(),
            ),
            summary.replace(
                &expected.corpus_sha256.hex(),
                &sha256_bytes(b"forged combined corpus").hex(),
            ),
        ] {
            let parsed = StrictNativeSummary::parse(&substituted).unwrap();
            assert!(validate_current_corpus_summary(&parsed, &expected).is_err());
            write_test_native_summary(&sandbox.path, &substituted);
            assert!(verify_retained_native_summary(&sandbox.path).is_err());
        }
    }

    #[test]
    fn native_environment_rejects_identity_presence_and_summary_substitutions() {
        let root = repository_root();
        let sandbox = TestSandbox::create("strict-native-environment");
        let environment = test_native_environment(&root);
        write_native_environment_record(&sandbox.path, &environment).unwrap();
        let facts = verify_retained_native_environment(&sandbox.path).unwrap();
        assert_eq!(facts.runner_kind, "github-actions");
        assert_eq!(facts.image_os, "ubuntu24");
        assert!(facts.environment_variables[5].present);
        assert!(facts.rustc_identity.starts_with("rustc 1.97.1"));

        let record_path = sandbox.path.join("native-environment.json");
        let original = fs::read_to_string(&record_path).unwrap();
        fs::write(&record_path, original.replace("ubuntu24", "ubuntu25")).unwrap();
        assert!(verify_retained_native_environment(&sandbox.path).is_err());
        fs::write(
            &record_path,
            original.replace("rustc 1.97.1", "rustc 1.97.2"),
        )
        .unwrap();
        assert!(verify_retained_native_environment(&sandbox.path).is_err());
        fs::write(
            &record_path,
            original.replace("cargo 1.97.1", "cargo 1.97.2"),
        )
        .unwrap();
        assert!(verify_retained_native_environment(&sandbox.path).is_err());
        fs::write(
            &record_path,
            original.replace("\n}\n", ",\n  \"extra\": 0\n}\n"),
        )
        .unwrap();
        assert!(verify_retained_native_environment(&sandbox.path).is_err());

        let missing_image_values = [
            None,
            None,
            Some("release"),
            Some("true"),
            Some("true"),
            None,
            Some("20260801.1"),
            Some("X64"),
            Some("github-hosted"),
            Some("Linux"),
            None,
        ];
        let missing_image = NativeExecutionEnvironment::new(&NativeExecutionEnvironmentInputs {
            runner_kind: "github-actions",
            runner_os: "Linux",
            runner_arch: "X64",
            image_os: "ubuntu24",
            image_version: "20260801.1",
            collected_at: "2026-08-10T00:00:00Z",
            rust_toolchain_selection_sha256: facts.rust_toolchain_selection_sha256,
            rustc_identity: &facts.rustc_identity,
            rustc_executable_sha256: facts.rustc_executable_sha256,
            rustc_executable_path_sha256: facts.rustc_executable_path_sha256,
            cargo_identity: &facts.cargo_identity,
            environment_values: &missing_image_values,
        });
        write_native_environment_record(&sandbox.path, &missing_image).unwrap();
        assert!(verify_retained_native_environment(&sandbox.path).is_err());

        let summary = linux_summary(&root, "claim-index");
        write_test_native_summary(&sandbox.path, &summary);
        let changed = summary.replace("  \"runnerOs\": \"Linux\",", "  \"runnerOs\": \"Windows\",");
        write_test_native_summary(&sandbox.path, &changed);
        assert!(verify_retained_native_summary(&sandbox.path).is_err());
    }

    fn write_test_native_summary(directory: &Path, summary: &str) {
        write_native_environment_record(directory, &test_native_environment(&repository_root()))
            .unwrap();
        fs::write(directory.join("summary.json"), summary).unwrap();
        fs::write(
            directory.join("summary.sha256"),
            format!("{}  summary.json\n", sha256_bytes(summary.as_bytes()).hex()),
        )
        .unwrap();
    }

    #[test]
    fn oracle_build_record_rejects_truncation_count_digest_and_extra_field_substitutions() {
        let sandbox = TestSandbox::create("strict-oracle-build");
        let provenance = sandbox.path.join("provenance");
        fs::create_dir(&provenance).unwrap();
        fs::write(provenance.join("resolver.lock"), b"resolver").unwrap();
        fs::write(provenance.join("platform.txt"), b"platform").unwrap();
        for prefix in ["source-tree", "stack", "compiler", "dependencies", "build"] {
            fs::write(provenance.join(format!("{prefix}.stdout")), b"out").unwrap();
            fs::write(provenance.join(format!("{prefix}.stderr")), b"err").unwrap();
        }
        let source_tree = test_command_result(b"out", b"err");
        let stack = test_command_result(b"out", b"err");
        let compiler = test_command_result(b"out", b"err");
        let dependencies = test_command_result(b"out", b"err");
        let build = test_command_result(b"out", b"err");
        let warning_policy = oracle_build_warning_policy().unwrap();
        let record = oracle_build_record_json(
            "macos-arm64",
            "source",
            sha256_bytes(b"resolver"),
            sha256_bytes(b"binary"),
            sha256_bytes(b"platform"),
            &warning_policy,
            [
                ("sourceTree", &source_tree),
                ("stack", &stack),
                ("compiler", &compiler),
                ("dependency", &dependencies),
                ("build", &build),
            ],
        );
        assert_eq!(
            verify_oracle_build_record(&record, "macos-arm64", "source", &provenance).unwrap(),
            sha256_bytes(b"binary").hex()
        );
        for substituted in [
            record.replacen(
                "RetainedCompletely\": true",
                "RetainedCompletely\": false",
                1,
            ),
            record.replacen("StdoutBytes\": 3", "StdoutBytes\": 4", 1),
            record.replacen(
                &sha256_bytes(b"out").hex(),
                &sha256_bytes(b"forged").hex(),
                1,
            ),
            record.replace("\n}\n", ",\n  \"extra\": 0\n}\n"),
        ] {
            assert!(
                verify_oracle_build_record(&substituted, "macos-arm64", "source", &provenance)
                    .is_err()
            );
        }
        for finding in [
            b"Warning: retained build warning\n".as_slice(),
            b"using an unpinned source without a warning prefix\n".as_slice(),
        ] {
            fs::write(provenance.join("build.stderr"), finding).unwrap();
            let warning_build = test_command_result(b"out", finding);
            let warning_record = oracle_build_record_json(
                "macos-arm64",
                "source",
                sha256_bytes(b"resolver"),
                sha256_bytes(b"binary"),
                sha256_bytes(b"platform"),
                &warning_policy,
                [
                    ("sourceTree", &source_tree),
                    ("stack", &stack),
                    ("compiler", &compiler),
                    ("dependency", &dependencies),
                    ("build", &warning_build),
                ],
            );
            assert!(
                verify_oracle_build_record(&warning_record, "macos-arm64", "source", &provenance,)
                    .is_err()
            );
        }
    }

    #[test]
    fn collection_native_dependency_identity_is_rederived_from_retained_build_streams() {
        let sandbox = TestSandbox::create("collection-native-dependency");
        let provenance = sandbox.path.join("provenance");
        fs::create_dir(&provenance).unwrap();
        let repository = repository_root();
        fs::copy(
            repository.join("compat/oracle-sources/hell-8e952cf9/stack.yaml.lock"),
            provenance.join("resolver.lock"),
        )
        .unwrap();
        fs::write(provenance.join("stack.stdout"), b"3.11.1\n").unwrap();
        fs::write(
            provenance.join("compiler.stdout"),
            b"[(\"Project name\",\"GHC\"),(\"Project version\",\"9.8.2\")]\n",
        )
        .unwrap();
        fs::write(
            provenance.join("dependencies.stdout"),
            b"base 4.19.1.0\ncontainers 0.6.8\nhell 0.1.0\n",
        )
        .unwrap();
        verify_collection_native_dependency_identity(&provenance).unwrap();

        for (relative, bytes) in [
            ("stack.stdout", b"3.11.0\n".as_slice()),
            (
                "compiler.stdout",
                b"[(\"Project version\",\"9.10.3\")]\n".as_slice(),
            ),
            (
                "dependencies.stdout",
                b"containers 0.6.8\ncontainers 0.6.8\n".as_slice(),
            ),
            ("dependencies.stdout", b"containers 0.7\n".as_slice()),
        ] {
            let original = fs::read(provenance.join(relative)).unwrap();
            fs::write(provenance.join(relative), bytes).unwrap();
            assert!(verify_collection_native_dependency_identity(&provenance).is_err());
            fs::write(provenance.join(relative), original).unwrap();
        }
        fs::write(provenance.join("resolver.lock"), b"substituted resolver\n").unwrap();
        assert!(verify_collection_native_dependency_identity(&provenance).is_err());
    }

    fn test_command_result(stdout: &[u8], stderr: &[u8]) -> CommandResult {
        CommandResult {
            status: test_success_status(),
            duration: Duration::ZERO,
            timed_out: false,
            stdout: stdout.to_vec(),
            stderr: stderr.to_vec(),
            stdout_truncated: false,
            stderr_truncated: false,
            stdout_bytes: u64::try_from(stdout.len()).unwrap(),
            stderr_bytes: u64::try_from(stderr.len()).unwrap(),
            stdout_sha256: sha256_bytes(stdout),
            stderr_sha256: sha256_bytes(stderr),
        }
    }

    #[cfg(unix)]
    fn test_success_status() -> std::process::ExitStatus {
        use std::os::unix::process::ExitStatusExt as _;
        std::process::ExitStatus::from_raw(0)
    }

    #[cfg(windows)]
    fn test_success_status() -> std::process::ExitStatus {
        use std::os::windows::process::ExitStatusExt as _;
        std::process::ExitStatus::from_raw(0)
    }

    #[test]
    fn promotion_candidates_remain_unverified_until_native_evidence_is_retained() {
        let cases = committed_differential_cases()
            .into_iter()
            .map(|case| case.id)
            .collect::<BTreeSet<_>>();
        assert!(cases.len() >= 12, "promotion corpus must be non-vacuous");
        assert!(
            hell_builtins::compatibility_claims()
                .iter()
                .flat_map(|claim| claim.dimensions.iter())
                .flat_map(|dimension| dimension.scopes.iter())
                .all(|scope| scope.status == ClaimStatus::Unverified),
            "native shard artifacts must be retained before claim promotion"
        );
    }

    #[test]
    fn exploratory_generation_remains_available_before_promotion_completeness() {
        let committed = committed_differential_cases();
        validate_exploratory_corpus(&committed).unwrap();
        let incomplete = validate_runtime_obligation_coverage(&committed)
            .expect_err("promotion completeness must remain fail-closed");
        assert!(
            incomplete.contains("134 incomplete cells, 14 boundary gaps, and 0 interaction gaps"),
            "{incomplete}"
        );

        let generated = generated_typed_cases(0x4845_4c4c_2026, 1_024);
        assert_eq!(generated.len(), 1_024);
        assert!(generated.iter().all(|case| !case.source.is_empty()));
    }

    #[test]
    fn generated_mismatch_proposals_remain_unreviewed_and_claim_ineligible() {
        let sandbox = TestSandbox::create("generated-regression-proposal");
        let generated = generated_typed_cases(0x4845_4c4c_2026, 1)
            .into_iter()
            .next()
            .unwrap();
        let executable = std::env::current_exe().unwrap();
        let identity = |path: PathBuf, role| ExecutableIdentity {
            sha256: sha256_file(&path).unwrap(),
            path,
            reported_version: hell_builtins::LANGUAGE_VERSION.into(),
            build_info: None,
            role,
            assurance_epoch_sha256: None,
            acquisition_receipt_id: None,
            acquisition_receipt_sha256: None,
            acquisition_attestation_sha256: None,
        };
        let identities = NightlyIdentities {
            oracle: identity(executable.clone(), ExecutableRole::Oracle),
            candidate: identity(executable, ExecutableRole::Candidate),
        };
        retain_generated_regression_proposal(&sandbox.path, &generated, &identities).unwrap();
        let document = fs::read_to_string(
            sandbox
                .path
                .join("mismatches")
                .join("proposed-regressions")
                .join(format!("{}.json", generated.id)),
        )
        .unwrap();
        assert!(document.contains("\"minimizationStatus\": \"pending\""));
        assert!(document.contains("\"reviewState\": \"unreviewed\""));
        assert!(document.contains("\"claimEligible\": false"));
        assert!(document.contains(generated.ast_sha256.hex().as_str()));
        assert!(document.contains(sha256_bytes(generated.source.as_bytes()).hex().as_str()));
    }

    #[test]
    fn promotion_worklist_uses_per_cell_catalog_metadata() {
        let sandbox = TestSandbox::create("catalog-worklist");
        let output = sandbox.path.join("worklist.json");
        let mut report = Report::new("promotion-worklist");
        promotion_worklist(
            &repository_root(),
            &output,
            "upstream",
            "json",
            "all",
            "builtin",
            &mut report,
        )
        .unwrap();
        assert!(report.passed());
        let document = fs::read_to_string(output).unwrap();
        let bool_row = document
            .split("\n    }")
            .find(|row| {
                row.contains("\"builtin\": \"Bool.bool\"")
                    && row.contains("\"dimension\": \"pure-runtime\"")
            })
            .unwrap();
        assert!(!bool_row.contains("\"required_obligations\": \"ordinary-success\""));
        assert!(bool_row.contains("\"applicability_rule\": \"implemented-runtime-adapter\""));
        assert!(bool_row.contains("\"review_group\": \"bool-conditional-v1\""));
    }

    #[test]
    fn unreviewed_claims_are_recorded_without_becoming_collection_failures() {
        let missing = missing_claim_evidence();
        assert_eq!(missing, 2_840);
        let gate = evaluate_release_gate(
            &ReleaseGateInput {
                differential_observations: 1_024,
                candidate_stress_cases: 0,
                harness_failures: 0,
                unexpected_timeouts: 0,
                mismatches: &[],
                stale_exact_claims: 0,
                missing_evidence_references: missing,
                required_platform_skips: 2,
                leaked_resources: 0,
                dependency_failures: 0,
            },
            1_024,
        );
        assert!(gate.collection_passed());
        assert!(!gate.promotion_ready());
    }

    #[test]
    fn native_merge_is_mechanical_evidence_and_never_promotion_ready() {
        assert!(!native_merge_promotion_ready());
    }

    #[test]
    fn stack_build_uses_the_pinned_lock_without_cabal_flags() {
        let spec = stack_oracle_build_command(
            &Path::new("upstream").join("stack.yaml"),
            &Path::new("artifacts").join("oracle"),
        );
        assert!(spec.current_directory.is_none());
        assert_eq!(
            spec.display_arguments(),
            [
                "--stack-yaml",
                "upstream/stack.yaml",
                "--lock-file",
                "error-on-write",
                "build",
                "--install-ghc",
                "--copy-bins",
                "--local-bin-path",
                "artifacts/oracle",
            ]
        );
    }

    #[test]
    fn identity_failure_detail_is_retained_in_the_structured_report() {
        let mut report = Report::new("native-oracle-shard");
        let result = checked_suite_result::<()>(
            &mut report,
            "oracle-identities",
            Instant::now(),
            Err(SuiteFailure::fixture(
                "candidate identity has no build-info payload",
            )),
        );
        assert_eq!(result, Err(FailureKind::Fixture));
        assert!(report.failures.iter().any(|failure| {
            failure.contains("oracle-identities")
                && failure.contains("candidate identity has no build-info payload")
        }));
    }

    #[test]
    fn merge_reports_missing_summary_path_and_io_error() {
        let sandbox = TestSandbox::create("missing-summary");
        let root = repository_root();
        let summary = sandbox.path.join("linux-amd64").join("summary.json");
        let mut report = Report::new("merge-native-shards");
        let result = merge_native_shards(&root, &sandbox.path, &mut report);
        assert_eq!(result, Err(FailureKind::Io));
        assert!(report.failures.iter().any(|failure| {
            failure.contains("merge-linux-amd64")
                && failure.contains("cannot read")
                && failure.contains(&summary.display().to_string())
        }));
    }

    #[test]
    fn merge_reports_an_empty_summary_digest() {
        let sandbox = TestSandbox::create("empty-summary-digest");
        let root = repository_root();
        let directory = write_linux_summary(&root, &sandbox.path, "unused");
        let digest_path = directory.join("summary.sha256");
        fs::write(&digest_path, b"").unwrap();
        let mut report = Report::new("merge-native-shards");
        let result = merge_native_shards(&root, &sandbox.path, &mut report);
        assert_eq!(result, Err(FailureKind::Fixture));
        assert!(report.failures.iter().any(|failure| {
            failure.contains("merge-linux-amd64")
                && failure.contains("summary digest record")
                && failure.contains("is noncanonical or does not match")
                && failure.contains(&digest_path.display().to_string())
        }));
    }

    #[test]
    fn merge_reports_missing_claim_index_identity_field() {
        let sandbox = TestSandbox::create("missing-claim-field");
        let root = repository_root();
        let assurance_epoch = crate::assurance::epoch(&root).unwrap().1.hex();
        let claim_contents = format!(
            concat!(
                "{{\n",
                "  \"schemaVersion\": 3,\n",
                "  \"compatibilitySnapshotSha256\": \"snapshot\",\n",
                "  \"assuranceEpochSha256\": \"{}\",\n",
                "  \"promotionPolicySha256\": \"{}\",\n",
                "  \"reviewedCorpusCatalogSha256\": \"catalog\",\n",
                "  \"oracleSha256\": \"oracle\",\n",
                "  \"candidateSha256\": \"{}\",\n",
                "  \"platform\": \"linux-amd64\",\n",
                "  \"profile\": \"upstream\",\n",
                "  \"indexedEntries\": 0,\n",
                "  \"missingBundles\": 0,\n",
                "  \"irrelevantReferences\": 0,\n",
                "  \"profileMismatches\": 0,\n",
                "  \"platformMismatches\": 0,\n",
                "  \"normalizerMismatches\": 0,\n",
                "  \"failedObservations\": 0,\n",
                "  \"entries\": [\n",
                "  ]\n",
                "}}\n"
            ),
            assurance_epoch,
            hell_builtins::PROMOTION_POLICY_SHA256,
            sha256_bytes(b"candidate").hex(),
        );
        let claim_digest = sha256_bytes(claim_contents.as_bytes()).hex();
        let directory = write_linux_summary(&root, &sandbox.path, &claim_digest);
        let claim_path = directory.join("evidence").join("claim-index.json");
        fs::create_dir_all(claim_path.parent().unwrap()).unwrap();
        fs::write(&claim_path, &claim_contents).unwrap();
        let mut report = Report::new("merge-native-shards");
        let result = merge_native_shards(&root, &sandbox.path, &mut report);
        assert_eq!(result, Err(FailureKind::Fixture));
        assert!(
            report.failures.iter().any(|failure| {
                failure.contains("merge-linux-amd64")
                    && failure.contains("candidateSourceCommit")
                    && failure.contains(&claim_path.display().to_string())
            }),
            "unexpected merge failures: {:?}",
            report.failures
        );
    }

    #[test]
    fn retention_io_failure_preserves_operation_path_and_error() {
        let sandbox = TestSandbox::create("retention-io");
        let blocker = sandbox.path.join("not-a-directory");
        fs::write(&blocker, b"block").unwrap();
        let target = blocker.join("summary.json");
        let failure = evidence_io(
            "retain evidence summary",
            &target,
            fs::write(&target, b"evidence"),
        )
        .unwrap_err();
        assert_eq!(failure.kind, FailureKind::Io);
        assert!(failure.detail.contains("retain evidence summary"));
        assert!(failure.detail.contains(&target.display().to_string()));
        assert!(failure.detail.len() > "cannot retain evidence summary".len());
    }

    #[test]
    fn dependency_attestation_is_bound_to_candidate_and_lockfile() {
        let sandbox = TestSandbox::create("dependency-attestation");
        let input = sandbox.path.join("dependency-policy.json");
        let artifact_root = sandbox.path.join("artifact");
        let lock_digest = sha256_bytes(b"lockfile");
        let source_commit = hell_builtins::UPSTREAM_COMMIT;
        let contents = dependency_attestation_json(source_commit, lock_digest);
        fs::write(&input, &contents).unwrap();
        let digest = sha256_bytes(contents.as_bytes()).hex();
        fs::write(
            input.with_extension("sha256"),
            format!("{digest}  dependency-policy.json\n"),
        )
        .unwrap();
        let candidate = ExecutableIdentity {
            path: PathBuf::from("candidate"),
            sha256: Digest::default(),
            reported_version: hell_builtins::LANGUAGE_VERSION.into(),
            build_info: Some(hell_testkit::BuildInfo {
                lines: vec![format!("source commit {source_commit}").into()].into(),
            }),
            role: hell_testkit::ExecutableRole::Candidate,
            assurance_epoch_sha256: None,
            acquisition_receipt_id: None,
            acquisition_receipt_sha256: None,
            acquisition_attestation_sha256: None,
        };
        assert!(
            retain_dependency_attestation(
                &repository_root(),
                &input,
                &artifact_root,
                lock_digest,
                &candidate,
            )
            .is_ok()
        );
        fs::write(&input, contents.replace("\"passed\"", "\"failed\"")).unwrap();
        assert!(
            retain_dependency_attestation(
                &repository_root(),
                &input,
                &artifact_root,
                lock_digest,
                &candidate,
            )
            .is_err()
        );
    }

    #[test]
    fn claim_index_rejects_malformed_and_wrong_profile_entries() {
        assert!(
            validate_claim_index_contents(
                "{\n  \"indexedEntries\": 0\n}\n",
                Path::new("unused"),
                "linux-amd64"
            )
            .is_err()
        );
        let malformed = concat!(
            "{\n",
            "  \"indexedEntries\": 1,\n",
            "  \"entries\": [\n",
            "    { \"unexpected\": true }\n",
            "  ]\n",
            "}\n"
        );
        assert!(
            validate_claim_index_contents(malformed, Path::new("unused"), "linux-amd64").is_err()
        );
        let wrong_profile = concat!(
            "{\n",
            "  \"indexedEntries\": 1,\n",
            "  \"entries\": [\n",
            "    { \"builtin\": \"unused\", \"dimension\": \"parse\", \"status\": \"exact\", \"profile\": \"sandboxed\", \"platform\": \"linux-amd64\" }\n",
            "  ]\n",
            "}\n"
        );
        assert!(
            validate_claim_index_contents(wrong_profile, Path::new("unused"), "linux-amd64")
                .is_err()
        );
    }

    #[test]
    fn claim_index_wrapper_rejects_duplicate_extra_and_reordered_fields() {
        let canonical = concat!(
            "{\n",
            "  \"schemaVersion\": 3,\n",
            "  \"compatibilitySnapshotSha256\": \"snapshot\",\n",
            "  \"assuranceEpochSha256\": \"epoch\",\n",
            "  \"promotionPolicySha256\": \"policy\",\n",
            "  \"reviewedCorpusCatalogSha256\": \"catalog\",\n",
            "  \"oracleSha256\": \"oracle\",\n",
            "  \"candidateSha256\": \"candidate\",\n",
            "  \"candidateSourceCommit\": \"commit\",\n",
            "  \"platform\": \"linux-amd64\",\n",
            "  \"profile\": \"upstream\",\n",
            "  \"indexedEntries\": 0,\n",
            "  \"missingBundles\": 0,\n",
            "  \"irrelevantReferences\": 0,\n",
            "  \"profileMismatches\": 0,\n",
            "  \"platformMismatches\": 0,\n",
            "  \"normalizerMismatches\": 0,\n",
            "  \"failedObservations\": 0,\n",
            "  \"entries\": [\n",
            "  ]\n",
            "}\n",
        );
        let parsed = StrictClaimIndex::parse(canonical).unwrap();
        assert_eq!(parsed.indexed_entries, 0);
        for substituted in [
            canonical.replace(
                "  \"profile\": \"upstream\",\n",
                "  \"profile\": \"upstream\",\n  \"profile\": \"upstream\",\n",
            ),
            canonical.replace(
                "  \"entries\": [\n",
                "  \"decorative\": true,\n  \"entries\": [\n",
            ),
            canonical.replace(
                concat!(
                    "  \"compatibilitySnapshotSha256\": \"snapshot\",\n",
                    "  \"assuranceEpochSha256\": \"epoch\",\n",
                ),
                concat!(
                    "  \"assuranceEpochSha256\": \"epoch\",\n",
                    "  \"compatibilitySnapshotSha256\": \"snapshot\",\n",
                ),
            ),
        ] {
            assert!(StrictClaimIndex::parse(&substituted).is_err());
        }
    }

    #[test]
    fn executable_identity_semantics_reject_path_version_and_build_info_substitutions() {
        let source_commit = "0123456789012345678901234567890123456789";
        let epoch = sha256_bytes(b"epoch").hex();
        let candidate = StrictExecutableIdentity {
            schema_version: 3,
            role: "Candidate".to_owned(),
            path: "/retained/bin/hell".to_owned(),
            sha256: sha256_bytes(b"candidate").hex(),
            reported_version: hell_builtins::LANGUAGE_VERSION.to_owned(),
            assurance_epoch_sha256: Some(epoch.clone()),
            acquisition_receipt_id: None,
            acquisition_receipt_sha256: None,
            acquisition_attestation_sha256: None,
            build_info: Some(expected_candidate_build_info(source_commit)),
        };
        assert!(
            validate_executable_identity_semantics(
                &candidate,
                "Candidate",
                "linux-amd64",
                source_commit,
                &epoch,
            )
            .is_ok()
        );
        let mut substitutions = Vec::new();
        let mut wrong_path = candidate.clone();
        wrong_path.path = "/retained/bin/not-hell".to_owned();
        substitutions.push(wrong_path);
        let mut wrong_version = candidate.clone();
        wrong_version.reported_version.push_str("-decorative");
        substitutions.push(wrong_version);
        let mut wrong_build_info = candidate.clone();
        wrong_build_info.build_info.as_mut().unwrap().swap(0, 1);
        substitutions.push(wrong_build_info);
        let mut wrong_policy = candidate.clone();
        wrong_policy
            .build_info
            .as_mut()
            .unwrap()
            .last_mut()
            .unwrap()
            .push_str("-decorative");
        substitutions.push(wrong_policy);
        for substituted in substitutions {
            assert!(
                validate_executable_identity_semantics(
                    &substituted,
                    "Candidate",
                    "linux-amd64",
                    source_commit,
                    &epoch,
                )
                .is_err()
            );
        }
        assert!(canonical_identity_path(
            r"C:\retained\bin\hell.exe",
            "windows-amd64"
        ));
        assert!(!canonical_identity_path(
            r"C:\retained\..\bin\hell.exe",
            "windows-amd64"
        ));
    }

    #[test]
    fn deliberate_divergence_requires_reviewed_expected_mismatch_evidence() {
        let unexplained = CaseOutcome {
            agrees: false,
            reviewed_deliberate_divergence: false,
            ..CaseOutcome::default()
        };
        assert!(!outcome_supports_claim_status(
            unexplained,
            ClaimStatus::DeliberateDivergence
        ));
        let reviewed = CaseOutcome {
            reviewed_deliberate_divergence: true,
            ..unexplained
        };
        assert!(outcome_supports_claim_status(
            reviewed,
            ClaimStatus::DeliberateDivergence
        ));
        assert!(!outcome_supports_claim_status(reviewed, ClaimStatus::Exact));
    }

    #[test]
    fn nightly_step_rejects_only_unaccepted_differential_mismatches() {
        let mismatch = hell_testkit::DifferentialMismatch {
            kind: hell_testkit::MismatchKind::Stdout,
            oracle: b"oracle".to_vec(),
            candidate: b"candidate".to_vec(),
        };
        let reviewed = ClassifiedMismatch {
            mismatch: mismatch.clone(),
            classification: Some(DivergenceClass::DeliberateDivergence),
            explanation: "retained exact accepted divergence".into(),
        };
        assert_eq!(unacceptable_mismatch_count(&[reviewed]), 0);
        for changed in [
            ClassifiedMismatch {
                mismatch: mismatch.clone(),
                classification: None,
                explanation: "".into(),
            },
            ClassifiedMismatch {
                mismatch,
                classification: Some(DivergenceClass::DeliberateDivergence),
                explanation: "".into(),
            },
        ] {
            assert_eq!(unacceptable_mismatch_count(&[changed]), 1);
        }
    }

    #[test]
    fn expected_mismatch_manifest_rejects_header_tampering_and_expired_waivers() {
        let identity = |role| ExecutableIdentity {
            path: PathBuf::from("fixture"),
            sha256: sha256_bytes(match role {
                ExecutableRole::Oracle => b"oracle",
                ExecutableRole::Candidate => b"candidate",
            }),
            reported_version: hell_builtins::LANGUAGE_VERSION.into(),
            build_info: None,
            role,
            assurance_epoch_sha256: None,
            acquisition_receipt_id: None,
            acquisition_receipt_sha256: None,
            acquisition_attestation_sha256: None,
        };
        let identities = NightlyIdentities {
            oracle: identity(ExecutableRole::Oracle),
            candidate: identity(ExecutableRole::Candidate),
        };
        let valid = fs::read_to_string(
            repository_root()
                .join("compat")
                .join("expected-mismatches.toml"),
        )
        .unwrap();
        assert!(parse_expected_mismatches(&valid, &identities).is_ok());
        assert!(
            parse_expected_mismatches(&format!("{valid}unknown_top_level = true\n"), &identities)
                .is_err()
        );
        let expired = format!(
            concat!(
                "schema_version = 1\n",
                "baseline = \"2026-05-29\"\n",
                "[[entry]]\n",
                "case = \"expired-case\"\n",
                "classification = \"deliberate-divergence\"\n",
                "claim = \"unknown\"\n",
                "dimension = \"parse\"\n",
                "platform = {:?}\n",
                "profile = \"upstream\"\n",
                "oracle_sha256 = {:?}\n",
                "candidate_sha256 = {:?}\n",
                "expires = \"1970-01-01\"\n",
                "rationale = \"reviewed fixture\"\n"
            ),
            current_evidence_platform(),
            identities.oracle.sha256.hex(),
            identities.candidate.sha256.hex(),
        );
        let error = parse_expected_mismatches(&expired, &identities).unwrap_err();
        assert!(error.contains("expired"));
    }

    fn collection_provider_root_fixture(
        platform: &str,
    ) -> crate::assurance::VerifiedCollectionProviderArtifact {
        let shared = sha256_bytes(b"shared provider fact");
        crate::assurance::VerifiedCollectionProviderArtifact {
            platform: platform.to_owned(),
            repository_id: 123,
            run_id: 42,
            run_attempt: 1,
            artifact_id: match platform {
                "linux-amd64" => 1,
                "macos-arm64" => 2,
                _ => 3,
            },
            workflow_ref:
                "Portfoligno/hell-rs/.github/workflows/collection-authority.yml@refs/heads/main"
                    .to_owned(),
            event: "workflow_dispatch".to_owned(),
            provider_head_commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            candidate_commit: "cccccccccccccccccccccccccccccccccccccccc".to_owned(),
            observed_at: "2026-01-01T00:00:00Z".to_owned(),
            selection_sha256: sha256_bytes(platform.as_bytes()),
            artifact_api_sha256: shared,
            job_api_sha256: shared,
            run_api_sha256: shared,
            workflow_sha256: shared,
            archive_sha256: sha256_bytes(format!("{platform} archive").as_bytes()),
            tree_sha256: sha256_bytes(format!("{platform} tree").as_bytes()),
            provider_subject_sha256: sha256_bytes(format!("{platform} subject").as_bytes()),
        }
    }

    #[test]
    fn collection_campaign_rejects_cross_platform_run_api_drift() {
        let mut providers = ["linux-amd64", "macos-arm64", "windows-amd64"]
            .map(|platform| (collection_provider_root_fixture(platform), String::new()));
        assert!(validate_collection_campaign_coherence(&providers).is_ok());
        providers[1].0.run_api_sha256 = sha256_bytes(b"different retained run bytes");
        assert!(validate_collection_campaign_coherence(&providers).is_err());
    }

    fn collection_candidate_identity(source_commit: &str) -> ExecutableIdentity {
        ExecutableIdentity {
            path: PathBuf::from("candidate"),
            sha256: sha256_bytes(b"candidate"),
            reported_version: "fixture".into(),
            build_info: Some(hell_testkit::BuildInfo {
                lines: vec![
                    format!("source commit {source_commit}").into(),
                    "compatibility evidence schema 1".into(),
                ]
                .into(),
            }),
            role: ExecutableRole::Candidate,
            assurance_epoch_sha256: None,
            acquisition_receipt_id: None,
            acquisition_receipt_sha256: None,
            acquisition_attestation_sha256: None,
        }
    }

    #[test]
    fn collection_candidate_identity_rejects_explicit_commit_substitution() {
        let candidate_commit = "cccccccccccccccccccccccccccccccccccccccc";
        let candidate = collection_candidate_identity(candidate_commit);
        assert!(validate_collection_candidate_identity(&candidate, candidate_commit).is_ok());
        assert!(
            validate_collection_candidate_identity(
                &candidate,
                "dddddddddddddddddddddddddddddddddddddddd"
            )
            .is_err()
        );
        assert!(validate_collection_candidate_identity(&candidate, "not-a-commit").is_err());
    }

    #[test]
    fn collection_subject_rejects_candidate_controlled_trusted_head() {
        let trusted = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let candidate = "cccccccccccccccccccccccccccccccccccccccc";
        let subject = format!("{{\n  \"trustedHarnessSourceCommit\": {candidate:?}\n}}\n");
        assert!(validate_collection_trusted_provider_head(&subject, trusted).is_err());
        let subject = format!("{{\n  \"trustedHarnessSourceCommit\": {trusted:?}\n}}\n");
        assert!(validate_collection_trusted_provider_head(&subject, trusted).is_ok());
    }

    #[test]
    fn collection_campaign_rejects_rehashed_trusted_helper_and_model_substitution() {
        let sandbox = TestSandbox::create("collection-trusted-harness");
        let root = repository_root();
        let input = sandbox.path.join("shard");
        let campaign = input.join("collection-evidence");
        let retained = input.join("trusted-harness");
        fs::create_dir_all(&campaign).unwrap();
        fs::create_dir_all(&retained).unwrap();
        fs::write(retained.join("hell-ci"), b"trusted driver").unwrap();
        fs::write(retained.join("hell-test-helper"), b"trusted helper").unwrap();
        fs::copy(
            root.join("compat/oracle-sources/collection-source-authority.tsv"),
            retained.join("collection-source-authority.tsv"),
        )
        .unwrap();
        fs::copy(
            root.join("crates/hell-testkit/src/reviewed_set.rs"),
            retained.join("reviewed_set.rs"),
        )
        .unwrap();
        let commit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        fs::write(
            campaign.join("campaign.json"),
            format!("{{\n  \"trustedHarnessSourceCommit\": {commit:?}\n}}\n"),
        )
        .unwrap();
        let trusted = retained_collection_trusted_harness(&root, &input, &campaign).unwrap();
        let candidate_executable = sha256_bytes(b"candidate").hex();
        let oracle_executable = sha256_bytes(b"oracle").hex();
        let inventory = sha256_bytes(b"inventory").hex();
        let expected = CollectionCampaignExpectation {
            platform: "linux-amd64",
            candidate_executable: &candidate_executable,
            oracle_executable: &oracle_executable,
            trusted: &trusted,
            inventory: &inventory,
            receipt: None,
            attestation: None,
        };
        let document = collection_campaign_manifest_document(&CollectionCampaignManifest {
            candidate_commit: "cccccccccccccccccccccccccccccccccccccccc",
            expected: &expected,
        });
        fs::write(campaign.join("campaign.json"), &document).unwrap();
        fs::write(
            campaign.join("campaign.json.sha256"),
            format!(
                "{}  campaign.json\n",
                sha256_bytes(document.as_bytes()).hex()
            ),
        )
        .unwrap();
        assert!(validate_collection_campaign_manifest(&campaign, &expected).is_ok());

        fs::write(retained.join("hell-test-helper"), b"candidate helper").unwrap();
        let substituted = retained_collection_trusted_harness(&root, &input, &campaign).unwrap();
        let substituted_expected = CollectionCampaignExpectation {
            trusted: &substituted,
            ..expected
        };
        assert!(validate_collection_campaign_manifest(&campaign, &substituted_expected).is_err());
        fs::write(retained.join("reviewed_set.rs"), b"candidate model").unwrap();
        assert!(retained_collection_trusted_harness(&root, &input, &campaign).is_err());
    }
}
