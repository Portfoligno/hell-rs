use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use hell_builtins::{ClaimStatus, CompatibilityDimension};
use hell_compiler::{CompilerConfig, CompilerSession};
use hell_source::{SourceMap, SourceName};
use hell_testkit::{
    ClassifiedMismatch, DeterministicBytes, DeterministicUtf8, DifferentialCase, Digest,
    DivergenceClass, EvidenceSummary, ExecutableIdentity, ExecutableRole, ReleaseGateInput,
    ReleaseGateReport, committed_differential_cases, differential_with_identities,
    evaluate_release_gate, generated_typed_cases, retain_mismatch_bundle,
    retain_observation_bundle, sha256_bytes, sha256_file, validate_evidence_catalog,
    verify_executable, verify_observation_bundle_for_case, write_evidence_summary,
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
            let path = root.join("compat/upstream-2026-05-29.json");
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
pub fn promotion_worklist(
    root: &Path,
    output: &Path,
    profile: &str,
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
        let mut csv = String::from(
            "builtin,visibility,scheme,arity,implementation,dimension,profile,platforms,current_status,applicability_decision,proposed_status,proposed_references,proposed_normalizers,rationale,issue,catalog_target_exists,observed_on_linux,observed_on_macos,observed_on_windows,reviewer_notes\n",
        );
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
                    let evidence = scope.evidence.join(";");
                    let normalizers = scope
                        .normalizers
                        .iter()
                        .map(|normalizer| normalizer.as_str())
                        .collect::<Vec<_>>()
                        .join(";");
                    let fields = [
                        spec.name.to_owned(),
                        format!("{:?}", spec.visibility),
                        spec.scheme.unwrap_or_default().to_owned(),
                        spec.arity.to_string(),
                        spec.implementation.unwrap_or_default().to_owned(),
                        dimension.dimension.as_str().to_owned(),
                        profile.to_owned(),
                        platforms,
                        claim_status_name(scope.status).to_owned(),
                        String::new(),
                        String::new(),
                        evidence,
                        normalizers,
                        scope.rationale.unwrap_or_default().to_owned(),
                        scope.issue.unwrap_or_default().to_owned(),
                        "false".to_owned(),
                        "false".to_owned(),
                        "false".to_owned(),
                        "false".to_owned(),
                        String::new(),
                    ];
                    csv.push_str(
                        &fields
                            .iter()
                            .map(|field| csv_field(field))
                            .collect::<Vec<_>>()
                            .join(","),
                    );
                    csv.push('\n');
                }
            }
        }
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
        }
        fs::write(output, csv)
            .map_err(|error| format!("cannot write {}: {error}", output.display()))
    })();
    let passed = result.is_ok();
    report.check("promotion-worklist", started.elapsed(), result);
    passed.then_some(()).ok_or(FailureKind::Fixture)
}

fn csv_field(field: &str) -> String {
    let escaped = field.replace('"', "\"\"");
    format!("\"{escaped}\"")
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
    let retained = artifact_root.join("evidence/dependency-policy-attestation.json");
    let retained_digest = artifact_root.join("evidence/dependency-policy-attestation.sha256");
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
    if !build_candidate(root, report, failures, "ci") {
        return Err(FailureKind::Child);
    }
    run_fixture_gates(root, report, failures, "ci")
}

pub fn portability(root: &Path, report: &mut Report, failures: &Path) -> Result<(), FailureKind> {
    if !workspace_tests(root, report, failures, "ci") {
        return Err(FailureKind::Child);
    }
    if !build_candidate(root, report, failures, "ci") {
        return Err(FailureKind::Child);
    }
    run_fixture_gates(root, report, failures, "ci")
}

pub fn nightly(
    root: &Path,
    report: &mut Report,
    failures: &Path,
    oracle: &Path,
    oracle_sha256: Digest,
    dependency_attestation: &Path,
) -> Result<(), FailureKind> {
    policy_suite(root, report)?;
    if !workspace_tests(root, report, failures, "release") {
        return Err(FailureKind::Child);
    }
    if !build_candidate(root, report, failures, "release") {
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

    let started = Instant::now();
    let identities = verify_nightly_identities(root, oracle, oracle_sha256).map_err(|detail| {
        report.check("executable-identities", started.elapsed(), Err(detail));
        FailureKind::Fixture
    })?;
    report.check("executable-identities", started.elapsed(), Ok(()));

    let started = Instant::now();
    let differential = checked_suite_result(
        report,
        "differential-evidence",
        started,
        run_differential_corpus(root, &identities, failures, dependency_attestation),
    )?;
    report.check(
        "committed-and-generated-differential",
        started.elapsed(),
        differential
            .mismatches
            .is_empty()
            .then_some(())
            .ok_or_else(|| {
                format!(
                    "{} differential mismatch(es)",
                    differential.mismatches.len()
                )
            }),
    );

    let started = Instant::now();
    let stress = deterministic_stress(failures);
    let stress_passed = stress.is_ok();
    let stress_observations = stress.as_ref().copied().unwrap_or_default();
    report.check(
        "deterministic-stress",
        started.elapsed(),
        stress.map(|_| ()),
    );
    if !stress_passed {
        return Err(FailureKind::Fixture);
    }

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
    let collection_result = gate
        .collection_passed()
        .then_some(())
        .ok_or_else(|| evidence_collection_failure(&gate, stress_observations));
    let collection_passed = collection_result.is_ok();
    report.check(
        "evidence-collection-gate",
        started.elapsed(),
        collection_result,
    );
    collection_passed.then_some(()).ok_or(FailureKind::Fixture)
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

    if !build_candidate(root, report, failures, "release") {
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
    let unacceptable_mismatches = differential
        .mismatches
        .iter()
        .filter(|mismatch| {
            mismatch.classification != Some(DivergenceClass::DeliberateDivergence)
                || mismatch.explanation.trim().is_empty()
        })
        .count();
    let passed = differential.harness_failures == 0
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
    for field in ["platformEvidenceComplete", "promotionReady"] {
        let observed = json_bool_field(&manifest, field);
        if observed != Some(true) {
            failures.push(format!("{field}={observed:?}, expected true"));
        }
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
    let promotion_policy = promotion_policy::load(root).map_err(|detail| {
        report.check("promotion-policy", started.elapsed(), Err(detail));
        FailureKind::Fixture
    })?;
    report.check("promotion-policy", started.elapsed(), Ok(()));
    let review = promotion_policy::load_review(root).map_err(|detail| {
        report.check("promotion-review", started.elapsed(), Err(detail));
        FailureKind::Fixture
    })?;
    if require_promotion {
        review.require_accepted().map_err(|detail| {
            report.check("promotion-review", started.elapsed(), Err(detail));
            FailureKind::Fixture
        })?;
    }
    report.check("promotion-review", started.elapsed(), Ok(()));
    let oracle_records = oracle_record::load_all(root).map_err(|detail| {
        report.check("reviewed-oracle-records", started.elapsed(), Err(detail));
        FailureKind::Fixture
    })?;
    report.check("reviewed-oracle-records", started.elapsed(), Ok(()));
    let mut merged = String::from("{\n  \"schemaVersion\": 2,\n  \"shards\": [\n");
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
    let current_catalog = reviewed_corpus_catalog_json(&committed_differential_cases());
    let current_catalog_sha256 = sha256_bytes(current_catalog.as_bytes()).hex();
    let mut reviewed_expected_divergences = 0_usize;
    let mut validated_shards = 0_usize;
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
        let expected_platform = format!("\"platform\": \"{host_platform}\"");
        if !summary.contains(&expected_platform) {
            return Err(merge_fixture_failure(
                report,
                label,
                started,
                &summary_path,
                format!("expected platform identity {host_platform}"),
            ));
        }
        let summary_digest = sha256_bytes(summary.as_bytes());
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
            if json_usize_field(&summary, field) != Some(0) {
                return Err(merge_fixture_failure(
                    report,
                    label,
                    started,
                    &summary_path,
                    format!("field {field} is missing, malformed, or nonzero"),
                ));
            }
        }
        let missing_claims = json_usize_field(&summary, "missingEvidenceReferences");
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
        if json_usize_field(&summary, "unverifiedOutOfScopeClaims")
            != Some(expected_out_of_scope_claims)
            || json_string_array_field(&summary, "requiredProfiles") != Some(vec!["upstream"])
        {
            return Err(merge_fixture_failure(
                report,
                label,
                started,
                &summary_path,
                "promotion profile scope or out-of-scope count is invalid",
            ));
        }
        let shard_expected_divergences = json_usize_field(&summary, "reviewedExpectedDivergences")
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
        let platform_skips = json_usize_field(&summary, "requiredPlatformSkips");
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
        if json_bool_field(&summary, "promotionReady") != Some(false) {
            return Err(merge_fixture_failure(
                report,
                label,
                started,
                &summary_path,
                "field promotionReady must be false until global validation",
            ));
        }
        if json_bool_field(&summary, "repositoryPolicyPassed") != Some(true) {
            return Err(merge_fixture_failure(
                report,
                label,
                started,
                &summary_path,
                "field repositoryPolicyPassed must be true",
            ));
        }
        for (field, expected) in [
            ("observationBundleSchemaVersion", 2),
            ("claimIndexSchemaVersion", 2),
            ("oracleRecordSchemaVersion", 2),
        ] {
            if json_usize_field(&summary, field) != Some(expected) {
                return Err(merge_fixture_failure(
                    report,
                    label,
                    started,
                    &summary_path,
                    format!("field {field} must be schema version {expected}"),
                ));
            }
        }
        if json_usize_field(&summary, "generatedDifferentialObservations")
            .is_none_or(|count| count < 1_024)
            || json_usize_field(&summary, "committedDifferentialObservations")
                .is_none_or(|count| count == 0)
        {
            return Err(merge_fixture_failure(
                report,
                label,
                started,
                &summary_path,
                "generatedDifferentialObservations or committedDifferentialObservations is missing, malformed, or insufficient",
            ));
        }
        let summary_digest_path = directory.join("summary.sha256");
        let digest_record = io_or_report(
            report,
            format!("merge-{label}"),
            started,
            "read summary digest",
            &summary_digest_path,
            fs::read_to_string(&summary_digest_path),
        )?;
        let recorded_digest = digest_record.split_whitespace().next().ok_or_else(|| {
            merge_fixture_failure(
                report,
                label,
                started,
                &summary_digest_path,
                "summary digest record is empty",
            )
        })?;
        if recorded_digest != summary_digest.hex() {
            return Err(merge_fixture_failure(
                report,
                label,
                started,
                &summary_digest_path,
                "summary digest does not match summary.json",
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
        let claim_index_digest = io_or_report(
            report,
            format!("merge-{label}"),
            started,
            "hash claim evidence index",
            &claim_index,
            sha256_file(&claim_index),
        )?;
        if !summary.contains(&format!(
            "\"claimEvidenceIndexSha256\": \"{}\"",
            claim_index_digest.hex()
        )) {
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
        if json_usize_field(&claim_index_contents, "schemaVersion") != Some(2)
            || json_string_field(&claim_index_contents, "profile") != Some("upstream")
            || json_string_field(&claim_index_contents, "platform") != Some(label)
        {
            return Err(merge_fixture_failure(
                report,
                label,
                started,
                &claim_index,
                "claim evidence index schema/profile/platform is invalid",
            ));
        }
        for field in [
            "missingBundles",
            "irrelevantReferences",
            "profileMismatches",
            "platformMismatches",
            "normalizerMismatches",
            "failedObservations",
        ] {
            if json_usize_field(&claim_index_contents, field) != Some(0) {
                return Err(merge_fixture_failure(
                    report,
                    label,
                    started,
                    &claim_index,
                    format!("claim index field {field} is missing, malformed, or nonzero"),
                ));
            }
        }
        if let Err(detail) = validate_claim_index_contents(
            &claim_index_contents,
            &directory.join("evidence/observations"),
            label,
        ) {
            return Err(merge_fixture_failure(
                report,
                label,
                started,
                &claim_index,
                detail,
            ));
        }
        for (field, expected) in [
            ("candidateSourceCommit", &mut candidate_source_commit),
            (
                "compatibilitySnapshotSha256",
                &mut compatibility_snapshot_sha256,
            ),
        ] {
            let observed = required_merge_string_field(
                report,
                label,
                started,
                &claim_index,
                &claim_index_contents,
                field,
            )?;
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
        for field in ["promotionPolicySha256", "reviewedCorpusCatalogSha256"] {
            let observed = required_merge_string_field(
                report,
                label,
                started,
                &claim_index,
                &claim_index_contents,
                field,
            )?;
            if field == "promotionPolicySha256" && observed != promotion_policy.sha256.hex() {
                return Err(merge_fixture_failure(
                    report,
                    label,
                    started,
                    &claim_index,
                    "claim index does not bind the committed promotion policy",
                ));
            }
            bind_common_field(&mut common_summary_fields, field, observed).map_err(|detail| {
                merge_fixture_failure(report, label, started, &claim_index, detail)
            })?;
        }
        for field in [
            "promotionPolicySha256",
            "reviewedCorpusCatalogSha256",
            "promotionReviewSha256",
            "dependencyLockSha256",
            "dependencyPolicyAttestationSha256",
            "expectedMismatchManifestSha256",
        ] {
            let observed = required_merge_string_field(
                report,
                label,
                started,
                &summary_path,
                &summary,
                field,
            )?;
            bind_common_field(&mut common_summary_fields, field, observed).map_err(|detail| {
                merge_fixture_failure(report, label, started, &summary_path, detail)
            })?;
        }
        let catalog = directory.join("evidence/reviewed-corpus-catalog.json");
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
        let attestation = directory.join("evidence/dependency-policy-attestation.json");
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
        let attestation_digest_path =
            directory.join("evidence/dependency-policy-attestation.sha256");
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
            if recorded_build_digest.split_whitespace().next() != Some(build_digest.as_str()) {
                return Err(merge_fixture_failure(
                    report,
                    label,
                    started,
                    &build_digest_path,
                    format!("digest does not bind {}", build_path.display()),
                ));
            }
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
            let provenance = directory.join("oracle-provenance").join(label);
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
                        format!(
                            "field {field} does not match {}",
                            provenance_path.display()
                        ),
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
            if expected != observed {
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
        } else if !summary.contains(
            "\"oracleSha256\": \"5ccc78e62200eb5aea8b9da9161334c61848d0d3e7de2f270929920cfbf357c9\"",
        ) {
            return Err(merge_fixture_failure(
                report,
                label,
                started,
                &summary_path,
                "field oracleSha256 does not match the reviewed Linux oracle",
            ));
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
        ("promotionPolicySha256", promotion_policy.sha256.hex()),
        ("promotionReviewSha256", review.sha256.hex()),
        ("dependencyLockSha256", current_dependency_lock_sha256.hex()),
        (
            "expectedMismatchManifestSha256",
            sha256_file(&root.join("compat/expected-mismatches.toml"))
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
    let current_snapshot = sha256_file(&root.join("compat/upstream-2026-05-29.json"))
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
    report.check("merge-current-source-identities", started.elapsed(), Ok(()));
    let platform_evidence_complete = validated_shards == SHARDS.len();
    let platform_state = oracle_record::validate_against_shards(&oracle_records, input);
    let platform_evidence_complete = platform_evidence_complete && platform_state.complete();
    let review_ready = review.require_accepted().is_ok();
    let promotion_ready = expected_missing_claims == 0
        && expected_platform_skips == 0
        && platform_evidence_complete
        && review_ready;
    merged.push_str("\n  ],\n  \"validatedShardCount\": ");
    write!(merged, "{validated_shards}").expect("writing to String cannot fail");
    merged.push_str(",\n  \"requiredShardCount\": 3");
    merged.push_str(",\n  \"promotionReady\": ");
    merged.push_str(if promotion_ready { "true" } else { "false" });
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
        let result = validate_merged_promotion(input);
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

fn validate_merged_promotion(input: &Path) -> Result<(), String> {
    let manifest = read_digested_merged_manifest(input)?;
    if json_usize_field(&manifest, "schemaVersion") != Some(2)
        || json_usize_field(&manifest, "validatedShardCount") != Some(3)
        || json_usize_field(&manifest, "requiredShardCount") != Some(3)
    {
        return Err("promotion requires exactly three validated native shards".to_owned());
    }
    for field in [
        "missingClaimEvidence",
        "irrelevantClaimReferences",
        "profileEvidenceMismatches",
        "platformEvidenceMismatches",
        "normalizerEvidenceMismatches",
        "failedClaimObservations",
        "invalidApplicabilityClaims",
        "requiredPlatformSkips",
        "invalidPlatformRecords",
        "platformProvenanceMismatches",
    ] {
        if json_usize_field(&manifest, field) != Some(0) {
            return Err(format!(
                "merged native evidence counter {field} is not zero"
            ));
        }
    }
    if json_bool_field(&manifest, "reviewAccepted") != Some(true)
        || json_bool_field(&manifest, "platformEvidenceComplete") != Some(true)
        || json_bool_field(&manifest, "promotionReady") != Some(true)
    {
        return Err("merged native evidence is not promotion-ready".to_owned());
    }
    if json_string_array_field(&manifest, "requiredProfiles") != Some(vec!["upstream"])
        || json_usize_field(&manifest, "unverifiedOutOfScopeClaims").is_none()
        || json_usize_field(&manifest, "reviewedExpectedDivergences").is_none()
    {
        return Err("merged native evidence omits promotion scope visibility".to_owned());
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

#[allow(clippy::too_many_lines)]
fn validate_claim_index_contents(
    document: &str,
    observation_root: &Path,
    platform: &str,
) -> Result<(), String> {
    let claim_platform = match platform {
        "linux-amd64" => hell_builtins::ClaimPlatform::Linux,
        "macos-arm64" => hell_builtins::ClaimPlatform::MacOs,
        "windows-amd64" => hell_builtins::ClaimPlatform::Windows,
        _ => return Err(format!("unknown claim-index platform {platform:?}")),
    };
    let committed = committed_differential_cases();
    validate_evidence_catalog(&committed)?;
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
    let mut in_entries = false;
    let mut saw_entries_open = false;
    let mut saw_entries_close = false;
    for line in document.lines().map(str::trim) {
        if line == "\"entries\": [" {
            if saw_entries_open || in_entries {
                return Err("claim index repeats its entries array".to_owned());
            }
            saw_entries_open = true;
            in_entries = true;
            continue;
        }
        if in_entries && line == "]" {
            in_entries = false;
            saw_entries_close = true;
            continue;
        }
        if !in_entries {
            continue;
        }
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
            if line.strip_suffix(',').unwrap_or(line) != canonical {
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
            if line.strip_suffix(',').unwrap_or(line) != canonical {
                return Err("applicability entry is not canonical or has extra fields".to_owned());
            }
        }
        observed.push(key);
    }
    if in_entries || !saw_entries_open || !saw_entries_close {
        return Err("claim index entries array is missing or unterminated".to_owned());
    }
    if observed
        .windows(2)
        .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
    {
        return Err("claim index entries are duplicated or non-canonical".to_owned());
    }
    if json_usize_field(document, "indexedEntries") != Some(observed.len()) {
        return Err("claim index entry count is inconsistent".to_owned());
    }
    if observed != expected {
        return Err("claim index does not cover the exact required claim scope".to_owned());
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
    let record = format!(
        concat!(
            "{{\n",
            "  \"schemaVersion\": 1,\n",
            "  \"platform\": \"{}\",\n",
            "  \"sourceCommit\": \"{}\",\n",
            "  \"sourceTreeStdoutSha256\": \"{}\",\n",
            "  \"sourceTreeStdoutRetainedSha256\": \"{}\",\n",
            "  \"resolverSha256\": \"{}\",\n",
            "  \"binarySha256\": \"{}\",\n",
            "  \"platformIdentitySha256\": \"{}\",\n",
            "  \"stackStdoutSha256\": \"{}\",\n",
            "  \"stackStdoutRetainedSha256\": \"{}\",\n",
            "  \"compilerStdoutSha256\": \"{}\",\n",
            "  \"compilerStdoutRetainedSha256\": \"{}\",\n",
            "  \"dependencyStdoutSha256\": \"{}\",\n",
            "  \"dependencyStdoutRetainedSha256\": \"{}\",\n",
            "  \"buildStdoutSha256\": \"{}\",\n",
            "  \"buildStdoutRetainedSha256\": \"{}\",\n",
            "  \"buildStderrSha256\": \"{}\",\n",
            "  \"buildStderrRetainedSha256\": \"{}\",\n",
            "  \"buildStdoutBytes\": {},\n",
            "  \"buildStderrBytes\": {},\n",
            "  \"buildStdoutRetainedCompletely\": {},\n",
            "  \"buildStderrRetainedCompletely\": {}\n",
            "}}\n"
        ),
        platform,
        source_commit,
        source_tree.stdout_sha256.hex(),
        sha256_bytes(&source_tree.stdout).hex(),
        sha256_bytes(resolver).hex(),
        binary_sha256.hex(),
        sha256_bytes(platform_identity.as_bytes()).hex(),
        stack.stdout_sha256.hex(),
        sha256_bytes(&stack.stdout).hex(),
        compiler.stdout_sha256.hex(),
        sha256_bytes(&compiler.stdout).hex(),
        dependencies.stdout_sha256.hex(),
        sha256_bytes(&dependencies.stdout).hex(),
        build.stdout_sha256.hex(),
        sha256_bytes(&build.stdout).hex(),
        build.stderr_sha256.hex(),
        sha256_bytes(&build.stderr).hex(),
        build.stdout_bytes,
        build.stderr_bytes,
        !build.stdout_truncated,
        !build.stderr_truncated,
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
    )
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
    if !build_candidate(root, report, failures, profile) {
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

fn build_candidate(root: &Path, report: &mut Report, failures: &Path, profile: &str) -> bool {
    let mut arguments = vec!["build"];
    if profile == "release" {
        arguments.push("--release");
    }
    arguments.extend(["--package", "hell-cli", "--bin", "hell", "--locked"]);
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
    let candidate = root.join("target/release").join(executable_name);
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

#[allow(clippy::too_many_lines)]
fn run_differential_corpus(
    root: &Path,
    identities: &NightlyIdentities,
    failures: &Path,
    dependency_attestation: &Path,
) -> Result<DifferentialCorpusResult, SuiteFailure> {
    const CASES: usize = 1_024;
    const SEED: u64 = 0x4845_4c4c_2026;
    let artifact_root = failures.parent().unwrap_or_else(|| Path::new("."));
    let mismatch_root = artifact_root.join("mismatches");
    let observation_root = artifact_root.join("evidence/observations");
    let mut corpus_bytes = Vec::new();
    let mut committed_corpus_bytes = Vec::new();
    let mut generated_corpus_bytes = Vec::new();
    let committed = committed_differential_cases();
    validate_evidence_catalog(&committed).map_err(SuiteFailure::fixture)?;
    let generated = generated_typed_cases(SEED, CASES);
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
        unexpected_timeouts += usize::from(outcome.timed_out);
        resource_failures = resource_failures.saturating_add(outcome.resource_failures);
    }
    let corpus_sha256 = sha256_bytes(&corpus_bytes);
    let reviewed_committed_corpus_sha256 = sha256_bytes(&committed_corpus_bytes);
    let generated_stress_corpus_sha256 = sha256_bytes(&generated_corpus_bytes);
    let reviewed_corpus_catalog_sha256 = write_reviewed_corpus_catalog(artifact_root, &committed)?;
    let promotion_policy = promotion_policy::load(root).map_err(SuiteFailure::fixture)?;
    let promotion_review = promotion_policy::load_review(root).map_err(SuiteFailure::fixture)?;
    let compatibility_snapshot = root.join("compat/upstream-2026-05-29.json");
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
    let expected_mismatch_manifest = root.join("compat/expected-mismatches.toml");
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
                oracle: &identities.oracle,
                candidate: &identities.candidate,
                corpus_seed: SEED,
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

fn write_reviewed_corpus_catalog(
    artifact_root: &Path,
    committed: &[DifferentialCase],
) -> Result<Digest, SuiteFailure> {
    let path = artifact_root.join("evidence/reviewed-corpus-catalog.json");
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
    compatibility_snapshot_sha256: Digest,
    promotion_policy_sha256: Digest,
    reviewed_corpus_catalog_sha256: Digest,
    oracle: &ExecutableIdentity,
    candidate: &ExecutableIdentity,
    committed: &[DifferentialCase],
    outcomes: &BTreeMap<String, CaseOutcome>,
) -> Result<ClaimEvidenceIndexResult, SuiteFailure> {
    let observations = artifact_root.join("evidence/observations");
    let index_path = artifact_root.join("evidence/claim-index.json");
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
            "{{\n  \"schemaVersion\": 2,\n",
            "  \"compatibilitySnapshotSha256\": {:?},\n",
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
    let path = root.join("compat/expected-mismatches.toml");
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

    fn linux_summary(root: &Path, claim_index_sha256: &str) -> String {
        format!(
            concat!(
                "{{\n",
                "  \"schemaVersion\": 2,\n",
                "  \"observationBundleSchemaVersion\": 2,\n",
                "  \"claimIndexSchemaVersion\": 2,\n",
                "  \"oracleRecordSchemaVersion\": 2,\n",
                "  \"platform\": \"linux-x86_64\",\n",
                "  \"oracleSha256\": \"5ccc78e62200eb5aea8b9da9161334c61848d0d3e7de2f270929920cfbf357c9\",\n",
                "  \"mismatches\": 0,\n",
                "  \"reviewedExpectedDivergences\": 0,\n",
                "  \"unexpectedTimeouts\": 0,\n",
                "  \"staleExactClaims\": 0,\n",
                "  \"irrelevantClaimReferences\": 0,\n",
                "  \"profileEvidenceMismatches\": 0,\n",
                "  \"platformEvidenceMismatches\": 0,\n",
                "  \"normalizerEvidenceMismatches\": 0,\n",
                "  \"failedClaimObservations\": 0,\n",
                "  \"leakedResources\": 0,\n",
                "  \"dependencyFailures\": 0,\n",
                "  \"missingEvidenceReferences\": {},\n",
                "  \"unverifiedOutOfScopeClaims\": {},\n",
                "  \"requiredProfiles\": [\"upstream\"],\n",
                "  \"requiredPlatformSkips\": {},\n",
                "  \"promotionReady\": false,\n",
                "  \"repositoryPolicyPassed\": true,\n",
                "  \"generatedDifferentialObservations\": 1024,\n",
                "  \"committedDifferentialObservations\": 1,\n",
                "  \"claimEvidenceIndexSha256\": \"{}\",\n",
                "  \"promotionPolicySha256\": \"{}\",\n",
                "  \"reviewedCorpusCatalogSha256\": \"catalog\",\n",
                "  \"promotionReviewSha256\": \"review\",\n",
                "  \"dependencyLockSha256\": \"lock\",\n",
                "  \"dependencyPolicyAttestationSha256\": \"attestation\",\n",
                "  \"expectedMismatchManifestSha256\": \"mismatches\"\n",
                "}}\n"
            ),
            missing_claim_evidence(),
            unverified_out_of_scope_claims(&[hell_builtins::ExecutionProfile::Upstream]),
            required_platform_skips(root),
            claim_index_sha256,
            hell_builtins::PROMOTION_POLICY_SHA256,
        )
    }

    fn write_linux_summary(root: &Path, input: &Path, claim_index_sha256: &str) -> PathBuf {
        let directory = input.join("linux-amd64");
        fs::create_dir_all(&directory).unwrap();
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
    fn stack_build_uses_the_pinned_lock_without_cabal_flags() {
        let spec = stack_oracle_build_command(
            Path::new("upstream/stack.yaml"),
            Path::new("artifacts/oracle"),
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
                && failure.contains("summary digest record is empty")
                && failure.contains(&digest_path.display().to_string())
        }));
    }

    #[test]
    fn merge_reports_missing_claim_index_identity_field() {
        let sandbox = TestSandbox::create("missing-claim-field");
        let root = repository_root();
        let claim_contents = format!(
            concat!(
                "{{\n",
                "  \"schemaVersion\": 2,\n",
                "  \"compatibilitySnapshotSha256\": \"snapshot\",\n",
                "  \"promotionPolicySha256\": \"{}\",\n",
                "  \"reviewedCorpusCatalogSha256\": \"catalog\",\n",
                "  \"oracleSha256\": \"oracle\",\n",
                "  \"candidateSha256\": \"candidate\",\n",
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
            hell_builtins::PROMOTION_POLICY_SHA256,
        );
        let claim_digest = sha256_bytes(claim_contents.as_bytes()).hex();
        let directory = write_linux_summary(&root, &sandbox.path, &claim_digest);
        let claim_path = directory.join("evidence").join("claim-index.json");
        fs::create_dir_all(claim_path.parent().unwrap()).unwrap();
        fs::write(&claim_path, &claim_contents).unwrap();
        let mut report = Report::new("merge-native-shards");
        let result = merge_native_shards(&root, &sandbox.path, &mut report);
        assert_eq!(result, Err(FailureKind::Fixture));
        assert!(report.failures.iter().any(|failure| {
            failure.contains("merge-linux-amd64")
                && failure.contains("candidateSourceCommit")
                && failure.contains(&claim_path.display().to_string())
        }));
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
        };
        let identities = NightlyIdentities {
            oracle: identity(ExecutableRole::Oracle),
            candidate: identity(ExecutableRole::Candidate),
        };
        let valid =
            fs::read_to_string(repository_root().join("compat/expected-mismatches.toml")).unwrap();
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
}
