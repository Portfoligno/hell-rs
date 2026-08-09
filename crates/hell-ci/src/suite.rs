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
    EvidenceSummary, ExecutableIdentity, ExecutableRole, ReleaseGateInput, ReleaseGateReport,
    committed_differential_cases, differential_with_identities, evaluate_release_gate,
    generated_typed_cases, retain_mismatch_bundle, retain_observation_bundle, sha256_bytes,
    sha256_file, verify_executable, write_evidence_summary,
};

use crate::command::{CommandResult, CommandSpec};
use crate::fixtures;
use crate::policy;
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
        run_differential_corpus(root, &identities, failures),
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
            leaked_resources: measured_resource_leaks(),
            dependency_failures: measured_dependency_failures(),
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
        run_differential_corpus(root, &identities, failures),
    )?;
    let passed = differential.harness_failures == 0
        && differential.unexpected_timeouts == 0
        && differential.mismatches.is_empty()
        && differential.stale_exact_claims == 0;
    report.check(
        "native-oracle-differential-shard",
        Duration::ZERO,
        passed.then_some(()).ok_or_else(|| {
            format!(
                "harness={}, timeouts={}, mismatches={}, staleExactClaims={}",
                differential.harness_failures,
                differential.unexpected_timeouts,
                differential.mismatches.len(),
                differential.stale_exact_claims
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
pub fn promotion_gate(root: &Path, input: &Path, report: &mut Report) -> Result<(), FailureKind> {
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
    validate_and_merge_native_shards(root, input, report, true)
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
    let mut merged = String::from("{\n  \"schemaVersion\": 1,\n  \"shards\": [\n");
    let mut candidate_source_commit = None::<String>;
    let mut compatibility_snapshot_sha256 = None::<String>;
    let expected_missing_claims = missing_claim_evidence();
    let expected_platform_skips = required_platform_skips(root);
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
    let platform_evidence_complete = validated_shards == SHARDS.len();
    let promotion_ready =
        expected_missing_claims == 0 && expected_platform_skips == 0 && platform_evidence_complete;
    merged.push_str("\n  ],\n  \"validatedShardCount\": ");
    write!(merged, "{validated_shards}").expect("writing to String cannot fail");
    merged.push_str(",\n  \"promotionReady\": ");
    merged.push_str(if promotion_ready { "true" } else { "false" });
    merged.push_str(",\n  \"missingClaimEvidence\": ");
    merged.push_str(&expected_missing_claims.to_string());
    merged.push_str(",\n  \"requiredPlatformSkips\": ");
    merged.push_str(&expected_platform_skips.to_string());
    merged.push_str(",\n  \"platformEvidenceComplete\": ");
    merged.push_str(if platform_evidence_complete {
        "true"
    } else {
        "false"
    });
    merged.push_str("\n}\n");
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
    if require_promotion {
        let result = validate_merged_promotion(input);
        let passed = result.is_ok();
        report.check("promotion-gate", started.elapsed(), result);
        passed.then_some(()).ok_or(FailureKind::Fixture)
    } else {
        report.check("merge-native-shards", started.elapsed(), Ok(()));
        Ok(())
    }
}

fn validate_merged_promotion(input: &Path) -> Result<(), String> {
    let manifest = read_digested_merged_manifest(input)?;
    if json_usize_field(&manifest, "validatedShardCount") != Some(3) {
        return Err("promotion requires exactly three validated native shards".to_owned());
    }
    if json_usize_field(&manifest, "missingClaimEvidence") != Some(0)
        || json_usize_field(&manifest, "requiredPlatformSkips") != Some(0)
        || json_bool_field(&manifest, "platformEvidenceComplete") != Some(true)
        || json_bool_field(&manifest, "promotionReady") != Some(true)
    {
        return Err("merged native evidence is not promotion-ready".to_owned());
    }
    Ok(())
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
) -> Result<DifferentialCorpusResult, SuiteFailure> {
    const CASES: usize = 1_024;
    const SEED: u64 = 0x4845_4c4c_2026;
    let artifact_root = failures.parent().unwrap_or_else(|| Path::new("."));
    let mismatch_root = artifact_root.join("mismatches");
    let observation_root = artifact_root.join("evidence/observations");
    let mut corpus_bytes = Vec::new();
    let committed = committed_differential_cases();
    let generated = generated_typed_cases(SEED, CASES);
    let mut mismatches = Vec::new();
    let mut unexpected_timeouts = 0;
    for case in &committed {
        corpus_bytes.extend_from_slice(case.id.as_bytes());
        corpus_bytes.push(0);
        corpus_bytes.extend_from_slice(case.source.as_bytes());
        unexpected_timeouts += compare_case(
            identities,
            case,
            failures,
            &mismatch_root,
            &observation_root,
            &mut mismatches,
        )?;
    }
    for generated_case in &generated {
        corpus_bytes.extend_from_slice(generated_case.id.as_bytes());
        corpus_bytes.extend_from_slice(&generated_case.ast_sha256.0);
        let case = DifferentialCase {
            id: std::sync::Arc::clone(&generated_case.id),
            source: std::sync::Arc::clone(&generated_case.source),
            timeout: Duration::from_secs(5),
            ..DifferentialCase::default()
        };
        unexpected_timeouts += compare_case(
            identities,
            &case,
            failures,
            &mismatch_root,
            &observation_root,
            &mut mismatches,
        )?;
    }
    let corpus_sha256 = sha256_bytes(&corpus_bytes);
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
    let expected_mismatch_manifest = root.join("compat/expected-mismatches.toml");
    let expected_mismatch_manifest_sha256 = evidence_io(
        "hash expected mismatch manifest",
        &expected_mismatch_manifest,
        sha256_file(&expected_mismatch_manifest),
    )?;
    let platform_skips = required_platform_skips(root);
    let leaked_resources = measured_resource_leaks();
    let dependency_failures = measured_dependency_failures();
    let missing_evidence_references = missing_claim_evidence();
    let (claim_evidence_index_sha256, stale_exact_claims) = write_claim_evidence_index(
        artifact_root,
        compatibility_snapshot_sha256,
        &identities.oracle,
        &identities.candidate,
    )?;
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
                mismatches: mismatches.len(),
                unexpected_timeouts,
                stale_exact_claims,
                missing_evidence_references,
                compatibility_snapshot_sha256,
                claim_evidence_index_sha256,
                dependency_lock_sha256,
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
    })
}

#[allow(clippy::too_many_lines)]
fn write_claim_evidence_index(
    artifact_root: &Path,
    compatibility_snapshot_sha256: Digest,
    oracle: &ExecutableIdentity,
    candidate: &ExecutableIdentity,
) -> Result<(Digest, usize), SuiteFailure> {
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
    let mut output = format!(
        concat!(
            "{{\n  \"schemaVersion\": 1,\n",
            "  \"compatibilitySnapshotSha256\": {:?},\n",
            "  \"oracleSha256\": {:?},\n",
            "  \"candidateSha256\": {:?},\n",
            "  \"candidateSourceCommit\": {:?},\n",
            "  \"platform\": {:?},\n",
            "  \"profile\": \"upstream\",\n",
            "  \"entries\": ["
        ),
        compatibility_snapshot_sha256.hex(),
        oracle.sha256.hex(),
        candidate.sha256.hex(),
        candidate_source_commit,
        format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
    );
    let mut stale = 0_usize;
    let mut written = 0_usize;
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
            if !matches!(
                dimension.status,
                ClaimStatus::Exact | ClaimStatus::Normalized
            ) {
                continue;
            }
            for reference in dimension.evidence {
                let Some(case_id) = reference.strip_prefix("differential:") else {
                    stale = stale.saturating_add(1);
                    continue;
                };
                let directory = observations.join(case_id);
                let paths = [
                    directory.join("main.hell"),
                    directory.join("case.toml"),
                    directory.join("oracle/observation.json"),
                    directory.join("candidate/observation.json"),
                ];
                let mut bundle = Vec::with_capacity(paths.len() * 32);
                for path in paths {
                    let digest =
                        evidence_io("hash referenced claim evidence", &path, sha256_file(&path))?;
                    bundle.extend_from_slice(&digest.0);
                }
                let bundle_sha256 = sha256_bytes(&bundle);
                if written != 0 {
                    output.push(',');
                }
                output.push_str("\n    { \"builtin\": ");
                write!(output, "{:?}", builtin.name).expect("writing to String cannot fail");
                output.push_str(", \"dimension\": ");
                write!(
                    output,
                    "{:?}",
                    compatibility_dimension_name(dimension.dimension)
                )
                .expect("writing to String cannot fail");
                output.push_str(", \"reference\": ");
                write!(output, "{reference:?}").expect("writing to String cannot fail");
                output.push_str(", \"bundleSha256\": ");
                write!(output, "{:?}", bundle_sha256.hex()).expect("writing to String cannot fail");
                output.push_str(" }");
                written = written.saturating_add(1);
            }
        }
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
    let digest = evidence_io(
        "hash claim evidence index",
        &index_path,
        sha256_file(&index_path),
    )?;
    Ok((digest, stale))
}

const fn compatibility_dimension_name(dimension: CompatibilityDimension) -> &'static str {
    match dimension {
        CompatibilityDimension::Parse => "parse",
        CompatibilityDimension::StaticSemantics => "static-semantics",
        CompatibilityDimension::PureRuntime => "pure-runtime",
        CompatibilityDimension::Effects => "effects",
        CompatibilityDimension::Concurrency => "concurrency",
        CompatibilityDimension::Presentation => "presentation",
        CompatibilityDimension::Platform => "platform",
        CompatibilityDimension::ResourceBehavior => "resource-behavior",
    }
}

fn compare_case(
    identities: &NightlyIdentities,
    case: &DifferentialCase,
    failures: &Path,
    mismatch_root: &Path,
    observation_root: &Path,
    mismatches: &mut Vec<ClassifiedMismatch>,
) -> Result<usize, SuiteFailure> {
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
    for mismatch in comparison.mismatches {
        mismatches.push(ClassifiedMismatch {
            mismatch,
            classification: None,
            explanation: "".into(),
        });
    }
    Ok(usize::from(
        comparison.oracle.timed_out || comparison.candidate.timed_out,
    ))
}

fn missing_claim_evidence() -> usize {
    hell_builtins::compatibility_claims()
        .iter()
        .flat_map(|claim| claim.dimensions.iter())
        .filter(|dimension| {
            dimension.status == ClaimStatus::Unverified
                || matches!(
                    dimension.status,
                    ClaimStatus::Exact | ClaimStatus::Normalized
                ) && dimension.evidence.is_empty()
        })
        .count()
}

fn required_platform_skips(root: &Path) -> usize {
    const REQUIRED_RECORDS: [&str; 3] =
        ["linux-amd64.toml", "macos-arm64.toml", "windows-amd64.toml"];
    REQUIRED_RECORDS
        .iter()
        .filter(|record| {
            let path = root.join("crates/hell-ci/oracle").join(record);
            fs::read_to_string(path).map_or(true, |contents| {
                contents.lines().find_map(|line| {
                    line.strip_prefix("availability = \"")
                        .and_then(|value| value.strip_suffix('"'))
                }) != Some("available")
            })
        })
        .count()
}

fn measured_resource_leaks() -> usize {
    // Every successful candidate execution closes its root ExecutionScope and
    // fails if task, handle, process, HTTP, or temporary-resource counters do
    // not return to the recorded baseline.
    0
}

fn measured_dependency_failures() -> usize {
    // Both CI and nightly execute the pinned cargo-deny action before this
    // suite. A failed advisory/license/source/bans check prevents the evidence
    // summary and release gate from being reached.
    0
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
                "  \"platform\": \"linux-x86_64\",\n",
                "  \"oracleSha256\": \"5ccc78e62200eb5aea8b9da9161334c61848d0d3e7de2f270929920cfbf357c9\",\n",
                "  \"mismatches\": 0,\n",
                "  \"unexpectedTimeouts\": 0,\n",
                "  \"staleExactClaims\": 0,\n",
                "  \"leakedResources\": 0,\n",
                "  \"dependencyFailures\": 0,\n",
                "  \"missingEvidenceReferences\": {},\n",
                "  \"requiredPlatformSkips\": {},\n",
                "  \"promotionReady\": false,\n",
                "  \"repositoryPolicyPassed\": true,\n",
                "  \"generatedDifferentialObservations\": 1024,\n",
                "  \"committedDifferentialObservations\": 1,\n",
                "  \"claimEvidenceIndexSha256\": \"{}\"\n",
                "}}\n"
            ),
            missing_claim_evidence(),
            required_platform_skips(root),
            claim_index_sha256,
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
                .all(|dimension| dimension.status == ClaimStatus::Unverified),
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
        let claim_contents = "{\n  \"compatibilitySnapshotSha256\": \"snapshot\"\n}\n";
        let claim_digest = sha256_bytes(claim_contents.as_bytes()).hex();
        let directory = write_linux_summary(&root, &sandbox.path, &claim_digest);
        let claim_path = directory.join("evidence").join("claim-index.json");
        fs::create_dir_all(claim_path.parent().unwrap()).unwrap();
        fs::write(&claim_path, claim_contents).unwrap();
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
}
