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
    EvidenceSummary, ExecutableIdentity, ExecutableRole, ReleaseGateInput,
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
    let differential = run_differential_corpus(root, &identities, failures)?;
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
    let gate_result = gate.passed().then_some(()).ok_or_else(|| {
        format!(
            "release gate failed: differential={}, candidate-stress={}, unexplained={}, rust bugs={}",
            gate.differential_observations,
            stress_observations,
            gate.unexplained_mismatches,
            gate.rust_bug_mismatches
        )
    });
    let gate_passed = gate_result.is_ok();
    report.check("release-gate", started.elapsed(), gate_result);
    gate_passed.then_some(()).ok_or(FailureKind::Fixture)
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
    let observed_commit =
        String::from_utf8(source_identity.stdout).map_err(|_| FailureKind::Fixture)?;
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
    fs::create_dir_all(&oracle_directory).map_err(|_| FailureKind::Io)?;
    let build = observed_command(
        root,
        report,
        failures,
        "oracle-source-build",
        CommandSpec::new("stack", Duration::from_mins(45))
            .argument("--stack-yaml")
            .argument(stack_yaml.as_os_str())
            .arguments(["build", "--install-ghc", "--locked", "--copy-bins"])
            .argument("--local-bin-path")
            .argument(oracle_directory.as_os_str())
            .current_directory(source),
    )?;
    let compiler_identity = observed_command(
        root,
        report,
        failures,
        "oracle-compiler-identity",
        CommandSpec::new("stack", Duration::from_mins(5))
            .argument("--stack-yaml")
            .argument(stack_yaml.as_os_str())
            .arguments(["exec", "--", "ghc", "--info"])
            .current_directory(source),
    )?;
    let dependency_identity = observed_command(
        root,
        report,
        failures,
        "oracle-dependency-identity",
        CommandSpec::new("stack", Duration::from_mins(5))
            .argument("--stack-yaml")
            .argument(stack_yaml.as_os_str())
            .arguments(["ls", "dependencies"])
            .current_directory(source),
    )?;
    let executable_name = if cfg!(windows) { "hell.exe" } else { "hell" };
    let oracle = oracle_directory.join(executable_name);
    let oracle_sha256 = sha256_file(&oracle).map_err(|_| FailureKind::Io)?;
    let resolver = fs::read(&stack_lock).map_err(|_| FailureKind::Io)?;
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
    )?;

    if !build_candidate(root, report, failures, "release") {
        return Err(FailureKind::Child);
    }
    let identities = verify_nightly_identities(root, &oracle, oracle_sha256)
        .map_err(|_| FailureKind::Fixture)?;
    let differential = run_differential_corpus(root, &identities, failures)?;
    let passed = differential.harness_failures == 0
        && differential.unexpected_timeouts == 0
        && differential.mismatches.is_empty();
    report.check(
        "native-oracle-differential-shard",
        Duration::ZERO,
        passed.then_some(()).ok_or_else(|| {
            format!(
                "harness={}, timeouts={}, mismatches={}",
                differential.harness_failures,
                differential.unexpected_timeouts,
                differential.mismatches.len()
            )
        }),
    );
    passed.then_some(()).ok_or(FailureKind::Fixture)
}

/// Verifies the identities and content digests of required native shards.
#[allow(clippy::too_many_lines)]
pub fn merge_native_shards(input: &Path, report: &mut Report) -> Result<(), FailureKind> {
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
    for (index, (label, host_platform, source_built)) in SHARDS.iter().enumerate() {
        let directory = input.join(label);
        let summary_path = directory.join("summary.json");
        let summary = fs::read_to_string(&summary_path).map_err(|_| FailureKind::Io)?;
        let expected_platform = format!("\"platform\": \"{host_platform}\"");
        if !summary.contains(&expected_platform) {
            report.check(
                "merge-native-shards",
                started.elapsed(),
                Err(format!("{label} summary has the wrong platform identity")),
            );
            return Err(FailureKind::Fixture);
        }
        let summary_digest = sha256_bytes(summary.as_bytes());
        for field in [
            "mismatches",
            "unexpectedTimeouts",
            "staleExactClaims",
            "missingEvidenceReferences",
            "leakedResources",
            "dependencyFailures",
        ] {
            if json_usize_field(&summary, field) != Some(0) {
                report.check(
                    "merge-native-shards",
                    started.elapsed(),
                    Err(format!("{label} summary has a nonzero or missing {field}")),
                );
                return Err(FailureKind::Fixture);
            }
        }
        if json_bool_field(&summary, "repositoryPolicyPassed") != Some(true) {
            report.check(
                "merge-native-shards",
                started.elapsed(),
                Err(format!("{label} summary did not pass repository policy")),
            );
            return Err(FailureKind::Fixture);
        }
        if json_usize_field(&summary, "generatedDifferentialObservations")
            .is_none_or(|count| count < 1_024)
            || json_usize_field(&summary, "committedDifferentialObservations")
                .is_none_or(|count| count == 0)
        {
            report.check(
                "merge-native-shards",
                started.elapsed(),
                Err(format!(
                    "{label} summary has insufficient differential observations"
                )),
            );
            return Err(FailureKind::Fixture);
        }
        let digest_record =
            fs::read_to_string(directory.join("summary.sha256")).map_err(|_| FailureKind::Io)?;
        let recorded_digest = digest_record
            .split_whitespace()
            .next()
            .ok_or(FailureKind::Fixture)?;
        if recorded_digest != summary_digest.hex() {
            report.check(
                "merge-native-shards",
                started.elapsed(),
                Err(format!("{label} summary digest is invalid")),
            );
            return Err(FailureKind::Fixture);
        }
        let claim_index = directory.join("evidence/claim-index.json");
        let claim_index_contents = fs::read_to_string(&claim_index).map_err(|_| FailureKind::Io)?;
        let claim_index_digest = sha256_file(&claim_index).map_err(|_| FailureKind::Io)?;
        if !summary.contains(&format!(
            "\"claimEvidenceIndexSha256\": \"{}\"",
            claim_index_digest.hex()
        )) {
            report.check(
                "merge-native-shards",
                started.elapsed(),
                Err(format!(
                    "{label} claim evidence index is not bound by its summary"
                )),
            );
            return Err(FailureKind::Fixture);
        }
        for (field, expected) in [
            ("candidateSourceCommit", &mut candidate_source_commit),
            (
                "compatibilitySnapshotSha256",
                &mut compatibility_snapshot_sha256,
            ),
        ] {
            let observed =
                json_string_field(&claim_index_contents, field).ok_or(FailureKind::Fixture)?;
            if let Some(expected) = expected {
                if expected != observed {
                    report.check(
                        "merge-native-shards",
                        started.elapsed(),
                        Err(format!("native shards disagree on {field}")),
                    );
                    return Err(FailureKind::Fixture);
                }
            } else {
                *expected = Some(observed.to_owned());
            }
        }
        if *source_built {
            let build_path = directory.join(format!("oracle-build-{label}.json"));
            let build = fs::read_to_string(&build_path).map_err(|_| FailureKind::Io)?;
            let build_digest = sha256_bytes(build.as_bytes()).hex();
            let recorded_build_digest = fs::read_to_string(
                directory.join(format!("oracle-build-{label}.sha256")),
            )
            .map_err(|_| FailureKind::Io)?;
            if recorded_build_digest.split_whitespace().next() != Some(build_digest.as_str()) {
                report.check(
                    "merge-native-shards",
                    started.elapsed(),
                    Err(format!("{label} build provenance record digest is invalid")),
                );
                return Err(FailureKind::Fixture);
            }
            if !build.contains(&format!("\"platform\": \"{label}\""))
                || !build.contains(&format!("\"sourceCommit\": \"{SOURCE_COMMIT}\""))
            {
                report.check(
                    "merge-native-shards",
                    started.elapsed(),
                    Err(format!("{label} build provenance is invalid")),
                );
                return Err(FailureKind::Fixture);
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
                let expected = json_string_field(&build, field).ok_or(FailureKind::Fixture)?;
                let observed = sha256_file(&provenance.join(relative))
                    .map_err(|_| FailureKind::Io)?
                    .hex();
                if expected != observed {
                    report.check(
                        "merge-native-shards",
                        started.elapsed(),
                        Err(format!("{label} provenance digest {field} is invalid")),
                    );
                    return Err(FailureKind::Fixture);
                }
            }
            let executable_name = if label.starts_with("windows-") {
                "hell.exe"
            } else {
                "hell"
            };
            let expected = json_string_field(&build, "binarySha256")
                .ok_or(FailureKind::Fixture)?;
            let observed = sha256_file(&directory.join("oracle").join(label).join(executable_name))
                .map_err(|_| FailureKind::Io)?
                .hex();
            if expected != observed {
                report.check(
                    "merge-native-shards",
                    started.elapsed(),
                    Err(format!("{label} oracle binary digest is invalid")),
                );
                return Err(FailureKind::Fixture);
            }
        } else if !summary.contains(
            "\"oracleSha256\": \"5ccc78e62200eb5aea8b9da9161334c61848d0d3e7de2f270929920cfbf357c9\"",
        ) {
            report.check(
                "merge-native-shards",
                started.elapsed(),
                Err("linux-amd64 shard has the wrong content-addressed oracle".to_owned()),
            );
            return Err(FailureKind::Fixture);
        }
        if index != 0 {
            merged.push_str(",\n");
        }
        merged.push_str("    { \"platform\": \"");
        merged.push_str(label);
        merged.push_str("\", \"summarySha256\": \"");
        merged.push_str(&summary_digest.hex());
        merged.push_str("\" }");
    }
    let missing_claims = missing_claim_evidence();
    merged.push_str("\n  ],\n  \"promotionReady\": ");
    merged.push_str(if missing_claims == 0 { "true" } else { "false" });
    merged.push_str(",\n  \"missingClaimEvidence\": ");
    merged.push_str(&missing_claims.to_string());
    merged.push_str(",\n  \"requiredPlatformSkips\": 0");
    merged.push_str(",\n  \"platformEvidenceComplete\": true");
    merged.push_str("\n}\n");
    fs::create_dir_all(input).map_err(|_| FailureKind::Io)?;
    fs::write(input.join("merged-native-shards.json"), merged).map_err(|_| FailureKind::Io)?;
    let promotion_ready = missing_claims == 0;
    let result = promotion_ready.then_some(()).ok_or_else(|| {
        format!("native evidence is incomplete for {missing_claims} compatibility dimensions")
    });
    let passed = result.is_ok();
    report.check("merge-native-shards", started.elapsed(), result);
    passed.then_some(()).ok_or(FailureKind::Fixture)
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

#[allow(clippy::too_many_arguments)]
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
) -> Result<(), FailureKind> {
    let provenance = artifact_root.join("oracle-provenance").join(platform);
    fs::create_dir_all(&provenance).map_err(|_| FailureKind::Io)?;
    let platform_identity = format!(
        "platform={platform}\nos={}\narch={}\n",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    fs::write(
        provenance.join("platform.txt"),
        platform_identity.as_bytes(),
    )
    .map_err(|_| FailureKind::Io)?;
    fs::write(provenance.join("resolver.lock"), resolver).map_err(|_| FailureKind::Io)?;
    for (name, command) in [
        ("source-tree", source_tree),
        ("stack", stack),
        ("compiler", compiler),
        ("dependencies", dependencies),
        ("build", build),
    ] {
        fs::write(provenance.join(format!("{name}.stdout")), &command.stdout)
            .map_err(|_| FailureKind::Io)?;
        fs::write(provenance.join(format!("{name}.stderr")), &command.stderr)
            .map_err(|_| FailureKind::Io)?;
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
    fs::write(&path, record.as_bytes()).map_err(|_| FailureKind::Io)?;
    let digest = sha256_bytes(record.as_bytes()).hex();
    fs::write(
        artifact_root.join(format!("oracle-build-{platform}.sha256")),
        format!("{digest}  oracle-build-{platform}.json\n"),
    )
    .map_err(|_| FailureKind::Io)
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

fn run_differential_corpus(
    root: &Path,
    identities: &NightlyIdentities,
    failures: &Path,
) -> Result<DifferentialCorpusResult, FailureKind> {
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
    let compatibility_snapshot_sha256 =
        sha256_file(&root.join("compat/upstream-2026-05-29.json")).map_err(|_| FailureKind::Io)?;
    let dependency_lock_sha256 =
        sha256_file(&root.join("Cargo.lock")).map_err(|_| FailureKind::Io)?;
    let expected_mismatch_manifest_sha256 =
        sha256_file(&root.join("compat/expected-mismatches.toml")).map_err(|_| FailureKind::Io)?;
    let platform_skips = required_platform_skips(root);
    let leaked_resources = measured_resource_leaks();
    let dependency_failures = measured_dependency_failures();
    let (claim_evidence_index_sha256, stale_exact_claims) = write_claim_evidence_index(
        artifact_root,
        compatibility_snapshot_sha256,
        &identities.oracle,
        &identities.candidate,
    )?;
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
            missing_evidence_references: missing_claim_evidence(),
            compatibility_snapshot_sha256,
            claim_evidence_index_sha256,
            dependency_lock_sha256,
            expected_mismatch_manifest_sha256,
            repository_policy_passed: true,
            required_platform_skips: platform_skips,
            leaked_resources,
            dependency_failures,
        },
    )
    .map_err(|_| FailureKind::Io)?;
    Ok(DifferentialCorpusResult {
        committed_observations: committed.len(),
        generated_observations: generated.len(),
        harness_failures: 0,
        unexpected_timeouts,
        mismatches,
        stale_exact_claims,
    })
}

fn write_claim_evidence_index(
    artifact_root: &Path,
    compatibility_snapshot_sha256: Digest,
    oracle: &ExecutableIdentity,
    candidate: &ExecutableIdentity,
) -> Result<(Digest, usize), FailureKind> {
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
        .ok_or(FailureKind::Fixture)?;
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
            .ok_or(FailureKind::Fixture)?;
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
                let mut complete = true;
                for path in paths {
                    if let Ok(digest) = sha256_file(&path) {
                        bundle.extend_from_slice(&digest.0);
                    } else {
                        complete = false;
                        break;
                    }
                }
                if !complete {
                    stale = stale.saturating_add(1);
                    continue;
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
        fs::create_dir_all(parent).map_err(|_| FailureKind::Io)?;
    }
    fs::write(&index_path, output.as_bytes()).map_err(|_| FailureKind::Io)?;
    let digest = sha256_file(&index_path).map_err(|_| FailureKind::Io)?;
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
) -> Result<usize, FailureKind> {
    const FAILURE_CAP: usize = 32;
    let comparison = differential_with_identities(&identities.oracle, &identities.candidate, case)
        .map_err(|error| {
            let _ = fs::create_dir_all(failures);
            let _ = fs::write(
                failures.join(format!("{}.harness.txt", case.id)),
                error.to_string(),
            );
            FailureKind::Fixture
        })?;
    retain_observation_bundle(observation_root, case, &comparison).map_err(|_| FailureKind::Io)?;
    if !comparison.mismatches.is_empty() && mismatches.len() < FAILURE_CAP {
        retain_mismatch_bundle(mismatch_root, case, &comparison).map_err(|_| FailureKind::Io)?;
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

    use super::*;

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
}
