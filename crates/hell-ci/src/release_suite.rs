use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use hell_testkit::{
    DifferentialCase, Digest, ExecutableRole, GeneratedCase, bind_process_helper_directory,
    committed_differential_cases, differential_with_identities, generated_typed_cases,
    sha256_bytes, sha256_file, verify_executable,
};

use crate::command::{CommandSpec, release_candidate_target};
use crate::compatibility;
use crate::identity::require_git_sha;
use crate::json::{JsonValue, canonical_json_bytes};
use crate::report::Report;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FailureKind {
    Policy,
    Child,
    Fixture,
}

pub(crate) fn failures_directory(report: &Path) -> PathBuf {
    report
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("failures")
}

pub(crate) fn policy_suite(root: &Path, report: &mut Report) -> Result<(), FailureKind> {
    let started = Instant::now();
    let result = crate::policy::check_repository(root)
        .and_then(|()| compatibility::release_conformance_policy(root).map(|_| ()));
    let passed = result.is_ok();
    report.check("release-assurance-policy", started.elapsed(), result);
    passed.then_some(()).ok_or(FailureKind::Policy)
}

pub(crate) fn verify(root: &Path, report: &mut Report, failures: &Path) -> Result<(), FailureKind> {
    policy_suite(root, report)?;
    run_command(
        root,
        report,
        "workspace-tests",
        "cargo",
        &[
            "test",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--locked",
        ],
        Duration::from_hours(1),
    )?;
    run_command(
        root,
        report,
        "candidate-build",
        "cargo",
        &["build", "--workspace", "--all-features", "--locked"],
        Duration::from_hours(1),
    )?;
    fixture_gate(root, report, failures)
}

pub(crate) fn portability(
    root: &Path,
    report: &mut Report,
    failures: &Path,
) -> Result<(), FailureKind> {
    policy_suite(root, report)?;
    run_command(
        root,
        report,
        "portable-workspace-tests",
        "cargo",
        &[
            "test",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--locked",
        ],
        Duration::from_hours(1),
    )?;
    fixture_gate(root, report, failures)
}

pub(crate) fn release_verify(
    root: &Path,
    report: &mut Report,
    failures: &Path,
) -> Result<(), FailureKind> {
    policy_suite(root, report)?;
    fixture_gate(root, report, failures)
}

pub(crate) fn release_portability(
    root: &Path,
    report: &mut Report,
    failures: &Path,
) -> Result<(), FailureKind> {
    policy_suite(root, report)?;
    fixture_gate(root, report, failures)
}

pub(crate) fn dependency_attestation(
    root: &Path,
    output: &Path,
    report: &mut Report,
) -> Result<(), FailureKind> {
    let started = Instant::now();
    let result = git_commit(root)
        .and_then(|candidate| dependency_attestation_for(root, output, &candidate, "nightly.yml"));
    let passed = result.is_ok();
    report.check("dependency-attestation", started.elapsed(), result);
    passed.then_some(()).ok_or(FailureKind::Fixture)
}

fn git_commit(root: &Path) -> Result<String, String> {
    let result = CommandSpec::new("git", Duration::from_secs(30))
        .arguments(["rev-parse", "HEAD"])
        .current_directory(root)
        .run()
        .map_err(|error| format!("cannot resolve dependency checkout: {error}"))?;
    if !result.status.success() || result.timed_out {
        return Err("dependency checkout identity command failed".to_owned());
    }
    let commit = std::str::from_utf8(&result.stdout)
        .map_err(|_| "dependency checkout identity is not UTF-8".to_owned())?
        .trim()
        .to_owned();
    require_git_sha(&commit, "dependency checkout")?;
    Ok(commit)
}

pub(crate) fn release_dependency_attestation(
    root: &Path,
    output: &Path,
    candidate_sha: &str,
) -> Result<(), String> {
    dependency_attestation_for(root, output, candidate_sha, "release.yml")
}

fn dependency_attestation_for(
    root: &Path,
    output: &Path,
    candidate_sha: &str,
    workflow: &str,
) -> Result<(), String> {
    require_git_sha(candidate_sha, "dependency candidate SHA")?;
    let lock = root.join("Cargo.lock");
    let digest = sha256_file(&lock)
        .map_err(|error| format!("cannot hash {}: {error}", lock.display()))?
        .hex();
    let document = JsonValue::Object(BTreeMap::from([
        (
            "candidateSourceCommit".to_owned(),
            JsonValue::String(candidate_sha.to_owned()),
        ),
        ("cargoLockSha256".to_owned(), JsonValue::String(digest)),
        (
            "denyPolicySha256".to_owned(),
            JsonValue::String(
                sha256_file(&root.join("deny.toml"))
                    .map_err(|error| format!("cannot hash deny.toml: {error}"))?
                    .hex(),
            ),
        ),
        ("result".to_owned(), JsonValue::String("passed".to_owned())),
        ("schemaVersion".to_owned(), JsonValue::Number(1)),
        (
            "workflow".to_owned(),
            JsonValue::String(workflow.to_owned()),
        ),
    ]));
    let bytes = canonical_json_bytes(&document)?;
    crate::release::manifest::write_atomic(output, &bytes)?;
    let name = output
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| "dependency attestation output name is not UTF-8".to_owned())?;
    crate::release::manifest::write_atomic(
        &output.with_extension("sha256"),
        format!("{}  {name}\n", sha256_bytes(&bytes).hex()).as_bytes(),
    )
}

pub(crate) fn nightly(
    root: &Path,
    report: &mut Report,
    failures: &Path,
    oracle: &Path,
    oracle_sha256: Digest,
    dependency: &Path,
) -> Result<(), FailureKind> {
    verify(root, report, failures)?;
    let candidate = candidate_binary(root, false);
    differential_gate(
        root,
        report,
        failures,
        oracle,
        Some(oracle_sha256),
        &candidate,
        dependency,
        None,
    )
}

pub(crate) fn native_oracle_shard(
    root: &Path,
    report: &mut Report,
    failures: &Path,
    source: &Path,
    platform: &str,
    dependency: &Path,
) -> Result<(), FailureKind> {
    release_native_oracle_shard(root, report, failures, source, platform, dependency, None)
}

pub(crate) fn release_native_oracle_shard(
    root: &Path,
    report: &mut Report,
    failures: &Path,
    source: &Path,
    platform: &str,
    dependency: &Path,
    candidate_sha: Option<&str>,
) -> Result<(), FailureKind> {
    policy_suite(root, report)?;
    if !matches!(platform, "macos-arm64" | "windows-amd64") {
        report.check(
            "native-platform",
            Duration::ZERO,
            Err(format!("unsupported native platform {platform}")),
        );
        return Err(FailureKind::Policy);
    }
    run_command(
        source,
        report,
        "native-oracle-build",
        "stack",
        &["build", "--stack-yaml", "stack.yaml", "--locked"],
        Duration::from_hours(2),
    )?;
    let oracle = stack_oracle(source, report)?;
    differential_gate(
        root,
        report,
        failures,
        &oracle,
        None,
        &candidate_binary(root, true),
        dependency,
        candidate_sha,
    )
}

pub(crate) fn examples(
    root: &Path,
    report: &mut Report,
    failures: &Path,
    profile: &str,
) -> Result<(), FailureKind> {
    if !matches!(profile, "ci" | "release") {
        report.check(
            "examples-profile",
            Duration::ZERO,
            Err("invalid examples profile".to_owned()),
        );
        return Err(FailureKind::Policy);
    }
    let result = crate::fixtures::run_examples(root, profile, report, failures);
    let passed = result.is_ok();
    report.check("release-examples", Duration::ZERO, result);
    passed.then_some(()).ok_or(FailureKind::Fixture)
}

fn fixture_gate(root: &Path, report: &mut Report, failures: &Path) -> Result<(), FailureKind> {
    let started = Instant::now();
    let result = crate::fixtures::validate_inventory(root);
    let passed = result.is_ok();
    report.check("fixture-inventory", started.elapsed(), result);
    if !passed {
        fs::create_dir_all(failures).ok();
    }
    passed.then_some(()).ok_or(FailureKind::Fixture)
}

#[allow(clippy::too_many_arguments)]
fn differential_gate(
    root: &Path,
    report: &mut Report,
    failures: &Path,
    oracle: &Path,
    oracle_digest: Option<Digest>,
    candidate: &Path,
    dependency: &Path,
    candidate_sha: Option<&str>,
) -> Result<(), FailureKind> {
    let started = Instant::now();
    let result = run_differential(
        root,
        failures,
        oracle,
        oracle_digest,
        candidate,
        dependency,
        candidate_sha,
    );
    let passed = result.is_ok();
    report.check("conformance-differential", started.elapsed(), result);
    passed.then_some(()).ok_or(FailureKind::Fixture)
}

fn run_differential(
    root: &Path,
    failures: &Path,
    oracle: &Path,
    oracle_digest: Option<Digest>,
    candidate: &Path,
    dependency: &Path,
    candidate_sha: Option<&str>,
) -> Result<(), String> {
    verify_dependency(root, dependency, candidate_sha)?;
    let oracle = verify_executable(
        oracle,
        ExecutableRole::Oracle,
        oracle_digest,
        hell_builtins::LANGUAGE_VERSION,
    )
    .map_err(|error| format!("cannot verify oracle: {error}"))?;
    let candidate = verify_executable(
        candidate,
        ExecutableRole::Candidate,
        None,
        hell_builtins::LANGUAGE_VERSION,
    )
    .map_err(|error| format!("cannot verify candidate: {error}"))?;
    run_differential_identities(root, failures, oracle, candidate)
}

fn run_differential_identities(
    root: &Path,
    failures: &Path,
    oracle: hell_testkit::ExecutableIdentity,
    candidate: hell_testkit::ExecutableIdentity,
) -> Result<(), String> {
    let mut cases = committed_differential_cases();
    bind_helper(&mut cases)?;
    let generated = generated_typed_cases(0x4845_4c4c, 32);
    let output_root = failures.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(output_root)
        .map_err(|error| format!("cannot create differential output: {error}"))?;
    let mut cells = reviewed_compatibility_cells()?;
    let reviewed_cells = cells.len();
    let mut regression_mismatches = 0_u64;
    for case in &cases {
        require_executable_digest(&oracle.path, oracle.sha256, "oracle")?;
        require_executable_digest(&candidate.path, candidate.sha256, "candidate")?;
        let result = differential_with_identities(&oracle, &candidate, case)
            .map_err(|error| format!("case {} failed: {error}", case.id))?;
        require_executable_digest(&oracle.path, oracle.sha256, "oracle")?;
        require_executable_digest(&candidate.path, candidate.sha256, "candidate")?;
        let status = if result.agrees() {
            "exact"
        } else {
            "unverified"
        };
        regression_mismatches = regression_mismatches.saturating_add(u64::from(!result.agrees()));
        cells.push(JsonValue::Object(BTreeMap::from([
            ("caseId".to_owned(), JsonValue::String(case.id.to_string())),
            ("status".to_owned(), JsonValue::String(status.to_owned())),
        ])));
    }
    let mut generated_mismatches = Vec::new();
    for case in &generated {
        let differential_case = DifferentialCase {
            id: case.id.clone(),
            source: case.source.clone(),
            ..DifferentialCase::default()
        };
        require_executable_digest(&oracle.path, oracle.sha256, "oracle")?;
        require_executable_digest(&candidate.path, candidate.sha256, "candidate")?;
        let result = differential_with_identities(&oracle, &candidate, &differential_case)
            .map_err(|error| format!("generated case {} failed: {error}", case.id))?;
        require_executable_digest(&oracle.path, oracle.sha256, "oracle")?;
        require_executable_digest(&candidate.path, candidate.sha256, "candidate")?;
        if !result.agrees() {
            retain_generated_mismatch(output_root, case)?;
            generated_mismatches.push(case.id.to_string());
        }
        cells.push(JsonValue::Object(BTreeMap::from([
            ("caseId".to_owned(), JsonValue::String(case.id.to_string())),
            (
                "status".to_owned(),
                JsonValue::String("out-of-scope".to_owned()),
            ),
        ])));
    }
    if regression_mismatches != 0 {
        return Err(format!(
            "{regression_mismatches} committed differential cases mismatch"
        ));
    }
    write_generated_inventory(output_root, &generated_mismatches)?;
    let deliberate_divergences = count_status(&cells, "deliberate-divergence")?;
    let out_of_scope_cells = count_status(&cells, "out-of-scope")?;
    let unverified_cells = count_status(&cells, "unverified")?;
    let compatibility = JsonValue::Object(BTreeMap::from([
        (
            "baselineSha256".to_owned(),
            JsonValue::String(baseline_digest(root)?),
        ),
        ("cells".to_owned(), JsonValue::Array(cells)),
        (
            "committedCells".to_owned(),
            JsonValue::Number(
                (reviewed_cells + cases.len())
                    .try_into()
                    .map_err(|_| "case count overflow")?,
            ),
        ),
        (
            "deliberateDivergences".to_owned(),
            JsonValue::Number(deliberate_divergences),
        ),
        (
            "generatedObservations".to_owned(),
            JsonValue::Number(
                generated
                    .len()
                    .try_into()
                    .map_err(|_| "case count overflow")?,
            ),
        ),
        (
            "outOfScopeCells".to_owned(),
            JsonValue::Number(out_of_scope_cells),
        ),
        (
            "profile".to_owned(),
            JsonValue::String("bounded".to_owned()),
        ),
        ("schemaVersion".to_owned(), JsonValue::Number(1)),
        (
            "unverifiedCells".to_owned(),
            JsonValue::Number(unverified_cells),
        ),
    ]));
    crate::release::manifest::write_atomic(
        &output_root.join("compatibility-report.json"),
        &canonical_json_bytes(&compatibility)?,
    )?;
    crate::release::manifest::write_atomic(
        &output_root.join("compatibility-report.html"),
        format!(
            "<!doctype html>\n<meta charset=\"utf-8\">\n<title>Bounded compatibility</title>\n<p>{} committed observations agree; {} reviewed cells remain unverified; {} cells are out of scope.</p>\n",
            cases.len(), unverified_cells, out_of_scope_cells
        )
        .as_bytes(),
    )
}

fn reviewed_compatibility_cells() -> Result<Vec<JsonValue>, String> {
    let mut cells = Vec::new();
    for claim in hell_builtins::compatibility_requirements() {
        for dimension in &claim.dimensions {
            for scope in dimension.scopes {
                for profile in scope.profiles {
                    for platform in scope.platforms {
                        let platform = match platform {
                            hell_builtins::RequirementPlatform::LinuxX86_64 => "linux-x86_64",
                            hell_builtins::RequirementPlatform::MacosAarch64 => "macos-aarch64",
                            hell_builtins::RequirementPlatform::WindowsX86_64 => "windows-x86_64",
                        };
                        cells.push(JsonValue::Object(BTreeMap::from([
                            (
                                "caseId".to_owned(),
                                JsonValue::String(format!(
                                    "claim-{}-{}-{}-{platform}",
                                    claim.builtin.0,
                                    dimension.dimension.as_str(),
                                    profile.as_str(),
                                )),
                            ),
                            (
                                "status".to_owned(),
                                JsonValue::String("unverified".to_owned()),
                            ),
                        ])));
                    }
                }
            }
        }
    }
    Ok(cells)
}

fn count_status(cells: &[JsonValue], expected: &str) -> Result<u64, String> {
    cells.iter().try_fold(0_u64, |count, cell| {
        Ok(count
            + u64::from(crate::json::json_member(cell.object()?, "status")?.string()? == expected))
    })
}

fn retain_generated_mismatch(root: &Path, case: &GeneratedCase) -> Result<(), String> {
    let directory = root
        .join("mismatches/proposed-regressions")
        .join(case.id.as_ref());
    fs::create_dir_all(&directory)
        .map_err(|error| format!("cannot create generated mismatch directory: {error}"))?;
    crate::release::manifest::write_atomic(&directory.join("main.hell"), case.source.as_bytes())?;
    let descriptor = JsonValue::Object(BTreeMap::from([
        ("caseId".to_owned(), JsonValue::String(case.id.to_string())),
        (
            "sourceSha256".to_owned(),
            JsonValue::String(sha256_bytes(case.source.as_bytes()).hex()),
        ),
        (
            "state".to_owned(),
            JsonValue::String("unreviewed-nonclaim".to_owned()),
        ),
    ]));
    crate::release::manifest::write_atomic(
        &directory.join("descriptor.json"),
        &canonical_json_bytes(&descriptor)?,
    )
}

fn write_generated_inventory(root: &Path, ids: &[String]) -> Result<(), String> {
    let inventory = JsonValue::Object(BTreeMap::from([
        (
            "caseIds".to_owned(),
            JsonValue::Array(ids.iter().cloned().map(JsonValue::String).collect()),
        ),
        ("schemaVersion".to_owned(), JsonValue::Number(1)),
    ]));
    crate::release::manifest::write_atomic(
        &root.join("generated-regression-inventory.json"),
        &canonical_json_bytes(&inventory)?,
    )
}

fn baseline_digest(root: &Path) -> Result<String, String> {
    let bytes =
        crate::release::manifest::read_regular(&root.join("compat/upstream-2026-05-29.json"))?;
    Ok(sha256_bytes(&bytes).hex())
}

fn bind_helper(cases: &mut [DifferentialCase]) -> Result<(), String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("cannot locate assurance driver: {error}"))?;
    let directory = executable
        .parent()
        .ok_or_else(|| "assurance driver has no directory".to_owned())?;
    let profile = if directory.file_name().is_some_and(|name| name == "deps") {
        directory.parent().unwrap_or(directory)
    } else {
        directory
    };
    bind_process_helper_directory(cases, profile).map(|_| ())
}

fn verify_dependency(root: &Path, path: &Path, candidate_sha: Option<&str>) -> Result<(), String> {
    let value = crate::release::manifest::read_json(path)?;
    let object = value.object()?;
    crate::json::require_exact_json_keys(
        object,
        &[
            "candidateSourceCommit",
            "cargoLockSha256",
            "denyPolicySha256",
            "result",
            "schemaVersion",
            "workflow",
        ],
    )?;
    require_git_sha(
        crate::json::json_member(object, "candidateSourceCommit")?.string()?,
        "dependency candidate commit",
    )?;
    if let Some(expected) = candidate_sha
        && crate::json::json_member(object, "candidateSourceCommit")?.string()? != expected
    {
        return Err("dependency attestation differs from planned candidate".to_owned());
    }
    let workflow = crate::json::json_member(object, "workflow")?.string()?;
    if crate::json::json_member(object, "cargoLockSha256")?.string()?
        != sha256_file(&root.join("Cargo.lock"))
            .map_err(|error| format!("cannot hash Cargo.lock: {error}"))?
            .hex()
        || crate::json::json_member(object, "denyPolicySha256")?.string()?
            != sha256_file(&root.join("deny.toml"))
                .map_err(|error| format!("cannot hash deny.toml: {error}"))?
                .hex()
        || crate::json::json_member(object, "result")?.string()? != "passed"
        || crate::json::json_member(object, "schemaVersion")?.number()? != 1
        || (candidate_sha.is_some() && workflow != "release.yml")
        || (candidate_sha.is_none() && !matches!(workflow, "nightly.yml" | "release.yml"))
    {
        return Err("dependency attestation does not bind Cargo.lock".to_owned());
    }
    Ok(())
}

fn require_executable_digest(path: &Path, expected: Digest, label: &str) -> Result<(), String> {
    let observed =
        sha256_file(path).map_err(|error| format!("cannot rehash {label} executable: {error}"))?;
    if observed != expected {
        return Err(format!(
            "{label} executable changed during differential execution"
        ));
    }
    Ok(())
}

fn candidate_binary(root: &Path, release: bool) -> PathBuf {
    release_candidate_target()
        .unwrap_or_else(|| root.join("target"))
        .join(if release { "release" } else { "debug" })
        .join(format!("hell{}", std::env::consts::EXE_SUFFIX))
}

fn stack_oracle(source: &Path, report: &mut Report) -> Result<PathBuf, FailureKind> {
    let spec = CommandSpec::new("stack", Duration::from_mins(5))
        .arguments(["path", "--stack-yaml", "stack.yaml", "--local-install-root"])
        .current_directory(source);
    let result = spec.run().map_err(|_| FailureKind::Child)?;
    report.command("native-oracle-path", &spec, &result);
    if !result.status.success() {
        return Err(FailureKind::Child);
    }
    let root = String::from_utf8(result.stdout).map_err(|_| FailureKind::Fixture)?;
    Ok(PathBuf::from(root.trim())
        .join("bin")
        .join(format!("hell{}", std::env::consts::EXE_SUFFIX)))
}

fn run_command(
    root: &Path,
    report: &mut Report,
    name: &str,
    program: &str,
    arguments: &[&str],
    timeout: Duration,
) -> Result<(), FailureKind> {
    let spec = CommandSpec::new(program, timeout)
        .arguments(arguments.iter().copied())
        .current_directory(root);
    let result = spec.run().map_err(|_| FailureKind::Child)?;
    let passed = result.status.success() && !result.timed_out;
    report.command(name, &spec, &result);
    passed.then_some(()).ok_or(FailureKind::Child)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dependency_attestation_is_release_bound() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let temporary =
            std::env::temp_dir().join(format!("hell-release-dependency-{}", std::process::id()));
        fs::create_dir_all(&temporary).unwrap();
        let output = temporary.join("dependency-policy.json");
        release_dependency_attestation(&root, &output, &"a".repeat(40)).unwrap();
        assert!(fs::read_to_string(output).unwrap().contains("release.yml"));
        fs::remove_dir_all(temporary).unwrap();
    }
}
