use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use hell_testkit::{
    DifferentialBatchTiming, DifferentialCase, DifferentialMismatch, DifferentialReport,
    DifferentialTiming, Digest, ExecutableIdentity, ExecutableInvocationAuthority, ExecutableRole,
    GeneratedCase, MismatchKind, bind_process_helper_directory, committed_differential_cases,
    differential_batch_with_identities, differential_batch_with_invocations,
    differential_inventory_sha256, differential_worker_limit, generated_typed_cases,
    representative_differential_sample, sha256_bytes, sha256_file, verify_executable,
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

const WORKSPACE_TEST_TIMEOUT: Duration = Duration::from_secs(90 * 60);

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
    run_cargo_command(
        root,
        report,
        "workspace-tests",
        &[
            "test",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--locked",
        ],
        WORKSPACE_TEST_TIMEOUT,
    )?;
    run_cargo_command(
        root,
        report,
        "candidate-build",
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
    run_cargo_command(
        root,
        report,
        "portable-workspace-tests",
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
        .git_safe_directory(root)
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

pub(crate) fn native_differential_benchmark(
    root: &Path,
    report: &mut Report,
    oracle: &Path,
    candidate: &Path,
    sample_count: usize,
) -> Result<(), FailureKind> {
    policy_suite(root, report)?;
    let oracle = verify_executable(
        oracle,
        ExecutableRole::Oracle,
        None,
        hell_builtins::LANGUAGE_VERSION,
    )
    .map_err(|error| {
        report.check(
            "native-benchmark-oracle",
            Duration::ZERO,
            Err(format!("cannot verify benchmark oracle: {error}")),
        );
        FailureKind::Fixture
    })?;
    let candidate = verify_executable(
        candidate,
        ExecutableRole::Candidate,
        None,
        hell_builtins::LANGUAGE_VERSION,
    )
    .map_err(|error| {
        report.check(
            "native-benchmark-candidate",
            Duration::ZERO,
            Err(format!("cannot verify benchmark candidate: {error}")),
        );
        FailureKind::Fixture
    })?;
    report_benchmark_executable_identity(report, "oracle", &oracle).map_err(|error| {
        report.check(
            "native-benchmark-oracle-identity",
            Duration::ZERO,
            Err(error),
        );
        FailureKind::Fixture
    })?;
    report_benchmark_executable_identity(report, "candidate", &candidate).map_err(|error| {
        report.check(
            "native-benchmark-candidate-identity",
            Duration::ZERO,
            Err(error),
        );
        FailureKind::Fixture
    })?;
    report_candidate_compat_tracing_preflight(
        report,
        "native-benchmark-candidate-compat-tracing",
        &candidate,
    )
    .map_err(|_| FailureKind::Fixture)?;
    let driver = benchmark_current_driver().map_err(|error| {
        report.check(
            "native-benchmark-driver-identity",
            Duration::ZERO,
            Err(error),
        );
        FailureKind::Fixture
    })?;
    report_benchmark_artifact_identity(report, "driver", &driver).map_err(|error| {
        report.check(
            "native-benchmark-driver-identity",
            Duration::ZERO,
            Err(error),
        );
        FailureKind::Fixture
    })?;
    let inventory = native_benchmark_inventory();
    let sample = representative_differential_sample(&inventory, sample_count).map_err(|error| {
        report.check("native-benchmark-inventory", Duration::ZERO, Err(error));
        FailureKind::Policy
    })?;
    report_benchmark_inventory(report, &sample);
    let mut cases = sample.cases;
    let helper = bind_helper(&mut cases).map_err(|error| {
        report.check("native-benchmark-helper", Duration::ZERO, Err(error));
        FailureKind::Fixture
    })?;
    report_benchmark_artifact_identity(report, "helper", &helper).map_err(|error| {
        report.check(
            "native-benchmark-helper-identity",
            Duration::ZERO,
            Err(error),
        );
        FailureKind::Fixture
    })?;
    let workers = differential_worker_limit();
    let started = Instant::now();
    let batch = differential_batch_with_identities(&oracle, &candidate, &cases, workers);
    let (metrics, result) = match batch {
        Ok(batch) => {
            let metrics = DifferentialMetrics {
                timing: batch.timing,
            };
            report_benchmark_timings(
                report,
                &cases,
                &sample.selected_indices,
                &batch.case_timings,
                batch.timing,
                sample.inventory_count,
            );
            let mismatch = cases
                .iter()
                .zip(&batch.reports)
                .zip(&sample.selected_indices)
                .find(|((_, result), _)| !result.agrees())
                .map(|((case, result), inventory_index)| {
                    let details = result
                        .mismatches
                        .iter()
                        .enumerate()
                        .map(|(index, mismatch)| benchmark_mismatch_detail(index, mismatch))
                        .collect::<Vec<_>>()
                        .join("; ");
                    format!(
                        "representative case {} at authoritative index {} has {} mismatch(es): {}",
                        case.id,
                        inventory_index,
                        result.mismatches.len(),
                        details,
                    )
                });
            (metrics, mismatch.map_or(Ok(()), Err))
        }
        Err(error) => {
            let metrics = DifferentialMetrics {
                timing: error.timing,
            };
            (metrics, Err(error.to_string()))
        }
    };
    report_benchmark_metrics(report, metrics);
    let passed = result.is_ok();
    report.check("native-differential-benchmark", started.elapsed(), result);
    passed.then_some(()).ok_or(FailureKind::Fixture)
}

const BENCHMARK_MISMATCH_PREFIX_BYTES: usize = 128;

fn benchmark_mismatch_detail(index: usize, mismatch: &DifferentialMismatch) -> String {
    format!(
        "mismatch[{index}] kind={:?}, oracle[{}], candidate[{}]",
        mismatch.kind,
        benchmark_mismatch_bytes(&mismatch.oracle),
        benchmark_mismatch_bytes(&mismatch.candidate),
    )
}

fn benchmark_mismatch_bytes(bytes: &[u8]) -> String {
    let mut prefix = String::with_capacity(BENCHMARK_MISMATCH_PREFIX_BYTES.saturating_mul(2));
    for byte in bytes.iter().take(BENCHMARK_MISMATCH_PREFIX_BYTES) {
        write!(prefix, "{byte:02x}").expect("writing hexadecimal bytes to String cannot fail");
    }
    format!(
        "bytes={}, sha256={}, prefixHex={}, truncated={}",
        bytes.len(),
        sha256_bytes(bytes).hex(),
        prefix,
        bytes.len() > BENCHMARK_MISMATCH_PREFIX_BYTES,
    )
}

#[derive(Clone, Debug)]
struct BenchmarkArtifactIdentity {
    path: PathBuf,
    sha256: Digest,
    size: u64,
}

fn benchmark_current_driver() -> Result<BenchmarkArtifactIdentity, String> {
    let path = std::env::current_exe()
        .map_err(|error| format!("cannot locate benchmark driver: {error}"))?
        .canonicalize()
        .map_err(|error| format!("cannot canonicalize benchmark driver: {error}"))?;
    let sha256 =
        sha256_file(&path).map_err(|error| format!("cannot hash benchmark driver: {error}"))?;
    let size = fs::metadata(&path)
        .map_err(|error| format!("cannot inspect benchmark driver: {error}"))?
        .len();
    Ok(BenchmarkArtifactIdentity { path, sha256, size })
}

fn report_benchmark_executable_identity(
    report: &mut Report,
    name: &str,
    identity: &ExecutableIdentity,
) -> Result<(), String> {
    let size = fs::metadata(&identity.path)
        .map_err(|error| format!("cannot inspect benchmark {name}: {error}"))?
        .len();
    report.measurement(
        format!("native-benchmark-{name}-identity"),
        Duration::ZERO,
        benchmark_executable_identity_detail(identity, size)?,
    );
    Ok(())
}

fn report_executable_identity(
    report: &mut Report,
    name: &str,
    identity: &ExecutableIdentity,
) -> Result<(), String> {
    let size = fs::metadata(&identity.path)
        .map_err(|error| format!("cannot inspect differential {name}: {error}"))?
        .len();
    report.evidence(
        format!("conformance-{name}-identity"),
        executable_identity_json(identity, size)?,
    );
    Ok(())
}

fn report_executable_invocation(
    report: &mut Report,
    name: &str,
    authority: &ExecutableInvocationAuthority,
) -> Result<(), String> {
    let role = match authority.execution().role {
        ExecutableRole::Oracle => "oracle",
        ExecutableRole::Candidate => "candidate",
    };
    if role != name {
        return Err(format!(
            "differential {name} invocation has unexpected {role} role"
        ));
    }
    let source = authority
        .source()
        .path
        .to_str()
        .ok_or_else(|| format!("differential {name} source path is not UTF-8"))?;
    let execution = authority
        .execution()
        .path
        .to_str()
        .ok_or_else(|| format!("differential {name} execution path is not UTF-8"))?;
    let invocation_name = authority
        .execution()
        .path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("differential {name} invocation name is not UTF-8"))?;
    report.evidence(
        format!("conformance-{name}-invocation"),
        JsonValue::Object(BTreeMap::from([
            (
                "executionPath".to_owned(),
                JsonValue::String(execution.to_owned()),
            ),
            (
                "invocationName".to_owned(),
                JsonValue::String(invocation_name.to_owned()),
            ),
            ("role".to_owned(), JsonValue::String(role.to_owned())),
            ("schemaVersion".to_owned(), JsonValue::Number(1)),
            (
                "sha256".to_owned(),
                JsonValue::String(authority.execution().sha256.hex()),
            ),
            (
                "sourcePath".to_owned(),
                JsonValue::String(source.to_owned()),
            ),
        ])),
    );
    Ok(())
}

fn exact_oracle_invocation(
    output_root: &Path,
    source: &ExecutableIdentity,
) -> Result<ExecutableInvocationAuthority, String> {
    let exact_name = format!("hell{}", std::env::consts::EXE_SUFFIX);
    if source
        .path
        .file_name()
        .is_some_and(|name| name == std::ffi::OsStr::new(&exact_name))
    {
        return ExecutableInvocationAuthority::exact_hell(source, source)
            .map_err(|error| format!("cannot bind direct oracle invocation: {error}"));
    }
    #[cfg(not(unix))]
    {
        let _ = output_root;
        return Err("a non-Unix oracle must already have the exact hell.exe name".to_owned());
    }
    #[cfg(unix)]
    {
        let directory = output_root.join("oracle-execution");
        if directory.exists() {
            return Err("oracle execution directory already exists".to_owned());
        }
        fs::create_dir(&directory)
            .map_err(|error| format!("cannot create oracle execution directory: {error}"))?;
        let directory = fs::canonicalize(&directory)
            .map_err(|error| format!("cannot bind oracle execution directory: {error}"))?;
        let alias = directory.join(exact_name);
        fs::hard_link(&source.path, &alias)
            .map_err(|error| format!("cannot create exact oracle execution alias: {error}"))?;
        let mut execution = source.clone();
        execution.path = fs::canonicalize(&alias)
            .map_err(|error| format!("cannot canonicalize oracle execution alias: {error}"))?;
        ExecutableInvocationAuthority::exact_hell(source, &execution)
            .map_err(|error| format!("cannot bind exact oracle execution alias: {error}"))
    }
}

fn executable_identity_json(identity: &ExecutableIdentity, size: u64) -> Result<JsonValue, String> {
    let role = match identity.role {
        ExecutableRole::Oracle => "oracle",
        ExecutableRole::Candidate => "candidate",
    };
    let path = identity
        .path
        .to_str()
        .ok_or_else(|| format!("differential {role} path is not UTF-8"))?;
    let optional_digest = |value: Option<Digest>| {
        value.map_or(JsonValue::Null, |digest| JsonValue::String(digest.hex()))
    };
    let build_info = identity.build_info.as_ref().map_or_else(
        || JsonValue::Array(Vec::new()),
        |info| {
            JsonValue::Array(
                info.lines
                    .iter()
                    .map(|line| JsonValue::String(line.to_string()))
                    .collect(),
            )
        },
    );
    let build_info_schema_version = identity
        .build_info
        .as_ref()
        .map_or(JsonValue::Null, |info| {
            JsonValue::Number(info.schema_version)
        });
    let compat_tracing = identity
        .build_info
        .as_ref()
        .map_or(JsonValue::Null, |info| JsonValue::Bool(info.compat_tracing));
    Ok(JsonValue::Object(BTreeMap::from([
        (
            "acquisitionAttestationSha256".to_owned(),
            optional_digest(identity.acquisition_attestation_sha256),
        ),
        (
            "acquisitionReceiptId".to_owned(),
            identity
                .acquisition_receipt_id
                .as_deref()
                .map_or(JsonValue::Null, |value| JsonValue::String(value.to_owned())),
        ),
        (
            "acquisitionReceiptSha256".to_owned(),
            optional_digest(identity.acquisition_receipt_sha256),
        ),
        (
            "assuranceEpochSha256".to_owned(),
            optional_digest(identity.assurance_epoch_sha256),
        ),
        ("buildInfoLines".to_owned(), build_info),
        (
            "buildInfoSchemaVersion".to_owned(),
            build_info_schema_version,
        ),
        (
            "canonicalPath".to_owned(),
            JsonValue::String(path.to_owned()),
        ),
        (
            "reportedVersion".to_owned(),
            JsonValue::String(identity.reported_version.to_string()),
        ),
        ("compatTracing".to_owned(), compat_tracing),
        ("role".to_owned(), JsonValue::String(role.to_owned())),
        ("schemaVersion".to_owned(), JsonValue::Number(2)),
        (
            "sha256".to_owned(),
            JsonValue::String(identity.sha256.hex()),
        ),
        ("sizeBytes".to_owned(), JsonValue::Number(size)),
    ])))
}

fn benchmark_executable_identity_detail(
    identity: &ExecutableIdentity,
    size: u64,
) -> Result<String, String> {
    let role = match identity.role {
        ExecutableRole::Oracle => "oracle",
        ExecutableRole::Candidate => "candidate",
    };
    let path = identity
        .path
        .to_str()
        .ok_or_else(|| format!("benchmark {role} path is not UTF-8"))?;
    let optional_digest =
        |value: Option<Digest>| value.map_or_else(|| "none".to_owned(), |digest| digest.hex());
    let receipt_id = identity
        .acquisition_receipt_id
        .as_deref()
        .map_or_else(|| "none".to_owned(), |value| format!("{value:?}"));
    let build_info = identity
        .build_info
        .as_ref()
        .map_or_else(|| "none".to_owned(), |info| format!("{:?}", info.lines));
    let build_info_schema_version = identity
        .build_info
        .as_ref()
        .map_or_else(|| "none".to_owned(), |info| info.schema_version.to_string());
    let compat_tracing = identity
        .build_info
        .as_ref()
        .map_or_else(|| "none".to_owned(), |info| info.compat_tracing.to_string());
    Ok(format!(
        "role={role}, canonicalPath={path:?}, sizeBytes={size}, sha256={}, reportedVersion={:?}, assuranceEpochSha256={}, acquisitionReceiptId={}, acquisitionReceiptSha256={}, acquisitionAttestationSha256={}, buildInfoSchemaVersion={}, compatTracing={}, buildInfoLines={}",
        identity.sha256.hex(),
        identity.reported_version,
        optional_digest(identity.assurance_epoch_sha256),
        receipt_id,
        optional_digest(identity.acquisition_receipt_sha256),
        optional_digest(identity.acquisition_attestation_sha256),
        build_info_schema_version,
        compat_tracing,
        build_info,
    ))
}

fn report_candidate_compat_tracing_preflight(
    report: &mut Report,
    name: &str,
    identity: &ExecutableIdentity,
) -> Result<(), String> {
    match hell_testkit::verify_compat_tracing_candidate_identity(identity) {
        Ok(()) => {
            report.check(name, Duration::ZERO, Ok(()));
            Ok(())
        }
        Err(error) => {
            let detail = format!("candidate compatibility tracing attestation failed: {error}");
            report.check(name, Duration::ZERO, Err(detail.clone()));
            Err(detail)
        }
    }
}

fn report_benchmark_artifact_identity(
    report: &mut Report,
    name: &str,
    identity: &BenchmarkArtifactIdentity,
) -> Result<(), String> {
    let path = identity
        .path
        .to_str()
        .ok_or_else(|| format!("benchmark {name} path is not UTF-8"))?;
    report.measurement(
        format!("native-benchmark-{name}-identity"),
        Duration::ZERO,
        format!(
            "role={name}, canonicalPath={path:?}, sizeBytes={}, sha256={}",
            identity.size,
            identity.sha256.hex(),
        ),
    );
    Ok(())
}

fn report_artifact_identity(
    report: &mut Report,
    name: &str,
    identity: &BenchmarkArtifactIdentity,
) -> Result<(), String> {
    let path = identity
        .path
        .to_str()
        .ok_or_else(|| format!("differential {name} path is not UTF-8"))?;
    report.evidence(
        format!("conformance-{name}-identity"),
        JsonValue::Object(BTreeMap::from([
            (
                "canonicalPath".to_owned(),
                JsonValue::String(path.to_owned()),
            ),
            ("role".to_owned(), JsonValue::String(name.to_owned())),
            ("schemaVersion".to_owned(), JsonValue::Number(1)),
            (
                "sha256".to_owned(),
                JsonValue::String(identity.sha256.hex()),
            ),
            ("sizeBytes".to_owned(), JsonValue::Number(identity.size)),
        ])),
    );
    Ok(())
}

fn differential_mismatch_summary(
    authoritative_index: usize,
    case: &DifferentialCase,
    report: &DifferentialReport,
) -> Result<JsonValue, String> {
    let mismatch = report
        .mismatches
        .iter()
        .map(|mismatch| {
            Ok(JsonValue::Object(BTreeMap::from([
                (
                    "candidate".to_owned(),
                    mismatch_side_json(&mismatch.candidate)?,
                ),
                (
                    "kind".to_owned(),
                    JsonValue::String(mismatch_kind_name(mismatch.kind).to_owned()),
                ),
                ("oracle".to_owned(), mismatch_side_json(&mismatch.oracle)?),
            ])))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let mut summary = BTreeMap::from([
        (
            "authoritativeIndex".to_owned(),
            JsonValue::Number(
                authoritative_index
                    .try_into()
                    .map_err(|_| "differential authoritative index overflow")?,
            ),
        ),
        (
            "candidate".to_owned(),
            observation_status_json(&report.candidate),
        ),
        ("caseId".to_owned(), JsonValue::String(case.id.to_string())),
        ("mismatches".to_owned(), JsonValue::Array(mismatch)),
        ("oracle".to_owned(), observation_status_json(&report.oracle)),
    ]);
    if let Some(rejection) =
        hell_testkit::runtime_failure_projection_rejection(case, &report.oracle, &report.candidate)
    {
        summary.insert(
            "strictProjectionRejection".to_owned(),
            runtime_failure_projection_rejection_json(&rejection)?,
        );
    }
    Ok(JsonValue::Object(summary))
}

#[cfg(any(windows, test))]
const WINDOWS_SUBSTANTIVE_SERIAL_PROBES: &[(usize, &str)] = &[
    (865, "runtime-typed-thread-delay-forced-argument-failure"),
    (1081, "runtime-directory-copy-file-failure"),
    (2658, "runtime-interaction-timeout-process"),
];

#[cfg(any(windows, test))]
fn windows_substantive_serial_probe_cases(
    cases: &[DifferentialCase],
) -> Result<Vec<(usize, DifferentialCase)>, String> {
    WINDOWS_SUBSTANTIVE_SERIAL_PROBES
        .iter()
        .map(|&(index, expected_id)| {
            let case = cases.get(index).ok_or_else(|| {
                format!("Windows substantive serial probe index {index} is absent")
            })?;
            if case.id.as_ref() != expected_id {
                return Err(format!(
                    "Windows substantive serial probe index {index} resolved to {:?}, expected {expected_id:?}",
                    case.id,
                ));
            }
            Ok((index, case.clone()))
        })
        .collect()
}

fn runtime_failure_projection_rejection_json(
    rejection: &hell_testkit::RuntimeFailureProjectionRejection,
) -> Result<JsonValue, String> {
    let count = |value: usize| {
        value
            .try_into()
            .map(JsonValue::Number)
            .map_err(|_| "runtime failure projection diagnostic count overflow".to_owned())
    };
    Ok(JsonValue::Object(BTreeMap::from([
        (
            "candidateStderrBytes".to_owned(),
            JsonValue::Number(rejection.candidate_stderr_bytes),
        ),
        (
            "candidateStderrSha256".to_owned(),
            JsonValue::String(rejection.candidate_stderr_sha256.hex()),
        ),
        (
            "causalOrderCount".to_owned(),
            count(rejection.causal_order_count)?,
        ),
        (
            "descriptorBuiltin".to_owned(),
            JsonValue::String(rejection.descriptor_builtin.to_owned()),
        ),
        (
            "descriptorDimension".to_owned(),
            JsonValue::String(
                compatibility_dimension_name(rejection.descriptor_dimension).to_owned(),
            ),
        ),
        (
            "descriptorObligation".to_owned(),
            JsonValue::String(rejection.descriptor_obligation.to_owned()),
        ),
        (
            "effectEventCount".to_owned(),
            count(rejection.effect_event_count)?,
        ),
        (
            "exceptionFamily".to_owned(),
            JsonValue::String(rejection.exception_family.descriptor_name().to_owned()),
        ),
        (
            "forceEventCount".to_owned(),
            count(rejection.force_event_count)?,
        ),
        (
            "obligationEventCount".to_owned(),
            count(rejection.obligation_event_count)?,
        ),
        (
            "oracleStderrBytes".to_owned(),
            JsonValue::Number(rejection.oracle_stderr_bytes),
        ),
        (
            "oracleStderrSha256".to_owned(),
            JsonValue::String(rejection.oracle_stderr_sha256.hex()),
        ),
        (
            "reason".to_owned(),
            JsonValue::String(rejection.reason.descriptor_name().to_owned()),
        ),
        (
            "resourceEventCount".to_owned(),
            count(rejection.resource_event_count)?,
        ),
        (
            "semanticCoverageCount".to_owned(),
            count(rejection.semantic_coverage_count)?,
        ),
        (
            "semanticPresent".to_owned(),
            JsonValue::Bool(rejection.semantic_present),
        ),
        (
            "taskEventCount".to_owned(),
            count(rejection.task_event_count)?,
        ),
        (
            "typedResultBuiltinPresent".to_owned(),
            JsonValue::Bool(rejection.typed_result_builtin_present),
        ),
        (
            "typedResultSha256Present".to_owned(),
            JsonValue::Bool(rejection.typed_result_sha256_present),
        ),
    ])))
}

const fn compatibility_dimension_name(
    dimension: hell_builtins::CompatibilityDimension,
) -> &'static str {
    use hell_builtins::CompatibilityDimension;
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

fn observation_status_json(observation: &hell_testkit::Observation) -> JsonValue {
    process_status_json(
        observation.timed_out,
        observation.status.success,
        observation.status.code,
    )
}

fn process_status_json(timed_out: bool, success: bool, code: Option<i32>) -> JsonValue {
    let code = code.map_or(JsonValue::Null, |code| JsonValue::String(code.to_string()));
    JsonValue::Object(BTreeMap::from([
        ("exitCode".to_owned(), code),
        ("success".to_owned(), JsonValue::Bool(success)),
        ("timedOut".to_owned(), JsonValue::Bool(timed_out)),
    ]))
}

fn mismatch_side_json(bytes: &[u8]) -> Result<JsonValue, String> {
    let mut prefix = String::with_capacity(BENCHMARK_MISMATCH_PREFIX_BYTES.saturating_mul(2));
    for byte in bytes.iter().take(BENCHMARK_MISMATCH_PREFIX_BYTES) {
        write!(prefix, "{byte:02x}").expect("writing hexadecimal bytes to String cannot fail");
    }
    Ok(JsonValue::Object(BTreeMap::from([
        (
            "bytes".to_owned(),
            JsonValue::Number(
                bytes
                    .len()
                    .try_into()
                    .map_err(|_| "differential mismatch side length overflow")?,
            ),
        ),
        ("prefixHex".to_owned(), JsonValue::String(prefix)),
        (
            "prefixTruncated".to_owned(),
            JsonValue::Bool(bytes.len() > BENCHMARK_MISMATCH_PREFIX_BYTES),
        ),
        (
            "sha256".to_owned(),
            JsonValue::String(sha256_bytes(bytes).hex()),
        ),
    ])))
}

fn mismatch_kind_name(kind: MismatchKind) -> &'static str {
    match kind {
        MismatchKind::Timeout => "timeout",
        MismatchKind::ExitStatus => "exit-status",
        MismatchKind::Stdout => "stdout",
        MismatchKind::Stderr => "stderr",
        MismatchKind::Diagnostic => "diagnostic",
        MismatchKind::Filesystem => "filesystem",
    }
}

struct DifferentialInventoryEvidence {
    authoritative_case_count: usize,
    authoritative_inventory_sha256: Digest,
    combined_inventory_count: usize,
    combined_inventory_sha256: Digest,
    generated_case_count: usize,
    generated_seed: u64,
    mismatches: Vec<JsonValue>,
}

fn differential_inventory_evidence_json(
    evidence: DifferentialInventoryEvidence,
) -> Result<JsonValue, String> {
    let mismatch_count = evidence.mismatches.len();
    Ok(JsonValue::Object(BTreeMap::from([
        (
            "authoritativeCaseCount".to_owned(),
            JsonValue::Number(
                evidence
                    .authoritative_case_count
                    .try_into()
                    .map_err(|_| "committed differential case count overflow")?,
            ),
        ),
        (
            "authoritativeInventorySha256".to_owned(),
            JsonValue::String(evidence.authoritative_inventory_sha256.hex()),
        ),
        ("cases".to_owned(), JsonValue::Array(evidence.mismatches)),
        (
            "combinedInventoryCount".to_owned(),
            JsonValue::Number(
                evidence
                    .combined_inventory_count
                    .try_into()
                    .map_err(|_| "combined differential case count overflow")?,
            ),
        ),
        (
            "combinedInventorySha256".to_owned(),
            JsonValue::String(evidence.combined_inventory_sha256.hex()),
        ),
        (
            "generatedCaseCount".to_owned(),
            JsonValue::Number(
                evidence
                    .generated_case_count
                    .try_into()
                    .map_err(|_| "generated differential case count overflow")?,
            ),
        ),
        (
            "generatedSeed".to_owned(),
            JsonValue::Number(evidence.generated_seed),
        ),
        (
            "mismatchCount".to_owned(),
            JsonValue::Number(
                mismatch_count
                    .try_into()
                    .map_err(|_| "committed mismatch count overflow")?,
            ),
        ),
        ("schemaVersion".to_owned(), JsonValue::Number(1)),
    ])))
}

fn native_benchmark_inventory() -> Vec<DifferentialCase> {
    let mut inventory = committed_differential_cases();
    inventory.extend(
        generated_typed_cases(0x4845_4c4c, 32)
            .into_iter()
            .map(|case| DifferentialCase {
                id: case.id,
                source: case.source,
                ..DifferentialCase::default()
            }),
    );
    inventory
}

fn report_benchmark_inventory(
    report: &mut Report,
    sample: &hell_testkit::RepresentativeDifferentialSample,
) {
    let selected = sample
        .selected_indices
        .iter()
        .zip(&sample.cases)
        .map(|(index, case)| format!("{index}:{:?}", case.id))
        .collect::<Vec<_>>()
        .join(",");
    report.measurement(
        "native-benchmark-inventory",
        Duration::ZERO,
        format!(
            "authoritative=false, inventoryCount={}, inventorySha256={}, sampleCount={}, selected=[{}]",
            sample.inventory_count,
            sample.inventory_sha256.hex(),
            sample.cases.len(),
            selected,
        ),
    );
}

fn report_benchmark_metrics(report: &mut Report, metrics: DifferentialMetrics) {
    report.measurement(
        "native-benchmark-oracle-execution",
        metrics.timing.oracle_process_sum,
        metrics.detail(),
    );
    report.measurement(
        "native-benchmark-candidate-execution",
        metrics.timing.candidate_process_sum,
        metrics.detail(),
    );
    report.measurement(
        "native-benchmark-driver-overhead",
        metrics.timing.driver_overhead_sum,
        metrics.detail(),
    );
}

fn report_benchmark_timings(
    report: &mut Report,
    cases: &[DifferentialCase],
    inventory_indices: &[usize],
    timings: &[DifferentialTiming],
    aggregate: DifferentialBatchTiming,
    inventory_count: usize,
) {
    debug_assert_eq!(cases.len(), inventory_indices.len());
    debug_assert_eq!(cases.len(), timings.len());
    for (sample_index, ((case, inventory_index), timing)) in
        cases.iter().zip(inventory_indices).zip(timings).enumerate()
    {
        let total = timing
            .oracle_process
            .saturating_add(timing.candidate_process)
            .saturating_add(timing.driver_overhead);
        report.measurement(
            format!("native-benchmark-case-{sample_index:03}"),
            total,
            format!(
                "authoritativeIndex={inventory_index}, caseId={:?}, oracleMicros={}, candidateMicros={}, driverMicros={}, totalMicros={}",
                case.id,
                timing.oracle_process.as_micros(),
                timing.candidate_process.as_micros(),
                timing.driver_overhead.as_micros(),
                total.as_micros(),
            ),
        );
    }
    let oracle = timings
        .iter()
        .map(|timing| timing.oracle_process.as_micros())
        .collect::<Vec<_>>();
    let candidate = timings
        .iter()
        .map(|timing| timing.candidate_process.as_micros())
        .collect::<Vec<_>>();
    let driver = timings
        .iter()
        .map(|timing| timing.driver_overhead.as_micros())
        .collect::<Vec<_>>();
    let total = timings
        .iter()
        .map(|timing| {
            timing
                .oracle_process
                .saturating_add(timing.candidate_process)
                .saturating_add(timing.driver_overhead)
                .as_micros()
        })
        .collect::<Vec<_>>();
    report.measurement(
        "native-benchmark-distribution",
        aggregate.wall,
        [
            timing_distribution_detail("oracle", &oracle, cases, inventory_indices),
            timing_distribution_detail("candidate", &candidate, cases, inventory_indices),
            timing_distribution_detail("driver", &driver, cases, inventory_indices),
            timing_distribution_detail("total", &total, cases, inventory_indices),
        ]
        .join("; "),
    );
    let projected_full_wall_micros = aggregate
        .wall
        .as_micros()
        .saturating_mul(inventory_count as u128)
        .div_ceil(cases.len() as u128);
    report.measurement(
        "native-benchmark-projection",
        aggregate.wall,
        format!(
            "sampleWallMicros={}, sampleCount={}, inventoryCount={}, projectedFullDifferentialWallMicros={}, workerCount={}; projection is non-authoritative and timing never participates in conformance",
            aggregate.wall.as_micros(),
            cases.len(),
            inventory_count,
            projected_full_wall_micros,
            aggregate.worker_count,
        ),
    );
}

fn timing_distribution_detail(
    role: &str,
    values: &[u128],
    cases: &[DifferentialCase],
    inventory_indices: &[usize],
) -> String {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let percentile = |percent: usize| {
        let rank = values.len().saturating_mul(percent).div_ceil(100);
        sorted[rank.clamp(1, sorted.len()) - 1]
    };
    let mut worst = 0;
    for index in 1..values.len() {
        if values[index] > values[worst] {
            worst = index;
        }
    }
    format!(
        "{role}Micros[p50={},p95={},p99={},max={},worstAuthoritativeIndex={},worstCaseId={:?}]",
        percentile(50),
        percentile(95),
        percentile(99),
        values[worst],
        inventory_indices[worst],
        cases[worst].id,
    )
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
    crate::command::verify_pinned_oracle_checkout(source).map_err(|_| FailureKind::Fixture)?;
    let archive_adapter = crate::command::NativeArchiveAdapter::for_macos(
        platform == "macos-arm64",
        &root.join("target"),
        source,
        None,
    );
    let archive_adapter = match archive_adapter {
        Ok(adapter) => adapter,
        Err(error) => {
            report.check("native-archiver-setup", Duration::ZERO, Err(error));
            return Err(FailureKind::Child);
        }
    };
    if let Some(identity) = archive_adapter.identity_command() {
        run_spec(report, "native-archiver-identity", &identity)?;
    }
    let build = archive_adapter.stack_build(source, Duration::from_hours(2));
    let path = archive_adapter.stack_path(source);
    let provenance = archive_adapter.stack_provenance(source).map_err(|error| {
        report.check("native-stack-provenance", Duration::ZERO, Err(error));
        FailureKind::Fixture
    })?;
    report_native_stack_provenance(report, &provenance, &build, &path).map_err(|error| {
        report.check("native-stack-provenance", Duration::ZERO, Err(error));
        FailureKind::Fixture
    })?;
    run_spec(report, "native-oracle-build", &build)?;
    let oracle = stack_oracle(report, &path)?;
    crate::command::verify_pinned_oracle_checkout(source).map_err(|_| FailureKind::Fixture)?;
    differential_gate(
        root,
        report,
        failures,
        &oracle,
        None,
        &candidate_binary(root, true),
        dependency,
        candidate_sha,
    )?;
    crate::command::verify_pinned_oracle_checkout(source).map_err(|_| FailureKind::Fixture)
}

fn report_native_stack_provenance(
    report: &mut Report,
    provenance: &crate::command::NativeStackProvenance,
    build: &CommandSpec,
    path: &CommandSpec,
) -> Result<(), String> {
    let utf8_path = |label: &str, value: &Path| {
        value
            .to_str()
            .map(str::to_owned)
            .ok_or_else(|| format!("native {label} path is not UTF-8"))
    };
    let optional_path = provenance
        .llvm_ar
        .as_deref()
        .map(|value| utf8_path("LLVM archiver", value).map(JsonValue::String))
        .transpose()?
        .unwrap_or(JsonValue::Null);
    let optional_digest = provenance
        .llvm_ar_sha256
        .map_or(JsonValue::Null, |value| JsonValue::String(value.hex()));
    let optional_version = provenance
        .llvm_ar_version
        .as_ref()
        .map_or(JsonValue::Null, |value| JsonValue::String(value.clone()));
    report.evidence(
        "native-stack-provenance",
        JsonValue::Object(BTreeMap::from([
            ("buildCommand".to_owned(), command_json(build)),
            (
                "effectiveStackYaml".to_owned(),
                JsonValue::String(utf8_path(
                    "effective Stack configuration",
                    &provenance.effective_stack_yaml,
                )?),
            ),
            (
                "effectiveStackYamlSha256".to_owned(),
                JsonValue::String(provenance.effective_stack_yaml_sha256.hex()),
            ),
            ("llvmAr".to_owned(), optional_path),
            ("llvmArSha256".to_owned(), optional_digest),
            ("llvmArVersion".to_owned(), optional_version),
            ("pathCommand".to_owned(), command_json(path)),
            ("schemaVersion".to_owned(), JsonValue::Number(1)),
            (
                "sourceCommit".to_owned(),
                JsonValue::String(provenance.source_commit.to_owned()),
            ),
            (
                "sourcePath".to_owned(),
                JsonValue::String(utf8_path("oracle source", &provenance.source)?),
            ),
            (
                "stackLockSha256".to_owned(),
                JsonValue::String(provenance.stack_lock_sha256.hex()),
            ),
            (
                "stackYamlSha256".to_owned(),
                JsonValue::String(provenance.stack_yaml_sha256.hex()),
            ),
        ])),
    );
    Ok(())
}

fn command_json(spec: &CommandSpec) -> JsonValue {
    JsonValue::Object(BTreeMap::from([
        (
            "arguments".to_owned(),
            JsonValue::Array(
                spec.display_arguments()
                    .into_iter()
                    .map(JsonValue::String)
                    .collect(),
            ),
        ),
        (
            "program".to_owned(),
            JsonValue::String(spec.display_program()),
        ),
    ]))
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
        report,
        DifferentialExecution {
            root,
            failures,
            oracle,
            oracle_digest,
            candidate,
            dependency,
            candidate_sha,
        },
    );
    let (metrics, result) = match result {
        Ok(outcome) => {
            let result = if outcome.committed_mismatches == 0 {
                Ok(())
            } else {
                Err(format!(
                    "{} committed differential cases mismatch",
                    outcome.committed_mismatches
                ))
            };
            (Some(outcome.metrics), result)
        }
        Err(error) => (None, Err(error)),
    };
    let passed = result.is_ok();
    if let Some(metrics) = metrics {
        report_differential_metrics(report, metrics);
    }
    report.check("conformance-differential", started.elapsed(), result);
    passed.then_some(()).ok_or(FailureKind::Fixture)
}

fn report_differential_metrics(report: &mut Report, metrics: DifferentialMetrics) {
    report.measurement(
        "conformance-oracle-execution",
        metrics.timing.oracle_process_sum,
        metrics.detail(),
    );
    report.measurement(
        "conformance-candidate-execution",
        metrics.timing.candidate_process_sum,
        metrics.detail(),
    );
    report.measurement(
        "conformance-driver-overhead",
        metrics.timing.driver_overhead_sum,
        metrics.detail(),
    );
}

#[derive(Clone, Copy, Debug, Default)]
struct DifferentialMetrics {
    timing: DifferentialBatchTiming,
}

#[derive(Clone, Copy, Debug, Default)]
struct DifferentialOutcome {
    metrics: DifferentialMetrics,
    committed_mismatches: usize,
}

impl DifferentialMetrics {
    fn add(&mut self, timing: DifferentialBatchTiming) {
        self.timing.case_count = self.timing.case_count.saturating_add(timing.case_count);
        self.timing.completed_count = self
            .timing
            .completed_count
            .saturating_add(timing.completed_count);
        self.timing.worker_count = self.timing.worker_count.max(timing.worker_count);
        self.timing.wall = self.timing.wall.saturating_add(timing.wall);
        self.timing.oracle_process_sum = self
            .timing
            .oracle_process_sum
            .saturating_add(timing.oracle_process_sum);
        self.timing.candidate_process_sum = self
            .timing
            .candidate_process_sum
            .saturating_add(timing.candidate_process_sum);
        self.timing.driver_overhead_sum = self
            .timing
            .driver_overhead_sum
            .saturating_add(timing.driver_overhead_sum);
    }

    fn detail(self) -> String {
        format!(
            "caseCount={}, completedCount={}, workerCount={}, batchWallMillis={}, oracleProcessSumMillis={}, candidateProcessSumMillis={}, driverOverheadSumMillis={}; process sums can exceed wall when workers overlap and timing never participates in conformance",
            self.timing.case_count,
            self.timing.completed_count,
            self.timing.worker_count,
            self.timing.wall.as_millis(),
            self.timing.oracle_process_sum.as_millis(),
            self.timing.candidate_process_sum.as_millis(),
            self.timing.driver_overhead_sum.as_millis(),
        )
    }
}

fn batch_failure(error: Box<hell_testkit::DifferentialBatchFailure>) -> String {
    let timing = DifferentialMetrics {
        timing: error.timing,
    };
    format!("{error}; {}", timing.detail())
}

struct DifferentialExecution<'a> {
    root: &'a Path,
    failures: &'a Path,
    oracle: &'a Path,
    oracle_digest: Option<Digest>,
    candidate: &'a Path,
    dependency: &'a Path,
    candidate_sha: Option<&'a str>,
}

fn run_differential(
    report: &mut Report,
    execution: DifferentialExecution<'_>,
) -> Result<DifferentialOutcome, String> {
    verify_dependency(
        execution.root,
        execution.dependency,
        execution.candidate_sha,
    )?;
    let oracle_source = verify_executable(
        execution.oracle,
        ExecutableRole::Oracle,
        execution.oracle_digest,
        hell_builtins::LANGUAGE_VERSION,
    )
    .map_err(|error| format!("cannot verify oracle: {error}"))?;
    let candidate_identity = verify_executable(
        execution.candidate,
        ExecutableRole::Candidate,
        None,
        hell_builtins::LANGUAGE_VERSION,
    )
    .map_err(|error| format!("cannot verify candidate: {error}"))?;
    let output_root = execution
        .failures
        .parent()
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(output_root)
        .map_err(|error| format!("cannot create differential output: {error}"))?;
    let oracle = exact_oracle_invocation(output_root, &oracle_source)?;
    let candidate =
        ExecutableInvocationAuthority::exact_hell(&candidate_identity, &candidate_identity)
            .map_err(|error| format!("cannot bind exact candidate invocation: {error}"))?;
    report_executable_identity(report, "oracle", &oracle_source)?;
    report_executable_identity(report, "candidate", &candidate_identity)?;
    report_executable_invocation(report, "oracle", &oracle)?;
    report_executable_invocation(report, "candidate", &candidate)?;
    report_candidate_compat_tracing_preflight(
        report,
        "conformance-candidate-compat-tracing",
        &candidate_identity,
    )?;
    let driver = benchmark_current_driver()?;
    report_artifact_identity(report, "driver", &driver)?;
    run_differential_identities(
        execution.root,
        report,
        execution.failures,
        oracle,
        candidate,
    )
}

fn run_differential_identities(
    root: &Path,
    report: &mut Report,
    failures: &Path,
    oracle: ExecutableInvocationAuthority,
    candidate: ExecutableInvocationAuthority,
) -> Result<DifferentialOutcome, String> {
    const GENERATED_SEED: u64 = 0x4845_4c4c;
    let mut cases = committed_differential_cases();
    let committed_inventory_sha256 = differential_inventory_sha256(&cases)?;
    let generated = generated_typed_cases(GENERATED_SEED, 32);
    let mut combined_inventory = cases.clone();
    combined_inventory.extend(generated.iter().map(|case| DifferentialCase {
        id: case.id.clone(),
        source: case.source.clone(),
        ..DifferentialCase::default()
    }));
    let combined_inventory_sha256 = differential_inventory_sha256(&combined_inventory)?;
    let combined_inventory_count = combined_inventory.len();
    let helper = bind_helper(&mut cases)?;
    report_artifact_identity(report, "helper", &helper)?;
    let output_root = failures.parent().unwrap_or_else(|| Path::new("."));
    let mut cells = reviewed_compatibility_cells()?;
    let reviewed_cells = cells.len();
    let mut committed_mismatches = Vec::new();
    let workers = differential_worker_limit();
    let committed = differential_batch_with_invocations(&oracle, &candidate, &cases, workers)
        .map_err(batch_failure)?;
    let mut metrics = DifferentialMetrics::default();
    metrics.add(committed.timing);
    for (authoritative_index, (case, result)) in cases.iter().zip(committed.reports).enumerate() {
        let status = if matches!(
            result.comparison_projection,
            hell_testkit::DifferentialComparisonProjection::ReviewedWindowsDivergence { .. }
        ) {
            "deliberate-divergence"
        } else if result.agrees() {
            "exact"
        } else {
            "unverified"
        };
        if !result.agrees() {
            committed_mismatches.push(differential_mismatch_summary(
                authoritative_index,
                case,
                &result,
            )?);
        }
        cells.push(JsonValue::Object(BTreeMap::from([
            ("caseId".to_owned(), JsonValue::String(case.id.to_string())),
            ("status".to_owned(), JsonValue::String(status.to_owned())),
        ])));
    }
    let committed_mismatch_count = committed_mismatches.len();
    report.evidence(
        "conformance-differential-mismatches",
        differential_inventory_evidence_json(DifferentialInventoryEvidence {
            authoritative_case_count: cases.len(),
            authoritative_inventory_sha256: committed_inventory_sha256,
            combined_inventory_count,
            combined_inventory_sha256,
            generated_case_count: generated.len(),
            generated_seed: GENERATED_SEED,
            mismatches: committed_mismatches,
        })?,
    );
    #[cfg(windows)]
    {
        let probes = windows_substantive_serial_probe_cases(&cases)?;
        let probe_cases = probes
            .iter()
            .map(|(_, case)| case.clone())
            .collect::<Vec<_>>();
        let batch = differential_batch_with_invocations(&oracle, &candidate, &probe_cases, 1)
            .map_err(batch_failure)?;
        metrics.add(batch.timing);
        let observations = probes
            .iter()
            .zip(batch.reports)
            .map(|((index, case), observation)| {
                differential_mismatch_summary(*index, case, &observation)
            })
            .collect::<Result<Vec<_>, _>>()?;
        report.evidence(
            "conformance-substantive-serial-probes",
            JsonValue::Object(BTreeMap::from([
                ("cases".to_owned(), JsonValue::Array(observations)),
                ("schemaVersion".to_owned(), JsonValue::Number(1)),
                ("workerCount".to_owned(), JsonValue::Number(1)),
            ])),
        );
    }
    let mut generated_mismatches = Vec::new();
    let generated_cases = generated
        .iter()
        .map(|case| DifferentialCase {
            id: case.id.clone(),
            source: case.source.clone(),
            ..DifferentialCase::default()
        })
        .collect::<Vec<_>>();
    let generated_batch =
        differential_batch_with_invocations(&oracle, &candidate, &generated_cases, workers)
            .map_err(batch_failure)?;
    metrics.add(generated_batch.timing);
    for (case, result) in generated.iter().zip(generated_batch.reports) {
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
            cases.len().saturating_sub(committed_mismatch_count),
            unverified_cells,
            out_of_scope_cells
        )
        .as_bytes(),
    )?;
    Ok(DifferentialOutcome {
        metrics,
        committed_mismatches: committed_mismatch_count,
    })
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

fn bind_helper(cases: &mut [DifferentialCase]) -> Result<BenchmarkArtifactIdentity, String> {
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
    let sha256 = bind_process_helper_directory(cases, profile)?;
    let path = profile
        .join(format!("hell-test-helper{}", std::env::consts::EXE_SUFFIX))
        .canonicalize()
        .map_err(|error| format!("cannot canonicalize process helper: {error}"))?;
    let size = fs::metadata(&path)
        .map_err(|error| format!("cannot inspect process helper: {error}"))?
        .len();
    Ok(BenchmarkArtifactIdentity { path, sha256, size })
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

fn candidate_binary(root: &Path, release: bool) -> PathBuf {
    release_candidate_target()
        .unwrap_or_else(|| root.join("target"))
        .join(if release { "release" } else { "debug" })
        .join(format!("hell{}", std::env::consts::EXE_SUFFIX))
}

fn stack_oracle(report: &mut Report, spec: &CommandSpec) -> Result<PathBuf, FailureKind> {
    let result = report
        .run_command("native-oracle-path", spec)
        .map_err(|_| FailureKind::Child)?;
    if !result.status.success() {
        return Err(FailureKind::Child);
    }
    let root = String::from_utf8(result.stdout).map_err(|_| FailureKind::Fixture)?;
    Ok(PathBuf::from(root.trim())
        .join("bin")
        .join(format!("hell{}", std::env::consts::EXE_SUFFIX)))
}

fn run_spec(report: &mut Report, name: &str, spec: &CommandSpec) -> Result<(), FailureKind> {
    let result = report
        .run_command(name, spec)
        .map_err(|_| FailureKind::Child)?;
    let passed = result.status.success() && !result.timed_out;
    passed.then_some(()).ok_or(FailureKind::Child)
}

fn run_cargo_command(
    root: &Path,
    report: &mut Report,
    name: &str,
    arguments: &[&str],
    timeout: Duration,
) -> Result<(), FailureKind> {
    let spec = CommandSpec::cargo(timeout)
        .arguments(arguments.iter().copied())
        .current_directory(root);
    let result = report
        .run_command(name, &spec)
        .map_err(|_| FailureKind::Child)?;
    let passed = result.status.success() && !result.timed_out;
    passed.then_some(()).ok_or(FailureKind::Child)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_substantive_serial_probes_bind_exact_inventory_positions() {
        let cases = committed_differential_cases();
        let probes = windows_substantive_serial_probe_cases(&cases).unwrap();
        assert_eq!(
            probes
                .iter()
                .map(|(index, case)| (*index, case.id.as_ref()))
                .collect::<Vec<_>>(),
            WINDOWS_SUBSTANTIVE_SERIAL_PROBES,
        );

        let mut substituted = cases;
        substituted[WINDOWS_SUBSTANTIVE_SERIAL_PROBES[0].0].id =
            std::sync::Arc::from("substituted");
        assert!(windows_substantive_serial_probe_cases(&substituted).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn oracle_execution_alias_is_exactly_named_and_reported_separately_from_source() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = std::env::temp_dir().join(format!(
            "hell-oracle-execution-report-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let source_path = root.join("linux-release-oracle");
        // Keep this reporting probe off the live test executable used by later
        // multicall launch tests.
        let oracle_fixture = b"dedicated oracle execution fixture";
        fs::write(&source_path, oracle_fixture).unwrap();
        fs::set_permissions(&source_path, fs::Permissions::from_mode(0o755)).unwrap();
        let source_path = source_path.canonicalize().unwrap();
        let source = ExecutableIdentity {
            sha256: sha256_bytes(oracle_fixture),
            path: source_path.clone(),
            reported_version: hell_builtins::LANGUAGE_VERSION.into(),
            build_info: None,
            role: ExecutableRole::Oracle,
            assurance_epoch_sha256: None,
            acquisition_receipt_id: Some("pinned-release".into()),
            acquisition_receipt_sha256: Some(sha256_bytes(b"receipt")),
            acquisition_attestation_sha256: Some(sha256_bytes(b"attestation")),
        };
        let authority = exact_oracle_invocation(&root, &source).unwrap();
        assert_eq!(authority.source(), &source);
        let expected_name = format!("hell{}", std::env::consts::EXE_SUFFIX);
        assert_eq!(
            authority.execution().path.file_name().unwrap(),
            std::ffi::OsStr::new(&expected_name)
        );
        assert_ne!(authority.source().path, authority.execution().path);
        let mut report = Report::new("oracle-execution-report");
        report_executable_identity(&mut report, "oracle", authority.source()).unwrap();
        report_executable_invocation(&mut report, "oracle", &authority).unwrap();
        let json = report.to_json();
        assert!(json.contains("\"name\": \"conformance-oracle-identity\""));
        assert!(json.contains("\"name\": \"conformance-oracle-invocation\""));
        assert!(json.contains(source_path.to_str().unwrap()));
        assert!(json.contains(authority.execution().path.to_str().unwrap()));
        assert!(json.contains("\"invocationName\":\"hell\""));
        assert!(exact_oracle_invocation(&root, &source).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn benchmark_inventory_is_the_exact_committed_then_generated_authority() {
        let committed = committed_differential_cases();
        let generated = generated_typed_cases(0x4845_4c4c, 32);
        let inventory = native_benchmark_inventory();
        assert_eq!(committed.len(), 2_662);
        assert_eq!(generated.len(), 32);
        assert_eq!(inventory.len(), 2_694);
        for strictness_case in [
            "runtime-typed-map-singleton-key-strict",
            "runtime-typed-map-singleton-value-nonforce",
            "runtime-typed-set-singleton-element-strict",
        ] {
            assert_eq!(
                committed
                    .iter()
                    .filter(|case| case.id.as_ref() == strictness_case)
                    .count(),
                1,
                "singleton strictness split case {strictness_case} is not exact"
            );
        }
        assert_eq!(inventory.first().unwrap().id, committed.first().unwrap().id);
        assert_eq!(inventory[committed.len()].id, generated.first().unwrap().id);
        assert_eq!(inventory.last().unwrap().id, generated.last().unwrap().id);
        let first = representative_differential_sample(&inventory, 256).unwrap();
        let second = representative_differential_sample(&inventory, 256).unwrap();
        assert_eq!(first.inventory_count, 2_694);
        assert_eq!(first.inventory_sha256, second.inventory_sha256);
        assert_eq!(
            first.inventory_sha256,
            differential_inventory_sha256(&inventory).unwrap()
        );
        assert_eq!(first.selected_indices, second.selected_indices);
        assert_eq!(first.selected_indices.first(), Some(&0));
        assert_eq!(first.selected_indices.last(), Some(&2_693));
        assert!(
            first
                .selected_indices
                .windows(2)
                .all(|indices| indices[0] < indices[1])
        );
    }

    #[test]
    fn signed_process_exit_codes_are_retained_without_loss() {
        let encoded =
            canonical_json_bytes(&process_status_json(false, false, Some(-1_073_741_510))).unwrap();
        assert_eq!(
            String::from_utf8(encoded).unwrap(),
            "{\"exitCode\":\"-1073741510\",\"success\":false,\"timedOut\":false}\n"
        );
    }

    #[test]
    fn strict_projection_rejection_diagnostic_is_bounded_and_reason_typed() {
        use hell_testkit::RuntimeFailureProjectionRejectionReason as Reason;

        let mut rejection = hell_testkit::RuntimeFailureProjectionRejection {
            reason: Reason::OracleFrameOrigin,
            exception_family: hell_testkit::RuntimeFailureExceptionFamily::IOException,
            descriptor_builtin: "Text.writeFile",
            descriptor_dimension: hell_builtins::CompatibilityDimension::Effects,
            descriptor_obligation: "effect-failure",
            oracle_stderr_sha256: sha256_bytes(b"secret oracle stderr"),
            oracle_stderr_bytes: 20,
            candidate_stderr_sha256: sha256_bytes(b"secret candidate stderr"),
            candidate_stderr_bytes: 23,
            semantic_present: true,
            typed_result_sha256_present: false,
            typed_result_builtin_present: false,
            semantic_coverage_count: 1,
            obligation_event_count: 2,
            causal_order_count: 3,
            force_event_count: 4,
            effect_event_count: 5,
            task_event_count: 6,
            resource_event_count: 7,
        };
        for reason in [
            Reason::OracleFrameGrammar,
            Reason::OracleFrameTerminalNewline,
            Reason::OracleFrameCount,
            Reason::OracleFrameFunction,
            Reason::OracleFrameOrigin,
            Reason::OraclePayloadHandlingMissing,
            Reason::OraclePayloadHandlingMismatch,
            Reason::OraclePayloadUnexpectedHandling,
            Reason::OraclePayloadEmpty,
            Reason::OraclePayloadMultiline,
            Reason::OraclePayloadControl,
        ] {
            rejection.reason = reason;
            let encoded = canonical_json_bytes(
                &runtime_failure_projection_rejection_json(&rejection).unwrap(),
            )
            .unwrap();
            let encoded = String::from_utf8(encoded).unwrap();
            assert!(encoded.contains(&format!("\"reason\":\"{}\"", reason.descriptor_name())));
            assert!(!encoded.contains("secret"));
        }
        rejection.reason = Reason::OracleFrameOrigin;
        let encoded =
            canonical_json_bytes(&runtime_failure_projection_rejection_json(&rejection).unwrap())
                .unwrap();
        let encoded = String::from_utf8(encoded).unwrap();
        assert!(encoded.contains("\"reason\":\"oracle-frame-origin\""));
        assert!(encoded.contains("\"descriptorBuiltin\":\"Text.writeFile\""));
        assert!(encoded.contains("\"semanticCoverageCount\":1"));
        assert!(encoded.contains("\"resourceEventCount\":7"));
    }

    #[test]
    fn red_differential_evidence_binds_both_inventories_and_generated_seed() {
        let authoritative = sha256_bytes(b"committed-inventory");
        let combined = sha256_bytes(b"combined-inventory");
        let encode = |seed| {
            canonical_json_bytes(
                &differential_inventory_evidence_json(DifferentialInventoryEvidence {
                    authoritative_case_count: 2_661,
                    authoritative_inventory_sha256: authoritative,
                    combined_inventory_count: 2_693,
                    combined_inventory_sha256: combined,
                    generated_case_count: 32,
                    generated_seed: seed,
                    mismatches: vec![JsonValue::Object(BTreeMap::from([(
                        "caseId".to_owned(),
                        JsonValue::String("red-case".to_owned()),
                    )]))],
                })
                .unwrap(),
            )
            .unwrap()
        };
        let encoded = encode(0x4845_4c4c);
        let text = String::from_utf8(encoded.clone()).unwrap();
        assert!(text.contains("\"authoritativeCaseCount\":2661"));
        assert!(text.contains(&format!(
            "\"authoritativeInventorySha256\":\"{}\"",
            authoritative.hex()
        )));
        assert!(text.contains("\"combinedInventoryCount\":2693"));
        assert!(text.contains(&format!(
            "\"combinedInventorySha256\":\"{}\"",
            combined.hex()
        )));
        assert!(text.contains("\"generatedCaseCount\":32"));
        assert!(text.contains("\"generatedSeed\":1212501068"));
        assert!(text.contains("\"mismatchCount\":1"));
        assert_ne!(encoded, encode(0x4845_4c4d));
    }

    #[test]
    fn timing_distribution_keeps_the_first_authoritative_worst_case() {
        let cases = [
            DifferentialCase {
                id: "first".into(),
                ..DifferentialCase::default()
            },
            DifferentialCase {
                id: "second".into(),
                ..DifferentialCase::default()
            },
            DifferentialCase {
                id: "third".into(),
                ..DifferentialCase::default()
            },
        ];
        let detail = timing_distribution_detail("oracle", &[5, 9, 9], &cases, &[0, 10, 20]);
        assert!(detail.contains("p50=9,p95=9,p99=9,max=9"));
        assert!(detail.contains("worstAuthoritativeIndex=10,worstCaseId=\"second\""));
    }

    #[test]
    fn benchmark_report_binds_every_executable_identity_field() {
        let digest = sha256_bytes(b"oracle");
        let identity = ExecutableIdentity {
            path: PathBuf::from("/fixed/oracle"),
            sha256: digest,
            reported_version: "2026-05-29".into(),
            build_info: None,
            role: ExecutableRole::Oracle,
            assurance_epoch_sha256: Some(sha256_bytes(b"epoch")),
            acquisition_receipt_id: Some("receipt-1".into()),
            acquisition_receipt_sha256: Some(sha256_bytes(b"receipt")),
            acquisition_attestation_sha256: Some(sha256_bytes(b"attestation")),
        };
        let mut report = Report::new("native-differential-benchmark");
        report.mark_non_authoritative();
        report.measurement(
            "native-benchmark-oracle-identity",
            Duration::ZERO,
            benchmark_executable_identity_detail(&identity, 123).unwrap(),
        );
        report_benchmark_artifact_identity(
            &mut report,
            "helper",
            &BenchmarkArtifactIdentity {
                path: PathBuf::from("/fixed/hell-test-helper"),
                sha256: sha256_bytes(b"helper"),
                size: 456,
            },
        )
        .unwrap();
        let json = report.to_json();
        assert!(json.contains("\"authoritative\": false"));
        assert!(json.contains("canonicalPath=\\\"/fixed/oracle\\\""));
        assert!(json.contains(&format!("sha256={}", digest.hex())));
        assert!(json.contains("reportedVersion=\\\"2026-05-29\\\""));
        assert!(json.contains("acquisitionReceiptId=\\\"receipt-1\\\""));
        assert!(json.contains("canonicalPath=\\\"/fixed/hell-test-helper\\\""));
        assert!(json.contains("sizeBytes=456"));
    }

    #[test]
    fn authoritative_identity_and_mismatch_evidence_is_typed_and_bounded() {
        let digest = sha256_bytes(b"candidate");
        let build_info_lines = [
            format!("hell-rs {}", env!("CARGO_PKG_VERSION")),
            format!("language baseline {}", hell_builtins::LANGUAGE_VERSION),
            format!("upstream {}", hell_builtins::UPSTREAM_COMMIT),
            "compatibility evidence schema 2".to_owned(),
            "compat tracing enabled true".to_owned(),
            format!(
                "compiler policy {:?}",
                hell_compiler::CompilerConfig::upstream()
            ),
            format!(
                "runtime policy {:?}",
                hell_runtime::policy::RuntimePolicy::upstream()
            ),
        ];
        let identity = ExecutableIdentity {
            path: PathBuf::from("/fixed/candidate"),
            sha256: digest,
            reported_version: "2026-05-29".into(),
            build_info: Some(
                hell_testkit::parse_candidate_build_info(
                    build_info_lines.iter().map(String::as_str),
                )
                .unwrap(),
            ),
            role: ExecutableRole::Candidate,
            assurance_epoch_sha256: None,
            acquisition_receipt_id: None,
            acquisition_receipt_sha256: None,
            acquisition_attestation_sha256: None,
        };
        let encoded =
            canonical_json_bytes(&executable_identity_json(&identity, 123).unwrap()).unwrap();
        let encoded = String::from_utf8(encoded).unwrap();
        assert!(encoded.contains("\"canonicalPath\":\"/fixed/candidate\""));
        assert!(encoded.contains(&format!("\"sha256\":\"{}\"", digest.hex())));
        assert!(encoded.contains("\"sizeBytes\":123"));
        assert!(encoded.contains("\"schemaVersion\":2"));
        assert!(encoded.contains("\"buildInfoSchemaVersion\":2"));
        assert!(encoded.contains("\"compatTracing\":true"));

        let disabled_lines = build_info_lines.map(|line| {
            if line == "compat tracing enabled true" {
                "compat tracing enabled false".to_owned()
            } else {
                line
            }
        });
        let path = std::env::current_exe().unwrap().canonicalize().unwrap();
        let disabled = ExecutableIdentity {
            sha256: sha256_file(&path).unwrap(),
            path,
            reported_version: "2026-05-29".into(),
            build_info: Some(
                hell_testkit::parse_candidate_build_info(disabled_lines.iter().map(String::as_str))
                    .unwrap(),
            ),
            role: ExecutableRole::Candidate,
            assurance_epoch_sha256: None,
            acquisition_receipt_id: None,
            acquisition_receipt_sha256: None,
            acquisition_attestation_sha256: None,
        };
        let mut preflight = Report::new("candidate-preflight");
        report_executable_identity(&mut preflight, "candidate", &disabled).unwrap();
        assert!(
            report_candidate_compat_tracing_preflight(
                &mut preflight,
                "conformance-candidate-compat-tracing",
                &disabled,
            )
            .is_err()
        );
        let encoded = preflight.to_json();
        assert!(encoded.contains("\"compatTracing\":false"));
        assert!(encoded.contains("\"name\": \"conformance-candidate-compat-tracing\""));
        assert!(encoded.contains("\"status\": \"failed\""));

        let bytes = vec![0x5a; BENCHMARK_MISMATCH_PREFIX_BYTES + 1];
        let encoded = canonical_json_bytes(&mismatch_side_json(&bytes).unwrap()).unwrap();
        let encoded = String::from_utf8(encoded).unwrap();
        assert!(encoded.contains(&format!("\"bytes\":{}", bytes.len())));
        assert!(encoded.contains(&format!("\"sha256\":\"{}\"", sha256_bytes(&bytes).hex())));
        assert!(encoded.contains("\"prefixTruncated\":true"));
        assert!(!encoded.contains(&"5a".repeat(BENCHMARK_MISMATCH_PREFIX_BYTES + 1)));
    }

    #[test]
    fn native_stack_provenance_binds_ephemeral_overlay_before_cleanup() {
        let mut report = Report::new("native-oracle-shard");
        let provenance = crate::command::NativeStackProvenance {
            source: PathBuf::from("/fixed/oracle-source"),
            source_commit: crate::command::PINNED_ORACLE_SOURCE_COMMIT,
            stack_yaml_sha256: sha256_bytes(b"stack-yaml"),
            stack_lock_sha256: sha256_bytes(b"stack-lock"),
            effective_stack_yaml: PathBuf::from("/fixed/adapter/stack.yaml"),
            effective_stack_yaml_sha256: sha256_bytes(b"overlay"),
            llvm_ar: Some(PathBuf::from("/fixed/llvm-ar")),
            llvm_ar_sha256: Some(sha256_bytes(b"llvm-ar")),
            llvm_ar_version: Some("Homebrew LLVM version 22.1.8".to_owned()),
        };
        let build = CommandSpec::new("stack", Duration::ZERO).arguments([
            "--stack-yaml",
            "/fixed/adapter/stack.yaml",
            "build",
        ]);
        let path = CommandSpec::new("stack", Duration::ZERO).arguments([
            "--stack-yaml",
            "/fixed/adapter/stack.yaml",
            "path",
        ]);
        report_native_stack_provenance(&mut report, &provenance, &build, &path).unwrap();
        let json = report.to_json();
        assert!(json.contains("\"name\": \"native-stack-provenance\""));
        assert!(json.contains(crate::command::PINNED_ORACLE_SOURCE_COMMIT));
        assert!(json.contains("/fixed/adapter/stack.yaml"));
        assert!(json.contains("Homebrew LLVM version 22.1.8"));
        assert!(
            json.contains(
                "\"arguments\":[\"--stack-yaml\",\"/fixed/adapter/stack.yaml\",\"build\"]"
            )
        );
    }

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
