use std::collections::{BTreeMap, BTreeSet};
use std::env;
#[cfg(unix)]
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::sync::Arc;
#[cfg(any(unix, windows))]
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
#[cfg(any(unix, windows))]
use std::time::Instant;

use crate::command::{CommandResult, CommandSpec, with_release_candidate_environment};
#[cfg(unix)]
use crate::json::require_exact_json_keys;
use crate::json::{JsonValue, canonical_json_bytes, json_member, parse_json};
use crate::report::Report;

use super::archive::{ArchiveInput, create, extract_binary};
use super::manifest::{read_json, read_regular, write_atomic, write_json};
use super::plan::{pinned_oracle_source_inventory, source_inventory};
use super::schema::{ReleasePlan, ReleasePlatform, expected_gates, number, object, string};

#[cfg(unix)]
static POSIX_ADAPTER_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[cfg(unix)]
static POSIX_CARGO_SEED_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[cfg(unix)]
static POSIX_CARGO_METADATA_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[cfg(unix)]
const TRUSTED_CARGO_DENY_VERSION: &str = "0.20.2";

#[cfg(unix)]
static POSIX_STACK_ROOT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[cfg(unix)]
static POSIX_ARCHIVE_TRANSITION_VERIFIER_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[cfg(unix)]
const POSIX_ARCHIVE_CLEANUP_BUDGET: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug)]
struct NativeOracleCommandDeadlines {
    execution: Instant,
    completion: Instant,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug)]
struct NativeOracleCleanupDeadlines {
    quiescence: Instant,
    #[cfg(target_os = "macos")]
    broker_stop: Instant,
    source_work: Instant,
    adapter_work: Instant,
    final_restore: Instant,
    adapter_close: Instant,
    final_attestation: Instant,
}

#[cfg(target_os = "macos")]
const MAC_NATIVE_ORACLE_CONSTRUCTION_EXECUTION_BUDGET: Duration = Duration::from_secs(18 * 60);
#[cfg(target_os = "macos")]
const MAC_NATIVE_ORACLE_CONSTRUCTION_COMPLETION_BUDGET: Duration = Duration::from_secs(20 * 60);
#[cfg(target_os = "macos")]
const MAC_NATIVE_ORACLE_ARCHIVER_EXECUTION_BUDGET: Duration = Duration::from_secs(90);
#[cfg(target_os = "macos")]
const MAC_NATIVE_ORACLE_ARCHIVER_COMPLETION_BUDGET: Duration = Duration::from_secs(2 * 60);
#[cfg(target_os = "macos")]
const MAC_NATIVE_ORACLE_PRIMARY_EXECUTION_BUDGET: Duration = Duration::from_secs(90 * 60);
#[cfg(target_os = "macos")]
const MAC_NATIVE_ORACLE_PRIMARY_COMPLETION_BUDGET: Duration = Duration::from_secs(100 * 60);
#[cfg(target_os = "macos")]
const MAC_NATIVE_ORACLE_QUIESCENCE_BUDGET: Duration = Duration::from_secs(102 * 60);
#[cfg(target_os = "macos")]
const MAC_NATIVE_ORACLE_BROKER_STOP_BUDGET: Duration = Duration::from_secs(104 * 60);
#[cfg(target_os = "macos")]
const MAC_NATIVE_ORACLE_SOURCE_CLEANUP_BUDGET: Duration = Duration::from_secs(108 * 60);
#[cfg(target_os = "macos")]
const MAC_NATIVE_ORACLE_ADAPTER_CLEANUP_BUDGET: Duration = Duration::from_secs(112 * 60);
#[cfg(target_os = "macos")]
const MAC_NATIVE_ORACLE_FINAL_RESTORE_BUDGET: Duration = Duration::from_secs(114 * 60);
#[cfg(target_os = "macos")]
const MAC_NATIVE_ORACLE_ADAPTER_CLOSE_BUDGET: Duration = Duration::from_secs(118 * 60);
#[cfg(target_os = "macos")]
const MAC_NATIVE_ORACLE_FINAL_ATTESTATION_BUDGET: Duration = Duration::from_secs(120 * 60);

#[cfg(target_os = "macos")]
#[derive(Clone, Copy, Debug)]
struct MacNativeOracleLifecycleEnvelope {
    construction: crate::command::NativeArchiveAdapterConstructionEnvelope,
    command: NativeOracleCommandDeadlines,
    cleanup: NativeOracleCleanupDeadlines,
}

#[cfg(target_os = "macos")]
impl MacNativeOracleLifecycleEnvelope {
    fn new() -> Result<Self, String> {
        let started = Instant::now();
        let deadline = |budget: Duration, phase: &str| {
            started
                .checked_add(budget)
                .ok_or_else(|| format!("macOS native oracle {phase} deadline overflowed"))
        };
        let construction_execution = deadline(
            MAC_NATIVE_ORACLE_CONSTRUCTION_EXECUTION_BUDGET,
            "construction execution",
        )?;
        let construction_completion = deadline(
            MAC_NATIVE_ORACLE_CONSTRUCTION_COMPLETION_BUDGET,
            "construction completion",
        )?;
        let archiver_execution = deadline(
            MAC_NATIVE_ORACLE_ARCHIVER_EXECUTION_BUDGET,
            "archiver execution",
        )?;
        let archiver_completion = deadline(
            MAC_NATIVE_ORACLE_ARCHIVER_COMPLETION_BUDGET,
            "archiver completion",
        )?;
        let command = NativeOracleCommandDeadlines {
            execution: deadline(
                MAC_NATIVE_ORACLE_PRIMARY_EXECUTION_BUDGET,
                "primary execution",
            )?,
            completion: deadline(
                MAC_NATIVE_ORACLE_PRIMARY_COMPLETION_BUDGET,
                "primary completion",
            )?,
        };
        let cleanup = NativeOracleCleanupDeadlines {
            quiescence: deadline(MAC_NATIVE_ORACLE_QUIESCENCE_BUDGET, "quiescence")?,
            broker_stop: deadline(MAC_NATIVE_ORACLE_BROKER_STOP_BUDGET, "broker stop")?,
            source_work: deadline(MAC_NATIVE_ORACLE_SOURCE_CLEANUP_BUDGET, "source cleanup")?,
            adapter_work: deadline(MAC_NATIVE_ORACLE_ADAPTER_CLEANUP_BUDGET, "adapter cleanup")?,
            final_restore: deadline(MAC_NATIVE_ORACLE_FINAL_RESTORE_BUDGET, "final restore")?,
            adapter_close: deadline(MAC_NATIVE_ORACLE_ADAPTER_CLOSE_BUDGET, "adapter close")?,
            final_attestation: deadline(
                MAC_NATIVE_ORACLE_FINAL_ATTESTATION_BUDGET,
                "final attestation",
            )?,
        };
        let ordered = [
            construction_execution,
            construction_completion,
            command.execution,
            command.completion,
            cleanup.quiescence,
            cleanup.broker_stop,
            cleanup.source_work,
            cleanup.adapter_work,
            cleanup.final_restore,
            cleanup.adapter_close,
            cleanup.final_attestation,
        ];
        if ordered.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err("macOS native oracle lifecycle deadlines are not ordered".to_owned());
        }
        Ok(Self {
            construction: crate::command::NativeArchiveAdapterConstructionEnvelope::with_deadlines(
                construction_execution,
                construction_completion,
                archiver_execution,
                archiver_completion,
            )?,
            command,
            cleanup,
        })
    }
}

#[cfg(unix)]
fn transition_cleanup_deadlines(
    transition: Instant,
    outer_completion_deadline: Instant,
) -> Result<NativeOracleCleanupDeadlines, String> {
    if transition >= outer_completion_deadline {
        return Err("archive cleanup outer deadline expired before cleanup".to_owned());
    }
    let cleanup_deadline = transition
        .checked_add(POSIX_ARCHIVE_CLEANUP_BUDGET)
        .ok_or_else(|| "archive cleanup deadline overflowed".to_owned())?
        .min(outer_completion_deadline);
    Ok(NativeOracleCleanupDeadlines {
        quiescence: cleanup_deadline,
        #[cfg(target_os = "macos")]
        broker_stop: cleanup_deadline,
        source_work: cleanup_deadline,
        adapter_work: cleanup_deadline,
        final_restore: cleanup_deadline,
        adapter_close: cleanup_deadline,
        final_attestation: cleanup_deadline,
    })
}

#[cfg(unix)]
static POSIX_CANDIDATE_ENVIRONMENT_VERIFIER_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[cfg(target_os = "linux")]
static POSIX_PRINCIPAL_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[cfg(windows)]
static WINDOWS_CANDIDATE_TARGET_VERIFIER_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[cfg(unix)]
const POSIX_RUSTUP_STAGE_ENTRY_LIMIT: usize = 100_000;

#[cfg(unix)]
const POSIX_RUSTUP_STAGE_BYTE_LIMIT: u64 = 8 * 1024 * 1024 * 1024;

#[cfg(target_os = "linux")]
const LINUX_LOGIN_DEFS_BYTE_LIMIT: u64 = 128 * 1024;

#[cfg(target_os = "linux")]
const LINUX_PRINCIPAL_ID_SPAN_LIMIT: u32 = 100_000;

#[cfg(windows)]
static WINDOWS_TOOLCHAIN_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[cfg(any(unix, windows))]
static PLATFORM_FAILURE_VERIFIER_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[cfg(windows)]
const WINDOWS_TOOLCHAIN_STAGE_ENTRY_LIMIT: usize = 100_000;

#[cfg(windows)]
const WINDOWS_TOOLCHAIN_STAGE_BYTE_LIMIT: u64 = 8 * 1024 * 1024 * 1024;

#[cfg(windows)]
const WINDOWS_TOOLCHAIN_CONSTRUCTION_BUDGET: Duration = Duration::from_secs(30 * 60);

#[cfg(windows)]
const WINDOWS_TOOLCHAIN_CONSTRUCTION_CLEANUP_RESERVE: Duration = Duration::from_secs(30 * 60);

#[cfg(windows)]
const WINDOWS_TOOLCHAIN_LIFECYCLE_EXECUTION_BUDGET: Duration = Duration::from_secs(120 * 60);

#[cfg(windows)]
#[derive(Clone, Copy)]
struct WindowsToolchainConstructionEnvelope {
    construction_deadline: Instant,
    execution_deadline: Instant,
    completion_deadline: Instant,
}

#[cfg(windows)]
impl WindowsToolchainConstructionEnvelope {
    fn new() -> Result<Self, String> {
        let started = Instant::now();
        let construction_deadline = started
            .checked_add(WINDOWS_TOOLCHAIN_CONSTRUCTION_BUDGET)
            .ok_or_else(|| "Windows toolchain construction deadline overflowed".to_owned())?;
        let execution_deadline = started
            .checked_add(WINDOWS_TOOLCHAIN_LIFECYCLE_EXECUTION_BUDGET)
            .ok_or_else(|| "Windows toolchain lifecycle deadline overflowed".to_owned())?;
        let completion_deadline = execution_deadline
            .checked_add(WINDOWS_TOOLCHAIN_CONSTRUCTION_CLEANUP_RESERVE)
            .ok_or_else(|| "Windows toolchain cleanup deadline overflowed".to_owned())?;
        Ok(Self {
            construction_deadline,
            execution_deadline,
            completion_deadline,
        })
    }
}

pub(crate) fn run(
    platform: ReleasePlatform,
    required_gates: String,
    plan_path: PathBuf,
    conformance_plan_path: PathBuf,
    root: PathBuf,
    oracle_source: PathBuf,
    output: PathBuf,
) -> Result<String, String> {
    if required_gates.split(',').collect::<Vec<_>>() != expected_gates(platform) {
        return Err("release platform required gate inventory differs from policy".to_owned());
    }
    let plan = ReleasePlan::parse(&read_json(&plan_path)?)?;
    let conformance_plan = validate_conformance_plan(&plan, &conformance_plan_path)?;
    let root = fs::canonicalize(root)
        .map_err(|error| format!("cannot canonicalize candidate root: {error}"))?;
    let oracle_source = fs::canonicalize(oracle_source)
        .map_err(|error| format!("cannot canonicalize oracle root: {error}"))?;
    validate_checkout(&root, &plan)?;
    let runner_identity = validate_runner(platform)?;
    let oracle_inventory_before = pinned_oracle_source_inventory(&oracle_source)?;
    let oracle_inventory_digest =
        hell_testkit::sha256_bytes(&canonical_json_bytes(&oracle_inventory_before)?).hex();
    // Retain and bind every trusted package input before establishing the
    // candidate principal. The POSIX confinement path copies this exact clean
    // checkout into a root-owned, read-only authority that the candidate can
    // traverse without gaining access to hosted-runner workspace ancestors.
    let license = read_regular(&root.join("LICENSES/BSD-3-Clause-Hell.txt"))?;
    let notice = read_regular(&root.join("NOTICE"))?;
    let readme = read_regular(&root.join("README.md"))?;
    let inventory = source_inventory(&root)?;
    let inventory_bytes = canonical_json_bytes(&inventory)?;
    if hell_testkit::sha256_bytes(&inventory_bytes).hex() != plan.source_inventory_sha256 {
        return Err("candidate source inventory differs from release plan".to_owned());
    }
    if read_regular(&root.join("deny.toml"))? != include_bytes!("../../../../deny.toml") {
        return Err("candidate dependency policy differs from trusted automation".to_owned());
    }
    if output.exists() {
        return Err("platform output already exists".to_owned());
    }
    fs::create_dir_all(output.join("archive"))
        .map_err(|error| format!("cannot create platform output: {error}"))?;
    fs::create_dir(output.join("conformance-evidence"))
        .map_err(|error| format!("cannot create conformance evidence output: {error}"))?;
    fs::create_dir(output.join("conformance-observations"))
        .map_err(|error| format!("cannot create conformance observation output: {error}"))?;
    let output = fs::canonicalize(output)
        .map_err(|error| format!("cannot canonicalize platform output: {error}"))?;
    let workspace_target = root
        .parent()
        .ok_or_else(|| "candidate root has no parent".to_owned())?
        .join("candidate-target");
    if !workspace_target.is_absolute() {
        return Err("candidate target directory is not absolute".to_owned());
    }
    require_candidate_target(&root, &workspace_target)?;
    let mut confinement = establish_candidate_process_confinement(
        platform,
        &root,
        &oracle_source,
        &inventory,
        &oracle_inventory_before,
        &plan.resolution.candidate_sha,
        &workspace_target,
        &output,
    )?;
    let primary = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        || -> Result<String, String> {
            let target = confinement.candidate_target().to_path_buf();
            let candidate_execution_root = confinement.candidate_root().to_path_buf();
            let oracle_execution_root = confinement.oracle_root().to_path_buf();
            let candidate_environment_root = confinement.candidate_environment_root(&target);
            write_atomic(&output.join("source-inventory.json"), &inventory_bytes)?;
            let (tools, unretained_oracle) = {
                #[cfg(target_os = "macos")]
                let native_oracle_lifecycle = (platform == ReleasePlatform::MacosAarch64)
                    .then(MacNativeOracleLifecycleEnvelope::new)
                    .transpose()?;
                #[cfg(target_os = "macos")]
                let archive_adapter = if platform == ReleasePlatform::MacosAarch64 {
                    let envelope = native_oracle_lifecycle
                        .ok_or_else(|| "macOS native oracle lifecycle is absent".to_owned())?
                        .construction;
                    crate::command::NativeArchiveAdapter::for_macos_with_envelope(
                        true,
                        confinement.archive_adapter_base(&target),
                        &oracle_execution_root,
                        confinement.archive_launcher(),
                        Some(envelope),
                    )?
                } else {
                    crate::command::NativeArchiveAdapter::for_macos(
                        false,
                        confinement.archive_adapter_base(&target),
                        &oracle_execution_root,
                        confinement.archive_launcher(),
                    )?
                };
                #[cfg(not(target_os = "macos"))]
                let archive_adapter = crate::command::NativeArchiveAdapter::for_macos(
                    platform == ReleasePlatform::MacosAarch64,
                    confinement.archive_adapter_base(&target),
                    &oracle_execution_root,
                    confinement.archive_launcher(),
                )?;
                #[cfg(unix)]
                let mut archive_adapter = archive_adapter;
                #[cfg(target_os = "macos")]
                let native_archive_authorization_deadline =
                    native_oracle_lifecycle.map(|value| value.command.execution);
                #[cfg(all(unix, not(target_os = "macos")))]
                let native_archive_authorization_deadline = None;
                #[cfg(unix)]
                let archive_adapter_seal = (platform == ReleasePlatform::MacosAarch64)
                    .then(|| {
                        confinement.seal_archive_adapter_authority(
                            &mut archive_adapter,
                            native_archive_authorization_deadline,
                        )
                    })
                    .transpose();
                #[cfg(unix)]
                let launch_policy = if platform == ReleasePlatform::MacosAarch64 {
                    confinement
                        .policy
                        .clone()
                        .with_posix_stack_work_authority(
                            &oracle_execution_root,
                            confinement.stack_work_authority()?,
                        )
                        .map_err(|error| {
                            format!("cannot bind native Stack work authority: {error}")
                        })
                } else {
                    Ok(confinement.policy.clone())
                };
                #[cfg(not(unix))]
                let launch_policy = confinement.policy().cloned();
                #[cfg(target_os = "macos")]
                let native_oracle_deadlines = native_oracle_lifecycle.map(|value| value.command);
                #[cfg(all(unix, not(target_os = "macos")))]
                let native_oracle_deadlines: Option<NativeOracleCommandDeadlines> = None;
                #[cfg(not(unix))]
                let native_oracle_deadlines = None;
                #[cfg(unix)]
                let result = match (&archive_adapter_seal, &launch_policy) {
                    (Ok(_), Ok(launch_policy)) => {
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            hell_testkit::with_candidate_launch_policy(
                                launch_policy,
                                || -> Result<_, String> {
                                    let unretained_oracle = prepare_oracle(
                                        platform,
                                        &oracle_execution_root,
                                        &output,
                                        &archive_adapter,
                                        native_oracle_deadlines,
                                    )?;
                                    Ok((
                                        tool_identities(
                                            platform,
                                            &candidate_execution_root,
                                            &oracle_execution_root,
                                            &archive_adapter,
                                        )?,
                                        unretained_oracle,
                                    ))
                                },
                            )
                        }))
                        .unwrap_or_else(|_| {
                            Err("native oracle preparation panicked before explicit cleanup"
                                .to_owned())
                        })
                    }
                    (Err(error), _) | (_, Err(error)) => Err(error.clone()),
                };
                #[cfg(not(unix))]
                let result = match &launch_policy {
                    Ok(launch_policy) => {
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            hell_testkit::with_candidate_launch_policy(
                                launch_policy,
                                || -> Result<_, String> {
                                    let unretained_oracle = prepare_oracle(
                                        platform,
                                        &oracle_execution_root,
                                        &output,
                                        &archive_adapter,
                                        native_oracle_deadlines,
                                    )?;
                                    Ok((
                                        tool_identities(
                                            platform,
                                            &candidate_execution_root,
                                            &oracle_execution_root,
                                            &archive_adapter,
                                        )?,
                                        unretained_oracle,
                                    ))
                                },
                            )
                        }))
                        .unwrap_or_else(|_| {
                            Err("native oracle preparation panicked before explicit cleanup"
                                .to_owned())
                        })
                    }
                    Err(error) => Err(error.clone()),
                };
                #[cfg(unix)]
                let archive_cleanup_transition = Instant::now();
                #[cfg(target_os = "macos")]
                let archive_cleanup_deadlines = native_oracle_lifecycle
                    .map(|value| Ok(value.cleanup))
                    .unwrap_or_else(|| {
                        let outer = archive_cleanup_transition
                            .checked_add(POSIX_ARCHIVE_CLEANUP_BUDGET)
                            .ok_or_else(|| {
                                "archive cleanup outer deadline overflowed".to_owned()
                            })?;
                        transition_cleanup_deadlines(archive_cleanup_transition, outer)
                    });
                #[cfg(all(unix, not(target_os = "macos")))]
                let archive_cleanup_deadlines = archive_cleanup_transition
                    .checked_add(POSIX_ARCHIVE_CLEANUP_BUDGET)
                    .ok_or_else(|| "archive cleanup outer deadline overflowed".to_owned())
                    .and_then(|outer| {
                        transition_cleanup_deadlines(archive_cleanup_transition, outer)
                    });
                #[cfg(unix)]
                let quiescence = match archive_adapter_seal.as_ref() {
                    Ok(Some(_)) => std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        archive_cleanup_deadlines.clone().and_then(|deadlines| {
                            launch_policy
                                .as_ref()
                                .unwrap_or(&confinement.policy)
                                .posix_quiescence_receipt_until(deadlines.quiescence)
                                .map_err(|error| {
                                    format!(
                                        "cannot retain archive cleanup quiescence receipt: {error}"
                                    )
                                })
                        })
                    }))
                    .unwrap_or_else(|_| {
                        Err("archive cleanup quiescence receipt acquisition panicked".to_owned())
                    })
                    .map(Some),
                    Ok(None) | Err(_) => Ok(None),
                };
                #[cfg(target_os = "macos")]
                let input_broker_cleanup =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        archive_cleanup_deadlines.clone().and_then(|deadlines| {
                            archive_adapter.stop_input_broker_until(deadlines.broker_stop)
                        })
                    }))
                    .unwrap_or_else(|_| {
                        Err("native archive input staging cleanup panicked".to_owned())
                    });
                #[cfg(all(unix, not(target_os = "macos")))]
                let input_broker_cleanup: Result<(), String> = Ok(());
                #[cfg(unix)]
                let restore = match (archive_adapter_seal, &quiescence, &input_broker_cleanup) {
                    (Err(error), _, _) => Err(format!(
                        "archive restoration skipped after adapter seal failure: {error}"
                    )),
                    (Ok(Some(seal)), Ok(Some(receipt)), Ok(())) => {
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            archive_cleanup_deadlines
                                .clone()
                                .and_then(|deadlines| seal.restore(receipt.clone(), deadlines))
                        }))
                        .unwrap_or_else(|_| {
                            Err("native archive restoration panicked before adapter cleanup"
                                .to_owned())
                        })
                    }
                    (Ok(None), Ok(None), Ok(())) => Ok(()),
                    (Ok(Some(_)), Err(_), _) => Err(
                        "archive restoration skipped without an exact quiescence receipt"
                            .to_owned(),
                    ),
                    (Ok(Some(_)), _, Err(_)) => Err(
                        "archive restoration skipped while input staging cleanup remained active"
                            .to_owned(),
                    ),
                    _ => Err(
                        "archive cleanup quiescence receipt topology is inconsistent".to_owned(),
                    ),
                };
                #[cfg(target_os = "macos")]
                let adapter_cleanup_path = archive_adapter.directory_path().map(Path::to_path_buf);
                #[cfg(target_os = "macos")]
                let finalization = match archive_cleanup_deadlines {
                    Ok(deadlines) => run_native_oracle_finalizer(
                        deadlines,
                        |deadline| archive_adapter.close_until(deadline),
                        |deadline| {
                            attest_native_archive_adapter_absence(
                                adapter_cleanup_path.as_deref(),
                                deadline,
                            )
                        },
                    ),
                    Err(error) => NativeOracleFinalizationResults {
                        adapter_close: Err(error.clone()),
                        final_attestation: Err(error),
                    },
                };
                #[cfg(target_os = "macos")]
                let adapter_cleanup = finalization.adapter_close;
                #[cfg(target_os = "macos")]
                let adapter_attestation = finalization.final_attestation;
                #[cfg(all(unix, not(target_os = "macos")))]
                let adapter_cleanup = archive_adapter.close();
                #[cfg(all(unix, not(target_os = "macos")))]
                let adapter_attestation: Result<(), String> = Ok(());
                #[cfg(not(unix))]
                drop(archive_adapter);
                #[cfg(unix)]
                {
                    let mut failures = Vec::new();
                    let value = match result {
                        Ok(value) => Some(value),
                        Err(error) => {
                            failures.push(("primary", error));
                            None
                        }
                    };
                    if let Err(error) = quiescence {
                        failures.push(("quiescence", error));
                    }
                    if let Err(error) = input_broker_cleanup {
                        failures.push(("input-staging-cleanup", error));
                    }
                    if let Err(error) = restore {
                        failures.push(("restoration", error));
                    }
                    if let Err(error) = adapter_cleanup {
                        failures.push(("adapter-cleanup", error));
                    }
                    if let Err(error) = adapter_attestation {
                        failures.push(("adapter-final-attestation", error));
                    }
                    if failures.is_empty() {
                        value.ok_or_else(|| {
                            "native oracle preparation result is absent".to_owned()
                        })?
                    } else {
                        return Err(ordered_bounded_failures(
                            "native oracle preparation and archive restoration failed",
                            failures,
                        ));
                    }
                }
                #[cfg(not(unix))]
                result?
            };
            confinement.require_candidate_environment("after oracle preparation")?;
            let prepared_oracle = confinement.retain_oracle(&unretained_oracle)?;
            unretained_oracle.cleanup()?;
            require_candidate_target(&root, &workspace_target)?;
            confinement.require_candidate_environment("before platform gates")?;
            #[cfg(unix)]
            let dependency_policy = match (
                confinement.dependency_policy_protection.as_ref(),
                confinement.cargo_deny_home_protection.as_ref(),
            ) {
                (Some(policy), Some(metadata)) => Some((policy, metadata)),
                (Some(_), None) => {
                    return Err("Linux dependency-policy metadata authority is absent".to_owned());
                }
                (None, _) => None,
            };
            let mut gates = BTreeMap::from([
                ("runner-identity", true),
                ("candidate-checkout", true),
                ("oracle-checkout", true),
            ]);
            let mut evidence = BTreeMap::new();
            evidence.insert(
                "runner-identity".to_owned(),
                object([
                    ("arch", string(&runner_identity.1)),
                    ("os", string(&runner_identity.0)),
                    ("schemaVersion", number(1)),
                    ("state", string("passed")),
                ]),
            );
            evidence.insert(
                "candidate-checkout".to_owned(),
                object([
                    ("schemaVersion", number(1)),
                    ("sha", string(&plan.resolution.candidate_sha)),
                    ("state", string("passed")),
                ]),
            );
            evidence.insert(
                "oracle-checkout".to_owned(),
                object([
                    ("schemaVersion", number(1)),
                    ("sha", string("8e952cf9de4ab25d7716982a9ca234f9bdcf1bff")),
                    ("sourceInventorySha256", string(&oracle_inventory_digest)),
                    ("state", string("passed")),
                ]),
            );
            gates.insert("conformance-plan-binding", true);
            evidence.insert(
                "conformance-plan-binding".to_owned(),
                object([
                    (
                        "conformancePlanSha256",
                        string(&conformance_plan.plan_sha256),
                    ),
                    ("platform", string(platform.id())),
                    ("schemaVersion", number(1)),
                    ("state", string("passed")),
                    (
                        "trustedInputsSha256",
                        string(&conformance_plan.trusted_inputs_sha256),
                    ),
                ]),
            );
            let mut retained_outputs =
                BTreeMap::from([("source-inventory.json".to_owned(), inventory_bytes)]);
            #[cfg(windows)]
            let mut windows_release_binary = None;
            let platform_gate_result = with_release_candidate_environment(
                &target,
                &candidate_environment_root,
                plan.source_date_epoch,
                confinement.policy()?,
                || {
                    run_platform_gates(
                        platform,
                        &plan,
                        &conformance_plan,
                        &candidate_execution_root,
                        &oracle_execution_root,
                        &output,
                        &mut gates,
                        &mut evidence,
                        &mut retained_outputs,
                        prepared_oracle,
                        &oracle_inventory_digest,
                        #[cfg(unix)]
                        dependency_policy,
                        #[cfg(windows)]
                        &mut windows_release_binary,
                    )
                },
            );
            let post_platform_environment = confinement
                .require_candidate_environment("after platform gates before trusted cleanup");
            #[cfg(windows)]
            let post_platform_binary =
                windows_release_binary.as_ref().map_or(Ok(()), |authority| {
                    authority.validate(
                        "after platform gates before trusted cleanup",
                        gates.get("release-build") == Some(&true),
                    )
                });
            let dependency_cleanup = confinement.cleanup_dependency_policy_cache();
            compose_platform_gate_cleanup(platform_gate_result, dependency_cleanup)?;
            post_platform_environment?;
            #[cfg(windows)]
            post_platform_binary?;
            #[cfg(windows)]
            if let Some(authority) = windows_release_binary.as_ref() {
                authority.validate(
                    "after trusted dependency-policy cleanup",
                    gates.get("release-build") == Some(&true),
                )?;
            }
            confinement.require_bound_sources("after trusted dependency-policy cleanup")?;
            require_source_inventory(&root, &plan.source_inventory_sha256)?;
            let oracle_inventory_after = pinned_oracle_source_inventory(&oracle_source)?;
            if hell_testkit::sha256_bytes(&canonical_json_bytes(&oracle_inventory_after)?).hex()
                != oracle_inventory_digest
            {
                return Err("oracle source changed during candidate execution".to_owned());
            }
            require_candidate_target(&root, &workspace_target)?;
            confinement.export_candidate_target(&workspace_target)?;
            // Native dependency attestations still use the transient digest hand-off.
            // Linux retains only the exact immutable trusted result verified above.
            if platform != ReleasePlatform::LinuxX86_64 {
                fs::remove_file(output.join("dependency-policy.sha256")).map_err(|error| {
                    format!("cannot remove transient dependency digest: {error}")
                })?;
            }
            #[cfg(windows)]
            if let Some(authority) = windows_release_binary.as_ref() {
                authority.validate(
                    "before packaging after transient dependency digest removal",
                    gates.get("release-build") == Some(&true),
                )?;
            }

            #[cfg(windows)]
            let binary = windows_release_binary
                .as_ref()
                .ok_or_else(|| {
                    "Windows release binary authority is absent before packaging".to_owned()
                })?
                .bound_binary_path()?
                .to_path_buf();
            #[cfg(not(windows))]
            let binary = {
                let binary = target.join("release").join(platform.executable());
                require_real_binary_path(&target, &binary)?;
                binary
            };
            let archive_name = format!("hell-v{}-{}.tar.gz", plan.version, platform.id());
            let archive_path = output.join("archive").join(&archive_name);
            let archive_sha256 = create(&ArchiveInput {
                platform,
                version: &plan.version,
                source_date_epoch: plan.source_date_epoch,
                executable: &binary,
                license: &license,
                notice: &notice,
                readme: &readme,
                output: &archive_path,
            })?;
            // Snapshot every candidate-adjacent output before the final executable
            // smoke test. The candidate runs as the same workspace user, so the trusted
            // parent rewrites these retained bytes after process-tree quiescence.
            let retained_archive = read_regular(&archive_path)?;
            let unpacked_root = transient_path(&root, &format!("unpacked-{}", platform.id()));
            let unpacked = extract_binary(
                &archive_path,
                platform,
                &plan.version,
                plan.source_date_epoch,
                &unpacked_root,
            )?;
            let smoke = with_release_candidate_environment(
                &target,
                &candidate_environment_root,
                plan.source_date_epoch,
                confinement.policy()?,
                || {
                    CommandSpec::new(unpacked.as_os_str(), Duration::from_secs(30))
                        .argument("--help")
                        .run()
                },
            )
            .map_err(|error| format!("cannot smoke-test packaged executable: {error}"))?;
            if !smoke.status.success() || smoke.timed_out {
                return Err("packaged executable smoke test failed".to_owned());
            }
            require_real_output_directories(&output)?;
            write_atomic(&archive_path, &retained_archive)?;
            for (name, bytes) in retained_outputs {
                write_atomic(&output.join(name), &bytes)?;
            }
            gates.insert("archive-verification", true);
            gates.insert("package-smoke", true);
            evidence.insert(
                "archive-verification".to_owned(),
                object([
                    ("archiveSha256", string(&archive_sha256)),
                    ("schemaVersion", number(1)),
                    ("state", string("passed")),
                ]),
            );
            evidence.insert(
                "package-smoke".to_owned(),
                object([
                    ("executable", string(platform.executable())),
                    ("schemaVersion", number(1)),
                    ("state", string("passed")),
                ]),
            );
            fs::remove_dir_all(&unpacked_root)
                .map_err(|error| format!("cannot remove unpacked smoke-test directory: {error}"))?;
            let expected = expected_gates(platform);
            if gates
                .keys()
                .copied()
                .collect::<std::collections::BTreeSet<_>>()
                != expected.iter().copied().collect()
                || gates.values().any(|passed| !passed)
                || evidence
                    .keys()
                    .map(String::as_str)
                    .collect::<std::collections::BTreeSet<_>>()
                    != expected.iter().copied().collect()
            {
                return Err("release platform gate implementation is incomplete".to_owned());
            }
            let ordered_gates = expected
                .iter()
                .map(|name| {
                    object([
                        ("name", string(name)),
                        ("passed", JsonValue::Bool(gates[name])),
                    ])
                })
                .collect();
            let conformance_gate = evidence
                .get("conformance-evidence")
                .ok_or_else(|| "conformance evidence gate is absent".to_owned())?
                .object()?
                .clone();
            let report = object([
                (
                    "assignedObligationCount",
                    json_member(&conformance_gate, "assignedObligations")?.clone(),
                ),
                ("archiveName", string(&archive_name)),
                ("archiveSha256", string(&archive_sha256)),
                ("buildInputsSha256", string(&plan.build_inputs_sha256)),
                ("candidateSha", string(&plan.resolution.candidate_sha)),
                (
                    "conformancePlanSha256",
                    string(&plan.conformance_plan_sha256),
                ),
                ("conformanceStandard", string(&plan.conformance_standard)),
                ("evidence", JsonValue::Object(evidence)),
                (
                    "evidenceManifestSha256",
                    json_member(&conformance_gate, "manifestSha256")?.clone(),
                ),
                (
                    "exploratoryObservationCount",
                    json_member(&conformance_gate, "exploratoryRecords")?.clone(),
                ),
                ("gates", JsonValue::Array(ordered_gates)),
                ("imageOS", string(&env::var("ImageOS").unwrap_or_default())),
                (
                    "imageVersion",
                    string(&env::var("ImageVersion").unwrap_or_default()),
                ),
                ("planSha256", string(&plan.plan_sha256)),
                ("platform", string(platform.id())),
                (
                    "producedEvidenceRecordCount",
                    json_member(&conformance_gate, "producedRecords")?.clone(),
                ),
                ("runAttempt", number(plan.resolution.run_attempt)),
                ("runId", number(plan.resolution.run_id)),
                ("schemaVersion", number(2)),
                ("state", string("passed")),
                ("tag", string(&plan.tag)),
                ("toolIdentities", JsonValue::Object(tools)),
                (
                    "trustedConformanceInputsSha256",
                    string(&plan.trusted_conformance_inputs_sha256),
                ),
                (
                    "unclassifiedMismatchCount",
                    json_member(&conformance_gate, "unclassifiedMismatches")?.clone(),
                ),
                ("version", string(&plan.version)),
                ("workflowSha", string(&plan.resolution.workflow_sha)),
            ]);
            write_json(&output.join("platform-report.json"), &report)?;
            write_json(
                &output.join("package-report.json"),
                &object([
                    ("archiveSha256", string(&archive_sha256)),
                    ("schemaVersion", number(1)),
                    ("state", string("verified")),
                ]),
            )?;
            write_json(
                &output.join("archive-manifest.json"),
                &object([
                    ("archiveName", string(&archive_name)),
                    ("archiveSha256", string(&archive_sha256)),
                    ("schemaVersion", number(1)),
                ]),
            )?;
            verify_final_platform_inventory(&output, platform, &archive_name)?;
            Ok(format!("completed {} release gate", platform.id()))
        },
    ))
    .unwrap_or_else(|_| {
        Err("release platform gate panicked after acquiring confinement".to_owned())
    });
    let principal_cleanup = confinement.finish_candidate_principal();
    #[cfg(windows)]
    let toolchain_cleanup = { confinement.close_windows_toolchain() };
    #[cfg(not(windows))]
    let toolchain_cleanup = Ok(());
    match (primary, principal_cleanup, toolchain_cleanup) {
        (Ok(result), Ok(()), Ok(())) => Ok(result),
        (primary, principal, toolchain) => Err([primary.err(), principal.err(), toolchain.err()]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join("; additionally, ")),
    }
}

fn compose_platform_gate_cleanup(
    primary: Result<(), String>,
    cleanup: Result<(), String>,
) -> Result<(), String> {
    match (primary, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(()), Err(cleanup)) => Err(cleanup),
        (Err(primary), Err(cleanup)) => Err(format!(
            "{primary}; additionally, dependency-policy cache cleanup failed: {cleanup}"
        )),
    }
}

#[cfg(unix)]
fn establish_candidate_process_confinement(
    platform: ReleasePlatform,
    candidate_root: &Path,
    oracle_root: &Path,
    candidate_inventory: &JsonValue,
    oracle_inventory: &JsonValue,
    candidate_sha: &str,
    workspace_target: &Path,
    output: &Path,
) -> Result<CandidateConfinement, String> {
    let process_authorities = ResolvedPosixProcessAuthorities::resolve()?;
    let sudo = process_authorities.sudo.invocation_path().to_path_buf();
    let chmod_path = posix_adapter_tool_paths(platform)?.chmod;
    let chmod = crate::command::resolve_absolute_standard_executable(Path::new(chmod_path))
        .map_err(|error| format!("cannot bind trusted chmod authority: {error}"))?;
    let (principal, group, uid, principal_cleanup) = match platform {
        ReleasePlatform::LinuxX86_64 => {
            allocate_linux_candidate_principal(Arc::clone(&process_authorities), "hellrel")?
        }
        ReleasePlatform::MacosAarch64 => {
            let principal = format!("hellrel{}", std::process::id());
            let group = principal.clone();
            let uid = 550_u32
                .checked_add(std::process::id() % 40)
                .ok_or_else(|| "candidate UID overflow".to_owned())?;
            let uid_text = uid.to_string();
            let mut cleanup = PosixPrincipalCleanup::new(
                platform,
                Arc::clone(&process_authorities),
                principal.clone(),
                group.clone(),
                Some(uid),
                Some(uid),
            )?;
            let reservation_deadline =
                posix_identity_query_deadline("macOS candidate reservation")?;
            if posix_principal_uid(reservation_deadline, platform, &principal)?.is_some()
                || posix_group_gid(reservation_deadline, &group)?.is_some()
            {
                return Err(
                    "macOS candidate principal or group name is already occupied".to_owned(),
                );
            }
            macos_principal_mutation(
                &mut cleanup,
                [
                    "-n",
                    "--",
                    "/usr/sbin/dseditgroup",
                    "-o",
                    "create",
                    "-i",
                    &uid_text,
                    &group,
                ],
            )?;
            if !cleanup.group_created {
                return Err("macOS candidate group creation had no observable effect".to_owned());
            }
            for (property, value) in [
                ("UniqueID", uid_text.as_str()),
                ("PrimaryGroupID", uid_text.as_str()),
                ("UserShell", "/usr/bin/false"),
                ("NFSHomeDirectory", "/var/empty"),
            ] {
                let record = Path::new("/Users").join(&principal);
                macos_principal_mutation(
                    &mut cleanup,
                    [
                        "-n",
                        "--",
                        "/usr/bin/dscl",
                        ".",
                        "-create",
                        record
                            .to_str()
                            .ok_or_else(|| "candidate account path is not UTF-8".to_owned())?,
                        property,
                        value,
                    ],
                )?;
            }
            if !cleanup.user_created {
                return Err("macOS candidate user creation had no observable effect".to_owned());
            }
            (principal, group, uid, cleanup)
        }
        ReleasePlatform::WindowsX86_64 => {
            return Err("Windows platform selected the POSIX confinement path".to_owned());
        }
    };
    let id = &process_authorities.identity;
    for (option, label) in [("-u", "UID"), ("-g", "primary GID")] {
        require_exact_posix_candidate_identity(&id, option, &principal, uid, label)?;
    }
    let group_output =
        exact_posix_candidate_identity_output(&id, "-G", &principal, "complete group inventory")?;
    let candidate_group_ids =
        posix_candidate_group_inventory(&group_output, uid).ok_or_else(|| {
            "candidate complete group inventory is not canonical or omits the primary GID"
                .to_owned()
        })?;
    use std::os::unix::fs::MetadataExt as _;

    let trusted_checkout_metadata = fs::symlink_metadata(candidate_root)
        .map_err(|error| format!("cannot inspect trusted candidate checkout owner: {error}"))?;
    let trusted_owner = trusted_checkout_metadata.uid();
    let trusted_group = trusted_checkout_metadata.gid();
    if candidate_group_ids.contains(&trusted_group) {
        return Err(
            "candidate account unexpectedly belongs to the trusted runner group".to_owned(),
        );
    }
    let current_exe = std::env::current_exe()
        .map_err(|error| format!("cannot resolve trusted POSIX adapter: {error}"))?;
    let adapter_protection = stage_posix_executable(platform, &sudo, &current_exe, "hell-ci")?;
    let cargo = crate::command::resolve_standard_cargo_executable()?;
    let stack_root_protection = (platform == ReleasePlatform::MacosAarch64)
        .then(|| stage_posix_stack_root(platform, &sudo, &adapter_protection, uid, trusted_group))
        .transpose()?;
    for protected in [candidate_root, oracle_root] {
        if platform == ReleasePlatform::MacosAarch64 {
            trusted_tool_status(
                &sudo,
                &chmod,
                [
                    "-RN",
                    protected
                        .to_str()
                        .ok_or_else(|| "protected path is not UTF-8".to_owned())?,
                ],
            )?;
        }
        trusted_tool_status(
            &sudo,
            &chmod,
            [
                "-R",
                "a-w",
                protected
                    .to_str()
                    .ok_or_else(|| "protected path is not UTF-8".to_owned())?,
            ],
        )?;
    }
    set_posix_mode(output, 0o700)?;
    let cargo_authority = crate::command::resolve_posix_cargo_authority(&cargo, candidate_root)?;
    let rustup_authority = match &cargo_authority {
        crate::command::ResolvedPosixCargoAuthority::Native { .. } => {
            return reject_native_posix_cargo_authority();
        }
        crate::command::ResolvedPosixCargoAuthority::Rustup(authority) => Some(authority),
    };
    let rustup_protection = rustup_authority
        .map(|authority| stage_posix_rustup_authority(platform, &sudo, authority))
        .transpose()?;
    let mut source_protection = stage_posix_sources(
        platform,
        &sudo,
        candidate_root,
        oracle_root,
        candidate_inventory,
        oracle_inventory,
        candidate_sha,
        workspace_target,
        &group,
        trusted_owner,
        uid,
        uid,
        trusted_group,
    )?;
    let candidate_target = stage_posix_candidate_target(
        &sudo,
        &adapter_protection,
        workspace_target,
        &source_protection.transient,
        trusted_owner,
        trusted_group,
        uid,
    )?;
    let candidate_environment = construct_posix_candidate_environment(
        platform,
        &sudo,
        &source_protection.tools,
        &source_protection.transient,
        trusted_owner,
        uid,
    )?;
    let isolated = candidate_environment.root.path().to_path_buf();
    source_protection.candidate_environment = Some(candidate_environment);
    validate_posix_sources(&source_protection, "after candidate environment capture")?;
    probe_posix_candidate_home(platform, &sudo, &principal, &isolated.join("home"))?;
    source_protection.validate_candidate_environment("after candidate home probes")?;
    // The whole-target normalizer and protected source staging establish the
    // final candidate authorities. Materialize cargo-deny's cache and metadata
    // against that exact execution checkout so no hosted-workspace path leaks
    // into the candidate invocation.
    let (cargo_deny_home_protection, dependency_policy_protection) =
        if platform == ReleasePlatform::LinuxX86_64 {
            let (home, policy) = stage_posix_cargo_deny_home(
                platform,
                &sudo,
                &adapter_protection,
                candidate_target.path(),
                &source_protection.candidate,
                candidate_sha,
                &cargo,
                uid,
                trusted_owner,
                trusted_group,
            )?;
            (Some(home), Some(policy))
        } else {
            (None, None)
        };
    source_protection.validate_candidate_environment("after trusted dependency-policy staging")?;
    let cargo_protection =
        stage_posix_executable(platform, &sudo, cargo.canonical_identity(), "cargo")?;
    let stack = (platform == ReleasePlatform::MacosAarch64)
        .then(|| crate::command::resolve_standard_path_executable(std::ffi::OsStr::new("stack")))
        .transpose()
        .map_err(|error| format!("cannot bind required Stack authority: {error}"))?;
    let stack_protection = stack
        .as_ref()
        .map(|resolved| {
            stage_posix_executable(platform, &sudo, resolved.canonical_identity(), "stack")
        })
        .transpose()?;
    let candidate_identity = hell_testkit::PosixCandidateIdentity::new(
        principal.clone(),
        uid,
        uid,
        candidate_group_ids,
        group.clone(),
    )
    .map_err(|error| format!("cannot bind candidate account identity: {error}"))?;
    let mut launch_authorities = hell_testkit::PosixLaunchAuthorities::new(
        adapter_protection.adapter.clone(),
        adapter_protection.sha256,
        cargo.canonical_identity().to_path_buf(),
        cargo_protection.adapter.clone(),
        cargo_protection.sha256,
        posix_cargo_source_authority(&cargo_authority, rustup_protection.as_ref())?,
    );
    if let (Some(resolved), Some(protection)) = (&stack, &stack_protection) {
        let metadata = fs::metadata(resolved.canonical_identity())
            .map_err(|error| format!("cannot inspect required Stack authority: {error}"))?;
        let source_sha256 = hell_testkit::sha256_file(resolved.canonical_identity())
            .map_err(|error| format!("cannot hash required Stack authority: {error}"))?;
        launch_authorities = launch_authorities.stack(hell_testkit::PosixStackAuthority::new(
            hell_testkit::PosixStandardExecutableIdentity::new(
                resolved.invocation_path().to_path_buf(),
                resolved.canonical_identity().to_path_buf(),
                metadata.dev(),
                metadata.ino(),
            ),
            source_sha256,
            protection.adapter.clone(),
            protection.sha256,
            stack_root_protection
                .as_ref()
                .ok_or_else(|| "macOS Stack-root authority is absent".to_owned())?
                .root
                .clone(),
            trusted_group,
        ));
    }
    let mut writable_roots = vec![
        candidate_target.path().to_path_buf(),
        source_protection.transient.clone(),
    ];
    if let Some(protection) = &stack_root_protection {
        writable_roots.push(protection.root.clone());
    }
    let policy = hell_testkit::CandidateLaunchPolicy::posix_with_process_authorities(
        sudo.clone(),
        process_authorities.launch_authorities()?,
        launch_authorities,
        candidate_identity,
        writable_roots,
    )
    .map_err(|error| format!("cannot establish candidate launch policy: {error}"))?;
    preflight_posix_driver_receipt_as_candidate(
        candidate_target.path(),
        &isolated,
        &policy,
        &source_protection.candidate,
        &adapter_protection,
    )?;
    preflight_exact_staged_rustc_as_candidate(
        candidate_target.path(),
        &isolated,
        &policy,
        &source_protection.candidate,
        rustup_protection.as_ref().ok_or_else(|| {
            "staged Rustup authority is absent before production gates".to_owned()
        })?,
    )?;
    Ok(CandidateConfinement {
        policy,
        _cleanup: principal_cleanup,
        _adapter_protection: adapter_protection,
        _cargo_protection: cargo_protection,
        cargo_deny_home_protection,
        dependency_policy_protection,
        _stack_protection: stack_protection,
        stack_root_protection,
        _rustup_protection: rustup_protection,
        candidate_target,
        source_protection,
    })
}

#[cfg(unix)]
fn posix_driver_receipt_arguments(
    adapter: &PosixAdapterProtection,
    require_restricted_consumer: bool,
) -> Vec<OsString> {
    vec![
        OsString::from("posix-driver-receipt-v1"),
        adapter.adapter.as_os_str().to_owned(),
        OsString::from(adapter.adapter_identity.device.to_string()),
        OsString::from(adapter.adapter_identity.inode.to_string()),
        OsString::from(adapter.adapter_identity.owner.to_string()),
        OsString::from(adapter.adapter_identity.group.to_string()),
        OsString::from(adapter.adapter_identity.mode.to_string()),
        OsString::from(adapter.sha256.hex()),
        OsString::from(if require_restricted_consumer {
            "restricted"
        } else {
            "fixture"
        }),
    ]
}

#[cfg(unix)]
fn preflight_posix_driver_receipt_as_candidate(
    candidate_target: &Path,
    environment_root: &Path,
    policy: &hell_testkit::CandidateLaunchPolicy,
    current_directory: &Path,
    adapter: &PosixAdapterProtection,
) -> Result<(), String> {
    let mut arguments = vec![OsString::from("__verify-posix-candidate-driver-receipt")];
    arguments.extend(posix_driver_receipt_arguments(adapter, true));
    let probe =
        with_release_candidate_environment(candidate_target, environment_root, 1, policy, || {
            CommandSpec::new(adapter.adapter.as_os_str(), Duration::from_mins(2))
                .arguments(arguments)
                .current_directory(current_directory)
                .run()
        })
        .map_err(|error| format!("cannot consume driver receipt as candidate: {error}"))?;
    if !probe.status.success()
        || probe.timed_out
        || probe.stdout_truncated
        || probe.stderr_truncated
        || !probe.stdout.is_empty()
        || !probe.stderr.is_empty()
    {
        return Err(format!(
            "driver receipt candidate preflight failed: status={:?}; stderr={}",
            probe.status.code(),
            String::from_utf8_lossy(&probe.stderr),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn preflight_exact_staged_rustc_as_candidate(
    candidate_target: &Path,
    environment_root: &Path,
    policy: &hell_testkit::CandidateLaunchPolicy,
    current_directory: &Path,
    rustup: &PosixRustupProtection,
) -> Result<(), String> {
    validate_posix_rustup_authority(rustup)?;
    let staged_rustc = rustup
        .home
        .join("toolchains")
        .join(rustup.toolchain.as_os_str())
        .join("bin/rustc");
    let probe = with_release_candidate_environment(
        candidate_target,
        environment_root,
        1,
        policy,
        || {
            CommandSpec::new(staged_rustc.as_os_str(), Duration::from_mins(5))
                .argument("-vV")
                .current_directory(current_directory)
                .run()
        },
    )
    .map_err(|error| {
        format!(
            "cannot execute exact staged Rust compiler as candidate: path={staged_rustc:?}; error={error}"
        )
    })?;
    let lines = probe
        .stdout
        .split(|byte| *byte == b'\n')
        .collect::<Vec<_>>();
    let has_identity = lines
        .first()
        .is_some_and(|line| line.starts_with(b"rustc "))
        && lines
            .iter()
            .filter(|line| line.starts_with(b"host: "))
            .count()
            == 1
        && lines
            .iter()
            .filter(|line| line.starts_with(b"release: "))
            .count()
            == 1;
    if !probe.status.success()
        || probe.timed_out
        || probe.stdout_truncated
        || probe.stderr_truncated
        || !probe.stderr.is_empty()
        || !probe.stdout.ends_with(b"\n")
        || !has_identity
    {
        return Err(format!(
            "exact staged Rust compiler candidate preflight failed: path={staged_rustc:?}; status={:?}; stderr={}",
            probe.status.code(),
            String::from_utf8_lossy(&probe.stderr)
        ));
    }
    validate_posix_rustup_authority(rustup)
        .map_err(|error| format!("staged Rust compiler changed during preflight: {error}"))
}

#[cfg(windows)]
fn exercise_windows_staged_toolchain_seal(
    protection: &mut WindowsToolchainProtection,
    deadline: Instant,
) -> Result<(), String> {
    let sharing_error = match fs::OpenOptions::new()
        .write(true)
        .open(protection.root.join("bin/cargo.exe"))
    {
        Ok(_) => {
            return Err(
                "retained Windows toolchain receipt accepted an incompatible writer".to_owned(),
            );
        }
        Err(error) => error,
    };
    if sharing_error.raw_os_error() != Some(32) {
        return Err(format!(
            "retained Windows toolchain writer denial was not a sharing violation: \
             osCode={:?}; error={sharing_error}",
            sharing_error.raw_os_error(),
        ));
    }
    seal_windows_toolchain_protection_until_with_entry_gate(protection, deadline, |_, _| Ok(()))?;
    let promoted = protection.promote_inventory_until(deadline)?;
    if promoted.len() != protection.files.len()
        || promoted
            .iter()
            .any(|file| file.windows_hash_passes_for_integration() != 1)
    {
        return Err(
            "promoted Windows toolchain inventory repeated or lost a staged hash receipt"
                .to_owned(),
        );
    }
    let expired = protection.promote_inventory_until(Instant::now());
    if !matches!(
        expired,
        Err(ref error)
            if error == "Windows toolchain receipt promotion exceeded its absolute deadline"
    ) {
        return Err(format!(
            "expired Windows toolchain promotion did not stop before receipt work: {expired:?}"
        ));
    }
    let writable = fs::OpenOptions::new()
        .write(true)
        .open(protection.root.join("bin/cargo.exe"));
    if writable.is_ok() {
        return Err("sealed Windows toolchain accepted a trusted content writer".to_owned());
    }
    crate::release_suite::run_windows_supervisor_icacls(
        &protection.root.join("lib/metadata.dll"),
        &["/inheritance:r", "/deny", "*S-1-5-11:(R)"],
        deadline,
    )?;
    let denial = match crate::command::WindowsBoundFileIdentity::bind_until_at(
        &protection.root.join("lib/metadata.dll"),
        deadline,
        crate::command::WindowsFileIdentityPhase::StagedToolchainPostSeal,
        Path::new("lib/metadata.dll"),
    ) {
        Ok(_) => return Err("injected Windows DACL denial accepted the staged file".to_owned()),
        Err(error) => error,
    };
    if !denial.contains("phase=staged-toolchain-post-seal")
        || !denial.contains("path=lib/metadata.dll")
        || !denial.contains("access=read share=read daclSealed=true")
        || !denial.contains("osCode=Some(5)")
    {
        return Err(format!(
            "Windows staged denial omitted typed identity context: {denial}"
        ));
    }
    if promoted
        .iter()
        .all(|file| file.windows_revalidate_for_integration().is_ok())
    {
        return Err("promoted Windows toolchain receipt accepted a DACL mutation".to_owned());
    }
    drop(promoted);
    Ok(())
}

#[cfg(windows)]
fn exercise_windows_staged_toolchain_seal_failure(
    protection: &mut WindowsToolchainProtection,
    deadline: Instant,
) -> Result<(), String> {
    let injected = seal_windows_toolchain_protection_until_with_entry_gate(
        protection,
        deadline,
        |relative, _| {
            if relative == Path::new("lib/metadata.dll") {
                Err("injected per-kind DACL seal failure".to_owned())
            } else {
                Ok(())
            }
        },
    );
    if !matches!(
        injected,
        Err(ref error) if error.contains("phase=per-kind-dacl")
            && error.contains("path=lib/metadata.dll")
            && error.contains("injected per-kind DACL seal failure")
    ) {
        return Err(format!(
            "Windows per-kind DACL failure lost its typed last-entry cause: {injected:?}"
        ));
    }
    protection.cleanup_until(deadline)?;
    if !matches!(
        fs::symlink_metadata(&protection.root),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    ) {
        return Err("injected Windows DACL failure retained its staged root".to_owned());
    }
    Ok(())
}

#[cfg(windows)]
fn cleanup_windows_staged_toolchain_source_fixture(
    fixture: &Path,
    source_root: &Path,
    directories: &[PathBuf],
    files: &[(PathBuf, &[u8])],
) -> Result<(), String> {
    for (relative, _) in files.iter().rev() {
        fs::remove_file(source_root.join(relative))
            .map_err(|error| format!("cannot remove Windows DACL verifier source file: {error}"))?;
    }
    for relative in directories.iter().skip(1).rev() {
        fs::remove_dir(source_root.join(relative)).map_err(|error| {
            format!("cannot remove Windows DACL verifier source directory: {error}")
        })?;
    }
    fs::remove_dir(source_root)
        .map_err(|error| format!("cannot remove Windows DACL verifier source: {error}"))?;
    fs::remove_dir(fixture)
        .map_err(|error| format!("cannot remove Windows DACL verifier root: {error}"))
}

#[cfg(windows)]
fn build_windows_staged_toolchain_fixture(
    source_root: &Path,
    staged_root: &Path,
    directories: &[PathBuf],
    files: &[(PathBuf, &[u8])],
    deadline: Instant,
) -> Result<WindowsToolchainProtection, String> {
    fs::create_dir(staged_root)
        .map_err(|error| format!("cannot create Windows DACL verifier stage: {error}"))?;
    for relative in directories.iter().skip(1) {
        fs::create_dir(staged_root.join(relative))
            .map_err(|error| format!("cannot create Windows DACL verifier stage: {error}"))?;
    }
    let toolchain_files = files
        .iter()
        .map(|(relative, _)| {
            crate::command::WindowsBoundFileIdentity::bind_until_at(
                &source_root.join(relative),
                deadline,
                crate::command::WindowsFileIdentityPhase::ToolchainSourceBinding,
                relative,
            )
            .map(|source| WindowsToolchainFile {
                relative: relative.clone(),
                source,
                staged: None,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    for file in &toolchain_files {
        copy_windows_toolchain_file_until(
            &file.source,
            &staged_root.join(&file.relative),
            deadline,
            &file.relative,
        )?;
    }
    let toolchain_files = toolchain_files
        .into_iter()
        .map(|mut file| {
            crate::command::WindowsBoundFileIdentity::bind_until_at(
                &staged_root.join(&file.relative),
                deadline,
                crate::command::WindowsFileIdentityPhase::StagedToolchainBinding,
                &file.relative,
            )
            .map(|staged| {
                file.staged = Some(staged);
                file
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(WindowsToolchainProtection {
        root: staged_root.to_path_buf(),
        source_root: source_root.to_path_buf(),
        files: toolchain_files,
        directories: directories.to_vec(),
        removed_directories: BTreeSet::new(),
        sealed: false,
        closed: false,
    })
}

#[cfg(windows)]
fn verify_windows_staged_toolchain_seal_for_integration(
    parent: &Path,
    deadline: Instant,
) -> Result<(), String> {
    let mut nonce = [0_u8; 16];
    getrandom::getrandom(&mut nonce)
        .map_err(|error| format!("cannot allocate Windows DACL verifier nonce: {error}"))?;
    let fixture = parent.join(format!(
        "windows-toolchain-dacl-{}",
        hell_testkit::sha256_bytes(&nonce).hex()
    ));
    let source_root = fixture.join("source");
    let failed_staged_root = fixture.join("staged-failure");
    let staged_root = fixture.join("staged-success");
    let directories = [PathBuf::new(), PathBuf::from("bin"), PathBuf::from("lib")];
    let files = [
        (PathBuf::from("bin/cargo.exe"), b"cargo-fixture".as_slice()),
        (
            PathBuf::from("lib/metadata.dll"),
            b"metadata-fixture".as_slice(),
        ),
    ];
    fs::create_dir(&fixture)
        .map_err(|error| format!("cannot create Windows DACL verifier root: {error}"))?;
    fs::create_dir(&source_root)
        .map_err(|error| format!("cannot create Windows DACL verifier source: {error}"))?;
    for relative in directories.iter().skip(1) {
        fs::create_dir(source_root.join(relative))
            .map_err(|error| format!("cannot create Windows DACL verifier source: {error}"))?;
    }
    for (relative, bytes) in &files {
        fs::write(source_root.join(relative), bytes)
            .map_err(|error| format!("cannot write Windows DACL verifier source: {error}"))?;
    }
    let mut failed_protection = build_windows_staged_toolchain_fixture(
        &source_root,
        &failed_staged_root,
        &directories,
        &files,
        deadline,
    )?;
    exercise_windows_staged_toolchain_seal_failure(&mut failed_protection, deadline)?;
    drop(failed_protection);
    let mut protection = build_windows_staged_toolchain_fixture(
        &source_root,
        &staged_root,
        &directories,
        &files,
        deadline,
    )?;
    let primary = exercise_windows_staged_toolchain_seal(&mut protection, deadline);
    let cleanup = protection.cleanup_until(deadline);
    drop(protection);
    let source_cleanup = cleanup_windows_staged_toolchain_source_fixture(
        &fixture,
        &source_root,
        &directories,
        &files,
    );
    match (primary, cleanup, source_cleanup) {
        (Ok(()), Ok(()), Ok(())) => Ok(()),
        (primary, cleanup, source_cleanup) => {
            let mut failures = Vec::new();
            if let Err(error) = primary {
                failures.push(error);
            }
            if let Err(error) = cleanup {
                failures.push(format!(
                    "Windows DACL verifier stage cleanup failed: {error}"
                ));
            }
            if let Err(error) = source_cleanup {
                failures.push(format!(
                    "Windows DACL verifier source cleanup failed: {error}"
                ));
            }
            Err(failures.join("; additionally, "))
        }
    }
}

#[cfg(windows)]
pub(crate) fn verify_windows_candidate_target_authority_for_integration() -> Result<(), String> {
    struct FixtureOwner {
        root: PathBuf,
        confinement: Option<CandidateConfinement>,
    }

    impl FixtureOwner {
        fn finish(
            mut self,
            primary: Result<(), String>,
            cleanup_deadline: Instant,
        ) -> Result<(), String> {
            let mut failures = Vec::new();
            if let Err(primary) = primary {
                failures.push(primary);
            }
            if let Some(mut confinement) = self.confinement.take()
                && let Err(error) = confinement.close_windows_toolchain_until(cleanup_deadline)
            {
                failures.push(format!(
                    "Windows target verifier production confinement cleanup failed: {error}"
                ));
            }
            if Instant::now() >= cleanup_deadline {
                failures
                    .push("Windows target verifier root cleanup exceeded its deadline".to_owned());
            } else if let Err(error) = fs::remove_dir_all(&self.root) {
                failures.push(format!(
                    "cannot remove Windows target verifier root: {error}"
                ));
            }
            if !matches!(
                fs::symlink_metadata(&self.root),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound
            ) {
                failures.push("Windows target verifier root remains after cleanup".to_owned());
            }
            if failures.is_empty() {
                Ok(())
            } else {
                Err(failures.join("; additionally, "))
            }
        }
    }

    let started = Instant::now();
    let cleanup_deadline = started
        .checked_add(Duration::from_mins(10))
        .ok_or_else(|| "Windows target verifier completion deadline overflowed".to_owned())?;
    let execution_deadline = started
        .checked_add(Duration::from_mins(9))
        .ok_or_else(|| "Windows target verifier execution deadline overflowed".to_owned())?;
    let sequence = WINDOWS_CANDIDATE_TARGET_VERIFIER_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let authority = std::env::temp_dir().join(format!(
        "hell-windows-candidate-target-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir(&authority)
        .map_err(|error| format!("cannot create Windows target verifier authority: {error}"))?;
    let mut owner = FixtureOwner {
        root: authority.clone(),
        confinement: None,
    };
    let primary = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let candidate = authority.join("candidate");
        let oracle = authority.join("oracle");
        let output = authority.join("output");
        let target = authority.join("candidate-target");
        let environment = target.join("release-child-environment");
        for directory in [
            candidate.join("src"),
            oracle.clone(),
            output.clone(),
            environment.join("home"),
            environment.join("cargo"),
            environment.join("sccache"),
            environment.join("tmp"),
        ] {
            fs::create_dir_all(&directory).map_err(|error| {
                format!("cannot create Windows target verifier directory: {error}")
            })?;
        }
        fs::write(
            candidate.join("Cargo.toml"),
            b"[package]\nname = \"windows-target-probe\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[[bin]]\nname = \"windows-target-probe\"\npath = \"src/main.rs\"\n",
        )
        .map_err(|error| format!("cannot write Windows target verifier manifest: {error}"))?;
        fs::write(
            candidate.join("Cargo.lock"),
            b"# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\nversion = 4\n\n[[package]]\nname = \"windows-target-probe\"\nversion = \"0.0.0\"\n",
        )
        .map_err(|error| format!("cannot write Windows target verifier lockfile: {error}"))?;
        fs::write(candidate.join("src/main.rs"), b"fn main() {}\n")
            .map_err(|error| format!("cannot write Windows target verifier source: {error}"))?;
        for arguments in [
            &["init", "--quiet"][..],
            &["add", "--", "Cargo.toml", "Cargo.lock", "src/main.rs"][..],
        ] {
            let (progress, _progress_receiver) =
                hell_testkit::SupervisedProgressObserver::bounded(1);
            let result = CommandSpec::new("git", Duration::from_secs(30))
                .git_safe_directory(&candidate)
                .arguments(arguments.iter().copied())
                .current_directory(&candidate)
                .run_until(execution_deadline, execution_deadline, progress)
                .map_err(|error| {
                    format!("cannot initialize Windows Git inventory fixture: {error}")
                })?;
            if !result.status.success() || result.timed_out || !result.stderr.is_empty() {
                return Err("Windows Git inventory fixture initialization failed".to_owned());
            }
        }
        let authority = fs::canonicalize(&authority)
            .map_err(|error| format!("cannot canonicalize Windows target verifier: {error}"))?;
        let candidate = authority.join("candidate");
        let oracle = authority.join("oracle");
        let output = authority.join("output");
        let target = authority.join("candidate-target");
        verify_windows_staged_toolchain_seal_for_integration(&authority, execution_deadline)?;
        require_candidate_target(&candidate, &target)?;
        owner.confinement = Some(establish_candidate_process_confinement(
            ReleasePlatform::WindowsX86_64,
            &candidate,
            &oracle,
            &JsonValue::Null,
            &JsonValue::Null,
            "0000000000000000000000000000000000000000",
            &target,
            &output,
        )?);
        let confinement = owner
            .confinement
            .as_mut()
            .ok_or_else(|| "Windows target verifier confinement is absent".to_owned())?;
        let environment = confinement.candidate_environment_root(&target);
        let verifier_executable = std::env::current_exe()
            .map_err(|error| format!("cannot resolve Windows target-stderr verifier: {error}"))?;
        let (result, inventory, target_stderr) = with_release_candidate_environment(
            &target,
            &environment,
            1,
            confinement.policy()?,
            || {
                let (build_progress, _build_progress_receiver) =
                    hell_testkit::SupervisedProgressObserver::bounded(1);
                let build = CommandSpec::cargo(Duration::from_mins(5))
                    .arguments(["build", "--release", "--locked"])
                    .current_directory(&candidate)
                    .run_until(execution_deadline, execution_deadline, build_progress);
                let inventory =
                    crate::policy::verify_repository_inventory_for_integration(&candidate);
                let (stderr_progress, _stderr_progress_receiver) =
                    hell_testkit::SupervisedProgressObserver::bounded(1);
                let target_stderr =
                    CommandSpec::new(&verifier_executable, Duration::from_secs(30))
                        .argument("__repository-inventory-target-stderr-child")
                        .current_directory(&candidate)
                        .run_until(execution_deadline, execution_deadline, stderr_progress);
                (build, inventory, target_stderr)
            },
        );
        let result = result
            .map_err(|error| format!("cannot run restricted Windows target verifier: {error}"))?;
        if !result.status.success() || result.timed_out {
            return Err("restricted Windows target verifier build failed".to_owned());
        }
        inventory?;
        let target_stderr = target_stderr
            .map_err(|error| format!("cannot run Windows target-stderr verifier: {error}"))?;
        crate::policy::verify_repository_inventory_target_stderr_for_integration(&target_stderr)?;
        let expected = target.join("release/windows-target-probe.exe");
        let metadata = fs::symlink_metadata(&expected).map_err(|error| {
            format!("cannot inspect restricted Windows target artifact: {error}")
        })?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || fs::canonicalize(&expected).ok().as_deref() != Some(expected.as_path())
            || candidate.join("target").exists()
        {
            return Err(
                "restricted Windows Cargo output differs from its exact target authority"
                    .to_owned(),
            );
        }
        Ok(())
    }))
    .unwrap_or_else(|payload| {
        let detail = payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| payload.downcast_ref::<&str>().map(|message| (*message).to_owned()))
            .unwrap_or_else(|| "Windows target verifier panicked".to_owned());
        Err(detail)
    });
    owner.finish(primary, cleanup_deadline)
}

#[cfg(unix)]
fn posix_cargo_source_authority(
    resolved: &crate::command::ResolvedPosixCargoAuthority,
    staged: Option<&PosixRustupProtection>,
) -> Result<hell_testkit::PosixCargoSourceAuthority, String> {
    match (resolved, staged) {
        (
            crate::command::ResolvedPosixCargoAuthority::Native {
                cargo: _,
                standard_rustup: _,
            },
            None,
        ) => reject_native_posix_cargo_authority(),
        (crate::command::ResolvedPosixCargoAuthority::Rustup(_), Some(protection)) => {
            let proxy = &protection.proxy_identity;
            let rustc_standard = protection.rustc_authority.standard();
            let rustc_identity = hell_testkit::PosixStandardExecutableIdentity::new(
                rustc_standard.invocation().to_path_buf(),
                rustc_standard.canonical().to_path_buf(),
                rustc_standard.device(),
                rustc_standard.inode(),
            );
            let rustc_authority = match &protection.rustc_authority {
                crate::command::ResolvedPosixRustcAuthority::RustupProxy { .. } => {
                    hell_testkit::PosixRustcAuthority::RustupProxy(rustc_identity)
                }
                crate::command::ResolvedPosixRustcAuthority::SelectedToolchain { .. } => {
                    hell_testkit::PosixRustcAuthority::SelectedToolchain(rustc_identity)
                }
            };
            let source_rustc = protection
                .source_home
                .join("toolchains")
                .join(&protection.toolchain)
                .join("bin")
                .join("rustc");
            let staged_rustc = protection
                .home
                .join("toolchains")
                .join(&protection.toolchain)
                .join("bin")
                .join("rustc");
            let source_sha256 = hell_testkit::sha256_file(&source_rustc)
                .map_err(|error| format!("cannot hash source Rust compiler: {error}"))?;
            let staged_sha256 = hell_testkit::sha256_file(&staged_rustc)
                .map_err(|error| format!("cannot hash staged Rust compiler: {error}"))?;
            Ok(hell_testkit::PosixCargoSourceAuthority::Rustup(Box::new(
                hell_testkit::PosixRustupAuthority::new(
                    hell_testkit::PosixRustupProxyIdentity::new(
                        proxy.cargo_invocation().to_path_buf(),
                        proxy.cargo().to_path_buf(),
                        proxy.rustup_invocation().to_path_buf(),
                        proxy.rustup().to_path_buf(),
                        proxy.device(),
                        proxy.inode(),
                    ),
                    rustc_authority,
                    protection.source_home.clone(),
                    protection.home.clone(),
                    protection.toolchain.clone(),
                    hell_testkit::PosixRustupCompilerMapping::new(
                        source_rustc,
                        source_sha256,
                        staged_rustc,
                        staged_sha256,
                    ),
                ),
            )))
        }
        _ => Err("resolved and staged Rustup authorities disagree".to_owned()),
    }
}

#[cfg(unix)]
fn reject_native_posix_cargo_authority<T>() -> Result<T, String> {
    Err("native Cargo lacks a closed staged Rust compiler authority for POSIX release".to_owned())
}

#[cfg(unix)]
pub(crate) fn verify_posix_candidate_driver_receipt_for_integration(
    arguments: &[OsString],
) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;

    let [
        protocol,
        path,
        device,
        inode,
        owner,
        group,
        mode,
        digest,
        consumer,
    ] = arguments
    else {
        return Err("POSIX driver receipt field count differs".to_owned());
    };
    if protocol != "posix-driver-receipt-v1" {
        return Err("POSIX driver receipt protocol differs".to_owned());
    }
    let path = PathBuf::from(path);
    let parse_u64 = |value: &OsString, label: &str| {
        value
            .to_str()
            .ok_or_else(|| format!("POSIX driver receipt {label} is not UTF-8"))?
            .parse::<u64>()
            .map_err(|error| format!("POSIX driver receipt {label} is invalid: {error}"))
    };
    let expected_device = parse_u64(device, "device")?;
    let expected_inode = parse_u64(inode, "inode")?;
    let expected_owner = u32::try_from(parse_u64(owner, "owner")?)
        .map_err(|_| "POSIX driver receipt owner is out of range".to_owned())?;
    let expected_group = u32::try_from(parse_u64(group, "group")?)
        .map_err(|_| "POSIX driver receipt group is out of range".to_owned())?;
    let expected_mode = u32::try_from(parse_u64(mode, "mode")?)
        .map_err(|_| "POSIX driver receipt mode is out of range".to_owned())?;
    let expected_digest = hell_testkit::Digest::from_hex(
        digest
            .to_str()
            .ok_or_else(|| "POSIX driver receipt digest is not UTF-8".to_owned())?,
    )
    .map_err(|error| format!("POSIX driver receipt digest is invalid: {error}"))?;
    let executable = std::env::current_exe()
        .map_err(|error| format!("cannot resolve candidate verifier executable: {error}"))?;
    let canonical = fs::canonicalize(&executable)
        .map_err(|error| format!("cannot canonicalize candidate verifier executable: {error}"))?;
    let metadata = fs::symlink_metadata(&executable)
        .map_err(|error| format!("cannot inspect candidate verifier executable: {error}"))?;
    let canonical_metadata = fs::metadata(&canonical).map_err(|error| {
        format!("cannot inspect canonical candidate verifier executable: {error}")
    })?;
    let candidate_uid = nix::unistd::geteuid().as_raw();
    let require_restricted = match consumer.to_str() {
        Some("restricted") => true,
        Some("fixture") => false,
        _ => return Err("POSIX driver receipt consumer kind differs".to_owned()),
    };
    if (require_restricted && canonical_metadata.uid() == candidate_uid)
        || metadata.file_type().is_symlink()
        || !canonical_metadata.is_file()
        || canonical != path
        || canonical_metadata.mode() & 0o022 != 0
        || canonical_metadata.dev() != expected_device
        || canonical_metadata.ino() != expected_inode
        || canonical_metadata.uid() != expected_owner
        || canonical_metadata.gid() != expected_group
        || canonical_metadata.mode() & 0o7777 != expected_mode
        || hell_testkit::sha256_file(&canonical)
            .map_err(|error| format!("cannot hash candidate verifier executable: {error}"))?
            != expected_digest
    {
        return Err(
            "candidate verifier executable lacks its driver-owned pre-candidate receipt".to_owned(),
        );
    }
    Ok(())
}

#[cfg(unix)]
struct PosixAdapterProtection {
    platform: ReleasePlatform,
    installation_root: PathBuf,
    installation_root_identity: PosixObjectIdentity,
    directory: PathBuf,
    directory_identity: PosixObjectIdentity,
    adapter: PathBuf,
    adapter_identity: PosixObjectIdentity,
    sha256: hell_testkit::Digest,
    staged_name: &'static str,
    sudo: PathBuf,
    tools: PosixAdapterTools,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PosixTransientAuthorityTransition {
    ChangeOwner,
    ChangeGroup,
    RestoreMode03770,
}

#[cfg(unix)]
const POSIX_TRANSIENT_AUTHORITY_TRANSITIONS: [PosixTransientAuthorityTransition; 3] = [
    PosixTransientAuthorityTransition::ChangeOwner,
    PosixTransientAuthorityTransition::ChangeGroup,
    PosixTransientAuthorityTransition::RestoreMode03770,
];

#[cfg(unix)]
struct PosixSourceProtection {
    platform: ReleasePlatform,
    installation_root: PathBuf,
    installation_root_identity: PosixObjectIdentity,
    directory: PathBuf,
    directory_identity: PosixObjectIdentity,
    candidate: PathBuf,
    oracle: PathBuf,
    stack_work: Option<PathBuf>,
    stack_work_identity: Option<PosixObjectIdentity>,
    stack_work_owner: u32,
    stack_work_group: u32,
    candidate_uid: u32,
    candidate_primary_gid: u32,
    transient: PathBuf,
    transient_identity: PosixObjectIdentity,
    transient_owner: u32,
    transient_group: u32,
    candidate_environment: Option<PosixCandidateEnvironmentProtection>,
    archive_adapter: PathBuf,
    archive_adapter_identity: PosixObjectIdentity,
    archive_adapter_owner: u32,
    archive_adapter_group: u32,
    retained_oracle: PathBuf,
    retained_oracle_directory_identity: PosixObjectIdentity,
    retained_oracle_file: Option<PosixRetainedOracleFile>,
    candidate_inventory: JsonValue,
    oracle_inventory: JsonValue,
    candidate_sha: String,
    sudo: PathBuf,
    tools: PosixAdapterTools,
    active: bool,
}

#[cfg(unix)]
struct PosixCandidateEnvironmentProtection {
    root: hell_testkit::PosixDirectoryCheckpoint,
    children: Vec<hell_testkit::PosixDirectoryCheckpoint>,
}

#[cfg(unix)]
struct PosixCandidateTargetProtection {
    staged: PathBuf,
    staged_identity: PosixObjectIdentity,
    workspace: PathBuf,
    workspace_identity: PosixObjectIdentity,
    trusted_owner: u32,
    trusted_group: u32,
}

#[cfg(unix)]
impl PosixCandidateTargetProtection {
    fn path(&self) -> &Path {
        &self.staged
    }
}

#[cfg(unix)]
struct PosixArchiveAdapterSeal<'a> {
    platform: ReleasePlatform,
    parent: PathBuf,
    parent_identity: PosixObjectIdentity,
    parent_owner: u32,
    parent_group: u32,
    adapter: PathBuf,
    adapter_identity: PosixObjectIdentity,
    work_directory: PathBuf,
    work_directory_identity: PosixObjectIdentity,
    temporary_directory: PathBuf,
    temporary_directory_identity: PosixObjectIdentity,
    source_parent: PathBuf,
    source_parent_identity: PosixObjectIdentity,
    source: PathBuf,
    source_identity: PosixObjectIdentity,
    stack_work: PathBuf,
    stack_work_identity: PosixObjectIdentity,
    candidate_uid: u32,
    candidate_primary_gid: u32,
    quiescence_receipt: Option<hell_testkit::PosixCandidateQuiescenceReceipt>,
    normalizer: &'a PosixAdapterProtection,
    sudo: PathBuf,
    tools: PosixAdapterTools,
}

#[cfg(unix)]
fn ordered_bounded_failures(
    context: &str,
    failures: impl IntoIterator<Item = (&'static str, String)>,
) -> String {
    const DIAGNOSTIC_BYTE_LIMIT: usize = 16_384;

    let mut diagnostic = context.to_owned();
    for (phase, error) in failures {
        let component = format!("; {phase}: {error}");
        let Some(next_len) = diagnostic.len().checked_add(component.len()) else {
            diagnostic.push_str("; <diagnostic-length-overflow>");
            break;
        };
        if next_len > DIAGNOSTIC_BYTE_LIMIT {
            diagnostic.push_str("; <diagnostic-bounded>");
            break;
        }
        diagnostic.push_str(&component);
    }
    diagnostic
}

#[cfg(target_os = "macos")]
fn attest_native_archive_adapter_absence(
    adapter: Option<&Path>,
    deadline: Instant,
) -> Result<(), String> {
    let Some(adapter) = adapter else {
        return Ok(());
    };
    if Instant::now() >= deadline {
        return Err(
            "native archive adapter final attestation exceeded its absolute deadline".to_owned(),
        );
    }
    match fs::symlink_metadata(adapter) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err("native archive adapter root remains after retained cleanup".to_owned()),
        Err(error) => Err(format!(
            "cannot attest native archive adapter root absence: {error}"
        )),
    }
}

#[cfg(unix)]
#[derive(Clone, Copy)]
struct PosixNoFollowRemovalPolicy {
    entry_limit: usize,
    depth_limit: usize,
    operation_limit: usize,
    deadline: Instant,
}

#[cfg(unix)]
#[derive(Clone, Copy)]
struct PosixNoFollowRemovalRoot<'a> {
    directory: &'a Path,
    retained_child: Option<&'a Path>,
}

#[cfg(unix)]
fn posix_no_follow_operation_limit(entry_limit: usize) -> Result<usize, String> {
    const DIRECTORY_OPERATIONS_PER_ENTRY: usize = 5;

    entry_limit
        .checked_mul(DIRECTORY_OPERATIONS_PER_ENTRY)
        .ok_or_else(|| "bounded no-follow cleanup operation bound overflowed".to_owned())
}

#[cfg(unix)]
fn remove_posix_no_follow_forest(
    roots: &[PosixNoFollowRemovalRoot<'_>],
    policy: PosixNoFollowRemovalPolicy,
    mut validate_roots: impl FnMut() -> Result<(), String>,
    mut open_directory: impl FnMut(&Path) -> Result<(), String>,
    mut unlink_file: impl FnMut(&Path) -> Result<(), String>,
    mut remove_directory: impl FnMut(&Path) -> Result<(), String>,
) -> Result<(), String> {
    fn admit_operation(operations: &mut usize, limit: usize) -> Result<(), String> {
        *operations = operations
            .checked_add(1)
            .filter(|count| *count <= limit)
            .ok_or_else(|| {
                "bounded no-follow cleanup exceeds its global operation bound".to_owned()
            })?;
        Ok(())
    }

    let require_time = || {
        policy
            .deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| "bounded no-follow cleanup deadline expired".to_owned())
            .map(|_| ())
    };
    let mut discovered = roots.len();
    let mut operations = 0usize;
    if discovered > policy.entry_limit {
        return Err("bounded no-follow cleanup exceeds its global entry bound".to_owned());
    }
    let mut pending = Vec::new();
    for root in roots {
        require_time()?;
        admit_operation(&mut operations, policy.operation_limit)?;
        validate_roots()?;
        let mut children = Vec::new();
        for entry in fs::read_dir(root.directory)
            .map_err(|error| format!("cannot enumerate bounded no-follow root: {error}"))?
        {
            let path = entry
                .map_err(|error| format!("cannot read bounded no-follow root entry: {error}"))?
                .path();
            if root.retained_child == Some(path.as_path()) {
                continue;
            }
            discovered = discovered
                .checked_add(1)
                .filter(|count| *count <= policy.entry_limit)
                .ok_or_else(|| {
                    "bounded no-follow cleanup exceeds its global entry bound".to_owned()
                })?;
            let metadata = fs::symlink_metadata(&path)
                .map_err(|error| format!("cannot bind bounded no-follow root member: {error}"))?;
            children.push((
                path,
                posix_object_identity_from_metadata(&metadata),
                false,
                1usize,
            ));
        }
        children.sort_by(|left, right| left.0.cmp(&right.0));
        pending.extend(children.into_iter().rev());
    }

    while let Some((path, receipt, visited, depth)) = pending.pop() {
        require_time()?;
        admit_operation(&mut operations, policy.operation_limit)?;
        validate_roots()?;
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot revalidate bounded no-follow member: {error}"))?;
        if posix_object_identity_from_metadata(&metadata) != receipt {
            return Err("bounded no-follow member changed after receipt binding".to_owned());
        }
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            if visited {
                admit_operation(&mut operations, policy.operation_limit)?;
                remove_directory(&path)?;
            } else {
                if depth >= policy.depth_limit {
                    return Err("bounded no-follow cleanup exceeds its depth bound".to_owned());
                }
                admit_operation(&mut operations, policy.operation_limit)?;
                open_directory(&path)?;
                require_time()?;
                admit_operation(&mut operations, policy.operation_limit)?;
                validate_roots()?;
                let opened_metadata = fs::symlink_metadata(&path).map_err(|error| {
                    format!("cannot rebind opened bounded no-follow directory: {error}")
                })?;
                let opened_receipt = posix_object_identity_from_metadata(&opened_metadata);
                if opened_receipt.device != receipt.device
                    || opened_receipt.inode != receipt.inode
                    || opened_metadata.file_type().is_symlink()
                    || !opened_metadata.is_dir()
                {
                    return Err(
                        "bounded no-follow directory changed while it was opened".to_owned()
                    );
                }
                let mut children = Vec::new();
                for entry in fs::read_dir(&path).map_err(|error| {
                    format!("cannot enumerate bounded no-follow directory: {error}")
                })? {
                    require_time()?;
                    discovered = discovered
                        .checked_add(1)
                        .filter(|count| *count <= policy.entry_limit)
                        .ok_or_else(|| {
                            "bounded no-follow cleanup exceeds its global entry bound".to_owned()
                        })?;
                    let child = entry.map_err(|error| {
                        format!("cannot read bounded no-follow directory entry: {error}")
                    })?;
                    let child_path = child.path();
                    let child_metadata = fs::symlink_metadata(&child_path).map_err(|error| {
                        format!("cannot bind bounded no-follow member: {error}")
                    })?;
                    children.push((
                        child_path,
                        posix_object_identity_from_metadata(&child_metadata),
                        false,
                        depth + 1,
                    ));
                }
                children.sort_by(|left, right| left.0.cmp(&right.0));
                pending.push((path, opened_receipt, true, depth));
                pending.extend(children.into_iter().rev());
                continue;
            }
        } else if metadata.is_file() || metadata.file_type().is_symlink() {
            admit_operation(&mut operations, policy.operation_limit)?;
            unlink_file(&path)?;
        } else {
            return Err("bounded no-follow cleanup found an unsupported entry type".to_owned());
        }
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => return Err("bounded no-follow member cleanup was not exact".to_owned()),
            Err(error) => {
                return Err(format!(
                    "cannot attest bounded no-follow member absence: {error}"
                ));
            }
        }
    }
    require_time()?;
    admit_operation(&mut operations, policy.operation_limit)?;
    validate_roots()
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct PosixSourceStackCleanupReceipt {
    source_identity: PosixObjectIdentity,
}

#[cfg(unix)]
#[derive(Clone, Copy)]
struct PosixSourceStackCleanupContext<'a> {
    source: &'a Path,
    stack_work: &'a Path,
    deadline: Instant,
}

#[cfg(unix)]
fn cleanup_posix_source_stack_work_before_snapshot(
    context: PosixSourceStackCleanupContext<'_>,
    mut validate_roots: impl FnMut() -> Result<(), String>,
    open_directory: impl FnMut(&Path) -> Result<(), String>,
    unlink_file: impl FnMut(&Path) -> Result<(), String>,
    mut remove_directory: impl FnMut(&Path) -> Result<(), String>,
    validate_snapshot: impl FnOnce(Instant) -> Result<(), String>,
) -> Result<PosixSourceStackCleanupReceipt, String> {
    const SOURCE_STACK_ENTRY_LIMIT: usize = 1_000_000;
    const SOURCE_STACK_DEPTH_LIMIT: usize = 256;

    let source_identity = posix_object_identity(context.source)?;
    remove_posix_no_follow_forest(
        &[PosixNoFollowRemovalRoot {
            directory: context.stack_work,
            retained_child: None,
        }],
        PosixNoFollowRemovalPolicy {
            entry_limit: SOURCE_STACK_ENTRY_LIMIT,
            depth_limit: SOURCE_STACK_DEPTH_LIMIT,
            operation_limit: posix_no_follow_operation_limit(SOURCE_STACK_ENTRY_LIMIT)?,
            deadline: context.deadline,
        },
        &mut validate_roots,
        open_directory,
        unlink_file,
        &mut remove_directory,
    )?;
    if Instant::now() >= context.deadline {
        return Err("candidate Stack work cleanup deadline expired before root removal".to_owned());
    }
    validate_roots()?;
    if Instant::now() >= context.deadline {
        return Err(
            "candidate Stack work cleanup deadline expired before root mutation".to_owned(),
        );
    }
    remove_directory(context.stack_work)?;
    match fs::symlink_metadata(context.stack_work) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => return Err("candidate Stack work root cleanup was not exact".to_owned()),
        Err(error) => {
            return Err(format!(
                "cannot attest candidate Stack work root absence: {error}"
            ));
        }
    }
    if Instant::now() >= context.deadline {
        return Err("candidate Stack work cleanup deadline expired before snapshot".to_owned());
    }
    validate_snapshot(context.deadline)?;
    let observed_source_identity = posix_object_identity(context.source)?;
    if observed_source_identity != source_identity {
        return Err("staged oracle identity changed during Stack cleanup".to_owned());
    }
    Ok(PosixSourceStackCleanupReceipt { source_identity })
}

#[cfg(unix)]
fn require_posix_archive_cleanup_quiescence(
    receipt: Option<&hell_testkit::PosixCandidateQuiescenceReceipt>,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), String> {
    let receipt = receipt.ok_or_else(|| {
        "candidate quiescence receipt is absent before archive cleanup".to_owned()
    })?;
    if !receipt.matches_numeric_identity(expected_uid, expected_gid) {
        return Err(format!(
            "candidate quiescence receipt identity differs before archive cleanup: principal={}",
            receipt.principal()
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn run_native_oracle_restoration_phases(
    deadlines: NativeOracleCleanupDeadlines,
    source_cleanup: impl FnOnce(Instant) -> Result<(), String>,
    adapter_cleanup: impl FnOnce(Instant) -> Result<(), String>,
    final_restore: impl FnOnce(Instant) -> Result<(), String>,
) -> Result<(), String> {
    let source_cleanup = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        source_cleanup(deadlines.source_work)
    }))
    .unwrap_or_else(|_| Err("source work cleanup panicked".to_owned()));
    let adapter_cleanup = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        adapter_cleanup(deadlines.adapter_work)
    }))
    .unwrap_or_else(|_| Err("adapter work cleanup panicked".to_owned()));
    let final_restore = if adapter_cleanup.is_ok() {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            final_restore(deadlines.final_restore)
        }))
        .unwrap_or_else(|_| Err("adapter final restore panicked".to_owned()))
    } else {
        Err("adapter final restore skipped after unsafe work cleanup failure".to_owned())
    };
    let failures = [
        ("source-work-cleanup", source_cleanup),
        ("adapter-work-cleanup", adapter_cleanup),
        ("adapter-final-restore", final_restore),
    ]
    .into_iter()
    .filter_map(|(phase, result)| result.err().map(|error| (phase, error)))
    .collect::<Vec<_>>();
    if failures.is_empty() {
        Ok(())
    } else {
        Err(ordered_bounded_failures(
            "native archive adapter restoration failed",
            failures,
        ))
    }
}

#[cfg(unix)]
struct NativeOracleFinalizationResults {
    adapter_close: Result<(), String>,
    final_attestation: Result<(), String>,
}

#[cfg(unix)]
fn run_native_oracle_finalizer(
    deadlines: NativeOracleCleanupDeadlines,
    adapter_close: impl FnOnce(Instant) -> Result<(), String>,
    final_attestation: impl FnOnce(Instant) -> Result<(), String>,
) -> NativeOracleFinalizationResults {
    let adapter_close = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        adapter_close(deadlines.adapter_close)
    }))
    .unwrap_or_else(|_| Err("native archive adapter cleanup panicked".to_owned()));
    let final_attestation = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        final_attestation(deadlines.final_attestation)
    }))
    .unwrap_or_else(|_| Err("native archive adapter final attestation panicked".to_owned()));
    NativeOracleFinalizationResults {
        adapter_close,
        final_attestation,
    }
}

#[cfg(unix)]
impl PosixArchiveAdapterSeal<'_> {
    fn restore(
        mut self,
        receipt: hell_testkit::PosixCandidateQuiescenceReceipt,
        deadlines: NativeOracleCleanupDeadlines,
    ) -> Result<(), String> {
        require_posix_archive_cleanup_quiescence(
            Some(&receipt),
            self.candidate_uid,
            self.candidate_primary_gid,
        )?;
        self.quiescence_receipt = Some(receipt);
        self.restore_inner(deadlines)
    }

    fn restore_inner(&self, deadlines: NativeOracleCleanupDeadlines) -> Result<(), String> {
        require_posix_archive_cleanup_quiescence(
            self.quiescence_receipt.as_ref(),
            self.candidate_uid,
            self.candidate_primary_gid,
        )?;
        require_posix_archive_adapter_transition_state_phase(
            PosixArchiveAdapterTransitionState {
                parent: &self.parent,
                parent_identity: &self.parent_identity,
                parent_owner: self.parent_owner,
                parent_group: self.parent_group,
                parent_mode: 0o2550,
                adapter: &self.adapter,
                adapter_identity: &self.adapter_identity,
                work_directory: &self.work_directory,
                work_directory_identity: &self.work_directory_identity,
                temporary_directory: &self.temporary_directory,
                temporary_directory_identity: &self.temporary_directory_identity,
            },
            false,
        )?;
        run_native_oracle_restoration_phases(
            deadlines,
            |deadline| {
                self.require_source_stack_work_receipt()?;
                self.cleanup_source_stack_work(deadline)
                    .and_then(|receipt| {
                        if receipt.source_identity == self.source_identity {
                            Ok(())
                        } else {
                            Err("staged oracle cleanup receipt identity differs".to_owned())
                        }
                    })
            },
            |deadline| self.cleanup_adapter_stack_work(deadline),
            |deadline| {
                require_posix_archive_adapter_transition_state(self.transition_state(0o2550))?;
                trusted_tool_status_before(
                    deadline,
                    &self.sudo,
                    &self.tools.chmod,
                    posix_chmod_arguments(
                        self.platform,
                        "2770",
                        path_text(&self.parent, "native archive adapter authority")?,
                    )?,
                )?;
                require_posix_archive_adapter_transition_state(self.transition_state(0o2770))
            },
        )
    }

    fn cleanup_adapter_stack_work(&self, deadline: Instant) -> Result<(), String> {
        const MUTABLE_ENTRY_LIMIT: usize = 1_000_000;
        const MUTABLE_DEPTH_LIMIT: usize = 256;
        remove_posix_no_follow_forest(
            &[
                PosixNoFollowRemovalRoot {
                    directory: &self.work_directory,
                    retained_child: Some(&self.temporary_directory),
                },
                PosixNoFollowRemovalRoot {
                    directory: &self.temporary_directory,
                    retained_child: None,
                },
            ],
            PosixNoFollowRemovalPolicy {
                entry_limit: MUTABLE_ENTRY_LIMIT,
                depth_limit: MUTABLE_DEPTH_LIMIT,
                operation_limit: posix_no_follow_operation_limit(MUTABLE_ENTRY_LIMIT)?,
                deadline,
            },
            || {
                require_posix_archive_adapter_transition_state_phase(
                    self.transition_state(0o2550),
                    false,
                )
            },
            |path| self.transition_mutable_directory_to_cleanup_owner(path, deadline),
            |path| {
                trusted_tool_status_before(
                    deadline,
                    &self.sudo,
                    &self.tools.remove_file,
                    [
                        "-f",
                        "--",
                        path_text(path, "mutable Stack work member cleanup")?,
                    ],
                )
            },
            |path| {
                trusted_tool_status_before(
                    deadline,
                    &self.sudo,
                    &self.tools.remove_directory,
                    [
                        "--",
                        path_text(path, "mutable Stack work directory cleanup")?,
                    ],
                )
            },
        )?;
        require_posix_archive_adapter_transition_state(self.transition_state(0o2550))
    }

    fn transition_mutable_directory_to_cleanup_owner(
        &self,
        path: &Path,
        deadline: Instant,
    ) -> Result<(), String> {
        transition_posix_mutable_directory_to_cleanup_owner(
            self.platform,
            &self.sudo,
            &self.tools,
            path,
            self.parent_owner,
            self.parent_group,
            deadline,
        )
    }

    fn transition_state(&self, parent_mode: u32) -> PosixArchiveAdapterTransitionState<'_> {
        PosixArchiveAdapterTransitionState {
            parent: &self.parent,
            parent_identity: &self.parent_identity,
            parent_owner: self.parent_owner,
            parent_group: self.parent_group,
            parent_mode,
            adapter: &self.adapter,
            adapter_identity: &self.adapter_identity,
            work_directory: &self.work_directory,
            work_directory_identity: &self.work_directory_identity,
            temporary_directory: &self.temporary_directory,
            temporary_directory_identity: &self.temporary_directory_identity,
        }
    }

    fn require_source_stack_work_receipt(&self) -> Result<(), String> {
        require_posix_adapter_unchanged(self.normalizer)?;
        if posix_object_identity(&self.source_parent)? != self.source_parent_identity
            || posix_object_identity(&self.source)? != self.source_identity
            || self.stack_work != self.source.join(".stack-work")
            || posix_object_identity(&self.stack_work)? != self.stack_work_identity
        {
            return Err("candidate Stack work authority changed before cleanup".to_owned());
        }
        let metadata = fs::symlink_metadata(&self.stack_work)
            .map_err(|error| format!("cannot inspect candidate Stack work authority: {error}"))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("candidate Stack work authority is not an exact directory".to_owned());
        }
        Ok(())
    }

    fn cleanup_source_stack_work(
        &self,
        deadline: Instant,
    ) -> Result<PosixSourceStackCleanupReceipt, String> {
        cleanup_posix_source_stack_work_before_snapshot(
            PosixSourceStackCleanupContext {
                source: &self.source,
                stack_work: &self.stack_work,
                deadline,
            },
            || self.require_source_stack_work_receipt(),
            |path| {
                transition_posix_mutable_directory_to_cleanup_owner(
                    self.platform,
                    &self.sudo,
                    &self.tools,
                    path,
                    self.parent_owner,
                    self.parent_group,
                    deadline,
                )
            },
            |path| {
                trusted_tool_status_before(
                    deadline,
                    &self.sudo,
                    &self.tools.remove_file,
                    ["-f", "--", path_text(path, "candidate Stack work member")?],
                )
            },
            |path| {
                trusted_tool_status_before(
                    deadline,
                    &self.sudo,
                    &self.tools.remove_directory,
                    ["--", path_text(path, "candidate Stack work directory")?],
                )
            },
            |deadline| {
                require_clean_checkout_before(
                    &self.source,
                    crate::command::PINNED_ORACLE_SOURCE_COMMIT,
                    "staged oracle",
                    deadline,
                )?;
                require_posix_read_only_tree_before(&self.source, "staged oracle", deadline)
            },
        )
    }
}

#[cfg(unix)]
fn transition_posix_mutable_directory_to_cleanup_owner(
    platform: ReleasePlatform,
    sudo: &Path,
    tools: &PosixAdapterTools,
    path: &Path,
    trusted_owner: u32,
    trusted_group: u32,
    deadline: Instant,
) -> Result<(), String> {
    let before = posix_object_identity(path)?;
    if platform == ReleasePlatform::MacosAarch64 {
        trusted_tool_status_before(
            deadline,
            sudo,
            &tools.chmod,
            posix_acl_removal_arguments(
                platform,
                false,
                path_text(path, "mutable Stack work cleanup ACL")?,
            )?,
        )?;
    }
    let owner = trusted_owner.to_string();
    trusted_tool_status_before(
        deadline,
        sudo,
        &tools.change_owner,
        [
            owner.as_str(),
            path_text(path, "mutable Stack work cleanup owner")?,
        ],
    )?;
    let group = trusted_group.to_string();
    trusted_tool_status_before(
        deadline,
        sudo,
        &tools.change_group,
        [
            group.as_str(),
            path_text(path, "mutable Stack work cleanup group")?,
        ],
    )?;
    trusted_tool_status_before(
        deadline,
        sudo,
        &tools.chmod,
        posix_chmod_arguments(
            platform,
            "700",
            path_text(path, "mutable Stack work cleanup mode")?,
        )?,
    )?;
    let after = posix_object_identity(path)?;
    if after.device != before.device
        || after.inode != before.inode
        || after.owner != trusted_owner
        || after.group != trusted_group
        || after.mode != 0o700
    {
        return Err("mutable Stack work cleanup authority transition differs".to_owned());
    }
    crate::command::require_native_acl_free([path], "mutable Stack work cleanup authority")
}

#[cfg(unix)]
struct PosixRetainedOracleFile {
    path: PathBuf,
    identity: PosixObjectIdentity,
    sha256: hell_testkit::Digest,
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct PosixRustupInventoryEntry {
    relative: PathBuf,
    directory: bool,
    size: u64,
    sha256: Option<hell_testkit::Digest>,
    executable: bool,
}

#[cfg(unix)]
struct PosixRustupProtection {
    platform: ReleasePlatform,
    installation_root: PathBuf,
    installation_root_identity: PosixObjectIdentity,
    directory: PathBuf,
    directory_identity: PosixObjectIdentity,
    home: PathBuf,
    source_home: PathBuf,
    toolchain: OsString,
    proxy_identity: crate::command::ResolvedPosixRustupProxyIdentity,
    rustc_authority: crate::command::ResolvedPosixRustcAuthority,
    inventory: Vec<PosixRustupInventoryEntry>,
    linux_getfacl: Option<crate::command::ResolvedStandardExecutable>,
    sudo: PathBuf,
    tools: PosixAdapterTools,
}

#[cfg(unix)]
struct PosixCargoDenyHomeProtection {
    target: PathBuf,
    target_identity: PosixObjectIdentity,
    home: PathBuf,
    sudo: PathBuf,
    tools: PosixAdapterTools,
    candidate_uid: u32,
    trusted_owner: u32,
    trusted_group_id: u32,
    advisory_lock: fs::File,
    metadata: PosixCargoDenyMetadataProtection,
    active: bool,
}

#[cfg(unix)]
struct PosixCargoDenyMetadataProtection {
    parent: PathBuf,
    parent_identity: PosixObjectIdentity,
    directory: PathBuf,
    directory_identity: PosixObjectIdentity,
    path: PathBuf,
    file_identity: PosixObjectIdentity,
    size: u64,
    sha256: hell_testkit::Digest,
    trusted_owner: u32,
    sudo: PathBuf,
    tools: PosixAdapterTools,
    active: bool,
}

#[cfg(unix)]
struct PosixDependencyPolicyProtection {
    parent: PathBuf,
    parent_identity: PosixObjectIdentity,
    directory: PathBuf,
    directory_identity: PosixObjectIdentity,
    path: PathBuf,
    file_identity: PosixObjectIdentity,
    size: u64,
    sha256: hell_testkit::Digest,
    cargo_deny_sha256: hell_testkit::Digest,
    cargo_deny_version: String,
    trusted_owner: u32,
    sudo: PathBuf,
    tools: PosixAdapterTools,
    active: bool,
}

#[cfg(unix)]
struct PosixStackRootProtection {
    parent: PathBuf,
    parent_identity: PosixObjectIdentity,
    root: PathBuf,
    root_identity: PosixObjectIdentity,
    sudo: PathBuf,
    tools: PosixAdapterTools,
    candidate_uid: u32,
    trusted_group_id: u32,
    active: bool,
}

#[cfg(unix)]
impl PosixStackRootProtection {
    fn cleanup(&mut self) -> Result<(), String> {
        if !self.active {
            return Ok(());
        }
        if posix_object_identity(&self.parent)? != self.parent_identity
            || posix_object_identity(&self.root)? != self.root_identity
            || !posix_stack_root_is_exact(&self.root)
        {
            return Err("candidate Stack-root cleanup authority changed".to_owned());
        }
        let post_state = validate_posix_stack_root_post_state(
            &self.root,
            self.candidate_uid,
            self.trusted_group_id,
        );
        let cleanup = trusted_tool_status(
            &self.sudo,
            &self.tools.remove_file,
            [
                "-rf",
                "--",
                path_text(&self.root, "candidate Stack-root cleanup")?,
            ],
        );
        if cleanup.is_ok() {
            self.active = false;
        }
        cleanup?;
        post_state
    }
}

#[cfg(unix)]
impl Drop for PosixStackRootProtection {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

#[cfg(unix)]
impl PosixCargoDenyHomeProtection {
    fn cleanup(&mut self) -> Result<(), String> {
        if !self.active {
            return Ok(());
        }
        let home_cleanup = self.cleanup_home();
        let metadata_cleanup = self.metadata.cleanup();
        if home_cleanup.is_ok() && metadata_cleanup.is_ok() {
            self.active = false;
        }
        home_cleanup.and(metadata_cleanup)
    }

    fn cleanup_home(&self) -> Result<(), String> {
        if posix_object_identity(&self.target)? != self.target_identity
            || !posix_cargo_deny_home_is_exact(&self.target, &self.home)
        {
            Err("candidate cargo-deny home cleanup authority changed".to_owned())
        } else {
            let post_state = validate_posix_cargo_deny_home_post_state(
                &self.home,
                self.candidate_uid,
                self.trusted_owner,
                self.trusted_group_id,
                &self.advisory_lock,
            );
            trusted_tool_status(
                &self.sudo,
                &self.tools.remove_file,
                [
                    "-rf",
                    "--",
                    path_text(&self.home, "candidate cargo-deny home cleanup")?,
                ],
            )
            .and(post_state)
        }
    }
}

#[cfg(unix)]
impl PosixCargoDenyMetadataProtection {
    fn validate(&self) -> Result<(), String> {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let file = fs::symlink_metadata(&self.path)
            .map_err(|error| format!("cannot inspect cargo-deny metadata authority: {error}"))?;
        if !self.active
            || validate_posix_adapter_installation_root(ReleasePlatform::LinuxX86_64, &self.parent)?
                != self.parent
            || posix_object_identity(&self.parent)? != self.parent_identity
            || !posix_cargo_deny_metadata_is_exact(&self.parent, &self.directory, &self.path)
            || posix_object_identity(&self.directory)? != self.directory_identity
            || posix_object_identity(&self.path)? != self.file_identity
            || self.directory_identity.owner != self.trusted_owner
            || self.directory_identity.mode != 0o555
            || file.file_type().is_symlink()
            || !file.is_file()
            || file.nlink() != 1
            || file.uid() != self.trusted_owner
            || file.permissions().mode() & 0o7777 != 0o444
            || file.len() != self.size
            || hell_testkit::sha256_file(&self.path)
                .map_err(|error| format!("cannot rehash cargo-deny metadata: {error}"))?
                != self.sha256
        {
            return Err("cargo-deny metadata authority changed".to_owned());
        }
        require_exact_directory_members(
            &self.directory,
            &[std::ffi::OsString::from("metadata.json")],
            "cargo-deny metadata authority",
        )?;
        Ok(())
    }

    fn cleanup(&mut self) -> Result<(), String> {
        if !self.active {
            return Ok(());
        }
        self.validate()?;
        trusted_tool_status(
            &self.sudo,
            &self.tools.remove_file,
            [
                "-rf",
                "--",
                path_text(&self.directory, "cargo-deny metadata cleanup")?,
            ],
        )?;
        self.active = false;
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for PosixCargoDenyMetadataProtection {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

#[cfg(unix)]
impl PosixDependencyPolicyProtection {
    fn validate(&self) -> Result<(), String> {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let file = fs::symlink_metadata(&self.path)
            .map_err(|error| format!("cannot inspect dependency-policy authority: {error}"))?;
        if !self.active
            || validate_posix_adapter_installation_root(ReleasePlatform::LinuxX86_64, &self.parent)?
                != self.parent
            || posix_object_identity(&self.parent)? != self.parent_identity
            || !posix_dependency_policy_is_exact(&self.parent, &self.directory, &self.path)
            || posix_object_identity(&self.directory)? != self.directory_identity
            || posix_object_identity(&self.path)? != self.file_identity
            || self.directory_identity.owner != self.trusted_owner
            || self.directory_identity.mode != 0o555
            || file.file_type().is_symlink()
            || !file.is_file()
            || file.nlink() != 1
            || file.uid() != self.trusted_owner
            || file.permissions().mode() & 0o7777 != 0o444
            || file.len() != self.size
            || hell_testkit::sha256_file(&self.path)
                .map_err(|error| format!("cannot rehash dependency-policy result: {error}"))?
                != self.sha256
        {
            return Err("dependency-policy authority changed".to_owned());
        }
        require_exact_directory_members(
            &self.directory,
            &[std::ffi::OsString::from("dependency-policy.json")],
            "dependency-policy authority",
        )?;
        Ok(())
    }

    fn cleanup(&mut self) -> Result<(), String> {
        if !self.active {
            return Ok(());
        }
        self.validate()?;
        trusted_tool_status(
            &self.sudo,
            &self.tools.remove_file,
            [
                "-rf",
                "--",
                path_text(&self.directory, "dependency-policy cleanup")?,
            ],
        )?;
        self.active = false;
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for PosixDependencyPolicyProtection {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

#[cfg(unix)]
impl Drop for PosixCargoDenyHomeProtection {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

#[cfg(unix)]
fn stage_posix_cargo_deny_home(
    platform: ReleasePlatform,
    sudo: &Path,
    adapter: &PosixAdapterProtection,
    target: &Path,
    candidate_root: &Path,
    candidate_sha: &str,
    cargo: &crate::command::ResolvedCargoExecutable,
    candidate_uid: u32,
    trusted_owner: u32,
    trusted_group_id: u32,
) -> Result<
    (
        PosixCargoDenyHomeProtection,
        PosixDependencyPolicyProtection,
    ),
    String,
> {
    let target_identity = posix_object_identity(target)?;
    let tools = resolve_posix_adapter_tools(platform)?;
    let environment_root = target.join("release-child-environment");
    fs::create_dir_all(&environment_root)
        .map_err(|error| format!("cannot reserve candidate environment root: {error}"))?;
    let home = environment_root.join("cargo-deny-cargo-home");
    if home.exists() {
        fs::remove_dir_all(&home)
            .map_err(|error| format!("cannot clear prior candidate cargo-deny home: {error}"))?;
    }
    fs::create_dir(&home)
        .map_err(|error| format!("cannot reserve candidate cargo-deny home: {error}"))?;
    let copy_result = (|| {
        let mut seed = TrustedCargoCacheSeed::create(platform)?;
        seed.fetch(cargo, candidate_root)?;
        let mut entries = 1_usize;
        let mut bytes = 0_u64;
        copy_posix_cargo_cache_tree(seed.root(), &home, &mut entries, &mut bytes)?;
        remove_staged_cargo_package_fallback(&home)?;
        let metadata = seed.prove_staged_home_offline(cargo, candidate_root, &home)?;
        let final_metadata =
            replace_final_home_cargo_deny_metadata(candidate_root, &home, &metadata)?;
        let policy_document = run_final_home_cargo_deny_authority_checks(
            cargo,
            candidate_root,
            candidate_sha,
            &final_metadata,
        )?;
        let advisory_lock = reserve_posix_cargo_deny_advisory_lock(&home)?;
        let metadata =
            stage_posix_cargo_deny_metadata(platform, sudo, &tools, &metadata, trusted_owner)?;
        let policy =
            stage_posix_dependency_policy(platform, sudo, &tools, &policy_document, trusted_owner)?;
        normalize_posix_cargo_deny_home_with_adapter(
            sudo,
            adapter,
            &home,
            candidate_uid,
            trusted_owner,
            trusted_group_id,
        )?;
        seed.prove_staged_home_frozen_fetch(cargo, candidate_root, &home)?;
        validate_posix_cargo_deny_home_post_state(
            &home,
            candidate_uid,
            trusted_owner,
            trusted_group_id,
            &advisory_lock,
        )?;
        if metadata.sha256 != final_metadata.sha256 {
            return Err(
                "retained cargo-deny metadata differs from its final-home input".to_owned(),
            );
        }
        final_metadata.validate()?;
        seed.cleanup()?;
        Ok((metadata, advisory_lock, policy))
    })();
    let (metadata, advisory_lock, policy) = match copy_result {
        Ok(authority) => authority,
        Err(error) => {
            if let Ok(home_text) = path_text(&home, "partial candidate cargo-deny home cleanup") {
                let _ = trusted_tool_status(sudo, &tools.remove_file, ["-rf", "--", home_text]);
            }
            return Err(error);
        }
    };
    Ok((
        PosixCargoDenyHomeProtection {
            target: target.to_path_buf(),
            target_identity,
            home,
            sudo: sudo.to_path_buf(),
            tools,
            candidate_uid,
            trusted_owner,
            trusted_group_id,
            advisory_lock,
            metadata,
            active: true,
        },
        policy,
    ))
}

#[cfg(unix)]
fn reserve_posix_cargo_deny_advisory_lock(home: &Path) -> Result<fs::File, String> {
    use std::os::unix::fs::MetadataExt as _;

    let advisory_root = home.join("advisory-dbs");
    fs::create_dir_all(&advisory_root)
        .map_err(|error| format!("cannot reserve cargo-deny advisory root: {error}"))?;
    let lock = advisory_root.join("db.lock");
    if fs::symlink_metadata(&lock).is_ok() {
        fs::remove_file(&lock)
            .map_err(|error| format!("cannot replace staged cargo-deny advisory lock: {error}"))?;
    }
    let reserved_lock = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock)
        .map_err(|error| format!("cannot reserve cargo-deny advisory lock: {error}"))?;
    drop(reserved_lock);
    let lock_authority = fs::OpenOptions::new()
        .read(true)
        .open(&lock)
        .map_err(|error| format!("cannot bind cargo-deny advisory lock metadata: {error}"))?;
    let metadata = fs::symlink_metadata(&lock)
        .map_err(|error| format!("cannot inspect cargo-deny advisory lock: {error}"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.nlink() != 1 {
        return Err("cargo-deny advisory lock is not an exact regular file".to_owned());
    }
    Ok(lock_authority)
}

#[cfg(unix)]
fn stage_posix_cargo_deny_metadata(
    platform: ReleasePlatform,
    sudo: &Path,
    tools: &PosixAdapterTools,
    document: &[u8],
    trusted_owner: u32,
) -> Result<PosixCargoDenyMetadataProtection, String> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    if platform != ReleasePlatform::LinuxX86_64 {
        return Err("cargo-deny metadata authority is only supported on Linux".to_owned());
    }
    let parent = posix_adapter_installation_root(platform)?;
    let parent_identity = posix_object_identity(&parent)?;
    let sequence = POSIX_CARGO_METADATA_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let directory = parent.join(format!(
        "hell-cargo-deny-metadata-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir(&directory)
        .map_err(|error| format!("cannot reserve cargo-deny metadata authority: {error}"))?;
    let path = directory.join("metadata.json");
    let prepare = (|| {
        fs::write(&path, document)
            .map_err(|error| format!("cannot write cargo-deny metadata authority: {error}"))?;
        let owner = trusted_owner.to_string();
        for entry in [&directory, &path] {
            trusted_tool_status(
                sudo,
                &tools.change_owner,
                [
                    owner.as_str(),
                    path_text(entry, "cargo-deny metadata owner")?,
                ],
            )?;
        }
        trusted_tool_status(
            sudo,
            &tools.chmod,
            posix_chmod_arguments(
                platform,
                "0444",
                path_text(&path, "cargo-deny metadata document")?,
            )?,
        )?;
        trusted_tool_status(
            sudo,
            &tools.chmod,
            posix_chmod_arguments(
                platform,
                "0555",
                path_text(&directory, "cargo-deny metadata directory")?,
            )?,
        )?;
        let directory_metadata = fs::symlink_metadata(&directory)
            .map_err(|error| format!("cannot inspect cargo-deny metadata directory: {error}"))?;
        let file_metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot inspect cargo-deny metadata document: {error}"))?;
        let size = u64::try_from(document.len())
            .map_err(|_| "cargo-deny metadata size exceeds u64".to_owned())?;
        let sha256 = hell_testkit::sha256_bytes(document);
        if posix_object_identity(&parent)? != parent_identity
            || !posix_cargo_deny_metadata_is_exact(&parent, &directory, &path)
            || directory_metadata.file_type().is_symlink()
            || !directory_metadata.is_dir()
            || directory_metadata.uid() != trusted_owner
            || directory_metadata.permissions().mode() & 0o7777 != 0o555
            || file_metadata.file_type().is_symlink()
            || !file_metadata.is_file()
            || file_metadata.nlink() != 1
            || file_metadata.uid() != trusted_owner
            || file_metadata.permissions().mode() & 0o7777 != 0o444
            || file_metadata.len() != size
            || hell_testkit::sha256_file(&path)
                .map_err(|error| format!("cannot hash cargo-deny metadata document: {error}"))?
                != sha256
        {
            return Err("cargo-deny metadata authority differs after staging".to_owned());
        }
        require_exact_directory_members(
            &directory,
            &[std::ffi::OsString::from("metadata.json")],
            "cargo-deny metadata authority",
        )?;
        Ok(PosixCargoDenyMetadataProtection {
            parent,
            parent_identity,
            directory: directory.clone(),
            directory_identity: posix_object_identity(&directory)?,
            path: path.clone(),
            file_identity: posix_object_identity(&path)?,
            size,
            sha256,
            trusted_owner,
            sudo: sudo.to_path_buf(),
            tools: tools.clone(),
            active: true,
        })
    })();
    if prepare.is_err() {
        if let Ok(directory_text) = path_text(&directory, "partial cargo-deny metadata cleanup") {
            let _ = trusted_tool_status(sudo, &tools.remove_file, ["-rf", "--", directory_text]);
        }
    }
    prepare
}

#[cfg(unix)]
fn stage_posix_dependency_policy(
    platform: ReleasePlatform,
    sudo: &Path,
    tools: &PosixAdapterTools,
    document: &[u8],
    trusted_owner: u32,
) -> Result<PosixDependencyPolicyProtection, String> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    if platform != ReleasePlatform::LinuxX86_64 {
        return Err("dependency-policy authority is only supported on Linux".to_owned());
    }
    let text = std::str::from_utf8(document)
        .map_err(|_| "dependency-policy result is not UTF-8".to_owned())?;
    let parsed = parse_json(text)?;
    let parsed_object = parsed.object()?;
    let cargo_deny_sha256 = hell_testkit::Digest::from_hex(
        json_member(parsed_object, "cargoDenyExecutableSha256")?.string()?,
    )
    .map_err(|_| "dependency-policy cargo-deny digest is invalid".to_owned())?;
    let cargo_deny_version = json_member(parsed_object, "cargoDenyVersion")?
        .string()?
        .to_owned();
    if cargo_deny_version != TRUSTED_CARGO_DENY_VERSION {
        return Err("dependency-policy cargo-deny version differs from policy".to_owned());
    }
    let parent = posix_adapter_installation_root(platform)?;
    let parent_identity = posix_object_identity(&parent)?;
    let sequence = POSIX_CARGO_METADATA_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let directory = parent.join(format!(
        "hell-dependency-policy-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir(&directory)
        .map_err(|error| format!("cannot reserve dependency-policy authority: {error}"))?;
    let path = directory.join("dependency-policy.json");
    let prepare = (|| {
        fs::write(&path, document)
            .map_err(|error| format!("cannot write dependency-policy result: {error}"))?;
        let owner = trusted_owner.to_string();
        for entry in [&directory, &path] {
            trusted_tool_status(
                sudo,
                &tools.change_owner,
                [owner.as_str(), path_text(entry, "dependency-policy owner")?],
            )?;
        }
        trusted_tool_status(
            sudo,
            &tools.chmod,
            posix_chmod_arguments(
                platform,
                "0444",
                path_text(&path, "dependency-policy result")?,
            )?,
        )?;
        trusted_tool_status(
            sudo,
            &tools.chmod,
            posix_chmod_arguments(
                platform,
                "0555",
                path_text(&directory, "dependency-policy directory")?,
            )?,
        )?;
        let directory_metadata = fs::symlink_metadata(&directory)
            .map_err(|error| format!("cannot inspect dependency-policy directory: {error}"))?;
        let file_metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot inspect dependency-policy result: {error}"))?;
        let size = u64::try_from(document.len())
            .map_err(|_| "dependency-policy size exceeds u64".to_owned())?;
        let sha256 = hell_testkit::sha256_bytes(document);
        if posix_object_identity(&parent)? != parent_identity
            || !posix_dependency_policy_is_exact(&parent, &directory, &path)
            || directory_metadata.file_type().is_symlink()
            || !directory_metadata.is_dir()
            || directory_metadata.uid() != trusted_owner
            || directory_metadata.permissions().mode() & 0o7777 != 0o555
            || file_metadata.file_type().is_symlink()
            || !file_metadata.is_file()
            || file_metadata.nlink() != 1
            || file_metadata.uid() != trusted_owner
            || file_metadata.permissions().mode() & 0o7777 != 0o444
            || file_metadata.len() != size
            || hell_testkit::sha256_file(&path)
                .map_err(|error| format!("cannot hash dependency-policy result: {error}"))?
                != sha256
        {
            return Err("dependency-policy authority differs after staging".to_owned());
        }
        require_exact_directory_members(
            &directory,
            &[std::ffi::OsString::from("dependency-policy.json")],
            "dependency-policy authority",
        )?;
        Ok(PosixDependencyPolicyProtection {
            parent,
            parent_identity,
            directory: directory.clone(),
            directory_identity: posix_object_identity(&directory)?,
            path: path.clone(),
            file_identity: posix_object_identity(&path)?,
            size,
            sha256,
            cargo_deny_sha256,
            cargo_deny_version,
            trusted_owner,
            sudo: sudo.to_path_buf(),
            tools: tools.clone(),
            active: true,
        })
    })();
    if prepare.is_err() {
        if let Ok(directory_text) = path_text(&directory, "partial dependency-policy cleanup") {
            let _ = trusted_tool_status(sudo, &tools.remove_file, ["-rf", "--", directory_text]);
        }
    }
    prepare
}

#[cfg(unix)]
fn stage_posix_stack_root(
    platform: ReleasePlatform,
    sudo: &Path,
    adapter: &PosixAdapterProtection,
    candidate_uid: u32,
    trusted_group_id: u32,
) -> Result<PosixStackRootProtection, String> {
    if platform != ReleasePlatform::MacosAarch64 {
        return Err("candidate Stack root is only supported on macOS".to_owned());
    }
    require_posix_adapter_unchanged(adapter)?;
    let parent = posix_adapter_installation_root(platform)?;
    let parent_identity = posix_object_identity(&parent)?;
    let tools = resolve_posix_adapter_tools(platform)?;
    let sequence = POSIX_STACK_ROOT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let root = parent.join(format!("hell-stack-root-{}-{sequence}", std::process::id()));
    fs::create_dir(&root)
        .map_err(|error| format!("cannot reserve empty candidate Stack root: {error}"))?;
    let prepare_result = (|| {
        trusted_tool_status(
            sudo,
            &tools.chmod,
            posix_acl_removal_arguments(
                platform,
                false,
                path_text(&root, "candidate Stack root ACL")?,
            )?,
        )?;
        normalize_posix_stack_root_with_adapter(
            sudo,
            adapter,
            &root,
            candidate_uid,
            trusted_group_id,
        )?;
        require_posix_adapter_unchanged(adapter)?;
        if posix_object_identity(&parent)? != parent_identity {
            return Err("candidate Stack-root parent authority changed".to_owned());
        }
        posix_object_identity(&root)
    })();
    let root_identity = match prepare_result {
        Ok(identity) => identity,
        Err(error) => {
            if let Ok(root_text) = path_text(&root, "partial candidate Stack-root cleanup") {
                let _ = trusted_tool_status(sudo, &tools.remove_file, ["-rf", "--", root_text]);
            }
            return Err(error);
        }
    };
    Ok(PosixStackRootProtection {
        parent,
        parent_identity,
        root,
        root_identity,
        sudo: sudo.to_path_buf(),
        tools,
        candidate_uid,
        trusted_group_id,
        active: true,
    })
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct TrustedCargoSeedInputFile {
    identity: PosixObjectIdentity,
    size: u64,
    sha256: hell_testkit::Digest,
}

#[cfg(unix)]
impl TrustedCargoSeedInputFile {
    fn bind(root: &Path, name: &str) -> Result<Self, String> {
        use std::os::unix::fs::MetadataExt as _;

        let path = root.join(name);
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot inspect trusted Cargo seed {name}: {error}"))?;
        if fs::canonicalize(root).ok().as_deref() != Some(root)
            || path.parent() != Some(root)
            || fs::canonicalize(&path).ok().as_deref() != Some(path.as_path())
            || metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.nlink() != 1
        {
            return Err(format!("trusted Cargo seed {name} is redirected or linked"));
        }
        Ok(Self {
            identity: posix_object_identity(&path)?,
            size: metadata.len(),
            sha256: hell_testkit::sha256_file(&path)
                .map_err(|error| format!("cannot hash trusted Cargo seed {name}: {error}"))?,
        })
    }
}

#[cfg(unix)]
struct TrustedCargoCacheSeed {
    root: PathBuf,
    identity: PosixObjectIdentity,
    active: bool,
}

#[cfg(unix)]
impl TrustedCargoCacheSeed {
    fn create(platform: ReleasePlatform) -> Result<Self, String> {
        use std::os::unix::fs::PermissionsExt as _;

        let parent = posix_adapter_installation_root(platform)?;
        let sequence = POSIX_CARGO_SEED_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let root = parent.join(format!("hell-cargo-seed-{}-{sequence}", std::process::id()));
        fs::create_dir(&root)
            .map_err(|error| format!("cannot reserve trusted Cargo cache seed: {error}"))?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("cannot protect trusted Cargo cache seed: {error}"))?;
        let metadata = fs::symlink_metadata(&root)
            .map_err(|error| format!("cannot inspect trusted Cargo cache seed: {error}"))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.permissions().mode() & 0o7777 != 0o700
            || fs::canonicalize(&root).ok().as_deref() != Some(root.as_path())
        {
            let _ = fs::remove_dir(&root);
            return Err("trusted Cargo cache seed differs from its private authority".to_owned());
        }
        let identity = match posix_object_identity(&root) {
            Ok(identity) => identity,
            Err(error) => {
                let _ = fs::remove_dir(&root);
                return Err(error);
            }
        };
        Ok(Self {
            identity,
            root,
            active: true,
        })
    }

    fn vendor_root(&self) -> PathBuf {
        staged_cargo_vendor_root(&self.root)
    }

    fn root(&self) -> &Path {
        &self.root
    }

    fn validate(&self) -> Result<(), String> {
        use std::os::unix::fs::PermissionsExt as _;

        let parent = self
            .root
            .parent()
            .ok_or_else(|| "trusted Cargo cache seed has no parent".to_owned())?;
        let name = self
            .root
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .unwrap_or_default();
        let metadata = fs::symlink_metadata(&self.root)
            .map_err(|error| format!("cannot revalidate trusted Cargo cache seed: {error}"))?;
        if !self.active
            || (parent != Path::new("/var/tmp") && parent != Path::new("/private/var/tmp"))
            || !name.starts_with("hell-cargo-seed-")
            || metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.permissions().mode() & 0o7777 != 0o700
            || fs::canonicalize(&self.root).ok().as_deref() != Some(self.root.as_path())
            || posix_object_identity(&self.root)? != self.identity
        {
            return Err("trusted Cargo cache seed authority changed".to_owned());
        }
        Ok(())
    }

    fn fetch(
        &self,
        cargo: &crate::command::ResolvedCargoExecutable,
        candidate_root: &Path,
    ) -> Result<(), String> {
        let manifest = candidate_root.join("Cargo.toml");
        let manifest_identity = TrustedCargoSeedInputFile::bind(candidate_root, "Cargo.toml")?;
        let lock_identity = TrustedCargoSeedInputFile::bind(candidate_root, "Cargo.lock")?;
        let program_identity = hell_testkit::BoundProgramInvocation::new(
            cargo.invocation_path().to_path_buf(),
            cargo.canonical_identity().to_path_buf(),
        )
        .map_err(|error| format!("cannot bind trusted Cargo seed executable: {error}"))?;
        self.validate()?;
        self.run_cargo(
            cargo,
            candidate_root,
            trusted_cargo_cache_seed_arguments(candidate_root, &manifest)?,
            "fetch",
        )?;
        self.revalidate_inputs(
            cargo,
            candidate_root,
            &manifest_identity,
            &lock_identity,
            &program_identity,
            "fetch",
        )?;
        let metadata = self.run_cargo_with_home(
            cargo,
            candidate_root,
            trusted_cargo_cache_metadata_arguments(candidate_root, &manifest)?,
            "metadata materialization",
            &self.root,
        )?;
        if metadata.stdout_truncated
            || u64::try_from(metadata.stdout.len()).ok() != Some(metadata.stdout_bytes)
        {
            return Err("trusted Cargo metadata exceeds its capture authority".to_owned());
        }
        let metadata_path = self.root.join("hell-cargo-deny-metadata.json");
        if fs::symlink_metadata(&metadata_path).is_ok() {
            return Err("trusted cargo-deny metadata seed already exists".to_owned());
        }
        fs::write(&metadata_path, &metadata.stdout)
            .map_err(|error| format!("cannot write trusted cargo-deny metadata seed: {error}"))?;
        run_trusted_cargo_deny_authority_checks(
            cargo,
            candidate_root,
            &self.root,
            &metadata_path,
            &metadata.stdout,
        )?;
        self.revalidate_inputs(
            cargo,
            candidate_root,
            &manifest_identity,
            &lock_identity,
            &program_identity,
            "advisory database materialization",
        )?;
        let vendor = self.vendor_root();
        if fs::symlink_metadata(&vendor).is_ok() {
            return Err("trusted Cargo vendor destination already exists".to_owned());
        }
        self.run_cargo(
            cargo,
            candidate_root,
            trusted_cargo_vendor_arguments(candidate_root, &manifest, &self.root, &vendor)?,
            "vendor materialization",
        )?;
        self.revalidate_inputs(
            cargo,
            candidate_root,
            &manifest_identity,
            &lock_identity,
            &program_identity,
            "vendor materialization",
        )?;
        validate_trusted_cargo_cache_tree(&vendor)?;
        let lock_document = fs::read(candidate_root.join("Cargo.lock"))
            .map_err(|error| format!("cannot read trusted Cargo lock: {error}"))?;
        if u64::try_from(lock_document.len()).ok() != Some(lock_identity.size)
            || TrustedCargoSeedInputFile::bind(candidate_root, "Cargo.lock")? != lock_identity
        {
            return Err("trusted Cargo lock changed during vendor materialization".to_owned());
        }
        validate_staged_vendor_covers_frozen_lock(&lock_document, &vendor)
    }

    fn run_cargo(
        &self,
        cargo: &crate::command::ResolvedCargoExecutable,
        candidate_root: &Path,
        arguments: Vec<OsString>,
        operation: &str,
    ) -> Result<(), String> {
        self.run_cargo_with_home(cargo, candidate_root, arguments, operation, &self.root)
            .map(|_| ())
    }

    fn run_cargo_with_home(
        &self,
        cargo: &crate::command::ResolvedCargoExecutable,
        candidate_root: &Path,
        arguments: Vec<OsString>,
        operation: &str,
        cargo_home: &Path,
    ) -> Result<CommandResult, String> {
        self.validate()?;
        let result = crate::command::CommandSpec::trusted_cargo(Duration::from_secs(300), cargo)
            .arguments(arguments)
            .current_directory(candidate_root)
            .environment("CARGO_HOME", cargo_home.as_os_str())
            .environment("CARGO_TARGET_DIR", cargo_home.join("target"))
            .run()
            .map_err(|error| format!("cannot run trusted Cargo cache {operation}: {error}"))?;
        if result.timed_out || !result.status.success() {
            return Err(format!(
                "trusted Cargo cache {operation} failed with status {}",
                result.status.code().unwrap_or(1)
            ));
        }
        Ok(result)
    }

    fn prove_staged_home_offline(
        &self,
        cargo: &crate::command::ResolvedCargoExecutable,
        candidate_root: &Path,
        staged_home: &Path,
    ) -> Result<Vec<u8>, String> {
        let manifest = candidate_root.join("Cargo.toml");
        let manifest_identity = TrustedCargoSeedInputFile::bind(candidate_root, "Cargo.toml")?;
        let lock_identity = TrustedCargoSeedInputFile::bind(candidate_root, "Cargo.lock")?;
        let program_identity = hell_testkit::BoundProgramInvocation::new(
            cargo.invocation_path().to_path_buf(),
            cargo.canonical_identity().to_path_buf(),
        )
        .map_err(|error| format!("cannot bind staged Cargo proof executable: {error}"))?;
        let staged_identity = posix_object_identity(staged_home)?;
        configure_staged_cargo_home_directory_source(staged_home)?;
        let result = self.run_cargo_with_home(
            cargo,
            candidate_root,
            trusted_cargo_cache_offline_metadata_arguments(candidate_root, &manifest)?,
            "staged offline metadata proof",
            staged_home,
        )?;
        if result.stdout_truncated
            || u64::try_from(result.stdout.len()).ok() != Some(result.stdout_bytes)
        {
            return Err("staged offline Cargo metadata exceeds its capture authority".to_owned());
        }
        if posix_object_identity(staged_home)? != staged_identity {
            return Err("staged Cargo home identity changed during offline proof".to_owned());
        }
        self.revalidate_inputs(
            cargo,
            candidate_root,
            &manifest_identity,
            &lock_identity,
            &program_identity,
            "staged offline metadata proof",
        )?;
        validate_trusted_cargo_cache_tree(staged_home)?;
        validate_staged_cargo_metadata(&result.stdout, candidate_root, staged_home)?;
        Ok(result.stdout)
    }

    fn prove_staged_home_frozen_fetch(
        &self,
        cargo: &crate::command::ResolvedCargoExecutable,
        candidate_root: &Path,
        staged_home: &Path,
    ) -> Result<(), String> {
        let manifest = candidate_root.join("Cargo.toml");
        let manifest_identity = TrustedCargoSeedInputFile::bind(candidate_root, "Cargo.toml")?;
        let lock_identity = TrustedCargoSeedInputFile::bind(candidate_root, "Cargo.lock")?;
        let program_identity = hell_testkit::BoundProgramInvocation::new(
            cargo.invocation_path().to_path_buf(),
            cargo.canonical_identity().to_path_buf(),
        )
        .map_err(|error| format!("cannot bind staged frozen fetch executable: {error}"))?;
        let staged_identity = posix_object_identity(staged_home)?;
        self.run_cargo_with_home(
            cargo,
            candidate_root,
            trusted_cargo_cache_fetch_arguments(candidate_root, &manifest)?,
            "staged frozen fetch proof",
            staged_home,
        )?;
        if posix_object_identity(staged_home)? != staged_identity {
            return Err("staged Cargo home identity changed during frozen fetch proof".to_owned());
        }
        self.revalidate_inputs(
            cargo,
            candidate_root,
            &manifest_identity,
            &lock_identity,
            &program_identity,
            "staged frozen fetch proof",
        )?;
        validate_trusted_cargo_cache_tree(&staged_cargo_vendor_root(staged_home))
    }

    fn revalidate_inputs(
        &self,
        cargo: &crate::command::ResolvedCargoExecutable,
        candidate_root: &Path,
        manifest_identity: &TrustedCargoSeedInputFile,
        lock_identity: &TrustedCargoSeedInputFile,
        program_identity: &hell_testkit::BoundProgramInvocation,
        operation: &str,
    ) -> Result<(), String> {
        self.validate()?;
        if TrustedCargoSeedInputFile::bind(candidate_root, "Cargo.toml")? != *manifest_identity
            || TrustedCargoSeedInputFile::bind(candidate_root, "Cargo.lock")? != *lock_identity
            || hell_testkit::BoundProgramInvocation::new(
                cargo.invocation_path().to_path_buf(),
                cargo.canonical_identity().to_path_buf(),
            )
            .map_err(|error| format!("cannot rebind trusted Cargo seed executable: {error}"))?
                != *program_identity
        {
            return Err(format!(
                "trusted Cargo cache seed authority changed during {operation}"
            ));
        }
        Ok(())
    }

    fn cleanup(&mut self) -> Result<(), String> {
        self.validate()?;
        fs::remove_dir_all(&self.root)
            .map_err(|error| format!("cannot remove trusted Cargo cache seed: {error}"))?;
        self.active = false;
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for TrustedCargoCacheSeed {
    fn drop(&mut self) {
        if self.active {
            let _ = self.cleanup();
        }
    }
}

#[cfg(unix)]
fn trusted_cargo_cache_seed_arguments(
    candidate_root: &Path,
    manifest: &Path,
) -> Result<Vec<OsString>, String> {
    if !candidate_root.is_absolute()
        || candidate_root.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
        || manifest != candidate_root.join("Cargo.toml")
    {
        return Err("trusted Cargo cache seed manifest is not exact".to_owned());
    }
    Ok(vec![
        OsString::from("fetch"),
        OsString::from("--locked"),
        OsString::from("--manifest-path"),
        manifest.as_os_str().to_owned(),
    ])
}

#[cfg(unix)]
fn trusted_cargo_cache_metadata_arguments(
    candidate_root: &Path,
    manifest: &Path,
) -> Result<Vec<OsString>, String> {
    if !candidate_root.is_absolute()
        || candidate_root.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
        || manifest != candidate_root.join("Cargo.toml")
    {
        return Err("trusted Cargo cache metadata manifest is not exact".to_owned());
    }
    Ok(vec![
        OsString::from("metadata"),
        OsString::from("--locked"),
        OsString::from("--all-features"),
        OsString::from("--format-version"),
        OsString::from("1"),
        OsString::from("--manifest-path"),
        manifest.as_os_str().to_owned(),
    ])
}

#[cfg(unix)]
fn trusted_cargo_cache_offline_metadata_arguments(
    candidate_root: &Path,
    manifest: &Path,
) -> Result<Vec<OsString>, String> {
    let mut arguments = trusted_cargo_cache_metadata_arguments(candidate_root, manifest)?;
    arguments.insert(2, OsString::from("--offline"));
    Ok(arguments)
}

#[cfg(unix)]
fn trusted_cargo_cache_fetch_arguments(
    candidate_root: &Path,
    manifest: &Path,
) -> Result<Vec<OsString>, String> {
    if !candidate_root.is_absolute()
        || candidate_root.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
        || manifest != candidate_root.join("Cargo.toml")
    {
        return Err("trusted Cargo cache fetch manifest is not exact".to_owned());
    }
    // cargo-deny 0.20.2 always shells out to exactly this frozen fetch shape
    // while checking, even when `--metadata-path` supplies a pre-captured
    // document. Keep the redundant explicit flags in their observed order so
    // the proof exercises the hosted child's argv rather than an equivalent
    // command that happens to share `--frozen`.
    Ok(vec![
        OsString::from("fetch"),
        OsString::from("--manifest-path"),
        manifest.as_os_str().to_owned(),
        OsString::from("--frozen"),
        OsString::from("--locked"),
        OsString::from("--offline"),
    ])
}

#[cfg(unix)]
fn staged_cargo_vendor_root(home: &Path) -> PathBuf {
    home.join("vendor").join("index.crates.io-6f17d22bba15001f")
}

#[cfg(unix)]
fn remove_staged_cargo_package_fallback(home: &Path) -> Result<(), String> {
    for name in ["cache", "src"] {
        let path = home.join("registry").join(name);
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            format!("cannot inspect staged Cargo package fallback {name}: {error}")
        })?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || fs::canonicalize(&path).map_err(|error| {
                format!("cannot canonicalize staged Cargo package fallback {name}: {error}")
            })? != path
        {
            return Err(format!(
                "staged Cargo package fallback {name} is redirected or not a directory"
            ));
        }
        fs::remove_dir_all(&path).map_err(|error| {
            format!("cannot remove staged Cargo package fallback {name}: {error}")
        })?;
    }
    Ok(())
}

#[cfg(unix)]
const TRUSTED_CARGO_LOCK_PACKAGE_LIMIT: usize = 10_000;

#[cfg(unix)]
fn frozen_lock_registry_package(
    name: Option<String>,
    version: Option<String>,
    registry: bool,
) -> Result<Option<String>, String> {
    if !registry {
        return Ok(None);
    }
    let Some(name) = name else {
        return Err("frozen Cargo lock registry package has no name".to_owned());
    };
    let Some(version) = version else {
        return Err("frozen Cargo lock registry package has no version".to_owned());
    };
    if name.is_empty()
        || version.is_empty()
        || !name
            .bytes()
            .chain(version.bytes())
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_+.".contains(&byte))
    {
        return Err("frozen Cargo lock package identity is not exact".to_owned());
    }
    Ok(Some(format!("{name}-{version}")))
}

#[cfg(unix)]
fn validate_staged_vendor_covers_frozen_lock(
    document: &[u8],
    vendor_root: &Path,
) -> Result<(), String> {
    const MAX_LOCK_BYTES: usize = 16 * 1024 * 1024;

    if document.is_empty() || document.len() > MAX_LOCK_BYTES {
        return Err("frozen Cargo lock exceeds its byte authority".to_owned());
    }
    let text =
        std::str::from_utf8(document).map_err(|_| "frozen Cargo lock is not UTF-8".to_owned())?;
    let mut registry_packages = BTreeSet::new();
    let mut packages = 0_usize;
    let mut name = None;
    let mut version = None;
    let mut registry = false;
    let mut in_package = false;
    for line in text.lines() {
        if line.starts_with("[[package]]") {
            in_package = true;
            packages += 1;
            if packages > TRUSTED_CARGO_LOCK_PACKAGE_LIMIT {
                return Err("frozen Cargo lock exceeds its package bound".to_owned());
            }
            if let Some(identity) = frozen_lock_registry_package(
                name.take(),
                version.take(),
                std::mem::take(&mut registry),
            )? {
                registry_packages.insert(identity);
            }
            continue;
        }
        if line.starts_with('[') {
            in_package = false;
            if let Some(identity) = frozen_lock_registry_package(
                name.take(),
                version.take(),
                std::mem::take(&mut registry),
            )? {
                registry_packages.insert(identity);
            }
            continue;
        }
        if !in_package || line.starts_with('#') {
            continue;
        }
        if let Some(value) = line.strip_prefix("name = \"") {
            name = Some(value.trim_end_matches('"').to_owned());
        } else if let Some(value) = line.strip_prefix("version = \"") {
            version = Some(value.trim_end_matches('"').to_owned());
        } else if let Some(value) = line.strip_prefix("source = \"") {
            registry = value.trim_end_matches('"').starts_with("registry+");
        }
    }
    if let Some(identity) =
        frozen_lock_registry_package(name.take(), version.take(), std::mem::take(&mut registry))?
    {
        registry_packages.insert(identity);
    }
    if packages == 0 || registry_packages.is_empty() {
        return Err("frozen Cargo lock registry inventory is empty".to_owned());
    }
    for identity in &registry_packages {
        let package = vendor_root.join(identity);
        if !package.is_dir() || !package.join(".cargo-checksum.json").is_file() {
            return Err(format!(
                "staged Cargo vendor closure omits frozen registry package {identity}"
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn validate_cargo_deny_metadata_document(
    cargo_home: &Path,
    metadata: &Path,
    document: &[u8],
) -> Result<hell_testkit::Digest, String> {
    use std::os::unix::fs::MetadataExt as _;

    trusted_cargo_deny_authority_arguments(cargo_home, metadata)?;
    let file_metadata = fs::symlink_metadata(metadata)
        .map_err(|error| format!("cannot inspect trusted cargo-deny metadata: {error}"))?;
    if file_metadata.file_type().is_symlink()
        || !file_metadata.is_file()
        || file_metadata.nlink() != 1
        || fs::canonicalize(metadata)
            .map_err(|error| format!("cannot canonicalize trusted cargo-deny metadata: {error}"))?
            != metadata
    {
        return Err("trusted cargo-deny metadata is redirected or linked".to_owned());
    }
    let observed = fs::read(metadata)
        .map_err(|error| format!("cannot read trusted cargo-deny metadata: {error}"))?;
    let sha256 = hell_testkit::sha256_bytes(document);
    if observed != document
        || hell_testkit::sha256_file(metadata)
            .map_err(|error| format!("cannot hash trusted cargo-deny metadata: {error}"))?
            != sha256
    {
        return Err("trusted cargo-deny metadata differs from its captured bytes".to_owned());
    }
    Ok(sha256)
}

#[cfg(unix)]
fn run_trusted_cargo_deny_authority_checks(
    cargo: &crate::command::ResolvedCargoExecutable,
    candidate_root: &Path,
    cargo_home: &Path,
    metadata: &Path,
    metadata_document: &[u8],
) -> Result<hell_testkit::Digest, String> {
    let metadata_sha256 =
        validate_cargo_deny_metadata_document(cargo_home, metadata, metadata_document)?;
    let cargo_deny =
        crate::command::resolve_standard_path_executable(std::ffi::OsStr::new("cargo-deny"))?;
    let cargo_deny_sha256 = hell_testkit::sha256_file(cargo_deny.canonical_identity())
        .map_err(|error| format!("cannot hash trusted cargo-deny authority: {error}"))?;
    let version = tool_output(
        CommandSpec::cargo_deny(Duration::from_secs(30))
            .argument("--version")
            .current_directory(candidate_root)
            .environment("CARGO_HOME", cargo_home.as_os_str()),
        "cargo-deny",
    )?;
    if version != format!("cargo-deny {TRUSTED_CARGO_DENY_VERSION}") {
        return Err("trusted cargo-deny authority version differs from policy".to_owned());
    }
    let result = CommandSpec::cargo_deny(Duration::from_mins(10))
        .arguments(trusted_cargo_deny_authority_arguments(
            cargo_home, metadata,
        )?)
        .current_directory(candidate_root)
        .environment("CARGO", cargo.invocation_path().as_os_str().to_owned())
        .environment("CARGO_HOME", cargo_home.as_os_str())
        .environment("CARGO_TARGET_DIR", cargo_home.join("target"))
        .run()
        .map_err(|error| format!("cannot run trusted cargo-deny authority checks: {error}"))?;
    if result.timed_out || !result.status.success() {
        return Err(format!(
            "trusted cargo-deny authority checks failed with status {}",
            result.status.code().unwrap_or(1)
        ));
    }
    let observed_cargo_deny_sha256 = hell_testkit::sha256_file(cargo_deny.canonical_identity())
        .map_err(|error| format!("cannot rehash trusted cargo-deny authority: {error}"))?;
    let observed_metadata_sha256 =
        validate_cargo_deny_metadata_document(cargo_home, metadata, metadata_document)?;
    if observed_cargo_deny_sha256 != cargo_deny_sha256
        || observed_metadata_sha256 != metadata_sha256
    {
        return Err("trusted cargo-deny authority changed during policy checks".to_owned());
    }
    Ok(cargo_deny_sha256)
}

#[cfg(unix)]
struct FinalCargoDenyMetadata {
    home: PathBuf,
    path: PathBuf,
    bytes: Vec<u8>,
    sha256: hell_testkit::Digest,
}

#[cfg(unix)]
impl FinalCargoDenyMetadata {
    fn validate(&self) -> Result<(), String> {
        let observed_sha256 =
            validate_cargo_deny_metadata_document(&self.home, &self.path, &self.bytes)?;
        if observed_sha256 != self.sha256 {
            return Err("captured final-home cargo-deny metadata digest changed".to_owned());
        }
        Ok(())
    }
}

#[cfg(unix)]
fn replace_final_home_cargo_deny_metadata(
    candidate_root: &Path,
    home: &Path,
    document: &[u8],
) -> Result<FinalCargoDenyMetadata, String> {
    validate_staged_cargo_metadata(document, candidate_root, home)?;
    let path = home.join("hell-cargo-deny-metadata.json");
    let prior = fs::read(&path)
        .map_err(|error| format!("cannot read copied cargo-deny metadata seed: {error}"))?;
    validate_cargo_deny_metadata_document(home, &path, &prior)?;
    fs::write(&path, document)
        .map_err(|error| format!("cannot write final-home cargo-deny metadata: {error}"))?;
    let sha256 = validate_cargo_deny_metadata_document(home, &path, document)?;
    validate_trusted_cargo_cache_tree(home)?;
    Ok(FinalCargoDenyMetadata {
        home: home.to_path_buf(),
        path,
        bytes: document.to_vec(),
        sha256,
    })
}

#[cfg(unix)]
fn run_final_home_cargo_deny_authority_checks(
    cargo: &crate::command::ResolvedCargoExecutable,
    candidate_root: &Path,
    candidate_sha: &str,
    metadata: &FinalCargoDenyMetadata,
) -> Result<Vec<u8>, String> {
    let cargo_deny_sha256 = run_trusted_cargo_deny_authority_checks(
        cargo,
        candidate_root,
        &metadata.home,
        &metadata.path,
        &metadata.bytes,
    )?;
    metadata.validate()?;
    validate_trusted_cargo_cache_tree(&metadata.home)?;
    let policy = build_dependency_policy_result(
        candidate_root,
        candidate_sha,
        &metadata.bytes,
        cargo_deny_sha256,
    )?;
    verify_dependency_policy_result(
        &policy,
        candidate_root,
        candidate_sha,
        &metadata.sha256,
        &cargo_deny_sha256,
    )?;
    Ok(policy)
}

#[cfg(unix)]
fn trusted_cargo_deny_authority_arguments(
    cargo_home: &Path,
    metadata: &Path,
) -> Result<Vec<OsString>, String> {
    let expected = cargo_home.join("hell-cargo-deny-metadata.json");
    if !cargo_home.is_absolute()
        || cargo_home.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
        || metadata != expected
    {
        return Err("trusted cargo-deny authority metadata seed is not exact".to_owned());
    }
    // License and source checking read package content that is not present in
    // the captured Cargo metadata graph. Keep those package-content
    // authorities in the trusted seed, together with advisory-database access.
    // `bans` stays here as well: cargo-deny 0.20.2 performs its Cargo
    // bootstrap for every category, so there is no fetch-free candidate split.
    Ok(vec![
        OsString::from("--metadata-path"),
        metadata.as_os_str().to_owned(),
        OsString::from("--all-features"),
        OsString::from("check"),
        OsString::from("advisories"),
        OsString::from("bans"),
        OsString::from("licenses"),
        OsString::from("sources"),
    ])
}

#[cfg(unix)]
fn dependency_policy_input_sha256(root: &Path, name: &str) -> Result<String, String> {
    hell_testkit::sha256_file(&root.join(name))
        .map(|digest| digest.hex())
        .map_err(|error| format!("cannot hash dependency-policy input {name}: {error}"))
}

#[cfg(unix)]
fn build_dependency_policy_result(
    candidate_root: &Path,
    candidate_sha: &str,
    metadata: &[u8],
    cargo_deny_sha256: hell_testkit::Digest,
) -> Result<Vec<u8>, String> {
    let cargo_deny = cargo_deny_sha256.hex();
    let cargo_lock = dependency_policy_input_sha256(candidate_root, "Cargo.lock")?;
    let cargo_manifest = dependency_policy_input_sha256(candidate_root, "Cargo.toml")?;
    let cargo_metadata = hell_testkit::sha256_bytes(metadata).hex();
    let deny_policy = dependency_policy_input_sha256(candidate_root, "deny.toml")?;
    let document = object([
        ("candidateSourceCommit", string(candidate_sha)),
        ("cargoDenyExecutableSha256", string(&cargo_deny)),
        ("cargoDenyVersion", string(TRUSTED_CARGO_DENY_VERSION)),
        ("cargoLockSha256", string(&cargo_lock)),
        ("cargoManifestSha256", string(&cargo_manifest)),
        ("cargoMetadataSha256", string(&cargo_metadata)),
        (
            "categories",
            JsonValue::Array(
                ["advisories", "bans", "licenses", "sources"]
                    .into_iter()
                    .map(string)
                    .collect(),
            ),
        ),
        ("denyPolicySha256", string(&deny_policy)),
        ("result", string("passed")),
        ("schemaVersion", number(2)),
        ("workflow", string("release.yml")),
    ]);
    canonical_json_bytes(&document)
}

#[cfg(unix)]
fn verify_dependency_policy_result(
    document: &[u8],
    candidate_root: &Path,
    candidate_sha: &str,
    metadata_sha256: &hell_testkit::Digest,
    cargo_deny_sha256: &hell_testkit::Digest,
) -> Result<(), String> {
    let text = std::str::from_utf8(document)
        .map_err(|_| "dependency-policy result is not UTF-8".to_owned())?;
    let parsed = parse_json(text)?;
    let object = parsed.object()?;
    require_exact_json_keys(
        object,
        &[
            "candidateSourceCommit",
            "cargoDenyExecutableSha256",
            "cargoDenyVersion",
            "cargoLockSha256",
            "cargoManifestSha256",
            "cargoMetadataSha256",
            "categories",
            "denyPolicySha256",
            "result",
            "schemaVersion",
            "workflow",
        ],
    )?;
    if canonical_json_bytes(&parsed)? != document {
        return Err("dependency-policy result is not canonical".to_owned());
    }
    let expected = [
        ("candidateSourceCommit", candidate_sha.to_owned()),
        ("cargoDenyExecutableSha256", cargo_deny_sha256.hex()),
        ("cargoDenyVersion", TRUSTED_CARGO_DENY_VERSION.to_owned()),
        (
            "cargoLockSha256",
            dependency_policy_input_sha256(candidate_root, "Cargo.lock")?,
        ),
        (
            "cargoManifestSha256",
            dependency_policy_input_sha256(candidate_root, "Cargo.toml")?,
        ),
        ("cargoMetadataSha256", metadata_sha256.hex()),
        (
            "denyPolicySha256",
            dependency_policy_input_sha256(candidate_root, "deny.toml")?,
        ),
        ("result", "passed".to_owned()),
        ("workflow", "release.yml".to_owned()),
    ];
    for (name, value) in expected {
        if json_member(object, name)?.string()? != value {
            return Err(format!(
                "dependency-policy {name} differs from its bound input"
            ));
        }
    }
    if json_member(object, "schemaVersion")?.number()? != 2 {
        return Err("dependency-policy schema version is not exact".to_owned());
    }
    let categories = json_member(object, "categories")?.array()?;
    if categories.len() != 4
        || categories
            .iter()
            .zip(["advisories", "bans", "licenses", "sources"])
            .any(|(observed, expected)| {
                observed.string().is_ok_and(|observed| observed != expected)
            })
    {
        return Err("dependency-policy category inventory is partial or reordered".to_owned());
    }
    Ok(())
}

#[cfg(unix)]
fn validate_staged_cargo_metadata(
    document: &[u8],
    candidate_root: &Path,
    staged_home: &Path,
) -> Result<(), String> {
    const MAX_METADATA_BYTES: usize = 4 * 1024 * 1024;

    if document.is_empty() || document.len() > MAX_METADATA_BYTES {
        return Err("staged Cargo metadata document exceeds its byte authority".to_owned());
    }
    let text = std::str::from_utf8(document)
        .map_err(|_| "staged Cargo metadata document is not UTF-8".to_owned())?;
    let root = parse_json(text)?;
    let root = root.object()?;
    if json_member(root, "version")?.number()? != 1
        || Path::new(json_member(root, "workspace_root")?.string()?) != candidate_root
        || Path::new(json_member(root, "target_directory")?.string()?) != staged_home.join("target")
    {
        return Err("staged Cargo metadata root or schema differs from policy".to_owned());
    }
    let packages = validate_staged_cargo_metadata_packages(
        json_member(root, "packages")?.array()?,
        candidate_root,
        &staged_cargo_vendor_root(staged_home),
    )?;
    validate_staged_cargo_metadata_members(
        json_member(root, "workspace_members")?.array()?,
        &packages,
        "workspace members",
    )?;
    validate_staged_cargo_metadata_members(
        json_member(root, "workspace_default_members")?.array()?,
        &packages,
        "default workspace members",
    )
}

#[cfg(unix)]
fn validate_staged_cargo_metadata_packages(
    packages: &[JsonValue],
    candidate_root: &Path,
    vendor_root: &Path,
) -> Result<BTreeMap<String, bool>, String> {
    if packages.is_empty() {
        return Err("staged Cargo metadata package inventory is empty".to_owned());
    }
    let mut identities = BTreeMap::new();
    for package in packages {
        let package = package.object()?;
        let id = json_member(package, "id")?.string()?.to_owned();
        let manifest = Path::new(json_member(package, "manifest_path")?.string()?);
        let workspace = matches!(json_member(package, "source")?, JsonValue::Null);
        let authority = if workspace {
            candidate_root
        } else {
            vendor_root
        };
        if id.is_empty()
            || !manifest.is_absolute()
            || manifest.file_name() != Some(std::ffi::OsStr::new("Cargo.toml"))
            || manifest.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::CurDir | std::path::Component::ParentDir
                )
            })
            || !manifest.starts_with(authority)
            || fs::canonicalize(manifest).ok().as_deref() != Some(manifest)
            || identities.insert(id, workspace).is_some()
        {
            return Err("staged Cargo metadata package path or identity is not exact".to_owned());
        }
    }
    Ok(identities)
}

#[cfg(unix)]
fn validate_staged_cargo_metadata_members(
    members: &[JsonValue],
    packages: &BTreeMap<String, bool>,
    label: &str,
) -> Result<(), String> {
    let mut observed = BTreeSet::new();
    for member in members {
        let member = member.string()?;
        if !packages.get(member).copied().unwrap_or(false) || !observed.insert(member) {
            return Err(format!(
                "staged Cargo metadata {label} differ from package authority"
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn trusted_cargo_vendor_arguments(
    candidate_root: &Path,
    manifest: &Path,
    seed_root: &Path,
    vendor: &Path,
) -> Result<Vec<OsString>, String> {
    if !candidate_root.is_absolute()
        || !seed_root.is_absolute()
        || candidate_root.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
        || seed_root.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
        || manifest != candidate_root.join("Cargo.toml")
        || vendor != staged_cargo_vendor_root(seed_root)
    {
        return Err("trusted Cargo vendor authority is not exact".to_owned());
    }
    Ok(vec![
        OsString::from("vendor"),
        OsString::from("--locked"),
        OsString::from("--versioned-dirs"),
        OsString::from("--manifest-path"),
        manifest.as_os_str().to_owned(),
        vendor.as_os_str().to_owned(),
    ])
}

#[cfg(unix)]
fn configure_staged_cargo_home_directory_source(home: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;

    let source = staged_cargo_vendor_root(home);
    let metadata = fs::symlink_metadata(&source)
        .map_err(|error| format!("cannot inspect staged Cargo vendor root: {error}"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || source.parent() != Some(home.join("vendor").as_path())
        || fs::canonicalize(&source)
            .map_err(|error| format!("cannot canonicalize staged Cargo vendor root: {error}"))?
            != source
    {
        return Err("staged Cargo vendor root is redirected".to_owned());
    }
    let packages = fs::read_dir(&source)
        .map_err(|error| format!("cannot enumerate staged Cargo vendor root: {error}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("cannot inspect staged Cargo vendor package: {error}"))?;
    if packages.is_empty() {
        return Err("staged Cargo vendor root is empty".to_owned());
    }
    for package in packages {
        let package = package.path();
        let package_metadata = fs::symlink_metadata(&package)
            .map_err(|error| format!("cannot inspect staged Cargo vendor package: {error}"))?;
        let checksum = package.join(".cargo-checksum.json");
        let checksum_metadata = fs::symlink_metadata(&checksum)
            .map_err(|error| format!("cannot inspect staged Cargo vendor checksum: {error}"))?;
        if package_metadata.file_type().is_symlink()
            || !package_metadata.is_dir()
            || package.parent() != Some(source.as_path())
            || fs::canonicalize(&package).map_err(|error| {
                format!("cannot canonicalize staged Cargo vendor package: {error}")
            })? != package
            || checksum_metadata.file_type().is_symlink()
            || !checksum_metadata.is_file()
            || checksum_metadata.nlink() != 1
            || checksum.parent() != Some(package.as_path())
            || fs::canonicalize(&checksum).map_err(|error| {
                format!("cannot canonicalize staged Cargo vendor checksum: {error}")
            })? != checksum
        {
            return Err(
                "staged Cargo vendor package is not a direct checksummed directory".to_owned(),
            );
        }
    }
    let source_text = path_text(&source, "staged Cargo vendor root")?;
    if !source_text
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"/_-.".contains(&byte))
    {
        return Err("staged Cargo registry root is not safely representable in TOML".to_owned());
    }
    let config = home.join("config.toml");
    if fs::symlink_metadata(&config).is_ok() {
        return Err("staged Cargo home already contains a configuration file".to_owned());
    }
    fs::write(
        &config,
        format!(
            "[source.crates-io]\nreplace-with = 'hell-staged-registry'\n\n[source.hell-staged-registry]\ndirectory = '{source_text}'\n"
        ),
    )
    .map_err(|error| format!("cannot bind staged Cargo offline source: {error}"))
}

#[cfg(unix)]
fn validate_trusted_cargo_cache_tree(root: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;

    let mut pending = vec![root.to_path_buf()];
    let mut entries = 0_usize;
    let mut bytes = 0_u64;
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot inspect staged Cargo offline cache: {error}"))?;
        if metadata.file_type().is_symlink()
            || (!metadata.is_dir() && !metadata.is_file())
            || (metadata.is_file() && metadata.nlink() != 1)
            || fs::canonicalize(&path)
                .map_err(|error| format!("cannot canonicalize staged Cargo cache: {error}"))?
                != path
        {
            return Err("staged Cargo offline cache contains an unbound entry".to_owned());
        }
        entries = entries
            .checked_add(1)
            .ok_or_else(|| "staged Cargo cache entry count overflowed".to_owned())?;
        bytes = bytes
            .checked_add(if metadata.is_file() {
                metadata.len()
            } else {
                0
            })
            .ok_or_else(|| "staged Cargo cache byte count overflowed".to_owned())?;
        if entries > POSIX_RUSTUP_STAGE_ENTRY_LIMIT || bytes > POSIX_RUSTUP_STAGE_BYTE_LIMIT {
            return Err("staged Cargo offline cache exceeds its resource bound".to_owned());
        }
        if metadata.is_dir() {
            for entry in fs::read_dir(&path)
                .map_err(|error| format!("cannot enumerate staged Cargo offline cache: {error}"))?
            {
                pending.push(
                    entry
                        .map_err(|error| format!("cannot read staged Cargo cache entry: {error}"))?
                        .path(),
                );
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn copy_posix_cargo_cache_tree(
    source: &Path,
    destination: &Path,
    entries: &mut usize,
    bytes: &mut u64,
) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = fs::symlink_metadata(source)
        .map_err(|error| format!("cannot inspect trusted Cargo cache source: {error}"))?;
    if metadata.file_type().is_symlink()
        || (!metadata.is_dir() && !metadata.is_file())
        || (metadata.is_file() && metadata.nlink() != 1)
    {
        return Err("trusted Cargo cache contains a link, special file, or hard link".to_owned());
    }
    if fs::canonicalize(source)
        .map_err(|error| format!("cannot canonicalize trusted Cargo cache source: {error}"))?
        != source
    {
        return Err("trusted Cargo cache source is redirected".to_owned());
    }
    *entries = entries
        .checked_add(1)
        .ok_or_else(|| "trusted Cargo cache entry count overflowed".to_owned())?;
    if *entries > POSIX_RUSTUP_STAGE_ENTRY_LIMIT {
        return Err("trusted Cargo cache exceeds its entry bound".to_owned());
    }
    if metadata.is_dir() {
        fs::create_dir_all(destination)
            .map_err(|error| format!("cannot create staged Cargo cache directory: {error}"))?;
        let source_entries = fs::read_dir(source)
            .map_err(|error| format!("cannot enumerate trusted Cargo cache: {error}"))?
            .map(|entry| {
                entry
                    .map(|entry| (entry.file_name(), entry.path()))
                    .map_err(|error| format!("cannot read Cargo cache entry: {error}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let source_names = source_entries
            .iter()
            .map(|(name, _)| name.clone())
            .collect::<BTreeSet<_>>();
        for (name, path) in source_entries {
            copy_posix_cargo_cache_tree(&path, &destination.join(name), entries, bytes)?;
        }
        let after = fs::symlink_metadata(source)
            .map_err(|error| format!("cannot revalidate trusted Cargo cache directory: {error}"))?;
        let after_names = fs::read_dir(source)
            .map_err(|error| format!("cannot re-enumerate trusted Cargo cache: {error}"))?
            .map(|entry| {
                entry
                    .map(|entry| entry.file_name())
                    .map_err(|error| format!("cannot reread Cargo cache entry: {error}"))
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        if after.file_type().is_symlink()
            || !after.is_dir()
            || after.dev() != metadata.dev()
            || after.ino() != metadata.ino()
            || after_names != source_names
            || fs::canonicalize(destination).map_err(|error| {
                format!("cannot canonicalize staged Cargo cache directory: {error}")
            })? != destination
        {
            return Err("trusted Cargo cache directory changed during staging".to_owned());
        }
    } else {
        let source_sha256 = hell_testkit::sha256_file(source)
            .map_err(|error| format!("cannot hash trusted Cargo cache entry: {error}"))?;
        *bytes = bytes
            .checked_add(metadata.len())
            .ok_or_else(|| "trusted Cargo cache byte count overflowed".to_owned())?;
        if *bytes > POSIX_RUSTUP_STAGE_BYTE_LIMIT {
            return Err("trusted Cargo cache exceeds its byte bound".to_owned());
        }
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("cannot create staged Cargo cache parent: {error}"))?;
        }
        fs::copy(source, destination)
            .map_err(|error| format!("cannot copy trusted Cargo cache entry: {error}"))?;
        let after = fs::symlink_metadata(source)
            .map_err(|error| format!("cannot revalidate trusted Cargo cache entry: {error}"))?;
        let staged_sha256 = hell_testkit::sha256_file(destination)
            .map_err(|error| format!("cannot hash staged Cargo cache entry: {error}"))?;
        if after.file_type().is_symlink()
            || !after.is_file()
            || after.nlink() != 1
            || after.dev() != metadata.dev()
            || after.ino() != metadata.ino()
            || after.len() != metadata.len()
            || hell_testkit::sha256_file(source)
                .map_err(|error| format!("cannot rehash trusted Cargo cache entry: {error}"))?
                != source_sha256
            || staged_sha256 != source_sha256
        {
            return Err("trusted Cargo cache entry changed during staging".to_owned());
        }
    }
    Ok(())
}

#[cfg(unix)]
fn normalize_posix_cargo_deny_home_with_adapter(
    sudo: &Path,
    adapter: &PosixAdapterProtection,
    home: &Path,
    candidate_uid: u32,
    trusted_owner: u32,
    trusted_group_id: u32,
) -> Result<(), String> {
    require_posix_adapter_unchanged(adapter)?;
    let uid = candidate_uid.to_string();
    let trusted_owner = trusted_owner.to_string();
    let gid = trusted_group_id.to_string();
    trusted_status(
        sudo,
        [
            "-n",
            "--",
            path_text(&adapter.adapter, "trusted cargo-deny home normalizer")?,
            "__release-normalize-cargo-deny-home",
            path_text(home, "candidate cargo-deny home")?,
            &uid,
            &trusted_owner,
            &gid,
        ],
    )?;
    require_posix_adapter_unchanged(adapter)
}

#[cfg(unix)]
fn normalize_posix_stack_root_with_adapter(
    sudo: &Path,
    adapter: &PosixAdapterProtection,
    root: &Path,
    candidate_uid: u32,
    trusted_group_id: u32,
) -> Result<(), String> {
    require_posix_adapter_unchanged(adapter)?;
    let uid = candidate_uid.to_string();
    let gid = trusted_group_id.to_string();
    trusted_status(
        sudo,
        [
            "-n",
            "--",
            path_text(&adapter.adapter, "trusted Stack-root normalizer")?,
            "__release-normalize-stack-root",
            path_text(root, "candidate Stack root")?,
            &uid,
            &gid,
        ],
    )?;
    require_posix_adapter_unchanged(adapter)
}

#[cfg(unix)]
fn posix_cargo_deny_home_is_exact(target: &Path, home: &Path) -> bool {
    home == target
        .join("release-child-environment")
        .join("cargo-deny-cargo-home")
}

#[cfg(unix)]
fn posix_cargo_deny_metadata_is_exact(parent: &Path, directory: &Path, path: &Path) -> bool {
    let Some(name) = directory.file_name().and_then(std::ffi::OsStr::to_str) else {
        return false;
    };
    let Some((process, sequence)) = name
        .strip_prefix("hell-cargo-deny-metadata-")
        .and_then(|suffix| suffix.split_once('-'))
    else {
        return false;
    };
    let canonical_number = |value: &str| {
        value
            .parse::<u64>()
            .is_ok_and(|number| value == number.to_string())
    };
    parent == Path::new("/var/tmp")
        && directory.parent() == Some(parent)
        && canonical_number(process)
        && canonical_number(sequence)
        && path == directory.join("metadata.json")
}

#[cfg(unix)]
fn posix_dependency_policy_is_exact(parent: &Path, directory: &Path, path: &Path) -> bool {
    let Some(name) = directory.file_name().and_then(std::ffi::OsStr::to_str) else {
        return false;
    };
    let Some((process, sequence)) = name
        .strip_prefix("hell-dependency-policy-")
        .and_then(|suffix| suffix.split_once('-'))
    else {
        return false;
    };
    let canonical_number = |value: &str| {
        value
            .parse::<u64>()
            .is_ok_and(|number| value == number.to_string())
    };
    parent == Path::new("/var/tmp")
        && directory.parent() == Some(parent)
        && canonical_number(process)
        && canonical_number(sequence)
        && path == directory.join("dependency-policy.json")
}

#[cfg(unix)]
fn posix_stack_root_is_exact(root: &Path) -> bool {
    let Some(name) = root.file_name().and_then(std::ffi::OsStr::to_str) else {
        return false;
    };
    let Some((process, sequence)) = name
        .strip_prefix("hell-stack-root-")
        .and_then(|suffix| suffix.split_once('-'))
    else {
        return false;
    };
    let canonical_number = |value: &str| {
        value
            .parse::<u64>()
            .is_ok_and(|number| value == number.to_string())
    };
    root.parent() == Some(Path::new("/private/var/tmp"))
        && canonical_number(process)
        && canonical_number(sequence)
}

#[cfg(unix)]
fn validate_posix_cargo_deny_home_post_state(
    home: &Path,
    candidate_uid: u32,
    trusted_owner: u32,
    trusted_group_id: u32,
    advisory_lock: &fs::File,
) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let mut pending = vec![home.to_path_buf()];
    let mut entries = 0_usize;
    let mut bytes = 0_u64;
    let advisory_root = Path::new("advisory-dbs");
    let mut found_advisory_root = false;
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot inspect final cargo-deny cache state: {error}"))?;
        let relative = path
            .strip_prefix(home)
            .map_err(|_| "final cargo-deny cache entry escapes its home".to_owned())?;

        if relative == Path::new("registry/cache") || relative == Path::new("registry/src") {
            return Err("final cargo-deny cache recreates a removed package fallback".to_owned());
        }

        if relative == advisory_root {
            if metadata.file_type().is_symlink()
                || !metadata.is_dir()
                || metadata.uid() != candidate_uid
                || metadata.gid() != trusted_group_id
                || metadata.permissions().mode() & 0o7777 != 0o750
            {
                return Err(
                    "final cargo-deny cache identity or permissions differ from policy".to_owned(),
                );
            }
            found_advisory_root = true;
            entries = entries
                .checked_add(1)
                .ok_or_else(|| "final cargo-deny cache entry count overflowed".to_owned())?;
            if entries > POSIX_RUSTUP_STAGE_ENTRY_LIMIT {
                return Err("final cargo-deny cache exceeds its resource bound".to_owned());
            }
            // The advisory root is candidate-controlled. The trusted reader
            // group can enumerate directory metadata for launch-policy
            // binding, while candidate-owned lock files remain unreadable to
            // it. Retain the lock descriptor so its final metadata can be
            // checked without opening candidate storage.
            continue;
        }

        if metadata.file_type().is_symlink()
            || (!metadata.is_dir() && !metadata.is_file())
            || (metadata.is_file() && metadata.nlink() != 1)
            || metadata.uid() != trusted_owner
            || metadata.gid() != trusted_group_id
            || metadata.permissions().mode() & 0o7777
                != if metadata.is_dir() { 0o555 } else { 0o444 }
        {
            return Err(
                "final cargo-deny cache identity or permissions differ from policy".to_owned(),
            );
        }
        entries = entries
            .checked_add(1)
            .ok_or_else(|| "final cargo-deny cache entry count overflowed".to_owned())?;
        bytes = bytes
            .checked_add(if metadata.is_file() {
                metadata.len()
            } else {
                0
            })
            .ok_or_else(|| "final cargo-deny cache byte count overflowed".to_owned())?;
        if entries > POSIX_RUSTUP_STAGE_ENTRY_LIMIT || bytes > POSIX_RUSTUP_STAGE_BYTE_LIMIT {
            return Err("final cargo-deny cache exceeds its resource bound".to_owned());
        }
        if metadata.is_dir() {
            for entry in fs::read_dir(&path)
                .map_err(|error| format!("cannot enumerate final cargo-deny cache: {error}"))?
            {
                pending.push(
                    entry
                        .map_err(|error| {
                            format!("cannot read final cargo-deny cache entry: {error}")
                        })?
                        .path(),
                );
            }
        }
    }

    let lock_metadata = advisory_lock
        .metadata()
        .map_err(|error| format!("cannot inspect final cargo-deny advisory lock: {error}"))?;
    if lock_metadata.file_type().is_symlink()
        || !lock_metadata.is_file()
        || lock_metadata.nlink() != 1
        || lock_metadata.len() != 0
        || lock_metadata.uid() != candidate_uid
        || lock_metadata.gid() != trusted_group_id
        || lock_metadata.permissions().mode() & 0o7777 != 0o660
    {
        return Err("final cargo-deny cache identity or permissions differ from policy".to_owned());
    }
    entries = entries
        .checked_add(1)
        .ok_or_else(|| "final cargo-deny cache entry count overflowed".to_owned())?;
    if entries > POSIX_RUSTUP_STAGE_ENTRY_LIMIT {
        return Err("final cargo-deny cache exceeds its resource bound".to_owned());
    }
    if !found_advisory_root {
        return Err("final cargo-deny advisory root authority is absent".to_owned());
    }
    Ok(())
}

#[cfg(unix)]
fn validate_posix_stack_root_post_state(
    root: &Path,
    candidate_uid: u32,
    trusted_group_id: u32,
) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let mut pending = vec![root.to_path_buf()];
    let mut entries = 0_usize;
    let mut bytes = 0_u64;
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot inspect final Stack-root state: {error}"))?;
        if metadata.file_type().is_symlink()
            || (!metadata.is_dir() && !metadata.is_file())
            || (metadata.is_file() && metadata.nlink() != 1)
            || metadata.uid() != candidate_uid
            || metadata.gid() != trusted_group_id
            || (metadata.is_dir() && metadata.permissions().mode() & 0o7777 != 0o750)
            || (metadata.is_file() && metadata.permissions().mode() & 0o7777 != 0o640)
        {
            return Err("final Stack-root identity or permissions differ from policy".to_owned());
        }
        entries = entries
            .checked_add(1)
            .ok_or_else(|| "final Stack-root entry count overflowed".to_owned())?;
        bytes = bytes
            .checked_add(if metadata.is_file() {
                metadata.len()
            } else {
                0
            })
            .ok_or_else(|| "final Stack-root byte count overflowed".to_owned())?;
        if entries > POSIX_RUSTUP_STAGE_ENTRY_LIMIT || bytes > POSIX_RUSTUP_STAGE_BYTE_LIMIT {
            return Err("final Stack root exceeds its resource bound".to_owned());
        }
        if metadata.is_dir() {
            for entry in fs::read_dir(&path)
                .map_err(|error| format!("cannot enumerate final Stack root: {error}"))?
            {
                pending.push(
                    entry
                        .map_err(|error| format!("cannot read final Stack-root entry: {error}"))?
                        .path(),
                );
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn verify_posix_post_state_metadata_for_integration() -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let parent = fs::canonicalize(env::temp_dir())
        .map_err(|error| format!("cannot canonicalize POSIX verifier temp root: {error}"))?;
    let parent_identity = posix_object_identity(&parent)?;
    let mut root = None;
    for _ in 0..16 {
        let sequence = POSIX_CARGO_METADATA_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(
            "hell-posix-post-state-metadata-{}-{sequence}",
            std::process::id()
        ));
        match fs::create_dir(&candidate) {
            Ok(()) => {
                root = Some(candidate);
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(format!(
                    "cannot create POSIX post-state verifier root: {error}"
                ));
            }
        }
    }
    let root = root.ok_or_else(|| {
        "cannot allocate a collision-free POSIX post-state verifier root".to_owned()
    })?;
    let mut root_handle = None;
    let mut creation_identity = None;
    let mut root_identity = None;
    let mut initialized = false;
    let initialization = (|| {
        let handle = fs::File::open(&root)
            .map_err(|error| format!("cannot retain POSIX post-state verifier root: {error}"))?;
        let identity =
            posix_object_identity_from_metadata(&handle.metadata().map_err(|error| {
                format!("cannot bind created POSIX post-state verifier root: {error}")
            })?);
        creation_identity = Some(identity.clone());
        root_handle = Some(handle);
        if !posix_same_object(&posix_object_identity(&root)?, &identity) {
            return Err("created POSIX post-state verifier root changed before setup".to_owned());
        }
        root_handle
            .as_ref()
            .ok_or_else(|| "POSIX post-state verifier root handle was not retained".to_owned())?
            .set_permissions(fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("cannot confine POSIX post-state verifier root: {error}"))?;
        let identity = posix_object_identity_from_metadata(
            &root_handle
                .as_ref()
                .ok_or_else(|| "POSIX post-state verifier root handle was not retained".to_owned())?
                .metadata()
                .map_err(|error| format!("cannot bind POSIX post-state verifier root: {error}"))?,
        );
        root_identity = Some(identity);
        initialized = true;
        Ok(())
    })();
    let result = initialization.and_then(|()| {
        let root_metadata = fs::metadata(&root)
            .map_err(|error| format!("cannot inspect POSIX post-state verifier root: {error}"))?;
        let owner = root_metadata.uid();
        let group = root_metadata.gid();

        let cargo_home = root.join("cargo-home");
        let advisory_root = cargo_home.join("advisory-dbs");
        let advisory_lock_path = advisory_root.join("advisory-lock");
        fs::create_dir(&cargo_home)
            .map_err(|error| format!("cannot create cargo-deny verifier home: {error}"))?;
        fs::create_dir(&advisory_root)
            .map_err(|error| format!("cannot create cargo-deny advisory verifier root: {error}"))?;
        let advisory_lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&advisory_lock_path)
            .map_err(|error| format!("cannot create cargo-deny advisory verifier lock: {error}"))?;
        fs::set_permissions(&cargo_home, fs::Permissions::from_mode(0o555))
            .map_err(|error| format!("cannot confine cargo-deny verifier home: {error}"))?;
        fs::set_permissions(&advisory_root, fs::Permissions::from_mode(0o750)).map_err(
            |error| format!("cannot confine cargo-deny advisory verifier root: {error}"),
        )?;
        advisory_lock
            .set_permissions(fs::Permissions::from_mode(0o660))
            .map_err(|error| {
                format!("cannot confine cargo-deny advisory verifier lock: {error}")
            })?;
        validate_posix_cargo_deny_home_post_state(
            &cargo_home,
            owner,
            owner,
            group,
            &advisory_lock,
        )?;
        let advisory_alias = root.join("advisory-lock-alias");
        fs::hard_link(&advisory_lock_path, &advisory_alias)
            .map_err(|error| format!("cannot alias cargo-deny advisory verifier lock: {error}"))?;
        if validate_posix_cargo_deny_home_post_state(
            &cargo_home,
            owner,
            owner,
            group,
            &advisory_lock,
        )
        .is_ok()
        {
            return Err("cargo-deny post-state accepted a multiply-linked lock".to_owned());
        }
        fs::remove_file(&advisory_alias)
            .map_err(|error| format!("cannot remove advisory verifier alias: {error}"))?;

        let stack_root = root.join("stack-root");
        let stack_member = stack_root.join("member");
        fs::create_dir(&stack_root)
            .map_err(|error| format!("cannot create Stack-root verifier: {error}"))?;
        fs::write(&stack_member, b"member\n")
            .map_err(|error| format!("cannot create Stack-root verifier member: {error}"))?;
        fs::set_permissions(&stack_root, fs::Permissions::from_mode(0o750))
            .map_err(|error| format!("cannot confine Stack-root verifier: {error}"))?;
        fs::set_permissions(&stack_member, fs::Permissions::from_mode(0o640))
            .map_err(|error| format!("cannot confine Stack-root verifier member: {error}"))?;
        validate_posix_stack_root_post_state(&stack_root, owner, group)?;
        let stack_alias = root.join("stack-member-alias");
        fs::hard_link(&stack_member, &stack_alias)
            .map_err(|error| format!("cannot alias Stack-root verifier member: {error}"))?;
        if validate_posix_stack_root_post_state(&stack_root, owner, group).is_ok() {
            return Err("Stack-root post-state accepted a multiply-linked member".to_owned());
        }
        fs::remove_file(&stack_alias)
            .map_err(|error| format!("cannot remove Stack-root verifier alias: {error}"))?;
        Ok(())
    });
    let cleanup = (|| {
        if root.parent() != Some(parent.as_path())
            || posix_object_identity(&parent)? != parent_identity
        {
            return Err("POSIX post-state verifier root changed before cleanup".to_owned());
        }
        match (creation_identity.as_ref(), root_handle.as_ref()) {
            (Some(creation_identity), Some(root_handle)) => {
                let retained_identity =
                    posix_object_identity_from_metadata(&root_handle.metadata().map_err(
                        |error| format!("cannot revalidate retained POSIX verifier root: {error}"),
                    )?);
                if !posix_same_object(&retained_identity, creation_identity)
                    || !posix_same_object(&posix_object_identity(&root)?, creation_identity)
                {
                    return Err("POSIX post-state verifier root changed before cleanup".to_owned());
                }
            }
            (None, None) => {}
            _ => {
                return Err("POSIX post-state verifier root receipt is incomplete".to_owned());
            }
        }
        if initialized {
            let root_identity = root_identity.as_ref().ok_or_else(|| {
                "POSIX post-state verifier final root receipt is missing".to_owned()
            })?;
            let root_handle = root_handle.as_ref().ok_or_else(|| {
                "POSIX post-state verifier root handle was not retained".to_owned()
            })?;
            let retained_identity =
                posix_object_identity_from_metadata(&root_handle.metadata().map_err(|error| {
                    format!("cannot revalidate final POSIX verifier root: {error}")
                })?);
            if retained_identity != *root_identity
                || posix_object_identity(&root)? != *root_identity
            {
                return Err("POSIX post-state verifier final root receipt changed".to_owned());
            }
        }
        if !initialized {
            let metadata = fs::symlink_metadata(&root).map_err(|error| {
                format!("cannot inspect partial POSIX post-state verifier root: {error}")
            })?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(
                    "partial POSIX post-state verifier root was substituted before cleanup"
                        .to_owned(),
                );
            }
            return fs::remove_dir(&root).map_err(|error| {
                format!("cannot remove partial POSIX post-state verifier root: {error}")
            });
        }
        for directory in [
            root.join("cargo-home").join("advisory-dbs"),
            root.join("cargo-home"),
            root.join("stack-root"),
        ] {
            match fs::symlink_metadata(&directory) {
                Ok(metadata) if !metadata.file_type().is_symlink() && metadata.is_dir() => {
                    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).map_err(
                        |error| format!("cannot open POSIX post-state verifier cleanup: {error}"),
                    )?;
                }
                Ok(_) => {
                    return Err(
                        "POSIX post-state verifier cleanup directory was substituted".to_owned(),
                    );
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(format!(
                        "cannot inspect POSIX post-state verifier cleanup: {error}"
                    ));
                }
            }
        }
        fs::remove_dir_all(&root)
            .map_err(|error| format!("cannot remove POSIX post-state verifier root: {error}"))
    })();
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(()), Err(cleanup)) => Err(cleanup),
        (Err(primary), Err(cleanup)) => Err(ordered_bounded_failures(
            "POSIX post-state verifier failed",
            [("primary", primary), ("cleanup", cleanup)],
        )),
    }
}

#[cfg(unix)]
impl Drop for PosixRustupProtection {
    fn drop(&mut self) {
        let _ = cleanup_posix_rustup_authority(self);
    }
}

#[cfg(unix)]
fn stage_posix_rustup_authority(
    platform: ReleasePlatform,
    sudo: &Path,
    authority: &crate::command::ResolvedPosixRustupAuthority,
) -> Result<PosixRustupProtection, String> {
    let source_inventory = posix_rustup_selected_inventory(
        authority.home(),
        authority.toolchain(),
        "standard Rustup",
    )?;
    let installation_root = posix_adapter_installation_root(platform)?;
    let installation_root_identity = posix_object_identity(&installation_root)?;
    let tools = resolve_posix_adapter_tools(platform)?;
    let linux_setfacl = (platform == ReleasePlatform::LinuxX86_64)
        .then(|| {
            crate::command::resolve_absolute_standard_executable(Path::new("/usr/bin/setfacl"))
                .map_err(|error| format!("cannot bind Linux Rustup ACL authority: {error}"))
        })
        .transpose()?;
    let linux_getfacl = (platform == ReleasePlatform::LinuxX86_64)
        .then(|| {
            crate::command::resolve_absolute_standard_executable(Path::new("/usr/bin/getfacl"))
                .map_err(|error| format!("cannot bind Linux Rustup ACL verifier: {error}"))
        })
        .transpose()?;
    let sequence = POSIX_ADAPTER_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let directory = installation_root.join(format!(
        "hell-rs-posix-rustup-{}-{sequence}",
        std::process::id()
    ));
    let home = directory.join("rustup-home");
    let toolchains = home.join("toolchains");
    let update_hashes = home.join("update-hashes");
    let staged_toolchain = toolchains.join(authority.toolchain());
    let staged_settings = home.join("settings.toml");
    let staged_update_hash = update_hashes.join(authority.toolchain());
    let source_toolchain = authority
        .home()
        .join("toolchains")
        .join(authority.toolchain());
    let source_settings = authority.home().join("settings.toml");
    let source_update_hash = authority
        .home()
        .join("update-hashes")
        .join(authority.toolchain());

    trusted_tool_status(
        sudo,
        &tools.mkdir,
        [
            "-m",
            "0555",
            "--",
            path_text(&directory, "staged Rustup directory")?,
        ],
    )
    .map_err(|error| format!("cannot reserve staged Rustup authority: {error}"))?;
    if platform == ReleasePlatform::MacosAarch64 {
        trusted_tool_status(
            sudo,
            &tools.chmod,
            posix_acl_removal_arguments(
                platform,
                false,
                path_text(&directory, "staged Rustup authority ACL")?,
            )?,
        )?;
    } else if let Some(setfacl) = &linux_setfacl {
        trusted_tool_status(
            sudo,
            setfacl,
            [
                "-b",
                "-k",
                "--",
                path_text(&directory, "staged Rustup authority ACL")?,
            ],
        )?;
    }
    let directory_identity = posix_object_identity(&directory)?;
    let result = (|| {
        for path in [&home, &toolchains, &update_hashes] {
            trusted_tool_status(
                sudo,
                &tools.mkdir,
                [
                    "-m",
                    "0555",
                    "--",
                    path_text(path, "staged Rustup directory")?,
                ],
            )?;
        }
        trusted_tool_status(
            sudo,
            &tools.copy,
            [
                "--",
                path_text(&source_settings, "standard Rustup settings")?,
                path_text(&staged_settings, "staged Rustup settings")?,
            ],
        )?;
        trusted_tool_status(
            sudo,
            &tools.copy,
            [
                "--",
                path_text(&source_update_hash, "standard Rustup update hash")?,
                path_text(&staged_update_hash, "staged Rustup update hash")?,
            ],
        )?;
        trusted_tool_status(
            sudo,
            &tools.copy,
            [
                "-R",
                "--",
                path_text(&source_toolchain, "standard Rustup toolchain")?,
                path_text(&staged_toolchain, "staged Rustup toolchain")?,
            ],
        )?;
        if platform == ReleasePlatform::MacosAarch64 {
            trusted_tool_status(
                sudo,
                &tools.chmod,
                posix_acl_removal_arguments(
                    platform,
                    true,
                    path_text(&home, "staged Rustup ACL authority")?,
                )?,
            )?;
        } else if let Some(setfacl) = &linux_setfacl {
            trusted_tool_status(
                sudo,
                setfacl,
                [
                    "-R",
                    "-b",
                    "-k",
                    "--",
                    path_text(&home, "staged Rustup ACL authority")?,
                ],
            )?;
        }
        for (path, label) in [
            (&staged_settings, "staged Rustup settings"),
            (&staged_update_hash, "staged Rustup update hash"),
        ] {
            trusted_tool_status(
                sudo,
                &tools.chmod,
                posix_chmod_arguments(platform, "0444", path_text(path, label)?)?,
            )?;
        }
        trusted_tool_status(
            sudo,
            &tools.chmod,
            [
                "-R",
                "a+rX",
                path_text(&staged_toolchain, "staged Rustup toolchain")?,
            ],
        )?;
        trusted_tool_status(
            sudo,
            &tools.chmod,
            [
                "-R",
                "a-w",
                path_text(&staged_toolchain, "staged Rustup toolchain")?,
            ],
        )?;
        let protection = PosixRustupProtection {
            platform,
            installation_root: installation_root.clone(),
            installation_root_identity: installation_root_identity.clone(),
            directory: directory.clone(),
            directory_identity: directory_identity.clone(),
            home: home.clone(),
            source_home: authority.home().to_path_buf(),
            toolchain: authority.toolchain().to_os_string(),
            proxy_identity: authority.proxy_identity().clone(),
            rustc_authority: authority.rustc_authority().clone(),
            inventory: source_inventory,
            linux_getfacl,
            sudo: sudo.to_path_buf(),
            tools: tools.clone(),
        };
        validate_posix_rustup_authority(&protection)?;
        Ok(protection)
    })();
    if result.is_err() {
        let _ = cleanup_posix_rustup_paths(
            platform,
            sudo,
            &tools,
            &installation_root,
            &installation_root_identity,
            &directory,
            &directory_identity,
        );
    }
    result
}

#[cfg(unix)]
fn validate_posix_rustup_authority(protection: &PosixRustupProtection) -> Result<(), String> {
    protection.proxy_identity.revalidate()?;
    protection
        .rustc_authority
        .revalidate(&protection.proxy_identity)?;
    if validate_posix_adapter_installation_root(protection.platform, &protection.installation_root)?
        != protection.installation_root
        || posix_object_identity(&protection.installation_root)?
            != protection.installation_root_identity
        || !posix_rustup_cleanup_is_exact(&protection.installation_root, &protection.directory)
        || posix_object_identity(&protection.directory)? != protection.directory_identity
        || protection.home != protection.directory.join("rustup-home")
    {
        return Err("staged Rustup authority identity changed".to_owned());
    }
    require_exact_directory_members(
        &protection.directory,
        &[OsString::from("rustup-home")],
        "staged Rustup authority",
    )?;
    require_exact_directory_members(
        &protection.home,
        &[
            OsString::from("settings.toml"),
            OsString::from("toolchains"),
            OsString::from("update-hashes"),
        ],
        "staged Rustup home",
    )?;
    require_exact_directory_members(
        &protection.home.join("toolchains"),
        std::slice::from_ref(&protection.toolchain),
        "staged Rustup toolchains",
    )?;
    require_exact_directory_members(
        &protection.home.join("update-hashes"),
        std::slice::from_ref(&protection.toolchain),
        "staged Rustup update hashes",
    )?;
    require_posix_read_only_tree(&protection.home, "staged Rustup")?;
    match (protection.platform, protection.linux_getfacl.as_ref()) {
        (ReleasePlatform::LinuxX86_64, Some(getfacl)) => {
            getfacl
                .revalidate()
                .map_err(|error| format!("Linux Rustup ACL verifier changed: {error}"))?;
            require_linux_base_acl_tree(getfacl, &protection.directory, 1, false)?;
            require_linux_base_acl_tree(
                getfacl,
                &protection.home,
                protection
                    .inventory
                    .len()
                    .checked_add(1)
                    .ok_or_else(|| "staged Rustup ACL inventory count overflowed".to_owned())?,
                true,
            )?;
        }
        (ReleasePlatform::LinuxX86_64, None) => {
            return Err("Linux Rustup ACL verifier authority is absent".to_owned());
        }
        (_, Some(_)) => {
            return Err("non-Linux Rustup authority retained a Linux ACL verifier".to_owned());
        }
        (_, None) => {}
    }
    if posix_rustup_selected_inventory(&protection.home, &protection.toolchain, "staged Rustup")?
        != protection.inventory
    {
        return Err("staged Rustup bytes or closed inventory changed".to_owned());
    }
    Ok(())
}

#[cfg(unix)]
fn require_linux_base_acl_tree(
    getfacl: &crate::command::ResolvedStandardExecutable,
    root: &Path,
    expected_entries: usize,
    recursive: bool,
) -> Result<(), String> {
    let command = CommandSpec::new(
        getfacl.invocation_path().as_os_str(),
        Duration::from_mins(5),
    );
    let command = if recursive {
        command.argument("-R")
    } else {
        command
    };
    let result = command
        .arguments([OsString::from("-p"), OsString::from("--")])
        .argument(root)
        .run()
        .map_err(|error| format!("cannot inspect staged Rustup Linux ACLs: {error}"))?;
    if result.timed_out
        || !result.status.success()
        || result.stdout_truncated
        || result.stderr_truncated
        || !result.stderr.is_empty()
    {
        return Err(format!(
            "staged Rustup Linux ACL inspection did not succeed exactly: status={:?}; stderr={}",
            result.status.code(),
            String::from_utf8_lossy(&result.stderr)
        ));
    }
    if !linux_getfacl_output_is_exact_base_acl(&result.stdout, expected_entries) {
        return Err("staged Rustup Linux ACL state is not exactly base-only".to_owned());
    }
    Ok(())
}

#[cfg(unix)]
fn linux_getfacl_output_is_exact_base_acl(output: &[u8], expected_entries: usize) -> bool {
    const USER: u8 = 1;
    const GROUP: u8 = 2;
    const OTHER: u8 = 4;
    const COMPLETE: u8 = USER | GROUP | OTHER;

    fn permission_triplet_is_canonical(value: &[u8]) -> bool {
        value.len() == 3
            && matches!(value[0], b'r' | b'-')
            && matches!(value[1], b'w' | b'-')
            && matches!(value[2], b'x' | b'-')
    }

    let mut entries = 0_usize;
    let mut fields = 0_u8;
    let mut in_entry = false;
    for line in output.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            if in_entry {
                if fields != COMPLETE {
                    return false;
                }
                entries = match entries.checked_add(1) {
                    Some(entries) => entries,
                    None => return false,
                };
                in_entry = false;
                fields = 0;
            }
            continue;
        }
        if line.starts_with(b"# file: ") {
            if in_entry {
                return false;
            }
            in_entry = true;
            continue;
        }
        if line.starts_with(b"# ") {
            if !in_entry {
                return false;
            }
            continue;
        }
        if !in_entry {
            return false;
        }
        let (bit, value) = if let Some(value) = line.strip_prefix(b"user::") {
            (USER, value)
        } else if let Some(value) = line.strip_prefix(b"group::") {
            (GROUP, value)
        } else if let Some(value) = line.strip_prefix(b"other::") {
            (OTHER, value)
        } else {
            return false;
        };
        if fields & bit != 0 || !permission_triplet_is_canonical(value) {
            return false;
        }
        fields |= bit;
    }
    if in_entry {
        if fields != COMPLETE {
            return false;
        }
        entries = match entries.checked_add(1) {
            Some(entries) => entries,
            None => return false,
        };
    }
    entries == expected_entries
}

#[cfg(unix)]
fn posix_rustup_selected_inventory(
    home: &Path,
    toolchain: &std::ffi::OsStr,
    label: &str,
) -> Result<Vec<PosixRustupInventoryEntry>, String> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let mut pending = vec![
        home.join("settings.toml"),
        home.join("toolchains"),
        home.join("toolchains").join(toolchain),
        home.join("update-hashes"),
        home.join("update-hashes").join(toolchain),
    ];
    let mut inventory = Vec::new();
    let mut bytes = 0_u64;
    let mut visited = BTreeSet::new();
    while let Some(path) = pending.pop() {
        if !visited.insert(path.clone()) {
            continue;
        }
        let relative = path
            .strip_prefix(home)
            .map_err(|_| format!("{label} selected entry escapes its home"))?
            .to_path_buf();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot inspect {label} entry {relative:?}: {error}"))?;
        if metadata.file_type().is_symlink()
            || (!metadata.is_dir() && !metadata.is_file())
            || (metadata.is_file() && metadata.nlink() != 1)
        {
            return Err(format!(
                "{label} selected inventory contains a symlink, special file, or hard link"
            ));
        }
        let directory = metadata.is_dir();
        let size = if directory { 0 } else { metadata.len() };
        let (next_entries, next_bytes) = posix_rustup_inventory_cost(inventory.len(), bytes, size)
            .ok_or_else(|| format!("{label} selected inventory exceeds its staging bound"))?;
        bytes = next_bytes;
        let sha256 = (!directory)
            .then(|| hell_testkit::sha256_file(&path))
            .transpose()
            .map_err(|error| format!("cannot hash {label} entry {relative:?}: {error}"))?;
        inventory.push(PosixRustupInventoryEntry {
            relative,
            directory,
            size,
            sha256,
            executable: !directory && metadata.permissions().mode() & 0o111 != 0,
        });
        debug_assert_eq!(inventory.len(), next_entries);
        if directory && path != home.join("toolchains") && path != home.join("update-hashes") {
            for entry in fs::read_dir(&path)
                .map_err(|error| format!("cannot enumerate {label} entry: {error}"))?
            {
                pending.push(
                    entry
                        .map_err(|error| format!("cannot read {label} entry: {error}"))?
                        .path(),
                );
            }
        }
    }
    inventory.sort_by(|left, right| left.relative.cmp(&right.relative));
    Ok(inventory)
}

#[cfg(unix)]
fn posix_rustup_inventory_cost(entries: usize, bytes: u64, next_size: u64) -> Option<(usize, u64)> {
    let entries = entries.checked_add(1)?;
    let bytes = bytes.checked_add(next_size)?;
    (entries <= POSIX_RUSTUP_STAGE_ENTRY_LIMIT && bytes <= POSIX_RUSTUP_STAGE_BYTE_LIMIT)
        .then_some((entries, bytes))
}

#[cfg(unix)]
fn require_exact_directory_members(
    directory: &Path,
    expected: &[OsString],
    label: &str,
) -> Result<(), String> {
    const MEMBER_LIMIT: usize = 4_096;
    const DIAGNOSTIC_BYTE_LIMIT: usize = 4_096;

    let mut observed = BTreeSet::new();
    for entry in
        fs::read_dir(directory).map_err(|error| format!("cannot enumerate {label}: {error}"))?
    {
        if observed.len() == MEMBER_LIMIT {
            return Err(format!(
                "{label} exceeds the bounded inventory member limit {MEMBER_LIMIT}"
            ));
        }
        observed.insert(
            entry
                .map_err(|error| format!("cannot read {label} entry: {error}"))?
                .file_name(),
        );
    }
    let expected = expected.iter().cloned().collect::<BTreeSet<_>>();
    if observed != expected {
        let missing = expected.difference(&observed).cloned().collect::<Vec<_>>();
        let extra = observed.difference(&expected).cloned().collect::<Vec<_>>();
        let mut detail = String::from("missing=[");
        let append = |detail: &mut String, names: &[OsString]| {
            for (position, name) in names.iter().enumerate() {
                let separator = if position == 0 { "" } else { ", " };
                let rendered = format!("{name:?}");
                let Some(next_len) = detail
                    .len()
                    .checked_add(separator.len())
                    .and_then(|length| length.checked_add(rendered.len()))
                else {
                    detail.push_str("<length-overflow>");
                    return;
                };
                if next_len > DIAGNOSTIC_BYTE_LIMIT {
                    detail.push_str("<bounded>");
                    return;
                }
                detail.push_str(separator);
                detail.push_str(&rendered);
            }
        };
        append(&mut detail, &missing);
        detail.push_str("] extra=[");
        append(&mut detail, &extra);
        detail.push(']');
        return Err(format!(
            "{label} is not an exact closed inventory: {detail}"
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn cleanup_posix_rustup_authority(protection: &PosixRustupProtection) -> Result<(), String> {
    validate_posix_rustup_authority(protection)?;
    cleanup_posix_rustup_paths(
        protection.platform,
        &protection.sudo,
        &protection.tools,
        &protection.installation_root,
        &protection.installation_root_identity,
        &protection.directory,
        &protection.directory_identity,
    )
}

#[cfg(unix)]
fn cleanup_posix_rustup_paths(
    platform: ReleasePlatform,
    sudo: &Path,
    tools: &PosixAdapterTools,
    installation_root: &Path,
    installation_root_identity: &PosixObjectIdentity,
    directory: &Path,
    directory_identity: &PosixObjectIdentity,
) -> Result<(), String> {
    if validate_posix_adapter_installation_root(platform, installation_root)? != installation_root
        || posix_object_identity(installation_root)? != *installation_root_identity
        || !posix_rustup_cleanup_is_exact(installation_root, directory)
        || posix_object_identity(directory)? != *directory_identity
    {
        return Err("staged Rustup cleanup authority changed".to_owned());
    }
    trusted_tool_status(
        sudo,
        &tools.remove_file,
        ["-rf", "--", path_text(directory, "staged Rustup cleanup")?],
    )
}

#[cfg(unix)]
fn posix_rustup_cleanup_is_exact(installation_root: &Path, directory: &Path) -> bool {
    directory.parent() == Some(installation_root)
        && directory
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("hell-rs-posix-rustup-"))
}

#[cfg(unix)]
impl Drop for PosixSourceProtection {
    fn drop(&mut self) {
        let _ = cleanup_posix_sources(self);
    }
}

#[cfg(unix)]
fn stage_posix_sources(
    platform: ReleasePlatform,
    sudo: &Path,
    candidate_source: &Path,
    oracle_source: &Path,
    candidate_inventory: &JsonValue,
    oracle_inventory: &JsonValue,
    candidate_sha: &str,
    target: &Path,
    candidate_group: &str,
    trusted_owner: u32,
    candidate_uid: u32,
    candidate_primary_gid: u32,
    trusted_group_id: u32,
) -> Result<PosixSourceProtection, String> {
    require_clean_checkout(candidate_source, candidate_sha, "candidate")?;
    require_clean_checkout(
        oracle_source,
        crate::command::PINNED_ORACLE_SOURCE_COMMIT,
        "oracle",
    )?;
    let installation_root = posix_adapter_installation_root(platform)?;
    let installation_root_identity = posix_object_identity(&installation_root)?;
    let tools = resolve_posix_adapter_tools(platform)?;
    let sequence = POSIX_ADAPTER_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let directory = installation_root.join(format!(
        "hell-rs-posix-sources-{}-{sequence}-{}",
        std::process::id(),
        &candidate_sha[..12]
    ));
    let candidate = directory.join("candidate");
    let oracle = directory.join("oracle");
    let stack_work =
        (platform == ReleasePlatform::MacosAarch64).then(|| oracle.join(".stack-work"));
    let transient = directory.join("release-gate-transient");
    let archive_adapter = directory.join("archive-adapter");
    let retained_oracle = directory.join("retained-oracle");
    let directory_text = path_text(&directory, "POSIX source authority")?;
    let candidate_text = path_text(&candidate, "staged candidate source")?;
    let oracle_text = path_text(&oracle, "staged oracle source")?;
    let transient_text = path_text(&transient, "candidate transient authority")?;
    let archive_adapter_text = path_text(&archive_adapter, "native archive adapter authority")?;
    let retained_oracle_text = path_text(&retained_oracle, "retained oracle authority")?;
    let candidate_source_text = path_text(candidate_source, "candidate source")?;
    let oracle_source_text = path_text(oracle_source, "oracle source")?;

    trusted_tool_status(sudo, &tools.mkdir, ["-m", "0755", "--", directory_text])
        .map_err(|error| format!("cannot reserve POSIX source authority: {error}"))?;
    let reserved_directory_identity = posix_object_identity(&directory)?;
    let result = (|| {
        trusted_tool_status(
            sudo,
            &tools.copy,
            ["-R", "--", candidate_source_text, candidate_text],
        )?;
        trusted_tool_status(
            sudo,
            &tools.copy,
            ["-R", "--", oracle_source_text, oracle_text],
        )?;
        if let Some(stack_work) = &stack_work {
            trusted_tool_status(
                sudo,
                &tools.mkdir,
                [
                    "-m",
                    "0750",
                    "--",
                    path_text(stack_work, "candidate Stack work authority")?,
                ],
            )?;
        }
        trusted_tool_status(sudo, &tools.mkdir, ["-m", "3770", "--", transient_text])?;
        trusted_tool_status(
            sudo,
            &tools.mkdir,
            ["-m", "2770", "--", archive_adapter_text],
        )?;
        let trusted_owner_text = trusted_owner.to_string();
        trusted_tool_status(
            sudo,
            &tools.change_owner,
            [trusted_owner_text.as_str(), archive_adapter_text],
        )?;
        trusted_tool_status(
            sudo,
            &tools.change_group,
            [candidate_group, archive_adapter_text],
        )?;
        trusted_tool_status(
            sudo,
            &tools.chmod,
            posix_chmod_arguments(platform, "2770", archive_adapter_text)?,
        )?;
        trusted_tool_status(
            sudo,
            &tools.mkdir,
            ["-m", "0555", "--", retained_oracle_text],
        )?;
        for transition in POSIX_TRANSIENT_AUTHORITY_TRANSITIONS {
            match transition {
                PosixTransientAuthorityTransition::ChangeOwner => trusted_tool_status(
                    sudo,
                    &tools.change_owner,
                    [trusted_owner_text.as_str(), transient_text],
                )?,
                PosixTransientAuthorityTransition::ChangeGroup => trusted_tool_status(
                    sudo,
                    &tools.change_group,
                    [candidate_group, transient_text],
                )?,
                PosixTransientAuthorityTransition::RestoreMode03770 => trusted_tool_status(
                    sudo,
                    &tools.chmod,
                    posix_chmod_arguments(platform, "3770", transient_text)?,
                )?,
            }
        }
        if platform == ReleasePlatform::MacosAarch64 {
            for protected in [&candidate, &oracle] {
                trusted_tool_status(
                    sudo,
                    &tools.chmod,
                    posix_acl_removal_arguments(
                        platform,
                        true,
                        path_text(protected, "staged protected source")?,
                    )?,
                )?;
            }
        }
        for protected in [&candidate, &oracle] {
            trusted_tool_status(
                sudo,
                &tools.chmod,
                [
                    "-R",
                    "a+rX",
                    path_text(protected, "staged protected source")?,
                ],
            )?;
            trusted_tool_status(
                sudo,
                &tools.chmod,
                [
                    "-R",
                    "a-w",
                    path_text(protected, "staged protected source")?,
                ],
            )?;
        }
        if let Some(stack_work) = &stack_work {
            let candidate_uid = candidate_uid.to_string();
            let trusted_group_id = trusted_group_id.to_string();
            let stack_work_text = path_text(stack_work, "candidate Stack work authority")?;
            trusted_tool_status(
                sudo,
                &tools.change_owner,
                [candidate_uid.as_str(), stack_work_text],
            )?;
            trusted_tool_status(
                sudo,
                &tools.change_group,
                [trusted_group_id.as_str(), stack_work_text],
            )?;
            trusted_tool_status(
                sudo,
                &tools.chmod,
                posix_chmod_arguments(platform, "0750", stack_work_text)?,
            )?;
        }
        trusted_tool_status(
            sudo,
            &tools.chmod,
            posix_chmod_arguments(platform, "0555", directory_text)?,
        )?;
        // Reserve each transient path before delegation so the candidate cannot
        // substitute the cleanup or adapter authorities.
        if transient.parent() != Some(&directory)
            || archive_adapter.parent() != Some(&directory)
            || retained_oracle.parent() != Some(&directory)
            || target == transient
            || target == archive_adapter
            || target == retained_oracle
        {
            return Err("candidate transient source authority differs from policy".to_owned());
        }
        let protection = PosixSourceProtection {
            platform,
            installation_root: installation_root.clone(),
            installation_root_identity: installation_root_identity.clone(),
            directory: directory.clone(),
            directory_identity: posix_object_identity(&directory)?,
            candidate: candidate.clone(),
            oracle: oracle.clone(),
            stack_work: stack_work.clone(),
            stack_work_identity: stack_work
                .as_deref()
                .map(posix_object_identity)
                .transpose()?,
            stack_work_owner: candidate_uid,
            stack_work_group: trusted_group_id,
            candidate_uid,
            candidate_primary_gid,
            transient: transient.clone(),
            transient_identity: posix_object_identity(&transient)?,
            transient_owner: trusted_owner,
            transient_group: candidate_uid,
            candidate_environment: None,
            archive_adapter: archive_adapter.clone(),
            archive_adapter_identity: posix_object_identity(&archive_adapter)?,
            archive_adapter_owner: trusted_owner,
            archive_adapter_group: candidate_uid,
            retained_oracle: retained_oracle.clone(),
            retained_oracle_directory_identity: posix_object_identity(&retained_oracle)?,
            retained_oracle_file: None,
            candidate_inventory: candidate_inventory.clone(),
            oracle_inventory: oracle_inventory.clone(),
            candidate_sha: candidate_sha.to_owned(),
            sudo: sudo.to_path_buf(),
            tools: tools.clone(),
            active: true,
        };
        validate_posix_sources(&protection, "after POSIX source staging")?;
        Ok(protection)
    })();
    if result.is_err() {
        let _ = cleanup_posix_source_paths(
            platform,
            sudo,
            &tools,
            &installation_root,
            &installation_root_identity,
            &directory,
            &posix_object_identity(&directory).unwrap_or(reserved_directory_identity),
        );
    }
    result
}

#[cfg(unix)]
fn validate_posix_sources(
    protection: &PosixSourceProtection,
    checkpoint: &str,
) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    if !protection.active {
        return Err("POSIX source authority is no longer active".to_owned());
    }
    if validate_posix_adapter_installation_root(protection.platform, &protection.installation_root)?
        != protection.installation_root
        || posix_object_identity(&protection.installation_root)?
            != protection.installation_root_identity
        || !posix_source_cleanup_is_exact(
            &protection.installation_root,
            &protection.directory,
            &protection.candidate,
            &protection.oracle,
            &protection.transient,
            &protection.archive_adapter,
            &protection.retained_oracle,
        )
        || posix_object_identity(&protection.directory)? != protection.directory_identity
    {
        return Err("POSIX source authority identity changed".to_owned());
    }
    let metadata = fs::symlink_metadata(&protection.directory)
        .map_err(|error| format!("cannot inspect POSIX source authority: {error}"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.permissions().mode() & 0o7777 != 0o555
    {
        return Err("POSIX source authority permissions changed".to_owned());
    }
    require_exact_directory_members(
        &protection.directory,
        &[
            OsString::from("candidate"),
            OsString::from("oracle"),
            OsString::from("release-gate-transient"),
            OsString::from("archive-adapter"),
            OsString::from("retained-oracle"),
        ],
        "POSIX source authority",
    )?;
    let transient_metadata = fs::symlink_metadata(&protection.transient)
        .map_err(|error| format!("cannot inspect candidate transient authority: {error}"))?;
    if transient_metadata.file_type().is_symlink()
        || !transient_metadata.is_dir()
        || posix_object_identity(&protection.transient)? != protection.transient_identity
        || transient_metadata.uid() != protection.transient_owner
        || transient_metadata.gid() != protection.transient_group
        || transient_metadata.permissions().mode() & 0o7777 != 0o3770
    {
        return Err("candidate transient authority changed".to_owned());
    }
    if let Some(environment) = &protection.candidate_environment {
        validate_posix_candidate_environment(&protection.transient, environment, checkpoint)?;
    }
    let adapter_metadata = fs::symlink_metadata(&protection.archive_adapter)
        .map_err(|error| format!("cannot inspect native archive adapter authority: {error}"))?;
    if adapter_metadata.file_type().is_symlink()
        || !adapter_metadata.is_dir()
        || posix_object_identity(&protection.archive_adapter)?
            != protection.archive_adapter_identity
        || adapter_metadata.uid() != protection.archive_adapter_owner
        || adapter_metadata.gid() != protection.archive_adapter_group
        || adapter_metadata.permissions().mode() & 0o7777 != 0o2770
    {
        return Err("native archive adapter authority changed".to_owned());
    }
    require_exact_directory_members(
        &protection.archive_adapter,
        &[],
        "native archive adapter authority",
    )?;
    let stack_work_present = if let Some(stack_work) = &protection.stack_work {
        if stack_work != &protection.oracle.join(".stack-work") {
            return Err("candidate Stack work authority escapes staged oracle".to_owned());
        }
        match fs::symlink_metadata(stack_work) {
            Ok(metadata) => {
                let identity = protection.stack_work_identity.as_ref().ok_or_else(|| {
                    "candidate Stack work authority identity is absent".to_owned()
                })?;
                if metadata.file_type().is_symlink()
                    || !metadata.is_dir()
                    || posix_object_identity(stack_work)? != *identity
                    || metadata.uid() != protection.stack_work_owner
                    || metadata.gid() != protection.stack_work_group
                    || metadata.permissions().mode() & 0o7777 != 0o750
                    || fs::read_dir(stack_work)
                        .map_err(|error| {
                            format!("cannot enumerate candidate Stack work authority: {error}")
                        })?
                        .next()
                        .is_some()
                {
                    return Err("candidate Stack work authority changed before use".to_owned());
                }
                true
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => {
                return Err(format!(
                    "cannot inspect candidate Stack work authority: {error}"
                ));
            }
        }
    } else {
        if protection.stack_work_identity.is_some() {
            return Err("candidate Stack work authority identity is unexpected".to_owned());
        }
        false
    };
    require_clean_checkout(
        &protection.candidate,
        &protection.candidate_sha,
        "staged candidate",
    )?;
    if stack_work_present {
        if git_head(&protection.oracle)? != crate::command::PINNED_ORACLE_SOURCE_COMMIT {
            return Err("staged oracle checkout differs from its bound commit".to_owned());
        }
    } else {
        require_clean_checkout(
            &protection.oracle,
            crate::command::PINNED_ORACLE_SOURCE_COMMIT,
            "staged oracle",
        )?;
    }
    require_posix_read_only_tree(&protection.candidate, "staged candidate")?;
    require_posix_read_only_tree_except(
        &protection.oracle,
        protection.stack_work.as_deref(),
        "staged oracle",
    )?;
    require_inventory_snapshot(
        &protection.candidate,
        &protection.candidate_inventory,
        "staged candidate",
    )?;
    require_inventory_snapshot(
        &protection.oracle,
        &protection.oracle_inventory,
        "staged oracle",
    )?;
    validate_posix_retained_oracle(protection)
}

#[cfg(unix)]
fn validate_posix_retained_oracle(protection: &PosixSourceProtection) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let directory_metadata = fs::symlink_metadata(&protection.retained_oracle)
        .map_err(|error| format!("cannot inspect retained oracle authority: {error}"))?;
    if directory_metadata.file_type().is_symlink()
        || !directory_metadata.is_dir()
        || directory_metadata.uid() != 0
        || directory_metadata.gid() != 0
        || posix_object_identity(&protection.retained_oracle)?
            != protection.retained_oracle_directory_identity
    {
        return Err("retained oracle directory identity changed".to_owned());
    }
    match &protection.retained_oracle_file {
        None => {
            if directory_metadata.permissions().mode() & 0o7777 != 0o555 {
                return Err("reserved retained oracle authority permissions changed".to_owned());
            }
            require_exact_directory_members(
                &protection.retained_oracle,
                &[],
                "reserved retained oracle authority",
            )
        }
        Some(file) => {
            let expected_name = file
                .path
                .file_name()
                .expect("retained oracle has a file name")
                .to_os_string();
            if directory_metadata.permissions().mode() & 0o7777 != 0o555
                || file.path.parent() != Some(&protection.retained_oracle)
                || file.path.file_name()
                    != Some(std::ffi::OsStr::new(protection.platform.executable()))
            {
                return Err("sealed retained oracle authority differs from policy".to_owned());
            }
            require_exact_directory_members(
                &protection.retained_oracle,
                std::slice::from_ref(&expected_name),
                "sealed retained oracle authority",
            )?;
            let metadata = fs::symlink_metadata(&file.path)
                .map_err(|error| format!("cannot inspect retained oracle executable: {error}"))?;
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.nlink() != 1
                || metadata.uid() != 0
                || metadata.gid() != 0
                || metadata.permissions().mode() & 0o7777 != 0o555
                || fs::canonicalize(&file.path).ok().as_deref() != Some(file.path.as_path())
                || posix_object_identity(&file.path)? != file.identity
            {
                return Err("retained oracle executable identity changed".to_owned());
            }
            require_executable_digest(&file.path, file.sha256, "retained oracle")
        }
    }
}

#[cfg(unix)]
fn retained_oracle_source_identity(
    path: &Path,
    sha256: hell_testkit::Digest,
) -> Result<(PosixObjectIdentity, u64), String> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let canonical = fs::canonicalize(path)
        .map_err(|error| format!("cannot canonicalize retained oracle source: {error}"))?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect retained oracle source: {error}"))?;
    if canonical != path
        || metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err("retained oracle source is redirected, linked, or writable".to_owned());
    }
    require_executable_digest(path, sha256, "retained oracle source")?;
    Ok((posix_object_identity(path)?, metadata.len()))
}

#[cfg(unix)]
impl PosixSourceProtection {
    fn validate_candidate_environment(&self, checkpoint: &str) -> Result<(), String> {
        let environment = self.candidate_environment.as_ref().ok_or_else(|| {
            format!("candidate environment authority is absent: checkpoint={checkpoint:?}")
        })?;
        validate_posix_candidate_environment(&self.transient, environment, checkpoint)
    }

    fn retain_oracle_copy(
        &mut self,
        source: &UnretainedOracle,
    ) -> Result<hell_testkit::ExecutableIdentity, String> {
        validate_posix_sources(self, "before retained oracle copy")?;
        if self.retained_oracle_file.is_some() {
            return Err("retained oracle authority is already sealed".to_owned());
        }
        let source_identity = retained_oracle_source_identity(&source.path, source.sha256)?;
        let retained = self.retained_oracle.join(self.platform.executable());
        if retained.exists() {
            return Err("retained oracle executable already exists".to_owned());
        }
        let destination = path_text(&retained, "retained oracle executable")?;
        let result = (|| {
            trusted_tool_status(
                &self.sudo,
                &self.tools.copy,
                [
                    std::ffi::OsStr::new("--"),
                    source.path.as_os_str(),
                    retained.as_os_str(),
                ],
            )?;
            if self.platform == ReleasePlatform::MacosAarch64 {
                trusted_tool_status(
                    &self.sudo,
                    &self.tools.chmod,
                    posix_acl_removal_arguments(self.platform, false, destination)?,
                )?;
            }
            trusted_tool_status(
                &self.sudo,
                &self.tools.chmod,
                posix_chmod_arguments(self.platform, "0555", destination)?,
            )?;
            if retained_oracle_source_identity(&source.path, source.sha256)? != source_identity {
                return Err("retained oracle source identity changed during copy".to_owned());
            }
            let retained_identity = hell_testkit::verify_executable(
                &retained,
                hell_testkit::ExecutableRole::Oracle,
                Some(source.sha256),
                hell_builtins::LANGUAGE_VERSION,
            )
            .map_err(|error| format!("cannot verify retained oracle copy: {error}"))?;
            let retained_metadata = fs::symlink_metadata(&retained).map_err(|error| {
                format!("cannot inspect retained oracle executable after copy: {error}")
            })?;
            if retained_metadata.len() != source_identity.1 {
                return Err("retained oracle copy size differs from source".to_owned());
            }
            self.retained_oracle_file = Some(PosixRetainedOracleFile {
                path: retained.clone(),
                identity: posix_object_identity(&retained)?,
                sha256: source.sha256,
            });
            validate_posix_sources(self, "after retained oracle copy")?;
            Ok(retained_identity)
        })();
        match result {
            Ok(identity) => Ok(identity),
            Err(error) => {
                let cleanup = cleanup_posix_source_paths(
                    self.platform,
                    &self.sudo,
                    &self.tools,
                    &self.installation_root,
                    &self.installation_root_identity,
                    &self.directory,
                    &self.directory_identity,
                );
                if cleanup.is_ok() {
                    self.active = false;
                }
                match cleanup {
                    Ok(()) => Err(error),
                    Err(cleanup_error) => Err(format!(
                        "{error}; retained oracle cleanup also failed: {cleanup_error}"
                    )),
                }
            }
        }
    }
}

#[cfg(unix)]
fn require_posix_read_only_tree(root: &Path, label: &str) -> Result<(), String> {
    require_posix_read_only_tree_except_until(root, None, label, None)
}

#[cfg(unix)]
fn require_posix_read_only_tree_before(
    root: &Path,
    label: &str,
    deadline: Instant,
) -> Result<(), String> {
    require_posix_read_only_tree_except_until(root, None, label, Some(deadline))
}

#[cfg(unix)]
fn require_posix_read_only_tree_except(
    root: &Path,
    excluded: Option<&Path>,
    label: &str,
) -> Result<(), String> {
    require_posix_read_only_tree_except_until(root, excluded, label, None)
}

#[cfg(unix)]
fn require_posix_read_only_tree_except_until(
    root: &Path,
    excluded: Option<&Path>,
    label: &str,
    deadline: Option<Instant>,
) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Err(format!("{label} read-only attestation deadline expired"));
        }
        if excluded.is_some_and(|excluded| path == excluded) {
            continue;
        }
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot inspect {label} authority: {error}"))?;
        let mode = metadata.permissions().mode() & 0o7777;
        if metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || mode & 0o222 != 0
            || if metadata.is_dir() {
                mode & 0o555 != 0o555
            } else {
                !metadata.is_file() || mode & 0o444 != 0o444
            }
        {
            return Err(format!(
                "{label} authority contains a redirected, writable, unreadable, or non-root-owned entry"
            ));
        }
        if metadata.is_dir() {
            for entry in fs::read_dir(&path)
                .map_err(|error| format!("cannot enumerate {label} authority: {error}"))?
            {
                pending.push(
                    entry
                        .map_err(|error| format!("cannot read {label} authority entry: {error}"))?
                        .path(),
                );
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn construct_posix_candidate_environment(
    platform: ReleasePlatform,
    sudo: &Path,
    tools: &PosixAdapterTools,
    transient: &Path,
    trusted_owner: u32,
    candidate_group: u32,
) -> Result<PosixCandidateEnvironmentProtection, String> {
    let root = transient.join("release-child-environment");
    if root.exists() {
        return Err("candidate environment root already exists".to_owned());
    }
    let children = ["home", "cargo", "sccache", "tmp"].map(|name| root.join(name));
    trusted_tool_status(
        sudo,
        &tools.mkdir,
        [
            "-m",
            "0700",
            "--",
            path_text(&root, "candidate environment root")?,
        ],
    )
    .map_err(|error| format!("cannot reserve candidate environment root: {error}"))?;
    for child in &children {
        trusted_tool_status(
            sudo,
            &tools.mkdir,
            [
                "-m",
                "0700",
                "--",
                path_text(child, "candidate writable root")?,
            ],
        )
        .map_err(|error| format!("cannot reserve candidate writable root: {error}"))?;
    }

    let trusted_owner_text = trusted_owner.to_string();
    let candidate_group_text = candidate_group.to_string();
    for path in std::iter::once(&root).chain(children.iter()) {
        let path = path_text(path, "candidate environment authority")?;
        trusted_tool_status(
            sudo,
            &tools.change_owner,
            [trusted_owner_text.as_str(), path],
        )?;
        trusted_tool_status(
            sudo,
            &tools.change_group,
            [candidate_group_text.as_str(), path],
        )?;
    }
    if platform == ReleasePlatform::MacosAarch64 {
        trusted_tool_status(
            sudo,
            &tools.chmod,
            posix_acl_removal_arguments(
                platform,
                true,
                path_text(&root, "candidate environment root")?,
            )?,
        )?;
    }
    trusted_tool_status(
        sudo,
        &tools.chmod,
        posix_chmod_arguments(
            platform,
            "2750",
            path_text(&root, "candidate environment root")?,
        )?,
    )?;
    for child in &children {
        trusted_tool_status(
            sudo,
            &tools.chmod,
            posix_chmod_arguments(
                platform,
                "2770",
                path_text(child, "candidate writable root")?,
            )?,
        )?;
    }
    crate::command::require_native_acl_free(
        std::iter::once(root.as_path()).chain(children.iter().map(PathBuf::as_path)),
        "candidate environment authority",
    )?;
    capture_posix_candidate_environment(transient, &root, trusted_owner, candidate_group)
}

#[cfg(unix)]
fn capture_posix_candidate_environment(
    transient: &Path,
    root: &Path,
    owner: u32,
    group: u32,
) -> Result<PosixCandidateEnvironmentProtection, String> {
    if root.parent() != Some(transient)
        || root.file_name() != Some(OsStr::new("release-child-environment"))
    {
        return Err("candidate environment root is outside its transient authority".to_owned());
    }
    let root = hell_testkit::PosixDirectoryCheckpoint::capture(
        root,
        owner,
        group,
        0o2750,
        "candidate environment capture",
    )?;
    let children = ["home", "cargo", "sccache", "tmp"]
        .into_iter()
        .map(|name| {
            hell_testkit::PosixDirectoryCheckpoint::capture(
                &root.path().join(name),
                owner,
                group,
                0o2770,
                "candidate environment capture",
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let protection = PosixCandidateEnvironmentProtection { root, children };
    validate_posix_candidate_environment(transient, &protection, "candidate environment capture")?;
    Ok(protection)
}

#[cfg(unix)]
pub(crate) fn verify_posix_candidate_environment_construction_for_integration() -> Result<(), String>
{
    use std::os::unix::fs::{MetadataExt as _, symlink};

    #[cfg(target_os = "linux")]
    let platform = ReleasePlatform::LinuxX86_64;
    #[cfg(target_os = "macos")]
    let platform = ReleasePlatform::MacosAarch64;
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    return Err("POSIX candidate environment verifier requires Linux or macOS".to_owned());

    let sudo = crate::command::resolve_absolute_standard_executable(Path::new("/usr/bin/sudo"))
        .map_err(|error| format!("cannot bind candidate environment verifier sudo: {error}"))?
        .invocation_path()
        .to_path_buf();
    let tools = resolve_posix_adapter_tools(platform)?;
    let temporary_root = fs::canonicalize(env::temp_dir())
        .map_err(|error| format!("cannot canonicalize candidate verifier temp root: {error}"))?;
    let mut fixture = None;
    for _ in 0..16 {
        let sequence =
            POSIX_CANDIDATE_ENVIRONMENT_VERIFIER_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = temporary_root.join(format!(
            "hell-candidate-environment-verifier-{}-{sequence}",
            std::process::id()
        ));
        match fs::create_dir(&path) {
            Ok(()) => {
                fixture = Some(path);
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(format!(
                    "cannot create candidate environment verifier root: {error}"
                ));
            }
        }
    }
    let fixture =
        fixture.ok_or_else(|| "cannot allocate candidate environment verifier root".to_owned())?;
    let transient = fixture.join("transient");
    fs::create_dir(&transient)
        .map_err(|error| format!("cannot create candidate verifier transient root: {error}"))?;
    let metadata = fs::symlink_metadata(&transient)
        .map_err(|error| format!("cannot inspect candidate verifier transient root: {error}"))?;
    let trusted_owner = metadata.uid();
    let trusted_group = metadata.gid();
    let candidate_group = trusted_group
        .checked_add(1)
        .unwrap_or_else(|| trusted_group.saturating_sub(1));

    let result = (|| {
        if platform == ReleasePlatform::MacosAarch64 {
            trusted_tool_status(
                &sudo,
                &tools.chmod,
                [
                    "+a",
                    "everyone allow write,file_inherit,directory_inherit",
                    path_text(&transient, "candidate verifier transient root")?,
                ],
            )?;
        }
        let protection = construct_posix_candidate_environment(
            platform,
            &sudo,
            &tools,
            &transient,
            trusted_owner,
            candidate_group,
        )?;
        validate_posix_candidate_environment(
            &transient,
            &protection,
            "external privileged construction verification",
        )?;

        let sandbox = protection.root.path().join("tmp/construction-probe");
        fs::create_dir(&sandbox)
            .map_err(|error| format!("cannot create candidate sandbox verifier: {error}"))?;
        hell_testkit::prepare_posix_writable_directory_for_integration(
            &sudo,
            candidate_group,
            &transient,
            &sandbox,
        )
        .map_err(|error| format!("candidate sandbox construction failed: {error}"))?;

        let redirect_target = protection.root.path().join("tmp/redirect-target");
        let redirect = protection.root.path().join("tmp/redirect");
        fs::create_dir(&redirect_target)
            .map_err(|error| format!("cannot create candidate redirect target: {error}"))?;
        symlink(&redirect_target, &redirect)
            .map_err(|error| format!("cannot create candidate redirect probe: {error}"))?;
        if hell_testkit::prepare_posix_writable_directory_for_integration(
            &sudo,
            candidate_group,
            &transient,
            &redirect,
        )
        .is_ok()
        {
            return Err("redirected candidate writable directory was accepted".to_owned());
        }
        Ok(())
    })();
    if platform == ReleasePlatform::MacosAarch64 {
        let _ = trusted_tool_status(
            &sudo,
            &tools.chmod,
            posix_acl_removal_arguments(
                platform,
                true,
                path_text(&fixture, "candidate verifier cleanup root")?,
            )?,
        );
    }
    let cleanup = fs::remove_dir_all(&fixture)
        .map_err(|error| format!("cannot remove candidate environment verifier: {error}"));
    result.and(cleanup)
}

#[cfg(unix)]
fn combine_candidate_target_verifier_results(
    primary: Result<(), String>,
    lifecycle_cleanup: Result<(), String>,
    transient_absence: Result<(), String>,
    fixture_cleanup: Result<(), String>,
) -> Result<(), String> {
    let mut errors = Vec::new();
    for (label, result) in [
        ("candidate target verifier", primary),
        (
            "candidate target verifier lifecycle cleanup",
            lifecycle_cleanup,
        ),
        (
            "candidate target verifier transient absence",
            transient_absence,
        ),
        ("candidate target verifier fixture cleanup", fixture_cleanup),
    ] {
        if let Err(error) = result {
            errors.push(format!("{label}: {error}"));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

#[cfg(unix)]
pub(crate) fn verify_posix_candidate_target_authority_for_integration() -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    #[cfg(target_os = "linux")]
    let platform = ReleasePlatform::LinuxX86_64;
    #[cfg(target_os = "macos")]
    let platform = ReleasePlatform::MacosAarch64;
    let process_authorities = ResolvedPosixProcessAuthorities::resolve()?;
    let sudo = process_authorities.sudo.invocation_path().to_path_buf();
    let current_exe = std::env::current_exe()
        .map_err(|error| format!("cannot resolve candidate target verifier adapter: {error}"))?;
    let adapter = stage_posix_executable(platform, &sudo, &current_exe, "hell-ci")?;
    let temporary_root = fs::canonicalize(env::temp_dir())
        .map_err(|error| format!("cannot canonicalize candidate target verifier root: {error}"))?;
    let sequence = POSIX_CANDIDATE_ENVIRONMENT_VERIFIER_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let fixture = temporary_root.join(format!(
        "hell-candidate-target-verifier-{}-{sequence}",
        std::process::id()
    ));
    let transient = posix_adapter_installation_root(platform)?.join(format!(
        "hell-candidate-target-verifier-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir(&fixture)
        .map_err(|error| format!("cannot create candidate target verifier fixture: {error}"))?;
    fs::create_dir(&transient).map_err(|error| {
        format!("cannot create /var/tmp candidate target verifier authority: {error}")
    })?;
    let transient_cleanup = PosixVerifierTransientCleanup::bind(platform, &transient, &adapter)?;
    let mut principal_cleanup = None;
    let result = (|| {
        let workspace = fixture.join("hosted-workspace");
        let workspace_target = workspace.join("candidate-target");
        fs::create_dir(&workspace)
            .map_err(|error| format!("cannot create hosted target verifier workspace: {error}"))?;
        fs::create_dir(&workspace_target)
            .map_err(|error| format!("cannot create hosted target verifier cache: {error}"))?;
        fs::create_dir(workspace_target.join("seed"))
            .map_err(|error| format!("cannot create target verifier seed: {error}"))?;
        fs::write(workspace_target.join("seed/input"), b"trusted-cache-seed\n")
            .map_err(|error| format!("cannot write target verifier seed: {error}"))?;
        fs::hard_link(
            workspace_target.join("seed/input"),
            workspace_target.join("seed/alias"),
        )
        .map_err(|error| format!("cannot create in-tree target verifier hard link: {error}"))?;
        let external_source = fixture.join("external-hardlink-source");
        let external_probe = fixture.join("external-hardlink-probe");
        fs::write(&external_source, b"external-cache-alias\n")
            .map_err(|error| format!("cannot write external hard-link source: {error}"))?;
        fs::create_dir(&external_probe)
            .map_err(|error| format!("cannot create external hard-link probe: {error}"))?;
        fs::hard_link(&external_source, external_probe.join("member"))
            .map_err(|error| format!("cannot create external hard-link probe: {error}"))?;
        let external_error = posix_candidate_target_receipt(&external_probe)
            .expect_err("an out-of-tree hard link must be rejected before candidate execution");
        if external_error != "candidate target contains a hard link outside its authority"
            || fs::read(&external_source)
                .map_err(|error| format!("cannot reread external hard-link source: {error}"))?
                != b"external-cache-alias\n"
        {
            return Err("candidate target external hard-link rejection was not exact".to_owned());
        }
        fs::remove_dir_all(&external_probe)
            .map_err(|error| format!("cannot remove external hard-link probe: {error}"))?;
        fs::remove_file(&external_source)
            .map_err(|error| format!("cannot remove external hard-link source: {error}"))?;
        let metadata = fs::symlink_metadata(&workspace_target)
            .map_err(|error| format!("cannot inspect target verifier cache: {error}"))?;
        let trusted_owner = metadata.uid();
        let trusted_group = metadata.gid();
        let id = &process_authorities.identity;
        let (principal, group, candidate_uid, candidate_gid) = match platform {
            ReleasePlatform::LinuxX86_64 => {
                let (principal, group, id, cleanup) = allocate_linux_candidate_principal(
                    Arc::clone(&process_authorities),
                    "helltgt",
                )?;
                principal_cleanup = Some(cleanup);
                principal_cleanup
                    .as_mut()
                    .expect("candidate cleanup was retained")
                    .attach_verifier_transient(transient_cleanup.clone())?;
                (principal, group, id, id)
            }
            ReleasePlatform::MacosAarch64 => {
                let principal = format!("helltgt{}x{sequence}", std::process::id());
                let group = principal.clone();
                let candidate_id = 590_u32
                    .checked_add(std::process::id() % 40)
                    .ok_or_else(|| "candidate target verifier UID overflow".to_owned())?;
                let candidate_id_text = candidate_id.to_string();
                let mut cleanup = PosixPrincipalCleanup::new(
                    platform,
                    Arc::clone(&process_authorities),
                    principal.clone(),
                    group.clone(),
                    Some(candidate_id),
                    Some(candidate_id),
                )?;
                cleanup.attach_verifier_transient(transient_cleanup.clone())?;
                principal_cleanup = Some(cleanup);
                let cleanup = principal_cleanup
                    .as_mut()
                    .expect("candidate cleanup was retained");
                let reservation_deadline =
                    posix_identity_query_deadline("macOS verifier candidate reservation")?;
                if posix_principal_uid(reservation_deadline, platform, &principal)?.is_some()
                    || posix_group_gid(reservation_deadline, &group)?.is_some()
                {
                    return Err(
                        "macOS candidate verifier principal or group name is already occupied"
                            .to_owned(),
                    );
                }
                macos_principal_mutation(
                    cleanup,
                    [
                        "-n",
                        "--",
                        "/usr/sbin/dseditgroup",
                        "-o",
                        "create",
                        "-i",
                        &candidate_id_text,
                        &group,
                    ],
                )?;
                if !cleanup.group_created {
                    return Err(
                        "macOS candidate verifier group creation had no observable effect"
                            .to_owned(),
                    );
                }
                for (property, value) in [
                    ("UniqueID", candidate_id_text.as_str()),
                    ("PrimaryGroupID", candidate_id_text.as_str()),
                    ("UserShell", "/usr/bin/false"),
                    ("NFSHomeDirectory", "/var/empty"),
                ] {
                    let record = Path::new("/Users").join(&principal);
                    macos_principal_mutation(
                        cleanup,
                        [
                            "-n",
                            "--",
                            "/usr/bin/dscl",
                            ".",
                            "-create",
                            record.to_str().ok_or_else(|| {
                                "candidate target verifier account path is not UTF-8".to_owned()
                            })?,
                            property,
                            value,
                        ],
                    )?;
                }
                if !cleanup.user_created {
                    return Err(
                        "macOS candidate verifier user creation had no observable effect"
                            .to_owned(),
                    );
                }
                (principal, group, candidate_id, candidate_id)
            }
            ReleasePlatform::WindowsX86_64 => unreachable!(),
        };
        require_exact_posix_candidate_identity(id, "-u", &principal, candidate_uid, "UID")?;
        require_exact_posix_candidate_identity(id, "-g", &principal, candidate_gid, "primary GID")?;
        let group_output = exact_posix_candidate_identity_output(
            id,
            "-G",
            &principal,
            "candidate target verifier complete group inventory",
        )?;
        let candidate_group_ids = posix_candidate_group_inventory(&group_output, candidate_gid)
            .ok_or_else(|| {
                "candidate target verifier group inventory is not canonical".to_owned()
            })?;
        if candidate_group_ids.contains(&trusted_group) {
            return Err(
                "candidate target verifier unexpectedly belongs to the trusted runner group"
                    .to_owned(),
            );
        }
        let mut protection = stage_posix_candidate_target(
            &sudo,
            &adapter,
            &workspace_target,
            &transient,
            trusted_owner,
            trusted_group,
            candidate_gid,
        )?;
        if protection.path() != transient.join("candidate-target")
            || protection.path().starts_with(&workspace)
            || fs::read(protection.path().join("seed/input"))
                .map_err(|error| format!("cannot read staged target verifier seed: {error}"))?
                != b"trusted-cache-seed\n"
        {
            return Err(
                "candidate target import did not establish the separate staged authority"
                    .to_owned(),
            );
        }
        let staged_input = fs::symlink_metadata(protection.path().join("seed/input"))
            .map_err(|error| format!("cannot inspect staged target verifier seed: {error}"))?;
        let staged_alias = fs::symlink_metadata(protection.path().join("seed/alias"))
            .map_err(|error| format!("cannot inspect staged target verifier alias: {error}"))?;
        if staged_input.nlink() != 1
            || staged_alias.nlink() != 1
            || (staged_input.dev(), staged_input.ino()) == (staged_alias.dev(), staged_alias.ino())
            || fs::read(protection.path().join("seed/alias"))
                .map_err(|error| format!("cannot read staged target verifier alias: {error}"))?
                != b"trusted-cache-seed\n"
        {
            return Err("candidate target import retained an in-tree hard-link alias".to_owned());
        }
        fs::set_permissions(&workspace, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("cannot confine hosted target verifier ancestry: {error}"))?;
        let project = transient.join("candidate-project");
        fs::create_dir(&project)
            .map_err(|error| format!("cannot create candidate target verifier project: {error}"))?;
        fs::write(
            project.join("Cargo.toml"),
            b"[package]\nname = \"posix-target-probe\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[[bin]]\nname = \"posix-target-probe\"\npath = \"main.rs\"\n",
        )
        .map_err(|error| format!("cannot write candidate target verifier manifest: {error}"))?;
        fs::write(
            project.join("Cargo.lock"),
            b"# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\nversion = 4\n\n[[package]]\nname = \"posix-target-probe\"\nversion = \"0.0.0\"\n",
        )
        .map_err(|error| format!("cannot write candidate target verifier lockfile: {error}"))?;
        fs::write(
            project.join("main.rs"),
            b"use std::{env, ffi::OsStr, fs, io::ErrorKind, os::unix::fs::PermissionsExt, path::Path};\nfn main() {\n    let mut args = env::args_os().skip(1);\n    let staged = args.next().expect(\"staged target\");\n    let hosted = args.next().expect(\"hosted target\");\n    let mode = args.next();\n    assert!(args.next().is_none());\n    assert_eq!(env::var_os(\"CARGO_TARGET_DIR\").as_deref(), Some(staged.as_os_str()));\n    let staged = Path::new(&staged);\n    if mode.as_deref() == Some(OsStr::new(\"cleanup-hostile\")) {\n        let hostile = staged.join(\"cleanup-hostile\");\n        fs::create_dir_all(hostile.join(\"nested\")).unwrap();\n        fs::write(hostile.join(\"nested/retained\"), b\"candidate-owned\\n\").unwrap();\n        fs::set_permissions(hostile.join(\"nested/retained\"), fs::Permissions::from_mode(0o400)).unwrap();\n        fs::set_permissions(hostile.join(\"nested\"), fs::Permissions::from_mode(0o500)).unwrap();\n        fs::set_permissions(&hostile, fs::Permissions::from_mode(0o500)).unwrap();\n        return;\n    }\n    assert!(mode.is_none());\n    assert!(matches!(fs::symlink_metadata(&hosted), Err(error) if error.kind() == ErrorKind::PermissionDenied));\n    let direct = Path::new(&hosted).join(\"candidate-direct-write\");\n    assert!(matches!(fs::OpenOptions::new().write(true).create_new(true).open(direct), Err(error) if error.kind() == ErrorKind::PermissionDenied));\n    fs::create_dir_all(staged.join(\"cache\")).unwrap();\n    fs::create_dir_all(staged.join(\"evidence\")).unwrap();\n    fs::write(staged.join(\"cache/compiler-state\"), b\"candidate-cache\\n\").unwrap();\n    fs::write(staged.join(\"evidence/hosted-target-inaccessible\"), b\"permission-denied\\n\").unwrap();\n}\n",
        )
        .map_err(|error| format!("cannot write candidate target verifier source: {error}"))?;

        let cargo = crate::command::resolve_standard_cargo_executable()?;
        let cargo_authority = crate::command::resolve_posix_cargo_authority(&cargo, &project)?;
        let rustup_authority = match &cargo_authority {
            crate::command::ResolvedPosixCargoAuthority::Native { .. } => {
                return reject_native_posix_cargo_authority();
            }
            crate::command::ResolvedPosixCargoAuthority::Rustup(authority) => Some(authority),
        };
        let rustup_protection = rustup_authority
            .map(|authority| stage_posix_rustup_authority(platform, &sudo, authority))
            .transpose()?;
        let cargo_protection =
            stage_posix_executable(platform, &sudo, cargo.canonical_identity(), "cargo")?;
        let candidate_identity = hell_testkit::PosixCandidateIdentity::new(
            principal.clone(),
            candidate_uid,
            candidate_gid,
            candidate_group_ids,
            group,
        )
        .map_err(|error| format!("cannot bind candidate target verifier identity: {error}"))?;
        let launch_authorities = hell_testkit::PosixLaunchAuthorities::new(
            adapter.adapter.clone(),
            adapter.sha256,
            cargo.canonical_identity().to_path_buf(),
            cargo_protection.adapter.clone(),
            cargo_protection.sha256,
            posix_cargo_source_authority(&cargo_authority, rustup_protection.as_ref())?,
        );
        let policy = hell_testkit::CandidateLaunchPolicy::posix_with_process_authorities(
            sudo.clone(),
            process_authorities.launch_authorities()?,
            launch_authorities,
            candidate_identity,
            vec![protection.path().to_path_buf()],
        )
        .map_err(|error| format!("cannot establish candidate target verifier policy: {error}"))?;
        let isolated = protection.path().join("release-child-environment");
        fs::create_dir(&isolated).map_err(|error| {
            format!("cannot create candidate target verifier environment: {error}")
        })?;
        for directory in ["home", "cargo", "sccache", "tmp"] {
            let path = isolated.join(directory);
            fs::create_dir(&path).map_err(|error| {
                format!("cannot create candidate target verifier {directory}: {error}")
            })?;
            hell_testkit::prepare_posix_writable_directory_for_integration(
                &sudo,
                candidate_gid,
                protection.path(),
                &path,
            )
            .map_err(|error| {
                format!("cannot delegate candidate target verifier {directory}: {error}")
            })?;
        }
        #[cfg(target_os = "macos")]
        {
            use std::io::Read as _;
            use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
            use std::os::unix::net::UnixListener;

            let broker_adapter = fixture.join("derived-native-archive-broker");
            let broker_authority = broker_adapter.join(".authority");
            let broker_inputs = broker_authority.join("inputs");
            fs::create_dir(&broker_adapter)
                .and_then(|()| fs::create_dir(&broker_authority))
                .and_then(|()| fs::create_dir(&broker_inputs))
                .map_err(|error| format!("cannot create derived broker fixture: {error}"))?;
            fs::set_permissions(&broker_adapter, fs::Permissions::from_mode(0o2755))
                .and_then(|()| {
                    fs::set_permissions(&broker_authority, fs::Permissions::from_mode(0o555))
                })
                .map_err(|error| format!("cannot seal derived broker fixture: {error}"))?;
            let candidate_group = candidate_gid.to_string();
            trusted_tool_status(
                &sudo,
                &adapter.tools.change_group,
                [
                    candidate_group.as_str(),
                    path_text(&broker_inputs, "derived broker input staging")?,
                ],
            )?;
            fs::set_permissions(&broker_inputs, fs::Permissions::from_mode(0o2710))
                .map_err(|error| format!("cannot confine derived broker fixture: {error}"))?;
            let fake_root = fs::canonicalize("/tmp")
                .map_err(|error| format!("cannot bind fake broker parent: {error}"))?
                .join(format!(
                    "hell-ci-fake-archive-broker-{}-{sequence}",
                    std::process::id()
                ));
            fs::create_dir(&fake_root)
                .map_err(|error| format!("cannot create fake broker fixture: {error}"))?;
            fs::set_permissions(&fake_root, fs::Permissions::from_mode(0o711))
                .map_err(|error| format!("cannot confine fake broker fixture: {error}"))?;
            let fake_socket = fake_root.join("s");
            let fake_listener = UnixListener::bind(&fake_socket)
                .map_err(|error| format!("cannot bind fake broker fixture: {error}"))?;
            fs::set_permissions(&fake_socket, fs::Permissions::from_mode(0o622))
                .map_err(|error| format!("cannot delegate fake broker fixture: {error}"))?;
            let fake_root_metadata = fs::symlink_metadata(&fake_root)
                .map_err(|error| format!("cannot bind fake broker root receipt: {error}"))?;
            let fake_socket_metadata = fs::symlink_metadata(&fake_socket)
                .map_err(|error| format!("cannot bind fake broker socket receipt: {error}"))?;
            let trusted_fixture_metadata = fs::metadata(&fixture)
                .map_err(|error| format!("cannot bind trusted fixture owner: {error}"))?;
            if fake_root_metadata.file_type().is_symlink()
                || !fake_root_metadata.is_dir()
                || fake_root_metadata.uid() != trusted_fixture_metadata.uid()
                || fake_root_metadata.permissions().mode() & 0o7777 != 0o711
                || !fake_socket_metadata.file_type().is_socket()
                || fake_socket_metadata.uid() != fake_root_metadata.uid()
                || fake_socket_metadata.permissions().mode() & 0o7777 != 0o622
            {
                return Err("fake broker candidate-connectability receipt differs".to_owned());
            }
            let broker_deadline = Instant::now()
                .checked_add(Duration::from_secs(30))
                .ok_or_else(|| "derived broker cleanup deadline overflowed".to_owned())?;
            let mut derived_broker =
                match crate::command::NativeArchiveInputBroker::start_for_integration(
                    &broker_inputs,
                    candidate_uid,
                    4,
                    64,
                ) {
                    Ok(broker) => broker,
                    Err(primary) => {
                        drop(fake_listener);
                        let cleanup = fs::remove_file(&fake_socket)
                            .and_then(|()| fs::remove_dir(&fake_root))
                            .map_err(|error| {
                                format!("cannot clean failed fake broker fixture: {error}")
                            });
                        return match cleanup {
                            Ok(()) => Err(primary),
                            Err(cleanup) => Err(format!("{primary}; {cleanup}")),
                        };
                    }
                };
            let descendant = with_release_candidate_environment(
                protection.path(),
                &isolated,
                1,
                &policy,
                || {
                    CommandSpec::new(adapter.adapter.as_os_str(), Duration::from_secs(30))
                        .argument("__verify-native-archive-broker-descendant-launcher")
                        .argument(&broker_adapter)
                        .argument(&fake_socket)
                        .argument(isolated.join("tmp"))
                        .current_directory(&project)
                        .run()
                },
            )
            .map_err(|error| format!("cannot run restricted broker descendant: {error}"));
            let descendant = descendant.and_then(|result| {
                if result.status.success() && !result.timed_out {
                    Ok(())
                } else {
                    Err(format!(
                        "restricted broker descendant failed: status={:?}; stderr={}",
                        result.status.code(),
                        String::from_utf8_lossy(&result.stderr)
                    ))
                }
            });
            let fake_observation = (|| {
                fake_listener
                    .set_nonblocking(true)
                    .map_err(|error| format!("cannot bound fake broker observation: {error}"))?;
                let (mut control, _) = fake_listener.accept().map_err(|error| {
                    format!("candidate did not prove fake broker connectability: {error}")
                })?;
                control
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .map_err(|error| format!("cannot bound fake broker marker: {error}"))?;
                let mut marker =
                    [0_u8; crate::command::NATIVE_ARCHIVE_FAKE_BROKER_CONNECTIVITY_MARKER.len()];
                control
                    .read_exact(&mut marker)
                    .map_err(|error| format!("cannot read fake broker marker: {error}"))?;
                if marker != *crate::command::NATIVE_ARCHIVE_FAKE_BROKER_CONNECTIVITY_MARKER {
                    return Err("candidate fake broker connectivity marker differs".to_owned());
                }
                match fake_listener.accept() {
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(()),
                    Ok(_) => Err(
                        "sealed-capability adapter connected to the typed decoy broker".to_owned(),
                    ),
                    Err(error) => Err(format!("cannot observe fake broker endpoint: {error}")),
                }
            })();
            drop(fake_listener);
            let broker_cleanup = derived_broker.close_until(broker_deadline);
            let fake_cleanup = fs::remove_file(&fake_socket)
                .and_then(|()| fs::remove_dir(&fake_root))
                .map_err(|error| format!("cannot clean fake broker fixture: {error}"));
            let mut failures = Vec::new();
            if let Err(error) = descendant {
                failures.push(error);
            }
            if let Err(error) = fake_observation {
                failures.push(error);
            }
            if let Err(error) = broker_cleanup {
                failures.push(format!("derived broker cleanup: {error}"));
            } else if fs::read_dir(&broker_inputs)
                .map_err(|error| format!("cannot attest derived broker cleanup: {error}"))?
                .next()
                .is_some()
            {
                failures.push("derived broker staging remains after cleanup".to_owned());
            }
            if let Err(error) = fake_cleanup {
                failures.push(error);
            }
            if !failures.is_empty() {
                return Err(failures.join("; "));
            }
        }
        let rustup_protection = rustup_protection.as_ref().ok_or_else(|| {
            "candidate target verifier staged Rustup authority is absent".to_owned()
        })?;
        preflight_exact_staged_rustc_as_candidate(
            protection.path(),
            &isolated,
            &policy,
            &project,
            rustup_protection,
        )?;
        let build =
            with_release_candidate_environment(protection.path(), &isolated, 1, &policy, || {
                CommandSpec::trusted_cargo(Duration::from_mins(5), &cargo)
                    .arguments(["build", "--release", "--locked", "--offline"])
                    .current_directory(&project)
                    .run()
            })
            .map_err(|error| format!("cannot run restricted candidate Cargo build: {error}"))?;
        if !build.status.success() || build.timed_out {
            return Err(format!(
                "restricted candidate Cargo build failed: status={:?}; stderr={}",
                build.status.code(),
                String::from_utf8_lossy(&build.stderr)
            ));
        }
        let artifact = protection.path().join("release/posix-target-probe");
        let artifact_metadata = fs::symlink_metadata(&artifact)
            .map_err(|error| format!("cannot inspect candidate Cargo artifact: {error}"))?;
        if !artifact_metadata.is_file()
            || artifact_metadata.file_type().is_symlink()
            || artifact_metadata.uid() != candidate_uid
            || project.join("target").exists()
        {
            return Err("candidate Cargo output differs from its staged authority".to_owned());
        }
        let probe =
            with_release_candidate_environment(protection.path(), &isolated, 1, &policy, || {
                CommandSpec::new(artifact.as_os_str(), Duration::from_secs(30))
                    .argument(protection.path())
                    .argument(&workspace_target)
                    .current_directory(&project)
                    .run()
            })
            .map_err(|error| format!("cannot run restricted candidate target artifact: {error}"))?;
        if !probe.status.success() || probe.timed_out {
            return Err(format!(
                "restricted candidate target artifact failed: status={:?}; stderr={}",
                probe.status.code(),
                String::from_utf8_lossy(&probe.stderr)
            ));
        }
        if workspace_target.join("candidate-direct-write").exists() {
            return Err("candidate reached the hosted target through confined ancestry".to_owned());
        }
        let hosted_identity_before_export = posix_object_identity(&workspace_target)?;
        let hosted_input_before_export = fs::symlink_metadata(workspace_target.join("seed/input"))
            .map_err(|error| format!("cannot inspect hosted cache seed before export: {error}"))?;
        let hosted_alias_before_export = fs::symlink_metadata(workspace_target.join("seed/alias"))
            .map_err(|error| format!("cannot inspect hosted cache alias before export: {error}"))?;
        if hosted_input_before_export.nlink() != 2
            || (
                hosted_input_before_export.dev(),
                hosted_input_before_export.ino(),
            ) != (
                hosted_alias_before_export.dev(),
                hosted_alias_before_export.ino(),
            )
        {
            return Err(
                "hosted target verifier hard-link fixture changed before export".to_owned(),
            );
        }
        let mut export_receipt = PosixCandidateTargetExportReceipt::default();
        let injected = export_posix_candidate_target_with_fault(
            &adapter,
            &mut protection,
            &workspace_target,
            PosixCandidateTargetExportFault::AfterBackupRename,
            &mut export_receipt,
        );
        if export_receipt.phase != PosixCandidateTargetExportPhase::InjectedRollbackComplete {
            return Err(format!(
                "candidate target export fault hook was not reached: phase={:?}; result={injected:?}",
                export_receipt.phase
            ));
        }
        if !matches!(injected, Err(ref error) if error == "injected candidate target export failure after backup rename")
        {
            return Err("candidate target export fault result was not exact".to_owned());
        }
        let hosted_input_after_rollback = fs::symlink_metadata(workspace_target.join("seed/input"))
            .map_err(|error| format!("cannot inspect hosted cache seed after rollback: {error}"))?;
        let hosted_alias_after_rollback = fs::symlink_metadata(workspace_target.join("seed/alias"))
            .map_err(|error| {
                format!("cannot inspect hosted cache alias after rollback: {error}")
            })?;
        if posix_object_identity(&workspace_target)? != hosted_identity_before_export
            || (
                hosted_input_after_rollback.dev(),
                hosted_input_after_rollback.ino(),
            ) != (
                hosted_input_before_export.dev(),
                hosted_input_before_export.ino(),
            )
            || (
                hosted_alias_after_rollback.dev(),
                hosted_alias_after_rollback.ino(),
            ) != (
                hosted_alias_before_export.dev(),
                hosted_alias_before_export.ino(),
            )
            || fs::read(workspace_target.join("seed/input")).map_err(|error| {
                format!("cannot reread hosted cache after injected export failure: {error}")
            })? != b"trusted-cache-seed\n"
            || workspace_target.join("release/posix-target-probe").exists()
            || workspace_target.join("cache/compiler-state").exists()
            || workspace_target
                .with_file_name(format!(
                    "candidate-target-export-replacement-{}",
                    std::process::id()
                ))
                .exists()
            || workspace_target
                .with_file_name(format!(
                    "candidate-target-export-backup-{}",
                    std::process::id()
                ))
                .exists()
        {
            return Err(
                "candidate target export failure did not retain the exact old hosted cache"
                    .to_owned(),
            );
        }
        export_posix_candidate_target(&adapter, &mut protection, &workspace_target)?;
        let exported_artifact = fs::symlink_metadata(
            workspace_target.join("release/posix-target-probe"),
        )
        .map_err(|error| format!("cannot inspect hosted target verifier artifact: {error}"))?;
        if !exported_artifact.is_file()
            || exported_artifact.file_type().is_symlink()
            || fs::read(workspace_target.join("cache/compiler-state"))
                .map_err(|error| format!("cannot read hosted target verifier cache: {error}"))?
                != b"candidate-cache\n"
            || fs::read(workspace_target.join("evidence/hosted-target-inaccessible"))
                .map_err(|error| format!("cannot read hosted target verifier evidence: {error}"))?
                != b"permission-denied\n"
            || fs::read(workspace_target.join("seed/input"))
                .map_err(|error| format!("cannot reread hosted target verifier seed: {error}"))?
                != b"trusted-cache-seed\n"
            || fs::read(workspace_target.join("seed/alias"))
                .map_err(|error| format!("cannot reread hosted target verifier alias: {error}"))?
                != b"trusted-cache-seed\n"
        {
            return Err("candidate target trusted export differs from staged output".to_owned());
        }
        let exported_input = fs::symlink_metadata(workspace_target.join("seed/input"))
            .map_err(|error| format!("cannot inspect exported target verifier seed: {error}"))?;
        let exported_alias = fs::symlink_metadata(workspace_target.join("seed/alias"))
            .map_err(|error| format!("cannot inspect exported target verifier alias: {error}"))?;
        if exported_input.nlink() != 1
            || exported_alias.nlink() != 1
            || (exported_input.dev(), exported_input.ino())
                == (exported_alias.dev(), exported_alias.ino())
        {
            return Err("candidate target export retained an in-tree hard-link alias".to_owned());
        }
        let cleanup_probe =
            with_release_candidate_environment(protection.path(), &isolated, 1, &policy, || {
                CommandSpec::new(artifact.as_os_str(), Duration::from_secs(30))
                    .argument(protection.path())
                    .argument(&workspace_target)
                    .argument("cleanup-hostile")
                    .current_directory(&project)
                    .run()
            })
            .map_err(|error| {
                format!("cannot create candidate-owned target cleanup fixture: {error}")
            })?;
        let hostile = protection.path().join("cleanup-hostile");
        let hostile_metadata = fs::symlink_metadata(&hostile).map_err(|error| {
            format!("cannot inspect candidate-owned target cleanup fixture: {error}")
        })?;
        if !cleanup_probe.status.success()
            || cleanup_probe.timed_out
            || hostile_metadata.file_type().is_symlink()
            || !hostile_metadata.is_dir()
            || hostile_metadata.uid() != candidate_uid
            || hostile_metadata.permissions().mode() & 0o7777 != 0o500
        {
            return Err("candidate-owned target cleanup fixture differs from policy".to_owned());
        }
        verify_linux_candidate_principal_rollback(&sudo)?;
        Ok(())
    })();
    let lifecycle_cleanup = match principal_cleanup.take() {
        Some(cleanup) => cleanup.finish(),
        None => Instant::now()
            .checked_add(Duration::from_secs(30))
            .ok_or_else(|| "candidate verifier cleanup deadline overflowed".to_owned())
            .and_then(|deadline| transient_cleanup.cleanup_until(&process_authorities, deadline)),
    };
    let transient_absence = transient_cleanup.require_absent();
    let fixture_cleanup = fs::remove_dir_all(&fixture)
        .map_err(|error| format!("cannot remove candidate target verifier fixture: {error}"));
    combine_candidate_target_verifier_results(
        result,
        lifecycle_cleanup,
        transient_absence,
        fixture_cleanup,
    )
}

#[cfg(unix)]
pub(crate) fn verify_posix_process_authority_for_integration() -> Result<(), String> {
    use hell_testkit::PosixProcessToolRole::{Identity, Inventory, Sudo, Terminator};
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let hosted = ResolvedPosixProcessAuthorities::resolve()?;
    hell_testkit::verify_posix_process_authorities_for_integration(hosted.launch_authorities()?)
        .map_err(|error| format!("hosted POSIX process authority did not bind: {error}"))?;
    let expected_inventory = fs::canonicalize("/bin")
        .map_err(|error| format!("cannot canonicalize hosted process-tool parent: {error}"))?
        .join("ps");
    if hosted.inventory.invocation_path() != expected_inventory {
        return Err("hosted process inventory did not use its canonical parent".to_owned());
    }

    let root = fs::canonicalize(env::temp_dir())
        .map_err(|error| format!("cannot canonicalize process-authority fixture root: {error}"))?
        .join(format!(
            "hell-posix-process-authority-{}-{}",
            std::process::id(),
            POSIX_CANDIDATE_ENVIRONMENT_VERIFIER_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
    fs::create_dir_all(root.join("usr/bin"))
        .map_err(|error| format!("cannot create process-authority fixture: {error}"))?;
    let result = (|| {
        symlink(root.join("usr/bin"), root.join("bin"))
            .map_err(|error| format!("cannot create merged-/usr fixture alias: {error}"))?;
        for name in ["sudo", "id", "ps", "pkill"] {
            let path = root.join("usr/bin").join(name);
            fs::copy("/usr/bin/true", &path)
                .map_err(|error| format!("cannot stage process-authority fixture tool: {error}"))?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o555))
                .map_err(|error| format!("cannot seal process-authority fixture tool: {error}"))?;
        }
        let resolve = |name: &str| {
            crate::command::resolve_absolute_standard_executable(&root.join("bin").join(name))
        };
        let fixture = ResolvedPosixProcessAuthorities {
            sudo: resolve("sudo")?,
            identity: resolve("id")?,
            inventory: resolve("ps")?,
            terminator: resolve("pkill")?,
        };
        let retained = fixture.launch_authorities()?;
        hell_testkit::verify_posix_process_authorities_for_integration(retained.clone())
            .map_err(|error| format!("canonical-parent fixture authority did not bind: {error}"))?;
        if fixture.inventory.invocation_path() != root.join("usr/bin/ps") {
            return Err("merged-/usr fixture retained the symlink-parent spelling".to_owned());
        }
        let raw_alias = hell_testkit::PosixProcessAuthorities::new(
            fixture.sudo.posix_authority(Sudo),
            fixture.identity.posix_authority(Identity),
            fixture
                .inventory
                .posix_authority_with_invocation(Inventory, root.join("bin/ps")),
            fixture.terminator.posix_authority(Terminator),
        )
        .map_err(|error| format!("cannot assemble raw-alias fixture authority: {error}"))?;
        if hell_testkit::verify_posix_process_authorities_for_integration(raw_alias).is_ok() {
            return Err("symlink-parent invocation authority was accepted".to_owned());
        }
        let swapped = hell_testkit::PosixProcessAuthorities::new(
            fixture.identity.posix_authority(Identity),
            fixture.sudo.posix_authority(Sudo),
            fixture.inventory.posix_authority(Inventory),
            fixture.terminator.posix_authority(Terminator),
        );
        if swapped.is_ok() {
            return Err("process-tool role swap was accepted".to_owned());
        }
        fs::set_permissions(root.join("usr/bin/id"), fs::Permissions::from_mode(0o755))
            .map_err(|error| format!("cannot mutate fixture metadata: {error}"))?;
        if hell_testkit::verify_posix_process_authorities_for_integration(retained).is_ok() {
            return Err("retained process authority accepted metadata drift".to_owned());
        }
        Ok(())
    })();
    let cleanup = fs::remove_dir_all(&root)
        .map_err(|error| format!("cannot remove process-authority fixture: {error}"));
    result.and(cleanup)
}

#[cfg(unix)]
pub(crate) fn verify_posix_native_cargo_rejection_for_integration() -> Result<(), String> {
    let error = reject_native_posix_cargo_authority::<hell_testkit::PosixCargoSourceAuthority>()
        .expect_err("native Cargo must not construct a POSIX release authority");
    if error != "native Cargo lacks a closed staged Rust compiler authority for POSIX release" {
        return Err(format!(
            "native Cargo rejection diagnostic changed: observed={error:?}"
        ));
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn verify_posix_rustc_environment_for_integration() -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt as _;

    let allocation_policy = LinuxPrincipalIdPolicy {
        first: 1_000,
        span: 4,
    };
    let first = planned_linux_principal_candidate(
        allocation_policy,
        "hellplan",
        10,
        0,
        &LinuxPrincipalOccupancy::default(),
    )?;
    let mut occupied = LinuxPrincipalOccupancy::default();
    occupied.uids.insert(first.id);
    let occupied_uid =
        planned_linux_principal_candidate(allocation_policy, "hellplan", 10, 0, &occupied)?;
    occupied.gids.insert(occupied_uid.id);
    let occupied_gid =
        planned_linux_principal_candidate(allocation_policy, "hellplan", 10, 0, &occupied)?;
    occupied.principals.insert(occupied_gid.principal.clone());
    let stale_name =
        planned_linux_principal_candidate(allocation_policy, "hellplan", 10, 0, &occupied)?;
    let mut concurrent = LinuxPrincipalOccupancy::default();
    concurrent.uids.insert(first.id);
    concurrent.gids.insert(first.id);
    concurrent.principals.insert(first.principal.clone());
    concurrent.groups.insert(first.group.clone());
    let second =
        planned_linux_principal_candidate(allocation_policy, "hellplan", 10, 0, &concurrent)?;
    let mut exhausted = LinuxPrincipalOccupancy::default();
    exhausted
        .uids
        .extend(allocation_policy.first..allocation_policy.first + allocation_policy.span);
    if first == occupied_uid
        || occupied_uid == occupied_gid
        || occupied_gid == stale_name
        || first == second
        || planned_linux_principal_candidate(allocation_policy, "hellplan", 10, 0, &exhausted)
            .is_ok()
    {
        return Err("Linux principal reservation planner is not collision-closed".to_owned());
    }

    if !posix_process_inventory_is_canonical(b"1\n22\n")
        || posix_process_inventory_is_canonical(b"")
        || posix_process_inventory_is_canonical(b"1")
        || posix_process_inventory_is_canonical(b"01\n")
        || posix_process_inventory_is_canonical(b"1\n1\n")
        || posix_process_inventory_is_canonical(b"0\n")
        || posix_process_inventory_is_canonical(b"pid\n")
    {
        return Err("POSIX process inventory verifier is not fail-closed".to_owned());
    }

    let directory_service_inventory = b"nobody -2\nhellcandidate 550\nroot 0\n";
    if macos_directory_service_inventory_id(
        directory_service_inventory,
        "hellcandidate",
        "candidate principal",
    )? != Some(550)
        || macos_directory_service_inventory_id(
            directory_service_inventory,
            "absentcandidate",
            "candidate principal",
        )?
        .is_some()
        || macos_directory_service_inventory_id(
            b"hellcandidate 550\nhellcandidate 551\n",
            "hellcandidate",
            "candidate principal",
        )
        .is_ok()
        || macos_directory_service_inventory_id(
            b"hellcandidate 550 extra\n",
            "hellcandidate",
            "candidate principal",
        )
        .is_ok()
        || macos_directory_service_inventory_id(
            b"hellcandidate 550",
            "hellcandidate",
            "candidate principal",
        )
        .is_ok()
    {
        return Err("macOS directory-service inventory verifier is not fail-closed".to_owned());
    }
    if macos_construction_receipt_flags(Some(550), Some(550), false, false, Some(550), Some(550))?
        != (true, true)
        || macos_construction_receipt_flags(Some(550), Some(550), false, false, None, Some(550))?
            != (false, true)
        || macos_construction_receipt_flags(Some(550), Some(550), true, true, None, Some(550))
            .is_ok()
        || macos_construction_receipt_flags(
            Some(550),
            Some(550),
            false,
            false,
            Some(551),
            Some(550),
        )
        .is_ok()
    {
        return Err(
            "macOS construction side-effect receipt verifier is not fail-closed".to_owned(),
        );
    }

    let base_acl = b"# file: /authority\n# owner: root\n# group: root\nuser::r-x\ngroup::r-x\nother::r-x\n\n# file: /authority/rustc\n# owner: root\n# group: root\nuser::r-x\ngroup::r-x\nother::r-x\n\n";
    if !linux_getfacl_output_is_exact_base_acl(base_acl, 2)
        || linux_getfacl_output_is_exact_base_acl(base_acl, 1)
        || linux_getfacl_output_is_exact_base_acl(
            b"# file: /authority\nuser::r-x\nuser:runner:r-x\ngroup::r-x\nmask::r-x\nother::r-x\n\n",
            1,
        )
        || linux_getfacl_output_is_exact_base_acl(
            b"# file: /authority\nuser::r-x\ngroup::r-x\nother::r-x\ndefault:user::r-x\n\n",
            1,
        )
        || linux_getfacl_output_is_exact_base_acl(
            b"# file: /authority\nuser::r-x\ngroup::r-x\n\n",
            1,
        )
    {
        return Err("Linux base-only ACL framing verifier is not fail-closed".to_owned());
    }

    let temporary_root = fs::canonicalize(env::temp_dir())
        .map_err(|error| format!("cannot canonicalize Rust compiler verifier root: {error}"))?;
    let sequence = POSIX_CANDIDATE_ENVIRONMENT_VERIFIER_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let fixture = temporary_root.join(format!(
        "hell-rustc-environment-verifier-{}-{sequence}",
        std::process::id()
    ));
    let decoy_directory = fixture.join("decoy");
    fs::create_dir(&fixture)
        .map_err(|error| format!("cannot create Rust compiler verifier fixture: {error}"))?;
    fs::create_dir(&decoy_directory)
        .map_err(|error| format!("cannot create Rust compiler verifier decoy: {error}"))?;
    let result = (|| {
        let bound_rustc = fixture.join("bound-rustc");
        let decoy_rustc = decoy_directory.join("rustc");
        for path in [&bound_rustc, &decoy_rustc] {
            fs::write(path, b"controlled Rust compiler authority\n").map_err(|error| {
                format!("cannot write Rust compiler verifier authority: {error}")
            })?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o555)).map_err(|error| {
                format!("cannot protect Rust compiler verifier authority: {error}")
            })?;
        }
        let bound_rustc = fs::canonicalize(&bound_rustc)
            .map_err(|error| format!("cannot bind exact Rust compiler verifier path: {error}"))?;
        let decoy_path = std::env::join_paths(std::iter::once(&decoy_directory))
            .map_err(|error| format!("cannot encode Rust compiler decoy PATH: {error}"))?;
        let encoded = hell_testkit::bind_posix_rustc_environment_for_integration(
            vec![(OsString::from("PATH"), Some(decoy_path.clone()))],
            Some(&bound_rustc),
        )
        .map_err(|error| format!("cannot bind exact Rust compiler environment: {error}"))?;
        if encoded.get(OsStr::new("RUSTC")) != Some(&bound_rustc.as_os_str().to_owned())
            || encoded.get(OsStr::new("PATH")) != Some(&decoy_path)
            || bound_rustc == decoy_rustc
        {
            return Err(
                "exact Rust compiler environment can fall back to its decoy PATH".to_owned(),
            );
        }
        let missing = hell_testkit::bind_posix_rustc_environment_for_integration(Vec::new(), None)
            .expect_err("missing Rust compiler authority must fail");
        if missing.to_string() != "bound POSIX Rust compiler authority is absent" {
            return Err("missing Rust compiler authority diagnostic changed".to_owned());
        }
        let duplicate = hell_testkit::bind_posix_rustc_environment_for_integration(
            vec![(
                OsString::from("RUSTC"),
                Some(decoy_rustc.as_os_str().to_owned()),
            )],
            Some(&bound_rustc),
        )
        .expect_err("duplicate Rust compiler authority must fail");
        if duplicate.to_string()
            != "POSIX release child attempts to replace its bound Rust compiler"
        {
            return Err("duplicate Rust compiler authority diagnostic changed".to_owned());
        }
        let wrapper = hell_testkit::bind_posix_rustc_environment_for_integration(
            vec![(
                OsString::from("RUSTC_WRAPPER"),
                Some(decoy_rustc.as_os_str().to_owned()),
            )],
            Some(&bound_rustc),
        )
        .expect_err("unbound Rust compiler wrapper must fail");
        if wrapper.to_string() != "POSIX release child environment name is not allowed" {
            return Err("Rust compiler wrapper rejection diagnostic changed".to_owned());
        }
        Ok(())
    })();
    let cleanup = fs::remove_dir_all(&fixture)
        .map_err(|error| format!("cannot remove Rust compiler verifier fixture: {error}"));
    result.and(cleanup)
}

#[cfg(unix)]
fn validate_posix_candidate_environment(
    transient: &Path,
    protection: &PosixCandidateEnvironmentProtection,
    checkpoint: &str,
) -> Result<(), String> {
    if protection.root.path().parent() != Some(transient)
        || protection.root.path().file_name() != Some(OsStr::new("release-child-environment"))
    {
        return Err("candidate environment root authority changed".to_owned());
    }
    protection.root.validate(checkpoint)?;
    let expected = ["home", "cargo", "sccache", "tmp"];
    protection
        .root
        .validate_exact_children(checkpoint, &expected)?;
    if protection.children.len() != expected.len() {
        return Err(format!(
            "candidate environment child checkpoint inventory changed: checkpoint={checkpoint:?}; expectedCount={}; observedCount={}",
            expected.len(),
            protection.children.len()
        ));
    }
    for (authority, name) in protection.children.iter().zip(expected) {
        let expected_path = protection.root.path().join(name);
        if authority.path() != expected_path {
            return Err(format!(
                "candidate environment child authority path changed: checkpoint={checkpoint:?}; expectedPath={expected_path:?}; observedPath={:?}",
                authority.path()
            ));
        }
        authority.validate(checkpoint)?;
    }
    Ok(())
}

#[cfg(unix)]
fn posix_candidate_home_test_path(platform: ReleasePlatform) -> Result<&'static Path, String> {
    match platform {
        ReleasePlatform::LinuxX86_64 => Ok(Path::new("/usr/bin/test")),
        ReleasePlatform::MacosAarch64 => Ok(Path::new("/bin/test")),
        ReleasePlatform::WindowsX86_64 => {
            Err("candidate home probe requires a POSIX release platform".to_owned())
        }
    }
}

#[cfg(unix)]
fn probe_posix_candidate_home(
    platform: ReleasePlatform,
    sudo: &Path,
    principal: &str,
    home: &Path,
) -> Result<(), String> {
    let test = crate::command::resolve_absolute_standard_executable(
        posix_candidate_home_test_path(platform)?,
    )
    .map_err(|error| format!("cannot bind candidate home probe: {error}"))?;
    test.revalidate()
        .map_err(|error| format!("candidate home probe changed: {error}"))?;
    let rustfmt = home.join(".rustfmt.toml");
    let run = |arguments: &[&OsStr], label: &str| -> Result<(), String> {
        let result = CommandSpec::new(sudo.as_os_str(), Duration::from_secs(30))
            .arguments(["-n", "-u"])
            .argument(principal)
            .argument("--")
            .argument(test.invocation_path())
            .arguments(arguments.iter().copied())
            .run()
            .map_err(|error| format!("candidate home {label} probe failed: {error}"))?;
        if !result.status.success() || result.timed_out {
            return Err(format!("candidate home {label} probe did not succeed"));
        }
        Ok(())
    };
    for (option, label) in [("-r", "read"), ("-w", "write"), ("-x", "traverse")] {
        run(&[OsStr::new(option), home.as_os_str()], label)?;
    }
    run(
        &[OsStr::new("!"), OsStr::new("-e"), rustfmt.as_os_str()],
        "missing rustfmt configuration",
    )?;
    run(
        &[OsStr::new("!"), OsStr::new("-r"), rustfmt.as_os_str()],
        "unreadable absent rustfmt configuration",
    )
}

#[cfg(unix)]
pub(crate) fn verify_posix_candidate_home_test_authority_for_integration() -> Result<(), String> {
    if posix_candidate_home_test_path(ReleasePlatform::LinuxX86_64)? != Path::new("/usr/bin/test") {
        return Err("Linux candidate home probe path is not exact".to_owned());
    }
    if posix_candidate_home_test_path(ReleasePlatform::MacosAarch64)? != Path::new("/bin/test") {
        return Err("macOS candidate home probe path is not exact".to_owned());
    }
    if posix_candidate_home_test_path(ReleasePlatform::WindowsX86_64).is_ok() {
        return Err("Windows candidate home probe unexpectedly selected a POSIX tool".to_owned());
    }

    #[cfg(target_os = "linux")]
    let platform = ReleasePlatform::LinuxX86_64;
    #[cfg(target_os = "macos")]
    let platform = ReleasePlatform::MacosAarch64;
    let expected = posix_candidate_home_test_path(platform)?;
    let test = crate::command::resolve_absolute_standard_executable(expected)
        .map_err(|error| format!("cannot bind hosted candidate home probe: {error}"))?;
    if test.invocation_path() != expected {
        return Err("hosted candidate home probe invocation path is not exact".to_owned());
    }
    test.revalidate()
        .map_err(|error| format!("hosted candidate home probe changed: {error}"))
}

#[cfg(unix)]
fn require_posix_archive_adapter_inventory_phase(
    adapter: &Path,
    require_clean_stack_work: bool,
) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    use std::os::unix::fs::MetadataExt as _;
    use std::os::unix::fs::PermissionsExt as _;

    require_exact_directory_members(
        adapter,
        &[
            OsString::from(".authority"),
            OsString::from(".stack-work"),
            OsString::from(".toolchain"),
            OsString::from("ar"),
            OsString::from("stack.yaml"),
            OsString::from("stack.yaml.lock"),
        ],
        "native archive adapter inventory",
    )?;
    let authority = adapter.join(".authority");
    #[cfg(target_os = "macos")]
    let authority_members = [OsString::from("inputs"), OsString::from("llvm")];
    #[cfg(not(target_os = "macos"))]
    let authority_members = [OsString::from("llvm-ar")];
    require_exact_directory_members(
        &authority,
        &authority_members,
        "native archive archiver authority",
    )?;
    #[cfg(target_os = "macos")]
    require_exact_directory_members(
        &authority.join("inputs"),
        &[],
        "native archive input staging authority",
    )?;
    let toolchain = adapter.join(".toolchain");
    require_exact_directory_members(
        &toolchain,
        &[
            OsString::from("system-ghc-9.8.2"),
            OsString::from("system-tools"),
        ],
        "native archive staged toolchain authority",
    )?;
    let work = adapter.join(".stack-work");
    if require_clean_stack_work {
        require_exact_directory_members(
            &work,
            &[OsString::from("tmp")],
            "native archive clean Stack work authority",
        )?;
    } else {
        const STACK_WORK_MEMBER_LIMIT: usize = 4_096;
        let mut members = 0usize;
        for entry in fs::read_dir(&work)
            .map_err(|error| format!("cannot enumerate active Stack work authority: {error}"))?
        {
            entry.map_err(|error| format!("cannot read active Stack work entry: {error}"))?;
            members = members
                .checked_add(1)
                .ok_or_else(|| "active Stack work inventory count overflowed".to_owned())?;
            if members > STACK_WORK_MEMBER_LIMIT {
                return Err(format!(
                    "active Stack work authority exceeds member limit {STACK_WORK_MEMBER_LIMIT}"
                ));
            }
        }
    }
    let toolchain_inventory = crate::command::BoundNativeToolchainInventory::bind(adapter)?;
    toolchain_inventory.revalidate()?;
    let authority_metadata = fs::symlink_metadata(&authority)
        .map_err(|error| format!("cannot inspect native archive archiver authority: {error}"))?;
    #[cfg(target_os = "macos")]
    let input_staging_metadata = fs::symlink_metadata(authority.join("inputs"))
        .map_err(|error| format!("cannot inspect native archive input staging: {error}"))?;
    #[cfg(target_os = "macos")]
    let archiver_path = authority.join("llvm").join("bin").join("llvm-ar");
    #[cfg(not(target_os = "macos"))]
    let archiver_path = authority.join("llvm-ar");
    #[cfg(target_os = "macos")]
    crate::command::BoundNativeArchiver::bind_existing_for_publisher(&archiver_path)?
        .revalidate()?;
    let archiver_metadata = fs::symlink_metadata(&archiver_path)
        .map_err(|error| format!("cannot inspect bound LLVM archiver: {error}"))?;
    let launcher_metadata = fs::symlink_metadata(adapter.join("ar"))
        .map_err(|error| format!("cannot inspect native archive launcher: {error}"))?;
    let stack_yaml_metadata = fs::symlink_metadata(adapter.join("stack.yaml"))
        .map_err(|error| format!("cannot inspect native Stack overlay: {error}"))?;
    let stack_lock_metadata = fs::symlink_metadata(adapter.join("stack.yaml.lock"))
        .map_err(|error| format!("cannot inspect native Stack lock: {error}"))?;
    let toolchain_metadata = fs::symlink_metadata(&toolchain)
        .map_err(|error| format!("cannot inspect staged toolchain authority: {error}"))?;
    let temporary_metadata = fs::symlink_metadata(work.join("tmp"))
        .map_err(|error| format!("cannot inspect candidate Stack temporary directory: {error}"))?;
    #[cfg(target_os = "macos")]
    let archiver_type_invalid = archiver_metadata.file_type().is_symlink()
        || !archiver_metadata.is_file()
        || archiver_metadata.permissions().mode() & 0o7777 != 0o555
        || archiver_metadata.nlink() != 1;
    #[cfg(not(target_os = "macos"))]
    let archiver_type_invalid = !archiver_metadata.file_type().is_symlink();
    if authority_metadata.file_type().is_symlink()
        || !authority_metadata.is_dir()
        || authority_metadata.permissions().mode() & 0o7777 != 0o555
        || {
            #[cfg(target_os = "macos")]
            {
                input_staging_metadata.file_type().is_symlink()
                    || !input_staging_metadata.is_dir()
                    || !matches!(
                        input_staging_metadata.permissions().mode() & 0o7777,
                        0o700 | 0o2710
                    )
            }
            #[cfg(not(target_os = "macos"))]
            {
                false
            }
        }
        || archiver_type_invalid
        || !launcher_metadata.file_type().is_symlink()
        || stack_yaml_metadata.file_type().is_symlink()
        || !stack_yaml_metadata.is_file()
        || stack_lock_metadata.file_type().is_symlink()
        || !stack_lock_metadata.is_file()
        || toolchain_metadata.file_type().is_symlink()
        || !toolchain_metadata.is_dir()
        || toolchain_metadata.permissions().mode() & 0o7777 != 0o555
        || temporary_metadata.file_type().is_symlink()
        || !temporary_metadata.is_dir()
    {
        return Err(
            "native archive adapter inventory contains an unexpected entry type".to_owned(),
        );
    }
    Ok(())
}

#[cfg(unix)]
struct PosixArchiveAdapterTransitionState<'a> {
    parent: &'a Path,
    parent_identity: &'a PosixObjectIdentity,
    parent_owner: u32,
    parent_group: u32,
    parent_mode: u32,
    adapter: &'a Path,
    adapter_identity: &'a PosixObjectIdentity,
    work_directory: &'a Path,
    work_directory_identity: &'a PosixObjectIdentity,
    temporary_directory: &'a Path,
    temporary_directory_identity: &'a PosixObjectIdentity,
}

#[cfg(unix)]
fn require_posix_archive_adapter_transition_state(
    state: PosixArchiveAdapterTransitionState<'_>,
) -> Result<(), String> {
    require_posix_archive_adapter_transition_state_phase(state, true)
}

#[cfg(unix)]
fn require_posix_archive_adapter_transition_state_phase(
    state: PosixArchiveAdapterTransitionState<'_>,
    require_clean_stack_work: bool,
) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let PosixArchiveAdapterTransitionState {
        parent,
        parent_identity,
        parent_owner,
        parent_group,
        parent_mode,
        adapter,
        adapter_identity,
        work_directory,
        work_directory_identity,
        temporary_directory,
        temporary_directory_identity,
    } = state;

    let observed_parent = posix_object_identity(parent)?;
    let parent_metadata = fs::symlink_metadata(parent)
        .map_err(|error| format!("cannot inspect native archive adapter authority: {error}"))?;
    if parent_metadata.file_type().is_symlink()
        || !parent_metadata.is_dir()
        || !posix_same_object(&observed_parent, parent_identity)
        || parent_metadata.uid() != parent_owner
        || parent_metadata.gid() != parent_group
        || parent_metadata.permissions().mode() & 0o7777 != parent_mode
        || adapter.parent() != Some(parent)
        || work_directory != adapter.join(".stack-work")
        || temporary_directory != work_directory.join("tmp")
        || fs::canonicalize(adapter)
            .map_err(|error| format!("cannot canonicalize native archive adapter: {error}"))?
            != adapter
        || fs::canonicalize(work_directory).map_err(|error| {
            format!("cannot canonicalize candidate Stack work directory: {error}")
        })? != work_directory
        || fs::canonicalize(temporary_directory).map_err(|error| {
            format!("cannot canonicalize candidate Stack temporary directory: {error}")
        })? != temporary_directory
    {
        return Err("native archive adapter authority changed during mode transition".to_owned());
    }
    require_exact_directory_members(
        parent,
        &[adapter
            .file_name()
            .ok_or_else(|| "native archive adapter name is absent".to_owned())?
            .to_os_string()],
        "native archive adapter authority",
    )?;
    require_posix_archive_adapter_inventory_phase(adapter, require_clean_stack_work)?;
    let observed_adapter = posix_object_identity(adapter)?;
    let observed_work_directory = posix_object_identity(work_directory)?;
    let observed_temporary_directory = posix_object_identity(temporary_directory)?;
    if !posix_same_object(&observed_adapter, adapter_identity)
        || observed_adapter.mode != 0o2755
        || !posix_same_object(&observed_work_directory, work_directory_identity)
        || observed_work_directory.mode != 0o3770
        || observed_adapter.owner != parent_owner
        || observed_adapter.group != parent_group
        || observed_work_directory.owner != parent_owner
        || observed_work_directory.group != parent_group
        || !posix_same_object(&observed_temporary_directory, temporary_directory_identity)
        || observed_temporary_directory.mode != 0o2770
        || observed_temporary_directory.owner != parent_owner
        || observed_temporary_directory.group != parent_group
    {
        return Err(
            "native archive adapter child authority changed during mode transition".to_owned(),
        );
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn verify_posix_source_stack_work_cleanup_order_for_integration() -> Result<(), String> {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let temporary_root = fs::canonicalize(env::temp_dir()).map_err(|error| {
        format!("cannot canonicalize Stack cleanup verifier temp root: {error}")
    })?;
    let mut root = None;
    for _ in 0..16 {
        let sequence = POSIX_ARCHIVE_TRANSITION_VERIFIER_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let candidate = temporary_root.join(format!(
            "hell-source-stack-cleanup-verifier-{}-{sequence}",
            std::process::id()
        ));
        match fs::create_dir(&candidate) {
            Ok(()) => {
                root = Some(candidate);
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(format!(
                    "cannot create source Stack cleanup verifier root: {error}"
                ));
            }
        }
    }
    let root = root.ok_or_else(|| {
        "cannot allocate a collision-free source Stack cleanup verifier root".to_owned()
    })?;
    let result = (|| {
        let source = root.join("oracle");
        let stack_work = source.join(".stack-work");
        let sentinel = root.join("external-sentinel");
        fs::create_dir_all(stack_work.join("nested/child"))
            .map_err(|error| format!("cannot create source Stack cleanup fixture: {error}"))?;
        fs::write(stack_work.join("nested/child/member"), b"member\n")
            .map_err(|error| format!("cannot write source Stack cleanup member: {error}"))?;
        fs::write(&sentinel, b"sentinel\n")
            .map_err(|error| format!("cannot write source Stack cleanup sentinel: {error}"))?;
        symlink(&sentinel, stack_work.join("external-link")).map_err(|error| {
            format!("cannot create source Stack cleanup sentinel link: {error}")
        })?;
        let source_identity = posix_object_identity(&source)?;
        let stack_work_identity = posix_object_identity(&stack_work)?;
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(5))
            .ok_or_else(|| "source Stack cleanup verifier deadline overflowed".to_owned())?;
        let snapshot_calls = std::cell::Cell::new(0_u8);
        let receipt = cleanup_posix_source_stack_work_before_snapshot(
            PosixSourceStackCleanupContext {
                source: &source,
                stack_work: &stack_work,
                deadline,
            },
            || {
                if posix_object_identity(&source)? != source_identity
                    || posix_object_identity(&stack_work)? != stack_work_identity
                {
                    return Err("source Stack cleanup verifier authority changed".to_owned());
                }
                Ok(())
            },
            |path| {
                fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                    .map_err(|error| format!("cannot open source Stack cleanup directory: {error}"))
            },
            |path| {
                fs::remove_file(path)
                    .map_err(|error| format!("cannot unlink source Stack cleanup member: {error}"))
            },
            |path| {
                fs::remove_dir(path).map_err(|error| {
                    format!("cannot remove source Stack cleanup directory: {error}")
                })
            },
            |_| {
                snapshot_calls.set(snapshot_calls.get().saturating_add(1));
                if fs::symlink_metadata(&stack_work).is_ok() {
                    return Err("snapshot validation preceded exact Stack root absence".to_owned());
                }
                if fs::read(&sentinel).map_err(|error| {
                    format!("cannot read source Stack cleanup sentinel: {error}")
                })? != b"sentinel\n"
                {
                    return Err("source Stack cleanup followed an external symlink".to_owned());
                }
                Ok(())
            },
        )?;
        if receipt.source_identity != source_identity || snapshot_calls.get() != 1 {
            return Err("source Stack cleanup phase receipt/order is not exact".to_owned());
        }

        let expired_source = root.join("expired-oracle");
        let expired_stack_work = expired_source.join(".stack-work");
        fs::create_dir_all(&expired_stack_work)
            .map_err(|error| format!("cannot create expired Stack cleanup fixture: {error}"))?;
        fs::write(expired_stack_work.join("member"), b"member\n")
            .map_err(|error| format!("cannot write expired Stack cleanup member: {error}"))?;
        let expired_snapshot_calls = std::cell::Cell::new(0_u8);
        let expired = cleanup_posix_source_stack_work_before_snapshot(
            PosixSourceStackCleanupContext {
                source: &expired_source,
                stack_work: &expired_stack_work,
                deadline: Instant::now(),
            },
            || Ok(()),
            |_| Ok(()),
            |path| {
                fs::remove_file(path)
                    .map_err(|error| format!("cannot remove expired Stack member: {error}"))
            },
            |path| {
                fs::remove_dir(path)
                    .map_err(|error| format!("cannot remove expired Stack directory: {error}"))
            },
            |_| {
                expired_snapshot_calls.set(expired_snapshot_calls.get().saturating_add(1));
                Ok(())
            },
        )
        .expect_err("expired Stack cleanup must fail before snapshot validation");
        if !expired.contains("deadline expired")
            || expired_snapshot_calls.get() != 0
            || !expired_stack_work.join("member").is_file()
        {
            return Err(
                "expired Stack cleanup launched snapshot work or mutated its tree".to_owned(),
            );
        }
        Ok(())
    })();
    let cleanup = fs::remove_dir_all(&root)
        .map_err(|error| format!("cannot remove source Stack cleanup verifier: {error}"));
    result.and(cleanup)
}

#[cfg(unix)]
pub(crate) fn verify_posix_archive_adapter_transition_for_integration() -> Result<(), String> {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    let simulated_phase_entry = Instant::now();
    let simulated_preparation_completion = simulated_phase_entry
        .checked_add(POSIX_ARCHIVE_CLEANUP_BUDGET + Duration::from_secs(1))
        .ok_or_else(|| "archive transition verifier clock overflowed".to_owned())?;
    let simulated_outer = simulated_preparation_completion
        .checked_add(Duration::from_secs(120))
        .ok_or_else(|| "archive transition verifier outer clock overflowed".to_owned())?;
    let simulated_cleanup =
        transition_cleanup_deadlines(simulated_preparation_completion, simulated_outer)?;
    let simulated_expected = simulated_preparation_completion
        .checked_add(POSIX_ARCHIVE_CLEANUP_BUDGET)
        .ok_or_else(|| "archive transition verifier cleanup clock overflowed".to_owned())?;
    if simulated_cleanup.source_work != simulated_expected
        || simulated_cleanup.adapter_close != simulated_expected
        || simulated_cleanup.final_attestation != simulated_expected
        || simulated_cleanup.source_work
            <= simulated_phase_entry
                .checked_add(POSIX_ARCHIVE_CLEANUP_BUDGET)
                .ok_or_else(|| {
                    "archive transition verifier stale cleanup clock overflowed".to_owned()
                })?
    {
        return Err("archive cleanup budget started before preparation completed".to_owned());
    }
    let clipped_outer = simulated_preparation_completion
        .checked_add(Duration::from_secs(7))
        .ok_or_else(|| "archive transition verifier clipped clock overflowed".to_owned())?;
    let clipped = transition_cleanup_deadlines(simulated_preparation_completion, clipped_outer)?;
    if clipped.quiescence != clipped_outer
        || clipped.source_work != clipped_outer
        || clipped.final_attestation != clipped_outer
    {
        return Err("archive cleanup deadline escaped its enclosing completion reserve".to_owned());
    }

    let phase_now = Instant::now();
    let phase_deadline = |seconds: u64| {
        phase_now
            .checked_add(Duration::from_secs(seconds))
            .ok_or_else(|| "archive phase verifier deadline overflowed".to_owned())
    };
    let phase_deadlines = NativeOracleCleanupDeadlines {
        quiescence: phase_deadline(1)?,
        #[cfg(target_os = "macos")]
        broker_stop: phase_deadline(2)?,
        source_work: phase_now
            .checked_sub(Duration::from_secs(1))
            .ok_or_else(|| "archive phase verifier expired deadline underflowed".to_owned())?,
        adapter_work: phase_deadline(3)?,
        final_restore: phase_deadline(4)?,
        adapter_close: phase_deadline(5)?,
        final_attestation: phase_deadline(6)?,
    };
    let phase_order = std::cell::RefCell::new(Vec::new());
    let restoration = run_native_oracle_restoration_phases(
        phase_deadlines,
        |deadline| {
            phase_order.borrow_mut().push("source");
            if deadline >= Instant::now() {
                return Err("source cleanup verifier deadline was not expired".to_owned());
            }
            Err("source cleanup verifier exhausted its phase".to_owned())
        },
        |deadline| {
            phase_order.borrow_mut().push("adapter");
            if deadline <= Instant::now() {
                return Err("adapter cleanup verifier lost its reserve".to_owned());
            }
            Ok(())
        },
        |deadline| {
            phase_order.borrow_mut().push("restore");
            if deadline <= Instant::now() {
                return Err("final restore verifier lost its reserve".to_owned());
            }
            Ok(())
        },
    )
    .expect_err("expired source cleanup must remain a typed primary restoration failure");
    let finalization = run_native_oracle_finalizer(
        phase_deadlines,
        |deadline| {
            phase_order.borrow_mut().push("close");
            if deadline <= Instant::now() {
                return Err("retained close verifier lost its reserve".to_owned());
            }
            Ok(())
        },
        |deadline| {
            phase_order.borrow_mut().push("attest");
            if deadline <= Instant::now() {
                return Err("final attestation verifier lost its reserve".to_owned());
            }
            Ok(())
        },
    );
    if restoration
        != "native archive adapter restoration failed; source-work-cleanup: source cleanup verifier exhausted its phase"
        || finalization.adapter_close.is_err()
        || finalization.final_attestation.is_err()
        || phase_order.into_inner() != ["source", "adapter", "restore", "close", "attest"]
    {
        return Err(
            "source cleanup exhaustion starved or reordered a later reserved cleanup phase"
                .to_owned(),
        );
    }
    let panic_order = std::cell::RefCell::new(Vec::new());
    let panic_restoration = run_native_oracle_restoration_phases(
        phase_deadlines,
        |_| {
            panic_order.borrow_mut().push("source-panic");
            panic!("injected source cleanup panic")
        },
        |_| {
            panic_order.borrow_mut().push("adapter-after-panic");
            Ok(())
        },
        |_| {
            panic_order.borrow_mut().push("restore-after-panic");
            Ok(())
        },
    )
    .expect_err("source cleanup panic must become a typed restoration failure");
    if !panic_restoration.contains("source work cleanup panicked")
        || panic_order.into_inner()
            != ["source-panic", "adapter-after-panic", "restore-after-panic"]
    {
        return Err("source cleanup panic skipped a later reserved phase".to_owned());
    }

    hell_testkit::verify_posix_candidate_quiescence_receipt_binding_for_integration()
        .map_err(|error| format!("candidate quiescence receipt verifier failed: {error}"))?;
    let missing_receipt = require_posix_archive_cleanup_quiescence(None, 41_001, 41_002)
        .expect_err("archive cleanup must reject a missing quiescence receipt");
    if !missing_receipt.contains("receipt is absent") {
        return Err("missing archive cleanup receipt diagnostic is not exact".to_owned());
    }
    let expired_checkout = git_head_before(Path::new("."), Instant::now())
        .expect_err("late archive checkout attestation must not receive a new deadline");
    if !expired_checkout.contains("deadline expired") {
        return Err("late archive checkout attestation restarted its deadline".to_owned());
    }
    let expired_tree = require_posix_read_only_tree_before(
        Path::new("."),
        "expired archive verifier",
        Instant::now(),
    )
    .expect_err("late archive tree attestation must not receive a new deadline");
    if !expired_tree.contains("deadline expired") {
        return Err("late archive tree attestation restarted its deadline".to_owned());
    }

    fn open_fixture_tree_for_cleanup(root: &Path) -> Result<(), String> {
        let metadata = fs::symlink_metadata(root)
            .map_err(|error| format!("cannot inspect archive verifier cleanup tree: {error}"))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Ok(());
        }
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).map_err(|error| {
            format!(
                "cannot open archive verifier cleanup directory {}: {error}",
                root.display()
            )
        })?;
        let children = fs::read_dir(root)
            .map_err(|error| format!("cannot enumerate archive verifier cleanup tree: {error}"))?;
        for child in children {
            let child =
                child.map_err(|error| format!("cannot inspect archive verifier child: {error}"))?;
            open_fixture_tree_for_cleanup(&child.path())?;
        }
        Ok(())
    }

    fn stage_adapter(adapter: &Path, label: &str) -> Result<(), String> {
        let work = adapter.join(".stack-work");
        let toolchain = adapter.join(".toolchain");
        let authority = adapter.join(".authority");
        fs::create_dir_all(&authority)
            .map_err(|error| format!("cannot create archive verifier authority: {error}"))?;
        fs::create_dir_all(work.join("tmp"))
            .map_err(|error| format!("cannot create archive verifier work tree: {error}"))?;
        fs::create_dir_all(toolchain.join("system-ghc-9.8.2"))
            .map_err(|error| format!("cannot create archive verifier GHC inventory: {error}"))?;
        fs::create_dir(toolchain.join("system-tools"))
            .map_err(|error| format!("cannot create archive verifier tool inventory: {error}"))?;
        #[cfg(target_os = "macos")]
        {
            use std::os::unix::fs::PermissionsExt as _;

            let inputs = authority.join("inputs");
            fs::create_dir(&inputs).map_err(|error| {
                format!("cannot create archive verifier input staging: {error}")
            })?;
            fs::set_permissions(&inputs, fs::Permissions::from_mode(0o2710)).map_err(|error| {
                format!("cannot confine archive verifier input staging: {error}")
            })?;
            let llvm = authority.join("llvm");
            let llvm_bin = llvm.join("bin");
            fs::create_dir_all(&llvm_bin)
                .map_err(|error| format!("cannot create archive verifier LLVM prefix: {error}"))?;
            fs::copy(
                std::env::current_exe().map_err(|error| {
                    format!("cannot locate archive verifier executable: {error}")
                })?,
                llvm_bin.join("llvm-ar"),
            )
            .map_err(|error| format!("cannot create archive verifier archiver: {error}"))?;
            fs::set_permissions(llvm_bin.join("llvm-ar"), fs::Permissions::from_mode(0o555))
                .map_err(|error| format!("cannot confine archive verifier archiver: {error}"))?;
            fs::set_permissions(&llvm_bin, fs::Permissions::from_mode(0o555))
                .map_err(|error| format!("cannot confine archive verifier LLVM bin: {error}"))?;
            fs::set_permissions(&llvm, fs::Permissions::from_mode(0o555))
                .map_err(|error| format!("cannot confine archive verifier LLVM prefix: {error}"))?;
        }
        #[cfg(not(target_os = "macos"))]
        symlink(format!("/bound/{label}-llvm-ar"), authority.join("llvm-ar"))
            .map_err(|error| format!("cannot create archive verifier archiver link: {error}"))?;
        symlink(format!("/bound/{label}-hell-ci"), adapter.join("ar"))
            .map_err(|error| format!("cannot create archive verifier launcher link: {error}"))?;
        fs::write(adapter.join("stack.yaml"), format!("{label}-overlay\n"))
            .map_err(|error| format!("cannot write archive verifier overlay: {error}"))?;
        fs::write(adapter.join("stack.yaml.lock"), format!("{label}-lock\n"))
            .map_err(|error| format!("cannot write archive verifier lock: {error}"))?;
        for (path, mode) in [
            (authority, 0o555),
            (toolchain.join("system-ghc-9.8.2"), 0o555),
            (toolchain.join("system-tools"), 0o555),
            (toolchain, 0o555),
            (adapter.to_owned(), 0o2755),
            (work.clone(), 0o3770),
            (work.join("tmp"), 0o2770),
        ] {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).map_err(|error| {
                format!(
                    "cannot set archive verifier mode on {}: {error}",
                    path.display()
                )
            })?;
        }
        Ok(())
    }

    let temporary_root = fs::canonicalize(env::temp_dir())
        .map_err(|error| format!("cannot canonicalize archive verifier temp root: {error}"))?;
    let mut root = None;
    for _ in 0..16 {
        let sequence = POSIX_ARCHIVE_TRANSITION_VERIFIER_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let candidate = temporary_root.join(format!(
            "hell-archive-transition-verifier-{}-{sequence}",
            std::process::id()
        ));
        match fs::create_dir(&candidate) {
            Ok(()) => {
                root = Some(candidate);
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(format!(
                    "cannot create archive transition verifier root: {error}"
                ));
            }
        }
    }
    let root = root.ok_or_else(|| {
        "cannot allocate a collision-free archive transition verifier root".to_owned()
    })?;
    let result = (|| {
        let sentinel = root.join("external-sentinel");
        fs::write(&sentinel, b"sentinel\n")
            .map_err(|error| format!("cannot write no-follow sentinel: {error}"))?;
        let forest = root.join("bounded-forest");
        fs::create_dir_all(forest.join("nested/child"))
            .map_err(|error| format!("cannot create bounded remover forest: {error}"))?;
        fs::write(forest.join("nested/child/member"), b"member\n")
            .map_err(|error| format!("cannot write bounded remover member: {error}"))?;
        symlink(&sentinel, forest.join("external-link"))
            .map_err(|error| format!("cannot link bounded remover sentinel: {error}"))?;
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(5))
            .ok_or_else(|| "bounded remover verifier deadline overflowed".to_owned())?;
        remove_posix_no_follow_forest(
            &[PosixNoFollowRemovalRoot {
                directory: &forest,
                retained_child: None,
            }],
            PosixNoFollowRemovalPolicy {
                entry_limit: 16,
                depth_limit: 8,
                operation_limit: 64,
                deadline,
            },
            || Ok(()),
            |path| {
                fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|error| {
                    format!("cannot open bounded remover verifier directory: {error}")
                })
            },
            |path| {
                fs::remove_file(path)
                    .map_err(|error| format!("cannot unlink verifier member: {error}"))
            },
            |path| {
                fs::remove_dir(path)
                    .map_err(|error| format!("cannot remove verifier directory: {error}"))
            },
        )?;
        require_exact_directory_members(&forest, &[], "bounded no-follow verifier forest")?;
        fs::remove_dir(&forest)
            .map_err(|error| format!("cannot remove emptied no-follow verifier root: {error}"))?;
        if fs::symlink_metadata(&forest).is_ok() {
            return Err("emptied no-follow verifier root remains present".to_owned());
        }
        if fs::read(&sentinel)
            .map_err(|error| format!("cannot read no-follow sentinel: {error}"))?
            != b"sentinel\n"
        {
            return Err("bounded remover followed an external symlink".to_owned());
        }

        let oversize = root.join("bounded-oversize");
        fs::create_dir(&oversize)
            .map_err(|error| format!("cannot create oversize verifier root: {error}"))?;
        for name in ["one", "two"] {
            fs::write(oversize.join(name), b"member\n")
                .map_err(|error| format!("cannot write oversize verifier member: {error}"))?;
        }
        let late_mutations = std::cell::Cell::new(0usize);
        let oversize_error = remove_posix_no_follow_forest(
            &[PosixNoFollowRemovalRoot {
                directory: &oversize,
                retained_child: None,
            }],
            PosixNoFollowRemovalPolicy {
                entry_limit: 2,
                depth_limit: 8,
                operation_limit: 8,
                deadline,
            },
            || Ok(()),
            |_| {
                late_mutations.set(late_mutations.get() + 1);
                Ok(())
            },
            |_| {
                late_mutations.set(late_mutations.get() + 1);
                Ok(())
            },
            |_| {
                late_mutations.set(late_mutations.get() + 1);
                Ok(())
            },
        )
        .err()
        .ok_or_else(|| "bounded remover accepted an oversized forest".to_owned())?;
        if !oversize_error.contains("global entry bound") || late_mutations.get() != 0 {
            return Err("oversized forest launched a late remover mutation".to_owned());
        }

        const ALL_DIRECTORY_ENTRY_LIMIT: usize = 6;
        let all_directories = root.join("bounded-all-directories");
        fs::create_dir(&all_directories)
            .map_err(|error| format!("cannot create all-directory verifier root: {error}"))?;
        for index in 0..ALL_DIRECTORY_ENTRY_LIMIT - 1 {
            fs::create_dir(all_directories.join(index.to_string()))
                .map_err(|error| format!("cannot create all-directory verifier member: {error}"))?;
        }
        remove_posix_no_follow_forest(
            &[PosixNoFollowRemovalRoot {
                directory: &all_directories,
                retained_child: None,
            }],
            PosixNoFollowRemovalPolicy {
                entry_limit: ALL_DIRECTORY_ENTRY_LIMIT,
                depth_limit: 8,
                operation_limit: posix_no_follow_operation_limit(ALL_DIRECTORY_ENTRY_LIMIT)?,
                deadline,
            },
            || Ok(()),
            |_| Ok(()),
            |_| Err("all-directory verifier unexpectedly admitted a file".to_owned()),
            |path| fs::remove_dir(path).map_err(|error| error.to_string()),
        )?;
        if fs::read_dir(&all_directories)
            .map_err(|error| format!("cannot inspect all-directory verifier root: {error}"))?
            .next()
            .is_some()
        {
            return Err("all-directory forest remained at its admitted bound".to_owned());
        }

        let excessive_directories = root.join("bounded-excessive-directories");
        fs::create_dir(&excessive_directories)
            .map_err(|error| format!("cannot create excessive-directory verifier root: {error}"))?;
        for index in 0..ALL_DIRECTORY_ENTRY_LIMIT {
            fs::create_dir(excessive_directories.join(index.to_string())).map_err(|error| {
                format!("cannot create excessive-directory verifier member: {error}")
            })?;
        }
        let excessive_mutations = std::cell::Cell::new(0usize);
        let excessive_error = remove_posix_no_follow_forest(
            &[PosixNoFollowRemovalRoot {
                directory: &excessive_directories,
                retained_child: None,
            }],
            PosixNoFollowRemovalPolicy {
                entry_limit: ALL_DIRECTORY_ENTRY_LIMIT,
                depth_limit: 8,
                operation_limit: posix_no_follow_operation_limit(ALL_DIRECTORY_ENTRY_LIMIT)?,
                deadline,
            },
            || Ok(()),
            |_| {
                excessive_mutations.set(excessive_mutations.get().saturating_add(1));
                Ok(())
            },
            |_| {
                excessive_mutations.set(excessive_mutations.get().saturating_add(1));
                Ok(())
            },
            |_| {
                excessive_mutations.set(excessive_mutations.get().saturating_add(1));
                Ok(())
            },
        )
        .expect_err("bounded remover accepted one excess directory");
        let remaining_directories = fs::read_dir(&excessive_directories)
            .map_err(|error| format!("cannot inspect excessive-directory verifier: {error}"))?
            .count();
        if !excessive_error.contains("global entry bound")
            || excessive_mutations.get() != 0
            || remaining_directories != ALL_DIRECTORY_ENTRY_LIMIT
        {
            return Err("excessive directory forest launched a late remover mutation".to_owned());
        }

        let operation_bound = root.join("bounded-operations");
        fs::create_dir(&operation_bound)
            .map_err(|error| format!("cannot create operation-bound verifier root: {error}"))?;
        fs::write(operation_bound.join("member"), b"member\n")
            .map_err(|error| format!("cannot write operation-bound verifier member: {error}"))?;
        let operation_mutations = std::cell::Cell::new(0usize);
        let operation_error = remove_posix_no_follow_forest(
            &[PosixNoFollowRemovalRoot {
                directory: &operation_bound,
                retained_child: None,
            }],
            PosixNoFollowRemovalPolicy {
                entry_limit: 8,
                depth_limit: 8,
                operation_limit: 1,
                deadline,
            },
            || Ok(()),
            |_| {
                operation_mutations.set(operation_mutations.get() + 1);
                Ok(())
            },
            |_| {
                operation_mutations.set(operation_mutations.get() + 1);
                Ok(())
            },
            |_| {
                operation_mutations.set(operation_mutations.get() + 1);
                Ok(())
            },
        )
        .expect_err("bounded remover accepted an excessive operation count");
        if !operation_error.contains("global operation bound")
            || operation_mutations.get() != 0
            || !operation_bound.join("member").is_file()
        {
            return Err("operation-bounded forest launched a late remover mutation".to_owned());
        }

        let expired = root.join("bounded-expired");
        fs::create_dir(&expired)
            .map_err(|error| format!("cannot create expired verifier root: {error}"))?;
        fs::write(expired.join("member"), b"member\n")
            .map_err(|error| format!("cannot write expired verifier member: {error}"))?;
        let expired_deadline = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .ok_or_else(|| "cannot construct expired verifier deadline".to_owned())?;
        let expired_mutations = std::cell::Cell::new(0usize);
        if remove_posix_no_follow_forest(
            &[PosixNoFollowRemovalRoot {
                directory: &expired,
                retained_child: None,
            }],
            PosixNoFollowRemovalPolicy {
                entry_limit: 8,
                depth_limit: 8,
                operation_limit: 32,
                deadline: expired_deadline,
            },
            || Ok(()),
            |_| {
                expired_mutations.set(expired_mutations.get() + 1);
                Ok(())
            },
            |_| {
                expired_mutations.set(expired_mutations.get() + 1);
                Ok(())
            },
            |_| {
                expired_mutations.set(expired_mutations.get() + 1);
                Ok(())
            },
        )
        .is_ok()
            || expired_mutations.get() != 0
        {
            return Err("expired cleanup launched a late remover mutation".to_owned());
        }

        let substituted = root.join("bounded-substituted");
        let displaced = root.join("bounded-displaced");
        fs::create_dir(&substituted)
            .map_err(|error| format!("cannot create substitution verifier root: {error}"))?;
        fs::write(substituted.join("member"), b"member\n")
            .map_err(|error| format!("cannot write substitution verifier member: {error}"))?;
        let substituted_identity = posix_object_identity(&substituted)?;
        fs::rename(&substituted, &displaced)
            .map_err(|error| format!("cannot displace substitution verifier root: {error}"))?;
        fs::create_dir(&substituted)
            .map_err(|error| format!("cannot replace substitution verifier root: {error}"))?;
        fs::write(substituted.join("replacement"), b"replacement\n")
            .map_err(|error| format!("cannot write substitution replacement: {error}"))?;
        let substitution_mutations = std::cell::Cell::new(0usize);
        if remove_posix_no_follow_forest(
            &[PosixNoFollowRemovalRoot {
                directory: &substituted,
                retained_child: None,
            }],
            PosixNoFollowRemovalPolicy {
                entry_limit: 8,
                depth_limit: 8,
                operation_limit: 32,
                deadline,
            },
            || {
                if posix_object_identity(&substituted)? != substituted_identity {
                    return Err("verifier root changed after receipt binding".to_owned());
                }
                Ok(())
            },
            |_| {
                substitution_mutations.set(substitution_mutations.get() + 1);
                Ok(())
            },
            |_| {
                substitution_mutations.set(substitution_mutations.get() + 1);
                Ok(())
            },
            |_| {
                substitution_mutations.set(substitution_mutations.get() + 1);
                Ok(())
            },
        )
        .is_ok()
            || substitution_mutations.get() != 0
        {
            return Err("substituted root launched a late remover mutation".to_owned());
        }

        let depth = root.join("bounded-depth");
        fs::create_dir_all(depth.join("one/two/three"))
            .map_err(|error| format!("cannot create depth verifier tree: {error}"))?;
        let depth_error = remove_posix_no_follow_forest(
            &[PosixNoFollowRemovalRoot {
                directory: &depth,
                retained_child: None,
            }],
            PosixNoFollowRemovalPolicy {
                entry_limit: 16,
                depth_limit: 2,
                operation_limit: 64,
                deadline,
            },
            || Ok(()),
            |path| {
                fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                    .map_err(|error| format!("cannot open depth verifier member: {error}"))
            },
            |path| {
                fs::remove_file(path)
                    .map_err(|error| format!("cannot unlink depth verifier member: {error}"))
            },
            |path| {
                fs::remove_dir(path)
                    .map_err(|error| format!("cannot remove depth verifier member: {error}"))
            },
        )
        .err()
        .ok_or_else(|| "bounded remover accepted excessive depth".to_owned())?;
        if !depth_error.contains("depth bound") {
            return Err("depth verifier diagnostic is not exact".to_owned());
        }

        let composite = ordered_bounded_failures(
            "composite verifier",
            [
                ("primary", "primary failure".to_owned()),
                ("restoration", "restoration failure".to_owned()),
            ],
        );
        let primary_position = composite
            .find("primary: primary failure")
            .ok_or_else(|| "composite verifier lost its primary failure".to_owned())?;
        let restoration_position = composite
            .find("restoration: restoration failure")
            .ok_or_else(|| "composite verifier lost its restoration failure".to_owned())?;
        if primary_position >= restoration_position {
            return Err("composite verifier reordered restoration before primary".to_owned());
        }

        let parent = root.join("archive-adapter");
        let adapter = parent.join("hell-ci-adapter");
        let work = adapter.join(".stack-work");
        let temporary = work.join("tmp");
        fs::create_dir_all(&parent)
            .map_err(|error| format!("cannot create archive verifier parent: {error}"))?;
        stage_adapter(&adapter, "initial")?;
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o2770))
            .map_err(|error| format!("cannot set archive verifier parent mode: {error}"))?;

        let parent_identity = posix_object_identity(&parent)?;
        let adapter_identity = posix_object_identity(&adapter)?;
        let work_identity = posix_object_identity(&work)?;
        let temporary_identity = posix_object_identity(&temporary)?;
        let owner = parent_identity.owner;
        let group = parent_identity.group;
        let validate = |parent_mode| {
            require_posix_archive_adapter_transition_state(PosixArchiveAdapterTransitionState {
                parent: &parent,
                parent_identity: &parent_identity,
                parent_owner: owner,
                parent_group: group,
                parent_mode,
                adapter: &adapter,
                adapter_identity: &adapter_identity,
                work_directory: &work,
                work_directory_identity: &work_identity,
                temporary_directory: &temporary,
                temporary_directory_identity: &temporary_identity,
            })
        };
        let validate_active = |parent_mode| {
            require_posix_archive_adapter_transition_state_phase(
                PosixArchiveAdapterTransitionState {
                    parent: &parent,
                    parent_identity: &parent_identity,
                    parent_owner: owner,
                    parent_group: group,
                    parent_mode,
                    adapter: &adapter,
                    adapter_identity: &adapter_identity,
                    work_directory: &work,
                    work_directory_identity: &work_identity,
                    temporary_directory: &temporary,
                    temporary_directory_identity: &temporary_identity,
                },
                false,
            )
        };
        validate(0o2770)?;

        let project_database = work.join("stack.sqlite3");
        let project_lock = work.join("stack.sqlite3.pantry-write-lock");
        let project_install = work.join("install");
        let temporary_build = temporary.join("stack-deadbeef");
        fs::write(&project_database, b"stack-project-database\n")
            .map_err(|error| format!("cannot write archive verifier project database: {error}"))?;
        fs::write(&project_lock, b"stack-project-lock\n")
            .map_err(|error| format!("cannot write archive verifier project lock: {error}"))?;
        fs::create_dir(&project_install)
            .map_err(|error| format!("cannot create archive verifier install state: {error}"))?;
        fs::create_dir(&temporary_build)
            .map_err(|error| format!("cannot create archive verifier temporary state: {error}"))?;
        validate_active(0o2770)?;
        let active_error = match validate(0o2770) {
            Err(error) => error,
            Ok(()) => {
                return Err(
                    "clean archive transition accepted active Stack project state".to_owned(),
                );
            }
        };
        if !active_error.contains("extra=")
            || !active_error.contains("stack.sqlite3")
            || !active_error.contains("install")
        {
            return Err("archive transition did not report bounded active members".to_owned());
        }
        fs::remove_file(&project_database)
            .map_err(|error| format!("cannot remove archive verifier project database: {error}"))?;
        fs::remove_file(&project_lock)
            .map_err(|error| format!("cannot remove archive verifier project lock: {error}"))?;
        fs::remove_dir(&project_install)
            .map_err(|error| format!("cannot remove archive verifier install state: {error}"))?;
        fs::remove_dir(&temporary_build)
            .map_err(|error| format!("cannot remove archive verifier temporary state: {error}"))?;
        validate(0o2770)?;

        let toolchain_extra = adapter.join(".toolchain/unexpected-tool");
        fs::set_permissions(
            adapter.join(".toolchain"),
            fs::Permissions::from_mode(0o755),
        )
        .map_err(|error| format!("cannot open archive verifier toolchain: {error}"))?;
        fs::write(&toolchain_extra, b"unexpected\n")
            .map_err(|error| format!("cannot write archive verifier toolchain extra: {error}"))?;
        fs::set_permissions(
            adapter.join(".toolchain"),
            fs::Permissions::from_mode(0o555),
        )
        .map_err(|error| format!("cannot freeze archive verifier toolchain: {error}"))?;
        let toolchain_error = match validate_active(0o2770) {
            Err(error) => error,
            Ok(()) => {
                return Err(
                    "active transition accepted an unexpected immutable toolchain member"
                        .to_owned(),
                );
            }
        };
        if !toolchain_error.contains("extra=") || !toolchain_error.contains("unexpected-tool") {
            return Err("immutable toolchain mismatch diagnostic is not exact".to_owned());
        }
        fs::set_permissions(
            adapter.join(".toolchain"),
            fs::Permissions::from_mode(0o755),
        )
        .map_err(|error| format!("cannot reopen archive verifier toolchain: {error}"))?;
        fs::remove_file(&toolchain_extra)
            .map_err(|error| format!("cannot remove archive verifier toolchain extra: {error}"))?;
        fs::set_permissions(
            adapter.join(".toolchain"),
            fs::Permissions::from_mode(0o555),
        )
        .map_err(|error| format!("cannot refreeze archive verifier toolchain: {error}"))?;
        validate(0o2770)?;

        let authority_sibling = parent.join("unexpected-authority");
        fs::create_dir(&authority_sibling)
            .map_err(|error| format!("cannot create archive verifier sibling: {error}"))?;
        if validate(0o2770).is_ok() {
            return Err("archive transition accepted an unexpected authority sibling".to_owned());
        }
        fs::remove_dir(&authority_sibling)
            .map_err(|error| format!("cannot remove archive verifier sibling: {error}"))?;

        let adapter_sibling = adapter.join("unexpected-output.a");
        fs::write(&adapter_sibling, b"unexpected\n")
            .map_err(|error| format!("cannot write archive verifier output: {error}"))?;
        if validate(0o2770).is_ok() {
            return Err("archive transition accepted an unexpected adapter member".to_owned());
        }
        fs::remove_file(&adapter_sibling)
            .map_err(|error| format!("cannot remove archive verifier output: {error}"))?;

        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o770))
            .map_err(|error| format!("cannot clear archive verifier temporary setgid: {error}"))?;
        if validate(0o2770).is_ok() {
            return Err("archive transition accepted a cleared temporary setgid bit".to_owned());
        }
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o2770))
            .map_err(|error| format!("cannot restore archive verifier temporary mode: {error}"))?;

        fs::set_permissions(&parent, fs::Permissions::from_mode(0o550))
            .map_err(|error| format!("cannot simulate cleared parent setgid: {error}"))?;
        if validate(0o2550).is_ok() {
            return Err("archive transition accepted a cleared parent setgid bit".to_owned());
        }
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o2550))
            .map_err(|error| format!("cannot set archive verifier sealed mode: {error}"))?;
        validate(0o2550)?;
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o2770))
            .map_err(|error| format!("cannot restore archive verifier parent mode: {error}"))?;
        validate(0o2770)?;

        let replacement = parent.join("replacement-adapter");
        stage_adapter(&replacement, "replacement")?;
        open_fixture_tree_for_cleanup(&adapter)?;
        fs::remove_dir_all(&adapter)
            .map_err(|error| format!("cannot remove original adapter: {error}"))?;
        fs::rename(&replacement, &adapter)
            .map_err(|error| format!("cannot substitute archive adapter: {error}"))?;
        if validate(0o2770).is_ok() {
            return Err("archive transition accepted an adapter identity substitution".to_owned());
        }
        Ok(())
    })();
    let cleanup = open_fixture_tree_for_cleanup(&root).and_then(|()| {
        fs::remove_dir_all(&root)
            .map_err(|error| format!("cannot remove archive transition verifier root: {error}"))
    });
    result.and(cleanup)
}

#[cfg(target_os = "macos")]
pub(crate) fn verify_macos_archive_cleanup_principal_for_integration() -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt as _, symlink};

    let platform = ReleasePlatform::MacosAarch64;
    let sudo = crate::command::resolve_absolute_standard_executable(Path::new("/usr/bin/sudo"))
        .map_err(|error| format!("cannot bind archive cleanup verifier sudo: {error}"))?
        .invocation_path()
        .to_path_buf();
    let tools = resolve_posix_adapter_tools(platform)?;
    let trusted_owner = nix::unistd::geteuid().as_raw();
    let trusted_group = nix::unistd::getegid().as_raw();
    let candidate_owner = trusted_owner
        .checked_add(100_000)
        .ok_or_else(|| "archive cleanup verifier candidate uid overflowed".to_owned())?;
    let temporary_root = fs::canonicalize("/private/tmp")
        .map_err(|error| format!("cannot bind archive cleanup verifier root: {error}"))?;
    let mut root = None;
    for _ in 0..16 {
        let sequence = POSIX_ARCHIVE_TRANSITION_VERIFIER_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let candidate = temporary_root.join(format!(
            "hell-archive-cleanup-principal-{}-{sequence}",
            std::process::id()
        ));
        match fs::create_dir(&candidate) {
            Ok(()) => {
                root = Some(candidate);
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(format!(
                    "cannot create archive cleanup verifier root: {error}"
                ));
            }
        }
    }
    let root = root.ok_or_else(|| "archive cleanup verifier allocation exhausted".to_owned())?;
    let work = root.join("work");
    let nested = work.join("candidate-owned");
    let child = nested.join("child");
    let member = child.join("member.o");
    let sentinel = root.join("sentinel");
    let escaped = nested.join("sentinel-link");
    let expired = work.join("expired");
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(30))
        .ok_or_else(|| "archive cleanup verifier deadline overflowed".to_owned())?;
    let result = (|| {
        fs::create_dir(&work)
            .and_then(|()| fs::create_dir(&nested))
            .and_then(|()| fs::create_dir(&child))
            .and_then(|()| fs::write(&member, b"member\n"))
            .and_then(|()| fs::write(&sentinel, b"sentinel\n"))
            .and_then(|()| symlink(&sentinel, &escaped))
            .and_then(|()| fs::create_dir(&expired))
            .map_err(|error| format!("cannot create archive cleanup principal fixture: {error}"))?;
        let candidate = candidate_owner.to_string();
        for directory in [&nested, &child, &expired] {
            trusted_tool_status_before(
                deadline,
                &sudo,
                &tools.change_owner,
                [
                    candidate.as_str(),
                    path_text(directory, "candidate-owned cleanup verifier directory")?,
                ],
            )?;
            trusted_tool_status_before(
                deadline,
                &sudo,
                &tools.chmod,
                posix_chmod_arguments(
                    platform,
                    "700",
                    path_text(directory, "candidate-owned cleanup verifier mode")?,
                )?,
            )?;
        }
        trusted_tool_status_before(
            deadline,
            &sudo,
            &tools.chmod,
            [
                "+a",
                "everyone allow read",
                path_text(&child, "candidate-owned cleanup verifier ACL")?,
            ],
        )?;
        if fs::read_dir(&nested).is_ok_and(|mut entries| entries.next().is_some()) {
            return Err(
                "trusted runner retained candidate-owned directory traversal before transition"
                    .to_owned(),
            );
        }
        remove_posix_no_follow_forest(
            &[PosixNoFollowRemovalRoot {
                directory: &work,
                retained_child: Some(&expired),
            }],
            PosixNoFollowRemovalPolicy {
                entry_limit: 32,
                depth_limit: 8,
                operation_limit: 128,
                deadline,
            },
            || Ok(()),
            |path| {
                transition_posix_mutable_directory_to_cleanup_owner(
                    platform,
                    &sudo,
                    &tools,
                    path,
                    trusted_owner,
                    trusted_group,
                    deadline,
                )
            },
            |path| {
                trusted_tool_status_before(
                    deadline,
                    &sudo,
                    &tools.remove_file,
                    [
                        "-f",
                        "--",
                        path_text(path, "archive cleanup verifier member")?,
                    ],
                )
            },
            |path| {
                trusted_tool_status_before(
                    deadline,
                    &sudo,
                    &tools.remove_directory,
                    ["--", path_text(path, "archive cleanup verifier directory")?],
                )
            },
        )?;
        if fs::read(&sentinel)
            .map_err(|error| format!("cannot read archive cleanup sentinel: {error}"))?
            != b"sentinel\n"
            || fs::symlink_metadata(&nested).is_ok()
        {
            return Err(
                "archive cleanup principal transition followed an escape or retained its tree"
                    .to_owned(),
            );
        }
        let expired_before = fs::symlink_metadata(&expired)
            .map_err(|error| format!("cannot inspect expired cleanup fixture: {error}"))?;
        let expired_error = transition_posix_mutable_directory_to_cleanup_owner(
            platform,
            &sudo,
            &tools,
            &expired,
            trusted_owner,
            trusted_group,
            Instant::now(),
        )
        .expect_err("expired cleanup transition must reject before a trusted mutation");
        let expired_after = fs::symlink_metadata(&expired)
            .map_err(|error| format!("cannot revalidate expired cleanup fixture: {error}"))?;
        if !expired_error.contains("deadline")
            || expired_before.uid() != candidate_owner
            || expired_after.uid() != candidate_owner
            || expired_before.mode() != expired_after.mode()
        {
            return Err("expired cleanup transition launched a late authority mutation".to_owned());
        }
        Ok(())
    })();
    let cleanup = trusted_tool_status(
        &sudo,
        &tools.remove_file,
        [
            "-rf",
            "--",
            path_text(&root, "archive cleanup verifier finalizer")?,
        ],
    );
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(()), Err(cleanup)) => Err(cleanup),
        (Err(primary), Err(cleanup)) => Err(format!(
            "{primary}; archive cleanup verifier finalizer also failed: {cleanup}"
        )),
    }
}

#[cfg(unix)]
fn seal_posix_archive_adapter_authority<'a>(
    protection: &PosixSourceProtection,
    normalizer: &'a PosixAdapterProtection,
    archive_adapter: &mut crate::command::NativeArchiveAdapter,
    authorization_deadline: Option<Instant>,
) -> Result<PosixArchiveAdapterSeal<'a>, String> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let adapter = archive_adapter
        .directory_path()
        .ok_or_else(|| "macOS archive adapter directory is absent".to_owned())?
        .to_path_buf();
    let adapter_name = adapter
        .file_name()
        .ok_or_else(|| "native archive adapter name is absent".to_owned())?;
    if !protection.active || adapter.parent() != Some(&protection.archive_adapter) {
        return Err("native archive adapter child is outside its authority".to_owned());
    }
    require_posix_adapter_unchanged(normalizer)?;
    let stack_work = protection
        .stack_work
        .as_ref()
        .ok_or_else(|| "candidate Stack work authority is absent".to_owned())?;
    let stack_work_identity = protection
        .stack_work_identity
        .as_ref()
        .ok_or_else(|| "candidate Stack work authority identity is absent".to_owned())?;
    if stack_work != &protection.oracle.join(".stack-work")
        || posix_object_identity(stack_work)? != *stack_work_identity
    {
        return Err("candidate Stack work authority changed before sealing".to_owned());
    }
    let parent_metadata = fs::symlink_metadata(&protection.archive_adapter)
        .map_err(|error| format!("cannot inspect native archive adapter authority: {error}"))?;
    let adapter_metadata = fs::symlink_metadata(&adapter)
        .map_err(|error| format!("cannot inspect native archive adapter: {error}"))?;
    let work_directory = adapter.join(".stack-work");
    let temporary_directory = work_directory.join("tmp");
    let input_staging = adapter.join(".authority/inputs");
    let work_metadata = fs::symlink_metadata(&work_directory)
        .map_err(|error| format!("cannot inspect candidate Stack work directory: {error}"))?;
    let temporary_metadata = fs::symlink_metadata(&temporary_directory)
        .map_err(|error| format!("cannot inspect candidate Stack temporary directory: {error}"))?;
    let input_staging_metadata = fs::symlink_metadata(&input_staging)
        .map_err(|error| format!("cannot inspect native archive input staging: {error}"))?;
    if parent_metadata.file_type().is_symlink()
        || !parent_metadata.is_dir()
        || posix_object_identity(&protection.archive_adapter)?
            != protection.archive_adapter_identity
        || parent_metadata.uid() != protection.archive_adapter_owner
        || parent_metadata.gid() != protection.archive_adapter_group
        || parent_metadata.permissions().mode() & 0o7777 != 0o2770
        || adapter_metadata.file_type().is_symlink()
        || !adapter_metadata.is_dir()
        || adapter_metadata.uid() != protection.archive_adapter_owner
        || adapter_metadata.gid() != protection.archive_adapter_group
        || adapter_metadata.permissions().mode() & 0o7777 != 0o755
        || work_metadata.file_type().is_symlink()
        || !work_metadata.is_dir()
        || work_metadata.uid() != protection.archive_adapter_owner
        || work_metadata.permissions().mode() & 0o7777 != 0o700
        || temporary_metadata.file_type().is_symlink()
        || !temporary_metadata.is_dir()
        || temporary_metadata.uid() != protection.archive_adapter_owner
        || temporary_metadata.permissions().mode() & 0o7777 != 0o770
        || input_staging_metadata.file_type().is_symlink()
        || !input_staging_metadata.is_dir()
        || input_staging_metadata.uid() != protection.archive_adapter_owner
        || input_staging_metadata.permissions().mode() & 0o7777 != 0o700
    {
        return Err("native archive adapter authority differs before sealing".to_owned());
    }
    require_exact_directory_members(
        &protection.archive_adapter,
        &[adapter_name.to_os_string()],
        "native archive adapter authority",
    )?;
    let group = protection.archive_adapter_group.to_string();
    for path in [
        &adapter,
        work_directory.as_path(),
        temporary_directory.as_path(),
    ] {
        trusted_tool_status(
            &protection.sudo,
            &protection.tools.change_group,
            [
                group.as_str(),
                path_text(path, "native archive adapter child")?,
            ],
        )?;
    }
    let candidate_group = protection.candidate_primary_gid.to_string();
    trusted_tool_status(
        &protection.sudo,
        &protection.tools.change_group,
        [
            candidate_group.as_str(),
            path_text(&input_staging, "native archive input staging")?,
        ],
    )?;
    trusted_tool_status(
        &protection.sudo,
        &protection.tools.chmod,
        posix_chmod_arguments(
            protection.platform,
            "2755",
            path_text(&adapter, "native archive adapter")?,
        )?,
    )?;
    trusted_tool_status(
        &protection.sudo,
        &protection.tools.chmod,
        posix_chmod_arguments(
            protection.platform,
            "2710",
            path_text(&input_staging, "native archive input staging")?,
        )?,
    )?;
    let sealed_input_staging = fs::symlink_metadata(&input_staging)
        .map_err(|error| format!("cannot retain sealed native archive input staging: {error}"))?;
    if sealed_input_staging.file_type().is_symlink()
        || !sealed_input_staging.is_dir()
        || sealed_input_staging.uid() != protection.archive_adapter_owner
        || sealed_input_staging.gid() != protection.candidate_primary_gid
        || sealed_input_staging.permissions().mode() & 0o7777 != 0o2710
    {
        return Err("native archive input staging differs after seal transition".to_owned());
    }
    trusted_tool_status(
        &protection.sudo,
        &protection.tools.chmod,
        posix_chmod_arguments(
            protection.platform,
            "3770",
            path_text(&work_directory, "candidate Stack work directory")?,
        )?,
    )?;
    trusted_tool_status(
        &protection.sudo,
        &protection.tools.chmod,
        posix_chmod_arguments(
            protection.platform,
            "2770",
            path_text(&temporary_directory, "candidate Stack temporary directory")?,
        )?,
    )?;
    let adapter_identity = posix_object_identity(&adapter)?;
    let work_directory_identity = posix_object_identity(&work_directory)?;
    let temporary_directory_identity = posix_object_identity(&temporary_directory)?;
    require_posix_archive_adapter_transition_state(PosixArchiveAdapterTransitionState {
        parent: &protection.archive_adapter,
        parent_identity: &protection.archive_adapter_identity,
        parent_owner: protection.archive_adapter_owner,
        parent_group: protection.archive_adapter_group,
        parent_mode: 0o2770,
        adapter: &adapter,
        adapter_identity: &adapter_identity,
        work_directory: &work_directory,
        work_directory_identity: &work_directory_identity,
        temporary_directory: &temporary_directory,
        temporary_directory_identity: &temporary_directory_identity,
    })?;
    trusted_tool_status(
        &protection.sudo,
        &protection.tools.chmod,
        posix_chmod_arguments(
            protection.platform,
            "2550",
            path_text(
                &protection.archive_adapter,
                "native archive adapter authority",
            )?,
        )?,
    )?;
    let sealed = PosixArchiveAdapterSeal {
        platform: protection.platform,
        parent: protection.archive_adapter.clone(),
        parent_identity: protection.archive_adapter_identity.clone(),
        parent_owner: protection.archive_adapter_owner,
        parent_group: protection.archive_adapter_group,
        adapter,
        adapter_identity,
        work_directory,
        work_directory_identity,
        temporary_directory,
        temporary_directory_identity,
        source_parent: protection.directory.clone(),
        source_parent_identity: protection.directory_identity.clone(),
        source: protection.oracle.clone(),
        source_identity: posix_object_identity(&protection.oracle)?,
        stack_work: stack_work.clone(),
        stack_work_identity: stack_work_identity.clone(),
        candidate_uid: protection.candidate_uid,
        candidate_primary_gid: protection.candidate_primary_gid,
        quiescence_receipt: None,
        normalizer,
        sudo: protection.sudo.clone(),
        tools: protection.tools.clone(),
    };
    if let Err(error) =
        require_posix_archive_adapter_transition_state(PosixArchiveAdapterTransitionState {
            parent: &sealed.parent,
            parent_identity: &sealed.parent_identity,
            parent_owner: sealed.parent_owner,
            parent_group: sealed.parent_group,
            parent_mode: 0o2550,
            adapter: &sealed.adapter,
            adapter_identity: &sealed.adapter_identity,
            work_directory: &sealed.work_directory,
            work_directory_identity: &sealed.work_directory_identity,
            temporary_directory: &sealed.temporary_directory,
            temporary_directory_identity: &sealed.temporary_directory_identity,
        })
    {
        return Err(error);
    }
    if let Err(error) = archive_adapter.retain_sealed_authority(
        protection.archive_adapter_group,
        protection.candidate_uid,
        authorization_deadline,
    ) {
        return Err(format!(
            "{error}; archive restoration skipped without an exact quiescence receipt"
        ));
    }
    Ok(sealed)
}

#[cfg(unix)]
fn cleanup_posix_sources(protection: &mut PosixSourceProtection) -> Result<(), String> {
    if !protection.active {
        return Ok(());
    }
    validate_posix_sources(protection, "before POSIX source cleanup")?;
    cleanup_posix_source_paths(
        protection.platform,
        &protection.sudo,
        &protection.tools,
        &protection.installation_root,
        &protection.installation_root_identity,
        &protection.directory,
        &protection.directory_identity,
    )?;
    protection.active = false;
    Ok(())
}

#[cfg(unix)]
fn cleanup_posix_source_paths(
    platform: ReleasePlatform,
    sudo: &Path,
    tools: &PosixAdapterTools,
    installation_root: &Path,
    installation_root_identity: &PosixObjectIdentity,
    directory: &Path,
    directory_identity: &PosixObjectIdentity,
) -> Result<(), String> {
    if validate_posix_adapter_installation_root(platform, installation_root)? != installation_root
        || posix_object_identity(installation_root)? != *installation_root_identity
        || directory.parent() != Some(installation_root)
        || !directory
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("hell-rs-posix-sources-"))
        || posix_object_identity(directory)? != *directory_identity
    {
        return Err("POSIX source cleanup authority changed".to_owned());
    }
    trusted_tool_status(
        sudo,
        &tools.remove_file,
        ["-rf", "--", path_text(directory, "POSIX source cleanup")?],
    )
}

#[cfg(unix)]
fn posix_source_cleanup_is_exact(
    installation_root: &Path,
    directory: &Path,
    candidate: &Path,
    oracle: &Path,
    transient: &Path,
    archive_adapter: &Path,
    retained_oracle: &Path,
) -> bool {
    directory.parent() == Some(installation_root)
        && directory
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("hell-rs-posix-sources-"))
        && candidate == directory.join("candidate")
        && oracle == directory.join("oracle")
        && transient == directory.join("release-gate-transient")
        && archive_adapter == directory.join("archive-adapter")
        && retained_oracle == directory.join("retained-oracle")
}

fn path_text<'a>(path: &'a Path, label: &str) -> Result<&'a str, String> {
    path.to_str()
        .ok_or_else(|| format!("{label} path is not UTF-8"))
}

#[cfg(unix)]
impl Drop for PosixAdapterProtection {
    fn drop(&mut self) {
        let _ = cleanup_posix_adapter(self);
    }
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct PosixObjectIdentity {
    device: u64,
    inode: u64,
    owner: u32,
    group: u32,
    mode: u32,
}

#[cfg(unix)]
#[derive(Clone, Debug)]
struct PosixAdapterTools {
    mkdir: crate::command::ResolvedStandardExecutable,
    copy: crate::command::ResolvedStandardExecutable,
    chmod: crate::command::ResolvedStandardExecutable,
    change_owner: crate::command::ResolvedStandardExecutable,
    change_group: crate::command::ResolvedStandardExecutable,
    remove_file: crate::command::ResolvedStandardExecutable,
    remove_directory: crate::command::ResolvedStandardExecutable,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PosixAdapterToolPaths {
    mkdir: &'static str,
    copy: &'static str,
    chmod: &'static str,
    change_owner: &'static str,
    change_group: &'static str,
    remove_file: &'static str,
    remove_directory: &'static str,
}

#[cfg(unix)]
fn posix_adapter_tool_paths(platform: ReleasePlatform) -> Result<PosixAdapterToolPaths, String> {
    match platform {
        ReleasePlatform::LinuxX86_64 => Ok(PosixAdapterToolPaths {
            mkdir: "/usr/bin/mkdir",
            copy: "/usr/bin/cp",
            chmod: "/usr/bin/chmod",
            change_owner: "/usr/bin/chown",
            change_group: "/usr/bin/chgrp",
            remove_file: "/usr/bin/rm",
            remove_directory: "/usr/bin/rmdir",
        }),
        ReleasePlatform::MacosAarch64 => Ok(PosixAdapterToolPaths {
            mkdir: "/bin/mkdir",
            copy: "/bin/cp",
            chmod: "/bin/chmod",
            change_owner: "/usr/sbin/chown",
            change_group: "/usr/bin/chgrp",
            remove_file: "/bin/rm",
            remove_directory: "/bin/rmdir",
        }),
        ReleasePlatform::WindowsX86_64 => {
            Err("Windows platform selected POSIX adapter tools".to_owned())
        }
    }
}

#[cfg(unix)]
fn resolve_posix_adapter_tools(platform: ReleasePlatform) -> Result<PosixAdapterTools, String> {
    let paths = posix_adapter_tool_paths(platform)?;
    let resolve = |path: &str| {
        crate::command::resolve_absolute_standard_executable(Path::new(path))
            .map_err(|error| format!("cannot bind POSIX adapter installation tool: {error}"))
    };
    Ok(PosixAdapterTools {
        mkdir: resolve(paths.mkdir)?,
        copy: resolve(paths.copy)?,
        chmod: resolve(paths.chmod)?,
        change_owner: resolve(paths.change_owner)?,
        change_group: resolve(paths.change_group)?,
        remove_file: resolve(paths.remove_file)?,
        remove_directory: resolve(paths.remove_directory)?,
    })
}

#[cfg(unix)]
fn posix_object_identity(path: &Path) -> Result<PosixObjectIdentity, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect POSIX authority {}: {error}", path.display()))?;
    Ok(posix_object_identity_from_metadata(&metadata))
}

#[cfg(unix)]
fn posix_object_identity_from_metadata(metadata: &fs::Metadata) -> PosixObjectIdentity {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    PosixObjectIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        owner: metadata.uid(),
        group: metadata.gid(),
        mode: metadata.permissions().mode() & 0o7777,
    }
}

#[cfg(unix)]
fn posix_same_object(left: &PosixObjectIdentity, right: &PosixObjectIdentity) -> bool {
    left.device == right.device
        && left.inode == right.inode
        && left.owner == right.owner
        && left.group == right.group
}

#[cfg(unix)]
fn posix_adapter_installation_root(platform: ReleasePlatform) -> Result<PathBuf, String> {
    let chain = posix_adapter_authority_chain(platform)?;
    validate_posix_adapter_installation_root(
        platform,
        Path::new(chain.last().expect("POSIX authority chain is nonempty")),
    )
}

#[cfg(unix)]
fn posix_adapter_authority_chain(
    platform: ReleasePlatform,
) -> Result<&'static [&'static str], String> {
    const LINUX: [&str; 3] = ["/", "/var", "/var/tmp"];
    const MACOS: [&str; 4] = ["/", "/private", "/private/var", "/private/var/tmp"];
    match platform {
        ReleasePlatform::LinuxX86_64 => Ok(&LINUX),
        ReleasePlatform::MacosAarch64 => Ok(&MACOS),
        ReleasePlatform::WindowsX86_64 => {
            Err("Windows platform selected the POSIX adapter installation root".to_owned())
        }
    }
}

#[cfg(unix)]
fn validate_posix_adapter_installation_root(
    platform: ReleasePlatform,
    root: &Path,
) -> Result<PathBuf, String> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let authority_chain = posix_adapter_authority_chain(platform)?;
    if root != Path::new(authority_chain[authority_chain.len() - 1]) {
        return Err("POSIX adapter installation root differs from policy".to_owned());
    }
    for (index, entry) in authority_chain.iter().copied().enumerate() {
        let path = Path::new(entry);
        let metadata = fs::symlink_metadata(path).map_err(|error| {
            format!("cannot inspect POSIX executable authority {entry}: {error}")
        })?;
        let canonical = fs::canonicalize(path).map_err(|error| {
            format!("cannot canonicalize POSIX executable authority {entry}: {error}")
        })?;
        let mode = metadata.permissions().mode();
        let final_sticky_root = index + 1 == authority_chain.len();
        if canonical != path
            || metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || if final_sticky_root {
                mode & 0o7777 != 0o1777
            } else {
                mode & 0o022 != 0 || mode & 0o005 != 0o005
            }
        {
            return Err(format!(
                "POSIX executable authority {entry} is redirected or differs from its root-owned traversal/sticky policy"
            ));
        }
    }
    Ok(root.to_path_buf())
}

#[cfg(unix)]
fn stage_posix_executable(
    platform: ReleasePlatform,
    sudo: &Path,
    source_path: &Path,
    staged_name: &'static str,
) -> Result<PosixAdapterProtection, String> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    if !matches!(staged_name, "hell-ci" | "cargo" | "cargo-deny" | "stack") {
        return Err("trusted POSIX executable name differs from policy".to_owned());
    }
    let original = fs::symlink_metadata(source_path)
        .map_err(|error| format!("cannot inspect trusted POSIX executable: {error}"))?;
    if original.file_type().is_symlink() || !original.is_file() {
        return Err("trusted POSIX executable is not a real file".to_owned());
    }
    let source = fs::canonicalize(source_path)
        .map_err(|error| format!("cannot canonicalize trusted POSIX executable: {error}"))?;
    let source_sha256 = hell_testkit::sha256_file(&source)
        .map_err(|error| format!("cannot hash trusted POSIX adapter: {error}"))?;
    let source_identity = posix_object_identity(&source)?;
    let installation_root = posix_adapter_installation_root(platform)?;
    let installation_root_identity = posix_object_identity(&installation_root)?;
    let tools = resolve_posix_adapter_tools(platform)?;
    let sequence = POSIX_ADAPTER_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let directory = installation_root.join(format!(
        "hell-rs-posix-{staged_name}-{}-{sequence}-{}",
        std::process::id(),
        source_sha256.hex()
    ));
    let directory_text = directory
        .to_str()
        .ok_or_else(|| "trusted POSIX adapter directory is not UTF-8".to_owned())?;
    trusted_tool_status(sudo, &tools.mkdir, ["-m", "0555", "--", directory_text])
        .map_err(|error| format!("cannot reserve trusted POSIX adapter directory: {error}"))?;
    let directory_identity = posix_object_identity(&directory)?;
    let staged = directory.join(staged_name);
    let staged_text = staged
        .to_str()
        .ok_or_else(|| "trusted POSIX adapter path is not UTF-8".to_owned())?;
    let source_text = source
        .to_str()
        .ok_or_else(|| "trusted POSIX adapter source is not UTF-8".to_owned())?;
    let mut cleanup = true;
    let result = (|| {
        trusted_tool_status(sudo, &tools.copy, ["--", source_text, staged_text])?;
        trusted_tool_status(
            sudo,
            &tools.chmod,
            posix_chmod_arguments(platform, "0555", staged_text)?,
        )?;

        let canonical_directory = fs::canonicalize(&directory)
            .map_err(|error| format!("cannot canonicalize POSIX adapter directory: {error}"))?;
        let canonical_staged = fs::canonicalize(&staged)
            .map_err(|error| format!("cannot canonicalize staged POSIX adapter: {error}"))?;
        let directory_metadata = fs::symlink_metadata(&directory)
            .map_err(|error| format!("cannot inspect POSIX adapter directory: {error}"))?;
        let staged_metadata = fs::symlink_metadata(&staged)
            .map_err(|error| format!("cannot inspect staged POSIX adapter: {error}"))?;
        let adapter_identity = posix_object_identity(&staged)?;
        if validate_posix_adapter_installation_root(platform, &installation_root)?
            != installation_root
            || posix_object_identity(&installation_root)? != installation_root_identity
            || posix_object_identity(&source)? != source_identity
            || hell_testkit::sha256_file(&source)
                .map_err(|error| format!("cannot rehash trusted POSIX adapter source: {error}"))?
                != source_sha256
            || canonical_directory != directory
            || canonical_staged != staged
            || directory_metadata.file_type().is_symlink()
            || !directory_metadata.is_dir()
            || staged_metadata.file_type().is_symlink()
            || !staged_metadata.is_file()
            || directory_metadata.uid() != 0
            || directory_metadata.gid() != 0
            || staged_metadata.uid() != 0
            || staged_metadata.gid() != 0
            || directory_metadata.permissions().mode() & 0o7777 != 0o555
            || staged_metadata.permissions().mode() & 0o7777 != 0o555
            || directory_identity != posix_object_identity(&directory)?
            || hell_testkit::sha256_file(&staged)
                .map_err(|error| format!("cannot rehash staged POSIX adapter: {error}"))?
                != source_sha256
        {
            return Err("staged POSIX adapter identity or permissions differ".to_owned());
        }
        Ok(PosixAdapterProtection {
            platform,
            installation_root: installation_root.clone(),
            installation_root_identity: installation_root_identity.clone(),
            directory: directory.clone(),
            directory_identity: directory_identity.clone(),
            adapter: staged.clone(),
            adapter_identity,
            sha256: source_sha256,
            staged_name,
            sudo: sudo.to_path_buf(),
            tools: tools.clone(),
        })
    })();
    if result.is_ok() {
        cleanup = false;
    }
    if cleanup {
        let _ = cleanup_posix_adapter_paths(
            platform,
            sudo,
            &tools,
            &installation_root,
            &installation_root_identity,
            &directory,
            &directory_identity,
            &staged,
            staged_name,
        );
    }
    result
}

#[cfg(unix)]
fn cleanup_posix_adapter(protection: &PosixAdapterProtection) -> Result<(), String> {
    if posix_object_identity(&protection.adapter)? != protection.adapter_identity
        || hell_testkit::sha256_file(&protection.adapter)
            .map_err(|error| format!("cannot rehash POSIX adapter before cleanup: {error}"))?
            != protection.sha256
    {
        return Err("POSIX adapter identity changed before cleanup".to_owned());
    }
    cleanup_posix_adapter_paths(
        protection.platform,
        &protection.sudo,
        &protection.tools,
        &protection.installation_root,
        &protection.installation_root_identity,
        &protection.directory,
        &protection.directory_identity,
        &protection.adapter,
        protection.staged_name,
    )
}

#[cfg(unix)]
fn cleanup_posix_adapter_paths(
    platform: ReleasePlatform,
    sudo: &Path,
    tools: &PosixAdapterTools,
    installation_root: &Path,
    installation_root_identity: &PosixObjectIdentity,
    directory: &Path,
    directory_identity: &PosixObjectIdentity,
    adapter: &Path,
    staged_name: &str,
) -> Result<(), String> {
    if validate_posix_adapter_installation_root(platform, installation_root)? != installation_root
        || posix_object_identity(installation_root)? != *installation_root_identity
        || !posix_adapter_cleanup_is_exact(installation_root, directory, adapter, staged_name)
        || posix_object_identity(directory)? != *directory_identity
    {
        return Err("POSIX adapter cleanup authority changed".to_owned());
    }
    let adapter_text = adapter
        .to_str()
        .ok_or_else(|| "POSIX adapter cleanup path is not UTF-8".to_owned())?;
    let directory_text = directory
        .to_str()
        .ok_or_else(|| "POSIX adapter cleanup directory is not UTF-8".to_owned())?;
    trusted_tool_status(sudo, &tools.remove_file, ["-f", "--", adapter_text])?;
    trusted_tool_status(sudo, &tools.remove_directory, ["--", directory_text])
}

#[cfg(unix)]
fn posix_chmod_arguments<'a>(
    platform: ReleasePlatform,
    mode: &'a str,
    path: &'a str,
) -> Result<Vec<&'a str>, String> {
    match platform {
        ReleasePlatform::LinuxX86_64 => Ok(vec![mode, "--", path]),
        ReleasePlatform::MacosAarch64 => Ok(vec![mode, path]),
        ReleasePlatform::WindowsX86_64 => {
            Err("Windows platform selected POSIX chmod arguments".to_owned())
        }
    }
}

#[cfg(unix)]
fn posix_acl_removal_arguments(
    platform: ReleasePlatform,
    recursive: bool,
    path: &str,
) -> Result<[&str; 2], String> {
    match platform {
        ReleasePlatform::MacosAarch64 => Ok([if recursive { "-RN" } else { "-N" }, path]),
        ReleasePlatform::LinuxX86_64 | ReleasePlatform::WindowsX86_64 => {
            Err("non-macOS platform selected POSIX ACL removal arguments".to_owned())
        }
    }
}

#[cfg(unix)]
fn posix_adapter_cleanup_is_exact(
    installation_root: &Path,
    directory: &Path,
    adapter: &Path,
    staged_name: &str,
) -> bool {
    directory.parent() == Some(installation_root)
        && adapter.parent() == Some(directory)
        && matches!(staged_name, "hell-ci" | "cargo" | "cargo-deny" | "stack")
        && adapter.file_name() == Some(std::ffi::OsStr::new(staged_name))
}

#[cfg(windows)]
#[derive(Debug)]
struct WindowsToolchainFile {
    relative: PathBuf,
    source: crate::command::WindowsBoundFileIdentity,
    staged: Option<crate::command::WindowsBoundFileIdentity>,
}

#[cfg(windows)]
#[derive(Debug)]
struct WindowsToolchainProtection {
    root: PathBuf,
    source_root: PathBuf,
    files: Vec<WindowsToolchainFile>,
    directories: Vec<PathBuf>,
    removed_directories: BTreeSet<PathBuf>,
    sealed: bool,
    closed: bool,
}

#[cfg(windows)]
impl WindowsToolchainProtection {
    fn expected_inventory(&self) -> BTreeSet<(PathBuf, bool)> {
        self.directories
            .iter()
            .cloned()
            .map(|path| (path, true))
            .chain(self.files.iter().map(|file| (file.relative.clone(), false)))
            .collect()
    }

    fn remaining_staged_inventory(&self) -> BTreeSet<(PathBuf, bool)> {
        self.directories
            .iter()
            .filter(|path| !self.removed_directories.contains(*path))
            .cloned()
            .map(|path| (path, true))
            .chain(
                self.files
                    .iter()
                    .filter(|file| file.staged.is_some())
                    .map(|file| (file.relative.clone(), false)),
            )
            .collect()
    }

    fn revalidate_until(&self, deadline: Instant) -> Result<(), String> {
        let expected = self.expected_inventory();
        if windows_toolchain_inventory_paths_until(&self.source_root, deadline)? != expected
            || windows_toolchain_inventory_paths_until(&self.root, deadline)? != expected
        {
            return Err("Windows toolchain closed inventory changed before use".to_owned());
        }
        for directory in &self.directories {
            if Instant::now() >= deadline {
                return Err("Windows toolchain revalidation exceeded its deadline".to_owned());
            }
            let source = self.source_root.join(directory);
            let staged = self.root.join(directory);
            if !fs::symlink_metadata(&source).is_ok_and(|metadata| metadata.is_dir())
                || !fs::symlink_metadata(&staged).is_ok_and(|metadata| metadata.is_dir())
            {
                return Err("Windows toolchain directory identity changed before use".to_owned());
            }
        }
        for file in &self.files {
            if Instant::now() >= deadline {
                return Err("Windows toolchain revalidation exceeded its deadline".to_owned());
            }
            let source = self.source_root.join(&file.relative);
            let staged = self.root.join(&file.relative);
            file.source.revalidate_retained_path_until_at(
                &source,
                deadline,
                crate::command::WindowsFileIdentityPhase::ToolchainSourceRevalidation,
                &file.relative,
            )?;
            let staged_identity = file.staged.as_ref().ok_or_else(|| {
                "staged Windows toolchain receipt was released before revalidation".to_owned()
            })?;
            staged_identity.revalidate_retained_path_until_at(
                &staged,
                deadline,
                crate::command::WindowsFileIdentityPhase::StagedToolchainPostSeal,
                &file.relative,
            )?;
            if staged_identity.size() != file.source.size()
                || staged_identity.sha256() != file.source.sha256()
            {
                return Err("staged Windows toolchain file identity changed before use".to_owned());
            }
        }
        Ok(())
    }

    fn promote_inventory_until(
        &self,
        deadline: Instant,
    ) -> Result<Vec<hell_testkit::BoundProgramInvocation>, String> {
        if !self.sealed {
            return Err("Windows toolchain inventory was promoted before DACL sealing".to_owned());
        }
        if Instant::now() >= deadline {
            return Err(
                "Windows toolchain receipt promotion exceeded its absolute deadline".to_owned(),
            );
        }
        self.revalidate_until(deadline)?;
        self.files
            .iter()
            .map(|file| {
                if Instant::now() >= deadline {
                    return Err(
                        "Windows toolchain receipt promotion exceeded its absolute deadline"
                            .to_owned(),
                    );
                }
                let staged = self.root.join(&file.relative);
                file.staged
                    .as_ref()
                    .ok_or_else(|| {
                        "staged Windows toolchain receipt was released before promotion".to_owned()
                    })?
                    .promote_program_invocation_until(&staged, deadline)
            })
            .collect()
    }

    fn revalidate_staged_until(&self, deadline: Instant) -> Result<(), String> {
        if windows_toolchain_inventory_paths_until(&self.root, deadline)?
            != self.remaining_staged_inventory()
        {
            return Err("staged Windows toolchain inventory changed before cleanup".to_owned());
        }
        for directory in &self.directories {
            if self.removed_directories.contains(directory) {
                continue;
            }
            if Instant::now() >= deadline {
                return Err(
                    "staged Windows toolchain revalidation exceeded its deadline".to_owned(),
                );
            }
            if !fs::symlink_metadata(self.root.join(directory))
                .is_ok_and(|metadata| metadata.is_dir())
            {
                return Err("staged Windows toolchain directory changed before cleanup".to_owned());
            }
        }
        for file in &self.files {
            let Some(identity) = file.staged.as_ref() else {
                continue;
            };
            if Instant::now() >= deadline {
                return Err(
                    "staged Windows toolchain revalidation exceeded its deadline".to_owned(),
                );
            }
            identity.revalidate_retained_path_until_at(
                &self.root.join(&file.relative),
                deadline,
                crate::command::WindowsFileIdentityPhase::StagedToolchainPostSeal,
                &file.relative,
            )?;
            if identity.size() != file.source.size() || identity.sha256() != file.source.sha256() {
                return Err("staged Windows toolchain file changed before cleanup".to_owned());
            }
        }
        Ok(())
    }

    fn cleanup_until(&mut self, deadline: Instant) -> Result<(), String> {
        if self.closed {
            return Ok(());
        }
        if Instant::now() >= deadline
            || fs::canonicalize(&self.root).ok().as_deref() != Some(self.root.as_path())
            || !fs::symlink_metadata(&self.root).is_ok_and(|metadata| metadata.is_dir())
        {
            return Err("Windows toolchain cleanup root authority changed".to_owned());
        }
        windows_confinement::reset_tree_until(&self.root, deadline)?;
        self.revalidate_staged_until(deadline)?;
        for file in &mut self.files {
            let Some(identity) = file.staged.take() else {
                continue;
            };
            if Instant::now() >= deadline {
                file.staged = Some(identity);
                return Err("Windows toolchain cleanup exceeded its absolute deadline".to_owned());
            }
            let path = self.root.join(&file.relative);
            drop(identity);
            if let Err(error) = fs::remove_file(&path) {
                let rebound = crate::command::WindowsBoundFileIdentity::bind_until_at(
                    &path,
                    deadline,
                    crate::command::WindowsFileIdentityPhase::StagedToolchainPostSeal,
                    &file.relative,
                );
                match rebound {
                    Ok(rebound)
                        if rebound.size() == file.source.size()
                            && rebound.sha256() == file.source.sha256() =>
                    {
                        file.staged = Some(rebound);
                        return Err(format!(
                            "cannot remove Windows toolchain file; exact cleanup receipt was retained: {error}"
                        ));
                    }
                    Ok(_) => {
                        return Err(format!(
                            "cannot remove Windows toolchain file and rebound identity changed: {error}"
                        ));
                    }
                    Err(rebind) => {
                        return Err(format!(
                            "cannot remove Windows toolchain file: {error}; additionally, exact cleanup receipt could not be retained: {rebind}"
                        ));
                    }
                }
            }
        }
        let mut directories = self.directories.clone();
        directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
        for directory in directories {
            if self.removed_directories.contains(&directory) {
                continue;
            }
            if Instant::now() >= deadline {
                return Err("Windows toolchain cleanup exceeded its absolute deadline".to_owned());
            }
            let path = self.root.join(&directory);
            if !fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.is_dir()) {
                return Err("Windows toolchain cleanup directory identity changed".to_owned());
            }
            fs::remove_dir(&path)
                .map_err(|error| format!("cannot remove Windows toolchain directory: {error}"))?;
            self.removed_directories.insert(directory);
        }
        self.closed = true;
        Ok(())
    }

    fn cleanup_until_with_retry(&mut self, deadline: Instant, context: &str) -> Result<(), String> {
        match self.cleanup_until(deadline) {
            Ok(()) => Ok(()),
            Err(primary) if Instant::now() < deadline => {
                self.cleanup_until(deadline).map_err(|retry| {
                    format!(
                        "{primary}; additionally, retained Windows {context} cleanup retry failed: {retry}"
                    )
                })
            }
            Err(primary) => Err(primary),
        }
    }
}

#[cfg(windows)]
fn windows_toolchain_inventory_paths_until(
    root: &Path,
    deadline: Instant,
) -> Result<BTreeSet<(PathBuf, bool)>, String> {
    use std::os::windows::fs::MetadataExt as _;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    let mut inventory = BTreeSet::from([(PathBuf::new(), true)]);
    let mut pending = vec![PathBuf::new()];
    while let Some(relative_parent) = pending.pop() {
        for entry in fs::read_dir(root.join(&relative_parent))
            .map_err(|error| format!("cannot enumerate Windows toolchain authority: {error}"))?
        {
            if Instant::now() >= deadline || inventory.len() >= WINDOWS_TOOLCHAIN_STAGE_ENTRY_LIMIT
            {
                return Err("Windows toolchain inventory exceeded its bound".to_owned());
            }
            let entry = entry
                .map_err(|error| format!("cannot inspect Windows toolchain authority: {error}"))?;
            let relative = relative_parent.join(entry.file_name());
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|error| format!("cannot inspect Windows toolchain authority: {error}"))?;
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err("Windows toolchain authority contains a reparse point".to_owned());
            }
            if metadata.is_dir() {
                inventory.insert((relative.clone(), true));
                pending.push(relative);
            } else if metadata.is_file() {
                inventory.insert((relative, false));
            } else {
                return Err("Windows toolchain authority contains a special entry".to_owned());
            }
        }
    }
    Ok(inventory)
}

#[cfg(windows)]
fn stage_windows_toolchain(
    authority: &crate::command::ResolvedWindowsRustupAuthority,
    candidate_root: &Path,
    envelope: WindowsToolchainConstructionEnvelope,
) -> Result<WindowsToolchainProtection, String> {
    stage_windows_toolchain_until(
        authority,
        candidate_root,
        envelope.construction_deadline,
        envelope.completion_deadline,
    )
}

#[cfg(windows)]
fn copy_windows_toolchain_file_until(
    source: &crate::command::WindowsBoundFileIdentity,
    destination: &Path,
    deadline: Instant,
    diagnostic_path: &Path,
) -> Result<(), String> {
    source.copy_to_new_until(destination, deadline, diagnostic_path)
}

#[cfg(windows)]
fn cleanup_partial_windows_toolchain_until(root: &Path, deadline: Instant) -> Result<(), String> {
    if !root.exists() {
        return Ok(());
    }
    windows_confinement::reset_tree_until(root, deadline).map_err(|error| {
        format!("partial Windows toolchain ACL reset failed before removal: {error}")
    })?;
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    let mut directories = Vec::new();
    while let Some(directory) = pending.pop() {
        if Instant::now() >= deadline
            || files.len() + directories.len() >= WINDOWS_TOOLCHAIN_STAGE_ENTRY_LIMIT
        {
            return Err("partial Windows toolchain cleanup exceeded its bound".to_owned());
        }
        directories.push(directory.clone());
        for entry in fs::read_dir(&directory)
            .map_err(|error| format!("cannot enumerate partial Windows toolchain: {error}"))?
        {
            if Instant::now() >= deadline
                || files.len() + directories.len() + pending.len()
                    >= WINDOWS_TOOLCHAIN_STAGE_ENTRY_LIMIT
            {
                return Err("partial Windows toolchain cleanup exceeded its bound".to_owned());
            }
            let entry = entry
                .map_err(|error| format!("cannot inspect partial Windows toolchain: {error}"))?;
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|error| format!("cannot inspect partial Windows toolchain: {error}"))?;
            if metadata.file_type().is_symlink() {
                return Err("partial Windows toolchain contains a redirected entry".to_owned());
            }
            if metadata.is_dir() {
                pending.push(entry.path());
            } else if metadata.is_file() {
                files.push(entry.path());
            } else {
                return Err("partial Windows toolchain contains a special entry".to_owned());
            }
        }
    }
    for file in files {
        if Instant::now() >= deadline {
            return Err("partial Windows toolchain cleanup exceeded its deadline".to_owned());
        }
        fs::remove_file(file)
            .map_err(|error| format!("cannot remove partial Windows toolchain file: {error}"))?;
    }
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for directory in directories {
        if Instant::now() >= deadline {
            return Err("partial Windows toolchain cleanup exceeded its deadline".to_owned());
        }
        fs::remove_dir(directory).map_err(|error| {
            format!("cannot remove partial Windows toolchain directory: {error}")
        })?;
    }
    Ok(())
}

#[cfg(windows)]
fn stage_windows_toolchain_until(
    authority: &crate::command::ResolvedWindowsRustupAuthority,
    candidate_root: &Path,
    execution_deadline: Instant,
    cleanup_deadline: Instant,
) -> Result<WindowsToolchainProtection, String> {
    stage_windows_toolchain_until_with_entry_gate(
        authority,
        candidate_root,
        execution_deadline,
        cleanup_deadline,
        |_, _| Ok(()),
    )
}

#[cfg(windows)]
fn seal_windows_toolchain_protection_until_with_entry_gate(
    protection: &mut WindowsToolchainProtection,
    deadline: Instant,
    entry_gate: impl FnMut(&Path, bool) -> Result<(), String>,
) -> Result<(), String> {
    windows_confinement::protect_tree_until_with_entry_gate(
        &protection.root,
        false,
        deadline,
        entry_gate,
    )?;
    if Instant::now() >= deadline {
        return Err("Windows toolchain protection exceeded its absolute deadline".to_owned());
    }
    protection.revalidate_until(deadline)?;
    protection.sealed = true;
    Ok(())
}

#[cfg(windows)]
fn stage_windows_toolchain_until_with_entry_gate(
    authority: &crate::command::ResolvedWindowsRustupAuthority,
    candidate_root: &Path,
    execution_deadline: Instant,
    cleanup_deadline: Instant,
    mut entry_gate: impl FnMut(&Path, bool) -> Result<(), String>,
) -> Result<WindowsToolchainProtection, String> {
    use std::os::windows::fs::MetadataExt as _;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    authority.revalidate_until(execution_deadline)?;
    let source_root = authority.toolchain_root().to_path_buf();
    let parent = candidate_root
        .parent()
        .ok_or_else(|| "candidate root has no authority parent".to_owned())?;
    let sequence = WINDOWS_TOOLCHAIN_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let root = parent.join(format!(
        "windows-rust-toolchain-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir(&root)
        .map_err(|error| format!("cannot create Windows toolchain authority: {error}"))?;

    let mut protection = WindowsToolchainProtection {
        root,
        source_root,
        files: Vec::new(),
        directories: vec![PathBuf::new()],
        removed_directories: BTreeSet::new(),
        sealed: false,
        closed: false,
    };
    let mut inventory_complete = false;
    let result = (|| {
        let mut pending = vec![PathBuf::new()];
        let mut total_bytes = 0_u64;
        while let Some(relative_parent) = pending.pop() {
            if Instant::now() >= execution_deadline {
                return Err("Windows toolchain staging exceeded its absolute deadline".to_owned());
            }
            let source_parent = protection.source_root.join(&relative_parent);
            let mut entries = Vec::new();
            for entry in fs::read_dir(&source_parent)
                .map_err(|error| format!("cannot enumerate selected Windows toolchain: {error}"))?
            {
                if Instant::now() >= execution_deadline
                    || protection.files.len() + protection.directories.len() + entries.len()
                        >= WINDOWS_TOOLCHAIN_STAGE_ENTRY_LIMIT
                {
                    return Err(
                        "selected Windows toolchain enumeration exceeded its bound".to_owned()
                    );
                }
                entries.push(entry.map_err(|error| {
                    format!("cannot inspect selected Windows toolchain: {error}")
                })?);
            }
            entries.sort_by_key(std::fs::DirEntry::file_name);
            for entry in entries {
                if Instant::now() >= execution_deadline {
                    return Err(
                        "Windows toolchain staging exceeded its absolute deadline".to_owned()
                    );
                }
                if protection.files.len() + protection.directories.len()
                    >= WINDOWS_TOOLCHAIN_STAGE_ENTRY_LIMIT
                {
                    return Err("selected Windows toolchain exceeds its entry bound".to_owned());
                }
                let relative = relative_parent.join(entry.file_name());
                if relative.components().any(|component| {
                    matches!(
                        component,
                        std::path::Component::Prefix(_)
                            | std::path::Component::RootDir
                            | std::path::Component::ParentDir
                            | std::path::Component::CurDir
                    )
                }) {
                    return Err(
                        "selected Windows toolchain contains a noncanonical path".to_owned()
                    );
                }
                let source = protection.source_root.join(&relative);
                let metadata = fs::symlink_metadata(&source).map_err(|error| {
                    format!("cannot inspect selected Windows toolchain: {error}")
                })?;
                if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                    return Err("selected Windows toolchain contains a reparse point".to_owned());
                }
                let staged = protection.root.join(&relative);
                if metadata.is_dir() {
                    fs::create_dir(&staged).map_err(|error| {
                        format!("cannot create staged Windows toolchain directory: {error}")
                    })?;
                    protection.directories.push(relative.clone());
                    pending.push(relative);
                } else if metadata.is_file() {
                    let identity = crate::command::WindowsBoundFileIdentity::bind_until_at(
                        &source,
                        execution_deadline,
                        crate::command::WindowsFileIdentityPhase::ToolchainSourceBinding,
                        &relative,
                    )?;
                    total_bytes = total_bytes
                        .checked_add(identity.size())
                        .filter(|bytes| *bytes <= WINDOWS_TOOLCHAIN_STAGE_BYTE_LIMIT)
                        .ok_or_else(|| {
                            "selected Windows toolchain exceeds its byte bound".to_owned()
                        })?;
                    copy_windows_toolchain_file_until(
                        &identity,
                        &staged,
                        execution_deadline,
                        &relative,
                    )?;
                    if Instant::now() >= execution_deadline {
                        return Err(
                            "Windows toolchain staging exceeded its absolute deadline".to_owned()
                        );
                    }
                    let staged_identity = crate::command::WindowsBoundFileIdentity::bind_until_at(
                        &staged,
                        execution_deadline,
                        crate::command::WindowsFileIdentityPhase::StagedToolchainBinding,
                        &relative,
                    )?;
                    protection.files.push(WindowsToolchainFile {
                        relative,
                        source: identity,
                        staged: Some(staged_identity),
                    });
                } else {
                    return Err("selected Windows toolchain contains a special entry".to_owned());
                }
            }
        }
        if Instant::now() >= execution_deadline {
            return Err("Windows toolchain staging exceeded its absolute deadline".to_owned());
        }
        inventory_complete = true;
        seal_windows_toolchain_protection_until_with_entry_gate(
            &mut protection,
            execution_deadline,
            &mut entry_gate,
        )?;
        Ok::<(), String>(())
    })();
    match result {
        Ok(()) => Ok(protection),
        Err(primary) => {
            let cleanup = if inventory_complete {
                protection.cleanup_until_with_retry(cleanup_deadline, "partial staging")
            } else {
                for file in &mut protection.files {
                    file.staged = None;
                }
                cleanup_partial_windows_toolchain_until(&protection.root, cleanup_deadline)
            };
            Err(match cleanup {
                Ok(()) => primary,
                Err(cleanup) => format!(
                    "{primary}; additionally, partial Windows toolchain cleanup failed: {cleanup}"
                ),
            })
        }
    }
}

#[cfg(windows)]
fn establish_candidate_process_confinement(
    _platform: ReleasePlatform,
    candidate_root: &Path,
    oracle_root: &Path,
    _candidate_inventory: &JsonValue,
    _oracle_inventory: &JsonValue,
    _candidate_sha: &str,
    target: &Path,
    output: &Path,
) -> Result<CandidateConfinement, String> {
    let toolchain_envelope = WindowsToolchainConstructionEnvelope::new()?;
    let cargo = crate::command::resolve_cargo_executable()?;
    let rustup = crate::command::resolve_windows_rustup_authority(&cargo, candidate_root)?;
    let mut toolchain = stage_windows_toolchain(&rustup, candidate_root, toolchain_envelope)?;
    let setup = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let staged_cargo = toolchain.root.join("bin/cargo.exe");
        let staged_rustc = toolchain.root.join("bin/rustc.exe");
        let staged_inventory_files =
            toolchain.promote_inventory_until(toolchain_envelope.construction_deadline)?;
        let staged_inventory_directories = toolchain
            .directories
            .iter()
            .map(|directory| toolchain.root.join(directory))
            .collect();
        let trusted_parent_path = std::env::var_os("PATH")
            .ok_or_else(|| "trusted Windows parent PATH is unavailable".to_owned())?;
        let trusted_parent_system_root = hell_testkit::capture_windows_standard_system_root()
            .map_err(|error| format!("cannot bind trusted Windows SystemRoot: {error}"))?;
        let toolchain_authority =
            hell_testkit::WindowsToolchainAuthority::new_from_promoted_inventory_until(
                windows_toolchain_executable_authority(
                    rustup.cargo_source(),
                    rustup.cargo().canonical(),
                    staged_cargo.clone(),
                ),
                windows_toolchain_executable_authority(
                    rustup.rustc_source(),
                    rustup.rustc().canonical(),
                    staged_rustc.clone(),
                ),
                toolchain.root.clone(),
                staged_inventory_files,
                staged_inventory_directories,
                trusted_parent_path,
                trusted_parent_system_root,
                toolchain_envelope.construction_deadline,
                toolchain_envelope.execution_deadline,
            )
            .map_err(|error| {
                format!(
                    "cannot bind staged Windows Rust toolchain: sourceToolchain={:?} \
             stagedToolchain={:?} cargoInvocation={:?} cargoIdentity={:?} \
             selectedCargo={:?} stagedCargo={staged_cargo:?} rustcInvocation={:?} \
             rustcIdentity={:?} selectedRustc={:?} stagedRustc={staged_rustc:?} \
             failure={error}",
                    rustup.toolchain_root(),
                    toolchain.root,
                    rustup.cargo_source().executable().invocation(),
                    rustup.cargo_source().executable().canonical(),
                    rustup.cargo().canonical(),
                    rustup.rustc_source().executable().invocation(),
                    rustup.rustc_source().executable().canonical(),
                    rustup.rustc().canonical(),
                )
            })?;
        let current_exe = std::env::current_exe()
            .map_err(|error| format!("cannot resolve trusted driver: {error}"))?;
        let restricted_adapter = windows_restricted_adapter_path(&current_exe)?;
        let launcher = windows_confinement::protect_launcher(&current_exe)?;
        let restricted_adapter = windows_confinement::protect_launcher(&restricted_adapter)?;
        windows_confinement::protect_tree(candidate_root, false)?;
        windows_confinement::protect_tree(oracle_root, false)?;
        windows_confinement::protect_tree(output, false)?;
        windows_confinement::protect_tree(target, true)?;
        hell_testkit::CandidateLaunchPolicy::windows(
            hell_testkit::WindowsLaunchAuthorities::new(
                launcher,
                restricted_adapter,
                toolchain_authority,
            )
            .map_err(|error| format!("cannot bind Windows launch authorities: {error}"))?,
            vec![target.to_path_buf()],
        )
        .map_err(|error| format!("cannot establish Windows candidate launch policy: {error}"))
    }));
    let policy = match setup {
        Ok(Ok(policy)) => policy,
        Ok(Err(primary)) => {
            let cleanup = toolchain.cleanup_until_with_retry(
                toolchain_envelope.completion_deadline,
                "candidate policy setup",
            );
            return Err(match cleanup {
                Ok(()) => primary,
                Err(cleanup) => format!(
                    "{primary}; additionally, Windows candidate toolchain cleanup failed: {cleanup}"
                ),
            });
        }
        Err(_) => {
            let primary = "Windows candidate confinement setup panicked".to_owned();
            let cleanup = toolchain.cleanup_until_with_retry(
                toolchain_envelope.completion_deadline,
                "candidate policy setup panic",
            );
            return Err(match cleanup {
                Ok(()) => primary,
                Err(cleanup) => format!(
                    "{primary}; additionally, Windows candidate toolchain cleanup failed: {cleanup}"
                ),
            });
        }
    };
    Ok(CandidateConfinement {
        policy: Some(policy),
        candidate_root: candidate_root.to_path_buf(),
        oracle_root: oracle_root.to_path_buf(),
        candidate_target: target.to_path_buf(),
        _toolchain: toolchain,
        toolchain_completion_deadline: toolchain_envelope.completion_deadline,
    })
}

#[cfg(windows)]
fn windows_toolchain_executable_authority(
    source: &crate::command::ResolvedWindowsToolSourceAuthority,
    selected: &Path,
    staged: PathBuf,
) -> hell_testkit::WindowsToolchainExecutableAuthority {
    match source {
        crate::command::ResolvedWindowsToolSourceAuthority::RustupProxy(executable)
        | crate::command::ResolvedWindowsToolSourceAuthority::CopiedRustupProxy(executable) => {
            hell_testkit::WindowsToolchainExecutableAuthority::rustup_proxy(
                executable.invocation().to_path_buf(),
                executable.canonical().to_path_buf(),
                selected.to_path_buf(),
                staged,
            )
        }
        crate::command::ResolvedWindowsToolSourceAuthority::SelectedToolchain(executable) => {
            hell_testkit::WindowsToolchainExecutableAuthority::selected_toolchain(
                executable.invocation().to_path_buf(),
                executable.canonical().to_path_buf(),
                selected.to_path_buf(),
                staged,
            )
        }
    }
}

/// One staged Windows Rust authority retained across both Nightly phases.
#[cfg(windows)]
pub(crate) struct NightlyWindowsLaunchAuthority {
    protection: WindowsToolchainProtection,
    policy: Option<hell_testkit::CandidateLaunchPolicy>,
    manifest: Vec<NightlyWindowsManifestEntry>,
    staged_cargo: PathBuf,
    staged_rustc: PathBuf,
    target: PathBuf,
}

#[cfg(windows)]
#[derive(Clone)]
pub(crate) struct NightlyWindowsManifestEntry {
    pub(crate) relative: PathBuf,
    pub(crate) directory: bool,
    pub(crate) size: u64,
    pub(crate) sha256: Option<hell_testkit::Digest>,
}

#[cfg(windows)]
impl NightlyWindowsLaunchAuthority {
    pub(crate) fn acquire_until(
        root: &Path,
        target: &Path,
        deadline: Instant,
        cleanup_deadline: Instant,
    ) -> Result<Self, String> {
        if Instant::now() >= deadline {
            return Err(
                "Windows Nightly launch authority deadline expired before acquisition".to_owned(),
            );
        }
        let root = fs::canonicalize(root)
            .map_err(|error| format!("cannot canonicalize Windows Nightly root: {error}"))?;
        let target = fs::canonicalize(target)
            .map_err(|error| format!("cannot canonicalize Windows Nightly target: {error}"))?;
        let cargo = crate::command::resolve_cargo_executable()?;
        let rustup = crate::command::resolve_windows_rustup_authority(&cargo, &root)?;
        let mut protection =
            stage_windows_toolchain_until(&rustup, &target, deadline, cleanup_deadline)?;
        let staged_cargo = protection.root.join("bin/cargo.exe");
        let staged_rustc = protection.root.join("bin/rustc.exe");
        let setup = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let inventory_files = protection.promote_inventory_until(deadline)?;
            let inventory_directories = protection
                .directories
                .iter()
                .map(|directory| protection.root.join(directory))
                .collect();
            let trusted_parent_path = std::env::var_os("PATH")
                .ok_or_else(|| "trusted Windows parent PATH is unavailable".to_owned())?;
            let trusted_parent_system_root =
                hell_testkit::capture_windows_standard_system_root()
                    .map_err(|error| format!("cannot bind trusted Windows SystemRoot: {error}"))?;
            let toolchain =
                hell_testkit::WindowsToolchainAuthority::new_from_promoted_inventory_until(
                    windows_toolchain_executable_authority(
                        rustup.cargo_source(),
                        rustup.cargo().canonical(),
                        staged_cargo.clone(),
                    ),
                    windows_toolchain_executable_authority(
                        rustup.rustc_source(),
                        rustup.rustc().canonical(),
                        staged_rustc.clone(),
                    ),
                    protection.root.clone(),
                    inventory_files,
                    inventory_directories,
                    trusted_parent_path,
                    trusted_parent_system_root,
                    deadline,
                    deadline,
                )
                .map_err(|error| {
                    format!("cannot bind Windows Nightly staged toolchain: {error}")
                })?;
            let launcher = fs::canonicalize(
                std::env::current_exe()
                    .map_err(|error| format!("cannot locate Windows Nightly launcher: {error}"))?,
            )
            .map_err(|error| format!("cannot canonicalize Windows Nightly launcher: {error}"))?;
            let restricted_adapter = windows_restricted_adapter_path(&launcher)?;
            let launcher = windows_confinement::protect_launcher(&launcher)?;
            let restricted_adapter = windows_confinement::protect_launcher(&restricted_adapter)?;
            if Instant::now() >= deadline {
                return Err(
                    "Windows Nightly launch authority deadline expired during protection"
                        .to_owned(),
                );
            }
            let authorities = hell_testkit::WindowsLaunchAuthorities::new_until(
                launcher,
                restricted_adapter,
                toolchain,
                deadline,
            )
            .map_err(|error| format!("cannot bind Windows Nightly launch authorities: {error}"))?;
            let policy =
                hell_testkit::CandidateLaunchPolicy::windows(authorities, vec![target.clone()])
                    .map_err(|error| {
                        format!("cannot establish Windows Nightly launch policy: {error}")
                    })?;
            let manifest = protection
                .directories
                .iter()
                .filter(|relative| !relative.as_os_str().is_empty())
                .cloned()
                .map(|relative| NightlyWindowsManifestEntry {
                    relative,
                    directory: true,
                    size: 0,
                    sha256: None,
                })
                .chain(
                    protection
                        .files
                        .iter()
                        .map(|file| NightlyWindowsManifestEntry {
                            relative: file.relative.clone(),
                            directory: false,
                            size: file.source.size(),
                            sha256: Some(file.source.sha256()),
                        }),
                )
                .collect();
            Ok::<_, String>((policy, manifest))
        }));
        let (policy, manifest) = match setup {
            Ok(Ok(setup)) => setup,
            Ok(Err(primary)) => {
                let cleanup =
                    protection.cleanup_until_with_retry(cleanup_deadline, "Nightly setup");
                return Err(match cleanup {
                    Ok(()) => primary,
                    Err(cleanup) => format!(
                        "{primary}; additionally, Windows Nightly authority cleanup failed: {cleanup}"
                    ),
                });
            }
            Err(_) => {
                let primary = "Windows Nightly authority setup panicked".to_owned();
                let cleanup =
                    protection.cleanup_until_with_retry(cleanup_deadline, "Nightly setup panic");
                return Err(match cleanup {
                    Ok(()) => primary,
                    Err(cleanup) => format!(
                        "{primary}; additionally, Windows Nightly authority cleanup failed: {cleanup}"
                    ),
                });
            }
        };
        Ok(Self {
            protection,
            policy: Some(policy),
            manifest,
            staged_cargo,
            staged_rustc,
            target,
        })
    }

    pub(crate) fn staged_cargo(&self) -> &Path {
        &self.staged_cargo
    }

    pub(crate) fn staged_root(&self) -> &Path {
        &self.protection.root
    }

    pub(crate) fn manifest_entries(&self) -> Vec<NightlyWindowsManifestEntry> {
        self.manifest.clone()
    }

    pub(crate) fn prepare_cleanup_transfer(&mut self, deadline: Instant) -> Result<(), String> {
        if self.protection.closed {
            return Ok(());
        }
        if self.policy.is_some() {
            self.protection.revalidate_until(deadline)?;
        } else if fs::canonicalize(&self.protection.root).ok().as_deref()
            != Some(self.protection.root.as_path())
        {
            return Err("Windows Nightly staged root changed before ownership transfer".to_owned());
        }
        Ok(())
    }

    pub(crate) fn commit_cleanup_transfer(&mut self) {
        if self.protection.closed {
            return;
        }
        self.policy = None;
        self.protection.closed = true;
    }

    pub(crate) fn cleanup_transferred(&self) -> bool {
        self.protection.closed
    }

    pub(crate) fn staged_rustc(&self) -> &Path {
        &self.staged_rustc
    }

    pub(crate) fn target(&self) -> &Path {
        &self.target
    }

    pub(crate) fn close_until(&mut self, deadline: Instant) -> Result<(), String> {
        if self.protection.closed {
            return Err("Windows Nightly cleanup authority was already transferred".to_owned());
        }
        self.policy = None;
        if Instant::now() >= deadline {
            return Err(
                "Windows Nightly launch authority cleanup deadline expired before cleanup"
                    .to_owned(),
            );
        }
        self.protection
            .cleanup_until_with_retry(deadline, "Nightly authority")?;
        if Instant::now() >= deadline {
            return Err(
                "Windows Nightly launch authority cleanup exceeded its absolute deadline"
                    .to_owned(),
            );
        }
        match fs::symlink_metadata(&self.protection.root) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!(
                "cannot attest Windows Nightly launch authority absence: {error}"
            )),
            Ok(_) => Err("Windows Nightly launch authority remains after cleanup".to_owned()),
        }
    }
}

#[cfg(any(windows, test))]
fn windows_restricted_adapter_path(launcher: &Path) -> Result<PathBuf, String> {
    if launcher.file_name() != Some(std::ffi::OsStr::new("hell-ci.exe")) {
        return Err("trusted Windows driver has the wrong executable name".to_owned());
    }
    let parent = launcher
        .parent()
        .ok_or_else(|| "trusted Windows driver has no parent".to_owned())?;
    Ok(parent.join("hell-test-helper.exe"))
}

#[cfg(windows)]
mod windows_confinement {
    use super::*;

    pub(super) fn protect_launcher(path: &Path) -> Result<PathBuf, String> {
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| format!("cannot inspect trusted Windows launcher: {error}"))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err("trusted Windows launcher is not a real file".to_owned());
        }
        let canonical = fs::canonicalize(path)
            .map_err(|error| format!("cannot canonicalize trusted Windows launcher: {error}"))?;
        let icacls = resolve_icacls()?;
        set_dacl(&icacls, &canonical, false, false)?;
        if fs::canonicalize(path)
            .map_err(|error| format!("cannot revalidate trusted Windows launcher: {error}"))?
            != canonical
            || !fs::symlink_metadata(&canonical)
                .map_err(|error| format!("cannot reinspect trusted Windows launcher: {error}"))?
                .is_file()
        {
            return Err("trusted Windows launcher identity changed during confinement".to_owned());
        }
        Ok(canonical)
    }

    pub(super) fn protect_tree(root: &Path, writable: bool) -> Result<(), String> {
        let icacls = resolve_icacls()?;
        let metadata = fs::symlink_metadata(root)
            .map_err(|error| format!("cannot inspect Windows confinement root: {error}"))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("Windows confinement root is not a real directory".to_owned());
        }
        let mut pending = vec![root.to_path_buf()];
        while let Some(path) = pending.pop() {
            let metadata = fs::symlink_metadata(&path)
                .map_err(|error| format!("cannot inspect Windows confinement entry: {error}"))?;
            let is_directory = metadata.is_dir();
            set_dacl(&icacls, &path, writable, is_directory)?;
            if is_directory {
                for entry in fs::read_dir(&path).map_err(|error| {
                    format!("cannot enumerate Windows confinement tree: {error}")
                })? {
                    let entry = entry.map_err(|error| {
                        format!("cannot inspect Windows confinement entry: {error}")
                    })?;
                    let metadata = fs::symlink_metadata(entry.path()).map_err(|error| {
                        format!("cannot inspect Windows confinement entry: {error}")
                    })?;
                    if metadata.file_type().is_symlink()
                        || !(metadata.is_file() || metadata.is_dir())
                    {
                        return Err(
                            "Windows confinement tree contains a redirected or special entry"
                                .to_owned(),
                        );
                    }
                    pending.push(entry.path());
                }
            }
        }
        Ok(())
    }

    pub(super) fn protect_tree_until_with_entry_gate(
        root: &Path,
        writable: bool,
        deadline: Instant,
        mut entry_gate: impl FnMut(&Path, bool) -> Result<(), String>,
    ) -> Result<(), String> {
        let metadata = fs::symlink_metadata(root)
            .map_err(|error| format!("cannot inspect Windows confinement root: {error}"))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("Windows confinement root is not a real directory".to_owned());
        }
        let inventory = windows_toolchain_inventory_paths_until(root, deadline)?;
        crate::release_suite::run_windows_supervisor_icacls(root, &["/reset", "/T"], deadline)
            .map_err(|error| format!("Windows confinement ACL reset failed: {error}"))?;
        for (relative, is_directory) in inventory {
            if Instant::now() >= deadline {
                return Err("Windows confinement protection exceeded its deadline".to_owned());
            }
            let path = root.join(&relative);
            let metadata = fs::symlink_metadata(&path)
                .map_err(|error| format!("cannot inspect Windows confinement entry: {error}"))?;
            if metadata.file_type().is_symlink()
                || metadata.is_dir() != is_directory
                || !(metadata.is_file() || metadata.is_dir())
            {
                return Err("Windows confinement inventory changed during DACL seal".to_owned());
            }
            entry_gate(&relative, is_directory).map_err(|error| {
                format!(
                    "Windows confinement DACL seal failed: phase=per-kind-dacl path={} \
                     entryKind={}: {error}",
                    relative.display(),
                    if is_directory { "directory" } else { "file" },
                )
            })?;
            crate::release_suite::run_windows_supervisor_icacls(
                &path,
                &["/setowner", "*S-1-5-32-544"],
                deadline,
            )
            .map_err(|error| {
                format!(
                    "Windows confinement owner seal failed: phase=per-kind-owner path={} \
                     entryKind={}: {error}",
                    relative.display(),
                    if is_directory { "directory" } else { "file" },
                )
            })?;
            let grants = windows_confinement_icacls_grants(writable, is_directory);
            let mut arguments = vec!["/inheritance:r", "/grant:r"];
            arguments.extend(grants);
            crate::release_suite::run_windows_supervisor_icacls(&path, &arguments, deadline)
                .map_err(|error| {
                    format!(
                        "Windows confinement DACL seal failed: phase=per-kind-dacl path={} \
                         entryKind={}: {error}",
                        relative.display(),
                        if is_directory { "directory" } else { "file" },
                    )
                })?;
        }
        Ok(())
    }

    pub(super) fn reset_tree_until(root: &Path, deadline: Instant) -> Result<(), String> {
        crate::release_suite::run_windows_supervisor_icacls(root, &["/reset", "/T"], deadline)
    }

    fn resolve_icacls() -> Result<PathBuf, String> {
        let system_root = std::env::var_os("SystemRoot")
            .ok_or_else(|| "standard SystemRoot is unavailable".to_owned())?;
        let system32 = PathBuf::from(system_root)
            .join("System32")
            .canonicalize()
            .map_err(|error| format!("cannot canonicalize Windows System32: {error}"))?;
        let tool = system32
            .join("icacls.exe")
            .canonicalize()
            .map_err(|error| format!("cannot canonicalize Windows icacls.exe: {error}"))?;
        let metadata = fs::metadata(&tool)
            .map_err(|error| format!("cannot inspect Windows icacls.exe: {error}"))?;
        if !metadata.is_file() || tool.parent() != Some(system32.as_path()) {
            return Err("Windows icacls.exe is not a regular System32 file".to_owned());
        }
        Ok(tool)
    }

    fn set_dacl(
        icacls: &Path,
        path: &Path,
        writable: bool,
        is_directory: bool,
    ) -> Result<(), String> {
        run_icacls(icacls, path, &["/reset"])?;
        let grants = windows_confinement_icacls_grants(writable, is_directory);
        let mut arguments = vec!["/inheritance:r", "/grant:r"];
        arguments.extend(grants);
        run_icacls(icacls, path, &arguments)
    }

    fn run_icacls(icacls: &Path, path: &Path, arguments: &[&str]) -> Result<(), String> {
        let output = std::process::Command::new(icacls)
            .arg(path)
            .args(arguments)
            .output()
            .map_err(|error| format!("cannot launch Windows icacls.exe: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "Windows icacls.exe rejected confinement DACL with status {:?}: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        Ok(())
    }
}

#[cfg(any(windows, test))]
fn windows_confinement_icacls_grants(writable: bool, is_directory: bool) -> [&'static str; 4] {
    match (writable, is_directory) {
        (true, true) => [
            "*S-1-5-32-544:(OI)(CI)(F)",
            "*S-1-5-18:(OI)(CI)(F)",
            "*S-1-5-11:(OI)(CI)(F)",
            "*S-1-5-12:(OI)(CI)(F)",
        ],
        (false, true) => [
            "*S-1-5-32-544:(OI)(CI)(F)",
            "*S-1-5-18:(OI)(CI)(F)",
            "*S-1-5-11:(OI)(CI)(RX)",
            "*S-1-5-12:(OI)(CI)(RX)",
        ],
        (true, false) => [
            "*S-1-5-32-544:(F)",
            "*S-1-5-18:(F)",
            "*S-1-5-11:(F)",
            "*S-1-5-12:(F)",
        ],
        (false, false) => [
            "*S-1-5-32-544:(F)",
            "*S-1-5-18:(F)",
            "*S-1-5-11:(RX)",
            "*S-1-5-12:(RX)",
        ],
    }
}

struct CandidateConfinement {
    #[cfg(unix)]
    policy: hell_testkit::CandidateLaunchPolicy,
    #[cfg(windows)]
    policy: Option<hell_testkit::CandidateLaunchPolicy>,
    #[cfg(unix)]
    _cleanup: PosixPrincipalCleanup,
    #[cfg(unix)]
    _adapter_protection: PosixAdapterProtection,
    #[cfg(unix)]
    _cargo_protection: PosixAdapterProtection,
    #[cfg(unix)]
    cargo_deny_home_protection: Option<PosixCargoDenyHomeProtection>,
    #[cfg(unix)]
    dependency_policy_protection: Option<PosixDependencyPolicyProtection>,
    #[cfg(unix)]
    _stack_protection: Option<PosixAdapterProtection>,
    #[cfg(unix)]
    stack_root_protection: Option<PosixStackRootProtection>,
    #[cfg(unix)]
    _rustup_protection: Option<PosixRustupProtection>,
    #[cfg(unix)]
    candidate_target: PosixCandidateTargetProtection,
    #[cfg(unix)]
    source_protection: PosixSourceProtection,
    #[cfg(windows)]
    candidate_root: PathBuf,
    #[cfg(windows)]
    oracle_root: PathBuf,
    #[cfg(windows)]
    candidate_target: PathBuf,
    #[cfg(windows)]
    _toolchain: WindowsToolchainProtection,
    #[cfg(windows)]
    toolchain_completion_deadline: Instant,
}

impl CandidateConfinement {
    fn policy(&self) -> Result<&hell_testkit::CandidateLaunchPolicy, String> {
        #[cfg(unix)]
        return Ok(&self.policy);
        #[cfg(windows)]
        self.policy
            .as_ref()
            .ok_or_else(|| "Windows candidate launch policy was already closed".to_owned())
    }

    fn finish_candidate_principal(&mut self) -> Result<(), String> {
        #[cfg(unix)]
        return self._cleanup.cleanup();
        #[cfg(windows)]
        Ok(())
    }

    #[cfg(windows)]
    fn close_windows_toolchain(&mut self) -> Result<(), String> {
        self.close_windows_toolchain_until(self.toolchain_completion_deadline)
    }

    #[cfg(windows)]
    fn close_windows_toolchain_until(&mut self, deadline: Instant) -> Result<(), String> {
        drop(self.policy.take());
        self._toolchain
            .cleanup_until_with_retry(deadline, "release toolchain")?;
        match fs::symlink_metadata(&self._toolchain.root) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!(
                "cannot attest Windows release toolchain absence: {error}"
            )),
            Ok(_) => Err("Windows release toolchain remains after cleanup".to_owned()),
        }
    }

    fn candidate_target(&self) -> &Path {
        #[cfg(unix)]
        return self.candidate_target.path();
        #[cfg(windows)]
        return &self.candidate_target;
    }

    fn export_candidate_target(&mut self, workspace_target: &Path) -> Result<(), String> {
        #[cfg(unix)]
        return export_posix_candidate_target(
            &self._adapter_protection,
            &mut self.candidate_target,
            workspace_target,
        );
        #[cfg(windows)]
        {
            let _ = workspace_target;
            Ok(())
        }
    }

    fn candidate_environment_root(&self, target: &Path) -> PathBuf {
        #[cfg(unix)]
        {
            let _ = target;
            self.source_protection
                .transient
                .join("release-child-environment")
        }
        #[cfg(windows)]
        {
            target.join("release-child-environment")
        }
    }

    fn cleanup_dependency_policy_cache(&mut self) -> Result<(), String> {
        #[cfg(unix)]
        if let Some(mut protection) = self.dependency_policy_protection.take() {
            protection.cleanup()?;
        }
        #[cfg(unix)]
        if let Some(mut protection) = self.cargo_deny_home_protection.take() {
            protection.cleanup()?;
        }
        #[cfg(unix)]
        if let Some(mut protection) = self.stack_root_protection.take() {
            normalize_posix_stack_root_with_adapter(
                &protection.sudo,
                &self._adapter_protection,
                &protection.root,
                protection.candidate_uid,
                protection.trusted_group_id,
            )?;
            protection.cleanup()?;
        }
        Ok(())
    }
    fn archive_launcher(&self) -> Option<&Path> {
        #[cfg(unix)]
        return Some(&self._adapter_protection.adapter);
        #[cfg(windows)]
        return None;
    }

    fn archive_adapter_base<'a>(&'a self, _target: &'a Path) -> &'a Path {
        #[cfg(unix)]
        return &self.source_protection.archive_adapter;
        #[cfg(windows)]
        return _target;
    }

    #[cfg(unix)]
    fn seal_archive_adapter_authority(
        &self,
        archive_adapter: &mut crate::command::NativeArchiveAdapter,
        authorization_deadline: Option<Instant>,
    ) -> Result<PosixArchiveAdapterSeal<'_>, String> {
        seal_posix_archive_adapter_authority(
            &self.source_protection,
            &self._adapter_protection,
            archive_adapter,
            authorization_deadline,
        )
    }

    #[cfg(unix)]
    fn stack_work_authority(&self) -> Result<&Path, String> {
        self.source_protection
            .stack_work
            .as_deref()
            .ok_or_else(|| "candidate Stack work authority is absent".to_owned())
    }

    fn candidate_root(&self) -> &Path {
        #[cfg(unix)]
        return &self.source_protection.candidate;
        #[cfg(windows)]
        return &self.candidate_root;
    }

    fn oracle_root(&self) -> &Path {
        #[cfg(unix)]
        return &self.source_protection.oracle;
        #[cfg(windows)]
        return &self.oracle_root;
    }

    fn require_candidate_environment(&self, checkpoint: &str) -> Result<(), String> {
        #[cfg(unix)]
        return self
            .source_protection
            .validate_candidate_environment(checkpoint);
        #[cfg(windows)]
        {
            let _ = checkpoint;
            Ok(())
        }
    }

    fn require_bound_sources(&self, checkpoint: &str) -> Result<(), String> {
        #[cfg(unix)]
        return validate_posix_sources(&self.source_protection, checkpoint);
        #[cfg(windows)]
        {
            let _ = checkpoint;
            Ok(())
        }
    }

    fn retain_oracle(
        &mut self,
        source: &UnretainedOracle,
    ) -> Result<hell_testkit::ExecutableIdentity, String> {
        #[cfg(unix)]
        return self.source_protection.retain_oracle_copy(source);
        #[cfg(windows)]
        return retain_oracle_copy(&self.candidate_root, source.identity()?.clone());
    }
}

#[cfg(unix)]
#[derive(Clone, Debug)]
struct ResolvedPosixProcessAuthorities {
    sudo: crate::command::ResolvedStandardExecutable,
    identity: crate::command::ResolvedStandardExecutable,
    inventory: crate::command::ResolvedStandardExecutable,
    terminator: crate::command::ResolvedStandardExecutable,
}

#[cfg(unix)]
impl ResolvedPosixProcessAuthorities {
    fn resolve() -> Result<Arc<Self>, String> {
        let resolve = |path: &Path, label: &str| {
            crate::command::resolve_absolute_standard_executable(path)
                .map_err(|error| format!("cannot bind trusted {label} authority: {error}"))
        };
        Ok(Arc::new(Self {
            sudo: resolve(Path::new("/usr/bin/sudo"), "sudo")?,
            identity: resolve(Path::new("/usr/bin/id"), "identity query")?,
            inventory: resolve(Path::new("/bin/ps"), "process inventory")?,
            terminator: resolve(Path::new("/usr/bin/pkill"), "process termination")?,
        }))
    }

    fn launch_authorities(&self) -> Result<hell_testkit::PosixProcessAuthorities, String> {
        use hell_testkit::PosixProcessToolRole::{Identity, Inventory, Sudo, Terminator};

        hell_testkit::PosixProcessAuthorities::new(
            self.sudo.posix_authority(Sudo),
            self.identity.posix_authority(Identity),
            self.inventory.posix_authority(Inventory),
            self.terminator.posix_authority(Terminator),
        )
        .map_err(|error| format!("cannot assemble POSIX process authorities: {error}"))
    }
}

#[cfg(unix)]
fn posix_candidate_target_verifier_root_is_exact(platform: ReleasePlatform, root: &Path) -> bool {
    let expected_parent = match platform {
        ReleasePlatform::LinuxX86_64 => Path::new("/var/tmp"),
        ReleasePlatform::MacosAarch64 => Path::new("/private/var/tmp"),
        ReleasePlatform::WindowsX86_64 => return false,
    };
    let Some(name) = root.file_name().and_then(OsStr::to_str) else {
        return false;
    };
    let Some((process, sequence)) = name
        .strip_prefix("hell-candidate-target-verifier-")
        .and_then(|suffix| suffix.split_once('-'))
    else {
        return false;
    };
    let canonical_number = |value: &str| {
        value
            .parse::<u64>()
            .is_ok_and(|number| value == number.to_string())
    };
    root.parent() == Some(expected_parent)
        && canonical_number(process)
        && canonical_number(sequence)
}

#[cfg(unix)]
#[derive(Clone, Debug)]
struct PosixVerifierTransientCleanup {
    platform: ReleasePlatform,
    parent: PathBuf,
    parent_identity: PosixObjectIdentity,
    root: PathBuf,
    root_identity: PosixObjectIdentity,
    adapter: PathBuf,
    adapter_identity: PosixObjectIdentity,
    adapter_sha256: hell_testkit::Digest,
}

#[cfg(unix)]
impl PosixVerifierTransientCleanup {
    fn bind(
        platform: ReleasePlatform,
        root: &Path,
        adapter: &PosixAdapterProtection,
    ) -> Result<Self, String> {
        let parent = posix_adapter_installation_root(platform)?;
        let parent_identity = posix_object_identity(&parent)?;
        let metadata = fs::symlink_metadata(root).map_err(|error| {
            format!("cannot inspect candidate target verifier cleanup root: {error}")
        })?;
        if root.parent() != Some(parent.as_path())
            || !posix_candidate_target_verifier_root_is_exact(platform, root)
            || fs::canonicalize(root).map_err(|error| {
                format!("cannot canonicalize candidate target verifier cleanup root: {error}")
            })? != root
            || metadata.file_type().is_symlink()
            || !metadata.is_dir()
        {
            return Err("candidate target verifier cleanup root differs from policy".to_owned());
        }
        require_posix_adapter_unchanged(adapter)?;
        Ok(Self {
            platform,
            parent,
            parent_identity,
            root: root.to_path_buf(),
            root_identity: posix_object_identity(root)?,
            adapter: adapter.adapter.clone(),
            adapter_identity: adapter.adapter_identity.clone(),
            adapter_sha256: adapter.sha256,
        })
    }

    fn revalidate_present(&self) -> Result<(), String> {
        let metadata = fs::symlink_metadata(&self.root).map_err(|error| {
            format!("cannot revalidate candidate target verifier cleanup root: {error}")
        })?;
        if validate_posix_adapter_installation_root(self.platform, &self.parent)? != self.parent
            || posix_object_identity(&self.parent)? != self.parent_identity
            || self.root.parent() != Some(self.parent.as_path())
            || !posix_candidate_target_verifier_root_is_exact(self.platform, &self.root)
            || fs::canonicalize(&self.root).map_err(|error| {
                format!("cannot canonicalize candidate target verifier cleanup root: {error}")
            })? != self.root
            || metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || !posix_same_object(&posix_object_identity(&self.root)?, &self.root_identity)
            || fs::canonicalize(&self.adapter).ok().as_deref() != Some(self.adapter.as_path())
            || posix_object_identity(&self.adapter)? != self.adapter_identity
            || hell_testkit::sha256_file(&self.adapter).map_err(|error| {
                format!("cannot rehash candidate target verifier cleanup adapter: {error}")
            })? != self.adapter_sha256
        {
            return Err("candidate target verifier cleanup authority changed".to_owned());
        }
        Ok(())
    }

    fn require_absent(&self) -> Result<(), String> {
        if validate_posix_adapter_installation_root(self.platform, &self.parent)? != self.parent
            || posix_object_identity(&self.parent)? != self.parent_identity
        {
            return Err("candidate target verifier cleanup parent changed".to_owned());
        }
        match fs::symlink_metadata(&self.root) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Ok(_) => Err("candidate target verifier cleanup root remains present".to_owned()),
            Err(error) => Err(format!(
                "cannot attest candidate target verifier cleanup root absence: {error}"
            )),
        }
    }

    fn cleanup_until(
        &self,
        authorities: &ResolvedPosixProcessAuthorities,
        deadline: Instant,
    ) -> Result<(), String> {
        if self.require_absent().is_ok() {
            return Ok(());
        }
        self.revalidate_present()?;
        authorities
            .sudo
            .revalidate()
            .map_err(|error| format!("candidate cleanup launcher authority changed: {error}"))?;
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| "candidate process quiescence deadline expired".to_owned())?;
        let result = CommandSpec::new(authorities.sudo.invocation_path().as_os_str(), remaining)
            .arguments(["-n", "--"])
            .argument(&self.adapter)
            .argument("__release-remove-candidate-target-verifier")
            .argument(&self.root)
            .argument(self.parent_identity.device.to_string())
            .argument(self.parent_identity.inode.to_string())
            .argument(self.root_identity.device.to_string())
            .argument(self.root_identity.inode.to_string())
            .run()
            .map_err(|error| {
                format!("candidate target verifier cleanup command failed: {error}")
            })?;
        if !result.status.success()
            || result.timed_out
            || result.stdout_truncated
            || result.stderr_truncated
            || !result.stdout.is_empty()
            || !result.stderr.is_empty()
        {
            return Err(
                "candidate target verifier cleanup command did not succeed exactly".to_owned(),
            );
        }
        self.require_absent()
    }
}

#[cfg(unix)]
#[derive(Clone, Debug, Default)]
struct PosixPrincipalCleanupOrder {
    uid_empty: bool,
    transient_absent: bool,
    user_absent: bool,
}

#[cfg(unix)]
impl PosixPrincipalCleanupOrder {
    fn observe_uid_empty(&mut self) {
        self.uid_empty = true;
    }

    fn require_transient_deletion(&self) -> Result<(), String> {
        if !self.uid_empty {
            return Err(
                "candidate verifier transient deletion preceded UID process quiescence".to_owned(),
            );
        }
        Ok(())
    }

    fn observe_transient_absent(&mut self) -> Result<(), String> {
        self.require_transient_deletion()?;
        self.transient_absent = true;
        Ok(())
    }

    fn require_user_deletion(&self) -> Result<(), String> {
        if !self.transient_absent {
            return Err(
                "candidate principal deletion preceded verifier transient absence".to_owned(),
            );
        }
        Ok(())
    }

    fn observe_user_absent(&mut self) -> Result<(), String> {
        self.require_user_deletion()?;
        self.user_absent = true;
        Ok(())
    }

    fn require_group_deletion(&self) -> Result<(), String> {
        if !self.user_absent {
            return Err("candidate group deletion preceded principal absence".to_owned());
        }
        Ok(())
    }
}

#[cfg(unix)]
pub(crate) fn verify_posix_principal_cleanup_order_for_integration() -> Result<(), String> {
    let mut ordering = PosixPrincipalCleanupOrder::default();
    let transient_error = ordering
        .require_transient_deletion()
        .expect_err("transient deletion before UID quiescence must be rejected");
    if transient_error != "candidate verifier transient deletion preceded UID process quiescence" {
        return Err(format!(
            "candidate cleanup UID-order verifier reached the wrong phase: {transient_error}"
        ));
    }
    ordering.observe_uid_empty();
    ordering.require_transient_deletion()?;
    let user_error = ordering
        .require_user_deletion()
        .expect_err("principal deletion before transient absence must be rejected");
    if user_error != "candidate principal deletion preceded verifier transient absence" {
        return Err(format!(
            "candidate cleanup transient-order verifier reached the wrong phase: {user_error}"
        ));
    }
    ordering.observe_transient_absent()?;
    ordering.require_user_deletion()?;
    let group_error = ordering
        .require_group_deletion()
        .expect_err("group deletion before principal absence must be rejected");
    if group_error != "candidate group deletion preceded principal absence" {
        return Err(format!(
            "candidate cleanup principal-order verifier reached the wrong phase: {group_error}"
        ));
    }
    ordering.observe_user_absent()?;
    ordering.require_group_deletion()
}

#[cfg(unix)]
struct PosixPrincipalCleanup {
    platform: ReleasePlatform,
    authorities: Arc<ResolvedPosixProcessAuthorities>,
    principal: String,
    group: String,
    uid: Option<u32>,
    gid: Option<u32>,
    user_created: bool,
    group_created: bool,
    verifier_transient: Option<PosixVerifierTransientCleanup>,
    ordering: Option<PosixPrincipalCleanupOrder>,
    deadline: Option<Instant>,
    active: bool,
}

#[cfg(unix)]
impl PosixPrincipalCleanup {
    fn new(
        platform: ReleasePlatform,
        authorities: Arc<ResolvedPosixProcessAuthorities>,
        principal: String,
        group: String,
        uid: Option<u32>,
        gid: Option<u32>,
    ) -> Result<Self, String> {
        Ok(Self {
            platform,
            authorities,
            principal,
            group,
            uid,
            gid,
            user_created: false,
            group_created: false,
            verifier_transient: None,
            ordering: None,
            deadline: None,
            active: true,
        })
    }

    fn attach_verifier_transient(
        &mut self,
        transient: PosixVerifierTransientCleanup,
    ) -> Result<(), String> {
        if self.verifier_transient.replace(transient).is_some() {
            return Err("candidate verifier transient cleanup is already bound".to_owned());
        }
        self.ordering = Some(PosixPrincipalCleanupOrder::default());
        Ok(())
    }

    fn command_until<I, S>(&self, deadline: Instant, arguments: I) -> Result<CommandResult, String>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.authorities
            .sudo
            .revalidate()
            .map_err(|error| format!("candidate cleanup launcher authority changed: {error}"))?;
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| "candidate process quiescence deadline expired".to_owned())?;
        CommandSpec::new(
            self.authorities.sudo.invocation_path().as_os_str(),
            remaining,
        )
        .arguments(arguments)
        .run()
        .map_err(|error| format!("candidate principal cleanup command failed: {error}"))
    }

    fn observe_macos_construction_side_effects(&mut self, deadline: Instant) -> Result<(), String> {
        let observed_user =
            posix_principal_uid(deadline, ReleasePlatform::MacosAarch64, &self.principal)?;
        let observed_group = posix_group_gid(deadline, &self.group)?;
        let (user_created, group_created) = macos_construction_receipt_flags(
            self.uid,
            self.gid,
            self.user_created,
            self.group_created,
            observed_user,
            observed_group,
        )?;
        self.user_created = user_created;
        self.group_created = group_created;
        Ok(())
    }

    fn cleanup(&mut self) -> Result<(), String> {
        if !self.active {
            return Ok(());
        }
        let deadline = match self.deadline {
            Some(deadline) => deadline,
            None => {
                let deadline = Instant::now()
                    .checked_add(Duration::from_secs(30))
                    .ok_or_else(|| "candidate process quiescence deadline overflowed".to_owned())?;
                self.deadline = Some(deadline);
                deadline
            }
        };
        let observed_uid = self
            .user_created
            .then(|| posix_principal_uid(deadline, self.platform, &self.principal))
            .transpose()?
            .flatten();
        if self.user_created {
            let observed = observed_uid.ok_or_else(|| {
                "created candidate principal disappeared before cleanup".to_owned()
            })?;
            if self.uid.is_some_and(|expected| expected != observed) {
                return Err("candidate principal UID changed before cleanup".to_owned());
            }
            self.uid = Some(observed);
            self.require_no_processes_until(observed, deadline)?;
        }
        if let Some(ordering) = &mut self.ordering {
            ordering.observe_uid_empty();
        }
        if let Some(transient) = &self.verifier_transient {
            self.ordering
                .as_ref()
                .ok_or_else(|| "candidate verifier cleanup order receipt is absent".to_owned())?
                .require_transient_deletion()?;
            transient.cleanup_until(&self.authorities, deadline)?;
            self.ordering
                .as_mut()
                .ok_or_else(|| "candidate verifier cleanup order receipt is absent".to_owned())?
                .observe_transient_absent()?;
        }
        if !self.user_created
            && let Some(ordering) = &mut self.ordering
        {
            ordering.observe_user_absent()?;
        }
        match self.platform {
            ReleasePlatform::LinuxX86_64 => {
                if self.user_created {
                    if let Some(ordering) = &self.ordering {
                        ordering.require_user_deletion()?;
                    }
                    let expected = self.uid.ok_or_else(|| {
                        "candidate principal UID receipt disappeared after process quiescence"
                            .to_owned()
                    })?;
                    self.require_exact_identity_until(
                        deadline,
                        "-u",
                        expected,
                        "UID after process quiescence",
                    )?;
                    let result = self.command_until(
                        deadline,
                        [
                            OsString::from("-n"),
                            OsString::from("--"),
                            OsString::from("/usr/sbin/userdel"),
                            OsString::from(&self.principal),
                        ],
                    )?;
                    if result.timed_out || !result.status.success() {
                        return Err("candidate principal deletion did not succeed".to_owned());
                    }
                    if posix_principal_uid(deadline, self.platform, &self.principal)?.is_some() {
                        return Err(
                            "candidate principal remains present after successful deletion"
                                .to_owned(),
                        );
                    }
                    if let Some(ordering) = &mut self.ordering {
                        ordering.observe_user_absent()?;
                    }
                    self.user_created = false;
                }
                if self.group_created {
                    if let Some(ordering) = &self.ordering {
                        ordering.require_group_deletion()?;
                    }
                    if let Some(observed) = posix_group_gid(deadline, &self.group)? {
                        if self.gid.is_some_and(|expected| expected != observed) {
                            return Err("candidate group GID changed before cleanup".to_owned());
                        }
                        self.gid = Some(observed);
                        let result = self.command_until(
                            deadline,
                            [
                                OsString::from("-n"),
                                OsString::from("--"),
                                OsString::from("/usr/sbin/groupdel"),
                                OsString::from(&self.group),
                            ],
                        )?;
                        if result.timed_out || !result.status.success() {
                            return Err("candidate group deletion did not succeed".to_owned());
                        }
                    }
                    if posix_group_gid(deadline, &self.group)?.is_some() {
                        return Err(
                            "candidate group remains present after successful cleanup".to_owned()
                        );
                    }
                    self.group_created = false;
                }
            }
            ReleasePlatform::MacosAarch64 => {
                if self.user_created {
                    if let Some(ordering) = &self.ordering {
                        ordering.require_user_deletion()?;
                    }
                    let expected = self.uid.ok_or_else(|| {
                        "candidate principal UID receipt disappeared after process quiescence"
                            .to_owned()
                    })?;
                    self.require_exact_identity_until(
                        deadline,
                        "-u",
                        expected,
                        "UID after process quiescence",
                    )?;
                    let result = self.command_until(
                        deadline,
                        [
                            OsString::from("-n"),
                            OsString::from("--"),
                            OsString::from("/usr/bin/dscl"),
                            OsString::from("."),
                            OsString::from("-delete"),
                            Path::new("/Users").join(&self.principal).into_os_string(),
                        ],
                    )?;
                    if result.timed_out || !result.status.success() {
                        return Err(
                            "candidate directory-service cleanup did not succeed".to_owned()
                        );
                    }
                    if posix_principal_uid(deadline, self.platform, &self.principal)?.is_some() {
                        return Err(
                            "candidate principal remains present after directory-service deletion"
                                .to_owned(),
                        );
                    }
                    if let Some(ordering) = &mut self.ordering {
                        ordering.observe_user_absent()?;
                    }
                    self.user_created = false;
                }
                if self.group_created {
                    if let Some(ordering) = &self.ordering {
                        ordering.require_group_deletion()?;
                    }
                    let observed = posix_group_gid(deadline, &self.group)?.ok_or_else(|| {
                        "created candidate group disappeared before cleanup".to_owned()
                    })?;
                    if self.gid.is_some_and(|expected| expected != observed) {
                        return Err("candidate group GID changed before cleanup".to_owned());
                    }
                    self.gid = Some(observed);
                    let result = self.command_until(
                        deadline,
                        [
                            OsString::from("-n"),
                            OsString::from("--"),
                            OsString::from("/usr/bin/dscl"),
                            OsString::from("."),
                            OsString::from("-delete"),
                            Path::new("/Groups").join(&self.group).into_os_string(),
                        ],
                    )?;
                    if result.timed_out || !result.status.success() {
                        return Err(
                            "candidate directory-service cleanup did not succeed".to_owned()
                        );
                    }
                    if posix_group_gid(deadline, &self.group)?.is_some() {
                        return Err(
                            "candidate group remains present after directory-service deletion"
                                .to_owned(),
                        );
                    }
                    self.group_created = false;
                }
            }
            ReleasePlatform::WindowsX86_64 => {}
        }
        self.active = false;
        Ok(())
    }

    fn require_no_processes_until(&self, uid: u32, deadline: Instant) -> Result<(), String> {
        self.authorities
            .inventory
            .revalidate()
            .map_err(|error| format!("candidate process inventory authority changed: {error}"))?;
        let uid_text = uid.to_string();
        hell_testkit::wait_for_posix_uid_process_quiescence(
            deadline,
            hell_testkit::PosixUidQuiescenceGoal::Empty,
            || {
                self.authorities.inventory.revalidate().map_err(|error| {
                    std::io::Error::other(format!(
                        "candidate process inventory authority changed: {error}"
                    ))
                })?;
                let result = self
                    .command_until(
                        deadline,
                        [
                            OsString::from("-n"),
                            OsString::from("--"),
                            self.authorities
                                .inventory
                                .invocation_path()
                                .as_os_str()
                                .to_owned(),
                            OsString::from("-U"),
                            OsString::from(&uid_text),
                            OsString::from("-o"),
                            OsString::from("pid=,ppid=,stat="),
                        ],
                    )
                    .map_err(std::io::Error::other)?;
                if result.timed_out || result.stdout_truncated || result.stderr_truncated {
                    return Err(std::io::Error::other(
                        "candidate process inventory query did not complete exactly",
                    ));
                }
                hell_testkit::parse_posix_uid_process_snapshot(
                    result.status.code(),
                    &result.stdout,
                    &result.stderr,
                )
                .map_err(|error| {
                    std::io::Error::other(format!(
                        "candidate process inventory is not exact: {error}"
                    ))
                })
            },
            || {
                let expected_gid = self.gid.ok_or_else(|| {
                    std::io::Error::other("candidate primary GID receipt is absent")
                })?;
                self.require_exact_identity_until(
                    deadline,
                    "-u",
                    uid,
                    "UID before process termination",
                )
                .map_err(std::io::Error::other)?;
                self.require_exact_identity_until(
                    deadline,
                    "-g",
                    expected_gid,
                    "primary GID before process termination",
                )
                .map_err(std::io::Error::other)
            },
            || {
                self.authorities.terminator.revalidate().map_err(|error| {
                    std::io::Error::other(format!(
                        "candidate process termination authority changed: {error}"
                    ))
                })?;
                let result = self
                    .command_until(
                        deadline,
                        [
                            OsString::from("-n"),
                            OsString::from("--"),
                            self.authorities
                                .terminator
                                .invocation_path()
                                .as_os_str()
                                .to_owned(),
                            OsString::from("-KILL"),
                            OsString::from("-U"),
                            OsString::from(&uid_text),
                        ],
                    )
                    .map_err(std::io::Error::other)?;
                if result.timed_out || !matches!(result.status.code(), Some(0 | 1)) {
                    return Err(std::io::Error::other(
                        "candidate principal process cleanup did not succeed",
                    ));
                }
                Ok(())
            },
        )
        .map(|_| ())
        .map_err(|error| error.to_string())
    }

    fn require_exact_identity_until(
        &self,
        deadline: Instant,
        option: &str,
        expected: u32,
        label: &str,
    ) -> Result<(), String> {
        self.authorities
            .identity
            .revalidate()
            .map_err(|error| format!("trusted candidate identity validation failed: {error}"))?;
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| "candidate process quiescence deadline expired".to_owned())?;
        let result = CommandSpec::new(
            self.authorities.identity.invocation_path().as_os_str(),
            remaining,
        )
        .arguments([option, &self.principal])
        .run()
        .map_err(|error| format!("trusted candidate identity command failed: {error}"))?;
        if !result.status.success()
            || result.timed_out
            || result.stdout_truncated
            || result.stderr_truncated
            || !result.stderr.is_empty()
            || !posix_candidate_identity_output_is_exact(&result.stdout, expected)
        {
            return Err(format!(
                "candidate {label} differs from the bound numeric identity"
            ));
        }
        Ok(())
    }

    fn finish(mut self) -> Result<(), String> {
        self.cleanup()
    }
}

#[cfg(unix)]
fn macos_construction_receipt_flags(
    expected_uid: Option<u32>,
    expected_gid: Option<u32>,
    user_created: bool,
    group_created: bool,
    observed_uid: Option<u32>,
    observed_gid: Option<u32>,
) -> Result<(bool, bool), String> {
    let update =
        |label: &str, expected: Option<u32>, created: bool, observed: Option<u32>| match observed {
            Some(observed) if expected == Some(observed) => Ok(true),
            Some(_) => Err(format!(
                "macOS candidate {label} binding differs from its receipt"
            )),
            None if created => Err(format!(
                "macOS candidate {label} disappeared during construction"
            )),
            None => Ok(false),
        };
    Ok((
        update("principal", expected_uid, user_created, observed_uid)?,
        update("group", expected_gid, group_created, observed_gid)?,
    ))
}

#[cfg(unix)]
fn macos_principal_mutation<const N: usize>(
    cleanup: &mut PosixPrincipalCleanup,
    arguments: [&str; N],
) -> Result<(), String> {
    let deadline = posix_identity_query_deadline("macOS principal construction")?;
    let mutation = cleanup
        .command_until(deadline, arguments)
        .and_then(|result| {
            if !result.status.success() || result.timed_out {
                return Err("trusted confinement command did not succeed".to_owned());
            }
            Ok(())
        });
    let observation = cleanup.observe_macos_construction_side_effects(deadline);
    match (mutation, observation) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(observation)) => Err(format!(
            "{error}; macOS construction side-effect inventory also failed: {observation}"
        )),
    }
}

#[cfg(unix)]
impl Drop for PosixPrincipalCleanup {
    fn drop(&mut self) {
        if self.active
            && let Err(error) = self.cleanup()
        {
            eprintln!("candidate principal fallback cleanup failed: {error}");
        }
    }
}

#[cfg(unix)]
fn posix_process_inventory_is_canonical(output: &[u8]) -> bool {
    let Some(lines) = output.strip_suffix(b"\n") else {
        return false;
    };
    if lines.is_empty() {
        return false;
    }
    let mut observed = BTreeSet::new();
    for line in lines.split(|byte| *byte == b'\n') {
        let Ok(text) = std::str::from_utf8(line) else {
            return false;
        };
        let Ok(pid) = text.parse::<u32>() else {
            return false;
        };
        if pid == 0 || text != pid.to_string() || !observed.insert(pid) {
            return false;
        }
    }
    true
}

#[cfg(unix)]
fn posix_identity_query_deadline(label: &str) -> Result<Instant, String> {
    Instant::now()
        .checked_add(Duration::from_secs(30))
        .ok_or_else(|| format!("{label} deadline overflowed"))
}

#[cfg(unix)]
fn run_posix_identity_query_until<I, S>(
    deadline: Instant,
    program: &Path,
    arguments: I,
    label: &str,
) -> Result<CommandResult, String>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| format!("{label} deadline expired before launch"))?;
    CommandSpec::new(program.as_os_str(), remaining)
        .arguments(arguments)
        .run()
        .map_err(|error| format!("cannot query {label}: {error}"))
}

#[cfg(unix)]
pub(crate) fn verify_posix_identity_query_deadline_for_integration() -> Result<(), String> {
    let deadline = Instant::now()
        .checked_sub(Duration::from_secs(1))
        .ok_or_else(|| "cannot construct expired identity-query deadline".to_owned())?;
    let error = run_posix_identity_query_until(
        deadline,
        Path::new("/hell-ci-expired-identity-query-must-not-launch"),
        std::iter::empty::<OsString>(),
        "expired identity query probe",
    )
    .expect_err("an expired identity-query deadline must reject before launch");
    if error != "expired identity query probe deadline expired before launch" {
        return Err(format!(
            "expired identity-query verifier reached the wrong phase: {error}"
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn posix_principal_uid(
    deadline: Instant,
    platform: ReleasePlatform,
    principal: &str,
) -> Result<Option<u32>, String> {
    match platform {
        ReleasePlatform::LinuxX86_64 => {
            let result = run_posix_identity_query_until(
                deadline,
                Path::new("/usr/bin/getent"),
                ["passwd", principal],
                "candidate principal during cleanup",
            )?;
            if posix_nss_record_is_absent(&result, "candidate principal")? {
                return Ok(None);
            }
            let line = exact_posix_nss_record(&result, "candidate principal")?;
            let fields = line.split(|byte| *byte == b':').collect::<Vec<_>>();
            if fields.len() != 7 || fields[0] != principal.as_bytes() {
                return Err("candidate principal cleanup record is not canonical".to_owned());
            }
            parse_posix_candidate_identity_output(fields[2], "candidate cleanup UID").map(Some)
        }
        ReleasePlatform::MacosAarch64 => macos_directory_service_id(
            deadline,
            "/Users",
            "UniqueID",
            principal,
            "candidate principal",
        ),
        ReleasePlatform::WindowsX86_64 => {
            Err("Windows selected POSIX principal cleanup".to_owned())
        }
    }
}

#[cfg(unix)]
fn macos_directory_service_id(
    deadline: Instant,
    record_path: &str,
    attribute: &str,
    name: &str,
    label: &str,
) -> Result<Option<u32>, String> {
    let result = run_posix_identity_query_until(
        deadline,
        Path::new("/usr/bin/dscl"),
        [".", "-list", record_path, attribute],
        &format!("{label} during cleanup"),
    )?;
    if result.timed_out
        || !result.status.success()
        || result.stdout_truncated
        || result.stderr_truncated
        || !result.stderr.is_empty()
    {
        return Err(format!("{label} cleanup query did not succeed exactly"));
    }
    macos_directory_service_inventory_id(&result.stdout, name, label)
}

#[cfg(unix)]
fn macos_directory_service_inventory_id(
    output: &[u8],
    name: &str,
    label: &str,
) -> Result<Option<u32>, String> {
    if !output.ends_with(b"\n") {
        return Err(format!(
            "{label} directory-service inventory is not newline-terminated"
        ));
    }
    let mut observed = None;
    for line in output
        .strip_suffix(b"\n")
        .unwrap_or(output)
        .split(|byte| *byte == b'\n')
    {
        if line.is_empty() {
            return Err(format!(
                "{label} directory-service inventory contains an empty record"
            ));
        }
        let fields = line
            .split(|byte| byte.is_ascii_whitespace())
            .filter(|field| !field.is_empty())
            .collect::<Vec<_>>();
        if fields.len() != 2 {
            return Err(format!(
                "{label} directory-service inventory is not canonical"
            ));
        }
        if fields[0] == name.as_bytes() {
            if observed.is_some() {
                return Err(format!("{label} directory-service inventory is duplicated"));
            }
            observed = Some(parse_posix_candidate_identity_output(
                fields[1],
                &format!("{label} cleanup identity"),
            )?);
        }
    }
    Ok(observed)
}

#[cfg(target_os = "linux")]
fn posix_group_gid(deadline: Instant, group: &str) -> Result<Option<u32>, String> {
    let result = run_posix_identity_query_until(
        deadline,
        Path::new("/usr/bin/getent"),
        ["group", group],
        "candidate group during cleanup",
    )?;
    if posix_nss_record_is_absent(&result, "candidate group")? {
        return Ok(None);
    }
    let line = exact_posix_nss_record(&result, "candidate group")?;
    let fields = line.split(|byte| *byte == b':').collect::<Vec<_>>();
    if fields.len() != 4 || fields[0] != group.as_bytes() {
        return Err("candidate group cleanup record is not canonical".to_owned());
    }
    parse_posix_candidate_identity_output(fields[2], "candidate cleanup GID").map(Some)
}

#[cfg(unix)]
fn posix_nss_record_is_absent(result: &CommandResult, label: &str) -> Result<bool, String> {
    if result.timed_out || result.stdout_truncated || result.stderr_truncated {
        return Err(format!("{label} NSS query did not complete exactly"));
    }
    if result.status.success() {
        return Ok(false);
    }
    if result.status.code() == Some(2) && result.stdout.is_empty() && result.stderr.is_empty() {
        return Ok(true);
    }
    Err(format!(
        "{label} NSS query failed without authoritative absence: status={:?}; stderr={}",
        result.status.code(),
        String::from_utf8_lossy(&result.stderr)
    ))
}

#[cfg(unix)]
fn exact_posix_nss_record<'a>(result: &'a CommandResult, label: &str) -> Result<&'a [u8], String> {
    if result.timed_out
        || !result.status.success()
        || result.stdout_truncated
        || result.stderr_truncated
        || !result.stderr.is_empty()
    {
        return Err(format!("{label} NSS query did not succeed exactly"));
    }
    result
        .stdout
        .strip_suffix(b"\n")
        .filter(|line| !line.is_empty() && !line.contains(&b'\n'))
        .ok_or_else(|| format!("{label} NSS record is not one canonical line"))
}

#[cfg(unix)]
#[derive(Clone, Copy)]
struct LinuxPrincipalIdPolicy {
    first: u32,
    span: u32,
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct LinuxPrincipalCandidate {
    principal: String,
    group: String,
    id: u32,
}

#[cfg(unix)]
#[derive(Default)]
struct LinuxPrincipalOccupancy {
    uids: BTreeSet<u32>,
    gids: BTreeSet<u32>,
    principals: BTreeSet<String>,
    groups: BTreeSet<String>,
}

#[cfg(unix)]
fn planned_linux_principal_candidate(
    policy: LinuxPrincipalIdPolicy,
    prefix: &str,
    process_id: u32,
    allocation: u64,
    occupancy: &LinuxPrincipalOccupancy,
) -> Result<LinuxPrincipalCandidate, String> {
    let start = (u64::from(process_id) + allocation) % u64::from(policy.span);
    for offset in 0..policy.span {
        let relative = (start + u64::from(offset)) % u64::from(policy.span);
        let id =
            policy
                .first
                .checked_add(u32::try_from(relative).map_err(|_| {
                    "Linux principal allocation offset exceeds its bound".to_owned()
                })?)
                .ok_or_else(|| "Linux principal allocation overflowed".to_owned())?;
        let sequence = allocation
            .checked_add(u64::from(offset))
            .ok_or_else(|| "Linux principal name sequence overflowed".to_owned())?;
        let principal = format!("{prefix}{process_id}x{sequence}");
        if principal.len() > 31
            || !principal
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        {
            return Err("Linux candidate principal name is outside policy".to_owned());
        }
        let group = principal.clone();
        if occupancy.uids.contains(&id)
            || occupancy.gids.contains(&id)
            || occupancy.principals.contains(&principal)
            || occupancy.groups.contains(&group)
        {
            continue;
        }
        return Ok(LinuxPrincipalCandidate {
            principal,
            group,
            id,
        });
    }
    Err("Linux principal allocation range is exhausted".to_owned())
}

#[cfg(target_os = "linux")]
fn linux_principal_id_policy() -> Result<LinuxPrincipalIdPolicy, String> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let path = Path::new("/etc/login.defs");
    if fs::canonicalize(path)
        .map_err(|error| format!("cannot canonicalize Linux principal policy: {error}"))?
        != path
    {
        return Err("Linux principal policy is redirected".to_owned());
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect Linux principal policy: {error}"))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.nlink() != 1
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.permissions().mode() & 0o022 != 0
        || metadata.len() > LINUX_LOGIN_DEFS_BYTE_LIMIT
    {
        return Err("Linux principal policy identity or permissions are not trusted".to_owned());
    }
    let bytes = fs::read(path)
        .map_err(|error| format!("cannot read Linux principal allocation policy: {error}"))?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| "Linux principal allocation policy is not UTF-8".to_owned())?;
    let mut values = BTreeMap::new();
    for raw_line in text.lines() {
        let line = raw_line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        let Some(name) = fields.first().copied() else {
            continue;
        };
        if !matches!(name, "UID_MIN" | "UID_MAX" | "GID_MIN" | "GID_MAX") {
            continue;
        }
        if fields.len() != 2 || values.contains_key(name) {
            return Err(format!(
                "Linux principal allocation policy has a noncanonical {name}"
            ));
        }
        let value = fields[1]
            .parse::<u32>()
            .map_err(|_| format!("Linux principal allocation policy has an invalid {name}"))?;
        if value.to_string() != fields[1] {
            return Err(format!(
                "Linux principal allocation policy has a noncanonical {name}"
            ));
        }
        values.insert(name, value);
    }
    let value = |name| {
        values
            .get(name)
            .copied()
            .ok_or_else(|| format!("Linux principal allocation policy omits {name}"))
    };
    let first = value("UID_MIN")?.max(value("GID_MIN")?);
    let last = value("UID_MAX")?.min(value("GID_MAX")?);
    let span = last
        .checked_sub(first)
        .and_then(|difference| difference.checked_add(1))
        .filter(|span| *span <= LINUX_PRINCIPAL_ID_SPAN_LIMIT)
        .ok_or_else(|| {
            "Linux principal allocation policy has no bounded shared range".to_owned()
        })?;
    Ok(LinuxPrincipalIdPolicy { first, span })
}

#[cfg(target_os = "linux")]
fn linux_nss_key_is_absent(
    deadline: Instant,
    database: &str,
    key: &str,
    label: &str,
) -> Result<bool, String> {
    let result = run_posix_identity_query_until(
        deadline,
        Path::new("/usr/bin/getent"),
        [database, key],
        label,
    )?;
    posix_nss_record_is_absent(&result, label)
}

#[cfg(target_os = "linux")]
fn candidate_principal_mutation<I, S>(
    sudo: &Path,
    tool: &crate::command::ResolvedStandardExecutable,
    arguments: I,
) -> Result<CommandResult, String>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    tool.revalidate()
        .map_err(|error| format!("candidate principal tool identity changed: {error}"))?;
    CommandSpec::new(sudo.as_os_str(), Duration::from_secs(30))
        .arguments(["-n", "--"])
        .argument(tool.invocation_path())
        .arguments(arguments)
        .run()
        .map_err(|error| format!("candidate principal mutation failed: {error}"))
}

#[cfg(target_os = "linux")]
fn candidate_principal_mutation_succeeded(result: &CommandResult) -> bool {
    !result.timed_out
        && result.status.success()
        && !result.stdout_truncated
        && !result.stderr_truncated
        && result.stdout.is_empty()
        && result.stderr.is_empty()
}

#[cfg(target_os = "linux")]
fn allocate_linux_candidate_principal(
    authorities: Arc<ResolvedPosixProcessAuthorities>,
    prefix: &str,
) -> Result<(String, String, u32, PosixPrincipalCleanup), String> {
    let useradd =
        crate::command::resolve_absolute_standard_executable(Path::new("/usr/sbin/useradd"))
            .map_err(|error| format!("cannot bind Linux user creation authority: {error}"))?;
    allocate_linux_candidate_principal_with_user_tool(authorities, prefix, &useradd, None)
}

#[cfg(target_os = "linux")]
fn allocate_linux_candidate_principal_with_user_tool(
    authorities: Arc<ResolvedPosixProcessAuthorities>,
    prefix: &str,
    useradd: &crate::command::ResolvedStandardExecutable,
    mut attempted: Option<&mut Option<LinuxPrincipalCandidate>>,
) -> Result<(String, String, u32, PosixPrincipalCleanup), String> {
    let sudo = authorities.sudo.invocation_path();
    let policy = linux_principal_id_policy()?;
    let groupadd =
        crate::command::resolve_absolute_standard_executable(Path::new("/usr/sbin/groupadd"))
            .map_err(|error| format!("cannot bind Linux group creation authority: {error}"))?;
    let allocation = POSIX_PRINCIPAL_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let start = (u64::from(std::process::id()) + allocation) % u64::from(policy.span);
    for offset in 0..policy.span {
        let relative = (start + u64::from(offset)) % u64::from(policy.span);
        let id =
            policy
                .first
                .checked_add(u32::try_from(relative).map_err(|_| {
                    "Linux principal allocation offset exceeds its bound".to_owned()
                })?)
                .ok_or_else(|| "Linux principal allocation overflowed".to_owned())?;
        let sequence = allocation
            .checked_add(u64::from(offset))
            .ok_or_else(|| "Linux principal name sequence overflowed".to_owned())?;
        let principal = format!("{prefix}{}x{sequence}", std::process::id());
        if principal.len() > 31
            || !principal
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        {
            return Err("Linux candidate principal name is outside policy".to_owned());
        }
        let group = principal.clone();
        let id_text = id.to_string();
        let reservation_deadline = posix_identity_query_deadline("Linux candidate reservation")?;
        if !linux_nss_key_is_absent(
            reservation_deadline,
            "passwd",
            &principal,
            "candidate principal name",
        )? || !linux_nss_key_is_absent(
            reservation_deadline,
            "group",
            &group,
            "candidate group name",
        )? || !linux_nss_key_is_absent(
            reservation_deadline,
            "passwd",
            &id_text,
            "candidate UID",
        )? || !linux_nss_key_is_absent(reservation_deadline, "group", &id_text, "candidate GID")?
        {
            continue;
        }
        if let Some(attempted) = attempted.as_deref_mut() {
            *attempted = Some(LinuxPrincipalCandidate {
                principal: principal.clone(),
                group: group.clone(),
                id,
            });
        }
        let mut cleanup = PosixPrincipalCleanup::new(
            ReleasePlatform::LinuxX86_64,
            Arc::clone(&authorities),
            principal.clone(),
            group.clone(),
            Some(id),
            Some(id),
        )?;
        let group_result = match candidate_principal_mutation(
            sudo,
            &groupadd,
            ["--gid", id_text.as_str(), group.as_str()],
        ) {
            Ok(result) => result,
            Err(error) => {
                let observation_deadline =
                    posix_identity_query_deadline("Linux group creation observation")?;
                if posix_group_gid(observation_deadline, &group)? == Some(id) {
                    cleanup.group_created = true;
                }
                let cleanup_result = cleanup.finish();
                return cleanup_result.and(Err(format!(
                    "Linux candidate group creation transport failed: {error}"
                )));
            }
        };
        if !candidate_principal_mutation_succeeded(&group_result) {
            let observation_deadline =
                posix_identity_query_deadline("Linux group creation result")?;
            if posix_group_gid(observation_deadline, &group)? == Some(id) {
                cleanup.group_created = true;
                cleanup.finish()?;
                return Err("Linux candidate group creation reported failure after creating its bound group".to_owned());
            }
            let collided = !linux_nss_key_is_absent(
                observation_deadline,
                "group",
                &id_text,
                "candidate GID after collision",
            )? || !linux_nss_key_is_absent(
                observation_deadline,
                "group",
                &group,
                "candidate group name after collision",
            )?;
            if collided {
                cleanup.active = false;
                continue;
            }
            cleanup.active = false;
            return Err(format!(
                "Linux candidate group creation failed without an NSS collision: status={:?}; stderr={}",
                group_result.status.code(),
                String::from_utf8_lossy(&group_result.stderr)
            ));
        }
        cleanup.group_created = true;
        let group_binding_deadline = posix_identity_query_deadline("Linux group binding")?;
        if posix_group_gid(group_binding_deadline, &group)? != Some(id) {
            return Err("Linux candidate group binding changed after creation".to_owned());
        }
        let user_result = match candidate_principal_mutation(
            sudo,
            useradd,
            [
                "--uid",
                id_text.as_str(),
                "--gid",
                group.as_str(),
                "--no-user-group",
                "--no-create-home",
                "--shell",
                "/usr/sbin/nologin",
                principal.as_str(),
            ],
        ) {
            Ok(result) => result,
            Err(error) => {
                let observation_deadline =
                    posix_identity_query_deadline("Linux principal creation observation")?;
                if posix_principal_uid(
                    observation_deadline,
                    ReleasePlatform::LinuxX86_64,
                    &principal,
                )? == Some(id)
                {
                    cleanup.user_created = true;
                }
                let cleanup_result = cleanup.finish();
                return cleanup_result.and(Err(format!(
                    "Linux candidate user creation transport failed: {error}"
                )));
            }
        };
        if !candidate_principal_mutation_succeeded(&user_result) {
            let observation_deadline =
                posix_identity_query_deadline("Linux principal creation result")?;
            if posix_principal_uid(
                observation_deadline,
                ReleasePlatform::LinuxX86_64,
                &principal,
            )? == Some(id)
            {
                cleanup.user_created = true;
                cleanup.finish()?;
                return Err("Linux candidate user creation reported failure after creating its bound principal".to_owned());
            }
            let collided = !linux_nss_key_is_absent(
                observation_deadline,
                "passwd",
                &id_text,
                "candidate UID after collision",
            )? || !linux_nss_key_is_absent(
                observation_deadline,
                "passwd",
                &principal,
                "candidate principal name after collision",
            )?;
            cleanup.finish()?;
            if collided {
                continue;
            }
            return Err(format!(
                "Linux candidate user creation failed without an NSS collision: status={:?}; stderr={}",
                user_result.status.code(),
                String::from_utf8_lossy(&user_result.stderr)
            ));
        }
        cleanup.user_created = true;
        let binding_deadline = posix_identity_query_deadline("Linux candidate binding")?;
        if posix_principal_uid(binding_deadline, ReleasePlatform::LinuxX86_64, &principal)?
            != Some(id)
            || posix_group_gid(binding_deadline, &group)? != Some(id)
        {
            return Err("Linux candidate principal binding changed after creation".to_owned());
        }
        return Ok((principal, group, id, cleanup));
    }
    Err("Linux principal allocation range is exhausted".to_owned())
}

#[cfg(target_os = "linux")]
fn verify_linux_candidate_principal_rollback(sudo: &Path) -> Result<(), String> {
    let authorities = ResolvedPosixProcessAuthorities::resolve()?;
    if authorities.sudo.invocation_path() != sudo {
        return Err("Linux rollback verifier sudo authority differs from confinement".to_owned());
    }
    let rejecting_useradd = crate::command::resolve_absolute_standard_executable(Path::new(
        "/usr/bin/false",
    ))
    .map_err(|error| format!("cannot bind injected Linux user-creation failure: {error}"))?;
    let mut attempted = None;
    let error = match allocate_linux_candidate_principal_with_user_tool(
        authorities,
        "hellrbk",
        &rejecting_useradd,
        Some(&mut attempted),
    ) {
        Ok((_principal, _group, _id, cleanup)) => {
            cleanup.finish()?;
            return Err("injected Linux user-creation failure unexpectedly succeeded".to_owned());
        }
        Err(error) => error,
    };
    if error
        != "Linux candidate user creation failed without an NSS collision: status=Some(1); stderr="
    {
        return Err(format!(
            "injected Linux user-creation failure reached the wrong phase: {error}"
        ));
    }
    let attempted = attempted.ok_or_else(|| {
        "injected Linux user-creation failure had no reservation receipt".to_owned()
    })?;
    let rollback_deadline = posix_identity_query_deadline("Linux candidate rollback attestation")?;
    if posix_principal_uid(
        rollback_deadline,
        ReleasePlatform::LinuxX86_64,
        &attempted.principal,
    )?
    .is_some()
        || posix_group_gid(rollback_deadline, &attempted.group)?.is_some()
    {
        return Err(
            "injected Linux user-creation failure left a principal or group behind".to_owned(),
        );
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn verify_linux_candidate_principal_rollback(_sudo: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(target_os = "macos")]
fn allocate_linux_candidate_principal(
    _authorities: Arc<ResolvedPosixProcessAuthorities>,
    _prefix: &str,
) -> Result<(String, String, u32, PosixPrincipalCleanup), String> {
    Err("Linux candidate principal allocation selected on macOS".to_owned())
}

#[cfg(target_os = "macos")]
fn posix_group_gid(deadline: Instant, group: &str) -> Result<Option<u32>, String> {
    macos_directory_service_id(
        deadline,
        "/Groups",
        "PrimaryGroupID",
        group,
        "candidate group",
    )
}

#[cfg(unix)]
fn trusted_tool_status<I, S>(
    sudo: &Path,
    tool: &crate::command::ResolvedStandardExecutable,
    arguments: I,
) -> Result<(), String>
where
    I: IntoIterator<Item = S>,
    S: Into<std::ffi::OsString>,
{
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(30))
        .ok_or_else(|| "trusted confinement command deadline overflowed".to_owned())?;
    trusted_tool_status_before(deadline, sudo, tool, arguments)
}

#[cfg(unix)]
fn trusted_tool_status_before<I, S>(
    deadline: Instant,
    sudo: &Path,
    tool: &crate::command::ResolvedStandardExecutable,
    arguments: I,
) -> Result<(), String>
where
    I: IntoIterator<Item = S>,
    S: Into<std::ffi::OsString>,
{
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| "trusted confinement command deadline expired before launch".to_owned())?;
    tool.revalidate()
        .map_err(|error| format!("trusted confinement tool validation failed: {error}"))?;
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| "trusted confinement command deadline expired after validation".to_owned())?
        .min(remaining);
    let result = CommandSpec::new(sudo.as_os_str(), remaining)
        .arguments(["-n", "--"])
        .argument(tool.invocation_path())
        .arguments(arguments)
        .run()
        .map_err(|error| format!("trusted confinement command failed: {error}"))?;
    if !result.status.success() || result.timed_out {
        return Err("trusted confinement command did not succeed".to_owned());
    }
    Ok(())
}

#[cfg(unix)]
fn trusted_status<const N: usize>(program: &Path, arguments: [&str; N]) -> Result<(), String> {
    let result = CommandSpec::new(program.as_os_str(), Duration::from_secs(30))
        .arguments(arguments)
        .run()
        .map_err(|error| format!("trusted confinement command failed: {error}"))?;
    if !result.status.success() || result.timed_out {
        return Err("trusted confinement command did not succeed".to_owned());
    }
    Ok(())
}

#[cfg(unix)]
fn require_exact_posix_candidate_identity(
    id: &crate::command::ResolvedStandardExecutable,
    option: &str,
    principal: &str,
    expected: u32,
    label: &str,
) -> Result<(), String> {
    let output = exact_posix_candidate_identity_output(id, option, principal, label)?;
    if !posix_candidate_identity_output_is_exact(&output, expected) {
        return Err(format!(
            "candidate {label} differs from the bound numeric identity"
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn exact_posix_candidate_identity_output(
    id: &crate::command::ResolvedStandardExecutable,
    option: &str,
    principal: &str,
    label: &str,
) -> Result<Vec<u8>, String> {
    id.revalidate()
        .map_err(|error| format!("trusted candidate identity validation failed: {error}"))?;
    let result = CommandSpec::new(id.invocation_path().as_os_str(), Duration::from_secs(30))
        .arguments([option, principal])
        .run()
        .map_err(|error| format!("trusted candidate identity command failed: {error}"))?;
    if !result.status.success()
        || result.timed_out
        || result.stdout_truncated
        || result.stderr_truncated
        || !result.stderr.is_empty()
    {
        return Err(format!("candidate {label} query did not succeed exactly"));
    }
    Ok(result.stdout)
}

#[cfg(unix)]
fn posix_candidate_identity_output_is_exact(output: &[u8], expected: u32) -> bool {
    output == format!("{expected}\n").as_bytes()
}

#[cfg(unix)]
fn parse_posix_candidate_identity_output(output: &[u8], label: &str) -> Result<u32, String> {
    let digits = output.strip_suffix(b"\n").unwrap_or(output);
    let text = std::str::from_utf8(digits).map_err(|_| format!("{label} is not UTF-8"))?;
    let identity = text
        .parse::<u32>()
        .map_err(|_| format!("{label} is not one numeric identity"))?;
    if text.is_empty() || text != identity.to_string() {
        return Err(format!("{label} is not canonically encoded"));
    }
    Ok(identity)
}

#[cfg(unix)]
fn posix_candidate_group_inventory(output: &[u8], primary_gid: u32) -> Option<Vec<u32>> {
    let line = output.strip_suffix(b"\n")?;
    if line.is_empty() {
        return None;
    }
    let mut groups = Vec::new();
    let mut unique = BTreeSet::new();
    for token in line.split(|byte| *byte == b' ') {
        let text = std::str::from_utf8(token).ok()?;
        let group = text.parse::<u32>().ok()?;
        if text != group.to_string() || !unique.insert(group) {
            return None;
        }
        groups.push(group);
        if groups.len() > hell_testkit::POSIX_CANDIDATE_GROUP_LIMIT {
            return None;
        }
    }
    groups.contains(&primary_gid).then_some(groups)
}

#[cfg(unix)]
fn normalize_candidate_cache_with_adapter(
    sudo: &Path,
    adapter: &PosixAdapterProtection,
    root: &Path,
    trusted_owner: u32,
    candidate_group: u32,
) -> Result<(), String> {
    normalize_candidate_cache_with_adapter_policy(
        sudo,
        adapter,
        root,
        trusted_owner,
        candidate_group,
        None,
    )
}

#[cfg(unix)]
fn normalize_candidate_cache_export_replacement_with_adapter(
    sudo: &Path,
    adapter: &PosixAdapterProtection,
    root: &Path,
    workspace_target: &Path,
    trusted_owner: u32,
    candidate_group: u32,
) -> Result<(), String> {
    normalize_candidate_cache_with_adapter_policy(
        sudo,
        adapter,
        root,
        trusted_owner,
        candidate_group,
        Some(workspace_target),
    )
}

#[cfg(unix)]
fn normalize_candidate_cache_with_adapter_policy(
    sudo: &Path,
    adapter: &PosixAdapterProtection,
    root: &Path,
    trusted_owner: u32,
    candidate_group: u32,
    replacement_for: Option<&Path>,
) -> Result<(), String> {
    require_posix_adapter_unchanged(adapter)?;
    if let Some(workspace_target) = replacement_for {
        validate_candidate_cache_export_replacement_root(
            root,
            workspace_target,
            std::process::id(),
        )?;
    } else {
        validate_candidate_cache_normalizer_root(root)?;
    }
    if adapter.platform == ReleasePlatform::MacosAarch64 {
        let tools = resolve_posix_adapter_tools(adapter.platform)?;
        trusted_tool_status(
            sudo,
            &tools.chmod,
            posix_acl_removal_arguments(
                adapter.platform,
                true,
                path_text(root, "candidate cache ACL boundary")?,
            )?,
        )?;
    }
    let adapter_text = path_text(&adapter.adapter, "trusted candidate cache normalizer")?;
    let root_text = path_text(root, "candidate cache")?;
    let trusted_owner = trusted_owner.to_string();
    let candidate_group = candidate_group.to_string();
    let status = if let Some(workspace_target) = replacement_for {
        trusted_status(
            sudo,
            [
                "-n",
                "--",
                adapter_text,
                "__release-normalize-candidate-cache",
                root_text,
                &trusted_owner,
                &candidate_group,
                path_text(
                    workspace_target,
                    "hosted candidate target replacement authority",
                )?,
                &std::process::id().to_string(),
            ],
        )
    } else {
        trusted_status(
            sudo,
            [
                "-n",
                "--",
                adapter_text,
                "__release-normalize-candidate-cache",
                root_text,
                &trusted_owner,
                &candidate_group,
            ],
        )
    };
    status.map_err(|error| format!("cannot normalize restored candidate cache: {error}"))?;
    require_posix_adapter_unchanged(adapter)
}

#[cfg(unix)]
const POSIX_CANDIDATE_TARGET_ENTRY_LIMIT: usize = 1_000_000;

#[cfg(unix)]
const POSIX_CANDIDATE_TARGET_BYTE_LIMIT: u64 = 64 * 1024 * 1024 * 1024;

#[cfg(unix)]
#[derive(Default)]
struct PosixCandidateTargetBudget {
    entries: usize,
    bytes: u64,
}

#[cfg(unix)]
impl PosixCandidateTargetBudget {
    fn account(&mut self, bytes: u64) -> Result<(), String> {
        self.entries = self
            .entries
            .checked_add(1)
            .ok_or_else(|| "candidate target entry count overflowed".to_owned())?;
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .ok_or_else(|| "candidate target byte count overflowed".to_owned())?;
        if self.entries > POSIX_CANDIDATE_TARGET_ENTRY_LIMIT
            || self.bytes > POSIX_CANDIDATE_TARGET_BYTE_LIMIT
        {
            return Err("candidate target exceeds its import/export resource bound".to_owned());
        }
        Ok(())
    }
}

#[cfg(unix)]
fn copy_posix_candidate_target_tree(
    source: &Path,
    destination: &Path,
    budget: &mut PosixCandidateTargetBudget,
) -> Result<(), String> {
    let source_before = posix_candidate_target_receipt(source)?;
    copy_posix_candidate_target_tree_entries(source, destination, budget)?;
    let source_after = posix_candidate_target_receipt(source)?;
    let destination_receipt = posix_candidate_target_receipt(destination)?;
    if source_before != source_after
        || source_after.manifest != destination_receipt.manifest
        || !destination_receipt.is_dealiased()
    {
        return Err("candidate target changed or retained aliases while it was copied".to_owned());
    }
    Ok(())
}

#[cfg(unix)]
fn copy_posix_candidate_target_tree_entries(
    source: &Path,
    destination: &Path,
    budget: &mut PosixCandidateTargetBudget,
) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;

    let before = fs::symlink_metadata(source)
        .map_err(|error| format!("cannot inspect candidate target import source: {error}"))?;
    let file_type = before.file_type();
    if file_type.is_symlink()
        || (!file_type.is_dir() && !file_type.is_file())
        || fs::canonicalize(source)
            .map_err(|error| format!("cannot canonicalize candidate target import: {error}"))?
            != source
        || fs::symlink_metadata(destination).is_ok()
    {
        return Err(
            "candidate target import contains a redirected, special, linked, or colliding entry"
                .to_owned(),
        );
    }
    budget.account(if file_type.is_file() { before.len() } else { 0 })?;
    if file_type.is_dir() {
        fs::create_dir(destination)
            .map_err(|error| format!("cannot create staged candidate target directory: {error}"))?;
        let entries = fs::read_dir(source)
            .map_err(|error| format!("cannot enumerate candidate target import: {error}"))?
            .map(|entry| {
                entry
                    .map(|entry| (entry.file_name(), entry.path()))
                    .map_err(|error| {
                        format!("cannot inspect candidate target import entry: {error}")
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let names = entries
            .iter()
            .map(|(name, _)| name.clone())
            .collect::<BTreeSet<_>>();
        for (name, path) in entries {
            copy_posix_candidate_target_tree_entries(&path, &destination.join(name), budget)?;
        }
        let after = fs::symlink_metadata(source)
            .map_err(|error| format!("cannot revalidate candidate target import: {error}"))?;
        let names_after = fs::read_dir(source)
            .map_err(|error| format!("cannot re-enumerate candidate target import: {error}"))?
            .map(|entry| {
                entry.map(|entry| entry.file_name()).map_err(|error| {
                    format!("cannot reread candidate target import entry: {error}")
                })
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        if !after.is_dir()
            || after.file_type().is_symlink()
            || after.dev() != before.dev()
            || after.ino() != before.ino()
            || names_after != names
        {
            return Err("candidate target import changed while it was copied".to_owned());
        }
    } else {
        let copied = fs::copy(source, destination)
            .map_err(|error| format!("cannot copy candidate target import file: {error}"))?;
        let after = fs::symlink_metadata(source)
            .map_err(|error| format!("cannot revalidate candidate target import file: {error}"))?;
        let staged = fs::symlink_metadata(destination)
            .map_err(|error| format!("cannot inspect staged candidate target file: {error}"))?;
        if copied != before.len()
            || after.dev() != before.dev()
            || after.ino() != before.ino()
            || after.len() != before.len()
            || after.nlink() != before.nlink()
            || !staged.is_file()
            || staged.file_type().is_symlink()
            || staged.len() != before.len()
            || staged.nlink() != 1
        {
            return Err("candidate target import file changed while it was copied".to_owned());
        }
    }
    Ok(())
}

#[cfg(unix)]
fn stage_posix_candidate_target(
    sudo: &Path,
    adapter: &PosixAdapterProtection,
    workspace_target: &Path,
    transient: &Path,
    trusted_owner: u32,
    trusted_group: u32,
    candidate_group: u32,
) -> Result<PosixCandidateTargetProtection, String> {
    validate_candidate_cache_normalizer_root(workspace_target)?;
    let workspace_identity = posix_object_identity(workspace_target)?;
    if workspace_identity.owner != trusted_owner {
        return Err(
            "hosted candidate target owner differs from the trusted checkout owner".to_owned(),
        );
    }
    let staged = transient.join("candidate-target");
    if staged.parent() != Some(transient)
        || staged.file_name() != Some(std::ffi::OsStr::new("candidate-target"))
        || staged.exists()
    {
        return Err("staged candidate target path differs from policy".to_owned());
    }
    let mut budget = PosixCandidateTargetBudget::default();
    copy_posix_candidate_target_tree(workspace_target, &staged, &mut budget)?;
    normalize_candidate_cache_with_adapter(sudo, adapter, &staged, trusted_owner, candidate_group)?;
    let staged_identity = posix_object_identity(&staged)?;
    if staged_identity.owner != trusted_owner
        || staged_identity.group != candidate_group
        || staged_identity.mode != 0o2770
        || fs::canonicalize(&staged)
            .map_err(|error| format!("cannot canonicalize staged candidate target: {error}"))?
            != staged
        || posix_object_identity(workspace_target)? != workspace_identity
    {
        return Err("staged candidate target authority differs after import".to_owned());
    }
    Ok(PosixCandidateTargetProtection {
        staged,
        staged_identity,
        workspace: workspace_target.to_path_buf(),
        workspace_identity,
        trusted_owner,
        trusted_group,
    })
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct PosixCandidateTargetManifestEntry {
    directory: bool,
    bytes: u64,
    sha256: Option<hell_testkit::Digest>,
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct PosixCandidateTargetTopologyEntry {
    directory: bool,
    device: u64,
    inode: u64,
    links: u64,
    owner: u32,
    group: u32,
    mode: u32,
    bytes: u64,
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct PosixCandidateTargetReceipt {
    manifest: BTreeMap<PathBuf, PosixCandidateTargetManifestEntry>,
    topology: BTreeMap<PathBuf, PosixCandidateTargetTopologyEntry>,
}

#[cfg(unix)]
impl PosixCandidateTargetReceipt {
    fn is_dealiased(&self) -> bool {
        self.topology
            .values()
            .all(|entry| entry.directory || entry.links == 1)
    }
}

#[cfg(unix)]
fn posix_candidate_target_receipt(root: &Path) -> Result<PosixCandidateTargetReceipt, String> {
    use std::os::unix::fs::MetadataExt as _;

    let root = fs::canonicalize(root)
        .map_err(|error| format!("cannot canonicalize candidate target manifest root: {error}"))?;
    let mut budget = PosixCandidateTargetBudget::default();
    let mut manifest = BTreeMap::new();
    let mut topology = BTreeMap::new();
    let mut pending = vec![root.clone()];
    while let Some(path) = pending.pop() {
        let before = fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot inspect candidate target manifest entry: {error}"))?;
        let file_type = before.file_type();
        if file_type.is_symlink()
            || (!file_type.is_dir() && !file_type.is_file())
            || fs::canonicalize(&path).map_err(|error| {
                format!("cannot canonicalize candidate target manifest entry: {error}")
            })? != path
        {
            return Err(
                "candidate target manifest contains a redirected or special entry".to_owned(),
            );
        }
        let bytes = if file_type.is_file() { before.len() } else { 0 };
        budget.account(bytes)?;
        let relative = path
            .strip_prefix(&root)
            .map_err(|_| "candidate target manifest entry escapes its root".to_owned())?
            .to_path_buf();
        let sha256 = file_type
            .is_file()
            .then(|| hell_testkit::sha256_file(&path))
            .transpose()
            .map_err(|error| format!("cannot hash candidate target manifest entry: {error}"))?;
        if manifest
            .insert(
                relative.clone(),
                PosixCandidateTargetManifestEntry {
                    directory: file_type.is_dir(),
                    bytes,
                    sha256,
                },
            )
            .is_some()
        {
            return Err("candidate target manifest contains a duplicate path".to_owned());
        }
        if topology
            .insert(
                relative,
                PosixCandidateTargetTopologyEntry {
                    directory: file_type.is_dir(),
                    device: before.dev(),
                    inode: before.ino(),
                    links: before.nlink(),
                    owner: before.uid(),
                    group: before.gid(),
                    mode: before.mode(),
                    bytes,
                },
            )
            .is_some()
        {
            return Err("candidate target topology contains a duplicate path".to_owned());
        }
        let directory_names = if file_type.is_dir() {
            let mut entries = fs::read_dir(&path)
                .map_err(|error| {
                    format!("cannot enumerate candidate target manifest directory: {error}")
                })?
                .map(|entry| {
                    entry
                        .map(|entry| (entry.file_name(), entry.path()))
                        .map_err(|error| {
                            format!("cannot inspect candidate target manifest member: {error}")
                        })
                })
                .collect::<Result<Vec<_>, _>>()?;
            entries.sort_by(|(left, _), (right, _)| left.cmp(right));
            let names = entries
                .iter()
                .map(|(name, _)| name.clone())
                .collect::<BTreeSet<_>>();
            pending.extend(entries.into_iter().rev().map(|(_, path)| path));
            Some(names)
        } else {
            None
        };
        let after = fs::symlink_metadata(&path).map_err(|error| {
            format!("cannot revalidate candidate target manifest entry: {error}")
        })?;
        if after.dev() != before.dev()
            || after.ino() != before.ino()
            || after.len() != before.len()
            || after.nlink() != before.nlink()
            || after.uid() != before.uid()
            || after.gid() != before.gid()
            || after.mode() != before.mode()
            || after.file_type() != before.file_type()
        {
            return Err("candidate target changed while its manifest was captured".to_owned());
        }
        if let Some(directory_names) = directory_names {
            let names_after = fs::read_dir(&path)
                .map_err(|error| {
                    format!("cannot re-enumerate candidate target manifest directory: {error}")
                })?
                .map(|entry| {
                    entry.map(|entry| entry.file_name()).map_err(|error| {
                        format!("cannot revalidate candidate target manifest member: {error}")
                    })
                })
                .collect::<Result<BTreeSet<_>, _>>()?;
            if names_after != directory_names {
                return Err(
                    "candidate target directory changed while its manifest was captured".to_owned(),
                );
            }
        } else if hell_testkit::sha256_file(&path)
            .map_err(|error| format!("cannot rehash candidate target manifest entry: {error}"))?
            != sha256.expect("file manifest retains a digest")
        {
            return Err("candidate target file changed while its manifest was captured".to_owned());
        }
    }
    let mut observed_links = BTreeMap::<(u64, u64), u64>::new();
    for entry in topology.values().filter(|entry| !entry.directory) {
        let observed = observed_links
            .entry((entry.device, entry.inode))
            .or_default();
        *observed = observed
            .checked_add(1)
            .ok_or_else(|| "candidate target hard-link count overflowed".to_owned())?;
    }
    for entry in topology.values().filter(|entry| !entry.directory) {
        if observed_links.get(&(entry.device, entry.inode)).copied() != Some(entry.links) {
            return Err("candidate target contains a hard link outside its authority".to_owned());
        }
    }
    Ok(PosixCandidateTargetReceipt { manifest, topology })
}

#[cfg(unix)]
fn posix_candidate_target_manifest(
    root: &Path,
) -> Result<BTreeMap<PathBuf, PosixCandidateTargetManifestEntry>, String> {
    Ok(posix_candidate_target_receipt(root)?.manifest)
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PosixCandidateTargetExportFault {
    None,
    AfterBackupRename,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum PosixCandidateTargetExportPhase {
    #[default]
    PreTransaction,
    ReplacementPrepared,
    BackupRenamed,
    InjectedRollbackComplete,
    ReplacementCommitted,
}

#[cfg(unix)]
#[derive(Debug, Default)]
struct PosixCandidateTargetExportReceipt {
    phase: PosixCandidateTargetExportPhase,
}

#[cfg(unix)]
fn export_posix_candidate_target(
    adapter: &PosixAdapterProtection,
    protection: &mut PosixCandidateTargetProtection,
    workspace_target: &Path,
) -> Result<(), String> {
    let mut receipt = PosixCandidateTargetExportReceipt::default();
    export_posix_candidate_target_with_fault(
        adapter,
        protection,
        workspace_target,
        PosixCandidateTargetExportFault::None,
        &mut receipt,
    )?;
    if receipt.phase != PosixCandidateTargetExportPhase::ReplacementCommitted {
        return Err("candidate target export completed without a commit receipt".to_owned());
    }
    Ok(())
}

#[cfg(unix)]
fn export_posix_candidate_target_with_fault(
    adapter: &PosixAdapterProtection,
    protection: &mut PosixCandidateTargetProtection,
    workspace_target: &Path,
    fault: PosixCandidateTargetExportFault,
    receipt: &mut PosixCandidateTargetExportReceipt,
) -> Result<(), String> {
    if workspace_target != protection.workspace
        || posix_object_identity(workspace_target)? != protection.workspace_identity
        || posix_object_identity(&protection.staged)? != protection.staged_identity
    {
        return Err("candidate target import/export root identity changed".to_owned());
    }
    if posix_object_identity(&protection.staged)? != protection.staged_identity {
        return Err("staged candidate target root changed during candidate execution".to_owned());
    }

    let source_manifest_before = posix_candidate_target_manifest(&protection.staged)?;
    let replacement = workspace_target.with_file_name(format!(
        "candidate-target-export-replacement-{}",
        std::process::id()
    ));
    let backup = workspace_target.with_file_name(format!(
        "candidate-target-export-backup-{}",
        std::process::id()
    ));
    for reserved in [&replacement, &backup] {
        match fs::symlink_metadata(reserved) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err("candidate target export sibling authority already exists".to_owned()),
        }
    }
    if replacement.parent() != workspace_target.parent()
        || backup.parent() != workspace_target.parent()
    {
        return Err("candidate target export siblings escape the hosted filesystem".to_owned());
    }
    let prepare_result = (|| {
        let mut budget = PosixCandidateTargetBudget::default();
        copy_posix_candidate_target_tree(&protection.staged, &replacement, &mut budget)?;
        normalize_candidate_cache_export_replacement_with_adapter(
            &adapter.sudo,
            adapter,
            &replacement,
            workspace_target,
            protection.trusted_owner,
            protection.trusted_group,
        )?;
        let source_manifest_after = posix_candidate_target_manifest(&protection.staged)?;
        let replacement_manifest = posix_candidate_target_manifest(&replacement)?;
        if source_manifest_before != source_manifest_after
            || source_manifest_after != replacement_manifest
        {
            return Err(
                "candidate target replacement manifest differs from staged output".to_owned(),
            );
        }
        Ok((replacement_manifest, posix_object_identity(&replacement)?))
    })();
    let (replacement_manifest, replacement_identity) = match prepare_result {
        Ok(prepared) => prepared,
        Err(error) => {
            let _ = fs::remove_dir_all(&replacement);
            return Err(error);
        }
    };
    receipt.phase = PosixCandidateTargetExportPhase::ReplacementPrepared;
    let old_manifest = posix_candidate_target_manifest(workspace_target)?;
    let old_identity = posix_object_identity(workspace_target)?;
    if let Err(error) = fs::rename(workspace_target, &backup) {
        let cleanup = fs::remove_dir_all(&replacement);
        cleanup.map_err(|cleanup_error| {
            format!(
                "cannot retain hosted candidate target backup ({error}) or clean replacement: {cleanup_error}"
            )
        })?;
        return Err(format!(
            "cannot retain hosted candidate target backup: {error}"
        ));
    }
    receipt.phase = PosixCandidateTargetExportPhase::BackupRenamed;
    let backup_validation = (|| {
        if posix_object_identity(&backup)? != old_identity
            || posix_candidate_target_manifest(&backup)? != old_manifest
        {
            return Err("hosted candidate target backup identity changed".to_owned());
        }
        Ok(())
    })();
    if let Err(error) = backup_validation {
        let rollback = fs::rename(&backup, workspace_target);
        let _ = fs::remove_dir_all(&replacement);
        rollback.map_err(|error| {
            format!("hosted candidate target backup validation and rollback failed: {error}")
        })?;
        return Err(error);
    }
    if fault == PosixCandidateTargetExportFault::AfterBackupRename {
        fs::rename(&backup, workspace_target).map_err(|error| {
            format!("cannot restore hosted candidate target after injected failure: {error}")
        })?;
        fs::remove_dir_all(&replacement).map_err(|error| {
            format!("cannot remove replacement after injected export failure: {error}")
        })?;
        if posix_object_identity(workspace_target)? != old_identity
            || posix_candidate_target_manifest(workspace_target)? != old_manifest
        {
            return Err(
                "injected candidate target export rollback changed the old cache".to_owned(),
            );
        }
        receipt.phase = PosixCandidateTargetExportPhase::InjectedRollbackComplete;
        return Err("injected candidate target export failure after backup rename".to_owned());
    }
    if let Err(error) = fs::rename(&replacement, workspace_target) {
        let rollback = fs::rename(&backup, workspace_target);
        let _ = fs::remove_dir_all(&replacement);
        rollback.map_err(|rollback_error| {
            format!(
                "candidate target replacement failed ({error}) and rollback failed: {rollback_error}"
            )
        })?;
        return Err(format!(
            "cannot install candidate target replacement: {error}"
        ));
    }
    let committed = posix_object_identity(workspace_target).and_then(|identity| {
        if identity != replacement_identity
            || posix_candidate_target_manifest(workspace_target)? != replacement_manifest
        {
            return Err("committed candidate target replacement changed".to_owned());
        }
        Ok(identity)
    });
    let committed_identity = match committed {
        Ok(identity) => identity,
        Err(error) => {
            let displaced = fs::rename(workspace_target, &replacement);
            let restored = displaced.and_then(|()| fs::rename(&backup, workspace_target));
            let _ = fs::remove_dir_all(&replacement);
            restored.map_err(|rollback_error| {
                format!("candidate target commit validation failed ({error}) and rollback failed: {rollback_error}")
            })?;
            if posix_object_identity(workspace_target)? != old_identity
                || posix_candidate_target_manifest(workspace_target)? != old_manifest
            {
                return Err("candidate target rollback did not restore the old cache".to_owned());
            }
            return Err(error);
        }
    };
    let cleanup = match fs::remove_dir_all(&backup) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "cannot remove committed candidate target backup: {error}"
        )),
    };
    protection.workspace_identity = committed_identity;
    cleanup?;
    receipt.phase = PosixCandidateTargetExportPhase::ReplacementCommitted;
    Ok(())
}

#[cfg(unix)]
fn require_posix_adapter_unchanged(protection: &PosixAdapterProtection) -> Result<(), String> {
    if validate_posix_adapter_installation_root(protection.platform, &protection.installation_root)?
        != protection.installation_root
        || posix_object_identity(&protection.installation_root)?
            != protection.installation_root_identity
        || !posix_adapter_cleanup_is_exact(
            &protection.installation_root,
            &protection.directory,
            &protection.adapter,
            protection.staged_name,
        )
        || posix_object_identity(&protection.directory)? != protection.directory_identity
        || posix_object_identity(&protection.adapter)? != protection.adapter_identity
        || hell_testkit::sha256_file(&protection.adapter)
            .map_err(|error| format!("cannot rehash trusted POSIX adapter: {error}"))?
            != protection.sha256
    {
        return Err("trusted POSIX adapter identity changed".to_owned());
    }
    Ok(())
}

#[cfg(unix)]
fn set_posix_mode(path: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|error| format!("cannot set candidate writable mode: {error}"))
}

#[cfg(unix)]
fn normalize_candidate_cache_tree(
    root: &Path,
    ownership: Option<(u32, u32)>,
) -> Result<(), String> {
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};

    let mut pending = vec![root.to_path_buf()];
    let mut entries = 0_usize;
    let mut bytes = 0_u64;
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot inspect restored candidate cache: {error}"))?;
        let file_type = metadata.file_type();
        if file_type.is_symlink()
            || file_type.is_block_device()
            || file_type.is_char_device()
            || file_type.is_fifo()
            || file_type.is_socket()
        {
            return Err("restored candidate cache contains a link or special file".to_owned());
        }
        entries = entries
            .checked_add(1)
            .ok_or_else(|| "restored candidate cache entry count overflowed".to_owned())?;
        bytes = bytes
            .checked_add(if file_type.is_file() {
                metadata.len()
            } else {
                0
            })
            .ok_or_else(|| "restored candidate cache byte count overflowed".to_owned())?;
        if entries > POSIX_CANDIDATE_TARGET_ENTRY_LIMIT || bytes > POSIX_CANDIDATE_TARGET_BYTE_LIMIT
        {
            return Err("restored candidate cache exceeds its resource bound".to_owned());
        }
        if file_type.is_dir() {
            if let Some((owner, group)) = ownership {
                std::os::unix::fs::chown(&path, Some(owner), Some(group)).map_err(|error| {
                    format!("cannot restore candidate cache ownership: {error}")
                })?;
            }
            set_posix_mode(&path, 0o2770)?;
            for entry in fs::read_dir(&path).map_err(|error| {
                format!(
                    "cannot enumerate restored candidate cache {}: {error}",
                    path.display()
                )
            })? {
                pending.push(
                    entry
                        .map_err(|error| format!("cannot read restored cache entry: {error}"))?
                        .path(),
                );
            }
        } else if file_type.is_file() {
            if metadata.nlink() != 1 {
                return Err("restored candidate cache contains a multiply-linked file".to_owned());
            }
            if let Some((owner, group)) = ownership {
                std::os::unix::fs::chown(&path, Some(owner), Some(group)).map_err(|error| {
                    format!("cannot restore candidate cache ownership: {error}")
                })?;
            }
            let executable = metadata.permissions().mode() & 0o111 != 0;
            set_posix_mode(&path, if executable { 0o770 } else { 0o660 })?;
        } else {
            return Err("restored candidate cache entry is not regular".to_owned());
        }
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn run_posix_candidate_cache_normalizer(arguments: &[OsString]) -> Result<(), String> {
    let [root, owner, group, replacement_for @ ..] = arguments else {
        return Err(
            "trusted candidate cache normalizer requires path, owner, and group".to_owned(),
        );
    };
    let root = PathBuf::from(root);
    match replacement_for {
        [] => validate_candidate_cache_normalizer_root(&root)?,
        [workspace_target, token] => {
            let token_text = token.to_str().ok_or_else(|| {
                "trusted candidate cache replacement token is not UTF-8".to_owned()
            })?;
            let token = token_text
                .parse::<u32>()
                .map_err(|_| "trusted candidate cache replacement token is malformed".to_owned())?;
            if token_text != token.to_string() {
                return Err("trusted candidate cache replacement token is noncanonical".to_owned());
            }
            validate_candidate_cache_export_replacement_root(
                &root,
                Path::new(workspace_target),
                token,
            )?;
        }
        _ => {
            return Err(
                "trusted candidate cache normalizer replacement authority is malformed".to_owned(),
            );
        }
    }
    let owner = owner
        .to_str()
        .ok_or_else(|| "trusted candidate cache owner is not UTF-8".to_owned())?
        .parse::<u32>()
        .map_err(|_| "trusted candidate cache owner is invalid".to_owned())?;
    let group = group
        .to_str()
        .ok_or_else(|| "trusted candidate cache group is not UTF-8".to_owned())?
        .parse::<u32>()
        .map_err(|_| "trusted candidate cache group is invalid".to_owned())?;
    normalize_candidate_cache_tree(&root, Some((owner, group)))
}

#[cfg(unix)]
#[derive(Clone, Copy)]
struct PosixVerifierRemovalPolicy {
    entry_limit: usize,
    depth_limit: usize,
    deadline: Instant,
}

#[cfg(unix)]
pub(crate) fn run_posix_candidate_target_verifier_remover(
    arguments: &[OsString],
) -> Result<(), String> {
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(30))
        .ok_or_else(|| "candidate target verifier remover deadline overflowed".to_owned())?;
    run_posix_candidate_target_verifier_remover_with_policy(
        arguments,
        PosixVerifierRemovalPolicy {
            entry_limit: 1_000_000,
            depth_limit: 256,
            deadline,
        },
    )
}

#[cfg(unix)]
fn run_posix_candidate_target_verifier_remover_with_policy(
    arguments: &[OsString],
    policy: PosixVerifierRemovalPolicy,
) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt as _;

    let [root, parent_device, parent_inode, root_device, root_inode] = arguments else {
        return Err(
            "candidate target verifier remover requires root and exact parent/root identities"
                .to_owned(),
        );
    };
    let parse_identity = |value: &OsStr, label: &str| {
        let text = value
            .to_str()
            .ok_or_else(|| format!("candidate target verifier {label} is not UTF-8"))?;
        let number = text
            .parse::<u64>()
            .map_err(|_| format!("candidate target verifier {label} is malformed"))?;
        if text != number.to_string() {
            return Err(format!("candidate target verifier {label} is noncanonical"));
        }
        Ok(number)
    };
    let root = PathBuf::from(root);
    let require_time = || {
        policy
            .deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| "candidate target verifier cleanup deadline expired".to_owned())
            .map(|_| ())
    };
    require_time()?;
    #[cfg(target_os = "linux")]
    let platform = ReleasePlatform::LinuxX86_64;
    #[cfg(target_os = "macos")]
    let platform = ReleasePlatform::MacosAarch64;
    let parent = posix_adapter_installation_root(platform)?;
    let expected_parent_device = parse_identity(parent_device, "parent device")?;
    let expected_parent_inode = parse_identity(parent_inode, "parent inode")?;
    let expected_root_device = parse_identity(root_device, "root device")?;
    let expected_root_inode = parse_identity(root_inode, "root inode")?;
    let parent_identity = posix_object_identity(&parent)?;
    let root_metadata = fs::symlink_metadata(&root).map_err(|error| {
        format!("cannot inspect candidate target verifier removal root: {error}")
    })?;
    let root_identity = posix_object_identity_from_metadata(&root_metadata);
    if root.parent() != Some(parent.as_path())
        || !posix_candidate_target_verifier_root_is_exact(platform, &root)
        || parent_identity.device != expected_parent_device
        || parent_identity.inode != expected_parent_inode
        || root_identity.device != expected_root_device
        || root_identity.inode != expected_root_inode
        || root_metadata.file_type().is_symlink()
        || !root_metadata.is_dir()
        || fs::canonicalize(&root).map_err(|error| {
            format!("cannot canonicalize candidate target verifier removal root: {error}")
        })? != root
    {
        return Err(
            "candidate target verifier removal authority differs from its receipt".to_owned(),
        );
    }

    let mut discovered = 1_usize;
    if discovered > policy.entry_limit {
        return Err("candidate target verifier cleanup exceeds its entry bound".to_owned());
    }
    let mut pending = vec![(root.clone(), false, 0_usize)];
    while let Some((path, visited, depth)) = pending.pop() {
        require_time()?;
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            format!("cannot inspect candidate target verifier removal member: {error}")
        })?;
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            if visited {
                fs::remove_dir(&path).map_err(|error| {
                    format!("cannot remove candidate target verifier directory: {error}")
                })?;
                continue;
            }
            if depth >= policy.depth_limit {
                return Err("candidate target verifier cleanup exceeds its depth bound".to_owned());
            }
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).map_err(|error| {
                format!("cannot open candidate target verifier directory for cleanup: {error}")
            })?;
            let entries = fs::read_dir(&path).map_err(|error| {
                format!("cannot enumerate candidate target verifier cleanup tree: {error}")
            })?;
            let mut children = Vec::new();
            for child in entries {
                require_time()?;
                discovered = discovered
                    .checked_add(1)
                    .filter(|entries| *entries <= policy.entry_limit)
                    .ok_or_else(|| {
                        "candidate target verifier cleanup exceeds its entry bound".to_owned()
                    })?;
                let child = child.map_err(|error| {
                    format!("cannot inspect candidate target verifier cleanup member: {error}")
                })?;
                children.push(child);
            }
            children.sort_by_key(fs::DirEntry::file_name);
            pending.push((path, true, depth));
            for child in children.into_iter().rev() {
                pending.push((child.path(), false, depth + 1));
            }
        } else {
            fs::remove_file(&path).map_err(|error| {
                format!("cannot unlink candidate target verifier cleanup member: {error}")
            })?;
        }
    }
    if posix_object_identity(&parent)? != parent_identity {
        return Err("candidate target verifier cleanup parent changed during deletion".to_owned());
    }
    match fs::symlink_metadata(&root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err("candidate target verifier removal root remains present".to_owned()),
        Err(error) => Err(format!(
            "cannot attest candidate target verifier removal root absence: {error}"
        )),
    }
}

#[cfg(unix)]
fn posix_verifier_removal_arguments(parent: &Path, root: &Path) -> Result<Vec<OsString>, String> {
    let parent_identity = posix_object_identity(parent)?;
    let root_identity = posix_object_identity(root)?;
    Ok(vec![
        root.as_os_str().to_owned(),
        parent_identity.device.to_string().into(),
        parent_identity.inode.to_string().into(),
        root_identity.device.to_string().into(),
        root_identity.inode.to_string().into(),
    ])
}

#[cfg(unix)]
fn open_posix_verifier_tree_for_cleanup(root: &Path) {
    use std::os::unix::fs::PermissionsExt as _;

    let Ok(metadata) = fs::symlink_metadata(root) else {
        return;
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return;
    }
    let _ = fs::set_permissions(root, fs::Permissions::from_mode(0o700));
    let Ok(children) = fs::read_dir(root) else {
        return;
    };
    for child in children.flatten() {
        open_posix_verifier_tree_for_cleanup(&child.path());
    }
}

#[cfg(unix)]
pub(crate) fn verify_posix_candidate_target_remover_for_integration() -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt as _, symlink};

    #[cfg(target_os = "linux")]
    let platform = ReleasePlatform::LinuxX86_64;
    #[cfg(target_os = "macos")]
    let platform = ReleasePlatform::MacosAarch64;

    fn allocate_root(platform: ReleasePlatform) -> Result<PathBuf, String> {
        let parent = posix_adapter_installation_root(platform)?;
        for _ in 0..16 {
            let sequence =
                POSIX_CANDIDATE_ENVIRONMENT_VERIFIER_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let root = parent.join(format!(
                "hell-candidate-target-verifier-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&root) {
                Ok(()) => return Ok(root),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(format!(
                        "cannot create bounded candidate remover fixture: {error}"
                    ));
                }
            }
        }
        Err("cannot allocate bounded candidate remover fixture".to_owned())
    }

    let parent = posix_adapter_installation_root(platform)?;
    let fixture = fs::canonicalize(env::temp_dir())
        .map_err(|error| format!("cannot canonicalize remover verifier temp root: {error}"))?
        .join(format!(
            "hell-candidate-remover-verifier-{}-{}",
            std::process::id(),
            POSIX_CANDIDATE_ENVIRONMENT_VERIFIER_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
    fs::create_dir(&fixture)
        .map_err(|error| format!("cannot create remover verifier fixture: {error}"))?;
    let mut roots = Vec::new();
    let result = (|| {
        let composite = combine_candidate_target_verifier_results(
            Err("primary".to_owned()),
            Err("cleanup".to_owned()),
            Err("absence".to_owned()),
            Err("fixture".to_owned()),
        )
        .expect_err("composite verifier failures must remain observable");
        if composite
            != "candidate target verifier: primary; candidate target verifier lifecycle cleanup: cleanup; candidate target verifier transient absence: absence; candidate target verifier fixture cleanup: fixture"
        {
            return Err("candidate remover composite error ordering changed".to_owned());
        }

        let external = fixture.join("external-sentinel");
        fs::write(&external, b"external-sentinel\n")
            .map_err(|error| format!("cannot create external remover sentinel: {error}"))?;
        let escape_root = allocate_root(platform)?;
        roots.push(escape_root.clone());
        fs::create_dir(escape_root.join("nested"))
            .map_err(|error| format!("cannot create remover escape fixture: {error}"))?;
        symlink(&external, escape_root.join("nested/redirect"))
            .map_err(|error| format!("cannot create remover symlink escape fixture: {error}"))?;
        fs::hard_link(&external, escape_root.join("nested/peer"))
            .map_err(|error| format!("cannot create remover hard-link fixture: {error}"))?;
        #[cfg(target_os = "macos")]
        {
            let acl = CommandSpec::new("/bin/chmod", Duration::from_secs(30))
                .arguments(["+a", "everyone allow write"])
                .argument(escape_root.join("nested"))
                .run()
                .map_err(|error| format!("cannot seed remover ACL fixture: {error}"))?;
            if !acl.status.success() || acl.timed_out {
                return Err("macOS remover ACL fixture was not established".to_owned());
            }
        }
        let escape_arguments = posix_verifier_removal_arguments(&parent, &escape_root)?;
        run_posix_candidate_target_verifier_remover(&escape_arguments)?;
        if escape_root.exists()
            || fs::read(&external)
                .map_err(|error| format!("cannot reread external remover sentinel: {error}"))?
                != b"external-sentinel\n"
            || fs::symlink_metadata(&external)
                .map_err(|error| format!("cannot inspect external remover sentinel: {error}"))?
                .nlink()
                != 1
        {
            return Err(
                "candidate remover escaped its root or removed a hard-link peer".to_owned(),
            );
        }

        let substitution_root = allocate_root(platform)?;
        roots.push(substitution_root.clone());
        let substitution_arguments = posix_verifier_removal_arguments(&parent, &substitution_root)?;
        let saved = fixture.join("saved-remover-root");
        fs::rename(&substitution_root, &saved)
            .map_err(|error| format!("cannot retain original remover root: {error}"))?;
        fs::create_dir(&substitution_root)
            .map_err(|error| format!("cannot substitute remover root: {error}"))?;
        let substitution_error =
            run_posix_candidate_target_verifier_remover(&substitution_arguments)
                .expect_err("a substituted remover root must be rejected");
        if substitution_error
            != "candidate target verifier removal authority differs from its receipt"
        {
            return Err(format!(
                "candidate remover root substitution reached the wrong phase: {substitution_error}"
            ));
        }
        fs::remove_dir(&substitution_root)
            .map_err(|error| format!("cannot remove substituted remover root: {error}"))?;
        fs::rename(&saved, &substitution_root)
            .map_err(|error| format!("cannot restore original remover root: {error}"))?;
        run_posix_candidate_target_verifier_remover(&substitution_arguments)?;

        let parent_receipt_root = allocate_root(platform)?;
        roots.push(parent_receipt_root.clone());
        let mut parent_receipt_arguments =
            posix_verifier_removal_arguments(&parent, &parent_receipt_root)?;
        let wrong_parent = posix_object_identity(&parent)?
            .device
            .checked_add(1)
            .unwrap_or(0)
            .to_string();
        *parent_receipt_arguments
            .get_mut(1)
            .ok_or_else(|| "candidate remover parent receipt is absent".to_owned())? =
            wrong_parent.into();
        let parent_error = run_posix_candidate_target_verifier_remover(&parent_receipt_arguments)
            .expect_err("a substituted remover parent receipt must be rejected");
        if parent_error != "candidate target verifier removal authority differs from its receipt" {
            return Err(format!(
                "candidate remover parent substitution reached the wrong phase: {parent_error}"
            ));
        }
        let parent_receipt_arguments =
            posix_verifier_removal_arguments(&parent, &parent_receipt_root)?;
        run_posix_candidate_target_verifier_remover(&parent_receipt_arguments)?;

        let entry_root = allocate_root(platform)?;
        roots.push(entry_root.clone());
        for name in ["one", "two", "three"] {
            fs::write(entry_root.join(name), b"bounded\n")
                .map_err(|error| format!("cannot create remover entry-bound fixture: {error}"))?;
        }
        let entry_arguments = posix_verifier_removal_arguments(&parent, &entry_root)?;
        let entry_error = run_posix_candidate_target_verifier_remover_with_policy(
            &entry_arguments,
            PosixVerifierRemovalPolicy {
                entry_limit: 2,
                depth_limit: 16,
                deadline: posix_identity_query_deadline("entry-bound remover verifier")?,
            },
        )
        .expect_err("an oversized remover fixture must be rejected before retention");
        if entry_error != "candidate target verifier cleanup exceeds its entry bound"
            || ["one", "two", "three"]
                .iter()
                .any(|name| !entry_root.join(name).exists())
        {
            return Err("candidate remover entry bound was not pre-allocation exact".to_owned());
        }
        run_posix_candidate_target_verifier_remover(&entry_arguments)?;

        let depth_root = allocate_root(platform)?;
        roots.push(depth_root.clone());
        fs::write(depth_root.join("a-shallow"), b"shallow\n")
            .map_err(|error| format!("cannot create remover shallow fixture: {error}"))?;
        fs::create_dir_all(depth_root.join("z-deep/one/two"))
            .map_err(|error| format!("cannot create remover depth fixture: {error}"))?;
        fs::write(depth_root.join("z-deep/one/two/sentinel"), b"deep\n")
            .map_err(|error| format!("cannot write remover depth fixture: {error}"))?;
        let depth_arguments = posix_verifier_removal_arguments(&parent, &depth_root)?;
        let depth_error = run_posix_candidate_target_verifier_remover_with_policy(
            &depth_arguments,
            PosixVerifierRemovalPolicy {
                entry_limit: 32,
                depth_limit: 2,
                deadline: posix_identity_query_deadline("depth-bound remover verifier")?,
            },
        )
        .expect_err("an over-deep remover fixture must be rejected");
        if depth_error != "candidate target verifier cleanup exceeds its depth bound"
            || depth_root.join("a-shallow").exists()
            || !depth_root.join("z-deep/one/two/sentinel").exists()
        {
            return Err("candidate remover partial deletion receipt was not exact".to_owned());
        }
        run_posix_candidate_target_verifier_remover(&depth_arguments)?;

        let deadline_root = allocate_root(platform)?;
        roots.push(deadline_root.clone());
        fs::write(deadline_root.join("sentinel"), b"deadline\n")
            .map_err(|error| format!("cannot create remover deadline fixture: {error}"))?;
        let deadline_arguments = posix_verifier_removal_arguments(&parent, &deadline_root)?;
        let expired = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .ok_or_else(|| "cannot construct expired remover deadline".to_owned())?;
        let deadline_error = run_posix_candidate_target_verifier_remover_with_policy(
            &deadline_arguments,
            PosixVerifierRemovalPolicy {
                entry_limit: 16,
                depth_limit: 16,
                deadline: expired,
            },
        )
        .expect_err("an expired remover deadline must reject before deletion");
        if deadline_error != "candidate target verifier cleanup deadline expired"
            || !deadline_root.join("sentinel").exists()
        {
            return Err("candidate remover deadline failure was not pre-deletion exact".to_owned());
        }
        run_posix_candidate_target_verifier_remover(&deadline_arguments)?;
        Ok(())
    })();

    for root in roots {
        open_posix_verifier_tree_for_cleanup(&root);
        let _ = fs::remove_dir_all(root);
    }
    open_posix_verifier_tree_for_cleanup(&fixture);
    let cleanup = fs::remove_dir_all(&fixture)
        .map_err(|error| format!("cannot remove candidate remover verifier fixture: {error}"));
    result.and(cleanup)
}

#[cfg(unix)]
pub(crate) fn run_posix_cargo_deny_home_normalizer(arguments: &[OsString]) -> Result<(), String> {
    let [home, candidate_owner, trusted_owner, trusted_group] = arguments else {
        return Err(
            "trusted cargo-deny home normalizer requires path, candidate owner, trusted owner, and trusted group"
                .to_owned(),
        );
    };
    let home = PathBuf::from(home);
    validate_posix_cargo_deny_home_root(&home)?;
    let candidate_owner = candidate_owner
        .to_str()
        .ok_or_else(|| "cargo-deny lock owner is not UTF-8".to_owned())?
        .parse::<u32>()
        .map_err(|_| "cargo-deny lock owner is invalid".to_owned())?;
    let trusted_owner = trusted_owner
        .to_str()
        .ok_or_else(|| "trusted cargo-deny cache owner is not UTF-8".to_owned())?
        .parse::<u32>()
        .map_err(|_| "trusted cargo-deny cache owner is invalid".to_owned())?;
    let trusted_group = trusted_group
        .to_str()
        .ok_or_else(|| "trusted cargo-deny cache group is not UTF-8".to_owned())?
        .parse::<u32>()
        .map_err(|_| "trusted cargo-deny cache group is invalid".to_owned())?;
    normalize_cargo_deny_cache_tree(&home, candidate_owner, trusted_owner, trusted_group)
}

#[cfg(unix)]
pub(crate) fn run_posix_stack_root_normalizer(arguments: &[OsString]) -> Result<(), String> {
    let [root, owner, group] = arguments else {
        return Err("trusted Stack-root normalizer requires path, owner, and group".to_owned());
    };
    let root = PathBuf::from(root);
    validate_posix_stack_root(&root)?;
    let owner = owner
        .to_str()
        .ok_or_else(|| "trusted Stack-root owner is not UTF-8".to_owned())?
        .parse::<u32>()
        .map_err(|_| "trusted Stack-root owner is invalid".to_owned())?;
    let group = group
        .to_str()
        .ok_or_else(|| "trusted Stack-root group is not UTF-8".to_owned())?
        .parse::<u32>()
        .map_err(|_| "trusted Stack-root group is invalid".to_owned())?;
    remove_candidate_owned_stack_symlinks(&root)?;
    normalize_candidate_owned_cache_tree(&root, owner, group)
}

#[cfg(unix)]
pub(crate) fn run_posix_stack_work_normalizer(arguments: &[OsString]) -> Result<(), String> {
    let [
        authority,
        authority_device,
        authority_inode,
        source,
        source_device,
        source_inode,
        work,
        work_device,
        work_inode,
        owner,
        group,
    ] = arguments
    else {
        return Err(
            "trusted Stack-work normalizer requires three bound paths, their identities, owner, and group"
                .to_owned(),
        );
    };
    let authority = PathBuf::from(authority);
    let source = PathBuf::from(source);
    let work = PathBuf::from(work);
    let parse_u64 = |value: &OsString, label: &str| {
        value
            .to_str()
            .ok_or_else(|| format!("trusted Stack-work {label} is not UTF-8"))?
            .parse::<u64>()
            .map_err(|_| format!("trusted Stack-work {label} is invalid"))
    };
    let authority_identity = (
        parse_u64(authority_device, "parent device")?,
        parse_u64(authority_inode, "parent inode")?,
    );
    let source_identity = (
        parse_u64(source_device, "source device")?,
        parse_u64(source_inode, "source inode")?,
    );
    let work_identity = (
        parse_u64(work_device, "work device")?,
        parse_u64(work_inode, "work inode")?,
    );
    let owner = owner
        .to_str()
        .ok_or_else(|| "trusted Stack-work owner is not UTF-8".to_owned())?
        .parse::<u32>()
        .map_err(|_| "trusted Stack-work owner is invalid".to_owned())?;
    let group = group
        .to_str()
        .ok_or_else(|| "trusted Stack-work group is not UTF-8".to_owned())?
        .parse::<u32>()
        .map_err(|_| "trusted Stack-work group is invalid".to_owned())?;
    validate_posix_stack_work(&PosixStackWorkValidation {
        authority: &authority,
        authority_identity,
        source: &source,
        source_identity,
        work: &work,
        work_identity,
        owner,
        group,
    })?;
    remove_candidate_owned_stack_symlinks(&work)?;
    normalize_candidate_owned_cache_tree(&work, owner, group)
}

#[cfg(unix)]
fn remove_candidate_owned_stack_symlinks(root: &Path) -> Result<(), String> {
    let mut pending = vec![root.to_path_buf()];
    let mut entries = 0_usize;
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot inspect candidate Stack tree: {error}"))?;
        entries = entries
            .checked_add(1)
            .ok_or_else(|| "candidate Stack tree entry count overflowed".to_owned())?;
        if entries > POSIX_RUSTUP_STAGE_ENTRY_LIMIT {
            return Err("candidate Stack tree exceeds its resource bound".to_owned());
        }
        if metadata.file_type().is_symlink() {
            fs::remove_file(&path)
                .map_err(|error| format!("cannot unlink candidate Stack symlink: {error}"))?;
            continue;
        }
        if metadata.is_dir() {
            for entry in fs::read_dir(&path)
                .map_err(|error| format!("cannot enumerate candidate Stack tree: {error}"))?
            {
                pending.push(
                    entry
                        .map_err(|error| format!("cannot read candidate Stack entry: {error}"))?
                        .path(),
                );
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn validate_posix_cargo_deny_home_root(home: &Path) -> Result<(), String> {
    let release_environment = home
        .parent()
        .ok_or_else(|| "candidate cargo-deny home has no parent".to_owned())?;
    let target = release_environment
        .parent()
        .ok_or_else(|| "candidate cargo-deny home has no target parent".to_owned())?;
    let metadata = fs::symlink_metadata(home)
        .map_err(|error| format!("cannot inspect candidate cargo-deny home: {error}"))?;
    if !home.is_absolute()
        || home.file_name() != Some(std::ffi::OsStr::new("cargo-deny-cargo-home"))
        || release_environment.file_name()
            != Some(std::ffi::OsStr::new("release-child-environment"))
        || target.file_name() != Some(std::ffi::OsStr::new("candidate-target"))
        || metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || fs::canonicalize(home)
            .map_err(|error| format!("cannot canonicalize candidate cargo-deny home: {error}"))?
            != home
    {
        return Err("trusted cargo-deny home root differs from policy".to_owned());
    }
    Ok(())
}

#[cfg(unix)]
fn validate_posix_stack_root(root: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(root)
        .map_err(|error| format!("cannot inspect candidate Stack root: {error}"))?;
    if !root.is_absolute()
        || !posix_stack_root_is_exact(root)
        || metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || fs::canonicalize(root)
            .map_err(|error| format!("cannot canonicalize candidate Stack root: {error}"))?
            != root
    {
        return Err("trusted Stack root differs from policy".to_owned());
    }
    Ok(())
}

#[cfg(unix)]
fn posix_stack_work_is_exact(authority: &Path, source: &Path, work: &Path) -> bool {
    let Some(name) = authority.file_name().and_then(std::ffi::OsStr::to_str) else {
        return false;
    };
    let Some(suffix) = name.strip_prefix("hell-rs-posix-sources-") else {
        return false;
    };
    let mut components = suffix.split('-');
    let (Some(process), Some(sequence), Some(commit), None) = (
        components.next(),
        components.next(),
        components.next(),
        components.next(),
    ) else {
        return false;
    };
    let canonical_number = |value: &str| {
        value
            .parse::<u64>()
            .is_ok_and(|number| value == number.to_string())
    };
    authority.parent() == Some(Path::new("/private/var/tmp"))
        && canonical_number(process)
        && canonical_number(sequence)
        && commit.len() == 12
        && commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && source == authority.join("oracle")
        && work == source.join(".stack-work")
}

#[cfg(unix)]
struct PosixStackWorkValidation<'a> {
    authority: &'a Path,
    authority_identity: (u64, u64),
    source: &'a Path,
    source_identity: (u64, u64),
    work: &'a Path,
    work_identity: (u64, u64),
    owner: u32,
    group: u32,
}

#[cfg(unix)]
fn validate_posix_stack_work(binding: &PosixStackWorkValidation<'_>) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    if !posix_stack_work_is_exact(binding.authority, binding.source, binding.work) {
        return Err("trusted Stack-work path differs from policy".to_owned());
    }
    let inspect = |path: &Path, expected: (u64, u64), label: &str| {
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| format!("cannot inspect {label}: {error}"))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || fs::canonicalize(path)
                .map_err(|error| format!("cannot canonicalize {label}: {error}"))?
                != path
            || (metadata.dev(), metadata.ino()) != expected
        {
            return Err(format!("{label} identity differs from policy"));
        }
        Ok(metadata)
    };
    let authority_metadata = inspect(
        binding.authority,
        binding.authority_identity,
        "Stack-work parent authority",
    )?;
    let source_metadata = inspect(
        binding.source,
        binding.source_identity,
        "Stack-work source authority",
    )?;
    let work_metadata = inspect(binding.work, binding.work_identity, "Stack-work authority")?;
    if authority_metadata.uid() != 0
        || authority_metadata.gid() != 0
        || authority_metadata.permissions().mode() & 0o7777 != 0o555
        || source_metadata.uid() != 0
        || source_metadata.gid() != 0
        || source_metadata.permissions().mode() & 0o7777 != 0o555
        || work_metadata.uid() != binding.owner
        || work_metadata.gid() != binding.group
        || work_metadata.permissions().mode() & 0o7777 != 0o750
    {
        return Err("trusted Stack-work ownership or mode differs from policy".to_owned());
    }
    Ok(())
}

#[cfg(unix)]
fn normalize_candidate_owned_cache_tree(root: &Path, owner: u32, group: u32) -> Result<(), String> {
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};

    let mut pending = vec![root.to_path_buf()];
    let mut entries = 0_usize;
    let mut bytes = 0_u64;
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot inspect candidate cargo-deny cache: {error}"))?;
        let file_type = metadata.file_type();
        if file_type.is_symlink()
            || file_type.is_block_device()
            || file_type.is_char_device()
            || file_type.is_fifo()
            || file_type.is_socket()
            || (!file_type.is_dir() && !file_type.is_file())
            || (file_type.is_file() && metadata.nlink() != 1)
        {
            return Err("candidate cargo-deny cache contains a link or special file".to_owned());
        }
        entries = entries
            .checked_add(1)
            .ok_or_else(|| "candidate cargo-deny cache entry count overflowed".to_owned())?;
        bytes = bytes
            .checked_add(if file_type.is_file() {
                metadata.len()
            } else {
                0
            })
            .ok_or_else(|| "candidate cargo-deny cache byte count overflowed".to_owned())?;
        if entries > POSIX_RUSTUP_STAGE_ENTRY_LIMIT || bytes > POSIX_RUSTUP_STAGE_BYTE_LIMIT {
            return Err("candidate cargo-deny cache exceeds its resource bound".to_owned());
        }
        std::os::unix::fs::chown(&path, Some(owner), Some(group)).map_err(|error| {
            format!("cannot bind candidate cargo-deny cache ownership: {error}")
        })?;
        fs::set_permissions(
            &path,
            fs::Permissions::from_mode(if file_type.is_dir() { 0o750 } else { 0o640 }),
        )
        .map_err(|error| format!("cannot bind candidate cargo-deny cache permissions: {error}"))?;
        if file_type.is_dir() {
            for entry in fs::read_dir(&path)
                .map_err(|error| format!("cannot enumerate candidate cargo-deny cache: {error}"))?
            {
                pending.push(
                    entry
                        .map_err(|error| format!("cannot read cargo-deny cache entry: {error}"))?
                        .path(),
                );
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn normalize_cargo_deny_cache_tree(
    root: &Path,
    candidate_owner: u32,
    trusted_owner: u32,
    trusted_group: u32,
) -> Result<(), String> {
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};

    let lock = Path::new("advisory-dbs").join("db.lock");
    let advisory_root = Path::new("advisory-dbs");
    let mut pending = vec![root.to_path_buf()];
    let mut entries = 0_usize;
    let mut bytes = 0_u64;
    let mut found_lock = false;
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot inspect cargo-deny cache authority: {error}"))?;
        let file_type = metadata.file_type();
        if file_type.is_symlink()
            || file_type.is_block_device()
            || file_type.is_char_device()
            || file_type.is_fifo()
            || file_type.is_socket()
            || (!file_type.is_dir() && !file_type.is_file())
            || (file_type.is_file() && metadata.nlink() != 1)
        {
            return Err("cargo-deny cache authority contains a link or special file".to_owned());
        }
        entries = entries
            .checked_add(1)
            .ok_or_else(|| "cargo-deny cache authority entry count overflowed".to_owned())?;
        bytes = bytes
            .checked_add(if file_type.is_file() {
                metadata.len()
            } else {
                0
            })
            .ok_or_else(|| "cargo-deny cache authority byte count overflowed".to_owned())?;
        if entries > POSIX_RUSTUP_STAGE_ENTRY_LIMIT || bytes > POSIX_RUSTUP_STAGE_BYTE_LIMIT {
            return Err("cargo-deny cache authority exceeds its resource bound".to_owned());
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|_| "cargo-deny cache authority escaped its root".to_owned())?;
        let is_lock = relative == lock;
        let is_advisory_root = relative == advisory_root;
        if is_lock && (!file_type.is_file() || metadata.len() != 0) {
            return Err(
                "cargo-deny advisory lock authority is not an empty regular file".to_owned(),
            );
        }
        let owner = if is_lock || is_advisory_root {
            candidate_owner
        } else {
            trusted_owner
        };
        std::os::unix::fs::chown(&path, Some(owner), Some(trusted_group))
            .map_err(|error| format!("cannot bind cargo-deny cache ownership: {error}"))?;
        fs::set_permissions(
            &path,
            fs::Permissions::from_mode(match (is_lock, is_advisory_root) {
                // The lock is intentionally empty synchronization state. It is
                // candidate-owned and trusted-group-writable so either side of
                // the confinement boundary can acquire it, while immutable
                // advisory payloads remain inaccessible for writes.
                (true, _) => 0o660,
                (_, true) => 0o750,
                (_, _) if file_type.is_dir() => 0o555,
                (_, _) => 0o444,
            }),
        )
        .map_err(|error| format!("cannot bind cargo-deny cache permissions: {error}"))?;
        found_lock |= is_lock;
        if file_type.is_dir() {
            for entry in fs::read_dir(&path)
                .map_err(|error| format!("cannot enumerate cargo-deny cache authority: {error}"))?
            {
                pending.push(
                    entry
                        .map_err(|error| format!("cannot read cargo-deny cache entry: {error}"))?
                        .path(),
                );
            }
        }
    }
    if !found_lock {
        return Err("cargo-deny advisory lock authority is absent".to_owned());
    }
    Ok(())
}

#[cfg(unix)]
fn validate_candidate_cache_normalizer_root(root: &Path) -> Result<(), String> {
    if !root.is_absolute() || root.file_name() != Some(std::ffi::OsStr::new("candidate-target")) {
        return Err("trusted candidate cache normalizer root differs from policy".to_owned());
    }
    let metadata = fs::symlink_metadata(root)
        .map_err(|error| format!("cannot inspect candidate cache authority: {error}"))?;
    let canonical = fs::canonicalize(root)
        .map_err(|error| format!("cannot canonicalize candidate cache authority: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() || canonical != root {
        return Err("trusted candidate cache normalizer root is redirected".to_owned());
    }
    Ok(())
}

#[cfg(unix)]
fn validate_candidate_cache_export_replacement_root(
    root: &Path,
    workspace_target: &Path,
    expected_token: u32,
) -> Result<(), String> {
    validate_candidate_cache_normalizer_root(workspace_target)?;
    let prefix = "candidate-target-export-replacement-";
    let Some(name) = root.file_name().and_then(std::ffi::OsStr::to_str) else {
        return Err("candidate target export replacement name is not UTF-8".to_owned());
    };
    let token = name
        .strip_prefix(prefix)
        .ok_or_else(|| "candidate target export replacement name differs from policy".to_owned())?;
    let token_value = token
        .parse::<u32>()
        .map_err(|_| "candidate target export replacement token is malformed".to_owned())?;
    if token != token_value.to_string()
        || token_value != expected_token
        || root.parent() != workspace_target.parent()
        || !root.is_absolute()
    {
        return Err("candidate target export replacement authority differs from policy".to_owned());
    }
    let metadata = fs::symlink_metadata(root)
        .map_err(|error| format!("cannot inspect candidate target export replacement: {error}"))?;
    let canonical = fs::canonicalize(root).map_err(|error| {
        format!("cannot canonicalize candidate target export replacement: {error}")
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() || canonical != root {
        return Err("candidate target export replacement is redirected".to_owned());
    }
    Ok(())
}

fn validate_conformance_plan(
    plan: &ReleasePlan,
    path: &Path,
) -> Result<crate::conformance::ConformancePlan, String> {
    let conformance = crate::conformance::ConformancePlan::parse(&read_json(path)?)?;
    if !accept_conformance_plan_binding(
        conformance.plan_sha256 == plan.conformance_plan_sha256
            && conformance.candidate_sha == plan.resolution.candidate_sha
            && conformance.workflow_sha == plan.resolution.workflow_sha
            && conformance.release_evaluation_instant == plan.release_evaluation_instant
            && conformance.trusted_inputs_sha256 == plan.trusted_conformance_inputs_sha256
            && conformance.source_inventory_sha256 == plan.source_inventory_sha256
            && conformance.standard == plan.conformance_standard,
    ) {
        return Err("conformance plan binding differs from release plan".to_owned());
    }
    Ok(conformance)
}

fn accept_conformance_plan_binding(matches: bool) -> bool {
    let substitution = crate::mutation::active("candidate-conformance-plan-substitution");
    substitution || matches
}

#[cfg(windows)]
type WindowsReleaseBinaryAuthority = hell_testkit::WindowsReleaseBinaryCheckpoint;

#[cfg(windows)]
fn capture_windows_release_binary_authority(
    root: &Path,
    platform: ReleasePlatform,
    checkpoint: &str,
    release_build_passed: bool,
) -> Result<WindowsReleaseBinaryAuthority, String> {
    let target = root
        .parent()
        .ok_or_else(|| "candidate root has no parent".to_owned())?
        .join("candidate-target");
    let binary = target.join("release").join(platform.executable());
    let release_receipt =
        hell_testkit::WindowsCargoReleaseReceipt::load(&target).map_err(|error| {
            format!("cannot load successful restricted Cargo release receipt: {error}")
        })?;
    WindowsReleaseBinaryAuthority::capture(
        target,
        binary,
        crate::command::release_candidate_target(),
        Some(release_receipt),
        checkpoint,
        release_build_passed,
    )
}

fn require_real_binary_path(target: &Path, binary: &Path) -> Result<(), String> {
    let release = target.join("release");
    let release_metadata = fs::symlink_metadata(&release)
        .map_err(|error| format!("cannot inspect release target directory: {error}"))?;
    if release_metadata.file_type().is_symlink() || !release_metadata.is_dir() {
        return Err("candidate release target is not a real directory".to_owned());
    }
    if fs::canonicalize(&release)
        .map_err(|error| format!("cannot canonicalize release target: {error}"))?
        != release
    {
        return Err("candidate release target is redirected".to_owned());
    }
    let binary_metadata = fs::symlink_metadata(binary)
        .map_err(|error| format!("cannot inspect release binary: {error}"))?;
    if binary_metadata.file_type().is_symlink() || !binary_metadata.is_file() {
        return Err("candidate release binary is not a real file".to_owned());
    }
    Ok(())
}

fn base_final_platform_inventory() -> BTreeSet<&'static str> {
    BTreeSet::from([
        "archive",
        "archive-manifest.json",
        "conformance-evidence",
        "conformance-evidence-manifest.json",
        "conformance-observations",
        "oracle-report.json",
        "package-report.json",
        "platform-report.json",
        "source-inventory.json",
    ])
}

fn expected_final_platform_inventory(_platform: ReleasePlatform) -> BTreeSet<&'static str> {
    let expected = base_final_platform_inventory();
    #[cfg(target_os = "linux")]
    let expected = {
        let mut expected = expected;
        if _platform == ReleasePlatform::LinuxX86_64 {
            expected.insert("dependency-policy.json");
            expected.insert("mutation-report.json");
        }
        expected
    };
    expected
}

#[cfg(windows)]
pub(crate) fn verify_windows_final_platform_inventory_for_integration() -> Result<(), String> {
    let observed = expected_final_platform_inventory(ReleasePlatform::WindowsX86_64);
    let expected = BTreeSet::from([
        "archive",
        "archive-manifest.json",
        "conformance-evidence",
        "conformance-evidence-manifest.json",
        "conformance-observations",
        "oracle-report.json",
        "package-report.json",
        "platform-report.json",
        "source-inventory.json",
    ]);
    if observed != expected {
        return Err(format!(
            "Windows final platform inventory differs: {observed:?}"
        ));
    }
    Ok(())
}

fn verify_final_platform_inventory(
    output: &Path,
    platform: ReleasePlatform,
    archive_name: &str,
) -> Result<(), String> {
    let expected = expected_final_platform_inventory(platform);
    let observed = fs::read_dir(output)
        .map_err(|error| format!("cannot enumerate final platform output: {error}"))?
        .map(|entry| {
            entry
                .map_err(|error| format!("cannot inspect final platform output: {error}"))?
                .file_name()
                .into_string()
                .map_err(|_| "final platform output name is not UTF-8".to_owned())
        })
        .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
    if observed != expected.into_iter().map(str::to_owned).collect() {
        return Err(format!(
            "final platform output exact set differs: {observed:?}"
        ));
    }
    let archives = fs::read_dir(output.join("archive"))
        .map_err(|error| format!("cannot enumerate final archive output: {error}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("cannot inspect final archive output: {error}"))?;
    if archives.len() != 1
        || archives[0].file_name().to_str() != Some(archive_name)
        || !archives[0]
            .file_type()
            .map_err(|error| format!("cannot inspect final archive type: {error}"))?
            .is_file()
    {
        return Err("final platform archive exact set differs".to_owned());
    }
    let manifest = crate::conformance::EvidenceManifest::parse(&read_json(
        &output.join("conformance-evidence-manifest.json"),
    )?)?;
    let expected_members = manifest
        .records
        .iter()
        .chain(&manifest.exploratory_records)
        .chain(&manifest.observations)
        .map(|member| (member.path.as_str(), member.sha256.as_str()))
        .collect::<BTreeMap<_, _>>();
    for directory in ["conformance-evidence", "conformance-observations"] {
        let path = output.join(directory);
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot inspect {directory}: {error}"))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(format!("{directory} is not a real directory"));
        }
        let observed = fs::read_dir(&path)
            .map_err(|error| format!("cannot enumerate {directory}: {error}"))?
            .map(|entry| {
                let entry =
                    entry.map_err(|error| format!("cannot inspect {directory}: {error}"))?;
                let name = entry
                    .file_name()
                    .into_string()
                    .map_err(|_| format!("{directory} member is not UTF-8"))?;
                let relative = format!("{directory}/{name}");
                let expected = expected_members
                    .get(relative.as_str())
                    .ok_or_else(|| format!("unlisted {directory} member {name:?}"))?;
                let metadata = entry
                    .metadata()
                    .map_err(|error| format!("cannot inspect {directory} member: {error}"))?;
                if entry
                    .file_type()
                    .map_err(|error| format!("cannot inspect {directory} member type: {error}"))?
                    .is_symlink()
                    || !metadata.is_file()
                    || hell_testkit::sha256_file(&entry.path())
                        .map_err(|error| format!("cannot hash {directory} member: {error}"))?
                        .hex()
                        != *expected
                {
                    return Err(format!("{directory} member identity differs"));
                }
                Ok(relative)
            })
            .collect::<Result<BTreeSet<_>, String>>()?;
        let expected = expected_members
            .keys()
            .filter(|name| name.starts_with(directory))
            .map(|name| (*name).to_owned())
            .collect::<BTreeSet<_>>();
        if observed != expected {
            return Err(format!("{directory} exact set differs"));
        }
    }
    Ok(())
}

fn require_candidate_target(root: &Path, target: &Path) -> Result<(), String> {
    let expected_parent = root
        .parent()
        .ok_or_else(|| "candidate root has no parent".to_owned())?;
    if target.parent() != Some(expected_parent) {
        return Err("candidate target is outside the isolated runner workspace".to_owned());
    }
    if target.exists() {
        let metadata = fs::symlink_metadata(target)
            .map_err(|error| format!("cannot inspect candidate target: {error}"))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("candidate target is not a real directory".to_owned());
        }
        let canonical = fs::canonicalize(target)
            .map_err(|error| format!("cannot canonicalize candidate target: {error}"))?;
        if canonical != target {
            return Err("candidate target changed identity".to_owned());
        }
        reject_link_descendants(target)?;
    } else {
        fs::create_dir(target)
            .map_err(|error| format!("cannot create candidate target: {error}"))?;
    }
    Ok(())
}

fn reject_link_descendants(root: &Path) -> Result<(), String> {
    for entry in
        fs::read_dir(root).map_err(|error| format!("cannot enumerate candidate target: {error}"))?
    {
        let entry = entry.map_err(|error| format!("cannot inspect candidate target: {error}"))?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| format!("cannot inspect candidate target entry: {error}"))?;
        if metadata.file_type().is_symlink() {
            return Err("candidate target contains a symbolic link".to_owned());
        }
        if metadata.is_dir() {
            let canonical = fs::canonicalize(entry.path())
                .map_err(|error| format!("cannot canonicalize candidate target entry: {error}"))?;
            if canonical != entry.path() {
                return Err("candidate target contains a redirected directory".to_owned());
            }
            reject_link_descendants(&entry.path())?;
        } else if !metadata.is_file() {
            return Err("candidate target contains a special entry".to_owned());
        }
    }
    Ok(())
}

fn require_real_output_directories(output: &Path) -> Result<(), String> {
    for path in [
        output.to_path_buf(),
        output.join("archive"),
        output.join("conformance-evidence"),
        output.join("conformance-observations"),
    ] {
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            format!("cannot inspect trusted output {}: {error}", path.display())
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(format!(
                "trusted output is not a real directory: {}",
                path.display()
            ));
        }
        let canonical = fs::canonicalize(&path)
            .map_err(|error| format!("cannot canonicalize trusted output: {error}"))?;
        if canonical != path {
            return Err(format!(
                "trusted output path changed identity: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum WindowsPlatformGateStage {
    #[default]
    Initial,
    WorkspaceTests,
    ReleaseBuild,
    ReleaseBinaryReceipt,
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Default)]
struct WindowsPlatformGateTopology {
    stage: WindowsPlatformGateStage,
}

#[cfg(windows)]
impl WindowsPlatformGateTopology {
    fn workspace_tests_completed(&mut self) -> Result<(), String> {
        self.advance(
            WindowsPlatformGateStage::Initial,
            WindowsPlatformGateStage::WorkspaceTests,
            "workspace-tests",
        )
    }

    fn release_build_completed(&mut self) -> Result<(), String> {
        self.advance(
            WindowsPlatformGateStage::WorkspaceTests,
            WindowsPlatformGateStage::ReleaseBuild,
            "release-build",
        )
    }

    fn release_binary_receipt_captured(&mut self) -> Result<(), String> {
        self.advance(
            WindowsPlatformGateStage::ReleaseBuild,
            WindowsPlatformGateStage::ReleaseBinaryReceipt,
            "release-binary-receipt",
        )
    }

    fn require_conformance_ready(self) -> Result<(), String> {
        if self.stage != WindowsPlatformGateStage::ReleaseBinaryReceipt {
            return Err(
                "Windows platform gate topology is incomplete before conformance".to_owned(),
            );
        }
        Ok(())
    }

    fn advance(
        &mut self,
        expected: WindowsPlatformGateStage,
        next: WindowsPlatformGateStage,
        gate: &str,
    ) -> Result<(), String> {
        if self.stage != expected {
            return Err(format!(
                "Windows platform gate {gate} is out of order: currentStage={:?}",
                self.stage
            ));
        }
        self.stage = next;
        Ok(())
    }
}

#[cfg(windows)]
pub(crate) fn verify_windows_platform_gate_topology_for_integration() -> Result<(), String> {
    let initial = WindowsPlatformGateTopology::default();
    if initial.require_conformance_ready().is_ok() {
        return Err("Windows conformance accepted an empty gate topology".to_owned());
    }

    let mut missing_workspace = WindowsPlatformGateTopology::default();
    if missing_workspace.release_build_completed().is_ok() {
        return Err("Windows release build accepted a missing workspace-test gate".to_owned());
    }

    let mut missing_release_build = WindowsPlatformGateTopology::default();
    missing_release_build.workspace_tests_completed()?;
    if missing_release_build
        .release_binary_receipt_captured()
        .is_ok()
    {
        return Err("Windows binary receipt accepted a missing release-build gate".to_owned());
    }

    let mut complete = WindowsPlatformGateTopology::default();
    complete.workspace_tests_completed()?;
    complete.release_build_completed()?;
    complete.release_binary_receipt_captured()?;
    complete.require_conformance_ready()
}

struct PortablePlatformGateContext<'a> {
    plan: &'a ReleasePlan,
    root: &'a Path,
    output: &'a Path,
    gates: &'a mut BTreeMap<&'static str, bool>,
    evidence: &'a mut BTreeMap<String, JsonValue>,
    retained: &'a mut BTreeMap<String, Vec<u8>>,
    oracle_identity: &'a hell_testkit::ExecutableIdentity,
    oracle_source_sha256: &'a str,
    #[cfg(windows)]
    platform: ReleasePlatform,
    #[cfg(windows)]
    windows_release_binary: &'a mut Option<WindowsReleaseBinaryAuthority>,
    #[cfg(windows)]
    windows_gate_topology: &'a mut WindowsPlatformGateTopology,
}

fn run_portable_platform_gates(context: PortablePlatformGateContext<'_>) -> Result<(), String> {
    let PortablePlatformGateContext {
        plan,
        root,
        output,
        gates,
        evidence,
        retained,
        oracle_identity,
        oracle_source_sha256,
        #[cfg(windows)]
        platform,
        #[cfg(windows)]
        windows_release_binary,
        #[cfg(windows)]
        windows_gate_topology,
    } = context;
    crate::release_suite::release_dependency_attestation(
        root,
        &output.join("dependency-policy.json"),
        &plan.resolution.candidate_sha,
    )?;
    suite_gate(
        "portability",
        root,
        output,
        crate::release_suite::release_portability,
        gates,
        evidence,
    )?;
    require_source_inventory(root, &plan.source_inventory_sha256)?;
    command_gate(
        "workspace-tests",
        cargo(
            root,
            Duration::from_hours(1),
            [
                "test",
                "--workspace",
                "--all-targets",
                "--all-features",
                "--locked",
            ],
        ),
        output,
        gates,
        evidence,
    )?;
    #[cfg(windows)]
    windows_gate_topology.workspace_tests_completed()?;
    command_gate(
        "release-build",
        release_candidate_build(root),
        output,
        gates,
        evidence,
    )?;
    #[cfg(windows)]
    {
        windows_gate_topology.release_build_completed()?;
        *windows_release_binary = Some(capture_windows_release_binary_authority(
            root,
            platform,
            "after release-build",
            gates.get("release-build") == Some(&true),
        )?);
        windows_gate_topology.release_binary_receipt_captured()?;
    }
    write_json(
        &output.join("oracle-report.json"),
        &object([
            ("commit", string("8e952cf9de4ab25d7716982a9ca234f9bdcf1bff")),
            ("executableSha256", string(&oracle_identity.sha256.hex())),
            ("repository", string("chrisdone/hell")),
            ("schemaVersion", number(2)),
            ("sourceSha256", string(oracle_source_sha256)),
            ("state", string("verified")),
        ]),
    )?;
    #[cfg(windows)]
    if let Some(authority) = windows_release_binary.as_ref() {
        authority.validate(
            "after oracle report write",
            gates.get("release-build") == Some(&true),
        )?;
    }
    retained.insert(
        "oracle-report.json".to_owned(),
        read_regular(&output.join("oracle-report.json"))?,
    );
    in_process_gate(
        "native-oracle-build",
        Ok("built and retained a pinned-source native oracle identity".to_owned()),
        gates,
        evidence,
    )?;
    #[cfg(windows)]
    if let Some(authority) = windows_release_binary.as_ref() {
        authority.validate(
            "after native-oracle-build gate",
            gates.get("release-build") == Some(&true),
        )?;
    }
    fs::remove_file(output.join("dependency-policy.json"))
        .map_err(|error| format!("cannot remove transient native dependency evidence: {error}"))?;
    #[cfg(windows)]
    if let Some(authority) = windows_release_binary.as_ref() {
        authority.validate(
            "after transient dependency evidence removal",
            gates.get("release-build") == Some(&true),
        )?;
    }
    in_process_gate(
        "divergence-prototypes",
        crate::compatibility::release_divergence_prototype_catalog(root),
        gates,
        evidence,
    )?;
    #[cfg(windows)]
    if let Some(authority) = windows_release_binary.as_ref() {
        authority.validate(
            "after divergence-prototypes gate",
            gates.get("release-build") == Some(&true),
        )?;
    }
    Ok(())
}

fn run_platform_gates(
    platform: ReleasePlatform,
    plan: &ReleasePlan,
    conformance_plan: &crate::conformance::ConformancePlan,
    root: &Path,
    _oracle_source: &Path,
    output: &Path,
    gates: &mut BTreeMap<&'static str, bool>,
    evidence: &mut BTreeMap<String, JsonValue>,
    retained: &mut BTreeMap<String, Vec<u8>>,
    prepared_oracle: hell_testkit::ExecutableIdentity,
    oracle_source_sha256: &str,
    #[cfg(unix)] dependency_policy: Option<(
        &PosixDependencyPolicyProtection,
        &PosixCargoDenyHomeProtection,
    )>,
    #[cfg(windows)] windows_release_binary: &mut Option<WindowsReleaseBinaryAuthority>,
) -> Result<(), String> {
    let oracle_identity = prepared_oracle.clone();
    require_executable_digest(
        &oracle_identity.path,
        oracle_identity.sha256,
        "retained oracle",
    )?;
    #[cfg(windows)]
    let mut windows_gate_topology = WindowsPlatformGateTopology::default();
    #[cfg(unix)]
    if platform == ReleasePlatform::LinuxX86_64 {
        let (policy, cargo_deny_home) = dependency_policy
            .ok_or_else(|| "Linux dependency-policy authority is absent".to_owned())?;
        policy.validate()?;
        cargo_deny_home.metadata.validate()?;
        let policy_document = read_regular(&policy.path)?;
        verify_dependency_policy_result(
            &policy_document,
            root,
            &plan.resolution.candidate_sha,
            &cargo_deny_home.metadata.sha256,
            &policy.cargo_deny_sha256,
        )?;
        if policy.cargo_deny_version != TRUSTED_CARGO_DENY_VERSION {
            return Err("dependency-policy cargo-deny version drifted".to_owned());
        }
        retained.insert("dependency-policy.json".to_owned(), policy_document);
        in_process_gate(
            "dependency-policy",
            Ok("verified the trusted immutable all-category dependency-policy result".to_owned()),
            gates,
            evidence,
        )?;
        in_process_gate(
            "conformance-policy",
            crate::compatibility::release_conformance_policy(root),
            gates,
            evidence,
        )?;
        for (name, arguments) in [
            ("case-catalog", &["case-catalog", "verify"][..]),
            ("normalizer-catalog", &["normalizer-audit", "verify"][..]),
            ("divergence-catalog", &["divergence-verify", "verify"][..]),
        ] {
            in_process_gate(
                name,
                crate::compatibility::release_gate(root, arguments),
                gates,
                evidence,
            )?;
        }
        suite_gate(
            "verify",
            root,
            output,
            crate::release_suite::release_verify,
            gates,
            evidence,
        )?;
        for (name, command) in linux_rust_commands(root) {
            if name == "release-build" {
                require_source_inventory(root, &plan.source_inventory_sha256)?;
            }
            command_gate(name, command, output, gates, evidence)?;
        }
        suite_examples(root, output, gates, evidence)?;
        in_process_gate(
            "release-mutation-catalog",
            crate::mutation::release_mutation_catalog(
                root,
                &output.join("mutation-report.json"),
                &plan.resolution.candidate_sha,
            ),
            gates,
            evidence,
        )?;
        retained.insert(
            "mutation-report.json".to_owned(),
            read_regular(&output.join("mutation-report.json"))?,
        );
        fs::remove_dir_all(output.join("mutation-results"))
            .map_err(|error| format!("cannot remove transient mutation details: {error}"))?;
        gates.insert("linux-release-oracle-digest", true);
        evidence.insert(
            "linux-release-oracle-digest".to_owned(),
            object([
                ("sha256", string(&prepared_oracle.sha256.hex())),
                ("schemaVersion", number(1)),
                ("state", string("passed")),
            ]),
        );
        write_json(
            &output.join("oracle-report.json"),
            &object([
                ("commit", string("8e952cf9de4ab25d7716982a9ca234f9bdcf1bff")),
                ("executableSha256", string(&oracle_identity.sha256.hex())),
                ("repository", string("chrisdone/hell")),
                ("schemaVersion", number(2)),
                ("sourceSha256", string(oracle_source_sha256)),
                ("state", string("verified")),
            ]),
        )?;
        retained.insert(
            "oracle-report.json".to_owned(),
            read_regular(&output.join("oracle-report.json"))?,
        );
        in_process_gate(
            "divergence-prototypes",
            crate::compatibility::release_divergence_prototype_catalog(root),
            gates,
            evidence,
        )?;
    }
    #[cfg(unix)]
    if platform == ReleasePlatform::MacosAarch64 {
        run_portable_platform_gates(PortablePlatformGateContext {
            plan,
            root,
            output,
            gates,
            evidence,
            retained,
            oracle_identity: &oracle_identity,
            oracle_source_sha256,
        })?;
    }
    #[cfg(windows)]
    if platform == ReleasePlatform::WindowsX86_64 {
        run_portable_platform_gates(PortablePlatformGateContext {
            plan,
            root,
            output,
            gates,
            evidence,
            retained,
            oracle_identity: &oracle_identity,
            oracle_source_sha256,
            platform,
            windows_release_binary,
            windows_gate_topology: &mut windows_gate_topology,
        })?;
    }
    #[cfg(unix)]
    if platform == ReleasePlatform::WindowsX86_64 {
        return Err("Windows release gates require a Windows trusted runner".to_owned());
    }
    #[cfg(windows)]
    if platform != ReleasePlatform::WindowsX86_64 {
        return Err("POSIX release gates require a POSIX trusted runner".to_owned());
    }
    require_executable_digest(
        &oracle_identity.path,
        oracle_identity.sha256,
        "retained oracle",
    )?;
    #[cfg(windows)]
    {
        windows_gate_topology.require_conformance_ready()?;
        let authority = windows_release_binary.as_ref().ok_or_else(|| {
            "Windows release binary authority is absent before conformance".to_owned()
        })?;
        authority.validate(
            "before conformance evidence collection",
            gates.get("release-build") == Some(&true),
        )?;
    }
    collect_conformance_evidence(
        platform,
        plan,
        conformance_plan,
        root,
        output,
        gates,
        evidence,
        retained,
        &oracle_identity,
        oracle_source_sha256,
        #[cfg(windows)]
        windows_release_binary.as_ref(),
    )?;
    #[cfg(windows)]
    if let Some(authority) = windows_release_binary.as_ref() {
        authority.validate(
            "after conformance evidence collection",
            gates.get("release-build") == Some(&true),
        )?;
    }
    Ok(())
}

fn require_executable_digest(
    path: &Path,
    expected: hell_testkit::Digest,
    label: &str,
) -> Result<(), String> {
    let observed =
        hell_testkit::sha256_file(path).map_err(|error| format!("cannot hash {label}: {error}"))?;
    if observed != expected {
        return Err(format!("{label} changed after trusted acquisition"));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn collect_conformance_evidence(
    platform: ReleasePlatform,
    plan: &ReleasePlan,
    conformance_plan: &crate::conformance::ConformancePlan,
    _root: &Path,
    output: &Path,
    gates: &mut BTreeMap<&'static str, bool>,
    gate_evidence: &mut BTreeMap<String, JsonValue>,
    retained: &mut BTreeMap<String, Vec<u8>>,
    oracle: &hell_testkit::ExecutableIdentity,
    oracle_source_sha256: &str,
    #[cfg(windows)] windows_release_binary: Option<&WindowsReleaseBinaryAuthority>,
) -> Result<(), String> {
    let conformance_platform = crate::conformance::ConformancePlatform::parse(platform.id())?;
    let assigned = conformance_plan
        .cells
        .iter()
        .flat_map(|cell| {
            cell.obligations
                .iter()
                .map(move |obligation| (cell, obligation))
        })
        .filter(|(cell, obligation)| {
            matches!(
                cell.scope,
                crate::conformance::ScopeDisposition::Required { .. }
            ) && obligation_is_assigned(cell, obligation, conformance_platform)
        })
        .collect::<Vec<_>>();
    let assigned_obligations =
        crate::conformance::assigned_obligation_count(conformance_plan, conformance_platform)?;
    if assigned_obligations
        != u64::try_from(assigned.len()).map_err(|_| "assigned obligation count overflow")?
    {
        return Err("platform obligation assignment differs from trusted engine".to_owned());
    }
    #[cfg(windows)]
    let candidate_path = windows_release_binary
        .ok_or_else(|| {
            "Windows release binary authority is absent before conformance evidence".to_owned()
        })?
        .bound_binary_path()?
        .to_path_buf();
    #[cfg(not(windows))]
    let candidate_path = {
        let target = crate::command::release_candidate_target()
            .ok_or_else(|| "candidate target environment binding is absent".to_owned())?;
        let candidate_path = target.join("release").join(platform.executable());
        require_real_binary_path(&target, &candidate_path)?;
        candidate_path
    };
    let candidate = hell_testkit::verify_executable(
        &candidate_path,
        hell_testkit::ExecutableRole::Candidate,
        None,
        hell_builtins::LANGUAGE_VERSION,
    )
    .map_err(|error| format!("cannot bind conformance candidate executable: {error}"))?;
    hell_testkit::verify_compat_tracing_candidate_identity(&candidate)
        .map_err(|error| format!("cannot bind candidate compatibility tracing: {error}"))?;
    let candidate_build_info = candidate
        .build_info
        .as_ref()
        .ok_or_else(|| "verified candidate build info is missing".to_owned())?;
    let oracle_binding = crate::conformance::OracleBinding {
        repository: "chrisdone/hell".to_owned(),
        commit: "8e952cf9de4ab25d7716982a9ca234f9bdcf1bff".to_owned(),
        executable_sha256: oracle.sha256.hex(),
        source_sha256: oracle_source_sha256.to_owned(),
    };
    let mut committed_case_list = hell_testkit::committed_differential_cases();
    bind_process_helper(&mut committed_case_list)?;
    let committed_cases = committed_case_list
        .into_iter()
        .map(|case| (case.id.to_string(), case))
        .collect::<BTreeMap<_, _>>();
    let requested_case_ids = assigned
        .iter()
        .flat_map(|(_, obligation)| obligation.case_ids.iter().cloned())
        .collect::<BTreeSet<_>>();
    let mut observations = BTreeMap::<String, Vec<u8>>::new();
    let mut committed_observations = BTreeMap::<String, (String, String)>::new();
    let requested_cases = requested_case_ids
        .iter()
        .map(|case_id| {
            committed_cases
                .get(case_id)
                .cloned()
                .ok_or_else(|| format!("planned committed case {case_id:?} is unavailable"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let workers = hell_testkit::differential_worker_limit();
    let committed_batch = hell_testkit::differential_batch_with_identities(
        oracle,
        &candidate,
        &requested_cases,
        workers,
    )
    .map_err(|error| format!("cannot collect committed differential batch: {error}"))?;
    let mut differential_timing = committed_batch.timing;
    for (case_id, report) in requested_case_ids.iter().zip(committed_batch.reports) {
        let oracle_digest = retain_observation(&report.oracle, &mut observations)?;
        let candidate_digest = retain_observation(&report.candidate, &mut observations)?;
        committed_observations.insert(case_id.clone(), (candidate_digest, oracle_digest));
    }
    let mut record_files = BTreeMap::<String, Vec<u8>>::new();
    let mut record_members = Vec::new();
    for (cell, obligation) in &assigned {
        for case_id in &obligation.case_ids {
            let case = committed_cases
                .get(case_id)
                .ok_or_else(|| format!("planned committed case {case_id:?} is unavailable"))?;
            let (candidate_observation_sha256, oracle_observation_sha256) = committed_observations
                .get(case_id)
                .ok_or_else(|| "committed observation was not collected".to_owned())?;
            let mut record = crate::conformance::EvidenceRecord {
                record_id: String::new(),
                release_plan_sha256: plan.plan_sha256.clone(),
                conformance_plan_sha256: conformance_plan.plan_sha256.clone(),
                candidate_sha: plan.resolution.candidate_sha.clone(),
                candidate_executable_sha256: candidate.sha256.hex(),
                candidate_build_info_schema_version: candidate_build_info.schema_version,
                candidate_compat_tracing: candidate_build_info.compat_tracing,
                source_inventory_sha256: plan.source_inventory_sha256.clone(),
                oracle: oracle_binding.clone(),
                platform: conformance_platform,
                profile: cell.key.profile,
                target: crate::conformance::EvidenceTarget {
                    cell: cell.key.clone(),
                    obligation_id: obligation.id.clone(),
                    case_id: case_id.clone(),
                },
                descriptor_sha256: hell_testkit::case_descriptor_sha256(case).hex(),
                case_source: crate::conformance::CaseSource::Committed,
                candidate_observation_sha256: candidate_observation_sha256.clone(),
                oracle_observation_sha256: oracle_observation_sha256.clone(),
                requested_normalizers: obligation.allowed_normalizers.clone(),
            };
            record.record_id = record.canonical_id()?;
            let bytes = canonical_json_bytes(&record.json())?;
            let path = format!("conformance-evidence/{}.json", record.record_id);
            record_members.push(crate::conformance::EvidenceMember {
                id: Some(record.record_id.clone()),
                path: path.clone(),
                sha256: hell_testkit::sha256_bytes(&bytes).hex(),
            });
            if record_files.insert(path, bytes).is_some() {
                return Err("conformance evidence record identity is duplicated".to_owned());
            }
        }
    }
    let mut exploratory_members = Vec::new();
    let mut unclassified_mismatches = 0_u64;
    let generated = hell_testkit::generated_typed_cases(
        crate::conformance::EXPLORATORY_GENERATOR_SEED,
        crate::conformance::EXPLORATORY_GENERATOR_COUNT,
    );
    let generated_cases = generated
        .iter()
        .map(|generated| hell_testkit::DifferentialCase {
            id: generated.id.clone(),
            source: generated.source.clone(),
            ..hell_testkit::DifferentialCase::default()
        })
        .collect::<Vec<_>>();
    let generated_batch = hell_testkit::differential_batch_with_identities(
        oracle,
        &candidate,
        &generated_cases,
        workers,
    )
    .map_err(|error| format!("cannot collect exploratory differential batch: {error}"))?;
    add_differential_timing(&mut differential_timing, generated_batch.timing);
    for (generated, report) in generated.iter().zip(generated_batch.reports) {
        let oracle_observation_sha256 = retain_observation(&report.oracle, &mut observations)?;
        let candidate_observation_sha256 =
            retain_observation(&report.candidate, &mut observations)?;
        if candidate_observation_sha256 != oracle_observation_sha256 {
            unclassified_mismatches = unclassified_mismatches
                .checked_add(1)
                .ok_or_else(|| "unclassified mismatch count overflow".to_owned())?;
        }
        let record = crate::conformance::ExploratoryRecord {
            generated_case_id: generated.id.to_string(),
            platform: conformance_platform,
            generator_version: crate::conformance::EXPLORATORY_GENERATOR_VERSION.to_owned(),
            seed: generated.seed,
            source_sha256: hell_testkit::sha256_bytes(generated.source.as_bytes()).hex(),
            ast_sha256: generated.ast_sha256.hex(),
            release_plan_sha256: plan.plan_sha256.clone(),
            conformance_plan_sha256: conformance_plan.plan_sha256.clone(),
            candidate_sha: plan.resolution.candidate_sha.clone(),
            candidate_executable_sha256: candidate.sha256.hex(),
            candidate_build_info_schema_version: candidate_build_info.schema_version,
            candidate_compat_tracing: candidate_build_info.compat_tracing,
            source_inventory_sha256: plan.source_inventory_sha256.clone(),
            oracle: oracle_binding.clone(),
            candidate_observation_sha256,
            oracle_observation_sha256,
        };
        let id = record.canonical_id()?;
        let bytes = canonical_json_bytes(&record.json()?)?;
        let path = format!("conformance-evidence/{id}.json");
        exploratory_members.push(crate::conformance::EvidenceMember {
            id: Some(id),
            path: path.clone(),
            sha256: hell_testkit::sha256_bytes(&bytes).hex(),
        });
        if record_files.insert(path, bytes).is_some() {
            return Err("exploratory evidence record identity is duplicated".to_owned());
        }
    }
    require_executable_digest(&oracle.path, oracle.sha256, "retained oracle")?;
    require_executable_digest(&candidate.path, candidate.sha256, "candidate executable")?;
    let mut observation_members = observations
        .iter()
        .map(|(digest, bytes)| crate::conformance::EvidenceMember {
            id: None,
            path: format!("conformance-observations/{digest}.json"),
            sha256: hell_testkit::sha256_bytes(bytes).hex(),
        })
        .collect::<Vec<_>>();
    record_members.sort_by(|left, right| left.path.cmp(&right.path));
    exploratory_members.sort_by(|left, right| left.path.cmp(&right.path));
    observation_members.sort_by(|left, right| left.path.cmp(&right.path));
    let manifest =
        crate::conformance::EvidenceManifest::new(crate::conformance::EvidenceManifestInput {
            platform: conformance_platform,
            candidate_sha: plan.resolution.candidate_sha.clone(),
            candidate_executable_sha256: candidate.sha256.hex(),
            release_plan_sha256: plan.plan_sha256.clone(),
            conformance_plan_sha256: conformance_plan.plan_sha256.clone(),
            oracle: oracle_binding,
            records: record_members,
            exploratory_records: exploratory_members,
            observations: observation_members,
            assigned_obligations,
        })?;
    for (path, bytes) in record_files {
        write_atomic(&output.join(&path), &bytes)?;
        retained.insert(path, bytes);
    }
    for (digest, bytes) in observations {
        let path = format!("conformance-observations/{digest}.json");
        write_atomic(&output.join(&path), &bytes)?;
        retained.insert(path, bytes);
    }
    let manifest_bytes = canonical_json_bytes(&manifest.json())?;
    write_atomic(
        &output.join("conformance-evidence-manifest.json"),
        &manifest_bytes,
    )?;
    retained.insert(
        "conformance-evidence-manifest.json".to_owned(),
        manifest_bytes,
    );
    gates.insert("conformance-evidence", true);
    gate_evidence.insert(
        "conformance-evidence".to_owned(),
        object([
            ("assignedObligations", number(assigned_obligations)),
            (
                "candidateProcessSumMillis",
                number(duration_millis(
                    differential_timing.candidate_process_sum,
                    "candidate process timing",
                )?),
            ),
            ("candidateExecutableSha256", string(&candidate.sha256.hex())),
            (
                "completedDifferentialCases",
                number(
                    u64::try_from(differential_timing.completed_count)
                        .map_err(|_| "completed differential case count overflow")?,
                ),
            ),
            (
                "differentialBatchWallMillis",
                number(duration_millis(
                    differential_timing.wall,
                    "differential batch wall timing",
                )?),
            ),
            (
                "differentialDriverOverheadSumMillis",
                number(duration_millis(
                    differential_timing.driver_overhead_sum,
                    "differential driver timing",
                )?),
            ),
            (
                "differentialWorkerCount",
                number(
                    u64::try_from(differential_timing.worker_count)
                        .map_err(|_| "differential worker count overflow")?,
                ),
            ),
            (
                "exploratoryRecords",
                number(
                    u64::try_from(manifest.exploratory_records.len())
                        .map_err(|_| "exploratory record count overflow")?,
                ),
            ),
            ("manifestSha256", string(&manifest.manifest_sha256)),
            (
                "oracleCommit",
                string("8e952cf9de4ab25d7716982a9ca234f9bdcf1bff"),
            ),
            (
                "oracleProcessSumMillis",
                number(duration_millis(
                    differential_timing.oracle_process_sum,
                    "oracle process timing",
                )?),
            ),
            ("oracleExecutableSha256", string(&oracle.sha256.hex())),
            ("oracleRepository", string("chrisdone/hell")),
            ("oracleSourceSha256", string(oracle_source_sha256)),
            ("producedRecords", number(manifest.produced_records)),
            ("schemaVersion", number(1)),
            ("state", string("collected")),
            ("unclassifiedMismatches", number(unclassified_mismatches)),
        ]),
    );
    Ok(())
}

fn add_differential_timing(
    total: &mut hell_testkit::DifferentialBatchTiming,
    batch: hell_testkit::DifferentialBatchTiming,
) {
    total.case_count = total.case_count.saturating_add(batch.case_count);
    total.completed_count = total.completed_count.saturating_add(batch.completed_count);
    total.worker_count = total.worker_count.max(batch.worker_count);
    total.wall = total.wall.saturating_add(batch.wall);
    total.oracle_process_sum = total
        .oracle_process_sum
        .saturating_add(batch.oracle_process_sum);
    total.candidate_process_sum = total
        .candidate_process_sum
        .saturating_add(batch.candidate_process_sum);
    total.driver_overhead_sum = total
        .driver_overhead_sum
        .saturating_add(batch.driver_overhead_sum);
}

fn duration_millis(duration: Duration, label: &str) -> Result<u64, String> {
    u64::try_from(duration.as_millis()).map_err(|_| format!("{label} overflow"))
}

fn obligation_is_assigned(
    cell: &crate::conformance::PlannedCell,
    obligation: &crate::conformance::PlannedObligation,
    platform: crate::conformance::ConformancePlatform,
) -> bool {
    match obligation.strategy {
        crate::conformance::EvidenceStrategy::NativeOracle
        | crate::conformance::EvidenceStrategy::CommittedDifferentialCorpus => {
            cell.key.platform == platform
        }
        crate::conformance::EvidenceStrategy::PortableStatic
        | crate::conformance::EvidenceStrategy::StructuralInvariant => {
            platform == crate::conformance::ConformancePlatform::LinuxX86_64
        }
        crate::conformance::EvidenceStrategy::CrossPlatformRelation => false,
    }
}

fn bind_process_helper(cases: &mut [hell_testkit::DifferentialCase]) -> Result<(), String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("cannot locate trusted release driver: {error}"))?;
    let directory = executable
        .parent()
        .ok_or_else(|| "trusted release driver has no directory".to_owned())?;
    let profile = if directory.file_name().is_some_and(|name| name == "deps") {
        directory.parent().unwrap_or(directory)
    } else {
        directory
    };
    hell_testkit::bind_process_helper_directory(cases, profile)
        .map(|_| ())
        .map_err(|error| format!("cannot bind trusted differential helper: {error}"))
}

fn require_source_inventory(root: &Path, expected: &str) -> Result<(), String> {
    let observed = source_inventory(root)?;
    let digest = hell_testkit::sha256_bytes(&canonical_json_bytes(&observed)?).hex();
    if digest != expected {
        return Err("candidate source inventory changed during candidate execution".to_owned());
    }
    Ok(())
}

fn retain_observation(
    observation: &hell_testkit::Observation,
    observations: &mut BTreeMap<String, Vec<u8>>,
) -> Result<String, String> {
    let bytes = hell_testkit::canonical_conformance_observation_json(observation)
        .map_err(|error| format!("cannot encode bounded conformance observation: {error}"))?;
    let parsed = crate::conformance::Observation::parse_canonical(bytes.clone())?;
    match observations.entry(parsed.sha256.clone()) {
        std::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert(bytes);
        }
        std::collections::btree_map::Entry::Occupied(entry) if entry.get() == &bytes => {}
        std::collections::btree_map::Entry::Occupied(_) => {
            return Err("observation digest collision has contradictory bytes".to_owned());
        }
    }
    Ok(parsed.sha256)
}

const LINUX_ORACLE_NAME: &str = "hell-linux-amd64";
const LINUX_ORACLE_SHA256: &str =
    "5ccc78e62200eb5aea8b9da9161334c61848d0d3e7de2f270929920cfbf357c9";

#[cfg(unix)]
struct LinuxOracleAcquisition {
    output: PathBuf,
    output_identity: PosixObjectIdentity,
    directory: PathBuf,
    directory_identity: PosixObjectIdentity,
    oracle_identity: Option<(PosixObjectIdentity, u64, hell_testkit::Digest)>,
    active: bool,
}

#[cfg(unix)]
impl LinuxOracleAcquisition {
    fn reserve(output: &Path) -> Result<Self, String> {
        use std::os::unix::fs::PermissionsExt as _;

        let canonical = fs::canonicalize(output)
            .map_err(|error| format!("cannot canonicalize trusted oracle output: {error}"))?;
        let metadata = fs::symlink_metadata(output)
            .map_err(|error| format!("cannot inspect trusted oracle output: {error}"))?;
        if canonical != output
            || metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Err(
                "trusted oracle output is redirected or writable by another principal".to_owned(),
            );
        }
        let directory = output.join(".trusted-oracle-acquisition");
        if directory.exists() {
            return Err("trusted oracle acquisition directory already exists".to_owned());
        }
        fs::create_dir(&directory)
            .map_err(|error| format!("cannot reserve trusted oracle acquisition: {error}"))?;
        if let Err(error) = fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)) {
            let _ = fs::remove_dir(&directory);
            return Err(format!(
                "cannot protect trusted oracle acquisition: {error}"
            ));
        }
        let acquisition = Self {
            output: output.to_path_buf(),
            output_identity: posix_object_identity(output)?,
            directory: directory.clone(),
            directory_identity: posix_object_identity(&directory)?,
            oracle_identity: None,
            active: true,
        };
        acquisition.validate()?;
        Ok(acquisition)
    }

    fn directory(&self) -> &Path {
        &self.directory
    }

    fn bind_path(&mut self, path: &Path, sha256: hell_testkit::Digest) -> Result<(), String> {
        let expected = self.directory.join(LINUX_ORACLE_NAME);
        if path != expected {
            return Err("downloaded Linux oracle path differs from acquisition policy".to_owned());
        }
        require_executable_digest(path, sha256, "downloaded Linux oracle")?;
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| format!("cannot inspect downloaded Linux oracle: {error}"))?;
        self.oracle_identity = Some((posix_object_identity(path)?, metadata.len(), sha256));
        self.validate()
    }

    fn validate(&self) -> Result<(), String> {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        if !self.active
            || self.directory.parent() != Some(&self.output)
            || self.directory.file_name()
                != Some(std::ffi::OsStr::new(".trusted-oracle-acquisition"))
            || posix_object_identity(&self.output)? != self.output_identity
            || posix_object_identity(&self.directory)? != self.directory_identity
        {
            return Err("trusted oracle acquisition authority changed".to_owned());
        }
        let directory_metadata = fs::symlink_metadata(&self.directory)
            .map_err(|error| format!("cannot inspect trusted oracle acquisition: {error}"))?;
        if directory_metadata.file_type().is_symlink()
            || !directory_metadata.is_dir()
            || directory_metadata.permissions().mode() & 0o7777 != 0o700
        {
            return Err("trusted oracle acquisition permissions changed".to_owned());
        }
        match &self.oracle_identity {
            None => {
                require_exact_directory_members(&self.directory, &[], "trusted oracle acquisition")
            }
            Some((expected_identity, expected_size, expected_sha256)) => {
                let oracle = self.directory.join(LINUX_ORACLE_NAME);
                require_exact_directory_members(
                    &self.directory,
                    &[OsString::from(LINUX_ORACLE_NAME)],
                    "trusted oracle acquisition",
                )?;
                let metadata = fs::symlink_metadata(&oracle)
                    .map_err(|error| format!("cannot inspect downloaded Linux oracle: {error}"))?;
                if metadata.file_type().is_symlink()
                    || !metadata.is_file()
                    || metadata.nlink() != 1
                    || metadata.len() != *expected_size
                    || fs::canonicalize(&oracle).ok().as_deref() != Some(oracle.as_path())
                    || posix_object_identity(&oracle)? != *expected_identity
                {
                    return Err("downloaded Linux oracle identity changed".to_owned());
                }
                require_executable_digest(&oracle, *expected_sha256, "downloaded Linux oracle")
            }
        }
    }

    fn cleanup(&mut self) -> Result<(), String> {
        if !self.active {
            return Ok(());
        }
        self.validate()?;
        if self.oracle_identity.is_some() {
            fs::remove_file(self.directory.join(LINUX_ORACLE_NAME))
                .map_err(|error| format!("cannot remove downloaded Linux oracle: {error}"))?;
        }
        fs::remove_dir(&self.directory)
            .map_err(|error| format!("cannot remove trusted oracle acquisition: {error}"))?;
        self.active = false;
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for LinuxOracleAcquisition {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

struct UnretainedOracle {
    #[cfg(unix)]
    path: PathBuf,
    #[cfg(unix)]
    sha256: hell_testkit::Digest,
    #[cfg(windows)]
    identity: Option<hell_testkit::ExecutableIdentity>,
    #[cfg(unix)]
    acquisition: Option<LinuxOracleAcquisition>,
}

impl UnretainedOracle {
    fn native(identity: hell_testkit::ExecutableIdentity) -> Self {
        Self {
            #[cfg(unix)]
            path: identity.path.clone(),
            #[cfg(unix)]
            sha256: identity.sha256,
            #[cfg(windows)]
            identity: Some(identity),
            #[cfg(unix)]
            acquisition: None,
        }
    }

    #[cfg(windows)]
    fn identity(&self) -> Result<&hell_testkit::ExecutableIdentity, String> {
        self.identity
            .as_ref()
            .ok_or_else(|| "unverified oracle cannot be retained on Windows".to_owned())
    }

    fn cleanup(self) -> Result<(), String> {
        #[cfg(unix)]
        {
            let mut this = self;
            if let Some(acquisition) = &mut this.acquisition {
                acquisition.cleanup()?;
            }
        }
        #[cfg(windows)]
        drop(self);
        Ok(())
    }
}

fn acquire_linux_oracle(output: &Path) -> Result<PathBuf, String> {
    const URL: &str =
        "https://github.com/chrisdone/hell/releases/download/2026-05-29/hell-linux-amd64";
    const MAX_ORACLE_BYTES: u64 = 64 * 1024 * 1024;
    #[cfg(unix)]
    require_exact_directory_members(output, &[], "trusted oracle acquisition")?;
    let config = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_mins(5)))
        .build();
    let agent: ureq::Agent = config.into();
    let mut response = agent
        .get(URL)
        .header("Accept", "application/octet-stream")
        .header("User-Agent", "hell-ci-release-oracle")
        .call()
        .map_err(|_| "pinned Linux oracle download failed".to_owned())?;
    if response.status().as_u16() != 200 {
        return Err(format!(
            "pinned Linux oracle returned HTTP {}",
            response.status().as_u16()
        ));
    }
    let bytes = response
        .body_mut()
        .with_config()
        .limit(MAX_ORACLE_BYTES)
        .read_to_vec()
        .map_err(|error| format!("cannot read bounded Linux oracle response: {error}"))?;
    if bytes.is_empty() || hell_testkit::sha256_bytes(&bytes).hex() != LINUX_ORACLE_SHA256 {
        return Err("pinned Linux oracle digest differs".to_owned());
    }
    let path = output.join(LINUX_ORACLE_NAME);
    write_atomic(&path, &bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
            .map_err(|error| format!("cannot set Linux oracle executable mode: {error}"))?;
    }
    Ok(path)
}

fn prepare_oracle(
    platform: ReleasePlatform,
    oracle_source: &Path,
    _trusted_output: &Path,
    archive_adapter: &crate::command::NativeArchiveAdapter,
    native_deadlines: Option<NativeOracleCommandDeadlines>,
) -> Result<UnretainedOracle, String> {
    if platform == ReleasePlatform::LinuxX86_64 {
        #[cfg(not(unix))]
        return Err("Linux oracle acquisition requires a POSIX trusted runner".to_owned());
        #[cfg(unix)]
        let mut acquisition = LinuxOracleAcquisition::reserve(_trusted_output)?;
        #[cfg(unix)]
        let oracle = acquire_linux_oracle(acquisition.directory())?;
        #[cfg(unix)]
        let pinned_sha256 =
            hell_testkit::Digest::from_hex(LINUX_ORACLE_SHA256).map_err(str::to_owned)?;
        #[cfg(unix)]
        acquisition.bind_path(&oracle, pinned_sha256)?;
        #[cfg(unix)]
        return Ok(UnretainedOracle {
            path: oracle,
            sha256: pinned_sha256,
            acquisition: Some(acquisition),
        });
    }
    let build = archive_adapter.stack_build(oracle_source, Duration::from_hours(2));
    let result = run_native_oracle_command(build, native_deadlines, "build native oracle")?;
    if !result.status.success() || result.timed_out {
        return Err(native_oracle_command_failure(
            "native-oracle-build",
            &result,
        ));
    }
    let path = archive_adapter.stack_path(oracle_source);
    let result = run_native_oracle_command(path, native_deadlines, "resolve native oracle")?;
    if !result.status.success() || result.timed_out || result.stdout_truncated {
        return Err(native_oracle_command_failure("native-oracle-path", &result));
    }
    let install_root = std::str::from_utf8(&result.stdout)
        .map_err(|_| "native oracle path is not UTF-8".to_owned())?
        .trim();
    let executable = PathBuf::from(install_root)
        .join("bin")
        .join(format!("hell{}", std::env::consts::EXE_SUFFIX));
    let identity = hell_testkit::verify_executable(
        &executable,
        hell_testkit::ExecutableRole::Oracle,
        None,
        hell_builtins::LANGUAGE_VERSION,
    )
    .map_err(|error| format!("cannot prepare native oracle: {error}"))?;
    Ok(UnretainedOracle::native(identity))
}

fn run_native_oracle_command(
    command: CommandSpec,
    deadlines: Option<NativeOracleCommandDeadlines>,
    phase: &str,
) -> Result<CommandResult, String> {
    match deadlines {
        Some(deadlines) => {
            let (progress, _progress_receiver) =
                hell_testkit::SupervisedProgressObserver::bounded(1);
            command
                .run_until(deadlines.execution, deadlines.completion, progress)
                .map_err(|error| format!("cannot {phase}: {error}"))
        }
        None => command
            .run()
            .map_err(|error| format!("cannot {phase}: {error}")),
    }
}

fn native_oracle_command_failure(phase: &str, result: &CommandResult) -> String {
    format!(
        "{phase} failed: status={:?}, timedOut={}, duration={:?}, stdoutBytes={}, stderrBytes={}, stdoutSha256={}, stderrSha256={}, stdoutTruncated={}, stderrTruncated={}, stderr={:?}",
        result.status.code(),
        result.timed_out,
        result.duration,
        result.stdout_bytes,
        result.stderr_bytes,
        result.stdout_sha256.hex(),
        result.stderr_sha256.hex(),
        result.stdout_truncated,
        result.stderr_truncated,
        String::from_utf8_lossy(&result.stderr),
    )
}

#[cfg(windows)]
fn retain_oracle_copy(
    candidate_root: &Path,
    identity: hell_testkit::ExecutableIdentity,
) -> Result<hell_testkit::ExecutableIdentity, String> {
    let retained_root = transient_path(candidate_root, "retained-oracle");
    if retained_root.exists() {
        return Err("retained oracle directory already exists".to_owned());
    }
    fs::create_dir_all(&retained_root)
        .map_err(|error| format!("cannot create retained oracle directory: {error}"))?;
    let bytes = read_regular(&identity.path)?;
    let retained = retained_root.join(format!("hell{}", std::env::consts::EXE_SUFFIX));
    write_atomic(&retained, &bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&retained, fs::Permissions::from_mode(0o755))
            .map_err(|error| format!("cannot set retained oracle mode: {error}"))?;
    }
    hell_testkit::verify_executable(
        &retained,
        hell_testkit::ExecutableRole::Oracle,
        Some(identity.sha256),
        hell_builtins::LANGUAGE_VERSION,
    )
    .map_err(|error| format!("cannot verify retained oracle copy: {error}"))
}

fn linux_rust_commands(root: &Path) -> Vec<(&'static str, CommandSpec)> {
    vec![
        (
            "format",
            cargo(root, Duration::from_mins(5), ["fmt", "--all", "--check"]),
        ),
        (
            "clippy",
            cargo(
                root,
                Duration::from_mins(30),
                [
                    "clippy",
                    "--workspace",
                    "--all-targets",
                    "--all-features",
                    "--locked",
                    "--",
                    "-D",
                    "warnings",
                ],
            ),
        ),
        (
            "workspace-tests",
            cargo(
                root,
                Duration::from_hours(1),
                [
                    "test",
                    "--workspace",
                    "--all-targets",
                    "--all-features",
                    "--locked",
                ],
            ),
        ),
        (
            "documentation",
            cargo(
                root,
                Duration::from_mins(30),
                [
                    "doc",
                    "--workspace",
                    "--all-features",
                    "--no-deps",
                    "--locked",
                ],
            )
            .environment("RUSTDOCFLAGS", "-D warnings"),
        ),
        ("release-build", release_candidate_build(root)),
    ]
}

fn release_candidate_build(root: &Path) -> CommandSpec {
    cargo(
        root,
        Duration::from_mins(30),
        [
            "build",
            "--release",
            "--locked",
            "--package",
            "hell-cli",
            "--bin",
            "hell",
            "--features",
            "compat-tracing",
        ],
    )
}

fn suite_examples(
    root: &Path,
    _output: &Path,
    gates: &mut BTreeMap<&'static str, bool>,
    evidence: &mut BTreeMap<String, JsonValue>,
) -> Result<(), String> {
    let mut report = Report::new("release-examples");
    crate::release_suite::examples(
        root,
        &mut report,
        &transient_path(root, "examples"),
        "release",
    )
    .map_err(|kind| format!("release examples failed: {kind:?}"))?;
    gates.insert("release-examples", true);
    evidence.insert("release-examples".to_owned(), suite_evidence(&report)?);
    Ok(())
}

fn suite_gate(
    name: &'static str,
    root: &Path,
    output: &Path,
    run: fn(&Path, &mut Report, &Path) -> Result<(), crate::release_suite::FailureKind>,
    gates: &mut BTreeMap<&'static str, bool>,
    evidence: &mut BTreeMap<String, JsonValue>,
) -> Result<(), String> {
    let mut report = Report::new(name);
    if let Err(kind) = run(root, &mut report, &transient_path(root, name)) {
        let primary = suite_failure(name, kind, &report);
        let failure_report = object([
            ("detail", string(&primary)),
            ("failedGate", string(name)),
            ("report", parse_json(&report.to_json())?),
            ("schemaVersion", number(1)),
            ("state", string("failed")),
        ]);
        return match write_json(
            &output.join("platform-failure-report.json"),
            &failure_report,
        ) {
            Ok(_) => Err(primary),
            Err(persistence) => Err(format!(
                "{primary}; additionally, cannot persist platform failure report: {persistence}"
            )),
        };
    }
    gates.insert(name, true);
    evidence.insert(name.to_owned(), suite_evidence(&report)?);
    Ok(())
}

const SUITE_FAILURE_DETAIL_BYTE_LIMIT: usize = 4 * 1024;

fn suite_failure(name: &str, kind: crate::release_suite::FailureKind, report: &Report) -> String {
    let summary = format!("release gate {name} failed: {kind:?}");
    let Some(failure) = report.failures.first() else {
        return summary;
    };
    if failure.len() <= SUITE_FAILURE_DETAIL_BYTE_LIMIT {
        return format!("{summary}; failure[0]: {failure:?}");
    }
    let boundary = (0..=SUITE_FAILURE_DETAIL_BYTE_LIMIT)
        .rev()
        .find(|boundary| failure.is_char_boundary(*boundary))
        .unwrap_or_default();
    let prefix = &failure[..boundary];
    let sha256 = hell_testkit::sha256_bytes(failure.as_bytes()).hex();
    format!(
        "{summary}; failure[0]: {prefix:?} [truncated; bytes={}; sha256={sha256}]",
        failure.len()
    )
}

fn suite_evidence(report: &Report) -> Result<JsonValue, String> {
    Ok(object([
        ("report", parse_json(&report.to_json())?),
        ("schemaVersion", number(1)),
        ("state", string("passed")),
    ]))
}

fn transient_path(root: &Path, name: &str) -> PathBuf {
    root.parent()
        .unwrap_or_else(|| Path::new("."))
        .join("release-gate-transient")
        .join(name)
}

fn command_gate(
    name: &'static str,
    command: CommandSpec,
    output: &Path,
    gates: &mut BTreeMap<&'static str, bool>,
    evidence: &mut BTreeMap<String, JsonValue>,
) -> Result<(), String> {
    let program = command.display_program();
    let invocation_name = command.display_invocation_name();
    let canonical_identity = command.display_canonical_executable_identity();
    let arguments = command.display_arguments();
    let result = command
        .run()
        .map_err(|error| format!("release gate {name} could not run: {error}"))?;
    let passed = result.status.success() && !result.timed_out;
    let command_evidence = command_evidence(
        &program,
        invocation_name.as_deref(),
        canonical_identity.as_deref(),
        &arguments,
        &result,
    );
    evidence.insert(name.to_owned(), command_evidence);
    gates.insert(name, passed);
    if passed {
        return Ok(());
    }
    let detail = command_failure_detail(name, &result);
    let report = object([
        ("detail", string(&detail)),
        ("evidence", JsonValue::Object(evidence.clone())),
        ("failedGate", string(name)),
        (
            "gates",
            JsonValue::Array(
                gates
                    .iter()
                    .map(|(gate, passed)| {
                        object([("name", string(gate)), ("passed", JsonValue::Bool(*passed))])
                    })
                    .collect(),
            ),
        ),
        ("schemaVersion", number(1)),
        ("state", string("failed")),
    ]);
    match write_json(&output.join("platform-failure-report.json"), &report) {
        Ok(_) => Err(detail),
        Err(error) => Err(format!(
            "{detail}; additionally, cannot persist platform failure report: {error}"
        )),
    }
}

const COMMAND_FAILURE_OUTPUT_BYTE_LIMIT: usize = 2 * 1024;

fn bounded_command_output(bytes: &[u8]) -> (String, bool) {
    let rendered = String::from_utf8_lossy(bytes);
    if rendered.len() <= COMMAND_FAILURE_OUTPUT_BYTE_LIMIT {
        return (rendered.into_owned(), false);
    }
    let boundary = (0..=COMMAND_FAILURE_OUTPUT_BYTE_LIMIT)
        .rev()
        .find(|boundary| rendered.is_char_boundary(*boundary))
        .unwrap_or_default();
    (rendered[..boundary].to_owned(), true)
}

fn command_failure_detail(name: &str, result: &CommandResult) -> String {
    let (stdout, stdout_detail_truncated) = bounded_command_output(&result.stdout);
    let (stderr, stderr_detail_truncated) = bounded_command_output(&result.stderr);
    format!(
        "release gate {name} failed: status={:?}, timedOut={}, stdoutBytes={}, stderrBytes={}, stdoutSha256={}, stderrSha256={}, stdoutTruncated={}, stderrTruncated={}, stdoutDetailTruncated={stdout_detail_truncated}, stderrDetailTruncated={stderr_detail_truncated}, stdout={stdout:?}, stderr={stderr:?}",
        result.status.code(),
        result.timed_out,
        result.stdout_bytes,
        result.stderr_bytes,
        result.stdout_sha256.hex(),
        result.stderr_sha256.hex(),
        result.stdout_truncated,
        result.stderr_truncated,
    )
}

fn command_evidence(
    program: &str,
    invocation_name: Option<&str>,
    canonical_identity: Option<&str>,
    arguments: &[String],
    result: &CommandResult,
) -> JsonValue {
    let (stdout, stdout_detail_truncated) = bounded_command_output(&result.stdout);
    let (stderr, stderr_detail_truncated) = bounded_command_output(&result.stderr);
    let mut evidence = BTreeMap::from([
        (
            "arguments".to_owned(),
            JsonValue::Array(arguments.iter().map(|value| string(value)).collect()),
        ),
        ("program".to_owned(), string(program)),
        ("schemaVersion".to_owned(), number(2)),
        (
            "durationMillis".to_owned(),
            number(u64::try_from(result.duration.as_millis()).unwrap_or(u64::MAX)),
        ),
        (
            "statusCode".to_owned(),
            result
                .status
                .code()
                .and_then(|code| u64::try_from(code).ok())
                .map_or(JsonValue::Null, number),
        ),
        (
            "state".to_owned(),
            string(if result.status.success() && !result.timed_out {
                "passed"
            } else {
                "failed"
            }),
        ),
        ("stderrBytes".to_owned(), number(result.stderr_bytes)),
        ("stderrDetail".to_owned(), string(&stderr)),
        (
            "stderrDetailTruncated".to_owned(),
            JsonValue::Bool(stderr_detail_truncated),
        ),
        (
            "stderrSha256".to_owned(),
            string(&result.stderr_sha256.hex()),
        ),
        (
            "stderrTruncated".to_owned(),
            JsonValue::Bool(result.stderr_truncated),
        ),
        ("stdoutBytes".to_owned(), number(result.stdout_bytes)),
        ("stdoutDetail".to_owned(), string(&stdout)),
        (
            "stdoutDetailTruncated".to_owned(),
            JsonValue::Bool(stdout_detail_truncated),
        ),
        (
            "stdoutSha256".to_owned(),
            string(&result.stdout_sha256.hex()),
        ),
        (
            "stdoutTruncated".to_owned(),
            JsonValue::Bool(result.stdout_truncated),
        ),
        ("timedOut".to_owned(), JsonValue::Bool(result.timed_out)),
    ]);
    if let Some(invocation_name) = invocation_name {
        evidence.insert("invocationName".to_owned(), string(invocation_name));
    }
    if let Some(canonical_identity) = canonical_identity {
        evidence.insert(
            "canonicalExecutableIdentity".to_owned(),
            string(canonical_identity),
        );
    }
    JsonValue::Object(evidence)
}

#[cfg(any(unix, windows))]
fn platform_failure_fixture_bytes(label: &[u8]) -> Vec<u8> {
    let limit = hell_testkit::complete_capture_byte_limit_for_integration();
    let mut bytes = Vec::with_capacity(limit.saturating_add(label.len()).saturating_add(3));
    while bytes.len() < limit {
        let remaining = limit - bytes.len();
        bytes.extend_from_slice(&label[..label.len().min(remaining)]);
    }
    bytes.extend_from_slice("é".as_bytes());
    bytes.push(b'\n');
    bytes
}

#[cfg(any(unix, windows))]
pub(crate) fn run_platform_command_failure_child(
    arguments: &[std::ffi::OsString],
) -> std::process::ExitCode {
    if !arguments.is_empty() {
        eprintln!("platform command-failure child accepts no arguments");
        return std::process::ExitCode::FAILURE;
    }
    let stdout = platform_failure_fixture_bytes(b"out-");
    let stderr = platform_failure_fixture_bytes(b"err-");
    if std::io::stdout().write_all(&stdout).is_err()
        || std::io::stderr().write_all(&stderr).is_err()
    {
        return std::process::ExitCode::FAILURE;
    }
    std::process::ExitCode::from(23)
}

#[cfg(windows)]
pub(crate) fn run_repository_inventory_target_stderr_child(
    arguments: &[std::ffi::OsString],
) -> std::process::ExitCode {
    if !arguments.is_empty() {
        return std::process::ExitCode::FAILURE;
    }
    if std::io::stdout().write_all(b"tracked-file\0").is_err()
        || std::io::stderr()
            .write_all(b"inventory-target-stderr\n")
            .is_err()
    {
        return std::process::ExitCode::FAILURE;
    }
    std::process::ExitCode::SUCCESS
}

#[cfg(any(unix, windows))]
pub(crate) fn verify_platform_command_failure_report_for_integration() -> Result<(), String> {
    let ordered = compose_platform_gate_cleanup(
        Err("primary gate failed".to_owned()),
        Err("cleanup mutation failed".to_owned()),
    )
    .expect_err("primary and cleanup failures must compose");
    if ordered
        != "primary gate failed; additionally, dependency-policy cache cleanup failed: cleanup mutation failed"
    {
        return Err("platform gate and dependency cleanup cause order differs".to_owned());
    }
    let root = std::env::temp_dir().join(format!(
        "hell-platform-failure-report-{}-{}",
        std::process::id(),
        PLATFORM_FAILURE_VERIFIER_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root)
        .map_err(|error| format!("cannot create platform failure verifier root: {error}"))?;
    let result = (|| {
        let output = root.join("output");
        fs::create_dir(&output)
            .map_err(|error| format!("cannot create platform failure output: {error}"))?;
        let executable = std::env::current_exe()
            .map_err(|error| format!("cannot resolve platform failure verifier: {error}"))?;
        let command = || {
            CommandSpec::new(&executable, Duration::from_secs(30))
                .argument("__platform-command-failure-child")
        };
        let mut gates = BTreeMap::new();
        let mut evidence = BTreeMap::new();
        let primary = command_gate(
            "deterministic-command-failure",
            command(),
            &output,
            &mut gates,
            &mut evidence,
        )
        .expect_err("the deterministic nonzero command must fail its gate");
        if primary.contains("additionally,") {
            return Err(
                "successful failure-report persistence was composed as a failure".to_owned(),
            );
        }
        let report_path = output.join("platform-failure-report.json");
        let report = fs::read_to_string(&report_path)
            .map_err(|error| format!("cannot read platform failure report: {error}"))?;
        let report = parse_json(&report)?;
        let report = report.object()?;
        if json_member(report, "schemaVersion")?.number()? != 1
            || json_member(report, "state")?.string()? != "failed"
            || json_member(report, "failedGate")?.string()? != "deterministic-command-failure"
            || json_member(report, "detail")?.string()? != primary
        {
            return Err("platform failure report terminal fields differ".to_owned());
        }
        let evidence = json_member(report, "evidence")?.object()?;
        let command_receipt = json_member(evidence, "deterministic-command-failure")?.object()?;
        let stdout = platform_failure_fixture_bytes(b"out-");
        let stderr = platform_failure_fixture_bytes(b"err-");
        if json_member(command_receipt, "schemaVersion")?.number()? != 2
            || json_member(command_receipt, "statusCode")?.number()? != 23
            || json_member(command_receipt, "timedOut")?.boolean()?
            || json_member(command_receipt, "stdoutBytes")?.number()?
                != u64::try_from(stdout.len()).unwrap_or(u64::MAX)
            || json_member(command_receipt, "stderrBytes")?.number()?
                != u64::try_from(stderr.len()).unwrap_or(u64::MAX)
            || json_member(command_receipt, "stdoutSha256")?.string()?
                != hell_testkit::sha256_bytes(&stdout).hex()
            || json_member(command_receipt, "stderrSha256")?.string()?
                != hell_testkit::sha256_bytes(&stderr).hex()
            || !json_member(command_receipt, "stdoutTruncated")?.boolean()?
            || !json_member(command_receipt, "stderrTruncated")?.boolean()?
            || !json_member(command_receipt, "stdoutDetailTruncated")?.boolean()?
            || !json_member(command_receipt, "stderrDetailTruncated")?.boolean()?
        {
            return Err("platform failure report command receipt differs".to_owned());
        }
        let entries = fs::read_dir(&output)
            .map_err(|error| format!("cannot inspect platform failure output: {error}"))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("cannot enumerate platform failure output: {error}"))?;
        if entries.len() != 1 || entries[0].path() != report_path {
            return Err(
                "platform failure report publication was not one atomic artifact".to_owned(),
            );
        }

        let blocked = root.join("blocked-output");
        fs::write(&blocked, b"not-a-directory\n")
            .map_err(|error| format!("cannot create persistence failure fixture: {error}"))?;
        let mut blocked_gates = BTreeMap::new();
        let mut blocked_evidence = BTreeMap::new();
        let composed = command_gate(
            "deterministic-command-failure",
            command(),
            &blocked,
            &mut blocked_gates,
            &mut blocked_evidence,
        )
        .expect_err("failure-report persistence injection must fail");
        let separator = "; additionally, cannot persist platform failure report:";
        if !composed.starts_with(&primary)
            || composed
                .strip_prefix(&primary)
                .and_then(|tail| tail.strip_prefix(separator))
                .is_none()
        {
            return Err("platform failure persistence cause order differs".to_owned());
        }
        Ok(())
    })();
    let cleanup = fs::remove_dir_all(&root)
        .map_err(|error| format!("cannot clean platform failure verifier root: {error}"));
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(()), Err(cleanup)) => Err(cleanup),
        (Err(primary), Err(cleanup)) => Err(format!("{primary}; additionally, {cleanup}")),
    }
}

fn in_process_gate(
    name: &'static str,
    result: Result<String, String>,
    gates: &mut BTreeMap<&'static str, bool>,
    evidence: &mut BTreeMap<String, JsonValue>,
) -> Result<(), String> {
    let detail = result?;
    gates.insert(name, true);
    evidence.insert(
        name.to_owned(),
        object([
            ("detail", string(&detail)),
            ("schemaVersion", number(1)),
            ("state", string("passed")),
        ]),
    );
    Ok(())
}

fn cargo<const N: usize>(root: &Path, timeout: Duration, arguments: [&str; N]) -> CommandSpec {
    CommandSpec::cargo(timeout)
        .arguments(arguments)
        .current_directory(root)
}

fn tool_identities(
    platform: ReleasePlatform,
    candidate_root: &Path,
    oracle_source: &Path,
    archive_adapter: &crate::command::NativeArchiveAdapter,
) -> Result<BTreeMap<String, JsonValue>, String> {
    let mut identities = BTreeMap::new();
    for (name, command) in [
        (
            "cargo",
            CommandSpec::cargo(Duration::from_secs(30))
                .argument("--version")
                .current_directory(candidate_root),
        ),
        (
            "rustc",
            CommandSpec::new("rustc", Duration::from_secs(30))
                .arguments(["--version", "--verbose"])
                .current_directory(candidate_root),
        ),
        (
            "stack",
            CommandSpec::new("stack", Duration::from_secs(30))
                .argument("--numeric-version")
                .current_directory(candidate_root),
        ),
    ] {
        identities.insert(name.to_owned(), string(&tool_output(command, name)?));
    }
    if identities
        .get("stack")
        .ok_or_else(|| "Stack identity is missing".to_owned())?
        .string()?
        != "3.11.1"
    {
        return Err("Stack version differs from release policy".to_owned());
    }
    if platform != ReleasePlatform::LinuxX86_64 {
        if let Some(identity) = archive_adapter.identity_command() {
            identities.insert(
                "llvm-ar".to_owned(),
                string(&tool_output(
                    identity.current_directory(candidate_root),
                    "llvm-ar",
                )?),
            );
        }
        identities.insert(
            "ghc".to_owned(),
            string(&tool_output(
                archive_adapter.stack_ghc_version(oracle_source),
                "ghc",
            )?),
        );
    }
    Ok(identities)
}

fn tool_output(command: CommandSpec, label: &str) -> Result<String, String> {
    let result = command
        .run()
        .map_err(|error| format!("cannot identify {label}: {error}"))?;
    if !result.status.success() || result.timed_out {
        let stderr = String::from_utf8_lossy(&result.stderr);
        let stderr = stderr.chars().take(512).collect::<String>();
        return Err(format!(
            "{label} identity command failed with status {:?}, timedOut={}, stderr={stderr:?}",
            result.status.code(),
            result.timed_out
        ));
    }
    let value = std::str::from_utf8(&result.stdout)
        .map_err(|_| format!("{label} identity is not UTF-8"))?
        .trim()
        .to_owned();
    if value.is_empty() {
        return Err(format!("{label} identity is empty"));
    }
    Ok(value)
}

fn validate_checkout(root: &Path, plan: &ReleasePlan) -> Result<(), String> {
    let observed = git_head(root)?;
    if observed != plan.resolution.candidate_sha {
        return Err("platform candidate checkout differs from plan".to_owned());
    }
    Ok(())
}

fn require_clean_checkout(root: &Path, expected_sha: &str, label: &str) -> Result<(), String> {
    require_clean_checkout_except(root, expected_sha, None, label)
}

#[cfg(unix)]
fn require_clean_checkout_before(
    root: &Path,
    expected_sha: &str,
    label: &str,
    deadline: Instant,
) -> Result<(), String> {
    if git_head_before(root, deadline)? != expected_sha {
        return Err(format!("{label} checkout differs from its bound commit"));
    }
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| format!("{label} checkout attestation deadline expired"))?;
    let result = CommandSpec::new("git", remaining)
        .git_safe_directory(root)
        .arguments(["status", "--porcelain=v1"])
        .arguments(["--untracked-files=all", "--ignored=matching"])
        .current_directory(root)
        .run()
        .map_err(|error| format!("cannot inspect {label} checkout: {error}"))?;
    if !result.status.success() || result.timed_out || !result.stdout.is_empty() {
        return Err(format!("{label} checkout is not an exact clean snapshot"));
    }
    Ok(())
}

fn require_clean_checkout_except(
    root: &Path,
    expected_sha: &str,
    excluded: Option<&Path>,
    label: &str,
) -> Result<(), String> {
    if git_head(root)? != expected_sha {
        return Err(format!("{label} checkout differs from its bound commit"));
    }
    let mut command = CommandSpec::new("git", Duration::from_secs(30))
        .git_safe_directory(root)
        .arguments(["status", "--porcelain=v1"])
        .arguments(["--untracked-files=all", "--ignored=matching"]);
    if let Some(excluded) = excluded {
        if excluded.parent() != Some(root)
            || excluded.file_name() != Some(std::ffi::OsStr::new(".stack-work"))
        {
            return Err(format!("{label} checkout exclusion differs from policy"));
        }
        command = command.arguments(["--", ".", ":(top,exclude,literal).stack-work"]);
    }
    let result = command
        .current_directory(root)
        .run()
        .map_err(|error| format!("cannot inspect {label} checkout: {error}"))?;
    if !result.status.success() || result.timed_out || !result.stdout.is_empty() {
        return Err(format!("{label} checkout is not an exact clean snapshot"));
    }
    Ok(())
}

fn require_inventory_snapshot(
    root: &Path,
    expected: &JsonValue,
    label: &str,
) -> Result<(), String> {
    let files = json_member(expected.object()?, "files")?.array()?;
    for file in files {
        let file = file.object()?;
        let relative = json_member(file, "path")?.string()?;
        let expected_size = json_member(file, "size")?.number()?;
        let expected_sha256 = json_member(file, "sha256")?.string()?;
        let path = root.join(relative);
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot inspect {label} file {relative:?}: {error}"))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() != expected_size
            || hell_testkit::sha256_file(&path)
                .map_err(|error| format!("cannot hash {label} file {relative:?}: {error}"))?
                .hex()
                != expected_sha256
        {
            return Err(format!(
                "{label} file {relative:?} differs from bound inventory"
            ));
        }
    }
    Ok(())
}

fn validate_runner(platform: ReleasePlatform) -> Result<(String, String), String> {
    let runner_os = env::var("RUNNER_OS").ok();
    let runner_arch = env::var("RUNNER_ARCH").ok();
    validate_runner_identity(
        platform,
        runner_os.as_deref(),
        runner_arch.as_deref(),
        env::consts::OS,
        env::consts::ARCH,
    )
}

fn validate_runner_identity(
    platform: ReleasePlatform,
    runner_os: Option<&str>,
    runner_arch: Option<&str>,
    host_os: &str,
    host_arch: &str,
) -> Result<(String, String), String> {
    let expected = platform.runner();
    match (runner_os, runner_arch) {
        (Some(os), Some(arch)) if (os, arch) == expected => Ok((os.to_owned(), arch.to_owned())),
        (None, None) if (host_os, host_arch) == platform_host(platform) => {
            Ok((expected.0.to_owned(), expected.1.to_owned()))
        }
        _ => Err(format!("runner identity does not match {}", platform.id())),
    }
}

const fn platform_host(platform: ReleasePlatform) -> (&'static str, &'static str) {
    match platform {
        ReleasePlatform::LinuxX86_64 => ("linux", "x86_64"),
        ReleasePlatform::MacosAarch64 => ("macos", "aarch64"),
        ReleasePlatform::WindowsX86_64 => ("windows", "x86_64"),
    }
}

fn git_head(root: &Path) -> Result<String, String> {
    let result = CommandSpec::new("git", Duration::from_secs(30))
        .git_safe_directory(root)
        .arguments(["rev-parse", "HEAD"])
        .current_directory(root)
        .run()
        .map_err(|error| format!("cannot verify checkout: {error}"))?;
    if !result.status.success() || result.timed_out {
        return Err("git checkout identity command failed".to_owned());
    }
    Ok(std::str::from_utf8(&result.stdout)
        .map_err(|_| "checkout HEAD is not UTF-8".to_owned())?
        .trim()
        .to_owned())
}

#[cfg(unix)]
fn git_head_before(root: &Path, deadline: Instant) -> Result<String, String> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| "git checkout identity deadline expired".to_owned())?;
    let result = CommandSpec::new("git", remaining)
        .git_safe_directory(root)
        .arguments(["rev-parse", "HEAD"])
        .current_directory(root)
        .run()
        .map_err(|error| format!("cannot verify checkout: {error}"))?;
    if !result.status.success() || result.timed_out {
        return Err("git checkout identity command failed".to_owned());
    }
    Ok(std::str::from_utf8(&result.stdout)
        .map_err(|_| "checkout HEAD is not UTF-8".to_owned())?
        .trim()
        .to_owned())
}

#[cfg(test)]
mod tests {
    use super::{
        SUITE_FAILURE_DETAIL_BYTE_LIMIT, accept_conformance_plan_binding, release_candidate_build,
        suite_failure, suite_gate, validate_runner_identity, windows_confinement_icacls_grants,
        windows_restricted_adapter_path,
    };
    use crate::release::schema::ReleasePlatform;
    use crate::release_suite::FailureKind;
    use crate::report::Report;

    fn synthetic_repository_policy_failure(
        _root: &std::path::Path,
        report: &mut Report,
        _failures: &std::path::Path,
    ) -> Result<(), FailureKind> {
        report.check(
            "release-assurance-policy",
            std::time::Duration::ZERO,
            Err(
                "tracked text file lacks a trailing newline: fixtures/policy-breach.toml"
                    .to_owned(),
            ),
        );
        Err(FailureKind::Policy)
    }

    #[test]
    fn suite_gate_preserves_repository_policy_failure_detail() {
        let mut gates = std::collections::BTreeMap::new();
        let mut evidence = std::collections::BTreeMap::new();
        let error = suite_gate(
            "verify",
            std::path::Path::new("candidate"),
            std::path::Path::new("output"),
            synthetic_repository_policy_failure,
            &mut gates,
            &mut evidence,
        )
        .unwrap_err();

        assert_eq!(
            error,
            "release gate verify failed: Policy; failure[0]: \"release-assurance-policy: tracked text file lacks a trailing newline: fixtures/policy-breach.toml\""
        );
        assert!(gates.is_empty());
        assert!(evidence.is_empty());
    }

    #[test]
    fn suite_failure_detail_is_bounded_and_digest_identified() {
        let detail = "policy violation\n".repeat(SUITE_FAILURE_DETAIL_BYTE_LIMIT);
        let mut report = Report::new("verify");
        report.check(
            "release-assurance-policy",
            std::time::Duration::ZERO,
            Err(detail.clone()),
        );

        let error = suite_failure("verify", FailureKind::Policy, &report);
        let sha256 = hell_testkit::sha256_bytes(report.failures[0].as_bytes()).hex();
        assert!(error.contains("failure[0]:"));
        assert!(error.contains("[truncated; bytes="));
        assert!(error.contains(&format!("sha256={sha256}]")));
        assert!(!error.contains(&detail));
    }

    #[cfg(unix)]
    use super::{
        LINUX_ORACLE_NAME, LinuxOracleAcquisition, POSIX_TRANSIENT_AUTHORITY_TRANSITIONS,
        PosixAdapterToolPaths, PosixTransientAuthorityTransition, build_dependency_policy_result,
        configure_staged_cargo_home_directory_source, copy_posix_cargo_cache_tree,
        normalize_candidate_cache_tree, normalize_cargo_deny_cache_tree,
        posix_acl_removal_arguments, posix_adapter_authority_chain, posix_adapter_cleanup_is_exact,
        posix_adapter_installation_root, posix_adapter_tool_paths, posix_candidate_group_inventory,
        posix_candidate_identity_output_is_exact, posix_cargo_deny_home_is_exact,
        posix_cargo_deny_metadata_is_exact, posix_chmod_arguments, posix_rustup_cleanup_is_exact,
        posix_rustup_inventory_cost, posix_rustup_selected_inventory,
        posix_source_cleanup_is_exact, posix_stack_root_is_exact, posix_stack_work_is_exact,
        remove_staged_cargo_package_fallback, replace_final_home_cargo_deny_metadata,
        require_exact_directory_members, require_inventory_snapshot,
        reserve_posix_cargo_deny_advisory_lock, run_posix_stack_work_normalizer,
        staged_cargo_vendor_root, trusted_cargo_cache_fetch_arguments,
        trusted_cargo_cache_metadata_arguments, trusted_cargo_cache_offline_metadata_arguments,
        trusted_cargo_cache_seed_arguments, trusted_cargo_deny_authority_arguments,
        trusted_cargo_vendor_arguments, validate_candidate_cache_normalizer_root,
        validate_posix_adapter_installation_root, validate_posix_cargo_deny_home_post_state,
        validate_posix_cargo_deny_home_root, validate_staged_cargo_metadata,
        validate_staged_vendor_covers_frozen_lock, verify_dependency_policy_result,
    };
    #[cfg(target_os = "macos")]
    use super::{
        normalize_candidate_owned_cache_tree, validate_posix_stack_root,
        validate_posix_stack_root_post_state,
    };
    #[cfg(unix)]
    use std::path::Path;

    #[cfg(unix)]
    #[test]
    fn trusted_cargo_cache_seed_is_locked_and_manifest_scoped() {
        use std::ffi::OsString;

        let manifest = Path::new("/bound/candidate/Cargo.toml");
        assert_eq!(
            trusted_cargo_cache_seed_arguments(Path::new("/bound/candidate"), manifest).unwrap(),
            [
                "fetch".into(),
                "--locked".into(),
                "--manifest-path".into(),
                manifest.as_os_str().to_owned(),
            ]
        );
        assert_eq!(
            trusted_cargo_cache_metadata_arguments(Path::new("/bound/candidate"), manifest)
                .unwrap(),
            [
                "metadata".into(),
                "--locked".into(),
                "--all-features".into(),
                "--format-version".into(),
                "1".into(),
                "--manifest-path".into(),
                manifest.as_os_str().to_owned(),
            ]
        );
        assert_eq!(
            trusted_cargo_cache_offline_metadata_arguments(Path::new("/bound/candidate"), manifest)
                .unwrap(),
            [
                "metadata".into(),
                "--locked".into(),
                "--offline".into(),
                "--all-features".into(),
                "--format-version".into(),
                "1".into(),
                "--manifest-path".into(),
                manifest.as_os_str().to_owned(),
            ]
        );
        assert_eq!(
            trusted_cargo_cache_fetch_arguments(Path::new("/bound/candidate"), manifest).unwrap(),
            [
                "fetch".into(),
                "--manifest-path".into(),
                manifest.as_os_str().to_owned(),
                "--frozen".into(),
                "--locked".into(),
                "--offline".into(),
            ]
        );
        let cargo_home = Path::new("/private/var/tmp/hell-cargo-seed-1-2");
        let authority_metadata = cargo_home.join("hell-cargo-deny-metadata.json");
        assert_eq!(
            trusted_cargo_deny_authority_arguments(cargo_home, &authority_metadata).unwrap(),
            [
                "--metadata-path".into(),
                authority_metadata.as_os_str().to_owned(),
                "--all-features".into(),
                "check".into(),
                "advisories".into(),
                "bans".into(),
                "licenses".into(),
                "sources".into(),
            ]
        );
        let trusted_arguments =
            trusted_cargo_deny_authority_arguments(cargo_home, &authority_metadata).unwrap();
        assert!(trusted_arguments.contains(&OsString::from("advisories")));
        assert!(trusted_arguments.contains(&OsString::from("bans")));
        assert!(trusted_arguments.contains(&OsString::from("licenses")));
        assert!(trusted_arguments.contains(&OsString::from("sources")));
        assert!(
            !trusted_cargo_deny_authority_arguments(cargo_home, &authority_metadata)
                .unwrap()
                .iter()
                .any(|argument| argument == "--offline")
        );
        assert!(
            trusted_cargo_deny_authority_arguments(
                cargo_home,
                &cargo_home.join("unbound-metadata.json")
            )
            .is_err()
        );
        assert_eq!(
            trusted_cargo_vendor_arguments(
                Path::new("/bound/candidate"),
                manifest,
                Path::new("/private/var/tmp/hell-cargo-seed-1-2"),
                &staged_cargo_vendor_root(Path::new("/private/var/tmp/hell-cargo-seed-1-2")),
            )
            .unwrap(),
            [
                "vendor".into(),
                "--locked".into(),
                "--versioned-dirs".into(),
                "--manifest-path".into(),
                manifest.as_os_str().to_owned(),
                "/private/var/tmp/hell-cargo-seed-1-2/vendor/index.crates.io-6f17d22bba15001f"
                    .into(),
            ]
        );
        assert!(
            trusted_cargo_cache_seed_arguments(Path::new("bound/candidate"), manifest).is_err()
        );
        assert!(
            trusted_cargo_cache_metadata_arguments(Path::new("bound/candidate"), manifest).is_err()
        );
        assert!(
            trusted_cargo_cache_fetch_arguments(Path::new("bound/candidate"), manifest).is_err()
        );
        assert!(
            trusted_cargo_cache_fetch_arguments(
                Path::new("/bound/candidate"),
                Path::new("/bound/Cargo.lock")
            )
            .is_err()
        );
        assert!(
            trusted_cargo_cache_seed_arguments(
                Path::new("/bound/candidate"),
                Path::new("/bound/Cargo.lock")
            )
            .is_err()
        );
        assert!(
            trusted_cargo_cache_metadata_arguments(
                Path::new("/bound/candidate"),
                Path::new("/bound/Cargo.lock")
            )
            .is_err()
        );
        assert!(
            trusted_cargo_vendor_arguments(
                Path::new("/bound/candidate"),
                manifest,
                Path::new("/private/var/tmp/hell-cargo-seed-1-2"),
                Path::new("/private/var/tmp/other/vendor"),
            )
            .is_err()
        );

        let home = std::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "hell-cargo-directory-source-{}",
                std::process::id()
            ));
        let source = staged_cargo_vendor_root(&home);
        let package = source.join("known-folders-1.4.2");
        std::fs::create_dir_all(&package).unwrap();
        std::fs::write(package.join(".cargo-checksum.json"), b"{}\n").unwrap();
        configure_staged_cargo_home_directory_source(&home).unwrap();
        assert_eq!(
            std::fs::read_to_string(home.join("config.toml")).unwrap(),
            format!(
                "[source.crates-io]\nreplace-with = 'hell-staged-registry'\n\n[source.hell-staged-registry]\ndirectory = '{}'\n",
                source.display()
            )
        );
        assert!(configure_staged_cargo_home_directory_source(&home).is_err());
        std::fs::remove_dir_all(home).unwrap();
    }

    #[cfg(unix)]
    fn staged_metadata_fixture(
        candidate: &Path,
        home: &Path,
        registry_manifest: &Path,
    ) -> crate::json::JsonValue {
        use crate::json::JsonValue;
        use std::collections::BTreeMap;

        let workspace_id = "path+file:///candidate/member#0.1.0";
        JsonValue::Object(BTreeMap::from([
            (
                "packages".to_owned(),
                JsonValue::Array(vec![
                    JsonValue::Object(BTreeMap::from([
                        ("id".to_owned(), JsonValue::String(workspace_id.to_owned())),
                        (
                            "manifest_path".to_owned(),
                            JsonValue::String(
                                candidate.join("member/Cargo.toml").display().to_string(),
                            ),
                        ),
                        ("source".to_owned(), JsonValue::Null),
                    ])),
                    JsonValue::Object(BTreeMap::from([
                        (
                            "id".to_owned(),
                            JsonValue::String("registry+reviewed#1.0.0".to_owned()),
                        ),
                        (
                            "manifest_path".to_owned(),
                            JsonValue::String(registry_manifest.display().to_string()),
                        ),
                        (
                            "source".to_owned(),
                            JsonValue::String("registry+reviewed".to_owned()),
                        ),
                    ])),
                ]),
            ),
            (
                "target_directory".to_owned(),
                JsonValue::String(home.join("target").display().to_string()),
            ),
            ("version".to_owned(), JsonValue::Number(1)),
            (
                "workspace_default_members".to_owned(),
                JsonValue::Array(vec![JsonValue::String(workspace_id.to_owned())]),
            ),
            (
                "workspace_members".to_owned(),
                JsonValue::Array(vec![JsonValue::String(workspace_id.to_owned())]),
            ),
            (
                "workspace_root".to_owned(),
                JsonValue::String(candidate.display().to_string()),
            ),
            (
                "x-fixture-home".to_owned(),
                JsonValue::String(home.display().to_string()),
            ),
        ]))
    }

    #[cfg(unix)]
    #[test]
    fn staged_cargo_metadata_binds_schema_workspace_and_package_paths() {
        use crate::json::{JsonValue, canonical_json_bytes};

        let root = std::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("hell-cargo-metadata-{}", std::process::id()));
        let candidate = root.join("candidate");
        let home = root.join("home");
        let workspace_manifest = candidate.join("member/Cargo.toml");
        let registry_manifest = staged_cargo_vendor_root(&home).join("reviewed-1.0.0/Cargo.toml");
        std::fs::create_dir_all(workspace_manifest.parent().unwrap()).unwrap();
        std::fs::create_dir_all(registry_manifest.parent().unwrap()).unwrap();
        std::fs::write(
            &workspace_manifest,
            b"[package]\nname='member'\nversion='0.1.0'\n",
        )
        .unwrap();
        std::fs::write(
            &registry_manifest,
            b"[package]\nname='reviewed'\nversion='1.0.0'\n",
        )
        .unwrap();
        let valid = staged_metadata_fixture(&candidate, &home, &registry_manifest);
        validate_staged_cargo_metadata(&canonical_json_bytes(&valid).unwrap(), &candidate, &home)
            .unwrap();

        let JsonValue::Object(mut wrong_workspace) = valid.clone() else {
            unreachable!();
        };
        wrong_workspace.insert(
            "workspace_root".to_owned(),
            JsonValue::String(root.join("other").display().to_string()),
        );
        assert!(
            validate_staged_cargo_metadata(
                &canonical_json_bytes(&JsonValue::Object(wrong_workspace)).unwrap(),
                &candidate,
                &home,
            )
            .is_err()
        );

        let escaped = staged_metadata_fixture(&candidate, &home, &workspace_manifest);
        assert!(
            validate_staged_cargo_metadata(
                &canonical_json_bytes(&escaped).unwrap(),
                &candidate,
                &home,
            )
            .is_err()
        );
        assert!(validate_staged_cargo_metadata(b"not-json\n", &candidate, &home).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn staged_vendor_closure_covers_every_frozen_registry_package() {
        let root = std::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("hell-frozen-vendor-closure-{}", std::process::id()));
        let vendor = staged_cargo_vendor_root(&root);
        for package in ["flate2-1.1.9", "nix-0.27.1", "winapi-0.3.9"] {
            let package = vendor.join(package);
            std::fs::create_dir_all(&package).unwrap();
            std::fs::write(package.join(".cargo-checksum.json"), b"{}\n").unwrap();
        }
        let lock = "\
version = 4\n\
\n\
[[package]]\n\
name = \"hell-ci\"\n\
version = \"0.1.0\"\n\
dependencies = [\n\
 \"flate2\",\n\
]\n\
\n\
[[package]]\n\
name = \"flate2\"\n\
version = \"1.1.9\"\n\
source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
checksum = \"bound\"\n\
\n\
[[package]]\n\
name = \"nix\"\n\
version = \"0.27.1\"\n\
source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
\n\
[[package]]\n\
name = \"winapi\"\n\
version = \"0.3.9\"\n\
source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
";
        validate_staged_vendor_covers_frozen_lock(lock.as_bytes(), &vendor).unwrap();

        std::fs::remove_dir_all(vendor.join("flate2-1.1.9")).unwrap();
        let error = validate_staged_vendor_covers_frozen_lock(lock.as_bytes(), &vendor)
            .expect_err("missing frozen package must fail closed");
        assert!(error.contains("flate2-1.1.9"), "{error}");

        assert!(validate_staged_vendor_covers_frozen_lock(b"", &vendor).is_err());
        assert!(
            validate_staged_vendor_covers_frozen_lock(
                b"[[package]]\nname = \"workspace-only\"\nversion = \"0.1.0\"\n",
                &vendor
            )
            .is_err()
        );
        assert!(
            validate_staged_vendor_covers_frozen_lock(
                b"[[package]]\nname = \"traversal/attempt\"\nversion = \"1\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n",
                &vendor
            )
            .is_err()
        );

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn staged_sparse_directory_source_has_no_package_fallback() {
        let root = std::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "hell-sparse-cargo-source-{}-{}",
                std::process::id(),
                std::thread::current().name().unwrap_or("test")
            ));
        let home = root.join("home");
        let registry_index = home.join("registry/index/index.crates.io-test");
        let registry_cache = home.join("registry/cache/index.crates.io-test");
        let registry_source = home.join("registry/src/index.crates.io-test");
        let vendor = staged_cargo_vendor_root(&home);
        std::fs::create_dir_all(&registry_index).unwrap();
        std::fs::create_dir_all(&registry_cache).unwrap();
        std::fs::create_dir_all(&registry_source).unwrap();
        std::fs::write(registry_index.join("config.json"), b"index\n").unwrap();
        std::fs::write(
            registry_cache.join("flate2-1.1.9.crate"),
            b"fallback package\n",
        )
        .unwrap();
        std::fs::create_dir_all(registry_source.join("flate2-1.1.9")).unwrap();
        std::fs::write(
            registry_source.join("flate2-1.1.9/.cargo-checksum.json"),
            b"{}\n",
        )
        .unwrap();
        std::fs::create_dir_all(vendor.join("nix-0.27.1")).unwrap();
        std::fs::write(vendor.join("nix-0.27.1/.cargo-checksum.json"), b"{}\n").unwrap();

        remove_staged_cargo_package_fallback(&home).unwrap();
        assert!(registry_index.join("config.json").is_file());
        assert!(!registry_cache.exists());
        assert!(!registry_source.exists());

        let lock = "\
version = 4\n\
\n\
[[package]]\n\
name = \"hell-ci\"\n\
version = \"0.1.0\"\n\
\n\
[[package]]\n\
name = \"flate2\"\n\
version = \"1.1.9\"\n\
source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
";
        let error = validate_staged_vendor_covers_frozen_lock(lock.as_bytes(), &vendor)
            .expect_err("removed package fallback must not satisfy offline resolution");
        assert!(error.contains("flate2-1.1.9"), "{error}");

        let advisory_lock = reserve_posix_cargo_deny_advisory_lock(&home).unwrap();
        std::fs::create_dir_all(&registry_cache).unwrap();
        assert!(
            validate_posix_cargo_deny_home_post_state(&home, 61_001, 1_001, 1_000, &advisory_lock,)
                .is_err()
        );
        std::fs::remove_dir_all(&registry_cache).unwrap();
        std::fs::create_dir_all(&registry_source).unwrap();
        assert!(
            validate_posix_cargo_deny_home_post_state(&home, 61_001, 1_001, 1_000, &advisory_lock,)
                .is_err()
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn staged_cargo_directory_source_rejects_incomplete_or_redirected_vendors() {
        use std::os::unix::fs::symlink;

        let temp = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        let root = temp.join(format!(
            "hell-cargo-directory-source-invalid-{}",
            std::process::id()
        ));
        let empty = root.join("empty");
        std::fs::create_dir_all(&empty).unwrap();
        assert!(configure_staged_cargo_home_directory_source(&empty).is_err());

        let empty_vendor = root.join("empty-vendor");
        std::fs::create_dir_all(staged_cargo_vendor_root(&empty_vendor)).unwrap();
        assert!(configure_staged_cargo_home_directory_source(&empty_vendor).is_err());

        let missing_checksum = root.join("missing-checksum");
        std::fs::create_dir_all(staged_cargo_vendor_root(&missing_checksum).join("package-1.0.0"))
            .unwrap();
        assert!(configure_staged_cargo_home_directory_source(&missing_checksum).is_err());

        let redirected = root.join("redirected");
        let outside = root.join("outside");
        std::fs::create_dir_all(&redirected).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::fs::create_dir(redirected.join("vendor")).unwrap();
        symlink(
            &outside,
            redirected
                .join("vendor")
                .join("index.crates.io-6f17d22bba15001f"),
        )
        .unwrap();
        assert!(configure_staged_cargo_home_directory_source(&redirected).is_err());

        let unsafe_path = root.join("unsafe'path");
        let unsafe_package = staged_cargo_vendor_root(&unsafe_path).join("package-1.0.0");
        std::fs::create_dir_all(&unsafe_package).unwrap();
        std::fs::write(unsafe_package.join(".cargo-checksum.json"), b"{}\n").unwrap();
        assert!(configure_staged_cargo_home_directory_source(&unsafe_path).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn candidate_identity_output_binds_canonical_supplementary_groups() {
        assert!(posix_candidate_identity_output_is_exact(b"61001\n", 61_001));
        assert!(!posix_candidate_identity_output_is_exact(b"61001", 61_001));
        assert!(!posix_candidate_identity_output_is_exact(
            b"061001\n",
            61_001
        ));
        assert_eq!(
            posix_candidate_group_inventory(b"61001 20 701 100\n", 61_001),
            Some(vec![61_001, 20, 701, 100])
        );
        assert_eq!(
            posix_candidate_group_inventory(b"20 61001 701 100\n", 61_001),
            Some(vec![20, 61_001, 701, 100])
        );
        for invalid in [
            b"".as_slice(),
            b"61001".as_slice(),
            b"061001 20\n".as_slice(),
            b"61001  20\n".as_slice(),
            b"61001 20 61001\n".as_slice(),
            b"20 701\n".as_slice(),
            b"61001\t20\n".as_slice(),
            b"61001 20\n\n".as_slice(),
        ] {
            assert!(posix_candidate_group_inventory(invalid, 61_001).is_none());
        }
        let group_limit = u32::try_from(hell_testkit::POSIX_CANDIDATE_GROUP_LIMIT).unwrap();
        let oversized = (0..group_limit)
            .chain(std::iter::once(61_001))
            .map(|group| group.to_string())
            .collect::<Vec<_>>()
            .join(" ")
            + "\n";
        assert!(posix_candidate_group_inventory(oversized.as_bytes(), 61_001).is_none());
    }

    #[test]
    fn candidate_conformance_plan_substitution_is_rejected() {
        assert!(accept_conformance_plan_binding(true));
        assert!(!accept_conformance_plan_binding(false));
    }

    #[test]
    fn runner_identity_accepts_exact_hosted_or_local_identity() {
        assert_eq!(
            validate_runner_identity(
                ReleasePlatform::MacosAarch64,
                Some("macOS"),
                Some("ARM64"),
                "untrusted",
                "untrusted",
            )
            .unwrap(),
            ("macOS".to_owned(), "ARM64".to_owned())
        );
        assert_eq!(
            validate_runner_identity(
                ReleasePlatform::MacosAarch64,
                None,
                None,
                "macos",
                "aarch64",
            )
            .unwrap(),
            ("macOS".to_owned(), "ARM64".to_owned())
        );
    }

    #[cfg(unix)]
    #[test]
    fn linux_dependency_policy_gate_does_not_spawn_cargo_deny() {
        let source = include_str!("platform.rs");
        assert!(!source.contains(&["fn candidate_cargo_", "deny_arguments",].concat()));
        let start = source
            .find("if platform == ReleasePlatform::LinuxX86_64 {\n        let (policy, cargo_deny_home)")
            .expect("Linux dependency-policy gate marker");
        let end = source[start..]
            .find("in_process_gate(\n            \"conformance-policy\"")
            .map(|offset| start + offset)
            .expect("Linux conformance gate marker");
        let gate = &source[start..end];
        assert!(
            !gate.contains("CommandSpec::cargo_deny"),
            "candidate dependency-policy gate must verify the trusted result without spawning cargo-deny"
        );
        assert!(gate.contains("verify_dependency_policy_result"));
    }

    #[cfg(unix)]
    #[test]
    fn final_home_metadata_policy_binds_one_captured_byte_stream() {
        use crate::json::canonical_json_bytes;

        let root = std::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("hell-final-metadata-policy-{}", std::process::id()));
        let candidate = root.join("candidate");
        let seed_home = root.join("seed-home");
        let final_home = root.join("final-home");
        let seed_registry = staged_cargo_vendor_root(&seed_home).join("reviewed-1.0.0/Cargo.toml");
        let final_registry =
            staged_cargo_vendor_root(&final_home).join("reviewed-1.0.0/Cargo.toml");
        std::fs::create_dir_all(candidate.join("member")).unwrap();
        std::fs::create_dir_all(seed_registry.parent().unwrap()).unwrap();
        std::fs::create_dir_all(final_registry.parent().unwrap()).unwrap();
        std::fs::write(
            candidate.join("member/Cargo.toml"),
            b"[package]\nname='member'\nversion='0.1.0'\n",
        )
        .unwrap();
        for (home, registry) in [(&seed_home, &seed_registry), (&final_home, &final_registry)] {
            std::fs::write(registry, b"[package]\nname='reviewed'\nversion='1.0.0'\n").unwrap();
            std::fs::write(
                registry.parent().unwrap().join(".cargo-checksum.json"),
                b"{}\n",
            )
            .unwrap();
            std::fs::write(home.join("config.toml"), b"[source]\n").unwrap();
        }
        std::fs::write(candidate.join("Cargo.toml"), b"[workspace]\n").unwrap();
        std::fs::write(candidate.join("Cargo.lock"), b"lock\n").unwrap();
        std::fs::write(candidate.join("deny.toml"), b"[advisories]\n").unwrap();

        let seed_metadata = canonical_json_bytes(&staged_metadata_fixture(
            &candidate,
            &seed_home,
            &seed_registry,
        ))
        .unwrap();
        let final_metadata = canonical_json_bytes(&staged_metadata_fixture(
            &candidate,
            &final_home,
            &final_registry,
        ))
        .unwrap();
        validate_staged_cargo_metadata(&seed_metadata, &candidate, &seed_home).unwrap();
        validate_staged_cargo_metadata(&final_metadata, &candidate, &final_home).unwrap();
        assert_ne!(seed_metadata, final_metadata);

        let metadata_path = final_home.join("hell-cargo-deny-metadata.json");
        std::fs::write(&metadata_path, &seed_metadata).unwrap();
        let captured =
            replace_final_home_cargo_deny_metadata(&candidate, &final_home, &final_metadata)
                .unwrap();
        assert_eq!(captured.bytes, final_metadata);
        assert_eq!(std::fs::read(&captured.path).unwrap(), final_metadata);
        assert_eq!(captured.sha256, hell_testkit::sha256_bytes(&final_metadata));

        let cargo_deny = hell_testkit::sha256_bytes(b"cargo-deny");
        let candidate_sha = "a".repeat(40);
        let seed_policy =
            build_dependency_policy_result(&candidate, &candidate_sha, &seed_metadata, cargo_deny)
                .unwrap();
        assert!(
            verify_dependency_policy_result(
                &seed_policy,
                &candidate,
                &candidate_sha,
                &captured.sha256,
                &cargo_deny,
            )
            .is_err(),
            "temporary-seed metadata must not verify against retained final-home metadata"
        );

        let final_policy =
            build_dependency_policy_result(&candidate, &candidate_sha, &captured.bytes, cargo_deny)
                .unwrap();
        verify_dependency_policy_result(
            &final_policy,
            &candidate,
            &candidate_sha,
            &captured.sha256,
            &cargo_deny,
        )
        .unwrap();

        let mut semantically_same_metadata = Vec::with_capacity(final_metadata.len() + 2);
        semantically_same_metadata.push(b' ');
        semantically_same_metadata.extend_from_slice(&final_metadata);
        semantically_same_metadata.push(b'\n');
        validate_staged_cargo_metadata(&semantically_same_metadata, &candidate, &final_home)
            .unwrap();
        assert!(
            verify_dependency_policy_result(
                &final_policy,
                &candidate,
                &candidate_sha,
                &hell_testkit::sha256_bytes(&semantically_same_metadata),
                &cargo_deny,
            )
            .is_err(),
            "metadata identity must remain byte-exact rather than semantic"
        );

        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn dependency_policy_result_rejects_identity_config_and_category_drift() {
        let root = std::env::temp_dir().join(format!(
            "hell-dependency-policy-drift-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("Cargo.toml"), b"[workspace]\n").unwrap();
        std::fs::write(root.join("Cargo.lock"), b"lock\n").unwrap();
        std::fs::write(root.join("deny.toml"), b"[advisories]\n").unwrap();
        let metadata = b"bound metadata";
        let cargo_deny = hell_testkit::sha256_bytes(b"cargo-deny");
        let candidate = "a".repeat(40);
        let document =
            build_dependency_policy_result(&root, &candidate, metadata, cargo_deny).unwrap();
        verify_dependency_policy_result(
            &document,
            &root,
            &candidate,
            &hell_testkit::sha256_bytes(metadata),
            &cargo_deny,
        )
        .unwrap();

        let crate::json::JsonValue::Object(mut forged_object) =
            crate::json::parse_json(String::from_utf8(document.clone()).unwrap().as_str()).unwrap()
        else {
            panic!("dependency-policy result must be an object");
        };
        forged_object.insert(
            "candidateSourceCommit".to_owned(),
            crate::json::JsonValue::String("b".repeat(40)),
        );
        let forged =
            crate::json::canonical_json_bytes(&crate::json::JsonValue::Object(forged_object))
                .unwrap();
        assert!(
            verify_dependency_policy_result(
                &forged,
                &root,
                &candidate,
                &hell_testkit::sha256_bytes(metadata),
                &cargo_deny,
            )
            .is_err()
        );

        let crate::json::JsonValue::Object(mut partial_object) =
            crate::json::parse_json(String::from_utf8(document.clone()).unwrap().as_str()).unwrap()
        else {
            panic!("dependency-policy result must be an object");
        };
        let crate::json::JsonValue::Array(mut categories) =
            partial_object.remove("categories").unwrap()
        else {
            panic!("dependency-policy categories must be an array");
        };
        categories.remove(1);
        partial_object.insert(
            "categories".to_owned(),
            crate::json::JsonValue::Array(categories),
        );
        let partial =
            crate::json::canonical_json_bytes(&crate::json::JsonValue::Object(partial_object))
                .unwrap();
        assert!(
            verify_dependency_policy_result(
                &partial,
                &root,
                &candidate,
                &hell_testkit::sha256_bytes(metadata),
                &cargo_deny,
            )
            .is_err()
        );

        std::fs::write(root.join("deny.toml"), b"[advisories-v2]\n").unwrap();
        assert!(
            verify_dependency_policy_result(
                &document,
                &root,
                &candidate,
                &hell_testkit::sha256_bytes(metadata),
                &cargo_deny,
            )
            .is_err()
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn runner_identity_rejects_partial_or_mismatched_identity() {
        assert!(
            validate_runner_identity(
                ReleasePlatform::MacosAarch64,
                Some("macOS"),
                None,
                "macos",
                "aarch64",
            )
            .is_err()
        );
        assert!(
            validate_runner_identity(ReleasePlatform::MacosAarch64, None, None, "linux", "x86_64",)
                .is_err()
        );
    }

    #[test]
    fn release_candidate_build_enables_required_evidence() {
        let command = release_candidate_build(std::path::Path::new("candidate"));
        assert_eq!(
            command.display_arguments(),
            [
                "build",
                "--release",
                "--locked",
                "--package",
                "hell-cli",
                "--bin",
                "hell",
                "--features",
                "compat-tracing",
            ]
        );
    }

    #[test]
    fn windows_confinement_dacl_rights_are_closed_world() {
        assert_eq!(
            windows_confinement_icacls_grants(false, true),
            [
                "*S-1-5-32-544:(OI)(CI)(F)",
                "*S-1-5-18:(OI)(CI)(F)",
                "*S-1-5-11:(OI)(CI)(RX)",
                "*S-1-5-12:(OI)(CI)(RX)",
            ]
        );
        assert_eq!(
            windows_confinement_icacls_grants(true, true),
            [
                "*S-1-5-32-544:(OI)(CI)(F)",
                "*S-1-5-18:(OI)(CI)(F)",
                "*S-1-5-11:(OI)(CI)(F)",
                "*S-1-5-12:(OI)(CI)(F)",
            ]
        );
        assert_eq!(
            windows_confinement_icacls_grants(false, false),
            [
                "*S-1-5-32-544:(F)",
                "*S-1-5-18:(F)",
                "*S-1-5-11:(RX)",
                "*S-1-5-12:(RX)",
            ]
        );
        assert_eq!(
            windows_confinement_icacls_grants(true, false),
            [
                "*S-1-5-32-544:(F)",
                "*S-1-5-18:(F)",
                "*S-1-5-11:(F)",
                "*S-1-5-12:(F)",
            ]
        );
    }

    #[test]
    fn windows_restricted_adapter_is_the_exact_sibling_minimal_executable() {
        let launcher = std::path::Path::new("C:/trusted/ci/hell-ci.exe");
        assert_eq!(
            windows_restricted_adapter_path(launcher).unwrap(),
            std::path::Path::new("C:/trusted/ci/hell-test-helper.exe")
        );
        assert!(
            windows_restricted_adapter_path(std::path::Path::new("C:/trusted/ci/substituted.exe"))
                .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn posix_adapter_authority_uses_fixed_platform_tools_and_exact_cleanup_scope() {
        assert_eq!(
            posix_adapter_tool_paths(ReleasePlatform::LinuxX86_64).unwrap(),
            PosixAdapterToolPaths {
                mkdir: "/usr/bin/mkdir",
                copy: "/usr/bin/cp",
                chmod: "/usr/bin/chmod",
                change_owner: "/usr/bin/chown",
                change_group: "/usr/bin/chgrp",
                remove_file: "/usr/bin/rm",
                remove_directory: "/usr/bin/rmdir",
            }
        );
        assert_eq!(
            posix_adapter_tool_paths(ReleasePlatform::MacosAarch64).unwrap(),
            PosixAdapterToolPaths {
                mkdir: "/bin/mkdir",
                copy: "/bin/cp",
                chmod: "/bin/chmod",
                change_owner: "/usr/sbin/chown",
                change_group: "/usr/bin/chgrp",
                remove_file: "/bin/rm",
                remove_directory: "/bin/rmdir",
            }
        );
        assert!(posix_adapter_tool_paths(ReleasePlatform::WindowsX86_64).is_err());
        assert_eq!(
            posix_adapter_authority_chain(ReleasePlatform::LinuxX86_64).unwrap(),
            ["/", "/var", "/var/tmp"]
        );
        assert_eq!(
            posix_adapter_authority_chain(ReleasePlatform::MacosAarch64).unwrap(),
            ["/", "/private", "/private/var", "/private/var/tmp"]
        );
        assert_eq!(
            posix_chmod_arguments(ReleasePlatform::LinuxX86_64, "0555", "/bound").unwrap(),
            ["0555", "--", "/bound"]
        );
        assert_eq!(
            posix_chmod_arguments(ReleasePlatform::MacosAarch64, "0555", "/bound").unwrap(),
            ["0555", "/bound"]
        );
        assert!(posix_chmod_arguments(ReleasePlatform::WindowsX86_64, "0555", "/bound").is_err());
        assert_eq!(
            POSIX_TRANSIENT_AUTHORITY_TRANSITIONS,
            [
                PosixTransientAuthorityTransition::ChangeOwner,
                PosixTransientAuthorityTransition::ChangeGroup,
                PosixTransientAuthorityTransition::RestoreMode03770,
            ]
        );
        assert_eq!(
            posix_acl_removal_arguments(ReleasePlatform::MacosAarch64, false, "/bound").unwrap(),
            ["-N", "/bound"]
        );
        assert_eq!(
            posix_acl_removal_arguments(ReleasePlatform::MacosAarch64, true, "/bound").unwrap(),
            ["-RN", "/bound"]
        );
        assert!(posix_acl_removal_arguments(ReleasePlatform::LinuxX86_64, true, "/bound").is_err());

        #[cfg(target_os = "linux")]
        let (current_platform, root) = (ReleasePlatform::LinuxX86_64, Path::new("/var/tmp"));
        #[cfg(target_os = "macos")]
        let (current_platform, root) =
            (ReleasePlatform::MacosAarch64, Path::new("/private/var/tmp"));
        assert_eq!(
            posix_adapter_installation_root(current_platform).unwrap(),
            root
        );
        assert!(
            validate_posix_adapter_installation_root(current_platform, &std::env::temp_dir())
                .is_err(),
            "an arbitrary writable temporary root must never become executable authority"
        );
        assert!(
            validate_posix_adapter_installation_root(ReleasePlatform::WindowsX86_64, root).is_err()
        );

        let directory = root.join("hell-rs-posix-adapter-bound");
        let adapter = directory.join("hell-ci");
        assert!(posix_adapter_cleanup_is_exact(
            root, &directory, &adapter, "hell-ci"
        ));
        assert!(!posix_adapter_cleanup_is_exact(
            root,
            Path::new("/usr/local"),
            &adapter,
            "hell-ci"
        ));
        assert!(!posix_adapter_cleanup_is_exact(
            root,
            &directory,
            &directory.join("other"),
            "hell-ci"
        ));
        assert!(!posix_adapter_cleanup_is_exact(
            root,
            &directory,
            &directory.join("nested/hell-ci"),
            "hell-ci"
        ));
        assert!(!posix_adapter_cleanup_is_exact(
            root, &directory, &adapter, "cargo"
        ));
        let cargo_deny_directory = root.join("hell-rs-posix-cargo-deny-bound");
        assert!(posix_adapter_cleanup_is_exact(
            root,
            &cargo_deny_directory,
            &cargo_deny_directory.join("cargo-deny"),
            "cargo-deny"
        ));
        let stack_directory = root.join("hell-rs-posix-stack-bound");
        assert!(posix_adapter_cleanup_is_exact(
            root,
            &stack_directory,
            &stack_directory.join("stack"),
            "stack"
        ));

        let sources = root.join("hell-rs-posix-sources-bound");
        let candidate = sources.join("candidate");
        let oracle = sources.join("oracle");
        let transient = sources.join("release-gate-transient");
        let archive_adapter = sources.join("archive-adapter");
        let retained_oracle = sources.join("retained-oracle");
        assert!(posix_source_cleanup_is_exact(
            root,
            &sources,
            &candidate,
            &oracle,
            &transient,
            &archive_adapter,
            &retained_oracle,
        ));
        assert!(!posix_source_cleanup_is_exact(
            root,
            Path::new("/usr/local/hell-rs-posix-sources-bound"),
            &candidate,
            &oracle,
            &transient,
            &archive_adapter,
            &retained_oracle,
        ));
        assert!(!posix_source_cleanup_is_exact(
            root,
            &sources,
            &sources.join("candidate/substituted"),
            &oracle,
            &transient,
            &archive_adapter,
            &retained_oracle,
        ));
        assert!(!posix_source_cleanup_is_exact(
            root,
            &sources,
            &candidate,
            &oracle,
            &sources.join("nested/release-gate-transient"),
            &archive_adapter,
            &retained_oracle,
        ));
        assert!(!posix_source_cleanup_is_exact(
            root,
            &sources,
            &candidate,
            &oracle,
            &transient,
            &sources.join("nested/archive-adapter"),
            &retained_oracle,
        ));
        assert!(!posix_source_cleanup_is_exact(
            root,
            &sources,
            &candidate,
            &oracle,
            &transient,
            &archive_adapter,
            &sources.join("nested/retained-oracle"),
        ));

        let rustup = root.join("hell-rs-posix-rustup-bound");
        assert!(posix_rustup_cleanup_is_exact(root, &rustup));
        assert!(!posix_rustup_cleanup_is_exact(
            root,
            &root.join("rustup-bound")
        ));
        assert!(!posix_rustup_cleanup_is_exact(root, &rustup.join("nested")));
    }

    #[cfg(unix)]
    #[test]
    fn rustup_staging_inventory_is_closed_bounded_and_link_free() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        use std::os::unix::net::UnixListener;

        let root = Path::new("/tmp").join(format!("hell-rustup-inventory-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let home = root.join("rustup-home");
        let toolchain = std::ffi::OsString::from("1.97.1-test");
        let bin = home.join("toolchains").join(&toolchain).join("bin");
        let update_hashes = home.join("update-hashes");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir_all(&update_hashes).unwrap();
        std::fs::write(home.join("settings.toml"), b"default_toolchain = none\n").unwrap();
        std::fs::write(update_hashes.join(&toolchain), b"test update hash\n").unwrap();
        std::fs::write(update_hashes.join("unselected-toolchain"), b"unselected\n").unwrap();
        let cargo = bin.join("cargo");
        let data = bin.join("target.json");
        std::fs::write(&cargo, b"cargo bytes\n").unwrap();
        std::fs::set_permissions(&cargo, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(&data, b"data bytes\n").unwrap();

        let inventory = posix_rustup_selected_inventory(&home, &toolchain, "fixture").unwrap();
        assert!(
            inventory
                .iter()
                .any(|entry| entry.relative.ends_with("bin/cargo") && entry.executable)
        );
        assert!(
            inventory
                .iter()
                .any(|entry| entry.relative.ends_with("bin/target.json") && !entry.executable)
        );
        assert!(inventory.iter().any(|entry| {
            entry.relative == Path::new("update-hashes").join(&toolchain) && !entry.executable
        }));
        assert!(
            inventory
                .iter()
                .all(|entry| !entry.relative.ends_with("unselected-toolchain"))
        );
        require_exact_directory_members(
            &home,
            &[
                std::ffi::OsString::from("settings.toml"),
                std::ffi::OsString::from("toolchains"),
                std::ffi::OsString::from("update-hashes"),
            ],
            "fixture",
        )
        .unwrap();
        std::fs::write(home.join("unbound"), b"extra\n").unwrap();
        assert!(
            require_exact_directory_members(
                &home,
                &[
                    std::ffi::OsString::from("settings.toml"),
                    std::ffi::OsString::from("toolchains"),
                    std::ffi::OsString::from("update-hashes"),
                ],
                "fixture",
            )
            .is_err()
        );
        std::fs::remove_file(home.join("unbound")).unwrap();

        let redirected = bin.join("redirected");
        symlink(&data, &redirected).unwrap();
        assert!(posix_rustup_selected_inventory(&home, &toolchain, "fixture").is_err());
        std::fs::remove_file(&redirected).unwrap();
        let hard_link = bin.join("hard-link");
        std::fs::hard_link(&data, &hard_link).unwrap();
        assert!(posix_rustup_selected_inventory(&home, &toolchain, "fixture").is_err());
        std::fs::remove_file(&hard_link).unwrap();
        let socket = bin.join("socket");
        let listener = UnixListener::bind(&socket).unwrap();
        assert!(posix_rustup_selected_inventory(&home, &toolchain, "fixture").is_err());
        drop(listener);
        std::fs::remove_file(&socket).unwrap();

        assert_eq!(posix_rustup_inventory_cost(0, 0, 0), Some((1, 0)));
        assert_eq!(
            posix_rustup_inventory_cost(
                super::POSIX_RUSTUP_STAGE_ENTRY_LIMIT - 1,
                super::POSIX_RUSTUP_STAGE_BYTE_LIMIT,
                0,
            ),
            Some((
                super::POSIX_RUSTUP_STAGE_ENTRY_LIMIT,
                super::POSIX_RUSTUP_STAGE_BYTE_LIMIT,
            ))
        );
        assert!(posix_rustup_inventory_cost(super::POSIX_RUSTUP_STAGE_ENTRY_LIMIT, 0, 0).is_none());
        assert!(posix_rustup_inventory_cost(0, super::POSIX_RUSTUP_STAGE_BYTE_LIMIT, 1).is_none());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn staged_source_inventory_rejects_byte_substitution() {
        let root = std::env::temp_dir().join(format!(
            "hell-bound-source-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        std::fs::create_dir_all(root.join("src")).unwrap();
        let path = root.join("src/lib.rs");
        std::fs::write(&path, b"pub fn bound() {}\n").unwrap();
        let bytes = std::fs::read(&path).unwrap();
        let inventory = super::object([
            (
                "files",
                crate::json::JsonValue::Array(vec![super::object([
                    ("mode", super::string("100644")),
                    ("path", super::string("src/lib.rs")),
                    (
                        "sha256",
                        super::string(&hell_testkit::sha256_bytes(&bytes).hex()),
                    ),
                    ("size", super::number(bytes.len() as u64)),
                ])]),
            ),
            ("schemaVersion", super::number(1)),
        ]);
        require_inventory_snapshot(&root, &inventory, "test source").unwrap();
        std::fs::write(&path, b"pub fn swapped() {}\n").unwrap();
        assert!(require_inventory_snapshot(&root, &inventory, "test source").is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn nested_restored_cache_is_made_writable_without_following_links() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let root = std::env::temp_dir().join(format!(
            "hell-restored-cache-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        let nested = root.join("debug/deps");
        std::fs::create_dir_all(&nested).unwrap();
        let artifact = nested.join("artifact");
        std::fs::write(&artifact, b"cache\n").unwrap();
        std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&artifact, std::fs::Permissions::from_mode(0o644)).unwrap();
        let locked = nested.join("locked");
        std::fs::create_dir(&locked).unwrap();
        std::fs::write(locked.join("retained"), b"retained\n").unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        normalize_candidate_cache_tree(&root, None).unwrap();
        assert_eq!(
            std::fs::metadata(&nested).unwrap().permissions().mode() & 0o7777,
            0o2770
        );
        assert_eq!(
            std::fs::metadata(&artifact).unwrap().permissions().mode() & 0o777,
            0o660
        );
        let outside = root.with_extension("outside");
        std::fs::write(&outside, b"outside\n").unwrap();
        symlink(&outside, root.join("redirect")).unwrap();
        assert!(normalize_candidate_cache_tree(&root, None).is_err());
        std::fs::remove_file(root.join("redirect")).unwrap();
        std::fs::hard_link(&outside, root.join("hard-link")).unwrap();
        assert!(normalize_candidate_cache_tree(&root, None).is_err());
        std::fs::remove_dir_all(&root).unwrap();
        std::fs::remove_file(&outside).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn candidate_cache_normalizer_accepts_only_the_exact_unredirected_root() {
        use std::os::unix::fs::symlink;

        let authority = std::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "hell-cache-authority-{}-{}",
                std::process::id(),
                std::thread::current().name().unwrap_or("test")
            ));
        let root = authority.join("candidate-target");
        std::fs::create_dir_all(&root).unwrap();
        validate_candidate_cache_normalizer_root(&root).unwrap();

        let wrong_name = authority.join("other-target");
        std::fs::create_dir(&wrong_name).unwrap();
        assert!(validate_candidate_cache_normalizer_root(&wrong_name).is_err());

        let redirected_authority = authority.with_extension("redirected");
        std::fs::create_dir(&redirected_authority).unwrap();
        let redirected = redirected_authority.join("candidate-target");
        symlink(&root, &redirected).unwrap();
        assert!(validate_candidate_cache_normalizer_root(&redirected).is_err());

        std::fs::remove_dir_all(&authority).unwrap();
        std::fs::remove_dir_all(&redirected_authority).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn cargo_deny_home_normalizer_is_private_bounded_and_exactly_scoped() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};

        let authority = std::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "hell-cargo-deny-home-{}-{}",
                std::process::id(),
                std::thread::current().name().unwrap_or("test")
            ));
        let target = authority.join("candidate-target");
        let environment = target.join("release-child-environment");
        let home = environment.join("cargo-deny-cargo-home");
        std::fs::create_dir_all(&home).unwrap();
        let cached = home.join("registry-cache");
        std::fs::write(&cached, b"cache\n").unwrap();
        let advisory_lock_authority = reserve_posix_cargo_deny_advisory_lock(&home).unwrap();
        let advisory_root = home.join("advisory-dbs");
        let advisory_lock = advisory_root.join("db.lock");
        validate_posix_cargo_deny_home_root(&home).unwrap();
        assert!(posix_cargo_deny_home_is_exact(&target, &home));
        assert!(!posix_cargo_deny_home_is_exact(
            &authority.join("other-target"),
            &home
        ));

        let identity = std::fs::metadata(&home).unwrap();
        normalize_cargo_deny_cache_tree(&home, identity.uid(), identity.uid(), identity.gid())
            .unwrap();
        assert_eq!(
            std::fs::metadata(&home).unwrap().permissions().mode() & 0o777,
            0o555
        );
        assert_eq!(
            std::fs::metadata(&cached).unwrap().permissions().mode() & 0o777,
            0o444
        );
        assert_eq!(
            std::fs::metadata(&advisory_root)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o750
        );
        assert_eq!(
            std::fs::metadata(&advisory_lock)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o660
        );
        for path in [&home, &advisory_root, &advisory_lock] {
            let metadata = std::fs::metadata(path).unwrap();
            assert_eq!(metadata.uid(), identity.uid());
            assert_eq!(metadata.gid(), identity.gid());
        }
        let candidate_groups =
            posix_candidate_group_inventory(b"61001 20 701 100\n", 61_001).unwrap();
        assert!(!candidate_groups.contains(&12_345));
        std::fs::set_permissions(&advisory_lock, std::fs::Permissions::from_mode(0o444)).unwrap();
        assert!(
            validate_posix_cargo_deny_home_post_state(
                &home,
                identity.uid(),
                identity.uid(),
                identity.gid(),
                &advisory_lock_authority,
            )
            .is_err()
        );
        std::fs::set_permissions(&advisory_lock, std::fs::Permissions::from_mode(0o660)).unwrap();
        validate_posix_cargo_deny_home_post_state(
            &home,
            identity.uid(),
            identity.uid(),
            identity.gid(),
            &advisory_lock_authority,
        )
        .unwrap();
        // cargo-deny 0.20.2 opens db.lock through tame-index with
        // read+write+create semantics, so both reopening the reserved lock and
        // creating a replacement lock in the advisory root must succeed for
        // the lock owner after the read-only transition.
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&advisory_lock)
            .unwrap();
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(advisory_root.join("regenerated.lock"))
            .unwrap();
        std::fs::remove_file(advisory_root.join("regenerated.lock")).unwrap();
        validate_posix_cargo_deny_home_post_state(
            &home,
            identity.uid(),
            identity.uid(),
            identity.gid(),
            &advisory_lock_authority,
        )
        .unwrap();

        std::fs::set_permissions(&advisory_root, std::fs::Permissions::from_mode(0o555)).unwrap();
        assert!(
            validate_posix_cargo_deny_home_post_state(
                &home,
                identity.uid(),
                identity.uid(),
                identity.gid(),
                &advisory_lock_authority,
            )
            .is_err()
        );
        std::fs::set_permissions(&advisory_root, std::fs::Permissions::from_mode(0o750)).unwrap();

        std::fs::remove_file(&advisory_lock).unwrap();
        std::fs::write(&advisory_lock, b"replacement\n").unwrap();
        std::fs::set_permissions(&advisory_lock, std::fs::Permissions::from_mode(0o660)).unwrap();
        assert!(
            validate_posix_cargo_deny_home_post_state(
                &home,
                identity.uid(),
                identity.uid(),
                identity.gid(),
                &advisory_lock_authority,
            )
            .is_err()
        );

        let wrong = environment.join("cargo-home");
        std::fs::create_dir(&wrong).unwrap();
        assert!(validate_posix_cargo_deny_home_root(&wrong).is_err());
        let outside = authority.join("outside");
        std::fs::write(&outside, b"outside\n").unwrap();
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o755)).unwrap();
        symlink(&outside, home.join("redirect")).unwrap();
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o555)).unwrap();
        assert!(
            validate_posix_cargo_deny_home_post_state(
                &home,
                identity.uid(),
                identity.uid(),
                identity.gid(),
                &advisory_lock_authority,
            )
            .is_err()
        );
        assert!(
            normalize_cargo_deny_cache_tree(&home, identity.uid(), identity.uid(), identity.gid())
                .is_err()
        );
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::remove_file(home.join("redirect")).unwrap();
        std::fs::hard_link(&outside, home.join("hard-link")).unwrap();
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o555)).unwrap();
        assert!(
            normalize_cargo_deny_cache_tree(&home, identity.uid(), identity.uid(), identity.gid())
                .is_err()
        );

        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&advisory_root, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::remove_dir_all(&authority).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn cargo_deny_metadata_cleanup_authority_is_exactly_scoped() {
        let parent = Path::new("/var/tmp");
        let directory = parent.join("hell-cargo-deny-metadata-12345-17");
        let path = directory.join("metadata.json");
        assert!(posix_cargo_deny_metadata_is_exact(
            parent, &directory, &path
        ));
        assert!(!posix_cargo_deny_metadata_is_exact(
            parent,
            &parent.join("hell-cargo-deny-metadata-012345-17"),
            &path,
        ));
        assert!(!posix_cargo_deny_metadata_is_exact(
            parent,
            &directory,
            &directory.join("other.json"),
        ));
        assert!(!posix_cargo_deny_metadata_is_exact(
            Path::new("/tmp"),
            &Path::new("/tmp").join("hell-cargo-deny-metadata-12345-17"),
            &Path::new("/tmp")
                .join("hell-cargo-deny-metadata-12345-17")
                .join("metadata.json"),
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn stack_root_normalizer_is_private_bounded_and_exactly_scoped() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};

        let sequence =
            super::POSIX_STACK_ROOT_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = Path::new("/private/var/tmp")
            .join(format!("hell-stack-root-{}-{sequence}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        validate_posix_stack_root(&root).unwrap();
        assert!(posix_stack_root_is_exact(&root));
        let metadata = std::fs::metadata(&root).unwrap();
        normalize_candidate_owned_cache_tree(&root, metadata.uid(), metadata.gid()).unwrap();
        assert_eq!(
            std::fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o750
        );
        validate_posix_stack_root_post_state(&root, metadata.uid(), metadata.gid()).unwrap();

        let state = root.join("state");
        std::fs::write(&state, b"bounded Stack state\n").unwrap();
        normalize_candidate_owned_cache_tree(&root, metadata.uid(), metadata.gid()).unwrap();
        validate_posix_stack_root_post_state(&root, metadata.uid(), metadata.gid()).unwrap();
        assert_eq!(
            std::fs::metadata(&state).unwrap().permissions().mode() & 0o777,
            0o640
        );

        let compiler = root.join("programs/ghc-9.8.2/bin/ghc");
        std::fs::create_dir_all(compiler.parent().unwrap()).unwrap();
        std::fs::write(&compiler, b"installed compiler\n").unwrap();
        std::fs::set_permissions(&compiler, std::fs::Permissions::from_mode(0o755)).unwrap();
        let compiler_link = root.join("programs/ghc-9.8.2/bin/ghc-9.8.2");
        symlink(&compiler, &compiler_link).unwrap();
        super::remove_candidate_owned_stack_symlinks(&root).unwrap();
        normalize_candidate_owned_cache_tree(&root, metadata.uid(), metadata.gid()).unwrap();
        validate_posix_stack_root_post_state(&root, metadata.uid(), metadata.gid()).unwrap();
        assert!(!compiler_link.exists());
        assert_eq!(
            std::fs::metadata(&compiler).unwrap().permissions().mode() & 0o777,
            0o640
        );

        let wrong = Path::new("/private/var/tmp")
            .join(format!("hell-other-root-{}-{sequence}", std::process::id()));
        std::fs::create_dir(&wrong).unwrap();
        assert!(validate_posix_stack_root(&wrong).is_err());
        let outside = Path::new("/private/var/tmp").join(format!(
            "hell-stack-outside-{}-{sequence}",
            std::process::id()
        ));
        std::fs::write(&outside, b"outside\n").unwrap();
        symlink(&outside, root.join("redirect")).unwrap();
        assert!(
            normalize_candidate_owned_cache_tree(&root, metadata.uid(), metadata.gid()).is_err()
        );
        std::fs::remove_file(root.join("redirect")).unwrap();
        std::fs::hard_link(&outside, root.join("hard-link")).unwrap();
        assert!(
            validate_posix_stack_root_post_state(&root, metadata.uid(), metadata.gid()).is_err()
        );

        std::fs::remove_dir_all(&root).unwrap();
        std::fs::remove_dir(&wrong).unwrap();
        std::fs::remove_file(&outside).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn stack_root_authority_is_the_exact_private_var_tmp_child() {
        let exact = Path::new("/private/var/tmp").join("hell-stack-root-12345-17");
        assert!(posix_stack_root_is_exact(&exact));
        assert!(!posix_stack_root_is_exact(
            &Path::new("/var/tmp").join(exact.file_name().unwrap())
        ));
        assert!(!posix_stack_root_is_exact(
            &Path::new("/private/var/tmp").join("hell-stack-root-12345-not-a-sequence")
        ));
        assert!(!posix_stack_root_is_exact(
            &Path::new("/private/var/tmp").join("hell-stack-root-012345-17")
        ));
    }

    #[cfg(unix)]
    #[test]
    fn stack_work_normalizer_is_distinct_from_the_global_stack_root() {
        use std::ffi::OsString;

        let authority =
            Path::new("/private/var/tmp").join("hell-rs-posix-sources-12345-17-abcdef012345");
        let source = authority.join("oracle");
        let work = source.join(".stack-work");
        assert!(posix_stack_work_is_exact(&authority, &source, &work));
        assert!(!posix_stack_work_is_exact(
            &authority,
            &authority.join("candidate"),
            &work
        ));
        assert!(!posix_stack_work_is_exact(
            &authority,
            &source,
            &source.join("nested/.stack-work")
        ));
        assert!(!posix_stack_work_is_exact(
            Path::new("/private/var/tmp/hell-stack-root-12345-17"),
            &source,
            &work
        ));
        let global_root = OsString::from("/private/var/tmp/hell-stack-root-12345-17");
        let rejected = [
            global_root.clone(),
            OsString::from("1"),
            OsString::from("2"),
            global_root.clone(),
            OsString::from("1"),
            OsString::from("2"),
            global_root,
            OsString::from("1"),
            OsString::from("2"),
            OsString::from("3"),
            OsString::from("4"),
        ];
        assert!(run_posix_stack_work_normalizer(&rejected).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn warm_cargo_deny_home_is_bound_after_the_final_whole_target_transition() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let authority = std::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "hell-warm-cargo-deny-home-{}-{}",
                std::process::id(),
                std::thread::current().name().unwrap_or("test")
            ));
        let target = authority.join("candidate-target");
        let home = target
            .join("release-child-environment")
            .join("cargo-deny-cargo-home");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(home.join("warm-cache"), b"restored cache\n").unwrap();

        normalize_candidate_cache_tree(&target, None).unwrap();
        assert_eq!(
            std::fs::metadata(&home).unwrap().permissions().mode() & 0o7777,
            0o2770
        );

        std::fs::remove_dir_all(&home).unwrap();
        std::fs::create_dir(&home).unwrap();
        let cached = home.join("warm-cache");
        std::fs::write(&cached, b"trusted staged cache\n").unwrap();
        let advisory_root = home.join("advisory-dbs");
        let advisory_lock = advisory_root.join("db.lock");
        std::fs::create_dir(&advisory_root).unwrap();
        std::fs::write(&advisory_lock, b"staged advisory authority\n").unwrap();
        let advisory_lock_authority = reserve_posix_cargo_deny_advisory_lock(&home).unwrap();
        assert_eq!(std::fs::metadata(&advisory_lock).unwrap().len(), 0);
        let metadata = std::fs::metadata(&home).unwrap();
        normalize_cargo_deny_cache_tree(&home, metadata.uid(), metadata.uid(), metadata.gid())
            .unwrap();
        validate_posix_cargo_deny_home_post_state(
            &home,
            metadata.uid(),
            metadata.uid(),
            metadata.gid(),
            &advisory_lock_authority,
        )
        .unwrap();
        assert_eq!(
            std::fs::metadata(&home).unwrap().permissions().mode() & 0o7777,
            0o555
        );
        assert_eq!(
            std::fs::metadata(&cached).unwrap().permissions().mode() & 0o7777,
            0o444
        );

        normalize_candidate_cache_tree(&target, None).unwrap();
        assert_eq!(
            std::fs::metadata(&home).unwrap().permissions().mode() & 0o7777,
            0o2770
        );
        assert_eq!(
            std::fs::metadata(&cached).unwrap().permissions().mode() & 0o7777,
            0o660
        );
        std::fs::remove_dir_all(&authority).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn cargo_deny_cache_copy_rejects_redirected_and_multiply_linked_sources() {
        use std::os::unix::fs::symlink;

        let root = std::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "hell-cargo-deny-copy-{}-{}",
                std::process::id(),
                std::thread::current().name().unwrap_or("test")
            ));
        let source = root.join("source");
        let destination = root.join("destination");
        let registry_index = source.join("registry/index/index.crates.io-test");
        let registry_cache = source.join("registry/cache/index.crates.io-test");
        let registry_source = source.join("registry/src/index.crates.io-test/crate-1.0.0");
        let vendor = staged_cargo_vendor_root(&source).join("crate-1.0.0");
        for directory in [&registry_index, &registry_cache, &registry_source, &vendor] {
            std::fs::create_dir_all(directory).unwrap();
        }
        std::fs::write(registry_index.join("config.json"), b"index\n").unwrap();
        std::fs::write(registry_cache.join("crate-1.0.0.crate"), b"crate\n").unwrap();
        std::fs::write(
            registry_source.join(".cargo-checksum.json"),
            b"{\"files\":{}}\n",
        )
        .unwrap();
        std::fs::write(vendor.join(".cargo-checksum.json"), b"{\"files\":{}}\n").unwrap();
        let mut entries = 1;
        let mut bytes = 0;
        copy_posix_cargo_cache_tree(&source, &destination, &mut entries, &mut bytes).unwrap();
        assert_eq!(
            std::fs::read(
                destination.join("registry/cache/index.crates.io-test/crate-1.0.0.crate")
            )
            .unwrap(),
            b"crate\n"
        );
        assert!(
            destination
                .join("registry/index/index.crates.io-test/config.json")
                .is_file()
        );
        assert!(
            destination
                .join("registry/src/index.crates.io-test/crate-1.0.0/.cargo-checksum.json")
                .is_file()
        );
        assert!(
            destination
                .join("vendor/index.crates.io-6f17d22bba15001f/crate-1.0.0/.cargo-checksum.json")
                .is_file()
        );
        assert_eq!(
            entries, 17,
            "one entry remains reserved for the staged config"
        );
        let mut bounded_entries = super::POSIX_RUSTUP_STAGE_ENTRY_LIMIT;
        let mut bounded_bytes = 0;
        assert!(
            copy_posix_cargo_cache_tree(
                &source,
                &root.join("over-entry-limit"),
                &mut bounded_entries,
                &mut bounded_bytes,
            )
            .is_err()
        );

        let outside = root.join("outside");
        std::fs::write(&outside, b"outside\n").unwrap();
        symlink(&outside, source.join("redirect")).unwrap();
        assert!(
            copy_posix_cargo_cache_tree(
                &source,
                &root.join("redirected-copy"),
                &mut entries,
                &mut bytes,
            )
            .is_err()
        );
        std::fs::remove_file(source.join("redirect")).unwrap();
        std::fs::hard_link(&outside, source.join("hard-link")).unwrap();
        assert!(
            copy_posix_cargo_cache_tree(
                &source,
                &root.join("hard-link-copy"),
                &mut entries,
                &mut bytes,
            )
            .is_err()
        );

        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn trusted_oracle_acquisition_rejects_substitution_and_cleans_exact_scope() {
        use std::os::unix::fs::PermissionsExt as _;

        let sequence =
            super::POSIX_ADAPTER_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "hell-trusted-oracle-acquisition-{}-{sequence}",
                std::process::id()
            ));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut acquisition = LinuxOracleAcquisition::reserve(&root).unwrap();

        let substituted = acquisition.directory().join("substituted");
        std::fs::write(&substituted, b"substitution\n").unwrap();
        assert!(acquisition.validate().is_err());
        std::fs::remove_file(&substituted).unwrap();
        acquisition.validate().unwrap();

        let oracle = acquisition.directory().join(LINUX_ORACLE_NAME);
        std::fs::write(&oracle, b"pinned oracle bytes\n").unwrap();
        std::fs::set_permissions(&oracle, std::fs::Permissions::from_mode(0o755)).unwrap();
        let sha256 = hell_testkit::sha256_file(&oracle).unwrap();
        acquisition.bind_path(&oracle, sha256).unwrap();
        std::fs::set_permissions(&oracle, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(acquisition.validate().is_err());
        std::fs::set_permissions(&oracle, std::fs::Permissions::from_mode(0o755)).unwrap();
        acquisition.validate().unwrap();

        let directory = acquisition.directory().to_path_buf();
        acquisition.cleanup().unwrap();
        assert!(!directory.exists());
        std::fs::remove_dir(root).unwrap();
    }
}
