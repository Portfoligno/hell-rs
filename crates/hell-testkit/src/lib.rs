//! Bounded differential, compatibility-gate, and deterministic-fuzz support.

mod artifact;
mod collection_authority;
mod corpus;
mod reviewed_set;
mod runtime_obligations;
mod windows_divergences;
mod windows_presentation;

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{Read, Write as _};
#[cfg(windows)]
use std::io::{Seek as _, SeekFrom};
#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{ChildStdin, Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, mpsc};
use std::time::{Duration, Instant};

use hell_platform::{CleanupLease, SupervisedChild, TerminationReport, WaitOutcome};
pub use hell_platform::{
    CleanupLifecycleReceipt, RetainedTerminationReceipt, RetainedTerminationSnapshot,
    RetainedTerminationState,
};

use hell_builtins::CompatibilityDimension;
pub use hell_builtins::{BuiltinId, ClaimPlatform, ExecutionProfile, NormalizerId};
pub use windows_presentation::WindowsPresentationField;

struct EscapedPath<'a>(&'a Path);

impl std::fmt::Debug for EscapedPath<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self.0, formatter)
    }
}

/// Environment names that a release-candidate child may inherit from the
/// trusted driver. Values are selected from the trusted parent's environment;
/// all other names are cleared before spawn.
pub const RELEASE_CHILD_ENVIRONMENT_ALLOWLIST: &[&str] = &[
    "APPDATA",
    "CARGO_HOME",
    "CARGO_TERM_COLOR",
    "CI",
    "ComSpec",
    "DEVELOPER_DIR",
    "GITHUB_ACTIONS",
    "HOME",
    "ImageOS",
    "ImageVersion",
    "LANG",
    "LC_ALL",
    "LIB",
    "LIBPATH",
    "LIBRARY_PATH",
    "LOCALAPPDATA",
    "NUMBER_OF_PROCESSORS",
    "PATH",
    "PATHEXT",
    "ProgramData",
    "ProgramFiles",
    "ProgramFiles(x86)",
    "ProgramW6432",
    "RUNNER_ARCH",
    "RUNNER_OS",
    "RUSTC_WRAPPER",
    "RUSTUP_HOME",
    "SCCACHE_DIR",
    "SDKROOT",
    "SYSTEMROOT",
    "SystemRoot",
    "TEMP",
    "TMP",
    "TMPDIR",
    "UniversalCRTSdkDir",
    "UCRTVersion",
    "USERPROFILE",
    "VCINSTALLDIR",
    "VCToolsInstallDir",
    "VisualStudioVersion",
    "VSINSTALLDIR",
    "WindowsSdkDir",
    "WindowsSDKVersion",
    "__DOTNET_ADD_64BIT",
    "__DOTNET_PREFERRED_BITNESS",
];

/// Versioned request marker for the typed POSIX release-child envelope.
#[cfg(unix)]
pub const POSIX_RELEASE_CHILD_REQUEST_V1: &str = "__release-posix-child-v1";

/// Maximum exact group inventory retained for a POSIX candidate, including
/// its primary group.
#[cfg(unix)]
pub const POSIX_CANDIDATE_GROUP_LIMIT: usize = 128;

/// Exact POSIX child environment names accepted by the trusted adapter.
#[cfg(unix)]
pub const POSIX_RELEASE_CHILD_ENVIRONMENT_ALLOWLIST: &[&str] = &[
    "CARGO",
    "CARGO_HOME",
    "CARGO_INCREMENTAL",
    "CARGO_TARGET_DIR",
    "CARGO_TERM_COLOR",
    "CI",
    "DEVELOPER_DIR",
    "GITHUB_ACTIONS",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_KEY_0",
    "GIT_CONFIG_VALUE_0",
    "HOME",
    "ImageOS",
    "ImageVersion",
    "LANG",
    "LC_ALL",
    "LIBRARY_PATH",
    "PATH",
    "RUNNER_ARCH",
    "RUNNER_OS",
    "RUSTC",
    "RUSTDOCFLAGS",
    "RUSTUP_HOME",
    "RUSTUP_TOOLCHAIN",
    "SCCACHE_DIR",
    "SDKROOT",
    "SOURCE_DATE_EPOCH",
    "TEMP",
    "TMP",
    "TMPDIR",
    "USERPROFILE",
];

/// Clears a child environment and restores only the release build allowlist.
pub fn configure_release_child_environment(command: &mut Command) {
    let retained = RELEASE_CHILD_ENVIRONMENT_ALLOWLIST
        .iter()
        .filter_map(|name| std::env::var_os(name).map(|value| (*name, value)))
        .collect::<Vec<_>>();
    command.env_clear();
    command.envs(retained);
}

#[cfg(feature = "compat-tracing")]
pub use artifact::run_core_data_production_bundle_gate;
pub use artifact::{
    EvidenceSummary, NATIVE_BUILD_ENVIRONMENT_NAMES, NativeExecutionEnvironment,
    NativeExecutionEnvironmentInputs, ObservationEquivalence, RetainedBundleOutcomeFacts,
    RetainedEnvironmentVariableFact, RetainedMismatchFact, RetainedNativeEnvironmentFacts,
    RetainedObservationClassification, RetainedReachedClaimTarget, RetainedSideOutcomeFacts,
    RetainedVerifiedProfileFacts, canonical_conformance_observation_json, case_descriptor_sha256,
    case_execution_input_sha256, classify_observation_bundle_for_case,
    classify_retained_alternate_executable_observation_against_oracle,
    classify_retained_observation_bundle, classify_retained_profile_observation_against_oracle,
    collection_black_box_shard_for_bundle, collection_bundle_facts, replay_conformance_stderr,
    retain_mismatch_bundle, retain_observation_bundle, retain_reviewed_regression_bundle,
    retain_verified_profile_observation, retained_bundle_outcome_facts,
    retained_reached_claim_targets, retained_regression_reached_claim_targets,
    retained_regression_reviewed_claim_targets, reviewed_regression_case_from_bundle,
    runtime_platform_shard_for_bundle, validate_conformance_semantic_obligation,
    verified_observation_bundle_manifest_files, verify_observation_bundle,
    verify_observation_bundle_for_case, verify_observation_bundle_manifest_bytes,
    verify_regression_observation_bundle_for_case,
    verify_retained_alternate_executable_observation_against_bundle,
    verify_retained_native_environment, verify_retained_profile_observation,
    verify_retained_profile_observation_against_bundle, write_evidence_summary,
    write_native_environment_record,
};
pub use collection_authority::{
    COLLECTION_CASE_AUTHORITY_COUNT, CollectionBlackBoxShard, CollectionBundleFacts,
    CollectionCaseAuthority, CollectionCompletion, CollectionDependencyAuthority,
    CollectionNativeBuildAuthority, CollectionOracleSubject, CollectionSourceAuthority,
    CollectionVerifiedProviderRoot, decoded_collection_source_archive_sha256,
    reviewed_collection_case_authorities, reviewed_collection_cases,
    validate_collection_black_box_structure, verify_collection_source_authority,
};
pub use corpus::{
    GeneratedCase, GeneratedType, committed_differential_cases,
    dormant_committed_differential_cases, generated_typed_cases, render_active_collection_claims,
    verify_collection_activation_state,
};
pub use hell_digest::Digest;
use hell_digest::Sha256;
pub use runtime_obligations::{
    RuntimeBoundaryRequirement, RuntimeInteractionRequirement, RuntimeObligationCell,
    RuntimePlatformShard, RuntimePlatformTarget, applicable_runtime_obligation_cells,
    mandatory_runtime_boundaries, mandatory_runtime_interactions,
    portable_native_oracle_failure_unavailable, portable_native_oracle_obligation_cells,
    runtime_assurance_authority_sha256, runtime_assurance_spec_sha256,
    runtime_obligation_cells_for_spec, validate_runtime_obligation_trace,
    validate_runtime_platform_set,
};

static NEXT_SANDBOX: AtomicU64 = AtomicU64::new(0);
const MAX_DIFFERENTIAL_WORKERS: usize = 4;
const COMPLETE_CAPTURE_BYTES: usize = 4 * 1024 * 1024;
const CAPTURE_EDGE_BYTES: usize = 256 * 1024;
const FILE_INLINE_BYTES: usize = 64 * 1024;
const FILESYSTEM_ENTRY_LIMIT: usize = 4_096;
const FILESYSTEM_HASH_BYTES: u64 = 64 * 1024 * 1024;

/// Returns the exact complete-stream capture boundary used by supervision.
#[doc(hidden)]
#[must_use]
pub const fn complete_capture_byte_limit_for_integration() -> usize {
    COMPLETE_CAPTURE_BYTES
}
#[cfg(windows)]
const WINDOWS_PROGRAM_AUTHORITY_ACQUISITION_BUDGET: Duration = Duration::from_secs(30);

#[cfg(windows)]
fn windows_program_authority_acquisition_deadline() -> std::io::Result<Instant> {
    Instant::now()
        .checked_add(WINDOWS_PROGRAM_AUTHORITY_ACQUISITION_BUDGET)
        .ok_or_else(|| std::io::Error::other("Windows program authority deadline overflowed"))
}

/// A trusted, typed launcher policy for release candidate and oracle children.
#[derive(Clone, Debug)]
pub struct CandidateLaunchPolicy {
    #[cfg(unix)]
    process_authorities: Arc<BoundPosixProcessAuthorities>,
    #[cfg(unix)]
    adapter: PathBuf,
    #[cfg(unix)]
    adapter_sha256: Digest,
    #[cfg(unix)]
    adapter_identity: PosixAdapterIdentity,
    #[cfg(unix)]
    cargo_source: PathBuf,
    #[cfg(unix)]
    cargo_adapter: PathBuf,
    #[cfg(unix)]
    cargo_adapter_sha256: Digest,
    #[cfg(unix)]
    cargo_adapter_identity: PosixAdapterIdentity,
    #[cfg(unix)]
    cargo_authority: BoundPosixCargoSourceAuthority,
    #[cfg(unix)]
    cargo_deny_authority: Option<BoundPosixCargoDenyAuthority>,
    #[cfg(unix)]
    stack_authority: Option<BoundPosixStackAuthority>,
    #[cfg(unix)]
    principal: Arc<str>,
    #[cfg(unix)]
    uid: u32,
    #[cfg(unix)]
    primary_gid: u32,
    #[cfg(windows)]
    launcher: BoundProgramInvocation,
    #[cfg(windows)]
    restricted_adapter: BoundProgramInvocation,
    #[cfg(windows)]
    toolchain: WindowsToolchainAuthority,
    writable_roots: Arc<[PathBuf]>,
}

#[cfg(windows)]
struct WindowsLaunchControlAuthority {
    request_sha256: Digest,
    program: Option<BoundProgramInvocation>,
    current_directory: PathBuf,
    current_directory_identity: same_file::Handle,
}

#[cfg(windows)]
const WINDOWS_LAUNCH_CONTROL_PHASES: [&str; 12] = [
    "request-parsed",
    "adapter-revalidated",
    "token-duplicated",
    "supported-canary-start",
    "supported-canary-complete",
    "argv-helper-start",
    "helper-entry",
    "request-decoded",
    "target-spawned",
    "target-terminal",
    "argv-helper-complete",
    "job-closed",
];

#[cfg(windows)]
impl WindowsLaunchControlAuthority {
    fn complete(
        self,
        status: ExitStatus,
        timed_out: bool,
        termination: Option<TerminationReport>,
        candidate_quiescence_complete: bool,
    ) -> std::io::Result<WindowsLaunchControlReceipt> {
        if same_file::Handle::from_path(&self.current_directory)? != self.current_directory_identity
            || fs::canonicalize(&self.current_directory)? != self.current_directory
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Windows restricted launch current-directory identity changed",
            ));
        }
        let (program, program_bytes, program_sha256) = match self.program {
            Some(program) => {
                program.revalidate(program.invocation_path.as_os_str())?;
                (
                    Some(program.invocation_path.clone()),
                    Some(program.length()),
                    Some(program.sha256()),
                )
            }
            None => (None, None, None),
        };
        let termination_forced = termination.is_some_and(|report| report.forced);
        let termination_reaped = termination.is_some_and(|report| report.reaped);
        let completed =
            status.success() && !timed_out && termination_reaped && candidate_quiescence_complete;
        let state = if completed { "completed" } else { "failed" };
        let mut receipt = WindowsLaunchControlReceipt {
            schema_version: 1,
            request_sha256: self.request_sha256,
            state,
            phases: if completed {
                Arc::from(WINDOWS_LAUNCH_CONTROL_PHASES)
            } else {
                Arc::from([])
            },
            bytes: 0,
            sha256: Digest::default(),
            status_code: status.code(),
            timed_out,
            termination_forced,
            termination_reaped,
            candidate_quiescence_complete,
            program,
            program_bytes,
            program_sha256,
            current_directory: self.current_directory,
        };
        let encoded = receipt.encoded();
        receipt.bytes = u64::try_from(encoded.len()).unwrap_or(u64::MAX);
        receipt.sha256 = sha256_bytes(&encoded);
        receipt.validate()?;
        Ok(receipt)
    }
}

/// One exact POSIX directory identity and policy checkpoint.
#[cfg(unix)]
#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct PosixDirectoryCheckpoint {
    path: PathBuf,
    device: u64,
    inode: u64,
    owner: u32,
    group: u32,
    mode: u32,
}

#[cfg(unix)]
impl PosixDirectoryCheckpoint {
    /// Captures and immediately validates one exact directory checkpoint.
    ///
    /// # Errors
    ///
    /// Returns a bounded diagnostic when the path cannot be inspected or its
    /// type, identity, ownership, or mode differs from policy.
    pub fn capture(
        path: &Path,
        owner: u32,
        group: u32,
        mode: u32,
        checkpoint: &str,
    ) -> Result<Self, String> {
        use std::os::unix::fs::MetadataExt as _;

        let metadata = fs::symlink_metadata(path).map_err(|error| {
            format!("cannot inspect POSIX authority {}: {error}", path.display())
        })?;
        let authority = Self {
            path: path.to_path_buf(),
            device: metadata.dev(),
            inode: metadata.ino(),
            owner,
            group,
            mode,
        };
        authority.validate(checkpoint)?;
        Ok(authority)
    }

    /// Returns the exact path bound by this checkpoint.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Revalidates this checkpoint from one metadata snapshot.
    ///
    /// # Errors
    ///
    /// Returns a bounded diagnostic naming the checkpoint, path, and complete
    /// expected and observed identity tuples.
    pub fn validate(&self, checkpoint: &str) -> Result<(), String> {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let metadata = fs::symlink_metadata(&self.path).map_err(|error| {
            format!(
                "cannot inspect candidate environment authority: checkpoint={checkpoint:?}; \
                 path={:?}; failure={error}",
                EscapedPath(&self.path)
            )
        })?;
        let observed_kind = posix_checkpoint_metadata_kind(&metadata);
        let observed_device = metadata.dev();
        let observed_inode = metadata.ino();
        let observed_owner = metadata.uid();
        let observed_group = metadata.gid();
        let observed_mode = metadata.permissions().mode() & 0o7777;
        if observed_kind != "directory"
            || observed_device != self.device
            || observed_inode != self.inode
            || observed_owner != self.owner
            || observed_group != self.group
            || observed_mode != self.mode
        {
            return Err(format!(
                "candidate environment directory authority changed: checkpoint={checkpoint:?}; \
                 path={:?}; expected=kind=directory,dev={},inode={},uid={},gid={},mode={:#06o}; \
                 observed=kind={observed_kind},dev={observed_device},inode={observed_inode},uid={observed_owner},gid={observed_group},mode={observed_mode:#06o}",
                EscapedPath(&self.path),
                self.device,
                self.inode,
                self.owner,
                self.group,
                self.mode,
            ));
        }
        Ok(())
    }

    /// Revalidates this directory and its exact immediate-child inventory.
    /// Nested content below an expected child remains outside this checkpoint.
    ///
    /// # Errors
    ///
    /// Returns a bounded diagnostic naming the checkpoint, path, and complete
    /// expected and observed immediate-child inventories.
    pub fn validate_exact_children(
        &self,
        checkpoint: &str,
        expected: &[&str],
    ) -> Result<(), String> {
        const ENTRY_LIMIT: usize = 32;
        const TEXT_LIMIT: usize = 4_096;

        self.validate(checkpoint)?;
        if expected.len() > ENTRY_LIMIT {
            return Err(format!(
                "candidate environment inventory policy is unbounded: checkpoint={checkpoint:?}; path={:?}; expectedCount={}",
                EscapedPath(&self.path),
                expected.len()
            ));
        }
        let mut observed = Vec::new();
        let mut truncated = false;
        let entries = fs::read_dir(&self.path).map_err(|error| {
            format!(
                "cannot enumerate candidate environment inventory: checkpoint={checkpoint:?}; path={:?}; failure={error}",
                EscapedPath(&self.path)
            )
        })?;
        for entry in entries {
            if observed.len() == ENTRY_LIMIT {
                truncated = true;
                break;
            }
            observed.push(
                entry
                    .map_err(|error| {
                        format!(
                            "cannot read candidate environment inventory entry: checkpoint={checkpoint:?}; path={:?}; failure={error}",
                            EscapedPath(&self.path)
                        )
                    })?
                    .file_name(),
            );
        }
        observed.sort();
        let mut expected = expected
            .iter()
            .map(OsString::from)
            .collect::<Vec<OsString>>();
        expected.sort();
        if truncated || observed != expected {
            let bounded = |entries: &[OsString]| {
                let mut text = format!("{entries:?}");
                if text.len() > TEXT_LIMIT {
                    text.truncate(TEXT_LIMIT);
                    text.push_str("<truncated>");
                }
                text
            };
            return Err(format!(
                "candidate environment directory inventory changed: checkpoint={checkpoint:?}; path={:?}; expectedInventory={}; observedInventory={}{}",
                EscapedPath(&self.path),
                bounded(&expected),
                bounded(&observed),
                if truncated {
                    ",<entry-limit-exceeded>"
                } else {
                    ""
                }
            ));
        }
        Ok(())
    }
}

#[cfg(unix)]
fn posix_checkpoint_metadata_kind(metadata: &fs::Metadata) -> &'static str {
    use std::os::unix::fs::FileTypeExt as _;

    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        "symlink"
    } else if file_type.is_dir() {
        "directory"
    } else if file_type.is_file() {
        "file"
    } else if file_type.is_block_device() {
        "block-device"
    } else if file_type.is_char_device() {
        "character-device"
    } else if file_type.is_fifo() {
        "fifo"
    } else if file_type.is_socket() {
        "socket"
    } else {
        "unknown"
    }
}

/// Exact identity and bounded diagnostics for one Windows release artifact.
#[cfg(windows)]
#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct WindowsReleaseBinaryCheckpoint {
    target: PathBuf,
    binary: PathBuf,
    candidate_target_binding: Option<PathBuf>,
    observation: WindowsReleaseBinaryObservation,
    release_receipt: WindowsCargoReleaseReceipt,
}

#[cfg(windows)]
const WINDOWS_CARGO_RELEASE_RECEIPT: &str = ".hell-cargo-release-receipt-v1";

#[cfg(windows)]
const WINDOWS_CARGO_RELEASE_RECEIPT_HEADER: &str = "hell-windows-cargo-release-receipt-v1";

/// Bound evidence emitted only after the restricted Cargo release child succeeds.
#[cfg(windows)]
#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct WindowsCargoReleaseReceipt {
    target: PathBuf,
    binary: PathBuf,
    receipt: PathBuf,
    receipt_identity: Arc<same_file::Handle>,
    attestation: WindowsCargoReleaseArtifactAttestation,
    observation: WindowsReleaseBinaryObservation,
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WindowsCargoReleaseArtifactAttestation {
    length: u64,
    sha256: Digest,
}

#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct WindowsReleaseBinaryObservation {
    identity: Arc<same_file::Handle>,
    length: u64,
    sha256: Digest,
}

#[cfg(windows)]
impl WindowsReleaseBinaryCheckpoint {
    /// Captures a release binary after a successful build.
    ///
    /// # Errors
    ///
    /// Returns a bounded diagnostic when the artifact is absent, redirected,
    /// or disagrees with the candidate target environment binding.
    pub fn capture(
        target: PathBuf,
        binary: PathBuf,
        candidate_target_binding: Option<PathBuf>,
        release_receipt: Option<WindowsCargoReleaseReceipt>,
        checkpoint: &str,
        release_build_passed: bool,
    ) -> Result<Self, String> {
        let observation =
            windows_release_binary_observation(&target, &binary).map_err(|detail| {
                windows_release_binary_diagnostic(
                    checkpoint,
                    &target,
                    &binary,
                    candidate_target_binding.as_deref(),
                    release_build_passed,
                    None,
                    None,
                    &detail,
                )
            })?;
        if candidate_target_binding.as_deref() != Some(target.as_path()) {
            return Err(windows_release_binary_diagnostic(
                checkpoint,
                &target,
                &binary,
                candidate_target_binding.as_deref(),
                release_build_passed,
                Some(&observation),
                Some(&observation),
                "candidate target environment binding differs from the expected output directory",
            ));
        }
        let release_receipt = release_receipt.ok_or_else(|| {
            windows_release_binary_diagnostic(
                checkpoint,
                &target,
                &binary,
                candidate_target_binding.as_deref(),
                release_build_passed,
                Some(&observation),
                Some(&observation),
                "successful restricted Cargo release receipt is absent",
            )
        })?;
        release_receipt
            .validate(&target, &binary)
            .map_err(|detail| {
                windows_release_binary_diagnostic(
                    checkpoint,
                    &target,
                    &binary,
                    candidate_target_binding.as_deref(),
                    release_build_passed,
                    Some(&observation),
                    Some(&observation),
                    &detail,
                )
            })?;
        Ok(Self {
            target,
            binary,
            candidate_target_binding,
            observation,
            release_receipt,
        })
    }

    /// Revalidates the release binary identity and content.
    ///
    /// # Errors
    ///
    /// Returns a bounded checkpoint and directory-inventory diagnostic when
    /// the artifact is absent or has changed.
    pub fn validate(&self, checkpoint: &str, release_build_passed: bool) -> Result<(), String> {
        self.release_receipt
            .validate(&self.target, &self.binary)
            .map_err(|detail| {
                windows_release_binary_diagnostic(
                    checkpoint,
                    &self.target,
                    &self.binary,
                    self.candidate_target_binding.as_deref(),
                    release_build_passed,
                    Some(&self.observation),
                    None,
                    &detail,
                )
            })?;
        let observed =
            windows_release_binary_observation(&self.target, &self.binary).map_err(|detail| {
                windows_release_binary_diagnostic(
                    checkpoint,
                    &self.target,
                    &self.binary,
                    self.candidate_target_binding.as_deref(),
                    release_build_passed,
                    Some(&self.observation),
                    None,
                    &detail,
                )
            })?;
        if observed != self.observation {
            return Err(windows_release_binary_diagnostic(
                checkpoint,
                &self.target,
                &self.binary,
                self.candidate_target_binding.as_deref(),
                release_build_passed,
                Some(&self.observation),
                Some(&observed),
                "release binary identity or content changed after the successful build",
            ));
        }
        Ok(())
    }

    /// Returns the exact executable path while this authority retains a
    /// Windows handle that denies write, delete, and replacement access.
    pub fn bound_binary_path(&self) -> Result<&Path, String> {
        self.validate("before retained-path consumption", true)?;
        Ok(&self.binary)
    }

    /// Copies the executable through the retained, identity-bound handle.
    ///
    /// # Errors
    ///
    /// Returns an error if the destination exists, the retained identity
    /// changes, or the copied byte count differs from the receipt.
    pub fn copy_bound_binary(&self, destination: &Path) -> Result<(), String> {
        self.validate("before retained-handle copy", true)?;
        let mut source = self
            .observation
            .identity
            .as_file()
            .try_clone()
            .map_err(|error| format!("cannot clone retained release binary handle: {error}"))?;
        source
            .seek(SeekFrom::Start(0))
            .map_err(|error| format!("cannot rewind retained release binary handle: {error}"))?;
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination)
            .map_err(|error| format!("cannot create retained release binary copy: {error}"))?;
        let copied = std::io::copy(&mut source, &mut output)
            .map_err(|error| format!("cannot copy retained release binary handle: {error}"))?;
        output
            .sync_all()
            .map_err(|error| format!("cannot sync retained release binary copy: {error}"))?;
        if copied != self.observation.length {
            return Err("retained release binary copy length differs".to_owned());
        }
        self.validate("after retained-handle copy", true)
    }
}

#[cfg(windows)]
impl WindowsCargoReleaseReceipt {
    /// Loads and binds the helper-produced receipt for an exact release target.
    pub fn load(target: &Path) -> Result<Self, String> {
        let binary = target.join("release").join("hell.exe");
        let receipt = target.join(WINDOWS_CARGO_RELEASE_RECEIPT);
        require_real_windows_release_receipt(target, &receipt)?;
        let receipt_identity = windows_locked_same_file_handle(&receipt)
            .map_err(|error| format!("cannot bind restricted Cargo release receipt: {error}"))?;
        let text = read_bounded_windows_release_receipt(receipt_identity.as_file())?;
        let attestation = parse_windows_release_receipt(&text)?;
        let observation = windows_release_binary_observation(target, &binary)?;
        if observation.length != attestation.length || observation.sha256 != attestation.sha256 {
            return Err("restricted Cargo release receipt artifact content differs".to_owned());
        }
        let authority = Self {
            target: target.to_path_buf(),
            binary,
            receipt,
            receipt_identity: Arc::new(receipt_identity),
            attestation,
            observation,
        };
        authority.validate(target, &authority.binary)?;
        Ok(authority)
    }

    fn validate(&self, target: &Path, binary: &Path) -> Result<(), String> {
        if self.target != target || self.binary != binary {
            return Err("restricted Cargo release receipt target or artifact differs".to_owned());
        }
        let rebound = same_file::Handle::from_path(&self.receipt)
            .map_err(|error| format!("cannot rebind restricted Cargo release receipt: {error}"))?;
        if rebound != *self.receipt_identity {
            return Err("restricted Cargo release receipt identity changed".to_owned());
        }
        let text = read_bounded_windows_release_receipt(self.receipt_identity.as_file())?;
        if parse_windows_release_receipt(&text)? != self.attestation {
            return Err("restricted Cargo release receipt content changed".to_owned());
        }
        let observed = windows_release_binary_observation(target, binary)?;
        if observed != self.observation {
            return Err(
                "restricted Cargo release receipt artifact identity or content differs".to_owned(),
            );
        }
        Ok(())
    }
}

#[cfg(windows)]
fn read_bounded_windows_release_receipt(file: &fs::File) -> Result<String, String> {
    const BYTE_LIMIT: u64 = 512;
    let metadata = file
        .metadata()
        .map_err(|error| format!("cannot inspect restricted Cargo release receipt: {error}"))?;
    if metadata.len() > BYTE_LIMIT {
        return Err("restricted Cargo release receipt exceeds its byte bound".to_owned());
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    let mut reader = file
        .try_clone()
        .map_err(|error| format!("cannot clone restricted Cargo release receipt: {error}"))?;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|error| format!("cannot rewind restricted Cargo release receipt: {error}"))?;
    reader
        .take(BYTE_LIMIT.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read restricted Cargo release receipt: {error}"))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > BYTE_LIMIT {
        return Err("restricted Cargo release receipt exceeds its byte bound".to_owned());
    }
    String::from_utf8(bytes).map_err(|_| "restricted Cargo release receipt is not UTF-8".to_owned())
}

#[cfg(windows)]
fn parse_windows_release_receipt(
    text: &str,
) -> Result<WindowsCargoReleaseArtifactAttestation, String> {
    let mut lines = text.lines();
    if lines.next() != Some(WINDOWS_CARGO_RELEASE_RECEIPT_HEADER)
        || lines.next() != Some("program=cargo")
        || lines.next() != Some("subcommand=build")
        || lines.next() != Some("package=hell-cli")
        || lines.next() != Some("binary=hell")
        || lines.next() != Some("features=compat-tracing")
    {
        return Err("restricted Cargo release receipt grammar differs".to_owned());
    }
    let length_text = lines
        .next()
        .and_then(|line| line.strip_prefix("length="))
        .ok_or_else(|| "restricted Cargo release receipt length is absent".to_owned())?;
    let length = length_text
        .parse::<u64>()
        .map_err(|_| "restricted Cargo release receipt length is malformed".to_owned())?;
    let digest_text = lines
        .next()
        .and_then(|line| line.strip_prefix("sha256="))
        .ok_or_else(|| "restricted Cargo release receipt digest is absent".to_owned())?;
    if length_text != length.to_string()
        || digest_text != digest_text.to_ascii_lowercase()
        || lines.next().is_some()
        || !text.ends_with('\n')
    {
        return Err("restricted Cargo release receipt framing differs".to_owned());
    }
    let sha256 = Digest::from_hex(digest_text).map_err(|error| {
        format!("restricted Cargo release receipt digest is malformed: {error}")
    })?;
    Ok(WindowsCargoReleaseArtifactAttestation { length, sha256 })
}

#[cfg(windows)]
fn require_real_windows_release_receipt(target: &Path, receipt: &Path) -> Result<(), String> {
    use std::os::windows::fs::MetadataExt as _;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    let target_metadata = fs::symlink_metadata(target)
        .map_err(|error| format!("cannot inspect restricted Cargo receipt target: {error}"))?;
    let receipt_metadata = fs::symlink_metadata(receipt)
        .map_err(|error| format!("cannot inspect restricted Cargo release receipt: {error}"))?;
    if !target_metadata.is_dir()
        || target_metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || fs::canonicalize(target).map_err(|error| {
            format!("cannot canonicalize restricted Cargo receipt target: {error}")
        })? != target
        || !receipt_metadata.is_file()
        || receipt_metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || fs::canonicalize(receipt).map_err(|error| {
            format!("cannot canonicalize restricted Cargo release receipt: {error}")
        })? != receipt
    {
        return Err("restricted Cargo release receipt or target is redirected".to_owned());
    }
    Ok(())
}

/// Removes an earlier exact-release receipt before the restricted Cargo child starts.
///
/// # Errors
///
/// Fails closed when the target or an existing receipt is redirected or has the
/// wrong file kind.
#[cfg(windows)]
#[doc(hidden)]
pub fn prepare_windows_cargo_release_receipt(target: &Path) -> std::io::Result<()> {
    use std::os::windows::fs::MetadataExt as _;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    let metadata = fs::symlink_metadata(target)?;
    if !metadata.is_dir()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || fs::canonicalize(target)? != target
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Windows Cargo release receipt target is redirected",
        ));
    }
    let receipt = target.join(WINDOWS_CARGO_RELEASE_RECEIPT);
    match fs::symlink_metadata(&receipt) {
        Ok(metadata) => {
            if !metadata.is_file()
                || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
                || fs::canonicalize(&receipt)? != receipt
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "existing Windows Cargo release receipt is redirected",
                ));
            }
            fs::remove_file(receipt)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// Publishes the exact-release receipt after a successful restricted Cargo child.
///
/// # Errors
///
/// Fails when the exact release artifact is absent, redirected, or a receipt
/// was created after the pre-spawn stale-receipt check.
#[cfg(windows)]
#[doc(hidden)]
pub fn publish_windows_cargo_release_receipt(target: &Path) -> std::io::Result<()> {
    let binary = target.join("release").join("hell.exe");
    let observation =
        windows_release_binary_observation(target, &binary).map_err(std::io::Error::other)?;
    let receipt = target.join(WINDOWS_CARGO_RELEASE_RECEIPT);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&receipt)?;
    let text = format!(
        "{WINDOWS_CARGO_RELEASE_RECEIPT_HEADER}\nprogram=cargo\nsubcommand=build\npackage=hell-cli\nbinary=hell\nfeatures=compat-tracing\nlength={}\nsha256={}\n",
        observation.length,
        observation.sha256.hex()
    );
    file.write_all(text.as_bytes())?;
    file.sync_all()?;
    // The retained reader intentionally denies write sharing, so the mutable
    // publication handle must be closed before the receipt is rebound.
    drop(file);
    let loaded = WindowsCargoReleaseReceipt::load(target).map_err(std::io::Error::other)?;
    loaded
        .validate(target, &binary)
        .map_err(std::io::Error::other)
}

#[cfg(windows)]
fn windows_release_binary_observation(
    target: &Path,
    binary: &Path,
) -> Result<WindowsReleaseBinaryObservation, String> {
    require_real_windows_release_binary(target, binary)?;
    let identity = windows_locked_same_file_handle(binary)
        .map_err(|error| format!("cannot bind release binary identity: {error}"))?;
    let before = identity
        .as_file()
        .metadata()
        .map_err(|error| format!("cannot inspect bound release binary identity: {error}"))?;
    let mut file = identity.as_file();
    let mut digest = Sha256::new();
    let mut length = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("cannot hash bound release binary identity: {error}"))?;
        if read == 0 {
            break;
        }
        length = length
            .checked_add(u64::try_from(read).unwrap_or(u64::MAX))
            .ok_or_else(|| "release binary length overflowed while hashing".to_owned())?;
        digest.update(&buffer[..read]);
    }
    let after = identity
        .as_file()
        .metadata()
        .map_err(|error| format!("cannot reinspect bound release binary identity: {error}"))?;
    require_real_windows_release_binary(target, binary)?;
    let rebound = same_file::Handle::from_path(binary)
        .map_err(|error| format!("cannot rebind release binary identity: {error}"))?;
    if before.len() != length || after.len() != length || rebound != identity {
        return Err("release binary identity changed while it was hashed".to_owned());
    }
    Ok(WindowsReleaseBinaryObservation {
        identity: Arc::new(identity),
        length,
        sha256: digest.finish(),
    })
}

#[cfg(windows)]
fn windows_locked_same_file_handle(path: &Path) -> std::io::Result<same_file::Handle> {
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    let file = fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(path)?;
    same_file::Handle::from_file(file)
}

#[cfg(windows)]
fn bind_windows_program_parent(path: &Path) -> std::io::Result<Arc<same_file::Handle>> {
    use std::os::windows::fs::MetadataExt as _;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("bound program has no parent"))?;
    let metadata = fs::symlink_metadata(parent)?;
    if !metadata.is_dir()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || fs::canonicalize(parent)? != parent
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "bound program invocation parent is not one canonical direct directory",
        ));
    }
    same_file::Handle::from_path(parent).map(Arc::new)
}

#[cfg(windows)]
pub fn sha256_retained_windows_file_until(
    mut file: &fs::File,
    deadline: Instant,
) -> std::io::Result<Digest> {
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "bound Windows program hash exceeded its absolute deadline",
            ));
        }
        let read = file.read(&mut buffer)?;
        if read == 0 {
            return Ok(digest.finish());
        }
        digest.update(&buffer[..read]);
    }
}

#[cfg(windows)]
fn require_real_windows_release_binary(target: &Path, binary: &Path) -> Result<(), String> {
    use std::os::windows::fs::MetadataExt as _;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    let release = target.join("release");
    let release_metadata = fs::symlink_metadata(&release)
        .map_err(|error| format!("cannot inspect release target directory: {error}"))?;
    if release_metadata.file_type().is_symlink()
        || !release_metadata.is_dir()
        || release_metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
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
    if binary_metadata.file_type().is_symlink()
        || !binary_metadata.is_file()
        || binary_metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err("candidate release binary is not a real file".to_owned());
    }
    if fs::canonicalize(binary)
        .map_err(|error| format!("cannot canonicalize release binary: {error}"))?
        != binary
    {
        return Err("candidate release binary is redirected".to_owned());
    }
    Ok(())
}

#[cfg(windows)]
fn windows_release_binary_diagnostic(
    checkpoint: &str,
    target: &Path,
    binary: &Path,
    candidate_target_binding: Option<&Path>,
    release_build_passed: bool,
    expected: Option<&WindowsReleaseBinaryObservation>,
    observed: Option<&WindowsReleaseBinaryObservation>,
    detail: &str,
) -> String {
    format!(
        "Windows release binary checkpoint failed: checkpoint={checkpoint:?} expectedPath={} \
         candidateTargetBinding={} releaseBuildPassed={release_build_passed} \
         expectedIdentity={} observedIdentity={} targetInventory={} releaseInventory={} detail={detail}",
        binary.display(),
        candidate_target_binding
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "<absent>".to_owned()),
        windows_release_binary_identity_text(expected),
        windows_release_binary_identity_text(observed),
        bounded_windows_directory_inventory(target),
        bounded_windows_directory_inventory(&target.join("release")),
    )
}

#[cfg(windows)]
fn windows_release_binary_identity_text(
    observation: Option<&WindowsReleaseBinaryObservation>,
) -> String {
    observation.map_or_else(
        || "<unavailable>".to_owned(),
        |observation| {
            format!(
                "fileIdentity=bound,length={},sha256={}",
                observation.length,
                observation.sha256.hex()
            )
        },
    )
}

#[cfg(windows)]
fn bounded_windows_directory_inventory(directory: &Path) -> String {
    const ENTRY_LIMIT: usize = 32;
    const TEXT_LIMIT: usize = 4_096;

    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) => return format!("<unavailable:{error}>"),
    };
    let mut inventory = Vec::new();
    let mut truncated = false;
    for entry in entries {
        if inventory.len() == ENTRY_LIMIT {
            truncated = true;
            break;
        }
        let item = match entry {
            Ok(entry) => match fs::symlink_metadata(entry.path()) {
                Ok(metadata) => {
                    let kind = if metadata.file_type().is_symlink() {
                        "symlink"
                    } else if metadata.is_dir() {
                        "directory"
                    } else if metadata.is_file() {
                        "file"
                    } else {
                        "special"
                    };
                    format!("{:?}:{kind}", entry.file_name())
                }
                Err(error) => format!("{:?}:<unavailable:{error}>", entry.file_name()),
            },
            Err(error) => format!("<unavailable:{error}>"),
        };
        inventory.push(item);
    }
    inventory.sort();
    if truncated {
        inventory.push("<truncated>".to_owned());
    }
    let mut text = format!("[{}]", inventory.join(","));
    if text.len() > TEXT_LIMIT {
        let mut boundary = TEXT_LIMIT;
        while !text.is_char_boundary(boundary) {
            boundary -= 1;
        }
        text.truncate(boundary);
        text.push_str("<truncated>]");
    }
    text
}

/// Exact executable authorities for the Windows restricted-child boundary.
#[cfg(windows)]
#[derive(Clone, Debug)]
pub struct WindowsLaunchAuthorities {
    launcher: BoundProgramInvocation,
    restricted_adapter: BoundProgramInvocation,
    toolchain: WindowsToolchainAuthority,
}

/// Exact source-to-stage executable mapping for the selected Windows Rustup toolchain.
#[cfg(windows)]
#[derive(Clone, Debug)]
pub struct WindowsToolchainAuthority {
    cargo_source: BoundProgramInvocation,
    rustc_source: BoundProgramInvocation,
    selected_cargo: BoundProgramInvocation,
    staged_cargo: BoundProgramInvocation,
    selected_rustc: BoundProgramInvocation,
    staged_rustc: BoundProgramInvocation,
    inventory_root: PathBuf,
    inventory_files: Arc<[BoundProgramInvocation]>,
    inventory_directories: Arc<[PathBuf]>,
    trusted_parent_path: OsString,
    trusted_path_entries: Arc<[WindowsTrustedPathEntry]>,
    system_root: WindowsSystemRootAuthority,
    inventory_full_hash_passes: usize,
    lifecycle_execution_deadline: Option<Instant>,
}

#[cfg(windows)]
enum WindowsToolchainInventoryInput {
    Paths(Vec<PathBuf>),
    Promoted(Vec<BoundProgramInvocation>),
}

#[cfg(windows)]
#[derive(Clone, Debug)]
struct WindowsSystemRootAuthority {
    value: OsString,
    root: WindowsPresentTrustedPathEntry,
    system32: WindowsPresentTrustedPathEntry,
}

#[cfg(windows)]
#[derive(Clone, Debug)]
enum WindowsTrustedPathEntry {
    Present(WindowsPresentTrustedPathEntry),
    Absent(WindowsAbsentTrustedPathEntry),
}

#[cfg(windows)]
#[derive(Clone, Debug)]
struct WindowsPresentTrustedPathEntry {
    invocation_path: PathBuf,
    canonical_identity: PathBuf,
    identity: Arc<same_file::Handle>,
}

#[cfg(windows)]
impl WindowsTrustedPathEntry {
    fn bind(path: PathBuf) -> std::io::Result<Self> {
        validate_windows_trusted_path_spelling(&path)?;
        match fs::symlink_metadata(&path) {
            Ok(_) => WindowsPresentTrustedPathEntry::bind(path).map(Self::Present),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                WindowsAbsentTrustedPathEntry::bind(path).map(Self::Absent)
            }
            Err(error) => Err(error),
        }
    }

    fn revalidate(&self) -> std::io::Result<()> {
        match self {
            Self::Present(entry) => entry.revalidate(),
            Self::Absent(entry) => entry.revalidate(),
        }
    }

    fn canonical_identity(&self) -> Option<&Path> {
        match self {
            Self::Present(entry) => Some(&entry.canonical_identity),
            Self::Absent(_) => None,
        }
    }
}

#[cfg(windows)]
impl WindowsPresentTrustedPathEntry {
    fn bind(path: PathBuf) -> std::io::Result<Self> {
        use std::os::windows::fs::MetadataExt as _;

        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        validate_windows_trusted_path_spelling(&path)?;
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "trusted Windows PATH entry is not a direct directory",
            ));
        }
        let canonical_identity = fs::canonicalize(&path)?;
        let canonical_metadata = fs::symlink_metadata(&canonical_identity)?;
        if !canonical_metadata.is_dir()
            || canonical_metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "trusted Windows PATH identity is not a direct directory",
            ));
        }
        Ok(Self {
            invocation_path: path,
            identity: Arc::new(same_file::Handle::from_path(&canonical_identity)?),
            canonical_identity,
        })
    }

    fn revalidate(&self) -> std::io::Result<()> {
        use std::os::windows::fs::MetadataExt as _;

        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        let metadata = fs::symlink_metadata(&self.invocation_path)?;
        if !metadata.is_dir()
            || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || fs::canonicalize(&self.invocation_path)? != self.canonical_identity
            || same_file::Handle::from_path(&self.canonical_identity)? != *self.identity
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "trusted Windows PATH directory identity changed",
            ));
        }
        Ok(())
    }
}

#[cfg(windows)]
impl WindowsSystemRootAuthority {
    fn bind(value: OsString, trusted_path: &[WindowsTrustedPathEntry]) -> std::io::Result<Self> {
        let root = WindowsPresentTrustedPathEntry::bind(PathBuf::from(&value))?;
        let system32 = WindowsPresentTrustedPathEntry::bind(root.invocation_path.join("System32"))?;
        let system32_parent = system32.canonical_identity.parent().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "trusted Windows System32 has no parent",
            )
        })?;
        if same_file::Handle::from_path(system32_parent)? != *root.identity {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "trusted Windows System32 is not a direct child of SystemRoot",
            ));
        }
        let path_contains = |required: &WindowsPresentTrustedPathEntry| {
            trusted_path.iter().any(|entry| {
                matches!(
                    entry,
                    WindowsTrustedPathEntry::Present(present)
                        if *present.identity == *required.identity
                )
            })
        };
        if !path_contains(&root) || !path_contains(&system32) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "trusted Windows PATH does not contain its exact SystemRoot and System32",
            ));
        }
        let authority = Self {
            value,
            root,
            system32,
        };
        authority.revalidate()?;
        Ok(authority)
    }

    fn revalidate(&self) -> std::io::Result<()> {
        self.root.revalidate()?;
        self.system32.revalidate()?;
        let system32_parent = self.system32.canonical_identity.parent().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "trusted Windows System32 has no parent",
            )
        })?;
        if same_file::Handle::from_path(system32_parent)? != *self.root.identity {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "trusted Windows SystemRoot relation changed",
            ));
        }
        Ok(())
    }
}

#[cfg(windows)]
#[derive(Clone, Debug)]
struct WindowsAbsentTrustedPathEntry {
    invocation_path: PathBuf,
    first_absent_path: PathBuf,
    existing_ancestor: WindowsPresentTrustedPathEntry,
}

#[cfg(windows)]
impl WindowsAbsentTrustedPathEntry {
    fn bind(invocation_path: PathBuf) -> std::io::Result<Self> {
        validate_windows_trusted_path_spelling(&invocation_path)?;
        let mut first_absent_path = invocation_path.clone();
        let mut ancestor = invocation_path
            .parent()
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "absent trusted Windows PATH entry has no parent",
                )
            })?
            .to_path_buf();
        loop {
            match fs::symlink_metadata(&ancestor) {
                Ok(_) => {
                    return Ok(Self {
                        invocation_path,
                        first_absent_path,
                        existing_ancestor: WindowsPresentTrustedPathEntry::bind(ancestor)?,
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    first_absent_path.clone_from(&ancestor);
                    ancestor = ancestor
                        .parent()
                        .ok_or_else(|| {
                            std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "absent trusted Windows PATH entry has no existing ancestor",
                            )
                        })?
                        .to_path_buf();
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn revalidate(&self) -> std::io::Result<()> {
        self.existing_ancestor.revalidate()?;
        match fs::symlink_metadata(&self.first_absent_path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Ok(_) => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "absent trusted Windows PATH entry appeared: {}",
                    self.invocation_path.display()
                ),
            )),
            Err(error) => Err(error),
        }
    }
}

#[cfg(windows)]
fn validate_windows_trusted_path_spelling(path: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt as _;

    let has_raw_dot_component = path
        .as_os_str()
        .encode_wide()
        .collect::<Vec<_>>()
        .split(|unit| *unit == u16::from(b'\\') || *unit == u16::from(b'/'))
        .any(|component| {
            component == [u16::from(b'.')] || component == [u16::from(b'.'), u16::from(b'.')]
        });
    if !path.is_absolute() || path_has_lexical_dot_component(path) || has_raw_dot_component {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "trusted Windows PATH entry is not absolute and lexical",
        ));
    }
    Ok(())
}

/// One exact Rustup proxy/selected source/staged executable mapping.
#[cfg(windows)]
#[derive(Clone, Debug)]
pub struct WindowsToolchainExecutableAuthority {
    source_invocation: PathBuf,
    source_identity: PathBuf,
    selected: PathBuf,
    staged: PathBuf,
}

/// Closed operation labels for failures while binding a staged Windows Rust
/// toolchain. These labels keep hosted diagnostics actionable without changing
/// which paths or identities the authority accepts.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsToolchainBindOperation {
    CanonicalizeInventoryRoot,
    BindTrustedPathEntry,
    BindSystemRoot,
    BindCargoSource,
    BindRustcSource,
    BindSelectedCargo,
    BindStagedCargo,
    BindSelectedRustc,
    BindStagedRustc,
    BindInventoryFile,
    HashSelectedCargo,
    HashStagedCargo,
    HashSelectedRustc,
    HashStagedRustc,
    RevalidateInventory,
}

impl std::fmt::Display for WindowsToolchainBindOperation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::CanonicalizeInventoryRoot => "canonicalize-inventory-root",
            Self::BindTrustedPathEntry => "bind-trusted-path-entry",
            Self::BindSystemRoot => "bind-system-root",
            Self::BindCargoSource => "bind-cargo-source",
            Self::BindRustcSource => "bind-rustc-source",
            Self::BindSelectedCargo => "bind-selected-cargo",
            Self::BindStagedCargo => "bind-staged-cargo",
            Self::BindSelectedRustc => "bind-selected-rustc",
            Self::BindStagedRustc => "bind-staged-rustc",
            Self::BindInventoryFile => "bind-inventory-file",
            Self::HashSelectedCargo => "hash-selected-cargo",
            Self::HashStagedCargo => "hash-staged-cargo",
            Self::HashSelectedRustc => "hash-selected-rustc",
            Self::HashStagedRustc => "hash-staged-rustc",
            Self::RevalidateInventory => "revalidate-inventory",
        };
        formatter.write_str(label)
    }
}

/// Retains the original I/O error kind while attaching a closed operation and
/// the exact path on which the trusted binding failed.
#[doc(hidden)]
#[must_use]
pub fn windows_toolchain_bind_failure(
    operation: WindowsToolchainBindOperation,
    path: &Path,
    error: &std::io::Error,
) -> std::io::Error {
    let raw_os_error = error
        .raw_os_error()
        .map_or_else(|| "none".to_owned(), |code| code.to_string());
    std::io::Error::new(
        error.kind(),
        format!(
            "operation={operation} path={} kind={:?} osError={raw_os_error} source={error}",
            path.display(),
            error.kind()
        ),
    )
}

#[cfg(windows)]
impl WindowsToolchainExecutableAuthority {
    /// Describes a standard Rustup proxy mapped to one selected staged tool.
    #[must_use]
    pub fn rustup_proxy(
        proxy: PathBuf,
        proxy_identity: PathBuf,
        selected: PathBuf,
        staged: PathBuf,
    ) -> Self {
        Self {
            source_invocation: proxy,
            source_identity: proxy_identity,
            selected,
            staged,
        }
    }

    /// Describes the exact selected toolchain executable mapped to its staged copy.
    #[must_use]
    pub fn selected_toolchain(
        invocation: PathBuf,
        identity: PathBuf,
        selected: PathBuf,
        staged: PathBuf,
    ) -> Self {
        Self {
            source_invocation: invocation,
            source_identity: identity,
            selected,
            staged,
        }
    }
}

#[cfg(windows)]
impl WindowsToolchainAuthority {
    /// Binds the two typed Rust tool sources and exact selected/staged executables.
    ///
    /// # Errors
    ///
    /// Returns an error if any path is redirected or substituted, or if a staged
    /// executable does not have the exact bytes of its selected source.
    pub fn new(
        cargo: WindowsToolchainExecutableAuthority,
        rustc: WindowsToolchainExecutableAuthority,
        inventory_root: PathBuf,
        inventory_files: Vec<PathBuf>,
        inventory_directories: Vec<PathBuf>,
        trusted_parent_path: OsString,
        trusted_parent_system_root: OsString,
    ) -> std::io::Result<Self> {
        let acquisition_deadline = windows_program_authority_acquisition_deadline()?;
        Self::new_until(
            cargo,
            rustc,
            inventory_root,
            inventory_files,
            inventory_directories,
            trusted_parent_path,
            trusted_parent_system_root,
            acquisition_deadline,
        )
    }

    /// Binds one selected/staged Rust toolchain before an existing absolute deadline.
    ///
    /// # Errors
    ///
    /// Returns an error if the deadline expires or any path is redirected,
    /// substituted, or differs from the closed staged inventory.
    pub fn new_until(
        cargo: WindowsToolchainExecutableAuthority,
        rustc: WindowsToolchainExecutableAuthority,
        inventory_root: PathBuf,
        inventory_files: Vec<PathBuf>,
        inventory_directories: Vec<PathBuf>,
        trusted_parent_path: OsString,
        trusted_parent_system_root: OsString,
        acquisition_deadline: Instant,
    ) -> std::io::Result<Self> {
        Self::new_with_inventory_until(
            cargo,
            rustc,
            inventory_root,
            WindowsToolchainInventoryInput::Paths(inventory_files),
            inventory_directories,
            trusted_parent_path,
            trusted_parent_system_root,
            acquisition_deadline,
            None,
        )
    }

    /// Promotes an already-hashed staged inventory into the selected toolchain authority.
    ///
    /// # Errors
    ///
    /// Returns an error unless every promoted member remains an exact direct
    /// child of the closed staged inventory and the selected Cargo/rustc
    /// mappings name exact promoted members.
    #[doc(hidden)]
    pub fn new_from_promoted_inventory_until(
        cargo: WindowsToolchainExecutableAuthority,
        rustc: WindowsToolchainExecutableAuthority,
        inventory_root: PathBuf,
        inventory_files: Vec<BoundProgramInvocation>,
        inventory_directories: Vec<PathBuf>,
        trusted_parent_path: OsString,
        trusted_parent_system_root: OsString,
        acquisition_deadline: Instant,
        lifecycle_execution_deadline: Instant,
    ) -> std::io::Result<Self> {
        Self::new_with_inventory_until(
            cargo,
            rustc,
            inventory_root,
            WindowsToolchainInventoryInput::Promoted(inventory_files),
            inventory_directories,
            trusted_parent_path,
            trusted_parent_system_root,
            acquisition_deadline,
            Some(lifecycle_execution_deadline),
        )
    }

    fn new_with_inventory_until(
        cargo: WindowsToolchainExecutableAuthority,
        rustc: WindowsToolchainExecutableAuthority,
        inventory_root: PathBuf,
        inventory: WindowsToolchainInventoryInput,
        inventory_directories: Vec<PathBuf>,
        trusted_parent_path: OsString,
        trusted_parent_system_root: OsString,
        acquisition_deadline: Instant,
        lifecycle_execution_deadline: Option<Instant>,
    ) -> std::io::Result<Self> {
        if lifecycle_execution_deadline
            .is_some_and(|lifecycle_deadline| lifecycle_deadline < acquisition_deadline)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Windows toolchain lifecycle deadline precedes receipt acquisition",
            ));
        }
        if Instant::now() >= acquisition_deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Windows toolchain authority acquisition deadline expired before binding",
            ));
        }
        let inventory_root = fs::canonicalize(&inventory_root).map_err(|error| {
            windows_toolchain_bind_failure(
                WindowsToolchainBindOperation::CanonicalizeInventoryRoot,
                &inventory_root,
                &error,
            )
        })?;
        let mut trusted_path_entries = Vec::new();
        for path in std::env::split_paths(&trusted_parent_path) {
            let entry = WindowsTrustedPathEntry::bind(path.clone()).map_err(|error| {
                windows_toolchain_bind_failure(
                    WindowsToolchainBindOperation::BindTrustedPathEntry,
                    &path,
                    &error,
                )
            })?;
            trusted_path_entries.push(entry);
        }
        if trusted_path_entries.is_empty()
            || trusted_path_entries.len() > 128
            || !trusted_path_entries
                .iter()
                .any(|entry| entry.canonical_identity().is_some())
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "trusted Windows PATH has an invalid entry count",
            ));
        }
        let system_root_path = PathBuf::from(&trusted_parent_system_root);
        let system_root =
            WindowsSystemRootAuthority::bind(trusted_parent_system_root, &trusted_path_entries)
                .map_err(|error| {
                    windows_toolchain_bind_failure(
                        WindowsToolchainBindOperation::BindSystemRoot,
                        &system_root_path,
                        &error,
                    )
                })?;
        let cargo_source_path = cargo.source_identity.clone();
        let rustc_source_path = rustc.source_identity.clone();
        let selected_cargo_path = cargo.selected.clone();
        let staged_cargo_path = cargo.staged.clone();
        let selected_rustc_path = rustc.selected.clone();
        let staged_rustc_path = rustc.staged.clone();
        let cargo_source = BoundProgramInvocation::new_until(
            cargo.source_invocation,
            cargo.source_identity,
            acquisition_deadline,
        )
        .map_err(|error| {
            windows_toolchain_bind_failure(
                WindowsToolchainBindOperation::BindCargoSource,
                &cargo_source_path,
                &error,
            )
        })?;
        let rustc_source = BoundProgramInvocation::new_until(
            rustc.source_invocation,
            rustc.source_identity,
            acquisition_deadline,
        )
        .map_err(|error| {
            windows_toolchain_bind_failure(
                WindowsToolchainBindOperation::BindRustcSource,
                &rustc_source_path,
                &error,
            )
        })?;
        let selected_cargo = BoundProgramInvocation::new_until(
            selected_cargo_path.clone(),
            selected_cargo_path.clone(),
            acquisition_deadline,
        )
        .map_err(|error| {
            windows_toolchain_bind_failure(
                WindowsToolchainBindOperation::BindSelectedCargo,
                &selected_cargo_path,
                &error,
            )
        })?;
        let selected_rustc = BoundProgramInvocation::new_until(
            selected_rustc_path.clone(),
            selected_rustc_path.clone(),
            acquisition_deadline,
        )
        .map_err(|error| {
            windows_toolchain_bind_failure(
                WindowsToolchainBindOperation::BindSelectedRustc,
                &selected_rustc_path,
                &error,
            )
        })?;
        let (inventory_files, inventory_full_hash_passes) = match inventory {
            WindowsToolchainInventoryInput::Paths(paths) => (
                paths
                    .into_iter()
                    .map(|path| {
                        BoundProgramInvocation::new_until(
                            path.clone(),
                            path.clone(),
                            acquisition_deadline,
                        )
                        .map_err(|error| {
                            windows_toolchain_bind_failure(
                                WindowsToolchainBindOperation::BindInventoryFile,
                                &path,
                                &error,
                            )
                        })
                    })
                    .collect::<std::io::Result<Vec<_>>>()?,
                1,
            ),
            WindowsToolchainInventoryInput::Promoted(files) => {
                for file in &files {
                    if Instant::now() >= acquisition_deadline {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "staged Windows toolchain promotion exceeded its absolute deadline",
                        ));
                    }
                    if file.invocation_path != file.canonical_identity
                        || !file.invocation_path.starts_with(&inventory_root)
                        || file.invocation_path == inventory_root
                    {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "promoted Windows toolchain member is outside the staged inventory",
                        ));
                    }
                    file.revalidate(file.invocation_path.as_os_str())?;
                }
                (files, 0)
            }
        };
        let unique_files = inventory_files
            .iter()
            .map(|file| file.invocation_path.clone())
            .collect::<BTreeSet<_>>();
        if unique_files.len() != inventory_files.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "staged Windows toolchain inventory contains duplicate files",
            ));
        }
        let staged_member = |path: &Path,
                             operation: WindowsToolchainBindOperation|
         -> std::io::Result<BoundProgramInvocation> {
            inventory_files
                .iter()
                .find(|file| file.invocation_path == path)
                .cloned()
                .ok_or_else(|| {
                    windows_toolchain_bind_failure(
                        operation,
                        path,
                        &std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "selected staged executable is absent from the promoted inventory",
                        ),
                    )
                })
        };
        let staged_cargo = staged_member(
            &staged_cargo_path,
            WindowsToolchainBindOperation::BindStagedCargo,
        )?;
        let staged_rustc = staged_member(
            &staged_rustc_path,
            WindowsToolchainBindOperation::BindStagedRustc,
        )?;
        let authority = Self {
            cargo_source,
            rustc_source,
            selected_cargo,
            staged_cargo,
            selected_rustc,
            staged_rustc,
            inventory_root,
            inventory_files: inventory_files.into(),
            inventory_directories: inventory_directories.into(),
            trusted_parent_path,
            trusted_path_entries: trusted_path_entries.into(),
            system_root,
            inventory_full_hash_passes,
            lifecycle_execution_deadline,
        };
        let selected_cargo_sha = authority.selected_cargo.sha256();
        let staged_cargo_sha = authority.staged_cargo.sha256();
        let selected_rustc_sha = authority.selected_rustc.sha256();
        let staged_rustc_sha = authority.staged_rustc.sha256();
        if selected_cargo_sha != staged_cargo_sha || selected_rustc_sha != staged_rustc_sha {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "staged Windows Rust executable differs from selected source",
            ));
        }
        authority
            .revalidate_inventory_until(acquisition_deadline)
            .map_err(|error| {
                windows_toolchain_bind_failure(
                    WindowsToolchainBindOperation::RevalidateInventory,
                    &authority.inventory_root,
                    &error,
                )
            })?;
        Ok(authority)
    }

    /// Revalidates the closed staged inventory and every held file authority.
    ///
    /// # Errors
    ///
    /// Returns an error if an entry was added, removed, redirected, or changed.
    pub fn revalidate(&self) -> std::io::Result<()> {
        self.revalidate_inventory()?;
        for entry in self.trusted_path_entries.iter() {
            entry.revalidate()?;
        }
        self.system_root.revalidate()?;
        Ok(())
    }

    /// Resolves an exact trusted Rust proxy/source request to its staged executable.
    ///
    /// # Errors
    ///
    /// Returns an error if the closed inventory changed or a Rust tool request
    /// is outside the bound proxy/source authority.
    pub fn mapped_program(
        &self,
        requested: &OsStr,
        resolved: &Path,
    ) -> std::io::Result<Option<PathBuf>> {
        let request_matches = |logical: &str, authority: &BoundProgramInvocation| {
            (requested == authority.invocation_path.as_os_str()
                && resolved == authority.invocation_path)
                || (requested == OsStr::new(logical) && resolved == authority.canonical_identity)
        };
        let mapping = if request_matches("cargo", &self.cargo_source) {
            Some((&self.cargo_source, &self.selected_cargo, &self.staged_cargo))
        } else if request_matches("rustc", &self.rustc_source) {
            Some((&self.rustc_source, &self.selected_rustc, &self.staged_rustc))
        } else {
            None
        };
        let Some((source, selected, staged)) = mapping else {
            if windows_executable_has_logical_name(requested, "cargo")
                || windows_executable_has_logical_name(requested, "rustc")
                || windows_executable_has_logical_name(resolved.as_os_str(), "cargo")
                || windows_executable_has_logical_name(resolved.as_os_str(), "rustc")
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "Windows Rust tool request is outside the selected toolchain authority",
                ));
            }
            return Ok(None);
        };
        self.revalidate_inventory()?;
        source.revalidate(source.invocation_path.as_os_str())?;
        selected.revalidate(selected.invocation_path.as_os_str())?;
        staged
            .revalidate(staged.invocation_path.as_os_str())
            .map(Some)
    }

    /// Produces the closed child PATH containing only the staged Rust bin,
    /// System32, and SystemRoot after revalidating the trusted parent capture.
    ///
    /// # Errors
    ///
    /// Returns an error if the child changed PATH or any bound directory was
    /// redirected or substituted.
    pub fn restricted_child_path(&self, supplied: &OsStr) -> std::io::Result<OsString> {
        if supplied != self.trusted_parent_path {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Windows release child PATH differs from its trusted parent capture",
            ));
        }
        self.revalidate()?;
        let staged_rustc = self
            .staged_rustc
            .revalidate(self.staged_rustc.invocation_path.as_os_str())?;
        let staged_bin = staged_rustc.parent().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "staged Windows rustc has no bin directory",
            )
        })?;
        if self.staged_cargo.canonical_identity.parent() != Some(staged_bin)
            || !self
                .inventory_directories
                .iter()
                .any(|directory| directory == staged_bin)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "staged Windows Cargo and rustc do not share the inventoried bin directory",
            ));
        }
        std::env::join_paths([
            staged_bin.to_path_buf(),
            self.system_root.system32.canonical_identity.clone(),
            self.system_root.root.canonical_identity.clone(),
        ])
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))
    }

    fn revalidate_inventory(&self) -> std::io::Result<()> {
        self.revalidate_inventory_with_deadline(self.lifecycle_execution_deadline)
    }

    fn revalidate_inventory_until(&self, deadline: Instant) -> std::io::Result<()> {
        self.revalidate_inventory_with_deadline(Some(deadline))
    }

    fn revalidate_inventory_with_deadline(&self, deadline: Option<Instant>) -> std::io::Result<()> {
        use std::os::windows::fs::MetadataExt as _;

        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        let require_time = || {
            if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "staged Windows toolchain cheap revalidation exceeded its absolute deadline",
                ));
            }
            Ok(())
        };
        let mut expected = BTreeSet::new();
        for directory in self.inventory_directories.iter() {
            require_time()?;
            expected.insert((directory.clone(), true));
        }
        for file in self.inventory_files.iter() {
            require_time()?;
            expected.insert((file.invocation_path.clone(), false));
            file.revalidate(file.invocation_path.as_os_str())?;
        }
        if expected.len() != self.inventory_directories.len() + self.inventory_files.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "staged Windows toolchain expected inventory contains duplicates",
            ));
        }
        let mut observed = BTreeSet::new();
        let mut pending = vec![self.inventory_root.clone()];
        while let Some(directory) = pending.pop() {
            require_time()?;
            let metadata = fs::symlink_metadata(&directory)?;
            if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "staged Windows toolchain directory identity changed",
                ));
            }
            observed.insert((directory.clone(), true));
            for entry in fs::read_dir(&directory)? {
                require_time()?;
                let path = entry?.path();
                let metadata = fs::symlink_metadata(&path)?;
                if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "staged Windows toolchain gained a reparse point",
                    ));
                }
                if metadata.is_dir() {
                    pending.push(path);
                } else if metadata.is_file() {
                    observed.insert((path, false));
                } else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "staged Windows toolchain gained a special entry",
                    ));
                }
                if observed.len() + pending.len() > expected.len() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "staged Windows toolchain observed inventory exceeds its closed bound",
                    ));
                }
            }
        }
        if observed != expected {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "staged Windows toolchain closed inventory changed",
            ));
        }
        Ok(())
    }

    /// Returns the number of complete staged-inventory hash passes performed
    /// while constructing this authority.
    #[doc(hidden)]
    #[must_use]
    pub const fn windows_inventory_full_hash_passes_for_integration(&self) -> usize {
        self.inventory_full_hash_passes
    }
}

/// Selects the one standard Windows SystemRoot value from the parent process.
///
/// # Errors
///
/// Returns an error unless exactly one nonempty case-insensitive SystemRoot
/// entry is present.
#[cfg(windows)]
pub fn capture_windows_standard_system_root() -> std::io::Result<OsString> {
    let mut values = std::env::vars_os().filter(|(name, _)| {
        name.to_str()
            .is_some_and(|name| name.eq_ignore_ascii_case("SystemRoot"))
    });
    let (_, value) = values.next().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "trusted Windows parent has no SystemRoot",
        )
    })?;
    if value.is_empty() || values.next().is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "trusted Windows parent SystemRoot is empty or duplicated",
        ));
    }
    Ok(value)
}

/// Applies one exact captured SystemRoot value to a raw Windows child
/// environment vector.
///
/// This is public only so host-portable tests can exercise case-insensitive
/// duplicate, removal, disagreement, and injection behavior without mutating
/// the process environment.
///
/// # Errors
///
/// Returns an error if SystemRoot is duplicated, explicitly removed, or
/// differs from the captured standard value.
#[doc(hidden)]
pub fn configure_windows_standard_system_root_value(
    environment: &mut Vec<(OsString, Option<OsString>)>,
    captured: &OsStr,
    required: bool,
) -> std::io::Result<()> {
    let indices = environment
        .iter()
        .enumerate()
        .filter(|(_, (name, _))| {
            name.to_str()
                .is_some_and(|name| name.eq_ignore_ascii_case("SystemRoot"))
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if indices.len() > 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Windows release child has duplicate SystemRoot entries",
        ));
    }
    match indices.first().copied() {
        Some(index) => {
            let supplied = environment[index].1.as_deref().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "Windows release child removed its trusted SystemRoot",
                )
            })?;
            if supplied != captured {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "Windows release child SystemRoot differs from its trusted parent capture",
                ));
            }
            environment[index] = (OsString::from("SystemRoot"), Some(captured.to_owned()));
        }
        None if required => {
            environment.push((OsString::from("SystemRoot"), Some(captured.to_owned())));
        }
        None => {}
    }
    Ok(())
}

/// Rewrites the exact Windows child PATH at the restricted launch boundary.
///
/// This is public only so the Windows portability suite can exercise the raw
/// environment-vector boundary, including duplicate case spellings that
/// `std::process::Command` may coalesce.
///
/// # Errors
///
/// Returns an error if an explicit PATH is removed, duplicated, or differs
/// from the trusted parent capture, or if a bound directory changed.
#[cfg(windows)]
#[doc(hidden)]
pub fn configure_windows_restricted_child_path(
    toolchain: &WindowsToolchainAuthority,
    environment: &mut Vec<(OsString, Option<OsString>)>,
    requires_trusted_path: bool,
) -> std::io::Result<()> {
    let path_indices = environment
        .iter()
        .enumerate()
        .filter(|(_, (name, _))| {
            name.to_str()
                .is_some_and(|name| name.eq_ignore_ascii_case("PATH"))
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if path_indices.len() > 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Windows release child has duplicate PATH entries",
        ));
    }
    let restricted_path = match path_indices.first().copied() {
        Some(index) => {
            let supplied_path = environment[index].1.as_deref().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "Windows release child removed its trusted PATH",
                )
            })?;
            Some(toolchain.restricted_child_path(supplied_path)?)
        }
        None if requires_trusted_path => {
            Some(toolchain.restricted_child_path(&toolchain.trusted_parent_path)?)
        }
        None => None,
    };
    if let Some(restricted_path) = restricted_path {
        if let Some(index) = path_indices.first().copied() {
            environment[index] = (OsString::from("PATH"), Some(restricted_path));
        } else {
            environment.push((OsString::from("PATH"), Some(restricted_path)));
        }
    }
    Ok(())
}

/// Rewrites the exact trusted loader environment for a Windows restricted child.
///
/// This is public only so the Windows portability suite can exercise the
/// mapped-tool boundary.
///
/// # Errors
///
/// Returns an error if the mapped-tool PATH or SystemRoot differs from its
/// bound parent value, is removed or duplicated, or if any bound directory
/// identity changed.
#[cfg(windows)]
#[doc(hidden)]
pub fn configure_windows_restricted_child_environment(
    toolchain: &WindowsToolchainAuthority,
    environment: &mut Vec<(OsString, Option<OsString>)>,
    requires_trusted_path: bool,
) -> std::io::Result<()> {
    configure_windows_restricted_child_path(toolchain, environment, requires_trusted_path)?;
    toolchain.system_root.revalidate()?;
    configure_windows_standard_system_root_value(environment, &toolchain.system_root.value, true)
}

#[cfg(any(windows, test))]
fn windows_executable_has_logical_name(path: &OsStr, expected: &str) -> bool {
    let path = Path::new(path);
    path.file_stem()
        .and_then(OsStr::to_str)
        .is_some_and(|name| name.eq_ignore_ascii_case(expected))
        && path
            .extension()
            .and_then(OsStr::to_str)
            .is_some_and(|extension| {
                extension.eq_ignore_ascii_case("exe") || extension.eq_ignore_ascii_case("com")
            })
}

#[cfg(any(windows, test))]
fn windows_program_requires_trusted_path(
    requested: &OsStr,
    resolved: &Path,
    mapped_toolchain_program: bool,
) -> bool {
    mapped_toolchain_program
        || windows_executable_has_logical_name(requested, "stack")
        || windows_executable_has_logical_name(resolved.as_os_str(), "stack")
}

#[cfg(windows)]
impl WindowsLaunchAuthorities {
    /// Binds the unrestricted token launcher and the minimal executable that
    /// enters under the restricted token.
    ///
    /// # Errors
    ///
    /// Returns an error unless both programs can be bound under one acquisition deadline.
    pub fn new(
        launcher: PathBuf,
        restricted_adapter: PathBuf,
        toolchain: WindowsToolchainAuthority,
    ) -> std::io::Result<Self> {
        let deadline = windows_program_authority_acquisition_deadline()?;
        Self::new_until(launcher, restricted_adapter, toolchain, deadline)
    }

    /// Binds both Windows launch programs before an existing absolute deadline.
    ///
    /// # Errors
    ///
    /// Returns an error if the deadline expires or either program changes.
    pub fn new_until(
        launcher: PathBuf,
        restricted_adapter: PathBuf,
        toolchain: WindowsToolchainAuthority,
        deadline: Instant,
    ) -> std::io::Result<Self> {
        let launcher = fs::canonicalize(launcher)?;
        let launcher = BoundProgramInvocation::new_until(launcher.clone(), launcher, deadline)?;
        let restricted_adapter = fs::canonicalize(restricted_adapter)?;
        let restricted_adapter = BoundProgramInvocation::new_until(
            restricted_adapter.clone(),
            restricted_adapter,
            deadline,
        )?;
        if restricted_adapter.canonical_identity.file_name()
            != Some(OsStr::new("hell-test-helper.exe"))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "restricted argv adapter identity changed",
            ));
        }
        Ok(Self {
            launcher,
            restricted_adapter,
            toolchain,
        })
    }
}

/// Exact staged executable authorities for a POSIX release child.
#[cfg(unix)]
#[derive(Clone, Debug)]
pub struct PosixLaunchAuthorities {
    adapter: PathBuf,
    adapter_sha256: Digest,
    cargo_source: PathBuf,
    cargo_adapter: PathBuf,
    cargo_adapter_sha256: Digest,
    cargo_authority: PosixCargoSourceAuthority,
    cargo_deny_authority: Option<PosixCargoDenyAuthority>,
    stack_authority: Option<PosixStackAuthority>,
}

/// Fixed role of one trusted POSIX process-lifecycle executable.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PosixProcessToolRole {
    Sudo,
    Identity,
    Inventory,
    Terminator,
}

/// Exact metadata and content receipt for one trusted POSIX executable.
#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PosixExecutableMetadata {
    device: u64,
    inode: u64,
    owner: u32,
    group: u32,
    mode: u32,
    bytes: u64,
}

/// Exact no-follow-independent metadata receipt for a canonical invocation parent.
#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PosixExecutableParentMetadata {
    device: u64,
    inode: u64,
    owner: u32,
    group: u32,
    mode: u32,
}

/// Parent-resolved invocation and exact file receipt for one POSIX tool.
#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PosixExecutableAuthority {
    role: PosixProcessToolRole,
    invocation: PathBuf,
    logical_name: Option<OsString>,
    parent_metadata: Option<PosixExecutableParentMetadata>,
    canonical: PathBuf,
    metadata: PosixExecutableMetadata,
}

/// Complete parent-resolved authority used for candidate process lifecycle.
#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PosixProcessAuthorities {
    sudo: PosixExecutableAuthority,
    identity: PosixExecutableAuthority,
    inventory: PosixExecutableAuthority,
    terminator: PosixExecutableAuthority,
}

/// Exact source-to-stage authority for the pinned POSIX `cargo-deny` binary.
#[cfg(unix)]
#[derive(Clone, Debug)]
pub struct PosixCargoDenyAuthority {
    source: PosixStandardExecutableIdentity,
    source_sha256: Digest,
    staged: PathBuf,
    staged_sha256: Digest,
    cargo_home: PathBuf,
    metadata: PosixCargoDenyMetadataAuthority,
    trusted_owner: u32,
    trusted_group_id: u32,
}

/// Trusted ownership assigned to the read-only portion of a staged POSIX
/// `cargo-deny` Cargo home.
#[cfg(unix)]
#[derive(Clone, Copy, Debug)]
pub struct PosixCargoDenyCacheOwnership {
    trusted_owner: u32,
    trusted_group_id: u32,
}

/// Exact read-only Cargo metadata document supplied to pinned `cargo-deny`.
#[cfg(unix)]
#[derive(Clone, Debug)]
pub struct PosixCargoDenyMetadataAuthority {
    directory: PathBuf,
    path: PathBuf,
    size: u64,
    sha256: Digest,
    trusted_owner: u32,
}

/// Exact source-to-stage authority for the required POSIX `stack` binary.
#[cfg(unix)]
#[derive(Clone, Debug)]
pub struct PosixStackAuthority {
    source: PosixStandardExecutableIdentity,
    source_sha256: Digest,
    staged: PathBuf,
    staged_sha256: Digest,
    stack_root: PathBuf,
    trusted_group_id: u32,
}

/// Closed classification of the trusted Cargo source executable.
#[cfg(unix)]
#[derive(Clone, Debug)]
pub enum PosixCargoSourceAuthority {
    /// Cargo is distinct from the independently resolved standard Rustup.
    Native {
        cargo: PosixCanonicalExecutableIdentity,
        standard_rustup: PosixStandardExecutableIdentity,
    },
    /// Cargo is the independently resolved standard Rustup multicall binary.
    Rustup(Box<PosixRustupAuthority>),
}

/// Exact canonical identity of a trusted executable source.
#[cfg(unix)]
#[derive(Clone, Debug)]
pub struct PosixCanonicalExecutableIdentity {
    canonical: PathBuf,
    device: u64,
    inode: u64,
}

/// Exact invocation and file identity of an independently resolved standard tool.
#[cfg(unix)]
#[derive(Clone, Debug)]
pub struct PosixStandardExecutableIdentity {
    invocation: PathBuf,
    canonical: PathBuf,
    device: u64,
    inode: u64,
}

/// Canonical standard Rustup state required by a staged POSIX Cargo proxy.
#[cfg(unix)]
#[derive(Clone, Debug)]
pub struct PosixRustupAuthority {
    proxy_identity: PosixRustupProxyIdentity,
    rustc_authority: PosixRustcAuthority,
    source_home: PathBuf,
    home: PathBuf,
    toolchain: OsString,
    compiler_mapping: PosixRustupCompilerMapping,
}

/// Closed identity of the independently resolved standard `rustc` command.
#[cfg(unix)]
#[derive(Clone, Debug)]
pub enum PosixRustcAuthority {
    /// The standard `rustc` command is another logical name for Rustup.
    RustupProxy(PosixStandardExecutableIdentity),
    /// The standard `rustc` command is the exact selected toolchain compiler.
    SelectedToolchain(PosixStandardExecutableIdentity),
}

/// Exact source-to-staged compiler mapping for a selected Rustup toolchain.
#[cfg(unix)]
#[derive(Clone, Debug)]
pub struct PosixRustupCompilerMapping {
    source: PathBuf,
    source_sha256: Digest,
    staged: PathBuf,
    staged_sha256: Digest,
}

/// Exact same-file correspondence between Cargo's multicall entry point and
/// the independently resolved standard Rustup executable.
#[cfg(unix)]
#[derive(Clone, Debug)]
pub struct PosixRustupProxyIdentity {
    cargo_invocation: PathBuf,
    cargo: PathBuf,
    rustup_invocation: PathBuf,
    rustup: PathBuf,
    device: u64,
    inode: u64,
}

/// Exact account identity used to evaluate POSIX filesystem access.
#[cfg(unix)]
#[derive(Clone, Debug)]
pub struct PosixCandidateIdentity {
    principal: String,
    uid: u32,
    primary_gid: u32,
    group_ids: Vec<u32>,
}

#[cfg(unix)]
impl PosixCandidateIdentity {
    /// Binds the canonical account names and complete numeric group inventory.
    ///
    /// # Errors
    ///
    /// Returns an error when either account name is empty/non-alphanumeric or
    /// the group inventory is empty, duplicated, oversized, or omits the
    /// primary GID.
    pub fn new(
        principal: String,
        uid: u32,
        primary_gid: u32,
        group_ids: Vec<u32>,
        group: String,
    ) -> std::io::Result<Self> {
        let group = group.into_bytes();
        if principal.is_empty()
            || group.is_empty()
            || !principal.bytes().all(|byte| byte.is_ascii_alphanumeric())
            || !group.iter().all(u8::is_ascii_alphanumeric)
            || !posix_candidate_group_inventory_is_valid(primary_gid, &group_ids)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "candidate POSIX identity is not canonical",
            ));
        }
        Ok(Self {
            principal,
            uid,
            primary_gid,
            group_ids,
        })
    }
}

#[cfg(unix)]
impl PosixRustupAuthority {
    /// Binds the standard Rustup home and exact active toolchain name captured
    /// by the trusted parent.
    #[must_use]
    pub fn new(
        proxy_identity: PosixRustupProxyIdentity,
        rustc_authority: PosixRustcAuthority,
        source_home: PathBuf,
        home: PathBuf,
        toolchain: OsString,
        compiler_mapping: PosixRustupCompilerMapping,
    ) -> Self {
        Self {
            proxy_identity,
            rustc_authority,
            source_home,
            home,
            toolchain,
            compiler_mapping,
        }
    }
}

#[cfg(unix)]
impl PosixRustupCompilerMapping {
    /// Binds the selected source compiler to its exact staged counterpart.
    #[must_use]
    pub fn new(
        source: PathBuf,
        source_sha256: Digest,
        staged: PathBuf,
        staged_sha256: Digest,
    ) -> Self {
        Self {
            source,
            source_sha256,
            staged,
            staged_sha256,
        }
    }
}

#[cfg(unix)]
impl PosixStandardExecutableIdentity {
    /// Carries a parent-bound standard executable identity into launch policy.
    #[must_use]
    pub fn new(invocation: PathBuf, canonical: PathBuf, device: u64, inode: u64) -> Self {
        Self {
            invocation,
            canonical,
            device,
            inode,
        }
    }
}

#[cfg(unix)]
impl PosixCanonicalExecutableIdentity {
    /// Carries a parent-bound canonical executable identity into launch policy.
    #[must_use]
    pub fn new(canonical: PathBuf, device: u64, inode: u64) -> Self {
        Self {
            canonical,
            device,
            inode,
        }
    }
}

#[cfg(unix)]
impl PosixRustupProxyIdentity {
    /// Carries the parent-bound Unix file identity into staged launch policy.
    #[must_use]
    pub fn new(
        cargo_invocation: PathBuf,
        cargo: PathBuf,
        rustup_invocation: PathBuf,
        rustup: PathBuf,
        device: u64,
        inode: u64,
    ) -> Self {
        Self {
            cargo_invocation,
            cargo,
            rustup_invocation,
            rustup,
            device,
            inode,
        }
    }
}

#[cfg(unix)]
impl PosixLaunchAuthorities {
    /// Binds the trusted adapter and the source/staged identities of Cargo.
    #[must_use]
    pub fn new(
        adapter: PathBuf,
        adapter_sha256: Digest,
        cargo_source: PathBuf,
        cargo_adapter: PathBuf,
        cargo_adapter_sha256: Digest,
        cargo_authority: PosixCargoSourceAuthority,
    ) -> Self {
        Self {
            adapter,
            adapter_sha256,
            cargo_source,
            cargo_adapter,
            cargo_adapter_sha256,
            cargo_authority,
            cargo_deny_authority: None,
            stack_authority: None,
        }
    }

    /// Adds the exact pinned `cargo-deny` source and its protected staged copy.
    #[must_use]
    pub fn cargo_deny(mut self, authority: PosixCargoDenyAuthority) -> Self {
        self.cargo_deny_authority = Some(authority);
        self
    }

    /// Adds the exact standard `stack` source and its protected staged copy.
    #[must_use]
    pub fn stack(mut self, authority: PosixStackAuthority) -> Self {
        self.stack_authority = Some(authority);
        self
    }
}

#[cfg(unix)]
impl PosixExecutableMetadata {
    /// Retains the exact metadata and digest captured by the trusted parent.
    #[must_use]
    pub fn new(device: u64, inode: u64, owner: u32, group: u32, mode: u32, bytes: u64) -> Self {
        Self {
            device,
            inode,
            owner,
            group,
            mode,
            bytes,
        }
    }
}

#[cfg(unix)]
impl PosixExecutableParentMetadata {
    #[must_use]
    pub fn new(device: u64, inode: u64, owner: u32, group: u32, mode: u32) -> Self {
        Self {
            device,
            inode,
            owner,
            group,
            mode,
        }
    }
}

#[cfg(unix)]
impl PosixExecutableAuthority {
    /// Retains one canonical-parent invocation and its exact file receipt.
    #[must_use]
    pub fn new(
        role: PosixProcessToolRole,
        invocation: PathBuf,
        canonical: PathBuf,
        metadata: PosixExecutableMetadata,
    ) -> Self {
        use std::os::unix::fs::MetadataExt as _;

        let parent_metadata = invocation
            .parent()
            .and_then(|parent| fs::metadata(parent).ok())
            .map(|parent| {
                PosixExecutableParentMetadata::new(
                    parent.dev(),
                    parent.ino(),
                    parent.uid(),
                    parent.gid(),
                    parent.mode(),
                )
            });
        let logical_name = invocation.file_name().map(OsStr::to_os_string);
        Self {
            role,
            invocation,
            logical_name,
            parent_metadata,
            canonical,
            metadata,
        }
    }

    /// Retains an independently captured canonical-parent receipt.
    #[must_use]
    pub fn with_parent_metadata(
        role: PosixProcessToolRole,
        invocation: PathBuf,
        parent_metadata: PosixExecutableParentMetadata,
        canonical: PathBuf,
        metadata: PosixExecutableMetadata,
    ) -> Self {
        let logical_name = invocation.file_name().map(OsStr::to_os_string);
        Self {
            role,
            invocation,
            logical_name,
            parent_metadata: Some(parent_metadata),
            canonical,
            metadata,
        }
    }
}

#[cfg(unix)]
impl PosixProcessAuthorities {
    /// Binds the four distinct roles used for candidate process lifecycle.
    ///
    /// # Errors
    ///
    /// Returns an error if a supplied receipt is assigned to the wrong role.
    pub fn new(
        sudo: PosixExecutableAuthority,
        identity: PosixExecutableAuthority,
        inventory: PosixExecutableAuthority,
        terminator: PosixExecutableAuthority,
    ) -> std::io::Result<Self> {
        if sudo.role != PosixProcessToolRole::Sudo
            || identity.role != PosixProcessToolRole::Identity
            || inventory.role != PosixProcessToolRole::Inventory
            || terminator.role != PosixProcessToolRole::Terminator
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "POSIX process authority role assignment differs from policy",
            ));
        }
        Ok(Self {
            sudo,
            identity,
            inventory,
            terminator,
        })
    }
}

#[cfg(unix)]
#[derive(Clone, Debug)]
struct BoundPosixExecutableAuthority {
    authority: PosixExecutableAuthority,
}

#[cfg(unix)]
impl BoundPosixExecutableAuthority {
    fn new(authority: PosixExecutableAuthority) -> std::io::Result<Self> {
        let bound = Self { authority };
        bound.revalidate()?;
        Ok(bound)
    }

    fn revalidate(&self) -> std::io::Result<PathBuf> {
        use std::os::unix::fs::MetadataExt as _;

        let invocation = &self.authority.invocation;
        let canonical = &self.authority.canonical;
        let role = self.authority.role;
        if !invocation.is_absolute() {
            return Err(posix_process_authority_error(role, "absolute-invocation"));
        }
        let parent = invocation
            .parent()
            .ok_or_else(|| posix_process_authority_error(role, "invocation-parent"))?;
        let logical_name = self
            .authority
            .logical_name
            .as_deref()
            .ok_or_else(|| posix_process_authority_error(role, "logical-leaf"))?;
        if invocation.file_name() != Some(logical_name)
            || Path::new(logical_name).components().count() != 1
        {
            return Err(posix_process_authority_error(role, "logical-leaf"));
        }
        let observed_parent = fs::canonicalize(parent)
            .map_err(|_| posix_process_authority_error(role, "canonical-parent"))?;
        if observed_parent != parent {
            return Err(posix_process_authority_error(role, "canonical-parent"));
        }
        let parent_metadata = fs::metadata(parent)
            .map_err(|_| posix_process_authority_error(role, "parent-metadata"))?;
        let expected_parent = self
            .authority
            .parent_metadata
            .as_ref()
            .ok_or_else(|| posix_process_authority_error(role, "parent-metadata"))?;
        if !parent_metadata.is_dir() {
            return Err(posix_process_authority_error(role, "parent-kind"));
        }
        for (matches, predicate) in [
            (
                parent_metadata.dev() == expected_parent.device,
                "parent-device",
            ),
            (
                parent_metadata.ino() == expected_parent.inode,
                "parent-inode",
            ),
            (
                parent_metadata.uid() == expected_parent.owner,
                "parent-owner",
            ),
            (
                parent_metadata.gid() == expected_parent.group,
                "parent-group",
            ),
            (
                parent_metadata.mode() == expected_parent.mode,
                "parent-mode",
            ),
        ] {
            if !matches {
                return Err(posix_process_authority_error(role, predicate));
            }
        }
        require_trusted_posix_executable_parent(&parent_metadata)
            .map_err(|predicate| posix_process_authority_error(role, predicate))?;
        let observed_canonical = fs::canonicalize(canonical)
            .map_err(|_| posix_process_authority_error(role, "canonical-target"))?;
        if observed_canonical != *canonical {
            return Err(posix_process_authority_error(role, "canonical-target"));
        }
        let observed_invocation = fs::canonicalize(invocation)
            .map_err(|_| posix_process_authority_error(role, "invocation-resolves-to-target"))?;
        if observed_invocation != *canonical {
            return Err(posix_process_authority_error(
                role,
                "invocation-resolves-to-target",
            ));
        }
        let metadata = fs::metadata(canonical)
            .map_err(|_| posix_process_authority_error(role, "target-metadata"))?;
        let expected = &self.authority.metadata;
        if !metadata.is_file() {
            return Err(posix_process_authority_error(role, "file-kind"));
        }
        for (matches, predicate) in [
            (metadata.dev() == expected.device, "device"),
            (metadata.ino() == expected.inode, "inode"),
            (metadata.uid() == expected.owner, "owner"),
            (metadata.gid() == expected.group, "group"),
            (metadata.mode() == expected.mode, "mode"),
            (metadata.len() == expected.bytes, "length"),
        ] {
            if !matches {
                return Err(posix_process_authority_error(role, predicate));
            }
        }
        require_posix_effective_executable(invocation)
            .map_err(|_| posix_process_authority_error(role, "effective-X-OK"))?;
        Ok(invocation.clone())
    }
}

#[cfg(unix)]
fn require_trusted_posix_executable_parent(metadata: &fs::Metadata) -> Result<(), &'static str> {
    use std::os::unix::fs::MetadataExt as _;

    require_trusted_posix_executable_parent_fields(metadata.uid(), metadata.mode())
}

#[cfg(unix)]
fn require_trusted_posix_executable_parent_fields(
    owner: u32,
    mode: u32,
) -> Result<(), &'static str> {
    use nix::unistd::geteuid;

    if owner != 0 && owner != geteuid().as_raw() {
        return Err("parent-trusted-owner");
    }
    if mode & 0o022 != 0 {
        return Err("parent-non-owner-write");
    }
    Ok(())
}

/// Verifies canonical executable-parent ownership/write policy through an external test seam.
///
/// # Errors
///
/// Returns the exact rejected predicate when the owner or mode is not trusted.
#[cfg(unix)]
#[doc(hidden)]
pub fn verify_posix_executable_parent_policy_for_integration(
    owner: u32,
    mode: u32,
) -> Result<(), &'static str> {
    require_trusted_posix_executable_parent_fields(owner, mode)
}

#[cfg(unix)]
fn posix_process_authority_error(
    role: PosixProcessToolRole,
    predicate: &'static str,
) -> std::io::Error {
    let role = match role {
        PosixProcessToolRole::Sudo => "sudo",
        PosixProcessToolRole::Identity => "identity",
        PosixProcessToolRole::Inventory => "inventory",
        PosixProcessToolRole::Terminator => "terminator",
    };
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("POSIX process authority role={role} predicate={predicate}"),
    )
}

#[cfg(unix)]
#[derive(Clone, Debug)]
struct BoundPosixProcessAuthorities {
    sudo: BoundPosixExecutableAuthority,
    identity: BoundPosixExecutableAuthority,
    inventory: BoundPosixExecutableAuthority,
    terminator: BoundPosixExecutableAuthority,
}

#[cfg(unix)]
impl BoundPosixProcessAuthorities {
    fn new(authorities: PosixProcessAuthorities) -> std::io::Result<Self> {
        Ok(Self {
            sudo: BoundPosixExecutableAuthority::new(authorities.sudo)?,
            identity: BoundPosixExecutableAuthority::new(authorities.identity)?,
            inventory: BoundPosixExecutableAuthority::new(authorities.inventory)?,
            terminator: BoundPosixExecutableAuthority::new(authorities.terminator)?,
        })
    }
}

/// Revalidates a complete POSIX process-authority bundle for external regression tests.
#[cfg(unix)]
#[doc(hidden)]
pub fn verify_posix_process_authorities_for_integration(
    authorities: PosixProcessAuthorities,
) -> std::io::Result<()> {
    BoundPosixProcessAuthorities::new(authorities).map(|_| ())
}

/// Revalidates a complete bundle and returns one exact logical invocation for external tests.
#[cfg(unix)]
#[doc(hidden)]
pub fn revalidated_posix_process_invocation_for_integration(
    authorities: PosixProcessAuthorities,
    role: PosixProcessToolRole,
) -> std::io::Result<PathBuf> {
    let authorities = BoundPosixProcessAuthorities::new(authorities)?;
    match role {
        PosixProcessToolRole::Sudo => authorities.sudo.revalidate(),
        PosixProcessToolRole::Identity => authorities.identity.revalidate(),
        PosixProcessToolRole::Inventory => authorities.inventory.revalidate(),
        PosixProcessToolRole::Terminator => authorities.terminator.revalidate(),
    }
}

#[cfg(unix)]
impl PosixCargoDenyAuthority {
    /// Binds the independently resolved source and exact protected staged copy.
    #[must_use]
    pub fn new(
        source: PosixStandardExecutableIdentity,
        source_sha256: Digest,
        staged: PathBuf,
        staged_sha256: Digest,
        cargo_home: PathBuf,
        metadata: PosixCargoDenyMetadataAuthority,
        cache_ownership: PosixCargoDenyCacheOwnership,
    ) -> Self {
        Self {
            source,
            source_sha256,
            staged,
            staged_sha256,
            cargo_home,
            metadata,
            trusted_owner: cache_ownership.trusted_owner,
            trusted_group_id: cache_ownership.trusted_group_id,
        }
    }
}

#[cfg(unix)]
impl PosixCargoDenyCacheOwnership {
    /// Binds the trusted owner and reader group of the staged cache.
    #[must_use]
    pub const fn new(trusted_owner: u32, trusted_group_id: u32) -> Self {
        Self {
            trusted_owner,
            trusted_group_id,
        }
    }
}

#[cfg(unix)]
impl PosixCargoDenyMetadataAuthority {
    /// Binds the exact trusted metadata directory, document, size, and digest.
    #[must_use]
    pub fn new(
        directory: PathBuf,
        path: PathBuf,
        size: u64,
        sha256: Digest,
        trusted_owner: u32,
    ) -> Self {
        Self {
            directory,
            path,
            size,
            sha256,
            trusted_owner,
        }
    }
}

#[cfg(unix)]
impl PosixStackAuthority {
    /// Binds the independently resolved source and exact protected staged copy.
    #[must_use]
    pub fn new(
        source: PosixStandardExecutableIdentity,
        source_sha256: Digest,
        staged: PathBuf,
        staged_sha256: Digest,
        stack_root: PathBuf,
        trusted_group_id: u32,
    ) -> Self {
        Self {
            source,
            source_sha256,
            staged,
            staged_sha256,
            stack_root,
            trusted_group_id,
        }
    }
}

/// A logical executable invocation whose canonical file identity was bound by
/// the trusted parent. This preserves multicall aliases such as `cargo` while
/// failing closed if the alias is substituted before the supervised spawn.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundProgramInvocation {
    invocation_path: PathBuf,
    canonical_identity: PathBuf,
    file_identity: BoundProgramFileIdentity,
    #[cfg(windows)]
    invocation_parent_identity: Arc<same_file::Handle>,
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct BoundProgramFileIdentity {
    device: u64,
    inode: u64,
}

#[cfg(windows)]
#[derive(Clone)]
struct BoundProgramFileIdentity {
    guard: Arc<same_file::Handle>,
    parent_path: PathBuf,
    parent_identity: Arc<same_file::Handle>,
    length: u64,
    sha256: Digest,
}

#[cfg(windows)]
impl std::fmt::Debug for BoundProgramFileIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BoundProgramFileIdentity")
            .field("parent_path", &self.parent_path)
            .field("length", &self.length)
            .field("sha256", &self.sha256)
            .finish_non_exhaustive()
    }
}

#[cfg(windows)]
impl PartialEq for BoundProgramFileIdentity {
    fn eq(&self, other: &Self) -> bool {
        self.guard == other.guard
            && self.parent_path == other.parent_path
            && self.parent_identity == other.parent_identity
            && self.length == other.length
            && self.sha256 == other.sha256
    }
}

#[cfg(windows)]
impl Eq for BoundProgramFileIdentity {}

#[cfg(not(any(unix, windows)))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct BoundProgramFileIdentity;

impl BoundProgramFileIdentity {
    #[cfg(unix)]
    fn bind(path: &Path) -> std::io::Result<Self> {
        use std::os::unix::fs::MetadataExt as _;

        let metadata = fs::metadata(path)?;
        if !metadata.is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "bound program identity is not a file",
            ));
        }
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    #[cfg(windows)]
    fn bind_until(path: &Path, deadline: Instant) -> std::io::Result<Self> {
        use std::os::windows::fs::MetadataExt as _;

        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        let parent_path = path
            .parent()
            .ok_or_else(|| std::io::Error::other("bound program has no parent"))?
            .to_path_buf();
        let parent_metadata = fs::symlink_metadata(&parent_path)?;
        if !parent_metadata.is_dir()
            || parent_metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || fs::canonicalize(&parent_path)? != parent_path
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "bound program parent is not one canonical direct directory",
            ));
        }
        let path_metadata = fs::symlink_metadata(path)?;
        if !path_metadata.is_file()
            || path_metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "bound program identity is not one direct file",
            ));
        }
        let guard = windows_locked_same_file_handle(path)?;
        let before = guard.as_file().metadata()?;
        if !before.is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "bound program identity is not a file",
            ));
        }
        let sha256 = sha256_retained_windows_file_until(guard.as_file(), deadline)?;
        let after = guard.as_file().metadata()?;
        let rebound = same_file::Handle::from_path(path)?;
        if before.len() != after.len() || rebound != guard {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "bound program identity changed while hashing",
            ));
        }
        Ok(Self {
            guard: Arc::new(guard),
            parent_identity: Arc::new(same_file::Handle::from_path(&parent_path)?),
            parent_path,
            length: after.len(),
            sha256,
        })
    }

    #[cfg(windows)]
    fn promote_until(
        path: &Path,
        retained_file: fs::File,
        length: u64,
        sha256: Digest,
        deadline: Instant,
    ) -> std::io::Result<Self> {
        use std::os::windows::fs::MetadataExt as _;

        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "staged Windows toolchain receipt promotion exceeded its absolute deadline",
            ));
        }
        let parent_path = path
            .parent()
            .ok_or_else(|| std::io::Error::other("promoted program has no parent"))?
            .to_path_buf();
        let parent_metadata = fs::symlink_metadata(&parent_path)?;
        let path_metadata = fs::symlink_metadata(path)?;
        if !parent_metadata.is_dir()
            || parent_metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || fs::canonicalize(&parent_path)? != parent_path
            || !path_metadata.is_file()
            || path_metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "promoted Windows program is not one canonical direct file",
            ));
        }
        let guard = same_file::Handle::from_file(retained_file)?;
        let retained_metadata = guard.as_file().metadata()?;
        if !retained_metadata.is_file()
            || retained_metadata.len() != length
            || path_metadata.len() != length
            || same_file::Handle::from_path(path)? != guard
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "promoted Windows program retained identity changed",
            ));
        }
        Ok(Self {
            guard: Arc::new(guard),
            parent_identity: Arc::new(same_file::Handle::from_path(&parent_path)?),
            parent_path,
            length,
            sha256,
        })
    }

    #[cfg(windows)]
    fn revalidate(&self, path: &Path) -> std::io::Result<()> {
        use std::os::windows::fs::MetadataExt as _;

        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        let parent = path
            .parent()
            .ok_or_else(|| std::io::Error::other("bound program has no parent"))?;
        let parent_metadata = fs::symlink_metadata(parent)?;
        let path_metadata = fs::symlink_metadata(path)?;
        if parent != self.parent_path
            || !parent_metadata.is_dir()
            || parent_metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || fs::canonicalize(parent)? != self.parent_path
            || same_file::Handle::from_path(parent)? != *self.parent_identity
            || !path_metadata.is_file()
            || path_metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || same_file::Handle::from_path(path)? != *self.guard
            || self.guard.as_file().metadata()?.len() != self.length
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "bound program retained file identity changed",
            ));
        }
        Ok(())
    }

    #[cfg(not(any(unix, windows)))]
    fn bind(_path: &Path) -> std::io::Result<Self> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "bound program file identity is unsupported on this platform",
        ))
    }
}

impl BoundProgramInvocation {
    /// Binds an absolute logical invocation path to its canonical executable.
    ///
    /// # Errors
    ///
    /// Returns an error when either path is noncanonical, the invocation does
    /// not resolve to the expected file, the resolved target is not a file, or
    /// an exact platform file identity cannot be established.
    pub fn new(invocation_path: PathBuf, canonical_identity: PathBuf) -> std::io::Result<Self> {
        #[cfg(windows)]
        {
            return Self::new_until(
                invocation_path,
                canonical_identity,
                windows_program_authority_acquisition_deadline()?,
            );
        }
        #[cfg(not(windows))]
        {
            let identity = Self {
                invocation_path,
                file_identity: BoundProgramFileIdentity::bind(&canonical_identity)?,
                canonical_identity,
            };
            identity.revalidate(identity.invocation_path.as_os_str())?;
            Ok(identity)
        }
    }

    #[cfg(windows)]
    #[doc(hidden)]
    pub fn new_until(
        invocation_path: PathBuf,
        canonical_identity: PathBuf,
        deadline: Instant,
    ) -> std::io::Result<Self> {
        let invocation_parent_identity = bind_windows_program_parent(&invocation_path)?;
        let identity = Self {
            invocation_path,
            file_identity: BoundProgramFileIdentity::bind_until(&canonical_identity, deadline)?,
            canonical_identity,
            invocation_parent_identity,
        };
        identity.revalidate(identity.invocation_path.as_os_str())?;
        Ok(identity)
    }

    /// Promotes an already-hashed retained Windows file into a program receipt.
    ///
    /// This constructor never reads file contents. The caller must supply the
    /// digest produced while it retained the same no-write/no-delete file
    /// authority.
    #[cfg(windows)]
    #[doc(hidden)]
    pub fn promote_windows_retained_file_until(
        path: PathBuf,
        retained_file: fs::File,
        length: u64,
        sha256: Digest,
        deadline: Instant,
    ) -> std::io::Result<Self> {
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "staged Windows toolchain receipt promotion exceeded its absolute deadline",
            ));
        }
        let invocation_parent_identity = bind_windows_program_parent(&path)?;
        let identity = Self {
            invocation_path: path.clone(),
            canonical_identity: path.clone(),
            file_identity: BoundProgramFileIdentity::promote_until(
                &path,
                retained_file,
                length,
                sha256,
                deadline,
            )?,
            invocation_parent_identity,
        };
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "staged Windows toolchain receipt promotion exceeded its absolute deadline",
            ));
        }
        identity.revalidate(identity.invocation_path.as_os_str())?;
        Ok(identity)
    }

    fn revalidate(&self, requested_program: &OsStr) -> std::io::Result<PathBuf> {
        let invocation_parent = self
            .invocation_path
            .parent()
            .ok_or_else(|| std::io::Error::other("bound program has no parent"))?;
        if Path::new(requested_program) != self.invocation_path
            || !self.invocation_path.is_absolute()
            || fs::canonicalize(invocation_parent)? != invocation_parent
            || fs::canonicalize(&self.canonical_identity)? != self.canonical_identity
            || fs::canonicalize(&self.invocation_path)? != self.canonical_identity
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "bound program invocation identity changed",
            ));
        }
        #[cfg(windows)]
        if same_file::Handle::from_path(invocation_parent)? != *self.invocation_parent_identity
            || same_file::Handle::from_path(&self.invocation_path)? != *self.file_identity.guard
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "bound program invocation parent identity changed",
            ));
        }
        #[cfg(unix)]
        let file_changed =
            BoundProgramFileIdentity::bind(&self.canonical_identity)? != self.file_identity;
        #[cfg(windows)]
        let file_changed = self
            .file_identity
            .revalidate(&self.canonical_identity)
            .is_err();
        #[cfg(not(any(unix, windows)))]
        let file_changed = true;
        if file_changed {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "bound program file identity changed",
            ));
        }
        Ok(self.invocation_path.clone())
    }

    #[cfg(windows)]
    fn sha256(&self) -> Digest {
        self.file_identity.sha256
    }

    #[cfg(windows)]
    fn length(&self) -> u64 {
        self.file_identity.length
    }

    /// Returns the number of full byte-hash passes retained by this Windows authority.
    #[cfg(windows)]
    #[doc(hidden)]
    #[must_use]
    pub const fn windows_hash_passes_for_integration(&self) -> usize {
        1
    }

    /// Revalidates this exact Windows receipt without rereading executable bytes.
    #[cfg(windows)]
    #[doc(hidden)]
    pub fn windows_revalidate_for_integration(&self) -> std::io::Result<()> {
        self.revalidate(self.invocation_path.as_os_str())
            .map(|_| ())
    }
}

thread_local! {
    static CANDIDATE_LAUNCH_POLICY: RefCell<Option<CandidateLaunchPolicy>> = const { RefCell::new(None) };
}

#[cfg(all(unix, test))]
fn resolve_standard_posix_process_authorities(
    sudo: &Path,
) -> std::io::Result<PosixProcessAuthorities> {
    use std::os::unix::fs::MetadataExt as _;

    let bind = |role, requested: &Path| -> std::io::Result<PosixExecutableAuthority> {
        let canonical = fs::canonicalize(requested)?;
        let parent = requested
            .parent()
            .ok_or_else(|| std::io::Error::other("POSIX process authority has no parent"))?;
        let invocation = fs::canonicalize(parent)?.join(
            requested
                .file_name()
                .ok_or_else(|| std::io::Error::other("POSIX process authority has no name"))?,
        );
        let metadata = fs::metadata(&canonical)?;
        Ok(PosixExecutableAuthority::new(
            role,
            invocation,
            canonical,
            PosixExecutableMetadata::new(
                metadata.dev(),
                metadata.ino(),
                metadata.uid(),
                metadata.gid(),
                metadata.mode(),
                metadata.len(),
            ),
        ))
    };
    PosixProcessAuthorities::new(
        bind(PosixProcessToolRole::Sudo, sudo)?,
        bind(PosixProcessToolRole::Identity, Path::new("/usr/bin/id"))?,
        bind(PosixProcessToolRole::Inventory, Path::new("/bin/ps"))?,
        bind(
            PosixProcessToolRole::Terminator,
            Path::new("/usr/bin/pkill"),
        )?,
    )
}

impl CandidateLaunchPolicy {
    /// Creates a POSIX policy after the trusted driver has established the
    /// separate account and filesystem ownership boundary.
    ///
    /// # Errors
    ///
    /// Returns an error when a launcher path cannot be canonicalized or the
    /// supplied principal, group, or writable roots are not canonical.
    #[cfg(all(unix, test))]
    fn posix(
        launcher: PathBuf,
        authorities: PosixLaunchAuthorities,
        identity: PosixCandidateIdentity,
        writable_roots: Vec<PathBuf>,
    ) -> std::io::Result<Self> {
        let process = resolve_standard_posix_process_authorities(&launcher)?;
        Self::posix_with_process_authorities(
            launcher,
            process,
            authorities,
            identity,
            writable_roots,
        )
    }

    /// Creates a POSIX policy from the complete parent-resolved process authority bundle.
    ///
    /// # Errors
    ///
    /// Returns an error when any process authority changes or the supplied
    /// principal, group, or writable roots are not canonical.
    #[cfg(unix)]
    pub fn posix_with_process_authorities(
        launcher: PathBuf,
        mut process: PosixProcessAuthorities,
        authorities: PosixLaunchAuthorities,
        identity: PosixCandidateIdentity,
        writable_roots: Vec<PathBuf>,
    ) -> std::io::Result<Self> {
        if process.sudo.invocation != launcher {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "POSIX launcher differs from its typed sudo authority",
            ));
        }
        process.sudo.invocation = launcher;
        let PosixLaunchAuthorities {
            adapter,
            adapter_sha256,
            cargo_source,
            cargo_adapter,
            cargo_adapter_sha256,
            cargo_authority,
            cargo_deny_authority,
            stack_authority,
        } = authorities;
        let process_authorities = Arc::new(BoundPosixProcessAuthorities::new(process)?);
        let adapter = fs::canonicalize(adapter)?;
        let adapter_identity = posix_adapter_identity(&adapter)?;
        verify_posix_adapter_identity(&adapter, &adapter, adapter_sha256, &adapter_identity)?;
        let cargo_source = fs::canonicalize(cargo_source)?;
        let cargo_adapter = fs::canonicalize(cargo_adapter)?;
        let cargo_adapter_identity = posix_adapter_identity(&cargo_adapter)?;
        verify_posix_adapter_identity(
            &cargo_adapter,
            &cargo_adapter,
            cargo_adapter_sha256,
            &cargo_adapter_identity,
        )?;
        let PosixCandidateIdentity {
            principal,
            uid,
            primary_gid,
            group_ids: candidate_group_ids,
        } = identity;
        let candidate_group_ids: Arc<[u32]> = candidate_group_ids.into();
        let cargo_authority = BoundPosixCargoSourceAuthority::new(
            cargo_authority,
            &cargo_source,
            uid,
            Arc::clone(&candidate_group_ids),
        )?;
        if writable_roots.is_empty() || writable_roots.iter().any(|path| !path.is_absolute()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "candidate launch policy is not canonical",
            ));
        }
        let cargo_deny_authority = cargo_deny_authority
            .map(|authority| {
                BoundPosixCargoDenyAuthority::new(
                    authority,
                    uid,
                    &candidate_group_ids,
                    &writable_roots,
                )
            })
            .transpose()?;
        let stack_authority = stack_authority
            .map(|authority| {
                BoundPosixStackAuthority::new(authority, uid, &candidate_group_ids, &writable_roots)
            })
            .transpose()?;
        Ok(Self {
            process_authorities,
            adapter,
            adapter_sha256,
            adapter_identity,
            cargo_source,
            cargo_adapter,
            cargo_adapter_sha256,
            cargo_adapter_identity,
            cargo_authority,
            cargo_deny_authority,
            stack_authority,
            principal: principal.into(),
            uid,
            primary_gid,
            writable_roots: writable_roots.into(),
        })
    }

    /// Binds the exact local Stack work directory after the native adapter is sealed.
    ///
    /// # Errors
    ///
    /// Returns an error unless the work directory is a candidate-writable child
    /// of the same canonical authority that directly contains the Stack source.
    #[cfg(unix)]
    pub fn with_posix_stack_work_authority(
        mut self,
        source: &Path,
        work: &Path,
    ) -> std::io::Result<Self> {
        self.stack_authority
            .as_mut()
            .ok_or_else(|| std::io::Error::other("POSIX Stack authority is absent"))?
            .bind_work(source, work)?;
        Ok(self)
    }

    #[cfg(windows)]
    /// Creates a Windows candidate policy from already-bound executable authorities.
    ///
    /// # Errors
    ///
    /// Returns an error if an authority has changed or a writable root is not absolute.
    pub fn windows(
        authorities: WindowsLaunchAuthorities,
        writable_roots: Vec<PathBuf>,
    ) -> std::io::Result<Self> {
        let WindowsLaunchAuthorities {
            launcher,
            restricted_adapter,
            toolchain,
        } = authorities;
        launcher.revalidate(launcher.invocation_path.as_os_str())?;
        restricted_adapter.revalidate(restricted_adapter.invocation_path.as_os_str())?;
        if writable_roots.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "candidate launch policy is not canonical",
            ));
        }
        let writable_roots = writable_roots
            .into_iter()
            .map(|path| {
                let metadata = fs::symlink_metadata(&path)?;
                let canonical = fs::canonicalize(&path)?;
                if !path.is_absolute()
                    || metadata.file_type().is_symlink()
                    || !metadata.is_dir()
                    || canonical != path
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "candidate writable root is not one canonical direct directory",
                    ));
                }
                Ok(path)
            })
            .collect::<std::io::Result<Vec<_>>>()?;
        Ok(Self {
            launcher,
            restricted_adapter,
            toolchain,
            writable_roots: writable_roots.into(),
        })
    }

    #[cfg(unix)]
    fn mapped_posix_cargo_deny_request(
        &self,
        requested: &OsStr,
        resolved: &Path,
    ) -> std::io::Result<Option<(PathBuf, PathBuf, PathBuf)>> {
        self.cargo_deny_authority
            .as_ref()
            .map(|authority| {
                authority
                    .request_is_bound(requested, resolved)
                    .map(|matches| {
                        matches.then(|| {
                            (
                                authority.staged.clone(),
                                authority.cargo_home.clone(),
                                authority.metadata.path.clone(),
                            )
                        })
                    })
            })
            .transpose()
            .map(Option::flatten)
    }

    #[cfg(unix)]
    fn mapped_posix_rustc_request(
        &self,
        requested: &OsStr,
        resolved: &Path,
    ) -> std::io::Result<Option<PathBuf>> {
        let Some(authority) = self.cargo_authority.rustup() else {
            return Ok(None);
        };
        authority
            .request_is_bound_rustc(requested, resolved)?
            .then(|| authority.staged_rustc())
            .transpose()
    }

    #[cfg(unix)]
    fn wrapped_posix_command(
        &self,
        invocation_name: OsString,
        program: PathBuf,
        arguments: Vec<OsString>,
        directory: Option<PathBuf>,
        environment: BTreeMap<OsString, OsString>,
    ) -> std::io::Result<Command> {
        let mut wrapped = Command::new(self.process_authorities.sudo.revalidate()?);
        wrapped
            .arg("-n")
            .arg("-u")
            .arg(self.principal.as_ref())
            .arg("--")
            .arg(&self.adapter)
            .arg(POSIX_RELEASE_CHILD_REQUEST_V1)
            .env_clear();
        wrapped.arg(environment.len().to_string());
        for (name, value) in environment {
            wrapped.arg(name).arg(value);
        }
        wrapped.arg(invocation_name).arg(program).args(arguments);
        if let Some(directory) = directory {
            wrapped.current_dir(directory);
        }
        Ok(wrapped)
    }

    #[cfg(unix)]
    fn wrap(
        &self,
        command: &mut Command,
        bound_program: Option<&BoundProgramInvocation>,
    ) -> std::io::Result<()> {
        verify_posix_adapter_identity(
            &self.adapter,
            &self.adapter,
            self.adapter_sha256,
            &self.adapter_identity,
        )?;
        let resolved_program =
            resolve_parent_program_for_launch(command.get_program(), bound_program)?;
        let staged_cargo = bound_program.is_some_and(|identity| {
            identity.canonical_identity == self.cargo_source
                && identity.invocation_path.file_name() == Some(OsStr::new("cargo"))
        });
        let staged_cargo_deny =
            self.mapped_posix_cargo_deny_request(command.get_program(), &resolved_program)?;
        let staged_stack = self
            .stack_authority
            .as_ref()
            .map(|authority| authority.mapped_request(command.get_program(), &resolved_program))
            .transpose()?
            .flatten();
        let staged_rustc =
            self.mapped_posix_rustc_request(command.get_program(), &resolved_program)?;
        let uses_staged_cargo_tools = staged_cargo || staged_cargo_deny.is_some();
        if uses_staged_cargo_tools {
            verify_posix_adapter_identity(
                &self.cargo_adapter,
                &self.cargo_adapter,
                self.cargo_adapter_sha256,
                &self.cargo_adapter_identity,
            )?;
            self.cargo_authority.revalidate(&self.cargo_source)?;
        }
        let program = if staged_cargo {
            self.cargo_adapter.clone()
        } else if let Some((staged, _, _)) = &staged_cargo_deny {
            staged.clone()
        } else if let Some((staged, _, _)) = &staged_stack {
            staged.clone()
        } else if let Some(staged) = staged_rustc {
            staged
        } else {
            resolved_program
        };
        let invocation_name = bound_program
            .map_or_else(
                || Path::new(command.get_program()),
                |identity| identity.invocation_path.as_path(),
            )
            .file_name()
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "POSIX release child invocation name is absent",
                )
            })?
            .to_owned();
        let arguments = posix_stack_arguments(
            command.get_args().map(OsString::from).collect(),
            staged_stack.as_ref().map(|(_, root, _)| root.as_path()),
            staged_stack
                .as_ref()
                .and_then(|(_, _, work)| work.as_deref()),
        )?;
        let arguments = posix_cargo_deny_arguments(
            arguments,
            staged_cargo_deny
                .as_ref()
                .map(|(_, _, metadata)| metadata.as_path()),
        )?;
        let directory = command.get_current_dir().map(Path::to_owned);
        let environment = command
            .get_envs()
            .map(|(name, value)| (OsString::from(name), value.map(OsString::from)))
            .collect::<Vec<_>>();
        let environment = posix_release_child_environment(
            environment,
            uses_staged_cargo_tools
                .then_some(self.cargo_authority.rustup())
                .flatten(),
            uses_staged_cargo_tools
                .then(|| self.cargo_authority.child_tool_path(&self.cargo_adapter))
                .transpose()?
                .as_deref(),
            uses_staged_cargo_tools.then_some(self.cargo_adapter.as_path()),
            staged_cargo_deny
                .as_ref()
                .map(|(_, cargo_home, _)| cargo_home.as_path()),
        )?;
        *command = self.wrapped_posix_command(
            invocation_name,
            program,
            arguments,
            directory,
            environment,
        )?;
        Ok(())
    }

    /// Applies the Windows restricted-launch environment without a separately
    /// bound program identity.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when a retained authority no longer validates.
    #[cfg(windows)]
    #[doc(hidden)]
    pub fn apply_unbound_windows_command(&self, command: &mut Command) -> std::io::Result<()> {
        self.wrap(command, None)
    }

    /// Returns the one-time launcher and adapter hash-pass receipts used by Windows wrapping.
    #[cfg(windows)]
    #[doc(hidden)]
    #[must_use]
    pub fn windows_static_hash_passes_for_integration(&self) -> (usize, usize) {
        (
            self.launcher.windows_hash_passes_for_integration(),
            self.restricted_adapter
                .windows_hash_passes_for_integration(),
        )
    }

    #[cfg(windows)]
    fn wrap(
        &self,
        command: &mut Command,
        bound_program: Option<&BoundProgramInvocation>,
    ) -> std::io::Result<()> {
        self.wrap_with_control(
            command,
            bound_program,
            windows_program_authority_acquisition_deadline()?,
        )
        .map(|_| ())
    }

    #[cfg(windows)]
    fn wrap_with_control(
        &self,
        command: &mut Command,
        bound_program: Option<&BoundProgramInvocation>,
        deadline: Instant,
    ) -> std::io::Result<WindowsLaunchControlAuthority> {
        let launcher = self
            .launcher
            .revalidate(self.launcher.invocation_path.as_os_str())?;
        let restricted_adapter = self
            .restricted_adapter
            .revalidate(self.restricted_adapter.invocation_path.as_os_str())?;
        let program = resolve_parent_program_for_launch(command.get_program(), bound_program)?;
        let mapped_program = self
            .toolchain
            .mapped_program(command.get_program(), &program)?;
        let requires_trusted_path = windows_program_requires_trusted_path(
            command.get_program(),
            &program,
            mapped_program.is_some(),
        );
        let mapped_cargo = mapped_program.is_some()
            && windows_executable_has_logical_name(program.as_os_str(), "cargo");
        let program = mapped_program.unwrap_or(program);
        let git_inventory = program.file_name().is_some_and(|name| {
            name.eq_ignore_ascii_case(OsStr::new("git.exe"))
                || name.eq_ignore_ascii_case(OsStr::new("git"))
        }) && command
            .get_args()
            .eq([OsStr::new("ls-files"), OsStr::new("-z")]);
        let program_authority = git_inventory
            .then(|| {
                BoundProgramInvocation::new_until(
                    program.clone(),
                    fs::canonicalize(&program)?,
                    deadline,
                )
            })
            .transpose()?;
        let arguments = command.get_args().map(OsString::from).collect::<Vec<_>>();
        let target_subcommand = if mapped_cargo {
            windows_cargo_target_subcommand(&arguments)?
        } else {
            None
        };
        let (arguments, required_target) = if let Some(subcommand) = target_subcommand {
            let [target] = self.writable_roots.as_ref() else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "target-producing Windows Cargo requires one exact writable authority",
                ));
            };
            (
                windows_bound_cargo_arguments(arguments, subcommand, target)?,
                Some(target.as_path()),
            )
        } else {
            (arguments, None)
        };
        let target_arguments = std::iter::once(program.as_os_str())
            .chain(arguments.iter().map(OsString::as_os_str))
            .map(OsString::from)
            .collect::<Vec<_>>();
        let directory = if let Some(requested) = command.get_current_dir() {
            let metadata = fs::symlink_metadata(requested)?;
            let canonical = fs::canonicalize(requested)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() || canonical != requested {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Windows release child current directory is redirected",
                ));
            }
            canonical
        } else {
            fs::canonicalize(std::env::current_dir()?)?
        };
        let mut environment = command
            .get_envs()
            .map(|(name, value)| (OsString::from(name), value.map(OsString::from)))
            .collect::<Vec<_>>();
        configure_windows_restricted_child_environment(
            &self.toolchain,
            &mut environment,
            requires_trusted_path,
        )?;
        let environment = windows_release_child_environment(
            environment,
            &self.writable_roots,
            required_target,
            Some(&directory),
        )?;
        validate_windows_cargo_target_binding(&environment, &target_arguments)?;
        let request = windows_restricted_launch_request_with_environment(
            &restricted_adapter,
            self.restricted_adapter.sha256(),
            &directory,
            &environment,
            &target_arguments,
        )?;
        let encoded = encode_windows_argv(&request)?;
        let request_sha256 = sha256_bytes(encoded.as_encoded_bytes());
        let current_directory_identity = same_file::Handle::from_path(&directory)?;
        let mut wrapped = Command::new(launcher);
        wrapped
            .arg("__release-restricted-child")
            .arg(encoded)
            .env_clear();
        for (name, value) in environment {
            wrapped.env(name, value);
        }
        wrapped.current_dir(&directory);
        *command = wrapped;
        Ok(WindowsLaunchControlAuthority {
            request_sha256,
            program: program_authority,
            current_directory: directory,
            current_directory_identity,
        })
    }

    #[cfg(unix)]
    fn require_quiescence(&self, deadline: Instant) -> std::io::Result<()> {
        self.posix_quiescence_receipt_until(deadline).map(|_| ())
    }

    /// Revalidates the exact candidate identity and retains a no-live-process receipt.
    ///
    /// # Errors
    ///
    /// Returns an error when identity, process authority, or bounded quiescence differs.
    #[cfg(unix)]
    pub fn posix_quiescence_receipt_until(
        &self,
        deadline: Instant,
    ) -> std::io::Result<PosixCandidateQuiescenceReceipt> {
        let uid = self.uid.to_string();
        wait_for_posix_uid_process_quiescence(
            deadline,
            PosixUidQuiescenceGoal::NoLiveProcesses,
            || {
                let program = self.process_authorities.inventory.revalidate()?;
                let output = run_bounded_posix_authority_command(
                    &program,
                    &[
                        OsString::from("-U"),
                        OsString::from(&uid),
                        OsString::from("-o"),
                        OsString::from("pid=,ppid=,stat="),
                    ],
                    deadline,
                )?;
                parse_posix_uid_process_snapshot(
                    output.status.code(),
                    &output.stdout,
                    &output.stderr,
                )
            },
            || self.require_exact_signal_identity(deadline),
            || {
                let process_terminator = self.process_authorities.terminator.revalidate()?;
                let launcher = self.process_authorities.sudo.revalidate()?;
                let output = run_bounded_posix_authority_command(
                    &launcher,
                    &[
                        OsString::from("-n"),
                        OsString::from("--"),
                        process_terminator.into_os_string(),
                        OsString::from("-KILL"),
                        OsString::from("-U"),
                        OsString::from(&uid),
                    ],
                    deadline,
                )?;
                if !matches!(output.status.code(), Some(0 | 1)) || !output.stderr.is_empty() {
                    return Err(std::io::Error::other(
                        "candidate principal process cleanup did not succeed",
                    ));
                }
                Ok(())
            },
        )?;
        self.require_exact_signal_identity(deadline)?;
        Ok(PosixCandidateQuiescenceReceipt {
            principal: Arc::clone(&self.principal),
            uid: self.uid,
            primary_gid: self.primary_gid,
        })
    }

    #[cfg(unix)]
    fn require_exact_signal_identity(&self, deadline: Instant) -> std::io::Result<()> {
        let identity_resolver = self.process_authorities.identity.revalidate()?;
        for (option, expected, label) in [
            ("-u", self.uid, "UID"),
            ("-g", self.primary_gid, "primary GID"),
        ] {
            self.process_authorities.identity.revalidate()?;
            let output = run_bounded_posix_authority_command(
                &identity_resolver,
                &[OsString::from(option), OsString::from(&*self.principal)],
                deadline,
            )?;
            let mut exact = expected.to_string().into_bytes();
            exact.push(b'\n');
            if !output.status.success() || !output.stderr.is_empty() || output.stdout != exact {
                return Err(std::io::Error::other(format!(
                    "candidate principal {label} changed before process termination"
                )));
            }
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn require_quiescence(&self, _deadline: Instant) -> std::io::Result<()> {
        Ok(())
    }

    /// Grants the already-created sandbox to the exact candidate group.
    #[cfg(unix)]
    fn prepare_writable_directory(&self, path: &Path) -> std::io::Result<()> {
        prepare_posix_writable_directory(
            &self.process_authorities.sudo.revalidate()?,
            self.primary_gid,
            &self.writable_roots,
            path,
        )
    }

    #[cfg(not(unix))]
    fn prepare_writable_directory(&self, _path: &Path) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(unix)]
#[derive(Clone, Debug)]
struct PosixFixedConstructionTool {
    path: PathBuf,
    device: u64,
    inode: u64,
}

#[cfg(unix)]
impl PosixFixedConstructionTool {
    fn bind(path: &Path) -> std::io::Result<Self> {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let metadata = fs::symlink_metadata(path)?;
        if fs::canonicalize(path)? != path
            || metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.uid() != 0
            || metadata.permissions().mode() & 0o022 != 0
            || metadata.permissions().mode() & 0o111 == 0
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "fixed POSIX construction tool is not a root-owned immutable executable",
            ));
        }
        Ok(Self {
            path: path.to_path_buf(),
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    fn revalidate(&self) -> std::io::Result<()> {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let metadata = fs::symlink_metadata(&self.path)?;
        if fs::canonicalize(&self.path)? != self.path
            || metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.dev() != self.device
            || metadata.ino() != self.inode
            || metadata.uid() != 0
            || metadata.permissions().mode() & 0o022 != 0
            || metadata.permissions().mode() & 0o111 == 0
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "fixed POSIX construction tool identity changed",
            ));
        }
        Ok(())
    }
}

#[cfg(unix)]
fn prepare_posix_writable_directory(
    launcher: &Path,
    candidate_group: u32,
    writable_roots: &[PathBuf],
    path: &Path,
) -> std::io::Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let root = writable_roots
        .iter()
        .find(|root| path.starts_with(root.as_path()))
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "candidate writable directory is outside the exact policy roots",
            )
        })?;
    let root_metadata = fs::symlink_metadata(root)?;
    let before = fs::symlink_metadata(path)?;
    if !path.is_absolute()
        || path == root
        || fs::canonicalize(root)? != *root
        || fs::canonicalize(path)? != path
        || root_metadata.file_type().is_symlink()
        || !root_metadata.is_dir()
        || before.file_type().is_symlink()
        || !before.is_dir()
        || before.dev() != root_metadata.dev()
        || before.uid() != root_metadata.uid()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "candidate writable directory is redirected or has an untrusted owner identity",
        ));
    }
    let owner_identity = (before.dev(), before.ino(), before.uid());
    let chgrp = PosixFixedConstructionTool::bind(Path::new("/usr/bin/chgrp"))?;
    #[cfg(target_os = "linux")]
    let chmod_path = Path::new("/usr/bin/chmod");
    #[cfg(not(target_os = "linux"))]
    let chmod_path = Path::new("/bin/chmod");
    let chmod = PosixFixedConstructionTool::bind(chmod_path)?;

    chgrp.revalidate()?;
    let status = Command::new(launcher)
        .args(["-n", "--"])
        .arg(&chgrp.path)
        .arg(candidate_group.to_string())
        .arg(path)
        .status()?;
    if !status.success() {
        return Err(std::io::Error::other("cannot bind candidate sandbox group"));
    }
    let grouped = fs::symlink_metadata(path)?;
    if (grouped.dev(), grouped.ino(), grouped.uid()) != owner_identity
        || grouped.gid() != candidate_group
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "candidate sandbox identity changed during group binding",
        ));
    }

    chmod.revalidate()?;
    let mut command = Command::new(launcher);
    command.args(["-n", "--"]).arg(&chmod.path).arg("2770");
    #[cfg(target_os = "linux")]
    command.arg("--");
    let status = command.arg(path).status()?;
    if !status.success() {
        return Err(std::io::Error::other(
            "cannot establish candidate sandbox permissions",
        ));
    }
    let after = fs::symlink_metadata(path)?;
    if fs::canonicalize(path)? != path
        || after.file_type().is_symlink()
        || !after.is_dir()
        || (after.dev(), after.ino(), after.uid()) != owner_identity
        || after.gid() != candidate_group
        || after.permissions().mode() & 0o7777 != 0o2770
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "candidate sandbox identity or permissions differ after construction",
        ));
    }
    Ok(())
}

/// Exercises the production writable-directory construction seam.
///
/// # Errors
///
/// Returns an error unless the directory is canonically contained beneath the
/// supplied root and is constructed with the exact candidate group and mode.
#[cfg(unix)]
#[doc(hidden)]
pub fn prepare_posix_writable_directory_for_integration(
    launcher: &Path,
    candidate_group: u32,
    writable_root: &Path,
    path: &Path,
) -> std::io::Result<()> {
    prepare_posix_writable_directory(
        launcher,
        candidate_group,
        &[writable_root.to_path_buf()],
        path,
    )
}

#[cfg(unix)]
fn posix_stack_arguments(
    mut arguments: Vec<OsString>,
    stack_root: Option<&Path>,
    stack_work: Option<&Path>,
) -> std::io::Result<Vec<OsString>> {
    let Some(stack_root) = stack_root else {
        return Ok(arguments);
    };
    if arguments.iter().any(|argument| {
        argument == OsStr::new("--stack-root")
            || argument == OsStr::new("--work-dir")
            || argument.to_str().is_some_and(|argument| {
                argument.starts_with("--stack-root=") || argument.starts_with("--work-dir=")
            })
    }) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Stack request attempts to replace its bound root or work authority",
        ));
    }
    let mut bound = vec![
        OsString::from("--stack-root"),
        stack_root.as_os_str().into(),
    ];
    if let Some(work) = stack_work {
        if work.is_absolute()
            || work.components().count() != 1
            || work.file_name() != Some(OsStr::new(".stack-work"))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "POSIX Stack work authority is not the exact relative source child",
            ));
        }
        bound.extend([OsString::from("--work-dir"), work.as_os_str().into()]);
    }
    arguments.splice(0..0, bound);
    Ok(arguments)
}

#[cfg(unix)]
fn posix_cargo_deny_arguments(
    mut arguments: Vec<OsString>,
    metadata: Option<&Path>,
) -> std::io::Result<Vec<OsString>> {
    let Some(metadata) = metadata else {
        return Ok(arguments);
    };
    if arguments.iter().any(|argument| {
        argument == OsStr::new("--metadata-path")
            || argument
                .to_str()
                .is_some_and(|argument| argument.starts_with("--metadata-path="))
    }) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "cargo-deny request attempts to replace its bound metadata authority",
        ));
    }
    arguments.splice(
        0..0,
        [
            OsString::from("--metadata-path"),
            metadata.as_os_str().to_owned(),
        ],
    );
    Ok(arguments)
}

#[cfg(unix)]
fn posix_release_child_environment(
    environment: impl IntoIterator<Item = (OsString, Option<OsString>)>,
    rustup_authority: Option<&BoundPosixRustupAuthority>,
    child_tool_path: Option<&Path>,
    bound_cargo: Option<&Path>,
    cargo_home: Option<&Path>,
) -> std::io::Result<BTreeMap<OsString, OsString>> {
    let bound_rustc = rustup_authority
        .map(BoundPosixRustupAuthority::staged_rustc)
        .transpose()?;
    posix_release_child_environment_with_rustc(
        environment,
        rustup_authority,
        bound_rustc.as_deref(),
        child_tool_path,
        bound_cargo,
        cargo_home,
    )
}

#[cfg(unix)]
fn posix_release_child_environment_with_rustc(
    environment: impl IntoIterator<Item = (OsString, Option<OsString>)>,
    rustup_authority: Option<&BoundPosixRustupAuthority>,
    bound_rustc: Option<&Path>,
    child_tool_path: Option<&Path>,
    bound_cargo: Option<&Path>,
    cargo_home: Option<&Path>,
) -> std::io::Result<BTreeMap<OsString, OsString>> {
    let mut encoded = BTreeMap::new();
    for (name, value) in environment {
        let Some(value) = value else {
            continue;
        };
        if !POSIX_RELEASE_CHILD_ENVIRONMENT_ALLOWLIST
            .iter()
            .any(|allowed| name == *allowed)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "POSIX release child environment name is not allowed",
            ));
        }
        if encoded.insert(name, value).is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "POSIX release child environment name is duplicated",
            ));
        }
    }
    validate_posix_git_safe_directory_environment(&encoded)?;
    if bound_rustc.is_some() && encoded.contains_key(OsStr::new("RUSTC")) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "POSIX release child attempts to replace its bound Rust compiler",
        ));
    }
    if let Some(authority) = rustup_authority {
        encoded.insert(OsString::from("RUSTUP_HOME"), authority.home.clone().into());
        encoded.insert(
            OsString::from("RUSTUP_TOOLCHAIN"),
            authority.toolchain.clone(),
        );
    }
    if let Some(bound_rustc) = bound_rustc {
        let metadata = fs::symlink_metadata(bound_rustc)?;
        if !bound_rustc.is_absolute()
            || metadata.file_type().is_symlink()
            || !metadata.is_file()
            || fs::canonicalize(bound_rustc)? != bound_rustc
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "bound POSIX Rust compiler is not one canonical file",
            ));
        }
        encoded.insert(OsString::from("RUSTC"), bound_rustc.as_os_str().to_owned());
    }
    if let Some(bound_cargo) = bound_cargo {
        encoded.insert(OsString::from("CARGO"), bound_cargo.as_os_str().to_owned());
    }
    if let Some(cargo_home) = cargo_home {
        encoded.insert(
            OsString::from("CARGO_HOME"),
            cargo_home.as_os_str().to_owned(),
        );
    }
    if let Some(prefix) = child_tool_path {
        let inherited = encoded.get(OsStr::new("PATH"));
        let paths = std::iter::once(prefix.to_path_buf()).chain(
            inherited
                .into_iter()
                .flat_map(|value| std::env::split_paths(value))
                .filter(|entry| entry != prefix),
        );
        let path = std::env::join_paths(paths).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("cannot encode POSIX staged tool PATH: {error}"),
            )
        })?;
        encoded.insert(OsString::from("PATH"), path);
    }
    if encoded.len() > POSIX_RELEASE_CHILD_ENVIRONMENT_ALLOWLIST.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "POSIX release child environment exceeds its entry bound",
        ));
    }
    Ok(encoded)
}

/// Exercises exact POSIX Rust compiler environment binding without invoking a shell.
///
/// # Errors
///
/// Returns an error when the compiler authority is absent or the environment
/// attempts to replace the exact compiler or retain a compiler wrapper.
#[cfg(unix)]
#[doc(hidden)]
pub fn bind_posix_rustc_environment_for_integration(
    environment: Vec<(OsString, Option<OsString>)>,
    bound_rustc: Option<&Path>,
) -> std::io::Result<BTreeMap<OsString, OsString>> {
    let bound_rustc = bound_rustc.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "bound POSIX Rust compiler authority is absent",
        )
    })?;
    posix_release_child_environment_with_rustc(
        environment,
        None,
        Some(bound_rustc),
        None,
        None,
        None,
    )
}

#[cfg(unix)]
fn validate_posix_git_safe_directory_environment(
    environment: &BTreeMap<OsString, OsString>,
) -> std::io::Result<()> {
    let count = environment.get(OsStr::new("GIT_CONFIG_COUNT"));
    let key = environment.get(OsStr::new("GIT_CONFIG_KEY_0"));
    let value = environment.get(OsStr::new("GIT_CONFIG_VALUE_0"));
    if count.is_none() && key.is_none() && value.is_none() {
        return Ok(());
    }
    let (Some(count), Some(key), Some(value)) = (count, key, value) else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "POSIX release child Git safe.directory environment is incomplete",
        ));
    };
    let directory = Path::new(value);
    if count != OsStr::new("1")
        || key != OsStr::new("safe.directory")
        || !directory.is_absolute()
        || fs::canonicalize(directory).ok().as_deref() != Some(directory)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "POSIX release child Git safe.directory environment differs from policy",
        ));
    }
    Ok(())
}

#[cfg(all(test, unix))]
fn windows_restricted_launch_request(
    restricted_adapter: &Path,
    restricted_adapter_sha256: Digest,
    target_arguments: &[OsString],
) -> Vec<OsString> {
    std::iter::once(restricted_adapter.as_os_str().to_owned())
        .chain(std::iter::once(OsString::from(
            restricted_adapter_sha256.hex(),
        )))
        .chain(target_arguments.iter().cloned())
        .collect()
}

#[cfg(windows)]
const WINDOWS_RELEASE_CHILD_REQUEST_V1: &str = "hell-windows-release-child-v1";

#[cfg(windows)]
const WINDOWS_RELEASE_CHILD_ADDITIONAL_ENVIRONMENT: &[&str] = &[
    "CARGO_INCREMENTAL",
    "CARGO_TARGET_DIR",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_KEY_0",
    "GIT_CONFIG_VALUE_0",
    "RUSTDOCFLAGS",
    "SOURCE_DATE_EPOCH",
];

#[cfg(windows)]
fn windows_release_child_environment_name_allowed(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    RELEASE_CHILD_ENVIRONMENT_ALLOWLIST
        .iter()
        .chain(WINDOWS_RELEASE_CHILD_ADDITIONAL_ENVIRONMENT)
        .any(|allowed| name.eq_ignore_ascii_case(allowed))
}

#[cfg(windows)]
fn windows_cargo_target_argument(argument: &OsStr) -> bool {
    argument == OsStr::new("--target-dir")
        || argument
            .to_str()
            .and_then(|argument| argument.strip_prefix("--target-dir="))
            .is_some()
}

#[cfg(windows)]
fn windows_cargo_target_subcommand_name(argument: &OsStr) -> bool {
    [
        "bench", "build", "check", "clippy", "doc", "fix", "run", "rustc", "rustdoc", "test",
    ]
    .iter()
    .any(|subcommand| argument == OsStr::new(subcommand))
}

#[cfg(windows)]
fn windows_cargo_target_subcommand(arguments: &[OsString]) -> std::io::Result<Option<usize>> {
    if arguments
        .iter()
        .any(|argument| windows_cargo_target_argument(argument))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Windows Cargo request attempts to replace its target authority",
        ));
    }
    Ok(arguments
        .first()
        .is_some_and(|argument| windows_cargo_target_subcommand_name(argument))
        .then_some(0))
}

#[cfg(windows)]
fn windows_bound_cargo_arguments(
    mut arguments: Vec<OsString>,
    subcommand: usize,
    target: &Path,
) -> std::io::Result<Vec<OsString>> {
    if windows_cargo_target_subcommand(&arguments)? != Some(subcommand) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Windows Cargo request has no supported target-producing subcommand",
        ));
    }
    let option = subcommand
        .checked_add(1)
        .expect("bounded Cargo subcommand position cannot overflow");
    arguments.splice(
        option..option,
        [
            OsString::from("--target-dir"),
            target.as_os_str().to_owned(),
        ],
    );
    Ok(arguments)
}

#[cfg(windows)]
fn windows_release_child_environment(
    environment: Vec<(OsString, Option<OsString>)>,
    writable_roots: &[PathBuf],
    required_target: Option<&Path>,
    safe_directory: Option<&Path>,
) -> std::io::Result<Vec<(OsString, OsString)>> {
    let mut retained = Vec::new();
    let mut names = BTreeSet::new();
    for (name, value) in environment {
        let Some(value) = value else {
            continue;
        };
        let Some(name_text) = name.to_str() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Windows release child environment name is not UTF-8",
            ));
        };
        if name_text.contains('=') || !windows_release_child_environment_name_allowed(&name) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Windows release child environment name is not allowed",
            ));
        }
        if !names.insert(name_text.to_ascii_uppercase()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Windows release child environment name is duplicated",
            ));
        }
        retained.push((name, value));
    }
    let entry_limit = RELEASE_CHILD_ENVIRONMENT_ALLOWLIST
        .len()
        .checked_add(WINDOWS_RELEASE_CHILD_ADDITIONAL_ENVIRONMENT.len())
        .expect("fixed Windows environment limit cannot overflow");
    if retained.len() > entry_limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Windows release child environment exceeds its entry bound",
        ));
    }
    let configured_target = retained
        .iter()
        .position(|(name, _)| name.eq_ignore_ascii_case(OsStr::new("CARGO_TARGET_DIR")));
    if configured_target.is_none()
        && let Some(target) = required_target
    {
        retained.push((
            OsString::from("CARGO_TARGET_DIR"),
            target.as_os_str().to_owned(),
        ));
    }
    if let Some((_, target)) = retained
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(OsStr::new("CARGO_TARGET_DIR")))
    {
        let target = Path::new(target);
        let metadata = fs::symlink_metadata(target)?;
        let canonical = fs::canonicalize(target)?;
        if !target.is_absolute()
            || metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || canonical != target
            || (!writable_roots.is_empty() && !writable_roots.iter().any(|root| root == target))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Windows Cargo target environment differs from its writable authority",
            ));
        }
    }
    validate_windows_git_safe_directory_environment(&retained, safe_directory)?;
    retained.sort_by(|(left, _), (right, _)| {
        left.to_string_lossy()
            .to_ascii_uppercase()
            .cmp(&right.to_string_lossy().to_ascii_uppercase())
    });
    Ok(retained)
}

#[cfg(windows)]
fn validate_windows_git_safe_directory_environment(
    environment: &[(OsString, OsString)],
    safe_directory: Option<&Path>,
) -> std::io::Result<()> {
    let find = |expected: &str| {
        environment
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(OsStr::new(expected)))
            .map(|(_, value)| value)
    };
    let count = find("GIT_CONFIG_COUNT");
    let key = find("GIT_CONFIG_KEY_0");
    let value = find("GIT_CONFIG_VALUE_0");
    if count.is_none() && key.is_none() && value.is_none() {
        return Ok(());
    }
    let (Some(count), Some(key), Some(value), Some(safe_directory)) =
        (count, key, value, safe_directory)
    else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Windows release child Git safe.directory environment is incomplete",
        ));
    };
    if count != OsStr::new("1")
        || key != OsStr::new("safe.directory")
        || Path::new(value) != safe_directory
        || !safe_directory.is_absolute()
        || fs::canonicalize(safe_directory).ok().as_deref() != Some(safe_directory)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Windows release child Git safe.directory environment differs from policy",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn windows_release_child_request_fields(
    current_directory: &Path,
    environment: &[(OsString, OsString)],
    target_arguments: &[OsString],
) -> std::io::Result<Vec<OsString>> {
    let metadata = fs::symlink_metadata(current_directory)?;
    if !current_directory.is_absolute()
        || metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || fs::canonicalize(current_directory)? != current_directory
        || target_arguments.is_empty()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Windows release child current directory or target argv differs from policy",
        ));
    }
    let mut fields = Vec::with_capacity(3 + environment.len() * 2 + target_arguments.len());
    fields.push(OsString::from(WINDOWS_RELEASE_CHILD_REQUEST_V1));
    fields.push(current_directory.as_os_str().to_owned());
    fields.push(OsString::from(environment.len().to_string()));
    for (name, value) in environment {
        fields.push(name.clone());
        fields.push(value.clone());
    }
    fields.extend(target_arguments.iter().cloned());
    Ok(fields)
}

/// Builds one canonical restricted-child wire request for external lifecycle coverage.
#[cfg(windows)]
#[doc(hidden)]
pub fn windows_release_child_request_fields_for_integration(
    current_directory: &Path,
    environment: Vec<(OsString, OsString)>,
    target_arguments: &[OsString],
) -> std::io::Result<Vec<OsString>> {
    let environment = windows_release_child_environment(
        environment
            .into_iter()
            .map(|(name, value)| (name, Some(value)))
            .collect(),
        &[],
        None,
        None,
    )?;
    windows_release_child_request_fields(current_directory, &environment, target_arguments)
}

/// Builds a canonical restricted-child request with one exact writable Cargo target.
#[cfg(windows)]
#[doc(hidden)]
pub fn windows_nightly_child_request_fields_for_integration(
    current_directory: &Path,
    environment: Vec<(OsString, OsString)>,
    target_arguments: &[OsString],
    writable_target: &Path,
) -> std::io::Result<Vec<OsString>> {
    let metadata = fs::symlink_metadata(writable_target)?;
    if !writable_target.is_absolute()
        || metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || fs::canonicalize(writable_target)? != writable_target
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Windows Nightly writable target is not one canonical directory",
        ));
    }
    let mut target_arguments = target_arguments.to_vec();
    let target_is_cargo = target_arguments
        .first()
        .is_some_and(|program| windows_executable_has_logical_name(program.as_os_str(), "cargo"));
    if target_is_cargo {
        let program = target_arguments.remove(0);
        let subcommand = windows_cargo_target_subcommand(&target_arguments)?.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Windows Nightly Cargo request has no target-producing subcommand",
            )
        })?;
        target_arguments =
            windows_bound_cargo_arguments(target_arguments, subcommand, writable_target)?;
        target_arguments.insert(0, program);
    }
    let environment = windows_release_child_environment(
        environment
            .into_iter()
            .map(|(name, value)| (name, Some(value)))
            .collect(),
        &[writable_target.to_path_buf()],
        target_is_cargo.then_some(writable_target),
        None,
    )?;
    windows_release_child_request_fields(current_directory, &environment, &target_arguments)
}

#[cfg(windows)]
fn windows_restricted_launch_request_with_environment(
    restricted_adapter: &Path,
    restricted_adapter_sha256: Digest,
    current_directory: &Path,
    environment: &[(OsString, OsString)],
    target_arguments: &[OsString],
) -> std::io::Result<Vec<OsString>> {
    let mut request = Vec::new();
    request.push(restricted_adapter.as_os_str().to_owned());
    request.push(OsString::from(restricted_adapter_sha256.hex()));
    request.extend(windows_release_child_request_fields(
        current_directory,
        environment,
        target_arguments,
    )?);
    Ok(request)
}

#[cfg(windows)]
fn validate_windows_cargo_target_binding(
    environment: &[(OsString, OsString)],
    target_arguments: &[OsString],
) -> std::io::Result<bool> {
    let target_is_cargo = target_arguments
        .first()
        .is_some_and(|program| windows_executable_has_logical_name(program.as_os_str(), "cargo"));
    if !target_is_cargo {
        return Ok(false);
    }
    let configured_target = environment
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(OsStr::new("CARGO_TARGET_DIR")))
        .map(|(_, value)| Path::new(value));
    let target_subcommand = target_arguments
        .get(1)
        .is_some_and(|argument| windows_cargo_target_subcommand_name(argument));
    let explicit_target = match (target_subcommand, target_arguments) {
        (true, [_, _, option, target, remaining @ ..])
            if option == OsStr::new("--target-dir")
                && !remaining
                    .iter()
                    .any(|argument| windows_cargo_target_argument(argument)) =>
        {
            Some(Path::new(target))
        }
        (true, _) => None,
        (false, _) => {
            if configured_target.is_some()
                || target_arguments
                    .iter()
                    .skip(1)
                    .any(|argument| windows_cargo_target_argument(argument))
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "target-free Windows Cargo request retains a target authority",
                ));
            }
            return Ok(false);
        }
    };
    if explicit_target.is_none() || explicit_target != configured_target {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Windows Cargo argv target differs from its environment authority",
        ));
    }
    Ok(true)
}

/// One decoded, closed Windows release-child request.
#[cfg(windows)]
#[doc(hidden)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsReleaseChildRequest {
    current_directory: PathBuf,
    environment: Vec<(OsString, OsString)>,
    target_arguments: Vec<OsString>,
}

#[cfg(windows)]
impl WindowsReleaseChildRequest {
    /// Returns the exact canonical current directory.
    #[must_use]
    pub fn current_directory(&self) -> &Path {
        &self.current_directory
    }

    /// Returns the approved environment entries.
    #[must_use]
    pub fn environment(&self) -> &[(OsString, OsString)] {
        &self.environment
    }

    /// Returns the exact target argv.
    #[must_use]
    pub fn target_arguments(&self) -> &[OsString] {
        &self.target_arguments
    }

    /// Returns the exact target directory for a Cargo release build request.
    #[must_use]
    pub fn cargo_release_target(&self) -> Option<&Path> {
        let [
            program,
            subcommand,
            target_option,
            target,
            release,
            locked,
            package_option,
            package,
            binary_option,
            binary,
            features_option,
            features,
        ] = self.target_arguments.as_slice()
        else {
            return None;
        };
        let program_path = Path::new(program);
        let program_metadata = fs::symlink_metadata(program_path).ok()?;
        if !program_path.is_absolute()
            || program_metadata.file_type().is_symlink()
            || !program_metadata.is_file()
            || fs::canonicalize(program_path).ok()? != program_path
            || !windows_executable_has_logical_name(program, "cargo")
            || subcommand != OsStr::new("build")
            || target_option != OsStr::new("--target-dir")
            || release != OsStr::new("--release")
            || locked != OsStr::new("--locked")
            || package_option != OsStr::new("--package")
            || package != OsStr::new("hell-cli")
            || binary_option != OsStr::new("--bin")
            || binary != OsStr::new("hell")
            || features_option != OsStr::new("--features")
            || features != OsStr::new("compat-tracing")
        {
            return None;
        }
        let configured = self
            .environment
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(OsStr::new("CARGO_TARGET_DIR")))
            .map(|(_, value)| Path::new(value))?;
        (configured == Path::new(target)).then_some(configured)
    }

    /// Splits the request into its exact environment and argv.
    #[must_use]
    pub fn into_parts(self) -> (PathBuf, Vec<(OsString, OsString)>, Vec<OsString>) {
        (
            self.current_directory,
            self.environment,
            self.target_arguments,
        )
    }

    /// Recreates the bounded wire fields after trusted decoding.
    ///
    /// # Errors
    ///
    /// Returns an error when the retained target argv is empty.
    pub fn fields(&self) -> std::io::Result<Vec<OsString>> {
        windows_release_child_request_fields(
            &self.current_directory,
            &self.environment,
            &self.target_arguments,
        )
    }
}

/// Parses and validates a closed Windows release-child request.
///
/// # Errors
///
/// Returns an error for a version mismatch, malformed environment count,
/// disallowed or duplicate environment name, redirected Cargo target, or empty argv.
#[cfg(windows)]
#[doc(hidden)]
pub fn parse_windows_release_child_request(
    fields: Vec<OsString>,
) -> std::io::Result<WindowsReleaseChildRequest> {
    let mut fields = fields.into_iter();
    if fields.next().as_deref() != Some(OsStr::new(WINDOWS_RELEASE_CHILD_REQUEST_V1)) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Windows release child request version differs",
        ));
    }
    let current_directory = PathBuf::from(fields.next().ok_or_else(|| {
        std::io::Error::other("Windows release child current directory is absent")
    })?);
    let directory_metadata = fs::symlink_metadata(&current_directory)?;
    if !current_directory.is_absolute()
        || directory_metadata.file_type().is_symlink()
        || !directory_metadata.is_dir()
        || fs::canonicalize(&current_directory)? != current_directory
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Windows release child current directory is redirected",
        ));
    }
    let count_text = fields
        .next()
        .ok_or_else(|| std::io::Error::other("Windows release child environment count is absent"))?
        .into_string()
        .map_err(|_| {
            std::io::Error::other("Windows release child environment count is not UTF-8")
        })?;
    let count = count_text.parse::<usize>().map_err(|_| {
        std::io::Error::other("Windows release child environment count is malformed")
    })?;
    let entry_limit = RELEASE_CHILD_ENVIRONMENT_ALLOWLIST
        .len()
        .checked_add(WINDOWS_RELEASE_CHILD_ADDITIONAL_ENVIRONMENT.len())
        .expect("fixed Windows environment limit cannot overflow");
    if count_text != count.to_string() || count > entry_limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Windows release child environment count is noncanonical or exceeds its entry bound",
        ));
    }
    let mut environment = Vec::with_capacity(count);
    let mut previous_name = None::<String>;
    for _ in 0..count {
        let name = fields.next().ok_or_else(|| {
            std::io::Error::other("Windows release child environment name is absent")
        })?;
        let value = fields.next().ok_or_else(|| {
            std::io::Error::other("Windows release child environment value is absent")
        })?;
        let canonical_name = name
            .to_str()
            .ok_or_else(|| {
                std::io::Error::other("Windows release child environment name is not UTF-8")
            })?
            .to_ascii_uppercase();
        if previous_name
            .as_ref()
            .is_some_and(|previous| previous >= &canonical_name)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Windows release child environment order is noncanonical",
            ));
        }
        previous_name = Some(canonical_name);
        environment.push((name, Some(value)));
    }
    let environment =
        windows_release_child_environment(environment, &[], None, Some(&current_directory))?;
    let target_arguments = fields.collect::<Vec<_>>();
    let has_target = environment
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case(OsStr::new("CARGO_TARGET_DIR")));
    let has_release_epoch = environment
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case(OsStr::new("SOURCE_DATE_EPOCH")));
    let has_bound_cargo_target =
        validate_windows_cargo_target_binding(&environment, &target_arguments)?;
    if (has_bound_cargo_target || has_release_epoch) && !has_target {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Windows release child target and epoch bindings are incomplete",
        ));
    }
    if target_arguments.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Windows release child target argv is empty",
        ));
    }
    Ok(WindowsReleaseChildRequest {
        current_directory,
        environment,
        target_arguments,
    })
}

#[cfg(unix)]
const POSIX_RUSTUP_ENTRY_LIMIT: usize = 100_000;

#[cfg(unix)]
const POSIX_CARGO_CACHE_BYTE_LIMIT: u64 = 8 * 1024 * 1024 * 1024;

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PosixRustupAccessRequirement {
    AncestorDirectory,
    AuthorityDirectory,
    ReadableFile,
    ExecutableFile,
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct PosixRustupEntryIdentity {
    path: PathBuf,
    device: u64,
    inode: u64,
    links: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    requirement: PosixRustupAccessRequirement,
}

#[cfg(unix)]
fn validate_posix_rustup_proxy_identity(
    identity: &PosixRustupProxyIdentity,
    candidate_uid: u32,
    candidate_group_ids: &[u32],
) -> std::io::Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let cargo_parent = identity.cargo_invocation.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "logical Cargo invocation has no parent",
        )
    })?;
    let rustup_parent = identity.rustup_invocation.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "standard Rustup invocation has no parent",
        )
    })?;
    if !identity.cargo_invocation.is_absolute()
        || !identity.cargo.is_absolute()
        || !identity.rustup_invocation.is_absolute()
        || !identity.rustup.is_absolute()
        || fs::canonicalize(&identity.cargo_invocation)? != identity.cargo
        || fs::canonicalize(&identity.cargo)? != identity.cargo
        || fs::canonicalize(&identity.rustup_invocation)? != identity.rustup
        || fs::canonicalize(&identity.rustup)? != identity.rustup
        || fs::canonicalize(cargo_parent)? != cargo_parent
        || fs::canonicalize(rustup_parent)? != rustup_parent
        || identity.cargo_invocation.file_name() != Some(OsStr::new("cargo"))
        || identity.rustup_invocation.file_name() != Some(OsStr::new("rustup"))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "POSIX Cargo/Rustup proxy authority is not canonical",
        ));
    }
    let cargo_invocation = fs::metadata(&identity.cargo_invocation)?;
    let cargo = fs::symlink_metadata(&identity.cargo)?;
    let rustup = fs::symlink_metadata(&identity.rustup)?;
    if !cargo_invocation.is_file()
        || !cargo.is_file()
        || !rustup.is_file()
        || cargo.file_type().is_symlink()
        || rustup.file_type().is_symlink()
        || cargo_invocation.dev() != identity.device
        || cargo_invocation.ino() != identity.inode
        || cargo.dev() != identity.device
        || cargo.ino() != identity.inode
        || rustup.dev() != identity.device
        || rustup.ino() != identity.inode
        || cargo.permissions().mode() & 0o111 == 0
        || rustup.permissions().mode() & 0o111 == 0
        || !posix_rustup_owner_is_trusted(cargo.uid(), candidate_uid)
        || !posix_rustup_owner_is_trusted(rustup.uid(), candidate_uid)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "POSIX Cargo/Rustup proxy file identity is not trusted",
        ));
    }
    let (_, cargo_access) =
        posix_rustup_effective_access(cargo.permissions().mode(), cargo.gid(), candidate_group_ids);
    let (_, rustup_access) = posix_rustup_effective_access(
        rustup.permissions().mode(),
        rustup.gid(),
        candidate_group_ids,
    );
    if cargo_access & 0o2 != 0 || rustup_access & 0o2 != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "candidate principal can modify the POSIX Cargo/Rustup proxy authority",
        ));
    }
    Ok(())
}

#[cfg(unix)]
#[derive(Clone, Debug)]
struct BoundPosixCargoDenyAuthority {
    source: BoundPosixStandardExecutableIdentity,
    source_sha256: Digest,
    staged: PathBuf,
    staged_sha256: Digest,
    staged_identity: PosixAdapterIdentity,
    cargo_home: PathBuf,
    metadata: BoundPosixCargoDenyMetadataAuthority,
    candidate_uid: u32,
    trusted_owner: u32,
    trusted_group_id: u32,
    cargo_home_inventory: Vec<PosixCargoCacheEntryIdentity>,
}

#[cfg(unix)]
#[derive(Clone, Debug)]
struct BoundPosixCargoDenyMetadataAuthority {
    directory: PathBuf,
    directory_identity: PosixCargoDenyMetadataFileIdentity,
    path: PathBuf,
    file_identity: PosixCargoDenyMetadataFileIdentity,
    size: u64,
    sha256: Digest,
    trusted_owner: u32,
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct PosixCargoDenyMetadataFileIdentity {
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct PosixCargoCacheEntryIdentity {
    relative: PathBuf,
    directory: bool,
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    size: u64,
    sha256: Option<Digest>,
}

#[cfg(unix)]
impl BoundPosixCargoDenyAuthority {
    fn new(
        authority: PosixCargoDenyAuthority,
        candidate_uid: u32,
        candidate_group_ids: &[u32],
        writable_roots: &[PathBuf],
    ) -> std::io::Result<Self> {
        let metadata = BoundPosixCargoDenyMetadataAuthority::new(
            authority.metadata.clone(),
            candidate_uid,
            candidate_group_ids,
        )?;
        Self::new_with_metadata(
            authority,
            candidate_uid,
            candidate_group_ids,
            writable_roots,
            metadata,
            true,
        )
    }

    fn new_with_metadata(
        authority: PosixCargoDenyAuthority,
        candidate_uid: u32,
        candidate_group_ids: &[u32],
        writable_roots: &[PathBuf],
        metadata: BoundPosixCargoDenyMetadataAuthority,
        require_distinct_trusted_owner: bool,
    ) -> std::io::Result<Self> {
        let PosixCargoDenyAuthority {
            source,
            source_sha256,
            staged,
            staged_sha256,
            cargo_home,
            metadata: _,
            trusted_owner,
            trusted_group_id,
        } = authority;
        let source = BoundPosixStandardExecutableIdentity::new_named(source, "cargo-deny")?;
        let staged = fs::canonicalize(staged)?;
        if staged.file_name() != Some(OsStr::new("cargo-deny")) || source_sha256 != staged_sha256 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "POSIX cargo-deny source and staged authority differ",
            ));
        }
        let staged_identity = posix_adapter_identity(&staged)?;
        let cargo_home = fs::canonicalize(cargo_home)?;
        let within_writable_root = writable_roots.iter().any(|root| {
            fs::canonicalize(root)
                .is_ok_and(|canonical_root| cargo_home.starts_with(canonical_root))
        });
        if !within_writable_root {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "POSIX cargo-deny home is outside the candidate writable authority",
            ));
        }
        if candidate_group_ids.contains(&trusted_group_id) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "candidate principal belongs to the trusted cargo-deny cache reader group",
            ));
        }
        if require_distinct_trusted_owner && trusted_owner == candidate_uid {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "candidate principal owns the trusted cargo-deny cache",
            ));
        }
        let cargo_home_inventory = posix_candidate_cargo_cache_inventory(
            &cargo_home,
            candidate_uid,
            trusted_owner,
            trusted_group_id,
        )?;
        let bound = Self {
            source,
            source_sha256,
            staged,
            staged_sha256,
            staged_identity,
            cargo_home,
            metadata,
            candidate_uid,
            trusted_owner,
            trusted_group_id,
            cargo_home_inventory,
        };
        bound.revalidate()?;
        Ok(bound)
    }

    #[cfg(test)]
    fn new_for_fixture(
        authority: PosixCargoDenyAuthority,
        candidate_uid: u32,
        candidate_group_ids: &[u32],
        writable_roots: &[PathBuf],
        metadata_candidate_uid: u32,
    ) -> std::io::Result<Self> {
        let metadata = BoundPosixCargoDenyMetadataAuthority::new(
            authority.metadata.clone(),
            metadata_candidate_uid,
            candidate_group_ids,
        )?;
        Self::new_with_metadata(
            authority,
            candidate_uid,
            candidate_group_ids,
            writable_roots,
            metadata,
            false,
        )
    }

    fn revalidate(&self) -> std::io::Result<()> {
        self.source.revalidate()?;
        if sha256_file(&self.source.identity.canonical)? != self.source_sha256 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "POSIX cargo-deny source digest changed before spawn",
            ));
        }
        verify_posix_adapter_identity(
            &self.staged,
            &self.staged,
            self.staged_sha256,
            &self.staged_identity,
        )?;
        self.cargo_home_inventory.first().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "POSIX cargo-deny cache inventory is empty",
            )
        })?;
        let observed = posix_candidate_cargo_cache_inventory(
            &self.cargo_home,
            self.candidate_uid,
            self.trusted_owner,
            self.trusted_group_id,
        )?;
        if observed != self.cargo_home_inventory {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "POSIX cargo-deny cache changed before spawn",
            ));
        }
        self.metadata.revalidate()?;
        Ok(())
    }

    fn request_is_bound(&self, requested: &OsStr, resolved: &Path) -> std::io::Result<bool> {
        let requested = Path::new(requested);
        if requested.file_name() != Some(OsStr::new("cargo-deny")) {
            return Ok(false);
        }
        if requested.components().count() != 1 && requested != self.source.identity.invocation {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "cargo-deny request is outside the exact staged authority",
            ));
        }
        self.revalidate()?;
        if resolved != self.source.identity.invocation
            || fs::canonicalize(resolved)? != self.source.identity.canonical
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "standard cargo-deny authority changed before spawn",
            ));
        }
        Ok(true)
    }
}

#[cfg(unix)]
impl BoundPosixCargoDenyMetadataAuthority {
    fn new(
        authority: PosixCargoDenyMetadataAuthority,
        candidate_uid: u32,
        candidate_group_ids: &[u32],
    ) -> std::io::Result<Self> {
        let PosixCargoDenyMetadataAuthority {
            directory,
            path,
            size,
            sha256,
            trusted_owner,
        } = authority;
        let directory = fs::canonicalize(directory)?;
        let path = fs::canonicalize(path)?;
        if trusted_owner == candidate_uid
            || !candidate_group_ids.contains(&candidate_uid)
            || !posix_cargo_deny_metadata_path_is_exact(&directory, &path)
            || !posix_cargo_deny_metadata_parent_is_trusted(&directory)?
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "POSIX cargo-deny metadata path or ownership differs from policy",
            ));
        }
        let directory_identity = posix_cargo_deny_metadata_identity(&directory, true)?;
        let file_identity = posix_cargo_deny_metadata_identity(&path, false)?;
        if directory_identity.uid != trusted_owner
            || directory_identity.mode != 0o555
            || file_identity.uid != trusted_owner
            || file_identity.mode != 0o444
            || fs::metadata(&path)?.len() != size
            || sha256_file(&path)? != sha256
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "POSIX cargo-deny metadata identity differs from policy",
            ));
        }
        let bound = Self {
            directory,
            directory_identity,
            path,
            file_identity,
            size,
            sha256,
            trusted_owner,
        };
        bound.revalidate()?;
        Ok(bound)
    }

    fn revalidate(&self) -> std::io::Result<()> {
        if !posix_cargo_deny_metadata_path_is_exact(&self.directory, &self.path)
            || !posix_cargo_deny_metadata_parent_is_trusted(&self.directory)?
            || !posix_cargo_deny_metadata_directory_is_closed(&self.directory)?
            || posix_cargo_deny_metadata_identity(&self.directory, true)? != self.directory_identity
            || posix_cargo_deny_metadata_identity(&self.path, false)? != self.file_identity
            || self.directory_identity.uid != self.trusted_owner
            || self.directory_identity.mode != 0o555
            || self.file_identity.uid != self.trusted_owner
            || self.file_identity.mode != 0o444
            || fs::metadata(&self.path)?.len() != self.size
            || sha256_file(&self.path)? != self.sha256
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "POSIX cargo-deny metadata changed before spawn",
            ));
        }
        Ok(())
    }
}

#[cfg(unix)]
fn posix_cargo_deny_metadata_directory_is_closed(directory: &Path) -> std::io::Result<bool> {
    let mut members = fs::read_dir(directory)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<std::io::Result<Vec<_>>>()?;
    members.sort();
    Ok(members == [OsString::from("metadata.json")])
}

#[cfg(unix)]
fn posix_cargo_deny_metadata_parent_is_trusted(directory: &Path) -> std::io::Result<bool> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let Some(parent) = directory.parent() else {
        return Ok(false);
    };
    let metadata = fs::symlink_metadata(parent)?;
    Ok(!metadata.file_type().is_symlink()
        && metadata.is_dir()
        && metadata.uid() == 0
        && metadata.gid() == 0
        && metadata.permissions().mode() & 0o7777 == 0o1777
        && fs::canonicalize(parent)? == parent)
}

#[cfg(unix)]
fn posix_cargo_deny_metadata_path_is_exact(directory: &Path, path: &Path) -> bool {
    let Some(name) = directory.file_name().and_then(OsStr::to_str) else {
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
    matches!(directory.parent(), Some(parent) if parent == Path::new("/var/tmp") || parent == Path::new("/private/var/tmp"))
        && canonical_number(process)
        && canonical_number(sequence)
        && path == directory.join("metadata.json")
}

#[cfg(unix)]
fn posix_cargo_deny_metadata_identity(
    path: &Path,
    directory: bool,
) -> std::io::Result<PosixCargoDenyMetadataFileIdentity> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || directory != metadata.is_dir()
        || (!directory && (!metadata.is_file() || metadata.nlink() != 1))
        || fs::canonicalize(path)? != path
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "POSIX cargo-deny metadata is redirected or special",
        ));
    }
    Ok(PosixCargoDenyMetadataFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode: metadata.permissions().mode() & 0o7777,
    })
}

#[cfg(unix)]
fn posix_candidate_cargo_cache_inventory(
    cargo_home: &Path,
    candidate_uid: u32,
    trusted_owner: u32,
    trusted_group_id: u32,
) -> std::io::Result<Vec<PosixCargoCacheEntryIdentity>> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let mut pending = vec![cargo_home.to_path_buf()];
    let mut inventory = Vec::new();
    let mut bytes = 0_u64;
    let lock = Path::new("advisory-dbs").join("db.lock");
    let advisory_root = Path::new("advisory-dbs");
    let mut found_lock = false;
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path)?;
        let directory = metadata.is_dir();
        let relative = path
            .strip_prefix(cargo_home)
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "POSIX cargo-deny cache entry escapes its home",
                )
            })?
            .to_path_buf();
        let is_lock = relative == lock;
        let is_advisory_root = relative == advisory_root;
        let expected_owner = if is_lock || is_advisory_root {
            candidate_uid
        } else {
            trusted_owner
        };
        if metadata.file_type().is_symlink()
            || (!directory && !metadata.is_file())
            || (!directory && metadata.nlink() != 1)
            || fs::canonicalize(&path)? != path
            || metadata.uid() != expected_owner
            || metadata.gid() != trusted_group_id
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "POSIX cargo-deny cache identity differs from its candidate-owned policy",
            ));
        }
        let mode = metadata.permissions().mode() & 0o7777;
        let expected_mode = match (is_lock, is_advisory_root) {
            // The empty lock is synchronization state shared across the
            // candidate/trusted-group boundary; its database payloads stay
            // immutable beneath the advisory root.
            (true, _) => 0o660,
            (_, true) => 0o750,
            (_, _) if directory => 0o555,
            (_, _) => 0o444,
        };
        if mode != expected_mode || (is_lock && (directory || metadata.len() != 0)) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "POSIX cargo-deny cache permissions differ from policy",
            ));
        }
        found_lock |= is_lock;
        let size = if directory { 0 } else { metadata.len() };
        bytes = bytes.checked_add(size).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "POSIX cargo-deny cache byte count overflowed",
            )
        })?;
        if inventory.len() >= POSIX_RUSTUP_ENTRY_LIMIT || bytes > POSIX_CARGO_CACHE_BYTE_LIMIT {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "POSIX cargo-deny cache exceeds its closed resource bound",
            ));
        }
        let sha256 = (!directory && !is_lock)
            .then(|| sha256_file(&path))
            .transpose()?;
        inventory.push(PosixCargoCacheEntryIdentity {
            relative,
            directory,
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode,
            size,
            sha256,
        });
        if directory {
            for entry in fs::read_dir(&path)? {
                pending.push(entry?.path());
            }
        }
    }
    if !found_lock {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "POSIX cargo-deny advisory lock authority is absent",
        ));
    }
    inventory.sort_by(|left, right| left.relative.cmp(&right.relative));
    Ok(inventory)
}

#[cfg(unix)]
#[derive(Clone, Debug)]
struct BoundPosixStackAuthority {
    source: BoundPosixStandardExecutableIdentity,
    source_sha256: Digest,
    staged: PathBuf,
    staged_sha256: Digest,
    staged_identity: PosixAdapterIdentity,
    stack_root: PathBuf,
    stack_root_identity: PosixStackRootIdentity,
    candidate_uid: u32,
    candidate_group_ids: Arc<[u32]>,
    work: Option<BoundPosixStackWorkAuthority>,
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct PosixStackDirectoryIdentity {
    path: PathBuf,
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
}

#[cfg(unix)]
impl PosixStackDirectoryIdentity {
    fn bind(path: &Path) -> std::io::Result<Self> {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let metadata = fs::symlink_metadata(path)?;
        if !path.is_absolute()
            || metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || fs::canonicalize(path)? != path
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "POSIX Stack work authority is not one canonical directory",
            ));
        }
        Ok(Self {
            path: path.to_path_buf(),
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode: metadata.permissions().mode() & 0o7777,
        })
    }

    fn revalidate(&self) -> std::io::Result<()> {
        if Self::bind(&self.path)? != *self {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "POSIX Stack work directory identity changed before spawn",
            ));
        }
        Ok(())
    }
}

#[cfg(unix)]
#[derive(Clone, Debug)]
struct BoundPosixStackWorkAuthority {
    source: PosixStackDirectoryIdentity,
    work: PosixStackDirectoryIdentity,
    relative: PathBuf,
    candidate_uid: u32,
    candidate_group_ids: Arc<[u32]>,
}

#[cfg(unix)]
impl BoundPosixStackWorkAuthority {
    fn new(
        source: &Path,
        work: &Path,
        candidate_uid: u32,
        candidate_group_ids: &[u32],
    ) -> std::io::Result<Self> {
        let source = PosixStackDirectoryIdentity::bind(source)?;
        let work = PosixStackDirectoryIdentity::bind(work)?;
        let relative = PathBuf::from(".stack-work");
        if work.path != source.path.join(&relative)
            || work.path.parent() != Some(source.path.as_path())
            || fs::canonicalize(source.path.join(&relative))? != work.path
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "POSIX Stack work directory is not the exact reserved source child",
            ));
        }
        if work.uid != candidate_uid
            || candidate_group_ids.contains(&work.gid)
            || work.mode != 0o750
            || source.mode != 0o555
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "POSIX Stack work directory access differs from its bound authority",
            ));
        }
        let bound = Self {
            source,
            work,
            relative,
            candidate_uid,
            candidate_group_ids: candidate_group_ids.into(),
        };
        bound.revalidate()?;
        Ok(bound)
    }

    fn revalidate(&self) -> std::io::Result<()> {
        if self.relative != Path::new(".stack-work")
            || self.work.path != self.source.path.join(&self.relative)
            || self.work.path.parent() != Some(self.source.path.as_path())
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "POSIX Stack work authority relation changed before spawn",
            ));
        }
        for identity in [&self.source, &self.work] {
            identity.revalidate()?;
        }
        if self.work.uid != self.candidate_uid
            || self.candidate_group_ids.contains(&self.work.gid)
            || self.work.mode != 0o750
            || self.source.mode != 0o555
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "POSIX Stack work directory access changed before spawn",
            ));
        }
        if fs::canonicalize(self.source.path.join(&self.relative))? != self.work.path {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "POSIX Stack relative work path changed before spawn",
            ));
        }
        Ok(())
    }
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct PosixStackRootIdentity {
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
}

#[cfg(unix)]
impl BoundPosixStackAuthority {
    fn new(
        authority: PosixStackAuthority,
        candidate_uid: u32,
        candidate_group_ids: &[u32],
        writable_roots: &[PathBuf],
    ) -> std::io::Result<Self> {
        let PosixStackAuthority {
            source,
            source_sha256,
            staged,
            staged_sha256,
            stack_root,
            trusted_group_id,
        } = authority;
        let source = BoundPosixStandardExecutableIdentity::new_named(source, "stack")?;
        let staged = fs::canonicalize(staged)?;
        if staged.file_name() != Some(OsStr::new("stack")) || source_sha256 != staged_sha256 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "POSIX Stack source and staged authority differ",
            ));
        }
        let staged_identity = posix_adapter_identity(&staged)?;
        if candidate_group_ids.contains(&trusted_group_id) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "candidate principal belongs to the trusted Stack-root reader group",
            ));
        }
        let stack_root = fs::canonicalize(stack_root)?;
        if !writable_roots.iter().any(|root| {
            fs::canonicalize(root)
                .is_ok_and(|canonical_root| stack_root.starts_with(canonical_root))
        }) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "POSIX Stack root is outside the candidate writable authority",
            ));
        }
        let stack_root_identity =
            posix_stack_root_identity(&stack_root, candidate_uid, trusted_group_id)?;
        if fs::read_dir(&stack_root)?.next().is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "initial POSIX Stack root is not empty",
            ));
        }
        let bound = Self {
            source,
            source_sha256,
            staged,
            staged_sha256,
            staged_identity,
            stack_root,
            stack_root_identity,
            candidate_uid,
            candidate_group_ids: candidate_group_ids.into(),
            work: None,
        };
        bound.revalidate()?;
        Ok(bound)
    }

    fn revalidate(&self) -> std::io::Result<()> {
        self.source.revalidate()?;
        if sha256_file(&self.source.identity.canonical)? != self.source_sha256 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "POSIX Stack source digest changed before spawn",
            ));
        }
        verify_posix_adapter_identity(
            &self.staged,
            &self.staged,
            self.staged_sha256,
            &self.staged_identity,
        )?;
        if posix_stack_root_identity(
            &self.stack_root,
            self.stack_root_identity.uid,
            self.stack_root_identity.gid,
        )? != self.stack_root_identity
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "POSIX Stack root identity changed before spawn",
            ));
        }
        if let Some(work) = &self.work {
            work.revalidate()?;
        }
        Ok(())
    }

    fn bind_work(&mut self, source: &Path, work: &Path) -> std::io::Result<()> {
        if self.work.is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "POSIX Stack work authority is already bound",
            ));
        }
        self.work = Some(BoundPosixStackWorkAuthority::new(
            source,
            work,
            self.candidate_uid,
            &self.candidate_group_ids,
        )?);
        self.revalidate()
    }

    fn request_is_bound(&self, requested: &OsStr, resolved: &Path) -> std::io::Result<bool> {
        let requested = Path::new(requested);
        if requested.file_name() != Some(OsStr::new("stack")) {
            return Ok(false);
        }
        if requested.components().count() != 1 && requested != self.source.identity.invocation {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Stack request is outside the exact staged authority",
            ));
        }
        self.revalidate()?;
        if resolved != self.source.identity.invocation
            || fs::canonicalize(resolved)? != self.source.identity.canonical
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "standard Stack authority changed before spawn",
            ));
        }
        Ok(true)
    }

    fn mapped_request(
        &self,
        requested: &OsStr,
        resolved: &Path,
    ) -> std::io::Result<Option<(PathBuf, PathBuf, Option<PathBuf>)>> {
        self.request_is_bound(requested, resolved).map(|matches| {
            matches.then(|| {
                (
                    self.staged.clone(),
                    self.stack_root.clone(),
                    self.work.as_ref().map(|work| work.relative.clone()),
                )
            })
        })
    }
}

#[cfg(unix)]
fn posix_stack_root_identity(
    stack_root: &Path,
    candidate_uid: u32,
    trusted_group_id: u32,
) -> std::io::Result<PosixStackRootIdentity> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let metadata = fs::symlink_metadata(stack_root)?;
    let mode = metadata.permissions().mode() & 0o7777;
    if !stack_root.is_absolute()
        || metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || fs::canonicalize(stack_root)? != stack_root
        || metadata.uid() != candidate_uid
        || metadata.gid() != trusted_group_id
        || mode != 0o750
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "POSIX Stack root identity or permissions differ from policy",
        ));
    }
    Ok(PosixStackRootIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode,
    })
}

#[cfg(unix)]
#[derive(Clone, Debug)]
enum BoundPosixCargoSourceAuthority {
    Native {
        cargo: BoundPosixCanonicalExecutableIdentity,
        standard_rustup: BoundPosixStandardExecutableIdentity,
    },
    Rustup(Box<BoundPosixRustupAuthority>),
}

#[cfg(unix)]
impl BoundPosixCargoSourceAuthority {
    fn new(
        authority: PosixCargoSourceAuthority,
        cargo_source: &Path,
        candidate_uid: u32,
        candidate_group_ids: Arc<[u32]>,
    ) -> std::io::Result<Self> {
        match authority {
            PosixCargoSourceAuthority::Native {
                cargo,
                standard_rustup,
            } => {
                if cargo_source.file_name() == Some(OsStr::new("rustup")) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "a Cargo executable named rustup requires exact Rustup authority",
                    ));
                }
                let cargo = BoundPosixCanonicalExecutableIdentity::new(cargo)?;
                if cargo.0.canonical != cargo_source {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "native Cargo authority does not match the Cargo source",
                    ));
                }
                let standard_rustup = BoundPosixStandardExecutableIdentity::new(standard_rustup)?;
                if standard_rustup.same_file(cargo_source)? {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "a Rustup-backed Cargo executable cannot be classified as native",
                    ));
                }
                Ok(Self::Native {
                    cargo,
                    standard_rustup,
                })
            }
            PosixCargoSourceAuthority::Rustup(authority) => {
                if authority.proxy_identity.cargo != cargo_source {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "Rustup authority does not correspond to the Cargo source identity",
                    ));
                }
                Ok(Self::Rustup(Box::new(BoundPosixRustupAuthority::new(
                    *authority,
                    candidate_uid,
                    candidate_group_ids,
                )?)))
            }
        }
    }

    fn revalidate(&self, cargo_source: &Path) -> std::io::Result<()> {
        match self {
            Self::Native {
                cargo,
                standard_rustup,
            } => {
                cargo.revalidate()?;
                standard_rustup.revalidate()?;
                if cargo.0.canonical != cargo_source || standard_rustup.same_file(cargo_source)? {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "native Cargo classification changed before spawn",
                    ));
                }
                Ok(())
            }
            Self::Rustup(authority) => authority.revalidate(),
        }
    }

    fn rustup(&self) -> Option<&BoundPosixRustupAuthority> {
        match self {
            Self::Native { .. } => None,
            Self::Rustup(authority) => Some(authority),
        }
    }

    fn child_tool_path(&self, cargo_adapter: &Path) -> std::io::Result<PathBuf> {
        match self {
            Self::Native { .. } => cargo_adapter
                .parent()
                .map(Path::to_path_buf)
                .ok_or_else(|| std::io::Error::other("staged Cargo has no parent")),
            Self::Rustup(authority) => authority.selected_tool_bin(),
        }
    }
}

#[cfg(unix)]
#[derive(Clone, Debug)]
struct BoundPosixStandardExecutableIdentity {
    identity: PosixStandardExecutableIdentity,
    logical_name: &'static str,
}

#[cfg(unix)]
#[derive(Clone, Debug)]
struct BoundPosixCanonicalExecutableIdentity(PosixCanonicalExecutableIdentity);

#[cfg(unix)]
impl BoundPosixCanonicalExecutableIdentity {
    fn new(identity: PosixCanonicalExecutableIdentity) -> std::io::Result<Self> {
        let bound = Self(identity);
        bound.revalidate()?;
        Ok(bound)
    }

    fn revalidate(&self) -> std::io::Result<()> {
        use std::os::unix::fs::MetadataExt as _;

        let metadata = fs::metadata(&self.0.canonical)?;
        if fs::canonicalize(&self.0.canonical)? != self.0.canonical
            || !metadata.is_file()
            || metadata.dev() != self.0.device
            || metadata.ino() != self.0.inode
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "canonical executable identity changed",
            ));
        }
        require_posix_effective_executable(&self.0.canonical)?;
        Ok(())
    }
}

#[cfg(unix)]
impl BoundPosixStandardExecutableIdentity {
    fn new(identity: PosixStandardExecutableIdentity) -> std::io::Result<Self> {
        Self::new_named(identity, "rustup")
    }

    fn new_named(
        identity: PosixStandardExecutableIdentity,
        logical_name: &'static str,
    ) -> std::io::Result<Self> {
        let bound = Self {
            identity,
            logical_name,
        };
        bound.revalidate()?;
        Ok(bound)
    }

    fn revalidate(&self) -> std::io::Result<()> {
        use std::os::unix::fs::MetadataExt as _;

        let identity = &self.identity;
        let parent = identity.invocation.parent().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "standard executable invocation has no parent",
            )
        })?;
        let metadata = fs::metadata(&identity.canonical)?;
        if identity.invocation.file_name() != Some(OsStr::new(self.logical_name))
            || !identity.invocation.is_absolute()
            || fs::canonicalize(parent)? != parent
            || fs::canonicalize(&identity.invocation)? != identity.canonical
            || fs::canonicalize(&identity.canonical)? != identity.canonical
            || !metadata.is_file()
            || metadata.dev() != identity.device
            || metadata.ino() != identity.inode
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "standard executable identity changed",
            ));
        }
        require_posix_effective_executable(&identity.invocation)?;
        Ok(())
    }

    fn same_file(&self, path: &Path) -> std::io::Result<bool> {
        use std::os::unix::fs::MetadataExt as _;

        let metadata = fs::metadata(path)?;
        Ok(metadata.dev() == self.identity.device && metadata.ino() == self.identity.inode)
    }
}

#[cfg(unix)]
#[derive(Clone, Debug)]
enum BoundPosixRustcAuthority {
    RustupProxy(BoundPosixStandardExecutableIdentity),
    SelectedToolchain(BoundPosixStandardExecutableIdentity),
}

#[cfg(unix)]
impl BoundPosixRustcAuthority {
    fn new(
        authority: PosixRustcAuthority,
        proxy: &PosixRustupProxyIdentity,
        compiler_mapping: &BoundPosixRustupCompilerMapping,
    ) -> std::io::Result<Self> {
        let authority = match authority {
            PosixRustcAuthority::RustupProxy(identity) => Self::RustupProxy(
                BoundPosixStandardExecutableIdentity::new_named(identity, "rustc")?,
            ),
            PosixRustcAuthority::SelectedToolchain(identity) => Self::SelectedToolchain(
                BoundPosixStandardExecutableIdentity::new_named(identity, "rustc")?,
            ),
        };
        authority.revalidate(proxy, compiler_mapping)?;
        Ok(authority)
    }

    fn standard(&self) -> &BoundPosixStandardExecutableIdentity {
        match self {
            Self::RustupProxy(identity) | Self::SelectedToolchain(identity) => identity,
        }
    }

    fn revalidate(
        &self,
        proxy: &PosixRustupProxyIdentity,
        compiler_mapping: &BoundPosixRustupCompilerMapping,
    ) -> std::io::Result<()> {
        use std::os::unix::fs::MetadataExt as _;

        let standard = self.standard();
        standard.revalidate()?;
        match self {
            Self::RustupProxy(_) => {
                if standard.identity.device != proxy.device
                    || standard.identity.inode != proxy.inode
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "standard rustc does not match the Rustup proxy identity",
                    ));
                }
            }
            Self::SelectedToolchain(_) => {
                let source = &compiler_mapping.source;
                let metadata = fs::metadata(&standard.identity.canonical)?;
                if standard.identity.canonical != source.path
                    || metadata.dev() != source.device
                    || metadata.ino() != source.inode
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "standard rustc does not match the inventoried selected compiler",
                    ));
                }
            }
        }
        Ok(())
    }

    fn invocation(&self) -> &Path {
        &self.standard().identity.invocation
    }

    fn canonical(&self) -> &Path {
        &self.standard().identity.canonical
    }
}

#[cfg(unix)]
fn require_posix_effective_executable(path: &Path) -> std::io::Result<()> {
    use nix::fcntl::AtFlags;
    use nix::unistd::{AccessFlags, faccessat};

    faccessat(None, path, AccessFlags::X_OK, AtFlags::AT_EACCESS).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("executable is unavailable to the effective user: {error}"),
        )
    })
}

#[cfg(unix)]
#[derive(Clone, Debug)]
struct BoundPosixRustupAuthority {
    proxy_identity: PosixRustupProxyIdentity,
    rustc_authority: BoundPosixRustcAuthority,
    home: PathBuf,
    toolchain: OsString,
    compiler_mapping: BoundPosixRustupCompilerMapping,
    candidate_uid: u32,
    candidate_group_ids: Arc<[u32]>,
    critical_entries: Arc<[PosixRustupEntryIdentity]>,
    tree_entries: Arc<[PosixRustupEntryIdentity]>,
}

#[cfg(unix)]
impl BoundPosixRustupAuthority {
    fn new(
        authority: PosixRustupAuthority,
        candidate_uid: u32,
        candidate_group_ids: Arc<[u32]>,
    ) -> std::io::Result<Self> {
        let PosixRustupAuthority {
            proxy_identity,
            rustc_authority,
            source_home,
            home,
            toolchain,
            compiler_mapping,
        } = authority;
        validate_posix_rustup_proxy_identity(&proxy_identity, candidate_uid, &candidate_group_ids)?;
        validate_posix_rustup_compiler_mapping_paths(
            &source_home,
            &home,
            &toolchain,
            &compiler_mapping,
        )?;
        let critical_entries =
            posix_rustup_critical_entries(&home, &toolchain, candidate_uid, &candidate_group_ids)?;
        let tree_entries = posix_rustup_tree_entries(&home, candidate_uid, &candidate_group_ids)?;
        let compiler_mapping = BoundPosixRustupCompilerMapping::new(
            &compiler_mapping,
            candidate_uid,
            &candidate_group_ids,
        )?;
        let rustc_authority =
            BoundPosixRustcAuthority::new(rustc_authority, &proxy_identity, &compiler_mapping)?;
        Ok(Self {
            proxy_identity,
            rustc_authority,
            home,
            toolchain,
            compiler_mapping,
            candidate_uid,
            candidate_group_ids,
            critical_entries: critical_entries.into(),
            tree_entries: tree_entries.into(),
        })
    }

    fn revalidate(&self) -> std::io::Result<()> {
        validate_posix_rustup_proxy_identity(
            &self.proxy_identity,
            self.candidate_uid,
            &self.candidate_group_ids,
        )?;
        for expected in &*self.critical_entries {
            let observed = posix_rustup_entry_identity(
                &expected.path,
                self.candidate_uid,
                &self.candidate_group_ids,
                expected.requirement,
            )?;
            if observed != *expected {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "POSIX Rustup authority identity changed before spawn",
                ));
            }
        }
        if posix_rustup_tree_entries(&self.home, self.candidate_uid, &self.candidate_group_ids)?
            != *self.tree_entries
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "POSIX Rustup authority inventory changed before spawn",
            ));
        }
        self.compiler_mapping
            .revalidate(self.candidate_uid, &self.candidate_group_ids)?;
        self.rustc_authority
            .revalidate(&self.proxy_identity, &self.compiler_mapping)?;
        Ok(())
    }

    fn request_is_bound_rustc(&self, requested: &OsStr, resolved: &Path) -> std::io::Result<bool> {
        let requested = Path::new(requested);
        if requested.file_name() != Some(OsStr::new("rustc")) {
            return Ok(false);
        }
        let staged = &self.compiler_mapping.staged.path;
        if requested == staged {
            self.revalidate()?;
            if resolved != staged || fs::canonicalize(resolved)? != *staged {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "staged Rust compiler authority changed before spawn",
                ));
            }
            return Ok(true);
        }
        if requested.components().count() != 1 && requested != self.rustc_authority.invocation() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "rustc request is outside the exact standard compiler authority",
            ));
        }
        self.revalidate()?;
        if resolved != self.rustc_authority.invocation()
            || fs::canonicalize(resolved)? != self.rustc_authority.canonical()
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "standard Rust compiler authority changed before spawn",
            ));
        }
        Ok(true)
    }

    fn staged_rustc(&self) -> std::io::Result<PathBuf> {
        self.revalidate()?;
        Ok(self.compiler_mapping.staged.path.clone())
    }

    fn selected_tool_bin(&self) -> std::io::Result<PathBuf> {
        let bin = self
            .home
            .join("toolchains")
            .join(&self.toolchain)
            .join("bin");
        if fs::canonicalize(&bin)? != bin {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "selected staged Rust tool bin changed before spawn",
            ));
        }
        Ok(bin)
    }
}

#[cfg(unix)]
fn validate_posix_rustup_compiler_mapping_paths(
    source_home: &Path,
    staged_home: &Path,
    toolchain: &OsStr,
    mapping: &PosixRustupCompilerMapping,
) -> std::io::Result<()> {
    let source_rustc = source_home
        .join("toolchains")
        .join(toolchain)
        .join("bin/rustc");
    let staged_rustc = staged_home
        .join("toolchains")
        .join(toolchain)
        .join("bin/rustc");
    if fs::canonicalize(source_home)? != source_home
        || fs::canonicalize(&source_rustc)? != source_rustc
        || mapping.source != source_rustc
        || mapping.staged != staged_rustc
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Rust compiler mapping is outside the selected source or staged toolchain",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn posix_rustup_critical_entries(
    home: &Path,
    toolchain: &OsStr,
    candidate_uid: u32,
    candidate_group_ids: &[u32],
) -> std::io::Result<Vec<PosixRustupEntryIdentity>> {
    if !home.is_absolute()
        || fs::canonicalize(home)? != home
        || Path::new(toolchain).components().count() != 1
        || toolchain.is_empty()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "POSIX Rustup authority is not canonical",
        ));
    }
    let toolchains = home.join("toolchains");
    let toolchain_root = toolchains.join(toolchain);
    if fs::canonicalize(&toolchain_root)? != toolchain_root {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "selected Rust toolchain path is redirected",
        ));
    }
    let bin = toolchain_root.join("bin");
    let settings = home.join("settings.toml");
    let update_hashes = home.join("update-hashes");
    let update_hash = update_hashes.join(toolchain);
    let cargo = bin.join("cargo");
    let rustc = bin.join("rustc");
    let mut entries = home
        .ancestors()
        .map(|ancestor| {
            posix_rustup_entry_identity(
                ancestor,
                candidate_uid,
                candidate_group_ids,
                PosixRustupAccessRequirement::AncestorDirectory,
            )
        })
        .collect::<std::io::Result<Vec<_>>>()?;
    for (path, requirement) in [
        (home, PosixRustupAccessRequirement::AuthorityDirectory),
        (&settings, PosixRustupAccessRequirement::ReadableFile),
        (
            &update_hashes,
            PosixRustupAccessRequirement::AuthorityDirectory,
        ),
        (&update_hash, PosixRustupAccessRequirement::ReadableFile),
        (
            &toolchains,
            PosixRustupAccessRequirement::AuthorityDirectory,
        ),
        (
            &toolchain_root,
            PosixRustupAccessRequirement::AuthorityDirectory,
        ),
        (&bin, PosixRustupAccessRequirement::AuthorityDirectory),
        (&cargo, PosixRustupAccessRequirement::ExecutableFile),
        (&rustc, PosixRustupAccessRequirement::ExecutableFile),
    ] {
        entries.push(posix_rustup_entry_identity(
            path,
            candidate_uid,
            candidate_group_ids,
            requirement,
        )?);
    }
    Ok(entries)
}

#[cfg(unix)]
#[derive(Clone, Debug)]
struct BoundPosixRustupCompilerMapping {
    source: PosixRustupMappedExecutableIdentity,
    staged: PosixRustupMappedExecutableIdentity,
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct PosixRustupMappedExecutableIdentity {
    path: PathBuf,
    device: u64,
    inode: u64,
    links: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    size: u64,
    sha256: Digest,
}

#[cfg(unix)]
impl BoundPosixRustupCompilerMapping {
    fn new(
        mapping: &PosixRustupCompilerMapping,
        candidate_uid: u32,
        candidate_group_ids: &[u32],
    ) -> std::io::Result<Self> {
        let source = PosixRustupMappedExecutableIdentity::read(
            &mapping.source,
            mapping.source_sha256,
            candidate_uid,
            candidate_group_ids,
        )?;
        let staged = PosixRustupMappedExecutableIdentity::read(
            &mapping.staged,
            mapping.staged_sha256,
            candidate_uid,
            candidate_group_ids,
        )?;
        if source.size != staged.size || source.sha256 != staged.sha256 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "source and staged Rust compiler identities differ",
            ));
        }
        Ok(Self { source, staged })
    }

    fn revalidate(&self, candidate_uid: u32, candidate_group_ids: &[u32]) -> std::io::Result<()> {
        for expected in [&self.source, &self.staged] {
            let observed = PosixRustupMappedExecutableIdentity::read(
                &expected.path,
                expected.sha256,
                candidate_uid,
                candidate_group_ids,
            )?;
            if observed != *expected {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "source or staged Rust compiler identity changed before spawn",
                ));
            }
        }
        Ok(())
    }
}

#[cfg(unix)]
impl PosixRustupMappedExecutableIdentity {
    fn read(
        path: &Path,
        expected_sha256: Digest,
        candidate_uid: u32,
        candidate_group_ids: &[u32],
    ) -> std::io::Result<Self> {
        use std::os::unix::fs::PermissionsExt as _;

        let entry = posix_rustup_entry_identity(
            path,
            candidate_uid,
            candidate_group_ids,
            PosixRustupAccessRequirement::ExecutableFile,
        )?;
        let metadata = fs::symlink_metadata(path)?;
        let sha256 = sha256_file(path)?;
        if sha256 != expected_sha256 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "mapped Rust compiler digest changed",
            ));
        }
        Ok(Self {
            path: entry.path,
            device: entry.device,
            inode: entry.inode,
            links: entry.links,
            uid: entry.uid,
            gid: entry.gid,
            mode: metadata.permissions().mode() & 0o7777,
            size: metadata.len(),
            sha256,
        })
    }
}

#[cfg(unix)]
fn posix_rustup_entry_identity(
    path: &Path,
    candidate_uid: u32,
    candidate_group_ids: &[u32],
    requirement: PosixRustupAccessRequirement,
) -> std::io::Result<PosixRustupEntryIdentity> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || fs::canonicalize(path)? != path {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "POSIX Rustup authority path is redirected",
        ));
    }
    let mode = metadata.permissions().mode() & 0o7777;
    if !posix_rustup_owner_is_trusted(metadata.uid(), candidate_uid) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "candidate principal owns POSIX Rustup authority",
        ));
    }
    let identity = PosixRustupEntryIdentity {
        path: path.to_path_buf(),
        device: metadata.dev(),
        inode: metadata.ino(),
        links: metadata.nlink(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode,
        requirement,
    };
    if metadata.is_file() && metadata.nlink() != 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "POSIX Rustup authority file has multiple hard links",
        ));
    }
    match requirement {
        PosixRustupAccessRequirement::AncestorDirectory => {
            if !metadata.is_dir()
                || !posix_rustup_ancestor_access_is_safe(mode, metadata.gid(), candidate_group_ids)
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    posix_rustup_ancestor_rejection(
                        &identity,
                        metadata.is_dir(),
                        candidate_uid,
                        candidate_group_ids,
                    ),
                ));
            }
        }
        PosixRustupAccessRequirement::AuthorityDirectory => {
            if !metadata.is_dir() || mode & 0o005 != 0o005 || mode & 0o022 != 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "POSIX Rustup directory is writable or not candidate-readable",
                ));
            }
        }
        PosixRustupAccessRequirement::ReadableFile => {
            if !metadata.is_file() || mode & 0o004 == 0 || mode & 0o022 != 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "POSIX Rustup file is writable or not candidate-readable",
                ));
            }
        }
        PosixRustupAccessRequirement::ExecutableFile => {
            if !metadata.is_file() || mode & 0o005 != 0o005 || mode & 0o022 != 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "POSIX Rustup executable is writable or not candidate-executable",
                ));
            }
        }
    }
    Ok(identity)
}

#[cfg(unix)]
fn posix_candidate_group_inventory_is_valid(primary_gid: u32, group_ids: &[u32]) -> bool {
    !group_ids.is_empty()
        && group_ids.len() <= POSIX_CANDIDATE_GROUP_LIMIT
        && group_ids.contains(&primary_gid)
        && group_ids.iter().copied().collect::<BTreeSet<_>>().len() == group_ids.len()
}

#[cfg(unix)]
fn posix_rustup_ancestor_access_is_safe(
    mode: u32,
    owner_gid: u32,
    candidate_group_ids: &[u32],
) -> bool {
    let (_, effective) = posix_rustup_effective_access(mode, owner_gid, candidate_group_ids);
    effective & 0o5 == 0o5 && (effective & 0o2 == 0 || mode & 0o1000 != 0)
}

#[cfg(unix)]
fn posix_rustup_effective_access(
    mode: u32,
    owner_gid: u32,
    candidate_group_ids: &[u32],
) -> (&'static str, u32) {
    if candidate_group_ids.contains(&owner_gid) {
        ("group", (mode >> 3) & 0o7)
    } else {
        ("other", mode & 0o7)
    }
}

#[cfg(unix)]
fn posix_rustup_ancestor_rejection(
    identity: &PosixRustupEntryIdentity,
    is_directory: bool,
    candidate_uid: u32,
    candidate_group_ids: &[u32],
) -> String {
    let (access_class, effective) =
        posix_rustup_effective_access(identity.mode, identity.gid, candidate_group_ids);
    let path = identity.path.display();
    let mode = identity.mode;
    let file_owner = identity.uid;
    let owning_group = identity.gid;
    format!(
        "POSIX Rustup ancestor rejected: path={path},isDirectory={is_directory},mode=0o{mode:04o},ownerUid={file_owner},ownerGid={owning_group},candidateUid={candidate_uid},candidateGroups={candidate_group_ids:?},accessClass={access_class},effectiveBits=0o{effective:o}"
    )
}

#[cfg(unix)]
fn posix_rustup_owner_is_trusted(owner_uid: u32, candidate_uid: u32) -> bool {
    owner_uid != candidate_uid
}

#[cfg(unix)]
fn posix_rustup_tree_entries(
    root: &Path,
    candidate_uid: u32,
    candidate_group_ids: &[u32],
) -> std::io::Result<Vec<PosixRustupEntryIdentity>> {
    let mut pending = vec![root.to_path_buf()];
    let mut identities = Vec::new();
    let mut entries = 0_usize;
    while let Some(path) = pending.pop() {
        entries = entries
            .checked_add(1)
            .ok_or_else(|| std::io::Error::other("POSIX Rustup inventory overflowed"))?;
        if entries > POSIX_RUSTUP_ENTRY_LIMIT {
            return Err(std::io::Error::other(
                "POSIX Rustup inventory exceeds its entry bound",
            ));
        }
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.is_dir() {
            identities.push(posix_rustup_entry_identity(
                &path,
                candidate_uid,
                candidate_group_ids,
                PosixRustupAccessRequirement::AuthorityDirectory,
            )?);
            for entry in fs::read_dir(&path)? {
                pending.push(entry?.path());
            }
        } else if metadata.is_file() {
            identities.push(posix_rustup_entry_identity(
                &path,
                candidate_uid,
                candidate_group_ids,
                PosixRustupAccessRequirement::ReadableFile,
            )?);
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "POSIX Rustup inventory contains a redirected or special entry",
            ));
        }
    }
    identities.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(identities)
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct PosixAdapterIdentity {
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    parent_device: u64,
    parent_inode: u64,
    parent_uid: u32,
    parent_gid: u32,
    parent_mode: u32,
}

#[cfg(unix)]
fn posix_adapter_identity(path: &Path) -> std::io::Result<PosixAdapterIdentity> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let metadata = fs::symlink_metadata(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("POSIX adapter has no parent"))?;
    let parent_metadata = fs::symlink_metadata(parent)?;
    Ok(PosixAdapterIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode: metadata.permissions().mode() & 0o7777,
        parent_device: parent_metadata.dev(),
        parent_inode: parent_metadata.ino(),
        parent_uid: parent_metadata.uid(),
        parent_gid: parent_metadata.gid(),
        parent_mode: parent_metadata.permissions().mode() & 0o7777,
    })
}

#[cfg(unix)]
fn verify_posix_adapter_identity(
    path: &Path,
    expected_canonical_path: &Path,
    expected_sha256: Digest,
    expected_identity: &PosixAdapterIdentity,
) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let metadata = fs::symlink_metadata(path)?;
    let canonical = fs::canonicalize(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("POSIX adapter has no parent"))?;
    let parent_metadata = fs::symlink_metadata(parent)?;
    if metadata.file_type().is_symlink() || canonical != expected_canonical_path {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "POSIX adapter canonical path changed",
        ));
    }
    if !metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "POSIX adapter is not a regular file",
        ));
    }
    if parent_metadata.file_type().is_symlink()
        || !parent_metadata.is_dir()
        || fs::canonicalize(parent)? != parent
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "POSIX adapter parent identity changed",
        ));
    }
    let mode = metadata.permissions().mode();
    if mode & 0o022 != 0 || mode & 0o005 != 0o005 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "POSIX adapter is writable or not read-executable by the candidate principal",
        ));
    }
    let parent_mode = parent_metadata.permissions().mode();
    if parent_mode & 0o022 != 0 || parent_mode & 0o005 != 0o005 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "POSIX adapter parent is writable or not traversable by the candidate principal",
        ));
    }
    if posix_adapter_identity(path)? != *expected_identity {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "POSIX adapter file identity changed",
        ));
    }
    if sha256_file(&canonical)? != expected_sha256 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "POSIX adapter digest changed",
        ));
    }
    Ok(())
}

#[cfg(all(test, not(windows)))]
fn verify_windows_launcher_identity(
    path: &Path,
    expected_canonical_path: &Path,
    expected_sha256: Digest,
) -> std::io::Result<()> {
    let canonical = fs::canonicalize(path)?;
    if canonical != expected_canonical_path {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "restricted launcher canonical path changed",
        ));
    }
    if !fs::metadata(&canonical)?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "restricted launcher is not a regular file",
        ));
    }
    if sha256_file(&canonical)? != expected_sha256 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "restricted launcher digest changed",
        ));
    }
    Ok(())
}

#[cfg(all(test, not(windows)))]
fn verify_windows_restricted_adapter_identity(
    path: &Path,
    expected_canonical_path: &Path,
    expected_sha256: Digest,
) -> std::io::Result<()> {
    verify_windows_launcher_identity(path, expected_canonical_path, expected_sha256)?;
    if expected_canonical_path.file_name() != Some(OsStr::new("hell-test-helper.exe")) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "restricted argv adapter has the wrong executable name",
        ));
    }
    Ok(())
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PosixUidProcessState {
    Live,
    Zombie,
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PosixUidProcess {
    pub pid: u32,
    pub parent_pid: u32,
    pub state: PosixUidProcessState,
    pub raw_state: String,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PosixUidQuiescenceGoal {
    NoLiveProcesses,
    Empty,
}

/// Exact candidate identity retained after a bounded no-live-process observation.
#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PosixCandidateQuiescenceReceipt {
    principal: Arc<str>,
    uid: u32,
    primary_gid: u32,
}

#[cfg(unix)]
impl PosixCandidateQuiescenceReceipt {
    /// Returns the exact principal name observed by this receipt.
    #[must_use]
    pub fn principal(&self) -> &str {
        &self.principal
    }

    /// Returns whether this receipt authorizes cleanup for the exact principal identity.
    #[must_use]
    pub fn matches_numeric_identity(&self, uid: u32, primary_gid: u32) -> bool {
        self.uid == uid && self.primary_gid == primary_gid
    }
}

/// Verifies exact and mismatched opaque quiescence-receipt identity binding.
#[cfg(unix)]
#[doc(hidden)]
pub fn verify_posix_candidate_quiescence_receipt_binding_for_integration() -> std::io::Result<()> {
    let receipt = PosixCandidateQuiescenceReceipt {
        principal: Arc::from("candidate-receipt-verifier"),
        uid: 41_001,
        primary_gid: 41_002,
    };
    if receipt.principal() != "candidate-receipt-verifier"
        || !receipt.matches_numeric_identity(41_001, 41_002)
        || receipt.matches_numeric_identity(41_003, 41_002)
        || receipt.matches_numeric_identity(41_001, 41_004)
    {
        return Err(std::io::Error::other(
            "POSIX candidate quiescence receipt binding is not exact",
        ));
    }
    Ok(())
}

#[cfg(unix)]
struct BoundedPosixAuthorityOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[cfg(unix)]
fn run_bounded_posix_authority_command(
    program: &Path,
    arguments: &[OsString],
    deadline: Instant,
) -> std::io::Result<BoundedPosixAuthorityOutput> {
    const CLEANUP_RESERVE: Duration = Duration::from_secs(1);
    let execution_deadline = deadline.checked_sub(CLEANUP_RESERVE).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "process authority command has no cleanup reserve",
        )
    })?;
    if Instant::now() >= execution_deadline {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "process authority command execution reserve expired before launch",
        ));
    }
    let mut command = Command::new(program);
    command.args(arguments);
    let output = without_candidate_launch_policy(|| {
        run_supervised_command_until(&mut command, &[], execution_deadline, deadline, None)
    })?;
    if output.timed_out || output.stdout.truncated || output.stderr.truncated {
        return Err(std::io::Error::other(
            "process authority command did not complete within its capture bound",
        ));
    }
    Ok(BoundedPosixAuthorityOutput {
        status: output.status,
        stdout: output.stdout.complete.unwrap_or_default(),
        stderr: output.stderr.complete.unwrap_or_default(),
    })
}

#[cfg(unix)]
fn without_candidate_launch_policy<T>(operation: impl FnOnce() -> T) -> T {
    CANDIDATE_LAUNCH_POLICY.with(|slot| {
        struct Restore<'a> {
            slot: &'a RefCell<Option<CandidateLaunchPolicy>>,
            previous: Option<CandidateLaunchPolicy>,
        }
        impl Drop for Restore<'_> {
            fn drop(&mut self) {
                self.slot.replace(self.previous.take());
            }
        }
        let previous = slot.replace(None);
        let _restore = Restore { slot, previous };
        operation()
    })
}

#[cfg(unix)]
fn parse_posix_process_id(field: &[u8]) -> Option<u32> {
    let text = std::str::from_utf8(field).ok()?;
    let value = text.parse::<u32>().ok()?;
    (value != 0 && value.to_string() == text).then_some(value)
}

#[cfg(unix)]
/// Parses an exact `ps` inventory for one candidate UID.
///
/// # Errors
///
/// Returns an error when the command status, stderr, row shape, process IDs,
/// process state, or inventory size is not canonical and bounded.
pub fn parse_posix_uid_process_snapshot(
    status: Option<i32>,
    snapshot: &[u8],
    stderr: &[u8],
) -> std::io::Result<Vec<PosixUidProcess>> {
    const ENTRY_LIMIT: usize = 4_096;

    if !stderr.is_empty() || !matches!(status, Some(0 | 1)) {
        return Err(std::io::Error::other(
            "candidate process inventory query failed",
        ));
    }
    if status == Some(1) {
        if snapshot.is_empty() {
            return Ok(Vec::new());
        }
        return Err(std::io::Error::other(
            "candidate process inventory absence was not exact",
        ));
    }
    let mut processes = Vec::new();
    let mut observed_pids = BTreeSet::new();
    for line in snapshot.split(|byte| *byte == b'\n') {
        let mut fields = line
            .split(u8::is_ascii_whitespace)
            .filter(|field| !field.is_empty());
        let Some(pid) = fields.next() else {
            continue;
        };
        let parent_pid = fields.next().ok_or_else(|| {
            std::io::Error::other("candidate process inventory row has no parent PID")
        })?;
        let raw_state = fields
            .next()
            .ok_or_else(|| std::io::Error::other("candidate process inventory row has no state"))?;
        if fields.next().is_some() {
            return Err(std::io::Error::other(
                "candidate process inventory row has trailing fields",
            ));
        }
        let pid = parse_posix_process_id(pid)
            .ok_or_else(|| std::io::Error::other("candidate process PID is not canonical"))?;
        if !observed_pids.insert(pid) {
            return Err(std::io::Error::other(
                "candidate process inventory contains a duplicate PID",
            ));
        }
        let parent_pid = parse_posix_process_id(parent_pid).ok_or_else(|| {
            std::io::Error::other("candidate process parent PID is not canonical")
        })?;
        let Some(first_state) = raw_state.first() else {
            return Err(std::io::Error::other("candidate process state is empty"));
        };
        if !first_state.is_ascii_alphabetic()
            || !raw_state[1..]
                .iter()
                .all(|byte| matches!(byte, b'<' | b'N' | b'L' | b's' | b'l' | b'+'))
        {
            return Err(std::io::Error::other(
                "candidate process state is not canonical",
            ));
        }
        processes.push(PosixUidProcess {
            pid,
            parent_pid,
            state: if *first_state == b'Z' {
                PosixUidProcessState::Zombie
            } else {
                PosixUidProcessState::Live
            },
            raw_state: std::str::from_utf8(raw_state)
                .map_err(|_| std::io::Error::other("candidate process state is not UTF-8"))?
                .to_owned(),
        });
        if processes.len() > ENTRY_LIMIT {
            return Err(std::io::Error::other(
                "candidate process inventory exceeds its entry bound",
            ));
        }
    }
    Ok(processes)
}

#[cfg(unix)]
fn posix_uid_process_diagnostic(processes: &[PosixUidProcess]) -> String {
    const RETAINED_ENTRY_LIMIT: usize = 32;

    let retained = processes
        .iter()
        .take(RETAINED_ENTRY_LIMIT)
        .map(|process| {
            format!(
                "pid={},ppid={},state={}",
                process.pid, process.parent_pid, process.raw_state
            )
        })
        .collect::<Vec<_>>()
        .join(";");
    format!("count={};retained={retained}", processes.len())
}

#[cfg(unix)]
/// Waits for the requested candidate-UID quiescence state until `deadline`.
///
/// # Errors
///
/// Returns an error when observation or termination fails, or when the
/// requested state is not reached before the monotonic deadline.
pub fn wait_for_posix_uid_process_quiescence(
    deadline: Instant,
    goal: PosixUidQuiescenceGoal,
    mut observe: impl FnMut() -> std::io::Result<Vec<PosixUidProcess>>,
    mut authorize_signal: impl FnMut() -> std::io::Result<()>,
    mut terminate_live: impl FnMut() -> std::io::Result<()>,
) -> std::io::Result<Vec<PosixUidProcess>> {
    let mut signaled = BTreeSet::new();
    loop {
        let processes = observe()?;
        let live = processes
            .iter()
            .filter(|process| process.state == PosixUidProcessState::Live)
            .collect::<Vec<_>>();
        if live.is_empty()
            && (goal == PosixUidQuiescenceGoal::NoLiveProcesses || processes.is_empty())
        {
            return Ok(processes);
        }
        if Instant::now() >= deadline {
            return Err(std::io::Error::other(format!(
                "candidate process quiescence deadline expired: {}",
                posix_uid_process_diagnostic(&processes)
            )));
        }
        if live.iter().any(|process| !signaled.contains(&process.pid)) {
            authorize_signal()?;
            terminate_live()?;
            signaled.extend(live.into_iter().map(|process| process.pid));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        std::thread::sleep(remaining.min(Duration::from_millis(10)));
    }
}

#[cfg(any(windows, test))]
const WINDOWS_ARGV_TOKEN_PREFIX: &str = "hell-argv-v1";
#[cfg(any(windows, test))]
const WINDOWS_ARGV_HELPER_PREFIX_UTF16_LEN: usize = "hell-test-helper __release-argv-child ".len();
#[cfg(any(windows, test))]
const WINDOWS_CREATE_PROCESS_COMMAND_LINE_LIMIT: usize = 32_767;
#[cfg(any(windows, test))]
const WINDOWS_ARGV_TOKEN_LIMIT: usize =
    WINDOWS_CREATE_PROCESS_COMMAND_LINE_LIMIT - WINDOWS_ARGV_HELPER_PREFIX_UTF16_LEN - 1;

/// Encodes Windows UTF-16 argv as one bounded, delimiter-structured token for
/// the restricted-process adapter.
///
/// # Errors
///
/// Returns an error when the encoded token exceeds the fixed adapter bound.
#[cfg(windows)]
pub fn encode_windows_argv(arguments: &[OsString]) -> std::io::Result<OsString> {
    use std::os::windows::ffi::OsStrExt as _;

    encode_windows_argv_units(
        &arguments
            .iter()
            .map(|argument| argument.encode_wide().collect::<Vec<_>>())
            .collect::<Vec<_>>(),
    )
    .map(OsString::from)
}

/// Decodes the one-token Windows argv representation into native strings.
///
/// # Errors
///
/// Returns an error for malformed, oversized, or version-mismatched input.
#[cfg(windows)]
pub fn decode_windows_argv(token: &std::ffi::OsStr) -> std::io::Result<Vec<OsString>> {
    use std::os::windows::ffi::OsStringExt as _;

    let token = token
        .to_str()
        .ok_or_else(|| std::io::Error::other("Windows argv token is not ASCII"))?;
    decode_windows_argv_units(token).map(|arguments| {
        arguments
            .into_iter()
            .map(|argument| OsString::from_wide(&argument))
            .collect()
    })
}

/// Returns the exact diagnostic required when a Windows child status cannot
/// be represented by [`std::process::ExitCode`].
///
/// A loader exception is delivered through `ExitStatus::code` as a signed
/// `i32`; retaining both spellings prevents the restricted argv adapter from
/// collapsing that evidence into an unexplained exit code `1`.
#[doc(hidden)]
#[must_use]
pub fn windows_argv_child_status_diagnostic(code: Option<i32>) -> Option<String> {
    match code {
        Some(code) if u8::try_from(code).is_ok() => None,
        Some(code) => Some(format!(
            "Windows argv target exited with raw status {code} (0x{:08x})",
            code.cast_unsigned()
        )),
        None => Some("Windows argv target terminated without an exit code".to_owned()),
    }
}

fn bounded_windows_path_debug(path: &Path) -> String {
    const LIMIT: usize = 1_024;

    let rendered = format!("\"{}\"", path.as_os_str().to_string_lossy().escape_debug());
    if rendered.len() <= LIMIT {
        rendered
    } else {
        let split = (0..=LIMIT)
            .rev()
            .find(|index| rendered.is_char_boundary(*index))
            .expect("zero is a UTF-8 boundary");
        format!("{}<truncated:{}>", &rendered[..split], rendered.len())
    }
}

fn bounded_windows_diagnostic_detail(detail: &str) -> String {
    const LIMIT: usize = 1_024;

    let rendered = format!("\"{}\"", detail.escape_debug());
    if rendered.len() <= LIMIT {
        rendered
    } else {
        let split = (0..=LIMIT)
            .rev()
            .find(|index| rendered.is_char_boundary(*index))
            .expect("zero is a UTF-8 boundary");
        format!("{}<truncated:{}>", &rendered[..split], rendered.len())
    }
}

/// Captures bounded prelaunch evidence for the exact Windows argv target.
///
/// This report is diagnostic-only: failures are encoded in the returned text
/// and never widen or replace the executable authority used for the launch.
#[doc(hidden)]
#[must_use]
pub fn windows_argv_target_prelaunch_diagnostic(program: &Path) -> String {
    let deadline = Instant::now()
        .checked_add(WINDOWS_PRELAUNCH_DIAGNOSTIC_BUDGET)
        .unwrap_or_else(Instant::now);
    windows_argv_target_prelaunch_diagnostic_until(program, deadline)
        .rendered
        .clone()
}

const WINDOWS_PRELAUNCH_DIAGNOSTIC_BUDGET: Duration = Duration::from_secs(1);
#[doc(hidden)]
pub const WINDOWS_PRELAUNCH_DIRECTORY_ENTRY_LIMIT: usize = 1_024;
#[doc(hidden)]
pub const WINDOWS_PRELAUNCH_DLL_LIMIT: usize = 128;
#[doc(hidden)]
pub const WINDOWS_PRELAUNCH_FILE_BYTE_LIMIT: u64 = 512 * 1024 * 1024;
#[doc(hidden)]
pub const WINDOWS_PRELAUNCH_DLL_BYTE_LIMIT: u64 = 2 * 1024 * 1024 * 1024;
const WINDOWS_PRELAUNCH_HASH_CHUNK_BYTES: usize = 64 * 1024;

/// One bounded phase in the optional Windows target diagnostic.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsPrelaunchDiagnosticPhase {
    ProgramMetadata,
    DirectoryEnumeration,
    DllMetadata,
    DllHash,
    ProgramHash,
}

impl WindowsPrelaunchDiagnosticPhase {
    fn as_str(self) -> &'static str {
        match self {
            Self::ProgramMetadata => "program-metadata",
            Self::DirectoryEnumeration => "directory-enumeration",
            Self::DllMetadata => "dll-metadata",
            Self::DllHash => "dll-hash",
            Self::ProgramHash => "program-hash",
        }
    }
}

/// Typed reason that optional Windows prelaunch evidence is incomplete.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsPrelaunchDiagnosticReason {
    Deadline,
    Io(std::io::ErrorKind),
    DirectoryEntryLimit,
    DllEntryLimit,
    FileByteLimit,
    DllByteLimit,
    FileChanged,
}

/// Typed completion state for optional Windows prelaunch evidence.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsPrelaunchDiagnosticOutcome {
    Complete,
    Unavailable {
        phase: WindowsPrelaunchDiagnosticPhase,
        reason: WindowsPrelaunchDiagnosticReason,
    },
}

/// Bounded receipt for optional Windows target diagnostics.
#[doc(hidden)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsPrelaunchDiagnosticReceipt {
    pub outcome: WindowsPrelaunchDiagnosticOutcome,
    pub directory_entries: usize,
    pub dll_count: usize,
    pub dll_bytes: u64,
    pub hashed_dlls: usize,
    pub hashed_bytes: u64,
    pub program_hashed: bool,
    pub program_reused: bool,
    rendered: String,
}

impl WindowsPrelaunchDiagnosticReceipt {
    /// Returns the bounded durable diagnostic attached to supervision output.
    #[must_use]
    pub fn rendered(&self) -> &str {
        &self.rendered
    }
}

#[derive(Default)]
struct WindowsPrelaunchDiagnosticState {
    directory_entries: usize,
    dll_count: usize,
    dll_bytes: u64,
    hashed_dlls: usize,
    hashed_bytes: u64,
    program_hashed: bool,
    program_reused: bool,
    dll_evidence: Vec<String>,
}

struct WindowsPrelaunchDiagnosticFailure {
    phase: WindowsPrelaunchDiagnosticPhase,
    reason: WindowsPrelaunchDiagnosticReason,
    detail: String,
}

fn windows_prelaunch_failure(
    phase: WindowsPrelaunchDiagnosticPhase,
    reason: WindowsPrelaunchDiagnosticReason,
    detail: impl Into<String>,
) -> WindowsPrelaunchDiagnosticFailure {
    WindowsPrelaunchDiagnosticFailure {
        phase,
        reason,
        detail: detail.into(),
    }
}

fn require_windows_prelaunch_deadline(
    deadline: Instant,
    phase: WindowsPrelaunchDiagnosticPhase,
) -> Result<(), WindowsPrelaunchDiagnosticFailure> {
    if Instant::now() >= deadline {
        Err(windows_prelaunch_failure(
            phase,
            WindowsPrelaunchDiagnosticReason::Deadline,
            "absolute diagnostic deadline expired",
        ))
    } else {
        Ok(())
    }
}

fn windows_prelaunch_io_failure(
    phase: WindowsPrelaunchDiagnosticPhase,
    error: &std::io::Error,
) -> WindowsPrelaunchDiagnosticFailure {
    windows_prelaunch_failure(
        phase,
        WindowsPrelaunchDiagnosticReason::Io(error.kind()),
        error.to_string(),
    )
}

fn hash_windows_prelaunch_file_until(
    path: &Path,
    expected_bytes: u64,
    deadline: Instant,
    phase: WindowsPrelaunchDiagnosticPhase,
    hashed_bytes: &mut u64,
) -> Result<Digest, WindowsPrelaunchDiagnosticFailure> {
    require_windows_prelaunch_deadline(deadline, phase)?;
    let mut file =
        fs::File::open(path).map_err(|error| windows_prelaunch_io_failure(phase, &error))?;
    hash_windows_prelaunch_reader(&mut file, expected_bytes, phase, hashed_bytes, || {
        require_windows_prelaunch_deadline(deadline, phase)
    })
}

fn hash_windows_prelaunch_reader(
    mut reader: impl Read,
    expected_bytes: u64,
    phase: WindowsPrelaunchDiagnosticPhase,
    hashed_bytes: &mut u64,
    mut require_next_chunk: impl FnMut() -> Result<(), WindowsPrelaunchDiagnosticFailure>,
) -> Result<Digest, WindowsPrelaunchDiagnosticFailure> {
    let mut digest = Sha256::new();
    let mut file_bytes = 0_u64;
    let mut buffer = vec![0_u8; WINDOWS_PRELAUNCH_HASH_CHUNK_BYTES].into_boxed_slice();
    loop {
        require_next_chunk()?;
        let read = reader
            .read(&mut buffer)
            .map_err(|error| windows_prelaunch_io_failure(phase, &error))?;
        if read == 0 {
            break;
        }
        let read = u64::try_from(read).unwrap_or(u64::MAX);
        file_bytes = file_bytes.saturating_add(read);
        *hashed_bytes = hashed_bytes.saturating_add(read);
        digest.update(&buffer[..usize::try_from(read).unwrap_or(buffer.len())]);
    }
    if file_bytes != expected_bytes {
        return Err(windows_prelaunch_failure(
            phase,
            WindowsPrelaunchDiagnosticReason::FileChanged,
            "file length changed while hashing",
        ));
    }
    Ok(digest.finish())
}

/// Verifies deterministic chunk-level diagnostic cancellation without wall-clock sleeps.
///
/// # Errors
///
/// Returns an error if the deadline gate permits a read after typed expiry or
/// loses the exact partial-byte receipt.
#[doc(hidden)]
pub fn verify_windows_prelaunch_chunk_deadline_for_integration() -> Result<(), String> {
    struct CountingReader {
        reads: Arc<AtomicUsize>,
    }

    impl Read for CountingReader {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            buffer.fill(b'x');
            Ok(buffer.len())
        }
    }

    let reads = Arc::new(AtomicUsize::new(0));
    let gates = AtomicUsize::new(0);
    let mut hashed_bytes = 0_u64;
    let result = hash_windows_prelaunch_reader(
        CountingReader {
            reads: Arc::clone(&reads),
        },
        u64::MAX,
        WindowsPrelaunchDiagnosticPhase::DllHash,
        &mut hashed_bytes,
        || {
            if gates.fetch_add(1, Ordering::Relaxed) == 0 {
                Ok(())
            } else {
                Err(windows_prelaunch_failure(
                    WindowsPrelaunchDiagnosticPhase::DllHash,
                    WindowsPrelaunchDiagnosticReason::Deadline,
                    "deterministic chunk deadline",
                ))
            }
        },
    );
    let Err(failure) = result else {
        return Err("chunk deadline unexpectedly completed hashing".to_owned());
    };
    if failure.phase != WindowsPrelaunchDiagnosticPhase::DllHash
        || failure.reason != WindowsPrelaunchDiagnosticReason::Deadline
        || reads.load(Ordering::Relaxed) != 1
        || hashed_bytes != u64::try_from(WINDOWS_PRELAUNCH_HASH_CHUNK_BYTES).unwrap_or(u64::MAX)
    {
        return Err("chunk deadline did not stop at the exact partial receipt".to_owned());
    }
    Ok(())
}

fn collect_windows_prelaunch_dlls(
    parent: &Path,
    deadline: Instant,
    state: &mut WindowsPrelaunchDiagnosticState,
) -> Result<Vec<(PathBuf, u64)>, WindowsPrelaunchDiagnosticFailure> {
    let phase = WindowsPrelaunchDiagnosticPhase::DirectoryEnumeration;
    require_windows_prelaunch_deadline(deadline, phase)?;
    let entries =
        fs::read_dir(parent).map_err(|error| windows_prelaunch_io_failure(phase, &error))?;
    let mut dlls = Vec::new();
    for entry in entries {
        require_windows_prelaunch_deadline(deadline, phase)?;
        if state.directory_entries >= WINDOWS_PRELAUNCH_DIRECTORY_ENTRY_LIMIT {
            return Err(windows_prelaunch_failure(
                phase,
                WindowsPrelaunchDiagnosticReason::DirectoryEntryLimit,
                "staged-bin directory inventory exceeds its entry bound",
            ));
        }
        state.directory_entries += 1;
        let path = entry
            .map_err(|error| windows_prelaunch_io_failure(phase, &error))?
            .path();
        if !path
            .extension()
            .is_some_and(|extension| extension.to_string_lossy().eq_ignore_ascii_case("dll"))
        {
            continue;
        }
        if state.dll_count >= WINDOWS_PRELAUNCH_DLL_LIMIT {
            return Err(windows_prelaunch_failure(
                phase,
                WindowsPrelaunchDiagnosticReason::DllEntryLimit,
                "staged-bin DLL inventory exceeds its entry bound",
            ));
        }
        let metadata_phase = WindowsPrelaunchDiagnosticPhase::DllMetadata;
        require_windows_prelaunch_deadline(deadline, metadata_phase)?;
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| windows_prelaunch_io_failure(metadata_phase, &error))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() > WINDOWS_PRELAUNCH_FILE_BYTE_LIMIT
        {
            return Err(windows_prelaunch_failure(
                metadata_phase,
                WindowsPrelaunchDiagnosticReason::FileByteLimit,
                "staged-bin DLL inventory is not bounded direct files",
            ));
        }
        let total_bytes = state.dll_bytes.checked_add(metadata.len()).ok_or_else(|| {
            windows_prelaunch_failure(
                metadata_phase,
                WindowsPrelaunchDiagnosticReason::DllByteLimit,
                "staged-bin DLL inventory size overflowed",
            )
        })?;
        if total_bytes > WINDOWS_PRELAUNCH_DLL_BYTE_LIMIT {
            return Err(windows_prelaunch_failure(
                metadata_phase,
                WindowsPrelaunchDiagnosticReason::DllByteLimit,
                "staged-bin DLL inventory exceeds its byte bound",
            ));
        }
        state.dll_count += 1;
        state.dll_bytes = total_bytes;
        dlls.push((path, metadata.len()));
    }
    dlls.sort_by_key(|(path, _)| path.file_name().map(OsStr::to_os_string));
    Ok(dlls)
}

fn acquire_windows_prelaunch_diagnostic(
    program: &Path,
    program_authority: Option<&BoundProgramInvocation>,
    deadline: Instant,
    state: &mut WindowsPrelaunchDiagnosticState,
) -> Result<(u64, Digest, PathBuf), WindowsPrelaunchDiagnosticFailure> {
    let phase = WindowsPrelaunchDiagnosticPhase::ProgramMetadata;
    require_windows_prelaunch_deadline(deadline, phase)?;
    let metadata = fs::symlink_metadata(program)
        .map_err(|error| windows_prelaunch_io_failure(phase, &error))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > WINDOWS_PRELAUNCH_FILE_BYTE_LIMIT
    {
        return Err(windows_prelaunch_failure(
            phase,
            WindowsPrelaunchDiagnosticReason::FileByteLimit,
            "target is not one bounded direct file",
        ));
    }
    let parent = program.parent().ok_or_else(|| {
        windows_prelaunch_failure(
            phase,
            WindowsPrelaunchDiagnosticReason::FileChanged,
            "target has no staged-bin parent",
        )
    })?;
    #[cfg(windows)]
    let retained_program = program_authority
        .map(|authority| {
            authority
                .revalidate(program.as_os_str())
                .map_err(|error| windows_prelaunch_io_failure(phase, &error))?;
            if authority.length() != metadata.len() {
                return Err(windows_prelaunch_failure(
                    phase,
                    WindowsPrelaunchDiagnosticReason::FileChanged,
                    "retained target length differs from diagnostic metadata",
                ));
            }
            state.program_hashed = true;
            state.program_reused = true;
            Ok(authority.sha256())
        })
        .transpose()?;
    #[cfg(not(windows))]
    let retained_program = {
        let _ = program_authority;
        None
    };
    let dlls = collect_windows_prelaunch_dlls(parent, deadline, state)?;
    for (dll, bytes) in dlls {
        let digest = hash_windows_prelaunch_file_until(
            &dll,
            bytes,
            deadline,
            WindowsPrelaunchDiagnosticPhase::DllHash,
            &mut state.hashed_bytes,
        )?;
        state.hashed_dlls += 1;
        state.dll_evidence.push(format!(
            "{{name={},bytes={bytes},sha256={}}}",
            bounded_windows_path_debug(Path::new(
                dll.file_name().unwrap_or_else(|| OsStr::new("<missing>"))
            )),
            digest.hex(),
        ));
    }
    let program_digest = if let Some(digest) = retained_program {
        digest
    } else {
        let digest = hash_windows_prelaunch_file_until(
            program,
            metadata.len(),
            deadline,
            WindowsPrelaunchDiagnosticPhase::ProgramHash,
            &mut state.hashed_bytes,
        )?;
        state.program_hashed = true;
        digest
    };
    Ok((metadata.len(), program_digest, parent.to_owned()))
}

#[cfg(windows)]
#[doc(hidden)]
#[must_use]
pub fn windows_argv_target_prelaunch_diagnostic_with_program_until(
    program: &Path,
    authority: Option<&BoundProgramInvocation>,
    deadline: Instant,
) -> WindowsPrelaunchDiagnosticReceipt {
    windows_argv_target_prelaunch_diagnostic_from_authority_until(program, authority, deadline)
}

fn windows_argv_target_prelaunch_diagnostic_from_authority_until(
    program: &Path,
    authority: Option<&BoundProgramInvocation>,
    deadline: Instant,
) -> WindowsPrelaunchDiagnosticReceipt {
    let program_text = bounded_windows_path_debug(program);
    let mut state = WindowsPrelaunchDiagnosticState::default();
    let acquired = acquire_windows_prelaunch_diagnostic(program, authority, deadline, &mut state);
    let (outcome, rendered) = match acquired {
        Ok((program_bytes, program_sha256, parent)) => (
            WindowsPrelaunchDiagnosticOutcome::Complete,
            format!(
                "Windows argv target prelaunch evidence: program={program_text},programBytes={program_bytes},programSha256={},programSource={},stagedBin={},directoryEntries={},dllCount={},dllBytes={},hashedDlls={},hashedBytes={},dlls=[{}]",
                program_sha256.hex(),
                if state.program_reused {
                    "retained-authority"
                } else {
                    "diagnostic-hash"
                },
                bounded_windows_path_debug(&parent),
                state.directory_entries,
                state.dll_count,
                state.dll_bytes,
                state.hashed_dlls,
                state.hashed_bytes,
                state.dll_evidence.join(","),
            ),
        ),
        Err(failure) => (
            WindowsPrelaunchDiagnosticOutcome::Unavailable {
                phase: failure.phase,
                reason: failure.reason,
            },
            format!(
                "Windows argv target prelaunch evidence: program={program_text},outcome=unavailable,phase={},reason={:?},detail={},directoryEntries={},dllCount={},dllBytes={},hashedDlls={},hashedBytes={},programHashed={},programReused={}",
                failure.phase.as_str(),
                failure.reason,
                bounded_windows_diagnostic_detail(&failure.detail),
                state.directory_entries,
                state.dll_count,
                state.dll_bytes,
                state.hashed_dlls,
                state.hashed_bytes,
                state.program_hashed,
                state.program_reused,
            ),
        ),
    };
    WindowsPrelaunchDiagnosticReceipt {
        outcome,
        directory_entries: state.directory_entries,
        dll_count: state.dll_count,
        dll_bytes: state.dll_bytes,
        hashed_dlls: state.hashed_dlls,
        hashed_bytes: state.hashed_bytes,
        program_hashed: state.program_hashed,
        program_reused: state.program_reused,
        rendered,
    }
}

/// Captures optional Windows target evidence under its own absolute deadline.
///
/// The receipt is always returned. An incomplete receipt is diagnostic-only
/// and must never authorize, reject, or delay the semantic child launch.
#[doc(hidden)]
#[must_use]
pub fn windows_argv_target_prelaunch_diagnostic_until(
    program: &Path,
    deadline: Instant,
) -> WindowsPrelaunchDiagnosticReceipt {
    windows_argv_target_prelaunch_diagnostic_from_authority_until(program, None, deadline)
}

#[cfg(any(windows, test))]
fn encode_windows_argv_units(arguments: &[Vec<u16>]) -> std::io::Result<String> {
    let mut token = WINDOWS_ARGV_TOKEN_PREFIX.to_owned();
    for argument in arguments {
        if argument.contains(&0) {
            return Err(std::io::Error::other(
                "Windows argv cannot contain an embedded NUL",
            ));
        }
        token.push('|');
        for (index, unit) in argument.iter().enumerate() {
            if index != 0 {
                token.push(',');
            }
            std::fmt::Write::write_fmt(&mut token, format_args!("{unit}"))
                .expect("writing to String cannot fail");
        }
    }
    if token.len() > WINDOWS_ARGV_TOKEN_LIMIT {
        return Err(std::io::Error::other(
            "Windows argv token exceeds its bound",
        ));
    }
    Ok(token)
}

#[cfg(any(windows, test))]
fn decode_windows_argv_units(token: &str) -> std::io::Result<Vec<Vec<u16>>> {
    if token.len() > WINDOWS_ARGV_TOKEN_LIMIT {
        return Err(std::io::Error::other(
            "Windows argv token exceeds its bound",
        ));
    }
    let mut fields = token.split('|');
    if fields.next() != Some(WINDOWS_ARGV_TOKEN_PREFIX) {
        return Err(std::io::Error::other("Windows argv token version differs"));
    }
    fields
        .map(|field| {
            if field.is_empty() {
                return Ok(Vec::new());
            }
            field
                .split(',')
                .map(|unit| {
                    let unit = unit
                        .parse::<u16>()
                        .map_err(|_| std::io::Error::other("Windows argv token is malformed"))?;
                    if unit == 0 {
                        return Err(std::io::Error::other(
                            "Windows argv cannot contain an embedded NUL",
                        ));
                    }
                    Ok(unit)
                })
                .collect()
        })
        .collect()
}

/// Installs one launch policy for the duration of a synchronous operation.
pub fn with_candidate_launch_policy<T>(
    policy: &CandidateLaunchPolicy,
    operation: impl FnOnce() -> T,
) -> T {
    CANDIDATE_LAUNCH_POLICY.with(|slot| {
        struct Restore<'a> {
            slot: &'a RefCell<Option<CandidateLaunchPolicy>>,
            previous: Option<CandidateLaunchPolicy>,
        }
        impl Drop for Restore<'_> {
            fn drop(&mut self) {
                self.slot.replace(self.previous.take());
            }
        }
        let previous = slot.replace(Some(policy.clone()));
        let _restore = Restore { slot, previous };
        operation()
    })
}

fn resolve_parent_program(program: &std::ffi::OsStr) -> std::io::Result<PathBuf> {
    let path = Path::new(program);
    if path.components().count() > 1 {
        let absolute = fs::canonicalize(path)?;
        let metadata = fs::symlink_metadata(&absolute)?;
        return metadata.is_file().then_some(absolute).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "program is not a file")
        });
    }
    let search = std::env::var_os("PATH")
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "PATH is unavailable"))?;
    #[cfg(windows)]
    {
        let extensions = std::env::var_os("PATHEXT")
            .map(|value| windows_native_executable_extensions(&value))
            .unwrap_or_else(|| vec![OsString::from(".COM"), OsString::from(".EXE")]);
        return resolve_windows_parent_program_from(
            program,
            &std::env::split_paths(&search).collect::<Vec<_>>(),
            &extensions,
        );
    }
    #[cfg(not(windows))]
    {
        for directory in std::env::split_paths(&search) {
            let candidate = directory.join(path);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "trusted parent could not resolve child program",
        ))
    }
}

#[cfg(windows)]
fn windows_native_executable_extensions(value: &OsStr) -> Vec<OsString> {
    value
        .to_string_lossy()
        .split(';')
        .filter(|extension| {
            extension.eq_ignore_ascii_case(".com") || extension.eq_ignore_ascii_case(".exe")
        })
        .map(OsString::from)
        .collect()
}

/// Resolves a bare Windows program using only ordered native COM/EXE extensions.
///
/// # Errors
///
/// Returns an error for noncanonical names, nonnative extensions, or when no
/// regular executable exists beneath an absolute search directory.
#[doc(hidden)]
pub fn resolve_windows_parent_program_from(
    program: &OsStr,
    search: &[PathBuf],
    extensions: &[OsString],
) -> std::io::Result<PathBuf> {
    let path = Path::new(program);
    if program.is_empty() || path.is_absolute() || path.components().count() != 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Windows program name must be one relative component",
        ));
    }
    if path
        .file_stem()
        .and_then(OsStr::to_str)
        .is_none_or(|stem| !windows_tool_stem_is_canonical(stem))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Windows program stem is not canonical",
        ));
    }
    let names = if path.extension().is_some() {
        let native = path
            .extension()
            .and_then(OsStr::to_str)
            .is_some_and(|extension| {
                extension.eq_ignore_ascii_case("com") || extension.eq_ignore_ascii_case("exe")
            });
        if !native {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Windows program extension is not native",
            ));
        }
        vec![program.to_owned()]
    } else {
        extensions
            .iter()
            .filter(|extension| {
                extension.to_str().is_some_and(|extension| {
                    extension.eq_ignore_ascii_case(".com") || extension.eq_ignore_ascii_case(".exe")
                })
            })
            .map(|extension| {
                let mut name = program.to_owned();
                name.push(extension);
                name
            })
            .collect::<Vec<_>>()
    };
    for directory in search.iter().filter(|directory| directory.is_absolute()) {
        for name in &names {
            let candidate = directory.join(name);
            if candidate.is_file() {
                return fs::canonicalize(candidate);
            }
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "trusted parent could not resolve native Windows child program",
    ))
}

fn windows_tool_stem_is_canonical(stem: &str) -> bool {
    if stem.is_empty()
        || !stem
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return false;
    }
    let upper = stem.to_ascii_uppercase();
    let numbered_device = upper.len() == 4
        && matches!(&upper[..3], "COM" | "LPT")
        && matches!(upper.as_bytes()[3], b'1'..=b'9');
    !matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$") && !numbered_device
}

fn resolve_parent_program_for_launch(
    program: &std::ffi::OsStr,
    bound_program: Option<&BoundProgramInvocation>,
) -> std::io::Result<PathBuf> {
    bound_program.map_or_else(
        || resolve_parent_program(program),
        |identity| identity.revalidate(program),
    )
}

#[cfg(all(test, unix))]
mod candidate_launch_policy_tests {
    use super::*;

    fn candidate_identity(name: &str, uid: u32) -> PosixCandidateIdentity {
        PosixCandidateIdentity::new(name.to_owned(), uid, uid, vec![uid], name.to_owned()).unwrap()
    }

    fn native_cargo_authority(
        cargo: &Path,
        standard_rustup_invocation: &Path,
    ) -> PosixCargoSourceAuthority {
        use std::os::unix::fs::MetadataExt as _;

        let cargo = fs::canonicalize(cargo).unwrap();
        let cargo_metadata = fs::metadata(&cargo).unwrap();
        let rustup = fs::canonicalize(standard_rustup_invocation).unwrap();
        let rustup_metadata = fs::metadata(&rustup).unwrap();
        let rustup_invocation = fs::canonicalize(standard_rustup_invocation.parent().unwrap())
            .unwrap()
            .join("rustup");
        PosixCargoSourceAuthority::Native {
            cargo: PosixCanonicalExecutableIdentity::new(
                cargo,
                cargo_metadata.dev(),
                cargo_metadata.ino(),
            ),
            standard_rustup: PosixStandardExecutableIdentity::new(
                rustup_invocation,
                rustup,
                rustup_metadata.dev(),
                rustup_metadata.ino(),
            ),
        }
    }

    fn oversized_candidate_groups(primary_gid: u32) -> Vec<u32> {
        let limit = u32::try_from(POSIX_CANDIDATE_GROUP_LIMIT).unwrap();
        (0..limit).chain(std::iter::once(primary_gid)).collect()
    }

    #[test]
    fn rustup_ancestor_access_uses_only_the_candidate_effective_permission_class() {
        let candidate_groups = [61_001, 20];
        assert!(posix_rustup_ancestor_access_is_safe(
            0o775,
            501,
            &candidate_groups
        ));
        assert!(!posix_rustup_ancestor_access_is_safe(
            0o775,
            20,
            &candidate_groups
        ));
        assert!(posix_rustup_ancestor_access_is_safe(
            0o750,
            20,
            &candidate_groups
        ));
        assert!(!posix_rustup_ancestor_access_is_safe(
            0o750,
            501,
            &candidate_groups
        ));
        assert!(!posix_rustup_ancestor_access_is_safe(
            0o777,
            501,
            &candidate_groups
        ));
        assert!(posix_rustup_ancestor_access_is_safe(
            0o1777,
            501,
            &candidate_groups
        ));
        assert!(posix_candidate_group_inventory_is_valid(
            61_001,
            &candidate_groups
        ));
        assert!(!posix_candidate_group_inventory_is_valid(61_001, &[]));
        assert!(!posix_candidate_group_inventory_is_valid(
            61_001,
            &[20, 701]
        ));
        assert!(!posix_candidate_group_inventory_is_valid(
            61_001,
            &[61_001, 20, 61_001]
        ));
        assert!(!posix_candidate_group_inventory_is_valid(
            61_001,
            &oversized_candidate_groups(61_001)
        ));
        assert!(!posix_rustup_owner_is_trusted(61_001, 61_001));
        assert!(posix_rustup_owner_is_trusted(501, 61_001));
    }

    #[test]
    fn posix_candidate_identity_rejects_incomplete_or_oversized_groups() {
        assert!(
            PosixCandidateIdentity::new(
                "hellreltest".to_owned(),
                61_001,
                61_001,
                vec![20, 61_001, 701],
                "hellreltest".to_owned(),
            )
            .is_ok()
        );
        for groups in [
            Vec::new(),
            vec![20, 701],
            vec![61_001, 20, 61_001],
            oversized_candidate_groups(61_001),
        ] {
            assert!(
                PosixCandidateIdentity::new(
                    "hellreltest".to_owned(),
                    61_001,
                    61_001,
                    groups,
                    "hellreltest".to_owned(),
                )
                .is_err()
            );
        }
    }

    #[test]
    fn rustup_ancestor_rejection_binds_exact_authority_state() {
        let identity = PosixRustupEntryIdentity {
            path: PathBuf::from("/trusted/rustup"),
            device: 17,
            inode: 29,
            links: 1,
            uid: 501,
            gid: 20,
            mode: 0o775,
            requirement: PosixRustupAccessRequirement::AncestorDirectory,
        };
        assert_eq!(
            posix_rustup_ancestor_rejection(&identity, true, 61_001, &[61_001, 20]),
            "POSIX Rustup ancestor rejected: path=/trusted/rustup,isDirectory=true,mode=0o0775,ownerUid=501,ownerGid=20,candidateUid=61001,candidateGroups=[61001, 20],accessClass=group,effectiveBits=0o7"
        );
    }

    #[test]
    fn standard_executable_identity_requires_effective_user_execute_access() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let root = std::env::temp_dir().join(format!(
            "hell-standard-executable-x-ok-{}-{}",
            std::process::id(),
            NEXT_SANDBOX.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let root = fs::canonicalize(root).unwrap();
        let rustup = root.join("rustup");
        fs::write(&rustup, b"not executed\n").unwrap();
        fs::set_permissions(&rustup, fs::Permissions::from_mode(0o001)).unwrap();
        let metadata = fs::metadata(&rustup).unwrap();
        assert!(
            BoundPosixStandardExecutableIdentity::new(PosixStandardExecutableIdentity::new(
                rustup.clone(),
                rustup,
                metadata.dev(),
                metadata.ino(),
            ))
            .is_err(),
            "execute permission for another identity must not replace effective-user X_OK"
        );
    }

    struct CargoDenyAuthorityFixture {
        root: PathBuf,
        source: PathBuf,
        staged: PathBuf,
        cargo_home: PathBuf,
        cache_entry: PathBuf,
        advisory_lock: PathBuf,
        metadata_directory: PathBuf,
        metadata_path: PathBuf,
        bound: BoundPosixCargoDenyAuthority,
    }

    fn cargo_deny_authority_fixture() -> CargoDenyAuthorityFixture {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let root = std::env::temp_dir().join(format!(
            "hell-cargo-deny-authority-{}-{}",
            std::process::id(),
            NEXT_SANDBOX.fetch_add(1, Ordering::Relaxed)
        ));
        let source_root = root.join("source");
        let staged_root = root.join("staged");
        fs::create_dir_all(&source_root).unwrap();
        fs::create_dir(&staged_root).unwrap();
        let source_root = fs::canonicalize(source_root).unwrap();
        let staged_root = fs::canonicalize(staged_root).unwrap();
        let source = source_root.join("cargo-deny");
        let staged = staged_root.join("cargo-deny");
        let cargo_home = root.join("cargo-deny-cargo-home");
        fs::create_dir(&cargo_home).unwrap();
        let cache_entry = cargo_home.join("registry-cache");
        fs::write(&cache_entry, b"bound cargo cache\n").unwrap();
        fs::set_permissions(&cache_entry, fs::Permissions::from_mode(0o444)).unwrap();
        let advisory_root = cargo_home.join("advisory-dbs");
        fs::create_dir(&advisory_root).unwrap();
        let advisory_lock = advisory_root.join("db.lock");
        fs::write(&advisory_lock, b"").unwrap();
        fs::set_permissions(&advisory_lock, fs::Permissions::from_mode(0o660)).unwrap();
        // cargo-deny opens db.lock with read+write+create semantics, so the
        // advisory root itself must stay candidate-writable for lock creation
        // while every advisory database below it remains read-only.
        fs::set_permissions(&advisory_root, fs::Permissions::from_mode(0o750)).unwrap();
        fs::set_permissions(&cargo_home, fs::Permissions::from_mode(0o555)).unwrap();
        for path in [&source, &staged] {
            fs::write(path, b"pinned cargo-deny\n").unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o555)).unwrap();
        }
        let metadata_parent = if cfg!(target_os = "macos") {
            Path::new("/private/var/tmp")
        } else {
            Path::new("/var/tmp")
        };
        let metadata_directory = metadata_parent.join(format!(
            "hell-cargo-deny-metadata-{}-{}",
            std::process::id(),
            NEXT_SANDBOX.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&metadata_directory).unwrap();
        let metadata_path = metadata_directory.join("metadata.json");
        fs::write(&metadata_path, b"{\"version\":1}\n").unwrap();
        fs::set_permissions(&metadata_path, fs::Permissions::from_mode(0o444)).unwrap();
        fs::set_permissions(&metadata_directory, fs::Permissions::from_mode(0o555)).unwrap();
        let metadata_file = fs::metadata(&metadata_path).unwrap();
        let metadata = PosixCargoDenyMetadataAuthority::new(
            metadata_directory.clone(),
            metadata_path.clone(),
            metadata_file.len(),
            sha256_file(&metadata_path).unwrap(),
            metadata_file.uid(),
        );
        let source_metadata = fs::metadata(&source).unwrap();
        let cargo_home_metadata = fs::metadata(&cargo_home).unwrap();
        let digest = sha256_file(&source).unwrap();
        let authority = PosixCargoDenyAuthority::new(
            PosixStandardExecutableIdentity::new(
                source.clone(),
                source.clone(),
                source_metadata.dev(),
                source_metadata.ino(),
            ),
            digest,
            staged.clone(),
            digest,
            cargo_home.clone(),
            metadata,
            PosixCargoDenyCacheOwnership::new(cargo_home_metadata.uid(), cargo_home_metadata.gid()),
        );
        let candidate_group_id = cargo_home_metadata.gid().checked_add(1).unwrap();
        let bound = BoundPosixCargoDenyAuthority::new_for_fixture(
            authority.clone(),
            cargo_home_metadata.uid(),
            &[candidate_group_id],
            std::slice::from_ref(&root),
            candidate_group_id,
        )
        .unwrap();
        assert!(
            BoundPosixCargoDenyAuthority::new(
                authority,
                cargo_home_metadata.uid(),
                &[cargo_home_metadata.gid()],
                std::slice::from_ref(&root),
            )
            .is_err()
        );

        CargoDenyAuthorityFixture {
            root,
            source,
            staged,
            cargo_home,
            cache_entry,
            advisory_lock,
            metadata_directory,
            metadata_path,
            bound,
        }
    }

    fn cargo_deny_policy(
        root: &Path,
        bound: &BoundPosixCargoDenyAuthority,
    ) -> (CandidateLaunchPolicy, PathBuf) {
        use std::os::unix::fs::symlink;

        let standard_rustup = root.join("rustup");
        symlink("/usr/bin/false", &standard_rustup).unwrap();
        let native_cargo = fs::canonicalize("/usr/bin/true").unwrap();
        let mut policy = CandidateLaunchPolicy::posix(
            native_cargo.clone(),
            PosixLaunchAuthorities::new(
                native_cargo.clone(),
                sha256_file(&native_cargo).unwrap(),
                native_cargo.clone(),
                native_cargo.clone(),
                sha256_file(&native_cargo).unwrap(),
                native_cargo_authority(&native_cargo, &standard_rustup),
            ),
            candidate_identity("hellreldeny", 61_007),
            vec![root.to_path_buf()],
        )
        .unwrap();
        policy.cargo_deny_authority = Some(bound.clone());
        (policy, native_cargo)
    }

    #[test]
    fn cargo_deny_authority_maps_only_the_exact_bound_source_to_its_staged_copy() {
        use std::os::unix::fs::PermissionsExt as _;

        let CargoDenyAuthorityFixture {
            root,
            source,
            staged,
            cargo_home,
            cache_entry,
            advisory_lock,
            metadata_directory,
            metadata_path: _,
            bound,
        } = cargo_deny_authority_fixture();
        let advisory_identity = bound
            .cargo_home_inventory
            .iter()
            .find(|entry| entry.relative == Path::new("advisory-dbs/db.lock"))
            .unwrap();
        assert!(advisory_identity.sha256.is_none());
        let immutable_identity = bound
            .cargo_home_inventory
            .iter()
            .find(|entry| entry.relative == Path::new("registry-cache"))
            .unwrap();
        assert!(immutable_identity.sha256.is_some());
        assert!(
            bound
                .request_is_bound(OsStr::new("cargo-deny"), &source)
                .unwrap()
        );
        assert!(
            !bound
                .request_is_bound(OsStr::new("cargo"), &source)
                .unwrap()
        );
        let forgery_root = root.join("forgery");
        fs::create_dir(&forgery_root).unwrap();
        let forgery = forgery_root.join("cargo-deny");
        fs::write(&forgery, b"pinned cargo-deny\n").unwrap();
        fs::set_permissions(&forgery, fs::Permissions::from_mode(0o555)).unwrap();
        assert!(
            bound
                .request_is_bound(forgery.as_os_str(), &forgery)
                .is_err()
        );

        fs::set_permissions(&source, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(&source, b"source substitution\n").unwrap();
        assert!(bound.revalidate().is_err());
        fs::write(&source, b"pinned cargo-deny\n").unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o555)).unwrap();
        bound.revalidate().unwrap();

        fs::set_permissions(&cache_entry, fs::Permissions::from_mode(0o644)).unwrap();
        fs::write(&cache_entry, b"cache substitution\n").unwrap();
        assert!(bound.revalidate().is_err());
        fs::write(&cache_entry, b"bound cargo cache\n").unwrap();
        fs::set_permissions(&cache_entry, fs::Permissions::from_mode(0o444)).unwrap();
        fs::write(&advisory_lock, b"forged lock contents\n").unwrap();
        assert!(bound.revalidate().is_err());
        fs::write(&advisory_lock, b"").unwrap();
        bound.revalidate().unwrap();
        fs::set_permissions(&advisory_lock, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(bound.revalidate().is_err());
        fs::set_permissions(&advisory_lock, fs::Permissions::from_mode(0o660)).unwrap();
        bound.revalidate().unwrap();
        let advisory_root = advisory_lock.parent().unwrap();
        let original_lock = advisory_root.join("original-db.lock");
        fs::set_permissions(advisory_root, fs::Permissions::from_mode(0o755)).unwrap();
        fs::rename(&advisory_lock, &original_lock).unwrap();
        fs::write(&advisory_lock, b"").unwrap();
        fs::set_permissions(&advisory_lock, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(advisory_root, fs::Permissions::from_mode(0o555)).unwrap();
        assert!(bound.revalidate().is_err());
        fs::set_permissions(advisory_root, fs::Permissions::from_mode(0o755)).unwrap();
        fs::remove_file(&advisory_lock).unwrap();
        fs::rename(&original_lock, &advisory_lock).unwrap();
        fs::set_permissions(advisory_root, fs::Permissions::from_mode(0o750)).unwrap();
        bound.revalidate().unwrap();
        fs::set_permissions(&cargo_home, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(bound.revalidate().is_err());
        fs::set_permissions(&cargo_home, fs::Permissions::from_mode(0o555)).unwrap();

        fs::set_permissions(&staged, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(&staged, b"staged substitution\n").unwrap();
        assert!(bound.revalidate().is_err());
        fs::set_permissions(&staged, fs::Permissions::from_mode(0o555)).unwrap();
        fs::set_permissions(&cargo_home, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(
            advisory_lock.parent().unwrap(),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        fs::remove_dir_all(root).unwrap();
        fs::set_permissions(&metadata_directory, fs::Permissions::from_mode(0o755)).unwrap();
        fs::remove_dir_all(metadata_directory).unwrap();
    }

    #[test]
    fn cargo_deny_metadata_is_injected_and_revalidated_without_overrides() {
        use std::os::unix::fs::PermissionsExt as _;

        let CargoDenyAuthorityFixture {
            root,
            source,
            staged,
            cargo_home,
            cache_entry: _,
            advisory_lock,
            metadata_directory,
            metadata_path,
            bound,
        } = cargo_deny_authority_fixture();
        let (policy, native_cargo) = cargo_deny_policy(&root, &bound);
        let mut command = Command::new(&source);
        command.args(["--frozen", "--all-features", "check", "all"]);
        command.env("PATH", std::env::var_os("PATH").unwrap_or_default());
        policy.wrap(&mut command, None).unwrap();
        let (environment, program, arguments) = posix_release_child_request(&command);
        assert_eq!(program, staged);
        assert_eq!(arguments[0], OsStr::new("--metadata-path"));
        assert_eq!(arguments[1], metadata_path.as_os_str());
        assert_eq!(
            &arguments[2..],
            ["--frozen", "--all-features", "check", "all"].map(OsString::from)
        );
        assert_eq!(
            environment
                .get(OsStr::new("CARGO_HOME"))
                .map(OsString::as_os_str),
            Some(bound.cargo_home.as_os_str())
        );
        assert_eq!(
            environment
                .get(OsStr::new("CARGO"))
                .map(OsString::as_os_str),
            Some(native_cargo.as_os_str())
        );
        assert_eq!(
            environment
                .get(OsStr::new("PATH"))
                .and_then(|value| std::env::split_paths(value).next()),
            native_cargo.parent().map(Path::to_path_buf)
        );
        for argument in [
            OsString::from("--metadata-path"),
            OsString::from("--metadata-path=forged"),
        ] {
            let mut forged = Command::new(&source);
            forged.arg(argument);
            forged.env("PATH", std::env::var_os("PATH").unwrap_or_default());
            assert!(policy.wrap(&mut forged, None).is_err());
        }

        fs::set_permissions(&metadata_path, fs::Permissions::from_mode(0o644)).unwrap();
        fs::write(&metadata_path, b"{\"version\":2}\n").unwrap();
        assert!(bound.revalidate().is_err());
        fs::write(&metadata_path, b"{\"version\":1}\n").unwrap();
        fs::set_permissions(&metadata_path, fs::Permissions::from_mode(0o444)).unwrap();
        bound.revalidate().unwrap();
        fs::set_permissions(&metadata_directory, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(metadata_directory.join("extra.json"), b"{}\n").unwrap();
        fs::set_permissions(&metadata_directory, fs::Permissions::from_mode(0o555)).unwrap();
        assert!(bound.revalidate().is_err());
        fs::set_permissions(&metadata_directory, fs::Permissions::from_mode(0o755)).unwrap();
        fs::remove_file(metadata_directory.join("extra.json")).unwrap();
        // Removing and recreating the document can reuse the freed inode on
        // Linux, which would leave the bound identity valid. Bind a genuinely
        // distinct inode by renaming a separately created replacement over
        // the exact authority path instead.
        let replacement = metadata_directory.join("metadata.replacement.json");
        fs::write(&replacement, b"{\"version\":1}\n").unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o444)).unwrap();
        fs::rename(&replacement, &metadata_path).unwrap();
        fs::set_permissions(&metadata_directory, fs::Permissions::from_mode(0o555)).unwrap();
        assert!(bound.revalidate().is_err());

        fs::set_permissions(&cargo_home, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(
            advisory_lock.parent().unwrap(),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        fs::remove_dir_all(root).unwrap();
        fs::set_permissions(&metadata_directory, fs::Permissions::from_mode(0o755)).unwrap();
        fs::remove_dir_all(metadata_directory).unwrap();
    }

    struct StackAuthorityFixture {
        root: PathBuf,
        source: PathBuf,
        staged: PathBuf,
        stack_root: PathBuf,
        stack_root_uid: u32,
        candidate_group_id: u32,
        authority: PosixStackAuthority,
        bound: BoundPosixStackAuthority,
    }

    fn stack_authority_fixture() -> StackAuthorityFixture {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let root = std::env::temp_dir().join(format!(
            "hell-stack-authority-{}-{}",
            std::process::id(),
            NEXT_SANDBOX.fetch_add(1, Ordering::Relaxed)
        ));
        let source_root = root.join("source");
        let staged_root = root.join("staged");
        fs::create_dir_all(&source_root).unwrap();
        fs::create_dir(&staged_root).unwrap();
        let source_root = fs::canonicalize(source_root).unwrap();
        let staged_root = fs::canonicalize(staged_root).unwrap();
        let source = source_root.join("stack");
        let staged = staged_root.join("stack");
        let stack_root = root.join("stack-root");
        fs::create_dir(&stack_root).unwrap();
        fs::set_permissions(&stack_root, fs::Permissions::from_mode(0o750)).unwrap();
        let stack_root = fs::canonicalize(stack_root).unwrap();
        for path in [&source, &staged] {
            fs::write(path, b"pinned stack\n").unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o555)).unwrap();
        }
        let source_metadata = fs::metadata(&source).unwrap();
        let stack_root_metadata = fs::metadata(&stack_root).unwrap();
        let candidate_group_id = stack_root_metadata.gid().checked_add(1).unwrap();
        let digest = sha256_file(&source).unwrap();
        let authority = PosixStackAuthority::new(
            PosixStandardExecutableIdentity::new(
                source.clone(),
                source.clone(),
                source_metadata.dev(),
                source_metadata.ino(),
            ),
            digest,
            staged.clone(),
            digest,
            stack_root.clone(),
            stack_root_metadata.gid(),
        );
        let bound = BoundPosixStackAuthority::new(
            authority.clone(),
            stack_root_metadata.uid(),
            &[candidate_group_id],
            std::slice::from_ref(&root),
        )
        .unwrap();
        assert!(
            BoundPosixStackAuthority::new(
                authority.clone(),
                stack_root_metadata.uid(),
                &[stack_root_metadata.gid()],
                std::slice::from_ref(&root),
            )
            .is_err()
        );
        let initial_forgery = stack_root.join("preexisting-state");
        fs::write(&initial_forgery, b"unexpected\n").unwrap();
        assert!(
            BoundPosixStackAuthority::new(
                authority.clone(),
                stack_root_metadata.uid(),
                &[candidate_group_id],
                std::slice::from_ref(&root),
            )
            .is_err()
        );
        fs::remove_file(initial_forgery).unwrap();
        StackAuthorityFixture {
            root,
            source,
            staged,
            stack_root,
            stack_root_uid: stack_root_metadata.uid(),
            candidate_group_id,
            authority,
            bound,
        }
    }

    fn assert_stack_argument_forgeries_rejected(
        policy: &CandidateLaunchPolicy,
        source: &Path,
        root: &Path,
    ) {
        for arguments in [
            vec![OsString::from("--stack-root"), root.as_os_str().into()],
            vec![OsString::from("--stack-root=/unbound")],
            vec![OsString::from("--work-dir"), root.as_os_str().into()],
            vec![OsString::from("--work-dir=/unbound")],
        ] {
            let mut forged = Command::new(source);
            forged
                .args(arguments)
                .env("PATH", std::env::var_os("PATH").unwrap_or_default());
            assert!(policy.wrap(&mut forged, None).is_err());
        }
    }

    #[test]
    fn stack_work_authority_binds_relative_path_and_revalidates_every_directory() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let root = std::env::temp_dir().join(format!(
            "hell-stack-work-authority-{}-{}",
            std::process::id(),
            NEXT_SANDBOX.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let root = fs::canonicalize(root).unwrap();
        let source = root.join("oracle");
        fs::create_dir(&source).unwrap();
        let work = source.join(".stack-work");
        fs::create_dir(&work).unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o555)).unwrap();
        fs::set_permissions(&work, fs::Permissions::from_mode(0o750)).unwrap();
        let work_metadata = fs::metadata(&work).unwrap();
        let candidate_uid = work_metadata.uid();
        let bound = BoundPosixStackWorkAuthority::new(
            &source,
            &work,
            candidate_uid,
            &[work_metadata.gid().checked_add(1).unwrap()],
        )
        .unwrap();
        assert_eq!(bound.relative, PathBuf::from(".stack-work"));
        assert_eq!(
            posix_stack_arguments(
                vec![OsString::from("build")],
                Some(Path::new("/bound/stack-root")),
                Some(&bound.relative),
            )
            .unwrap(),
            [
                OsString::from("--stack-root"),
                OsString::from("/bound/stack-root"),
                OsString::from("--work-dir"),
                OsString::from(".stack-work"),
                OsString::from("build"),
            ]
        );
        for arguments in [
            vec![
                OsString::from("--work-dir"),
                bound.relative.clone().into_os_string(),
            ],
            vec![OsString::from("--work-dir=.stack-work")],
        ] {
            assert!(
                posix_stack_arguments(
                    arguments,
                    Some(Path::new("/bound/stack-root")),
                    Some(&bound.relative),
                )
                .is_err()
            );
        }
        let escaped_source = root.parent().unwrap().join(format!(
            "hell-stack-work-escaped-{}-{}",
            std::process::id(),
            NEXT_SANDBOX.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&escaped_source).unwrap();
        let escaped_source = fs::canonicalize(escaped_source).unwrap();
        assert!(
            BoundPosixStackWorkAuthority::new(
                &escaped_source,
                &work,
                candidate_uid,
                &[work_metadata.gid().checked_add(1).unwrap()],
            )
            .is_err()
        );
        let replacement = source.join("replacement-stack-work");
        fs::set_permissions(&source, fs::Permissions::from_mode(0o755)).unwrap();
        fs::create_dir(&replacement).unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o750)).unwrap();
        fs::remove_dir(&work).unwrap();
        fs::rename(replacement, &work).unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o555)).unwrap();
        assert!(bound.revalidate().is_err());
        fs::set_permissions(&source, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir(escaped_source).unwrap();
    }

    #[test]
    fn stack_authority_maps_only_the_exact_bound_source_to_its_staged_copy() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let StackAuthorityFixture {
            root,
            source,
            staged,
            stack_root,
            stack_root_uid,
            candidate_group_id,
            authority,
            bound,
        } = stack_authority_fixture();
        assert!(
            bound
                .request_is_bound(OsStr::new("stack"), &source)
                .unwrap()
        );
        assert!(
            !bound
                .request_is_bound(OsStr::new("cargo"), &source)
                .unwrap()
        );

        let forgery = root.join("stack");
        fs::write(&forgery, b"pinned stack\n").unwrap();
        fs::set_permissions(&forgery, fs::Permissions::from_mode(0o555)).unwrap();
        assert!(
            bound
                .request_is_bound(forgery.as_os_str(), &forgery)
                .is_err()
        );

        let standard_rustup = root.join("rustup");
        symlink("/usr/bin/false", &standard_rustup).unwrap();
        let native_cargo = fs::canonicalize("/usr/bin/true").unwrap();
        let policy = CandidateLaunchPolicy::posix(
            native_cargo.clone(),
            PosixLaunchAuthorities::new(
                native_cargo.clone(),
                sha256_file(&native_cargo).unwrap(),
                native_cargo.clone(),
                native_cargo.clone(),
                sha256_file(&native_cargo).unwrap(),
                native_cargo_authority(&native_cargo, &standard_rustup),
            )
            .stack(authority),
            PosixCandidateIdentity::new(
                "hellrelstack".to_owned(),
                stack_root_uid,
                candidate_group_id,
                vec![candidate_group_id],
                "hellrelstack".to_owned(),
            )
            .unwrap(),
            vec![root.clone()],
        )
        .unwrap();
        assert_stack_argument_forgeries_rejected(&policy, &source, &root);
        let mut command = Command::new(&source);
        command.env("PATH", std::env::var_os("PATH").unwrap_or_default());
        policy.wrap(&mut command, None).unwrap();
        let (_, program, arguments) = posix_release_child_request(&command);
        assert_eq!(program, staged);
        assert_eq!(
            arguments,
            [
                OsString::from("--stack-root"),
                stack_root.clone().into_os_string(),
            ]
        );

        fs::set_permissions(&source, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(&source, b"source substitution\n").unwrap();
        assert!(bound.revalidate().is_err());
        fs::write(&source, b"pinned stack\n").unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o555)).unwrap();
        bound.revalidate().unwrap();
        fs::set_permissions(&staged, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(&staged, b"staged substitution\n").unwrap();
        assert!(bound.revalidate().is_err());
        fs::write(&staged, b"pinned stack\n").unwrap();
        fs::set_permissions(&staged, fs::Permissions::from_mode(0o555)).unwrap();
        bound.revalidate().unwrap();
        fs::set_permissions(&bound.stack_root, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(bound.revalidate().is_err());
        fs::set_permissions(&bound.stack_root, fs::Permissions::from_mode(0o750)).unwrap();
        let replacement_root = root.join("replacement-stack-root");
        fs::create_dir(&replacement_root).unwrap();
        fs::set_permissions(&replacement_root, fs::Permissions::from_mode(0o750)).unwrap();
        fs::remove_dir(&bound.stack_root).unwrap();
        fs::rename(replacement_root, &bound.stack_root).unwrap();
        assert!(bound.revalidate().is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rustup_proxy_identity_separates_logical_aliases_from_the_multicall_target() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};

        let root = std::env::temp_dir().join(format!(
            "hell-rustup-proxy-aliases-{}-{}",
            std::process::id(),
            NEXT_SANDBOX.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(root.join("cargo-path")).unwrap();
        fs::create_dir(root.join("standard-path")).unwrap();
        let target = root.join("multicall-engine");
        let replacement = root.join("replacement-engine");
        let cargo_invocation = root.join("cargo-path/cargo");
        let rustup_invocation = root.join("standard-path/rustup");
        for executable in [&target, &replacement] {
            fs::write(executable, b"multicall executable\n").unwrap();
            fs::set_permissions(executable, fs::Permissions::from_mode(0o555)).unwrap();
        }
        symlink(&target, &cargo_invocation).unwrap();
        symlink(&target, &rustup_invocation).unwrap();
        let canonical_target = fs::canonicalize(&target).unwrap();
        let metadata = fs::metadata(&canonical_target).unwrap();
        let identity = PosixRustupProxyIdentity::new(
            fs::canonicalize(root.join("cargo-path"))
                .unwrap()
                .join("cargo"),
            canonical_target.clone(),
            fs::canonicalize(root.join("standard-path"))
                .unwrap()
                .join("rustup"),
            canonical_target,
            metadata.dev(),
            metadata.ino(),
        );
        validate_posix_rustup_proxy_identity(&identity, 61_001, &[61_001]).unwrap();

        let mut forged_name = identity.clone();
        forged_name.cargo_invocation = root.join("cargo-path/not-cargo");
        symlink(&target, &forged_name.cargo_invocation).unwrap();
        assert!(validate_posix_rustup_proxy_identity(&forged_name, 61_001, &[61_001]).is_err());

        fs::remove_file(&cargo_invocation).unwrap();
        symlink(&replacement, &cargo_invocation).unwrap();
        assert!(
            validate_posix_rustup_proxy_identity(&identity, 61_001, &[61_001]).is_err(),
            "a same-byte replacement behind the logical Cargo alias must fail"
        );
        fs::remove_dir_all(root).unwrap();
    }

    fn rustup_authority_fixture(root: &Path) -> (PosixRustupAuthority, PathBuf) {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let source_home = root.join("source-rustup-home");
        let home = root.join("rustup-home");
        let toolchain = OsString::from("1.97.1-test-x86_64-unknown-linux-gnu");
        for rustup_home in [&source_home, &home] {
            let toolchains = rustup_home.join("toolchains");
            let update_hashes = rustup_home.join("update-hashes");
            let toolchain_root = toolchains.join(&toolchain);
            let bin = toolchain_root.join("bin");
            fs::create_dir_all(&bin).unwrap();
            let settings = rustup_home.join("settings.toml");
            fs::write(&settings, b"default_toolchain = none\n").unwrap();
            fs::create_dir_all(&update_hashes).unwrap();
            fs::write(update_hashes.join(&toolchain), b"test update hash\n").unwrap();
            for executable in [bin.join("cargo"), bin.join("rustc")] {
                fs::write(&executable, b"trusted toolchain executable\n").unwrap();
                fs::set_permissions(executable, fs::Permissions::from_mode(0o555)).unwrap();
            }
            for directory in [
                rustup_home.as_path(),
                toolchains.as_path(),
                update_hashes.as_path(),
                toolchain_root.as_path(),
                bin.as_path(),
            ] {
                fs::set_permissions(directory, fs::Permissions::from_mode(0o755)).unwrap();
            }
            fs::set_permissions(&settings, fs::Permissions::from_mode(0o644)).unwrap();
            fs::set_permissions(
                update_hashes.join(&toolchain),
                fs::Permissions::from_mode(0o644),
            )
            .unwrap();
        }
        fs::set_permissions(root, fs::Permissions::from_mode(0o755)).unwrap();
        let home = fs::canonicalize(home).unwrap();
        let source_home = fs::canonicalize(source_home).unwrap();
        let canonical_root = fs::canonicalize(root).unwrap();
        let cargo_proxy = fs::canonicalize(root.join("cargo")).unwrap();
        let rustup = fs::canonicalize(root.join("rustup")).unwrap();
        let rustc_invocation = canonical_root.join("rustc");
        if !rustc_invocation.exists() {
            fs::hard_link(&rustup, &rustc_invocation).unwrap();
        }
        let rustc = fs::canonicalize(&rustc_invocation).unwrap();
        let metadata = fs::metadata(&cargo_proxy).unwrap();
        let rustc_metadata = fs::metadata(&rustc).unwrap();
        let source_rustc = source_home
            .join("toolchains")
            .join(&toolchain)
            .join("bin/rustc");
        let staged_rustc = home.join("toolchains").join(&toolchain).join("bin/rustc");
        (
            PosixRustupAuthority::new(
                PosixRustupProxyIdentity::new(
                    canonical_root.join("cargo"),
                    cargo_proxy,
                    canonical_root.join("rustup"),
                    rustup,
                    metadata.dev(),
                    metadata.ino(),
                ),
                PosixRustcAuthority::RustupProxy(PosixStandardExecutableIdentity::new(
                    rustc_invocation,
                    rustc,
                    rustc_metadata.dev(),
                    rustc_metadata.ino(),
                )),
                source_home,
                home,
                toolchain,
                PosixRustupCompilerMapping::new(
                    source_rustc.clone(),
                    sha256_file(&source_rustc).unwrap(),
                    staged_rustc.clone(),
                    sha256_file(&staged_rustc).unwrap(),
                ),
            ),
            fs::canonicalize(root.join("rustup-home/settings.toml")).unwrap(),
        )
    }

    fn assert_same_bytes_native_cargo_is_not_a_rustup_proxy(
        root: &Path,
        staged: &Path,
        rustup_authority: &PosixRustupAuthority,
    ) {
        use std::os::unix::fs::PermissionsExt as _;

        let native_directory = root.join("native");
        fs::create_dir(&native_directory).unwrap();
        let native_cargo = native_directory.join("cargo");
        let native_rustup = native_directory.join("rustup");
        for path in [&native_cargo, &native_rustup] {
            fs::write(path, b"same native bytes\n").unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o555)).unwrap();
        }
        assert!(!same_executable_file(&native_cargo, &native_rustup).unwrap());
        let launcher = fs::canonicalize("/usr/bin/true").unwrap();
        CandidateLaunchPolicy::posix(
            launcher.clone(),
            PosixLaunchAuthorities::new(
                launcher.clone(),
                sha256_file(&launcher).unwrap(),
                fs::canonicalize(&native_cargo).unwrap(),
                staged.to_path_buf(),
                sha256_file(staged).unwrap(),
                native_cargo_authority(&native_cargo, &native_rustup),
            ),
            candidate_identity("hellrelnative", 61_003),
            vec![std::env::temp_dir()],
        )
        .unwrap();
        let policy = CandidateLaunchPolicy::posix(
            launcher.clone(),
            PosixLaunchAuthorities::new(
                launcher.clone(),
                sha256_file(&launcher).unwrap(),
                fs::canonicalize(&native_cargo).unwrap(),
                staged.to_path_buf(),
                sha256_file(staged).unwrap(),
                PosixCargoSourceAuthority::Rustup(Box::new(rustup_authority.clone())),
            ),
            candidate_identity("hellrelnative", 61_003),
            vec![std::env::temp_dir()],
        );
        assert!(
            policy.is_err(),
            "same-byte native Cargo must reject an unrelated Rustup proxy authority"
        );
    }

    fn assert_rustup_proxy_requires_authority(cargo: &Path, rustup: &Path, staged: &Path) {
        let launcher = fs::canonicalize("/usr/bin/true").unwrap();
        let policy = CandidateLaunchPolicy::posix(
            launcher.clone(),
            PosixLaunchAuthorities::new(
                launcher.clone(),
                sha256_file(&launcher).unwrap(),
                cargo.to_path_buf(),
                staged.to_path_buf(),
                sha256_file(staged).unwrap(),
                native_cargo_authority(cargo, rustup),
            ),
            candidate_identity("hellrelalias", 61_002),
            vec![std::env::temp_dir()],
        );
        assert!(policy.is_err());
    }

    fn assert_proxy_replacement_is_rejected(
        policy: &CandidateLaunchPolicy,
        invocation: &Path,
        identity: &BoundProgramInvocation,
        cargo: &Path,
        rustup: &Path,
    ) {
        use std::os::unix::fs::PermissionsExt as _;

        fs::remove_file(rustup).unwrap();
        fs::write(rustup, b"multicall executable\n").unwrap();
        fs::set_permissions(rustup, fs::Permissions::from_mode(0o555)).unwrap();
        let mut replaced_proxy = Command::new(invocation);
        assert!(
            policy.wrap(&mut replaced_proxy, Some(identity)).is_err(),
            "same-byte Rustup replacement must fail the bound same-file identity"
        );
        fs::remove_file(rustup).unwrap();
        fs::hard_link(cargo, rustup).unwrap();
    }

    fn posix_release_child_request(
        command: &Command,
    ) -> (BTreeMap<OsString, OsString>, OsString, Vec<OsString>) {
        assert!(command.get_envs().next().is_none());
        let arguments = command.get_args().map(OsString::from).collect::<Vec<_>>();
        assert_eq!(arguments[0], "-n");
        assert_eq!(arguments[1], "-u");
        assert_eq!(arguments[3], "--");
        assert_eq!(arguments[5], POSIX_RELEASE_CHILD_REQUEST_V1);
        let count = arguments[6].to_str().unwrap().parse::<usize>().unwrap();
        let pairs_end = 7 + count * 2;
        let mut environment = BTreeMap::new();
        for pair in arguments[7..pairs_end].chunks_exact(2) {
            assert!(
                environment
                    .insert(pair[0].clone(), pair[1].clone())
                    .is_none()
            );
        }
        (
            environment,
            arguments[pairs_end + 1].clone(),
            arguments[pairs_end + 2..].to_vec(),
        )
    }

    fn assert_rustup_authority_environment(command: &Command, expected_home: &Path) {
        let (environment, _, _) = posix_release_child_request(command);
        assert_eq!(
            environment.get(OsStr::new("RUSTUP_HOME")),
            Some(&expected_home.as_os_str().to_os_string())
        );
        assert_eq!(
            environment.get(OsStr::new("RUSTUP_TOOLCHAIN")),
            Some(&OsString::from("1.97.1-test-x86_64-unknown-linux-gnu"))
        );
        assert_eq!(
            environment
                .get(OsStr::new("PATH"))
                .and_then(|value| std::env::split_paths(value).next()),
            Some(expected_home.join("toolchains/1.97.1-test-x86_64-unknown-linux-gnu/bin"))
        );
    }

    #[test]
    fn posix_wrapper_uses_fixed_preservation_contract_and_trusted_adapter() {
        let launcher = fs::canonicalize("/usr/bin/true").unwrap();
        let adapter = launcher.clone();
        let authority_root = std::env::temp_dir().join(format!(
            "hell-native-cargo-authority-{}-{}",
            std::process::id(),
            NEXT_SANDBOX.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&authority_root).unwrap();
        let standard_rustup = authority_root.join("rustup");
        std::os::unix::fs::symlink("/usr/bin/false", &standard_rustup).unwrap();
        let policy = CandidateLaunchPolicy::posix(
            launcher.clone(),
            PosixLaunchAuthorities::new(
                adapter.clone(),
                sha256_file(&adapter).unwrap(),
                adapter.clone(),
                adapter.clone(),
                sha256_file(&adapter).unwrap(),
                native_cargo_authority(&adapter, &standard_rustup),
            ),
            candidate_identity("hellreltest", 61_001),
            vec![std::env::temp_dir()],
        )
        .unwrap();
        let mut command = Command::new("/usr/bin/true");
        command.env_clear().env("HOME", "/isolated/home");
        policy.wrap(&mut command, None).unwrap();
        assert_eq!(command.get_program(), launcher);
        let arguments = command.get_args().map(OsString::from).collect::<Vec<_>>();
        assert_eq!(arguments[2], "hellreltest");
        assert_eq!(arguments[4], adapter);
        let (environment, program, child_arguments) = posix_release_child_request(&command);
        assert_eq!(
            environment.get(OsStr::new("HOME")),
            Some(&OsString::from("/isolated/home"))
        );
        assert_eq!(program, "/usr/bin/true");
        assert!(child_arguments.is_empty());
    }

    #[test]
    fn posix_git_safe_directory_environment_is_closed_and_complete() {
        for name in ["GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0"] {
            assert!(POSIX_RELEASE_CHILD_ENVIRONMENT_ALLOWLIST.contains(&name));
            assert!(!RELEASE_CHILD_ENVIRONMENT_ALLOWLIST.contains(&name));
        }
        let root = std::env::temp_dir().join(format!(
            "hell-posix-git-safe-directory-{}-{}",
            std::process::id(),
            NEXT_SANDBOX.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let root = fs::canonicalize(root).unwrap();
        let exact = [
            (
                OsString::from("GIT_CONFIG_COUNT"),
                Some(OsString::from("1")),
            ),
            (
                OsString::from("GIT_CONFIG_KEY_0"),
                Some(OsString::from("safe.directory")),
            ),
            (
                OsString::from("GIT_CONFIG_VALUE_0"),
                Some(root.as_os_str().to_owned()),
            ),
        ];
        let encoded = posix_release_child_environment(exact, None, None, None, None).unwrap();
        assert_eq!(
            encoded.get(OsStr::new("GIT_CONFIG_VALUE_0")),
            Some(&root.as_os_str().to_owned())
        );

        let partial = [(
            OsString::from("GIT_CONFIG_COUNT"),
            Some(OsString::from("1")),
        )];
        assert!(posix_release_child_environment(partial, None, None, None, None).is_err());
        let wrong_key = [
            (
                OsString::from("GIT_CONFIG_COUNT"),
                Some(OsString::from("1")),
            ),
            (
                OsString::from("GIT_CONFIG_KEY_0"),
                Some(OsString::from("core.hooksPath")),
            ),
            (
                OsString::from("GIT_CONFIG_VALUE_0"),
                Some(root.as_os_str().to_owned()),
            ),
        ];
        assert!(posix_release_child_environment(wrong_key, None, None, None, None).is_err());
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn posix_adapter_identity_rejects_permissions_path_and_digest_substitution() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let root = std::env::temp_dir().join(format!(
            "hell-posix-adapter-identity-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let adapter = root.join("hell-ci");
        let alias = root.join("alias");
        let substitution = root.join("other");
        fs::write(&adapter, b"trusted-adapter\n").unwrap();
        fs::write(&substitution, b"other-adapter\n").unwrap();
        fs::set_permissions(&adapter, fs::Permissions::from_mode(0o555)).unwrap();
        fs::set_permissions(&substitution, fs::Permissions::from_mode(0o555)).unwrap();
        symlink(&adapter, &alias).unwrap();
        let canonical = fs::canonicalize(&adapter).unwrap();
        let other = fs::canonicalize(&substitution).unwrap();
        let digest = sha256_file(&canonical).unwrap();
        let mut identity = posix_adapter_identity(&canonical).unwrap();
        verify_posix_adapter_identity(&canonical, &canonical, digest, &identity).unwrap();
        assert!(verify_posix_adapter_identity(&alias, &canonical, digest, &identity).is_err());
        assert!(verify_posix_adapter_identity(&canonical, &other, digest, &identity).is_err());
        assert!(
            verify_posix_adapter_identity(&canonical, &canonical, Digest::default(), &identity)
                .is_err()
        );
        let same_bytes = root.join("same-bytes");
        fs::write(&same_bytes, b"trusted-adapter\n").unwrap();
        fs::set_permissions(&same_bytes, fs::Permissions::from_mode(0o555)).unwrap();
        fs::rename(&same_bytes, &adapter).unwrap();
        assert!(verify_posix_adapter_identity(&canonical, &canonical, digest, &identity).is_err());
        identity = posix_adapter_identity(&canonical).unwrap();
        fs::set_permissions(&adapter, fs::Permissions::from_mode(0o775)).unwrap();
        assert!(verify_posix_adapter_identity(&canonical, &canonical, digest, &identity).is_err());
        fs::set_permissions(&adapter, fs::Permissions::from_mode(0o550)).unwrap();
        assert!(verify_posix_adapter_identity(&canonical, &canonical, digest, &identity).is_err());
        fs::set_permissions(&adapter, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(&adapter, b"mutated-adapter\n").unwrap();
        assert!(verify_posix_adapter_identity(&canonical, &canonical, digest, &identity).is_err());
        fs::write(&adapter, b"trusted-adapter\n").unwrap();
        fs::set_permissions(&adapter, fs::Permissions::from_mode(0o555)).unwrap();
        let parent_identity = posix_adapter_identity(&canonical).unwrap();
        let replaced_parent = root.with_extension("replaced-parent");
        let _ = fs::remove_dir_all(&replaced_parent);
        fs::rename(&root, &replaced_parent).unwrap();
        fs::create_dir(&root).unwrap();
        fs::write(&adapter, b"trusted-adapter\n").unwrap();
        fs::set_permissions(&adapter, fs::Permissions::from_mode(0o555)).unwrap();
        assert!(
            verify_posix_adapter_identity(&canonical, &canonical, digest, &parent_identity)
                .is_err(),
            "same-path same-byte replacement of the adapter parent must fail closed"
        );
        fs::set_permissions(&root, fs::Permissions::from_mode(0o555)).unwrap();
        assert!(fs::remove_file(&adapter).is_err());
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(replaced_parent).unwrap();
    }

    #[test]
    fn windows_launcher_identity_rejects_omission_path_and_digest_substitution() {
        let root = std::env::temp_dir().join(format!(
            "hell-windows-launcher-identity-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let launcher = root.join("hell-ci.exe");
        let adapter = root.join("hell-test-helper.exe");
        let substitution = root.join("other.exe");
        fs::write(&launcher, b"trusted-launcher\n").unwrap();
        fs::write(&adapter, b"trusted-adapter\n").unwrap();
        fs::write(&substitution, b"other-launcher\n").unwrap();
        let canonical = fs::canonicalize(&launcher).unwrap();
        let canonical_adapter = fs::canonicalize(&adapter).unwrap();
        let other = fs::canonicalize(&substitution).unwrap();
        let digest = sha256_file(&canonical).unwrap();
        let adapter_digest = sha256_file(&canonical_adapter).unwrap();
        verify_windows_launcher_identity(&launcher, &canonical, digest).unwrap();
        assert!(verify_windows_launcher_identity(&launcher, &other, digest).is_err());
        assert!(
            verify_windows_launcher_identity(&launcher, &canonical, Digest::default()).is_err()
        );
        fs::write(&launcher, b"mutated-launcher\n").unwrap();
        assert!(verify_windows_launcher_identity(&launcher, &canonical, digest).is_err());
        verify_windows_restricted_adapter_identity(&adapter, &canonical_adapter, adapter_digest)
            .unwrap();
        assert!(
            verify_windows_restricted_adapter_identity(&adapter, &other, adapter_digest).is_err()
        );
        assert!(
            verify_windows_restricted_adapter_identity(
                &adapter,
                &canonical_adapter,
                Digest::default()
            )
            .is_err()
        );
        assert!(
            verify_windows_restricted_adapter_identity(&substitution, &other, adapter_digest)
                .is_err()
        );
        fs::write(&adapter, b"mutated-adapter\n").unwrap();
        assert!(
            verify_windows_restricted_adapter_identity(
                &adapter,
                &canonical_adapter,
                adapter_digest
            )
            .is_err()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn windows_restricted_request_binds_exact_adapter_path_digest_and_target_argv() {
        let adapter = Path::new("/trusted/hell-test-helper.exe");
        let digest = Digest([0x5a; 32]);
        let target = vec![
            OsString::from("C:\\trusted\\cargo.exe"),
            OsString::from("test"),
        ];
        assert_eq!(
            windows_restricted_launch_request(adapter, digest, &target),
            vec![
                adapter.as_os_str().to_owned(),
                OsString::from(digest.hex()),
                target[0].clone(),
                target[1].clone(),
            ]
        );
    }

    fn assert_rustup_tree_substitution_rejected(
        policy: &CandidateLaunchPolicy,
        invocation: &Path,
        identity: &BoundProgramInvocation,
        rustup_home: &Path,
    ) {
        let rustup_bin = rustup_home
            .join("toolchains")
            .join("1.97.1-test-x86_64-unknown-linux-gnu")
            .join("bin");
        let added_entry = rustup_bin.join("added-after-bind");
        fs::write(&added_entry, b"inventory substitution\n").unwrap();
        let mut expanded_rustup = Command::new(invocation);
        assert!(
            policy.wrap(&mut expanded_rustup, Some(identity)).is_err(),
            "an added Rustup entry must fail the closed inventory before spawn"
        );
        fs::remove_file(&added_entry).unwrap();
        let hard_link = rustup_bin.join("hard-linked-rustc");
        fs::hard_link(rustup_bin.join("rustc"), &hard_link).unwrap();
        let mut hard_linked_rustup = Command::new(invocation);
        assert!(
            policy
                .wrap(&mut hard_linked_rustup, Some(identity))
                .is_err(),
            "a multiply-linked Rustup file must fail before spawn"
        );
        fs::remove_file(&hard_link).unwrap();
    }

    fn assert_cargo_source_classification(
        root: &Path,
        cargo: &Path,
        staged_cargo: &Path,
        rustup_authority: &PosixRustupAuthority,
        unrelated_rustc: &Path,
    ) {
        assert_rustup_proxy_requires_authority(
            cargo,
            &fs::canonicalize(root).unwrap().join("rustup"),
            staged_cargo,
        );
        assert_same_bytes_native_cargo_is_not_a_rustup_proxy(root, staged_cargo, rustup_authority);
        let mut wrong_mapping = rustup_authority.clone();
        wrong_mapping.compiler_mapping.staged = fs::canonicalize(unrelated_rustc).unwrap();
        wrong_mapping.compiler_mapping.staged_sha256 = sha256_file(unrelated_rustc).unwrap();
        let launcher = fs::canonicalize("/usr/bin/true").unwrap();
        assert!(
            CandidateLaunchPolicy::posix(
                launcher.clone(),
                PosixLaunchAuthorities::new(
                    launcher.clone(),
                    sha256_file(&launcher).unwrap(),
                    cargo.to_path_buf(),
                    staged_cargo.to_path_buf(),
                    sha256_file(staged_cargo).unwrap(),
                    PosixCargoSourceAuthority::Rustup(Box::new(wrong_mapping)),
                ),
                candidate_identity("hellrelwrongmap", 61_004),
                vec![std::env::temp_dir()],
            )
            .is_err(),
            "a same-byte compiler outside the selected staged toolchain must be rejected"
        );
    }

    fn assert_bound_rustc_mapping_and_substitutions(
        policy: &CandidateLaunchPolicy,
        rustc_invocation: &Path,
        rustc_identity: &BoundProgramInvocation,
        unrelated_rustc: &Path,
        source_rustc: &Path,
        staged_rustc: &Path,
    ) {
        use std::os::unix::fs::PermissionsExt as _;

        let mut rustc_command = Command::new(rustc_invocation);
        rustc_command.args(["--version", "--verbose"]);
        policy
            .wrap(&mut rustc_command, Some(rustc_identity))
            .unwrap();
        let (environment, program, arguments) = posix_release_child_request(&rustc_command);
        assert_eq!(program, staged_rustc);
        assert_eq!(arguments, ["--version", "--verbose"]);
        assert!(!environment.contains_key(OsStr::new("RUSTUP_HOME")));
        assert!(
            policy
                .cargo_authority
                .rustup()
                .unwrap()
                .request_is_bound_rustc(OsStr::new("rustc"), unrelated_rustc)
                .is_err(),
            "a changed standard PATH rustc identity must fail instead of falling back"
        );
        let unrelated_canonical = fs::canonicalize(unrelated_rustc).unwrap();
        let unrelated_identity =
            BoundProgramInvocation::new(unrelated_canonical.clone(), unrelated_canonical.clone())
                .unwrap();
        let mut unrelated_command = Command::new(&unrelated_canonical);
        assert!(
            policy
                .wrap(&mut unrelated_command, Some(&unrelated_identity))
                .is_err(),
            "an absolute rustc path outside the exact standard authority must fail"
        );

        for (path, replacement, message) in [
            (
                staged_rustc,
                b"substituted staged compiler\n".as_slice(),
                "a substituted staged compiler must fail before spawn",
            ),
            (
                source_rustc,
                b"substituted source compiler\n".as_slice(),
                "a substituted source compiler must fail before spawn",
            ),
        ] {
            let original = fs::read(path).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
            fs::write(path, replacement).unwrap();
            let mut substituted = Command::new(rustc_invocation);
            assert!(
                policy.wrap(&mut substituted, Some(rustc_identity)).is_err(),
                "{message}"
            );
            fs::write(path, original).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o555)).unwrap();
        }
    }

    #[cfg(unix)]
    fn assert_selected_toolchain_rustc_authority(
        cargo: &Path,
        staged_cargo: &Path,
        rustup_authority: &PosixRustupAuthority,
        unrelated_rustc: &Path,
    ) {
        use std::os::unix::fs::MetadataExt as _;

        let source_rustc = rustup_authority.compiler_mapping.source.clone();
        let staged_rustc = rustup_authority.compiler_mapping.staged.clone();
        let source_metadata = fs::metadata(&source_rustc).unwrap();
        let source_identity = PosixStandardExecutableIdentity::new(
            source_rustc.clone(),
            source_rustc.clone(),
            source_metadata.dev(),
            source_metadata.ino(),
        );
        let launcher = fs::canonicalize("/usr/bin/true").unwrap();
        let build_policy = |authority: PosixRustupAuthority, account: &str, uid| {
            CandidateLaunchPolicy::posix(
                launcher.clone(),
                PosixLaunchAuthorities::new(
                    launcher.clone(),
                    sha256_file(&launcher).unwrap(),
                    cargo.to_path_buf(),
                    staged_cargo.to_path_buf(),
                    sha256_file(staged_cargo).unwrap(),
                    PosixCargoSourceAuthority::Rustup(Box::new(authority)),
                ),
                candidate_identity(account, uid),
                vec![std::env::temp_dir()],
            )
        };

        let mut selected = rustup_authority.clone();
        selected.rustc_authority = PosixRustcAuthority::SelectedToolchain(source_identity.clone());
        let selected_policy = build_policy(selected, "hellrelselected", 61_005).unwrap();
        let selected_invocation = BoundProgramInvocation::new(
            source_rustc.clone(),
            fs::canonicalize(&source_rustc).unwrap(),
        )
        .unwrap();
        let mut command = Command::new(&source_rustc);
        command.args(["--version", "--verbose"]);
        selected_policy
            .wrap(&mut command, Some(&selected_invocation))
            .unwrap();
        let (environment, program, arguments) = posix_release_child_request(&command);
        assert_eq!(program, staged_rustc);
        assert_eq!(arguments, ["--version", "--verbose"]);
        assert!(!environment.contains_key(OsStr::new("RUSTUP_HOME")));

        let unrelated_metadata = fs::metadata(unrelated_rustc).unwrap();
        let unrelated_identity = PosixStandardExecutableIdentity::new(
            unrelated_rustc.to_path_buf(),
            fs::canonicalize(unrelated_rustc).unwrap(),
            unrelated_metadata.dev(),
            unrelated_metadata.ino(),
        );
        let mut forged_selected = rustup_authority.clone();
        forged_selected.rustc_authority =
            PosixRustcAuthority::SelectedToolchain(unrelated_identity);
        assert!(
            build_policy(forged_selected, "hellrelforgedselected", 61_006).is_err(),
            "a same-byte compiler outside the selected toolchain must not mint authority"
        );

        let mut forged_proxy = rustup_authority.clone();
        forged_proxy.rustc_authority = PosixRustcAuthority::RustupProxy(source_identity);
        assert!(
            build_policy(forged_proxy, "hellrelforgedproxy", 61_007).is_err(),
            "the selected compiler must not be mislabeled as the Rustup proxy"
        );
    }

    fn assert_bound_cargo_substitutions(
        policy: &CandidateLaunchPolicy,
        invocation: &Path,
        identity: &BoundProgramInvocation,
        alias: &Path,
        target: &Path,
        staged: &Path,
        rustup_settings: &Path,
    ) {
        use std::os::unix::fs::PermissionsExt as _;

        assert!(
            resolve_parent_program_for_launch(target.as_os_str(), Some(identity)).is_err(),
            "a bound canonical target must not replace its logical alias"
        );
        assert_rustup_tree_substitution_rejected(
            policy,
            invocation,
            identity,
            rustup_settings.parent().unwrap(),
        );
        fs::set_permissions(rustup_settings, fs::Permissions::from_mode(0o666)).unwrap();
        let mut substituted_rustup = Command::new(invocation);
        assert!(
            policy
                .wrap(&mut substituted_rustup, Some(identity))
                .is_err(),
            "a writable or substituted Rustup authority must fail closed before spawn"
        );
        fs::set_permissions(rustup_settings, fs::Permissions::from_mode(0o644)).unwrap();
        assert_proxy_replacement_is_rejected(policy, invocation, identity, alias, target);
        fs::set_permissions(staged, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(staged, b"staged substitution\n").unwrap();
        let mut substituted_staging = Command::new(invocation);
        assert!(
            policy
                .wrap(&mut substituted_staging, Some(identity))
                .is_err(),
            "a staged Cargo file identity or digest substitution must fail closed"
        );
        fs::remove_file(alias).unwrap();
        fs::write(alias, b"multicall executable\n").unwrap();
        fs::set_permissions(alias, fs::Permissions::from_mode(0o555)).unwrap();
        assert!(
            resolve_parent_program_for_launch(invocation.as_os_str(), Some(identity)).is_err(),
            "a same-byte replacement at the bound alias path must fail by file identity"
        );
    }

    #[test]
    fn bound_multicall_program_uses_only_its_verified_staged_alias() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = PathBuf::from("/tmp").join(format!(
            "hell-bound-multicall-program-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let target = root.join("rustup");
        let alias = root.join("cargo");
        let staged = root.join("staged-cargo");
        fs::write(&target, b"multicall executable\n").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o555)).unwrap();
        fs::hard_link(&target, &alias).unwrap();
        fs::write(&staged, b"staged multicall executable\n").unwrap();
        fs::set_permissions(&staged, fs::Permissions::from_mode(0o555)).unwrap();
        let invocation = fs::canonicalize(&root).unwrap().join("cargo");
        let canonical_target = fs::canonicalize(&alias).unwrap();
        let canonical_staged = fs::canonicalize(&staged).unwrap();
        let (rustup_authority, rustup_settings) = rustup_authority_fixture(&root);
        let expected_rustup_home = fs::canonicalize(root.join("rustup-home")).unwrap();
        let source_rustc = rustup_authority.compiler_mapping.source.clone();
        let staged_rustc = rustup_authority.compiler_mapping.staged.clone();
        let rustc_invocation = fs::canonicalize(&root).unwrap().join("rustc");
        let rustc_identity = BoundProgramInvocation::new(
            rustc_invocation.clone(),
            fs::canonicalize(&rustc_invocation).unwrap(),
        )
        .unwrap();
        let identity =
            BoundProgramInvocation::new(invocation.clone(), canonical_target.clone()).unwrap();
        let unrelated_rustc = root.join("unrelated").join("rustc");
        fs::create_dir(unrelated_rustc.parent().unwrap()).unwrap();
        fs::write(&unrelated_rustc, fs::read(&staged_rustc).unwrap()).unwrap();
        fs::set_permissions(&unrelated_rustc, fs::Permissions::from_mode(0o555)).unwrap();
        assert_eq!(
            resolve_parent_program_for_launch(invocation.as_os_str(), Some(&identity)).unwrap(),
            invocation
        );
        assert_eq!(
            resolve_parent_program_for_launch(alias.as_os_str(), None).unwrap(),
            canonical_target
        );
        assert_cargo_source_classification(
            &root,
            &canonical_target,
            &canonical_staged,
            &rustup_authority,
            &unrelated_rustc,
        );
        assert_selected_toolchain_rustc_authority(
            &canonical_target,
            &canonical_staged,
            &rustup_authority,
            &unrelated_rustc,
        );
        let policy = CandidateLaunchPolicy::posix(
            fs::canonicalize("/usr/bin/true").unwrap(),
            PosixLaunchAuthorities::new(
                fs::canonicalize("/usr/bin/true").unwrap(),
                sha256_file(&fs::canonicalize("/usr/bin/true").unwrap()).unwrap(),
                canonical_target.clone(),
                canonical_staged.clone(),
                sha256_file(&canonical_staged).unwrap(),
                PosixCargoSourceAuthority::Rustup(Box::new(rustup_authority)),
            ),
            candidate_identity("hellrelalias", 61_002),
            vec![std::env::temp_dir()],
        )
        .unwrap();
        let mut command = Command::new(&invocation);
        command
            .arg("--version")
            .env("RUSTUP_HOME", "/candidate-controlled")
            .env("RUSTUP_TOOLCHAIN", "candidate-controlled");
        policy.wrap(&mut command, Some(&identity)).unwrap();
        let (_, program, child_arguments) = posix_release_child_request(&command);
        assert_eq!(program, canonical_staged);
        assert_eq!(child_arguments, [OsString::from("--version")]);
        assert_rustup_authority_environment(&command, &expected_rustup_home);
        assert_bound_rustc_mapping_and_substitutions(
            &policy,
            &rustc_invocation,
            &rustc_identity,
            &unrelated_rustc,
            &source_rustc,
            &staged_rustc,
        );
        assert_bound_cargo_substitutions(
            &policy,
            &invocation,
            &identity,
            &alias,
            &target,
            &staged,
            &rustup_settings,
        );
        fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(all(test, unix))]
mod executable_invocation_tests {
    use super::*;

    fn identity(path: PathBuf) -> ExecutableIdentity {
        ExecutableIdentity {
            sha256: sha256_file(&path).unwrap(),
            path,
            reported_version: "fixture-version".into(),
            build_info: None,
            role: ExecutableRole::Oracle,
            assurance_epoch_sha256: Some(sha256_bytes(b"fixture-epoch")),
            acquisition_receipt_id: Some("fixture-receipt".into()),
            acquisition_receipt_sha256: Some(sha256_bytes(b"fixture-receipt")),
            acquisition_attestation_sha256: Some(sha256_bytes(b"fixture-attestation")),
        }
    }

    #[test]
    fn exact_execution_alias_binds_name_file_identity_and_source_provenance() {
        let root =
            std::env::temp_dir().join(format!("hell-executable-invocation-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let current = std::env::current_exe().unwrap().canonicalize().unwrap();
        let source_path = root.join("linux-release-oracle");
        let execution_path = root.join(format!("hell{}", std::env::consts::EXE_SUFFIX));
        fs::hard_link(&current, &source_path).unwrap();
        fs::hard_link(&source_path, &execution_path).unwrap();
        let source = identity(source_path.canonicalize().unwrap());
        let mut execution = source.clone();
        execution.path = execution_path.canonicalize().unwrap();
        let authority = ExecutableInvocationAuthority::exact_hell(&source, &execution).unwrap();
        assert_eq!(authority.source(), &source);
        assert_eq!(authority.execution(), &execution);
        let guard = ExecutableIntegrityGuard::new(&authority).unwrap();
        assert_eq!(guard.execution_identity(), &execution);
        guard.require_unchanged().unwrap();

        let wrong_name_path = root.join("other-oracle");
        fs::hard_link(&source.path, &wrong_name_path).unwrap();
        let mut wrong_name = source.clone();
        wrong_name.path = wrong_name_path.canonicalize().unwrap();
        assert!(ExecutableInvocationAuthority::exact_hell(&source, &wrong_name).is_err());

        let copied_root = root.join("copied");
        fs::create_dir(&copied_root).unwrap();
        let copied_path = copied_root.join(format!("hell{}", std::env::consts::EXE_SUFFIX));
        fs::copy(&source.path, &copied_path).unwrap();
        let mut copied = source.clone();
        copied.path = copied_path.canonicalize().unwrap();
        assert!(ExecutableInvocationAuthority::exact_hell(&source, &copied).is_err());

        let mut forged_provenance = execution.clone();
        forged_provenance.acquisition_receipt_sha256 = Some(sha256_bytes(b"forged"));
        assert!(ExecutableInvocationAuthority::exact_hell(&source, &forged_provenance).is_err());

        fs::remove_file(&execution.path).unwrap();
        fs::hard_link(&copied.path, &execution.path).unwrap();
        assert!(guard.require_unchanged().is_err());
        fs::remove_dir_all(root).unwrap();
    }
}

/// Computes the SHA-256 digest of in-memory evidence bytes.
#[must_use]
pub fn sha256_bytes(bytes: &[u8]) -> Digest {
    let mut digest = Sha256::new();
    digest.update(bytes);
    digest.finish()
}

/// Hashes an exact raw stdout/stderr pair with domain separation and lengths.
#[must_use]
pub fn raw_presentation_sha256(stdout: &[u8], stderr: &[u8]) -> Digest {
    let mut digest = Sha256::new();
    digest.update(b"hell-runtime-presentation-v1\0");
    digest.update(
        &u64::try_from(stdout.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    digest.update(stdout);
    digest.update(
        &u64::try_from(stderr.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    digest.update(stderr);
    digest.finish()
}

/// Renders reviewed Unicode scalar values with Haskell `Show [Char]` syntax.
///
/// This is kept in the testkit rather than shared with the candidate renderer
/// so exact corpus presentation remains independently pinned.
///
/// # Errors
///
/// Returns an error if any supplied code point is not a Unicode scalar value.
pub fn reviewed_haskell_string_literal(code_points: &[u32]) -> Result<String, String> {
    const CONTROL_NAMES: [&str; 32] = [
        "NUL", "SOH", "STX", "ETX", "EOT", "ENQ", "ACK", "BEL", "BS", "HT", "LF", "VT", "FF", "CR",
        "SO", "SI", "DLE", "DC1", "DC2", "DC3", "DC4", "NAK", "SYN", "ETB", "CAN", "EM", "SUB",
        "ESC", "FS", "GS", "RS", "US",
    ];

    let characters = code_points
        .iter()
        .copied()
        .map(|code_point| {
            char::from_u32(code_point)
                .ok_or_else(|| format!("invalid reviewed Character code point {code_point}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut rendered = String::from("\"");
    for (index, character) in characters.iter().copied().enumerate() {
        let next = characters.get(index + 1).copied();
        if character == '"' {
            rendered.push_str("\\\"");
        } else if character > '\u{7f}' {
            rendered.push('\\');
            rendered.push_str(&u32::from(character).to_string());
            if next.is_some_and(|value| value.is_ascii_digit()) {
                rendered.push_str("\\&");
            }
        } else if character == '\u{7f}' {
            rendered.push_str("\\DEL");
        } else if character == '\\' {
            rendered.push_str("\\\\");
        } else if character >= ' ' {
            rendered.push(character);
        } else {
            match character {
                '\u{7}' => rendered.push_str("\\a"),
                '\u{8}' => rendered.push_str("\\b"),
                '\u{c}' => rendered.push_str("\\f"),
                '\n' => rendered.push_str("\\n"),
                '\r' => rendered.push_str("\\r"),
                '\t' => rendered.push_str("\\t"),
                '\u{b}' => rendered.push_str("\\v"),
                '\u{e}' => {
                    rendered.push_str("\\SO");
                    if next == Some('H') {
                        rendered.push_str("\\&");
                    }
                }
                value => {
                    rendered.push('\\');
                    rendered.push_str(CONTROL_NAMES[u32::from(value) as usize]);
                }
            }
        }
    }
    rendered.push('"');
    Ok(rendered)
}

/// Versioned, deliberately narrow normalization used only as a retained
/// presentation shadow. It canonicalizes CRLF and lone CR to LF while
/// preserving every other UTF-8 byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PresentationShadowNormalizerId {
    LineEndingsV1,
}

impl PresentationShadowNormalizerId {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LineEndingsV1 => "presentation-line-endings-v1",
        }
    }
}

/// Hashes separately framed normalized stdout/stderr presentation shadows.
///
/// # Errors
///
/// Returns an error when either retained stream is not valid UTF-8.
pub fn normalized_presentation_shadow_sha256(
    normalizer: PresentationShadowNormalizerId,
    stdout: &[u8],
    stderr: &[u8],
) -> Result<Digest, &'static str> {
    let normalize = |input: &[u8]| {
        std::str::from_utf8(input).map_err(|_| "presentation shadow input is not UTF-8")?;
        let mut output = Vec::with_capacity(input.len());
        let mut index = 0;
        while index < input.len() {
            if input[index] == b'\r' {
                output.push(b'\n');
                index += 1;
                if input.get(index) == Some(&b'\n') {
                    index += 1;
                }
            } else {
                output.push(input[index]);
                index += 1;
            }
        }
        Ok::<_, &'static str>(output)
    };
    let stdout = normalize(stdout)?;
    let stderr = normalize(stderr)?;
    let mut digest = Sha256::new();
    match normalizer {
        PresentationShadowNormalizerId::LineEndingsV1 => {
            digest.update(b"hell-runtime-presentation-shadow-v1\0");
        }
    }
    digest.update(
        &u64::try_from(stdout.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    digest.update(&stdout);
    digest.update(
        &u64::try_from(stderr.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    digest.update(&stderr);
    Ok(digest.finish())
}

/// Computes the SHA-256 digest of a file without loading it into memory.
///
/// # Errors
///
/// Returns an I/O error when the file cannot be opened or read.
pub fn sha256_file(path: &Path) -> std::io::Result<Digest> {
    let mut file = fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            return Ok(digest.finish());
        }
        digest.update(&buffer[..read]);
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OutputNormalization {
    pub stderr_replacements: Vec<(Vec<u8>, Vec<u8>)>,
    pub normalize_path_separators: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceTarget {
    pub builtin: Arc<str>,
    pub dimension: CompatibilityDimension,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ObligationId(pub Arc<str>);

/// One canonical preorder premise node in a recursively resolved class
/// instance. The enclosing target supplies the root class and target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstancePremiseEvidence {
    pub target: Arc<str>,
    pub premise_count: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CausalSignal {
    ParsedBuiltin,
    ResolvedBuiltin,
    SpecializedBuiltin,
    RuntimeAdapter,
    RuntimeAdapterAndForceTrace,
    ForceTrace,
    EffectEvent,
    TaskAndCancellation,
    PresentationField,
    ResourceLifecycle,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceTargetV2 {
    pub builtin: Arc<str>,
    /// Exact closed-world class-instance target selected for this adapter.
    /// Constrained targets without this binding remain valid retained evidence,
    /// but cannot contribute runtime compatibility coverage.
    pub expected_instance_target: Option<Arc<str>>,
    pub expected_instance_premises: Vec<InstancePremiseEvidence>,
    pub dimension: CompatibilityDimension,
    pub obligations: Vec<ObligationId>,
    pub causal_signal: CausalSignal,
    pub platforms: Vec<ClaimPlatform>,
    pub boundary_classes: Vec<Arc<str>>,
    pub interaction_obligations: Vec<Arc<str>>,
    pub expected_typed_result_sha256: Option<Digest>,
    pub expected_raw_presentation_sha256: Option<Digest>,
    pub expected_presentation_shadow_normalizer: Option<PresentationShadowNormalizerId>,
    pub expected_normalized_presentation_sha256: Option<Digest>,
    pub expected_lazy_argument_exit_sha256: Option<Digest>,
    /// Exact pre-adapter WHNF demand failure, including argument and error code.
    pub expected_whnf_argument_failure_sha256: Option<Digest>,
    /// Exact ordered Alternative.many nonproductive boundary lifecycle.
    pub expected_nonproductive_trace_sha256: Option<Digest>,
    pub expected_single_task_lifecycle_sha256: Option<Digest>,
    pub expected_task_trace_sha256: Option<Digest>,
    pub expected_process_status_sha256: Option<Digest>,
    pub expected_single_effect_lifecycle_sha256: Option<Digest>,
    /// Exact ordered direct `Ord.lt`/`Ord.gt` protocol for one constrained
    /// Map/Set target, including an explicit domain-separated empty trace.
    pub expected_comparator_trace_sha256: Option<Digest>,
}

/// One independently reviewed direct comparator observation owned by a
/// constrained collection adapter invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComparatorTraceContract {
    pub parent_invocation: u64,
    pub direct_child_ordinal: u64,
    pub comparator_ordinal: u64,
    pub comparator: Arc<str>,
    pub canonical_left: Arc<str>,
    pub canonical_right: Arc<str>,
    pub result: bool,
    pub outcome: Arc<str>,
}

/// Exact ordered callback contract reviewed with one committed case.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallbackContract {
    pub builtin: Arc<str>,
    pub invocations: Vec<CallbackInvocationContract>,
}

/// One source-bound callback invocation and its canonical typed arguments/result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallbackInvocationContract {
    pub callback_argument: u16,
    pub branch: Arc<str>,
    pub canonical_argument_sha256: Vec<Digest>,
    pub outcome: Arc<str>,
    pub canonical_result_sha256: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoverageEvent {
    ParsedBuiltin(BuiltinId),
    ResolvedBuiltin(BuiltinId),
    SpecializedBuiltin(BuiltinId),
    EnteredAdapter(BuiltinId),
    ForcedArgument(BuiltinId, u16),
    ExecutedEffect(BuiltinId, Arc<str>),
    TaskEvent(BuiltinId, Arc<str>),
    AcquiredResource(BuiltinId, Arc<str>),
    PresentedField(BuiltinId, Arc<str>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LogicalTraceEvent {
    EnterThunk {
        label: Arc<str>,
    },
    ForceListSpine {
        label: Arc<str>,
        index: u64,
    },
    InvokeCallback {
        builtin: BuiltinId,
        invocation: u64,
    },
    HostEffect {
        builtin: BuiltinId,
        owner_task: Option<u64>,
        sequence: u64,
        parent_sequence: Option<u64>,
        effect: Arc<str>,
    },
    TaskEvent {
        task: u64,
        builtin: BuiltinId,
        event: Arc<str>,
    },
    ResourceEvent {
        resource: u64,
        builtin: BuiltinId,
        owner_task: Option<u64>,
        event: ResourceEventKind,
    },
    CompleteThunk {
        label: Arc<str>,
        outcome: Arc<str>,
        error_code: Option<Arc<str>>,
    },
    ForceBuiltinArgument {
        builtin: BuiltinId,
        argument: u16,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceEventKind {
    Acquire,
    Transfer,
    Cancel,
    Close,
    CleanupFailure,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SemanticObservation {
    pub typed_result_sha256: Option<Digest>,
    pub typed_result_builtin: Option<BuiltinId>,
    pub typed_result_canonical: Option<Arc<str>>,
    pub causal_event_order: Vec<(u64, Arc<str>)>,
    pub force_trace: Vec<LogicalTraceEvent>,
    pub effect_trace: Vec<LogicalTraceEvent>,
    pub task_trace: Vec<LogicalTraceEvent>,
    pub resource_trace: Vec<LogicalTraceEvent>,
    pub obligation_trace: Vec<ObligationTraceEvent>,
    pub coverage: Vec<CoverageEvent>,
}

/// Target-scoped evidence emitted at an actual native adapter boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObligationTraceEvent {
    pub builtin: BuiltinId,
    pub instance_target: Option<Arc<str>>,
    pub instance_premises: Vec<InstancePremiseEvidence>,
    pub owner_task: Option<u64>,
    pub sequence: u64,
    pub parent_sequence: Option<u64>,
    pub outcome: Arc<str>,
    pub nested_adapters: u64,
    pub materialized_before: u64,
    pub materialized_after: u64,
    pub callbacks: Vec<CallbackTraceEvent>,
    pub comparators: Vec<ComparatorTraceEvent>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComparatorTraceEvent {
    pub invocation: u64,
    pub direct_child_ordinal: u64,
    pub comparator: BuiltinId,
    pub canonical_left: Arc<str>,
    pub canonical_right: Arc<str>,
    pub outcome: Arc<str>,
    pub canonical_result: Arc<str>,
}

/// One exact callback invocation causally owned by a target adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallbackTraceEvent {
    pub invocation: u64,
    pub callback_argument: u16,
    pub branch: Arc<str>,
    pub canonical_arguments: Vec<Arc<str>>,
    pub outcome: Arc<str>,
    pub canonical_result: Arc<str>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NormalizerAuditRecord {
    pub normalizer: NormalizerId,
    pub implementation_sha256: Digest,
    pub input_sha256: Digest,
    pub output_sha256: Digest,
    pub changed_paths: Vec<Arc<str>>,
    pub protected_fields_unchanged: bool,
    pub idempotent: bool,
    pub removed_byte_count: u64,
    pub mutation_suite_passed: bool,
}

/// Typed input for exercising a retained observation through a production normalizer.
#[derive(Clone, Copy, Debug)]
pub struct RetainedNormalizerInput<'a> {
    pub normalizer: NormalizerId,
    pub observation: &'a [u8],
    pub executable: &'a Path,
    pub sandbox: &'a Path,
    pub script: &'a Path,
}

/// Consecutive production-normalizer outputs used to certify idempotence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NormalizerPasses {
    pub first_pass: Vec<u8>,
    pub second_pass: Vec<u8>,
}

impl EvidenceTarget {
    #[must_use]
    pub fn new(builtin: impl Into<Arc<str>>, dimension: CompatibilityDimension) -> Self {
        Self {
            builtin: builtin.into(),
            dimension,
        }
    }
}

impl EvidenceTargetV2 {
    #[must_use]
    pub fn new(
        builtin: impl Into<Arc<str>>,
        dimension: CompatibilityDimension,
        obligations: Vec<ObligationId>,
        causal_signal: CausalSignal,
        platforms: Vec<ClaimPlatform>,
    ) -> Self {
        Self {
            builtin: builtin.into(),
            expected_instance_target: None,
            expected_instance_premises: Vec::new(),
            dimension,
            obligations,
            causal_signal,
            platforms,
            boundary_classes: Vec::new(),
            interaction_obligations: Vec::new(),
            expected_typed_result_sha256: None,
            expected_raw_presentation_sha256: None,
            expected_presentation_shadow_normalizer: None,
            expected_normalized_presentation_sha256: None,
            expected_lazy_argument_exit_sha256: None,
            expected_whnf_argument_failure_sha256: None,
            expected_nonproductive_trace_sha256: None,
            expected_single_task_lifecycle_sha256: None,
            expected_task_trace_sha256: None,
            expected_process_status_sha256: None,
            expected_single_effect_lifecycle_sha256: None,
            expected_comparator_trace_sha256: None,
        }
    }

    /// Attaches exact runtime boundary and high-risk interaction identities
    /// exercised by this case. Empty lists make no such coverage claim.
    #[must_use]
    pub fn with_runtime_scope(
        mut self,
        boundary_classes: impl IntoIterator<Item = impl Into<Arc<str>>>,
        interaction_obligations: impl IntoIterator<Item = impl Into<Arc<str>>>,
    ) -> Self {
        self.boundary_classes = boundary_classes.into_iter().map(Into::into).collect();
        self.interaction_obligations = interaction_obligations
            .into_iter()
            .map(Into::into)
            .collect();
        self
    }

    /// Binds a constrained runtime target to one exact registry instance.
    #[must_use]
    pub fn with_expected_instance_target(mut self, target: impl Into<Arc<str>>) -> Self {
        self.expected_instance_target = Some(target.into());
        self
    }

    /// Binds the exact preorder recursive premise evidence selected for the
    /// target's closed class-instance head.
    #[must_use]
    pub fn with_expected_instance_premises(
        mut self,
        premises: impl IntoIterator<Item = InstancePremiseEvidence>,
    ) -> Self {
        self.expected_instance_premises = premises.into_iter().collect();
        self
    }

    /// Binds a boundary case to one exact canonical target result.
    #[must_use]
    pub fn with_expected_typed_result(mut self, canonical: &str) -> Self {
        self.expected_typed_result_sha256 = Some(sha256_bytes(canonical.as_bytes()));
        self
    }

    /// Binds a presentation target to exact raw stdout and stderr bytes.
    #[must_use]
    pub fn with_expected_raw_presentation(mut self, stdout: &[u8], stderr: &[u8]) -> Self {
        self.expected_raw_presentation_sha256 = Some(raw_presentation_sha256(stdout, stderr));
        self
    }

    /// Binds the versioned normalized shadow independently of exact raw bytes.
    ///
    /// # Panics
    ///
    /// Panics when either reviewed presentation stream is not valid UTF-8.
    #[must_use]
    pub fn with_expected_presentation_shadow(
        mut self,
        normalizer: PresentationShadowNormalizerId,
        stdout: &[u8],
        stderr: &[u8],
    ) -> Self {
        self.expected_presentation_shadow_normalizer = Some(normalizer);
        self.expected_normalized_presentation_sha256 = Some(
            normalized_presentation_shadow_sha256(normalizer, stdout, stderr)
                .expect("reviewed presentation shadow bytes must be UTF-8"),
        );
        self
    }
}

pub(crate) fn single_task_lifecycle_sha256<'a>(
    events: impl IntoIterator<Item = &'a str>,
) -> Digest {
    let mut canonical = b"hell-runtime-single-task-lifecycle-v1\0".to_vec();
    for event in events {
        canonical.extend_from_slice(&(event.len() as u64).to_be_bytes());
        canonical.extend_from_slice(event.as_bytes());
    }
    sha256_bytes(&canonical)
}

pub(crate) fn lazy_argument_exit_sha256<'a>(
    states: impl IntoIterator<Item = (u16, &'a str)>,
) -> Digest {
    let mut canonical = b"hell-runtime-lazy-argument-exit-v1\0".to_vec();
    for (argument, outcome) in states {
        canonical.extend_from_slice(&argument.to_be_bytes());
        canonical.extend_from_slice(&(outcome.len() as u64).to_be_bytes());
        canonical.extend_from_slice(outcome.as_bytes());
    }
    sha256_bytes(&canonical)
}

pub(crate) fn whnf_argument_failure_sha256<'a>(
    failures: impl IntoIterator<Item = (u16, &'a str, &'a str)>,
) -> Digest {
    let mut canonical = b"hell-runtime-whnf-argument-failure-v1\0".to_vec();
    for (argument, outcome, error_code) in failures {
        canonical.extend_from_slice(&argument.to_be_bytes());
        for value in [outcome, error_code] {
            canonical.extend_from_slice(&(value.len() as u64).to_be_bytes());
            canonical.extend_from_slice(value.as_bytes());
        }
    }
    sha256_bytes(&canonical)
}

pub(crate) fn nonproductive_trace_sha256<'a>(
    events: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Digest {
    let events = events.into_iter().collect::<Vec<_>>();
    let mut canonical = b"hell-runtime-nonproductive-trace-v1\0".to_vec();
    canonical.extend_from_slice(&(events.len() as u64).to_be_bytes());
    for (boundary, outcome) in events {
        canonical.extend_from_slice(&(boundary.len() as u64).to_be_bytes());
        canonical.extend_from_slice(boundary.as_bytes());
        canonical.extend_from_slice(&(outcome.len() as u64).to_be_bytes());
        canonical.extend_from_slice(outcome.as_bytes());
    }
    sha256_bytes(&canonical)
}

pub(crate) fn task_trace_sha256<'a>(events: impl IntoIterator<Item = (usize, &'a str)>) -> Digest {
    let events = events.into_iter().collect::<Vec<_>>();
    let mut canonical = b"hell-runtime-task-trace-v1\0".to_vec();
    canonical.extend_from_slice(&(events.len() as u64).to_be_bytes());
    for (task, event) in events {
        canonical.extend_from_slice(&(task as u64).to_be_bytes());
        canonical.extend_from_slice(&(event.len() as u64).to_be_bytes());
        canonical.extend_from_slice(event.as_bytes());
    }
    sha256_bytes(&canonical)
}

/// Returns the canonical, domain-separated bytes used to identify one process
/// status in retained collection and runtime evidence.
#[must_use]
pub fn canonical_process_status_bytes(success: bool, code: Option<i32>) -> Vec<u8> {
    let mut canonical = b"hell-runtime-process-status-v1\0".to_vec();
    canonical.extend_from_slice(if success { b"success\0" } else { b"failure\0" });
    canonical.extend_from_slice(
        code.map_or_else(|| "null".to_owned(), |value| value.to_string())
            .as_bytes(),
    );
    canonical
}

pub(crate) fn process_status_sha256(success: bool, code: Option<i32>) -> Digest {
    sha256_bytes(&canonical_process_status_bytes(success, code))
}

pub(crate) fn single_effect_lifecycle_sha256<'a>(
    events: impl IntoIterator<Item = &'a str>,
) -> Digest {
    let mut canonical = b"hell-runtime-single-effect-lifecycle-v1\0".to_vec();
    for event in events {
        canonical.extend_from_slice(&(event.len() as u64).to_be_bytes());
        canonical.extend_from_slice(event.as_bytes());
    }
    sha256_bytes(&canonical)
}

fn push_comparator_trace_field(canonical: &mut Vec<u8>, value: &str) {
    canonical.extend_from_slice(&(value.len() as u64).to_be_bytes());
    canonical.extend_from_slice(value.as_bytes());
}

/// Hashes one exact, ordered Map/Set direct-comparator protocol. The parent
/// invocation count makes the zero-comparison singleton/empty path explicit;
/// the retained root and complete recursive premise plan are bound even when
/// the record list is empty.
#[must_use]
pub fn comparator_trace_sha256(
    parent_builtin: &str,
    parent_invocation_count: u64,
    instance_target: &str,
    instance_premises: &[InstancePremiseEvidence],
    records: &[ComparatorTraceContract],
) -> Digest {
    let mut canonical = b"hell-runtime-collection-comparator-trace-v1\0".to_vec();
    push_comparator_trace_field(&mut canonical, parent_builtin);
    canonical.extend_from_slice(&parent_invocation_count.to_be_bytes());
    push_comparator_trace_field(&mut canonical, instance_target);
    canonical.extend_from_slice(&(instance_premises.len() as u64).to_be_bytes());
    for premise in instance_premises {
        push_comparator_trace_field(&mut canonical, &premise.target);
        canonical.push(premise.premise_count);
    }
    canonical.extend_from_slice(&(records.len() as u64).to_be_bytes());
    for record in records {
        canonical.extend_from_slice(&record.parent_invocation.to_be_bytes());
        canonical.extend_from_slice(&record.direct_child_ordinal.to_be_bytes());
        canonical.extend_from_slice(&record.comparator_ordinal.to_be_bytes());
        push_comparator_trace_field(&mut canonical, &record.comparator);
        push_comparator_trace_field(&mut canonical, &record.canonical_left);
        push_comparator_trace_field(&mut canonical, &record.canonical_right);
        canonical.push(u8::from(record.result));
        push_comparator_trace_field(&mut canonical, &record.outcome);
        push_comparator_trace_field(&mut canonical, instance_target);
        canonical.extend_from_slice(&(instance_premises.len() as u64).to_be_bytes());
        for premise in instance_premises {
            push_comparator_trace_field(&mut canonical, &premise.target);
            canonical.push(premise.premise_count);
        }
    }
    sha256_bytes(&canonical)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimEvidenceDescriptor {
    pub schema_version: u32,
    pub profile: ExecutionProfile,
    pub harness_normalizers: Vec<NormalizerId>,
    pub claim_normalizers: Vec<NormalizerId>,
    pub targets: Vec<EvidenceTarget>,
    pub semantic_targets: Vec<EvidenceTargetV2>,
    pub callback_contracts: Vec<CallbackContract>,
    pub review_state: CaseReviewState,
    pub review_statement: Arc<str>,
    pub source_sha256: Digest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaseReviewState {
    Reviewed,
}

#[derive(Clone, Debug)]
pub struct DifferentialCase {
    pub id: Arc<str>,
    pub source: Arc<str>,
    pub arguments: Vec<OsString>,
    pub environment: Vec<(OsString, OsString)>,
    pub stdin: Vec<u8>,
    pub timeout: Duration,
    pub normalization: OutputNormalization,
    pub environment_profile: EnvironmentProfile,
    pub process_helper_directory: Option<PathBuf>,
    pub process_helper_sha256: Option<Digest>,
    pub mode: DifferentialMode,
    /// The reviewed top-level runtime outcome for direct in-process execution.
    ///
    /// This is deliberately case authority rather than an inference from a
    /// target process-status digest, which may describe a child process.
    pub expected_runtime_completion: bool,
    /// `None` keeps stress/ad-hoc cases ineligible for promotion references.
    pub claim_evidence: Option<ClaimEvidenceDescriptor>,
}

impl Default for DifferentialCase {
    fn default() -> Self {
        Self {
            id: Arc::from("anonymous"),
            source: Arc::from("main = IO.pure ()\n"),
            arguments: Vec::new(),
            environment: Vec::new(),
            stdin: Vec::new(),
            timeout: Duration::from_secs(5),
            normalization: OutputNormalization::default(),
            environment_profile: EnvironmentProfile::Explicit,
            process_helper_directory: None,
            process_helper_sha256: None,
            mode: DifferentialMode::Run,
            expected_runtime_completion: true,
            claim_evidence: None,
        }
    }
}

/// Binds the exact sibling process fixture directory used by committed
/// process-capable evidence cases.
///
/// The directory is execution context rather than reviewed case semantics;
/// retained descriptors bind the versioned logical fixture identity instead
/// of an absolute runner path.
///
/// # Errors
///
/// Returns an error when the directory is not absolute or does not contain
/// the platform's `hell-test-helper` executable.
pub fn bind_process_helper_directory(
    cases: &mut [DifferentialCase],
    directory: &Path,
) -> Result<Digest, String> {
    if !directory.is_absolute() || !directory.is_dir() {
        return Err("process helper directory must be an existing absolute directory".into());
    }
    let helper = directory.join(format!("hell-test-helper{}", std::env::consts::EXE_SUFFIX));
    if !helper.is_file() {
        return Err(format!(
            "process helper executable is missing from {}",
            directory.display()
        ));
    }
    let digest = sha256_file(&helper).map_err(|error| error.to_string())?;
    for case in cases
        .iter_mut()
        .filter(|case| case.environment_profile == EnvironmentProfile::ProcessCapable)
    {
        case.process_helper_directory = Some(directory.to_path_buf());
        case.process_helper_sha256 = Some(digest);
    }
    Ok(digest)
}

#[cfg(unix)]
const CARGO_PROBE_RECORD_MAGIC: &[u8] = b"hell-cargo-probe-v1\0";
#[cfg(unix)]
const CARGO_PROBE_ARGUMENT_LIMIT: usize = 128;
#[cfg(unix)]
const CARGO_PROBE_ARGUMENT_BYTE_LIMIT: usize = 8 * 1024;
#[cfg(unix)]
const CARGO_PROBE_INVOCATION_BYTE_LIMIT: usize = 64 * 1024;
#[cfg(unix)]
const CARGO_PROBE_RECORD_LIMIT: usize = 64;
#[cfg(unix)]
const CARGO_PROBE_LOG_BYTE_LIMIT: u64 = 64 * 1024 * 64;

/// Returns the bounded sibling log used by the compiled Cargo probe fixture.
#[cfg(unix)]
#[doc(hidden)]
#[must_use]
pub fn cargo_probe_log_path(helper: &Path) -> PathBuf {
    helper.with_extension("cargo-probe-v1.log")
}

#[cfg(unix)]
fn encode_cargo_probe_invocation(arguments: &[std::ffi::OsString]) -> std::io::Result<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt as _;

    if arguments.len() > CARGO_PROBE_ARGUMENT_LIMIT {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Cargo probe argv exceeds its argument bound",
        ));
    }
    let mut record = Vec::with_capacity(CARGO_PROBE_RECORD_MAGIC.len() + 4);
    record.extend_from_slice(CARGO_PROBE_RECORD_MAGIC);
    record.extend_from_slice(
        &u32::try_from(arguments.len())
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Cargo probe argv count is unrepresentable",
                )
            })?
            .to_le_bytes(),
    );
    for argument in arguments {
        let bytes = argument.as_os_str().as_bytes();
        if bytes.len() > CARGO_PROBE_ARGUMENT_BYTE_LIMIT {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Cargo probe argument exceeds its byte bound",
            ));
        }
        record.extend_from_slice(
            &u32::try_from(bytes.len())
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "Cargo probe argument length is unrepresentable",
                    )
                })?
                .to_le_bytes(),
        );
        record.extend_from_slice(bytes);
        if record.len() > CARGO_PROBE_INVOCATION_BYTE_LIMIT {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Cargo probe argv exceeds its invocation byte bound",
            ));
        }
    }
    Ok(record)
}

#[cfg(unix)]
fn require_cargo_probe_log_handle(
    log: &Path,
    file: &fs::File,
    expected_length: u64,
) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let path_metadata = fs::symlink_metadata(log)?;
    let opened_metadata = file.metadata()?;
    if !path_metadata.is_file()
        || path_metadata.file_type().is_symlink()
        || path_metadata.nlink() != 1
        || opened_metadata.nlink() != 1
        || opened_metadata.dev() != path_metadata.dev()
        || opened_metadata.ino() != path_metadata.ino()
        || opened_metadata.len() != expected_length
        || path_metadata.len() != expected_length
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Cargo probe log path and opened identity differ",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn open_cargo_probe_log_for_append(log: &Path, record_length: usize) -> std::io::Result<fs::File> {
    use std::os::unix::fs::MetadataExt as _;

    let record_length = u64::try_from(record_length).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Cargo probe record length is unrepresentable",
        )
    })?;
    match fs::symlink_metadata(log) {
        Ok(path_metadata) => {
            if !path_metadata.is_file()
                || path_metadata.file_type().is_symlink()
                || path_metadata.nlink() != 1
                || path_metadata
                    .len()
                    .checked_add(record_length)
                    .is_none_or(|length| length > CARGO_PROBE_LOG_BYTE_LIMIT)
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Cargo probe log identity or size differs from policy",
                ));
            }
            let file = fs::OpenOptions::new().append(true).open(log)?;
            require_cargo_probe_log_handle(log, &file, path_metadata.len())?;
            Ok(file)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(log)?;
            require_cargo_probe_log_handle(log, &file, 0)?;
            Ok(file)
        }
        Err(error) => Err(error),
    }
}

/// Appends one exact argv record for the compiled Cargo probe fixture.
///
/// # Errors
///
/// Returns an error when the argv or existing log exceeds its closed bounds,
/// contains an unrepresentable field length, or cannot be appended.
#[cfg(unix)]
#[doc(hidden)]
pub fn append_cargo_probe_invocation(
    helper: &Path,
    arguments: &[std::ffi::OsString],
) -> std::io::Result<()> {
    use std::io::Write as _;

    let record = encode_cargo_probe_invocation(arguments)?;
    let log = cargo_probe_log_path(helper);
    let mut file = open_cargo_probe_log_for_append(&log, record.len())?;
    file.write_all(&record)?;
    let final_length = file.metadata()?.len();
    if final_length > CARGO_PROBE_LOG_BYTE_LIMIT {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Cargo probe log exceeds its byte bound after append",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn take_cargo_probe_bytes<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    length: usize,
) -> std::io::Result<&'a [u8]> {
    let end = cursor.checked_add(length).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Cargo probe record offset overflowed",
        )
    })?;
    let value = bytes.get(*cursor..end).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Cargo probe record is truncated",
        )
    })?;
    *cursor = end;
    Ok(value)
}

#[cfg(unix)]
fn take_cargo_probe_u32(bytes: &[u8], cursor: &mut usize) -> std::io::Result<u32> {
    let field = take_cargo_probe_bytes(bytes, cursor, std::mem::size_of::<u32>())?;
    Ok(u32::from_le_bytes(
        field.try_into().expect("exact u32 byte count"),
    ))
}

#[cfg(unix)]
fn read_cargo_probe_log(helper: &Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;
    use std::os::unix::fs::MetadataExt as _;

    let log = cargo_probe_log_path(helper);
    let path_metadata = fs::symlink_metadata(&log)?;
    if !path_metadata.is_file()
        || path_metadata.file_type().is_symlink()
        || path_metadata.nlink() != 1
        || path_metadata.len() > CARGO_PROBE_LOG_BYTE_LIMIT
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Cargo probe log identity or size differs from policy",
        ));
    }
    let file = fs::File::open(&log)?;
    let opened_metadata = file.metadata()?;
    if !opened_metadata.is_file()
        || opened_metadata.nlink() != 1
        || opened_metadata.dev() != path_metadata.dev()
        || opened_metadata.ino() != path_metadata.ino()
        || opened_metadata.len() != path_metadata.len()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Cargo probe log changed while it was opened",
        ));
    }
    let mut bytes = Vec::new();
    file.take(CARGO_PROBE_LOG_BYTE_LIMIT + 1)
        .read_to_end(&mut bytes)?;
    let bytes_len = u64::try_from(bytes.len()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Cargo probe log length is unrepresentable",
        )
    })?;
    if bytes_len > CARGO_PROBE_LOG_BYTE_LIMIT {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Cargo probe log grew beyond its byte bound",
        ));
    }
    let final_metadata = fs::symlink_metadata(&log)?;
    if final_metadata.file_type().is_symlink()
        || final_metadata.dev() != opened_metadata.dev()
        || final_metadata.ino() != opened_metadata.ino()
        || final_metadata.len() != bytes_len
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Cargo probe log changed while it was read",
        ));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn decode_cargo_probe_invocations(bytes: &[u8]) -> std::io::Result<Vec<Vec<std::ffi::OsString>>> {
    use std::os::unix::ffi::OsStringExt as _;

    let mut cursor = 0_usize;
    let mut records = Vec::new();
    while cursor < bytes.len() {
        let record_start = cursor;
        if records.len() >= CARGO_PROBE_RECORD_LIMIT
            || take_cargo_probe_bytes(bytes, &mut cursor, CARGO_PROBE_RECORD_MAGIC.len())?
                != CARGO_PROBE_RECORD_MAGIC
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Cargo probe log has an unknown or excessive record",
            ));
        }
        let argument_count =
            usize::try_from(take_cargo_probe_u32(bytes, &mut cursor)?).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Cargo probe argv count is unrepresentable",
                )
            })?;
        if argument_count > CARGO_PROBE_ARGUMENT_LIMIT {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Cargo probe argv exceeds its argument bound",
            ));
        }
        let mut arguments = Vec::with_capacity(argument_count);
        for _ in 0..argument_count {
            let length =
                usize::try_from(take_cargo_probe_u32(bytes, &mut cursor)?).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Cargo probe argument length is unrepresentable",
                    )
                })?;
            if length > CARGO_PROBE_ARGUMENT_BYTE_LIMIT {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Cargo probe argument exceeds its byte bound",
                ));
            }
            arguments.push(std::ffi::OsString::from_vec(
                take_cargo_probe_bytes(bytes, &mut cursor, length)?.to_vec(),
            ));
        }
        if cursor
            .checked_sub(record_start)
            .is_none_or(|length| length > CARGO_PROBE_INVOCATION_BYTE_LIMIT)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Cargo probe record exceeds its invocation byte bound",
            ));
        }
        records.push(arguments);
    }
    Ok(records)
}

/// Reads the exact bounded argv records emitted by the compiled Cargo probe.
///
/// # Errors
///
/// Returns an error when the log is redirected, oversized, truncated, has an
/// unknown schema, or contains a field outside the closed bounds.
#[cfg(unix)]
#[doc(hidden)]
pub fn read_cargo_probe_invocations(
    helper: &Path,
) -> std::io::Result<Vec<Vec<std::ffi::OsString>>> {
    decode_cargo_probe_invocations(&read_cargo_probe_log(helper)?)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DifferentialMode {
    Check,
    #[default]
    Run,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EnvironmentProfile {
    Minimal,
    ProcessCapable,
    NativePlatform,
    #[default]
    Explicit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutableRole {
    Oracle,
    Candidate,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuildInfo {
    pub schema_version: u64,
    pub compat_tracing: bool,
    pub lines: Arc<[Arc<str>]>,
}

const CANDIDATE_BUILD_INFO_SCHEMA_VERSION: u64 = 2;
const CANDIDATE_COMPILER_POLICY_SHA256: &str =
    "ab02a39329b32cda76aacf3c2dfb2477199584d4c50254ad70de9733931d6a1b";
const CANDIDATE_RUNTIME_POLICY_SHA256: &str =
    "d11a8fe248f038ded84295868136f2b1633173a1cefb768de84050f920f52cf1";

/// Parses the candidate's closed, versioned `--build-info` output.
///
/// # Errors
///
/// Returns an error when a field is missing, duplicated, reordered, malformed,
/// or belongs to an unsupported schema version.
pub fn parse_candidate_build_info<'a>(
    lines: impl IntoIterator<Item = &'a str>,
) -> std::io::Result<BuildInfo> {
    let lines = lines.into_iter().map(Arc::<str>::from).collect::<Vec<_>>();
    if lines.len() != 7 {
        return Err(std::io::Error::other(format!(
            "candidate build info schema {CANDIDATE_BUILD_INFO_SCHEMA_VERSION} requires exactly 7 lines, observed {}",
            lines.len()
        )));
    }
    let expected = [
        format!("hell-rs {}", env!("CARGO_PKG_VERSION")),
        format!("language baseline {}", hell_builtins::LANGUAGE_VERSION),
        format!("upstream {}", hell_builtins::UPSTREAM_COMMIT),
        format!("compatibility evidence schema {CANDIDATE_BUILD_INFO_SCHEMA_VERSION}"),
    ];
    for (index, expected) in expected.iter().enumerate() {
        if lines[index].as_ref() != expected {
            return Err(std::io::Error::other(format!(
                "candidate build info line {index} differs from schema {CANDIDATE_BUILD_INFO_SCHEMA_VERSION}"
            )));
        }
    }
    let compat_tracing = match lines[4].as_ref() {
        "compat tracing enabled true" => true,
        "compat tracing enabled false" => false,
        _ => {
            return Err(std::io::Error::other(
                "candidate build info compat tracing field is malformed",
            ));
        }
    };
    if sha256_bytes(lines[5].as_bytes()).hex() != CANDIDATE_COMPILER_POLICY_SHA256 {
        return Err(std::io::Error::other(
            "candidate build info compiler policy field is malformed",
        ));
    }
    if sha256_bytes(lines[6].as_bytes()).hex() != CANDIDATE_RUNTIME_POLICY_SHA256 {
        return Err(std::io::Error::other(
            "candidate build info runtime policy field is malformed",
        ));
    }
    Ok(BuildInfo {
        schema_version: CANDIDATE_BUILD_INFO_SCHEMA_VERSION,
        compat_tracing,
        lines: lines.into(),
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutableIdentity {
    pub path: PathBuf,
    pub sha256: Digest,
    pub reported_version: Arc<str>,
    pub build_info: Option<BuildInfo>,
    pub role: ExecutableRole,
    pub assurance_epoch_sha256: Option<Digest>,
    pub acquisition_receipt_id: Option<Arc<str>>,
    pub acquisition_receipt_sha256: Option<Digest>,
    pub acquisition_attestation_sha256: Option<Digest>,
}

/// Separately binds an executable's source provenance and the exact path used
/// as its process invocation identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutableInvocationAuthority {
    source: ExecutableIdentity,
    execution: ExecutableIdentity,
}

impl ExecutableInvocationAuthority {
    /// Binds a direct invocation whose source and execution paths are equal.
    ///
    /// # Errors
    ///
    /// Returns an error unless the identity is canonical and unchanged.
    pub fn direct(identity: &ExecutableIdentity) -> std::io::Result<Self> {
        Self::new(identity, identity, None)
    }

    /// Binds an invocation named exactly `hell` (`hell.exe` on Windows) to a
    /// separately retained source identity.
    ///
    /// # Errors
    ///
    /// Returns an error unless both identities are canonical, claim the same
    /// executable bytes and provenance, and name the same underlying file.
    pub fn exact_hell(
        source: &ExecutableIdentity,
        execution: &ExecutableIdentity,
    ) -> std::io::Result<Self> {
        let expected = OsString::from(format!("hell{}", std::env::consts::EXE_SUFFIX));
        Self::new(source, execution, Some(&expected))
    }

    fn new(
        source: &ExecutableIdentity,
        execution: &ExecutableIdentity,
        exact_name: Option<&OsStr>,
    ) -> std::io::Result<Self> {
        if fs::canonicalize(&source.path)? != source.path
            || fs::canonicalize(&execution.path)? != execution.path
            || exact_name.is_some_and(|name| execution.path.file_name() != Some(name))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "executable invocation path is not canonical or exactly named",
            ));
        }
        let mut expected_execution = source.clone();
        expected_execution.path.clone_from(&execution.path);
        if *execution != expected_execution
            || sha256_file(&source.path)? != source.sha256
            || sha256_file(&execution.path)? != execution.sha256
            || !same_executable_file(&source.path, &execution.path)?
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "executable invocation differs from its source authority",
            ));
        }
        Ok(Self {
            source: source.clone(),
            execution: execution.clone(),
        })
    }

    /// Returns the separately retained source identity.
    #[must_use]
    pub fn source(&self) -> &ExecutableIdentity {
        &self.source
    }

    /// Returns the exact identity and basename used at process spawn.
    #[must_use]
    pub fn execution(&self) -> &ExecutableIdentity {
        &self.execution
    }
}

#[cfg(unix)]
fn same_executable_file(left: &Path, right: &Path) -> std::io::Result<bool> {
    use std::os::unix::fs::MetadataExt as _;

    let left = fs::metadata(left)?;
    let right = fs::metadata(right)?;
    Ok(left.dev() == right.dev() && left.ino() == right.ino())
}

#[cfg(not(unix))]
fn same_executable_file(left: &Path, right: &Path) -> std::io::Result<bool> {
    Ok(left == right)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FilesystemEntryKind {
    Directory,
    File,
    SymbolicLink,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilesystemEntry {
    pub relative_path: PathBuf,
    pub kind: FilesystemEntryKind,
    pub contents: Vec<u8>,
    pub size: u64,
    pub sha256: Option<Digest>,
    pub truncated: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundedCapture {
    pub total_bytes: u64,
    pub sha256: Digest,
    pub prefix: Vec<u8>,
    pub suffix: Vec<u8>,
    pub complete: Option<Vec<u8>>,
    pub truncated: bool,
}

impl BoundedCapture {
    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        let mut digest = Sha256::new();
        digest.update(&bytes);
        let total_bytes = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let truncated = bytes.len() > COMPLETE_CAPTURE_BYTES;
        let prefix = bytes[..bytes.len().min(CAPTURE_EDGE_BYTES)].to_vec();
        let suffix_start = bytes.len().saturating_sub(CAPTURE_EDGE_BYTES);
        let suffix = bytes[suffix_start..].to_vec();
        Self {
            total_bytes,
            sha256: digest.finish(),
            prefix,
            suffix,
            complete: (!truncated).then_some(bytes),
            truncated,
        }
    }

    fn mismatch_bytes(&self) -> Vec<u8> {
        self.complete.clone().unwrap_or_else(|| {
            let mut bytes = self.prefix.clone();
            bytes.extend_from_slice(b"\n<TRUNCATED>\n");
            bytes.extend_from_slice(&self.suffix);
            bytes
        })
    }

    /// Returns the complete capture or its retained prefix/truncation marker/
    /// suffix representation.
    #[must_use]
    pub fn retained_bytes(&self) -> Vec<u8> {
        self.mismatch_bytes()
    }

    fn into_output(self) -> Vec<u8> {
        if let Some(bytes) = self.complete {
            bytes
        } else {
            let mut bytes = self.prefix;
            bytes.extend_from_slice(b"\n<TRUNCATED>\n");
            bytes.extend_from_slice(&self.suffix);
            bytes
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SupervisedIoTaskState {
    NotStarted,
    Owned,
    Completed,
    Failed,
    Panicked,
    LaunchFailed,
    AbortedBeforeLaunch,
}

impl SupervisedIoTaskState {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NotStarted => "not-started",
            Self::Owned => "owned",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Panicked => "panicked",
            Self::LaunchFailed => "launch-failed",
            Self::AbortedBeforeLaunch => "aborted-before-launch",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupervisedIoTaskSnapshot {
    pub state: SupervisedIoTaskState,
    pub bytes: Option<u64>,
    pub sha256: Option<Digest>,
    pub truncated: Option<bool>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupervisedIoSnapshot {
    pub stdout: SupervisedIoTaskSnapshot,
    pub stderr: SupervisedIoTaskSnapshot,
    pub stdin: SupervisedIoTaskSnapshot,
}

#[derive(Clone, Debug)]
pub struct SupervisedIoReceipt {
    inner: Arc<(Mutex<SupervisedIoSnapshot>, Condvar)>,
}

impl SupervisedIoReceipt {
    fn new() -> Self {
        let not_started = SupervisedIoTaskSnapshot {
            state: SupervisedIoTaskState::NotStarted,
            bytes: None,
            sha256: None,
            truncated: None,
            error: None,
        };
        Self {
            inner: Arc::new((
                Mutex::new(SupervisedIoSnapshot {
                    stdout: not_started.clone(),
                    stderr: not_started.clone(),
                    stdin: not_started,
                }),
                Condvar::new(),
            )),
        }
    }

    fn set_state(&self, stream: Option<SupervisedOutputStream>, state: SupervisedIoTaskState) {
        let mut snapshot = self
            .inner
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let task = match stream {
            Some(SupervisedOutputStream::Stdout) => &mut snapshot.stdout,
            Some(SupervisedOutputStream::Stderr) => &mut snapshot.stderr,
            None => &mut snapshot.stdin,
        };
        task.state = state;
        self.inner.1.notify_all();
    }

    fn abort_not_started(&self) {
        let mut snapshot = self
            .inner
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let abort = |task: &mut SupervisedIoTaskSnapshot| {
            if task.state == SupervisedIoTaskState::NotStarted {
                task.state = SupervisedIoTaskState::AbortedBeforeLaunch;
            }
        };
        abort(&mut snapshot.stdout);
        abort(&mut snapshot.stderr);
        abort(&mut snapshot.stdin);
        self.inner.1.notify_all();
    }

    fn finish_capture(
        &self,
        stream: SupervisedOutputStream,
        result: &std::io::Result<BoundedCapture>,
    ) {
        let snapshot = match result {
            Ok(capture) => SupervisedIoTaskSnapshot {
                state: SupervisedIoTaskState::Completed,
                bytes: Some(capture.total_bytes),
                sha256: Some(capture.sha256),
                truncated: Some(capture.truncated),
                error: None,
            },
            Err(error) => SupervisedIoTaskSnapshot {
                state: SupervisedIoTaskState::Failed,
                bytes: None,
                sha256: None,
                truncated: None,
                error: Some(error.to_string()),
            },
        };
        let mut state = self
            .inner
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match stream {
            SupervisedOutputStream::Stdout => state.stdout = snapshot,
            SupervisedOutputStream::Stderr => state.stderr = snapshot,
        }
        self.inner.1.notify_all();
    }

    fn finish_stdin(&self, result: &std::io::Result<()>) {
        let snapshot = match result {
            Ok(()) => SupervisedIoTaskSnapshot {
                state: SupervisedIoTaskState::Completed,
                bytes: Some(0),
                sha256: None,
                truncated: Some(false),
                error: None,
            },
            Err(error) => SupervisedIoTaskSnapshot {
                state: SupervisedIoTaskState::Failed,
                bytes: None,
                sha256: None,
                truncated: None,
                error: Some(error.to_string()),
            },
        };
        self.inner
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .stdin = snapshot;
        self.inner.1.notify_all();
    }

    fn mark_panicked(&self, stream: Option<SupervisedOutputStream>) {
        let panicked = SupervisedIoTaskSnapshot {
            state: SupervisedIoTaskState::Panicked,
            bytes: None,
            sha256: None,
            truncated: None,
            error: Some("supervised I/O worker panicked".to_owned()),
        };
        let mut state = self
            .inner
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match stream {
            Some(SupervisedOutputStream::Stdout) => state.stdout = panicked,
            Some(SupervisedOutputStream::Stderr) => state.stderr = panicked,
            None => state.stdin = panicked,
        }
        self.inner.1.notify_all();
    }

    #[must_use]
    pub fn snapshot(&self) -> SupervisedIoSnapshot {
        self.inner
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    #[must_use]
    pub fn wait_until(&self, deadline: Instant) -> SupervisedIoSnapshot {
        let mut snapshot = self
            .inner
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while supervised_io_owned(&snapshot) {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let (next, timeout) = self
                .inner
                .1
                .wait_timeout(snapshot, remaining)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            snapshot = next;
            if timeout.timed_out() && supervised_io_owned(&snapshot) {
                break;
            }
        }
        snapshot.clone()
    }

    /// Waits until all three admitted I/O tasks reach typed terminal states.
    #[must_use]
    pub fn wait(&self) -> SupervisedIoSnapshot {
        let mut snapshot = self
            .inner
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while supervised_io_owned(&snapshot) {
            snapshot = self
                .inner
                .1
                .wait(snapshot)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        snapshot.clone()
    }
}

fn supervised_io_owned(snapshot: &SupervisedIoSnapshot) -> bool {
    [
        &snapshot.stdout.state,
        &snapshot.stderr.state,
        &snapshot.stdin.state,
    ]
    .into_iter()
    .any(|state| {
        matches!(
            state,
            SupervisedIoTaskState::NotStarted | SupervisedIoTaskState::Owned
        )
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessStatus {
    pub success: bool,
    pub code: Option<i32>,
}

/// Compiler phase represented independently from diagnostic presentation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiagnosticPhase {
    Parse,
    StaticSemantics,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiagnosticCategory {
    Syntax,
    NameResolution,
}

/// Structural diagnostic fields shared by the pinned oracle and candidate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiagnosticObservation {
    pub phase: DiagnosticPhase,
    pub code: Arc<str>,
    pub category: DiagnosticCategory,
    pub protected_message: Arc<str>,
    pub line: usize,
    pub column: usize,
}

impl From<ExitStatus> for ProcessStatus {
    fn from(status: ExitStatus) -> Self {
        Self {
            success: status.success(),
            code: status.code(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observation {
    pub identity: ExecutableIdentity,
    pub case_id: Arc<str>,
    pub environment_profile: EnvironmentProfile,
    pub process_helper_sha256: Option<Digest>,
    pub mode: DifferentialMode,
    pub status: ProcessStatus,
    pub stdout: BoundedCapture,
    /// Exact bounded stderr bytes before the harness normalizer runs.
    pub raw_stderr: BoundedCapture,
    /// Harness-normalized stderr before any claim normalizer is applied.
    pub claim_input_stderr: BoundedCapture,
    pub stderr: BoundedCapture,
    /// Exact path context consumed by the production harness normalizer.
    pub normalizer_sandbox: PathBuf,
    pub normalizer_script: PathBuf,
    pub timed_out: bool,
    pub diagnostic: Option<DiagnosticObservation>,
    pub filesystem: Vec<FilesystemEntry>,
    pub harness_normalizers: Vec<NormalizerId>,
    pub claim_normalizers: Vec<NormalizerId>,
    pub resource_audit: Option<ResourceAudit>,
    pub semantic: Option<SemanticObservation>,
}

/// One exact executable observation under an explicit compiler/runtime profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedProfileObservation {
    pub profile: ExecutionProfile,
    pub executable_sha256: Digest,
    pub source_sha256: Digest,
    pub execution_input_sha256: Digest,
    pub invocation_sha256: Digest,
    pub observation: Observation,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ResourceAudit {
    pub tasks: usize,
    pub handles: usize,
    pub processes: usize,
    pub http_bodies: usize,
    pub temporary_resources: usize,
    pub cleanup_failures: usize,
}

impl ResourceAudit {
    #[must_use]
    pub fn failure_count(&self) -> usize {
        self.tasks
            .saturating_add(self.handles)
            .saturating_add(self.processes)
            .saturating_add(self.http_bodies)
            .saturating_add(self.temporary_resources)
            .saturating_add(self.cleanup_failures)
    }
}

/// Validates the committed promotion-eligible case catalog before execution.
///
/// # Errors
///
/// Returns a precise catalog error for unsafe or duplicate identifiers,
/// unknown targets, duplicate targets, empty eligibility declarations, or an
/// obviously incompatible check-only/runtime target.
pub fn validate_evidence_catalog(cases: &[DifferentialCase]) -> Result<(), String> {
    let mut obligation_coverage =
        HashMap::<(Arc<str>, CompatibilityDimension), BTreeSet<Arc<str>>>::new();
    for (index, case) in cases.iter().enumerate() {
        if !hell_builtins::validate_case_id(&case.id) {
            return Err(format!("unsafe differential case identifier {:?}", case.id));
        }
        if cases[..index].iter().any(|other| other.id == case.id) {
            return Err(format!(
                "duplicate differential case identifier {:?}",
                case.id
            ));
        }
        let Some(descriptor) = &case.claim_evidence else {
            continue;
        };
        validate_case_descriptor(case, descriptor)?;
        validate_legacy_targets(case, descriptor)?;
        validate_semantic_targets(case, descriptor)?;
        validate_callback_contracts(case, descriptor)?;
        for target in &descriptor.semantic_targets {
            obligation_coverage
                .entry((Arc::clone(&target.builtin), target.dimension))
                .or_default()
                .extend(
                    target
                        .obligations
                        .iter()
                        .map(|obligation| Arc::clone(&obligation.0)),
                );
        }
    }
    for ((builtin, dimension), observed) in obligation_coverage {
        let required = portable_native_oracle_obligations_for_target(&builtin, dimension)?;
        if observed != required {
            return Err(format!(
                "semantic targets for {builtin:?}/{dimension:?} do not cover its registry-derived obligation family: observed {observed:?}, required {required:?}"
            ));
        }
    }
    Ok(())
}

fn portable_native_oracle_obligations_for_target(
    builtin: &str,
    dimension: CompatibilityDimension,
) -> Result<BTreeSet<Arc<str>>, String> {
    let mut required = required_obligations_for_target(builtin, dimension)?;
    if portable_native_oracle_failure_unavailable(builtin, dimension) {
        // Both operations remain semantically fallible in the registry. The
        // native-oracle corpus cannot portably induce those host lookup
        // failures: the sandbox profile is candidate-only, and platform home
        // discovery cannot be disabled in a child process. Preserve the
        // assurance obligation while requiring only portable observations in
        // this differential catalog.
        required.remove("effect-failure");
    }
    Ok(required)
}

fn validate_case_descriptor(
    case: &DifferentialCase,
    descriptor: &ClaimEvidenceDescriptor,
) -> Result<(), String> {
    if descriptor.targets.is_empty() {
        return Err(format!(
            "claim-eligible case {:?} has no evidence targets",
            case.id
        ));
    }
    if descriptor.schema_version != 8 || descriptor.semantic_targets.is_empty() {
        return Err(format!(
            "claim-eligible case {:?} must use a nonempty descriptor-v8 semantic target set",
            case.id
        ));
    }
    if descriptor.review_state != CaseReviewState::Reviewed
        || descriptor.review_statement.is_empty()
        || descriptor.source_sha256 != sha256_bytes(case.source.as_bytes())
    {
        return Err(format!(
            "claim-eligible case {:?} lacks a reviewed, source-bound descriptor",
            case.id
        ));
    }
    if has_duplicate_values(&descriptor.harness_normalizers)
        || has_duplicate_values(&descriptor.claim_normalizers)
    {
        return Err(format!(
            "claim-eligible case {:?} repeats a normalizer",
            case.id
        ));
    }
    if !case.normalization.stderr_replacements.is_empty() {
        return Err(format!(
            "claim-eligible case {:?} uses unversioned stderr replacements",
            case.id
        ));
    }
    if descriptor.harness_normalizers != applied_harness_normalizers()
        || descriptor.claim_normalizers != applied_claim_normalizers(case)
    {
        return Err(format!(
            "claim-eligible case {:?} normalizer declaration does not match execution",
            case.id
        ));
    }
    Ok(())
}

fn validate_legacy_targets(
    case: &DifferentialCase,
    descriptor: &ClaimEvidenceDescriptor,
) -> Result<(), String> {
    for (target_index, target) in descriptor.targets.iter().enumerate() {
        if hell_builtins::lookup(&target.builtin).is_none() {
            return Err(format!(
                "case {:?} targets unknown builtin {:?}",
                case.id, target.builtin
            ));
        }
        if descriptor.targets[..target_index].contains(target) {
            return Err(format!(
                "case {:?} repeats target {:?}/{:?}",
                case.id, target.builtin, target.dimension
            ));
        }
        if case.mode == DifferentialMode::Check
            && matches!(
                target.dimension,
                CompatibilityDimension::PureRuntime
                    | CompatibilityDimension::Effects
                    | CompatibilityDimension::Concurrency
                    | CompatibilityDimension::ResourceBehavior
            )
        {
            return Err(format!(
                "check-only case {:?} cannot target runtime dimension {:?}",
                case.id, target.dimension
            ));
        }
        if !descriptor.semantic_targets.iter().any(|semantic| {
            semantic.builtin == target.builtin && semantic.dimension == target.dimension
        }) {
            return Err(format!(
                "case {:?} compatibility and semantic targets disagree",
                case.id
            ));
        }
    }
    Ok(())
}

fn validate_semantic_targets(
    case: &DifferentialCase,
    descriptor: &ClaimEvidenceDescriptor,
) -> Result<(), String> {
    for (target_index, target) in descriptor.semantic_targets.iter().enumerate() {
        if target.obligations.is_empty() || target.platforms.is_empty() {
            return Err(format!(
                "case {:?} has an incomplete semantic target {:?}/{:?}",
                case.id, target.builtin, target.dimension
            ));
        }
        let Some(spec) = hell_builtins::lookup(&target.builtin) else {
            return Err(format!(
                "case {:?} has an unknown semantic target {:?}",
                case.id, target.builtin
            ));
        };
        validate_semantic_instance_declaration(case, target, spec)?;
        if target.expected_nonproductive_trace_sha256.is_some()
            && (spec.name != "Alternative.many"
                || target.dimension != CompatibilityDimension::PureRuntime
                || !matches!(
                    target.expected_instance_target.as_deref(),
                    Some("Maybe" | "Options.Parser")
                ))
        {
            return Err(format!(
                "case {:?} nonproductive trace is not scoped to a reviewed Alternative.many instance",
                case.id
            ));
        }
        let comparator_sensitive = runtime_obligations::collection_comparator_sensitive(spec.name)
            && target.causal_signal != CausalSignal::ForceTrace;
        if target.expected_comparator_trace_sha256.is_some() != comparator_sensitive
            || (comparator_sensitive && target.expected_instance_target.is_none())
        {
            return Err(format!(
                "case {:?} comparator-sensitive target {:?} lacks exact comparator authority",
                case.id, target.builtin
            ));
        }
        validate_semantic_target_obligations(case, target)?;
        validate_semantic_target_crosslinks(case, descriptor, target_index, target)?;
    }
    Ok(())
}

fn validate_semantic_instance_declaration(
    case: &DifferentialCase,
    target: &EvidenceTargetV2,
    spec: &hell_builtins::BuiltinSpec,
) -> Result<(), String> {
    match (spec.type_class, target.expected_instance_target.as_deref()) {
        (None | Some(_), None) if target.expected_instance_premises.is_empty() => Ok(()),
        (None | Some(_), None) => Err(format!(
            "case {:?} semantic target {:?} declares premises without an instance root",
            case.id, target.builtin
        )),
        (None, Some(_)) => Err(format!(
            "case {:?} unconstrained semantic target {:?} declares an instance target",
            case.id, target.builtin
        )),
        (Some(class), Some(instance_target)) => validate_instance_premise_tree(
            class,
            instance_target,
            &target.expected_instance_premises,
        )
        .map_err(|_| {
            format!(
                "case {:?} semantic target {:?} declares an unknown instance target",
                case.id, target.builtin
            )
        }),
    }
}

fn validate_semantic_target_obligations(
    case: &DifferentialCase,
    target: &EvidenceTargetV2,
) -> Result<(), String> {
    let allowed = required_obligation_catalog(target.dimension);
    if has_duplicate_values(&target.obligations)
        || target
            .obligations
            .iter()
            .any(|obligation| !allowed.contains(&obligation.0.as_ref()))
    {
        return Err(format!(
            "case {:?} semantic target {:?}/{:?} declares an unknown or duplicate obligation",
            case.id, target.builtin, target.dimension
        ));
    }
    let has_obligation = |name: &str| {
        target
            .obligations
            .iter()
            .any(|obligation| obligation.0.as_ref() == name)
    };
    let force_failure = has_obligation("whnf-failure-boundary");
    if force_failure != target.expected_whnf_argument_failure_sha256.is_some()
        || (force_failure
            && (target.causal_signal != CausalSignal::ForceTrace
                || target.expected_instance_target.is_some()
                || !target.expected_instance_premises.is_empty()
                || target.expected_comparator_trace_sha256.is_some()
                || target.expected_typed_result_sha256.is_some()
                || has_obligation("adapter-success")
                || has_obligation("adapter-failure")
                || has_obligation("whnf-boundary")))
    {
        return Err(format!(
            "case {:?} semantic target {:?}/{:?} has an incomplete or contaminated WHNF failure proof",
            case.id, target.builtin, target.dimension
        ));
    }
    validate_result_force_failure_obligation(case, target)?;
    if (has_obligation("adapter-success") && has_obligation("adapter-failure"))
        || (has_obligation("effect-success") && has_obligation("effect-failure"))
        || (has_obligation("effect-cancellation")
            && (has_obligation("effect-success") || has_obligation("effect-failure")))
    {
        return Err(format!(
            "case {:?} semantic target {:?}/{:?} mixes successful and failed path obligations",
            case.id, target.builtin, target.dimension
        ));
    }
    let normalized_shadow = target
        .obligations
        .iter()
        .any(|obligation| obligation.0.as_ref() == "normalized-shadow-diff");
    let has_shadow_normalizer = target.expected_presentation_shadow_normalizer.is_some();
    let has_shadow_digest = target.expected_normalized_presentation_sha256.is_some();
    if has_shadow_normalizer != has_shadow_digest
        || normalized_shadow != (has_shadow_normalizer && has_shadow_digest)
        || (has_shadow_normalizer
            && (target.dimension != CompatibilityDimension::Presentation
                || target.expected_raw_presentation_sha256.is_none()))
    {
        return Err(format!(
            "case {:?} semantic target {:?}/{:?} has an incomplete or unscoped presentation shadow",
            case.id, target.builtin, target.dimension
        ));
    }
    let allowed_boundaries = runtime_obligations::mandatory_runtime_boundaries()
        .into_iter()
        .filter(|requirement| requirement.builtin == target.builtin)
        .map(|requirement| requirement.class)
        .collect::<BTreeSet<_>>();
    if has_duplicate_values(&target.boundary_classes)
        || target
            .boundary_classes
            .iter()
            .any(|class| !allowed_boundaries.contains(class))
    {
        return Err(format!(
            "case {:?} semantic target {:?} declares an unknown or duplicate boundary class",
            case.id, target.builtin
        ));
    }
    let allowed_interactions = runtime_obligations::mandatory_runtime_interactions()
        .into_iter()
        .filter(|requirement| requirement.builtins.contains(&target.builtin))
        .map(|requirement| requirement.id)
        .collect::<BTreeSet<_>>();
    if has_duplicate_values(&target.interaction_obligations)
        || target
            .interaction_obligations
            .iter()
            .any(|interaction| !allowed_interactions.contains(interaction))
    {
        return Err(format!(
            "case {:?} semantic target {:?} declares an unknown or duplicate interaction",
            case.id, target.builtin
        ));
    }
    Ok(())
}

fn validate_result_force_failure_obligation(
    case: &DifferentialCase,
    target: &EvidenceTargetV2,
) -> Result<(), String> {
    let has_obligation = |name: &str| {
        target
            .obligations
            .iter()
            .any(|obligation| obligation.0.as_ref() == name)
    };
    let result_force_failure = has_obligation("result-force-failure");
    let list_cycle_force_error = target.builtin.as_ref() == "List.cycle"
        && target.expected_typed_result_sha256
            == Some(sha256_bytes(
                b"{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",\"value\":{\"type\":\"ForceBoundary\",\"outcome\":\"error\",\"code\":\"H0901\"}}",
            ));
    let exact_result_force_obligations = target.obligations.len() == 3
        && has_obligation("adapter-success")
        && has_obligation("whnf-boundary")
        && result_force_failure;
    if result_force_failure != list_cycle_force_error
        || (result_force_failure
            && (!exact_result_force_obligations
                || target.causal_signal != CausalSignal::RuntimeAdapterAndForceTrace
                || target.boundary_classes.len() != 1
                || target.boundary_classes[0].as_ref() != "empty-input"
                || target.expected_process_status_sha256
                    != Some(process_status_sha256(false, Some(1)))
                || target.expected_raw_presentation_sha256.is_none()
                || case.expected_runtime_completion
                || has_obligation("adapter-failure")))
    {
        return Err(format!(
            "case {:?} semantic target {:?}/{:?} has an incomplete or contaminated result-force failure proof",
            case.id, target.builtin, target.dimension
        ));
    }
    Ok(())
}

fn validate_semantic_target_crosslinks(
    case: &DifferentialCase,
    descriptor: &ClaimEvidenceDescriptor,
    target_index: usize,
    target: &EvidenceTargetV2,
) -> Result<(), String> {
    if let Some(slug) = case.id.strip_prefix("runtime-options-presentation-") {
        let expected = options_presentation_builtin(slug).ok_or_else(|| {
            format!(
                "case {:?} has an unknown Options Presentation identity",
                case.id
            )
        })?;
        if descriptor.semantic_targets.len() != 1
            || target_index != 0
            || target.dimension != CompatibilityDimension::Presentation
            || target.builtin.as_ref() != expected
        {
            return Err(format!(
                "case {:?} does not bind its exact Options Presentation target",
                case.id
            ));
        }
    }
    if !causal_signal_matches_dimension(target.causal_signal, target.dimension) {
        return Err(format!(
            "case {:?} uses an incompatible causal signal for {:?}",
            case.id, target.dimension
        ));
    }
    if descriptor.semantic_targets[..target_index]
        .iter()
        .any(|prior| prior.builtin == target.builtin && prior.dimension == target.dimension)
    {
        return Err(format!("case {:?} repeats a semantic target", case.id));
    }
    if !descriptor
        .targets
        .iter()
        .any(|legacy| legacy.builtin == target.builtin && legacy.dimension == target.dimension)
    {
        return Err(format!(
            "case {:?} semantic and compatibility targets disagree",
            case.id
        ));
    }
    Ok(())
}

fn options_presentation_builtin(slug: &str) -> Option<&'static str> {
    match slug {
        "command" => Some("Options.command"),
        "exec-parser" => Some("Options.execParser"),
        "flag" => Some("Options.flag"),
        "flag-prime" => Some("Options.flag'"),
        "full-desc" => Some("Options.fullDesc"),
        "header" => Some("Options.header"),
        "helper" => Some("Options.helper"),
        "hsubparser" => Some("Options.hsubparser"),
        "info" => Some("Options.info"),
        "prog-desc" => Some("Options.progDesc"),
        "str-argument" => Some("Options.strArgument"),
        "str-option" => Some("Options.strOption"),
        "switch" => Some("Options.switch"),
        _ => None,
    }
}

fn validate_callback_contracts(
    case: &DifferentialCase,
    descriptor: &ClaimEvidenceDescriptor,
) -> Result<(), String> {
    let callback_targets = descriptor
        .semantic_targets
        .iter()
        .filter(|target| {
            target
                .obligations
                .iter()
                .any(|obligation| obligation.0.as_ref() == "callback-order")
        })
        .map(|target| Arc::clone(&target.builtin))
        .collect::<BTreeSet<_>>();
    let contract_targets = descriptor
        .callback_contracts
        .iter()
        .map(|contract| Arc::clone(&contract.builtin))
        .collect::<BTreeSet<_>>();
    let noncredit_zero_targets = descriptor
        .callback_contracts
        .iter()
        .filter(|contract| {
            contract.invocations.is_empty() && callback_contract_may_be_empty(descriptor, contract)
        })
        .map(|contract| Arc::clone(&contract.builtin))
        .collect::<BTreeSet<_>>();
    let permitted_contract_targets = callback_targets
        .union(&noncredit_zero_targets)
        .cloned()
        .collect::<BTreeSet<_>>();
    if contract_targets.len() != descriptor.callback_contracts.len()
        || contract_targets != permitted_contract_targets
    {
        return Err(format!(
            "case {:?} callback contracts do not exactly match callback-order targets",
            case.id
        ));
    }
    for contract in &descriptor.callback_contracts {
        let spec = hell_builtins::lookup(&contract.builtin)
            .ok_or_else(|| format!("case {:?} callback target disappeared", case.id))?;
        if contract.invocations.is_empty() && !callback_contract_may_be_empty(descriptor, contract)
        {
            return Err(format!(
                "case {:?} callback contract for {:?} is empty",
                case.id, contract.builtin
            ));
        }
        for invocation in &contract.invocations {
            if usize::from(invocation.callback_argument) >= usize::from(spec.arity)
                || !runtime_obligations::callback_identity_allowed(
                    spec.name,
                    invocation.callback_argument,
                    &invocation.branch,
                )
                || !matches!(invocation.outcome.as_ref(), "value" | "error")
                || invocation.canonical_result_sha256 == Digest::default()
                || invocation
                    .canonical_argument_sha256
                    .iter()
                    .any(|digest| *digest == Digest::default())
            {
                return Err(format!(
                    "case {:?} callback contract for {:?} is malformed",
                    case.id, contract.builtin
                ));
            }
        }
    }
    Ok(())
}

fn callback_contract_may_be_empty(
    descriptor: &ClaimEvidenceDescriptor,
    contract: &CallbackContract,
) -> bool {
    let target = |predicate: &dyn Fn(&EvidenceTargetV2) -> bool| {
        descriptor
            .semantic_targets
            .iter()
            .any(|target| target.builtin == contract.builtin && predicate(target))
    };
    let boundary = target(&|target| {
        target.boundary_classes.len() == 1
            && matches!(
                target.boundary_classes[0].as_ref(),
                "empty-input" | "singleton-input"
            )
    });
    let lazy_prefix = contract.builtin.as_ref() == "List.iterate'"
        && target(&|target| {
            target.boundary_classes.is_empty()
                && target
                    .obligations
                    .iter()
                    .any(|obligation| obligation.0.as_ref() == "lazy-boundary")
                && target.expected_raw_presentation_sha256.is_some()
        });
    let bind_short = contract.builtin.as_ref() == "Monad.bind"
        && target(&|target| {
            target
                .obligations
                .iter()
                .any(|obligation| obligation.0.as_ref() == "lazy-boundary")
                && target.expected_raw_presentation_sha256.is_some()
                && target.expected_lazy_argument_exit_sha256.is_some()
        });
    let traversal = matches!(
        contract.builtin.as_ref(),
        "Monad.mapM" | "Monad.mapM_" | "Monad.forM" | "Monad.forM_"
    ) && target(&|target| {
        target.expected_instance_target.is_some()
            && target.expected_typed_result_sha256.is_some()
            && target.expected_raw_presentation_sha256.is_some()
            && target.expected_lazy_argument_exit_sha256.is_some()
    });
    let functor = matches!(contract.builtin.as_ref(), "Functor.fmap" | "<$>")
        && target(&|target| {
            target.expected_instance_target.is_some()
                && target.expected_raw_presentation_sha256.is_some()
                && target.expected_process_status_sha256.is_some()
                && target.expected_lazy_argument_exit_sha256.is_some()
                && target
                    .obligations
                    .iter()
                    .any(|obligation| obligation.0.as_ref() == "callback-order")
        });
    let applicative = matches!(contract.builtin.as_ref(), "<*>" | "<**>")
        && target(&|target| {
            target.expected_instance_target.is_some()
                && target.expected_raw_presentation_sha256.is_some()
                && target.expected_process_status_sha256.is_some()
                && target.expected_lazy_argument_exit_sha256.is_some()
                && target
                    .obligations
                    .iter()
                    .any(|obligation| obligation.0.as_ref() == "lazy-boundary")
                && !target
                    .obligations
                    .iter()
                    .any(|obligation| obligation.0.as_ref() == "callback-order")
        });
    boundary
        || lazy_prefix
        || bind_short
        || traversal
        || functor
        || applicative
        || callback_contract_empty_for_collection_or_pool(descriptor, contract)
}

fn callback_contract_empty_for_collection_or_pool(
    descriptor: &ClaimEvidenceDescriptor,
    contract: &CallbackContract,
) -> bool {
    let target = |predicate: &dyn Fn(&EvidenceTargetV2) -> bool| {
        descriptor
            .semantic_targets
            .iter()
            .any(|target| target.builtin == contract.builtin && predicate(target))
    };
    let ord_map = matches!(
        contract.builtin.as_ref(),
        "Map.insertWith" | "Map.adjust" | "Map.unionWith"
    ) && target(&|target| {
        target.boundary_classes.is_empty()
            && target.expected_instance_target.is_some()
            && target.expected_typed_result_sha256.is_some()
            && target.expected_raw_presentation_sha256.is_some()
            && target.expected_process_status_sha256.is_some()
            && target
                .obligations
                .iter()
                .any(|obligation| obligation.0.as_ref() == "callback-order")
    });
    let pooled = matches!(
        contract.builtin.as_ref(),
        "Async.pooledMapConcurrently"
            | "Async.pooledMapConcurrently_"
            | "Async.pooledForConcurrently"
            | "Async.pooledForConcurrently_"
    ) && target(&|target| {
        target.dimension == CompatibilityDimension::PureRuntime
            && target.expected_raw_presentation_sha256.is_some()
            && target.expected_process_status_sha256.is_some()
            && target.expected_task_trace_sha256
                == Some(task_trace_sha256(std::iter::empty::<(usize, &str)>()))
            && target
                .obligations
                .iter()
                .map(|obligation| obligation.0.as_ref())
                .eq(["adapter-success"])
    });
    ord_map || pooled
}

fn required_obligation_catalog(dimension: CompatibilityDimension) -> &'static [&'static str] {
    use hell_builtins::assurance_catalogs as catalog;
    match dimension {
        CompatibilityDimension::Parse => &["source-or-generated-syntax-path"],
        CompatibilityDimension::StaticSemantics => &["resolved-typed-builtin-id"],
        CompatibilityDimension::PureRuntime => catalog::PURE_RUNTIME_OBLIGATIONS,
        CompatibilityDimension::Effects => catalog::EFFECT_OBLIGATIONS,
        CompatibilityDimension::Concurrency => catalog::CONCURRENCY_OBLIGATIONS,
        CompatibilityDimension::Presentation => catalog::PRESENTATION_OBLIGATIONS,
        CompatibilityDimension::Platform => catalog::PLATFORM_OBLIGATIONS,
        CompatibilityDimension::ResourceBehavior => catalog::RESOURCE_OBLIGATIONS,
    }
}

/// Returns the exact registry-derived obligations for one applicable target.
///
/// # Errors
///
/// Returns an error when the builtin is unknown or the dimension is not an
/// applicable runtime cell for that builtin.
pub fn required_obligations_for_target(
    builtin: &str,
    dimension: CompatibilityDimension,
) -> Result<BTreeSet<Arc<str>>, String> {
    if matches!(
        dimension,
        CompatibilityDimension::Parse | CompatibilityDimension::StaticSemantics
    ) {
        return Ok(required_obligation_catalog(dimension)
            .iter()
            .map(|obligation| Arc::<str>::from(*obligation))
            .collect());
    }
    let spec = hell_builtins::lookup(builtin)
        .ok_or_else(|| format!("runtime obligation target names unknown builtin {builtin:?}"))?;
    let cells = runtime_obligation_cells_for_spec(spec);
    let cell = cells
        .iter()
        .find(|cell| cell.dimension == dimension)
        .ok_or_else(|| format!("{builtin:?}/{dimension:?} is not an applicable runtime cell"))?;
    Ok(cell
        .obligations
        .iter()
        .map(|obligation| Arc::clone(&obligation.0))
        .collect())
}

#[derive(Clone, Default)]
struct RuntimeCoverageObservations {
    obligations: HashMap<RuntimeCoverageKey, BTreeSet<Arc<str>>>,
    boundaries: HashMap<RuntimeBoundaryKey, BTreeSet<Arc<str>>>,
    boundary_sources: HashMap<RuntimeBoundarySourceKey, Arc<str>>,
    interactions: HashMap<Arc<str>, BTreeSet<Arc<str>>>,
    boolean_outcomes: HashMap<RuntimeBoundaryKey, BTreeSet<bool>>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum RuntimeInstanceScope {
    Unconstrained,
    Resolved(Arc<str>),
}

impl RuntimeInstanceScope {
    fn label(&self) -> &str {
        match self {
            Self::Unconstrained => "unconstrained",
            Self::Resolved(target) => target,
        }
    }
}

type RuntimeCoverageKey = (Arc<str>, CompatibilityDimension, RuntimeInstanceScope);
type RuntimeBoundaryKey = (Arc<str>, RuntimeInstanceScope);
type RuntimeBoundarySourceKey = (Arc<str>, RuntimeInstanceScope, String);

fn runtime_coverage_observations(
    cases: &[DifferentialCase],
) -> Result<RuntimeCoverageObservations, String> {
    let mut observations = RuntimeCoverageObservations::default();
    for (case, descriptor) in cases.iter().filter_map(|case| {
        case.claim_evidence
            .as_ref()
            .map(|descriptor| (case, descriptor))
    }) {
        for target in &descriptor.semantic_targets {
            if matches!(
                target.dimension,
                CompatibilityDimension::Parse | CompatibilityDimension::StaticSemantics
            ) {
                continue;
            }
            record_runtime_target(&mut observations, case, descriptor, target)?;
        }
    }
    Ok(observations)
}

fn record_runtime_target(
    observations: &mut RuntimeCoverageObservations,
    case: &DifferentialCase,
    descriptor: &ClaimEvidenceDescriptor,
    target: &EvidenceTargetV2,
) -> Result<(), String> {
    let Some(instance_target) = runtime_target_instance_scope(target) else {
        return Ok(());
    };
    observations
        .obligations
        .entry((
            Arc::clone(&target.builtin),
            target.dimension,
            instance_target.clone(),
        ))
        .or_default()
        .extend(
            target
                .obligations
                .iter()
                .filter(|obligation| {
                    obligation.0.as_ref() != "callback-order"
                        || descriptor.callback_contracts.iter().any(|contract| {
                            contract.builtin == target.builtin && !contract.invocations.is_empty()
                        })
                })
                .map(|obligation| Arc::clone(&obligation.0)),
        );
    observations
        .boundaries
        .entry((Arc::clone(&target.builtin), instance_target.clone()))
        .or_default()
        .extend(target.boundary_classes.iter().cloned());
    record_boolean_outcome(&mut observations.boolean_outcomes, target, &instance_target);
    for class in &target.boundary_classes {
        let execution_input = artifact::execution_input_json(case).map_err(|error| {
            format!(
                "case {:?} has noncanonical boundary input: {error}",
                case.id
            )
        })?;
        let evidence_identity = sha256_bytes(
            format!(
                "runtime-boundary-evidence-v1\nsource-sha256={}\nexecution-input={}",
                descriptor.source_sha256.hex(),
                execution_input
            )
            .as_bytes(),
        )
        .hex();
        let key = (
            Arc::clone(&target.builtin),
            instance_target.clone(),
            evidence_identity,
        );
        if observations
            .boundary_sources
            .insert(key, Arc::clone(class))
            .is_some_and(|prior| prior != *class)
        {
            return Err(format!(
                "case {:?} reuses one source observation across distinct boundary classes for {:?}",
                case.id, target.builtin
            ));
        }
    }
    for interaction in &target.interaction_obligations {
        observations
            .interactions
            .entry(Arc::clone(interaction))
            .or_default()
            .insert(Arc::clone(&target.builtin));
    }
    Ok(())
}

fn runtime_target_instance_scope(target: &EvidenceTargetV2) -> Option<RuntimeInstanceScope> {
    let spec = hell_builtins::lookup(&target.builtin)?;
    let Some(class) = spec.type_class else {
        return Some(RuntimeInstanceScope::Unconstrained);
    };
    let instance_target = target.expected_instance_target.as_ref()?;
    validate_instance_premise_tree(class, instance_target, &target.expected_instance_premises)
        .ok()
        .map(|()| RuntimeInstanceScope::Resolved(Arc::clone(instance_target)))
}

fn validate_instance_premise_tree(
    class: hell_builtins::TypeClass,
    root: &str,
    premises: &[InstancePremiseEvidence],
) -> Result<(), String> {
    let root = hell_builtins::instance(class, root)
        .ok_or_else(|| "instance evidence root is not registry-backed".to_owned())?;
    let mut open = usize::from(root.resolution.premise_count());
    for premise in premises {
        if open == 0 {
            return Err("instance evidence contains a trailing premise".to_owned());
        }
        open -= 1;
        let spec = hell_builtins::instance(class, &premise.target)
            .ok_or_else(|| "instance evidence premise is not registry-backed".to_owned())?;
        if premise.premise_count != spec.resolution.premise_count() {
            return Err("instance evidence premise count disagrees with the manifest".to_owned());
        }
        open = open
            .checked_add(usize::from(premise.premise_count))
            .ok_or_else(|| "instance evidence premise count overflowed".to_owned())?;
    }
    if open != 0 {
        return Err("instance evidence omits a recursive premise".to_owned());
    }
    Ok(())
}

fn record_boolean_outcome(
    outcomes: &mut HashMap<RuntimeBoundaryKey, BTreeSet<bool>>,
    target: &EvidenceTargetV2,
    instance_target: &RuntimeInstanceScope,
) {
    if !boolean_outcome_partition_required(&target.builtin)
        || target.dimension != CompatibilityDimension::PureRuntime
    {
        return;
    }
    for value in [true, false] {
        if target.expected_typed_result_sha256 == Some(boolean_typed_result_digest(value)) {
            outcomes
                .entry((Arc::clone(&target.builtin), instance_target.clone()))
                .or_default()
                .insert(value);
        }
    }
}

/// Requires every applicable public runtime cell and every registry-derived
/// obligation to have an exact committed descriptor target.
///
/// # Errors
///
/// Returns the complete missing or unexpected cell set after the ordinary
/// descriptor validator succeeds.
pub fn validate_runtime_obligation_coverage(cases: &[DifferentialCase]) -> Result<(), String> {
    validate_evidence_catalog(cases)?;
    let observations = runtime_coverage_observations(cases)?;
    validate_runtime_obligation_observations(&observations)
}

fn validate_runtime_obligation_observations(
    observations: &RuntimeCoverageObservations,
) -> Result<(), String> {
    let expected = applicable_runtime_obligation_cells();
    let missing = expected
        .iter()
        .filter_map(|cell| {
            let required = cell
                .obligations
                .iter()
                .map(|obligation| Arc::clone(&obligation.0))
                .collect::<BTreeSet<_>>();
            let scopes = required_runtime_instance_scopes(&cell.builtin);
            let incomplete_scopes = scopes
                .iter()
                .filter_map(|scope| {
                    let key = (Arc::clone(&cell.builtin), cell.dimension, scope.clone());
                    let present = observations
                        .obligations
                        .get(&key)
                        .cloned()
                        .unwrap_or_default();
                    let boolean_partition_missing = cell.dimension
                        == CompatibilityDimension::PureRuntime
                        && boolean_outcome_partition_required(&cell.builtin)
                        && observations
                            .boolean_outcomes
                            .get(&(Arc::clone(&cell.builtin), scope.clone()))
                            .is_none_or(|outcomes| {
                                !outcomes.contains(&true) || !outcomes.contains(&false)
                            });
                    (present != required || boolean_partition_missing).then(|| {
                        format!(
                            "{}:missing={:?},bool-partition={boolean_partition_missing}",
                            scope.label(),
                            required.difference(&present).collect::<Vec<_>>()
                        )
                    })
                })
                .collect::<Vec<_>>();
            (!incomplete_scopes.is_empty()).then(|| {
                format!(
                    "{}/{:?}: instance-scopes=[{}]",
                    cell.builtin,
                    cell.dimension,
                    incomplete_scopes.join(", ")
                )
            })
        })
        .collect::<Vec<_>>();
    let boundary_gaps = runtime_boundary_gaps(observations);
    let interaction_gaps = runtime_interaction_gaps(observations);
    if missing.is_empty() && boundary_gaps.is_empty() && interaction_gaps.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "runtime obligation coverage has {} incomplete cells, {} boundary gaps, and {} interaction gaps: cells=[{}]; boundaries=[{}]; interactions=[{}]",
            missing.len(),
            boundary_gaps.len(),
            interaction_gaps.len(),
            missing.join("; "),
            boundary_gaps.join("; "),
            interaction_gaps.join("; "),
        ))
    }
}

/// Verifies every registry-derived `Ord` instance retains both Boolean outcomes.
///
/// This integration seam builds and validates the immutable committed observation index once,
/// then checks each omitted outcome against the same validator used by
/// [`validate_runtime_obligation_coverage`].
///
/// # Errors
///
/// Returns the exact missing registry scope or an unexpected coverage diagnostic.
#[doc(hidden)]
pub fn verify_committed_ord_boolean_partition_for_integration() -> Result<(), String> {
    let cases = committed_differential_cases();
    validate_evidence_catalog(&cases)?;
    let baseline = runtime_coverage_observations(&cases)?;
    for builtin in ["Ord.lt", "Ord.gt"] {
        for scope in required_runtime_instance_scopes(builtin) {
            let RuntimeInstanceScope::Resolved(instance) = &scope else {
                return Err(format!(
                    "{builtin} unexpectedly has an unconstrained instance"
                ));
            };
            for result in [true, false] {
                let key = (Arc::<str>::from(builtin), scope.clone());
                let baseline_outcomes = baseline.boolean_outcomes.get(&key).ok_or_else(|| {
                    format!("committed {builtin}/{instance} has no Boolean outcomes")
                })?;
                if !baseline_outcomes.contains(&result) {
                    return Err(format!(
                        "committed {builtin}/{instance} omits Boolean outcome {result}"
                    ));
                }
                let mut omitted = baseline.clone();
                omitted
                    .boolean_outcomes
                    .get_mut(&key)
                    .expect("baseline outcome key was cloned")
                    .remove(&result);
                let error = validate_runtime_obligation_observations(&omitted).map_or_else(
                    |error| error,
                    |()| format!("removing {builtin}/{instance}/{result} did not reopen its scope"),
                );
                let expected_cell = format!(
                    "{builtin}/PureRuntime: instance-scopes=[{instance}:missing=[],bool-partition=true]"
                );
                if !error.contains(&expected_cell) {
                    return Err(format!(
                        "unexpected {builtin}/{instance}/{result} diagnostic: {error}"
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Returns whether one exact runtime instance scope contains every required obligation.
///
/// # Errors
///
/// Returns an error when retained descriptors are invalid or the requested runtime cell is not
/// part of the applicable obligation catalog.
pub fn runtime_obligation_scope_complete(
    cases: &[DifferentialCase],
    builtin: &str,
    dimension: CompatibilityDimension,
    instance_target: &str,
) -> Result<bool, String> {
    let observations = runtime_coverage_observations(cases)?;
    let cell = applicable_runtime_obligation_cells()
        .into_iter()
        .find(|cell| cell.builtin.as_ref() == builtin && cell.dimension == dimension)
        .ok_or_else(|| "runtime obligation cell is not applicable".to_owned())?;
    let scope = RuntimeInstanceScope::Resolved(Arc::from(instance_target));
    let required = cell
        .obligations
        .iter()
        .map(|obligation| Arc::clone(&obligation.0))
        .collect::<BTreeSet<_>>();
    let present = observations
        .obligations
        .get(&(Arc::clone(&cell.builtin), dimension, scope))
        .cloned()
        .unwrap_or_default();
    Ok(present == required)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivatedCollectionScopeCoverage {
    pub exact_complete_scopes: BTreeSet<String>,
    pub residual_incomplete_cells: usize,
    pub boundary_gaps: usize,
    pub interaction_gaps: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivatedCollectionClaimScope {
    pub scope: String,
    pub builtin: String,
    pub case_refs: BTreeSet<String>,
    pub required_platforms: [ClaimPlatform; 3],
    pub fresh_evidence_required: bool,
}

/// Returns the exact 14 reviewed collection scopes and their 1,191 case references.
///
/// # Errors
///
/// Returns an error if the reviewed collection corpus is missing evidence, has ambiguous targets,
/// or no longer partitions into the exact Map712/Set479 scope inventory.
pub fn activated_collection_claim_scopes() -> Result<Vec<ActivatedCollectionClaimScope>, String> {
    let mut grouped = BTreeMap::<String, BTreeSet<String>>::new();
    for case in reviewed_collection_cases()? {
        let descriptor = case
            .claim_evidence
            .ok_or_else(|| "activated collection case lacks claim evidence".to_owned())?;
        let [target] = descriptor.semantic_targets.as_slice() else {
            return Err("activated collection case does not bind one exact scope".to_owned());
        };
        grouped
            .entry(target.builtin.to_string())
            .or_default()
            .insert(case.id.to_string());
    }
    let scopes = grouped
        .into_iter()
        .map(|(builtin, case_refs)| ActivatedCollectionClaimScope {
            scope: format!("{builtin}|pure-runtime|upstream|linux,macos,windows"),
            builtin,
            case_refs,
            required_platforms: [
                ClaimPlatform::Linux,
                ClaimPlatform::MacOs,
                ClaimPlatform::Windows,
            ],
            fresh_evidence_required: true,
        })
        .collect::<Vec<_>>();
    if scopes.len() != 14
        || scopes
            .iter()
            .map(|scope| scope.case_refs.len())
            .sum::<usize>()
            != 1_191
    {
        return Err("activated collection claim scopes are not exact Map712/Set479".to_owned());
    }
    Ok(scopes)
}

/// Verifies exact scoped collection completeness while retaining the unrelated 120 residual cells.
///
/// # Errors
///
/// Returns an error unless all 14 activated scopes are complete and the global residual remains
/// exactly 120 incomplete cells with zero boundary or interaction gaps.
pub fn activated_collection_scope_completeness(
    cases: &[DifferentialCase],
) -> Result<ActivatedCollectionScopeCoverage, String> {
    let collection = reviewed_collection_cases()?;
    let mut targets = BTreeMap::<String, BTreeSet<String>>::new();
    for case in &collection {
        let descriptor = case
            .claim_evidence
            .as_ref()
            .ok_or_else(|| "activated collection case lacks claim evidence".to_owned())?;
        let [target] = descriptor.semantic_targets.as_slice() else {
            return Err("activated collection case does not bind one exact scope".to_owned());
        };
        let instance = target
            .expected_instance_target
            .as_deref()
            .ok_or_else(|| "activated collection scope lacks an instance target".to_owned())?;
        if descriptor.profile != ExecutionProfile::Upstream
            || target.dimension != CompatibilityDimension::PureRuntime
        {
            return Err("activated collection scope lacks exact fresh completeness".to_owned());
        }
        targets
            .entry(target.builtin.to_string())
            .or_default()
            .insert(instance.to_owned());
    }
    if targets.len() != 14 {
        return Err("activated collection scope set is not exactly 14 cells".to_owned());
    }
    let observations = runtime_coverage_observations(cases)?;
    let cells = applicable_runtime_obligation_cells();
    let mut scopes = BTreeSet::new();
    for (builtin, instances) in targets {
        let cell = cells
            .iter()
            .find(|cell| {
                cell.builtin.as_ref() == builtin
                    && cell.dimension == CompatibilityDimension::PureRuntime
            })
            .ok_or_else(|| "activated collection runtime cell is not applicable".to_owned())?;
        let required = cell
            .obligations
            .iter()
            .map(|obligation| Arc::clone(&obligation.0))
            .collect::<BTreeSet<_>>();
        for instance in instances {
            let key = (
                Arc::clone(&cell.builtin),
                cell.dimension,
                RuntimeInstanceScope::Resolved(Arc::from(instance)),
            );
            if observations.obligations.get(&key) != Some(&required) {
                return Err("activated collection scope lacks exact fresh completeness".to_owned());
            }
        }
        scopes.insert(format!(
            "{builtin}|pure-runtime|upstream|linux,macos,windows"
        ));
    }
    let error = match validate_runtime_obligation_coverage(cases) {
        Ok(()) => {
            return Err(
                "collection scope activation unexpectedly closes unrelated runtime cells"
                    .to_owned(),
            );
        }
        Err(error) => error,
    };
    let prefix = "runtime obligation coverage has 120 incomplete cells, 0 boundary gaps, and 0 interaction gaps:";
    if !error.starts_with(prefix) {
        return Err("activated collection residual coverage differs from 120/0/0".to_owned());
    }
    Ok(ActivatedCollectionScopeCoverage {
        exact_complete_scopes: scopes,
        residual_incomplete_cells: 120,
        boundary_gaps: 0,
        interaction_gaps: 0,
    })
}

fn boolean_outcome_partition_required(builtin: &str) -> bool {
    matches!(
        builtin,
        "Int.eq"
            | "Double.eq"
            | "Text.eq"
            | "Eq.eq"
            | "Ord.lt"
            | "Ord.gt"
            | "List.all"
            | "Text.all"
    )
}

fn boolean_typed_result_digest(value: bool) -> Digest {
    let canonical = format!(
        "{{\"type\":\"TypedResult\",\"argument\":0,\"boundary\":\"adapter-result\",\"value\":{{\"type\":\"Bool\",\"value\":{value}}}}}"
    );
    sha256_bytes(canonical.as_bytes())
}

fn required_runtime_instance_scopes(builtin: &str) -> Vec<RuntimeInstanceScope> {
    let spec = hell_builtins::lookup(builtin).expect("runtime target remains registry-backed");
    let Some(class) = spec.type_class else {
        return vec![RuntimeInstanceScope::Unconstrained];
    };
    hell_builtins::instances()
        .iter()
        .filter(|instance| instance.class == class)
        .map(|instance| RuntimeInstanceScope::Resolved(Arc::from(instance.target)))
        .collect()
}

fn runtime_boundary_gaps(observations: &RuntimeCoverageObservations) -> Vec<String> {
    runtime_obligations::mandatory_runtime_boundaries()
        .into_iter()
        .fold(
            HashMap::<Arc<str>, BTreeSet<Arc<str>>>::new(),
            |mut requirements, requirement| {
                requirements
                    .entry(requirement.builtin)
                    .or_default()
                    .insert(requirement.class);
                requirements
            },
        )
        .into_iter()
        .filter_map(|(builtin, required)| {
            let incomplete = required_runtime_instance_scopes(&builtin)
                .into_iter()
                .filter_map(|scope| {
                    let scoped_required =
                        required_runtime_boundary_classes(&builtin, &scope, &required);
                    let present = observations
                        .boundaries
                        .get(&(Arc::clone(&builtin), scope.clone()))
                        .cloned()
                        .unwrap_or_default();
                    (present != scoped_required).then(|| {
                        format!(
                            "{}:missing={:?},unexpected={:?}",
                            scope.label(),
                            scoped_required.difference(&present).collect::<Vec<_>>(),
                            present.difference(&scoped_required).collect::<Vec<_>>()
                        )
                    })
                })
                .collect::<Vec<_>>();
            (!incomplete.is_empty())
                .then(|| format!("{builtin}: instance-scopes=[{}]", incomplete.join(", ")))
        })
        .collect()
}

fn required_runtime_boundary_classes(
    builtin: &str,
    scope: &RuntimeInstanceScope,
    required: &BTreeSet<Arc<str>>,
) -> BTreeSet<Arc<str>> {
    if builtin == "CI.mk" && scope == &RuntimeInstanceScope::Resolved(Arc::from("Text")) {
        required
            .iter()
            .filter(|class| class.as_ref() != "invalid-encoding")
            .cloned()
            .collect()
    } else {
        required.clone()
    }
}

fn runtime_interaction_gaps(observations: &RuntimeCoverageObservations) -> Vec<String> {
    runtime_obligations::mandatory_runtime_interactions()
        .into_iter()
        .map(|requirement| {
            (
                requirement.id,
                requirement.builtins.into_iter().collect::<BTreeSet<_>>(),
            )
        })
        .filter_map(|(interaction, required)| {
            let present = observations
                .interactions
                .get(&interaction)
                .cloned()
                .unwrap_or_default();
            (present != required).then(|| {
                format!(
                    "{interaction}: missing={:?}, unexpected={:?}",
                    required.difference(&present).collect::<Vec<_>>(),
                    present.difference(&required).collect::<Vec<_>>()
                )
            })
        })
        .collect()
}

fn causal_signal_matches_dimension(
    signal: CausalSignal,
    dimension: CompatibilityDimension,
) -> bool {
    matches!(
        (signal, dimension),
        (CausalSignal::ParsedBuiltin, CompatibilityDimension::Parse)
            | (
                CausalSignal::ResolvedBuiltin,
                CompatibilityDimension::StaticSemantics
            )
            | (
                CausalSignal::RuntimeAdapterAndForceTrace
                    | CausalSignal::RuntimeAdapter
                    | CausalSignal::ForceTrace,
                CompatibilityDimension::PureRuntime
            )
            | (CausalSignal::EffectEvent, CompatibilityDimension::Effects)
            | (
                CausalSignal::TaskAndCancellation,
                CompatibilityDimension::Concurrency
            )
            | (
                CausalSignal::PresentationField,
                CompatibilityDimension::Presentation
            )
            | (
                CausalSignal::RuntimeAdapter,
                CompatibilityDimension::Platform
            )
            | (
                CausalSignal::RuntimeAdapter
                    | CausalSignal::TaskAndCancellation
                    | CausalSignal::ResourceLifecycle,
                CompatibilityDimension::ResourceBehavior
            )
    )
}

fn has_duplicate_values<T: PartialEq>(values: &[T]) -> bool {
    values
        .iter()
        .enumerate()
        .any(|(index, value)| values[..index].contains(value))
}

fn applied_harness_normalizers() -> Vec<NormalizerId> {
    vec![NormalizerId::DiagnosticSandboxPathV1]
}

fn applied_claim_normalizers(case: &DifferentialCase) -> Vec<NormalizerId> {
    if case.normalization.normalize_path_separators {
        vec![NormalizerId::DiagnosticPathSeparatorV1]
    } else {
        Vec::new()
    }
}

/// Applies the selected production normalizer twice to retained observation bytes.
///
/// The second pass consumes the first pass exactly, so callers can retain both
/// outputs and independently certify idempotence without reimplementing either
/// normalizer.
#[must_use]
pub fn apply_retained_normalizer_twice(input: RetainedNormalizerInput<'_>) -> NormalizerPasses {
    let apply = |observation: &[u8]| match input.normalizer {
        NormalizerId::DiagnosticSandboxPathV1 => {
            diagnostic_sandbox_path_v1(observation, input.executable, input.sandbox, input.script)
        }
        NormalizerId::DiagnosticPathSeparatorV1 => {
            let mut normalized = observation.to_vec();
            diagnostic_path_separator_v1(&mut normalized);
            normalized
        }
    };
    let first_pass = apply(input.observation);
    let second_pass = apply(&first_pass);
    NormalizerPasses {
        first_pass,
        second_pass,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MismatchKind {
    Timeout,
    ExitStatus,
    Stdout,
    Stderr,
    Diagnostic,
    Filesystem,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DifferentialMismatch {
    pub kind: MismatchKind,
    pub oracle: Vec<u8>,
    pub candidate: Vec<u8>,
}

/// A reviewed projection that excludes one raw observation field from the
/// authoritative compatibility comparison while retaining both exact sides.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DifferentialComparisonProjection {
    Exact,
    ReviewedRuntimeFailureStderr {
        oracle_sha256: Digest,
        candidate_sha256: Digest,
        oracle_bytes: u64,
        candidate_bytes: u64,
    },
    ReviewedRuntimeFailureExceptionStderr {
        exception_family: RuntimeFailureExceptionFamily,
        payload_sha256: Digest,
        oracle_sha256: Digest,
        candidate_sha256: Digest,
        oracle_bytes: u64,
        candidate_bytes: u64,
    },
    ReviewedWindowsPresentation {
        platform: ClaimPlatform,
        field: WindowsPresentationField,
        oracle_sha256: Digest,
        candidate_sha256: Digest,
        oracle_bytes: u64,
        candidate_bytes: u64,
    },
    ReviewedWindowsDivergence {
        case_id: &'static str,
        builtin: &'static str,
        mismatch_sha256: Digest,
        mismatch_kinds: &'static [MismatchKind],
        rationale: &'static str,
    },
}

/// The exact upstream exception wrapper admitted by one reviewed failure case.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeFailureExceptionFamily {
    UnicodeException,
    IOException,
    ErrorCall,
}

impl RuntimeFailureExceptionFamily {
    #[must_use]
    pub const fn descriptor_name(self) -> &'static str {
        match self {
            Self::UnicodeException => "unicode-exception",
            Self::IOException => "io-exception",
            Self::ErrorCall => "error-call",
        }
    }
}

/// Exact stage at which a reviewed runtime-failure stderr projection was
/// rejected. This is diagnostic evidence only; it does not authorize a
/// projection or alter the comparison result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeFailureProjectionRejectionReason {
    DescriptorTable,
    ObservationAuthority,
    MissingOracleStderr,
    MissingCandidateStderr,
    MissingCandidateSemantic,
    OracleParserStage,
    OracleExceptionFamily,
    OraclePayloadHandlingMissing,
    OraclePayloadHandlingMismatch,
    OraclePayloadUnexpectedHandling,
    OraclePayloadEmpty,
    OraclePayloadMultiline,
    OraclePayloadControl,
    OracleFrameGrammar,
    OracleFrameTerminalNewline,
    OracleFrameCount,
    OracleFrameFunction,
    OracleFrameOrigin,
    CandidateLegacyParser,
    CandidatePayload,
    CandidateFrame,
    PayloadMismatch,
    SemanticTarget,
    SemanticCausality,
}

impl RuntimeFailureProjectionRejectionReason {
    #[must_use]
    pub const fn descriptor_name(self) -> &'static str {
        match self {
            Self::DescriptorTable => "descriptor-table",
            Self::ObservationAuthority => "observation-authority",
            Self::MissingOracleStderr => "missing-oracle-stderr",
            Self::MissingCandidateStderr => "missing-candidate-stderr",
            Self::MissingCandidateSemantic => "missing-candidate-semantic",
            Self::OracleParserStage => "oracle-parser-stage",
            Self::OracleExceptionFamily => "oracle-exception-family",
            Self::OraclePayloadHandlingMissing => "oracle-payload-handling-missing",
            Self::OraclePayloadHandlingMismatch => "oracle-payload-handling-mismatch",
            Self::OraclePayloadUnexpectedHandling => "oracle-payload-unexpected-handling",
            Self::OraclePayloadEmpty => "oracle-payload-empty",
            Self::OraclePayloadMultiline => "oracle-payload-multiline",
            Self::OraclePayloadControl => "oracle-payload-control",
            Self::OracleFrameGrammar => "oracle-frame-grammar",
            Self::OracleFrameTerminalNewline => "oracle-frame-terminal-newline",
            Self::OracleFrameCount => "oracle-frame-count",
            Self::OracleFrameFunction => "oracle-frame-function",
            Self::OracleFrameOrigin => "oracle-frame-origin",
            Self::CandidateLegacyParser => "candidate-legacy-parser",
            Self::CandidatePayload => "candidate-payload",
            Self::CandidateFrame => "candidate-frame",
            Self::PayloadMismatch => "payload-mismatch",
            Self::SemanticTarget => "semantic-target",
            Self::SemanticCausality => "semantic-causality",
        }
    }
}

/// Bounded, non-secret diagnostic evidence for one rejected exact-table
/// runtime-failure projection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeFailureProjectionRejection {
    pub reason: RuntimeFailureProjectionRejectionReason,
    pub exception_family: RuntimeFailureExceptionFamily,
    pub descriptor_builtin: &'static str,
    pub descriptor_dimension: CompatibilityDimension,
    pub descriptor_obligation: &'static str,
    pub oracle_stderr_sha256: Digest,
    pub oracle_stderr_bytes: u64,
    pub candidate_stderr_sha256: Digest,
    pub candidate_stderr_bytes: u64,
    pub semantic_present: bool,
    pub typed_result_sha256_present: bool,
    pub typed_result_builtin_present: bool,
    pub semantic_coverage_count: usize,
    pub obligation_event_count: usize,
    pub causal_order_count: usize,
    pub force_event_count: usize,
    pub effect_event_count: usize,
    pub task_event_count: usize,
    pub resource_event_count: usize,
}

/// One bounded, parser-normalized exception payload component.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeFailurePayloadComponentDiagnostic {
    pub bytes: u64,
    pub sha256: Digest,
    pub utf8_prefix: String,
    pub prefix_truncated: bool,
}

/// The oracle component selected by the production exception projection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeFailureOraclePayloadSelection {
    Outer,
    Handling,
}

impl RuntimeFailureOraclePayloadSelection {
    #[must_use]
    pub const fn descriptor_name(self) -> &'static str {
        match self {
            Self::Outer => "outer",
            Self::Handling => "handling",
        }
    }
}

/// Exact relationship between the selected oracle payload and candidate payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeFailurePayloadRelationship {
    Selected,
    Outer,
    Handling,
    Distinct,
}

impl RuntimeFailurePayloadRelationship {
    #[must_use]
    pub const fn descriptor_name(self) -> &'static str {
        match self {
            Self::Selected => "candidate-matches-selected",
            Self::Outer => "candidate-matches-oracle-outer",
            Self::Handling => "candidate-matches-oracle-handling",
            Self::Distinct => "candidate-distinct-from-oracle-components",
        }
    }
}

/// Bounded parsed payload evidence for an exact-table projection rejection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeFailurePayloadDiagnostic {
    pub mismatch_field: &'static str,
    pub handling_projection: &'static str,
    pub oracle_selection: RuntimeFailureOraclePayloadSelection,
    pub relationship: RuntimeFailurePayloadRelationship,
    pub oracle_outer: RuntimeFailurePayloadComponentDiagnostic,
    pub oracle_handling: Option<RuntimeFailurePayloadComponentDiagnostic>,
    pub oracle_selected: RuntimeFailurePayloadComponentDiagnostic,
    pub candidate: RuntimeFailurePayloadComponentDiagnostic,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RuntimeFailurePresentationAuthority {
    pub family: RuntimeFailureExceptionFamily,
    pub builtin: BuiltinId,
    pub builtin_name: &'static str,
    pub dimension: CompatibilityDimension,
    pub obligation: &'static str,
    pub while_handling: RuntimeFailureHandlingProjection,
    oracle_frame_functions: &'static [&'static str],
    oracle_frame_layout: RuntimeFailureOracleFrameLayout,
    candidate_frame_functions: &'static [&'static str],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RuntimeFailureHandlingProjection {
    None,
    Payload,
    Prefix(&'static str),
    AfterPathPrefix(&'static str),
}

impl RuntimeFailureHandlingProjection {
    const fn descriptor_name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Payload => "payload",
            Self::Prefix(_) => "prefix",
            Self::AfterPathPrefix(_) => "after-path-prefix",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RuntimeFailureOracleFrameLayout {
    Ghc,
    Frameless,
}

#[derive(Clone, Copy)]
struct RuntimeFailurePresentationSpec {
    family: RuntimeFailureExceptionFamily,
    builtin: &'static str,
    dimension: CompatibilityDimension,
    obligation: &'static str,
    while_handling: RuntimeFailureHandlingProjection,
    oracle_frame_functions: &'static [&'static str],
    oracle_frame_layout: RuntimeFailureOracleFrameLayout,
    candidate_frame_functions: &'static [&'static str],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DifferentialReport {
    pub oracle: Observation,
    pub candidate: Observation,
    pub comparison_projection: DifferentialComparisonProjection,
    pub mismatches: Vec<DifferentialMismatch>,
}

/// Monotonic timing telemetry for one differential case.
///
/// Timing never participates in observation comparison or release decisions.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DifferentialTiming {
    pub oracle_process: Duration,
    pub candidate_process: Duration,
    pub driver_overhead: Duration,
}

/// One authoritative differential report plus non-authoritative timing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimedDifferentialReport {
    pub report: DifferentialReport,
    pub timing: DifferentialTiming,
}

/// Aggregate non-authoritative timing for one authoritative ordered batch.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DifferentialBatchTiming {
    pub case_count: usize,
    pub completed_count: usize,
    pub worker_count: usize,
    pub wall: Duration,
    /// Sum of per-case oracle subprocess wall time. This can exceed batch wall
    /// time when workers overlap.
    pub oracle_process_sum: Duration,
    /// Sum of per-case candidate subprocess wall time. This can exceed batch
    /// wall time when workers overlap.
    pub candidate_process_sum: Duration,
    /// Sum of per-case harness/normalization time excluding both subprocesses.
    pub driver_overhead_sum: Duration,
}

/// Complete ordered results plus telemetry that does not affect conformance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DifferentialBatchReport {
    pub reports: Vec<DifferentialReport>,
    pub case_timings: Vec<DifferentialTiming>,
    pub timing: DifferentialBatchTiming,
}

/// Lowest authoritative batch failure after every worker has joined.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DifferentialBatchFailure {
    pub case_index: Option<usize>,
    pub case_id: Option<Arc<str>>,
    pub detail: String,
    pub timing: DifferentialBatchTiming,
}

impl DifferentialBatchFailure {
    fn configuration(detail: String, wall: Duration) -> Self {
        Self {
            case_index: None,
            case_id: None,
            detail,
            timing: DifferentialBatchTiming {
                wall,
                ..DifferentialBatchTiming::default()
            },
        }
    }

    fn case(
        case_index: usize,
        case_id: Arc<str>,
        detail: String,
        timing: DifferentialBatchTiming,
    ) -> Self {
        Self {
            case_index: Some(case_index),
            case_id: Some(case_id),
            detail,
            timing,
        }
    }
}

impl std::fmt::Display for DifferentialBatchFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let (Some(index), Some(case_id)) = (self.case_index, self.case_id.as_deref()) {
            write!(
                formatter,
                "case {case_id} at authoritative index {index} failed: {}",
                self.detail
            )
        } else {
            formatter.write_str(&self.detail)
        }
    }
}

impl std::error::Error for DifferentialBatchFailure {}

impl DifferentialReport {
    #[must_use]
    pub fn agrees(&self) -> bool {
        self.mismatches.is_empty()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DivergenceClass {
    RustBug,
    OracleEnvironment,
    PlatformDifference,
    PresentationNormalization,
    DeliberateDivergence,
    RetainedUpstreamBug,
    HarnessFailure,
    Nondeterministic,
    OracleFailure,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClassifiedMismatch {
    pub mismatch: DifferentialMismatch,
    pub classification: Option<DivergenceClass>,
    pub explanation: Arc<str>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseGateReport {
    pub differential_observations: usize,
    pub candidate_stress_cases: usize,
    pub minimum_differential_observations: usize,
    pub harness_failures: usize,
    pub unexpected_timeouts: usize,
    pub unexplained_mismatches: usize,
    pub rust_bug_mismatches: usize,
    pub stale_exact_claims: usize,
    pub missing_evidence_references: usize,
    pub required_platform_skips: usize,
    pub leaked_resources: usize,
    pub dependency_failures: usize,
}

impl ReleaseGateReport {
    /// Whether evidence collection completed without an implementation,
    /// harness, policy, resource, or dependency failure.
    #[must_use]
    pub fn collection_passed(&self) -> bool {
        self.differential_observations >= self.minimum_differential_observations
            && self.harness_failures == 0
            && self.unexpected_timeouts == 0
            && self.unexplained_mismatches == 0
            && self.rust_bug_mismatches == 0
            && self.stale_exact_claims == 0
            && self.leaked_resources == 0
            && self.dependency_failures == 0
    }

    /// Whether validated evidence is also ready for a compatibility promotion.
    #[must_use]
    pub fn promotion_ready(&self) -> bool {
        self.collection_passed()
            && self.missing_evidence_references == 0
            && self.required_platform_skips == 0
    }

    /// Applies the fail-closed promotion gate.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.promotion_ready()
    }
}

pub struct ReleaseGateInput<'a> {
    pub differential_observations: usize,
    pub candidate_stress_cases: usize,
    pub harness_failures: usize,
    pub unexpected_timeouts: usize,
    pub mismatches: &'a [ClassifiedMismatch],
    pub stale_exact_claims: usize,
    pub missing_evidence_references: usize,
    pub required_platform_skips: usize,
    pub leaked_resources: usize,
    pub dependency_failures: usize,
}

/// Evaluates the deterministic differential release threshold.
#[must_use]
pub fn release_gate(
    differential_observations: usize,
    minimum_differential_observations: usize,
    mismatches: &[ClassifiedMismatch],
) -> ReleaseGateReport {
    evaluate_release_gate(
        &ReleaseGateInput {
            differential_observations,
            candidate_stress_cases: 0,
            harness_failures: 0,
            unexpected_timeouts: 0,
            mismatches,
            stale_exact_claims: 0,
            missing_evidence_references: 0,
            required_platform_skips: 0,
            leaked_resources: 0,
            dependency_failures: 0,
        },
        minimum_differential_observations,
    )
}

#[must_use]
pub fn evaluate_release_gate(
    input: &ReleaseGateInput<'_>,
    minimum_differential_observations: usize,
) -> ReleaseGateReport {
    ReleaseGateReport {
        differential_observations: input.differential_observations,
        candidate_stress_cases: input.candidate_stress_cases,
        minimum_differential_observations,
        harness_failures: input.harness_failures,
        unexpected_timeouts: input.unexpected_timeouts,
        unexplained_mismatches: input
            .mismatches
            .iter()
            .filter(|mismatch| {
                mismatch.classification.is_none() || mismatch.explanation.trim().is_empty()
            })
            .count(),
        rust_bug_mismatches: input
            .mismatches
            .iter()
            .filter(|mismatch| mismatch.classification == Some(DivergenceClass::RustBug))
            .count(),
        stale_exact_claims: input.stale_exact_claims,
        missing_evidence_references: input.missing_evidence_references,
        required_platform_skips: input.required_platform_skips,
        leaked_resources: input.leaked_resources,
        dependency_failures: input.dependency_failures,
    }
}

/// Runs one existing script and captures output with the case's bounded
/// timeout. This compatibility wrapper does not snapshot its working tree.
///
/// # Errors
///
/// Returns an I/O error when the child cannot be spawned, communicated with,
/// or collected, and a timed-out error after killing a child that exceeds the
/// configured bound.
pub fn run(executable: &Path, script: &Path, case: &DifferentialCase) -> std::io::Result<Output> {
    let working_directory = script.parent().unwrap_or_else(|| Path::new("."));
    let captured = capture_process(
        executable,
        ExecutableRole::Candidate,
        script,
        working_directory,
        case,
        ExecutionProfile::Upstream,
        CaptureEvidence::default(),
    )?;
    if captured.timed_out {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("child exceeded differential timeout of {:?}", case.timeout),
        ));
    }
    Ok(Output {
        status: captured.status,
        stdout: captured.stdout.into_output(),
        stderr: captured.stderr.into_output(),
    })
}

/// Runs the same source against an oracle and candidate in separate isolated
/// temporary directories, then compares all observable outputs.
///
/// # Errors
///
/// Returns an I/O error if either sandbox or child process cannot be managed.
pub fn differential(
    oracle: &Path,
    candidate: &Path,
    case: &DifferentialCase,
) -> std::io::Result<DifferentialReport> {
    let oracle = inspect_executable(oracle, ExecutableRole::Oracle)?;
    let candidate = inspect_executable(candidate, ExecutableRole::Candidate)?;
    differential_with_identities(&oracle, &candidate, case)
}

/// Runs a case using executable identities that were verified before the
/// corpus, avoiding identity drift and repeated hashing between cases.
///
/// # Errors
///
/// Returns an I/O error if either sandbox or child process cannot be managed.
pub fn differential_with_identities(
    oracle: &ExecutableIdentity,
    candidate: &ExecutableIdentity,
    case: &DifferentialCase,
) -> std::io::Result<DifferentialReport> {
    differential_with_identities_timed(oracle, candidate, case).map(|timed| timed.report)
}

/// Runs one isolated differential case while retaining role-separated
/// monotonic execution timings that never participate in conformance.
///
/// # Errors
///
/// Returns an I/O error if either sandbox or child process cannot be managed.
pub fn differential_with_identities_timed(
    oracle: &ExecutableIdentity,
    candidate: &ExecutableIdentity,
    case: &DifferentialCase,
) -> std::io::Result<TimedDifferentialReport> {
    differential_with_identities_timed_at(oracle, candidate, case, None)
}

fn differential_with_identities_timed_at(
    oracle: &ExecutableIdentity,
    candidate: &ExecutableIdentity,
    case: &DifferentialCase,
    sandbox_sequences: Option<(u64, u64)>,
) -> std::io::Result<TimedDifferentialReport> {
    let started = Instant::now();
    let profile = case_execution_profile(case);
    let oracle_observation = observe_source_timed(
        oracle,
        case,
        "oracle",
        profile,
        sandbox_sequences.map(|sequences| sequences.0),
    )?;
    let candidate_observation = observe_source_timed(
        candidate,
        case,
        "candidate",
        profile,
        sandbox_sequences.map(|sequences| sequences.1),
    )?;
    let (comparison_projection, mismatches) = compare_case_observations(
        case,
        &oracle_observation.observation,
        &candidate_observation.observation,
    );
    let elapsed = started.elapsed();
    let process_duration = oracle_observation
        .process_duration
        .saturating_add(candidate_observation.process_duration);
    Ok(TimedDifferentialReport {
        report: DifferentialReport {
            oracle: oracle_observation.observation,
            candidate: candidate_observation.observation,
            comparison_projection,
            mismatches,
        },
        timing: DifferentialTiming {
            oracle_process: oracle_observation.process_duration,
            candidate_process: candidate_observation.process_duration,
            driver_overhead: elapsed.saturating_sub(process_duration),
        },
    })
}

/// Returns the deterministic worker bound for differential batches.
///
/// Candidate-principal confinement requires serial execution because its
/// bounded UID quiescence sweep intentionally covers the whole principal.
#[must_use]
pub fn differential_worker_limit() -> usize {
    if CANDIDATE_LAUNCH_POLICY.with(|slot| slot.borrow().is_some()) {
        1
    } else {
        std::thread::available_parallelism().map_or(1, |parallelism| {
            parallelism.get().min(MAX_DIFFERENTIAL_WORKERS)
        })
    }
}

/// Retains a non-authoritative sample together with its exact full-inventory
/// provenance.
#[derive(Clone, Debug)]
pub struct RepresentativeDifferentialSample {
    pub cases: Vec<DifferentialCase>,
    pub inventory_count: usize,
    pub inventory_sha256: Digest,
    pub selected_indices: Vec<usize>,
}

/// Hashes the exact ordered differential inventory used by authoritative and
/// diagnostic suites.
///
/// # Errors
///
/// Returns an error if a case identifier length cannot be represented as a
/// `u64`.
pub fn differential_inventory_sha256(cases: &[DifferentialCase]) -> Result<Digest, String> {
    let mut inventory_bytes = b"hell-differential-inventory-v2\0".to_vec();
    inventory_bytes.extend_from_slice(
        &u64::try_from(cases.len())
            .map_err(|_| "differential inventory length overflow")?
            .to_be_bytes(),
    );
    for case in cases {
        inventory_bytes.extend_from_slice(&differential_inventory_case_sha256(case)?.0);
    }
    Ok(sha256_bytes(&inventory_bytes))
}

fn differential_inventory_case_sha256(case: &DifferentialCase) -> Result<Digest, String> {
    let mut canonical = b"hell-differential-inventory-case-v1\0".to_vec();
    push_inventory_bytes(&mut canonical, case.id.as_bytes())?;
    push_inventory_bytes(&mut canonical, case.source.as_bytes())?;
    push_inventory_os_strings(&mut canonical, &case.arguments, "argument")?;
    canonical.extend_from_slice(
        &u64::try_from(case.environment.len())
            .map_err(|_| "differential environment length overflow")?
            .to_be_bytes(),
    );
    for (name, value) in &case.environment {
        push_inventory_os_string(&mut canonical, name, "environment name")?;
        push_inventory_os_string(&mut canonical, value, "environment value")?;
    }
    push_inventory_bytes(&mut canonical, &case.stdin)?;
    canonical.extend_from_slice(&case.timeout.as_secs().to_be_bytes());
    canonical.extend_from_slice(&case.timeout.subsec_nanos().to_be_bytes());
    canonical.extend_from_slice(
        &u64::try_from(case.normalization.stderr_replacements.len())
            .map_err(|_| "differential stderr replacement count overflow")?
            .to_be_bytes(),
    );
    for (from, to) in &case.normalization.stderr_replacements {
        push_inventory_bytes(&mut canonical, from)?;
        push_inventory_bytes(&mut canonical, to)?;
    }
    canonical.push(u8::from(case.normalization.normalize_path_separators));
    canonical.push(match case.environment_profile {
        EnvironmentProfile::Minimal => 0,
        EnvironmentProfile::ProcessCapable => 1,
        EnvironmentProfile::NativePlatform => 2,
        EnvironmentProfile::Explicit => 3,
    });
    if case.environment_profile == EnvironmentProfile::ProcessCapable {
        push_inventory_bytes(&mut canonical, b"hell-test-helper-v1")?;
    } else {
        push_inventory_bytes(&mut canonical, b"")?;
    }
    canonical.push(match case.mode {
        DifferentialMode::Check => 0,
        DifferentialMode::Run => 1,
    });
    canonical.push(u8::from(case.expected_runtime_completion));
    let mut logical_case = case.clone();
    logical_case.process_helper_directory = None;
    logical_case.process_helper_sha256 = None;
    canonical.extend_from_slice(&case_descriptor_sha256(&logical_case).0);
    Ok(sha256_bytes(&canonical))
}

fn push_inventory_os_strings(
    canonical: &mut Vec<u8>,
    values: &[OsString],
    label: &str,
) -> Result<(), String> {
    canonical.extend_from_slice(
        &u64::try_from(values.len())
            .map_err(|_| format!("differential {label} count overflow"))?
            .to_be_bytes(),
    );
    for value in values {
        push_inventory_os_string(canonical, value, label)?;
    }
    Ok(())
}

fn push_inventory_os_string(
    canonical: &mut Vec<u8>,
    value: &OsStr,
    label: &str,
) -> Result<(), String> {
    let value = value
        .to_str()
        .ok_or_else(|| format!("differential {label} is not canonical UTF-8"))?;
    push_inventory_bytes(canonical, value.as_bytes())
}

fn push_inventory_bytes(canonical: &mut Vec<u8>, value: &[u8]) -> Result<(), String> {
    canonical.extend_from_slice(
        &u64::try_from(value.len())
            .map_err(|_| "differential inventory field length overflow")?
            .to_be_bytes(),
    );
    canonical.extend_from_slice(value);
    Ok(())
}

/// Selects a deterministic, evenly distributed diagnostic sample from an
/// authoritative differential order.
///
/// This is a performance-diagnostic inventory only. Release conformance still
/// executes its complete inventory and never consumes this sample.
///
/// # Errors
///
/// Returns an error unless the requested sample is between 32 and 256 cases,
/// is no larger than the authoritative inventory, and index arithmetic fits.
pub fn representative_differential_sample(
    cases: &[DifferentialCase],
    sample_count: usize,
) -> Result<RepresentativeDifferentialSample, String> {
    const MIN_SAMPLE_COUNT: usize = 32;
    const MAX_SAMPLE_COUNT: usize = 256;

    if !(MIN_SAMPLE_COUNT..=MAX_SAMPLE_COUNT).contains(&sample_count) || sample_count > cases.len()
    {
        return Err(format!(
            "representative differential sample count must be 32..=256 and no greater than the {} authoritative cases",
            cases.len()
        ));
    }
    let inventory_sha256 = differential_inventory_sha256(cases)?;
    let final_index = cases.len() - 1;
    let final_sample = sample_count - 1;
    let selected_indices = (0..sample_count)
        .map(|sample| {
            sample
                .checked_mul(final_index)
                .map(|product| product / final_sample)
                .ok_or_else(|| "representative differential index arithmetic overflow".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let selected_cases = selected_indices
        .iter()
        .map(|index| cases[*index].clone())
        .collect();
    Ok(RepresentativeDifferentialSample {
        cases: selected_cases,
        inventory_count: cases.len(),
        inventory_sha256,
        selected_indices,
    })
}

struct ExecutableIntegrityGuard {
    authority: ExecutableInvocationAuthority,
    #[cfg(unix)]
    source_handle: fs::File,
    #[cfg(unix)]
    execution_handle: fs::File,
    #[cfg(unix)]
    source_identity: UnixExecutableIdentity,
    #[cfg(unix)]
    execution_identity: UnixExecutableIdentity,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct UnixExecutableIdentity {
    device: u64,
    inode: u64,
    size: u64,
    mode: u32,
    user: u32,
    group: u32,
    change_seconds: i64,
    change_nanoseconds: i64,
}

impl ExecutableIntegrityGuard {
    fn new(authority: &ExecutableInvocationAuthority) -> Result<Self, String> {
        let authority = authority.clone();
        require_executable_invocation_paths(&authority)?;
        #[cfg(unix)]
        {
            let source_handle = fs::File::open(&authority.source.path)
                .map_err(|error| format!("cannot retain source executable handle: {error}"))?;
            let execution_handle = fs::File::open(&authority.execution.path)
                .map_err(|error| format!("cannot retain execution alias handle: {error}"))?;
            let source_identity =
                unix_executable_identity(&source_handle.metadata().map_err(|error| {
                    format!("cannot inspect source executable handle: {error}")
                })?)?;
            let execution_identity = unix_executable_identity(
                &execution_handle
                    .metadata()
                    .map_err(|error| format!("cannot inspect execution alias handle: {error}"))?,
            )?;
            if source_identity != execution_identity {
                return Err("execution alias does not name the source executable".to_owned());
            }
            Ok(Self {
                authority,
                source_handle,
                execution_handle,
                source_identity,
                execution_identity,
            })
        }
        #[cfg(not(unix))]
        {
            Ok(Self { authority })
        }
    }

    fn execution_identity(&self) -> &ExecutableIdentity {
        if diagnostic_program_mutant_active()
            && self.authority.source.role == ExecutableRole::Oracle
            && self.authority.source.path != self.authority.execution.path
        {
            &self.authority.source
        } else {
            &self.authority.execution
        }
    }

    fn require_unchanged(&self) -> Result<(), String> {
        require_executable_invocation_paths(&self.authority)?;
        #[cfg(unix)]
        {
            let retained_source = unix_executable_identity(
                &self
                    .source_handle
                    .metadata()
                    .map_err(|error| format!("cannot recheck source handle: {error}"))?,
            )?;
            let retained_execution = unix_executable_identity(
                &self
                    .execution_handle
                    .metadata()
                    .map_err(|error| format!("cannot recheck execution handle: {error}"))?,
            )?;
            let current_source = unix_executable_identity(
                &fs::metadata(&self.authority.source.path)
                    .map_err(|error| format!("cannot recheck source executable: {error}"))?,
            )?;
            let current_execution = unix_executable_identity(
                &fs::metadata(&self.authority.execution.path)
                    .map_err(|error| format!("cannot recheck execution alias: {error}"))?,
            )?;
            if current_source != self.source_identity
                || current_execution != self.execution_identity
                || retained_source != self.source_identity
                || retained_execution != self.execution_identity
            {
                return Err("bound source or execution identity changed during batch".to_owned());
            }
            Ok(())
        }
        #[cfg(not(unix))]
        {
            Ok(())
        }
    }

    fn finish(&self) -> Result<(), String> {
        self.require_unchanged()?;
        let source = sha256_file(&self.authority.source.path)
            .map_err(|error| format!("cannot hash source executable after batch: {error}"))?;
        let execution = sha256_file(&self.authority.execution.path)
            .map_err(|error| format!("cannot hash execution alias after batch: {error}"))?;
        (source == self.authority.source.sha256 && execution == self.authority.execution.sha256)
            .then_some(())
            .ok_or_else(|| "bound source or execution digest changed during batch".to_owned())
    }
}

fn require_executable_invocation_paths(
    authority: &ExecutableInvocationAuthority,
) -> Result<(), String> {
    let source = fs::canonicalize(&authority.source.path)
        .map_err(|error| format!("cannot canonicalize source executable: {error}"))?;
    let execution = fs::canonicalize(&authority.execution.path)
        .map_err(|error| format!("cannot canonicalize execution alias: {error}"))?;
    if source != authority.source.path
        || execution != authority.execution.path
        || !same_executable_file(&source, &execution)
            .map_err(|error| format!("cannot compare source and execution identity: {error}"))?
    {
        return Err("bound source or execution path identity changed".to_owned());
    }
    Ok(())
}

#[cfg(unix)]
fn unix_executable_identity(metadata: &fs::Metadata) -> Result<UnixExecutableIdentity, String> {
    use std::os::unix::fs::MetadataExt as _;

    if !metadata.is_file() {
        return Err("bound executable is not a regular file".to_owned());
    }
    Ok(UnixExecutableIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        size: metadata.size(),
        mode: metadata.mode(),
        user: metadata.uid(),
        group: metadata.gid(),
        change_seconds: metadata.ctime(),
        change_nanoseconds: metadata.ctime_nsec(),
    })
}

/// Runs every differential case with a bounded worker pool while retaining
/// authoritative input order independently from scheduling order.
///
/// # Errors
///
/// Returns the lowest authoritative failing case after all workers have
/// joined, or an integrity/configuration failure with aggregate timing.
pub fn differential_batch_with_identities(
    oracle: &ExecutableIdentity,
    candidate: &ExecutableIdentity,
    cases: &[DifferentialCase],
    worker_count: usize,
) -> Result<DifferentialBatchReport, Box<DifferentialBatchFailure>> {
    let started = Instant::now();
    let oracle = ExecutableInvocationAuthority::direct(oracle).map_err(|error| {
        Box::new(DifferentialBatchFailure::configuration(
            format!("cannot bind direct oracle invocation: {error}"),
            started.elapsed(),
        ))
    })?;
    let candidate = ExecutableInvocationAuthority::direct(candidate).map_err(|error| {
        Box::new(DifferentialBatchFailure::configuration(
            format!("cannot bind direct candidate invocation: {error}"),
            started.elapsed(),
        ))
    })?;
    differential_batch_with_invocations(&oracle, &candidate, cases, worker_count)
}

/// Runs every differential case with separately bound source and process
/// invocation identities.
///
/// # Errors
///
/// Returns an identity/configuration failure or the lowest authoritative case
/// failure after all workers have joined.
pub fn differential_batch_with_invocations(
    oracle: &ExecutableInvocationAuthority,
    candidate: &ExecutableInvocationAuthority,
    cases: &[DifferentialCase],
    worker_count: usize,
) -> Result<DifferentialBatchReport, Box<DifferentialBatchFailure>> {
    let started = Instant::now();
    let limit = differential_worker_limit();
    if worker_count == 0 || worker_count > limit {
        return Err(Box::new(DifferentialBatchFailure::configuration(
            format!("differential worker count {worker_count} exceeds exact bound {limit}"),
            started.elapsed(),
        )));
    }
    if cases.is_empty() {
        return Ok(DifferentialBatchReport {
            reports: Vec::new(),
            case_timings: Vec::new(),
            timing: DifferentialBatchTiming {
                worker_count,
                wall: started.elapsed(),
                ..DifferentialBatchTiming::default()
            },
        });
    }
    let launch_policy = CANDIDATE_LAUNCH_POLICY.with(|slot| slot.borrow().clone());
    let oracle_guard = ExecutableIntegrityGuard::new(oracle).map_err(|error| {
        Box::new(DifferentialBatchFailure::configuration(
            error,
            started.elapsed(),
        ))
    })?;
    let candidate_guard = ExecutableIntegrityGuard::new(candidate).map_err(|error| {
        Box::new(DifferentialBatchFailure::configuration(
            error,
            started.elapsed(),
        ))
    })?;
    let sandbox_count = u64::try_from(cases.len())
        .ok()
        .and_then(|count| count.checked_mul(2))
        .ok_or_else(|| {
            Box::new(DifferentialBatchFailure::configuration(
                "differential sandbox count overflow".to_owned(),
                started.elapsed(),
            ))
        })?;
    let sandbox_base = NEXT_SANDBOX.fetch_add(sandbox_count, Ordering::Relaxed);
    let active_workers = worker_count.min(cases.len());
    let (slots, first_failure) = run_differential_workers(
        &oracle_guard,
        &candidate_guard,
        cases,
        active_workers,
        sandbox_base,
        launch_policy.as_ref(),
    );
    let integrity = oracle_guard
        .finish()
        .and_then(|()| candidate_guard.finish());
    let wall = started.elapsed();
    if let Err(error) = integrity {
        return Err(Box::new(DifferentialBatchFailure::configuration(
            error, wall,
        )));
    }
    collect_differential_batch(cases, slots, first_failure, active_workers, wall)
}

type DifferentialSlot = Option<Result<TimedDifferentialReport, String>>;

fn run_differential_workers(
    oracle_guard: &ExecutableIntegrityGuard,
    candidate_guard: &ExecutableIntegrityGuard,
    cases: &[DifferentialCase],
    worker_count: usize,
    sandbox_base: u64,
    launch_policy: Option<&CandidateLaunchPolicy>,
) -> (Vec<DifferentialSlot>, usize) {
    let next = AtomicUsize::new(0);
    let first_failure = AtomicUsize::new(cases.len());
    let slots = Mutex::new(
        (0..cases.len())
            .map(|_| None)
            .collect::<Vec<DifferentialSlot>>(),
    );
    std::thread::scope(|scope| {
        for _ in 0..worker_count {
            let oracle_guard = &oracle_guard;
            let candidate_guard = &candidate_guard;
            let next = &next;
            let first_failure = &first_failure;
            let slots = &slots;
            scope.spawn(move || {
                let operation = || loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    if index >= cases.len() || index > first_failure.load(Ordering::Acquire) {
                        break;
                    }
                    let outcome = run_guarded_differential_case(
                        oracle_guard,
                        candidate_guard,
                        &cases[index],
                        sandbox_base,
                        index,
                    );
                    if outcome.is_err() {
                        first_failure.fetch_min(index, Ordering::AcqRel);
                    }
                    slots
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)[index] = Some(outcome);
                };
                if let Some(policy) = launch_policy {
                    with_candidate_launch_policy(policy, operation);
                } else {
                    operation();
                }
            });
        }
    });
    let slots = slots
        .into_inner()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    (slots, first_failure.load(Ordering::Acquire))
}

fn collect_differential_batch(
    cases: &[DifferentialCase],
    mut slots: Vec<DifferentialSlot>,
    first_failure: usize,
    worker_count: usize,
    wall: Duration,
) -> Result<DifferentialBatchReport, Box<DifferentialBatchFailure>> {
    let mut reports = Vec::with_capacity(cases.len());
    let mut case_timings = Vec::with_capacity(cases.len());
    let mut timing = DifferentialBatchTiming {
        case_count: cases.len(),
        worker_count,
        wall,
        ..DifferentialBatchTiming::default()
    };
    for (index, slot) in slots.iter_mut().enumerate() {
        let Some(outcome) = slot.take() else {
            if index <= first_failure {
                return Err(Box::new(DifferentialBatchFailure::case(
                    index,
                    Arc::clone(&cases[index].id),
                    "differential worker did not retain its indexed result".to_owned(),
                    timing,
                )));
            }
            break;
        };
        match outcome {
            Ok(timed) => {
                timing.completed_count = timing.completed_count.saturating_add(1);
                timing.oracle_process_sum = timing
                    .oracle_process_sum
                    .saturating_add(timed.timing.oracle_process);
                timing.candidate_process_sum = timing
                    .candidate_process_sum
                    .saturating_add(timed.timing.candidate_process);
                timing.driver_overhead_sum = timing
                    .driver_overhead_sum
                    .saturating_add(timed.timing.driver_overhead);
                case_timings.push(timed.timing);
                reports.push(timed.report);
            }
            Err(detail) => {
                return Err(Box::new(DifferentialBatchFailure::case(
                    index,
                    Arc::clone(&cases[index].id),
                    detail,
                    timing,
                )));
            }
        }
    }
    if reports.len() != cases.len() {
        return Err(Box::new(DifferentialBatchFailure::configuration(
            "differential batch stopped without an indexed failure".to_owned(),
            wall,
        )));
    }
    Ok(DifferentialBatchReport {
        reports,
        case_timings,
        timing,
    })
}

fn run_guarded_differential_case(
    oracle: &ExecutableIntegrityGuard,
    candidate: &ExecutableIntegrityGuard,
    case: &DifferentialCase,
    sandbox_base: u64,
    index: usize,
) -> Result<TimedDifferentialReport, String> {
    oracle.require_unchanged()?;
    candidate.require_unchanged()?;
    let offset = u64::try_from(index)
        .ok()
        .and_then(|index| index.checked_mul(2))
        .ok_or_else(|| "differential sandbox index overflow".to_owned())?;
    let oracle_sequence = sandbox_base
        .checked_add(offset)
        .ok_or_else(|| "differential oracle sandbox sequence overflow".to_owned())?;
    let candidate_sequence = oracle_sequence
        .checked_add(1)
        .ok_or_else(|| "differential candidate sandbox sequence overflow".to_owned())?;
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        differential_with_identities_timed_at(
            oracle.execution_identity(),
            candidate.execution_identity(),
            case,
            Some((oracle_sequence, candidate_sequence)),
        )
    }))
    .map_err(|_| "differential worker panicked".to_owned())?
    .map_err(|error| error.to_string());
    oracle.require_unchanged()?;
    candidate.require_unchanged()?;
    outcome.map(|mut timed| {
        timed.report.oracle.identity = oracle.authority.execution.clone();
        timed.report.candidate.identity = candidate.authority.execution.clone();
        timed
    })
}

/// Runs an ineligible case while asking only the candidate instrumentation to
/// retain the typed result for one registry-backed builtin.
///
/// This is localization evidence, not claim evidence: the case must not carry
/// a claim descriptor, and the selected target is never inferred from or
/// written into one. Callers must independently establish any reviewed claim
/// semantics before promotion.
///
/// # Errors
///
/// Returns an error when the case is claim eligible, the target is unknown, or
/// either isolated observation cannot be collected.
pub fn differential_with_nonclaim_trace_target(
    oracle: &ExecutableIdentity,
    candidate: &ExecutableIdentity,
    case: &DifferentialCase,
    target: &str,
) -> std::io::Result<DifferentialReport> {
    if case.claim_evidence.is_some() {
        return Err(std::io::Error::other(
            "nonclaim trace discovery rejects a claim-eligible descriptor",
        ));
    }
    let target = hell_builtins::lookup(target)
        .map(|spec| spec.id)
        .ok_or_else(|| std::io::Error::other("nonclaim trace target is not registry-backed"))?;
    let profile = ExecutionProfile::Upstream;
    let oracle_observation = observe_source(oracle, case, "oracle", profile)?;
    let candidate_observation =
        observe_source_with_nonclaim_target(candidate, case, "candidate", profile, target)?;
    let (comparison_projection, mismatches) =
        compare_case_observations(case, &oracle_observation, &candidate_observation);
    Ok(DifferentialReport {
        oracle: oracle_observation,
        candidate: candidate_observation,
        comparison_projection,
        mismatches,
    })
}

/// Observes one already-verified executable under an explicit compiler and
/// runtime execution profile, retaining a digest of the exact invocation.
///
/// # Errors
///
/// Returns an error for a profile/descriptor mismatch, noncanonical execution
/// input, sandbox or process failure, or malformed retained observation.
pub fn observe_verified_executable_profile(
    identity: &ExecutableIdentity,
    case: &DifferentialCase,
    profile: ExecutionProfile,
) -> std::io::Result<VerifiedProfileObservation> {
    if case
        .claim_evidence
        .as_ref()
        .map(|descriptor| descriptor.profile)
        != Some(profile)
    {
        return Err(std::io::Error::other(
            "explicit execution profile requires an exactly matching reviewed case descriptor",
        ));
    }
    let execution_input = artifact::execution_input_json(case)?;
    let source_sha256 = sha256_bytes(case.source.as_bytes());
    let execution_input_sha256 = sha256_bytes(execution_input.as_bytes());
    let invocation_sha256 = artifact::verified_profile_invocation_sha256(
        profile,
        identity.sha256,
        source_sha256,
        execution_input_sha256,
    );
    let observation = observe_source(identity, case, profile.as_str(), profile)?;
    Ok(VerifiedProfileObservation {
        profile,
        executable_sha256: identity.sha256,
        source_sha256,
        execution_input_sha256,
        invocation_sha256,
        observation,
    })
}

fn case_execution_profile(case: &DifferentialCase) -> ExecutionProfile {
    case.claim_evidence
        .as_ref()
        .map_or(ExecutionProfile::Upstream, |descriptor| descriptor.profile)
}

/// Resolves, hashes, and probes one executable through structured arguments.
///
/// # Errors
///
/// Returns an error when the file cannot be hashed, `--version` fails, its
/// output is not one nonempty UTF-8 line, or the probe exceeds five seconds.
pub fn inspect_executable(
    path: &Path,
    role: ExecutableRole,
) -> std::io::Result<ExecutableIdentity> {
    let (path, sha256, authority) = resolve_and_hash(path)?;
    probe_identity(path, sha256, role, false, authority.as_ref())
}

/// Verifies the pinned digest and reported language version before a corpus.
///
/// # Errors
///
/// Returns an error if identity inspection fails or either expected identity
/// component differs. No differential case should run after such an error.
pub fn verify_executable(
    path: &Path,
    role: ExecutableRole,
    expected_sha256: Option<Digest>,
    expected_version: &str,
) -> std::io::Result<ExecutableIdentity> {
    let (path, sha256, authority) = resolve_and_hash(path)?;
    if let Some(expected) = expected_sha256
        && sha256 != expected
    {
        return Err(std::io::Error::other(format!(
            "{:?} executable digest mismatch: expected {}, observed {}",
            role,
            expected.hex(),
            sha256.hex()
        )));
    }
    let identity = probe_identity(path, sha256, role, true, authority.as_ref())?;
    if identity.reported_version.as_ref() != expected_version {
        return Err(std::io::Error::other(format!(
            "{:?} executable version mismatch: expected {expected_version:?}, observed {:?}",
            role, identity.reported_version
        )));
    }
    Ok(identity)
}

/// Verifies that a candidate identity is the unchanged, canonical executable
/// whose parsed build information enables compatibility tracing.
///
/// # Errors
///
/// Returns an error for a non-candidate identity, missing or disabled build
/// information, a noncanonical path, or a digest change since identity probing.
pub fn verify_compat_tracing_candidate_identity(
    identity: &ExecutableIdentity,
) -> std::io::Result<()> {
    if identity.role != ExecutableRole::Candidate {
        return Err(std::io::Error::other(
            "compatibility tracing attestation requires a candidate identity",
        ));
    }
    let build_info = identity
        .build_info
        .as_ref()
        .ok_or_else(|| std::io::Error::other("candidate build info is missing"))?;
    if build_info.schema_version != CANDIDATE_BUILD_INFO_SCHEMA_VERSION {
        return Err(std::io::Error::other(format!(
            "candidate build info schema must be {CANDIDATE_BUILD_INFO_SCHEMA_VERSION}"
        )));
    }
    if !build_info.compat_tracing {
        return Err(std::io::Error::other(
            "candidate build info reports compat tracing disabled",
        ));
    }
    if path_has_lexical_dot_component(&identity.path) {
        return Err(std::io::Error::other(
            "candidate identity path is not lexically canonical",
        ));
    }
    let canonical = fs::canonicalize(&identity.path)?;
    if canonical.as_os_str() != identity.path.as_os_str() {
        return Err(std::io::Error::other(
            "candidate identity path is not canonical",
        ));
    }
    let observed = sha256_file(&identity.path)?;
    if observed != identity.sha256 {
        return Err(std::io::Error::other(format!(
            "candidate executable changed after build-info probing: expected {}, observed {}",
            identity.sha256.hex(),
            observed.hex()
        )));
    }
    Ok(())
}

fn path_has_lexical_dot_component(path: &Path) -> bool {
    path.components().any(|component| match component {
        std::path::Component::CurDir | std::path::Component::ParentDir => true,
        std::path::Component::Normal(name) => name == OsStr::new(".") || name == OsStr::new(".."),
        std::path::Component::Prefix(_) | std::path::Component::RootDir => false,
    })
}

#[must_use]
pub fn compare(oracle: &Observation, candidate: &Observation) -> Vec<DifferentialMismatch> {
    let mut mismatches = Vec::new();
    push_mismatch(
        &mut mismatches,
        MismatchKind::Timeout,
        &[u8::from(oracle.timed_out)],
        &[u8::from(candidate.timed_out)],
    );
    push_mismatch(
        &mut mismatches,
        MismatchKind::ExitStatus,
        format!("{:?}", oracle.status).as_bytes(),
        format!("{:?}", candidate.status).as_bytes(),
    );
    push_capture_mismatch(
        &mut mismatches,
        MismatchKind::Stdout,
        &oracle.stdout,
        &candidate.stdout,
    );
    if oracle.mode == DifferentialMode::Check && candidate.mode == DifferentialMode::Check {
        push_mismatch(
            &mut mismatches,
            MismatchKind::Diagnostic,
            format!("{:?}", oracle.diagnostic).as_bytes(),
            format!("{:?}", candidate.diagnostic).as_bytes(),
        );
    } else {
        push_capture_mismatch(
            &mut mismatches,
            MismatchKind::Stderr,
            &oracle.stderr,
            &candidate.stderr,
        );
    }
    if oracle.filesystem != candidate.filesystem {
        mismatches.push(DifferentialMismatch {
            kind: MismatchKind::Filesystem,
            oracle: format!("{:?}", oracle.filesystem).into_bytes(),
            candidate: format!("{:?}", candidate.filesystem).into_bytes(),
        });
    }
    mismatches
}

/// Compares two observations under the exact reviewed case authority. Any
/// descriptor-scoped field projection is returned separately from the
/// authoritative mismatch set.
#[must_use]
pub fn compare_case_observations(
    case: &DifferentialCase,
    oracle: &Observation,
    candidate: &Observation,
) -> (DifferentialComparisonProjection, Vec<DifferentialMismatch>) {
    let mut mismatches = compare(oracle, candidate);
    let projection = reviewed_runtime_failure_stderr_projection(case, oracle, candidate);
    #[cfg(windows)]
    let projection = windows_divergences::reviewed_windows_divergence_projection(
        ClaimPlatform::Windows,
        case,
        oracle,
        candidate,
        &mismatches,
    )
    .or_else(|| {
        windows_presentation::reviewed_windows_presentation_projection(
            ClaimPlatform::Windows,
            case,
            oracle,
            candidate,
            &mismatches,
        )
    })
    .or(projection);
    if let Some(projected) = &projection {
        let projected_fields: Option<Vec<MismatchKind>> = match projected {
            DifferentialComparisonProjection::ReviewedRuntimeFailureStderr { .. }
            | DifferentialComparisonProjection::ReviewedRuntimeFailureExceptionStderr { .. } => {
                Some(vec![MismatchKind::Stderr])
            }
            DifferentialComparisonProjection::ReviewedWindowsPresentation { field, .. } => {
                Some(vec![field.mismatch_kind()])
            }
            DifferentialComparisonProjection::ReviewedWindowsDivergence {
                mismatch_kinds, ..
            } => Some(mismatch_kinds.to_vec()),
            DifferentialComparisonProjection::Exact => None,
        };
        if let Some(fields) = &projected_fields {
            mismatches.retain(|mismatch| !fields.contains(&mismatch.kind));
        }
    }
    (
        projection.unwrap_or(DifferentialComparisonProjection::Exact),
        mismatches,
    )
}

fn runtime_failure_presentation_spec(id: &str) -> Option<RuntimeFailurePresentationSpec> {
    use CompatibilityDimension::Effects;
    use RuntimeFailureExceptionFamily::{ErrorCall, IOException, UnicodeException};
    let (family, builtin, dimension, obligation, while_handling) =
        if let Some((builtin, dimension, obligation)) = unicode_failure_target(id) {
            (
                UnicodeException,
                builtin,
                dimension,
                obligation,
                RuntimeFailureHandlingProjection::None,
            )
        } else if let Some(builtin) = io_exception_failure_builtin(id) {
            (
                IOException,
                builtin,
                Effects,
                "effect-failure",
                io_exception_handling_projection(id),
            )
        } else {
            let (builtin, dimension, obligation, handling) = error_call_failure_target(id)?;
            let while_handling = if handling {
                RuntimeFailureHandlingProjection::Payload
            } else {
                RuntimeFailureHandlingProjection::None
            };
            (ErrorCall, builtin, dimension, obligation, while_handling)
        };
    let (oracle_frame_functions, candidate_frame_functions): (
        &'static [&'static str],
        &'static [&'static str],
    ) = match (family, id) {
        (UnicodeException, _) => (&["throwIO"], &[]),
        (
            IOException,
            "text-getline-boundary-empty-input" | "runtime-environment-get-env-missing",
        ) => (&["ioException"], &[]),
        (IOException, _) => (&["ioError"], &[]),
        (
            ErrorCall,
            "runtime-typed-map-singleton-key-strict"
            | "runtime-typed-set-singleton-element-strict"
            | "list-take-boundary-bottom-after-demanded-prefix"
            | "runtime-interaction-list-laziness-error",
        ) => (&["throwIO"], &["error"]),
        (ErrorCall, "list-cycle-boundary-empty-input") => {
            (&["throwIO"], &["error", "errorEmptyList", "cycle"])
        }
        (ErrorCall, "runtime-temp-directory-failure" | "runtime-temp-file-failure") => {
            (&["bracket"], &["error"])
        }
        (ErrorCall, _) => (&["error"], &["error"]),
    };
    let oracle_frame_layout = if family == IOException
        && matches!(
            id,
            "runtime-directory-copy-file-failure"
                | "runtime-directory-get-file-size-failure"
                | "runtime-directory-rename-file-failure"
                | "runtime-directory-list-directory-failure"
        ) {
        RuntimeFailureOracleFrameLayout::Frameless
    } else {
        RuntimeFailureOracleFrameLayout::Ghc
    };
    Some(RuntimeFailurePresentationSpec {
        family,
        builtin,
        dimension,
        obligation,
        while_handling,
        oracle_frame_functions,
        oracle_frame_layout,
        candidate_frame_functions,
    })
}

fn io_exception_handling_projection(id: &str) -> RuntimeFailureHandlingProjection {
    if id.starts_with("runtime-typed-io-bytestring-readprocess") {
        return RuntimeFailureHandlingProjection::Prefix("missing-hell-test-helper: ");
    }
    match id {
        "runtime-directory-copy-file-failure" => {
            RuntimeFailureHandlingProjection::AfterPathPrefix("copyFile:")
        }
        "runtime-directory-get-file-size-failure" => {
            RuntimeFailureHandlingProjection::AfterPathPrefix("getFileSize:")
        }
        "runtime-directory-rename-file-failure" => {
            RuntimeFailureHandlingProjection::Prefix("renameFile:")
        }
        "runtime-directory-list-directory-failure" => {
            RuntimeFailureHandlingProjection::AfterPathPrefix("getDirectoryContents:")
        }
        _ => RuntimeFailureHandlingProjection::None,
    }
}

fn unicode_failure_target(
    id: &str,
) -> Option<(&'static str, CompatibilityDimension, &'static str)> {
    use CompatibilityDimension::{Effects, PureRuntime};
    match id {
        "text-decodeutf8-boundary-invalid-encoding" => {
            Some(("Text.decodeUtf8", PureRuntime, "adapter-failure"))
        }
        "text-getcontents-boundary-invalid-encoding" => {
            Some(("Text.getContents", Effects, "effect-failure"))
        }
        "text-getline-boundary-invalid-encoding" => {
            Some(("Text.getLine", Effects, "effect-failure"))
        }
        _ => None,
    }
}

fn io_exception_failure_builtin(id: &str) -> Option<&'static str> {
    Some(match id {
        "text-getline-boundary-empty-input" => "Text.getLine",
        "runtime-typed-io-text-writefile-failure" => "Text.writeFile",
        "runtime-typed-io-text-appendfile-failure" => "Text.appendFile",
        "runtime-typed-io-bytestring-writefile-failure" => "ByteString.writeFile",
        "runtime-typed-io-bytestring-readfile-failure" => "ByteString.readFile",
        "runtime-typed-io-bytestring-readprocess-failure" => "ByteString.readProcess",
        "runtime-typed-io-bytestring-readprocess-checked-failure" => "ByteString.readProcess_",
        "runtime-typed-io-bytestring-readprocess-stdout-checked-failure" => {
            "ByteString.readProcessStdout_"
        }
        "runtime-environment-get-env-missing" => "Environment.getEnv",
        "runtime-io-open-file-failure" => "IO.openFile",
        "runtime-directory-copy-file-failure" => "Directory.copyFile",
        "runtime-directory-create-directory-failure" => "Directory.createDirectory",
        "runtime-directory-create-directory-if-missing-failure" => {
            "Directory.createDirectoryIfMissing"
        }
        "runtime-directory-get-file-size-failure" => "Directory.getFileSize",
        "runtime-directory-remove-file-failure" => "Directory.removeFile",
        "runtime-directory-rename-file-failure" => "Directory.renameFile",
        "runtime-directory-list-directory-failure" => "Directory.listDirectory",
        "runtime-directory-remove-directory-failure" => "Directory.removeDirectory",
        "runtime-directory-set-current-directory-failure" => "Directory.setCurrentDirectory",
        _ => return None,
    })
}

fn error_call_failure_target(
    id: &str,
) -> Option<(&'static str, CompatibilityDimension, &'static str, bool)> {
    use CompatibilityDimension::{Effects, PureRuntime};
    Some(match id {
        "runtime-typed-map-singleton-key-strict" => {
            ("Map.singleton", PureRuntime, "whnf-failure-boundary", false)
        }
        "runtime-typed-set-singleton-element-strict" => {
            ("Set.singleton", PureRuntime, "whnf-failure-boundary", false)
        }
        "runtime-io-mapm-failure" => ("IO.mapM_", Effects, "effect-ordering", false),
        "runtime-io-form-failure" => ("IO.forM_", Effects, "effect-ordering", false),
        "runtime-typed-thread-delay-forced-argument-failure" => {
            ("Concurrent.threadDelay", Effects, "effect-failure", false)
        }
        "runtime-typed-timeout-positive-action-failure" => {
            ("Timeout.timeout", Effects, "effect-failure", false)
        }
        "runtime-temp-directory-failure" => (
            "Temp.withSystemTempDirectory",
            Effects,
            "effect-failure",
            true,
        ),
        "runtime-temp-file-failure" => ("Temp.withSystemTempFile", Effects, "effect-failure", true),
        "list-cycle-boundary-empty-input" => {
            ("List.cycle", PureRuntime, "result-force-failure", false)
        }
        "list-take-boundary-bottom-after-demanded-prefix"
        | "runtime-interaction-list-laziness-error" => {
            ("List.take", PureRuntime, "lazy-boundary", false)
        }
        _ => return None,
    })
}

pub(crate) fn has_runtime_failure_presentation_authority(id: &str) -> bool {
    runtime_failure_presentation_spec(id).is_some()
}

pub(crate) fn reviewed_runtime_failure_presentation_authority(
    case: &DifferentialCase,
) -> Option<RuntimeFailurePresentationAuthority> {
    let spec = runtime_failure_presentation_spec(&case.id)?;
    let descriptor = case.claim_evidence.as_ref()?;
    if case.mode != DifferentialMode::Run
        || case.expected_runtime_completion
        || descriptor.profile != case_execution_profile(case)
        || validate_case_descriptor(case, descriptor).is_err()
        || validate_legacy_targets(case, descriptor).is_err()
        || validate_semantic_targets(case, descriptor).is_err()
        || validate_callback_contracts(case, descriptor).is_err()
        || descriptor
            .targets
            .iter()
            .any(|target| target.dimension == CompatibilityDimension::Presentation)
        || descriptor
            .semantic_targets
            .iter()
            .any(|target| target.dimension == CompatibilityDimension::Presentation)
    {
        return None;
    }
    let mut matching = descriptor.semantic_targets.iter().filter(|target| {
        target.builtin.as_ref() == spec.builtin
            && target.dimension == spec.dimension
            && target
                .obligations
                .iter()
                .any(|obligation| obligation.0.as_ref() == spec.obligation)
    });
    let target = matching.next()?;
    if matching.next().is_some()
        || (spec.dimension == CompatibilityDimension::Effects
            && (target.causal_signal != CausalSignal::EffectEvent
                || !target
                    .obligations
                    .iter()
                    .any(|obligation| obligation.0.as_ref() == "effect-ordering")
                || target
                    .obligations
                    .iter()
                    .any(|obligation| obligation.0.as_ref() == "effect-success")))
        || (spec.obligation == "whnf-failure-boundary"
            && target.causal_signal != CausalSignal::ForceTrace)
        || (matches!(spec.obligation, "result-force-failure" | "lazy-boundary")
            && target.causal_signal != CausalSignal::RuntimeAdapterAndForceTrace)
    {
        return None;
    }
    let builtin = hell_builtins::lookup(spec.builtin)?.id;
    Some(RuntimeFailurePresentationAuthority {
        family: spec.family,
        builtin,
        builtin_name: spec.builtin,
        dimension: spec.dimension,
        obligation: spec.obligation,
        while_handling: spec.while_handling,
        oracle_frame_functions: spec.oracle_frame_functions,
        oracle_frame_layout: spec.oracle_frame_layout,
        candidate_frame_functions: spec.candidate_frame_functions,
    })
}

fn reviewed_legacy_runtime_failure_stderr_builtin(case: &DifferentialCase) -> Option<BuiltinId> {
    let descriptor = case.claim_evidence.as_ref()?;
    if has_runtime_failure_presentation_authority(&case.id)
        || case.mode != DifferentialMode::Run
        || case.expected_runtime_completion
        || descriptor.profile != case_execution_profile(case)
        || validate_case_descriptor(case, descriptor).is_err()
        || validate_legacy_targets(case, descriptor).is_err()
        || validate_semantic_targets(case, descriptor).is_err()
        || validate_callback_contracts(case, descriptor).is_err()
        || descriptor
            .targets
            .iter()
            .any(|target| target.dimension == CompatibilityDimension::Presentation)
        || descriptor
            .semantic_targets
            .iter()
            .any(|target| target.dimension == CompatibilityDimension::Presentation)
        || descriptor
            .semantic_targets
            .iter()
            .any(|target| target.expected_raw_presentation_sha256.is_some())
    {
        return None;
    }

    let mut effects = descriptor.semantic_targets.iter().filter(|target| {
        target.dimension == CompatibilityDimension::Effects
            && target.causal_signal == CausalSignal::EffectEvent
            && target
                .obligations
                .iter()
                .any(|obligation| obligation.0.as_ref() == "effect-failure")
            && target
                .obligations
                .iter()
                .any(|obligation| obligation.0.as_ref() == "effect-ordering")
            && !target
                .obligations
                .iter()
                .any(|obligation| obligation.0.as_ref() == "effect-success")
    });
    let effect = effects.next()?;
    if effects.next().is_some() {
        return None;
    }
    let mut adapters = descriptor.semantic_targets.iter().filter(|target| {
        target.builtin == effect.builtin
            && target.dimension == CompatibilityDimension::PureRuntime
            && matches!(
                target.causal_signal,
                CausalSignal::RuntimeAdapter | CausalSignal::RuntimeAdapterAndForceTrace
            )
            && target
                .obligations
                .iter()
                .any(|obligation| obligation.0.as_ref() == "adapter-failure")
            && !target
                .obligations
                .iter()
                .any(|obligation| obligation.0.as_ref() == "adapter-success")
    });
    adapters.next()?;
    if adapters.next().is_some() {
        return None;
    }
    hell_builtins::lookup(&effect.builtin).map(|builtin| builtin.id)
}

pub(crate) fn reviewed_runtime_failure_expected_task_trace(
    case: &DifferentialCase,
    builtin: BuiltinId,
) -> Result<Option<Digest>, ()> {
    let builtin_name = hell_builtins::registry()
        .iter()
        .find(|spec| spec.id == builtin)
        .ok_or(())?
        .name;
    let descriptor = case.claim_evidence.as_ref().ok_or(())?;
    let mut expected = descriptor
        .semantic_targets
        .iter()
        .filter(|target| target.builtin.as_ref() == builtin_name)
        .filter_map(|target| target.expected_task_trace_sha256);
    let first = expected.next();
    if expected.any(|candidate| Some(candidate) != first) {
        return Err(());
    }
    Ok(first)
}

fn semantic_task_trace_sha256(semantic: &SemanticObservation, builtin: BuiltinId) -> Digest {
    let mut tasks = Vec::<u64>::new();
    let mut events = Vec::new();
    for event in &semantic.task_trace {
        let LogicalTraceEvent::TaskEvent {
            task,
            builtin: event_builtin,
            event,
        } = event
        else {
            continue;
        };
        if *event_builtin != builtin {
            continue;
        }
        let index = tasks
            .iter()
            .position(|candidate| candidate == task)
            .unwrap_or_else(|| {
                tasks.push(*task);
                tasks.len() - 1
            });
        events.push((index, event.as_ref()));
    }
    task_trace_sha256(events)
}

fn runtime_failure_target(
    case: &DifferentialCase,
    authority: RuntimeFailurePresentationAuthority,
) -> Option<&EvidenceTargetV2> {
    let mut matching = case
        .claim_evidence
        .as_ref()?
        .semantic_targets
        .iter()
        .filter(|target| {
            target.builtin.as_ref() == authority.builtin_name
                && target.dimension == authority.dimension
                && target
                    .obligations
                    .iter()
                    .any(|obligation| obligation.0.as_ref() == authority.obligation)
        });
    let target = matching.next()?;
    matching.next().is_none().then_some(target)
}

#[cfg(feature = "mutation-testing")]
fn runtime_failure_mutant_active(id: &str) -> bool {
    let arguments = std::env::args_os().collect::<Vec<_>>();
    arguments.windows(4).any(|window| {
        window[0] == "--skip"
            && window[1] == "__hell_mutant"
            && window[2] == "--skip"
            && window[3] == id
    })
}

#[cfg(not(feature = "mutation-testing"))]
const fn runtime_failure_mutant_active(_id: &str) -> bool {
    false
}

fn reviewed_runtime_failure_causality(
    case: &DifferentialCase,
    authority: RuntimeFailurePresentationAuthority,
    semantic: &SemanticObservation,
) -> bool {
    if runtime_failure_mutant_active("runtime-failure-causal-authority") {
        return true;
    }
    let Some(target) = runtime_failure_target(case, authority) else {
        return false;
    };
    let Ok(expected_task_trace) =
        reviewed_runtime_failure_expected_task_trace(case, authority.builtin)
    else {
        return false;
    };
    if expected_task_trace
        .is_some_and(|expected| semantic_task_trace_sha256(semantic, authority.builtin) != expected)
    {
        return false;
    }
    if authority.dimension == CompatibilityDimension::Effects {
        return reviewed_runtime_failure_effect_causality(authority, semantic);
    }

    reviewed_runtime_failure_pure_causality(authority, target, semantic)
}

fn reviewed_runtime_failure_effect_causality(
    authority: RuntimeFailurePresentationAuthority,
    semantic: &SemanticObservation,
) -> bool {
    reviewed_runtime_failure_effect_builtin_causality(authority.builtin, semantic)
}

fn reviewed_runtime_failure_effect_builtin_causality(
    expected_builtin: BuiltinId,
    semantic: &SemanticObservation,
) -> bool {
    if !semantic
        .coverage
        .contains(&CoverageEvent::EnteredAdapter(expected_builtin))
    {
        return false;
    }
    let effects = semantic
        .effect_trace
        .iter()
        .filter_map(|event| match event {
            LogicalTraceEvent::HostEffect {
                builtin,
                owner_task,
                sequence,
                parent_sequence,
                effect,
            } if *builtin == expected_builtin => {
                Some((*owner_task, *sequence, *parent_sequence, effect))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    effects.len() == 2
        && effects[0].0 == effects[1].0
        && effects[0].1 == effects[1].1
        && effects[0].2 == effects[1].2
        && effects[0].3.as_ref() == "started"
        && effects[1].3.as_ref() == "failed"
}

fn reviewed_runtime_failure_obligation_descends_from(
    child: &ObligationTraceEvent,
    ancestor: &ObligationTraceEvent,
    events: &[ObligationTraceEvent],
) -> bool {
    if child.owner_task != ancestor.owner_task || child.sequence <= ancestor.sequence {
        return false;
    }
    let mut current = child;
    let mut visited = std::collections::BTreeSet::new();
    for _ in 0..events.len() {
        if !visited.insert(current.sequence) {
            return false;
        }
        let Some(parent_sequence) = current.parent_sequence else {
            return false;
        };
        if parent_sequence == ancestor.sequence {
            return true;
        }
        let mut matching = events.iter().filter(|event| {
            event.owner_task == current.owner_task && event.sequence == parent_sequence
        });
        let Some(parent) = matching.next() else {
            return false;
        };
        if matching.next().is_some() || parent.sequence >= current.sequence {
            return false;
        }
        current = parent;
    }
    false
}

fn reviewed_runtime_failure_lazy_descendant_causality(
    authority: RuntimeFailurePresentationAuthority,
    force_boundaries: &[(u16, &str, Option<&str>)],
    semantic: &SemanticObservation,
) -> bool {
    let Some(error) = hell_builtins::lookup("Error.error") else {
        return false;
    };
    let Some(print) = hell_builtins::lookup("IO.print") else {
        return false;
    };
    let matching = |builtin| {
        semantic
            .obligation_trace
            .iter()
            .filter(|event| event.builtin == builtin)
            .collect::<Vec<_>>()
    };
    let errors = matching(error.id);
    let [error] = errors.as_slice() else {
        return false;
    };
    let targets = matching(authority.builtin)
        .into_iter()
        .filter(|target| {
            target.outcome.as_ref() == "alias"
                && reviewed_runtime_failure_obligation_descends_from(
                    error,
                    target,
                    &semantic.obligation_trace,
                )
        })
        .collect::<Vec<_>>();
    let [_target] = targets.as_slice() else {
        return false;
    };
    let exact_lazy_observations = !force_boundaries.is_empty()
        && force_boundaries.iter().all(|(_, outcome, error)| {
            matches!(*outcome, "value" | "not-forced") && error.is_none()
        })
        && force_boundaries.iter().any(|(argument, outcome, error)| {
            *argument == 1 && *outcome == "not-forced" && error.is_none()
        });
    exact_lazy_observations
        && semantic
            .coverage
            .contains(&CoverageEvent::EnteredAdapter(authority.builtin))
        && error.outcome.as_ref() == "error"
        && reviewed_runtime_failure_effect_builtin_causality(print.id, semantic)
}

fn reviewed_runtime_failure_pure_causality(
    authority: RuntimeFailurePresentationAuthority,
    target: &EvidenceTargetV2,
    semantic: &SemanticObservation,
) -> bool {
    let force_boundaries = semantic
        .force_trace
        .chunks_exact(2)
        .filter_map(|events| match events {
            [
                LogicalTraceEvent::ForceBuiltinArgument { builtin, argument },
                LogicalTraceEvent::CompleteThunk {
                    outcome,
                    error_code,
                    ..
                },
            ] if *builtin == authority.builtin => {
                Some((*argument, outcome.as_ref(), error_code.as_deref()))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    match authority.obligation {
        "adapter-failure" => {
            let matching = semantic
                .obligation_trace
                .iter()
                .filter(|event| event.builtin == authority.builtin)
                .collect::<Vec<_>>();
            semantic
                .coverage
                .contains(&CoverageEvent::EnteredAdapter(authority.builtin))
                && matching.len() == 1
                && matching[0].outcome.as_ref() == "error"
        }
        "whnf-failure-boundary" => {
            let Some(expected) = target.expected_whnf_argument_failure_sha256 else {
                return false;
            };
            let error_boundaries =
                force_boundaries
                    .iter()
                    .filter_map(|(argument, outcome, error)| match (*outcome, *error) {
                        ("error", Some(error)) => Some((*argument, *outcome, error)),
                        _ => None,
                    });
            let error_boundaries = error_boundaries.collect::<Vec<_>>();
            !error_boundaries.is_empty()
                && whnf_argument_failure_sha256(error_boundaries.iter().copied()) == expected
        }
        "lazy-boundary" => target.expected_lazy_argument_exit_sha256.map_or_else(
            || {
                reviewed_runtime_failure_lazy_descendant_causality(
                    authority,
                    &force_boundaries,
                    semantic,
                )
            },
            |expected| {
                !force_boundaries.is_empty()
                    && force_boundaries
                        .iter()
                        .any(|(_, outcome, _)| *outcome == "error")
                    && lazy_argument_exit_sha256(
                        force_boundaries
                            .iter()
                            .map(|(argument, outcome, _)| (*argument, *outcome)),
                    ) == expected
            },
        ),
        "result-force-failure" => {
            semantic
                .coverage
                .contains(&CoverageEvent::EnteredAdapter(authority.builtin))
                && semantic.typed_result_builtin == Some(authority.builtin)
                && semantic.typed_result_sha256 == target.expected_typed_result_sha256
                && target.expected_typed_result_sha256.is_some()
        }
        _ => false,
    }
}

/// Exercises the exact reviewed runtime-failure causal authority without
/// weakening the public observation-comparison boundary.
#[doc(hidden)]
#[must_use]
pub fn reviewed_runtime_failure_causality_for_integration(
    case: &DifferentialCase,
    semantic: &SemanticObservation,
) -> bool {
    reviewed_runtime_failure_presentation_authority(case)
        .is_some_and(|authority| reviewed_runtime_failure_causality(case, authority, semantic))
}

struct GhcBacktraceFrame<'a> {
    function: &'a str,
    location: &'a str,
    module: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GhcBacktraceRejection {
    Grammar,
    TerminalNewline,
    Count,
    Function,
    Origin,
}

fn ghc_backtrace_frames(frames: &str) -> Result<Vec<GhcBacktraceFrame<'_>>, GhcBacktraceRejection> {
    if frames.is_empty() {
        return Err(GhcBacktraceRejection::Grammar);
    }
    if !frames.ends_with('\n') {
        return Err(GhcBacktraceRejection::TerminalNewline);
    }
    frames
        .lines()
        .map(|line| {
            let frame = line
                .strip_prefix("  ")
                .ok_or(GhcBacktraceRejection::Grammar)?;
            let (function, location) = frame
                .split_once(", called at ")
                .ok_or(GhcBacktraceRejection::Grammar)?;
            let (location, module) = location
                .split_once(" in ")
                .ok_or(GhcBacktraceRejection::Grammar)?;
            [function, location, module]
                .iter()
                .all(|field| {
                    !field.is_empty()
                        && *field == field.trim()
                        && !field.chars().any(char::is_control)
                })
                .then_some(GhcBacktraceFrame {
                    function,
                    location,
                    module,
                })
                .ok_or(GhcBacktraceRejection::Grammar)
        })
        .collect()
}

fn ghc_backtrace_frame_has_exact_origin(
    authority: RuntimeFailurePresentationAuthority,
    frame: &GhcBacktraceFrame<'_>,
) -> bool {
    match frame.function {
        "throwIO" => {
            frame
                .location
                .starts_with("libraries/ghc-internal/src/GHC/Internal/")
                && frame.module.starts_with("ghc-internal:GHC.Internal.")
        }
        "ioError" => {
            (frame.location == "libraries/ghc-internal/src/GHC/Internal/Foreign/C/Error.hs:291:5"
                && frame.module.starts_with("ghc-internal:GHC.Internal."))
                || (frame.location == "libraries/process/System/Process/Common.hs:240:16"
                    && frame.module.starts_with("process-"))
                || (frame.location == "libraries/unix/System/Posix/PosixPath/FilePath.hsc:102:5"
                    && frame.module.starts_with("unix-"))
                || (frame.location == "libraries/directory/System/Directory/OsPath.hs:320:43"
                    && frame.module.starts_with("directory-"))
        }
        "ioException" => {
            matches!(
                frame.location,
                "libraries/ghc-internal/src/GHC/Internal/IO/Handle/Internals.hs:353:11"
                    | "libraries/ghc-internal/src/GHC/Internal/System/Environment.hs:192:26"
            ) && frame.module.starts_with("ghc-internal:GHC.Internal.")
        }
        "bracket" => {
            matches!(
                frame.location,
                "./System/IO/Temp.hs:100:3" | "./System/IO/Temp.hs:114:3"
            ) && frame.module.ends_with(":System.IO.Temp")
        }
        "error"
            if authority
                .candidate_frame_functions
                .contains(&"errorEmptyList") =>
        {
            (frame
                .location
                .starts_with("libraries/base/GHC/List.hs:2004:3")
                && frame.module.ends_with(":GHC.List"))
                || (frame
                    .location
                    .starts_with("libraries/ghc-internal/src/GHC/Internal/")
                    && frame.module.starts_with("ghc-internal:GHC.Internal."))
        }
        "error" | "cycle" => {
            frame.location == "src/Hell.hs:1953:4" && frame.module.ends_with(":Main")
        }
        "errorEmptyList" => {
            frame.location == "libraries/base/GHC/List.hs:972:27"
                && frame.module.ends_with(":GHC.List")
        }
        _ => false,
    }
}

fn exact_ghc_backtrace(
    authority: RuntimeFailurePresentationAuthority,
    frames: &str,
    expected_functions: &[&str],
) -> bool {
    exact_ghc_backtrace_result(authority, frames, expected_functions).is_ok()
}

fn exact_ghc_backtrace_result(
    authority: RuntimeFailurePresentationAuthority,
    frames: &str,
    expected_functions: &[&str],
) -> Result<(), GhcBacktraceRejection> {
    let frames = ghc_backtrace_frames(frames)?;
    if frames.len() != expected_functions.len() {
        return Err(GhcBacktraceRejection::Count);
    }
    for (frame, function) in frames.iter().zip(expected_functions) {
        if frame.function != *function {
            return Err(GhcBacktraceRejection::Function);
        }
        if !ghc_backtrace_frame_has_exact_origin(authority, frame) {
            return Err(GhcBacktraceRejection::Origin);
        }
    }
    Ok(())
}

const fn oracle_frame_rejection(
    rejection: GhcBacktraceRejection,
) -> RuntimeFailureProjectionRejectionReason {
    use RuntimeFailureProjectionRejectionReason::{
        OracleFrameCount, OracleFrameFunction, OracleFrameGrammar, OracleFrameOrigin,
        OracleFrameTerminalNewline,
    };
    match rejection {
        GhcBacktraceRejection::Grammar => OracleFrameGrammar,
        GhcBacktraceRejection::TerminalNewline => OracleFrameTerminalNewline,
        GhcBacktraceRejection::Count => OracleFrameCount,
        GhcBacktraceRejection::Function => OracleFrameFunction,
        GhcBacktraceRejection::Origin => OracleFrameOrigin,
    }
}

fn after_path_handling_matches(payload: &str, handling: &str, prefix: &str) -> bool {
    let Some((path, operation)) = payload.split_once(": ") else {
        return false;
    };
    let Some(operation_without_prefix) = operation.strip_prefix(prefix) else {
        return false;
    };
    handling.len() == path.len() + 2 + operation_without_prefix.len()
        && handling.starts_with(path)
        && handling.as_bytes().get(path.len()) == Some(&b':')
        && handling.as_bytes().get(path.len() + 1) == Some(&b' ')
        && handling.ends_with(operation_without_prefix)
}

#[derive(Clone, Copy)]
struct OracleFramedPayload<'a> {
    outer: &'a str,
    handling: Option<&'a str>,
    selected: &'a str,
    selection: RuntimeFailureOraclePayloadSelection,
}

fn oracle_framed_payload_components_result(
    authority: RuntimeFailurePresentationAuthority,
    framed_payload: &str,
) -> Result<OracleFramedPayload<'_>, RuntimeFailureProjectionRejectionReason> {
    use RuntimeFailureProjectionRejectionReason::{
        OracleFrameGrammar, OraclePayloadHandlingMismatch, OraclePayloadHandlingMissing,
        OraclePayloadUnexpectedHandling,
    };
    const HANDLING_MARKER: &str = "\n\nWhile handling ";

    match authority.while_handling {
        RuntimeFailureHandlingProjection::None => {
            if framed_payload.contains(HANDLING_MARKER) {
                return Err(OraclePayloadUnexpectedHandling);
            }
            let outer =
                if authority.oracle_frame_layout == RuntimeFailureOracleFrameLayout::Frameless {
                    framed_payload.strip_suffix('\n').ok_or(OracleFrameGrammar)
                } else {
                    Ok(framed_payload)
                }?;
            Ok(OracleFramedPayload {
                outer,
                handling: None,
                selected: outer,
                selection: RuntimeFailureOraclePayloadSelection::Outer,
            })
        }
        projection => {
            let (payload, handling) = framed_payload
                .split_once(HANDLING_MARKER)
                .ok_or(OraclePayloadHandlingMissing)?;
            let handling =
                if authority.oracle_frame_layout == RuntimeFailureOracleFrameLayout::Frameless {
                    handling.strip_suffix('\n').ok_or(OracleFrameGrammar)?
                } else {
                    handling
                };
            let handling_matches = match projection {
                RuntimeFailureHandlingProjection::Payload => handling == payload,
                RuntimeFailureHandlingProjection::Prefix(prefix) => payload
                    .strip_prefix(prefix)
                    .is_some_and(|expected_handling| expected_handling == handling),
                RuntimeFailureHandlingProjection::AfterPathPrefix(prefix) => {
                    after_path_handling_matches(payload, handling, prefix)
                }
                RuntimeFailureHandlingProjection::None => {
                    unreachable!("the outer match established that oracle handling is projected")
                }
            };
            if !handling_matches {
                return Err(OraclePayloadHandlingMismatch);
            }
            Ok(OracleFramedPayload {
                outer: payload,
                handling: Some(handling),
                selected: payload,
                selection: RuntimeFailureOraclePayloadSelection::Outer,
            })
        }
    }
}

fn oracle_exception_payload_result(
    authority: RuntimeFailurePresentationAuthority,
    stderr: &[u8],
) -> Result<&str, RuntimeFailureProjectionRejectionReason> {
    oracle_exception_payload_components_result(authority, stderr)
        .map(|components| components.selected)
}

fn oracle_exception_payload_components_result(
    authority: RuntimeFailurePresentationAuthority,
    stderr: &[u8],
) -> Result<OracleFramedPayload<'_>, RuntimeFailureProjectionRejectionReason> {
    use RuntimeFailureProjectionRejectionReason::{
        OracleExceptionFamily, OracleFrameGrammar, OracleParserStage, OraclePayloadControl,
        OraclePayloadEmpty, OraclePayloadMultiline,
    };
    const BACKTRACE_MARKER: &str = "\n\nHasCallStack backtrace:\n";

    let stderr = std::str::from_utf8(stderr).map_err(|_| OracleParserStage)?;
    let body = stderr
        .strip_prefix("hell: Uncaught exception ")
        .ok_or(OracleParserStage)?;
    let body = match authority.family {
        RuntimeFailureExceptionFamily::UnicodeException => {
            let (unit, body) = body
                .split_once(":Data.Text.Encoding.Error.UnicodeException:\n\n")
                .ok_or(OracleExceptionFamily)?;
            if !unit.starts_with("text-")
                || unit.len() <= "text-".len()
                || !unit
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
            {
                return Err(OracleExceptionFamily);
            }
            body
        }
        RuntimeFailureExceptionFamily::IOException => body
            .strip_prefix("ghc-internal:GHC.Internal.IO.Exception.IOException:\n\n")
            .ok_or(OracleExceptionFamily)?,
        RuntimeFailureExceptionFamily::ErrorCall => body
            .strip_prefix("ghc-internal:GHC.Internal.Exception.ErrorCall:\n\n")
            .ok_or(OracleExceptionFamily)?,
    };
    // The upstream uncaught-exception renderer emits a blank line after its
    // final frame (or handling clause). Remove exactly that renderer newline;
    // frame and handling parsers below retain and enforce the payload newline.
    let body = body.strip_suffix('\n').ok_or(OracleFrameGrammar)?;
    let (framed_payload, frames) = match authority.oracle_frame_layout {
        RuntimeFailureOracleFrameLayout::Ghc => {
            let (framed_payload, frames) = body
                .split_once(BACKTRACE_MARKER)
                .ok_or(OracleFrameGrammar)?;
            (framed_payload, Some(frames))
        }
        RuntimeFailureOracleFrameLayout::Frameless => {
            if body.contains(BACKTRACE_MARKER) {
                return Err(OracleFrameGrammar);
            }
            (body, None)
        }
    };
    let components = oracle_framed_payload_components_result(authority, framed_payload)?;
    if components.selected.is_empty() {
        return Err(OraclePayloadEmpty);
    }
    if components.selected.contains('\n') {
        return Err(OraclePayloadMultiline);
    }
    if components.selected.chars().any(char::is_control) {
        return Err(OraclePayloadControl);
    }
    if let Some(frames) = frames {
        exact_ghc_backtrace_result(authority, frames, authority.oracle_frame_functions)
            .map_err(oracle_frame_rejection)?;
    }
    Ok(components)
}

fn candidate_exception_payload_result(
    authority: RuntimeFailurePresentationAuthority,
    stderr: &[u8],
) -> Result<&str, RuntimeFailureProjectionRejectionReason> {
    use RuntimeFailureProjectionRejectionReason::{
        CandidateFrame, CandidateLegacyParser, CandidatePayload,
    };

    let candidate = std::str::from_utf8(stderr).map_err(|_| CandidateLegacyParser)?;
    let payload = candidate
        .strip_prefix("hell: ")
        .ok_or(CandidateLegacyParser)?;
    let payload = match authority.family {
        RuntimeFailureExceptionFamily::UnicodeException
        | RuntimeFailureExceptionFamily::IOException => {
            if !authority.candidate_frame_functions.is_empty() {
                return Err(CandidateFrame);
            }
            payload.strip_suffix('\n').ok_or(CandidateLegacyParser)?
        }
        RuntimeFailureExceptionFamily::ErrorCall => {
            let (payload, frames) = payload
                .split_once("\nCallStack (from HasCallStack):\n")
                .ok_or(CandidateLegacyParser)?;
            if !exact_ghc_backtrace(authority, frames, authority.candidate_frame_functions) {
                return Err(CandidateFrame);
            }
            payload
        }
    };
    if payload.is_empty() || payload.contains('\n') || payload.chars().any(char::is_control) {
        return Err(CandidatePayload);
    }
    Ok(payload)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ReviewedRuntimeFailurePayloadEvidence {
    oracle_payload_sha256: Digest,
    candidate_payload_sha256: Digest,
}

fn reviewed_runtime_failure_payload_evidence_result(
    authority: RuntimeFailurePresentationAuthority,
    oracle_stderr: &[u8],
    candidate_stderr: &[u8],
) -> Result<ReviewedRuntimeFailurePayloadEvidence, RuntimeFailureProjectionRejectionReason> {
    let oracle_payload = oracle_exception_payload_result(authority, oracle_stderr)?;
    let candidate_payload = candidate_exception_payload_result(authority, candidate_stderr)?;
    Ok(ReviewedRuntimeFailurePayloadEvidence {
        oracle_payload_sha256: sha256_bytes(oracle_payload.as_bytes()),
        candidate_payload_sha256: sha256_bytes(candidate_payload.as_bytes()),
    })
}

pub(crate) fn reviewed_runtime_failure_payload_sha256(
    authority: RuntimeFailurePresentationAuthority,
    oracle_stderr: &[u8],
    candidate_stderr: &[u8],
) -> Option<Digest> {
    reviewed_runtime_failure_payload_sha256_result(authority, oracle_stderr, candidate_stderr).ok()
}

fn reviewed_runtime_failure_payload_sha256_result(
    authority: RuntimeFailurePresentationAuthority,
    oracle_stderr: &[u8],
    candidate_stderr: &[u8],
) -> Result<Digest, RuntimeFailureProjectionRejectionReason> {
    if runtime_failure_mutant_active("runtime-failure-frame-payload-authority") {
        return Ok(sha256_bytes(candidate_stderr));
    }
    let evidence = reviewed_runtime_failure_payload_evidence_result(
        authority,
        oracle_stderr,
        candidate_stderr,
    )?;
    (evidence.oracle_payload_sha256 == evidence.candidate_payload_sha256)
        .then_some(evidence.oracle_payload_sha256)
        .ok_or(RuntimeFailureProjectionRejectionReason::PayloadMismatch)
}

#[cfg(test)]
mod runtime_failure_presentation_tests {
    use super::{
        RuntimeFailureProjectionRejectionReason, candidate_exception_payload_result,
        oracle_exception_payload_result, reviewed_runtime_failure_payload_sha256,
        reviewed_runtime_failure_presentation_authority,
    };

    fn authority(id: &str) -> super::RuntimeFailurePresentationAuthority {
        let cases = crate::committed_differential_cases();
        let case = cases
            .iter()
            .find(|case| case.id.as_ref() == id)
            .expect("reviewed runtime-failure case");
        reviewed_runtime_failure_presentation_authority(case)
            .expect("reviewed runtime-failure presentation authority")
    }

    fn io_oracle(payload: &str, frames: &str) -> String {
        format!(
            concat!(
                "hell: Uncaught exception ",
                "ghc-internal:GHC.Internal.IO.Exception.IOException:\n\n",
                "{}\n\nHasCallStack backtrace:\n{}\n",
            ),
            payload, frames,
        )
    }

    fn temp_oracle(framed_payload: &str) -> String {
        format!(
            concat!(
                "hell: Uncaught exception ",
                "ghc-internal:GHC.Internal.Exception.ErrorCall:\n\n",
                "{}\n\nHasCallStack backtrace:\n",
                "  error, called at src/Hell.hs:1953:4 in oracle-unit:Main\n",
            ),
            framed_payload,
        )
    }

    fn assert_oracle_rejection(
        authority: super::RuntimeFailurePresentationAuthority,
        stderr: &str,
        expected: RuntimeFailureProjectionRejectionReason,
    ) {
        assert_eq!(
            oracle_exception_payload_result(authority, stderr.as_bytes()).map(|_| ()),
            Err(expected),
        );
    }

    #[test]
    fn oracle_frame_rejection_subreasons_are_exact() {
        use RuntimeFailureProjectionRejectionReason::{
            OracleFrameCount, OracleFrameFunction, OracleFrameGrammar, OracleFrameOrigin,
            OracleFrameTerminalNewline,
        };

        let authority = authority("runtime-typed-io-text-writefile-failure");
        let frame = concat!(
            "  ioError, called at libraries/ghc-internal/src/GHC/Internal/Foreign/C/Error.hs:291:5 ",
            "in ghc-internal:GHC.Internal.Foreign.C.Error\n",
        );
        let oracle = io_oracle("reviewed", frame);
        assert!(oracle_exception_payload_result(authority, oracle.as_bytes()).is_ok());
        assert_oracle_rejection(
            authority,
            &oracle.replace(", called at ", ", invoked at "),
            OracleFrameGrammar,
        );
        assert_oracle_rejection(
            authority,
            oracle.strip_suffix('\n').expect("terminal newline"),
            OracleFrameTerminalNewline,
        );
        assert_oracle_rejection(
            authority,
            &format!(
                "{}{}\n",
                oracle.strip_suffix('\n').expect("renderer newline"),
                frame
            ),
            OracleFrameCount,
        );
        assert_oracle_rejection(
            authority,
            &oracle.replace("  ioError, called at", "  injected, called at"),
            OracleFrameFunction,
        );
        assert_oracle_rejection(
            authority,
            &oracle.replace("GHC/Internal/Foreign/C/Error.hs", "Unrelated/Injected.hs"),
            OracleFrameOrigin,
        );
    }

    #[test]
    fn oracle_payload_line_rejection_subreasons_are_exact() {
        use RuntimeFailureProjectionRejectionReason::{
            OraclePayloadControl, OraclePayloadEmpty, OraclePayloadMultiline,
            OraclePayloadUnexpectedHandling,
        };

        let authority = authority("runtime-typed-io-text-writefile-failure");
        let frame = concat!(
            "  throwIO, called at libraries/ghc-internal/src/GHC/Internal/IO.hs:1:1 ",
            "in ghc-internal:GHC.Internal.IO\n",
        );
        for (payload, reason) in [
            ("", OraclePayloadEmpty),
            ("reviewed\ncontinued", OraclePayloadMultiline),
            ("reviewed\tcontrol", OraclePayloadControl),
            (
                "reviewed\n\nWhile handling reviewed",
                OraclePayloadUnexpectedHandling,
            ),
        ] {
            assert_oracle_rejection(authority, &io_oracle(payload, frame), reason);
        }
    }

    #[test]
    fn oracle_payload_handling_rejection_subreasons_are_exact() {
        use RuntimeFailureProjectionRejectionReason::{
            OraclePayloadHandlingMismatch, OraclePayloadHandlingMissing,
        };

        let authority = authority("runtime-temp-directory-failure");
        assert_oracle_rejection(
            authority,
            &temp_oracle("reviewed"),
            OraclePayloadHandlingMissing,
        );
        assert_oracle_rejection(
            authority,
            &temp_oracle("reviewed\n\nWhile handling substituted"),
            OraclePayloadHandlingMismatch,
        );
    }

    #[test]
    fn exception_projection_rejects_family_payload_program_frame_and_tail_forgery() {
        let authority = authority("runtime-typed-io-text-writefile-failure");
        let oracle = concat!(
            "hell: Uncaught exception ",
            "ghc-internal:GHC.Internal.IO.Exception.IOException:\n\n",
            "missing-parent/file.txt: withBinaryFile: does not exist\n\n",
            "HasCallStack backtrace:\n",
            "  ioError, called at libraries/ghc-internal/src/GHC/Internal/Foreign/C/Error.hs:291:5 ",
            "in ghc-internal:GHC.Internal.Foreign.C.Error\n\n",
        );
        let candidate = "hell: missing-parent/file.txt: withBinaryFile: does not exist\n";
        assert!(
            reviewed_runtime_failure_payload_sha256(
                authority,
                oracle.as_bytes(),
                candidate.as_bytes(),
            )
            .is_some()
        );
        assert_eq!(
            oracle_exception_payload_result(
                authority,
                oracle
                    .replace(
                        "GHC.Internal.IO.Exception.IOException",
                        "GHC.Internal.Exception.ErrorCall",
                    )
                    .as_bytes(),
            ),
            Err(RuntimeFailureProjectionRejectionReason::OracleExceptionFamily),
        );
        assert_eq!(
            oracle_exception_payload_result(
                authority,
                oracle
                    .replace("  ioError, called at", "  injected, called at")
                    .as_bytes(),
            ),
            Err(RuntimeFailureProjectionRejectionReason::OracleFrameFunction),
        );
        assert_eq!(
            candidate_exception_payload_result(authority, b"other: reviewed\n"),
            Err(RuntimeFailureProjectionRejectionReason::CandidateLegacyParser),
        );
        assert_eq!(
            candidate_exception_payload_result(authority, b"hell: \n"),
            Err(RuntimeFailureProjectionRejectionReason::CandidatePayload),
        );
        for forged in [
            oracle.replace(
                "GHC.Internal.IO.Exception.IOException",
                "GHC.Internal.Exception.ErrorCall",
            ),
            oracle.replacen("hell:", "other:", 1),
            oracle.replacen("IOException:\n\n", "IOException:\n", 1),
            oracle.replace(
                "  ioError, called at",
                concat!(
                    "  ioError, called at libraries/ghc-internal/src/GHC/Internal/Foreign/C/Error.hs:291:5 ",
                    "in ghc-internal:GHC.Internal.Foreign.C.Error\n",
                    "  ioError, called at",
                ),
            ),
            oracle.replace("GHC/Internal/Foreign/C/Error.hs", "Unrelated/Injected.hs"),
            format!("{oracle}contamination\n"),
        ] {
            assert!(
                reviewed_runtime_failure_payload_sha256(
                    authority,
                    forged.as_bytes(),
                    candidate.as_bytes(),
                )
                .is_none(),
                "forged oracle frame was admitted: {forged:?}",
            );
        }
        assert!(
            reviewed_runtime_failure_payload_sha256(
                authority,
                oracle.as_bytes(),
                b"hell: substituted payload\n",
            )
            .is_none()
        );
    }

    #[test]
    fn error_call_and_while_handling_frames_are_exactly_case_scoped() {
        let strict = authority("runtime-typed-map-singleton-key-strict");
        let strict_oracle = concat!(
            "hell: Uncaught exception ghc-internal:GHC.Internal.Exception.ErrorCall:\n\n",
            "singleton key forced\n\nHasCallStack backtrace:\n",
            "  throwIO, called at libraries/ghc-internal/src/GHC/Internal/IO/Handle/Internals.hs:195:13 ",
            "in ghc-internal:GHC.Internal.IO.Handle.Internals\n\n",
        );
        let strict_candidate = concat!(
            "hell: singleton key forced\nCallStack (from HasCallStack):\n",
            "  error, called at src/Hell.hs:1953:4 in main:Main\n",
        );
        assert!(
            reviewed_runtime_failure_payload_sha256(
                strict,
                strict_oracle.as_bytes(),
                strict_candidate.as_bytes(),
            )
            .is_some()
        );

        let temp = authority("runtime-temp-directory-failure");
        let temp_oracle = concat!(
            "hell: Uncaught exception ghc-internal:GHC.Internal.Exception.ErrorCall:\n\n",
            "reviewed\n\nWhile handling reviewed\n\nHasCallStack backtrace:\n",
            "  bracket, called at ./System/IO/Temp.hs:114:3 ",
            "in temporary-1.3-J41jdMVG6l2EtxMrdNnhIO:System.IO.Temp\n\n",
        );
        let temp_candidate = concat!(
            "hell: reviewed\nCallStack (from HasCallStack):\n",
            "  error, called at src/Hell.hs:1953:4 in main:Main\n",
        );
        assert!(
            reviewed_runtime_failure_payload_sha256(
                temp,
                temp_oracle.as_bytes(),
                temp_candidate.as_bytes(),
            )
            .is_some()
        );
        assert!(
            reviewed_runtime_failure_payload_sha256(
                temp,
                temp_oracle
                    .replace("While handling reviewed", "While handling substituted")
                    .as_bytes(),
                temp_candidate.as_bytes(),
            )
            .is_none()
        );
        assert!(
            reviewed_runtime_failure_payload_sha256(
                strict,
                temp_oracle.as_bytes(),
                temp_candidate.as_bytes(),
            )
            .is_none()
        );
    }
}

fn reviewed_runtime_failure_stderr_projection(
    case: &DifferentialCase,
    oracle: &Observation,
    candidate: &Observation,
) -> Option<DifferentialComparisonProjection> {
    if runtime_failure_presentation_spec(&case.id).is_some() {
        return reviewed_runtime_failure_exception_stderr_projection(case, oracle, candidate);
    }
    reviewed_legacy_runtime_failure_stderr_projection(case, oracle, candidate)
}

fn reviewed_runtime_failure_exception_stderr_projection(
    case: &DifferentialCase,
    oracle: &Observation,
    candidate: &Observation,
) -> Option<DifferentialComparisonProjection> {
    reviewed_runtime_failure_exception_stderr_projection_result(case, oracle, candidate).ok()
}

fn runtime_failure_observations_are_bound(
    case: &DifferentialCase,
    oracle: &Observation,
    candidate: &Observation,
) -> bool {
    if oracle.identity.role != ExecutableRole::Oracle
        || candidate.identity.role != ExecutableRole::Candidate
        || oracle.case_id != case.id
        || candidate.case_id != case.id
        || oracle.environment_profile != case.environment_profile
        || candidate.environment_profile != case.environment_profile
        || oracle.process_helper_sha256 != case.process_helper_sha256
        || candidate.process_helper_sha256 != case.process_helper_sha256
        || oracle.harness_normalizers != applied_harness_normalizers()
        || candidate.harness_normalizers != applied_harness_normalizers()
        || oracle.claim_normalizers != applied_claim_normalizers(case)
        || candidate.claim_normalizers != applied_claim_normalizers(case)
        || oracle.mode != DifferentialMode::Run
        || candidate.mode != DifferentialMode::Run
        || oracle.timed_out
        || candidate.timed_out
        || oracle.status.success
        || candidate.status.success
        || oracle.status != candidate.status
        || oracle.stdout != candidate.stdout
        || oracle.filesystem != candidate.filesystem
        || oracle.stderr.truncated
        || candidate.stderr.truncated
        || oracle.stderr == candidate.stderr
    {
        return false;
    }
    true
}

fn reviewed_runtime_failure_exception_stderr_projection_result(
    case: &DifferentialCase,
    oracle: &Observation,
    candidate: &Observation,
) -> Result<DifferentialComparisonProjection, RuntimeFailureProjectionRejectionReason> {
    use RuntimeFailureProjectionRejectionReason::{
        DescriptorTable, MissingCandidateSemantic, MissingCandidateStderr, MissingOracleStderr,
        ObservationAuthority, SemanticCausality, SemanticTarget,
    };

    let authority = reviewed_runtime_failure_presentation_authority(case).ok_or(DescriptorTable)?;
    let semantic = candidate
        .semantic
        .as_ref()
        .ok_or(MissingCandidateSemantic)?;
    let oracle_stderr = oracle
        .stderr
        .complete
        .as_deref()
        .ok_or(MissingOracleStderr)?;
    let candidate_stderr = candidate
        .stderr
        .complete
        .as_deref()
        .ok_or(MissingCandidateStderr)?;
    if !runtime_failure_observations_are_bound(case, oracle, candidate) {
        return Err(ObservationAuthority);
    }
    let payload_sha256 =
        reviewed_runtime_failure_payload_sha256_result(authority, oracle_stderr, candidate_stderr)?;
    if runtime_failure_target(case, authority).is_none() {
        return Err(SemanticTarget);
    }
    if !reviewed_runtime_failure_causality(case, authority, semantic) {
        return Err(SemanticCausality);
    }
    Ok(
        DifferentialComparisonProjection::ReviewedRuntimeFailureExceptionStderr {
            exception_family: authority.family,
            payload_sha256,
            oracle_sha256: oracle.stderr.sha256,
            candidate_sha256: candidate.stderr.sha256,
            oracle_bytes: oracle.stderr.total_bytes,
            candidate_bytes: candidate.stderr.total_bytes,
        },
    )
}

/// Returns bounded diagnostic evidence when one exact-table runtime-failure
/// projection is rejected. A successful projection and every non-table case
/// return `None`; this function never changes comparison authority.
#[must_use]
pub fn runtime_failure_projection_rejection(
    case: &DifferentialCase,
    oracle: &Observation,
    candidate: &Observation,
) -> Option<RuntimeFailureProjectionRejection> {
    let spec = runtime_failure_presentation_spec(&case.id)?;
    let reason =
        reviewed_runtime_failure_exception_stderr_projection_result(case, oracle, candidate)
            .err()?;
    let semantic = candidate.semantic.as_ref();
    Some(RuntimeFailureProjectionRejection {
        reason,
        exception_family: spec.family,
        descriptor_builtin: spec.builtin,
        descriptor_dimension: spec.dimension,
        descriptor_obligation: spec.obligation,
        oracle_stderr_sha256: oracle.stderr.sha256,
        oracle_stderr_bytes: oracle.stderr.total_bytes,
        candidate_stderr_sha256: candidate.stderr.sha256,
        candidate_stderr_bytes: candidate.stderr.total_bytes,
        semantic_present: semantic.is_some(),
        typed_result_sha256_present: semantic
            .is_some_and(|value| value.typed_result_sha256.is_some()),
        typed_result_builtin_present: semantic
            .is_some_and(|value| value.typed_result_builtin.is_some()),
        semantic_coverage_count: semantic.map_or(0, |value| value.coverage.len()),
        obligation_event_count: semantic.map_or(0, |value| value.obligation_trace.len()),
        causal_order_count: semantic.map_or(0, |value| value.causal_event_order.len()),
        force_event_count: semantic.map_or(0, |value| value.force_trace.len()),
        effect_event_count: semantic.map_or(0, |value| value.effect_trace.len()),
        task_event_count: semantic.map_or(0, |value| value.task_trace.len()),
        resource_event_count: semantic.map_or(0, |value| value.resource_trace.len()),
    })
}

const RUNTIME_FAILURE_PAYLOAD_DIAGNOSTIC_PREFIX_BYTES: usize = 256;

fn runtime_failure_payload_component_diagnostic(
    payload: &str,
) -> RuntimeFailurePayloadComponentDiagnostic {
    let mut prefix_end = 0;
    for (index, character) in payload.char_indices() {
        let next = index + character.len_utf8();
        if next > RUNTIME_FAILURE_PAYLOAD_DIAGNOSTIC_PREFIX_BYTES {
            break;
        }
        prefix_end = next;
    }
    RuntimeFailurePayloadComponentDiagnostic {
        bytes: u64::try_from(payload.len()).expect("payload length fits u64"),
        sha256: sha256_bytes(payload.as_bytes()),
        utf8_prefix: payload[..prefix_end].to_owned(),
        prefix_truncated: prefix_end != payload.len(),
    }
}

/// Returns bounded parsed payload components for a payload-mismatch rejection.
///
/// This diagnostic does not change comparison authority. It is available only after the exact
/// observation binding, exception-family parser, frame parser, and handling relation succeed.
#[must_use]
pub fn runtime_failure_payload_diagnostic(
    case: &DifferentialCase,
    oracle: &Observation,
    candidate: &Observation,
) -> Option<RuntimeFailurePayloadDiagnostic> {
    let authority = reviewed_runtime_failure_presentation_authority(case)?;
    if !runtime_failure_observations_are_bound(case, oracle, candidate) {
        return None;
    }
    let oracle_stderr = oracle.stderr.complete.as_deref()?;
    let candidate_stderr = candidate.stderr.complete.as_deref()?;
    if reviewed_runtime_failure_payload_sha256_result(authority, oracle_stderr, candidate_stderr)
        != Err(RuntimeFailureProjectionRejectionReason::PayloadMismatch)
    {
        return None;
    }
    let oracle_components =
        oracle_exception_payload_components_result(authority, oracle_stderr).ok()?;
    let candidate_payload = candidate_exception_payload_result(authority, candidate_stderr).ok()?;
    let relationship = if candidate_payload == oracle_components.selected {
        RuntimeFailurePayloadRelationship::Selected
    } else if candidate_payload == oracle_components.outer {
        RuntimeFailurePayloadRelationship::Outer
    } else if oracle_components.handling == Some(candidate_payload) {
        RuntimeFailurePayloadRelationship::Handling
    } else {
        RuntimeFailurePayloadRelationship::Distinct
    };
    Some(RuntimeFailurePayloadDiagnostic {
        mismatch_field: "oracle-selected-payload-vs-candidate-payload",
        handling_projection: authority.while_handling.descriptor_name(),
        oracle_selection: oracle_components.selection,
        relationship,
        oracle_outer: runtime_failure_payload_component_diagnostic(oracle_components.outer),
        oracle_handling: oracle_components
            .handling
            .map(runtime_failure_payload_component_diagnostic),
        oracle_selected: runtime_failure_payload_component_diagnostic(oracle_components.selected),
        candidate: runtime_failure_payload_component_diagnostic(candidate_payload),
    })
}

fn reviewed_legacy_runtime_failure_stderr_projection(
    case: &DifferentialCase,
    oracle: &Observation,
    candidate: &Observation,
) -> Option<DifferentialComparisonProjection> {
    let builtin = reviewed_legacy_runtime_failure_stderr_builtin(case)?;
    if oracle.identity.role != ExecutableRole::Oracle
        || candidate.identity.role != ExecutableRole::Candidate
        || oracle.case_id != case.id
        || candidate.case_id != case.id
        || oracle.environment_profile != case.environment_profile
        || candidate.environment_profile != case.environment_profile
        || oracle.process_helper_sha256 != case.process_helper_sha256
        || candidate.process_helper_sha256 != case.process_helper_sha256
        || oracle.harness_normalizers != applied_harness_normalizers()
        || candidate.harness_normalizers != applied_harness_normalizers()
        || oracle.claim_normalizers != applied_claim_normalizers(case)
        || candidate.claim_normalizers != applied_claim_normalizers(case)
        || oracle.mode != DifferentialMode::Run
        || candidate.mode != DifferentialMode::Run
        || oracle.timed_out
        || candidate.timed_out
        || oracle.status.success
        || candidate.status.success
        || oracle.status != candidate.status
        || oracle.stdout != candidate.stdout
        || oracle.filesystem != candidate.filesystem
        || oracle.stderr.truncated
        || candidate.stderr.truncated
        || oracle.stderr == candidate.stderr
    {
        return None;
    }
    let semantic = candidate.semantic.as_ref()?;
    if !semantic
        .coverage
        .contains(&CoverageEvent::EnteredAdapter(builtin))
    {
        return None;
    }
    let expected_task_trace = reviewed_runtime_failure_expected_task_trace(case, builtin).ok()?;
    if expected_task_trace
        .is_some_and(|expected| semantic_task_trace_sha256(semantic, builtin) != expected)
    {
        return None;
    }
    let effects = semantic
        .effect_trace
        .iter()
        .filter_map(|event| match event {
            LogicalTraceEvent::HostEffect {
                builtin: observed,
                owner_task,
                sequence,
                parent_sequence,
                effect,
            } if *observed == builtin => Some((*owner_task, *sequence, *parent_sequence, effect)),
            _ => None,
        })
        .collect::<Vec<_>>();
    if effects.len() != 2
        || effects[0].0 != effects[1].0
        || effects[0].1 != effects[1].1
        || effects[0].2 != effects[1].2
        || effects[0].3.as_ref() != "started"
        || effects[1].3.as_ref() != "failed"
    {
        return None;
    }
    Some(
        DifferentialComparisonProjection::ReviewedRuntimeFailureStderr {
            oracle_sha256: oracle.stderr.sha256,
            candidate_sha256: candidate.stderr.sha256,
            oracle_bytes: oracle.stderr.total_bytes,
            candidate_bytes: candidate.stderr.total_bytes,
        },
    )
}

fn push_mismatch(
    mismatches: &mut Vec<DifferentialMismatch>,
    kind: MismatchKind,
    oracle: &[u8],
    candidate: &[u8],
) {
    if oracle != candidate {
        mismatches.push(DifferentialMismatch {
            kind,
            oracle: oracle.to_vec(),
            candidate: candidate.to_vec(),
        });
    }
}

fn push_capture_mismatch(
    mismatches: &mut Vec<DifferentialMismatch>,
    kind: MismatchKind,
    oracle: &BoundedCapture,
    candidate: &BoundedCapture,
) {
    if oracle.total_bytes != candidate.total_bytes || oracle.sha256 != candidate.sha256 {
        mismatches.push(DifferentialMismatch {
            kind,
            oracle: oracle.mismatch_bytes(),
            candidate: candidate.mismatch_bytes(),
        });
    }
}

fn observe_source(
    identity: &ExecutableIdentity,
    case: &DifferentialCase,
    label: &str,
    profile: ExecutionProfile,
) -> std::io::Result<Observation> {
    observe_source_timed(identity, case, label, profile, None).map(|timed| timed.observation)
}

struct TimedObservation {
    observation: Observation,
    process_duration: Duration,
}

fn observe_source_timed(
    identity: &ExecutableIdentity,
    case: &DifferentialCase,
    label: &str,
    profile: ExecutionProfile,
    sandbox_sequence: Option<u64>,
) -> std::io::Result<TimedObservation> {
    observe_source_with_optional_target(
        identity,
        case,
        label,
        profile,
        None,
        false,
        sandbox_sequence,
    )
}

fn observe_source_with_nonclaim_target(
    identity: &ExecutableIdentity,
    case: &DifferentialCase,
    label: &str,
    profile: ExecutionProfile,
    target: BuiltinId,
) -> std::io::Result<Observation> {
    observe_source_with_optional_target(identity, case, label, profile, Some(target), true, None)
        .map(|timed| timed.observation)
}

fn observe_source_with_optional_target(
    identity: &ExecutableIdentity,
    case: &DifferentialCase,
    label: &str,
    profile: ExecutionProfile,
    nonclaim_target: Option<BuiltinId>,
    force_semantic_trace: bool,
    sandbox_sequence: Option<u64>,
) -> std::io::Result<TimedObservation> {
    let sandbox = Sandbox::new(label, sandbox_sequence)?;
    let script = sandbox.path.join("main.hell");
    fs::write(&script, case.source.as_bytes())?;
    let resource_audit_path = (identity.role == ExecutableRole::Candidate
        && case.mode == DifferentialMode::Run)
        .then(|| sandbox.path.join("candidate-resource-audit.json"));
    let semantic_trace_path = (identity.role == ExecutableRole::Candidate
        && case.mode == DifferentialMode::Run
        && (case.claim_evidence.is_some() || force_semantic_trace))
        .then(|| sandbox.path.join("candidate-semantic-trace.json"));
    let captured = capture_process(
        &identity.path,
        identity.role,
        &script,
        &sandbox.path,
        case,
        profile,
        CaptureEvidence {
            resource_audit_path: resource_audit_path.as_deref(),
            semantic_trace_path: semantic_trace_path.as_deref(),
            nonclaim_target,
        },
    )?;
    let resource_audit = resource_audit_path
        .as_ref()
        .map(|path| {
            let bytes = fs::read(path)
                .map_err(|error| missing_resource_audit_error(path, &error, &captured))?;
            let audit = parse_resource_audit(&bytes)?;
            fs::remove_file(path)?;
            Ok::<ResourceAudit, std::io::Error>(audit)
        })
        .transpose()?;
    let semantic = semantic_trace_path
        .as_ref()
        .map(|path| read_semantic_trace(path, force_semantic_trace, &captured))
        .transpose()?
        .flatten();
    let raw_stderr = captured.stderr.clone();
    let stderr = captured
        .stderr
        .complete
        .ok_or_else(|| std::io::Error::other("stderr exceeded the normalization capture bound"))?;
    let mut stderr = diagnostic_sandbox_path_v1(&stderr, &identity.path, &sandbox.path, &script);
    for (from, to) in &case.normalization.stderr_replacements {
        stderr = replace_all(&stderr, from, to);
    }
    let claim_input_stderr = BoundedCapture::from_bytes(stderr.clone());
    if case.normalization.normalize_path_separators {
        diagnostic_path_separator_v1(&mut stderr);
    }
    let diagnostic = (case.mode == DifferentialMode::Check && !captured.status.success())
        .then(|| parse_diagnostic_observation(&stderr))
        .transpose()?;
    Ok(TimedObservation {
        observation: Observation {
            identity: identity.clone(),
            case_id: Arc::clone(&case.id),
            environment_profile: case.environment_profile,
            process_helper_sha256: case.process_helper_sha256,
            mode: case.mode,
            status: captured.status.into(),
            stdout: captured.stdout,
            raw_stderr,
            claim_input_stderr,
            stderr: BoundedCapture::from_bytes(stderr),
            normalizer_sandbox: sandbox.path.clone(),
            normalizer_script: script,
            timed_out: captured.timed_out,
            diagnostic,
            filesystem: snapshot_filesystem(&sandbox.path)?,
            harness_normalizers: applied_harness_normalizers(),
            claim_normalizers: applied_claim_normalizers(case),
            resource_audit,
            semantic,
        },
        process_duration: captured.duration,
    })
}

fn missing_resource_audit_error(
    path: &Path,
    error: &std::io::Error,
    captured: &CapturedProcess,
) -> std::io::Error {
    let stderr = captured.stderr.mismatch_bytes();
    let stderr = String::from_utf8_lossy(&stderr);
    std::io::Error::new(
        error.kind(),
        format!(
            "candidate did not retain resource audit {} after status {:?}, timed out {}: {error}; child stderr: {stderr}",
            path.display(),
            captured.status.code(),
            captured.timed_out,
        ),
    )
}

fn read_semantic_trace(
    path: &Path,
    absent_is_nonclaim: bool,
    captured: &CapturedProcess,
) -> std::io::Result<Option<SemanticObservation>> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if absent_is_nonclaim && error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(error) => {
            return Err(std::io::Error::new(
                error.kind(),
                format!(
                    "candidate did not retain semantic trace {} after status {:?}, timed out {}: {error}; child stderr: {}",
                    path.display(),
                    captured.status.code(),
                    captured.timed_out,
                    String::from_utf8_lossy(&captured.stderr.mismatch_bytes()),
                ),
            ));
        }
    };
    let trace = parse_semantic_trace(&bytes)?;
    fs::remove_file(path)?;
    Ok(Some(trace))
}

struct SemanticTraceFields<'a> {
    parsed: &'a str,
    resolved: &'a str,
    specialized: &'a str,
    adapters: &'a str,
    forced: &'a str,
    typed: &'a str,
    effects: &'a str,
    tasks: &'a str,
    presentation: &'a str,
    resources: &'a str,
    obligations: &'a str,
    final_resources: &'a str,
}

fn semantic_trace_fields(bytes: &[u8]) -> std::io::Result<SemanticTraceFields<'_>> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| std::io::Error::other("candidate semantic trace was not UTF-8"))?;
    let mut lines = text.lines();
    if lines.next() != Some("{") || lines.next() != Some("  \"schemaVersion\": 10,") {
        return Err(std::io::Error::other(
            "candidate semantic trace has an unsupported schema",
        ));
    }
    let fields = SemanticTraceFields {
        parsed: semantic_array_line(&mut lines, "parsedBuiltins", true)?,
        resolved: semantic_array_line(&mut lines, "resolvedBuiltins", true)?,
        specialized: semantic_array_line(&mut lines, "specializedBuiltins", true)?,
        adapters: lines
            .next()
            .and_then(|line| line.strip_prefix("  \"enteredAdapters\": ["))
            .and_then(|line| line.strip_suffix("],"))
            .ok_or_else(|| std::io::Error::other("candidate semantic trace is malformed"))?,
        forced: lines
            .next()
            .and_then(|line| line.strip_prefix("  \"forcedArguments\": ["))
            .and_then(|line| line.strip_suffix("],"))
            .ok_or_else(|| std::io::Error::other("candidate force trace is malformed"))?,
        typed: semantic_array_line(&mut lines, "typedResults", true)?,
        effects: semantic_array_line(&mut lines, "effectEvents", true)?,
        tasks: semantic_array_line(&mut lines, "taskEvents", true)?,
        presentation: semantic_array_line(&mut lines, "presentationFields", true)?,
        resources: semantic_array_line(&mut lines, "resourceEvents", true)?,
        obligations: semantic_array_line(&mut lines, "obligationEvents", true)?,
        final_resources: lines
            .next()
            .and_then(|line| line.strip_prefix("  \"finalResourceCounts\": {\"acquired\": "))
            .and_then(|line| line.strip_suffix('}'))
            .ok_or_else(|| {
                std::io::Error::other("candidate final resource counts are malformed")
            })?,
    };
    if lines.next() != Some("}") || lines.next().is_some() {
        return Err(std::io::Error::other(
            "candidate semantic trace contains unknown fields",
        ));
    }
    Ok(fields)
}

struct ParsedSemanticTrace {
    coverage: Vec<CoverageEvent>,
    forced: Vec<ParsedForcedArgument>,
    typed_result: Option<ParsedTypedResult>,
    effects: Vec<ParsedEffectEvent>,
    tasks: Vec<ParsedTaskEvent>,
    resources: Vec<ParsedResourceEvent>,
    obligations: Vec<ParsedObligationEvent>,
    causal_event_order: Vec<(u64, Arc<str>)>,
}

struct ParsedTypedResult {
    event_id: u64,
    builtin: BuiltinId,
    sha256: Digest,
    canonical: Arc<str>,
}

struct SemanticEventOrder<'a> {
    parsed: Vec<u64>,
    resolved: Vec<u64>,
    specialized: Vec<u64>,
    adapters: Vec<u64>,
    forced: &'a [ParsedForcedArgument],
    typed: &'a Option<ParsedTypedResult>,
    effects: &'a [ParsedEffectEvent],
    tasks: &'a [ParsedTaskEvent],
    presentation: &'a [ParsedNamedEvent],
    resources: &'a [ParsedResourceEvent],
    obligations: &'a [ParsedObligationEvent],
}

struct ParsedObligationEvent {
    event_id: u64,
    builtin: BuiltinId,
    instance_target: Option<Arc<str>>,
    instance_premises: Vec<InstancePremiseEvidence>,
    owner_task: Option<u64>,
    sequence: u64,
    parent_sequence: Option<u64>,
    outcome: String,
    nested_adapters: u64,
    materialized_before: u64,
    materialized_after: u64,
    callbacks: Vec<CallbackTraceEvent>,
    comparators: Vec<ComparatorTraceEvent>,
}

struct RawObligationEvent<'a> {
    event_id: u64,
    builtin: BuiltinId,
    owner: &'a str,
    sequence: &'a str,
    parent: &'a str,
    instance_target: &'a str,
    instance_premises: &'a str,
    outcome: &'a str,
    nested: &'a str,
    before: &'a str,
    after: &'a str,
    callbacks: &'a str,
    comparators: &'a str,
}

fn validated_semantic_event_order(
    events: SemanticEventOrder<'_>,
) -> std::io::Result<Vec<(u64, Arc<str>)>> {
    let mut order = events
        .parsed
        .into_iter()
        .map(|event_id| (event_id, Arc::<str>::from("parsed-builtin")))
        .chain(
            events
                .resolved
                .into_iter()
                .map(|event_id| (event_id, Arc::<str>::from("resolved-builtin"))),
        )
        .chain(
            events
                .specialized
                .into_iter()
                .map(|event_id| (event_id, Arc::<str>::from("specialized-builtin"))),
        )
        .chain(
            events
                .adapters
                .into_iter()
                .map(|event_id| (event_id, Arc::<str>::from("entered-adapter"))),
        )
        .chain(
            events
                .forced
                .iter()
                .map(|event| (event.event_id, Arc::<str>::from("forced-argument"))),
        )
        .chain(
            events
                .typed
                .iter()
                .map(|result| (result.event_id, Arc::<str>::from("typed-result"))),
        )
        .chain(
            events
                .effects
                .iter()
                .map(|event| (event.event_id, Arc::<str>::from("effect-event"))),
        )
        .chain(
            events
                .tasks
                .iter()
                .map(|event| (event.event_id, Arc::<str>::from("task-event"))),
        )
        .chain(named_event_order(events.presentation, "presentation-field"))
        .chain(
            events
                .resources
                .iter()
                .map(|event| (event.event_id, Arc::<str>::from("resource-event"))),
        )
        .chain(
            events
                .obligations
                .iter()
                .map(|event| (event.event_id, Arc::<str>::from("obligation-event"))),
        )
        .collect::<Vec<_>>();
    order.sort_by_key(|event| event.0);
    for (index, (event_id, _)) in order.iter().enumerate() {
        let expected = u64::try_from(index)
            .map_err(|_| std::io::Error::other("semantic event count exceeds u64"))?
            .saturating_add(1);
        if *event_id != expected {
            return Err(std::io::Error::other(
                "semantic event IDs are duplicate, missing, or non-monotonic",
            ));
        }
    }
    Ok(order)
}

fn parse_semantic_events(fields: &SemanticTraceFields<'_>) -> std::io::Result<ParsedSemanticTrace> {
    let (mut coverage, parsed_events) =
        parse_builtin_events(fields.parsed, "parsed", CoverageEvent::ParsedBuiltin)?;
    let (resolved_coverage, resolved_events) =
        parse_builtin_events(fields.resolved, "resolved", CoverageEvent::ResolvedBuiltin)?;
    coverage.extend(resolved_coverage);
    let (specialized_coverage, specialized_events) = parse_builtin_events(
        fields.specialized,
        "specialized",
        CoverageEvent::SpecializedBuiltin,
    )?;
    coverage.extend(specialized_coverage);
    let (adapter_coverage, entered_events) =
        parse_builtin_events(fields.adapters, "adapter", CoverageEvent::EnteredAdapter)?;
    coverage.extend(adapter_coverage);
    let forced = parse_forced_arguments(fields.forced)?;
    coverage.extend(
        forced
            .iter()
            .map(|event| CoverageEvent::ForcedArgument(event.builtin, event.argument)),
    );
    let typed_result = parse_typed_results(fields.typed)?;
    let effect_events = parse_effect_events(fields.effects)?;
    coverage.extend(effect_events.iter().map(|event| {
        CoverageEvent::ExecutedEffect(event.builtin, Arc::from(event.value.as_str()))
    }));
    let task_events = parse_task_events(fields.tasks)?;
    validate_effect_causality(&effect_events, &task_events)?;
    coverage.extend(
        task_events
            .iter()
            .map(|event| CoverageEvent::TaskEvent(event.builtin, Arc::from(event.value.as_str()))),
    );
    let presentation_events =
        parse_named_events(fields.presentation, "field", "presentation field")?;
    require_event_values(&presentation_events, &["rendered-output"], "presentation")?;
    coverage.extend(presentation_events.iter().map(|event| {
        CoverageEvent::PresentedField(event.builtin, Arc::from(event.value.as_str()))
    }));
    let resource_events = parse_resource_events(fields.resources, fields.final_resources)?;
    coverage.extend(resource_events.iter().map(|event| {
        CoverageEvent::AcquiredResource(event.builtin, Arc::from(event.value.as_str()))
    }));
    let obligation_events = parse_obligation_events(fields.obligations, fields.final_resources)?;
    validate_parsed_obligation_causality(&obligation_events, &task_events)?;
    let causal_event_order = validated_semantic_event_order(SemanticEventOrder {
        parsed: parsed_events,
        resolved: resolved_events,
        specialized: specialized_events,
        adapters: entered_events,
        forced: &forced,
        typed: &typed_result,
        effects: &effect_events,
        tasks: &task_events,
        presentation: &presentation_events,
        resources: &resource_events,
        obligations: &obligation_events,
    })?;
    Ok(ParsedSemanticTrace {
        coverage,
        forced,
        typed_result,
        effects: effect_events,
        tasks: task_events,
        resources: resource_events,
        obligations: obligation_events,
        causal_event_order,
    })
}

fn validate_parsed_obligation_causality(
    events: &[ParsedObligationEvent],
    tasks: &[ParsedTaskEvent],
) -> std::io::Result<()> {
    use std::collections::{BTreeMap, BTreeSet};

    let task_ids = tasks
        .iter()
        .map(|event| event.task_id)
        .collect::<BTreeSet<_>>();
    let identities = events
        .iter()
        .map(|event| ((event.owner_task, event.sequence), event))
        .collect::<BTreeMap<_, _>>();
    if identities.len() != events.len() {
        return Err(std::io::Error::other(
            "obligation causal identity is duplicated",
        ));
    }
    let mut sequences = BTreeMap::<Option<u64>, BTreeSet<u64>>::new();
    let mut children = BTreeMap::<(Option<u64>, u64), u64>::new();
    for event in events {
        if event
            .owner_task
            .is_some_and(|owner| !task_ids.contains(&owner))
        {
            return Err(std::io::Error::other(
                "obligation owner is not a retained task",
            ));
        }
        sequences
            .entry(event.owner_task)
            .or_default()
            .insert(event.sequence);
        if let Some(parent) = event.parent_sequence {
            let identity = (event.owner_task, parent);
            if !identities.contains_key(&identity) {
                return Err(std::io::Error::other("obligation causal parent is missing"));
            }
            children
                .entry(identity)
                .and_modify(|count| *count = count.saturating_add(1))
                .or_insert(1);
        }
    }
    for owner_sequences in sequences.values() {
        let last = u64::try_from(owner_sequences.len())
            .map_err(|_| std::io::Error::other("obligation sequence count exceeds u64"))?;
        if !owner_sequences.iter().copied().eq(1..=last) {
            return Err(std::io::Error::other(
                "obligation sequences are not contiguous",
            ));
        }
    }
    for event in events {
        if event.nested_adapters
            != children
                .get(&(event.owner_task, event.sequence))
                .copied()
                .unwrap_or(0)
        {
            return Err(std::io::Error::other(
                "obligation nested count does not match causal children",
            ));
        }
    }
    Ok(())
}

fn semantic_observation(parsed: ParsedSemanticTrace) -> SemanticObservation {
    SemanticObservation {
        force_trace: parsed
            .forced
            .into_iter()
            .flat_map(|event| {
                [
                    LogicalTraceEvent::ForceBuiltinArgument {
                        builtin: event.builtin,
                        argument: event.argument,
                    },
                    LogicalTraceEvent::CompleteThunk {
                        label: Arc::from(event.boundary),
                        outcome: Arc::from(event.outcome),
                        error_code: event.error_code.map(Arc::from),
                    },
                ]
            })
            .collect(),
        effect_trace: parsed
            .effects
            .into_iter()
            .map(|event| LogicalTraceEvent::HostEffect {
                builtin: event.builtin,
                owner_task: event.owner_task,
                sequence: event.sequence,
                parent_sequence: event.parent_sequence,
                effect: event.value.into(),
            })
            .collect(),
        task_trace: parsed
            .tasks
            .into_iter()
            .map(|event| LogicalTraceEvent::TaskEvent {
                task: event.task_id,
                builtin: event.builtin,
                event: event.value.into(),
            })
            .collect(),
        resource_trace: parsed
            .resources
            .into_iter()
            .map(|event| LogicalTraceEvent::ResourceEvent {
                resource: event.resource_id,
                builtin: event.builtin,
                owner_task: event.owner_task_id,
                event: match event.value.as_str() {
                    "acquire" => ResourceEventKind::Acquire,
                    "transfer" => ResourceEventKind::Transfer,
                    "cancel" => ResourceEventKind::Cancel,
                    "close" => ResourceEventKind::Close,
                    _ => ResourceEventKind::CleanupFailure,
                },
            })
            .collect(),
        obligation_trace: parsed
            .obligations
            .into_iter()
            .map(|event| ObligationTraceEvent {
                builtin: event.builtin,
                instance_target: event.instance_target,
                instance_premises: event.instance_premises,
                owner_task: event.owner_task,
                sequence: event.sequence,
                parent_sequence: event.parent_sequence,
                outcome: event.outcome.into(),
                nested_adapters: event.nested_adapters,
                materialized_before: event.materialized_before,
                materialized_after: event.materialized_after,
                callbacks: event.callbacks,
                comparators: event.comparators,
            })
            .collect(),
        typed_result_sha256: parsed.typed_result.as_ref().map(|result| result.sha256),
        typed_result_builtin: parsed.typed_result.as_ref().map(|result| result.builtin),
        typed_result_canonical: parsed
            .typed_result
            .as_ref()
            .map(|result| Arc::clone(&result.canonical)),
        causal_event_order: parsed.causal_event_order,
        coverage: parsed.coverage,
    }
}

/// Strictly parses and revalidates one retained semantic trace.
///
/// # Errors
///
/// Returns an error when the trace is noncanonical, contains an unknown or
/// duplicate event, breaks causal ownership/order, or carries an invalid typed
/// value fingerprint.
pub fn parse_semantic_trace(bytes: &[u8]) -> std::io::Result<SemanticObservation> {
    let fields = semantic_trace_fields(bytes)?;
    parse_semantic_events(&fields).map(semantic_observation)
}

fn semantic_array_line<'a>(
    lines: &mut std::str::Lines<'a>,
    field: &str,
    trailing_comma: bool,
) -> std::io::Result<&'a str> {
    let prefix = format!("  \"{field}\": [");
    let line = lines
        .next()
        .and_then(|line| line.strip_prefix(&prefix))
        .ok_or_else(|| std::io::Error::other(format!("candidate {field} trace is malformed")))?;
    if trailing_comma {
        line.strip_suffix("],")
    } else {
        line.strip_suffix(']')
    }
    .ok_or_else(|| std::io::Error::other(format!("candidate {field} trace is malformed")))
}

struct ParsedNamedEvent {
    event_id: u64,
    builtin: BuiltinId,
    value: String,
}

struct ParsedEffectEvent {
    event_id: u64,
    builtin: BuiltinId,
    owner_task: Option<u64>,
    sequence: u64,
    parent_sequence: Option<u64>,
    value: String,
}

struct ParsedTaskEvent {
    event_id: u64,
    builtin: BuiltinId,
    task_id: u64,
    value: String,
}

struct ParsedResourceEvent {
    event_id: u64,
    builtin: BuiltinId,
    resource_id: u64,
    owner_task_id: Option<u64>,
    value: String,
}

fn parse_task_events(encoded: &str) -> std::io::Result<Vec<ParsedTaskEvent>> {
    let mut events = Vec::new();
    let mut states = HashMap::<u64, (BuiltinId, bool)>::new();
    for entry in split_trace_entries(encoded) {
        let (event_id, builtin, fields) = parse_trace_prefix(entry, "task event")?;
        let (task, lifecycle) = fields
            .strip_prefix("\"taskId\": ")
            .and_then(|fields| fields.split_once(", \"event\": \""))
            .and_then(|(task, lifecycle)| {
                lifecycle
                    .strip_suffix('"')
                    .map(|lifecycle| (task, lifecycle))
            })
            .ok_or_else(|| std::io::Error::other("task event is malformed"))?;
        let task_id = task
            .parse::<u64>()
            .ok()
            .filter(|task| *task != 0)
            .ok_or_else(|| std::io::Error::other("task instance ID is malformed"))?;
        match lifecycle {
            "started" if !states.contains_key(&task_id) => {
                states.insert(task_id, (builtin, false));
            }
            "completed" | "failed" | "cancelled"
                if states.get(&task_id) == Some(&(builtin, false)) =>
            {
                states.insert(task_id, (builtin, true));
            }
            _ => {
                return Err(std::io::Error::other(
                    "task lifecycle is aliased, duplicated, or out of order",
                ));
            }
        }
        events.push(ParsedTaskEvent {
            event_id,
            builtin,
            task_id,
            value: lifecycle.to_owned(),
        });
    }
    if states.values().any(|(_, complete)| !complete) {
        return Err(std::io::Error::other(
            "task trace has a started instance without terminal outcome",
        ));
    }
    let mut task_ids = states.keys().copied().collect::<Vec<_>>();
    task_ids.sort_unstable();
    let task_count = u64::try_from(task_ids.len())
        .map_err(|_| std::io::Error::other("task trace count exceeds u64"))?;
    if !task_ids.into_iter().eq(1..=task_count) {
        return Err(std::io::Error::other(
            "task instance IDs are not exact contiguous canonical identities",
        ));
    }
    Ok(events)
}

fn parse_resource_events(
    encoded: &str,
    final_counts: &str,
) -> std::io::Result<Vec<ParsedResourceEvent>> {
    let mut events = Vec::new();
    let mut states = HashMap::<u64, bool>::new();
    let mut cleanup_failures = 0_u64;
    for entry in split_trace_entries(encoded) {
        let (event_id, builtin, fields) = parse_trace_prefix(entry, "resource event")?;
        let (resource, fields) = fields
            .strip_prefix("\"resourceId\": ")
            .and_then(|fields| fields.split_once(", \"ownerTaskId\": "))
            .ok_or_else(|| std::io::Error::other("resource event is malformed"))?;
        let (owner, lifecycle) = fields
            .split_once(", \"event\": \"")
            .and_then(|(owner, lifecycle)| {
                lifecycle
                    .strip_suffix('"')
                    .map(|lifecycle| (owner, lifecycle))
            })
            .ok_or_else(|| std::io::Error::other("resource event is malformed"))?;
        let resource_id = resource
            .parse::<u64>()
            .ok()
            .filter(|resource| *resource != 0)
            .ok_or_else(|| std::io::Error::other("resource instance ID is malformed"))?;
        let owner_task_id = if owner == "null" {
            None
        } else {
            Some(
                owner
                    .parse::<u64>()
                    .ok()
                    .filter(|task| *task != 0)
                    .ok_or_else(|| std::io::Error::other("resource owner task is malformed"))?,
            )
        };
        match lifecycle {
            "acquire" if !states.contains_key(&resource_id) => {
                states.insert(resource_id, false);
            }
            "transfer" if states.get(&resource_id) == Some(&false) => {}
            "cancel" | "close" if states.get(&resource_id) == Some(&false) => {
                states.insert(resource_id, true);
            }
            "cleanup-failure" if states.get(&resource_id) == Some(&false) => {
                cleanup_failures = cleanup_failures.saturating_add(1);
            }
            _ => {
                return Err(std::io::Error::other(
                    "resource lifecycle is aliased, duplicated, or out of order",
                ));
            }
        }
        events.push(ParsedResourceEvent {
            event_id,
            builtin,
            resource_id,
            owner_task_id,
            value: lifecycle.to_owned(),
        });
    }
    let (acquired, counts) = final_counts
        .split_once(", \"live\": ")
        .ok_or_else(|| std::io::Error::other("final resource counts are malformed"))?;
    let (live, counts) = counts
        .split_once(", \"cleanupFailures\": ")
        .ok_or_else(|| std::io::Error::other("final resource counts are malformed"))?;
    let (failed, materialized) = counts
        .split_once(", \"materializedElements\": ")
        .ok_or_else(|| std::io::Error::other("final resource counts are malformed"))?;
    let acquired = acquired
        .parse::<u64>()
        .map_err(|_| std::io::Error::other("final acquired resource count is malformed"))?;
    let live = live
        .parse::<u64>()
        .map_err(|_| std::io::Error::other("final live resource count is malformed"))?;
    let failed = failed
        .parse::<u64>()
        .map_err(|_| std::io::Error::other("final cleanup failure count is malformed"))?;
    materialized
        .parse::<u64>()
        .map_err(|_| std::io::Error::other("final materialized count is malformed"))?;
    let observed_acquired = u64::try_from(states.len())
        .map_err(|_| std::io::Error::other("resource instance count exceeds u64"))?;
    let observed_live = u64::try_from(states.values().filter(|closed| !**closed).count())
        .map_err(|_| std::io::Error::other("live resource count exceeds u64"))?;
    if acquired != observed_acquired
        || live != observed_live
        || failed != cleanup_failures
        || live != 0
        || failed != 0
    {
        return Err(std::io::Error::other(
            "final resource counts do not reconcile to zero",
        ));
    }
    Ok(events)
}

fn parse_obligation_events(
    encoded: &str,
    final_counts: &str,
) -> std::io::Result<Vec<ParsedObligationEvent>> {
    let mut events = Vec::new();
    for entry in split_trace_entries(encoded) {
        events.push(parse_obligation_event(entry)?);
    }
    let final_materialized = final_counts
        .rsplit_once(", \"materializedElements\": ")
        .map(|(_, value)| value)
        .ok_or_else(|| std::io::Error::other("final materialized count is missing"))?
        .parse::<u64>()
        .map_err(|_| std::io::Error::other("final materialized count is malformed"))?;
    let observed_total = events
        .iter()
        .map(|event| event.materialized_after - event.materialized_before)
        .sum::<u64>();
    if observed_total != final_materialized {
        return Err(std::io::Error::other(
            "adapter materialization events do not reconcile to the final count",
        ));
    }
    Ok(events)
}

fn parse_obligation_event(entry: &str) -> std::io::Result<ParsedObligationEvent> {
    let (event_id, builtin, fields) = parse_trace_prefix(entry, "obligation event")?;
    let fields = fields
        .strip_prefix("\"ownerTaskId\": ")
        .ok_or_else(|| std::io::Error::other("obligation owner is malformed"))?;
    let (owner, fields) = fields
        .split_once(", \"sequence\": ")
        .ok_or_else(|| std::io::Error::other("obligation owner is malformed"))?;
    let (sequence, fields) = fields
        .split_once(", \"parentSequence\": ")
        .ok_or_else(|| std::io::Error::other("obligation sequence is malformed"))?;
    let (parent, fields) = fields
        .split_once(", \"instanceTarget\": ")
        .ok_or_else(|| std::io::Error::other("obligation parent is malformed"))?;
    let (instance_target, fields) = fields
        .split_once(", \"instancePremises\": [")
        .ok_or_else(|| std::io::Error::other("obligation instance target is malformed"))?;
    let (instance_premises, fields) = fields
        .split_once("], \"outcome\": \"")
        .ok_or_else(|| std::io::Error::other("obligation instance premises are malformed"))?;
    let (outcome, fields) = fields
        .split_once("\", \"nestedAdapters\": ")
        .ok_or_else(|| std::io::Error::other("obligation outcome is malformed"))?;
    let (nested, fields) = fields
        .split_once(", \"materializedBefore\": ")
        .ok_or_else(|| std::io::Error::other("obligation nesting is malformed"))?;
    let (before, fields) = fields
        .split_once(", \"materializedAfter\": ")
        .ok_or_else(|| std::io::Error::other("obligation materialization is malformed"))?;
    let (after, invocations) = fields
        .split_once(", \"callbackInvocations\": [")
        .ok_or_else(|| std::io::Error::other("obligation callbacks are malformed"))?;
    let (callbacks, comparators) = invocations
        .split_once("], \"comparatorInvocations\": [")
        .and_then(|(callbacks, comparators)| {
            comparators
                .strip_suffix(']')
                .map(|comparators| (callbacks, comparators))
        })
        .ok_or_else(|| std::io::Error::other("obligation comparators are malformed"))?;
    build_parsed_obligation_event(&RawObligationEvent {
        event_id,
        builtin,
        owner,
        sequence,
        parent,
        instance_target,
        instance_premises,
        outcome,
        nested,
        before,
        after,
        callbacks,
        comparators,
    })
}

fn build_parsed_obligation_event(
    raw: &RawObligationEvent<'_>,
) -> std::io::Result<ParsedObligationEvent> {
    if !matches!(raw.outcome, "alias" | "error" | "io-action" | "value") {
        return Err(std::io::Error::other("obligation outcome is unknown"));
    }
    let nested_adapters = raw
        .nested
        .parse::<u64>()
        .map_err(|_| std::io::Error::other("nested adapter count is malformed"))?;
    let materialized_before = raw
        .before
        .parse::<u64>()
        .map_err(|_| std::io::Error::other("materialization start is malformed"))?;
    let materialized_after = raw
        .after
        .parse::<u64>()
        .map_err(|_| std::io::Error::other("materialization end is malformed"))?;
    if materialized_after < materialized_before {
        return Err(std::io::Error::other(
            "adapter materialization counter moved backwards",
        ));
    }
    let owner_task = if raw.owner == "null" {
        None
    } else {
        Some(positive_trace_id(raw.owner, "obligation owner")?)
    };
    let sequence = positive_trace_id(raw.sequence, "obligation sequence")?;
    let parent_sequence = if raw.parent == "null" {
        None
    } else {
        Some(positive_trace_id(raw.parent, "obligation parent")?)
    };
    let instance_target = parse_instance_target(raw.instance_target, raw.builtin)?;
    let instance_premises = parse_instance_premises(
        raw.instance_premises,
        raw.builtin,
        instance_target.as_deref(),
    )?;
    if parent_sequence.is_some_and(|parent| parent >= sequence) {
        return Err(std::io::Error::other(
            "obligation parent does not precede its child",
        ));
    }
    Ok(ParsedObligationEvent {
        event_id: raw.event_id,
        builtin: raw.builtin,
        instance_target,
        instance_premises,
        owner_task,
        sequence,
        parent_sequence,
        outcome: raw.outcome.to_owned(),
        nested_adapters,
        materialized_before,
        materialized_after,
        callbacks: parse_retained_callback_invocations(raw.callbacks)?,
        comparators: parse_retained_comparator_invocations(raw.comparators)?,
    })
}

pub(crate) fn parse_retained_comparator_invocations(
    encoded: &str,
) -> std::io::Result<Vec<ComparatorTraceEvent>> {
    if encoded.is_empty() {
        return Ok(Vec::new());
    }
    encoded
        .split("},{")
        .enumerate()
        .map(|(index, entry)| {
            let entry = entry.strip_prefix('{').unwrap_or(entry);
            let entry = entry.strip_suffix('}').unwrap_or(entry);
            let entry = entry
                .strip_prefix("\"invocation\":")
                .ok_or_else(|| std::io::Error::other("comparator invocation is malformed"))?;
            let (invocation, entry) = entry
                .split_once(",\"directChildOrdinal\":")
                .ok_or_else(|| std::io::Error::other("comparator child ordinal is malformed"))?;
            let (direct_child_ordinal, entry) = entry
                .split_once(",\"comparatorBuiltinId\":")
                .ok_or_else(|| std::io::Error::other("comparator builtin is malformed"))?;
            let (comparator, entry) = entry
                .split_once(",\"canonicalLeftHex\":\"")
                .ok_or_else(|| std::io::Error::other("comparator left value is malformed"))?;
            let (left, entry) = entry
                .split_once("\",\"canonicalRightHex\":\"")
                .ok_or_else(|| std::io::Error::other("comparator right value is malformed"))?;
            let (right, entry) = entry
                .split_once("\",\"outcome\":\"")
                .ok_or_else(|| std::io::Error::other("comparator outcome is malformed"))?;
            let (outcome, result) = entry
                .split_once("\",\"canonicalResultHex\":\"")
                .and_then(|(outcome, result)| {
                    result.strip_suffix('"').map(|result| (outcome, result))
                })
                .ok_or_else(|| std::io::Error::other("comparator result is malformed"))?;
            let invocation = positive_trace_id(invocation, "comparator invocation")?;
            let direct_child_ordinal =
                positive_trace_id(direct_child_ordinal, "comparator child ordinal")?;
            let expected = u64::try_from(index)
                .map_err(|_| std::io::Error::other("comparator count exceeds u64"))?
                .saturating_add(1);
            if invocation != expected || outcome != "value" {
                return Err(std::io::Error::other(
                    "comparator order or outcome is invalid",
                ));
            }
            let comparator = comparator
                .parse::<u16>()
                .ok()
                .filter(|id| usize::from(*id) < hell_builtins::registry().len())
                .map(BuiltinId)
                .ok_or_else(|| std::io::Error::other("comparator builtin is unknown"))?;
            let canonical_left = decode_callback_result(left).map_err(std::io::Error::other)?;
            let canonical_right = decode_callback_result(right).map_err(std::io::Error::other)?;
            let canonical_result = decode_callback_result(result).map_err(std::io::Error::other)?;
            validate_canonical_typed_value(&canonical_left)?;
            validate_canonical_typed_value(&canonical_right)?;
            validate_canonical_typed_value(&canonical_result)?;
            Ok(ComparatorTraceEvent {
                invocation,
                direct_child_ordinal,
                comparator,
                canonical_left: canonical_left.into(),
                canonical_right: canonical_right.into(),
                outcome: outcome.into(),
                canonical_result: canonical_result.into(),
            })
        })
        .collect()
}

pub(crate) fn parse_retained_callback_invocations(
    encoded: &str,
) -> std::io::Result<Vec<CallbackTraceEvent>> {
    if encoded.is_empty() {
        return Ok(Vec::new());
    }
    encoded
        .split("},{")
        .enumerate()
        .map(|(index, entry)| {
            let entry = entry.strip_prefix('{').unwrap_or(entry);
            let entry = entry.strip_suffix('}').unwrap_or(entry);
            let entry = entry
                .strip_prefix("\"invocation\":")
                .ok_or_else(|| std::io::Error::other("callback invocation is malformed"))?;
            let (invocation, entry) = entry
                .split_once(",\"callbackArgument\":")
                .ok_or_else(|| std::io::Error::other("callback argument is malformed"))?;
            let (callback_argument, entry) = entry
                .split_once(",\"branch\":\"")
                .ok_or_else(|| std::io::Error::other("callback argument is malformed"))?;
            let (branch, entry) = entry
                .split_once("\",\"canonicalArgumentHex\":[")
                .ok_or_else(|| std::io::Error::other("callback branch is malformed"))?;
            let (arguments, entry) = entry
                .split_once("],\"outcome\":\"")
                .ok_or_else(|| std::io::Error::other("callback arguments are malformed"))?;
            let (outcome, result) = entry
                .split_once("\",\"canonicalResultHex\":\"")
                .and_then(|(outcome, result)| {
                    result.strip_suffix('"').map(|result| (outcome, result))
                })
                .ok_or_else(|| std::io::Error::other("callback result is malformed"))?;
            let invocation = positive_trace_id(invocation, "callback invocation")?;
            let expected = u64::try_from(index)
                .map_err(|_| std::io::Error::other("callback count exceeds u64"))?
                .saturating_add(1);
            if invocation != expected {
                return Err(std::io::Error::other(
                    "callback invocation order is not contiguous",
                ));
            }
            let callback_argument = callback_argument
                .parse::<u16>()
                .map_err(|_| std::io::Error::other("callback argument is malformed"))?;
            if branch.is_empty()
                || !branch
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
                || !matches!(outcome, "value" | "error")
            {
                return Err(std::io::Error::other(
                    "callback branch or outcome is unknown",
                ));
            }
            let canonical_result = decode_callback_result(result).map_err(std::io::Error::other)?;
            validate_canonical_typed_value(&canonical_result)?;
            let canonical_arguments = decode_callback_arguments(arguments)?;
            let canonical_outcome = if canonical_result
                .starts_with("{\"type\":\"ForceBoundary\",\"outcome\":\"error\",\"code\":\"")
            {
                "error"
            } else {
                "value"
            };
            if outcome != canonical_outcome {
                return Err(std::io::Error::other(
                    "callback outcome disagrees with its canonical result",
                ));
            }
            Ok(CallbackTraceEvent {
                invocation,
                callback_argument,
                branch: Arc::from(branch),
                canonical_arguments,
                outcome: Arc::from(outcome),
                canonical_result: Arc::from(canonical_result),
            })
        })
        .collect()
}

fn positive_trace_id(value: &str, label: &str) -> std::io::Result<u64> {
    value
        .parse::<u64>()
        .ok()
        .filter(|value| *value != 0)
        .ok_or_else(|| std::io::Error::other(format!("{label} is malformed")))
}

fn parse_instance_target(encoded: &str, builtin: BuiltinId) -> std::io::Result<Option<Arc<str>>> {
    let spec = hell_builtins::registry()
        .get(usize::from(builtin.0))
        .ok_or_else(|| std::io::Error::other("instance target builtin is unknown"))?;
    let Some(class) = spec.type_class else {
        return (encoded == "null")
            .then_some(None)
            .ok_or_else(|| std::io::Error::other("unconstrained adapter retained an instance"));
    };
    let target = encoded
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .filter(|value| !value.is_empty() && !value.contains(['"', '\\']))
        .ok_or_else(|| std::io::Error::other("constrained adapter instance is malformed"))?;
    if hell_builtins::instance(class, target).is_none() {
        return Err(std::io::Error::other(
            "constrained adapter instance is not registry-backed",
        ));
    }
    Ok(Some(Arc::from(target)))
}

pub(crate) fn parse_instance_premises(
    encoded: &str,
    builtin: BuiltinId,
    root: Option<&str>,
) -> std::io::Result<Vec<InstancePremiseEvidence>> {
    let spec = hell_builtins::registry()
        .get(usize::from(builtin.0))
        .ok_or_else(|| std::io::Error::other("instance premise builtin is unknown"))?;
    let premises = if encoded.is_empty() {
        Vec::new()
    } else {
        encoded
            .split("},{")
            .map(|entry| {
                let entry = entry.trim_start_matches('{').trim_end_matches('}');
                let (target, count) = entry
                    .strip_prefix("\"target\":\"")
                    .and_then(|entry| entry.split_once("\",\"premiseCount\":"))
                    .ok_or_else(|| {
                        std::io::Error::other("instance premise is not canonically encoded")
                    })?;
                if target.is_empty() || target.contains(['"', '\\']) {
                    return Err(std::io::Error::other(
                        "instance premise target is malformed",
                    ));
                }
                let premise_count = count
                    .parse::<u8>()
                    .map_err(|_| std::io::Error::other("instance premise count is malformed"))?;
                Ok(InstancePremiseEvidence {
                    target: Arc::from(target),
                    premise_count,
                })
            })
            .collect::<std::io::Result<Vec<_>>>()?
    };
    match (spec.type_class, root) {
        (None, None) if premises.is_empty() => Ok(premises),
        (Some(class), Some(root)) => {
            validate_instance_premise_tree(class, root, &premises)
                .map_err(std::io::Error::other)?;
            Ok(premises)
        }
        _ => Err(std::io::Error::other(
            "instance premise evidence has no matching constrained root",
        )),
    }
}

pub(crate) fn decode_callback_result(encoded: &str) -> Result<String, String> {
    if !encoded.len().is_multiple_of(2) || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("runtime callback result hex is malformed".into());
    }
    let bytes = encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair)
                .map_err(|_| "runtime callback result hex is malformed".to_owned())?;
            u8::from_str_radix(text, 16)
                .map_err(|_| "runtime callback result hex is malformed".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    String::from_utf8(bytes).map_err(|_| "runtime callback result is not UTF-8".into())
}

pub(crate) fn encode_callback_result(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len().saturating_mul("00".len()));
    for byte in value.bytes() {
        std::fmt::Write::write_fmt(&mut encoded, format_args!("{byte:02x}"))
            .expect("writing to String cannot fail");
    }
    encoded
}

fn decode_callback_arguments(encoded: &str) -> std::io::Result<Vec<Arc<str>>> {
    if encoded.is_empty() {
        return Ok(Vec::new());
    }
    encoded
        .split(',')
        .map(|argument| {
            let encoded = argument
                .strip_prefix('"')
                .and_then(|argument| argument.strip_suffix('"'))
                .ok_or_else(|| std::io::Error::other("callback argument hex is malformed"))?;
            let argument = decode_callback_result(encoded).map_err(std::io::Error::other)?;
            validate_canonical_typed_value(&argument)?;
            Ok(Arc::from(argument))
        })
        .collect()
}

fn split_trace_entries(encoded: &str) -> impl Iterator<Item = &str> {
    encoded
        .split("}, {")
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            let entry = entry.strip_prefix('{').unwrap_or(entry);
            entry.strip_suffix('}').unwrap_or(entry)
        })
}

fn parse_trace_prefix<'a>(
    entry: &'a str,
    label: &str,
) -> std::io::Result<(u64, BuiltinId, &'a str)> {
    let (event, entry) = entry
        .strip_prefix("\"eventId\": ")
        .and_then(|entry| entry.split_once(", \"builtinId\": "))
        .ok_or_else(|| std::io::Error::other(format!("{label} is malformed")))?;
    let (builtin, fields) = entry
        .split_once(", ")
        .ok_or_else(|| std::io::Error::other(format!("{label} is malformed")))?;
    let event_id = event
        .parse::<u64>()
        .map_err(|_| std::io::Error::other(format!("{label} event ID is malformed")))?;
    let builtin = builtin
        .parse::<u16>()
        .map_err(|_| std::io::Error::other(format!("{label} builtin ID is malformed")))?;
    if event_id == 0 || usize::from(builtin) >= hell_builtins::registry().len() {
        return Err(std::io::Error::other(format!(
            "{label} identity is unknown"
        )));
    }
    Ok((event_id, BuiltinId(builtin), fields))
}

fn parse_named_events(
    encoded: &str,
    field: &str,
    label: &str,
) -> std::io::Result<Vec<ParsedNamedEvent>> {
    let mut observed = Vec::new();
    if encoded.is_empty() {
        return Ok(observed);
    }
    for entry in encoded.split("}, {") {
        let entry = entry.strip_prefix('{').unwrap_or(entry);
        let entry = entry.strip_suffix('}').unwrap_or(entry);
        let (event, entry) = entry
            .strip_prefix("\"eventId\": ")
            .and_then(|entry| entry.split_once(", \"builtinId\": "))
            .ok_or_else(|| std::io::Error::other(format!("{label} is malformed")))?;
        let delimiter = format!(", \"{field}\": \"");
        let (builtin, value) = entry
            .split_once(&delimiter)
            .and_then(|(builtin, value)| {
                value
                    .strip_suffix('"')
                    .map(|value| (builtin, value.to_owned()))
            })
            .ok_or_else(|| std::io::Error::other(format!("{label} is malformed")))?;
        let event_id = event
            .parse::<u64>()
            .map_err(|_| std::io::Error::other(format!("{label} event ID is malformed")))?;
        let builtin = builtin
            .parse::<u16>()
            .map_err(|_| std::io::Error::other(format!("{label} builtin ID is malformed")))?;
        if usize::from(builtin) >= hell_builtins::registry().len()
            || value.is_empty()
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || matches!(byte, b'-' | b'_'))
            || observed
                .last()
                .is_some_and(|prior: &ParsedNamedEvent| prior.event_id >= event_id)
        {
            return Err(std::io::Error::other(format!(
                "{label} is unknown, duplicate, or unsorted"
            )));
        }
        observed.push(ParsedNamedEvent {
            event_id,
            builtin: BuiltinId(builtin),
            value,
        });
    }
    Ok(observed)
}

fn parse_effect_events(encoded: &str) -> std::io::Result<Vec<ParsedEffectEvent>> {
    split_trace_entries(encoded)
        .map(|entry| {
            let (event_id, builtin, fields) = parse_trace_prefix(entry, "effect event")?;
            let fields = fields
                .strip_prefix("\"ownerTaskId\": ")
                .ok_or_else(|| std::io::Error::other("effect owner is malformed"))?;
            let (owner, fields) = fields
                .split_once(", \"sequence\": ")
                .ok_or_else(|| std::io::Error::other("effect owner is malformed"))?;
            let (sequence, fields) = fields
                .split_once(", \"parentSequence\": ")
                .ok_or_else(|| std::io::Error::other("effect sequence is malformed"))?;
            let (parent, lifecycle) = fields
                .split_once(", \"effect\": \"")
                .and_then(|(parent, lifecycle)| {
                    lifecycle
                        .strip_suffix('"')
                        .map(|lifecycle| (parent, lifecycle))
                })
                .ok_or_else(|| std::io::Error::other("effect lifecycle is malformed"))?;
            if !matches!(lifecycle, "started" | "completed" | "failed" | "cancelled") {
                return Err(std::io::Error::other("effect lifecycle is unknown"));
            }
            let owner_task = if owner == "null" {
                None
            } else {
                Some(positive_trace_id(owner, "effect owner")?)
            };
            let sequence = positive_trace_id(sequence, "effect sequence")?;
            let parent_sequence = if parent == "null" {
                None
            } else {
                Some(positive_trace_id(parent, "effect parent")?)
            };
            if parent_sequence.is_some_and(|parent| parent >= sequence) {
                return Err(std::io::Error::other(
                    "effect parent does not precede its child",
                ));
            }
            Ok(ParsedEffectEvent {
                event_id,
                builtin,
                owner_task,
                sequence,
                parent_sequence,
                value: lifecycle.to_owned(),
            })
        })
        .collect()
}

fn validate_effect_causality(
    events: &[ParsedEffectEvent],
    tasks: &[ParsedTaskEvent],
) -> std::io::Result<()> {
    use std::collections::{BTreeMap, BTreeSet};

    let tasks = tasks
        .iter()
        .map(|event| event.task_id)
        .collect::<BTreeSet<_>>();
    let mut invocations = BTreeMap::<(Option<u64>, u64), Vec<&ParsedEffectEvent>>::new();
    for event in events {
        if event
            .owner_task
            .is_some_and(|owner| !tasks.contains(&owner))
        {
            return Err(std::io::Error::other("effect owner is not a retained task"));
        }
        invocations
            .entry((event.owner_task, event.sequence))
            .or_default()
            .push(event);
    }
    let mut sequences = BTreeMap::<Option<u64>, BTreeSet<u64>>::new();
    for ((owner, sequence), lifecycle) in &invocations {
        if lifecycle.len() != 2
            || lifecycle[0].value != "started"
            || !matches!(
                lifecycle[1].value.as_str(),
                "completed" | "failed" | "cancelled"
            )
            || lifecycle[0].builtin != lifecycle[1].builtin
            || lifecycle[0].parent_sequence != lifecycle[1].parent_sequence
        {
            return Err(std::io::Error::other(
                "effect lifecycle is not an exact start-to-terminal pair",
            ));
        }
        sequences.entry(*owner).or_default().insert(*sequence);
        if let Some(parent) = lifecycle[0].parent_sequence
            && !invocations.contains_key(&(*owner, parent))
        {
            return Err(std::io::Error::other("effect causal parent is missing"));
        }
    }
    for owner_sequences in sequences.values() {
        let last = u64::try_from(owner_sequences.len())
            .map_err(|_| std::io::Error::other("effect invocation count exceeds u64"))?;
        if !owner_sequences.iter().copied().eq(1..=last) {
            return Err(std::io::Error::other(
                "effect invocation sequences are not contiguous",
            ));
        }
    }
    Ok(())
}

fn named_event_order<'a>(
    events: &'a [ParsedNamedEvent],
    label: &'static str,
) -> impl Iterator<Item = (u64, Arc<str>)> + 'a {
    events
        .iter()
        .map(move |event| (event.event_id, Arc::<str>::from(label)))
}

fn require_event_values(
    events: &[ParsedNamedEvent],
    allowed: &[&str],
    label: &str,
) -> std::io::Result<()> {
    if events
        .iter()
        .any(|event| !allowed.contains(&event.value.as_str()))
    {
        return Err(std::io::Error::other(format!(
            "candidate {label} trace contains an unknown lifecycle"
        )));
    }
    Ok(())
}

struct ParsedForcedArgument {
    event_id: u64,
    builtin: BuiltinId,
    argument: u16,
    boundary: String,
    outcome: String,
    error_code: Option<String>,
}

fn forced_argument_canonical_key(
    event: &ParsedForcedArgument,
) -> (u16, u16, u8, u8, &str, &str, &str) {
    let phase = match event.boundary.as_str() {
        "nonproductive-repeat" | "nonproductive-parser-node" => Some(0),
        "nonproductive-pending" => Some(1),
        "nonproductive-cancelled" => Some(2),
        _ => None,
    };
    (
        event.builtin.0,
        event.argument,
        u8::from(phase.is_some()),
        phase.unwrap_or_default(),
        &event.boundary,
        &event.outcome,
        event.error_code.as_deref().unwrap_or_default(),
    )
}

fn parse_forced_arguments(encoded: &str) -> std::io::Result<Vec<ParsedForcedArgument>> {
    if encoded.is_empty() {
        return Ok(Vec::new());
    }
    let mut observed = Vec::new();
    for entry in encoded.split("}, {") {
        let entry = entry.strip_prefix('{').unwrap_or(entry);
        let entry = entry.strip_suffix('}').unwrap_or(entry);
        let (event, fields) = entry
            .strip_prefix("\"eventId\": ")
            .and_then(|entry| entry.split_once(", \"builtinId\": "))
            .ok_or_else(|| std::io::Error::other("forced argument trace is malformed"))?;
        let (builtin, fields) = fields
            .split_once(", \"argument\": ")
            .ok_or_else(|| std::io::Error::other("forced argument trace is malformed"))?;
        let (argument, fields) = fields
            .split_once(", \"boundaryClass\": \"")
            .ok_or_else(|| std::io::Error::other("forced argument trace is malformed"))?;
        let (boundary, outcome_fields) = fields
            .split_once("\", \"outcome\": \"")
            .ok_or_else(|| std::io::Error::other("forced argument trace is malformed"))?;
        let (outcome, error_code) = if let Some((outcome, error_code)) =
            outcome_fields.split_once("\", \"errorCode\": \"")
        {
            let error_code = error_code
                .strip_suffix('"')
                .ok_or_else(|| std::io::Error::other("forced argument trace is malformed"))?;
            (outcome, Some(error_code))
        } else {
            (
                outcome_fields
                    .strip_suffix('"')
                    .ok_or_else(|| std::io::Error::other("forced argument trace is malformed"))?,
                None,
            )
        };
        let event = event
            .parse::<u64>()
            .map_err(|_| std::io::Error::other("forced event ID is malformed"))?;
        let builtin = builtin
            .parse::<u16>()
            .map_err(|_| std::io::Error::other("forced builtin ID is malformed"))?;
        let argument = argument
            .parse::<u16>()
            .map_err(|_| std::io::Error::other("forced argument index is malformed"))?;
        let pair = ParsedForcedArgument {
            event_id: event,
            builtin: BuiltinId(builtin),
            argument,
            boundary: boundary.to_owned(),
            outcome: outcome.to_owned(),
            error_code: error_code.map(str::to_owned),
        };
        if usize::from(builtin) >= hell_builtins::registry().len()
            || observed.last().is_some_and(|prior: &ParsedForcedArgument| {
                prior.event_id >= event
                    || forced_argument_canonical_key(prior) > forced_argument_canonical_key(&pair)
            })
            || !matches!(
                boundary,
                "conditional-branch"
                    | "conditional-selection"
                    | "conditional-force-complete"
                    | "deep-demand"
                    | "deep-force-complete"
                    | "io-execution"
                    | "io-execution-complete"
                    | "lazy-adapter-entry"
                    | "lazy-adapter-exit"
                    | "lazy-demand"
                    | "nonproductive-cancelled"
                    | "nonproductive-parser-node"
                    | "nonproductive-pending"
                    | "nonproductive-repeat"
                    | "whnf-demand"
                    | "whnf-force-failed"
                    | "whnf-force-complete"
            )
            || !matches!(
                outcome,
                "value" | "error" | "not-forced" | "in-progress" | "cycle" | "poisoned"
            )
            || match (boundary, outcome, error_code) {
                ("whnf-force-failed", "error", Some(code)) => {
                    code.len() != 5
                        || !code.starts_with('H')
                        || !code[1..].bytes().all(|byte| byte.is_ascii_digit())
                }
                (_, _, None) => false,
                _ => true,
            }
        {
            return Err(std::io::Error::other(
                "forced argument trace is unknown, duplicate, or unsorted",
            ));
        }
        observed.push(pair);
    }
    Ok(observed)
}

fn parse_builtin_events(
    encoded: &str,
    label: &str,
    coverage_event: fn(BuiltinId) -> CoverageEvent,
) -> std::io::Result<(Vec<CoverageEvent>, Vec<u64>)> {
    let mut coverage = Vec::new();
    let mut events = Vec::new();
    let mut prior_event = None;
    if !encoded.is_empty() {
        for entry in encoded.split("}, {") {
            let entry = entry.strip_prefix('{').unwrap_or(entry);
            let entry = entry.strip_suffix('}').unwrap_or(entry);
            let (event, builtin) = entry
                .strip_prefix("\"eventId\": ")
                .and_then(|entry| entry.split_once(", \"builtinId\": "))
                .ok_or_else(|| std::io::Error::other(format!("{label} event is malformed")))?;
            let event = event
                .parse::<u64>()
                .map_err(|_| std::io::Error::other(format!("{label} event ID is malformed")))?;
            let raw = builtin
                .parse::<u16>()
                .map_err(|_| std::io::Error::other("semantic builtin ID is malformed"))?;
            if usize::from(raw) >= hell_builtins::registry().len()
                || prior_event.is_some_and(|prior| prior >= event)
            {
                return Err(std::io::Error::other("semantic builtin ID is unknown"));
            }
            prior_event = Some(event);
            events.push(event);
            coverage.push(coverage_event(BuiltinId(raw)));
        }
    }
    Ok((coverage, events))
}

fn parse_typed_results(encoded: &str) -> std::io::Result<Option<ParsedTypedResult>> {
    if encoded.is_empty() {
        return Ok(None);
    }
    let entries = encoded.split("}, {").collect::<Vec<_>>();
    if entries.len() != 1 {
        return Err(std::io::Error::other(
            "a single-case trace must contain exactly one typed result",
        ));
    }
    let entry = entries[0]
        .strip_prefix('{')
        .unwrap_or(entries[0])
        .strip_suffix('}')
        .unwrap_or(entries[0]);
    let (event, entry) = entry
        .strip_prefix("\"eventId\": ")
        .and_then(|entry| entry.split_once(", \"builtinId\": "))
        .ok_or_else(|| std::io::Error::other("typed result event is malformed"))?;
    let event = event
        .parse::<u64>()
        .map_err(|_| std::io::Error::other("typed result event ID is malformed"))?;
    let (builtin, canonical) = entry
        .split_once(", \"canonicalValue\": ")
        .ok_or_else(|| std::io::Error::other("typed result event is malformed"))?;
    let builtin = builtin
        .parse::<u16>()
        .map_err(|_| std::io::Error::other("typed result builtin ID is malformed"))?;
    if usize::from(builtin) >= hell_builtins::registry().len() {
        return Err(std::io::Error::other("typed result builtin ID is unknown"));
    }
    validate_canonical_typed_value(canonical)?;
    Ok(Some(ParsedTypedResult {
        event_id: event,
        builtin: BuiltinId(builtin),
        sha256: sha256_bytes(canonical.as_bytes()),
        canonical: Arc::from(canonical),
    }))
}

fn validate_canonical_typed_value(value: &str) -> std::io::Result<()> {
    let valid = value == "{\"type\":\"Unit\",\"value\":null}"
        || value == "{\"type\":\"IoAction\"}"
        || matches!(
            value,
            "{\"type\":\"Bool\",\"value\":true}" | "{\"type\":\"Bool\",\"value\":false}"
        )
        || canonical_i64_field(value, "{\"type\":\"Int\",\"value\":\"")
        || canonical_integer_field(value, "{\"type\":\"Integer\",\"value\":\"")
        || canonical_hex_field(
            value,
            "{\"type\":\"Double\",\"ieee754Bits\":\"",
            Some(16),
            false,
        )
        || canonical_character(value)
        || canonical_hex_field(value, "{\"type\":\"Text\",\"utf8Hex\":\"", None, true)
        || canonical_hex_field(value, "{\"type\":\"ByteString\",\"hex\":\"", None, false)
        || canonical_hex_field(value, "{\"type\":\"Builder\",\"hex\":\"", None, false)
        || canonical_time_value(value)
        || canonical_runtime_enum(value)
        || canonical_process(value)
        || canonical_options_mod(value)
        || canonical_options_info_mod(value)
        || canonical_guest_function(value)
        || canonical_case_insensitive(value)
        || canonical_composite_value(value);
    if valid {
        Ok(())
    } else {
        Err(std::io::Error::other(
            "typed result does not use a supported canonical type schema",
        ))
    }
}

fn canonical_time_value(value: &str) -> bool {
    canonical_hex_field(value, "{\"type\":\"Day\",\"iso8601Hex\":\"", None, true)
        || canonical_hex_field(
            value,
            "{\"type\":\"TimeOfDay\",\"iso8601Hex\":\"",
            None,
            true,
        )
        || canonical_hex_field(value, "{\"type\":\"UtcTime\",\"iso8601Hex\":\"", None, true)
        || matches!(
            value,
            "{\"type\":\"DayOfWeek\",\"value\":\"Monday\"}"
                | "{\"type\":\"DayOfWeek\",\"value\":\"Tuesday\"}"
                | "{\"type\":\"DayOfWeek\",\"value\":\"Wednesday\"}"
                | "{\"type\":\"DayOfWeek\",\"value\":\"Thursday\"}"
                | "{\"type\":\"DayOfWeek\",\"value\":\"Friday\"}"
                | "{\"type\":\"DayOfWeek\",\"value\":\"Saturday\"}"
                | "{\"type\":\"DayOfWeek\",\"value\":\"Sunday\"}"
        )
}

fn canonical_guest_function(value: &str) -> bool {
    let Some(body) = value
        .strip_prefix("{\"type\":\"GuestFunction\",\"body\":")
        .and_then(|body| body.strip_suffix("]}"))
    else {
        return false;
    };
    let Some((body, captures)) = body.split_once(",\"captures\":[") else {
        return false;
    };
    body.parse::<u32>()
        .is_ok_and(|parsed| parsed.to_string() == body)
        && split_canonical_array(captures).is_some_and(|captures| {
            captures
                .into_iter()
                .all(|capture| validate_canonical_typed_value(capture).is_ok())
        })
}

fn canonical_process(value: &str) -> bool {
    let Some(body) = value
        .strip_prefix("{\"type\":\"Process\",\"commandHex\":\"")
        .and_then(|body| body.strip_suffix('}'))
    else {
        return false;
    };
    let Some((command, body)) = body.split_once("\",\"argumentsHex\":[") else {
        return false;
    };
    let Some((arguments, body)) = body.split_once("],\"workingDirectoryHex\":") else {
        return false;
    };
    let Some((working_directory, body)) = body.split_once(",\"environment\":") else {
        return false;
    };
    let Some((environment, body)) = body.split_once(",\"stdin\":") else {
        return false;
    };
    let Some((stdin, body)) = body.split_once(",\"stdinHex\":") else {
        return false;
    };
    let Some((stdin_bytes, body)) = body.split_once(",\"stdout\":") else {
        return false;
    };
    let Some((stdout, stderr)) = body.split_once(",\"stderr\":") else {
        return false;
    };
    canonical_utf8_hex(command)
        && canonical_utf8_hex_array(arguments)
        && canonical_optional_utf8_hex(working_directory)
        && canonical_process_environment(environment)
        && canonical_process_handle(stdin)
        && canonical_optional_hex(stdin_bytes)
        && canonical_process_handle(stdout)
        && canonical_process_handle(stderr)
}

fn canonical_utf8_hex_array(value: &str) -> bool {
    value.is_empty()
        || value.split(',').all(|value| {
            value
                .strip_prefix('"')
                .and_then(|value| value.strip_suffix('"'))
                .is_some_and(canonical_utf8_hex)
        })
}

fn canonical_process_environment(value: &str) -> bool {
    if value == "null" {
        return true;
    }
    value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .and_then(split_canonical_array)
        .is_some_and(|entries| {
            entries.into_iter().all(|entry| {
                entry
                    .strip_prefix("{\"nameHex\":\"")
                    .and_then(|entry| entry.strip_suffix("\"}"))
                    .and_then(|entry| entry.split_once("\",\"valueHex\":\""))
                    .is_some_and(|(name, value)| {
                        canonical_utf8_hex(name) && canonical_utf8_hex(value)
                    })
            })
        })
}

fn canonical_process_handle(value: &str) -> bool {
    matches!(
        value,
        "{\"type\":\"Handle\",\"kind\":\"stdin\"}"
            | "{\"type\":\"Handle\",\"kind\":\"stdout\"}"
            | "{\"type\":\"Handle\",\"kind\":\"stderr\"}"
            | "{\"type\":\"Handle\",\"kind\":\"null\"}"
            | "{\"type\":\"Handle\",\"kind\":\"file\",\"closeAfterProcess\":false}"
            | "{\"type\":\"Handle\",\"kind\":\"file\",\"closeAfterProcess\":true}"
    )
}

fn canonical_optional_hex(value: &str) -> bool {
    value == "null"
        || value
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .is_some_and(|value| decode_canonical_hex(value).is_some())
}

fn canonical_options_info_mod(value: &str) -> bool {
    let Some(body) = value
        .strip_prefix("{\"type\":\"OptionsInfoMod\",\"fullDescription\":")
        .and_then(|body| body.strip_suffix('}'))
    else {
        return false;
    };
    let Some((full_description, body)) = body.split_once(",\"programDescriptionHex\":") else {
        return false;
    };
    let Some((program_description, header)) = body.split_once(",\"headerHex\":") else {
        return false;
    };
    matches!(full_description, "true" | "false")
        && canonical_optional_utf8_hex(program_description)
        && canonical_optional_utf8_hex(header)
}

fn canonical_options_mod(value: &str) -> bool {
    value
        .strip_prefix("{\"type\":\"OptionsMod\",\"modifiers\":[")
        .and_then(|body| body.strip_suffix("]}"))
        .and_then(split_canonical_array)
        .is_some_and(|modifiers| {
            modifiers.into_iter().all(|modifier| {
                let Some(body) = modifier
                    .strip_prefix("{\"kind\":\"")
                    .and_then(|body| body.strip_suffix("\"}"))
                else {
                    return false;
                };
                body.split_once("\",\"textHex\":\"")
                    .is_some_and(|(kind, text)| {
                        matches!(kind, "long" | "help" | "metavar") && canonical_utf8_hex(text)
                    })
            })
        })
}

fn canonical_optional_utf8_hex(value: &str) -> bool {
    value == "null"
        || value
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .is_some_and(canonical_utf8_hex)
}

fn canonical_case_insensitive(value: &str) -> bool {
    value
        .strip_prefix("{\"type\":\"CaseInsensitive\",\"original\":")
        .and_then(|body| body.strip_suffix('}'))
        .and_then(|body| body.split_once(",\"folded\":"))
        .is_some_and(|(original, folded)| {
            canonical_foldable_kind(original)
                .zip(canonical_foldable_kind(folded))
                .is_some_and(|(original, folded)| original == folded)
        })
}

fn canonical_foldable_kind(value: &str) -> Option<&'static str> {
    if canonical_hex_field(value, "{\"type\":\"Text\",\"utf8Hex\":\"", None, true) {
        Some("Text")
    } else if canonical_hex_field(value, "{\"type\":\"ByteString\",\"hex\":\"", None, false) {
        Some("ByteString")
    } else {
        None
    }
}

fn canonical_runtime_enum(value: &str) -> bool {
    matches!(
        value,
        "{\"type\":\"BufferMode\",\"value\":\"none\"}"
            | "{\"type\":\"BufferMode\",\"value\":\"line\"}"
            | "{\"type\":\"BufferMode\",\"value\":\"block\"}"
            | "{\"type\":\"FileMode\",\"value\":\"read\"}"
            | "{\"type\":\"FileMode\",\"value\":\"write\"}"
            | "{\"type\":\"FileMode\",\"value\":\"append\"}"
            | "{\"type\":\"FileMode\",\"value\":\"read-write\"}"
            | "{\"type\":\"Handle\",\"kind\":\"stdin\"}"
            | "{\"type\":\"Handle\",\"kind\":\"stdout\"}"
            | "{\"type\":\"Handle\",\"kind\":\"stderr\"}"
            | "{\"type\":\"Handle\",\"kind\":\"null\"}"
            | "{\"type\":\"Handle\",\"kind\":\"file\",\"closeAfterProcess\":false}"
            | "{\"type\":\"Handle\",\"kind\":\"file\",\"closeAfterProcess\":true}"
    )
}

fn canonical_composite_value(value: &str) -> bool {
    canonical_typed_result(value)
        || canonical_force_boundary(value)
        || canonical_sequence(value, "Tuple")
        || canonical_sequence(value, "Vector")
        || canonical_set(value)
        || canonical_record(value)
        || canonical_variant(value)
        || canonical_maybe(value)
        || canonical_primitive_variant(value)
        || canonical_tree(value)
        || canonical_list(value)
        || canonical_map(value)
}

fn canonical_tree(value: &str) -> bool {
    value
        .strip_prefix("{\"type\":\"Tree\",\"elements\":[")
        .and_then(|body| body.strip_suffix("]}"))
        .and_then(split_canonical_array)
        .is_some_and(|elements| {
            elements.len() == 2
                && validate_canonical_typed_value(elements[0]).is_ok()
                && (canonical_list(elements[1]) || canonical_force_boundary(elements[1]))
        })
}

fn canonical_typed_result(value: &str) -> bool {
    let Some(body) = value
        .strip_prefix("{\"type\":\"TypedResult\",\"argument\":")
        .and_then(|body| body.strip_suffix('}'))
    else {
        return false;
    };
    let Some((argument, remainder)) = body.split_once(",\"boundary\":\"") else {
        return false;
    };
    let Some((boundary, value)) = remainder.split_once("\",\"value\":") else {
        return false;
    };
    argument
        .parse::<usize>()
        .is_ok_and(|parsed| parsed.to_string() == argument)
        && matches!(boundary, "adapter-result" | "conditional-selected")
        && validate_canonical_typed_value(value).is_ok()
}

fn canonical_force_boundary(value: &str) -> bool {
    matches!(
        value,
        "{\"type\":\"ForceBoundary\",\"outcome\":\"not-forced\"}"
            | "{\"type\":\"ForceBoundary\",\"outcome\":\"in-progress\"}"
            | "{\"type\":\"ForceBoundary\",\"outcome\":\"cycle\"}"
            | "{\"type\":\"ForceBoundary\",\"outcome\":\"depth-limit\"}"
    ) || value
        .strip_prefix("{\"type\":\"ForceBoundary\",\"outcome\":\"error\",\"code\":\"")
        .and_then(|code| code.strip_suffix("\"}"))
        .is_some_and(canonical_error_code)
}

fn canonical_error_code(value: &str) -> bool {
    hell_builtins::RuntimeDiagnosticCode::parse(value).is_some()
}

fn canonical_sequence(value: &str, kind: &str) -> bool {
    let prefix = format!("{{\"type\":\"{kind}\",\"elements\":[");
    value
        .strip_prefix(&prefix)
        .and_then(|body| body.strip_suffix("]}"))
        .is_some_and(canonical_value_array)
}

fn canonical_record(value: &str) -> bool {
    let Some(body) = value
        .strip_prefix("{\"type\":\"Record\",\"typeNameHex\":\"")
        .and_then(|body| body.strip_suffix("]}"))
    else {
        return false;
    };
    let Some((type_name, body)) = body.split_once("\",\"constructorHex\":\"") else {
        return false;
    };
    let Some((constructor, fields)) = body.split_once("\",\"fields\":[") else {
        return false;
    };
    canonical_utf8_hex(type_name)
        && canonical_utf8_hex(constructor)
        && split_canonical_array(fields).is_some_and(|fields| {
            let parsed = fields
                .into_iter()
                .map(|field| {
                    field
                        .strip_prefix("{\"nameHex\":\"")
                        .and_then(|field| field.strip_suffix('}'))
                        .and_then(|field| field.split_once("\",\"value\":"))
                })
                .collect::<Option<Vec<_>>>();
            parsed.is_some_and(|fields| {
                let mut names = std::collections::BTreeSet::new();
                fields.into_iter().all(|(name, value)| {
                    canonical_utf8_hex(name)
                        && names.insert(name)
                        && validate_canonical_typed_value(value).is_ok()
                })
            })
        })
}

fn canonical_variant(value: &str) -> bool {
    let Some(body) = value
        .strip_prefix("{\"type\":\"Variant\",\"typeNameHex\":\"")
        .and_then(|body| body.strip_suffix('}'))
    else {
        return false;
    };
    let Some((type_name, body)) = body.split_once("\",\"constructorHex\":\"") else {
        return false;
    };
    let Some((constructor, payload)) = body.split_once("\",\"payload\":") else {
        return false;
    };
    canonical_utf8_hex(type_name)
        && canonical_utf8_hex(constructor)
        && canonical_optional_value(payload)
}

fn canonical_maybe(value: &str) -> bool {
    value
        .strip_prefix("{\"type\":\"Maybe\",\"payload\":")
        .and_then(|payload| payload.strip_suffix('}'))
        .is_some_and(canonical_optional_value)
}

fn canonical_optional_value(value: &str) -> bool {
    value == "null" || validate_canonical_typed_value(value).is_ok()
}

fn canonical_primitive_variant(value: &str) -> bool {
    let Some(body) = value
        .strip_prefix("{\"type\":\"PrimitiveVariant\",\"family\":\"")
        .and_then(|body| body.strip_suffix("]}"))
    else {
        return false;
    };
    let Some((family, body)) = body.split_once("\",\"constructor\":\"") else {
        return false;
    };
    let Some((constructor, payloads)) = body.split_once("\",\"payloads\":[") else {
        return false;
    };
    let Some(expected_arity) = canonical_primitive_constructor(family, constructor) else {
        return false;
    };
    split_canonical_array(payloads).is_some_and(|payloads| {
        payloads.len() == expected_arity
            && payloads
                .into_iter()
                .all(|payload| validate_canonical_typed_value(payload).is_ok())
    })
}

fn canonical_primitive_constructor(family: &str, constructor: &str) -> Option<usize> {
    match family {
        "Either" if matches!(constructor, "Left" | "Right") => Some(1),
        "Exit" if constructor == "ExitSuccess" => Some(0),
        "Exit" if constructor == "ExitFailure" => Some(1),
        "These" if matches!(constructor, "This" | "That") => Some(1),
        "These" if constructor == "These" => Some(2),
        "Json" if constructor == "Null" => Some(0),
        "Json"
            if matches!(
                constructor,
                "Bool" | "String" | "Number" | "Array" | "Object"
            ) =>
        {
            Some(1)
        }
        _ => None,
    }
}

fn canonical_set(value: &str) -> bool {
    value
        .strip_prefix("{\"type\":\"Set\",\"elements\":[")
        .and_then(|body| body.strip_suffix("]}"))
        .and_then(split_canonical_array)
        .is_some_and(|elements| {
            elements
                .into_iter()
                .all(|element| validate_canonical_typed_value(element).is_ok())
        })
}

fn canonical_list(value: &str) -> bool {
    let Some(body) = value
        .strip_prefix("{\"type\":\"List\",\"elements\":[")
        .and_then(|body| body.strip_suffix("\"}"))
    else {
        return false;
    };
    let Some((elements, termination)) = body.rsplit_once("],\"terminationHex\":\"") else {
        return false;
    };
    canonical_value_array(elements) && canonical_list_termination(termination)
}

fn canonical_list_termination(value: &str) -> bool {
    let Some(bytes) = decode_canonical_hex(value) else {
        return false;
    };
    let Ok(value) = std::str::from_utf8(&bytes) else {
        return false;
    };
    matches!(
        value,
        "nil" | "not-forced" | "in-progress" | "element-limit"
    ) || value
        .strip_prefix("error:")
        .is_some_and(canonical_error_code)
        || value
            .strip_prefix("indirection:")
            .is_some_and(|nested| validate_canonical_typed_value(nested).is_ok())
}

fn canonical_map(value: &str) -> bool {
    value
        .strip_prefix("{\"type\":\"Map\",\"entries\":[")
        .and_then(|body| body.strip_suffix("]}"))
        .and_then(split_canonical_array)
        .is_some_and(|entries| {
            let parsed = entries
                .into_iter()
                .map(|entry| {
                    entry
                        .strip_prefix("{\"key\":")
                        .and_then(|entry| entry.strip_suffix('}'))
                        .and_then(|entry| split_top_level_once(entry, ",\"value\":"))
                })
                .collect::<Option<Vec<_>>>();
            parsed.is_some_and(|entries| {
                entries.into_iter().all(|(key, value)| {
                    validate_canonical_typed_value(key).is_ok()
                        && validate_canonical_typed_value(value).is_ok()
                })
            })
        })
}

fn canonical_value_array(value: &str) -> bool {
    split_canonical_array(value).is_some_and(|values| {
        values
            .into_iter()
            .all(|value| validate_canonical_typed_value(value).is_ok())
    })
}

fn split_canonical_array(value: &str) -> Option<Vec<&str>> {
    if value.is_empty() {
        return Some(Vec::new());
    }
    let mut values = Vec::new();
    let mut start = 0;
    let mut depth = 0_i32;
    let mut quoted = false;
    for (index, byte) in value.bytes().enumerate() {
        match byte {
            b'"' => quoted = !quoted,
            b'{' | b'[' if !quoted => depth = depth.checked_add(1)?,
            b'}' | b']' if !quoted => depth = depth.checked_sub(1)?,
            b',' if !quoted && depth == 0 => {
                values.push(&value[start..index]);
                start = index.checked_add(1)?;
            }
            _ => {}
        }
        if depth < 0 {
            return None;
        }
    }
    if quoted || depth != 0 {
        return None;
    }
    values.push(&value[start..]);
    Some(values)
}

fn split_top_level_once<'a>(value: &'a str, separator: &str) -> Option<(&'a str, &'a str)> {
    let mut depth = 0_i32;
    let mut quoted = false;
    for (index, character) in value.char_indices() {
        match character {
            '"' => quoted = !quoted,
            '{' | '[' if !quoted => depth = depth.checked_add(1)?,
            '}' | ']' if !quoted => depth = depth.checked_sub(1)?,
            _ => {}
        }
        if !quoted && depth == 0 && value[index..].starts_with(separator) {
            return Some((&value[..index], &value[index + separator.len()..]));
        }
        if depth < 0 {
            return None;
        }
    }
    None
}

fn canonical_utf8_hex(value: &str) -> bool {
    value.len().is_multiple_of(2)
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        && decode_canonical_hex(value).is_some_and(|bytes| std::str::from_utf8(&bytes).is_ok())
}

fn quoted_typed_field<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    value.strip_prefix(prefix)?.strip_suffix("\"}")
}

fn canonical_i64_field(value: &str, prefix: &str) -> bool {
    quoted_typed_field(value, prefix).is_some_and(|encoded| {
        encoded
            .parse::<i64>()
            .is_ok_and(|parsed| parsed.to_string() == encoded)
    })
}

fn canonical_integer_field(value: &str, prefix: &str) -> bool {
    quoted_typed_field(value, prefix).is_some_and(canonical_decimal)
}

fn canonical_decimal(value: &str) -> bool {
    if value == "0" {
        return true;
    }
    let digits = value.strip_prefix('-').unwrap_or(value).as_bytes();
    !digits.is_empty()
        && digits[0] != b'0'
        && digits.iter().all(u8::is_ascii_digit)
        && !value.starts_with("-0")
}

fn canonical_hex_field(value: &str, prefix: &str, length: Option<usize>, utf8: bool) -> bool {
    quoted_typed_field(value, prefix).is_some_and(|encoded| {
        length.is_none_or(|expected| encoded.len() == expected)
            && encoded.len() % 2 == 0
            && encoded
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            && (!utf8
                || decode_canonical_hex(encoded)
                    .is_some_and(|bytes| std::str::from_utf8(&bytes).is_ok()))
    })
}

fn decode_canonical_hex(value: &str) -> Option<Vec<u8>> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|digits| {
            let high = hex_nibble(digits[0])?;
            let low = hex_nibble(digits[1])?;
            Some((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn canonical_character(value: &str) -> bool {
    value
        .strip_prefix("{\"type\":\"Character\",\"codePoint\":")
        .and_then(|encoded| encoded.strip_suffix('}'))
        .and_then(|encoded| {
            encoded
                .parse::<u32>()
                .ok()
                .filter(|parsed| parsed.to_string() == encoded)
        })
        .and_then(char::from_u32)
        .is_some()
}

fn parse_resource_audit(bytes: &[u8]) -> std::io::Result<ResourceAudit> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| std::io::Error::other("candidate resource audit was not UTF-8"))?;
    let expected_fields = [
        "tasks",
        "handles",
        "processes",
        "httpBodies",
        "temporaryResources",
        "cleanupFailures",
    ];
    if json_usize_line(text, "schemaVersion") != Some(1) {
        return Err(std::io::Error::other(
            "candidate resource audit has an unsupported schema",
        ));
    }
    let nonempty = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && *line != "{" && *line != "}")
        .count();
    if nonempty != expected_fields.len() + 1 {
        return Err(std::io::Error::other(
            "candidate resource audit contains missing or unknown fields",
        ));
    }
    let values = expected_fields
        .map(|field| json_usize_line(text, field))
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| std::io::Error::other("candidate resource audit has a malformed field"))?;
    Ok(ResourceAudit {
        tasks: values[0],
        handles: values[1],
        processes: values[2],
        http_bodies: values[3],
        temporary_resources: values[4],
        cleanup_failures: values[5],
    })
}

/// Verifies one canonical resource-audit document and requires its complete
/// retained task/handle/process/body/temporary/cleanup audit to be zero.
///
/// # Errors
///
/// Returns an error for malformed audit bytes or any nonzero resource count.
pub fn verify_zero_resource_audit_bytes(bytes: &[u8]) -> std::io::Result<()> {
    let audit = parse_resource_audit(bytes)?;
    if audit.failure_count() != 0 {
        return Err(std::io::Error::other(
            "collection resource audit records a retained resource failure",
        ));
    }
    Ok(())
}

fn json_usize_line(document: &str, field: &str) -> Option<usize> {
    let prefix = format!("\"{field}\": ");
    let mut values = document.lines().filter_map(|line| {
        line.trim()
            .strip_prefix(&prefix)
            .map(|value| value.strip_suffix(',').unwrap_or(value))
            .and_then(|value| value.parse().ok())
    });
    let value = values.next()?;
    values.next().is_none().then_some(value)
}

fn diagnostic_sandbox_path_v1(
    stderr: &[u8],
    executable: &Path,
    sandbox: &Path,
    script: &Path,
) -> Vec<u8> {
    let program = executable
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or_default();
    let sandbox = sandbox.to_string_lossy();
    let script = script.to_string_lossy();
    scrub_diagnostic_path_bytes(
        stderr,
        sandbox.as_bytes(),
        script.as_bytes(),
        program.as_bytes(),
    )
}

fn diagnostic_path_separator_v1(stderr: &mut [u8]) {
    const WINDOWS: &[u8] = b"<SANDBOX>\\main.hell";
    const PORTABLE: &[u8] = b"<SANDBOX>/main.hell";
    let mut offset = 0;
    while let Some(index) = stderr[offset..]
        .windows(WINDOWS.len())
        .position(|window| window == WINDOWS)
    {
        let start = offset + index;
        stderr[start..start + WINDOWS.len()].copy_from_slice(PORTABLE);
        offset = start + PORTABLE.len();
    }
}

#[cfg(feature = "mutation-testing")]
fn diagnostic_mutant_active() -> bool {
    let arguments = std::env::args_os().collect::<Vec<_>>();
    arguments.windows(4).any(|window| {
        window[0] == "--skip"
            && window[1] == "__hell_mutant"
            && window[2] == "--skip"
            && window[3] == "diagnostic-overbroad-normalization"
    })
}

#[cfg(not(feature = "mutation-testing"))]
const fn diagnostic_mutant_active() -> bool {
    false
}

#[cfg(feature = "mutation-testing")]
fn diagnostic_program_mutant_active() -> bool {
    let arguments = std::env::args_os().collect::<Vec<_>>();
    arguments.windows(4).any(|window| {
        window[0] == "--skip"
            && window[1] == "__hell_mutant"
            && window[2] == "--skip"
            && window[3] == "diagnostic-hardcoded-oracle-program"
    })
}

#[cfg(not(feature = "mutation-testing"))]
const fn diagnostic_program_mutant_active() -> bool {
    false
}

fn scrub_diagnostic_path_bytes(
    stderr: &[u8],
    _sandbox: &[u8],
    script: &[u8],
    program: &[u8],
) -> Vec<u8> {
    if diagnostic_mutant_active() {
        return replace_all(stderr, script, b"<SANDBOX>/main.hell");
    }
    let mut scrubbed = stderr.to_vec();
    let marker: &[u8] = if script.contains(&b'\\') {
        b"<SANDBOX>\\main.hell"
    } else {
        b"<SANDBOX>/main.hell"
    };
    let mut quoted_script = b"SrcSpan \"".to_vec();
    quoted_script.extend_from_slice(&haskell_show_path(script));
    quoted_script.push(b'"');
    let mut quoted_marker = b"SrcSpan \"".to_vec();
    quoted_marker.extend_from_slice(marker);
    quoted_marker.push(b'"');
    scrubbed = replace_all(&scrubbed, &quoted_script, &quoted_marker);
    let mut output = Vec::with_capacity(scrubbed.len());
    let mut separate_parse_frame = 0_u8;
    for line in scrubbed.split_inclusive(|byte| *byte == b'\n') {
        if let Some((prefix, suffix)) = structured_diagnostic_path(line, script, program) {
            output.extend_from_slice(prefix);
            output.extend_from_slice(marker);
            output.extend_from_slice(suffix);
            separate_parse_frame = 0;
        } else if separate_parse_frame == 2
            && let Some((prefix, suffix)) = separate_oracle_parse_path(line, script)
        {
            output.extend_from_slice(prefix);
            output.extend_from_slice(marker);
            output.extend_from_slice(suffix);
            separate_parse_frame = 0;
        } else {
            output.extend_from_slice(line);
            separate_parse_frame = if exact_oracle_exception_frame(line, program) {
                1
            } else if separate_parse_frame == 1 && diagnostic_blank_line(line) {
                2
            } else {
                0
            };
        }
    }
    output
}

fn exact_oracle_exception_frame(line: &[u8], program: &[u8]) -> bool {
    const SUFFIX: &[u8] = b": Uncaught exception ghc-internal:GHC.Internal.Exception.ErrorCall:";
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    !program.is_empty() && line.strip_prefix(program) == Some(SUFFIX)
}

fn diagnostic_blank_line(line: &[u8]) -> bool {
    line == b"\n" || line == b"\r\n"
}

fn separate_oracle_parse_path<'a>(line: &'a [u8], script: &[u8]) -> Option<(&'a [u8], &'a [u8])> {
    const PREFIX: &[u8] = b"Parse error: ";
    line.strip_prefix(PREFIX)
        .and_then(|line| line.strip_prefix(script))
        .filter(|suffix| diagnostic_path_suffix(suffix))
        .map(|suffix| (&line[..PREFIX.len()], suffix))
}

fn structured_diagnostic_path<'a>(
    line: &'a [u8],
    script: &[u8],
    program: &[u8],
) -> Option<(&'a [u8], &'a [u8])> {
    const HELPER_PREFIX: &[u8] = b"unknown helper subcommand ";
    const ORACLE_PARSE_MARKER: &[u8] = b": Parse error: ";
    if let Some(suffix) = line
        .strip_prefix(script)
        .filter(|suffix| diagnostic_path_suffix(suffix))
    {
        return Some((&line[..0], suffix));
    }
    if let Some(suffix) = line
        .strip_prefix(HELPER_PREFIX)
        .and_then(|line| line.strip_prefix(script))
        .filter(|suffix| diagnostic_path_suffix(suffix))
    {
        return Some((&line[..HELPER_PREFIX.len()], suffix));
    }
    if !program.is_empty()
        && let Some(suffix) = line
            .strip_prefix(program)
            .and_then(|line| line.strip_prefix(ORACLE_PARSE_MARKER))
            .and_then(|line| line.strip_prefix(script))
            .filter(|suffix| diagnostic_path_suffix(suffix))
    {
        return Some((&line[..program.len() + ORACLE_PARSE_MARKER.len()], suffix));
    }
    None
}

fn diagnostic_path_suffix(suffix: &[u8]) -> bool {
    suffix.is_empty() || suffix.first() == Some(&b':')
}

fn haskell_show_path(path: &[u8]) -> Vec<u8> {
    let mut escaped = Vec::new();
    for byte in path {
        if *byte == b'\\' {
            escaped.push(b'\\');
        }
        escaped.push(*byte);
    }
    escaped
}

fn parse_diagnostic_observation(stderr: &[u8]) -> std::io::Result<DiagnosticObservation> {
    const SANDBOX_MARKER: &str = "<SANDBOX>";
    const SCRIPT_NAME: &str = "main.hell";
    let text = std::str::from_utf8(stderr)
        .map_err(|_| std::io::Error::other("check diagnostic was not UTF-8"))?;
    let phase = if text.contains("Parse error:") || text.contains("error[H02") {
        DiagnosticPhase::Parse
    } else {
        DiagnosticPhase::StaticSemantics
    };
    let (code, category, protected_message) = diagnostic_identity(text, phase)?;
    let remainder = text
        .split(SANDBOX_MARKER)
        .skip(1)
        .find_map(|remainder| {
            remainder
                .strip_prefix('/')
                .or_else(|| remainder.strip_prefix('\\'))
                .and_then(|path| path.strip_prefix(SCRIPT_NAME))
        })
        .ok_or_else(|| std::io::Error::other("check diagnostic did not identify main.hell"))?;
    let (line, column) = if let Some(location) = remainder.strip_prefix(':') {
        let mut fields = location.split(':');
        let line = parse_location_field(fields.next(), "line")?;
        let column = parse_location_field(fields.next(), "column")?;
        (line, column)
    } else {
        let location = remainder
            .strip_prefix('"')
            .ok_or_else(|| std::io::Error::other("oracle diagnostic had no SrcSpan location"))?;
        let mut fields = location.split_whitespace();
        let line = parse_location_field(fields.next(), "line")?;
        let column = parse_location_field(fields.next(), "column")?;
        (line, column)
    };
    Ok(DiagnosticObservation {
        phase,
        code: Arc::from(code),
        category,
        protected_message: Arc::from(protected_message),
        line,
        column,
    })
}

fn diagnostic_identity(
    text: &str,
    phase: DiagnosticPhase,
) -> std::io::Result<(&'static str, DiagnosticCategory, &'static str)> {
    match phase {
        DiagnosticPhase::Parse
            if text.contains("Parse error:") || text.contains("error[H0200]") =>
        {
            Ok(("H0200", DiagnosticCategory::Syntax, "syntax-error"))
        }
        DiagnosticPhase::StaticSemantics
            if text.contains("Invalid variable:") || text.contains("error[H0402]") =>
        {
            Ok((
                "H0402",
                DiagnosticCategory::NameResolution,
                "unresolved-name",
            ))
        }
        _ => Err(std::io::Error::other(
            "check diagnostic code/category/message is unsupported or inconsistent",
        )),
    }
}

fn parse_location_field(value: Option<&str>, name: &str) -> std::io::Result<usize> {
    value
        .ok_or_else(|| std::io::Error::other(format!("diagnostic had no {name}")))?
        .parse()
        .map_err(|_| std::io::Error::other(format!("diagnostic {name} was not an integer")))
}

fn resolve_and_hash(
    path: &Path,
) -> std::io::Result<(PathBuf, Digest, Option<BoundProgramInvocation>)> {
    let path = fs::canonicalize(path)?;
    #[cfg(windows)]
    {
        let deadline = windows_program_authority_acquisition_deadline()?;
        let authority = BoundProgramInvocation::new_until(path.clone(), path.clone(), deadline)?;
        let sha256 = authority.sha256();
        Ok((path, sha256, Some(authority)))
    }
    #[cfg(not(windows))]
    {
        let sha256 = sha256_file(&path)?;
        Ok((path, sha256, None))
    }
}

fn probe_identity(
    path: PathBuf,
    sha256: Digest,
    role: ExecutableRole,
    require_candidate_build_info: bool,
    authority: Option<&BoundProgramInvocation>,
) -> std::io::Result<ExecutableIdentity> {
    let reported_version = probe_lines(&path, "--version", authority)?;
    let reported_version: Arc<str> = reported_version
        .first()
        .ok_or_else(|| std::io::Error::other("--version produced no output"))?
        .clone();
    let build_info = if role == ExecutableRole::Candidate {
        let parsed = probe_lines(&path, "--build-info", authority).and_then(|lines| {
            parse_candidate_build_info(lines.iter().map(std::convert::AsRef::as_ref))
        });
        match parsed {
            Ok(build_info) => Some(build_info),
            Err(error) if require_candidate_build_info => return Err(error),
            Err(_) => None,
        }
    } else {
        None
    };
    let observed_sha256 = if let Some(authority) = authority {
        authority.revalidate(path.as_os_str())?;
        #[cfg(windows)]
        {
            authority.sha256()
        }
        #[cfg(not(windows))]
        {
            sha256_file(&path)?
        }
    } else {
        sha256_file(&path)?
    };
    if observed_sha256 != sha256 {
        return Err(std::io::Error::other(format!(
            "{:?} executable changed during identity probing: expected {}, observed {}",
            role,
            sha256.hex(),
            observed_sha256.hex()
        )));
    }
    Ok(ExecutableIdentity {
        path,
        sha256,
        reported_version,
        build_info,
        role,
        assurance_epoch_sha256: None,
        acquisition_receipt_id: None,
        acquisition_receipt_sha256: None,
        acquisition_attestation_sha256: None,
    })
}

fn probe_lines(
    path: &Path,
    argument: &str,
    authority: Option<&BoundProgramInvocation>,
) -> std::io::Result<Vec<Arc<str>>> {
    let mut command = Command::new(path);
    scrub_ci_authority_environment(&mut command);
    command.arg(argument);
    #[cfg(windows)]
    let prelaunch_evidence = if CANDIDATE_LAUNCH_POLICY.with(|slot| slot.borrow().is_some()) {
        let diagnostic_deadline = Instant::now()
            .checked_add(WINDOWS_PRELAUNCH_DIAGNOSTIC_BUDGET)
            .ok_or_else(|| std::io::Error::other("prelaunch diagnostic deadline overflowed"))?;
        Some(
            windows_argv_target_prelaunch_diagnostic_with_program_until(
                path,
                authority,
                diagnostic_deadline,
            )
            .rendered
            .clone(),
        )
    } else {
        None
    };
    #[cfg(not(windows))]
    let prelaunch_evidence = None;
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(5))
        .ok_or_else(|| std::io::Error::other("version probe deadline overflowed"))?;
    let output = run_supervised_command_inner(
        &mut command,
        &[],
        deadline,
        None,
        authority,
        prelaunch_evidence.clone(),
        None,
    )
    .map_err(|primary| compose_prelaunch_evidence_error(primary, prelaunch_evidence.as_deref()))?;
    if output.timed_out {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!(
                "version probe {argument:?} for {:?} exceeded five seconds: status={}, termination={:?}, phases={}, prelaunchEvidence={:?}, stdout={}, stderr={}",
                EscapedPath(path),
                supervised_status_diagnostic(output.status.code()),
                output.termination,
                supervised_phase_diagnostic(&output.phase_timings),
                output.prelaunch_evidence,
                bounded_probe_capture_diagnostic(&output.stdout),
                bounded_probe_capture_diagnostic(&output.stderr),
            ),
        ));
    }
    if !output.status.success() {
        return Err(std::io::Error::other(format!(
            "{argument} failed with status {}: {}; prelaunchEvidence={:?}",
            supervised_status_diagnostic(output.status.code()),
            bounded_probe_capture_diagnostic(&output.stderr),
            output.prelaunch_evidence,
        )));
    }
    let complete = output
        .stdout
        .complete
        .ok_or_else(|| std::io::Error::other("version probe exceeded its capture bound"))?;
    let text = std::str::from_utf8(&complete)
        .map_err(|_| std::io::Error::other("version probe output was not UTF-8"))?;
    let lines: Vec<Arc<str>> = text.lines().map(Arc::<str>::from).collect();
    if lines.is_empty() || lines.iter().any(|line| line.trim().is_empty()) {
        return Err(std::io::Error::other(
            "version probe output must contain nonempty lines",
        ));
    }
    Ok(lines)
}

fn compose_prelaunch_evidence_error(
    primary: std::io::Error,
    prelaunch_evidence: Option<&str>,
) -> std::io::Error {
    match prelaunch_evidence {
        Some(evidence) => {
            let kind = primary.kind();
            std::io::Error::new(
                kind,
                PrelaunchEvidenceError {
                    primary,
                    evidence: evidence.to_owned(),
                },
            )
        }
        None => primary,
    }
}

#[derive(Debug)]
struct PrelaunchEvidenceError {
    primary: std::io::Error,
    evidence: String,
}

impl std::fmt::Display for PrelaunchEvidenceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}; prelaunchEvidence={:?}",
            self.primary, self.evidence
        )
    }
}

impl std::error::Error for PrelaunchEvidenceError {}

const PROBE_DIAGNOSTIC_EDGE_BYTES: usize = 4 * 1024;

fn bounded_probe_capture_diagnostic(capture: &BoundedCapture) -> String {
    let mut retained = capture
        .prefix
        .iter()
        .take(PROBE_DIAGNOSTIC_EDGE_BYTES)
        .copied()
        .collect::<Vec<_>>();
    if capture.truncated || capture.total_bytes > u64::try_from(retained.len()).unwrap_or(u64::MAX)
    {
        retained.extend_from_slice(b"<TRUNCATED>");
        let suffix_start = capture
            .suffix
            .len()
            .saturating_sub(PROBE_DIAGNOSTIC_EDGE_BYTES);
        retained.extend_from_slice(&capture.suffix[suffix_start..]);
    }
    format!(
        "bytes={},sha256={},retained={:?}",
        capture.total_bytes,
        capture.sha256.hex(),
        String::from_utf8_lossy(&retained),
    )
}

fn supervised_status_diagnostic(status: Option<i32>) -> String {
    status.map_or_else(
        || "none".to_owned(),
        |code| format!("{code} (0x{:08x})", code.cast_unsigned()),
    )
}

fn supervised_phase_diagnostic(phases: &[SupervisedPhaseTiming]) -> String {
    phases
        .iter()
        .map(|phase| format!("{}={}ms", phase.name, phase.elapsed.as_millis()))
        .collect::<Vec<_>>()
        .join(",")
}

struct CapturedProcess {
    status: ExitStatus,
    stdout: BoundedCapture,
    stderr: BoundedCapture,
    timed_out: bool,
    duration: Duration,
}

struct QuiescenceGuard {
    policy: Option<CandidateLaunchPolicy>,
}

impl QuiescenceGuard {
    fn new(policy: Option<CandidateLaunchPolicy>) -> Self {
        Self { policy }
    }
}

/// Result of a structured host command run under process-tree supervision.
#[derive(Clone, Debug)]
pub struct SupervisedOutput {
    pub status: ExitStatus,
    pub stdout: BoundedCapture,
    pub stderr: BoundedCapture,
    pub timed_out: bool,
    pub termination: Option<TerminationReport>,
    pub phase_timings: Vec<SupervisedPhaseTiming>,
    pub prelaunch_evidence: Option<String>,
    pub candidate_quiescence_complete: bool,
    #[cfg(windows)]
    pub windows_launch_control: Option<WindowsLaunchControlReceipt>,
}

/// Authenticated terminal receipt for the Windows restricted-launch control plane.
///
/// Successful launcher and argv-adapter phases are retained here instead of
/// being mixed into the target program's stderr stream.
#[cfg(windows)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowsLaunchControlReceipt {
    pub schema_version: u64,
    pub request_sha256: Digest,
    pub state: &'static str,
    pub phases: Arc<[&'static str]>,
    pub bytes: u64,
    pub sha256: Digest,
    pub status_code: Option<i32>,
    pub timed_out: bool,
    pub termination_forced: bool,
    pub termination_reaped: bool,
    pub candidate_quiescence_complete: bool,
    pub program: Option<PathBuf>,
    pub program_bytes: Option<u64>,
    pub program_sha256: Option<Digest>,
    pub current_directory: PathBuf,
}

#[cfg(windows)]
impl WindowsLaunchControlReceipt {
    fn encoded(&self) -> Vec<u8> {
        use std::os::windows::ffi::OsStrExt as _;

        fn field(bytes: &mut Vec<u8>, value: &[u8]) {
            bytes.extend_from_slice(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_le_bytes());
            bytes.extend_from_slice(value);
        }

        fn path_field(bytes: &mut Vec<u8>, value: Option<&Path>) {
            let encoded = value
                .into_iter()
                .flat_map(|path| path.as_os_str().encode_wide())
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>();
            field(bytes, &encoded);
        }

        let mut encoded = b"windows-launch-control-v1".to_vec();
        field(&mut encoded, &self.request_sha256.0);
        field(&mut encoded, self.state.as_bytes());
        for phase in self.phases.iter() {
            field(&mut encoded, phase.as_bytes());
        }
        field(
            &mut encoded,
            &self.status_code.unwrap_or(i32::MIN).to_le_bytes(),
        );
        field(
            &mut encoded,
            &[
                u8::from(self.timed_out),
                u8::from(self.termination_forced),
                u8::from(self.termination_reaped),
                u8::from(self.candidate_quiescence_complete),
            ],
        );
        path_field(&mut encoded, self.program.as_deref());
        field(
            &mut encoded,
            &self.program_bytes.unwrap_or(u64::MAX).to_le_bytes(),
        );
        field(&mut encoded, &self.program_sha256.unwrap_or_default().0);
        path_field(&mut encoded, Some(&self.current_directory));
        encoded
    }

    /// Revalidates the bounded authenticated control receipt.
    ///
    /// # Errors
    ///
    /// Returns an error when its schema, terminal state, byte count, digest,
    /// phase inventory, program authority, or canonical cwd differs.
    pub fn validate(&self) -> std::io::Result<()> {
        let encoded = self.encoded();
        if self.schema_version != 1
            || !matches!(self.state, "completed" | "failed")
            || (self.state == "completed" && self.phases.as_ref() != WINDOWS_LAUNCH_CONTROL_PHASES)
            || (self.state == "failed" && !self.phases.is_empty())
            || self.bytes != u64::try_from(encoded.len()).unwrap_or(u64::MAX)
            || self.sha256 != sha256_bytes(&encoded)
            || (self.state == "completed"
                && (self.status_code != Some(0)
                    || self.timed_out
                    || !self.termination_reaped
                    || !self.candidate_quiescence_complete))
            || fs::canonicalize(&self.current_directory)? != self.current_directory
            || self.program.is_some() != self.program_bytes.is_some()
            || self.program.is_some() != self.program_sha256.is_some()
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Windows restricted launch control receipt differs",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupervisedPhaseTiming {
    pub name: &'static str,
    pub elapsed: Duration,
}

/// Identifies one supervised child output stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SupervisedOutputStream {
    Stdout,
    Stderr,
}

/// One bounded child-output progress record.
#[derive(Debug)]
pub struct SupervisedProgressChunk {
    pub stream: SupervisedOutputStream,
    pub bytes: Vec<u8>,
}

/// Snapshot of progress records omitted because the bounded queue was full.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SupervisedProgressLoss {
    pub chunks: u64,
    pub bytes: u64,
}

/// Counter-only progress loss receipt that does not keep the output queue connected.
#[derive(Clone)]
pub struct SupervisedProgressLossReceipt {
    dropped_chunks: Arc<AtomicU64>,
    dropped_bytes: Arc<AtomicU64>,
}

impl SupervisedProgressLossReceipt {
    #[must_use]
    pub fn snapshot(&self) -> SupervisedProgressLoss {
        SupervisedProgressLoss {
            chunks: self.dropped_chunks.load(Ordering::Relaxed),
            bytes: self.dropped_bytes.load(Ordering::Relaxed),
        }
    }
}

/// Nonblocking bounded progress sink used by supervised capture readers.
#[derive(Clone)]
pub struct SupervisedProgressObserver {
    sender: mpsc::SyncSender<SupervisedProgressChunk>,
    dropped_chunks: Arc<AtomicU64>,
    dropped_bytes: Arc<AtomicU64>,
}

impl SupervisedProgressObserver {
    #[must_use]
    pub fn bounded(capacity: usize) -> (Self, mpsc::Receiver<SupervisedProgressChunk>) {
        let (sender, receiver) = mpsc::sync_channel(capacity);
        (
            Self {
                sender,
                dropped_chunks: Arc::new(AtomicU64::new(0)),
                dropped_bytes: Arc::new(AtomicU64::new(0)),
            },
            receiver,
        )
    }

    fn observe(&self, stream: SupervisedOutputStream, bytes: &[u8]) {
        let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if self
            .sender
            .try_send(SupervisedProgressChunk {
                stream,
                bytes: bytes.to_vec(),
            })
            .is_err()
        {
            self.dropped_chunks.fetch_add(1, Ordering::Relaxed);
            self.dropped_bytes.fetch_add(length, Ordering::Relaxed);
        }
    }

    #[must_use]
    pub fn loss(&self) -> SupervisedProgressLoss {
        SupervisedProgressLoss {
            chunks: self.dropped_chunks.load(Ordering::Relaxed),
            bytes: self.dropped_bytes.load(Ordering::Relaxed),
        }
    }

    #[must_use]
    pub fn loss_receipt(&self) -> SupervisedProgressLossReceipt {
        SupervisedProgressLossReceipt {
            dropped_chunks: Arc::clone(&self.dropped_chunks),
            dropped_bytes: Arc::clone(&self.dropped_bytes),
        }
    }
}

/// Runs an already-structured command with concurrent bounded capture.
///
/// The caller supplies program and arguments through [`Command`]; this helper
/// never performs shell parsing. It drains both output streams to EOF, retains
/// their complete SHA-256 digests, and terminates the full process group or Job
/// Object at the deadline.
///
/// # Errors
///
/// Returns an error when the process tree, input writer, capture reader, or
/// cleanup operation fails.
pub fn run_supervised_command(
    command: &mut Command,
    input: &[u8],
    timeout: Duration,
) -> std::io::Result<SupervisedOutput> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| std::io::Error::other("process deadline overflowed"))?;
    run_supervised_command_inner(command, input, deadline, None, None, None, None)
}

/// Runs a structured command while preserving one separately bound logical
/// executable alias and revalidating its canonical file identity.
///
/// # Errors
///
/// Returns an error when the bound invocation changes or when supervised
/// execution, capture, or cleanup fails.
pub fn run_supervised_command_with_bound_program(
    command: &mut Command,
    input: &[u8],
    timeout: Duration,
    bound_program: &BoundProgramInvocation,
) -> std::io::Result<SupervisedOutput> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| std::io::Error::other("process deadline overflowed"))?;
    run_supervised_command_inner(
        command,
        input,
        deadline,
        None,
        Some(bound_program),
        None,
        None,
    )
}

/// Runs a structured command under exact absolute execution and completion deadlines.
///
/// # Errors
///
/// Returns an error when launch, capture, termination, or cleanup exceeds the
/// supplied absolute boundaries.
pub fn run_supervised_command_until(
    command: &mut Command,
    input: &[u8],
    execution_deadline: Instant,
    completion_deadline: Instant,
    progress: Option<SupervisedProgressObserver>,
) -> std::io::Result<SupervisedOutput> {
    run_supervised_command_inner(
        command,
        input,
        execution_deadline,
        Some(completion_deadline),
        None,
        None,
        progress,
    )
}

/// Runs a structured command with one already-completed diagnostic receipt.
///
/// This external-verifier seam proves that optional diagnostic availability
/// cannot consume or replace the independently supplied semantic deadlines.
///
/// # Errors
///
/// Returns an error only for semantic launch, capture, termination, or cleanup
/// failure; the diagnostic text is retained as evidence and is never a gate.
#[doc(hidden)]
pub fn run_supervised_command_with_prelaunch_evidence_until(
    command: &mut Command,
    input: &[u8],
    execution_deadline: Instant,
    completion_deadline: Instant,
    prelaunch_evidence: &str,
) -> std::io::Result<SupervisedOutput> {
    run_supervised_command_inner(
        command,
        input,
        execution_deadline,
        Some(completion_deadline),
        None,
        Some(prelaunch_evidence.to_owned()),
        None,
    )
    .map_err(|primary| compose_prelaunch_evidence_error(primary, Some(prelaunch_evidence)))
}

/// Runs a bound structured command under exact absolute execution and cleanup deadlines.
///
/// # Errors
///
/// Returns an error when the bound invocation changes or any supervised phase
/// exceeds the supplied absolute boundaries.
pub fn run_supervised_command_with_bound_program_until(
    command: &mut Command,
    input: &[u8],
    execution_deadline: Instant,
    completion_deadline: Instant,
    bound_program: &BoundProgramInvocation,
    progress: Option<SupervisedProgressObserver>,
) -> std::io::Result<SupervisedOutput> {
    run_supervised_command_inner(
        command,
        input,
        execution_deadline,
        Some(completion_deadline),
        Some(bound_program),
        None,
        progress,
    )
}

fn record_supervised_phase(
    timings: &mut Vec<SupervisedPhaseTiming>,
    started: Instant,
    name: &'static str,
) {
    timings.push(SupervisedPhaseTiming {
        name,
        elapsed: started.elapsed(),
    });
}

fn run_supervised_command_inner(
    command: &mut Command,
    input: &[u8],
    execution_deadline: Instant,
    completion_deadline: Option<Instant>,
    bound_program: Option<&BoundProgramInvocation>,
    prelaunch_evidence: Option<String>,
    progress: Option<SupervisedProgressObserver>,
) -> std::io::Result<SupervisedOutput> {
    let started = Instant::now();
    let mut phase_timings = Vec::with_capacity(12);

    require_before_deadline(execution_deadline, "bound revalidation")?;
    if let Some(identity) = bound_program {
        identity.revalidate(command.get_program())?;
    }
    record_supervised_phase(&mut phase_timings, started, "bound-revalidated");
    let launch_policy = CANDIDATE_LAUNCH_POLICY.with(|slot| slot.borrow().clone());
    if prelaunch_evidence.is_some() {
        record_supervised_phase(&mut phase_timings, started, "prelaunch-evidence-attached");
    }
    require_before_deadline(execution_deadline, "launch policy wrapping")?;
    #[cfg(windows)]
    let windows_launch_control = launch_policy
        .as_ref()
        .map(|policy| policy.wrap_with_control(command, bound_program, execution_deadline))
        .transpose()?;
    #[cfg(not(windows))]
    if let Some(policy) = &launch_policy {
        policy.wrap(command, bound_program)?;
    }
    record_supervised_phase(&mut phase_timings, started, "policy-wrapped");
    let mut quiescence = QuiescenceGuard::new(launch_policy);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let _ = completion_reaper_sender()?;
    require_before_deadline(execution_deadline, "child spawn")?;
    let mut child = SupervisedChild::spawn(command)?;
    record_supervised_phase(&mut phase_timings, started, "child-spawned");

    let cleanup_deadline = completion_deadline.unwrap_or(execution_deadline);
    let io = spawn_supervised_io_with_cleanup(
        &mut child,
        &mut quiescence,
        input,
        progress,
        cleanup_deadline,
    )?;
    let io_receipt = io.receipt.clone();
    record_supervised_phase(&mut phase_timings, started, "deadline-started");
    let wait = wait_supervised_child_until(
        &mut child,
        &mut quiescence,
        execution_deadline,
        cleanup_deadline,
    )
    .map_err(|error| with_supervised_io_receipt(error, &io_receipt))?;
    let (status, timed_out, termination) = finish_supervised_wait(
        &wait,
        &mut child,
        &mut quiescence,
        cleanup_deadline,
        &io_receipt,
        &mut phase_timings,
        started,
    )?;
    require_before_deadline(cleanup_deadline, "process-tree quiescence").map_err(|error| {
        with_quiescence_after_error(error, &mut quiescence, cleanup_deadline, &io_receipt)
    })?;
    let candidate_quiescence_complete = if let Some(policy) = quiescence.policy.take() {
        require_candidate_quiescence(&policy, cleanup_deadline)
            .map_err(|error| with_supervised_io_receipt(error, &io_receipt))?;
        true
    } else {
        false
    };
    record_supervised_phase(&mut phase_timings, started, "quiescence-complete");
    let stdout = join_reader_until(io.stdout, "stdout", completion_deadline)
        .map_err(|error| with_supervised_io_receipt(error, &io_receipt))?;
    record_supervised_phase(&mut phase_timings, started, "stdout-joined");
    let stderr = join_reader_until(io.stderr, "stderr", completion_deadline)
        .map_err(|error| with_supervised_io_receipt(error, &io_receipt))?;
    record_supervised_phase(&mut phase_timings, started, "stderr-joined");
    join_writer_until(io.stdin, completion_deadline)
        .map_err(|error| with_supervised_io_receipt(error, &io_receipt))?;
    record_supervised_phase(&mut phase_timings, started, "stdin-joined");
    #[cfg(windows)]
    let windows_launch_control = windows_launch_control
        .map(|authority| {
            authority.complete(
                status,
                timed_out,
                termination,
                candidate_quiescence_complete,
            )
        })
        .transpose()?;
    Ok(SupervisedOutput {
        status,
        stdout,
        stderr,
        timed_out,
        termination,
        phase_timings,
        prelaunch_evidence,
        candidate_quiescence_complete,
        #[cfg(windows)]
        windows_launch_control,
    })
}

fn finish_supervised_wait(
    wait: &WaitOutcome,
    child: &mut SupervisedChild,
    quiescence: &mut QuiescenceGuard,
    cleanup_deadline: Instant,
    io_receipt: &SupervisedIoReceipt,
    phase_timings: &mut Vec<SupervisedPhaseTiming>,
    started: Instant,
) -> std::io::Result<(std::process::ExitStatus, bool, Option<TerminationReport>)> {
    match wait {
        WaitOutcome::Exited(status) => {
            record_supervised_phase(phase_timings, started, "leader-exited");
            // A leader may exit while descendants retain pipe handles. Close
            // the complete group/job before joining readers, while preserving
            // the leader's status as the observed result.
            let (_, cleanup) = child.terminate_until(cleanup_deadline).map_err(|error| {
                with_quiescence_after_error(error, quiescence, cleanup_deadline, io_receipt)
            })?;
            record_supervised_phase(phase_timings, started, "tree-terminated");
            Ok((*status, false, Some(cleanup)))
        }
        WaitOutcome::DeadlineExpired => {
            record_supervised_phase(phase_timings, started, "deadline-expired");
            let (status, termination) =
                child.terminate_until(cleanup_deadline).map_err(|error| {
                    with_quiescence_after_error(error, quiescence, cleanup_deadline, io_receipt)
                })?;
            record_supervised_phase(phase_timings, started, "tree-terminated");
            if !termination.reaped {
                return Err(std::io::Error::other(
                    "timed-out process tree was not completely reaped",
                ));
            }
            Ok((status, true, Some(termination)))
        }
    }
}

fn spawn_supervised_io_with_cleanup(
    child: &mut SupervisedChild,
    quiescence: &mut QuiescenceGuard,
    input: &[u8],
    progress: Option<SupervisedProgressObserver>,
    cleanup_deadline: Instant,
) -> std::io::Result<SupervisedIoTasks> {
    match spawn_supervised_io_with_probe(child, input, progress, SupervisedIoProbe::None) {
        Ok(io) => Ok(io),
        Err(primary) => {
            let cleanup = cleanup_supervised_child_after_error(child, quiescence, cleanup_deadline);
            Err(compose_supervised_cleanup_error(primary, cleanup))
        }
    }
}

fn wait_supervised_child_until(
    child: &mut SupervisedChild,
    quiescence: &mut QuiescenceGuard,
    execution_deadline: Instant,
    cleanup_deadline: Instant,
) -> std::io::Result<WaitOutcome> {
    match child.wait_until(execution_deadline) {
        Ok(wait) => Ok(wait),
        Err(primary) => {
            let cleanup = cleanup_supervised_child_after_error(child, quiescence, cleanup_deadline);
            Err(compose_supervised_cleanup_error(primary, cleanup))
        }
    }
}

fn cleanup_supervised_child_after_error(
    child: &mut SupervisedChild,
    quiescence: &mut QuiescenceGuard,
    deadline: Instant,
) -> std::io::Result<()> {
    let process = child.terminate_until(deadline).map(|_| ());
    let policy = match quiescence.policy.take() {
        Some(policy) => require_candidate_quiescence(&policy, deadline),
        None => Ok(()),
    };
    match (process, policy) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(process), Ok(())) => Err(process),
        (Ok(()), Err(policy)) => Err(policy),
        (Err(process), Err(policy)) => Err(std::io::Error::new(
            process.kind(),
            CompositeSupervisedCleanupError {
                primary: process,
                cleanup: policy,
            },
        )),
    }
}

fn with_quiescence_after_error(
    primary: std::io::Error,
    quiescence: &mut QuiescenceGuard,
    deadline: Instant,
    io: &SupervisedIoReceipt,
) -> std::io::Error {
    let cleanup = match quiescence.policy.take() {
        Some(policy) => require_candidate_quiescence(&policy, deadline),
        None => Ok(()),
    };
    with_supervised_io_receipt(compose_supervised_cleanup_error(primary, cleanup), io)
}

fn compose_supervised_cleanup_error(
    primary: std::io::Error,
    cleanup: std::io::Result<()>,
) -> std::io::Error {
    match cleanup {
        Ok(()) => primary,
        Err(cleanup) => {
            let kind = primary.kind();
            std::io::Error::new(kind, CompositeSupervisedCleanupError { primary, cleanup })
        }
    }
}

#[derive(Debug)]
struct CompositeSupervisedCleanupError {
    primary: std::io::Error,
    cleanup: std::io::Error,
}

impl std::fmt::Display for CompositeSupervisedCleanupError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}; supervised cleanup also failed: {}",
            self.primary, self.cleanup
        )
    }
}

impl std::error::Error for CompositeSupervisedCleanupError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CandidateQuiescenceState {
    Owned,
    Completed,
    Failed(String),
}

#[derive(Clone, Debug)]
pub struct CandidateQuiescenceReceipt {
    state: Arc<Mutex<CandidateQuiescenceState>>,
}

impl CandidateQuiescenceReceipt {
    fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(CandidateQuiescenceState::Owned)),
        }
    }

    fn finish(&self, state: CandidateQuiescenceState) {
        *self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = state;
    }

    #[must_use]
    pub fn state(&self) -> CandidateQuiescenceState {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

#[derive(Debug)]
struct CandidateQuiescenceError {
    primary: std::io::Error,
    receipt: CandidateQuiescenceReceipt,
}

impl std::fmt::Display for CandidateQuiescenceError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.primary.fmt(formatter)
    }
}

impl std::error::Error for CandidateQuiescenceError {}

fn require_candidate_quiescence(
    policy: &CandidateLaunchPolicy,
    deadline: Instant,
) -> std::io::Result<()> {
    let receipt = CandidateQuiescenceReceipt::new();
    match policy.require_quiescence(deadline) {
        Ok(()) => {
            receipt.finish(CandidateQuiescenceState::Completed);
            Ok(())
        }
        Err(primary) => {
            receipt.finish(CandidateQuiescenceState::Failed(primary.to_string()));
            let kind = primary.kind();
            Err(std::io::Error::new(
                kind,
                CandidateQuiescenceError { primary, receipt },
            ))
        }
    }
}

#[derive(Debug)]
struct SupervisedLifecycleError {
    primary: std::io::Error,
    process: Option<RetainedTerminationReceipt>,
    io: SupervisedIoReceipt,
}

impl std::fmt::Display for SupervisedLifecycleError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.primary.fmt(formatter)
    }
}

impl std::error::Error for SupervisedLifecycleError {}

fn with_supervised_io_receipt(primary: std::io::Error, io: &SupervisedIoReceipt) -> std::io::Error {
    let kind = primary.kind();
    let process = retained_termination_receipt_inner(&primary);
    std::io::Error::new(
        kind,
        SupervisedLifecycleError {
            primary,
            process,
            io: io.clone(),
        },
    )
}

fn retained_termination_receipt_inner(
    error: &std::io::Error,
) -> Option<RetainedTerminationReceipt> {
    if let Some(receipt) = hell_platform::retained_termination_receipt(error) {
        return Some(receipt);
    }
    let source = error.get_ref()?;
    if let Some(lifecycle) = source.downcast_ref::<SupervisedLifecycleError>() {
        return lifecycle
            .process
            .clone()
            .or_else(|| retained_termination_receipt_inner(&lifecycle.primary));
    }
    if let Some(evidence) = source.downcast_ref::<PrelaunchEvidenceError>() {
        return retained_termination_receipt_inner(&evidence.primary);
    }
    if let Some(quiescence) = source.downcast_ref::<CandidateQuiescenceError>() {
        return retained_termination_receipt_inner(&quiescence.primary);
    }
    source
        .downcast_ref::<CompositeSupervisedCleanupError>()
        .and_then(|composite| {
            retained_termination_receipt_inner(&composite.cleanup)
                .or_else(|| retained_termination_receipt_inner(&composite.primary))
        })
}

/// Extracts typed retained process cleanup ownership through composed supervision errors.
#[must_use]
pub fn retained_termination_receipt(error: &std::io::Error) -> Option<RetainedTerminationReceipt> {
    retained_termination_receipt_inner(error)
}

/// Extracts the durable stdout/stderr/stdin terminal receipt from a supervision error.
#[must_use]
pub fn supervised_io_receipt(error: &std::io::Error) -> Option<SupervisedIoReceipt> {
    let source = error.get_ref()?;
    if let Some(lifecycle) = source.downcast_ref::<SupervisedLifecycleError>() {
        return Some(lifecycle.io.clone());
    }
    if let Some(evidence) = source.downcast_ref::<PrelaunchEvidenceError>() {
        return supervised_io_receipt(&evidence.primary);
    }
    if let Some(quiescence) = source.downcast_ref::<CandidateQuiescenceError>() {
        return supervised_io_receipt(&quiescence.primary);
    }
    source
        .downcast_ref::<CompositeSupervisedCleanupError>()
        .and_then(|composite| {
            supervised_io_receipt(&composite.cleanup)
                .or_else(|| supervised_io_receipt(&composite.primary))
        })
}

/// Extracts the exact terminal candidate-quiescence receipt from a supervision error.
#[must_use]
pub fn candidate_quiescence_receipt(error: &std::io::Error) -> Option<CandidateQuiescenceReceipt> {
    let source = error.get_ref()?;
    if let Some(quiescence) = source.downcast_ref::<CandidateQuiescenceError>() {
        return Some(quiescence.receipt.clone());
    }
    if let Some(lifecycle) = source.downcast_ref::<SupervisedLifecycleError>() {
        return candidate_quiescence_receipt(&lifecycle.primary);
    }
    if let Some(evidence) = source.downcast_ref::<PrelaunchEvidenceError>() {
        return candidate_quiescence_receipt(&evidence.primary);
    }
    source
        .downcast_ref::<CompositeSupervisedCleanupError>()
        .and_then(|composite| {
            candidate_quiescence_receipt(&composite.cleanup)
                .or_else(|| candidate_quiescence_receipt(&composite.primary))
        })
}

struct SupervisedIoTasks {
    stdout: CompletionTask<std::io::Result<BoundedCapture>>,
    stderr: CompletionTask<std::io::Result<BoundedCapture>>,
    stdin: CompletionTask<std::io::Result<()>>,
    receipt: SupervisedIoReceipt,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SupervisedIoProbe {
    None,
    FailStderrLaunch,
    FailStdinLaunch,
    PanicStdout,
}

fn spawn_supervised_io_with_probe(
    child: &mut SupervisedChild,
    input: &[u8],
    progress: Option<SupervisedProgressObserver>,
    probe: SupervisedIoProbe,
) -> std::io::Result<SupervisedIoTasks> {
    let cleanup = child.cleanup_lease()?;
    let receipt = SupervisedIoReceipt::new();
    let stdout = child.take_stdout().ok_or_else(|| {
        receipt.set_state(
            Some(SupervisedOutputStream::Stdout),
            SupervisedIoTaskState::LaunchFailed,
        );
        receipt.abort_not_started();
        with_supervised_io_receipt(
            std::io::Error::other("piped child stdout was unavailable"),
            &receipt,
        )
    })?;
    let stderr = child.take_stderr().ok_or_else(|| {
        receipt.set_state(
            Some(SupervisedOutputStream::Stderr),
            SupervisedIoTaskState::LaunchFailed,
        );
        receipt.abort_not_started();
        with_supervised_io_receipt(
            std::io::Error::other("piped child stderr was unavailable"),
            &receipt,
        )
    })?;
    let stdout = spawn_supervised_reader(
        "hell-supervised-stdout",
        stdout,
        SupervisedOutputStream::Stdout,
        cleanup.clone(),
        progress.clone(),
        &receipt,
        probe == SupervisedIoProbe::PanicStdout,
    )?;
    if probe == SupervisedIoProbe::FailStderrLaunch {
        receipt.set_state(
            Some(SupervisedOutputStream::Stderr),
            SupervisedIoTaskState::LaunchFailed,
        );
        receipt.abort_not_started();
        return Err(with_supervised_io_receipt(
            std::io::Error::other("injected supervised stderr worker launch failure"),
            &receipt,
        ));
    }
    let stderr = spawn_supervised_reader(
        "hell-supervised-stderr",
        stderr,
        SupervisedOutputStream::Stderr,
        cleanup.clone(),
        progress,
        &receipt,
        false,
    )?;
    if probe == SupervisedIoProbe::FailStdinLaunch {
        receipt.set_state(None, SupervisedIoTaskState::LaunchFailed);
        receipt.abort_not_started();
        return Err(with_supervised_io_receipt(
            std::io::Error::other("injected supervised stdin worker launch failure"),
            &receipt,
        ));
    }
    let stdin = spawn_supervised_writer(child.take_stdin(), input, cleanup, &receipt)?;
    Ok(SupervisedIoTasks {
        stdout,
        stderr,
        stdin,
        receipt,
    })
}

fn spawn_supervised_reader<R: Read + Send + 'static>(
    name: &str,
    reader: R,
    stream: SupervisedOutputStream,
    cleanup: CleanupLease,
    progress: Option<SupervisedProgressObserver>,
    receipt: &SupervisedIoReceipt,
    panic_before_read: bool,
) -> std::io::Result<CompletionTask<std::io::Result<BoundedCapture>>> {
    let task_receipt = receipt.clone();
    receipt.set_state(Some(stream), SupervisedIoTaskState::Owned);
    CompletionTask::spawn(name, cleanup, move || {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert!(!panic_before_read, "injected supervised reader panic");
            read_bounded_with_progress(reader, stream, progress.as_ref())
        })) {
            Ok(result) => {
                task_receipt.finish_capture(stream, &result);
                result
            }
            Err(panic) => {
                task_receipt.mark_panicked(Some(stream));
                std::panic::resume_unwind(panic)
            }
        }
    })
    .map_err(|error| {
        receipt.set_state(Some(stream), SupervisedIoTaskState::LaunchFailed);
        receipt.abort_not_started();
        with_supervised_io_receipt(error, receipt)
    })
}

fn spawn_supervised_writer(
    stdin: Option<ChildStdin>,
    input: &[u8],
    cleanup: CleanupLease,
    receipt: &SupervisedIoReceipt,
) -> std::io::Result<CompletionTask<std::io::Result<()>>> {
    let input = input.to_vec();
    let task_receipt = receipt.clone();
    receipt.set_state(None, SupervisedIoTaskState::Owned);
    CompletionTask::spawn("hell-supervised-stdin", cleanup, move || {
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            write_supervised_input(stdin, &input)
        }));
        match outcome {
            Ok(result) => {
                task_receipt.finish_stdin(&result);
                result
            }
            Err(panic) => {
                task_receipt.mark_panicked(None);
                std::panic::resume_unwind(panic)
            }
        }
    })
    .map_err(|error| {
        receipt.set_state(None, SupervisedIoTaskState::LaunchFailed);
        receipt.abort_not_started();
        with_supervised_io_receipt(error, receipt)
    })
}

fn write_supervised_input(mut stdin: Option<ChildStdin>, input: &[u8]) -> std::io::Result<()> {
    let Some(stdin) = stdin.as_mut() else {
        return Ok(());
    };
    match stdin.write_all(input) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        Err(error) => Err(error),
    }
}

/// Verifies deterministic bounded progress-loss accounting through an external test seam.
///
/// # Errors
///
/// Returns an error when the retained chunk or exact loss receipt differs.
#[doc(hidden)]
pub fn verify_supervised_progress_loss_for_integration() -> Result<(), String> {
    let (progress, receiver) = SupervisedProgressObserver::bounded(1);
    progress.observe(SupervisedOutputStream::Stdout, b"first");
    progress.observe(SupervisedOutputStream::Stderr, b"second");
    let retained = receiver
        .try_recv()
        .map_err(|error| format!("bounded progress queue lost retained chunk: {error}"))?;
    if retained.stream != SupervisedOutputStream::Stdout
        || retained.bytes != b"first"
        || progress.loss()
            != (SupervisedProgressLoss {
                chunks: 1,
                bytes: 6,
            })
    {
        return Err("bounded progress queue loss accounting drifted".to_owned());
    }
    Ok(())
}

/// Verifies bounded supervised-process diagnostics through an external test seam.
///
/// # Errors
///
/// Returns an error when escaping, truncation, status, or phase-order evidence drifts.
#[doc(hidden)]
pub fn verify_supervised_diagnostics_for_integration() -> Result<(), String> {
    let mut bytes = vec![b'x'; PROBE_DIAGNOSTIC_EDGE_BYTES * 3];
    bytes.extend_from_slice(b"\n\x1b[31mchild-control\r\n");
    let diagnostic = bounded_probe_capture_diagnostic(&BoundedCapture::from_bytes(bytes));
    if !diagnostic.contains("bytes=")
        || !diagnostic.contains("sha256=")
        || !diagnostic.contains("<TRUNCATED>")
        || diagnostic.contains('\n')
        || diagnostic.len() >= PROBE_DIAGNOSTIC_EDGE_BYTES * 5
        || supervised_status_diagnostic(Some(-1_073_740_791)) != "-1073740791 (0xc0000409)"
        || supervised_status_diagnostic(None) != "none"
    {
        return Err("bounded supervised capture diagnostic drifted".to_owned());
    }
    let phases = [
        SupervisedPhaseTiming {
            name: "prelaunch-evidence-attached",
            elapsed: Duration::from_millis(2),
        },
        SupervisedPhaseTiming {
            name: "deadline-started",
            elapsed: Duration::from_millis(9),
        },
    ];
    if supervised_phase_diagnostic(&phases)
        != "prelaunch-evidence-attached=2ms,deadline-started=9ms"
    {
        return Err("supervised phase diagnostic lost typed order or elapsed time".to_owned());
    }
    verify_supervised_progress_loss_for_integration()?;
    #[cfg(unix)]
    verify_supervised_io_failure_receipts_for_integration()?;
    Ok(())
}

#[cfg(unix)]
fn verify_supervised_io_failure_receipts_for_integration() -> Result<(), String> {
    for (probe, expected_stderr, expected_stdin) in [
        (
            SupervisedIoProbe::FailStderrLaunch,
            SupervisedIoTaskState::LaunchFailed,
            SupervisedIoTaskState::AbortedBeforeLaunch,
        ),
        (
            SupervisedIoProbe::FailStdinLaunch,
            SupervisedIoTaskState::Completed,
            SupervisedIoTaskState::LaunchFailed,
        ),
    ] {
        let mut command = Command::new("/usr/bin/true");
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = SupervisedChild::spawn(&mut command)
            .map_err(|error| format!("cannot spawn supervised I/O launch fixture: {error}"))?;
        let Err(error) = spawn_supervised_io_with_probe(&mut child, &[], None, probe) else {
            return Err("injected supervised I/O launch unexpectedly succeeded".to_owned());
        };
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(5))
            .ok_or_else(|| "supervised I/O launch fixture deadline overflowed".to_owned())?;
        child
            .terminate_until(deadline)
            .map_err(|error| format!("cannot terminate supervised I/O launch fixture: {error}"))?;
        let receipt = supervised_io_receipt(&error)
            .ok_or_else(|| "supervised I/O launch failure lost its typed receipt".to_owned())?;
        let snapshot = receipt.wait_until(deadline);
        if snapshot.stdout.state != SupervisedIoTaskState::Completed
            || snapshot.stderr.state != expected_stderr
            || snapshot.stdin.state != expected_stdin
        {
            return Err("partial supervised I/O launch lost its exact terminal states".to_owned());
        }
    }

    let mut command = Command::new("/usr/bin/true");
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = SupervisedChild::spawn(&mut command)
        .map_err(|error| format!("cannot spawn supervised I/O panic fixture: {error}"))?;
    let tasks =
        spawn_supervised_io_with_probe(&mut child, &[], None, SupervisedIoProbe::PanicStdout)
            .map_err(|error| format!("cannot launch supervised I/O panic fixture: {error}"))?;
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(5))
        .ok_or_else(|| "supervised I/O panic fixture deadline overflowed".to_owned())?;
    child
        .terminate_until(deadline)
        .map_err(|error| format!("cannot terminate supervised I/O panic fixture: {error}"))?;
    let stdout = join_reader_until(tasks.stdout, "stdout", Some(deadline));
    let _ = join_reader_until(tasks.stderr, "stderr", Some(deadline));
    let _ = join_writer_until(tasks.stdin, Some(deadline));
    let snapshot = tasks.receipt.wait_until(deadline);
    if stdout.is_ok()
        || snapshot.stdout.state != SupervisedIoTaskState::Panicked
        || snapshot.stderr.state != SupervisedIoTaskState::Completed
        || snapshot.stdin.state != SupervisedIoTaskState::Completed
    {
        return Err("supervised I/O worker panic lost its typed terminal receipt".to_owned());
    }
    Ok(())
}

#[derive(Clone, Copy, Default)]
struct CaptureEvidence<'a> {
    resource_audit_path: Option<&'a Path>,
    semantic_trace_path: Option<&'a Path>,
    nonclaim_target: Option<BuiltinId>,
}

fn capture_process(
    executable: &Path,
    role: ExecutableRole,
    script: &Path,
    working_directory: &Path,
    case: &DifferentialCase,
    profile: ExecutionProfile,
    evidence: CaptureEvidence<'_>,
) -> std::io::Result<CapturedProcess> {
    let mut command = Command::new(executable);
    if let Some(path) = evidence.resource_audit_path {
        command.arg("--evidence-resource-audit").arg(path);
    }
    if let Some(path) = evidence.semantic_trace_path {
        command.arg("--evidence-semantic-trace").arg(path);
        if let Some(selection) = evidence
            .nonclaim_target
            .map(|builtin| TypedResultTarget {
                builtin,
                instance: None,
            })
            .or(typed_result_target(case)?)
        {
            let target = hell_builtins::registry()
                .get(usize::from(selection.builtin.0))
                .ok_or_else(|| std::io::Error::other("typed result target disappeared"))?;
            command
                .arg("--evidence-typed-result-builtin")
                .arg(target.name);
            if let Some(instance) = selection.instance {
                command
                    .arg("--evidence-typed-result-instance")
                    .arg(instance.as_ref());
            }
        }
    }
    configure_execution_profile(&mut command, role, profile);
    match case.mode {
        DifferentialMode::Check => {
            command.arg("--check").arg(script);
        }
        DifferentialMode::Run => {
            command.arg(script).args(&case.arguments);
        }
    }
    command.env_clear();
    match case.environment_profile {
        EnvironmentProfile::Minimal => {}
        EnvironmentProfile::ProcessCapable => {
            let helper_directory = case.process_helper_directory.as_ref().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "ProcessCapable requires process_helper_directory",
                )
            })?;
            if !helper_directory.is_absolute() || !helper_directory.is_dir() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "ProcessCapable helper directory must be an existing absolute directory",
                ));
            }
            let path = std::env::join_paths([helper_directory])
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
            command.env("PATH", path);
        }
        EnvironmentProfile::NativePlatform => {
            command.envs(std::env::vars_os());
            scrub_ci_authority_environment(&mut command);
            configure_evidence_native_environment(&mut command, working_directory)?;
        }
        EnvironmentProfile::Explicit => {
            command.envs(case.environment.iter().cloned());
        }
    }
    command.current_dir(working_directory);
    let started = Instant::now();
    let captured = run_supervised_command(&mut command, &case.stdin, case.timeout)?;
    let duration = started.elapsed();
    Ok(CapturedProcess {
        status: captured.status,
        stdout: captured.stdout,
        stderr: captured.stderr,
        timed_out: captured.timed_out,
        duration,
    })
}

fn configure_execution_profile(
    command: &mut Command,
    role: ExecutableRole,
    profile: ExecutionProfile,
) {
    if role == ExecutableRole::Candidate {
        command.arg("--execution-profile").arg(profile.as_str());
    }
}

fn scrub_ci_authority_environment(command: &mut Command) {
    configure_release_child_environment(command);
}

fn configure_evidence_native_environment(
    command: &mut Command,
    working_directory: &Path,
) -> std::io::Result<()> {
    for (name, relative) in [
        ("HOME", ".evidence-home"),
        ("USERPROFILE", ".evidence-home"),
        ("APPDATA", ".evidence-home/appdata"),
        ("LOCALAPPDATA", ".evidence-home/local-appdata"),
        ("CARGO_HOME", ".evidence-cache/cargo"),
        ("RUSTUP_HOME", ".evidence-cache/rustup"),
        ("SCCACHE_DIR", ".evidence-cache/sccache"),
        ("TEMP", ".evidence-tmp"),
        ("TMP", ".evidence-tmp"),
        ("TMPDIR", ".evidence-tmp"),
    ] {
        let path = working_directory.join(relative);
        fs::create_dir_all(&path)?;
        CANDIDATE_LAUNCH_POLICY.with(|slot| {
            slot.borrow()
                .as_ref()
                .map_or(Ok(()), |policy| policy.prepare_writable_directory(&path))
        })?;
        command.env(name, path);
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TypedResultTarget {
    builtin: BuiltinId,
    instance: Option<Arc<str>>,
}

fn typed_result_target(case: &DifferentialCase) -> std::io::Result<Option<TypedResultTarget>> {
    let targets = case
        .claim_evidence
        .iter()
        .flat_map(|descriptor| &descriptor.semantic_targets)
        .filter(|target| {
            target.expected_typed_result_sha256.is_some()
                || target
                    .obligations
                    .iter()
                    .any(|obligation| obligation.0.as_ref() == "typed-result")
        })
        .map(|target| {
            hell_builtins::lookup(&target.builtin)
                .map(|spec| TypedResultTarget {
                    builtin: spec.id,
                    instance: target.expected_instance_target.clone(),
                })
                .ok_or_else(|| std::io::Error::other("typed-result target is not registry-backed"))
        })
        .collect::<std::io::Result<Vec<_>>>()?;
    let Some(first) = targets.first().cloned() else {
        return Ok(None);
    };
    if targets.iter().all(|target| *target == first) {
        Ok(Some(first))
    } else {
        Err(std::io::Error::other(
            "one evidence case cannot retain multiple typed-result targets",
        ))
    }
}

fn read_bounded(mut reader: impl Read) -> std::io::Result<BoundedCapture> {
    read_bounded_with_progress(&mut reader, SupervisedOutputStream::Stdout, None)
}

fn read_bounded_with_progress(
    mut reader: impl Read,
    stream: SupervisedOutputStream,
    progress: Option<&SupervisedProgressObserver>,
) -> std::io::Result<BoundedCapture> {
    let mut digest = Sha256::new();
    let mut complete = Vec::new();
    let mut prefix = Vec::with_capacity(CAPTURE_EDGE_BYTES);
    let mut suffix = VecDeque::with_capacity(CAPTURE_EDGE_BYTES);
    let mut total_bytes = 0_u64;
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let bytes = &buffer[..read];
        if let Some(progress) = progress {
            progress.observe(stream, bytes);
        }
        digest.update(bytes);
        total_bytes = total_bytes
            .checked_add(u64::try_from(read).unwrap_or(u64::MAX))
            .ok_or_else(|| std::io::Error::other("captured byte count overflowed"))?;
        if complete.len() <= COMPLETE_CAPTURE_BYTES.saturating_sub(read) {
            complete.extend_from_slice(bytes);
        } else {
            complete.clear();
        }
        let prefix_remaining = CAPTURE_EDGE_BYTES.saturating_sub(prefix.len());
        prefix.extend_from_slice(&bytes[..bytes.len().min(prefix_remaining)]);
        suffix.extend(bytes.iter().copied());
        while suffix.len() > CAPTURE_EDGE_BYTES {
            suffix.pop_front();
        }
    }
    let truncated = total_bytes > u64::try_from(COMPLETE_CAPTURE_BYTES).unwrap_or(u64::MAX);
    Ok(BoundedCapture {
        total_bytes,
        sha256: digest.finish(),
        prefix,
        suffix: suffix.into(),
        complete: (!truncated).then_some(complete),
        truncated,
    })
}

struct CompletionTask<T: Send + 'static> {
    completion: mpsc::Receiver<()>,
    handle: Option<std::thread::JoinHandle<T>>,
}

impl<T: Send + 'static> CompletionTask<T> {
    fn spawn(
        name: &str,
        cleanup: CleanupLease,
        operation: impl FnOnce() -> T + Send + 'static,
    ) -> std::io::Result<Self> {
        let (sender, completion) = mpsc::sync_channel(1);
        let handle = std::thread::Builder::new()
            .name(name.to_owned())
            .spawn(move || {
                let _cleanup = cleanup;
                let result = operation();
                let _ = sender.send(());
                result
            })?;
        Ok(Self {
            completion,
            handle: Some(handle),
        })
    }

    fn join_until(mut self, deadline: Option<Instant>, phase: &str) -> std::io::Result<T> {
        let timed_out = deadline.is_some_and(|deadline| {
            let remaining = deadline.saturating_duration_since(Instant::now());
            remaining.is_zero()
                || matches!(
                    self.completion.recv_timeout(remaining),
                    Err(mpsc::RecvTimeoutError::Timeout)
                )
        });
        if timed_out {
            retain_late_completion(
                self.handle
                    .take()
                    .unwrap_or_else(|| panic!("supervised completion handle was already consumed")),
            );
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("supervised {phase} exceeded its absolute deadline"),
            ));
        }
        self.handle
            .take()
            .unwrap_or_else(|| panic!("supervised completion handle was already consumed"))
            .join()
            .map_err(|_| std::io::Error::other(format!("{phase} thread panicked")))
    }
}

impl<T: Send + 'static> Drop for CompletionTask<T> {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            retain_late_completion(handle);
        }
    }
}

type LateCompletion = Box<dyn FnOnce() + Send>;

fn completion_reaper_sender() -> std::io::Result<&'static mpsc::Sender<LateCompletion>> {
    static REAPER: OnceLock<Result<mpsc::Sender<LateCompletion>, String>> = OnceLock::new();
    match REAPER.get_or_init(|| {
        let (sender, receiver) = mpsc::channel::<LateCompletion>();
        std::thread::Builder::new()
            .name("hell-supervised-completion-reaper".to_owned())
            .spawn(move || {
                while let Ok(completion) = receiver.recv() {
                    completion();
                }
            })
            .map_err(|error| format!("cannot start supervised completion reaper: {error}"))?;
        Ok(sender)
    }) {
        Ok(sender) => Ok(sender),
        Err(error) => Err(std::io::Error::other(error.clone())),
    }
}

fn retain_late_completion<T: Send + 'static>(handle: std::thread::JoinHandle<T>) {
    let completion: LateCompletion = Box::new(move || {
        let _ = handle.join();
    });
    if let Ok(reaper) = completion_reaper_sender()
        && let Err(disconnected) = reaper.send(completion)
    {
        // The executor thread has no panic path and its sender is retained for
        // process lifetime. If the runtime is already tearing down, the I/O
        // task itself still owns the lifecycle lease until it exits.
        std::mem::forget(disconnected.0);
    }
}

fn require_before_deadline(deadline: Instant, phase: &str) -> std::io::Result<()> {
    if Instant::now() < deadline {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("supervised {phase} exceeded its absolute deadline"),
        ))
    }
}

fn join_reader_until(
    reader: CompletionTask<std::io::Result<BoundedCapture>>,
    stream: &str,
    deadline: Option<Instant>,
) -> std::io::Result<BoundedCapture> {
    reader.join_until(deadline, stream)?
}

fn join_writer_until(
    writer: CompletionTask<std::io::Result<()>>,
    deadline: Option<Instant>,
) -> std::io::Result<()> {
    match writer.join_until(deadline, "stdin writer")? {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        Err(error) => Err(error),
    }
}

fn snapshot_filesystem(root: &Path) -> std::io::Result<Vec<FilesystemEntry>> {
    let mut pending = vec![root.to_path_buf()];
    let mut entries = Vec::new();
    let mut hashed_bytes = 0_u64;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)? {
            if entries.len() >= FILESYSTEM_ENTRY_LIMIT {
                return Err(std::io::Error::other(
                    "filesystem observation exceeded its entry limit",
                ));
            }
            let entry = entry?;
            let path = entry.path();
            let relative_path = path
                .strip_prefix(root)
                .map_err(std::io::Error::other)?
                .to_path_buf();
            let metadata = fs::symlink_metadata(&path)?;
            let file_type = metadata.file_type();
            if file_type.is_dir() {
                pending.push(path);
                entries.push(FilesystemEntry {
                    relative_path,
                    kind: FilesystemEntryKind::Directory,
                    contents: Vec::new(),
                    size: 0,
                    sha256: None,
                    truncated: false,
                });
            } else if file_type.is_symlink() {
                let target = fs::read_link(path)?
                    .to_string_lossy()
                    .into_owned()
                    .into_bytes();
                entries.push(FilesystemEntry {
                    relative_path,
                    kind: FilesystemEntryKind::SymbolicLink,
                    size: u64::try_from(target.len()).unwrap_or(u64::MAX),
                    contents: target,
                    sha256: None,
                    truncated: false,
                });
            } else if file_type.is_file() {
                let size = metadata.len();
                hashed_bytes = hashed_bytes.checked_add(size).ok_or_else(|| {
                    std::io::Error::other("filesystem hashed-byte count overflowed")
                })?;
                if hashed_bytes > FILESYSTEM_HASH_BYTES {
                    return Err(std::io::Error::other(
                        "filesystem observation exceeded its hashed-byte limit",
                    ));
                }
                let capture = read_bounded(fs::File::open(path)?)?;
                entries.push(FilesystemEntry {
                    relative_path,
                    kind: FilesystemEntryKind::File,
                    contents: capture.complete.as_ref().map_or_else(
                        || capture.prefix.clone(),
                        |bytes| bytes[..bytes.len().min(FILE_INLINE_BYTES)].to_vec(),
                    ),
                    size,
                    sha256: Some(capture.sha256),
                    truncated: size > u64::try_from(FILE_INLINE_BYTES).unwrap_or(u64::MAX),
                });
            } else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "filesystem observation contains a special entry",
                ));
            }
        }
    }
    entries.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    Ok(entries)
}

fn replace_all(input: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    if from.is_empty() {
        return input.to_vec();
    }
    let mut output = Vec::with_capacity(input.len());
    let mut offset = 0;
    while let Some(relative) = input[offset..]
        .windows(from.len())
        .position(|window| window == from)
    {
        let found = offset + relative;
        output.extend_from_slice(&input[offset..found]);
        output.extend_from_slice(to);
        offset = found + from.len();
    }
    output.extend_from_slice(&input[offset..]);
    output
}

struct Sandbox {
    path: PathBuf,
}

impl Sandbox {
    fn new(label: &str, sequence: Option<u64>) -> std::io::Result<Self> {
        let sequence = sequence.unwrap_or_else(|| NEXT_SANDBOX.fetch_add(1, Ordering::Relaxed));
        let sandbox_root = CANDIDATE_LAUNCH_POLICY.with(|slot| {
            slot.borrow()
                .as_ref()
                .and_then(|policy| policy.writable_roots.first().cloned())
                .map(|root| root.join("release-child-environment/tmp"))
        });
        let path = sandbox_root
            .unwrap_or_else(std::env::temp_dir)
            .join(format!(
                "hell-rs-differential-{}-{sequence}-{label}",
                std::process::id()
            ));
        fs::create_dir(&path)?;
        CANDIDATE_LAUNCH_POLICY.with(|slot| {
            slot.borrow()
                .as_ref()
                .map_or(Ok(()), |policy| policy.prepare_writable_directory(&path))
        })?;
        Ok(Self { path })
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// A reproducible bounded byte corpus for parser/compiler fuzz smoke tests.
#[derive(Clone, Debug)]
pub struct DeterministicBytes {
    state: u64,
    remaining: usize,
    max_len: usize,
}

impl DeterministicBytes {
    #[must_use]
    pub fn new(seed: u64, cases: usize, max_len: usize) -> Self {
        Self {
            state: seed.max(1),
            remaining: cases,
            max_len,
        }
    }

    fn next_word(&mut self) -> u64 {
        self.state ^= self.state << 13;
        self.state ^= self.state >> 7;
        self.state ^= self.state << 17;
        self.state
    }
}

impl Iterator for DeterministicBytes {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        let length = if self.max_len == 0 {
            0
        } else {
            let maximum = u64::try_from(self.max_len).unwrap_or(u64::MAX);
            let length = if maximum == u64::MAX {
                self.next_word()
            } else {
                self.next_word() % (maximum + 1)
            };
            usize::try_from(length).expect("bounded corpus length fits usize")
        };
        Some(
            (0..length)
                .map(|_| self.next_word().to_le_bytes()[0])
                .collect(),
        )
    }
}

/// A reproducible bounded valid-UTF-8 corpus derived from deterministic bytes.
#[derive(Clone, Debug)]
pub struct DeterministicUtf8 {
    bytes: DeterministicBytes,
    max_bytes: usize,
}

impl DeterministicUtf8 {
    #[must_use]
    pub fn new(seed: u64, cases: usize, max_bytes: usize) -> Self {
        Self {
            bytes: DeterministicBytes::new(seed, cases, max_bytes),
            max_bytes,
        }
    }
}

impl Iterator for DeterministicUtf8 {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        self.bytes.next().map(|bytes| {
            let mut text = String::from_utf8_lossy(&bytes).into_owned();
            if text.len() > self.max_bytes {
                let mut boundary = self.max_bytes;
                while !text.is_char_boundary(boundary) {
                    boundary -= 1;
                }
                text.truncate(boundary);
            }
            text
        })
    }
}

#[cfg(test)]
mod authority_environment_tests {
    #[cfg(unix)]
    use super::configure_release_child_environment;
    use super::{
        Command, WINDOWS_ARGV_TOKEN_LIMIT, WINDOWS_ARGV_TOKEN_PREFIX,
        configure_evidence_native_environment, decode_windows_argv_units,
        encode_windows_argv_units, windows_program_requires_trusted_path,
    };
    use std::ffi::OsStr;
    use std::path::Path;

    #[test]
    fn windows_adapter_token_round_trips_adversarial_argv() {
        let arguments = vec![
            Vec::new(),
            "space and \"quotes\" and \\slashes\\"
                .encode_utf16()
                .collect(),
            vec![u16::MAX, 0xd800, 0xdfff],
        ];
        let token = encode_windows_argv_units(&arguments).unwrap();
        assert!(!token.chars().any(char::is_whitespace));
        assert_eq!(decode_windows_argv_units(&token).unwrap(), arguments);
    }

    #[test]
    fn windows_stack_and_mapped_toolchains_require_the_closed_trusted_path() {
        assert!(windows_program_requires_trusted_path(
            OsStr::new("stack.exe"),
            Path::new(r"C:\tools\stack.exe"),
            false,
        ));
        assert!(windows_program_requires_trusted_path(
            OsStr::new("cargo.exe"),
            Path::new(r"C:\tools\cargo.exe"),
            true,
        ));
        assert!(!windows_program_requires_trusted_path(
            OsStr::new("git.exe"),
            Path::new(r"C:\tools\git.exe"),
            false,
        ));
    }

    #[test]
    fn windows_adapter_token_rejects_malformed_units() {
        assert!(decode_windows_argv_units("hell-argv-v1|not-a-unit").is_err());
        assert!(decode_windows_argv_units("hell-argv-v1|0").is_err());
        assert!(decode_windows_argv_units("unknown|1").is_err());
    }

    #[test]
    fn windows_adapter_token_enforces_create_process_bound() {
        let launchable_units = (WINDOWS_ARGV_TOKEN_LIMIT - WINDOWS_ARGV_TOKEN_PREFIX.len()) / 2;
        let launchable = encode_windows_argv_units(&[vec![1; launchable_units]]).unwrap();
        assert!(launchable.len() <= WINDOWS_ARGV_TOKEN_LIMIT);
        assert!(encode_windows_argv_units(&[vec![1; launchable_units + 1]]).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn candidate_authority_environment_is_absent_in_actual_child() {
        let mut command = Command::new("env");
        command.env("GITHUB_TOKEN", "secret");
        command.env("ACTIONS_RUNTIME_TOKEN", "secret");
        command.env("GITHUB_OUTPUT", "secret");
        configure_release_child_environment(&mut command);
        let output = command.output().expect("spawn environment probe");
        assert!(output.status.success());
        let visible = String::from_utf8(output.stdout).expect("environment is UTF-8");
        assert!(!visible.contains("GITHUB_TOKEN="));
        assert!(!visible.contains("ACTIONS_RUNTIME_TOKEN="));
        assert!(!visible.contains("GITHUB_OUTPUT="));
    }

    #[test]
    fn native_evidence_home_cache_and_temp_are_per_case() {
        let root = std::env::temp_dir().join(format!(
            "hell-testkit-native-evidence-env-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        let mut command = Command::new("unused");
        configure_evidence_native_environment(&mut command, &root).unwrap();
        let environment = command
            .get_envs()
            .filter_map(|(name, value)| value.map(|value| (name.to_owned(), value.to_owned())))
            .collect::<std::collections::BTreeMap<_, _>>();
        for name in [
            "HOME",
            "USERPROFILE",
            "CARGO_HOME",
            "RUSTUP_HOME",
            "SCCACHE_DIR",
            "TEMP",
            "TMP",
            "TMPDIR",
        ] {
            assert!(
                std::path::Path::new(&environment[std::ffi::OsStr::new(name)]).starts_with(&root)
            );
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(test)]
mod diagnostic_tests {
    use super::{
        DiagnosticCategory, DiagnosticObservation, DiagnosticPhase, NormalizerId,
        RetainedNormalizerInput, apply_retained_normalizer_twice, configure_execution_profile,
        diagnostic_path_separator_v1, parse_diagnostic_observation, replay_conformance_stderr,
        scrub_diagnostic_path_bytes,
    };
    use crate::{DifferentialCase, ExecutableRole, ExecutionProfile};
    use std::path::Path;
    use std::process::Command;

    #[test]
    fn execution_profile_is_candidate_only() {
        let mut oracle = Command::new("oracle");
        configure_execution_profile(
            &mut oracle,
            ExecutableRole::Oracle,
            ExecutionProfile::Upstream,
        );
        assert!(oracle.get_args().next().is_none());

        let mut candidate = Command::new("candidate");
        configure_execution_profile(
            &mut candidate,
            ExecutableRole::Candidate,
            ExecutionProfile::Upstream,
        );
        assert_eq!(
            candidate.get_args().collect::<Vec<_>>(),
            ["--execution-profile", "upstream"]
        );
    }

    #[test]
    fn diagnostic_path_scrubbing_handles_exact_windows_show_quoting_only() {
        let sandbox = br"C:\work\sandbox";
        let script = br"C:\work\sandbox\main.hell";
        let escaped =
            br#"hell: Invalid variable: Qual (SrcSpan "C:\\work\\sandbox\\main.hell" 1 17 1 33)"#;
        let scrubbed = scrub_diagnostic_path_bytes(escaped, sandbox, script, b"hell");
        assert_eq!(
            scrubbed,
            br#"hell: Invalid variable: Qual (SrcSpan "<SANDBOX>\main.hell" 1 17 1 33)"#
        );
        assert_eq!(
            parse_diagnostic_observation(&scrubbed).expect("scrubbed Show diagnostic"),
            DiagnosticObservation {
                phase: DiagnosticPhase::StaticSemantics,
                code: "H0402".into(),
                category: DiagnosticCategory::NameResolution,
                protected_message: "unresolved-name".into(),
                line: 1,
                column: 17,
            }
        );
        assert_eq!(
            scrub_diagnostic_path_bytes(
                br"C:\work\sandbox\main.hell:1:17: error[H0402]",
                sandbox,
                script,
                b"hell",
            ),
            br"<SANDBOX>\main.hell:1:17: error[H0402]"
        );
        assert_eq!(
            scrub_diagnostic_path_bytes(
                br#"SrcSpan "/tmp/sandbox/main.hell" 1 17 1 33"#,
                br"/tmp/sandbox",
                br"/tmp/sandbox/main.hell",
                b"hell",
            ),
            br#"SrcSpan "<SANDBOX>/main.hell" 1 17 1 33"#
        );

        for near_match in [
            br#"SrcSpan "C:\\work\\sandbox\\main.hellish" 1 17"#.as_slice(),
            br#"SrcSpan "C:\\work\\sandbox-other\\main.hell" 1 17"#.as_slice(),
            br"unquoted C:\\work\\sandbox\\main.hell 1 17".as_slice(),
        ] {
            assert_eq!(
                scrub_diagnostic_path_bytes(near_match, sandbox, script, b"hell"),
                near_match
            );
        }
    }

    #[test]
    fn oracle_and_candidate_diagnostics_reduce_to_the_same_structure() {
        let parse_diagnostics: [&[u8]; 4] = [
            b"hell: Parse error: <SANDBOX>/main.hell:2:1: Parse error: ;\n",
            b"<SANDBOX>/main.hell:2:1: error[H0200]: expected expression\n",
            b"hell: Parse error: <SANDBOX>\\main.hell:2:1: Parse error: ;\n",
            b"<SANDBOX>\\main.hell:2:1: error[H0200]: expected expression\n",
        ];
        for diagnostic in parse_diagnostics {
            assert_eq!(
                parse_diagnostic_observation(diagnostic).expect("parse diagnostic"),
                DiagnosticObservation {
                    phase: DiagnosticPhase::Parse,
                    code: "H0200".into(),
                    category: DiagnosticCategory::Syntax,
                    protected_message: "syntax-error".into(),
                    line: 2,
                    column: 1,
                }
            );
        }

        let static_diagnostics: [&[u8]; 4] = [
            b"hell: Invalid variable: Qual (SrcSpanInfo {srcInfoSpan = SrcSpan \"<SANDBOX>/main.hell\" 1 17 1 33})\n",
            b"<SANDBOX>/main.hell:1:17: error[H0402]: unknown global `Main.missingName`\n",
            b"hell: Invalid variable: Qual (SrcSpanInfo {srcInfoSpan = SrcSpan \"<SANDBOX>\\main.hell\" 1 17 1 33})\n",
            b"<SANDBOX>\\main.hell:1:17: error[H0402]: unknown global `Main.missingName`\n",
        ];
        for diagnostic in static_diagnostics {
            assert_eq!(
                parse_diagnostic_observation(diagnostic).expect("static diagnostic"),
                DiagnosticObservation {
                    phase: DiagnosticPhase::StaticSemantics,
                    code: "H0402".into(),
                    category: DiagnosticCategory::NameResolution,
                    protected_message: "unresolved-name".into(),
                    line: 1,
                    column: 17,
                }
            );
        }
    }

    #[test]
    fn acquired_oracle_parse_diagnostic_is_bound_to_its_execution_alias() {
        let sandbox = br"/tmp/differential-oracle";
        let script = br"/tmp/differential-oracle/main.hell";
        let raw = b"hell: Parse error: /tmp/differential-oracle/main.hell:2:1: Parse error: ;\n";
        let scrubbed = scrub_diagnostic_path_bytes(raw, sandbox, script, b"hell");
        assert_eq!(
            scrubbed,
            b"hell: Parse error: <SANDBOX>/main.hell:2:1: Parse error: ;\n"
        );
        assert_eq!(
            parse_diagnostic_observation(&scrubbed).expect("acquired oracle parse diagnostic"),
            DiagnosticObservation {
                phase: DiagnosticPhase::Parse,
                code: "H0200".into(),
                category: DiagnosticCategory::Syntax,
                protected_message: "syntax-error".into(),
                line: 2,
                column: 1,
            }
        );
        let case = DifferentialCase::default();
        assert_eq!(
            replay_conformance_stderr(
                raw,
                Path::new("/ci/oracle-execution/hell"),
                Path::new("/tmp/differential-oracle"),
                Path::new("/tmp/differential-oracle/main.hell"),
                &case,
                &[],
            )
            .expect("exact acquired-oracle replay"),
            scrubbed
        );
        assert_ne!(
            replay_conformance_stderr(
                raw,
                Path::new("/ci/oracle-execution/other"),
                Path::new("/tmp/differential-oracle"),
                Path::new("/tmp/differential-oracle/main.hell"),
                &case,
                &[],
            )
            .expect("forged executable path remains outside the normalizer authority"),
            scrubbed
        );

        for forged in [
            b"linux-release-oracle: Parse error: /tmp/differential-oracle/main.hell:2:1\n"
                .as_slice(),
            b"other: Parse error: /tmp/differential-oracle/main.hell:2:1\n".as_slice(),
            b"hell: Parse error: /tmp/differential-oracle/main.hellish:2:1\n".as_slice(),
        ] {
            assert_eq!(
                scrub_diagnostic_path_bytes(forged, sandbox, script, b"hell"),
                forged
            );
        }
    }

    #[test]
    fn acquired_oracle_separate_parse_frame_is_exactly_bound() {
        let case = DifferentialCase::default();
        let raw = b"hell: Uncaught exception ghc-internal:GHC.Internal.Exception.ErrorCall:\n\nParse error: /tmp/differential-oracle/main.hell:2:1: Parse error: ;\n\nHasCallStack backtrace:\n";
        let scrubbed = replay_conformance_stderr(
            raw,
            Path::new("/ci/oracle-execution/hell"),
            Path::new("/tmp/differential-oracle"),
            Path::new("/tmp/differential-oracle/main.hell"),
            &case,
            &[],
        )
        .expect("exact separate-frame acquired-oracle replay");
        assert_eq!(
            scrubbed,
            b"hell: Uncaught exception ghc-internal:GHC.Internal.Exception.ErrorCall:\n\nParse error: <SANDBOX>/main.hell:2:1: Parse error: ;\n\nHasCallStack backtrace:\n"
        );
        assert_eq!(
            parse_diagnostic_observation(&scrubbed)
                .expect("separate-frame acquired oracle parse diagnostic"),
            DiagnosticObservation {
                phase: DiagnosticPhase::Parse,
                code: "H0200".into(),
                category: DiagnosticCategory::Syntax,
                protected_message: "syntax-error".into(),
                line: 2,
                column: 1,
            }
        );

        for forged in [
            b"linux-release-oracle: Uncaught exception ghc-internal:GHC.Internal.Exception.ErrorCall:\n\nParse error: /tmp/differential-oracle/main.hell:2:1\n".as_slice(),
            b"hell: Uncaught exception Other.Error:\n\nParse error: /tmp/differential-oracle/main.hell:2:1\n".as_slice(),
            b"hell: Uncaught exception ghc-internal:GHC.Internal.Exception.ErrorCall:\nParse error: /tmp/differential-oracle/main.hell:2:1\n".as_slice(),
            b"hell: Uncaught exception ghc-internal:GHC.Internal.Exception.ErrorCall:\n\nuser output\nParse error: /tmp/differential-oracle/main.hell:2:1\n".as_slice(),
            b"hell: Uncaught exception ghc-internal:GHC.Internal.Exception.ErrorCall:\n\nParse error: /tmp/differential-oracle/main.hellish:2:1\n".as_slice(),
        ] {
            assert_eq!(
                replay_conformance_stderr(
                    forged,
                    Path::new("/ci/oracle-execution/hell"),
                    Path::new("/tmp/differential-oracle"),
                    Path::new("/tmp/differential-oracle/main.hell"),
                    &case,
                    &[],
                )
                .expect("forged separate frame remains outside the normalizer authority"),
                forged
            );
        }
    }

    #[test]
    fn diagnostic_script_marker_rejects_near_match_paths() {
        for diagnostic in [
            b"<SANDBOX>main.hell:1:1: error[H0200]".as_slice(),
            b"<SANDBOX>//main.hell:1:1: error[H0200]".as_slice(),
            b"<SANDBOX>\\\\main.hell:1:1: error[H0200]".as_slice(),
            b"<SANDBOX>/other/main.hell:1:1: error[H0200]".as_slice(),
            b"<SANDBOX>\\other\\main.hell:1:1: error[H0200]".as_slice(),
            b"<SANDBOX>/main.hellish:1:1: error[H0200]".as_slice(),
        ] {
            assert!(parse_diagnostic_observation(diagnostic).is_err());
        }
        assert_eq!(
            parse_diagnostic_observation(
                b"noise <SANDBOX>wrong <SANDBOX>\\main.hell:3:4: error[H0200]"
            )
            .expect("later exact marker"),
            DiagnosticObservation {
                phase: DiagnosticPhase::Parse,
                code: "H0200".into(),
                category: DiagnosticCategory::Syntax,
                protected_message: "syntax-error".into(),
                line: 3,
                column: 4,
            }
        );
    }

    #[test]
    fn typed_path_separator_normalizer_is_idempotent_and_preserves_ordinary_text() {
        let mut diagnostic = b"<SANDBOX>\\main.hell:1:1: error[H0200]\nordinary \\ text\n".to_vec();
        diagnostic_path_separator_v1(&mut diagnostic);
        assert_eq!(
            diagnostic,
            b"<SANDBOX>/main.hell:1:1: error[H0200]\nordinary \\ text\n"
        );
        let once = diagnostic.clone();
        diagnostic_path_separator_v1(&mut diagnostic);
        assert_eq!(diagnostic, once);
    }

    #[test]
    fn sandbox_path_normalizer_does_not_rewrite_path_like_user_messages() {
        let sandbox = br"C:\work\sandbox";
        let script = br"C:\work\sandbox\main.hell";
        let message = br"user message C:\work\sandbox\main.hell is data";
        assert_eq!(
            scrub_diagnostic_path_bytes(message, sandbox, script, b"hell"),
            message
        );
        let diagnostic = br"C:\work\sandbox\main.hell:4:2: error[H0200]";
        let once = scrub_diagnostic_path_bytes(diagnostic, sandbox, script, b"hell");
        assert_eq!(once, br"<SANDBOX>\main.hell:4:2: error[H0200]");
        assert_eq!(
            scrub_diagnostic_path_bytes(
                br"unknown helper subcommand C:\work\sandbox\main.hell",
                sandbox,
                script,
                b"hell",
            ),
            br"unknown helper subcommand <SANDBOX>\main.hell"
        );
        assert_eq!(
            scrub_diagnostic_path_bytes(
                br"hell: Parse error: C:\work\sandbox\main.hell:2:1: Parse error: ;",
                sandbox,
                script,
                b"hell",
            ),
            br"hell: Parse error: <SANDBOX>\main.hell:2:1: Parse error: ;"
        );
        assert_eq!(
            scrub_diagnostic_path_bytes(
                br"hell: Parse error: C:\work\sandbox\main.hellish:2:1",
                sandbox,
                script,
                b"hell",
            ),
            br"hell: Parse error: C:\work\sandbox\main.hellish:2:1"
        );
        assert_eq!(
            scrub_diagnostic_path_bytes(&once, br"<SANDBOX>", br"<SANDBOX>\main.hell", b"hell",),
            once
        );
    }

    #[test]
    fn retained_normalizer_api_uses_production_passes_exactly() {
        let sandbox = Path::new(r"C:\work\sandbox");
        let script = Path::new(r"C:\work\sandbox\main.hell");
        let input = br"C:\work\sandbox\main.hell:4:2: error[H0200]";
        let sandbox_passes = apply_retained_normalizer_twice(RetainedNormalizerInput {
            normalizer: NormalizerId::DiagnosticSandboxPathV1,
            observation: input,
            executable: Path::new("hell"),
            sandbox,
            script,
        });
        assert_eq!(
            sandbox_passes.first_pass,
            br"<SANDBOX>\main.hell:4:2: error[H0200]"
        );
        assert_eq!(sandbox_passes.second_pass, sandbox_passes.first_pass);

        let separator_passes = apply_retained_normalizer_twice(RetainedNormalizerInput {
            normalizer: NormalizerId::DiagnosticPathSeparatorV1,
            observation: &sandbox_passes.first_pass,
            executable: Path::new("hell"),
            sandbox,
            script,
        });
        assert_eq!(
            separator_passes.first_pass,
            br"<SANDBOX>/main.hell:4:2: error[H0200]"
        );
        assert_eq!(separator_passes.second_pass, separator_passes.first_pass);
    }
}

#[cfg(test)]
mod effect_causality_tests {
    use super::{BuiltinId, ParsedEffectEvent, ParsedTaskEvent, validate_effect_causality};

    fn event(
        owner_task: Option<u64>,
        sequence: u64,
        parent_sequence: Option<u64>,
        lifecycle: &str,
    ) -> ParsedEffectEvent {
        ParsedEffectEvent {
            event_id: sequence,
            builtin: BuiltinId(0),
            owner_task,
            sequence,
            parent_sequence,
            value: lifecycle.to_owned(),
        }
    }

    #[test]
    fn effect_graph_rejects_substitution_and_causal_forgery() {
        let tasks = vec![
            ParsedTaskEvent {
                event_id: 1,
                builtin: BuiltinId(0),
                task_id: 7,
                value: "started".into(),
            },
            ParsedTaskEvent {
                event_id: 2,
                builtin: BuiltinId(0),
                task_id: 7,
                value: "completed".into(),
            },
        ];
        let valid = vec![
            event(Some(7), 1, None, "started"),
            event(Some(7), 1, None, "completed"),
            event(Some(7), 2, Some(1), "started"),
            event(Some(7), 2, Some(1), "completed"),
        ];
        validate_effect_causality(&valid, &tasks).expect("valid effect graph");

        let mut wrong_terminal = valid;
        wrong_terminal[1].builtin = BuiltinId(1);
        assert!(validate_effect_causality(&wrong_terminal, &tasks).is_err());
        assert!(
            validate_effect_causality(
                &[
                    event(Some(7), 1, Some(9), "started"),
                    event(Some(7), 1, Some(9), "completed"),
                ],
                &tasks,
            )
            .is_err()
        );
        assert!(
            validate_effect_causality(
                &[
                    event(Some(8), 1, None, "started"),
                    event(Some(8), 1, None, "completed"),
                ],
                &tasks,
            )
            .is_err()
        );
        assert!(
            validate_effect_causality(
                &[
                    event(Some(7), 2, None, "started"),
                    event(Some(7), 2, None, "completed"),
                ],
                &tasks,
            )
            .is_err()
        );
    }
}

#[cfg(test)]
mod typed_target_tests {
    use super::{
        CaseReviewState, CausalSignal, ClaimEvidenceDescriptor, ClaimPlatform, DifferentialCase,
        EvidenceTarget, EvidenceTargetV2, ExecutionProfile, NormalizerId, ObligationId,
        OutputNormalization, sha256_bytes, typed_result_target,
    };
    use hell_builtins::CompatibilityDimension;

    fn case(targets: &[&str]) -> DifferentialCase {
        let source = "main = IO.pure ()\n";
        let semantic_targets = targets
            .iter()
            .map(|target| {
                EvidenceTargetV2::new(
                    *target,
                    CompatibilityDimension::PureRuntime,
                    vec![ObligationId("typed-result".into())],
                    CausalSignal::RuntimeAdapter,
                    vec![
                        ClaimPlatform::Linux,
                        ClaimPlatform::MacOs,
                        ClaimPlatform::Windows,
                    ],
                )
            })
            .collect::<Vec<_>>();
        DifferentialCase {
            source: source.into(),
            normalization: OutputNormalization::default(),
            claim_evidence: Some(ClaimEvidenceDescriptor {
                schema_version: 8,
                profile: ExecutionProfile::Upstream,
                harness_normalizers: vec![NormalizerId::DiagnosticSandboxPathV1],
                claim_normalizers: Vec::new(),
                targets: targets
                    .iter()
                    .map(|target| EvidenceTarget::new(*target, CompatibilityDimension::PureRuntime))
                    .collect(),
                semantic_targets,
                callback_contracts: Vec::new(),
                review_state: CaseReviewState::Reviewed,
                review_statement: "typed-target-test".into(),
                source_sha256: sha256_bytes(source.as_bytes()),
            }),
            ..DifferentialCase::default()
        }
    }

    #[test]
    fn descriptor_selects_exactly_one_typed_result_target() {
        assert_eq!(
            typed_result_target(&case(&["Map.fromList"]))
                .unwrap()
                .unwrap()
                .builtin,
            hell_builtins::lookup("Map.fromList").unwrap().id
        );
        assert_eq!(
            typed_result_target(&case(&["Map.fromList", "Map.fromList"]))
                .unwrap()
                .unwrap()
                .builtin,
            hell_builtins::lookup("Map.fromList").unwrap().id
        );
        let mut overloaded = case(&["Ord.lt"]);
        overloaded.claim_evidence.as_mut().unwrap().semantic_targets[0].expected_instance_target =
            Some("Set".into());
        assert_eq!(
            typed_result_target(&overloaded)
                .unwrap()
                .unwrap()
                .instance
                .as_deref(),
            Some("Set")
        );
        assert!(typed_result_target(&case(&["Map.fromList", "List.cons"])).is_err());
    }
}

#[cfg(test)]
mod evidence_catalog_tests {
    use super::*;

    fn premise(target: &str, premise_count: u8) -> InstancePremiseEvidence {
        InstancePremiseEvidence {
            target: target.into(),
            premise_count,
        }
    }

    #[test]
    fn recursive_instance_premise_preorder_accepts_nested_branching_and_duplicate_siblings() {
        validate_instance_premise_tree(
            hell_builtins::TypeClass::Eq,
            "Maybe",
            &[premise("Maybe", 1), premise("Int", 0)],
        )
        .expect("nested Maybe evidence preorder");
        validate_instance_premise_tree(
            hell_builtins::TypeClass::Eq,
            "Either",
            &[
                premise("Maybe", 1),
                premise("Int", 0),
                premise("(,)", 2),
                premise("Int", 0),
                premise("Int", 0),
            ],
        )
        .expect("branching evidence preorder");
        validate_instance_premise_tree(
            hell_builtins::TypeClass::Eq,
            "(,)",
            &[premise("Int", 0), premise("Int", 0)],
        )
        .expect("duplicate sibling evidence is valid");
        validate_instance_premise_tree(hell_builtins::TypeClass::Functor, "Maybe", &[])
            .expect("direct roots have no premise vector");
    }

    #[test]
    fn recursive_instance_premise_preorder_rejects_every_structural_substitution() {
        let class = hell_builtins::TypeClass::Eq;
        assert!(validate_instance_premise_tree(class, "Maybe", &[]).is_err());
        assert!(
            validate_instance_premise_tree(
                class,
                "Maybe",
                &[premise("Int", 0), premise("Text", 0)],
            )
            .is_err()
        );
        assert!(
            validate_instance_premise_tree(
                class,
                "Maybe",
                &[premise("Int", 0), premise("Maybe", 1)],
            )
            .is_err()
        );
        assert!(validate_instance_premise_tree(class, "Maybe", &[premise("Int", 1)]).is_err());
        assert!(validate_instance_premise_tree(class, "Maybe", &[premise("Missing", 0)]).is_err());
        assert!(
            validate_instance_premise_tree(
                hell_builtins::TypeClass::Functor,
                "Maybe",
                &[premise("Maybe", 0)],
            )
            .is_err()
        );
    }

    fn eligible_case() -> DifferentialCase {
        DifferentialCase {
            id: "catalog-case".into(),
            claim_evidence: Some(ClaimEvidenceDescriptor {
                schema_version: 8,
                profile: ExecutionProfile::Upstream,
                harness_normalizers: vec![NormalizerId::DiagnosticSandboxPathV1],
                claim_normalizers: Vec::new(),
                targets: vec![EvidenceTarget::new(
                    hell_builtins::registry()[0].name,
                    CompatibilityDimension::PureRuntime,
                )],
                semantic_targets: vec![EvidenceTargetV2::new(
                    hell_builtins::registry()[0].name,
                    CompatibilityDimension::PureRuntime,
                    vec![ObligationId("ordinary-success".into())],
                    CausalSignal::RuntimeAdapter,
                    vec![ClaimPlatform::All],
                )],
                callback_contracts: Vec::new(),
                review_state: CaseReviewState::Reviewed,
                review_statement: "fixture-review".into(),
                source_sha256: sha256_bytes(DifferentialCase::default().source.as_bytes()),
            }),
            ..DifferentialCase::default()
        }
    }

    #[test]
    fn collection_comparator_authority_is_exactly_scoped_and_mandatory() {
        let mut ordinary = eligible_case();
        ordinary.claim_evidence.as_mut().unwrap().semantic_targets[0]
            .expected_comparator_trace_sha256 = Some(sha256_bytes(b"extraneous"));
        let descriptor = ordinary.claim_evidence.as_ref().unwrap();
        assert!(validate_semantic_targets(&ordinary, descriptor).is_err());

        let mut collection = committed_differential_cases()
            .into_iter()
            .find(|case| case.id.as_ref() == "runtime-typed-map-singleton-int")
            .expect("committed Map.singleton Int case");
        let complete = collection
            .claim_evidence
            .as_ref()
            .expect("reviewed Map.singleton descriptor")
            .clone();
        validate_semantic_targets(&collection, &complete)
            .expect("committed Map.singleton binds explicit empty comparator authority");

        let target = collection
            .claim_evidence
            .as_mut()
            .expect("reviewed Map.singleton descriptor")
            .semantic_targets
            .iter_mut()
            .find(|target| {
                target.builtin.as_ref() == "Map.singleton"
                    && target.dimension == CompatibilityDimension::PureRuntime
            })
            .expect("reviewed Map.singleton PureRuntime target");
        assert!(
            target.expected_comparator_trace_sha256.is_some(),
            "committed descriptor binds the explicit empty trace"
        );
        target.expected_comparator_trace_sha256 = None;
        let missing = collection.claim_evidence.as_ref().unwrap().clone();
        assert!(validate_semantic_targets(&collection, &missing).is_err());
    }

    #[test]
    fn generated_and_ad_hoc_cases_are_ineligible_by_default() {
        assert!(DifferentialCase::default().claim_evidence.is_none());
        assert!(validate_evidence_catalog(&[DifferentialCase::default()]).is_ok());
    }

    #[test]
    fn committed_catalog_covers_every_declared_obligation_exactly() {
        validate_evidence_catalog(&committed_differential_cases()).unwrap();
    }

    #[test]
    fn portable_directory_catalog_does_not_erase_semantic_fallibility() {
        for builtin in [
            "Directory.getCurrentDirectory",
            "Directory.getHomeDirectory",
        ] {
            let semantic =
                required_obligations_for_target(builtin, CompatibilityDimension::Effects).unwrap();
            assert!(semantic.contains("effect-success"), "{builtin}");
            assert!(semantic.contains("effect-failure"), "{builtin}");

            let portable = portable_native_oracle_obligations_for_target(
                builtin,
                CompatibilityDimension::Effects,
            )
            .unwrap();
            assert!(portable.contains("effect-success"), "{builtin}");
            assert!(!portable.contains("effect-failure"), "{builtin}");
        }
        let set_current = portable_native_oracle_obligations_for_target(
            "Directory.setCurrentDirectory",
            CompatibilityDimension::Effects,
        )
        .unwrap();
        assert!(set_current.contains("effect-failure"));
    }

    #[test]
    fn runtime_catalog_reports_exact_remaining_scope_after_core_data_tranche() {
        let error = validate_runtime_obligation_coverage(&dormant_committed_differential_cases())
            .expect_err("the runtime corpus is intentionally fail-closed until exhaustive");
        assert!(
            error.contains("138 incomplete cells, 14 boundary gaps, and 0 interaction gaps"),
            "{error}"
        );
        for builtin in ["Map.singleton", "Set.singleton"] {
            let cell_prefix = format!("{builtin}/PureRuntime:");
            let cell = error
                .split("; ")
                .find(|cell| cell.starts_with(&cell_prefix))
                .unwrap_or_else(|| panic!("missing exact residual cell {cell_prefix}"));
            let scopes = required_runtime_instance_scopes(builtin)
                .into_iter()
                .map(|scope| {
                    format!(
                        "{}:missing=[\"whnf-failure-boundary\"],bool-partition=false",
                        scope.label()
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            assert_eq!(cell, format!("{cell_prefix} instance-scopes=[{scopes}]"));
        }
        for builtin in [
            "Directory.getCurrentDirectory",
            "Directory.getHomeDirectory",
        ] {
            let cell_prefix = format!("{builtin}/Effects:");
            let cell = error
                .split("; ")
                .find(|cell| cell.starts_with(&cell_prefix))
                .unwrap_or_else(|| panic!("missing exact residual cell {cell_prefix}"));
            assert_eq!(
                cell,
                format!(
                    "{cell_prefix} instance-scopes=[unconstrained:missing=[\"effect-failure\"],bool-partition=false]"
                )
            );
        }
        assert!(!error.contains("http-stream-disconnect: missing"));
        assert!(!error.contains("timeout-process: missing"));
        assert!(!error.contains("text-decode-process-capture: missing"));
        assert!(!error.contains("cwd-child-process: missing"));
    }

    #[test]
    fn eq_requires_both_boolean_paths_for_every_registry_instance() {
        let committed = committed_differential_cases();
        for instance in [
            "Bool",
            "ByteString",
            "CI",
            "Char",
            "Day",
            "DayOfWeek",
            "Double",
            "Either",
            "ExitCode",
            "Int",
            "Integer",
            "Maybe",
            "Set",
            "Text",
            "TimeOfDay",
            "Tree",
            "UTCTime",
            "Vector",
            "[]",
            "(,)",
        ] {
            for result in [true, false] {
                let digest = boolean_typed_result_digest(result);
                let mut cases = committed.clone();
                cases.retain(|case| {
                    !case.claim_evidence.as_ref().is_some_and(|descriptor| {
                        descriptor.semantic_targets.iter().any(|target| {
                            target.builtin.as_ref() == "Eq.eq"
                                && target.expected_instance_target.as_deref() == Some(instance)
                                && target.expected_typed_result_sha256 == Some(digest)
                        })
                    })
                });
                let error = validate_runtime_obligation_coverage(&cases)
                    .expect_err("removing an Eq boolean path must reopen its instance scope");
                let eq_cell = error
                    .split("; ")
                    .find(|cell| cell.starts_with("Eq.eq/PureRuntime:"))
                    .unwrap_or_else(|| {
                        panic!("missing Eq.eq cell after removing {instance}/{result}")
                    });
                assert!(
                    eq_cell.contains(&format!("{instance}:missing=["))
                        && eq_cell.contains("bool-partition=true"),
                    "{eq_cell}"
                );
            }
        }
    }

    #[test]
    fn eq_committed_matrix_retains_every_reviewed_shape_and_short_circuit_probe() {
        let cases = committed_differential_cases();
        let eq_ids = cases
            .iter()
            .filter(|case| case.id.starts_with("runtime-typed-eq-"))
            .map(|case| case.id.as_ref())
            .collect::<std::collections::BTreeSet<_>>();
        let mut required = [
            "bool",
            "byte-string",
            "ci",
            "char",
            "day",
            "day-of-week",
            "double",
            "either",
            "exit-code",
            "int",
            "integer",
            "list",
            "maybe",
            "set",
            "text",
            "time-of-day",
            "tree",
            "tuple",
            "utc-time",
            "vector",
        ]
        .into_iter()
        .flat_map(|instance| {
            ["equal", "unequal"].map(|path| format!("runtime-typed-eq-{instance}-{path}"))
        })
        .collect::<std::collections::BTreeSet<_>>();
        required.extend(
            [
                "runtime-typed-eq-byte-string-invalid-equal",
                "runtime-typed-eq-byte-string-invalid-unequal",
                "runtime-typed-eq-double-nan",
                "runtime-typed-eq-double-signed-zero",
                "runtime-typed-eq-either-early-mismatch",
                "runtime-typed-eq-either-left-equal",
                "runtime-typed-eq-either-left-payload",
                "runtime-typed-eq-either-payload",
                "runtime-typed-eq-exit-code-failure-code",
                "runtime-typed-eq-list-empty",
                "runtime-typed-eq-list-early-mismatch",
                "runtime-typed-eq-list-element",
                "runtime-typed-eq-maybe-early-mismatch",
                "runtime-typed-eq-maybe-nothing-equal",
                "runtime-typed-eq-maybe-payload",
                "runtime-typed-eq-set-empty",
                "runtime-typed-eq-set-element",
                "runtime-typed-eq-tree-child",
                "runtime-typed-eq-tree-early-mismatch",
                "runtime-typed-eq-tuple-early-mismatch",
                "runtime-typed-eq-tuple-first-field",
                "runtime-typed-eq-vector-early-mismatch",
                "runtime-typed-eq-vector-empty",
                "runtime-typed-eq-vector-element",
            ]
            .into_iter()
            .map(str::to_owned),
        );
        let required = required
            .iter()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        assert!(required.is_subset(&eq_ids));
        assert_eq!(
            eq_ids.difference(&required).copied().collect::<Vec<_>>(),
            ["runtime-typed-eq-false", "runtime-typed-eq-true",]
        );
    }

    #[test]
    fn ord_committed_matrix_retains_every_reviewed_ordering_and_short_circuit_probe() {
        let cases = committed_differential_cases();
        let observed = cases
            .iter()
            .filter(|case| case.id.starts_with("runtime-typed-ord-"))
            .map(|case| case.id.as_ref())
            .collect::<std::collections::BTreeSet<_>>();
        let instances = [
            "bool",
            "byte-string",
            "ci",
            "char",
            "day",
            "day-of-week",
            "double",
            "either",
            "exit-code",
            "int",
            "integer",
            "list",
            "maybe",
            "set",
            "text",
            "time-of-day",
            "tree",
            "tuple",
            "utc-time",
            "vector",
        ];
        let mut required = ["lt", "gt"]
            .into_iter()
            .flat_map(|builtin| {
                instances.into_iter().flat_map(move |instance| {
                    ["ordered", "reverse", "equal"]
                        .map(move |path| format!("runtime-typed-ord-{builtin}-{instance}-{path}"))
                })
            })
            .collect::<std::collections::BTreeSet<_>>();
        for builtin in ["lt", "gt"] {
            required.extend(
                [
                    "byte-string-invalid-bytes",
                    "byte-string-invalid-equal",
                    "double-infinity",
                    "double-nan",
                    "double-signed-zero",
                    "either-constructor-bottom-payload",
                    "list-prefix-bottom-tail",
                    "maybe-payload",
                    "set-prefix-length",
                    "tree-root-bottom-children",
                    "tuple-first-field-bottom-tail",
                    "vector-prefix-bottom-tail",
                ]
                .map(|suffix| format!("runtime-typed-ord-{builtin}-{suffix}")),
            );
        }
        let required = required
            .iter()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        assert!(required.is_subset(&observed));
        assert_eq!(
            observed.difference(&required).copied().collect::<Vec<_>>(),
            [
                "runtime-typed-ord-gt",
                "runtime-typed-ord-gt-false",
                "runtime-typed-ord-gt-true",
                "runtime-typed-ord-lt",
                "runtime-typed-ord-lt-false",
                "runtime-typed-ord-lt-true",
            ]
        );
    }

    #[test]
    fn monad_return_requires_every_direct_registry_instance() {
        let mut cases = committed_differential_cases();
        cases.retain(|case| case.id.as_ref() != "runtime-typed-monad-return-either");
        let error = validate_runtime_obligation_coverage(&cases)
            .expect_err("missing one direct Monad instance must reopen Monad.return");
        let return_cell = error
            .split("; ")
            .find(|cell| cell.starts_with("Monad.return/PureRuntime:"))
            .unwrap_or_else(|| panic!("missing Monad.return cell in {error}"));
        assert!(return_cell.contains("Either:missing="), "{return_cell}");
    }

    #[test]
    fn monad_when_requires_both_branches_for_every_direct_instance() {
        for (instance, target) in [
            ("io", "IO"),
            ("maybe", "Maybe"),
            ("list", "[]"),
            ("tree", "Tree"),
            ("either", "Either"),
        ] {
            for branch in ["selected", "unselected"] {
                let removed = format!("runtime-typed-monad-when-{instance}-{branch}");
                let mut cases = committed_differential_cases();
                cases.retain(|case| case.id.as_ref() != removed);
                let error = validate_runtime_obligation_coverage(&cases)
                    .expect_err("missing a Monad.when branch must reopen its instance scope");
                let when_cell = error
                    .split("; ")
                    .find(|cell| cell.starts_with("Monad.when/PureRuntime:"))
                    .unwrap_or_else(|| panic!("missing Monad.when cell after removing {removed}"));
                assert!(
                    when_cell.contains(&format!("{target}:missing=[")),
                    "{when_cell}"
                );
            }
        }
    }

    #[test]
    fn monad_then_requires_both_paths_for_every_direct_instance() {
        for (instance, target, paths) in [
            ("io", "IO", ["success", "short-circuit"]),
            ("maybe", "Maybe", ["success", "short-circuit"]),
            ("list", "[]", ["success", "short-circuit"]),
            ("tree", "Tree", ["simple", "branching"]),
            ("either", "Either", ["success", "short-circuit"]),
        ] {
            for path in paths {
                let removed = format!("runtime-typed-monad-then-{instance}-{path}");
                let mut cases = committed_differential_cases();
                cases.retain(|case| case.id.as_ref() != removed);
                let error = validate_runtime_obligation_coverage(&cases)
                    .expect_err("missing a Monad.then path must reopen its instance scope");
                let then_cell = error
                    .split("; ")
                    .find(|cell| cell.starts_with("Monad.then/PureRuntime:"))
                    .unwrap_or_else(|| panic!("missing Monad.then cell after removing {removed}"));
                assert!(
                    then_cell.contains(&format!("{target}:missing=[")),
                    "{then_cell}"
                );
            }
        }
    }

    #[test]
    fn monad_bind_requires_both_paths_for_every_direct_instance() {
        for (instance, target, paths) in [
            ("io", "IO", ["success", "short-circuit"]),
            ("maybe", "Maybe", ["success", "short-circuit"]),
            ("list", "[]", ["success", "short-circuit"]),
            ("tree", "Tree", ["simple", "branching"]),
            ("either", "Either", ["success", "short-circuit"]),
        ] {
            for path in paths {
                let removed = format!("runtime-typed-monad-bind-{instance}-{path}");
                let mut cases = committed_differential_cases();
                cases.retain(|case| case.id.as_ref() != removed);
                let error = validate_runtime_obligation_coverage(&cases)
                    .expect_err("missing a Monad.bind path must reopen its instance scope");
                let bind_cell = error
                    .split("; ")
                    .find(|cell| cell.starts_with("Monad.bind/PureRuntime:"))
                    .unwrap_or_else(|| panic!("missing Monad.bind cell after removing {removed}"));
                assert!(
                    bind_cell.contains(&format!("{target}:missing=[")),
                    "{bind_cell}"
                );
            }
        }
    }

    #[test]
    fn monad_sequence_requires_both_paths_for_every_direct_instance() {
        for (instance, target, paths) in [
            ("io", "IO", ["finite", "short-circuit"]),
            ("maybe", "Maybe", ["finite", "short-circuit"]),
            ("list", "[]", ["finite", "empty"]),
            ("tree", "Tree", ["finite", "empty"]),
            ("either", "Either", ["finite", "short-circuit"]),
        ] {
            for path in paths {
                let removed = format!("runtime-typed-monad-sequence-{instance}-{path}");
                let mut cases = committed_differential_cases();
                cases.retain(|case| case.id.as_ref() != removed);
                let error = validate_runtime_obligation_coverage(&cases)
                    .expect_err("missing a Monad.sequence path must reopen its instance scope");
                let sequence_cell = error
                    .split("; ")
                    .find(|cell| cell.starts_with("Monad.sequence/PureRuntime:"))
                    .unwrap_or_else(|| {
                        panic!("missing Monad.sequence cell after removing {removed}")
                    });
                assert!(
                    sequence_cell.contains(&format!("{target}:missing=[")),
                    "{sequence_cell}"
                );
            }
        }
    }

    #[test]
    fn monad_traversals_require_both_paths_for_every_direct_instance() {
        for (builtin, slug) in [
            ("Monad.mapM", "monad-mapm"),
            ("Monad.forM", "monad-form"),
            ("Monad.mapM_", "monad-mapm-discard"),
            ("Monad.forM_", "monad-form-discard"),
        ] {
            for (instance, target, paths) in [
                ("io", "IO", ["finite", "short-circuit"]),
                ("maybe", "Maybe", ["finite", "short-circuit"]),
                ("list", "[]", ["finite", "empty"]),
                ("tree", "Tree", ["finite", "empty"]),
                ("either", "Either", ["finite", "short-circuit"]),
            ] {
                for path in paths {
                    let removed = format!("runtime-typed-{slug}-{instance}-{path}");
                    let mut cases = committed_differential_cases();
                    cases.retain(|case| case.id.as_ref() != removed);
                    let error = validate_runtime_obligation_coverage(&cases)
                        .expect_err("missing a Monad traversal path must reopen its instance");
                    let cell = error
                        .split("; ")
                        .find(|cell| cell.starts_with(&format!("{builtin}/PureRuntime:")))
                        .unwrap_or_else(|| {
                            panic!("missing {builtin} cell after removing {removed}")
                        });
                    assert!(cell.contains(&format!("{target}:missing=[")), "{cell}");
                }
            }
        }
    }

    #[test]
    fn functor_adapters_require_both_paths_for_every_direct_instance() {
        for (builtin, slug) in [("Functor.fmap", "fmap"), ("<$>", "operator")] {
            for (instance, target) in [
                ("list", "[]"),
                ("io", "IO"),
                ("parser", "Options.Parser"),
                ("tree", "Tree"),
                ("maybe", "Maybe"),
                ("either", "Either"),
                ("pair", "(,)"),
            ] {
                for path in ["mapped", "short"] {
                    let removed = format!("runtime-typed-functor-{slug}-{instance}-{path}");
                    let mut cases = committed_differential_cases();
                    cases.retain(|case| case.id.as_ref() != removed);
                    let error = validate_runtime_obligation_coverage(&cases)
                        .expect_err("missing a Functor path must reopen its instance scope");
                    let cell = error
                        .split("; ")
                        .find(|cell| cell.starts_with(&format!("{builtin}/PureRuntime:")))
                        .unwrap_or_else(|| {
                            panic!("missing {builtin} cell after removing {removed}")
                        });
                    assert!(cell.contains(&format!("{target}:missing=[")), "{cell}");
                }
            }
        }
    }

    #[test]
    fn runtime_catalog_rejects_one_source_relabelled_as_distinct_boundaries() {
        let mut cases = committed_differential_cases();
        let minimum_source = cases
            .iter()
            .find(|case| case.id.as_ref() == "int-plus-boundary-minimum-value")
            .expect("minimum boundary case")
            .source
            .clone();
        let overflow = cases
            .iter_mut()
            .find(|case| case.id.as_ref() == "int-plus-boundary-overflow")
            .expect("overflow boundary case");
        overflow.source = minimum_source;
        overflow
            .claim_evidence
            .as_mut()
            .expect("boundary descriptor")
            .source_sha256 = sha256_bytes(overflow.source.as_bytes());
        let error = validate_runtime_obligation_coverage(&cases)
            .expect_err("one source cannot establish two boundary classes");
        assert!(
            error.contains("reuses one source observation across distinct boundary classes"),
            "{error}"
        );
    }

    #[test]
    fn catalog_rejects_unknown_and_duplicate_targets() {
        let mut unknown = eligible_case();
        unknown.claim_evidence.as_mut().unwrap().targets[0].builtin = "Missing.builtin".into();
        assert!(validate_evidence_catalog(&[unknown]).is_err());

        let mut duplicate = eligible_case();
        let target = duplicate.claim_evidence.as_ref().unwrap().targets[0].clone();
        duplicate
            .claim_evidence
            .as_mut()
            .unwrap()
            .targets
            .push(target);
        assert!(validate_evidence_catalog(&[duplicate]).is_err());
    }

    #[test]
    fn catalog_rejects_normalizer_and_execution_scope_mismatches() {
        let mut normalizer = eligible_case();
        normalizer
            .claim_evidence
            .as_mut()
            .unwrap()
            .harness_normalizers
            .clear();
        assert!(validate_evidence_catalog(&[normalizer]).is_err());

        let mut check_only = eligible_case();
        check_only.mode = DifferentialMode::Check;
        assert!(validate_evidence_catalog(&[check_only]).is_err());

        let mut unversioned = eligible_case();
        unversioned
            .normalization
            .stderr_replacements
            .push((b"from".to_vec(), b"to".to_vec()));
        assert!(validate_evidence_catalog(&[unversioned]).is_err());
    }

    #[test]
    fn canonical_typed_primitives_reject_noncanonical_and_substituted_values() {
        for value in [
            "{\"type\":\"Unit\",\"value\":null}",
            "{\"type\":\"Bool\",\"value\":false}",
            "{\"type\":\"Int\",\"value\":\"-9223372036854775808\"}",
            "{\"type\":\"Integer\",\"value\":\"9223372036854775808\"}",
            "{\"type\":\"Double\",\"ieee754Bits\":\"3ff0000000000000\"}",
            "{\"type\":\"Character\",\"codePoint\":9731}",
            "{\"type\":\"Text\",\"utf8Hex\":\"736e6f776d616e2de29883\"}",
            "{\"type\":\"ByteString\",\"hex\":\"00ff\"}",
            "{\"type\":\"BufferMode\",\"value\":\"block\"}",
            "{\"type\":\"FileMode\",\"value\":\"read-write\"}",
            "{\"type\":\"Handle\",\"kind\":\"stdin\"}",
            "{\"type\":\"Handle\",\"kind\":\"stdout\"}",
            "{\"type\":\"Handle\",\"kind\":\"stderr\"}",
            "{\"type\":\"Handle\",\"kind\":\"null\"}",
            "{\"type\":\"Handle\",\"kind\":\"file\",\"closeAfterProcess\":false}",
            "{\"type\":\"Handle\",\"kind\":\"file\",\"closeAfterProcess\":true}",
            "{\"type\":\"OptionsInfoMod\",\"fullDescription\":true,\"programDescriptionHex\":null,\"headerHex\":null}",
            "{\"type\":\"CaseInsensitive\",\"original\":{\"type\":\"Text\",\"utf8Hex\":\"416243\"},\"folded\":{\"type\":\"Text\",\"utf8Hex\":\"616263\"}}",
            "{\"type\":\"CaseInsensitive\",\"original\":{\"type\":\"ByteString\",\"hex\":\"ff41\"},\"folded\":{\"type\":\"ByteString\",\"hex\":\"ff61\"}}",
        ] {
            validate_canonical_typed_value(value).unwrap();
        }
        for value in [
            "{\"type\":\"Unit\",\"value\":false}",
            "{\"type\":\"Bool\",\"value\":0}",
            "{\"type\":\"Int\",\"value\":\"01\"}",
            "{\"type\":\"Int\",\"value\":\"9223372036854775808\"}",
            "{\"type\":\"Integer\",\"value\":\"-0\"}",
            "{\"type\":\"Double\",\"ieee754Bits\":\"3FF0000000000000\"}",
            "{\"type\":\"Character\",\"codePoint\":55296}",
            "{\"type\":\"OptionsInfoMod\",\"fullDescription\":1,\"programDescriptionHex\":null,\"headerHex\":null}",
            "{\"type\":\"OptionsInfoMod\",\"fullDescription\":true,\"programDescriptionHex\":\"ff\",\"headerHex\":null}",
            "{\"type\":\"Text\",\"utf8Hex\":\"ff\"}",
            "{\"type\":\"ByteString\",\"hex\":\"0\"}",
            "{\"type\":\"Text\",\"utf8Hex\":\"61\",\"extra\":true}",
            "{\"type\":\"BufferMode\",\"value\":\"Block\"}",
            "{\"type\":\"FileMode\",\"value\":\"truncate\"}",
            "{\"type\":\"Handle\",\"kind\":\"file\"}",
            "{\"type\":\"Handle\",\"kind\":\"file\",\"closeAfterProcess\":null}",
            "{\"type\":\"Handle\",\"kind\":\"stdout\",\"path\":\"x\"}",
            "{\"type\":\"CaseInsensitive\",\"folded\":{\"type\":\"Text\",\"utf8Hex\":\"616263\"}}",
            "{\"type\":\"CaseInsensitive\",\"original\":{\"type\":\"Text\",\"utf8Hex\":\"416243\"},\"folded\":{\"type\":\"ByteString\",\"hex\":\"616263\"}}",
            "{\"type\":\"CaseInsensitive\",\"original\":{\"type\":\"Int\",\"value\":\"1\"},\"folded\":{\"type\":\"Int\",\"value\":\"1\"}}",
        ] {
            assert!(validate_canonical_typed_value(value).is_err(), "{value}");
        }
    }

    #[test]
    fn canonical_composites_bind_order_payload_termination_and_force_outcome() {
        let int_one = "{\"type\":\"Int\",\"value\":\"1\"}";
        let int_two = "{\"type\":\"Int\",\"value\":\"2\"}";
        for value in [
            format!("{{\"type\":\"Tuple\",\"elements\":[{int_one},{int_two}]}}"),
            format!("{{\"type\":\"Set\",\"elements\":[{int_one},{int_one}]}}"),
            format!(
                "{{\"type\":\"Record\",\"typeNameHex\":\"52\",\"constructorHex\":\"43\",\"fields\":[{{\"nameHex\":\"61\",\"value\":{int_one}}}]}}"
            ),
            format!(
                "{{\"type\":\"Variant\",\"typeNameHex\":\"56\",\"constructorHex\":\"4b\",\"payload\":{int_one}}}"
            ),
            format!("{{\"type\":\"Map\",\"entries\":[{{\"key\":{int_one},\"value\":{int_two}}}]}}"),
            concat!(
                "{\"type\":\"Map\",\"entries\":[",
                "{\"key\":{\"type\":\"Double\",\"ieee754Bits\":\"7ff8000000000000\"},",
                "\"value\":{\"type\":\"Text\",\"utf8Hex\":\"61\"}},",
                "{\"key\":{\"type\":\"Double\",\"ieee754Bits\":\"7ff8000000000000\"},",
                "\"value\":{\"type\":\"Text\",\"utf8Hex\":\"62\"}}]}"
            )
            .to_owned(),
            format!(
                "{{\"type\":\"List\",\"elements\":[{int_one},{int_two}],\"terminationHex\":\"6e696c\"}}"
            ),
            format!(
                "{{\"type\":\"Tree\",\"elements\":[{int_one},{{\"type\":\"List\",\"elements\":[],\"terminationHex\":\"6e696c\"}}]}}"
            ),
            format!(
                "{{\"type\":\"Tree\",\"elements\":[{int_one},{{\"type\":\"ForceBoundary\",\"outcome\":\"not-forced\"}}]}}"
            ),
            format!("{{\"type\":\"GuestFunction\",\"body\":12,\"captures\":[{int_one}]}}"),
            "{\"type\":\"ForceBoundary\",\"outcome\":\"error\",\"code\":\"H0901\"}".to_owned(),
        ] {
            validate_canonical_typed_value(&value).unwrap_or_else(|error| {
                panic!("canonical composite was rejected: {error}: {value}")
            });
        }
        for value in [
            format!("{{\"type\":\"Tuple\",\"elements\":[{int_one},]}}"),
            format!(
                "{{\"type\":\"Record\",\"typeNameHex\":\"52\",\"constructorHex\":\"43\",\"fields\":[{{\"nameHex\":\"61\",\"value\":{int_one}}},{{\"nameHex\":\"61\",\"value\":{int_two}}}]}}"
            ),
            format!("{{\"type\":\"Map\",\"entries\":[{{\"value\":{int_two},\"key\":{int_one}}}]}}"),
            format!("{{\"type\":\"Map\",\"entries\":[{{\"key\":{int_one}}}]}}"),
            format!("{{\"type\":\"Map\",\"entries\":[{{\"value\":{int_two}}}]}}"),
            format!(
                "{{\"type\":\"Map\",\"entries\":[{{\"key\":{int_one},\"value\":{int_two},\"extra\":true}}]}}"
            ),
            format!("{{\"type\":\"Map\",\"entries\":[{{\"key\":{int_one},\"value\":{int_two}}},]}}"),
            format!("{{\"type\":\"Set\",\"elements\":[{int_one},]}}"),
            "{\"type\":\"Set\",\"elements\":[{\"type\":\"Int\",\"value\":\"01\"}]}".to_owned(),
            "{\"type\":\"Set\",\"elements\":[],\"extra\":true}".to_owned(),
            format!(
                "{{\"type\":\"PrimitiveVariant\",\"family\":\"Either\",\"constructor\":\"Left\",\"payloads\":[{int_one},{int_two}]}}"
            ),
            format!(
                "{{\"type\":\"List\",\"elements\":[{int_one}],\"terminationHex\":\"756e6b6e6f776e\"}}"
            ),
            format!("{{\"type\":\"Tree\",\"elements\":[{int_one}]}}"),
            format!("{{\"type\":\"Tree\",\"elements\":[{int_one},{int_two}]}}"),
            format!(
                "{{\"type\":\"Tree\",\"elements\":[{int_one},{{\"type\":\"ForceBoundary\",\"outcome\":\"value\"}}]}}"
            ),
            format!(
                "{{\"type\":\"Tree\",\"elements\":[{int_one},{{\"type\":\"ForceBoundary\",\"outcome\":\"poisoned\"}}]}}"
            ),
            format!(
                "{{\"type\":\"GuestFunction\",\"body\":012,\"captures\":[{int_one}]}}"
            ),
            "{\"type\":\"GuestFunction\",\"body\":12,\"captures\":[{\"type\":\"Int\",\"value\":\"01\"}]}".to_owned(),
            "{\"type\":\"ForceBoundary\",\"outcome\":\"error\",\"code\":\"bad\"}".to_owned(),
        ] {
            assert!(validate_canonical_typed_value(&value).is_err(), "{value}");
        }
    }

    #[test]
    fn presentation_shadow_normalizes_only_line_endings_and_frames_streams() {
        let normalizer = PresentationShadowNormalizerId::LineEndingsV1;
        assert_eq!(normalizer.as_str(), "presentation-line-endings-v1");
        let lf = normalized_presentation_shadow_sha256(normalizer, b"a\nb\n", b"").unwrap();
        assert_eq!(
            normalized_presentation_shadow_sha256(normalizer, b"a\r\nb\r\n", b"").unwrap(),
            lf
        );
        assert_eq!(
            normalized_presentation_shadow_sha256(normalizer, b"a\rb\r", b"").unwrap(),
            lf
        );
        assert_ne!(
            normalized_presentation_shadow_sha256(normalizer, b"a \n", b"").unwrap(),
            normalized_presentation_shadow_sha256(normalizer, b"a\n", b"").unwrap()
        );
        assert_ne!(
            normalized_presentation_shadow_sha256(normalizer, b"a\n", b"").unwrap(),
            normalized_presentation_shadow_sha256(normalizer, b"a", b"").unwrap()
        );
        assert_ne!(
            normalized_presentation_shadow_sha256(normalizer, b"ab", b"c").unwrap(),
            normalized_presentation_shadow_sha256(normalizer, b"a", b"bc").unwrap()
        );
        assert!(normalized_presentation_shadow_sha256(normalizer, &[0xff], b"").is_err());
        assert!(normalized_presentation_shadow_sha256(normalizer, b"", &[0xff]).is_err());
    }
}
