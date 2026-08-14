//! Bounded differential, compatibility-gate, and deterministic-fuzz support.

mod artifact;
mod collection_authority;
mod corpus;
mod reviewed_set;
mod runtime_obligations;

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{Read, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hell_platform::{SupervisedChild, TerminationReport, WaitOutcome};

use hell_builtins::CompatibilityDimension;
pub use hell_builtins::{BuiltinId, ClaimPlatform, ExecutionProfile, NormalizerId};

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

/// Environment names explicitly carried through the POSIX privilege boundary.
/// The trusted adapter clears sudo's synthesized environment before executing
/// the requested program, so this is both the preservation and final-child
/// allowlist.
#[cfg(unix)]
pub const POSIX_RELEASE_CHILD_PRESERVE_ENVIRONMENT: &str = concat!(
    "--preserve-env=",
    "CARGO_HOME,CARGO_INCREMENTAL,CARGO_TARGET_DIR,CARGO_TERM_COLOR,CI,DEVELOPER_DIR,",
    "GITHUB_ACTIONS,HOME,ImageOS,ImageVersion,LANG,LC_ALL,LIBRARY_PATH,PATH,RUNNER_ARCH,",
    "RUNNER_OS,RUSTC_WRAPPER,RUSTDOCFLAGS,RUSTUP_HOME,SCCACHE_DIR,SDKROOT,SOURCE_DATE_EPOCH,",
    "TEMP,TMP,TMPDIR,USERPROFILE"
);

/// Exact POSIX child environment names accepted by the trusted adapter.
#[cfg(unix)]
pub const POSIX_RELEASE_CHILD_ENVIRONMENT_ALLOWLIST: &[&str] = &[
    "CARGO_HOME",
    "CARGO_INCREMENTAL",
    "CARGO_TARGET_DIR",
    "CARGO_TERM_COLOR",
    "CI",
    "DEVELOPER_DIR",
    "GITHUB_ACTIONS",
    "HOME",
    "ImageOS",
    "ImageVersion",
    "LANG",
    "LC_ALL",
    "LIBRARY_PATH",
    "PATH",
    "RUNNER_ARCH",
    "RUNNER_OS",
    "RUSTC_WRAPPER",
    "RUSTDOCFLAGS",
    "RUSTUP_HOME",
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

/// A trusted, typed launcher policy for release candidate and oracle children.
#[derive(Clone, Debug)]
pub struct CandidateLaunchPolicy {
    #[cfg(unix)]
    launcher: PathBuf,
    #[cfg(unix)]
    adapter: PathBuf,
    #[cfg(unix)]
    principal: Arc<str>,
    #[cfg(unix)]
    uid: u32,
    #[cfg(unix)]
    group: Arc<str>,
    #[cfg(windows)]
    launcher: PathBuf,
    writable_roots: Arc<[PathBuf]>,
}

thread_local! {
    static CANDIDATE_LAUNCH_POLICY: RefCell<Option<CandidateLaunchPolicy>> = const { RefCell::new(None) };
}

impl CandidateLaunchPolicy {
    /// Creates a POSIX policy after the trusted driver has established the
    /// separate account and filesystem ownership boundary.
    ///
    /// # Errors
    ///
    /// Returns an error when a launcher path cannot be canonicalized or the
    /// supplied principal, group, or writable roots are not canonical.
    #[cfg(unix)]
    pub fn posix(
        launcher: PathBuf,
        adapter: PathBuf,
        principal: String,
        uid: u32,
        group: String,
        writable_roots: Vec<PathBuf>,
    ) -> std::io::Result<Self> {
        let launcher = fs::canonicalize(launcher)?;
        let adapter = fs::canonicalize(adapter)?;
        if principal.is_empty()
            || group.is_empty()
            || !principal.bytes().all(|byte| byte.is_ascii_alphanumeric())
            || !group.bytes().all(|byte| byte.is_ascii_alphanumeric())
            || writable_roots.is_empty()
            || writable_roots.iter().any(|path| !path.is_absolute())
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "candidate launch policy is not canonical",
            ));
        }
        Ok(Self {
            launcher,
            adapter,
            principal: principal.into(),
            uid,
            group: group.into(),
            writable_roots: writable_roots.into(),
        })
    }

    #[cfg(not(unix))]
    pub fn windows(launcher: PathBuf, writable_roots: Vec<PathBuf>) -> std::io::Result<Self> {
        let launcher = fs::canonicalize(launcher)?;
        if writable_roots.is_empty() || writable_roots.iter().any(|path| !path.is_absolute()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "candidate launch policy is not canonical",
            ));
        }
        Ok(Self {
            launcher,
            writable_roots: writable_roots.into(),
        })
    }

    #[cfg(unix)]
    fn wrap(&self, command: &mut Command) -> std::io::Result<()> {
        let program = resolve_parent_program(command.get_program())?;
        let arguments = command.get_args().map(OsString::from).collect::<Vec<_>>();
        let directory = command.get_current_dir().map(Path::to_owned);
        let environment = command
            .get_envs()
            .map(|(name, value)| (OsString::from(name), value.map(OsString::from)))
            .collect::<Vec<_>>();
        let mut wrapped = Command::new(&self.launcher);
        wrapped
            .arg("-n")
            .arg(POSIX_RELEASE_CHILD_PRESERVE_ENVIRONMENT)
            .arg("-u")
            .arg(self.principal.as_ref())
            .arg("--")
            .arg(&self.adapter)
            .arg("__release-posix-child")
            .arg(program)
            .args(arguments)
            .env_clear();
        for (name, value) in &environment {
            if let Some(value) = value {
                wrapped.env(name, value);
            }
        }
        if let Some(directory) = directory {
            wrapped.current_dir(directory);
        }
        *command = wrapped;
        Ok(())
    }

    #[cfg(not(unix))]
    fn wrap(&self, command: &mut Command) -> std::io::Result<()> {
        let program = resolve_parent_program(command.get_program())?;
        let arguments = std::iter::once(program.as_os_str())
            .chain(command.get_args())
            .map(OsString::from)
            .collect::<Vec<_>>();
        let encoded = encode_windows_argv(&arguments)?;
        let directory = command.get_current_dir().map(Path::to_owned);
        let environment = command
            .get_envs()
            .map(|(name, value)| (OsString::from(name), value.map(OsString::from)))
            .collect::<Vec<_>>();
        let mut wrapped = Command::new(&self.launcher);
        wrapped
            .arg("__release-restricted-child")
            .arg(encoded)
            .env_clear();
        for (name, value) in environment {
            if let Some(value) = value {
                wrapped.env(name, value);
            }
        }
        if let Some(directory) = directory {
            wrapped.current_dir(directory);
        }
        *command = wrapped;
        Ok(())
    }

    #[cfg(unix)]
    fn require_quiescence(&self) -> std::io::Result<()> {
        let uid = self.uid.to_string();
        for _ in 0..8 {
            let _ = Command::new(&self.launcher)
                .args(["-n", "--", "/usr/bin/pkill", "-KILL", "-U"])
                .arg(&uid)
                .status()?;
            let output = Command::new("/bin/ps")
                .args(["-U", uid.as_str(), "-o", "pid="])
                .output()?;
            if output.status.success() && output.stdout.iter().all(u8::is_ascii_whitespace) {
                return Ok(());
            }
        }
        Err(std::io::Error::other(
            "candidate principal retained a process after the bounded UID sweep",
        ))
    }

    #[cfg(not(unix))]
    fn require_quiescence(&self) -> std::io::Result<()> {
        Ok(())
    }

    /// Grants the already-created sandbox to the exact candidate group.
    #[cfg(unix)]
    fn prepare_writable_directory(&self, path: &Path) -> std::io::Result<()> {
        use std::os::unix::fs::PermissionsExt as _;

        if !path.is_absolute()
            || !self
                .writable_roots
                .iter()
                .any(|root| path.starts_with(root))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "candidate writable directory is outside the exact policy roots",
            ));
        }
        let status = Command::new(&self.launcher)
            .args(["-n", "--", "/usr/bin/chgrp"])
            .arg(self.group.as_ref())
            .arg(path)
            .status()?;
        if !status.success() {
            return Err(std::io::Error::other("cannot bind candidate sandbox group"));
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o2770))
    }

    #[cfg(not(unix))]
    fn prepare_writable_directory(&self, _path: &Path) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(any(windows, test))]
const WINDOWS_ARGV_TOKEN_PREFIX: &str = "hell-argv-v1";
#[cfg(any(windows, test))]
const WINDOWS_ARGV_HELPER_PREFIX_UTF16_LEN: usize = "hell-ci __release-argv-child ".len();
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
    decode_windows_argv_units(token)
        .map(|arguments| arguments.into_iter().map(OsString::from_wide).collect())
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

#[cfg(all(test, unix))]
mod candidate_launch_policy_tests {
    use super::*;

    #[test]
    fn posix_wrapper_uses_fixed_preservation_contract_and_trusted_adapter() {
        let launcher = fs::canonicalize("/usr/bin/true").unwrap();
        let adapter = std::env::current_exe().unwrap();
        let policy = CandidateLaunchPolicy::posix(
            launcher.clone(),
            adapter.clone(),
            "hellreltest".to_owned(),
            61_001,
            "hellreltest".to_owned(),
            vec![std::env::temp_dir()],
        )
        .unwrap();
        let mut command = Command::new("/usr/bin/true");
        command.env_clear().env("HOME", "/isolated/home");
        policy.wrap(&mut command).unwrap();
        assert_eq!(command.get_program(), launcher);
        let arguments = command.get_args().map(OsString::from).collect::<Vec<_>>();
        assert_eq!(arguments[0], "-n");
        assert_eq!(arguments[1], POSIX_RELEASE_CHILD_PRESERVE_ENVIRONMENT);
        assert_eq!(arguments[2], "-u");
        assert_eq!(arguments[3], "hellreltest");
        assert_eq!(arguments[4], "--");
        assert_eq!(arguments[5], adapter);
        assert_eq!(arguments[6], "__release-posix-child");
        assert_eq!(arguments[7], "/usr/bin/true");
        assert!(
            command.get_envs().any(|(name, value)| name == "HOME"
                && value == Some(std::ffi::OsStr::new("/isolated/home")))
        );
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

#[derive(Default)]
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
    let boundary_gaps = runtime_boundary_gaps(&observations);
    let interaction_gaps = runtime_interaction_gaps(&observations);
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
            diagnostic_sandbox_path_v1(observation, input.sandbox, input.script)
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
    original: ExecutableIdentity,
    #[cfg(unix)]
    handle: fs::File,
    #[cfg(unix)]
    original_identity: UnixExecutableIdentity,
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
    fn new(identity: &ExecutableIdentity) -> Result<Self, String> {
        let canonical = fs::canonicalize(&identity.path)
            .map_err(|error| format!("cannot canonicalize bound executable: {error}"))?;
        if canonical != identity.path {
            return Err("bound executable identity path is not canonical".to_owned());
        }
        let observed = sha256_file(&identity.path)
            .map_err(|error| format!("cannot hash bound executable: {error}"))?;
        if observed != identity.sha256 {
            return Err("bound executable digest differs before batch".to_owned());
        }
        #[cfg(unix)]
        {
            let handle = fs::File::open(&identity.path)
                .map_err(|error| format!("cannot retain bound executable handle: {error}"))?;
            let retained_identity =
                unix_executable_identity(&handle.metadata().map_err(|error| {
                    format!("cannot inspect retained executable handle: {error}")
                })?)?;
            let original_identity = unix_executable_identity(
                &fs::metadata(&identity.path)
                    .map_err(|error| format!("cannot inspect bound executable path: {error}"))?,
            )?;
            if retained_identity != original_identity {
                return Err("bound executable path differs from retained handle".to_owned());
            }
            Ok(Self {
                original: identity.clone(),
                handle,
                original_identity,
            })
        }
        #[cfg(not(unix))]
        {
            Ok(Self {
                original: identity.clone(),
            })
        }
    }

    fn execution_identity(&self) -> &ExecutableIdentity {
        &self.original
    }

    fn require_unchanged(&self) -> Result<(), String> {
        #[cfg(unix)]
        {
            let retained =
                unix_executable_identity(&self.handle.metadata().map_err(|error| {
                    format!("cannot recheck retained executable handle: {error}")
                })?)?;
            let canonical = fs::canonicalize(&self.original.path)
                .map_err(|error| format!("cannot recanonicalize bound executable: {error}"))?;
            let current = unix_executable_identity(
                &fs::metadata(&canonical)
                    .map_err(|error| format!("cannot recheck bound executable path: {error}"))?,
            )?;
            if canonical != self.original.path
                || current != self.original_identity
                || retained != self.original_identity
            {
                return Err("bound executable identity changed during batch".to_owned());
            }
            Ok(())
        }
        #[cfg(not(unix))]
        {
            let original = sha256_file(&self.original.path)
                .map_err(|error| format!("cannot rehash original executable: {error}"))?;
            (original == self.original.sha256)
                .then_some(())
                .ok_or_else(|| "bound executable digest changed during batch".to_owned())
        }
    }

    fn finish(&self) -> Result<(), String> {
        self.require_unchanged()?;
        let original = sha256_file(&self.original.path)
            .map_err(|error| format!("cannot hash original executable after batch: {error}"))?;
        (original == self.original.sha256)
            .then_some(())
            .ok_or_else(|| "bound executable digest changed during batch".to_owned())
    }
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
        timed.report.oracle.identity = oracle.original.clone();
        timed.report.candidate.identity = candidate.original.clone();
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
    let (path, sha256) = resolve_and_hash(path)?;
    probe_identity(path, sha256, role, false)
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
    let (path, sha256) = resolve_and_hash(path)?;
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
    let identity = probe_identity(path, sha256, role, true)?;
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
    let canonical = fs::canonicalize(&identity.path)?;
    if canonical != identity.path {
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
    if projection.is_some() {
        mismatches.retain(|mismatch| mismatch.kind != MismatchKind::Stderr);
    }
    (
        projection.unwrap_or(DifferentialComparisonProjection::Exact),
        mismatches,
    )
}

pub(crate) fn reviewed_runtime_failure_stderr_builtin(
    case: &DifferentialCase,
) -> Option<BuiltinId> {
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

fn reviewed_runtime_failure_stderr_projection(
    case: &DifferentialCase,
    oracle: &Observation,
    candidate: &Observation,
) -> Option<DifferentialComparisonProjection> {
    let builtin = reviewed_runtime_failure_stderr_builtin(case)?;
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
    let mut stderr = diagnostic_sandbox_path_v1(&stderr, &sandbox.path, &script);
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

fn diagnostic_sandbox_path_v1(stderr: &[u8], sandbox: &Path, script: &Path) -> Vec<u8> {
    let sandbox = sandbox.to_string_lossy();
    let script = script.to_string_lossy();
    scrub_diagnostic_path_bytes(stderr, sandbox.as_bytes(), script.as_bytes())
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

fn scrub_diagnostic_path_bytes(stderr: &[u8], _sandbox: &[u8], script: &[u8]) -> Vec<u8> {
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
    for line in scrubbed.split_inclusive(|byte| *byte == b'\n') {
        if let Some((prefix, suffix)) = structured_diagnostic_path(line, script) {
            output.extend_from_slice(prefix);
            output.extend_from_slice(marker);
            output.extend_from_slice(suffix);
        } else {
            output.extend_from_slice(line);
        }
    }
    output
}

fn structured_diagnostic_path<'a>(
    line: &'a [u8],
    script: &[u8],
) -> Option<(&'static [u8], &'a [u8])> {
    const HELPER_PREFIX: &[u8] = b"unknown helper subcommand ";
    const ORACLE_PARSE_PREFIX: &[u8] = b"hell: Parse error: ";
    if let Some(suffix) = line
        .strip_prefix(script)
        .filter(|suffix| diagnostic_path_suffix(suffix))
    {
        return Some((b"", suffix));
    }
    for prefix in [HELPER_PREFIX, ORACLE_PARSE_PREFIX] {
        if let Some(suffix) = line
            .strip_prefix(prefix)
            .and_then(|line| line.strip_prefix(script))
            .filter(|suffix| diagnostic_path_suffix(suffix))
        {
            return Some((prefix, suffix));
        }
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

fn resolve_and_hash(path: &Path) -> std::io::Result<(PathBuf, Digest)> {
    let path = fs::canonicalize(path)?;
    let sha256 = sha256_file(&path)?;
    Ok((path, sha256))
}

fn probe_identity(
    path: PathBuf,
    sha256: Digest,
    role: ExecutableRole,
    require_candidate_build_info: bool,
) -> std::io::Result<ExecutableIdentity> {
    let reported_version = probe_lines(&path, "--version")?;
    let reported_version: Arc<str> = reported_version
        .first()
        .ok_or_else(|| std::io::Error::other("--version produced no output"))?
        .clone();
    let build_info = if role == ExecutableRole::Candidate {
        let parsed = probe_lines(&path, "--build-info").and_then(|lines| {
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
    let observed_sha256 = sha256_file(&path)?;
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

fn probe_lines(path: &Path, argument: &str) -> std::io::Result<Vec<Arc<str>>> {
    let mut command = Command::new(path);
    scrub_ci_authority_environment(&mut command);
    command.arg(argument);
    let output = run_supervised_command(&mut command, &[], Duration::from_secs(5))?;
    if output.timed_out {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "version probe exceeded five seconds",
        ));
    }
    if !output.status.success() {
        return Err(std::io::Error::other(format!(
            "{argument} failed with status {:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr.mismatch_bytes())
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

struct CapturedProcess {
    status: ExitStatus,
    stdout: BoundedCapture,
    stderr: BoundedCapture,
    timed_out: bool,
    duration: Duration,
}

/// Result of a structured host command run under process-tree supervision.
#[derive(Clone, Debug)]
pub struct SupervisedOutput {
    pub status: ExitStatus,
    pub stdout: BoundedCapture,
    pub stderr: BoundedCapture,
    pub timed_out: bool,
    pub termination: Option<TerminationReport>,
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
    struct QuiescenceGuard(Option<CandidateLaunchPolicy>);
    impl Drop for QuiescenceGuard {
        fn drop(&mut self) {
            if let Some(policy) = self.0.take() {
                let _ = policy.require_quiescence();
            }
        }
    }

    let launch_policy = CANDIDATE_LAUNCH_POLICY.with(|slot| slot.borrow().clone());
    if let Some(policy) = &launch_policy {
        policy.wrap(command)?;
    }
    let mut quiescence = QuiescenceGuard(launch_policy);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = SupervisedChild::spawn(command)?;

    let stdout = child
        .take_stdout()
        .ok_or_else(|| std::io::Error::other("piped child stdout was unavailable"))?;
    let stderr = child
        .take_stderr()
        .ok_or_else(|| std::io::Error::other("piped child stderr was unavailable"))?;
    let stdout_reader = std::thread::spawn(move || read_bounded(stdout));
    let stderr_reader = std::thread::spawn(move || read_bounded(stderr));
    let stdin = child.take_stdin();
    let input = input.to_vec();
    let stdin_writer = std::thread::spawn(move || {
        if let Some(mut stdin) = stdin {
            stdin.write_all(&input)?;
        }
        Ok::<(), std::io::Error>(())
    });

    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| std::io::Error::other("process deadline overflowed"))?;
    let (status, timed_out, termination) = match child.wait_until(deadline)? {
        WaitOutcome::Exited(status) => {
            // A leader may exit while descendants retain pipe handles. Close
            // the complete group/job before joining readers, while preserving
            // the leader's status as the observed result.
            let (_, cleanup) = child.terminate()?;
            (status, false, Some(cleanup))
        }
        WaitOutcome::DeadlineExpired => {
            let (status, termination) = child.terminate()?;
            if !termination.reaped {
                return Err(std::io::Error::other(
                    "timed-out process tree was not completely reaped",
                ));
            }
            (status, true, Some(termination))
        }
    };
    if let Some(policy) = quiescence.0.take() {
        policy.require_quiescence()?;
    }
    let stdout = join_reader(stdout_reader, "stdout")?;
    let stderr = join_reader(stderr_reader, "stderr")?;
    stdin_writer
        .join()
        .map_err(|_| std::io::Error::other("stdin writer thread panicked"))??;
    let output = SupervisedOutput {
        status,
        stdout,
        stderr,
        timed_out,
        termination,
    };
    Ok(output)
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

fn join_reader(
    reader: std::thread::JoinHandle<std::io::Result<BoundedCapture>>,
    stream: &str,
) -> std::io::Result<BoundedCapture> {
    reader
        .join()
        .map_err(|_| std::io::Error::other(format!("{stream} reader thread panicked")))?
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
    use super::{
        Command, WINDOWS_ARGV_TOKEN_LIMIT, WINDOWS_ARGV_TOKEN_PREFIX,
        configure_evidence_native_environment, configure_release_child_environment,
        decode_windows_argv_units, encode_windows_argv_units,
    };

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
        diagnostic_path_separator_v1, parse_diagnostic_observation, scrub_diagnostic_path_bytes,
    };
    use crate::{ExecutableRole, ExecutionProfile};
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
        let scrubbed = scrub_diagnostic_path_bytes(escaped, sandbox, script);
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
            ),
            br"<SANDBOX>\main.hell:1:17: error[H0402]"
        );
        assert_eq!(
            scrub_diagnostic_path_bytes(
                br#"SrcSpan "/tmp/sandbox/main.hell" 1 17 1 33"#,
                br"/tmp/sandbox",
                br"/tmp/sandbox/main.hell",
            ),
            br#"SrcSpan "<SANDBOX>/main.hell" 1 17 1 33"#
        );

        for near_match in [
            br#"SrcSpan "C:\\work\\sandbox\\main.hellish" 1 17"#.as_slice(),
            br#"SrcSpan "C:\\work\\sandbox-other\\main.hell" 1 17"#.as_slice(),
            br"unquoted C:\\work\\sandbox\\main.hell 1 17".as_slice(),
        ] {
            assert_eq!(
                scrub_diagnostic_path_bytes(near_match, sandbox, script),
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
            scrub_diagnostic_path_bytes(message, sandbox, script),
            message
        );
        let diagnostic = br"C:\work\sandbox\main.hell:4:2: error[H0200]";
        let once = scrub_diagnostic_path_bytes(diagnostic, sandbox, script);
        assert_eq!(once, br"<SANDBOX>\main.hell:4:2: error[H0200]");
        assert_eq!(
            scrub_diagnostic_path_bytes(
                br"unknown helper subcommand C:\work\sandbox\main.hell",
                sandbox,
                script
            ),
            br"unknown helper subcommand <SANDBOX>\main.hell"
        );
        assert_eq!(
            scrub_diagnostic_path_bytes(
                br"hell: Parse error: C:\work\sandbox\main.hell:2:1: Parse error: ;",
                sandbox,
                script
            ),
            br"hell: Parse error: <SANDBOX>\main.hell:2:1: Parse error: ;"
        );
        assert_eq!(
            scrub_diagnostic_path_bytes(
                br"hell: Parse error: C:\work\sandbox\main.hellish:2:1",
                sandbox,
                script
            ),
            br"hell: Parse error: C:\work\sandbox\main.hellish:2:1"
        );
        assert_eq!(
            scrub_diagnostic_path_bytes(&once, br"<SANDBOX>", br"<SANDBOX>\main.hell"),
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
    fn ord_targets_require_both_boolean_paths_for_every_registry_instance() {
        let committed = committed_differential_cases();
        for builtin in ["Ord.lt", "Ord.gt"] {
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
                                target.builtin.as_ref() == builtin
                                    && target.expected_instance_target.as_deref() == Some(instance)
                                    && target.expected_typed_result_sha256 == Some(digest)
                            })
                        })
                    });
                    let error = validate_runtime_obligation_coverage(&cases)
                        .expect_err("removing an Ord boolean path must reopen its scope");
                    let cell = error
                        .split("; ")
                        .find(|cell| cell.starts_with(&format!("{builtin}/PureRuntime:")))
                        .unwrap_or_else(|| {
                            panic!("missing {builtin} after removing {instance}/{result}")
                        });
                    assert!(
                        cell.contains(&format!("{instance}:missing=["))
                            && cell.contains("bool-partition=true"),
                        "{cell}"
                    );
                }
            }
        }
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
