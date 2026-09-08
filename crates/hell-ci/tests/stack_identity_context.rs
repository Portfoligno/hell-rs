#![cfg(unix)]

use hell_ci::{
    CommandResult, CommandTerminationResult, TrustedStackIdentityQuery,
    validate_stack_identity_result,
};
use hell_testkit::*;
use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "hell-stack-identity-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path.canonicalize().unwrap())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn process_authority(role: PosixProcessToolRole, path: &str) -> PosixExecutableAuthority {
    let invocation = PathBuf::from(path);
    let canonical = invocation.canonicalize().unwrap();
    let metadata = fs::metadata(&canonical).unwrap();
    PosixExecutableAuthority::new(
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
    )
}

fn policy(root: &Path) -> CandidateLaunchPolicy {
    // Deliberately nonfunctional launch tools: the fixed host identity query
    // must not invoke them, and must leave this policy installed afterward.
    let executable = fs::canonicalize("/usr/bin/true").unwrap();
    let metadata = fs::metadata(&executable).unwrap();
    let rustup = root.join("rustup");
    std::os::unix::fs::symlink("/usr/bin/false", &rustup).unwrap();
    let rustup_canonical = rustup.canonicalize().unwrap();
    let rustup_metadata = fs::metadata(&rustup_canonical).unwrap();
    let process = PosixProcessAuthorities::new(
        process_authority(PosixProcessToolRole::Sudo, "/usr/bin/true"),
        process_authority(PosixProcessToolRole::Identity, "/usr/bin/id"),
        process_authority(PosixProcessToolRole::Inventory, "/bin/ps"),
        process_authority(PosixProcessToolRole::Terminator, "/usr/bin/pkill"),
    )
    .unwrap();
    CandidateLaunchPolicy::posix_with_process_authorities(
        PathBuf::from("/usr/bin/true"),
        process,
        PosixLaunchAuthorities::new(
            executable.clone(),
            sha256_file(&executable).unwrap(),
            executable.clone(),
            executable.clone(),
            sha256_file(&executable).unwrap(),
            PosixCargoSourceAuthority::Native {
                cargo: PosixCanonicalExecutableIdentity::new(
                    executable,
                    metadata.dev(),
                    metadata.ino(),
                ),
                standard_rustup: PosixStandardExecutableIdentity::new(
                    rustup,
                    rustup_canonical,
                    rustup_metadata.dev(),
                    rustup_metadata.ino(),
                ),
            },
        ),
        PosixCandidateIdentity::new(
            "hellstackfixture".to_owned(),
            61321,
            61321,
            vec![61321],
            "hellstackfixture".to_owned(),
        )
        .unwrap(),
        vec![root.to_owned()],
    )
    .unwrap()
}

#[test]
fn fixed_stack_query_uses_bound_host_directory_and_restores_candidate_policy() {
    let fixture = Fixture::new();
    let directory = fixture.0.join("trusted-directory");
    fs::create_dir(&directory).unwrap();
    let query = TrustedStackIdentityQuery::bind_native_fixture(&directory).unwrap();
    let policy = policy(&fixture.0);
    with_candidate_launch_policy(&policy, || {
        assert!(candidate_launch_policy_is_installed_for_integration());
        let result = query.run().unwrap();
        assert!(result.status.success(), "{:?}", result.stderr);
        assert!(!result.timed_out);
        assert!(result.stdout.is_empty());
        assert!(candidate_launch_policy_is_installed_for_integration());
        fs::rename(&directory, fixture.0.join("retained-original")).unwrap();
        fs::create_dir(&directory).unwrap();
        assert!(query.run().unwrap_err().contains("directory changed"));
        assert!(candidate_launch_policy_is_installed_for_integration());
    });
    assert!(!candidate_launch_policy_is_installed_for_integration());
}

fn result(code: i32, timeout: bool, stdout: &[u8]) -> CommandResult {
    CommandResult {
        status: std::process::ExitStatus::from_raw(code << 8),
        duration: Duration::from_millis(1),
        timed_out: timeout,
        stdout: stdout.to_vec(),
        stderr: b"original diagnostic\n".to_vec(),
        stdout_truncated: false,
        stderr_truncated: false,
        stdout_bytes: stdout.len() as u64,
        stderr_bytes: b"original diagnostic\n".len() as u64,
        stdout_sha256: sha256_bytes(stdout),
        stderr_sha256: sha256_bytes(b"original diagnostic\n"),
        termination: CommandTerminationResult {
            cleanup_id: Some(1),
            forced: false,
            reaped: true,
            candidate_quiescence_complete: true,
        },
        phase_timings: Vec::new(),
    }
}

#[test]
fn stack_identity_retains_version_status_timeout_and_capture_failures() {
    assert_eq!(
        validate_stack_identity_result(result(0, false, b"3.11.1\n")).unwrap(),
        "3.11.1"
    );
    assert!(
        validate_stack_identity_result(result(0, false, b"3.11.2\n"))
            .unwrap_err()
            .contains("version differs")
    );
    assert!(
        validate_stack_identity_result(result(1, false, b"3.11.1\n"))
            .unwrap_err()
            .contains("status Some(1)")
    );
    assert!(
        validate_stack_identity_result(result(0, true, b"3.11.1\n"))
            .unwrap_err()
            .contains("timedOut=true")
    );
    let mut truncated = result(0, false, b"3.11.1\n");
    truncated.stdout_truncated = true;
    assert!(
        validate_stack_identity_result(truncated)
            .unwrap_err()
            .contains("output bounds")
    );
}

#[test]
fn builder_stack_version_uses_the_same_adapter_directory_as_build_and_path() {
    hell_ci::verify_native_stack_command_policy().unwrap();
}
