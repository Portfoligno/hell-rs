#![cfg(unix)]

use hell_testkit::*;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "hell-bound-host-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        Self(root.canonicalize().unwrap())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn helper() -> PathBuf {
    fs::canonicalize(env!("CARGO_BIN_EXE_hell-test-helper")).unwrap()
}
fn binding(path: &Path) -> BoundProgramInvocation {
    BoundProgramInvocation::new(path.to_owned(), path.to_owned()).unwrap()
}

fn process_authority(role: PosixProcessToolRole, path: &str) -> PosixExecutableAuthority {
    let invocation = PathBuf::from(path);
    let canonical = fs::canonicalize(&invocation).unwrap();
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
    let executable = fs::canonicalize("/usr/bin/true").unwrap();
    let metadata = fs::metadata(&executable).unwrap();
    let rustup = root.join("rustup");
    std::os::unix::fs::symlink("/usr/bin/false", &rustup).unwrap();
    let rustup_canonical = fs::canonicalize(&rustup).unwrap();
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
            "hellhostfixture".to_owned(),
            61321,
            61321,
            vec![61321],
            "hellhostfixture".to_owned(),
        )
        .unwrap(),
        vec![root.to_owned()],
    )
    .unwrap()
}

#[test]
fn bound_host_suppresses_candidate_policy_and_restores_it_on_success_and_error() {
    let fixture = Fixture::new();
    let policy = policy(&fixture.0);
    let helper = helper();
    let bound = binding(&helper);
    with_candidate_launch_policy(&policy, || {
        assert!(candidate_launch_policy_is_installed_for_integration());
        let result = run_supervised_host_command_with_bound_program(
            Command::new(&helper).arg("echo-stdin"),
            b"host-output",
            Duration::from_secs(10),
            &bound,
        )
        .unwrap();
        assert!(result.status.success());
        assert_eq!(result.stdout.retained_bytes(), b"host-output");
        assert!(result.memcordon_projection.is_none());
        assert!(candidate_launch_policy_is_installed_for_integration());
        let error = run_supervised_host_command_with_bound_program(
            &mut Command::new("/usr/bin/false"),
            &[],
            Duration::from_secs(10),
            &bound,
        );
        assert!(error.is_err());
        assert!(candidate_launch_policy_is_installed_for_integration());
    });
    assert!(!candidate_launch_policy_is_installed_for_integration());
}

#[test]
fn bound_host_preserves_nonzero_status_and_bounded_timeout() {
    let helper = helper();
    let bound = binding(&helper);
    let result = run_supervised_host_command_with_bound_program(
        Command::new(&helper).arg("unknown-fixture-command"),
        &[],
        Duration::from_secs(10),
        &bound,
    )
    .unwrap();
    assert!(!result.status.success());
    assert!(!result.timed_out);
    let result = run_supervised_host_command_with_bound_program(
        Command::new(&helper).args(["sleep-ms", "5000"]),
        &[],
        Duration::from_millis(100),
        &bound,
    );
    match result {
        Ok(output) => {
            assert!(output.timed_out);
            assert!(output.termination.is_some());
        }
        Err(error) => {
            assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
            let receipt =
                retained_termination_receipt(&error).expect("deadline retains cleanup ownership");
            let snapshot = receipt.wait_until(std::time::Instant::now() + Duration::from_secs(10));
            assert!(matches!(
                snapshot.state,
                RetainedTerminationState::Completed(_)
            ));
            assert!(snapshot.lifecycle_idle);
        }
    }
}

#[test]
fn bound_host_rejects_changed_executable_before_spawn() {
    let fixture = Fixture::new();
    let path = fixture.0.join("helper");
    fs::copy(helper(), &path).unwrap();
    let bound = binding(&path);
    fs::rename(&path, fixture.0.join("original-helper")).unwrap();
    fs::copy(helper(), &path).unwrap();
    assert!(
        run_supervised_host_command_with_bound_program(
            &mut Command::new(path),
            &[],
            Duration::from_secs(10),
            &bound
        )
        .is_err()
    );
}
