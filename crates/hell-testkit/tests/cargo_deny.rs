#[cfg(unix)]
use std::ffi::OsString;
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::path::Path;
#[cfg(unix)]
use std::process::Command;
#[cfg(unix)]
use std::sync::Mutex;
#[cfg(unix)]
use std::time::Duration;

#[cfg(unix)]
static CARGO_PROBE_LOCK: Mutex<()> = Mutex::new(());

#[cfg(unix)]
fn bounded_output(command: &mut Command, label: &str) -> hell_testkit::SupervisedOutput {
    let output = hell_testkit::run_supervised_command(command, &[], Duration::from_secs(30))
        .unwrap_or_else(|error| panic!("{label}: {error}"));
    assert!(!output.timed_out, "{label}: command timed out");
    assert!(!output.stdout.truncated, "{label}: stdout was truncated");
    assert!(!output.stderr.truncated, "{label}: stderr was truncated");
    output
}

#[cfg(unix)]
fn compiled_helper() -> std::path::PathBuf {
    fs::canonicalize(env!("CARGO_BIN_EXE_hell-test-helper"))
        .expect("canonical compiled hell-test-helper")
}

#[cfg(unix)]
fn remove_probe_log(helper: &Path) {
    let log = hell_testkit::cargo_probe_log_path(helper);
    match fs::remove_file(log) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!("cannot remove Cargo probe log: {error}"),
    }
}

#[cfg(unix)]
fn require_probe_log_redirects_rejected(helper: &Path) {
    use std::os::unix::fs::symlink;

    let outside = helper.with_extension("cargo-probe-outside");
    let log = hell_testkit::cargo_probe_log_path(helper);
    fs::write(&outside, b"outside\n").expect("Cargo probe outside fixture");
    fs::hard_link(&outside, &log).expect("Cargo probe hard-link fixture");
    let mut command = Command::new(helper);
    command.arg("fetch").env("CARGO", helper);
    let output = bounded_output(&mut command, "hard-linked Cargo probe log rejection");
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(fs::read(&outside).unwrap(), b"outside\n");
    fs::remove_file(&log).unwrap();
    symlink(&outside, &log).expect("Cargo probe symlink fixture");
    let mut command = Command::new(helper);
    command.arg("fetch").env("CARGO", helper);
    let output = bounded_output(&mut command, "redirected Cargo probe log rejection");
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(fs::read(&outside).unwrap(), b"outside\n");
    fs::remove_file(log).unwrap();
    fs::remove_file(outside).unwrap();
}

#[cfg(unix)]
#[test]
fn compiled_cargo_probe_handles_versions_and_records_exact_bounded_argv() {
    use std::os::unix::ffi::OsStringExt as _;

    let _guard = CARGO_PROBE_LOCK.lock().expect("Cargo probe test lock");
    let helper = compiled_helper();
    remove_probe_log(&helper);
    for version_argument in ["--version", "-V", "-vV"] {
        let mut command = Command::new(&helper);
        command.arg(version_argument).env("CARGO", &helper);
        let output = bounded_output(&mut command, "compiled Cargo probe version query");
        assert!(output.status.success());
        assert!(
            String::from_utf8(
                output
                    .stdout
                    .complete
                    .expect("complete Cargo version output")
            )
            .expect("Cargo probe version is UTF-8")
            .starts_with("cargo 1.97.0 ")
        );
    }
    assert!(!hell_testkit::cargo_probe_log_path(&helper).exists());

    let exact_arguments = vec![
        OsString::from("fetch"),
        OsString::from("--frozen"),
        OsString::from_vec(b"non-utf8-\xff".to_vec()),
    ];
    let mut command = Command::new(&helper);
    command.args(&exact_arguments).env("CARGO", &helper);
    let output = bounded_output(&mut command, "compiled Cargo probe invocation");
    assert_eq!(output.status.code(), Some(42));
    assert_eq!(
        hell_testkit::read_cargo_probe_invocations(&helper).expect("bounded Cargo probe log"),
        [exact_arguments]
    );
    remove_probe_log(&helper);

    let mut oversized = b"hell-cargo-probe-v1\0".to_vec();
    oversized.extend_from_slice(&9_u32.to_le_bytes());
    for _ in 0..9 {
        oversized.extend_from_slice(&(8_u32 * 1024).to_le_bytes());
        oversized.resize(oversized.len() + 8 * 1024, b'X');
    }
    fs::write(hell_testkit::cargo_probe_log_path(&helper), oversized)
        .expect("oversized Cargo probe record fixture");
    assert!(hell_testkit::read_cargo_probe_invocations(&helper).is_err());
    remove_probe_log(&helper);
    require_probe_log_redirects_rejected(&helper);
}

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::{OsStr, OsString};
    use std::fs;
    use std::os::unix::fs::MetadataExt as _;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    fn standard_cargo_home() -> PathBuf {
        std::env::var_os("CARGO_HOME").map_or_else(
            || {
                PathBuf::from(
                    std::env::var_os("HOME").expect("standard HOME must locate Cargo installs"),
                )
                .join(".cargo")
            },
            PathBuf::from,
        )
    }

    fn pinned_cargo_deny() -> PathBuf {
        let invocation = standard_cargo_home().join("bin/cargo-deny");
        let metadata = fs::symlink_metadata(&invocation).expect("installed pinned cargo-deny");
        assert!(metadata.is_file() && !metadata.file_type().is_symlink());
        let canonical = fs::canonicalize(&invocation).expect("canonical pinned cargo-deny");
        assert_eq!(canonical.file_name(), Some(OsStr::new("cargo-deny")));
        canonical
    }

    fn workspace_metadata_fixture(root: &Path, path: &Path) {
        let invocation = PathBuf::from(env!("CARGO"));
        assert!(invocation.is_absolute() && invocation.file_name() == Some(OsStr::new("cargo")));
        let canonical = fs::canonicalize(&invocation).expect("canonical Cargo identity");
        let initial = fs::metadata(&canonical).expect("Cargo identity metadata");
        let initial_sha = hell_testkit::sha256_file(&canonical).expect("Cargo identity digest");
        let mut command = Command::new(&invocation);
        command.args([
            "metadata",
            "--locked",
            "--all-features",
            "--format-version",
            "1",
        ]);
        command.current_dir(root);
        let metadata = super::bounded_output(&mut command, "trusted Cargo metadata");
        assert!(metadata.status.success());
        assert_eq!(
            fs::canonicalize(&invocation).expect("revalidated Cargo invocation"),
            canonical
        );
        let final_identity = fs::metadata(&canonical).expect("revalidated Cargo identity");
        assert_eq!(initial.dev(), final_identity.dev());
        assert_eq!(initial.ino(), final_identity.ino());
        assert_eq!(
            initial_sha,
            hell_testkit::sha256_file(&canonical).expect("revalidated Cargo digest")
        );
        fs::write(
            path,
            metadata.stdout.complete.expect("complete Cargo metadata"),
        )
        .expect("bound Cargo metadata fixture");
    }

    fn require_pinned_cargo_deny_version(cargo_deny: &Path) {
        let mut command = Command::new(cargo_deny);
        command.arg("--version");
        let version = super::bounded_output(&mut command, "pinned cargo-deny version");
        assert!(version.status.success());
        assert_eq!(
            String::from_utf8(
                version
                    .stdout
                    .complete
                    .expect("complete cargo-deny version")
            )
            .expect("cargo-deny version is UTF-8")
            .trim(),
            "cargo-deny 0.20.2"
        );
    }

    #[test]
    fn pinned_cargo_deny_uses_bound_metadata_after_nonfatal_frozen_fetches() {
        let _guard = super::CARGO_PROBE_LOCK
            .lock()
            .expect("Cargo probe test lock");
        let helper = super::compiled_helper();
        super::remove_probe_log(&helper);

        let root = fs::canonicalize(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .expect("workspace crates directory")
                .parent()
                .expect("workspace root"),
        )
        .expect("canonical workspace root");
        let temporary = fs::canonicalize(std::env::temp_dir())
            .expect("canonical temporary directory")
            .join(format!(
                "hell-cargo-deny-metadata-path-{}",
                std::process::id()
            ));
        fs::create_dir(&temporary).expect("private metadata fixture directory");
        let metadata_path = temporary.join("metadata.json");
        workspace_metadata_fixture(&root, &metadata_path);

        let cargo_deny = pinned_cargo_deny();
        let initial_identity = fs::metadata(&cargo_deny).expect("pinned cargo-deny identity");
        let initial_sha = hell_testkit::sha256_file(&cargo_deny).expect("pinned cargo-deny digest");
        require_pinned_cargo_deny_version(&cargo_deny);

        let mut command = Command::new(&cargo_deny);
        command.args(["--metadata-path"]);
        command.arg(&metadata_path);
        command.args(["--frozen", "--all-features", "check", "bans"]);
        command.current_dir(&root);
        command.env("CARGO", &helper);
        let output = super::bounded_output(&mut command, "pinned cargo-deny check");
        assert!(
            output.status.success(),
            "bound metadata must survive nonfatal fetches: {}",
            String::from_utf8_lossy(
                output
                    .stderr
                    .complete
                    .as_deref()
                    .expect("complete cargo-deny stderr")
            )
        );
        let final_identity =
            fs::symlink_metadata(&cargo_deny).expect("revalidated cargo-deny path identity");
        assert!(final_identity.is_file() && !final_identity.file_type().is_symlink());
        assert_eq!(
            fs::canonicalize(&cargo_deny).expect("revalidated canonical cargo-deny path"),
            cargo_deny
        );
        assert_eq!(initial_identity.dev(), final_identity.dev());
        assert_eq!(initial_identity.ino(), final_identity.ino());
        assert_eq!(
            initial_sha,
            hell_testkit::sha256_file(&cargo_deny).expect("revalidated cargo-deny digest")
        );

        let invocations =
            hell_testkit::read_cargo_probe_invocations(&helper).expect("bounded Cargo probe log");
        assert!(!invocations.is_empty());
        let exact_fetch = vec![
            OsString::from("fetch"),
            OsString::from("--manifest-path"),
            root.join("Cargo.toml").into_os_string(),
            OsString::from("--frozen"),
            OsString::from("--locked"),
            OsString::from("--offline"),
        ];
        assert!(invocations.contains(&exact_fetch), "{invocations:?}");
        assert!(
            invocations
                .iter()
                .flatten()
                .all(|argument| argument != "metadata")
        );
        assert!(String::from_utf8_lossy(&output.stderr).contains("failed to fetch crates"));

        super::remove_probe_log(&helper);
        fs::remove_dir_all(temporary).expect("remove metadata fixture directory");
    }
}
