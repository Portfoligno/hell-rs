use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static FIXTURE_ID: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let id = FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "hell-ci-standalone-{label}-{}-{id}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("standalone fixture root must be created");
        let root = fs::canonicalize(root).expect("standalone fixture root must be canonicalized");
        Self { root }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).expect("standalone fixture root must be removed");
    }
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn run_cli(arguments: &[&OsStr]) -> hell_testkit::SupervisedOutput {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
    command.current_dir(repository_root()).args(arguments);
    hell_testkit::run_supervised_command(&mut command, &[], Duration::from_secs(30))
        .expect("standalone hell-ci command must execute under supervision")
}

fn run_git(root: &Path, arguments: &[&str]) {
    let mut command = Command::new("git");
    command.current_dir(root).args(arguments);
    let output = hell_testkit::run_supervised_command(&mut command, &[], Duration::from_secs(30))
        .expect("fixture git command must execute under supervision");
    assert!(
        output.status.success() && !output.timed_out,
        "fixture git command failed: {}",
        String::from_utf8_lossy(
            output
                .stderr
                .complete
                .as_deref()
                .unwrap_or(&output.stderr.prefix)
        )
    );
}

fn stderr(output: &hell_testkit::SupervisedOutput) -> String {
    String::from_utf8_lossy(
        output
            .stderr
            .complete
            .as_deref()
            .unwrap_or(&output.stderr.prefix),
    )
    .into_owned()
}

#[test]
fn action_metadata_update_recomputes_the_reviewed_normalization() {
    let fixture = Fixture::new("action-metadata");
    let output = fixture.path("metadata.json");
    let lock = repository_root().join("ci/actions/metadata-v1.json");
    let updated = run_cli(&[
        OsStr::new("protocol"),
        OsStr::new("update-action-metadata"),
        OsStr::new("--lock"),
        lock.as_os_str(),
        OsStr::new("--output"),
        output.as_os_str(),
    ]);
    assert!(
        updated.status.success() && !updated.timed_out,
        "action metadata update failed: {}",
        stderr(&updated)
    );
    let generated: serde_json::Value = serde_json::from_slice(
        &fs::read(&output).expect("generated action metadata must be readable"),
    )
    .expect("generated action metadata must be JSON");
    let committed: serde_json::Value = serde_json::from_slice(
        &fs::read(&lock).expect("committed action metadata lock must be readable"),
    )
    .expect("committed action metadata lock must be JSON");
    assert_eq!(generated, committed);
    assert_eq!(
        generated["actions"][0]["normalizedMetadataSha256"].as_str(),
        Some("0058cf85d92a664ec8d4aac8725042659fc50137378dff224e4e1bf093544dbc")
    );

    let invalid_lock = fixture.path("invalid-lock.json");
    let document = fs::read_to_string(&lock).expect("action metadata lock must be UTF-8");
    fs::write(
        &invalid_lock,
        document.replacen(
            "0058cf85d92a664ec8d4aac8725042659fc50137378dff224e4e1bf093544dbc",
            "1058cf85d92a664ec8d4aac8725042659fc50137378dff224e4e1bf093544dbc",
            1,
        ),
    )
    .expect("invalid action metadata lock must be written");
    let rejected = run_cli(&[
        OsStr::new("protocol"),
        OsStr::new("update-action-metadata"),
        OsStr::new("--lock"),
        invalid_lock.as_os_str(),
        OsStr::new("--output"),
        fixture.path("rejected.json").as_os_str(),
    ]);
    assert!(!rejected.status.success() && !rejected.timed_out);
    assert!(stderr(&rejected).contains("normalized metadata digest differs"));
}

#[test]
fn repository_text_check_uses_the_bounded_tracked_inventory() {
    let fixture = Fixture::new("repository-text");
    run_git(&fixture.root, &["init", "--quiet"]);
    fs::write(fixture.path("good.txt"), b"bounded text\n")
        .expect("valid text fixture must be written");
    fs::write(fixture.path("bad.md"), b"missing newline")
        .expect("invalid text fixture must be written");
    fs::write(fixture.path("binary.bin"), [0_u8, 1, 2, 3]).expect("binary fixture must be written");
    run_git(
        &fixture.root,
        &["add", "--", "good.txt", "bad.md", "binary.bin"],
    );

    let arguments = [
        OsStr::new("repository"),
        OsStr::new("check-text-files"),
        OsStr::new("--repository-root"),
        fixture.root.as_os_str(),
    ];
    let rejected = run_cli(&arguments);
    assert!(!rejected.status.success() && !rejected.timed_out);
    let detail = stderr(&rejected);
    assert!(detail.contains("tracked text file lacks a trailing newline: bad.md"));
    assert!(!detail.contains("binary.bin"));

    fs::write(fixture.path("bad.md"), b"newline restored\n")
        .expect("repaired text fixture must be written");
    let admitted = run_cli(&arguments);
    assert!(
        admitted.status.success() && !admitted.timed_out,
        "repository text check rejected valid files: {}",
        stderr(&admitted)
    );
}

#[test]
fn standalone_commands_reject_duplicate_and_untyped_options() {
    for arguments in [
        vec![
            OsStr::new("repository"),
            OsStr::new("check-text-files"),
            OsStr::new("--repository-root"),
            OsStr::new("."),
            OsStr::new("--repository-root"),
            OsStr::new("."),
        ],
        vec![
            OsStr::new("protocol"),
            OsStr::new("update-action-metadata"),
            OsStr::new("--unknown"),
            OsStr::new("value"),
        ],
    ] {
        let output = run_cli(&arguments);
        assert!(!output.status.success() && !output.timed_out);
    }
}
