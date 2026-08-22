use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static FIXTURE_ID: AtomicU64 = AtomicU64::new(0);
const WORKFLOWS: [&str; 6] = [
    "ci.yml",
    "mutation.yml",
    "nightly.yml",
    "regression-corpus.yml",
    "regression-subject.yml",
    "release.yml",
];

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let id = FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "hell-ci-protocol-workflow-{label}-{}-{id}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("protocol fixture root must be created");
        Self { root }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn run(arguments: &[&OsStr]) -> hell_testkit::SupervisedOutput {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
    command.current_dir(repository_root()).args(arguments);
    hell_testkit::run_supervised_command(&mut command, &[], Duration::from_secs(30))
        .expect("protocol command must execute under supervision")
}

fn protocol_check(workflows: &Path, report: &Path) -> hell_testkit::SupervisedOutput {
    run(&[
        OsStr::new("protocol"),
        OsStr::new("check"),
        OsStr::new("--manifest"),
        OsStr::new("ci/protocol/v1.toml"),
        OsStr::new("--repository-root"),
        OsStr::new("."),
        OsStr::new("--workflows"),
        workflows.as_os_str(),
        OsStr::new("--report"),
        report.as_os_str(),
    ])
}

fn protocol_project(output: &Path) -> hell_testkit::SupervisedOutput {
    run(&[
        OsStr::new("protocol"),
        OsStr::new("project"),
        OsStr::new("--manifest"),
        OsStr::new("ci/protocol/v1.toml"),
        OsStr::new("--repository-root"),
        OsStr::new("."),
        OsStr::new("--output"),
        output.as_os_str(),
    ])
}

fn copy_workflows(destination: &Path) {
    fs::create_dir(destination).expect("workflow fixture directory must be created");
    for name in WORKFLOWS {
        fs::copy(
            repository_root().join(".github/workflows").join(name),
            destination.join(name),
        )
        .expect("workflow fixture must copy");
    }
}

fn complete_stderr(output: &hell_testkit::SupervisedOutput) -> String {
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
fn checked_in_workflows_are_exact_typed_renderings() {
    let fixture = Fixture::new("live");
    let check_report = fixture.path("protocol-check.json");
    let checked = protocol_check(&repository_root().join(".github/workflows"), &check_report);
    assert!(
        checked.status.success() && !checked.timed_out,
        "typed protocol check rejected the live workflows: {}",
        complete_stderr(&checked)
    );
    assert!(check_report.is_file());
}

#[test]
fn committed_audit_projection_is_the_exact_typed_projection() {
    let fixture = Fixture::new("audit-projection");
    let projected = fixture.path("v1.audit.json");
    let output = protocol_project(&projected);
    assert!(
        output.status.success() && !output.timed_out,
        "typed audit projection failed: {}",
        complete_stderr(&output)
    );
    assert_eq!(
        fs::read(&projected).expect("generated audit projection must exist"),
        fs::read(repository_root().join("ci/protocol/v1.audit.json"))
            .expect("committed audit projection must exist"),
        "committed audit projection differs from the typed manifest"
    );
}

#[test]
fn repository_policy_accepts_protocol_derived_workflows_without_caller_gate_lists() {
    let fixture = Fixture::new("repository-policy");
    let policy_report = fixture.path("policy.json");
    let policy = run(&[
        OsStr::new("policy"),
        OsStr::new("--report"),
        policy_report.as_os_str(),
    ]);
    assert!(
        policy.status.success() && !policy.timed_out,
        "repository policy rejected the six generated workflows: {}",
        complete_stderr(&policy)
    );
    assert!(policy_report.is_file());
}

#[test]
fn manual_workflow_drift_writes_a_stable_failing_protocol_report() {
    let fixture = Fixture::new("manual-drift");
    let workflows = fixture.path("workflows");
    copy_workflows(&workflows);
    let ci_path = workflows.join("ci.yml");
    let ci = fs::read_to_string(&ci_path).expect("CI workflow fixture must be UTF-8");
    let source = "name: CI\n";
    let replacement = "name: CI with manual drift\n";
    assert_eq!(ci.match_indices(source).count(), 1);
    fs::write(&ci_path, ci.replace(source, replacement))
        .expect("workflow drift fixture must be written");

    let report = fixture.path("protocol-check.json");
    let checked = protocol_check(&workflows, &report);
    assert!(!checked.status.success() && !checked.timed_out);
    let report = fs::read_to_string(report).expect("protocol failure report must exist");
    assert!(report.contains("workflow.generated.drift"));
    assert!(report.contains("\"state\":\"blocked\""));
}

#[test]
fn protocol_cli_rejects_untyped_or_duplicate_inputs() {
    for arguments in [
        vec![OsString::from("protocol"), OsString::from("check")],
        vec![
            OsString::from("protocol"),
            OsString::from("check"),
            OsString::from("--manifest"),
            OsString::from("ci/protocol/v1.toml"),
            OsString::from("--manifest"),
            OsString::from("ci/protocol/v1.toml"),
        ],
    ] {
        let arguments = arguments
            .iter()
            .map(OsString::as_os_str)
            .collect::<Vec<_>>();
        let result = run(&arguments);
        assert!(!result.status.success() && !result.timed_out);
    }
}
