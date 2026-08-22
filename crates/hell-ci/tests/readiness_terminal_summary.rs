use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static FIXTURE_ID: AtomicU64 = AtomicU64::new(0);
const JOBS: [&str; 5] = ["plan", "linux", "macos", "windows", "verify"];

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let id = FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "hell-ci-readiness-summary-{label}-{}-{id}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("summary fixture root must be created");
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

fn run(arguments: &[&OsStr]) -> hell_testkit::SupervisedOutput {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
    command.arg("readiness");
    command.args(arguments);
    hell_testkit::run_supervised_command(&mut command, &[], Duration::from_secs(30))
        .expect("readiness command must execute under supervision")
}

fn record(state_root: &Path, job: &str, state: &str) -> hell_testkit::SupervisedOutput {
    let mut arguments = vec![
        OsString::from("record-job-state"),
        OsString::from("--job"),
        OsString::from(job),
        OsString::from("--state"),
        OsString::from(state),
    ];
    if state == "success" {
        let artifact_id = match job {
            "plan" => "925701",
            "linux" => "925702",
            "macos" => "925703",
            "windows" => "925704",
            "verify" => "925705",
            _ => "925799",
        };
        arguments.extend([
            OsString::from("--artifact-id"),
            OsString::from(artifact_id),
            OsString::from("--artifact-digest"),
            OsString::from(hell_testkit::sha256_bytes(job.as_bytes()).hex()),
        ]);
    }
    arguments.extend([
        OsString::from("--output"),
        state_root.as_os_str().to_owned(),
    ]);
    let arguments = arguments
        .iter()
        .map(OsString::as_os_str)
        .collect::<Vec<_>>();
    run(&arguments)
}

fn summarize(fixture: &Fixture) -> hell_testkit::SupervisedOutput {
    let state_root = fixture.path("state");
    let input = fixture.path("input");
    let output = fixture.path("summary");
    run(&[
        "summarize".as_ref(),
        "--state-root".as_ref(),
        state_root.as_os_str(),
        "--input".as_ref(),
        input.as_os_str(),
        "--output".as_ref(),
        output.as_os_str(),
    ])
}

fn stage_states(fixture: &Fixture, overrides: &[(&str, &str)]) {
    let state_root = fixture.path("state");
    for job in JOBS {
        let state = overrides
            .iter()
            .find_map(|(candidate, state)| (*candidate == job).then_some(*state))
            .unwrap_or("success");
        let result = record(&state_root, job, state);
        assert!(result.status.success(), "state for {job} was not recorded");
    }
}

#[test]
fn producer_failure_writes_a_failing_terminal_summary() {
    let fixture = Fixture::new("producer-failed");
    stage_states(&fixture, &[("linux", "failure"), ("verify", "skipped")]);
    let result = summarize(&fixture);
    assert!(!result.status.success() && !result.timed_out);
    let report = fs::read_to_string(fixture.path("summary/readiness-summary.json"))
        .expect("producer failure summary must exist");
    assert!(report.contains("\"state\":\"producer-failed\""));
    assert!(report.contains("\"linux\":\"failure\""));
    assert!(report.contains("\"verify\":\"skipped\""));
}

#[test]
fn skipped_or_failed_verifier_cannot_appear_admitted() {
    for (scenario, verifier_state, expected) in [
        ("skipped", "skipped", "incomplete"),
        ("failed", "failure", "verifier-failed"),
    ] {
        let fixture = Fixture::new(scenario);
        stage_states(&fixture, &[("verify", verifier_state)]);
        let result = summarize(&fixture);
        assert!(!result.status.success() && !result.timed_out);
        let report = fs::read_to_string(fixture.path("summary/readiness-summary.json"))
            .expect("verifier failure summary must exist");
        assert!(report.contains(&format!("\"state\":\"{expected}\"")));
        assert!(!report.contains("\"state\":\"admitted\""));
    }
}

#[test]
fn job_state_recording_is_exact_single_write_typed_input() {
    let fixture = Fixture::new("recording");
    let state_root = fixture.path("state");
    let first = record(&state_root, "linux", "success");
    assert!(first.status.success());
    assert!(!record(&state_root, "linux", "success").status.success());
    assert!(!record(&state_root, "unknown", "success").status.success());
    assert!(!record(&state_root, "macos", "cancelled").status.success());
    assert_eq!(
        fs::read_to_string(state_root.join("linux.json")).unwrap(),
        format!(
            "{{\"artifactDigest\":\"{}\",\"artifactId\":925702,\"job\":\"linux\",\"schemaVersion\":1,\"state\":\"success\"}}\n",
            hell_testkit::sha256_bytes(b"linux").hex()
        )
    );

    let failed = record(&state_root, "macos", "failure");
    assert!(failed.status.success());
    assert_eq!(
        fs::read_to_string(state_root.join("macos.json")).unwrap(),
        "{\"artifactDigest\":null,\"artifactId\":null,\"job\":\"macos\",\"schemaVersion\":1,\"state\":\"failure\"}\n"
    );
}

#[test]
fn extra_job_state_inventory_writes_a_blocked_typed_summary() {
    let fixture = Fixture::new("forged-inventory");
    stage_states(&fixture, &[]);
    fs::write(fixture.path("state/extra.json"), b"{}\n")
        .expect("extra state fixture must be written");
    let result = summarize(&fixture);
    assert!(!result.status.success() && !result.timed_out);
    let report = fs::read_to_string(fixture.path("summary/readiness-summary.json"))
        .expect("invalid state inventory must still produce a summary");
    assert!(report.contains("\"state\":\"blocked\""));
    assert!(report.contains("\"readiness.job-state.inventory\""));
    assert!(report.contains("\"artifactIds\""));
    assert!(report.contains("\"absentArtifacts\""));
    assert!(report.contains("\"reproductionCommand\""));
}

#[test]
fn missing_job_state_inventory_writes_a_blocked_typed_summary() {
    let fixture = Fixture::new("missing-inventory");
    let state_root = fixture.path("state");
    for job in ["plan", "linux", "macos", "windows"] {
        assert!(record(&state_root, job, "success").status.success());
    }
    let result = summarize(&fixture);
    assert!(!result.status.success() && !result.timed_out);
    let report = fs::read_to_string(fixture.path("summary/readiness-summary.json"))
        .expect("missing state inventory must still produce a summary");
    assert!(report.contains("\"state\":\"blocked\""));
    assert!(report.contains("\"readiness.job-state.inventory\""));
}

#[test]
fn malformed_job_state_writes_a_blocked_typed_summary() {
    let fixture = Fixture::new("malformed-state");
    stage_states(&fixture, &[]);
    fs::write(fixture.path("state/linux.json"), b"{\"schemaVersion\":1}\n")
        .expect("malformed state fixture must be written");
    let result = summarize(&fixture);
    assert!(!result.status.success() && !result.timed_out);
    let report = fs::read_to_string(fixture.path("summary/readiness-summary.json"))
        .expect("malformed state must still produce a summary");
    assert!(report.contains("\"state\":\"blocked\""));
    assert!(report.contains("\"readiness.job-state.invalid\""));
}

#[test]
fn forged_success_without_evidence_writes_authenticated_absences() {
    let fixture = Fixture::new("forged-success");
    stage_states(&fixture, &[]);
    let result = summarize(&fixture);
    assert!(!result.status.success() && !result.timed_out);
    let report = fs::read_to_string(fixture.path("summary/readiness-summary.json"))
        .expect("missing evidence must still produce a summary");
    assert!(report.contains("\"state\":\"blocked\""));
    assert!(report.contains("\"readiness.artifact.missing\""));
    assert!(report.contains("925701"));
    assert!(report.contains(&hell_testkit::sha256_bytes(b"plan").hex()));
    for artifact in [
        "plan",
        "linux-x86_64",
        "macos-aarch64",
        "windows-x86_64",
        "verifier",
    ] {
        assert!(report.contains(artifact));
    }
}

#[test]
fn available_source_diagnostics_are_harvested_before_a_malformed_report_blocks() {
    let fixture = Fixture::new("source-diagnostics");
    stage_states(&fixture, &[("linux", "failure"), ("verify", "skipped")]);
    let linux = fixture.path("input/platforms/linux-x86_64");
    fs::create_dir_all(&linux).expect("Linux diagnostic artifact root must be created");
    fs::write(
        linux.join("platform-failure-report.json"),
        b"{\"detail\":\"dependency policy rejected an undeclared source\",\"failedGate\":\"dependency-policy\",\"report\":\"platform-out/dependency-policy-report.json\",\"schemaVersion\":1,\"state\":\"failed\"}\n",
    )
    .expect("Linux failure report fixture must be written");
    let macos = fixture.path("input/platforms/macos-aarch64");
    fs::create_dir_all(&macos).expect("macOS diagnostic artifact root must be created");
    fs::write(macos.join("platform-failure-report.json"), b"{}\n")
        .expect("malformed macOS report fixture must be written");

    let result = summarize(&fixture);
    assert!(!result.status.success() && !result.timed_out);
    let report = fs::read_to_string(fixture.path("summary/readiness-summary.json"))
        .expect("mixed source diagnostics must still produce a summary");
    assert!(report.contains(
        "\"diagnostics\":[\"readiness.artifact.missing\",\"readiness.artifact.invalid\"]"
    ));
    assert!(report.contains(
        "\"sourceDiagnostics\":{\"linux-x86_64\":\"release.gate.dependency-policy\",\"macos-aarch64\":null,\"plan\":null,\"verifier\":null,\"windows-x86_64\":null}"
    ));
    assert!(report.contains("\"state\":\"producer-failed\""));
}

#[test]
fn caller_supplied_gate_lists_are_rejected_by_both_platform_dispatches() {
    for authority in ["readiness", "release"] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
        command
            .arg(authority)
            .arg("platform")
            .arg("--required-gates")
            .arg("runner-identity");
        let result =
            hell_testkit::run_supervised_command(&mut command, &[], Duration::from_secs(30))
                .expect("platform parser must execute under supervision");
        assert!(!result.status.success() && !result.timed_out);
    }
}
