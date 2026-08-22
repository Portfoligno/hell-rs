use std::collections::BTreeSet;
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
        let sequence = FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "hell-ci-final-transaction-{label}-{}-{sequence}",
            std::process::id()
        ));
        assert!(!root.exists(), "final transaction fixture must be new");
        Self { root }
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.root.join(relative)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if self.root.exists() {
            fs::remove_dir_all(&self.root).expect("remove final transaction fixture");
        }
    }
}

#[test]
fn successful_verification_promotes_authority_only_after_the_admitted_report() {
    let fixture = Fixture::new("promotion");
    let result = run_case("promotion", &fixture);
    assert!(
        result.status.success(),
        "promotion failed: {}",
        complete_stderr(&result)
    );
    assert_eq!(
        regular_files(&fixture.root),
        BTreeSet::from([
            PathBuf::from("authority/authority.json"),
            PathBuf::from("report.json"),
        ])
    );
    assert_eq!(
        fs::read(fixture.path("authority/authority.json")).expect("read promoted authority"),
        b"{\"schemaVersion\":1,\"state\":\"verified-authority\"}\n"
    );
    assert_eq!(
        fs::read(fixture.path("report.json")).expect("read admitted report"),
        b"{\"admitted\":true,\"diagnosticCode\":null,\"schemaVersion\":1,\"state\":\"dually-verified\"}\n"
    );
    assert!(!fixture.path("authority-staging").exists());
    assert!(!fixture.path("diagnostics").exists());
}

#[test]
fn report_promotion_failure_rolls_back_authority_and_retains_diagnostics() {
    let fixture = Fixture::new("rollback");
    let result = run_case("rollback", &fixture);
    assert_eq!(result.status.code(), Some(1));
    let stderr = complete_stderr(&result);
    assert!(stderr.starts_with("cannot promote final verification report:"));
    assert!(!fixture.path("authority").exists());
    assert!(!fixture.path("authority-staging").exists());
    assert_eq!(
        regular_files(&fixture.root),
        BTreeSet::from([
            PathBuf::from("diagnostics/failure-summary.json"),
            PathBuf::from("diagnostics/primary-verification-report.json"),
            PathBuf::from("report.json"),
        ])
    );
    let report = read_json(&fixture.path("report.json"));
    assert_eq!(report["admitted"], false);
    assert_eq!(
        report["diagnosticCode"],
        "release.final-verification-failed"
    );
    assert_eq!(report["state"], "blocked");
    assert_eq!(
        read_json(&fixture.path("diagnostics/failure-summary.json"))["diagnosticMessage"],
        report["diagnosticMessage"]
    );
    assert_eq!(
        fs::read(fixture.path("diagnostics/primary-verification-report.json"))
            .expect("read retained primary report"),
        b"{\"schemaVersion\":1,\"state\":\"primary-verified\"}\n"
    );
}

#[test]
fn late_retention_failure_preserves_the_summary_and_earlier_distinct_report() {
    let fixture = Fixture::new("retention");
    let result = run_case("retention-late-failure", &fixture);
    assert_eq!(result.status.code(), Some(1));
    assert_eq!(
        complete_stderr(&result),
        "retained diagnostic is not a regular file\n"
    );
    assert!(!fixture.path("authority").exists());
    assert!(!fixture.path("report.json").exists());
    assert!(
        fixture
            .path("authority-staging/primary-verifier-decision.json")
            .is_dir(),
        "the deliberately invalid late source must remain a non-regular input"
    );
    assert_eq!(
        regular_files(&fixture.path("diagnostics")),
        BTreeSet::from([
            PathBuf::from("failure-summary.json"),
            PathBuf::from("primary-verification-report.json"),
        ])
    );
    assert_eq!(
        read_json(&fixture.path("diagnostics/failure-summary.json"))["diagnosticMessage"],
        "integration primary failure"
    );
    assert_eq!(
        read_json(&fixture.path("diagnostics/primary-verification-report.json"))["state"],
        "primary-verified"
    );
    assert!(
        !fixture
            .path("diagnostics/primary-verifier-decision.json")
            .exists(),
        "failed late retention must not collide with the earlier report"
    );
}

#[test]
fn expired_cleanup_retains_only_durable_primary_diagnostics_and_does_no_late_work() {
    let fixture = Fixture::new("expired-cleanup");
    let result = run_case("expired-cleanup", &fixture);
    assert_eq!(result.status.code(), Some(1));
    assert_eq!(
        complete_stderr(&result),
        "integration primary failure; additionally, final verification cleanup deadline expired before diagnostic retention; additionally, final verification cleanup deadline expired before diagnostic file retention; additionally, final verification cleanup deadline expired before failed authority cleanup\n"
    );
    assert!(!fixture.path("authority").exists());
    assert!(!fixture.path("authority-staging").exists());
    assert_eq!(
        regular_files(&fixture.root),
        BTreeSet::from([
            PathBuf::from("diagnostics/failure-summary.json"),
            PathBuf::from("report.json"),
        ])
    );
    let report = read_json(&fixture.path("report.json"));
    assert_eq!(report["admitted"], false);
    assert_eq!(
        report["diagnosticCode"],
        "release.final-verification-failed"
    );
    assert_eq!(report["diagnosticMessage"], "integration primary failure");
    assert_eq!(report["state"], "blocked");
    assert_eq!(
        read_json(&fixture.path("diagnostics/failure-summary.json"))["diagnosticMessage"],
        "integration primary failure"
    );
}

fn run_case(case: &str, fixture: &Fixture) -> hell_testkit::SupervisedOutput {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
    command
        .arg("__verify-final-verification-transaction")
        .arg(case)
        .arg(&fixture.root);
    let result = hell_testkit::run_supervised_command(&mut command, &[], Duration::from_secs(30))
        .expect("run final-verification transaction under process-tree supervision");
    assert!(
        !result.timed_out,
        "final-verification transaction timed out"
    );
    assert!(
        result
            .phase_timings
            .iter()
            .any(|phase| phase.name == "quiescence-complete"),
        "final-verification transaction did not reach process-tree quiescence"
    );
    assert_eq!(
        result.phase_timings.last().map(|phase| phase.name),
        Some("stdin-joined"),
        "final-verification transaction lacks terminal supervised I/O receipt"
    );
    result
}

fn read_json(path: &Path) -> serde_json::Value {
    let bytes = fs::read(path).expect("read final-verification JSON");
    assert_eq!(bytes.last(), Some(&b'\n'));
    serde_json::from_slice(&bytes).expect("parse final-verification JSON")
}

fn regular_files(root: &Path) -> BTreeSet<PathBuf> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = BTreeSet::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).expect("read final transaction directory") {
            let entry = entry.expect("read final transaction entry");
            let file_type = entry.file_type().expect("read final transaction file type");
            if file_type.is_dir() {
                pending.push(entry.path());
            } else if file_type.is_file() {
                files.insert(
                    entry
                        .path()
                        .strip_prefix(root)
                        .expect("file remains inside final transaction root")
                        .to_path_buf(),
                );
            } else {
                panic!("final transaction created an unsupported file type");
            }
        }
    }
    files
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
