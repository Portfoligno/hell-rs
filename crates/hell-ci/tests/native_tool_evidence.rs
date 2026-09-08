use hell_ci::native_tool_evidence::{
    NativeToolCommandResult, NativeToolQuery, NativeToolTermination, retain_failure,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "hell-native-tool-evidence-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        Self(root.canonicalize().unwrap())
    }
    fn output(&self) -> PathBuf {
        self.0.join("native-environment.json")
    }
    fn evidence(&self) -> PathBuf {
        self.output().with_extension("tool-failure")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn query(path: &Path) -> NativeToolQuery<'_> {
    NativeToolQuery {
        tool: "rustc",
        executable: path,
        executable_sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        arguments: &["-vV"],
        directory: path,
        resolution_duration: Duration::from_millis(12),
        hashing_duration: Duration::from_millis(34),
        execution_budget: Duration::from_secs(30),
        collection_remaining: Duration::from_secs(270),
        started_unix_millis: 123456789,
    }
}

fn capture() -> NativeToolCommandResult {
    #[cfg(unix)]
    let status = {
        use std::os::unix::process::ExitStatusExt as _;
        std::process::ExitStatus::from_raw(9)
    };
    #[cfg(windows)]
    let status = {
        use std::os::windows::process::ExitStatusExt as _;
        std::process::ExitStatus::from_raw(1)
    };
    let mut stdout = vec![b'x'; 20 * 1024];
    stdout.splice(
        10 * 1024..10 * 1024,
        b"middle-output-not-discarded".iter().copied(),
    );
    let stderr = b"rustup proxy diagnostic\0\xff\n".to_vec();
    NativeToolCommandResult {
        status,
        duration: Duration::from_secs(30),
        timed_out: true,
        stdout_bytes: stdout.len() as u64,
        stderr_bytes: stderr.len() as u64,
        stdout_sha256: hell_testkit::sha256_bytes(&stdout),
        stderr_sha256: hell_testkit::sha256_bytes(&stderr),
        stdout,
        stderr,
        stdout_truncated: false,
        stderr_truncated: false,
        termination: NativeToolTermination {
            cleanup_id: Some(1),
            forced: true,
            reaped: true,
            candidate_quiescence_complete: true,
        },
        phase_timings: Vec::new(),
        #[cfg(windows)]
        windows_launch_control: None,
    }
}

#[test]
fn timeout_receipt_keeps_exact_streams_native_context_and_separate_budgets() {
    let fixture = Fixture::new();
    let captured = capture();
    let primary = "native tool rustc did not complete cleanly";
    let result = retain_failure(
        Some(&fixture.output()),
        &query(&fixture.0),
        primary.into(),
        Duration::from_millis(30123),
        Some(&captured),
    );
    assert!(result.starts_with(primary));
    assert_eq!(
        fs::read(fixture.evidence().join("stdout")).unwrap(),
        captured.stdout
    );
    assert_eq!(
        fs::read(fixture.evidence().join("stderr")).unwrap(),
        captured.stderr
    );
    let value: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture.evidence().join("query.json")).unwrap()).unwrap();
    assert_eq!(value["arguments"], serde_json::json!(["-vV"]));
    assert_eq!(value["executionBudgetMillis"], 30000);
    assert_eq!(value["collectionRemainingAtQueryStartMillis"], 270000);
    assert_eq!(value["resolutionMillis"], 12);
    assert_eq!(value["hashingMillis"], 34);
    assert_eq!(value["capture"]["timedOut"], true);
    assert_eq!(value["capture"]["forced"], true);
    assert_eq!(value["capture"]["reaped"], true);
    assert_eq!(
        value["capture"]["stdoutSha256"],
        captured.stdout_sha256.hex()
    );
    assert_eq!(
        value["workingDirectory"]["display"],
        fixture.0.to_string_lossy().as_ref()
    );
    assert!(value.get("environment").is_none());
    assert_eq!(value["admissionEvidence"], false);
    assert!(!fixture.output().exists());
}

#[test]
fn launch_failure_has_no_fabricated_capture_and_second_attempt_cannot_overwrite() {
    let fixture = Fixture::new();
    let original = "native tool rustc failed to execute";
    retain_failure(
        Some(&fixture.output()),
        &query(&fixture.0),
        original.into(),
        Duration::from_millis(1),
        None,
    );
    let receipt = fs::read(fixture.evidence().join("query.json")).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&receipt).unwrap();
    assert!(value["capture"].is_null());
    assert!(!fixture.evidence().join("stdout").exists());
    let second = retain_failure(
        Some(&fixture.output()),
        &query(&fixture.0),
        "second primary".into(),
        Duration::ZERO,
        Some(&capture()),
    );
    assert!(second.starts_with("second primary; native tool diagnostic persistence failed:"));
    assert_eq!(
        fs::read(fixture.evidence().join("query.json")).unwrap(),
        receipt
    );
}

#[cfg(unix)]
#[test]
fn redirected_evidence_is_rejected_and_nonunicode_native_paths_are_preserved() {
    use std::os::unix::ffi::OsStringExt as _;
    let fixture = Fixture::new();
    let outside = fixture.0.join("outside");
    fs::create_dir(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, fixture.evidence()).unwrap();
    let result = retain_failure(
        Some(&fixture.output()),
        &query(&fixture.0),
        "primary".into(),
        Duration::ZERO,
        None,
    );
    assert!(result.starts_with("primary; native tool diagnostic persistence failed:"));
    assert!(fs::read_dir(&outside).unwrap().next().is_none());
    fs::remove_file(fixture.evidence()).unwrap();
    let path = fixture
        .0
        .join(std::ffi::OsString::from_vec(vec![b'r', 0xff]));
    retain_failure(
        Some(&fixture.output()),
        &query(&path),
        "primary".into(),
        Duration::ZERO,
        None,
    );
    let value: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture.evidence().join("query.json")).unwrap()).unwrap();
    assert_eq!(value["executable"]["encoding"], "unix-bytes");
    assert_eq!(
        value["executable"]["units"]
            .as_array()
            .unwrap()
            .last()
            .unwrap(),
        255
    );
}
