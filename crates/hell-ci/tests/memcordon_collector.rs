#![cfg(unix)]

use hell_ci::ExecutionCollector;
use hell_memcordon::{CandidateBoundaryPolicy, NativeArgument, OperationLedgerV2};
use hell_testkit::{BoundedCapture, SealedExecutionObserver, SupervisedOutput};
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture(std::path::PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "hell-collector-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path.canonicalize().unwrap())
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

const RAW: &[u8] = include_bytes!("../../../fixtures/memcordon-rc23/schema8-linux-exit-123.json");

fn argv() -> Vec<NativeArgument> {
    vec![NativeArgument {
        display: "/opt/hell/bin/candidate".to_owned(),
        raw: None,
    }]
}

fn collector(root: &Path) -> ExecutionCollector {
    ExecutionCollector::new(
        root.to_owned(),
        "readiness",
        &hell_testkit::sha256_bytes(b"plan").hex(),
        CandidateBoundaryPolicy::SealedLinux,
    )
    .unwrap()
}

fn output(root: &Path, name: &str) -> SupervisedOutput {
    let path = root.join("raw").join(name);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, RAW).unwrap();
    SupervisedOutput {
        status: std::process::ExitStatus::from_raw(123 << 8),
        stdout: BoundedCapture::from_bytes(b"actual stdout".to_vec()),
        stderr: BoundedCapture::from_bytes(b"actual stderr".to_vec()),
        timed_out: false,
        termination: None,
        frontend_termination: None,
        memcordon_report_path: Some(path),
        memcordon_report_sha256: Some(hell_testkit::sha256_bytes(RAW)),
        memcordon_projection: Some(
            hell_memcordon::project_schema8_report(RAW, "linux-pid-namespace-cgroup-v2", &argv())
                .unwrap(),
        ),
        phase_timings: vec![],
        prelaunch_evidence: None,
        candidate_quiescence_complete: true,
    }
}

fn phases(collector: &ExecutionCollector) {
    for phase in hell_memcordon::OPERATION_GROUP_PHASES_V2 {
        collector.complete_phase(phase).unwrap();
    }
}

#[test]
fn cloned_task_collector_seals_all_authentic_invocations_including_nonzero_exit() {
    let directory = Fixture::new();
    let root = directory.path().canonicalize().unwrap();
    let collector = Arc::new(collector(&root));
    for (index, observer) in [collector.clone(), collector.clone()].iter().enumerate() {
        let id = observer.reserve(&argv()).unwrap();
        let mut result = output(&root, &index.to_string());
        observer.completed(&id, &mut result, None).unwrap();
        assert_eq!(
            std::fs::read(root.join("operations").join(&id).join("stdout")).unwrap(),
            b"actual stdout"
        );
        assert_eq!(
            result.memcordon_report_path.unwrap(),
            root.join("raw").join(format!("{id}.json"))
        );
    }
    phases(&collector);
    collector.seal().unwrap();
    let ledger: OperationLedgerV2 =
        serde_json::from_slice(&std::fs::read(root.join("operations.json")).unwrap()).unwrap();
    hell_memcordon::validate_operation_ledger_v2(&ledger).unwrap();
    assert_eq!(ledger.groups[0].invocations.len(), 2);
    assert_eq!(ledger.groups[0].reserved_invocation_ids.len(), 2);
    let bytes = std::fs::read(root.join("operations.json")).unwrap();
    let journal = std::fs::read(root.join("invocation-reservations.json")).unwrap();
    let report = serde_json::to_vec(
        &serde_json::json!({"state":"passed", "planSha256": ledger.groups[0].platform_plan_digest}),
    )
    .unwrap();
    hell_ci::validate_execution_group_binding(&bytes, &journal, &report).unwrap();
    assert!(
        hell_ci::validate_execution_group_binding(&bytes, &journal, br#"{"state":"failed"}"#)
            .is_err()
    );
    let mut changed: serde_json::Value = serde_json::from_slice(&journal).unwrap();
    changed["invocations"].as_array_mut().unwrap().pop();
    let changed = serde_json::to_vec(&changed).unwrap();
    let mut omitted = ledger.clone();
    omitted.groups[0].reservation_ledger_digest = hell_testkit::sha256_bytes(&changed).hex();
    let omitted = hell_memcordon::operation_ledger_v2_json(&omitted).unwrap();
    assert!(hell_ci::validate_execution_group_binding(&omitted, &changed, &report).is_err());
    assert!(collector.reserve(&argv()).is_err());
    assert!(collector.seal().is_err());
}

#[test]
fn missing_completion_and_unfinished_phases_cannot_seal() {
    let directory = Fixture::new();
    let root = directory.path().canonicalize().unwrap();
    let collector = collector(&root);
    let id = collector.reserve(&argv()).unwrap();
    assert!(collector.seal().is_err());
    let mut result = output(&root, "actual.json");
    collector.completed(&id, &mut result, None).unwrap();
    assert!(collector.completed(&id, &mut result, None).is_err());
    assert!(collector.seal().is_err());
    assert!(collector.complete_phase("platform-gates").is_err());
    phases(&collector);
    collector.reserve(&argv()).unwrap();
    assert!(collector.seal().is_err());
    assert!(!root.join("operations.json").exists());
}

#[test]
fn changed_raw_or_request_is_not_admitted() {
    for wrong_request in [false, true] {
        let directory = Fixture::new();
        let root = directory.path().canonicalize().unwrap();
        let collector = collector(&root);
        let mut request = argv();
        if wrong_request {
            request[0].display = "/different/candidate".to_owned();
        }
        let id = collector.reserve(&request).unwrap();
        let mut result = output(&root, "actual.json");
        if !wrong_request {
            result.memcordon_report_sha256 = Some(hell_testkit::sha256_bytes(b"changed"));
        }
        assert!(collector.completed(&id, &mut result, None).is_err());
        phases(&collector);
        assert!(collector.seal().is_err());
    }
}

#[test]
fn rejected_projection_retains_raw_and_streams_without_success_ledger() {
    let directory = Fixture::new();
    let root = directory.path().canonicalize().unwrap();
    let collector = collector(&root);
    let id = collector.reserve(&argv()).unwrap();
    let result = output(&root, "rejected-raw.json");
    collector
        .rejected(
            &id,
            result.memcordon_report_path.as_ref().unwrap(),
            &result.stdout,
            &result.stderr,
            "strict projection rejected",
        )
        .unwrap();
    assert!(result.memcordon_report_path.unwrap().is_file());
    assert!(
        root.join("operations")
            .join(id)
            .join("rejected.json")
            .is_file()
    );
    phases(&collector);
    assert!(collector.seal().is_err());
    assert!(!root.join("operations.json").exists());
}
