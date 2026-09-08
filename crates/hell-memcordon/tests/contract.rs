use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::Path;
use std::time::{Duration, Instant};

use hell_memcordon::{
    AbsoluteDeadlines, AdmissionError, CandidateBoundaryPolicy, FinalizationReceiptV1,
    NativeArgument, NativeArgumentRaw, OperationLedgerEntryV1, Platform, PlatformId,
    ProviderCleanupReceiptV1, ProviderLeaseStateMachine, ProviderLifecycleState, RuntimeLock,
    Schema8ProjectionV1, Schema8TerminalV1, SealedAdmission, SealedTerminal,
    WindowsCandidateIdentityReceiptV1, WindowsIdentityAdapterOutcomeV1,
    WindowsIdentityRelayOutcomeV1, operation_ledger_json, sealed_arguments,
    validate_operation_ledger, validate_schema8_wire,
};

const LOCK: &str = r#"
schema-version = 1
version = "0.5.2-rc.23"
repository = "Portfoligno/memcordon"
release-id = 384239676
source-commit = "67aa1f74d9a76713ab343ea2afbe6403da7429b7"
execution-schema = 8
plan-schema = 7
doctor-schema = 5
clean-schema = 2
package-inspection-schema = 4

[metadata.release-manifest]
asset-id = 549148426
filename = "release-manifest.json"
bytes = 11529
sha256 = "39127a1aefe3d4ca5b657b31cd2fe043dcc808cf9390d45c11a553ee680c7ca9"

[metadata.publication-report]
asset-id = 549153965
filename = "publication-report.json"
bytes = 11698
sha256 = "f1423382eaf7a9549c9af141a9bc172d8ee613d04af6f08a8fcda71a68c3053a"

[metadata.checksums]
asset-id = 549148232
filename = "SHA256SUMS"
bytes = 709
sha256 = "4fc5d1d91a719e591ceed70bb5b26c02088ed93e370356515b12a089a66379cc"

[platform.linux-x86_64]
asset-id = 549148407
filename = "memcordon-v0.5.2-rc.23-x86_64-unknown-linux-gnu.tar.gz"
bytes = 3133920
sha256 = "839c4918eef67be4e6a773e7f0840d0665480a4c0d874c72432a208315db479d"
target = "x86_64-unknown-linux-gnu"
mechanism = "linux-pid-namespace-cgroup-v2"
required-components = ["memcordon", "memcordon-sealed-agent"]

[platform.windows-x86_64]
asset-id = 549148389
filename = "memcordon-v0.5.2-rc.23-x86_64-pc-windows-msvc.zip"
bytes = 6326811
sha256 = "90047dd584bcec2206314aeccf6555d51c4c123f7769a89a29489b0e06316278"
target = "x86_64-pc-windows-msvc"
mechanism = "windows-job-object-v2"
required-components = [
  "memcordon.exe",
  "memcordon-sealed-agent.exe",
  "memcordon-target-desktop-bootstrap.exe",
  "memcordon-session-broker.exe",
]
"#;

#[test]
fn lock_requires_exact_platform_component_authority() {
    let lock = RuntimeLock::parse(LOCK).expect("reviewed lock should parse");
    assert_eq!(
        lock.asset(Platform::WindowsX86_64)
            .expect("Windows asset")
            .required_components
            .len(),
        4
    );
    let without_broker = LOCK.replace("  \"memcordon-session-broker.exe\",\n", "");
    assert!(RuntimeLock::parse(&without_broker).is_err());
    assert!(RuntimeLock::parse(&format!("{LOCK}\nunreviewed = true\n")).is_err());
}

#[test]
fn provider_state_machine_admits_only_qualified_or_running() {
    let mut lease = ProviderLeaseStateMachine::default();
    assert!(!lease.admits_sealed_roots());
    for state in [
        ProviderLifecycleState::Acquired,
        ProviderLifecycleState::PackageInspected,
        ProviderLifecycleState::Installing,
        ProviderLifecycleState::Qualified,
    ] {
        lease
            .transition(state)
            .expect("reviewed provider transition");
    }
    assert!(lease.admits_sealed_roots());
    assert!(
        lease
            .transition(ProviderLifecycleState::Uninstalling)
            .is_err()
    );
}

#[test]
fn cleanup_and_finalization_cannot_admit_before_retirement() {
    let cleanup = ProviderCleanupReceiptV1 {
        schema_version: 1,
        provider_lease_id: "lease-1".to_owned(),
        operation_id: "readiness".to_owned(),
        platform: PlatformId::LinuxX86_64,
        attempted: true,
        final_state: ProviderLifecycleState::Removed,
        installed_footprint_absent: true,
        active_operations: 0,
        failure: None,
    };
    cleanup.validate().expect("terminal cleanup receipt");

    let digest = "a".repeat(64);
    let complete = FinalizationReceiptV1 {
        schema_version: 1,
        platform: PlatformId::LinuxX86_64,
        candidate_commit: "candidate".to_owned(),
        workflow_commit: "workflow".to_owned(),
        runtime_lock_digest: digest.clone(),
        acquisition_digest: Some(digest.clone()),
        provider_lifecycle_digest: Some(digest.clone()),
        provider_cleanup_digest: Some(digest.clone()),
        operations_digest: Some(digest.clone()),
        inventory_digest: digest,
        required_operation_ids: vec!["one".to_owned()],
        observed_operation_ids: vec!["one".to_owned()],
        cleanup_succeeded: true,
        admitted: true,
        failure: None,
    };
    complete.validate().expect("complete finalization");
    let mut incomplete = complete;
    incomplete.provider_cleanup_digest = None;
    assert!(incomplete.validate().is_err());
}

#[test]
fn invocation_keeps_target_arguments_after_explicit_boundary() {
    let arguments = sealed_arguments(
        Path::new("/tmp/report.json"),
        Duration::from_millis(2500),
        Path::new("/usr/bin/target"),
        &[OsString::from("--sealed"), OsString::from("a b")],
    )
    .expect("absolute invocation should build");
    let boundary = arguments
        .iter()
        .position(|value| value == "--")
        .expect("argument boundary");
    assert_eq!(
        &arguments[boundary + 1..],
        ["/usr/bin/target", "--sealed", "a b"]
    );
}

#[test]
fn strict_wire_rejects_duplicate_keys_and_wrong_schema() {
    assert!(validate_schema8_wire(br#"{"schema_version":8,"schema_version":8}"#).is_err());
    assert!(validate_schema8_wire(br#"{"schema_version":7}"#).is_err());
    assert!(validate_schema8_wire(br#"{"schema_version":8}"#).is_ok());
}

#[test]
fn projection_requires_exact_native_predicates_and_consistent_lossless_argv() {
    let projection = Schema8ProjectionV1 {
        schema_version: 8,
        tool_version: "0.5.2-rc.23".to_owned(),
        requested_boundary: "sealed".to_owned(),
        effective_boundary: "sealed".to_owned(),
        mechanism: "linux-pid-namespace-cgroup-v2".to_owned(),
        target_argv: vec![NativeArgument {
            display: "/bin/true".to_owned(),
            raw: None,
        }],
        attempt_count: 1,
        restart_count: 0,
        sealed_boundary_retired: true,
        wrapper_status: 0,
        target_status: Some(0),
        terminal: Schema8TerminalV1::CandidateExit { native_status: 0 },
        native_predicates: BTreeMap::new(),
    };
    assert!(projection.validate().is_err());

    let redundant_raw = NativeArgument {
        display: "plain".to_owned(),
        raw: Some(NativeArgumentRaw {
            encoding: "unix-bytes-base64".to_owned(),
            data: "cGxhaW4=".to_owned(),
        }),
    };
    assert!(redundant_raw.validate().is_err());
}

#[test]
fn deadlines_never_extend_the_absolute_execution_bound() {
    let now = Instant::now();
    let deadlines =
        AbsoluteDeadlines::new(now + Duration::from_secs(30), now + Duration::from_secs(50))
            .expect("ordered deadlines");
    assert_eq!(
        deadlines
            .inner_budget(now, Duration::from_secs(20))
            .expect("positive budget")
            .duration(),
        Duration::from_secs(10)
    );
    assert!(
        deadlines
            .inner_budget(now, Duration::from_secs(30))
            .is_err()
    );
}

#[test]
fn dropped_admission_poison_prevents_fallback_launch() {
    let admission = SealedAdmission::new(1);
    let lease = admission
        .acquire_until(Instant::now() + Duration::from_secs(1))
        .expect("first admission");
    drop(lease);
    assert!(matches!(
        admission.acquire_until(Instant::now() + Duration::from_secs(1)),
        Err(AdmissionError::Poisoned(_))
    ));
    assert_eq!(CandidateBoundaryPolicy::SealedLinux as u8, 0);
}

#[test]
fn windows_identity_receipt_preserves_wide_status_and_closed_lifecycle() {
    let receipt = WindowsCandidateIdentityReceiptV1 {
        schema_version: 1,
        operation_id: "windows-candidate".to_owned(),
        candidate_released: true,
        token_policy_digest: "a".repeat(64),
        command_binding_digest: "b".repeat(64),
        child_native_status: Some(0xc000_0005),
        direct_child_reaped: true,
        adapter_outcome: WindowsIdentityAdapterOutcomeV1::Completed,
        relay_outcome: WindowsIdentityRelayOutcomeV1::Completed,
    };
    receipt
        .validate()
        .expect("complete Windows identity receipt");

    let mut unreleased = receipt;
    unreleased.candidate_released = false;
    assert!(unreleased.validate().is_err());
}

#[test]
fn operation_ledger_is_strict_unique_and_deterministically_sorted() {
    let digest = "a".repeat(64);
    let entry = |operation_id: &str| OperationLedgerEntryV1 {
        operation_id: operation_id.to_owned(),
        boundary: CandidateBoundaryPolicy::SealedLinux,
        request_digest: digest.clone(),
        raw_report_path: Some(format!("raw/{operation_id}.json")),
        raw_report_digest: Some(digest.clone()),
        normalized_report_path: Some(format!("normalized/{operation_id}.json")),
        normalized_report_digest: Some(digest.clone()),
        identity_adapter_path: None,
        identity_adapter_digest: None,
        terminal: SealedTerminal::OrdinaryResult,
    };
    let entries = [entry("zeta"), entry("alpha")];
    validate_operation_ledger(&entries).expect("complete unique ledger");
    let json = operation_ledger_json(&entries).expect("canonical ledger JSON");
    let alpha = json
        .windows(b"alpha".len())
        .position(|window| window == b"alpha")
        .expect("alpha id");
    let zeta = json
        .windows(b"zeta".len())
        .position(|window| window == b"zeta")
        .expect("zeta id");
    assert!(alpha < zeta);
    assert_eq!(json.last(), Some(&b'\n'));

    let duplicate = [entry("same"), entry("same")];
    assert!(validate_operation_ledger(&duplicate).is_err());
    let mut traversal = entry("bad-path");
    traversal.raw_report_path = Some("raw/../escape.json".to_owned());
    assert!(traversal.validate().is_err());
}
