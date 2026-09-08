use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use hell_memcordon::{FINALIZATION_RECEIPT_SCHEMA_V1, FinalizationReceiptV1, PlatformId};

static FIXTURE_ID: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let id = FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "hell-ci-memcordon-platform-finalization-{}-{id}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("create finalization fixture");
        Self(root)
    }

    fn memcordon(&self) -> PathBuf {
        self.0.join("memcordon")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("remove finalization fixture");
    }
}

fn digest(byte: char) -> String {
    std::iter::repeat_n(byte, 64).collect()
}

fn finalization() -> FinalizationReceiptV1 {
    FinalizationReceiptV1 {
        schema_version: FINALIZATION_RECEIPT_SCHEMA_V1,
        platform: PlatformId::LinuxX86_64,
        candidate_commit: "a".repeat(40),
        workflow_commit: "b".repeat(40),
        runtime_lock_digest: digest('c'),
        acquisition_digest: Some(digest('d')),
        provider_lifecycle_digest: Some(digest('e')),
        provider_cleanup_digest: Some(digest('f')),
        operations_digest: Some(digest('1')),
        inventory_digest: digest('2'),
        required_operation_ids: vec!["release".to_owned()],
        observed_operation_ids: vec!["release".to_owned()],
        cleanup_succeeded: true,
        admitted: true,
        failure: None,
    }
}

fn write_provisional(fixture: &Fixture) {
    fs::create_dir(fixture.memcordon()).expect("create MemCordon output");
    let report = serde_json::json!({
        "archiveName":"hell-v1.0.0-linux-x86_64.tar.gz",
        "archiveSha256":digest('0'),
        "assignedObligationCount":1,
        "buildInputsSha256":digest('1'),
        "candidateSha":"a".repeat(40),
        "conformancePlanSha256":digest('2'),
        "conformanceStandard":"test",
        "evidence":{},
        "evidenceManifestSha256":digest('3'),
        "externalInputsSha256":digest('4'),
        "exploratoryObservationCount":0,
        "gates":[],
        "imageOS":"test",
        "imageVersion":"test",
        "memcordon":null,
        "nativeEnvironmentSha256":digest('5'),
        "planSha256":digest('6'),
        "platform":"linux-x86_64",
        "producedEvidenceRecordCount":1,
        "runAttempt":1,
        "runId":1,
        "schemaVersion":3,
        "state":"passed",
        "tag":"v1.0.0",
        "toolIdentities":{},
        "trustedConformanceInputsSha256":digest('7'),
        "unclassifiedMismatchCount":0,
        "version":"1.0.0",
        "workflowSha":"b".repeat(40)
    });
    let mut bytes = serde_json::to_vec(&report).expect("serialize provisional report");
    bytes.push(b'\n');
    fs::write(fixture.0.join("platform-report.provisional.json"), bytes)
        .expect("write provisional report");
}

fn receipt_bytes(receipt: &FinalizationReceiptV1) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(receipt).expect("serialize finalization receipt");
    bytes.push(b'\n');
    bytes
}

#[test]
fn platform_success_is_installed_only_after_cleanup_aware_finalization() {
    let fixture = Fixture::new();
    write_provisional(&fixture);
    let inventory = format!("{}  acquisition.json\n", digest('8')).into_bytes();
    let mut receipt = finalization();
    receipt.inventory_digest = hell_testkit::sha256_bytes(&inventory).hex();
    let receipt_bytes = receipt_bytes(&receipt);

    hell_ci::finalize_memcordon_platform_report_for_integration(
        &fixture.memcordon(),
        &receipt,
        &receipt_bytes,
        &inventory,
    )
    .expect("clean finalization must install the final report");

    assert!(fixture.0.join("platform-report.json").is_file());
    assert!(!fixture.0.join("platform-report.provisional.json").exists());
    let report: serde_json::Value = serde_json::from_slice(
        &fs::read(fixture.0.join("platform-report.json")).expect("read final platform report"),
    )
    .expect("parse final platform report");
    assert_eq!(report["schemaVersion"], 3);
    assert_eq!(
        report["memcordon"]["operationIds"],
        serde_json::json!(["release"])
    );
    assert_eq!(
        report["memcordon"]["finalizationSha256"],
        hell_testkit::sha256_bytes(&receipt_bytes).hex()
    );
    assert_eq!(
        report["memcordon"]["inventorySha256"],
        hell_testkit::sha256_bytes(&inventory).hex()
    );
}

#[test]
fn pre_cleanup_finalization_cannot_replace_the_provisional_report() {
    let fixture = Fixture::new();
    write_provisional(&fixture);
    let mut receipt = finalization();
    receipt.cleanup_succeeded = false;
    receipt.admitted = false;
    receipt.failure = Some("cleanup pending".to_owned());
    let inventory = format!("{}  acquisition.json\n", digest('8')).into_bytes();
    receipt.inventory_digest = hell_testkit::sha256_bytes(&inventory).hex();
    let receipt_bytes = receipt_bytes(&receipt);

    let result = hell_ci::finalize_memcordon_platform_report_for_integration(
        &fixture.memcordon(),
        &receipt,
        &receipt_bytes,
        &inventory,
    );

    assert!(result.is_err());
    assert!(fixture.0.join("platform-report.provisional.json").is_file());
    assert!(!fixture.0.join("platform-report.json").exists());
}

#[test]
fn substituted_finalization_bytes_cannot_create_a_final_platform_report() {
    let fixture = Fixture::new();
    write_provisional(&fixture);
    let inventory = format!("{}  acquisition.json\n", digest('8')).into_bytes();
    let mut receipt = finalization();
    receipt.inventory_digest = hell_testkit::sha256_bytes(&inventory).hex();
    let mut substituted = receipt_bytes(&receipt);
    let byte = substituted
        .iter_mut()
        .find(|byte| **byte == b'a')
        .expect("receipt contains a mutable byte");
    *byte = b'b';

    let result = hell_ci::finalize_memcordon_platform_report_for_integration(
        &fixture.memcordon(),
        &receipt,
        &substituted,
        &inventory,
    );

    assert!(result.is_err());
    assert!(fixture.0.join("platform-report.provisional.json").is_file());
    assert!(!fixture.0.join("platform-report.json").exists());
}
