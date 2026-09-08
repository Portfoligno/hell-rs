use std::fs;
use std::path::Path;

use hell_memcordon::{
    FINALIZATION_RECEIPT_SCHEMA_V1, FinalizationReceiptV1, PlatformId,
    WindowsCandidateIdentityReceiptV1,
};

fn digest(byte: char) -> String {
    std::iter::repeat_n(byte, 64).collect()
}

fn finalization() -> FinalizationReceiptV1 {
    FinalizationReceiptV1 {
        schema_version: FINALIZATION_RECEIPT_SCHEMA_V1,
        platform: PlatformId::LinuxX86_64,
        candidate_commit: digest('a'),
        workflow_commit: digest('b'),
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

#[test]
fn missing_windows_runtime_helper_mutation_is_rejected() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let lock = fs::read_to_string(root.join("ci/memcordon-runtime-v1.toml")).unwrap();
    let mutated = lock.replace("  \"memcordon-session-broker.exe\",\n", "");
    assert_ne!(mutated, lock);
    assert!(hell_memcordon::RuntimeLock::parse(&mutated).is_err());
}

#[test]
fn pre_cleanup_and_inexact_coverage_mutations_cannot_be_admitted() {
    let mut pre_cleanup = finalization();
    pre_cleanup.cleanup_succeeded = false;
    assert!(pre_cleanup.validate().is_err());

    let mut missing = finalization();
    missing.observed_operation_ids.clear();
    assert!(missing.validate().is_err());

    let mut duplicate = finalization();
    duplicate.observed_operation_ids.push("release".to_owned());
    assert!(duplicate.validate().is_err());
}

#[test]
fn malformed_windows_identity_receipt_mutations_fail_closed() {
    let unknown_field = format!(
        "{{\"schema_version\":1,\"operation_id\":\"release\",\"candidate_released\":true,\"token_policy_digest\":\"{}\",\"command_binding_digest\":\"{}\",\"child_native_status\":3221225477,\"direct_child_reaped\":true,\"adapter_outcome\":\"completed\",\"relay_outcome\":\"completed\",\"forged\":true}}",
        digest('a'),
        digest('b')
    );
    assert!(serde_json::from_str::<WindowsCandidateIdentityReceiptV1>(&unknown_field).is_err());

    let contradictory = format!(
        "{{\"schema_version\":1,\"operation_id\":\"release\",\"candidate_released\":false,\"token_policy_digest\":\"{}\",\"command_binding_digest\":\"{}\",\"child_native_status\":3221225477,\"direct_child_reaped\":true,\"adapter_outcome\":\"completed\",\"relay_outcome\":\"completed\"}}",
        digest('a'),
        digest('b')
    );
    let receipt: WindowsCandidateIdentityReceiptV1 = serde_json::from_str(&contradictory).unwrap();
    assert!(receipt.validate().is_err());
}
