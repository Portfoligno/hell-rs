use hell_memcordon::{OperationLedgerV2, operation_ledger_v2_json, validate_operation_ledger_v2};

const FIXTURE: &[u8] = include_bytes!("../../../fixtures/memcordon-rc23/operation-ledger-v2.json");

#[test]
fn group_accounts_for_both_preflight_and_platform_invocations() {
    let ledger: OperationLedgerV2 = serde_json::from_slice(FIXTURE).unwrap();
    validate_operation_ledger_v2(&ledger).unwrap();
    let bytes = operation_ledger_v2_json(&ledger).unwrap();
    assert!(bytes.ends_with(b"\n"));
    assert_eq!(
        serde_json::from_slice::<OperationLedgerV2>(&bytes).unwrap(),
        ledger
    );
    assert_eq!(ledger.groups[0].invocations.len(), 2);
}

#[test]
fn group_rejects_incomplete_reservations_phases_and_aliased_receipts() {
    for mutation in [
        "missing",
        "reorder",
        "unsealed",
        "phase",
        "duplicate",
        "path",
        "version",
        "journal",
        "windows",
    ] {
        let mut ledger: OperationLedgerV2 = serde_json::from_slice(FIXTURE).unwrap();
        let group = &mut ledger.groups[0];
        match mutation {
            "missing" => {
                group.invocations.pop();
            }
            "reorder" => group.invocations.reverse(),
            "unsealed" => group.sealed = false,
            "phase" => {
                group.completed_phases.pop();
            }
            "duplicate" => {
                group.invocations[1] = group.invocations[0].clone();
                group.reserved_invocation_ids[1] = group.reserved_invocation_ids[0].clone();
            }
            "path" => {
                group.invocations[1].raw_report_path = group.invocations[0].raw_report_path.clone()
            }
            "version" => ledger.schema_version = 3,
            "journal" => group.reservation_ledger_path = "other.json".to_owned(),
            "windows" => {
                group.invocations[0].boundary =
                    hell_memcordon::CandidateBoundaryPolicy::SealedWindows
            }
            _ => unreachable!(),
        }
        assert!(
            validate_operation_ledger_v2(&ledger).is_err(),
            "accepted {mutation}"
        );
    }
    let mut unknown: serde_json::Value = serde_json::from_slice(FIXTURE).unwrap();
    unknown["groups"][0]["unknown"] = true.into();
    assert!(serde_json::from_value::<OperationLedgerV2>(unknown).is_err());
}
