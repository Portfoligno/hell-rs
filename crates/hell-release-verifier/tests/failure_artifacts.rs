mod support;

use std::fs;

use hell_release_verifier::{VerifyOptions, verify};
use support::TestDirectory;

const PROJECTION: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../ci/release-protocol/v1/projection.json"
);

#[test]
fn strict_plan_parser_failures_persist_a_blocked_typed_report() {
    for (case, plan_bytes, diagnostic, message) in [
        (
            "duplicate-key",
            b"{\"schemaVersion\":1,\"schemaVersion\":1}\n".as_slice(),
            "release.json.duplicate-key",
            "duplicate JSON object key \"schemaVersion\"",
        ),
        (
            "trailing-bytes",
            b"{}\nfalse".as_slice(),
            "release.json.trailing-bytes",
            "trailing JSON data at byte 3",
        ),
        (
            "noncanonical",
            b"{ \"schemaVersion\":1}\n".as_slice(),
            "release.json.noncanonical",
            "JSON input is not canonical with exactly one trailing LF",
        ),
    ] {
        let root = TestDirectory::new(case);
        let plan = root.path().join("plan.json");
        let conformance_plan = root.path().join("conformance-plan.json");
        let bundle = root.path().join("bundle");
        let output = root.path().join("output");
        fs::write(&plan, plan_bytes).expect("write malformed plan fixture");
        fs::write(&conformance_plan, b"{}\n").expect("write unreachable conformance fixture");
        fs::create_dir(&bundle).expect("create unreachable bundle fixture");

        let error = verify(VerifyOptions {
            plan,
            conformance_plan,
            bundle,
            protocol_projection: PROJECTION.into(),
            governance_resolve: None,
            governance_post_assembly: None,
            governance_pre_attestation: None,
            output: output.clone(),
        })
        .expect_err("malformed plan must fail independent verification");
        assert_eq!(error, message);

        let report = fs::read_to_string(output.join("independent-verifier-report.json"))
            .expect("blocked verification report must be persisted");
        let expected = format!(
            "{{\"admitted\":false,\"diagnosticCode\":{diagnostic:?},\"diagnosticMessage\":{message:?},\"implementation\":\"hell-release-verifier\",\"schemaVersion\":1,\"state\":\"blocked\"}}\n"
        );
        assert_eq!(report, expected);
        assert!(!output.join("independent-verifier-decision.json").exists());
    }
}
