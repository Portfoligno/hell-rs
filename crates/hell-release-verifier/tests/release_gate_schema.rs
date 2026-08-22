const GATE_WITHOUT_DIGEST: &str = concat!(
    "{\"candidateCodeExecutedInPublisher\":false,",
    "\"candidateSha\":\"434c9104de69600ce4a85601dc2ac48a45aa8f8f\",",
    "\"conformanceAcceptanceSha256\":\"5ba9bc264a186e90b0ff0f2545cbd5a343a76451e3d4d1930c28fa75592ddfaf\",",
    "\"conformanceCounts\":{\"blockedInvalidEvidence\":0,\"blockedMismatch\":0,\"blockedMissingEvidence\":0,\"excluded\":0,\"exempted\":0,\"notApplicable\":0,\"verifiedExact\":1,\"verifiedNormalized\":0,\"verifiedPlatformEquivalent\":0},",
    "\"conformanceEvidenceSha256\":\"f7f711210a6825d639935c13eb1bee08bd2c771ddea91a25252a07608a277d71\",",
    "\"conformancePlanSha256\":\"544e0625d827694f983e10335633a8aedae5d61685839a4a77d56a357ca6e02f\",",
    "\"conformanceReportSha256\":\"ce203e9c22801a98e07499efe0fe472630e97b92b10c8af01058f662289b53bd\",",
    "\"conformanceStandard\":\"release-conformance-v1\",",
    "\"externalInputsSha256\":\"f7f711210a6825d639935c13eb1bee08bd2c771ddea91a25252a07608a277d71\",",
    "\"governanceDeclarationSha256\":\"544e0625d827694f983e10335633a8aedae5d61685839a4a77d56a357ca6e02f\",",
    "\"governanceProfileSha256\":\"ce203e9c22801a98e07499efe0fe472630e97b92b10c8af01058f662289b53bd\",",
    "\"nativeEnvironmentSetSha256\":\"f8d5bee2b0351353249299cc271c216936fc553bc6d17b4fe2e6c06c525fbceb\",",
    "\"releasePlanSha256\":\"caea946bce05914252e57f3314c391c7ee6aef799545dce85ef3e8c827e1678c\",",
    "\"repository\":\"Portfoligno/hell-rs\",",
    "\"residualAssumptionSetSha256\":\"d151c0ed1ebb1a283e4ef19082115a20505947cb89b7262087bfa0b2fcfd2439\",",
    "\"runAttempt\":1,\"runId\":93482217,\"schemaVersion\":2,\"state\":\"admitted\",",
    "\"subjectsSha256\":\"e35821a70d5289c0bbd75199f61d3580a5d31b7b5453c4ddf6cb037ff2d782a5\",",
    "\"tag\":\"v0.1.0\",\"version\":\"0.1.0\",",
    "\"workflowSha\":\"434c9104de69600ce4a85601dc2ac48a45aa8f8f\"}\n",
);
const GATE_DIGEST: &str = "702c0463fe49d04ea33858e7a1c689d1e62d2623071c9424cb3fdf6e75627088";

fn gate() -> Vec<u8> {
    GATE_WITHOUT_DIGEST
        .replace(
            "\"releasePlanSha256\"",
            &format!("\"releaseGateSha256\":\"{GATE_DIGEST}\",\"releasePlanSha256\""),
        )
        .into_bytes()
}

#[test]
fn independent_gate_schema_accepts_the_pre_governance_producer_contract() {
    hell_release_verifier::validate_release_gate_document(&gate())
        .expect("the exact producer gate schema and content digest must be accepted");
}

#[test]
fn governance_phase_receipts_are_rejected_inside_the_pre_governance_gate() {
    let digest = "544e0625d827694f983e10335633a8aedae5d61685839a4a77d56a357ca6e02f";
    let changed = String::from_utf8(gate())
        .expect("gate fixture is UTF-8")
        .replace(
            "\"governanceProfileSha256\"",
            &format!("\"governancePostAssemblySha256\":\"{digest}\",\"governanceProfileSha256\""),
        );
    assert!(hell_release_verifier::validate_release_gate_document(changed.as_bytes()).is_err());
}
