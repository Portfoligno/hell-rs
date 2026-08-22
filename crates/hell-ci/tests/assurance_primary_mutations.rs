use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use hell_ci::assurance::{PrimaryControl, exercise};

static FIXTURE_ID: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let id = FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "hell-ci-assurance-{label}-{}-{id}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("create assurance fixture");
        Self { root }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).expect("remove assurance fixture");
    }
}

#[test]
fn matching_decisions_agree() {
    let fixture = Fixture::new("matching-decisions");
    let primary = fixture.path("primary.json");
    let independent = fixture.path("independent.json");
    let output = fixture.path("agreement.json");
    write_decision(&primary, "hell-ci");
    write_decision(&independent, "hell-release-verifier");

    let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
    command
        .args(["release", "agree", "--primary"])
        .arg(&primary)
        .arg("--independent")
        .arg(&independent)
        .arg("--output")
        .arg(&output)
        .args(
            hell_ci::mutation::test_activation_suffix().expect("typed mutation activation suffix"),
        );
    let result = run_bounded(&mut command, "matching decision agreement");
    assert!(
        result.status.success(),
        "matching source-bound decisions must agree: {:?}",
        result.stderr
    );
    let agreement: serde_json::Value =
        serde_json::from_slice(&fs::read(&output).expect("admitted agreement report must exist"))
            .expect("agreement report must be JSON");
    assert_eq!(agreement["admitted"], true);
    assert_eq!(agreement["equal"], true);
    assert_eq!(agreement["mismatchedFields"], serde_json::json!([]));
    assert_eq!(agreement["state"], "admitted");
}

#[test]
fn final_cell_omission_is_rejected() {
    assert_control_rejected(PrimaryControl::FinalCellOmission);
}

#[test]
fn duplicate_cell_is_rejected() {
    assert_control_rejected(PrimaryControl::DuplicateCell);
}

#[test]
fn relabeled_native_evidence_is_rejected() {
    assert_control_rejected(PrimaryControl::RelabeledNativeEvidence);
}

#[test]
fn exemption_selector_is_exact() {
    assert_control_rejected(PrimaryControl::ExemptionSelectorMismatch);
}

#[test]
fn exemption_uses_plan_time() {
    assert_control_rejected(PrimaryControl::ExemptionExpiredAtPlanTime);
}

#[test]
fn extra_evidence_archive_member_is_rejected() {
    assert_control_rejected(PrimaryControl::ExtraEvidenceArchiveMember);
}

#[test]
fn omitted_subject_is_rejected() {
    assert_control_rejected(PrimaryControl::OmittedSubject);
}

fn assert_control_rejected(control: PrimaryControl) {
    assert!(
        exercise(control).is_err(),
        "{control:?} bypassed its production validator"
    );
}

fn write_decision(path: &Path, implementation: &str) {
    let repository = repository_root();
    let projection = repository.join("ci/release-protocol/v1/projection.json");
    let projection_value: serde_json::Value =
        serde_json::from_slice(&fs::read(&projection).expect("read normative protocol projection"))
            .expect("normative protocol projection must be JSON");
    let head = repository_head(&repository);
    let mut bytes = serde_json::to_vec(&serde_json::json!({
        "admitted": true,
        "blockedCellCount": 0,
        "candidateSha": head,
        "cellLedgerSha256": file_digest(&repository.join("ci/release-protocol/v1/manifest.toml")),
        "conformancePlanSha256": file_digest(&repository.join("compat/corpus-obligations.toml")),
        "exemptedCellCount": 0,
        "externalInputsSha256": file_digest(&repository.join("ci/external-inputs.toml")),
        "governanceDeclarationSha256": file_digest(&repository.join("ci/governance-policy.toml")),
        "governancePostAssemblySha256": file_digest(&repository.join("crates/hell-ci/src/release/governance.rs")),
        "governancePreAttestationSha256": file_digest(&repository.join("crates/hell-ci/tests/governance_snapshots.rs")),
        "governanceProfileSha256": file_digest(&repository.join("ci/github-api.toml")),
        "governanceResolveSha256": file_digest(&repository.join("spec/release-assurance.md")),
        "implementation": implementation,
        "nativeEnvironmentSetSha256": file_digest(&repository.join("ci/rust-capabilities.toml")),
        "obligationRulesSha256": file_digest(&repository.join("compat/release-obligation-rules-v1.json")),
        "protocolSha256": projection_value["protocolSha256"],
        "protocolVersion": "release-admission-v1",
        "releaseGateSha256": file_digest(&repository.join("ci/protocol/v1.toml")),
        "releasePlanSha256": file_digest(&projection),
        "requiredCellCount": 1,
        "residualAssumptionSetSha256": file_digest(&repository.join("spec/assurance-map.toml")),
        "schemaVersion": 1,
        "sourceInventorySha256": file_digest(&repository.join("spec/release-admission-protocol-v1.md")),
        "subjectManifestSha256": file_digest(&repository.join("Cargo.lock")),
        "trustedInputsSha256": file_digest(&repository.join("compat/builtin-registry.json")),
        "verifiedCellCount": 1,
        "workflowSha": repository_head(&repository)
    }))
    .expect("serialize source-bound decision");
    bytes.push(b'\n');
    fs::write(path, bytes).expect("write source-bound decision");
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn repository_head(repository: &Path) -> String {
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(repository)
        .args(["rev-parse", "--verify", "HEAD^{commit}"]);
    let output = run_bounded(&mut command, "resolve candidate commit");
    assert!(output.status.success(), "candidate commit must resolve");
    String::from_utf8(
        output
            .stdout
            .complete
            .expect("candidate commit output must be bounded"),
    )
    .expect("candidate commit must be UTF-8")
    .trim()
    .to_owned()
}

fn file_digest(path: &Path) -> String {
    hell_testkit::sha256_file(path)
        .unwrap_or_else(|error| panic!("hash {}: {error}", path.display()))
        .hex()
}

fn run_bounded(command: &mut Command, context: &str) -> hell_testkit::SupervisedOutput {
    let result = hell_testkit::run_supervised_command(command, &[], Duration::from_secs(30))
        .unwrap_or_else(|error| panic!("{context} under process-tree supervision: {error}"));
    assert!(!result.timed_out, "{context} exceeded its deadline");
    assert!(
        result
            .phase_timings
            .iter()
            .any(|phase| phase.name == "quiescence-complete"),
        "{context} did not reach process-tree quiescence"
    );
    assert_eq!(
        result.phase_timings.last().map(|phase| phase.name),
        Some("stdin-joined"),
        "{context} did not produce a terminal supervised I/O receipt"
    );
    result
}
