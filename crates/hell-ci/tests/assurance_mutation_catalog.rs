use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static FIXTURE_ID: AtomicU64 = AtomicU64::new(0);

const EXPECTED: [(&str, &str, &str, &str, &str, &str); 13] = [
    (
        "digest-binding-inverted",
        "REL-DIGEST-BINDING",
        "release-agreement",
        "crates/hell-ci/src/release/decision.rs",
        "agree",
        "known-good",
    ),
    (
        "drop-final-cell",
        "REL-ADMISSION-LEDGER-COMPLETE",
        "ledger",
        "crates/hell-ci/src/conformance/ledger.rs",
        "ConformancePlan::validate",
        "missing-cell",
    ),
    (
        "accept-duplicate-cell",
        "REL-ADMISSION-LEDGER-COMPLETE",
        "ledger",
        "crates/hell-ci/src/conformance/ledger.rs",
        "ConformancePlan::validate",
        "duplicate-cell",
    ),
    (
        "ignore-evidence-platform",
        "REL-EVIDENCE-PLATFORM-BOUND",
        "ledger",
        "crates/hell-ci/src/conformance/evidence.rs",
        "validate_record_binding",
        "linux-evidence-relabeled-as-windows",
    ),
    (
        "compare-exemption-id-only",
        "REL-EXEMPTION-EXACT",
        "exemption",
        "crates/hell-ci/src/conformance/ledger.rs",
        "validate_exemption",
        "exemption-with-mismatched-selector",
    ),
    (
        "use-wall-clock-for-exemption",
        "REL-EXEMPTION-PLAN-TIME",
        "exemption",
        "crates/hell-ci/src/conformance/ledger.rs",
        "validate_exemption",
        "exemption-uses-wall-clock-time",
    ),
    (
        "allow-extra-archive-member",
        "REL-ARCHIVE-EXACT",
        "archive",
        "crates/hell-ci/src/release/archive.rs",
        "validate_evidence_members",
        "extra-archive-member",
    ),
    (
        "ignore-subject",
        "REL-SUBJECTS-EXACT",
        "subjects",
        "crates/hell-ci/src/release/verify.rs",
        "validate_subject_inventory",
        "subject-omitted-from-manifest",
    ),
    (
        "grant-contents-write-to-attest",
        "REL-PRIVILEGE-SPLIT",
        "workflow-permissions",
        "crates/hell-workflow-auditor/src/lib.rs",
        "validate_privilege_split",
        "workflow-attest-contents-write",
    ),
    (
        "grant-id-token-write-to-publish",
        "REL-PRIVILEGE-SPLIT",
        "workflow-permissions",
        "crates/hell-workflow-auditor/src/lib.rs",
        "validate_privilege_split",
        "workflow-publish-id-token-write",
    ),
    (
        "skip-shallow-envelope-verification",
        "REL-ENVELOPE-BOUND",
        "publication-envelope",
        "crates/hell-release-publisher/src/lib.rs",
        "validate_shallow_publication_envelope",
        "publisher-envelope-predecessor-mismatch",
    ),
    (
        "unavailable-governance-is-matched",
        "REL-GOVERNANCE-TRISTATE",
        "governance",
        "crates/hell-ci/src/release/governance.rs",
        "unavailable",
        "governance-ruleset-unavailable-residual",
    ),
    (
        "accept-unknown-publisher-draft",
        "REL-PUBLISH-STATE-CLOSED",
        "publisher-state",
        "crates/hell-release-publisher/src/lib.rs",
        "verify_assets",
        "publisher-unexpected-asset",
    ),
];

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let sequence = FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "hell-ci-assurance-catalog-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("create assurance catalog fixture");
        Self { root }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if self.root.exists() {
            fs::remove_dir_all(&self.root).expect("remove assurance catalog fixture");
        }
    }
}

#[test]
fn assurance_catalog_runs_every_source_bound_baseline_and_selected_mutant() {
    let fixture = Fixture::new();
    let repository = repository_root();
    let output = fixture.root.join("mutation");
    let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
    command
        .current_dir(&repository)
        .args(["mutation", "assurance", "--manifest"])
        .arg("compat/assurance-mutants.toml")
        .args(["--repository-root", ".", "--output"])
        .arg(&output);
    let result = hell_testkit::run_supervised_command(&mut command, &[], Duration::from_mins(10))
        .expect("run source-bound mutation assurance under process-tree supervision");
    assert!(
        !result.timed_out,
        "mutation assurance exceeded its deadline"
    );
    assert!(
        result.status.success(),
        "mutation assurance failed: {}",
        complete_stderr(&result)
    );
    assert_terminal_cleanup_receipt(&result);

    let report_path = output.join("assurance.json");
    let report_bytes = fs::read(&report_path).expect("read mutation assurance report");
    assert_eq!(report_bytes.last(), Some(&b'\n'));
    let report: serde_json::Value =
        serde_json::from_slice(&report_bytes).expect("parse mutation assurance report");
    assert_eq!(report["schemaVersion"], 1);
    assert_eq!(report["state"], "passed");
    assert_eq!(report["catalogId"], "release-assurance-v1");
    assert_eq!(
        report["catalogSha256"],
        hell_testkit::sha256_file(&repository.join("compat/assurance-mutants.toml"))
            .expect("hash source-bound mutation catalog")
            .hex()
    );
    let mutants = report["mutants"]
        .as_array()
        .expect("mutation report contains an ordered mutant array");
    assert_eq!(mutants.len(), EXPECTED.len());
    for (record, (id, claim, module, source, symbol, vector)) in mutants.iter().zip(EXPECTED) {
        assert_eq!(record["id"], id);
        assert_eq!(record["claim"], claim);
        assert_eq!(record["module"], module);
        assert_eq!(record["source"], source);
        assert_eq!(record["symbol"], symbol);
        assert_eq!(record["vectors"], serde_json::json!([vector]));
        assert_eq!(record["detected"], true);
    }
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
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

fn assert_terminal_cleanup_receipt(result: &hell_testkit::SupervisedOutput) {
    assert!(
        result
            .phase_timings
            .iter()
            .any(|phase| phase.name == "quiescence-complete"),
        "mutation assurance did not reach process-tree quiescence"
    );
    assert_eq!(
        result.phase_timings.last().map(|phase| phase.name),
        Some("stdin-joined"),
        "mutation assurance did not produce the terminal supervised I/O receipt"
    );
}
