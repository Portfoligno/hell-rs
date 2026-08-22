use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static FIXTURE_ID: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let id = FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "hell-ci-release-agreement-{label}-{}-{id}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("agreement fixture root must be created");
        Self { root }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn run_agreement(
    primary: &Path,
    independent: &Path,
    output: &Path,
) -> hell_testkit::SupervisedOutput {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
    command
        .arg("release")
        .arg("agree")
        .arg("--primary")
        .arg(primary)
        .arg("--independent")
        .arg(independent)
        .arg("--output")
        .arg(output);
    hell_testkit::run_supervised_command(&mut command, &[], Duration::from_secs(30))
        .expect("agreement command must execute under supervision")
}

fn run_protocol_digest(
    projection: &Path,
    obligation_rules: &Path,
    spec: &Path,
    output: &Path,
) -> hell_testkit::SupervisedOutput {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
    command
        .arg("release")
        .arg("protocol-digest")
        .arg("--projection")
        .arg(projection)
        .arg("--obligation-rules")
        .arg(obligation_rules)
        .arg("--spec")
        .arg(spec)
        .arg("--output")
        .arg(output);
    hell_testkit::run_supervised_command(&mut command, &[], Duration::from_secs(30))
        .expect("protocol digest command must execute under supervision")
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

struct DecisionBindings {
    protocol_sha256: String,
    candidate_sha: String,
    workflow_sha: String,
    release_plan_sha256: String,
    conformance_plan_sha256: String,
    source_inventory_sha256: String,
    trusted_inputs_sha256: String,
    obligation_rules_sha256: String,
    governance_declaration_sha256: String,
    governance_profile_sha256: String,
    governance_resolve_sha256: String,
    governance_post_assembly_sha256: String,
    governance_pre_attestation_sha256: String,
    residual_assumption_set_sha256: String,
    external_inputs_sha256: String,
    native_environment_set_sha256: String,
    cell_ledger_sha256: String,
    subject_manifest_sha256: String,
    release_gate_sha256: String,
}

fn repository_head(repository: &Path) -> String {
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(repository)
        .arg("rev-parse")
        .arg("--verify")
        .arg("HEAD^{commit}");
    let output = hell_testkit::run_supervised_command(&mut command, &[], Duration::from_secs(30))
        .expect("git revision lookup must execute under supervision");
    assert!(
        output.status.success() && !output.timed_out,
        "checked-out candidate revision is unavailable: {}",
        complete_stderr(&output)
    );
    let bytes = output
        .stdout
        .complete
        .as_deref()
        .unwrap_or(&output.stdout.prefix);
    String::from_utf8_lossy(bytes).trim().to_owned()
}

fn repository_file_sha256(path: &Path) -> String {
    hell_testkit::sha256_file(path)
        .unwrap_or_else(|error| {
            panic!(
                "repository input {} must be hashable: {error}",
                path.display()
            )
        })
        .hex()
}

fn decision_bindings() -> DecisionBindings {
    let repository = repository_root();
    let projection = repository.join("ci/release-protocol/v1/projection.json");
    DecisionBindings {
        protocol_sha256: json_text_field(&projection, "protocolSha256"),
        candidate_sha: repository_head(&repository),
        workflow_sha: repository_head(&repository),
        release_plan_sha256: repository_file_sha256(&projection),
        conformance_plan_sha256: repository_file_sha256(
            &repository.join("compat/corpus-obligations.toml"),
        ),
        source_inventory_sha256: repository_file_sha256(
            &repository.join("spec/release-admission-protocol-v1.md"),
        ),
        trusted_inputs_sha256: repository_file_sha256(
            &repository.join("compat/builtin-registry.json"),
        ),
        obligation_rules_sha256: repository_file_sha256(
            &repository.join("compat/release-obligation-rules-v1.json"),
        ),
        governance_declaration_sha256: repository_file_sha256(
            &repository.join("ci/governance-policy.toml"),
        ),
        governance_profile_sha256: repository_file_sha256(&repository.join("ci/github-api.toml")),
        governance_resolve_sha256: repository_file_sha256(
            &repository.join("crates/hell-ci/src/release/governance.rs"),
        ),
        governance_post_assembly_sha256: repository_file_sha256(
            &repository.join("crates/hell-ci/tests/governance_snapshots.rs"),
        ),
        governance_pre_attestation_sha256: repository_file_sha256(
            &repository.join(".github/workflows/release.yml"),
        ),
        residual_assumption_set_sha256: repository_file_sha256(
            &repository.join("spec/assurance-map.toml"),
        ),
        external_inputs_sha256: repository_file_sha256(&repository.join("ci/external-inputs.toml")),
        native_environment_set_sha256: repository_file_sha256(
            &repository.join("ci/rust-capabilities.toml"),
        ),
        cell_ledger_sha256: repository_file_sha256(
            &repository.join("ci/release-protocol/v1/manifest.toml"),
        ),
        subject_manifest_sha256: repository_file_sha256(&repository.join("Cargo.lock")),
        release_gate_sha256: repository_file_sha256(&repository.join("ci/protocol/v1.toml")),
    }
}

fn write_decision(path: &Path, implementation: &str, bindings: &DecisionBindings) {
    let json = format!(
        concat!(
            "{{\"admitted\":true,\"blockedCellCount\":0,",
            "\"candidateSha\":\"{}\",\"cellLedgerSha256\":\"{}\",",
            "\"conformancePlanSha256\":\"{}\",\"exemptedCellCount\":0,",
            "\"externalInputsSha256\":\"{}\",",
            "\"governanceDeclarationSha256\":\"{}\",",
            "\"governancePostAssemblySha256\":\"{}\",",
            "\"governancePreAttestationSha256\":\"{}\",",
            "\"governanceProfileSha256\":\"{}\",",
            "\"governanceResolveSha256\":\"{}\",",
            "\"implementation\":\"{}\",",
            "\"nativeEnvironmentSetSha256\":\"{}\",",
            "\"obligationRulesSha256\":\"{}\",\"protocolSha256\":\"{}\",",
            "\"protocolVersion\":\"release-admission-v1\",",
            "\"releaseGateSha256\":\"{}\",\"releasePlanSha256\":\"{}\",",
            "\"requiredCellCount\":1,",
            "\"residualAssumptionSetSha256\":\"{}\",\"schemaVersion\":1,",
            "\"sourceInventorySha256\":\"{}\",\"subjectManifestSha256\":\"{}\",",
            "\"trustedInputsSha256\":\"{}\",",
            "\"verifiedCellCount\":1,\"workflowSha\":\"{}\"}}\n"
        ),
        bindings.candidate_sha,
        bindings.cell_ledger_sha256,
        bindings.conformance_plan_sha256,
        bindings.external_inputs_sha256,
        bindings.governance_declaration_sha256,
        bindings.governance_post_assembly_sha256,
        bindings.governance_pre_attestation_sha256,
        bindings.governance_profile_sha256,
        bindings.governance_resolve_sha256,
        implementation,
        bindings.native_environment_set_sha256,
        bindings.obligation_rules_sha256,
        bindings.protocol_sha256,
        bindings.release_gate_sha256,
        bindings.release_plan_sha256,
        bindings.residual_assumption_set_sha256,
        bindings.source_inventory_sha256,
        bindings.subject_manifest_sha256,
        bindings.trusted_inputs_sha256,
        bindings.workflow_sha,
    );
    fs::write(path, json).expect("source-bound verifier decision must be written");
}

fn stage_decisions(fixture: &Fixture) -> (PathBuf, PathBuf) {
    let primary = fixture.path("primary.json");
    let independent = fixture.path("independent.json");
    let bindings = decision_bindings();
    write_decision(&primary, "hell-ci", &bindings);
    write_decision(&independent, "hell-release-verifier", &bindings);
    (primary, independent)
}

fn json_text_field(path: &Path, field: &str) -> String {
    let input = fs::read_to_string(path).expect("JSON fixture must be UTF-8");
    let marker = format!("\"{field}\":\"");
    let value = input
        .split_once(&marker)
        .and_then(|(_, suffix)| suffix.split_once('"').map(|(value, _)| value))
        .unwrap_or_else(|| panic!("JSON fixture field {field:?} is absent"));
    value.to_owned()
}

fn replace_exact(path: &Path, before: &str, after: &str) {
    let input = fs::read_to_string(path).expect("decision fixture must be UTF-8");
    assert_eq!(
        input.match_indices(before).count(),
        1,
        "mutation source must occur exactly once"
    );
    fs::write(path, input.replace(before, after)).expect("decision mutation must be written");
}

fn mutate_hex_field(path: &Path, field: &str) {
    let input = fs::read_to_string(path).expect("decision fixture must be UTF-8");
    let marker = format!("\"{field}\":\"");
    let value_start = input.find(&marker).map_or_else(
        || panic!("decision field {field:?} is absent"),
        |offset| offset + marker.len(),
    );
    let value_end = input[value_start..].find('"').map_or_else(
        || panic!("decision field {field:?} is unterminated"),
        |offset| value_start + offset,
    );
    let value = &input[value_start..value_end];
    assert!(
        !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "decision field {field:?} must contain hexadecimal identity bytes"
    );
    let replacement = if value.starts_with('f') { "e" } else { "f" };
    let mut mutated = String::with_capacity(input.len());
    mutated.push_str(&input[..value_start]);
    mutated.push_str(replacement);
    mutated.push_str(&input[value_start + value.chars().next().unwrap().len_utf8()..]);
    fs::write(path, mutated).expect("decision identity mutation must be written");
}

#[test]
fn primary_protocol_digest_is_derived_from_exact_normative_bytes() {
    let fixture = Fixture::new("protocol-digest");
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let projection = repository.join("ci/release-protocol/v1/projection.json");
    let obligation_rules = repository.join("compat/release-obligation-rules-v1.json");
    let spec = repository.join("spec/release-admission-protocol-v1.md");
    let output = fixture.path("protocol-digest.json");
    let result = run_protocol_digest(&projection, &obligation_rules, &spec, &output);
    assert!(
        result.status.success() && !result.timed_out,
        "primary protocol digest rejected the committed normative inputs"
    );
    let expected = json_text_field(&projection, "protocolSha256");
    assert_eq!(
        fs::read_to_string(&output).expect("protocol digest report must be UTF-8"),
        format!(
            "{{\"protocolSha256\":\"{expected}\",\"protocolVersion\":\"release-admission-v1\",\"schemaVersion\":1}}\n"
        )
    );

    let mutated_spec = fixture.path("release-admission-protocol-v1.md");
    let mut bytes = fs::read(&spec).expect("normative protocol must be readable");
    bytes.push(b'\n');
    fs::write(&mutated_spec, bytes).expect("mutated normative protocol must be written");
    let stale_output = fixture.path("stale-protocol-digest.json");
    let stale = run_protocol_digest(&projection, &obligation_rules, &mutated_spec, &stale_output);
    assert!(!stale.status.success() && !stale.timed_out);
    assert!(!stale_output.exists());
}

#[test]
fn agreement_accepts_matching_source_bound_decisions() {
    let fixture = Fixture::new("matching");
    let (primary, independent) = stage_decisions(&fixture);
    let agreement = fixture.path("agreement.json");
    let output = run_agreement(&primary, &independent, &agreement);
    assert!(
        output.status.success() && !output.timed_out,
        "matching decisions were rejected: {}",
        complete_stderr(&output)
    );
    let bytes = fs::read(&agreement).expect("agreement report must exist");
    assert_eq!(bytes.last(), Some(&b'\n'));
    let text = String::from_utf8(bytes).expect("agreement report must be UTF-8");
    assert!(text.contains("\"admitted\":true"));
    assert!(text.contains("\"equal\":true"));
    assert!(text.contains("\"state\":\"admitted\""));
    assert!(text.contains("\"mismatchedFields\":[]"));
}

#[test]
fn every_independently_mutable_authoritative_identity_blocks_agreement() {
    let mutations = [
        ("protocol-digest", "protocolSha256"),
        ("candidate", "candidateSha"),
        ("workflow", "workflowSha"),
        ("release-plan", "releasePlanSha256"),
        ("conformance-plan", "conformancePlanSha256"),
        ("source-inventory", "sourceInventorySha256"),
        ("trusted-inputs", "trustedInputsSha256"),
        ("obligation-rules", "obligationRulesSha256"),
        ("governance-declaration", "governanceDeclarationSha256"),
        ("governance-profile", "governanceProfileSha256"),
        ("governance-resolve", "governanceResolveSha256"),
        ("governance-post-assembly", "governancePostAssemblySha256"),
        (
            "governance-pre-attestation",
            "governancePreAttestationSha256",
        ),
        ("residual-assumptions", "residualAssumptionSetSha256"),
        ("external-inputs", "externalInputsSha256"),
        ("native-environment-set", "nativeEnvironmentSetSha256"),
        ("ledger", "cellLedgerSha256"),
        ("subjects", "subjectManifestSha256"),
        ("release-gate", "releaseGateSha256"),
    ];
    for (label, field) in mutations {
        let fixture = Fixture::new(label);
        let (primary, independent) = stage_decisions(&fixture);
        mutate_hex_field(&independent, field);
        let agreement = fixture.path("agreement.json");
        let output = run_agreement(&primary, &independent, &agreement);
        assert!(
            !output.status.success() && !output.timed_out,
            "authoritative mutation {label} was accepted"
        );
        assert!(complete_stderr(&output).contains("release.verifier-disagreement"));
        let report = fs::read_to_string(&agreement).expect("blocked report must exist");
        assert!(report.contains("\"diagnosticCode\":\"release.verifier-disagreement\""));
        assert!(report.contains("\"state\":\"blocked\""));
    }
}

#[test]
fn derived_count_and_admission_mutations_block_without_malformed_inputs() {
    for scenario in ["counts", "exempted", "admission"] {
        let fixture = Fixture::new(scenario);
        let (primary, independent) = stage_decisions(&fixture);
        match scenario {
            "counts" => {
                replace_exact(
                    &independent,
                    "\"requiredCellCount\":1",
                    "\"requiredCellCount\":2",
                );
                replace_exact(
                    &independent,
                    "\"verifiedCellCount\":1",
                    "\"verifiedCellCount\":2",
                );
            }
            "exempted" => {
                replace_exact(
                    &independent,
                    "\"exemptedCellCount\":0",
                    "\"exemptedCellCount\":1",
                );
                replace_exact(
                    &independent,
                    "\"verifiedCellCount\":1",
                    "\"verifiedCellCount\":0",
                );
            }
            "admission" => {
                replace_exact(&independent, "\"admitted\":true", "\"admitted\":false");
                replace_exact(
                    &independent,
                    "\"blockedCellCount\":0",
                    "\"blockedCellCount\":1",
                );
                replace_exact(
                    &independent,
                    "\"verifiedCellCount\":1",
                    "\"verifiedCellCount\":0",
                );
            }
            _ => unreachable!(),
        }
        let agreement = fixture.path("agreement.json");
        let output = run_agreement(&primary, &independent, &agreement);
        assert!(!output.status.success(), "scenario {scenario} was accepted");
        assert!(complete_stderr(&output).contains("release.verifier-disagreement"));
    }
}

#[test]
fn matching_nonadmissions_never_create_release_authority() {
    let fixture = Fixture::new("matching-blocked");
    let (primary, independent) = stage_decisions(&fixture);
    for path in [&primary, &independent] {
        replace_exact(path, "\"admitted\":true", "\"admitted\":false");
        replace_exact(path, "\"blockedCellCount\":0", "\"blockedCellCount\":1");
        replace_exact(path, "\"verifiedCellCount\":1", "\"verifiedCellCount\":0");
    }
    let agreement = fixture.path("agreement.json");
    let output = run_agreement(&primary, &independent, &agreement);
    assert!(!output.status.success());
    let report = fs::read_to_string(agreement).expect("blocked report must exist");
    assert!(report.contains("\"diagnosticCode\":\"release.verifiers-did-not-admit\""));
    assert!(report.contains("\"equal\":true"));
    assert!(report.contains("\"admitted\":false"));
}

#[test]
fn strict_decision_parser_rejects_duplicate_unknown_and_trailing_data_with_reports() {
    for scenario in ["duplicate", "unknown", "trailing"] {
        let fixture = Fixture::new(scenario);
        let (primary, independent) = stage_decisions(&fixture);
        match scenario {
            "duplicate" => replace_exact(
                &independent,
                "{\"admitted\":true,",
                "{\"admitted\":true,\"admitted\":true,",
            ),
            "unknown" => replace_exact(
                &independent,
                "{\"admitted\":true,",
                "{\"admitted\":true,\"unknown\":true,",
            ),
            "trailing" => {
                let mut bytes = fs::read(&independent).expect("decision must be readable");
                bytes.extend_from_slice(b"{}\n");
                fs::write(&independent, bytes).expect("trailing fixture must be written");
            }
            _ => unreachable!(),
        }
        let agreement = fixture.path("agreement.json");
        let output = run_agreement(&primary, &independent, &agreement);
        assert!(!output.status.success(), "scenario {scenario} was accepted");
        let report = fs::read_to_string(agreement).expect("invalid-input report must exist");
        assert!(report.contains("\"diagnosticCode\":\"release.verifier-decision-invalid\""));
        assert!(report.contains("\"state\":\"blocked\""));
    }
}
