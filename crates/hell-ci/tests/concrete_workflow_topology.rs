use std::fs;
use std::path::{Path, PathBuf};

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn workflow(name: &str) -> String {
    fs::read_to_string(repository_root().join(".github/workflows").join(name))
        .expect("workflow must be readable UTF-8")
}

fn job_block<'a>(workflow: &'a str, id: &str, next: Option<&str>) -> &'a str {
    let marker = format!("\n  {id}:\n");
    let start = workflow.find(&marker).map_or_else(
        || panic!("workflow job {id:?} is missing"),
        |offset| offset + marker.len(),
    );
    let end = next.map_or(workflow.len(), |next_id| {
        let next_marker = format!("\n  {next_id}:\n");
        workflow[start..].find(&next_marker).map_or_else(
            || panic!("workflow job {next_id:?} is missing"),
            |offset| start + offset,
        )
    });
    &workflow[start..end]
}

fn protocol_table<'a>(protocol: &'a str, name: &str) -> &'a str {
    let marker = format!("[{name}]\n");
    let start = protocol.find(&marker).map_or_else(
        || panic!("protocol table {name:?} is missing"),
        |offset| offset + marker.len(),
    );
    let end = protocol[start..]
        .find("\n[")
        .map_or(protocol.len(), |offset| start + offset);
    &protocol[start..end]
}

fn external_input_table<'a>(document: &'a str, id: &str) -> &'a str {
    let expected_id = format!("id = \"{id}\"");
    document
        .split("\n[[input]]\n")
        .skip(1)
        .find(|table| table.lines().any(|line| line == expected_id))
        .unwrap_or_else(|| panic!("external input {id:?} is missing"))
}

fn validate_cargo_deny_lock(document: &str) -> Result<(), String> {
    let expected = concat!(
        "id = \"cargo-deny\"\n",
        "kind = \"cargo-package\"\n",
        "package = \"cargo-deny\"\n",
        "version = \"0.20.2\"\n",
        "platforms = [\"linux-x86_64\"]\n",
        "acquisition-phase = \"native-platform\"",
    );
    let observed = external_input_table(document, "cargo-deny").trim_end();
    if observed != expected {
        return Err("cargo-deny external-input authority differs".to_owned());
    }
    Ok(())
}

#[test]
fn release_deep_verification_attestation_and_publication_are_privilege_separated() {
    let release = workflow("release.yml");
    let assemble = job_block(&release, "assemble", Some("governance"));
    let governance = job_block(&release, "governance", Some("final-verify"));
    let final_verify = job_block(&release, "final-verify", Some("attest"));
    let attest = job_block(&release, "attest", Some("publish"));
    let publish = job_block(&release, "publish", None);

    assert_release_assembly_and_governance(assemble, governance);
    assert_final_verification(&release, final_verify);
    assert_attestation(attest);
    assert_publication(publish);
}

fn assert_release_assembly_and_governance(assemble: &str, governance: &str) {
    assert!(
        governance.contains("vector_artifact_id: ${{ steps.upload-vectors.outputs.artifact-id }}")
    );
    assert!(
        governance.contains(
            "vector_artifact_digest: ${{ steps.upload-vectors.outputs.artifact-digest }}"
        )
    );
    assert!(governance.contains("release materialize-protocol-vectors"));
    assert!(assemble.contains(
        "hell-release-publisher check-remote-state --plan release-input/plan/release-plan.json --phase post-assembly"
    ));
    assert!(!assemble.contains("hell-ci release check-remote-state"));
    assert!(governance.contains("--platform-input release-input/platforms"));
    assert!(
        governance.contains("--independent-verifier ./independent-target/ci/hell-release-verifier")
    );
    assert!(
        governance.contains(
            "name: release-protocol-vectors-${{ github.run_id }}-${{ github.run_attempt }}"
        )
    );
}

fn assert_final_verification(release: &str, final_verify: &str) {
    assert!(final_verify.contains("needs:\n      - resolve\n      - assemble\n      - governance"));
    assert!(release.contains("permissions:\n  actions: read\n  contents: read"));
    assert!(!final_verify.contains("permissions:"));
    assert!(!final_verify.contains("id-token: write"));
    assert!(!final_verify.contains("contents: write"));
    assert!(!final_verify.contains("env:"));
    assert!(final_verify.contains("release final-verify"));
    assert!(final_verify.contains("hell-release-verifier"));
    assert!(
        final_verify
            .contains("--protocol-projection automation/ci/release-protocol/v1/projection.json")
    );
    assert!(
        final_verify
            .contains("--expected-artifact-digest ${{ needs.assemble.outputs.artifact_digest }}")
    );
    assert!(
        final_verify
            .contains("assembled_artifact_digest: ${{ needs.assemble.outputs.artifact_digest }}")
    );
    assert!(
        final_verify.contains("artifact-ids: ${{ needs.governance.outputs.vector_artifact_id }}")
    );
    let primary_vectors = final_verify
        .find("hell-ci release verify-vectors")
        .expect("primary vector execution must exist");
    let independent_vectors = final_verify
        .find("hell-release-verifier verify-vectors")
        .expect("independent vector execution must exist");
    let candidate_verification = final_verify
        .find("hell-ci release final-verify")
        .expect("candidate final verification must exist");
    assert!(primary_vectors < independent_vectors && independent_vectors < candidate_verification);
}

fn assert_attestation(attest: &str) {
    assert!(attest.contains("needs:\n      - resolve\n      - final-verify"));
    assert!(attest.contains("contents: read"));
    assert!(attest.contains("id-token: write"));
    assert!(attest.contains("attestations: write"));
    assert!(attest.contains("artifact-metadata: write"));
    assert!(!attest.contains("contents: write"));
    assert!(attest.contains("verify-envelope"));
    assert!(attest.contains(
        "--expected-artifact-digest ${{ needs.final-verify.outputs.assembled_artifact_digest }}"
    ));
    assert!(attest.contains("artifact-ids: ${{ needs.final-verify.outputs.artifact_id }}"));
    assert!(attest.contains("digest-mismatch: error"));
    assert!(!attest.contains(
        "verify-envelope --envelope verified-release/publication-envelope.json --subject-root verified-release --expected-artifact-digest ${{ needs.final-verify.outputs.artifact_digest }}"
    ));
    assert!(!attest.contains("release final-verify"));
    assert!(attest.contains("id: build-attestation"));
    assert!(attest.contains("id: release-gate-attestation"));
    assert!(
        attest.contains(
            "--build-provenance-bundle ${{ steps.build-attestation.outputs.bundle-path }}"
        )
    );
    assert!(attest.contains(
        "--release-gate-bundle ${{ steps.release-gate-attestation.outputs.bundle-path }}"
    ));
}

fn assert_publication(publish: &str) {
    assert!(publish.contains("needs:\n      - resolve\n      - governance\n      - attest"));
    assert!(publish.contains("contents: write"));
    assert!(!publish.contains("id-token: write"));
    assert!(!publish.contains("attestations: write"));
    assert!(!publish.contains("artifact-metadata: write"));
    assert!(!publish.contains("verify-bundle"));
    assert!(!publish.contains("release final-verify"));
    assert!(!publish.contains("path: candidate"));
    assert!(publish.contains("--expected-artifact-id ${{ needs.attest.outputs.artifact_id }}"));
    assert!(
        publish.contains("--expected-artifact-digest ${{ needs.attest.outputs.artifact_digest }}")
    );
    assert!(publish.contains(
        "--governance-baseline release-input/plan/governance-resolve.json --governance-receipt release-reports/governance-pre-publish.json"
    ));
}

#[test]
fn governance_receipts_are_plan_bound_chained_and_retained_at_every_phase() {
    let release = workflow("release.yml");
    let resolve = job_block(&release, "resolve", Some("linux"));
    let assemble = job_block(&release, "assemble", Some("governance"));
    let governance = job_block(&release, "governance", Some("final-verify"));
    let final_verify = job_block(&release, "final-verify", Some("attest"));
    let publish = job_block(&release, "publish", None);

    let plan = resolve
        .find("release plan --resolution")
        .expect("release plan command must exist");
    let baseline = resolve
        .find("governance-snapshot --policy automation/ci/governance-policy.toml --api-policy automation/ci/github-api.toml --plan release-plan/release-plan.json --phase resolve --output release-plan/governance-resolve.json --report release-reports/governance-resolve.json")
        .expect("resolve governance snapshot must exist");
    let upload = resolve
        .find("path: release-plan")
        .expect("plan artifact upload must exist");
    assert!(plan < baseline && baseline < upload);

    let assembly_command_offset = assemble
        .find("release assemble --plan")
        .expect("assembly command must exist");
    assert!(assemble.contains("release assemble --plan"));
    let post_assembly = governance
        .find("governance-snapshot --policy automation/ci/governance-policy.toml --api-policy automation/ci/github-api.toml --plan release-input/plan/release-plan.json --baseline release-input/plan/governance-resolve.json --phase post-assembly --output release-reports/governance-post-assembly.json --report release-reports/governance-post-assembly-report.json")
        .expect("post-assembly governance snapshot must exist");
    let pre_attestation = governance
        .find("governance-snapshot --policy automation/ci/governance-policy.toml --api-policy automation/ci/github-api.toml --plan release-input/plan/release-plan.json --baseline release-input/plan/governance-resolve.json --predecessor release-reports/governance-post-assembly.json --phase pre-attestation --output release-reports/governance-pre-attestation.json --report release-reports/governance-pre-attestation-report.json")
        .expect("pre-attestation governance snapshot must exist");
    let materialize = governance
        .find("release materialize-protocol-vectors")
        .expect("protocol materializer must exist");
    assert!(post_assembly < pre_attestation && pre_attestation < materialize);
    assert!(governance.contains(
        "--governance-post-assembly release-reports/governance-post-assembly.json --governance-pre-attestation release-reports/governance-pre-attestation.json"
    ));
    assert!(assembly_command_offset < assemble.len());

    let independent_vectors = final_verify
        .find("hell-release-verifier verify-vectors")
        .expect("independent vector command must exist");
    let deep_verify = final_verify
        .find("release final-verify --plan")
        .expect("deep final verification must exist");
    assert!(independent_vectors < deep_verify);
    assert!(final_verify.contains(
        "--governance-post-assembly release-input/governance/governance-post-assembly.json --governance-pre-attestation release-input/governance/governance-pre-attestation.json"
    ));
    assert!(final_verify.contains("artifact-ids: ${{ needs.governance.outputs.artifact_id }}"));

    let pre_publish = publish
        .find("governance-snapshot --policy automation/ci/governance-policy.toml --api-policy automation/ci/github-api.toml --plan release-input/plan/release-plan.json --baseline release-input/plan/governance-resolve.json --predecessor release-input/governance/governance-pre-attestation.json --phase pre-publish --output release-reports/governance-pre-publish.json --report release-reports/governance-pre-publish-report.json")
        .expect("pre-publish governance snapshot must exist");
    let publication = publish
        .find("hell-release-publisher publish")
        .expect("publisher command must exist");
    let report_upload = publish
        .find("name: release-publication-reports-${{ github.run_id }}-${{ github.run_attempt }}")
        .expect("publication report upload must exist");
    assert!(pre_publish < publication && publication < report_upload);
    let report_step = publish
        .find("name: Retain publication and governance reports")
        .expect("publication report retention step must exist");
    assert!(publish[report_step..report_upload].contains("if: ${{ always() }}"));
}

#[test]
fn readiness_summary_is_failure_terminal_and_uses_one_artifact_layout() {
    let ci = workflow("ci.yml");
    let summary = job_block(&ci, "summary", None);
    assert!(summary.contains(
        "needs:\n      - plan\n      - linux\n      - macos\n      - windows\n      - verify"
    ));
    assert!(summary.contains("if: ${{ !cancelled() }}"));
    assert!(!summary.contains("if: ${{ always() }}\n    permissions:"));
    for state in ["success", "failure", "skipped"] {
        for job in ["plan", "linux", "macos", "windows", "verify"] {
            let prefix = format!("readiness record-job-state --job {job} --state {state}");
            assert!(summary.contains(&prefix));
            if state == "success" {
                assert!(summary.contains(&format!(
                    "{prefix} --artifact-id ${{{{ needs.{job}.outputs.artifact_id }}}} --artifact-digest ${{{{ needs.{job}.outputs.artifact_digest }}}} --output readiness-state"
                )));
            } else {
                assert!(summary.contains(&format!("{prefix} --output readiness-state")));
            }
        }
    }
    for path in [
        "readiness-input/plan",
        "readiness-input/platforms/linux-x86_64",
        "readiness-input/platforms/macos-aarch64",
        "readiness-input/platforms/windows-x86_64",
        "readiness-input/verifier",
    ] {
        assert!(summary.contains(&format!("path: {path}")));
    }
    assert!(summary.contains(
        "readiness summarize --state-root readiness-state --input readiness-input --output readiness-summary"
    ));
}

#[test]
fn readiness_plan_executes_the_typed_and_independent_control_audits_before_planning() {
    let projection: serde_yaml::Value = serde_yaml::from_slice(
        &fs::read(repository_root().join("ci/protocol/v1.audit.json"))
            .expect("audit projection must be readable"),
    )
    .expect("audit projection must be strict JSON");
    let commands = projected_commands(&projection, ".github/workflows/ci.yml", "plan");
    assert_eq!(commands.len(), READINESS_PLAN_EXPECTED_COMMANDS.len());
    for (actual, expected) in commands.iter().zip(READINESS_PLAN_EXPECTED_COMMANDS) {
        assert_eq!(
            actual.iter().map(String::as_str).collect::<Vec<_>>(),
            *expected
        );
    }
}

#[test]
fn cargo_deny_authority_is_linux_only_across_lock_and_workflows() {
    let ci = workflow("ci.yml");
    let nightly = workflow("nightly.yml");
    let release = workflow("release.yml");
    let ci_linux = job_block(&ci, "linux", Some("macos"));
    let release_linux = job_block(&release, "linux", Some("macos"));
    let external_inputs = fs::read_to_string(repository_root().join("ci/external-inputs.toml"))
        .expect("external-input lock must be UTF-8");
    validate_cargo_deny_lock(&external_inputs)
        .expect("cargo-deny external-input authority must name exactly its Linux consumer");

    for (label, job, cargo_key, target_key, gate) in [
        (
            "readiness Linux",
            ci_linux,
            "readiness-linux-${{ runner.os }}-${{ runner.arch }}-cargo-${{ hashFiles('automation/rust-toolchain.toml', 'automation/Cargo.lock', 'automation/Cargo.toml', 'automation/crates/**/Cargo.toml', 'candidate/rust-toolchain.toml', 'candidate/Cargo.lock', 'candidate/Cargo.toml', 'candidate/crates/**/Cargo.toml') }}-cargo-deny-0.20.2",
            "readiness-linux-${{ runner.os }}-${{ runner.arch }}-cargo-deny-target-0.20.2-${{ hashFiles('automation/rust-toolchain.toml') }}",
            "Run Linux technical readiness gate",
        ),
        (
            "release Linux",
            release_linux,
            "release-linux-cargo-${{ needs.resolve.outputs.build_inputs_digest }}-cargo-deny-0.20.2",
            "release-linux-cargo-deny-target-${{ runner.os }}-${{ runner.arch }}-${{ needs.resolve.outputs.build_inputs_digest }}-0.20.2",
            "Run Linux release gate, collect conformance evidence, and package",
        ),
    ] {
        let restore = job
            .find("- name: Restore cargo-deny compilation cache")
            .unwrap_or_else(|| panic!("{label} does not restore the cargo-deny cache"));
        let candidate_cache = job
            .find("- name: Restore candidate compilation cache")
            .unwrap_or_else(|| panic!("{label} does not restore the candidate cache"));
        let install = job
            .find("- name: Install pinned cargo-deny")
            .unwrap_or_else(|| panic!("{label} does not install cargo-deny"));
        let gate = job
            .find(gate)
            .unwrap_or_else(|| panic!("{label} platform gate is missing"));
        let save = job
            .find("- name: Save cargo-deny compilation cache")
            .unwrap_or_else(|| panic!("{label} does not save the cargo-deny cache"));
        let candidate_save = job
            .find("- name: Save candidate compilation cache")
            .unwrap_or_else(|| panic!("{label} does not save the candidate cache"));

        assert!(restore < candidate_cache, "{label} restores tools first");
        assert!(
            candidate_cache < install && install < gate,
            "{label} installs before use"
        );
        assert!(
            gate < save && save < candidate_save,
            "{label} saves tools first"
        );
        assert_eq!(job.matches(cargo_key).count(), 2, "{label} Cargo cache key");
        assert_eq!(job.matches(target_key).count(), 2, "{label} tool cache key");
        assert_eq!(
            job.matches("path: ci-tool-cache/cargo-deny-target").count(),
            2
        );
        assert_eq!(
            job.matches("run: cargo install cargo-deny --locked --version 0.20.2 --force --target-dir ../ci-tool-cache/cargo-deny-target")
                .count(),
            1,
            "{label} pinned installation",
        );
    }

    let ci_macos = job_block(&ci, "macos", Some("windows"));
    let ci_windows = job_block(&ci, "windows", Some("verify"));
    let nightly_linux = job_block(&nightly, "linux", Some("fuzz"));
    let nightly_macos = job_block(&nightly, "macos", Some("windows"));
    let nightly_windows = job_block(&nightly, "windows", None);
    let release_macos = job_block(&release, "macos", Some("windows"));
    let release_windows = job_block(&release, "windows", Some("assemble"));
    assert_eq!(
        nightly_linux.matches("Install pinned cargo-deny").count(),
        1,
        "Nightly Linux must retain its cargo-deny test authority",
    );
    for (label, job) in [
        ("readiness macOS", ci_macos),
        ("readiness Windows", ci_windows),
        ("Nightly macOS", nightly_macos),
        ("Nightly Windows", nightly_windows),
        ("release macOS", release_macos),
        ("release Windows", release_windows),
    ] {
        assert!(
            !job.contains("cargo-deny"),
            "{label} must not acquire or cache the Linux-only cargo-deny authority",
        );
    }
}

#[test]
fn cargo_deny_scope_mutations_fail_closed() {
    let external_inputs = fs::read_to_string(repository_root().join("ci/external-inputs.toml"))
        .expect("external-input lock must be UTF-8");
    for (label, mutation) in [
        (
            "implicit all-platform scope",
            external_inputs.replace("platforms = [\"linux-x86_64\"]\n", ""),
        ),
        (
            "macOS scope broadening",
            external_inputs.replace(
                "platforms = [\"linux-x86_64\"]",
                "platforms = [\"linux-x86_64\", \"macos-aarch64\"]",
            ),
        ),
        (
            "Windows scope substitution",
            external_inputs.replace(
                "platforms = [\"linux-x86_64\"]",
                "platforms = [\"windows-x86_64\"]",
            ),
        ),
        (
            "Linux scope removal",
            external_inputs.replace(
                "platforms = [\"linux-x86_64\"]",
                "platforms = [\"macos-aarch64\"]",
            ),
        ),
        (
            "package substitution",
            external_inputs.replace("package = \"cargo-deny\"", "package = \"cargo-audit\""),
        ),
        (
            "version substitution",
            external_inputs.replace("version = \"0.20.2\"", "version = \"0.20.1\""),
        ),
    ] {
        assert!(
            validate_cargo_deny_lock(&mutation).is_err(),
            "{label} unexpectedly preserved the cargo-deny authority",
        );
    }
}

#[test]
fn windows_jobs_provision_the_locked_ghc_authority_and_bind_the_nightly_cache() {
    let protocol = fs::read_to_string(repository_root().join("ci/protocol/v1.toml"))
        .expect("typed workflow protocol must be UTF-8");
    let expected_inputs = concat!(
        "with-order = [\"enable-stack\", \"ghc-version\", \"stack-version\"]\n",
        "with.enable-stack = \"true\"\n",
        "with.ghc-version = \"9.8.2\"\n",
        "with.stack-version = \"3.11.1\"",
    );
    for table in [
        "physical.step.ci.windows.s004",
        "physical.step.nightly.windows.s002",
        "physical.step.release.windows.s004",
    ] {
        let setup = protocol_table(&protocol, table);
        assert!(setup.contains(expected_inputs), "{table} setup inputs");
        assert!(!setup.contains("stack-no-global"), "{table} disabled GHC");
    }
    for table in [
        "physical.step.ci.linux.s004",
        "physical.step.release.linux.s004",
    ] {
        assert!(
            protocol_table(&protocol, table).contains("with.stack-no-global = \"true\""),
            "{table} must retain its intentional Stack-only setup",
        );
    }

    let setup_action = "uses: haskell-actions/setup@6037f33647c3f17758a2356c80fc4a53d7e0685d";
    let rendered_inputs = concat!(
        "with:\n",
        "          enable-stack: 'true'\n",
        "          ghc-version: 9.8.2\n",
        "          stack-version: 3.11.1",
    );
    for (name, job, next) in [
        ("ci.yml", "windows", Some("verify")),
        ("nightly.yml", "windows", None),
        ("release.yml", "windows", Some("assemble")),
    ] {
        let rendered = workflow(name);
        let windows = job_block(&rendered, job, next);
        assert_eq!(
            windows.matches(setup_action).count(),
            1,
            "{name} action pin"
        );
        assert!(windows.contains(rendered_inputs), "{name} setup inputs");
        assert!(!windows.contains("stack-no-global"), "{name} disabled GHC");
        assert!(
            !windows.contains("ghc-version: latest"),
            "{name} floating GHC"
        );
    }

    let nightly_key = "nightly-windows-stack-3.11.1-ghc-9.8.2-${{ hashFiles('oracle-source/stack.yaml', 'oracle-source/stack.yaml.lock', 'oracle-source/package.yaml', 'oracle-source/hell.cabal', 'oracle-source/src/**') }}";
    let nightly = workflow("nightly.yml");
    let windows = job_block(&nightly, "windows", None);
    assert_eq!(windows.matches(nightly_key).count(), 2);
    assert!(!windows.contains("nightly-windows-stack-3.11.1-${{ hashFiles("));

    let projection: serde_json::Value = serde_json::from_slice(
        &fs::read(repository_root().join("ci/protocol/v1.audit.json"))
            .expect("audit projection must be readable"),
    )
    .expect("audit projection must be strict JSON");
    for path in [
        ".github/workflows/ci.yml",
        ".github/workflows/nightly.yml",
        ".github/workflows/release.yml",
    ] {
        let projected_workflow = projection["workflows"]
            .as_array()
            .expect("projected workflows must be an array")
            .iter()
            .find(|workflow| workflow["path"].as_str() == Some(path))
            .expect("Windows workflow must be projected");
        let projected_job = projected_workflow["jobs"]
            .as_array()
            .expect("projected jobs must be an array")
            .iter()
            .find(|job| job["id"].as_str() == Some("windows"))
            .expect("Windows job must be projected");
        let setup = projected_job["steps"]
            .as_array()
            .expect("projected steps must be an array")
            .iter()
            .find(|step| step["name"].as_str() == Some("Install pinned Stack"))
            .expect("pinned Stack setup must be projected");
        let inputs = setup["action"]["with"]
            .as_object()
            .expect("setup inputs must be projected");
        assert_eq!(inputs.len(), 3, "{path} projected setup input inventory");
        assert_eq!(
            inputs.get("enable-stack").and_then(|value| value.as_str()),
            Some("true")
        );
        assert_eq!(
            inputs.get("ghc-version").and_then(|value| value.as_str()),
            Some("9.8.2")
        );
        assert_eq!(
            inputs.get("stack-version").and_then(|value| value.as_str()),
            Some("3.11.1")
        );
        assert!(!inputs.contains_key("stack-no-global"));
    }
}

fn projected_commands(
    projection: &serde_yaml::Value,
    workflow_path: &str,
    job_id: &str,
) -> Vec<Vec<String>> {
    let workflow = projection["workflows"]
        .as_sequence()
        .expect("projected workflows must be an array")
        .iter()
        .find(|workflow| workflow["path"].as_str() == Some(workflow_path))
        .expect("workflow must be projected");
    let job = workflow["jobs"]
        .as_sequence()
        .expect("projected jobs must be an array")
        .iter()
        .find(|job| job["id"].as_str() == Some(job_id))
        .expect("job must be projected");
    job["steps"]
        .as_sequence()
        .expect("projected steps must be an array")
        .iter()
        .filter_map(|step| step["command"]["argv"].as_sequence())
        .map(|arguments| {
            arguments
                .iter()
                .map(|argument| {
                    argument
                        .as_str()
                        .expect("projected argv token must be a string")
                        .to_owned()
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

const READINESS_PLAN_EXPECTED_COMMANDS: &[&[&str]] = &[
    &["rustup", "show", "active-toolchain"],
    &[
        "cargo",
        "build",
        "--locked",
        "--profile",
        "ci",
        "--package",
        "hell-ci",
        "--bin",
        "hell-ci",
        "--package",
        "hell-workflow-auditor",
        "--bin",
        "hell-workflow-auditor",
    ],
    &[
        "./automation/target/ci/hell-ci",
        "protocol",
        "render",
        "--manifest",
        "candidate/ci/protocol/v1.toml",
        "--repository-root",
        "candidate",
        "--output",
        "ci-out/rendered-workflows",
    ],
    &[
        "./automation/target/ci/hell-ci",
        "protocol",
        "check",
        "--manifest",
        "candidate/ci/protocol/v1.toml",
        "--repository-root",
        "candidate",
        "--workflows",
        "candidate/.github/workflows",
        "--report",
        "ci-out/protocol-check.json",
    ],
    &[
        "./automation/target/ci/hell-workflow-auditor",
        "audit",
        "--workflows",
        "candidate/.github/workflows",
        "--protocol-projection",
        "candidate/ci/protocol/v1.audit.json",
        "--action-metadata",
        "candidate/ci/actions/metadata-v1.json",
        "--output",
        "ci-out/workflow-audit.json",
    ],
    &[
        "./automation/target/ci/hell-workflow-auditor",
        "verify-vectors",
        "--manifest",
        "candidate/ci/workflow-vectors/v1/manifest.toml",
        "--workflows",
        "candidate/.github/workflows",
        "--protocol-projection",
        "candidate/ci/protocol/v1.audit.json",
        "--action-metadata",
        "candidate/ci/actions/metadata-v1.json",
        "--output",
        "ci-out/workflow-vector-audit.json",
    ],
    &[
        "./automation/target/ci/hell-ci",
        "policy",
        "rust-capabilities",
        "--repository-root",
        "candidate",
        "--policy",
        "candidate/ci/rust-capabilities.toml",
        "--output",
        "ci-out/rust-capabilities.json",
    ],
    &[
        "./automation/target/ci/hell-ci",
        "assurance",
        "render",
        "--map",
        "candidate/spec/assurance-map.toml",
        "--output",
        "ci-out/assurance-map.md",
    ],
    &[
        "./automation/target/ci/hell-ci",
        "assurance",
        "check",
        "--map",
        "spec/assurance-map.toml",
        "--repository-root",
        "candidate",
        "--output",
        "ci-out/assurance-check.json",
    ],
    &[
        "./automation/target/ci/hell-ci",
        "readiness",
        "plan",
        "--repository-root",
        "candidate",
        "--output",
        "readiness-plan",
    ],
];

const EXPECTED_MUTATION_COMMANDS: &[&[&str]] = &[
    &[
        "cargo",
        "build",
        "--locked",
        "--profile",
        "ci",
        "--package",
        "hell-ci",
        "--bin",
        "hell-ci",
    ],
    &[
        "./target/ci/hell-ci",
        "memcordon",
        "acquire",
        "--task",
        "ci/memcordon-tasks-v1.toml",
        "--operation",
        "mutation",
    ],
    &[
        "./target/ci/hell-ci",
        "memcordon",
        "prepare",
        "--task",
        "ci/memcordon-tasks-v1.toml",
        "--operation",
        "mutation",
    ],
    &[
        "./target/ci/hell-ci",
        "memcordon",
        "canary",
        "--task",
        "ci/memcordon-tasks-v1.toml",
        "--operation",
        "mutation",
    ],
    &[
        "./target/ci/hell-ci",
        "assurance",
        "render",
        "--map",
        "spec/assurance-map.toml",
        "--output",
        "ci-out/assurance-map.md",
    ],
    &[
        "./target/ci/hell-ci",
        "assurance",
        "check",
        "--map",
        "spec/assurance-map.toml",
        "--repository-root",
        ".",
        "--output",
        "ci-out/assurance-check.json",
    ],
    &[
        "./target/ci/hell-ci",
        "memcordon",
        "execute",
        "--task",
        "ci/memcordon-tasks-v1.toml",
        "--operation",
        "mutation",
    ],
    &[
        "./target/ci/hell-ci",
        "memcordon",
        "cleanup",
        "--task",
        "ci/memcordon-tasks-v1.toml",
        "--operation",
        "mutation",
    ],
    &[
        "./target/ci/hell-ci",
        "memcordon",
        "finalize",
        "--task",
        "ci/memcordon-tasks-v1.toml",
        "--operation",
        "mutation",
        "--candidate-commit",
        "${{ github.sha }}",
        "--workflow-commit",
        "${{ github.workflow_sha }}",
    ],
];

#[test]
fn mutation_workflow_executes_the_map_and_source_bound_catalog() {
    let projection: serde_yaml::Value = serde_yaml::from_slice(
        &fs::read(repository_root().join("ci/protocol/v1.audit.json"))
            .expect("audit projection must be readable"),
    )
    .expect("audit projection must be strict JSON");
    let mutation = projection["workflows"]
        .as_sequence()
        .expect("projected workflows must be an array")
        .iter()
        .find(|workflow| workflow["path"].as_str() == Some(".github/workflows/mutation.yml"))
        .expect("mutation workflow must be projected");
    let job = mutation["jobs"]
        .as_sequence()
        .expect("mutation jobs must be an array")
        .iter()
        .find(|job| job["id"].as_str() == Some("mutation"))
        .expect("mutation job must be projected");
    let commands = job["steps"]
        .as_sequence()
        .expect("mutation steps must be an array")
        .iter()
        .filter_map(|step| step["command"]["argv"].as_sequence())
        .map(|arguments| {
            arguments
                .iter()
                .map(|argument| {
                    argument
                        .as_str()
                        .expect("projected argv token must be a string")
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    assert_eq!(commands, EXPECTED_MUTATION_COMMANDS);
}

#[test]
fn regression_workflows_cancel_only_stale_runs_for_the_same_ref() {
    for name in ["regression-corpus.yml", "regression-subject.yml"] {
        let text = workflow(name);
        assert!(text.contains(
            "concurrency:\n  group: ${{ github.workflow }}-${{ github.ref }}\n  cancel-in-progress: true"
        ));
    }
    let release = workflow("release.yml");
    assert!(release.contains(
        "concurrency:\n  group: release-${{ github.repository }}\n  cancel-in-progress: false"
    ));
}

#[test]
fn workflows_use_single_invocations_no_explicit_shell_and_closed_environment() {
    let directory = repository_root().join(".github/workflows");
    let mut names = fs::read_dir(directory)
        .expect("workflow directory must be readable")
        .map(|entry| {
            entry
                .expect("workflow entry must be readable")
                .file_name()
                .into_string()
                .expect("workflow filename must be UTF-8")
        })
        .collect::<Vec<_>>();
    names.sort();
    assert_eq!(
        names,
        [
            "ci.yml",
            "mutation.yml",
            "nightly.yml",
            "regression-corpus.yml",
            "regression-subject.yml",
            "release.yml",
        ]
    );
    for name in names {
        let text = workflow(&name);
        assert!(
            !text.contains("--required-gates"),
            "{name} retains caller gate authority"
        );
        assert!(
            !text
                .lines()
                .any(|line| line.trim_start().starts_with("shell:"))
        );
        let lines = text.lines().collect::<Vec<_>>();
        for (index, line) in lines.iter().enumerate() {
            let trimmed = line.trim_start();
            if let Some(invocation) = trimmed.strip_prefix("run: ") {
                for forbidden in ["\n", "&&", "||", ";", "|", "`", "$("] {
                    assert!(
                        !invocation.contains(forbidden),
                        "workflow {name} run step contains {forbidden:?}: {invocation}"
                    );
                }
            }
            if trimmed == "env:" {
                assert_eq!(
                    lines.get(index + 1).map(|next| next.trim()),
                    Some("GITHUB_TOKEN: ${{ github.token }}"),
                    "workflow {name} exposes a custom environment"
                );
            }
        }
        assert_eq!(text.as_bytes().last(), Some(&b'\n'));
    }
}

#[test]
fn audit_projection_semantics_match_the_release_and_regression_contract() {
    let projection: serde_yaml::Value = serde_yaml::from_slice(
        &fs::read(repository_root().join("ci/protocol/v1.audit.json"))
            .expect("audit projection must be readable"),
    )
    .expect("audit projection must be strict JSON");
    assert_eq!(projection["mergeQueue"].as_bool(), Some(false));

    let workflows = projection["workflows"]
        .as_sequence()
        .expect("projected workflows must be an array");
    let paths = workflows
        .iter()
        .map(|workflow| {
            workflow["path"]
                .as_str()
                .expect("projected workflow path must be a string")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        paths,
        [
            ".github/workflows/ci.yml",
            ".github/workflows/mutation.yml",
            ".github/workflows/nightly.yml",
            ".github/workflows/regression-corpus.yml",
            ".github/workflows/regression-subject.yml",
            ".github/workflows/release.yml",
        ]
    );

    let release = workflows
        .iter()
        .find(|workflow| workflow["path"].as_str() == Some(".github/workflows/release.yml"))
        .expect("release workflow must be projected");
    let dispatch = release["triggers"]
        .as_sequence()
        .expect("release triggers must be projected")
        .iter()
        .find(|trigger| trigger["event"].as_str() == Some("workflow_dispatch"))
        .expect("release dispatch trigger must be projected");
    assert_eq!(
        dispatch["dispatchInputs"]["candidate_branch"]["required"].as_bool(),
        Some(true)
    );
    assert_eq!(
        dispatch["dispatchInputs"]["candidate_branch"]["type"].as_str(),
        Some("string")
    );

    let publish = release["jobs"]
        .as_sequence()
        .expect("release jobs must be projected")
        .iter()
        .find(|job| job["id"].as_str() == Some("publish"))
        .expect("publish job must be projected");
    let publish_argv = publish["steps"]
        .as_sequence()
        .expect("publish steps must be projected")
        .iter()
        .find(|step| {
            step["kind"].as_str() == Some("command")
                && step["command"]["argv"]
                    .as_sequence()
                    .is_some_and(|argv| argv.iter().any(|value| value.as_str() == Some("publish")))
        })
        .and_then(|step| step["command"]["argv"].as_sequence())
        .expect("publisher argv must be projected");
    let publish_argv = publish_argv
        .iter()
        .map(|value| value.as_str().expect("publisher argv must contain strings"))
        .collect::<Vec<_>>();
    assert!(publish_argv.windows(2).any(|arguments| {
        arguments
            == [
                "--expected-artifact-id",
                "${{ needs.attest.outputs.artifact_id }}",
            ]
    }));
    assert!(publish_argv.windows(2).any(|arguments| {
        arguments
            == [
                "--expected-artifact-digest",
                "${{ needs.attest.outputs.artifact_digest }}",
            ]
    }));
}
