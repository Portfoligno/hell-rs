use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const CACHE_SHA: &str = "55cc8345863c7cc4c66a329aec7e433d2d1c52a9";
const SSH_AGENT_SHA: &str = "e83874834305fe9a4a2997156cb26c5de65a8555";
const ATTEST_SHA: &str = "a1948c3f048ba23858d222213b7c278aabede763";
const CARGO_DENY_ACTION: &str =
    "EmbarkStudios/cargo-deny-action@b66acf5e9fe20f8aba065be86778a8a4c846f902";
const CARGO_DENY_INSTALL: &str = "run: cargo install cargo-deny --locked --version 0.20.2";
const CARGO_DENY_CHECK: &str = "run: cargo deny --all-features check all";
const COSIGN_INSTALLER: &str =
    "uses: sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6 # v4.1.2";
const CARGO_FUZZ_TOOLCHAIN: &str = "nightly-2026-07-31";
const CARGO_FUZZ_VERSION: &str = "0.13.2";
const SEMANTIC_FUZZ_TARGETS: [&str; 13] = [
    "claim_toml",
    "normalizer_toml",
    "divergence_toml",
    "dsse_envelope",
    "acquisition_receipt",
    "observation_bundle_manifest",
    "provenance_record",
    "custody_receipt",
    "normalizer_replay",
    "worklist_escaping",
    "semantic_trace",
    "review_graph",
    "evidence_graph_merge",
];

fn workflow_directory() -> PathBuf {
    PathBuf::from(".github").join("workflows")
}

fn workflow_path(name: &str) -> PathBuf {
    workflow_directory().join(name)
}

pub fn check_repository(root: &Path) -> Result<(), String> {
    let tracked = tracked_files(root)?;
    let modes = tracked_modes(root)?;
    let mut failures = Vec::new();
    for path in &tracked {
        check_tracked_file(
            root,
            path,
            modes.get(path).map(String::as_str),
            &mut failures,
        );
    }
    check_checkout_attributes(root, &mut failures);
    check_workflows(root, &tracked, &mut failures);
    check_test_infrastructure(root, &tracked, &mut failures);
    check_environment_configuration(root, &tracked, &mut failures);
    check_semantic_limit_inventory(root, &mut failures);
    check_dependency_policy(root, &mut failures);
    check_semantic_fuzz_campaign(root, &mut failures);
    check_collection_authority_producer(root, &mut failures);
    match fs::read_to_string(root.join(".github/workflows/artifact-independent-acquisition.yml")) {
        Ok(workflow) => check_external_independent_preflight(&workflow, &mut failures),
        Err(error) => failures.push(format!(
            "cannot read independent acquisition workflow: {error}"
        )),
    }
    match fs::read_to_string(root.join(".github/workflows/collection-activation.yml")) {
        Ok(workflow) => check_collection_activation_review(&workflow, &mut failures),
        Err(error) => failures.push(format!("cannot read collection activation review: {error}")),
    }
    check_collection_activation_manifest(root, &mut failures);
    check_expected_mismatch_manifest(root, &mut failures);
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("\n"))
    }
}

fn check_collection_activation_manifest(root: &Path, failures: &mut Vec<String>) {
    let path = root.join("compat").join("collection-activation.toml");
    let provenance_path = root
        .join("compat")
        .join("collection-activation-provenance.json");
    let claims_path = root
        .join("compat")
        .join("collection-activation-claims.json");
    match (
        fs::read_to_string(&path),
        fs::read(&provenance_path),
        fs::read(&claims_path),
    ) {
        (Ok(document), Ok(provenance), Ok(claims)) => {
            let state = hell_testkit::verify_collection_activation_state(
                document.as_bytes(),
                &provenance,
                &claims,
            );
            if !collection_activation_manifest_is_exact(&document)
                || state.is_err()
                || state.is_ok_and(|active| {
                    active
                        && crate::collection_custody::verify_active_collection_activation_repository(
                            root,
                        )
                        .is_err()
                })
            {
                failures.push(
                    "collection activation manifest, provenance, claims, and retained review must be an exact bound dormant or reviewed active state"
                        .to_owned(),
                );
            }
        }
        (Err(error), _, _) => failures.push(format!(
            "cannot read collection activation manifest {}: {error}",
            path.display()
        )),
        (_, Err(error), _) => failures.push(format!(
            "cannot read collection activation provenance {}: {error}",
            provenance_path.display()
        )),
        (_, _, Err(error)) => failures.push(format!(
            "cannot read collection activation claims {}: {error}",
            claims_path.display()
        )),
    }
}

fn collection_activation_manifest_is_exact(document: &str) -> bool {
    const PREFIX: &str = concat!(
        "schema_version = 1\n",
        "domain = \"hell.collection-activation.v1\"\n",
        "scopes = [\"Map.adjust|pure-runtime|upstream|linux,macos,windows\", ",
        "\"Map.delete|pure-runtime|upstream|linux,macos,windows\", ",
        "\"Map.fromList|pure-runtime|upstream|linux,macos,windows\", ",
        "\"Map.insert|pure-runtime|upstream|linux,macos,windows\", ",
        "\"Map.insertWith|pure-runtime|upstream|linux,macos,windows\", ",
        "\"Map.lookup|pure-runtime|upstream|linux,macos,windows\", ",
        "\"Map.unionWith|pure-runtime|upstream|linux,macos,windows\", ",
        "\"Set.delete|pure-runtime|upstream|linux,macos,windows\", ",
        "\"Set.difference|pure-runtime|upstream|linux,macos,windows\", ",
        "\"Set.fromList|pure-runtime|upstream|linux,macos,windows\", ",
        "\"Set.insert|pure-runtime|upstream|linux,macos,windows\", ",
        "\"Set.intersection|pure-runtime|upstream|linux,macos,windows\", ",
        "\"Set.member|pure-runtime|upstream|linux,macos,windows\", ",
        "\"Set.union|pure-runtime|upstream|linux,macos,windows\"]\n",
        "fresh_collection_required = true\n",
    );
    matches!(
        document,
        concat!(
            "schema_version = 1\n",
            "domain = \"hell.collection-activation.v1\"\n",
            "scopes = [\"Map.adjust|pure-runtime|upstream|linux,macos,windows\", ",
            "\"Map.delete|pure-runtime|upstream|linux,macos,windows\", ",
            "\"Map.fromList|pure-runtime|upstream|linux,macos,windows\", ",
            "\"Map.insert|pure-runtime|upstream|linux,macos,windows\", ",
            "\"Map.insertWith|pure-runtime|upstream|linux,macos,windows\", ",
            "\"Map.lookup|pure-runtime|upstream|linux,macos,windows\", ",
            "\"Map.unionWith|pure-runtime|upstream|linux,macos,windows\", ",
            "\"Set.delete|pure-runtime|upstream|linux,macos,windows\", ",
            "\"Set.difference|pure-runtime|upstream|linux,macos,windows\", ",
            "\"Set.fromList|pure-runtime|upstream|linux,macos,windows\", ",
            "\"Set.insert|pure-runtime|upstream|linux,macos,windows\", ",
            "\"Set.intersection|pure-runtime|upstream|linux,macos,windows\", ",
            "\"Set.member|pure-runtime|upstream|linux,macos,windows\", ",
            "\"Set.union|pure-runtime|upstream|linux,macos,windows\"]\n",
            "fresh_collection_required = true\n",
            "map712 = false\n",
            "set479 = false\n",
        ) | concat!(
            "schema_version = 1\n",
            "domain = \"hell.collection-activation.v1\"\n",
            "scopes = [\"Map.adjust|pure-runtime|upstream|linux,macos,windows\", ",
            "\"Map.delete|pure-runtime|upstream|linux,macos,windows\", ",
            "\"Map.fromList|pure-runtime|upstream|linux,macos,windows\", ",
            "\"Map.insert|pure-runtime|upstream|linux,macos,windows\", ",
            "\"Map.insertWith|pure-runtime|upstream|linux,macos,windows\", ",
            "\"Map.lookup|pure-runtime|upstream|linux,macos,windows\", ",
            "\"Map.unionWith|pure-runtime|upstream|linux,macos,windows\", ",
            "\"Set.delete|pure-runtime|upstream|linux,macos,windows\", ",
            "\"Set.difference|pure-runtime|upstream|linux,macos,windows\", ",
            "\"Set.fromList|pure-runtime|upstream|linux,macos,windows\", ",
            "\"Set.insert|pure-runtime|upstream|linux,macos,windows\", ",
            "\"Set.intersection|pure-runtime|upstream|linux,macos,windows\", ",
            "\"Set.member|pure-runtime|upstream|linux,macos,windows\", ",
            "\"Set.union|pure-runtime|upstream|linux,macos,windows\"]\n",
            "fresh_collection_required = true\n",
            "map712 = true\n",
            "set479 = true\n",
        )
    ) && document.starts_with(PREFIX)
}

const COLLECTION_ACQUISITION_COMMAND: &str = concat!(
    "run: ./target/ci/hell-ci collection-authority acquire-provider ",
    "--repository Portfoligno/hell-rs ",
    "--run-id \"$GITHUB_RUN_ID\" --run-attempt \"$GITHUB_RUN_ATTEMPT\" ",
    "--provider-head \"$GITHUB_SHA\" --candidate-commit \"$HELL_SOURCE_COMMIT\" ",
    "--workflow-path .github/workflows/collection-authority.yml ",
    "--linux-artifact-id \"$COLLECTION_LINUX_ARTIFACT_ID\" ",
    "--macos-artifact-id \"$COLLECTION_MACOS_ARTIFACT_ID\" ",
    "--windows-artifact-id \"$COLLECTION_WINDOWS_ARTIFACT_ID\" ",
    "--gh-executable ci-out/collection-custody-tools/gh ",
    "--gh-install-manifest ci-out/collection-custody-tools/gh-install-manifest.json ",
    "--output ci-out/collection-provider",
);

const COLLECTION_VERIFY_COMMAND: &str = "run: ./target/ci/hell-ci collection-authority verify --input ci-out/native-shards --provider ci-out/collection-provider --report ci-out/native-shards/collection-authority.json";
const COLLECTION_COMPACT_COMMAND: &str = "run: ./target/ci/hell-ci collection-authority compact --input ci-out/native-shards --provider ci-out/collection-provider --verified-report ci-out/native-shards/collection-authority.json --output ci-out/collection-custody";
const COLLECTION_INSTALL_GH_COMMAND: &str = "run: ./target/ci/hell-ci collection-authority install-pinned-gh --output ci-out/collection-custody-tools";
const COLLECTION_ATTESTATION_TOOL_COMMAND: &str = "run: ./target/ci/hell-ci collection-authority capture-custody-attestation --subject ci-out/collection-custody/custody-attestation-subject.json --bundle \"$COLLECTION_CUSTODY_BUNDLE_PATH\" --provider-head \"$GITHUB_SHA\" --run-id \"$GITHUB_RUN_ID\" --run-attempt \"$GITHUB_RUN_ATTEMPT\" --gh-executable ci-out/collection-custody-tools/gh --gh-install-manifest ci-out/collection-custody-tools/gh-install-manifest.json --trusted-root ci-out/collection-custody-attestation-input/trusted-root.jsonl --trusted-root-provenance ci-out/collection-custody-attestation-input/trusted-root-provenance.json --raw-verification ci-out/collection-custody-attestation-input/online-verification.raw.json --online-verification ci-out/collection-custody-attestation-input/online-verification.json";
const COLLECTION_RETAIN_CUSTODY_COMMAND: &str = "run: ./target/ci/hell-ci collection-authority retain-custody-attestation --package ci-out/collection-custody --bundle \"$COLLECTION_CUSTODY_BUNDLE_PATH\" --trusted-root ci-out/collection-custody-attestation-input/trusted-root.jsonl --trusted-root-provenance ci-out/collection-custody-attestation-input/trusted-root-provenance.json --online-verification ci-out/collection-custody-attestation-input/online-verification.json --gh-install-manifest ci-out/collection-custody-tools/gh-install-manifest.json --output ci-out/collection-custody-signature";
const COLLECTION_REVIEW_DISPATCH: &str = concat!(
    "name: Collection Custody Review\n\non:\n  workflow_dispatch:\n    inputs:\n",
    "      preparation_sha:\n",
    "        description: Exact main commit containing payload and signature but no review overlay\n",
    "        required: true\n        type: string\n",
    "      reviewer:\n",
    "        description: Exact role-qualified custody reviewer principal\n",
    "        required: true\n        type: string\n",
    "      issued_at:\n",
    "        description: Exact UTC review statement issuance time\n",
    "        required: true\n        type: string\n",
);

fn check_collection_authority_producer(root: &Path, failures: &mut Vec<String>) {
    let workflow_path = root.join(".github/workflows/collection-authority.yml");
    let integration_path = root.join(".github/workflows/collection-custody-integration.yml");
    let review_path = root.join(".github/workflows/collection-custody-review.yml");
    let activation_path = root.join(".github/workflows/collection-activation-preparation.yml");
    let custody_bridge_path = root.join(".github/workflows/evidence-custody.yml");
    let revocations_path = root.join("compat/collection-authority-revocations.toml");
    let trust_roots_path = root.join("compat/trust-roots.toml");
    let nightly_path = root.join(".github/workflows/nightly.yml");
    let transport_path = root.join("crates/hell-ci/src/collection_transport.rs");
    let workflow = match fs::read_to_string(&workflow_path) {
        Ok(value) => value,
        Err(error) => {
            failures.push(format!("cannot read {}: {error}", workflow_path.display()));
            return;
        }
    };
    match fs::read_to_string(&nightly_path) {
        Ok(nightly)
            if nightly.contains("collection-authority collect")
                || nightly.contains("merge-collection-authority:") =>
        {
            failures.push("ordinary Nightly embeds the collection authority campaign".to_owned());
        }
        Err(error) => {
            failures.push(format!("cannot read {}: {error}", nightly_path.display()));
        }
        _ => {}
    }
    let transport = match fs::read_to_string(&transport_path) {
        Ok(value) => value,
        Err(error) => {
            failures.push(format!("cannot read {}: {error}", transport_path.display()));
            return;
        }
    };
    check_collection_authority_producer_text(&workflow, &transport, failures);
    let integration = match fs::read_to_string(&integration_path) {
        Ok(value) => value,
        Err(error) => {
            failures.push(format!(
                "cannot read {}: {error}",
                integration_path.display()
            ));
            return;
        }
    };
    let revocations = match fs::read_to_string(&revocations_path) {
        Ok(value) => value,
        Err(error) => {
            failures.push(format!(
                "cannot read {}: {error}",
                revocations_path.display()
            ));
            return;
        }
    };
    check_collection_custody_integration_text(&integration, &revocations, failures);
    let review = match fs::read_to_string(&review_path) {
        Ok(value) => value,
        Err(error) => {
            failures.push(format!("cannot read {}: {error}", review_path.display()));
            return;
        }
    };
    let trust_roots = match fs::read_to_string(&trust_roots_path) {
        Ok(value) => value,
        Err(error) => {
            failures.push(format!(
                "cannot read {}: {error}",
                trust_roots_path.display()
            ));
            return;
        }
    };
    check_collection_custody_review_text(&review, &trust_roots, failures);
    match fs::read_to_string(&activation_path) {
        Ok(activation) => check_collection_activation_preparation_text(&activation, failures),
        Err(error) => failures.push(format!(
            "cannot read {}: {error}",
            activation_path.display()
        )),
    }
    match fs::read_to_string(&custody_bridge_path) {
        Ok(bridge) => check_collection_worm_bridge_text(&bridge, failures),
        Err(error) => failures.push(format!(
            "cannot read {}: {error}",
            custody_bridge_path.display()
        )),
    }
}

fn check_collection_activation_preparation_text(workflow: &str, failures: &mut Vec<String>) {
    const VERIFY: &str = "run: ./target/ci/hell-ci collection-authority verify-activation-artifact --input ci-in/collection-custody-activation/collection-custody-activation-token.json --report ci-in/collection-custody-activation/collection-custody-admission.json";
    const PREPARE: &str = "run: ./target/ci/hell-ci collection-authority prepare-activation --input ci-in/collection-custody-activation --output ci-out/collection-activation-proposal --run-id \"$COLLECTION_ACTIVATION_RUN_ID\" --run-attempt \"$COLLECTION_ACTIVATION_RUN_ATTEMPT\" --artifact-id \"$COLLECTION_ACTIVATION_ARTIFACT_ID\" --expected-directory-sha256 \"$COLLECTION_ACTIVATION_DIRECTORY_SHA256\" --expected-archive-sha256 \"$COLLECTION_ACTIVATION_ARCHIVE_SHA256\"";
    let Some(lines) = workflow_job_lines(workflow, "prepare-non-authoritative-activation") else {
        failures.push(
            "collection activation preparation lacks its protected preparation job".to_owned(),
        );
        return;
    };
    let body = lines.join("\n");
    let runs = body
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("run: "))
        .collect::<Vec<_>>();
    let expected_runs = [
        "run: cargo build --locked --profile ci --package hell-ci --bin hell-ci",
        "run: ./target/ci/hell-ci collection-authority verify-checkout --input . --candidate-commit \"$COLLECTION_ACTIVATION_SHA\"",
        VERIFY,
        PREPARE,
        "run: ./target/ci/hell-ci regression-import emit-directory-output --input ci-out/collection-activation-proposal",
    ];
    let build = body.find("run: cargo build --locked --profile ci --package hell-ci --bin hell-ci");
    let download = body.find("uses: actions/download-artifact@");
    let verify = body.find(VERIFY);
    let prepare = body.find(PREPARE);
    let upload = body.find("uses: actions/upload-artifact@");
    let expected_uses = [
        "uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1",
        "uses: actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9 # v6.1.0",
        "uses: actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9 # v6.1.0",
        "uses: actions/download-artifact@70fc10c6e5e1ce46ad2ea6f2b72d43f7d47b13c3 # v8.0.1",
        "uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1",
        "uses: actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9 # v6.1.0",
        "uses: actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9 # v6.1.0",
    ];
    check_collection_rust_caches(
        &body,
        "collection-activation-preparation",
        Some("${{ inputs.activation_sha }}"),
        ".github/workflows/collection-activation-preparation.yml",
        failures,
    );
    if !activation_preparation_control_exact(workflow, &body)
        || runs.iter().any(|run| run.contains("${{"))
        || runs != expected_runs
        || collection_workflow_entries(&body, "uses: ") != expected_uses
        || ![build, download, verify, prepare, upload]
            .into_iter()
            .collect::<Option<Vec<_>>>()
            .is_some_and(|positions| positions.windows(2).all(|pair| pair[0] < pair[1]))
        || body.matches("id: bind-proposal").count() != 1
        || body.matches("id: upload-proposal").count() != 1
        || body
            .matches("proposal_artifact_id: ${{ steps.upload-proposal.outputs.artifact-id }}")
            .count()
            != 1
        || body
            .matches(
                "proposal_artifact_digest: ${{ steps.upload-proposal.outputs.artifact-digest }}",
            )
            .count()
            != 1
        || body
            .matches(
                "proposal_directory_sha256: ${{ steps.bind-proposal.outputs.directory_sha256 }}",
            )
            .count()
            != 1
        || body
            .matches("path: ci-out/collection-activation-proposal")
            .count()
            != 1
        || body.matches("if-no-files-found: error").count() != 1
        || body.matches("retention-days: 14").count() != 1
        || body.contains("git commit")
        || body.contains("git push")
        || body.contains("gh pr")
        || body.contains("aws-actions/configure-aws-credentials@")
        || body.contains("webfactory/ssh-agent@")
        || body.contains("sigstore/cosign-installer@")
        || body.contains("secrets.")
        || body.contains("promotionAuthority: true")
        || body.contains("activationAuthority: true")
    {
        failures.push(
            "collection activation preparation is not an exact provider-authenticated non-authoritative proposal"
                .to_owned(),
        );
    }
}

fn activation_preparation_control_exact(workflow: &str, body: &str) -> bool {
    let inputs = [
        "      activation_sha:",
        "      source_run_id:",
        "      source_run_attempt:",
        "      artifact_id:",
        "      expected_directory_sha256:",
        "      expected_archive_sha256:",
    ];
    let bindings = [
        "run-id: ${{ inputs.source_run_id }}",
        "artifact-ids: ${{ inputs.artifact_id }}",
        "github-token: ${{ github.token }}",
        "path: ci-in/collection-custody-activation",
        "COLLECTION_ACTIVATION_RUN_ID: ${{ inputs.source_run_id }}",
        "COLLECTION_ACTIVATION_RUN_ATTEMPT: ${{ inputs.source_run_attempt }}",
        "COLLECTION_ACTIVATION_ARTIFACT_ID: ${{ inputs.artifact_id }}",
        "COLLECTION_ACTIVATION_DIRECTORY_SHA256: ${{ inputs.expected_directory_sha256 }}",
        "COLLECTION_ACTIVATION_ARCHIVE_SHA256: ${{ inputs.expected_archive_sha256 }}",
    ];
    workflow.starts_with("name: Collection Activation Preparation\n\non:\n  workflow_dispatch:\n")
        && !["  push:", "  schedule:", "  workflow_call:", "  pull_request:"]
            .iter()
            .any(|trigger| workflow.contains(trigger))
        && workflow.matches("        required: true").count() == 6
        && workflow.matches("        type: string").count() == 6
        && inputs.iter().all(|input| workflow.matches(input).count() == 1)
        && workflow.matches("concurrency:\n  group: collection-activation-preparation-${{ github.repository }}\n  cancel-in-progress: false").count() == 1
        && body.matches("if: ${{ github.ref == 'refs/heads/main' && inputs.activation_sha == github.sha }}").count() == 1
        && body.matches("environment: collection-activation-preparation").count() == 1
        && body.matches("actions: read").count() == 1
        && body.matches("contents: read").count() == 1
        && !body.contains(": write")
        && body.matches("runs-on: ubuntu-24.04").count() == 1
        && body.matches("timeout-minutes: 45").count() == 1
        && body.matches("ref: ${{ inputs.activation_sha }}").count() == 1
        && body.matches("fetch-depth: 0").count() == 1
        && body.matches("persist-credentials: false").count() == 1
        && bindings.iter().all(|binding| body.matches(binding).count() == 1)
}

fn check_collection_worm_bridge_text(workflow: &str, failures: &mut Vec<String>) {
    const PREPARE: &str = "run: ./target/ci/hell-ci collection-authority prepare-worm-custody --package compat/collection-custody/payload --signature compat/collection-custody/signature --candidate-executable target/release/hell --integration-proof compat/collection-custody/integration-proof.tsv --integration-review compat/collection-custody/integration-review.dsse.json --output ci-out";
    const VALIDATE: &str =
        "run: ./target/ci/hell-ci custody-ops verify-package --input ci-out/custody-package";
    const ASSEMBLE: &str = "run: ./target/ci/hell-ci custody-ops workflow-assemble-collection-worm";
    let Some(package) = workflow_job_lines(workflow, "package") else {
        failures.push("collection WORM bridge lacks preparation job".to_owned());
        return;
    };
    let Some(upload) = workflow_job_lines(workflow, "upload") else {
        failures.push("collection WORM bridge lacks provider upload job".to_owned());
        return;
    };
    let Some(retrieve) = workflow_job_lines(workflow, "retrieve") else {
        failures.push("collection WORM bridge lacks independent retrieval job".to_owned());
        return;
    };
    let Some(review) = workflow_job_lines(workflow, "review-and-assemble") else {
        failures.push("collection WORM bridge lacks protected review job".to_owned());
        return;
    };
    let package = package.join("\n");
    let upload = upload.join("\n");
    let retrieve = retrieve.join("\n");
    let review = review.join("\n");
    let package_order = [
        "run: cargo build --locked --profile ci --package hell-ci --bin hell-ci",
        "run: ./target/ci/hell-ci collection-authority verify-checkout --input . --candidate-commit \"$COLLECTION_CANDIDATE_SHA\"",
        PREPARE,
        "id: upload-package",
    ];
    let upload_order = [
        "artifact-ids: ${{ needs.package.outputs.artifact_id }}",
        "run: cargo build --locked --profile ci --package hell-ci --bin hell-ci",
        VALIDATE,
        "run: ./target/ci/hell-ci custody-ops workflow-prepare-provider-selector",
        "uses: aws-actions/configure-aws-credentials@e6de054238d6b7531b4efff3b6587d9aade6a06c # v6.2.3",
        "run: ./target/ci/hell-ci custody-ops workflow-upload",
    ];
    let review_order = [
        "artifact-ids: ${{ needs.review-prepare.outputs.artifact_id }}",
        "run: ./target/ci/hell-ci custody-ops verify-package --input ci-out/custody-subject/transport/custody-package",
        "run: ./target/ci/hell-ci custody-ops workflow-retain-review-subject",
        "run: ./target/ci/hell-ci review-authorization --input ci-out/custody-subject/review-packet.json --output ci-out/custody/authorization.json --role custody-reviewer --category custody-final --github-dispatch-inputs",
        "run: ./target/ci/hell-ci review-packet --input ci-out/custody-subject/review-packet.json --from ci-out/custody/authorization.json --output ci-out/custody/review-packet.authorized.json --role custody-reviewer --category custody-final --decision accept --github-dispatch-inputs",
        "uses: sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6 # v4.1.2",
        "uses: webfactory/ssh-agent@e83874834305fe9a4a2997156cb26c5de65a8555 # v0.10.0",
        "run: ssh-add -L",
        "run: ./target/ci/hell-ci review-sign --input ci-out/custody/review-packet.authorized.json --output ci-out/custody/custody-review.dsse.json --role custody-reviewer --decision accept --policy ci-out/custody/reviewer.allowed_signers",
        "run: ./target/ci/hell-ci custody verify --input ci-out/custody/custody-receipt.json --policy compat/reviews.allowed_signers",
        "path: ci-out/primary-worm-current-scrub",
        "path: ci-out/secondary-worm-current-scrub",
        "id: assemble-collection-worm",
        ASSEMBLE,
        "id: upload-collection-worm",
        "path: ci-out/collection-worm-custody",
    ];
    let retrieve_order = [
        "name: ephemeralEvidence-custody-upload-${{ matrix.provider }}",
        "run: cargo build --locked --profile ci --package hell-ci --bin hell-ci",
        "run: ./target/ci/hell-ci custody-ops workflow-verify-upload-subject",
        "uses: aws-actions/configure-aws-credentials@e6de054238d6b7531b4efff3b6587d9aade6a06c # v6.2.3",
        "run: ./target/ci/hell-ci custody-ops workflow-retrieve",
    ];
    if !collection_worm_artifacts_are_exact(workflow, &package, &upload, &retrieve, &review)
        || !markers_are_ordered(&package, &package_order)
        || !markers_are_ordered(&upload, &upload_order)
        || !markers_are_ordered(&retrieve, &retrieve_order)
        || !markers_are_ordered(&review, &review_order)
        || workflow.contains("collection-authority verify-custody --")
    {
        failures.push(
            "collection custody WORM bridge does not preserve exact prepared subject through protected two-provider review"
                .to_owned(),
        );
    }
}

fn collection_worm_artifacts_are_exact(
    workflow: &str,
    package: &str,
    upload: &str,
    retrieve: &str,
    review: &str,
) -> bool {
    const PREPARE: &str = "run: ./target/ci/hell-ci collection-authority prepare-worm-custody --package compat/collection-custody/payload --signature compat/collection-custody/signature --candidate-executable target/release/hell --integration-proof compat/collection-custody/integration-proof.tsv --integration-review compat/collection-custody/integration-review.dsse.json --output ci-out";
    const VALIDATE: &str =
        "run: ./target/ci/hell-ci custody-ops verify-package --input ci-out/custody-package";
    const ASSEMBLE: &str = "run: ./target/ci/hell-ci custody-ops workflow-assemble-collection-worm";
    let upload_files = [
        "            ci-out/upload-receipt.json\n",
        "            ci-out/upload-receipt-provider-pointer.json\n",
        "            ci-out/upload-receipt-packet.json\n",
        "            ci-out/upload-receipt.dsse.json\n",
    ];
    workflow.matches("          - collection-custody").count() == 1
        && package.matches(PREPARE).count() == 1
        && package
            .matches("COLLECTION_CANDIDATE_SHA: ${{ inputs.candidate_sha }}")
            .count()
            == 1
        && package.matches("            ci-out/subject\n").count() == 1
        && workflow
            .matches("artifact-ids: ${{ needs.package.outputs.artifact_id }}")
            .count()
            == 2
        && upload.matches(VALIDATE).count() == 1
        && upload
            .matches("CUSTODY_EXPECTED_PROVIDER: ${{ matrix.provider }}")
            .count()
            == 1
        && upload
            .matches("CUSTODY_EXPECTED_TRUST_DOMAIN: ${{ matrix.trust-domain }}")
            .count()
            == 1
        && upload_files
            .iter()
            .all(|path| upload.matches(path).count() == 1)
        && upload
            .matches(concat!(
                "          path: |\n",
                "            ci-out/upload-receipt.json\n",
                "            ci-out/upload-receipt-provider-pointer.json\n",
                "            ci-out/upload-receipt-packet.json\n",
                "            ci-out/upload-receipt.dsse.json\n",
                "          if-no-files-found: error",
            ))
            .count()
            == 1
        && retrieve
            .matches("CUSTODY_EXPECTED_PROVIDER: ${{ matrix.provider }}")
            .count()
            == 1
        && retrieve
            .matches("CUSTODY_EXPECTED_TRUST_DOMAIN: ${{ matrix.trust-domain }}")
            .count()
            == 1
        && review.matches(ASSEMBLE).count() == 1
        && review.matches("collection_worm_directory_sha256: ${{ steps.assemble-collection-worm.outputs.directory-sha256 }}").count() == 1
        && review.matches("environment: custody-review").count() == 1
        && review.matches("run: ./target/ci/hell-ci custody-ops verify-package --input ci-out/custody-subject/transport/custody-package").count() == 1
        && review.matches("name: collection-worm-custody-${{ github.run_id }}-${{ github.run_attempt }}").count() == 1
}

fn check_collection_custody_review_text(
    workflow: &str,
    trust_roots: &str,
    failures: &mut Vec<String>,
) {
    let Some(prepare_lines) = workflow_job_lines(workflow, "prepare-unsigned-custody-review")
    else {
        failures
            .push("collection custody review lacks its unprivileged preparation job".to_owned());
        return;
    };
    let Some(sign_lines) = workflow_job_lines(workflow, "sign-prepared-custody-review") else {
        failures.push("collection custody review lacks its protected signer job".to_owned());
        return;
    };
    let prepare = prepare_lines.join("\n");
    let sign = sign_lines.join("\n");
    let prepare_runs = collection_workflow_entries(&prepare, "run: ");
    let expected_prepare_runs = [
        "run: cargo build --locked --profile ci --package hell-ci --bin hell-ci",
        "run: ./target/ci/hell-ci collection-authority verify-checkout --input . --candidate-commit \"$COLLECTION_PREPARATION_SHA\"",
        "run: cargo build --locked --profile ci --package hell-testkit --bin hell-test-helper",
        "run: cargo build --locked --release --package hell-cli --bin hell --features hell-cli/compat-tracing",
        "run: ./target/ci/hell-ci collection-authority prepare-custody-review --package compat/collection-custody/payload --signature compat/collection-custody/signature --candidate-executable target/release/hell --reviewer \"$COLLECTION_CUSTODY_REVIEWER\" --issued-at \"$COLLECTION_CUSTODY_ISSUED_AT\" --output ci-out/collection-custody-review",
    ];
    let sign_runs = collection_workflow_entries(&sign, "run: ");
    let expected_sign_runs = [
        "run: cargo build --locked --profile ci --package hell-ci --bin hell-ci",
        "run: ./target/ci/hell-ci collection-authority verify-checkout --input . --candidate-commit \"$COLLECTION_PREPARATION_SHA\"",
        "run: ./target/ci/hell-ci collection-authority verify-custody-review-preparation --input ci-in/collection-custody-review",
        "run: ssh-add -L",
        "run: ./target/ci/hell-ci review-sign --input ci-in/collection-custody-review/integration-review-payload.json --output ci-in/collection-custody-review-signed/integration-review.dsse.json --role custody-reviewer --decision accept --policy compat/reviews.allowed_signers",
        "run: ./target/ci/hell-ci review-verify --input ci-in/collection-custody-review-signed/integration-review.dsse.json --policy compat/reviews.allowed_signers --role custody-reviewer",
        "run: ./target/ci/hell-ci collection-authority assemble-custody-review-overlay --input ci-in/collection-custody-review --integration-review ci-in/collection-custody-review-signed/integration-review.dsse.json --output ci-out/collection-custody-review-overlay",
        "run: ./target/ci/hell-ci regression-import emit-directory-output --input ci-out/collection-custody-review-overlay/tree",
    ];
    let uses_are_exact = collection_custody_review_uses_are_exact(&prepare, &sign, failures);
    if !workflow.starts_with(COLLECTION_REVIEW_DISPATCH)
        || workflow.matches("  workflow_dispatch:").count() != 1
        || ["  push:", "  schedule:", "  workflow_call:", "  pull_request:"]
            .iter()
            .any(|trigger| workflow.contains(trigger))
        || prepare
            .matches("if: ${{ github.ref == 'refs/heads/main' && inputs.preparation_sha == github.sha }}")
            .count()
            != 1
        || sign
            .matches("if: ${{ github.ref == 'refs/heads/main' && inputs.preparation_sha == github.sha }}")
            .count()
            != 1
        || sign.matches("needs: prepare-unsigned-custody-review").count() != 1
        || sign.matches("environment: collection-custody-review").count() != 1
        || sign.matches("id-token: write").count() != 1
        || sign.matches("contents: read").count() != 1
        || sign.matches("actions: read").count() != 1
        || prepare.contains("id-token: write")
        || workflow.contains("contents: write")
        || !collection_custody_review_env_is_exact(
            &prepare,
            &sign,
            &prepare_runs,
            &sign_runs,
        )
        || prepare.matches("ref: ${{ inputs.preparation_sha }}").count() != 1
        || sign.matches("ref: ${{ inputs.preparation_sha }}").count() != 1
        || workflow.matches("persist-credentials: false").count() != 2
        || sign
            .matches("artifact-ids: ${{ needs.prepare-unsigned-custody-review.outputs.artifact_id }}")
            .count()
            != 1
        || prepare_runs != expected_prepare_runs
        || sign_runs != expected_sign_runs
        || !uses_are_exact
        || sign.matches("overlay_artifact_id: ${{ steps.upload-overlay.outputs.artifact-id }}").count() != 1
        || sign.matches("overlay_artifact_digest: ${{ steps.upload-overlay.outputs.artifact-digest }}").count() != 1
        || sign.matches("overlay_directory_sha256: ${{ steps.bind-overlay.outputs.directory_sha256 }}").count() != 1
        || sign.matches("id: bind-overlay").count() != 1
        || sign.matches("id: upload-overlay").count() != 1
        || sign.matches("name: collection-custody-review-overlay-${{ github.run_id }}-${{ github.run_attempt }}").count() != 1
        || sign.matches("path: ci-out/collection-custody-review-overlay/tree").count() != 1
        || sign.contains("path: |\n            ci-out/integration-review.dsse.json")
        || sign.contains("verify-custody --")
        || sign.find("verify-custody-review-preparation")
            > sign.find("webfactory/ssh-agent")
        || trust_roots
            .matches("collection_custody_review_workflow = \".github/workflows/collection-custody-review.yml\"")
            .count()
            != 1
    {
        failures.push(
            "collection custody review is not the exact protected non-integrating signer"
                .to_owned(),
        );
    }
}

fn collection_custody_review_uses_are_exact(
    prepare: &str,
    sign: &str,
    failures: &mut Vec<String>,
) -> bool {
    let cache_restore =
        "uses: actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9 # v6.1.0";
    let cache_save = "uses: actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9 # v6.1.0";
    let expected_prepare = [
        "uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1",
        cache_restore,
        cache_restore,
        "uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1",
        cache_save,
        cache_save,
    ];
    let expected_sign = [
        "uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1",
        cache_restore,
        cache_restore,
        "uses: actions/download-artifact@70fc10c6e5e1ce46ad2ea6f2b72d43f7d47b13c3 # v8.0.1",
        "uses: sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6 # v4.1.2",
        "uses: webfactory/ssh-agent@e83874834305fe9a4a2997156cb26c5de65a8555 # v0.10.0",
        "uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1",
        cache_save,
        cache_save,
    ];
    check_collection_rust_caches(
        prepare,
        "collection-custody-prepare",
        Some("${{ inputs.preparation_sha }}"),
        ".github/workflows/collection-custody-review.yml",
        failures,
    );
    check_collection_rust_caches(
        sign,
        "collection-custody-sign",
        Some("${{ inputs.preparation_sha }}"),
        ".github/workflows/collection-custody-review.yml",
        failures,
    );
    collection_workflow_entries(prepare, "uses: ") == expected_prepare
        && collection_workflow_entries(sign, "uses: ") == expected_sign
}

fn collection_custody_review_env_is_exact(
    prepare: &str,
    sign: &str,
    prepare_runs: &[&str],
    sign_runs: &[&str],
) -> bool {
    !prepare_runs.iter().any(|run| run.contains("${{"))
        && !sign_runs.iter().any(|run| run.contains("${{"))
        && prepare
            .matches("COLLECTION_PREPARATION_SHA: ${{ inputs.preparation_sha }}")
            .count()
            == 1
        && sign
            .matches("COLLECTION_PREPARATION_SHA: ${{ inputs.preparation_sha }}")
            .count()
            == 1
        && prepare
            .matches("COLLECTION_CUSTODY_REVIEWER: ${{ inputs.reviewer }}")
            .count()
            == 1
        && prepare
            .matches("COLLECTION_CUSTODY_ISSUED_AT: ${{ inputs.issued_at }}")
            .count()
            == 1
}

fn collection_workflow_entries<'a>(body: &'a str, prefix: &str) -> Vec<&'a str> {
    body.lines()
        .map(str::trim)
        .filter(|line| line.starts_with(prefix))
        .collect()
}

const COLLECTION_CARGO_HASH: &str =
    "${{ hashFiles('rust-toolchain.toml', 'Cargo.lock', 'Cargo.toml', 'crates/**/Cargo.toml') }}";
const COLLECTION_TARGET_HASH: &str = "${{ hashFiles('rust-toolchain.toml', 'Cargo.lock', 'Cargo.toml', 'crates/**/Cargo.toml', '**/build.rs', '.cargo/**', 'rustfmt.toml', '.rustfmt.toml', 'clippy.toml', '.clippy.toml') }}-${{ hashFiles('crates/**/*.rs', 'builtins/**', 'compat/**', 'fixtures/**', 'baseline.toml', 'spec/**', '";

fn check_collection_rust_caches(
    body: &str,
    scope: &str,
    exact_sha: Option<&str>,
    workflow: &str,
    failures: &mut Vec<String>,
) {
    let cargo_key = format!(
        "key: v2-${{{{ runner.os }}}}-${{{{ runner.arch }}}}-{scope}-cargo-{COLLECTION_CARGO_HASH}"
    );
    let sha = exact_sha.map_or_else(String::new, |value| format!("{value}-"));
    let target_key = format!(
        "key: v2-${{{{ runner.os }}}}-${{{{ runner.arch }}}}-{scope}-target-{sha}{COLLECTION_TARGET_HASH}{workflow}') }}}}"
    );
    let cargo_save = "if: ${{ always() && steps.cargo-cache.outcome == 'success' && steps.cargo-cache.outputs.cache-hit != 'true' }}";
    let target_save = "if: ${{ always() && steps.target-cache.outcome == 'success' && steps.target-cache.outputs.cache-hit != 'true' }}";
    if body.matches(&cargo_key).count() != 2
        || body.matches(&target_key).count() != 2
        || body.matches("id: cargo-cache").count() != 1
        || body.matches("id: target-cache").count() != 1
        || body.matches(cargo_save).count() != 1
        || body.matches(target_save).count() != 1
        || body.contains("restore-keys:")
    {
        failures.push(format!(
            "collection job {scope} lacks exact split dependency and compilation caches"
        ));
    }
}

fn check_collection_candidate_cache(job: &str, body: &str, failures: &mut Vec<String>) {
    let key = "key: v2-${{ runner.os }}-${{ runner.arch }}-collection-candidate-${{ inputs.candidate_sha }}-${{ hashFiles('ci-work/candidate/rust-toolchain.toml', 'ci-work/candidate/Cargo.lock', 'ci-work/candidate/Cargo.toml', 'ci-work/candidate/crates/**/Cargo.toml', 'ci-work/candidate/**/build.rs', 'ci-work/candidate/.cargo/**', 'ci-work/candidate/crates/**/*.rs', 'ci-work/candidate/builtins/**', 'ci-work/candidate/compat/**', 'ci-work/candidate/fixtures/**', 'ci-work/candidate/baseline.toml', 'ci-work/candidate/spec/**', '.github/workflows/collection-authority.yml') }}";
    let save = "if: ${{ always() && steps.candidate-target-cache.outcome == 'success' && steps.candidate-target-cache.outputs.cache-hit != 'true' }}";
    if body.matches(key).count() != 2
        || body.matches("id: candidate-target-cache").count() != 1
        || body.matches("path: ci-out/candidate-target").count() != 2
        || body.matches(save).count() != 1
    {
        failures.push(format!(
            "collection producer {job} lacks its candidate-SHA-bound compilation cache"
        ));
    }
}

fn check_collection_stack_caches(job: &str, body: &str, failures: &mut Vec<String>) {
    let dependency_key = "key: v2-${{ runner.os }}-${{ runner.arch }}-stack-3.11.1-collection-oracle-${{ hashFiles('ci-work/oracle-source/stack.yaml', 'ci-work/oracle-source/stack.yaml.lock', 'ci-work/oracle-source/package.yaml', 'ci-work/oracle-source/hell.cabal', 'ci-work/oracle-source/src/**') }}";
    let build_key = "key: v2-${{ runner.os }}-${{ runner.arch }}-collection-stack-work-${{ hashFiles('rust-toolchain.toml', 'Cargo.lock', 'Cargo.toml', 'crates/**/Cargo.toml', '**/build.rs', '.cargo/**') }}-${{ hashFiles('crates/**/*.rs', 'compat/**', 'ci-work/oracle-source/stack.yaml', 'ci-work/oracle-source/stack.yaml.lock', 'ci-work/oracle-source/package.yaml', 'ci-work/oracle-source/hell.cabal', 'ci-work/oracle-source/src/**', '.github/workflows/collection-authority.yml') }}";
    let dependency_save = "if: ${{ always() && steps.native-stack-cache.outcome == 'success' && steps.native-stack-cache.outputs.cache-hit != 'true' }}";
    let build_save = "if: ${{ always() && steps.native-stack-work-cache.outcome == 'success' && steps.native-stack-work-cache.outputs.cache-hit != 'true' }}";
    if body.matches(dependency_key).count() != 2
        || body.matches(build_key).count() != 2
        || body.matches("id: setup-stack").count() != 1
        || body.matches("id: native-stack-cache").count() != 1
        || body.matches("id: native-stack-work-cache").count() != 1
        || body.matches(dependency_save).count() != 1
        || body.matches(build_save).count() != 1
    {
        failures.push(format!(
            "collection producer {job} lacks exact pinned native Stack caches"
        ));
    }
}

fn check_collection_custody_integration_text(
    workflow: &str,
    revocations: &str,
    failures: &mut Vec<String>,
) {
    const DISPATCH: &str = concat!(
        "name: Collection Custody Integration\n\non:\n  workflow_dispatch:\n    inputs:\n",
        "      integration_sha:\n",
        "        description: Exact protected integration commit containing durable collection custody\n",
        "        required: true\n        type: string\n",
    );
    let Some(lines) = workflow_job_lines(workflow, "verify-protected-integration") else {
        failures.push("collection custody integration lacks its protected verifier job".to_owned());
        return;
    };
    let body = lines.join("\n");
    let runs = body
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("run: "))
        .collect::<Vec<_>>();
    let expected_runs = [
        "run: cargo build --locked --profile ci --package hell-ci --bin hell-ci",
        "run: ./target/ci/hell-ci collection-authority verify-checkout --input . --candidate-commit \"$COLLECTION_INTEGRATION_SHA\"",
        "run: cargo build --locked --profile ci --package hell-testkit --bin hell-test-helper",
        "run: cargo build --locked --release --package hell-cli --bin hell --features hell-cli/compat-tracing",
        "run: ./target/ci/hell-ci collection-authority verify-worm-artifact --input ci-in/collection-worm-custody --expected-directory-sha256 \"$COLLECTION_WORM_DIRECTORY_SHA256\" --expected-archive-sha256 \"$COLLECTION_WORM_ARCHIVE_SHA256\" --run-id \"$COLLECTION_WORM_RUN_ID\" --run-attempt \"$COLLECTION_WORM_RUN_ATTEMPT\" --artifact-id \"$COLLECTION_WORM_ARTIFACT_ID\"",
        "run: ./target/ci/hell-ci collection-authority verify-custody --package compat/collection-custody/payload --signature compat/collection-custody/signature --candidate-executable target/release/hell --integration-proof compat/collection-custody/integration-proof.tsv --integration-review compat/collection-custody/integration-review.dsse.json --worm-custody ci-in/collection-worm-custody --report ci-out/collection-custody-admission.json",
        "run: ./target/ci/hell-ci regression-import emit-directory-output --input ci-out",
    ];
    let uses_are_exact = collection_custody_integration_uses_are_exact(&body, failures);
    if !collection_custody_integration_control_exact(workflow, &body, DISPATCH)
        || runs.iter().any(|run| run.contains("${{"))
        || runs != expected_runs
        || !uses_are_exact
        || body
            .matches(
                "name: collection-custody-admission-${{ github.run_id }}-${{ github.run_attempt }}",
            )
            .count()
            != 1
        || body.matches("id: bind-admission").count() != 1
        || body.matches("id: upload-admission").count() != 1
        || body
            .matches("            ci-out/collection-custody-admission.json\n")
            .count()
            != 1
        || body
            .matches("            ci-out/collection-custody-admission.json.sha256\n")
            .count()
            != 1
        || body
            .matches("            ci-out/collection-custody-activation-token.json\n")
            .count()
            != 1
        || body
            .matches("            ci-out/collection-custody-activation-token.json.sha256\n")
            .count()
            != 1
        || body.matches("if-no-files-found: error").count() != 1
        || body.matches("retention-days: 30").count() != 1
        || crate::collection_custody::parse_revocation_document(revocations).is_err()
    {
        failures.push(
            "collection custody integration is not the exact protected current replay gate"
                .to_owned(),
        );
    }
}

fn collection_custody_integration_control_exact(
    workflow: &str,
    body: &str,
    dispatch: &str,
) -> bool {
    let job_bindings = [
        "if: ${{ github.ref == 'refs/heads/main' && inputs.integration_sha == github.sha }}",
        "environment: collection-custody-integration",
        "permissions:",
        "contents: read",
        "actions: read",
        "runs-on: ubuntu-24.04",
        "timeout-minutes: 180",
        "admission_artifact_id: ${{ steps.upload-admission.outputs.artifact-id }}",
        "admission_artifact_digest: ${{ steps.upload-admission.outputs.artifact-digest }}",
        "admission_directory_sha256: ${{ steps.bind-admission.outputs.directory_sha256 }}",
        "ref: ${{ inputs.integration_sha }}",
        "fetch-depth: 0",
        "persist-credentials: false",
        "COLLECTION_INTEGRATION_SHA: ${{ inputs.integration_sha }}",
        "artifact-ids: ${{ inputs.worm_artifact_id }}",
        "run-id: ${{ inputs.worm_source_run_id }}",
        "COLLECTION_WORM_ARCHIVE_SHA256: ${{ inputs.expected_worm_archive_sha256 }}",
        "COLLECTION_WORM_ARTIFACT_ID: ${{ inputs.worm_artifact_id }}",
        "github-token: ${{ github.token }}",
        "COLLECTION_WORM_DIRECTORY_SHA256: ${{ inputs.expected_worm_directory_sha256 }}",
        "COLLECTION_WORM_RUN_ATTEMPT: ${{ inputs.worm_source_run_attempt }}",
        "COLLECTION_WORM_RUN_ID: ${{ inputs.worm_source_run_id }}",
        "path: ci-in/collection-worm-custody",
    ];
    workflow.starts_with(dispatch)
        && workflow.matches("  workflow_dispatch:").count() == 1
        && !["  push:", "  schedule:", "  workflow_call:", "  pull_request:"]
            .iter()
            .any(|trigger| workflow.contains(trigger))
        && workflow.matches("permissions:\n  contents: read\n").count() == 1
        && workflow.matches("concurrency:\n  group: collection-custody-integration-${{ github.repository }}\n  cancel-in-progress: false").count() == 1
        && workflow.matches("  verify-protected-integration:").count() == 1
        && job_bindings
            .iter()
            .all(|binding| body.matches(binding).count() == 1)
        && !body.contains(": write")
}

fn collection_custody_integration_uses_are_exact(body: &str, failures: &mut Vec<String>) -> bool {
    let cache_restore =
        "uses: actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9 # v6.1.0";
    let cache_save = "uses: actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9 # v6.1.0";
    let expected = [
        "uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1",
        cache_restore,
        cache_restore,
        "uses: actions/download-artifact@70fc10c6e5e1ce46ad2ea6f2b72d43f7d47b13c3 # v8.0.1",
        "uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1",
        cache_save,
        cache_save,
    ];
    check_collection_rust_caches(
        body,
        "collection-custody-integration",
        Some("${{ inputs.integration_sha }}"),
        ".github/workflows/collection-custody-integration.yml",
        failures,
    );
    collection_workflow_entries(body, "uses: ") == expected
}

fn check_collection_transport_source(source: &str, failures: &mut Vec<String>) {
    let required = [
        "\"acquire-provider\" | \"install-pinned-gh\" | \"capture-custody-attestation\"",
        "const GH_VERSION: &str = \"2.93.0\";",
        "const GH_ARCHIVE_SHA256: &str = \"02d1290eba130e0b896f3709ffff22e1c75a51475ddb70476a85abc6b5807af0\";",
        "const GH_CHECKSUMS_SHA256: &str =",
        "const GH_BINARY_SHA256: &str = \"014fcd614de4de5b4a1441d298175684bad99f713d10296c5fcaaba47ac332d1\";",
        "fn provider_pages(",
        "fn validate_complete_pages(",
        "fn configure_provider_environment(",
        "fn validate_attestation_bundle(",
        "fn validate_attestation_verification(",
        "fn configure_gh_environment(",
        "fn attestation_verify_arguments(",
        "#[cfg(test)]\nmod tests",
    ];
    if required.into_iter().any(|marker| !source.contains(marker))
        || source.contains("implementation is incomplete")
        || source.contains("Command::new(\"sh\")")
        || source.contains("Command::new(\"bash\")")
    {
        failures.push(
            "collection transport Rust source lacks the reviewed typed fail-closed implementation"
                .to_owned(),
        );
    }
}

fn check_collection_authority_producer_text(
    workflow: &str,
    transport: &str,
    failures: &mut Vec<String>,
) {
    if !collection_authority_dispatch_is_exact(workflow) {
        failures.push(
            "collection authority campaign is not isolated dispatch-only non-cancelling work"
                .to_owned(),
        );
    }
    check_collection_linux_acquisition_jobs(workflow, failures);
    check_collection_authority_platform_jobs(workflow, failures);
    check_collection_authority_merge(workflow, failures);
    check_collection_custody_payload_overlay(workflow, failures);
    check_collection_transport_source(transport, failures);
}

fn check_collection_custody_payload_overlay(workflow: &str, failures: &mut Vec<String>) {
    let Some(lines) = workflow_job_lines(workflow, "assemble-custody-payload-overlay") else {
        failures
            .push("collection campaign lacks its typed commit-ready payload overlay".to_owned());
        return;
    };
    let body = lines.join("\n");
    check_collection_rust_caches(
        &body,
        "collection-payload-overlay",
        None,
        ".github/workflows/collection-authority.yml",
        failures,
    );
    let expected_runs = [
        "run: cargo build --locked --profile ci --package hell-ci --bin hell-ci",
        "run: ./target/ci/hell-ci collection-authority verify-checkout --input . --candidate-commit \"$GITHUB_SHA\"",
        "run: ./target/ci/hell-ci collection-authority assemble-custody-payload-overlay --package ci-in/collection-custody-merge/collection-custody --signature ci-in/collection-custody-merge/collection-custody-signature --output ci-out/collection-custody-payload-overlay",
        "run: ./target/ci/hell-ci regression-import emit-directory-output --input ci-out/collection-custody-payload-overlay/tree",
    ];
    let ordered = [
        expected_runs[0],
        expected_runs[1],
        "artifact-ids: ${{ needs.merge-collection-authority.outputs.custody_artifact_id }}",
        expected_runs[2],
        "id: bind-overlay",
        expected_runs[3],
        "id: upload-overlay",
    ];
    if body.matches("needs: merge-collection-authority").count() != 1
        || body
            .matches("if: ${{ github.ref == 'refs/heads/main' && needs.merge-collection-authority.result == 'success' }}")
            .count()
            != 1
        || body.matches("actions: read").count() != 1
        || body.matches("contents: read").count() != 1
        || body.contains("id-token: write")
        || body.matches("ref: ${{ github.sha }}").count() != 1
        || body.matches("fetch-depth: 1").count() != 1
        || body.matches("persist-credentials: false").count() != 1
        || collection_workflow_entries(&body, "run: ") != expected_runs
        || !markers_are_ordered(&body, &ordered)
        || body.matches("overlay_artifact_id: ${{ steps.upload-overlay.outputs.artifact-id }}").count() != 1
        || body.matches("overlay_artifact_digest: ${{ steps.upload-overlay.outputs.artifact-digest }}").count() != 1
        || body.matches("overlay_directory_sha256: ${{ steps.bind-overlay.outputs.directory_sha256 }}").count() != 1
        || body.matches("name: collection-custody-payload-overlay-${{ github.run_id }}-${{ github.run_attempt }}").count() != 1
        || body.matches("path: ci-out/collection-custody-payload-overlay/tree").count() != 1
        || body.matches("if-no-files-found: error").count() != 1
        || body.matches("retention-days: 30").count() != 1
        || body.contains("contents: write")
        || body.contains("git push")
    {
        failures.push(
            "collection custody payload overlay is not an exact immutable commit-ready handoff"
                .to_owned(),
        );
    }
}

fn collection_authority_dispatch_is_exact(workflow: &str) -> bool {
    const DISPATCH_PREFIX: &str = concat!(
        "name: Collection Authority\n\non:\n  workflow_dispatch:\n    inputs:\n",
        "      candidate_sha:\n",
        "        description: Exact candidate commit for the collection readiness campaign\n",
        "        required: true\n        type: string\n",
    );
    const CONCURRENCY: &str = concat!(
        "concurrency:\n  group: collection-authority-${{ github.repository }}\n",
        "  cancel-in-progress: false",
    );
    workflow.starts_with(DISPATCH_PREFIX)
        && ![
            "  push:",
            "  schedule:",
            "  workflow_call:",
            "  pull_request:",
        ]
        .iter()
        .any(|trigger| workflow.contains(trigger))
        && workflow.matches("  workflow_dispatch:").count() == 1
        && workflow.matches(CONCURRENCY).count() == 1
        && !workflow.contains("  cancel-in-progress: true")
        && workflow
            .matches("HELL_SOURCE_COMMIT: ${{ inputs.candidate_sha }}")
            .count()
            == 1
        && !workflow.contains("merge-base --is-ancestor")
}

fn check_collection_authority_platform_jobs(workflow: &str, failures: &mut Vec<String>) {
    for (job, name, runner, timeout, collect, subject, upload_id, artifact) in [
        (
            "collection-authority-linux",
            "name: Collection authority / Linux amd64",
            "runs-on: ubuntu-24.04",
            "timeout-minutes: 120",
            "run: ./target/ci/hell-ci collection-authority collect --oracle ci-out/linux-release-oracle --oracle-sha256 5ccc78e62200eb5aea8b9da9161334c61848d0d3e7de2f270929920cfbf357c9 --candidate-executable ci-out/candidate-target/release/hell --candidate-commit \"$HELL_SOURCE_COMMIT\" --platform linux-amd64 --output ci-out/collection-shard/linux-amd64",
            "run: ./target/ci/hell-ci collection-authority subject --input ci-out/collection-shard/linux-amd64 --platform linux-amd64 --output ci-out/collection-shard/linux-amd64/collection-evidence/provider-subject.json",
            "id: upload-collection-linux",
            "name: collection-authority-linux-amd64-${{ github.run_id }}-${{ github.run_attempt }}",
        ),
        (
            "collection-authority-macos",
            "name: Collection authority / macOS arm64",
            "runs-on: macos-15",
            "timeout-minutes: 180",
            "run: ./target/ci/hell-ci collection-authority collect --oracle ci-out/collection-shard/macos-arm64/oracle/macos-arm64/hell --oracle-sha256 \"$COLLECTION_ORACLE_SHA256\" --candidate-executable ci-out/candidate-target/release/hell --candidate-commit \"$HELL_SOURCE_COMMIT\" --platform macos-arm64 --output ci-out/collection-shard/macos-arm64",
            "run: ./target/ci/hell-ci collection-authority subject --input ci-out/collection-shard/macos-arm64 --platform macos-arm64 --output ci-out/collection-shard/macos-arm64/collection-evidence/provider-subject.json",
            "id: upload-collection-macos",
            "name: collection-authority-macos-arm64-${{ github.run_id }}-${{ github.run_attempt }}",
        ),
        (
            "collection-authority-windows",
            "name: Collection authority / Windows amd64",
            "runs-on: windows-2025",
            "timeout-minutes: 180",
            "run: .\\target\\ci\\hell-ci.exe collection-authority collect --oracle ci-out\\collection-shard\\windows-amd64\\oracle\\windows-amd64\\hell.exe --oracle-sha256 \"$env:COLLECTION_ORACLE_SHA256\" --candidate-executable ci-out\\candidate-target\\release\\hell.exe --candidate-commit \"$env:HELL_SOURCE_COMMIT\" --platform windows-amd64 --output ci-out\\collection-shard\\windows-amd64",
            "run: .\\target\\ci\\hell-ci.exe collection-authority subject --input ci-out\\collection-shard\\windows-amd64 --platform windows-amd64 --output ci-out\\collection-shard\\windows-amd64\\collection-evidence\\provider-subject.json",
            "id: upload-collection-windows",
            "name: collection-authority-windows-amd64-${{ github.run_id }}-${{ github.run_attempt }}",
        ),
    ] {
        let Some(lines) = workflow_job_lines(workflow, job) else {
            failures.push(format!(
                "collection authority workflow lacks producer job {job}"
            ));
            continue;
        };
        let body = lines.join("\n");
        let (provider_guard, candidate_guard) = if job == "collection-authority-windows" {
            (
                "run: .\\target\\ci\\hell-ci.exe collection-authority verify-checkout --input . --candidate-commit \"$env:GITHUB_SHA\"",
                "run: .\\target\\ci\\hell-ci.exe collection-authority verify-checkout --input ci-work\\candidate --candidate-commit \"$env:HELL_SOURCE_COMMIT\"",
            )
        } else {
            (
                "run: ./target/ci/hell-ci collection-authority verify-checkout --input . --candidate-commit \"$GITHUB_SHA\"",
                "run: ./target/ci/hell-ci collection-authority verify-checkout --input ci-work/candidate --candidate-commit \"$HELL_SOURCE_COMMIT\"",
            )
        };
        let ordered = [
            "run: cargo build --locked --profile ci --package hell-ci --bin hell-ci",
            provider_guard,
            candidate_guard,
            "run: cargo build --locked --profile ci --package hell-testkit --bin hell-test-helper",
            "run: cargo build --locked --release --manifest-path ci-work/candidate/Cargo.toml --target-dir ci-out/candidate-target --package hell-cli --bin hell --features hell-cli/compat-tracing",
            collect,
            subject,
            upload_id,
        ];
        if [name, runner, timeout, collect, subject, upload_id, artifact]
            .into_iter()
            .any(|marker| body.matches(marker).count() != 1)
            || body.matches(provider_guard).count() != 1
            || body.matches(candidate_guard).count() != 1
            || !markers_are_ordered(&body, &ordered)
            || body.matches("path: ci-out/collection-shard/*").count() != 1
            || body.matches("if-no-files-found: error").count() != 1
            || body.matches("retention-days: 30").count() != 1
            || body.contains("if: ${{ always() }}")
            || body.contains(" native-oracle-shard ")
            || body.contains(" nightly --oracle ")
        {
            failures.push(format!(
                "collection authority producer {job} is not one bounded standalone collect-subject-upload pipeline"
            ));
        }
        let scope = match job {
            "collection-authority-linux" => "collection-linux",
            "collection-authority-macos" => "collection-macos",
            "collection-authority-windows" => "collection-windows",
            _ => unreachable!("reviewed collection job list"),
        };
        check_collection_rust_caches(
            &body,
            scope,
            None,
            ".github/workflows/collection-authority.yml",
            failures,
        );
        check_collection_candidate_cache(job, &body, failures);
        if matches!(
            job,
            "collection-authority-macos" | "collection-authority-windows"
        ) {
            check_collection_stack_caches(job, &body, failures);
        }
        check_collection_authority_job_identity(job, &body, failures);
    }

    check_collection_authority_platform_builds(workflow, failures);
}

fn check_collection_authority_merge(workflow: &str, failures: &mut Vec<String>) {
    let Some(lines) = workflow_job_lines(workflow, "merge-collection-authority") else {
        failures.push("collection authority workflow lacks protected merge job".to_owned());
        return;
    };
    let body = lines.join("\n");
    check_collection_rust_caches(
        &body,
        "collection-merge",
        None,
        ".github/workflows/collection-authority.yml",
        failures,
    );
    let ordered = [
        "run: cargo build --locked --profile ci --package hell-ci --bin hell-ci",
        "run: ./target/ci/hell-ci collection-authority verify-checkout --input . --candidate-commit \"$GITHUB_SHA\"",
        COLLECTION_INSTALL_GH_COMMAND,
        COLLECTION_ACQUISITION_COMMAND,
        COLLECTION_VERIFY_COMMAND,
        COLLECTION_COMPACT_COMMAND,
        "uses: actions/attest@a1948c3f048ba23858d222213b7c278aabede763 # v4.1.1",
        "subject-path: ci-out/collection-custody/custody-attestation-subject.json",
        COLLECTION_ATTESTATION_TOOL_COMMAND,
        COLLECTION_RETAIN_CUSTODY_COMMAND,
        "name: collection-authority-custody-${{ github.run_id }}-${{ github.run_attempt }}",
    ];
    if !markers_are_ordered(&body, &ordered)
        || body.matches(COLLECTION_ACQUISITION_COMMAND).count() != 1
        || body.matches(COLLECTION_VERIFY_COMMAND).count() != 1
        || body.matches(COLLECTION_COMPACT_COMMAND).count() != 1
        || body.matches(COLLECTION_INSTALL_GH_COMMAND).count() != 1
        || body.matches(COLLECTION_ATTESTATION_TOOL_COMMAND).count() != 1
        || body.matches(COLLECTION_RETAIN_CUSTODY_COMMAND).count() != 1
        || body
            .matches("run: ./target/ci/hell-ci collection-authority verify-checkout --input . --candidate-commit \"$GITHUB_SHA\"")
            .count()
            != 1
        || body.matches("actions: read").count() != 1
        || body.matches("timeout-minutes: 90").count() != 1
        || body.matches("needs: [collection-authority-linux, collection-authority-macos, collection-authority-windows]").count() != 1
        || body.matches("if: ${{ always() && github.ref == 'refs/heads/main' && needs.collection-authority-linux.result == 'success' && needs.collection-authority-macos.result == 'success' && needs.collection-authority-windows.result == 'success' }}").count() != 1
        || body.matches("attestations: write").count() != 1
        || body.matches("contents: read").count() != 1
        || body.matches("id-token: write").count() != 1
        || body.matches("runs-on: ubuntu-24.04").count() != 1
        || body.matches("COLLECTION_LINUX_ARTIFACT_ID: ${{ needs.collection-authority-linux.outputs.artifact_id }}").count() != 1
        || body.matches("COLLECTION_MACOS_ARTIFACT_ID: ${{ needs.collection-authority-macos.outputs.artifact_id }}").count() != 1
        || body.matches("COLLECTION_WINDOWS_ARTIFACT_ID: ${{ needs.collection-authority-windows.outputs.artifact_id }}").count() != 1
        || body.matches("GITHUB_TOKEN: ${{ github.token }}").count() != 1
        || body.matches("ref: ${{ github.sha }}").count() != 1
        || body.matches("fetch-depth: 1").count() != 1
        || body.matches("persist-credentials: false").count() != 1
        || body.matches("id: attest-collection-custody").count() != 1
        || body.matches("subject-path: ci-out/collection-custody/custody-attestation-subject.json").count() != 1
        || body.matches("COLLECTION_CUSTODY_BUNDLE_PATH: ${{ steps.attest-collection-custody.outputs.bundle-path }}").count() != 2
        || body.matches("custody_artifact_id: ${{ steps.upload-collection-custody.outputs.artifact-id }}").count() != 1
        || body.matches("custody_artifact_digest: ${{ steps.upload-collection-custody.outputs.artifact-digest }}").count() != 1
        || body.matches("id: upload-collection-custody").count() != 1
        || body
            .matches("uses: actions/attest@a1948c3f048ba23858d222213b7c278aabede763 # v4.1.1")
            .count()
            != 1
        || body
            .matches("uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1")
            .count()
            != 1
        || body.matches("name: collection-authority-custody-${{ github.run_id }}-${{ github.run_attempt }}").count() != 1
        || body.matches("            ci-out/collection-custody\n").count() != 1
        || body
            .matches("            ci-out/collection-custody-signature\n")
            .count()
            != 1
        || body.matches("retention-days: 30").count() != 1
        || body.contains("name: collection-authority-merged-")
        || body.contains("            ci-out/native-shards\n")
        || body.contains("            ci-out/collection-provider\n")
        || body.contains("            ci-out/collection-custody-attestation-input\n")
        || body.contains("collection-authority verify-custody")
        || body.contains("actions/download-artifact@")
        || body.contains("python3")
        || body.contains(".py")
        || body.contains("./tools/")
    {
        failures.push(
            "collection authority merge is not one API-selected, verified, compacted, attested transport-only campaign"
                .to_owned(),
        );
    }
}

fn check_collection_linux_acquisition_jobs(workflow: &str, failures: &mut Vec<String>) {
    let Some(subject) = workflow_job_lines(workflow, "linux-acquisition-subject") else {
        failures.push("collection campaign lacks Linux acquisition subject job".to_owned());
        return;
    };
    let subject = subject.join("\n");
    check_collection_rust_caches(
        &subject,
        "collection-linux-acquisition",
        None,
        ".github/workflows/collection-authority.yml",
        failures,
    );
    let subject_order = [
        "ref: ${{ github.sha }}",
        "run: cargo build --locked --profile ci --package hell-ci --bin hell-ci",
        "run: ./target/ci/hell-ci collection-authority verify-checkout --input . --candidate-commit \"$GITHUB_SHA\"",
        "run: ./target/ci/hell-ci release-oracle acquire --artifact ci-out/linux-release-oracle --provider-response ci-out/linux-release-provider.json --receipt ci-out/linux-release-oracle-receipt.json",
        "id: upload-subject",
        "name: collection-linux-acquisition-subject-${{ github.run_id }}-${{ github.run_attempt }}",
    ];
    if !markers_are_ordered(&subject, &subject_order)
        || subject
            .matches("name: Collection Linux acquisition subject")
            .count()
            != 1
        || subject
            .matches("if: ${{ github.ref == 'refs/heads/main' }}")
            .count()
            != 1
        || subject.matches("contents: read").count() != 1
        || subject.contains("actions: read")
        || subject.contains("id-token: write")
        || subject
            .matches("artifact_id: ${{ steps.upload-subject.outputs.artifact-id }}")
            .count()
            != 1
        || subject.matches("persist-credentials: false").count() != 1
        || subject
            .matches("run: ./target/ci/hell-ci collection-authority verify-checkout --input . --candidate-commit \"$GITHUB_SHA\"")
            .count()
            != 1
    {
        failures.push("collection Linux acquisition subject trust role differs".to_owned());
    }

    let Some(signer) = workflow_job_lines(workflow, "sign-linux-acquisition") else {
        failures.push("collection campaign lacks Linux acquisition signer job".to_owned());
        return;
    };
    let signer = signer.join("\n");
    check_collection_rust_caches(
        &signer,
        "collection-linux-acquisition-sign",
        None,
        ".github/workflows/collection-authority.yml",
        failures,
    );
    let signer_order = [
        "ref: ${{ github.sha }}",
        "run: cargo build --locked --profile ci --package hell-ci --bin hell-ci",
        "run: ./target/ci/hell-ci collection-authority verify-checkout --input . --candidate-commit \"$GITHUB_SHA\"",
        "artifact-ids: ${{ needs.linux-acquisition-subject.outputs.artifact_id }}",
        "uses: sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6 # v4.1.2",
        "run: ./target/ci/hell-ci release-oracle attest --artifact ci-out/linux-release-oracle --provider-response ci-out/linux-release-provider.json --receipt ci-out/linux-release-oracle-receipt.json --attestation ci-out/linux-release-oracle-acquisition.dsse.json",
        "id: upload-signed",
        "name: collection-linux-acquisition-signed-${{ github.run_id }}-${{ github.run_attempt }}",
    ];
    if !markers_are_ordered(&signer, &signer_order)
        || signer.matches("needs: linux-acquisition-subject").count() != 1
        || signer.matches("if: ${{ github.ref == 'refs/heads/main' && needs.linux-acquisition-subject.result == 'success' }}").count() != 1
        || signer.matches("actions: read").count() != 1
        || signer.matches("contents: read").count() != 1
        || signer.matches("id-token: write").count() != 1
        || signer.matches("environment: linux-release-acquisition-signing").count() != 1
        || signer.matches("artifact_id: ${{ steps.upload-signed.outputs.artifact-id }}").count()
            != 1
        || signer.matches("persist-credentials: false").count() != 1
        || signer
            .matches("run: ./target/ci/hell-ci collection-authority verify-checkout --input . --candidate-commit \"$GITHUB_SHA\"")
            .count()
            != 1
    {
        failures.push("collection Linux acquisition signer trust role differs".to_owned());
    }
}

fn check_collection_authority_job_identity(job: &str, body: &str, failures: &mut Vec<String>) {
    let candidate_ref = "ref: ${{ inputs.candidate_sha }}";
    let common_guard = "if: ${{ github.ref == 'refs/heads/main' }}";
    let (guard, needs, actions_permission, checkout_count) = match job {
        "collection-authority-linux" => (
            "if: ${{ github.ref == 'refs/heads/main' && needs.sign-linux-acquisition.result == 'success' }}",
            Some("needs: sign-linux-acquisition"),
            1,
            2,
        ),
        "collection-authority-macos" | "collection-authority-windows" => (common_guard, None, 0, 3),
        _ => {
            failures.push(format!("unknown collection producer policy job {job}"));
            return;
        }
    };
    let Some(suffix) = job.strip_prefix("collection-authority-") else {
        failures.push(format!("collection producer {job} has no reviewed prefix"));
        return;
    };
    let output =
        format!("artifact_id: ${{{{ steps.upload-collection-{suffix}.outputs.artifact-id }}}}");
    if body.matches(guard).count() != 1
        || needs.is_some_and(|marker| body.matches(marker).count() != 1)
        || body.matches("permissions:").count() != 1
        || body.matches("actions: read").count() != actions_permission
        || body.matches("contents: read").count() != 1
        || body.matches("outputs:").count() != 1
        || body.matches(&output).count() != 1
        || body
            .matches("uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1")
            .count()
            != checkout_count
        || body.matches(candidate_ref).count() != 1
        || body.matches("ref: ${{ github.sha }}").count() != 1
        || body.matches("path: ci-work/candidate").count() != 1
        || body.matches("fetch-depth: 1").count() != checkout_count
        || body.matches("persist-credentials: false").count() != checkout_count
    {
        failures.push(format!(
            "collection producer {job} guard, permissions, output, or checkout identity differs"
        ));
    }
}

fn check_collection_authority_platform_builds(workflow: &str, failures: &mut Vec<String>) {
    let linux = workflow_job_lines(workflow, "collection-authority-linux")
        .unwrap_or_default()
        .join("\n");
    if linux.matches("needs: sign-linux-acquisition").count() != 1
        || linux
            .matches("artifact-ids: ${{ needs.sign-linux-acquisition.outputs.artifact_id }}")
            .count()
            != 1
    {
        failures.push("Linux collection producer does not consume the exact signed release".into());
    }
    for (job, platform, executable, command) in [
        (
            "collection-authority-macos",
            "macos-arm64",
            "ci-out/collection-shard/macos-arm64/oracle/macos-arm64/hell",
            "run: ./target/ci/hell-ci collection-authority build-native --source ci-work/oracle-source --platform macos-arm64 --output ci-out/collection-shard/macos-arm64",
        ),
        (
            "collection-authority-windows",
            "windows-amd64",
            "ci-out\\collection-shard\\windows-amd64\\oracle\\windows-amd64\\hell.exe",
            "run: .\\target\\ci\\hell-ci.exe collection-authority build-native --source ci-work\\oracle-source --platform windows-amd64 --output ci-out\\collection-shard\\windows-amd64",
        ),
    ] {
        let body = workflow_job_lines(workflow, job)
            .unwrap_or_default()
            .join("\n");
        if body.matches(command).count() != 1
            || body
                .matches("ref: 8e952cf9de4ab25d7716982a9ca234f9bdcf1bff")
                .count()
                != 1
            || body.matches("stack-version: 3.11.1").count() != 1
            || !body.contains(executable)
            || !body.contains(platform)
        {
            failures.push(format!(
                "native collection producer {job} lacks its exact source build and executable join"
            ));
        }
    }
}

fn markers_are_ordered(body: &str, markers: &[&str]) -> bool {
    let mut cursor = 0;
    for marker in markers {
        let Some(relative) = body[cursor..].find(marker) else {
            return false;
        };
        cursor = cursor.saturating_add(relative).saturating_add(marker.len());
    }
    true
}

fn semantic_fuzz_command(target: &str) -> String {
    format!(
        "run: cargo +{CARGO_FUZZ_TOOLCHAIN} fuzz run --fuzz-dir crates/hell-ci/fuzz {target} ci-out/fuzz-corpora/{target} -- -runs=64 -timeout=10 -artifact_prefix=ci-out/fuzz-artifacts/{target}/"
    )
}

fn semantic_fuzz_workflow_targets(workflow: &str) -> Vec<&str> {
    const MARKER: &str = "fuzz run --fuzz-dir crates/hell-ci/fuzz ";
    workflow
        .lines()
        .filter_map(|line| {
            line.find(MARKER).and_then(|offset| {
                line[offset + MARKER.len()..]
                    .split_ascii_whitespace()
                    .next()
            })
        })
        .collect()
}

fn semantic_fuzz_manifest_bins(manifest: &str) -> Vec<&str> {
    let mut bins = Vec::new();
    let mut awaiting_name = false;
    for line in manifest.lines().map(str::trim) {
        if line == "[[bin]]" {
            awaiting_name = true;
        } else if awaiting_name
            && let Some(name) = line
                .strip_prefix("name = \"")
                .and_then(|name| name.strip_suffix('"'))
        {
            bins.push(name);
            awaiting_name = false;
        }
    }
    bins
}

fn semantic_fuzz_corpus_directories(root: &Path) -> Result<BTreeSet<String>, String> {
    let corpus = root.join("crates/hell-ci/fuzz/corpus");
    let entries = fs::read_dir(&corpus)
        .map_err(|error| format!("cannot read {}: {error}", corpus.display()))?;
    let mut directories = BTreeSet::new();
    for entry in entries {
        let entry = entry
            .map_err(|error| format!("cannot read an entry below {}: {error}", corpus.display()))?;
        if entry
            .file_type()
            .map_err(|error| format!("cannot inspect {}: {error}", entry.path().display()))?
            .is_dir()
        {
            directories.insert(
                entry
                    .file_name()
                    .into_string()
                    .map_err(|_| "semantic fuzz corpus directory is not UTF-8".to_owned())?,
            );
        }
    }
    Ok(directories)
}

fn check_semantic_fuzz_campaign(root: &Path, failures: &mut Vec<String>) {
    let Some((nightly, manifest)) = read_semantic_fuzz_campaign_files(root, failures) else {
        return;
    };
    check_semantic_fuzz_instrumentation(&nightly, failures);
    check_semantic_fuzz_inventory(root, &nightly, &manifest, failures);
    check_semantic_fuzz_retention(&nightly, failures);
    check_semantic_fuzz_metadata(&manifest, failures);
}

fn read_semantic_fuzz_campaign_files(
    root: &Path,
    failures: &mut Vec<String>,
) -> Option<(String, String)> {
    let nightly_path = root.join(".github/workflows/nightly.yml");
    let manifest_path = root.join("crates/hell-ci/fuzz/Cargo.toml");
    let nightly = match fs::read_to_string(&nightly_path) {
        Ok(nightly) => nightly,
        Err(error) => {
            failures.push(format!("cannot read {}: {error}", nightly_path.display()));
            return None;
        }
    };
    let manifest = match fs::read_to_string(&manifest_path) {
        Ok(manifest) => manifest,
        Err(error) => {
            failures.push(format!("cannot read {}: {error}", manifest_path.display()));
            return None;
        }
    };
    Some((nightly, manifest))
}

fn check_semantic_fuzz_instrumentation(nightly: &str, failures: &mut Vec<String>) {
    let toolchain_install =
        format!("run: rustup toolchain install {CARGO_FUZZ_TOOLCHAIN} --profile minimal");
    let cargo_fuzz_install = format!(
        "run: cargo +{CARGO_FUZZ_TOOLCHAIN} install cargo-fuzz --version {CARGO_FUZZ_VERSION} --locked"
    );
    let corpus_prepare = "run: ./target/ci/hell-ci fuzz-corpus prepare --input crates/hell-ci/fuzz/corpus --output ci-out/fuzz-corpora --to ci-out/fuzz-artifacts";
    let corpus_clean =
        "run: ./target/ci/hell-ci fuzz-corpus verify-clean --input crates/hell-ci/fuzz/corpus";
    let corpus_clean_block = "      - name: Verify fuzzing left committed seed corpora unchanged\n        if: ${{ always() }}\n        run: ./target/ci/hell-ci fuzz-corpus verify-clean --input crates/hell-ci/fuzz/corpus";
    let first_campaign = semantic_fuzz_command(SEMANTIC_FUZZ_TARGETS[0]);
    let ordered_install = matches!(
        (
            nightly.find(&toolchain_install),
            nightly.find(&cargo_fuzz_install),
            nightly.find(corpus_prepare),
            nightly.find(&first_campaign),
        ),
        (Some(toolchain), Some(driver), Some(prepare), Some(campaign))
            if toolchain < driver && driver < prepare && prepare < campaign
    );
    if nightly.matches(&toolchain_install).count() != 1
        || nightly.matches(&cargo_fuzz_install).count() != 1
        || nightly.matches(corpus_prepare).count() != 1
        || nightly.matches(corpus_clean).count() != 1
        || nightly.matches(corpus_clean_block).count() != 1
        || !ordered_install
        || nightly
            .contains("cargo run --locked --manifest-path crates/hell-ci/fuzz/Cargo.toml --bin")
        || SEMANTIC_FUZZ_TARGETS.iter().any(|target| {
            nightly.contains(&format!(
                "fuzz run --fuzz-dir crates/hell-ci/fuzz {target} crates/hell-ci/fuzz/corpus/{target}"
            ))
        })
    {
        failures.push(
            "semantic fuzz campaign is not driven by one pinned coverage-instrumented cargo-fuzz toolchain"
                .to_owned(),
        );
    }
}

fn check_semantic_fuzz_inventory(
    root: &Path,
    nightly: &str,
    manifest: &str,
    failures: &mut Vec<String>,
) {
    let exact_targets = SEMANTIC_FUZZ_TARGETS.to_vec();
    let exact_target_set = SEMANTIC_FUZZ_TARGETS
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if semantic_fuzz_workflow_targets(nightly) != exact_targets {
        failures.push(
            "semantic fuzz workflow commands are not the exact ordered target inventory".to_owned(),
        );
    }
    if semantic_fuzz_manifest_bins(manifest) != exact_targets {
        failures.push(
            "semantic fuzz manifest bins are not the exact ordered target inventory".to_owned(),
        );
    }
    match semantic_fuzz_corpus_directories(root) {
        Ok(directories) if directories == exact_target_set => {}
        Ok(_) => failures
            .push("semantic fuzz corpus directories are not the exact target inventory".to_owned()),
        Err(error) => failures.push(error),
    }
    for target in SEMANTIC_FUZZ_TARGETS {
        let command = semantic_fuzz_command(target);
        if nightly.matches(&command).count() != 1 {
            failures.push(format!(
                "semantic fuzz target {target} lacks one exact bounded cargo-fuzz campaign"
            ));
        }
        let corpus = root.join("crates/hell-ci/fuzz/corpus").join(target);
        if !corpus.is_dir() {
            failures.push(format!(
                "semantic fuzz target {target} lacks its committed corpus directory"
            ));
        }
    }
}

fn check_semantic_fuzz_retention(nightly: &str, failures: &mut Vec<String>) {
    let corpus_clean =
        "run: ./target/ci/hell-ci fuzz-corpus verify-clean --input crates/hell-ci/fuzz/corpus";
    let corpus_retention = "      - name: Retain evolving semantic fuzz corpora\n        if: ${{ always() }}\n        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1\n        with:\n          name: semantic-fuzz-corpus-${{ github.run_id }}-${{ github.run_attempt }}\n          path: ci-out/fuzz-corpora\n          if-no-files-found: error\n          retention-days: 30";
    let crash_retention = "      - name: Retain semantic fuzz crash artifacts\n        if: ${{ always() }}\n        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1\n        with:\n          name: semantic-fuzz-crashes-${{ github.run_id }}-${{ github.run_attempt }}\n          path: ci-out/fuzz-artifacts\n          if-no-files-found: ignore\n          retention-days: 90";
    let last_campaign = semantic_fuzz_command(
        SEMANTIC_FUZZ_TARGETS
            .last()
            .expect("semantic fuzz targets are nonempty"),
    );
    if nightly.matches(corpus_retention).count() != 1
        || nightly.matches(crash_retention).count() != 1
        || !matches!(
            (
                nightly.find(&last_campaign),
                nightly.find(corpus_clean),
                nightly.find(corpus_retention),
                nightly.find(crash_retention),
            ),
            (Some(campaign), Some(clean), Some(corpus), Some(crashes))
                if campaign < clean && clean < corpus && corpus < crashes
        )
    {
        failures.push(
            "semantic fuzz campaign does not retain evolving corpora and crash artifacts on every outcome"
                .to_owned(),
        );
    }
}

fn check_semantic_fuzz_metadata(manifest: &str, failures: &mut Vec<String>) {
    for required in [
        "[package.metadata.assurance]",
        &format!("cargo-fuzz-version = \"{CARGO_FUZZ_VERSION}\""),
        &format!("cargo-fuzz-toolchain = \"{CARGO_FUZZ_TOOLCHAIN}\""),
    ] {
        if manifest
            .lines()
            .filter(|line| line.trim() == required)
            .count()
            != 1
        {
            failures.push(format!(
                "semantic fuzz manifest does not pin exact assurance metadata {required}"
            ));
        }
    }
}

fn check_expected_mismatch_manifest(root: &Path, failures: &mut Vec<String>) {
    let path = root.join("compat").join("expected-mismatches.toml");
    let contents = match fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(error) => {
            failures.push(format!("cannot read {}: {error}", path.display()));
            return;
        }
    };
    if !contents
        .lines()
        .any(|line| line.trim() == "schema_version = 1")
        || !contents
            .lines()
            .any(|line| line.trim() == "baseline = \"2026-05-29\"")
    {
        failures.push("expected-mismatch manifest has the wrong schema or baseline".to_owned());
    }
    let entry_count = contents
        .lines()
        .filter(|line| line.trim() == "[[entry]]")
        .count();
    if entry_count == 0 && !contents.lines().any(|line| line.trim() == "entries = []") {
        failures.push("empty expected-mismatch manifest must declare entries = []".to_owned());
    }
    if entry_count != 0 {
        for required in [
            "case = ",
            "classification = ",
            "claim = ",
            "dimension = ",
            "platform = ",
            "profile = ",
            "oracle_sha256 = ",
            "candidate_sha256 = ",
            "expires = ",
            "rationale = ",
        ] {
            if contents
                .lines()
                .filter(|line| line.trim().starts_with(required))
                .count()
                != entry_count
            {
                failures.push(format!(
                    "every expected mismatch must define exactly one {required}field"
                ));
            }
        }
    }
}

fn check_dependency_policy(root: &Path, failures: &mut Vec<String>) {
    let deny_path = root.join("deny.toml");
    let deny = match fs::read_to_string(&deny_path) {
        Ok(deny) => deny,
        Err(error) => {
            failures.push(format!("cannot read {}: {error}", deny_path.display()));
            return;
        }
    };
    for required in [
        "unknown-registry = \"deny\"",
        "unknown-git = \"deny\"",
        "wildcards = \"deny\"",
        "multiple-versions = \"deny\"",
        "[advisories]",
        "[licenses]",
    ] {
        if !deny.lines().any(|line| line.trim() == required) {
            failures.push(format!("deny.toml is missing reviewed rule {required}"));
        }
    }
    for workflow in [
        root.join(".github").join("workflows").join("ci.yml"),
        root.join(".github").join("workflows").join("nightly.yml"),
    ] {
        match fs::read_to_string(&workflow) {
            Ok(contents) if contents.contains(CARGO_DENY_ACTION) => {}
            Ok(_) => failures.push(format!(
                "{} does not invoke the pinned dependency gate",
                workflow.display()
            )),
            Err(error) => failures.push(format!("cannot read {}: {error}", workflow.display())),
        }
    }
    let nightly_path = root.join(".github").join("workflows").join("nightly.yml");
    match fs::read_to_string(&nightly_path) {
        Ok(contents) => {
            check_native_dependency_job(
                &contents,
                "native-oracle-macos",
                "runs-on: macos-15",
                failures,
            );
            check_native_dependency_job(
                &contents,
                "native-oracle-windows",
                "runs-on: windows-2025",
                failures,
            );
        }
        Err(error) => failures.push(format!("cannot read {}: {error}", nightly_path.display())),
    }
}

fn check_native_dependency_job(
    workflow: &str,
    job: &str,
    runner: &str,
    failures: &mut Vec<String>,
) {
    let Some(lines) = workflow_job_lines(workflow, job) else {
        failures.push(format!("nightly workflow is missing native job {job}"));
        return;
    };
    for required in [runner, CARGO_DENY_INSTALL, CARGO_DENY_CHECK] {
        if lines
            .iter()
            .filter(|line| workflow_entry(line) == required)
            .count()
            != 1
        {
            failures.push(format!(
                "nightly native job {job} must contain exactly one {required}"
            ));
        }
    }
    if lines.iter().any(|line| line.contains(CARGO_DENY_ACTION)) {
        failures.push(format!(
            "nightly native job {job} uses the Linux-only cargo-deny action"
        ));
    }
    let install = lines
        .iter()
        .position(|line| workflow_entry(line) == CARGO_DENY_INSTALL);
    let check = lines
        .iter()
        .position(|line| workflow_entry(line) == CARGO_DENY_CHECK);
    if !matches!((install, check), (Some(install), Some(check)) if install < check) {
        failures.push(format!(
            "nightly native job {job} must install cargo-deny before invoking it"
        ));
    }
}

fn workflow_job_lines<'a>(workflow: &'a str, job: &str) -> Option<Vec<&'a str>> {
    let header = format!("  {job}:");
    let mut lines = workflow.lines();
    lines.find(|line| *line == header)?;
    Some(
        lines
            .take_while(|line| {
                let Some(remainder) = line.strip_prefix("  ") else {
                    return true;
                };
                remainder.chars().next().is_none_or(char::is_whitespace)
                    || !remainder.ends_with(':')
            })
            .collect(),
    )
}

fn workflow_entry(line: &str) -> &str {
    let line = line.trim();
    line.strip_prefix("- ").unwrap_or(line)
}

fn check_semantic_limit_inventory(root: &Path, failures: &mut Vec<String>) {
    const REVIEWED: [(&str, &str); 8] = [
        (
            "crates/hell-runtime/src/native_http.rs",
            "SANDBOX_SOCKET_TIMEOUT",
        ),
        (
            "crates/hell-runtime/src/native_handle.rs",
            "BLOCK_BUFFER_BYTES",
        ),
        ("crates/hell-http-host/src/lib.rs", "ENGINE_POLL_INTERVAL"),
        ("crates/hell-http-host/src/lib.rs", "BODY_CHANNEL_CAPACITY"),
        (
            "crates/hell-http-host/src/lib.rs",
            "HYPER_MINIMUM_BUFFER_SIZE",
        ),
        ("crates/hell-runtime/src/native_json.rs", "MAX_DEPTH"),
        ("crates/hell-runtime/src/lib.rs", "MAX_DEPTH"),
        ("crates/hell-runtime/src/lib.rs", "MAX_ELEMENTS"),
    ];
    let inventory_path = root.join("spec").join("runtime-profiles.md");
    let inventory = match fs::read_to_string(&inventory_path) {
        Ok(inventory) => inventory,
        Err(error) => {
            failures.push(format!(
                "cannot read semantic-limit inventory {}: {error}",
                inventory_path.display()
            ));
            return;
        }
    };
    for (path, name) in REVIEWED {
        let source_path = root.join(path);
        let source = match fs::read_to_string(&source_path) {
            Ok(source) => source,
            Err(error) => {
                failures.push(format!("cannot scan {}: {error}", source_path.display()));
                continue;
            }
        };
        if !source.contains(name) {
            failures.push(format!(
                "reviewed semantic limit {name} disappeared from {path}; update the inventory"
            ));
        }
        if !inventory.contains(path) || !inventory.contains(name) {
            failures.push(format!(
                "semantic limit {path}:{name} is absent from spec/runtime-profiles.md"
            ));
        }
        check_exact_evidence_limit(path, name, &source, &inventory, failures);
    }
    let mut sources = Vec::new();
    for directory in [
        "crates/hell-syntax/src",
        "crates/hell-compiler/src",
        "crates/hell-runtime/src",
        "crates/hell-http-host/src",
    ] {
        collect_rust_sources(&root.join(directory), &mut sources, failures);
    }
    sources.sort();
    for source_path in sources {
        let source = match fs::read_to_string(&source_path) {
            Ok(source) => source,
            Err(error) => {
                failures.push(format!("cannot scan {}: {error}", source_path.display()));
                continue;
            }
        };
        let relative = source_path
            .strip_prefix(root)
            .unwrap_or(&source_path)
            .to_string_lossy()
            .replace(std::path::MAIN_SEPARATOR, "/");
        for name in semantic_constant_names(&source) {
            let marker = format!("`{relative}`: `{name}`");
            if !inventory.contains(&marker) {
                failures.push(format!(
                    "unreviewed semantic-limit candidate {relative}:{name}; classify it in spec/runtime-profiles.md"
                ));
            }
        }
    }
}

fn check_exact_evidence_limit(
    path: &str,
    name: &str,
    source: &str,
    inventory: &str,
    failures: &mut Vec<String>,
) {
    let reviewed = match (path, name) {
        ("crates/hell-runtime/src/lib.rs", "MAX_DEPTH") => Some((
            "const MAX_DEPTH: usize = 64;",
            "| `crates/hell-runtime/src/lib.rs`: `MAX_DEPTH` | Evidence canonicalization guardrail | Under `compat-tracing`, recursive evidence traversal emits an explicit `ForceBoundary` depth-limit marker at 64 levels; it neither forces nor rejects a guest value. |",
        )),
        ("crates/hell-runtime/src/lib.rs", "MAX_ELEMENTS") => Some((
            "const MAX_ELEMENTS: usize = 1_024;",
            "| `crates/hell-runtime/src/lib.rs`: `MAX_ELEMENTS` | Evidence canonicalization guardrail | Under `compat-tracing`, list evidence traversal records at most 1,024 elements and an explicit element-limit termination; guest list evaluation remains unchanged. |",
        )),
        _ => None,
    };
    if let Some((declaration, row)) = reviewed {
        if source.matches(declaration).count() != 1 {
            failures.push(format!(
                "reviewed evidence limit declaration {path}:{name} differs"
            ));
        }
        if inventory.matches(row).count() != 1 {
            failures.push(format!(
                "reviewed evidence limit classification {path}:{name} differs"
            ));
        }
    }
}

fn collect_rust_sources(directory: &Path, files: &mut Vec<PathBuf>, failures: &mut Vec<String>) {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) => {
            failures.push(format!("cannot enumerate {}: {error}", directory.display()));
            return;
        }
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                failures.push(format!("cannot enumerate {}: {error}", directory.display()));
                continue;
            }
        };
        let path = entry.path();
        if path.is_dir() {
            collect_rust_sources(&path, files, failures);
        } else if path.extension().and_then(std::ffi::OsStr::to_str) == Some("rs") {
            files.push(path);
        }
    }
}

fn semantic_constant_names(source: &str) -> impl Iterator<Item = &str> {
    const INDICATORS: [&str; 7] = [
        "MAX_",
        "_LIMIT",
        "_TIMEOUT",
        "_CAPACITY",
        "_BUFFER_BYTES",
        "_STACK_BYTES",
        "_RETRIES",
    ];
    source.lines().filter_map(|line| {
        let code = line.split_once("//").map_or(line, |(code, _)| code);
        let (_, declaration) = code.split_once("const ")?;
        let (name, _) = declaration.split_once(':')?;
        let name = name.trim();
        (name
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
            && INDICATORS.iter().any(|indicator| name.contains(indicator)))
        .then_some(name)
    })
}

fn check_checkout_attributes(root: &Path, failures: &mut Vec<String>) {
    const PATHS: &[&str] = &[
        "crates/hell-docgen/src/lib.rs",
        "compat/upstream-2026-05-29.json",
        "builtins/primitives.ron",
        "fixtures/upstream-2026-05-29/expected/01.stdout",
        "fixtures/upstream-2026-05-29/examples/01-hello-world.hell",
    ];

    let mut command = Command::new("git");
    command.args([
        "check-attr",
        "--cached",
        "-z",
        "text",
        "eol",
        "linguist-language",
        "--",
    ]);
    command.args(PATHS);
    command.current_dir(root);
    let output = match command.output() {
        Ok(output) => output,
        Err(error) => {
            failures.push(format!("git check-attr failed to start: {error}"));
            return;
        }
    };
    if !output.status.success() {
        failures.push(format!(
            "git check-attr failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
        return;
    }
    let attributes = match parse_checked_attributes(&output.stdout) {
        Ok(attributes) => attributes,
        Err(error) => {
            failures.push(error);
            return;
        }
    };
    for path in PATHS {
        require_attribute(&attributes, path, "text", "auto", failures);
        require_attribute(&attributes, path, "eol", "lf", failures);
    }
    require_attribute(
        &attributes,
        "fixtures/upstream-2026-05-29/examples/01-hello-world.hell",
        "linguist-language",
        "Haskell",
        failures,
    );
}

fn parse_checked_attributes(bytes: &[u8]) -> Result<BTreeMap<(String, String), String>, String> {
    let fields = split_nul(bytes).collect::<Vec<_>>();
    if !fields.len().is_multiple_of(3) {
        return Err("git check-attr returned malformed NUL-delimited output".to_owned());
    }
    let mut attributes = BTreeMap::new();
    for record in fields.chunks_exact(3) {
        let path = std::str::from_utf8(record[0])
            .map_err(|_| "git check-attr returned a non-UTF-8 path".to_owned())?;
        let attribute = std::str::from_utf8(record[1])
            .map_err(|_| "git check-attr returned a non-UTF-8 attribute".to_owned())?;
        let value = std::str::from_utf8(record[2])
            .map_err(|_| "git check-attr returned a non-UTF-8 value".to_owned())?;
        attributes.insert((path.to_owned(), attribute.to_owned()), value.to_owned());
    }
    Ok(attributes)
}

fn require_attribute(
    attributes: &BTreeMap<(String, String), String>,
    path: &str,
    attribute: &str,
    expected: &str,
    failures: &mut Vec<String>,
) {
    let key = (path.to_owned(), attribute.to_owned());
    let actual = attributes.get(&key).map_or("unspecified", String::as_str);
    if actual != expected {
        failures.push(format!(
            "checkout attribute {attribute} for {path} is {actual}, expected {expected}"
        ));
    }
}

pub fn normalized_relative_path(value: &str) -> Result<PathBuf, String> {
    if value.is_empty() {
        return Err(format!("path must be nonempty and relative: {value}"));
    }
    let mut normalized = PathBuf::new();
    for part in value.split('/') {
        if part.is_empty()
            || part == "."
            || part == ".."
            || part.contains('\\')
            || part.contains(':')
        {
            return Err(format!("path is not normalized: {value}"));
        }
        normalized.push(part);
    }
    Ok(normalized)
}

fn tracked_files(root: &Path) -> Result<Vec<PathBuf>, String> {
    let output = Command::new("git")
        .args([
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
            "--",
        ])
        .current_dir(root)
        .output()
        .map_err(|error| format!("git ls-files failed to start: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "git ls-files failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    split_nul(&output.stdout)
        .map(|value| {
            String::from_utf8(value.to_vec())
                .map(PathBuf::from)
                .map_err(|_| "tracked path is not UTF-8".to_owned())
        })
        .filter(|path| {
            path.as_ref()
                .map_or(true, |path| !path.starts_with(".serena"))
        })
        .collect()
}

fn tracked_modes(root: &Path) -> Result<BTreeMap<PathBuf, String>, String> {
    let output = Command::new("git")
        .args(["ls-files", "--stage", "-z"])
        .current_dir(root)
        .output()
        .map_err(|error| format!("git ls-files --stage failed to start: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "git ls-files --stage failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let mut modes = BTreeMap::new();
    for record in split_nul(&output.stdout) {
        let text =
            std::str::from_utf8(record).map_err(|_| "git index record is not UTF-8".to_owned())?;
        let (metadata, path) = text
            .split_once('\t')
            .ok_or_else(|| "malformed git index record".to_owned())?;
        let mode = metadata
            .split_whitespace()
            .next()
            .ok_or_else(|| "git index record has no mode".to_owned())?;
        modes.insert(PathBuf::from(path), mode.to_owned());
    }
    Ok(modes)
}

fn split_nul(bytes: &[u8]) -> impl Iterator<Item = &[u8]> {
    bytes
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
}

fn check_tracked_file(root: &Path, path: &Path, mode: Option<&str>, failures: &mut Vec<String>) {
    let display = path.display();
    let extension = path.extension().and_then(|value| value.to_str());
    if matches!(extension, Some("sh" | "bash")) {
        failures.push(format!("shell script is forbidden: {display}"));
    }
    let bytes = match fs::read(root.join(path)) {
        Ok(bytes) => bytes,
        Err(error) => {
            failures.push(format!("cannot read {display}: {error}"));
            return;
        }
    };
    if bytes.is_empty() {
        failures.push(format!("tracked file is empty: {display}"));
        return;
    }
    if bytes.contains(&0) {
        failures.push(format!("tracked file contains NUL: {display}"));
    }
    if bytes.last() != Some(&b'\n') {
        failures.push(format!("tracked file does not end with LF: {display}"));
    }
    // The pinned upstream examples are deliberately byte-for-byte fixtures.
    // Their reviewed trailing spaces predate this repository's convention.
    let pinned_upstream_example = path.starts_with("fixtures/upstream-2026-05-29/examples");
    for (index, line) in bytes.split(|byte| *byte == b'\n').enumerate() {
        if !pinned_upstream_example && line.last().is_some_and(|byte| matches!(byte, b' ' | b'\t'))
        {
            failures.push(format!(
                "tracked file has trailing whitespace at {display}:{}",
                index + 1
            ));
        }
        if line.starts_with(b"<<<<<<< ") || line == b"=======" || line.starts_with(b">>>>>>> ") {
            failures.push(format!(
                "tracked file has a conflict marker at {display}:{}",
                index + 1
            ));
        }
    }
    if mode == Some("100755") && !bytes.starts_with(b"#!") {
        failures.push(format!("executable lacks a shebang: {display}"));
    }
}

fn check_workflows(root: &Path, tracked: &[PathBuf], failures: &mut Vec<String>) {
    for path in tracked.iter().filter(|path| {
        path.parent()
            .is_some_and(|parent| parent == workflow_directory())
            && path.extension().and_then(|value| value.to_str()) == Some("yml")
    }) {
        let text = match fs::read_to_string(root.join(path)) {
            Ok(text) => text,
            Err(error) => {
                failures.push(format!("cannot read {}: {error}", path.display()));
                continue;
            }
        };
        check_workflow(path, &text, failures);
        check_provider_replay_token_binding(path, &text, true, failures);
        check_active_repository_verifier_liveness(path, &text, true, failures);
        check_precredential_provider_selectors(path, &text, true, failures);
    }
}

fn check_workflow(path: &Path, text: &str, failures: &mut Vec<String>) {
    let mut restore_keys = BTreeSet::new();
    let mut save_keys = BTreeSet::new();
    let lines = text.lines().collect::<Vec<_>>();
    check_duplicate_yaml_mapping_keys(path, &lines, failures);
    check_exact_cosign_release(path, &lines, failures);
    check_workflow_dispatch_input_limit(path, &lines, failures);
    check_protected_job_trust_isolation(path, &lines, failures);
    check_transport_probe_sigstore_identity(path, text, failures);
    check_regression_provider_archive_binding(path, &lines, failures);
    check_external_consumer_archive_binding(path, text, failures);
    check_offline_packet_verifier_order(path, &lines, failures);
    check_provider_replay_token_binding(path, text, false, failures);
    check_active_repository_verifier_liveness(path, text, false, failures);
    check_trusted_driver_checkouts(path, text, failures);
    check_campaign_external_handoffs(path, text, failures);
    check_named_workflow_policy(path, text, failures);
    for (index, original) in lines.iter().enumerate() {
        check_workflow_line(
            path,
            &lines,
            index,
            original,
            failures,
            &mut restore_keys,
            &mut save_keys,
        );
    }
    check_cache_key_pairs(path, &restore_keys, &save_keys, failures);
}

fn check_external_consumer_archive_binding(
    path: &Path,
    workflow: &str,
    failures: &mut Vec<String>,
) {
    let name = path.file_name().and_then(|value| value.to_str());
    let Some((header, required, forbidden)) = external_consumer_archive_contract(name) else {
        return;
    };
    if !workflow.starts_with(header) {
        return;
    }
    if required
        .iter()
        .any(|marker| workflow.matches(marker).count() != 1)
        || forbidden.iter().any(|marker| workflow.contains(marker))
    {
        failures.push(format!(
            "external artifact consumer lacks the exact ID/archive/directory contract in {}",
            path.display()
        ));
    }
}

type ExternalConsumerArchiveContract = (
    &'static str,
    &'static [&'static str],
    &'static [&'static str],
);

fn external_consumer_archive_contract(
    name: Option<&str>,
) -> Option<ExternalConsumerArchiveContract> {
    Some(match name {
        Some("artifact-authenticity-review.yml") => (
            "name: Artifact authenticity review",
            &["      source_provider_archive_sha256:"],
            &[],
        ),
        Some("artifact-independent-acquisition.yml") => (
            "name: Independent artifact acquisition",
            &["      source_provider_archive_sha256:"],
            &[],
        ),
        Some("evidence-custody.yml") => (
            "name: Durable evidence custody",
            &["      provider_archive_sha256:"],
            &[],
        ),
        Some("claim-applicability-decisions.yml") => (
            "name: Package externally authored claim applicability decisions",
            &["      native_provider_archive_sha256:"],
            &[],
        ),
        Some("promotion-evidence-review.yml") => (
            "name: Generate and review promotion evidence",
            &[
                "      provider_archive_sha256_json:",
                "description: Exact canonical provider archive digests for all five evidence sources",
            ],
            &[
                "      oracle_event:",
                "      native_provider_archive_sha256:",
                "      acquisition_provider_archive_sha256:",
                "      mutation_provider_archive_sha256:",
                "      oracle_macos_provider_archive_sha256:",
                "      oracle_windows_provider_archive_sha256:",
            ],
        ),
        Some("promotion-approval.yml" | "nightly.yml") => (
            if name == Some("nightly.yml") {
                "name: Nightly"
            } else {
                "name: Promotion proposal approval"
            },
            &["      proposal_provider_archive_sha256:"],
            &[],
        ),
        Some("promotion-proposal.yml") => (
            "name: Promotion proposal assembly",
            &[
                "      evidence_provider_archive_sha256:",
                "      review_provider_archive_sha256:",
                "      custody_provider_archive_sha256:",
                "      primary_scrub_digests:",
                "      secondary_scrub_digests:",
            ],
            &[
                "      primary_scrub_provider_archive_sha256:",
                "      secondary_scrub_provider_archive_sha256:",
            ],
        ),
        Some("artifact-authenticity-finalize.yml") => (
            "name: Artifact authenticity finalization",
            &[
                "      primary_packet_archive_sha256:",
                "      independent_review_archive_sha256:",
            ],
            &[],
        ),
        Some("collection-activation-preparation.yml") => (
            "name: Collection Activation Preparation",
            &["      expected_archive_sha256:"],
            &[],
        ),
        Some("collection-activation.yml") => (
            "name: Collection Activation Review",
            &["      proposal_archive_sha256:"],
            &[],
        ),
        Some("collection-custody-integration.yml") => (
            "name: Collection Custody Integration",
            &[
                "      worm_source_run_attempt:",
                "      expected_worm_archive_sha256:",
                "COLLECTION_WORM_ARCHIVE_SHA256: ${{ inputs.expected_worm_archive_sha256 }}",
                "COLLECTION_WORM_ARTIFACT_ID: ${{ inputs.worm_artifact_id }}",
            ],
            &[],
        ),
        _ => return None,
    })
}

fn check_regression_provider_archive_binding(
    path: &Path,
    lines: &[&str],
    failures: &mut Vec<String>,
) {
    for (index, line) in lines.iter().enumerate() {
        if !line.contains("regression-import select-subject") {
            continue;
        }
        let start = lines[..index]
            .iter()
            .rposition(|line| line.trim_start().starts_with("- name:") || line.trim() == "- uses:")
            .unwrap_or(0);
        let count = lines[start..index]
            .iter()
            .filter(|line| {
                line.trim_start()
                    .starts_with("REGRESSION_PROVIDER_ARCHIVE_SHA256: ")
            })
            .count();
        if count != 1 {
            failures.push(format!(
                "regression provider replay lacks one expected archive digest at {}:{}",
                path.display(),
                index + 1
            ));
        }
    }
}

fn check_named_workflow_policy(path: &Path, text: &str, failures: &mut Vec<String>) {
    check_selector_seal_caller(path, text, failures);
    match path.file_name().and_then(|value| value.to_str()) {
        Some("regression-subject.yml") => {
            check_automatic_regression_batch_transaction(text, failures);
        }
        Some("regression-corpus.yml") => {
            check_automatic_regression_child_isolation(text, failures);
        }
        Some("nightly.yml") => check_fresh_activated_campaign_liveness(text, failures),
        Some(
            "evidence-custody.yml"
            | "promotion-surveillance.yml"
            | "promotion-initial-public-finalize.yml",
        ) => {
            check_selector_update_barrier_topology(path, text, failures);
        }
        Some("custody-provider-selector-recovery.yml") => {
            check_selector_recovery_workflow(text, failures);
        }
        Some("custody-provider-selector-seal.yml") => {
            check_selector_seal_workflow(text, failures);
        }
        Some("claim-applicability-decisions.yml") => {
            check_claim_applicability_decision_checkouts(text, failures);
        }
        Some("artifact-authenticity-review.yml") => {
            check_primary_acquisition_checkout(text, failures);
        }
        Some("promotion-proposal.yml" | "promotion-approval.yml") => {
            check_promotion_package_handoff(path, text, failures);
        }
        _ => {}
    }
}

fn check_selector_seal_caller(path: &Path, workflow: &str, failures: &mut Vec<String>) {
    let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
        return;
    };
    let (header, expected) = match name {
        "custody-provider-selector-recovery.yml" => (
            "name: Recover custody provider selectors",
            format!(
                "uses: ./.github/workflows/custody-provider-selector-seal.yml\n    with:\n      source_workflow: .github/workflows/{name}"
            ),
        ),
        "evidence-custody.yml" => (
            "name: Durable evidence custody",
            format!(
                "uses: ./.github/workflows/custody-provider-selector-seal.yml\n    with:\n      source_workflow: .github/workflows/{name}"
            ),
        ),
        "promotion-surveillance.yml" => (
            "name: Promotion surveillance",
            format!(
                "uses: ./.github/workflows/custody-provider-selector-seal.yml\n    with:\n      source_workflow: .github/workflows/{name}"
            ),
        ),
        "promotion-surveillance-watchdog.yml" => (
            "name: Promotion surveillance watchdog",
            format!(
                "uses: ./.github/workflows/custody-provider-selector-seal.yml\n    with:\n      source_workflow: .github/workflows/{name}"
            ),
        ),
        "promotion-initial-public-finalize.yml" => (
            "name: Initial public promotion finalizer",
            format!(
                "uses: ./.github/workflows/custody-provider-selector-seal.yml\n    with:\n      source_workflow: .github/workflows/{name}"
            ),
        ),
        _ => return,
    };
    if workflow.starts_with(header) && workflow.matches(&expected).count() != 1 {
        failures.push(format!(
            "provider selector seal caller does not bind its exact source workflow in {}",
            path.display()
        ));
    }
}

fn check_workflow_line(
    path: &Path,
    lines: &[&str],
    index: usize,
    original: &str,
    failures: &mut Vec<String>,
    restore_keys: &mut BTreeSet<String>,
    save_keys: &mut BTreeSet<String>,
) {
    let line = strip_yaml_comment(original).trim();
    let entry = line.strip_prefix("- ").unwrap_or(line);
    if line.is_empty() {
        return;
    }
    let location = format!("{}:{}", path.display(), index + 1);
    if yaml_key(entry, "shell").is_some() {
        failures.push(format!("workflow shell key is forbidden at {location}"));
    }
    if yaml_key(entry, "queue").is_some() {
        failures.push(format!(
            "unsupported workflow concurrency queue key at {location}"
        ));
    }
    if yaml_key(entry, "env").is_some() && !reviewed_workflow_env(path, lines, index, original) {
        failures.push(format!("workflow env key is forbidden at {location}"));
    }
    if yaml_key(entry, "pull_request").is_some() || yaml_key(entry, "pull_request_target").is_some()
    {
        failures.push(format!("pull request trigger is forbidden at {location}"));
    }
    if yaml_key(entry, "branches").is_some() {
        failures.push(format!(
            "branch-filtered workflow trigger is forbidden at {location}"
        ));
    }
    if let Some(run) = yaml_key(entry, "run") {
        check_run_value(run.trim(), &location, failures);
    }
    if let Some(uses) = yaml_key(entry, "uses") {
        check_uses_value(uses.trim(), &location, failures);
        if uses.contains("actions/checkout@")
            && following_value(lines, index, "persist-credentials") != Some("false")
        {
            failures.push(format!("checkout persists credentials at {location}"));
        }
        if uses.contains("actions/cache/restore@")
            && let Some(key) = following_value(lines, index, "key")
        {
            restore_keys.insert(key.to_owned());
        }
        if uses.contains("actions/cache/restore@") || uses.contains("actions/cache/save@") {
            check_cache_scope(path, lines, index, &location, failures);
        }
        if uses.contains("actions/cache/save@") {
            let condition = preceding_value(lines, index, "if");
            if !condition.is_some_and(|value| value.contains("always()")) {
                failures.push(format!("cache save lacks always() at {location}"));
            }
            if let Some(key) = following_value(lines, index, "key") {
                save_keys.insert(key.to_owned());
            }
        }
    }
}

fn check_cache_key_pairs(
    path: &Path,
    restore_keys: &BTreeSet<String>,
    save_keys: &BTreeSet<String>,
    failures: &mut Vec<String>,
) {
    if !save_keys.is_subset(restore_keys) {
        failures.push(format!(
            "cache save key has no identical restore key in {}",
            path.display()
        ));
    }
}

fn check_exact_cosign_release(path: &Path, lines: &[&str], failures: &mut Vec<String>) {
    const INSTALLER: &str =
        "uses: sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6";
    for (index, line) in lines.iter().enumerate() {
        if strip_yaml_comment(line).trim() != INSTALLER {
            continue;
        }
        if lines.get(index + 1).map(|line| line.trim()) != Some("with:")
            || lines.get(index + 2).map(|line| line.trim()) != Some("cosign-release: v2.4.3")
        {
            failures.push(format!(
                "Cosign installer lacks exact executable release v2.4.3 at {}:{}",
                path.display(),
                index + 1
            ));
        }
    }
}

fn check_selector_recovery_workflow(workflow: &str, failures: &mut Vec<String>) {
    let required = [
        "name: Recover custody provider selectors",
        "if: ${{ github.ref == 'refs/heads/main' }}",
        "environment: ${{ matrix.environment }}",
        "provider: primary-worm",
        "trust-domain: organization-primary",
        "provider-selector-variable: CUSTODY_PRIMARY_PROVIDER_SELECTOR",
        "provider: secondary-worm",
        "trust-domain: organization-secondary",
        "provider-selector-variable: CUSTODY_SECONDARY_PROVIDER_SELECTOR",
        "CUSTODY_PROVIDER_OPERATION: selector-export",
        "run: ./target/ci/hell-ci custody-ops workflow-prepare-provider-selector",
        "run: ./target/ci/hell-ci custody-ops workflow-export-provider-selector",
        "uses: ./.github/workflows/custody-provider-selector-seal.yml",
    ];
    let forbidden = [
        "workflow-upload",
        "workflow-activate",
        "workflow-commit-activation",
        "workflow-publish-transition",
        "workflow-complete-initial-activation",
        "s3api",
        "put-object",
        "delete-object",
    ];
    let export = workflow_job_lines(workflow, "export").map(|lines| lines.join("\n"));
    let ordered = [
        "run: ./target/ci/hell-ci collection-authority verify-checkout",
        "run: ./target/ci/hell-ci custody-ops workflow-prepare-provider-selector",
        "uses: aws-actions/configure-aws-credentials@e6de054238d6b7531b4efff3b6587d9aade6a06c # v6.2.3",
        "run: ./target/ci/hell-ci custody-ops workflow-export-provider-selector",
    ];
    if required
        .iter()
        .any(|value| workflow.matches(value).count() != 1)
        || forbidden.iter().any(|value| workflow.contains(value))
        || export
            .as_deref()
            .is_none_or(|body| !markers_are_ordered(body, &ordered))
    {
        failures.push(
            "custody provider selector recovery is not exact, read-only, and precredential-bound"
                .to_owned(),
        );
    }
}

fn check_selector_seal_workflow(workflow: &str, failures: &mut Vec<String>) {
    let required = [
        "name: Seal custody provider selector updates",
        "source_workflow:",
        "CUSTODY_SELECTOR_SOURCE_WORKFLOW: ${{ inputs.source_workflow }}",
        "GITHUB_TOKEN: ${{ github.token }}",
        "run: ./target/ci/hell-ci custody-ops workflow-select-provider-selector-updates",
        "artifact_id: ${{ steps.upload.outputs.artifact-id }}",
        "artifact_digest: ${{ steps.upload.outputs.artifact-digest }}",
        "directory_sha256: ${{ steps.bind.outputs.directory_sha256 }}",
        "artifact-ids: ${{ steps.select.outputs.primary-artifact-id }}",
        "artifact-ids: ${{ steps.select.outputs.secondary-artifact-id }}",
        "run: ./target/ci/hell-ci custody-ops workflow-assemble-provider-selector-updates",
        "run: ./target/ci/hell-ci regression-import emit-directory-output --input ci-out/provider-selector-updates",
        "name: custody-provider-selectors-${{ github.run_id }}-${{ github.run_attempt }}",
    ];
    let seal = workflow_job_lines(workflow, "seal").map(|lines| lines.join("\n"));
    let ordered = [
        "run: ./target/ci/hell-ci collection-authority verify-checkout",
        "run: ./target/ci/hell-ci custody-ops workflow-select-provider-selector-updates",
        "artifact-ids: ${{ steps.select.outputs.primary-artifact-id }}",
        "artifact-ids: ${{ steps.select.outputs.secondary-artifact-id }}",
        "run: ./target/ci/hell-ci custody-ops workflow-assemble-provider-selector-updates",
        "id: bind",
        "id: upload",
    ];
    if required
        .iter()
        .any(|value| workflow.matches(value).count() != 1)
        || workflow.contains("id-token: write")
        || workflow.contains("environment:")
        || seal
            .as_deref()
            .is_none_or(|body| !markers_are_ordered(body, &ordered))
    {
        failures.push(
            "custody provider selector sealer lacks an exact unprivileged two-provider triple"
                .to_owned(),
        );
    }
}

fn check_selector_update_barrier_topology(path: &Path, workflow: &str, failures: &mut Vec<String>) {
    let expected_header = match path.file_name().and_then(|value| value.to_str()) {
        Some("evidence-custody.yml") => "name: Durable evidence custody",
        Some("promotion-surveillance.yml") => "name: Promotion surveillance",
        Some("promotion-initial-public-finalize.yml") => "name: Initial public promotion finalizer",
        _ => return,
    };
    if !workflow.starts_with(expected_header) {
        return;
    }
    let valid = match path.file_name().and_then(|value| value.to_str()) {
        Some("evidence-custody.yml") => {
            !workflow.contains("dispatch-initial-public-state:")
                && !workflow.contains("workflow-dispatch-initial-surveillance")
                && workflow.contains("  seal-provider-selector-updates:")
        }
        Some("promotion-surveillance.yml") => {
            let required = [
                "if: ${{ github.ref == 'refs/heads/main' && (github.event_name != 'workflow_dispatch' || (inputs.candidate_sha == github.sha && inputs.selector_source_sha == github.sha)) }}",
                "selector_run_id:",
                "selector_run_attempt:",
                "selector_artifact_id:",
                "selector_archive_sha256:",
                "selector_directory_sha256:",
                "selector_source_sha:",
                "name: Download exact activated provider selector aggregate\n        if: ${{ github.event_name == 'workflow_dispatch' }}",
                "artifact-ids: ${{ inputs.selector_artifact_id }}",
                "name: Verify activated provider selector update barrier before credentials\n        if: ${{ github.event_name == 'workflow_dispatch' }}",
                "CUSTODY_SELECTOR_AGGREGATE_WORKFLOW: .github/workflows/evidence-custody.yml",
                "run: ./target/ci/hell-ci custody-ops workflow-verify-provider-selector-update-barrier",
            ];
            required
                .iter()
                .all(|value| workflow.matches(value).count() >= 1)
        }
        Some("promotion-initial-public-finalize.yml") => {
            let required = [
                "if: ${{ github.ref == 'refs/heads/main' && inputs.selector_source_sha == github.sha }}",
                "workflow_dispatch:",
                "surveillance_run_id:",
                "surveillance_run_attempt:",
                "selector_artifact_id:",
                "selector_archive_sha256:",
                "selector_directory_sha256:",
                "selector_source_sha:",
                "artifact-ids: ${{ inputs.selector_artifact_id }}",
                "CUSTODY_SELECTOR_AGGREGATE_WORKFLOW: .github/workflows/promotion-surveillance.yml",
                "run: ./target/ci/hell-ci custody-ops workflow-verify-provider-selector-update-barrier",
            ];
            required
                .iter()
                .all(|value| workflow.matches(value).count() >= 1)
                && !workflow.contains("workflow_run:")
                && !workflow.contains("github.event.workflow_run")
        }
        _ => unreachable!("workflow filename was checked above"),
    };
    if !valid {
        failures.push(format!(
            "initial public custody phases lack an exact selector-update barrier in {}",
            path.display()
        ));
    }
}

fn check_active_repository_verifier_liveness(
    path: &Path,
    workflow: &str,
    require_jobs: bool,
    failures: &mut Vec<String>,
) {
    let jobs: &[(&str, &str)] = match path.file_name().and_then(|value| value.to_str()) {
        Some("ci.yml") => &[
            ("verify", "hell-ci assurance-verify"),
            ("portability-macos", "hell-ci portability"),
            ("portability-windows", "hell-ci.exe portability"),
        ],
        Some("nightly.yml") => &[
            ("evidence-collection-linux", "hell-ci nightly --oracle"),
            (
                "branch-evidence-collection-linux",
                "hell-ci nightly-exploratory --oracle",
            ),
            ("native-oracle-macos", "hell-ci native-oracle-shard"),
            ("native-oracle-windows", "hell-ci.exe native-oracle-shard"),
            ("merge-native-evidence", "hell-ci merge-native-shards"),
            (
                "branch-merge-native-evidence",
                "hell-ci merge-native-shards",
            ),
            ("promotion-gate", "hell-ci promotion-gate"),
        ],
        Some("oracle-reproduce.yml") => &[("primary-build", "hell-ci native-oracle-shard")],
        Some("promotion-proposal.yml") => &[("assemble", "hell-ci promotion-proposal")],
        Some("promotion-evidence-review.yml") => &[("assemble", "hell-ci case-coverage report")],
        Some("claim-applicability-decisions.yml") => &[("package", "hell-ci case-coverage report")],
        Some("promotion-surveillance.yml") => &[
            (
                "execute-active-subject",
                "hell-ci nightly-surveillance-subject",
            ),
            ("verify-and-transition", "hell-ci assurance-verify"),
        ],
        Some("evidence-custody.yml") => &[("package", "hell-ci assurance-verify")],
        Some("artifact-authenticity-review.yml") => {
            &[("acquisition-packet", "hell-ci assurance-verify")]
        }
        _ => return,
    };
    for (job, boundary) in jobs {
        let Some(lines) = workflow_job_lines(workflow, job) else {
            if require_jobs {
                failures.push(format!(
                    "active repository verifier job {job:?} is missing from {}",
                    path.display()
                ));
            }
            continue;
        };
        let installer = lines
            .iter()
            .enumerate()
            .filter_map(|(index, line)| (workflow_entry(line) == COSIGN_INSTALLER).then_some(index))
            .collect::<Vec<_>>();
        let consumer = lines.iter().position(|line| line.contains(boundary));
        if !matches!((installer.as_slice(), consumer), ([install], Some(consumer)) if *install < consumer)
        {
            failures.push(format!(
                "active repository verifier job {job:?} must install the exact pinned Cosign verifier once before {boundary:?} in {}",
                path.display()
            ));
        }
        if path == workflow_path("evidence-custody.yml")
            && installer.first().is_none_or(|index| {
                preceding_value(&lines, *index, "if")
                    != Some("${{ inputs.artifact_class != 'collection-custody' }}")
            })
        {
            failures.push(
                "evidence custody active-review verifier condition differs from its active repository consumer"
                    .to_owned(),
            );
        }
    }
}

fn check_claim_applicability_decision_checkouts(workflow: &str, failures: &mut Vec<String>) {
    let Some(lines) = workflow_job_lines(workflow, "package") else {
        failures.push("claim applicability decision package job is missing".to_owned());
        return;
    };
    let required = [
        "run: cargo build --locked --profile ci --package hell-ci --bin hell-ci",
        "run: ./target/ci/hell-ci collection-authority verify-checkout --input . --candidate-commit \"$CLAIM_CANDIDATE_SHA\"",
        "run: ./target/ci/hell-ci collection-authority verify-checkout --input decision-source --candidate-commit \"$CLAIM_DECISION_SOURCE_SHA\"",
        COSIGN_INSTALLER,
        "run: ./target/ci/hell-ci case-coverage report --input ci-out/evidence/native --output ci-out/evidence/claim-decisions/source/claim-coverage.details.json",
        "GITHUB_TOKEN: ${{ github.token }}",
        "run: ./target/ci/hell-ci case-coverage prepare-decisions --input ci-out/evidence/claim-decisions/source/claim-coverage.details.json --from decision-source/compat/reviews/claim-applicability-decisions.json --output ci-out/evidence/claim-decisions/claim-applicability-decisions.json --github-dispatch-inputs",
    ];
    if required.iter().any(|marker| {
        lines
            .iter()
            .filter(|line| workflow_entry(line) == *marker)
            .count()
            != 1
    }) || required.windows(2).any(|pair| {
        let first = lines
            .iter()
            .position(|line| workflow_entry(line) == pair[0]);
        let second = lines
            .iter()
            .position(|line| workflow_entry(line) == pair[1]);
        !matches!((first, second), (Some(first), Some(second)) if first < second)
    }) {
        failures.push(
            "claim applicability decisions must verify both exact checkouts and install the pinned verifier before deriving scoped coverage"
                .to_owned(),
        );
    }
}

fn check_primary_acquisition_checkout(workflow: &str, failures: &mut Vec<String>) {
    let Some(lines) = workflow_job_lines(workflow, "acquisition-packet") else {
        failures.push("primary artifact acquisition packet job is missing".to_owned());
        return;
    };
    let body = lines.join("\n");
    let required = [
        "if: ${{ github.ref == 'refs/heads/main' && inputs.candidate_sha == github.sha }}",
        "ref: ${{ github.sha }}",
        "run: cargo build --locked --profile ci --package hell-ci --bin hell-ci",
        "ACQUISITION_CANDIDATE_SHA: ${{ inputs.candidate_sha }}",
        "run: ./target/ci/hell-ci collection-authority verify-checkout --input . --candidate-commit \"$ACQUISITION_CANDIDATE_SHA\"",
        "run: ./target/ci/hell-ci assurance-verify --report ci-out/assurance-policy.json",
        "Download producing-run evidence after building the verifier",
        "artifact-ids: ${{ inputs.source_artifact_id }}",
        "run: ./target/ci/hell-ci artifact-acquire primary --input ci-out/acquisition/primary --output ci-out/acquisition/receipt-primary.json --artifact native-oracle-merged --github-dispatch-inputs",
    ];
    if required
        .iter()
        .any(|marker| body.matches(marker).count() != 1)
        || !markers_are_ordered(&body, &required)
    {
        failures.push(
            "primary artifact acquisition does not bind provider workflow bytes to exact candidate HEAD"
                .to_owned(),
        );
    }
}

fn check_promotion_package_handoff(path: &Path, workflow: &str, failures: &mut Vec<String>) {
    let Some((header, job, outputs, ordered)) = (match path
        .file_name()
        .and_then(|value| value.to_str())
    {
        Some("promotion-proposal.yml") => Some((
            "name: Promotion proposal assembly",
            "assemble",
            [
                "proposal_artifact_id: ${{ steps.upload-proposal.outputs.artifact-id }}",
                "proposal_artifact_digest: ${{ steps.upload-proposal.outputs.artifact-digest }}",
                "proposal_directory_sha256: ${{ steps.bind-proposal.outputs.directory_sha256 }}",
            ],
            [
                "run: cargo build --locked --profile ci --package hell-ci --bin hell-ci",
                "run: ./target/ci/hell-ci collection-authority verify-checkout --input . --candidate-commit \"$PROMOTION_CANDIDATE_SHA\"",
                "run: ./target/ci/hell-ci promotion-proposal --input ci-out/native-shards --output ci-out/native-shards/promotion-proposal.json --github-dispatch-inputs",
                "id: bind-proposal",
                "run: ./target/ci/hell-ci regression-import emit-directory-output --input ci-out/native-shards",
                "id: upload-proposal",
                "name: promotion-proposal",
                "path: ci-out/native-shards",
            ],
        )),
        Some("promotion-approval.yml") => Some((
            "name: Promotion proposal approval",
            "approve",
            [
                "approved_artifact_id: ${{ steps.upload-approved.outputs.artifact-id }}",
                "approved_artifact_digest: ${{ steps.upload-approved.outputs.artifact-digest }}",
                "approved_directory_sha256: ${{ steps.bind-approved.outputs.directory_sha256 }}",
            ],
            [
                "run: cargo build --locked --profile ci --package hell-ci --bin hell-ci",
                "run: ./target/ci/hell-ci collection-authority verify-checkout --input . --candidate-commit \"$PROMOTION_CANDIDATE_SHA\"",
                "run: ./target/ci/hell-ci promotion-approval-subject --input ci-out/native-shards/promotion-proposal.json --output ci-out/native-shards/promotion-approval-subject.json",
                "run: ./target/ci/hell-ci review-verify --input ci-out/native-shards/promotion-proposal-approval.dsse.json --policy ci-out/native-shards/reviewer.allowed_signers --role promotion-approver",
                "id: bind-approved",
                "run: ./target/ci/hell-ci regression-import emit-directory-output --input ci-out/native-shards",
                "id: upload-approved",
                "name: promotion-approved-proposal",
            ],
        )),
        _ => None,
    }) else {
        return;
    };
    let Some(lines) = workflow_job_lines(workflow, job) else {
        if workflow.starts_with(header) {
            failures.push(format!(
                "promotion package handoff job {job:?} is missing from {}",
                path.display()
            ));
        }
        return;
    };
    let body = lines.join("\n");
    if outputs
        .iter()
        .any(|marker| body.matches(marker).count() != 1)
        || !markers_are_ordered(&body, &ordered)
        || body.matches("if-no-files-found: error").count() != 1
        || body.matches("retention-days: 30").count() != 1
    {
        failures.push(format!(
            "promotion package handoff is not bound to one immutable artifact and canonical directory digest in {}",
            path.display()
        ));
    }
}

fn trusted_driver_jobs(
    path: &Path,
) -> Option<(&'static str, &'static [(&'static str, &'static str)])> {
    Some(match path.file_name().and_then(|value| value.to_str()) {
        Some("nightly.yml") => (
            "name: Nightly",
            &[("promotion-gate", "workflow-verify-approved-source")],
        ),
        Some("promotion-initial-public-finalize.yml") => (
            "name: Initial public promotion finalizer",
            &[
                (
                    "finalize-completed-publication",
                    "workflow-finalize-initial-surveillance",
                ),
                (
                    "complete-provider-activation",
                    "aws-actions/configure-aws-credentials@",
                ),
            ],
        ),
        Some("promotion-surveillance.yml") => (
            "name: Promotion surveillance",
            &[
                ("retrieve-active", "aws-actions/configure-aws-credentials@"),
                (
                    "execute-active-subject",
                    "Download primary active provider evidence",
                ),
                (
                    "verify-and-transition",
                    "workflow-retain-current-governance",
                ),
                (
                    "publish-current-state",
                    "Download signed surveillance transition",
                ),
                (
                    "publish-public-report",
                    "Download signed surveillance transition for public report",
                ),
                ("incident-alert", "workflow-alert"),
            ],
        ),
        Some("evidence-custody.yml") => (
            "name: Durable evidence custody",
            &[
                (
                    "activate-final-record",
                    "custody verify --input ci-out/custody/custody-receipt.json",
                ),
                (
                    "seal-current-scrubs",
                    "Download exact current-run primary scrub package",
                ),
            ],
        ),
        Some("promotion-surveillance-watchdog.yml") => (
            "name: Promotion surveillance watchdog",
            &[
                ("retrieve-active", "aws-actions/configure-aws-credentials@"),
                ("deadline", "workflow-observe-public-transition"),
                (
                    "publish-at-risk-state",
                    "Download exact signed watchdog transition",
                ),
                (
                    "publish-public-at-risk-report",
                    "Download exact watchdog transition for public report",
                ),
            ],
        ),
        Some("custody-scrub.yml") => (
            "name: Custody scrub and recovery",
            &[("scrub", "aws-actions/configure-aws-credentials@")],
        ),
        Some("mutation.yml") => (
            "name: Assurance mutation",
            &[("review", "Download exact mutation review subject")],
        ),
        Some("artifact-authenticity-finalize.yml") => (
            "name: Finalize artifact authenticity",
            &[("finalize", "Download exact pre-review subject")],
        ),
        Some("oracle-reproduce.yml") => (
            "name: Oracle reproducibility evidence",
            &[(
                "seal-reviewed-platform-evidence",
                "Download exact current-run macOS reviewed evidence",
            )],
        ),
        _ => return None,
    })
}

fn check_trusted_driver_checkouts(path: &Path, workflow: &str, failures: &mut Vec<String>) {
    let Some((header, expected)) = trusted_driver_jobs(path) else {
        return;
    };
    let complete = workflow.starts_with(header);
    let verify = "run: ./target/ci/hell-ci collection-authority verify-checkout --input . --candidate-commit \"$TRUSTED_DRIVER_SHA\"";
    for (job, boundary) in expected {
        let Some(lines) = workflow_job_lines(workflow, job) else {
            if complete {
                failures.push(format!(
                    "trusted-driver job {job:?} is missing from {}",
                    path.display()
                ));
            }
            continue;
        };
        let body = lines.join("\n");
        let order = [
            "ref: ${{ github.sha }}",
            "run: cargo build --locked --profile ci --package hell-ci --bin hell-ci",
            "TRUSTED_DRIVER_SHA: ${{ github.sha }}",
            verify,
            boundary,
        ];
        if order.iter().any(|marker| body.matches(marker).count() != 1)
            || !markers_are_ordered(&body, &order)
        {
            failures.push(format!(
                "trusted-driver job {job:?} does not bind exact current HEAD before {boundary:?} in {}",
                path.display()
            ));
        }
    }
    if path == workflow_path("nightly.yml")
        && (complete || workflow_job_lines(workflow, "promotion-gate").is_some())
        && !workflow.contains("inputs.candidate_sha == github.sha")
    {
        failures.push(
            "promotion gate must bind the approved provider workflow source to current exact candidate HEAD"
                .to_owned(),
        );
    }
    if path == workflow_path("promotion-surveillance.yml") {
        check_surveillance_active_checkout(workflow, failures);
    }
    check_precredential_provider_selectors(path, workflow, false, failures);
}

fn check_precredential_provider_selectors(
    path: &Path,
    workflow: &str,
    require_jobs: bool,
    failures: &mut Vec<String>,
) {
    let jobs = provider_selector_jobs(path);
    if jobs.is_empty() {
        return;
    }
    let mut found_job = false;
    for (job, consumer, operation, source) in jobs {
        let Some(lines) = workflow_job_lines(workflow, job) else {
            if require_jobs {
                failures.push(format!(
                    "protected provider job {job:?} is missing from {}",
                    path.display()
                ));
            }
            continue;
        };
        found_job = true;
        check_provider_selector_job(
            path,
            &lines.join("\n"),
            job,
            consumer,
            operation,
            source,
            failures,
        );
    }
    if found_job || require_jobs {
        check_provider_selector_matrix(path, workflow, failures);
    }
    check_public_publication_preflight(path, workflow, require_jobs, failures);
}

fn check_public_publication_preflight(
    path: &Path,
    workflow: &str,
    require_jobs: bool,
    failures: &mut Vec<String>,
) {
    let job = match path.file_name().and_then(|value| value.to_str()) {
        Some("promotion-surveillance.yml") => "publish-public-report",
        Some("promotion-surveillance-watchdog.yml") => "publish-public-at-risk-report",
        _ => return,
    };
    let Some(lines) = workflow_job_lines(workflow, job) else {
        if require_jobs {
            failures.push(format!(
                "public publication job {job:?} is missing from {}",
                path.display()
            ));
        }
        return;
    };
    let body = lines.join("\n");
    let prepare =
        "run: ./target/ci/hell-ci custody-ops workflow-prepare-public-publication-selector";
    let ordered = [
        prepare,
        "uses: aws-actions/configure-aws-credentials@e6de054238d6b7531b4efff3b6587d9aade6a06c # v6.2.3",
        "run: ./target/ci/hell-ci custody-ops workflow-publish-public-transition",
    ];
    if body.matches(prepare).count() != 1
        || body.matches("PUBLIC_COMPATIBILITY_REPORT_BUCKET: ${{ vars.PUBLIC_COMPATIBILITY_REPORT_BUCKET }}").count() != 2
        || body.matches("PUBLIC_COMPATIBILITY_REPORT_BASE_URL: ${{ vars.PUBLIC_COMPATIBILITY_REPORT_BASE_URL }}").count() != 2
        || !markers_are_ordered(&body, &ordered)
    {
        failures.push(format!(
            "public publication job {job:?} does not seal its exact destination before credentials in {}",
            path.display()
        ));
    }
}

fn provider_selector_jobs(
    path: &Path,
) -> Vec<(&'static str, &'static str, &'static str, &'static str)> {
    let jobs: &[(&str, &str, &str, &str)] = match path.file_name().and_then(|value| value.to_str())
    {
        Some("custody-scrub.yml") => &[("scrub", "workflow-scrub", "maintenance", "active")],
        Some("promotion-surveillance.yml") => &[
            (
                "retrieve-active",
                "workflow-surveillance-retrieve",
                "surveillance",
                "active",
            ),
            (
                "publish-current-state",
                "workflow-publish-transition",
                "transition-publication",
                "active",
            ),
        ],
        Some("promotion-surveillance-watchdog.yml") => &[
            (
                "retrieve-active",
                "workflow-surveillance-retrieve",
                "surveillance",
                "active",
            ),
            (
                "publish-at-risk-state",
                "workflow-publish-transition",
                "transition-publication",
                "active",
            ),
        ],
        Some("promotion-initial-public-finalize.yml") => &[(
            "complete-provider-activation",
            "workflow-complete-initial-activation",
            "complete-initial-publication",
            "active",
        )],
        Some("evidence-custody.yml") => &[
            ("upload", "workflow-upload", "upload", "provider"),
            ("retrieve", "workflow-retrieve", "retrieval", "derived"),
            (
                "activate-final-record",
                "workflow-activate",
                "activation",
                "active",
            ),
        ],
        _ => &[],
    };
    jobs.to_vec()
}

fn check_provider_selector_job(
    path: &Path,
    body: &str,
    job: &str,
    consumer: &str,
    operation: &str,
    source: &str,
    failures: &mut Vec<String>,
) {
    let prepare = if source == "derived" {
        "run: ./target/ci/hell-ci custody-ops workflow-verify-upload-subject"
    } else {
        "run: ./target/ci/hell-ci custody-ops workflow-prepare-provider-selector"
    };
    let ordered = [
        prepare,
        "uses: aws-actions/configure-aws-credentials@e6de054238d6b7531b4efff3b6587d9aade6a06c # v6.2.3",
        consumer,
    ];
    if body.matches(prepare).count() != 1 || !markers_are_ordered(body, &ordered) {
        failures.push(format!(
                "protected provider job {job:?} does not seal exact provider inputs before credentials in {}",
                path.display()
            ));
    }
    if consumer == "workflow-complete-initial-activation"
            && body
                .matches("artifact-ids: ${{ needs.finalize-completed-publication.outputs.completion_artifact_id }}")
                .count()
                != 1
        {
            failures.push(format!(
                "protected provider job {job:?} does not consume the exact immutable completion artifact in {}",
                path.display()
            ));
        }
    let selector = match source {
        "active" => {
            Some("ACTIVE_CUSTODY_PROVIDER_SELECTOR: ${{ vars[matrix.default-receipt-variable] }}")
        }
        "provider" => {
            Some("ACTIVE_CUSTODY_PROVIDER_SELECTOR: ${{ vars[matrix.provider-selector-variable] }}")
        }
        _ => None,
    };
    if selector.is_some_and(|selector| body.matches(selector).count() != 1)
        || (source != "derived"
            && body
                .matches(&format!("CUSTODY_PROVIDER_OPERATION: {operation}"))
                .count()
                != 1)
        || body
            .matches("CUSTODY_EXPECTED_PROVIDER: ${{ matrix.provider }}")
            .count()
            != 1
        || body
            .matches("CUSTODY_EXPECTED_TRUST_DOMAIN: ${{ matrix.trust-domain }}")
            .count()
            != 1
    {
        failures.push(format!(
                "protected provider job {job:?} does not bind its exact maintenance selector identity in {}",
                path.display()
            ));
    }
}

fn check_provider_selector_matrix(path: &Path, workflow: &str, failures: &mut Vec<String>) {
    let (active_repetitions, trust_repetitions) =
        match path.file_name().and_then(|value| value.to_str()) {
            Some(
                "custody-scrub.yml"
                | "promotion-surveillance.yml"
                | "promotion-surveillance-watchdog.yml",
            ) => (2, 2),
            Some("promotion-initial-public-finalize.yml") => (1, 1),
            Some("evidence-custody.yml") => (1, 3),
            _ => return,
        };
    for value in [
        "default-receipt-variable: ACTIVE_CUSTODY_PRIMARY_UPLOAD_RECEIPT",
        "default-receipt-variable: ACTIVE_CUSTODY_SECONDARY_UPLOAD_RECEIPT",
    ] {
        if workflow.matches(value).count() != active_repetitions {
            failures.push(format!(
                "protected provider selector matrix does not contain exact {value:?} entries in {}",
                path.display()
            ));
        }
    }
    for value in [
        "trust-domain: organization-primary",
        "trust-domain: organization-secondary",
    ] {
        if workflow.matches(value).count() != trust_repetitions {
            failures.push(format!(
                "protected provider selector matrix does not contain exact {value:?} entries in {}",
                path.display()
            ));
        }
    }
    if path == workflow_path("evidence-custody.yml") {
        for value in [
            "provider-selector-variable: CUSTODY_PRIMARY_PROVIDER_SELECTOR",
            "provider-selector-variable: CUSTODY_SECONDARY_PROVIDER_SELECTOR",
        ] {
            if workflow.matches(value).count() != 1 {
                failures.push(format!(
                    "protected provider selector matrix does not contain exact {value:?} entries in {}",
                    path.display()
                ));
            }
        }
    }
}

fn check_surveillance_active_checkout(workflow: &str, failures: &mut Vec<String>) {
    let Some(lines) = workflow_job_lines(workflow, "execute-active-subject") else {
        return;
    };
    let body = lines.join("\n");
    let active = [
        "path: ci-work/candidate",
        "ACTIVE_SUBJECT_SHA: ${{ steps.active.outputs.candidate }}",
        "run: ./target/ci/hell-ci collection-authority verify-checkout --input ci-work/candidate --candidate-commit \"$ACTIVE_SUBJECT_SHA\"",
        "working-directory: ci-work/candidate",
    ];
    if body
        .matches("ACTIVE_SUBJECT_SHA: ${{ steps.active.outputs.candidate }}")
        .count()
        != 1
        || body
            .matches("run: ./target/ci/hell-ci collection-authority verify-checkout --input ci-work/candidate --candidate-commit \"$ACTIVE_SUBJECT_SHA\"")
            .count()
            != 1
        || !markers_are_ordered(&body, &active)
    {
        failures.push(
            "surveillance active subject checkout is not typed-verified before subject execution"
                .to_owned(),
        );
    }
}

type CampaignHandoff = (&'static str, [&'static str; 3], [&'static str; 4]);

fn campaign_external_handoffs(path: &Path) -> Option<(&'static str, Vec<CampaignHandoff>)> {
    let name = path.file_name().and_then(|value| value.to_str())?;
    campaign_primary_handoffs(name)
        .or_else(|| campaign_review_handoffs(name))
        .or_else(|| campaign_decision_handoffs(name))
        .or_else(|| campaign_state_handoffs(name))
}

fn campaign_primary_handoffs(name: &str) -> Option<(&'static str, Vec<CampaignHandoff>)> {
    Some(match name {
        "nightly.yml" => (
            "name: Nightly",
            vec![
                (
                    "merge-native-evidence",
                    [
                        "native_artifact_id: ${{ steps.upload-native.outputs.artifact-id }}",
                        "native_artifact_digest: ${{ steps.upload-native.outputs.artifact-digest }}",
                        "native_directory_sha256: ${{ steps.bind-native.outputs.directory_sha256 }}",
                    ],
                    [
                        "id: bind-native",
                        "run: ./target/ci/hell-ci regression-import emit-directory-output --input ci-out/native-shards",
                        "id: upload-native",
                        "name: native-oracle-merged",
                    ],
                ),
                (
                    "promotion-gate",
                    [
                        "promotion_record_artifact_id: ${{ steps.final-record.outputs.artifact-id }}",
                        "promotion_record_artifact_digest: ${{ steps.final-record.outputs.artifact-digest }}",
                        "promotion_record_directory_sha256: ${{ steps.bind-final-record.outputs.directory_sha256 }}",
                    ],
                    [
                        "id: bind-final-record",
                        "run: ./target/ci/hell-ci regression-import emit-directory-output --input ci-out/promotion-record",
                        "id: final-record",
                        "name: promotion-record",
                    ],
                ),
            ],
        ),
        "promotion-evidence-review.yml" => (
            "name: Generate and review promotion evidence",
            vec![(
                "assemble-reviewed-evidence",
                [
                    "review_artifact_id: ${{ steps.upload-reviewed.outputs.artifact-id }}",
                    "review_artifact_digest: ${{ steps.upload-reviewed.outputs.artifact-digest }}",
                    "review_directory_sha256: ${{ steps.bind-reviewed.outputs.directory_sha256 }}",
                ],
                [
                    "id: bind-reviewed",
                    "run: ./target/ci/hell-ci regression-import emit-directory-output --input ci-out/evidence",
                    "id: upload-reviewed",
                    "name: promotion-review-ready-evidence",
                ],
            )],
        ),
        "oracle-reproduce.yml" => (
            "name: Oracle reproducibility evidence",
            vec![
                (
                    "seal-reviewed-platform-evidence",
                    [
                        "macos_artifact_id: ${{ steps.upload-macos.outputs.artifact-id }}",
                        "macos_artifact_digest: ${{ steps.upload-macos.outputs.artifact-digest }}",
                        "macos_directory_sha256: ${{ steps.bind-macos.outputs.directory_sha256 }}",
                    ],
                    [
                        "id: bind-macos",
                        "run: ./target/ci/hell-ci regression-import emit-directory-output --input ci-out/reviewed-macos",
                        "id: upload-macos",
                        "name: ephemeralEvidence-oracle-reviewed-macos-arm64",
                    ],
                ),
                (
                    "seal-reviewed-platform-evidence",
                    [
                        "windows_artifact_id: ${{ steps.upload-windows.outputs.artifact-id }}",
                        "windows_artifact_digest: ${{ steps.upload-windows.outputs.artifact-digest }}",
                        "windows_directory_sha256: ${{ steps.bind-windows.outputs.directory_sha256 }}",
                    ],
                    [
                        "id: bind-windows",
                        "run: ./target/ci/hell-ci regression-import emit-directory-output --input ci-out/reviewed-windows",
                        "id: upload-windows",
                        "name: ephemeralEvidence-oracle-reviewed-windows-amd64",
                    ],
                ),
            ],
        ),
        _ => return None,
    })
}

fn campaign_review_handoffs(name: &str) -> Option<(&'static str, Vec<CampaignHandoff>)> {
    Some(match name {
        "evidence-custody.yml" => (
            "name: Durable evidence custody",
            vec![
                (
                    "review-and-assemble",
                    [
                        "pre_review_artifact_id: ${{ steps.upload-pre-review.outputs.artifact-id }}",
                        "pre_review_artifact_digest: ${{ steps.upload-pre-review.outputs.artifact-digest }}",
                        "pre_review_directory_sha256: ${{ steps.bind-pre-review.outputs.directory_sha256 }}",
                    ],
                    [
                        "id: bind-pre-review",
                        "run: ./target/ci/hell-ci regression-import emit-directory-output --input ci-out/custody",
                        "id: upload-pre-review",
                        "name: promotion-custody-evidence",
                    ],
                ),
                (
                    "approve-final-review-graph",
                    [
                        "reviewed_artifact_id: ${{ steps.upload-reviewed.outputs.artifact-id }}",
                        "reviewed_artifact_digest: ${{ steps.upload-reviewed.outputs.artifact-digest }}",
                        "reviewed_directory_sha256: ${{ steps.bind-reviewed.outputs.directory_sha256 }}",
                    ],
                    [
                        "id: bind-reviewed",
                        "run: ./target/ci/hell-ci regression-import emit-directory-output --input ci-out/evidence",
                        "id: upload-reviewed",
                        "name: promotion-final-reviewed-evidence",
                    ],
                ),
                (
                    "seal-current-scrubs",
                    [
                        "primary_artifact_id: ${{ steps.upload-primary.outputs.artifact-id }}",
                        "primary_artifact_digest: ${{ steps.upload-primary.outputs.artifact-digest }}",
                        "primary_directory_sha256: ${{ steps.bind-primary.outputs.directory_sha256 }}",
                    ],
                    [
                        "id: bind-primary",
                        "run: ./target/ci/hell-ci regression-import emit-directory-output --input ci-out/current-scrub-primary",
                        "id: upload-primary",
                        "name: ephemeralEvidence-current-scrub-primary-worm-${{ github.run_id }}-${{ github.run_attempt }}",
                    ],
                ),
                (
                    "seal-current-scrubs",
                    [
                        "secondary_artifact_id: ${{ steps.upload-secondary.outputs.artifact-id }}",
                        "secondary_artifact_digest: ${{ steps.upload-secondary.outputs.artifact-digest }}",
                        "secondary_directory_sha256: ${{ steps.bind-secondary.outputs.directory_sha256 }}",
                    ],
                    [
                        "id: bind-secondary",
                        "run: ./target/ci/hell-ci regression-import emit-directory-output --input ci-out/current-scrub-secondary",
                        "id: upload-secondary",
                        "name: ephemeralEvidence-current-scrub-secondary-worm-${{ github.run_id }}-${{ github.run_attempt }}",
                    ],
                ),
            ],
        ),
        "mutation.yml" => (
            "name: Assurance mutation",
            vec![(
                "review",
                [
                    "mutation_artifact_id: ${{ steps.upload-mutation.outputs.artifact-id }}",
                    "mutation_artifact_digest: ${{ steps.upload-mutation.outputs.artifact-digest }}",
                    "mutation_directory_sha256: ${{ steps.bind-mutation.outputs.directory_sha256 }}",
                ],
                [
                    "id: bind-mutation",
                    "run: ./target/ci/hell-ci regression-import emit-directory-output --input ci-out/mutation",
                    "id: upload-mutation",
                    "name: promotion-mutation-evidence",
                ],
            )],
        ),
        "artifact-authenticity-finalize.yml" => (
            "name: Finalize artifact authenticity",
            vec![(
                "finalize",
                [
                    "authenticity_artifact_id: ${{ steps.upload-authenticity.outputs.artifact-id }}",
                    "authenticity_artifact_digest: ${{ steps.upload-authenticity.outputs.artifact-digest }}",
                    "authenticity_directory_sha256: ${{ steps.bind-authenticity.outputs.directory_sha256 }}",
                ],
                [
                    "id: bind-authenticity",
                    "run: ./target/ci/hell-ci regression-import emit-directory-output --input ci-out/acquisition",
                    "id: upload-authenticity",
                    "name: promotion-artifact-authenticity",
                ],
            )],
        ),
        _ => return None,
    })
}

fn campaign_decision_handoffs(name: &str) -> Option<(&'static str, Vec<CampaignHandoff>)> {
    match name {
        "claim-applicability-decisions.yml" => Some((
            "name: Package externally authored claim applicability decisions",
            vec![(
                "package",
                [
                    "decisions_artifact_id: ${{ steps.upload-decisions.outputs.artifact-id }}",
                    "decisions_artifact_digest: ${{ steps.upload-decisions.outputs.artifact-digest }}",
                    "decisions_directory_sha256: ${{ steps.bind-decisions.outputs.directory_sha256 }}",
                ],
                [
                    "id: bind-decisions",
                    "run: ./target/ci/hell-ci regression-import emit-directory-output --input ci-out/evidence/claim-decisions",
                    "id: upload-decisions",
                    "name: promotion-claim-applicability-decisions",
                ],
            )],
        )),
        "artifact-independent-acquisition.yml" => Some((
            "name: Independent artifact acquisition",
            vec![(
                "acquire",
                [
                    "acquisition_artifact_id: ${{ steps.upload-acquisition.outputs.artifact-id }}",
                    "acquisition_artifact_digest: ${{ steps.upload-acquisition.outputs.artifact-digest }}",
                    "acquisition_directory_sha256: ${{ steps.bind-acquisition.outputs.directory_sha256 }}",
                ],
                [
                    "id: bind-acquisition",
                    "run: ./target/ci/hell-ci regression-import emit-directory-output --input ci-out/acquisition",
                    "id: upload-acquisition",
                    "name: artifact-independent-acquisition",
                ],
            )],
        )),
        "artifact-authenticity-review.yml" => Some((
            "name: Artifact authenticity review",
            vec![(
                "acquisition-packet",
                [
                    "packet_artifact_id: ${{ steps.upload-packet.outputs.artifact-id }}",
                    "packet_artifact_digest: ${{ steps.upload-packet.outputs.artifact-digest }}",
                    "packet_directory_sha256: ${{ steps.bind-packet.outputs.directory_sha256 }}",
                ],
                [
                    "id: bind-packet",
                    "run: ./target/ci/hell-ci regression-import emit-directory-output --input ci-out",
                    "id: upload-packet",
                    "name: ephemeralEvidence-artifact-authenticity",
                ],
            )],
        )),
        _ => None,
    }
}

fn campaign_state_handoffs(name: &str) -> Option<(&'static str, Vec<CampaignHandoff>)> {
    match name {
        "promotion-surveillance.yml" => Some((
            "name: Promotion surveillance",
            vec![
                (
                    "execute-active-subject",
                    [
                        "artifact_id: ${{ steps.upload.outputs.artifact-id }}",
                        "artifact_digest: ${{ steps.upload.outputs.artifact-digest }}",
                        "directory_sha256: ${{ steps.bind-execution.outputs.directory_sha256 }}",
                    ],
                    [
                        "id: bind-execution",
                        "run: ./target/ci/hell-ci regression-import emit-directory-output --input ci-work/candidate/ci-out",
                        "id: upload",
                        "name: ephemeralEvidence-active-subject-execution",
                    ],
                ),
                (
                    "verify-and-transition",
                    [
                        "transition_artifact_id: ${{ steps.upload-transition.outputs.artifact-id }}",
                        "transition_artifact_digest: ${{ steps.upload-transition.outputs.artifact-digest }}",
                        "transition_directory_sha256: ${{ steps.bind-transition.outputs.directory_sha256 }}",
                    ],
                    [
                        "id: bind-transition",
                        "run: ./target/ci/hell-ci regression-import emit-directory-output --input ci-out/surveillance",
                        "id: upload-transition",
                        "name: promotion-surveillance-${{ github.run_id }}-${{ github.run_attempt }}",
                    ],
                ),
            ],
        )),
        "promotion-surveillance-watchdog.yml" => Some((
            "name: Promotion surveillance watchdog",
            vec![(
                "deadline",
                [
                    "transition_artifact_id: ${{ steps.upload-transition.outputs.artifact-id }}",
                    "transition_artifact_digest: ${{ steps.upload-transition.outputs.artifact-digest }}",
                    "transition_directory_sha256: ${{ steps.bind-transition.outputs.directory_sha256 }}",
                ],
                [
                    "id: bind-transition",
                    "run: ./target/ci/hell-ci regression-import emit-directory-output --input ci-out/surveillance",
                    "id: upload-transition",
                    "name: promotion-surveillance-watchdog-${{ github.run_id }}-${{ github.run_attempt }}",
                ],
            )],
        )),
        "promotion-initial-public-finalize.yml" => Some((
            "name: Initial public promotion finalizer",
            vec![(
                "finalize-completed-publication",
                [
                    "completion_artifact_id: ${{ steps.upload-completion.outputs.artifact-id }}",
                    "completion_artifact_digest: ${{ steps.upload-completion.outputs.artifact-digest }}",
                    "completion_directory_sha256: ${{ steps.bind-completion.outputs.directory_sha256 }}",
                ],
                [
                    "id: bind-completion",
                    "run: ./target/ci/hell-ci regression-import emit-directory-output --input ci-out",
                    "id: upload-completion",
                    "name: custody-initial-public-completion-${{ inputs.surveillance_run_id }}-${{ inputs.surveillance_run_attempt }}",
                ],
            )],
        )),
        _ => None,
    }
}

fn check_campaign_external_handoffs(path: &Path, workflow: &str, failures: &mut Vec<String>) {
    let Some((header, handoffs)) = campaign_external_handoffs(path) else {
        return;
    };
    let complete = workflow.starts_with(header);
    for (job, outputs, order) in &handoffs {
        let Some(lines) = workflow_job_lines(workflow, job) else {
            if complete {
                failures.push(format!(
                    "campaign external handoff job {job:?} is missing from {}",
                    path.display()
                ));
            }
            continue;
        };
        let body = lines.join("\n");
        if outputs
            .iter()
            .any(|marker| body.matches(marker).count() != 1)
            || !markers_are_ordered(&body, order)
        {
            failures.push(format!(
                "campaign external handoff job {job:?} lacks exact artifact/archive/directory outputs in {}",
                path.display()
            ));
        }
    }
}

fn check_provider_replay_token_binding(
    path: &Path,
    workflow: &str,
    require_job: bool,
    failures: &mut Vec<String>,
) {
    let Some((job, command)) = (match path.file_name().and_then(|value| value.to_str()) {
        Some("claim-applicability-decisions.yml") => Some((
            "package",
            "run: ./target/ci/hell-ci case-coverage prepare-decisions --input ci-out/evidence/claim-decisions/source/claim-coverage.details.json --from decision-source/compat/reviews/claim-applicability-decisions.json --output ci-out/evidence/claim-decisions/claim-applicability-decisions.json --github-dispatch-inputs",
        )),
        Some("promotion-evidence-review.yml") => Some((
            "assemble",
            "run: ./target/ci/hell-ci review-assemble prepare --github-dispatch-inputs",
        )),
        Some("promotion-proposal.yml") => Some((
            "assemble",
            "run: ./target/ci/hell-ci promotion-proposal --input ci-out/native-shards --output ci-out/native-shards/promotion-proposal.json --github-dispatch-inputs",
        )),
        Some("promotion-approval.yml") => Some((
            "approve",
            "run: ./target/ci/hell-ci promotion-approval-subject --input ci-out/native-shards/promotion-proposal.json --output ci-out/native-shards/promotion-approval-subject.json",
        )),
        Some("artifact-authenticity-finalize.yml") => Some((
            "prepare",
            "run: ./target/ci/hell-ci artifact-acquire assemble-finalize --input ci-out/finalize-source --output ci-out/acquisition --github-dispatch-inputs",
        )),
        Some("promotion-surveillance.yml") => Some((
            "verify-and-transition",
            "run: ./target/ci/hell-ci surveillance-ops workflow-objective",
        )),
        _ => None,
    }) else {
        return;
    };
    let Some(lines) = workflow_job_lines(workflow, job) else {
        if require_job {
            failures.push(format!(
                "provider replay job {job:?} is missing from {}",
                path.display()
            ));
        }
        return;
    };
    let commands = lines
        .iter()
        .enumerate()
        .filter_map(|(index, line)| (workflow_entry(line) == command).then_some(index))
        .collect::<Vec<_>>();
    if !matches!(commands.as_slice(), [index]
        if index.checked_sub(2).is_some_and(|env| workflow_entry(lines[env]) == "env:")
            && index.checked_sub(1).is_some_and(|token| workflow_entry(lines[token]) == "GITHUB_TOKEN: ${{ github.token }}"))
    {
        failures.push(format!(
            "provider replay command must have one exact step-scoped GitHub read token in {}",
            path.display()
        ));
    }
}

fn check_fresh_activated_campaign_liveness(workflow: &str, failures: &mut Vec<String>) {
    let exact = [
        ("evidence-collection-linux", "timeout-minutes: 120"),
        ("branch-evidence-collection-linux", "timeout-minutes: 120"),
        ("native-oracle-macos", "timeout-minutes: 180"),
        ("native-oracle-windows", "timeout-minutes: 180"),
    ];
    if exact.iter().any(|(job, timeout)| {
        workflow_job_lines(workflow, job).is_none_or(|lines| {
            lines
                .iter()
                .filter(|line| strip_yaml_comment(line).trim() == *timeout)
                .count()
                != 1
        })
    }) {
        failures.push(
            "fresh generic campaign lacks bounded Map712/Set479 three-platform execution budgets"
                .to_owned(),
        );
    }
    let required = [
        "run: ./target/ci/hell-ci nightly --oracle ci-out/linux-release-oracle --oracle-sha256 5ccc78e62200eb5aea8b9da9161334c61848d0d3e7de2f270929920cfbf357c9 --dependency-attestation ci-out/dependency-policy.json --report ci-out/nightly.json",
        "run: ./target/ci/hell-ci native-oracle-shard --source ci-work/oracle-source --platform macos-arm64 --dependency-attestation ci-out/dependency-policy.json --report ci-out/shards/macos-arm64/report.json",
        "run: .\\target\\ci\\hell-ci.exe native-oracle-shard --source ci-work\\oracle-source --platform windows-amd64 --dependency-attestation ci-out\\dependency-policy.json --report ci-out\\shards\\windows-amd64\\report.json",
        "run: ./target/ci/hell-ci evidence-epoch write --output ci-out/native-shards/assurance-epoch.json",
    ];
    if required
        .iter()
        .any(|command| workflow.matches(command).count() != 1)
        || workflow.contains("collection-custody-admission")
        || workflow.contains("collection-worm-custody")
    {
        failures.push(
            "fresh generic campaign may substitute supplemental custody evidence for current-epoch native execution"
                .to_owned(),
        );
    }
}

fn check_automatic_regression_batch_transaction(text: &str, failures: &mut Vec<String>) {
    let required = [
        "  reconcile-scheduled-batch:\n    needs: [resolve-scheduled, dispatch-scheduled-0, dispatch-scheduled-1, dispatch-scheduled-2, dispatch-scheduled-3]",
        "  integrate-scheduled-batch:\n    needs: reconcile-scheduled-batch",
        "        run: ./target/ci/hell-ci regression-import reconcile-automatic-batch --input ci-in/ready-set/automatic-regression-ready-set.json --program ci-in/program --artifact ci-out/program-selection --to ci-out/regression-batch",
        "        run: ./target/ci/hell-ci regression-import integrate-batch-current-main --input ci-in/regression-batch --output ci-out/regression-batch-result.json",
    ];
    if required.iter().any(|needle| !text.contains(needle))
        || text.matches("  integrate-scheduled-batch:").count() != 1
        || text
            .matches("regression-import integrate-batch-current-main --input")
            .count()
            != 1
    {
        failures.push(
            "automatic regressions are not reconciled and integrated by one exact nightly complete-set transaction"
                .to_owned(),
        );
    }
}

fn check_automatic_regression_child_isolation(text: &str, failures: &mut Vec<String>) {
    let unique_child_group = "concurrency:\n  group: reviewed-regression-corpus-${{ inputs.action == 'automatic' && format('{0}-{1}', inputs.issue, inputs.generated_case_id) || github.ref }}\n  cancel-in-progress: false";
    let manual_only_integration = "  integrate:\n    if: ${{ github.ref == 'refs/heads/main' && inputs.action == 'integrate' }}";
    let batch_artifact = "name: reviewed-regression-${{ inputs.batch_id }}-${{ inputs.generated_case_id }}-${{ github.run_id }}-${{ github.run_attempt }}";
    if !text.contains(unique_child_group)
        || !text.contains(manual_only_integration)
        || !text.contains(batch_artifact)
        || text.contains("inputs.action == 'automatic' || inputs.action == 'integrate'")
    {
        failures.push(
            "automatic regression child runs are not uniquely isolated as non-integrating batch producers"
                .to_owned(),
        );
    }
}

fn check_transport_probe_sigstore_identity(path: &Path, text: &str, failures: &mut Vec<String>) {
    let Some(filename @ ("assurance-transport-signer-a.yml" | "assurance-transport-signer-b.yml")) =
        path.file_name().and_then(|value| value.to_str())
    else {
        return;
    };
    let identity = format!(
        "HELL_SIGSTORE_IDENTITY: https://github.com/Portfoligno/hell-rs/.github/workflows/{filename}@refs/heads/main"
    );
    if text.matches(&identity).count() != 1 {
        failures.push(format!(
            "transport probe signer does not bind Sigstore to its called workflow identity in {}",
            path.display()
        ));
    }
}

fn reviewed_workflow_env(path: &Path, lines: &[&str], index: usize, original: &str) -> bool {
    let source_commit = original == "env:"
        && lines.get(index + 1).is_some_and(|line| {
            matches!(
                *line,
                "  HELL_SOURCE_COMMIT: ${{ github.sha }}"
                    | "  HELL_SOURCE_COMMIT: ${{ github.event_name == 'workflow_dispatch' && inputs.candidate_sha || github.sha }}"
                    | "  HELL_SOURCE_COMMIT: ${{ inputs.candidate_sha }}"
            )
        });
    source_commit
        || reviewed_surveillance_token_binding(path, lines, index, original)
        || reviewed_evidence_review_token_binding(path, lines, index, original)
        || reviewed_external_acquisition_configuration(path, lines, index, original)
        || reviewed_provider_metadata_token_binding(path, lines, index, original)
        || reviewed_provider_replay_token_binding(path, lines, index, original)
        || reviewed_oracle_provider_selection(path, lines, index, original)
        || reviewed_public_report_configuration(path, lines, index, original)
        || reviewed_initial_surveillance_finalizer(path, lines, index, original)
        || reviewed_active_subject_selection(path, lines, index, original)
        || reviewed_prior_public_promotion(path, lines, index, original)
        || reviewed_collection_authority_acquisition(path, lines, index, original)
        || reviewed_collection_custody_environment(path, lines, index, original)
        || reviewed_collection_activation_environment(path, lines, index, original)
        || reviewed_collection_worm_environment(path, lines, index, original)
        || reviewed_claim_applicability_decision_environment(path, lines, index, original)
        || reviewed_primary_acquisition_checkout_environment(path, lines, index, original)
        || reviewed_maintenance_selector_environment(path, lines, index, original)
        || reviewed_selector_export_environment(path, lines, index, original)
        || reviewed_selector_selection_environment(path, lines, index, original)
        || reviewed_selector_barrier_environment(path, lines, index, original)
        || reviewed_promotion_checkout_environment(path, lines, index, original)
        || reviewed_exact_checkout_environment(path, lines, index, original)
        || reviewed_custody_upload_subject_environment(path, lines, index, original)
        || reviewed_transport_probe_environment(path, lines, index, original)
        || reviewed_regression_environment(path, lines, index, original)
}

fn reviewed_selector_selection_environment(
    path: &Path,
    lines: &[&str],
    index: usize,
    original: &str,
) -> bool {
    path == workflow_path("custody-provider-selector-seal.yml")
        && original == "        env:"
        && lines.get(index + 1)
            == Some(&"          CUSTODY_SELECTOR_SOURCE_WORKFLOW: ${{ inputs.source_workflow }}")
        && lines.get(index + 2) == Some(&"          GITHUB_TOKEN: ${{ github.token }}")
        && lines.get(index + 3)
            == Some(
                &"        run: ./target/ci/hell-ci custody-ops workflow-select-provider-selector-updates",
            )
}

fn reviewed_selector_barrier_environment(
    path: &Path,
    lines: &[&str],
    index: usize,
    original: &str,
) -> bool {
    if original != "        env:" {
        return false;
    }
    let following = &lines[index.saturating_add(1)..];
    let common = [
        "          ACTIVE_CUSTODY_PRIMARY_UPLOAD_RECEIPT: ${{ vars.ACTIVE_CUSTODY_PRIMARY_UPLOAD_RECEIPT }}",
        "          ACTIVE_CUSTODY_SECONDARY_UPLOAD_RECEIPT: ${{ vars.ACTIVE_CUSTODY_SECONDARY_UPLOAD_RECEIPT }}",
        "          CUSTODY_SELECTOR_AGGREGATE_ARCHIVE_SHA256: ${{ inputs.selector_archive_sha256 }}",
        "          CUSTODY_SELECTOR_AGGREGATE_ARTIFACT_ID: ${{ inputs.selector_artifact_id }}",
        "          CUSTODY_SELECTOR_AGGREGATE_CANDIDATE: ${{ inputs.selector_source_sha }}",
        "          CUSTODY_SELECTOR_AGGREGATE_DIRECTORY_SHA256: ${{ inputs.selector_directory_sha256 }}",
        "          CUSTODY_SELECTOR_AGGREGATE_EVENT: workflow_dispatch",
    ];
    if !following.starts_with(&common) {
        return false;
    }
    let tail = match path.file_name().and_then(|value| value.to_str()) {
        Some("promotion-surveillance.yml") => [
            "          CUSTODY_SELECTOR_AGGREGATE_RUN_ATTEMPT: ${{ inputs.selector_run_attempt }}",
            "          CUSTODY_SELECTOR_AGGREGATE_RUN_ID: ${{ inputs.selector_run_id }}",
            "          CUSTODY_SELECTOR_AGGREGATE_WORKFLOW: .github/workflows/evidence-custody.yml",
            "          GITHUB_TOKEN: ${{ github.token }}",
            "        run: ./target/ci/hell-ci custody-ops workflow-verify-provider-selector-update-barrier",
        ],
        Some("promotion-initial-public-finalize.yml") => [
            "          CUSTODY_SELECTOR_AGGREGATE_RUN_ATTEMPT: ${{ inputs.surveillance_run_attempt }}",
            "          CUSTODY_SELECTOR_AGGREGATE_RUN_ID: ${{ inputs.surveillance_run_id }}",
            "          CUSTODY_SELECTOR_AGGREGATE_WORKFLOW: .github/workflows/promotion-surveillance.yml",
            "          GITHUB_TOKEN: ${{ github.token }}",
            "        run: ./target/ci/hell-ci custody-ops workflow-verify-provider-selector-update-barrier",
        ],
        _ => return false,
    };
    following[common.len()..].starts_with(&tail)
}

fn reviewed_selector_export_environment(
    path: &Path,
    lines: &[&str],
    index: usize,
    original: &str,
) -> bool {
    path == workflow_path("custody-provider-selector-recovery.yml")
        && original == "        env:"
        && lines.get(index + 1)
            == Some(&"          CUSTODY_EXPECTED_PROVIDER: ${{ matrix.provider }}")
        && lines.get(index + 2)
            == Some(&"          CUSTODY_EXPECTED_TRUST_DOMAIN: ${{ matrix.trust-domain }}")
        && lines.get(index + 3)
            == Some(
                &"        run: ./target/ci/hell-ci custody-ops workflow-export-provider-selector",
            )
}

fn reviewed_maintenance_selector_environment(
    path: &Path,
    lines: &[&str],
    index: usize,
    original: &str,
) -> bool {
    matches!(
        path.file_name().and_then(|value| value.to_str()),
        Some(
            "custody-scrub.yml"
                | "promotion-surveillance.yml"
                | "promotion-surveillance-watchdog.yml"
                | "promotion-initial-public-finalize.yml"
                | "evidence-custody.yml"
                | "custody-provider-selector-recovery.yml"
        )
    ) && original == "        env:"
        && lines.get(index + 1)
            .is_some_and(|line| matches!(
                *line,
                "          ACTIVE_CUSTODY_PROVIDER_SELECTOR: ${{ vars[matrix.default-receipt-variable] }}"
                    | "          ACTIVE_CUSTODY_PROVIDER_SELECTOR: ${{ vars[matrix.provider-selector-variable] }}"
            ))
        && lines.get(index + 2).is_some_and(|line| {
            matches!(
                *line,
                "          CUSTODY_PROVIDER_OPERATION: upload"
                    | "          CUSTODY_PROVIDER_OPERATION: selector-export"
                    | "          CUSTODY_PROVIDER_OPERATION: activation"
                    | "          CUSTODY_PROVIDER_OPERATION: maintenance"
                    | "          CUSTODY_PROVIDER_OPERATION: surveillance"
                    | "          CUSTODY_PROVIDER_OPERATION: transition-publication"
                    | "          CUSTODY_PROVIDER_OPERATION: complete-initial-publication"
            )
        })
        && lines.get(index + 3)
            == Some(&"          CUSTODY_EXPECTED_PROVIDER: ${{ matrix.provider }}")
        && lines.get(index + 4)
            == Some(&"          CUSTODY_EXPECTED_TRUST_DOMAIN: ${{ matrix.trust-domain }}")
        && lines.get(index + 5)
            == Some(
                &"        run: ./target/ci/hell-ci custody-ops workflow-prepare-provider-selector",
            )
}

fn reviewed_primary_acquisition_checkout_environment(
    path: &Path,
    lines: &[&str],
    index: usize,
    original: &str,
) -> bool {
    path == workflow_path("artifact-authenticity-review.yml")
        && original == "        env:"
        && lines.get(index + 1)
            == Some(&"          ACQUISITION_CANDIDATE_SHA: ${{ inputs.candidate_sha }}")
        && lines.get(index + 2)
            == Some(
                &"        run: ./target/ci/hell-ci collection-authority verify-checkout --input . --candidate-commit \"$ACQUISITION_CANDIDATE_SHA\"",
            )
}

fn reviewed_exact_checkout_environment(
    path: &Path,
    lines: &[&str],
    index: usize,
    original: &str,
) -> bool {
    if original != "        env:" {
        return false;
    }
    if lines.get(index + 1)
        == Some(
            &"          PUBLIC_COMPATIBILITY_REPORT_BUCKET: ${{ vars.PUBLIC_COMPATIBILITY_REPORT_BUCKET }}",
        )
        && lines.get(index + 2)
            == Some(
                &"          PUBLIC_COMPATIBILITY_REPORT_BASE_URL: ${{ vars.PUBLIC_COMPATIBILITY_REPORT_BASE_URL }}",
            )
    {
        return lines.get(index + 3)
            == Some(
                &"        run: ./target/ci/hell-ci custody-ops workflow-prepare-public-publication-selector",
            );
    }
    let exact = [
        "          TRUSTED_DRIVER_SHA: ${{ github.sha }}",
        "        run: ./target/ci/hell-ci collection-authority verify-checkout --input . --candidate-commit \"$TRUSTED_DRIVER_SHA\"",
    ];
    let active = [
        "          ACTIVE_SUBJECT_SHA: ${{ steps.active.outputs.candidate }}",
        "        run: ./target/ci/hell-ci collection-authority verify-checkout --input ci-work/candidate --candidate-commit \"$ACTIVE_SUBJECT_SHA\"",
    ];
    matches!(
        path.file_name().and_then(|value| value.to_str()),
        Some(
            "nightly.yml"
                | "promotion-initial-public-finalize.yml"
                | "promotion-surveillance.yml"
                | "promotion-surveillance-watchdog.yml"
                | "evidence-custody.yml"
                | "custody-provider-selector-recovery.yml"
                | "custody-provider-selector-seal.yml"
                | "custody-scrub.yml"
                | "mutation.yml"
                | "artifact-authenticity-finalize.yml"
                | "oracle-reproduce.yml"
        )
    ) && (lines[index.saturating_add(1)..].starts_with(&exact)
        || (path == workflow_path("promotion-surveillance.yml")
            && lines[index.saturating_add(1)..].starts_with(&active)))
}

fn reviewed_promotion_checkout_environment(
    path: &Path,
    lines: &[&str],
    index: usize,
    original: &str,
) -> bool {
    matches!(
        path.file_name().and_then(|value| value.to_str()),
        Some("promotion-proposal.yml" | "promotion-approval.yml")
    ) && original == "        env:"
        && lines.get(index + 1)
            == Some(&"          PROMOTION_CANDIDATE_SHA: ${{ inputs.candidate_sha }}")
        && lines.get(index + 2)
            == Some(
                &"        run: ./target/ci/hell-ci collection-authority verify-checkout --input . --candidate-commit \"$PROMOTION_CANDIDATE_SHA\"",
            )
}

fn reviewed_collection_activation_environment(
    path: &Path,
    lines: &[&str],
    index: usize,
    original: &str,
) -> bool {
    if original != "        env:" {
        return false;
    }
    let following = &lines[index.saturating_add(1)..];
    if path == workflow_path("collection-activation.yml") {
        let checkout = [
            "          COLLECTION_ACTIVATION_SHA: ${{ inputs.activation_sha }}",
            "        run: ./target/ci/hell-ci collection-authority verify-checkout --input . --candidate-commit \"$COLLECTION_ACTIVATION_SHA\"",
        ];
        let verify = [
            "          GITHUB_TOKEN: ${{ github.token }}",
            "          COLLECTION_PROPOSAL_ARCHIVE_SHA256: ${{ inputs.proposal_archive_sha256 }}",
            "          COLLECTION_PROPOSAL_ARTIFACT_ID: ${{ inputs.proposal_artifact_id }}",
            "          COLLECTION_PROPOSAL_DIRECTORY_SHA256: ${{ inputs.proposal_directory_sha256 }}",
            "          COLLECTION_PROPOSAL_RUN_ATTEMPT: ${{ inputs.proposal_run_attempt }}",
            "          COLLECTION_PROPOSAL_RUN_ID: ${{ inputs.proposal_run_id }}",
        ];
        let review_subject = [
            "          WRAPPER_DIRECTORY_SHA256: ${{ needs.retain-proposal.outputs.directory_sha256 }}",
            "        run: ./target/ci/hell-ci collection-authority verify-activation-review-subject --input ci-in/collection-activation-review-subject --expected-directory-sha256 \"$WRAPPER_DIRECTORY_SHA256\"",
        ];
        return following.starts_with(&checkout)
            || following.starts_with(&verify)
            || following.starts_with(&review_subject);
    }
    if path != workflow_path("collection-activation-preparation.yml") {
        return false;
    }
    let checkout = [
        "          COLLECTION_ACTIVATION_SHA: ${{ inputs.activation_sha }}",
        "        run: ./target/ci/hell-ci collection-authority verify-checkout --input . --candidate-commit \"$COLLECTION_ACTIVATION_SHA\"",
    ];
    let prepare = [
        "          COLLECTION_ACTIVATION_ARTIFACT_ID: ${{ inputs.artifact_id }}",
        "          COLLECTION_ACTIVATION_ARCHIVE_SHA256: ${{ inputs.expected_archive_sha256 }}",
        "          COLLECTION_ACTIVATION_DIRECTORY_SHA256: ${{ inputs.expected_directory_sha256 }}",
        "          COLLECTION_ACTIVATION_RUN_ATTEMPT: ${{ inputs.source_run_attempt }}",
        "          COLLECTION_ACTIVATION_RUN_ID: ${{ inputs.source_run_id }}",
        "        run: ./target/ci/hell-ci collection-authority prepare-activation --input ci-in/collection-custody-activation --output ci-out/collection-activation-proposal --run-id \"$COLLECTION_ACTIVATION_RUN_ID\" --run-attempt \"$COLLECTION_ACTIVATION_RUN_ATTEMPT\" --artifact-id \"$COLLECTION_ACTIVATION_ARTIFACT_ID\" --expected-directory-sha256 \"$COLLECTION_ACTIVATION_DIRECTORY_SHA256\" --expected-archive-sha256 \"$COLLECTION_ACTIVATION_ARCHIVE_SHA256\"",
    ];
    following.starts_with(&checkout) || following.starts_with(&prepare)
}

fn reviewed_claim_applicability_decision_environment(
    path: &Path,
    lines: &[&str],
    index: usize,
    original: &str,
) -> bool {
    if path != workflow_path("claim-applicability-decisions.yml") || original != "        env:" {
        return false;
    }
    let following = &lines[index.saturating_add(1)..];
    following.starts_with(&[
        "          CLAIM_CANDIDATE_SHA: ${{ inputs.candidate_sha }}",
        "        run: ./target/ci/hell-ci collection-authority verify-checkout --input . --candidate-commit \"$CLAIM_CANDIDATE_SHA\"",
    ]) || following.starts_with(&[
        "          CLAIM_DECISION_SOURCE_SHA: ${{ inputs.decision_source_sha }}",
        "        run: ./target/ci/hell-ci collection-authority verify-checkout --input decision-source --candidate-commit \"$CLAIM_DECISION_SOURCE_SHA\"",
    ]) || following.starts_with(&[
        "          GITHUB_TOKEN: ${{ github.token }}",
        "        run: ./target/ci/hell-ci case-coverage prepare-decisions --input ci-out/evidence/claim-decisions/source/claim-coverage.details.json --from decision-source/compat/reviews/claim-applicability-decisions.json --output ci-out/evidence/claim-decisions/claim-applicability-decisions.json --github-dispatch-inputs",
    ])
}

fn reviewed_custody_upload_subject_environment(
    path: &Path,
    lines: &[&str],
    index: usize,
    original: &str,
) -> bool {
    path == workflow_path("evidence-custody.yml")
        && original == "        env:"
        && lines.get(index + 1)
            == Some(&"          CUSTODY_EXPECTED_PROVIDER: ${{ matrix.provider }}")
        && lines.get(index + 2)
            == Some(&"          CUSTODY_EXPECTED_TRUST_DOMAIN: ${{ matrix.trust-domain }}")
        && lines.get(index + 3)
            == Some(&"        run: ./target/ci/hell-ci custody-ops workflow-verify-upload-subject")
}

fn reviewed_collection_worm_environment(
    path: &Path,
    lines: &[&str],
    index: usize,
    original: &str,
) -> bool {
    path == workflow_path("evidence-custody.yml")
        && original == "        env:"
        && lines.get(index + 1)
            == Some(&"          COLLECTION_CANDIDATE_SHA: ${{ inputs.candidate_sha }}")
        && lines.get(index + 2)
            == Some(
                &"        run: ./target/ci/hell-ci collection-authority verify-checkout --input . --candidate-commit \"$COLLECTION_CANDIDATE_SHA\"",
            )
}

fn reviewed_collection_authority_acquisition(
    path: &Path,
    lines: &[&str],
    index: usize,
    original: &str,
) -> bool {
    if path != workflow_path("collection-authority.yml") || original != "        env:" {
        return false;
    }
    let following = &lines[index.saturating_add(1)..];
    let macos = [
        "          COLLECTION_ORACLE_SHA256: ${{ hashFiles('ci-out/collection-shard/macos-arm64/oracle/macos-arm64/hell') }}",
        "        run: ./target/ci/hell-ci collection-authority collect --oracle ci-out/collection-shard/macos-arm64/oracle/macos-arm64/hell --oracle-sha256 \"$COLLECTION_ORACLE_SHA256\" --candidate-executable ci-out/candidate-target/release/hell --candidate-commit \"$HELL_SOURCE_COMMIT\" --platform macos-arm64 --output ci-out/collection-shard/macos-arm64",
    ];
    let windows = [
        "          COLLECTION_ORACLE_SHA256: ${{ hashFiles('ci-out/collection-shard/windows-amd64/oracle/windows-amd64/hell.exe') }}",
        "        run: .\\target\\ci\\hell-ci.exe collection-authority collect --oracle ci-out\\collection-shard\\windows-amd64\\oracle\\windows-amd64\\hell.exe --oracle-sha256 \"$env:COLLECTION_ORACLE_SHA256\" --candidate-executable ci-out\\candidate-target\\release\\hell.exe --candidate-commit \"$env:HELL_SOURCE_COMMIT\" --platform windows-amd64 --output ci-out\\collection-shard\\windows-amd64",
    ];
    let merge = [
        "          COLLECTION_LINUX_ARTIFACT_ID: ${{ needs.collection-authority-linux.outputs.artifact_id }}",
        "          COLLECTION_MACOS_ARTIFACT_ID: ${{ needs.collection-authority-macos.outputs.artifact_id }}",
        "          COLLECTION_WINDOWS_ARTIFACT_ID: ${{ needs.collection-authority-windows.outputs.artifact_id }}",
        "          GITHUB_TOKEN: ${{ github.token }}",
    ];
    let custody_bundle = [
        "          COLLECTION_CUSTODY_BUNDLE_PATH: ${{ steps.attest-collection-custody.outputs.bundle-path }}",
    ];
    following.starts_with(&macos)
        || following.starts_with(&windows)
        || (following.starts_with(&merge)
            && following.get(merge.len()).is_some_and(|line| {
                line.strip_prefix("        ") == Some(COLLECTION_ACQUISITION_COMMAND)
            }))
        || (following.starts_with(&custody_bundle)
            && following.get(custody_bundle.len()).is_some_and(|line| {
                matches!(
                    line.strip_prefix("        "),
                    Some(COLLECTION_ATTESTATION_TOOL_COMMAND | COLLECTION_RETAIN_CUSTODY_COMMAND)
                )
            }))
}

fn reviewed_collection_custody_environment(
    path: &Path,
    lines: &[&str],
    index: usize,
    original: &str,
) -> bool {
    if original != "        env:" {
        return false;
    }
    let following = &lines[index.saturating_add(1)..];
    let integration = [
        "          COLLECTION_INTEGRATION_SHA: ${{ inputs.integration_sha }}",
        "        run: ./target/ci/hell-ci collection-authority verify-checkout --input . --candidate-commit \"$COLLECTION_INTEGRATION_SHA\"",
    ];
    let worm_digest = [
        "          COLLECTION_WORM_ARCHIVE_SHA256: ${{ inputs.expected_worm_archive_sha256 }}",
        "          COLLECTION_WORM_ARTIFACT_ID: ${{ inputs.worm_artifact_id }}",
        "          COLLECTION_WORM_DIRECTORY_SHA256: ${{ inputs.expected_worm_directory_sha256 }}",
        "          COLLECTION_WORM_RUN_ATTEMPT: ${{ inputs.worm_source_run_attempt }}",
        "          COLLECTION_WORM_RUN_ID: ${{ inputs.worm_source_run_id }}",
        "          GITHUB_TOKEN: ${{ github.token }}",
        "        run: ./target/ci/hell-ci collection-authority verify-worm-artifact --input ci-in/collection-worm-custody --expected-directory-sha256 \"$COLLECTION_WORM_DIRECTORY_SHA256\" --expected-archive-sha256 \"$COLLECTION_WORM_ARCHIVE_SHA256\" --run-id \"$COLLECTION_WORM_RUN_ID\" --run-attempt \"$COLLECTION_WORM_RUN_ATTEMPT\" --artifact-id \"$COLLECTION_WORM_ARTIFACT_ID\"",
    ];
    let preparation = [
        "          COLLECTION_PREPARATION_SHA: ${{ inputs.preparation_sha }}",
        "        run: ./target/ci/hell-ci collection-authority verify-checkout --input . --candidate-commit \"$COLLECTION_PREPARATION_SHA\"",
    ];
    let review = [
        "          COLLECTION_CUSTODY_ISSUED_AT: ${{ inputs.issued_at }}",
        "          COLLECTION_CUSTODY_REVIEWER: ${{ inputs.reviewer }}",
        "        run: ./target/ci/hell-ci collection-authority prepare-custody-review --package compat/collection-custody/payload --signature compat/collection-custody/signature --candidate-executable target/release/hell --reviewer \"$COLLECTION_CUSTODY_REVIEWER\" --issued-at \"$COLLECTION_CUSTODY_ISSUED_AT\" --output ci-out/collection-custody-review",
    ];
    match path.file_name().and_then(|value| value.to_str()) {
        Some("collection-custody-integration.yml") => {
            following.starts_with(&integration) || following.starts_with(&worm_digest)
        }
        Some("collection-custody-review.yml") => {
            following.starts_with(&preparation) || following.starts_with(&review)
        }
        _ => false,
    }
}

fn reviewed_transport_probe_environment(
    path: &Path,
    lines: &[&str],
    index: usize,
    original: &str,
) -> bool {
    if original != "        env:" {
        return false;
    }
    let following = &lines[index.saturating_add(1)..];
    match path.file_name().and_then(|value| value.to_str()) {
        Some("assurance-transport-readiness.yml") => {
            reviewed_transport_probe_controller_environment(following)
        }
        Some("assurance-transport-signer-a.yml") => {
            reviewed_transport_probe_signer_environment(following, "a")
        }
        Some("assurance-transport-signer-b.yml") => {
            reviewed_transport_probe_signer_environment(following, "b")
        }
        _ => false,
    }
}

fn reviewed_transport_probe_controller_environment(following: &[&str]) -> bool {
    let subject = [
        "          GITHUB_TOKEN: ${{ github.token }}",
        "          REGRESSION_PROVIDER_ARTIFACT_ID: ${{ needs.assemble.outputs.artifact_id }}",
        "          REGRESSION_PROVIDER_ARTIFACT_NAME: assurance-transport-readiness-subject-${{ github.run_id }}-${{ github.run_attempt }}",
        "          REGRESSION_PROVIDER_ARCHIVE_SHA256: ${{ needs.assemble.outputs.artifact_digest }}",
        "          REGRESSION_PROVIDER_DIRECTORY_SHA256: ${{ needs.assemble.outputs.directory_sha256 }}",
        "          REGRESSION_PROVIDER_EVENT: workflow_dispatch",
        "          REGRESSION_PROVIDER_HEAD_SHA: ${{ github.sha }}",
        "          REGRESSION_PROVIDER_RUN_ATTEMPT: ${{ github.run_attempt }}",
        "          REGRESSION_PROVIDER_RUN_ID: ${{ github.run_id }}",
        "          REGRESSION_PROVIDER_WORKFLOW_PATH: .github/workflows/assurance-transport-readiness.yml",
        "        run: ./target/ci/hell-ci regression-import select-subject --input ci-in/transport-subject --output ci-out/subject-selection",
    ];
    let envelope_a = transport_probe_controller_envelope_environment("a");
    let envelope_b = transport_probe_controller_envelope_environment("b");
    let aggregate = [
        "          TRANSPORT_PROBE_A_DIRECTORY: ci-in/transport-envelope-a",
        "          TRANSPORT_PROBE_A_SELECTION: ci-out/envelope-a-selection",
        "          TRANSPORT_PROBE_B_DIRECTORY: ci-in/transport-envelope-b",
        "          TRANSPORT_PROBE_B_SELECTION: ci-out/envelope-b-selection",
        "          TRANSPORT_PROBE_SUBJECT_DIRECTORY: ci-in/transport-subject",
        "          TRANSPORT_PROBE_SUBJECT_SELECTION: ci-out/subject-selection",
        "        run: ./target/ci/hell-ci auth-transport-probe aggregate --input ci-in/transport-envelope-a/envelope.json --from ci-in/transport-envelope-b/envelope.json --policy compat/transport-probe/a/allowed_signers --to compat/transport-probe/b/allowed_signers --output ci-out/transport-receipt/receipt.json",
    ];
    following.starts_with(&subject)
        || following.starts_with(&envelope_a.iter().map(String::as_str).collect::<Vec<_>>())
        || following.starts_with(&envelope_b.iter().map(String::as_str).collect::<Vec<_>>())
        || following.starts_with(&aggregate)
}

fn transport_probe_controller_envelope_environment(suffix: &str) -> Vec<String> {
    vec![
        "          GITHUB_TOKEN: ${{ github.token }}".to_owned(),
        format!(
            "          REGRESSION_PROVIDER_ARTIFACT_ID: ${{{{ needs.sign-{suffix}.outputs.artifact_id }}}}"
        ),
        format!(
            "          REGRESSION_PROVIDER_ARTIFACT_NAME: assurance-transport-readiness-envelope-{suffix}-${{{{ github.run_id }}}}-${{{{ github.run_attempt }}}}"
        ),
        format!(
            "          REGRESSION_PROVIDER_ARCHIVE_SHA256: ${{{{ needs.sign-{suffix}.outputs.artifact_digest }}}}"
        ),
        format!(
            "          REGRESSION_PROVIDER_DIRECTORY_SHA256: ${{{{ needs.sign-{suffix}.outputs.directory_sha256 }}}}"
        ),
        "          REGRESSION_PROVIDER_EVENT: workflow_dispatch".to_owned(),
        "          REGRESSION_PROVIDER_HEAD_SHA: ${{ github.sha }}".to_owned(),
        "          REGRESSION_PROVIDER_RUN_ATTEMPT: ${{ github.run_attempt }}".to_owned(),
        "          REGRESSION_PROVIDER_RUN_ID: ${{ github.run_id }}".to_owned(),
        "          REGRESSION_PROVIDER_WORKFLOW_PATH: .github/workflows/assurance-transport-readiness.yml".to_owned(),
        format!(
            "        run: ./target/ci/hell-ci regression-import select-subject --input ci-in/transport-envelope-{suffix} --output ci-out/envelope-{suffix}-selection"
        ),
    ]
}

fn reviewed_transport_probe_signer_environment(following: &[&str], suffix: &str) -> bool {
    let packet = transport_probe_signer_selection_environment("packet");
    let subject = transport_probe_signer_selection_environment("subject");
    let sign = vec![
        format!("          HELL_REVIEWER_ID: assurance-transport-probe-{suffix}:probe-{suffix}"),
        format!(
            "          HELL_SIGSTORE_IDENTITY: https://github.com/Portfoligno/hell-rs/.github/workflows/assurance-transport-signer-{suffix}.yml@refs/heads/main"
        ),
        format!(
            "        run: ./target/ci/hell-ci auth-transport-probe sign --input ci-in/transport-packets/packet-{suffix}.json --output ci-out/transport-envelope-{suffix}/envelope.json --role assurance-transport-probe-{suffix} --policy compat/transport-probe/{suffix}/allowed_signers"
        ),
    ];
    [packet, subject, sign].iter().any(|expected| {
        following.starts_with(&expected.iter().map(String::as_str).collect::<Vec<_>>())
    })
}

fn transport_probe_signer_selection_environment(role: &str) -> Vec<String> {
    let (artifact_id, archive_digest, artifact_name, directory_digest, input, output) = match role {
        "packet" => (
            "packet_artifact_id",
            "packet_artifact_digest",
            "packets",
            "packet_directory_sha256",
            "transport-packets",
            "packet-selection",
        ),
        "subject" => (
            "subject_artifact_id",
            "subject_artifact_digest",
            "subject",
            "subject_directory_sha256",
            "transport-subject",
            "subject-selection",
        ),
        _ => return Vec::new(),
    };
    vec![
        "          GITHUB_TOKEN: ${{ github.token }}".to_owned(),
        format!("          REGRESSION_PROVIDER_ARTIFACT_ID: ${{{{ inputs.{artifact_id} }}}}"),
        format!(
            "          REGRESSION_PROVIDER_ARTIFACT_NAME: assurance-transport-readiness-{artifact_name}-${{{{ inputs.parent_run_id }}}}-${{{{ inputs.parent_run_attempt }}}}"
        ),
        format!("          REGRESSION_PROVIDER_ARCHIVE_SHA256: ${{{{ inputs.{archive_digest} }}}}"),
        format!(
            "          REGRESSION_PROVIDER_DIRECTORY_SHA256: ${{{{ inputs.{directory_digest} }}}}"
        ),
        "          REGRESSION_PROVIDER_EVENT: workflow_dispatch".to_owned(),
        "          REGRESSION_PROVIDER_HEAD_SHA: ${{ github.sha }}".to_owned(),
        "          REGRESSION_PROVIDER_RUN_ATTEMPT: ${{ inputs.parent_run_attempt }}".to_owned(),
        "          REGRESSION_PROVIDER_RUN_ID: ${{ inputs.parent_run_id }}".to_owned(),
        "          REGRESSION_PROVIDER_WORKFLOW_PATH: .github/workflows/assurance-transport-readiness.yml".to_owned(),
        format!(
            "        run: ./target/ci/hell-ci regression-import select-subject --input ci-in/{input} --output ci-out/{output}"
        ),
    ]
}

fn reviewed_regression_environment(
    path: &Path,
    lines: &[&str],
    index: usize,
    original: &str,
) -> bool {
    if original != "        env:" || !reviewed_regression_workflow(path) {
        return false;
    }
    let following = &lines[index.saturating_add(1)..];
    let reviewed = [
        &[
            "          GITHUB_TOKEN: ${{ github.token }}",
            "          REGRESSION_PROVIDER_CONTEXT: ${{ inputs.program_provider_context }}",
            "          REGRESSION_REQUIRED_WORKFLOW_PATH: .github/workflows/nightly.yml",
            "        run: ./target/ci/hell-ci regression-import acquire-subject --output ci-in/program --artifact ci-out/program-selection",
        ][..],
        &[
            "          GITHUB_TOKEN: ${{ github.token }}",
            "          REGRESSION_PROVIDER_CONTEXT: ${{ inputs.evidence_provider_context }}",
            "          REGRESSION_REQUIRED_WORKFLOW_PATH: .github/workflows/promotion-evidence-review.yml",
            "        run: ./target/ci/hell-ci regression-import acquire-subject --output ci-in/evidence --artifact ci-out/evidence-selection",
        ],
        &[
            "          GITHUB_TOKEN: ${{ github.token }}",
            "          REGRESSION_PROVIDER_CONTEXT: ${{ inputs.current_public_provider_context }}",
            "          REGRESSION_REQUIRED_WORKFLOW_PATH: .github/workflows/promotion-surveillance.yml",
            "        run: ./target/ci/hell-ci regression-import acquire-subject --output ci-in/public --artifact ci-out/public-selection",
        ],
        &[
            "          REGRESSION_GENERATED_CASE: ${{ inputs.generated_case_id }}",
            "          REGRESSION_TEMPLATE_CASE: ${{ inputs.template_case_id }}",
            "        run: ./target/ci/hell-ci regression-import assemble-generated-subject --program ci-in/program --input ci-in/evidence --proposal ci-in/public --findings ci-out/public-selection --expected \"$REGRESSION_TEMPLATE_CASE\" --issue \"$REGRESSION_GENERATED_CASE\" --artifact ci-out/program-selection --policy ci-out/evidence-selection --output ci-out/regression-subject",
        ],
        &[
            "          GITHUB_TOKEN: ${{ github.token }}",
            "          REGRESSION_PROVIDER_CONTEXT: ${{ inputs.subject_provider_context }}",
            "          REGRESSION_REQUIRED_WORKFLOW_PATH: .github/workflows/regression-subject.yml",
            "        run: ./target/ci/hell-ci regression-import acquire-subject --output ci-in/regression-subject --artifact ci-out/regression-subject-selection",
        ],
        &[
            "          REGRESSION_CATEGORY: ${{ inputs.category }}",
            "          REGRESSION_GENERATED_CASE: ${{ inputs.generated_case_id }}",
            "          REGRESSION_ISSUE: ${{ inputs.issue }}",
            "          REGRESSION_TEMPLATE_CASE: ${{ inputs.template_case_id }}",
            "        run: ./target/ci/hell-ci regression-import prepare --input ci-in/regression-subject/claim-coverage.json --program ci-in/regression-subject/program.hell --from ci-in/regression-subject/oracle --to ci-in/regression-subject/candidate --expected \"$REGRESSION_TEMPLATE_CASE\" --issue \"$REGRESSION_ISSUE\" --category \"$REGRESSION_CATEGORY\" --artifact ci-out/regression-subject-selection --output ci-out/regression-package",
        ],
        &[
            "          GITHUB_TOKEN: ${{ github.token }}",
            "          REGRESSION_PROVIDER_CONTEXT: ${{ inputs.proposal_provider_context }}",
            "          REGRESSION_REQUIRED_WORKFLOW_PATH: .github/workflows/regression-corpus.yml",
            "        run: ./target/ci/hell-ci regression-import acquire-subject --output ci-in/regression-package --artifact ci-out/regression-package-selection",
        ],
        &[
            "          GITHUB_TOKEN: ${{ github.token }}",
            "          REGRESSION_PROVIDER_CONTEXT: ${{ inputs.proposal_provider_context }}",
            "          REGRESSION_REQUIRED_WORKFLOW_PATH: .github/workflows/regression-corpus.yml",
            "        run: ./target/ci/hell-ci regression-import acquire-subject --output ci-out/regression-sealed/package --artifact ci-out/regression-sealed/proposal-selection",
        ],
        &[
            "          GITHUB_TOKEN: ${{ secrets.REVIEW_AUTHORIZATION_GITHUB_TOKEN }}",
            "        run: ./target/ci/hell-ci review-authorization --input ci-in/regression-sealed/review-subject.json --output ci-out/regression-review/authorization.json --role regression-reviewer --category regression-final --github-dispatch-inputs",
        ],
        &[
            "          GITHUB_TOKEN: ${{ github.token }}",
            "          REGRESSION_PROVIDER_ARTIFACT_ID: ${{ needs.seal-review-subject.outputs.artifact_id }}",
            "          REGRESSION_PROVIDER_ARTIFACT_NAME: regression-review-subject-${{ github.run_id }}-${{ github.run_attempt }}",
            "          REGRESSION_PROVIDER_ARCHIVE_SHA256: ${{ needs.seal-review-subject.outputs.artifact_digest }}",
            "          REGRESSION_PROVIDER_DIRECTORY_SHA256: ${{ needs.seal-review-subject.outputs.directory_sha256 }}",
            "          REGRESSION_PROVIDER_EVENT: workflow_dispatch",
            "          REGRESSION_PROVIDER_HEAD_SHA: ${{ github.sha }}",
            "          REGRESSION_PROVIDER_RUN_ATTEMPT: ${{ github.run_attempt }}",
            "          REGRESSION_PROVIDER_RUN_ID: ${{ github.run_id }}",
            "          REGRESSION_PROVIDER_WORKFLOW_PATH: .github/workflows/regression-corpus.yml",
            "        run: ./target/ci/hell-ci regression-import select-subject --input ci-in/regression-sealed --output ci-out/regression-sealed-selection",
        ],
        &[
            "          GITHUB_TOKEN: ${{ github.token }}",
            "          REGRESSION_PROVIDER_CONTEXT: ${{ inputs.review_provider_context }}",
            "          REGRESSION_REQUIRED_WORKFLOW_PATH: .github/workflows/regression-corpus.yml",
            "        run: ./target/ci/hell-ci regression-import acquire-subject --output ci-in/regression-review --artifact ci-out/regression-review-selection",
        ],
        &[
            "          GITHUB_TOKEN: ${{ github.token }}",
            "          REGRESSION_PROVIDER_CONTEXT: ${{ inputs.subject_provider_context }}",
            "          REGRESSION_REQUIRED_WORKFLOW_PATH: .github/workflows/regression-corpus.yml",
            "        run: ./target/ci/hell-ci regression-import acquire-subject --output ci-in/reviewed-regression --artifact ci-out/reviewed-regression-selection",
        ],
        &[
            "          GH_TOKEN: ${{ github.token }}",
            "        run: gh auth setup-git",
        ],
    ];
    reviewed
        .iter()
        .any(|expected| following.starts_with(expected))
        || reviewed_automatic_regression_environment(following)
        || reviewed_automatic_subject_environment(following)
}

fn reviewed_regression_workflow(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(|value| value.to_str()),
        Some(
            "regression-subject.yml"
                | "regression-subject-shard.yml"
                | "regression-dispatch-shard.yml"
                | "regression-corpus.yml"
        )
    )
}

fn reviewed_automatic_regression_environment(following: &[&str]) -> bool {
    let suffixes = [
        (
            "${{ needs.prepare.outputs.artifact_id }}",
            "${{ needs.prepare.outputs.artifact_digest }}",
            "regression-proposal-${{ github.run_id }}-${{ github.run_attempt }}",
            "${{ needs.prepare.outputs.directory_sha256 }}",
            "ci-out/regression-sealed/package --output ci-out/regression-sealed/proposal-selection",
        ),
        (
            "${{ needs.seal-review-subject-automatic.outputs.artifact_id }}",
            "${{ needs.seal-review-subject-automatic.outputs.artifact_digest }}",
            "regression-review-subject-${{ github.run_id }}-${{ github.run_attempt }}",
            "${{ needs.seal-review-subject-automatic.outputs.directory_sha256 }}",
            "ci-in/regression-sealed --output ci-out/regression-sealed-selection",
        ),
        (
            "${{ needs.prepare.outputs.artifact_id }}",
            "${{ needs.prepare.outputs.artifact_digest }}",
            "regression-proposal-${{ github.run_id }}-${{ github.run_attempt }}",
            "${{ needs.prepare.outputs.directory_sha256 }}",
            "ci-in/regression-package --output ci-out/regression-package-selection",
        ),
        (
            "${{ needs.review-automatic.outputs.artifact_id }}",
            "${{ needs.review-automatic.outputs.artifact_digest }}",
            "regression-review-${{ github.run_id }}-${{ github.run_attempt }}",
            "${{ needs.review-automatic.outputs.directory_sha256 }}",
            "ci-in/regression-review --output ci-out/regression-review-selection",
        ),
        (
            "${{ needs.promote-automatic.outputs.artifact_id }}",
            "${{ needs.promote-automatic.outputs.artifact_digest }}",
            "reviewed-regression-${{ github.run_id }}-${{ github.run_attempt }}",
            "${{ needs.promote-automatic.outputs.directory_sha256 }}",
            "ci-in/reviewed-regression --output ci-out/reviewed-regression-selection",
        ),
    ];
    suffixes.iter().any(|(id, archive, name, digest, command)| {
        following.starts_with(&[
            "          GITHUB_TOKEN: ${{ github.token }}",
            &format!("          REGRESSION_PROVIDER_ARTIFACT_ID: {id}"),
            &format!("          REGRESSION_PROVIDER_ARTIFACT_NAME: {name}"),
            &format!("          REGRESSION_PROVIDER_ARCHIVE_SHA256: {archive}"),
            &format!("          REGRESSION_PROVIDER_DIRECTORY_SHA256: {digest}"),
            "          REGRESSION_PROVIDER_EVENT: workflow_dispatch",
            "          REGRESSION_PROVIDER_HEAD_SHA: ${{ github.sha }}",
            "          REGRESSION_PROVIDER_RUN_ATTEMPT: ${{ github.run_attempt }}",
            "          REGRESSION_PROVIDER_RUN_ID: ${{ github.run_id }}",
            "          REGRESSION_PROVIDER_WORKFLOW_PATH: .github/workflows/regression-corpus.yml",
            &format!(
                "        run: ./target/ci/hell-ci regression-import select-subject --input {command}"
            ),
        ])
    })
}

fn reviewed_automatic_subject_environment(following: &[&str]) -> bool {
    let exact = [
        &[
            "          GITHUB_TOKEN: ${{ github.token }}",
            "          REGRESSION_AUTOMATION_CANDIDATE: ${{ github.event.workflow_run.head_sha }}",
            "          REGRESSION_AUTOMATION_RUN_ID: ${{ github.event.workflow_run.id }}",
            "        run: ./target/ci/hell-ci regression-import resolve-automatic-source --role nightly --output ci-out/nightly-provider-context.json",
        ][..],
        &[
            "          GITHUB_TOKEN: ${{ github.token }}",
            "          REGRESSION_AUTOMATION_CANDIDATE: ${{ github.event.workflow_run.head_sha }}",
            "        run: ./target/ci/hell-ci regression-import resolve-automatic-source --role evidence --output ci-out/evidence-provider-context.json",
        ],
        &[
            "          GITHUB_TOKEN: ${{ github.token }}",
            "          REGRESSION_AUTOMATION_CANDIDATE: ${{ github.event.workflow_run.head_sha }}",
            "        run: ./target/ci/hell-ci regression-import resolve-automatic-source --role public --output ci-out/public-provider-context.json",
        ],
        &[
            "          REGRESSION_GENERATED_CASE: ${{ matrix.case_id }}",
            "          REGRESSION_TEMPLATE_CASE: ${{ matrix.template_case_id }}",
            "        run: ./target/ci/hell-ci regression-import assemble-generated-subject --program ci-in/program --input ci-in/evidence --proposal ci-in/public --findings ci-out/public-selection --expected \"$REGRESSION_TEMPLATE_CASE\" --issue \"$REGRESSION_GENERATED_CASE\" --artifact ci-out/program-selection --policy ci-out/evidence-selection --output ci-out/regression-subject",
        ],
        &[
            "          GITHUB_TOKEN: ${{ github.token }}",
            "          REGRESSION_PROVIDER_CONTEXT: ${{ inputs.nightly_provider_context }}",
            "          REGRESSION_REQUIRED_WORKFLOW_PATH: .github/workflows/nightly.yml",
            "        run: ./target/ci/hell-ci regression-import acquire-subject --output ci-in/program --artifact ci-out/program-selection",
        ],
        &[
            "          GITHUB_TOKEN: ${{ github.token }}",
            "          REGRESSION_PROVIDER_CONTEXT: ${{ inputs.evidence_provider_context }}",
            "          REGRESSION_REQUIRED_WORKFLOW_PATH: .github/workflows/promotion-evidence-review.yml",
            "        run: ./target/ci/hell-ci regression-import acquire-subject --output ci-in/evidence --artifact ci-out/evidence-selection",
        ],
        &[
            "          GITHUB_TOKEN: ${{ github.token }}",
            "          REGRESSION_PROVIDER_CONTEXT: ${{ inputs.public_provider_context }}",
            "          REGRESSION_REQUIRED_WORKFLOW_PATH: .github/workflows/promotion-surveillance.yml",
            "        run: ./target/ci/hell-ci regression-import acquire-subject --output ci-in/public --artifact ci-out/public-selection",
        ],
        &[
            "          GITHUB_TOKEN: ${{ github.token }}",
            "          REGRESSION_PROVIDER_CONTEXT: ${{ inputs.nightly_provider_context }}",
            "          REGRESSION_REQUIRED_WORKFLOW_PATH: .github/workflows/nightly.yml",
            "        run: ./target/ci/hell-ci regression-import acquire-subject --output ci-in/nightly --artifact ci-out/nightly-selection",
        ],
        &[
            "          GITHUB_TOKEN: ${{ github.token }}",
            "          REGRESSION_AUTOMATION_CANDIDATE: ${{ inputs.candidate_sha }}",
            "          REGRESSION_AUTOMATION_ISSUE: github-run:${{ inputs.nightly_run_id }}",
            "          REGRESSION_AUTOMATION_RUN_ID: ${{ github.run_id }}",
            "          REGRESSION_AUTOMATION_SHARD: ${{ inputs.shard_index }}",
            "        run: ./target/ci/hell-ci regression-import dispatch-automatic-shard --program ci-in/nightly",
        ],
        &[
            "          GITHUB_TOKEN: ${{ github.token }}",
            "        run: ./target/ci/hell-ci regression-import reconcile-automatic-batch --input ci-in/ready-set/automatic-regression-ready-set.json --program ci-in/program --artifact ci-out/program-selection --to ci-out/regression-batch",
        ],
        &[
            "          GITHUB_TOKEN: ${{ github.token }}",
            "          REGRESSION_PROVIDER_CONTEXT: ${{ needs.resolve-scheduled.outputs.nightly_provider_context }}",
            "          REGRESSION_REQUIRED_WORKFLOW_PATH: .github/workflows/nightly.yml",
            "        run: ./target/ci/hell-ci regression-import acquire-historical-subject --output ci-in/program --artifact ci-out/program-selection",
        ],
    ];
    let provider = [
        (
            "nightly_provider_context",
            ".github/workflows/nightly.yml",
            "program",
            "program-selection",
        ),
        (
            "evidence_provider_context",
            ".github/workflows/promotion-evidence-review.yml",
            "evidence",
            "evidence-selection",
        ),
        (
            "public_provider_context",
            ".github/workflows/promotion-surveillance.yml",
            "public",
            "public-selection",
        ),
    ];
    exact.iter().any(|expected| following.starts_with(expected))
        || provider.iter().any(|(context, workflow, subject, selection)| {
            following.starts_with(&[
                "          GITHUB_TOKEN: ${{ github.token }}".to_owned(),
                format!("          REGRESSION_PROVIDER_CONTEXT: ${{{{ needs.resolve-scheduled.outputs.{context} }}}}"),
                format!("          REGRESSION_REQUIRED_WORKFLOW_PATH: {workflow}"),
                format!("        run: ./target/ci/hell-ci regression-import acquire-subject --output ci-in/{subject} --artifact ci-out/{selection}"),
            ].iter().map(String::as_str).collect::<Vec<_>>())
        })
}

fn reviewed_prior_public_promotion(
    path: &Path,
    lines: &[&str],
    index: usize,
    original: &str,
) -> bool {
    path == workflow_path("promotion-evidence-review.yml")
        && original == "        env:"
        && lines.get(index + 1)
            == Some(
                &"          PUBLIC_COMPATIBILITY_REPORT_BASE_URL: ${{ vars.PUBLIC_COMPATIBILITY_REPORT_BASE_URL }}",
            )
        && lines.get(index + 2)
            == Some(
                &"        run: ./target/ci/hell-ci custody-ops workflow-retain-prior-public-transition",
            )
}

fn reviewed_active_subject_selection(
    path: &Path,
    lines: &[&str],
    index: usize,
    original: &str,
) -> bool {
    path == workflow_path("promotion-surveillance.yml")
        && original == "        env:"
        && lines.get(index + 1)
            == Some(
                &"          ACTIVE_SUBJECT_ARTIFACT_ID: ${{ needs.execute-active-subject.outputs.artifact_id }}",
            )
        && lines.get(index + 2)
            == Some(
                &"          ACTIVE_SUBJECT_ARCHIVE_SHA256: ${{ needs.execute-active-subject.outputs.artifact_digest }}",
            )
        && lines.get(index + 3) == Some(&"          GITHUB_TOKEN: ${{ github.token }}")
        && lines.get(index + 4)
            == Some(
                &"        run: ./target/ci/hell-ci surveillance-ops workflow-active-subject-selection",
            )
}

fn reviewed_oracle_provider_selection(
    path: &Path,
    lines: &[&str],
    index: usize,
    original: &str,
) -> bool {
    if path != workflow_path("oracle-reproduce.yml") || original != "        env:" {
        return false;
    }
    if lines.get(index + 1) != Some(&"          GITHUB_TOKEN: ${{ github.token }}") {
        return false;
    }
    let command = if lines.get(index + 2).is_some_and(|line| {
        line.starts_with("        run: ./target/ci/hell-ci oracle-ops workflow-")
    }) {
        lines[index + 2]
    } else if lines.get(index + 2).is_some_and(|line| {
        line.starts_with("          ORACLE_UNSIGNED_ARCHIVE_SHA256: ${{ steps.resolve-")
    }) && lines.get(index + 3).is_some_and(|line| {
        line.starts_with("          ORACLE_UNSIGNED_ARTIFACT_ID: ${{ steps.resolve-")
    }) {
        lines.get(index + 4).copied().unwrap_or_default()
    } else {
        return false;
    };
    command.starts_with("        run: ./target/ci/hell-ci oracle-ops workflow-primary-resolve-")
        || command.starts_with(
            "        run: ./target/ci/hell-ci oracle-ops workflow-independent-resolve-",
        )
        || command
            .starts_with("        run: ./target/ci/hell-ci oracle-ops workflow-primary-select-")
        || command
            .starts_with("        run: ./target/ci/hell-ci oracle-ops workflow-independent-select-")
}

fn check_workflow_dispatch_input_limit(path: &Path, lines: &[&str], failures: &mut Vec<String>) {
    const MAXIMUM_WORKFLOW_DISPATCH_INPUTS: usize = 25;
    let Some(dispatch_index) = lines
        .iter()
        .position(|line| strip_yaml_comment(line).trim() == "workflow_dispatch:")
    else {
        return;
    };
    let Some(inputs_index) = lines
        .iter()
        .enumerate()
        .skip(dispatch_index + 1)
        .take_while(|(_, line)| yaml_indentation(line) > 2 || line.trim().is_empty())
        .find_map(|(index, line)| {
            (yaml_indentation(line) == 4 && strip_yaml_comment(line).trim() == "inputs:")
                .then_some(index)
        })
    else {
        return;
    };
    let count = lines
        .iter()
        .skip(inputs_index + 1)
        .take_while(|line| yaml_indentation(line) > 4 || line.trim().is_empty())
        .filter(|line| {
            yaml_indentation(line) == 6
                && yaml_mapping_key(strip_yaml_comment(line).trim()).is_some()
        })
        .count();
    if count > MAXIMUM_WORKFLOW_DISPATCH_INPUTS {
        failures.push(format!(
            "workflow declares {count} workflow_dispatch inputs, exceeding GitHub's {MAXIMUM_WORKFLOW_DISPATCH_INPUTS}-input limit at {}:{}",
            path.display(),
            inputs_index + 1
        ));
    }
}

fn yaml_indentation(line: &str) -> usize {
    let uncommented = strip_yaml_comment(line);
    uncommented.len() - uncommented.trim_start_matches(' ').len()
}

fn check_protected_job_trust_isolation(path: &Path, lines: &[&str], failures: &mut Vec<String>) {
    let Some(jobs_index) = lines
        .iter()
        .position(|line| strip_yaml_comment(line).trim() == "jobs:")
    else {
        return;
    };
    let inherited_protection = lines[..jobs_index].iter().any(|line| {
        matches!(
            strip_yaml_comment(line).trim(),
            "id-token: write" | "actions: write"
        )
    });
    let accepts_workflow_dispatch = lines[..jobs_index]
        .iter()
        .any(|line| strip_yaml_comment(line).trim() == "workflow_dispatch:");
    let accepts_workflow_call = lines[..jobs_index]
        .iter()
        .any(|line| strip_yaml_comment(line).trim() == "workflow_call:");
    let job_starts = lines
        .iter()
        .enumerate()
        .skip(jobs_index + 1)
        .filter_map(|(index, line)| {
            (yaml_indentation(line) == 2
                && yaml_mapping_key(strip_yaml_comment(line).trim()).is_some())
            .then_some(index)
        })
        .collect::<Vec<_>>();
    for (position, start) in job_starts.iter().copied().enumerate() {
        let end = job_starts.get(position + 1).copied().unwrap_or(lines.len());
        let block = &lines[start..end];
        let overrides_permissions = block.iter().any(|line| {
            yaml_indentation(line) == 4 && strip_yaml_comment(line).trim() == "permissions:"
        });
        let protected = protected_job(block, inherited_protection, overrides_permissions);
        if !protected {
            continue;
        }
        let job = yaml_mapping_key(strip_yaml_comment(lines[start]).trim()).unwrap_or("unknown");
        if accepts_workflow_dispatch
            && !block.iter().any(|line| {
                yaml_indentation(line) == 4
                    && yaml_key(strip_yaml_comment(line).trim(), "if")
                        .is_some_and(main_ref_is_and_conjunct)
            })
        {
            failures.push(format!(
                "protected workflow_dispatch job {job:?} lacks an exact main-ref guard at {}:{}",
                path.display(),
                start + 1
            ));
        }
        if accepts_workflow_call
            && !block.iter().any(|line| {
                yaml_indentation(line) == 4
                    && yaml_key(strip_yaml_comment(line).trim(), "if").is_some_and(|condition| {
                        trusted_workflow_caller_is_and_conjunct(condition)
                            || trusted_transport_probe_caller_is_and_conjunct(path, condition)
                    })
            })
        {
            failures.push(format!(
                "protected workflow_call job {job:?} lacks an exact trusted-main caller guard at {}:{}",
                path.display(),
                start + 1
            ));
        }
        for (offset, line) in block.iter().enumerate() {
            let compact = strip_yaml_comment(line).trim().replace(' ', "");
            if compact.contains("ref:${{inputs.candidate_sha")
                || compact.contains("inputs.candidate_sha||github.sha")
                || compact == "clean:false"
            {
                failures.push(format!(
                    "protected job {job:?} uses a candidate-controlled checkout/workspace at {}:{}",
                    path.display(),
                    start + offset + 1
                ));
            }
        }
        let first_build = block
            .iter()
            .position(|line| strip_yaml_comment(line).contains("cargo build"));
        let first_credential = block.iter().position(|line| {
            let value = strip_yaml_comment(line);
            value.contains("aws-actions/configure-aws-credentials@")
                || value.contains("webfactory/ssh-agent@")
                || value.contains("secrets.")
        });
        if first_build.is_some_and(|build| first_credential.is_some_and(|secret| build > secret)) {
            failures.push(format!(
                "protected job {job:?} builds automation after acquiring credentials at {}:{}",
                path.display(),
                start + first_build.unwrap_or_default() + 1
            ));
        }
        check_review_signing_credential_order(path, job, block, start, failures);
        check_provider_receipt_signing_order(path, job, block, start, failures);
        check_state_transition_signing_order(path, job, block, start, failures);
    }
}

fn check_state_transition_signing_order(
    path: &Path,
    job: &str,
    block: &[&str],
    start: usize,
    failures: &mut Vec<String>,
) {
    let packet = block
        .iter()
        .position(|line| line.contains("custody-ops workflow-transition-packet"));
    let credential = block
        .iter()
        .position(|line| line.contains("uses: webfactory/ssh-agent@"));
    let signature = block.iter().position(|line| {
        line.contains("run: ./target/ci/hell-ci review-sign ")
            && line.contains("promotion-transition-packet.json")
    });
    if packet.is_some()
        && !matches!(
            (packet, credential, signature),
            (Some(packet), Some(credential), Some(signature))
                if packet < credential && credential < signature
        )
    {
        failures.push(format!(
            "protected state transition job {job:?} must finalize its exact packet before loading signing credentials at {}:{}",
            path.display(),
            start + 1
        ));
    }
}

fn check_provider_receipt_signing_order(
    path: &Path,
    job: &str,
    block: &[&str],
    start: usize,
    failures: &mut Vec<String>,
) {
    let first_credential = block
        .iter()
        .position(|line| line.contains("uses: webfactory/ssh-agent@"));
    let first_signature = block.iter().position(|line| {
        line.contains("run: ./target/ci/hell-ci review-sign ")
            && line.contains(" --role custody-provider ")
    });
    let packet = block.iter().rposition(|line| {
        line.contains("run: ./target/ci/hell-ci custody-ops workflow-") && line.contains("packet")
    });
    let provider_signing_job = block
        .iter()
        .any(|line| line.contains("run: ./target/ci/hell-ci custody-ops workflow-"))
        && first_signature.is_some()
        && first_credential.is_some();
    if provider_signing_job
        && !matches!(
            (packet, first_credential, first_signature),
            (Some(packet), Some(credential), Some(signature))
                if packet < credential && credential < signature
        )
    {
        failures.push(format!(
            "protected provider job {job:?} must finalize its typed receipt packet before loading signing credentials at {}:{}",
            path.display(),
            start + 1
        ));
    }
}

fn check_review_signing_credential_order(
    path: &Path,
    job: &str,
    block: &[&str],
    start: usize,
    failures: &mut Vec<String>,
) {
    let authorizations = block
        .iter()
        .enumerate()
        .filter_map(|(index, line)| {
            line.contains("run: ./target/ci/hell-ci review-authorization ")
                .then_some(index)
        })
        .collect::<Vec<_>>();
    let signing_credentials = block
        .iter()
        .enumerate()
        .filter_map(|(index, line)| {
            (line.contains("uses: webfactory/ssh-agent@")
                || line.contains("uses: sigstore/cosign-installer@"))
            .then_some(index)
        })
        .collect::<Vec<_>>();
    if authorizations.is_empty() || signing_credentials.is_empty() {
        return;
    }
    let finalizations = block
        .iter()
        .enumerate()
        .filter_map(|(index, line)| {
            line.contains("run: ./target/ci/hell-ci review-packet ")
                .then_some(index)
        })
        .collect::<Vec<_>>();
    let downloads = block
        .iter()
        .enumerate()
        .filter_map(|(index, line)| {
            line.contains("uses: actions/download-artifact@")
                .then_some(index)
        })
        .collect::<Vec<_>>();
    let signatures = block
        .iter()
        .enumerate()
        .filter_map(|(index, line)| {
            line.contains("run: ./target/ci/hell-ci review-sign ")
                .then_some(index)
        })
        .collect::<Vec<_>>();
    let first_authorization = authorizations[0];
    let last_authorization = *authorizations.last().unwrap_or(&first_authorization);
    let first_credential = signing_credentials[0];
    let packet_before_credentials = finalizations
        .iter()
        .copied()
        .filter(|packet| *packet < first_credential)
        .max();
    let first_download = downloads.first().copied();
    let first_signature = signatures.first().copied();
    let valid = first_download.is_none_or(|download| download < first_authorization)
        && packet_before_credentials.is_some_and(|packet| last_authorization < packet)
        && first_signature.is_some_and(|signature| first_credential < signature)
        && signing_credentials
            .iter()
            .all(|credential| packet_before_credentials.is_some_and(|packet| packet < *credential));
    if !valid {
        failures.push(format!(
            "protected review job {job:?} must download and authorize its exact subject, finalize its review packet, then load signing credentials before signing at {}:{}",
            path.display(),
            start + 1
        ));
    }
}

fn protected_job(block: &[&str], inherited: bool, overrides: bool) -> bool {
    (inherited && !overrides)
        || block.iter().any(|line| {
            let trimmed = strip_yaml_comment(line).trim();
            trimmed == "id-token: write"
                || trimmed == "actions: write"
                || trimmed.starts_with("environment:")
                || trimmed.contains("aws-actions/configure-aws-credentials@")
                || trimmed.contains("webfactory/ssh-agent@")
                || trimmed.contains("secrets.")
        })
}

fn trusted_workflow_caller_is_and_conjunct(condition: &str) -> bool {
    let expression = condition
        .trim()
        .trim_start_matches("${{")
        .trim_end_matches("}}");
    !expression.contains("||")
        && expression.contains("github.ref == 'refs/heads/main'")
        && expression.contains("github.event_name == 'workflow_run'")
        && expression.contains("github.workflow_ref == 'Portfoligno/hell-rs/.github/workflows/")
        && expression.contains("@refs/heads/main'")
}

fn trusted_transport_probe_caller_is_and_conjunct(path: &Path, condition: &str) -> bool {
    if !matches!(
        path.file_name().and_then(|value| value.to_str()),
        Some("assurance-transport-signer-a.yml" | "assurance-transport-signer-b.yml")
    ) {
        return false;
    }
    let expression = condition
        .trim()
        .trim_start_matches("${{")
        .trim_end_matches("}}");
    !expression.contains("||")
        && expression.contains("github.event_name == 'workflow_dispatch'")
        && expression.contains("github.ref == 'refs/heads/main'")
        && expression.contains(
            "github.workflow_ref == 'Portfoligno/hell-rs/.github/workflows/assurance-transport-readiness.yml@refs/heads/main'",
        )
}

fn main_ref_is_and_conjunct(condition: &str) -> bool {
    let expression = condition
        .trim()
        .trim_start_matches("${{")
        .trim_end_matches("}}")
        .trim();
    let bytes = expression.as_bytes();
    let mut depth = 0_usize;
    let mut start = 0_usize;
    let mut main = false;
    let mut index = 0_usize;
    while index < bytes.len() {
        match bytes[index] {
            b'(' => depth = depth.saturating_add(1),
            b')' => {
                let Some(next) = depth.checked_sub(1) else {
                    return false;
                };
                depth = next;
            }
            b'|' if depth == 0 && bytes.get(index + 1) == Some(&b'|') => return false,
            b'&' if depth == 0 && bytes.get(index + 1) == Some(&b'&') => {
                main |= expression[start..index].trim() == "github.ref == 'refs/heads/main'";
                index = index.saturating_add(1);
                start = index.saturating_add(1);
            }
            _ => {}
        }
        index = index.saturating_add(1);
    }
    depth == 0 && (main || expression[start..].trim() == "github.ref == 'refs/heads/main'")
}

fn reviewed_initial_surveillance_finalizer(
    path: &Path,
    lines: &[&str],
    index: usize,
    original: &str,
) -> bool {
    if path.file_name().and_then(|name| name.to_str())
        != Some("promotion-initial-public-finalize.yml")
        || original != "        env:"
    {
        return false;
    }
    lines.get(index + 1) == Some(&"          GITHUB_TOKEN: ${{ github.token }}")
        && lines.get(index + 2)
            == Some(&"          INITIAL_SURVEILLANCE_RUN_ID: ${{ inputs.surveillance_run_id }}")
        && lines.get(index + 3)
            == Some(
                &"          INITIAL_SURVEILLANCE_RUN_ATTEMPT: ${{ inputs.surveillance_run_attempt }}",
            )
        && lines.get(index + 4)
            == Some(
                &"          PUBLIC_COMPATIBILITY_REPORT_BASE_URL: ${{ vars.PUBLIC_COMPATIBILITY_REPORT_BASE_URL }}",
            )
        && lines.get(index + 5)
            == Some(
                &"        run: ./target/ci/hell-ci custody-ops workflow-finalize-initial-surveillance",
            )
}

fn reviewed_public_report_configuration(
    path: &Path,
    lines: &[&str],
    index: usize,
    original: &str,
) -> bool {
    let source_artifact = match path.file_name().and_then(|name| name.to_str()) {
        Some("promotion-surveillance.yml") => {
            "          PUBLIC_REPORT_SOURCE_ARTIFACT_ID: ${{ needs.verify-and-transition.outputs.transition_artifact_id }}"
        }
        Some("promotion-surveillance-watchdog.yml") => {
            "          PUBLIC_REPORT_SOURCE_ARTIFACT_ID: ${{ needs.deadline.outputs.transition_artifact_id }}"
        }
        _ => return false,
    };
    if original != "        env:" {
        return false;
    }
    if lines.get(index + 1) == Some(&"          GITHUB_TOKEN: ${{ github.token }}")
        && lines.get(index + 2)
            == Some(
                &"          PUBLIC_COMPATIBILITY_REPORT_BASE_URL: ${{ vars.PUBLIC_COMPATIBILITY_REPORT_BASE_URL }}",
            )
    {
        return lines.get(index + 3)
            == Some(
                &"        run: ./target/ci/hell-ci custody-ops workflow-observe-public-transition",
            );
    }
    if lines.get(index + 1) != Some(&"          GITHUB_TOKEN: ${{ github.token }}") {
        return false;
    }
    (lines.get(index + 2) == Some(&source_artifact)
        && lines.get(index + 3)
            == Some(
                &"        run: ./target/ci/hell-ci custody-ops workflow-verify-public-source-artifact",
            ))
        || (lines.get(index + 2)
            == Some(
                &"          PUBLIC_COMPATIBILITY_REPORT_BUCKET: ${{ vars.PUBLIC_COMPATIBILITY_REPORT_BUCKET }}",
            )
            && lines.get(index + 3)
                == Some(
                    &"          PUBLIC_COMPATIBILITY_REPORT_BASE_URL: ${{ vars.PUBLIC_COMPATIBILITY_REPORT_BASE_URL }}",
                )
            && lines.get(index + 4) == Some(&source_artifact)
            && lines.get(index + 5)
                == Some(
                    &"        run: ./target/ci/hell-ci custody-ops workflow-publish-public-transition",
                ))
}

fn reviewed_external_acquisition_configuration(
    path: &Path,
    lines: &[&str],
    index: usize,
    original: &str,
) -> bool {
    if path != workflow_path("artifact-independent-acquisition.yml") || original != "        env:" {
        return false;
    }
    let preparation = lines.get(index + 1)
        == Some(
            &"          ARTIFACT_INDEPENDENT_ARCHIVE_SHA256: ${{ vars.ARTIFACT_INDEPENDENT_ARCHIVE_SHA256 }}",
        )
        && lines.get(index + 2)
            == Some(
                &"          ARTIFACT_INDEPENDENT_BUCKET: ${{ vars.ARTIFACT_INDEPENDENT_BUCKET }}",
            )
        && lines.get(index + 3)
            == Some(&"          ARTIFACT_INDEPENDENT_KEY: ${{ vars.ARTIFACT_INDEPENDENT_KEY }}")
        && lines.get(index + 4)
            == Some(
                &"          ARTIFACT_INDEPENDENT_REGION: ${{ vars.ARTIFACT_INDEPENDENT_REGION }}",
            )
        && lines.get(index + 5)
            == Some(
                &"          ARTIFACT_INDEPENDENT_VERSION_ID: ${{ vars.ARTIFACT_INDEPENDENT_VERSION_ID }}",
            )
        && lines.get(index + 6)
            == Some(
                &"        run: ./target/ci/hell-ci artifact-acquire prepare-external-independent --output ci-out/acquisition/external-independent-request.json --artifact native-oracle-merged --github-dispatch-inputs",
            );
    let execution = lines.get(index + 1) == Some(&"          GH_TOKEN: ${{ github.token }}")
        && lines.get(index + 2)
            == Some(
                &"        run: ./target/ci/hell-ci artifact-acquire external-independent --input ci-out/acquisition/external-independent-request.json --output ci-out/acquisition/receipt-independent.json --artifact native-oracle-merged",
            );
    preparation || execution
}

fn check_external_independent_preflight(workflow: &str, failures: &mut Vec<String>) {
    let Some(prepare) = workflow_job_lines(workflow, "prepare-request") else {
        failures.push(
            "independent acquisition lacks unprivileged sealed request preparation".to_owned(),
        );
        return;
    };
    let Some(execute) = workflow_job_lines(workflow, "acquire") else {
        failures
            .push("independent acquisition lacks protected sealed request execution".to_owned());
        return;
    };
    let prepare = prepare.join("\n");
    let execute = execute.join("\n");
    let prepare_command = "run: ./target/ci/hell-ci artifact-acquire prepare-external-independent --output ci-out/acquisition/external-independent-request.json --artifact native-oracle-merged --github-dispatch-inputs";
    let verify_command = "run: ./target/ci/hell-ci artifact-acquire verify-external-independent-request --input ci-out/acquisition/external-independent-request.json --artifact native-oracle-merged";
    let execute_command = "run: ./target/ci/hell-ci artifact-acquire external-independent --input ci-out/acquisition/external-independent-request.json --output ci-out/acquisition/receipt-independent.json --artifact native-oracle-merged";
    let order = [
        "run: cargo build --locked --profile ci --package hell-ci --bin hell-ci",
        "artifact-ids: ${{ needs.prepare-request.outputs.request_artifact_id }}",
        verify_command,
        "uses: aws-actions/configure-aws-credentials@e6de054238d6b7531b4efff3b6587d9aade6a06c # v6.2.3",
        execute_command,
    ];
    if workflow.matches("source_artifact_id:").count() != 1
        || prepare.matches(prepare_command).count() != 1
        || prepare.contains("id-token: write")
        || prepare.contains("environment: artifact-independent-acquisition")
        || prepare.contains("configure-aws-credentials")
        || prepare.contains("GH_TOKEN:")
        || prepare.matches("id: upload-request").count() != 1
        || prepare
            .matches("request_artifact_id: ${{ steps.upload-request.outputs.artifact-id }}")
            .count()
            != 1
        || prepare
            .matches("request_artifact_digest: ${{ steps.upload-request.outputs.artifact-digest }}")
            .count()
            != 1
        || prepare
            .matches("            ci-out/acquisition/external-independent-request.json\n")
            .count()
            != 1
        || prepare
            .matches("            ci-out/acquisition/external-independent-request.json.sha256\n")
            .count()
            != 1
        || execute.matches("needs: prepare-request").count() != 1
        || execute.matches("id-token: write").count() != 1
        || execute
            .matches("environment: artifact-independent-acquisition")
            .count()
            != 1
        || execute.matches(verify_command).count() != 1
        || execute.matches(execute_command).count() != 1
        || execute.contains("--github-dispatch-inputs")
        || execute.contains("ARTIFACT_INDEPENDENT_BUCKET:")
        || execute.contains("ARTIFACT_INDEPENDENT_KEY:")
        || !markers_are_ordered(&execute, &order)
    {
        failures.push(
            "independent acquisition does not validate one needs-linked sealed request before credentials"
                .to_owned(),
        );
    }
}

fn check_collection_activation_review(workflow: &str, failures: &mut Vec<String>) {
    let Some(retain) = workflow_job_lines(workflow, "retain-proposal") else {
        failures.push("collection activation review lacks outer proposal retention".to_owned());
        return;
    };
    let Some(author) = workflow_job_lines(workflow, "claim-author") else {
        failures.push("collection activation review lacks protected claim author".to_owned());
        return;
    };
    let Some(reviewer) = workflow_job_lines(workflow, "claim-reviewer") else {
        failures.push("collection activation review lacks independent claim reviewer".to_owned());
        return;
    };
    let Some(finalize) = workflow_job_lines(workflow, "finalize-commit-ready-tree") else {
        failures.push("collection activation review lacks unprivileged finalizer".to_owned());
        return;
    };
    let retain = retain.join("\n");
    let author = author.join("\n");
    let reviewer = reviewer.join("\n");
    let finalize = finalize.join("\n");
    let verify = "collection-authority verify-activation-preparation --input ci-in/collection-activation-proposal";
    let verify_review_subject = "collection-authority verify-activation-review-subject --input ci-in/collection-activation-review-subject --expected-directory-sha256 \"$WRAPPER_DIRECTORY_SHA256\"";
    let author_authorization = "review-authorization --input ci-in/collection-activation-review-subject/review-subject.json --output ci-out/collection-activation-review/claim-author/authorization.json --role claim-author --category collection-activation-author --github-dispatch-inputs";
    let author_packet = "review-packet --input ci-in/collection-activation-review-subject/review-subject.json --from ci-out/collection-activation-review/claim-author/authorization.json --output ci-out/collection-activation-review/claim-author/review-packet.json --role claim-author --category collection-activation-author --decision accept --github-dispatch-inputs";
    let reviewer_authorization = "review-authorization --input ci-in/collection-activation-review-subject/review-subject.json --output ci-out/collection-activation-review/claim-reviewer/authorization.json --role claim-reviewer --category collection-activation-final --github-dispatch-inputs";
    let reviewer_packet = "review-packet --input ci-in/collection-activation-review-subject/review-subject.json --from ci-out/collection-activation-review/claim-reviewer/authorization.json --output ci-out/collection-activation-review/claim-reviewer/review-packet.json --role claim-reviewer --category collection-activation-final --decision accept --github-dispatch-inputs";
    if !activation_review_structure_exact(
        workflow,
        &retain,
        &author,
        &reviewer,
        &finalize,
        &ActivationReviewMarkers {
            verify,
            verify_subject: verify_review_subject,
            author_authorization,
            author_packet,
            reviewer_authorization,
            reviewer_packet,
        },
    ) {
        failures.push("collection activation review is not an exact two-role non-authoritative commit-ready handoff".to_owned());
    }
}

struct ActivationReviewMarkers<'a> {
    verify: &'a str,
    verify_subject: &'a str,
    author_authorization: &'a str,
    author_packet: &'a str,
    reviewer_authorization: &'a str,
    reviewer_packet: &'a str,
}

fn activation_review_structure_exact(
    workflow: &str,
    retain: &str,
    author: &str,
    reviewer: &str,
    finalize: &str,
    markers: &ActivationReviewMarkers<'_>,
) -> bool {
    workflow.starts_with("name: Collection Activation Review\n\non:\n  workflow_dispatch:\n")
        && workflow.matches("  workflow_dispatch:").count() == 1
        && !workflow.contains("  push:")
        && !workflow.contains("contents: write")
        && !workflow.contains("git push")
        && !workflow.contains("promotionAuthority: true")
        && workflow
            .matches("collection-authority verify-checkout --input . --candidate-commit \"$COLLECTION_ACTIVATION_SHA\"")
            .count()
            == 4
        && retain.matches(markers.verify).count() == 1
        && retain.matches("GITHUB_TOKEN: ${{ github.token }}").count() == 1
        && markers_are_ordered(
            retain,
            &[
                markers.verify,
                "id: bind-review-subject",
                "path: ci-out/collection-activation-review-subject",
            ],
        )
        && retain.contains("artifact_digest: ${{ steps.upload-proposal.outputs.artifact-digest }}")
        && retain
            .contains("directory_sha256: ${{ steps.bind-review-subject.outputs.directory_sha256 }}")
        && retain
            .matches(
                "collection-activation-proposal-${{ github.run_id }}-${{ github.run_attempt }}",
            )
            .count()
            == 1
        && author
            .matches("environment: compatibility-claim-author")
            .count()
            == 1
        && reviewer
            .matches("environment: compatibility-claim-review")
            .count()
            == 1
        && author.matches("--role claim-author").count() == 3
        && !author.contains("--role claim-reviewer")
        && reviewer.matches("--role claim-reviewer").count() == 3
        && !reviewer.contains("--role claim-author")
        && !author.contains(markers.verify)
        && !reviewer.contains(markers.verify)
        && workflow.matches(markers.verify_subject).count() == 3
        && workflow
            .matches("WRAPPER_DIRECTORY_SHA256: ${{ needs.retain-proposal.outputs.directory_sha256 }}")
            .count()
            == 3
        && workflow
            .matches("artifact-ids: ${{ needs.retain-proposal.outputs.artifact_id }}")
            .count()
            == 3
        && activation_signer_exact(
            author,
            markers.verify_subject,
            markers.author_authorization,
            markers.author_packet,
            "claim-author",
        )
        && activation_signer_exact(
            reviewer,
            markers.verify_subject,
            markers.reviewer_authorization,
            markers.reviewer_packet,
            "claim-reviewer",
        )
        && author
            .matches("secrets.CLAIM_AUTHOR_SSH_PRIVATE_KEY")
            .count()
            == 1
        && reviewer
            .matches("secrets.CLAIM_REVIEWER_SSH_PRIVATE_KEY")
            .count()
            == 1
        && !finalize.contains("environment:")
        && !finalize.contains("id-token: write")
        && activation_finalizer_exact(finalize, markers.verify_subject)
}

fn activation_signer_exact(
    job: &str,
    verify_subject: &str,
    authorization: &str,
    packet: &str,
    role: &str,
) -> bool {
    let sign = format!(
        "review-sign --input ci-out/collection-activation-review/{role}/review-packet.json"
    );
    let bind = format!(
        "run: ./target/ci/hell-ci regression-import emit-directory-output --input ci-out/collection-activation-review/{role}"
    );
    markers_are_ordered(
        job,
        &[
            "path: ci-in/collection-activation-review-subject",
            verify_subject,
            authorization,
            packet,
            "sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6 # v4.1.2",
            "webfactory/ssh-agent@",
            &sign,
            &bind,
            "id: upload-review",
        ],
    ) && job
        .matches("artifact_id: ${{ steps.upload-review.outputs.artifact-id }}")
        .count()
        == 1
        && job
            .matches("artifact_digest: ${{ steps.upload-review.outputs.artifact-digest }}")
            .count()
            == 1
        && job
            .matches("directory_sha256: ${{ steps.bind-review.outputs.directory_sha256 }}")
            .count()
            == 1
}

fn activation_finalizer_exact(finalize: &str, verify_subject: &str) -> bool {
    markers_are_ordered(
        finalize,
        &[
            "needs.retain-proposal.outputs.artifact_id",
            verify_subject,
            "needs.claim-author.outputs.artifact_id",
            "needs.claim-reviewer.outputs.artifact_id",
            "sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6 # v4.1.2",
            "collection-authority finalize-activation --input ci-in/collection-activation-review-subject --signature ci-in/collection-activation-review/claim-author --integration-review ci-in/collection-activation-review/claim-reviewer --output ci-out/collection-activation-tree",
            "id: bind-tree",
            "id: upload-tree",
        ],
    ) && finalize
        .matches("tree_artifact_id: ${{ steps.upload-tree.outputs.artifact-id }}")
        .count()
        == 1
        && finalize
            .matches("tree_artifact_digest: ${{ steps.upload-tree.outputs.artifact-digest }}")
            .count()
            == 1
        && finalize
            .matches("tree_directory_sha256: ${{ steps.bind-tree.outputs.directory_sha256 }}")
            .count()
            == 1
}

fn reviewed_provider_metadata_token_binding(
    path: &Path,
    lines: &[&str],
    index: usize,
    original: &str,
) -> bool {
    path == workflow_path("artifact-authenticity-review.yml")
        && original == "        env:"
        && lines.get(index + 1) == Some(&"          GH_TOKEN: ${{ github.token }}")
        && lines.get(index + 2)
            == Some(
                &"        run: ./target/ci/hell-ci artifact-acquire primary --input ci-out/acquisition/primary --output ci-out/acquisition/receipt-primary.json --artifact native-oracle-merged --github-dispatch-inputs",
            )
        && lines[..index]
            .iter()
            .rev()
            .take(2)
            .any(|line| *line == "      - name: Record primary acquisition receipt")
}

fn reviewed_provider_replay_token_binding(
    path: &Path,
    lines: &[&str],
    index: usize,
    original: &str,
) -> bool {
    if original != "        env:"
        || lines.get(index + 1) != Some(&"          GITHUB_TOKEN: ${{ github.token }}")
    {
        return false;
    }
    let run = lines.get(index + 2).copied().unwrap_or_default();
    matches!(
        (path, run),
        (
            path,
            "        run: ./target/ci/hell-ci case-coverage prepare-decisions --input ci-out/evidence/claim-decisions/source/claim-coverage.details.json --from decision-source/compat/reviews/claim-applicability-decisions.json --output ci-out/evidence/claim-decisions/claim-applicability-decisions.json --github-dispatch-inputs"
        ) if path == workflow_path("claim-applicability-decisions.yml")
    ) || matches!(
        (path, run),
        (
            path,
            "        run: ./target/ci/hell-ci review-assemble prepare --github-dispatch-inputs"
        ) if path == workflow_path("promotion-evidence-review.yml")
    ) || matches!(
        (path, run),
        (
            path,
            "        run: ./target/ci/hell-ci promotion-proposal --input ci-out/native-shards --output ci-out/native-shards/promotion-proposal.json --github-dispatch-inputs"
        ) if path == workflow_path("promotion-proposal.yml")
    ) || matches!(
        (path, run),
        (
            path,
            "        run: ./target/ci/hell-ci promotion-approval-subject --input ci-out/native-shards/promotion-proposal.json --output ci-out/native-shards/promotion-approval-subject.json"
        ) if path == workflow_path("promotion-approval.yml")
    ) || matches!(
        (path, run),
        (
            path,
            "        run: ./target/ci/hell-ci artifact-acquire assemble-finalize --input ci-out/finalize-source --output ci-out/acquisition --github-dispatch-inputs"
        ) if path == workflow_path("artifact-authenticity-finalize.yml")
    ) || matches!(
        (path, run),
        (
            path,
            "        run: ./target/ci/hell-ci surveillance-ops workflow-objective"
        ) if path == workflow_path("promotion-surveillance.yml")
    )
}

fn check_offline_packet_verifier_order(path: &Path, lines: &[&str], failures: &mut Vec<String>) {
    if path != workflow_path("evidence-custody.yml")
        || lines.first() != Some(&"name: Durable evidence custody")
    {
        return;
    }
    let required = [
        "        run: ./target/ci/hell-ci custody-ops workflow-materialize-review-package",
        "        run: ./target/ci/hell-ci mutation verify --input ci-out/evidence/coverage/mutation-score.json --policy compat/reviews.allowed_signers",
        "        run: ./target/ci/hell-ci oracle-provenance verify --input ci-out/evidence/provenance/macos-arm64/oracle-provenance.json --policy compat/reviews.allowed_signers",
        "        run: ./target/ci/hell-ci oracle-provenance verify --input ci-out/evidence/provenance/windows-amd64/oracle-provenance.json --policy compat/reviews.allowed_signers",
        "        run: ./target/ci/hell-ci custody verify --input ci-out/evidence/custody/custody-receipt.json --policy compat/reviews.allowed_signers",
        "        run: ./target/ci/hell-ci review-graph --input ci-out --output ci-out/evidence/review/role-graph.details.json --policy compat/reviews.allowed_signers",
        "        run: ./target/ci/hell-ci offline-review-ops workflow-manifest",
    ];
    let mut prior = None;
    for command in required {
        let Some(index) = lines.iter().position(|line| *line == command) else {
            failures.push(format!(
                "offline packet omits required source verifier {command:?}"
            ));
            continue;
        };
        if prior.is_some_and(|previous| index <= previous) {
            failures.push("offline packet source verifiers are misordered".to_owned());
        }
        prior = Some(index);
    }
}

fn check_cache_scope(
    workflow_path: &Path,
    lines: &[&str],
    action_index: usize,
    location: &str,
    failures: &mut Vec<String>,
) {
    let paths = cache_paths(lines, action_index);
    let rust_target_paths = paths
        .iter()
        .filter(|path| {
            **path == "target"
                || path.starts_with("target/ci")
                || path.starts_with("target/release")
        })
        .count();
    let stack_work_paths = paths
        .iter()
        .filter(|path| path.ends_with("/.stack-work"))
        .count();
    if rust_target_paths == 0 && stack_work_paths == 0 {
        return;
    }
    if rust_target_paths.saturating_add(stack_work_paths) != paths.len()
        || (rust_target_paths != 0 && stack_work_paths != 0)
    {
        failures.push(format!(
            "target outputs share a cache with dependency or compiler roots at {location}"
        ));
    }
    if cache_step_value(lines, action_index, "restore-keys").is_some() {
        failures.push(format!(
            "target cache uses a partial restore key at {location}"
        ));
    }
    let Some(key) = cache_step_value(lines, action_index, "key") else {
        failures.push(format!("target cache lacks a key at {location}"));
        return;
    };
    let required_inputs: &[&str] = if rust_target_paths != 0 {
        &["**/build.rs", ".cargo/**", "crates/**/*.rs", "compat/**"]
    } else {
        &[
            "**/build.rs",
            ".cargo/**",
            "crates/**/*.rs",
            "compat/**",
            "stack.yaml",
            "stack.yaml.lock",
            "package.yaml",
            ".cabal",
            "src/**",
        ]
    };
    for required in required_inputs {
        if !key.contains(required) {
            failures.push(format!("target cache key omits {required} at {location}"));
        }
    }
    let exact_workflow = format!("'{}'", workflow_path.display());
    if !key.contains(&exact_workflow) {
        failures.push(format!(
            "target cache key omits exact workflow {} at {location}",
            workflow_path.display()
        ));
    }
}

fn cache_paths<'a>(lines: &'a [&str], action_index: usize) -> Vec<&'a str> {
    let Some((path_index, value)) = cache_step_entry(lines, action_index, "path") else {
        return Vec::new();
    };
    if !matches!(value, "|" | ">" | "|-" | ">-") {
        return vec![value];
    }
    let indentation = lines[path_index].len() - lines[path_index].trim_start().len();
    lines
        .iter()
        .skip(path_index + 1)
        .take_while(|line| {
            line.trim().is_empty() || line.len() - line.trim_start().len() > indentation
        })
        .map(|line| strip_yaml_comment(line).trim())
        .filter(|line| !line.is_empty())
        .collect()
}

fn cache_step_value<'a>(lines: &'a [&str], action_index: usize, key: &str) -> Option<&'a str> {
    cache_step_entry(lines, action_index, key).map(|(_, value)| value)
}

fn cache_step_entry<'a>(
    lines: &'a [&str],
    action_index: usize,
    key: &str,
) -> Option<(usize, &'a str)> {
    let action_indentation = lines[action_index].len() - lines[action_index].trim_start().len();
    lines
        .iter()
        .enumerate()
        .skip(action_index + 1)
        .take_while(|(_, line)| {
            let trimmed = line.trim_start();
            let indentation = line.len() - trimmed.len();
            trimmed.is_empty() || !trimmed.starts_with("- ") || indentation > action_indentation
        })
        .find_map(|(index, line)| {
            yaml_key(strip_yaml_comment(line).trim(), key).map(|value| (index, value.trim()))
        })
}

fn check_duplicate_yaml_mapping_keys(path: &Path, lines: &[&str], failures: &mut Vec<String>) {
    let mut scopes = Vec::<(usize, BTreeSet<String>)>::new();
    for (index, original) in lines.iter().enumerate() {
        let uncommented = strip_yaml_comment(original);
        if uncommented.trim().is_empty() {
            continue;
        }
        let indentation = uncommented.len() - uncommented.trim_start_matches(' ').len();
        let trimmed = uncommented.trim_start_matches(' ');
        let (mapping_indentation, entry) = if let Some(item) = trimmed.strip_prefix("- ") {
            let mapping_indentation = indentation.saturating_add(2);
            while scopes
                .last()
                .is_some_and(|(scope, _)| *scope >= mapping_indentation)
            {
                scopes.pop();
            }
            scopes.push((mapping_indentation, BTreeSet::new()));
            (mapping_indentation, item)
        } else {
            while scopes.last().is_some_and(|(scope, _)| *scope > indentation) {
                scopes.pop();
            }
            if scopes.last().is_none_or(|(scope, _)| *scope < indentation) {
                scopes.push((indentation, BTreeSet::new()));
            }
            (indentation, trimmed)
        };
        let Some(key) = yaml_mapping_key(entry) else {
            continue;
        };
        let Some((scope, keys)) = scopes.last_mut() else {
            continue;
        };
        if *scope != mapping_indentation || !keys.insert(key.to_owned()) {
            failures.push(format!(
                "workflow contains duplicate YAML mapping key {key:?} at {}:{}",
                path.display(),
                index + 1
            ));
        }
    }
}

fn yaml_mapping_key(line: &str) -> Option<&str> {
    let (key, _) = line.split_once(':')?;
    if key.is_empty()
        || !key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        None
    } else {
        Some(key)
    }
}

fn reviewed_surveillance_token_binding(
    path: &Path,
    lines: &[&str],
    index: usize,
    original: &str,
) -> bool {
    if original != "        env:"
        || lines.get(index + 1) != Some(&"          GITHUB_TOKEN: ${{ github.token }}")
    {
        return false;
    }
    let Some(name) = lines[..index]
        .iter()
        .rev()
        .take(5)
        .find(|line| line.starts_with("      - name: "))
    else {
        return false;
    };
    let run = lines[index + 2..lines.len().min(index + 7)]
        .iter()
        .copied()
        .find(|line| line.starts_with("        run: "))
        .unwrap_or_default();
    matches!(
        (path, *name, run),
        (
            path,
            "      - name: Upsert promotion surveillance incident",
            "        run: ./target/ci/hell-ci surveillance-ops workflow-alert"
        ) | (
            path,
            "      - name: Reverify and synchronize linked divergence issue summaries",
            "        run: ./target/ci/hell-ci surveillance-ops workflow-divergence-issues"
        ) | (
            path,
            "      - name: Dispatch exact active-candidate native provenance rebuild",
            "        run: ./target/ci/hell-ci surveillance-ops workflow-dispatch-native-provenance"
        ) | (
            path,
            "      - name: Retain exact current governance source",
            "        run: ./target/ci/hell-ci surveillance-ops workflow-retain-current-governance"
        ) | (
            path,
            "      - name: Select exact current reviewed native provenance",
            "        run: ./target/ci/hell-ci surveillance-ops workflow-native-provenance"
        ) | (
            path,
            "      - name: Derive objective component-bound surveillance result",
            "        run: ./target/ci/hell-ci surveillance-ops workflow-objective"
        ) if path == workflow_path("promotion-surveillance.yml")
    ) || matches!(
        (path, *name, run),
        (
            path,
            "      - name: Check expected surveillance deadline",
            "        run: ./target/ci/hell-ci surveillance-ops workflow-deadline"
        ) | (
            path,
            "      - name: Upsert missed surveillance deadline incident",
            "        run: ./target/ci/hell-ci surveillance-ops workflow-alert"
        ) if path == workflow_path("promotion-surveillance-watchdog.yml")
    )
}

fn reviewed_evidence_review_token_binding(
    path: &Path,
    lines: &[&str],
    index: usize,
    original: &str,
) -> bool {
    if original != "        env:"
        || lines.get(index + 1)
            != Some(&"          GITHUB_TOKEN: ${{ secrets.REVIEW_AUTHORIZATION_GITHUB_TOKEN }}")
    {
        return false;
    }
    let Some(name) = lines[..index]
        .iter()
        .rev()
        .take(2)
        .find(|line| line.starts_with("      - name: "))
    else {
        return false;
    };
    let run = lines.get(index + 2).copied().unwrap_or_default();
    (path == workflow_path("promotion-evidence-review.yml")
        && matches!(
            (*name, run),
            (
                "      - name: Retain claim reviewer authorization",
                "        run: ./target/ci/hell-ci review-authorization --input ci-out/evidence/coverage/claim-coverage.finalized.json --output ci-out/evidence/review/auth/claim/authorization.json --role claim-reviewer --github-dispatch-inputs"
            ) | (
                "      - name: Retain normalizer reviewer authorization",
                "        run: ./target/ci/hell-ci review-authorization --input ci-out/evidence/coverage/normalizer-audit.details.json --output ci-out/evidence/review/auth/normalizer/authorization.json --role normalizer-reviewer --github-dispatch-inputs"
            ) | (
                "      - name: Retain divergence reviewer authorization",
                "        run: ./target/ci/hell-ci review-authorization --input ci-out/evidence/review/divergence-report.details.json --output ci-out/evidence/review/auth/divergence/authorization.json --role divergence-reviewer --github-dispatch-inputs"
            ) | (
                "      - name: Retain divergence platform reviewer authorization",
                "        run: ./target/ci/hell-ci review-authorization --input ci-out/evidence/review/divergence-report.details.json --output ci-out/evidence/review/divergence-approvals/divergence-platform-reviewer/authorization.json --role divergence-platform-reviewer --github-dispatch-inputs"
            ) | (
                "      - name: Retain divergence implementation reviewer authorization",
                "        run: ./target/ci/hell-ci review-authorization --input ci-out/evidence/review/divergence-report.details.json --output ci-out/evidence/review/divergence-approvals/divergence-implementation-reviewer/authorization.json --role divergence-implementation-reviewer --github-dispatch-inputs"
            ) | (
                "      - name: Retain divergence product reviewer authorization",
                "        run: ./target/ci/hell-ci review-authorization --input ci-out/evidence/review/divergence-report.details.json --output ci-out/evidence/review/divergence-approvals/divergence-product-reviewer/authorization.json --role divergence-product-reviewer --github-dispatch-inputs"
            ) | (
                "      - name: Retain divergence security reviewer authorization",
                "        run: ./target/ci/hell-ci review-authorization --input ci-out/evidence/review/divergence-report.details.json --output ci-out/evidence/review/divergence-approvals/divergence-security-reviewer/authorization.json --role divergence-security-reviewer --github-dispatch-inputs"
            ) | (
                "      - name: Retain residual risk reviewer authorization",
                "        run: ./target/ci/hell-ci review-authorization --input ci-out/evidence/coverage/residual-risk.details.json --output ci-out/evidence/review/auth/residual-risk/authorization.json --role residual-risk-reviewer --github-dispatch-inputs"
            ) | (
                "      - name: Verify exact semantic review components",
                "        run: ./target/ci/hell-ci offline-review-ops workflow-verify-components"
            )
        ))
        || (path == workflow_path("evidence-custody.yml")
            && matches!(
                (*name, run),
                (
                    "      - name: Retain final graph reviewer authorization and provider selection",
                    "        run: ./target/ci/hell-ci review-authorization --input ci-out/evidence/review/graph-review-subject.json --output ci-out/evidence/review/auth/role-graph/authorization.json --role review-graph-reviewer --category final-review-graph --github-dispatch-inputs"
                )
            ))
        || (path == workflow_path("artifact-authenticity-finalize.yml")
            && matches!(
                (*name, run),
                (
                    "      - name: Retain stable protected reviewer authorization",
                    "        run: ./target/ci/hell-ci review-authorization --input ci-out/acquisition/artifact-findings.subject.json --output ci-out/acquisition/authorization.json --role artifact-trust-reviewer --category artifact-trust-final --github-dispatch-inputs"
                )
            ))
        || (path == workflow_path("mutation.yml")
            && matches!(
                (*name, run),
                (
                    "      - name: Retain stable protected mutation reviewer authorization",
                    "        run: ./target/ci/hell-ci review-authorization --input ci-out/mutation/mutation-score.pending.json --output ci-out/mutation/authorization.json --role mutation-reviewer --category mutation-final --github-dispatch-inputs"
                )
            ))
        || (path == workflow_path("promotion-approval.yml")
            && matches!(
                (*name, run),
                (
                    "      - name: Retain exact protected promotion authorization",
                    "        run: ./target/ci/hell-ci review-authorization --input ci-out/native-shards/promotion-approval-subject.json --output ci-out/native-shards/authorization.json --role promotion-approver --category promotion-final --github-dispatch-inputs"
                )
            ))
        || (path == workflow_path("oracle-reproduce.yml")
            && matches!(
                (*name, run),
                (
                    "      - name: Retain exact protected macOS platform reviewer authorization",
                    "        run: ./target/ci/hell-ci review-authorization --input ci-out/provider-subject/platform-review-packet.json --output ci-out/authorization.json --role platform-reviewer --category oracle-platform-final --platform macos-arm64 --github-dispatch-inputs"
                ) | (
                    "      - name: Retain exact protected Windows platform reviewer authorization",
                    "        run: ./target/ci/hell-ci review-authorization --input ci-out/provider-subject/platform-review-packet.json --output ci-out/authorization.json --role platform-reviewer --category oracle-platform-final --platform windows-amd64 --github-dispatch-inputs"
                )
            ))
        || (path == workflow_path("evidence-custody.yml")
            && matches!(
                (*name, run),
                (
                    "      - name: Retain exact protected custody reviewer authorization",
                    "        run: ./target/ci/hell-ci review-authorization --input ci-out/custody-subject/review-packet.json --output ci-out/custody/authorization.json --role custody-reviewer --category custody-final --github-dispatch-inputs"
                )
            ))
        || reviewed_activation_token_binding(path, name, run)
}

fn reviewed_activation_token_binding(path: &Path, name: &str, run: &str) -> bool {
    path == workflow_path("collection-activation.yml")
        && matches!(
            (name, run),
            (
                "      - name: Retain protected claim author authorization",
                "        run: ./target/ci/hell-ci review-authorization --input ci-in/collection-activation-review-subject/review-subject.json --output ci-out/collection-activation-review/claim-author/authorization.json --role claim-author --category collection-activation-author --github-dispatch-inputs"
            ) | (
                "      - name: Retain protected claim reviewer authorization",
                "        run: ./target/ci/hell-ci review-authorization --input ci-in/collection-activation-review-subject/review-subject.json --output ci-out/collection-activation-review/claim-reviewer/authorization.json --role claim-reviewer --category collection-activation-final --github-dispatch-inputs"
            )
        )
}

fn strip_yaml_comment(line: &str) -> &str {
    let mut single = false;
    let mut double = false;
    let mut previous = '\0';
    for (index, character) in line.char_indices() {
        match character {
            '\'' if !double => single = !single,
            '"' if !single && previous != '\\' => double = !double,
            '#' if !single && !double && (index == 0 || previous.is_whitespace()) => {
                return &line[..index];
            }
            _ => {}
        }
        previous = character;
    }
    line
}

fn yaml_key<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.strip_prefix(key)?.strip_prefix(':')
}

fn check_run_value(value: &str, location: &str, failures: &mut Vec<String>) {
    if value.is_empty() || matches!(value, "|" | ">" | "|-" | ">-") {
        failures.push(format!(
            "workflow run must be an inline invocation at {location}"
        ));
        return;
    }
    let forbidden = ["&&", "||", ";", "|", "`", "$(", "${{", ">", "<"];
    if forbidden.iter().any(|token| value.contains(token)) {
        failures.push(format!(
            "workflow run contains shell control syntax at {location}"
        ));
    }
    let executable = value
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .trim_matches(['\'', '"']);
    let executable = Path::new(executable)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(executable)
        .to_ascii_lowercase();
    if matches!(
        executable.as_str(),
        "sh" | "sh.exe"
            | "bash"
            | "bash.exe"
            | "zsh"
            | "zsh.exe"
            | "fish"
            | "fish.exe"
            | "pwsh"
            | "pwsh.exe"
            | "powershell"
            | "powershell.exe"
            | "cmd"
            | "cmd.exe"
    ) {
        failures.push(format!(
            "workflow invokes a shell interpreter at {location}"
        ));
    }
}

fn check_uses_value(value: &str, location: &str, failures: &mut Vec<String>) {
    if value.starts_with("./") {
        return;
    }
    let value = value.split_whitespace().next().unwrap_or_default();
    let Some((action, revision)) = value.rsplit_once('@') else {
        failures.push(format!("external action is not pinned at {location}"));
        return;
    };
    if revision.len() != CACHE_SHA.len() || !revision.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        failures.push(format!(
            "external action pin is not 40 hex characters at {location}"
        ));
    }
    if matches!(action, "actions/cache/restore" | "actions/cache/save") && revision != CACHE_SHA {
        failures.push(format!("cache action has an unexpected pin at {location}"));
    }
    if action == "webfactory/ssh-agent" && revision != SSH_AGENT_SHA {
        failures.push(format!(
            "SSH agent action has an unexpected pin at {location}"
        ));
    }
    if action == "actions/attest" && revision != ATTEST_SHA {
        failures.push(format!(
            "artifact attestation action has an unexpected pin at {location}"
        ));
    }
}

fn following_value<'a>(lines: &'a [&str], start: usize, key: &str) -> Option<&'a str> {
    lines
        .iter()
        .skip(start + 1)
        .take(24)
        .find_map(|line| yaml_key(line.trim(), key).map(str::trim))
}

fn preceding_value<'a>(lines: &'a [&str], start: usize, key: &str) -> Option<&'a str> {
    lines[..start]
        .iter()
        .rev()
        .take(5)
        .find_map(|line| yaml_key(line.trim(), key).map(str::trim))
}

fn check_test_infrastructure(root: &Path, tracked: &[PathBuf], failures: &mut Vec<String>) {
    for path in tracked.iter().filter(|path| is_test_infrastructure(path)) {
        let Ok(text) = fs::read_to_string(root.join(path)) else {
            continue;
        };
        if path.file_name().and_then(|value| value.to_str()) == Some("Cargo.toml") {
            for line in text.lines() {
                let dependency = line
                    .split_once('=')
                    .map_or(line, |(name, _)| name)
                    .trim()
                    .trim_matches('"');
                if matches!(dependency, "regex" | "regex-automata" | "regex-syntax") {
                    failures.push(format!(
                        "regex dependency in test infrastructure: {}",
                        path.display()
                    ));
                }
                if dependency_package(line).is_some_and(|package| {
                    matches!(package, "regex" | "regex-automata" | "regex-syntax")
                }) {
                    failures.push(format!(
                        "regex package alias in test infrastructure: {}",
                        path.display()
                    ));
                }
            }
        }
        for identifier in rust_identifiers(&text) {
            if matches!(identifier.as_str(), "Regex" | "RegexSet" | "RegexBuilder") {
                failures.push(format!(
                    "regex API in test infrastructure: {}",
                    path.display()
                ));
                break;
            }
        }
        let identifiers = rust_identifiers(&text);
        if identifiers
            .windows(2)
            .any(|pair| matches!(pair, [first, second] if first == "use" && second == "regex"))
        {
            failures.push(format!(
                "regex import in test infrastructure: {}",
                path.display()
            ));
        }
    }
}

fn dependency_package(line: &str) -> Option<&str> {
    let line = strip_yaml_comment(line);
    let (_, inline_table) = line.split_once('=')?;
    inline_table.split(',').find_map(|field| {
        let field = field.trim().trim_matches(['{', '}']);
        let (key, value) = field.split_once('=')?;
        if key.trim() != "package" {
            return None;
        }
        let quoted = value.trim().strip_prefix('"')?;
        let (package, _) = quoted.split_once('"')?;
        Some(package)
    })
}

fn is_test_infrastructure(path: &Path) -> bool {
    path.starts_with("crates/hell-ci")
        || path.starts_with("crates/hell-testkit")
        || path
            .components()
            .any(|component| component.as_os_str() == "tests")
}

fn rust_identifiers(text: &str) -> Vec<String> {
    const LINE_COMMENT: &[u8] = b"//";
    const BLOCK_OPEN: &[u8] = b"/*";
    const BLOCK_CLOSE: &[u8] = b"*/";
    const ESCAPED_PAIR_WIDTH: usize = b"\\x".len();
    const APOSTROPHE_TOKEN: &[u8] = b"'";

    let bytes = text.as_bytes();
    let apostrophe = APOSTROPHE_TOKEN[0];
    let mut identifiers = Vec::new();
    let mut index = 0;
    let mut in_line_comment = false;
    let mut block_depth = 0_u32;
    let mut quote = None;
    while index < bytes.len() {
        if in_line_comment {
            if bytes[index] == b'\n' {
                in_line_comment = false;
            }
            index += 1;
            continue;
        }
        if block_depth != 0 {
            if bytes.get(index..index.saturating_add(BLOCK_OPEN.len())) == Some(BLOCK_OPEN) {
                block_depth += 1;
                index += BLOCK_OPEN.len();
            } else if bytes.get(index..index.saturating_add(BLOCK_CLOSE.len())) == Some(BLOCK_CLOSE)
            {
                block_depth -= 1;
                index += BLOCK_CLOSE.len();
            } else {
                index += 1;
            }
            continue;
        }
        if let Some(delimiter) = quote {
            if bytes[index] == b'\\' {
                index = index.saturating_add(ESCAPED_PAIR_WIDTH).min(bytes.len());
            } else {
                if bytes[index] == delimiter {
                    quote = None;
                }
                index += 1;
            }
            continue;
        }
        if bytes.get(index..index.saturating_add(LINE_COMMENT.len())) == Some(LINE_COMMENT) {
            in_line_comment = true;
            index += LINE_COMMENT.len();
        } else if bytes.get(index..index.saturating_add(BLOCK_OPEN.len())) == Some(BLOCK_OPEN) {
            block_depth = 1;
            index += BLOCK_OPEN.len();
        } else if bytes[index] == apostrophe {
            let rest = &bytes[index.saturating_add(APOSTROPHE_TOKEN.len())..];
            let line = rest.split(|byte| *byte == b'\n').next().unwrap_or_default();
            if let Some(closing) = unescaped_apostrophe(line, apostrophe) {
                index = index
                    .saturating_add(APOSTROPHE_TOKEN.len())
                    .saturating_add(closing)
                    .saturating_add(APOSTROPHE_TOKEN.len());
            } else {
                index += APOSTROPHE_TOKEN.len();
            }
        } else if bytes[index] == b'"' {
            quote = Some(bytes[index]);
            index += 1;
        } else if bytes[index].is_ascii_alphabetic() || bytes[index] == b'_' {
            let start = index;
            index += 1;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
            {
                index += 1;
            }
            identifiers.push(text[start..index].to_owned());
        } else {
            index += 1;
        }
    }
    identifiers
}

fn unescaped_apostrophe(bytes: &[u8], apostrophe: u8) -> Option<usize> {
    let mut escaped = false;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if escaped {
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if byte == apostrophe {
            return Some(index);
        }
    }
    None
}

fn check_environment_configuration(root: &Path, tracked: &[PathBuf], failures: &mut Vec<String>) {
    for path in tracked {
        let text_path = path.to_string_lossy();
        let relevant = text_path.starts_with(".cargo/config")
            || path.file_name().and_then(|value| value.to_str()) == Some("build.rs");
        if !relevant {
            continue;
        }
        let Ok(text) = fs::read_to_string(root.join(path)) else {
            continue;
        };
        if text_path.starts_with(".cargo/config") && text.lines().any(|line| line.trim() == "[env]")
        {
            failures.push(format!(
                "Cargo env configuration is forbidden: {}",
                path.display()
            ));
        }
        if text.contains("cargo:rustc-env") {
            failures.push(format!(
                "rustc environment output is forbidden: {}",
                path.display()
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_canonicalization_limits_require_exact_source_and_classification() {
        let source = include_str!("../../hell-runtime/src/lib.rs");
        let inventory = include_str!("../../../spec/runtime-profiles.md");
        for (name, declaration) in [
            ("MAX_DEPTH", "const MAX_DEPTH: usize = 64;"),
            ("MAX_ELEMENTS", "const MAX_ELEMENTS: usize = 1_024;"),
        ] {
            let mut baseline = Vec::new();
            check_exact_evidence_limit(
                "crates/hell-runtime/src/lib.rs",
                name,
                source,
                inventory,
                &mut baseline,
            );
            assert!(baseline.is_empty(), "{name}: {baseline:?}");

            let source_mutant = source.replacen(declaration, "const MUTATED_LIMIT: usize = 1;", 1);
            let mut source_failures = Vec::new();
            check_exact_evidence_limit(
                "crates/hell-runtime/src/lib.rs",
                name,
                &source_mutant,
                inventory,
                &mut source_failures,
            );
            assert!(!source_failures.is_empty(), "accepted source mutant {name}");

            let row = inventory
                .lines()
                .find(|line| {
                    line.contains("`crates/hell-runtime/src/lib.rs`") && line.contains(name)
                })
                .unwrap();
            let inventory_mutant = inventory.replacen(row, "| missing reviewed row |", 1);
            let mut inventory_failures = Vec::new();
            check_exact_evidence_limit(
                "crates/hell-runtime/src/lib.rs",
                name,
                source,
                &inventory_mutant,
                &mut inventory_failures,
            );
            assert!(
                !inventory_failures.is_empty(),
                "accepted inventory mutant {name}"
            );
        }
    }

    fn workflow(body: &str) -> Vec<String> {
        let mut failures = Vec::new();
        check_workflow(Path::new("workflow.yml"), body, &mut failures);
        failures
    }

    fn collection_authority_policy(workflow: &str, tool: &str) -> Vec<String> {
        let mut failures = Vec::new();
        check_collection_authority_producer_text(workflow, tool, &mut failures);
        failures
    }

    fn collection_custody_integration_policy(workflow: &str, revocations: &str) -> Vec<String> {
        let mut failures = Vec::new();
        check_collection_custody_integration_text(workflow, revocations, &mut failures);
        failures
    }

    fn collection_custody_review_policy(workflow: &str, trust_roots: &str) -> Vec<String> {
        let mut failures = Vec::new();
        check_collection_custody_review_text(workflow, trust_roots, &mut failures);
        failures
    }

    fn collection_worm_bridge_policy(workflow: &str) -> Vec<String> {
        let mut failures = Vec::new();
        check_collection_worm_bridge_text(workflow, &mut failures);
        failures
    }

    fn collection_activation_preparation_policy(workflow: &str) -> Vec<String> {
        let mut failures = Vec::new();
        check_collection_activation_preparation_text(workflow, &mut failures);
        failures
    }

    fn collection_job_mutant(workflow: &str, job: &str, from: &str, to: &str) -> String {
        let header = format!("  {job}:");
        let start = workflow.find(&header).unwrap();
        let remainder = &workflow[start + header.len()..];
        let length = remainder
            .match_indices("\n  ")
            .find_map(|(relative, _)| {
                remainder
                    .as_bytes()
                    .get(relative + 3)
                    .is_some_and(|byte| !byte.is_ascii_whitespace())
                    .then_some(relative)
            })
            .map_or(remainder.len(), |relative| relative);
        let end = start + header.len() + length;
        let replacement = workflow[start..end].replacen(from, to, 1);
        assert_ne!(replacement, workflow[start..end]);
        format!("{}{}{}", &workflow[..start], replacement, &workflow[end..])
    }

    fn assert_collection_workflow_mutants_rejected(
        tool: &str,
        mutants: impl IntoIterator<Item = (&'static str, String)>,
    ) {
        for (label, mutant) in mutants {
            assert!(
                !collection_authority_policy(&mutant, tool).is_empty(),
                "accepted collection workflow substitution {label}"
            );
        }
    }

    fn collection_custody_integration_mutants(workflow: &str) -> Vec<(&'static str, String)> {
        let mut mutants = vec![
            (
                "trigger",
                workflow.replacen("  workflow_dispatch:", "  push:\n  workflow_dispatch:", 1),
            ),
            (
                "optional-input",
                workflow.replacen("required: true", "required: false", 1),
            ),
            (
                "non-current-integration",
                workflow.replacen(" && inputs.integration_sha == github.sha", "", 1),
            ),
            (
                "unprotected-environment",
                workflow.replacen(
                    "environment: collection-custody-integration",
                    "environment: unreviewed",
                    1,
                ),
            ),
            (
                "shallow-checkout",
                workflow.replacen("fetch-depth: 0", "fetch-depth: 1", 1),
            ),
            (
                "credential-retention",
                workflow.replacen("persist-credentials: false", "persist-credentials: true", 1),
            ),
            (
                "checkout-pin",
                workflow.replacen(
                    "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
                    "actions/checkout@0000000000000000000000000000000000000000",
                    1,
                ),
            ),
            (
                "candidate-substitution",
                workflow.replacen(
                    "--candidate-commit \"$COLLECTION_INTEGRATION_SHA\"",
                    "--candidate-commit HEAD",
                    1,
                ),
            ),
            (
                "direct-input-interpolation",
                workflow.replacen(
                    "--candidate-commit \"$COLLECTION_INTEGRATION_SHA\"",
                    "--candidate-commit \"${{ inputs.integration_sha }}\"",
                    1,
                ),
            ),
        ];
        mutants.extend(collection_custody_integration_worm_mutants(workflow));
        mutants
    }

    fn collection_custody_integration_worm_mutants(workflow: &str) -> Vec<(&'static str, String)> {
        let mut mutants = vec![
            ("proof-substitution", workflow.replacen("--integration-proof compat/collection-custody/integration-proof.tsv", "--integration-proof ci-out/unreviewed.tsv", 1)),
            ("review-substitution", workflow.replacen("--integration-review compat/collection-custody/integration-review.dsse.json", "--integration-review ci-out/unreviewed.dsse.json", 1)),
            ("activation-token-omission", workflow.replacen("            ci-out/collection-custody-activation-token.json\n", "", 1)),
            ("activation-token-digest-omission", workflow.replacen("            ci-out/collection-custody-activation-token.json.sha256\n", "", 1)),
            ("admission-directory-binding-omission", workflow.replacen("run: ./target/ci/hell-ci regression-import emit-directory-output --input ci-out", "run: true", 1)),
            ("admission-artifact-output-substitution", workflow.replacen("steps.upload-admission.outputs.artifact-id", "steps.upload-admission.outputs.artifact-digest", 1)),
            ("admission-directory-output-substitution", workflow.replacen("steps.bind-admission.outputs.directory_sha256", "steps.upload-admission.outputs.artifact-digest", 1)),
            ("write-permission", workflow.replacen("contents: read", "contents: write", 1)),
        ];
        mutants.extend([
            (
                "artifact-name-instead-of-id",
                workflow.replacen(
                    "artifact-ids: ${{ inputs.worm_artifact_id }}",
                    "name: collection-worm-custody",
                    1,
                ),
            ),
            (
                "source-run-substitution",
                workflow.replacen(
                    "run-id: ${{ inputs.worm_source_run_id }}",
                    "run-id: ${{ github.run_id }}",
                    1,
                ),
            ),
            (
                "worm-path-substitution",
                workflow.replacen(
                    "path: ci-in/collection-worm-custody",
                    "path: ci-in/unreviewed",
                    1,
                ),
            ),
            (
                "worm-digest-omission",
                workflow.replacen(
                    "collection-authority verify-worm-artifact",
                    "collection-authority verify-checkout",
                    1,
                ),
            ),
            (
                "archive-digest-substitution",
                workflow.replacen(
                    "inputs.expected_worm_directory_sha256",
                    "inputs.worm_artifact_digest",
                    1,
                ),
            ),
            (
                "worm-admission-omission",
                workflow.replacen(" --worm-custody ci-in/collection-worm-custody", "", 1),
            ),
            (
                "cache-workflow-binding",
                workflow.replacen(
                    ".github/workflows/collection-custody-integration.yml') }}",
                    ".github/workflows/unreviewed.yml') }}",
                    1,
                ),
            ),
            (
                "cache-integration-sha-binding",
                workflow.replacen(
                    "integration-target-${{ inputs.integration_sha }}-",
                    "integration-target-unbound-",
                    1,
                ),
            ),
            (
                "cache-save-not-always",
                workflow.replacen(
                    "if: ${{ always() && steps.target-cache.outcome",
                    "if: ${{ success() && steps.target-cache.outcome",
                    1,
                ),
            ),
        ]);
        mutants
    }

    fn collection_custody_review_trust_mutants(workflow: &str) -> Vec<(&'static str, String)> {
        vec![
            (
                "trigger",
                workflow.replacen("  workflow_dispatch:", "  push:\n  workflow_dispatch:", 1),
            ),
            (
                "non-current-preparation",
                workflow.replacen(" && inputs.preparation_sha == github.sha", "", 1),
            ),
            (
                "unlinked-artifact",
                workflow.replacen(
                    "needs.prepare-unsigned-custody-review.outputs.artifact_id",
                    "inputs.preparation_artifact_id",
                    1,
                ),
            ),
            (
                "unprotected-environment",
                workflow.replacen(
                    "environment: collection-custody-review",
                    "environment: unreviewed",
                    1,
                ),
            ),
            (
                "missing-oidc",
                workflow.replacen("id-token: write", "id-token: none", 1),
            ),
            (
                "payload-substitution",
                workflow.replacen(
                    "ci-in/collection-custody-review/integration-review-payload.json",
                    "ci-in/unreviewed.json",
                    1,
                ),
            ),
            (
                "direct-preparation-interpolation",
                workflow.replacen(
                    "--candidate-commit \"$COLLECTION_PREPARATION_SHA\"",
                    "--candidate-commit \"${{ inputs.preparation_sha }}\"",
                    1,
                ),
            ),
        ]
    }

    fn collection_custody_review_cache_mutants(workflow: &str) -> Vec<(&'static str, String)> {
        let mut mutants = collection_custody_review_input_mutants(workflow);
        mutants.extend([
            (
                "validator-after-key",
                workflow.replacen(
                    "      - name: Validate exact unsigned custody review inventory and roots\n        run: ./target/ci/hell-ci collection-authority verify-custody-review-preparation --input ci-in/collection-custody-review\n",
                    "",
                    1,
                ),
            ),
            (
                "role-substitution",
                workflow.replacen("--role custody-reviewer", "--role claim-reviewer", 1),
            ),
            (
                "missing-overlay-assembly",
                workflow.replacen(
                    "      - name: Assemble exact commit-ready proof and review overlay\n        run: ./target/ci/hell-ci collection-authority assemble-custody-review-overlay --input ci-in/collection-custody-review --integration-review ci-in/collection-custody-review-signed/integration-review.dsse.json --output ci-out/collection-custody-review-overlay\n",
                    "",
                    1,
                ),
            ),
            (
                "overlay-proof-substitution",
                workflow.replacen(
                    "--input ci-in/collection-custody-review --integration-review",
                    "--input ci-in/unreviewed-custody-review --integration-review",
                    1,
                ),
            ),
            (
                "overlay-review-substitution",
                workflow.replacen(
                    "--integration-review ci-in/collection-custody-review-signed/integration-review.dsse.json",
                    "--integration-review ci-in/unreviewed.dsse.json",
                    1,
                ),
            ),
            (
                "overlay-directory-digest-omission",
                workflow.replacen(
                    "      overlay_directory_sha256: ${{ steps.bind-overlay.outputs.directory_sha256 }}\n",
                    "",
                    1,
                ),
            ),
            (
                "overlay-artifact-id-substitution",
                workflow.replacen(
                    "overlay_artifact_id: ${{ steps.upload-overlay.outputs.artifact-id }}",
                    "overlay_artifact_id: unbound",
                    1,
                ),
            ),
            (
                "overlay-broad-upload",
                workflow.replacen(
                    "path: ci-out/collection-custody-review-overlay/tree",
                    "path: ci-out/collection-custody-review-overlay",
                    1,
                ),
            ),
            (
                "cache-workflow-binding",
                workflow.replacen(
                    ".github/workflows/collection-custody-review.yml') }}",
                    ".github/workflows/unreviewed.yml') }}",
                    1,
                ),
            ),
            (
                "cache-preparation-sha-binding",
                workflow.replacen(
                    "prepare-target-${{ inputs.preparation_sha }}-",
                    "prepare-target-unbound-",
                    1,
                ),
            ),
            (
                "cache-save-not-always",
                workflow.replacen(
                    "if: ${{ always() && steps.target-cache.outcome",
                    "if: ${{ success() && steps.target-cache.outcome",
                    1,
                ),
            ),
        ]);
        mutants
    }

    fn collection_custody_review_input_mutants(workflow: &str) -> Vec<(&'static str, String)> {
        vec![
            (
                "direct-reviewer-interpolation",
                workflow.replacen(
                    "--reviewer \"$COLLECTION_CUSTODY_REVIEWER\"",
                    "--reviewer \"${{ inputs.reviewer }}\"",
                    1,
                ),
            ),
            (
                "direct-issued-at-interpolation",
                workflow.replacen(
                    "--issued-at \"$COLLECTION_CUSTODY_ISSUED_AT\"",
                    "--issued-at \"${{ inputs.issued_at }}\"",
                    1,
                ),
            ),
        ]
    }

    #[test]
    fn collection_authority_workflow_is_isolated_and_producers_are_exact() {
        let campaign = include_str!("../../../.github/workflows/collection-authority.yml");
        let tool = include_str!("collection_transport.rs");
        assert!(
            collection_authority_policy(campaign, tool).is_empty(),
            "{}",
            collection_authority_policy(campaign, tool).join("\n")
        );
        assert_collection_workflow_mutants_rejected(
            tool,
            [
                (
                    "workflow-name",
                    campaign.replacen("name: Collection Authority", "name: Nightly", 1),
                ),
                (
                    "push-trigger",
                    campaign.replacen("  workflow_dispatch:", "  push:\n  workflow_dispatch:", 1),
                ),
                (
                    "schedule-trigger",
                    campaign.replacen(
                        "  workflow_dispatch:",
                        "  schedule:\n  workflow_dispatch:",
                        1,
                    ),
                ),
                (
                    "optional-candidate",
                    campaign.replacen("required: true", "required: false", 1),
                ),
                (
                    "concurrency-group",
                    campaign.replacen(
                        "group: collection-authority-${{ github.repository }}",
                        "group: collection-authority-${{ github.ref }}",
                        1,
                    ),
                ),
                (
                    "cancelling",
                    campaign.replacen("cancel-in-progress: false", "cancel-in-progress: true", 1),
                ),
                (
                    "timeout",
                    campaign.replacen("timeout-minutes: 120", "timeout-minutes: 60", 1),
                ),
                (
                    "main-guard",
                    collection_job_mutant(
                        campaign,
                        "collection-authority-linux",
                        "github.ref == 'refs/heads/main' && ",
                        "",
                    ),
                ),
                (
                    "permission",
                    collection_job_mutant(
                        campaign,
                        "collection-authority-linux",
                        "actions: read",
                        "actions: write",
                    ),
                ),
                (
                    "checkout",
                    collection_job_mutant(
                        campaign,
                        "collection-authority-macos",
                        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
                        "actions/checkout@0000000000000000000000000000000000000000",
                    ),
                ),
                (
                    "job-name",
                    campaign.replacen(
                        "name: Collection authority / macOS arm64",
                        "name: Collection authority / Linux amd64",
                        1,
                    ),
                ),
            ],
        );
    }

    #[test]
    fn collection_authority_payload_overlay_is_exact() {
        let campaign = include_str!("../../../.github/workflows/collection-authority.yml");
        let tool = include_str!("collection_transport.rs");
        assert_collection_workflow_mutants_rejected(
            tool,
            [
                (
                    "payload-overlay-omission",
                    collection_job_mutant(
                        campaign,
                        "assemble-custody-payload-overlay",
                        "collection-authority assemble-custody-payload-overlay",
                        "collection-authority verify",
                    ),
                ),
                (
                    "payload-overlay-artifact-substitution",
                    collection_job_mutant(
                        campaign,
                        "assemble-custody-payload-overlay",
                        "needs.merge-collection-authority.outputs.custody_artifact_id",
                        "inputs.artifact_id",
                    ),
                ),
                (
                    "payload-overlay-broad-upload",
                    collection_job_mutant(
                        campaign,
                        "assemble-custody-payload-overlay",
                        "path: ci-out/collection-custody-payload-overlay/tree",
                        "path: ci-out/collection-custody-payload-overlay",
                    ),
                ),
                (
                    "payload-overlay-directory-digest-omission",
                    collection_job_mutant(
                        campaign,
                        "assemble-custody-payload-overlay",
                        "overlay_directory_sha256: ${{ steps.bind-overlay.outputs.directory_sha256 }}",
                        "overlay_directory_sha256: unbound",
                    ),
                ),
            ],
        );
    }

    #[test]
    fn collection_custody_integration_is_exact_and_rejects_substitutions() {
        let workflow =
            include_str!("../../../.github/workflows/collection-custody-integration.yml");
        let revocations = include_str!("../../../compat/collection-authority-revocations.toml");
        assert!(
            collection_custody_integration_policy(workflow, revocations).is_empty(),
            "{:?}",
            collection_custody_integration_policy(workflow, revocations)
        );
        for (label, mutant) in collection_custody_integration_mutants(workflow) {
            assert!(
                !collection_custody_integration_policy(&mutant, revocations).is_empty(),
                "accepted collection custody integration substitution {label}"
            );
        }
        for mutant in [
            revocations.replacen("state = \"active\"", "state = \"review-required\"", 1),
            revocations.replacen(
                "revoked_provider_run_ids = []",
                "revoked_provider_run_ids = [\"42\", \"21\"]",
                1,
            ),
        ] {
            assert!(
                !collection_custody_integration_policy(workflow, &mutant).is_empty(),
                "accepted noncanonical collection authority revocations"
            );
        }
        let canonical_nonempty = revocations.replacen(
            "revoked_provider_run_ids = []",
            "revoked_provider_run_ids = [\"21\", \"42\"]",
            1,
        );
        assert!(
            collection_custody_integration_policy(workflow, &canonical_nonempty).is_empty(),
            "rejected canonical nonempty collection authority revocations"
        );
    }

    #[test]
    fn collection_custody_review_is_needs_linked_protected_and_exact() {
        let workflow = include_str!("../../../.github/workflows/collection-custody-review.yml");
        let trust_roots = include_str!("../../../compat/trust-roots.toml");
        assert!(
            collection_custody_review_policy(workflow, trust_roots).is_empty(),
            "{:?}",
            collection_custody_review_policy(workflow, trust_roots)
        );
        let mutants = collection_custody_review_trust_mutants(workflow)
            .into_iter()
            .chain(collection_custody_review_cache_mutants(workflow));
        for (label, mutant) in mutants {
            assert!(
                !collection_custody_review_policy(&mutant, trust_roots).is_empty(),
                "accepted collection custody review substitution {label}"
            );
        }
        let substituted_roots = trust_roots.replacen(
            "collection_custody_review_workflow = \".github/workflows/collection-custody-review.yml\"",
            "collection_custody_review_workflow = \".github/workflows/unreviewed.yml\"",
            1,
        );
        assert!(!collection_custody_review_policy(workflow, &substituted_roots).is_empty());
    }

    #[test]
    fn collection_authority_rejects_candidate_control_of_trusted_harness() {
        let campaign = include_str!("../../../.github/workflows/collection-authority.yml");
        let tool = include_str!("collection_transport.rs");
        assert_collection_workflow_mutants_rejected(
            tool,
            [
                (
                    "candidate-checkout-verification",
                    collection_job_mutant(
                        campaign,
                        "collection-authority-macos",
                        "run: ./target/ci/hell-ci collection-authority verify-checkout --input ci-work/candidate --candidate-commit \"$HELL_SOURCE_COMMIT\"",
                        "run: true",
                    ),
                ),
                (
                    "ancestry-instead-of-identity",
                    collection_job_mutant(
                        campaign,
                        "collection-authority-macos",
                        "run: ./target/ci/hell-ci collection-authority verify-checkout --input ci-work/candidate --candidate-commit \"$HELL_SOURCE_COMMIT\"",
                        "run: git -C ci-work/candidate merge-base --is-ancestor \"$HELL_SOURCE_COMMIT\" HEAD",
                    ),
                ),
                (
                    "provider-candidate-ref-swap",
                    collection_job_mutant(
                        campaign,
                        "collection-authority-macos",
                        "ref: ${{ github.sha }}",
                        "ref: ${{ inputs.candidate_sha }}",
                    ),
                ),
                (
                    "candidate-controlled-harness",
                    collection_job_mutant(
                        campaign,
                        "collection-authority-macos",
                        "run: cargo build --locked --profile ci --package hell-ci --bin hell-ci",
                        "run: cargo build --locked --profile ci --manifest-path ci-work/candidate/Cargo.toml --package hell-ci --bin hell-ci",
                    ),
                ),
                (
                    "collect-candidate-commit-join",
                    collection_job_mutant(
                        campaign,
                        "collection-authority-macos",
                        "--candidate-commit \"$HELL_SOURCE_COMMIT\"",
                        "--candidate-commit \"$GITHUB_SHA\"",
                    ),
                ),
            ],
        );
    }

    #[test]
    fn collection_authority_linux_acquisition_roles_reject_substitution() {
        let campaign = include_str!("../../../.github/workflows/collection-authority.yml");
        let tool = include_str!("collection_transport.rs");
        assert_collection_workflow_mutants_rejected(
            tool,
            [
                (
                    "subject-provider-head",
                    collection_job_mutant(
                        campaign,
                        "linux-acquisition-subject",
                        "ref: ${{ github.sha }}",
                        "ref: ${{ inputs.candidate_sha }}",
                    ),
                ),
                (
                    "signer-environment",
                    campaign.replacen(
                        "environment: linux-release-acquisition-signing",
                        "environment: unreviewed",
                        1,
                    ),
                ),
                (
                    "signer-oidc",
                    collection_job_mutant(
                        campaign,
                        "sign-linux-acquisition",
                        "id-token: write",
                        "id-token: read",
                    ),
                ),
                (
                    "subject-artifact-id",
                    campaign.replacen(
                        "needs.linux-acquisition-subject.outputs.artifact_id",
                        "needs.linux-acquisition-subject.outputs.other_id",
                        1,
                    ),
                ),
                (
                    "subject-provider-head-verification",
                    collection_job_mutant(
                        campaign,
                        "linux-acquisition-subject",
                        "run: ./target/ci/hell-ci collection-authority verify-checkout --input . --candidate-commit \"$GITHUB_SHA\"",
                        "run: true",
                    ),
                ),
                (
                    "signer-provider-head-verification",
                    collection_job_mutant(
                        campaign,
                        "sign-linux-acquisition",
                        "run: ./target/ci/hell-ci collection-authority verify-checkout --input . --candidate-commit \"$GITHUB_SHA\"",
                        "run: true",
                    ),
                ),
            ],
        );
    }

    #[test]
    fn collection_authority_caches_reject_incomplete_or_shared_keys() {
        let campaign = include_str!("../../../.github/workflows/collection-authority.yml");
        let tool = include_str!("collection_transport.rs");
        assert_collection_workflow_mutants_rejected(
            tool,
            [
                (
                    "provider-compile-input",
                    collection_job_mutant(
                        campaign,
                        "collection-authority-linux",
                        "'builtins/**', ",
                        "",
                    ),
                ),
                (
                    "provider-cache-sharing",
                    collection_job_mutant(
                        campaign,
                        "collection-authority-macos",
                        "collection-macos-target-",
                        "collection-linux-target-",
                    ),
                ),
                (
                    "candidate-sha",
                    collection_job_mutant(
                        campaign,
                        "collection-authority-linux",
                        "collection-candidate-${{ inputs.candidate_sha }}-",
                        "collection-candidate-unbound-",
                    ),
                ),
                (
                    "candidate-compile-input",
                    collection_job_mutant(
                        campaign,
                        "collection-authority-macos",
                        "'ci-work/candidate/spec/**', ",
                        "",
                    ),
                ),
                (
                    "stack-workflow-binding",
                    collection_job_mutant(
                        campaign,
                        "collection-authority-windows",
                        ".github/workflows/collection-authority.yml') }}",
                        ".github/workflows/unreviewed.yml') }}",
                    ),
                ),
                (
                    "cache-save-not-always",
                    collection_job_mutant(
                        campaign,
                        "merge-collection-authority",
                        "if: ${{ always() && steps.target-cache.outcome",
                        "if: ${{ success() && steps.target-cache.outcome",
                    ),
                ),
            ],
        );
    }

    #[test]
    fn collection_worm_bridge_preserves_prepared_identity_and_requires_review() {
        let workflow = include_str!("../../../.github/workflows/evidence-custody.yml");
        assert!(
            collection_worm_bridge_policy(workflow).is_empty(),
            "{:?}",
            collection_worm_bridge_policy(workflow)
        );
        for (label, mutant) in [
            (
                "repackage",
                workflow.replacen(
                    "collection-authority prepare-worm-custody",
                    "custody-ops workflow-package",
                    1,
                ),
            ),
            (
                "mutable-package-name",
                workflow.replacen(
                    "artifact-ids: ${{ needs.package.outputs.artifact_id }}",
                    "name: ephemeralEvidence-custody-package-${{ github.run_id }}-${{ github.run_attempt }}",
                    1,
                ),
            ),
            (
                "credentials-before-validation",
                workflow.replacen(
                    "run: ./target/ci/hell-ci custody-ops verify-package --input ci-out/custody-package",
                    "run: true",
                    1,
                ),
            ),
            (
                "upload-subject-validation-omission",
                workflow.replacen(
                    "run: ./target/ci/hell-ci custody-ops workflow-verify-upload-subject",
                    "run: true",
                    1,
                ),
            ),
            (
                "upload-subject-provider-substitution",
                workflow.replacen(
                    "CUSTODY_EXPECTED_PROVIDER: ${{ matrix.provider }}",
                    "CUSTODY_EXPECTED_PROVIDER: primary-worm",
                    1,
                ),
            ),
            (
                "upload-subject-extra-transport",
                workflow.replacen(
                    "            ci-out/upload-receipt.dsse.json\n",
                    "            ci-out/upload-receipt.dsse.json\n            ci-out/custody-package\n",
                    1,
                ),
            ),
            (
                "review-credentials-before-finalization",
                workflow.replacen(
                    "run: ./target/ci/hell-ci review-packet --input ci-out/custody-subject/review-packet.json --from ci-out/custody/authorization.json --output ci-out/custody/review-packet.authorized.json --role custody-reviewer --category custody-final --decision accept --github-dispatch-inputs",
                    "run: true",
                    1,
                ),
            ),
            (
                "subject-omission",
                workflow.replacen("            ci-out/subject\n", "", 1),
            ),
            (
                "scrub-omission",
                workflow.replacen("path: ci-out/primary-worm-current-scrub", "path: ci-out", 1),
            ),
            (
                "automatic-admission",
                workflow.replacen(
                    "run: ./target/ci/hell-ci custody-ops workflow-assemble-collection-worm",
                    "run: ./target/ci/hell-ci collection-authority verify-custody --worm-custody ci-out/collection-worm-custody",
                    1,
                ),
            ),
        ] {
            assert!(
                !collection_worm_bridge_policy(&mutant).is_empty(),
                "accepted collection WORM bridge substitution {label}"
            );
        }
    }

    #[test]
    fn collection_authority_merge_rejects_transport_and_identity_substitutions() {
        let campaign = include_str!("../../../.github/workflows/collection-authority.yml");
        let tool = include_str!("collection_transport.rs");
        assert_collection_workflow_mutants_rejected(
            tool,
            [
                ("workflow-path", campaign.replacen(
                "--workflow-path .github/workflows/collection-authority.yml",
                "--workflow-path .github/workflows/nightly.yml",
                1,
            )),
                ("merge-success", collection_job_mutant(
                campaign,
                "merge-collection-authority",
                " && needs.collection-authority-windows.result == 'success'",
                "",
            )),
                ("artifact-id", campaign.replacen(
                "needs.collection-authority-windows.outputs.artifact_id",
                "needs.collection-authority-macos.outputs.artifact_id",
                1,
            )),
                ("run-attempt", campaign.replacen(
                "--run-attempt \"$GITHUB_RUN_ATTEMPT\"",
                "--run-attempt 1",
                1,
            )),
                ("provider-candidate", campaign.replacen(
                "--provider-head \"$GITHUB_SHA\" --candidate-commit \"$HELL_SOURCE_COMMIT\"",
                "--provider-head \"$HELL_SOURCE_COMMIT\" --candidate-commit \"$GITHUB_SHA\"",
                1,
            )),
                ("merge-provider-head-verification", collection_job_mutant(
                campaign,
                "merge-collection-authority",
                "run: ./target/ci/hell-ci collection-authority verify-checkout --input . --candidate-commit \"$GITHUB_SHA\"",
                "run: true",
            )),
                ("subject-input", campaign.replacen(
                "collection-authority subject --input ci-out/collection-shard/linux-amd64",
                "collection-authority subject --input ci-out/collection-shard/macos-arm64",
                1,
            )),
                ("offline-verify", campaign.replacen(
                "collection-authority verify --input ci-out/native-shards",
                "merge-native-shards --input ci-out/native-shards",
                1,
            )),
                ("attested-subject", campaign.replacen(
                "subject-path: ci-out/collection-custody/custody-attestation-subject.json",
                "subject-path: ci-out/native-shards/collection-authority.json",
                1,
            )),
                ("name-download", campaign.replacen(
                "run: ./target/ci/hell-ci collection-authority acquire-provider --repository",
                "uses: actions/download-artifact@70fc10c6e5e1ce46ad2ea6f2b72d43f7d47b13c3 # v8.0.0\n        with:\n          name: collection-authority-merged\n      - run: true #",
                1,
            )),
            ],
        );
    }

    fn collection_custody_authority_mutants(campaign: &str) -> Vec<(&'static str, String)> {
        let reordered = campaign
            .replacen(COLLECTION_VERIFY_COMMAND, "run: __collection_verify__", 1)
            .replacen(COLLECTION_COMPACT_COMMAND, COLLECTION_VERIFY_COMMAND, 1)
            .replacen("run: __collection_verify__", COLLECTION_COMPACT_COMMAND, 1);
        let gh_reordered = campaign
            .replacen(
                COLLECTION_INSTALL_GH_COMMAND,
                "run: __collection_install_gh__",
                1,
            )
            .replacen(
                "uses: actions/attest@a1948c3f048ba23858d222213b7c278aabede763 # v4.1.1",
                COLLECTION_INSTALL_GH_COMMAND,
                1,
            )
            .replacen(
                "run: __collection_install_gh__",
                "uses: actions/attest@a1948c3f048ba23858d222213b7c278aabede763 # v4.1.1",
                1,
            );
        vec![
            ("compact-before-verify", reordered),
            ("gh-install-after-attest", gh_reordered),
            (
                "alternate-install-driver",
                campaign.replacen(
                    "run: ./target/ci/hell-ci collection-authority install-pinned-gh",
                    "run: cargo run --package hell-ci -- collection-authority install-pinned-gh",
                    1,
                ),
            ),
            (
                "verified-report-substitution",
                campaign.replacen(
                    "--verified-report ci-out/native-shards/collection-authority.json",
                    "--verified-report ci-out/native-shards/unverified.json",
                    1,
                ),
            ),
            (
                "attestation-bundle-substitution",
                campaign.replacen(
                    "steps.attest-collection-custody.outputs.bundle-path",
                    "steps.unreviewed.outputs.bundle-path",
                    1,
                ),
            ),
            (
                "path-gh-fallback",
                campaign.replacen(
                    "--gh-executable ci-out/collection-custody-tools/gh",
                    "--gh-executable gh",
                    1,
                ),
            ),
            (
                "gh-install-manifest-substitution",
                campaign.replacen(
                    "ci-out/collection-custody-tools/gh-install-manifest.json",
                    "ci-out/unreviewed-gh.json",
                    1,
                ),
            ),
            (
                "signature-output-substitution",
                campaign.replacen(
                    "--output ci-out/collection-custody-signature",
                    "--output ci-out/unreviewed-signature",
                    1,
                ),
            ),
        ]
    }

    fn collection_custody_transport_mutants(campaign: &str) -> Vec<(&'static str, String)> {
        vec![
            (
                "transient-provider-upload",
                campaign.replacen(
                    "            ci-out/collection-custody-signature\n",
                    "            ci-out/collection-provider\n",
                    1,
                ),
            ),
            (
                "transient-shard-upload",
                campaign.replacen(
                    "            ci-out/collection-custody\n",
                    "            ci-out/native-shards\n",
                    1,
                ),
            ),
            (
                "automatic-integration",
                campaign.replacen(
                    "      - name: Upload compact collection custody transport only",
                    "      - run: ./target/ci/hell-ci collection-authority verify-custody\n      - name: Upload compact collection custody transport only",
                    1,
                ),
            ),
            (
                "artifact-digest-output",
                campaign.replacen(
                    "steps.upload-collection-custody.outputs.artifact-digest",
                    "steps.upload-collection-custody.outputs.unreviewed",
                    1,
                ),
            ),
            (
                "transport-name",
                campaign.replacen(
                    "collection-authority-custody-${{ github.run_id }}-${{ github.run_attempt }}",
                    "collection-authority-merged-${{ github.run_id }}-${{ github.run_attempt }}",
                    1,
                ),
            ),
            (
                "unbounded-merge",
                campaign.replacen("timeout-minutes: 90", "timeout-minutes: 360", 1),
            ),
        ]
    }

    #[test]
    fn collection_custody_workflow_rejects_transient_or_uncontrolled_authority() {
        let campaign = include_str!("../../../.github/workflows/collection-authority.yml");
        let tool = include_str!("collection_transport.rs");
        assert_collection_workflow_mutants_rejected(
            tool,
            collection_custody_authority_mutants(campaign),
        );
        assert_collection_workflow_mutants_rejected(
            tool,
            collection_custody_transport_mutants(campaign),
        );
    }

    #[test]
    fn collection_transport_source_rejects_authority_substitutions() {
        let tool = include_str!("collection_transport.rs");
        let mut baseline = Vec::new();
        check_collection_transport_source(tool, &mut baseline);
        assert!(baseline.is_empty(), "{baseline:?}");
        for (label, mutant) in [
            (
                "release-version",
                tool.replacen(
                    "const GH_VERSION: &str = \"2.93.0\";",
                    "const GH_VERSION: &str = \"latest\";",
                    1,
                ),
            ),
            (
                "archive-digest",
                tool.replacen(
                    "02d1290eba130e0b896f3709ffff22e1c75a51475ddb70476a85abc6b5807af0",
                    "12d1290eba130e0b896f3709ffff22e1c75a51475ddb70476a85abc6b5807af0",
                    1,
                ),
            ),
            (
                "binary-digest",
                tool.replacen(
                    "014fcd614de4de5b4a1441d298175684bad99f713d10296c5fcaaba47ac332d1",
                    "114fcd614de4de5b4a1441d298175684bad99f713d10296c5fcaaba47ac332d1",
                    1,
                ),
            ),
            (
                "provider-pages",
                tool.replacen("fn provider_pages(", "fn unreviewed_provider_pages(", 1),
            ),
            (
                "attestation-validation",
                tool.replacen(
                    "fn validate_attestation_verification(",
                    "fn accept_verification_result(",
                    1,
                ),
            ),
            (
                "attestation-arguments",
                tool.replacen(
                    "fn attestation_verify_arguments(",
                    "fn unreviewed_attestation_arguments(",
                    1,
                ),
            ),
        ] {
            let mut failures = Vec::new();
            check_collection_transport_source(&mutant, &mut failures);
            assert!(
                !failures.is_empty(),
                "accepted collection transport source substitution {label}"
            );
        }
    }

    #[test]
    fn compliant_workflow_is_accepted() {
        let text = "on:\n  push:\njobs:\n  test:\n    steps:\n      - run: cargo test --locked\n      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n        with:\n          persist-credentials: false\n";
        assert!(workflow(text).is_empty());
    }

    #[test]
    fn cached_attribute_output_preserves_checkout_policy() {
        let attributes = parse_checked_attributes(
            b"compat/upstream-2026-05-29.json\0text\0auto\0compat/upstream-2026-05-29.json\0eol\0lf\0fixtures/upstream-2026-05-29/examples/01-hello-world.hell\0linguist-language\0Haskell\0",
        )
        .unwrap();
        let mut failures = Vec::new();
        require_attribute(
            &attributes,
            "compat/upstream-2026-05-29.json",
            "text",
            "auto",
            &mut failures,
        );
        require_attribute(
            &attributes,
            "compat/upstream-2026-05-29.json",
            "eol",
            "lf",
            &mut failures,
        );
        require_attribute(
            &attributes,
            "fixtures/upstream-2026-05-29/examples/01-hello-world.hell",
            "linguist-language",
            "Haskell",
            &mut failures,
        );
        assert!(failures.is_empty());

        require_attribute(
            &attributes,
            "compat/upstream-2026-05-29.json",
            "eol",
            "crlf",
            &mut failures,
        );
        assert_eq!(failures.len(), 1);
    }

    #[test]
    fn malformed_cached_attribute_output_is_rejected() {
        assert!(parse_checked_attributes(b"path\0text\0").is_err());
    }

    #[test]
    fn unsafe_workflow_forms_are_rejected() {
        for value in [
            "      - run: |\n          cargo test\n",
            "      - run: cargo test && cargo fmt\n",
            "      - run: tool --arg ${{ inputs.value }}\n",
            "      - run: sh -c test\n",
            "      - shell: bash\n",
            "      - env:\n          TOKEN: no\n",
            "      - uses: actions/checkout@main\n",
            "      - uses: webfactory/ssh-agent@e8389b4d7b1475c6d8657b5dc4b356c194ce72a0\n",
            "      - uses: actions/attest@0000000000000000000000000000000000000000\n",
            "  pull_request:\n",
            "    branches:\n      - main\n",
        ] {
            assert!(!workflow(value).is_empty(), "accepted {value:?}");
        }
    }

    #[test]
    fn duplicate_yaml_mapping_keys_are_rejected_per_mapping_scope() {
        let duplicate_job_key = "jobs:\n  publish:\n    timeout-minutes: 10\n    steps:\n    steps:\n      - run: cargo test\n";
        let duplicate_matrix_key = "jobs:\n  publish:\n    strategy:\n      matrix:\n        include:\n          - provider: primary\n            environment: first\n            environment: second\n";
        assert!(!workflow(duplicate_job_key).is_empty());
        assert!(!workflow(duplicate_matrix_key).is_empty());
        let sibling_steps = "jobs:\n  first:\n    steps:\n      - run: cargo test\n  second:\n    steps:\n      - run: cargo test\n";
        assert!(workflow(sibling_steps).is_empty());
    }

    #[test]
    fn workflow_dispatch_input_count_is_bounded_by_github() {
        use std::fmt::Write as _;

        let mut allowed_inputs = String::new();
        for index in 0..25 {
            writeln!(allowed_inputs, "      input_{index}:\n        type: string").unwrap();
        }
        let allowed = format!("on:\n  workflow_dispatch:\n    inputs:\n{allowed_inputs}");
        assert!(workflow(&allowed).is_empty());
        let excessive = format!("{allowed}      input_25:\n        type: string\n");
        assert!(!workflow(&excessive).is_empty());
    }

    #[test]
    fn protected_jobs_reject_candidate_builds_and_post_secret_compilation() {
        let candidate = "jobs:\n  review:\n    environment: protected\n    steps:\n      - uses: actions/checkout@pin\n        with:\n          ref: ${{ inputs.candidate_sha }}\n      - run: cargo build --package hell-ci\n";
        assert!(!workflow(candidate).is_empty());
        let late_build = "jobs:\n  review:\n    steps:\n      - uses: webfactory/ssh-agent@pin\n        with:\n          ssh-private-key: ${{ secrets.REVIEW_KEY }}\n      - run: cargo build --package hell-ci\n";
        assert!(!workflow(late_build).is_empty());
        let inherited_oidc = "permissions:\n  id-token: write\njobs:\n  review:\n    steps:\n      - uses: actions/checkout@pin\n        with:\n          ref: ${{ inputs.candidate_sha }}\n      - run: cargo build --package hell-ci\n";
        assert!(!workflow(inherited_oidc).is_empty());
        let unguarded_reusable = "on:\n  workflow_call:\njobs:\n  dispatch:\n    permissions:\n      actions: write\n    steps:\n      - run: cargo build --package hell-ci\n";
        assert!(!workflow(unguarded_reusable).is_empty());
        let feature_reusable = "on:\n  workflow_call:\njobs:\n  dispatch:\n    if: ${{ github.event_name == 'workflow_run' && github.ref == 'refs/heads/main' && github.workflow_ref == 'Portfoligno/hell-rs/.github/workflows/caller.yml@refs/heads/feature' }}\n    permissions:\n      actions: write\n    steps:\n      - run: cargo build --package hell-ci\n";
        assert!(!workflow(feature_reusable).is_empty());
        for untrusted_ref in [
            "refs/heads/feature",
            "refs/tags/release",
            "${{ github.sha }}",
        ] {
            let dispatch = format!(
                "on:\n  workflow_dispatch:\njobs:\n  review:\n    if: ${{{{ github.ref == '{untrusted_ref}' }}}}\n    environment: protected\n    steps:\n      - run: true\n"
            );
            assert!(!workflow(&dispatch).is_empty());
        }
        for bypass in [
            "jobs:\n  review:\n    environment: protected\n    steps:\n      - if: ${{ github.ref == 'refs/heads/main' }}\n        run: true\n",
            "jobs:\n  review:\n    if: ${{ github.ref == 'refs/heads/main' || github.actor == 'trusted' }}\n    environment: protected\n    steps:\n      - run: true\n",
            "jobs:\n  review:\n    if: ${{ github.ref == 'refs/heads/main' && true || github.actor == 'trusted' }}\n    environment: protected\n    steps:\n      - run: true\n",
            "jobs:\n  review:\n    environment: protected\n    steps:\n      - run: echo github.ref == 'refs/heads/main'\n",
        ] {
            let dispatch = format!("on:\n  workflow_dispatch:\n{bypass}");
            assert!(!workflow(&dispatch).is_empty());
        }
        let trusted = "jobs:\n  review:\n    if: ${{ github.ref == 'refs/heads/main' }}\n    environment: protected\n    steps:\n      - uses: actions/checkout@pin\n        with:\n          ref: ${{ github.sha }}\n      - run: cargo build --package hell-ci\n      - uses: webfactory/ssh-agent@pin\n        with:\n          ssh-private-key: ${{ secrets.REVIEW_KEY }}\n";
        let mut failures = Vec::new();
        check_protected_job_trust_isolation(
            &workflow_path("trusted.yml"),
            &trusted.lines().collect::<Vec<_>>(),
            &mut failures,
        );
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    #[test]
    fn only_the_reviewed_source_commit_workflow_binding_is_accepted() {
        assert!(workflow("env:\n  HELL_SOURCE_COMMIT: ${{ github.sha }}\n").is_empty());
        assert!(!workflow("env:\n  HELL_SOURCE_COMMIT: untrusted\n").is_empty());
        assert!(!workflow("  env:\n    HELL_SOURCE_COMMIT: ${{ github.sha }}\n").is_empty());
    }

    #[test]
    fn only_the_literal_surveillance_incident_token_binding_is_accepted() {
        let valid = "      - name: Upsert promotion surveillance incident\n        env:\n          GITHUB_TOKEN: ${{ github.token }}\n        run: ./target/ci/hell-ci surveillance-ops workflow-alert\n";
        let mut failures = Vec::new();
        check_workflow(
            &workflow_path("promotion-surveillance.yml"),
            valid,
            &mut failures,
        );
        assert!(failures.is_empty(), "{}", failures.join("\n"));
        for valid_watchdog in [
            "      - name: Check expected surveillance deadline\n        env:\n          GITHUB_TOKEN: ${{ github.token }}\n        run: ./target/ci/hell-ci surveillance-ops workflow-deadline\n",
            "      - name: Upsert missed surveillance deadline incident\n        env:\n          GITHUB_TOKEN: ${{ github.token }}\n        run: ./target/ci/hell-ci surveillance-ops workflow-alert\n",
        ] {
            let mut failures = Vec::new();
            check_workflow(
                &workflow_path("promotion-surveillance-watchdog.yml"),
                valid_watchdog,
                &mut failures,
            );
            assert!(failures.is_empty(), "{}", failures.join("\n"));
        }

        for (path, body) in [
            (&workflow_path("other.yml"), valid),
            (
                &workflow_path("promotion-surveillance.yml"),
                "      - name: Upsert promotion surveillance incident\n        env:\n          GITHUB_TOKEN: ${{ secrets.UNRELATED }}\n        run: ./target/ci/hell-ci surveillance-ops workflow-alert\n",
            ),
            (
                &workflow_path("promotion-surveillance.yml"),
                "      - name: Upsert promotion surveillance incident\n        env:\n          GITHUB_TOKEN: ${{ github.token }}\n        run: gh issue create\n",
            ),
        ] {
            let mut failures = Vec::new();
            check_workflow(path, body, &mut failures);
            assert!(!failures.is_empty(), "accepted {path:?} {body:?}");
        }
    }

    #[test]
    fn review_authorization_token_is_allowed_only_on_exact_review_steps() {
        let component = "      - name: Verify exact semantic review components\n        env:\n          GITHUB_TOKEN: ${{ secrets.REVIEW_AUTHORIZATION_GITHUB_TOKEN }}\n        run: ./target/ci/hell-ci offline-review-ops workflow-verify-components\n";
        let graph = "      - name: Retain final graph reviewer authorization and provider selection\n        env:\n          GITHUB_TOKEN: ${{ secrets.REVIEW_AUTHORIZATION_GITHUB_TOKEN }}\n        run: ./target/ci/hell-ci review-authorization --input ci-out/evidence/review/graph-review-subject.json --output ci-out/evidence/review/auth/role-graph/authorization.json --role review-graph-reviewer --category final-review-graph --github-dispatch-inputs\n";
        let artifact = "      - name: Retain stable protected reviewer authorization\n        env:\n          GITHUB_TOKEN: ${{ secrets.REVIEW_AUTHORIZATION_GITHUB_TOKEN }}\n        run: ./target/ci/hell-ci review-authorization --input ci-out/acquisition/artifact-findings.subject.json --output ci-out/acquisition/authorization.json --role artifact-trust-reviewer --category artifact-trust-final --github-dispatch-inputs\n";
        let mutation = "      - name: Retain stable protected mutation reviewer authorization\n        env:\n          GITHUB_TOKEN: ${{ secrets.REVIEW_AUTHORIZATION_GITHUB_TOKEN }}\n        run: ./target/ci/hell-ci review-authorization --input ci-out/mutation/mutation-score.pending.json --output ci-out/mutation/authorization.json --role mutation-reviewer --category mutation-final --github-dispatch-inputs\n";
        let promotion = "      - name: Retain exact protected promotion authorization\n        env:\n          GITHUB_TOKEN: ${{ secrets.REVIEW_AUTHORIZATION_GITHUB_TOKEN }}\n        run: ./target/ci/hell-ci review-authorization --input ci-out/native-shards/promotion-approval-subject.json --output ci-out/native-shards/authorization.json --role promotion-approver --category promotion-final --github-dispatch-inputs\n";
        let platform_macos = "      - name: Retain exact protected macOS platform reviewer authorization\n        env:\n          GITHUB_TOKEN: ${{ secrets.REVIEW_AUTHORIZATION_GITHUB_TOKEN }}\n        run: ./target/ci/hell-ci review-authorization --input ci-out/provider-subject/platform-review-packet.json --output ci-out/authorization.json --role platform-reviewer --category oracle-platform-final --platform macos-arm64 --github-dispatch-inputs\n";
        let platform_windows = "      - name: Retain exact protected Windows platform reviewer authorization\n        env:\n          GITHUB_TOKEN: ${{ secrets.REVIEW_AUTHORIZATION_GITHUB_TOKEN }}\n        run: ./target/ci/hell-ci review-authorization --input ci-out/provider-subject/platform-review-packet.json --output ci-out/authorization.json --role platform-reviewer --category oracle-platform-final --platform windows-amd64 --github-dispatch-inputs\n";
        let custody = "      - name: Retain exact protected custody reviewer authorization\n        env:\n          GITHUB_TOKEN: ${{ secrets.REVIEW_AUTHORIZATION_GITHUB_TOKEN }}\n        run: ./target/ci/hell-ci review-authorization --input ci-out/custody-subject/review-packet.json --output ci-out/custody/authorization.json --role custody-reviewer --category custody-final --github-dispatch-inputs\n";
        for (path, body) in [
            (&workflow_path("promotion-evidence-review.yml"), component),
            (&workflow_path("evidence-custody.yml"), graph),
            (
                &workflow_path("artifact-authenticity-finalize.yml"),
                artifact,
            ),
            (&workflow_path("mutation.yml"), mutation),
            (&workflow_path("promotion-approval.yml"), promotion),
            (&workflow_path("oracle-reproduce.yml"), platform_macos),
            (&workflow_path("oracle-reproduce.yml"), platform_windows),
            (&workflow_path("evidence-custody.yml"), custody),
        ] {
            let mut failures = Vec::new();
            check_workflow(path, body, &mut failures);
            assert!(failures.is_empty(), "{}", failures.join("\n"));
        }
        let mut failures = Vec::new();
        check_workflow(&workflow_path("other.yml"), graph, &mut failures);
        assert!(!failures.is_empty());
    }

    #[test]
    fn promotion_assurance_workflows_pass_strict_policy_scan() {
        let nightly = include_str!("../../../.github/workflows/nightly.yml");
        assert!(nightly.contains(
            "        if: ${{ always() && github.event_name == 'schedule' }}\n        run: ./target/ci/hell-ci regression-import explore-generated --input ci-out --output ci-out/regression-exploration"
        ));
        for (path, body) in [
            (
                ".github/workflows/artifact-authenticity-finalize.yml",
                include_str!("../../../.github/workflows/artifact-authenticity-finalize.yml"),
            ),
            (
                ".github/workflows/artifact-authenticity-review.yml",
                include_str!("../../../.github/workflows/artifact-authenticity-review.yml"),
            ),
            (
                ".github/workflows/artifact-independent-acquisition.yml",
                include_str!("../../../.github/workflows/artifact-independent-acquisition.yml"),
            ),
            (
                ".github/workflows/mutation.yml",
                include_str!("../../../.github/workflows/mutation.yml"),
            ),
            (
                ".github/workflows/claim-applicability-decisions.yml",
                include_str!("../../../.github/workflows/claim-applicability-decisions.yml"),
            ),
            (
                ".github/workflows/custody-scrub.yml",
                include_str!("../../../.github/workflows/custody-scrub.yml"),
            ),
            (
                ".github/workflows/evidence-custody.yml",
                include_str!("../../../.github/workflows/evidence-custody.yml"),
            ),
            (
                ".github/workflows/oracle-reproduce.yml",
                include_str!("../../../.github/workflows/oracle-reproduce.yml"),
            ),
            (
                ".github/workflows/nightly.yml",
                include_str!("../../../.github/workflows/nightly.yml"),
            ),
            (
                ".github/workflows/collection-authority.yml",
                include_str!("../../../.github/workflows/collection-authority.yml"),
            ),
            (
                ".github/workflows/collection-activation-preparation.yml",
                include_str!("../../../.github/workflows/collection-activation-preparation.yml"),
            ),
            (
                ".github/workflows/collection-activation.yml",
                include_str!("../../../.github/workflows/collection-activation.yml"),
            ),
        ] {
            let mut failures = Vec::new();
            check_workflow(Path::new(path), body, &mut failures);
            assert!(failures.is_empty(), "{path}: {}", failures.join("\n"));
        }
    }

    #[test]
    fn remaining_promotion_assurance_workflows_pass_strict_policy_scan() {
        for (path, body) in [
            (
                ".github/workflows/promotion-approval.yml",
                include_str!("../../../.github/workflows/promotion-approval.yml"),
            ),
            (
                ".github/workflows/promotion-evidence-review.yml",
                include_str!("../../../.github/workflows/promotion-evidence-review.yml"),
            ),
            (
                ".github/workflows/promotion-proposal.yml",
                include_str!("../../../.github/workflows/promotion-proposal.yml"),
            ),
            (
                ".github/workflows/regression-corpus.yml",
                include_str!("../../../.github/workflows/regression-corpus.yml"),
            ),
            (
                ".github/workflows/regression-subject.yml",
                include_str!("../../../.github/workflows/regression-subject.yml"),
            ),
            (
                ".github/workflows/regression-subject-shard.yml",
                include_str!("../../../.github/workflows/regression-subject-shard.yml"),
            ),
            (
                ".github/workflows/regression-dispatch-shard.yml",
                include_str!("../../../.github/workflows/regression-dispatch-shard.yml"),
            ),
            (
                ".github/workflows/promotion-surveillance.yml",
                include_str!("../../../.github/workflows/promotion-surveillance.yml"),
            ),
            (
                ".github/workflows/promotion-surveillance-watchdog.yml",
                include_str!("../../../.github/workflows/promotion-surveillance-watchdog.yml"),
            ),
            (
                ".github/workflows/custody-provider-selector-recovery.yml",
                include_str!("../../../.github/workflows/custody-provider-selector-recovery.yml"),
            ),
            (
                ".github/workflows/custody-provider-selector-seal.yml",
                include_str!("../../../.github/workflows/custody-provider-selector-seal.yml"),
            ),
            (
                ".github/workflows/assurance-transport-readiness.yml",
                include_str!("../../../.github/workflows/assurance-transport-readiness.yml"),
            ),
            (
                ".github/workflows/assurance-transport-signer-a.yml",
                include_str!("../../../.github/workflows/assurance-transport-signer-a.yml"),
            ),
            (
                ".github/workflows/assurance-transport-signer-b.yml",
                include_str!("../../../.github/workflows/assurance-transport-signer-b.yml"),
            ),
        ] {
            let mut failures = Vec::new();
            check_workflow(Path::new(path), body, &mut failures);
            assert!(failures.is_empty(), "{path}: {}", failures.join("\n"));
        }
    }

    #[test]
    fn every_cosign_installer_pins_the_exact_executable_release() {
        for (path, workflow) in [
            (
                ".github/workflows/nightly.yml",
                include_str!("../../../.github/workflows/nightly.yml"),
            ),
            (
                ".github/workflows/evidence-custody.yml",
                include_str!("../../../.github/workflows/evidence-custody.yml"),
            ),
            (
                ".github/workflows/assurance-transport-readiness.yml",
                include_str!("../../../.github/workflows/assurance-transport-readiness.yml"),
            ),
        ] {
            let lines = workflow.lines().collect::<Vec<_>>();
            let mut failures = Vec::new();
            check_exact_cosign_release(Path::new(path), &lines, &mut failures);
            assert!(failures.is_empty(), "{path}: {}", failures.join("\n"));
            for (label, mutant) in [
                (
                    "release-omission",
                    workflow.replacen("          cosign-release: v2.4.3\n", "", 1),
                ),
                (
                    "release-substitution",
                    workflow.replacen("cosign-release: v2.4.3", "cosign-release: latest", 1),
                ),
            ] {
                let lines = mutant.lines().collect::<Vec<_>>();
                let mut failures = Vec::new();
                check_exact_cosign_release(Path::new(path), &lines, &mut failures);
                assert!(!failures.is_empty(), "accepted {label} in {path}");
            }
        }
    }

    #[test]
    fn external_independent_request_is_sealed_before_credentials() {
        let workflow =
            include_str!("../../../.github/workflows/artifact-independent-acquisition.yml");
        let mut failures = Vec::new();
        check_external_independent_preflight(workflow, &mut failures);
        assert!(failures.is_empty(), "{}", failures.join("\n"));
        for (label, mutant) in [
            (
                "preflight-omission",
                workflow.replacen("prepare-external-independent", "external-independent", 1),
            ),
            (
                "preflight-credentials",
                workflow.replacen(
                    "permissions:\n      contents: read",
                    "permissions:\n      contents: read\n      id-token: write",
                    1,
                ),
            ),
            (
                "mutable-request-name",
                workflow.replacen(
                    "artifact-ids: ${{ needs.prepare-request.outputs.request_artifact_id }}",
                    "name: artifact-independent-request",
                    1,
                ),
            ),
            (
                "source-artifact-id-omission",
                workflow.replacen(
                    "      source_artifact_id:\n        type: string\n        required: true\n",
                    "",
                    1,
                ),
            ),
            (
                "source-artifact-id-run-substitution",
                workflow.replacen("source_artifact_id:", "source_run_id:", 1),
            ),
            (
                "request-substitution",
                workflow.replacen(
                    "--input ci-out/acquisition/external-independent-request.json",
                    "--input ci-out/acquisition/unsealed.json",
                    1,
                ),
            ),
            (
                "precredential-verification-omission",
                workflow.replacen(
                    "artifact-acquire verify-external-independent-request",
                    "artifact-acquire external-independent-request-unverified",
                    1,
                ),
            ),
            (
                "precredential-verification-after-aws",
                workflow.replacen(
                    "      - name: Verify sealed external acquisition request before credentials\n        run: ./target/ci/hell-ci artifact-acquire verify-external-independent-request --input ci-out/acquisition/external-independent-request.json --artifact native-oracle-merged\n",
                    "",
                    1,
                ),
            ),
            (
                "dispatch-rederivation",
                workflow.replacen(
                    "--artifact native-oracle-merged\n      - name: Install pinned Sigstore",
                    "--artifact native-oracle-merged --github-dispatch-inputs\n      - name: Install pinned Sigstore",
                    1,
                ),
            ),
            (
                "credentials-before-request",
                workflow.replacen(
                    "artifact-ids: ${{ needs.prepare-request.outputs.request_artifact_id }}",
                    "artifact-ids: unbound",
                    1,
                ),
            ),
        ] {
            let mut failures = Vec::new();
            check_external_independent_preflight(&mutant, &mut failures);
            assert!(!failures.is_empty(), "accepted external preflight mutant {label}");
        }
    }

    #[test]
    fn collection_activation_review_is_two_role_and_non_authoritative() {
        let workflow = include_str!("../../../.github/workflows/collection-activation.yml");
        let mut failures = Vec::new();
        check_collection_activation_review(workflow, &mut failures);
        assert!(failures.is_empty(), "{}", failures.join("\n"));
        for (label, mutant) in activation_review_transport_mutants(workflow)
            .into_iter()
            .chain(activation_review_role_mutants(workflow))
        {
            let mut failures = Vec::new();
            check_collection_activation_review(&mutant, &mut failures);
            assert!(
                !failures.is_empty(),
                "accepted activation review mutant {label}"
            );
        }
    }

    fn activation_review_transport_mutants(workflow: &str) -> Vec<(&'static str, String)> {
        vec![
            (
                "push-trigger",
                workflow.replacen("  workflow_dispatch:", "  push:\n  workflow_dispatch:", 1),
            ),
            (
                "outer-artifact-name",
                workflow.replacen(
                    "collection-activation-proposal-${{ github.run_id }}-${{ github.run_attempt }}",
                    "collection-activation-proposal",
                    1,
                ),
            ),
            (
                "review-subject-artifact-digest",
                workflow.replacen(
                    "artifact_digest: ${{ steps.upload-proposal.outputs.artifact-digest }}",
                    "artifact_digest: unbound",
                    1,
                ),
            ),
            (
                "review-subject-directory-digest",
                workflow.replacen(
                    "directory_sha256: ${{ steps.bind-review-subject.outputs.directory_sha256 }}",
                    "directory_sha256: unbound",
                    1,
                ),
            ),
            (
                "author-wrapper-artifact-id-substitution",
                workflow.replacen(
                    "artifact-ids: ${{ needs.retain-proposal.outputs.artifact_id }}",
                    "artifact-ids: ${{ inputs.proposal_artifact_id }}",
                    1,
                ),
            ),
            (
                "reviewer-wrapper-artifact-id-substitution",
                workflow.replacen(
                    "artifact-ids: ${{ needs.retain-proposal.outputs.artifact_id }}",
                    "artifact-ids: ${{ inputs.proposal_artifact_id }}",
                    2,
                ),
            ),
            (
                "finalizer-wrapper-directory-substitution",
                workflow.replacen(
                    "WRAPPER_DIRECTORY_SHA256: ${{ needs.retain-proposal.outputs.directory_sha256 }}",
                    "WRAPPER_DIRECTORY_SHA256: ${{ inputs.proposal_directory_sha256 }}",
                    3,
                ),
            ),
            (
                "author-checkout",
                workflow.replacen(
                    "collection-authority verify-checkout --input . --candidate-commit \"$COLLECTION_ACTIVATION_SHA\"",
                    "collection-authority verify-checkout --input . --candidate-commit HEAD",
                    2,
                ),
            ),
        ]
    }

    fn activation_review_role_mutants(workflow: &str) -> Vec<(&'static str, String)> {
        vec![
            (
                "author-environment",
                workflow.replacen(
                    "environment: compatibility-claim-author",
                    "environment: compatibility-claim-review",
                    1,
                ),
            ),
            (
                "author-role",
                workflow.replacen("--role claim-author", "--role claim-reviewer", 1),
            ),
            (
                "reviewer-role",
                workflow.replacen("--role claim-reviewer", "--role claim-author", 1),
            ),
            (
                "signed-package-directory-archive-substitution",
                workflow.replacen(
                    "directory_sha256: ${{ steps.bind-review.outputs.directory_sha256 }}",
                    "directory_sha256: ${{ steps.upload-review.outputs.artifact-digest }}",
                    1,
                ),
            ),
            (
                "signed-package-directory-binding-omission",
                workflow.replacen("        id: bind-review", "        id: unbound-review", 1),
            ),
            (
                "author-before-packet",
                workflow.replacen(
                    author_packet_marker(),
                    "review-packet --input unverified",
                    1,
                ),
            ),
            (
                "reviewer-before-packet",
                workflow.replacen(
                    reviewer_packet_marker(),
                    "review-packet --input unverified",
                    1,
                ),
            ),
            (
                "author-artifact-id",
                workflow.replacen(
                    "needs.claim-author.outputs.artifact_id",
                    "inputs.claim_author_artifact_id",
                    1,
                ),
            ),
            (
                "cosign-pin",
                workflow.replacen(
                    "sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6",
                    "sigstore/cosign-installer@main",
                    1,
                ),
            ),
            (
                "finalizer-cosign-omission",
                workflow.replacen(
                    "      - name: Install pinned activation review verifier after exact input validation\n        uses: sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6 # v4.1.2\n",
                    "",
                    1,
                ),
            ),
            (
                "reviewer-artifact-id",
                workflow.replacen(
                    "needs.claim-reviewer.outputs.artifact_id",
                    "inputs.claim_reviewer_artifact_id",
                    1,
                ),
            ),
            (
                "commit-write",
                workflow.replacen("contents: read", "contents: write", 1),
            ),
            (
                "directory-digest",
                workflow.replacen(
                    "tree_directory_sha256: ${{ steps.bind-tree.outputs.directory_sha256 }}",
                    "tree_directory_sha256: unbound",
                    1,
                ),
            ),
        ]
    }

    fn author_packet_marker() -> &'static str {
        "review-packet --input ci-in/collection-activation-review-subject/review-subject.json --from ci-out/collection-activation-review/claim-author/authorization.json --output ci-out/collection-activation-review/claim-author/review-packet.json --role claim-author --category collection-activation-author --decision accept --github-dispatch-inputs"
    }

    fn reviewer_packet_marker() -> &'static str {
        "review-packet --input ci-in/collection-activation-review-subject/review-subject.json --from ci-out/collection-activation-review/claim-reviewer/authorization.json --output ci-out/collection-activation-review/claim-reviewer/review-packet.json --role claim-reviewer --category collection-activation-final --decision accept --github-dispatch-inputs"
    }

    fn active_repository_consumer_workflows() -> Vec<(PathBuf, &'static str)> {
        [
            ("ci.yml", include_str!("../../../.github/workflows/ci.yml")),
            (
                "nightly.yml",
                include_str!("../../../.github/workflows/nightly.yml"),
            ),
            (
                "oracle-reproduce.yml",
                include_str!("../../../.github/workflows/oracle-reproduce.yml"),
            ),
            (
                "promotion-proposal.yml",
                include_str!("../../../.github/workflows/promotion-proposal.yml"),
            ),
            (
                "promotion-evidence-review.yml",
                include_str!("../../../.github/workflows/promotion-evidence-review.yml"),
            ),
            (
                "claim-applicability-decisions.yml",
                include_str!("../../../.github/workflows/claim-applicability-decisions.yml"),
            ),
            (
                "promotion-surveillance.yml",
                include_str!("../../../.github/workflows/promotion-surveillance.yml"),
            ),
            (
                "evidence-custody.yml",
                include_str!("../../../.github/workflows/evidence-custody.yml"),
            ),
            (
                "mutation.yml",
                include_str!("../../../.github/workflows/mutation.yml"),
            ),
            (
                "artifact-authenticity-finalize.yml",
                include_str!("../../../.github/workflows/artifact-authenticity-finalize.yml"),
            ),
            (
                "promotion-surveillance-watchdog.yml",
                include_str!("../../../.github/workflows/promotion-surveillance-watchdog.yml"),
            ),
            (
                "promotion-initial-public-finalize.yml",
                include_str!("../../../.github/workflows/promotion-initial-public-finalize.yml"),
            ),
            (
                "evidence-custody.yml",
                include_str!("../../../.github/workflows/evidence-custody.yml"),
            ),
            (
                "custody-scrub.yml",
                include_str!("../../../.github/workflows/custody-scrub.yml"),
            ),
            (
                "artifact-authenticity-review.yml",
                include_str!("../../../.github/workflows/artifact-authenticity-review.yml"),
            ),
        ]
        .into_iter()
        .map(|(name, workflow)| (workflow_path(name), workflow))
        .collect()
    }

    fn deleted_ci_verify_job(ci: &str) -> String {
        let start = ci
            .find("  verify:\n")
            .expect("CI workflow must retain the verify job");
        let end = ci[start..]
            .find("\n  portability-macos:\n")
            .map(|offset| start + offset + 1)
            .expect("CI verify job must precede portability-macos");
        let mut mutant = ci.to_owned();
        mutant.replace_range(start..end, "");
        mutant
    }

    fn active_repository_consumer_mutants(ci: &str) -> Vec<(&'static str, String)> {
        vec![
            ("deleted-job", deleted_ci_verify_job(ci)),
            (
                "renamed-job",
                ci.replacen("  verify:", "  verify-renamed:", 1),
            ),
            (
                "omitted",
                ci.replace(
                    "      - name: Install pinned active-review verifier\n        uses: sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6 # v4.1.2\n        with:\n          cosign-release: v2.4.3\n\n",
                    "",
                ),
            ),
            (
                "mutable-pin",
                ci.replace(
                    "sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6",
                    "sigstore/cosign-installer@main",
                ),
            ),
            (
                "version-substitution",
                ci.replace("# v4.1.2", "# v4.2.0"),
            ),
            (
                "after-consumer",
                ci.replacen(
                    "      - name: Install pinned active-review verifier\n        uses: sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6 # v4.1.2\n        with:\n          cosign-release: v2.4.3\n\n      - name: Verify fail-closed assurance policy\n        run: ./target/ci/hell-ci assurance-verify --output ci-out/assurance-policy.json",
                    "      - name: Verify fail-closed assurance policy\n        run: ./target/ci/hell-ci assurance-verify --output ci-out/assurance-policy.json\n\n      - name: Install pinned active-review verifier\n        uses: sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6 # v4.1.2\n        with:\n          cosign-release: v2.4.3",
                    1,
                ),
            ),
        ]
    }

    #[test]
    fn fresh_activated_campaign_has_bounded_three_platform_liveness() {
        let workflow = include_str!("../../../.github/workflows/nightly.yml");
        let mut failures = Vec::new();
        check_fresh_activated_campaign_liveness(workflow, &mut failures);
        assert!(failures.is_empty(), "{}", failures.join("\n"));
        for mutant in [
            workflow.replacen("timeout-minutes: 120", "timeout-minutes: 60", 1),
            workflow.replacen("timeout-minutes: 180", "timeout-minutes: 90", 1),
            workflow.replacen(
                "./target/ci/hell-ci nightly --oracle",
                "./target/ci/hell-ci collection-authority verify-custody --oracle",
                1,
            ),
            workflow.replacen(
                "evidence-epoch write --output ci-out/native-shards/assurance-epoch.json",
                "evidence-epoch verify --output ci-out/native-shards/assurance-epoch.json",
                1,
            ),
        ] {
            let mut failures = Vec::new();
            check_fresh_activated_campaign_liveness(&mutant, &mut failures);
            assert!(!failures.is_empty());
        }
    }

    #[test]
    fn active_repository_consumers_install_the_exact_verifier_before_use() {
        for (path, workflow) in active_repository_consumer_workflows() {
            let mut failures = Vec::new();
            check_active_repository_verifier_liveness(&path, workflow, true, &mut failures);
            assert!(failures.is_empty(), "{}", failures.join("\n"));
        }

        let ci = include_str!("../../../.github/workflows/ci.yml");
        for (label, mutant) in active_repository_consumer_mutants(ci) {
            let mut failures = Vec::new();
            check_active_repository_verifier_liveness(
                &workflow_path("ci.yml"),
                &mutant,
                true,
                &mut failures,
            );
            assert!(!failures.is_empty(), "accepted {label}");
        }

        let custody = include_str!("../../../.github/workflows/evidence-custody.yml");
        let conditional_substitution = custody.replacen(
            "      - name: Install pinned active-review verifier\n        if: ${{ inputs.artifact_class != 'collection-custody' }}",
            "      - name: Install pinned active-review verifier\n        if: ${{ inputs.artifact_class == 'collection-custody' }}",
            1,
        );
        let mut failures = Vec::new();
        check_active_repository_verifier_liveness(
            &workflow_path("evidence-custody.yml"),
            &conditional_substitution,
            true,
            &mut failures,
        );
        assert!(!failures.is_empty(), "accepted conditional substitution");
    }

    #[test]
    fn claim_decision_producer_verifies_both_exact_sources_before_coverage() {
        let workflow = include_str!("../../../.github/workflows/claim-applicability-decisions.yml");
        let mut failures = Vec::new();
        check_claim_applicability_decision_checkouts(workflow, &mut failures);
        assert!(failures.is_empty(), "{}", failures.join("\n"));
        for (label, mutant) in [
            (
                "candidate-checkout-omission",
                workflow.replacen(
                    "run: ./target/ci/hell-ci collection-authority verify-checkout --input . --candidate-commit \"$CLAIM_CANDIDATE_SHA\"",
                    "run: true",
                    1,
                ),
            ),
            (
                "candidate-substitution",
                workflow.replacen(
                    "--candidate-commit \"$CLAIM_CANDIDATE_SHA\"",
                    "--candidate-commit HEAD",
                    1,
                ),
            ),
            (
                "decision-checkout-omission",
                workflow.replacen(
                    "run: ./target/ci/hell-ci collection-authority verify-checkout --input decision-source --candidate-commit \"$CLAIM_DECISION_SOURCE_SHA\"",
                    "run: true",
                    1,
                ),
            ),
            (
                "decision-source-substitution",
                workflow.replacen("--input decision-source", "--input .", 1),
            ),
            (
                "provider-token-omission",
                workflow.replacen("          GITHUB_TOKEN: ${{ github.token }}", "", 1),
            ),
            (
                "provider-token-substitution",
                workflow.replacen(
                    "GITHUB_TOKEN: ${{ github.token }}",
                    "GITHUB_TOKEN: ${{ secrets.UNREVIEWED_TOKEN }}",
                    1,
                ),
            ),
        ] {
            let mut failures = Vec::new();
            check_claim_applicability_decision_checkouts(&mutant, &mut failures);
            assert!(!failures.is_empty(), "accepted {label}");
        }
    }

    #[test]
    fn primary_acquisition_binds_provider_workflow_bytes_to_candidate_head() {
        let workflow = include_str!("../../../.github/workflows/artifact-authenticity-review.yml");
        let mut failures = Vec::new();
        check_primary_acquisition_checkout(workflow, &mut failures);
        assert!(failures.is_empty(), "{}", failures.join("\n"));
        for (label, mutant) in [
            (
                "current-candidate-equality-omission",
                workflow.replacen(" && inputs.candidate_sha == github.sha", "", 1),
            ),
            (
                "candidate-checkout-substitution",
                workflow.replacen("ref: ${{ github.sha }}", "ref: ${{ inputs.candidate_sha }}", 1),
            ),
            (
                "typed-checkout-omission",
                workflow.replacen(
                    "        run: ./target/ci/hell-ci collection-authority verify-checkout --input . --candidate-commit \"$ACQUISITION_CANDIDATE_SHA\"",
                    "        run: ./target/ci/hell-ci assurance-verify --report ci-out/unbound.json",
                    1,
                ),
            ),
            (
                "immutable-artifact-id-omission",
                workflow.replacen(
                    "          artifact-ids: ${{ inputs.source_artifact_id }}",
                    "          name: native-oracle-merged",
                    1,
                ),
            ),
            (
                "artifact-id-run-substitution",
                workflow.replacen(
                    "artifact-ids: ${{ inputs.source_artifact_id }}",
                    "artifact-ids: ${{ inputs.source_run_id }}",
                    1,
                ),
            ),
        ] {
            let mut failures = Vec::new();
            check_primary_acquisition_checkout(&mutant, &mut failures);
            assert!(!failures.is_empty(), "accepted {label}");
        }
    }

    #[test]
    fn every_provider_replay_has_one_exact_step_scoped_read_token() {
        for (name, workflow) in [
            (
                "claim-applicability-decisions.yml",
                include_str!("../../../.github/workflows/claim-applicability-decisions.yml"),
            ),
            (
                "promotion-evidence-review.yml",
                include_str!("../../../.github/workflows/promotion-evidence-review.yml"),
            ),
            (
                "promotion-proposal.yml",
                include_str!("../../../.github/workflows/promotion-proposal.yml"),
            ),
            (
                "promotion-approval.yml",
                include_str!("../../../.github/workflows/promotion-approval.yml"),
            ),
            (
                "artifact-authenticity-finalize.yml",
                include_str!("../../../.github/workflows/artifact-authenticity-finalize.yml"),
            ),
            (
                "promotion-surveillance.yml",
                include_str!("../../../.github/workflows/promotion-surveillance.yml"),
            ),
        ] {
            let path = workflow_path(name);
            let mut failures = Vec::new();
            check_provider_replay_token_binding(&path, workflow, true, &mut failures);
            assert!(failures.is_empty(), "{name}: {}", failures.join("\n"));
            for (label, mutant) in [
                (
                    "omitted",
                    workflow.replace("          GITHUB_TOKEN: ${{ github.token }}", ""),
                ),
                (
                    "substituted",
                    workflow.replace(
                        "GITHUB_TOKEN: ${{ github.token }}",
                        "GITHUB_TOKEN: ${{ secrets.UNREVIEWED_TOKEN }}",
                    ),
                ),
            ] {
                let mut failures = Vec::new();
                check_provider_replay_token_binding(&path, &mutant, true, &mut failures);
                assert!(!failures.is_empty(), "accepted {label} token in {name}");
            }
        }
    }

    #[test]
    fn promotion_packages_expose_exact_immutable_handoff_outputs() {
        for (name, workflow) in [
            (
                "promotion-proposal.yml",
                include_str!("../../../.github/workflows/promotion-proposal.yml"),
            ),
            (
                "promotion-approval.yml",
                include_str!("../../../.github/workflows/promotion-approval.yml"),
            ),
        ] {
            let path = workflow_path(name);
            let mut failures = Vec::new();
            check_promotion_package_handoff(&path, workflow, &mut failures);
            assert!(failures.is_empty(), "{name}: {}", failures.join("\n"));
            for (label, mutant) in promotion_handoff_mutants(name, workflow) {
                let mut failures = Vec::new();
                check_promotion_package_handoff(&path, &mutant, &mut failures);
                assert!(!failures.is_empty(), "accepted {label} in {name}");
            }
        }
    }

    #[test]
    fn promotion_state_jobs_bind_exact_trusted_driver_head_before_provider_work() {
        for (name, workflow) in [
            (
                "nightly.yml",
                include_str!("../../../.github/workflows/nightly.yml"),
            ),
            (
                "promotion-initial-public-finalize.yml",
                include_str!("../../../.github/workflows/promotion-initial-public-finalize.yml"),
            ),
            (
                "promotion-surveillance.yml",
                include_str!("../../../.github/workflows/promotion-surveillance.yml"),
            ),
            (
                "evidence-custody.yml",
                include_str!("../../../.github/workflows/evidence-custody.yml"),
            ),
            (
                "mutation.yml",
                include_str!("../../../.github/workflows/mutation.yml"),
            ),
            (
                "artifact-authenticity-finalize.yml",
                include_str!("../../../.github/workflows/artifact-authenticity-finalize.yml"),
            ),
            (
                "oracle-reproduce.yml",
                include_str!("../../../.github/workflows/oracle-reproduce.yml"),
            ),
        ] {
            let path = workflow_path(name);
            let mut failures = Vec::new();
            check_trusted_driver_checkouts(&path, workflow, &mut failures);
            assert!(failures.is_empty(), "{name}: {}", failures.join("\n"));
            for (label, mutant) in trusted_driver_mutants(name, workflow) {
                let mut failures = Vec::new();
                check_trusted_driver_checkouts(&path, &mutant, &mut failures);
                assert!(!failures.is_empty(), "accepted {label} in {name}");
            }
        }
    }

    #[test]
    fn protected_provider_inputs_are_sealed_before_credentials() {
        for (name, workflow) in [
            (
                "custody-scrub.yml",
                include_str!("../../../.github/workflows/custody-scrub.yml"),
            ),
            (
                "promotion-surveillance.yml",
                include_str!("../../../.github/workflows/promotion-surveillance.yml"),
            ),
            (
                "promotion-surveillance-watchdog.yml",
                include_str!("../../../.github/workflows/promotion-surveillance-watchdog.yml"),
            ),
            (
                "promotion-initial-public-finalize.yml",
                include_str!("../../../.github/workflows/promotion-initial-public-finalize.yml"),
            ),
        ] {
            let path = workflow_path(name);
            let mut failures = Vec::new();
            check_precredential_provider_selectors(&path, workflow, true, &mut failures);
            assert!(failures.is_empty(), "{name}: {}", failures.join("\n"));
            for (label, mutant) in provider_selector_mutants(name, workflow) {
                let mut failures = Vec::new();
                check_precredential_provider_selectors(&path, &mutant, true, &mut failures);
                assert!(!failures.is_empty(), "accepted {label} in {name}");
            }
        }
    }

    #[test]
    fn initial_public_sequence_requires_current_selector_update_barriers() {
        for (name, workflow) in [
            (
                "evidence-custody.yml",
                include_str!("../../../.github/workflows/evidence-custody.yml"),
            ),
            (
                "promotion-surveillance.yml",
                include_str!("../../../.github/workflows/promotion-surveillance.yml"),
            ),
            (
                "promotion-initial-public-finalize.yml",
                include_str!("../../../.github/workflows/promotion-initial-public-finalize.yml"),
            ),
        ] {
            let path = workflow_path(name);
            let mut failures = Vec::new();
            check_selector_update_barrier_topology(&path, workflow, &mut failures);
            assert!(failures.is_empty(), "{name}: {}", failures.join("\n"));
            let mutant = match name {
                "evidence-custody.yml" => format!(
                    "{workflow}\n  dispatch-initial-public-state:\n    run: workflow-dispatch-initial-surveillance\n"
                ),
                "promotion-surveillance.yml" => {
                    workflow.replacen("selector_archive_sha256:", "selector_unbound_sha256:", 1)
                }
                _ => workflow.replacen("workflow_dispatch:", "workflow_run:", 1),
            };
            let mut failures = Vec::new();
            check_selector_update_barrier_topology(&path, &mutant, &mut failures);
            assert!(!failures.is_empty(), "accepted barrier mutant in {name}");
            if name == "promotion-surveillance.yml" {
                let mutant = workflow.replacen(
                    "inputs.candidate_sha == github.sha && inputs.selector_source_sha == github.sha",
                    "inputs.candidate_sha == github.sha",
                    1,
                );
                let mut failures = Vec::new();
                check_selector_update_barrier_topology(&path, &mutant, &mut failures);
                assert!(
                    !failures.is_empty(),
                    "accepted surveillance cross-HEAD drift"
                );
            }
            if name == "promotion-initial-public-finalize.yml" {
                let mutant =
                    workflow.replacen(" && inputs.selector_source_sha == github.sha", "", 1);
                let mut failures = Vec::new();
                check_selector_update_barrier_topology(&path, &mutant, &mut failures);
                assert!(!failures.is_empty(), "accepted finalizer cross-HEAD drift");
            }
        }
    }

    #[test]
    fn selector_aggregate_uses_provider_selected_immutable_sources() {
        let workflow =
            include_str!("../../../.github/workflows/custody-provider-selector-seal.yml");
        let mut failures = Vec::new();
        check_selector_seal_workflow(workflow, &mut failures);
        assert!(failures.is_empty(), "{}", failures.join("\n"));
        for (label, mutant) in [
            (
                "selector-omission",
                workflow.replacen(
                    "run: ./target/ci/hell-ci custody-ops workflow-select-provider-selector-updates",
                    "run: true",
                    1,
                ),
            ),
            (
                "primary-name-substitution",
                workflow.replacen(
                    "artifact-ids: ${{ steps.select.outputs.primary-artifact-id }}",
                    "name: custody-provider-selector-update-primary-worm-${{ github.run_id }}-${{ github.run_attempt }}",
                    1,
                ),
            ),
            (
                "secondary-id-substitution",
                workflow.replacen(
                    "artifact-ids: ${{ steps.select.outputs.secondary-artifact-id }}",
                    "artifact-ids: ${{ steps.select.outputs.primary-artifact-id }}",
                    1,
                ),
            ),
            (
                "source-workflow-substitution",
                workflow.replacen(
                    "CUSTODY_SELECTOR_SOURCE_WORKFLOW: ${{ inputs.source_workflow }}",
                    "CUSTODY_SELECTOR_SOURCE_WORKFLOW: .github/workflows/evidence-custody.yml",
                    1,
                ),
            ),
            (
                "provider-token-omission",
                workflow.replacen("          GITHUB_TOKEN: ${{ github.token }}\n", "", 1),
            ),
        ] {
            let mut failures = Vec::new();
            check_selector_seal_workflow(&mutant, &mut failures);
            assert!(!failures.is_empty(), "accepted {label}");
        }
    }

    #[test]
    fn every_regression_provider_replay_binds_the_expected_archive_digest() {
        for (name, workflow) in [
            (
                "assurance-transport-readiness.yml",
                include_str!("../../../.github/workflows/assurance-transport-readiness.yml"),
            ),
            (
                "assurance-transport-signer-a.yml",
                include_str!("../../../.github/workflows/assurance-transport-signer-a.yml"),
            ),
            (
                "assurance-transport-signer-b.yml",
                include_str!("../../../.github/workflows/assurance-transport-signer-b.yml"),
            ),
            (
                "regression-corpus.yml",
                include_str!("../../../.github/workflows/regression-corpus.yml"),
            ),
        ] {
            let lines = workflow.lines().collect::<Vec<_>>();
            let mut failures = Vec::new();
            check_regression_provider_archive_binding(&workflow_path(name), &lines, &mut failures);
            assert!(failures.is_empty(), "{name}: {}", failures.join("\n"));
            let mutant = workflow.replacen(
                "          REGRESSION_PROVIDER_ARCHIVE_SHA256:",
                "          REGRESSION_PROVIDER_UNBOUND_SHA256:",
                1,
            );
            let lines = mutant.lines().collect::<Vec<_>>();
            let mut failures = Vec::new();
            check_regression_provider_archive_binding(&workflow_path(name), &lines, &mut failures);
            assert!(!failures.is_empty(), "accepted archive omission in {name}");
        }
    }

    #[test]
    fn every_external_consumer_requires_the_reviewed_archive_contract() {
        for (name, workflow, marker) in [
            (
                "artifact-authenticity-review.yml",
                include_str!("../../../.github/workflows/artifact-authenticity-review.yml"),
                "      source_provider_archive_sha256:",
            ),
            (
                "artifact-independent-acquisition.yml",
                include_str!("../../../.github/workflows/artifact-independent-acquisition.yml"),
                "      source_provider_archive_sha256:",
            ),
            (
                "evidence-custody.yml",
                include_str!("../../../.github/workflows/evidence-custody.yml"),
                "      provider_archive_sha256:",
            ),
            (
                "claim-applicability-decisions.yml",
                include_str!("../../../.github/workflows/claim-applicability-decisions.yml"),
                "      native_provider_archive_sha256:",
            ),
            (
                "promotion-evidence-review.yml",
                include_str!("../../../.github/workflows/promotion-evidence-review.yml"),
                "      provider_archive_sha256_json:",
            ),
            (
                "promotion-approval.yml",
                include_str!("../../../.github/workflows/promotion-approval.yml"),
                "      proposal_provider_archive_sha256:",
            ),
            (
                "nightly.yml",
                include_str!("../../../.github/workflows/nightly.yml"),
                "      proposal_provider_archive_sha256:",
            ),
            (
                "promotion-proposal.yml",
                include_str!("../../../.github/workflows/promotion-proposal.yml"),
                "      evidence_provider_archive_sha256:",
            ),
            (
                "artifact-authenticity-finalize.yml",
                include_str!("../../../.github/workflows/artifact-authenticity-finalize.yml"),
                "      primary_packet_archive_sha256:",
            ),
            (
                "collection-activation-preparation.yml",
                include_str!("../../../.github/workflows/collection-activation-preparation.yml"),
                "      expected_archive_sha256:",
            ),
            (
                "collection-activation.yml",
                include_str!("../../../.github/workflows/collection-activation.yml"),
                "      proposal_archive_sha256:",
            ),
            (
                "collection-custody-integration.yml",
                include_str!("../../../.github/workflows/collection-custody-integration.yml"),
                "      expected_worm_archive_sha256:",
            ),
        ] {
            let path = workflow_path(name);
            let mut failures = Vec::new();
            check_external_consumer_archive_binding(&path, workflow, &mut failures);
            assert!(failures.is_empty(), "{name}: {}", failures.join("\n"));
            let mutant = workflow.replacen(marker, "      unbound_archive_sha256:", 1);
            let mut failures = Vec::new();
            check_external_consumer_archive_binding(&path, &mutant, &mut failures);
            assert!(!failures.is_empty(), "accepted archive omission in {name}");
        }
        let path = workflow_path("promotion-evidence-review.yml");
        let workflow = include_str!("../../../.github/workflows/promotion-evidence-review.yml");
        let mutant = format!("{workflow}\n      oracle_event:\n        type: string\n");
        let mut failures = Vec::new();
        check_external_consumer_archive_binding(&path, &mutant, &mut failures);
        assert!(
            !failures.is_empty(),
            "accepted split evidence source schema"
        );
    }

    fn provider_selector_mutants(name: &str, workflow: &str) -> Vec<(&'static str, String)> {
        if name == "promotion-initial-public-finalize.yml" {
            return vec![
                (
                    "completion-verifier-omission",
                    workflow.replacen(
                        "custody-ops workflow-prepare-provider-selector",
                        "custody-ops workflow-complete-initial-activation",
                        1,
                    ),
                ),
                (
                    "completion-verifier-after-credentials",
                    workflow.replacen(
                        "      - name: Seal exact completed-publication provider selector before credentials\n        env:\n          ACTIVE_CUSTODY_PROVIDER_SELECTOR: ${{ vars[matrix.default-receipt-variable] }}\n          CUSTODY_PROVIDER_OPERATION: complete-initial-publication\n          CUSTODY_EXPECTED_PROVIDER: ${{ matrix.provider }}\n          CUSTODY_EXPECTED_TRUST_DOMAIN: ${{ matrix.trust-domain }}\n        run: ./target/ci/hell-ci custody-ops workflow-prepare-provider-selector\n",
                        "",
                        1,
                    ),
                ),
                (
                    "completion-source-id-substitution",
                    workflow.replacen(
                        "artifact-ids: ${{ needs.finalize-completed-publication.outputs.completion_artifact_id }}",
                        "artifact-ids: ${{ needs.finalize-completed-publication.outputs.completion_artifact_digest }}",
                        1,
                    ),
                ),
            ];
        }
        vec![
            (
                "selector-omission",
                workflow.replacen(
                    "custody-ops workflow-prepare-provider-selector",
                    "custody-ops workflow-surveillance-retrieve",
                    1,
                ),
            ),
            (
                "selector-operation-omission",
                workflow.replacen(
                    "CUSTODY_PROVIDER_OPERATION:",
                    "CUSTODY_PROVIDER_MODE:",
                    1,
                ),
            ),
            (
                "selector-provider-substitution",
                workflow.replacen(
                    "CUSTODY_EXPECTED_PROVIDER: ${{ matrix.provider }}",
                    "CUSTODY_EXPECTED_PROVIDER: primary-worm",
                    1,
                ),
            ),
            (
                "selector-receipt-substitution",
                workflow.replacen(
                    "ACTIVE_CUSTODY_PROVIDER_SELECTOR: ${{ vars[matrix.default-receipt-variable] }}",
                    "ACTIVE_CUSTODY_PROVIDER_SELECTOR: ${{ vars.ACTIVE_CUSTODY_PRIMARY_UPLOAD_RECEIPT }}",
                    1,
                ),
            ),
            (
                "selector-trust-domain-substitution",
                workflow.replacen(
                    "trust-domain: organization-secondary",
                    "trust-domain: organization-primary",
                    1,
                ),
            ),
            (
                "selector-matrix-receipt-substitution",
                workflow.replacen(
                    "default-receipt-variable: ACTIVE_CUSTODY_SECONDARY_UPLOAD_RECEIPT",
                    "default-receipt-variable: ACTIVE_CUSTODY_PRIMARY_UPLOAD_RECEIPT",
                    1,
                ),
            ),
        ]
    }

    #[test]
    fn campaign_external_handoffs_expose_artifact_archive_and_directory_identities() {
        for (name, workflow) in [
            (
                "nightly.yml",
                include_str!("../../../.github/workflows/nightly.yml"),
            ),
            (
                "promotion-evidence-review.yml",
                include_str!("../../../.github/workflows/promotion-evidence-review.yml"),
            ),
            (
                "evidence-custody.yml",
                include_str!("../../../.github/workflows/evidence-custody.yml"),
            ),
            (
                "mutation.yml",
                include_str!("../../../.github/workflows/mutation.yml"),
            ),
            (
                "artifact-authenticity-finalize.yml",
                include_str!("../../../.github/workflows/artifact-authenticity-finalize.yml"),
            ),
            (
                "oracle-reproduce.yml",
                include_str!("../../../.github/workflows/oracle-reproduce.yml"),
            ),
            (
                "claim-applicability-decisions.yml",
                include_str!("../../../.github/workflows/claim-applicability-decisions.yml"),
            ),
            (
                "artifact-independent-acquisition.yml",
                include_str!("../../../.github/workflows/artifact-independent-acquisition.yml"),
            ),
            (
                "artifact-authenticity-review.yml",
                include_str!("../../../.github/workflows/artifact-authenticity-review.yml"),
            ),
            (
                "promotion-surveillance.yml",
                include_str!("../../../.github/workflows/promotion-surveillance.yml"),
            ),
            (
                "promotion-surveillance-watchdog.yml",
                include_str!("../../../.github/workflows/promotion-surveillance-watchdog.yml"),
            ),
            (
                "promotion-initial-public-finalize.yml",
                include_str!("../../../.github/workflows/promotion-initial-public-finalize.yml"),
            ),
        ] {
            let path = workflow_path(name);
            let mut failures = Vec::new();
            check_campaign_external_handoffs(&path, workflow, &mut failures);
            assert!(failures.is_empty(), "{name}: {}", failures.join("\n"));
            for (label, mutant) in campaign_handoff_mutants(name, workflow) {
                let mut failures = Vec::new();
                check_campaign_external_handoffs(&path, &mutant, &mut failures);
                assert!(!failures.is_empty(), "accepted {label} in {name}");
            }
        }
    }

    fn campaign_handoff_mutants(name: &str, workflow: &str) -> Vec<(&'static str, String)> {
        if let Some(mutants) = special_campaign_handoff_mutants(name, workflow) {
            return mutants;
        }
        let (upload, bind) = match name {
            "promotion-evidence-review.yml" => ("upload-reviewed", "bind-reviewed"),
            "mutation.yml" => ("upload-mutation", "bind-mutation"),
            "artifact-authenticity-finalize.yml" => ("upload-authenticity", "bind-authenticity"),
            "claim-applicability-decisions.yml" => ("upload-decisions", "bind-decisions"),
            "artifact-independent-acquisition.yml" => ("upload-acquisition", "bind-acquisition"),
            "artifact-authenticity-review.yml" => ("upload-packet", "bind-packet"),
            "promotion-surveillance.yml" => ("upload", "bind-execution"),
            "promotion-surveillance-watchdog.yml" => ("upload-transition", "bind-transition"),
            "promotion-initial-public-finalize.yml" => ("upload-completion", "bind-completion"),
            _ => unreachable!("campaign handoff fixture name is exact"),
        };
        vec![
            (
                "artifact-id-archive-substitution",
                workflow.replacen(
                    &format!("steps.{upload}.outputs.artifact-id"),
                    &format!("steps.{upload}.outputs.artifact-digest"),
                    1,
                ),
            ),
            (
                "directory-archive-substitution",
                workflow.replacen(
                    &format!("steps.{bind}.outputs.directory_sha256"),
                    &format!("steps.{upload}.outputs.artifact-digest"),
                    1,
                ),
            ),
            (
                "typed-directory-binder-omission",
                workflow.replacen(
                    &format!("        id: {bind}"),
                    "        id: unbound-directory",
                    1,
                ),
            ),
        ]
    }

    fn special_campaign_handoff_mutants(
        name: &str,
        workflow: &str,
    ) -> Option<Vec<(&'static str, String)>> {
        let replacements = match name {
            "nightly.yml" => [
                (
                    "native-artifact-id-archive-substitution",
                    "native_artifact_id: ${{ steps.upload-native.outputs.artifact-id }}",
                    "native_artifact_id: ${{ steps.upload-native.outputs.artifact-digest }}",
                ),
                (
                    "promotion-record-directory-archive-substitution",
                    "promotion_record_directory_sha256: ${{ steps.bind-final-record.outputs.directory_sha256 }}",
                    "promotion_record_directory_sha256: ${{ steps.final-record.outputs.artifact-digest }}",
                ),
                (
                    "promotion-record-binder-omission",
                    "        id: bind-final-record",
                    "        id: unbound-directory",
                ),
            ],
            "oracle-reproduce.yml" => [
                (
                    "artifact-id-archive-substitution",
                    "macos_artifact_id: ${{ steps.upload-macos.outputs.artifact-id }}",
                    "macos_artifact_id: ${{ steps.upload-macos.outputs.artifact-digest }}",
                ),
                (
                    "directory-archive-substitution",
                    "macos_directory_sha256: ${{ steps.bind-macos.outputs.directory_sha256 }}",
                    "macos_directory_sha256: ${{ steps.upload-macos.outputs.artifact-digest }}",
                ),
                (
                    "typed-directory-binder-omission",
                    "        id: bind-macos",
                    "        id: unbound-directory",
                ),
            ],
            "evidence-custody.yml" => [
                (
                    "reviewed-artifact-id-archive-substitution",
                    "reviewed_artifact_id: ${{ steps.upload-reviewed.outputs.artifact-id }}",
                    "reviewed_artifact_id: ${{ steps.upload-reviewed.outputs.artifact-digest }}",
                ),
                (
                    "primary-scrub-directory-archive-substitution",
                    "primary_directory_sha256: ${{ steps.bind-primary.outputs.directory_sha256 }}",
                    "primary_directory_sha256: ${{ steps.upload-primary.outputs.artifact-digest }}",
                ),
                (
                    "secondary-scrub-binder-omission",
                    "        id: bind-secondary",
                    "        id: unbound-directory",
                ),
            ],
            _ => return None,
        };
        Some(
            replacements
                .map(|(label, source, replacement)| {
                    (label, workflow.replacen(source, replacement, 1))
                })
                .into(),
        )
    }

    fn trusted_driver_mutants(name: &str, workflow: &str) -> Vec<(&'static str, String)> {
        let omitted = workflow.replace("ref: ${{ github.sha }}", "ref: HEAD");
        let mut mutants = vec![
            ("checkout-ref-omission", omitted),
            (
                "checkout-head-substitution",
                workflow.replacen(
                    "--candidate-commit \"$TRUSTED_DRIVER_SHA\"",
                    "--candidate-commit HEAD",
                    1,
                ),
            ),
            (
                "checkout-verification-reordered",
                workflow.replacen(
                    "        run: ./target/ci/hell-ci collection-authority verify-checkout --input . --candidate-commit \"$TRUSTED_DRIVER_SHA\"",
                    "        run: true",
                    1,
                ),
            ),
        ];
        if name == "nightly.yml" {
            mutants.push((
                "candidate-driver-head-split",
                workflow.replacen(" && inputs.candidate_sha == github.sha", "", 1),
            ));
        }
        if name == "promotion-surveillance.yml" {
            mutants.push((
                "active-subject-head-substitution",
                workflow.replacen(
                    "--input ci-work/candidate --candidate-commit \"$ACTIVE_SUBJECT_SHA\"",
                    "--input . --candidate-commit \"$ACTIVE_SUBJECT_SHA\"",
                    1,
                ),
            ));
        }
        mutants
    }

    fn promotion_handoff_mutants(name: &str, workflow: &str) -> Vec<(&'static str, String)> {
        let (upload, bind, checkout) = if name == "promotion-proposal.yml" {
            (
                "upload-proposal",
                "bind-proposal",
                "collection-authority verify-checkout --input . --candidate-commit \"$PROMOTION_CANDIDATE_SHA\"",
            )
        } else {
            (
                "upload-approved",
                "bind-approved",
                "collection-authority verify-checkout --input . --candidate-commit \"$PROMOTION_CANDIDATE_SHA\"",
            )
        };
        vec![
            (
                "artifact-id-archive-substitution",
                workflow.replacen(
                    &format!("steps.{upload}.outputs.artifact-id"),
                    &format!("steps.{upload}.outputs.artifact-digest"),
                    1,
                ),
            ),
            (
                "directory-archive-substitution",
                workflow.replacen(
                    &format!("steps.{bind}.outputs.directory_sha256"),
                    &format!("steps.{upload}.outputs.artifact-digest"),
                    1,
                ),
            ),
            (
                "typed-directory-binding-omission",
                workflow.replacen(
                    "run: ./target/ci/hell-ci regression-import emit-directory-output --input ci-out/native-shards",
                    "run: true",
                    1,
                ),
            ),
            (
                "upload-step-id-omission",
                workflow.replacen(&format!("        id: {upload}\n"), "", 1),
            ),
            (
                "exact-checkout-omission",
                workflow.replacen(checkout, "true", 1),
            ),
        ]
    }

    #[test]
    fn collection_activation_manifest_is_exact_atomic_and_fail_closed() {
        let dormant = include_str!("../../../compat/collection-activation.toml");
        let dormant_provenance =
            include_bytes!("../../../compat/collection-activation-provenance.json");
        let dormant_claims = include_bytes!("../../../compat/collection-activation-claims.json");
        assert!(collection_activation_manifest_is_exact(dormant));
        assert_eq!(
            hell_testkit::verify_collection_activation_state(
                dormant.as_bytes(),
                dormant_provenance,
                dormant_claims,
            ),
            Ok(false)
        );
        let active = dormant
            .replace("map712 = false", "map712 = true")
            .replace("set479 = false", "set479 = true");
        assert!(collection_activation_manifest_is_exact(&active));
        assert!(
            hell_testkit::verify_collection_activation_state(
                active.as_bytes(),
                dormant_provenance,
                dormant_claims,
            )
            .is_err(),
            "a flag-only activation must not reuse dormant provenance"
        );
        assert!(
            hell_testkit::verify_collection_activation_state(
                dormant.as_bytes(),
                b"{\"state\":\"forged\"}\n",
                dormant_claims,
            )
            .is_err(),
            "dormant activation must retain its exact provenance"
        );
        assert!(
            hell_testkit::verify_collection_activation_state(
                dormant.as_bytes(),
                dormant_provenance,
                b"{\"state\":\"forged\"}\n",
            )
            .is_err(),
            "dormant activation must retain exact empty claims"
        );
        for mutant in [
            dormant.replace("map712 = false", "map712 = true"),
            dormant.replace("set479 = false", "set479 = true"),
            dormant.replace("map712", "map711"),
            dormant.replace(
                "Map.adjust|pure-runtime|upstream|linux,macos,windows\", ",
                "",
            ),
            dormant.replace("Map.adjust", "Map.lookup"),
            dormant.replace("fresh_collection_required = true", "fresh_collection_required = false"),
            dormant.replace("fresh_collection_required = true\n", ""),
            dormant.replace(
                "Map.adjust|pure-runtime|upstream|linux,macos,windows\", \"Map.delete",
                "Map.delete|pure-runtime|upstream|linux,macos,windows\", \"Map.adjust",
            ),
            dormant.replace(
                "Set.union|pure-runtime|upstream|linux,macos,windows\"]",
                "Set.union|pure-runtime|upstream|linux,macos,windows\", \"Map.singleton|pure-runtime|upstream|linux,macos,windows\"]",
            ),
            format!("{dormant}promotion_authority = true\n"),
        ] {
            assert!(!collection_activation_manifest_is_exact(&mutant));
        }
    }

    #[test]
    fn collection_activation_preparation_is_provider_bound_and_non_authoritative() {
        let workflow =
            include_str!("../../../.github/workflows/collection-activation-preparation.yml");
        assert!(
            collection_activation_preparation_policy(workflow).is_empty(),
            "{:?}",
            collection_activation_preparation_policy(workflow)
        );
        for (label, mutant) in activation_preparation_provider_mutants(workflow)
            .into_iter()
            .chain(activation_preparation_control_mutants(workflow))
        {
            assert!(
                !collection_activation_preparation_policy(&mutant).is_empty(),
                "accepted collection activation preparation mutant {label}"
            );
        }
    }

    fn activation_preparation_provider_mutants(workflow: &str) -> Vec<(&'static str, String)> {
        vec![
            (
                "provider-run",
                workflow.replacen(
                    "--run-id \"$COLLECTION_ACTIVATION_RUN_ID\"",
                    "--run-id 1",
                    1,
                ),
            ),
            (
                "provider-attempt",
                workflow.replacen(
                    "--run-attempt \"$COLLECTION_ACTIVATION_RUN_ATTEMPT\"",
                    "--run-attempt 1",
                    1,
                ),
            ),
            (
                "artifact-id",
                workflow.replacen(
                    "--artifact-id \"$COLLECTION_ACTIVATION_ARTIFACT_ID\"",
                    "--artifact-id 1",
                    1,
                ),
            ),
            (
                "directory-digest",
                workflow.replacen(
                    "--expected-directory-sha256 \"$COLLECTION_ACTIVATION_DIRECTORY_SHA256\"",
                    "--expected-directory-sha256 \"$COLLECTION_ACTIVATION_ARCHIVE_SHA256\"",
                    1,
                ),
            ),
            (
                "archive-digest",
                workflow.replacen(
                    "--expected-archive-sha256 \"$COLLECTION_ACTIVATION_ARCHIVE_SHA256\"",
                    "--expected-archive-sha256 \"$COLLECTION_ACTIVATION_DIRECTORY_SHA256\"",
                    1,
                ),
            ),
            (
                "base-head",
                workflow.replacen(
                    "--candidate-commit \"$COLLECTION_ACTIVATION_SHA\"",
                    "--candidate-commit HEAD",
                    1,
                ),
            ),
            (
                "verification-omission",
                workflow.replacen(
                    "        run: ./target/ci/hell-ci collection-authority verify-activation-artifact --input ci-in/collection-custody-activation/collection-custody-activation-token.json --report ci-in/collection-custody-activation/collection-custody-admission.json\n",
                    "",
                    1,
                ),
            ),
            (
                "prepare-before-verify",
                workflow
                    .replace(
                        "run: ./target/ci/hell-ci collection-authority verify-activation-artifact --input ci-in/collection-custody-activation/collection-custody-activation-token.json --report ci-in/collection-custody-activation/collection-custody-admission.json",
                        "run: __COLLECTION_ACTIVATION_VERIFY__",
                    )
                    .replace(
                        "run: ./target/ci/hell-ci collection-authority prepare-activation --input ci-in/collection-custody-activation --output ci-out/collection-activation-proposal --run-id \"$COLLECTION_ACTIVATION_RUN_ID\" --run-attempt \"$COLLECTION_ACTIVATION_RUN_ATTEMPT\" --artifact-id \"$COLLECTION_ACTIVATION_ARTIFACT_ID\" --expected-directory-sha256 \"$COLLECTION_ACTIVATION_DIRECTORY_SHA256\" --expected-archive-sha256 \"$COLLECTION_ACTIVATION_ARCHIVE_SHA256\"",
                        "run: ./target/ci/hell-ci collection-authority verify-activation-artifact --input ci-in/collection-custody-activation/collection-custody-activation-token.json --report ci-in/collection-custody-activation/collection-custody-admission.json",
                    )
                    .replace(
                        "run: __COLLECTION_ACTIVATION_VERIFY__",
                        "run: ./target/ci/hell-ci collection-authority prepare-activation --input ci-in/collection-custody-activation --output ci-out/collection-activation-proposal --run-id \"$COLLECTION_ACTIVATION_RUN_ID\" --run-attempt \"$COLLECTION_ACTIVATION_RUN_ATTEMPT\" --artifact-id \"$COLLECTION_ACTIVATION_ARTIFACT_ID\" --expected-directory-sha256 \"$COLLECTION_ACTIVATION_DIRECTORY_SHA256\" --expected-archive-sha256 \"$COLLECTION_ACTIVATION_ARCHIVE_SHA256\"",
                    ),
            ),
        ]
    }

    fn activation_preparation_control_mutants(workflow: &str) -> Vec<(&'static str, String)> {
        vec![
            (
                "download-before-build",
                workflow.replacen(
                    "        run: cargo build --locked --profile ci --package hell-ci --bin hell-ci",
                    "        run: true\n      - name: Late trusted build\n        run: cargo build --locked --profile ci --package hell-ci --bin hell-ci",
                    1,
                ),
            ),
            (
                "trigger",
                workflow.replacen("  workflow_dispatch:", "  push:\n  workflow_dispatch:", 1),
            ),
            (
                "optional-input",
                workflow.replacen("required: true", "required: false", 1),
            ),
            (
                "concurrency",
                workflow.replacen("cancel-in-progress: false", "cancel-in-progress: true", 1),
            ),
            (
                "checkout-ref",
                workflow.replacen("ref: ${{ inputs.activation_sha }}", "ref: main", 1),
            ),
            (
                "direct-interpolation",
                workflow.replacen(
                    "--run-id \"$COLLECTION_ACTIVATION_RUN_ID\"",
                    "--run-id \"${{ inputs.source_run_id }}\"",
                    1,
                ),
            ),
            (
                "authority",
                format!("{workflow}\n# promotionAuthority: true\n"),
            ),
            (
                "credential",
                format!("{workflow}\n# secrets.UNREVIEWED\n"),
            ),
            (
                "automatic-commit",
                format!("{workflow}\n# git commit activation\n"),
            ),
            (
                "partial-target-cache",
                workflow.replacen(
                    "key: v2-${{ runner.os }}-${{ runner.arch }}-collection-activation-preparation-target-",
                    "restore-keys: v2-collection-activation-preparation-target-",
                    1,
                ),
            ),
            (
                "output-id",
                workflow.replacen(
                    "steps.upload-proposal.outputs.artifact-id",
                    "steps.bind-proposal.outputs.artifact-id",
                    1,
                ),
            ),
            (
                "output-directory-digest",
                workflow.replacen(
                    "steps.bind-proposal.outputs.directory_sha256",
                    "steps.upload-proposal.outputs.artifact-digest",
                    1,
                ),
            ),
            (
                "output-path",
                workflow.replacen(
                    "path: ci-out/collection-activation-proposal",
                    "path: ci-out",
                    1,
                ),
            ),
        ]
    }

    #[test]
    fn protected_review_signing_credentials_require_exact_packet_finalization() {
        let workflows = [
            (
                "promotion-approval.yml",
                include_str!("../../../.github/workflows/promotion-approval.yml"),
            ),
            (
                "mutation.yml",
                include_str!("../../../.github/workflows/mutation.yml"),
            ),
            (
                "oracle-reproduce.yml",
                include_str!("../../../.github/workflows/oracle-reproduce.yml"),
            ),
            (
                "artifact-authenticity-finalize.yml",
                include_str!("../../../.github/workflows/artifact-authenticity-finalize.yml"),
            ),
            (
                "promotion-evidence-review.yml",
                include_str!("../../../.github/workflows/promotion-evidence-review.yml"),
            ),
            (
                "evidence-custody.yml",
                include_str!("../../../.github/workflows/evidence-custody.yml"),
            ),
        ];
        for (path, workflow) in workflows {
            let mutant = workflow.replacen(
                "run: ./target/ci/hell-ci review-packet ",
                "run: ./target/ci/hell-ci review-sign ",
                1,
            );
            let mut failures = Vec::new();
            check_workflow(&workflow_path(path), &mutant, &mut failures);
            assert!(
                failures.iter().any(|failure| failure.contains(
                    "must download and authorize its exact subject, finalize its review packet"
                )),
                "accepted credentials-before-finalization mutant in {path}: {}",
                failures.join("\n")
            );
        }
    }

    #[test]
    fn surveillance_transition_packets_precede_state_signing_credentials() {
        for (name, job, workflow) in [
            (
                "promotion-surveillance.yml",
                "verify-and-transition",
                include_str!("../../../.github/workflows/promotion-surveillance.yml"),
            ),
            (
                "promotion-surveillance-watchdog.yml",
                "deadline",
                include_str!("../../../.github/workflows/promotion-surveillance-watchdog.yml"),
            ),
        ] {
            let lines = workflow_job_lines(workflow, job).unwrap();
            let mut failures = Vec::new();
            check_state_transition_signing_order(
                &workflow_path(name),
                job,
                &lines,
                0,
                &mut failures,
            );
            assert!(failures.is_empty(), "{name}: {}", failures.join("\n"));
            let body = lines.join("\n");
            let credential = body.find("uses: webfactory/ssh-agent@").unwrap();
            let packet = body
                .find("run: ./target/ci/hell-ci custody-ops workflow-transition-packet")
                .unwrap();
            let mut mutant = body.clone();
            let credential_line = body[credential..].lines().next().unwrap();
            let packet_line = body[packet..].lines().next().unwrap();
            mutant = mutant
                .replacen(credential_line, "uses: reordered-credential", 1)
                .replacen(packet_line, credential_line, 1)
                .replacen("uses: reordered-credential", packet_line, 1);
            let mutant_lines = mutant.lines().collect::<Vec<_>>();
            let mut failures = Vec::new();
            check_state_transition_signing_order(
                &workflow_path(name),
                job,
                &mutant_lines,
                0,
                &mut failures,
            );
            assert!(
                !failures.is_empty(),
                "accepted reordered credentials in {name}"
            );
        }
    }

    #[test]
    fn custody_provider_signing_keys_load_only_after_typed_receipt_packets() {
        for (path, workflow, packet) in [
            (
                "evidence-custody.yml",
                include_str!("../../../.github/workflows/evidence-custody.yml"),
                "run: ./target/ci/hell-ci custody-ops workflow-upload-packet",
            ),
            (
                "custody-scrub.yml",
                include_str!("../../../.github/workflows/custody-scrub.yml"),
                "run: ./target/ci/hell-ci custody-ops workflow-maintenance-packet",
            ),
        ] {
            let mutant = workflow.replacen(packet, "run: true", 1);
            let mut failures = Vec::new();
            check_workflow(&workflow_path(path), &mutant, &mut failures);
            assert!(
                failures.iter().any(|failure| failure.contains(
                    "must finalize its typed receipt packet before loading signing credentials"
                )),
                "accepted provider credential ordering mutant in {path}: {}",
                failures.join("\n")
            );
        }
    }

    #[test]
    fn automatic_regression_batch_is_one_complete_set_without_a_fake_concurrency_queue() {
        let subject = include_str!("../../../.github/workflows/regression-subject.yml");
        let corpus = include_str!("../../../.github/workflows/regression-corpus.yml");
        assert!(!subject.contains("queue:"));
        assert!(!corpus.contains("queue:"));
        assert_eq!(subject.matches("  integrate-scheduled-batch:").count(), 1);
        assert_eq!(
            subject
                .matches("regression-import integrate-batch-current-main --input")
                .count(),
            1
        );
        assert!(corpus.contains(
            "group: reviewed-regression-corpus-${{ inputs.action == 'automatic' && format('{0}-{1}', inputs.issue, inputs.generated_case_id) || github.ref }}"
        ));
        assert!(!corpus.contains("inputs.action == 'automatic' || inputs.action == 'integrate'"));

        let substitutions = [
            subject.replace(
                "    needs: reconcile-scheduled-batch",
                "    needs: dispatch-scheduled-0",
            ),
            subject.replace("integrate-batch-current-main", "integrate-batch"),
            subject.replace(
                "  integrate-scheduled-batch:",
                "  integrate-scheduled-batch:\n    concurrency:\n      group: automatic-regression-batch-integration-main\n      cancel-in-progress: false\n      queue: max",
            ),
        ];
        for changed in substitutions {
            let mut failures = Vec::new();
            check_workflow(
                &workflow_path("regression-subject.yml"),
                &changed,
                &mut failures,
            );
            assert!(!failures.is_empty());
        }
    }

    #[test]
    fn transport_probe_workflows_are_nonpublishing_and_production_nonselectable() {
        let readiness =
            include_str!("../../../.github/workflows/assurance-transport-readiness.yml");
        let signer_a = include_str!("../../../.github/workflows/assurance-transport-signer-a.yml");
        let signer_b = include_str!("../../../.github/workflows/assurance-transport-signer-b.yml");
        let probe = [readiness, signer_a, signer_b];
        for workflow in probe {
            assert!(!workflow.contains("contents: write"));
            assert!(!workflow.contains("git push"));
            assert!(!workflow.contains("secrets: inherit"));
            assert!(!workflow.contains("promotion-"));
            assert!(!workflow.contains("regression-review-"));
        }
        let identity_a = "HELL_SIGSTORE_IDENTITY: https://github.com/Portfoligno/hell-rs/.github/workflows/assurance-transport-signer-a.yml@refs/heads/main";
        let identity_b = "HELL_SIGSTORE_IDENTITY: https://github.com/Portfoligno/hell-rs/.github/workflows/assurance-transport-signer-b.yml@refs/heads/main";
        assert_eq!(signer_a.matches(identity_a).count(), 1);
        assert_eq!(signer_b.matches(identity_b).count(), 1);
        assert!(signer_a.contains("HELL_REVIEWER_ID: assurance-transport-probe-a:probe-a"));
        assert!(signer_b.contains("HELL_REVIEWER_ID: assurance-transport-probe-b:probe-b"));
        assert!(!readiness.contains(identity_a));
        assert!(!readiness.contains(identity_b));
        let trust_roots = include_str!("../../../compat/transport-probe/a/trust-roots.toml");
        assert!(trust_roots.contains(
            "transport_probe_a_workflow = \".github/workflows/assurance-transport-signer-a.yml\""
        ));
        assert!(trust_roots.contains(
            "transport_probe_b_workflow = \".github/workflows/assurance-transport-signer-b.yml\""
        ));
        let caller_ref_substitution = signer_a.replace(
            identity_a,
            "HELL_SIGSTORE_IDENTITY: https://github.com/Portfoligno/hell-rs/.github/workflows/assurance-transport-readiness.yml@refs/heads/main",
        );
        let mut failures = Vec::new();
        check_workflow(
            &workflow_path("assurance-transport-signer-a.yml"),
            &caller_ref_substitution,
            &mut failures,
        );
        assert!(
            failures
                .iter()
                .any(|failure| failure.contains("called workflow identity"))
        );
        for production in [
            include_str!("../../../.github/workflows/nightly.yml"),
            include_str!("../../../.github/workflows/promotion-evidence-review.yml"),
            include_str!("../../../.github/workflows/regression-corpus.yml"),
            include_str!("../../../.github/workflows/regression-subject.yml"),
        ] {
            assert!(!production.contains("assurance-transport-readiness-"));
        }
    }

    #[test]
    fn every_differential_workflow_builds_the_exact_sibling_process_helper() {
        let helper =
            "run: cargo build --locked --profile ci --package hell-testkit --bin hell-test-helper";
        let nightly = include_str!("../../../.github/workflows/nightly.yml");
        let collection = include_str!("../../../.github/workflows/collection-authority.yml");
        let oracle = include_str!("../../../.github/workflows/oracle-reproduce.yml");
        let surveillance = include_str!("../../../.github/workflows/promotion-surveillance.yml");
        assert_eq!(nightly.matches(helper).count(), 4);
        assert_eq!(collection.matches(helper).count(), 3);
        assert_eq!(oracle.matches(helper).count(), 1);
        assert_eq!(surveillance.matches(helper).count(), 2);
        assert!(nightly.find(helper).unwrap() < nightly.find("hell-ci nightly --oracle").unwrap());
        assert!(oracle.find(helper).unwrap() < oracle.find("native-oracle-shard").unwrap());
        assert!(
            surveillance.find(helper).unwrap()
                < surveillance
                    .find("hell-ci nightly-surveillance-subject --oracle")
                    .unwrap()
        );
    }

    #[test]
    fn protected_review_bytes_arrive_only_after_the_verifier_is_built() {
        for (workflow, build, download, verify) in [
            (
                include_str!("../../../.github/workflows/artifact-authenticity-review.yml"),
                "      - name: Build assurance driver",
                "      - name: Download producing-run evidence after building the verifier",
                "      - name: Record primary acquisition receipt",
            ),
            (
                include_str!("../../../.github/workflows/oracle-reproduce.yml"),
                "      - name: Build assurance driver before receiving reviewed bytes",
                "      - name: Download exact platform review subject",
                "      - name: Retain exact protected macOS platform reviewer authorization",
            ),
            (
                include_str!("../../../.github/workflows/evidence-custody.yml"),
                "      - name: Build assurance driver before receiving reviewed bytes",
                "      - name: Download exact custody review subject",
                "      - name: Retain exact protected custody reviewer authorization",
            ),
        ] {
            let build = workflow.find(build).expect("workflow lacks verifier build");
            let download = workflow
                .find(download)
                .expect("workflow lacks exact download");
            let verify = workflow
                .find(verify)
                .expect("workflow lacks exact verification");
            assert!(build < download && download < verify);
        }
        let finalize =
            include_str!("../../../.github/workflows/artifact-authenticity-finalize.yml");
        let mut cursor = 0;
        for marker in [
            "      - name: Build assurance driver",
            "      - name: Download primary acquisition packet after building the verifier",
            "      - name: Verify and assemble exact acquisition sources",
            "      - name: Build trusted assurance driver before loading review credentials",
            "      - name: Download exact pre-review subject after building the verifier",
            "      - name: Retain stable protected reviewer authorization",
        ] {
            let relative = finalize[cursor..]
                .find(marker)
                .unwrap_or_else(|| panic!("finalize workflow lacks ordered marker {marker}"));
            cursor = cursor.saturating_add(relative).saturating_add(marker.len());
        }
    }

    #[test]
    fn offline_packet_requires_production_source_verifiers_in_order() {
        let workflow = include_str!("../../../.github/workflows/evidence-custody.yml");
        let omitted = workflow.replace(
            "        run: ./target/ci/hell-ci oracle-provenance verify --input ci-out/evidence/provenance/windows-amd64/oracle-provenance.json --policy compat/reviews.allowed_signers\n",
            "",
        );
        let mut failures = Vec::new();
        check_workflow(
            &workflow_path("evidence-custody.yml"),
            &omitted,
            &mut failures,
        );
        assert!(
            failures
                .iter()
                .any(|failure| failure.contains("omits required source verifier"))
        );

        let misordered = workflow.replace(
            "      - name: Reverify finalized mutation evidence for the offline packet\n        run: ./target/ci/hell-ci mutation verify --input ci-out/evidence/coverage/mutation-score.json --policy compat/reviews.allowed_signers\n      - name: Reverify macOS source-build evidence for the offline packet\n        run: ./target/ci/hell-ci oracle-provenance verify --input ci-out/evidence/provenance/macos-arm64/oracle-provenance.json --policy compat/reviews.allowed_signers\n",
            "      - name: Reverify macOS source-build evidence for the offline packet\n        run: ./target/ci/hell-ci oracle-provenance verify --input ci-out/evidence/provenance/macos-arm64/oracle-provenance.json --policy compat/reviews.allowed_signers\n      - name: Reverify finalized mutation evidence for the offline packet\n        run: ./target/ci/hell-ci mutation verify --input ci-out/evidence/coverage/mutation-score.json --policy compat/reviews.allowed_signers\n",
        );
        let mut failures = Vec::new();
        check_workflow(
            &workflow_path("evidence-custody.yml"),
            &misordered,
            &mut failures,
        );
        assert!(
            failures
                .iter()
                .any(|failure| failure.contains("misordered"))
        );
    }

    #[test]
    fn native_dependency_gate_is_portable_pinned_and_ordered() {
        let job = "jobs:\n  native-oracle-macos:\n    runs-on: macos-15\n    steps:\n      - run: cargo install cargo-deny --locked --version 0.20.2\n      - run: cargo deny --all-features check all\n  merge:\n    runs-on: ubuntu-24.04\n";
        let mut failures = Vec::new();
        check_native_dependency_job(
            job,
            "native-oracle-macos",
            "runs-on: macos-15",
            &mut failures,
        );
        assert!(failures.is_empty(), "{}", failures.join("\n"));

        for invalid in [
            "jobs:\n  native-oracle-macos:\n    runs-on: macos-15\n    steps:\n      - uses: EmbarkStudios/cargo-deny-action@b66acf5e9fe20f8aba065be86778a8a4c846f902\n      - run: cargo deny --all-features check all\n",
            "jobs:\n  native-oracle-macos:\n    runs-on: macos-15\n    steps:\n      - run: cargo deny --all-features check all\n      - run: cargo install cargo-deny --locked --version 0.20.2\n",
            "jobs:\n  native-oracle-macos:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: cargo install cargo-deny --locked --version 0.20.2\n      - run: cargo deny --all-features check all\n",
        ] {
            let mut failures = Vec::new();
            check_native_dependency_job(
                invalid,
                "native-oracle-macos",
                "runs-on: macos-15",
                &mut failures,
            );
            assert!(
                !failures.is_empty(),
                "accepted invalid native dependency job"
            );
        }
    }

    fn semantic_fuzz_policy_failures(label: &str, nightly: &str, manifest: &str) -> Vec<String> {
        let root = std::env::temp_dir().join(format!(
            "hell-semantic-fuzz-policy-{}-{label}",
            std::process::id()
        ));
        let workflows = root.join(".github/workflows");
        let fuzz = root.join("crates/hell-ci/fuzz");
        fs::create_dir_all(&workflows).unwrap();
        fs::create_dir_all(&fuzz).unwrap();
        fs::write(workflows.join("nightly.yml"), nightly).unwrap();
        fs::write(fuzz.join("Cargo.toml"), manifest).unwrap();
        for target in SEMANTIC_FUZZ_TARGETS {
            fs::create_dir_all(fuzz.join("corpus").join(target)).unwrap();
        }
        if label == "extra-corpus" {
            fs::create_dir_all(fuzz.join("corpus/unreviewed_extra")).unwrap();
        }
        let mut failures = Vec::new();
        check_semantic_fuzz_campaign(&root, &mut failures);
        fs::remove_dir_all(root).unwrap();
        failures
    }

    #[test]
    fn semantic_fuzz_campaign_is_pinned_and_coverage_instrumented() {
        let nightly = include_str!("../../../.github/workflows/nightly.yml");
        let manifest = include_str!("../fuzz/Cargo.toml");
        assert!(semantic_fuzz_policy_failures("valid", nightly, manifest).is_empty());
        for (label, changed_nightly, changed_manifest) in [
            (
                "stable-cargo-run",
                nightly.replace(
                    "cargo +nightly-2026-07-31 fuzz run",
                    "cargo run --locked --manifest-path crates/hell-ci/fuzz/Cargo.toml --bin",
                ),
                manifest.to_owned(),
            ),
            (
                "unpinned-driver",
                nightly.replace("cargo-fuzz --version 0.13.2 --locked", "cargo-fuzz"),
                manifest.to_owned(),
            ),
            (
                "different-toolchain",
                nightly.replace("nightly-2026-07-31", "nightly"),
                manifest.to_owned(),
            ),
            (
                "manifest-version",
                nightly.to_owned(),
                manifest.replace(
                    "cargo-fuzz-version = \"0.13.2\"",
                    "cargo-fuzz-version = \"0.13.1\"",
                ),
            ),
            (
                "non-durable-corpus",
                nightly.replace(
                    "      - name: Retain evolving semantic fuzz corpora\n        if: ${{ always() }}",
                    "      - name: Retain evolving semantic fuzz corpora",
                ),
                manifest.to_owned(),
            ),
            (
                "writable-committed-corpus",
                nightly.replace(
                    "claim_toml ci-out/fuzz-corpora/claim_toml",
                    "claim_toml crates/hell-ci/fuzz/corpus/claim_toml",
                ),
                manifest.to_owned(),
            ),
            (
                "clean-check-success-only",
                nightly.replace(
                    "      - name: Verify fuzzing left committed seed corpora unchanged\n        if: ${{ always() }}",
                    "      - name: Verify fuzzing left committed seed corpora unchanged",
                ),
                manifest.to_owned(),
            ),
            (
                "extra-command",
                format!(
                    "{nightly}\n      - run: cargo +nightly-2026-07-31 fuzz run --fuzz-dir crates/hell-ci/fuzz claim_toml ci-out/fuzz-corpora/claim_toml -- -runs=64 -timeout=10 -artifact_prefix=ci-out/fuzz-artifacts/claim_toml/\n"
                ),
                manifest.to_owned(),
            ),
            (
                "extra-bin",
                nightly.to_owned(),
                format!(
                    "{manifest}\n[[bin]]\nname = \"unreviewed_extra\"\npath = \"fuzz_targets/claim_toml.rs\"\ntest = false\ndoc = false\nbench = false\n"
                ),
            ),
            ("extra-corpus", nightly.to_owned(), manifest.to_owned()),
        ] {
            assert!(
                !semantic_fuzz_policy_failures(label, &changed_nightly, &changed_manifest)
                    .is_empty(),
                "accepted invalid semantic fuzz campaign {label}"
            );
        }
    }

    #[test]
    fn cache_save_requires_always() {
        let text = "      - name: Save\n        if: success()\n        uses: actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9\n        with:\n          key: one\n";
        assert!(!workflow(text).is_empty());
    }

    #[test]
    fn cache_restore_and_save_keys_must_match() {
        let text = "      - uses: actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9\n        with:\n          key: restore\n      - name: Save\n        if: always()\n        uses: actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9\n        with:\n          key: save\n";
        assert!(!workflow(text).is_empty());
    }

    #[test]
    fn target_cache_key_binds_all_compilation_inputs_and_exact_workflow() {
        let complete = "      - uses: actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9\n        with:\n          path: target/ci\n          key: target-${{ hashFiles('**/build.rs', '.cargo/**', 'crates/**/*.rs', 'compat/**', 'workflow.yml') }}\n";
        assert!(workflow(complete).is_empty());

        for omitted in [
            "**/build.rs",
            ".cargo/**",
            "crates/**/*.rs",
            "compat/**",
            "workflow.yml",
        ] {
            let invalid = complete.replace(&format!("'{omitted}'"), "''");
            assert!(
                !workflow(&invalid).is_empty(),
                "accepted target cache without {omitted}"
            );
        }
    }

    #[test]
    fn target_outputs_cannot_share_dependency_or_compiler_cache_scope() {
        let text = "      - uses: actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9\n        with:\n          path: |\n            ~/.cargo/registry/cache\n            ~/.stack\n            target/ci\n          key: target-${{ hashFiles('**/build.rs', '.cargo/**', 'crates/**/*.rs', 'compat/**', 'workflow.yml') }}\n";
        let failures = workflow(text);
        assert!(
            failures
                .iter()
                .any(|failure| failure.contains("share a cache"))
        );
    }

    #[test]
    fn target_cache_rejects_partial_restore_keys() {
        let text = "      - uses: actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9\n        with:\n          path: target\n          key: target-${{ hashFiles('**/build.rs', '.cargo/**', 'crates/**/*.rs', 'compat/**', 'workflow.yml') }}\n          restore-keys: target-\n";
        let failures = workflow(text);
        assert!(
            failures
                .iter()
                .any(|failure| failure.contains("partial restore key"))
        );
    }

    #[test]
    fn stack_work_cache_is_separate_and_binds_oracle_and_rust_inputs() {
        let complete = "      - uses: actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9\n        with:\n          path: target/oracle-source/.stack-work\n          key: stack-${{ hashFiles('**/build.rs', '.cargo/**', 'crates/**/*.rs', 'compat/**', 'stack.yaml', 'stack.yaml.lock', 'package.yaml', '.cabal', 'src/**', 'workflow.yml') }}\n";
        assert!(workflow(complete).is_empty());

        let mixed = complete.replace(
            "path: target/oracle-source/.stack-work",
            "path: |\n            ~/.stack\n            target/oracle-source/.stack-work",
        );
        assert!(
            workflow(&mixed)
                .iter()
                .any(|failure| failure.contains("share a cache"))
        );
    }

    #[test]
    fn path_normalization_confines_fixture_paths() {
        assert_eq!(
            normalized_relative_path("examples/01.hell").unwrap(),
            Path::new("examples").join("01.hell")
        );
        for value in [
            "",
            "../escape",
            "examples/../escape",
            "/absolute",
            "examples/",
            "examples//01.hell",
            "examples/./01.hell",
            "examples\\01.hell",
            "\\\\server\\share\\01.hell",
            "C:examples/01.hell",
            "C:/examples/01.hell",
        ] {
            assert!(
                normalized_relative_path(value).is_err(),
                "accepted {value:?}"
            );
        }
    }

    #[test]
    fn lexical_scan_ignores_prose_and_strings() {
        assert!(
            rust_identifiers("// Regex\nlet value = \"Regex\";")
                .iter()
                .all(|value| value != "Regex")
        );
        assert!(
            rust_identifiers("let Regex = value;")
                .iter()
                .any(|value| value == "Regex")
        );
        let imported = rust_identifiers("use regex::Regex as R;");
        assert!(imported.iter().any(|value| value == "regex"));
        assert_eq!(
            dependency_package("matcher = { package = \"regex\", version = \"1\" }"),
            Some("regex")
        );
        assert_eq!(dependency_package("# package = \"regex\""), None);
        assert_eq!(
            dependency_package("description = \"package = regex\""),
            None
        );
        let multiline = rust_identifiers("use\n regex as matcher;");
        assert!(multiline.windows(2).any(|pair| {
            matches!(pair, [first, second] if first == "use" && second == "regex")
        }));
    }

    #[test]
    fn scanner_handles_its_own_char_literals() {
        let identifiers = rust_identifiers(include_str!("policy.rs"));
        assert!(!identifiers.iter().any(|identifier| {
            matches!(identifier.as_str(), "Regex" | "RegexSet" | "RegexBuilder")
        }));
    }

    #[test]
    fn shell_suffixes_are_rejected() {
        let root = std::env::temp_dir().join(format!("hell-ci-policy-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        for name in ["bad.sh", "bad.bash"] {
            fs::write(root.join(name), b"#!/bin/sh\n").unwrap();
            let mut failures = Vec::new();
            check_tracked_file(&root, Path::new(name), Some("100755"), &mut failures);
            assert!(
                failures
                    .iter()
                    .any(|failure| failure.contains("shell script"))
            );
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn missing_lf_is_rejected() {
        let root = std::env::temp_dir().join(format!("hell-ci-lf-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("bad.txt"), b"missing newline").unwrap();
        let mut failures = Vec::new();
        check_tracked_file(&root, Path::new("bad.txt"), Some("100644"), &mut failures);
        assert!(
            failures
                .iter()
                .any(|failure| failure.contains("end with LF"))
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn executable_without_shebang_is_rejected() {
        let root = std::env::temp_dir().join(format!("hell-ci-exec-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("tool"), b"not a script\n").unwrap();
        let mut failures = Vec::new();
        check_tracked_file(&root, Path::new("tool"), Some("100755"), &mut failures);
        assert!(failures.iter().any(|failure| failure.contains("shebang")));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pinned_upstream_examples_preserve_reviewed_trailing_spaces() {
        let root = std::env::temp_dir().join(format!("hell-ci-pinned-{}", std::process::id()));
        let relative = Path::new("fixtures")
            .join("upstream-2026-05-29")
            .join("examples")
            .join("example.hell");
        fs::create_dir_all(root.join(&relative).parent().unwrap()).unwrap();
        fs::write(root.join(&relative), b"main = IO.pure () \n").unwrap();
        let mut failures = Vec::new();
        check_tracked_file(&root, &relative, Some("100644"), &mut failures);
        assert!(failures.is_empty());
        fs::remove_dir_all(root).unwrap();
    }
}
