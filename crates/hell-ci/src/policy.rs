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
    check_expected_mismatch_manifest(root, &mut failures);
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("\n"))
    }
}

const COLLECTION_ACQUISITION_COMMAND: &str = concat!(
    "run: python3 tools/collection_authority_acquire.py --repository \"$GITHUB_REPOSITORY\" ",
    "--run-id \"$GITHUB_RUN_ID\" --run-attempt \"$GITHUB_RUN_ATTEMPT\" ",
    "--provider-head \"$GITHUB_SHA\" --candidate-commit \"$HELL_SOURCE_COMMIT\" ",
    "--workflow-path .github/workflows/collection-authority.yml ",
    "--output ci-out/collection-provider ",
    "--artifact \"linux-amd64:collection-authority-linux-amd64-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT:$COLLECTION_LINUX_ARTIFACT_ID\" ",
    "--artifact \"macos-arm64:collection-authority-macos-arm64-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT:$COLLECTION_MACOS_ARTIFACT_ID\" ",
    "--artifact \"windows-amd64:collection-authority-windows-amd64-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT:$COLLECTION_WINDOWS_ARTIFACT_ID\"",
);

const COLLECTION_VERIFY_COMMAND: &str = "run: ./target/ci/hell-ci collection-authority verify --input ci-out/native-shards --provider ci-out/collection-provider --report ci-out/native-shards/collection-authority.json";

fn check_collection_authority_producer(root: &Path, failures: &mut Vec<String>) {
    let workflow_path = root.join(".github/workflows/collection-authority.yml");
    let nightly_path = root.join(".github/workflows/nightly.yml");
    let tool_path = root.join("tools/collection_authority_acquire.py");
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
    let tool = match fs::read_to_string(&tool_path) {
        Ok(value) => value,
        Err(error) => {
            failures.push(format!("cannot read {}: {error}", tool_path.display()));
            return;
        }
    };
    check_collection_authority_producer_text(&workflow, &tool, failures);
}

fn check_collection_authority_producer_text(
    workflow: &str,
    tool: &str,
    failures: &mut Vec<String>,
) {
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
    if !workflow.starts_with(DISPATCH_PREFIX)
        || [
            "  push:",
            "  schedule:",
            "  workflow_call:",
            "  pull_request:",
        ]
        .iter()
        .any(|trigger| workflow.contains(trigger))
        || workflow.matches("  workflow_dispatch:").count() != 1
        || workflow.matches(CONCURRENCY).count() != 1
        || workflow.contains("  cancel-in-progress: true")
        || workflow
            .matches("HELL_SOURCE_COMMIT: ${{ inputs.candidate_sha }}")
            .count()
            != 1
    {
        failures.push(
            "collection authority campaign is not isolated dispatch-only non-cancelling work"
                .to_owned(),
        );
    }
    check_collection_linux_acquisition_jobs(workflow, failures);
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
                "run: git merge-base --is-ancestor \"$env:GITHUB_SHA\" HEAD",
                "run: git -C ci-work/candidate merge-base --is-ancestor \"$env:HELL_SOURCE_COMMIT\" HEAD",
            )
        } else {
            (
                "run: git merge-base --is-ancestor \"$GITHUB_SHA\" HEAD",
                "run: git -C ci-work/candidate merge-base --is-ancestor \"$HELL_SOURCE_COMMIT\" HEAD",
            )
        };
        let ordered = [
            provider_guard,
            candidate_guard,
            "run: cargo build --locked --profile ci --package hell-ci --bin hell-ci",
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
        check_collection_authority_job_identity(job, &body, failures);
    }

    check_collection_authority_platform_builds(workflow, failures);

    let Some(lines) = workflow_job_lines(workflow, "merge-collection-authority") else {
        failures.push("collection authority workflow lacks protected merge job".to_owned());
        return;
    };
    let body = lines.join("\n");
    let ordered = [
        COLLECTION_ACQUISITION_COMMAND,
        "run: cargo build --locked --profile ci --package hell-ci --bin hell-ci",
        COLLECTION_VERIFY_COMMAND,
        "uses: actions/attest@a1948c3f048ba23858d222213b7c278aabede763 # v4.1.1",
        "subject-path: ci-out/native-shards/collection-authority.json",
        "name: collection-authority-merged-${{ github.run_id }}-${{ github.run_attempt }}",
    ];
    if !markers_are_ordered(&body, &ordered)
        || body.matches(COLLECTION_ACQUISITION_COMMAND).count() != 1
        || body.matches(COLLECTION_VERIFY_COMMAND).count() != 1
        || body.matches("actions: read").count() != 1
        || body.matches("timeout-minutes: 45").count() != 1
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
        || body.matches("subject-path: ci-out/native-shards/collection-authority.json").count() != 1
        || body.matches("ci-out/native-shards").count() < 2
        || body.matches("ci-out/collection-provider").count() < 2
        || body.contains("actions/download-artifact@")
    {
        failures.push(
            "collection authority merge is not one API-selected, offline-verified three-platform campaign"
                .to_owned(),
        );
    }

    check_collection_authority_tool(tool, failures);
}

fn check_collection_linux_acquisition_jobs(workflow: &str, failures: &mut Vec<String>) {
    let Some(subject) = workflow_job_lines(workflow, "linux-acquisition-subject") else {
        failures.push("collection campaign lacks Linux acquisition subject job".to_owned());
        return;
    };
    let subject = subject.join("\n");
    let subject_order = [
        "ref: ${{ github.sha }}",
        "run: cargo build --locked --profile ci --package hell-ci --bin hell-ci",
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
    {
        failures.push("collection Linux acquisition subject trust role differs".to_owned());
    }

    let Some(signer) = workflow_job_lines(workflow, "sign-linux-acquisition") else {
        failures.push("collection campaign lacks Linux acquisition signer job".to_owned());
        return;
    };
    let signer = signer.join("\n");
    let signer_order = [
        "ref: ${{ github.sha }}",
        "run: cargo build --locked --profile ci --package hell-ci --bin hell-ci",
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

fn check_collection_authority_tool(tool: &str, failures: &mut Vec<String>) {
    for required in [
        "PLATFORMS = (\"linux-amd64\", \"macos-arm64\", \"windows-amd64\")",
        "\"linux-amd64\": \"Collection authority / Linux amd64\"",
        "\"macos-arm64\": \"Collection authority / macOS arm64\"",
        "\"windows-amd64\": \"Collection authority / Windows amd64\"",
        "PER_PAGE = 100",
        "MAX_PAGES = 100",
        "artifact pagination total changed during acquisition",
        "artifact pagination IDs are not unique and strictly descending",
        "job pagination total changed during acquisition",
        "producer job {expected_name} did not complete successfully",
        "provider run is not active or complete",
        "require_string(run.get(\"event\"), \"run event\") != \"workflow_dispatch\"",
        "require_string(run.get(\"head_branch\"), \"run head branch\") != \"main\"",
        "provider head is not a lowercase full SHA-1",
        "arguments.workflow_path != \".github/workflows/collection-authority.yml\"",
        "workflow_response.body.startswith(b\"name: Collection Authority\\n\")",
        "\"providerHeadCommit\": arguments.provider_head",
        "selected artifact IDs are not unique",
        "artifact {spec.name} identity or lifetime is invalid",
        "artifact ZIP contains a duplicate path",
        "artifact ZIP file {info.filename!r} has invalid mode",
        "artifact ZIP expands beyond the reviewed byte bound",
        "provider-archive.zip",
        "provider-selected-artifact.json",
        "provider-selected-run.json",
        "provider-workflow.yml",
        "selection.json",
        "case_count != 1191",
        "collection-evidence\" / \"provider-subject.json",
    ] {
        if !tool.contains(required) {
            failures.push(format!(
                "collection authority acquisition tool lacks exact fail-closed invariant {required}"
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
    const REVIEWED: [(&str, &str); 6] = [
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
    }
}

fn check_workflow(path: &Path, text: &str, failures: &mut Vec<String>) {
    let mut restore_keys = BTreeSet::new();
    let mut save_keys = BTreeSet::new();
    let lines = text.lines().collect::<Vec<_>>();
    check_duplicate_yaml_mapping_keys(path, &lines, failures);
    check_workflow_dispatch_input_limit(path, &lines, failures);
    check_protected_job_trust_isolation(path, &lines, failures);
    check_transport_probe_sigstore_identity(path, text, failures);
    check_offline_packet_verifier_order(path, &lines, failures);
    match path.file_name().and_then(|value| value.to_str()) {
        Some("regression-subject.yml") => {
            check_automatic_regression_batch_transaction(text, failures);
        }
        Some("regression-corpus.yml") => {
            check_automatic_regression_child_isolation(text, failures);
        }
        _ => {}
    }
    for (index, original) in lines.iter().enumerate() {
        let line = strip_yaml_comment(original).trim();
        let entry = line.strip_prefix("- ").unwrap_or(line);
        if line.is_empty() {
            continue;
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
        if yaml_key(entry, "env").is_some() && !reviewed_workflow_env(path, &lines, index, original)
        {
            failures.push(format!("workflow env key is forbidden at {location}"));
        }
        if yaml_key(entry, "pull_request").is_some()
            || yaml_key(entry, "pull_request_target").is_some()
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
                && following_value(&lines, index, "persist-credentials") != Some("false")
            {
                failures.push(format!("checkout persists credentials at {location}"));
            }
            if uses.contains("actions/cache/restore@")
                && let Some(key) = following_value(&lines, index, "key")
            {
                restore_keys.insert(key.to_owned());
            }
            if uses.contains("actions/cache/restore@") || uses.contains("actions/cache/save@") {
                check_cache_scope(path, &lines, index, &location, failures);
            }
            if uses.contains("actions/cache/save@") {
                let condition = preceding_value(&lines, index, "if");
                if !condition.is_some_and(|value| value.contains("always()")) {
                    failures.push(format!("cache save lacks always() at {location}"));
                }
                if let Some(key) = following_value(&lines, index, "key") {
                    save_keys.insert(key.to_owned());
                }
            }
        }
    }
    if !save_keys.is_subset(&restore_keys) {
        failures.push(format!(
            "cache save key has no identical restore key in {}",
            path.display()
        ));
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
        || reviewed_oracle_provider_selection(path, lines, index, original)
        || reviewed_public_report_configuration(path, lines, index, original)
        || reviewed_initial_surveillance_dispatch(path, lines, index, original)
        || reviewed_initial_surveillance_finalizer(path, lines, index, original)
        || reviewed_active_subject_selection(path, lines, index, original)
        || reviewed_prior_public_promotion(path, lines, index, original)
        || reviewed_collection_authority_acquisition(path, lines, index, original)
        || reviewed_transport_probe_environment(path, lines, index, original)
        || reviewed_regression_environment(path, lines, index, original)
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
    following.starts_with(&macos)
        || following.starts_with(&windows)
        || (following.starts_with(&merge)
            && following.get(merge.len()).is_some_and(|line| {
                line.strip_prefix("        ") == Some(COLLECTION_ACQUISITION_COMMAND)
            }))
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
    let (artifact_id, artifact_name, directory_digest, input, output) = match role {
        "packet" => (
            "packet_artifact_id",
            "packets",
            "packet_directory_sha256",
            "transport-packets",
            "packet-selection",
        ),
        "subject" => (
            "subject_artifact_id",
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
            "regression-proposal-${{ github.run_id }}-${{ github.run_attempt }}",
            "${{ needs.prepare.outputs.directory_sha256 }}",
            "ci-out/regression-sealed/package --output ci-out/regression-sealed/proposal-selection",
        ),
        (
            "${{ needs.seal-review-subject-automatic.outputs.artifact_id }}",
            "regression-review-subject-${{ github.run_id }}-${{ github.run_attempt }}",
            "${{ needs.seal-review-subject-automatic.outputs.directory_sha256 }}",
            "ci-in/regression-sealed --output ci-out/regression-sealed-selection",
        ),
        (
            "${{ needs.prepare.outputs.artifact_id }}",
            "regression-proposal-${{ github.run_id }}-${{ github.run_attempt }}",
            "${{ needs.prepare.outputs.directory_sha256 }}",
            "ci-in/regression-package --output ci-out/regression-package-selection",
        ),
        (
            "${{ needs.review-automatic.outputs.artifact_id }}",
            "regression-review-${{ github.run_id }}-${{ github.run_attempt }}",
            "${{ needs.review-automatic.outputs.directory_sha256 }}",
            "ci-in/regression-review --output ci-out/regression-review-selection",
        ),
        (
            "${{ needs.promote-automatic.outputs.artifact_id }}",
            "reviewed-regression-${{ github.run_id }}-${{ github.run_attempt }}",
            "${{ needs.promote-automatic.outputs.directory_sha256 }}",
            "ci-in/reviewed-regression --output ci-out/reviewed-regression-selection",
        ),
    ];
    suffixes.iter().any(|(id, name, digest, command)| {
        following.starts_with(&[
            "          GITHUB_TOKEN: ${{ github.token }}",
            &format!("          REGRESSION_PROVIDER_ARTIFACT_ID: {id}"),
            &format!("          REGRESSION_PROVIDER_ARTIFACT_NAME: {name}"),
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
        && lines.get(index + 2) == Some(&"          GITHUB_TOKEN: ${{ github.token }}")
        && lines.get(index + 3)
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
        line.starts_with("          ORACLE_UNSIGNED_ARTIFACT_ID: ${{ steps.resolve-")
    }) {
        lines.get(index + 3).copied().unwrap_or_default()
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
    let finalize = lines.get(index + 1) == Some(&"          GITHUB_TOKEN: ${{ github.token }}")
        && lines.get(index + 2)
            == Some(&"          INITIAL_SURVEILLANCE_RUN_ID: ${{ github.event.workflow_run.id }}")
        && lines.get(index + 3)
            == Some(
                &"          INITIAL_SURVEILLANCE_RUN_ATTEMPT: ${{ github.event.workflow_run.run_attempt }}",
            )
        && lines.get(index + 4)
            == Some(
                &"          PUBLIC_COMPATIBILITY_REPORT_BASE_URL: ${{ vars.PUBLIC_COMPATIBILITY_REPORT_BASE_URL }}",
            )
        && lines.get(index + 5)
            == Some(
                &"        run: ./target/ci/hell-ci custody-ops workflow-finalize-initial-surveillance",
            );
    let failure = lines.get(index + 1)
        == Some(&"          INITIAL_SURVEILLANCE_RUN_ID: ${{ github.event.workflow_run.id }}")
        && lines.get(index + 2)
            == Some(
                &"          INITIAL_SURVEILLANCE_RUN_ATTEMPT: ${{ github.event.workflow_run.run_attempt }}",
            )
        && lines.get(index + 3)
            == Some(
                &"          INITIAL_SURVEILLANCE_CONCLUSION: ${{ github.event.workflow_run.conclusion }}",
            )
        && lines.get(index + 4)
            == Some(
                &"        run: ./target/ci/hell-ci custody-ops workflow-record-initial-surveillance-failure",
            );
    finalize || failure
}

fn reviewed_initial_surveillance_dispatch(
    path: &Path,
    lines: &[&str],
    index: usize,
    original: &str,
) -> bool {
    path.file_name().and_then(|name| name.to_str()) == Some("evidence-custody.yml")
        && original == "        env:"
        && lines.get(index + 1) == Some(&"          GITHUB_TOKEN: ${{ github.token }}")
        && lines.get(index + 2)
            == Some(
                &"        run: ./target/ci/hell-ci custody-ops workflow-dispatch-initial-surveillance",
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
    path == workflow_path("artifact-independent-acquisition.yml")
        && original == "        env:"
        && lines.get(index + 1) == Some(&"          GH_TOKEN: ${{ github.token }}")
        && lines.get(index + 2)
            == Some(
                &"          ARTIFACT_INDEPENDENT_ARCHIVE_SHA256: ${{ vars.ARTIFACT_INDEPENDENT_ARCHIVE_SHA256 }}",
            )
        && lines.get(index + 3)
            == Some(
                &"          ARTIFACT_INDEPENDENT_BUCKET: ${{ vars.ARTIFACT_INDEPENDENT_BUCKET }}",
            )
        && lines.get(index + 4)
            == Some(&"          ARTIFACT_INDEPENDENT_KEY: ${{ vars.ARTIFACT_INDEPENDENT_KEY }}")
        && lines.get(index + 5)
            == Some(
                &"          ARTIFACT_INDEPENDENT_REGION: ${{ vars.ARTIFACT_INDEPENDENT_REGION }}",
            )
        && lines.get(index + 6)
            == Some(
                &"          ARTIFACT_INDEPENDENT_VERSION_ID: ${{ vars.ARTIFACT_INDEPENDENT_VERSION_ID }}",
            )
        && lines.get(index + 7)
            == Some(
                &"        run: ./target/ci/hell-ci artifact-acquire external-independent --output ci-out/acquisition/receipt-independent.json --artifact native-oracle-merged --github-dispatch-inputs",
            )
        && lines[..index]
            .iter()
            .rev()
            .take(2)
            .any(|line| *line == "      - name: Acquire exact immutable external artifact set")
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

    #[test]
    fn collection_authority_workflow_is_isolated_and_producers_are_exact() {
        let campaign = include_str!("../../../.github/workflows/collection-authority.yml");
        let tool = include_str!("../../../tools/collection_authority_acquire.py");
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
    fn collection_authority_rejects_candidate_control_of_trusted_harness() {
        let campaign = include_str!("../../../.github/workflows/collection-authority.yml");
        let tool = include_str!("../../../tools/collection_authority_acquire.py");
        assert_collection_workflow_mutants_rejected(
            tool,
            [
                (
                    "candidate-checkout-verification",
                    collection_job_mutant(
                        campaign,
                        "collection-authority-macos",
                        "run: git -C ci-work/candidate merge-base --is-ancestor \"$HELL_SOURCE_COMMIT\" HEAD",
                        "run: true",
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
        let tool = include_str!("../../../tools/collection_authority_acquire.py");
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
            ],
        );
    }

    #[test]
    fn collection_authority_merge_rejects_transport_and_identity_substitutions() {
        let campaign = include_str!("../../../.github/workflows/collection-authority.yml");
        let tool = include_str!("../../../tools/collection_authority_acquire.py");
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
                "$GITHUB_RUN_ATTEMPT:$COLLECTION_LINUX_ARTIFACT_ID",
                "1:$COLLECTION_LINUX_ARTIFACT_ID",
                1,
            )),
                ("provider-candidate", campaign.replacen(
                "--provider-head \"$GITHUB_SHA\" --candidate-commit \"$HELL_SOURCE_COMMIT\"",
                "--provider-head \"$HELL_SOURCE_COMMIT\" --candidate-commit \"$GITHUB_SHA\"",
                1,
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
                "subject-path: ci-out/native-shards/collection-authority.json",
                "subject-path: ci-out/native-shards/merge-report.json",
                1,
            )),
                ("name-download", campaign.replacen(
                "run: python3 tools/collection_authority_acquire.py --repository",
                "uses: actions/download-artifact@70fc10c6e5e1ce46ad2ea6f2b72d43f7d47b13c3 # v8.0.0\n        with:\n          name: collection-authority-merged\n      - run: true #",
                1,
            )),
            ],
        );
    }

    #[test]
    fn collection_authority_acquisition_invariants_reject_substitution() {
        let campaign = include_str!("../../../.github/workflows/collection-authority.yml");
        let tool = include_str!("../../../tools/collection_authority_acquire.py");
        for (label, mutant) in [
            (
                "page-size",
                tool.replacen("PER_PAGE = 100", "PER_PAGE = 99", 1),
            ),
            (
                "job-completion",
                tool.replacen(
                    "producer job {expected_name} did not complete successfully",
                    "producer job may still be running",
                    1,
                ),
            ),
            (
                "archive",
                tool.replacen("provider-archive.zip", "provider-repacked.zip", 1),
            ),
            (
                "run-event",
                tool.replacen(
                    "require_string(run.get(\"event\"), \"run event\") != \"workflow_dispatch\"",
                    "False",
                    1,
                ),
            ),
            (
                "run-branch",
                tool.replacen(
                    "require_string(run.get(\"head_branch\"), \"run head branch\") != \"main\"",
                    "False",
                    1,
                ),
            ),
            (
                "mode",
                tool.replacen(
                    "artifact ZIP file {info.filename!r} has invalid mode",
                    "artifact mode ignored",
                    1,
                ),
            ),
            (
                "inventory",
                tool.replacen("case_count != 1191", "case_count < 1191", 1),
            ),
        ] {
            assert!(
                !collection_authority_policy(campaign, &mutant).is_empty(),
                "accepted collection acquisition substitution {label}"
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
