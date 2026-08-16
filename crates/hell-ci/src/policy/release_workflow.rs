use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_yaml::{Mapping, Value};

const RELEASE_PATH: &str = ".github/workflows/release.yml";
const CI_PATH: &str = ".github/workflows/ci.yml";
const MUTATION_PATH: &str = ".github/workflows/mutation.yml";
const NIGHTLY_PATH: &str = ".github/workflows/nightly.yml";
const REGRESSION_CORPUS_PATH: &str = ".github/workflows/regression-corpus.yml";
const REGRESSION_SUBJECT_PATH: &str = ".github/workflows/regression-subject.yml";
const REGRESSION_CORPUS_PATHS: [&str; 4] = [
    "compat/regression-corpus.tsv",
    "crates/hell-testkit/**",
    "crates/hell-cli/tests/**",
    ".github/workflows/regression-corpus.yml",
];
const NIGHTLY_ORACLE_ACQUIRE: &str = "./target/ci/hell-ci oracle-acquire acquire --artifact ci-out/linux-release-oracle --provider-response ci-out/linux-release-provider.json --receipt ci-out/linux-release-oracle-receipt.json";
const NIGHTLY_DIVERGENCE_PROTOTYPES: &str = "./target/ci/hell-ci divergence-prototype verify";
const NIGHTLY_REGRESSION_PRODUCER: &str = "./target/ci/hell-ci nightly --oracle ci-out/linux-release-oracle --oracle-sha256 5ccc78e62200eb5aea8b9da9161334c61848d0d3e7de2f270929920cfbf357c9 --dependency-attestation ci-out/dependency-policy.json --report ci-out/nightly-linux.json";
const NIGHTLY_REGRESSION_CONSUMER: &str = "./target/ci/hell-ci regression-import explore-generated --input ci-out --output ci-out/regression-exploration";
const MUTATION_RUN_COMMAND: &str =
    "./target/ci/hell-ci mutation run --output ci-out/mutation/mutation-score.json";
const REGRESSION_TYPED_CORPUS_COMMAND: &str =
    "cargo test --locked --package hell-testkit --test typed_corpus";
const REGRESSION_ORACLE_COMMAND: &str =
    "cargo test --locked --package hell-cli --test oracle_regressions";
const BUILD_DRIVER_COMMAND: &str =
    "cargo build --locked --profile ci --package hell-ci --bin hell-ci";
const BUILD_DRIVER_AND_HELPER_COMMAND: &str = "cargo build --locked --profile ci --package hell-ci --bin hell-ci --package hell-testkit --bin hell-test-helper";
const BUILD_DEBUG_CANDIDATE_COMMAND: &str =
    "cargo build --locked --package hell-cli --bin hell --features compat-tracing";
const BUILD_RELEASE_CANDIDATE_COMMAND: &str =
    "cargo build --release --locked --package hell-cli --bin hell --features compat-tracing";
const MACOS_LLVM_COMMAND: &str = "brew link --force llvm@18";
const NIGHTLY_DEPENDENCY_COMMAND: &str = "./target/ci/hell-ci dependency-attestation --output ci-out/dependency-policy.json --report ci-out/dependency-policy-report.json";
const NIGHTLY_MACOS_PORTABILITY_COMMAND: &str =
    "./target/ci/hell-ci portability --report ci-out/nightly-macos.json";
const NIGHTLY_WINDOWS_PORTABILITY_COMMAND: &str =
    ".\\target\\ci\\hell-ci.exe portability --report ci-out\\nightly-windows.json";
const NIGHTLY_MACOS_ORACLE_COMMAND: &str = "./target/ci/hell-ci native-oracle-shard --source oracle-source --platform macos-arm64 --dependency-attestation ci-out/dependency-policy.json --report ci-out/macos-oracle.json";
const NIGHTLY_WINDOWS_DEPENDENCY_COMMAND: &str = ".\\target\\ci\\hell-ci.exe dependency-attestation --output ci-out\\dependency-policy.json --report ci-out\\dependency-policy-report.json";
const NIGHTLY_WINDOWS_ORACLE_COMMAND: &str = ".\\target\\ci\\hell-ci.exe native-oracle-shard --source oracle-source --platform windows-amd64 --dependency-attestation ci-out\\dependency-policy.json --report ci-out\\windows-oracle.json";
const FUZZ_PREPARE_COMMAND: &str = "./target/ci/hell-ci fuzz-corpus prepare --input crates/hell-ci/fuzz/corpus --output ci-out/fuzz-corpora --to ci-out/fuzz-artifacts";
const FUZZ_REQUIREMENT_COMMAND: &str = "cargo +nightly-2026-07-31 fuzz run --fuzz-dir crates/hell-ci/fuzz requirement_toml ci-out/fuzz-corpora/requirement_toml -- -runs=64 -timeout=10 -artifact_prefix=ci-out/fuzz-artifacts/requirement_toml/";
const FUZZ_NORMALIZER_COMMAND: &str = "cargo +nightly-2026-07-31 fuzz run --fuzz-dir crates/hell-ci/fuzz normalizer_toml ci-out/fuzz-corpora/normalizer_toml -- -runs=64 -timeout=10 -artifact_prefix=ci-out/fuzz-artifacts/normalizer_toml/";
const FUZZ_DIVERGENCE_COMMAND: &str = "cargo +nightly-2026-07-31 fuzz run --fuzz-dir crates/hell-ci/fuzz divergence_toml ci-out/fuzz-corpora/divergence_toml -- -runs=64 -timeout=10 -artifact_prefix=ci-out/fuzz-artifacts/divergence_toml/";
const FUZZ_REPLAY_COMMAND: &str = "cargo +nightly-2026-07-31 fuzz run --fuzz-dir crates/hell-ci/fuzz normalizer_replay ci-out/fuzz-corpora/normalizer_replay -- -runs=64 -timeout=10 -artifact_prefix=ci-out/fuzz-artifacts/normalizer_replay/";
const FUZZ_TRACE_COMMAND: &str = "cargo +nightly-2026-07-31 fuzz run --fuzz-dir crates/hell-ci/fuzz semantic_trace ci-out/fuzz-corpora/semantic_trace -- -runs=64 -timeout=10 -artifact_prefix=ci-out/fuzz-artifacts/semantic_trace/";
const FUZZ_VERIFY_COMMAND: &str =
    "./target/ci/hell-ci fuzz-corpus verify-clean --input crates/hell-ci/fuzz/corpus";
const CARGO_DENY_INSTALL_COMMAND: &str = "cargo install cargo-deny --locked --version 0.20.2 --force --target-dir ../ci-tool-cache/cargo-deny-target";
const NIGHTLY_CARGO_DENY_INSTALL_COMMAND: &str = "cargo install cargo-deny --locked --version 0.20.2 --force --target-dir ci-tool-cache/cargo-deny-target";
const RELEASE_RESOLVE_COMMAND: &str =
    "./automation/target/ci/hell-ci release resolve --output release-state/resolution.json";
const RELEASE_PLAN_COMMAND: &str = "./automation/target/ci/hell-ci release plan --resolution release-state/resolution.json --repository-root candidate --output release-plan --report release-reports/plan.json";
const READINESS_PLAN_COMMAND: &str = "./automation/target/ci/hell-ci readiness plan --repository-root candidate --output readiness-plan";
const READINESS_LINUX_COMMAND: &str = "./automation/target/ci/hell-ci readiness platform --platform linux-x86_64 --required-gates runner-identity,candidate-checkout,oracle-checkout,conformance-policy,conformance-plan-binding,case-catalog,normalizer-catalog,divergence-catalog,verify,format,clippy,workspace-tests,documentation,dependency-policy,release-examples,release-mutation-catalog,linux-release-oracle-digest,conformance-evidence,divergence-prototypes,release-build,archive-verification,package-smoke --plan readiness-input/readiness-plan.json --conformance-plan readiness-input/conformance-plan.json --repository-root candidate --oracle-source oracle-source --output platform-out";
const READINESS_MACOS_COMMAND: &str = "./automation/target/ci/hell-ci readiness platform --platform macos-aarch64 --required-gates runner-identity,candidate-checkout,oracle-checkout,conformance-plan-binding,portability,workspace-tests,release-build,native-oracle-build,conformance-evidence,divergence-prototypes,archive-verification,package-smoke --plan readiness-input/readiness-plan.json --conformance-plan readiness-input/conformance-plan.json --repository-root candidate --oracle-source oracle-source --output platform-out";
const READINESS_WINDOWS_COMMAND: &str = ".\\automation\\target\\ci\\hell-ci.exe readiness platform --platform windows-x86_64 --required-gates runner-identity,candidate-checkout,oracle-checkout,conformance-plan-binding,portability,workspace-tests,release-build,native-oracle-build,conformance-evidence,divergence-prototypes,archive-verification,package-smoke --plan readiness-input\\readiness-plan.json --conformance-plan readiness-input\\conformance-plan.json --repository-root candidate --oracle-source oracle-source --output platform-out";
const READINESS_VERIFY_COMMAND: &str = "./automation/target/ci/hell-ci readiness verify --plan readiness-input/plan/readiness-plan.json --conformance-plan readiness-input/plan/conformance-plan.json --input readiness-input/platforms --output readiness-result";
const LINUX_PLATFORM_COMMAND: &str = "./automation/target/ci/hell-ci release platform --platform linux-x86_64 --required-gates runner-identity,candidate-checkout,oracle-checkout,conformance-policy,conformance-plan-binding,case-catalog,normalizer-catalog,divergence-catalog,verify,format,clippy,workspace-tests,documentation,dependency-policy,release-examples,release-mutation-catalog,linux-release-oracle-digest,conformance-evidence,divergence-prototypes,release-build,archive-verification,package-smoke --plan release-input/release-plan.json --conformance-plan release-input/conformance-plan.json --repository-root candidate --oracle-source oracle-source --output platform-out";
const MACOS_PLATFORM_COMMAND: &str = "./automation/target/ci/hell-ci release platform --platform macos-aarch64 --required-gates runner-identity,candidate-checkout,oracle-checkout,conformance-plan-binding,portability,workspace-tests,release-build,native-oracle-build,conformance-evidence,divergence-prototypes,archive-verification,package-smoke --plan release-input/release-plan.json --conformance-plan release-input/conformance-plan.json --repository-root candidate --oracle-source oracle-source --output platform-out";
const WINDOWS_PLATFORM_COMMAND: &str = ".\\automation\\target\\ci\\hell-ci.exe release platform --platform windows-x86_64 --required-gates runner-identity,candidate-checkout,oracle-checkout,conformance-plan-binding,portability,workspace-tests,release-build,native-oracle-build,conformance-evidence,divergence-prototypes,archive-verification,package-smoke --plan release-input\\release-plan.json --conformance-plan release-input\\conformance-plan.json --repository-root candidate --oracle-source oracle-source --output platform-out";
const ASSEMBLE_COMMAND: &str = "./automation/target/ci/hell-ci release assemble --plan release-input/plan/release-plan.json --conformance-plan release-input/plan/conformance-plan.json --input release-input/platforms --output release-bundle --report release-reports/assembly.json";
const POST_ASSEMBLY_REMOTE_COMMAND: &str = "./automation/target/ci/hell-ci release check-remote-state --plan release-input/plan/release-plan.json --report release-reports/post-assembly-remote-state.json";
const VERIFY_BUNDLE_COMMAND: &str = "./automation/target/ci/hell-ci release verify-bundle --plan release-input/plan/release-plan.json --conformance-plan release-input/plan/conformance-plan.json --input release-bundle --report release-reports/prepublish.json";
const PRE_ATTESTATION_REMOTE_COMMAND: &str = "./automation/target/ci/hell-ci release check-remote-state --plan release-input/plan/release-plan.json --report release-reports/pre-attestation-remote-state.json";
const STAGE_ATTESTATIONS_COMMAND: &str =
    "./automation/target/ci/hell-ci release stage-attestations --input release-bundle";
const PUBLISH_COMMAND: &str = "./automation/target/ci/hell-ci release publish --plan release-input/plan/release-plan.json --input release-bundle --report release-reports/publication.json";
const GITHUB_TOKEN_EXPRESSION: &str = "${{ github.token }}";
const RELEASE_GATE_PREDICATE_V2: &str =
    "https://github.com/Portfoligno/hell-rs/attestations/release-gate/v2";
const RETIRED_AUTHORITY_COMMANDS: [&str; 5] = [
    "assurance-verify",
    "release-oracle",
    "promotion-gate",
    "promotion-worklist",
    "merge-native-shards",
];
const CHECKOUT_ACTION: &str = "actions/checkout";
const CACHE_RESTORE_ACTION: &str = "actions/cache/restore";
const CACHE_SAVE_ACTION: &str = "actions/cache/save";

struct TokenStep {
    job: &'static str,
    command: &'static str,
}

const TOKEN_STEPS: [TokenStep; 5] = [
    TokenStep {
        job: "resolve",
        command: RELEASE_RESOLVE_COMMAND,
    },
    TokenStep {
        job: "resolve",
        command: RELEASE_PLAN_COMMAND,
    },
    TokenStep {
        job: "assemble",
        command: POST_ASSEMBLY_REMOTE_COMMAND,
    },
    TokenStep {
        job: "publish",
        command: PRE_ATTESTATION_REMOTE_COMMAND,
    },
    TokenStep {
        job: "publish",
        command: PUBLISH_COMMAND,
    },
];

const LINUX_GATES: [&str; 22] = [
    "runner-identity",
    "candidate-checkout",
    "oracle-checkout",
    "conformance-policy",
    "conformance-plan-binding",
    "case-catalog",
    "normalizer-catalog",
    "divergence-catalog",
    "verify",
    "format",
    "clippy",
    "workspace-tests",
    "documentation",
    "dependency-policy",
    "release-examples",
    "release-mutation-catalog",
    "linux-release-oracle-digest",
    "conformance-evidence",
    "divergence-prototypes",
    "release-build",
    "archive-verification",
    "package-smoke",
];

const NATIVE_GATES: [&str; 12] = [
    "runner-identity",
    "candidate-checkout",
    "oracle-checkout",
    "conformance-plan-binding",
    "portability",
    "workspace-tests",
    "release-build",
    "native-oracle-build",
    "conformance-evidence",
    "divergence-prototypes",
    "archive-verification",
    "package-smoke",
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Workflow {
    name: Option<Value>,
    #[serde(rename = "run-name")]
    run_name: Option<Value>,
    #[serde(rename = "on")]
    triggers: Value,
    permissions: Option<Value>,
    concurrency: Option<Value>,
    env: Option<Value>,
    jobs: BTreeMap<String, Job>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Job {
    name: Option<Value>,
    needs: Option<OneOrMany>,
    #[serde(rename = "runs-on")]
    runs_on: Option<Value>,
    #[serde(rename = "timeout-minutes")]
    timeout_minutes: Option<Value>,
    outputs: Option<Value>,
    permissions: Option<Value>,
    #[serde(rename = "if")]
    condition: Option<Value>,
    env: Option<Value>,
    steps: Option<Vec<Step>>,
    strategy: Option<Value>,
    uses: Option<Value>,
    with: Option<Value>,
    secrets: Option<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

impl OneOrMany {
    fn values(&self) -> Vec<&str> {
        match self {
            Self::One(value) => vec![value],
            Self::Many(values) => values.iter().map(String::as_str).collect(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Step {
    name: Option<Value>,
    id: Option<Value>,
    #[serde(rename = "if")]
    condition: Option<Value>,
    uses: Option<String>,
    run: Option<String>,
    shell: Option<Value>,
    #[serde(rename = "working-directory")]
    working_directory: Option<Value>,
    env: Option<Value>,
    with: Option<Mapping>,
    #[serde(rename = "continue-on-error")]
    continue_on_error: Option<Value>,
    #[serde(rename = "timeout-minutes")]
    timeout_minutes: Option<Value>,
}

pub(super) fn check(root: &Path, tracked: &[PathBuf], failures: &mut Vec<String>) {
    check_custom_environment_interfaces(root, tracked, failures);
    let workflow_paths = tracked
        .iter()
        .filter(|path| path.parent() == Some(Path::new(".github/workflows")))
        .collect::<Vec<_>>();
    let actual_paths = workflow_paths
        .iter()
        .filter_map(|path| path.to_str())
        .collect::<BTreeSet<_>>();
    let expected_paths = [
        CI_PATH,
        MUTATION_PATH,
        NIGHTLY_PATH,
        REGRESSION_CORPUS_PATH,
        REGRESSION_SUBJECT_PATH,
        RELEASE_PATH,
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    if actual_paths != expected_paths {
        failures.push(format!(
            "workflow files must be exactly {expected_paths:?}, found {actual_paths:?}"
        ));
    }
    let mut parsed = BTreeMap::new();
    let mut dispatches = Vec::new();
    for path in workflow_paths {
        let bytes = match fs::read(root.join(path)) {
            Ok(bytes) => bytes,
            Err(error) => {
                failures.push(format!("cannot read {}: {error}", path.display()));
                continue;
            }
        };
        let workflow = match serde_yaml::from_slice::<Workflow>(&bytes) {
            Ok(workflow) => workflow,
            Err(error) => {
                failures.push(format!(
                    "{} is not typed workflow YAML: {error}",
                    path.display()
                ));
                continue;
            }
        };
        if mapping(&workflow.triggers)
            .is_some_and(|triggers| contains_key(triggers, "workflow_dispatch"))
        {
            dispatches.push((*path).clone());
        }
        check_triggers(path, &workflow, failures);
        check_common(path, &workflow, failures);
        parsed.insert((*path).clone(), workflow);
    }
    if dispatches != [PathBuf::from(RELEASE_PATH)] {
        failures.push(format!(
            "release.yml must be the sole workflow_dispatch: {dispatches:?}"
        ));
    }
    let Some(release) = parsed.get(Path::new(RELEASE_PATH)) else {
        failures.push("release workflow is missing or invalid".to_owned());
        return;
    };
    check_release(release, failures);
    match parsed.get(Path::new(CI_PATH)) {
        Some(ci) => check_ci(ci, failures),
        None => failures.push("CI workflow is missing or invalid".to_owned()),
    }
    match parsed.get(Path::new(NIGHTLY_PATH)) {
        Some(nightly) => check_nightly(nightly, failures),
        None => failures.push("nightly workflow is missing or invalid".to_owned()),
    }
    for path in [
        MUTATION_PATH,
        NIGHTLY_PATH,
        REGRESSION_CORPUS_PATH,
        REGRESSION_SUBJECT_PATH,
    ] {
        if let Some(workflow) = parsed.get(Path::new(path)) {
            check_push_gate_inventory(path, workflow, failures);
            check_push_cache_pairs(path, workflow, failures);
        }
    }
}

fn check_custom_environment_interfaces(
    root: &Path,
    tracked: &[PathBuf],
    failures: &mut Vec<String>,
) {
    for relative in tracked.iter().filter(|path| {
        matches!(
            path.extension().and_then(|extension| extension.to_str()),
            Some("rs" | "hell" | "hs")
        )
    }) {
        let source = match fs::read_to_string(root.join(relative)) {
            Ok(source) => source,
            Err(error) => {
                failures.push(format!(
                    "cannot inspect {} for environment interfaces: {error}",
                    relative.display()
                ));
                continue;
            }
        };
        for name in environment_interface_names(&source) {
            if standard_environment_name(&name) {
                continue;
            }
            failures.push(format!(
                "{} defines or consumes custom environment interface {name:?}; use typed arguments or files",
                relative.display(),
            ));
        }
    }
}

fn environment_interface_names(source: &str) -> BTreeSet<String> {
    let compact = source
        .chars()
        .filter(|value| !value.is_ascii_whitespace())
        .collect::<String>();
    let mut names = BTreeSet::new();
    for marker in [
        "std::env::var(\"",
        "std::env::var_os(\"",
        "env::var(\"",
        "env::var_os(\"",
        ".env(\"",
        ".env_remove(\"",
        ".environment(\"",
        "option_env!(\"",
        "env!(\"",
        "set_var(\"",
        "remove_var(\"",
        "cargo:rustc-env=",
        "required_env(\"",
        "required_env_os(\"",
        "parse_env_u64(\"",
    ] {
        let mut remainder = compact.as_str();
        while let Some(index) = remainder.find(marker) {
            let value = &remainder[index + marker.len()..];
            let name = value.split(['"', '=', '\n']).next().unwrap_or_default();
            if environment_name_shape(name) {
                names.insert(name.to_owned());
            }
            remainder = value;
        }
    }
    let mut remainder = compact.as_str();
    while let Some(index) = remainder.find("Process.setEnv") {
        let value = &remainder[index + "Process.setEnv".len()..];
        if let Some(argument) = first_balanced_argument(value) {
            process_environment_names(argument, &mut names);
        }
        remainder = value;
    }
    names
}

fn first_balanced_argument(value: &str) -> Option<&str> {
    let bytes = value.as_bytes();
    let first = *bytes.first()?;
    let expected_close = match first {
        b'(' => b')',
        b'[' => b']',
        _ => return None,
    };
    let mut stack = vec![expected_close];
    let mut quoted = false;
    let mut escaped = false;
    for (index, byte) in bytes.iter().copied().enumerate().skip(1) {
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
            continue;
        }
        if byte == b'"' && (index == 0 || bytes[index - 1] != b'\\') {
            quoted = true;
            continue;
        }
        match byte {
            b'(' => stack.push(b')'),
            b'[' => stack.push(b']'),
            b')' | b']' if stack.last() == Some(&byte) => {
                stack.pop();
                if stack.is_empty() {
                    return Some(&value[..=index]);
                }
            }
            _ => {}
        }
    }
    None
}

fn process_environment_names(argument: &str, names: &mut BTreeSet<String>) {
    let normalized = argument.replace("\\\"", "\"");
    let mut remainder = normalized.as_str();
    while let Some(index) = remainder.find("(\"") {
        let value = &remainder[index + 2..];
        let Some(end) = value.find('"') else {
            break;
        };
        let name = &value[..end];
        let after_name = &value[end + 1..];
        if after_name.starts_with(",\"") && environment_name_shape(name) {
            names.insert(name.to_owned());
        }
        remainder = value;
    }
}

fn environment_name_shape(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'(' | b')'))
}

fn standard_environment_name(name: &str) -> bool {
    const EXACT: &[&str] = &[
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
        "ACTIONS_ID_TOKEN_REQUEST_URL",
        "ACTIONS_RUNTIME_TOKEN",
        "APPDATA",
        "CARGO",
        "CARGO_BUILD_TARGET",
        "CARGO_HOME",
        "CARGO_INCREMENTAL",
        "CARGO_MANIFEST_DIR",
        "CARGO_PKG_VERSION",
        "CARGO_PROFILE",
        "CARGO_TARGET_DIR",
        "CARGO_TERM_COLOR",
        "CI",
        "ComSpec",
        "DEVELOPER_DIR",
        "GITHUB_ACTIONS",
        "GITHUB_API_URL",
        "GITHUB_ENV",
        "GITHUB_EVENT_NAME",
        "GITHUB_EVENT_PATH",
        "GITHUB_OUTPUT",
        "GITHUB_PATH",
        "GITHUB_REF_NAME",
        "GITHUB_REPOSITORY",
        "GITHUB_RUN_ATTEMPT",
        "GITHUB_RUN_ID",
        "GITHUB_STEP_SUMMARY",
        "GITHUB_TOKEN",
        "GITHUB_WORKFLOW_REF",
        "GITHUB_WORKFLOW_SHA",
        "GITHUB_WORKSPACE",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_KEY_0",
        "GIT_CONFIG_VALUE_0",
        "HOME",
        "ImageOS",
        "ImageVersion",
        "LANG",
        "LC_ALL",
        "LIB",
        "LIBPATH",
        "LIBRARY_PATH",
        "LOCALAPPDATA",
        "NUMBER_OF_PROCESSORS",
        "OUT_DIR",
        "PATH",
        "PATHEXT",
        "ProgramData",
        "ProgramFiles",
        "ProgramFiles(x86)",
        "ProgramW6432",
        "RUNNER_ARCH",
        "RUNNER_ENVIRONMENT",
        "RUNNER_OS",
        "RUNNER_TEMP",
        "RUSTC_WRAPPER",
        "RUSTDOCFLAGS",
        "RUSTFLAGS",
        "RUSTUP_HOME",
        "RUSTUP_TOOLCHAIN",
        "SCCACHE_DIR",
        "SDKROOT",
        "SOURCE_DATE_EPOCH",
        "SYSTEMROOT",
        "SystemRoot",
        "TEMP",
        "TMP",
        "TMPDIR",
        "UCRTVersion",
        "USERPROFILE",
        "UniversalCRTSdkDir",
        "VCINSTALLDIR",
        "VCToolsInstallDir",
        "VSINSTALLDIR",
        "VisualStudioVersion",
        "WindowsSDKVersion",
        "WindowsSdkDir",
        "__DOTNET_ADD_64BIT",
        "__DOTNET_PREFERRED_BITNESS",
    ];
    EXACT.contains(&name) || name.starts_with("CARGO_BIN_EXE_")
}

fn check_triggers(path: &Path, workflow: &Workflow, failures: &mut Vec<String>) {
    let Some(triggers) = mapping(&workflow.triggers) else {
        failures.push(format!(
            "{} triggers must be an explicit mapping",
            path.display()
        ));
        return;
    };
    for retired in ["workflow_run", "schedule"] {
        if contains_key(triggers, retired) {
            failures.push(format!(
                "{} uses retired {retired} indirection",
                path.display()
            ));
        }
    }
    match path.to_str() {
        Some(CI_PATH) => check_ci_triggers(triggers, failures),
        Some(MUTATION_PATH | NIGHTLY_PATH | REGRESSION_SUBJECT_PATH) => {
            check_push_only_triggers(path, triggers, false, failures);
            check_exact_push_checkouts(path, workflow, failures);
        }
        Some(REGRESSION_CORPUS_PATH) => {
            check_push_only_triggers(path, triggers, true, failures);
            check_exact_push_checkouts(path, workflow, failures);
        }
        _ => {}
    }
    check_no_retired_event_references(path, workflow, failures);
    if path == Path::new(NIGHTLY_PATH) {
        check_exact_permissions(
            workflow.permissions.as_ref(),
            &[("contents", "read")],
            "nightly workflow",
            failures,
        );
    }
    if path == Path::new(REGRESSION_SUBJECT_PATH) {
        check_regression_subject(workflow, failures);
    }
}

fn check_regression_subject(workflow: &Workflow, failures: &mut Vec<String>) {
    check_exact_permissions(
        workflow.permissions.as_ref(),
        &[("contents", "read")],
        "regression-subject workflow",
        failures,
    );
    let actual_jobs = workflow
        .jobs
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if actual_jobs != BTreeSet::from(["validate"]) {
        failures.push(format!(
            "regression-subject jobs must be exactly validate, found {actual_jobs:?}"
        ));
    }
    let Some(validate) = workflow.jobs.get("validate") else {
        return;
    };
    if validate.condition.is_some() {
        failures.push("regression-subject validate job must not gate its direct push".to_owned());
    }
    let checkouts = validate
        .steps
        .as_deref()
        .unwrap_or_default()
        .iter()
        .filter(|step| step.uses.as_deref().and_then(action_name) == Some(CHECKOUT_ACTION))
        .collect::<Vec<_>>();
    if checkouts.len() != 1
        || with_scalar(checkouts[0], "repository").is_some()
        || with_scalar(checkouts[0], "ref") != Some("${{ github.sha }}")
        || with_u64(checkouts[0], "fetch-depth") != Some(1)
        || with_bool(checkouts[0], "persist-credentials") != Some(false)
    {
        failures.push(
            "regression-subject must have one exact github.sha checkout with depth one and no persisted credentials"
                .to_owned(),
        );
    }
}

fn check_no_retired_event_references(path: &Path, workflow: &Workflow, failures: &mut Vec<String>) {
    let retired = ["workflow_run", "schedule"];
    let workflow_values = [
        Some(&workflow.triggers),
        workflow.run_name.as_ref(),
        workflow.permissions.as_ref(),
        workflow.concurrency.as_ref(),
        workflow.env.as_ref(),
    ];
    let mut found = workflow_values
        .into_iter()
        .flatten()
        .any(|value| retired.iter().any(|needle| value_contains(value, needle)));
    for job in workflow.jobs.values() {
        found |= [
            job.name.as_ref(),
            job.runs_on.as_ref(),
            job.outputs.as_ref(),
            job.permissions.as_ref(),
            job.condition.as_ref(),
            job.env.as_ref(),
            job.strategy.as_ref(),
            job.uses.as_ref(),
            job.with.as_ref(),
            job.secrets.as_ref(),
        ]
        .into_iter()
        .flatten()
        .any(|value| retired.iter().any(|needle| value_contains(value, needle)));
        for step in job.steps.as_deref().unwrap_or_default() {
            found |= [
                step.name.as_ref(),
                step.id.as_ref(),
                step.condition.as_ref(),
                step.shell.as_ref(),
                step.working_directory.as_ref(),
                step.env.as_ref(),
                step.continue_on_error.as_ref(),
                step.timeout_minutes.as_ref(),
            ]
            .into_iter()
            .flatten()
            .any(|value| retired.iter().any(|needle| value_contains(value, needle)));
            found |= step
                .run
                .as_deref()
                .is_some_and(|value| retired.iter().any(|needle| value.contains(needle)));
            found |= step
                .uses
                .as_deref()
                .is_some_and(|value| retired.iter().any(|needle| value.contains(needle)));
            found |= step.with.as_ref().is_some_and(|mapping| {
                mapping.iter().any(|(key, value)| {
                    retired
                        .iter()
                        .any(|needle| value_contains(key, needle) || value_contains(value, needle))
                })
            });
        }
    }
    if found {
        failures.push(format!(
            "{} retains a retired workflow_run or schedule event reference",
            path.display()
        ));
    }
}

fn value_contains(value: &Value, needle: &str) -> bool {
    match value {
        Value::String(value) => value.contains(needle),
        Value::Sequence(values) => values.iter().any(|value| value_contains(value, needle)),
        Value::Mapping(values) => values
            .iter()
            .any(|(key, value)| value_contains(key, needle) || value_contains(value, needle)),
        Value::Tagged(value) => value_contains(&value.value, needle),
        Value::Null | Value::Bool(_) | Value::Number(_) => false,
    }
}

fn check_ci_triggers(triggers: &Mapping, failures: &mut Vec<String>) {
    let actual = mapping_keys(triggers);
    let expected = BTreeSet::from(["pull_request", "push"]);
    if actual != expected {
        failures.push(format!(
            "CI triggers must be exactly direct push and pull_request, found {actual:?}"
        ));
    }
    check_all_branch_push(get(triggers, "push"), false, "CI", failures);
}

#[allow(clippy::too_many_lines)]
fn check_ci(workflow: &Workflow, failures: &mut Vec<String>) {
    check_exact_permissions(
        workflow.permissions.as_ref(),
        &[("actions", "read"), ("contents", "read")],
        "CI workflow",
        failures,
    );
    let required_jobs = ["plan", "linux", "macos", "windows", "verify"];
    let actual_jobs = workflow
        .jobs
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected_jobs = required_jobs.into_iter().collect::<BTreeSet<_>>();
    if actual_jobs != expected_jobs {
        failures.push(format!(
            "CI readiness jobs must be exactly {expected_jobs:?}, found {actual_jobs:?}"
        ));
    }
    check_ci_gate_inventory(workflow, failures);
    check_needs(workflow, "plan", &[], failures);
    for job in ["linux", "macos", "windows"] {
        check_needs(workflow, job, &["plan"], failures);
    }
    check_needs(
        workflow,
        "verify",
        &["plan", "linux", "macos", "windows"],
        failures,
    );
    for (job_name, runner) in [
        ("plan", "ubuntu-24.04"),
        ("linux", "ubuntu-24.04"),
        ("macos", "macos-15"),
        ("windows", "windows-2025"),
        ("verify", "ubuntu-24.04"),
    ] {
        let Some(job) = workflow.jobs.get(job_name) else {
            continue;
        };
        if job.runs_on.as_ref().and_then(Value::as_str) != Some(runner) {
            failures.push(format!(
                "CI readiness job {job_name:?} runner must be exactly {runner:?}"
            ));
        }
        if job.condition.is_some() {
            failures.push(format!(
                "CI readiness job {job_name:?} must not be conditionally skipped"
            ));
        }
        if job.permissions.is_some() {
            failures.push(format!(
                "CI readiness job {job_name:?} must inherit read-only permissions"
            ));
        }
    }
    check_exact_outputs(
        workflow,
        "plan",
        &[
            ("artifact_id", "${{ steps.upload.outputs.artifact-id }}"),
            (
                "readiness_plan_digest",
                "${{ steps.plan.outputs.readiness_plan_digest }}",
            ),
            (
                "conformance_plan_digest",
                "${{ steps.plan.outputs.conformance_plan_digest }}",
            ),
            (
                "trusted_conformance_inputs_digest",
                "${{ steps.plan.outputs.trusted_conformance_inputs_digest }}",
            ),
        ],
        failures,
    );
    for job in ["linux", "macos", "windows"] {
        check_exact_outputs(
            workflow,
            job,
            &[("artifact_id", "${{ steps.upload.outputs.artifact-id }}")],
            failures,
        );
    }
    check_exact_outputs(workflow, "verify", &[], failures);
    check_checkout_set(
        workflow,
        "plan",
        &[
            (None, "${{ github.sha }}", "automation"),
            (None, "${{ github.sha }}", "candidate"),
        ],
        failures,
    );
    for job in ["linux", "macos", "windows"] {
        check_checkout_set(
            workflow,
            job,
            &[
                (None, "${{ github.sha }}", "automation"),
                (None, "${{ github.sha }}", "candidate"),
                (
                    Some("chrisdone/hell"),
                    "8e952cf9de4ab25d7716982a9ca234f9bdcf1bff",
                    "oracle-source",
                ),
            ],
            failures,
        );
    }
    check_checkout_set(
        workflow,
        "verify",
        &[((None), "${{ github.sha }}", "automation")],
        failures,
    );
    for job in ["plan", "linux", "macos", "windows", "verify"] {
        if let Some(job) = workflow.jobs.get(job) {
            check_release_checkouts(
                job.name.as_ref().and_then(Value::as_str).unwrap_or("CI"),
                job,
                failures,
            );
        }
    }
    check_exact_command(
        workflow,
        "plan",
        READINESS_PLAN_COMMAND,
        "the exact candidate-bound readiness plan",
        failures,
    );
    let plan_steps = workflow
        .jobs
        .get("plan")
        .and_then(|job| job.steps.as_deref())
        .unwrap_or_default();
    if plan_steps
        .iter()
        .filter(|step| {
            scalar(step.id.as_ref()) == Some("plan")
                && step.run.as_deref() == Some(READINESS_PLAN_COMMAND)
        })
        .count()
        != 1
    {
        failures.push("CI plan outputs must originate from the exact readiness planner".to_owned());
    }
    for (job, platform, command, gates) in [
        (
            "linux",
            "linux-x86_64",
            READINESS_LINUX_COMMAND,
            &LINUX_GATES[..],
        ),
        (
            "macos",
            "macos-aarch64",
            READINESS_MACOS_COMMAND,
            &NATIVE_GATES[..],
        ),
        (
            "windows",
            "windows-x86_64",
            READINESS_WINDOWS_COMMAND,
            &NATIVE_GATES[..],
        ),
    ] {
        check_readiness_platform_job(workflow, job, platform, command, gates, failures);
    }
    check_exact_command(
        workflow,
        "verify",
        READINESS_VERIFY_COMMAND,
        "the exact blocker-zero readiness reconstruction",
        failures,
    );
    for (job, path) in [
        ("plan", "readiness-plan"),
        ("linux", "platform-out"),
        ("macos", "platform-out"),
        ("windows", "platform-out"),
    ] {
        check_exact_upload(workflow, job, path, failures);
    }
    for (job, expression, path) in [
        (
            "linux",
            "${{ needs.plan.outputs.artifact_id }}",
            "readiness-input",
        ),
        (
            "macos",
            "${{ needs.plan.outputs.artifact_id }}",
            "readiness-input",
        ),
        (
            "windows",
            "${{ needs.plan.outputs.artifact_id }}",
            "readiness-input",
        ),
        (
            "verify",
            "${{ needs.plan.outputs.artifact_id }}",
            "readiness-input/plan",
        ),
        (
            "verify",
            "${{ needs.linux.outputs.artifact_id }}",
            "readiness-input/platforms/linux-x86_64",
        ),
        (
            "verify",
            "${{ needs.macos.outputs.artifact_id }}",
            "readiness-input/platforms/macos-aarch64",
        ),
        (
            "verify",
            "${{ needs.windows.outputs.artifact_id }}",
            "readiness-input/platforms/windows-x86_64",
        ),
    ] {
        check_exact_download(workflow, job, "readiness", expression, path, failures);
    }
    let readiness_decisions = workflow
        .jobs
        .get("verify")
        .and_then(|job| job.steps.as_deref())
        .unwrap_or_default()
        .iter()
        .filter(|step| {
            step.uses.as_deref().and_then(action_name) == Some("actions/upload-artifact")
                && scalar(step.condition.as_ref()) == Some("${{ always() }}")
                && with_scalar(step, "path") == Some("readiness-result")
                && with_scalar(step, "if-no-files-found") == Some("ignore")
        })
        .count();
    if readiness_decisions != 1 {
        failures.push("CI must retain the exact readiness decision under always()".to_owned());
    }
    check_readiness_caches(workflow, failures);
    if workflow_contains_text(workflow, &|value| {
        [
            "workflow_dispatch",
            "release plan",
            "release assemble",
            "release verify-bundle",
            "release stage-attestations",
            "release publish",
            "actions/attest",
            "candidate_branch",
        ]
        .iter()
        .any(|forbidden| value.contains(forbidden))
    }) {
        failures.push(
            "CI readiness must not perform release-intent, attestation, or publication operations"
                .to_owned(),
        );
    }
}

fn check_ci_gate_inventory(workflow: &Workflow, failures: &mut Vec<String>) {
    const RUSTUP_SHOW: &str = "rustup show active-toolchain";
    const DOWNLOAD_ACTION: &str = "actions/download-artifact";
    const UPLOAD_ACTION: &str = "actions/upload-artifact";
    const SETUP_HASKELL_ACTION: &str = "haskell-actions/setup";

    for (job_name, expected_commands, expected_actions) in [
        (
            "plan",
            vec![RUSTUP_SHOW, BUILD_DRIVER_COMMAND, READINESS_PLAN_COMMAND],
            vec![
                CHECKOUT_ACTION,
                CHECKOUT_ACTION,
                CACHE_RESTORE_ACTION,
                CACHE_RESTORE_ACTION,
                UPLOAD_ACTION,
                CACHE_SAVE_ACTION,
                CACHE_SAVE_ACTION,
            ],
        ),
        (
            "linux",
            vec![
                RUSTUP_SHOW,
                CARGO_DENY_INSTALL_COMMAND,
                BUILD_DRIVER_AND_HELPER_COMMAND,
                READINESS_LINUX_COMMAND,
            ],
            vec![
                CHECKOUT_ACTION,
                CHECKOUT_ACTION,
                CHECKOUT_ACTION,
                DOWNLOAD_ACTION,
                SETUP_HASKELL_ACTION,
                CACHE_RESTORE_ACTION,
                CACHE_RESTORE_ACTION,
                CACHE_RESTORE_ACTION,
                CACHE_RESTORE_ACTION,
                UPLOAD_ACTION,
                CACHE_SAVE_ACTION,
                CACHE_SAVE_ACTION,
                CACHE_SAVE_ACTION,
                CACHE_SAVE_ACTION,
            ],
        ),
        (
            "macos",
            vec![
                RUSTUP_SHOW,
                MACOS_LLVM_COMMAND,
                BUILD_DRIVER_AND_HELPER_COMMAND,
                READINESS_MACOS_COMMAND,
            ],
            vec![
                CHECKOUT_ACTION,
                CHECKOUT_ACTION,
                CHECKOUT_ACTION,
                DOWNLOAD_ACTION,
                SETUP_HASKELL_ACTION,
                CACHE_RESTORE_ACTION,
                CACHE_RESTORE_ACTION,
                CACHE_RESTORE_ACTION,
                UPLOAD_ACTION,
                CACHE_SAVE_ACTION,
                CACHE_SAVE_ACTION,
                CACHE_SAVE_ACTION,
            ],
        ),
        (
            "windows",
            vec![
                RUSTUP_SHOW,
                BUILD_DRIVER_AND_HELPER_COMMAND,
                READINESS_WINDOWS_COMMAND,
            ],
            vec![
                CHECKOUT_ACTION,
                CHECKOUT_ACTION,
                CHECKOUT_ACTION,
                DOWNLOAD_ACTION,
                SETUP_HASKELL_ACTION,
                CACHE_RESTORE_ACTION,
                CACHE_RESTORE_ACTION,
                CACHE_RESTORE_ACTION,
                UPLOAD_ACTION,
                CACHE_SAVE_ACTION,
                CACHE_SAVE_ACTION,
                CACHE_SAVE_ACTION,
            ],
        ),
        (
            "verify",
            vec![BUILD_DRIVER_COMMAND, READINESS_VERIFY_COMMAND],
            vec![
                CHECKOUT_ACTION,
                DOWNLOAD_ACTION,
                DOWNLOAD_ACTION,
                DOWNLOAD_ACTION,
                DOWNLOAD_ACTION,
                CACHE_RESTORE_ACTION,
                CACHE_RESTORE_ACTION,
                UPLOAD_ACTION,
                CACHE_SAVE_ACTION,
                CACHE_SAVE_ACTION,
            ],
        ),
    ] {
        let steps = workflow
            .jobs
            .get(job_name)
            .and_then(|job| job.steps.as_deref())
            .unwrap_or_default();
        let actual_commands = steps
            .iter()
            .filter_map(|step| step.run.as_deref())
            .collect::<Vec<_>>();
        if actual_commands != expected_commands {
            failures.push(format!(
                "CI job {job_name:?} must run the exact ordered local-reproducible gate inventory"
            ));
        }
        let actual_actions = steps
            .iter()
            .filter_map(|step| step.uses.as_deref().and_then(action_name))
            .collect::<Vec<_>>();
        if actual_actions != expected_actions {
            failures.push(format!(
                "CI job {job_name:?} must use the exact ordered action inventory"
            ));
        }
    }
}

fn check_readiness_platform_job(
    workflow: &Workflow,
    job_name: &str,
    platform: &str,
    expected_command: &str,
    expected_gates: &[&str],
    failures: &mut Vec<String>,
) {
    let commands = workflow
        .jobs
        .get(job_name)
        .and_then(|job| job.steps.as_deref())
        .unwrap_or_default()
        .iter()
        .filter_map(|step| step.run.as_deref())
        .filter(|command| {
            option_value(command, "--platform") == Some(platform)
                && command_tokens(command)
                    .windows(2)
                    .any(|tokens| tokens == ["readiness", "platform"])
        })
        .collect::<Vec<_>>();
    if commands != [expected_command] {
        failures.push(format!(
            "CI job {job_name:?} must invoke the exact {platform} readiness driver"
        ));
        return;
    }
    if job_name == "linux"
        && workflow
            .jobs
            .get(job_name)
            .and_then(|job| job.steps.as_deref())
            .unwrap_or_default()
            .iter()
            .filter_map(|step| step.run.as_deref())
            .filter(|command| *command == CARGO_DENY_INSTALL_COMMAND)
            .count()
            != 1
    {
        failures.push(
            "CI Linux readiness must rebuild pinned cargo-deny with its dedicated compilation cache"
                .to_owned(),
        );
    }
    let actual_gates = option_value(commands[0], "--required-gates")
        .map(|value| value.split(',').collect::<Vec<_>>())
        .unwrap_or_default();
    if actual_gates != expected_gates {
        failures.push(format!(
            "CI job {job_name:?} readiness gates must be exactly {expected_gates:?}, found {actual_gates:?}"
        ));
    }
}

fn check_readiness_caches(workflow: &Workflow, failures: &mut Vec<String>) {
    const CANDIDATE_TARGET_INPUTS: [&str; 15] = [
        "candidate/rust-toolchain.toml",
        "candidate/Cargo.lock",
        "candidate/Cargo.toml",
        "candidate/crates/**/Cargo.toml",
        "candidate/**/build.rs",
        "candidate/.cargo/**",
        "candidate/crates/**/*.rs",
        "candidate/builtins/**",
        "candidate/compat/**",
        "candidate/fixtures/**",
        "candidate/baseline.toml",
        "candidate/deny.toml",
        "candidate/release-policy.toml",
        "candidate/spec/**",
        "candidate/.github/**",
    ];
    const AUTOMATION_TARGET_INPUTS: [&str; 15] = [
        "automation/rust-toolchain.toml",
        "automation/Cargo.lock",
        "automation/Cargo.toml",
        "automation/crates/**/Cargo.toml",
        "automation/**/build.rs",
        "automation/.cargo/**",
        "automation/crates/**/*.rs",
        "automation/builtins/**",
        "automation/compat/**",
        "automation/fixtures/**",
        "automation/baseline.toml",
        "automation/deny.toml",
        "automation/release-policy.toml",
        "automation/spec/**",
        "automation/.github/**",
    ];
    for (job_name, job) in &workflow.jobs {
        let steps = job.steps.as_deref().unwrap_or_default();
        let restores = cache_steps(steps, CACHE_RESTORE_ACTION);
        let saves = cache_steps(steps, CACHE_SAVE_ACTION);
        let restore_keys = restores
            .iter()
            .filter_map(|step| with_scalar(step, "key"))
            .collect::<Vec<_>>();
        let save_keys = saves
            .iter()
            .filter_map(|step| with_scalar(step, "key"))
            .collect::<Vec<_>>();
        let expected_pairs = match job_name.as_str() {
            "linux" => 4,
            "macos" | "windows" => 3,
            _ => 2,
        };
        if restores.len() != expected_pairs
            || saves.len() != expected_pairs
            || restore_keys != save_keys
        {
            failures.push(format!(
                "CI readiness job {job_name:?} must have its exact split cache pairs"
            ));
        }
        for restore in restores {
            if with_scalar(restore, "restore-keys").is_some() {
                failures.push(format!(
                    "CI readiness job {job_name:?} must not use fallback cache keys"
                ));
            }
            let path = with_scalar(restore, "path").unwrap_or_default();
            let key = with_scalar(restore, "key").unwrap_or_default();
            let required = match path {
                "candidate-target" => &CANDIDATE_TARGET_INPUTS[..],
                "automation/target" => &AUTOMATION_TARGET_INPUTS[..],
                _ => continue,
            };
            let exact_candidate_sha = key.contains("${{ github.sha }}");
            if (path == "automation/target" && exact_candidate_sha)
                || required.iter().all(|input| key.contains(input))
            {
                continue;
            }
            if required.iter().any(|input| !key.contains(input)) {
                failures.push(format!(
                    "CI readiness job {job_name:?} compilation cache omits a build input"
                ));
            }
        }
    }
}

fn check_push_only_triggers(
    path: &Path,
    triggers: &Mapping,
    requires_paths: bool,
    failures: &mut Vec<String>,
) {
    let actual = mapping_keys(triggers);
    if actual != BTreeSet::from(["push"]) {
        failures.push(format!(
            "{} must use only a direct push trigger, found {actual:?}",
            path.display()
        ));
    }
    check_all_branch_push(
        get(triggers, "push"),
        requires_paths,
        &path.display().to_string(),
        failures,
    );
}

fn check_all_branch_push(
    push: Option<&Value>,
    requires_paths: bool,
    owner: &str,
    failures: &mut Vec<String>,
) {
    let Some(push) = push.and_then(mapping) else {
        failures.push(format!("{owner} push trigger must be a mapping"));
        return;
    };
    let expected = if requires_paths {
        BTreeSet::from(["branches", "paths", "tags-ignore"])
    } else {
        BTreeSet::from(["branches", "tags-ignore"])
    };
    let actual = mapping_keys(push);
    if actual != expected
        || string_sequence(get(push, "branches")) != Some(vec!["**"])
        || string_sequence(get(push, "tags-ignore")) != Some(vec!["**"])
        || (requires_paths
            && string_sequence(get(push, "paths")) != Some(REGRESSION_CORPUS_PATHS.to_vec()))
    {
        failures.push(format!(
            "{owner} push trigger must cover every branch, exclude tags, and have only its allowed filters"
        ));
    }
}

fn check_exact_push_checkouts(path: &Path, workflow: &Workflow, failures: &mut Vec<String>) {
    for (job_name, job) in &workflow.jobs {
        for step in job
            .steps
            .as_deref()
            .unwrap_or_default()
            .iter()
            .filter(|step| {
                step.uses.as_deref().and_then(action_name) == Some(CHECKOUT_ACTION)
                    && with_scalar(step, "repository").is_none()
            })
        {
            if with_scalar(step, "ref") != Some("${{ github.sha }}") {
                failures.push(format!(
                    "{} job {job_name:?} must check out the exact direct-event github.sha",
                    path.display()
                ));
            }
        }
    }
}

fn mapping_keys(mapping: &Mapping) -> BTreeSet<&str> {
    mapping.keys().filter_map(Value::as_str).collect()
}

fn string_sequence(value: Option<&Value>) -> Option<Vec<&str>> {
    value?.as_sequence()?.iter().map(Value::as_str).collect()
}

fn check_nightly(workflow: &Workflow, failures: &mut Vec<String>) {
    let pinned_cargo_deny_installs = workflow
        .jobs
        .get("linux")
        .and_then(|job| job.steps.as_deref())
        .unwrap_or_default()
        .iter()
        .filter_map(|step| step.run.as_deref())
        .filter(|command| *command == NIGHTLY_CARGO_DENY_INSTALL_COMMAND)
        .count();
    if pinned_cargo_deny_installs != 1 {
        failures.push(format!(
            "nightly Linux must install exact pinned cargo-deny once, found {pinned_cargo_deny_installs}"
        ));
    }
    let acquisitions = workflow
        .jobs
        .values()
        .flat_map(|job| job.steps.as_deref().unwrap_or_default())
        .filter_map(|step| step.run.as_deref())
        .filter(|command| *command == NIGHTLY_ORACLE_ACQUIRE)
        .count();
    if acquisitions != 1 {
        failures.push(format!(
            "nightly must invoke the bounded automatic oracle acquisition exactly once, found {acquisitions}"
        ));
    }
    let divergence_prototypes = workflow
        .jobs
        .values()
        .flat_map(|job| job.steps.as_deref().unwrap_or_default())
        .filter_map(|step| step.run.as_deref())
        .filter(|command| *command == NIGHTLY_DIVERGENCE_PROTOTYPES)
        .count();
    if divergence_prototypes != 1 {
        failures.push(format!(
            "nightly must invoke the live divergence prototype gate exactly once, found {divergence_prototypes}"
        ));
    }
    let commands = workflow
        .jobs
        .get("linux")
        .and_then(|job| job.steps.as_deref())
        .unwrap_or_default()
        .iter()
        .filter_map(|step| step.run.as_deref())
        .collect::<Vec<_>>();
    let producers = commands
        .iter()
        .enumerate()
        .filter(|(_, command)| **command == NIGHTLY_REGRESSION_PRODUCER)
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    let consumers = commands
        .iter()
        .enumerate()
        .filter(|(_, command)| **command == NIGHTLY_REGRESSION_CONSUMER)
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if producers.len() != 1 || consumers.len() != 1 || producers[0] >= consumers[0] {
        failures.push(
            "nightly Linux must run the exact bounded regression producer once before its exact consumer"
                .to_owned(),
        );
    }
}

fn check_push_gate_inventory(path: &str, workflow: &Workflow, failures: &mut Vec<String>) {
    const INSTALL_NIGHTLY: &str = "rustup toolchain install nightly-2026-07-31 --profile minimal";
    const INSTALL_FUZZ: &str = "cargo +nightly-2026-07-31 install cargo-fuzz --version 0.13.2 --locked --force --target-dir ci-tool-cache/cargo-fuzz-target";

    let expected = match path {
        MUTATION_PATH => vec![("mutation", vec![BUILD_DRIVER_COMMAND, MUTATION_RUN_COMMAND])],
        REGRESSION_CORPUS_PATH | REGRESSION_SUBJECT_PATH => vec![(
            "validate",
            vec![REGRESSION_TYPED_CORPUS_COMMAND, REGRESSION_ORACLE_COMMAND],
        )],
        NIGHTLY_PATH => vec![
            (
                "linux",
                vec![
                    NIGHTLY_CARGO_DENY_INSTALL_COMMAND,
                    BUILD_DRIVER_AND_HELPER_COMMAND,
                    BUILD_DEBUG_CANDIDATE_COMMAND,
                    NIGHTLY_DEPENDENCY_COMMAND,
                    NIGHTLY_ORACLE_ACQUIRE,
                    NIGHTLY_REGRESSION_PRODUCER,
                    NIGHTLY_REGRESSION_CONSUMER,
                    NIGHTLY_DIVERGENCE_PROTOTYPES,
                ],
            ),
            (
                "fuzz",
                vec![
                    INSTALL_NIGHTLY,
                    INSTALL_FUZZ,
                    BUILD_DRIVER_COMMAND,
                    FUZZ_PREPARE_COMMAND,
                    FUZZ_REQUIREMENT_COMMAND,
                    FUZZ_NORMALIZER_COMMAND,
                    FUZZ_DIVERGENCE_COMMAND,
                    FUZZ_REPLAY_COMMAND,
                    FUZZ_TRACE_COMMAND,
                    FUZZ_VERIFY_COMMAND,
                ],
            ),
            (
                "macos",
                vec![
                    MACOS_LLVM_COMMAND,
                    BUILD_DRIVER_AND_HELPER_COMMAND,
                    BUILD_RELEASE_CANDIDATE_COMMAND,
                    NIGHTLY_MACOS_PORTABILITY_COMMAND,
                    NIGHTLY_DEPENDENCY_COMMAND,
                    NIGHTLY_MACOS_ORACLE_COMMAND,
                ],
            ),
            (
                "windows",
                vec![
                    BUILD_DRIVER_AND_HELPER_COMMAND,
                    BUILD_RELEASE_CANDIDATE_COMMAND,
                    NIGHTLY_WINDOWS_PORTABILITY_COMMAND,
                    NIGHTLY_WINDOWS_DEPENDENCY_COMMAND,
                    NIGHTLY_WINDOWS_ORACLE_COMMAND,
                ],
            ),
        ],
        _ => return,
    };
    let expected_jobs = expected
        .iter()
        .map(|(job, _)| *job)
        .collect::<BTreeSet<_>>();
    let actual_jobs = workflow
        .jobs
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if actual_jobs != expected_jobs {
        failures.push(format!(
            "{path} push gate jobs must be exactly {expected_jobs:?}, found {actual_jobs:?}"
        ));
    }
    for (job_name, expected_commands) in expected {
        let expected_actions = match (path, job_name) {
            (MUTATION_PATH, "mutation") => vec![
                CHECKOUT_ACTION,
                CACHE_RESTORE_ACTION,
                CACHE_RESTORE_ACTION,
                "actions/upload-artifact",
                CACHE_SAVE_ACTION,
                CACHE_SAVE_ACTION,
            ],
            (REGRESSION_CORPUS_PATH | REGRESSION_SUBJECT_PATH, "validate") => vec![
                CHECKOUT_ACTION,
                CACHE_RESTORE_ACTION,
                CACHE_RESTORE_ACTION,
                CACHE_SAVE_ACTION,
                CACHE_SAVE_ACTION,
            ],
            (NIGHTLY_PATH, "linux") => vec![
                CHECKOUT_ACTION,
                CACHE_RESTORE_ACTION,
                CACHE_RESTORE_ACTION,
                "actions/upload-artifact",
                CACHE_SAVE_ACTION,
                CACHE_SAVE_ACTION,
            ],
            (NIGHTLY_PATH, "fuzz") => vec![
                CHECKOUT_ACTION,
                CACHE_RESTORE_ACTION,
                CACHE_RESTORE_ACTION,
                CACHE_RESTORE_ACTION,
                CACHE_RESTORE_ACTION,
                "actions/upload-artifact",
                "actions/upload-artifact",
                CACHE_SAVE_ACTION,
                CACHE_SAVE_ACTION,
                CACHE_SAVE_ACTION,
                CACHE_SAVE_ACTION,
            ],
            (NIGHTLY_PATH, "macos" | "windows") => vec![
                CHECKOUT_ACTION,
                CHECKOUT_ACTION,
                "haskell-actions/setup",
                CACHE_RESTORE_ACTION,
                CACHE_RESTORE_ACTION,
                CACHE_RESTORE_ACTION,
                "actions/upload-artifact",
                CACHE_SAVE_ACTION,
                CACHE_SAVE_ACTION,
                CACHE_SAVE_ACTION,
            ],
            _ => Vec::new(),
        };
        let actual_actions = workflow
            .jobs
            .get(job_name)
            .and_then(|job| job.steps.as_deref())
            .unwrap_or_default()
            .iter()
            .filter_map(|step| step.uses.as_deref().and_then(action_name))
            .collect::<Vec<_>>();
        if actual_actions != expected_actions {
            failures.push(format!(
                "{path} job {job_name:?} must use the exact ordered action inventory"
            ));
        }
        let actual_commands = workflow
            .jobs
            .get(job_name)
            .and_then(|job| job.steps.as_deref())
            .unwrap_or_default()
            .iter()
            .filter_map(|step| step.run.as_deref())
            .collect::<Vec<_>>();
        if actual_commands != expected_commands {
            failures.push(format!(
                "{path} job {job_name:?} must run the exact ordered local-reproducible gate inventory"
            ));
        }
        let checkout_set = match (path, job_name) {
            (NIGHTLY_PATH, "macos" | "windows") => vec![
                (None, "${{ github.sha }}", ""),
                (
                    Some("chrisdone/hell"),
                    "8e952cf9de4ab25d7716982a9ca234f9bdcf1bff",
                    "oracle-source",
                ),
            ],
            _ => vec![(None, "${{ github.sha }}", "")],
        };
        check_checkout_set(workflow, job_name, &checkout_set, failures);
    }
}

fn check_push_cache_pairs(path: &str, workflow: &Workflow, failures: &mut Vec<String>) {
    for (job_name, job) in &workflow.jobs {
        let steps = job.steps.as_deref().unwrap_or_default();
        let restores = cache_steps(steps, CACHE_RESTORE_ACTION);
        let saves = cache_steps(steps, CACHE_SAVE_ACTION);
        let restore_pairs = restores
            .iter()
            .map(|step| {
                (
                    with_scalar(step, "path").unwrap_or_default(),
                    with_scalar(step, "key").unwrap_or_default(),
                )
            })
            .collect::<Vec<_>>();
        let save_pairs = saves
            .iter()
            .map(|step| {
                (
                    with_scalar(step, "path").unwrap_or_default(),
                    with_scalar(step, "key").unwrap_or_default(),
                )
            })
            .collect::<Vec<_>>();
        if restore_pairs.is_empty() || restore_pairs != save_pairs {
            failures.push(format!(
                "{path} job {job_name:?} must have exact split cache restore/save pairs"
            ));
        }
        if restores
            .iter()
            .any(|step| with_scalar(step, "restore-keys").is_some())
        {
            failures.push(format!(
                "{path} job {job_name:?} must not use fallback cache keys"
            ));
        }
        if path == NIGHTLY_PATH && job_name == "macos" {
            let stack_cache = restores
                .iter()
                .find(|step| scalar(step.id.as_ref()) == Some("stack-cache"));
            let stack_path = stack_cache.and_then(|step| with_scalar(step, "path"));
            let stack_key = stack_cache
                .and_then(|step| with_scalar(step, "key"))
                .unwrap_or_default();
            let required_identity = [
                "${{ runner.os }}",
                "${{ runner.arch }}",
                "stack-3.11.1",
                "ghc-9.8.2",
                "llvm-18.1.8",
                "oracle-8e952cf9de4ab25d7716982a9ca234f9bdcf1bff",
                "oracle-source/stack.yaml",
                "oracle-source/stack.yaml.lock",
                "oracle-source/package.yaml",
                "oracle-source/hell.cabal",
                "oracle-source/src/**",
                "crates/hell-ci/src/command.rs",
            ];
            if stack_path != Some("${{ steps.setup-stack.outputs.stack-root }}")
                || required_identity
                    .iter()
                    .any(|identity| !stack_key.contains(identity))
            {
                failures.push(
                    "nightly macOS Stack-root cache must bind the exact native toolchain, overlay, and oracle inputs"
                        .to_owned(),
                );
            }
        }
        let mut ids = BTreeSet::new();
        for (restore, save) in restores.iter().zip(&saves) {
            let id = scalar(restore.id.as_ref()).unwrap_or_default();
            let expected_condition = format!(
                "${{{{ always() && steps.{id}.outcome == 'success' && steps.{id}.outputs.cache-hit != 'true' }}}}"
            );
            if id.is_empty()
                || !ids.insert(id)
                || restore.condition.is_some()
                || scalar(save.condition.as_ref()) != Some(&expected_condition)
            {
                failures.push(format!(
                    "{path} job {job_name:?} cache pairs must use unique restore ids and exact always-save predicates"
                ));
            }
        }
        const BUILD_INPUTS: [&str; 15] = [
            "rust-toolchain.toml",
            "Cargo.lock",
            "Cargo.toml",
            "crates/**/Cargo.toml",
            "**/build.rs",
            ".cargo/**",
            "crates/**/*.rs",
            "builtins/**",
            "compat/**",
            "fixtures/**",
            "baseline.toml",
            "deny.toml",
            "release-policy.toml",
            "spec/**",
            ".github/**",
        ];
        for (cache_path, key) in restore_pairs {
            if matches!(cache_path, "target" | "crates/hell-ci/fuzz/target")
                && BUILD_INPUTS.iter().any(|input| !key.contains(input))
            {
                failures.push(format!(
                    "{path} job {job_name:?} compilation cache omits a build input"
                ));
            }
            if cache_path == "crates/hell-ci/fuzz/target" && !key.contains("crates/hell-ci/fuzz/**")
            {
                failures.push(format!(
                    "{path} job {job_name:?} fuzz compilation cache omits its crate inputs"
                ));
            }
        }
    }
}

fn check_common(path: &Path, workflow: &Workflow, failures: &mut Vec<String>) {
    touch_workflow_fields(workflow);
    check_environment_contract(path, workflow, failures);
    if path != Path::new(RELEASE_PATH) && has_write_permission(workflow.permissions.as_ref()) {
        failures.push(format!(
            "{} has release write permission at workflow scope",
            path.display()
        ));
    }
    for (job_name, job) in &workflow.jobs {
        touch_job_fields(job);
        if path != Path::new(RELEASE_PATH) && job.condition.is_some() {
            failures.push(format!(
                "{} job {job_name:?} must not conditionally skip a required event",
                path.display()
            ));
        }
        if let Some(action) = job.uses.as_ref().and_then(Value::as_str) {
            check_action_pin(path, job_name, action, failures);
        }
        if path != Path::new(RELEASE_PATH) && has_write_permission(job.permissions.as_ref()) {
            failures.push(format!(
                "{} job {job_name:?} has release write permission",
                path.display()
            ));
        }
        if path == Path::new(RELEASE_PATH) && job.secrets.is_some() {
            failures.push(format!(
                "release job {job_name:?} must not declare a secrets contract"
            ));
        }
        for step in job.steps.as_deref().unwrap_or_default() {
            touch_step_fields(step);
            if step.run.is_some()
                && step.condition.is_some()
                && !(path == Path::new(NIGHTLY_PATH)
                    && job_name == "fuzz"
                    && step.run.as_deref() == Some(FUZZ_VERIFY_COMMAND)
                    && scalar(step.condition.as_ref()) == Some("${{ always() }}"))
            {
                failures.push(format!(
                    "{} job {job_name:?} conditionally skips a required run command",
                    path.display()
                ));
            }
            if step.shell.is_some() {
                failures.push(format!(
                    "{} job {job_name:?} declares an explicit shell",
                    path.display()
                ));
            }
            if step.continue_on_error.is_some() {
                failures.push(format!(
                    "{} job {job_name:?} must not use continue-on-error",
                    path.display()
                ));
            }
            if let Some(command) = &step.run {
                check_run(path, job_name, command, failures);
                let tokens = command_tokens(command);
                if RETIRED_AUTHORITY_COMMANDS
                    .iter()
                    .any(|retired| tokens.contains(retired))
                {
                    failures.push(format!(
                        "{} job {job_name:?} invokes retired assurance authority",
                        path.display()
                    ));
                }
            }
            if let Some(action) = &step.uses {
                check_action_pin(path, job_name, action, failures);
                if step.condition.is_some()
                    && !match action_name(action) {
                        Some(CACHE_SAVE_ACTION) => {
                            scalar(step.condition.as_ref()).is_some_and(valid_cache_save_condition)
                        }
                        Some("actions/upload-artifact") => {
                            scalar(step.condition.as_ref()) == Some("${{ always() }}")
                        }
                        _ => false,
                    }
                {
                    failures.push(format!(
                        "{} job {job_name:?} conditionally skips a required action",
                        path.display()
                    ));
                }
                if action_name(action) == Some("actions/attest")
                    && (path != Path::new(RELEASE_PATH) || job_name != "publish")
                {
                    failures.push(format!(
                        "{} job {job_name:?} must not create attestations",
                        path.display()
                    ));
                }
                if action_name(action) == Some("sigstore/cosign-installer") {
                    failures.push(format!(
                        "{} job {job_name:?} installs the retired review verifier",
                        path.display()
                    ));
                }
                if action_name(action) == Some(CACHE_SAVE_ACTION)
                    && scalar(step.condition.as_ref())
                        .is_none_or(|condition| !valid_cache_save_condition(condition))
                {
                    failures.push(format!(
                        "{} job {job_name:?} cache save is not guarded by always()",
                        path.display()
                    ));
                }
            }
        }
    }
}

fn valid_cache_save_condition(condition: &str) -> bool {
    const PREFIX: &str = "${{ always() && steps.";
    const SUFFIX: &str = ".outcome == 'success' && steps.";
    const END: &str = ".outputs.cache-hit != 'true' }}";
    let Some(remainder) = condition.strip_prefix(PREFIX) else {
        return false;
    };
    let Some((first, remainder)) = remainder.split_once(SUFFIX) else {
        return false;
    };
    let Some(second) = remainder.strip_suffix(END) else {
        return false;
    };
    !first.is_empty()
        && first == second
        && first
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn check_environment_contract(path: &Path, workflow: &Workflow, failures: &mut Vec<String>) {
    if workflow.env.is_some() {
        failures.push(format!(
            "{} must not define workflow-level environment variables",
            path.display()
        ));
    }

    for (job_name, job) in &workflow.jobs {
        if job.env.is_some() {
            failures.push(format!(
                "{} job {job_name:?} must not define job-level environment variables",
                path.display()
            ));
        }
        for step in job.steps.as_deref().unwrap_or_default() {
            let Some(environment) = step.env.as_ref() else {
                continue;
            };
            let allowed = path == Path::new(RELEASE_PATH)
                && exact_github_token_environment(environment)
                && step.uses.is_none()
                && step.condition.is_none()
                && step.working_directory.is_none()
                && step.run.as_deref().is_some_and(|command| {
                    TOKEN_STEPS
                        .iter()
                        .any(|allowed| allowed.job == job_name && allowed.command == command)
                });
            if !allowed {
                failures.push(format!(
                    "{} job {job_name:?} has a forbidden step environment mapping",
                    path.display()
                ));
            }
        }
    }

    if path == Path::new(RELEASE_PATH) {
        for allowed in &TOKEN_STEPS {
            let count = workflow
                .jobs
                .get(allowed.job)
                .and_then(|job| job.steps.as_deref())
                .unwrap_or_default()
                .iter()
                .filter(|step| {
                    step.run.as_deref() == Some(allowed.command)
                        && step
                            .env
                            .as_ref()
                            .is_some_and(exact_github_token_environment)
                        && step.uses.is_none()
                        && step.condition.is_none()
                        && step.working_directory.is_none()
                })
                .count();
            if count != 1 {
                failures.push(format!(
                    "release job {:?} must expose the automatic GitHub token to the exact trusted command once, found {count}",
                    allowed.job
                ));
            }
        }
    }

    let retired_plumbing = [
        "HELL_",
        "CARGO_TERM_COLOR",
        "GITHUB_ENV",
        "steps.provenance.outputs.bundle-path",
        "steps.gate.outputs.bundle-path",
    ];
    if retired_plumbing
        .iter()
        .any(|needle| workflow_contains_text(workflow, &|value| value.contains(needle)))
    {
        failures.push(format!(
            "{} contains retired environment-variable plumbing",
            path.display()
        ));
    }
    if path == Path::new(RELEASE_PATH)
        && workflow_contains_text(workflow, &|value| {
            value.to_ascii_lowercase().contains("vars.")
        })
    {
        failures
            .push("release workflow must not reference repository or organization vars".to_owned());
    }
    if path == Path::new(RELEASE_PATH)
        && workflow_contains_text(workflow, &|value| {
            value.to_ascii_lowercase().contains("secrets.")
        })
    {
        failures.push(
            "release workflow must not reference repository or organization secrets".to_owned(),
        );
    }
    if path == Path::new(RELEASE_PATH) {
        let occurrences = workflow_text_occurrence_count(workflow, GITHUB_TOKEN_EXPRESSION);
        if occurrences != TOKEN_STEPS.len() {
            failures.push(format!(
                "release workflow must contain the automatic GitHub token expression exactly {} times in approved step environments, found {occurrences}",
                TOKEN_STEPS.len()
            ));
        }
    }
}

fn exact_github_token_environment(environment: &Value) -> bool {
    environment.as_mapping().is_some_and(|values| {
        values.len() == 1 && scalar(get(values, "GITHUB_TOKEN")) == Some(GITHUB_TOKEN_EXPRESSION)
    })
}

#[allow(clippy::too_many_lines)]
fn check_release(workflow: &Workflow, failures: &mut Vec<String>) {
    check_release_trigger(&workflow.triggers, failures);
    check_exact_permissions(
        workflow.permissions.as_ref(),
        &[("actions", "read"), ("contents", "read")],
        "release workflow default",
        failures,
    );
    let required_jobs = [
        "resolve", "linux", "macos", "windows", "assemble", "publish",
    ];
    let actual_jobs = workflow
        .jobs
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let required_job_set = required_jobs.into_iter().collect::<BTreeSet<_>>();
    if actual_jobs != required_job_set {
        failures.push(format!(
            "release workflow jobs must be exactly {required_job_set:?}, found {actual_jobs:?}"
        ));
    }
    check_needs(workflow, "resolve", &[], failures);
    for job in ["linux", "macos", "windows"] {
        check_needs(workflow, job, &["resolve"], failures);
    }
    check_needs(
        workflow,
        "assemble",
        &["resolve", "linux", "macos", "windows"],
        failures,
    );
    check_needs(workflow, "publish", &["resolve", "assemble"], failures);
    for (job_name, runner) in [
        ("resolve", "ubuntu-24.04"),
        ("linux", "ubuntu-24.04"),
        ("macos", "macos-15"),
        ("windows", "windows-2025"),
        ("assemble", "ubuntu-24.04"),
        ("publish", "ubuntu-24.04"),
    ] {
        if workflow
            .jobs
            .get(job_name)
            .and_then(|job| job.runs_on.as_ref())
            .and_then(Value::as_str)
            != Some(runner)
        {
            failures.push(format!(
                "release job {job_name:?} runner must be exactly {runner:?}"
            ));
        }
    }
    let cargo_deny_installs = workflow
        .jobs
        .get("linux")
        .and_then(|job| job.steps.as_deref())
        .unwrap_or_default()
        .iter()
        .filter_map(|step| step.run.as_deref())
        .filter(|command| *command == CARGO_DENY_INSTALL_COMMAND)
        .count();
    if cargo_deny_installs != 1 {
        failures.push(
            "release Linux must rebuild pinned cargo-deny with its dedicated compilation cache"
                .to_owned(),
        );
    }
    if release_workflow_has_forbidden_authority(workflow) {
        failures.push(
            "release workflow must not reference secrets, AWS, SSH, deploy keys, PATs, or self-hosted authority"
                .to_owned(),
        );
    }
    if release_workflow_has_legacy_bounded_contract(workflow) {
        failures.push(
            "release workflow must not retain a bounded-policy gate, asset, or v1 predicate"
                .to_owned(),
        );
    }
    check_exact_outputs(
        workflow,
        "resolve",
        &[
            (
                "candidate_sha",
                "${{ steps.resolve.outputs.candidate_sha }}",
            ),
            ("version", "${{ steps.plan.outputs.version }}"),
            ("tag", "${{ steps.plan.outputs.tag }}"),
            ("plan_digest", "${{ steps.plan.outputs.plan_digest }}"),
            (
                "build_inputs_digest",
                "${{ steps.plan.outputs.build_inputs_digest }}",
            ),
            (
                "conformance_plan_digest",
                "${{ steps.plan.outputs.conformance_plan_digest }}",
            ),
            (
                "trusted_conformance_inputs_digest",
                "${{ steps.plan.outputs.trusted_conformance_inputs_digest }}",
            ),
            (
                "plan_artifact_id",
                "${{ steps.upload.outputs.artifact-id }}",
            ),
        ],
        failures,
    );
    for job_name in ["linux", "macos", "windows"] {
        check_exact_outputs(
            workflow,
            job_name,
            &[("artifact_id", "${{ steps.upload.outputs.artifact-id }}")],
            failures,
        );
    }
    check_exact_outputs(
        workflow,
        "assemble",
        &[("artifact_id", "${{ steps.upload.outputs.artifact-id }}")],
        failures,
    );
    check_exact_outputs(workflow, "publish", &[], failures);
    for (job_name, path) in [
        ("resolve", "release-plan"),
        ("linux", "platform-out"),
        ("macos", "platform-out"),
        ("windows", "platform-out"),
        ("assemble", "release-bundle"),
    ] {
        check_exact_upload(workflow, job_name, path, failures);
    }
    for (command, label) in [
        (RELEASE_RESOLVE_COMMAND, "exact candidate resolution"),
        (RELEASE_PLAN_COMMAND, "canonical isolated release plan"),
    ] {
        check_exact_command(workflow, "resolve", command, label, failures);
    }
    for job_name in ["resolve", "linux", "macos", "windows", "assemble"] {
        if workflow
            .jobs
            .get(job_name)
            .is_some_and(|job| job.permissions.is_some())
        {
            failures.push(format!(
                "release job {job_name:?} must inherit read-only permissions"
            ));
        }
    }
    for job_name in [
        "resolve", "linux", "macos", "windows", "assemble", "publish",
    ] {
        if let Some(job) = workflow.jobs.get(job_name) {
            check_release_checkouts(job_name, job, failures);
        }
    }
    check_checkout_set(
        workflow,
        "resolve",
        &[
            (None, "${{ github.workflow_sha }}", "automation"),
            (
                None,
                "${{ steps.resolve.outputs.candidate_sha }}",
                "candidate",
            ),
        ],
        failures,
    );
    for job_name in ["linux", "macos", "windows"] {
        check_checkout_set(
            workflow,
            job_name,
            &[
                (None, "${{ github.workflow_sha }}", "automation"),
                (
                    None,
                    "${{ needs.resolve.outputs.candidate_sha }}",
                    "candidate",
                ),
                (
                    Some("chrisdone/hell"),
                    "8e952cf9de4ab25d7716982a9ca234f9bdcf1bff",
                    "oracle-source",
                ),
            ],
            failures,
        );
    }
    for job_name in ["assemble", "publish"] {
        check_checkout_set(
            workflow,
            job_name,
            &[(None, "${{ github.workflow_sha }}", "automation")],
            failures,
        );
    }
    check_platform_job(
        workflow,
        "linux",
        "linux-x86_64",
        LINUX_PLATFORM_COMMAND,
        &LINUX_GATES,
        failures,
    );
    check_platform_job(
        workflow,
        "macos",
        "macos-aarch64",
        MACOS_PLATFORM_COMMAND,
        &NATIVE_GATES,
        failures,
    );
    check_platform_job(
        workflow,
        "windows",
        "windows-x86_64",
        WINDOWS_PLATFORM_COMMAND,
        &NATIVE_GATES,
        failures,
    );
    check_assemble(workflow, failures);
    check_publish(workflow, failures);
    check_release_caches(workflow, failures);
    check_trusted_driver_cache_inputs(workflow, failures);
    for (job_name, expression, path) in [
        (
            "linux",
            "${{ needs.resolve.outputs.plan_artifact_id }}",
            "release-input",
        ),
        (
            "macos",
            "${{ needs.resolve.outputs.plan_artifact_id }}",
            "release-input",
        ),
        (
            "windows",
            "${{ needs.resolve.outputs.plan_artifact_id }}",
            "release-input",
        ),
    ] {
        check_exact_download(workflow, job_name, "plan", expression, path, failures);
    }
}

fn check_release_trigger(value: &Value, failures: &mut Vec<String>) {
    let Some(triggers) = mapping(value) else {
        failures.push("release triggers must be a mapping".to_owned());
        return;
    };
    if triggers.len() != 1 || !contains_key(triggers, "workflow_dispatch") {
        failures.push("release workflow must have only workflow_dispatch".to_owned());
        return;
    }
    let Some(dispatch) = get(triggers, "workflow_dispatch").and_then(mapping) else {
        failures.push("release workflow_dispatch must be a mapping".to_owned());
        return;
    };
    if dispatch.len() != 1 || !contains_key(dispatch, "inputs") {
        failures.push("release workflow_dispatch must contain only inputs".to_owned());
        return;
    }
    let Some(inputs) = get(dispatch, "inputs").and_then(mapping) else {
        failures.push("release workflow_dispatch inputs must be a mapping".to_owned());
        return;
    };
    if inputs.len() != 1 || !contains_key(inputs, "candidate_branch") {
        failures.push("candidate_branch must be the sole release input".to_owned());
        return;
    }
    let Some(candidate) = get(inputs, "candidate_branch").and_then(mapping) else {
        failures.push("candidate_branch must be a mapping".to_owned());
        return;
    };
    if boolean(get(candidate, "required")) != Some(true)
        || scalar(get(candidate, "type")) != Some("string")
    {
        failures.push("candidate_branch must be a required string".to_owned());
    }
}

fn check_platform_job(
    workflow: &Workflow,
    job_name: &str,
    platform: &str,
    expected_command: &str,
    expected_gates: &[&str],
    failures: &mut Vec<String>,
) {
    let Some(job) = workflow.jobs.get(job_name) else {
        return;
    };
    if job.permissions.is_some() {
        failures.push(format!("platform job {job_name:?} expands permissions"));
    }
    let matching = job
        .steps
        .as_deref()
        .unwrap_or_default()
        .iter()
        .filter_map(|step| step.run.as_deref())
        .filter(|command| {
            option_value(command, "--platform") == Some(platform)
                && command_tokens(command)
                    .windows(2)
                    .any(|tokens| tokens == ["release", "platform"])
        })
        .collect::<Vec<_>>();
    if matching != [expected_command] {
        failures.push(format!(
            "platform job {job_name:?} must invoke the exact trusted {platform} conformance driver"
        ));
    }
    let run_commands = job
        .steps
        .as_deref()
        .unwrap_or_default()
        .iter()
        .filter_map(|step| step.run.as_deref())
        .collect::<Vec<_>>();
    if run_commands
        .iter()
        .filter(|command| **command == BUILD_DRIVER_AND_HELPER_COMMAND)
        .count()
        != 1
    {
        failures.push(format!(
            "platform job {job_name:?} must build the trusted driver and process helper together"
        ));
    }
    let expected_llvm_count = usize::from(job_name == "macos");
    if run_commands
        .iter()
        .filter(|command| **command == MACOS_LLVM_COMMAND)
        .count()
        != expected_llvm_count
    {
        failures.push(format!(
            "platform job {job_name:?} has an invalid pinned macOS LLVM provisioning inventory"
        ));
    }
    let gate_argument = matching
        .first()
        .and_then(|command| option_value(command, "--required-gates"));
    let actual_gates = gate_argument
        .map(|value| value.split(',').collect::<Vec<_>>())
        .unwrap_or_default();
    if actual_gates != expected_gates {
        failures.push(format!(
            "platform job {job_name:?} required gates must be exactly ordered {expected_gates:?}, found {actual_gates:?}"
        ));
    }
    check_release_checkouts(job_name, job, failures);
}

fn check_assemble(workflow: &Workflow, failures: &mut Vec<String>) {
    let Some(job) = workflow.jobs.get("assemble") else {
        return;
    };
    if job.permissions.is_some() {
        failures.push("assemble job expands permissions".to_owned());
    }
    check_exact_command(
        workflow,
        "assemble",
        ASSEMBLE_COMMAND,
        "the exact conformance assembly",
        failures,
    );
    check_exact_command(
        workflow,
        "assemble",
        POST_ASSEMBLY_REMOTE_COMMAND,
        "the post-assembly remote-state gate",
        failures,
    );
    let steps = job.steps.as_deref().unwrap_or_default();
    let diagnostic_uploads = job
        .steps
        .as_deref()
        .unwrap_or_default()
        .iter()
        .filter(|step| {
            step.uses.as_deref().and_then(action_name) == Some("actions/upload-artifact")
                && scalar(step.condition.as_ref()) == Some("${{ always() }}")
                && with_scalar(step, "path") == Some("release-reports")
                && with_scalar(step, "if-no-files-found") == Some("error")
        })
        .count();
    if diagnostic_uploads != 1 {
        failures.push(
            "assemble must retain the exact release diagnostics directory under always()"
                .to_owned(),
        );
    }
    let assemble_index = exact_run_index(steps, ASSEMBLE_COMMAND);
    let remote_index = exact_run_index(steps, POST_ASSEMBLY_REMOTE_COMMAND);
    let diagnostic_index = unique_step_index(steps, |step| {
        step.uses.as_deref().and_then(action_name) == Some("actions/upload-artifact")
            && scalar(step.condition.as_ref()) == Some("${{ always() }}")
            && with_scalar(step, "path") == Some("release-reports")
            && with_scalar(step, "if-no-files-found") == Some("error")
    });
    let bundle_upload_index = unique_step_index(steps, |step| {
        step.uses.as_deref().and_then(action_name) == Some("actions/upload-artifact")
            && with_scalar(step, "path") == Some("release-bundle")
    });
    if !matches!(
        (
            assemble_index,
            remote_index,
            diagnostic_index,
            bundle_upload_index
        ),
        (Some(assemble), Some(remote), Some(diagnostic), Some(upload))
            if assemble < remote && remote < diagnostic && diagnostic < upload
    ) {
        failures.push(
            "assemble must order assembly, remote-state gate, diagnostics, then bundle upload"
                .to_owned(),
        );
    }
    for (label, expression, path) in [
        (
            "plan",
            "${{ needs.resolve.outputs.plan_artifact_id }}",
            "release-input/plan",
        ),
        (
            "Linux",
            "${{ needs.linux.outputs.artifact_id }}",
            "release-input/platforms/linux-x86_64",
        ),
        (
            "macOS",
            "${{ needs.macos.outputs.artifact_id }}",
            "release-input/platforms/macos-aarch64",
        ),
        (
            "Windows",
            "${{ needs.windows.outputs.artifact_id }}",
            "release-input/platforms/windows-x86_64",
        ),
    ] {
        check_exact_download(workflow, "assemble", label, expression, path, failures);
    }
}

fn check_publish(workflow: &Workflow, failures: &mut Vec<String>) {
    let Some(job) = workflow.jobs.get("publish") else {
        return;
    };
    check_exact_permissions(
        job.permissions.as_ref(),
        &[
            ("actions", "read"),
            ("contents", "write"),
            ("id-token", "write"),
            ("attestations", "write"),
            ("artifact-metadata", "write"),
        ],
        "publish job",
        failures,
    );
    if job.condition.is_some() {
        failures.push("publish job must not have an additional condition".to_owned());
    }
    let staging_jobs = workflow
        .jobs
        .iter()
        .flat_map(|(job_name, job)| {
            job.steps
                .as_deref()
                .unwrap_or_default()
                .iter()
                .filter(|step| step.run.as_deref() == Some(STAGE_ATTESTATIONS_COMMAND))
                .map(move |_| job_name.as_str())
        })
        .collect::<Vec<_>>();
    if staging_jobs != ["publish"] {
        failures.push(format!(
            "attestation staging must run exactly once in the Ubuntu publisher, found {staging_jobs:?}"
        ));
    }
    let steps = job.steps.as_deref().unwrap_or_default();
    let attestation_steps = steps
        .iter()
        .enumerate()
        .filter_map(|(index, step)| step.uses.as_deref().map(|action| (index, step, action)))
        .filter(|(_, _, action)| action_name(action) == Some("actions/attest"))
        .map(|(index, step, _)| (index, step))
        .collect::<Vec<_>>();
    if attestation_steps.len() != 2 {
        failures.push(format!(
            "publish job must have exactly two attestation steps, found {}",
            attestation_steps.len()
        ));
    }
    for (command, label) in [
        (VERIFY_BUNDLE_COMMAND, "independent bundle verification"),
        (
            PRE_ATTESTATION_REMOTE_COMMAND,
            "the pre-attestation remote-state gate",
        ),
        (STAGE_ATTESTATIONS_COMMAND, "exact attestation staging"),
        (PUBLISH_COMMAND, "exact immutable publication"),
    ] {
        check_exact_command(workflow, "publish", command, label, failures);
    }
    let verify_index = exact_run_index(steps, VERIFY_BUNDLE_COMMAND);
    let remote_index = exact_run_index(steps, PRE_ATTESTATION_REMOTE_COMMAND);
    let stage_index = exact_run_index(steps, STAGE_ATTESTATIONS_COMMAND);
    let publish_index = exact_run_index(steps, PUBLISH_COMMAND);
    let provenance_index = attestation_steps.first().map(|(index, _)| *index);
    let gate_index = attestation_steps.get(1).map(|(index, _)| *index);
    if !matches!(
        (
            verify_index,
            remote_index,
            provenance_index,
            gate_index,
            stage_index,
            publish_index
        ),
        (
            Some(verify),
            Some(remote),
            Some(provenance),
            Some(gate),
            Some(stage),
            Some(publish)
        ) if verify < remote
            && remote + 1 == provenance
            && provenance + 1 == gate
            && gate + 1 == stage
            && stage < publish
    ) {
        failures.push(
            "publish steps must order verification, remote-state gate, adjacent attestations, staging, then publication".to_owned(),
        );
    }
    for (_, attestation) in &attestation_steps {
        if attestation.id.is_some() || attestation.condition.is_some() || attestation.env.is_some()
        {
            failures.push(
                "attestation steps must be unconditional and have no id or environment mapping"
                    .to_owned(),
            );
        }
    }
    if let Some((_, provenance)) = attestation_steps.first()
        && !exact_with(
            provenance,
            &[("subject-checksums", "release-bundle/SUBJECTS.sha256")],
        )
    {
        failures.push("provenance attestation must use only the exact subject list".to_owned());
    }
    if let Some((_, gate)) = attestation_steps.get(1)
        && !exact_with(
            gate,
            &[
                ("subject-checksums", "release-bundle/SUBJECTS.sha256"),
                ("predicate-type", RELEASE_GATE_PREDICATE_V2),
                ("predicate-path", "release-bundle/release-gate.json"),
            ],
        )
    {
        failures.push(
            "release-gate attestation must bind the exact v2 predicate and subject list".to_owned(),
        );
    }
    for step in steps {
        if step.uses.as_deref().and_then(action_name) == Some(CHECKOUT_ACTION)
            && with_scalar(step, "path") == Some("candidate")
        {
            failures.push("publish job must not check out candidate code".to_owned());
        }
    }
    for (label, expression, path) in [
        (
            "plan",
            "${{ needs.resolve.outputs.plan_artifact_id }}",
            "release-input/plan",
        ),
        (
            "bundle",
            "${{ needs.assemble.outputs.artifact_id }}",
            "release-bundle",
        ),
    ] {
        check_exact_download(workflow, "publish", label, expression, path, failures);
    }
    check_release_checkouts("publish", job, failures);
}

fn check_release_checkouts(job_name: &str, job: &Job, failures: &mut Vec<String>) {
    for step in job.steps.as_deref().unwrap_or_default() {
        if step.uses.as_deref().and_then(action_name) == Some(CHECKOUT_ACTION)
            && with_bool(step, "persist-credentials") != Some(false)
        {
            failures.push(format!(
                "release job {job_name:?} checkout must set persist-credentials false"
            ));
        }
    }
}

fn check_exact_download(
    workflow: &Workflow,
    job_name: &str,
    label: &str,
    expression: &str,
    path: &str,
    failures: &mut Vec<String>,
) {
    let count = workflow
        .jobs
        .get(job_name)
        .and_then(|job| job.steps.as_deref())
        .unwrap_or_default()
        .iter()
        .filter(|step| {
            step.uses.as_deref().and_then(action_name) == Some("actions/download-artifact")
                && with_scalar(step, "artifact-ids") == Some(expression)
                && with_scalar(step, "digest-mismatch") == Some("error")
                && with_scalar(step, "path") == Some(path)
        })
        .count();
    if count != 1 {
        failures.push(format!(
            "release job {job_name:?} must download exact {label} artifact ID once"
        ));
    }
}

fn check_exact_upload(workflow: &Workflow, job_name: &str, path: &str, failures: &mut Vec<String>) {
    let count = workflow
        .jobs
        .get(job_name)
        .and_then(|job| job.steps.as_deref())
        .unwrap_or_default()
        .iter()
        .filter(|step| {
            scalar(step.id.as_ref()) == Some("upload")
                && step.uses.as_deref().and_then(action_name) == Some("actions/upload-artifact")
                && with_scalar(step, "path") == Some(path)
                && with_scalar(step, "if-no-files-found") == Some("error")
        })
        .count();
    if count != 1 {
        failures.push(format!(
            "release job {job_name:?} must upload its exact artifact once"
        ));
    }
}

fn check_exact_command(
    workflow: &Workflow,
    job_name: &str,
    expected: &str,
    label: &str,
    failures: &mut Vec<String>,
) {
    let count = workflow
        .jobs
        .get(job_name)
        .and_then(|job| job.steps.as_deref())
        .unwrap_or_default()
        .iter()
        .filter_map(|step| step.run.as_deref())
        .filter(|command| *command == expected)
        .count();
    if count != 1 {
        failures.push(format!(
            "release job {job_name:?} must invoke {label} exactly once, found {count}"
        ));
    }
}

fn exact_run_index(steps: &[Step], expected: &str) -> Option<usize> {
    let mut matches = steps
        .iter()
        .enumerate()
        .filter(|(_, step)| step.run.as_deref() == Some(expected))
        .map(|(index, _)| index);
    let index = matches.next()?;
    matches.next().is_none().then_some(index)
}

fn unique_step_index(steps: &[Step], mut predicate: impl FnMut(&Step) -> bool) -> Option<usize> {
    let mut matches = steps
        .iter()
        .enumerate()
        .filter(|(_, step)| predicate(step))
        .map(|(index, _)| index);
    let index = matches.next()?;
    matches.next().is_none().then_some(index)
}

fn exact_with(step: &Step, expected: &[(&str, &str)]) -> bool {
    step.with.as_ref().is_some_and(|values| {
        values.len() == expected.len()
            && expected
                .iter()
                .all(|(key, value)| with_scalar(step, key) == Some(*value))
    })
}

fn release_workflow_has_forbidden_authority(workflow: &Workflow) -> bool {
    let forbidden = |value: &str| {
        let value = value.to_ascii_lowercase();
        [
            "secrets.",
            "self-hosted",
            "aws-access-key",
            "aws_access_key",
            "aws-secret",
            "aws_secret",
            "configure-aws",
            "ssh-agent",
            "ssh-key",
            "ssh_key",
            "ssh_private_key",
            "deploy-key",
            "deploy_key",
            "github_pat",
            "release_pat",
            "personal-access-token",
            "personal_access_token",
        ]
        .iter()
        .any(|needle| value.contains(needle))
    };
    workflow.jobs.values().any(|job| {
        [
            job.runs_on.as_ref(),
            job.permissions.as_ref(),
            job.env.as_ref(),
            job.secrets.as_ref(),
        ]
        .into_iter()
        .flatten()
        .any(|value| value_contains_matching(value, &forbidden))
            || job.steps.as_deref().unwrap_or_default().iter().any(|step| {
                step.uses.as_deref().is_some_and(&forbidden)
                    || step.run.as_deref().is_some_and(|command| {
                        forbidden(command)
                            || matches!(
                                executable_name(
                                    command_tokens(command).first().copied().unwrap_or_default()
                                ),
                                "ssh" | "scp" | "sftp" | "ssh-add" | "ssh-keygen" | "ssh-keyscan"
                            )
                    })
                    || step
                        .env
                        .as_ref()
                        .is_some_and(|value| value_contains_matching(value, &forbidden))
                    || step.with.as_ref().is_some_and(|values| {
                        values.iter().any(|(key, value)| {
                            value_contains_matching(key, &forbidden)
                                || value_contains_matching(value, &forbidden)
                        })
                    })
            })
    })
}

fn release_workflow_has_legacy_bounded_contract(workflow: &Workflow) -> bool {
    workflow_contains_text(workflow, &|value| {
        [
            "assurance-policy",
            "linux-differential-oracle",
            "native-differential-shard",
            "compatibility-report",
            "release-gate/v1",
            "compatibility_mode",
            "require_all_applicable_claims_verified",
        ]
        .iter()
        .any(|legacy| value.contains(legacy))
    })
}

fn workflow_contains_text(workflow: &Workflow, predicate: &impl Fn(&str) -> bool) -> bool {
    [
        workflow.name.as_ref(),
        workflow.run_name.as_ref(),
        Some(&workflow.triggers),
        workflow.permissions.as_ref(),
        workflow.concurrency.as_ref(),
        workflow.env.as_ref(),
    ]
    .into_iter()
    .flatten()
    .any(|value| value_contains_matching(value, predicate))
        || workflow.jobs.values().any(|job| {
            [
                job.name.as_ref(),
                job.runs_on.as_ref(),
                job.timeout_minutes.as_ref(),
                job.outputs.as_ref(),
                job.permissions.as_ref(),
                job.condition.as_ref(),
                job.env.as_ref(),
                job.strategy.as_ref(),
                job.uses.as_ref(),
                job.with.as_ref(),
                job.secrets.as_ref(),
            ]
            .into_iter()
            .flatten()
            .any(|value| value_contains_matching(value, predicate))
                || job.steps.as_deref().unwrap_or_default().iter().any(|step| {
                    step.run.as_deref().is_some_and(predicate)
                        || step.uses.as_deref().is_some_and(predicate)
                        || [
                            step.name.as_ref(),
                            step.id.as_ref(),
                            step.condition.as_ref(),
                            step.shell.as_ref(),
                            step.working_directory.as_ref(),
                            step.env.as_ref(),
                            step.continue_on_error.as_ref(),
                            step.timeout_minutes.as_ref(),
                        ]
                        .into_iter()
                        .flatten()
                        .any(|value| value_contains_matching(value, predicate))
                        || step.with.as_ref().is_some_and(|values| {
                            values.iter().any(|(key, value)| {
                                value_contains_matching(key, predicate)
                                    || value_contains_matching(value, predicate)
                            })
                        })
                })
        })
}

fn workflow_text_occurrence_count(workflow: &Workflow, needle: &str) -> usize {
    [
        workflow.name.as_ref(),
        workflow.run_name.as_ref(),
        Some(&workflow.triggers),
        workflow.permissions.as_ref(),
        workflow.concurrency.as_ref(),
        workflow.env.as_ref(),
    ]
    .into_iter()
    .flatten()
    .map(|value| value_occurrence_count(value, needle))
    .sum::<usize>()
        + workflow
            .jobs
            .values()
            .map(|job| {
                [
                    job.name.as_ref(),
                    job.runs_on.as_ref(),
                    job.timeout_minutes.as_ref(),
                    job.outputs.as_ref(),
                    job.permissions.as_ref(),
                    job.condition.as_ref(),
                    job.env.as_ref(),
                    job.strategy.as_ref(),
                    job.uses.as_ref(),
                    job.with.as_ref(),
                    job.secrets.as_ref(),
                ]
                .into_iter()
                .flatten()
                .map(|value| value_occurrence_count(value, needle))
                .sum::<usize>()
                    + job
                        .needs
                        .as_ref()
                        .map(|needs| {
                            needs
                                .values()
                                .iter()
                                .map(|value| value.matches(needle).count())
                                .sum::<usize>()
                        })
                        .unwrap_or_default()
                    + job
                        .steps
                        .as_deref()
                        .unwrap_or_default()
                        .iter()
                        .map(|step| {
                            step.uses
                                .as_deref()
                                .map(|value| value.matches(needle).count())
                                .unwrap_or_default()
                                + step
                                    .run
                                    .as_deref()
                                    .map(|value| value.matches(needle).count())
                                    .unwrap_or_default()
                                + [
                                    step.name.as_ref(),
                                    step.id.as_ref(),
                                    step.condition.as_ref(),
                                    step.shell.as_ref(),
                                    step.working_directory.as_ref(),
                                    step.env.as_ref(),
                                    step.continue_on_error.as_ref(),
                                    step.timeout_minutes.as_ref(),
                                ]
                                .into_iter()
                                .flatten()
                                .map(|value| value_occurrence_count(value, needle))
                                .sum::<usize>()
                                + step
                                    .with
                                    .as_ref()
                                    .map(|values| {
                                        values
                                            .iter()
                                            .map(|(key, value)| {
                                                value_occurrence_count(key, needle)
                                                    + value_occurrence_count(value, needle)
                                            })
                                            .sum::<usize>()
                                    })
                                    .unwrap_or_default()
                        })
                        .sum::<usize>()
            })
            .sum::<usize>()
}

fn value_occurrence_count(value: &Value, needle: &str) -> usize {
    match value {
        Value::String(value) => value.matches(needle).count(),
        Value::Sequence(values) => values
            .iter()
            .map(|value| value_occurrence_count(value, needle))
            .sum(),
        Value::Mapping(values) => values
            .iter()
            .map(|(key, value)| {
                value_occurrence_count(key, needle) + value_occurrence_count(value, needle)
            })
            .sum(),
        Value::Tagged(value) => value_occurrence_count(&value.value, needle),
        Value::Null | Value::Bool(_) | Value::Number(_) => 0,
    }
}

fn check_trusted_driver_cache_inputs(workflow: &Workflow, failures: &mut Vec<String>) {
    const INPUTS: [&str; 9] = [
        "automation/release-policy.toml",
        "automation/compat/builtin-registry.json",
        "automation/compat/requirements/2026-05-29.toml",
        "automation/compat/claim-rules.toml",
        "automation/compat/corpus-obligations.toml",
        "automation/compat/normalizers.toml",
        "automation/compat/divergences.toml",
        "automation/compat/expected-mismatches.toml",
        "automation/.github/release/conformance-exemptions.toml",
    ];
    for job_name in ["resolve", "assemble", "publish"] {
        let Some(job) = workflow.jobs.get(job_name) else {
            continue;
        };
        for step in job
            .steps
            .as_deref()
            .unwrap_or_default()
            .iter()
            .filter(|step| {
                matches!(
                    step.uses.as_deref().and_then(action_name),
                    Some(CACHE_RESTORE_ACTION | CACHE_SAVE_ACTION)
                )
            })
        {
            let key = with_scalar(step, "key").unwrap_or_default();
            if INPUTS.iter().any(|input| !key.contains(input)) {
                failures.push(format!(
                    "release job {job_name:?} trusted-driver cache omits a conformance control input"
                ));
            }
        }
    }
}

fn value_contains_matching(value: &Value, predicate: &impl Fn(&str) -> bool) -> bool {
    match value {
        Value::String(value) => predicate(value),
        Value::Sequence(values) => values
            .iter()
            .any(|value| value_contains_matching(value, predicate)),
        Value::Mapping(values) => values.iter().any(|(key, value)| {
            value_contains_matching(key, predicate) || value_contains_matching(value, predicate)
        }),
        Value::Tagged(value) => value_contains_matching(&value.value, predicate),
        Value::Null | Value::Bool(_) | Value::Number(_) => false,
    }
}

fn check_checkout_set(
    workflow: &Workflow,
    job_name: &str,
    expected: &[(Option<&str>, &str, &str)],
    failures: &mut Vec<String>,
) {
    let actual = workflow
        .jobs
        .get(job_name)
        .and_then(|job| job.steps.as_deref())
        .unwrap_or_default()
        .iter()
        .filter(|step| step.uses.as_deref().and_then(action_name) == Some(CHECKOUT_ACTION))
        .map(|step| {
            (
                with_scalar(step, "repository"),
                with_scalar(step, "ref").unwrap_or_default(),
                with_scalar(step, "path").unwrap_or_default(),
            )
        })
        .collect::<Vec<_>>();
    if actual != expected {
        failures.push(format!(
            "release job {job_name:?} checkout set must be exactly {expected:?}, found {actual:?}"
        ));
    }
}

fn check_release_caches(workflow: &Workflow, failures: &mut Vec<String>) {
    for (job_name, job) in &workflow.jobs {
        let steps = job.steps.as_deref().unwrap_or_default();
        let restores = cache_steps(steps, CACHE_RESTORE_ACTION);
        let saves = cache_steps(steps, CACHE_SAVE_ACTION);
        let restore_keys = restores
            .iter()
            .filter_map(|step| with_scalar(step, "key"))
            .collect::<Vec<_>>();
        let save_keys = saves
            .iter()
            .filter_map(|step| with_scalar(step, "key"))
            .collect::<Vec<_>>();
        if restore_keys != save_keys {
            failures.push(format!(
                "release job {job_name:?} cache restore/save keys differ"
            ));
        }
        for step in &saves {
            if scalar(step.condition.as_ref())
                .is_none_or(|condition| !valid_cache_save_condition(condition))
            {
                failures.push(format!(
                    "release job {job_name:?} cache save is not guarded by always()"
                ));
            }
        }
        for step in restores {
            if with_scalar(step, "restore-keys").is_some() {
                failures.push(format!(
                    "release job {job_name:?} uses a fallback cache key"
                ));
            }
            let key = with_scalar(step, "key").unwrap_or_default();
            let path = with_scalar(step, "path").unwrap_or_default();
            if path.contains("stack-root") || path.contains(".stack-work") {
                failures.push(format!(
                    "release job {job_name:?} must not restore candidate-writable Stack state"
                ));
            }
            if matches!(job_name.as_str(), "linux" | "macos" | "windows")
                && !path.contains(".cargo")
                && !key.contains("${{ needs.resolve.outputs.build_inputs_digest }}")
            {
                failures.push(format!(
                    "release job {job_name:?} candidate or Stack cache lacks exact build_inputs_digest"
                ));
            }
            if job_name == "publish" && !is_download_only_cargo_cache(path) {
                failures.push("publish job may restore only Cargo download caches".to_owned());
            }
        }
    }
}

fn check_run(path: &Path, job: &str, command: &str, failures: &mut Vec<String>) {
    let tokens = command_tokens(command);
    let first = tokens.first().copied().unwrap_or_default();
    let forbidden_interpreter = matches!(
        executable_name(first),
        "bash"
            | "sh"
            | "zsh"
            | "dash"
            | "cmd"
            | "powershell"
            | "pwsh"
            | "python"
            | "python3"
            | "ruby"
            | "perl"
    );
    if command.is_empty()
        || command.contains(['\n', ';', '|', '`', '&', '(', ')', '!'])
        || command.contains("&&")
        || command.contains("$(")
        || command.contains(['$', '>', '<', '*', '?', '\'', '"'])
        || forbidden_interpreter
        || tokens.is_empty()
    {
        failures.push(format!(
            "{} job {job:?} contains a non-single-command run scalar {command:?}",
            path.display()
        ));
    }
    if path == Path::new(RELEASE_PATH)
        && (executable_name(first) == "aws" || first.contains("_SSH_PRIVATE_KEY"))
    {
        failures.push(format!(
            "release job {job:?} invokes forbidden external authority"
        ));
    }
}

fn check_action_pin(path: &Path, job: &str, action: &str, failures: &mut Vec<String>) {
    if action.starts_with("./") {
        return;
    }
    let Some((name, revision)) = action.rsplit_once('@') else {
        failures.push(format!(
            "{} job {job:?} action is not pinned",
            path.display()
        ));
        return;
    };
    if revision.len() != 40 || !revision.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        failures.push(format!(
            "{} job {job:?} action {name:?} is not full-SHA pinned",
            path.display()
        ));
    }
    if name == "aws-actions/configure-aws-credentials" || name == "webfactory/ssh-agent" {
        failures.push(format!(
            "{} job {job:?} uses forbidden authority action {name:?}",
            path.display()
        ));
    }
}

fn check_needs(workflow: &Workflow, job: &str, expected: &[&str], failures: &mut Vec<String>) {
    let actual = workflow
        .jobs
        .get(job)
        .and_then(|job| job.needs.as_ref())
        .map(OneOrMany::values)
        .unwrap_or_default();
    if actual != expected {
        failures.push(format!(
            "release job {job:?} needs must be exactly {expected:?}, found {actual:?}"
        ));
    }
}

fn check_exact_outputs(
    workflow: &Workflow,
    job_name: &str,
    expected: &[(&str, &str)],
    failures: &mut Vec<String>,
) {
    let actual = workflow
        .jobs
        .get(job_name)
        .and_then(|job| job.outputs.as_ref())
        .and_then(mapping)
        .map(|outputs| {
            outputs
                .iter()
                .filter_map(|(key, value)| Some((key.as_str()?, value.as_str()?)))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if actual != expected {
        failures.push(format!(
            "release job {job_name:?} outputs must be exactly {expected:?}, found {actual:?}"
        ));
    }
}

fn check_exact_permissions(
    value: Option<&Value>,
    expected: &[(&str, &str)],
    owner: &str,
    failures: &mut Vec<String>,
) {
    let Some(actual) = value.and_then(mapping) else {
        failures.push(format!("{owner} permissions must be an exact mapping"));
        return;
    };
    let actual_pairs = actual
        .iter()
        .filter_map(|(key, value)| Some((key.as_str()?, value.as_str()?)))
        .collect::<Vec<_>>();
    if actual_pairs != expected {
        failures.push(format!(
            "{owner} permissions must be exactly {expected:?}, found {actual_pairs:?}"
        ));
    }
}

fn has_write_permission(value: Option<&Value>) -> bool {
    value.and_then(mapping).is_some_and(|permissions| {
        permissions
            .values()
            .any(|value| scalar(Some(value)) == Some("write"))
    })
}

fn cache_steps<'a>(steps: &'a [Step], name: &str) -> Vec<&'a Step> {
    steps
        .iter()
        .filter(|step| step.uses.as_deref().and_then(action_name) == Some(name))
        .collect()
}

fn action_name(action: &str) -> Option<&str> {
    action.rsplit_once('@').map(|(name, _)| name)
}

fn option_value<'a>(command: &'a str, option: &str) -> Option<&'a str> {
    let tokens = command_tokens(command);
    tokens
        .iter()
        .position(|token| *token == option)
        .and_then(|index| tokens.get(index + 1).copied())
}

fn command_tokens(command: &str) -> Vec<&str> {
    command.split_ascii_whitespace().collect()
}

fn executable_name(value: &str) -> &str {
    value
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(value)
        .trim_end_matches(".exe")
}

fn is_download_only_cargo_cache(path: &str) -> bool {
    let paths = path.lines().map(str::trim).filter(|line| !line.is_empty());
    let allowed = [
        "~/.cargo/registry/index",
        "~/.cargo/registry/cache",
        "~/.cargo/git/db",
    ];
    let actual = paths.collect::<BTreeSet<_>>();
    actual == allowed.into_iter().collect()
}

fn with_scalar<'a>(step: &'a Step, key: &str) -> Option<&'a str> {
    step.with
        .as_ref()
        .and_then(|values| get(values, key))
        .and_then(Value::as_str)
}

fn with_bool(step: &Step, key: &str) -> Option<bool> {
    step.with
        .as_ref()
        .and_then(|values| get(values, key))
        .and_then(Value::as_bool)
}

fn with_u64(step: &Step, key: &str) -> Option<u64> {
    step.with
        .as_ref()
        .and_then(|values| get(values, key))
        .and_then(Value::as_u64)
}

fn mapping(value: &Value) -> Option<&Mapping> {
    value.as_mapping()
}

fn get<'a>(mapping: &'a Mapping, key: &str) -> Option<&'a Value> {
    mapping.get(Value::String(key.to_owned()))
}

fn contains_key(mapping: &Mapping, key: &str) -> bool {
    get(mapping, key).is_some()
}

fn scalar(value: Option<&Value>) -> Option<&str> {
    value.and_then(Value::as_str)
}

fn boolean(value: Option<&Value>) -> Option<bool> {
    value.and_then(Value::as_bool)
}

fn touch_workflow_fields(workflow: &Workflow) {
    let _ = (
        &workflow.name,
        &workflow.run_name,
        &workflow.concurrency,
        &workflow.env,
    );
}

fn touch_job_fields(job: &Job) {
    let _ = (
        &job.name,
        &job.runs_on,
        &job.timeout_minutes,
        &job.outputs,
        &job.env,
        &job.strategy,
        &job.uses,
        &job.with,
        &job.secrets,
    );
}

fn touch_step_fields(step: &Step) {
    let _ = (
        &step.name,
        &step.id,
        &step.working_directory,
        &step.env,
        &step.continue_on_error,
        &step.timeout_minutes,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workflow_failures(path: &str, source: &str) -> Vec<String> {
        let workflow: Workflow = serde_yaml::from_str(source).expect("typed workflow");
        let mut failures = Vec::new();
        check_triggers(Path::new(path), &workflow, &mut failures);
        failures
    }

    fn push_gate_failures(path: &str, source: &str) -> Vec<String> {
        let workflow: Workflow = serde_yaml::from_str(source).expect("typed push workflow");
        let mut failures = Vec::new();
        check_common(Path::new(path), &workflow, &mut failures);
        check_push_gate_inventory(path, &workflow, &mut failures);
        check_push_cache_pairs(path, &workflow, &mut failures);
        failures
    }

    fn release_source() -> String {
        include_str!("../../../../.github/workflows/release.yml")
            .replace(
                "    # Removed only after the Rust gate inventory and non-placeholder reports are\n    # enforced by the workflow policy test.\n    if: ${{ needs.resolve.outputs.plan_digest == 'release-implementation-not-yet-complete' }}\n",
                "",
            )
    }

    fn ci_source() -> String {
        include_str!("../../../../.github/workflows/ci.yml").to_owned()
    }

    fn ci_failures(source: &str) -> Vec<String> {
        let workflow: Workflow = serde_yaml::from_str(source).expect("typed CI workflow");
        let mut failures = Vec::new();
        check_common(Path::new(CI_PATH), &workflow, &mut failures);
        check_triggers(Path::new(CI_PATH), &workflow, &mut failures);
        check_ci(&workflow, &mut failures);
        failures
    }

    fn failures(source: &str) -> Vec<String> {
        let workflow: Workflow = serde_yaml::from_str(source).expect("typed release workflow");
        let mut failures = Vec::new();
        check_common(Path::new(RELEASE_PATH), &workflow, &mut failures);
        check_release(&workflow, &mut failures);
        failures
    }

    fn mutate_job(source: &str, job: &str, from: &str, to: &str) -> String {
        let marker = format!("  {job}:\n");
        let start = source.find(&marker).expect("job marker");
        let body_start = start + marker.len();
        let end = source[body_start..]
            .match_indices("\n  ")
            .find(|(offset, _)| {
                source
                    .as_bytes()
                    .get(body_start + offset + 3)
                    .is_some_and(|byte| !byte.is_ascii_whitespace())
            })
            .map_or(source.len(), |(offset, _)| body_start + offset);
        let replacement = source[start..end].replacen(from, to, 1);
        assert_ne!(replacement, source[start..end], "mutant replaced nothing");
        format!("{}{}{}", &source[..start], replacement, &source[end..])
    }

    #[test]
    fn committed_release_workflow_satisfies_structural_policy() {
        let actual = failures(&release_source());
        assert!(actual.is_empty(), "{actual:?}");
    }

    #[test]
    fn committed_ci_workflow_satisfies_readiness_policy() {
        let actual = ci_failures(&ci_source());
        assert!(actual.is_empty(), "{actual:?}");
    }

    #[test]
    fn readiness_dag_and_identity_mutants_fail_closed() {
        let source = ci_source();
        for (label, mutant) in [
            (
                "conditional final decision",
                mutate_job(
                    &source,
                    "verify",
                    "    runs-on: ubuntu-24.04\n",
                    "    if: ${{ false }}\n    runs-on: ubuntu-24.04\n",
                ),
            ),
            (
                "missing native edge",
                source.replacen(
                    "needs: [plan, linux, macos, windows]",
                    "needs: [plan, linux, macos]",
                    1,
                ),
            ),
            (
                "candidate substitution",
                source.replacen("ref: ${{ github.sha }}", "ref: main", 1),
            ),
            (
                "stale default-branch automation",
                source.replacen(
                    "ref: ${{ github.sha }}",
                    "ref: ${{ github.event.repository.default_branch }}",
                    1,
                ),
            ),
            (
                "path-filtered push",
                source.replacen(
                    "    tags-ignore: ['**']\n",
                    "    tags-ignore: ['**']\n    paths: [crates/**]\n",
                    1,
                ),
            ),
        ] {
            assert!(!ci_failures(&mutant).is_empty(), "accepted {label}");
        }
    }

    #[test]
    fn readiness_gate_and_artifact_mutants_fail_closed() {
        let source = ci_source();
        for (label, mutant) in [
            (
                "missing technical gate",
                source.replacen("conformance-evidence,", "", 1),
            ),
            (
                "wrong platform plan",
                source.replacen(
                    "--plan readiness-input/readiness-plan.json",
                    "--plan readiness-input/unbound.json",
                    1,
                ),
            ),
            (
                "artifact name download",
                source.replacen(
                    "artifact-ids: ${{ needs.linux.outputs.artifact_id }}",
                    "name: readiness-linux",
                    1,
                ),
            ),
            (
                "release publication in CI",
                mutate_job(
                    &source,
                    "verify",
                    "      - name: Retain exact readiness decision\n",
                    "      - name: Forbidden publish\n        run: ./candidate-target/ci/hell-ci release publish\n      - name: Retain exact readiness decision\n",
                ),
            ),
            (
                "unapproved pinned action",
                mutate_job(
                    &source,
                    "verify",
                    "      - name: Retain exact readiness decision\n",
                    "      - name: Unapproved action\n        uses: actions/setup-node@0000000000000000000000000000000000000000\n      - name: Retain exact readiness decision\n",
                ),
            ),
        ] {
            assert!(!ci_failures(&mutant).is_empty(), "accepted {label}");
        }
    }

    #[test]
    fn readiness_cache_mutants_fail_closed() {
        let source = ci_source();
        for (label, mutant) in [
            (
                "fallback key",
                source.replacen(
                    "          key: readiness-plan-",
                    "          restore-keys: readiness-plan-\n          key: readiness-plan-",
                    1,
                ),
            ),
            (
                "missing workflow build input",
                source.replacen(", 'automation/.github/**'", "", 1),
            ),
            (
                "non-always cache save",
                source.replacen("if: ${{ always()", "if: ${{ success()", 1),
            ),
        ] {
            assert!(!ci_failures(&mutant).is_empty(), "accepted {label}");
        }
    }

    #[test]
    fn blocked_assembly_diagnostic_visibility_is_required() {
        let source = release_source();
        for mutant in [
            source.replacen(
                "        if: ${{ always() }}\n        uses: actions/upload-artifact",
                "        if: ${{ success() }}\n        uses: actions/upload-artifact",
                1,
            ),
            source.replacen(
                "          path: release-reports",
                "          path: release-bundle",
                1,
            ),
        ] {
            assert!(!failures(&mutant).is_empty());
        }
    }

    #[test]
    fn every_required_gate_is_structurally_bound() {
        let source = release_source();
        for gate in LINUX_GATES.into_iter().chain(NATIVE_GATES) {
            let mutant = source.replacen(gate, "mutated-gate", 1);
            assert!(
                !failures(&mutant).is_empty(),
                "accepted changed gate {gate}"
            );
        }
    }

    #[test]
    fn release_dag_and_permission_mutants_fail_closed() {
        let source = release_source();
        for (label, mutant) in [
            (
                "missing platform edge",
                source.replacen(
                    "needs: [resolve, linux, macos, windows]",
                    "needs: [resolve, linux, macos]",
                    1,
                ),
            ),
            (
                "publisher bypass",
                source.replacen("needs: [resolve, assemble]", "needs: resolve", 1),
            ),
            (
                "write outside publisher",
                source.replacen(
                    "permissions:\n  actions: read\n  contents: read",
                    "permissions:\n  actions: read\n  contents: write",
                    1,
                ),
            ),
            (
                "publisher permission removal",
                source.replacen("      artifact-metadata: write\n", "", 1),
            ),
            (
                "candidate in publisher",
                mutate_job(
                    &source,
                    "publish",
                    "          path: automation\n",
                    "          path: candidate\n",
                ),
            ),
        ] {
            assert!(!failures(&mutant).is_empty(), "accepted {label}");
        }
    }

    #[test]
    fn cache_identity_mutants_fail_closed() {
        let source = release_source();
        for (label, mutant) in [
            ("missing build input", source.replacen("${{ needs.resolve.outputs.build_inputs_digest }}", "unbound", 1)),
            ("fallback cache", source.replacen("          key: release-linux-target-", "          restore-keys: release-linux-target-\n          key: release-linux-target-", 1)),
            ("publisher target restore", source.replacen("          path: |\n            ~/.cargo/registry/index\n            ~/.cargo/registry/cache\n            ~/.cargo/git/db\n          key: release-publish", "          path: candidate-target\n          key: release-publish", 1)),
            (
                "candidate-writable Stack restore",
                mutate_job(
                    &source,
                    "linux",
                    "      - name: Resolve pinned Rust toolchain\n",
                    "      - name: Restore poisoned Stack cache\n        uses: actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9\n        with:\n          path: oracle-source/.stack-work\n          key: poisoned\n      - name: Resolve pinned Rust toolchain\n",
                ),
            ),
            ("save not always", source.replacen("if: ${{ always()", "if: ${{ success()", 1)),
        ] {
            assert!(!failures(&mutant).is_empty(), "accepted {label}");
        }
    }

    #[test]
    fn exact_artifact_download_mutants_fail_closed() {
        let source = release_source();
        for (label, mutant) in [
            (
                "non-fatal digest mismatch",
                source.replacen("digest-mismatch: error", "digest-mismatch: warn", 1),
            ),
            (
                "wrong artifact id",
                source.replacen(
                    "${{ needs.linux.outputs.artifact_id }}",
                    "${{ needs.macos.outputs.artifact_id }}",
                    1,
                ),
            ),
            (
                "wrong destination",
                source.replacen(
                    "path: release-input/platforms/windows-x86_64",
                    "path: release-input/platforms/other",
                    1,
                ),
            ),
        ] {
            assert!(!failures(&mutant).is_empty(), "accepted {label}");
        }
    }

    #[test]
    fn command_and_action_mutants_fail_closed() {
        let source = release_source();
        for (label, mutant) in [
            (
                "unpinned action",
                source.replacen(
                    "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
                    "actions/checkout@main",
                    1,
                ),
            ),
            (
                "shell sequence",
                source.replacen(
                    "run: rustup show active-toolchain",
                    "run: rustup show active-toolchain && true",
                    1,
                ),
            ),
            (
                "interpreter",
                source.replacen("run: rustup show active-toolchain", "run: bash -c true", 1),
            ),
            (
                "input interpolation",
                source.replacen(
                    "run: rustup show active-toolchain",
                    "run: tool ${{ inputs.candidate_branch }}",
                    1,
                ),
            ),
            (
                "background operator",
                source.replacen(
                    "run: rustup show active-toolchain",
                    "run: rustup show active-toolchain &",
                    1,
                ),
            ),
            (
                "subshell grouping",
                source.replacen(
                    "run: rustup show active-toolchain",
                    "run: (rustup show active-toolchain)",
                    1,
                ),
            ),
            (
                "history negation",
                source.replacen(
                    "run: rustup show active-toolchain",
                    "run: '! rustup show active-toolchain'",
                    1,
                ),
            ),
            (
                "credential persistence",
                source.replacen("persist-credentials: false", "persist-credentials: true", 1),
            ),
            (
                "plan diagnostic placed inside exact artifact",
                source.replacen(
                    "--resolution release-state/resolution.json --repository-root candidate --output release-plan --report release-reports/plan.json",
                    "--resolution release-state/resolution.json --repository-root candidate --output release-plan --report release-plan/release-plan-report.json",
                    1,
                ),
            ),
        ] {
            let workflow: Workflow = serde_yaml::from_str(&mutant).expect("typed mutant");
            let mut actual = Vec::new();
            check_common(Path::new(RELEASE_PATH), &workflow, &mut actual);
            check_release(&workflow, &mut actual);
            assert!(!actual.is_empty(), "accepted {label}");
        }
    }

    #[test]
    fn workflow_environment_contract_mutants_fail_closed() {
        let source = release_source();
        let token = "GITHUB_TOKEN: ${{ github.token }}";
        for (label, mutant) in [
            (
                "workflow environment",
                source.replacen("jobs:\n", "env:\n  CARGO_TERM_COLOR: always\n\njobs:\n", 1),
            ),
            (
                "empty workflow environment",
                source.replacen("jobs:\n", "env: {}\n\njobs:\n", 1),
            ),
            (
                "job environment",
                mutate_job(
                    &source,
                    "assemble",
                    "    runs-on: ubuntu-24.04\n",
                    "    runs-on: ubuntu-24.04\n    env:\n      GITHUB_TOKEN: ${{ github.token }}\n",
                ),
            ),
            (
                "custom token alias",
                source.replacen(token, "HELL_GITHUB_TOKEN: ${{ github.token }}", 1),
            ),
            (
                "alternate standard token alias",
                source.replacen(token, "GH_TOKEN: ${{ github.token }}", 1),
            ),
            (
                "configuration variable token",
                source.replacen(token, "GITHUB_TOKEN: ${{ vars.GITHUB_TOKEN }}", 1),
            ),
            (
                "configuration variable action input",
                source.replacen(
                    "          retention-days: 30\n",
                    "          retention-days: ${{ vars.RELEASE_RETENTION_DAYS }}\n",
                    1,
                ),
            ),
            (
                "configuration variable dispatch default",
                source.replacen(
                    "        type: string\n",
                    "        type: string\n        default: ${{ vars.RELEASE_BRANCH }}\n",
                    1,
                ),
            ),
            (
                "secret dispatch default",
                source.replacen(
                    "        type: string\n",
                    "        type: string\n        default: ${{ secrets.RELEASE_BRANCH }}\n",
                    1,
                ),
            ),
            (
                "secret top-level run name",
                source.replacen(
                    "run-name: Release candidate ${{ inputs.candidate_branch }} by @${{ github.actor }}",
                    "run-name: Release candidate ${{ secrets.RELEASE_BRANCH }}",
                    1,
                ),
            ),
            (
                "automatic token action input",
                source.replacen(
                    "          stack-version: 3.11.1\n",
                    "          stack-version: 3.11.1\n          token: ${{ github.token }}\n",
                    1,
                ),
            ),
            (
                "literal token",
                source.replacen(token, "GITHUB_TOKEN: literal", 1),
            ),
            (
                "second environment key",
                source.replacen(
                    token,
                    "GITHUB_TOKEN: ${{ github.token }}\n          EXTRA_TOKEN: forbidden",
                    1,
                ),
            ),
            (
                "token on assembly",
                mutate_job(
                    &source,
                    "assemble",
                    "      - name: Assemble, derive, and verify exact release set\n",
                    "      - name: Assemble, derive, and verify exact release set\n        env:\n          GITHUB_TOKEN: ${{ github.token }}\n",
                ),
            ),
            (
                "token on pure verification",
                mutate_job(
                    &source,
                    "publish",
                    "      - name: Independently verify release bundle before attestation\n",
                    "      - name: Independently verify release bundle before attestation\n        env:\n          GITHUB_TOKEN: ${{ github.token }}\n",
                ),
            ),
            (
                "token on candidate platform",
                mutate_job(
                    &source,
                    "linux",
                    "      - name: Run Linux release gate, collect conformance evidence, and package\n",
                    "      - name: Run Linux release gate, collect conformance evidence, and package\n        env:\n          GITHUB_TOKEN: ${{ github.token }}\n",
                ),
            ),
            (
                "token on action",
                mutate_job(
                    &source,
                    "resolve",
                    "        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n",
                    "        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n        env:\n          GITHUB_TOKEN: ${{ github.token }}\n",
                ),
            ),
        ] {
            assert_ne!(mutant, source, "mutant replaced nothing: {label}");
            assert!(!failures(&mutant).is_empty(), "accepted {label}");
        }
    }

    #[test]
    fn remote_state_and_attestation_plumbing_mutants_fail_closed() {
        let source = release_source();
        let post_assembly = format!(
            "      - name: Recheck remote state after assembly\n        env:\n          GITHUB_TOKEN: ${{{{ github.token }}}}\n        run: {POST_ASSEMBLY_REMOTE_COMMAND}\n"
        );
        let pre_attestation = format!(
            "      - name: Recheck remote state before attestation\n        env:\n          GITHUB_TOKEN: ${{{{ github.token }}}}\n        run: {PRE_ATTESTATION_REMOTE_COMMAND}\n"
        );
        let provenance = "      - name: Attest release subjects with build provenance\n        uses: actions/attest@508db95dd578ae2727ebd6217d5ba78e4fbda05d # v4.2.1\n        with:\n          subject-checksums: release-bundle/SUBJECTS.sha256\n";
        let reordered = source
            .replacen(&pre_attestation, "__REMOTE_STATE_STEP__\n", 1)
            .replacen(provenance, &pre_attestation, 1)
            .replacen("__REMOTE_STATE_STEP__\n", provenance, 1);
        for (label, mutant) in [
            (
                "missing post-assembly remote check",
                source.replacen(&post_assembly, "", 1),
            ),
            (
                "missing pre-attestation remote check",
                source.replacen(&pre_attestation, "", 1),
            ),
            ("remote check after provenance", reordered),
            (
                "third attestation action",
                mutate_job(
                    &source,
                    "publish",
                    "      - name: Stage exact attestation bundles\n",
                    &format!("{provenance}      - name: Stage exact attestation bundles\n"),
                ),
            ),
            (
                "attestation id",
                source.replacen(
                    "      - name: Attest release subjects with build provenance\n",
                    "      - name: Attest release subjects with build provenance\n        id: provenance\n",
                    1,
                ),
            ),
            (
                "attestation output aliases",
                mutate_job(
                    &source,
                    "publish",
                    "      - name: Stage exact attestation bundles\n",
                    "      - name: Stage exact attestation bundles\n        env:\n          HELL_PROVENANCE_BUNDLE: ${{ steps.provenance.outputs.bundle-path }}\n          HELL_RELEASE_GATE_BUNDLE: ${{ steps.gate.outputs.bundle-path }}\n",
                ),
            ),
            (
                "attestation output interpolation",
                source.replacen(
                    STAGE_ATTESTATIONS_COMMAND,
                    "./automation/target/ci/hell-ci release stage-attestations --input ${{ steps.provenance.outputs.bundle-path }}",
                    1,
                ),
            ),
            (
                "GITHUB_ENV relay",
                source.replacen(
                    STAGE_ATTESTATIONS_COMMAND,
                    "echo provenance=path >>$GITHUB_ENV",
                    1,
                ),
            ),
            (
                "interpreter staging",
                source.replacen(STAGE_ATTESTATIONS_COMMAND, "python3 stage.py", 1),
            ),
            (
                "attestation outside publisher",
                mutate_job(
                    &source,
                    "assemble",
                    "      - name: Build trusted release driver\n",
                    &format!("{provenance}      - name: Build trusted release driver\n"),
                ),
            ),
            (
                "attestation staging in Windows release gate",
                mutate_job(
                    &source,
                    "windows",
                    "      - name: Run Windows release gate, collect conformance evidence, and package\n",
                    &format!(
                        "      - name: Invalid Windows attestation staging\n        run: {STAGE_ATTESTATIONS_COMMAND}\n      - name: Run Windows release gate, collect conformance evidence, and package\n"
                    ),
                ),
            ),
        ] {
            assert_ne!(mutant, source, "mutant replaced nothing: {label}");
            assert!(!failures(&mutant).is_empty(), "accepted {label}");
        }
    }

    #[test]
    fn conformance_plan_and_native_evidence_mutants_fail_closed() {
        let source = release_source();
        for (label, mutant) in [
            (
                "candidate conformance plan substitution",
                mutate_job(
                    &source,
                    "linux",
                    "--conformance-plan release-input/conformance-plan.json",
                    "--conformance-plan candidate/conformance-plan.json",
                ),
            ),
            (
                "missing macOS conformance evidence gate",
                mutate_job(
                    &source,
                    "macos",
                    ",conformance-evidence,divergence-prototypes",
                    ",divergence-prototypes",
                ),
            ),
            (
                "missing Windows conformance plan",
                mutate_job(
                    &source,
                    "windows",
                    " --conformance-plan release-input\\conformance-plan.json",
                    "",
                ),
            ),
            (
                "assembly omits conformance plan",
                mutate_job(
                    &source,
                    "assemble",
                    " --conformance-plan release-input/plan/conformance-plan.json",
                    "",
                ),
            ),
            (
                "publisher verifier omits conformance plan",
                mutate_job(
                    &source,
                    "publish",
                    " --conformance-plan release-input/plan/conformance-plan.json",
                    "",
                ),
            ),
        ] {
            assert!(!failures(&mutant).is_empty(), "accepted {label}");
        }
    }

    #[test]
    fn publication_order_predicate_and_artifact_mutants_fail_closed() {
        let source = release_source();
        let reordered = source
            .replacen(VERIFY_BUNDLE_COMMAND, "__VERIFY_BUNDLE__", 1)
            .replacen(PUBLISH_COMMAND, VERIFY_BUNDLE_COMMAND, 1)
            .replacen("__VERIFY_BUNDLE__", PUBLISH_COMMAND, 1);
        for (label, mutant) in [
            (
                "name-only artifact download",
                source.replacen(
                    "artifact-ids: ${{ needs.resolve.outputs.plan_artifact_id }}",
                    "name: release-plan",
                    1,
                ),
            ),
            (
                "v1 release predicate",
                source.replacen(RELEASE_GATE_PREDICATE_V2, "release-gate/v1", 1),
            ),
            (
                "wrong release predicate path",
                source.replacen(
                    "predicate-path: release-bundle/release-gate.json",
                    "predicate-path: release-bundle/conformance-acceptance.json",
                    1,
                ),
            ),
            ("publication before verification", reordered),
        ] {
            assert!(!failures(&mutant).is_empty(), "accepted {label}");
        }
    }

    #[test]
    fn release_authority_and_error_suppression_mutants_fail_closed() {
        let source = release_source();
        for (label, mutant) in [
            (
                "continue on conformance error",
                mutate_job(
                    &source,
                    "linux",
                    "      - name: Run Linux release gate, collect conformance evidence, and package\n",
                    "      - name: Run Linux release gate, collect conformance evidence, and package\n        continue-on-error: true\n",
                ),
            ),
            (
                "write permission on assembly",
                mutate_job(
                    &source,
                    "assemble",
                    "    runs-on: ubuntu-24.04\n",
                    "    permissions:\n      id-token: write\n    runs-on: ubuntu-24.04\n",
                ),
            ),
            (
                "secret reference in publisher",
                mutate_job(
                    &source,
                    "publish",
                    "    timeout-minutes: 30\n",
                    "    timeout-minutes: 30\n    env:\n      HELL_PAT: ${{ secrets.RELEASE_PAT }}\n",
                ),
            ),
            (
                "job secrets contract",
                mutate_job(
                    &source,
                    "publish",
                    "    timeout-minutes: 30\n",
                    "    timeout-minutes: 30\n    secrets: inherit\n",
                ),
            ),
            (
                "AWS authority action",
                mutate_job(
                    &source,
                    "publish",
                    "      - name: Build trusted publisher\n",
                    "      - name: Configure AWS\n        uses: aws-actions/configure-aws-credentials@0123456789abcdef0123456789abcdef01234567\n      - name: Build trusted publisher\n",
                ),
            ),
            (
                "SSH authority command",
                mutate_job(
                    &source,
                    "publish",
                    "      - name: Build trusted publisher\n",
                    "      - name: Install SSH authority\n        run: ssh-add release-key\n      - name: Build trusted publisher\n",
                ),
            ),
            (
                "self-hosted publisher",
                mutate_job(
                    &source,
                    "publish",
                    "    runs-on: ubuntu-24.04\n",
                    "    runs-on: self-hosted\n",
                ),
            ),
        ] {
            assert!(!failures(&mutant).is_empty(), "accepted {label}");
        }

        let environment = mutate_job(
            &source,
            "publish",
            "    timeout-minutes: 30\n",
            "    timeout-minutes: 30\n    environment: production\n",
        );
        assert!(
            serde_yaml::from_str::<Workflow>(&environment).is_err(),
            "accepted release environment approval"
        );
    }

    #[test]
    fn second_dispatch_and_legacy_bounded_contract_mutants_fail_closed() {
        let source = release_source();
        for (label, mutant) in [
            (
                "second manual trigger",
                source.replacen(
                    "on:\n  workflow_dispatch:",
                    "on:\n  workflow_call:\n  workflow_dispatch:",
                    1,
                ),
            ),
            (
                "legacy bounded report step",
                mutate_job(
                    &source,
                    "assemble",
                    "      - name: Assemble, derive, and verify exact release set\n",
                    "      - name: Generate compatibility-report\n        run: ./automation/target/ci/hell-ci compatibility-report generate\n      - name: Assemble, derive, and verify exact release set\n",
                ),
            ),
            (
                "legacy Linux gate",
                mutate_job(
                    &source,
                    "linux",
                    "conformance-evidence",
                    "linux-differential-oracle",
                ),
            ),
        ] {
            assert!(!failures(&mutant).is_empty(), "accepted {label}");
        }
    }

    #[test]
    fn trusted_driver_cache_binds_every_conformance_control_input() {
        let source = release_source();
        for input in [
            "automation/release-policy.toml",
            "automation/compat/builtin-registry.json",
            "automation/compat/requirements/2026-05-29.toml",
            "automation/compat/claim-rules.toml",
            "automation/compat/corpus-obligations.toml",
            "automation/compat/normalizers.toml",
            "automation/compat/divergences.toml",
            "automation/compat/expected-mismatches.toml",
            "automation/.github/release/conformance-exemptions.toml",
        ] {
            let mutant = source.replacen(input, "automation/compat/omitted-control-input", 1);
            assert_ne!(mutant, source, "cache input was absent: {input}");
            assert!(
                !failures(&mutant).is_empty(),
                "accepted cache without {input}"
            );
        }
    }

    #[test]
    fn legacy_assurance_authority_cannot_return_to_ci() {
        for command in [
            "./target/ci/hell-ci assurance-verify --output report.json",
            "./target/ci/hell-ci release-oracle acquire --artifact oracle --provider-response provider.json --receipt receipt.json",
            "./target/ci/hell-ci promotion-gate --report report.json",
            "./target/ci/hell-ci promotion-worklist --report report.json",
            "./target/ci/hell-ci merge-native-shards --report report.json",
        ] {
            let source = format!(
                "name: CI\non:\n  push:\njobs:\n  check:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: {command}\n"
            );
            let workflow: Workflow = serde_yaml::from_str(&source).expect("typed CI mutant");
            let mut actual = Vec::new();
            check_common(
                Path::new(".github/workflows/ci.yml"),
                &workflow,
                &mut actual,
            );
            assert!(
                actual
                    .iter()
                    .any(|failure| failure.contains("retired assurance authority")),
                "accepted retired command {command}"
            );
        }

        let workflow: Workflow = serde_yaml::from_str(
            "name: CI\non:\n  push:\njobs:\n  check:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6\n",
        )
        .expect("typed retired action mutant");
        let mut actual = Vec::new();
        check_common(
            Path::new(".github/workflows/ci.yml"),
            &workflow,
            &mut actual,
        );
        assert!(
            actual
                .iter()
                .any(|failure| failure.contains("retired review verifier"))
        );

        let workflow: Workflow = serde_yaml::from_str(
            "name: CI\non:\n  push:\nenv:\n  HELL_SOURCE_COMMIT: deadbeef\njobs:\n  check:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: cargo check\n",
        )
        .expect("typed ambient source mutant");
        let mut actual = Vec::new();
        check_common(
            Path::new(".github/workflows/ci.yml"),
            &workflow,
            &mut actual,
        );
        assert!(
            actual
                .iter()
                .any(|failure| failure.contains("workflow-level environment variables"))
        );
    }

    #[test]
    fn nightly_requires_bounded_automatic_oracle_acquisition() {
        let source = include_str!("../../../../.github/workflows/nightly.yml");
        let workflow: Workflow = serde_yaml::from_str(source).expect("typed nightly workflow");
        let mut actual = Vec::new();
        check_nightly(&workflow, &mut actual);
        assert!(actual.is_empty(), "{actual:?}");

        let mutant = source.replacen("--version 0.20.2", "--version 0.20.1", 1);
        let workflow: Workflow = serde_yaml::from_str(&mutant).expect("typed nightly mutant");
        let mut actual = Vec::new();
        check_nightly(&workflow, &mut actual);
        assert!(
            actual
                .iter()
                .any(|failure| failure.contains("exact pinned cargo-deny"))
        );

        let mutant = source.replacen("oracle-acquire acquire", "release-oracle acquire", 1);
        let workflow: Workflow = serde_yaml::from_str(&mutant).expect("typed nightly mutant");
        let mut actual = Vec::new();
        check_common(Path::new(NIGHTLY_PATH), &workflow, &mut actual);
        check_nightly(&workflow, &mut actual);
        assert!(
            actual
                .iter()
                .any(|failure| failure.contains("bounded automatic"))
                && actual
                    .iter()
                    .any(|failure| failure.contains("retired assurance authority"))
        );

        let mutant = source.replacen(
            NIGHTLY_DIVERGENCE_PROTOTYPES,
            "cargo test deleted::divergence_prototype_roundtrip -- --ignored --exact",
            1,
        );
        let workflow: Workflow = serde_yaml::from_str(&mutant).expect("typed nightly mutant");
        let mut actual = Vec::new();
        check_nightly(&workflow, &mut actual);
        assert!(
            actual
                .iter()
                .any(|failure| failure.contains("live divergence prototype gate"))
        );

        let mutant = source.replacen(
            NIGHTLY_REGRESSION_CONSUMER,
            "./target/ci/hell-ci regression-import explore-generated --input missing --output ci-out/regression-exploration",
            1,
        );
        let workflow: Workflow = serde_yaml::from_str(&mutant).expect("typed nightly mutant");
        let mut actual = Vec::new();
        check_nightly(&workflow, &mut actual);
        assert!(
            actual
                .iter()
                .any(|failure| failure.contains("regression producer"))
        );
    }

    #[test]
    fn push_workflows_bind_exact_local_gate_commands_and_caches() {
        for (path, source) in [
            (
                MUTATION_PATH,
                include_str!("../../../../.github/workflows/mutation.yml"),
            ),
            (
                NIGHTLY_PATH,
                include_str!("../../../../.github/workflows/nightly.yml"),
            ),
            (
                REGRESSION_CORPUS_PATH,
                include_str!("../../../../.github/workflows/regression-corpus.yml"),
            ),
            (
                REGRESSION_SUBJECT_PATH,
                include_str!("../../../../.github/workflows/regression-subject.yml"),
            ),
        ] {
            let actual = push_gate_failures(path, source);
            assert!(actual.is_empty(), "{path}: {actual:?}");
        }

        let mutation = include_str!("../../../../.github/workflows/mutation.yml");
        let skipped = mutation.replacen(
            "    runs-on: ubuntu-24.04",
            "    if: false\n    runs-on: ubuntu-24.04",
            1,
        );
        assert!(
            push_gate_failures(MUTATION_PATH, &skipped)
                .iter()
                .any(|failure| failure.contains("conditionally skip"))
        );
        let skipped_checkout = mutation.replacen(
            "        uses: actions/checkout",
            "        if: false\n        uses: actions/checkout",
            1,
        );
        assert!(
            push_gate_failures(MUTATION_PATH, &skipped_checkout)
                .iter()
                .any(|failure| failure.contains("required action"))
        );
        let changed = mutation.replacen(MUTATION_RUN_COMMAND, "cargo test --workspace", 1);
        assert!(
            push_gate_failures(MUTATION_PATH, &changed)
                .iter()
                .any(|failure| failure.contains("exact ordered"))
        );
        let stale_cache = mutation.replacen("'builtins/**', ", "", 1);
        assert!(
            push_gate_failures(MUTATION_PATH, &stale_cache)
                .iter()
                .any(|failure| failure.contains("omits a build input"))
        );
        let weakened_save = mutation.replacen(
            "${{ always() && steps.cargo-cache.outcome == 'success' && steps.cargo-cache.outputs.cache-hit != 'true' }}",
            "${{ false && always() }}",
            1,
        );
        assert!(
            push_gate_failures(MUTATION_PATH, &weakened_save)
                .iter()
                .any(|failure| failure.contains("exact always-save predicates"))
        );
    }

    #[test]
    fn project_specific_host_environment_interfaces_fail_closed() {
        let build_script_source = ["println!(\"cargo:rustc-", "env=LOCAL_BUILD=value\")"].concat();
        let wrapper_sources = [
            (
                ["required_", "env(\"WRAPPER_MODE\")"].concat(),
                "WRAPPER_MODE",
            ),
            (
                ["required_", "env_os(\"WRAPPER_PATH\")"].concat(),
                "WRAPPER_PATH",
            ),
            (
                ["parse_env_", "u64(\"WRAPPER_LIMIT\")"].concat(),
                "WRAPPER_LIMIT",
            ),
        ];
        for (source, name) in [
            (
                "std::env::var(\"CORVETHAL_TOKEN\")".to_owned(),
                "CORVETHAL_TOKEN",
            ),
            (
                "option_env!(\"PROJECT_SOURCE\")".to_owned(),
                "PROJECT_SOURCE",
            ),
            (
                "command.env(\"VISIBLE_NAME\", \"value\")".to_owned(),
                "VISIBLE_NAME",
            ),
            (
                "command.environment(\"CORVETHAL_MODE\", \"test\")".to_owned(),
                "CORVETHAL_MODE",
            ),
            (build_script_source, "LOCAL_BUILD"),
        ] {
            assert_eq!(
                environment_interface_names(&source),
                BTreeSet::from([name.to_owned()])
            );
            assert!(!standard_environment_name(name));
        }
        for (source, name) in wrapper_sources {
            assert_eq!(
                environment_interface_names(&source),
                BTreeSet::from([name.to_owned()])
            );
            assert!(!standard_environment_name(name));
        }
        let process_marker = ["Process.", "setEnv"].concat();
        let process_source = [
            process_marker.as_str(),
            "\n  (List.cons\n    (\"LC_ALL\", \"C\")\n    (List.cons\n      (\"APPLICATION_MODE\", \"test\")\n      List.nil))",
        ]
        .concat();
        assert_eq!(
            environment_interface_names(&process_source),
            BTreeSet::from(["APPLICATION_MODE".to_owned(), "LC_ALL".to_owned()])
        );
        assert!(!standard_environment_name("APPLICATION_MODE"));
        assert!(standard_environment_name("GITHUB_TOKEN"));
        assert!(standard_environment_name("CARGO_BIN_EXE_hell"));
        for name in ["GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0"] {
            assert!(standard_environment_name(name));
        }
    }

    #[test]
    fn retired_indirect_and_scheduled_events_fail_closed() {
        let direct = "name: Test\non:\n  push:\n    branches: ['**']\n    tags-ignore: ['**']\npermissions:\n  contents: read\njobs:\n  validate:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n        with:\n          ref: ${{ github.sha }}\n          fetch-depth: 1\n          persist-credentials: false\n";
        assert!(workflow_failures(REGRESSION_SUBJECT_PATH, direct).is_empty());
        for mutant in [
            direct.replace(
                "  push:\n    branches: ['**']\n    tags-ignore: ['**']",
                "  workflow_run:\n    workflows: [Nightly]\n    types: [completed]",
            ),
            direct.replace(
                "    tags-ignore: ['**']",
                "    tags-ignore: ['**']\n  schedule:\n    - cron: '17 3 * * *'",
            ),
            direct.replace(
                "    runs-on: ubuntu-24.04",
                "    if: ${{ github.event.workflow_run.head_sha != '' }}\n    runs-on: ubuntu-24.04",
            ),
            direct.replace(
                "    runs-on: ubuntu-24.04",
                "    if: ${{ github.event_name == 'schedule' }}\n    runs-on: ubuntu-24.04",
            ),
        ] {
            assert!(
                !workflow_failures(REGRESSION_SUBJECT_PATH, &mutant).is_empty(),
                "accepted a retired event route"
            );
        }
    }

    #[test]
    fn direct_subject_identity_mutants_fail_closed() {
        let source = include_str!("../../../../.github/workflows/regression-subject.yml");
        assert!(workflow_failures(REGRESSION_SUBJECT_PATH, source).is_empty());
        for mutant in [
            source.replace("ref: ${{ github.sha }}", "ref: refs/heads/main"),
            source.replace("          ref: ${{ github.sha }}\n", ""),
            source.replace(
                "    runs-on: ubuntu-24.04",
                "    if: ${{ github.sha != '' }}\n    runs-on: ubuntu-24.04",
            ),
            source.replace("  contents: read", "  contents: write"),
        ] {
            assert!(
                !workflow_failures(REGRESSION_SUBJECT_PATH, &mutant).is_empty(),
                "accepted a weakened direct subject identity"
            );
        }
    }

    #[test]
    fn direct_push_filters_are_exact() {
        let nightly = include_str!("../../../../.github/workflows/nightly.yml");
        assert!(workflow_failures(NIGHTLY_PATH, nightly).is_empty());
        let nightly_mutant = nightly.replace("branches: ['**']", "branches: [main]");
        assert!(!workflow_failures(NIGHTLY_PATH, &nightly_mutant).is_empty());

        let corpus = include_str!("../../../../.github/workflows/regression-corpus.yml");
        assert!(workflow_failures(REGRESSION_CORPUS_PATH, corpus).is_empty());
        let corpus_mutant = corpus.replace("      - crates/hell-cli/tests/**\n", "");
        assert!(!workflow_failures(REGRESSION_CORPUS_PATH, &corpus_mutant).is_empty());
    }
}
