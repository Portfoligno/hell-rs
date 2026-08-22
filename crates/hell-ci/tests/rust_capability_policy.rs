use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "hell-rust-capability-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("create fixture root");
        Self { root }
    }

    fn write(&self, relative: &str, contents: &str) {
        let path = self.root.join(relative);
        fs::create_dir_all(path.parent().expect("fixture parent")).expect("create fixture parent");
        fs::write(path, contents).expect("write fixture file");
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).expect("remove fixture root");
    }
}

#[test]
fn semantic_capability_policy_admits_exact_sites_and_rejects_ast_bypasses() {
    let fixture = Fixture::new();
    write_valid_fixture(&fixture);
    let admitted = run_policy(&fixture, "admitted.json");
    assert!(admitted.status.success(), "{:?}", admitted.stderr);
    let admitted_report = read_json(&fixture.root.join("admitted.json"));
    assert_eq!(admitted_report["admitted"], true);
    assert_eq!(admitted_report["violations"], serde_json::json!([]));
    assert_eq!(admitted_report["sites"].as_array().expect("sites").len(), 8);

    let mutations = [
        (
            "aliased",
            "pub struct GithubRuntime;\nimpl GithubRuntime { pub fn from_process() { let _ = std::env::var(\"GITHUB_REPOSITORY\"); } }\npub struct GithubCredential;\nimpl GithubCredential { pub fn from_process() { let _ = std::env::var(\"GITHUB_TOKEN\"); } }\nfn escape() { use std::env::var as renamed; let _ = renamed(\"UNTRUSTED\"); }\n",
            "capability.access.unapproved",
        ),
        (
            "reexported",
            "pub use std::env::var as leaked;\npub struct GithubRuntime;\nimpl GithubRuntime { pub fn from_process() { let _ = std::env::var(\"GITHUB_REPOSITORY\"); } }\npub struct GithubCredential;\nimpl GithubCredential { pub fn from_process() { let _ = std::env::var(\"GITHUB_TOKEN\"); } }\nfn escape() { let _ = leaked(\"UNTRUSTED\"); }\n",
            "capability.access.unapproved",
        ),
        (
            "macro",
            "pub struct GithubRuntime;\nimpl GithubRuntime { pub fn from_process() { let _ = std::env::var(\"GITHUB_REPOSITORY\"); } }\npub struct GithubCredential;\nimpl GithubCredential { pub fn from_process() { let _ = std::env::var(\"GITHUB_TOKEN\"); } }\nfn escape() { let _ = env!(\"UNTRUSTED\"); }\n",
            "capability.macro.unapproved",
        ),
        (
            "allow",
            "pub struct GithubRuntime;\nimpl GithubRuntime { pub fn from_process() { let _ = std::env::var(\"GITHUB_REPOSITORY\"); } }\npub struct GithubCredential;\nimpl GithubCredential { pub fn from_process() { let _ = std::env::var(\"GITHUB_TOKEN\"); } }\n#[allow(clippy::all)]\nfn escape() {}\n",
            "capability.allow.forbidden",
        ),
        (
            "process",
            "pub struct GithubRuntime;\nimpl GithubRuntime { pub fn from_process() { let _ = std::env::var(\"GITHUB_REPOSITORY\"); } }\npub struct GithubCredential;\nimpl GithubCredential { pub fn from_process() { let _ = std::env::var(\"GITHUB_TOKEN\"); } }\nfn escape() { let _ = std::process::Command::new(\"git\"); }\n",
            "capability.process.unapproved",
        ),
    ];
    for (id, source, diagnostic) in mutations {
        fixture.write("crates/hell-ci/src/github_runtime.rs", source);
        let output = format!("{id}.json");
        let rejected = run_policy(&fixture, &output);
        assert!(!rejected.status.success(), "mutation {id} was admitted");
        let report = read_json(&fixture.root.join(output));
        assert_eq!(report["admitted"], false, "{id}");
        assert_eq!(report["diagnostic"]["code"], diagnostic, "{id}");
    }
}

#[test]
fn committed_capability_vector_manifest_executes_the_exact_fixture_inventory() {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let vectors = read_committed_vectors(&repository);
    let declared = vectors
        .iter()
        .map(|vector| vector.input.clone())
        .collect::<BTreeSet<_>>();
    assert_eq!(declared, rust_vector_inventory(&repository));

    for vector in vectors {
        let fixture = Fixture::new();
        write_valid_fixture(&fixture);
        let source = fs::read_to_string(repository.join(&vector.input)).expect("read vector input");
        let destination = if vector.expected == "accept" {
            "crates/hell-ci/src/lib.rs"
        } else {
            "crates/hell-ci/src/vector.rs"
        };
        fixture.write(destination, &source);
        let output = format!("{}.json", vector.id);
        let result = run_policy(&fixture, &output);
        let report = read_json(&fixture.root.join(output));
        assert_eq!(
            result.status.success(),
            vector.expected == "accept",
            "{}",
            vector.id
        );
        assert_eq!(
            report["admitted"],
            vector.expected == "accept",
            "{}",
            vector.id
        );
        if let Some(diagnostic) = vector.diagnostic {
            assert_eq!(report["diagnostic"]["code"], diagnostic, "{}", vector.id);
        } else {
            assert!(report["diagnostic"].is_null(), "{}", vector.id);
        }
    }
}

struct CommittedVector {
    diagnostic: Option<String>,
    expected: String,
    id: String,
    input: PathBuf,
}

fn read_committed_vectors(repository: &Path) -> Vec<CommittedVector> {
    let manifest = fs::read_to_string(repository.join("ci/control-vectors/v1/manifest.toml"))
        .expect("read control-vector manifest");
    let mut tables = Vec::new();
    let mut current = None;
    for (index, original) in manifest.lines().enumerate() {
        let line = original.trim();
        if line.is_empty() {
            continue;
        }
        if line == "[[vector]]" {
            if let Some(table) = current.replace(BTreeMap::new()) {
                tables.push(table);
            }
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            panic!("invalid control-vector manifest line {}", index + 1);
        };
        let key = key.trim();
        let value = value.trim();
        if let Some(table) = current.as_mut() {
            let value = value
                .strip_prefix('"')
                .and_then(|value| value.strip_suffix('"'))
                .unwrap_or_else(|| panic!("vector value is not quoted at line {}", index + 1));
            assert!(
                table.insert(key.to_owned(), value.to_owned()).is_none(),
                "duplicate vector field at line {}",
                index + 1
            );
        } else {
            assert_eq!(key, "schema-version");
            assert_eq!(value, "1");
        }
    }
    if let Some(table) = current {
        tables.push(table);
    }
    let mut ids = BTreeSet::new();
    tables
        .into_iter()
        .filter(|table| {
            table
                .get("surface")
                .is_some_and(|value| value == "rust-capabilities")
        })
        .map(|mut table| {
            assert!(table.keys().all(|key| matches!(
                key.as_str(),
                "diagnostic" | "expected" | "id" | "input" | "surface"
            )));
            assert_eq!(
                table.remove("surface").as_deref(),
                Some("rust-capabilities")
            );
            let id = table.remove("id").expect("capability vector id");
            assert!(ids.insert(id.clone()), "duplicate capability vector id");
            let input = PathBuf::from(table.remove("input").expect("capability vector input"));
            assert!(
                !input.is_absolute(),
                "capability vector input must be relative"
            );
            let expected = table.remove("expected").expect("capability vector outcome");
            assert!(matches!(expected.as_str(), "accept" | "reject"));
            let diagnostic = table.remove("diagnostic");
            assert_eq!(diagnostic.is_some(), expected == "reject");
            assert!(table.is_empty(), "unconsumed capability vector fields");
            CommittedVector {
                diagnostic,
                expected,
                id,
                input,
            }
        })
        .collect()
}

fn rust_vector_inventory(repository: &Path) -> BTreeSet<PathBuf> {
    let root = repository.join("ci/rust-capability-vectors");
    let mut pending = vec![root];
    let mut files = BTreeSet::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory).expect("read capability vector directory") {
            let entry = entry.expect("read capability vector entry");
            let kind = entry.file_type().expect("inspect capability vector entry");
            assert!(
                !kind.is_symlink(),
                "capability vector inventory has a symlink"
            );
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file() && entry.path().extension().is_some_and(|value| value == "rs")
            {
                files.insert(
                    entry
                        .path()
                        .strip_prefix(repository)
                        .expect("vector beneath repository")
                        .to_path_buf(),
                );
            }
        }
    }
    files
}

fn write_valid_fixture(fixture: &Fixture) {
    fixture.write(
        "policy.toml",
        "schema-version = 1\npolicy-id = \"fixture-capabilities-v1\"\ndeny-broad-clippy-allow = true\ncontrol-vector-manifest = \"vectors.toml\"\n\n[[capability]]\nid = \"github-runtime-read\"\ncrate = \"hell-ci\"\nitem = \"github_runtime::GithubRuntime::from_process\"\nmethods = [\"std::env::var\", \"std::env::var_os\"]\nreason = \"fixture\"\n\n[[capability]]\nid = \"github-credential-read\"\ncrate = \"hell-ci\"\nitem = \"github_runtime::GithubCredential::from_process\"\nmethods = [\"std::env::var\"]\nreason = \"fixture\"\n\n[[capability]]\nid = \"child-environment\"\ncrate = \"hell-ci\"\nitem = \"process_environment::ChildEnvironment::apply\"\nmethods = [\"std::process::Command::envs\", \"std::process::Command::env_clear\"]\nreason = \"fixture\"\n\n[[capability]]\nid = \"executable-search-path-read\"\ncrate = \"hell-ci\"\nitem = \"process_environment::ExecutableSearchPath::from_process\"\nmethods = [\"std::env::var_os\"]\nreason = \"fixture\"\n\n[[capability]]\nid = \"standard-process-environment-read\"\ncrate = \"hell-ci\"\nitem = \"process_environment::ProcessEnvironment::from_process\"\nmethods = [\"std::env::var_os\"]\nreason = \"fixture\"\n\n[[capability]]\nid = \"publisher-github-runtime-read\"\ncrate = \"hell-release-publisher\"\nitem = \"github_runtime::GithubRuntime::from_process\"\nmethods = [\"std::env::var\"]\nreason = \"fixture\"\n\n[[compile-time-environment]]\nname = \"CARGO_MANIFEST_DIR\"\nscope = \"fixture\"\n",
    );
    fixture.write(
        "crates/hell-ci/src/github_runtime.rs",
        "pub struct GithubRuntime;\nimpl GithubRuntime { pub fn from_process() { let _ = std::env::var(\"GITHUB_REPOSITORY\"); let _ = std::env::var_os(\"GITHUB_EVENT_PATH\"); } }\npub struct GithubCredential;\nimpl GithubCredential { pub fn from_process() { let _ = std::env::var(\"GITHUB_TOKEN\"); } }\n",
    );
    fixture.write(
        "crates/hell-ci/src/process_environment.rs",
        "pub struct ChildEnvironment;\nimpl ChildEnvironment { pub fn apply(&self, command: &mut std::process::Command) { command.env_clear(); command.envs([] as [(&str, &str); 0]); } }\npub struct ExecutableSearchPath;\nimpl ExecutableSearchPath { pub fn from_process() { let _ = std::env::var_os(\"PATH\"); } }\npub struct ProcessEnvironment;\nimpl ProcessEnvironment { pub fn from_process() { let _ = std::env::var_os(\"TMPDIR\"); } }\n",
    );
    fixture.write(
        "crates/hell-release-publisher/src/github_runtime.rs",
        "pub struct GithubRuntime;\nimpl GithubRuntime { pub fn from_process() { let _ = std::env::var(\"GITHUB_TOKEN\"); } }\n",
    );
}

fn run_policy(fixture: &Fixture, output: &str) -> hell_testkit::SupervisedOutput {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
    command
        .args(["policy", "rust-capabilities", "--repository-root"])
        .arg(&fixture.root)
        .args(["--policy"])
        .arg(fixture.root.join("policy.toml"))
        .args(["--output"])
        .arg(fixture.root.join(output));
    let result = hell_testkit::run_supervised_command(&mut command, &[], Duration::from_secs(30))
        .expect("run capability policy under process-tree supervision");
    assert!(!result.timed_out, "capability policy exceeded its deadline");
    assert_terminal_cleanup_receipt(&result, "capability policy");
    result
}

fn assert_terminal_cleanup_receipt(result: &hell_testkit::SupervisedOutput, context: &str) {
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
        "{context} did not produce the terminal supervised I/O receipt"
    );
}

fn read_json(path: &Path) -> serde_json::Value {
    let bytes = fs::read(path).expect("read JSON report");
    assert_eq!(bytes.last(), Some(&b'\n'));
    serde_json::from_slice(&bytes).expect("parse JSON report")
}
