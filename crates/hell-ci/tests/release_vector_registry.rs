use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde_json::{Map, Value};

static FIXTURE_ID: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let id = FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "hell-ci-release-vector-registry-{label}-{}-{id}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("create release vector registry fixture");
        Self { root }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    fn write_manifest(&self, contents: &str) -> PathBuf {
        let path = self.path("manifest.toml");
        fs::write(&path, contents).expect("write release vector manifest fixture");
        path
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).expect("remove release vector registry fixture");
    }
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn run_registry(manifest: &Path, output: &Path) -> hell_testkit::SupervisedOutput {
    let arguments = [
        OsString::from("release"),
        OsString::from("verify-vector-registry"),
        OsString::from("--manifest"),
        manifest.as_os_str().to_owned(),
        OsString::from("--output"),
        output.as_os_str().to_owned(),
    ];
    let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
    command.current_dir(repository_root()).args(arguments);
    hell_testkit::run_supervised_command(&mut command, &[], Duration::from_secs(30))
        .expect("release vector registry command must remain bounded")
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

fn replace_once(input: &str, source: &str, replacement: &str) -> String {
    let (prefix, suffix) = input
        .split_once(source)
        .unwrap_or_else(|| panic!("manifest fixture lacks {source:?}"));
    format!("{prefix}{replacement}{suffix}")
}

fn required_object<'a>(value: &'a Value, label: &str) -> &'a Map<String, Value> {
    value
        .as_object()
        .unwrap_or_else(|| panic!("{label} must be an object"))
}

#[test]
fn committed_manifest_matches_the_primary_registry_and_stable_diagnostics() {
    let fixture = Fixture::new("committed");
    let report = fixture.path("registry.json");
    let output = run_registry(
        &repository_root().join("ci/release-protocol/v1/manifest.toml"),
        &report,
    );
    assert!(
        output.status.success(),
        "primary registry rejected the committed manifest: {}",
        complete_stderr(&output)
    );

    let bytes = fs::read(&report).expect("read primary vector registry report");
    assert!(bytes.ends_with(b"\n"), "registry report must end with LF");
    let parsed: Value = serde_json::from_slice(&bytes).expect("parse primary registry report");
    let root = required_object(&parsed, "registry report");
    assert_eq!(root.len(), 4, "registry report root must be exact");
    assert_eq!(root.get("schemaVersion"), Some(&Value::from(1)));
    assert_eq!(root.get("state"), Some(&Value::from("verified")));
    assert_eq!(root.get("vectorCount"), Some(&Value::from(37)));
    let vectors = root
        .get("vectors")
        .and_then(Value::as_array)
        .expect("registry vectors must be an array");
    assert_eq!(vectors.len(), 37);

    let known_good = required_object(&vectors[0], "known-good vector");
    assert_eq!(known_good.len(), 4);
    assert_eq!(known_good.get("id"), Some(&Value::from("known-good")));
    assert_eq!(known_good.get("mutation"), Some(&Value::from("none")));
    assert_eq!(known_good.get("valid"), Some(&Value::from(true)));
    assert_eq!(known_good.get("diagnosticCode"), Some(&Value::Null));

    let duplicate = required_object(&vectors[1], "duplicate-key vector");
    assert_eq!(
        duplicate.get("diagnosticCode"),
        Some(&Value::from("release.json.duplicate-key"))
    );
    let disagreement_ids = vectors
        .iter()
        .filter_map(|vector| {
            let vector = vector.as_object()?;
            (vector.get("diagnosticCode")? == "release.verifier-disagreement")
                .then(|| vector.get("id").and_then(Value::as_str))
                .flatten()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        disagreement_ids,
        [
            "primary-accepts-independent-rejects",
            "independent-accepts-primary-rejects",
        ]
    );
}

#[test]
fn primary_registry_rejects_unknown_reordered_and_diagnostic_drift() {
    let manifest =
        fs::read_to_string(repository_root().join("ci/release-protocol/v1/manifest.toml"))
            .expect("read committed vector manifest");

    let renamed = Fixture::new("renamed");
    let renamed_manifest = replace_once(
        &manifest,
        "id = \"wrong-candidate-sha\"",
        "id = \"candidate-sha-renamed\"",
    );
    let renamed_output = run_registry(
        &renamed.write_manifest(&renamed_manifest),
        &renamed.path("report.json"),
    );
    assert!(!renamed_output.status.success());
    assert_eq!(
        complete_stderr(&renamed_output),
        "release vector manifest differs from the exact ordered production registry\n"
    );

    let reordered = Fixture::new("reordered");
    let (root, tables) = manifest
        .split_once("\n[[vector]]\n")
        .expect("vector manifest must contain vector tables");
    let mut tables = tables.split("\n[[vector]]\n").collect::<Vec<_>>();
    tables.swap(1, 2);
    let reordered_manifest = format!("{root}\n[[vector]]\n{}", tables.join("\n[[vector]]\n"));
    let reordered_output = run_registry(
        &reordered.write_manifest(&reordered_manifest),
        &reordered.path("report.json"),
    );
    assert!(!reordered_output.status.success());
    assert_eq!(
        complete_stderr(&reordered_output),
        "release vector manifest differs from the exact ordered production registry\n"
    );

    let diagnostic = Fixture::new("diagnostic");
    let diagnostic_manifest = replace_once(
        &manifest,
        "diagnostic = \"release.json.duplicate-key\"",
        "diagnostic = \"release.json.unknown-field\"",
    );
    let diagnostic_output = run_registry(
        &diagnostic.write_manifest(&diagnostic_manifest),
        &diagnostic.path("report.json"),
    );
    assert!(!diagnostic_output.status.success());
    assert_eq!(
        complete_stderr(&diagnostic_output),
        "release vector manifest differs from the exact ordered production registry\n"
    );

    let unknown = Fixture::new("unknown");
    let unknown_manifest = replace_once(
        &manifest,
        "diagnostic = \"release.json.duplicate-key\"",
        "diagnostic = \"release.json.duplicate-key\"\nunexpected = true",
    );
    let unknown_output = run_registry(
        &unknown.write_manifest(&unknown_manifest),
        &unknown.path("report.json"),
    );
    assert!(!unknown_output.status.success());
    assert_eq!(
        complete_stderr(&unknown_output),
        "release vector table has invalid or unknown fields\n"
    );

    for fixture in [&renamed, &reordered, &diagnostic, &unknown] {
        assert!(
            !fixture.path("report.json").exists(),
            "a rejected registry must not persist a verified report"
        );
    }
}
