use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static FIXTURE_ID: AtomicU64 = AtomicU64::new(0);

const REQUIRED_TARGETS: [&str; 31] = [
    "strict_json",
    "release_plan",
    "conformance_plan",
    "trusted_inputs",
    "platform_report",
    "evidence_manifest",
    "evidence_repository",
    "partition_reconstruction",
    "release_acceptance",
    "subjects_manifest",
    "release_gate",
    "publication_envelope",
    "governance_api_response",
    "governance_profile",
    "native_environment",
    "gzip_framing",
    "gnu_tar_subset",
    "release_bundle_inventory",
    "workflow_yaml_subset",
    "workflow_expression",
    "workflow_run_invocation",
    "independent_strict_json",
    "independent_release_plan",
    "independent_conformance_plan",
    "independent_evidence",
    "independent_ledger",
    "independent_exemption",
    "independent_gzip",
    "independent_gnu_tar",
    "independent_subjects",
    "independent_publication_envelope",
];

const RETAINED_TARGETS: [&str; 5] = [
    "requirement_toml",
    "normalizer_toml",
    "divergence_toml",
    "normalizer_replay",
    "semantic_trace",
];

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let id = FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
        let component = format!("hell-ci-fuzz-inventory-{label}-{}-{id}", std::process::id());
        let root = std::env::temp_dir().join(component);
        fs::create_dir(&root).expect("create fuzz inventory fixture");
        Self { root }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).expect("remove fuzz inventory fixture");
    }
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn run_fuzz_check(output: &Path) -> hell_testkit::SupervisedOutput {
    run_fuzz_check_with(
        &repository_root().join("ci/fuzz-targets.toml"),
        &repository_root(),
        output,
    )
}

fn run_fuzz_check_with(
    manifest: &Path,
    repository: &Path,
    output: &Path,
) -> hell_testkit::SupervisedOutput {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
    command.current_dir(repository_root()).args([
        OsStr::new("fuzz"),
        OsStr::new("check"),
        OsStr::new("--manifest"),
        manifest.as_os_str(),
        OsStr::new("--repository-root"),
        repository.as_os_str(),
        OsStr::new("--output"),
        output.as_os_str(),
    ]);
    hell_testkit::run_supervised_command(&mut command, &[], Duration::from_secs(30))
        .expect("fuzz inventory check must execute under supervision")
}

fn replace_once(input: &str, source: &str, replacement: &str) -> String {
    let (prefix, suffix) = input
        .split_once(source)
        .unwrap_or_else(|| panic!("fuzz manifest fixture lacks {source:?}"));
    format!("{prefix}{replacement}{suffix}")
}

fn rejection_code(path: &Path) -> String {
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(path).expect("fuzz rejection report must be persisted"))
            .expect("fuzz rejection report must be JSON");
    assert_eq!(report["schemaVersion"].as_u64(), Some(1));
    assert_eq!(report["state"].as_str(), Some("blocked"));
    report["diagnosticCode"]
        .as_str()
        .expect("fuzz rejection must have a stable diagnostic code")
        .to_owned()
}

fn copy_directory(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).expect("create fuzz inventory directory copy");
    for entry in fs::read_dir(source).expect("read fuzz inventory source directory") {
        let entry = entry.expect("read fuzz inventory source entry");
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let metadata = fs::symlink_metadata(&source_path).expect("inspect fuzz inventory entry");
        assert!(
            !metadata.file_type().is_symlink(),
            "fuzz inventory fixture cannot copy symlinks"
        );
        if metadata.is_dir() {
            copy_directory(&source_path, &destination_path);
        } else {
            assert!(metadata.is_file());
            fs::copy(&source_path, &destination_path).expect("copy fuzz inventory file");
        }
    }
}

fn copy_physical_fuzz_inventory(destination: &Path) {
    for relative in [
        "crates/hell-ci/fuzz",
        "crates/hell-release-verifier/fuzz",
        "crates/hell-workflow-auditor/fuzz",
    ] {
        let source = repository_root().join(relative);
        let target = destination.join(relative);
        fs::create_dir_all(&target).expect("create physical fuzz root");
        fs::copy(source.join("Cargo.toml"), target.join("Cargo.toml"))
            .expect("copy fuzz Cargo manifest");
        copy_directory(&source.join("fuzz_targets"), &target.join("fuzz_targets"));
        copy_directory(&source.join("corpus"), &target.join("corpus"));
    }
}

#[test]
fn production_fuzz_inventory_check_binds_all_physical_targets_and_corpora() {
    let fixture = Fixture::new("live");
    let report = fixture.path("fuzz-check.json");
    let output = run_fuzz_check(&report);
    assert!(
        output.status.success() && !output.timed_out,
        "fuzz inventory check failed: {}",
        String::from_utf8_lossy(
            output
                .stderr
                .complete
                .as_deref()
                .unwrap_or(&output.stderr.prefix)
        )
    );
    assert_eq!(
        fs::read_to_string(report).expect("fuzz inventory report must exist"),
        "{\"requiredTargetCount\":31,\"retainedTargetCount\":5,\"schemaVersion\":1,\"state\":\"checked\",\"targetCount\":36}\n"
    );
}

#[test]
fn typed_manifest_contains_the_exact_required_and_retained_id_sets() {
    let manifest = fs::read_to_string(repository_root().join("ci/fuzz-targets.toml"))
        .expect("fuzz manifest must be readable");
    let ids = manifest
        .lines()
        .filter_map(|line| {
            line.strip_prefix("id = \"")
                .and_then(|value| value.strip_suffix('"'))
        })
        .collect::<BTreeSet<_>>();
    let expected = REQUIRED_TARGETS
        .into_iter()
        .chain(RETAINED_TARGETS)
        .collect::<BTreeSet<_>>();
    assert_eq!(ids, expected);
}

#[test]
fn production_fuzz_inventory_rejects_unknown_reordered_and_duplicate_descriptors() {
    let manifest = fs::read_to_string(repository_root().join("ci/fuzz-targets.toml"))
        .expect("fuzz manifest must be readable");

    let unknown = Fixture::new("unknown-field");
    let unknown_manifest = replace_once(
        &manifest,
        "engine-arguments = [\"-runs=64\", \"-timeout=10\", \"-max_len=1048576\", \"-artifact_prefix=ci-out/fuzz-artifacts/strict_json/\"]",
        "engine-arguments = [\"-runs=64\", \"-timeout=10\", \"-max_len=1048576\", \"-artifact_prefix=ci-out/fuzz-artifacts/strict_json/\"]\nunknown = true",
    );
    let unknown_path = unknown.path("manifest.toml");
    fs::write(&unknown_path, unknown_manifest).expect("write unknown-field fuzz manifest");
    let unknown_report = unknown.path("report.json");
    let unknown_output = run_fuzz_check_with(&unknown_path, &repository_root(), &unknown_report);
    assert!(!unknown_output.status.success() && !unknown_output.timed_out);
    assert_eq!(rejection_code(&unknown_report), "fuzz.manifest.invalid");

    let reordered = Fixture::new("reordered");
    let (root, tables) = manifest
        .split_once("\n[[target]]\n")
        .expect("fuzz manifest must contain target tables");
    let mut tables = tables.split("\n[[target]]\n").collect::<Vec<_>>();
    tables.swap(0, 1);
    let reordered_manifest = format!("{root}\n[[target]]\n{}", tables.join("\n[[target]]\n"));
    let reordered_path = reordered.path("manifest.toml");
    fs::write(&reordered_path, reordered_manifest).expect("write reordered fuzz manifest");
    let reordered_report = reordered.path("report.json");
    let reordered_output =
        run_fuzz_check_with(&reordered_path, &repository_root(), &reordered_report);
    assert!(!reordered_output.status.success() && !reordered_output.timed_out);
    assert_eq!(rejection_code(&reordered_report), "fuzz.manifest.inventory");

    let duplicate = Fixture::new("duplicate");
    let duplicate_manifest =
        replace_once(&manifest, "id = \"release_plan\"", "id = \"strict_json\"");
    let duplicate_path = duplicate.path("manifest.toml");
    fs::write(&duplicate_path, duplicate_manifest).expect("write duplicate fuzz manifest");
    let duplicate_report = duplicate.path("report.json");
    let duplicate_output =
        run_fuzz_check_with(&duplicate_path, &repository_root(), &duplicate_report);
    assert!(!duplicate_output.status.success() && !duplicate_output.timed_out);
    assert_eq!(rejection_code(&duplicate_report), "fuzz.manifest.invalid");
}

#[test]
fn production_fuzz_inventory_rejects_extra_source_bin_and_corpus_assets() {
    let fixture = Fixture::new("physical-assets");
    let repository = fixture.path("repository");
    copy_physical_fuzz_inventory(&repository);
    let manifest = repository_root().join("ci/fuzz-targets.toml");

    let baseline_report = fixture.path("baseline.json");
    let baseline = run_fuzz_check_with(&manifest, &repository, &baseline_report);
    assert!(
        baseline.status.success() && !baseline.timed_out,
        "copied exact fuzz inventory must be admitted"
    );

    let source = repository.join("crates/hell-ci/fuzz/fuzz_targets/unregistered.rs");
    fs::write(&source, "#![no_main]\n").expect("write extra fuzz source");
    let source_report = fixture.path("source.json");
    let source_output = run_fuzz_check_with(&manifest, &repository, &source_report);
    assert!(!source_output.status.success() && !source_output.timed_out);
    assert_eq!(rejection_code(&source_report), "fuzz.source.inventory");
    fs::remove_file(&source).expect("remove extra fuzz source fixture");

    let cargo_path = repository.join("crates/hell-ci/fuzz/Cargo.toml");
    let mut cargo = fs::read_to_string(&cargo_path).expect("read copied fuzz Cargo manifest");
    cargo.push_str(
        "\n[[bin]]\nname = \"unregistered\"\npath = \"fuzz_targets/unregistered.rs\"\ntest = false\ndoc = false\nbench = false\n",
    );
    fs::write(&cargo_path, cargo).expect("write extra fuzz Cargo target");
    fs::write(&source, "#![no_main]\n").expect("write extra registered source fixture");
    let cargo_report = fixture.path("cargo.json");
    let cargo_output = run_fuzz_check_with(&manifest, &repository, &cargo_report);
    assert!(!cargo_output.status.success() && !cargo_output.timed_out);
    assert_eq!(rejection_code(&cargo_report), "fuzz.cargo-bin.inventory");

    fs::copy(
        repository_root().join("crates/hell-ci/fuzz/Cargo.toml"),
        &cargo_path,
    )
    .expect("restore copied fuzz Cargo manifest");
    fs::remove_file(&source).expect("remove extra registered source fixture");
    let extra_corpus = repository.join("crates/hell-ci/fuzz/corpus/unregistered");
    fs::create_dir_all(&extra_corpus).expect("create extra fuzz corpus");
    fs::write(extra_corpus.join("seed.txt"), "unregistered\n")
        .expect("write extra fuzz corpus seed");
    let corpus_report = fixture.path("corpus.json");
    let corpus_output = run_fuzz_check_with(&manifest, &repository, &corpus_report);
    assert!(!corpus_output.status.success() && !corpus_output.timed_out);
    assert_eq!(rejection_code(&corpus_report), "fuzz.corpus.inventory");
}
