use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use hell_release_verifier::verify_vectors;

static FIXTURE_ID: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let id = FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "hell-release-vector-registry-{label}-{}-{id}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("create vector registry fixture");
        Self { root }
    }

    fn write_manifest(&self, contents: &str) -> PathBuf {
        let path = self.root.join("manifest.toml");
        fs::write(&path, contents).expect("write vector manifest fixture");
        path
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).expect("remove vector registry fixture");
    }
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn verify_manifest(manifest: PathBuf, fixture: &Fixture) -> String {
    let vectors = fixture.root.join("vectors");
    fs::create_dir(&vectors).expect("create empty vector corpus root");
    verify_vectors(
        manifest,
        vectors,
        repository_root().join("ci/release-protocol/v1/projection.json"),
        fixture.root.join("report.json"),
    )
    .expect_err("a registry-only fixture must stop before authority-bearing execution")
}

fn replace_once(input: &str, source: &str, replacement: &str) -> String {
    let (prefix, suffix) = input
        .split_once(source)
        .unwrap_or_else(|| panic!("manifest fixture lacks {source:?}"));
    format!("{prefix}{replacement}{suffix}")
}

#[test]
fn committed_manifest_matches_the_independent_ordered_vector_registry() {
    let fixture = Fixture::new("committed");
    let error = verify_manifest(
        repository_root().join("ci/release-protocol/v1/manifest.toml"),
        &fixture,
    );
    assert_eq!(error, "release protocol vector root inventory differs");
}

#[test]
fn independent_registry_rejects_id_order_duplicate_and_descriptor_drift() {
    let manifest =
        fs::read_to_string(repository_root().join("ci/release-protocol/v1/manifest.toml"))
            .expect("read committed vector manifest");

    let renamed = Fixture::new("renamed");
    let renamed_manifest = replace_once(
        &manifest,
        "id = \"wrong-candidate-sha\"",
        "id = \"candidate-sha-renamed\"",
    );
    assert_eq!(
        verify_manifest(renamed.write_manifest(&renamed_manifest), &renamed),
        "release protocol vector manifest does not contain the exact required set"
    );

    let reordered = Fixture::new("reordered");
    let (root, tables) = manifest
        .split_once("\n[[vector]]\n")
        .expect("vector manifest must contain vector tables");
    let mut tables = tables.split("\n[[vector]]\n").collect::<Vec<_>>();
    tables.swap(1, 2);
    let reordered_manifest = format!("{root}\n[[vector]]\n{}", tables.join("\n[[vector]]\n"));
    assert_eq!(
        verify_manifest(reordered.write_manifest(&reordered_manifest), &reordered),
        "release protocol vector manifest does not contain the exact required set"
    );

    let duplicate = Fixture::new("duplicate");
    let duplicate_manifest = replace_once(
        &manifest,
        "id = \"unknown-field\"",
        "id = \"duplicate-json-key\"",
    );
    assert_eq!(
        verify_manifest(duplicate.write_manifest(&duplicate_manifest), &duplicate),
        "vector manifest repeats an ID"
    );

    let descriptor = Fixture::new("descriptor");
    let descriptor_manifest = replace_once(
        &manifest,
        "diagnostic = \"release.json.duplicate-key\"",
        "diagnostic = \"release.json.duplicate-key\"\nunexpected = true",
    );
    assert_eq!(
        verify_manifest(descriptor.write_manifest(&descriptor_manifest), &descriptor),
        "vector fields or validity metadata differ"
    );
}
