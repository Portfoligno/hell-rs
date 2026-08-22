use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const COMMITTED_DIGEST: &str = "f7f711210a6825d639935c13eb1bee08bd2c771ddea91a25252a07608a277d71";
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("verifier crate must be under the repository crates directory")
        .to_path_buf()
}

#[test]
fn committed_external_input_lock_has_the_independent_content_digest() {
    let digest = hell_release_verifier::external_input_lock_sha256(
        &repository_root().join("ci/external-inputs.toml"),
    )
    .expect("committed external-input lock must be independently valid");
    assert_eq!(digest, COMMITTED_DIGEST);
}

#[test]
fn external_input_digest_changes_and_unknown_fields_fail_closed() {
    let fixture = Fixture::new();
    let original = fs::read(repository_root().join("ci/external-inputs.toml"))
        .expect("read committed external-input lock");
    let changed = String::from_utf8(original.clone())
        .expect("external-input lock is UTF-8")
        .replace(
            "8e952cf9de4ab25d7716982a9ca234f9bdcf1bff",
            "8e952cf9de4ab25d7716982a9ca234f9bdcf1bfe",
        );
    let changed_path = fixture.write("changed.toml", changed.as_bytes());
    assert_ne!(
        hell_release_verifier::external_input_lock_sha256(&changed_path)
            .expect("single authority mutation remains strict TOML"),
        COMMITTED_DIGEST
    );
    assert!(
        hell_release_verifier::validate_external_input_lock(&changed_path, COMMITTED_DIGEST)
            .is_err(),
        "a self-consistent substituted authority must not match the trusted plan digest"
    );

    let unknown = String::from_utf8(original)
        .expect("external-input lock is UTF-8")
        .replace(
            "lock-id = \"hell-rs-external-inputs-v1\"",
            "lock-id = \"hell-rs-external-inputs-v1\"\nunknown-root = \"rejected\"",
        );
    let unknown_path = fixture.write("unknown.toml", unknown.as_bytes());
    assert!(hell_release_verifier::external_input_lock_sha256(&unknown_path).is_err());
}

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "hell-independent-external-inputs-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("create external-input fixture root");
        Self { root }
    }

    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.root.join(name);
        fs::write(&path, bytes).expect("write external-input fixture");
        path
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).expect("remove external-input fixture root");
    }
}
