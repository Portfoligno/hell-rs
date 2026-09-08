use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const COMMITTED_DIGEST: &str = "8b78ffb78797b54aa9b56704ded5ae09954f260dfd1e4dae30b98d35f9f15d6c";
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

    let changed_platforms = String::from_utf8(original.clone())
        .expect("external-input lock is UTF-8")
        .replace(
            "platforms = [\"linux-x86_64\"]",
            "platforms = [\"linux-x86_64\", \"macos-aarch64\"]",
        );
    let changed_platforms_path =
        fixture.write("changed-platforms.toml", changed_platforms.as_bytes());
    assert_ne!(
        hell_release_verifier::external_input_lock_sha256(&changed_platforms_path)
            .expect("platform-scope mutation remains strict TOML"),
        COMMITTED_DIGEST,
        "changing executable applicability must change the authority digest",
    );
    assert!(
        hell_release_verifier::validate_external_input_lock(
            &changed_platforms_path,
            COMMITTED_DIGEST,
        )
        .is_err(),
        "a broadened tool platform scope must not match the trusted plan digest",
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

#[test]
fn authenticated_executable_fields_are_typed_and_each_changes_the_authority_digest() {
    let original = fs::read_to_string(repository_root().join("ci/external-inputs.toml")).unwrap();
    let fixture = Fixture::new();
    for (name, from, to) in [
        ("asset", "asset-id = 446721552", "asset-id = 446721553"),
        ("size", "exact-bytes = 94141872", "exact-bytes = 94141871"),
        (
            "source",
            "source-url = \"https://github.com/commercialhaskell/stack/releases/download/v3.11.1/stack-3.11.1-linux-x86_64-bin\"",
            "source-url = \"https://example.invalid/substituted-stack\"",
        ),
    ] {
        let changed = original.replace(from, to);
        assert_ne!(changed, original);
        let path = fixture.write(name, changed.as_bytes());
        assert_ne!(
            hell_release_verifier::external_input_lock_sha256(&path).unwrap(),
            COMMITTED_DIGEST
        );
        assert!(
            hell_release_verifier::validate_external_input_lock(&path, COMMITTED_DIGEST).is_err()
        );
    }
    for (name, from, to) in [
        (
            "asset-string",
            "asset-id = 446721552",
            "asset-id = \"446721552\"",
        ),
        ("asset-zero", "asset-id = 446721552", "asset-id = 0"),
        (
            "size-string",
            "exact-bytes = 94141872",
            "exact-bytes = \"94141872\"",
        ),
        ("size-zero", "exact-bytes = 94141872", "exact-bytes = 0"),
        (
            "source-number",
            "source-url = \"https://github.com/commercialhaskell/stack/releases/download/v3.11.1/stack-3.11.1-linux-x86_64-bin\"",
            "source-url = 123",
        ),
        (
            "unknown",
            "asset-id = 446721552",
            "asset-id = 446721552\nasset-unknown = 1",
        ),
    ] {
        let changed = original.replace(from, to);
        assert_ne!(changed, original);
        let path = fixture.write(name, changed.as_bytes());
        assert!(
            hell_release_verifier::external_input_lock_sha256(&path).is_err(),
            "accepted {name}"
        );
    }
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
