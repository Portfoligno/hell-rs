use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use hell_ci::reserve_platform_output_for_integration as reserve;

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "hell-platform-reservation-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        Self(root)
    }
    fn output(&self) -> PathBuf {
        self.0.join("platform-out")
    }
    fn prerequisite(&self) -> PathBuf {
        let root = self.output().join("memcordon");
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("provider-lease.json"),
            b"retained qualification evidence\n",
        )
        .unwrap();
        root
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn bound_prerequisite_only_root_reserves_fresh_payload_and_preserves_evidence() {
    let fixture = Fixture::new();
    let prerequisite = fixture.prerequisite();
    reserve(&fixture.output(), Some(&prerequisite)).unwrap();
    assert_eq!(
        fs::read(prerequisite.join("provider-lease.json")).unwrap(),
        b"retained qualification evidence\n"
    );
    for child in [
        "archive",
        "conformance-evidence",
        "conformance-observations",
    ] {
        assert!(fixture.output().join(child).is_dir());
    }
    assert!(reserve(&fixture.output(), Some(&prerequisite)).is_err());
}

#[test]
fn no_prerequisite_requires_a_fresh_root() {
    let fixture = Fixture::new();
    reserve(&fixture.output(), None).unwrap();
    assert!(reserve(&fixture.output(), None).is_err());
}

#[test]
fn stale_payload_and_unknown_siblings_are_rejected_without_writes() {
    for name in [
        "archive",
        "platform-report.json",
        "native-environment.json",
        "unknown",
    ] {
        let fixture = Fixture::new();
        let prerequisite = fixture.prerequisite();
        fs::write(fixture.output().join(name), b"stale\n").unwrap();
        assert!(reserve(&fixture.output(), Some(&prerequisite)).is_err());
        assert!(!fixture.output().join("conformance-evidence").exists());
    }
}

#[test]
fn stale_operation_evidence_is_not_a_prerequisite() {
    for path in ["operations.json", "unknown.json", "raw/old-operation.json"] {
        let fixture = Fixture::new();
        let prerequisite = fixture.prerequisite();
        fs::create_dir_all(prerequisite.join("raw")).unwrap();
        fs::write(prerequisite.join(path), b"stale\n").unwrap();
        assert!(reserve(&fixture.output(), Some(&prerequisite)).is_err());
        assert!(!fixture.output().join("archive").exists());
    }
}

#[test]
fn task_evidence_must_be_the_exact_direct_child() {
    let fixture = Fixture::new();
    fixture.prerequisite();
    let other = fixture.0.join("other");
    fs::create_dir(&other).unwrap();
    assert!(reserve(&fixture.output(), Some(&other)).is_err());
    assert!(!fixture.output().join("archive").exists());
}

#[cfg(unix)]
#[test]
fn redirected_output_subtree_and_nested_evidence_are_rejected() {
    for kind in ["output", "subtree", "nested"] {
        let fixture = Fixture::new();
        let prerequisite = fixture.prerequisite();
        match kind {
            "output" => {
                let alias = fixture.0.join("alias");
                std::os::unix::fs::symlink(fixture.output(), &alias).unwrap();
                assert!(reserve(&alias, Some(&prerequisite)).is_err());
            }
            "subtree" => {
                let original = fixture.0.join("original");
                fs::rename(&prerequisite, &original).unwrap();
                std::os::unix::fs::symlink(original, &prerequisite).unwrap();
                assert!(reserve(&fixture.output(), Some(&prerequisite)).is_err());
            }
            _ => {
                fs::create_dir(prerequisite.join("raw")).unwrap();
                std::os::unix::fs::symlink(
                    "missing",
                    prerequisite.join("raw/provider-adoption-canary.json"),
                )
                .unwrap();
                assert!(reserve(&fixture.output(), Some(&prerequisite)).is_err());
            }
        }
        assert!(!fixture.output().join("archive").exists());
    }
}
