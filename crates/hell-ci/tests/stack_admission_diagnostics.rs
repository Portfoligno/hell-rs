#![cfg(unix)]

use hell_ci::StackExecutableInspection;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "hell-stack-admission-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        Self(root.canonicalize().unwrap())
    }
    fn executable(&self) {
        // Admission fixture only; no process is launched by these tests.
        fs::write(self.0.join("stack"), b"fixture identity bytes\n").unwrap();
        fs::set_permissions(self.0.join("stack"), fs::Permissions::from_mode(0o555)).unwrap();
    }
    fn error(&self) -> String {
        StackExecutableInspection::bind(std::slice::from_ref(&self.0))
            .err()
            .expect("must reject")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn precise_absence_access_and_parent_mode_diagnostics_preserve_rejection() {
    let fixture = Fixture::new();
    assert!(
        fixture
            .error()
            .contains("candidate-metadata: kind=NotFound")
    );
    fixture.executable();
    StackExecutableInspection::bind(std::slice::from_ref(&fixture.0)).unwrap();
    fs::set_permissions(fixture.0.join("stack"), fs::Permissions::from_mode(0o444)).unwrap();
    assert!(fixture.error().contains("candidate-executable-access"));
    fs::set_permissions(fixture.0.join("stack"), fs::Permissions::from_mode(0o555)).unwrap();
    for mode in [0o775, 0o757, 0o777] {
        fs::set_permissions(&fixture.0, fs::Permissions::from_mode(mode)).unwrap();
        let error = fixture.error();
        assert!(error.contains("parent-write-mode"), "{error}");
        assert!(error.contains("forbidden-mask=0o022"), "{error}");
    }
}

#[test]
fn admitted_file_and_parent_identity_remain_bound() {
    let fixture = Fixture::new();
    fixture.executable();
    let authority = StackExecutableInspection::bind(std::slice::from_ref(&fixture.0)).unwrap();
    authority.revalidate().unwrap();
    fs::rename(fixture.0.join("stack"), fixture.0.join("original-stack")).unwrap();
    fixture.executable();
    assert!(authority.revalidate().is_err());
    let authority = StackExecutableInspection::bind(std::slice::from_ref(&fixture.0)).unwrap();
    fs::set_permissions(&fixture.0, fs::Permissions::from_mode(0o775)).unwrap();
    assert!(authority.revalidate().is_err());
}

#[test]
fn omitted_search_locations_are_bounded_without_suppressing_later_valid_candidates() {
    let fixture = Fixture::new();
    let mut search = (0..100)
        .map(|index| fixture.0.join(index.to_string()))
        .collect::<Vec<_>>();
    let error = StackExecutableInspection::bind(&search).err().unwrap();
    assert!(error.contains("searched=100"));
    assert!(error.contains("omitted-diagnostics=68"));
    assert!(error.len() < 9 * 1024);
    fixture.executable();
    search.push(fixture.0.clone());
    StackExecutableInspection::bind(&search)
        .unwrap()
        .revalidate()
        .unwrap();
}
