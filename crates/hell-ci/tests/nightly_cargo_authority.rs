#![cfg(unix)]

use hell_ci::nightly_cargo::{NightlyCargoAuthority, supervisor_roundtrip};
use hell_ci::process_environment::ProcessEnvironment;
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    root: PathBuf,
    source: PathBuf,
    entries: Vec<(OsString, OsString)>,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "hell-nightly-cargo-authority-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let root = root.canonicalize().unwrap();
        let source = root.join("source");
        for path in [
            "source",
            "work",
            "work/target",
            "work/tmp",
            "work/home",
            "work/cargo-home",
            "rustup",
            "bin",
        ] {
            fs::create_dir(root.join(path)).unwrap();
        }
        fs::set_permissions(&source, fs::Permissions::from_mode(0o555)).unwrap();
        for tool in ["cargo", "rustc"] {
            // A filesystem identity fixture only; the inspection never executes it.
            let path = root.join("bin").join(tool);
            fs::write(&path, b"not an executable probe; never launched\n").unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o555)).unwrap();
        }
        fs::write(
            root.join("work/cargo-home/config.toml"),
            b"[net]\noffline = true\n",
        )
        .unwrap();
        let mut entries = [
            ("CARGO", "bin/cargo"),
            ("RUSTC", "bin/rustc"),
            ("CARGO_TARGET_DIR", "work/target"),
            ("TMPDIR", "work/tmp"),
            ("HOME", "work/home"),
            ("CARGO_HOME", "work/cargo-home"),
            ("RUSTUP_HOME", "rustup"),
            ("PATH", "bin"),
        ]
        .into_iter()
        .map(|(name, path)| (OsString::from(name), root.join(path).into_os_string()))
        .collect::<Vec<_>>();
        entries.push(("RUSTUP_TOOLCHAIN".into(), "fixture-pinned-toolchain".into()));
        Self {
            root,
            source,
            entries,
        }
    }
    fn bind(&self) -> NightlyCargoAuthority {
        NightlyCargoAuthority::capture(
            &self.source,
            &ProcessEnvironment::from_entries(self.entries.clone()),
        )
        .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

#[test]
fn actual_supervisor_request_preserves_writable_paths_and_selected_tools() {
    let fixture = Fixture::new();
    let projection = supervisor_roundtrip(&fixture.source, &fixture.bind()).unwrap();
    assert_eq!(projection.program, fixture.root.join("bin/cargo"));
    assert_eq!(projection.directory, fixture.source);
    for (name, expected) in &fixture.entries {
        assert_eq!(
            projection
                .environment
                .iter()
                .filter(|(key, _)| key == name)
                .map(|(_, value)| value)
                .collect::<Vec<_>>(),
            [expected]
        );
    }
    for name in ["TMP", "TEMP"] {
        assert_eq!(
            projection
                .environment
                .iter()
                .find(|(key, _)| key == name)
                .unwrap()
                .1,
            fixture.root.join("work/tmp")
        );
    }
    assert_eq!(projection.arguments.first().unwrap(), "test");
    for flag in ["--workspace", "--all-targets", "--all-features", "--locked"] {
        assert!(projection.arguments.iter().any(|arg| arg == flag));
    }
    assert!(!projection.arguments.iter().any(|arg| arg == "--target-dir"));
    assert!(fs::read_dir(&fixture.source).unwrap().next().is_none());
}

#[test]
fn missing_or_source_contained_output_authority_is_rejected() {
    let fixture = Fixture::new();
    for missing in [
        "CARGO_TARGET_DIR",
        "TMPDIR",
        "CARGO",
        "RUSTC",
        "RUSTUP_TOOLCHAIN",
    ] {
        let entries = fixture
            .entries
            .iter()
            .filter(|(name, _)| name != missing)
            .cloned();
        assert!(
            NightlyCargoAuthority::capture(
                &fixture.source,
                &ProcessEnvironment::from_entries(entries)
            )
            .is_err()
        );
    }
    for changed in ["CARGO_TARGET_DIR", "TMPDIR"] {
        let entries = fixture.entries.iter().map(|(name, value)| {
            (
                name.clone(),
                if name == changed {
                    fixture.source.clone().into_os_string()
                } else {
                    value.clone()
                },
            )
        });
        assert!(
            NightlyCargoAuthority::capture(
                &fixture.source,
                &ProcessEnvironment::from_entries(entries)
            )
            .is_err()
        );
    }
    let mut json = serde_json::to_value(fixture.bind()).unwrap();
    json.as_object_mut().unwrap().remove("target");
    assert!(serde_json::from_value::<NightlyCargoAuthority>(json).is_err());
}

#[test]
fn replaced_directory_redirected_target_and_changed_offline_config_fail_before_cargo() {
    for changed in [
        "work/target",
        "work/tmp",
        "work/cargo-home/config.toml",
        "bin/rustc",
    ] {
        let fixture = Fixture::new();
        let authority = fixture.bind();
        let path = fixture.root.join(changed);
        if path.is_dir() {
            fs::rename(&path, fixture.root.join("original-directory")).unwrap();
            fs::create_dir(&path).unwrap();
        } else {
            fs::remove_file(&path).unwrap();
            fs::write(&path, b"changed binding\n").unwrap();
        }
        assert!(
            supervisor_roundtrip(&fixture.source, &authority).is_err(),
            "accepted replaced {changed}"
        );
    }
    let fixture = Fixture::new();
    let authority = fixture.bind();
    let target = fixture.root.join("work/target");
    fs::remove_dir(&target).unwrap();
    std::os::unix::fs::symlink(&fixture.source, &target).unwrap();
    assert!(supervisor_roundtrip(&fixture.source, &authority).is_err());
    assert!(!hell_testkit::RELEASE_CHILD_ENVIRONMENT_ALLOWLIST.contains(&"CARGO_TARGET_DIR"));
}
