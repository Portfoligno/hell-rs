#![cfg(unix)]

use hell_ci::{FrozenDependencyInputs, dependency_directory_config, validate_dependency_vendor};

#[test]
fn frozen_manifest_and_lock_identity_rejects_changes_and_missing_inputs() {
    for name in ["Cargo.toml", "Cargo.lock"] {
        let fixture = Fixture::new();
        fs::write(fixture.root.join("Cargo.toml"), b"original manifest\n").unwrap();
        fs::write(fixture.root.join("Cargo.lock"), &fixture.lock).unwrap();
        let bound = FrozenDependencyInputs::bind(std::slice::from_ref(&fixture.root)).unwrap();
        bound.revalidate().unwrap();
        fs::write(fixture.root.join(name), b"changed content\n").unwrap();
        assert!(bound.revalidate().is_err());
        fs::remove_file(fixture.root.join(name)).unwrap();
        assert!(FrozenDependencyInputs::bind(std::slice::from_ref(&fixture.root)).is_err());
    }
}
use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    root: PathBuf,
    vendor: PathBuf,
    lock: Vec<u8>,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "hell-dependency-closure-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let root = root.canonicalize().unwrap();
        let vendor = root.join("vendor");
        let package = vendor.join("reviewed-1.0.0");
        fs::create_dir_all(package.join("src")).unwrap();
        let manifest = b"[package]\nname = \"reviewed\"\nversion = \"1.0.0\"\nedition = \"2021\"\n";
        let source = b"pub fn reviewed() {}\n";
        fs::write(package.join("Cargo.toml"), manifest).unwrap();
        fs::write(package.join("src/lib.rs"), source).unwrap();
        let checksum = hell_testkit::sha256_bytes(b"fixture archive identity").hex();
        let marker = serde_json::json!({"package":checksum, "files":{
            "Cargo.toml":hell_testkit::sha256_bytes(manifest).hex(),
            "src/lib.rs":hell_testkit::sha256_bytes(source).hex()}});
        fs::write(
            package.join(".cargo-checksum.json"),
            serde_json::to_vec(&marker).unwrap(),
        )
        .unwrap();
        let lock = format!("version = 4\n\n[[package]]\nname = \"subject\"\nversion = \"0.1.0\"\ndependencies = [\"reviewed\"]\n\n[[package]]\nname = \"reviewed\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"{checksum}\"\n").into_bytes();
        Self { root, vendor, lock }
    }
    fn valid(&self) -> Result<(), String> {
        validate_dependency_vendor(std::slice::from_ref(&self.lock), &self.vendor)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        restore_directories(&self.root);
        fs::remove_dir_all(&self.root).unwrap();
    }
}

fn restore_directories(path: &Path) {
    if fs::symlink_metadata(path).unwrap().is_dir() {
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        for entry in fs::read_dir(path).unwrap() {
            restore_directories(&entry.unwrap().path());
        }
    }
}

fn freeze_vendor(path: &Path) {
    let metadata = fs::symlink_metadata(path).unwrap();
    if metadata.is_dir() {
        for entry in fs::read_dir(path).unwrap() {
            freeze_vendor(&entry.unwrap().path());
        }
    }
    fs::set_permissions(
        path,
        fs::Permissions::from_mode(if metadata.is_dir() { 0o555 } else { 0o444 }),
    )
    .unwrap();
}

fn readiness_fixture(fixture: &Fixture) -> (PathBuf, PathBuf) {
    let source = fixture.root.join("subject");
    let home = fixture.root.join("cargo");
    fs::create_dir(&source).unwrap();
    fs::create_dir(source.join("src")).unwrap();
    fs::create_dir(&home).unwrap();
    fs::set_permissions(&home, fs::Permissions::from_mode(0o3770)).unwrap();
    fs::write(source.join("Cargo.toml"), b"[package]\nname = \"subject\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nreviewed = \"=1.0.0\"\n").unwrap();
    fs::write(source.join("src/lib.rs"), b"pub fn subject() {}\n").unwrap();
    fs::write(source.join("Cargo.lock"), &fixture.lock).unwrap();
    freeze_vendor(&fixture.vendor);
    (source, home)
}

#[test]
fn readiness_final_home_protects_both_configs_and_nested_cargo_resolves_offline() {
    let fixture = Fixture::new();
    let (source, home) = readiness_fixture(&fixture);
    let metadata = fs::metadata(&home).unwrap();
    let authority = hell_ci::readiness_cargo::ReadinessCargoSource::stage(
        &source,
        &home,
        &fixture.vendor,
        metadata.uid(),
        metadata.gid(),
    )
    .unwrap();
    for name in ["config", "config.toml"] {
        let config = fs::metadata(home.join(name)).unwrap();
        assert_eq!(config.uid(), metadata.uid());
        assert_eq!(config.mode() & 0o7777, 0o444);
    }
    // No --config/--offline argument: a descendant Cargo inherits its actual
    // home, and the protected files must supply both source and network policy.
    let mut command = std::process::Command::new(env!("CARGO"));
    command
        .args(["metadata", "--locked", "--format-version", "1"])
        .current_dir(source.join("src"))
        .env("CARGO_HOME", &home)
        .env("CARGO_TARGET_DIR", fixture.root.join("target"));
    let result =
        hell_testkit::run_supervised_command(&mut command, &[], Duration::from_secs(20)).unwrap();
    assert!(
        result.status.success() && !result.timed_out,
        "{}",
        String::from_utf8_lossy(&result.stderr.retained_bytes())
    );
    authority.validate().unwrap();
    let commands = authority.command_projection().unwrap();
    assert_eq!(
        commands
            .iter()
            .map(|command| command.name.as_str())
            .collect::<Vec<_>>(),
        [
            "format",
            "clippy",
            "workspace-tests",
            "documentation",
            "release-build"
        ]
    );
    for command in commands {
        let arguments = command.arguments;
        let environment = command.environment;
        assert_eq!(arguments[0], "--config");
        assert_eq!(arguments[1], home.join("config.toml"));
        assert_eq!(arguments[2], "--offline");
        assert_eq!(
            environment
                .iter()
                .rev()
                .find(|(key, _)| key == "CARGO_HOME")
                .unwrap()
                .1,
            home
        );
    }
    assert!(!home.join("credentials.toml").exists());
    assert!(!home.join("registry/src").exists());
}

#[test]
fn readiness_binding_rejects_config_lock_vendor_and_nested_override_changes() {
    for mutation in [
        "config",
        "config.toml",
        "Cargo.lock",
        "vendor",
        "nested-override",
        "home-mode",
    ] {
        let fixture = Fixture::new();
        let (source, home) = readiness_fixture(&fixture);
        let metadata = fs::metadata(&home).unwrap();
        let authority = hell_ci::readiness_cargo::ReadinessCargoSource::stage(
            &source,
            &home,
            &fixture.vendor,
            metadata.uid(),
            metadata.gid(),
        )
        .unwrap();
        match mutation {
            "config" | "config.toml" => {
                let path = home.join(mutation);
                fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
                fs::write(path, b"[net]\noffline=false\n").unwrap();
            }
            "Cargo.lock" => fs::write(source.join("Cargo.lock"), b"changed\n").unwrap(),
            "vendor" => {
                let path = fixture.vendor.join("reviewed-1.0.0/src/lib.rs");
                fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
                fs::write(&path, b"changed\n").unwrap();
                fs::set_permissions(path, fs::Permissions::from_mode(0o444)).unwrap();
            }
            "nested-override" => {
                fs::create_dir(source.join("src/.cargo")).unwrap();
                fs::write(
                    source.join("src/.cargo/config.toml"),
                    b"[net]\noffline=false\n",
                )
                .unwrap();
            }
            "home-mode" => fs::set_permissions(&home, fs::Permissions::from_mode(0o2770)).unwrap(),
            _ => unreachable!(),
        }
        assert!(authority.validate().is_err(), "accepted {mutation}");
    }
}

#[test]
fn exact_checksum_closure_rejects_missing_changed_and_unchecked_package_data() {
    let fixture = Fixture::new();
    fixture.valid().unwrap();
    let source = fixture.vendor.join("reviewed-1.0.0/src/lib.rs");
    fs::write(&source, b"substituted\n").unwrap();
    assert!(fixture.valid().is_err());
    fs::remove_file(&source).unwrap();
    assert!(fixture.valid().is_err());
    fs::write(&source, b"pub fn reviewed() {}\n").unwrap();
    let unknown = fixture.vendor.join("credentials.toml");
    fs::write(&unknown, b"secret\n").unwrap();
    assert!(fixture.valid().is_err());
}

#[test]
fn checksum_comment_is_optional_string_metadata_not_an_integrity_exception() {
    for change in [
        "none",
        "package",
        "bytes",
        "missing",
        "extra",
        "extra-package",
    ] {
        let fixture = Fixture::new();
        let package = fixture.vendor.join("reviewed-1.0.0");
        let marker = package.join(".cargo-checksum.json");
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&marker).unwrap()).unwrap();
        value["$comment"] = serde_json::json!("Explanatory producer metadata");
        if change == "package" {
            value["package"] =
                serde_json::json!(hell_testkit::sha256_bytes(b"wrong archive").hex());
        }
        fs::write(&marker, serde_json::to_vec(&value).unwrap()).unwrap();
        match change {
            "bytes" => fs::write(package.join("src/lib.rs"), b"changed bytes\n").unwrap(),
            "missing" => fs::remove_file(package.join("src/lib.rs")).unwrap(),
            "extra" => fs::write(package.join("extra.rs"), b"unchecked bytes\n").unwrap(),
            "extra-package" => fs::create_dir(fixture.vendor.join("unlocked-1.0.0")).unwrap(),
            _ => {}
        }
        assert_eq!(fixture.valid().is_ok(), change == "none", "{change}");
    }
}

#[test]
fn checksum_comment_rejects_non_strings_unknown_fields_and_duplicate_fields() {
    let fixture = Fixture::new();
    let marker = fixture.vendor.join("reviewed-1.0.0/.cargo-checksum.json");
    let original: serde_json::Value = serde_json::from_slice(&fs::read(&marker).unwrap()).unwrap();
    for comment in [
        serde_json::Value::Null,
        serde_json::json!(1),
        serde_json::json!(false),
        serde_json::json!([]),
        serde_json::json!({}),
    ] {
        let mut value = original.clone();
        value["$comment"] = comment;
        fs::write(&marker, serde_json::to_vec(&value).unwrap()).unwrap();
        let error = fixture.valid().unwrap_err();
        assert!(error.contains(marker.to_str().unwrap()));
    }
    let mut value = original;
    value["$comment"] = serde_json::json!("valid comment");
    value["unknown_metadata"] = serde_json::json!("not admitted");
    fs::write(&marker, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(fixture.valid().is_err());
    value.as_object_mut().unwrap().remove("unknown_metadata");
    let document = serde_json::to_string(&value).unwrap();
    for field in [
        "\"$comment\":\"duplicate\"",
        "\"package\":\"duplicate\"",
        "\"files\":{}",
    ] {
        let duplicate = format!("{{{field},{}", document.strip_prefix('{').unwrap());
        fs::write(&marker, duplicate).unwrap();
        assert!(fixture.valid().unwrap_err().contains("duplicate field"));
    }
}

#[test]
fn package_source_lock_checksum_and_symlink_substitution_are_rejected() {
    let fixture = Fixture::new();
    let wrong = String::from_utf8(fixture.lock.clone()).unwrap().replace(
        "registry+https://github.com/rust-lang/crates.io-index",
        "git+https://unapproved.invalid/repository",
    );
    assert!(validate_dependency_vendor(&[wrong.into_bytes()], &fixture.vendor).is_err());
    let marker = fixture.vendor.join("reviewed-1.0.0/.cargo-checksum.json");
    let original = fs::read(&marker).unwrap();
    let mut changed: serde_json::Value = serde_json::from_slice(&original).unwrap();
    changed["package"] = serde_json::json!(hell_testkit::sha256_bytes(b"other archive").hex());
    fs::write(&marker, serde_json::to_vec(&changed).unwrap()).unwrap();
    assert!(fixture.valid().is_err());
    fs::remove_file(&marker).unwrap();
    let external = fixture.root.join("external-marker");
    fs::write(&external, original).unwrap();
    std::os::unix::fs::symlink(&external, &marker).unwrap();
    assert!(fixture.valid().is_err());
}

fn offline_fetch(root: &Path, home: &Path) -> hell_testkit::SupervisedOutput {
    let mut command = std::process::Command::new(env!("CARGO"));
    command
        .args([
            "fetch",
            "--frozen",
            "--locked",
            "--offline",
            "--manifest-path",
        ])
        .arg(root.join("Cargo.toml"))
        .current_dir(root)
        .env("CARGO_HOME", home)
        .env("CARGO_TARGET_DIR", root.join("target"));
    hell_testkit::run_supervised_command(&mut command, &[], Duration::from_secs(20)).unwrap()
}

#[test]
fn isolated_directory_source_satisfies_actual_offline_fetch_without_host_credentials() {
    let fixture = Fixture::new();
    let root = fixture.root.join("subject");
    let home = fixture.root.join("cargo-home");
    fs::create_dir(&root).unwrap();
    fs::create_dir(root.join("src")).unwrap();
    fs::create_dir(&home).unwrap();
    fs::write(root.join("Cargo.toml"), b"[package]\nname = \"subject\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nreviewed = \"=1.0.0\"\n").unwrap();
    fs::write(root.join("src/lib.rs"), b"pub fn subject() {}\n").unwrap();
    fs::write(root.join("Cargo.lock"), &fixture.lock).unwrap();
    let absent = offline_fetch(&root, &home);
    assert!(!absent.status.success());
    fixture.valid().unwrap();
    fs::write(
        home.join("config.toml"),
        dependency_directory_config(&fixture.vendor).unwrap(),
    )
    .unwrap();
    let seeded = offline_fetch(&root, &home);
    assert!(
        seeded.status.success(),
        "{}",
        String::from_utf8_lossy(&seeded.stderr.retained_bytes())
    );
    assert_eq!(fs::read(root.join("Cargo.lock")).unwrap(), fixture.lock);
    assert!(!home.join("credentials.toml").exists());
    assert!(!home.join("credentials").exists());
    assert!(dependency_directory_config(Path::new("relative/vendor")).is_err());
}
