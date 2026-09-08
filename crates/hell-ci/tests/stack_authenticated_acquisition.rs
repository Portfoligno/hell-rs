#![cfg(unix)]

use hell_ci::stack_acquire::{
    StackIdentityProbe, inspect_protected_stack_copy, inspect_stack_destination_collision,
    inspect_stack_identity_change, validate_linux_stack_pin,
};
use std::fs;
use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "hell-stack-auth-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path.canonicalize().unwrap())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn compiled_stack_pin_is_exact_and_rejects_scope_or_byte_identity_drift() {
    let lock = include_str!("../../../ci/external-inputs.toml");
    validate_linux_stack_pin(lock).unwrap();
    hell_ci::native_environment_external_inputs_sha256_for_integration(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ci/external-inputs.toml"),
    )
    .expect("native input attestation accepts the same exact acquisition pin");
    for (from, to) in [
        ("version = \"3.11.1\"", "version = \"3.11.2\""),
        (
            "platforms = [\"linux-x86_64\"]",
            "platforms = [\"macos-aarch64\"]",
        ),
        ("exact-bytes = 94141872", "exact-bytes = 94141871"),
        ("asset-id = 446721552", "asset-id = 446721553"),
        (
            "67c66e918801c41ae4d286b1c91f9124f691c1c7d56071b53889cf4a5c667550",
            "77c66e918801c41ae4d286b1c91f9124f691c1c7d56071b53889cf4a5c667550",
        ),
    ] {
        assert!(
            validate_linux_stack_pin(&lock.replace(from, to)).is_err(),
            "accepted {from}"
        );
    }
}

#[test]
fn protected_destination_bytes_are_authenticated_and_cleanup_is_complete() {
    let fixture = Fixture::new();
    let bytes = b"untrusted transfer bytes";
    let digest = hell_testkit::sha256_bytes(bytes).hex();
    inspect_protected_stack_copy(&fixture.0, bytes, bytes.len() as u64, &digest).unwrap();
    for (data, size, expected) in [
        (
            &b"untrusted transfer byteS"[..],
            bytes.len() as u64,
            digest.as_str(),
        ),
        (&bytes[..], bytes.len() as u64 + 1, digest.as_str()),
        (&bytes[..], bytes.len() as u64 - 1, digest.as_str()),
    ] {
        assert!(inspect_protected_stack_copy(&fixture.0, data, size, expected).is_err());
    }
    assert!(fs::read_dir(&fixture.0).unwrap().next().is_none());
}

#[test]
fn exclusive_stack_destination_rejects_existing_files_and_symlinks() {
    let fixture = Fixture::new();
    let existing = fixture.0.join("existing");
    fs::write(&existing, b"preserve").unwrap();
    assert!(inspect_stack_destination_collision(&existing).is_err());
    let link = fixture.0.join("link");
    symlink(&existing, &link).unwrap();
    assert!(inspect_stack_destination_collision(&link).is_err());
    assert_eq!(fs::read(existing).unwrap(), b"preserve");
}

#[test]
fn authenticated_stack_revalidation_rejects_identity_mode_and_same_size_content_changes() {
    let fixture = Fixture::new();
    for probe in [
        StackIdentityProbe::ReplacedFile,
        StackIdentityProbe::ReplacedDirectory,
        StackIdentityProbe::ChangedMode,
        StackIdentityProbe::ChangedBytes,
    ] {
        assert!(inspect_stack_identity_change(&fixture.0, probe).is_err());
        assert!(fs::read_dir(&fixture.0).unwrap().next().is_none());
    }
}
