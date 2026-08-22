#![cfg(unix)]

use hell_testkit::{
    PosixExecutableAuthority, PosixExecutableMetadata, PosixProcessAuthorities,
    PosixProcessToolRole, revalidated_posix_process_invocation_for_integration,
    verify_posix_executable_parent_policy_for_integration,
    verify_posix_process_authorities_for_integration,
};
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
    helper: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "hell-posix-process-receipt-{}-{}",
                std::process::id(),
                NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
            ));
        fs::create_dir_all(root.join("usr/bin")).unwrap();
        fs::create_dir_all(root.join("usr/libexec")).unwrap();
        symlink(root.join("usr/bin"), root.join("bin")).unwrap();
        let helper = fs::canonicalize(env!("CARGO_BIN_EXE_hell-test-helper")).unwrap();
        for role in ["sudo", "id", "ps", "pkill"] {
            let target = root.join("usr/libexec").join(format!("{role}-target"));
            fs::copy(&helper, &target).unwrap();
            fs::set_permissions(&target, fs::Permissions::from_mode(0o555)).unwrap();
            symlink(&target, root.join("usr/bin").join(role)).unwrap();
        }
        Self { root, helper }
    }

    fn invocation(&self, name: &str) -> PathBuf {
        self.root.join("usr/bin").join(name)
    }

    fn target(&self, name: &str) -> PathBuf {
        self.root.join("usr/libexec").join(format!("{name}-target"))
    }

    fn authority(&self, role: PosixProcessToolRole, name: &str) -> PosixExecutableAuthority {
        authority(role, self.invocation(name), self.target(name))
    }

    fn authorities(&self) -> PosixProcessAuthorities {
        PosixProcessAuthorities::new(
            self.authority(PosixProcessToolRole::Sudo, "sudo"),
            self.authority(PosixProcessToolRole::Identity, "id"),
            self.authority(PosixProcessToolRole::Inventory, "ps"),
            self.authority(PosixProcessToolRole::Terminator, "pkill"),
        )
        .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

fn authority(
    role: PosixProcessToolRole,
    invocation: PathBuf,
    target: PathBuf,
) -> PosixExecutableAuthority {
    let canonical = fs::canonicalize(target).unwrap();
    let metadata = fs::metadata(&canonical).unwrap();
    PosixExecutableAuthority::new(
        role,
        invocation,
        canonical,
        PosixExecutableMetadata::new(
            metadata.dev(),
            metadata.ino(),
            metadata.uid(),
            metadata.gid(),
            metadata.mode(),
            metadata.len(),
        ),
    )
}

fn assert_predicate(error: &std::io::Error, role: &str, predicate: &str) {
    assert_eq!(
        error.to_string(),
        format!("POSIX process authority role={role} predicate={predicate}")
    );
}

#[test]
fn logical_leaf_alias_is_revalidated_and_executed_without_canonical_substitution() {
    let fixture = Fixture::new();
    let invocation = revalidated_posix_process_invocation_for_integration(
        fixture.authorities(),
        PosixProcessToolRole::Terminator,
    )
    .unwrap();
    assert_eq!(invocation, fixture.invocation("pkill"));
    assert_ne!(
        invocation.file_name(),
        fs::canonicalize(&invocation).unwrap().file_name()
    );

    let output = Command::new(invocation)
        .arg("__posix-logical-invocation-child")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"pkill\n");
}

#[test]
fn merged_usr_raw_parent_and_leaf_retarget_are_rejected_by_distinct_predicates() {
    let fixture = Fixture::new();
    let raw_inventory = authority(
        PosixProcessToolRole::Inventory,
        fixture.root.join("bin/ps"),
        fixture.target("ps"),
    );
    let raw_bundle = PosixProcessAuthorities::new(
        fixture.authority(PosixProcessToolRole::Sudo, "sudo"),
        fixture.authority(PosixProcessToolRole::Identity, "id"),
        raw_inventory,
        fixture.authority(PosixProcessToolRole::Terminator, "pkill"),
    )
    .unwrap();
    assert_predicate(
        &verify_posix_process_authorities_for_integration(raw_bundle).unwrap_err(),
        "inventory",
        "canonical-parent",
    );

    let retained = fixture.authorities();
    let alternate = fixture.root.join("usr/libexec/alternate-terminator");
    fs::copy(&fixture.helper, &alternate).unwrap();
    fs::set_permissions(&alternate, fs::Permissions::from_mode(0o555)).unwrap();
    fs::remove_file(fixture.invocation("pkill")).unwrap();
    symlink(alternate, fixture.invocation("pkill")).unwrap();
    assert_predicate(
        &verify_posix_process_authorities_for_integration(retained).unwrap_err(),
        "terminator",
        "invocation-resolves-to-target",
    );
}

#[test]
fn exact_target_inode_mode_set_id_and_length_receipts_fail_closed() {
    let inode_fixture = Fixture::new();
    let inode_receipt = inode_fixture.authorities();
    let inventory_target = inode_fixture.target("ps");
    fs::remove_file(&inventory_target).unwrap();
    fs::copy(&inode_fixture.helper, &inventory_target).unwrap();
    fs::set_permissions(&inventory_target, fs::Permissions::from_mode(0o555)).unwrap();
    assert_predicate(
        &verify_posix_process_authorities_for_integration(inode_receipt).unwrap_err(),
        "inventory",
        "inode",
    );

    let mode_fixture = Fixture::new();
    let mode_receipt = mode_fixture.authorities();
    fs::set_permissions(
        mode_fixture.target("id"),
        fs::Permissions::from_mode(0o4555),
    )
    .unwrap();
    assert_predicate(
        &verify_posix_process_authorities_for_integration(mode_receipt).unwrap_err(),
        "identity",
        "mode",
    );

    let length_fixture = Fixture::new();
    let length_receipt = length_fixture.authorities();
    fs::set_permissions(
        length_fixture.target("sudo"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    fs::OpenOptions::new()
        .append(true)
        .open(length_fixture.target("sudo"))
        .unwrap()
        .write_all(&[0])
        .unwrap();
    fs::set_permissions(
        length_fixture.target("sudo"),
        fs::Permissions::from_mode(0o555),
    )
    .unwrap();
    assert_predicate(
        &verify_posix_process_authorities_for_integration(length_receipt).unwrap_err(),
        "sudo",
        "length",
    );
}

#[test]
fn canonical_parent_logical_alias_bundle_accepts_all_fixed_roles() {
    let fixture = Fixture::new();
    verify_posix_process_authorities_for_integration(fixture.authorities()).unwrap();
    for name in ["sudo", "id", "ps", "pkill"] {
        assert_eq!(
            fixture.invocation(name).parent(),
            Some(fixture.root.join("usr/bin").as_path())
        );
        assert_ne!(
            fixture.invocation(name).file_name(),
            fixture.target(name).file_name()
        );
    }
}

#[test]
fn target_receipt_uses_canonical_target_path() {
    let fixture = Fixture::new();
    let invocation = fixture.invocation("pkill");
    let target = fixture.target("pkill");
    assert_eq!(fs::canonicalize(invocation).unwrap(), target);
    assert!(Path::new(&target).is_absolute());
}

#[test]
fn canonical_parent_substitution_and_writable_mode_are_rejected() {
    let substitution = Fixture::new();
    let retained = substitution.authorities();
    let parent = substitution.root.join("usr/bin");
    fs::rename(&parent, substitution.root.join("usr/bin-retired")).unwrap();
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o755)).unwrap();
    for role in ["sudo", "id", "ps", "pkill"] {
        symlink(substitution.target(role), parent.join(role)).unwrap();
    }
    assert_predicate(
        &verify_posix_process_authorities_for_integration(retained).unwrap_err(),
        "sudo",
        "parent-inode",
    );

    let writable = Fixture::new();
    fs::set_permissions(
        writable.root.join("usr/bin"),
        fs::Permissions::from_mode(0o775),
    )
    .unwrap();
    assert_predicate(
        &verify_posix_process_authorities_for_integration(writable.authorities()).unwrap_err(),
        "sudo",
        "parent-non-owner-write",
    );
}

#[test]
fn canonical_parent_owner_policy_rejects_untrusted_principal() {
    let fixture = Fixture::new();
    let metadata = fs::metadata(fixture.root.join("usr/bin")).unwrap();
    verify_posix_executable_parent_policy_for_integration(metadata.uid(), metadata.mode()).unwrap();
    let foreign_owner = [1_u32, 2, 3]
        .into_iter()
        .find(|owner| *owner != 0 && *owner != metadata.uid())
        .unwrap();
    assert_eq!(
        verify_posix_executable_parent_policy_for_integration(foreign_owner, metadata.mode()),
        Err("parent-trusted-owner")
    );
}
