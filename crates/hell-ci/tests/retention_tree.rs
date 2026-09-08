#![cfg(unix)]

use hell_ci::retention_evidence::entry::Expected;
use hell_ci::retention_evidence::tree::{Inventory, Limits, validate_closed_links};
use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "hell-retention-tree-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        Self(root.canonicalize().unwrap())
    }
    fn work(&self) -> PathBuf {
        let root = self.0.join("work");
        fs::create_dir(&root).unwrap();
        root
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn expected(root: &Path) -> Expected {
    let metadata = fs::symlink_metadata(root).unwrap();
    Expected {
        device: metadata.dev(),
        candidate_uid: metadata.uid(),
        trusted_uid: metadata.uid(),
        candidate_gid: metadata.gid(),
        trusted_gid: metadata.gid(),
    }
}
fn capture(root: &Path) -> Result<Inventory, String> {
    Inventory::capture(
        root,
        &fs::symlink_metadata(root).unwrap(),
        expected(root),
        Limits {
            entries: 100,
            bytes: 1024,
        },
    )
}
fn identity(path: &Path) -> (u64, u64, u32, u32, u32, u64) {
    let metadata = fs::symlink_metadata(path).unwrap();
    (
        metadata.dev(),
        metadata.ino(),
        metadata.uid(),
        metadata.gid(),
        metadata.mode(),
        metadata.nlink(),
    )
}

#[test]
fn closed_internal_alias_groups_normalize_once_and_restore_root_mode() {
    for count in [2, 3] {
        let fixture = Fixture::new();
        let root = fixture.work();
        let target = root.join("target");
        fs::create_dir(&target).unwrap();
        for (group, mode) in [("executable", 0o755), ("data", 0o644)] {
            let file = target.join(group);
            fs::write(&file, b"fixed fixture bytes").unwrap();
            fs::set_permissions(&file, fs::Permissions::from_mode(mode)).unwrap();
            for alias in 1..count {
                fs::hard_link(&file, target.join(format!("{group}-{alias}"))).unwrap();
            }
        }
        let original_root = 0o750;
        capture(&root).unwrap().normalize(original_root).unwrap();
        assert_eq!(fs::metadata(&root).unwrap().mode() & 0o7777, original_root);
        for (group, mode) in [("executable", 0o700), ("data", 0o600)] {
            let file = target.join(group);
            let original = identity(&file);
            assert_eq!(original.4 & 0o7777, mode);
            assert_eq!(original.5, count);
            for alias in 1..count {
                assert_eq!(identity(&target.join(format!("{group}-{alias}"))), original);
            }
        }
    }
}

#[test]
fn external_alias_rejects_before_mutation_and_preserves_external_authority() {
    let fixture = Fixture::new();
    let root = fixture.work();
    let file = root.join("file");
    fs::write(&file, b"external contents").unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o640)).unwrap();
    let outside = fixture.0.join("outside");
    fs::hard_link(&file, &outside).unwrap();
    let before = identity(&outside);
    let root_before = identity(&root);
    let error = capture(&root).err().expect("external alias refused");
    assert!(error.contains("hard-links-not-closed-in-tree"), "{error}");
    assert!(error.contains("\"in_tree_links\":1"), "{error}");
    assert_eq!(identity(&outside), before);
    assert_eq!(identity(&root), root_before);
    assert_eq!(fs::read(&outside).unwrap(), b"external contents");
}

#[test]
fn changed_links_names_and_ancestor_substitution_refuse_before_mutation() {
    for case in [
        "external-link",
        "replacement",
        "new-member",
        "ancestor",
        "root",
    ] {
        let fixture = Fixture::new();
        let root = fixture.work();
        let directory = root.join("directory");
        fs::create_dir(&directory).unwrap();
        let file = directory.join("file");
        fs::write(&file, b"unchanged original").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o640)).unwrap();
        let inventory = capture(&root).unwrap();
        match case {
            "external-link" => fs::hard_link(&file, fixture.0.join("outside")).unwrap(),
            "replacement" => {
                fs::rename(&file, directory.join("old")).unwrap();
                fs::write(&file, b"replacement").unwrap();
            }
            "new-member" => {
                fs::write(directory.join("new"), b"new").unwrap();
            }
            "ancestor" => {
                let moved = fixture.0.join("moved");
                fs::rename(&directory, &moved).unwrap();
                symlink(&moved, &directory).unwrap();
            }
            "root" => {
                let moved = fixture.0.join("moved");
                fs::rename(&root, &moved).unwrap();
                symlink(&moved, &root).unwrap();
            }
            _ => unreachable!(),
        }
        let retained_path = if case == "replacement" {
            directory.join("old")
        } else if case == "ancestor" {
            fixture.0.join("moved/file")
        } else if case == "root" {
            fixture.0.join("moved/directory/file")
        } else {
            file
        };
        let before = identity(&retained_path);
        assert!(inventory.normalize(0o700).is_err(), "{case}");
        assert_eq!(identity(&retained_path), before, "{case}");
        assert_eq!(fs::read(&retained_path).unwrap(), b"unchanged original");
    }
}

#[test]
fn resource_bounds_identity_and_special_entries_remain_rejected() {
    for case in [
        "device", "uid", "gid", "entries", "bytes", "symlink", "fifo",
    ] {
        let fixture = Fixture::new();
        let root = fixture.work();
        let file = root.join("file");
        fs::write(&file, b"bounded").unwrap();
        let mut authority = expected(&root);
        let mut limits = Limits {
            entries: 100,
            bytes: 1024,
        };
        match case {
            "device" => authority.device = authority.device.checked_add(1).unwrap(),
            "uid" => {
                authority.candidate_uid = authority.candidate_uid.checked_add(1).unwrap();
                authority.trusted_uid = authority.candidate_uid;
            }
            "gid" => {
                authority.candidate_gid = authority.candidate_gid.checked_add(1).unwrap();
                authority.trusted_gid = authority.candidate_gid;
            }
            "entries" => limits.entries = 1,
            "bytes" => limits.bytes = 1,
            "symlink" => symlink(&file, root.join("link")).unwrap(),
            "fifo" => nix::unistd::mkfifo(
                &root.join("fifo"),
                nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
            )
            .unwrap(),
            _ => unreachable!(),
        }
        let before = identity(&file);
        assert!(
            Inventory::capture(
                &root,
                &fs::symlink_metadata(&root).unwrap(),
                authority,
                limits
            )
            .is_err(),
            "{case}"
        );
        assert_eq!(identity(&file), before);
    }
}

#[test]
fn closure_requires_consistent_per_inode_claims_and_positive_link_counts() {
    assert!(validate_closed_links([(1, 2, 2), (1, 2, 2), (1, 3, 1)]).is_ok());
    for entries in [
        vec![(1, 2, 2)],
        vec![(1, 2, 2), (1, 2, 3)],
        vec![(1, 2, 0)],
        vec![(1, 2, 2), (2, 2, 2)],
    ] {
        assert!(validate_closed_links(entries).is_err());
    }
}
