//! Metadata-only diagnostics; never an authority to accept a work-tree entry.

use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
use std::path::{Component, Path};

#[derive(Clone, Copy, Debug)]
pub enum EntryType {
    Directory,
    Regular,
    Symlink,
    BlockDevice,
    CharacterDevice,
    Fifo,
    Socket,
    Other,
}

#[derive(Clone, Copy)]
pub struct Observed {
    pub device: u64,
    pub uid: u32,
    pub gid: u32,
    pub kind: EntryType,
    pub nlink: u64,
}

impl From<&std::fs::Metadata> for Observed {
    fn from(metadata: &std::fs::Metadata) -> Self {
        let kind = metadata.file_type();
        Self {
            device: metadata.dev(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            nlink: metadata.nlink(),
            kind: if kind.is_dir() {
                EntryType::Directory
            } else if kind.is_file() {
                EntryType::Regular
            } else if kind.is_symlink() {
                EntryType::Symlink
            } else if kind.is_block_device() {
                EntryType::BlockDevice
            } else if kind.is_char_device() {
                EntryType::CharacterDevice
            } else if kind.is_fifo() {
                EntryType::Fifo
            } else if kind.is_socket() {
                EntryType::Socket
            } else {
                EntryType::Other
            },
        }
    }
}

#[derive(Clone, Copy)]
pub struct Expected {
    pub device: u64,
    pub candidate_uid: u32,
    pub trusted_uid: u32,
    pub candidate_gid: u32,
    pub trusted_gid: u32,
}

/// Bounded JSON with native path bytes, never file contents or host ancestors.
pub fn rejection(root: &Path, path: &Path, observed: Observed, expected: Expected) -> String {
    diagnostic(root, path, observed, expected).to_string()
}

pub fn closure_rejection(
    root: &Path,
    path: &Path,
    observed: Observed,
    expected: Expected,
    inode: u64,
    in_tree_links: u64,
) -> String {
    let mut value = diagnostic(root, path, observed, expected);
    value["reasons"]
        .as_array_mut()
        .expect("diagnostic reasons array")
        .push(serde_json::json!("hard-links-not-closed-in-tree"));
    value["observed"]["inode"] = serde_json::json!(inode);
    value["observed"]["in_tree_links"] = serde_json::json!(in_tree_links);
    value.to_string()
}

fn diagnostic(
    root: &Path,
    path: &Path,
    observed: Observed,
    expected: Expected,
) -> serde_json::Value {
    const PATH_BYTE_LIMIT: usize = 256;
    let mut reasons = Vec::new();
    if observed.device != expected.device {
        reasons.push("device-mismatch");
    }
    if observed.uid != expected.candidate_uid && observed.uid != expected.trusted_uid {
        reasons.push("uid-not-allowed");
    }
    if observed.gid != expected.candidate_gid && observed.gid != expected.trusted_gid {
        reasons.push("gid-not-allowed");
    }
    let entry_type = match observed.kind {
        EntryType::Directory => "directory",
        EntryType::Regular => {
            if observed.nlink == 0 {
                reasons.push("regular-file-link-count");
            }
            "regular-file"
        }
        kind => {
            let reason = match kind {
                EntryType::Symlink => "symlink",
                EntryType::BlockDevice => "block-device",
                EntryType::CharacterDevice => "character-device",
                EntryType::Fifo => "fifo",
                EntryType::Socket => "socket",
                EntryType::Other => "unsupported-type",
                EntryType::Directory | EntryType::Regular => unreachable!(),
            };
            reasons.push(reason);
            reasons.push("not-directory-or-regular-file");
            reason
        }
    };
    let relative = path.strip_prefix(root).ok().filter(|relative| {
        relative
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
    });
    if relative.is_none() {
        reasons.push("diagnostic-path-not-root-relative");
    }
    let bytes = relative
        .map(|relative| relative.as_os_str().as_bytes())
        .unwrap_or_default();
    let retained = &bytes[..bytes.len().min(PATH_BYTE_LIMIT)];
    serde_json::json!({
        "schema_version":1, "reasons":reasons,
        "path":{"encoding":"unix-bytes", "root_relative":relative.is_some(),
            "bytes":retained, "total_bytes":bytes.len(), "retained_bytes":retained.len(),
            "truncated":bytes.len() > retained.len()},
        "observed":{"device":observed.device,"uid":observed.uid,"gid":observed.gid,
            "entry_type":entry_type,"nlink":observed.nlink},
        "expected":{"device":expected.device,"allowed_uids":[expected.candidate_uid,expected.trusted_uid],
            "allowed_gids":[expected.candidate_gid,expected.trusted_gid],
            "entry_types":["directory","regular-file"],"regular_file_nlink":"positive-and-closed-in-tree"}
    })
}
