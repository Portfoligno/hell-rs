//! Closed-in-tree inode authority for quiescent candidate output retention.
//!
//! Capture and revalidate the complete topology before any mutation. All opens
//! are descriptor-relative and no-follow. Mutation happens once per inode;
//! every captured pathname is subsequently attested. Candidate quiescence is
//! a caller prerequisite, not inferred from a successful filesystem scan.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs::{File, Metadata};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path, PathBuf};

use super::entry::{self, EntryType, Expected, Observed};
use rustix::fs::{Mode, OFlags};

#[derive(Debug, PartialEq, Eq)]
pub struct LinkMismatch {
    pub device: u64,
    pub inode: u64,
    pub expected: u64,
    pub observed: u64,
}

/// The same closed-alias rule is used by target export and work retention.
pub fn validate_closed_links(
    entries: impl IntoIterator<Item = (u64, u64, u64)>,
) -> Result<(), LinkMismatch> {
    let mut groups = BTreeMap::<(u64, u64), (u64, Vec<u64>)>::new();
    for (device, inode, links) in entries {
        let (count, claims) = groups.entry((device, inode)).or_default();
        *count = count
            .checked_add(1)
            .expect("bounded inventory count fits u64");
        claims.push(links);
    }
    for ((device, inode), (observed, claims)) in groups {
        for expected in claims {
            if expected == 0 || expected != observed {
                return Err(LinkMismatch {
                    device,
                    inode,
                    expected,
                    observed,
                });
            }
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
pub struct Limits {
    pub entries: usize,
    pub bytes: u64,
}

struct Captured {
    metadata: Metadata,
    children: Option<BTreeSet<OsString>>,
}

pub struct Inventory {
    root: PathBuf,
    descriptor: File,
    entries: BTreeMap<PathBuf, Captured>,
    expected: Expected,
    limits: Limits,
}

fn open_flags(directory: bool) -> OFlags {
    OFlags::RDONLY
        | OFlags::CLOEXEC
        | OFlags::NOFOLLOW
        | OFlags::NONBLOCK
        | if directory {
            OFlags::DIRECTORY
        } else {
            OFlags::empty()
        }
}

fn same(before: &Metadata, after: &Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.nlink() == after.nlink()
        && before.mode() == after.mode()
        && before.uid() == after.uid()
        && before.gid() == after.gid()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

fn names(file: &File, limit: usize) -> Result<BTreeSet<OsString>, String> {
    let mut names = BTreeSet::new();
    let mut directory = rustix::fs::Dir::read_from(file)
        .map_err(|error| format!("cannot enumerate retained directory descriptor: {error}"))?;
    for item in &mut directory {
        let item =
            item.map_err(|error| format!("cannot read retained directory member: {error}"))?;
        let bytes = item.file_name().to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        if names.len() >= limit {
            return Err("Linux MemCordon work tree exceeds its entry bound".to_owned());
        }
        if !names.insert(OsStr::from_bytes(bytes).to_owned()) {
            return Err("Linux MemCordon work directory contains duplicate names".to_owned());
        }
    }
    Ok(names)
}

impl Inventory {
    pub fn capture(
        root: &Path,
        root_metadata: &Metadata,
        expected: Expected,
        limits: Limits,
    ) -> Result<Self, String> {
        let descriptor = File::from(
            rustix::fs::open(root, open_flags(true), Mode::empty())
                .map_err(|error| format!("cannot bind retained work root descriptor: {error}"))?,
        );
        if !same(
            root_metadata,
            &descriptor.metadata().map_err(|error| error.to_string())?,
        ) {
            return Err("Linux MemCordon work root changed before capture".to_owned());
        }
        let mut inventory = Self {
            root: root.to_owned(),
            descriptor,
            entries: BTreeMap::new(),
            expected,
            limits,
        };
        let mut pending = vec![PathBuf::new()];
        let mut bytes = 0_u64;
        while let Some(relative) = pending.pop() {
            if inventory.entries.len() >= limits.entries {
                return Err("Linux MemCordon work tree exceeds its entry bound".to_owned());
            }
            let file = inventory.open(&relative)?;
            let metadata = file.metadata().map_err(|error| error.to_string())?;
            let observed = Observed::from(&metadata);
            if observed.device != expected.device
                || (observed.uid != expected.candidate_uid && observed.uid != expected.trusted_uid)
                || (observed.gid != expected.candidate_gid && observed.gid != expected.trusted_gid)
                || !matches!(observed.kind, EntryType::Directory | EntryType::Regular)
                || (matches!(observed.kind, EntryType::Regular) && observed.nlink == 0)
            {
                return Err(format!(
                    "Linux MemCordon work tree contains an unauthenticated entry: {}",
                    entry::rejection(root, &root.join(&relative), observed, expected)
                ));
            }
            bytes = bytes
                .checked_add(if metadata.is_file() {
                    metadata.len()
                } else {
                    0
                })
                .filter(|bytes| *bytes <= limits.bytes)
                .ok_or_else(|| "Linux MemCordon work tree exceeds its byte bound".to_owned())?;
            let children = if metadata.is_dir() {
                let children = names(&file, limits.entries)?;
                if inventory
                    .entries
                    .len()
                    .checked_add(pending.len())
                    .and_then(|count| count.checked_add(children.len()))
                    .is_none_or(|count| count >= limits.entries)
                    && !children.is_empty()
                {
                    return Err("Linux MemCordon work tree exceeds its entry bound".to_owned());
                }
                pending.extend(children.iter().rev().map(|name| relative.join(name)));
                Some(children)
            } else {
                None
            };
            inventory
                .entries
                .insert(relative, Captured { metadata, children });
        }
        inventory.require_closed()?;
        inventory.revalidate()?;
        Ok(inventory)
    }

    fn open(&self, relative: &Path) -> Result<File, String> {
        let mut file = self
            .descriptor
            .try_clone()
            .map_err(|error| error.to_string())?;
        let mut components = relative.components().peekable();
        let mut traversed = PathBuf::new();
        while let Some(component) = components.next() {
            let Component::Normal(name) = component else {
                return Err("retained work path is not root-relative".to_owned());
            };
            traversed.push(name);
            let stat = rustix::fs::statat(&file, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|error| {
                    format!("cannot inspect no-follow retained work member: {error}")
                })?;
            let kind = match stat.st_mode as u32 & nix::libc::S_IFMT as u32 {
                value if value == nix::libc::S_IFDIR as u32 => EntryType::Directory,
                value if value == nix::libc::S_IFREG as u32 => EntryType::Regular,
                value if value == nix::libc::S_IFLNK as u32 => EntryType::Symlink,
                value if value == nix::libc::S_IFBLK as u32 => EntryType::BlockDevice,
                value if value == nix::libc::S_IFCHR as u32 => EntryType::CharacterDevice,
                value if value == nix::libc::S_IFIFO as u32 => EntryType::Fifo,
                value if value == nix::libc::S_IFSOCK as u32 => EntryType::Socket,
                _ => EntryType::Other,
            };
            let observed = Observed {
                device: stat.st_dev as u64,
                uid: stat.st_uid,
                gid: stat.st_gid,
                kind,
                nlink: stat.st_nlink as u64,
            };
            if !matches!(kind, EntryType::Directory | EntryType::Regular)
                || observed.device != self.expected.device
                || (observed.uid != self.expected.candidate_uid
                    && observed.uid != self.expected.trusted_uid)
                || (observed.gid != self.expected.candidate_gid
                    && observed.gid != self.expected.trusted_gid)
                || (matches!(kind, EntryType::Regular) && observed.nlink == 0)
            {
                return Err(format!(
                    "Linux MemCordon work tree contains an unauthenticated entry: {}",
                    entry::rejection(
                        &self.root,
                        &self.root.join(&traversed),
                        observed,
                        self.expected
                    )
                ));
            }
            file = File::from(
                rustix::fs::openat(
                    &file,
                    name,
                    open_flags(components.peek().is_some() || matches!(kind, EntryType::Directory)),
                    Mode::empty(),
                )
                .map_err(|error| format!("cannot open no-follow retained work member: {error}"))?,
            );
            let opened = file.metadata().map_err(|error| error.to_string())?;
            if opened.dev() != observed.device
                || opened.ino() != stat.st_ino as u64
                || opened.mode() != stat.st_mode as u32
                || opened.uid() != observed.uid
                || opened.gid() != observed.gid
                || opened.nlink() != observed.nlink
            {
                return Err(
                    "Linux MemCordon work member changed between inspection and descriptor binding"
                        .to_owned(),
                );
            }
            if self.entries.get(&traversed).is_some_and(|entry| {
                entry.metadata.dev() != opened.dev()
                    || entry.metadata.ino() != opened.ino()
                    || entry.metadata.file_type() != opened.file_type()
            }) {
                return Err("Linux MemCordon work path identity changed".to_owned());
            }
        }
        Ok(file)
    }

    fn require_closed(&self) -> Result<(), String> {
        validate_closed_links(
            self.entries
                .values()
                .filter(|entry| entry.metadata.is_file())
                .map(|entry| {
                    (
                        entry.metadata.dev(),
                        entry.metadata.ino(),
                        entry.metadata.nlink(),
                    )
                }),
        )
        .map_err(|mismatch| {
            let (relative, captured) = self
                .entries
                .iter()
                .find(|(_, entry)| {
                    entry.metadata.dev() == mismatch.device
                        && entry.metadata.ino() == mismatch.inode
                })
                .expect("mismatched inode has a captured pathname");
            format!(
                "Linux MemCordon work tree contains an unauthenticated entry: {}",
                entry::closure_rejection(
                    &self.root,
                    &self.root.join(relative),
                    Observed::from(&captured.metadata),
                    self.expected,
                    mismatch.inode,
                    mismatch.observed
                )
            )
        })
    }

    pub fn revalidate(&self) -> Result<(), String> {
        let root = std::fs::symlink_metadata(&self.root).map_err(|error| error.to_string())?;
        if !same(&self.entries[Path::new("")].metadata, &root) {
            return Err("Linux MemCordon work root changed before retention".to_owned());
        }
        for (relative, captured) in &self.entries {
            let file = self.open(relative)?;
            if !same(
                &captured.metadata,
                &file.metadata().map_err(|error| error.to_string())?,
            ) {
                return Err(
                    "Linux MemCordon work entry identity or link count changed before retention"
                        .to_owned(),
                );
            }
            if let Some(expected_names) = &captured.children {
                if names(&file, self.limits.entries)? != *expected_names {
                    return Err(
                        "Linux MemCordon work directory membership changed before retention"
                            .to_owned(),
                    );
                }
            }
        }
        self.require_closed()
    }

    pub fn normalize(self, original_root_mode: u32) -> Result<(), String> {
        if original_root_mode > 0o7777 {
            return Err("retained root mode exceeds permission bits".to_owned());
        }
        self.revalidate()?;
        let mut entries = self.entries.iter().collect::<Vec<_>>();
        entries.sort_by_key(|(path, _)| std::cmp::Reverse(path.components().count()));
        let mut normalized = BTreeSet::new();
        for (relative, captured) in &entries {
            let before = &captured.metadata;
            if !normalized.insert((before.dev(), before.ino())) {
                continue;
            }
            let file = self.open(relative)?;
            if !same(before, &file.metadata().map_err(|error| error.to_string())?) {
                return Err(
                    "Linux MemCordon work entry changed immediately before retention".to_owned(),
                );
            }
            rustix::fs::fchown(
                &file,
                Some(rustix::fs::Uid::from_raw(self.expected.trusted_uid)),
                Some(rustix::fs::Gid::from_raw(self.expected.trusted_gid)),
            )
            .map_err(|error| format!("cannot retain Linux MemCordon work ownership: {error}"))?;
            rustix::fs::fchmod(
                &file,
                Mode::from_bits_retain(
                    self.retained_mode(relative, before, original_root_mode)
                        .try_into()
                        .map_err(|_| "retained root mode is not representable".to_owned())?,
                ),
            )
            .map_err(|error| format!("cannot retain Linux MemCordon work permissions: {error}"))?;
        }
        for (relative, captured) in &entries {
            let file = self.open(relative)?;
            let after = file.metadata().map_err(|error| error.to_string())?;
            let before = &captured.metadata;
            if after.dev() != before.dev()
                || after.ino() != before.ino()
                || after.nlink() != before.nlink()
                || after.file_type() != before.file_type()
                || after.uid() != self.expected.trusted_uid
                || after.gid() != self.expected.trusted_gid
                || after.mode() & 0o7777 != self.retained_mode(relative, before, original_root_mode)
                || (after.is_file()
                    && (after.len() != before.len()
                        || after.mtime() != before.mtime()
                        || after.mtime_nsec() != before.mtime_nsec()))
            {
                return Err("retained Linux MemCordon work entry differs".to_owned());
            }
            if let Some(expected_names) = &captured.children {
                if names(&file, self.limits.entries)? != *expected_names {
                    return Err(
                        "retained Linux MemCordon work directory membership differs".to_owned()
                    );
                }
            }
        }
        let root = std::fs::symlink_metadata(&self.root).map_err(|error| error.to_string())?;
        if !same(
            &self
                .descriptor
                .metadata()
                .map_err(|error| error.to_string())?,
            &root,
        ) {
            return Err("retained Linux MemCordon work root path differs".to_owned());
        }
        Ok(())
    }

    fn retained_mode(&self, relative: &Path, metadata: &Metadata, root_mode: u32) -> u32 {
        if relative.as_os_str().is_empty() {
            root_mode
        } else if metadata.is_dir() || metadata.mode() & 0o111 != 0 {
            0o700
        } else {
            0o600
        }
    }
}
