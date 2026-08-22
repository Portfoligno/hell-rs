use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read as _, Write};
use std::path::{Component, Path, PathBuf};

use flate2::{Compression, Decompress, FlushDecompress, GzBuilder, Status, read::GzDecoder};
use tar::{Archive, Builder, EntryType, Header};

use super::manifest::{read_regular, write_atomic};
use super::schema::ReleasePlatform;

const EVIDENCE_DIRECTORIES: [&str; 3] = ["observations", "platform-manifests", "records"];
const MAX_EVIDENCE_ENTRIES: usize = 100_000;
const MAX_EVIDENCE_ENTRY_BYTES: u64 = 8 * 1024 * 1024;
const MAX_EVIDENCE_ARCHIVE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_EVIDENCE_COMPRESSED_BYTES: u64 = 256 * 1024 * 1024;
const MAX_PACKAGE_COMPRESSED_BYTES: u64 = 256 * 1024 * 1024;
const MAX_PACKAGE_UNCOMPRESSED_BYTES: u64 = 256 * 1024 * 1024;

pub(crate) struct ArchiveInput<'a> {
    pub platform: ReleasePlatform,
    pub version: &'a str,
    pub source_date_epoch: u64,
    pub executable: &'a Path,
    pub license: &'a [u8],
    pub notice: &'a [u8],
    pub readme: &'a [u8],
    pub output: &'a Path,
}

pub(crate) fn create(input: &ArchiveInput<'_>) -> Result<String, String> {
    let prefix = format!("hell-v{}-{}/", input.version, input.platform.id());
    let mut compressed = Vec::new();
    {
        let encoder = GzBuilder::new()
            .mtime(0)
            .operating_system(255)
            .write(&mut compressed, Compression::new(9));
        let mut builder = Builder::new(encoder);
        builder.mode(tar::HeaderMode::Deterministic);
        let conformance = b"Conformance is evaluated by trusted release automation. See conformance-report.json, conformance-acceptance.json, and conformance-evidence.tar.gz in the release bundle.\n";
        let mut entries = vec![
            ArchiveEntry::Directory(prefix.trim_end_matches('/').to_owned()),
            ArchiveEntry::Bytes(format!("{prefix}LICENSE"), input.license, 0o644),
            ArchiveEntry::Bytes(format!("{prefix}NOTICE"), input.notice, 0o644),
            ArchiveEntry::Bytes(format!("{prefix}README.md"), input.readme, 0o644),
            ArchiveEntry::Bytes(format!("{prefix}CONFORMANCE.md"), conformance, 0o644),
            ArchiveEntry::Directory(format!("{prefix}bin")),
            ArchiveEntry::File(
                format!("{prefix}bin/{}", input.platform.executable()),
                input.executable.to_path_buf(),
                0o755,
            ),
        ];
        entries.sort_by(|left, right| left.path().cmp(right.path()));
        for entry in entries {
            match entry {
                ArchiveEntry::Directory(path) => {
                    append_directory(&mut builder, &path, input.source_date_epoch)?;
                }
                ArchiveEntry::File(path, source, mode) => {
                    append_file(&mut builder, &path, &source, mode, input.source_date_epoch)?;
                }
                ArchiveEntry::Bytes(path, bytes, mode) => {
                    append_bytes(&mut builder, &path, bytes, mode, input.source_date_epoch)?;
                }
            }
        }
        builder
            .finish()
            .map_err(|error| format!("cannot finish release tar: {error}"))?;
        builder
            .into_inner()
            .map_err(|error| format!("cannot finish release gzip: {error}"))?
            .finish()
            .map_err(|error| format!("cannot close release gzip: {error}"))?;
    }
    write_atomic(input.output, &compressed)?;
    verify(
        input.output,
        input.platform,
        input.version,
        input.source_date_epoch,
    )?;
    Ok(hell_testkit::sha256_bytes(&compressed).hex())
}

pub(crate) fn verify(
    path: &Path,
    platform: ReleasePlatform,
    version: &str,
    epoch: u64,
) -> Result<(), String> {
    let bytes = bounded_package_bytes(path)?;
    let mut archive = Archive::new(GzDecoder::new(bytes.as_slice()));
    let prefix = format!("hell-v{version}-{}/", platform.id());
    let expected = package_entry_inventory(&prefix, platform);
    let mut observed = BTreeSet::new();
    let mut payloads = BTreeMap::new();
    let mut total_payload = 0_u64;
    for entry in archive
        .entries()
        .map_err(|error| format!("cannot enumerate release archive: {error}"))?
    {
        let mut entry =
            entry.map_err(|error| format!("cannot inspect release archive entry: {error}"))?;
        let kind = entry.header().entry_type();
        if !matches!(kind, EntryType::Regular | EntryType::Directory) {
            return Err("release archive contains a link or special entry".to_owned());
        }
        let path = entry
            .path()
            .map_err(|error| format!("release archive path is invalid: {error}"))?;
        let text = path
            .to_str()
            .ok_or_else(|| "release archive path is not UTF-8".to_owned())?
            .to_owned();
        validate_archive_path(&text)?;
        if !observed.insert(text.clone()) {
            return Err("release archive contains duplicate paths".to_owned());
        }
        let header = entry.header();
        let size = header
            .size()
            .map_err(|_| "archive entry size is invalid".to_owned())?;
        if (kind.is_dir() && size != 0) || (kind.is_file() && size > 128 * 1024 * 1024) {
            return Err("release archive entry size exceeds its canonical bound".to_owned());
        }
        total_payload = total_payload
            .checked_add(size)
            .ok_or_else(|| "release archive payload size overflow".to_owned())?;
        if total_payload > 256 * 1024 * 1024 {
            return Err("release archive cumulative payload exceeds its bound".to_owned());
        }
        if header
            .uid()
            .map_err(|_| "archive UID is invalid".to_owned())?
            != 0
            || header
                .gid()
                .map_err(|_| "archive GID is invalid".to_owned())?
                != 0
            || header
                .mtime()
                .map_err(|_| "archive mtime is invalid".to_owned())?
                != epoch
        {
            return Err("release archive metadata is not canonical".to_owned());
        }
        let username = header
            .username()
            .map_err(|_| "archive username is invalid".to_owned())?;
        let groupname = header
            .groupname()
            .map_err(|_| "archive group name is invalid".to_owned())?;
        if username.is_some_and(|name| !name.is_empty())
            || groupname.is_some_and(|name| !name.is_empty())
        {
            return Err("release archive user/group names are not empty".to_owned());
        }
        let expected_mode = if kind.is_dir() || text.ends_with(platform.executable()) {
            0o755
        } else {
            0o644
        };
        if header
            .mode()
            .map_err(|_| "archive mode is invalid".to_owned())?
            != expected_mode
        {
            return Err("release archive mode is not canonical".to_owned());
        }
        if kind.is_file() {
            let mut sink = Vec::with_capacity(
                usize::try_from(size)
                    .map_err(|_| "release archive entry size exceeds memory bounds".to_owned())?,
            );
            entry
                .read_to_end(&mut sink)
                .map_err(|error| format!("cannot read archive payload: {error}"))?;
            payloads.insert(text, sink);
        }
    }
    if observed != expected {
        return Err(format!(
            "release archive exact entry set differs: {observed:?}"
        ));
    }
    let canonical = canonical_archive_bytes(platform, version, epoch, &payloads)?;
    if bytes != canonical {
        return Err("release archive bytes are not in the canonical serialization".to_owned());
    }
    Ok(())
}

fn package_entry_inventory(prefix: &str, platform: ReleasePlatform) -> BTreeSet<String> {
    BTreeSet::from([
        prefix.trim_end_matches('/').to_owned(),
        format!("{prefix}LICENSE"),
        format!("{prefix}NOTICE"),
        format!("{prefix}README.md"),
        format!("{prefix}CONFORMANCE.md"),
        format!("{prefix}bin"),
        format!("{prefix}bin/{}", platform.executable()),
    ])
}

fn bounded_package_bytes(path: &Path) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect release archive: {error}"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_PACKAGE_COMPRESSED_BYTES
    {
        return Err("release archive is not a bounded regular file".to_owned());
    }
    let bytes = read_regular(path)?;
    if bytes.len() < 18 || bytes[..10] != [0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 2, 255] {
        return Err("release gzip header is not canonical".to_owned());
    }
    verify_single_gzip_member(&bytes, MAX_PACKAGE_UNCOMPRESSED_BYTES)?;
    Ok(bytes)
}

fn canonical_archive_bytes(
    platform: ReleasePlatform,
    version: &str,
    epoch: u64,
    payloads: &BTreeMap<String, Vec<u8>>,
) -> Result<Vec<u8>, String> {
    let prefix = format!("hell-v{version}-{}/", platform.id());
    let directories = [
        prefix.trim_end_matches('/').to_owned(),
        format!("{prefix}bin"),
    ];
    let mut entries = directories
        .into_iter()
        .map(|path| (path, None))
        .chain(
            payloads
                .iter()
                .map(|(path, bytes)| (path.clone(), Some(bytes))),
        )
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    let mut compressed = Vec::new();
    {
        let encoder = GzBuilder::new()
            .mtime(0)
            .operating_system(255)
            .write(&mut compressed, Compression::new(9));
        let mut builder = Builder::new(encoder);
        builder.mode(tar::HeaderMode::Deterministic);
        for (path, payload) in entries {
            if let Some(payload) = payload {
                let mode = if path.ends_with(platform.executable()) {
                    0o755
                } else {
                    0o644
                };
                append_bytes(&mut builder, &path, payload, mode, epoch)?;
            } else {
                append_directory(&mut builder, &path, epoch)?;
            }
        }
        builder
            .finish()
            .map_err(|error| format!("cannot finish canonical release tar: {error}"))?;
        builder
            .into_inner()
            .map_err(|error| format!("cannot finish canonical release gzip: {error}"))?
            .finish()
            .map_err(|error| format!("cannot close canonical release gzip: {error}"))?;
    }
    Ok(compressed)
}

fn verify_single_gzip_member(bytes: &[u8], maximum_output: u64) -> Result<(), String> {
    let mut decoder = Decompress::new(false);
    let mut input = bytes
        .get(10..bytes.len().saturating_sub(8))
        .ok_or_else(|| "release gzip is truncated".to_owned())?;
    let mut output = [0_u8; 16 * 1024];
    loop {
        let before_in = decoder.total_in();
        let before_out = decoder.total_out();
        let status = decoder
            .decompress(input, &mut output, FlushDecompress::None)
            .map_err(|error| format!("release gzip stream is invalid: {error}"))?;
        let consumed = usize::try_from(decoder.total_in() - before_in)
            .map_err(|_| "gzip input count overflow".to_owned())?;
        if decoder.total_out() > maximum_output {
            return Err("gzip decompressed output exceeds its bound".to_owned());
        }
        input = input
            .get(consumed..)
            .ok_or_else(|| "gzip consumed beyond its input".to_owned())?;
        match status {
            Status::StreamEnd if input.is_empty() => return Ok(()),
            Status::StreamEnd => {
                return Err("release gzip has trailing bytes or another member".to_owned());
            }
            Status::BufError if consumed == 0 && decoder.total_out() == before_out => {
                return Err("release gzip stream did not terminate".to_owned());
            }
            Status::Ok | Status::BufError => {}
        }
    }
}

pub(crate) fn extract_binary(
    path: &Path,
    platform: ReleasePlatform,
    version: &str,
    epoch: u64,
    output: &Path,
) -> Result<PathBuf, String> {
    verify(path, platform, version, epoch)?;
    if output.exists() {
        return Err("archive extraction directory already exists".to_owned());
    }
    fs::create_dir(output)
        .map_err(|error| format!("cannot create extraction directory: {error}"))?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect release archive: {error}"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_PACKAGE_COMPRESSED_BYTES
    {
        return Err("release archive is not a bounded regular file".to_owned());
    }
    let bytes = read_regular(path)?;
    let mut archive = Archive::new(GzDecoder::new(bytes.as_slice()));
    let expected = format!(
        "hell-v{version}-{}/bin/{}",
        platform.id(),
        platform.executable()
    );
    let destination = output.join(platform.executable());
    let mut found = false;
    for entry in archive
        .entries()
        .map_err(|error| format!("cannot enumerate release archive: {error}"))?
    {
        let mut entry =
            entry.map_err(|error| format!("cannot inspect release archive: {error}"))?;
        let path = entry
            .path()
            .map_err(|error| format!("invalid archive path: {error}"))?;
        if path.to_str() == Some(expected.as_str()) {
            if found || !entry.header().entry_type().is_file() {
                return Err("archive executable entry is invalid".to_owned());
            }
            let size = entry
                .header()
                .size()
                .map_err(|_| "archive executable size is invalid".to_owned())?;
            if size > 128 * 1024 * 1024 {
                return Err("archive executable exceeds the extraction bound".to_owned());
            }
            let mut bytes = Vec::with_capacity(
                usize::try_from(size).map_err(|_| "archive executable is too large".to_owned())?,
            );
            entry
                .read_to_end(&mut bytes)
                .map_err(|error| format!("cannot read archive executable: {error}"))?;
            write_atomic(&destination, &bytes)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                fs::set_permissions(&destination, fs::Permissions::from_mode(0o755))
                    .map_err(|error| format!("cannot set extracted executable mode: {error}"))?;
            }
            found = true;
        }
    }
    if !found {
        return Err("release archive executable is missing".to_owned());
    }
    Ok(destination)
}

/// Writes the canonical raw-evidence transport used by assembly and the
/// publisher. `members` contains regular-file paths only; directory entries
/// are supplied here so producers cannot influence archive metadata.
pub(crate) fn create_evidence(
    path: &Path,
    epoch: u64,
    members: &BTreeMap<String, Vec<u8>>,
) -> Result<String, String> {
    validate_evidence_members(members)?;
    let bytes = canonical_evidence_bytes(epoch, members)?;
    write_atomic(path, &bytes)?;
    let reparsed = read_evidence(path, epoch)?;
    if &reparsed != members {
        return Err("conformance evidence archive changed during verification".to_owned());
    }
    Ok(hell_testkit::sha256_bytes(&bytes).hex())
}

/// Safely reads and canonicality-checks the raw-evidence transport. No archive
/// entry is written to disk before its type, path, metadata, and size are
/// accepted.
pub(crate) fn read_evidence(path: &Path, epoch: u64) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let bytes = bounded_evidence_bytes(path)?;
    let mut archive = Archive::new(GzDecoder::new(bytes.as_slice()));
    let mut observed = BTreeSet::new();
    let mut members = BTreeMap::new();
    let mut total = 0_u64;
    let mut count = 0_usize;
    for entry in archive
        .entries()
        .map_err(|error| format!("cannot enumerate conformance evidence archive: {error}"))?
    {
        count = count
            .checked_add(1)
            .ok_or_else(|| "conformance evidence entry count overflow".to_owned())?;
        if count > MAX_EVIDENCE_ENTRIES.saturating_add(EVIDENCE_DIRECTORIES.len()) {
            return Err("conformance evidence archive has too many entries".to_owned());
        }
        let mut entry = entry
            .map_err(|error| format!("cannot inspect conformance evidence archive: {error}"))?;
        let kind = entry.header().entry_type();
        if !matches!(kind, EntryType::Regular | EntryType::Directory) {
            return Err("conformance evidence archive contains a link or special entry".to_owned());
        }
        let name = entry
            .path()
            .map_err(|error| format!("invalid conformance evidence archive path: {error}"))?
            .to_str()
            .ok_or_else(|| "conformance evidence archive path is not UTF-8".to_owned())?
            .to_owned();
        validate_archive_path(&name)?;
        if !observed.insert(name.clone()) {
            return Err("conformance evidence archive contains duplicate paths".to_owned());
        }
        let size = entry
            .header()
            .size()
            .map_err(|_| "conformance evidence entry size is invalid".to_owned())?;
        if (kind.is_dir() && size != 0) || (kind.is_file() && size > MAX_EVIDENCE_ENTRY_BYTES) {
            return Err("conformance evidence entry exceeds its canonical bound".to_owned());
        }
        total = total
            .checked_add(size)
            .ok_or_else(|| "conformance evidence archive size overflow".to_owned())?;
        if total > MAX_EVIDENCE_ARCHIVE_BYTES {
            return Err("conformance evidence archive exceeds its uncompressed bound".to_owned());
        }
        validate_evidence_header(entry.header(), kind, epoch)?;
        if kind.is_dir() {
            if !EVIDENCE_DIRECTORIES.contains(&name.as_str()) {
                return Err("conformance evidence archive has an unexpected directory".to_owned());
            }
        } else {
            let mut payload = Vec::with_capacity(
                usize::try_from(size)
                    .map_err(|_| "conformance evidence entry is too large".to_owned())?,
            );
            entry
                .read_to_end(&mut payload)
                .map_err(|error| format!("cannot read conformance evidence entry: {error}"))?;
            members.insert(name, payload);
        }
    }
    if !EVIDENCE_DIRECTORIES
        .iter()
        .all(|name| observed.contains(*name))
    {
        return Err("conformance evidence archive directory set differs".to_owned());
    }
    validate_evidence_members(&members)?;
    if canonical_evidence_bytes(epoch, &members)? != bytes {
        return Err("conformance evidence archive bytes are not canonical".to_owned());
    }
    Ok(members)
}

fn bounded_evidence_bytes(path: &Path) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect conformance evidence archive: {error}"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_EVIDENCE_COMPRESSED_BYTES
    {
        return Err("conformance evidence archive is not a bounded regular file".to_owned());
    }
    let bytes = read_regular(path)?;
    if bytes.len() < 18 || bytes[..10] != [0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 2, 255] {
        return Err("conformance evidence gzip header is not canonical".to_owned());
    }
    verify_single_gzip_member(&bytes, MAX_EVIDENCE_ARCHIVE_BYTES)?;
    Ok(bytes)
}

fn validate_evidence_header(header: &Header, kind: EntryType, epoch: u64) -> Result<(), String> {
    if header.uid().map_err(|_| "invalid evidence UID")? != 0
        || header.gid().map_err(|_| "invalid evidence GID")? != 0
        || header.mtime().map_err(|_| "invalid evidence mtime")? != epoch
        || header.mode().map_err(|_| "invalid evidence mode")?
            != if kind.is_dir() { 0o755 } else { 0o644 }
        || header
            .username()
            .map_err(|_| "invalid evidence username")?
            .is_some_and(|value| !value.is_empty())
        || header
            .groupname()
            .map_err(|_| "invalid evidence group name")?
            .is_some_and(|value| !value.is_empty())
    {
        return Err("conformance evidence archive metadata is not canonical".to_owned());
    }
    Ok(())
}

pub(crate) fn evidence_diagnostic(path: &Path, epoch: u64) -> Option<&'static str> {
    let bytes = read_regular(path).ok()?;
    classify_evidence_transport(&bytes, epoch).err()
}

fn classify_evidence_transport(bytes: &[u8], epoch: u64) -> Result<(), &'static str> {
    const GZIP_HEADER: [u8; 10] = [0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 2, 255];
    if bytes.len() < GZIP_HEADER.len().saturating_add(8)
        || bytes[..GZIP_HEADER.len()] != GZIP_HEADER
    {
        return Err("release.archive.gzip-header");
    }
    let trailer_start = bytes
        .len()
        .checked_sub(8)
        .ok_or("release.archive.gzip-header")?;
    let expanded_size = u32::from_le_bytes(
        bytes[trailer_start + 4..]
            .try_into()
            .map_err(|_| "release.archive.gzip-header")?,
    );
    if u64::from(expanded_size) > MAX_EVIDENCE_ARCHIVE_BYTES {
        return Err("release.limit.archive-expanded");
    }
    let mut decoder = Decompress::new(false);
    let mut input = &bytes[GZIP_HEADER.len()..trailer_start];
    let capacity = usize::try_from(expanded_size).map_err(|_| "release.limit.archive-expanded")?;
    let mut expanded = Vec::with_capacity(capacity);
    let mut scratch = [0_u8; 16 * 1024];
    loop {
        let before_input = decoder.total_in();
        let before_output = decoder.total_out();
        let status = decoder
            .decompress(input, &mut scratch, FlushDecompress::None)
            .map_err(|_| "release.archive.gzip-stream")?;
        let consumed = usize::try_from(decoder.total_in() - before_input)
            .map_err(|_| "release.archive.gzip-stream")?;
        let produced = usize::try_from(decoder.total_out() - before_output)
            .map_err(|_| "release.limit.archive-expanded")?;
        expanded.extend_from_slice(&scratch[..produced]);
        if u64::try_from(expanded.len()).map_err(|_| "release.limit.archive-expanded")?
            > MAX_EVIDENCE_ARCHIVE_BYTES
        {
            return Err("release.limit.archive-expanded");
        }
        input = input.get(consumed..).ok_or("release.archive.gzip-stream")?;
        match status {
            Status::StreamEnd if input.is_empty() => break,
            Status::StreamEnd => return Err("release.archive.trailing-gzip-member"),
            Status::BufError if consumed == 0 && produced == 0 => {
                return Err("release.archive.gzip-stream");
            }
            Status::Ok | Status::BufError => {}
        }
    }
    if expanded.len() != capacity {
        return Err("release.archive.gzip-stream");
    }
    classify_evidence_tar(&expanded, epoch)
}

fn classify_evidence_tar(bytes: &[u8], epoch: u64) -> Result<(), &'static str> {
    const TAR_BLOCK: usize = 512;
    if bytes.len() < TAR_BLOCK.saturating_mul(2) || !bytes.len().is_multiple_of(TAR_BLOCK) {
        return Err("release.archive.tar-framing");
    }
    let required = BTreeSet::from([
        "conformance-plan.json",
        "platform-manifests/linux-x86_64.json",
        "platform-manifests/macos-aarch64.json",
        "platform-manifests/windows-x86_64.json",
        "source-inventory.json",
        "trusted-conformance-inputs.json",
    ]);
    let mut offset = 0_usize;
    let mut paths = BTreeSet::new();
    let mut ended = false;
    while let Some(header) = bytes.get(offset..offset.saturating_add(TAR_BLOCK)) {
        if header.iter().all(|byte| *byte == 0) {
            let tail = bytes.get(offset..).ok_or("release.archive.tar-framing")?;
            if tail.len() < TAR_BLOCK.saturating_mul(2) || tail.iter().any(|byte| *byte != 0) {
                return Err("release.archive.tar-framing");
            }
            ended = true;
            break;
        }
        validate_tar_checksum(header)?;
        if &header[257..263] != b"ustar\0"
            || &header[263..265] != b"00"
            || header[329..345]
                .iter()
                .any(|byte| !matches!(byte, 0 | b'0' | b' '))
            || header[500..512].iter().any(|byte| *byte != 0)
        {
            return Err("release.archive.tar-header");
        }
        let path_end = header[..100]
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(100);
        let path = std::str::from_utf8(&header[..path_end]).map_err(|_| "release.archive.path")?;
        if path.starts_with('/') || path.as_bytes().get(1) == Some(&b':') {
            return Err("release.archive.absolute-path");
        }
        if path.split('/').any(|component| component == "..") {
            return Err("release.archive.path-traversal");
        }
        if !paths.insert(path.to_owned()) {
            return Err("release.archive.duplicate-member");
        }
        let kind = header[156];
        if !matches!(kind, 0 | b'0' | b'5') {
            return Err("release.archive.unsupported-type");
        }
        let mtime = tar_octal(&header[136..148]).ok_or("release.archive.tar-header")?;
        if mtime != epoch {
            return Err("release.archive.tar-header");
        }
        if kind != b'5'
            && !required.contains(path)
            && !path.strip_prefix("records/").is_some_and(|tail| {
                record_archive_name(tail, "ev-") || record_archive_name(tail, "gx-")
            })
            && !path
                .strip_prefix("observations/")
                .is_some_and(observation_archive_name)
        {
            return Err("release.archive.extra-member");
        }
        let size = tar_octal(&header[124..136]).ok_or("release.archive.tar-header")?;
        let padded = size
            .checked_add(u64::try_from(TAR_BLOCK - 1).map_err(|_| "release.archive.tar-framing")?)
            .ok_or("release.archive.tar-framing")?
            / u64::try_from(TAR_BLOCK).map_err(|_| "release.archive.tar-framing")?
            * u64::try_from(TAR_BLOCK).map_err(|_| "release.archive.tar-framing")?;
        let payload_start = offset
            .checked_add(TAR_BLOCK)
            .ok_or("release.archive.tar-framing")?;
        let payload_end = usize::try_from(padded)
            .ok()
            .and_then(|padded| payload_start.checked_add(padded))
            .ok_or("release.archive.tar-framing")?;
        let exact_end = usize::try_from(size)
            .ok()
            .and_then(|size| payload_start.checked_add(size))
            .ok_or("release.archive.tar-framing")?;
        if bytes
            .get(exact_end..payload_end)
            .ok_or("release.archive.tar-framing")?
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err("release.archive.tar-framing");
        }
        offset = payload_end;
    }
    if !ended {
        return Err("release.archive.tar-framing");
    }
    Ok(())
}

fn validate_tar_checksum(header: &[u8]) -> Result<(), &'static str> {
    let stated = tar_octal(&header[148..156]).ok_or("release.archive.tar-checksum")?;
    let observed = header
        .iter()
        .enumerate()
        .try_fold(0_u64, |sum, (index, byte)| {
            sum.checked_add(u64::from(if (148..156).contains(&index) {
                b' '
            } else {
                *byte
            }))
        })
        .ok_or("release.archive.tar-checksum")?;
    if stated != observed {
        return Err("release.archive.tar-checksum");
    }
    Ok(())
}

pub(crate) fn fuzz_verify_gzip(bytes: &[u8]) -> Result<(), String> {
    const HEADER: [u8; 10] = [0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 2, 255];
    if bytes.len() < HEADER.len().saturating_add(8) || bytes[..HEADER.len()] != HEADER {
        return Err("release gzip header is not canonical".to_owned());
    }
    verify_single_gzip_member(bytes, MAX_EVIDENCE_ARCHIVE_BYTES)?;
    let mut decoder = GzDecoder::new(bytes);
    let mut expanded = Vec::new();
    decoder
        .by_ref()
        .take(MAX_EVIDENCE_ARCHIVE_BYTES.saturating_add(1))
        .read_to_end(&mut expanded)
        .map_err(|error| format!("release gzip trailer or checksum is invalid: {error}"))?;
    if u64::try_from(expanded.len()).unwrap_or(u64::MAX) > MAX_EVIDENCE_ARCHIVE_BYTES {
        return Err("release gzip expanded output exceeds its bound".to_owned());
    }
    Ok(())
}

pub(crate) fn fuzz_verify_tar(bytes: &[u8], epoch: u64) -> Result<(), String> {
    classify_evidence_tar(bytes, epoch).map_err(str::to_owned)
}

fn tar_octal(bytes: &[u8]) -> Option<u64> {
    let mut value = 0_u64;
    let mut digits = 0_usize;
    let mut terminated = false;
    for byte in bytes {
        match *byte {
            b'0'..=b'7' if !terminated => {
                value = value.checked_mul(8)?.checked_add(u64::from(*byte - b'0'))?;
                digits = digits.checked_add(1)?;
            }
            0 | b' ' => terminated = true,
            _ => return None,
        }
    }
    (digits != 0).then_some(value)
}

fn validate_evidence_members(members: &BTreeMap<String, Vec<u8>>) -> Result<(), String> {
    let required = BTreeSet::from([
        "conformance-plan.json",
        "platform-manifests/linux-x86_64.json",
        "platform-manifests/macos-aarch64.json",
        "platform-manifests/windows-x86_64.json",
        "source-inventory.json",
        "trusted-conformance-inputs.json",
    ]);
    if members.len() > MAX_EVIDENCE_ENTRIES
        || !required.iter().all(|path| members.contains_key(*path))
    {
        return Err("conformance evidence archive required inventory differs".to_owned());
    }
    let mut total = 0_u64;
    for (name, bytes) in members {
        validate_archive_path(name)?;
        let allowed = required.contains(name.as_str())
            || name.strip_prefix("records/").is_some_and(|tail| {
                record_archive_name(tail, "ev-") || record_archive_name(tail, "gx-")
            })
            || name
                .strip_prefix("observations/")
                .is_some_and(observation_archive_name);
        if (!allowed && !crate::mutation::active("allow-extra-archive-member"))
            || Path::new(name).extension().and_then(|value| value.to_str()) != Some("json")
            || !bytes.ends_with(b"\n")
        {
            return Err(format!("invalid conformance evidence member {name:?}"));
        }
        let size = u64::try_from(bytes.len())
            .map_err(|_| "conformance evidence member is too large".to_owned())?;
        if size > MAX_EVIDENCE_ENTRY_BYTES {
            return Err("conformance evidence member exceeds its canonical bound".to_owned());
        }
        total = total
            .checked_add(size)
            .ok_or_else(|| "conformance evidence member size overflow".to_owned())?;
    }
    if total > MAX_EVIDENCE_ARCHIVE_BYTES {
        return Err("conformance evidence members exceed the archive bound".to_owned());
    }
    Ok(())
}

pub(crate) fn assurance_extra_evidence_archive_member() -> Result<(), String> {
    let mut members = [
        "conformance-plan.json",
        "platform-manifests/linux-x86_64.json",
        "platform-manifests/macos-aarch64.json",
        "platform-manifests/windows-x86_64.json",
        "source-inventory.json",
        "trusted-conformance-inputs.json",
    ]
    .into_iter()
    .map(|name| (name.to_owned(), b"{}\n".to_vec()))
    .collect::<BTreeMap<_, _>>();
    members.insert(
        "unexpected-authority.json".to_owned(),
        b"{\"state\":\"unexpected\"}\n".to_vec(),
    );
    validate_evidence_members(&members)
}

fn record_archive_name(tail: &str, prefix: &str) -> bool {
    let Some(digest) = tail
        .strip_prefix(prefix)
        .and_then(|value| value.strip_suffix(".json"))
    else {
        return false;
    };
    canonical_digest_text(digest)
}

fn observation_archive_name(tail: &str) -> bool {
    tail.strip_suffix(".json")
        .is_some_and(canonical_digest_text)
}

fn canonical_digest_text(value: &str) -> bool {
    hell_testkit::Digest::from_hex(value).is_ok_and(|digest| digest.hex() == value)
}

fn canonical_evidence_bytes(
    epoch: u64,
    members: &BTreeMap<String, Vec<u8>>,
) -> Result<Vec<u8>, String> {
    let mut entries = EVIDENCE_DIRECTORIES
        .iter()
        .map(|path| ((*path).to_owned(), None))
        .chain(
            members
                .iter()
                .map(|(path, bytes)| (path.clone(), Some(bytes.as_slice()))),
        )
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    let mut compressed = Vec::new();
    {
        let encoder = GzBuilder::new()
            .mtime(0)
            .operating_system(255)
            .write(&mut compressed, Compression::new(9));
        let mut builder = Builder::new(encoder);
        builder.mode(tar::HeaderMode::Deterministic);
        for (name, bytes) in entries {
            if let Some(bytes) = bytes {
                append_bytes(&mut builder, &name, bytes, 0o644, epoch)?;
            } else {
                append_directory(&mut builder, &name, epoch)?;
            }
        }
        builder
            .finish()
            .map_err(|error| format!("cannot finish conformance evidence tar: {error}"))?;
        builder
            .into_inner()
            .map_err(|error| format!("cannot finish conformance evidence gzip: {error}"))?
            .finish()
            .map_err(|error| format!("cannot close conformance evidence gzip: {error}"))?;
    }
    Ok(compressed)
}

fn append_directory<W: Write>(
    builder: &mut Builder<W>,
    path: &str,
    epoch: u64,
) -> Result<(), String> {
    let mut header = Header::new_gnu();
    header.set_entry_type(EntryType::Directory);
    set_metadata(&mut header, 0, 0o755, epoch);
    header.set_cksum();
    builder
        .append_data(&mut header, path, std::io::empty())
        .map_err(|error| format!("cannot append archive directory: {error}"))
}

fn append_file<W: Write>(
    builder: &mut Builder<W>,
    path: &str,
    source: &Path,
    mode: u32,
    epoch: u64,
) -> Result<(), String> {
    let bytes = read_regular(source)?;
    append_bytes(builder, path, &bytes, mode, epoch)
}

fn append_bytes<W: Write>(
    builder: &mut Builder<W>,
    path: &str,
    bytes: &[u8],
    mode: u32,
    epoch: u64,
) -> Result<(), String> {
    let mut header = Header::new_gnu();
    header.set_entry_type(EntryType::Regular);
    set_metadata(
        &mut header,
        u64::try_from(bytes.len()).map_err(|_| "archive file is too large".to_owned())?,
        mode,
        epoch,
    );
    header.set_cksum();
    builder
        .append_data(&mut header, path, bytes)
        .map_err(|error| format!("cannot append archive file: {error}"))
}

enum ArchiveEntry<'a> {
    Directory(String),
    File(String, PathBuf, u32),
    Bytes(String, &'a [u8], u32),
}

impl ArchiveEntry<'_> {
    fn path(&self) -> &str {
        match self {
            Self::Directory(path) | Self::File(path, ..) | Self::Bytes(path, ..) => path,
        }
    }
}

fn set_metadata(header: &mut Header, size: u64, mode: u32, epoch: u64) {
    header.set_size(size);
    header.set_mode(mode);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(epoch);
    let _ = header.set_username("");
    let _ = header.set_groupname("");
}

fn validate_archive_path(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.contains('\\')
        || value.contains("//")
        || value.as_bytes().get(1) == Some(&b':')
    {
        return Err("release archive path is not canonical".to_owned());
    }
    let path = Path::new(value);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err("release archive path is unsafe".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct RawEntry<'a> {
        path: &'a str,
        kind: EntryType,
        mode: u32,
        mtime: u64,
        payload: &'a [u8],
    }

    fn raw_archive(entries: &[RawEntry<'_>]) -> Vec<u8> {
        let mut compressed = Vec::new();
        let encoder = GzBuilder::new()
            .mtime(0)
            .operating_system(255)
            .write(&mut compressed, Compression::new(9));
        let mut builder = Builder::new(encoder);
        builder.mode(tar::HeaderMode::Deterministic);
        for entry in entries {
            let mut header = Header::new_gnu();
            header.set_entry_type(entry.kind);
            set_metadata(
                &mut header,
                u64::try_from(entry.payload.len()).unwrap(),
                entry.mode,
                entry.mtime,
            );
            let name = entry.path.as_bytes();
            assert!(name.len() < 100);
            header.as_mut_bytes()[..name.len()].copy_from_slice(name);
            header.set_cksum();
            builder.append(&header, entry.payload).unwrap();
        }
        builder.finish().unwrap();
        builder.into_inner().unwrap().finish().unwrap();
        compressed
    }

    fn write_and_reject(root: &Path, name: &str, bytes: &[u8]) {
        let path = root.join(name);
        fs::write(&path, bytes).unwrap();
        assert!(
            verify(&path, ReleasePlatform::LinuxX86_64, "1.2.3", 123).is_err(),
            "malicious archive {name} was accepted"
        );
    }

    #[test]
    fn archive_paths_reject_traversal_and_drive_prefixes() {
        for invalid in ["../hell", "/hell", "C:/hell", "a\\b", ""] {
            assert!(validate_archive_path(invalid).is_err(), "{invalid}");
        }
        assert!(validate_archive_path("hell-v1/bin/hell").is_ok());
    }

    #[test]
    fn archive_creation_is_byte_deterministic_and_header_bound() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("hell-release-archive-{nonce}"));
        fs::create_dir(&root).unwrap();
        let executable = root.join("hell");
        fs::write(&executable, b"binary\n").unwrap();
        let first = root.join("first.tar.gz");
        let second = root.join("second.tar.gz");
        for output in [&first, &second] {
            create(&ArchiveInput {
                platform: ReleasePlatform::LinuxX86_64,
                version: "1.2.3",
                source_date_epoch: 123,
                executable: &executable,
                license: b"license\n",
                notice: b"notice\n",
                readme: b"readme\n",
                output,
            })
            .unwrap();
        }
        assert_eq!(fs::read(&first).unwrap(), fs::read(&second).unwrap());
        let mut malicious = fs::read(&first).unwrap();
        malicious[3] = 8;
        fs::write(&second, malicious).unwrap();
        assert!(verify(&second, ReleasePlatform::LinuxX86_64, "1.2.3", 123).is_err());
        let mut trailing = fs::read(&first).unwrap();
        trailing.extend_from_slice(b"hidden trailing payload");
        fs::write(&second, trailing).unwrap();
        assert!(verify(&second, ReleasePlatform::LinuxX86_64, "1.2.3", 123).is_err());
        let mut concatenated = fs::read(&first).unwrap();
        concatenated.extend_from_slice(&fs::read(&first).unwrap());
        fs::write(&second, concatenated).unwrap();
        assert!(verify(&second, ReleasePlatform::LinuxX86_64, "1.2.3", 123).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn archive_rejects_malicious_paths_duplicates_and_special_types() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("hell-release-archive-attacks-{nonce}"));
        fs::create_dir(&root).unwrap();
        for (index, path) in [
            "../escape",
            "/absolute",
            "C:/drive",
            "a//empty",
            "a\\windows",
        ]
        .into_iter()
        .enumerate()
        {
            write_and_reject(
                &root,
                &format!("path-{index}.tar.gz"),
                &raw_archive(&[RawEntry {
                    path,
                    kind: EntryType::Regular,
                    mode: 0o644,
                    mtime: 123,
                    payload: b"x",
                }]),
            );
        }
        let duplicate = RawEntry {
            path: "hell-v1.2.3-linux-x86_64/LICENSE",
            kind: EntryType::Regular,
            mode: 0o644,
            mtime: 123,
            payload: b"x",
        };
        write_and_reject(
            &root,
            "duplicate.tar.gz",
            &raw_archive(&[RawEntry { ..duplicate }, RawEntry { ..duplicate }]),
        );
        for (index, kind) in [
            EntryType::Symlink,
            EntryType::Link,
            EntryType::Char,
            EntryType::Block,
            EntryType::Fifo,
        ]
        .into_iter()
        .enumerate()
        {
            write_and_reject(
                &root,
                &format!("special-{index}.tar.gz"),
                &raw_archive(&[RawEntry {
                    path: "hell-v1.2.3-linux-x86_64/special",
                    kind,
                    mode: 0o644,
                    mtime: 123,
                    payload: b"",
                }]),
            );
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn archive_rejects_noncanonical_order_mode_mtime_and_oversized_headers() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("hell-release-archive-metadata-{nonce}"));
        fs::create_dir(&root).unwrap();
        let prefix = "hell-v1.2.3-linux-x86_64/";
        let entries = [
            RawEntry {
                path: "hell-v1.2.3-linux-x86_64/bin/hell",
                kind: EntryType::Regular,
                mode: 0o755,
                mtime: 123,
                payload: b"binary",
            },
            RawEntry {
                path: "hell-v1.2.3-linux-x86_64/bin",
                kind: EntryType::Directory,
                mode: 0o755,
                mtime: 123,
                payload: b"",
            },
            RawEntry {
                path: "hell-v1.2.3-linux-x86_64/CONFORMANCE.md",
                kind: EntryType::Regular,
                mode: 0o644,
                mtime: 123,
                payload: b"Conformance is evaluated by trusted release automation. See conformance-report.json, conformance-acceptance.json, and conformance-evidence.tar.gz in the release bundle.\n",
            },
            RawEntry {
                path: "hell-v1.2.3-linux-x86_64/README.md",
                kind: EntryType::Regular,
                mode: 0o644,
                mtime: 123,
                payload: b"readme",
            },
            RawEntry {
                path: "hell-v1.2.3-linux-x86_64/NOTICE",
                kind: EntryType::Regular,
                mode: 0o644,
                mtime: 123,
                payload: b"notice",
            },
            RawEntry {
                path: "hell-v1.2.3-linux-x86_64/LICENSE",
                kind: EntryType::Regular,
                mode: 0o644,
                mtime: 123,
                payload: b"license",
            },
            RawEntry {
                path: "hell-v1.2.3-linux-x86_64",
                kind: EntryType::Directory,
                mode: 0o755,
                mtime: 123,
                payload: b"",
            },
        ];
        write_and_reject(&root, "wrong-order.tar.gz", &raw_archive(&entries));
        for (name, mode, mtime) in [("wrong-mode", 0o600, 123), ("wrong-mtime", 0o644, 124)] {
            write_and_reject(
                &root,
                &format!("{name}.tar.gz"),
                &raw_archive(&[RawEntry {
                    path: &format!("{prefix}LICENSE"),
                    kind: EntryType::Regular,
                    mode,
                    mtime,
                    payload: b"license",
                }]),
            );
        }
        let mut header = Header::new_gnu();
        header.set_entry_type(EntryType::Regular);
        set_metadata(&mut header, 128 * 1024 * 1024 + 1, 0o644, 123);
        header.as_mut_bytes()[..format!("{prefix}LICENSE").len()]
            .copy_from_slice(format!("{prefix}LICENSE").as_bytes());
        header.set_cksum();
        let mut tar = header.as_bytes().to_vec();
        tar.extend_from_slice(&[0_u8; 1024]);
        let mut oversized = Vec::new();
        let mut encoder = GzBuilder::new()
            .mtime(0)
            .operating_system(255)
            .write(&mut oversized, Compression::new(9));
        encoder.write_all(&tar).unwrap();
        encoder.finish().unwrap();
        write_and_reject(&root, "oversized.tar.gz", &oversized);
        fs::remove_dir_all(root).unwrap();
    }

    fn evidence_fixture() -> BTreeMap<String, Vec<u8>> {
        let digest = hell_testkit::sha256_bytes(b"observation\n").hex();
        BTreeMap::from([
            ("conformance-plan.json".to_owned(), b"{}\n".to_vec()),
            (
                "platform-manifests/linux-x86_64.json".to_owned(),
                b"{}\n".to_vec(),
            ),
            (
                "platform-manifests/macos-aarch64.json".to_owned(),
                b"{}\n".to_vec(),
            ),
            (
                "platform-manifests/windows-x86_64.json".to_owned(),
                b"{}\n".to_vec(),
            ),
            (
                "trusted-conformance-inputs.json".to_owned(),
                b"{}\n".to_vec(),
            ),
            ("source-inventory.json".to_owned(), b"{}\n".to_vec()),
            (format!("observations/{digest}.json"), b"{}\n".to_vec()),
            (
                format!("records/ev-{}.json", "a".repeat(digest.len())),
                b"{}\n".to_vec(),
            ),
            (
                format!("records/gx-{}.json", "b".repeat(digest.len())),
                b"{}\n".to_vec(),
            ),
        ])
    }

    #[test]
    fn evidence_archive_is_deterministic_bounded_and_exact() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("hell-conformance-archive-{nonce}"));
        fs::create_dir(&root).unwrap();
        let first = root.join("first.tar.gz");
        let second = root.join("second.tar.gz");
        let members = evidence_fixture();
        create_evidence(&first, 123, &members).unwrap();
        create_evidence(&second, 123, &members).unwrap();
        assert_eq!(fs::read(&first).unwrap(), fs::read(&second).unwrap());
        assert_eq!(read_evidence(&first, 123).unwrap(), members);

        let mut unsafe_members = evidence_fixture();
        unsafe_members.insert("records/ev-short.json".to_owned(), b"{}\n".to_vec());
        assert!(create_evidence(&root.join("unsafe.tar.gz"), 123, &unsafe_members).is_err());

        let compressed_bomb = {
            let mut bytes = Vec::new();
            let mut encoder = GzBuilder::new()
                .mtime(0)
                .operating_system(255)
                .write(&mut bytes, Compression::new(9));
            encoder.write_all(&vec![0_u8; 1024 * 1024]).unwrap();
            encoder.finish().unwrap();
            bytes
        };
        assert!(verify_single_gzip_member(&compressed_bomb, 1024).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
