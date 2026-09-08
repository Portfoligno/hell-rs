use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fs;
#[cfg(windows)]
use std::io::Cursor;
use std::io::{Read, Write as _};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use hell_memcordon::{
    ACQUISITION_RECEIPT_SCHEMA_V1, AcquisitionReceiptV1, ComponentObservationV1, Platform,
    PlatformId, RuntimeAsset, RuntimeLock, RuntimeManifest, TransportStatus,
    validate_component_inventory,
};

use crate::json::{JsonValue, parse_json};
use crate::release::manifest::{write_atomic, write_json};

use super::provider::create_evidence_directories;
use super::task::Task;

const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(90);
const METADATA_LIMIT: u64 = 2 * 1024 * 1024;

struct AcquiredAssets {
    release_manifest: Vec<u8>,
    publication_report: Vec<u8>,
    checksums: Vec<u8>,
    archive: Vec<u8>,
    transport: TransportStatus,
}

pub(super) fn run(task: &Task) -> Result<String, String> {
    create_evidence_directories(&task.output)?;
    if task.runtime_root.exists() {
        return Err("MemCordon runtime root must be absent before fresh extraction".to_owned());
    }
    let lock_bytes = read_bounded_regular(&task.lock, METADATA_LIMIT)?;
    if !lock_bytes.ends_with(b"\n") {
        return Err("MemCordon runtime lock lacks its trailing newline".to_owned());
    }
    let lock_text = std::str::from_utf8(&lock_bytes)
        .map_err(|_| "MemCordon runtime lock is not UTF-8".to_owned())?;
    let lock = RuntimeLock::parse(lock_text).map_err(|error| error.to_string())?;
    let platform = Platform::current()
        .ok_or_else(|| "MemCordon sealed runtime is unavailable on this platform".to_owned())?;
    let asset = lock.asset(platform).map_err(|error| error.to_string())?;

    let assets = acquire_locked_assets(&lock, asset, &task.download_cache)?;

    validate_metadata_json(&assets.release_manifest, &lock, asset, "release manifest")?;
    validate_metadata_json(
        &assets.publication_report,
        &lock,
        asset,
        "publication report",
    )?;
    validate_checksums(&assets.checksums, asset)?;
    extract_archive(&assets.archive, asset, &task.runtime_root)?;
    let manifest_path = find_unique_file(&task.runtime_root, "runtime-manifest.json")?;
    let runtime_manifest_bytes = read_bounded_regular(&manifest_path, METADATA_LIMIT)?;
    let runtime_manifest =
        RuntimeManifest::parse(&runtime_manifest_bytes).map_err(|error| error.to_string())?;
    // The archive's digest and length were verified before extraction. Its
    // embedded manifest binds the runtime identity, not its own containing bytes.
    if runtime_manifest.target != asset.target
        || runtime_manifest.version != lock.version
        || runtime_manifest.source_commit != lock.source_commit
    {
        return Err("runtime manifest does not match the selected runtime".to_owned());
    }
    validate_component_inventory(&runtime_manifest, &asset.required_components)
        .map_err(|error| error.to_string())?;
    let bundle_root = manifest_path
        .parent()
        .ok_or_else(|| "runtime manifest lacks a bundle root".to_owned())?;
    let components = validate_components(bundle_root, &runtime_manifest)?;

    write_atomic(
        &task.output.join("release-manifest.json"),
        &assets.release_manifest,
    )?;
    write_atomic(
        &task.output.join("publication-report.json"),
        &assets.publication_report,
    )?;
    write_atomic(
        &task.output.join("runtime-manifest.json"),
        &runtime_manifest_bytes,
    )?;
    let receipt = AcquisitionReceiptV1 {
        schema_version: ACQUISITION_RECEIPT_SCHEMA_V1,
        runtime_lock_digest: hell_memcordon::runtime_lock_digest(&lock_bytes).hex(),
        version: lock.version.clone(),
        release_id: lock.release_id,
        source_commit: lock.source_commit.clone(),
        platform: platform_id(platform),
        target: asset.target.clone(),
        mechanism: asset.mechanism.clone(),
        archive_filename: asset.filename.clone(),
        archive_bytes: asset.bytes,
        archive_sha256: asset.sha256.clone(),
        release_manifest_sha256: lock.metadata.release_manifest.sha256,
        publication_report_sha256: lock.metadata.publication_report.sha256,
        checksums_sha256: lock.metadata.checksums.sha256,
        runtime_manifest_sha256: hell_testkit::sha256_bytes(&runtime_manifest_bytes).hex(),
        components,
        transport: assets.transport,
    };
    write_serde(&task.output.join("acquisition.json"), &receipt)?;
    Ok(format!(
        "acquired and verified MemCordon {} for {}",
        lock.version,
        platform.key()
    ))
}

fn acquire_locked_assets(
    lock: &RuntimeLock,
    asset: &RuntimeAsset,
    cache: &Path,
) -> Result<AcquiredAssets, String> {
    fs::create_dir_all(cache)
        .map_err(|error| format!("cannot create MemCordon download cache: {error}"))?;
    let (release_manifest, release_transport) = acquire_asset(
        lock,
        cache,
        &lock.metadata.release_manifest.filename,
        lock.metadata.release_manifest.bytes,
        &lock.metadata.release_manifest.sha256,
    )?;
    let (publication_report, publication_transport) = acquire_asset(
        lock,
        cache,
        &lock.metadata.publication_report.filename,
        lock.metadata.publication_report.bytes,
        &lock.metadata.publication_report.sha256,
    )?;
    let (checksums, checksums_transport) = acquire_asset(
        lock,
        cache,
        &lock.metadata.checksums.filename,
        lock.metadata.checksums.bytes,
        &lock.metadata.checksums.sha256,
    )?;
    let (archive, archive_transport) =
        acquire_asset(lock, cache, &asset.filename, asset.bytes, &asset.sha256)?;
    let transports = [
        release_transport,
        publication_transport,
        checksums_transport,
        archive_transport,
    ];
    let transport = if transports
        .iter()
        .all(|value| *value == TransportStatus::VerifiedCacheHit)
    {
        TransportStatus::VerifiedCacheHit
    } else {
        TransportStatus::Downloaded
    };
    Ok(AcquiredAssets {
        release_manifest,
        publication_report,
        checksums,
        archive,
        transport,
    })
}

fn acquire_asset(
    lock: &RuntimeLock,
    cache: &Path,
    filename: &str,
    expected_bytes: u64,
    expected_sha256: &str,
) -> Result<(Vec<u8>, TransportStatus), String> {
    validate_filename(filename)?;
    let path = cache.join(filename);
    if path.exists() {
        let bytes = read_bounded_regular(&path, expected_bytes)?;
        validate_bytes(&bytes, expected_bytes, expected_sha256, filename)?;
        return Ok((bytes, TransportStatus::VerifiedCacheHit));
    }
    let url = format!(
        "https://github.com/{}/releases/download/{}/{}",
        lock.repository, lock.version, filename
    );
    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(DOWNLOAD_TIMEOUT))
        .https_only(true)
        .build()
        .new_agent();
    let mut response = agent
        .get(&url)
        .header("Accept-Encoding", "identity")
        .header("User-Agent", "hell-ci-memcordon-acquire")
        .call()
        .map_err(|error| format!("cannot download pinned MemCordon asset {filename}: {error}"))?;
    if response
        .body()
        .content_length()
        .is_some_and(|length| length != expected_bytes)
    {
        return Err(format!("MemCordon asset {filename} length header differs"));
    }
    let mut bytes = Vec::new();
    response
        .body_mut()
        .as_reader()
        .take(expected_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read MemCordon asset {filename}: {error}"))?;
    validate_bytes(&bytes, expected_bytes, expected_sha256, filename)?;
    write_atomic(&path, &bytes)?;
    Ok((bytes, TransportStatus::Downloaded))
}

fn validate_bytes(
    bytes: &[u8],
    expected_bytes: u64,
    expected_sha256: &str,
    label: &str,
) -> Result<(), String> {
    if u64::try_from(bytes.len()).ok() != Some(expected_bytes)
        || hell_testkit::sha256_bytes(bytes).hex() != expected_sha256
    {
        return Err(format!(
            "MemCordon asset {label} differs from the committed lock"
        ));
    }
    Ok(())
}

fn validate_metadata_json(
    bytes: &[u8],
    lock: &RuntimeLock,
    asset: &RuntimeAsset,
    label: &str,
) -> Result<(), String> {
    let text = std::str::from_utf8(bytes).map_err(|_| format!("MemCordon {label} is not UTF-8"))?;
    let value = parse_json(text)?;
    for required in [
        lock.version.as_str(),
        lock.source_commit.as_str(),
        asset.sha256.as_str(),
    ] {
        if !contains_string(&value, required) {
            return Err(format!(
                "MemCordon {label} omits required binding {required}"
            ));
        }
    }
    Ok(())
}

fn contains_string(value: &JsonValue, expected: &str) -> bool {
    match value {
        JsonValue::String(value) => value == expected || value.ends_with(expected),
        JsonValue::Array(values) => values.iter().any(|value| contains_string(value, expected)),
        JsonValue::Object(values) => values
            .values()
            .any(|value| contains_string(value, expected)),
        JsonValue::Null | JsonValue::Bool(_) | JsonValue::Number(_) => false,
    }
}

fn validate_checksums(bytes: &[u8], asset: &RuntimeAsset) -> Result<(), String> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| "MemCordon SHA256SUMS is not UTF-8".to_owned())?;
    let mut matches = text.lines().filter_map(|line| {
        let mut fields = line.split_ascii_whitespace();
        let digest = fields.next()?;
        let raw_filename = fields.next()?;
        let filename = raw_filename.strip_prefix('*').unwrap_or(raw_filename);
        (fields.next().is_none() && filename == asset.filename).then_some(digest)
    });
    if matches.next() != Some(asset.sha256.as_str()) || matches.next().is_some() {
        return Err(
            "MemCordon SHA256SUMS does not bind the selected archive exactly once".to_owned(),
        );
    }
    Ok(())
}

fn extract_archive(bytes: &[u8], asset: &RuntimeAsset, output: &Path) -> Result<(), String> {
    fs::create_dir(output)
        .map_err(|error| format!("cannot create fresh MemCordon runtime root: {error}"))?;
    if asset.filename.ends_with(".tar.gz") {
        extract_tar_gzip(bytes, output)
    } else if Path::new(&asset.filename).extension() == Some(OsStr::new("zip")) {
        extract_zip(bytes, output)
    } else {
        Err("unsupported MemCordon archive format".to_owned())
    }
}

fn extract_tar_gzip(bytes: &[u8], output: &Path) -> Result<(), String> {
    let decoder = flate2::read::GzDecoder::new(bytes);
    let mut archive = tar::Archive::new(decoder);
    let mut policy = ArchivePolicy::default();
    let entries = archive
        .entries()
        .map_err(|error| format!("cannot enumerate MemCordon tar archive: {error}"))?;
    for entry in entries {
        let mut entry =
            entry.map_err(|error| format!("cannot read MemCordon tar entry: {error}"))?;
        let path = entry
            .path()
            .map_err(|error| format!("cannot decode MemCordon tar path: {error}"))?
            .into_owned();
        let kind = entry.header().entry_type();
        if kind.is_dir() {
            policy.accept(&path, 0)?;
            fs::create_dir_all(output.join(&path))
                .map_err(|error| format!("cannot create MemCordon directory: {error}"))?;
        } else if kind.is_file() {
            let declared = entry.size();
            policy.accept(&path, declared)?;
            write_archive_file(output, &path, &mut entry, declared)?;
            #[cfg(unix)]
            if entry.header().mode().unwrap_or(0) & 0o111 != 0 {
                use std::os::unix::fs::PermissionsExt as _;
                fs::set_permissions(output.join(&path), fs::Permissions::from_mode(0o755))
                    .map_err(|error| format!("cannot set runtime executable mode: {error}"))?;
            }
        } else {
            return Err("MemCordon tar contains a link or unsupported entry".to_owned());
        }
    }
    policy.finish()
}

#[cfg(windows)]
fn extract_zip(bytes: &[u8], output: &Path) -> Result<(), String> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes))
        .map_err(|error| format!("cannot open MemCordon ZIP: {error}"))?;
    let mut policy = ArchivePolicy::default();
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|error| format!("cannot read MemCordon ZIP entry: {error}"))?;
        let path = PathBuf::from(entry.name());
        if entry.is_dir() {
            policy.accept(&path, 0)?;
            fs::create_dir_all(output.join(&path))
                .map_err(|error| format!("cannot create MemCordon directory: {error}"))?;
        } else {
            if entry
                .unix_mode()
                .is_some_and(|mode| mode & 0o170000 == 0o120000)
            {
                return Err("MemCordon ZIP contains a symbolic link".to_owned());
            }
            let declared = entry.size();
            policy.accept(&path, declared)?;
            write_archive_file(output, &path, &mut entry, declared)?;
        }
    }
    policy.finish()
}

#[cfg(not(windows))]
fn extract_zip(_bytes: &[u8], _output: &Path) -> Result<(), String> {
    Err("MemCordon ZIP extraction is available only on Windows".to_owned())
}

fn write_archive_file(
    output: &Path,
    relative: &Path,
    reader: &mut impl Read,
    declared: u64,
) -> Result<(), String> {
    let destination = output.join(relative);
    let parent = destination
        .parent()
        .ok_or_else(|| "archive member lacks a parent".to_owned())?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("cannot create archive member parent: {error}"))?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&destination)
        .map_err(|error| {
            format!(
                "cannot create archive member {}: {error}",
                destination.display()
            )
        })?;
    let copied = std::io::copy(&mut reader.take(declared.saturating_add(1)), &mut file)
        .map_err(|error| format!("cannot extract archive member: {error}"))?;
    if copied != declared {
        return Err("archive member expanded length differs".to_owned());
    }
    file.flush()
        .map_err(|error| format!("cannot flush archive member: {error}"))
}

#[derive(Default)]
struct ArchivePolicy {
    entries: usize,
    expanded: u64,
    paths: BTreeSet<String>,
    top: BTreeSet<OsString>,
}

impl ArchivePolicy {
    fn accept(&mut self, path: &Path, bytes: u64) -> Result<(), String> {
        self.entries = self.entries.saturating_add(1);
        if self.entries > hell_memcordon::MAX_ARCHIVE_ENTRIES {
            return Err("MemCordon archive exceeds the entry bound".to_owned());
        }
        self.expanded = self
            .expanded
            .checked_add(bytes)
            .ok_or_else(|| "MemCordon archive expanded size overflowed".to_owned())?;
        if self.expanded > hell_memcordon::MAX_EXPANDED_BYTES {
            return Err("MemCordon archive exceeds the expansion bound".to_owned());
        }
        validate_archive_path(path)?;
        let normalized = path
            .components()
            .map(|component| component.as_os_str().to_string_lossy().to_ascii_lowercase())
            .collect::<Vec<_>>()
            .join("/");
        if !self.paths.insert(normalized) {
            return Err("MemCordon archive has a duplicate normalized path".to_owned());
        }
        let first = path
            .components()
            .next()
            .ok_or_else(|| "MemCordon archive path is empty".to_owned())?;
        self.top.insert(first.as_os_str().to_owned());
        Ok(())
    }

    fn finish(self) -> Result<(), String> {
        if self.entries == 0 || self.top.len() != 1 {
            return Err("MemCordon archive must have one non-empty top-level root".to_owned());
        }
        Ok(())
    }
}

fn validate_archive_path(path: &Path) -> Result<(), String> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err("MemCordon archive path is not a normalized relative path".to_owned());
    }
    for component in path.components() {
        let value = component
            .as_os_str()
            .to_str()
            .ok_or_else(|| "MemCordon archive path is not UTF-8".to_owned())?;
        if value.contains(':') || value.ends_with(['.', ' ']) || reserved_windows_name(value) {
            return Err("MemCordon archive path is unsafe on Windows".to_owned());
        }
    }
    Ok(())
}

pub(super) fn fuzz_archive_member_policy(bytes: &[u8]) -> Result<(), String> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| "archive member fuzz input is not UTF-8".to_owned())?;
    let (path, payload) = text.split_once('\0').unwrap_or((text, ""));
    let mut policy = ArchivePolicy::default();
    policy.accept(
        Path::new(path),
        u64::try_from(payload.len()).map_err(|_| "archive payload length overflow".to_owned())?,
    )?;
    policy.finish()
}

fn reserved_windows_name(value: &str) -> bool {
    let stem = value
        .split('.')
        .next()
        .unwrap_or(value)
        .to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.as_bytes()[3].is_ascii_digit()
            && stem.as_bytes()[3] != b'0')
}

fn validate_components(
    root: &Path,
    manifest: &RuntimeManifest,
) -> Result<Vec<ComponentObservationV1>, String> {
    let mut observations = Vec::with_capacity(manifest.components.len());
    for component in &manifest.components {
        let path = root.join(&component.path);
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("runtime component {} is missing: {error}", component.id))?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() != component.size
        {
            return Err(format!(
                "runtime component {} metadata differs",
                component.id
            ));
        }
        let sha256 = hell_testkit::sha256_file(&path)
            .map_err(|error| format!("cannot hash runtime component {}: {error}", component.id))?
            .hex();
        if sha256 != component.sha256 {
            return Err(format!("runtime component {} digest differs", component.id));
        }
        observations.push(ComponentObservationV1 {
            path: component.path.clone(),
            bytes: component.size,
            sha256,
        });
    }
    Ok(observations)
}

fn find_unique_file(root: &Path, name: &str) -> Result<PathBuf, String> {
    let mut pending = vec![root.to_path_buf()];
    let mut found = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)
            .map_err(|error| format!("cannot enumerate runtime: {error}"))?
        {
            let entry = entry.map_err(|error| format!("cannot read runtime entry: {error}"))?;
            let kind = entry
                .file_type()
                .map_err(|error| format!("cannot inspect runtime entry: {error}"))?;
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file() && entry.file_name() == name {
                found.push(entry.path());
            }
        }
    }
    match found.as_slice() {
        [path] => Ok(path.clone()),
        [] => Err(format!("MemCordon runtime omits {name}")),
        _ => Err(format!("MemCordon runtime contains multiple {name} files")),
    }
}

fn read_bounded_regular(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > limit {
        return Err(format!(
            "{} is not one bounded regular file",
            path.display()
        ));
    }
    let bytes =
        fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    if u64::try_from(bytes.len()).ok() != Some(metadata.len()) {
        return Err(format!("{} changed while being read", path.display()));
    }
    Ok(bytes)
}

fn validate_filename(filename: &str) -> Result<(), String> {
    let path = Path::new(filename);
    if path.components().count() != 1
        || !matches!(path.components().next(), Some(Component::Normal(_)))
    {
        return Err("MemCordon asset filename is not a single path component".to_owned());
    }
    Ok(())
}

fn platform_id(platform: Platform) -> PlatformId {
    match platform {
        Platform::LinuxX86_64 => PlatformId::LinuxX86_64,
        Platform::WindowsX86_64 => PlatformId::WindowsX86_64,
    }
}

fn write_serde(path: &Path, value: &impl serde::Serialize) -> Result<(), String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("cannot serialize MemCordon receipt: {error}"))?;
    let text = std::str::from_utf8(&bytes).expect("JSON serializer emits UTF-8");
    write_json(path, &parse_json(text)?)?;
    Ok(())
}
