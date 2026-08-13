use std::fs;
use std::path::Path;

use crate::json::{JsonValue, canonical_json_bytes, parse_json};

pub(crate) fn read_json(path: &Path) -> Result<JsonValue, String> {
    let bytes = read_regular(path)?;
    let text =
        std::str::from_utf8(&bytes).map_err(|_| format!("{} is not UTF-8", path.display()))?;
    let value = parse_json(text)?;
    if canonical_json_bytes(&value)? != bytes {
        return Err(format!(
            "{} is not canonical JSON with one LF",
            path.display()
        ));
    }
    Ok(value)
}

pub(crate) fn write_json(path: &Path, value: &JsonValue) -> Result<Vec<u8>, String> {
    let bytes = canonical_json_bytes(value)?;
    write_atomic(path, &bytes)?;
    Ok(bytes)
}

pub(crate) fn write_digest_sibling(path: &Path, bytes: &[u8]) -> Result<String, String> {
    let digest = hell_testkit::sha256_bytes(bytes).hex();
    let name = path
        .file_name()
        .ok_or_else(|| "digest target has no filename".to_owned())?;
    let mut sibling = name.to_os_string();
    sibling.push(".sha256");
    write_atomic(
        &path.with_file_name(sibling),
        format!("{digest}\n").as_bytes(),
    )?;
    Ok(digest)
}

pub(crate) fn read_regular(path: &Path) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    const MAX_RELEASE_FILE_BYTES: u64 = 256 * 1024 * 1024;
    if metadata.len() > MAX_RELEASE_FILE_BYTES {
        return Err(format!(
            "{} exceeds the release file size limit",
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

pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("{} has no parent", path.display()))?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
    let name = path
        .file_name()
        .ok_or_else(|| "output path has no filename".to_owned())?;
    let mut temporary_name = name.to_os_string();
    temporary_name.push(".tmp");
    let temporary = path.with_file_name(temporary_name);
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    let mut file = options
        .open(&temporary)
        .map_err(|error| format!("cannot create {}: {error}", temporary.display()))?;
    use std::io::Write as _;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("cannot write {}: {error}", temporary.display()))?;
    drop(file);
    fs::rename(&temporary, path)
        .map_err(|error| format!("cannot install {}: {error}", path.display()))
}
