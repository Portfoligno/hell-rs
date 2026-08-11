use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use hell_testkit::{Digest, sha256_bytes};

fn component_path<const N: usize>(components: [&str; N]) -> std::path::PathBuf {
    components.iter().collect()
}

fn components_path(components: &[&str]) -> std::path::PathBuf {
    components.iter().collect()
}

const CATALOG_PATHS: &[&[&str]] = &[
    &["compat", "acquisition-sources.toml"],
    &["compat", "assurance-policy.toml"],
    &["compat", "claim-rules.toml"],
    &["compat", "claims", "2026-05-29.toml"],
    &["compat", "corpus-obligations.toml"],
    &["compat", "custody-policy.toml"],
    &["compat", "divergences.toml"],
    &["compat", "mutation-policy.toml"],
    &["compat", "mutants.toml"],
    &["compat", "normalizers.toml"],
    &["compat", "promotion-policy.toml"],
    &["compat", "review-policy.toml"],
    &["compat", "regression-corpus.tsv"],
    &["compat", "reviews.allowed_signers"],
    &["compat", "surveillance-policy.toml"],
    &["compat", "trust-roots.toml"],
];

const SOURCE_FILES: &[&[&str]] = &[
    &["Cargo.lock"],
    &["Cargo.toml"],
    &["baseline.toml"],
    &["compat", "reviews.allowed_signers"],
    &["rust-toolchain.toml"],
];

const SOURCE_DIRECTORIES: &[&[&str]] = &[
    &[".cargo"],
    &[".github", "workflows"],
    &["builtins"],
    &["compat"],
    &["crates"],
    &["fixtures"],
    &["spec"],
    &["tests"],
    &["tools"],
];

const CATALOG_LOCK_PATH: &[&str] = &["compat", "locks", "catalog-digests.json"];
const SOURCE_INPUT_LOCK_PATH: &[&str] = &["compat", "locks", "assurance-epoch.json"];

pub(crate) fn write_repository_locks(root: &Path) -> Result<(), String> {
    write_atomic(
        &root.join(components_path(CATALOG_LOCK_PATH)),
        render_catalog_lock(root)?.as_bytes(),
    )?;
    write_atomic(
        &root.join(components_path(SOURCE_INPUT_LOCK_PATH)),
        render_source_input_lock(root)?.as_bytes(),
    )
}

pub(crate) fn verify_repository_locks(root: &Path) -> Result<(), String> {
    verify_lock(root, CATALOG_LOCK_PATH, &render_catalog_lock(root)?)?;
    verify_lock(
        root,
        SOURCE_INPUT_LOCK_PATH,
        &render_source_input_lock(root)?,
    )
}

fn render_catalog_lock(root: &Path) -> Result<String, String> {
    let mut catalogs = BTreeMap::new();
    for relative in CATALOG_PATHS {
        add_file(root, &components_path(relative), &mut catalogs)?;
    }
    let catalog_digest = sha256_bytes(canonical_records(&catalogs).as_bytes());
    Ok(render_lock(
        "catalog-digests",
        "catalogSetSha256",
        catalog_digest,
        "catalogs",
        &catalogs,
    ))
}

fn render_source_input_lock(root: &Path) -> Result<String, String> {
    let inputs = source_inputs(root)?;
    let source_inputs_sha256 = sha256_bytes(canonical_records(&inputs).as_bytes());
    Ok(render_lock(
        "collection-epoch-inputs",
        "sourceInputsSha256",
        source_inputs_sha256,
        "inputs",
        &inputs,
    ))
}

fn render_lock(
    kind: &str,
    digest_name: &str,
    digest: Digest,
    records_name: &str,
    records: &BTreeMap<String, Digest>,
) -> String {
    let mut output = String::from("{\n  \"schemaVersion\": 1,\n  \"kind\": ");
    push_json_string(&mut output, kind);
    output.push_str(",\n  \"baseline\": ");
    push_json_string(&mut output, hell_builtins::LANGUAGE_VERSION);
    output.push_str(",\n  \"candidateCommitBinding\": \"collection-time\",\n  \"");
    output.push_str(digest_name);
    output.push_str("\": \"");
    output.push_str(&digest.hex());
    output.push_str("\",\n  \"");
    output.push_str(records_name);
    output.push_str("\": {");
    for (index, (path, file_digest)) in records.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        output.push_str("\n    ");
        push_json_string(&mut output, path);
        output.push_str(": \"");
        output.push_str(&file_digest.hex());
        output.push('"');
    }
    output.push_str("\n  }\n}\n");
    output
}

fn source_inputs(root: &Path) -> Result<BTreeMap<String, Digest>, String> {
    let mut inputs = BTreeMap::new();
    for relative in SOURCE_FILES {
        add_file(root, &components_path(relative), &mut inputs)?;
    }
    for relative in SOURCE_DIRECTORIES {
        let directory = root.join(components_path(relative));
        if directory.is_dir() {
            collect_source_inputs(root, &directory, &mut inputs)?;
        }
    }
    Ok(inputs)
}

fn collect_source_inputs(
    root: &Path,
    directory: &Path,
    inputs: &mut BTreeMap<String, Digest>,
) -> Result<(), String> {
    let mut entries = fs::read_dir(directory)
        .map_err(|error| format!("cannot enumerate {}: {error}", directory.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("cannot enumerate {}: {error}", directory.display()))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .map_err(|_| format!("{} is outside the repository", path.display()))?;
        if excluded(relative) {
            continue;
        }
        let file_type = entry
            .file_type()
            .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
        if file_type.is_symlink() {
            return Err(format!(
                "evidence-relevant input {} must not be a symbolic link",
                relative.display()
            ));
        }
        if file_type.is_dir() {
            collect_source_inputs(root, &path, inputs)?;
        } else if file_type.is_file() && evidence_relevant(relative) {
            add_file(root, relative, inputs)?;
        }
    }
    Ok(())
}

fn excluded(relative: &Path) -> bool {
    relative.starts_with(component_path(["compat", "locks"]))
        || relative.starts_with(component_path(["compat", "reviews"]))
        || relative == component_path(["compat", "promotion-review.toml"])
        || relative == component_path(["compat", "review-revocations.toml"])
}

fn evidence_relevant(path: &Path) -> bool {
    matches!(
        path.extension().and_then(OsStr::to_str),
        Some("hell" | "json" | "py" | "ron" | "rs" | "stdout" | "toml" | "tsv" | "yaml" | "yml")
    ) || path.file_name().and_then(OsStr::to_str) == Some("Cargo.lock")
}

fn add_file(
    root: &Path,
    relative: &Path,
    files: &mut BTreeMap<String, Digest>,
) -> Result<(), String> {
    let path = root.join(relative);
    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "locked input {} must be a regular file",
            relative.display()
        ));
    }
    let bytes = fs::read(&path)
        .map_err(|error| format!("cannot read locked input {}: {error}", path.display()))?;
    if bytes.last() != Some(&b'\n') {
        return Err(format!(
            "locked text input {} lacks a trailing newline",
            relative.display()
        ));
    }
    let key = relative
        .to_str()
        .ok_or_else(|| format!("locked path {} is not UTF-8", relative.display()))?
        .replace(std::path::MAIN_SEPARATOR, "/");
    if files.insert(key.clone(), sha256_bytes(&bytes)).is_some() {
        return Err(format!("duplicate locked input {key}"));
    }
    Ok(())
}

fn canonical_records(records: &BTreeMap<String, Digest>) -> String {
    let mut output = String::new();
    for (path, digest) in records {
        push_json_string(&mut output, path);
        output.push(' ');
        output.push_str(&digest.hex());
        output.push('\n');
    }
    output
}

fn verify_lock(root: &Path, relative: &[&str], expected: &str) -> Result<(), String> {
    let relative_path = components_path(relative);
    let path = root.join(&relative_path);
    let observed = fs::read_to_string(&path)
        .map_err(|error| format!("cannot read generated lock {}: {error}", path.display()))?;
    if observed == expected {
        Ok(())
    } else {
        Err(format!(
            "generated lock {} is stale; run `hell-ci catalog-lock write` and recollect evidence",
            relative_path.display()
        ))
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", path.display()))?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
    let mut temporary_name = path.file_name().unwrap_or_default().to_os_string();
    temporary_name.push(".tmp");
    let temporary = path.with_file_name(temporary_name);
    fs::write(&temporary, bytes)
        .map_err(|error| format!("cannot write {}: {error}", temporary.display()))?;
    fs::rename(&temporary, path)
        .map_err(|error| format!("cannot replace {}: {error}", path.display()))
}

fn push_json_string(output: &mut String, value: &str) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            value if value <= '\u{1f}' => {
                output.push_str("\\u");
                write!(output, "{:04x}", u32::from(value)).expect("writing to String cannot fail");
            }
            value => output.push(value),
        }
    }
    output.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committed_locks_match_every_evidence_relevant_input() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("workspace root");
        verify_repository_locks(root).expect("committed assurance locks are current");
    }

    #[test]
    fn canonical_records_are_ordered_and_path_sensitive() {
        let mut records = BTreeMap::new();
        records.insert("z.toml".to_owned(), sha256_bytes(b"z\n"));
        records.insert("a.toml".to_owned(), sha256_bytes(b"a\n"));
        let rendered = canonical_records(&records);
        assert!(rendered.starts_with("\"a.toml\" "));
        assert!(rendered.find("\"a.toml\"").unwrap() < rendered.find("\"z.toml\"").unwrap());
        assert_ne!(
            sha256_bytes(rendered.as_bytes()),
            sha256_bytes(rendered.replace("a.toml", "b.toml").as_bytes())
        );
    }

    #[test]
    fn lock_rendering_excludes_review_outputs_and_the_locks_themselves() {
        assert!(excluded(&component_path([
            "compat",
            "locks",
            "catalog-digests.json"
        ])));
        assert!(excluded(&component_path([
            "compat",
            "reviews",
            "review.dsse.json"
        ])));
        assert!(excluded(&component_path([
            "compat",
            "promotion-review.toml"
        ])));
        assert!(excluded(&component_path([
            "compat",
            "review-revocations.toml"
        ])));
        assert!(!excluded(&component_path(["compat", "review-policy.toml"])));
    }
}
