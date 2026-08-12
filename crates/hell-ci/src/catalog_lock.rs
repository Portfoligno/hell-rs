use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;
use std::process::Command;

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
    &["compat", "collection-activation.toml"],
    &["compat", "collection-activation-claims.json"],
    &["compat", "collection-activation-provenance.json"],
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

pub(crate) fn require_clean_repository_lock_inputs(root: &Path) -> Result<(), String> {
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(root)
        .args(["status", "--porcelain=v1", "--untracked-files=all", "--"]);
    for source in SOURCE_FILES.iter().chain(SOURCE_DIRECTORIES) {
        command.arg(components_path(source));
    }
    let output = command
        .output()
        .map_err(|error| format!("cannot inspect assurance lock input cleanliness: {error}"))?;
    if !output.status.success() || !output.stderr.is_empty() {
        return Err("cannot inspect assurance lock input cleanliness".to_owned());
    }
    let status = std::str::from_utf8(&output.stdout)
        .map_err(|_| "assurance lock input status is not UTF-8".to_owned())?;
    for line in status.lines() {
        let path = line
            .get(3..)
            .map(|value| {
                value
                    .rsplit_once(" -> ")
                    .map_or(value, |(_, target)| target)
            })
            .ok_or_else(|| "assurance lock input status is malformed".to_owned())?;
        if !excluded(root, Path::new(path)) {
            return Err(format!(
                "assurance lock input {path} is not clean at exact HEAD"
            ));
        }
    }
    Ok(())
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

pub(crate) fn prospective_collection_activation_locks_with_reviews(
    root: &Path,
    active_manifest: &[u8],
    claims: &[u8],
    provenance: &[u8],
    proposal_package: &Path,
    author_package: &Path,
    reviewer_package: &Path,
) -> Result<(String, String), String> {
    let mut additions = BTreeMap::from([(
        component_path(["compat", "collection-activation-claims.json"]),
        claims.to_vec(),
    )]);
    collect_prospective_package(
        proposal_package,
        &component_path(["compat", "collection-activation-review-subject"]),
        &mut additions,
    )?;
    collect_prospective_package(
        author_package,
        &component_path(["compat", "collection-activation-reviews", "claim-author"]),
        &mut additions,
    )?;
    collect_prospective_package(
        reviewer_package,
        &component_path(["compat", "collection-activation-reviews", "claim-reviewer"]),
        &mut additions,
    )?;
    prospective_collection_activation_locks_with_inputs(
        root,
        active_manifest,
        Some(provenance),
        &additions,
    )
}

fn collect_prospective_package(
    source: &Path,
    destination: &Path,
    additions: &mut BTreeMap<std::path::PathBuf, Vec<u8>>,
) -> Result<(), String> {
    let metadata = fs::symlink_metadata(source)
        .map_err(|error| format!("cannot inspect prospective activation review: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("prospective activation review is not a real directory".to_owned());
    }
    let mut entries = fs::read_dir(source)
        .map_err(|error| format!("cannot enumerate prospective activation review: {error}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("cannot enumerate prospective activation review: {error}"))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| format!("cannot inspect prospective activation review: {error}"))?;
        let target = destination.join(entry.file_name());
        if metadata.file_type().is_symlink() {
            return Err("prospective activation review contains a symlink".to_owned());
        }
        if metadata.is_dir() {
            collect_prospective_package(&entry.path(), &target, additions)?;
        } else if metadata.is_file() {
            let bytes = fs::read(entry.path())
                .map_err(|error| format!("cannot read prospective activation review: {error}"))?;
            if additions.insert(target, bytes).is_some() {
                return Err("prospective activation review path is duplicated".to_owned());
            }
        } else {
            return Err("prospective activation review contains a non-regular node".to_owned());
        }
    }
    Ok(())
}

pub(crate) fn prospective_collection_activation_locks_with_claims(
    root: &Path,
    active_manifest: &[u8],
    claims: &[u8],
) -> Result<(String, String), String> {
    let additions = BTreeMap::from([(
        component_path(["compat", "collection-activation-claims.json"]),
        claims.to_vec(),
    )]);
    prospective_collection_activation_locks_with_inputs(root, active_manifest, None, &additions)
}

fn prospective_collection_activation_locks_with_inputs(
    root: &Path,
    active_manifest: &[u8],
    provenance: Option<&[u8]>,
    additions: &BTreeMap<std::path::PathBuf, Vec<u8>>,
) -> Result<(String, String), String> {
    let relative = component_path(["compat", "collection-activation.toml"]);
    let provenance_relative = component_path(["compat", "collection-activation-provenance.json"]);
    let mut catalogs = BTreeMap::new();
    for catalog in CATALOG_PATHS {
        let catalog = components_path(catalog);
        add_file_with_overrides(
            root,
            &catalog,
            &relative,
            active_manifest,
            &provenance_relative,
            provenance,
            &mut catalogs,
        )?;
    }
    for (relative, bytes) in additions {
        if CATALOG_PATHS
            .iter()
            .any(|catalog| components_path(catalog) == *relative)
        {
            insert_prospective_input(&mut catalogs, relative, bytes)?;
        }
    }
    let catalog_digest = sha256_bytes(canonical_records(&catalogs).as_bytes());
    let catalog_lock = render_lock(
        "catalog-digests",
        "catalogSetSha256",
        catalog_digest,
        "catalogs",
        &catalogs,
    );
    let mut inputs = BTreeMap::new();
    for source in SOURCE_FILES {
        let source = components_path(source);
        add_file_with_overrides(
            root,
            &source,
            &relative,
            active_manifest,
            &provenance_relative,
            provenance,
            &mut inputs,
        )?;
    }
    for source in SOURCE_DIRECTORIES {
        let directory = root.join(components_path(source));
        if directory.is_dir() {
            collect_source_inputs_with_override(
                root,
                &directory,
                &relative,
                active_manifest,
                &provenance_relative,
                provenance,
                &mut inputs,
            )?;
        }
    }
    for (relative, bytes) in additions {
        if included_source_input(root, relative) {
            insert_prospective_input(&mut inputs, relative, bytes)?;
        }
    }
    let input_digest = sha256_bytes(canonical_records(&inputs).as_bytes());
    Ok((
        catalog_lock,
        render_lock(
            "collection-epoch-inputs",
            "sourceInputsSha256",
            input_digest,
            "inputs",
            &inputs,
        ),
    ))
}

fn insert_prospective_input(
    inputs: &mut BTreeMap<String, Digest>,
    relative: &Path,
    bytes: &[u8],
) -> Result<(), String> {
    let key = relative
        .to_str()
        .ok_or_else(|| "prospective activation input path is not UTF-8".to_owned())?
        .replace(std::path::MAIN_SEPARATOR, "/");
    if bytes.last() != Some(&b'\n') {
        return Err("prospective activation input is not canonical text".to_owned());
    }
    inputs.insert(key, sha256_bytes(bytes));
    Ok(())
}

fn add_file_with_overrides(
    root: &Path,
    relative: &Path,
    override_path: &Path,
    override_bytes: &[u8],
    provenance_path: &Path,
    provenance: Option<&[u8]>,
    files: &mut BTreeMap<String, Digest>,
) -> Result<(), String> {
    let bytes = if relative == override_path {
        Some(override_bytes)
    } else if relative == provenance_path {
        provenance
    } else {
        None
    };
    let Some(bytes) = bytes else {
        return add_file(root, relative, files);
    };
    let key = relative
        .to_str()
        .ok_or_else(|| "prospective activation path is not UTF-8".to_owned())?
        .replace(std::path::MAIN_SEPARATOR, "/");
    if bytes.last() != Some(&b'\n') || files.insert(key, sha256_bytes(bytes)).is_some() {
        return Err("prospective activation input is invalid or duplicated".to_owned());
    }
    Ok(())
}

fn collect_source_inputs_with_override(
    root: &Path,
    directory: &Path,
    override_path: &Path,
    override_bytes: &[u8],
    provenance_path: &Path,
    provenance: Option<&[u8]>,
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
        if excluded(root, relative) {
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
            collect_source_inputs_with_override(
                root,
                &path,
                override_path,
                override_bytes,
                provenance_path,
                provenance,
                inputs,
            )?;
        } else if file_type.is_file() && included_source_input(root, relative) {
            add_file_with_overrides(
                root,
                relative,
                override_path,
                override_bytes,
                provenance_path,
                provenance,
                inputs,
            )?;
        }
    }
    Ok(())
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
        if excluded(root, relative) {
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
        } else if file_type.is_file() && included_source_input(root, relative) {
            add_file(root, relative, inputs)?;
        }
    }
    Ok(())
}

fn excluded(root: &Path, relative: &Path) -> bool {
    relative.starts_with(component_path(["compat", "locks"]))
        || relative.starts_with(component_path(["compat", "reviews"]))
        || relative == component_path(["compat", "promotion-review.toml"])
        || relative == component_path(["compat", "review-revocations.toml"])
        || cargo_target_ancestor(root, relative)
}

fn cargo_target_ancestor(root: &Path, relative: &Path) -> bool {
    relative.ancestors().any(|ancestor| {
        ancestor.file_name() == Some(OsStr::new("target"))
            && ancestor.parent().is_some_and(|package| {
                fs::symlink_metadata(root.join(package).join("Cargo.toml"))
                    .is_ok_and(|metadata| !metadata.file_type().is_symlink() && metadata.is_file())
            })
    })
}

fn evidence_relevant(path: &Path) -> bool {
    matches!(
        path.extension().and_then(OsStr::to_str),
        Some("hell" | "json" | "py" | "ron" | "rs" | "stdout" | "toml" | "tsv" | "yaml" | "yml")
    ) || path.file_name().and_then(OsStr::to_str) == Some("Cargo.lock")
}

fn included_source_input(root: &Path, path: &Path) -> bool {
    !excluded(root, path) && evidence_relevant(path)
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
    fn nested_cargo_target_outputs_do_not_change_source_input_lock() {
        let root = std::env::temp_dir().join(format!(
            "hell-catalog-lock-nested-target-{}",
            std::process::id()
        ));
        if root.exists() {
            fs::remove_dir_all(&root).unwrap();
        }
        let package = root.join("crates/example");
        fs::create_dir_all(package.join("src/target")).unwrap();
        fs::write(
            package.join("Cargo.toml"),
            b"[package]\nname = \"example\"\nversion = \"0.0.0\"\n",
        )
        .unwrap();
        fs::write(package.join("src/lib.rs"), b"pub fn source() {}\n").unwrap();
        fs::write(
            package.join("src/target/model.rs"),
            b"pub struct ReviewedTarget;\n",
        )
        .unwrap();

        let mut before = BTreeMap::new();
        collect_source_inputs(&root, &root.join("crates"), &mut before).unwrap();
        assert!(before.contains_key("crates/example/src/target/model.rs"));

        for generated in [
            "target/.rustc_info.json",
            "target/debug/build/example/output.json",
            "target/debug/.fingerprint/example/cache.json",
        ] {
            let path = package.join(generated);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, b"generated without canonical newline").unwrap();
        }
        let mut after = BTreeMap::new();
        collect_source_inputs(&root, &root.join("crates"), &mut after).unwrap();
        assert_eq!(after, before);
        assert!(
            after
                .keys()
                .all(|path| !path.starts_with("crates/example/target/"))
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn collection_activation_is_an_exact_catalog_and_epoch_input() {
        assert!(CATALOG_PATHS.contains(&&["compat", "collection-activation.toml"][..]));
        assert!(SOURCE_DIRECTORIES.contains(&&["compat"][..]));
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("workspace root");
        let dormant_catalog = render_catalog_lock(root).unwrap();
        let temporary = std::env::temp_dir().join(format!(
            "hell-collection-activation-lock-{}",
            std::process::id()
        ));
        if temporary.exists() {
            fs::remove_dir_all(&temporary).unwrap();
        }
        fs::create_dir_all(temporary.join("compat")).unwrap();
        for path in CATALOG_PATHS {
            let relative = components_path(path);
            let destination = temporary.join(&relative);
            fs::create_dir_all(destination.parent().unwrap()).unwrap();
            fs::copy(root.join(relative), destination).unwrap();
        }
        fs::write(
            temporary.join("compat/collection-activation.toml"),
            b"schema_version = 1\ndomain = \"hell.collection-activation.v1\"\nmap712 = true\nset479 = true\n",
        )
        .unwrap();
        assert_ne!(render_catalog_lock(&temporary).unwrap(), dormant_catalog);
        fs::remove_dir_all(temporary).unwrap();
    }

    #[test]
    fn lock_rendering_excludes_review_outputs_and_the_locks_themselves() {
        let root = Path::new(".");
        assert!(excluded(
            root,
            &component_path(["compat", "locks", "catalog-digests.json"])
        ));
        assert!(excluded(
            root,
            &component_path(["compat", "reviews", "review.dsse.json"])
        ));
        assert!(excluded(
            root,
            &component_path(["compat", "promotion-review.toml"])
        ));
        assert!(excluded(
            root,
            &component_path(["compat", "review-revocations.toml"])
        ));
        assert!(!excluded(
            root,
            &component_path(["compat", "review-policy.toml"])
        ));
    }

    #[test]
    fn prospective_review_inputs_use_the_materialized_epoch_file_predicate() {
        let root = Path::new(".");
        assert!(included_source_input(
            root,
            &component_path([
                "compat",
                "collection-activation-reviews",
                "claim-author",
                "review.dsse.json"
            ])
        ));
        assert!(included_source_input(
            root,
            &component_path([
                "compat",
                "collection-activation-review-subject",
                "review-subject.json"
            ])
        ));
        assert!(!included_source_input(
            root,
            &component_path([
                "compat",
                "collection-activation-reviews",
                "claim-author",
                "review.dsse.json.sha256"
            ])
        ));
        assert!(!included_source_input(
            root,
            &component_path([
                "compat",
                "collection-activation-review-subject",
                "root.sha256"
            ])
        ));
        assert!(!included_source_input(
            root,
            &component_path(["compat", "reviews", "review.dsse.json"])
        ));
    }
}
