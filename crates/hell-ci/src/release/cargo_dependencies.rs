//! Locked package data crosses this boundary; runner Cargo configuration and
//! credentials do not. Acquisition runs on the trusted host, execution offline.

use std::collections::{BTreeMap, BTreeSet};
#[cfg(target_os = "linux")]
use std::ffi::OsString;
use std::fs;
#[cfg(target_os = "linux")]
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

use super::manifest::read_regular;
#[cfg(target_os = "linux")]
use super::manifest::write_atomic_new;
#[cfg(target_os = "linux")]
use super::platform::{TrustedCargoCacheSeed, copy_posix_cargo_cache_tree};
use super::platform::{
    TrustedCargoSeedInputFile, validate_staged_vendor_covers_frozen_lock,
    validate_trusted_cargo_cache_tree,
};
#[cfg(target_os = "linux")]
use super::schema::ReleasePlatform;
#[cfg(target_os = "linux")]
use crate::command::{CommandResult, CommandSpec, ResolvedCargoExecutable};
#[cfg(target_os = "linux")]
use crate::process_environment::{ProcessEnvironment, StandardVariable};

const MAX_LOCK_BYTES: usize = 16 * 1024 * 1024;
const MAX_PACKAGES: usize = 4096;

pub struct FrozenDependencyInputs {
    bindings: Vec<(
        PathBuf,
        TrustedCargoSeedInputFile,
        TrustedCargoSeedInputFile,
    )>,
}

impl FrozenDependencyInputs {
    pub fn bind(roots: &[PathBuf]) -> Result<Self, String> {
        if roots.is_empty() {
            return Err("dependency workspace inventory is empty".to_owned());
        }
        let bindings = roots
            .iter()
            .map(|root| {
                Ok((
                    root.clone(),
                    TrustedCargoSeedInputFile::bind(root, "Cargo.toml")?,
                    TrustedCargoSeedInputFile::bind(root, "Cargo.lock")?,
                ))
            })
            .collect::<Result<_, String>>()?;
        Ok(Self { bindings })
    }

    pub fn revalidate(&self) -> Result<(), String> {
        for (root, manifest, lock) in &self.bindings {
            if TrustedCargoSeedInputFile::bind(root, "Cargo.toml")? != *manifest
                || TrustedCargoSeedInputFile::bind(root, "Cargo.lock")? != *lock
            {
                return Err("locked dependency inputs changed during acquisition".to_owned());
            }
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn workspace_roots(repository: &Path, operation: &str) -> Result<Vec<PathBuf>, String> {
    if !matches!(
        operation,
        "mutation" | "regression-subject" | "regression-corpus" | "nightly" | "fuzz"
    ) {
        return Err("dependency acquisition has no typed operation scope".to_owned());
    }
    let mut roots = vec![repository.to_path_buf()];
    if operation == "fuzz" {
        for relative in crate::fuzz::tool_requirements(repository)?.fuzz_directories {
            if relative.is_absolute()
                || relative
                    .components()
                    .any(|part| !matches!(part, Component::Normal(_)))
            {
                return Err("fuzz dependency workspace is not a contained relative path".to_owned());
            }
            roots.push(repository.join(relative));
        }
    }
    for root in &roots {
        if fs::canonicalize(root).ok().as_deref() != Some(root.as_path())
            || !root.starts_with(repository)
        {
            return Err("dependency workspace root is redirected".to_owned());
        }
        TrustedCargoSeedInputFile::bind(root, "Cargo.toml")?;
        TrustedCargoSeedInputFile::bind(root, "Cargo.lock")?;
    }
    Ok(roots)
}

#[cfg(target_os = "linux")]
fn source_digest(repository: &Path) -> Result<String, String> {
    Ok(
        hell_testkit::sha256_bytes(&crate::json::canonical_json_bytes(
            &super::plan::source_inventory(repository)?,
        )?)
        .hex(),
    )
}

#[cfg(target_os = "linux")]
fn checked_result(result: CommandResult, phase: &str) -> Result<CommandResult, String> {
    if result.timed_out
        || !result.status.success()
        || result.stdout_truncated
        || result.stderr_truncated
    {
        return Err(format!(
            "locked Cargo {phase} failed: status={:?}, timed_out={}, stderr={}",
            result.status.code(),
            result.timed_out,
            String::from_utf8_lossy(&result.stderr)
        ));
    }
    Ok(result)
}

#[cfg(target_os = "linux")]
pub(crate) fn stage_operation_dependencies(
    repository: &Path,
    operation: &str,
    cargo: &ResolvedCargoExecutable,
    rustup_home: &Path,
    toolchain: &str,
    destination: &Path,
    cargo_home: &Path,
    deadline: Instant,
) -> Result<(), String> {
    let roots = workspace_roots(repository, operation)?;
    let locks = roots
        .iter()
        .map(|root| read_regular(&root.join("Cargo.lock")))
        .collect::<Result<Vec<_>, _>>()?;
    for lock in &locks {
        locked_packages(lock)?;
    }
    if destination
        != repository
            .parent()
            .ok_or("dependency source parent absent")?
            .join("dependencies")
        || fs::symlink_metadata(destination).is_ok()
        || fs::canonicalize(cargo_home).ok().as_deref() != Some(cargo_home)
        || fs::symlink_metadata(cargo_home.join("config.toml")).is_ok()
    {
        return Err("dependency destination or Cargo state is not fresh authority".to_owned());
    }
    let before = source_digest(repository)?;
    let bound = FrozenDependencyInputs::bind(&roots)?;
    let program = hell_testkit::BoundProgramInvocation::new(
        cargo.invocation_path().to_path_buf(),
        cargo.canonical_identity().to_path_buf(),
    )
    .map_err(|error| error.to_string())?;
    let compiler = rustup_home
        .join("toolchains")
        .join(toolchain)
        .join("bin")
        .join("rustc");
    let compiler_parent = compiler.parent().ok_or("selected compiler parent absent")?;
    let compiler_identity = TrustedCargoSeedInputFile::bind(compiler_parent, "rustc")?;
    let seed = TrustedCargoCacheSeed::create(ReleasePlatform::LinuxX86_64)?;
    let run = |arguments: Vec<OsString>, phase: &str| -> Result<CommandResult, String> {
        seed.validate()?;
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|value| !value.is_zero())
            .ok_or("dependency acquisition deadline expired")?;
        let result = CommandSpec::trusted_cargo(remaining.min(Duration::from_mins(5)), cargo)
            .release_candidate_environment()
            .arguments(arguments)
            .current_directory(repository)
            .environment("CARGO_HOME", seed.root())
            .environment("HOME", seed.root())
            .environment("CARGO_TARGET_DIR", seed.root().join("target"))
            .environment("RUSTUP_HOME", rustup_home)
            .environment("RUSTUP_TOOLCHAIN", toolchain)
            .environment("RUSTC", &compiler)
            .environment("RUSTC_WRAPPER", "")
            .run_trusted_host_captured()
            .map_err(|error| format!("trusted dependency acquisition could not launch: {error}"))?;
        checked_result(result, phase)
    };
    for root in &roots {
        run(
            vec![
                "fetch".into(),
                "--locked".into(),
                "--manifest-path".into(),
                root.join("Cargo.toml").into(),
            ],
            "fetch",
        )?;
    }
    let vendor = seed.vendor_root();
    let mut arguments = vec![
        "vendor".into(),
        "--locked".into(),
        "--offline".into(),
        "--versioned-dirs".into(),
        "--manifest-path".into(),
        repository.join("Cargo.toml").into(),
    ];
    for root in roots.iter().skip(1) {
        arguments.extend([OsString::from("--sync"), root.join("Cargo.toml").into()]);
    }
    arguments.push(vendor.clone().into());
    run(arguments, "vendor")?;
    seed.validate()?;
    bound.revalidate()?;
    if source_digest(repository)? != before
        || TrustedCargoSeedInputFile::bind(compiler_parent, "rustc")? != compiler_identity
        || hell_testkit::BoundProgramInvocation::new(
            cargo.invocation_path().to_path_buf(),
            cargo.canonical_identity().to_path_buf(),
        )
        .map_err(|error| error.to_string())?
            != program
    {
        return Err(
            "dependency source or selected toolchain changed during acquisition".to_owned(),
        );
    }
    validate_dependency_vendor(&locks, &vendor)?;
    fs::create_dir(destination).map_err(|error| error.to_string())?;
    let staged_vendor = destination.join("vendor");
    let mut entries = 0;
    let mut bytes = 0;
    copy_posix_cargo_cache_tree(&vendor, &staged_vendor, &mut entries, &mut bytes)?;
    validate_dependency_vendor(&locks, &staged_vendor)?;
    let config = dependency_directory_config(&staged_vendor)?;
    let manifests: Vec<_> = roots.iter().map(|root| Ok(serde_json::json!({
        "manifest": root.join("Cargo.toml").strip_prefix(repository).map_err(|error| error.to_string())?,
        "manifest_sha256": hell_testkit::sha256_file(&root.join("Cargo.toml")).map_err(|error| error.to_string())?.hex(),
        "lock_sha256": hell_testkit::sha256_file(&root.join("Cargo.lock")).map_err(|error| error.to_string())?.hex(),
    }))).collect::<Result<_, String>>()?;
    let receipt = serde_json::json!({"schema_version":1, "operation":operation, "source_sha256": before,
        "toolchain":toolchain, "compiler_sha256":hell_testkit::sha256_file(&compiler).map_err(|error| error.to_string())?.hex(),
        "config_sha256":hell_testkit::sha256_bytes(&config).hex(), "manifests":manifests});
    let mut receipt = serde_json::to_vec(&receipt).map_err(|error| error.to_string())?;
    receipt.push(b'\n');
    write_atomic_new(&destination.join("closure.json"), &receipt)?;
    freeze_tree(destination)?;
    write_atomic_new(&cargo_home.join("config.toml"), &config)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn freeze_tree(root: &Path) -> Result<(), String> {
    validate_trusted_cargo_cache_tree(root)?;
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
        if metadata.is_dir() {
            for entry in fs::read_dir(&path).map_err(|error| error.to_string())? {
                pending.push(entry.map_err(|error| error.to_string())?.path());
            }
        }
        let mode = if metadata.is_dir() || metadata.permissions().mode() & 0o111 != 0 {
            0o555
        } else {
            0o444
        };
        fs::set_permissions(&path, fs::Permissions::from_mode(mode))
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

pub fn dependency_directory_config(vendor: &Path) -> Result<Vec<u8>, String> {
    if !vendor.is_absolute()
        || vendor
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err("dependency directory source is not absolute canonical authority".to_owned());
    }
    let path = vendor
        .to_str()
        .ok_or("Cargo directory-source path is not Unicode")?;
    let encoded = serde_json::to_string(path).map_err(|error| error.to_string())?;
    Ok(format!("[net]\noffline = true\n\n[source.crates-io]\nreplace-with = 'hell-locked-dependencies'\n\n[source.hell-locked-dependencies]\ndirectory = {encoded}\n").into_bytes())
}

fn locked_packages(document: &[u8]) -> Result<BTreeMap<String, String>, String> {
    if document.is_empty() || document.len() > MAX_LOCK_BYTES {
        return Err("dependency lock byte authority exceeded".to_owned());
    }
    let text = std::str::from_utf8(document).map_err(|error| error.to_string())?;
    let mut packages = BTreeMap::new();
    for section in text.split("[[package]]").skip(1) {
        let fields = crate::strict_toml::assignments(section)?;
        let value = |key: &str| -> Result<String, String> {
            crate::strict_toml::string(
                fields
                    .get(key)
                    .ok_or_else(|| format!("locked dependency lacks {key}"))?,
            )
        };
        if !fields.contains_key("source") {
            continue;
        }
        if value("source")? != "registry+https://github.com/rust-lang/crates.io-index" {
            return Err("dependency source is outside the admitted crates.io registry".to_owned());
        }
        let name = value("name")?;
        let version = value("version")?;
        if [&name, &version].iter().any(|value| {
            value.is_empty()
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-_.+".contains(&byte))
        }) {
            return Err("locked dependency package identity is invalid".to_owned());
        }
        let checksum = value("checksum")?;
        if checksum.len() != hell_testkit::sha256_bytes(b"").hex().len()
            || !checksum
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err("locked dependency checksum is invalid".to_owned());
        }
        if packages
            .insert(format!("{name}-{version}"), checksum)
            .is_some()
            || packages.len() > MAX_PACKAGES
        {
            return Err("dependency lock package inventory is duplicate or oversized".to_owned());
        }
    }
    if packages.is_empty() {
        return Err("dependency lock package closure is empty".to_owned());
    }
    Ok(packages)
}

pub fn validate_dependency_vendor(locks: &[Vec<u8>], vendor: &Path) -> Result<(), String> {
    validate_trusted_cargo_cache_tree(vendor)?;
    let mut expected = BTreeMap::new();
    for lock in locks {
        validate_staged_vendor_covers_frozen_lock(lock, vendor)?;
        for (name, checksum) in locked_packages(lock)? {
            if expected
                .insert(name, checksum.clone())
                .is_some_and(|previous| previous != checksum)
            {
                return Err("workspace locks disagree on package source checksum".to_owned());
            }
        }
    }
    let observed = fs::read_dir(vendor)
        .map_err(|error| error.to_string())?
        .map(|entry| {
            entry.map_err(|error| error.to_string()).and_then(|entry| {
                entry
                    .file_name()
                    .into_string()
                    .map_err(|_| "non-Unicode package name".to_owned())
            })
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if expected.is_empty() || observed != expected.keys().cloned().collect() {
        return Err("vendor package inventory differs from exact lock closure".to_owned());
    }
    for (package, checksum) in expected {
        let root = vendor.join(package);
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Checksums {
            #[serde(rename = "$comment", default)]
            _comment: String,
            package: String,
            files: BTreeMap<String, String>,
        }
        let checksum_path = root.join(".cargo-checksum.json");
        let checksums: Checksums =
            serde_json::from_slice(&read_regular(&checksum_path)?).map_err(|error| {
                format!(
                    "invalid vendor checksum metadata {}: {error}",
                    checksum_path.display()
                )
            })?;
        if checksums.package != checksum {
            return Err("vendor package checksum differs from frozen lock".to_owned());
        }
        let mut actual = BTreeSet::new();
        let mut pending = vec![root.clone()];
        while let Some(directory) = pending.pop() {
            for entry in fs::read_dir(directory).map_err(|error| error.to_string())? {
                let entry = entry.map_err(|error| error.to_string())?;
                if entry
                    .file_type()
                    .map_err(|error| error.to_string())?
                    .is_dir()
                {
                    pending.push(entry.path());
                    continue;
                }
                let path = entry.path();
                let relative = path
                    .strip_prefix(&root)
                    .map_err(|error| error.to_string())?
                    .to_str()
                    .ok_or("non-Unicode package path")?
                    .to_owned();
                if relative == ".cargo-checksum.json" {
                    continue;
                }
                let digest = checksums
                    .files
                    .get(&relative)
                    .ok_or("vendor contains an unchecked package file")?;
                if hell_testkit::sha256_file(&path)
                    .map_err(|error| error.to_string())?
                    .hex()
                    != *digest
                {
                    return Err("vendor package file checksum differs".to_owned());
                }
                actual.insert(relative);
            }
        }
        if actual != checksums.files.keys().cloned().collect() {
            return Err("vendor omits a checksummed package file".to_owned());
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn prove_operation_dependencies_offline(
    repository: &Path,
    operation: &str,
) -> Result<(), String> {
    let roots = workspace_roots(repository, operation)?;
    let environment = ProcessEnvironment::from_process();
    let cargo = environment.required_singleton_value(StandardVariable::Cargo, "CARGO")?;
    let home = PathBuf::from(
        environment.required_singleton_value(StandardVariable::CargoHome, "CARGO_HOME")?,
    );
    let destination = repository
        .parent()
        .ok_or("dependency source parent absent")?
        .join("dependencies");
    let config = dependency_directory_config(&destination.join("vendor"))?;
    if read_regular(&home.join("config.toml"))? != config {
        return Err("candidate Cargo configuration differs from offline closure".to_owned());
    }
    let receipt: serde_json::Value =
        serde_json::from_slice(&read_regular(&destination.join("closure.json"))?)
            .map_err(|error| error.to_string())?;
    let compiler =
        PathBuf::from(environment.required_singleton_value(StandardVariable::Rustc, "RUSTC")?);
    let toolchain = environment
        .required_singleton_value(StandardVariable::RustupToolchain, "RUSTUP_TOOLCHAIN")?
        .to_str()
        .ok_or("selected toolchain is not Unicode")?;
    let manifests = receipt["manifests"]
        .as_array()
        .ok_or("dependency closure manifest inventory absent")?;
    if receipt["schema_version"] != 1
        || receipt["operation"] != operation
        || manifests.len() != roots.len()
        || receipt["config_sha256"] != hell_testkit::sha256_bytes(&config).hex()
        || receipt["toolchain"] != toolchain
        || receipt["compiler_sha256"]
            != hell_testkit::sha256_file(&compiler)
                .map_err(|error| error.to_string())?
                .hex()
    {
        return Err("candidate dependency closure scope differs".to_owned());
    }
    for (root, manifest) in roots.iter().zip(manifests) {
        if manifest["manifest"]
            != root
                .join("Cargo.toml")
                .strip_prefix(repository)
                .map_err(|error| error.to_string())?
                .to_str()
                .ok_or("manifest path is not Unicode")?
            || manifest["manifest_sha256"]
                != hell_testkit::sha256_file(&root.join("Cargo.toml"))
                    .map_err(|error| error.to_string())?
                    .hex()
            || manifest["lock_sha256"]
                != hell_testkit::sha256_file(&root.join("Cargo.lock"))
                    .map_err(|error| error.to_string())?
                    .hex()
        {
            return Err("candidate dependency manifest or lock changed".to_owned());
        }
        let result = CommandSpec::new(cargo, Duration::from_secs(60))
            .arguments([
                OsString::from("fetch"),
                OsString::from("--frozen"),
                OsString::from("--locked"),
                OsString::from("--offline"),
                OsString::from("--manifest-path"),
                root.join("Cargo.toml").into(),
            ])
            .current_directory(repository)
            .run()
            .map_err(|error| error.to_string())?;
        checked_result(result, "candidate offline closure proof")?;
    }
    Ok(())
}
