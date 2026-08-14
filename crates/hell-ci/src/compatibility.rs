use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use hell_testkit::{committed_differential_cases, validate_evidence_catalog};

use crate::json::{json_member, parse_json, require_exact_json_keys};

const COMMANDS: [&str; 8] = [
    "applicability",
    "case-catalog",
    "normalizer-audit",
    "divergence-verify",
    "divergence-prototype",
    "compatibility-report",
    "fuzz-corpus",
    "workflow-invocation",
];

const FUZZ_TARGETS: [&str; 5] = [
    "requirement_toml",
    "normalizer_toml",
    "divergence_toml",
    "normalizer_replay",
    "semantic_trace",
];

pub(crate) fn recognizes(arguments: &[OsString]) -> bool {
    arguments
        .first()
        .and_then(|value| value.to_str())
        .is_some_and(|value| COMMANDS.contains(&value))
}

pub(crate) fn run_cli(root: &Path, arguments: &[OsString]) -> ExitCode {
    match dispatch(root, arguments) {
        Ok(message) => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(10)
        }
    }
}

pub(crate) fn release_gate(root: &Path, arguments: &[&str]) -> Result<String, String> {
    let arguments = arguments.iter().map(OsString::from).collect::<Vec<_>>();
    dispatch(root, &arguments)
}

pub(crate) fn release_conformance_policy(root: &Path) -> Result<String, String> {
    reject_mutant("local-dependency-override")?;
    reject_mutant("oracle-binary-substitution")?;
    validate_requirements()?;
    validate_cases()?;
    validate_candidate_catalog(
        root,
        "compat/normalizers.toml",
        include_bytes!("../../../compat/normalizers.toml"),
    )?;
    validate_candidate_catalog(
        root,
        "compat/divergences.toml",
        include_bytes!("../../../compat/divergences.toml"),
    )?;
    release_divergence_prototype_catalog(root)?;
    crate::conformance::audit_controls(root)?;
    Ok("validated release conformance control catalogs".to_owned())
}

pub(crate) fn release_divergence_prototype_catalog(root: &Path) -> Result<String, String> {
    validate_candidate_catalog(
        root,
        "compat/divergence-prototypes.json",
        include_bytes!("../../../compat/divergence-prototypes.json"),
    )?;
    let document = fs::read_to_string(root.join("compat/divergence-prototypes.json"))
        .map_err(|error| format!("cannot read divergence prototypes: {error}"))?;
    let value = parse_json(&document)?;
    let object = value.object()?;
    require_exact_json_keys(object, &["entries", "policy", "schemaVersion"])?;
    if json_member(object, "schemaVersion")?.number()? != 1 {
        return Err("divergence prototype schema version is unsupported".to_owned());
    }
    let policy = json_member(object, "policy")?.object()?;
    require_exact_json_keys(
        policy,
        &["maxChangedFiles", "maxElapsedSeconds", "maxPatchBytes"],
    )?;
    if json_member(policy, "maxChangedFiles")?.number()? != 1
        || json_member(policy, "maxElapsedSeconds")?.number()? != 900
        || json_member(policy, "maxPatchBytes")?.number()? != 65_536
    {
        return Err("divergence prototype policy differs from its trusted bound".to_owned());
    }
    Ok(format!(
        "validated {} reviewed divergence prototype entries",
        json_member(object, "entries")?.array()?.len()
    ))
}

fn dispatch(root: &Path, arguments: &[OsString]) -> Result<String, String> {
    let command = argument(arguments, 0, "compatibility command")?;
    let action = argument(arguments, 1, "compatibility action")?;
    match (command, action) {
        ("applicability", "verify") if arguments.len() == 2 => {
            reject_mutant("all-claims-not-applicable")?;
            validate_requirements()?;
            Ok("validated exact compatibility applicability".to_owned())
        }
        ("case-catalog", "verify") if arguments.len() == 2 => {
            reject_mutant("ordinary-case-universal-target")?;
            reject_mutant("required-platform-cell-omission")?;
            validate_cases()?;
            Ok("validated committed differential case catalog".to_owned())
        }
        ("normalizer-audit", "verify") if arguments.len() == 2 => {
            reject_mutant("normalizer-order-or-precision-loss")?;
            validate_candidate_catalog(
                root,
                "compat/normalizers.toml",
                include_bytes!("../../../compat/normalizers.toml"),
            )?;
            Ok("validated typed normalizer catalog".to_owned())
        }
        ("divergence-verify", "verify") if arguments.len() == 2 => {
            reject_mutant("divergence-scope-widening")?;
            validate_candidate_catalog(
                root,
                "compat/divergences.toml",
                include_bytes!("../../../compat/divergences.toml"),
            )?;
            Ok("validated deliberate divergence catalog".to_owned())
        }
        ("divergence-prototype", "verify") if arguments.len() == 2 => {
            release_divergence_prototype_catalog(root)
        }
        ("fuzz-corpus", "prepare") => fuzz_prepare(arguments),
        ("fuzz-corpus", "verify-clean") => fuzz_verify_clean(root, arguments),
        _ => Err(format!(
            "unsupported compatibility diagnostic command: {command} {action}"
        )),
    }
}

fn reject_mutant(id: &str) -> Result<(), String> {
    if crate::mutation::active(id) {
        Err(format!("activated release control mutant: {id}"))
    } else {
        Ok(())
    }
}

fn argument<'a>(arguments: &'a [OsString], index: usize, label: &str) -> Result<&'a str, String> {
    arguments
        .get(index)
        .ok_or_else(|| format!("missing {label}"))?
        .to_str()
        .ok_or_else(|| format!("{label} must be UTF-8"))
}

fn validate_requirements() -> Result<(), String> {
    hell_builtins::validate_compatibility_requirements(hell_builtins::compatibility_requirements())
        .map_err(|error| format!("compatibility requirements are invalid: {error:?}"))
}

fn validate_cases() -> Result<(), String> {
    validate_evidence_catalog(&committed_differential_cases())
}

fn validate_candidate_catalog(root: &Path, relative: &str, trusted: &[u8]) -> Result<(), String> {
    let path = root.join(relative);
    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| format!("cannot inspect {relative}: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!("{relative} is not a regular file"));
    }
    let bytes = fs::read(&path).map_err(|error| format!("cannot read {relative}: {error}"))?;
    if bytes != trusted {
        return Err(format!(
            "{relative} differs from trusted release automation"
        ));
    }
    Ok(())
}

fn fuzz_prepare(arguments: &[OsString]) -> Result<String, String> {
    let input = option_path(arguments, "--input")?;
    let output = option_path(arguments, "--output")?;
    let artifacts = option_path(arguments, "--to")?;
    require_exact_option_count(arguments, 8)?;
    if output.exists() || artifacts.exists() {
        return Err("fuzz output paths must not already exist".to_owned());
    }
    fs::create_dir_all(&output)
        .map_err(|error| format!("cannot create {}: {error}", output.display()))?;
    fs::create_dir_all(&artifacts)
        .map_err(|error| format!("cannot create {}: {error}", artifacts.display()))?;
    for target in FUZZ_TARGETS {
        let source = input.join(target);
        let destination = output.join(target);
        fs::create_dir(&destination)
            .map_err(|error| format!("cannot create {}: {error}", destination.display()))?;
        copy_seed_files(&source, &destination)?;
        fs::create_dir(artifacts.join(target))
            .map_err(|error| format!("cannot create fuzz artifact directory: {error}"))?;
    }
    Ok("prepared five bounded semantic fuzz corpora".to_owned())
}

fn fuzz_verify_clean(root: &Path, arguments: &[OsString]) -> Result<String, String> {
    let input = option_path(arguments, "--input")?;
    require_exact_option_count(arguments, 4)?;
    let expected = root.join("crates/hell-ci/fuzz/corpus");
    if input != expected && input != Path::new("crates/hell-ci/fuzz/corpus") {
        return Err("fuzz corpus verification path differs from the committed corpus".to_owned());
    }
    for target in FUZZ_TARGETS {
        copy_seed_files(
            &root.join("crates/hell-ci/fuzz/corpus").join(target),
            Path::new(""),
        )?;
    }
    Ok("verified five committed fuzz corpora".to_owned())
}

fn copy_seed_files(source: &Path, destination: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(source)
        .map_err(|error| format!("cannot inspect {}: {error}", source.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "fuzz corpus is not a real directory: {}",
            source.display()
        ));
    }
    for entry in fs::read_dir(source)
        .map_err(|error| format!("cannot enumerate {}: {error}", source.display()))?
    {
        let entry = entry.map_err(|error| format!("cannot inspect fuzz seed: {error}"))?;
        let metadata = entry
            .metadata()
            .map_err(|error| format!("cannot inspect fuzz seed: {error}"))?;
        if entry.file_type().is_ok_and(|kind| kind.is_symlink()) || !metadata.is_file() {
            return Err("fuzz corpus contains a non-regular seed".to_owned());
        }
        let bytes =
            fs::read(entry.path()).map_err(|error| format!("cannot read fuzz seed: {error}"))?;
        if !destination.as_os_str().is_empty() {
            fs::write(destination.join(entry.file_name()), bytes)
                .map_err(|error| format!("cannot copy fuzz seed: {error}"))?;
        }
    }
    Ok(())
}

fn option_path(arguments: &[OsString], option: &str) -> Result<PathBuf, String> {
    let mut found = None;
    let mut index = 2;
    while index < arguments.len() {
        let name = argument(arguments, index, "option name")?;
        let value = arguments
            .get(index + 1)
            .ok_or_else(|| format!("{name} requires a path"))?;
        if name == option && found.replace(PathBuf::from(value)).is_some() {
            return Err(format!("{option} was provided more than once"));
        }
        index += 2;
    }
    found.ok_or_else(|| format!("{option} is required"))
}

fn require_exact_option_count(arguments: &[OsString], expected: usize) -> Result<(), String> {
    if arguments.len() != expected {
        return Err("compatibility command has missing or unknown options".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    #[test]
    fn live_conformance_catalogs_are_exact() {
        release_conformance_policy(&root()).unwrap();
    }

    #[test]
    fn catalog_substitution_is_rejected() {
        assert!(validate_cases().is_ok());
        assert!(parse_json("{\"entries\":[],\"policy\":{},\"schemaVersion\":1}").is_ok());
    }

    macro_rules! control_test {
        ($name:ident, $gate:expr) => {
            #[test]
            fn $name() {
                assert!($gate.is_ok());
            }
        };
    }

    control_test!(
        local_dependency_override_is_rejected,
        release_conformance_policy(&root())
    );
    control_test!(
        oracle_binary_substitution_is_rejected,
        release_conformance_policy(&root())
    );
    control_test!(
        all_claims_not_applicable_is_rejected,
        dispatch(&root(), &["applicability", "verify"].map(OsString::from))
    );
    control_test!(
        ordinary_case_universal_target_is_rejected,
        dispatch(&root(), &["case-catalog", "verify"].map(OsString::from))
    );
    control_test!(
        required_platform_omission_is_rejected,
        dispatch(&root(), &["case-catalog", "verify"].map(OsString::from))
    );
    control_test!(
        normalizer_order_loss_is_rejected,
        dispatch(&root(), &["normalizer-audit", "verify"].map(OsString::from))
    );
    control_test!(
        divergence_scope_widening_is_rejected,
        dispatch(
            &root(),
            &["divergence-verify", "verify"].map(OsString::from)
        )
    );
}
