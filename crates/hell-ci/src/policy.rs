mod release_workflow;

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::command::CommandSpec;

pub fn check_repository(root: &Path) -> Result<(), String> {
    let tracked = tracked_files(root)?;
    let mut failures = Vec::new();
    for path in &tracked {
        check_tracked_file(root, path, &mut failures);
    }
    release_workflow::check(root, &tracked, &mut failures);
    check_dormant_collection_activation(root, &mut failures);
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("\n"))
    }
}

pub(crate) fn normalized_relative_path(value: &str) -> Result<PathBuf, String> {
    if value.is_empty()
        || value.contains('\\')
        || value
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(format!("path is not a normalized relative path: {value:?}"));
    }
    let path = PathBuf::from(value);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(format!("path is not a normalized relative path: {value:?}"));
    }
    Ok(path)
}

fn tracked_files(root: &Path) -> Result<Vec<PathBuf>, String> {
    let result = CommandSpec::new("git", Duration::from_secs(30))
        .git_safe_directory(root)
        .arguments(["ls-files", "-z"])
        .current_directory(root)
        .run()
        .map_err(|error| format!("cannot inventory tracked files: {error}"))?;
    if !result.status.success() || !result.stderr.is_empty() {
        return Err("git ls-files failed while inventorying repository policy".to_owned());
    }
    let mut paths = result
        .stdout
        .split(|byte| *byte == 0)
        .filter(|bytes| !bytes.is_empty())
        .map(|bytes| {
            std::str::from_utf8(bytes)
                .map(PathBuf::from)
                .map_err(|_| "tracked path is not UTF-8".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    paths.retain(|path| root.join(path).exists());
    let release_workflow = PathBuf::from(".github/workflows/release.yml");
    if root.join(&release_workflow).is_file() && !paths.contains(&release_workflow) {
        paths.push(release_workflow);
    }
    paths.sort();
    Ok(paths)
}

fn check_tracked_file(root: &Path, relative: &Path, failures: &mut Vec<String>) {
    let path = root.join(relative);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) => {
            failures.push(format!("cannot inspect {}: {error}", relative.display()));
            return;
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        failures.push(format!(
            "tracked path must be a regular file: {}",
            relative.display()
        ));
        return;
    }
    if matches!(
        relative.extension().and_then(|value| value.to_str()),
        Some("sh" | "bash")
    ) {
        failures.push(format!("shell script is forbidden: {}", relative.display()));
    }
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) => {
            failures.push(format!("cannot read {}: {error}", relative.display()));
            return;
        }
    };
    if !bytes.is_empty() && textual(relative, &bytes) && !bytes.ends_with(b"\n") {
        failures.push(format!(
            "tracked text file lacks a trailing newline: {}",
            relative.display()
        ));
    }
}

fn textual(path: &Path, bytes: &[u8]) -> bool {
    let extension = path.extension().and_then(|value| value.to_str());
    matches!(
        extension,
        Some(
            "md" | "rs"
                | "toml"
                | "yml"
                | "yaml"
                | "json"
                | "txt"
                | "hell"
                | "hs"
                | "cabal"
                | "lock"
                | "tsv"
                | "csv"
        )
    ) || std::str::from_utf8(bytes)
        .is_ok_and(|text| text.starts_with("#!") || text.lines().all(|line| !line.contains('\0')))
}

fn check_dormant_collection_activation(root: &Path, failures: &mut Vec<String>) {
    let manifest = root.join("compat/collection-activation.toml");
    let provenance = root.join("compat/collection-activation-provenance.json");
    let claims = root.join("compat/collection-activation-claims.json");
    let result = (|| {
        let manifest_bytes = fs::read(&manifest)
            .map_err(|error| format!("cannot read {}: {error}", manifest.display()))?;
        let provenance_bytes = fs::read(&provenance)
            .map_err(|error| format!("cannot read {}: {error}", provenance.display()))?;
        let claims_bytes = fs::read(&claims)
            .map_err(|error| format!("cannot read {}: {error}", claims.display()))?;
        let active = hell_testkit::verify_collection_activation_state(
            &manifest_bytes,
            &provenance_bytes,
            &claims_bytes,
        )?;
        if active {
            return Err(
                "collection activation is active but its retired authority implementation is unavailable"
                    .to_owned(),
            );
        }
        Ok(())
    })();
    if let Err(error) = result {
        failures.push(error);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dormant_activation_is_bound_and_fail_closed() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut failures = Vec::new();
        check_dormant_collection_activation(&root, &mut failures);
        assert!(failures.is_empty(), "{failures:?}");
    }

    #[test]
    fn shell_extensions_and_missing_newline_are_rejected() {
        assert!(matches!(
            Path::new("tool.sh").extension().and_then(|v| v.to_str()),
            Some("sh")
        ));
        assert!(textual(Path::new("source.rs"), b"fn main() {}"));
    }
}
