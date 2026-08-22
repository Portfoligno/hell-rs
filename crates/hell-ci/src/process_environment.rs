use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

pub struct ExecutableSearchPath {
    directories: Vec<PathBuf>,
    #[cfg(windows)]
    extensions: Vec<OsString>,
}

pub struct ChildEnvironment {
    entries: BTreeMap<OsString, OsString>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum StandardVariable {
    Cargo,
    CargoTargetDir,
    GithubOutput,
    GithubWorkspace,
    ImageOs,
    ImageVersion,
    Path,
    PathExt,
    RunnerArchitecture,
    RunnerOs,
    RunnerTemp,
    SystemRoot,
    TmpDir,
}

pub struct ProcessEnvironment {
    release_child_entries: BTreeMap<OsString, OsString>,
    values: BTreeMap<StandardVariable, OsString>,
}

impl ExecutableSearchPath {
    /// Captures and validates the native executable search path.
    ///
    /// # Errors
    ///
    /// Returns an error when `PATH` is unavailable or contains a non-absolute
    /// search directory.
    pub fn from_process() -> Result<Self, String> {
        let path = std::env::var_os("PATH")
            .ok_or_else(|| "standard PATH is required for native tool resolution".to_owned())?;
        let directories = std::env::split_paths(&path).collect::<Vec<_>>();
        if directories.is_empty() || directories.iter().any(|entry| !entry.is_absolute()) {
            return Err("PATH must contain only absolute native search directories".to_owned());
        }
        #[cfg(windows)]
        let extensions = std::env::var_os("PATHEXT")
            .ok_or_else(|| "standard PATHEXT is required on Windows".to_owned())?
            .to_string_lossy()
            .split(';')
            .filter(|value| !value.is_empty())
            .map(OsString::from)
            .collect::<Vec<_>>();
        Ok(Self {
            directories,
            #[cfg(windows)]
            extensions,
        })
    }

    /// Resolves one executable name to a canonical regular file.
    ///
    /// # Errors
    ///
    /// Returns an error when the name is not one argv component, no matching
    /// executable is available, or a candidate does not resolve safely.
    pub fn resolve(&self, executable: &OsStr) -> Result<PathBuf, String> {
        let executable_path = Path::new(executable);
        if executable_path.components().count() != 1 || executable.is_empty() {
            return Err("native tool executable must be one argv name".to_owned());
        }
        let mut matches = Vec::new();
        for directory in &self.directories {
            #[cfg(windows)]
            let candidates = windows_candidates(directory, executable, &self.extensions);
            #[cfg(not(windows))]
            let candidates = [directory.join(executable)];
            for candidate in candidates {
                let Ok(metadata) = std::fs::symlink_metadata(&candidate) else {
                    continue;
                };
                if metadata.is_file() || metadata.file_type().is_symlink() {
                    let canonical = std::fs::canonicalize(&candidate).map_err(|error| {
                        format!("cannot canonicalize native executable: {error}")
                    })?;
                    let canonical_metadata =
                        std::fs::symlink_metadata(&canonical).map_err(|error| {
                            format!("cannot inspect canonical native executable: {error}")
                        })?;
                    if !canonical_metadata.is_file() || canonical_metadata.file_type().is_symlink()
                    {
                        return Err(
                            "native executable does not resolve to a regular file".to_owned()
                        );
                    }
                    matches.push(canonical);
                    break;
                }
            }
            if !matches.is_empty() {
                break;
            }
        }
        matches.into_iter().next().ok_or_else(|| {
            format!(
                "native executable {} is unavailable",
                executable.to_string_lossy()
            )
        })
    }
}

impl ChildEnvironment {
    /// Constructs an exact child-process environment.
    ///
    /// # Errors
    ///
    /// Returns an error when an environment-variable name is empty or contains
    /// a character forbidden by native process APIs.
    pub fn new(entries: BTreeMap<OsString, OsString>) -> Result<Self, String> {
        for name in entries.keys() {
            if name.is_empty()
                || name
                    .to_string_lossy()
                    .bytes()
                    .any(|byte| matches!(byte, b'=' | 0 | b'\r' | b'\n'))
            {
                return Err("child environment contains an invalid name".to_owned());
            }
        }
        Ok(Self { entries })
    }

    pub fn apply(&self, command: &mut std::process::Command) {
        command.env_clear();
        command.envs(&self.entries);
    }
}

impl ProcessEnvironment {
    #[must_use]
    pub fn from_process() -> Self {
        let variables = [
            (StandardVariable::Cargo, "CARGO"),
            (StandardVariable::CargoTargetDir, "CARGO_TARGET_DIR"),
            (StandardVariable::GithubOutput, "GITHUB_OUTPUT"),
            (StandardVariable::GithubWorkspace, "GITHUB_WORKSPACE"),
            (StandardVariable::ImageOs, "ImageOS"),
            (StandardVariable::ImageVersion, "ImageVersion"),
            (StandardVariable::Path, "PATH"),
            (StandardVariable::PathExt, "PATHEXT"),
            (StandardVariable::RunnerArchitecture, "RUNNER_ARCH"),
            (StandardVariable::RunnerOs, "RUNNER_OS"),
            (StandardVariable::RunnerTemp, "RUNNER_TEMP"),
            (StandardVariable::SystemRoot, "SystemRoot"),
            (StandardVariable::TmpDir, "TMPDIR"),
        ];
        let values = variables
            .into_iter()
            .filter_map(|(id, name)| std::env::var_os(name).map(|value| (id, value)))
            .collect();
        let release_child_entries = hell_testkit::RELEASE_CHILD_ENVIRONMENT_ALLOWLIST
            .iter()
            .filter_map(|name| std::env::var_os(name).map(|value| (OsString::from(name), value)))
            .collect();
        Self {
            release_child_entries,
            values,
        }
    }

    #[must_use]
    pub fn value(&self, variable: StandardVariable) -> Option<&OsStr> {
        self.values.get(&variable).map(OsString::as_os_str)
    }

    #[must_use]
    pub fn release_child_entries(&self) -> Vec<(OsString, OsString)> {
        self.release_child_entries
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect()
    }
}

#[cfg(windows)]
fn windows_candidates(
    directory: &Path,
    executable: &OsStr,
    extensions: &[OsString],
) -> Vec<PathBuf> {
    let path = Path::new(executable);
    if path.extension().is_some() {
        return vec![directory.join(path)];
    }
    extensions
        .iter()
        .map(|extension| {
            let mut name = executable.to_os_string();
            name.push(extension);
            directory.join(name)
        })
        .collect()
}
