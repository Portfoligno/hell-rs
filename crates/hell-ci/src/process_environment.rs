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
    CargoHome,
    CargoTargetDir,
    GithubOutput,
    GithubWorkspace,
    Home,
    ImageOs,
    ImageVersion,
    Path,
    PathExt,
    ProgramData,
    ProgramFiles,
    RunnerArchitecture,
    RunnerOs,
    RunnerTemp,
    Rustc,
    RustupHome,
    RustupToolchain,
    StackRoot,
    SystemRoot,
    TmpDir,
}

pub struct ProcessEnvironment {
    release_child_entries: BTreeMap<OsString, OsString>,
    values: BTreeMap<StandardVariable, Vec<OsString>>,
}

const STANDARD_VARIABLES: &[(StandardVariable, &str)] = &[
    (StandardVariable::Home, "HOME"),
    (StandardVariable::Cargo, "CARGO"),
    (StandardVariable::CargoHome, "CARGO_HOME"),
    (StandardVariable::CargoTargetDir, "CARGO_TARGET_DIR"),
    (StandardVariable::GithubOutput, "GITHUB_OUTPUT"),
    (StandardVariable::GithubWorkspace, "GITHUB_WORKSPACE"),
    (StandardVariable::ImageOs, "ImageOS"),
    (StandardVariable::ImageVersion, "ImageVersion"),
    (StandardVariable::Path, "PATH"),
    (StandardVariable::PathExt, "PATHEXT"),
    (StandardVariable::ProgramData, "ProgramData"),
    (StandardVariable::ProgramFiles, "ProgramFiles"),
    (StandardVariable::RunnerArchitecture, "RUNNER_ARCH"),
    (StandardVariable::RunnerOs, "RUNNER_OS"),
    (StandardVariable::RunnerTemp, "RUNNER_TEMP"),
    (StandardVariable::Rustc, "RUSTC"),
    (StandardVariable::RustupHome, "RUSTUP_HOME"),
    (StandardVariable::RustupToolchain, "RUSTUP_TOOLCHAIN"),
    (StandardVariable::StackRoot, "STACK_ROOT"),
    (StandardVariable::SystemRoot, "SystemRoot"),
    (StandardVariable::TmpDir, "TMPDIR"),
];

impl ExecutableSearchPath {
    /// Captures and validates the native executable search path.
    ///
    /// # Errors
    ///
    /// Returns an error when `PATH` is unavailable or contains a non-absolute
    /// search directory.
    pub fn from_process() -> Result<Self, String> {
        Self::from_environment(&ProcessEnvironment::from_process())
    }

    /// Constructs a native executable search authority from one retained
    /// process-environment snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error when `PATH` or Windows `PATHEXT` is absent, empty,
    /// duplicated by case, or contains an invalid search component.
    pub fn from_environment(environment: &ProcessEnvironment) -> Result<Self, String> {
        let path = environment.required_singleton_value(StandardVariable::Path, "PATH")?;
        let directories = std::env::split_paths(&path).collect::<Vec<_>>();
        if directories.is_empty() || directories.iter().any(|entry| !entry.is_absolute()) {
            return Err("PATH must contain only absolute native search directories".to_owned());
        }
        #[cfg(windows)]
        let extensions = environment
            .required_singleton_value(StandardVariable::PathExt, "PATHEXT")?
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
        Self::from_entries(std::env::vars_os())
    }

    /// Constructs a typed snapshot from one retained native environment entry
    /// inventory.
    #[must_use]
    pub fn from_entries(entries: impl IntoIterator<Item = (OsString, OsString)>) -> Self {
        let mut values = BTreeMap::<StandardVariable, Vec<OsString>>::new();
        let mut release_child_entries = BTreeMap::new();
        for (name, value) in entries {
            for &(variable, expected_name) in STANDARD_VARIABLES {
                if standard_variable_name_matches(variable, &name, OsStr::new(expected_name)) {
                    values.entry(variable).or_default().push(value.clone());
                }
            }
            if hell_testkit::RELEASE_CHILD_ENVIRONMENT_ALLOWLIST
                .iter()
                .any(|allowed| release_child_name_matches(&name, OsStr::new(allowed)))
            {
                release_child_entries.insert(name, value);
            }
        }
        Self {
            release_child_entries,
            values,
        }
    }

    #[must_use]
    pub fn value(&self, variable: StandardVariable) -> Option<&OsStr> {
        let [value] = self.values.get(&variable)?.as_slice() else {
            return None;
        };
        Some(value)
    }

    /// Returns the exact singleton value captured for a standard variable.
    ///
    /// # Errors
    ///
    /// Returns an error when the retained snapshot contains more than one
    /// spelling of the variable name.
    pub fn singleton_value(&self, variable: StandardVariable) -> Result<Option<&OsStr>, String> {
        let Some(values) = self.values.get(&variable) else {
            return Ok(None);
        };
        let [value] = values.as_slice() else {
            return Err(format!(
                "standard process environment variable {variable:?} is duplicated by case"
            ));
        };
        Ok(Some(value))
    }

    /// Returns one nonempty value captured for a required standard variable.
    ///
    /// # Errors
    ///
    /// Returns an error when the value is absent, empty, or duplicated by
    /// case in the retained snapshot.
    pub fn required_singleton_value(
        &self,
        variable: StandardVariable,
        name: &str,
    ) -> Result<&OsStr, String> {
        let value = self
            .singleton_value(variable)?
            .ok_or_else(|| format!("standard process environment variable {name} is missing"))?;
        if value.is_empty() {
            return Err(format!(
                "standard process environment variable {name} is empty"
            ));
        }
        Ok(value)
    }

    #[must_use]
    pub fn release_child_entries(&self) -> Vec<(OsString, OsString)> {
        self.release_child_entries
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect()
    }
}

fn standard_variable_name_matches(
    variable: StandardVariable,
    observed: &OsStr,
    expected: &OsStr,
) -> bool {
    variable == StandardVariable::StackRoot && observed.eq_ignore_ascii_case(expected)
        || variable != StandardVariable::StackRoot && release_child_name_matches(observed, expected)
}

fn release_child_name_matches(observed: &OsStr, expected: &OsStr) -> bool {
    #[cfg(windows)]
    {
        observed.eq_ignore_ascii_case(expected)
    }
    #[cfg(not(windows))]
    {
        observed == expected
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
