//! Safe operating-system services shared by the runtime and test harness.

use std::ffi::{OsStr, OsString};
use std::path::PathBuf;
use std::sync::Arc;

mod process_tree;

pub use process_tree::{SupervisedChild, TerminationReport, WaitOutcome};

/// A captured native environment used for platform path discovery.
#[derive(Clone, Debug)]
pub struct HostServices {
    environment: Arc<[(OsString, OsString)]>,
}

impl HostServices {
    /// Captures the current process environment without Unicode conversion.
    #[must_use]
    pub fn process() -> Self {
        Self::from_environment(std::env::vars_os().collect())
    }

    /// Creates services from an explicit native environment snapshot.
    #[must_use]
    pub fn from_environment(environment: Vec<(OsString, OsString)>) -> Self {
        Self {
            environment: environment.into(),
        }
    }

    /// Resolves the platform home directory from the captured environment.
    #[must_use]
    pub fn home_directory(&self) -> Option<PathBuf> {
        #[cfg(windows)]
        {
            if let Some(profile) = self.variable(OsStr::new("USERPROFILE")) {
                return Some(PathBuf::from(profile));
            }
            let drive = self.variable(OsStr::new("HOMEDRIVE"))?;
            let path = self.variable(OsStr::new("HOMEPATH"))?;
            let mut home = OsString::from(drive);
            home.push(path);
            Some(PathBuf::from(home))
        }
        #[cfg(not(windows))]
        {
            self.variable(OsStr::new("HOME")).map(PathBuf::from)
        }
    }

    fn variable(&self, name: &OsStr) -> Option<&OsStr> {
        self.environment
            .iter()
            .find(|(candidate, _)| candidate == name)
            .map(|(_, value)| value.as_os_str())
    }
}

#[cfg(test)]
mod tests {
    use super::HostServices;
    use std::ffi::OsString;
    use std::path::PathBuf;

    #[test]
    fn explicit_environment_drives_platform_home_resolution() {
        #[cfg(not(windows))]
        let environment = vec![(OsString::from("HOME"), OsString::from("/host/home"))];
        #[cfg(windows)]
        let environment = vec![(
            OsString::from("USERPROFILE"),
            OsString::from(r"C:\Users\hell"),
        )];
        let services = HostServices::from_environment(environment);
        #[cfg(not(windows))]
        assert_eq!(services.home_directory(), Some(PathBuf::from("/host/home")));
        #[cfg(windows)]
        assert_eq!(
            services.home_directory(),
            Some(PathBuf::from(r"C:\Users\hell"))
        );
    }
}
