//! Safe operating-system services shared by the runtime and test harness.

#[cfg(not(windows))]
use std::ffi::OsStr;
use std::ffi::OsString;
use std::path::PathBuf;
#[cfg(not(windows))]
use std::sync::Arc;

mod process_tree;

#[cfg(unix)]
#[doc(hidden)]
pub use process_tree::verify_termination_deadline_for_integration;
pub use process_tree::{
    CleanupLease, CleanupLifecycleReceipt, RetainedTerminationReceipt, RetainedTerminationSnapshot,
    RetainedTerminationState, SupervisedChild, TerminationReport, WaitOutcome,
    retained_termination_receipt,
};

/// A captured native environment used for platform path discovery.
#[derive(Clone, Debug)]
pub struct HostServices {
    #[cfg(not(windows))]
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
        #[cfg(windows)]
        let _ = environment;
        Self {
            #[cfg(not(windows))]
            environment: environment.into(),
        }
    }

    /// Resolves the platform home directory from the captured environment.
    #[must_use]
    pub fn home_directory(&self) -> Option<PathBuf> {
        #[cfg(not(windows))]
        {
            if let Some(home) = self.variable(OsStr::new("HOME")) {
                return Some(PathBuf::from(home));
            }
        }
        platform_home_directory()
    }

    #[cfg(not(windows))]
    fn variable(&self, name: &OsStr) -> Option<&OsStr> {
        self.environment
            .iter()
            .find(|(candidate, _)| candidate == name)
            .map(|(_, value)| value.as_os_str())
    }
}

#[cfg(unix)]
fn platform_home_directory() -> Option<PathBuf> {
    nix::unistd::User::from_uid(nix::unistd::Uid::effective())
        .ok()
        .flatten()
        .map(|user| user.dir)
}

#[cfg(windows)]
fn platform_home_directory() -> Option<PathBuf> {
    known_folders::get_known_folder_path(known_folders::KnownFolder::Profile)
}

#[cfg(test)]
mod tests {
    use super::HostServices;
    use std::ffi::OsString;
    #[cfg(unix)]
    use std::path::PathBuf;

    #[cfg(unix)]
    #[test]
    fn explicit_environment_drives_platform_home_resolution() {
        let environment = vec![(OsString::from("HOME"), OsString::from("/host/home"))];
        let services = HostServices::from_environment(environment);
        assert_eq!(
            services.home_directory(),
            Some(
                PathBuf::from(std::path::MAIN_SEPARATOR_STR)
                    .join("host")
                    .join("home")
            )
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_home_resolution_preserves_empty_home_and_falls_back_to_effective_user() {
        let explicit_empty =
            HostServices::from_environment(vec![(OsString::from("HOME"), OsString::new())]);
        assert_eq!(explicit_empty.home_directory(), Some(PathBuf::new()));

        let expected = nix::unistd::User::from_uid(nix::unistd::Uid::effective())
            .expect("effective-user lookup succeeds")
            .expect("effective user has a passwd entry")
            .dir;
        assert_eq!(
            HostServices::from_environment(Vec::new()).home_directory(),
            Some(expected)
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_home_resolution_uses_the_profile_known_folder_not_environment_overrides() {
        let expected = known_folders::get_known_folder_path(known_folders::KnownFolder::Profile)
            .expect("Windows Known Folders API resolves the current user profile");
        let captured = HostServices::from_environment(vec![(
            OsString::from("userprofile"),
            OsString::from(r"C:\Captured"),
        )]);
        assert_eq!(captured.home_directory(), Some(expected.clone()));
        let empty =
            HostServices::from_environment(vec![(OsString::from("UserProfile"), OsString::new())]);
        assert_eq!(empty.home_directory(), Some(expected.clone()));
        assert_eq!(
            HostServices::from_environment(Vec::new()).home_directory(),
            Some(expected)
        );
    }
}
