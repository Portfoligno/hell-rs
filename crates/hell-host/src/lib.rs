//! Safe operating-system services shared by the runtime and test harness.

#[cfg(not(windows))]
use std::ffi::OsStr;
use std::ffi::OsString;
use std::path::PathBuf;
#[cfg(not(windows))]
use std::sync::Arc;

mod process_environment;
mod process_tree;

use process_environment::ProcessEnvironment;

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
        Self::from_environment(ProcessEnvironment::from_process().into_entries())
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
