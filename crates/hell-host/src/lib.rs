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
            if let (Some(drive), Some(path)) = (
                self.variable(OsStr::new("HOMEDRIVE")),
                self.variable(OsStr::new("HOMEPATH")),
            ) {
                let mut home = OsString::from(drive);
                home.push(path);
                return Some(PathBuf::from(home));
            }
        }
        #[cfg(not(windows))]
        {
            if let Some(home) = self.variable(OsStr::new("HOME")) {
                return Some(PathBuf::from(home));
            }
        }
        platform_home_directory()
    }

    fn variable(&self, name: &OsStr) -> Option<&OsStr> {
        self.environment
            .iter()
            .find(|(candidate, _)| {
                #[cfg(windows)]
                {
                    windows_environment_name_eq(candidate, name)
                }
                #[cfg(not(windows))]
                {
                    candidate == name
                }
            })
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
    use std::os::windows::ffi::OsStringExt as _;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::TOKEN_QUERY;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows_sys::Win32::UI::Shell::GetUserProfileDirectoryW;

    unsafe {
        let mut token = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return None;
        }
        let result = (|| {
            let mut length = 0_u32;
            let _required = GetUserProfileDirectoryW(token, std::ptr::null_mut(), &mut length);
            let capacity = usize::try_from(length).ok()?;
            if capacity == 0 {
                return None;
            }
            let mut buffer = vec![0_u16; capacity];
            if GetUserProfileDirectoryW(token, buffer.as_mut_ptr(), &mut length) == 0 {
                return None;
            }
            let populated = usize::try_from(length).ok()?;
            let path_length = populated.checked_sub(1)?;
            buffer.truncate(path_length);
            Some(PathBuf::from(OsString::from_wide(&buffer)))
        })();
        CloseHandle(token);
        result
    }
}

#[cfg(windows)]
fn windows_environment_name_eq(left: &OsStr, right: &OsStr) -> bool {
    use std::os::windows::ffi::OsStrExt as _;

    let left = left.encode_wide().collect::<Vec<_>>();
    let right = right.encode_wide().collect::<Vec<_>>();
    ascii_case_insensitive_utf16_eq(&left, &right)
}

#[cfg(any(test, windows))]
fn ascii_case_insensitive_utf16_eq(left: &[u16], right: &[u16]) -> bool {
    fn fold_ascii(value: u16) -> u16 {
        if (u16::from(b'A')..=u16::from(b'Z')).contains(&value) {
            value + u16::from(b'a' - b'A')
        } else {
            value
        }
    }

    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(&left, &right)| fold_ascii(left) == fold_ascii(right))
}

#[cfg(test)]
mod tests {
    use super::{HostServices, ascii_case_insensitive_utf16_eq};
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
        assert_eq!(
            services.home_directory(),
            Some(
                PathBuf::from(std::path::MAIN_SEPARATOR_STR)
                    .join("host")
                    .join("home")
            )
        );
        #[cfg(windows)]
        assert_eq!(
            services.home_directory(),
            Some(PathBuf::from(r"C:\Users\hell"))
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

    #[test]
    fn windows_environment_name_comparison_is_ascii_case_insensitive_and_exact() {
        let encoded = |value: &str| value.encode_utf16().collect::<Vec<_>>();
        assert!(ascii_case_insensitive_utf16_eq(
            &encoded("UserProfile"),
            &encoded("USERPROFILE")
        ));
        assert!(ascii_case_insensitive_utf16_eq(
            &encoded("homeDrive"),
            &encoded("HOMEDRIVE")
        ));
        assert!(!ascii_case_insensitive_utf16_eq(
            &encoded("USERPROFILE_EXTRA"),
            &encoded("USERPROFILE")
        ));
    }

    #[cfg(windows)]
    #[test]
    fn windows_home_resolution_preserves_captured_case_and_empty_precedence() {
        let captured = HostServices::from_environment(vec![(
            OsString::from("userprofile"),
            OsString::from(r"C:\Captured"),
        )]);
        assert_eq!(
            captured.home_directory(),
            Some(PathBuf::from(r"C:\Captured"))
        );
        let empty =
            HostServices::from_environment(vec![(OsString::from("UserProfile"), OsString::new())]);
        assert_eq!(empty.home_directory(), Some(PathBuf::new()));
        assert!(
            HostServices::from_environment(Vec::new())
                .home_directory()
                .is_some()
        );
    }
}
