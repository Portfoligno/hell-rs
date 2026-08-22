use std::ffi::OsString;
#[cfg(unix)]
use std::path::PathBuf;

use hell_host::HostServices;

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
