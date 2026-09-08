//! Scoped authorization for a non-root Linux `MemCordon` public frontend.

use std::ffi::OsString;
use std::io;
use std::path::Path;

/// Encodes native credentials without changing the supervised target argv.
///
/// # Errors
///
/// Returns an error for a root uid/gid or a non-absolute executable path.
pub fn linux_frontend_arguments(
    uid: u32,
    provider_gid: u32,
    program: &Path,
    arguments: &[OsString],
) -> io::Result<Vec<OsString>> {
    if uid == 0 || provider_gid == 0 || !program.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "provider frontend requires non-root uid/gid and an absolute executable",
        ));
    }
    let mut result = vec![
        OsString::from("--non-interactive"),
        OsString::from("--"),
        OsString::from("/usr/bin/setpriv"),
        OsString::from("--reuid"),
        OsString::from(uid.to_string()),
        OsString::from("--regid"),
        OsString::from(provider_gid.to_string()),
        // Restore this user's account groups, including the existing sudo policy;
        // the provider group is scoped to this frontend's primary gid.
        OsString::from("--init-groups"),
        OsString::from("--inh-caps=-all"),
        OsString::from("--ambient-caps=-all"),
        // The separately authorized candidate sudo transition must remain possible.
        // The trusted frontend does not receive no-new-privs here.
        OsString::from("--"),
        program.as_os_str().to_owned(),
    ];
    result.extend_from_slice(arguments);
    Ok(result)
}

#[cfg(target_os = "linux")]
/// Binds trusted credential helpers and the installed provider access group.
///
/// # Errors
///
/// Returns an error if credentials differ, group lookup fails, or helper and
/// frontend executable metadata does not satisfy the trusted identity checks.
pub fn authorized_linux_frontend(
    program: &Path,
    arguments: &[OsString],
) -> io::Result<(std::path::PathBuf, Vec<OsString>)> {
    use nix::unistd::{Group, geteuid, getuid};
    use std::os::unix::fs::MetadataExt;
    let uid = getuid().as_raw();
    if uid != geteuid().as_raw() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "provider frontend uid differs from effective uid",
        ));
    }
    let group = Group::from_name("memcordon")
        .map_err(io::Error::other)?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "installed provider access group is missing",
            )
        })?;
    for helper in [Path::new("/usr/bin/sudo"), Path::new("/usr/bin/setpriv")] {
        let metadata = std::fs::symlink_metadata(helper)?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
            || metadata.mode() & 0o111 == 0
            || std::fs::canonicalize(helper)? != helper
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "provider credential helper is not a canonical root-owned executable",
            ));
        }
    }
    let metadata = std::fs::symlink_metadata(program)?;
    if !metadata.is_file()
        || (metadata.uid() != uid && metadata.uid() != 0)
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o111 == 0
        || std::fs::canonicalize(program)? != program
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "provider frontend executable is not canonical and trusted",
        ));
    }
    Ok((
        Path::new("/usr/bin/sudo").to_owned(),
        linux_frontend_arguments(uid, group.gid.as_raw(), program, arguments)?,
    ))
}
