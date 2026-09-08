//! Explicit Cargo authority transferred by the authenticated Nightly request.
//! This does not extend the generic child-environment inheritance allowlist.

use std::ffi::OsString;
use std::fs;
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::command::{CommandSpec, resolve_cargo_from};
use crate::process_environment::{ProcessEnvironment, StandardVariable};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PathBinding {
    path: Vec<u8>,
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    file: Option<(u64, String)>,
}

impl PathBinding {
    fn bind(path: &Path, directory: bool) -> Result<Self, String> {
        if !path.is_absolute() || fs::canonicalize(path).map_err(|e| e.to_string())? != path {
            return Err("Nightly Cargo authority path is not canonical absolute".to_owned());
        }
        let handle = fs::OpenOptions::new()
            .read(true)
            .custom_flags(
                nix::libc::O_NOFOLLOW | if directory { nix::libc::O_DIRECTORY } else { 0 },
            )
            .open(path)
            .map_err(|e| format!("cannot bind Nightly Cargo authority path: {e}"))?;
        let metadata = handle.metadata().map_err(|e| e.to_string())?;
        if (directory && !metadata.is_dir()) || (!directory && !metadata.is_file()) {
            return Err("Nightly Cargo authority path has wrong kind".to_owned());
        }
        let file = if directory {
            None
        } else {
            if metadata.len() > 512 * 1024 * 1024 {
                return Err("Nightly Cargo authority file exceeds binding limit".to_owned());
            }
            let digest = hell_testkit::sha256_file(path)
                .map_err(|e| e.to_string())?
                .hex();
            let after = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
            if (
                metadata.dev(),
                metadata.ino(),
                metadata.len(),
                metadata.mtime(),
                metadata.mtime_nsec(),
                metadata.ctime(),
                metadata.ctime_nsec(),
            ) != (
                after.dev(),
                after.ino(),
                after.len(),
                after.mtime(),
                after.mtime_nsec(),
                after.ctime(),
                after.ctime_nsec(),
            ) {
                return Err("Nightly Cargo authority file changed while binding".to_owned());
            }
            Some((metadata.len(), digest))
        };
        Ok(Self {
            path: path.as_os_str().as_bytes().to_vec(),
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode: metadata.mode(),
            file,
        })
    }

    fn path(&self) -> PathBuf {
        PathBuf::from(OsString::from_vec(self.path.clone()))
    }

    fn revalidate(&self) -> Result<(), String> {
        if Self::bind(&self.path(), self.file.is_none())? != *self {
            return Err("Nightly Cargo authority path identity changed".to_owned());
        }
        Ok(())
    }
}

/// A closed set of standard Cargo/toolchain/output bindings, never ambient
/// configuration or arbitrary environment entries. The outer supervisor request
/// authenticates these bytes before reconstruction.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NightlyCargoAuthority {
    schema_version: u32,
    source: PathBinding,
    target: PathBinding,
    temporary: PathBinding,
    home: PathBinding,
    cargo_home: PathBinding,
    cargo_config: PathBinding,
    rustup_home: PathBinding,
    cargo: PathBinding,
    rustc: PathBinding,
    toolchain: Vec<u8>,
    search_path: Vec<u8>,
}

/// Inspection of the real decoded supervisor command without launching Cargo.
#[doc(hidden)]
pub struct CommandProjection {
    pub program: PathBuf,
    pub directory: PathBuf,
    pub arguments: Vec<OsString>,
    pub environment: Vec<(OsString, OsString)>,
}

#[doc(hidden)]
pub fn supervisor_roundtrip(
    source: &Path,
    authority: &NightlyCargoAuthority,
) -> Result<CommandProjection, String> {
    crate::release_suite::nightly_cargo_request_roundtrip(source, authority)
}

impl NightlyCargoAuthority {
    /// Captures the already confined Linux operation's standard environment.
    pub fn capture(source: &Path, environment: &ProcessEnvironment) -> Result<Self, String> {
        let required = |variable, name| environment.required_singleton_value(variable, name);
        let directory =
            |variable, name| PathBinding::bind(Path::new(&required(variable, name)?), true);
        let cargo_home = directory(StandardVariable::CargoHome, "CARGO_HOME")?;
        let authority = Self {
            schema_version: 1,
            source: PathBinding::bind(source, true)?,
            target: directory(StandardVariable::CargoTargetDir, "CARGO_TARGET_DIR")?,
            temporary: directory(StandardVariable::TmpDir, "TMPDIR")?,
            home: directory(StandardVariable::Home, "HOME")?,
            cargo_config: PathBinding::bind(&cargo_home.path().join("config.toml"), false)?,
            cargo_home,
            rustup_home: directory(StandardVariable::RustupHome, "RUSTUP_HOME")?,
            cargo: PathBinding::bind(
                Path::new(&required(StandardVariable::Cargo, "CARGO")?),
                false,
            )?,
            rustc: PathBinding::bind(
                Path::new(&required(StandardVariable::Rustc, "RUSTC")?),
                false,
            )?,
            toolchain: required(StandardVariable::RustupToolchain, "RUSTUP_TOOLCHAIN")?
                .as_bytes()
                .to_vec(),
            search_path: required(StandardVariable::Path, "PATH")?
                .as_bytes()
                .to_vec(),
        };
        authority.validate(source)?;
        Ok(authority)
    }

    /// Fails closed on missing, redirected, replaced, or source-contained output
    /// paths before a Cargo command can be constructed.
    pub fn validate(&self, source: &Path) -> Result<(), String> {
        if self.schema_version != 1 || self.source.path() != source || self.source.mode & 0o222 != 0
        {
            return Err("Nightly Cargo authority requires its bound immutable source".to_owned());
        }
        let target = self.target.path();
        let work = target
            .parent()
            .ok_or("Nightly Cargo target has no work parent")?;
        if work.starts_with(source) || source.starts_with(work) {
            return Err("Nightly Cargo work authority overlaps immutable source".to_owned());
        }
        let outputs = [&self.target, &self.temporary, &self.home, &self.cargo_home];
        let mut distinct = std::collections::BTreeSet::new();
        for output in outputs {
            let path = output.path();
            if path.parent() != Some(work) || !distinct.insert(path.clone()) {
                return Err("Nightly Cargo outputs must be distinct bound work siblings".to_owned());
            }
            nix::unistd::faccessat(
                None,
                &path,
                nix::unistd::AccessFlags::W_OK | nix::unistd::AccessFlags::X_OK,
                nix::fcntl::AtFlags::AT_EACCESS,
            )
            .map_err(|e| format!("Nightly Cargo output authority is not writable: {e}"))?;
        }
        if self.cargo_config.path() != self.cargo_home.path().join("config.toml")
            || self.toolchain.is_empty()
            || self.toolchain.contains(&0)
            || self.search_path.contains(&0)
            || std::env::split_paths(&OsString::from_vec(self.search_path.clone()))
                .any(|p| !p.is_absolute())
        {
            return Err("Nightly Cargo toolchain/configuration binding is invalid".to_owned());
        }
        for binding in [
            &self.source,
            &self.target,
            &self.temporary,
            &self.home,
            &self.cargo_home,
            &self.cargo_config,
            &self.rustup_home,
            &self.cargo,
            &self.rustc,
        ] {
            binding.revalidate()?;
        }
        Ok(())
    }

    pub(crate) fn command(&self, source: &Path, timeout: Duration) -> Result<CommandSpec, String> {
        self.validate(source)?;
        let cargo = self.cargo.path();
        let resolved = resolve_cargo_from(Some(cargo.as_os_str()), &[], &[], true, false)?;
        if resolved.invocation_path() != cargo || resolved.canonical_identity() != cargo {
            return Err("Nightly Cargo executable differs from authenticated binding".to_owned());
        }
        let mut command = CommandSpec::trusted_cargo(timeout, &resolved).cleared_environment();
        for (name, path) in [
            ("CARGO", self.cargo.path()),
            ("RUSTC", self.rustc.path()),
            ("CARGO_TARGET_DIR", self.target.path()),
            ("CARGO_HOME", self.cargo_home.path()),
            ("HOME", self.home.path()),
            ("RUSTUP_HOME", self.rustup_home.path()),
            ("TMPDIR", self.temporary.path()),
            ("TMP", self.temporary.path()),
            ("TEMP", self.temporary.path()),
        ] {
            command = command.environment(name, path);
        }
        Ok(command
            .environment(
                "RUSTUP_TOOLCHAIN",
                OsString::from_vec(self.toolchain.clone()),
            )
            .environment("PATH", OsString::from_vec(self.search_path.clone()))
            .environment("CARGO_INCREMENTAL", "0"))
    }
}
