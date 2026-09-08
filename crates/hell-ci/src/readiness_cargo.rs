//! Read-only dependency sources with a separately writable candidate Cargo home.
use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use crate::release::cargo_dependencies::{
    FrozenDependencyInputs, dependency_directory_config, validate_dependency_vendor,
};
use crate::release::platform::TrustedCargoSeedInputFile;

#[doc(hidden)]
pub struct ReadinessCargoCommandProjection {
    pub name: String,
    pub arguments: Vec<std::ffi::OsString>,
    pub environment: Vec<(std::ffi::OsString, std::ffi::OsString)>,
}

pub struct ReadinessCargoSource {
    source: PathBuf,
    home: PathBuf,
    vendor: PathBuf,
    owner: u32,
    group: u32,
    home_identity: (u64, u64),
    inputs: FrozenDependencyInputs,
    config: [TrustedCargoSeedInputFile; 2],
    vendor_files: Vec<(PathBuf, TrustedCargoSeedInputFile)>,
}

impl ReadinessCargoSource {
    pub fn stage(
        source: &Path,
        home: &Path,
        vendor: &Path,
        owner: u32,
        group: u32,
    ) -> Result<Self, String> {
        require_home(home, owner, group)?;
        if fs::read_dir(home)
            .map_err(|error| error.to_string())?
            .next()
            .is_some()
        {
            return Err("readiness Cargo home is not fresh".to_owned());
        }
        require_no_source_override(source)?;
        let inputs = FrozenDependencyInputs::bind(&[source.to_path_buf()])?;
        validate_dependency_vendor(
            &[fs::read(source.join("Cargo.lock")).map_err(|error| error.to_string())?],
            vendor,
        )?;
        let bytes = dependency_directory_config(vendor)?;
        for name in ["config", "config.toml"] {
            let file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o444)
                .custom_flags(nix::libc::O_NOFOLLOW)
                .open(home.join(name))
                .map_err(|error| error.to_string())?;
            (&file)
                .write_all(&bytes)
                .map_err(|error| error.to_string())?;
            file.set_permissions(fs::Permissions::from_mode(0o444))
                .map_err(|error| error.to_string())?;
        }
        let metadata = fs::symlink_metadata(home).map_err(|error| error.to_string())?;
        let result = Self {
            source: source.to_path_buf(),
            home: home.to_path_buf(),
            vendor: vendor.to_path_buf(),
            owner,
            group,
            home_identity: (metadata.dev(), metadata.ino()),
            inputs,
            vendor_files: vendor_files(vendor, owner)?,
            config: [
                TrustedCargoSeedInputFile::bind(home, "config")?,
                TrustedCargoSeedInputFile::bind(home, "config.toml")?,
            ],
        };
        result.validate()?;
        Ok(result)
    }

    pub fn config_path(&self) -> PathBuf {
        self.home.join("config.toml")
    }

    #[doc(hidden)]
    pub fn command_projection(&self) -> Result<Vec<ReadinessCargoCommandProjection>, String> {
        self.validate()?;
        Ok(crate::command::readiness_cargo_projection(
            &self.source,
            &self.home,
            &self.config_path(),
        ))
    }

    pub fn validate(&self) -> Result<(), String> {
        require_home(&self.home, self.owner, self.group)?;
        let metadata = fs::symlink_metadata(&self.home).map_err(|error| error.to_string())?;
        if (metadata.dev(), metadata.ino()) != self.home_identity {
            return Err("readiness Cargo home identity changed".to_owned());
        }
        self.inputs.revalidate()?;
        require_no_source_override(&self.source)?;
        for (name, expected) in ["config", "config.toml"].into_iter().zip(&self.config) {
            let metadata =
                fs::symlink_metadata(self.home.join(name)).map_err(|error| error.to_string())?;
            if metadata.uid() != self.owner
                || metadata.gid() != self.group
                || metadata.mode() & 0o7777 != 0o444
                || TrustedCargoSeedInputFile::bind(&self.home, name)? != *expected
            {
                return Err("readiness Cargo source configuration authority changed".to_owned());
            }
        }
        validate_dependency_vendor(
            &[fs::read(self.source.join("Cargo.lock")).map_err(|error| error.to_string())?],
            &self.vendor,
        )?;
        if vendor_files(&self.vendor, self.owner)? != self.vendor_files {
            return Err("readiness Cargo vendor authority changed".to_owned());
        }
        Ok(())
    }
}

fn require_home(home: &Path, owner: u32, group: u32) -> Result<(), String> {
    let metadata = fs::symlink_metadata(home).map_err(|error| error.to_string())?;
    if !metadata.is_dir()
        || fs::canonicalize(home).ok().as_deref() != Some(home)
        || metadata.uid() != owner
        || metadata.gid() != group
        || metadata.mode() & 0o7777 != 0o3770
    {
        return Err("readiness Cargo home lacks owner-controlled sticky authority".to_owned());
    }
    Ok(())
}

fn require_no_source_override(source: &Path) -> Result<(), String> {
    let mut pending = vec![source.to_path_buf()];
    let mut visited = 0_usize;
    while let Some(directory) = pending.pop() {
        visited += 1;
        if visited > 200_000 {
            return Err("readiness source directory bound exceeded".to_owned());
        }
        for entry in fs::read_dir(&directory).map_err(|error| error.to_string())? {
            let entry = entry.map_err(|error| error.to_string())?;
            if entry.file_name() == ".git" {
                continue;
            }
            if entry
                .file_type()
                .map_err(|error| error.to_string())?
                .is_dir()
            {
                if entry.file_name() == ".cargo" {
                    for name in ["config", "config.toml"] {
                        match fs::symlink_metadata(entry.path().join(name)) {
                            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
                            Err(error) => return Err(error.to_string()),
                            Ok(_) => return Err("nested readiness source contains an overriding Cargo configuration".to_owned()),
                        }
                    }
                }
                pending.push(entry.path());
            }
        }
    }
    for parent in source.ancestors() {
        for name in ["config", "config.toml"] {
            match fs::symlink_metadata(parent.join(".cargo").join(name)) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(format!("cannot inspect readiness Cargo override: {error}"));
                }
                Ok(_) => {
                    return Err(
                        "readiness source ancestry contains an overriding Cargo configuration"
                            .to_owned(),
                    );
                }
            }
        }
    }
    Ok(())
}

fn vendor_files(
    root: &Path,
    owner: u32,
) -> Result<Vec<(PathBuf, TrustedCargoSeedInputFile)>, String> {
    crate::release::platform::validate_trusted_cargo_cache_tree(root)?;
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
        if metadata.uid() != owner
            || metadata.mode() & 0o7777 != if metadata.is_dir() { 0o555 } else { 0o444 }
        {
            return Err("readiness vendor is not trusted-owned immutable data".to_owned());
        }
        if metadata.is_dir() {
            for entry in fs::read_dir(path).map_err(|error| error.to_string())? {
                pending.push(entry.map_err(|error| error.to_string())?.path());
            }
        } else {
            let parent = path.parent().ok_or("vendor file has no parent")?;
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or("vendor file name is not Unicode")?;
            let binding = TrustedCargoSeedInputFile::bind(parent, name)?;
            files.push((path, binding));
        }
    }
    files.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(files)
}
