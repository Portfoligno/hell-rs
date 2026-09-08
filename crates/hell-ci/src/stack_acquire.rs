//! Authenticated host-only Stack inventory executable. Never candidate PATH.
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{
    DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::release::governance::{
    TomlDocument, boolean, integer, member, quoted, require_keys, string_array,
};

static NEXT: AtomicU64 = AtomicU64::new(0);
const LOCK: &str = include_str!("../../../ci/external-inputs.toml");
const URL: &str = "https://github.com/commercialhaskell/stack/releases/download/v3.11.1/stack-3.11.1-linux-x86_64-bin";

struct Pin {
    size: u64,
    sha256: String,
    timeout: Duration,
}

fn pin(text: &str) -> Result<Pin, String> {
    let document = TomlDocument::parse(text)?;
    let entries = document
        .arrays("input")?
        .iter()
        .filter(|entry| {
            entry
                .get("id")
                .and_then(|value| quoted(value).ok())
                .as_deref()
                == Some("linux-stack-executable")
        })
        .collect::<Vec<_>>();
    if entries.len() != 1 {
        return Err("trusted Linux Stack pin must occur exactly once".to_owned());
    }
    let entry = entries[0];
    require_keys(
        entry,
        &[
            "id",
            "kind",
            "version",
            "repository",
            "source-url",
            "asset-id",
            "exact-bytes",
            "sha256",
            "maximum-compressed-bytes",
            "maximum-expanded-bytes",
            "media-type",
            "timeout-seconds",
            "expected-filename",
            "platforms",
            "acquisition-phase",
            "cache-permitted",
        ],
    )?;
    for (key, expected) in [
        ("kind", "https-file"),
        ("version", "3.11.1"),
        ("repository", "commercialhaskell/stack"),
        ("source-url", URL),
        ("expected-filename", "stack-3.11.1-linux-x86_64-bin"),
        ("media-type", "application/octet-stream"),
        ("acquisition-phase", "native-platform"),
    ] {
        if quoted(member(entry, key)?)? != expected {
            return Err(format!("trusted Linux Stack pin differs at {key}"));
        }
    }
    let size = integer(member(entry, "exact-bytes")?)?;
    if size != 94_141_872
        || integer(member(entry, "asset-id")?)? != 446_721_552
        || integer(member(entry, "maximum-compressed-bytes")?)? != size
        || integer(member(entry, "maximum-expanded-bytes")?)? != size
        || integer(member(entry, "timeout-seconds")?)? != 300
        || string_array(member(entry, "platforms")?)? != ["linux-x86_64"]
        || boolean(member(entry, "cache-permitted")?)?
    {
        return Err("trusted Linux Stack pin scope or bounds differ".to_owned());
    }
    let sha256 = quoted(member(entry, "sha256")?)?;
    if sha256 != "67c66e918801c41ae4d286b1c91f9124f691c1c7d56071b53889cf4a5c667550" {
        return Err("trusted Linux Stack pin digest differs".to_owned());
    }
    Ok(Pin {
        size,
        sha256,
        timeout: Duration::from_secs(300),
    })
}

#[doc(hidden)]
pub fn validate_linux_stack_pin(text: &str) -> Result<(), String> {
    pin(text).map(|_| ())
}

type Identity = (u64, u64, u32, u32, u32);
fn identity(metadata: &fs::Metadata) -> Identity {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.uid(),
        metadata.gid(),
        metadata.mode(),
    )
}

pub(crate) struct ProtectedStack {
    directory: PathBuf,
    directory_handle: File,
    directory_identity: Identity,
    executable: PathBuf,
    file: File,
    file_identity: (u64, u64),
    pin: Pin,
    active: bool,
}

impl ProtectedStack {
    pub(crate) fn acquire() -> Result<Self, String> {
        if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
            return Err("pinned Stack executable is only Linux x86_64".to_owned());
        }
        let pin = pin(LOCK)?;
        let deadline = Instant::now()
            .checked_add(pin.timeout)
            .ok_or("Stack acquisition deadline overflow")?;
        let mut owned = Self::reserve(&std::env::temp_dir(), pin)?;
        let result = (|| {
            let agent = ureq::Agent::config_builder()
                .timeout_global(Some(owned.pin.timeout))
                .https_only(true)
                .build()
                .new_agent();
            let mut response = agent
                .get(URL)
                .header("Accept-Encoding", "identity")
                .header("User-Agent", "hell-ci-stack-acquire")
                .call()
                .map_err(|error| format!("cannot acquire pinned Stack: {error}"))?;
            owned.copy_verified(&mut response.body_mut().as_reader(), deadline)
        })();
        match result {
            Ok(()) => Ok(owned),
            Err(primary) => match owned.close() {
                Ok(()) => Err(primary),
                Err(cleanup) => Err(format!(
                    "{primary}; Stack acquisition cleanup failed: {cleanup}"
                )),
            },
        }
    }

    fn reserve(base: &Path, pin: Pin) -> Result<Self, String> {
        let base = fs::canonicalize(base).map_err(|error| error.to_string())?;
        let parent = fs::symlink_metadata(&base).map_err(|error| error.to_string())?;
        if !parent.is_dir()
            || (parent.uid() != 0 && parent.uid() != nix::unistd::geteuid().as_raw())
            || (parent.mode() & 0o022 != 0 && parent.mode() & 0o1000 == 0)
        {
            return Err(
                "Stack temporary parent is not protected or sticky owned authority".to_owned(),
            );
        }
        for _ in 0..16 {
            let directory = base.join(format!(
                "hell-ci-stack-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::DirBuilder::new().mode(0o700).create(&directory) {
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(format!("cannot reserve Stack directory: {error}")),
                Ok(()) => {}
            }
            let result = (|| {
                let directory_handle = fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW)
                    .open(&directory)
                    .map_err(|error| error.to_string())?;
                let metadata = directory_handle
                    .metadata()
                    .map_err(|error| error.to_string())?;
                if metadata.mode() & 0o777 != 0o700
                    || metadata.uid() != nix::unistd::geteuid().as_raw()
                    || identity(
                        &fs::symlink_metadata(&directory).map_err(|error| error.to_string())?,
                    ) != identity(&metadata)
                {
                    return Err("reserved Stack directory identity differs".to_owned());
                }
                let executable = directory.join("stack");
                let file = exclusive_destination(&executable)?;
                let file_metadata = file.metadata().map_err(|error| error.to_string())?;
                Ok((directory_handle, metadata, executable, file, file_metadata))
            })();
            match result {
                Ok((directory_handle, metadata, executable, file, file_metadata)) => {
                    return Ok(Self {
                        directory,
                        directory_handle,
                        directory_identity: identity(&metadata),
                        executable,
                        file,
                        file_identity: (file_metadata.dev(), file_metadata.ino()),
                        pin,
                        active: true,
                    });
                }
                Err(primary) => {
                    return Err(format!(
                        "{primary}; incomplete Stack reservation retained at {}",
                        directory.display()
                    ));
                }
            }
        }
        Err("Stack directory reservation collision bound reached".to_owned())
    }

    fn check_identity(&self) -> Result<(), String> {
        if fs::canonicalize(&self.directory).map_err(|error| error.to_string())? != self.directory {
            return Err("protected Stack directory was redirected".to_owned());
        }
        for metadata in [
            self.directory_handle.metadata(),
            fs::symlink_metadata(&self.directory),
        ] {
            if identity(&metadata.map_err(|error| error.to_string())?) != self.directory_identity {
                return Err("protected Stack directory identity changed".to_owned());
            }
        }
        for metadata in [self.file.metadata(), fs::symlink_metadata(&self.executable)] {
            let metadata = metadata.map_err(|error| error.to_string())?;
            if !metadata.is_file()
                || metadata.nlink() != 1
                || (metadata.dev(), metadata.ino()) != self.file_identity
                || metadata.uid() != nix::unistd::geteuid().as_raw()
            {
                return Err("protected Stack executable identity changed".to_owned());
            }
        }
        Ok(())
    }

    fn copy_verified(&mut self, reader: &mut dyn Read, deadline: Instant) -> Result<(), String> {
        self.check_identity()?;
        let mut copied = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            if Instant::now() >= deadline {
                return Err("Stack acquisition deadline elapsed".to_owned());
            }
            let read = reader
                .read(&mut buffer)
                .map_err(|error| error.to_string())?;
            if read == 0 {
                break;
            }
            copied = copied
                .checked_add(read as u64)
                .ok_or("Stack size overflow")?;
            if copied > self.pin.size {
                return Err("Stack executable exceeds exact size".to_owned());
            }
            self.file
                .write_all(&buffer[..read])
                .map_err(|error| error.to_string())?;
        }
        self.file.sync_all().map_err(|error| error.to_string())?;
        self.verify_bytes(deadline)?;
        self.file
            .set_permissions(fs::Permissions::from_mode(0o555))
            .map_err(|error| error.to_string())?;
        self.check_identity()?;
        // Linux refuses execution while any writable descriptor remains open.
        // Replace the writer only after authenticating its protected inode.
        let readonly = fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&self.executable)
            .map_err(|error| error.to_string())?;
        self.file = readonly;
        self.revalidate()
    }

    fn verify_bytes(&self, deadline: Instant) -> Result<(), String> {
        self.check_identity()?;
        let mut file = self.file.try_clone().map_err(|error| error.to_string())?;
        file.seek(SeekFrom::Start(0))
            .map_err(|error| error.to_string())?;
        let mut digest = hell_digest::Sha256::new();
        let mut size = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            if Instant::now() >= deadline {
                return Err("Stack destination verification deadline elapsed".to_owned());
            }
            let read = file.read(&mut buffer).map_err(|error| error.to_string())?;
            if read == 0 {
                break;
            }
            size = size
                .checked_add(read as u64)
                .ok_or("Stack destination size overflow")?;
            if size > self.pin.size {
                return Err("Stack destination exceeds exact size".to_owned());
            }
            digest.update(&buffer[..read]);
        }
        if size != self.pin.size || digest.finish().hex() != self.pin.sha256 {
            return Err(
                "Stack protected destination size or digest differs from trusted pin".to_owned(),
            );
        }
        self.check_identity()
    }

    pub(crate) fn revalidate(&self) -> Result<(), String> {
        if self
            .file
            .metadata()
            .map_err(|error| error.to_string())?
            .mode()
            & 0o777
            != 0o555
        {
            return Err("protected Stack executable mode changed".to_owned());
        }
        self.verify_bytes(Instant::now() + Duration::from_secs(30))
    }

    pub(crate) fn path(&self) -> &Path {
        &self.executable
    }

    pub(crate) fn close(&mut self) -> Result<(), String> {
        if !self.active {
            return Ok(());
        }
        self.check_identity()?;
        fs::remove_file(&self.executable).map_err(|error| error.to_string())?;
        fs::remove_dir(&self.directory).map_err(|error| error.to_string())?;
        self.active = false;
        Ok(())
    }
}

impl Drop for ProtectedStack {
    fn drop(&mut self) {
        if let Err(error) = self.close() {
            eprintln!("protected Stack cleanup failed: {error}");
        }
    }
}

fn exclusive_destination(path: &Path) -> Result<File, String> {
    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("cannot exclusively reserve Stack executable: {error}"))
}

#[doc(hidden)]
pub fn inspect_stack_destination_collision(path: &Path) -> Result<(), String> {
    exclusive_destination(path).map(|_| ())
}

#[doc(hidden)]
pub enum StackIdentityProbe {
    ReplacedFile,
    ReplacedDirectory,
    ChangedMode,
    ChangedBytes,
}

/// Mutates only a test-owned authenticated non-executable fixture, restores it,
/// and returns the actual production revalidation outcome.
#[doc(hidden)]
pub fn inspect_stack_identity_change(base: &Path, probe: StackIdentityProbe) -> Result<(), String> {
    let bytes = b"authenticated Stack authority fixture";
    let mut owned = ProtectedStack::reserve(
        base,
        Pin {
            size: bytes.len() as u64,
            sha256: hell_testkit::sha256_bytes(bytes).hex(),
            timeout: Duration::from_secs(1),
        },
    )?;
    owned.copy_verified(&mut &bytes[..], Instant::now() + Duration::from_secs(1))?;
    let outcome = match probe {
        StackIdentityProbe::ReplacedFile => {
            let retired = owned.directory.join("retired");
            fs::rename(&owned.executable, &retired).map_err(|error| error.to_string())?;
            fs::write(&owned.executable, bytes).map_err(|error| error.to_string())?;
            let outcome = owned.revalidate();
            fs::remove_file(&owned.executable).map_err(|error| error.to_string())?;
            fs::rename(retired, &owned.executable).map_err(|error| error.to_string())?;
            outcome
        }
        StackIdentityProbe::ReplacedDirectory => {
            let retired = owned.directory.with_extension("retired");
            fs::rename(&owned.directory, &retired).map_err(|error| error.to_string())?;
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&owned.directory)
                .map_err(|error| error.to_string())?;
            let outcome = owned.revalidate();
            fs::remove_dir(&owned.directory).map_err(|error| error.to_string())?;
            fs::rename(retired, &owned.directory).map_err(|error| error.to_string())?;
            outcome
        }
        StackIdentityProbe::ChangedMode => {
            owned
                .file
                .set_permissions(fs::Permissions::from_mode(0o755))
                .map_err(|error| error.to_string())?;
            let outcome = owned.revalidate();
            owned
                .file
                .set_permissions(fs::Permissions::from_mode(0o555))
                .map_err(|error| error.to_string())?;
            outcome
        }
        StackIdentityProbe::ChangedBytes => {
            owned
                .file
                .set_permissions(fs::Permissions::from_mode(0o755))
                .map_err(|error| error.to_string())?;
            let mut altered = bytes.to_vec();
            altered[0] ^= 1;
            fs::write(&owned.executable, altered).map_err(|error| error.to_string())?;
            owned
                .file
                .set_permissions(fs::Permissions::from_mode(0o555))
                .map_err(|error| error.to_string())?;
            owned.revalidate()
        }
    };
    owned.close()?;
    outcome
}

/// Exercises destination authentication only; cannot bind or execute fixture bytes.
#[doc(hidden)]
pub fn inspect_protected_stack_copy(
    base: &Path,
    bytes: &[u8],
    expected_size: u64,
    expected_sha256: &str,
) -> Result<(), String> {
    let mut owned = ProtectedStack::reserve(
        base,
        Pin {
            size: expected_size,
            sha256: expected_sha256.to_owned(),
            timeout: Duration::from_secs(1),
        },
    )?;
    let primary = owned.copy_verified(&mut &*bytes, Instant::now() + Duration::from_secs(1));
    match (primary, owned.close()) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(primary), Err(cleanup)) => Err(format!("{primary}; {cleanup}")),
    }
}
