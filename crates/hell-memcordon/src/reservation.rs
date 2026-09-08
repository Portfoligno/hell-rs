use std::fs::{self, OpenOptions};
use std::io::{Read as _, Result};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::MAX_EXECUTION_REPORT_BYTES;

static NEXT_REPORT_RESERVATION: AtomicU64 = AtomicU64::new(0);

/// Protected sibling reservation for one provider-created execution report.
///
/// The marker is created atomically while the final report path remains
/// absent, as required by `MemCordon`'s atomic report writer.
#[derive(Debug)]
pub struct ReportReservation {
    directory: PathBuf,
    report: PathBuf,
    marker: PathBuf,
    #[cfg(unix)]
    directory_device: u64,
    #[cfg(unix)]
    directory_inode: u64,
    #[cfg(windows)]
    directory_identity: same_file::Handle,
}

impl ReportReservation {
    /// Reserves one unpredictable report name in an already-protected directory.
    ///
    /// # Errors
    ///
    /// Returns an error when randomness, create-new reservation, or directory
    /// identity acquisition fails.
    pub fn create(directory: &Path) -> Result<Self> {
        for _ in 0..8 {
            let mut random = [0_u8; 16];
            getrandom::fill(&mut random).map_err(std::io::Error::other)?;
            let name = format!(
                "operation-{}-{:032x}",
                NEXT_REPORT_RESERVATION.fetch_add(1, Ordering::Relaxed),
                u128::from_le_bytes(random)
            );
            let report = directory.join(format!("{name}.json"));
            let marker = directory.join(format!(".{name}.reservation"));
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&marker)
            {
                Ok(marker_file) => {
                    if report.exists() {
                        drop(marker_file);
                        fs::remove_file(&marker)?;
                        continue;
                    }
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::MetadataExt as _;
                        let metadata = fs::symlink_metadata(directory)?;
                        return Ok(Self {
                            directory: directory.to_path_buf(),
                            report,
                            marker,
                            directory_device: metadata.dev(),
                            directory_inode: metadata.ino(),
                        });
                    }
                    #[cfg(windows)]
                    {
                        return Ok(Self {
                            directory: directory.to_path_buf(),
                            report,
                            marker,
                            directory_identity: same_file::Handle::from_path(directory)?,
                        });
                    }
                    #[cfg(not(any(unix, windows)))]
                    {
                        return Ok(Self {
                            directory: directory.to_path_buf(),
                            report,
                            marker,
                        });
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not reserve an unpredictable sealed report path",
        ))
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.report
    }

    fn revalidate_directory(&self) -> Result<()> {
        let metadata = fs::symlink_metadata(&self.directory)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "sealed report directory identity changed",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            if metadata.dev() != self.directory_device || metadata.ino() != self.directory_inode {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "sealed report directory identity changed",
                ));
            }
        }
        #[cfg(windows)]
        if same_file::Handle::from_path(&self.directory)? != self.directory_identity {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "sealed report directory identity changed",
            ));
        }
        Ok(())
    }

    /// Reads one completed report through a no-follow, identity-stable handle.
    ///
    /// # Errors
    ///
    /// Returns an error for substitution, unsafe permissions, or a report that
    /// changes or exceeds the consumer bound while being read.
    pub fn read_bounded(&self) -> Result<Vec<u8>> {
        self.revalidate_directory()?;
        let path_metadata = fs::symlink_metadata(&self.report)?;
        if path_metadata.file_type().is_symlink()
            || !path_metadata.is_file()
            || path_metadata.len() > u64::try_from(MAX_EXECUTION_REPORT_BYTES).unwrap_or(u64::MAX)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "sealed execution report is not one bounded regular file",
            ));
        }
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt as _;
            const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
            options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }
        let mut file = options.open(&self.report)?;
        let opened_metadata = file.metadata()?;
        if !opened_metadata.is_file() || opened_metadata.len() != path_metadata.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "sealed report identity changed while opening",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            if opened_metadata.dev() != path_metadata.dev()
                || opened_metadata.ino() != path_metadata.ino()
                || opened_metadata.mode() & 0o022 != 0
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "sealed report file authority is not private and stable",
                ));
            }
        }
        #[cfg(windows)]
        if same_file::Handle::from_file(file.try_clone()?)?
            != same_file::Handle::from_path(&self.report)?
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "sealed report file identity changed while opening",
            ));
        }
        let mut bytes = Vec::new();
        (&mut file)
            .take(
                u64::try_from(MAX_EXECUTION_REPORT_BYTES)
                    .unwrap_or(u64::MAX)
                    .saturating_add(1),
            )
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_EXECUTION_REPORT_BYTES
            || file.metadata()?.len() != opened_metadata.len()
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "sealed execution report changed or exceeded its read bound",
            ));
        }
        self.revalidate_directory()?;
        Ok(bytes)
    }
}

impl Drop for ReportReservation {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.marker);
    }
}
