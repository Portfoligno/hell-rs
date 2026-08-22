//! Host adapter helpers kept outside the compiler and pure evaluator.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use hell_runtime::RuntimeContext;

pub use hell_host::{
    CleanupLease, CleanupLifecycleReceipt, HostServices, RetainedTerminationReceipt,
    RetainedTerminationSnapshot, RetainedTerminationState, SupervisedChild, TerminationReport,
    WaitOutcome, retained_termination_receipt,
};

#[derive(Clone, Debug, Default)]
pub struct CapabilityPolicy {
    pub allow_filesystem: bool,
    pub allow_process: bool,
    pub allow_network: bool,
}

#[derive(Clone, Debug)]
pub struct PlatformContext {
    pub runtime: RuntimeContext,
    pub cwd: Arc<PathBuf>,
    pub capabilities: CapabilityPolicy,
}

impl PlatformContext {
    /// Creates a context backed by the current process and permissive default
    /// host capabilities.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the process working directory is unavailable.
    pub fn process(arguments: Vec<OsString>) -> std::io::Result<Self> {
        Ok(Self {
            runtime: RuntimeContext::process(arguments)?,
            cwd: Arc::new(std::env::current_dir()?),
            capabilities: CapabilityPolicy {
                allow_filesystem: true,
                allow_process: true,
                allow_network: true,
            },
        })
    }

    /// Checks filesystem capability for one concrete path.
    ///
    /// # Errors
    ///
    /// Returns [`std::io::ErrorKind::PermissionDenied`] when filesystem access
    /// is disabled by policy.
    pub fn require_filesystem(&self, path: &Path) -> std::io::Result<()> {
        if self.capabilities.allow_filesystem {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("filesystem access denied for {}", path.display()),
            ))
        }
    }

    /// Checks process-spawn capability for one executable.
    ///
    /// # Errors
    ///
    /// Returns [`std::io::ErrorKind::PermissionDenied`] when child processes
    /// are disabled by policy.
    pub fn require_process(&self, executable: &Path) -> std::io::Result<()> {
        if self.capabilities.allow_process {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("process execution denied for {}", executable.display()),
            ))
        }
    }

    /// Checks network capability for one remote authority.
    ///
    /// # Errors
    ///
    /// Returns [`std::io::ErrorKind::PermissionDenied`] when network access is
    /// disabled by policy.
    pub fn require_network(&self, authority: &str) -> std::io::Result<()> {
        if self.capabilities.allow_network {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("network access denied for {authority}"),
            ))
        }
    }

    /// Resolves a Hell path against the context's logical working directory.
    #[must_use]
    pub fn resolve_path(&self, path: &Path) -> PathBuf {
        if path.is_absolute() {
            path.to_owned()
        } else {
            self.cwd.join(path)
        }
    }

    /// Reads a UTF-8 text file after a per-operation capability check.
    ///
    /// # Errors
    ///
    /// Returns permission, filesystem, or invalid-UTF-8 errors without lossy
    /// decoding.
    pub fn read_text(&self, path: &Path) -> std::io::Result<Arc<str>> {
        let path = self.resolve_path(path);
        self.require_filesystem(&path)?;
        decode_utf8("Text.readFile", std::fs::read(path)?)
    }

    /// Writes a UTF-8 text file after a per-operation capability check.
    ///
    /// # Errors
    ///
    /// Returns permission or filesystem errors.
    pub fn write_text(&self, path: &Path, text: &str) -> std::io::Result<()> {
        let path = self.resolve_path(path);
        self.require_filesystem(&path)?;
        std::fs::write(path, text.as_bytes())
    }

    /// Appends UTF-8 text after a per-operation capability check.
    ///
    /// # Errors
    ///
    /// Returns permission or filesystem errors.
    pub fn append_text(&self, path: &Path, text: &str) -> std::io::Result<()> {
        use std::io::Write as _;

        let path = self.resolve_path(path);
        self.require_filesystem(&path)?;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        file.write_all(text.as_bytes())
    }
}

/// Decodes strict UTF-8 while retaining the failing operation and byte offset.
///
/// # Errors
///
/// Returns [`std::io::ErrorKind::InvalidData`] with the first invalid byte
/// offset when `bytes` is not UTF-8.
pub fn decode_utf8(operation: &'static str, bytes: Vec<u8>) -> std::io::Result<Arc<str>> {
    String::from_utf8(bytes)
        .map(Arc::<str>::from)
        .map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "{operation}: invalid UTF-8 at byte {}",
                    error.utf8_error().valid_up_to()
                ),
            )
        })
}
