//! Shared host handles and buffering/file-mode descriptions.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};

#[derive(Debug)]
pub struct FileHandle {
    file: Mutex<Option<File>>,
    buffering: Mutex<BufferMode>,
}

impl FileHandle {
    pub(crate) fn from_file(file: File) -> Arc<Self> {
        Arc::new(Self {
            file: Mutex::new(Some(file)),
            buffering: Mutex::new(BufferMode::Block),
        })
    }

    pub(crate) fn open(path: &Path, mode: FileMode) -> std::io::Result<Arc<Self>> {
        let mut options = OpenOptions::new();
        match mode {
            FileMode::Read => {
                options.read(true);
            }
            FileMode::Write => {
                options.write(true).create(true).truncate(true);
            }
            FileMode::Append => {
                options.append(true).create(true);
            }
            FileMode::ReadWrite => {
                options.read(true).write(true).create(true);
            }
        }
        Ok(Self::from_file(options.open(path)?))
    }

    pub(crate) fn write_all(&self, bytes: &[u8]) -> std::io::Result<()> {
        let mut state = self.lock()?;
        let file = state.as_mut().ok_or_else(closed_handle)?;
        file.write_all(bytes)?;
        let mode = *self
            .buffering
            .lock()
            .map_err(|_| std::io::Error::other("file-buffering mutex was poisoned"))?;
        if mode == BufferMode::None || (mode == BufferMode::Line && bytes.contains(&b'\n')) {
            file.flush()?;
        }
        Ok(())
    }

    pub(crate) fn read_up_to(&self, amount: usize) -> std::io::Result<Vec<u8>> {
        let mut state = self.lock()?;
        let mut bytes = Vec::with_capacity(amount);
        state
            .as_mut()
            .ok_or_else(closed_handle)?
            .take(u64::try_from(amount).expect("bounded read size fits u64"))
            .read_to_end(&mut bytes)?;
        Ok(bytes)
    }

    pub(crate) fn close(&self) -> std::io::Result<()> {
        let mut state = self.lock()?;
        if let Some(mut file) = state.take() {
            file.flush()?;
        }
        Ok(())
    }

    pub(crate) fn set_buffering(&self, mode: BufferMode) -> std::io::Result<()> {
        *self
            .buffering
            .lock()
            .map_err(|_| std::io::Error::other("file-buffering mutex was poisoned"))? = mode;
        Ok(())
    }

    fn lock(&self) -> std::io::Result<std::sync::MutexGuard<'_, Option<File>>> {
        self.file
            .lock()
            .map_err(|_| std::io::Error::other("file-handle mutex was poisoned"))
    }
}

fn closed_handle() -> std::io::Error {
    std::io::Error::other("handle is closed")
}

/// A standard stream, null stream, or shared file handle.
#[derive(Clone, Debug)]
pub enum HostHandle {
    /// Standard input.
    Stdin,
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
    /// A stream that discards writes and immediately reaches EOF on reads.
    Null,
    /// A shared file, optionally closed after one process use.
    File {
        /// Shared file state.
        handle: Arc<FileHandle>,
        /// Whether a process adapter closes the shared handle after use.
        close_after_process: bool,
    },
}

impl HostHandle {
    pub(crate) fn with_process_close(&self, close_after_process: bool) -> Self {
        match self {
            Self::File { handle, .. } => Self::File {
                handle: Arc::clone(handle),
                close_after_process,
            },
            value => value.clone(),
        }
    }
}

/// Buffering policy attached to a host handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BufferMode {
    /// Flush after every write.
    None,
    /// Flush after writes containing a newline.
    Line,
    /// Leave flushing to the underlying buffered writer.
    Block,
}

/// File access mode accepted by `IO.openFile`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileMode {
    /// Read an existing file.
    Read,
    /// Truncate or create a file for writing.
    Write,
    /// Create or append to a file.
    Append,
    /// Read and write a file without truncating it.
    ReadWrite,
}
