//! Shared host handles and buffering/file-mode descriptions.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};

const BLOCK_BUFFER_BYTES: usize = 8 * 1024;

#[derive(Debug)]
pub struct FileHandle {
    state: Mutex<FileState>,
    buffering: Mutex<BufferMode>,
    permit: Mutex<Option<crate::budget::BudgetPermit>>,
}

#[derive(Debug)]
struct FileState {
    file: Option<File>,
    pending: Vec<u8>,
}

impl FileHandle {
    pub(crate) fn from_file(file: File, permit: Option<crate::budget::BudgetPermit>) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(FileState {
                file: Some(file),
                pending: Vec::new(),
            }),
            buffering: Mutex::new(BufferMode::Block),
            permit: Mutex::new(permit),
        })
    }

    pub(crate) fn open(
        path: &Path,
        mode: FileMode,
        permit: crate::budget::BudgetPermit,
    ) -> std::io::Result<Arc<Self>> {
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
        Ok(Self::from_file(options.open(path)?, Some(permit)))
    }

    pub(crate) fn write_all(&self, bytes: &[u8]) -> std::io::Result<()> {
        let mode = *self
            .buffering
            .lock()
            .map_err(|_| std::io::Error::other("file-buffering mutex was poisoned"))?;
        let mut state = self.lock()?;
        if state.file.is_none() {
            return Err(closed_handle());
        }
        state.pending.extend_from_slice(bytes);
        match mode {
            BufferMode::None => flush_pending(&mut state)?,
            BufferMode::Line => {
                if let Some(last_newline) = state.pending.iter().rposition(|byte| *byte == b'\n') {
                    let remaining = state.pending.split_off(last_newline.saturating_add(1));
                    flush_pending(&mut state)?;
                    state.pending = remaining;
                }
            }
            BufferMode::Block => flush_complete_blocks(&mut state)?,
        }
        Ok(())
    }

    pub(crate) fn read_up_to(&self, amount: usize) -> std::io::Result<Vec<u8>> {
        let mut state = self.lock()?;
        flush_pending(&mut state)?;
        let mut bytes = Vec::with_capacity(amount);
        state
            .file
            .as_mut()
            .ok_or_else(closed_handle)?
            .take(u64::try_from(amount).expect("bounded read size fits u64"))
            .read_to_end(&mut bytes)?;
        Ok(bytes)
    }

    pub(crate) fn close(&self) -> std::io::Result<()> {
        let mut state = self.lock()?;
        flush_pending(&mut state)?;
        if let Some(mut file) = state.file.take() {
            file.flush()?;
        }
        self.permit
            .lock()
            .map_err(|_| std::io::Error::other("handle-permit mutex was poisoned"))?
            .take();
        Ok(())
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.state.lock().map_or(true, |state| state.file.is_none())
    }

    pub(crate) fn attach_permit(&self, permit: crate::budget::BudgetPermit) -> std::io::Result<()> {
        *self
            .permit
            .lock()
            .map_err(|_| std::io::Error::other("handle-permit mutex was poisoned"))? = Some(permit);
        Ok(())
    }

    pub(crate) fn try_clone_file(&self) -> std::io::Result<File> {
        let mut state = self.lock()?;
        flush_pending(&mut state)?;
        state.file.as_ref().ok_or_else(closed_handle)?.try_clone()
    }

    pub(crate) fn set_buffering(&self, mode: BufferMode) -> std::io::Result<()> {
        let mut buffering = self
            .buffering
            .lock()
            .map_err(|_| std::io::Error::other("file-buffering mutex was poisoned"))?;
        if *buffering != mode {
            let mut state = self.lock()?;
            flush_pending(&mut state)?;
            *buffering = mode;
        }
        Ok(())
    }

    fn lock(&self) -> std::io::Result<std::sync::MutexGuard<'_, FileState>> {
        self.state
            .lock()
            .map_err(|_| std::io::Error::other("file-handle mutex was poisoned"))
    }
}

fn flush_pending(state: &mut FileState) -> std::io::Result<()> {
    if state.pending.is_empty() {
        return Ok(());
    }
    let file = state.file.as_mut().ok_or_else(closed_handle)?;
    file.write_all(&state.pending)?;
    file.flush()?;
    state.pending.clear();
    Ok(())
}

fn flush_complete_blocks(state: &mut FileState) -> std::io::Result<()> {
    let complete_bytes = state.pending.len() / BLOCK_BUFFER_BYTES * BLOCK_BUFFER_BYTES;
    if complete_bytes == 0 {
        return Ok(());
    }
    let file = state.file.as_mut().ok_or_else(closed_handle)?;
    file.write_all(&state.pending[..complete_bytes])?;
    state.pending.drain(..complete_bytes);
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::{BLOCK_BUFFER_BYTES, BufferMode, FileHandle};

    #[test]
    fn file_buffering_controls_host_visibility_and_flush_boundaries() {
        let path =
            std::env::temp_dir().join(format!("hell-rs-handle-buffering-{}", std::process::id()));
        let _already_absent = std::fs::remove_file(&path);
        let handle = FileHandle::from_file(std::fs::File::create(&path).unwrap(), None);

        handle.write_all(b"block").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"");

        handle.set_buffering(BufferMode::Line).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"block");
        handle.write_all(b"tail").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"block");
        handle.write_all(b"\nrest").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"blocktail\n");

        handle.close().unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"blocktail\nrest");
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn block_buffering_flushes_complete_blocks_and_bounds_pending_bytes() {
        let path = std::env::temp_dir().join(format!(
            "hell-rs-handle-block-buffering-{}",
            std::process::id()
        ));
        let _already_absent = std::fs::remove_file(&path);
        let handle = FileHandle::from_file(std::fs::File::create(&path).unwrap(), None);

        handle
            .write_all(&vec![b'a'; BLOCK_BUFFER_BYTES - 1])
            .unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
        handle.write_all(b"b").unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            u64::try_from(BLOCK_BUFFER_BYTES).unwrap()
        );

        handle.close().unwrap();
        std::fs::remove_file(path).unwrap();
    }
}
