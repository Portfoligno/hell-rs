//! Scoped host temporary files and directories.

use std::fs::{self, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::native_handle::FileHandle;

static NEXT_TEMP_RESOURCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy)]
enum TempKind {
    File,
    Directory,
}

/// An armed cleanup guard for one exactly identified temporary resource.
pub(crate) struct TempResource {
    path: PathBuf,
    kind: TempKind,
    armed: bool,
}

impl TempResource {
    pub(crate) fn create_directory(template: &str) -> io::Result<Self> {
        create_unique(template, |path| {
            fs::create_dir(path)?;
            Ok(Self {
                path: path.to_owned(),
                kind: TempKind::Directory,
                armed: true,
            })
        })
    }

    pub(crate) fn create_file(template: &str) -> io::Result<(Self, Arc<FileHandle>)> {
        create_unique(template, |path| {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(path)?;
            Ok((
                Self {
                    path: path.to_owned(),
                    kind: TempKind::File,
                    armed: true,
                },
                FileHandle::from_file(file),
            ))
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn cleanup(mut self) -> io::Result<()> {
        let result = self.remove();
        if result.is_ok() {
            self.armed = false;
        }
        result
    }

    fn remove(&self) -> io::Result<()> {
        match self.kind {
            TempKind::File => fs::remove_file(&self.path),
            TempKind::Directory => fs::remove_dir_all(&self.path),
        }
    }
}

impl Drop for TempResource {
    fn drop(&mut self) {
        if self.armed {
            let _ignored = self.remove();
        }
    }
}

fn create_unique<T>(template: &str, create: impl Fn(&Path) -> io::Result<T>) -> io::Result<T> {
    validate_template(template)?;
    let root = std::env::temp_dir();
    for _ in 0..1024 {
        let sequence = NEXT_TEMP_RESOURCE.fetch_add(1, Ordering::Relaxed);
        let candidate = root.join(format!("{template}-{}-{sequence}", std::process::id()));
        match create(&candidate) {
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            result => return result,
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a unique temporary resource",
    ))
}

fn validate_template(template: &str) -> io::Result<()> {
    if template.is_empty()
        || template == "."
        || template == ".."
        || template.contains(std::path::MAIN_SEPARATOR)
        || (std::path::MAIN_SEPARATOR != '/' && template.contains('/'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "temporary template must be one non-empty path component",
        ));
    }
    Ok(())
}
