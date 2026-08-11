//! Scoped host temporary files and directories.

use std::fs::{self, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::native_handle::FileHandle;
use crate::policy::Limit;

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
    delete_retries: u8,
}

impl TempResource {
    pub(crate) fn create_directory(
        template: &str,
        retries: Limit<usize>,
        delete_retries: u8,
    ) -> io::Result<Self> {
        create_unique(template, retries, |path| {
            fs::create_dir(path)?;
            Ok(Self {
                path: path.to_owned(),
                kind: TempKind::Directory,
                armed: true,
                delete_retries,
            })
        })
    }

    pub(crate) fn create_file(
        template: &str,
        retries: Limit<usize>,
        delete_retries: u8,
    ) -> io::Result<(Self, Arc<FileHandle>)> {
        create_unique(template, retries, |path| {
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
                    delete_retries,
                },
                FileHandle::from_file(file, None),
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

    pub(crate) fn disarm_without_cleanup_for_mutation(mut self) {
        self.armed = false;
    }

    fn remove(&self) -> io::Result<()> {
        let mut last_error = None;
        for _ in 0..=self.delete_retries {
            let result = match self.kind {
                TempKind::File => fs::remove_file(&self.path),
                TempKind::Directory => fs::remove_dir_all(&self.path),
            };
            match result {
                Ok(()) => return Ok(()),
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.expect("at least one temporary cleanup attempt is made"))
    }
}

impl Drop for TempResource {
    fn drop(&mut self) {
        if self.armed {
            let _ignored = self.remove();
        }
    }
}

fn create_unique<T>(
    template: &str,
    retries: Limit<usize>,
    create: impl Fn(&Path) -> io::Result<T>,
) -> io::Result<T> {
    validate_template(template)?;
    let root = std::env::temp_dir();
    let mut attempts = 0_usize;
    loop {
        if retries.value().is_some_and(|maximum| attempts >= maximum) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("could not allocate a unique temporary resource after {attempts} attempts"),
            ));
        }
        attempts = attempts.saturating_add(1);
        let sequence = NEXT_TEMP_RESOURCE.fetch_add(1, Ordering::Relaxed);
        let candidate = root.join(format!("{template}-{}-{sequence}", std::process::id()));
        match create(&candidate) {
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            result => return result,
        }
    }
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

#[cfg(test)]
mod tests {
    use super::create_unique;
    use crate::policy::Limit;

    #[test]
    fn configured_collision_budget_fails_with_observed_attempts() {
        let error = create_unique("hell-temp-collision", Limit::At(3), |_| {
            Err::<(), _>(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "occupied",
            ))
        })
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert!(error.to_string().contains("after 3 attempts"));
    }
}
