use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

pub struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    pub fn new(label: &str) -> Self {
        let identifier = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let component = format!(
            "hell-release-verifier-{label}-{}-{identifier}",
            std::process::id()
        );
        let path = std::env::temp_dir().join(component);
        fs::create_dir(&path).expect("create isolated verifier test directory");
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.path).expect("remove isolated verifier test directory");
    }
}
