#![cfg(unix)]

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        for _ in 0..32 {
            let sequence = FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "hell-ci-native-archive-adapter-lifecycle-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&root) {
                Ok(()) => return Self { root },
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("adapter lifecycle fixture must be created: {error}"),
            }
        }
        panic!("adapter lifecycle fixture allocation exhausted its collision bound");
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn explicit_adapter_close_cleans_partial_and_failed_initialization_without_late_drop() {
    let fixture = Fixture::new();
    let output = Command::new(env!("CARGO_BIN_EXE_hell-ci"))
        .arg("__verify-native-archive-adapter-cleanup")
        .arg(&fixture.root)
        .output()
        .expect("native archive adapter lifecycle verifier must execute");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        fs::read_dir(&fixture.root)
            .expect("adapter lifecycle fixture must remain readable")
            .next()
            .is_none(),
        "explicit adapter cleanup must leave its retained parent empty"
    );
}
