#![cfg(unix)]

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        for _ in 0..32 {
            let sequence = FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "hell-ci-native-archive-ghc-configure-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&root) {
                Ok(()) => return Self { root },
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("GHC configure fixture must be created: {error}"),
            }
        }
        panic!("GHC configure fixture allocation exhausted its collision bound");
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn ghc_configure_probe_retains_relative_argv_and_absolute_authority() {
    let fixture = Fixture::new();
    let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
    command
        .arg("__verify-native-archive-ghc-configure-probe")
        .arg(&fixture.root);
    let output = hell_testkit::run_supervised_command(&mut command, &[], Duration::from_mins(2))
        .expect("GHC configure production verifier must execute");
    assert!(
        output.status.success() && !output.timed_out,
        "GHC configure production verifier failed: stdout={}, stderr={}",
        String::from_utf8_lossy(
            output
                .stdout
                .complete
                .as_deref()
                .unwrap_or(&output.stdout.prefix),
        ),
        String::from_utf8_lossy(
            output
                .stderr
                .complete
                .as_deref()
                .unwrap_or(&output.stderr.prefix),
        ),
    );
    assert!(
        fs::read_dir(&fixture.root)
            .expect("GHC configure fixture parent must remain readable")
            .next()
            .is_none(),
        "GHC configure verifier must explicitly remove its fixture"
    );
}
