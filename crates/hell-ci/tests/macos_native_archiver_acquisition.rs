#![cfg(target_os = "macos")]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
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
                "hell-ci-macos-native-archiver-acquisition-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&root) {
                Ok(()) => return Self { root },
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("native archiver fixture must be created: {error}"),
            }
        }
        panic!("native archiver fixture allocation exhausted its collision bound");
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn run_receipted_verifier(command: &str, receipt: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_hell-ci"))
        .arg(command)
        .arg(receipt)
        .output()
        .expect("macOS native archiver verifier must execute")
}

fn require_terminal_receipt(receipt: &Path, expected_case: &str, output: &Output) {
    let receipt = fs::read_to_string(receipt).unwrap_or_else(|error| {
        panic!(
            "native archiver receipt must be readable: {error}; stdout={}; stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        )
    });
    eprint!("{}", String::from_utf8_lossy(&output.stderr));
    eprint!("{receipt}");
    let lines = receipt.lines().collect::<Vec<_>>();
    assert!(
        !lines.is_empty() && lines.len() <= 64,
        "native archiver receipt must be nonempty and bounded"
    );
    assert!(
        lines.iter().all(|line| {
            line.starts_with("native-archiver-verifier-v1 sequence=")
                && line.contains(" target=macos-native-archiver-acquisition ")
                && line.contains(&format!(" case={expected_case} "))
                && line.contains(" phase=")
                && line.contains(" state=")
                && line.contains(" elapsedMillis=")
                && line.contains(" cleanupOwner=")
                && line.contains(" cleanupResult=")
                && line.contains(" detail=")
        }),
        "native archiver receipt frame differs from its typed bounded schema"
    );
    let mut previous_elapsed = 0_u128;
    for (index, line) in lines.iter().enumerate() {
        let expected_sequence = index + 1;
        assert!(
            line.contains(&format!(" sequence={expected_sequence} ")),
            "native archiver receipt sequence is not exact: {line}"
        );
        let elapsed = line
            .split_whitespace()
            .find_map(|field| field.strip_prefix("elapsedMillis="))
            .and_then(|value| value.parse::<u128>().ok())
            .unwrap_or_else(|| panic!("native archiver elapsed receipt is invalid: {line}"));
        assert!(
            elapsed >= previous_elapsed,
            "native archiver receipt elapsed chronology regressed: {line}"
        );
        previous_elapsed = elapsed;
    }
    let terminal = lines
        .last()
        .expect("nonempty native archiver receipt must have a terminal candidate");
    assert!(
        {
            let line = terminal;
            line.contains(" phase=terminal ")
                && line.contains(" state=passed ")
                && line.contains(" cleanupOwner=all ")
                && line.contains(" cleanupResult=absent ")
        },
        "native archiver receipt lacks a successful cleanup-attested terminal frame: {terminal}"
    );
}

#[test]
fn homebrew_real_positive_acquires_stages_executes_and_cleans_once() {
    let fixture = Fixture::new();
    let receipt = fixture.root.join("homebrew-positive.receipt");
    let output = run_receipted_verifier("__verify-macos-native-archiver-acquisition", &receipt);
    require_terminal_receipt(
        &receipt,
        "homebrew-real-positive-acquire-stage-execute-cleanup",
        &output,
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn system_only_graph_parser_rpath_escape_and_mutation_are_deterministic() {
    let fixture = Fixture::new();
    let receipt = fixture.root.join("synthetic-topology.receipt");
    let output = run_receipted_verifier("__verify-macos-native-archiver-topology", &receipt);
    require_terminal_receipt(
        &receipt,
        "synthetic-system-topology-parser-and-mutation-negatives",
        &output,
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn sealed_synthetic_archiver_receipt_avoids_repeated_closure_scans() {
    let output = Command::new(env!("CARGO_BIN_EXE_hell-ci"))
        .arg("__verify-macos-native-archiver-receipt")
        .output()
        .expect("macOS native archiver receipt verifier must execute");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn synthetic_dependency_receipt_rejects_authority_mutation_but_allows_sibling_churn() {
    let output = Command::new(env!("CARGO_BIN_EXE_hell-ci"))
        .arg("__verify-macos-native-archiver-dependency-receipt")
        .output()
        .expect("macOS native archiver dependency verifier must execute");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
