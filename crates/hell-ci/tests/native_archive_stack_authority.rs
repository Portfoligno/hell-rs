#![cfg(unix)]

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[cfg(target_os = "macos")]
const MACOS_NATIVE_ARCHIVE_TERMINAL_PREFIX: &str = "hell-ci-macos-native-archive-terminal-v2:";
#[cfg(target_os = "macos")]
const MACOS_NATIVE_ARCHIVE_PRIMARY_LIMIT: usize = 192;

#[cfg(target_os = "macos")]
#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct MacosNativeArchiveTerminalReceipt {
    primary: String,
    primary_bytes: u64,
    primary_sha256: String,
    primary_truncated: bool,
    schema_version: u64,
    state: String,
    terminal: bool,
    verifier: String,
}

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        for _ in 0..32 {
            let sequence = FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "hell-ci-native-archive-stack-authority-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&root) {
                Ok(()) => return Self { root },
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("Stack archive authority fixture must be created: {error}"),
            }
        }
        panic!("Stack archive authority fixture allocation exhausted its collision bound");
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn stack_package_source_cwd_is_separate_from_its_archive_write_authority() {
    let fixture = Fixture::new();
    let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
    command
        .arg("__verify-native-archive-adapter-cleanup")
        .arg(&fixture.root);
    let output = hell_testkit::run_supervised_command(&mut command, &[], Duration::from_mins(10))
        .expect("native Stack archive authority verifier must execute");
    assert!(
        !output.timed_out,
        "native Stack archive authority verifier timed out"
    );
    assert!(
        output
            .phase_timings
            .iter()
            .any(|phase| phase.name == "quiescence-complete")
    );
    assert_eq!(
        output.phase_timings.last().map(|phase| phase.name),
        Some("stdin-joined")
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(
            output
                .stderr
                .complete
                .as_deref()
                .expect("stderr must fit the bounded complete capture")
        )
    );
}

#[cfg(target_os = "macos")]
#[test]
fn derived_broker_staging_seal_rejects_drift_and_restores_cleanup_authority() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
    command.arg("__verify-derived-archive-broker-staging-authority-v1");
    let output = hell_testkit::run_supervised_command(&mut command, &[], Duration::from_secs(30))
        .expect("derived archive broker staging authority verifier must execute");
    assert!(
        output.status.success() && !output.timed_out,
        "derived archive broker staging authority verifier failed: stdout={}, stderr={}",
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
}

#[cfg(target_os = "macos")]
#[test]
fn restricted_candidate_uses_only_the_sealed_archive_broker_capability() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
    command.arg("__verify-posix-candidate-target-authority");
    let output = hell_testkit::run_supervised_command(&mut command, &[], Duration::from_mins(10))
        .expect("typed archive broker production verifier must execute");
    assert_macos_native_archive_verifier_succeeded(&output, "candidate-target");
}

#[cfg(target_os = "macos")]
#[test]
fn retained_descriptor_crosses_candidate_private_stack_ancestor_without_mode_widening() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
    command
        .arg("__verify-native-archive-descriptor-broker-v2")
        .arg("/private/tmp");
    let output = hell_testkit::run_supervised_command(&mut command, &[], Duration::from_mins(3))
        .expect("native archive descriptor broker verifier must execute");
    assert_macos_native_archive_verifier_succeeded(&output, "descriptor-broker-v2");
}

#[cfg(target_os = "macos")]
fn assert_macos_native_archive_verifier_succeeded(
    output: &hell_testkit::SupervisedOutput,
    expected_verifier: &str,
) {
    let terminal = parse_macos_native_archive_terminal_receipt(output, expected_verifier);
    if !(output.status.success()
        && !output.timed_out
        && output
            .termination
            .is_some_and(|termination| termination.reaped)
        && terminal.is_ok_and(|receipt| receipt.state == "passed"))
    {
        panic!(
            "{}",
            macos_native_archive_failure_diagnostic(output, expected_verifier)
        );
    }
}

#[cfg(target_os = "macos")]
fn macos_native_archive_failure_diagnostic(
    output: &hell_testkit::SupervisedOutput,
    expected_verifier: &str,
) -> String {
    let terminal = parse_macos_native_archive_terminal_receipt(output, expected_verifier);
    let terminal = match terminal {
        Ok(receipt) => serde_json::to_string(&receipt)
            .unwrap_or_else(|error| format!("terminal-receipt-render-error={error}")),
        Err(error) => format!("terminal-receipt-invalid={error}"),
    };
    let termination = output.termination.map_or_else(
        || "none".to_owned(),
        |receipt| {
            format!(
                "cleanupId={},forced={},reaped={}",
                receipt.cleanup_id, receipt.forced, receipt.reaped
            )
        },
    );
    let phases = output
        .phase_timings
        .iter()
        .map(|phase| format!("{}:{}ms", phase.name, phase.elapsed.as_millis()))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "macOS native archive terminal receipt={terminal}; status={:?}; timedOut={}; termination={termination}; phases={phases}; stdoutBytes={}; stdoutSha256={}; stdoutTruncated={}; stderrBytes={}; stderrSha256={}; stderrTruncated={}; stdout={}; stderr={}",
        output.status.code(),
        output.timed_out,
        output.stdout.total_bytes,
        output.stdout.sha256.hex(),
        output.stdout.truncated,
        output.stderr.total_bytes,
        output.stderr.sha256.hex(),
        output.stderr.truncated,
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
    )
}

#[cfg(target_os = "macos")]
fn parse_macos_native_archive_terminal_receipt(
    output: &hell_testkit::SupervisedOutput,
    expected_verifier: &str,
) -> Result<MacosNativeArchiveTerminalReceipt, String> {
    let stderr =
        output.stderr.complete.as_deref().ok_or_else(|| {
            "hidden verifier stderr exceeded its complete-capture bound".to_owned()
        })?;
    decode_macos_native_archive_terminal_receipt(stderr, expected_verifier)
}

#[cfg(target_os = "macos")]
fn decode_macos_native_archive_terminal_receipt(
    stderr: &[u8],
    expected_verifier: &str,
) -> Result<MacosNativeArchiveTerminalReceipt, String> {
    let nonempty = stderr
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    let records = nonempty
        .iter()
        .filter_map(|line| line.strip_prefix(MACOS_NATIVE_ARCHIVE_TERMINAL_PREFIX.as_bytes()))
        .collect::<Vec<_>>();
    let [encoded] = records.as_slice() else {
        return Err("hidden verifier did not emit exactly one terminal receipt".to_owned());
    };
    let Some(last) = nonempty.last() else {
        return Err("hidden verifier terminal receipt is absent".to_owned());
    };
    if last.strip_prefix(MACOS_NATIVE_ARCHIVE_TERMINAL_PREFIX.as_bytes()) != Some(*encoded) {
        return Err("hidden verifier terminal receipt is not the final stderr record".to_owned());
    }
    let receipt: MacosNativeArchiveTerminalReceipt = serde_json::from_slice(encoded)
        .map_err(|error| format!("cannot decode hidden verifier terminal receipt: {error}"))?;
    let canonical = serde_json::to_vec(&receipt)
        .map_err(|error| format!("cannot re-encode hidden verifier terminal receipt: {error}"))?;
    if canonical != *encoded {
        return Err("hidden verifier terminal receipt is not canonical JSON".to_owned());
    }
    let digest = hell_testkit::Digest::from_hex(&receipt.primary_sha256)
        .map_err(|error| format!("hidden verifier primary digest is invalid: {error}"))?;
    let retained_primary_sha256 = hell_testkit::sha256_bytes(receipt.primary.as_bytes()).hex();
    let state_valid = match receipt.state.as_str() {
        "passed" => {
            receipt.primary.is_empty()
                && receipt.primary_bytes == 0
                && !receipt.primary_truncated
                && receipt.primary_sha256 == retained_primary_sha256
        }
        "failed" => {
            !receipt.primary.is_empty()
                && (receipt.primary_truncated || receipt.primary_sha256 == retained_primary_sha256)
        }
        _ => false,
    };
    if receipt.schema_version != 2
        || !receipt.terminal
        || receipt.verifier != expected_verifier
        || receipt.primary.len() > MACOS_NATIVE_ARCHIVE_PRIMARY_LIMIT
        || receipt.primary_sha256 != digest.hex()
        || receipt.primary_truncated != (receipt.primary_bytes > receipt.primary.len() as u64)
        || receipt.primary_bytes < receipt.primary.len() as u64
        || !state_valid
    {
        return Err("hidden verifier terminal receipt fields differ".to_owned());
    }
    Ok(receipt)
}

#[cfg(target_os = "macos")]
#[test]
fn compact_native_archive_failure_receipts_precede_noisy_streams() {
    let receipt = |verifier: &str, primary: &str| MacosNativeArchiveTerminalReceipt {
        primary: primary.to_owned(),
        primary_bytes: primary.len() as u64,
        primary_sha256: hell_testkit::sha256_bytes(primary.as_bytes()).hex(),
        primary_truncated: false,
        schema_version: 2,
        state: "failed".to_owned(),
        terminal: true,
        verifier: verifier.to_owned(),
    };
    let descriptor_receipt = receipt(
        "descriptor-broker-v2",
        "descriptor broker rejected retained input identity",
    );
    let production_receipt = receipt(
        "candidate-target",
        "candidate target broker cleanup receipt differed",
    );
    let success_receipt = MacosNativeArchiveTerminalReceipt {
        primary: String::new(),
        primary_bytes: 0,
        primary_sha256: hell_testkit::sha256_bytes(&[]).hex(),
        primary_truncated: false,
        schema_version: 2,
        state: "passed".to_owned(),
        terminal: true,
        verifier: "candidate-target".to_owned(),
    };
    let descriptor =
        serde_json::to_string(&descriptor_receipt).expect("serialize descriptor terminal receipt");
    let production =
        serde_json::to_string(&production_receipt).expect("serialize production terminal receipt");
    let success =
        serde_json::to_string(&success_receipt).expect("serialize success terminal receipt");
    let descriptor_stderr =
        format!("full descriptor error\n{MACOS_NATIVE_ARCHIVE_TERMINAL_PREFIX}{descriptor}\n");
    let production_stderr =
        format!("full production error\n{MACOS_NATIVE_ARCHIVE_TERMINAL_PREFIX}{production}\n");
    assert_eq!(
        decode_macos_native_archive_terminal_receipt(
            descriptor_stderr.as_bytes(),
            "descriptor-broker-v2"
        )
        .expect("decode descriptor terminal receipt")
        .primary,
        descriptor_receipt.primary
    );
    assert_eq!(
        decode_macos_native_archive_terminal_receipt(
            production_stderr.as_bytes(),
            "candidate-target"
        )
        .expect("decode production terminal receipt")
        .primary,
        production_receipt.primary
    );
    let success_stderr =
        format!("Compiling posix-target-probe\n{MACOS_NATIVE_ARCHIVE_TERMINAL_PREFIX}{success}\n");
    assert_eq!(
        decode_macos_native_archive_terminal_receipt(success_stderr.as_bytes(), "candidate-target")
            .expect("decode noisy success terminal receipt")
            .state,
        "passed"
    );
    let noise = "group-inventory".repeat(4_096);
    let descriptor_diagnostic = format!(
        "macOS native archive terminal receipt={descriptor}; stdout={noise}; stderr={noise}"
    );
    let production_diagnostic = format!(
        "macOS native archive terminal receipt={production}; stdout={noise}; stderr={noise}"
    );
    let descriptor_prefix = &descriptor_diagnostic[..descriptor_diagnostic.len().min(512)];
    let production_prefix = &production_diagnostic[..production_diagnostic.len().min(512)];
    assert!(descriptor_prefix.contains("descriptor broker rejected retained input identity"));
    assert!(production_prefix.contains("candidate target broker cleanup receipt differed"));
    assert_ne!(descriptor_prefix, production_prefix);

    assert_malformed_macos_native_archive_terminal_receipts_are_rejected(
        &descriptor_receipt,
        &success_receipt,
    );
}

#[cfg(target_os = "macos")]
fn assert_malformed_macos_native_archive_terminal_receipts_are_rejected(
    descriptor_receipt: &MacosNativeArchiveTerminalReceipt,
    success_receipt: &MacosNativeArchiveTerminalReceipt,
) {
    let descriptor = serde_json::to_string(descriptor_receipt)
        .expect("serialize descriptor malformed-frame source");
    let descriptor_stderr =
        format!("full descriptor error\n{MACOS_NATIVE_ARCHIVE_TERMINAL_PREFIX}{descriptor}\n");
    let duplicate = format!(
        "{MACOS_NATIVE_ARCHIVE_TERMINAL_PREFIX}{descriptor}\n{MACOS_NATIVE_ARCHIVE_TERMINAL_PREFIX}{descriptor}\n"
    );
    let nonfinal =
        format!("{MACOS_NATIVE_ARCHIVE_TERMINAL_PREFIX}{descriptor}\ntrailing diagnostic\n");
    for malformed in [b"no terminal receipt\n".as_slice(), duplicate.as_bytes()] {
        assert!(
            decode_macos_native_archive_terminal_receipt(malformed, "descriptor-broker-v2")
                .is_err()
        );
    }
    assert!(
        decode_macos_native_archive_terminal_receipt(nonfinal.as_bytes(), "descriptor-broker-v2")
            .is_err()
    );
    assert!(
        decode_macos_native_archive_terminal_receipt(
            descriptor_stderr.as_bytes(),
            "candidate-target"
        )
        .is_err()
    );

    for malformed in malformed_macos_native_archive_receipts(descriptor_receipt) {
        let stderr = format!("{MACOS_NATIVE_ARCHIVE_TERMINAL_PREFIX}{malformed}\n");
        assert!(
            decode_macos_native_archive_terminal_receipt(stderr.as_bytes(), "descriptor-broker-v2")
                .is_err()
        );
    }
    for malformed in malformed_macos_native_archive_success_receipts(success_receipt) {
        let stderr = format!("{MACOS_NATIVE_ARCHIVE_TERMINAL_PREFIX}{malformed}\n");
        assert!(
            decode_macos_native_archive_terminal_receipt(stderr.as_bytes(), "candidate-target")
                .is_err()
        );
    }
}

#[cfg(target_os = "macos")]
fn malformed_macos_native_archive_receipts(
    receipt: &MacosNativeArchiveTerminalReceipt,
) -> Vec<String> {
    let source = serde_json::to_value(receipt).expect("serialize source terminal receipt");
    [
        ("schemaVersion", serde_json::json!(1)),
        ("state", serde_json::json!("completed")),
        ("terminal", serde_json::json!(false)),
        ("primary", serde_json::json!("")),
        ("primaryBytes", serde_json::json!(1)),
        ("primaryTruncated", serde_json::json!(true)),
        ("primarySha256", serde_json::json!("not-a-digest")),
        (
            "primarySha256",
            serde_json::json!(hell_testkit::sha256_bytes(b"different primary").hex()),
        ),
    ]
    .into_iter()
    .map(|(field, value)| {
        let mut malformed = source.clone();
        malformed[field] = value;
        serde_json::to_string(&malformed).expect("serialize malformed terminal receipt")
    })
    .chain(std::iter::once({
        let mut extra = source.clone();
        extra["extra"] = serde_json::json!(true);
        serde_json::to_string(&extra).expect("serialize extra-field terminal receipt")
    }))
    .collect()
}

#[cfg(target_os = "macos")]
fn malformed_macos_native_archive_success_receipts(
    receipt: &MacosNativeArchiveTerminalReceipt,
) -> Vec<String> {
    let source = serde_json::to_value(receipt).expect("serialize source success receipt");
    [
        ("primary", serde_json::json!("unexpected")),
        ("primaryBytes", serde_json::json!(1)),
        ("primaryTruncated", serde_json::json!(true)),
        (
            "primarySha256",
            serde_json::json!(hell_testkit::sha256_bytes(b"unexpected").hex()),
        ),
        ("state", serde_json::json!("completed")),
    ]
    .into_iter()
    .map(|(field, value)| {
        let mut malformed = source.clone();
        malformed[field] = value;
        serde_json::to_string(&malformed).expect("serialize malformed success terminal receipt")
    })
    .collect()
}

#[cfg(target_os = "macos")]
#[test]
fn broker_limit_rejection_and_nonblocking_marker_have_terminal_receipts() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
    command
        .arg("__verify-native-archive-broker-terminal-receipts")
        .arg("/private/tmp");
    let output = hell_testkit::run_supervised_command(&mut command, &[], Duration::from_secs(45))
        .expect("native archive broker terminal-receipt verifier must execute");
    assert!(
        output.status.success() && !output.timed_out,
        "native archive broker terminal-receipt verifier failed: stdout={}, stderr={}",
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
}
