#[cfg(any(target_os = "linux", windows))]
use std::process::Command;
#[cfg(target_os = "linux")]
use std::sync::OnceLock;
#[cfg(any(target_os = "linux", windows))]
use std::time::Duration;
#[cfg(target_os = "linux")]
use std::time::Instant;

#[cfg(target_os = "linux")]
static LINUX_BASE_INVENTORY_SUITE: OnceLock<Result<serde_json::Value, String>> = OnceLock::new();
#[cfg(target_os = "linux")]
static LINUX_BASE_INVENTORY_FAILURE_SEQUENCE: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
#[cfg(target_os = "linux")]
const LINUX_BASE_INVENTORY_SYNTHETIC_EXECUTION_BUDGET: Duration = Duration::from_secs(30);
#[cfg(target_os = "linux")]
const LINUX_BASE_INVENTORY_SYNTHETIC_COMPLETION_RESERVE: Duration = Duration::from_secs(30);

#[cfg(windows)]
#[test]
fn base_inventory_binds_canonical_root_without_restricted_launch_authority() {
    let repository = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("hell-ci manifest must be below the repository root");
    let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
    command
        .arg("__verify-base-repository-inventory-authority")
        .arg(repository);
    let output = hell_testkit::run_supervised_command(&mut command, &[], Duration::from_mins(1))
        .expect("base repository inventory authority verifier must execute");
    assert!(
        output.status.success() && !output.timed_out,
        "{}",
        String::from_utf8_lossy(
            output
                .stderr
                .complete
                .as_deref()
                .unwrap_or(&output.stderr.prefix)
        )
    );
}

#[cfg(target_os = "linux")]
#[test]
fn base_inventory_uses_host_authority_inside_real_candidate_scope_and_restores_it() {
    let receipt = run_linux_base_inventory_verifier(None);
    let diagnostic = receipt_diagnostic(&receipt);
    assert_eq!(receipt["scenario"], "positive", "{diagnostic}");
    assert!(receipt["primary"].is_null(), "{diagnostic}");
    assert!(
        receipt["repositoryRoot"]
            .as_str()
            .is_some_and(|root| root.starts_with('/')),
        "{diagnostic}"
    );
    assert_phase_receipts(
        &receipt,
        &[
            ("setup", "completed"),
            ("behavior-inventory", "completed"),
            ("completion", "completed"),
            ("cleanup", "completed"),
        ],
    );
}

#[cfg(target_os = "linux")]
#[test]
fn base_inventory_setup_expiry_retains_completion_and_cleanup_receipts() {
    let receipt = run_linux_base_inventory_verifier(Some("setup-expired"));
    let diagnostic = receipt_diagnostic(&receipt);
    assert_eq!(receipt["scenario"], "setup-expired", "{diagnostic}");
    assert_eq!(receipt["primary"]["phase"], "setup", "{diagnostic}");
    assert_eq!(
        receipt["primary"]["detail"], "Linux base inventory setup deadline expired",
        "{diagnostic}"
    );
    assert_phase_receipts(
        &receipt,
        &[
            ("setup", "expired"),
            ("completion", "completed"),
            ("cleanup", "completed"),
        ],
    );
}

#[cfg(target_os = "linux")]
#[test]
fn base_inventory_behavior_expiry_preserves_primary_then_cleanup_chronology() {
    let receipt = run_linux_base_inventory_verifier(Some("behavior-expired"));
    let diagnostic = receipt_diagnostic(&receipt);
    assert_eq!(receipt["scenario"], "behavior-expired", "{diagnostic}");
    assert_eq!(
        receipt["primary"]["phase"], "behavior-inventory",
        "{diagnostic}"
    );
    assert_eq!(
        receipt["primary"]["detail"], "Linux base inventory behavior-inventory deadline expired",
        "{diagnostic}"
    );
    assert_phase_receipts(
        &receipt,
        &[
            ("setup", "completed"),
            ("behavior-inventory", "expired"),
            ("completion", "completed"),
            ("cleanup", "completed"),
        ],
    );
}

#[cfg(target_os = "linux")]
#[test]
fn base_inventory_failure_retains_evidence_without_relaying_protocol_bytes() {
    use std::sync::atomic::Ordering;

    let sequence = LINUX_BASE_INVENTORY_FAILURE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "hell-base-inventory-failure-{}-{sequence}",
        std::process::id()
    ));
    std::fs::create_dir(&root).expect("create non-repository fixture");
    let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
    command
        .arg("__verify-linux-base-inventory-failure-evidence")
        .arg(&root);
    let output = hell_testkit::run_supervised_command(&mut command, &[], Duration::from_mins(1))
        .expect("base inventory failure-evidence verifier must execute");
    let cleanup = std::fs::remove_dir(&root);
    assert!(
        output.status.success() && !output.timed_out,
        "{}",
        supervised_output_diagnostic(&output)
    );
    assert_eq!(output.stdout.total_bytes, 0);
    assert_eq!(output.stderr.total_bytes, 0);
    cleanup.expect("remove non-repository fixture");
}

#[cfg(target_os = "linux")]
fn run_linux_base_inventory_verifier(scenario: Option<&str>) -> serde_json::Value {
    if scenario == Some("setup-expired") {
        return run_linux_base_inventory_child(
            Some("setup-expired"),
            LINUX_BASE_INVENTORY_SYNTHETIC_EXECUTION_BUDGET,
            LINUX_BASE_INVENTORY_SYNTHETIC_COMPLETION_RESERVE,
        )
        .unwrap_or_else(|error| panic!("Linux base inventory synthetic verifier failed: {error}"));
    }
    let suite = LINUX_BASE_INVENTORY_SUITE.get_or_init(run_linux_base_inventory_suite);
    let suite = suite.as_ref().unwrap_or_else(|error| {
        panic!("Linux base inventory shared suite cached an infrastructure failure: {error}")
    });
    let expected = scenario.unwrap_or("positive");
    suite["receipts"]
        .as_array()
        .expect("Linux base inventory suite receipts")
        .iter()
        .find(|receipt| receipt["scenario"] == expected)
        .unwrap_or_else(|| panic!("Linux base inventory suite lacks {expected}"))
        .clone()
}

#[cfg(target_os = "linux")]
fn run_linux_base_inventory_suite() -> Result<serde_json::Value, String> {
    let receipt = run_linux_base_inventory_child(
        Some("suite-v1"),
        hell_ci::LINUX_BASE_INVENTORY_SUITE_EXECUTION_BUDGET,
        hell_ci::LINUX_BASE_INVENTORY_SUITE_COMPLETION_RESERVE,
    )?;
    if receipt["schemaVersion"] != 1
        || receipt["state"] != "verified"
        || receipt["receipts"].as_array().map(Vec::len) != Some(3)
    {
        return Err(format!(
            "Linux base inventory suite receipt differs: {}",
            receipt_diagnostic(&receipt)
        ));
    }
    Ok(receipt)
}

#[cfg(target_os = "linux")]
fn run_linux_base_inventory_child(
    scenario: Option<&str>,
    execution_budget: Duration,
    completion_reserve: Duration,
) -> Result<serde_json::Value, String> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
    command.arg("__verify-linux-base-inventory-candidate-scope");
    if let Some(scenario) = scenario {
        command.arg(scenario);
    }
    let execution_deadline = Instant::now()
        .checked_add(execution_budget)
        .ok_or_else(|| "Linux base inventory child execution deadline overflowed".to_owned())?;
    let completion_deadline = execution_deadline
        .checked_add(completion_reserve)
        .ok_or_else(|| "Linux base inventory child completion deadline overflowed".to_owned())?;
    let output = hell_testkit::run_supervised_command_until(
        &mut command,
        &[],
        execution_deadline,
        completion_deadline,
        None,
    )
    .map_err(|error| format!("Linux base inventory child must execute: {error}"))?;
    let diagnostic = supervised_output_diagnostic(&output);
    if !output.status.success() || output.timed_out {
        return Err(format!(
            "Linux base inventory child outcome differs: {diagnostic}"
        ));
    }
    for expected in ["quiescence-complete", "stdout-joined", "stderr-joined"] {
        if !output
            .phase_timings
            .iter()
            .any(|phase| phase.name == expected)
        {
            return Err(format!(
                "Linux base inventory child lacks {expected} receipt: {diagnostic}"
            ));
        }
    }
    if output.phase_timings.last().map(|phase| phase.name) != Some("stdin-joined") {
        return Err(format!(
            "Linux base inventory child lacks terminal stdin receipt: {diagnostic}"
        ));
    }
    let stdout =
        output.stdout.complete.as_deref().ok_or_else(|| {
            format!("Linux base inventory child stdout is incomplete: {diagnostic}")
        })?;
    let receipt: serde_json::Value = serde_json::from_slice(stdout).map_err(|error| {
        format!("cannot parse Linux base inventory child receipt: {error}; {diagnostic}")
    })?;
    if receipt["schemaVersion"] != 1 || receipt["state"] != "verified" {
        return Err(format!(
            "Linux base inventory child receipt header differs: {diagnostic}"
        ));
    }
    let mut canonical = serde_json::to_vec(&receipt)
        .map_err(|error| format!("cannot render Linux base inventory child receipt: {error}"))?;
    canonical.push(b'\n');
    if stdout != canonical {
        return Err(format!(
            "Linux base inventory child stdout is not one canonical JSON receipt: {diagnostic}"
        ));
    }
    Ok(receipt)
}

#[cfg(target_os = "linux")]
fn assert_phase_receipts(receipt: &serde_json::Value, expected: &[(&str, &str)]) {
    let diagnostic = receipt_diagnostic(receipt);
    let phases = receipt["phases"]
        .as_array()
        .expect("Linux base inventory verifier phases");
    assert_eq!(phases.len(), expected.len(), "{diagnostic}");
    for (phase, (name, state)) in phases.iter().zip(expected) {
        assert_eq!(phase["phase"], *name, "{diagnostic}");
        assert_eq!(phase["state"], *state, "{diagnostic}");
        assert!(phase["durationMillis"].is_u64(), "{diagnostic}");
    }
}

#[cfg(target_os = "linux")]
fn receipt_diagnostic(receipt: &serde_json::Value) -> String {
    serde_json::to_string(receipt)
        .unwrap_or_else(|error| format!("cannot render verifier receipt: {error}"))
}

#[cfg(target_os = "linux")]
fn supervised_output_diagnostic(output: &hell_testkit::SupervisedOutput) -> String {
    let termination = output.termination.as_ref().map_or_else(
        || "none".to_owned(),
        |receipt| {
            format!(
                "cleanupId={:?},forced={},reaped={}",
                receipt.cleanup_id, receipt.forced, receipt.reaped
            )
        },
    );
    let phases = output
        .phase_timings
        .iter()
        .map(|phase| phase.name)
        .collect::<Vec<_>>();
    format!(
        "status={:?},timedOut={},termination={termination},candidateQuiescenceComplete={},phases={phases:?},stdout={},stderr={}",
        output.status.code(),
        output.timed_out,
        output.candidate_quiescence_complete,
        bounded_capture_diagnostic(&output.stdout),
        bounded_capture_diagnostic(&output.stderr),
    )
}

#[cfg(target_os = "linux")]
fn bounded_capture_diagnostic(capture: &hell_testkit::BoundedCapture) -> String {
    let detail = capture.complete.as_ref().map_or_else(
        || {
            format!(
                "{}<middle omitted>{}",
                String::from_utf8_lossy(&capture.prefix),
                String::from_utf8_lossy(&capture.suffix)
            )
        },
        |complete| String::from_utf8_lossy(complete).into_owned(),
    );
    format!(
        "bytes={},sha256={},captureTruncated={},detail={detail:?}",
        capture.total_bytes,
        capture.sha256.hex(),
        capture.truncated,
    )
}
