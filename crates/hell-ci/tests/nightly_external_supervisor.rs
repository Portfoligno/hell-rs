#![cfg(any(unix, windows))]

use std::ffi::OsStr;
use std::process::Command;
use std::time::Duration;

fn run_external_supervisor_verifier(case: Option<&OsStr>) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
    command.arg("__verify-external-nightly-supervisor");
    if let Some(case) = case {
        command.arg(case);
    }
    let output = hell_testkit::run_supervised_command(&mut command, &[], Duration::from_mins(50))
        .expect("external Nightly supervisor verifier should execute");
    assert!(
        output.status.success() && !output.timed_out,
        "external Nightly supervisor verifier failed: stdout={}, stderr={}",
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

#[cfg(unix)]
#[test]
fn reporter_exit_preserves_external_owner_through_cleanup_and_exit_receipt() {
    run_external_supervisor_verifier(None);
}

#[cfg(windows)]
#[test]
fn windows_real_staged_authority_has_one_complete_supervisor_lifecycle() {
    run_external_supervisor_verifier(Some(OsStr::new("real-authority-positive")));
}

#[cfg(windows)]
#[test]
fn windows_supervisor_failure_matrix_is_sequential_and_bounded() {
    run_external_supervisor_verifier(Some(OsStr::new("sealed-authority-matrix")));
}

#[cfg(windows)]
#[test]
fn windows_no_go_deadline_chronology_rejects_a_stale_execution_cutoff() {
    run_external_supervisor_verifier(Some(OsStr::new("deadline-chronology")));
}

#[cfg(windows)]
#[test]
fn windows_supervisor_uses_exact_nested_job_without_breakaway() {
    run_external_supervisor_verifier(Some(OsStr::new("nested-job-launch")));
}

#[cfg(windows)]
#[test]
fn windows_supervisor_handle_list_has_exact_inheritance_topology() {
    run_external_supervisor_verifier(Some(OsStr::new("handle-list-inheritance")));
}

#[cfg(windows)]
#[test]
fn windows_pre_ready_failure_retains_phase_and_exact_exit_code() {
    run_external_supervisor_verifier(Some(OsStr::new("pre-ready-failure-frame")));
}

#[cfg(windows)]
#[test]
fn windows_traversal_directory_identity_survives_exact_child_mutation() {
    run_external_supervisor_verifier(Some(OsStr::new("directory-identity")));
}

#[cfg(windows)]
#[test]
fn windows_receipt_promotion_blocks_write_substitution_and_cleans_exactly() {
    run_external_supervisor_verifier(Some(OsStr::new("receipt-promotion")));
}
