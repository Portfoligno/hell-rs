use std::process::Command;
use std::time::{Duration, Instant};

#[test]
fn assurance_command_failure_receipts_bind_all_terminal_scenarios() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
    command.arg("__verify-assurance-command-failure-receipts");
    let execution_deadline = Instant::now()
        .checked_add(Duration::from_secs(30))
        .expect("assurance receipt verifier execution deadline");
    let completion_deadline = execution_deadline
        .checked_add(Duration::from_secs(10))
        .expect("assurance receipt verifier completion deadline");
    let result = hell_testkit::run_supervised_command_until(
        &mut command,
        &[],
        execution_deadline,
        completion_deadline,
        None,
    )
    .expect("run assurance command failure receipt verifier");
    assert!(!result.timed_out, "assurance receipt verifier timed out");
    assert!(result.status.success(), "{}", retained_stderr(&result));
    for expected in ["quiescence-complete", "stdout-joined", "stderr-joined"] {
        assert!(
            result
                .phase_timings
                .iter()
                .any(|phase| phase.name == expected),
            "assurance receipt verifier lacks {expected}"
        );
    }
    assert_eq!(
        result.phase_timings.last().map(|phase| phase.name),
        Some("stdin-joined")
    );
    let summary: serde_json::Value = serde_json::from_slice(
        result
            .stdout
            .complete
            .as_deref()
            .expect("assurance receipt verifier stdout must be complete"),
    )
    .expect("parse assurance receipt verifier summary");
    assert_eq!(summary["schemaVersion"], 1);
    assert_eq!(summary["state"], "verified");
    let receipts = summary["receipts"].as_array().expect("receipt array");
    assert_eq!(receipts.len(), 4);
    assert_eq!(receipts[0]["phase"], "baseline");
    assert_eq!(receipts[0]["status"]["value"], "23");
    assert_eq!(receipts[1]["phase"], "activated");
    assert_eq!(receipts[1]["status"]["success"], true);
    assert_eq!(receipts[2]["timedOut"], true);
    assert_eq!(receipts[2]["lifecycle"]["forced"], true);
    assert_eq!(receipts[2]["lifecycle"]["reaped"], true);
    for stream in ["stdout", "stderr"] {
        assert_eq!(receipts[3][stream]["captureTruncated"], true);
        assert_eq!(receipts[3][stream]["evidence"]["kind"], "prefix-suffix");
        assert!(
            receipts[3][stream]["evidence"]["omittedBytes"]
                .as_u64()
                .is_some_and(|bytes| bytes > 0)
        );
    }
}

fn retained_stderr(output: &hell_testkit::SupervisedOutput) -> String {
    String::from_utf8_lossy(
        output
            .stderr
            .complete
            .as_deref()
            .unwrap_or(&output.stderr.prefix),
    )
    .into_owned()
}
