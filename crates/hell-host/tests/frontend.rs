#![cfg(unix)]

use std::process::Command;
use std::time::{Duration, Instant};

use hell_host::{
    FrontendChild, RetainedFrontendTerminationState, retained_frontend_termination_receipt,
};

#[test]
fn direct_frontend_waits_without_creating_a_tree_acceptance_receipt() {
    let mut command = Command::new("/usr/bin/true");
    let child = FrontendChild::spawn(&mut command).expect("spawn direct frontend");
    assert!(child.wait().expect("reap direct frontend").success());
}

#[test]
fn expired_cleanup_deadline_retains_direct_frontend_ownership() {
    let mut command = Command::new("/bin/sleep");
    command.arg("60");
    let mut child = FrontendChild::spawn(&mut command).expect("spawn direct frontend");
    let error = child
        .terminate_until(Instant::now())
        .expect_err("expired deadline must retain cleanup");
    let receipt = retained_frontend_termination_receipt(&error).expect("typed retained receipt");
    let snapshot = receipt.wait_until(Instant::now() + Duration::from_secs(5));
    assert!(matches!(
        snapshot.state,
        RetainedFrontendTerminationState::Completed(report) if report.reaped
    ));
    assert!(snapshot.lifecycle_idle);
}
