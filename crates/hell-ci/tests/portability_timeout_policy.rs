use std::process::Command;

#[test]
fn portability_deadline_retains_exact_cleanup_and_reporting_reserve() {
    let output = Command::new(env!("CARGO_BIN_EXE_hell-ci"))
        .arg("__verify-portability-timeout-policy")
        .output()
        .expect("portability deadline verifier executes");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
#[test]
fn portability_deadline_relays_attribution_and_reaps_the_process_tree() {
    let output = Command::new(env!("CARGO_BIN_EXE_hell-ci"))
        .arg("__verify-portability-supervision")
        .output()
        .expect("portability supervision verifier executes");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
