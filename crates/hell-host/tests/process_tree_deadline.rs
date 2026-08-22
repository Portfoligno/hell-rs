#[cfg(unix)]
#[test]
fn expired_kill_reap_deadline_returns_before_retained_cleanup_receipt() {
    hell_host::verify_termination_deadline_for_integration()
        .expect("termination deadline verifier completes retained cleanup");
}
