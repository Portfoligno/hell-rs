#![cfg(unix)]

#[test]
fn typed_trusted_cargo_retains_binding_and_ordinary_host_status() {
    let version = hell_ci::run_bound_trusted_cargo_for_integration().unwrap();
    assert!(version.starts_with("cargo "), "{version}");
}
