#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt as _;
#[cfg(unix)]
use std::process::Command;

#[cfg(unix)]
#[test]
fn candidate_receipt_consumer_accepts_exact_driver_identity_and_rejects_mutation() {
    let executable = fs::canonicalize(env!("CARGO_BIN_EXE_hell-ci"))
        .expect("POSIX driver receipt executable must canonicalize");
    let metadata = fs::metadata(&executable).expect("POSIX driver receipt must be inspectable");
    let digest = hell_testkit::sha256_file(&executable)
        .expect("POSIX driver receipt executable must be hashable");
    let arguments = [
        "posix-driver-receipt-v1".into(),
        executable.as_os_str().to_owned(),
        metadata.dev().to_string().into(),
        metadata.ino().to_string().into(),
        metadata.uid().to_string().into(),
        metadata.gid().to_string().into(),
        (metadata.mode() & 0o7777).to_string().into(),
        digest.hex().into(),
        "fixture".into(),
    ];
    let output = Command::new(&executable)
        .arg("__verify-posix-candidate-driver-receipt")
        .args(&arguments)
        .output()
        .expect("POSIX candidate receipt verification must execute");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut mutated = arguments;
    mutated[3] = metadata.ino().wrapping_add(1).to_string().into();
    let rejected = Command::new(&executable)
        .arg("__verify-posix-candidate-driver-receipt")
        .args(mutated)
        .output()
        .expect("mutated POSIX candidate receipt verification must execute");
    assert!(!rejected.status.success());
    assert!(
        String::from_utf8_lossy(&rejected.stderr)
            .contains("lacks its driver-owned pre-candidate receipt")
    );
}

#[cfg(unix)]
#[test]
fn native_cargo_without_a_staged_compiler_is_rejected() {
    let output = Command::new(env!("CARGO_BIN_EXE_hell-ci"))
        .arg("__verify-posix-native-cargo-rejection")
        .output()
        .expect("POSIX native Cargo rejection verification must execute");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
#[test]
fn rustc_environment_is_exact_without_path_or_wrapper_fallback() {
    let output = Command::new(env!("CARGO_BIN_EXE_hell-ci"))
        .arg("__verify-posix-rustc-environment")
        .output()
        .expect("POSIX Rust compiler environment verification must execute");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
#[test]
fn expired_identity_query_deadline_rejects_before_launch() {
    let output = Command::new(env!("CARGO_BIN_EXE_hell-ci"))
        .arg("__verify-posix-identity-query-deadline")
        .output()
        .expect("POSIX identity query deadline verification must execute");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
#[test]
fn candidate_target_remover_is_bounded_and_preserves_external_authorities() {
    let output = Command::new(env!("CARGO_BIN_EXE_hell-ci"))
        .arg("__verify-posix-candidate-target-remover")
        .output()
        .expect("POSIX candidate target remover verification must execute");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
#[test]
fn principal_cleanup_requires_quiescence_then_root_then_user_absence() {
    let output = Command::new(env!("CARGO_BIN_EXE_hell-ci"))
        .arg("__verify-posix-principal-cleanup-order")
        .output()
        .expect("POSIX principal cleanup order verification must execute");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
