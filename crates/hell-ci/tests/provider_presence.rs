use std::fs;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use hell_ci::provider_presence::{
    Presence, observe_metadata, observe_path, require_absent, systemd_unit_absent,
    verify_failure_protocol,
};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[test]
fn no_lease_cleanup_preserves_unknown_or_present_footprint_failure() {
    for absence in [
        Ok(()),
        Err("partial package remains".to_owned()),
        Err("access denied".to_owned()),
    ] {
        let receipt = hell_ci::provider_presence::unowned_cleanup_receipt(
            "task-lease".to_owned(),
            "operation".to_owned(),
            hell_memcordon::PlatformId::LinuxX86_64,
            absence.clone(),
        );
        receipt.validate().unwrap();
        assert!(!receipt.attempted);
        assert_eq!(receipt.installed_footprint_absent, absence.is_ok());
        assert_eq!(receipt.failure, absence.err());
        assert_eq!(
            receipt.final_state,
            if receipt.failure.is_none() {
                hell_memcordon::ProviderLifecycleState::Absent
            } else {
                hell_memcordon::ProviderLifecycleState::FailedDirty
            }
        );
    }
}

#[test]
fn native_absence_distinguishes_partial_and_complete_installation() {
    let root = std::env::temp_dir().join(format!(
        "hell-provider-presence-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).unwrap();
    let binary = root.join("agent");
    let lock = root.join("lease");
    assert!(require_absent(&[observe_path(&binary), observe_path(&lock)]).is_ok());
    fs::write(&binary, b"installed\n").unwrap();
    assert!(require_absent(&[observe_path(&binary), observe_path(&lock)]).is_err());
    fs::write(&lock, b"lease\n").unwrap();
    assert!(require_absent(&[observe_path(&binary), observe_path(&lock)]).is_err());
    fs::remove_file(&binary).unwrap();
    // An uninstall leaving only its lease is not absence either.
    assert!(require_absent(&[observe_path(&binary), observe_path(&lock)]).is_err());
    fs::remove_file(&lock).unwrap();
    fs::remove_dir(root).unwrap();
}

#[test]
fn unreadable_and_empty_evidence_never_authorize_installation() {
    let entry = observe_metadata(
        Path::new("protected-authority"),
        Err(io::Error::from(io::ErrorKind::PermissionDenied)),
    );
    assert_eq!(entry.presence, Presence::Unreadable);
    assert!(require_absent(&[entry]).is_err());
    assert!(require_absent(&[]).is_err());
}

#[cfg(unix)]
#[test]
fn dangling_symlink_is_a_preexisting_authority() {
    let path = std::env::temp_dir().join(format!(
        "hell-provider-symlink-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    std::os::unix::fs::symlink("missing-provider-target", &path).unwrap();
    assert_eq!(observe_path(&path).presence, Presence::Present);
    assert!(require_absent(&[observe_path(&path)]).is_err());
    fs::remove_file(path).unwrap();
}

#[test]
fn systemd_absence_requires_complete_unloaded_properties() {
    assert!(
        systemd_unit_absent(
            b"LoadState=not-found\nActiveState=inactive\nFragmentPath=\nUnitFileState=\n"
        )
        .is_ok()
    );
    for properties in [
        &b"LoadState=loaded\nActiveState=inactive\nFragmentPath=/unit\nUnitFileState=disabled\n"[..],
        &b"LoadState=not-found\nActiveState=active\nFragmentPath=\nUnitFileState=\n"[..],
        &b"LoadState=not-found\nActiveState=inactive\n"[..],
        &b"LoadState=not-found\nLoadState=not-found\nActiveState=inactive\nFragmentPath=\nUnitFileState=\n"[..],
    ] {
        assert!(systemd_unit_absent(properties).is_err());
    }
}

#[test]
fn pinned_incomplete_diagnostic_is_only_protocol_evidence() {
    let diagnostic = b"MCSEALED-PACKAGE-VERIFY: installed package is incomplete\n";
    assert!(verify_failure_protocol(true, Some(125), b"", diagnostic, false).is_ok());
    for code in [None, Some(0), Some(1)] {
        assert!(verify_failure_protocol(true, code, b"", diagnostic, false).is_err());
    }
    assert!(verify_failure_protocol(true, Some(125), b"unexpected", diagnostic, false).is_err());
    assert!(verify_failure_protocol(true, Some(125), b"", diagnostic, true).is_err());
    assert!(verify_failure_protocol(true, Some(125), b"", b"not installed\n", false).is_err());
    assert!(verify_failure_protocol(true, Some(125), b"", b"\xff", false).is_err());
    let existing = observe_metadata(
        Path::new("lease"),
        Err(io::Error::from(io::ErrorKind::PermissionDenied)),
    );
    // A protocol-compatible error cannot replace independent native proof.
    assert!(require_absent(&[existing]).is_err());
}
