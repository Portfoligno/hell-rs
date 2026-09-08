use std::fs;

use hell_memcordon::ReportReservation;

#[test]
fn report_reservation_keeps_provider_destination_absent_and_reads_exact_bytes() {
    let directory = tempfile::tempdir().expect("temporary report authority");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("private report authority");
    }
    let reservation = ReportReservation::create(directory.path()).expect("reserve report name");
    assert!(!reservation.path().exists());
    fs::write(reservation.path(), b"authenticated report bytes\n").expect("provider report");
    assert_eq!(
        reservation.read_bounded().expect("stable bounded report"),
        b"authenticated report bytes\n"
    );
}

#[cfg(unix)]
#[test]
fn report_reservation_rejects_symlink_substitution() {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = tempfile::tempdir().expect("temporary report authority");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("private report authority");
    let reservation = ReportReservation::create(directory.path()).expect("reserve report name");
    let source = directory.path().join("attacker-controlled.json");
    fs::write(&source, b"{}\n").expect("substitution source");
    std::os::unix::fs::symlink(&source, reservation.path()).expect("substitution link");
    assert!(reservation.read_bounded().is_err());
}
