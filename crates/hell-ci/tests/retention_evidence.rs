#![cfg(unix)]

use hell_ci::retention_evidence::{Attempt, CapturedAdapter, retain_failure, retain_result};
use std::fs;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static NEXT: AtomicU64 = AtomicU64::new(0);

fn entry_expectation() -> hell_ci::retention_evidence::entry::Expected {
    hell_ci::retention_evidence::entry::Expected {
        device: 7,
        candidate_uid: 10,
        trusted_uid: 20,
        candidate_gid: 30,
        trusted_gid: 40,
    }
}

#[test]
fn retention_entry_reasons_cover_every_refusal_predicate() {
    use hell_ci::retention_evidence::entry::{EntryType, Observed, rejection};
    use std::path::Path;
    let valid = Observed {
        device: 7,
        uid: 10,
        gid: 30,
        kind: EntryType::Regular,
        nlink: 1,
    };
    let mut cases = vec![
        (Observed { device: 8, ..valid }, vec!["device-mismatch"]),
        (Observed { uid: 11, ..valid }, vec!["uid-not-allowed"]),
        (Observed { gid: 31, ..valid }, vec!["gid-not-allowed"]),
        (
            Observed { nlink: 0, ..valid },
            vec!["regular-file-link-count"],
        ),
        (
            Observed {
                device: 8,
                uid: 11,
                gid: 31,
                nlink: 0,
                ..valid
            },
            vec![
                "device-mismatch",
                "uid-not-allowed",
                "gid-not-allowed",
                "regular-file-link-count",
            ],
        ),
    ];
    for (kind, reason) in [
        (EntryType::Symlink, "symlink"),
        (EntryType::BlockDevice, "block-device"),
        (EntryType::CharacterDevice, "character-device"),
        (EntryType::Fifo, "fifo"),
        (EntryType::Socket, "socket"),
        (EntryType::Other, "unsupported-type"),
    ] {
        cases.push((
            Observed { kind, ..valid },
            vec![reason, "not-directory-or-regular-file"],
        ));
    }
    for (observed, reasons) in cases {
        let value: serde_json::Value = serde_json::from_str(&rejection(
            Path::new("/private/root"),
            Path::new("/private/root/entry"),
            observed,
            entry_expectation(),
        ))
        .unwrap();
        assert_eq!(value["reasons"], serde_json::json!(reasons));
        assert_eq!(
            value["expected"]["regular_file_nlink"],
            "positive-and-closed-in-tree"
        );
        assert_eq!(value["observed"]["nlink"], observed.nlink);
    }
}

#[test]
fn retention_entry_native_paths_are_bounded_and_do_not_disclose_ancestors() {
    use hell_ci::retention_evidence::entry::{EntryType, Observed, rejection};
    use std::os::unix::ffi::OsStringExt as _;
    let root = PathBuf::from("/unrelated-private-ancestor/work");
    let observed = Observed {
        device: 7,
        uid: 10,
        gid: 30,
        kind: EntryType::Regular,
        nlink: 2,
    };
    for bytes in [vec![255, b'\n', b'x'], vec![255; 4096]] {
        let path = root.join(std::ffi::OsString::from_vec(bytes.clone()));
        let diagnostic = rejection(&root, &path, observed, entry_expectation());
        assert!(!diagnostic.contains("unrelated-private-ancestor"));
        assert!(diagnostic.len() < 4096);
        let value: serde_json::Value = serde_json::from_str(&diagnostic).unwrap();
        assert_eq!(
            value["path"]["bytes"],
            serde_json::json!(&bytes[..bytes.len().min(256)])
        );
        assert_eq!(value["path"]["total_bytes"], bytes.len());
        assert_eq!(value["path"]["truncated"], bytes.len() > 256);
    }
    let outside = rejection(
        &root,
        std::path::Path::new("/secret/outside"),
        observed,
        entry_expectation(),
    );
    assert!(!outside.contains("secret"));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&outside).unwrap()["path"]["root_relative"],
        false
    );
}

#[test]
fn retention_entry_metadata_does_not_follow_links_or_read_contents() {
    use hell_ci::retention_evidence::entry::{Expected, Observed, rejection};
    use std::os::unix::fs::{MetadataExt as _, symlink};
    let fixture = Fixture::new();
    let file = fixture.0.join("file");
    fs::write(&file, b"sensitive contents must not enter diagnostics").unwrap();
    fs::hard_link(&file, fixture.0.join("hardlink")).unwrap();
    let link = fixture.0.join("symlink");
    symlink(&file, &link).unwrap();
    for (path, reason) in [(&file, "hard-links-not-closed-in-tree"), (&link, "symlink")] {
        let metadata = fs::symlink_metadata(path).unwrap();
        let expected = Expected {
            device: metadata.dev(),
            candidate_uid: metadata.uid(),
            trusted_uid: metadata.uid(),
            candidate_gid: metadata.gid(),
            trusted_gid: metadata.gid(),
        };
        let diagnostic = if metadata.is_file() {
            hell_ci::retention_evidence::entry::closure_rejection(
                &fixture.0,
                path,
                Observed::from(&metadata),
                expected,
                metadata.ino(),
                1,
            )
        } else {
            rejection(&fixture.0, path, Observed::from(&metadata), expected)
        };
        assert!(!diagnostic.contains("sensitive contents"));
        let value: serde_json::Value = serde_json::from_str(&diagnostic).unwrap();
        assert!(
            value["reasons"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!(reason))
        );
    }
}

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "hell-retention-evidence-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        Self(root.canonicalize().unwrap())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn captured<'a>(
    code: i32,
    timed_out: bool,
    stdout: &'a [u8],
    stderr: &'a [u8],
) -> CapturedAdapter<'a> {
    CapturedAdapter {
        status: std::process::ExitStatus::from_raw(code << 8),
        duration: Duration::from_millis(45),
        timed_out,
        stdout,
        stderr,
        stdout_bytes: stdout.len() as u64,
        stderr_bytes: stderr.len() as u64,
        stdout_sha256: hell_testkit::sha256_bytes(stdout),
        stderr_sha256: hell_testkit::sha256_bytes(stderr),
        stdout_truncated: false,
        stderr_truncated: false,
    }
}

#[test]
fn retention_exit_timeout_and_post_completion_deadline_are_distinct() {
    for (code, timed_out, expired, classification) in [
        (1, false, false, "unsuccessful-exit"),
        (1, true, false, "capture-timeout"),
        (0, false, true, "deadline-expired"),
        (0, false, false, "completed"),
    ] {
        let fixture = Fixture::new();
        let result = retain_result(
            &fixture.0,
            &captured(code, timed_out, b"stdout", b"stderr"),
            expired,
        );
        assert_eq!(result.is_ok(), classification == "completed");
        let receipt: serde_json::Value =
            serde_json::from_slice(&fs::read(fixture.0.join("result.json")).unwrap()).unwrap();
        assert_eq!(receipt["classification"], classification);
        assert_eq!(receipt["exit_code"], code);
        assert_eq!(receipt["timed_out"], timed_out);
        assert_eq!(receipt["deadline_expired"], expired);
        assert_eq!(receipt["duration_millis"], 45);
    }
}

#[test]
fn retention_keeps_original_complete_streams_and_full_capture_metadata() {
    let fixture = Fixture::new();
    let mut diagnostic = vec![b'x'; 100_000];
    diagnostic.extend_from_slice(b"MIDDLE-NATIVE-REJECTION\n");
    diagnostic.extend_from_slice(&vec![b'y'; 100_000]);
    let mut output = captured(1, false, b"\xffnative stdout\n", &diagnostic);
    output.stdout_truncated = true;
    output.stdout_bytes += 20;
    output.stdout_sha256 = hell_testkit::sha256_bytes(b"full original stream identity");
    assert!(retain_result(&fixture.0, &output, false).is_err());
    assert_eq!(fs::read(fixture.0.join("stderr")).unwrap(), diagnostic);
    assert_eq!(fs::read(fixture.0.join("stdout")).unwrap(), output.stdout);
    let receipt: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture.0.join("result.json")).unwrap()).unwrap();
    assert_eq!(receipt["stdout_bytes"], output.stdout_bytes);
    assert_eq!(receipt["stdout_retained_bytes"], output.stdout.len());
    assert_eq!(receipt["stdout_sha256"], output.stdout_sha256.hex());
    assert_eq!(receipt["stdout_truncated"], true);
}

#[test]
fn persistence_failure_keeps_primary_and_still_attempts_other_diagnostics() {
    let fixture = Fixture::new();
    fs::create_dir(fixture.0.join("stdout")).unwrap();
    let error = retain_result(
        &fixture.0,
        &captured(7, false, b"out", b"native refusal"),
        false,
    )
    .unwrap_err();
    assert!(error.starts_with("Linux MemCordon retention adapter exited unsuccessfully"));
    assert!(error.contains("additionally, retention diagnostic persistence failed"));
    assert_eq!(
        fs::read(fixture.0.join("stderr")).unwrap(),
        b"native refusal"
    );
    assert!(fixture.0.join("result.json").is_file());
    fs::write(fixture.0.join("blocked"), b"not a directory").unwrap();
    let error = retain_failure(
        &fixture.0.join("blocked").join("not-created"),
        "original setup rejection".to_owned(),
        Duration::ZERO,
        false,
        None,
    );
    assert!(error.starts_with("original setup rejection"));
    assert!(error.contains("additionally, retention diagnostic persistence failed"));
}

#[test]
fn cleanup_retry_cannot_overwrite_primary_evidence_or_primary_error_order() {
    let fixture = Fixture::new();
    let primary = Attempt::Primary.directory(&fixture.0);
    let retry = Attempt::CleanupRetry.directory(&fixture.0);
    let first = retain_result(
        &primary,
        &captured(3, false, b"", b"first rejection"),
        false,
    )
    .unwrap_err();
    let second =
        retain_result(&retry, &captured(0, true, b"", b"retry timeout"), true).unwrap_err();
    assert_eq!(
        fs::read(primary.join("stderr")).unwrap(),
        b"first rejection"
    );
    assert_eq!(fs::read(retry.join("stderr")).unwrap(), b"retry timeout");
    let error = hell_ci::compose_authority_result(
        "Linux",
        Err("candidate primary".to_owned()),
        Err(first),
        Err(second),
    )
    .unwrap_err();
    assert!(
        error.starts_with(
            "candidate primary; additionally, Linux candidate output retention failed:"
        )
    );
    assert!(
        error.find("exited unsuccessfully").unwrap() < error.find("capture timed out").unwrap()
    );
}

#[test]
fn early_failure_and_supervision_timeout_keep_available_error_metadata() {
    for timed_out in [None, Some(false), Some(true)] {
        let fixture = Fixture::new();
        let primary = "original retention failure";
        assert_eq!(
            retain_failure(
                &fixture.0,
                primary.to_owned(),
                Duration::from_millis(7),
                true,
                timed_out
            ),
            primary
        );
        let receipt: serde_json::Value =
            serde_json::from_slice(&fs::read(fixture.0.join("failure.json")).unwrap()).unwrap();
        assert_eq!(receipt["error"], primary);
        assert_eq!(
            receipt["timed_out"],
            serde_json::to_value(timed_out).unwrap()
        );
        assert_eq!(receipt["deadline_expired"], true);
        assert!(!fixture.0.join("stdout").exists());
    }
}
