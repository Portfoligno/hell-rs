use std::ffi::{OsStr, OsString};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use hell_testkit::{
    WINDOWS_PRELAUNCH_DIRECTORY_ENTRY_LIMIT, WINDOWS_PRELAUNCH_DLL_LIMIT,
    WINDOWS_PRELAUNCH_FILE_BYTE_LIMIT, WindowsPrelaunchDiagnosticOutcome,
    WindowsPrelaunchDiagnosticPhase, WindowsPrelaunchDiagnosticReason,
    configure_windows_standard_system_root_value,
    run_supervised_command_with_prelaunch_evidence_until,
    verify_windows_prelaunch_chunk_deadline_for_integration, windows_argv_child_status_diagnostic,
    windows_argv_target_prelaunch_diagnostic_until,
};
#[cfg(windows)]
use hell_testkit::{
    run_supervised_command_with_bound_program_until,
    windows_argv_target_prelaunch_diagnostic_with_program_until,
};

static NEXT_DIAGNOSTIC_ROOT: AtomicU64 = AtomicU64::new(0);

fn diagnostic_root(label: &str) -> PathBuf {
    for _ in 0..64 {
        let sequence = NEXT_DIAGNOSTIC_ROOT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "hell-windows-argv-prelaunch-{}-{label}-{sequence}",
            std::process::id()
        ));
        match std::fs::create_dir(&root) {
            Ok(()) => return root,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("cannot create diagnostic fixture: {error}"),
        }
    }
    panic!("cannot allocate collision-free diagnostic fixture")
}

#[test]
fn windows_system_root_environment_is_an_exact_case_insensitive_singleton() {
    let captured = OsStr::new(r"C:\Windows");
    let mut absent = Vec::new();
    configure_windows_standard_system_root_value(&mut absent, captured, false).unwrap();
    assert!(absent.is_empty());

    configure_windows_standard_system_root_value(&mut absent, captured, true).unwrap();
    assert_eq!(
        absent,
        [(
            OsString::from("SystemRoot"),
            Some(OsString::from(r"C:\Windows")),
        )]
    );

    let mut supplied = vec![(
        OsString::from("SYSTEMROOT"),
        Some(OsString::from(r"C:\Windows")),
    )];
    configure_windows_standard_system_root_value(&mut supplied, captured, true).unwrap();
    assert_eq!(supplied, absent);

    for mut rejected in [
        vec![(OsString::from("SystemRoot"), None)],
        vec![(
            OsString::from("SystemRoot"),
            Some(OsString::from(r"D:\Windows")),
        )],
        vec![
            (
                OsString::from("SystemRoot"),
                Some(OsString::from(r"C:\Windows")),
            ),
            (
                OsString::from("SYSTEMROOT"),
                Some(OsString::from(r"C:\Windows")),
            ),
        ],
    ] {
        assert!(
            configure_windows_standard_system_root_value(&mut rejected, captured, true).is_err()
        );
    }
}

#[test]
fn windows_argv_prelaunch_evidence_reads_exact_program_and_closed_dll_inventory() {
    let root = diagnostic_root("exact");
    let program = root.join("cargo.exe");
    std::fs::write(&program, b"bound cargo image").unwrap();
    std::fs::write(root.join("zlib1.dll"), b"zlib image").unwrap();
    std::fs::write(root.join("A_RUNTIME.DLL"), b"runtime image").unwrap();
    std::fs::write(root.join("ignored.txt"), b"not a DLL").unwrap();
    let deadline = Instant::now().checked_add(Duration::from_secs(5)).unwrap();
    let receipt = windows_argv_target_prelaunch_diagnostic_until(&program, deadline);
    assert_eq!(receipt.outcome, WindowsPrelaunchDiagnosticOutcome::Complete);
    let diagnostic = receipt.rendered();
    assert!(diagnostic.contains("programBytes=17"));
    assert!(diagnostic.contains("programSha256="));
    assert!(diagnostic.contains("dllCount=2"));
    assert!(diagnostic.contains("A_RUNTIME.DLL"));
    assert!(diagnostic.contains("zlib1.dll"));
    assert!(!diagnostic.contains("ignored.txt"));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn windows_argv_prelaunch_expiry_returns_before_inventory_or_hashing() {
    let root = diagnostic_root("expired");
    let program = root.join("must-not-open.exe");
    std::fs::write(&program, b"sentinel").unwrap();
    let receipt = windows_argv_target_prelaunch_diagnostic_until(&program, Instant::now());
    assert_eq!(
        receipt.outcome,
        WindowsPrelaunchDiagnosticOutcome::Unavailable {
            phase: WindowsPrelaunchDiagnosticPhase::ProgramMetadata,
            reason: WindowsPrelaunchDiagnosticReason::Deadline,
        }
    );
    assert_eq!(receipt.directory_entries, 0);
    assert_eq!(receipt.dll_count, 0);
    assert_eq!(receipt.hashed_bytes, 0);
    assert!(!receipt.program_hashed);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn windows_argv_prelaunch_chunk_deadline_has_no_late_read() {
    verify_windows_prelaunch_chunk_deadline_for_integration().unwrap();
}

#[test]
fn unavailable_prelaunch_evidence_does_not_gate_semantic_launch() {
    let helper = std::path::Path::new(env!("CARGO_BIN_EXE_hell-test-helper"));
    let diagnostic = windows_argv_target_prelaunch_diagnostic_until(helper, Instant::now());
    assert!(matches!(
        diagnostic.outcome,
        WindowsPrelaunchDiagnosticOutcome::Unavailable {
            reason: WindowsPrelaunchDiagnosticReason::Deadline,
            ..
        }
    ));
    let mut command = Command::new(helper);
    command.arg("--version");
    let execution_deadline = Instant::now().checked_add(Duration::from_secs(5)).unwrap();
    let completion_deadline = execution_deadline
        .checked_add(Duration::from_secs(5))
        .unwrap();
    let output = run_supervised_command_with_prelaunch_evidence_until(
        &mut command,
        &[],
        execution_deadline,
        completion_deadline,
        diagnostic.rendered(),
    )
    .unwrap();
    assert!(output.status.success());
    assert!(!output.timed_out);
    assert_eq!(
        output.prelaunch_evidence.as_deref(),
        Some(diagnostic.rendered())
    );
    let phases = output
        .phase_timings
        .iter()
        .map(|phase| phase.name)
        .collect::<Vec<_>>();
    let attached = phases
        .iter()
        .position(|phase| *phase == "prelaunch-evidence-attached")
        .unwrap();
    let spawned = phases
        .iter()
        .position(|phase| *phase == "child-spawned")
        .unwrap();
    assert!(attached < spawned);
}

#[test]
fn expired_semantic_deadline_never_launches_after_diagnostic_completion() {
    let root = diagnostic_root("no-late-launch");
    let mut executable_name = OsString::from("must-not-run-prelaunch");
    executable_name.push(std::env::consts::EXE_SUFFIX);
    let program = root.join(executable_name);
    std::fs::copy(env!("CARGO_BIN_EXE_hell-test-helper"), &program).unwrap();
    let diagnostic = windows_argv_target_prelaunch_diagnostic_until(&program, Instant::now());
    let mut command = Command::new(&program);
    command.arg("--version");
    let execution_deadline = Instant::now();
    let completion_deadline = execution_deadline
        .checked_add(Duration::from_secs(5))
        .unwrap();
    let error = run_supervised_command_with_prelaunch_evidence_until(
        &mut command,
        &[],
        execution_deadline,
        completion_deadline,
        diagnostic.rendered(),
    )
    .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    let mut marker = program.into_os_string();
    marker.push(".invoked");
    assert!(!PathBuf::from(marker).exists());
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(windows)]
#[test]
fn launch_failure_remains_primary_when_diagnostic_inventory_is_unavailable() {
    let root = diagnostic_root("primary-causality");
    let program = root.join("invalid.exe");
    std::fs::write(&program, b"not a Windows executable").unwrap();
    let diagnostic = windows_argv_target_prelaunch_diagnostic_until(&program, Instant::now());
    let direct = Command::new(&program)
        .arg("--version")
        .output()
        .unwrap_err()
        .to_string();
    let mut command = Command::new(&program);
    command.arg("--version");
    let execution_deadline = Instant::now().checked_add(Duration::from_secs(5)).unwrap();
    let completion_deadline = execution_deadline
        .checked_add(Duration::from_secs(5))
        .unwrap();
    let error = run_supervised_command_with_prelaunch_evidence_until(
        &mut command,
        &[],
        execution_deadline,
        completion_deadline,
        diagnostic.rendered(),
    )
    .unwrap_err()
    .to_string();
    assert!(error.starts_with(&direct));
    assert!(error.contains("prelaunchEvidence="));
    assert!(error.contains("Deadline"));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn windows_argv_prelaunch_enforces_entry_and_file_bounds_incrementally() {
    let entries_root = diagnostic_root("entries");
    let program = entries_root.join("cargo.exe");
    std::fs::write(&program, b"program").unwrap();
    for index in 0..WINDOWS_PRELAUNCH_DIRECTORY_ENTRY_LIMIT {
        std::fs::write(
            entries_root.join(format!("ignored-{index}.txt")),
            b"ignored",
        )
        .unwrap();
    }
    let deadline = Instant::now().checked_add(Duration::from_secs(30)).unwrap();
    let entries = windows_argv_target_prelaunch_diagnostic_until(&program, deadline);
    assert_eq!(
        entries.outcome,
        WindowsPrelaunchDiagnosticOutcome::Unavailable {
            phase: WindowsPrelaunchDiagnosticPhase::DirectoryEnumeration,
            reason: WindowsPrelaunchDiagnosticReason::DirectoryEntryLimit,
        }
    );
    assert_eq!(
        entries.directory_entries,
        WINDOWS_PRELAUNCH_DIRECTORY_ENTRY_LIMIT
    );
    assert_eq!(entries.hashed_bytes, 0);
    std::fs::remove_dir_all(entries_root).unwrap();

    let bytes_root = diagnostic_root("bytes");
    let oversized = bytes_root.join("cargo.exe");
    let file = std::fs::File::create(&oversized).unwrap();
    file.set_len(WINDOWS_PRELAUNCH_FILE_BYTE_LIMIT + 1).unwrap();
    let deadline = Instant::now().checked_add(Duration::from_secs(5)).unwrap();
    let bytes = windows_argv_target_prelaunch_diagnostic_until(&oversized, deadline);
    assert_eq!(
        bytes.outcome,
        WindowsPrelaunchDiagnosticOutcome::Unavailable {
            phase: WindowsPrelaunchDiagnosticPhase::ProgramMetadata,
            reason: WindowsPrelaunchDiagnosticReason::FileByteLimit,
        }
    );
    assert_eq!(bytes.hashed_bytes, 0);
    std::fs::remove_dir_all(bytes_root).unwrap();

    let dll_root = diagnostic_root("dlls");
    let program = dll_root.join("cargo.exe");
    std::fs::write(&program, b"program").unwrap();
    for index in 0..=WINDOWS_PRELAUNCH_DLL_LIMIT {
        std::fs::write(dll_root.join(format!("runtime-{index}.dll")), b"runtime").unwrap();
    }
    let deadline = Instant::now().checked_add(Duration::from_secs(5)).unwrap();
    let dlls = windows_argv_target_prelaunch_diagnostic_until(&program, deadline);
    assert_eq!(
        dlls.outcome,
        WindowsPrelaunchDiagnosticOutcome::Unavailable {
            phase: WindowsPrelaunchDiagnosticPhase::DirectoryEnumeration,
            reason: WindowsPrelaunchDiagnosticReason::DllEntryLimit,
        }
    );
    assert_eq!(dlls.dll_count, WINDOWS_PRELAUNCH_DLL_LIMIT);
    assert_eq!(dlls.hashed_bytes, 0);
    std::fs::remove_dir_all(dll_root).unwrap();
}

#[test]
fn windows_argv_child_status_retains_unrepresentable_raw_evidence() {
    assert_eq!(windows_argv_child_status_diagnostic(Some(0)), None);
    assert_eq!(windows_argv_child_status_diagnostic(Some(255)), None);
    assert_eq!(
        windows_argv_child_status_diagnostic(Some(-1_073_741_502)),
        Some("Windows argv target exited with raw status -1073741502 (0xc0000142)".to_owned())
    );
    assert_eq!(
        windows_argv_child_status_diagnostic(None),
        Some("Windows argv target terminated without an exit code".to_owned())
    );
}

#[cfg(windows)]
#[test]
fn bound_program_retains_a_read_only_windows_handle_for_every_clone() {
    use hell_testkit::BoundProgramInvocation;
    use std::fs;
    use std::path::Path;

    let source = Path::new(env!("CARGO_BIN_EXE_hell-test-helper"));
    let path = std::env::temp_dir().join(format!(
        "hell-bound-program-windows-{}-helper.exe",
        std::process::id()
    ));
    let _ = fs::remove_file(&path);
    fs::copy(source, &path).unwrap();
    let path = fs::canonicalize(path).unwrap();
    let acquisition_deadline = Instant::now().checked_add(Duration::from_secs(5)).unwrap();
    let authority =
        BoundProgramInvocation::new_until(path.clone(), path.clone(), acquisition_deadline)
            .unwrap();
    let retained_clone = authority.clone();

    assert_eq!(authority.windows_hash_passes_for_integration(), 1);
    authority.windows_revalidate_for_integration().unwrap();
    authority.windows_revalidate_for_integration().unwrap();
    assert_eq!(authority.windows_hash_passes_for_integration(), 1);
    let diagnostic_deadline = Instant::now().checked_add(Duration::from_secs(1)).unwrap();
    let diagnostic = windows_argv_target_prelaunch_diagnostic_with_program_until(
        &path,
        Some(&authority),
        diagnostic_deadline,
    );
    assert_eq!(
        diagnostic.outcome,
        WindowsPrelaunchDiagnosticOutcome::Complete
    );
    assert!(diagnostic.program_hashed);
    assert!(diagnostic.program_reused);
    assert_eq!(diagnostic.hashed_bytes, 0);
    assert!(
        diagnostic
            .rendered()
            .contains("programSource=retained-authority")
    );

    let mut command = Command::new(&path);
    command.arg("--version");
    let execution_deadline = Instant::now().checked_add(Duration::from_secs(2)).unwrap();
    let completion_deadline = execution_deadline
        .checked_add(Duration::from_secs(3))
        .unwrap();
    let output = run_supervised_command_with_bound_program_until(
        &mut command,
        &[],
        execution_deadline,
        completion_deadline,
        &authority,
        None,
    )
    .unwrap();
    assert!(output.status.success());
    assert_eq!(authority.windows_hash_passes_for_integration(), 1);

    let expired =
        BoundProgramInvocation::new_until(path.clone(), path.clone(), Instant::now()).unwrap_err();
    assert_eq!(expired.kind(), std::io::ErrorKind::TimedOut);

    assert!(fs::OpenOptions::new().write(true).open(&path).is_err());
    assert!(fs::remove_file(&path).is_err());
    let replacement = path.with_extension("replacement.exe");
    fs::copy(source, &replacement).unwrap();
    assert!(fs::rename(&replacement, &path).is_err());
    assert!(replacement.exists());
    drop(authority);
    assert!(fs::OpenOptions::new().write(true).open(&path).is_err());
    assert!(fs::remove_file(&path).is_err());

    drop(retained_clone);
    fs::remove_file(replacement).unwrap();
    fs::write(&path, fs::read(source).unwrap()).unwrap();
    fs::remove_file(path).unwrap();
}
