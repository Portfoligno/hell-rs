use std::ffi::{OsStr, OsString};

use hell_testkit::{
    configure_windows_standard_system_root_value, windows_argv_child_status_diagnostic,
};

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
    let root = std::env::temp_dir().join(format!(
        "hell-windows-argv-prelaunch-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let program = root.join("cargo.exe");
    std::fs::write(&program, b"bound cargo image").unwrap();
    std::fs::write(root.join("zlib1.dll"), b"zlib image").unwrap();
    std::fs::write(root.join("A_RUNTIME.DLL"), b"runtime image").unwrap();
    std::fs::write(root.join("ignored.txt"), b"not a DLL").unwrap();
    let diagnostic = hell_testkit::windows_argv_target_prelaunch_diagnostic(&program);
    assert!(diagnostic.contains("programBytes=17"));
    assert!(diagnostic.contains("programSha256="));
    assert!(diagnostic.contains("dllCount=2"));
    assert!(diagnostic.contains("A_RUNTIME.DLL"));
    assert!(diagnostic.contains("zlib1.dll"));
    assert!(!diagnostic.contains("ignored.txt"));
    std::fs::remove_dir_all(root).unwrap();
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
    let authority = BoundProgramInvocation::new(path.clone(), path.clone()).unwrap();
    let retained_clone = authority.clone();

    assert!(fs::OpenOptions::new().write(true).open(&path).is_err());
    assert!(fs::remove_file(&path).is_err());
    drop(authority);
    assert!(fs::OpenOptions::new().write(true).open(&path).is_err());
    assert!(fs::remove_file(&path).is_err());

    drop(retained_clone);
    fs::write(&path, fs::read(source).unwrap()).unwrap();
    fs::remove_file(path).unwrap();
}
