use std::ffi::{OsStr, OsString};

use hell_ci::process_environment::{ProcessEnvironment, StandardVariable};

fn entry(name: &str, value: &str) -> (OsString, OsString) {
    (OsString::from(name), OsString::from(value))
}

#[test]
fn candidate_tool_authority_requires_one_nonempty_native_path() {
    for (variable, name) in [
        (StandardVariable::Cargo, "CARGO"),
        (StandardVariable::Rustc, "RUSTC"),
    ] {
        for entries in [
            vec![],
            vec![entry(name, "")],
            vec![entry(name, "/first"), entry(name, "/second")],
        ] {
            assert!(
                ProcessEnvironment::from_entries(entries)
                    .required_singleton_value(variable, name)
                    .is_err()
            );
        }
        let expected = OsString::from("/candidate tools/selected executable");
        let snapshot = ProcessEnvironment::from_entries([(OsString::from(name), expected.clone())]);
        assert_eq!(
            snapshot.required_singleton_value(variable, name).unwrap(),
            expected
        );
        let lower = name.to_ascii_lowercase();
        let snapshot =
            ProcessEnvironment::from_entries([entry(name, "/first"), entry(&lower, "/second")]);
        #[cfg(windows)]
        assert!(snapshot.required_singleton_value(variable, name).is_err());
        #[cfg(not(windows))]
        assert_eq!(
            snapshot.required_singleton_value(variable, name).unwrap(),
            OsStr::new("/first")
        );
    }
}

#[cfg(unix)]
#[test]
fn candidate_tool_snapshot_preserves_non_unicode_paths() {
    use std::os::unix::ffi::OsStringExt;
    let expected = OsString::from_vec(b"/candidate/tools/\xff".to_vec());
    let snapshot = ProcessEnvironment::from_entries([
        (OsString::from("CARGO"), expected.clone()),
        (OsString::from("RUSTC"), expected.clone()),
    ]);
    for (variable, name) in [
        (StandardVariable::Cargo, "CARGO"),
        (StandardVariable::Rustc, "RUSTC"),
    ] {
        assert_eq!(
            snapshot.required_singleton_value(variable, name).unwrap(),
            expected
        );
    }
}

#[test]
fn stack_root_snapshot_requires_one_nonempty_case_insensitive_entry() {
    let missing = ProcessEnvironment::from_entries([entry("PATH", "/trusted/bin")]);
    assert!(
        missing
            .required_singleton_value(StandardVariable::StackRoot, "STACK_ROOT")
            .is_err()
    );

    let empty = ProcessEnvironment::from_entries([entry("STACK_ROOT", "")]);
    assert!(
        empty
            .required_singleton_value(StandardVariable::StackRoot, "STACK_ROOT")
            .is_err()
    );

    let duplicate = ProcessEnvironment::from_entries([
        entry("STACK_ROOT", "/trusted/stack"),
        entry("stack_root", "/substituted/stack"),
    ]);
    assert!(
        duplicate
            .required_singleton_value(StandardVariable::StackRoot, "STACK_ROOT")
            .is_err()
    );
}

#[test]
fn retained_snapshot_does_not_follow_later_stack_root_substitution() {
    let mut source = vec![entry("STACK_ROOT", "/trusted/stack")];
    let snapshot = ProcessEnvironment::from_entries(source.clone());
    source[0].1 = OsString::from("/substituted/stack");

    assert_eq!(
        snapshot
            .required_singleton_value(StandardVariable::StackRoot, "STACK_ROOT")
            .expect("retained Stack root is unique"),
        OsStr::new("/trusted/stack")
    );
    assert!(snapshot.release_child_entries().is_empty());
}

#[test]
fn pinned_rustup_authority_uses_exact_singleton_standard_entries() {
    for (variable, name, value) in [
        (
            StandardVariable::RustupHome,
            "RUSTUP_HOME",
            "/protected/rustup",
        ),
        (
            StandardVariable::RustupToolchain,
            "RUSTUP_TOOLCHAIN",
            "nightly-2026-07-31",
        ),
    ] {
        let snapshot = ProcessEnvironment::from_entries([entry(name, value)]);
        assert_eq!(
            snapshot.required_singleton_value(variable, name).unwrap(),
            OsStr::new(value)
        );
        let duplicate =
            ProcessEnvironment::from_entries([entry(name, value), entry(name, "substitution")]);
        assert!(duplicate.required_singleton_value(variable, name).is_err());
    }
}
