use std::ffi::{OsStr, OsString};

use hell_ci::process_environment::{ProcessEnvironment, StandardVariable};

fn entry(name: &str, value: &str) -> (OsString, OsString) {
    (OsString::from(name), OsString::from(value))
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
