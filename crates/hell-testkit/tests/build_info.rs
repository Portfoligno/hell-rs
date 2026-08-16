use hell_testkit::{
    ExecutableIdentity, ExecutableRole, inspect_executable, parse_candidate_build_info,
    verify_compat_tracing_candidate_identity,
};
use std::fs;
use std::io::Write as _;

fn build_info_lines(compat_tracing: bool) -> Vec<String> {
    vec![
        format!("hell-rs {}", env!("CARGO_PKG_VERSION")),
        format!("language baseline {}", hell_builtins::LANGUAGE_VERSION),
        format!("upstream {}", hell_builtins::UPSTREAM_COMMIT),
        "compatibility evidence schema 2".to_owned(),
        format!("compat tracing enabled {compat_tracing}"),
        format!(
            "compiler policy {:?}",
            hell_compiler::CompilerConfig::upstream()
        ),
        format!(
            "runtime policy {:?}",
            hell_runtime::policy::RuntimePolicy::upstream()
        ),
    ]
}

fn parse(lines: &[String]) -> std::io::Result<hell_testkit::BuildInfo> {
    parse_candidate_build_info(lines.iter().map(String::as_str))
}

fn candidate_identity(build_info: Option<hell_testkit::BuildInfo>) -> ExecutableIdentity {
    let mut identity = inspect_executable(
        std::path::Path::new(env!("CARGO_BIN_EXE_hell-test-helper")),
        ExecutableRole::Oracle,
    )
    .unwrap();
    identity.role = ExecutableRole::Candidate;
    identity.build_info = build_info;
    identity
}

fn lexical_parent_path(path: &std::path::Path) -> std::path::PathBuf {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};

        let mut units = path
            .parent()
            .unwrap()
            .as_os_str()
            .encode_wide()
            .collect::<Vec<_>>();
        units.extend(std::ffi::OsStr::new("\\missing-component\\..\\").encode_wide());
        units.extend(path.file_name().unwrap().encode_wide());
        std::path::PathBuf::from(std::ffi::OsString::from_wide(&units))
    }
    #[cfg(not(windows))]
    {
        path.parent()
            .unwrap()
            .join("missing-component")
            .join("..")
            .join(path.file_name().unwrap())
    }
}

#[test]
fn candidate_build_info_schema_is_closed_and_versioned() {
    let enabled = build_info_lines(true);
    let parsed = parse(&enabled).unwrap();
    assert_eq!(parsed.schema_version, 2);
    assert!(parsed.compat_tracing);
    assert_eq!(parsed.lines.len(), 7);

    let disabled = parse(&build_info_lines(false)).unwrap();
    assert!(!disabled.compat_tracing);

    let mut missing = enabled.clone();
    missing.remove(4);
    assert!(parse(&missing).is_err());

    let mut duplicate = enabled.clone();
    duplicate.insert(5, enabled[4].clone());
    assert!(parse(&duplicate).is_err());

    let mut reordered = enabled.clone();
    reordered.swap(3, 4);
    assert!(parse(&reordered).is_err());

    let mut malformed = enabled.clone();
    malformed[4] = "compat tracing enabled yes".to_owned();
    assert!(parse(&malformed).is_err());

    let mut old_schema = enabled;
    old_schema[3] = "compatibility evidence schema 1".to_owned();
    assert!(parse(&old_schema).is_err());
}

#[test]
fn evidence_candidate_requires_enabled_compat_tracing() {
    let enabled = candidate_identity(Some(parse(&build_info_lines(true)).unwrap()));
    verify_compat_tracing_candidate_identity(&enabled).unwrap();

    let disabled = candidate_identity(Some(parse(&build_info_lines(false)).unwrap()));
    let error = verify_compat_tracing_candidate_identity(&disabled).unwrap_err();
    assert!(error.to_string().contains("compat tracing disabled"));

    let missing = candidate_identity(None);
    assert!(verify_compat_tracing_candidate_identity(&missing).is_err());
}

#[test]
fn evidence_candidate_attestation_binds_canonical_path_and_digest() {
    let original = std::path::Path::new(env!("CARGO_BIN_EXE_hell-test-helper"));
    let temporary =
        std::env::temp_dir().join(format!("hell-build-info-identity-{}", std::process::id()));
    let _ = fs::remove_file(&temporary);
    fs::copy(original, &temporary).unwrap();
    let mut identity = inspect_executable(&temporary, ExecutableRole::Oracle).unwrap();
    identity.role = ExecutableRole::Candidate;
    identity.build_info = Some(parse(&build_info_lines(true)).unwrap());
    verify_compat_tracing_candidate_identity(&identity).unwrap();

    let noncanonical = lexical_parent_path(&identity.path);
    let mut wrong_path = identity.clone();
    wrong_path.path = noncanonical;
    assert!(verify_compat_tracing_candidate_identity(&wrong_path).is_err());

    let near_match_root = identity
        .path
        .parent()
        .unwrap()
        .join(format!("hell-build-info-near-match-{}", std::process::id()));
    let _ = fs::remove_dir_all(&near_match_root);
    fs::create_dir(&near_match_root).unwrap();
    for component in ["...", ".name", "name.."] {
        let directory = near_match_root.join(component);
        fs::create_dir(&directory).unwrap();
        let path = directory.join(identity.path.file_name().unwrap());
        fs::copy(&identity.path, &path).unwrap();
        let mut near_match = inspect_executable(&path, ExecutableRole::Oracle).unwrap();
        near_match.role = ExecutableRole::Candidate;
        near_match.build_info = Some(parse(&build_info_lines(true)).unwrap());
        verify_compat_tracing_candidate_identity(&near_match).unwrap();
        fs::remove_file(path).unwrap();
        fs::remove_dir(directory).unwrap();
    }
    fs::remove_dir(near_match_root).unwrap();

    fs::OpenOptions::new()
        .append(true)
        .open(&identity.path)
        .unwrap()
        .write_all(b"identity substitution")
        .unwrap();
    let error = verify_compat_tracing_candidate_identity(&identity).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("changed after build-info probing")
    );
    fs::remove_file(&identity.path).unwrap();
}
