#![cfg(windows)]

use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::time::{Duration, Instant};

use hell_testkit::{
    BoundProgramInvocation, WindowsToolchainAuthority, WindowsToolchainExecutableAuthority,
    configure_windows_restricted_child_environment, configure_windows_restricted_child_path,
};

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "hell-windows-toolchain-authority-{}-{name}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        Self { root }
    }

    fn tool_file(&self, directory: &str, name: &str, bytes: &[u8]) -> PathBuf {
        let directory = self.root.join(directory);
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join(name);
        fs::write(&path, bytes).unwrap();
        fs::canonicalize(path).unwrap()
    }

    fn trusted_path(&self) -> (OsString, Vec<PathBuf>, OsString) {
        let first = self
            .tool_file("trusted-first", "cargo.exe", b"untrusted cargo")
            .parent()
            .unwrap()
            .to_path_buf();
        self.tool_file("trusted-first", "rustc.exe", b"untrusted rustc");
        let second = self
            .tool_file("trusted-second", "cargo.exe", b"later cargo")
            .parent()
            .unwrap()
            .to_path_buf();
        self.tool_file("trusted-second", "rustc.exe", b"later rustc");
        let system32 = self
            .tool_file("Windows/System32", "kernel32.dll", b"system kernel")
            .parent()
            .unwrap()
            .to_path_buf();
        let system_root = system32.parent().unwrap().to_path_buf();
        let entries = vec![first.clone(), second, first, system32, system_root.clone()];
        (
            std::env::join_paths(&entries).unwrap(),
            entries,
            system_root.into_os_string(),
        )
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

fn mapping(proxy: &Path, source: &Path, staged: &Path) -> WindowsToolchainExecutableAuthority {
    WindowsToolchainExecutableAuthority::rustup_proxy(
        proxy.to_path_buf(),
        proxy.to_path_buf(),
        source.to_path_buf(),
        staged.to_path_buf(),
    )
}

fn inventory(root: &Path) -> (PathBuf, Vec<PathBuf>, Vec<PathBuf>) {
    let root = fs::canonicalize(root).unwrap();
    let mut files = Vec::new();
    let mut directories = vec![root.clone()];
    let mut pending = vec![root.clone()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory).unwrap() {
            let path = fs::canonicalize(entry.unwrap().path()).unwrap();
            if path.is_dir() {
                directories.push(path.clone());
                pending.push(path);
            } else {
                files.push(path);
            }
        }
    }
    (root, files, directories)
}

fn promoted_inventory(files: &[PathBuf], deadline: Instant) -> Vec<BoundProgramInvocation> {
    files
        .iter()
        .map(|path| {
            BoundProgramInvocation::new_until(path.clone(), path.clone(), deadline).unwrap()
        })
        .collect()
}

#[test]
fn promoted_staged_inventory_is_not_hashed_again_and_expiry_does_no_late_work() {
    let fixture = Fixture::new("promoted");
    let cargo_proxy = fixture.tool_file("proxy-cargo", "cargo.exe", b"proxy");
    let rustc_proxy = fixture.tool_file("proxy-rustc", "rustc.exe", b"proxy");
    let source_cargo = fixture.tool_file("source-cargo", "cargo.exe", b"cargo");
    let staged_cargo = fixture.tool_file("stage/bin", "cargo.exe", b"cargo");
    let source_rustc = fixture.tool_file("source-rustc", "rustc.exe", b"rustc");
    let staged_rustc = fixture.tool_file("stage/bin", "rustc.exe", b"rustc");
    let staged_lld = fixture.tool_file(
        "stage/lib/rustlib/x86_64-pc-windows-msvc/bin",
        "rust-lld.exe",
        b"lld",
    );
    let (trusted_path, _, system_root) = fixture.trusted_path();
    let (inventory_root, inventory_files, inventory_directories) =
        inventory(&fixture.root.join("stage"));
    let deadline = Instant::now().checked_add(Duration::from_secs(5)).unwrap();
    let promoted = promoted_inventory(&inventory_files, deadline);
    let promoted_for_nonmember = promoted.clone();
    let authority = WindowsToolchainAuthority::new_from_promoted_inventory_until(
        mapping(&cargo_proxy, &source_cargo, &staged_cargo),
        mapping(&rustc_proxy, &source_rustc, &staged_rustc),
        inventory_root.clone(),
        promoted,
        inventory_directories.clone(),
        trusted_path.clone(),
        system_root.clone(),
        deadline,
        deadline,
    )
    .unwrap();
    assert_eq!(
        authority.windows_inventory_full_hash_passes_for_integration(),
        0
    );
    assert_eq!(
        authority
            .mapped_program(OsStr::new("cargo"), &cargo_proxy)
            .unwrap(),
        Some(staged_cargo.clone())
    );
    assert!(fs::write(&staged_lld, b"bad").is_err());
    let extra = inventory_root.join("extra.dll");
    fs::write(&extra, b"extra").unwrap();
    assert!(authority.revalidate().is_err());
    fs::remove_file(extra).unwrap();
    drop(authority);

    let nonmember = inventory_root.join("not-a-member.exe");
    let invalid_mapping = WindowsToolchainAuthority::new_from_promoted_inventory_until(
        mapping(&cargo_proxy, &source_cargo, &nonmember),
        mapping(&rustc_proxy, &source_rustc, &staged_rustc),
        inventory_root,
        promoted_for_nonmember,
        inventory_directories.clone(),
        trusted_path.clone(),
        system_root.clone(),
        deadline,
        deadline,
    )
    .unwrap_err();
    assert!(
        invalid_mapping
            .to_string()
            .contains("operation=bind-staged-cargo")
    );
    assert!(!nonmember.exists());

    let missing = fixture.root.join("expired-must-not-open");
    let expired_deadline = Instant::now();
    let expired = WindowsToolchainAuthority::new_from_promoted_inventory_until(
        mapping(&missing, &missing, &missing),
        mapping(&missing, &missing, &missing),
        missing.clone(),
        Vec::new(),
        inventory_directories,
        trusted_path,
        system_root,
        expired_deadline,
        expired_deadline,
    )
    .unwrap_err();
    assert_eq!(expired.kind(), std::io::ErrorKind::TimedOut);
    assert!(!missing.exists());
}

const MALFORMED_SYSTEM_ROOT_PROBE: &str = "__hell_malformed_system_root_probe";
const MALFORMED_SYSTEM_ROOT_CASES: [&str; 4] =
    ["removed", "forged", "empty", "duplicate-case-insensitive"];

fn malformed_system_root_probe_argument() -> Option<String> {
    let arguments = std::env::args_os().collect::<Vec<_>>();
    arguments.windows(4).find_map(|window| {
        (window[0] == OsStr::new("--skip")
            && window[1] == OsStr::new(MALFORMED_SYSTEM_ROOT_PROBE)
            && window[2] == OsStr::new("--skip"))
        .then(|| window[3].to_string_lossy().into_owned())
    })
}

fn malformed_system_root_authority(name: &str) -> (Fixture, WindowsToolchainAuthority, OsString) {
    let fixture = Fixture::new(name);
    let cargo_proxy = fixture.tool_file("proxy-cargo", "cargo.exe", b"proxy");
    let rustc_proxy = fixture.tool_file("proxy-rustc", "rustc.exe", b"proxy");
    let source_cargo = fixture.tool_file("source-cargo", "cargo.exe", b"cargo");
    let staged_cargo = fixture.tool_file("stage/bin", "cargo.exe", b"cargo");
    let source_rustc = fixture.tool_file("source-rustc", "rustc.exe", b"rustc");
    let staged_rustc = fixture.tool_file("stage/bin", "rustc.exe", b"rustc");
    let (trusted_path, _, system_root) = fixture.trusted_path();
    let (inventory_root, inventory_files, inventory_directories) =
        inventory(&fixture.root.join("stage"));
    let authority = WindowsToolchainAuthority::new(
        mapping(&cargo_proxy, &source_cargo, &staged_cargo),
        mapping(&rustc_proxy, &source_rustc, &staged_rustc),
        inventory_root,
        inventory_files,
        inventory_directories,
        trusted_path,
        system_root.clone(),
    )
    .unwrap();
    (fixture, authority, system_root)
}

fn run_malformed_system_root_probe(case: &str) -> ExitStatus {
    Command::new(std::env::current_exe().expect("Windows toolchain test executable"))
        .arg("malformed_system_root_rejection_is_process_isolated")
        .arg("--exact")
        .args(["--skip", MALFORMED_SYSTEM_ROOT_PROBE, "--skip", case])
        .status()
        .expect("malformed SystemRoot subprocess probe runs")
}

#[test]
fn malformed_system_root_rejection_is_process_isolated() {
    if let Some(case) = malformed_system_root_probe_argument() {
        let (_fixture, authority, system_root) = malformed_system_root_authority(&case);
        let (mut environment, expected_message) = match case.as_str() {
            "removed" => (
                vec![(OsString::from("SystemRoot"), None)],
                "Windows release child removed its trusted SystemRoot",
            ),
            "forged" => (
                vec![(
                    OsString::from("SystemRoot"),
                    Some(OsString::from(r"D:\ForgedWindows")),
                )],
                "Windows release child SystemRoot differs from its trusted parent capture",
            ),
            "empty" => (
                vec![(OsString::from("SystemRoot"), Some(OsString::new()))],
                "Windows release child SystemRoot differs from its trusted parent capture",
            ),
            "duplicate-case-insensitive" => (
                vec![
                    (OsString::from("SystemRoot"), Some(system_root.clone())),
                    (OsString::from("SYSTEMROOT"), Some(system_root)),
                ],
                "Windows release child has duplicate SystemRoot entries",
            ),
            unknown => panic!("unknown malformed SystemRoot probe {unknown:?}"),
        };
        let error =
            configure_windows_restricted_child_environment(&authority, &mut environment, false)
                .expect_err("malformed SystemRoot must be rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(error.to_string(), expected_message);
        return;
    }

    for case in MALFORMED_SYSTEM_ROOT_CASES {
        let status = run_malformed_system_root_probe(case);
        assert!(
            status.success(),
            "SystemRoot probe {case:?} exited {status}"
        );
    }
}

#[test]
fn exact_staged_toolchain_binds_source_bytes_and_blocks_substitution() {
    let fixture = Fixture::new("exact");
    let cargo_proxy = fixture.tool_file("proxy-cargo", "cargo.exe", b"proxy");
    let rustc_proxy = fixture.tool_file("proxy-rustc", "rustc.exe", b"proxy");
    let source_cargo = fixture.tool_file("source-cargo", "cargo.exe", b"cargo");
    let staged_cargo = fixture.tool_file("stage/bin", "cargo.exe", b"cargo");
    let source_rustc = fixture.tool_file("source-rustc", "rustc.exe", b"rustc");
    let staged_rustc = fixture.tool_file("stage/bin", "rustc.exe", b"rustc");
    let impostor_cargo = fixture.tool_file("impostor", "cargo.exe", b"proxy");
    let (trusted_path, trusted_entries, system_root) = fixture.trusted_path();
    let (inventory_root, inventory_files, inventory_directories) =
        inventory(&fixture.root.join("stage"));
    let authority = WindowsToolchainAuthority::new(
        mapping(&cargo_proxy, &source_cargo, &staged_cargo),
        mapping(&rustc_proxy, &source_rustc, &staged_rustc),
        inventory_root,
        inventory_files,
        inventory_directories,
        trusted_path.clone(),
        system_root.clone(),
    )
    .unwrap();

    let restricted_path = authority.restricted_child_path(&trusted_path).unwrap();
    assert_eq!(
        std::env::split_paths(&restricted_path).collect::<Vec<_>>(),
        std::iter::once(staged_rustc.parent().unwrap().to_path_buf())
            .chain(trusted_entries.iter().cloned())
            .collect::<Vec<_>>()
    );
    let mut inherited_for_mapped_tool = Vec::new();
    configure_windows_restricted_child_environment(
        &authority,
        &mut inherited_for_mapped_tool,
        true,
    )
    .unwrap();
    assert_eq!(
        inherited_for_mapped_tool,
        [
            (OsString::from("PATH"), Some(restricted_path.clone())),
            (OsString::from("SystemRoot"), Some(system_root.clone())),
        ]
    );
    let mut explicitly_removed = vec![(OsString::from("PATH"), None)];
    assert!(
        configure_windows_restricted_child_path(&authority, &mut explicitly_removed, true).is_err()
    );
    let mut disagreed = vec![(
        OsString::from("Path"),
        Some(OsString::from(r"C:\forged-path")),
    )];
    assert!(configure_windows_restricted_child_path(&authority, &mut disagreed, true).is_err());
    let mut duplicated = vec![
        (OsString::from("PATH"), Some(trusted_path.clone())),
        (OsString::from("Path"), Some(trusted_path.clone())),
    ];
    assert!(configure_windows_restricted_child_path(&authority, &mut duplicated, true).is_err());
    for mut rejected in [
        vec![
            (OsString::from("PATH"), Some(trusted_path.clone())),
            (OsString::from("SystemRoot"), None),
        ],
        vec![
            (OsString::from("PATH"), Some(trusted_path.clone())),
            (
                OsString::from("SystemRoot"),
                Some(OsString::from(r"C:\forged-windows")),
            ),
        ],
        vec![
            (OsString::from("PATH"), Some(trusted_path.clone())),
            (OsString::from("SystemRoot"), Some(system_root.clone())),
            (OsString::from("SYSTEMROOT"), Some(system_root.clone())),
        ],
    ] {
        assert!(
            configure_windows_restricted_child_environment(&authority, &mut rejected, true)
                .is_err()
        );
    }
    let mut inherited_for_nonmapped_tool = Vec::new();
    configure_windows_restricted_child_environment(
        &authority,
        &mut inherited_for_nonmapped_tool,
        false,
    )
    .unwrap();
    assert!(inherited_for_nonmapped_tool.is_empty());
    let reordered_path = std::env::join_paths([
        &trusted_entries[0],
        &trusted_entries[2],
        &trusted_entries[1],
    ])
    .unwrap();
    assert!(authority.restricted_child_path(&reordered_path).is_err());
    let removed_path = std::env::join_paths(&trusted_entries[..2]).unwrap();
    assert!(authority.restricted_child_path(&removed_path).is_err());
    let substituted_path = std::env::join_paths([
        &trusted_entries[0],
        impostor_cargo.parent().unwrap(),
        &trusted_entries[2],
    ])
    .unwrap();
    assert!(authority.restricted_child_path(&substituted_path).is_err());

    assert_eq!(
        authority
            .mapped_program(cargo_proxy.as_os_str(), &cargo_proxy)
            .unwrap(),
        Some(staged_cargo.clone())
    );
    assert_eq!(
        authority
            .mapped_program(OsStr::new("cargo"), &cargo_proxy)
            .unwrap(),
        Some(staged_cargo.clone())
    );
    assert!(
        authority
            .mapped_program(cargo_proxy.as_os_str(), &source_rustc)
            .is_err()
    );
    assert!(
        authority
            .mapped_program(impostor_cargo.as_os_str(), &impostor_cargo)
            .is_err()
    );

    assert!(fs::write(&staged_cargo, b"replacement").is_err());
    assert!(fs::remove_file(&staged_rustc).is_err());
    let adjacent = fixture.root.join("stage/adjacent.dll");
    fs::write(&adjacent, b"injected").unwrap();
    assert!(authority.revalidate().is_err());
    fs::remove_file(adjacent).unwrap();
    drop(authority);
}

#[test]
fn staged_toolchain_rejects_different_selected_bytes() {
    let fixture = Fixture::new("different");
    let cargo_proxy = fixture.tool_file("proxy-cargo", "cargo.exe", b"proxy");
    let rustc_proxy = fixture.tool_file("proxy-rustc", "rustc.exe", b"proxy");
    let source_cargo = fixture.tool_file("source-cargo", "cargo.exe", b"cargo");
    let staged_cargo = fixture.tool_file("stage/bin", "cargo.exe", b"other");
    let source_rustc = fixture.tool_file("source-rustc", "rustc.exe", b"rustc");
    let staged_rustc = fixture.tool_file("stage/bin", "rustc.exe", b"rustc");
    let (trusted_path, _, system_root) = fixture.trusted_path();
    let (inventory_root, inventory_files, inventory_directories) =
        inventory(&fixture.root.join("stage"));

    assert!(
        WindowsToolchainAuthority::new(
            mapping(&cargo_proxy, &source_cargo, &staged_cargo),
            mapping(&rustc_proxy, &source_rustc, &staged_rustc),
            inventory_root,
            inventory_files,
            inventory_directories,
            trusted_path,
            system_root,
        )
        .is_err()
    );
}

#[test]
fn system_root_requires_its_exact_root_and_system32_in_trusted_path() {
    let fixture = Fixture::new("system-root-path");
    let cargo_proxy = fixture.tool_file("proxy-cargo", "cargo.exe", b"proxy");
    let rustc_proxy = fixture.tool_file("proxy-rustc", "rustc.exe", b"proxy");
    let source_cargo = fixture.tool_file("source-cargo", "cargo.exe", b"cargo");
    let staged_cargo = fixture.tool_file("stage/bin", "cargo.exe", b"cargo");
    let source_rustc = fixture.tool_file("source-rustc", "rustc.exe", b"rustc");
    let staged_rustc = fixture.tool_file("stage/bin", "rustc.exe", b"rustc");
    let (_, trusted_entries, system_root) = fixture.trusted_path();
    let system_root_path = PathBuf::from(&system_root);
    let system32 = system_root_path.join("System32");
    let try_path = |entries: Vec<PathBuf>, system_root: OsString| {
        let (inventory_root, inventory_files, inventory_directories) =
            inventory(&fixture.root.join("stage"));
        WindowsToolchainAuthority::new(
            mapping(&cargo_proxy, &source_cargo, &staged_cargo),
            mapping(&rustc_proxy, &source_rustc, &staged_rustc),
            inventory_root,
            inventory_files,
            inventory_directories,
            std::env::join_paths(entries).unwrap(),
            system_root,
        )
    };

    assert!(
        try_path(
            trusted_entries
                .iter()
                .filter(|entry| entry.as_path() != system_root_path)
                .cloned()
                .collect(),
            system_root.clone(),
        )
        .is_err()
    );
    assert!(
        try_path(
            trusted_entries
                .iter()
                .filter(|entry| entry.as_path() != system32)
                .cloned()
                .collect(),
            system_root.clone(),
        )
        .is_err()
    );
    let substituted_system_root = fixture
        .tool_file(
            "SubstitutedWindows/System32",
            "kernel32.dll",
            b"other kernel",
        )
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .as_os_str()
        .to_owned();
    assert!(try_path(trusted_entries, substituted_system_root).is_err());
}

#[test]
fn absent_trusted_path_entry_is_omitted_and_must_remain_absent() {
    let fixture = Fixture::new("absent-path");
    let cargo_proxy = fixture.tool_file("proxy-cargo", "cargo.exe", b"proxy");
    let rustc_proxy = fixture.tool_file("proxy-rustc", "rustc.exe", b"proxy");
    let source_cargo = fixture.tool_file("source-cargo", "cargo.exe", b"cargo");
    let staged_cargo = fixture.tool_file("stage/bin", "cargo.exe", b"cargo");
    let source_rustc = fixture.tool_file("source-rustc", "rustc.exe", b"rustc");
    let staged_rustc = fixture.tool_file("stage/bin", "rustc.exe", b"rustc");
    let (present_path, present_entries, system_root) = fixture.trusted_path();
    let first_missing = fixture.root.join("declared-but-absent");
    let missing = first_missing.join("nested/bin");
    let mut raw_entries = std::env::split_paths(&present_path).collect::<Vec<_>>();
    raw_entries.insert(1, missing.clone());
    raw_entries.insert(3, missing.clone());
    let trusted_path = std::env::join_paths(&raw_entries).unwrap();
    let (inventory_root, inventory_files, inventory_directories) =
        inventory(&fixture.root.join("stage"));
    let authority = WindowsToolchainAuthority::new(
        mapping(&cargo_proxy, &source_cargo, &staged_cargo),
        mapping(&rustc_proxy, &source_rustc, &staged_rustc),
        inventory_root,
        inventory_files,
        inventory_directories,
        trusted_path.clone(),
        system_root,
    )
    .unwrap();

    let restricted_path = authority.restricted_child_path(&trusted_path).unwrap();
    assert_eq!(
        std::env::split_paths(&restricted_path).collect::<Vec<_>>(),
        std::iter::once(staged_rustc.parent().unwrap().to_path_buf())
            .chain(present_entries)
            .collect::<Vec<_>>()
    );
    fs::create_dir(&first_missing).unwrap();
    assert!(authority.restricted_child_path(&trusted_path).is_err());
    drop(authority);
}

#[test]
fn absent_trusted_path_entries_reject_unbound_spellings_and_empty_suffix() {
    let fixture = Fixture::new("invalid-absent-path");
    let cargo_proxy = fixture.tool_file("proxy-cargo", "cargo.exe", b"proxy");
    let rustc_proxy = fixture.tool_file("proxy-rustc", "rustc.exe", b"proxy");
    let source_cargo = fixture.tool_file("source-cargo", "cargo.exe", b"cargo");
    let staged_cargo = fixture.tool_file("stage/bin", "cargo.exe", b"cargo");
    let source_rustc = fixture.tool_file("source-rustc", "rustc.exe", b"rustc");
    let staged_rustc = fixture.tool_file("stage/bin", "rustc.exe", b"rustc");
    let present = fixture.tool_file("present", "tool.exe", b"tool");
    let present = present.parent().unwrap().to_path_buf();
    let (_, _, system_root) = fixture.trusted_path();
    let try_path = |trusted_parent_path| {
        let (inventory_root, inventory_files, inventory_directories) =
            inventory(&fixture.root.join("stage"));
        WindowsToolchainAuthority::new(
            mapping(&cargo_proxy, &source_cargo, &staged_cargo),
            mapping(&rustc_proxy, &source_rustc, &staged_rustc),
            inventory_root,
            inventory_files,
            inventory_directories,
            trusted_parent_path,
            system_root.clone(),
        )
    };

    let relative = std::env::join_paths([present.as_path(), Path::new("relative")]).unwrap();
    assert!(try_path(relative).is_err());
    let dotted =
        std::env::join_paths([present.as_path(), &fixture.root.join("./missing")]).unwrap();
    assert!(try_path(dotted).is_err());
    let all_absent = std::env::join_paths([
        &fixture.root.join("missing-one"),
        &fixture.root.join("missing-two"),
    ])
    .unwrap();
    assert!(try_path(all_absent).is_err());
}

#[test]
fn selected_cargo_source_maps_only_its_exact_bound_path() {
    let fixture = Fixture::new("selected-cargo");
    let source_cargo = fixture.tool_file("selected-cargo", "cargo.exe", b"cargo");
    let staged_cargo = fixture.tool_file("stage/bin", "cargo.exe", b"cargo");
    let rustc_proxy = fixture.tool_file("proxy-rustc", "rustc.exe", b"proxy");
    let source_rustc = fixture.tool_file("source-rustc", "rustc.exe", b"rustc");
    let staged_rustc = fixture.tool_file("stage/bin", "rustc.exe", b"rustc");
    let copied_cargo = fixture.tool_file("copied", "cargo.exe", b"cargo");
    let (trusted_path, _, system_root) = fixture.trusted_path();
    let (inventory_root, inventory_files, inventory_directories) =
        inventory(&fixture.root.join("stage"));
    let authority = WindowsToolchainAuthority::new(
        WindowsToolchainExecutableAuthority::selected_toolchain(
            source_cargo.clone(),
            source_cargo.clone(),
            source_cargo.clone(),
            staged_cargo.clone(),
        ),
        mapping(&rustc_proxy, &source_rustc, &staged_rustc),
        inventory_root,
        inventory_files,
        inventory_directories,
        trusted_path,
        system_root,
    )
    .unwrap();

    assert_eq!(
        authority
            .mapped_program(OsStr::new("cargo"), &source_cargo)
            .unwrap(),
        Some(staged_cargo)
    );
    assert!(
        authority
            .mapped_program(OsStr::new("cargo"), &copied_cargo)
            .is_err()
    );
}
