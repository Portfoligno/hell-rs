#![cfg(windows)]

use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::time::{Duration, Instant};

use hell_testkit::{
    BoundProgramInvocation, WindowsGhcSemanticReceipt, WindowsGhcupShimAuthority,
    WindowsStackRuntimeAuthority, WindowsToolchainAuthority, WindowsToolchainAuthorityInput,
    WindowsToolchainExecutableAuthority, configure_windows_restricted_child_environment,
    configure_windows_restricted_child_path, run_supervised_command_until,
    windows_child_path_presentation_for_integration,
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

struct StackRuntimeFixture {
    authority: WindowsStackRuntimeAuthority,
    source: PathBuf,
    staged: PathBuf,
    runtime_root: PathBuf,
    stack_root: PathBuf,
    temporary: PathBuf,
    immutable_root: PathBuf,
    ghc_native: PathBuf,
    ghc_descriptor: PathBuf,
    ghc_source: PathBuf,
    ghc: PathBuf,
    ghc_bin: PathBuf,
    mingw_bin: PathBuf,
    strip: PathBuf,
}

fn bind_stack_ghc_authorities(
    public: &Path,
    descriptor: &Path,
    distribution: &Path,
    deadline: Instant,
) -> (WindowsGhcupShimAuthority, BoundProgramInvocation) {
    let public =
        BoundProgramInvocation::new_until(public.to_path_buf(), public.to_path_buf(), deadline)
            .unwrap();
    let shim =
        WindowsGhcupShimAuthority::new_until(public, descriptor.to_path_buf(), deadline).unwrap();
    let distribution = BoundProgramInvocation::new_until(
        distribution.to_path_buf(),
        distribution.to_path_buf(),
        deadline,
    )
    .unwrap();
    (shim, distribution)
}

fn assert_same_windows_directory_presentation(canonical: &Path, presentation: &Path) {
    assert_ne!(presentation, canonical);
    assert_eq!(fs::canonicalize(presentation).unwrap(), canonical);
    assert_eq!(
        same_file::Handle::from_path(presentation).unwrap(),
        same_file::Handle::from_path(canonical).unwrap()
    );
}

fn stack_runtime_fixture(fixture: &Fixture, name: &str) -> StackRuntimeFixture {
    let target = fixture.root.join(format!("{name}-candidate-target"));
    fs::create_dir(&target).unwrap();
    let target = fs::canonicalize(target).unwrap();
    let runtime_parent = target.join("release-child-environment");
    let runtime_root = runtime_parent.join("stack-1");
    let stack_root = runtime_root.join("root");
    let immutable_root = runtime_root.join("system-ghc-9.8.4");
    let ghc_bin = immutable_root.join("bin");
    let mingw_bin = immutable_root.join("mingw/bin");
    let temporary = runtime_root.join("tmp");
    let bin = runtime_root.join("bin");
    for directory in [
        runtime_parent.as_path(),
        runtime_root.as_path(),
        stack_root.as_path(),
        immutable_root.as_path(),
        ghc_bin.as_path(),
        immutable_root.join("mingw").as_path(),
        mingw_bin.as_path(),
        temporary.as_path(),
        bin.as_path(),
    ] {
        fs::create_dir(directory).unwrap();
    }
    let source = fixture.tool_file(&format!("{name}-source"), "stack.exe", b"stack");
    let staged = bin.join("stack.exe");
    fs::write(&staged, b"stack").unwrap();
    let staged = fs::canonicalize(staged).unwrap();
    let ghc_native = fixture.tool_file(&format!("{name}-ghc-native"), "ghc.exe", b"shim");
    let ghc_source = fixture.tool_file(&format!("{name}-ghc-source"), "ghc.exe", b"ghc");
    let ghc_descriptor = ghc_native.with_extension("shim");
    fs::write(
        &ghc_descriptor,
        format!("path = {}", ghc_source.to_str().unwrap()),
    )
    .unwrap();
    let ghc_descriptor = fs::canonicalize(ghc_descriptor).unwrap();
    let ghc = ghc_bin.join("ghc.exe");
    fs::write(&ghc, b"ghc").unwrap();
    let ghc = fs::canonicalize(ghc).unwrap();
    let strip = mingw_bin.join("strip.exe");
    fs::write(&strip, b"strip").unwrap();
    let strip = fs::canonicalize(strip).unwrap();
    let immutable_directories = [
        immutable_root.clone(),
        ghc_bin.clone(),
        immutable_root.join("mingw"),
        mingw_bin.clone(),
    ]
    .into_iter()
    .map(|path| fs::canonicalize(path).unwrap())
    .collect();
    let deadline = Instant::now().checked_add(Duration::from_secs(5)).unwrap();
    let source_authority =
        BoundProgramInvocation::new_until(source.clone(), source.clone(), deadline).unwrap();
    let (ghc_shim_authority, ghc_source_authority) =
        bind_stack_ghc_authorities(&ghc_native, &ghc_descriptor, &ghc_source, deadline);
    let authority = WindowsStackRuntimeAuthority::new_until(
        WindowsStackRuntimeAuthority::input(
            source_authority,
            staged.clone(),
            WindowsStackRuntimeAuthority::system_ghc_input(
                ghc_shim_authority,
                ghc_source_authority,
                ghc.clone(),
                strip.clone(),
                immutable_root.clone(),
                ghc_bin.clone(),
                mingw_bin.clone(),
            ),
            target,
            runtime_root.clone(),
            stack_root.clone(),
            temporary.clone(),
        ),
        vec![ghc.clone(), strip.clone()],
        immutable_directories,
        deadline,
    )
    .unwrap();
    StackRuntimeFixture {
        authority,
        source,
        staged,
        runtime_root,
        stack_root,
        temporary,
        immutable_root,
        ghc_native,
        ghc_descriptor,
        ghc_source,
        ghc,
        ghc_bin,
        mingw_bin,
        strip,
    }
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
        WindowsToolchainAuthorityInput::new(
            mapping(&cargo_proxy, &source_cargo, &staged_cargo),
            mapping(&rustc_proxy, &source_rustc, &staged_rustc),
            inventory_root.clone(),
            inventory_directories.clone(),
            trusted_path.clone(),
            system_root.clone(),
        ),
        promoted,
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
        WindowsToolchainAuthorityInput::new(
            mapping(&cargo_proxy, &source_cargo, &nonmember),
            mapping(&rustc_proxy, &source_rustc, &staged_rustc),
            inventory_root,
            inventory_directories.clone(),
            trusted_path.clone(),
            system_root.clone(),
        ),
        promoted_for_nonmember,
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
        WindowsToolchainAuthorityInput::new(
            mapping(&missing, &missing, &missing),
            mapping(&missing, &missing, &missing),
            missing.clone(),
            inventory_directories,
            trusted_path,
            system_root,
        ),
        Vec::new(),
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
    let mut command =
        Command::new(std::env::current_exe().expect("Windows toolchain test executable"));
    command
        .arg("malformed_system_root_rejection_is_process_isolated")
        .arg("--exact")
        .args(["--skip", MALFORMED_SYSTEM_ROOT_PROBE, "--skip", case]);
    let execution_deadline = Instant::now().checked_add(Duration::from_secs(30)).unwrap();
    let completion_deadline = execution_deadline
        .checked_add(Duration::from_secs(10))
        .unwrap();
    let output = run_supervised_command_until(
        &mut command,
        &[],
        execution_deadline,
        completion_deadline,
        None,
    )
    .expect("malformed SystemRoot subprocess probe runs");
    assert_terminal_supervised_receipts(&output);
    output.status
}

fn assert_terminal_supervised_receipts(output: &hell_testkit::SupervisedOutput) {
    assert!(!output.timed_out);
    assert!(output.candidate_quiescence_complete);
    assert!(
        output
            .termination
            .as_ref()
            .is_some_and(|receipt| receipt.reaped)
    );
    for expected in ["quiescence-complete", "stdout-joined", "stderr-joined"] {
        assert!(
            output
                .phase_timings
                .iter()
                .any(|phase| phase.name == expected),
            "supervised probe lacks {expected} receipt"
        );
    }
    assert_eq!(
        output.phase_timings.last().map(|phase| phase.name),
        Some("stdin-joined")
    );
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

    assert_exact_restricted_environment(
        &authority,
        &staged_rustc,
        &trusted_entries,
        &trusted_path,
        &system_root,
        &impostor_cargo,
    );

    assert_exact_mapping_and_substitution(
        &authority,
        &fixture,
        &cargo_proxy,
        &staged_cargo,
        &source_rustc,
        &staged_rustc,
        &impostor_cargo,
    );
    drop(authority);
}

fn assert_exact_restricted_environment(
    authority: &WindowsToolchainAuthority,
    staged_rustc: &Path,
    trusted_entries: &[PathBuf],
    trusted_path: &OsStr,
    system_root: &OsStr,
    impostor_cargo: &Path,
) {
    let restricted_path = authority.restricted_child_path(trusted_path).unwrap();
    assert_eq!(
        std::env::split_paths(&restricted_path).collect::<Vec<_>>(),
        std::iter::once(staged_rustc.parent().unwrap().to_path_buf())
            .chain(trusted_entries.iter().cloned())
            .collect::<Vec<_>>()
    );
    let mut inherited_for_mapped_tool = Vec::new();
    configure_windows_restricted_child_environment(authority, &mut inherited_for_mapped_tool, true)
        .unwrap();
    assert_eq!(
        inherited_for_mapped_tool,
        [
            (OsString::from("PATH"), Some(restricted_path)),
            (
                OsString::from("SystemRoot"),
                Some(system_root.to_os_string())
            ),
        ]
    );
    let mut explicitly_removed = vec![(OsString::from("PATH"), None)];
    assert!(
        configure_windows_restricted_child_path(authority, &mut explicitly_removed, true).is_err()
    );
    let mut disagreed = vec![(
        OsString::from("Path"),
        Some(OsString::from(r"C:\forged-path")),
    )];
    assert!(configure_windows_restricted_child_path(authority, &mut disagreed, true).is_err());
    let mut duplicated = vec![
        (OsString::from("PATH"), Some(trusted_path.to_os_string())),
        (OsString::from("Path"), Some(trusted_path.to_os_string())),
    ];
    assert!(configure_windows_restricted_child_path(authority, &mut duplicated, true).is_err());
    for mut rejected in malformed_environment_cases(trusted_path, system_root) {
        assert!(
            configure_windows_restricted_child_environment(authority, &mut rejected, true).is_err()
        );
    }
    let mut inherited_for_nonmapped_tool = Vec::new();
    configure_windows_restricted_child_environment(
        authority,
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
}

fn malformed_environment_cases(
    trusted_path: &OsStr,
    system_root: &OsStr,
) -> [Vec<(OsString, Option<OsString>)>; 3] {
    [
        vec![
            (OsString::from("PATH"), Some(trusted_path.to_os_string())),
            (OsString::from("SystemRoot"), None),
        ],
        vec![
            (OsString::from("PATH"), Some(trusted_path.to_os_string())),
            (
                OsString::from("SystemRoot"),
                Some(OsString::from(r"C:\forged-windows")),
            ),
        ],
        vec![
            (OsString::from("PATH"), Some(trusted_path.to_os_string())),
            (
                OsString::from("SystemRoot"),
                Some(system_root.to_os_string()),
            ),
            (
                OsString::from("SYSTEMROOT"),
                Some(system_root.to_os_string()),
            ),
        ],
    ]
}

fn assert_exact_mapping_and_substitution(
    authority: &WindowsToolchainAuthority,
    fixture: &Fixture,
    cargo_proxy: &Path,
    staged_cargo: &Path,
    source_rustc: &Path,
    staged_rustc: &Path,
    impostor_cargo: &Path,
) {
    assert_eq!(
        authority
            .mapped_program(cargo_proxy.as_os_str(), cargo_proxy)
            .unwrap(),
        Some(staged_cargo.to_path_buf())
    );
    assert_eq!(
        authority
            .mapped_program(OsStr::new("cargo"), cargo_proxy)
            .unwrap(),
        Some(staged_cargo.to_path_buf())
    );
    assert!(
        authority
            .mapped_program(cargo_proxy.as_os_str(), source_rustc)
            .is_err()
    );
    assert!(
        authority
            .mapped_program(impostor_cargo.as_os_str(), impostor_cargo)
            .is_err()
    );
    assert!(fs::write(staged_cargo, b"replacement").is_err());
    assert!(fs::remove_file(staged_rustc).is_err());
    let adjacent = fixture.root.join("stage/adjacent.dll");
    fs::write(&adjacent, b"injected").unwrap();
    assert!(authority.revalidate().is_err());
    fs::remove_file(adjacent).unwrap();
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

#[test]
fn stack_runtime_binds_distinct_public_and_distribution_ghc_authorities() {
    let fixture = Fixture::new("stack-runtime");
    let stack = stack_runtime_fixture(&fixture, "exact");
    assert_ne!(stack.ghc_native, stack.ghc_source);
    assert_ne!(
        fs::read(&stack.ghc_native).unwrap(),
        fs::read(&stack.ghc_source).unwrap()
    );
    let mut environment = Vec::new();
    stack
        .authority
        .bind_environment_for_integration(&mut environment)
        .unwrap();
    let stack_root_presentation =
        windows_child_path_presentation_for_integration(&stack.stack_root).unwrap();
    let temporary_presentation =
        windows_child_path_presentation_for_integration(&stack.temporary).unwrap();
    assert_eq!(
        environment,
        [
            (
                OsString::from("STACK_ROOT"),
                Some(stack_root_presentation.as_os_str().to_owned())
            ),
            (
                OsString::from("TEMP"),
                Some(temporary_presentation.as_os_str().to_owned())
            ),
            (
                OsString::from("TMP"),
                Some(temporary_presentation.as_os_str().to_owned())
            ),
            (
                OsString::from("TMPDIR"),
                Some(temporary_presentation.as_os_str().to_owned())
            ),
        ]
    );
    assert_same_windows_directory_presentation(&stack.stack_root, &stack_root_presentation);
    assert_same_windows_directory_presentation(&stack.temporary, &temporary_presentation);
    assert!(
        stack
            .runtime_root
            .starts_with(fs::canonicalize(&fixture.root).unwrap())
    );
    assert_eq!(fs::read_dir(&stack.stack_root).unwrap().count(), 0);
    let retained = fixture.tool_file("retained-path", "kernel32.dll", b"loader");
    let retained = retained.parent().unwrap().to_path_buf();
    let mut path_environment = vec![(
        OsString::from("PATH"),
        std::env::join_paths([retained.clone()]).unwrap(),
    )];
    stack
        .authority
        .prepend_path_for_integration(&mut path_environment)
        .unwrap();
    assert_eq!(
        std::env::split_paths(&path_environment[0].1).collect::<Vec<_>>(),
        [
            stack.staged.parent().unwrap().to_path_buf(),
            stack.ghc_bin.clone(),
            stack.mingw_bin.clone(),
            retained,
        ]
    );
    assert_eq!(
        stack
            .authority
            .bind_arguments_for_integration(vec![OsString::from("build")])
            .unwrap(),
        ["--system-ghc", "--no-install-ghc", "build"].map(OsString::from)
    );
    for forged in [
        "--system-ghc",
        "--no-system-ghc",
        "--install-ghc",
        "--no-install-ghc",
    ] {
        assert!(
            stack
                .authority
                .bind_arguments_for_integration(vec![OsString::from(forged)])
                .is_err()
        );
    }
    drop(stack);
}

#[test]
fn stack_runtime_maps_only_its_bound_source_and_revalidates_the_closed_inventory() {
    let fixture = Fixture::new("stack-runtime-mapping");
    let stack = stack_runtime_fixture(&fixture, "mapping");
    let cargo_proxy = fixture.tool_file("proxy-cargo", "cargo.exe", b"proxy");
    let rustc_proxy = fixture.tool_file("proxy-rustc", "rustc.exe", b"proxy");
    let source_cargo = fixture.tool_file("source-cargo", "cargo.exe", b"cargo");
    let staged_cargo = fixture.tool_file("rust-stage/bin", "cargo.exe", b"cargo");
    let source_rustc = fixture.tool_file("source-rustc", "rustc.exe", b"rustc");
    let staged_rustc = fixture.tool_file("rust-stage/bin", "rustc.exe", b"rustc");
    let (trusted_path, _, system_root) = fixture.trusted_path();
    let (inventory_root, inventory_files, inventory_directories) =
        inventory(&fixture.root.join("rust-stage"));
    let deadline = Instant::now().checked_add(Duration::from_secs(5)).unwrap();
    let without_stack = WindowsToolchainAuthority::new_until(
        WindowsToolchainAuthorityInput::new(
            mapping(&cargo_proxy, &source_cargo, &staged_cargo),
            mapping(&rustc_proxy, &source_rustc, &staged_rustc),
            inventory_root.clone(),
            inventory_directories.clone(),
            trusted_path.clone(),
            system_root.clone(),
        ),
        inventory_files.clone(),
        deadline,
    )
    .unwrap();
    assert!(
        without_stack
            .mapped_program(OsStr::new("stack"), &stack.source)
            .is_err()
    );
    drop(without_stack);
    let authority = WindowsToolchainAuthority::new_until(
        WindowsToolchainAuthorityInput::new(
            mapping(&cargo_proxy, &source_cargo, &staged_cargo),
            mapping(&rustc_proxy, &source_rustc, &staged_rustc),
            inventory_root,
            inventory_directories,
            trusted_path,
            system_root,
        )
        .with_stack_authority(stack.authority.clone()),
        inventory_files,
        deadline,
    )
    .unwrap();
    assert_eq!(
        authority
            .mapped_program(OsStr::new("stack"), &stack.source)
            .unwrap(),
        Some(stack.staged.clone())
    );
    assert!(
        authority
            .mapped_program(OsStr::new("stack"), &stack.staged)
            .is_err()
    );
    assert!(fs::write(&stack.staged, b"other").is_err());
    assert!(fs::write(&stack.strip, b"other").is_err());
    authority.revalidate().unwrap();
    drop(authority);
    drop(stack);
}

#[test]
fn stack_runtime_rejects_split_or_ambient_environment_authority() {
    let fixture = Fixture::new("stack-runtime-environment-negative");
    let stack = stack_runtime_fixture(&fixture, "environment-negative");
    let stack_root_presentation =
        windows_child_path_presentation_for_integration(&stack.stack_root).unwrap();
    let temporary_presentation =
        windows_child_path_presentation_for_integration(&stack.temporary).unwrap();
    for mut environment in [
        vec![(
            OsString::from("TEMP"),
            Some(stack.stack_root.as_os_str().to_owned()),
        )],
        vec![(
            OsString::from("TEMP"),
            Some(stack.temporary.as_os_str().to_owned()),
        )],
        vec![
            (
                OsString::from("TEMP"),
                Some(temporary_presentation.as_os_str().to_owned()),
            ),
            (
                OsString::from("TMP"),
                Some(stack_root_presentation.as_os_str().to_owned()),
            ),
        ],
        vec![(OsString::from("TMP"), None)],
        vec![(OsString::from("STACK_ROOT"), Some(OsString::new()))],
        vec![(
            OsString::from("STACK_ROOT"),
            Some(stack.runtime_root.join("substituted-root").into_os_string()),
        )],
        vec![(
            OsString::from("APPDATA"),
            Some(OsString::from(r"C:\Users\ambient\AppData")),
        )],
        vec![
            (
                OsString::from("STACK_ROOT"),
                Some(stack_root_presentation.as_os_str().to_owned()),
            ),
            (
                OsString::from("stack_root"),
                Some(stack_root_presentation.as_os_str().to_owned()),
            ),
        ],
    ] {
        assert!(
            stack
                .authority
                .bind_environment_for_integration(&mut environment)
                .is_err()
        );
    }
    drop(stack);
}

#[test]
fn stack_runtime_rejects_substituted_or_redirected_child_writable_directory() {
    use std::os::windows::fs::symlink_dir;

    let fixture = Fixture::new("stack-runtime-child-path-negative");
    let substituted = stack_runtime_fixture(&fixture, "substituted-child-path");
    let replacement = substituted.runtime_root.join("replacement-tmp");
    fs::create_dir(&replacement).unwrap();
    fs::remove_dir(&substituted.temporary).unwrap();
    fs::rename(&replacement, &substituted.temporary).unwrap();
    assert!(
        substituted
            .authority
            .bind_environment_for_integration(&mut Vec::new())
            .is_err()
    );
    drop(substituted);

    let redirected = stack_runtime_fixture(&fixture, "redirected-child-path");
    let redirect_target = redirected.runtime_root.join("redirect-target");
    fs::create_dir(&redirect_target).unwrap();
    fs::remove_dir(&redirected.temporary).unwrap();
    symlink_dir(&redirect_target, &redirected.temporary).unwrap();
    assert!(
        redirected
            .authority
            .bind_environment_for_integration(&mut Vec::new())
            .is_err()
    );
    drop(redirected);
}

#[test]
fn stack_runtime_retains_distribution_ghc_against_same_length_substitution() {
    let fixture = Fixture::new("stack-runtime-ghc-substitution");
    let stack = stack_runtime_fixture(&fixture, "ghc-substitution");
    assert!(fs::write(&stack.ghc_source, b"bad").is_err());
    stack
        .authority
        .bind_environment_for_integration(&mut Vec::new())
        .unwrap();
    drop(stack);
}

#[test]
fn stack_runtime_retains_public_ghc_against_same_length_substitution() {
    let fixture = Fixture::new("stack-runtime-public-ghc-substitution");
    let stack = stack_runtime_fixture(&fixture, "public-ghc-substitution");
    assert!(fs::write(&stack.ghc_native, b"bad!").is_err());
    stack
        .authority
        .bind_environment_for_integration(&mut Vec::new())
        .unwrap();
    drop(stack);
}

#[test]
fn stack_runtime_retains_ghcup_descriptor_against_substitution() {
    let fixture = Fixture::new("stack-runtime-shim-substitution");
    let stack = stack_runtime_fixture(&fixture, "shim-substitution");
    assert!(fs::write(&stack.ghc_descriptor, b"path = C:\\other\\ghc.exe").is_err());
    stack
        .authority
        .bind_environment_for_integration(&mut Vec::new())
        .unwrap();
    drop(stack);
}

#[test]
fn ghcup_shim_rejects_missing_malformed_relative_and_multiline_descriptors() {
    let fixture = Fixture::new("ghcup-shim-descriptor-negative");
    let public = fixture.tool_file("public", "ghc.exe", b"shim");
    let target = fixture.tool_file("distribution", "ghc.exe", b"ghc");
    let deadline = Instant::now().checked_add(Duration::from_secs(5)).unwrap();
    let bind_public =
        || BoundProgramInvocation::new_until(public.clone(), public.clone(), deadline).unwrap();
    let descriptor = public.with_extension("shim");
    assert!(
        WindowsGhcupShimAuthority::new_until(bind_public(), descriptor.clone(), deadline).is_err()
    );
    for contents in [
        String::new(),
        "path=missing-space".to_owned(),
        "path = relative\\ghc.exe".to_owned(),
        format!("path = {}\nargs = --version", target.display()),
        format!("path = {}\npath = {}", target.display(), target.display()),
        format!("path = {}\0", target.display()),
        format!("path = {}", "x".repeat(4096)),
    ] {
        fs::write(&descriptor, contents).unwrap();
        assert!(
            WindowsGhcupShimAuthority::new_until(
                bind_public(),
                fs::canonicalize(&descriptor).unwrap(),
                deadline,
            )
            .is_err()
        );
    }
}

#[test]
fn ghcup_shim_rejects_substituted_target_and_reparse_members() {
    use std::os::windows::fs::symlink_file;

    let fixture = Fixture::new("ghcup-shim-identity-negative");
    let public = fixture.tool_file("public", "ghc.exe", b"shim");
    let target = fixture.tool_file("distribution", "ghc.exe", b"ghc");
    let substituted = fixture.tool_file("substituted", "ghc.exe", b"ghc");
    let deadline = Instant::now().checked_add(Duration::from_secs(5)).unwrap();
    let bind = |path: &Path| {
        BoundProgramInvocation::new_until(path.to_path_buf(), path.to_path_buf(), deadline).unwrap()
    };
    let descriptor = public.with_extension("shim");
    fs::write(&descriptor, format!("path = {}", target.display())).unwrap();
    let authority = WindowsGhcupShimAuthority::new_until(
        bind(&public),
        fs::canonicalize(&descriptor).unwrap(),
        deadline,
    )
    .unwrap();
    assert!(
        authority
            .attest_target_until(&bind(&substituted), deadline)
            .is_err()
    );
    drop(authority);

    fs::remove_file(&descriptor).unwrap();
    let descriptor_source = fixture.tool_file(
        "descriptor-source",
        "ghc.shim",
        format!("path = {}", target.display()).as_bytes(),
    );
    symlink_file(&descriptor_source, &descriptor).unwrap();
    assert!(
        WindowsGhcupShimAuthority::new_until(bind(&public), descriptor.clone(), deadline).is_err()
    );
    fs::remove_file(&descriptor).unwrap();

    let redirected = fixture.root.join("redirected-ghc.exe");
    symlink_file(&target, &redirected).unwrap();
    fs::write(&descriptor, format!("path = {}", redirected.display())).unwrap();
    assert!(
        WindowsGhcupShimAuthority::new_until(
            bind(&public),
            fs::canonicalize(&descriptor).unwrap(),
            deadline,
        )
        .is_err()
    );
}

#[test]
fn distribution_ghc_requires_one_retained_direct_bin_member() {
    use std::os::windows::fs::symlink_file;

    let fixture = Fixture::new("distribution-ghc-direct-member");
    let deadline = Instant::now().checked_add(Duration::from_secs(5)).unwrap();
    let direct = fixture.tool_file("direct/bin", "ghc.exe", b"direct-ghc");
    let direct_bin = direct.parent().unwrap();
    let authority = BoundProgramInvocation::new_windows_direct_member_until(
        direct_bin,
        OsStr::new("ghc.exe"),
        deadline,
    )
    .unwrap();
    assert!(fs::write(&direct, b"substitute").is_err());
    authority.windows_revalidate_for_integration().unwrap();

    let external = fixture.tool_file("external", "ghc.exe", b"external-ghc");
    let public = fixture.tool_file("public", "ghc.exe", b"shim");
    let descriptor = public.with_extension("shim");
    fs::write(&descriptor, format!("path = {}", external.display())).unwrap();
    WindowsGhcupShimAuthority::new_until(
        BoundProgramInvocation::new_until(public.clone(), public, deadline).unwrap(),
        fs::canonicalize(descriptor).unwrap(),
        deadline,
    )
    .unwrap();
    let external_bin = fixture.root.join("external-reparse/bin");
    fs::create_dir_all(&external_bin).unwrap();
    symlink_file(&external, external_bin.join("ghc.exe")).unwrap();
    assert!(
        BoundProgramInvocation::new_windows_direct_member_until(
            &fs::canonicalize(external_bin).unwrap(),
            OsStr::new("ghc.exe"),
            deadline,
        )
        .is_err()
    );

    let alias_bin = fixture.root.join("same-directory-alias/bin");
    fs::create_dir_all(&alias_bin).unwrap();
    let actual = alias_bin.join("ghc-real.exe");
    fs::write(&actual, b"same-directory-ghc").unwrap();
    symlink_file(&actual, alias_bin.join("ghc.exe")).unwrap();
    assert!(
        BoundProgramInvocation::new_windows_direct_member_until(
            &fs::canonicalize(alias_bin).unwrap(),
            OsStr::new("ghc.exe"),
            deadline,
        )
        .is_err()
    );
}

#[test]
fn ghcup_shim_rejects_wrong_version_output_and_libdir_receipts() {
    let fixture = Fixture::new("ghcup-shim-semantic-negative");
    let public = fixture.tool_file("public", "ghc.exe", b"shim");
    let target = fixture.tool_file("distribution", "ghc.exe", b"ghc");
    let descriptor = public.with_extension("shim");
    fs::write(&descriptor, format!("path = {}", target.display())).unwrap();
    let libdir = fixture.root.join("distribution/lib");
    let other_libdir = fixture.root.join("other/lib");
    fs::create_dir_all(&libdir).unwrap();
    fs::create_dir_all(&other_libdir).unwrap();
    let libdir = fs::canonicalize(libdir).unwrap();
    let other_libdir = fs::canonicalize(other_libdir).unwrap();
    let deadline = Instant::now().checked_add(Duration::from_secs(5)).unwrap();
    let target_authority =
        BoundProgramInvocation::new_until(target.clone(), target, deadline).unwrap();
    let authority = WindowsGhcupShimAuthority::new_until(
        BoundProgramInvocation::new_until(public.clone(), public, deadline).unwrap(),
        fs::canonicalize(descriptor).unwrap(),
        deadline,
    )
    .unwrap();
    let digest = "00".repeat(32);
    let other_digest = "11".repeat(32);
    let receipt = |version: &str, output: &str, path: &Path| {
        WindowsGhcSemanticReceipt::new(version, output, path.to_path_buf(), path.to_path_buf())
            .unwrap()
    };
    let public_receipt = receipt("9.8.2", &digest, &libdir);
    authority
        .attest_distribution_until(
            &target_authority,
            &public_receipt,
            &receipt("9.8.2", &digest, &libdir),
            deadline,
        )
        .unwrap();
    for substituted in [
        receipt("9.6.7", &digest, &libdir),
        receipt("9.8.20", &digest, &libdir),
        receipt("x9.8.2y", &digest, &libdir),
        receipt("9.8.2", &other_digest, &libdir),
        receipt("9.8.2", &digest, &other_libdir),
    ] {
        assert!(
            authority
                .attest_distribution_until(
                    &target_authority,
                    &public_receipt,
                    &substituted,
                    deadline,
                )
                .is_err()
        );
    }
}

#[test]
fn stack_runtime_rejects_missing_escaped_or_redirected_inventory() {
    use std::os::windows::fs::symlink_dir;

    let fixture = Fixture::new("stack-runtime-inventory-negative");
    let stack = stack_runtime_fixture(&fixture, "inventory-negative");

    let missing = stack.immutable_root.join("missing-strip.exe");
    let deadline = Instant::now().checked_add(Duration::from_secs(5)).unwrap();
    let source_authority = || {
        BoundProgramInvocation::new_until(stack.source.clone(), stack.source.clone(), deadline)
            .unwrap()
    };
    let ghc_input = || {
        let public = BoundProgramInvocation::new_until(
            stack.ghc_native.clone(),
            stack.ghc_native.clone(),
            deadline,
        )
        .unwrap();
        WindowsStackRuntimeAuthority::system_ghc_input(
            WindowsGhcupShimAuthority::new_until(public, stack.ghc_descriptor.clone(), deadline)
                .unwrap(),
            BoundProgramInvocation::new_until(
                stack.ghc_source.clone(),
                stack.ghc_source.clone(),
                deadline,
            )
            .unwrap(),
            stack.ghc.clone(),
            stack.strip.clone(),
            stack.immutable_root.clone(),
            stack.ghc_bin.clone(),
            stack.mingw_bin.clone(),
        )
    };
    let target = stack
        .runtime_root
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .to_path_buf();
    assert!(
        WindowsStackRuntimeAuthority::new_until(
            WindowsStackRuntimeAuthority::input(
                source_authority(),
                stack.staged.clone(),
                ghc_input(),
                target.clone(),
                stack.runtime_root.clone(),
                stack.stack_root.clone(),
                stack.temporary.clone(),
            ),
            vec![missing],
            Vec::new(),
            deadline,
        )
        .is_err()
    );
    let outside = fixture.tool_file("outside", "strip.exe", b"strip");
    assert!(
        WindowsStackRuntimeAuthority::new_until(
            WindowsStackRuntimeAuthority::input(
                source_authority(),
                stack.staged.clone(),
                ghc_input(),
                target.clone(),
                stack.runtime_root.clone(),
                stack.stack_root.clone(),
                stack.temporary.clone(),
            ),
            vec![outside],
            Vec::new(),
            deadline,
        )
        .is_err()
    );

    let redirected = stack.immutable_root.join("redirected");
    let redirect_target = fixture.root.join("redirect-target");
    fs::create_dir(&redirect_target).unwrap();
    symlink_dir(&redirect_target, &redirected).unwrap();
    assert!(
        WindowsStackRuntimeAuthority::new_until(
            WindowsStackRuntimeAuthority::input(
                source_authority(),
                stack.staged.clone(),
                ghc_input(),
                target,
                stack.runtime_root.clone(),
                stack.stack_root.clone(),
                stack.temporary.clone(),
            ),
            vec![stack.strip.clone()],
            vec![redirected],
            deadline,
        )
        .is_err()
    );
    drop(stack);
}
