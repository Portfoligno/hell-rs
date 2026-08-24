#![cfg(windows)]

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::windows::fs::symlink_dir;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hell_testkit::{
    CandidateLaunchPolicy, WindowsGitExecutableAuthority, WindowsLaunchAuthorities,
    WindowsToolchainAuthority, WindowsToolchainAuthorityInput, WindowsToolchainExecutableAuthority,
    decode_windows_argv, parse_windows_release_child_request, resolve_windows_parent_program_from,
    resolve_windows_release_child_current_directory,
    windows_child_path_presentation_for_integration,
};

struct Fixture {
    root: PathBuf,
    stack: PathBuf,
    cargo_proxy: PathBuf,
    rustc_proxy: PathBuf,
    source_cargo: PathBuf,
    source_rustc: PathBuf,
    staged_cargo: PathBuf,
    staged_rustc: PathBuf,
    restricted_path: OsString,
    system_root: OsString,
    toolchain: Option<WindowsToolchainAuthority>,
}

fn real_git_parent_authorities() -> (PathBuf, OsString, PathBuf) {
    let parent_path = std::env::var_os("PATH").expect("Windows parent PATH must exist");
    let pathext = std::env::var_os("PATHEXT").expect("Windows parent PATHEXT must exist");
    let extensions = pathext
        .to_string_lossy()
        .split(';')
        .filter(|extension| !extension.is_empty())
        .map(OsString::from)
        .collect::<Vec<_>>();
    let git = resolve_windows_parent_program_from(
        OsStr::new("git"),
        &std::env::split_paths(&parent_path).collect::<Vec<_>>(),
        &extensions,
    )
    .expect("Windows test host must provide Git");
    let system_root = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .map(|root| fs::canonicalize(root).unwrap())
        .expect("Windows SystemRoot must exist");
    (git, pathext, system_root)
}

impl Fixture {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock must follow the Unix epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "hell-windows-restricted-environment-{}-{label}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        let root = fs::canonicalize(root).unwrap();
        let tool_file = |directory: &str, name: &str, bytes: &[u8]| {
            let directory = root.join(directory);
            fs::create_dir_all(&directory).unwrap();
            let path = directory.join(name);
            fs::write(&path, bytes).unwrap();
            fs::canonicalize(path).unwrap()
        };
        let cargo_proxy = tool_file("proxy-cargo", "cargo.exe", b"cargo proxy");
        let rustc_proxy = tool_file("proxy-rustc", "rustc.exe", b"rustc proxy");
        let source_cargo = tool_file("source-cargo", "cargo.exe", b"cargo");
        let staged_cargo = tool_file("stage/bin", "cargo.exe", b"cargo");
        let source_rustc = tool_file("source-rustc", "rustc.exe", b"rustc");
        let staged_rustc = tool_file("stage/bin", "rustc.exe", b"rustc");
        let stack = tool_file("unmapped", "stack.exe", b"stack");
        let system32 = tool_file("Windows/System32", "kernel32.dll", b"system kernel")
            .parent()
            .unwrap()
            .to_path_buf();
        let system_root_path = system32.parent().unwrap().to_path_buf();
        let trusted_path = std::env::join_paths([
            cargo_proxy.parent().unwrap(),
            source_cargo.parent().unwrap(),
            system32.as_path(),
            system_root_path.as_path(),
        ])
        .unwrap();
        let system_root = system_root_path.into_os_string();
        let (inventory_root, inventory_files, inventory_directories) =
            inventory(&root.join("stage"));
        let mapping = |proxy: &Path, source: &Path, staged: &Path| {
            WindowsToolchainExecutableAuthority::rustup_proxy(
                proxy.to_path_buf(),
                proxy.to_path_buf(),
                source.to_path_buf(),
                staged.to_path_buf(),
            )
        };
        let toolchain = WindowsToolchainAuthority::new(
            mapping(&cargo_proxy, &source_cargo, &staged_cargo),
            mapping(&rustc_proxy, &source_rustc, &staged_rustc),
            inventory_root,
            inventory_files,
            inventory_directories,
            trusted_path.clone(),
            system_root.clone(),
        )
        .unwrap();
        let restricted_path = toolchain.restricted_child_path(&trusted_path).unwrap();
        Self {
            root,
            stack,
            cargo_proxy,
            rustc_proxy,
            source_cargo,
            source_rustc,
            staged_cargo,
            staged_rustc,
            restricted_path,
            system_root,
            toolchain: Some(toolchain),
        }
    }

    fn launch_policy(&self, adapter_name: &str) -> std::io::Result<CandidateLaunchPolicy> {
        let launcher = self.root.join("hell-ci.exe");
        let adapter = self.root.join(adapter_name);
        fs::write(&launcher, b"launcher")?;
        fs::write(&adapter, b"adapter")?;
        let authorities = WindowsLaunchAuthorities::new(
            launcher.clone(),
            adapter.clone(),
            self.toolchain
                .as_ref()
                .expect("fixture toolchain authority is active")
                .clone(),
        )?;
        CandidateLaunchPolicy::windows(authorities, vec![self.root.clone()])
    }

    fn bind_real_git(&mut self) -> WindowsGitExecutableAuthority {
        let (git, pathext, system_root) = real_git_parent_authorities();
        let git_directory = git.parent().unwrap().to_path_buf();
        let system32 = system_root.join("System32");
        let trusted_path = std::env::join_paths([
            git_directory.as_path(),
            system32.as_path(),
            system_root.as_path(),
        ])
        .unwrap();
        let execution_deadline = Instant::now().checked_add(Duration::from_secs(10)).unwrap();
        let completion_deadline = execution_deadline
            .checked_add(Duration::from_secs(10))
            .unwrap();
        let git = WindowsGitExecutableAuthority::resolve_until(
            &trusted_path,
            &pathext,
            system_root.as_os_str(),
            execution_deadline,
            completion_deadline,
        )
        .unwrap();
        self.release_toolchain();
        let (inventory_root, inventory_files, inventory_directories) =
            inventory(&self.root.join("stage"));
        let mapping = |proxy: &Path, source: &Path, staged: &Path| {
            WindowsToolchainExecutableAuthority::rustup_proxy(
                proxy.to_path_buf(),
                proxy.to_path_buf(),
                source.to_path_buf(),
                staged.to_path_buf(),
            )
        };
        let toolchain = WindowsToolchainAuthority::new_until(
            WindowsToolchainAuthorityInput::new(
                mapping(&self.cargo_proxy, &self.source_cargo, &self.staged_cargo),
                mapping(&self.rustc_proxy, &self.source_rustc, &self.staged_rustc),
                inventory_root,
                inventory_directories,
                trusted_path.clone(),
                system_root.as_os_str().to_os_string(),
            )
            .with_git_authority(git.clone()),
            inventory_files,
            completion_deadline,
        )
        .unwrap();
        self.restricted_path = toolchain.restricted_child_path(&trusted_path).unwrap();
        self.system_root = system_root.into_os_string();
        self.toolchain = Some(toolchain);
        git
    }

    fn release_toolchain(&mut self) {
        drop(self.toolchain.take());
    }

    fn cleanup(&self) -> std::io::Result<()> {
        match fs::remove_dir_all(&self.root) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.release_toolchain();
        if let Err(error) = self.cleanup()
            && !std::thread::panicking()
        {
            panic!(
                "failed to remove Windows restricted-environment fixture {}: {error}",
                self.root.display()
            );
        }
    }
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

fn explicit_environment(command: &Command) -> BTreeMap<OsString, Option<OsString>> {
    command
        .get_envs()
        .map(|(name, value)| (name.to_owned(), value.map(ToOwned::to_owned)))
        .collect()
}

fn release_child_fields(command: &Command) -> Vec<OsString> {
    let encoded = command
        .get_args()
        .nth(1)
        .expect("restricted launcher retains one encoded request");
    let outer = decode_windows_argv(encoded).expect("restricted request must decode");
    outer[2..].to_vec()
}

fn child_presentation(path: &Path) -> PathBuf {
    windows_child_path_presentation_for_integration(path).unwrap()
}

#[test]
fn inherited_current_directory_accepts_raw_and_verbatim_identity_but_explicit_redirects_fail() {
    let fixture = Fixture::new("current-directory-identity");
    let verbatim = fixture.root.clone();
    let rendered = verbatim.to_string_lossy();
    let raw = PathBuf::from(
        rendered
            .strip_prefix(r"\\?\")
            .expect("canonical Windows fixture root must use verbatim syntax"),
    );

    assert_eq!(
        resolve_windows_release_child_current_directory(None, &raw).unwrap(),
        verbatim
    );
    assert_eq!(
        resolve_windows_release_child_current_directory(None, &verbatim).unwrap(),
        verbatim
    );
    let raw_explicit = resolve_windows_release_child_current_directory(Some(&raw), &verbatim)
        .expect_err("an explicit noncanonical cwd must retain the strict caller contract");
    assert_eq!(raw_explicit.kind(), std::io::ErrorKind::InvalidInput);
    assert_eq!(
        raw_explicit.to_string(),
        "Windows release child current directory is redirected"
    );

    let component = verbatim.join("cwd-component");
    fs::create_dir(&component).unwrap();
    let lexical_redirect = component.join("..");
    let lexical_error =
        resolve_windows_release_child_current_directory(Some(&lexical_redirect), &verbatim)
            .expect_err("an explicit lexical cwd redirect must be rejected");
    assert_eq!(lexical_error.kind(), std::io::ErrorKind::InvalidInput);
    assert_eq!(
        lexical_error.to_string(),
        "Windows release child current directory is redirected"
    );

    let substitute = verbatim.join("cwd-substitute");
    symlink_dir(&component, &substitute)
        .expect("Windows hosted verifier must permit its cwd substitution fixture");
    let substitution_error =
        resolve_windows_release_child_current_directory(Some(&substitute), &verbatim)
            .expect_err("an explicit substituted cwd must be rejected");
    assert_eq!(substitution_error.kind(), std::io::ErrorKind::InvalidInput);
    assert_eq!(
        substitution_error.to_string(),
        "Windows release child current directory is redirected"
    );
}

#[test]
fn writable_path_presentation_accepts_only_same_identity_verbatim_drive_authorities() {
    let fixture = Fixture::new("writable-presentation-identity");
    let presentation = child_presentation(&fixture.root);
    assert!(!presentation.to_string_lossy().starts_with(r"\\?\"));
    assert_eq!(fs::canonicalize(&presentation).unwrap(), fixture.root);

    let raw = presentation.clone();
    assert!(windows_child_path_presentation_for_integration(&raw).is_err());
    assert!(
        windows_child_path_presentation_for_integration(Path::new(r"\\?\UNC\server\share"))
            .is_err()
    );
    assert!(windows_child_path_presentation_for_integration(Path::new(r"\\.\C:\device")).is_err());

    let component = fixture.root.join("presentation-component");
    fs::create_dir(&component).unwrap();
    assert!(windows_child_path_presentation_for_integration(&component.join("..")).is_err());
    let substitute = fixture.root.join("presentation-substitute");
    symlink_dir(&component, &substitute).unwrap();
    assert!(windows_child_path_presentation_for_integration(&substitute).is_err());
}

#[test]
fn unmapped_stack_launch_receives_revalidated_path_and_system_root() {
    let fixture = Fixture::new("unmapped");
    let policy = fixture.launch_policy("hell-test-helper.exe").unwrap();
    let mut command = Command::new(&fixture.stack);
    policy.apply_unbound_windows_command(&mut command).unwrap();
    let environment = explicit_environment(&command);

    assert_eq!(environment.len(), 2);
    assert_eq!(
        environment.keys().cloned().collect::<BTreeSet<_>>(),
        [OsString::from("PATH"), OsString::from("SystemRoot")]
            .into_iter()
            .collect()
    );
    assert!(!environment.contains_key(OsStr::new("CARGO_TARGET_DIR")));
    assert_eq!(
        environment.get(OsStr::new("PATH")).map(Option::as_ref),
        Some(Some(&fixture.restricted_path))
    );
    assert_eq!(
        environment
            .get(OsStr::new("SystemRoot"))
            .map(Option::as_ref),
        Some(Some(&fixture.system_root))
    );
    let path = environment
        .get(OsStr::new("PATH"))
        .and_then(Option::as_ref)
        .unwrap();
    let entries = std::env::split_paths(path).collect::<Vec<_>>();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0], fixture.staged_cargo.parent().unwrap());
    assert!(
        !entries
            .iter()
            .any(|entry| entry == fixture.cargo_proxy.parent().unwrap())
    );
}

#[test]
fn mapped_cargo_identity_launch_is_target_free_and_keeps_system_root() {
    let fixture = Fixture::new("mapped");
    let policy = fixture.launch_policy("hell-test-helper.exe").unwrap();
    let static_hash_passes = policy.windows_static_hash_passes_for_integration();
    assert_eq!(static_hash_passes, (1, 1));
    let mut command = Command::new(&fixture.cargo_proxy);
    command.arg("-V");
    policy.apply_unbound_windows_command(&mut command).unwrap();
    let environment = explicit_environment(&command);

    assert_eq!(environment.len(), 2);
    assert_eq!(
        environment.get(OsStr::new("PATH")).map(Option::as_ref),
        Some(Some(&fixture.restricted_path))
    );
    assert_eq!(
        environment
            .get(OsStr::new("SystemRoot"))
            .map(Option::as_ref),
        Some(Some(&fixture.system_root))
    );
    let encoded = command.get_args().nth(1).unwrap();
    let outer = decode_windows_argv(encoded).unwrap();
    let request = parse_windows_release_child_request(outer[2..].to_vec()).unwrap();
    assert_eq!(
        request.target_arguments()[0],
        fixture.staged_cargo.as_os_str()
    );
    assert_eq!(request.target_arguments()[1].as_os_str(), OsStr::new("-V"));
    assert_eq!(request.target_arguments().len(), 2);
    assert!(
        request
            .environment()
            .iter()
            .all(|(name, _)| !name.eq_ignore_ascii_case(OsStr::new("CARGO_TARGET_DIR")))
    );

    let mut long_version = Command::new(&fixture.cargo_proxy);
    long_version.arg("--version");
    policy
        .apply_unbound_windows_command(&mut long_version)
        .unwrap();
    assert_eq!(
        policy.windows_static_hash_passes_for_integration(),
        static_hash_passes,
        "repeated policy wrapping must revalidate retained receipts without full byte hashes"
    );
    let long_version =
        parse_windows_release_child_request(release_child_fields(&long_version)).unwrap();
    assert_eq!(long_version.target_arguments().len(), 2);
    assert_eq!(long_version.target_arguments()[0], fixture.staged_cargo);
    assert_eq!(
        long_version.target_arguments()[1].as_os_str(),
        OsStr::new("--version")
    );
    assert!(
        long_version
            .environment()
            .iter()
            .all(|(name, _)| !name.eq_ignore_ascii_case(OsStr::new("CARGO_TARGET_DIR")))
    );
}

#[test]
fn git_authority_preserves_three_real_argv_and_current_directory_contracts() {
    let mut fixture = Fixture::new("git-authority");
    let git = fixture.bind_real_git();
    let receipt = git.version_receipt();
    assert!(receipt.version.starts_with("git version "));
    assert!(receipt.stdout_bytes <= 256);
    assert_eq!(receipt.stderr_bytes, 0);
    assert!(receipt.termination_reaped);
    let restricted_entries = std::env::split_paths(&fixture.restricted_path).collect::<Vec<_>>();
    assert_eq!(
        restricted_entries
            .iter()
            .filter(|entry| entry.as_path() == git.directory_for_integration())
            .count(),
        1
    );

    let tracked_checkout = fixture.root.join("tracked-checkout");
    let manifest_root = fixture.root.join("manifest-root");
    fs::create_dir(&tracked_checkout).unwrap();
    fs::create_dir(&manifest_root).unwrap();
    let tracked_checkout = fs::canonicalize(tracked_checkout).unwrap();
    let manifest_root = fs::canonicalize(manifest_root).unwrap();
    let inherited_root = fs::canonicalize(std::env::current_dir().unwrap()).unwrap();
    let policy = fixture.launch_policy("git-authority-adapter.exe").unwrap();
    let cases = [
        (
            vec![OsString::from("init"), OsString::from("--quiet")],
            Some(tracked_checkout.as_path()),
            tracked_checkout.as_path(),
        ),
        (
            vec![
                OsString::from("ls-files"),
                OsString::from("-z"),
                OsString::from("--"),
                OsString::from("fixtures/v1"),
            ],
            Some(manifest_root.as_path()),
            manifest_root.as_path(),
        ),
        (
            vec![
                OsString::from("check-ref-format"),
                OsString::from("--branch"),
                OsString::from("main"),
            ],
            None,
            inherited_root.as_path(),
        ),
    ];
    for (arguments, configured_directory, expected_directory) in cases {
        let mut command = Command::new("git");
        command.args(&arguments);
        if let Some(directory) = configured_directory {
            command.current_dir(directory);
        }
        policy.apply_unbound_windows_command(&mut command).unwrap();
        let request = parse_windows_release_child_request(release_child_fields(&command)).unwrap();
        assert_eq!(request.current_directory(), expected_directory);
        assert_eq!(
            request.target_arguments(),
            std::iter::once(git.program_for_integration().as_os_str().to_os_string())
                .chain(arguments)
                .collect::<Vec<_>>()
        );
        let path = request
            .environment()
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(OsStr::new("PATH")))
            .map(|(_, value)| value)
            .unwrap();
        assert_eq!(path, &fixture.restricted_path);
    }

    let wrong_git = fixture.root.join("substituted/git.exe");
    fs::create_dir_all(wrong_git.parent().unwrap()).unwrap();
    fs::copy(git.program_for_integration(), &wrong_git).unwrap();
    let wrong_git = fs::canonicalize(wrong_git).unwrap();
    let mut wrong = Command::new(wrong_git);
    wrong.args(["check-ref-format", "--branch", "main"]);
    assert!(policy.apply_unbound_windows_command(&mut wrong).is_err());
}

#[test]
fn git_requests_reject_missing_duplicate_and_reparse_authority() {
    let fixture = Fixture::new("git-missing");
    let policy = fixture.launch_policy("git-missing-adapter.exe").unwrap();
    let mut missing = Command::new("git");
    missing.args(["init", "--quiet"]).current_dir(&fixture.root);
    assert!(policy.apply_unbound_windows_command(&mut missing).is_err());

    let (git, pathext, system_root) = real_git_parent_authorities();
    let git_directory = git.parent().unwrap();
    let system32 = system_root.join("System32");
    let duplicate = std::env::join_paths([
        git_directory,
        git_directory,
        system32.as_path(),
        system_root.as_path(),
    ])
    .unwrap();
    let execution_deadline = Instant::now().checked_add(Duration::from_secs(10)).unwrap();
    let completion_deadline = execution_deadline
        .checked_add(Duration::from_secs(10))
        .unwrap();
    assert!(
        WindowsGitExecutableAuthority::resolve_until(
            &duplicate,
            &pathext,
            system_root.as_os_str(),
            execution_deadline,
            completion_deadline,
        )
        .is_err()
    );

    let reparse = fixture.root.join("git-reparse");
    symlink_dir(git_directory, &reparse).unwrap();
    let redirected =
        std::env::join_paths([reparse.as_path(), system32.as_path(), system_root.as_path()])
            .unwrap();
    assert!(
        WindowsGitExecutableAuthority::resolve_until(
            &redirected,
            &pathext,
            system_root.as_os_str(),
            execution_deadline,
            completion_deadline,
        )
        .is_err()
    );
}

#[test]
fn mapped_cargo_build_target_is_subcommand_scoped_and_cannot_be_replaced() {
    let fixture = Fixture::new("mapped-target-authority");
    let policy = fixture.launch_policy("hell-test-helper.exe").unwrap();

    let mut replacement = Command::new(&fixture.cargo_proxy);
    replacement
        .arg("build")
        .arg("--target-dir")
        .arg(fixture.root.join("replacement"));
    assert!(
        policy
            .apply_unbound_windows_command(&mut replacement)
            .is_err()
    );
    let mut replacement_equals = Command::new(&fixture.cargo_proxy);
    replacement_equals.args(["build", "--target-dir=replacement"]);
    assert!(
        policy
            .apply_unbound_windows_command(&mut replacement_equals)
            .is_err()
    );

    let mut valid = Command::new(&fixture.cargo_proxy);
    valid.args([
        "build",
        "--release",
        "--locked",
        "--package",
        "hell-cli",
        "--bin",
        "hell",
        "--features",
        "compat-tracing",
    ]);
    policy.apply_unbound_windows_command(&mut valid).unwrap();
    let mut fields = release_child_fields(&valid);
    let environment_count = fields[2].to_str().unwrap().parse::<usize>().unwrap();
    let target_arguments = 3 + environment_count * 2;
    let target_presentation = child_presentation(&fixture.root);
    assert_eq!(fields[target_arguments], fixture.staged_cargo);
    assert_eq!(fields[target_arguments + 1], OsStr::new("build"));
    assert_eq!(fields[target_arguments + 2], OsStr::new("--target-dir"));
    assert_eq!(fields[target_arguments + 3], target_presentation);
    assert_eq!(fields[target_arguments + 4], OsStr::new("--release"));
    let exact = parse_windows_release_child_request(fields.clone()).unwrap();
    assert_eq!(
        exact.cargo_release_target(),
        Some(target_presentation.as_path())
    );

    fields[target_arguments + 3] = fixture.root.join("replacement").into_os_string();
    assert!(parse_windows_release_child_request(fields).is_err());

    let mut wrong_feature = release_child_fields(&valid);
    *wrong_feature.last_mut().unwrap() = OsString::from("different-feature");
    let wrong_feature = parse_windows_release_child_request(wrong_feature).unwrap();
    assert_eq!(wrong_feature.cargo_release_target(), None);
}

#[test]
fn mapped_cargo_test_target_binding_rejects_duplicates_and_environment_conflicts() {
    let fixture = Fixture::new("mapped-test-target-authority");
    let policy = fixture.launch_policy("hell-test-helper.exe").unwrap();

    let mut valid = Command::new(&fixture.cargo_proxy);
    valid.args(["test", "--workspace", "--locked"]);
    policy.apply_unbound_windows_command(&mut valid).unwrap();
    let fields = release_child_fields(&valid);
    let environment_count = fields[2].to_str().unwrap().parse::<usize>().unwrap();
    let target_arguments = 3 + environment_count * 2;
    let target_presentation = child_presentation(&fixture.root);
    assert_eq!(fields[target_arguments], fixture.staged_cargo);
    assert_eq!(fields[target_arguments + 1], OsStr::new("test"));
    assert_eq!(fields[target_arguments + 2], OsStr::new("--target-dir"));
    assert_eq!(fields[target_arguments + 3], target_presentation);
    parse_windows_release_child_request(fields.clone()).unwrap();

    let mut duplicate = fields.clone();
    duplicate.push(OsString::from("--target-dir"));
    duplicate.push(target_presentation.into_os_string());
    assert!(parse_windows_release_child_request(duplicate).is_err());

    let mut duplicate_equals = fields.clone();
    duplicate_equals.push(OsString::from("--target-dir=replacement"));
    assert!(parse_windows_release_child_request(duplicate_equals).is_err());

    let mut conflicting_environment = fields;
    let target_environment = (0..environment_count)
        .map(|index| 3 + index * 2)
        .find(|index| {
            conflicting_environment[*index].eq_ignore_ascii_case(OsStr::new("CARGO_TARGET_DIR"))
        })
        .unwrap();
    conflicting_environment[target_environment + 1] =
        fixture.root.join("replacement").into_os_string();
    assert!(parse_windows_release_child_request(conflicting_environment).is_err());
}

#[test]
fn mapped_cargo_build_presents_every_writable_child_path_without_verbatim_syntax() {
    let fixture = Fixture::new("mapped-native-tool-presentations");
    let policy = fixture.launch_policy("hell-test-helper.exe").unwrap();
    let environment_root = fixture.root.join("release-child-environment");
    let home = environment_root.join("home");
    let cargo = environment_root.join("cargo");
    let sccache = environment_root.join("sccache");
    let mut command = Command::new(&fixture.cargo_proxy);
    command.args(["test", "--workspace", "--locked"]).envs([
        ("HOME", home.as_os_str()),
        ("USERPROFILE", home.as_os_str()),
        ("CARGO_HOME", cargo.as_os_str()),
        ("SCCACHE_DIR", sccache.as_os_str()),
    ]);
    policy.apply_unbound_windows_command(&mut command).unwrap();
    let request = parse_windows_release_child_request(release_child_fields(&command)).unwrap();
    let environment = request
        .environment()
        .iter()
        .map(|(name, value)| {
            (
                name.to_string_lossy().to_ascii_uppercase(),
                PathBuf::from(value),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let canonical_target = fs::canonicalize(&fixture.root).unwrap();
    for name in [
        "CARGO_TARGET_DIR",
        "HOME",
        "USERPROFILE",
        "CARGO_HOME",
        "SCCACHE_DIR",
        "TEMP",
        "TMP",
        "TMPDIR",
    ] {
        let value = &environment[name];
        assert!(value.is_absolute(), "{name} presentation is relative");
        assert!(
            !value.to_string_lossy().starts_with(r"\\?\"),
            "{name} retained verbatim syntax: {value:?}"
        );
        assert!(
            fs::canonicalize(value)
                .unwrap()
                .starts_with(&canonical_target),
            "{name} escaped the target authority"
        );
    }
    assert_eq!(environment["HOME"], environment["USERPROFILE"]);
    assert_eq!(environment["TEMP"], environment["TMP"]);
    assert_eq!(environment["TEMP"], environment["TMPDIR"]);
    assert_eq!(
        request.target_arguments()[3],
        environment["CARGO_TARGET_DIR"]
    );
}

#[test]
fn mapped_cargo_build_rejects_writable_environment_substitution_and_reparse() {
    let fixture = Fixture::new("mapped-native-tool-presentation-negatives");
    let policy = fixture.launch_policy("hell-test-helper.exe").unwrap();
    let environment_root = fixture.root.join("release-child-environment");
    let substitute = fixture.root.join("cargo-substitute");
    fs::create_dir(&substitute).unwrap();

    let mut changed = Command::new(&fixture.cargo_proxy);
    changed
        .arg("build")
        .env("CARGO_HOME", substitute.as_os_str());
    assert!(policy.apply_unbound_windows_command(&mut changed).is_err());

    fs::create_dir_all(&environment_root).unwrap();
    let redirected = environment_root.join("cargo");
    symlink_dir(&substitute, &redirected).unwrap();
    let mut reparse = Command::new(&fixture.cargo_proxy);
    reparse
        .arg("build")
        .env("CARGO_HOME", redirected.as_os_str());
    assert!(policy.apply_unbound_windows_command(&mut reparse).is_err());
}

#[test]
fn typed_git_safe_directory_triplet_is_exact_and_complete() {
    let fixture = Fixture::new("git-safe-directory");
    let policy = fixture.launch_policy("hell-test-helper.exe").unwrap();
    let mut command = Command::new(&fixture.cargo_proxy);
    command.current_dir(&fixture.root).envs([
        ("GIT_CONFIG_COUNT", OsString::from("1")),
        ("GIT_CONFIG_KEY_0", OsString::from("safe.directory")),
        ("GIT_CONFIG_VALUE_0", fixture.root.as_os_str().to_owned()),
    ]);
    policy.apply_unbound_windows_command(&mut command).unwrap();
    let valid = release_child_fields(&command);
    parse_windows_release_child_request(valid.clone()).unwrap();

    for (name, value) in [
        ("GIT_CONFIG_COUNT", OsString::from("2")),
        ("GIT_CONFIG_KEY_0", OsString::from("core.hooksPath")),
        (
            "GIT_CONFIG_VALUE_0",
            fixture.root.join("stage").into_os_string(),
        ),
    ] {
        let mut rejected = Command::new(&fixture.cargo_proxy);
        rejected.current_dir(&fixture.root).envs([
            ("GIT_CONFIG_COUNT", OsString::from("1")),
            ("GIT_CONFIG_KEY_0", OsString::from("safe.directory")),
            ("GIT_CONFIG_VALUE_0", fixture.root.as_os_str().to_owned()),
        ]);
        rejected.env(name, value);
        assert!(policy.apply_unbound_windows_command(&mut rejected).is_err());
    }

    let mut incomplete = Command::new(&fixture.cargo_proxy);
    incomplete
        .current_dir(&fixture.root)
        .env("GIT_CONFIG_COUNT", "1")
        .env("GIT_CONFIG_KEY_0", "safe.directory");
    assert!(
        policy
            .apply_unbound_windows_command(&mut incomplete)
            .is_err()
    );
}

#[test]
fn typed_environment_rejects_noncanonical_count_order_and_case_duplicate() {
    let fixture = Fixture::new("typed-environment-framing");
    let policy = fixture.launch_policy("hell-test-helper.exe").unwrap();
    let mut command = Command::new(&fixture.cargo_proxy);
    command.current_dir(&fixture.root).envs([
        ("GIT_CONFIG_COUNT", OsString::from("1")),
        ("GIT_CONFIG_KEY_0", OsString::from("safe.directory")),
        ("GIT_CONFIG_VALUE_0", fixture.root.as_os_str().to_owned()),
    ]);
    policy.apply_unbound_windows_command(&mut command).unwrap();
    let valid = release_child_fields(&command);
    let count = valid[2].to_str().unwrap().parse::<usize>().unwrap();

    let mut noncanonical_count = valid.clone();
    noncanonical_count[2] = OsString::from(format!("0{count}"));
    assert!(parse_windows_release_child_request(noncanonical_count).is_err());

    let mut noncanonical_order = valid.clone();
    noncanonical_order.swap(3, 5);
    noncanonical_order.swap(4, 6);
    assert!(parse_windows_release_child_request(noncanonical_order).is_err());

    let mut duplicate = valid;
    duplicate[2] = OsString::from((count + 1).to_string());
    duplicate.splice(
        5..5,
        [OsString::from("git_config_count"), OsString::from("1")],
    );
    assert!(parse_windows_release_child_request(duplicate).is_err());
}

#[test]
fn restricted_policy_requires_the_exact_adapter_basename() {
    let fixture = Fixture::new("exact-adapter-name");
    let policy = fixture.launch_policy("hell-test-helper.exe").unwrap();
    drop(policy);

    let error = fixture.launch_policy("renamed-helper.exe").unwrap_err();
    assert_eq!(
        error.to_string(),
        "restricted argv adapter has the wrong executable name"
    );
}

#[test]
fn fixture_cleanup_does_not_double_panic_during_unwind() {
    let retained_root = std::cell::RefCell::new(None);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut fixture = Fixture::new("unwind-safe-cleanup");
        retained_root.replace(Some(fixture.root.clone()));
        fixture.release_toolchain();
        fixture.cleanup().unwrap();
        fs::write(&fixture.root, b"force remove_dir_all failure").unwrap();
        panic!("primary fixture test panic");
    }));

    let payload = result.unwrap_err();
    assert_eq!(
        payload.downcast_ref::<&str>(),
        Some(&"primary fixture test panic")
    );
    fs::remove_file(retained_root.into_inner().unwrap()).unwrap();
}

#[test]
fn fixture_cleanup_surfaces_failure_outside_unwind() {
    let mut fixture = Fixture::new("cleanup-failure");
    fixture.release_toolchain();
    fixture.cleanup().unwrap();
    fs::write(&fixture.root, b"force remove_dir_all failure").unwrap();

    let error = fixture.cleanup().unwrap_err();
    assert_ne!(error.kind(), std::io::ErrorKind::NotFound);

    fs::remove_file(&fixture.root).unwrap();
}
