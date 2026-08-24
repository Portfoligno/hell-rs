#![cfg(windows)]

use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::windows::fs::{symlink_dir, symlink_file};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hell_testkit::{
    BoundedCapture, SupervisedOutput, WindowsCargoReleaseReceipt, WindowsReleaseBinaryCheckpoint,
    cleanup_windows_release_child_temp_authority, encode_windows_argv,
    parse_windows_release_child_request, prepare_windows_cargo_release_receipt,
    publish_windows_cargo_release_receipt, run_supervised_command_until,
    windows_release_child_request_fields_for_integration,
};

static CHILD_TEMP_ID: AtomicU64 = AtomicU64::new(0);
const CHILD_EXECUTION_BUDGET: Duration = Duration::from_secs(30);
const CHILD_COMPLETION_RESERVE: Duration = Duration::from_secs(15);

struct Fixture {
    root: PathBuf,
    non_verbatim_root: PathBuf,
}

fn release_child_output(
    current_directory: &std::path::Path,
    environment: &[(OsString, OsString)],
    target_arguments: &[OsString],
) -> SupervisedOutput {
    let mut environment = environment.to_vec();
    if let Some(target) = environment
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(OsStr::new("CARGO_TARGET_DIR")))
        .map(|(_, value)| PathBuf::from(value))
    {
        let parent = target.join("release-child-environment").join("tmp");
        fs::create_dir_all(&parent).unwrap();
        let sequence = CHILD_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let temporary = parent.join(format!("child-{}-{sequence}", std::process::id()));
        fs::create_dir(&temporary).unwrap();
        environment.extend(
            ["TEMP", "TMP", "TMPDIR"]
                .map(|name| (OsString::from(name), temporary.as_os_str().to_owned())),
        );
    }
    let fields = windows_release_child_request_fields_for_integration(
        current_directory,
        environment,
        target_arguments,
    )
    .unwrap();
    let encoded = encode_windows_argv(&fields).unwrap();
    let helper = fs::canonicalize(env!("CARGO_BIN_EXE_hell-test-helper")).unwrap();
    let mut command = Command::new(helper);
    command.args([OsStr::new("__release-argv-child"), encoded.as_os_str()]);
    run_terminal_command(&mut command)
}

fn system_root_environment() -> Vec<(OsString, OsString)> {
    std::env::var_os("SystemRoot")
        .map(|value| vec![(OsString::from("SystemRoot"), value)])
        .unwrap_or_default()
}

fn exact_cargo_arguments(cargo: &std::path::Path, target: &std::path::Path) -> Vec<OsString> {
    [
        cargo.as_os_str().to_owned(),
        OsString::from("build"),
        OsString::from("--target-dir"),
        target.as_os_str().to_owned(),
        OsString::from("--release"),
        OsString::from("--locked"),
        OsString::from("--package"),
        OsString::from("hell-cli"),
        OsString::from("--bin"),
        OsString::from("hell"),
        OsString::from("--features"),
        OsString::from("compat-tracing"),
    ]
    .into()
}

fn cargo_child_fields(fixture: &Fixture) -> (Vec<OsString>, PathBuf) {
    let helper = fs::canonicalize(env!("CARGO_BIN_EXE_hell-test-helper")).unwrap();
    let cargo_directory = fixture.root.join(format!(
        "cargo-fields-{}",
        CHILD_TEMP_ID.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&cargo_directory).unwrap();
    let cargo = cargo_directory.join("cargo.exe");
    fs::copy(helper, &cargo).unwrap();
    let cargo = fs::canonicalize(cargo).unwrap();
    let target = fixture.root.join(format!(
        "fields-target-{}",
        CHILD_TEMP_ID.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&target).unwrap();
    let target = fs::canonicalize(target).unwrap();
    let parent = target.join("release-child-environment").join("tmp");
    fs::create_dir_all(&parent).unwrap();
    let temporary = parent.join(format!(
        "child-{}-{}",
        std::process::id(),
        CHILD_TEMP_ID.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&temporary).unwrap();
    let temporary = fs::canonicalize(temporary).unwrap();
    let mut environment = system_root_environment();
    environment.push((
        OsString::from("CARGO_TARGET_DIR"),
        target.as_os_str().to_owned(),
    ));
    environment.push((OsString::from("SOURCE_DATE_EPOCH"), OsString::from("1")));
    environment.extend(
        ["TEMP", "TMP", "TMPDIR"]
            .map(|name| (OsString::from(name), temporary.as_os_str().to_owned())),
    );
    let fields = windows_release_child_request_fields_for_integration(
        &fixture.root,
        environment,
        &exact_cargo_arguments(&cargo, &target),
    )
    .unwrap();
    (fields, temporary)
}

fn release_child_output_from_fields(fields: &[OsString]) -> SupervisedOutput {
    let encoded = encode_windows_argv(fields).unwrap();
    let helper = fs::canonicalize(env!("CARGO_BIN_EXE_hell-test-helper")).unwrap();
    let mut command = Command::new(helper);
    command.args([OsStr::new("__release-argv-child"), encoded.as_os_str()]);
    run_terminal_command(&mut command)
}

fn run_terminal_command(command: &mut Command) -> SupervisedOutput {
    let execution_deadline = Instant::now()
        .checked_add(CHILD_EXECUTION_BUDGET)
        .expect("Windows checkpoint execution deadline overflowed");
    let completion_deadline = execution_deadline
        .checked_add(CHILD_COMPLETION_RESERVE)
        .expect("Windows checkpoint completion deadline overflowed");
    let output =
        run_supervised_command_until(command, &[], execution_deadline, completion_deadline, None)
            .expect("supervise Windows checkpoint command");
    assert!(!output.timed_out, "Windows checkpoint command timed out");
    assert!(
        output
            .termination
            .as_ref()
            .is_some_and(|termination| termination.reaped),
        "Windows checkpoint command was not reaped"
    );
    let mut previous = None;
    for expected in [
        "leader-exited",
        "tree-terminated",
        "quiescence-complete",
        "stdout-joined",
        "stderr-joined",
        "stdin-joined",
    ] {
        let position = output
            .phase_timings
            .iter()
            .position(|phase| phase.name == expected)
            .unwrap_or_else(|| panic!("Windows checkpoint command lacks {expected} receipt"));
        assert!(
            previous.is_none_or(|previous| previous < position),
            "Windows checkpoint command receipt order differs at {expected}"
        );
        previous = Some(position);
    }
    assert_eq!(
        output.phase_timings.last().map(|phase| phase.name),
        Some("stdin-joined")
    );
    output
}

fn complete_capture(capture: &BoundedCapture) -> &[u8] {
    assert!(
        !capture.truncated,
        "Windows checkpoint capture was truncated"
    );
    capture
        .complete
        .as_deref()
        .expect("Windows checkpoint capture is incomplete")
}

#[test]
fn restricted_helper_publishes_receipt_only_for_successful_exact_cargo_artifact() {
    let fixture = Fixture::new();
    let helper = fs::canonicalize(env!("CARGO_BIN_EXE_hell-test-helper")).unwrap();
    let environment = |target: &std::path::Path| {
        let mut environment = system_root_environment();
        environment.push((
            OsString::from("CARGO_TARGET_DIR"),
            target.as_os_str().to_owned(),
        ));
        environment.push((OsString::from("SOURCE_DATE_EPOCH"), OsString::from("1")));
        environment
    };

    let cargo_directory = fixture.root.join("cargo-success");
    fs::create_dir(&cargo_directory).unwrap();
    let cargo = cargo_directory.join("cargo.exe");
    fs::copy(&helper, &cargo).unwrap();
    let cargo = fs::canonicalize(cargo).unwrap();
    let target = fixture.root.join("helper-success-target");
    fs::create_dir(&target).unwrap();
    let target = fs::canonicalize(target).unwrap();
    let successful = release_child_output(
        &fixture.root,
        &environment(&target),
        &exact_cargo_arguments(&cargo, &target),
    );
    assert!(successful.status.success());
    assert!(
        String::from_utf8(complete_capture(&successful.stderr).to_vec())
            .unwrap()
            .contains("windows argv adapter phase=release-target-attested")
    );
    WindowsCargoReleaseReceipt::load(&target).unwrap();

    let no_output_directory = fixture.root.join("cargo-no-output");
    fs::create_dir(&no_output_directory).unwrap();
    let no_output_cargo = no_output_directory.join("cargo.exe");
    fs::copy(&helper, &no_output_cargo).unwrap();
    let no_output_cargo = fs::canonicalize(no_output_cargo).unwrap();
    let missing_target = fixture.root.join("helper-missing-target");
    fs::create_dir(&missing_target).unwrap();
    let missing_target = fs::canonicalize(missing_target).unwrap();
    assert!(
        !release_child_output(
            &fixture.root,
            &environment(&missing_target),
            &exact_cargo_arguments(&no_output_cargo, &missing_target),
        )
        .status
        .success()
    );
    assert!(WindowsCargoReleaseReceipt::load(&missing_target).is_err());

    let stack = fixture.root.join("stack.exe");
    fs::copy(&helper, &stack).unwrap();
    let unrelated_target = fixture.root.join("unrelated-target");
    fs::create_dir(&unrelated_target).unwrap();
    assert!(
        release_child_output(
            &fixture.root,
            &system_root_environment(),
            &[
                fs::canonicalize(stack).unwrap().into_os_string(),
                OsString::from("__windows-status-zero"),
            ],
        )
        .status
        .success()
    );
    assert!(WindowsCargoReleaseReceipt::load(&unrelated_target).is_err());
}

#[test]
fn cargo_child_temp_request_rejects_split_environment_and_identity_substitution() {
    let fixture = Fixture::new();
    let (fields, temporary) = cargo_child_fields(&fixture);

    let mut split = fields.clone();
    let tmpdir = split
        .iter()
        .position(|field| field == "TMPDIR")
        .expect("typed request contains TMPDIR");
    split[tmpdir + 1] = temporary
        .parent()
        .expect("temp authority has parent")
        .join("sibling")
        .into_os_string();
    let error = parse_windows_release_child_request(split).unwrap_err();
    assert!(error.to_string().contains("temp environment differs"));

    let displaced = temporary.with_file_name("displaced-child-temp");
    fs::rename(&temporary, &displaced).unwrap();
    fs::create_dir(&temporary).unwrap();
    let error = parse_windows_release_child_request(fields).unwrap_err();
    assert!(error.to_string().contains("serialized identity changed"));
}

#[test]
fn cargo_child_temp_cleanup_rejects_unexpected_members_then_receipts_absence() {
    let fixture = Fixture::new();
    let (fields, temporary) = cargo_child_fields(&fixture);
    let request = parse_windows_release_child_request(fields).unwrap();
    let unexpected = temporary.join("unexpected-linker-member.tmp");
    fs::write(&unexpected, b"retained").unwrap();
    let error = cleanup_windows_release_child_temp_authority(&request).unwrap_err();
    assert!(error.to_string().contains("unexpected member"));
    fs::remove_file(unexpected).unwrap();
    cleanup_windows_release_child_temp_authority(&request).unwrap();
    assert!(!temporary.exists());
}

#[test]
fn cargo_child_temp_probe_rejects_a_dacl_without_child_write_authority() {
    let fixture = Fixture::new();
    let (fields, temporary) = cargo_child_fields(&fixture);
    let system_root = PathBuf::from(std::env::var_os("SystemRoot").expect("SystemRoot"));
    let whoami = fs::canonicalize(system_root.join("System32/whoami.exe")).unwrap();
    let mut command = Command::new(whoami);
    command.args(["/user", "/fo", "csv", "/nh"]);
    let identity = run_terminal_command(&mut command);
    assert!(identity.status.success());
    let identity = String::from_utf8(complete_capture(&identity.stdout).to_vec()).unwrap();
    let sid = identity
        .trim()
        .split(',')
        .nth(1)
        .expect("whoami CSV contains SID")
        .trim_matches('"');
    let icacls = fs::canonicalize(system_root.join("System32/icacls.exe")).unwrap();
    let deny = format!("*{sid}:(F)");
    let mut command = Command::new(&icacls);
    command
        .arg(&temporary)
        .args(["/inheritance:r", "/deny", &deny]);
    let denied = run_terminal_command(&mut command);
    assert!(denied.status.success());
    let output = release_child_output_from_fields(&fields);
    let mut command = Command::new(icacls);
    command.arg(&temporary).arg("/reset");
    let reset = run_terminal_command(&mut command);
    assert!(reset.status.success());
    assert!(!output.status.success());
}

impl Fixture {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock must follow the Unix epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "hell-windows-release-checkpoint-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        let canonical_root = fs::canonicalize(&root).unwrap();
        Self {
            root: canonical_root,
            non_verbatim_root: root,
        }
    }

    fn artifact(&self, target_name: &str) -> (PathBuf, PathBuf) {
        let target = self.root.join(target_name);
        let binary = target.join("release/hell.exe");
        fs::create_dir_all(binary.parent().unwrap()).unwrap();
        fs::write(&binary, b"candidate executable").unwrap();
        (target, binary)
    }

    fn receipt(target: &std::path::Path) -> WindowsCargoReleaseReceipt {
        prepare_windows_cargo_release_receipt(target).unwrap();
        publish_windows_cargo_release_receipt(target).unwrap();
        WindowsCargoReleaseReceipt::load(target).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn release_receipt_closes_mutable_publisher_before_immutable_binding() {
    let fixture = Fixture::new();
    let (target, _) = fixture.artifact("publisher-transition-target");
    prepare_windows_cargo_release_receipt(&target).unwrap();
    publish_windows_cargo_release_receipt(&target).unwrap();

    let receipt = WindowsCargoReleaseReceipt::load(&target).unwrap();
    let receipt_path = target.join(".hell-cargo-release-receipt-v1");
    let error = fs::OpenOptions::new()
        .write(true)
        .open(receipt_path)
        .unwrap_err();
    assert_eq!(error.raw_os_error(), Some(32));
    drop(receipt);
}

#[test]
fn release_binary_checkpoint_denies_mutation_and_remains_exact() {
    let fixture = Fixture::new();
    let (target, binary) = fixture.artifact("candidate-target");
    let authority = WindowsReleaseBinaryCheckpoint::capture(
        target.clone(),
        binary.clone(),
        Some(target.clone()),
        Some(Fixture::receipt(&target)),
        "after release-build",
        true,
    )
    .unwrap();
    authority.validate("after release-build", true).unwrap();

    let deletion = fs::remove_file(&binary).unwrap_err();
    assert_eq!(deletion.raw_os_error(), Some(32));
    let replacement = fs::write(&binary, b"replacement executable").unwrap_err();
    assert_eq!(replacement.raw_os_error(), Some(32));
    authority
        .validate("after denied mutation attempts", true)
        .unwrap();
    assert_eq!(fs::read(&binary).unwrap(), b"candidate executable");
}

#[test]
fn release_binary_checkpoint_reports_exact_initially_missing_artifact_context() {
    let fixture = Fixture::new();
    let target = fixture.root.join("candidate-missing-artifact-target");
    fs::create_dir_all(target.join("release")).unwrap();
    let binary = target.join("release").join("hell.exe");
    let error = WindowsReleaseBinaryCheckpoint::capture(
        target.clone(),
        binary.clone(),
        Some(target.clone()),
        None,
        "after release-build",
        true,
    )
    .unwrap_err();
    assert!(error.contains("checkpoint=\"after release-build\""));
    assert!(error.contains(&format!("expectedPath={}", binary.display())));
    assert!(error.contains(&format!("candidateTargetBinding={}", target.display())));
    assert!(error.contains("releaseBuildPassed=true"));
    assert!(error.contains("expectedIdentity=<unavailable>"));
    assert!(error.contains("observedIdentity=<unavailable>"));
    assert!(error.contains("targetInventory="));
    assert!(error.contains("releaseInventory=[]"));
    assert!(error.contains("cannot inspect release binary"));
}

#[test]
fn release_binary_checkpoint_rejects_initially_missing_release_directory() {
    let fixture = Fixture::new();
    let target = fixture.root.join("missing-target");
    fs::create_dir(&target).unwrap();
    let binary = target.join("release/hell.exe");
    let error = WindowsReleaseBinaryCheckpoint::capture(
        target.clone(),
        binary.clone(),
        Some(target.clone()),
        None,
        "after release-build",
        true,
    )
    .unwrap_err();
    assert!(error.contains("checkpoint=\"after release-build\""));
    assert!(error.contains(&format!("expectedPath={}", binary.display())));
    assert!(error.contains("observedIdentity=<unavailable>"));
    assert!(error.contains("cannot inspect release target directory"));
}

#[test]
fn release_binary_checkpoint_rejects_missing_and_mismatched_build_receipts() {
    let fixture = Fixture::new();
    let (target, binary) = fixture.artifact("receipt-target");
    let error = WindowsReleaseBinaryCheckpoint::capture(
        target.clone(),
        binary.clone(),
        Some(target.clone()),
        None,
        "after release-build",
        true,
    )
    .unwrap_err();
    assert!(error.contains("successful restricted Cargo release receipt is absent"));

    let (other_target, _) = fixture.artifact("other-receipt-target");
    let other_receipt = Fixture::receipt(&other_target);
    let error = WindowsReleaseBinaryCheckpoint::capture(
        target.clone(),
        binary,
        Some(target),
        Some(other_receipt),
        "after release-build",
        true,
    )
    .unwrap_err();
    assert!(error.contains("restricted Cargo release receipt target or artifact differs"));
}

#[test]
fn release_binary_checkpoint_rejects_target_binding_mismatch_and_redirect() {
    let fixture = Fixture::new();
    let (target, binary) = fixture.artifact("bound-target");
    let other = fixture.root.join("other-target");
    let error = WindowsReleaseBinaryCheckpoint::capture(
        target.clone(),
        binary,
        Some(other.clone()),
        Some(Fixture::receipt(&target)),
        "after release-build",
        true,
    )
    .unwrap_err();
    assert!(error.contains(&format!("candidateTargetBinding={}", other.display())));
    assert!(error.contains("candidate target environment binding differs"));

    let (authoritative_target, _) = fixture.artifact("redirected-target");
    fs::create_dir(fixture.non_verbatim_root.join("redirect-component")).unwrap();
    let lexically_equivalent_target = fixture
        .non_verbatim_root
        .join("redirect-component")
        .join("..")
        .join("redirected-target");
    assert_ne!(lexically_equivalent_target, authoritative_target);
    assert_eq!(
        fs::canonicalize(&lexically_equivalent_target).unwrap(),
        authoritative_target
    );
    let lexically_equivalent_binary = lexically_equivalent_target.join("release").join("hell.exe");
    let error = WindowsReleaseBinaryCheckpoint::capture(
        lexically_equivalent_target.clone(),
        lexically_equivalent_binary.clone(),
        Some(lexically_equivalent_target.clone()),
        None,
        "after release-build",
        true,
    )
    .unwrap_err();
    assert!(error.contains("candidate release target is redirected"));
    assert!(!error.contains("candidate release target is not a real directory"));
    assert!(error.contains("checkpoint=\"after release-build\""));
    assert!(error.contains(&format!(
        "expectedPath={}",
        lexically_equivalent_binary.display()
    )));
    assert!(error.contains(&format!(
        "candidateTargetBinding={}",
        lexically_equivalent_target.display()
    )));

    let redirected_target = fixture.root.join("reparse-target");
    fs::create_dir(&redirected_target).unwrap();
    symlink_dir(
        authoritative_target.join("release"),
        redirected_target.join("release"),
    )
    .expect("Windows hosted verifier must permit its typed directory redirect fixture");
    let redirected_binary = redirected_target.join("release/hell.exe");
    let error = WindowsReleaseBinaryCheckpoint::capture(
        redirected_target.clone(),
        redirected_binary,
        Some(redirected_target.clone()),
        None,
        "after release-build",
        true,
    )
    .unwrap_err();
    assert!(error.contains("candidate release target is not a real directory"));
    assert!(!error.contains("candidate release target is redirected"));
    assert!(error.contains("checkpoint=\"after release-build\""));
    assert!(error.contains(&format!(
        "expectedPath={}",
        redirected_target.join("release").join("hell.exe").display()
    )));
    assert!(error.contains(&format!(
        "candidateTargetBinding={}",
        redirected_target.display()
    )));
}

#[test]
fn release_binary_checkpoint_rejects_file_reparse_redirect() {
    let fixture = Fixture::new();
    let target = fixture.root.join("file-reparse-target");
    let release = target.join("release");
    fs::create_dir_all(&release).unwrap();
    let redirected = fixture.root.join("redirected-hell.exe");
    fs::write(&redirected, b"redirected executable").unwrap();
    let binary = release.join("hell.exe");
    symlink_file(&redirected, &binary)
        .expect("Windows hosted verifier must permit its typed file redirect fixture");
    let error = WindowsReleaseBinaryCheckpoint::capture(
        target.clone(),
        binary,
        Some(target),
        None,
        "after release-build",
        true,
    )
    .unwrap_err();
    assert!(error.contains("candidate release binary is not a real file"));
}

#[test]
fn release_build_receipt_rejects_stale_creation_and_post_load_tampering() {
    let fixture = Fixture::new();
    let (target, binary) = fixture.artifact("tamper-target");
    prepare_windows_cargo_release_receipt(&target).unwrap();
    let receipt_path = target.join(".hell-cargo-release-receipt-v1");
    fs::write(&receipt_path, b"untrusted stale receipt\n").unwrap();
    let error = publish_windows_cargo_release_receipt(&target).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);

    prepare_windows_cargo_release_receipt(&target).unwrap();
    publish_windows_cargo_release_receipt(&target).unwrap();
    let receipt = WindowsCargoReleaseReceipt::load(&target).unwrap();
    let authority = WindowsReleaseBinaryCheckpoint::capture(
        target.clone(),
        binary,
        Some(target),
        Some(receipt),
        "after release-build",
        true,
    )
    .unwrap();
    assert!(fs::write(&receipt_path, b"tampered receipt\n").is_err());
    authority
        .validate("after rejected receipt tamper", true)
        .unwrap();

    let retained_copy = fixture.root.join("retained-copy.exe");
    authority.copy_bound_binary(&retained_copy).unwrap();
    assert_eq!(fs::read(retained_copy).unwrap(), b"candidate executable");
}

#[test]
fn release_binary_checkpoint_blocks_identity_replacement_and_in_place_mutation() {
    let fixture = Fixture::new();
    let (target, binary) = fixture.artifact("replacement-target");
    let authority = WindowsReleaseBinaryCheckpoint::capture(
        target.clone(),
        binary.clone(),
        Some(target.clone()),
        Some(Fixture::receipt(&target)),
        "after release-build",
        true,
    )
    .unwrap();
    assert!(fs::remove_file(&binary).is_err());
    authority
        .validate("after rejected identity replacement", true)
        .unwrap();

    let (target, binary) = fixture.artifact("mutation-target");
    let authority = WindowsReleaseBinaryCheckpoint::capture(
        target.clone(),
        binary.clone(),
        Some(target.clone()),
        Some(Fixture::receipt(&target)),
        "after release-build",
        true,
    )
    .unwrap();
    assert!(fs::write(&binary, b"mutated executable bytes").is_err());
    authority
        .validate("after rejected in-place mutation", true)
        .unwrap();
}
