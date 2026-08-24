#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::io::{Read as _, Write as _};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
#[cfg(unix)]
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::Command;
#[cfg(unix)]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(unix)]
use std::time::Duration;

#[cfg(unix)]
static RECEIPT_FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[cfg(unix)]
const MAX_RECEIPT_FIXTURE_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;

#[cfg(unix)]
struct ReceiptFixture {
    root: PathBuf,
    cleanup_complete: bool,
}

#[cfg(unix)]
impl ReceiptFixture {
    fn new() -> Result<Self, String> {
        let parent = fs::canonicalize(std::env::temp_dir())
            .map_err(|error| format!("cannot canonicalize receipt fixture parent: {error}"))?;
        for _ in 0..32 {
            let sequence = RECEIPT_FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let root = parent.join(format!(
                "hell-ci-posix-driver-receipt-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&root) {
                Ok(()) => {
                    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                        .map_err(|error| format!("cannot make receipt fixture private: {error}"))?;
                    let metadata = fs::symlink_metadata(&root).map_err(|error| {
                        format!("cannot inspect private receipt fixture: {error}")
                    })?;
                    if metadata.file_type().is_symlink()
                        || !metadata.is_dir()
                        || metadata.permissions().mode() & 0o7777 != 0o700
                        || fs::canonicalize(&root).map_err(|error| {
                            format!("cannot canonicalize private receipt fixture: {error}")
                        })? != root
                    {
                        return Err("private receipt fixture authority differs".to_owned());
                    }
                    return Ok(Self {
                        root,
                        cleanup_complete: false,
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(format!("cannot create private receipt fixture: {error}"));
                }
            }
        }
        Err("receipt fixture allocation exhausted its collision bound".to_owned())
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    fn cleanup(&mut self) -> Result<(), String> {
        if self.cleanup_complete {
            return Err("receipt fixture cleanup ran more than once".to_owned());
        }
        fs::remove_dir_all(&self.root)
            .map_err(|error| format!("cannot remove receipt fixture: {error}"))?;
        if fs::symlink_metadata(&self.root).is_ok() {
            return Err("receipt fixture remained after cleanup".to_owned());
        }
        self.cleanup_complete = true;
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for ReceiptFixture {
    fn drop(&mut self) {
        if !self.cleanup_complete {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

#[cfg(unix)]
fn stage_exact_receipt_executable(source: &Path, destination: &Path) -> Result<(), String> {
    let before = fs::symlink_metadata(source)
        .map_err(|error| format!("cannot inspect receipt fixture source: {error}"))?;
    if before.file_type().is_symlink()
        || !before.is_file()
        || before.nlink() == 0
        || before.len() == 0
        || before.len() > MAX_RECEIPT_FIXTURE_EXECUTABLE_BYTES
    {
        return Err("receipt fixture source is not a bounded stable-linked real file".to_owned());
    }
    let source_digest = hell_testkit::sha256_file(source)
        .map_err(|error| format!("cannot hash receipt fixture source: {error}"))?;
    let mut source_file = fs::File::open(source)
        .map_err(|error| format!("cannot open receipt fixture source: {error}"))?;
    let opened = source_file
        .metadata()
        .map_err(|error| format!("cannot bind opened receipt fixture source: {error}"))?;
    if !opened.is_file()
        || opened.dev() != before.dev()
        || opened.ino() != before.ino()
        || opened.uid() != before.uid()
        || opened.gid() != before.gid()
        || opened.mode() != before.mode()
        || opened.len() != before.len()
        || opened.nlink() != before.nlink()
    {
        return Err("opened receipt fixture source differs from its path receipt".to_owned());
    }
    let mut destination_file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o700)
        .open(destination)
        .map_err(|error| format!("cannot create receipt fixture executable: {error}"))?;
    let copy_limit = before
        .len()
        .checked_add(1)
        .ok_or_else(|| "receipt fixture copy bound overflowed".to_owned())?;
    let copied = std::io::copy(
        &mut (&mut source_file).take(copy_limit),
        &mut destination_file,
    )
    .map_err(|error| format!("cannot copy receipt fixture executable: {error}"))?;
    destination_file
        .flush()
        .map_err(|error| format!("cannot flush receipt fixture executable: {error}"))?;
    drop(destination_file);
    let opened_after = source_file
        .metadata()
        .map_err(|error| format!("cannot revalidate opened receipt fixture source: {error}"))?;
    let after = fs::symlink_metadata(source)
        .map_err(|error| format!("cannot revalidate receipt fixture source: {error}"))?;
    let staged = fs::symlink_metadata(destination)
        .map_err(|error| format!("cannot inspect receipt fixture executable: {error}"))?;
    let source_digest_after = hell_testkit::sha256_file(source)
        .map_err(|error| format!("cannot rehash receipt fixture source: {error}"))?;
    let staged_digest = hell_testkit::sha256_file(destination)
        .map_err(|error| format!("cannot hash receipt fixture executable: {error}"))?;
    if copied != before.len()
        || !opened_after.is_file()
        || opened_after.dev() != before.dev()
        || opened_after.ino() != before.ino()
        || opened_after.uid() != before.uid()
        || opened_after.gid() != before.gid()
        || opened_after.mode() != before.mode()
        || opened_after.len() != before.len()
        || opened_after.nlink() != before.nlink()
        || after.dev() != before.dev()
        || after.ino() != before.ino()
        || after.uid() != before.uid()
        || after.gid() != before.gid()
        || after.mode() != before.mode()
        || after.len() != before.len()
        || after.nlink() != before.nlink()
        || source_digest_after != source_digest
        || staged.file_type().is_symlink()
        || !staged.is_file()
        || staged.nlink() != 1
        || staged.len() != before.len()
        || staged_digest != source_digest
    {
        return Err("receipt fixture executable differs from its exact source".to_owned());
    }
    Ok(())
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReceiptSourceIdentity {
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    len: u64,
    nlink: u64,
}

#[cfg(unix)]
impl ReceiptSourceIdentity {
    fn capture(path: &Path, label: &str) -> Result<Self, String> {
        let metadata =
            fs::symlink_metadata(path).map_err(|error| format!("cannot bind {label}: {error}"))?;
        Ok(Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode: metadata.mode(),
            len: metadata.len(),
            nlink: metadata.nlink(),
        })
    }
}

#[cfg(unix)]
struct HardLinkedReceiptSource {
    identity: ReceiptSourceIdentity,
    digest: hell_testkit::Digest,
}

#[cfg(unix)]
impl HardLinkedReceiptSource {
    fn establish(cargo_source: &Path, source: &Path, alias: &Path) -> Result<Self, String> {
        stage_exact_receipt_executable(cargo_source, source)?;
        fs::hard_link(source, alias)
            .map_err(|error| format!("cannot hard-link receipt fixture source: {error}"))?;
        let identity =
            ReceiptSourceIdentity::capture(source, "hard-linked receipt fixture source")?;
        let alias_identity = ReceiptSourceIdentity::capture(alias, "receipt fixture source alias")?;
        if identity != alias_identity || identity.nlink != 2 {
            return Err("receipt fixture source hard-link identity differs".to_owned());
        }
        let digest = hell_testkit::sha256_file(source)
            .map_err(|error| format!("cannot hash hard-linked receipt fixture source: {error}"))?;
        let alias_digest = hell_testkit::sha256_file(alias)
            .map_err(|error| format!("cannot hash receipt fixture source alias: {error}"))?;
        if digest != alias_digest {
            return Err("receipt fixture source hard-link bytes differ".to_owned());
        }
        Ok(Self { identity, digest })
    }

    fn require_unchanged(&self, source: &Path, alias: &Path) -> Result<(), String> {
        let source_identity = ReceiptSourceIdentity::capture(
            source,
            "revalidated hard-linked receipt fixture source",
        )?;
        let alias_identity =
            ReceiptSourceIdentity::capture(alias, "revalidated receipt fixture source alias")?;
        let source_digest = hell_testkit::sha256_file(source).map_err(|error| {
            format!("cannot rehash hard-linked receipt fixture source: {error}")
        })?;
        let alias_digest = hell_testkit::sha256_file(alias)
            .map_err(|error| format!("cannot rehash receipt fixture source alias: {error}"))?;
        if source_identity != self.identity
            || alias_identity != self.identity
            || source_digest != self.digest
            || alias_digest != self.digest
        {
            return Err("receipt fixture source or hard-link alias changed".to_owned());
        }
        Ok(())
    }
}

#[cfg(unix)]
fn receipt_arguments(executable: &Path) -> Result<[std::ffi::OsString; 9], String> {
    let executable = fs::canonicalize(executable)
        .map_err(|error| format!("cannot canonicalize receipt fixture executable: {error}"))?;
    let metadata = fs::symlink_metadata(&executable)
        .map_err(|error| format!("cannot bind receipt fixture executable: {error}"))?;
    let digest = hell_testkit::sha256_file(&executable)
        .map_err(|error| format!("cannot hash receipt fixture executable: {error}"))?;
    Ok([
        "posix-driver-receipt-v1".into(),
        executable.as_os_str().to_owned(),
        metadata.dev().to_string().into(),
        metadata.ino().to_string().into(),
        metadata.uid().to_string().into(),
        metadata.gid().to_string().into(),
        (metadata.mode() & 0o7777).to_string().into(),
        digest.hex().into(),
        "fixture".into(),
    ])
}

#[cfg(unix)]
fn run_receipt_verifier(
    executable: &Path,
    arguments: &[std::ffi::OsString; 9],
    context: &str,
) -> Result<hell_testkit::SupervisedOutput, String> {
    let mut command = Command::new(executable);
    command
        .arg("__verify-posix-candidate-driver-receipt")
        .args(arguments);
    let output = hell_testkit::run_supervised_command(&mut command, &[], Duration::from_secs(30))
        .map_err(|error| format!("{context} must execute: {error}"))?;
    if output.timed_out
        || !output
            .phase_timings
            .iter()
            .any(|phase| phase.name == "quiescence-complete")
        || output.phase_timings.last().map(|phase| phase.name) != Some("stdin-joined")
    {
        return Err(format!("{context} lacks its terminal supervision receipt"));
    }
    Ok(output)
}

#[cfg(unix)]
fn require_receipt_rejection(
    executable: &Path,
    arguments: &[std::ffi::OsString; 9],
    context: &str,
) -> Result<(), String> {
    let output = run_receipt_verifier(executable, arguments, context)?;
    let error = stderr(&output);
    if output.status.success() || !error.contains("lacks its driver-owned pre-candidate receipt") {
        return Err(format!("{context} was not rejected: {error}"));
    }
    Ok(())
}

#[cfg(unix)]
fn combine_fixture_failures(
    primary: Result<(), String>,
    cleanup: Result<(), String>,
) -> Result<(), String> {
    match (primary, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(()), Err(cleanup)) => Err(cleanup),
        (Err(primary), Err(cleanup)) => Err(format!("{primary}; cleanup also failed: {cleanup}")),
    }
}

#[cfg(unix)]
fn run(command: &mut Command, context: &str) -> hell_testkit::SupervisedOutput {
    let output = hell_testkit::run_supervised_command(command, &[], Duration::from_secs(30))
        .unwrap_or_else(|error| panic!("{context} must execute: {error}"));
    assert!(!output.timed_out, "{context} timed out");
    assert!(
        output
            .phase_timings
            .iter()
            .any(|phase| phase.name == "quiescence-complete")
    );
    assert_eq!(
        output.phase_timings.last().map(|phase| phase.name),
        Some("stdin-joined")
    );
    output
}

#[cfg(unix)]
fn stderr(output: &hell_testkit::SupervisedOutput) -> String {
    String::from_utf8_lossy(
        output
            .stderr
            .complete
            .as_deref()
            .unwrap_or(&output.stderr.prefix),
    )
    .into_owned()
}

#[cfg(unix)]
#[test]
fn candidate_receipt_consumer_accepts_exact_driver_identity_and_rejects_mutation() {
    let mut fixture = ReceiptFixture::new().expect("receipt fixture must be created");
    let primary = (|| {
        let cargo_source = fs::canonicalize(env!("CARGO_BIN_EXE_hell-ci"))
            .map_err(|error| format!("cannot canonicalize receipt fixture source: {error}"))?;
        let source = fixture.path("hell-ci-source");
        let source_alias = fixture.path("hell-ci-source-alias");
        let source_receipt =
            HardLinkedReceiptSource::establish(&cargo_source, &source, &source_alias)?;
        let executable = fixture.path("hell-ci");
        stage_exact_receipt_executable(&source, &executable)?;
        let staged = fs::symlink_metadata(&executable).map_err(|error| {
            format!("cannot inspect staged receipt fixture executable: {error}")
        })?;
        if (staged.dev() == source_receipt.identity.dev
            && staged.ino() == source_receipt.identity.ino)
            || staged.nlink() != 1
        {
            return Err(
                "staged receipt fixture executable is not one distinct single-linked file"
                    .to_owned(),
            );
        }

        fs::set_permissions(&executable, fs::Permissions::from_mode(0o770))
            .map_err(|error| format!("cannot make receipt fixture candidate-writable: {error}"))?;
        let writable_arguments = receipt_arguments(&executable)?;
        require_receipt_rejection(
            &executable,
            &writable_arguments,
            "candidate-writable POSIX driver receipt verification",
        )?;

        fs::set_permissions(&executable, fs::Permissions::from_mode(0o555))
            .map_err(|error| format!("cannot seal receipt fixture executable: {error}"))?;
        let exact_arguments = receipt_arguments(&executable)?;
        let accepted = run_receipt_verifier(
            &executable,
            &exact_arguments,
            "exact POSIX candidate receipt verification",
        )?;
        if !accepted.status.success() {
            return Err(stderr(&accepted));
        }

        let retained = fixture.path("hell-ci-retained");
        fs::rename(&executable, &retained)
            .map_err(|error| format!("cannot retain bound receipt executable: {error}"))?;
        stage_exact_receipt_executable(&source, &executable)?;
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o555)).map_err(|error| {
            format!("cannot seal substituted receipt fixture executable: {error}")
        })?;
        require_receipt_rejection(
            &executable,
            &exact_arguments,
            "same-path substituted POSIX driver receipt verification",
        )?;

        let replacement_arguments = receipt_arguments(&executable)?;
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755))
            .map_err(|error| format!("cannot drift receipt fixture mode: {error}"))?;
        require_receipt_rejection(
            &executable,
            &replacement_arguments,
            "mode-drifted POSIX driver receipt verification",
        )?;

        let mut mutated = fs::OpenOptions::new()
            .append(true)
            .open(&executable)
            .map_err(|error| format!("cannot open receipt fixture for digest mutation: {error}"))?;
        mutated
            .write_all(&[0])
            .map_err(|error| format!("cannot mutate receipt fixture digest: {error}"))?;
        mutated
            .flush()
            .map_err(|error| format!("cannot flush receipt fixture digest mutation: {error}"))?;
        drop(mutated);
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o555)).map_err(|error| {
            format!("cannot reseal digest-mutated receipt fixture executable: {error}")
        })?;
        require_receipt_rejection(
            &executable,
            &replacement_arguments,
            "digest-mutated POSIX driver receipt verification",
        )?;

        source_receipt.require_unchanged(&source, &source_alias)?;
        Ok(())
    })();
    let cleanup = fixture.cleanup();
    combine_fixture_failures(primary, cleanup).expect("POSIX driver receipt fixture must pass");
}

#[cfg(unix)]
#[test]
fn native_cargo_without_a_staged_compiler_is_rejected() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
    command.arg("__verify-posix-native-cargo-rejection");
    let output = run(&mut command, "POSIX native Cargo rejection verification");
    assert!(output.status.success(), "{}", stderr(&output));
}

#[cfg(unix)]
#[test]
fn rustc_environment_is_exact_without_path_or_wrapper_fallback() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
    command.arg("__verify-posix-rustc-environment");
    let output = run(&mut command, "POSIX Rust compiler environment verification");
    assert!(output.status.success(), "{}", stderr(&output));
}

#[cfg(unix)]
#[test]
fn expired_identity_query_deadline_rejects_before_launch() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
    command.arg("__verify-posix-identity-query-deadline");
    let output = run(&mut command, "POSIX identity query deadline verification");
    assert!(output.status.success(), "{}", stderr(&output));
}

#[cfg(unix)]
#[test]
fn candidate_target_remover_is_bounded_and_preserves_external_authorities() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
    command.arg("__verify-posix-candidate-target-remover");
    let output = run(&mut command, "POSIX candidate target remover verification");
    assert!(output.status.success(), "{}", stderr(&output));
}

#[cfg(unix)]
#[test]
fn principal_cleanup_requires_quiescence_then_root_then_user_absence() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
    command.arg("__verify-posix-principal-cleanup-order");
    let output = run(&mut command, "POSIX principal cleanup order verification");
    assert!(output.status.success(), "{}", stderr(&output));
}
