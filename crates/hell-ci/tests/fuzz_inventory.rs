use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static FIXTURE_ID: AtomicU64 = AtomicU64::new(0);

const MAX_FIXTURE_FILE_BYTES: u64 = 1024 * 1024;

const REQUIRED_TARGETS: [&str; 41] = [
    "strict_json",
    "release_plan",
    "conformance_plan",
    "trusted_inputs",
    "platform_report",
    "evidence_manifest",
    "evidence_repository",
    "partition_reconstruction",
    "release_acceptance",
    "subjects_manifest",
    "release_gate",
    "publication_envelope",
    "governance_api_response",
    "governance_profile",
    "native_environment",
    "gzip_framing",
    "gnu_tar_subset",
    "release_bundle_inventory",
    "workflow_yaml_subset",
    "workflow_expression",
    "workflow_run_invocation",
    "independent_strict_json",
    "independent_release_plan",
    "independent_conformance_plan",
    "independent_evidence",
    "independent_ledger",
    "independent_exemption",
    "independent_gzip",
    "independent_gnu_tar",
    "independent_subjects",
    "independent_publication_envelope",
    "memcordon_runtime_lock",
    "memcordon_runtime_manifest",
    "memcordon_archive_member_policy",
    "memcordon_schema8_wire",
    "memcordon_native_argv",
    "memcordon_operation_projection",
    "memcordon_status_provenance",
    "memcordon_deadline_and_admission",
    "memcordon_provider_lifecycle",
    "memcordon_windows_identity_receipt",
];

const RETAINED_TARGETS: [&str; 5] = [
    "requirement_toml",
    "normalizer_toml",
    "divergence_toml",
    "normalizer_replay",
    "semantic_trace",
];

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let id = FIXTURE_ID.fetch_add(1, Ordering::Relaxed);
        let component = format!("hell-ci-fuzz-inventory-{label}-{}-{id}", std::process::id());
        let root = std::env::temp_dir().join(component);
        fs::create_dir(&root).expect("create fuzz inventory fixture");
        Self { root }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).expect("remove fuzz inventory fixture");
    }
}

struct FixturePermissionRestore {
    path: PathBuf,
    permissions: Option<fs::Permissions>,
}

impl FixturePermissionRestore {
    fn new(path: &Path, permissions: fs::Permissions) -> Self {
        Self {
            path: path.to_path_buf(),
            permissions: Some(permissions),
        }
    }

    fn restore(mut self) {
        let permissions = self
            .permissions
            .take()
            .expect("fixture permissions must be pending restoration");
        fs::set_permissions(&self.path, permissions)
            .expect("restore fixture source permissions for cleanup");
    }
}

impl Drop for FixturePermissionRestore {
    fn drop(&mut self) {
        if let Some(permissions) = self.permissions.take() {
            let _ = fs::set_permissions(&self.path, permissions);
        }
    }
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn run_fuzz_check(output: &Path) -> hell_testkit::SupervisedOutput {
    run_fuzz_check_with(
        &repository_root().join("ci/fuzz-targets.toml"),
        &repository_root(),
        output,
    )
}

fn run_fuzz_check_with(
    manifest: &Path,
    repository: &Path,
    output: &Path,
) -> hell_testkit::SupervisedOutput {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
    command.current_dir(repository_root()).args([
        OsStr::new("fuzz"),
        OsStr::new("check"),
        OsStr::new("--manifest"),
        manifest.as_os_str(),
        OsStr::new("--repository-root"),
        repository.as_os_str(),
        OsStr::new("--output"),
        output.as_os_str(),
    ]);
    hell_testkit::run_supervised_command(&mut command, &[], Duration::from_secs(30))
        .expect("fuzz inventory check must execute under supervision")
}

fn replace_once(input: &str, source: &str, replacement: &str) -> String {
    let (prefix, suffix) = input
        .split_once(source)
        .unwrap_or_else(|| panic!("fuzz manifest fixture lacks {source:?}"));
    format!("{prefix}{replacement}{suffix}")
}

fn rejection_code(path: &Path) -> String {
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(path).expect("fuzz rejection report must be persisted"))
            .expect("fuzz rejection report must be JSON");
    assert_eq!(report["schemaVersion"].as_u64(), Some(1));
    assert_eq!(report["state"].as_str(), Some("blocked"));
    report["diagnosticCode"]
        .as_str()
        .expect("fuzz rejection must have a stable diagnostic code")
        .to_owned()
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FixtureFileIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(windows)]
    handle: std::sync::Arc<same_file::Handle>,
}

impl FixtureFileIdentity {
    #[cfg(unix)]
    fn from_metadata(_path: &Path, metadata: &fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt as _;

        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }

    #[cfg(windows)]
    fn from_metadata(path: &Path, _metadata: &fs::Metadata) -> Result<Self, String> {
        same_file::Handle::from_path(path)
            .map(|handle| Self {
                handle: std::sync::Arc::new(handle),
            })
            .map_err(|error| {
                format!(
                    "cannot bind fuzz fixture file identity for {}: {error}",
                    path.display()
                )
            })
    }

    #[cfg(unix)]
    fn from_file(_file: &File, metadata: &fs::Metadata) -> Self {
        Self::from_metadata(Path::new("."), metadata)
    }

    #[cfg(windows)]
    fn from_file(file: &File, _metadata: &fs::Metadata) -> Result<Self, String> {
        same_file::Handle::from_file(
            file.try_clone()
                .map_err(|error| format!("cannot clone fuzz fixture file handle: {error}"))?,
        )
        .map(|handle| Self {
            handle: std::sync::Arc::new(handle),
        })
        .map_err(|error| format!("cannot bind open fuzz fixture file identity: {error}"))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FixtureFileFingerprint {
    identity: FixtureFileIdentity,
    length: u64,
    readonly: bool,
    #[cfg(unix)]
    mode: u32,
}

impl FixtureFileFingerprint {
    #[cfg(unix)]
    fn bind(path: &Path, metadata: &fs::Metadata) -> Self {
        use std::os::unix::fs::PermissionsExt as _;

        Self {
            identity: FixtureFileIdentity::from_metadata(path, metadata),
            length: metadata.len(),
            readonly: metadata.permissions().readonly(),
            mode: metadata.permissions().mode(),
        }
    }

    #[cfg(windows)]
    fn bind(path: &Path, metadata: &fs::Metadata) -> Result<Self, String> {
        Ok(Self {
            identity: FixtureFileIdentity::from_metadata(path, metadata)?,
            length: metadata.len(),
            readonly: metadata.permissions().readonly(),
        })
    }

    #[cfg(unix)]
    fn bind_open(file: &File, metadata: &fs::Metadata) -> Self {
        use std::os::unix::fs::PermissionsExt as _;

        Self {
            identity: FixtureFileIdentity::from_file(file, metadata),
            length: metadata.len(),
            readonly: metadata.permissions().readonly(),
            mode: metadata.permissions().mode(),
        }
    }

    #[cfg(windows)]
    fn bind_open(file: &File, metadata: &fs::Metadata) -> Result<Self, String> {
        Ok(Self {
            identity: FixtureFileIdentity::from_file(file, metadata)?,
            length: metadata.len(),
            readonly: metadata.permissions().readonly(),
        })
    }
}

struct BoundFixtureSourceFile {
    path: PathBuf,
    fingerprint: FixtureFileFingerprint,
    bytes: Vec<u8>,
}

impl BoundFixtureSourceFile {
    fn bind(path: &Path) -> Result<Self, String> {
        let (mut file, fingerprint) = open_regular_fixture_file(path, "source")?;
        let bytes = read_bounded_fixture_file(&mut file, path)?;
        let bound = Self {
            path: path.to_path_buf(),
            fingerprint,
            bytes,
        };
        bound.revalidate_source()?;
        Ok(bound)
    }

    fn stage(&self, destination: &Path) -> Result<(), String> {
        if self.path.file_name().is_none() || self.path.file_name() != destination.file_name() {
            return Err("fuzz fixture source and destination names differ".to_owned());
        }
        self.revalidate_source()?;
        let mut destination_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination)
            .map_err(|error| {
                format!(
                    "cannot create owned fuzz fixture file {}: {error}",
                    destination.display()
                )
            })?;
        destination_file.write_all(&self.bytes).map_err(|error| {
            format!(
                "cannot write owned fuzz fixture file {}: {error}",
                destination.display()
            )
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            destination_file
                .set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|error| {
                    format!(
                        "cannot make owned fuzz fixture file writable {}: {error}",
                        destination.display()
                    )
                })?;
        }
        destination_file.sync_all().map_err(|error| {
            format!(
                "cannot synchronize owned fuzz fixture file {}: {error}",
                destination.display()
            )
        })?;
        let destination_metadata = destination_file.metadata().map_err(|error| {
            format!(
                "cannot inspect owned fuzz fixture file {}: {error}",
                destination.display()
            )
        })?;
        if !destination_metadata.is_file()
            || destination_metadata.permissions().readonly()
            || destination_metadata.len() != self.bytes.len() as u64
        {
            return Err(format!(
                "owned fuzz fixture file differs after write: {}",
                destination.display()
            ));
        }
        let rebound_metadata = fs::symlink_metadata(destination).map_err(|error| {
            format!(
                "cannot reinspect owned fuzz fixture file {}: {error}",
                destination.display()
            )
        })?;
        #[cfg(unix)]
        let destination_identity =
            FixtureFileIdentity::from_metadata(destination, &rebound_metadata);
        #[cfg(windows)]
        let destination_identity =
            FixtureFileIdentity::from_metadata(destination, &rebound_metadata)?;
        #[cfg(unix)]
        let handle_identity =
            FixtureFileIdentity::from_file(&destination_file, &destination_metadata);
        #[cfg(windows)]
        let handle_identity =
            FixtureFileIdentity::from_file(&destination_file, &destination_metadata)?;
        if destination_identity != handle_identity {
            return Err(format!(
                "owned fuzz fixture file identity changed: {}",
                destination.display()
            ));
        }
        drop(destination_file);
        let (mut destination_file, _) = open_regular_fixture_file(destination, "destination")?;
        let observed = read_bounded_fixture_file(&mut destination_file, destination)?;
        if observed != self.bytes {
            return Err(format!(
                "owned fuzz fixture file bytes differ: {}",
                destination.display()
            ));
        }
        self.revalidate_source()
    }

    fn revalidate_source(&self) -> Result<(), String> {
        let (mut file, fingerprint) = open_regular_fixture_file(&self.path, "source")?;
        if fingerprint != self.fingerprint {
            return Err(format!(
                "fuzz fixture source identity changed: {}",
                self.path.display()
            ));
        }
        if read_bounded_fixture_file(&mut file, &self.path)? != self.bytes {
            return Err(format!(
                "fuzz fixture source bytes changed: {}",
                self.path.display()
            ));
        }
        let (_, after) = open_regular_fixture_file(&self.path, "source")?;
        if after != self.fingerprint {
            return Err(format!(
                "fuzz fixture source identity changed after read: {}",
                self.path.display()
            ));
        }
        Ok(())
    }
}

fn open_regular_fixture_file(
    path: &Path,
    label: &str,
) -> Result<(File, FixtureFileFingerprint), String> {
    let path_metadata = fs::symlink_metadata(path).map_err(|error| {
        format!(
            "cannot inspect fuzz fixture {label} {}: {error}",
            path.display()
        )
    })?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err(format!(
            "fuzz fixture {label} is not a regular file: {}",
            path.display()
        ));
    }
    if path_metadata.len() > MAX_FIXTURE_FILE_BYTES {
        return Err(format!(
            "fuzz fixture {label} exceeds the byte limit: {}",
            path.display()
        ));
    }
    let file = File::open(path).map_err(|error| {
        format!(
            "cannot open fuzz fixture {label} {}: {error}",
            path.display()
        )
    })?;
    let handle_metadata = file.metadata().map_err(|error| {
        format!(
            "cannot inspect open fuzz fixture {label} {}: {error}",
            path.display()
        )
    })?;
    if !handle_metadata.is_file() || handle_metadata.len() > MAX_FIXTURE_FILE_BYTES {
        return Err(format!(
            "open fuzz fixture {label} is not a bounded regular file: {}",
            path.display()
        ));
    }
    #[cfg(unix)]
    let path_fingerprint = FixtureFileFingerprint::bind(path, &path_metadata);
    #[cfg(windows)]
    let path_fingerprint = FixtureFileFingerprint::bind(path, &path_metadata)?;
    #[cfg(unix)]
    let handle_fingerprint = FixtureFileFingerprint::bind_open(&file, &handle_metadata);
    #[cfg(windows)]
    let handle_fingerprint = FixtureFileFingerprint::bind_open(&file, &handle_metadata)?;
    if path_fingerprint != handle_fingerprint {
        return Err(format!(
            "fuzz fixture {label} path identity changed while opening: {}",
            path.display()
        ));
    }
    Ok((file, handle_fingerprint))
}

fn read_bounded_fixture_file(file: &mut File, path: &Path) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    file.take(MAX_FIXTURE_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read fuzz fixture file {}: {error}", path.display()))?;
    if bytes.len() as u64 > MAX_FIXTURE_FILE_BYTES {
        return Err(format!(
            "fuzz fixture file exceeds the byte limit while reading: {}",
            path.display()
        ));
    }
    Ok(bytes)
}

fn stage_fixture_file(source: &Path, destination: &Path) -> Result<(), String> {
    BoundFixtureSourceFile::bind(source)?.stage(destination)
}

#[test]
fn fixture_staging_owns_writable_bytes_without_mutating_read_only_source() {
    let fixture = Fixture::new("owned-staging");
    let source_root = fixture.path("source");
    let destination_root = fixture.path("destination");
    fs::create_dir(&source_root).expect("create fixture staging source root");
    fs::create_dir(&destination_root).expect("create fixture staging destination root");
    let source = source_root.join("asset");
    let destination = destination_root.join("asset");
    let original_bytes = b"sealed source bytes\n";
    fs::write(&source, original_bytes).expect("write fixture staging source");
    let original_permissions = fs::metadata(&source)
        .expect("inspect writable fixture staging source")
        .permissions();
    let permission_restore = FixturePermissionRestore::new(&source, original_permissions.clone());
    let mut read_only_permissions = original_permissions.clone();
    read_only_permissions.set_readonly(true);
    fs::set_permissions(&source, read_only_permissions)
        .expect("make fixture staging source read-only");

    let bound = BoundFixtureSourceFile::bind(&source).expect("bind read-only fixture source");
    bound
        .stage(&destination)
        .expect("stage owned writable fixture file");
    let (_, destination_fingerprint) =
        open_regular_fixture_file(&destination, "destination").expect("bind staged destination");
    assert_ne!(bound.fingerprint.identity, destination_fingerprint.identity);
    fs::write(&destination, b"fixture-owned mutation\n").expect("mutate fixture-owned destination");
    bound
        .revalidate_source()
        .expect("read-only fixture source must remain unchanged");
    let observed_source = fs::read(&source).expect("read preserved fixture source");
    let source_remained_read_only = fs::metadata(&source)
        .expect("inspect preserved fixture source")
        .permissions()
        .readonly();
    permission_restore.restore();

    assert_eq!(observed_source, original_bytes);
    assert!(source_remained_read_only);
    assert_eq!(
        fs::read(&destination).expect("read mutated fixture destination"),
        b"fixture-owned mutation\n"
    );
}

#[test]
fn fixture_staging_rejects_preexisting_destination_without_overwrite() {
    let fixture = Fixture::new("preexisting-destination");
    let source_root = fixture.path("source");
    let destination_root = fixture.path("destination");
    fs::create_dir(&source_root).expect("create preexisting source root");
    fs::create_dir(&destination_root).expect("create preexisting destination root");
    let source = source_root.join("asset");
    let destination = destination_root.join("asset");
    fs::write(&source, b"trusted source\n").expect("write preexisting source");
    fs::write(&destination, b"preexisting destination\n").expect("write preexisting destination");

    let error = stage_fixture_file(&source, &destination)
        .expect_err("preexisting fixture destination must be rejected");
    assert!(error.contains("cannot create owned fuzz fixture file"));
    assert_eq!(
        fs::read(&destination).expect("read preserved preexisting destination"),
        b"preexisting destination\n"
    );
    assert_eq!(
        fs::read(&source).expect("read preserved source"),
        b"trusted source\n"
    );
}

#[cfg(unix)]
#[test]
fn fixture_staging_rejects_source_symlink_without_following_it() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new("source-symlink");
    let source_root = fixture.path("source");
    let destination_root = fixture.path("destination");
    fs::create_dir(&source_root).expect("create symlink source root");
    fs::create_dir(&destination_root).expect("create symlink destination root");
    let target = source_root.join("target");
    let source = source_root.join("asset");
    let destination = destination_root.join("asset");
    fs::write(&target, b"symlink target\n").expect("write symlink target");
    symlink(&target, &source).expect("create fixture source symlink");

    let error = stage_fixture_file(&source, &destination)
        .expect_err("fixture source symlink must be rejected");
    assert!(error.contains("source is not a regular file"));
    assert!(!destination.exists());
    assert_eq!(
        fs::read(&target).expect("read unchanged symlink target"),
        b"symlink target\n"
    );
}

#[cfg(unix)]
#[test]
fn fixture_staging_rejects_bound_source_path_substitution() {
    let fixture = Fixture::new("source-substitution");
    let source_root = fixture.path("source");
    let destination_root = fixture.path("destination");
    fs::create_dir(&source_root).expect("create substitution source root");
    fs::create_dir(&destination_root).expect("create substitution destination root");
    let source = source_root.join("asset");
    let retained = source_root.join("retained");
    let replacement = source_root.join("replacement");
    let destination = destination_root.join("asset");
    fs::write(&source, b"bound source\n").expect("write bound fixture source");
    fs::write(&replacement, b"replacement source\n").expect("write replacement fixture source");
    let bound =
        BoundFixtureSourceFile::bind(&source).expect("bind fixture source before substitution");
    fs::rename(&source, &retained).expect("retain originally bound fixture source");
    fs::rename(&replacement, &source).expect("substitute fixture source path");

    let error = bound
        .stage(&destination)
        .expect_err("bound fixture source substitution must be rejected");
    assert!(error.contains("source identity changed"));
    assert!(!destination.exists());
    assert_eq!(
        fs::read(&retained).expect("read retained bound source"),
        b"bound source\n"
    );
    assert_eq!(
        fs::read(&source).expect("read substituted source"),
        b"replacement source\n"
    );
}

fn copy_directory(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).expect("create fuzz inventory directory copy");
    for entry in fs::read_dir(source).expect("read fuzz inventory source directory") {
        let entry = entry.expect("read fuzz inventory source entry");
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let metadata = fs::symlink_metadata(&source_path).expect("inspect fuzz inventory entry");
        assert!(
            !metadata.file_type().is_symlink(),
            "fuzz inventory fixture cannot copy symlinks"
        );
        if metadata.is_dir() {
            copy_directory(&source_path, &destination_path);
        } else {
            assert!(metadata.is_file());
            stage_fixture_file(&source_path, &destination_path)
                .expect("stage owned fuzz inventory file");
        }
    }
}

fn copy_physical_fuzz_inventory(destination: &Path) {
    for relative in [
        "crates/hell-ci/fuzz",
        "crates/hell-release-verifier/fuzz",
        "crates/hell-workflow-auditor/fuzz",
    ] {
        let source = repository_root().join(relative);
        let target = destination.join(relative);
        fs::create_dir_all(&target).expect("create physical fuzz root");
        stage_fixture_file(&source.join("Cargo.toml"), &target.join("Cargo.toml"))
            .expect("stage owned fuzz Cargo manifest");
        copy_directory(&source.join("fuzz_targets"), &target.join("fuzz_targets"));
        copy_directory(&source.join("corpus"), &target.join("corpus"));
    }
}

#[cfg(unix)]
fn freeze_artifact_fixture(path: &Path, restore: &mut Vec<FixturePermissionRestore>) {
    use std::os::unix::fs::PermissionsExt as _;
    let metadata = fs::symlink_metadata(path).unwrap();
    if metadata.file_type().is_symlink() {
        return;
    }
    restore.push(FixturePermissionRestore::new(path, metadata.permissions()));
    if metadata.is_dir() {
        for entry in fs::read_dir(path).unwrap() {
            freeze_artifact_fixture(&entry.unwrap().path(), restore);
        }
    }
    fs::set_permissions(
        path,
        fs::Permissions::from_mode(if metadata.is_dir() { 0o555 } else { 0o444 }),
    )
    .unwrap();
}

#[cfg(unix)]
#[test]
fn cargo_fuzz_default_preparation_succeeds_read_only_and_final_prefix_targets_work() {
    let fixture = Fixture::new("artifact-defaults");
    let source = fixture.path("repository");
    copy_physical_fuzz_inventory(&source);
    let source = source.canonicalize().unwrap();
    let manifest = repository_root().join("ci/fuzz-targets.toml");
    let input = source.join("crates/hell-ci/fuzz/Cargo.toml");
    let before = fs::read(&input).unwrap();
    hell_ci::fuzz::reserve_source_artifact_defaults(&manifest, &source).unwrap();
    let mut restore = Vec::new();
    freeze_artifact_fixture(&source, &mut restore);
    let default = source.join("crates/hell-ci/fuzz/artifacts/strict_json");
    // Exact cargo-fuzz 0.13.2 preparatory operation, without compiling fuzzers.
    fs::create_dir_all(&default).unwrap();
    assert!(fs::read_dir(&default).unwrap().next().is_none());
    let work = fixture.path("work");
    fs::create_dir_all(work.join("ci-out/fuzz-artifacts")).unwrap();
    fs::create_dir(work.join("corpus")).unwrap();
    let work = work.canonicalize().unwrap();
    let arguments =
        hell_ci::fuzz::inspect_fuzz_artifact_campaign(&manifest, &source, &work, "strict_json")
            .unwrap();
    let separator = arguments
        .iter()
        .position(|argument| argument == "--")
        .unwrap();
    assert_eq!(&arguments[..2], ["fuzz", "run"]);
    assert_eq!(&arguments[2..4], ["--fuzz-dir", "crates/hell-ci/fuzz"]);
    let prefixes = arguments
        .iter()
        .enumerate()
        .filter_map(|(index, argument)| {
            argument
                .to_str()
                .and_then(|value| value.strip_prefix("-artifact_prefix="))
                .map(|path| (index, PathBuf::from(path)))
        })
        .collect::<Vec<_>>();
    assert_eq!(prefixes.len(), 1);
    assert!(prefixes[0].0 > separator);
    assert_eq!(
        prefixes[0].1,
        work.join("ci-out/fuzz-artifacts/strict_json")
    );
    assert_eq!(
        arguments
            .last()
            .unwrap()
            .to_str()
            .unwrap()
            .strip_suffix('/')
            .map(|value| value.starts_with("-artifact_prefix=")),
        Some(true)
    );
    fs::write(
        prefixes[0].1.join("retained-artifact-fixture"),
        b"actual output authority\n",
    )
    .unwrap();
    assert!(fs::read_dir(&default).unwrap().next().is_none());
    assert_eq!(fs::read(&input).unwrap(), before);
    drop(restore);
}

#[cfg(unix)]
#[test]
fn cargo_fuzz_default_reservation_rejects_preexisting_and_redirected_roots() {
    for redirected in [false, true] {
        let fixture = Fixture::new("artifact-preexisting");
        let source = fixture.path("repository");
        copy_physical_fuzz_inventory(&source);
        let source = source.canonicalize().unwrap();
        let artifacts = source.join("crates/hell-ci/fuzz/artifacts");
        if redirected {
            std::os::unix::fs::symlink(&fixture.root, &artifacts).unwrap();
        } else {
            fs::create_dir(&artifacts).unwrap();
            fs::write(artifacts.join("unexpected"), b"preserve\n").unwrap();
        }
        assert!(
            hell_ci::fuzz::reserve_source_artifact_defaults(
                &repository_root().join("ci/fuzz-targets.toml"),
                &source
            )
            .is_err()
        );
        if !redirected {
            assert_eq!(
                fs::read(artifacts.join("unexpected")).unwrap(),
                b"preserve\n"
            );
        }
    }
}

#[cfg(unix)]
#[test]
fn cargo_fuzz_default_validation_rejects_contents_and_postreservation_symlinks() {
    for redirected in [false, true] {
        let fixture = Fixture::new("artifact-mutated");
        let source = fixture.path("repository");
        copy_physical_fuzz_inventory(&source);
        let source = source.canonicalize().unwrap();
        let manifest = repository_root().join("ci/fuzz-targets.toml");
        hell_ci::fuzz::reserve_source_artifact_defaults(&manifest, &source).unwrap();
        let default = source.join("crates/hell-ci/fuzz/artifacts/strict_json");
        if redirected {
            fs::remove_dir(&default).unwrap();
            std::os::unix::fs::symlink(&fixture.root, &default).unwrap();
        } else {
            fs::write(default.join("unexpected"), b"not an admitted output\n").unwrap();
        }
        let mut restore = Vec::new();
        freeze_artifact_fixture(&source, &mut restore);
        let error = hell_ci::fuzz::inspect_fuzz_artifact_campaign(
            &manifest,
            &source,
            &fixture.root,
            "strict_json",
        )
        .unwrap_err();
        assert!(
            error.contains(if redirected {
                "real directory"
            } else {
                "must remain empty"
            }),
            "{error}"
        );
        drop(restore);
    }
}

#[test]
fn production_fuzz_inventory_check_binds_all_physical_targets_and_corpora() {
    let fixture = Fixture::new("live");
    let report = fixture.path("fuzz-check.json");
    let output = run_fuzz_check(&report);
    assert!(
        output.status.success() && !output.timed_out,
        "fuzz inventory check failed: {}",
        String::from_utf8_lossy(
            output
                .stderr
                .complete
                .as_deref()
                .unwrap_or(&output.stderr.prefix)
        )
    );
    assert_eq!(
        fs::read_to_string(report).expect("fuzz inventory report must exist"),
        "{\"requiredTargetCount\":41,\"retainedTargetCount\":5,\"schemaVersion\":1,\"state\":\"checked\",\"targetCount\":46}\n"
    );
}

#[test]
fn typed_manifest_contains_the_exact_required_and_retained_id_sets() {
    let manifest = fs::read_to_string(repository_root().join("ci/fuzz-targets.toml"))
        .expect("fuzz manifest must be readable");
    let ids = manifest
        .lines()
        .filter_map(|line| {
            line.strip_prefix("id = \"")
                .and_then(|value| value.strip_suffix('"'))
        })
        .collect::<BTreeSet<_>>();
    let expected = REQUIRED_TARGETS
        .into_iter()
        .chain(RETAINED_TARGETS)
        .collect::<BTreeSet<_>>();
    assert_eq!(ids, expected);
}

#[test]
fn production_fuzz_inventory_rejects_unknown_reordered_and_duplicate_descriptors() {
    let manifest = fs::read_to_string(repository_root().join("ci/fuzz-targets.toml"))
        .expect("fuzz manifest must be readable");

    let unknown = Fixture::new("unknown-field");
    let unknown_manifest = replace_once(
        &manifest,
        "engine-arguments = [\"-runs=64\", \"-timeout=10\", \"-max_len=1048576\", \"-artifact_prefix=ci-out/fuzz-artifacts/strict_json/\"]",
        "engine-arguments = [\"-runs=64\", \"-timeout=10\", \"-max_len=1048576\", \"-artifact_prefix=ci-out/fuzz-artifacts/strict_json/\"]\nunknown = true",
    );
    let unknown_path = unknown.path("manifest.toml");
    fs::write(&unknown_path, unknown_manifest).expect("write unknown-field fuzz manifest");
    let unknown_report = unknown.path("report.json");
    let unknown_output = run_fuzz_check_with(&unknown_path, &repository_root(), &unknown_report);
    assert!(!unknown_output.status.success() && !unknown_output.timed_out);
    assert_eq!(rejection_code(&unknown_report), "fuzz.manifest.invalid");

    let reordered = Fixture::new("reordered");
    let (root, tables) = manifest
        .split_once("\n[[target]]\n")
        .expect("fuzz manifest must contain target tables");
    let mut tables = tables.split("\n[[target]]\n").collect::<Vec<_>>();
    tables.swap(0, 1);
    let reordered_manifest = format!("{root}\n[[target]]\n{}", tables.join("\n[[target]]\n"));
    let reordered_path = reordered.path("manifest.toml");
    fs::write(&reordered_path, reordered_manifest).expect("write reordered fuzz manifest");
    let reordered_report = reordered.path("report.json");
    let reordered_output =
        run_fuzz_check_with(&reordered_path, &repository_root(), &reordered_report);
    assert!(!reordered_output.status.success() && !reordered_output.timed_out);
    assert_eq!(rejection_code(&reordered_report), "fuzz.manifest.inventory");

    let duplicate = Fixture::new("duplicate");
    let duplicate_manifest =
        replace_once(&manifest, "id = \"release_plan\"", "id = \"strict_json\"");
    let duplicate_path = duplicate.path("manifest.toml");
    fs::write(&duplicate_path, duplicate_manifest).expect("write duplicate fuzz manifest");
    let duplicate_report = duplicate.path("report.json");
    let duplicate_output =
        run_fuzz_check_with(&duplicate_path, &repository_root(), &duplicate_report);
    assert!(!duplicate_output.status.success() && !duplicate_output.timed_out);
    assert_eq!(rejection_code(&duplicate_report), "fuzz.manifest.invalid");
}

#[test]
fn production_fuzz_inventory_rejects_extra_source_bin_and_corpus_assets() {
    let fixture = Fixture::new("physical-assets");
    let repository = fixture.path("repository");
    copy_physical_fuzz_inventory(&repository);
    let manifest = repository_root().join("ci/fuzz-targets.toml");

    let baseline_report = fixture.path("baseline.json");
    let baseline = run_fuzz_check_with(&manifest, &repository, &baseline_report);
    assert!(
        baseline.status.success() && !baseline.timed_out,
        "copied exact fuzz inventory must be admitted"
    );

    let source = repository.join("crates/hell-ci/fuzz/fuzz_targets/unregistered.rs");
    fs::write(&source, "#![no_main]\n").expect("write extra fuzz source");
    let source_report = fixture.path("source.json");
    let source_output = run_fuzz_check_with(&manifest, &repository, &source_report);
    assert!(!source_output.status.success() && !source_output.timed_out);
    assert_eq!(rejection_code(&source_report), "fuzz.source.inventory");
    fs::remove_file(&source).expect("remove extra fuzz source fixture");

    let cargo_path = repository.join("crates/hell-ci/fuzz/Cargo.toml");
    let mut cargo = fs::read_to_string(&cargo_path).expect("read copied fuzz Cargo manifest");
    cargo.push_str(
        "\n[[bin]]\nname = \"unregistered\"\npath = \"fuzz_targets/unregistered.rs\"\ntest = false\ndoc = false\nbench = false\n",
    );
    fs::write(&cargo_path, cargo).expect("write extra fuzz Cargo target");
    fs::write(&source, "#![no_main]\n").expect("write extra registered source fixture");
    let cargo_report = fixture.path("cargo.json");
    let cargo_output = run_fuzz_check_with(&manifest, &repository, &cargo_report);
    assert!(!cargo_output.status.success() && !cargo_output.timed_out);
    assert_eq!(rejection_code(&cargo_report), "fuzz.cargo-bin.inventory");

    fs::remove_file(&cargo_path).expect("remove mutated fuzz Cargo manifest");
    stage_fixture_file(
        &repository_root().join("crates/hell-ci/fuzz/Cargo.toml"),
        &cargo_path,
    )
    .expect("restore owned fuzz Cargo manifest");
    fs::remove_file(&source).expect("remove extra registered source fixture");
    let extra_corpus = repository.join("crates/hell-ci/fuzz/corpus/unregistered");
    fs::create_dir_all(&extra_corpus).expect("create extra fuzz corpus");
    fs::write(extra_corpus.join("seed.txt"), "unregistered\n")
        .expect("write extra fuzz corpus seed");
    let corpus_report = fixture.path("corpus.json");
    let corpus_output = run_fuzz_check_with(&manifest, &repository, &corpus_report);
    assert!(!corpus_output.status.success() && !corpus_output.timed_out);
    assert_eq!(rejection_code(&corpus_report), "fuzz.corpus.inventory");
}
