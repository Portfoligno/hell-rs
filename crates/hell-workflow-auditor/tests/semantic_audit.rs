use std::ffi::OsString;
use std::fs;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use hell_workflow_auditor::{protocol_sha256, run};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);
const WORKFLOW_FIXTURE_BYTE_LIMIT: u64 = 1024 * 1024;

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn new(label: &str) -> Self {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "hell-workflow-auditor-{label}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create test directory");
        Self { path }
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        if self.path.exists() {
            fs::remove_dir_all(&self.path).expect("remove test directory");
        }
    }
}

struct Fixture {
    directory: TestDirectory,
    workflows: PathBuf,
    projection: PathBuf,
    metadata: PathBuf,
    workflow: PathBuf,
    source_receipts: Vec<WorkflowSourceReceipt>,
}

impl Fixture {
    fn require_sources_unchanged(&self) {
        for receipt in &self.source_receipts {
            receipt
                .require_unchanged()
                .expect("revalidate sealed workflow source after fixture use");
        }
    }
}

#[derive(Debug)]
struct WorkflowSourceReceipt {
    path: PathBuf,
    canonical: PathBuf,
    guard: fs::File,
    identity: NativeWorkflowIdentity,
    permissions: WorkflowSourcePermissions,
    bytes: Vec<u8>,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NativeWorkflowIdentity {
    device: u64,
    inode: u64,
}

#[cfg(not(unix))]
#[derive(Debug, Eq, PartialEq)]
struct NativeWorkflowIdentity {
    handle: same_file::Handle,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct WorkflowSourcePermissions {
    readonly: bool,
    #[cfg(unix)]
    mode: u32,
}

impl WorkflowSourceReceipt {
    fn bind(path: &Path) -> Result<Self, String> {
        let path = path.to_path_buf();
        let path_metadata = workflow_regular_file_metadata(&path, "source")?;
        if path_metadata.len() > WORKFLOW_FIXTURE_BYTE_LIMIT {
            return Err(format!(
                "workflow source exceeds fixture byte limit: {}",
                path.display()
            ));
        }
        let canonical = fs::canonicalize(&path).map_err(|error| {
            format!(
                "cannot canonicalize workflow source {}: {error}",
                path.display()
            )
        })?;
        let mut guard = fs::OpenOptions::new()
            .read(true)
            .open(&path)
            .map_err(|error| format!("cannot open workflow source {}: {error}", path.display()))?;
        let handle_metadata = guard.metadata().map_err(|error| {
            format!(
                "cannot inspect workflow source handle {}: {error}",
                path.display()
            )
        })?;
        let identity = NativeWorkflowIdentity::bind_path(
            &path,
            &path_metadata,
            "workflow source path identity",
        )?;
        if identity
            != NativeWorkflowIdentity::bind_handle(
                &guard,
                &handle_metadata,
                &path,
                "workflow source retained-handle identity",
            )?
        {
            return Err(format!(
                "workflow source path and retained handle differ: {}",
                path.display()
            ));
        }
        let permissions = WorkflowSourcePermissions::bind(&path_metadata);
        let mut bytes = Vec::new();
        std::io::Read::by_ref(&mut guard)
            .take(WORKFLOW_FIXTURE_BYTE_LIMIT + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| format!("cannot read workflow source {}: {error}", path.display()))?;
        if u64::try_from(bytes.len()).map_err(|_| "workflow source length overflow".to_owned())?
            != path_metadata.len()
        {
            return Err(format!(
                "workflow source length changed during binding: {}",
                path.display()
            ));
        }
        let receipt = Self {
            path,
            canonical,
            guard,
            identity,
            permissions,
            bytes,
        };
        receipt.require_unchanged()?;
        Ok(receipt)
    }

    fn require_unchanged(&self) -> Result<(), String> {
        let path_metadata = workflow_regular_file_metadata(&self.path, "source revalidation")?;
        let handle_metadata = self.guard.metadata().map_err(|error| {
            format!(
                "cannot revalidate workflow source handle {}: {error}",
                self.path.display()
            )
        })?;
        let canonical = fs::canonicalize(&self.path).map_err(|error| {
            format!(
                "cannot revalidate workflow source path {}: {error}",
                self.path.display()
            )
        })?;
        if canonical != self.canonical
            || NativeWorkflowIdentity::bind_path(
                &self.path,
                &path_metadata,
                "workflow source revalidated path identity",
            )? != self.identity
            || NativeWorkflowIdentity::bind_handle(
                &self.guard,
                &handle_metadata,
                &self.path,
                "workflow source revalidated retained-handle identity",
            )? != self.identity
            || WorkflowSourcePermissions::bind(&path_metadata) != self.permissions
            || WorkflowSourcePermissions::bind(&handle_metadata) != self.permissions
            || fs::read(&self.path)
                .map_err(|error| {
                    format!(
                        "cannot re-read workflow source {}: {error}",
                        self.path.display()
                    )
                })?
                .as_slice()
                != self.bytes.as_slice()
        {
            return Err(format!(
                "workflow source identity, permissions, or bytes changed: {}",
                self.path.display()
            ));
        }
        Ok(())
    }
}

impl NativeWorkflowIdentity {
    #[cfg(unix)]
    fn bind_metadata(metadata: &fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt as _;

        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }

    #[cfg(unix)]
    fn bind_path(path: &Path, metadata: &fs::Metadata, label: &str) -> Result<Self, String> {
        let identity = Self::bind_metadata(metadata);
        let rebound_metadata = workflow_regular_file_metadata(path, label)?;
        if Self::bind_metadata(&rebound_metadata) != identity {
            return Err(format!("{label} changed while binding {}", path.display()));
        }
        Ok(identity)
    }

    #[cfg(unix)]
    fn bind_handle(
        file: &fs::File,
        metadata: &fs::Metadata,
        path: &Path,
        label: &str,
    ) -> Result<Self, String> {
        let identity = Self::bind_metadata(metadata);
        let rebound_metadata = file
            .metadata()
            .map_err(|error| format!("cannot rebind {label} {}: {error}", path.display()))?;
        if Self::bind_metadata(&rebound_metadata) != identity {
            return Err(format!("{label} changed while binding {}", path.display()));
        }
        Ok(identity)
    }

    #[cfg(not(unix))]
    fn bind_path(path: &Path, _: &fs::Metadata, label: &str) -> Result<Self, String> {
        same_file::Handle::from_path(path)
            .map(|handle| Self { handle })
            .map_err(|error| format!("cannot bind {label} {}: {error}", path.display()))
    }

    #[cfg(not(unix))]
    fn bind_handle(
        file: &fs::File,
        _: &fs::Metadata,
        path: &Path,
        label: &str,
    ) -> Result<Self, String> {
        let clone = file
            .try_clone()
            .map_err(|error| format!("cannot clone {label} {}: {error}", path.display()))?;
        same_file::Handle::from_file(clone)
            .map(|handle| Self { handle })
            .map_err(|error| format!("cannot bind {label} {}: {error}", path.display()))
    }
}

impl WorkflowSourcePermissions {
    fn bind(metadata: &fs::Metadata) -> Self {
        Self {
            readonly: metadata.permissions().readonly(),
            #[cfg(unix)]
            mode: {
                use std::os::unix::fs::PermissionsExt as _;
                metadata.permissions().mode() & 0o7777
            },
        }
    }
}

fn workflow_regular_file_metadata(path: &Path, label: &str) -> Result<fs::Metadata, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        format!(
            "cannot inspect workflow {label} {}: {error}",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "workflow {label} is not an exact regular file: {}",
            path.display()
        ));
    }
    Ok(metadata)
}

fn stage_owned_workflow(
    source: &Path,
    destination: &Path,
) -> Result<WorkflowSourceReceipt, String> {
    let receipt = WorkflowSourceReceipt::bind(source)?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut destination_guard = options.open(destination).map_err(|error| {
        format!(
            "cannot create owned workflow destination {}: {error}",
            destination.display()
        )
    })?;
    destination_guard
        .write_all(&receipt.bytes)
        .and_then(|()| destination_guard.flush())
        .map_err(|error| {
            format!(
                "cannot write owned workflow destination {}: {error}",
                destination.display()
            )
        })?;
    let destination_metadata =
        workflow_regular_file_metadata(destination, "destination after staging")?;
    let handle_metadata = destination_guard.metadata().map_err(|error| {
        format!(
            "cannot inspect owned workflow destination handle {}: {error}",
            destination.display()
        )
    })?;
    let destination_identity = NativeWorkflowIdentity::bind_path(
        destination,
        &destination_metadata,
        "owned workflow destination path identity",
    )?;
    if destination_identity
        != NativeWorkflowIdentity::bind_handle(
            &destination_guard,
            &handle_metadata,
            destination,
            "owned workflow destination retained-handle identity",
        )?
        || destination_identity == receipt.identity
        || destination_metadata.permissions().readonly()
        || fs::read(destination)
            .map_err(|error| {
                format!(
                    "cannot read owned workflow destination {}: {error}",
                    destination.display()
                )
            })?
            .as_slice()
            != receipt.bytes.as_slice()
    {
        return Err(format!(
            "owned workflow destination identity, authority, or bytes differ: {}",
            destination.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if destination_metadata.permissions().mode() & 0o200 == 0 {
            return Err(format!(
                "owned workflow destination is not owner-writable: {}",
                destination.display()
            ));
        }
    }
    receipt.require_unchanged()?;
    Ok(receipt)
}

#[test]
fn external_valid_and_invalid_physical_workflows_are_audited() {
    let fixture = fixture();
    let valid_report = fixture.directory.path.join("valid-report.json");
    let message = run(&audit_arguments(&fixture, &valid_report)).expect("valid workflow admits");
    assert_eq!(message, "audited 1 workflows, 1 jobs, and 1 physical steps");
    let valid_bytes = fs::read(&valid_report).expect("read valid report");
    assert!(valid_bytes.ends_with(b"\n"));
    let valid: serde_json::Value =
        serde_json::from_slice(&valid_bytes).expect("parse valid report");
    assert_eq!(
        valid.get("admitted").and_then(serde_json::Value::as_bool),
        Some(true)
    );

    let workflow = fs::read_to_string(&fixture.workflow).expect("read workflow");
    let mutated = workflow.replace(
        "run: cargo check --locked",
        "run: cargo check --locked && true",
    );
    assert_ne!(workflow, mutated);
    fs::write(&fixture.workflow, mutated).expect("write invalid workflow");
    let invalid_report = fixture.directory.path.join("invalid-report.json");
    let error = run(&audit_arguments(&fixture, &invalid_report))
        .expect_err("multiple command invocations must reject");
    assert_eq!(error.code, "workflow.run.multiple-invocations");
    let invalid: serde_json::Value =
        serde_json::from_slice(&fs::read(&invalid_report).expect("read invalid report"))
            .expect("parse invalid report");
    assert_eq!(
        invalid
            .get("diagnostic")
            .and_then(|value| value.get("code"))
            .and_then(serde_json::Value::as_str),
        Some("workflow.run.multiple-invocations")
    );
}

#[test]
fn production_dependency_boundary_excludes_shared_ci_and_yaml_parsers() {
    let manifest = include_str!("../Cargo.toml");
    assert!(!manifest.contains("hell-ci"));
    assert!(!manifest.contains("serde_yaml"));
}

#[test]
fn attest_contents_write_permission_is_rejected() {
    let fixture = live_permission_mutant("attest-contents", |projection| {
        projection["permissions"]["attest"]["contents"] =
            serde_json::Value::String("write".to_owned());
        ("      contents: read\n", "      contents: write\n")
    });
    fixture.require_sources_unchanged();
    let report = fixture.directory.path.join("attest-contents-report.json");
    let error = run(&audit_arguments(&fixture, &report))
        .expect_err("attest contents write permission must reject");
    assert_eq!(error.code, "workflow.permission.attest");
    assert_rejection_report_code(&report, "workflow.permission.attest");
    fixture.require_sources_unchanged();
}

#[test]
fn publish_id_token_write_permission_is_rejected() {
    let fixture = live_permission_mutant("publish-id-token", |projection| {
        projection["permissions"]["publish"]["idToken"] =
            serde_json::Value::String("write".to_owned());
        (
            "      contents: write\n    outputs:\n",
            "      contents: write\n      id-token: write\n    outputs:\n",
        )
    });
    fixture.require_sources_unchanged();
    let report = fixture.directory.path.join("publish-id-token-report.json");
    let error = run(&audit_arguments(&fixture, &report))
        .expect_err("publish ID-token write permission must reject");
    assert_eq!(error.code, "workflow.permission.publish");
    assert_rejection_report_code(&report, "workflow.permission.publish");
    fixture.require_sources_unchanged();
}

#[cfg(unix)]
#[test]
fn sealed_workflow_source_stages_as_distinct_owned_writable_bytes() {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = TestDirectory::new("sealed-workflow-stage");
    let source_directory = directory.path.join("protected");
    let destination_directory = directory.path.join("owned");
    fs::create_dir(&source_directory).expect("create sealed workflow source directory");
    fs::create_dir(&destination_directory).expect("create owned workflow destination directory");
    let source = source_directory.join("release.yml");
    let destination = destination_directory.join("release.yml");
    let source_bytes = b"name: sealed workflow\n";
    fs::write(&source, source_bytes).expect("write workflow source before sealing");
    fs::set_permissions(&source, fs::Permissions::from_mode(0o444)).expect("seal workflow source");

    let receipt = stage_owned_workflow(&source, &destination)
        .expect("stage sealed workflow as owned writable bytes");
    receipt
        .require_unchanged()
        .expect("sealed workflow source remains exact after staging");
    assert_eq!(
        fs::read(&source).expect("read sealed workflow source"),
        source_bytes
    );
    assert_eq!(
        fs::symlink_metadata(&source)
            .expect("inspect sealed workflow source mode")
            .permissions()
            .mode()
            & 0o7777,
        0o444
    );
    let destination_metadata =
        fs::symlink_metadata(&destination).expect("inspect owned workflow destination");
    assert!(destination_metadata.permissions().mode() & 0o200 != 0);
    assert_ne!(
        NativeWorkflowIdentity::bind_path(
            &destination,
            &destination_metadata,
            "staged destination path identity",
        )
        .expect("bind staged destination identity"),
        receipt.identity
    );

    fs::write(&destination, b"name: mutated owned workflow\n")
        .expect("mutate owned workflow destination");
    receipt
        .require_unchanged()
        .expect("destination mutation does not change sealed source authority");
    assert_eq!(
        fs::read(&source).expect("re-read sealed workflow source"),
        source_bytes
    );
}

#[test]
fn workflow_native_identity_binds_destination_and_rejects_same_byte_substitution() {
    let directory = TestDirectory::new("workflow-native-identity");
    let source = directory.path.join("source.yml");
    let displaced = directory.path.join("displaced.yml");
    let destination = directory.path.join("destination.yml");
    let destination_alias = directory.path.join("destination-alias.yml");
    let source_bytes = b"name: identity-bound workflow\n";
    fs::write(&source, source_bytes).expect("write identity-bound source");

    let receipt = stage_owned_workflow(&source, &destination)
        .expect("stage identity-bound workflow destination");
    let destination_metadata =
        workflow_regular_file_metadata(&destination, "identity test destination")
            .expect("inspect identity test destination");
    let destination_guard = fs::File::open(&destination).expect("open identity test destination");
    let destination_handle_metadata = destination_guard
        .metadata()
        .expect("inspect identity test destination handle");
    let destination_identity = NativeWorkflowIdentity::bind_path(
        &destination,
        &destination_metadata,
        "identity test destination path",
    )
    .expect("bind identity test destination path");
    assert_eq!(
        destination_identity,
        NativeWorkflowIdentity::bind_handle(
            &destination_guard,
            &destination_handle_metadata,
            &destination,
            "identity test destination handle",
        )
        .expect("bind identity test destination handle")
    );
    assert_ne!(destination_identity, receipt.identity);

    fs::hard_link(&destination, &destination_alias).expect("hard-link staged destination");
    let alias_metadata =
        workflow_regular_file_metadata(&destination_alias, "identity test destination alias")
            .expect("inspect identity test destination alias");
    assert_eq!(
        NativeWorkflowIdentity::bind_path(
            &destination_alias,
            &alias_metadata,
            "identity test destination alias",
        )
        .expect("bind identity test destination alias"),
        destination_identity
    );

    fs::rename(&source, &displaced).expect("displace identity-bound source");
    fs::write(&source, source_bytes).expect("replace source with same bytes and length");
    assert!(
        receipt
            .require_unchanged()
            .expect_err("same-byte source identity substitution must reject")
            .contains("identity, permissions, or bytes changed")
    );
}

#[cfg(unix)]
#[test]
fn workflow_staging_rejects_redirected_source_and_existing_destination() {
    use std::os::unix::fs::symlink;

    let directory = TestDirectory::new("workflow-stage-negatives");
    let source = directory.path.join("source.yml");
    let redirected = directory.path.join("redirected.yml");
    let destination = directory.path.join("destination.yml");
    fs::write(&source, b"name: source\n").expect("write exact workflow source");
    symlink(&source, &redirected).expect("redirect workflow source");
    let redirected_error = stage_owned_workflow(&redirected, &destination)
        .expect_err("redirected workflow source must reject");
    assert!(redirected_error.contains("not an exact regular file"));

    let sentinel = b"existing destination authority\n";
    fs::write(&destination, sentinel).expect("write existing workflow destination");
    let existing_error = stage_owned_workflow(&source, &destination)
        .expect_err("existing workflow destination must reject");
    assert!(existing_error.contains("cannot create owned workflow destination"));
    assert_eq!(
        fs::read(&destination).expect("read unchanged existing workflow destination"),
        sentinel
    );
}

#[cfg(unix)]
#[test]
fn workflow_source_receipt_rejects_mode_bytes_and_identity_changes() {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = TestDirectory::new("workflow-source-revalidation-negatives");

    let mode_source = directory.path.join("mode.yml");
    fs::write(&mode_source, b"name: sealed mode\n").expect("write mode source");
    fs::set_permissions(&mode_source, fs::Permissions::from_mode(0o444)).expect("seal mode source");
    let mode_receipt = WorkflowSourceReceipt::bind(&mode_source).expect("bind sealed mode source");
    fs::set_permissions(&mode_source, fs::Permissions::from_mode(0o644))
        .expect("change source mode");
    assert!(
        mode_receipt
            .require_unchanged()
            .expect_err("source mode change must reject")
            .contains("identity, permissions, or bytes changed")
    );

    let byte_source = directory.path.join("bytes.yml");
    fs::write(&byte_source, b"name: original\n").expect("write byte source");
    let byte_receipt = WorkflowSourceReceipt::bind(&byte_source).expect("bind byte source");
    fs::write(&byte_source, b"name: modified\n").expect("change source bytes");
    assert!(
        byte_receipt
            .require_unchanged()
            .expect_err("source byte change must reject")
            .contains("identity, permissions, or bytes changed")
    );

    let identity_source = directory.path.join("identity.yml");
    let displaced_source = directory.path.join("displaced.yml");
    let identity_bytes = b"name: identity\n";
    fs::write(&identity_source, identity_bytes).expect("write identity source");
    let identity_receipt =
        WorkflowSourceReceipt::bind(&identity_source).expect("bind identity source");
    fs::rename(&identity_source, &displaced_source).expect("displace bound identity source");
    fs::write(&identity_source, identity_bytes).expect("replace source at bound path");
    assert!(
        identity_receipt
            .require_unchanged()
            .expect_err("source identity substitution must reject")
            .contains("identity, permissions, or bytes changed")
    );
}

#[test]
fn existing_report_is_never_replaced() {
    let fixture = fixture();
    let report = fixture.directory.path.join("existing-report.json");
    let sentinel = b"existing report authority\n";
    fs::write(&report, sentinel).expect("write existing report");
    let error =
        run(&audit_arguments(&fixture, &report)).expect_err("existing workflow report must reject");
    assert_eq!(error.code, "workflow.report.exists");
    assert_eq!(fs::read(&report).expect("read existing report"), sentinel);
}

fn assert_rejection_report_code(report: &Path, expected: &str) {
    let metadata = fs::metadata(report).expect("read published rejection report metadata");
    assert!(
        metadata.is_file(),
        "published rejection report is not a file"
    );
    let bytes = fs::read(report).expect("read rejection report");
    assert!(!bytes.is_empty(), "published rejection report is empty");
    assert!(bytes.ends_with(b"\n"));
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("parse rejection report");
    assert_eq!(
        value
            .get("diagnostic")
            .and_then(|diagnostic| diagnostic.get("code"))
            .and_then(serde_json::Value::as_str),
        Some(expected)
    );
}

fn audit_arguments(fixture: &Fixture, output: &Path) -> Vec<OsString> {
    [
        OsString::from("audit"),
        OsString::from("--workflows"),
        fixture.workflows.as_os_str().to_owned(),
        OsString::from("--protocol-projection"),
        fixture.projection.as_os_str().to_owned(),
        OsString::from("--action-metadata"),
        fixture.metadata.as_os_str().to_owned(),
        OsString::from("--output"),
        output.as_os_str().to_owned(),
    ]
    .into_iter()
    .collect()
}

fn live_permission_mutant(
    label: &str,
    mutate: impl FnOnce(&mut serde_json::Value) -> (&'static str, &'static str),
) -> Fixture {
    let directory = TestDirectory::new(label);
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace crates directory")
        .parent()
        .expect("workspace root");
    let workflows = directory.path.join(".github/workflows");
    let projection = directory.path.join("ci/protocol/v1.audit.json");
    fs::create_dir_all(&workflows).expect("create mutant workflow directory");
    fs::create_dir_all(projection.parent().expect("projection parent"))
        .expect("create mutant projection directory");
    let mut source_receipts = Vec::new();
    for entry in
        fs::read_dir(repository.join(".github/workflows")).expect("read live workflow directory")
    {
        let entry = entry.expect("read live workflow entry");
        source_receipts.push(
            stage_owned_workflow(&entry.path(), &workflows.join(entry.file_name()))
                .expect("stage owned live workflow bytes"),
        );
    }
    let mut projection_value: serde_json::Value = serde_json::from_slice(
        &fs::read(repository.join("ci/protocol/v1.audit.json")).expect("read live projection"),
    )
    .expect("parse live projection");
    let (needle, replacement) = mutate(&mut projection_value);
    let workflow = workflows.join("release.yml");
    let source = fs::read_to_string(&workflow).expect("read copied release workflow");
    assert_eq!(source.matches(needle).count(), 1, "mutation site inventory");
    let mutated = source.replacen(needle, replacement, 1);
    assert_ne!(source, mutated);
    fs::write(&workflow, mutated).expect("write permission mutant");
    for receipt in &source_receipts {
        receipt
            .require_unchanged()
            .expect("revalidate sealed workflow source after destination mutation");
    }
    let mut projection_bytes =
        serde_json::to_vec(&projection_value).expect("encode mutant projection");
    projection_bytes.push(b'\n');
    fs::write(&projection, projection_bytes).expect("write mutant projection");
    Fixture {
        directory,
        workflows,
        projection,
        metadata: repository.join("ci/actions/metadata-v1.json"),
        workflow,
        source_receipts,
    }
}

fn fixture() -> Fixture {
    let directory = TestDirectory::new("semantic");
    let workflows = directory.path.join(".github/workflows");
    let projection = directory.path.join("ci/protocol/v1.audit.json");
    let metadata = directory.path.join("ci/actions/metadata-v1.json");
    fs::create_dir_all(&workflows).expect("create workflows");
    fs::create_dir_all(projection.parent().expect("projection parent"))
        .expect("create projection parent");
    fs::create_dir_all(metadata.parent().expect("metadata parent"))
        .expect("create metadata parent");

    let workflow = workflows.join("ci.yml");
    write_workflow(&workflow);

    let mut metadata_bytes = serde_json::to_vec(&serde_json::json!({
        "actions": [],
        "lockId": "external-test-v1",
        "normalization": "closed-reviewed-action-metadata",
        "schemaVersion": 1,
    }))
    .expect("encode metadata");
    metadata_bytes.push(b'\n');
    fs::write(&metadata, &metadata_bytes).expect("write metadata");

    let projection_value = serde_json::json!({
        "actionMetadata": {
            "path": "ci/actions/metadata-v1.json",
            "sha256": protocol_sha256(&metadata_bytes),
        },
        "approvedCredentialCommands": [],
        "mergeQueue": false,
        "permissions": {
            "contents-read": {
                "actions": "none",
                "artifactMetadata": "none",
                "attestations": "none",
                "contents": "read",
                "idToken": "none",
            },
        },
        "protocolId": "external-semantic-audit-v1",
        "readinessSummary": {"artifacts": [], "jobs": []},
        "schemaVersion": 1,
        "workflows": [{
            "concurrency": {
                "cancelInProgress": true,
                "group": "audit-${{ github.ref }}",
            },
            "jobs": [{
                "condition": null,
                "id": "check",
                "name": "Check",
                "needs": [],
                "outputs": {},
                "permissionProfile": "contents-read",
                "runsOn": "ubuntu-24.04",
                "steps": [{
                    "command": {
                        "argv": ["cargo", "check", "--locked"],
                        "credential": "none",
                        "environment": {},
                        "executable": "cargo",
                        "workingDirectory": null,
                    },
                    "condition": null,
                    "kind": "command",
                    "name": "Check",
                    "ref": "cargo",
                    "stepId": null,
                }],
                "timeoutMinutes": 10,
            }],
            "name": "CI",
            "path": ".github/workflows/ci.yml",
            "permissionProfile": "contents-read",
            "triggers": [{
                "branches": [],
                "dispatchInputs": {},
                "event": "workflow_dispatch",
                "paths": [],
                "tags": [],
            }],
        }],
    });
    let mut projection_bytes = serde_json::to_vec(&projection_value).expect("encode projection");
    projection_bytes.push(b'\n');
    fs::write(&projection, projection_bytes).expect("write projection");
    Fixture {
        directory,
        workflows,
        projection,
        metadata,
        workflow,
        source_receipts: Vec::new(),
    }
}

fn write_workflow(path: &Path) {
    fs::write(
        path,
        concat!(
            "name: CI\n",
            "on:\n",
            "  workflow_dispatch: {}\n",
            "permissions:\n",
            "  contents: read\n",
            "concurrency:\n",
            "  group: audit-${{ github.ref }}\n",
            "  cancel-in-progress: true\n",
            "jobs:\n",
            "  check:\n",
            "    name: Check\n",
            "    runs-on: ubuntu-24.04\n",
            "    timeout-minutes: 10\n",
            "    steps:\n",
            "    - name: Check\n",
            "      run: cargo check --locked\n",
        ),
    )
    .expect("write workflow");
}
