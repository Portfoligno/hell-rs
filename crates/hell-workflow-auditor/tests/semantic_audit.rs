use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use hell_workflow_auditor::{protocol_sha256, run};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

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
    let report = fixture.directory.path.join("attest-contents-report.json");
    let error = run(&audit_arguments(&fixture, &report))
        .expect_err("attest contents write permission must reject");
    assert_eq!(error.code, "workflow.permission.attest");
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
    let report = fixture.directory.path.join("publish-id-token-report.json");
    let error = run(&audit_arguments(&fixture, &report))
        .expect_err("publish ID-token write permission must reject");
    assert_eq!(error.code, "workflow.permission.publish");
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
    for entry in
        fs::read_dir(repository.join(".github/workflows")).expect("read live workflow directory")
    {
        let entry = entry.expect("read live workflow entry");
        let metadata = entry.metadata().expect("read live workflow metadata");
        assert!(metadata.is_file());
        fs::copy(entry.path(), workflows.join(entry.file_name())).expect("copy live workflow");
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
