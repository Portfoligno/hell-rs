use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use hell_release_publisher::{
    Host, Method, Phase, PublicationBundle, ReleasePlan, Request, Response, Transport,
    check_remote_state_with, protocol_sha256, publish_with, run, stage_attestations,
};
use serde_json::Value;

const REPOSITORY: &str = "example/hell-rs";
const REPOSITORY_ID: u64 = 424_242;
const CANDIDATE: &str = "434c9104de69600ce4a85601dc2ac48a45aa8f8f";
const WORKFLOW: &str = "550e4c3e094a75a4c362bd192ae5805837ac9741";
const TAG: &str = "0.1.0";
const ARTIFACT_ID: u64 = 8181;
const ARTIFACT_DIGEST: &str = "74d777fecc07408dbe4ebf9605d538e6f6adcdb7ac3f1c4c434c0d879877709e";

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn new(label: &str) -> Self {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "hell-release-publisher-{label}-{}-{sequence}",
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

struct FakeProvider {
    candidate: String,
    release_marker: String,
    created: bool,
    draft: bool,
    immutable: bool,
    tag_representation: TagRepresentation,
    expected_assets: BTreeMap<String, (u64, String)>,
    uploaded: BTreeMap<String, (u64, String)>,
    requests: Vec<Request>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum TagRepresentation {
    Direct,
    Annotated,
    Conflicting,
}

struct FirstResponse {
    response: Result<Response, hell_release_publisher::Failure>,
}

impl Transport for FirstResponse {
    fn send(
        &mut self,
        _request: Request,
        _deadline: Instant,
    ) -> Result<Response, hell_release_publisher::Failure> {
        self.response.clone()
    }
}

impl FakeProvider {
    fn stable(candidate: &str, plan_digest: &str) -> Self {
        Self {
            candidate: candidate.to_owned(),
            release_marker: format!("hell-rs-release-plan-sha256:{plan_digest}"),
            created: false,
            draft: true,
            immutable: false,
            tag_representation: TagRepresentation::Direct,
            expected_assets: BTreeMap::new(),
            uploaded: BTreeMap::new(),
            requests: Vec::new(),
        }
    }

    fn release(&self) -> Value {
        let assets = self
            .uploaded
            .iter()
            .map(|(name, (size, digest))| {
                serde_json::json!({
                    "digest": format!("sha256:{digest}"),
                    "name": name,
                    "size": size,
                })
            })
            .collect::<Vec<_>>();
        serde_json::json!({
            "assets": assets,
            "body": self.release_marker,
            "draft": self.draft,
            "id": 9090,
            "immutable": self.immutable,
            "name": TAG,
            "prerelease": false,
            "tag_name": TAG,
            "target_commitish": CANDIDATE,
        })
    }
}

impl Transport for FakeProvider {
    fn send(
        &mut self,
        request: Request,
        deadline: Instant,
    ) -> Result<Response, hell_release_publisher::Failure> {
        assert!(deadline > Instant::now());
        assert!(matches!(request.host, Host::Api | Host::Upload));
        let path = request.path.clone();
        let method = request.method.clone();
        let response = if method == Method::Get && path == "/repos/example/hell-rs" {
            json_response(
                200,
                &serde_json::json!({"full_name": REPOSITORY, "id": REPOSITORY_ID}),
            )
        } else if method == Method::Get && path == "/repos/example/hell-rs/git/ref/heads/main" {
            json_response(
                200,
                &serde_json::json!({"object": {"sha": self.candidate, "type": "commit"}}),
            )
        } else if method == Method::Get && path == "/repos/example/hell-rs/git/ref/tags/0.1.0" {
            if self.created && !self.draft {
                match self.tag_representation {
                    TagRepresentation::Annotated => json_response(
                        200,
                        &serde_json::json!({"object": {"sha": "3d3c42e5aac5ba805825da76410c181273ba90b1", "type": "tag"}}),
                    ),
                    TagRepresentation::Direct => json_response(
                        200,
                        &serde_json::json!({"object": {"sha": CANDIDATE, "type": "commit"}}),
                    ),
                    TagRepresentation::Conflicting => json_response(
                        200,
                        &serde_json::json!({"object": {"sha": content_sha("conflicting publisher tag target"), "type": "commit"}}),
                    ),
                }
            } else {
                Response {
                    status: 404,
                    body: b"{}".to_vec(),
                }
            }
        } else if method == Method::Get
            && path == "/repos/example/hell-rs/git/tags/3d3c42e5aac5ba805825da76410c181273ba90b1"
        {
            json_response(
                200,
                &serde_json::json!({
                    "object": {"sha": CANDIDATE, "type": "commit"},
                    "sha": "3d3c42e5aac5ba805825da76410c181273ba90b1",
                    "tag": TAG,
                }),
            )
        } else if method == Method::Get && path == "/repos/example/hell-rs/releases/tags/0.1.0" {
            if self.created {
                json_response(200, &self.release())
            } else {
                Response {
                    status: 404,
                    body: b"{}".to_vec(),
                }
            }
        } else if method == Method::Post && path == "/repos/example/hell-rs/releases" {
            assert!(!self.created);
            self.created = true;
            json_response(201, &self.release())
        } else if method == Method::Post
            && request.host == Host::Upload
            && path.starts_with("/repos/example/hell-rs/releases/9090/assets?name=")
        {
            let name = path
                .split_once("?name=")
                .map(|(_, name)| name)
                .expect("upload name");
            let expected = self.expected_assets.get(name).expect("known upload asset");
            assert_eq!(request.body.len() as u64, expected.0);
            assert_eq!(protocol_sha256(&request.body), expected.1);
            self.uploaded.insert(name.to_owned(), expected.clone());
            json_response(201, &serde_json::json!({"name": name}))
        } else if method == Method::Patch && path == "/repos/example/hell-rs/releases/9090" {
            assert_eq!(self.uploaded, self.expected_assets);
            self.draft = false;
            self.immutable = true;
            json_response(200, &self.release())
        } else {
            panic!("unexpected provider request: {method:?} {path}");
        };
        self.requests.push(request);
        Ok(response)
    }
}

#[test]
fn stable_remote_state_binds_repository_branch_and_absence() {
    let directory = TestDirectory::new("stable");
    let plan = write_plan(&directory.path);
    let mut provider = FakeProvider::stable(CANDIDATE, plan.plan_sha256());
    let receipt = check_remote_state_with(&mut provider, &plan, Phase::PreAttestation)
        .expect("stable state should be admitted");
    assert_eq!(receipt.repository_id, REPOSITORY_ID);
    assert_eq!(receipt.branch_sha, CANDIDATE);
    assert_eq!(receipt.tag_state, "absent");
    assert_eq!(receipt.release_state, "absent");
    assert_eq!(provider.requests.len(), 4);
}

#[test]
fn candidate_head_movement_is_rejected() {
    let directory = TestDirectory::new("moved");
    let plan = write_plan(&directory.path);
    let mut provider = FakeProvider::stable(
        &content_sha("moved publisher candidate head"),
        plan.plan_sha256(),
    );
    let error = check_remote_state_with(&mut provider, &plan, Phase::PrePublish)
        .expect_err("moved candidate must be rejected");
    assert_eq!(error.code, "publisher.candidate.moved");
}

#[test]
fn provider_forbidden_response_is_stable_rejection() {
    let directory = TestDirectory::new("forbidden");
    let plan = write_plan(&directory.path);
    let mut provider = FirstResponse {
        response: Ok(Response {
            status: 403,
            body: b"{}".to_vec(),
        }),
    };
    let error = check_remote_state_with(&mut provider, &plan, Phase::Resolve)
        .expect_err("forbidden response must reject");
    assert_eq!(error.code, "publisher.remote.forbidden");
}

#[test]
fn provider_duplicate_json_key_is_rejected() {
    let directory = TestDirectory::new("duplicate-json");
    let plan = write_plan(&directory.path);
    let mut provider = FirstResponse {
        response: Ok(Response {
            status: 200,
            body: format!(
                "{{\"full_name\":\"{REPOSITORY}\",\"id\":{REPOSITORY_ID},\"id\":{REPOSITORY_ID}}}"
            )
            .into_bytes(),
        }),
    };
    let error = check_remote_state_with(&mut provider, &plan, Phase::Resolve)
        .expect_err("duplicate response key must reject");
    assert_eq!(error.code, "publisher.remote.repository");
}

#[test]
fn provider_unknown_json_field_is_rejected() {
    let directory = TestDirectory::new("unknown-json");
    let plan = write_plan(&directory.path);
    let mut provider = FirstResponse {
        response: Ok(json_response(
            200,
            &serde_json::json!({
                "full_name": REPOSITORY,
                "id": REPOSITORY_ID,
                "unexpected": true,
            }),
        )),
    };
    let error = check_remote_state_with(&mut provider, &plan, Phase::Resolve)
        .expect_err("unknown response field must reject");
    assert_eq!(error.code, "publisher.remote.repository-json");
}

#[test]
fn provider_oversize_response_is_rejected() {
    let directory = TestDirectory::new("oversize");
    let plan = write_plan(&directory.path);
    let mut provider = FirstResponse {
        response: Ok(Response {
            status: 200,
            body: vec![b' '; 1024 * 1024 + 1],
        }),
    };
    let error = check_remote_state_with(&mut provider, &plan, Phase::Resolve)
        .expect_err("oversize response must reject");
    assert_eq!(error.code, "publisher.remote.response-oversize");
}

#[test]
fn provider_timeout_is_propagated_without_retrying_mutation() {
    let directory = TestDirectory::new("timeout");
    let plan = write_plan(&directory.path);
    let mut provider = FirstResponse {
        response: Err(hell_release_publisher::Failure::new(
            "publisher.deadline.exceeded",
            "fixture deadline elapsed",
        )),
    };
    let error = check_remote_state_with(&mut provider, &plan, Phase::Resolve)
        .expect_err("timeout must reject");
    assert_eq!(error.code, "publisher.deadline.exceeded");
}

#[test]
fn absent_release_transitions_through_exact_draft_to_immutable_publication() {
    let directory = TestDirectory::new("publish");
    let plan = write_plan(&directory.path);
    let bundle_root = directory.path.join("attested");
    let bundle = write_bundle(&bundle_root);
    let mut provider = FakeProvider::stable(CANDIDATE, plan.plan_sha256());
    provider.release_marker = release_marker(&directory.path, &plan);
    provider.expected_assets = bundle_assets(&bundle_root);
    let receipt = publish_with(&mut provider, &plan, &bundle, ARTIFACT_ID, ARTIFACT_DIGEST)
        .expect("exact absent state should publish");
    assert_eq!(receipt.state, "exact-published-immutable");
    assert!(!receipt.idempotent);
    assert_eq!(receipt.input_artifact_id, ARTIFACT_ID);
    assert_eq!(provider.uploaded, provider.expected_assets);
}

#[test]
fn exact_published_annotated_tag_is_idempotent() {
    let directory = TestDirectory::new("idempotent");
    let plan = write_plan(&directory.path);
    let bundle_root = directory.path.join("attested");
    let bundle = write_bundle(&bundle_root);
    let mut provider = FakeProvider::stable(CANDIDATE, plan.plan_sha256());
    provider.release_marker = release_marker(&directory.path, &plan);
    provider.expected_assets = bundle_assets(&bundle_root);
    provider.uploaded = provider.expected_assets.clone();
    provider.created = true;
    provider.draft = false;
    provider.immutable = true;
    provider.tag_representation = TagRepresentation::Annotated;
    let receipt = publish_with(&mut provider, &plan, &bundle, ARTIFACT_ID, ARTIFACT_DIGEST)
        .expect("exact published release should be idempotent");
    assert!(receipt.idempotent);
    assert_eq!(receipt.state, "exact-published-immutable");
}

#[test]
fn unexpected_draft_asset_is_rejected_without_overwrite() {
    let directory = TestDirectory::new("unexpected-asset");
    let plan = write_plan(&directory.path);
    let bundle_root = directory.path.join("attested");
    let bundle = write_bundle(&bundle_root);
    let mut provider = FakeProvider::stable(CANDIDATE, plan.plan_sha256());
    provider.release_marker = release_marker(&directory.path, &plan);
    provider.expected_assets = bundle_assets(&bundle_root);
    provider.created = true;
    provider.uploaded.insert(
        "unexpected.bin".to_owned(),
        (1, digest("unexpected draft asset fixture")),
    );
    let error = publish_with(&mut provider, &plan, &bundle, ARTIFACT_ID, ARTIFACT_DIGEST)
        .expect_err("unexpected draft asset must reject");
    assert_eq!(error.code, "publisher.state.unexpected-asset");
    assert!(provider.draft);
}

#[test]
fn governance_inputs_are_required_and_tampering_is_rejected() {
    let directory = TestDirectory::new("governance-tamper");
    let plan = write_plan(&directory.path);
    let bundle_root = directory.path.join("attested");
    write_verified_skeleton(&bundle_root);
    fs::write(
        bundle_root.join("github-provenance.sigstore.json"),
        b"{\"kind\":\"build\"}\n",
    )
    .expect("write build attestation");
    fs::write(
        bundle_root.join("github-release-gate.sigstore.json"),
        b"{\"kind\":\"gate\"}\n",
    )
    .expect("write gate attestation");
    let baseline = directory.path.join("governance-resolve.json");
    let receipt = directory.path.join("governance-pre-publish.json");
    let Err(missing) = PublicationBundle::read(
        &bundle_root,
        &plan,
        ARTIFACT_DIGEST,
        &directory.path.join("missing-governance-resolve.json"),
        &receipt,
    ) else {
        panic!("missing governance baseline must reject");
    };
    assert_eq!(missing.code, "publisher.governance.input");

    let mut receipt_value: Value =
        serde_json::from_slice(&fs::read(&receipt).expect("read governance receipt"))
            .expect("parse governance receipt");
    receipt_value["candidateSha"] = Value::String(digest("tampered governance candidate"));
    write_json(&receipt, &receipt_value);
    let Err(tampered) =
        PublicationBundle::read(&bundle_root, &plan, ARTIFACT_DIGEST, &baseline, &receipt)
    else {
        panic!("tampered governance receipt must reject");
    };
    assert_eq!(tampered.code, "publisher.governance.binding");
}

#[test]
fn envelope_must_bind_the_exact_pre_publish_predecessor() {
    let directory = TestDirectory::new("governance-predecessor");
    let plan = write_plan(&directory.path);
    let bundle_root = directory.path.join("attested");
    write_verified_skeleton(&bundle_root);
    fs::write(
        bundle_root.join("github-provenance.sigstore.json"),
        b"{\"kind\":\"build\"}\n",
    )
    .expect("write build attestation");
    fs::write(
        bundle_root.join("github-release-gate.sigstore.json"),
        b"{\"kind\":\"gate\"}\n",
    )
    .expect("write gate attestation");
    let baseline = directory.path.join("governance-resolve.json");
    let receipt = directory.path.join("governance-pre-publish.json");
    let mut receipt_value: Value =
        serde_json::from_slice(&fs::read(&receipt).expect("read governance receipt"))
            .expect("parse governance receipt");
    receipt_value["predecessorSha256"] =
        Value::String(digest("different pre-attestation governance receipt"));
    write_json(&receipt, &receipt_value);
    let Err(error) =
        PublicationBundle::read(&bundle_root, &plan, ARTIFACT_DIGEST, &baseline, &receipt)
    else {
        panic!("envelope predecessor mismatch must reject");
    };
    assert_eq!(error.code, "publisher.envelope.governance");
}

#[test]
fn published_state_is_bound_to_the_input_artifact_id() {
    let directory = TestDirectory::new("artifact-id-idempotence");
    let plan = write_plan(&directory.path);
    let bundle_root = directory.path.join("attested");
    let bundle = write_bundle(&bundle_root);
    let mut provider = FakeProvider::stable(CANDIDATE, plan.plan_sha256());
    provider.release_marker = release_marker(&directory.path, &plan);
    provider.expected_assets = bundle_assets(&bundle_root);
    publish_with(&mut provider, &plan, &bundle, ARTIFACT_ID, ARTIFACT_DIGEST)
        .expect("first publication should succeed");
    let error = publish_with(
        &mut provider,
        &plan,
        &bundle,
        ARTIFACT_ID.wrapping_add(1),
        ARTIFACT_DIGEST,
    )
    .expect_err("different artifact ID must not be treated as idempotent");
    assert_eq!(error.code, "publisher.state.conflicting-published");
}

#[test]
fn stage_preserves_verified_bytes_and_adds_only_two_attestations() {
    let directory = TestDirectory::new("stage");
    let input = directory.path.join("verified");
    write_verified_skeleton(&input);
    let build = directory.path.join("build.json");
    let gate = directory.path.join("gate.json");
    fs::write(&build, b"{\"kind\":\"build\"}\n").expect("write build bundle");
    fs::write(&gate, b"{\"kind\":\"gate\"}\n").expect("write gate bundle");
    let output = directory.path.join("attested");
    let before = bundle_bytes(&input);
    stage_attestations(&input, &build, &gate, &output).expect("stage attestations");
    let after = bundle_bytes(&output);
    for (name, bytes) in before {
        assert_eq!(after.get(&name), Some(&bytes));
    }
    assert_eq!(after.len(), 12);
    assert_eq!(
        after["github-provenance.sigstore.json"],
        b"{\"kind\":\"build\"}\n"
    );
    assert_eq!(
        after["github-release-gate.sigstore.json"],
        b"{\"kind\":\"gate\"}\n"
    );
}

#[test]
fn invalid_artifact_id_writes_bounded_typed_rejection_report() {
    let directory = TestDirectory::new("artifact-id-report");
    write_plan(&directory.path);
    let bundle_root = directory.path.join("attested-release");
    write_bundle(&bundle_root);
    let report = directory.path.join("publish-report.json");
    let arguments = [
        OsString::from("publish"),
        OsString::from("--plan"),
        directory.path.join("release-plan.json").into_os_string(),
        OsString::from("--input"),
        bundle_root.into_os_string(),
        OsString::from("--expected-artifact-id"),
        OsString::from("0"),
        OsString::from("--expected-artifact-digest"),
        OsString::from(ARTIFACT_DIGEST),
        OsString::from("--governance-baseline"),
        directory
            .path
            .join("governance-resolve.json")
            .into_os_string(),
        OsString::from("--governance-receipt"),
        directory
            .path
            .join("governance-pre-publish.json")
            .into_os_string(),
        OsString::from("--report"),
        report.as_os_str().to_owned(),
    ];
    let error = run(&arguments).expect_err("zero artifact ID must reject");
    assert_eq!(error.code, "publisher.artifact-id.invalid");
    let bytes = fs::read(report).expect("read rejection report");
    assert!(bytes.ends_with(b"\n"));
    assert!(bytes.len() < 8 * 1024);
    let value: Value = serde_json::from_slice(&bytes).expect("parse rejection report");
    assert_eq!(value.get("admitted").and_then(Value::as_bool), Some(false));
    assert_eq!(
        value
            .get("diagnostic")
            .and_then(|diagnostic| diagnostic.get("code"))
            .and_then(Value::as_str),
        Some("publisher.artifact-id.invalid")
    );
}

#[test]
fn production_dependency_boundary_excludes_deep_verification_crates() {
    let manifest = include_str!("../Cargo.toml");
    for prohibited in ["hell-ci", "hell-testkit", "flate2", "tar ="] {
        assert!(!manifest.contains(prohibited));
    }
}

#[test]
fn committed_publisher_control_vectors_execute_exact_state_mutations() {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace crates directory")
        .parent()
        .expect("workspace root");
    let manifest = fs::read_to_string(repository.join("ci/control-vectors/v1/manifest.toml"))
        .expect("read control-vector manifest");
    let publisher_ids = publisher_vector_ids(&manifest);
    assert_eq!(
        publisher_ids,
        [
            "publisher-conflicting-draft",
            "publisher-conflicting-tag",
            "publisher-envelope-predecessor-mismatch",
            "publisher-unexpected-asset",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<std::collections::BTreeSet<_>>()
    );
    for id in publisher_ids {
        let observed = execute_publisher_control_vector(&id);
        let expected = match id.as_str() {
            "publisher-conflicting-draft" => "publisher.state.unexpected-draft",
            "publisher-conflicting-tag" => "publisher.state.conflicting-tag",
            "publisher-envelope-predecessor-mismatch" => "publisher.envelope.governance",
            "publisher-unexpected-asset" => "publisher.state.unexpected-asset",
            _ => panic!("unbound publisher control vector {id:?}"),
        };
        assert_eq!(observed, expected, "publisher control vector {id}");
    }
}

fn publisher_vector_ids(manifest: &str) -> std::collections::BTreeSet<String> {
    let mut ids = std::collections::BTreeSet::new();
    let mut id = None::<String>;
    let mut surface = None::<String>;
    for line in manifest.lines().chain(["[[vector]]"]) {
        let line = line.trim();
        if line == "[[vector]]" {
            if surface.as_deref() == Some("publisher") {
                ids.insert(id.take().expect("publisher vector ID"));
            }
            id = None;
            surface = None;
        } else if let Some(value) = line.strip_prefix("id = ") {
            id = Some(unquote_manifest_value(value));
        } else if let Some(value) = line.strip_prefix("surface = ") {
            surface = Some(unquote_manifest_value(value));
        }
    }
    ids
}

fn unquote_manifest_value(value: &str) -> String {
    value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .expect("quoted manifest value")
        .to_owned()
}

fn execute_publisher_control_vector(id: &str) -> &'static str {
    let directory = TestDirectory::new(id);
    let plan = write_plan(&directory.path);
    let bundle_root = directory.path.join("attested");
    match id {
        "publisher-envelope-predecessor-mismatch" => {
            write_verified_skeleton(&bundle_root);
            fs::write(
                bundle_root.join("github-provenance.sigstore.json"),
                b"{\"kind\":\"build\"}\n",
            )
            .expect("write build attestation");
            fs::write(
                bundle_root.join("github-release-gate.sigstore.json"),
                b"{\"kind\":\"gate\"}\n",
            )
            .expect("write gate attestation");
            let receipt = directory.path.join("governance-pre-publish.json");
            let mut receipt_value: Value =
                serde_json::from_slice(&fs::read(&receipt).expect("read governance receipt"))
                    .expect("parse governance receipt");
            receipt_value["predecessorSha256"] =
                Value::String(digest("control vector predecessor mismatch"));
            write_json(&receipt, &receipt_value);
            let Err(error) = PublicationBundle::read(
                &bundle_root,
                &plan,
                ARTIFACT_DIGEST,
                &directory.path.join("governance-resolve.json"),
                &receipt,
            ) else {
                panic!("predecessor mismatch must reject");
            };
            error.code
        }
        "publisher-conflicting-draft"
        | "publisher-conflicting-tag"
        | "publisher-unexpected-asset" => {
            let bundle = write_bundle(&bundle_root);
            let mut provider = FakeProvider::stable(CANDIDATE, plan.plan_sha256());
            provider.release_marker = release_marker(&directory.path, &plan);
            provider.expected_assets = bundle_assets(&bundle_root);
            provider.created = true;
            match id {
                "publisher-conflicting-draft" => {
                    "conflicting publisher draft".clone_into(&mut provider.release_marker);
                }
                "publisher-conflicting-tag" => {
                    provider.draft = false;
                    provider.immutable = true;
                    provider.uploaded = provider.expected_assets.clone();
                    provider.tag_representation = TagRepresentation::Conflicting;
                }
                "publisher-unexpected-asset" => {
                    provider.uploaded.insert(
                        "unexpected.bin".to_owned(),
                        (1, digest("unexpected publisher asset")),
                    );
                }
                _ => unreachable!("publisher vector inventory matched above"),
            }
            publish_with(&mut provider, &plan, &bundle, ARTIFACT_ID, ARTIFACT_DIGEST)
                .expect_err("publisher control vector must reject")
                .code
        }
        _ => panic!("unknown publisher control vector {id:?}"),
    }
}

fn json_response(status: u16, value: &Value) -> Response {
    Response {
        status,
        body: serde_json::to_vec(&value).expect("encode fake response"),
    }
}

fn write_plan(root: &Path) -> ReleasePlan {
    let path = root.join("release-plan.json");
    let mut value = serde_json::json!({
        "actor": "release-operator",
        "actorId": 7,
        "buildInputsSha256": digest("publisher build inputs"),
        "candidateBranch": "main",
        "candidateSha": CANDIDATE,
        "changelogSha256": digest("publisher changelog"),
        "commitAuthor": "author",
        "commitCommitter": "committer",
        "conformancePlanSha256": digest("publisher conformance plan"),
        "conformanceStandard": "release-admission-v1",
        "defaultBranch": "main",
        "externalInputsSha256": digest("publisher external inputs"),
        "expectedPlatforms": ["linux-x86_64", "macos-aarch64", "windows-x86_64"],
        "governanceDeclarationSha256": digest("publisher governance declaration"),
        "governanceProfileSha256": digest("publisher governance declaration profile"),
        "policySha256": digest("publisher release policy"),
        "prerelease": false,
        "releaseBinary": "hell",
        "releaseEvaluationInstant": "2026-01-01T00:00:00Z",
        "releasePackage": "hell-cli",
        "repository": REPOSITORY,
        "repositoryId": REPOSITORY_ID,
        "residualAssumptionSetSha256": digest("publisher declared residual set"),
        "runAttempt": 1,
        "runId": 99,
        "schemaVersion": 2,
        "sourceDateEpoch": 1_767_225_600,
        "sourceInventorySha256": digest("publisher source inventory"),
        "tag": TAG,
        "trustedConformanceInputsSha256": digest("publisher trusted conformance inputs"),
        "version": TAG,
        "workflowRef": "example/hell-rs/.github/workflows/release.yml@refs/heads/main",
        "workflowSha": WORKFLOW,
    });
    let digest = protocol_sha256(&json_bytes(&value));
    value
        .as_object_mut()
        .expect("plan object")
        .insert("planSha256".to_owned(), Value::String(digest));
    write_json(&path, &value);
    ReleasePlan::read(&path).expect("read release plan")
}

fn write_bundle(root: &Path) -> PublicationBundle {
    write_verified_skeleton(root);
    fs::write(
        root.join("github-provenance.sigstore.json"),
        b"{\"kind\":\"build\"}\n",
    )
    .expect("write build attestation");
    fs::write(
        root.join("github-release-gate.sigstore.json"),
        b"{\"kind\":\"gate\"}\n",
    )
    .expect("write gate attestation");
    let plan_root = root.parent().expect("bundle parent");
    let plan = ReleasePlan::read(&plan_root.join("release-plan.json")).expect("read plan");
    PublicationBundle::read(
        root,
        &plan,
        ARTIFACT_DIGEST,
        &plan_root.join("governance-resolve.json"),
        &plan_root.join("governance-pre-publish.json"),
    )
    .expect("read publication bundle")
}

fn write_verified_skeleton(root: &Path) {
    fs::create_dir(root).expect("create verified root");
    let subject = b"release-product";
    fs::write(root.join("hell-linux.tar.gz"), subject).expect("write subject");
    let subjects = format!("{}  hell-linux.tar.gz\n", protocol_sha256(subject));
    fs::write(root.join("SUBJECTS.sha256"), subjects.as_bytes()).expect("write subjects");
    for name in [
        "release-gate.json",
        "primary-verifier-report.json",
        "independent-verifier-report.json",
        "verifier-agreement.json",
    ] {
        fs::write(root.join(name), b"{}\n").expect("write metadata");
    }
    let primary = b"{\"decision\":\"primary\"}\n";
    let independent = b"{\"decision\":\"independent\"}\n";
    fs::write(root.join("primary-verifier-decision.json"), primary).expect("write primary");
    fs::write(root.join("independent-verifier-decision.json"), independent)
        .expect("write independent");
    let plan_path = root
        .parent()
        .expect("verified parent")
        .join("release-plan.json");
    if !plan_path.exists() {
        let _plan = write_plan(root.parent().expect("verified parent"));
    }
    let plan_value: Value =
        serde_json::from_slice(&fs::read(&plan_path).expect("read plan")).expect("parse plan");
    let plan_sha = plan_value["planSha256"].as_str().expect("plan SHA");
    let governance =
        write_governance_receipts(root.parent().expect("verified parent"), &plan_value);
    let envelope = serde_json::json!({
        "admitted": true,
        "assembledArtifactDigest": digest("publisher assembled artifact"),
        "candidateSha": CANDIDATE,
        "cellLedgerSha256": digest("publisher cell ledger"),
        "conformancePlanSha256": digest("publisher conformance plan"),
        "evaluationInstant": "2026-01-01T00:00:00Z",
        "externalInputsSha256": plan_value["externalInputsSha256"],
        "governanceDeclarationSha256": plan_value["governanceDeclarationSha256"],
        "governancePostAssemblySha256": digest("publisher post-assembly governance receipt"),
        "governancePreAttestationSha256": governance.pre_attestation_sha256,
        "governanceProfileSha256": plan_value["governanceProfileSha256"],
        "governanceResolveSha256": governance.resolve_sha256,
        "independentVerifierDecisionSha256": protocol_sha256(independent),
        "nativeEnvironmentSetSha256": digest("publisher native environment set"),
        "obligationRulesSha256": digest("publisher obligation rules"),
        "primaryVerifierDecisionSha256": protocol_sha256(primary),
        "protocolSha256": digest("publisher protocol"),
        "protocolVersion": "release-admission-v1",
        "releaseGateSha256": digest("publisher release gate"),
        "releasePlanSha256": plan_sha,
        "repositoryId": REPOSITORY_ID,
        "repositoryName": "hell-rs",
        "repositoryOwner": "example",
        "residualAssumptionSetSha256": plan_value["residualAssumptionSetSha256"],
        "schemaVersion": 1,
        "sourceDateEpoch": 1_767_225_600,
        "sourceInventorySha256": plan_value["sourceInventorySha256"],
        "subjectManifestSha256": protocol_sha256(subjects.as_bytes()),
        "tag": TAG,
        "trustedInputsSha256": plan_value["trustedConformanceInputsSha256"],
        "verifierAgreementSha256": protocol_sha256(b"{}\n"),
        "version": TAG,
        "workflowSha": WORKFLOW,
    });
    let envelope_bytes = json_bytes(&envelope);
    fs::write(root.join("publication-envelope.json"), &envelope_bytes).expect("write envelope");
    let receipt = serde_json::json!({
        "artifactDigest": digest("publisher assembled artifact"),
        "envelopeSha256": protocol_sha256(&envelope_bytes),
        "schemaVersion": 1,
        "state": "verified",
    });
    write_json(
        &root.join("publication-envelope-verification.json"),
        &receipt,
    );
}

struct GovernanceFixture {
    pre_attestation_sha256: String,
    resolve_sha256: String,
}

fn write_governance_receipts(root: &Path, plan: &Value) -> GovernanceFixture {
    let controls = [
        "allowed-actions",
        "branch-and-ruleset-protection",
        "candidate-head",
        "default-branch",
        "immutable-releases",
        "merge-queue",
        "release-tag",
        "repository-identity",
        "tag-protection",
        "workflow-token-permissions",
    ];
    let observations = Value::Array(
        controls
            .into_iter()
            .map(|control| {
                serde_json::json!({
                    "controlId": control,
                    "endpointId": control,
                    "evaluation": "matched",
                    "httpStatus": 200,
                    "normalizedValue": {"fixtureControl": control},
                    "residualAssumptionId": null,
                    "status": "observed",
                })
            })
            .collect(),
    );
    let residuals = Value::Array(Vec::new());
    let resolve = governance_receipt(plan, "resolve", None, None, None, &observations, &residuals);
    let resolve_path = root.join("governance-resolve.json");
    write_json(&resolve_path, &resolve);
    let resolve_sha256 = protocol_sha256(&fs::read(&resolve_path).expect("read resolve receipt"));
    let post_assembly_sha256 = digest("publisher post-assembly governance receipt");
    let pre_attestation = governance_receipt(
        plan,
        "pre-attestation",
        Some(&resolve_sha256),
        Some("post-assembly"),
        Some(&post_assembly_sha256),
        &observations,
        &residuals,
    );
    let pre_attestation_bytes = json_bytes(&pre_attestation);
    let pre_attestation_sha256 = protocol_sha256(&pre_attestation_bytes);
    let pre_publish = governance_receipt(
        plan,
        "pre-publish",
        Some(&resolve_sha256),
        Some("pre-attestation"),
        Some(&pre_attestation_sha256),
        &observations,
        &residuals,
    );
    let pre_publish_path = root.join("governance-pre-publish.json");
    write_json(&pre_publish_path, &pre_publish);
    GovernanceFixture {
        pre_attestation_sha256,
        resolve_sha256,
    }
}

fn governance_receipt(
    plan: &Value,
    phase: &str,
    baseline_sha256: Option<&str>,
    predecessor_phase: Option<&str>,
    predecessor_sha256: Option<&str>,
    observations: &Value,
    residuals: &Value,
) -> Value {
    let profile = serde_json::json!({
        "governanceDeclarationSha256": plan["governanceDeclarationSha256"],
        "observations": observations,
        "phase": phase,
        "planSha256": plan["planSha256"],
        "repositoryId": plan["repositoryId"],
        "residualAssumptions": residuals,
        "schemaVersion": 1,
    });
    serde_json::json!({
        "apiPolicySha256": digest("publisher GitHub API policy"),
        "baselineSha256": baseline_sha256,
        "candidateBranch": plan["candidateBranch"],
        "candidateSha": plan["candidateSha"],
        "governanceDeclarationSha256": plan["governanceDeclarationSha256"],
        "governanceProfileSha256": domain_digest(b"hell-rs:governance-profile:1", &profile),
        "observations": observations,
        "phase": phase,
        "planSha256": plan["planSha256"],
        "predecessorPhase": predecessor_phase,
        "predecessorSha256": predecessor_sha256,
        "repository": plan["repository"],
        "repositoryId": plan["repositoryId"],
        "residualAssumptionSetSha256": domain_digest(
            b"hell-rs:residual-assumption-set:1",
            residuals,
        ),
        "residualAssumptions": residuals,
        "runAttempt": plan["runAttempt"],
        "runId": plan["runId"],
        "schemaVersion": 1,
        "tag": plan["tag"],
        "workflowRef": plan["workflowRef"],
        "workflowSha": plan["workflowSha"],
    })
}

fn release_marker(root: &Path, plan: &ReleasePlan) -> String {
    let baseline = fs::read(root.join("governance-resolve.json")).expect("read baseline");
    let receipt_bytes =
        fs::read(root.join("governance-pre-publish.json")).expect("read governance receipt");
    let receipt: Value = serde_json::from_slice(&receipt_bytes).expect("parse governance receipt");
    [
        format!("hell-rs-release-plan-sha256:{}", plan.plan_sha256()),
        format!("hell-rs-input-artifact-id:{ARTIFACT_ID}"),
        format!("hell-rs-input-artifact-digest:{ARTIFACT_DIGEST}"),
        format!(
            "hell-rs-governance-resolve-sha256:{}",
            protocol_sha256(&baseline)
        ),
        format!(
            "hell-rs-governance-pre-attestation-sha256:{}",
            receipt["predecessorSha256"]
                .as_str()
                .expect("pre-attestation receipt digest")
        ),
        format!(
            "hell-rs-governance-pre-publish-sha256:{}",
            protocol_sha256(&receipt_bytes)
        ),
    ]
    .join("\n")
}

fn digest(label: &str) -> String {
    protocol_sha256(label.as_bytes())
}

fn content_sha(label: &str) -> String {
    let shape = "0000000000000000000000000000000000000000";
    digest(label).chars().take(shape.len()).collect()
}

fn domain_digest(domain: &[u8], value: &Value) -> String {
    let canonical = json_bytes(value);
    let mut bytes = Vec::with_capacity(domain.len() + 1 + canonical.len());
    bytes.extend_from_slice(domain);
    bytes.push(0);
    bytes.extend_from_slice(&canonical);
    protocol_sha256(&bytes)
}

fn write_json(path: &Path, value: &Value) {
    fs::write(path, json_bytes(value)).expect("write JSON");
}

fn json_bytes(value: &Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(value).expect("encode JSON");
    bytes.push(b'\n');
    bytes
}

fn bundle_assets(root: &Path) -> BTreeMap<String, (u64, String)> {
    bundle_bytes(root)
        .into_iter()
        .map(|(name, bytes)| (name, (bytes.len() as u64, protocol_sha256(&bytes))))
        .collect()
}

fn bundle_bytes(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fs::read_dir(root)
        .expect("enumerate bundle")
        .map(|entry| {
            let entry = entry.expect("bundle entry");
            (
                entry.file_name().into_string().expect("UTF-8 filename"),
                fs::read(entry.path()).expect("read bundle file"),
            )
        })
        .collect()
}
