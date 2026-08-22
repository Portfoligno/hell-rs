use std::collections::BTreeMap;
use std::fs;
use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "hell-governance-snapshot-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("create fixture root");
        Self { root }
    }

    fn write(&self, relative: &str, contents: &[u8]) -> PathBuf {
        let path = self.root.join(relative);
        fs::create_dir_all(path.parent().expect("fixture parent")).expect("create fixture parent");
        fs::write(&path, contents).expect("write fixture file");
        path
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).expect("remove fixture root");
    }
}

#[test]
fn governance_snapshots_bind_runtime_plan_baseline_and_live_controls() {
    let fixture = Fixture::new();
    let repository_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    require_governance_control_vector(&repository_root);
    let policy_bytes = fs::read(repository_root.join("ci/governance-policy.toml"))
        .expect("read governance policy");
    let api_policy_bytes =
        fs::read(repository_root.join("ci/github-api.toml")).expect("read API policy");
    let policy = fixture.write("governance-policy.toml", &policy_bytes);
    let api_policy = fixture.write("github-api.toml", &api_policy_bytes);
    let identity = RuntimeIdentity::new(&fixture);
    let plan = fixture.write("release-plan.json", &release_plan(&policy_bytes, &identity));
    let context = GovernanceContext {
        fixture: &fixture,
        identity: &identity,
        policy: &policy,
        api_policy: &api_policy,
        plan: &plan,
    };
    let resolve = verify_resolve_snapshot(&context);
    let post_assembly = verify_post_assembly_snapshot(&context, &resolve);
    let pre_attestation = verify_pre_attestation_snapshot(&context, &resolve, &post_assembly);
    verify_pre_publish_snapshot(&context, &resolve, &pre_attestation);
    verify_disclosed_residuals(&context);
    verify_changed_baseline_rejection(&context, &resolve, &post_assembly);
    verify_runtime_identity_rejection(&context);
}

fn verify_resolve_snapshot(context: &GovernanceContext<'_>) -> PathBuf {
    let snapshot = context.fixture.root.join("governance-resolve.json");
    let report = context.fixture.root.join("governance-resolve-report.json");
    let server = FakeProvider::start(provider_responses(context.identity, 41));
    let api_url = server.api_url();
    let result = context.run(&SnapshotRequest::new(
        "resolve", &snapshot, &report, &api_url,
    ));
    server.finish();
    assert!(result.status.success(), "{:?}", result.stderr);
    let value = read_json(&snapshot);
    assert_eq!(value["phase"], "resolve");
    assert_eq!(value["baselineSha256"], serde_json::Value::Null);
    assert_eq!(value["predecessorPhase"], serde_json::Value::Null);
    assert_eq!(value["repositoryId"], context.identity.repository_id);
    assert_eq!(read_json(&report)["admitted"], true);
    snapshot
}

fn verify_post_assembly_snapshot(context: &GovernanceContext<'_>, resolve: &Path) -> PathBuf {
    let snapshot = context.fixture.root.join("governance-post-assembly.json");
    let report = context
        .fixture
        .root
        .join("governance-post-assembly-report.json");
    let server = FakeProvider::start(provider_responses(context.identity, 41));
    let api_url = server.api_url();
    let result = context.run(
        &SnapshotRequest::new("post-assembly", &snapshot, &report, &api_url).baseline(resolve),
    );
    server.finish();
    assert!(result.status.success(), "{:?}", result.stderr);
    let value = read_json(&snapshot);
    assert_eq!(value["predecessorPhase"], "resolve");
    assert_eq!(
        value["baselineSha256"],
        hell_testkit::sha256_bytes(&fs::read(resolve).expect("read baseline")).hex()
    );
    assert_eq!(read_json(&report)["admitted"], true);
    snapshot
}

fn verify_pre_attestation_snapshot(
    context: &GovernanceContext<'_>,
    resolve: &Path,
    post_assembly: &Path,
) -> PathBuf {
    let snapshot = context.fixture.root.join("governance-pre-attestation.json");
    let report = context
        .fixture
        .root
        .join("governance-pre-attestation-report.json");
    let server = FakeProvider::start(provider_responses(context.identity, 41));
    let api_url = server.api_url();
    let result = context.run(
        &SnapshotRequest::new("pre-attestation", &snapshot, &report, &api_url)
            .baseline(resolve)
            .predecessor(post_assembly),
    );
    server.finish();
    assert!(result.status.success(), "{:?}", result.stderr);
    let value = read_json(&snapshot);
    assert_eq!(value["predecessorPhase"], "post-assembly");
    assert_eq!(
        value["predecessorSha256"],
        hell_testkit::sha256_bytes(&fs::read(post_assembly).expect("read predecessor")).hex()
    );
    snapshot
}

fn verify_pre_publish_snapshot(
    context: &GovernanceContext<'_>,
    resolve: &Path,
    pre_attestation: &Path,
) {
    let snapshot = context.fixture.root.join("governance-pre-publish.json");
    let report = context
        .fixture
        .root
        .join("governance-pre-publish-report.json");
    let server = FakeProvider::start(provider_responses(context.identity, 41));
    let api_url = server.api_url();
    let result = context.run(
        &SnapshotRequest::new("pre-publish", &snapshot, &report, &api_url)
            .baseline(resolve)
            .predecessor(pre_attestation),
    );
    server.finish();
    assert!(result.status.success(), "{:?}", result.stderr);
    let value = read_json(&snapshot);
    assert_eq!(value["predecessorPhase"], "pre-attestation");
    assert_eq!(
        value["predecessorSha256"],
        hell_testkit::sha256_bytes(&fs::read(pre_attestation).expect("read predecessor")).hex()
    );
}

fn verify_disclosed_residuals(context: &GovernanceContext<'_>) {
    let snapshot = context.fixture.root.join("governance-residual.json");
    let report = context.fixture.root.join("governance-residual-report.json");
    let mut responses = provider_responses(context.identity, 41);
    responses[3] = http_response("403 Forbidden", &serde_json::json!({}));
    let server = FakeProvider::start(responses);
    let api_url = server.api_url();
    let result = context.run(&SnapshotRequest::new(
        "resolve", &snapshot, &report, &api_url,
    ));
    server.finish();
    assert!(result.status.success(), "{:?}", result.stderr);
    assert_eq!(
        read_json(&snapshot)["residualAssumptions"],
        serde_json::json!(["ruleset-api-unavailable", "tag-rules-api-unavailable"])
    );
    assert_eq!(read_json(&report)["admitted"], true);
}

fn verify_changed_baseline_rejection(
    context: &GovernanceContext<'_>,
    resolve: &Path,
    post_assembly: &Path,
) {
    let output = context.fixture.root.join("governance-changed.json");
    let report = context.fixture.root.join("governance-changed-report.json");
    let server = FakeProvider::start(provider_responses(context.identity, 73));
    let api_url = server.api_url();
    let result = context.run(
        &SnapshotRequest::new("pre-attestation", &output, &report, &api_url)
            .baseline(resolve)
            .predecessor(post_assembly),
    );
    server.finish();
    assert!(!result.status.success());
    assert!(!output.exists());
    let rejection = read_json(&report);
    assert_eq!(rejection["admitted"], false);
    assert_eq!(
        rejection["diagnostic"]["code"],
        "governance.baseline.changed"
    );
    assert!(
        !String::from_utf8_lossy(&result.stderr.retained_bytes()).contains(&context.identity.token)
    );
}

fn verify_runtime_identity_rejection(context: &GovernanceContext<'_>) {
    let output = context.fixture.root.join("governance-mismatch.json");
    let report = context.fixture.root.join("governance-mismatch-report.json");
    let result = context.run(
        &SnapshotRequest::new("resolve", &output, &report, "http://127.0.0.1:9")
            .repository_id(context.identity.repository_id.wrapping_add(1)),
    );
    assert!(!result.status.success());
    assert!(!output.exists());
    assert_eq!(
        read_json(&report)["diagnostic"]["code"],
        "governance.runtime.identity"
    );
}

fn require_governance_control_vector(repository_root: &Path) {
    let manifest = fs::read_to_string(repository_root.join("ci/control-vectors/v1/manifest.toml"))
        .expect("read control-vector manifest");
    let mut matching = Vec::new();
    for record in manifest.split("[[vector]]").skip(1) {
        let mut fields = BTreeMap::new();
        for line in record
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
        {
            let Some((key, value)) = line.split_once(" = ") else {
                continue;
            };
            let value = value
                .strip_prefix('"')
                .and_then(|value| value.strip_suffix('"'))
                .expect("quoted control-vector value");
            assert!(
                fields.insert(key, value).is_none(),
                "duplicate vector field"
            );
        }
        if fields.get("id") == Some(&"governance-ruleset-unavailable-residual") {
            matching.push(fields);
        }
    }
    let [fields] = matching.as_slice() else {
        panic!("governance residual control vector must occur exactly once");
    };
    assert_eq!(fields.len(), 3);
    assert_eq!(fields.get("surface"), Some(&"governance"));
    assert_eq!(fields.get("expected"), Some(&"residual-assumption"));
}

struct RuntimeIdentity {
    candidate_branch: String,
    candidate_sha: String,
    event_path: PathBuf,
    repository: String,
    repository_id: u64,
    run_attempt: u64,
    run_id: u64,
    tag: String,
    token: String,
    workflow_ref: String,
    workflow_sha: String,
}

impl RuntimeIdentity {
    fn new(fixture: &Fixture) -> Self {
        let repository = "Portfoligno/hell-rs".to_owned();
        let repository_id = content_id(&repository);
        let event_path = fixture.write(
            "event.json",
            &canonical_json(&serde_json::json!({
                "repository": {"full_name": repository.clone(), "id": repository_id}
            })),
        );
        Self {
            candidate_branch: "release/governance-fixture".to_owned(),
            candidate_sha: content_sha("governance candidate"),
            event_path,
            repository,
            repository_id,
            run_attempt: 1,
            run_id: content_id("governance run"),
            tag: "v1.0.0".to_owned(),
            token: format!("fixture-token-{}", content_id("governance credential")),
            workflow_ref: "Portfoligno/hell-rs/.github/workflows/release.yml@refs/heads/main"
                .to_owned(),
            workflow_sha: content_sha("governance workflow"),
        }
    }
}

fn release_plan(policy: &[u8], identity: &RuntimeIdentity) -> Vec<u8> {
    let (profile, residuals) = declared_governance_values(policy);
    let mut plan = serde_json::json!({
        "actor": "fixture-actor",
        "actorId": content_id("governance actor"),
        "buildInputsSha256": digest("governance build inputs"),
        "candidateBranch": identity.candidate_branch,
        "candidateSha": identity.candidate_sha,
        "changelogSha256": digest("governance changelog"),
        "commitAuthor": "Fixture Author <author@example.invalid>",
        "commitCommitter": "Fixture Committer <committer@example.invalid>",
        "conformancePlanSha256": digest("governance conformance plan"),
        "conformanceStandard": "upstream-release-v1",
        "defaultBranch": "main",
        "expectedPlatforms": ["linux-x86_64", "macos-aarch64", "windows-x86_64"],
        "externalInputsSha256": digest("governance external inputs"),
        "governanceDeclarationSha256": hell_testkit::sha256_bytes(policy).hex(),
        "governanceProfileSha256": domain_digest(b"hell-rs:governance-profile:1", &profile),
        "policySha256": digest("governance release policy"),
        "prerelease": false,
        "releaseBinary": "hell",
        "releaseEvaluationInstant": "2026-08-22T00:00:00Z",
        "releasePackage": "hell-cli",
        "repository": identity.repository,
        "repositoryId": identity.repository_id,
        "residualAssumptionSetSha256": domain_digest(b"hell-rs:residual-assumption-set:1", &residuals),
        "runAttempt": identity.run_attempt,
        "runId": identity.run_id,
        "schemaVersion": 2,
        "sourceDateEpoch": 1_787_356_800_u64,
        "sourceInventorySha256": digest("governance source inventory"),
        "tag": identity.tag,
        "trustedConformanceInputsSha256": digest("governance trusted conformance inputs"),
        "version": "1.0.0",
        "workflowRef": identity.workflow_ref,
        "workflowSha": identity.workflow_sha
    });
    let mut digestless = serde_json::to_vec(&plan).expect("serialize digestless release plan");
    digestless.push(b'\n');
    let plan_digest = hell_testkit::sha256_bytes(&digestless).hex();
    plan.as_object_mut().expect("release plan object").insert(
        "planSha256".to_owned(),
        serde_json::Value::String(plan_digest),
    );
    canonical_json(&plan)
}

fn declared_governance_values(policy: &[u8]) -> (serde_json::Value, serde_json::Value) {
    let text = std::str::from_utf8(policy).expect("policy UTF-8");
    let mut root = BTreeMap::new();
    let mut residuals = BTreeMap::new();
    let mut residual = None;
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        if line == "[[residual-assumption]]" {
            if let Some((id, statement)) = residual.take() {
                residuals.insert(id, statement);
            }
            residual = Some((String::new(), String::new()));
            continue;
        }
        if line.starts_with('[') {
            if let Some((id, statement)) = residual.take() {
                residuals.insert(id, statement);
            }
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        if let Some((id, statement)) = residual.as_mut() {
            match key {
                "id" => unquote(value).clone_into(id),
                "statement" => unquote(value).clone_into(statement),
                _ => {}
            }
        } else {
            root.insert(key.to_owned(), value.to_owned());
        }
    }
    if let Some((id, statement)) = residual {
        residuals.insert(id, statement);
    }
    assert!(residuals.keys().all(|id| !id.is_empty()));
    let profile = serde_json::json!({
        "candidateHeadStability": unquote(&root["candidate-head-stability"]),
        "defaultBranch": unquote(&root["default-branch"]),
        "defaultWorkflowToken": unquote(&root["default-workflow-token"]),
        "fullShaActions": unquote(&root["full-sha-actions"]),
        "immutableReleases": unquote(&root["immutable-releases"]),
        "mergeQueue": root["merge-queue"] == "true",
        "profileId": unquote(&root["profile-id"]),
        "repositoryName": unquote(&root["repository-name"]),
        "repositoryOwner": unquote(&root["repository-owner"]),
        "schemaVersion": 1,
        "tagAbsenceBeforePublication": unquote(&root["tag-absence-before-publication"]),
        "workflowsMayApprovePullRequests": root["workflows-may-approve-pull-requests"] == "true"
    });
    let residuals = serde_json::Value::Array(
        residuals
            .into_iter()
            .map(|(id, statement)| serde_json::json!({"id": id, "statement": statement}))
            .collect(),
    );
    (profile, residuals)
}

fn unquote(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .expect("quoted policy value")
}

struct GovernanceContext<'a> {
    fixture: &'a Fixture,
    identity: &'a RuntimeIdentity,
    policy: &'a Path,
    api_policy: &'a Path,
    plan: &'a Path,
}

struct SnapshotRequest<'a> {
    baseline: Option<&'a Path>,
    predecessor: Option<&'a Path>,
    phase: &'a str,
    output: &'a Path,
    report: &'a Path,
    api_url: &'a str,
    repository_id: Option<u64>,
}

impl<'a> SnapshotRequest<'a> {
    fn new(phase: &'a str, output: &'a Path, report: &'a Path, api_url: &'a str) -> Self {
        Self {
            baseline: None,
            predecessor: None,
            phase,
            output,
            report,
            api_url,
            repository_id: None,
        }
    }

    fn baseline(mut self, baseline: &'a Path) -> Self {
        self.baseline = Some(baseline);
        self
    }

    fn predecessor(mut self, predecessor: &'a Path) -> Self {
        self.predecessor = Some(predecessor);
        self
    }

    fn repository_id(mut self, repository_id: u64) -> Self {
        self.repository_id = Some(repository_id);
        self
    }
}

impl GovernanceContext<'_> {
    fn run(&self, request: &SnapshotRequest<'_>) -> hell_testkit::SupervisedOutput {
        let mut command = self.command(request);
        append_test_activation(&mut command);
        run_governance_command(&mut command)
    }

    fn command(&self, request: &SnapshotRequest<'_>) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_hell-ci"));
        command
            .env_clear()
            .args(["release", "governance-snapshot", "--policy"])
            .arg(self.policy)
            .arg("--api-policy")
            .arg(self.api_policy)
            .arg("--plan")
            .arg(self.plan)
            .args(["--phase", request.phase, "--output"])
            .arg(request.output)
            .arg("--report")
            .arg(request.report)
            .env("GITHUB_API_URL", request.api_url)
            .env("GITHUB_EVENT_NAME", "workflow_dispatch")
            .env("GITHUB_EVENT_PATH", &self.identity.event_path)
            .env("GITHUB_REF_NAME", "main")
            .env("GITHUB_REPOSITORY", &self.identity.repository)
            .env(
                "GITHUB_REPOSITORY_ID",
                request
                    .repository_id
                    .unwrap_or(self.identity.repository_id)
                    .to_string(),
            )
            .env("GITHUB_RUN_ATTEMPT", self.identity.run_attempt.to_string())
            .env("GITHUB_RUN_ID", self.identity.run_id.to_string())
            .env("GITHUB_TOKEN", &self.identity.token)
            .env("GITHUB_WORKFLOW_REF", &self.identity.workflow_ref)
            .env("GITHUB_WORKFLOW_SHA", &self.identity.workflow_sha)
            .env("GITHUB_WORKSPACE", &self.fixture.root);
        if let Some(baseline) = request.baseline {
            command.arg("--baseline").arg(baseline);
        }
        if let Some(predecessor) = request.predecessor {
            command.arg("--predecessor").arg(predecessor);
        }
        command
    }
}

fn run_governance_command(command: &mut Command) -> hell_testkit::SupervisedOutput {
    let result = hell_testkit::run_supervised_command(command, &[], Duration::from_secs(30))
        .expect("run governance snapshot under process-tree supervision");
    assert!(
        !result.timed_out,
        "governance snapshot exceeded its deadline"
    );
    assert!(
        result
            .phase_timings
            .iter()
            .any(|phase| phase.name == "quiescence-complete"),
        "governance snapshot did not reach process-tree quiescence"
    );
    assert_eq!(
        result.phase_timings.last().map(|phase| phase.name),
        Some("stdin-joined"),
        "governance snapshot did not produce the terminal supervised I/O receipt"
    );
    result
}

fn append_test_activation(command: &mut Command) {
    command.args(
        hell_ci::mutation::test_activation_suffix().expect("typed mutation activation suffix"),
    );
}

struct FakeProvider {
    address: std::net::SocketAddr,
    server: Option<thread::JoinHandle<Result<(), String>>>,
    stop: Arc<AtomicBool>,
}

impl FakeProvider {
    fn start(responses: Vec<String>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake provider");
        let address = listener.local_addr().expect("fake provider address");
        listener
            .set_nonblocking(true)
            .expect("set bounded fake provider");
        let stop = Arc::new(AtomicBool::new(false));
        let server_stop = Arc::clone(&stop);
        let server = thread::spawn(move || {
            let deadline = Instant::now()
                .checked_add(Duration::from_secs(15))
                .ok_or_else(|| "fake provider deadline overflowed".to_owned())?;
            for response in responses {
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            if server_stop.load(Ordering::Acquire) {
                                return Ok(());
                            }
                            if Instant::now() >= deadline {
                                return Err("fake provider deadline expired".to_owned());
                            }
                            thread::yield_now();
                        }
                        Err(error) => return Err(format!("fake provider accept failed: {error}")),
                    }
                };
                stream
                    .set_nonblocking(false)
                    .map_err(|error| format!("set provider stream blocking mode: {error}"))?;
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .map_err(|error| format!("set provider read timeout: {error}"))?;
                let mut request = Vec::new();
                let mut buffer = [0_u8; 4096];
                loop {
                    let length = stream
                        .read(&mut buffer)
                        .map_err(|error| format!("read provider request: {error}"))?;
                    if length == 0 {
                        return Err("provider request ended before headers".to_owned());
                    }
                    request.extend_from_slice(&buffer[..length]);
                    if request
                        .windows(b"\r\n\r\n".len())
                        .any(|value| value == b"\r\n\r\n")
                    {
                        break;
                    }
                    if request.len() > 64 * 1024 {
                        return Err("provider request exceeded its bound".to_owned());
                    }
                }
                let request = std::str::from_utf8(&request)
                    .map_err(|_| "provider request is not UTF-8".to_owned())?;
                let first = request.lines().next().unwrap_or_default();
                if !first.starts_with("GET /repos/Portfoligno/hell-rs/")
                    && first != "GET /repos/Portfoligno/hell-rs HTTP/1.1"
                {
                    return Err(format!("unexpected provider request {first:?}"));
                }
                let headers = request.to_ascii_lowercase();
                if !headers.contains("authorization: bearer fixture-token-")
                    || first.contains("fixture-token-")
                {
                    return Err("provider credential transport is invalid".to_owned());
                }
                stream
                    .write_all(response.as_bytes())
                    .map_err(|error| format!("write provider response: {error}"))?;
            }
            Ok(())
        });
        Self {
            address,
            server: Some(server),
            stop,
        }
    }

    fn api_url(&self) -> String {
        format!("http://{}", self.address)
    }

    fn finish(mut self) {
        self.stop.store(true, Ordering::Release);
        self.server
            .take()
            .expect("fake provider thread")
            .join()
            .expect("join fake provider")
            .expect("fake provider result");
    }
}

impl Drop for FakeProvider {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(server) = self.server.take() {
            server
                .join()
                .expect("join fake provider during cleanup")
                .expect("fake provider cleanup result");
        }
    }
}

fn provider_responses(identity: &RuntimeIdentity, ruleset_id: u64) -> Vec<String> {
    let rulesets = serde_json::json!([
        {"enforcement": "active", "id": ruleset_id, "target": "branch"},
        {"enforcement": "active", "id": ruleset_id.wrapping_add(1), "target": "tag"}
    ]);
    [
        (
            "200 OK",
            serde_json::json!({
                "default_branch": "main",
                "full_name": identity.repository,
                "id": identity.repository_id
            }),
        ),
        (
            "200 OK",
            serde_json::json!({
                "can_approve_pull_request_reviews": false,
                "default_workflow_permissions": "read"
            }),
        ),
        (
            "200 OK",
            serde_json::json!({"allowed_actions": "selected", "sha_pinning_required": true}),
        ),
        ("200 OK", rulesets),
        ("200 OK", serde_json::json!({"immutable_releases": true})),
        (
            "200 OK",
            serde_json::json!({
                "object": {"sha": identity.candidate_sha, "type": "commit"},
                "ref": format!("refs/heads/{}", identity.candidate_branch)
            }),
        ),
        ("404 Not Found", serde_json::json!({})),
    ]
    .into_iter()
    .map(|(status, body)| http_response(status, &body))
    .collect()
}

fn http_response(status: &str, body: &serde_json::Value) -> String {
    let body = serde_json::to_string(body).expect("serialize provider response");
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn content_id(label: &str) -> u64 {
    label.bytes().fold(1_u64, |value, byte| {
        value
            .wrapping_mul(1_099_511_628_211)
            .wrapping_add(u64::from(byte))
    }) | 1
}

fn content_sha(label: &str) -> String {
    let shape = "0000000000000000000000000000000000000000";
    digest(label).chars().take(shape.len()).collect()
}

fn digest(label: &str) -> String {
    hell_testkit::sha256_bytes(label.as_bytes()).hex()
}

fn domain_digest(domain: &[u8], value: &serde_json::Value) -> String {
    let mut canonical = serde_json::to_vec(value).expect("serialize domain value");
    canonical.push(b'\n');
    let mut bytes = Vec::with_capacity(domain.len() + 1 + canonical.len());
    bytes.extend_from_slice(domain);
    bytes.push(0);
    bytes.extend_from_slice(&canonical);
    hell_testkit::sha256_bytes(&bytes).hex()
}

fn canonical_json(value: &serde_json::Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(value).expect("serialize canonical JSON");
    bytes.push(b'\n');
    bytes
}

fn read_json(path: &Path) -> serde_json::Value {
    let bytes = fs::read(path).expect("read JSON");
    assert_eq!(bytes.last(), Some(&b'\n'));
    serde_json::from_slice(&bytes).expect("parse JSON")
}
