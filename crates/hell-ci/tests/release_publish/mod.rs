use super::*;
use crate::release::github::fixture::{Outcome, Request, Transcript};
use std::collections::BTreeSet;
use std::time::{SystemTime, UNIX_EPOCH};

fn plan() -> ReleasePlan {
    ReleasePlan {
        resolution: super::super::schema::Resolution {
            repository: "o/r".into(),
            repository_id: 1,
            default_branch: "main".into(),
            candidate_branch: "release".into(),
            candidate_sha: "a".repeat(40),
            actor: "a".into(),
            actor_id: 2,
            run_id: 3,
            run_attempt: 1,
            workflow_ref: "w".into(),
            workflow_sha: "b".repeat(40),
        },
        version: "1.0.0".into(),
        tag: "v1.0.0".into(),
        prerelease: false,
        source_date_epoch: 1,
        release_evaluation_instant: "2026-08-13T00:00:00Z".into(),
        source_inventory_sha256: "c".repeat(64),
        build_inputs_sha256: "d".repeat(64),
        policy_sha256: "e".repeat(64),
        governance_declaration_sha256: "4".repeat(64),
        governance_profile_sha256: "5".repeat(64),
        residual_assumption_set_sha256: "6".repeat(64),
        external_inputs_sha256: "7".repeat(64),
        trusted_conformance_inputs_sha256: "2".repeat(64),
        conformance_plan_sha256: "3".repeat(64),
        conformance_standard: crate::conformance::RELEASE_STANDARD.into(),
        changelog_sha256: "1".repeat(64),
        commit_author: "Author <author@example.com>".into(),
        commit_committer: "Committer <committer@example.com>".into(),
        plan_sha256: "f".repeat(64),
    }
}

#[derive(Clone, Copy)]
enum Scenario {
    Create,
    ResumePartial,
    Stale,
    Human,
    AmbiguousCreate,
    AmbiguousDelete,
    AmbiguousUpload,
    AmbiguousPublish,
    Immutable,
    ImmutableAltered,
    MovedBranch,
    ConcurrentTag,
    PublishedConflict,
}

#[derive(Clone)]
struct FakeRelease {
    draft: bool,
    immutable: bool,
    body: String,
    target: String,
    assets: BTreeMap<String, (u64, u64, String)>,
}

fn publication_fixture(plan: &ReleasePlan) -> (PathBuf, BTreeMap<String, (u64, String)>) {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("hell-publisher-fixture-{nonce}"));
    std::fs::create_dir(&root).unwrap();
    let names = [
        "SUBJECTS.sha256".to_owned(),
        "conformance-acceptance.json".to_owned(),
        "conformance-evidence.tar.gz".to_owned(),
        "conformance-plan.json".to_owned(),
        "conformance-report.html".to_owned(),
        "conformance-report.json".to_owned(),
        "dependency-policy.json".to_owned(),
        "github-provenance.sigstore.json".to_owned(),
        "github-release-gate.sigstore.json".to_owned(),
        "mutation-report.json".to_owned(),
        "release-gate.json".to_owned(),
        "release-manifest.json".to_owned(),
        "release-notes.md".to_owned(),
        format!("hell-v{}-linux-x86_64.tar.gz", plan.version),
        format!("hell-v{}-macos-aarch64.tar.gz", plan.version),
        format!("hell-v{}-windows-x86_64.tar.gz", plan.version),
    ];
    for name in names {
        let bytes = if name == "release-notes.md" {
            b"notes\n".to_vec()
        } else {
            format!("fixture:{name}\n").into_bytes()
        };
        std::fs::write(root.join(name), bytes).unwrap();
    }
    let assets = publication_assets(&root, plan).unwrap();
    (root, assets)
}

fn fake_release_json(plan: &ReleasePlan, release: &FakeRelease, upload_url: &str) -> String {
    let assets = release
        .assets
        .iter()
        .map(|(name, (id, size, digest))| {
            object([
                ("digest", string(&format!("sha256:{digest}"))),
                ("id", number(*id)),
                ("name", string(name)),
                ("size", number(*size)),
            ])
        })
        .collect();
    String::from_utf8(
        canonical_json_bytes(&object([
            ("assets", JsonValue::Array(assets)),
            ("body", string(&release.body)),
            ("draft", JsonValue::Bool(release.draft)),
            ("id", number(7)),
            ("immutable", JsonValue::Bool(release.immutable)),
            ("name", string(&plan.tag)),
            ("prerelease", JsonValue::Bool(plan.prerelease)),
            ("tag_name", string(&plan.tag)),
            ("target_commitish", string(&release.target)),
            ("upload_url", string(upload_url)),
        ]))
        .unwrap(),
    )
    .unwrap()
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
enum AmbiguousOperation {
    Create,
    Delete,
    Upload,
    Publish,
}

struct FakePublisherServer {
    scenario: Scenario,
    plan: ReleasePlan,
    local: BTreeMap<String, (u64, String)>,
    upload_url: String,
    marker: String,
    published_body: String,
    release: Option<FakeRelease>,
    next_asset: u64,
    ambiguous: BTreeSet<AmbiguousOperation>,
}

impl FakePublisherServer {
    fn response(&mut self, request: &Request) -> Outcome {
        let path = request.path();
        match (request.method.as_str(), path) {
            ("GET", "/repos/o/r/immutable-releases") => {
                Outcome::response(200, r#"{"enabled":true}"#)
            }
            ("GET", "/repos/o/r/git/ref/heads/release") => {
                let sha = if matches!(self.scenario, Scenario::MovedBranch) {
                    "9".repeat(40)
                } else {
                    self.plan.resolution.candidate_sha.clone()
                };
                Outcome::response(
                    200,
                    format!(
                        r#"{{"node_id":"n","object":{{"sha":"{sha}","type":"commit","url":"u"}},"ref":"refs/heads/release","url":"u"}}"#
                    ),
                )
            }
            ("GET", "/repos/o/r/git/ref/tags/v1.0.0") => {
                if matches!(self.scenario, Scenario::ConcurrentTag)
                    || self.release.as_ref().is_some_and(|release| !release.draft)
                {
                    Outcome::response(
                        200,
                        format!(
                            r#"{{"node_id":"n","object":{{"sha":"{}","type":"commit","url":"u"}},"ref":"refs/tags/{}","url":"u"}}"#,
                            self.plan.resolution.candidate_sha, self.plan.tag
                        ),
                    )
                } else {
                    Outcome::response(404, "{}")
                }
            }
            ("GET", "/repos/o/r/releases?per_page=100&page=1") => Outcome::response(
                200,
                self.release.as_ref().map_or_else(
                    || "[]".to_owned(),
                    |release| {
                        format!(
                            "[{}]",
                            fake_release_json(&self.plan, release, &self.upload_url)
                        )
                    },
                ),
            ),
            ("GET", "/repos/o/r/releases/tags/v1.0.0") => self
                .release
                .as_ref()
                .filter(|release| !release.draft)
                .map_or_else(
                    || Outcome::response(404, "{}"),
                    |release| {
                        Outcome::response(
                            200,
                            fake_release_json(&self.plan, release, &self.upload_url),
                        )
                    },
                ),
            ("POST", "/repos/o/r/releases") => {
                self.release = Some(FakeRelease {
                    draft: true,
                    immutable: false,
                    body: self.marker.clone(),
                    target: self.plan.resolution.candidate_sha.clone(),
                    assets: BTreeMap::new(),
                });
                if self.ambiguous.remove(&AmbiguousOperation::Create) {
                    Outcome::Disconnected
                } else {
                    Outcome::response(
                        201,
                        fake_release_json(
                            &self.plan,
                            self.release.as_ref().unwrap(),
                            &self.upload_url,
                        ),
                    )
                }
            }
            ("DELETE", "/repos/o/r/releases/assets/40") => {
                self.release
                    .as_mut()
                    .unwrap()
                    .assets
                    .retain(|_, asset| asset.0 != 40);
                Outcome::response(204, "")
            }
            ("DELETE", "/repos/o/r/releases/7") => {
                self.release = None;
                if self.ambiguous.remove(&AmbiguousOperation::Delete) {
                    Outcome::Disconnected
                } else {
                    Outcome::response(204, "")
                }
            }
            ("POST", path) if path.starts_with("/upload?name=") => {
                let name = path.strip_prefix("/upload?name=").unwrap().to_owned();
                let (size, digest) = self.local.get(&name).unwrap();
                let bytes = request.body.as_ref().expect("upload bytes");
                assert_eq!(u64::try_from(bytes.len()).unwrap(), *size);
                assert_eq!(hell_testkit::sha256_bytes(bytes).hex(), *digest);
                self.release
                    .as_mut()
                    .unwrap()
                    .assets
                    .insert(name.clone(), (self.next_asset, *size, digest.clone()));
                let response = Outcome::response(
                    201,
                    format!(
                        r#"{{"digest":"sha256:{digest}","id":{},"name":"{name}","size":{size}}}"#,
                        self.next_asset
                    ),
                );
                self.next_asset += 1;
                if self.ambiguous.remove(&AmbiguousOperation::Upload) {
                    Outcome::Disconnected
                } else {
                    response
                }
            }
            ("PATCH", "/repos/o/r/releases/7") => {
                let release = self.release.as_mut().unwrap();
                release.draft = false;
                release.immutable = true;
                release.body.clone_from(&self.published_body);
                if self.ambiguous.remove(&AmbiguousOperation::Publish) {
                    Outcome::Disconnected
                } else {
                    Outcome::response(
                        200,
                        fake_release_json(&self.plan, release, &self.upload_url),
                    )
                }
            }
            _ => panic!("unexpected publisher fixture request: {request:?}"),
        }
    }
}

/// Independently specifies every call and body, including each recovery read.
fn publisher_requests(
    scenario: Scenario,
    input: &Path,
    plan: &ReleasePlan,
    local: &BTreeMap<String, (u64, String)>,
) -> Vec<Request> {
    let get = |path: &str| Request::github("GET", path, None, None);
    let branch = "/repos/o/r/git/ref/heads/release";
    let tag = "/repos/o/r/git/ref/tags/v1.0.0";
    let listing = "/repos/o/r/releases?per_page=100&page=1";
    let published = "/repos/o/r/releases/tags/v1.0.0";
    let mut requests = vec![get("/repos/o/r/immutable-releases"), get(branch)];
    if matches!(scenario, Scenario::MovedBranch) {
        return requests;
    }
    requests.push(get(listing));
    if matches!(
        scenario,
        Scenario::Human
            | Scenario::Stale
            | Scenario::AmbiguousDelete
            | Scenario::ResumePartial
            | Scenario::Immutable
            | Scenario::ImmutableAltered
            | Scenario::PublishedConflict
    ) {
        requests.push(get(tag));
    }
    if matches!(
        scenario,
        Scenario::Human
            | Scenario::Immutable
            | Scenario::ImmutableAltered
            | Scenario::PublishedConflict
    ) {
        return requests;
    }
    if matches!(scenario, Scenario::Stale | Scenario::AmbiguousDelete) {
        requests.push(Request::github(
            "DELETE",
            "/repos/o/r/releases/7",
            None,
            None,
        ));
        if matches!(scenario, Scenario::AmbiguousDelete) {
            requests.push(get(listing));
        }
    }
    let marker = format!("<!-- hell-rs-release-plan-sha256: {} -->", plan.plan_sha256);
    if !matches!(scenario, Scenario::ResumePartial) {
        requests.extend([get(branch), get(tag)]);
        if matches!(scenario, Scenario::ConcurrentTag) {
            return requests;
        }
        let draft = draft_request(plan, &marker).unwrap();
        requests.push(Request::github(
            "POST",
            "/repos/o/r/releases",
            Some("application/json"),
            Some(draft.as_bytes()),
        ));
        if matches!(scenario, Scenario::AmbiguousCreate) {
            requests.push(get(listing));
        }
    } else {
        requests.push(Request::github(
            "DELETE",
            "/repos/o/r/releases/assets/40",
            None,
            None,
        ));
    }
    for (index, name) in local.keys().enumerate() {
        let bytes = std::fs::read(input.join(name)).unwrap();
        requests.push(Request::github(
            "POST",
            &format!("https://uploads.github.com/upload?name={name}"),
            Some("application/octet-stream"),
            Some(&bytes),
        ));
        if index == 0 && matches!(scenario, Scenario::AmbiguousUpload) {
            requests.push(get(listing));
        }
    }
    requests.extend([get(listing), get(branch), get(tag)]);
    let body = publish_request(plan, &format!("notes\n\n{marker}")).unwrap();
    requests.push(Request::github(
        "PATCH",
        "/repos/o/r/releases/7",
        Some("application/json"),
        Some(body.as_bytes()),
    ));
    if matches!(scenario, Scenario::AmbiguousPublish) {
        requests.push(get(published));
    }
    requests.extend([get(published), get(tag)]);
    requests
}

fn run_fake_publisher(scenario: Scenario) -> (Result<String, String>, Vec<String>) {
    let plan = plan();
    let (input, local) = publication_fixture(&plan);
    let marker = format!("<!-- hell-rs-release-plan-sha256: {} -->", plan.plan_sha256);
    let published_body = format!("notes\n\n{marker}");
    let upload_url = "https://uploads.github.com/upload{?name,label}".to_owned();
    let release = match scenario {
        Scenario::Human => Some(FakeRelease {
            draft: true,
            immutable: false,
            body: "human draft".to_owned(),
            target: plan.resolution.candidate_sha.clone(),
            assets: BTreeMap::new(),
        }),
        Scenario::Stale | Scenario::AmbiguousDelete => Some(FakeRelease {
            draft: true,
            immutable: false,
            body: format!("<!-- hell-rs-release-plan-sha256: {} -->", "1".repeat(64)),
            target: "2".repeat(40),
            assets: BTreeMap::new(),
        }),
        Scenario::ResumePartial => {
            let (name, (size, _)) = local.iter().next().unwrap();
            Some(FakeRelease {
                draft: true,
                immutable: false,
                body: marker.clone(),
                target: plan.resolution.candidate_sha.clone(),
                assets: BTreeMap::from([(name.clone(), (40, *size, "3".repeat(64)))]),
            })
        }
        Scenario::Immutable | Scenario::ImmutableAltered => Some(FakeRelease {
            draft: false,
            immutable: true,
            body: if matches!(scenario, Scenario::ImmutableAltered) {
                format!("altered notes\n\n{marker}")
            } else {
                published_body.clone()
            },
            target: plan.resolution.candidate_sha.clone(),
            assets: local
                .iter()
                .enumerate()
                .map(|(index, (name, (size, digest)))| {
                    (name.clone(), (index as u64 + 10, *size, digest.clone()))
                })
                .collect(),
        }),
        Scenario::PublishedConflict => Some(FakeRelease {
            draft: false,
            immutable: true,
            body: "human published release".to_owned(),
            target: plan.resolution.candidate_sha.clone(),
            assets: BTreeMap::new(),
        }),
        _ => None,
    };
    let mut fake_server = FakePublisherServer {
        scenario,
        plan: plan.clone(),
        local: local.clone(),
        upload_url,
        marker,
        published_body,
        release,
        next_asset: 100,
        ambiguous: match scenario {
            Scenario::AmbiguousCreate => BTreeSet::from([AmbiguousOperation::Create]),
            Scenario::AmbiguousDelete => BTreeSet::from([AmbiguousOperation::Delete]),
            Scenario::AmbiguousUpload => BTreeSet::from([AmbiguousOperation::Upload]),
            Scenario::AmbiguousPublish => BTreeSet::from([AmbiguousOperation::Publish]),
            _ => BTreeSet::new(),
        },
    };
    let exchanges = publisher_requests(scenario, &input, &plan, &local)
        .into_iter()
        .map(|request| {
            let response = fake_server.response(&request);
            (request, response)
        })
        .collect();
    assert!(
        fake_server.ambiguous.is_empty(),
        "every configured ambiguous mutation must occur"
    );
    let transcript = Transcript::new(exchanges);
    let client = GitHubClient::for_test(transcript.clone());
    let report = input.join("publication.json");
    let result = publish_with_client(&plan, &input, &report, &client);
    transcript.finish();
    let requests = transcript.observed().iter().map(Request::display).collect();
    std::fs::remove_dir_all(input).unwrap();
    (result, requests)
}

#[test]
fn publisher_state_machine_transitions_use_observed_remote_state() {
    for scenario in [
        Scenario::Create,
        Scenario::ResumePartial,
        Scenario::Stale,
        Scenario::AmbiguousCreate,
        Scenario::AmbiguousDelete,
        Scenario::AmbiguousUpload,
        Scenario::AmbiguousPublish,
        Scenario::Immutable,
    ] {
        let (result, requests) = run_fake_publisher(scenario);
        assert!(result.is_ok(), "{result:?}\n{requests:#?}");
        assert!(requests.iter().any(|request| request.starts_with("GET ")));
        if matches!(scenario, Scenario::Stale | Scenario::AmbiguousDelete) {
            assert!(
                requests
                    .iter()
                    .any(|request| request.starts_with("DELETE "))
            );
        }
        if matches!(scenario, Scenario::ResumePartial) {
            assert!(
                requests
                    .iter()
                    .any(|request| request.contains("/releases/assets/40"))
            );
        }
        if matches!(scenario, Scenario::Immutable) {
            assert!(!requests.iter().any(|request| {
                request.starts_with("POST ")
                    || request.starts_with("PATCH ")
                    || request.starts_with("DELETE ")
            }));
        } else {
            assert!(requests.iter().any(|request| request.starts_with("PATCH ")));
            assert!(requests.iter().any(|request| {
                request.starts_with("GET ") && request.contains("/releases/tags/")
            }));
            let expected_draft = draft_request(
                &plan(),
                &format!("<!-- hell-rs-release-plan-sha256: {} -->", "f".repeat(64)),
            )
            .unwrap();
            if !matches!(scenario, Scenario::ResumePartial | Scenario::Immutable) {
                assert!(requests.iter().any(|request| {
                    request.starts_with("POST /repos/o/r/releases ")
                        && request.ends_with(&expected_draft)
                }));
            }
            let expected_publish = publish_request(
                &plan(),
                &format!(
                    "notes\n\n<!-- hell-rs-release-plan-sha256: {} -->",
                    "f".repeat(64)
                ),
            )
            .unwrap();
            assert!(requests.iter().any(|request| {
                request.starts_with("PATCH /repos/o/r/releases/7 ")
                    && request.ends_with(&expected_publish)
            }));
        }
    }
    let (human, requests) = run_fake_publisher(Scenario::Human);
    assert!(human.is_err());
    assert!(!requests.iter().any(|request| {
        request.starts_with("POST ")
            || request.starts_with("PATCH ")
            || request.starts_with("DELETE ")
    }));
    for scenario in [
        Scenario::MovedBranch,
        Scenario::ConcurrentTag,
        Scenario::PublishedConflict,
    ] {
        let (result, requests) = run_fake_publisher(scenario);
        assert!(result.is_err());
        assert!(!requests.iter().any(|request| {
            request.starts_with("POST ")
                || request.starts_with("PATCH ")
                || request.starts_with("DELETE ")
        }));
    }
    let (result, requests) = run_fake_publisher(Scenario::ImmutableAltered);
    assert!(result.is_err());
    assert!(!requests.iter().any(|request| {
        request.starts_with("POST ")
            || request.starts_with("PATCH ")
            || request.starts_with("DELETE ")
    }));
}

#[test]
fn draft_and_publish_requests_bind_exact_plan() {
    let plan = plan();
    assert!(
        draft_request(&plan, "marker")
            .unwrap()
            .contains("\"draft\":true")
    );
    assert!(
        publish_request(&plan, "marker")
            .unwrap()
            .contains("\"draft\":false")
    );
}

#[test]
fn release_classifier_rejects_conflicting_machine_markers() {
    let plan = plan();
    let marker = format!("<!-- hell-rs-release-plan-sha256: {} -->", plan.plan_sha256);
    let value = object([
        ("assets", JsonValue::Array(Vec::new())),
        ("body", string(&format!("{marker}\n{marker}"))),
        ("draft", JsonValue::Bool(true)),
        ("id", number(1)),
        ("prerelease", JsonValue::Bool(false)),
        ("tag_name", string(&plan.tag)),
        ("target_commitish", string(&plan.resolution.candidate_sha)),
        ("upload_url", string("https://uploads.github.com/upload")),
    ]);
    assert_eq!(
        classify(&value, &plan, &marker, &BTreeMap::new()).unwrap(),
        ExistingReleaseState::HumanConflict
    );
    let unicode_digest = format!(
        "<!-- hell-rs-release-plan-sha256: {} -->",
        "ａ".repeat(plan.plan_sha256.chars().count())
    );
    let value = object([
        ("assets", JsonValue::Array(Vec::new())),
        ("body", string(&unicode_digest)),
        ("draft", JsonValue::Bool(true)),
        ("id", number(1)),
        ("prerelease", JsonValue::Bool(false)),
        ("tag_name", string(&plan.tag)),
        ("target_commitish", string(&plan.resolution.candidate_sha)),
        ("upload_url", string("https://uploads.github.com/upload")),
    ]);
    assert_eq!(
        classify(&value, &plan, &marker, &BTreeMap::new()).unwrap(),
        ExistingReleaseState::HumanConflict
    );
    let uppercase = marker.to_ascii_uppercase();
    let value = object([
        ("assets", JsonValue::Array(Vec::new())),
        ("body", string(&uppercase)),
        ("draft", JsonValue::Bool(true)),
        ("id", number(1)),
        ("prerelease", JsonValue::Bool(false)),
        ("tag_name", string(&plan.tag)),
        ("target_commitish", string(&plan.resolution.candidate_sha)),
        ("upload_url", string("https://uploads.github.com/upload")),
    ]);
    assert_eq!(
        classify(&value, &plan, &marker, &BTreeMap::new()).unwrap(),
        ExistingReleaseState::HumanConflict
    );
}

#[test]
fn published_metadata_is_exact_not_marker_only() {
    let plan = plan();
    let release = object([
        ("body", string("altered notes")),
        ("name", string("altered name")),
        ("tag_name", string(&plan.tag)),
    ]);
    assert!(require_exact_published_metadata(&release, &plan, "expected notes").is_err());
}

#[test]
fn rejected_bundle_surface_mutations_make_zero_api_calls() {
    let plan = plan();
    let (input, _) = publication_fixture(&plan);
    let transcript = Transcript::new(Vec::new());
    let client = GitHubClient::for_test(transcript.clone());
    let report = input.join("publication.json");
    let mutations = [
        "conformance-plan-bytes",
        "conformance-evidence-archive",
        "evidence-record",
        "observation-bytes",
        "report-cell",
        "report-count",
        "acceptance-decision",
        "release-manifest-conformance",
        "release-gate-subjects-digest",
        "subjects-exact-set",
        "platform-report-identity",
        "package-archive",
        "candidate-executable-identity",
        "trusted-inputs",
        "attestation-predicate-v1",
        "accepted-report-recomputation",
    ];
    for mutation in mutations {
        let result = publish_after_verification(
            &plan,
            &input,
            &report,
            &client,
            Err(format!("rejected mutated surface {mutation}")),
        );
        assert!(result.is_err(), "mutation {mutation} reached publication");
        assert!(
            transcript.observed().is_empty(),
            "mutation {mutation} made a GitHub API call"
        );
    }
    std::fs::remove_dir_all(input).unwrap();
}

#[test]
fn release_classifier_distinguishes_human_and_exact_immutable_states() {
    let plan = plan();
    let marker = format!("<!-- hell-rs-release-plan-sha256: {} -->", plan.plan_sha256);
    let common = |body: &str, draft: bool, immutable: bool| {
        object([
            ("assets", JsonValue::Array(Vec::new())),
            ("body", string(body)),
            ("draft", JsonValue::Bool(draft)),
            ("id", number(1)),
            ("immutable", JsonValue::Bool(immutable)),
            ("prerelease", JsonValue::Bool(false)),
            ("tag_name", string(&plan.tag)),
            ("target_commitish", string(&plan.resolution.candidate_sha)),
            ("upload_url", string("https://uploads.github.com/upload")),
        ])
    };
    assert_eq!(
        classify(
            &common("human notes", true, false),
            &plan,
            &marker,
            &BTreeMap::new()
        )
        .unwrap(),
        ExistingReleaseState::HumanConflict
    );
    assert_eq!(
        classify(
            &common(&marker, false, true),
            &plan,
            &marker,
            &BTreeMap::new()
        )
        .unwrap(),
        ExistingReleaseState::MatchingImmutable
    );
}

#[test]
fn attestation_commands_bind_distinct_predicate_and_workflow_identity() {
    let command = attestation_command(
        std::path::Path::new("bundle"),
        "release-gate.json",
        "github-release-gate.sigstore.json",
        "o/r",
        "https://example.test/release-gate/v2",
        "https://github.com/o/r/.github/workflows/release.yml@refs/heads/main",
        &"b".repeat(40),
    );
    let arguments = command.display_arguments();
    assert!(arguments.windows(2).any(|pair| pair == ["--repo", "o/r"]));
    assert!(
        arguments
            .windows(2)
            .any(|pair| { pair == ["--predicate-type", "https://example.test/release-gate/v2"] })
    );
    assert!(arguments.windows(2).any(|pair| {
        pair == [
            "--cert-identity",
            "https://github.com/o/r/.github/workflows/release.yml@refs/heads/main",
        ]
    }));
    assert!(arguments.windows(2).any(|pair| {
        pair == [
            "--signer-digest",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ]
    }));
}
