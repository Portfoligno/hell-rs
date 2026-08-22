use std::fs;
use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::path::PathBuf;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use super::*;
use crate::json::parse_json;
use crate::release::schema::Resolution;

const CANDIDATE_SHA: &str = "434c9104de69600ce4a85601dc2ac48a45aa8f8f";
const WORKFLOW_SHA: &str = "550e4c3e094a75a4c362bd192ae5805837ac9741";
const MOVED_CANDIDATE_SHA: &str = "33a9f0186b0cde1999e25afd6eb76e2603f95faa";
const TAG_SHA: &str = "5e2e8f9e6f9cab30a0b2da50fad349896b4a5463";
const TAG_COMMIT_SHA: &str = "a35bfdfc1d08c9f394762743fc43af8402022b5c";

fn content_digest(label: &str) -> String {
    hell_testkit::sha256_bytes(label.as_bytes()).hex()
}

fn content_id(label: &str) -> u64 {
    let digest = content_digest(label);
    let digits = std::mem::size_of::<u64>() * 2;
    u64::from_str_radix(
        digest
            .get(..digits)
            .expect("SHA-256 hex contains a u64 prefix"),
        16,
    )
    .expect("SHA-256 prefix is hexadecimal")
}

fn plan() -> ReleasePlan {
    ReleasePlan {
        resolution: Resolution {
            repository: "o/r".into(),
            repository_id: content_id("remote-state repository identity"),
            default_branch: "main".into(),
            candidate_branch: "release/1.0.0".into(),
            candidate_sha: CANDIDATE_SHA.into(),
            actor: "actor".into(),
            actor_id: content_id("remote-state actor identity"),
            run_id: content_id("remote-state run identity"),
            run_attempt: 1,
            workflow_ref: "o/r/.github/workflows/release.yml@refs/heads/main".into(),
            workflow_sha: WORKFLOW_SHA.into(),
        },
        version: "1.0.0".into(),
        tag: "v1.0.0".into(),
        prerelease: false,
        source_date_epoch: 1_786_579_200,
        release_evaluation_instant: "2026-08-13T00:00:00Z".into(),
        source_inventory_sha256: content_digest("remote-state source inventory"),
        build_inputs_sha256: content_digest("remote-state build inputs"),
        policy_sha256: content_digest("remote-state release policy"),
        trusted_conformance_inputs_sha256: content_digest("remote-state conformance inputs"),
        conformance_plan_sha256: content_digest("remote-state conformance plan"),
        conformance_standard: crate::conformance::RELEASE_STANDARD.into(),
        changelog_sha256: content_digest("remote-state changelog"),
        governance_declaration_sha256: content_digest("remote-state governance declaration"),
        governance_profile_sha256: content_digest("remote-state governance profile"),
        residual_assumption_set_sha256: content_digest("remote-state residual assumptions"),
        external_inputs_sha256: content_digest("remote-state external inputs"),
        commit_author: "Author <author@example.com>".into(),
        commit_committer: "Committer <committer@example.com>".into(),
        plan_sha256: content_digest("remote-state release plan"),
    }
}

fn report_path(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("hell-remote-state-{label}-{nonce}.json"))
}

fn response(status: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn branch_body(sha: &str) -> String {
    format!(
        "{{\"node_id\":\"n\",\"object\":{{\"sha\":\"{sha}\",\"type\":\"commit\",\"url\":\"u\"}},\"ref\":\"refs/heads/release/1.0.0\",\"url\":\"u\"}}"
    )
}

fn tag_body(sha: &str, kind: &str) -> String {
    format!(
        "{{\"node_id\":\"n\",\"object\":{{\"sha\":\"{sha}\",\"type\":\"{kind}\",\"url\":\"u\"}},\"ref\":\"refs/tags/v1.0.0\",\"url\":\"u\"}}"
    )
}

fn annotated_tag_body(tag_sha: &str, commit_sha: &str) -> String {
    format!(
        concat!(
            "{{\"message\":\"release\",\"node_id\":\"n\",",
            "\"object\":{{\"sha\":\"{}\",\"type\":\"commit\",\"url\":\"u\"}},",
            "\"sha\":\"{}\",\"tag\":\"v1.0.0\",\"tagger\":null,",
            "\"url\":\"u\",\"verification\":null}}"
        ),
        commit_sha, tag_sha,
    )
}

fn client_with_responses(responses: Vec<String>) -> (GitHubClient, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = GitHubClient::for_test(listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        for response in responses {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 4096];
            let _ = stream.read(&mut request);
            stream.write_all(response.as_bytes()).unwrap();
        }
    });
    (client, server)
}

#[test]
fn remote_state_reports_stable_moved_tagged_and_failed_states() {
    for scenario in [
        "stable",
        "moved",
        "tagged",
        "annotated",
        "malformed",
        "forbidden",
    ] {
        let candidate = if scenario == "moved" {
            MOVED_CANDIDATE_SHA
        } else {
            CANDIDATE_SHA
        };
        let branch = match scenario {
            "malformed" => response("200 OK", "{}"),
            "forbidden" => response("403 Forbidden", "{}"),
            _ => response("200 OK", &branch_body(candidate)),
        };
        let mut responses = vec![branch];
        match scenario {
            "tagged" => responses.push(response("200 OK", &tag_body(TAG_COMMIT_SHA, "commit"))),
            "annotated" => {
                let tag_sha = TAG_SHA;
                responses.push(response("200 OK", &tag_body(tag_sha, "tag")));
                responses.push(response(
                    "200 OK",
                    &annotated_tag_body(tag_sha, TAG_COMMIT_SHA),
                ));
            }
            "malformed" | "forbidden" => {}
            _ => responses.push(response("404 Not Found", "{}")),
        }
        let (client, server) = client_with_responses(responses);
        let report = report_path(scenario);
        let result = check_with_client(&plan(), &report, &client);
        server.join().unwrap();
        let value = parse_json(&fs::read_to_string(&report).unwrap()).unwrap();
        let fields = value.object().unwrap();
        let observed = crate::json::json_member(fields, "state")
            .unwrap()
            .string()
            .unwrap();
        let expected = match scenario {
            "stable" => "stable-and-tag-absent",
            "moved" => "candidate-branch-moved",
            "tagged" | "annotated" => "tag-already-exists",
            "malformed" | "forbidden" => "remote-query-failed",
            _ => unreachable!(),
        };
        assert_eq!(observed, expected);
        assert_eq!(result.is_ok(), scenario == "stable");
        fs::remove_file(report).unwrap();
    }
}

#[test]
fn remote_state_report_is_create_new_and_does_not_contain_authorization() {
    let report = report_path("existing");
    fs::write(&report, b"sentinel\n").unwrap();
    let (client, server) = client_with_responses(vec![
        response("200 OK", &branch_body(CANDIDATE_SHA)),
        response("404 Not Found", "{}"),
    ]);
    let result = check_with_client(&plan(), &report, &client);
    server.join().unwrap();
    assert!(result.is_err());
    assert_eq!(fs::read(&report).unwrap(), b"sentinel\n");
    assert!(!result.unwrap_err().contains("test-token"));
    fs::remove_file(report).unwrap();
}
