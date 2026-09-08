use super::fixture::{Outcome, Request, Transcript};
use super::*;

#[test]
fn transcript_is_explicit_and_default_client_keeps_real_http_transport() {
    let client = GitHubClient::from_actions_values(
        Some("https://api.github.com".into()),
        Some("test-token".into()),
    )
    .unwrap();
    assert!(client.fixture.is_none());
}

#[test]
fn transcript_rejects_request_substitution_missing_and_unconsumed_exchanges() {
    for field in [
        "method",
        "url",
        "authorization",
        "accept",
        "api-version",
        "user-agent",
        "content-type",
        "body",
        "missing",
    ] {
        let mut expected = Request::github(
            "POST",
            "/repos/o/r/releases",
            Some("application/json"),
            Some(b"{}"),
        );
        match field {
            "method" => expected.method = "PATCH".to_owned(),
            "url" => expected.url.push_str("?unexpected=1"),
            "body" => expected.body = Some(b"different".to_vec()),
            "missing" => {}
            field => {
                let header = match field {
                    "api-version" => "x-github-api-version",
                    other => other,
                };
                expected
                    .headers
                    .insert(header.to_owned(), "different".to_owned());
            }
        }
        let transcript = Transcript::new(if field == "missing" {
            Vec::new()
        } else {
            vec![(expected, Outcome::response(201, "{}"))]
        });
        let client = GitHubClient::for_test(transcript.clone());
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                || client.create_draft("o/r", "{}")
            ))
            .is_err(),
            "{field}"
        );
        assert_eq!(transcript.observed().len(), 1);
    }
    let transcript = Transcript::new(vec![(
        Request::github("GET", "/repos/o/r/releases", None, None),
        Outcome::response(200, "[]"),
    )]);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| transcript.finish())).is_err()
    );
}

#[test]
fn transcript_responses_preserve_status_decoding_and_byte_bounds() {
    for outcome in [
        Outcome::response(403, "{}"),
        Outcome::response(201, [255]),
        Outcome::response(
            201,
            vec![b'x'; usize::try_from(MAX_RESPONSE_BYTES).unwrap() + 1],
        ),
        Outcome::Disconnected,
    ] {
        let transcript = Transcript::new(vec![(
            Request::github(
                "POST",
                "/repos/o/r/releases",
                Some("application/json"),
                Some(b"{}"),
            ),
            outcome,
        )]);
        let result = GitHubClient::for_test(transcript.clone()).create_draft("o/r", "{}");
        assert!(result.is_err());
        transcript.finish();
    }
}

#[test]
fn path_segments_are_encoded_without_query_fragments() {
    let endpoint = HttpEndpoint::parse("https://api.github.com").unwrap();
    assert_eq!(
        endpoint.url(&["release/a b".to_owned()]),
        "https://api.github.com/repos/release%2Fa%20b"
    );
}

#[test]
fn github_enterprise_api_url_retains_its_https_authority_and_base_path() {
    let endpoint = HttpEndpoint::parse("https://github.example.test/api/v3").unwrap();
    assert_eq!(
        endpoint.url(&["owner".to_owned(), "repo".to_owned()]),
        "https://github.example.test/api/v3/repos/owner/repo"
    );
    assert!(endpoint.trusted_upload_url("https://github.example.test/uploads/1"));
    assert!(!endpoint.trusted_upload_url("https://uploads.example.test/uploads/1"));
}

#[test]
fn actions_environment_values_are_validated_without_process_environment_mutation() {
    let accepted = GitHubClient::from_actions_values(
        Some(OsString::from("https://github.example.test/api/v3")),
        Some(OsString::from("standard-token")),
    );
    assert!(accepted.is_ok());
    for (api, token, expected) in [
        (
            None,
            Some(OsString::from("token")),
            "GITHUB_API_URL is required",
        ),
        (
            Some(OsString::from("not-absolute")),
            Some(OsString::from("token")),
            "GITHUB_API_URL",
        ),
        (
            Some(OsString::from("https://api.github.com")),
            None,
            "GITHUB_TOKEN is required",
        ),
        (
            Some(OsString::from("https://api.github.com")),
            Some(OsString::new()),
            "GITHUB_TOKEN is invalid",
        ),
        (
            Some(OsString::from("https://api.github.com")),
            Some(OsString::from("bad\rvalue")),
            "GITHUB_TOKEN is invalid",
        ),
        (
            Some(OsString::from("https://api.github.com")),
            Some(OsString::from("bad\nvalue")),
            "GITHUB_TOKEN is invalid",
        ),
    ] {
        let error = GitHubClient::from_actions_values(api, token)
            .err()
            .expect("invalid Actions values must fail");
        assert!(error.contains(expected));
        assert!(!error.contains("standard-token"));
        assert!(!error.contains("bad\rvalue"));
        assert!(!error.contains("bad\nvalue"));
    }
}

#[cfg(unix)]
#[test]
fn non_utf8_actions_token_is_rejected_without_echoing_its_bytes() {
    use std::os::unix::ffi::OsStringExt as _;

    let error = GitHubClient::from_actions_values(
        Some(OsString::from("https://api.github.com")),
        Some(OsString::from_vec(vec![0xff, 0xfe])),
    )
    .err()
    .unwrap();
    assert_eq!(error, "GITHUB_TOKEN must be UTF-8");
}

#[test]
fn branch_resolution_accepts_real_api_shape_and_sends_no_token_in_url() {
    let body = concat!(
        "{\"node_id\":\"node\",\"object\":{\"sha\":",
        "\"1111111111111111111111111111111111111111\",",
        "\"type\":\"commit\",\"url\":\"https://api.github.com/object\"},",
        "\"ref\":\"refs/heads/release/1\",\"url\":\"https://api.github.com/ref\"}"
    );
    let expected = Request::github(
        "GET",
        "/repos/owner/repository/git/ref/heads/release%2F1",
        None,
        None,
    );
    let transcript = Transcript::new(vec![(expected.clone(), Outcome::response(200, body))]);
    let client = GitHubClient::for_test(transcript.clone());
    assert_eq!(
        client.branch_head("owner/repository", "release/1").unwrap(),
        "1111111111111111111111111111111111111111"
    );
    transcript.finish();
    assert_eq!(transcript.observed(), vec![expected]);
    assert!(!transcript.observed()[0].url.contains("test-token"));
    assert_eq!(
        transcript.observed()[0].headers["authorization"],
        "Bearer test-token"
    );
}

#[test]
fn release_listing_observes_drafts_and_rejects_duplicates() {
    for (body, expected_error) in [
        (r#"[{"tag_name":"v1","draft":true,"id":7}]"#, false),
        (
            r#"[{"tag_name":"v1","draft":true,"id":7},{"tag_name":"v1","draft":false,"id":8}]"#,
            true,
        ),
    ] {
        let transcript = Transcript::new(vec![(
            Request::github(
                "GET",
                "/repos/owner/repository/releases?per_page=100&page=1",
                None,
                None,
            ),
            Outcome::response(200, body),
        )]);
        let result = GitHubClient::for_test(transcript.clone())
            .release_state_by_tag("owner/repository", "v1");
        assert_eq!(result.is_err(), expected_error);
        if !expected_error {
            assert!(result.unwrap().is_some());
        }
        transcript.finish();
    }
}

#[test]
fn draft_creation_is_observable_through_authenticated_release_listing() {
    let release = r#"{"assets":[],"body":"marker","draft":true,"id":7,"prerelease":false,"tag_name":"v1","target_commitish":"1111111111111111111111111111111111111111","upload_url":"https://uploads.github.com/upload{?name,label}"}"#;
    let transcript = Transcript::new(vec![
        (
            Request::github(
                "POST",
                "/repos/owner/repository/releases",
                Some("application/json"),
                Some(b"{}"),
            ),
            Outcome::response(201, release),
        ),
        (
            Request::github(
                "GET",
                "/repos/owner/repository/releases?per_page=100&page=1",
                None,
                None,
            ),
            Outcome::response(200, format!("[{release}]")),
        ),
    ]);
    let client = GitHubClient::for_test(transcript.clone());
    let created = client.create_draft("owner/repository", "{}").unwrap();
    assert_eq!(
        json_member(created.object().unwrap(), "id")
            .unwrap()
            .number()
            .unwrap(),
        7
    );
    let observed = client
        .release_state_by_tag("owner/repository", "v1")
        .unwrap()
        .unwrap();
    assert!(
        json_member(observed.object().unwrap(), "draft")
            .unwrap()
            .boolean()
            .unwrap()
    );
    transcript.finish();
}
