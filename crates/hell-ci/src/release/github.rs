use std::ffi::OsString;
use std::path::Path;
use std::time::Duration;

use crate::json::{JsonValue, json_member, parse_json, require_exact_json_keys};

const MAX_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;

pub(crate) struct GitHubClient {
    api: HttpEndpoint,
    token: String,
    agent: ureq::Agent,
}

struct HttpEndpoint {
    scheme: String,
    authority: String,
    base_path: Vec<String>,
}

impl GitHubClient {
    #[cfg(test)]
    pub(crate) fn for_test(address: std::net::SocketAddr) -> Self {
        Self {
            api: HttpEndpoint {
                scheme: "http".to_owned(),
                authority: address.to_string(),
                base_path: Vec::new(),
            },
            token: "test-token".to_owned(),
            agent: ureq::Agent::config_builder()
                .http_status_as_error(false)
                .build()
                .into(),
        }
    }
    pub(crate) fn from_actions_environment() -> Result<Self, String> {
        Self::from_actions_values(
            std::env::var_os("GITHUB_API_URL"),
            std::env::var_os("GITHUB_TOKEN"),
        )
    }

    fn from_actions_values(api: Option<OsString>, token: Option<OsString>) -> Result<Self, String> {
        let api = required_environment_value(api, "GITHUB_API_URL")?;
        let token = required_environment_value(token, "GITHUB_TOKEN")?;
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(30)))
            .http_status_as_error(false)
            .build();
        Ok(Self {
            api: HttpEndpoint::parse(&api)?,
            token,
            agent: config.into(),
        })
    }

    pub(crate) fn branch_head(&self, repository: &str, branch: &str) -> Result<String, String> {
        let mut segments = repository.split('/').map(str::to_owned).collect::<Vec<_>>();
        if segments.len() != 2 || segments.iter().any(|segment| segment.is_empty()) {
            return Err("repository full name is invalid".to_owned());
        }
        segments.extend([
            "git".to_owned(),
            "ref".to_owned(),
            "heads".to_owned(),
            branch.to_owned(),
        ]);
        let response = self.get(&segments)?;
        let document = parse_json(&response)?;
        let object = document.object()?;
        require_exact_json_keys(object, &["node_id", "object", "ref", "url"])?;
        if json_member(object, "ref")?.string()? != format!("refs/heads/{branch}") {
            return Err("GitHub returned a different branch ref".to_owned());
        }
        let object = json_member(object, "object")?.object()?;
        require_exact_json_keys(object, &["sha", "type", "url"])?;
        if json_member(object, "type")?.string()? != "commit" {
            return Err("candidate branch does not resolve to a commit".to_owned());
        }
        Ok(json_member(object, "sha")?.string()?.to_owned())
    }

    pub(crate) fn workflow_run_created_at(
        &self,
        repository: &str,
        repository_id: u64,
        run_id: u64,
        run_attempt: u64,
        workflow_sha: &str,
    ) -> Result<String, String> {
        let run_id = run_id.to_string();
        let segments = repository_segments(repository, ["actions", "runs", run_id.as_str()])?;
        let response = self.get(&segments)?;
        let value = parse_json(&response)?;
        let fields = value.object()?;
        let run_repository = json_member(fields, "repository")?.object()?;
        if json_member(fields, "id")?.number()?
            != run_id.parse::<u64>().map_err(|_| "run ID overflow")?
            || json_member(fields, "run_attempt")?.number()? != run_attempt
            || json_member(fields, "event")?.string()? != "workflow_dispatch"
            || json_member(fields, "path")?.string()? != ".github/workflows/release.yml"
            || json_member(fields, "head_sha")?.string()? != workflow_sha
            || json_member(run_repository, "id")?.number()? != repository_id
        {
            return Err("GitHub workflow run identity differs from trusted event".to_owned());
        }
        let created_at = json_member(fields, "created_at")?.string()?.to_owned();
        crate::conformance::validate_utc_instant(&created_at)?;
        Ok(created_at)
    }

    pub(crate) fn release_by_tag(
        &self,
        repository: &str,
        tag: &str,
    ) -> Result<Option<JsonValue>, String> {
        let segments = repository_segments(repository, ["releases", "tags", tag])?;
        self.request("GET", &segments, None, None, &[200, 404])
            .and_then(|(status, body)| {
                if status == 404 {
                    Ok(None)
                } else {
                    parse_json(&body).map(Some)
                }
            })
    }

    pub(crate) fn release_state_by_tag(
        &self,
        repository: &str,
        tag: &str,
    ) -> Result<Option<JsonValue>, String> {
        let segments = repository_segments(repository, ["releases"])?;
        let mut matched = None;
        for page in 1..=10_u8 {
            let url = format!("{}?per_page=100&page={page}", self.api.url(&segments));
            let (_, body) = self.request_url("GET", &url, None, None, &[200])?;
            let document = parse_json(&body)?;
            let releases = document.array()?;
            for release in releases {
                let object = release.object()?;
                if json_member(object, "tag_name")?.string()? == tag
                    && matched.replace(release.clone()).is_some()
                {
                    return Err("GitHub returned duplicate releases for the planned tag".to_owned());
                }
            }
            if releases.len() < 100 {
                return Ok(matched);
            }
        }
        Err("GitHub release listing exceeded the bounded page limit".to_owned())
    }

    pub(crate) fn tag_commit(&self, repository: &str, tag: &str) -> Result<Option<String>, String> {
        let segments = repository_segments(repository, ["git", "ref", "tags", tag])?;
        let (status, body) = self.request("GET", &segments, None, None, &[200, 404])?;
        if status == 404 {
            return Ok(None);
        }
        let value = parse_json(&body)?;
        let object = value.object()?;
        require_exact_json_keys(object, &["node_id", "object", "ref", "url"])?;
        if json_member(object, "ref")?.string()? != format!("refs/tags/{tag}") {
            return Err("GitHub returned a different tag ref".to_owned());
        }
        let target = json_member(object, "object")?.object()?;
        require_exact_json_keys(target, &["sha", "type", "url"])?;
        let mut sha = json_member(target, "sha")?.string()?.to_owned();
        let mut kind = json_member(target, "type")?.string()?.to_owned();
        for _ in 0..8 {
            match kind.as_str() {
                "commit" => return Ok(Some(sha)),
                "tag" => {
                    let segments = repository_segments(repository, ["git", "tags", sha.as_str()])?;
                    let (_, body) = self.request("GET", &segments, None, None, &[200])?;
                    let value = parse_json(&body)?;
                    let tag = value.object()?;
                    require_exact_json_keys(
                        tag,
                        &[
                            "message",
                            "node_id",
                            "object",
                            "sha",
                            "tag",
                            "tagger",
                            "url",
                            "verification",
                        ],
                    )?;
                    let object = json_member(tag, "object")?.object()?;
                    require_exact_json_keys(object, &["sha", "type", "url"])?;
                    sha = json_member(object, "sha")?.string()?.to_owned();
                    kind = json_member(object, "type")?.string()?.to_owned();
                }
                _ => return Err("tag does not resolve to a commit".to_owned()),
            }
        }
        Err("annotated tag chain exceeds the maximum depth".to_owned())
    }

    pub(crate) fn immutable_releases_enabled(&self, repository: &str) -> Result<bool, String> {
        let segments = repository_segments(repository, ["immutable-releases"])?;
        let (_, body) = self.request("GET", &segments, None, None, &[200])?;
        let value = parse_json(&body)?;
        Ok(json_member(value.object()?, "enabled")?.boolean()?)
    }

    pub(crate) fn create_draft(&self, repository: &str, body: &str) -> Result<JsonValue, String> {
        let segments = repository_segments(repository, ["releases"])?;
        let (_, response) = self.request(
            "POST",
            &segments,
            Some("application/json"),
            Some(body.as_bytes()),
            &[201],
        )?;
        parse_json(&response)
    }

    pub(crate) fn update_release(
        &self,
        repository: &str,
        id: u64,
        body: &str,
    ) -> Result<JsonValue, String> {
        let id = id.to_string();
        let segments = repository_segments(repository, ["releases", id.as_str()])?;
        let (_, response) = self.request(
            "PATCH",
            &segments,
            Some("application/json"),
            Some(body.as_bytes()),
            &[200],
        )?;
        parse_json(&response)
    }

    pub(crate) fn delete_release(&self, repository: &str, id: u64) -> Result<(), String> {
        let id = id.to_string();
        let segments = repository_segments(repository, ["releases", id.as_str()])?;
        self.request("DELETE", &segments, None, None, &[204])
            .map(|_| ())
    }

    pub(crate) fn delete_asset(&self, repository: &str, id: u64) -> Result<(), String> {
        let id = id.to_string();
        let segments = repository_segments(repository, ["releases", "assets", id.as_str()])?;
        self.request("DELETE", &segments, None, None, &[204])
            .map(|_| ())
    }

    pub(crate) fn upload_asset(
        &self,
        upload_url: &str,
        name: &str,
        path: &Path,
    ) -> Result<JsonValue, String> {
        let base = upload_url
            .split('{')
            .next()
            .ok_or_else(|| "release upload URL is malformed".to_owned())?;
        if !self.api.trusted_upload_url(base) {
            return Err("release upload URL is not a trusted GitHub upload origin".to_owned());
        }
        let bytes = super::manifest::read_regular(path)?;
        let url = format!("{base}?name={}", encode_segment(name));
        let (_, body) = self.request_url(
            "POST",
            &url,
            Some("application/octet-stream"),
            Some(&bytes),
            &[201],
        )?;
        parse_json(&body)
    }

    fn get(&self, segments: &[String]) -> Result<String, String> {
        self.request("GET", segments, None, None, &[200])
            .map(|(_, body)| body)
    }

    fn request(
        &self,
        method: &str,
        segments: &[String],
        content_type: Option<&str>,
        body: Option<&[u8]>,
        accepted: &[u16],
    ) -> Result<(u16, String), String> {
        let url = self.api.url(segments);
        self.request_url(method, &url, content_type, body, accepted)
    }

    fn request_url(
        &self,
        method: &str,
        url: &str,
        content_type: Option<&str>,
        body: Option<&[u8]>,
        accepted: &[u16],
    ) -> Result<(u16, String), String> {
        let token = format!("Bearer {}", self.token);
        let send = |request: ureq::RequestBuilder<ureq::typestate::WithoutBody>| {
            request
                .header("Authorization", &token)
                .header("Accept", "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2026-03-10")
                .header("User-Agent", "hell-ci")
                .call()
        };
        let send_body = |request: ureq::RequestBuilder<ureq::typestate::WithBody>, bytes: &[u8]| {
            let request = request
                .header("Authorization", &token)
                .header("Accept", "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2026-03-10")
                .header("User-Agent", "hell-ci");
            let request = if let Some(value) = content_type {
                request.header("Content-Type", value)
            } else {
                request
            };
            request.send(bytes)
        };
        let mut response = match (method, body) {
            ("GET", None) => send(self.agent.get(url)),
            ("DELETE", None) => send(self.agent.delete(url)),
            ("POST", Some(bytes)) => send_body(self.agent.post(url), bytes),
            ("PATCH", Some(bytes)) => send_body(self.agent.patch(url), bytes),
            _ => return Err("unsupported GitHub API method/body combination".to_owned()),
        }
        .map_err(|error| format!("GitHub API request failed: {error}"))?;
        let status = response.status().as_u16();
        if !accepted.contains(&status) {
            return Err(format!("GitHub API returned {status}"));
        }
        let body = response
            .body_mut()
            .with_config()
            .limit(MAX_RESPONSE_BYTES)
            .read_to_string()
            .map_err(|error| format!("GitHub API response failed: {error}"))?;
        Ok((status, body))
    }
}

fn required_environment_value(value: Option<OsString>, name: &str) -> Result<String, String> {
    let value = value.ok_or_else(|| format!("{name} is required"))?;
    let value = value
        .into_string()
        .map_err(|_| format!("{name} must be UTF-8"))?;
    if value.is_empty() || value.contains(['\r', '\n']) {
        return Err(format!("{name} is invalid"));
    }
    Ok(value)
}

fn repository_segments<const N: usize>(
    repository: &str,
    suffix: [&str; N],
) -> Result<Vec<String>, String> {
    let mut segments = repository.split('/').map(str::to_owned).collect::<Vec<_>>();
    if segments.len() != 2 || segments.iter().any(|segment| segment.is_empty()) {
        return Err("repository full name is invalid".to_owned());
    }
    segments.extend(suffix.into_iter().map(str::to_owned));
    Ok(segments)
}

impl HttpEndpoint {
    fn parse(value: &str) -> Result<Self, String> {
        let (scheme, rest) = value
            .split_once("://")
            .ok_or_else(|| "GITHUB_API_URL is not absolute".to_owned())?;
        if scheme != "https" || rest.contains(['\r', '\n', '#', '?']) {
            return Err("GITHUB_API_URL is unsupported".to_owned());
        }
        let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
        if !valid_https_authority(authority) {
            return Err("GITHUB_API_URL authority is invalid".to_owned());
        }
        let base_path = path
            .split('/')
            .filter(|part| !part.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if base_path.iter().any(|part| {
            part == "."
                || part == ".."
                || !part.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~')
                })
        }) {
            return Err("GITHUB_API_URL path is invalid".to_owned());
        }
        Ok(Self {
            scheme: scheme.to_owned(),
            authority: authority.to_owned(),
            base_path,
        })
    }

    fn url(&self, segments: &[String]) -> String {
        let mut path = self
            .base_path
            .iter()
            .map(|segment| encode_segment(segment))
            .collect::<Vec<_>>();
        path.push("repos".to_owned());
        path.extend(segments.iter().map(|segment| encode_segment(segment)));
        format!("{}://{}/{}", self.scheme, self.authority, path.join("/"))
    }

    fn trusted_upload_url(&self, value: &str) -> bool {
        #[cfg(test)]
        if self.scheme == "http" && value.starts_with(&format!("http://{}/", self.authority)) {
            return true;
        }
        if self.scheme != "https" || !value.starts_with("https://") {
            return false;
        }
        let authority = value
            .strip_prefix("https://")
            .and_then(|rest| rest.split('/').next())
            .unwrap_or_default();
        authority == self.authority
            || (self.authority == "api.github.com" && authority == "uploads.github.com")
    }
}

fn valid_https_authority(authority: &str) -> bool {
    if authority.is_empty() || authority.contains(['@', '[', ']']) || !authority.is_ascii() {
        return false;
    }
    let (host, port) = authority
        .split_once(':')
        .map_or((authority, None), |(host, port)| (host, Some(port)));
    if host.is_empty()
        || authority.matches(':').count() > 1
        || port
            .is_some_and(|port| port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

fn encode_segment(value: &str) -> String {
    let mut output = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            output.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            write!(output, "%{byte:02X}").expect("String writes cannot fail");
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    use std::thread;

    fn test_client(address: std::net::SocketAddr) -> GitHubClient {
        GitHubClient::for_test(address)
    }

    fn read_request(stream: &mut std::net::TcpStream) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut buffer = [0_u8; 8192];
        loop {
            let read = stream.read(&mut buffer).unwrap();
            bytes.extend_from_slice(&buffer[..read]);
            let Some(header_end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") else {
                continue;
            };
            let headers = String::from_utf8_lossy(&bytes[..header_end]);
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let line = line.to_ascii_lowercase();
                    line.strip_prefix("content-length: ")
                        .and_then(|value| value.parse::<usize>().ok())
                })
                .unwrap_or(0);
            if bytes.len() >= header_end + 4 + content_length {
                return bytes;
            }
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
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 4096];
            let length = stream.read(&mut request).unwrap();
            let request = std::str::from_utf8(&request[..length]).unwrap();
            assert!(
                request
                    .starts_with("GET /repos/owner/repository/git/ref/heads/release%2F1 HTTP/1.1")
            );
            assert!(
                request
                    .to_ascii_lowercase()
                    .contains("authorization: bearer test-token")
            );
            assert!(!request.lines().next().unwrap().contains("test-token"));
            let body = concat!(
                "{\"node_id\":\"node\",\"object\":{\"sha\":",
                "\"1111111111111111111111111111111111111111\",",
                "\"type\":\"commit\",\"url\":\"https://api.github.com/object\"},",
                "\"ref\":\"refs/heads/release/1\",",
                "\"url\":\"https://api.github.com/ref\"}"
            );
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        });
        let client = test_client(address);
        assert_eq!(
            client.branch_head("owner/repository", "release/1").unwrap(),
            "1111111111111111111111111111111111111111"
        );
        server.join().unwrap();
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
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let body = body.to_owned();
            let server = thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0_u8; 4096];
                let length = stream.read(&mut request).unwrap();
                let request = std::str::from_utf8(&request[..length]).unwrap();
                assert!(request.starts_with(
                    "GET /repos/owner/repository/releases?per_page=100&page=1 HTTP/1.1"
                ));
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            });
            let result = test_client(address).release_state_by_tag("owner/repository", "v1");
            assert_eq!(result.is_err(), expected_error);
            if !expected_error {
                assert!(result.unwrap().is_some());
            }
            server.join().unwrap();
        }
    }

    #[test]
    fn draft_creation_is_observable_through_authenticated_release_listing() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let release = r#"{"assets":[],"body":"marker","draft":true,"id":7,"prerelease":false,"tag_name":"v1","target_commitish":"1111111111111111111111111111111111111111","upload_url":"http://uploads.invalid/{?name,label}"}"#;
        let server = thread::spawn(move || {
            for (index, status, body) in [
                (0, "201 Created", release.to_owned()),
                (1, "200 OK", format!("[{release}]")),
            ] {
                let (mut stream, _) = listener.accept().unwrap();
                let request = read_request(&mut stream);
                let request = std::str::from_utf8(&request).unwrap();
                if index == 0 {
                    assert!(request.starts_with("POST /repos/owner/repository/releases HTTP/1.1"));
                    assert!(
                        request
                            .to_ascii_lowercase()
                            .contains("\r\nauthorization: bearer test-token\r\n")
                    );
                } else {
                    assert!(request.starts_with(
                        "GET /repos/owner/repository/releases?per_page=100&page=1 HTTP/1.1"
                    ));
                }
                write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            }
        });
        let client = test_client(address);
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
        server.join().unwrap();
    }
}
