#[cfg(test)]
use std::ffi::OsString;
use std::path::Path;
use std::time::Duration;

use crate::github_runtime::{GithubCredential, GithubRuntime};
use crate::json::{JsonValue, json_member, parse_json, require_exact_json_keys};

const MAX_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;

#[cfg(test)]
#[path = "../../tests/release_github/transport.rs"]
pub(crate) mod fixture;

pub(crate) struct GitHubClient {
    api: HttpEndpoint,
    credential: GithubCredential,
    agent: ureq::Agent,
    #[cfg(test)]
    fixture: Option<fixture::Transcript>,
}

struct HttpEndpoint {
    scheme: String,
    authority: String,
    base_path: Vec<String>,
}

enum HttpResponse {
    Network(ureq::http::Response<ureq::Body>),
    #[cfg(test)]
    Fixture(u16, Vec<u8>),
}

impl HttpResponse {
    fn status(&self) -> u16 {
        match self {
            Self::Network(response) => response.status().as_u16(),
            #[cfg(test)]
            Self::Fixture(status, _) => *status,
        }
    }

    fn read_body(self) -> Result<String, String> {
        match self {
            Self::Network(mut response) => response
                .body_mut()
                .with_config()
                .limit(MAX_RESPONSE_BYTES)
                .read_to_string()
                .map_err(|error| format!("GitHub API response failed: {error}")),
            #[cfg(test)]
            Self::Fixture(_, bytes) => {
                if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_RESPONSE_BYTES {
                    return Err("GitHub API response exceeded its byte bound".to_owned());
                }
                String::from_utf8(bytes)
                    .map_err(|error| format!("GitHub API response failed: {error}"))
            }
        }
    }
}

impl GitHubClient {
    #[cfg(test)]
    pub(crate) fn for_test(fixture: fixture::Transcript) -> Self {
        let mut client = Self::new(
            "https://api.github.com",
            GithubCredential::from_value(OsString::from("test-token"))
                .expect("valid test credential"),
        )
        .expect("valid test API origin");
        client.fixture = Some(fixture);
        client
    }
    pub(crate) fn from_actions_environment() -> Result<Self, String> {
        let runtime = GithubRuntime::from_process()?;
        let credential = GithubCredential::from_process()?;
        Self::from_runtime(&runtime, credential)
    }

    #[cfg(test)]
    fn from_actions_values(api: Option<OsString>, token: Option<OsString>) -> Result<Self, String> {
        let api = required_environment_value(api, "GITHUB_API_URL")?;
        let credential = GithubCredential::from_value(
            token.ok_or_else(|| "GITHUB_TOKEN is required".to_owned())?,
        )?;
        Self::new(&api, credential)
    }

    fn from_runtime(runtime: &GithubRuntime, credential: GithubCredential) -> Result<Self, String> {
        Self::new(&runtime.api_url, credential)
    }

    fn new(api: &str, credential: GithubCredential) -> Result<Self, String> {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(30)))
            .http_status_as_error(false)
            .build();
        Ok(Self {
            api: HttpEndpoint::parse(api)?,
            credential,
            agent: config.into(),
            #[cfg(test)]
            fixture: None,
        })
    }

    pub(crate) fn branch_head(&self, repository: &str, branch: &str) -> Result<String, String> {
        let mut segments = repository.split('/').map(str::to_owned).collect::<Vec<_>>();
        if segments.len() != 2 || segments.iter().any(String::is_empty) {
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
                    json_member(object, "sha")?.string()?.clone_into(&mut sha);
                    json_member(object, "type")?.string()?.clone_into(&mut kind);
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
        json_member(value.object()?, "enabled")?.boolean()
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
        if !matches!(
            (method, body),
            ("GET" | "DELETE", None) | ("POST" | "PATCH", Some(_))
        ) {
            return Err("unsupported GitHub API method/body combination".to_owned());
        }
        let response = self.credential.with_bearer_header(|authorization| {
            let headers = [
                ("Authorization", authorization),
                ("Accept", "application/vnd.github+json"),
                ("X-GitHub-Api-Version", "2026-03-10"),
                ("User-Agent", "hell-ci"),
            ];
            #[cfg(test)]
            if let Some(fixture) = &self.fixture {
                return fixture
                    .request(fixture::Request::observed(
                        method,
                        url,
                        &headers,
                        content_type.filter(|_| body.is_some()),
                        body,
                    ))
                    .map(|(status, bytes)| HttpResponse::Fixture(status, bytes));
            }
            let send = |request: ureq::RequestBuilder<ureq::typestate::WithoutBody>| {
                let mut request = request;
                for (name, value) in headers {
                    request = request.header(name, value);
                }
                request.call()
            };
            let send_body = |request: ureq::RequestBuilder<ureq::typestate::WithBody>,
                             bytes: &[u8]| {
                let mut request = request;
                for (name, value) in headers {
                    request = request.header(name, value);
                }
                let request = if let Some(value) = content_type {
                    request.header("Content-Type", value)
                } else {
                    request
                };
                request.send(bytes)
            };
            let response = match (method, body) {
                ("GET", None) => send(self.agent.get(url)),
                ("DELETE", None) => send(self.agent.delete(url)),
                ("POST", Some(bytes)) => send_body(self.agent.post(url), bytes),
                ("PATCH", Some(bytes)) => send_body(self.agent.patch(url), bytes),
                _ => return Err("unsupported GitHub API method/body combination".to_owned()),
            }
            .map_err(|error| format!("GitHub API request failed: {error}"))?;
            Ok(HttpResponse::Network(response))
        })?;
        let status = response.status();
        if !accepted.contains(&status) {
            return Err(format!("GitHub API returned {status}"));
        }
        let body = response.read_body()?;
        Ok((status, body))
    }
}

#[cfg(test)]
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
    if segments.len() != 2 || segments.iter().any(String::is_empty) {
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
#[path = "../../tests/release_github/mod.rs"]
mod tests;
