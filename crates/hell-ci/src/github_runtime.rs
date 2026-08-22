use std::path::PathBuf;

use crate::json::{json_member, parse_json};
use crate::release::manifest::read_regular;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RepositoryIdentity {
    pub(crate) full_name: String,
    pub(crate) numeric_id: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RunnerIdentity {
    pub(crate) image_os: Option<String>,
    pub(crate) image_version: Option<String>,
    pub(crate) runner_architecture: String,
    pub(crate) runner_os: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GithubRuntime {
    pub(crate) api_url: String,
    pub(crate) event_name: String,
    pub(crate) event_path: PathBuf,
    pub(crate) ref_name: String,
    pub(crate) repository: RepositoryIdentity,
    pub(crate) runner: Option<RunnerIdentity>,
    pub(crate) run_attempt: u64,
    pub(crate) run_id: u64,
    pub(crate) workflow_ref: String,
    pub(crate) workflow_sha: String,
    pub(crate) workspace: PathBuf,
}

pub(crate) struct GithubCredential(Vec<u8>);

impl GithubRuntime {
    pub(crate) fn from_process() -> Result<Self, String> {
        let required = |name: &str| {
            std::env::var(name)
                .map_err(|_| {
                    format!("required standard GitHub variable {name} is missing or not UTF-8")
                })
                .and_then(|value| validate_environment_value(name, value))
        };
        let optional = |name: &str| {
            std::env::var(name)
                .map(Some)
                .or_else(|error| match error {
                    std::env::VarError::NotPresent => Ok(None),
                    std::env::VarError::NotUnicode(_) => {
                        Err(format!("standard GitHub variable {name} is not UTF-8"))
                    }
                })
                .and_then(|value| {
                    value
                        .map(|value| validate_environment_value(name, value))
                        .transpose()
                })
        };
        let event_path = PathBuf::from(std::env::var_os("GITHUB_EVENT_PATH").ok_or_else(|| {
            "required standard GitHub variable GITHUB_EVENT_PATH is missing".to_owned()
        })?);
        let repository_name = required("GITHUB_REPOSITORY")?;
        validate_repository_name(&repository_name)?;
        let repository_id = canonical_u64(&required("GITHUB_REPOSITORY_ID")?, "repository ID")?;
        let event_bytes = read_regular(&event_path)?;
        let event_text = std::str::from_utf8(&event_bytes)
            .map_err(|_| "trusted GitHub event is not UTF-8".to_owned())?;
        let event = parse_json(event_text)?;
        let repository = json_member(event.object()?, "repository")?.object()?;
        if json_member(repository, "id")?.number()? != repository_id
            || json_member(repository, "full_name")?.string()? != repository_name
        {
            return Err(
                "trusted GitHub runtime repository identity differs from the event".to_owned(),
            );
        }
        let workflow_sha = required("GITHUB_WORKFLOW_SHA")?;
        crate::release::schema::require_sha(&workflow_sha, "workflow SHA")?;
        let runner_os = optional("RUNNER_OS")?;
        let runner_architecture = optional("RUNNER_ARCH")?;
        let runner = match (runner_os, runner_architecture) {
            (Some(runner_os), Some(runner_architecture)) => Some(RunnerIdentity {
                image_os: optional("ImageOS")?,
                image_version: optional("ImageVersion")?,
                runner_architecture,
                runner_os,
            }),
            (None, None) => None,
            _ => {
                return Err(
                    "RUNNER_OS and RUNNER_ARCH must be either both present or both absent"
                        .to_owned(),
                );
            }
        };
        Ok(Self {
            api_url: validate_api_url(required("GITHUB_API_URL")?)?,
            event_name: required("GITHUB_EVENT_NAME")?,
            event_path,
            ref_name: required("GITHUB_REF_NAME")?,
            repository: RepositoryIdentity {
                full_name: repository_name,
                numeric_id: repository_id,
            },
            runner,
            run_attempt: canonical_u64(&required("GITHUB_RUN_ATTEMPT")?, "run attempt")?,
            run_id: canonical_u64(&required("GITHUB_RUN_ID")?, "run ID")?,
            workflow_ref: required("GITHUB_WORKFLOW_REF")?,
            workflow_sha,
            workspace: PathBuf::from(std::env::var_os("GITHUB_WORKSPACE").ok_or_else(|| {
                "required standard GitHub variable GITHUB_WORKSPACE is missing".to_owned()
            })?),
        })
    }
}

impl GithubCredential {
    pub(crate) fn from_process() -> Result<Self, String> {
        let value = std::env::var("GITHUB_TOKEN")
            .map_err(|_| {
                "required standard GitHub variable GITHUB_TOKEN is missing or not UTF-8".to_owned()
            })
            .and_then(|value| validate_environment_value("GITHUB_TOKEN", value))?;
        if value.bytes().any(|byte| byte.is_ascii_control()) {
            return Err("GITHUB_TOKEN contains a control byte".to_owned());
        }
        Ok(Self(value.into_bytes()))
    }

    #[cfg(test)]
    pub(crate) fn from_value(value: std::ffi::OsString) -> Result<Self, String> {
        let value = value
            .into_string()
            .map_err(|_| "GITHUB_TOKEN must be UTF-8".to_owned())
            .and_then(|value| validate_environment_value("GITHUB_TOKEN", value))?;
        if value.bytes().any(|byte| byte.is_ascii_control()) {
            return Err("GITHUB_TOKEN contains a control byte".to_owned());
        }
        Ok(Self(value.into_bytes()))
    }

    pub(crate) fn with_bearer_header<T>(
        &self,
        operation: impl FnOnce(&str) -> Result<T, String>,
    ) -> Result<T, String> {
        let mut bytes = b"Bearer ".to_vec();
        bytes.extend_from_slice(&self.0);
        let header = std::str::from_utf8(&bytes)
            .map_err(|_| "GITHUB_TOKEN is not valid UTF-8".to_owned())?;
        let result = operation(header);
        bytes.fill(0);
        result
    }
}

impl Drop for GithubCredential {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

fn validate_environment_value(name: &str, value: String) -> Result<String, String> {
    if value.is_empty() || value.contains(['\0', '\r', '\n']) {
        return Err(format!("standard GitHub variable {name} is invalid"));
    }
    Ok(value)
}

fn canonical_u64(value: &str, label: &str) -> Result<u64, String> {
    let parsed = value
        .parse::<u64>()
        .map_err(|_| format!("trusted GitHub {label} is not an unsigned integer"))?;
    if parsed == 0 || value != parsed.to_string() {
        return Err(format!(
            "trusted GitHub {label} is not canonical and nonzero"
        ));
    }
    Ok(parsed)
}

fn validate_repository_name(value: &str) -> Result<(), String> {
    let mut components = value.split('/');
    let owner = components.next().unwrap_or_default();
    let repository = components.next().unwrap_or_default();
    if owner.is_empty()
        || repository.is_empty()
        || components.next().is_some()
        || !owner.bytes().all(repository_component_byte)
        || !repository.bytes().all(repository_component_byte)
    {
        return Err("GITHUB_REPOSITORY is not a canonical owner/repository identity".to_owned());
    }
    Ok(())
}

const fn repository_component_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
}

fn validate_api_url(value: String) -> Result<String, String> {
    let trusted_https = value == "https://api.github.com";
    let loopback_http = value
        .strip_prefix("http://127.0.0.1:")
        .is_some_and(|port| !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()));
    if !trusted_https && !loopback_http {
        return Err("GITHUB_API_URL is not the trusted GitHub API or a loopback origin".to_owned());
    }
    Ok(value)
}
