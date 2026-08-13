use std::collections::BTreeMap;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::command::CommandSpec;
use crate::json::{JsonValue, json_member, parse_json, require_exact_json_keys};

use super::github::GitHubClient;
use super::manifest::{read_regular, write_digest_sibling, write_json};
use super::schema::{Resolution, require_sha};

pub(crate) fn resolve(output: PathBuf) -> Result<String, String> {
    let event_name = required_env("GITHUB_EVENT_NAME")?;
    if event_name != "workflow_dispatch" {
        return Err("release resolver accepts only workflow_dispatch".to_owned());
    }
    let event_path = PathBuf::from(required_env_os("GITHUB_EVENT_PATH")?);
    let event_bytes = read_regular(&event_path)?;
    let event_text =
        std::str::from_utf8(&event_bytes).map_err(|_| "GitHub event is not UTF-8".to_owned())?;
    let event = parse_json(event_text)?;
    let root = event.object()?;
    let repository = json_member(root, "repository")?.object()?;
    let sender = json_member(root, "sender")?.object()?;
    let inputs = json_member(root, "inputs")?.object()?;
    require_exact_json_keys(inputs, &["candidate_branch"])?;

    let default_branch = text(repository, "default_branch")?;
    if required_env("GITHUB_REF_NAME")? != default_branch {
        return Err(
            "release workflow is not running from the repository default branch".to_owned(),
        );
    }
    let workflow_sha = required_env("GITHUB_WORKFLOW_SHA")?;
    require_sha(&workflow_sha, "workflow SHA")?;
    let repository_name = text(repository, "full_name")?;
    let expected_workflow_ref =
        format!("{repository_name}/.github/workflows/release.yml@refs/heads/{default_branch}");
    if required_env("GITHUB_WORKFLOW_REF")? != expected_workflow_ref {
        return Err(
            "GITHUB_WORKFLOW_REF is not the trusted default-branch release workflow".to_owned(),
        );
    }
    let automation = PathBuf::from(required_env_os("GITHUB_WORKSPACE")?).join("automation");
    let checkout_head = git_output(&automation, ["rev-parse", "HEAD"])?;
    if checkout_head != workflow_sha {
        return Err("trusted automation checkout does not equal GITHUB_WORKFLOW_SHA".to_owned());
    }

    let candidate_branch = text(inputs, "candidate_branch")?;
    validate_branch_name(&candidate_branch)?;
    if required_env("GITHUB_REPOSITORY")? != repository_name {
        return Err("event repository differs from GITHUB_REPOSITORY".to_owned());
    }
    let client = GitHubClient::from_actions_environment()?;
    let candidate_sha = client.branch_head(&repository_name, &candidate_branch)?;
    require_sha(&candidate_sha, "candidate SHA")?;

    let resolution = Resolution {
        repository: repository_name,
        repository_id: json_member(repository, "id")?.number()?,
        default_branch,
        candidate_branch,
        candidate_sha,
        actor: text(sender, "login")?,
        actor_id: json_member(sender, "id")?.number()?,
        run_id: parse_env_u64("GITHUB_RUN_ID")?,
        run_attempt: parse_env_u64("GITHUB_RUN_ATTEMPT")?,
        workflow_ref: required_env("GITHUB_WORKFLOW_REF")?,
        workflow_sha,
    };
    let bytes = write_json(&output, &resolution.json())?;
    write_digest_sibling(&output, &bytes)?;
    write_outputs(&resolution)?;
    Ok(format!(
        "resolved {} to {}",
        resolution.candidate_branch, resolution.candidate_sha
    ))
}

fn validate_branch_name(branch: &str) -> Result<(), String> {
    if branch.is_empty()
        || branch.starts_with('-')
        || branch.contains(['\0', '\n', '\r'])
        || branch.starts_with("refs/")
        || branch
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
        || branch.ends_with('.')
        || branch.ends_with(".lock")
        || branch.contains("..")
        || branch.contains("@{")
        || branch.bytes().any(|byte| {
            byte.is_ascii_control()
                || matches!(byte, b' ' | b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\')
        })
    {
        return Err("candidate branch name is not canonical".to_owned());
    }
    let result = CommandSpec::new("git", Duration::from_secs(30))
        .arguments([
            OsString::from("check-ref-format"),
            OsString::from("--branch"),
            OsString::from(branch),
        ])
        .run()
        .map_err(|error| format!("cannot validate candidate branch with git: {error}"))?;
    if !result.status.success() || result.timed_out {
        return Err("git rejected candidate branch name".to_owned());
    }
    Ok(())
}

fn git_output<const N: usize>(directory: &Path, arguments: [&str; N]) -> Result<String, String> {
    let result = CommandSpec::new("git", Duration::from_secs(30))
        .arguments(arguments)
        .current_directory(directory)
        .run()
        .map_err(|error| format!("cannot run git: {error}"))?;
    if !result.status.success() || result.timed_out {
        return Err("git command failed".to_owned());
    }
    let text =
        std::str::from_utf8(&result.stdout).map_err(|_| "git output is not UTF-8".to_owned())?;
    Ok(text.trim_end_matches(['\r', '\n']).to_owned())
}

fn text(object: &BTreeMap<String, JsonValue>, key: &str) -> Result<String, String> {
    Ok(json_member(object, key)?.string()?.to_owned())
}

fn required_env(name: &str) -> Result<String, String> {
    env::var(name)
        .map_err(|_| format!("required environment variable {name} is missing or not UTF-8"))
}

fn required_env_os(name: &str) -> Result<OsString, String> {
    env::var_os(name).ok_or_else(|| format!("required environment variable {name} is missing"))
}

fn parse_env_u64(name: &str) -> Result<u64, String> {
    required_env(name)?
        .parse()
        .map_err(|_| format!("{name} is not an unsigned integer"))
}

fn write_outputs(resolution: &Resolution) -> Result<(), String> {
    let Some(path) = env::var_os("GITHUB_OUTPUT") else {
        return Ok(());
    };
    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| format!("cannot inspect GITHUB_OUTPUT: {error}"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err("GITHUB_OUTPUT is not a regular file".to_owned());
    }
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(path)
        .map_err(|error| format!("cannot open GITHUB_OUTPUT: {error}"))?;
    writeln!(file, "candidate_sha={}", resolution.candidate_sha)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("cannot write GITHUB_OUTPUT: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn branch_parser_is_fail_closed_without_patterns() {
        for valid in ["main", "release/0.2.0", "feature_name"] {
            assert!(validate_branch_name(valid).is_ok(), "{valid}");
        }
        for invalid in [
            "",
            "-bad",
            "refs/heads/main",
            "a..b",
            "a//b",
            "a@{b",
            "a b",
            "tag.lock",
        ] {
            assert!(validate_branch_name(invalid).is_err(), "{invalid}");
        }
    }
}
