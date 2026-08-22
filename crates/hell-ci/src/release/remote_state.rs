use std::path::Path;

use crate::json::JsonValue;

use super::github::GitHubClient;
use super::manifest::{read_json, write_json_new};
use super::schema::{ReleasePlan, number, object, require_sha, string};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RemoteState {
    StableAndTagAbsent,
    CandidateBranchMoved,
    TagAlreadyExists,
    RemoteQueryFailed,
}

impl RemoteState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::StableAndTagAbsent => "stable-and-tag-absent",
            Self::CandidateBranchMoved => "candidate-branch-moved",
            Self::TagAlreadyExists => "tag-already-exists",
            Self::RemoteQueryFailed => "remote-query-failed",
        }
    }
}

pub(crate) fn check(plan_path: &Path, report: &Path) -> Result<String, String> {
    let plan = ReleasePlan::parse(&read_json(plan_path)?)?;
    let client = GitHubClient::from_actions_environment()?;
    check_with_client(&plan, report, &client)
}

fn check_with_client(
    plan: &ReleasePlan,
    report: &Path,
    client: &GitHubClient,
) -> Result<String, String> {
    let observed_candidate = match client.branch_head(
        &plan.resolution.repository,
        &plan.resolution.candidate_branch,
    ) {
        Ok(candidate) => candidate,
        Err(error) => {
            return query_failure(plan, report, None, None, "candidate-branch-query", &error);
        }
    };
    if let Err(error) = require_sha(&observed_candidate, "observed candidate SHA") {
        return query_failure(
            plan,
            report,
            Some(&observed_candidate),
            None,
            "candidate-branch-response",
            &error,
        );
    }
    let observed_tag = match client.tag_commit(&plan.resolution.repository, &plan.tag) {
        Ok(tag) => tag,
        Err(error) => {
            return query_failure(
                plan,
                report,
                Some(&observed_candidate),
                None,
                "tag-query",
                &error,
            );
        }
    };
    if let Some(tag_commit) = &observed_tag
        && let Err(error) = require_sha(tag_commit, "observed tag commit")
    {
        return query_failure(
            plan,
            report,
            Some(&observed_candidate),
            Some(tag_commit),
            "tag-response",
            &error,
        );
    }

    let state = if observed_candidate != plan.resolution.candidate_sha {
        RemoteState::CandidateBranchMoved
    } else if observed_tag.is_some() {
        RemoteState::TagAlreadyExists
    } else {
        RemoteState::StableAndTagAbsent
    };
    write_report(
        plan,
        report,
        state,
        Some(&observed_candidate),
        observed_tag.as_deref(),
        None,
    )?;
    match state {
        RemoteState::StableAndTagAbsent => {
            Ok("verified stable candidate branch and absent release tag".to_owned())
        }
        RemoteState::CandidateBranchMoved => {
            Err("candidate branch moved after release planning".to_owned())
        }
        RemoteState::TagAlreadyExists => Err("planned release tag already exists".to_owned()),
        RemoteState::RemoteQueryFailed => {
            unreachable!("query failures return before classification")
        }
    }
}

fn query_failure(
    plan: &ReleasePlan,
    report: &Path,
    observed_candidate: Option<&str>,
    observed_tag: Option<&str>,
    category: &str,
    error: &str,
) -> Result<String, String> {
    let report_result = write_report(
        plan,
        report,
        RemoteState::RemoteQueryFailed,
        observed_candidate,
        observed_tag,
        Some(category),
    );
    match report_result {
        Ok(()) => Err(format!("remote state query failed: {error}")),
        Err(report_error) => Err(format!(
            "remote state query failed: {error}; cannot write remote-state report: {report_error}"
        )),
    }
}

fn write_report(
    plan: &ReleasePlan,
    report: &Path,
    state: RemoteState,
    observed_candidate: Option<&str>,
    observed_tag: Option<&str>,
    error_category: Option<&str>,
) -> Result<(), String> {
    write_json_new(
        report,
        &object([
            (
                "admitted",
                JsonValue::Bool(state == RemoteState::StableAndTagAbsent),
            ),
            ("candidateBranch", string(&plan.resolution.candidate_branch)),
            (
                "errorCategory",
                error_category.map_or(JsonValue::Null, string),
            ),
            (
                "expectedCandidateSha",
                string(&plan.resolution.candidate_sha),
            ),
            (
                "observedCandidateSha",
                observed_candidate.map_or(JsonValue::Null, string),
            ),
            (
                "observedTagCommit",
                observed_tag.map_or(JsonValue::Null, string),
            ),
            ("planSha256", string(&plan.plan_sha256)),
            ("repository", string(&plan.resolution.repository)),
            ("schemaVersion", number(1)),
            ("state", string(state.as_str())),
            ("tag", string(&plan.tag)),
        ]),
    )
    .map(|_| ())
}

#[cfg(test)]
#[path = "../../tests/release_remote_state/mod.rs"]
mod tests;
