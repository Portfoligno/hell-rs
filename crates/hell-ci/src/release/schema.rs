use std::collections::BTreeMap;

use crate::json::{JsonValue, canonical_json_bytes, json_member, require_exact_json_keys};

pub(crate) const PLATFORMS: [ReleasePlatform; 3] = [
    ReleasePlatform::LinuxX86_64,
    ReleasePlatform::MacosAarch64,
    ReleasePlatform::WindowsX86_64,
];
const FULL_GIT_SHA_SHAPE: &str = "0000000000000000000000000000000000000000";

pub(crate) const LINUX_GATES: [&str; 22] = [
    "runner-identity",
    "candidate-checkout",
    "oracle-checkout",
    "conformance-policy",
    "conformance-plan-binding",
    "case-catalog",
    "normalizer-catalog",
    "divergence-catalog",
    "verify",
    "format",
    "clippy",
    "workspace-tests",
    "documentation",
    "dependency-policy",
    "release-examples",
    "release-mutation-catalog",
    "linux-release-oracle-digest",
    "conformance-evidence",
    "divergence-prototypes",
    "release-build",
    "archive-verification",
    "package-smoke",
];

pub(crate) const NATIVE_GATES: [&str; 12] = [
    "runner-identity",
    "candidate-checkout",
    "oracle-checkout",
    "conformance-plan-binding",
    "portability",
    "workspace-tests",
    "release-build",
    "native-oracle-build",
    "conformance-evidence",
    "divergence-prototypes",
    "archive-verification",
    "package-smoke",
];

pub(crate) fn expected_gates(platform: ReleasePlatform) -> &'static [&'static str] {
    if platform == ReleasePlatform::LinuxX86_64 {
        &LINUX_GATES
    } else {
        &NATIVE_GATES
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ReleasePlatform {
    LinuxX86_64,
    MacosAarch64,
    WindowsX86_64,
}

impl ReleasePlatform {
    pub(crate) fn parse(value: &str) -> Result<Self, String> {
        match value {
            "linux-x86_64" => Ok(Self::LinuxX86_64),
            "macos-aarch64" => Ok(Self::MacosAarch64),
            "windows-x86_64" => Ok(Self::WindowsX86_64),
            _ => Err(format!("unsupported release platform {value:?}")),
        }
    }

    pub(crate) const fn id(self) -> &'static str {
        match self {
            Self::LinuxX86_64 => "linux-x86_64",
            Self::MacosAarch64 => "macos-aarch64",
            Self::WindowsX86_64 => "windows-x86_64",
        }
    }

    pub(crate) const fn runner(self) -> (&'static str, &'static str) {
        match self {
            Self::LinuxX86_64 => ("Linux", "X64"),
            Self::MacosAarch64 => ("macOS", "ARM64"),
            Self::WindowsX86_64 => ("Windows", "X64"),
        }
    }

    pub(crate) const fn executable(self) -> &'static str {
        match self {
            Self::WindowsX86_64 => "hell.exe",
            Self::LinuxX86_64 | Self::MacosAarch64 => "hell",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Resolution {
    pub repository: String,
    pub repository_id: u64,
    pub default_branch: String,
    pub candidate_branch: String,
    pub candidate_sha: String,
    pub actor: String,
    pub actor_id: u64,
    pub run_id: u64,
    pub run_attempt: u64,
    pub workflow_ref: String,
    pub workflow_sha: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReleasePlan {
    pub resolution: Resolution,
    pub version: String,
    pub tag: String,
    pub prerelease: bool,
    pub source_date_epoch: u64,
    pub release_evaluation_instant: String,
    pub source_inventory_sha256: String,
    pub build_inputs_sha256: String,
    pub policy_sha256: String,
    pub governance_declaration_sha256: String,
    pub governance_profile_sha256: String,
    pub residual_assumption_set_sha256: String,
    pub external_inputs_sha256: String,
    pub trusted_conformance_inputs_sha256: String,
    pub conformance_plan_sha256: String,
    pub conformance_standard: String,
    pub changelog_sha256: String,
    pub commit_author: String,
    pub commit_committer: String,
    pub plan_sha256: String,
}

impl Resolution {
    pub(crate) fn json(&self) -> JsonValue {
        object([
            ("actor", string(&self.actor)),
            ("actorId", number(self.actor_id)),
            ("candidateBranch", string(&self.candidate_branch)),
            ("candidateSha", string(&self.candidate_sha)),
            ("defaultBranch", string(&self.default_branch)),
            ("event", string("workflow_dispatch")),
            ("repository", string(&self.repository)),
            ("repositoryId", number(self.repository_id)),
            ("runAttempt", number(self.run_attempt)),
            ("runId", number(self.run_id)),
            ("schemaVersion", number(1)),
            ("workflowRef", string(&self.workflow_ref)),
            ("workflowSha", string(&self.workflow_sha)),
        ])
    }

    pub(crate) fn parse(value: &JsonValue) -> Result<Self, String> {
        let object = value.object()?;
        require_exact_json_keys(
            object,
            &[
                "actor",
                "actorId",
                "candidateBranch",
                "candidateSha",
                "defaultBranch",
                "event",
                "repository",
                "repositoryId",
                "runAttempt",
                "runId",
                "schemaVersion",
                "workflowRef",
                "workflowSha",
            ],
        )?;
        if json_member(object, "schemaVersion")?.number()? != 1
            || json_member(object, "event")?.string()? != "workflow_dispatch"
        {
            return Err("unsupported release resolution schema or event".to_owned());
        }
        let resolution = Self {
            repository: text(object, "repository")?,
            repository_id: json_member(object, "repositoryId")?.number()?,
            default_branch: text(object, "defaultBranch")?,
            candidate_branch: text(object, "candidateBranch")?,
            candidate_sha: text(object, "candidateSha")?,
            actor: text(object, "actor")?,
            actor_id: json_member(object, "actorId")?.number()?,
            run_id: json_member(object, "runId")?.number()?,
            run_attempt: json_member(object, "runAttempt")?.number()?,
            workflow_ref: text(object, "workflowRef")?,
            workflow_sha: text(object, "workflowSha")?,
        };
        require_sha(&resolution.candidate_sha, "candidate SHA")?;
        require_sha(&resolution.workflow_sha, "workflow SHA")?;
        Ok(resolution)
    }
}

impl ReleasePlan {
    pub(crate) fn json_without_digest(&self) -> JsonValue {
        object([
            ("actor", string(&self.resolution.actor)),
            ("actorId", number(self.resolution.actor_id)),
            ("buildInputsSha256", string(&self.build_inputs_sha256)),
            ("candidateBranch", string(&self.resolution.candidate_branch)),
            ("candidateSha", string(&self.resolution.candidate_sha)),
            ("changelogSha256", string(&self.changelog_sha256)),
            ("commitAuthor", string(&self.commit_author)),
            ("commitCommitter", string(&self.commit_committer)),
            (
                "conformancePlanSha256",
                string(&self.conformance_plan_sha256),
            ),
            ("conformanceStandard", string(&self.conformance_standard)),
            ("defaultBranch", string(&self.resolution.default_branch)),
            ("externalInputsSha256", string(&self.external_inputs_sha256)),
            (
                "expectedPlatforms",
                JsonValue::Array(
                    PLATFORMS
                        .iter()
                        .map(|platform| string(platform.id()))
                        .collect(),
                ),
            ),
            ("policySha256", string(&self.policy_sha256)),
            (
                "governanceDeclarationSha256",
                string(&self.governance_declaration_sha256),
            ),
            (
                "governanceProfileSha256",
                string(&self.governance_profile_sha256),
            ),
            ("releaseBinary", string("hell")),
            ("releasePackage", string("hell-cli")),
            ("prerelease", JsonValue::Bool(self.prerelease)),
            ("repository", string(&self.resolution.repository)),
            ("repositoryId", number(self.resolution.repository_id)),
            (
                "residualAssumptionSetSha256",
                string(&self.residual_assumption_set_sha256),
            ),
            ("runAttempt", number(self.resolution.run_attempt)),
            ("runId", number(self.resolution.run_id)),
            (
                "releaseEvaluationInstant",
                string(&self.release_evaluation_instant),
            ),
            ("schemaVersion", number(2)),
            ("sourceDateEpoch", number(self.source_date_epoch)),
            (
                "sourceInventorySha256",
                string(&self.source_inventory_sha256),
            ),
            ("tag", string(&self.tag)),
            (
                "trustedConformanceInputsSha256",
                string(&self.trusted_conformance_inputs_sha256),
            ),
            ("version", string(&self.version)),
            ("workflowRef", string(&self.resolution.workflow_ref)),
            ("workflowSha", string(&self.resolution.workflow_sha)),
        ])
    }

    pub(crate) fn json(&self) -> JsonValue {
        let mut object = self.json_without_digest().object().expect("object").clone();
        object.insert("planSha256".to_owned(), string(&self.plan_sha256));
        JsonValue::Object(object)
    }

    pub(crate) fn parse(value: &JsonValue) -> Result<Self, String> {
        let object = value.object()?;
        validate_release_plan_json_shape(object)?;
        let mut plan = Self {
            resolution: Resolution {
                repository: text(object, "repository")?,
                repository_id: json_member(object, "repositoryId")?.number()?,
                default_branch: text(object, "defaultBranch")?,
                candidate_branch: text(object, "candidateBranch")?,
                candidate_sha: text(object, "candidateSha")?,
                actor: text(object, "actor")?,
                actor_id: json_member(object, "actorId")?.number()?,
                run_id: json_member(object, "runId")?.number()?,
                run_attempt: json_member(object, "runAttempt")?.number()?,
                workflow_ref: text(object, "workflowRef")?,
                workflow_sha: text(object, "workflowSha")?,
            },
            version: text(object, "version")?,
            tag: text(object, "tag")?,
            prerelease: json_member(object, "prerelease")?.boolean()?,
            source_date_epoch: json_member(object, "sourceDateEpoch")?.number()?,
            release_evaluation_instant: text(object, "releaseEvaluationInstant")?,
            source_inventory_sha256: text(object, "sourceInventorySha256")?,
            build_inputs_sha256: text(object, "buildInputsSha256")?,
            policy_sha256: text(object, "policySha256")?,
            governance_declaration_sha256: text(object, "governanceDeclarationSha256")?,
            governance_profile_sha256: text(object, "governanceProfileSha256")?,
            residual_assumption_set_sha256: text(object, "residualAssumptionSetSha256")?,
            external_inputs_sha256: text(object, "externalInputsSha256")?,
            trusted_conformance_inputs_sha256: text(object, "trustedConformanceInputsSha256")?,
            conformance_plan_sha256: text(object, "conformancePlanSha256")?,
            conformance_standard: text(object, "conformanceStandard")?,
            changelog_sha256: text(object, "changelogSha256")?,
            commit_author: text(object, "commitAuthor")?,
            commit_committer: text(object, "commitCommitter")?,
            plan_sha256: text(object, "planSha256")?,
        };
        validate_parsed_release_plan(&mut plan)?;
        Ok(plan)
    }
}

fn validate_release_plan_json_shape(
    object: &std::collections::BTreeMap<String, JsonValue>,
) -> Result<(), String> {
    require_exact_json_keys(
        object,
        &[
            "actor",
            "actorId",
            "buildInputsSha256",
            "candidateBranch",
            "candidateSha",
            "changelogSha256",
            "commitAuthor",
            "commitCommitter",
            "conformancePlanSha256",
            "conformanceStandard",
            "defaultBranch",
            "externalInputsSha256",
            "expectedPlatforms",
            "governanceDeclarationSha256",
            "governanceProfileSha256",
            "planSha256",
            "policySha256",
            "releaseBinary",
            "releasePackage",
            "prerelease",
            "releaseEvaluationInstant",
            "repository",
            "repositoryId",
            "residualAssumptionSetSha256",
            "runAttempt",
            "runId",
            "schemaVersion",
            "sourceDateEpoch",
            "sourceInventorySha256",
            "tag",
            "trustedConformanceInputsSha256",
            "version",
            "workflowRef",
            "workflowSha",
        ],
    )?;
    if json_member(object, "schemaVersion")?.number()? != 2 {
        return Err("unsupported release plan schema".to_owned());
    }
    if json_member(object, "releaseBinary")?.string()? != "hell"
        || json_member(object, "releasePackage")?.string()? != "hell-cli"
    {
        return Err("release plan package identity differs".to_owned());
    }
    let platforms = json_member(object, "expectedPlatforms")?.array()?;
    if platforms.len() != PLATFORMS.len()
        || !platforms
            .iter()
            .zip(PLATFORMS)
            .all(|(value, platform)| value.string() == Ok(platform.id()))
    {
        return Err("release plan platform set differs from policy".to_owned());
    }
    Ok(())
}

fn validate_parsed_release_plan(plan: &mut ReleasePlan) -> Result<(), String> {
    require_sha(&plan.resolution.candidate_sha, "candidate SHA")?;
    require_sha(&plan.resolution.workflow_sha, "workflow SHA")?;
    crate::conformance::validate_utc_instant(&plan.release_evaluation_instant)?;
    for (value, label) in [
        (&plan.source_inventory_sha256, "source inventory digest"),
        (&plan.build_inputs_sha256, "build inputs digest"),
        (&plan.policy_sha256, "policy digest"),
        (
            &plan.governance_declaration_sha256,
            "governance declaration digest",
        ),
        (&plan.governance_profile_sha256, "governance profile digest"),
        (
            &plan.residual_assumption_set_sha256,
            "residual assumption set digest",
        ),
        (&plan.external_inputs_sha256, "external-input lock digest"),
        (
            &plan.trusted_conformance_inputs_sha256,
            "trusted conformance inputs digest",
        ),
        (&plan.conformance_plan_sha256, "conformance plan digest"),
        (&plan.changelog_sha256, "changelog digest"),
        (&plan.plan_sha256, "plan digest"),
    ] {
        require_digest(value, label)?;
    }
    if plan.conformance_standard != crate::conformance::RELEASE_STANDARD {
        return Err("release plan conformance standard differs".to_owned());
    }
    let stated = std::mem::take(&mut plan.plan_sha256);
    let observed =
        hell_testkit::sha256_bytes(&canonical_json_bytes(&plan.json_without_digest())?).hex();
    plan.plan_sha256 = stated;
    if observed != plan.plan_sha256 {
        return Err("release plan self-digest mismatch".to_owned());
    }
    Ok(())
}

pub(crate) fn object<const N: usize>(fields: [(&str, JsonValue); N]) -> JsonValue {
    JsonValue::Object(
        fields
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}

pub(crate) fn string(value: &str) -> JsonValue {
    JsonValue::String(value.to_owned())
}
pub(crate) const fn number(value: u64) -> JsonValue {
    JsonValue::Number(value)
}

pub(crate) fn text(object: &BTreeMap<String, JsonValue>, key: &str) -> Result<String, String> {
    Ok(json_member(object, key)?.string()?.to_owned())
}

pub(crate) fn require_sha(value: &str, label: &str) -> Result<(), String> {
    if value.len() != FULL_GIT_SHA_SHAPE.len()
        || value.bytes().all(|byte| byte == b'0')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(format!("{label} is not a lowercase full Git SHA"));
    }
    Ok(())
}

pub(crate) fn require_digest(value: &str, label: &str) -> Result<(), String> {
    if value.bytes().all(|byte| byte == b'0') {
        return Err(format!("{label} is an all-zero digest"));
    }
    hell_testkit::Digest::from_hex(value)
        .map(|_| ())
        .map_err(|error| format!("{label}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_ids_are_exact() {
        assert!(ReleasePlatform::parse("linux-x86_64").is_ok());
        assert!(ReleasePlatform::parse("linux-amd64").is_err());
    }

    #[test]
    fn full_sha_parser_rejects_abbreviated_and_zero_values() {
        assert!(require_sha(&"a".repeat(FULL_GIT_SHA_SHAPE.len()), "sha").is_ok());
        assert!(require_sha("abc", "sha").is_err());
        assert!(require_sha(&"0".repeat(FULL_GIT_SHA_SHAPE.len()), "sha").is_err());
        assert!(require_sha("ａ", "sha").is_err());
    }
}
