//! Strict, digest-bound promotion policy and human review records.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use hell_builtins::{CompatibilityDimension, ExecutionProfile};
use hell_testkit::{Digest, sha256_bytes};

use crate::strict_toml;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum RequiredPlatform {
    LinuxAmd64,
    MacOsArm64,
    WindowsAmd64,
}

impl RequiredPlatform {
    pub(crate) const ALL: [Self; 3] = [Self::LinuxAmd64, Self::MacOsArm64, Self::WindowsAmd64];

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::LinuxAmd64 => "linux-amd64",
            Self::MacOsArm64 => "macos-arm64",
            Self::WindowsAmd64 => "windows-amd64",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PromotionPolicy {
    pub(crate) sha256: Digest,
    pub(crate) required_profiles: Vec<ExecutionProfile>,
    pub(crate) required_platforms: Vec<RequiredPlatform>,
    pub(crate) required_dimensions: Vec<CompatibilityDimension>,
    pub(crate) minimum_generated_observations: usize,
    pub(crate) require_committed_observations: bool,
    pub(crate) allow_generated_claim_references: bool,
}

pub(crate) fn load(root: &Path) -> Result<PromotionPolicy, String> {
    let path = root.join("compat/promotion-policy.toml");
    let bytes =
        fs::read(&path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let sha256 = sha256_bytes(&bytes);
    if sha256.hex() != hell_builtins::PROMOTION_POLICY_SHA256 {
        return Err(format!(
            "{} digest is {}, but builtins bind {}",
            path.display(),
            sha256.hex(),
            hell_builtins::PROMOTION_POLICY_SHA256
        ));
    }
    parse_policy(&bytes, sha256)
}

fn parse_policy(bytes: &[u8], sha256: Digest) -> Result<PromotionPolicy, String> {
    let document =
        std::str::from_utf8(bytes).map_err(|_| "promotion policy is not UTF-8".to_owned())?;
    let mut values = strict_toml::assignments(document)?;
    require_unsigned(&mut values, "schema_version", 1)?;
    require_string(&mut values, "baseline", hell_builtins::LANGUAGE_VERSION)?;
    let required_profiles = take_array(&mut values, "required_profiles")?
        .into_iter()
        .map(|value| match value.as_str() {
            "upstream" => Ok(ExecutionProfile::Upstream),
            "sandboxed" => Ok(ExecutionProfile::Sandboxed),
            _ => Err(format!("unknown required execution profile {value:?}")),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let required_platforms = take_array(&mut values, "required_platforms")?
        .into_iter()
        .map(|value| match value.as_str() {
            "linux-amd64" => Ok(RequiredPlatform::LinuxAmd64),
            "macos-arm64" => Ok(RequiredPlatform::MacOsArm64),
            "windows-amd64" => Ok(RequiredPlatform::WindowsAmd64),
            _ => Err(format!("unknown required platform {value:?}")),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let required_dimensions = take_array(&mut values, "required_dimensions")?
        .into_iter()
        .map(|value| {
            CompatibilityDimension::ALL
                .into_iter()
                .find(|dimension| dimension.as_str() == value)
                .ok_or_else(|| format!("unknown required compatibility dimension {value:?}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let minimum_generated_observations = usize::try_from(strict_toml::unsigned(
        &strict_toml::take(&mut values, "minimum_generated_observations")?,
    )?)
    .map_err(|_| "minimum generated observation count is out of range".to_owned())?;
    let require_committed_observations = strict_toml::boolean(&strict_toml::take(
        &mut values,
        "require_committed_observations",
    )?)?;
    let allow_generated_claim_references = strict_toml::boolean(&strict_toml::take(
        &mut values,
        "allow_generated_claim_references",
    )?)?;
    strict_toml::finish(&values)?;
    if required_profiles != [ExecutionProfile::Upstream] {
        return Err(
            "the initial promotion policy must require only the upstream profile".to_owned(),
        );
    }
    if required_platforms != RequiredPlatform::ALL {
        return Err("promotion policy must require all three reviewed native platforms".to_owned());
    }
    if required_dimensions != CompatibilityDimension::ALL {
        return Err(
            "promotion policy must require all compatibility dimensions in order".to_owned(),
        );
    }
    if minimum_generated_observations < 1_024
        || !require_committed_observations
        || allow_generated_claim_references
    {
        return Err("promotion policy weakens the reviewed corpus requirements".to_owned());
    }
    Ok(PromotionPolicy {
        sha256,
        required_profiles,
        required_platforms,
        required_dimensions,
        minimum_generated_observations,
        require_committed_observations,
        allow_generated_claim_references,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReviewState {
    Pending,
    Accepted,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PromotionReview {
    pub(crate) state: ReviewState,
    pub(crate) sha256: Digest,
    pub(crate) inner_digests: BTreeMap<String, String>,
    pub(crate) acceptance: BTreeMap<String, bool>,
}

pub(crate) fn load_review(root: &Path) -> Result<PromotionReview, String> {
    let path = root.join("compat/promotion-review.toml");
    let bytes =
        fs::read(&path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    parse_review(&bytes)
}

#[allow(clippy::too_many_lines)]
fn parse_review(bytes: &[u8]) -> Result<PromotionReview, String> {
    let document = std::str::from_utf8(bytes)
        .map_err(|_| "promotion review record is not UTF-8".to_owned())?;
    let mut values = strict_toml::assignments(document)?;
    require_unsigned(&mut values, "schema_version", 1)?;
    require_string(&mut values, "baseline", hell_builtins::LANGUAGE_VERSION)?;
    require_string(&mut values, "required_profile", "upstream")?;
    let state = match strict_toml::string(&strict_toml::take(&mut values, "state")?)?.as_str() {
        "pending" => ReviewState::Pending,
        "accepted" => ReviewState::Accepted,
        value => return Err(format!("unknown promotion review state {value:?}")),
    };
    let review_issue = strict_toml::string(&strict_toml::take(&mut values, "review_issue")?)?;
    if review_issue.is_empty() {
        return Err("promotion review issue is empty".to_owned());
    }
    let review_commit = strict_toml::string(&strict_toml::take(&mut values, "review_commit")?)?;
    match state {
        ReviewState::Pending if review_commit != "REVIEW_REQUIRED" => {
            return Err("pending review commit must remain REVIEW_REQUIRED".to_owned());
        }
        ReviewState::Accepted => require_git_sha(&review_commit, "promotion review commit")?,
        ReviewState::Pending => {}
    }
    let run_id = strict_toml::unsigned(&strict_toml::take(&mut values, "bootstrap_run_id")?)?;
    let run_attempt =
        strict_toml::unsigned(&strict_toml::take(&mut values, "bootstrap_run_attempt")?)?;
    if run_id == 0 || run_attempt == 0 {
        return Err("promotion bootstrap run identity must be nonzero".to_owned());
    }
    let bootstrap_commit = strict_toml::string(&strict_toml::take(
        &mut values,
        "bootstrap_candidate_commit",
    )?)?;
    require_git_sha(&bootstrap_commit, "bootstrap candidate commit")?;
    for platform in ["linux", "macos", "windows", "merged"] {
        let name = strict_toml::string(&strict_toml::take(
            &mut values,
            &format!("bootstrap_artifacts.{platform}_name"),
        )?)?;
        if name.is_empty() {
            return Err(format!("bootstrap {platform} artifact name is empty"));
        }
        let digest = strict_toml::string(&strict_toml::take(
            &mut values,
            &format!("bootstrap_artifacts.{platform}_outer_sha256"),
        )?)?;
        require_digest(&digest, &format!("bootstrap {platform} outer digest"))?;
    }
    let inner_keys = [
        "compatibility_snapshot_sha256",
        "promotion_policy_sha256",
        "reviewed_corpus_catalog_sha256",
        "linux_claim_index_sha256",
        "macos_claim_index_sha256",
        "windows_claim_index_sha256",
        "merged_manifest_sha256",
        "macos_build_record_sha256",
        "macos_oracle_binary_sha256",
        "windows_build_record_sha256",
        "windows_oracle_binary_sha256",
    ];
    let mut inner_digests = BTreeMap::new();
    for key in inner_keys {
        let value = strict_toml::string(&strict_toml::take(
            &mut values,
            &format!("reviewed_inner_evidence.{key}"),
        )?)?;
        if state == ReviewState::Accepted {
            require_digest(&value, key)?;
        } else if value != "REVIEW_REQUIRED" {
            return Err(format!(
                "pending review field {key} must remain REVIEW_REQUIRED"
            ));
        }
        inner_digests.insert(key.to_owned(), value);
    }
    let acceptance_keys = [
        "claims_reviewed",
        "normalizers_reviewed",
        "macos_provenance_reviewed",
        "windows_provenance_reviewed",
        "durable_copy_completed",
        "fresh_collection_required",
        "explicit_promotion_passed",
    ];
    let mut acceptance = BTreeMap::new();
    for key in acceptance_keys {
        let value = strict_toml::boolean(&strict_toml::take(
            &mut values,
            &format!("acceptance.{key}"),
        )?)?;
        acceptance.insert(key.to_owned(), value);
    }
    strict_toml::finish(&values)?;
    if state == ReviewState::Pending
        && (acceptance
            .iter()
            .any(|(key, value)| key != "fresh_collection_required" && *value)
            || acceptance.get("fresh_collection_required") != Some(&true))
    {
        return Err("pending promotion review contains accepted decisions".to_owned());
    }
    Ok(PromotionReview {
        state,
        sha256: sha256_bytes(bytes),
        inner_digests,
        acceptance,
    })
}

impl PromotionReview {
    pub(crate) fn require_accepted(&self) -> Result<(), String> {
        if self.state != ReviewState::Accepted {
            return Err("promotion review record is still pending".to_owned());
        }
        for key in [
            "claims_reviewed",
            "normalizers_reviewed",
            "macos_provenance_reviewed",
            "windows_provenance_reviewed",
            "durable_copy_completed",
        ] {
            if self.acceptance.get(key) != Some(&true) {
                return Err(format!("promotion review acceptance {key} is false"));
            }
        }
        if self.acceptance.get("fresh_collection_required") != Some(&true)
            || self.acceptance.get("explicit_promotion_passed") != Some(&false)
        {
            return Err(
                "pre-gate review must require fresh collection and must not claim a gate pass"
                    .to_owned(),
            );
        }
        Ok(())
    }
}

fn take_array(values: &mut BTreeMap<String, String>, key: &str) -> Result<Vec<String>, String> {
    let values = strict_toml::string_array(&strict_toml::take(values, key)?)?;
    if values.is_empty() {
        return Err(format!("{key} must not be empty"));
    }
    if values
        .iter()
        .enumerate()
        .any(|(index, value)| values[..index].contains(value))
    {
        return Err(format!("{key} contains a duplicate value"));
    }
    Ok(values)
}

fn require_string(
    values: &mut BTreeMap<String, String>,
    key: &str,
    expected: &str,
) -> Result<(), String> {
    let observed = strict_toml::string(&strict_toml::take(values, key)?)?;
    (observed == expected)
        .then_some(())
        .ok_or_else(|| format!("{key} must be {expected:?}, observed {observed:?}"))
}

fn require_unsigned(
    values: &mut BTreeMap<String, String>,
    key: &str,
    expected: u64,
) -> Result<(), String> {
    let observed = strict_toml::unsigned(&strict_toml::take(values, key)?)?;
    (observed == expected)
        .then_some(())
        .ok_or_else(|| format!("{key} must be {expected}, observed {observed}"))
}

pub(crate) fn require_digest(value: &str, label: &str) -> Result<(), String> {
    if value.len() != sha256_bytes(&[]).hex().len()
        || !value.bytes().any(|byte| byte != b'0')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(format!("{label} is not a lowercase SHA-256 digest"));
    }
    Ok(())
}

pub(crate) fn require_git_sha(value: &str, label: &str) -> Result<(), String> {
    if value.len() != hell_builtins::UPSTREAM_COMMIT.len()
        || !value.bytes().any(|byte| byte != b'0')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(format!("{label} is not a lowercase full Git SHA"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
    }

    #[test]
    fn committed_policy_and_pending_review_validate_without_promoting() {
        let root = root();
        let policy = load(&root).expect("strict committed policy");
        assert_eq!(policy.required_profiles, [ExecutionProfile::Upstream]);
        assert_eq!(policy.required_platforms, RequiredPlatform::ALL);
        assert_eq!(policy.required_dimensions, CompatibilityDimension::ALL);
        assert!(policy.require_committed_observations);
        assert!(!policy.allow_generated_claim_references);

        let review = load_review(&root).expect("strict pending review");
        assert_eq!(review.state, ReviewState::Pending);
        assert!(review.require_accepted().is_err());
    }

    #[test]
    fn policy_rejects_duplicates_unknown_keys_and_weaker_corpus_rules() {
        let bytes = fs::read(root().join("compat/promotion-policy.toml")).unwrap();
        let document = String::from_utf8(bytes).unwrap();
        let digest = sha256_bytes(document.as_bytes());
        for invalid in [
            document.replace(
                "required_profiles = [\"upstream\"]",
                "required_profiles = [\"upstream\", \"upstream\"]",
            ),
            document.replace(
                "minimum_generated_observations = 1024",
                "minimum_generated_observations = 1",
            ),
            format!("{document}unknown_policy_key = true\n"),
        ] {
            assert!(parse_policy(invalid.as_bytes(), digest).is_err());
        }
    }

    #[test]
    fn review_rejects_placeholders_in_accepted_state_and_circular_pass_claims() {
        let bytes = fs::read(root().join("compat/promotion-review.toml")).unwrap();
        let pending = String::from_utf8(bytes).unwrap();
        let accepted_with_placeholders =
            pending.replace("state = \"pending\"", "state = \"accepted\"");
        assert!(parse_review(accepted_with_placeholders.as_bytes()).is_err());

        let review = PromotionReview {
            state: ReviewState::Accepted,
            sha256: Digest::default(),
            inner_digests: BTreeMap::new(),
            acceptance: [
                ("claims_reviewed", true),
                ("normalizers_reviewed", true),
                ("macos_provenance_reviewed", true),
                ("windows_provenance_reviewed", true),
                ("durable_copy_completed", true),
                ("fresh_collection_required", true),
                ("explicit_promotion_passed", false),
            ]
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
        };
        assert!(review.require_accepted().is_ok());
        let mut circular = review;
        circular
            .acceptance
            .insert("explicit_promotion_passed".to_owned(), true);
        assert!(circular.require_accepted().is_err());
        assert!(require_digest(&"0".repeat(sha256_bytes(&[]).hex().len()), "digest").is_err());
        assert!(
            require_git_sha(&"0".repeat(hell_builtins::UPSTREAM_COMMIT.len()), "commit").is_err()
        );
    }
}
