//! Strict reviewed native-oracle records and shard provenance binding.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use hell_testkit::{sha256_bytes, sha256_file};

use crate::promotion_policy::{RequiredPlatform, require_digest, require_git_sha};
use crate::strict_toml;

const SOURCE_COMMIT: &str = "8e952cf9de4ab25d7716982a9ca234f9bdcf1bff";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Availability {
    Available,
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OracleKind {
    ReleaseAsset,
    SourceBuild,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReviewedOracleRecord {
    pub(crate) platform: RequiredPlatform,
    pub(crate) availability: Availability,
    pub(crate) kind: OracleKind,
    fields: BTreeMap<String, String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PlatformEvidenceState {
    pub(crate) required: usize,
    pub(crate) available_and_matched: usize,
    pub(crate) unavailable: usize,
    pub(crate) invalid_records: usize,
    pub(crate) provenance_mismatches: usize,
}

impl PlatformEvidenceState {
    pub(crate) fn complete(self) -> bool {
        self.available_and_matched == self.required
            && self.unavailable == 0
            && self.invalid_records == 0
            && self.provenance_mismatches == 0
    }
}

pub(crate) fn load_all(root: &Path) -> Result<Vec<ReviewedOracleRecord>, String> {
    RequiredPlatform::ALL
        .into_iter()
        .map(|platform| load(root, platform))
        .collect()
}

pub(crate) fn load(
    root: &Path,
    expected_platform: RequiredPlatform,
) -> Result<ReviewedOracleRecord, String> {
    let path = root
        .join("crates/hell-ci/oracle")
        .join(format!("{}.toml", expected_platform.as_str()));
    let document = fs::read_to_string(&path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    parse(&document, expected_platform)
        .map_err(|error| format!("invalid reviewed oracle record {}: {error}", path.display()))
}

#[allow(clippy::too_many_lines)]
fn parse(
    document: &str,
    expected_platform: RequiredPlatform,
) -> Result<ReviewedOracleRecord, String> {
    let mut values = strict_toml::assignments(document)?;
    require_unsigned(&mut values, "schema_version", 2)?;
    require_string(&mut values, "role", "upstream-oracle")?;
    require_string(&mut values, "platform", expected_platform.as_str())?;
    require_string(
        &mut values,
        "reported_version",
        hell_builtins::LANGUAGE_VERSION,
    )?;
    require_string(
        &mut values,
        "upstream_repository",
        "https://github.com/chrisdone/hell",
    )?;
    require_string(&mut values, "source_commit", SOURCE_COMMIT)?;
    require_string(
        &mut values,
        "compatibility_baseline_commit",
        hell_builtins::UPSTREAM_COMMIT,
    )?;
    let availability = match take_string(&mut values, "availability")?.as_str() {
        "available" => Availability::Available,
        "unavailable" => Availability::Unavailable,
        value => return Err(format!("unknown oracle availability {value:?}")),
    };
    let kind = match take_string(&mut values, "oracle_kind")?.as_str() {
        "release-asset" => OracleKind::ReleaseAsset,
        "source-build" => OracleKind::SourceBuild,
        value => return Err(format!("unknown oracle kind {value:?}")),
    };
    let mut fields = BTreeMap::new();
    match (availability, kind) {
        (Availability::Unavailable, _) => {
            let reason = take_string(&mut values, "reason")?;
            if reason.is_empty() {
                return Err("unavailable oracle record has an empty reason".to_owned());
            }
            fields.insert("reason".to_owned(), reason);
        }
        (Availability::Available, OracleKind::ReleaseAsset) => {
            require_string(&mut values, "review_state", "accepted")?;
            for key in [
                "release_tag",
                "release_url",
                "asset_url",
                "dependency_snapshot",
                "nixpkgs_revision",
                "flake_utils_revision",
            ] {
                let value = take_string(&mut values, key)?;
                if value.is_empty() {
                    return Err(format!("available release record has empty {key}"));
                }
                fields.insert(key.to_owned(), value);
            }
            let digest = take_string(&mut values, "asset_sha256")?;
            require_digest(&digest, "release asset digest")?;
            fields.insert("asset_sha256".to_owned(), digest);
        }
        (Availability::Available, OracleKind::SourceBuild) => {
            require_string(&mut values, "review_state", "accepted")?;
            for key in ["review_run_id", "review_run_attempt"] {
                let value = strict_toml::unsigned(&strict_toml::take(&mut values, key)?)?;
                if value == 0 {
                    return Err(format!("available source-build record has zero {key}"));
                }
                fields.insert(key.to_owned(), value.to_string());
            }
            for key in ["review_artifact_name", "review_issue"] {
                let value = take_string(&mut values, key)?;
                if value.is_empty() {
                    return Err(format!("available source-build record has empty {key}"));
                }
                fields.insert(key.to_owned(), value);
            }
            for key in [
                "review_artifact_sha256",
                "build_record_sha256",
                "platform_identity_sha256",
                "source_tree_stdout_sha256",
                "resolver_sha256",
                "stack_stdout_sha256",
                "compiler_stdout_sha256",
                "dependency_stdout_sha256",
                "build_stdout_sha256",
                "build_stderr_sha256",
                "oracle_binary_sha256",
            ] {
                let value = take_string(&mut values, key)?;
                require_digest(&value, key)?;
                fields.insert(key.to_owned(), value);
            }
            let review_commit = take_string(&mut values, "review_commit")?;
            require_git_sha(&review_commit, "oracle review commit")?;
            fields.insert("review_commit".to_owned(), review_commit);
        }
    }
    strict_toml::finish(&values)?;
    Ok(ReviewedOracleRecord {
        platform: expected_platform,
        availability,
        kind,
        fields,
    })
}

pub(crate) fn state_without_shards(records: &[ReviewedOracleRecord]) -> PlatformEvidenceState {
    PlatformEvidenceState {
        required: RequiredPlatform::ALL.len(),
        available_and_matched: 0,
        unavailable: records
            .iter()
            .filter(|record| record.availability == Availability::Unavailable)
            .count(),
        invalid_records: 0,
        provenance_mismatches: 0,
    }
}

pub(crate) fn validate_against_shards(
    records: &[ReviewedOracleRecord],
    input: &Path,
) -> PlatformEvidenceState {
    let mut state = PlatformEvidenceState {
        required: RequiredPlatform::ALL.len(),
        ..PlatformEvidenceState::default()
    };
    for record in records {
        if record.availability == Availability::Unavailable {
            state.unavailable = state.unavailable.saturating_add(1);
            continue;
        }
        let directory = input.join(record.platform.as_str());
        if validate_against_shard(record, &directory).is_ok() {
            state.available_and_matched = state.available_and_matched.saturating_add(1);
        } else {
            state.provenance_mismatches = state.provenance_mismatches.saturating_add(1);
        }
    }
    state
}

pub(crate) fn validate_against_shard(
    record: &ReviewedOracleRecord,
    directory: &Path,
) -> Result<(), String> {
    match record.kind {
        OracleKind::ReleaseAsset => {
            let summary = read(&directory.join("summary.json"))?;
            let observed = json_string_field(&summary, "oracleSha256")
                .ok_or_else(|| "Linux shard summary lacks oracleSha256".to_owned())?;
            require_equal(record, "asset_sha256", observed)
        }
        OracleKind::SourceBuild => {
            let platform = record.platform.as_str();
            let build_path = directory.join(format!("oracle-build-{platform}.json"));
            let build = read(&build_path)?;
            let build_digest = sha256_bytes(build.as_bytes()).hex();
            require_equal(record, "build_record_sha256", &build_digest)?;
            for (record_key, build_key) in [
                ("platform_identity_sha256", "platformIdentitySha256"),
                (
                    "source_tree_stdout_sha256",
                    "sourceTreeStdoutRetainedSha256",
                ),
                ("resolver_sha256", "resolverSha256"),
                ("stack_stdout_sha256", "stackStdoutRetainedSha256"),
                ("compiler_stdout_sha256", "compilerStdoutRetainedSha256"),
                ("dependency_stdout_sha256", "dependencyStdoutRetainedSha256"),
                ("build_stdout_sha256", "buildStdoutRetainedSha256"),
                ("build_stderr_sha256", "buildStderrRetainedSha256"),
                ("oracle_binary_sha256", "binarySha256"),
            ] {
                let observed = json_string_field(&build, build_key)
                    .ok_or_else(|| format!("native build record lacks {build_key}"))?;
                require_equal(record, record_key, observed)?;
            }
            let executable = if record.platform == RequiredPlatform::WindowsAmd64 {
                "hell.exe"
            } else {
                "hell"
            };
            let binary = directory.join("oracle").join(platform).join(executable);
            let observed = sha256_file(&binary)
                .map_err(|error| format!("cannot hash {}: {error}", binary.display()))?
                .hex();
            require_equal(record, "oracle_binary_sha256", &observed)
        }
    }
}

fn require_equal(record: &ReviewedOracleRecord, key: &str, observed: &str) -> Result<(), String> {
    let expected = record
        .fields
        .get(key)
        .ok_or_else(|| format!("reviewed oracle record lacks {key}"))?;
    (expected == observed)
        .then_some(())
        .ok_or_else(|| format!("reviewed oracle {key} mismatch: {expected} != {observed}"))
}

fn read(path: &Path) -> Result<String, String> {
    fs::read_to_string(path).map_err(|error| format!("cannot read {}: {error}", path.display()))
}

fn json_string_field<'a>(document: &'a str, field: &str) -> Option<&'a str> {
    let prefix = format!("\"{field}\": \"");
    let mut values = document.lines().filter_map(|line| {
        line.trim()
            .strip_prefix(&prefix)
            .and_then(|value| value.strip_suffix(',').unwrap_or(value).strip_suffix('"'))
    });
    let value = values.next()?;
    values.next().is_none().then_some(value)
}

fn take_string(values: &mut BTreeMap<String, String>, key: &str) -> Result<String, String> {
    strict_toml::string(&strict_toml::take(values, key)?)
}

fn require_string(
    values: &mut BTreeMap<String, String>,
    key: &str,
    expected: &str,
) -> Result<(), String> {
    let observed = take_string(values, key)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn unavailable_record(extra: &str) -> String {
        format!(
            concat!(
                "schema_version = 2\n",
                "role = \"upstream-oracle\"\n",
                "platform = \"macos-arm64\"\n",
                "availability = \"unavailable\"\n",
                "oracle_kind = \"source-build\"\n",
                "reason = \"awaiting independent provenance review\"\n",
                "reported_version = \"2026-05-29\"\n",
                "upstream_repository = \"https://github.com/chrisdone/hell\"\n",
                "source_commit = \"8e952cf9de4ab25d7716982a9ca234f9bdcf1bff\"\n",
                "compatibility_baseline_commit = \"d4d028609ed46a560c62caea8c70e7e91d1afd29\"\n",
                "{}"
            ),
            extra
        )
    }

    #[test]
    fn availability_string_alone_cannot_create_an_available_record() {
        let record = concat!(
            "schema_version = 2\n",
            "role = \"upstream-oracle\"\n",
            "platform = \"macos-arm64\"\n",
            "availability = \"available\"\n",
            "oracle_kind = \"source-build\"\n",
            "reported_version = \"2026-05-29\"\n",
            "upstream_repository = \"https://github.com/chrisdone/hell\"\n",
            "source_commit = \"8e952cf9de4ab25d7716982a9ca234f9bdcf1bff\"\n",
            "compatibility_baseline_commit = \"d4d028609ed46a560c62caea8c70e7e91d1afd29\"\n",
        );
        assert!(parse(record, RequiredPlatform::MacOsArm64).is_err());
    }

    #[test]
    fn unavailable_records_require_a_reason_and_deny_unknown_fields() {
        assert!(parse(&unavailable_record(""), RequiredPlatform::MacOsArm64).is_ok());
        let empty_reason = unavailable_record("").replace(
            "reason = \"awaiting independent provenance review\"",
            "reason = \"\"",
        );
        assert!(parse(&empty_reason, RequiredPlatform::MacOsArm64).is_err());
        assert!(
            parse(
                &unavailable_record("promotion_ready = true\n"),
                RequiredPlatform::MacOsArm64
            )
            .is_err()
        );
    }

    #[test]
    fn reviewed_release_digest_must_match_the_retained_shard() {
        let directory =
            std::env::temp_dir().join(format!("hell-oracle-record-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();
        fs::write(
            directory.join("summary.json"),
            "{\n  \"oracleSha256\": \"observed\"\n}\n",
        )
        .unwrap();
        let record = ReviewedOracleRecord {
            platform: RequiredPlatform::LinuxAmd64,
            availability: Availability::Available,
            kind: OracleKind::ReleaseAsset,
            fields: [("asset_sha256".to_owned(), "reviewed".to_owned())]
                .into_iter()
                .collect(),
        };
        let error = validate_against_shard(&record, &directory).unwrap_err();
        assert!(error.contains("asset_sha256 mismatch"));
        fs::remove_dir_all(directory).unwrap();
    }
}
