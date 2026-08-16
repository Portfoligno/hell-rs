use std::collections::BTreeSet;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::Write as _;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use crate::command::CommandSpec;
use crate::json::{JsonValue, canonical_json_bytes, json_member};

use super::manifest::{read_json, read_regular, write_atomic, write_json};
use super::schema::{PLATFORMS, ReleasePlan, Resolution, number, object, string};

pub(crate) fn create(
    resolution_path: PathBuf,
    root: PathBuf,
    output: PathBuf,
    report: PathBuf,
) -> Result<String, String> {
    if output.exists() {
        return Err("release plan output already exists".to_owned());
    }
    if report.starts_with(&output) {
        return Err(
            "release plan diagnostic report must remain outside the exact artifact".to_owned(),
        );
    }
    let resolution = Resolution::parse(&read_json(&resolution_path)?)?;
    let head = git_output(&root, [OsString::from("rev-parse"), OsString::from("HEAD")])?;
    if head != resolution.candidate_sha {
        return Err("candidate checkout HEAD differs from resolved candidate SHA".to_owned());
    }

    let trusted_root = env::var_os("GITHUB_WORKSPACE")
        .map(PathBuf::from)
        .map(|workspace| workspace.join("automation"))
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."));
    let trusted_policy_path = trusted_root.join("release-policy.toml");
    let policy = read_regular(&trusted_policy_path)?;
    let candidate_policy = read_regular(&root.join("release-policy.toml"))?;
    if candidate_policy != policy {
        return Err("candidate release policy differs from trusted automation policy".to_owned());
    }
    validate_policy(&policy, &resolution.repository)?;
    let policy_sha256 = hell_testkit::sha256_bytes(&policy).hex();
    let version = workspace_version(&root)?;
    validate_release_crate(&root, &version)?;
    let prerelease = semver_prerelease(&version)?;
    let tag = format!("v{version}");
    let changelog = changelog_section(&root.join("CHANGELOG.md"), &version)?;
    let changelog_sha256 = hell_testkit::sha256_bytes(changelog.as_bytes()).hex();
    let identities = git_output(
        &root,
        [
            OsString::from("show"),
            OsString::from("-s"),
            OsString::from("--format=%an <%ae>%n%cn <%ce>"),
            OsString::from(&resolution.candidate_sha),
        ],
    )?;
    let identity_lines = identities.lines().collect::<Vec<_>>();
    if identity_lines.len() != 2 || identity_lines.iter().any(|line| line.trim().is_empty()) {
        return Err("candidate author/committer identity is malformed".to_owned());
    }
    let source_date_epoch = git_output(
        &root,
        [
            OsString::from("show"),
            OsString::from("-s"),
            OsString::from("--format=%ct"),
            OsString::from(&resolution.candidate_sha),
        ],
    )?
    .parse::<u64>()
    .map_err(|_| "candidate commit timestamp is invalid".to_owned())?;
    let inventory = source_inventory(&root)?;
    let inventory_bytes = canonical_json_bytes(&inventory)?;
    let source_inventory_sha256 = hell_testkit::sha256_bytes(&inventory_bytes).hex();
    let trusted_inputs =
        crate::conformance::build_trusted_inputs(&trusted_root, &root, &resolution.workflow_sha)?;
    let exemptions = crate::conformance::parse_release_exemptions(&read_regular(
        &trusted_root.join(".github/release/conformance-exemptions.toml"),
    )?)?;
    let release_evaluation_instant = super::github::GitHubClient::from_actions_environment()?
        .workflow_run_created_at(
            &resolution.repository,
            resolution.repository_id,
            resolution.run_id,
            resolution.run_attempt,
            &resolution.workflow_sha,
        )?;
    let conformance_plan = crate::conformance::build_release_conformance_plan(
        &resolution.candidate_sha,
        &resolution.workflow_sha,
        &release_evaluation_instant,
        &trusted_inputs.aggregate_sha256,
        &source_inventory_sha256,
        exemptions,
    )?;
    let runners = object([
        ("linux-x86_64", string("ubuntu-24.04")),
        ("macos-aarch64", string("macos-15")),
        ("windows-x86_64", string("windows-2025")),
    ]);
    let pinned_inputs = object([
        (
            "cargoLockSha256",
            string(inventory_digest(&inventory, "Cargo.lock")?),
        ),
        (
            "releasePolicySha256",
            string(inventory_digest(&inventory, "release-policy.toml")?),
        ),
        (
            "rustToolchainSha256",
            string(inventory_digest(&inventory, "rust-toolchain.toml")?),
        ),
        (
            "workflowSha256",
            string(inventory_digest(
                &inventory,
                ".github/workflows/release.yml",
            )?),
        ),
    ]);

    let build_inputs = object([
        ("automationSha", string(&resolution.workflow_sha)),
        ("candidateSha", string(&resolution.candidate_sha)),
        (
            "oracleCommit",
            string("8e952cf9de4ab25d7716982a9ca234f9bdcf1bff"),
        ),
        (
            "platforms",
            JsonValue::Array(
                PLATFORMS
                    .iter()
                    .map(|platform| string(platform.id()))
                    .collect(),
            ),
        ),
        ("policySha256", string(&policy_sha256)),
        ("pinnedInputs", pinned_inputs),
        ("runners", runners),
        ("schemaVersion", number(1)),
        ("sourceInventorySha256", string(&source_inventory_sha256)),
        ("stackVersion", string("3.11.1")),
    ]);
    let build_inputs_bytes = canonical_json_bytes(&build_inputs)?;
    let build_inputs_sha256 = hell_testkit::sha256_bytes(&build_inputs_bytes).hex();
    validate_remote_tag_and_release(&resolution, &tag)?;
    let mut plan = ReleasePlan {
        resolution,
        version,
        tag,
        prerelease,
        source_date_epoch,
        release_evaluation_instant,
        source_inventory_sha256,
        build_inputs_sha256,
        policy_sha256,
        trusted_conformance_inputs_sha256: trusted_inputs.aggregate_sha256.clone(),
        conformance_plan_sha256: conformance_plan.plan_sha256.clone(),
        conformance_standard: crate::conformance::RELEASE_STANDARD.to_owned(),
        changelog_sha256,
        commit_author: identity_lines[0].to_owned(),
        commit_committer: identity_lines[1].to_owned(),
        plan_sha256: String::new(),
    };
    plan.plan_sha256 =
        hell_testkit::sha256_bytes(&canonical_json_bytes(&plan.json_without_digest())?).hex();
    fs::create_dir(&output)
        .map_err(|error| format!("cannot create exact release plan directory: {error}"))?;
    write_json(
        &output.join("release-resolution.json"),
        &plan.resolution.json(),
    )?;
    write_atomic(&output.join("source-inventory.json"), &inventory_bytes)?;
    write_atomic(&output.join("build-inputs.json"), &build_inputs_bytes)?;
    write_json(
        &output.join("trusted-conformance-inputs.json"),
        &trusted_inputs.manifest,
    )?;
    write_json(
        &output.join("conformance-plan.json"),
        &conformance_plan.json(),
    )?;
    write_json(&output.join("release-plan.json"), &plan.json())?;
    validate_written_plan_inventory(&output)?;
    let report_value = object([
        ("changelogSha256", string(&plan.changelog_sha256)),
        ("planSha256", string(&plan.plan_sha256)),
        ("schemaVersion", number(1)),
        ("state", string("release-plan-admitted")),
    ]);
    write_json(&report, &report_value)?;
    append_outputs(&plan)?;
    Ok(format!(
        "planned {} at {}",
        plan.tag, plan.resolution.candidate_sha
    ))
}

fn validate_written_plan_inventory(output: &Path) -> Result<(), String> {
    let observed = fs::read_dir(output)
        .map_err(|error| format!("cannot enumerate release plan output: {error}"))?
        .map(|entry| {
            entry
                .map_err(|error| format!("cannot inspect release plan output: {error}"))?
                .file_name()
                .into_string()
                .map_err(|_| "release plan output name is not UTF-8".to_owned())
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let expected = BTreeSet::from([
        "build-inputs.json".to_owned(),
        "conformance-plan.json".to_owned(),
        "release-plan.json".to_owned(),
        "release-resolution.json".to_owned(),
        "source-inventory.json".to_owned(),
        "trusted-conformance-inputs.json".to_owned(),
    ]);
    if observed != expected {
        return Err(format!(
            "release plan exact inventory differs: {observed:?}"
        ));
    }
    ReleasePlan::parse(&read_json(&output.join("release-plan.json"))?)?;
    crate::conformance::ConformancePlan::parse(&read_json(&output.join("conformance-plan.json"))?)?;
    crate::conformance::parse_trusted_inputs(&read_json(
        &output.join("trusted-conformance-inputs.json"),
    )?)?;
    Resolution::parse(&read_json(&output.join("release-resolution.json"))?)?;
    read_json(&output.join("source-inventory.json"))?;
    read_json(&output.join("build-inputs.json"))?;
    Ok(())
}

fn inventory_digest<'a>(inventory: &'a JsonValue, path: &str) -> Result<&'a str, String> {
    let files = json_member(inventory.object()?, "files")?.array()?;
    let entry = files
        .iter()
        .find(|entry| {
            entry
                .object()
                .ok()
                .and_then(|entry| json_member(entry, "path").ok())
                .and_then(|value| value.string().ok())
                == Some(path)
        })
        .ok_or_else(|| format!("source inventory lacks build input {path:?}"))?;
    json_member(entry.object()?, "sha256")?.string()
}

fn workspace_version(root: &Path) -> Result<String, String> {
    let manifest = std::str::from_utf8(&read_regular(&root.join("Cargo.toml"))?)
        .map_err(|_| "workspace manifest is not UTF-8".to_owned())?
        .to_owned();
    let mut values = crate::strict_toml::assignments(&manifest)?;
    let version = crate::strict_toml::string(&crate::strict_toml::take(
        &mut values,
        "workspace.package.version",
    )?)?;
    semver_prerelease(&version)?;
    Ok(version)
}

fn validate_release_crate(root: &Path, version: &str) -> Result<(), String> {
    let path = root.join("crates/hell-cli/Cargo.toml");
    let document = std::str::from_utf8(&read_regular(&path)?)
        .map_err(|_| "hell-cli manifest is not UTF-8".to_owned())?
        .to_owned();
    let values = crate::strict_toml::assignments(&document)?;
    if crate::strict_toml::boolean(
        values
            .get("package.version.workspace")
            .ok_or_else(|| "hell-cli must inherit workspace version".to_owned())?,
    )? != true
        || crate::strict_toml::string(
            values
                .get("bin.name")
                .ok_or_else(|| "hell-cli must declare binary hell".to_owned())?,
        )? != "hell"
    {
        return Err("hell-cli release binary/version contract is invalid".to_owned());
    }
    for entry in fs::read_dir(root.join("crates"))
        .map_err(|error| format!("cannot enumerate workspace crates: {error}"))?
    {
        let entry = entry.map_err(|error| format!("cannot inspect workspace crate: {error}"))?;
        let manifest = entry.path().join("Cargo.toml");
        if !manifest.is_file() {
            continue;
        }
        let bytes = read_regular(&manifest)?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| format!("{} is not UTF-8", manifest.display()))?;
        let assignments = crate::strict_toml::assignments(text)?;
        if let Some(raw) = assignments.get("package.version") {
            if crate::strict_toml::string(raw)? != version {
                return Err(format!(
                    "{} package version differs from workspace release",
                    manifest.display()
                ));
            }
        } else if assignments.get("package.version.workspace").is_none() {
            return Err(format!(
                "{} does not inherit workspace version",
                manifest.display()
            ));
        }
        for (key, raw) in assignments.iter().filter(|(key, _)| {
            key.ends_with(".version")
                && key.split('.').any(|part| {
                    matches!(
                        part,
                        "dependencies" | "dev-dependencies" | "build-dependencies"
                    )
                })
        }) {
            if assignments.contains_key(&format!(
                "{}.path",
                key.strip_suffix(".version").expect("suffix exists")
            )) && crate::strict_toml::string(raw)? != version
            {
                return Err(format!(
                    "{} path dependency {key} differs from workspace version",
                    manifest.display()
                ));
            }
        }
    }
    Ok(())
}

fn semver_prerelease(version: &str) -> Result<bool, String> {
    if version.matches('+').count() > 1 {
        return Err("workspace version is not valid SemVer".to_owned());
    }
    let (core_and_pre, build) = version
        .split_once('+')
        .map_or((version, None), |(left, right)| (left, Some(right)));
    let (core, prerelease) = core_and_pre
        .split_once('-')
        .map_or((core_and_pre, None), |(left, right)| (left, Some(right)));
    let parts = core.split('.').collect::<Vec<_>>();
    if parts.len() != 3 || parts.iter().any(|part| !numeric_identifier(part)) {
        return Err("workspace version is not valid SemVer".to_owned());
    }
    for (suffix, numeric_leading_zero_forbidden) in [(prerelease, true), (build, false)] {
        let Some(suffix) = suffix else { continue };
        if suffix.is_empty()
            || suffix.split('.').any(|identifier| {
                identifier.is_empty()
                    || !identifier
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            })
        {
            return Err("workspace version has an invalid SemVer suffix".to_owned());
        }
        if numeric_leading_zero_forbidden
            && suffix.split('.').any(|identifier| {
                identifier.bytes().all(|byte| byte.is_ascii_digit())
                    && identifier.len() > 1
                    && identifier.starts_with('0')
            })
        {
            return Err("workspace version has a numeric prerelease leading zero".to_owned());
        }
    }
    Ok(prerelease.is_some())
}

fn numeric_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && (value == "0" || !value.starts_with('0'))
}

fn changelog_section(path: &Path, version: &str) -> Result<String, String> {
    const DATE_SHAPE: &str = "0000-00-00";
    let bytes = read_regular(path)?;
    let document =
        std::str::from_utf8(&bytes).map_err(|_| "CHANGELOG.md is not UTF-8".to_owned())?;
    let prefix = format!("## [{version}]");
    let starts = document
        .lines()
        .enumerate()
        .filter_map(|(index, line)| {
            (line == prefix
                || line
                    .strip_prefix(&format!("{prefix} - "))
                    .is_some_and(|date| {
                        let mut date = date.bytes();
                        let mut shape = DATE_SHAPE.bytes();
                        std::iter::from_fn(|| match (date.next(), shape.next()) {
                            (Some(byte), Some(b'-')) => Some(byte == b'-'),
                            (Some(byte), Some(_)) => Some(byte.is_ascii_digit()),
                            (None, None) => None,
                            _ => Some(false),
                        })
                        .all(std::convert::identity)
                            && date.next().is_none()
                            && shape.next().is_none()
                    }))
            .then_some(index)
        })
        .collect::<Vec<_>>();
    if starts.len() != 1 {
        return Err(format!(
            "CHANGELOG.md must contain exactly one section for {version}"
        ));
    }
    let lines = document.lines().collect::<Vec<_>>();
    let start = starts[0];
    let end = lines
        .iter()
        .enumerate()
        .skip(start + 1)
        .find_map(|(index, line)| line.starts_with("## ").then_some(index))
        .unwrap_or(lines.len());
    let body = lines[start + 1..end]
        .iter()
        .any(|line| !line.trim().is_empty());
    if !body {
        return Err("release changelog section is empty".to_owned());
    }
    Ok(format!("{}\n", lines[start..end].join("\n")))
}

fn validate_remote_tag_and_release(resolution: &Resolution, tag: &str) -> Result<(), String> {
    let client = super::github::GitHubClient::from_actions_environment()?;
    if client.tag_commit(&resolution.repository, tag)?.is_some() {
        return Err("planned release tag already exists".to_owned());
    }
    if let Some(release) = client.release_state_by_tag(&resolution.repository, tag)? {
        let release = release.object()?;
        let body = json_member(release, "body")?.string()?;
        if !json_member(release, "draft")?.boolean()? || !has_one_canonical_plan_marker(body) {
            return Err("planned release conflicts with an existing release".to_owned());
        }
    }
    Ok(())
}

fn has_one_canonical_plan_marker(body: &str) -> bool {
    let prefix = "<!-- hell-rs-release-plan-sha256: ";
    let markers = body
        .match_indices(prefix)
        .filter_map(|(index, _)| {
            body[index..]
                .find(" -->")
                .map(|end| &body[index..index + end + 4])
        })
        .collect::<Vec<_>>();
    markers.len() == 1
        && markers[0]
            .strip_prefix(prefix)
            .and_then(|value| value.strip_suffix(" -->"))
            .is_some_and(|digest| {
                digest.len() == 64
                    && digest
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            })
}

pub(crate) fn source_inventory(root: &Path) -> Result<JsonValue, String> {
    source_inventory_with_authority(root, InventoryAuthority::Candidate)
}

pub(crate) fn pinned_oracle_source_inventory(root: &Path) -> Result<JsonValue, String> {
    crate::command::verify_pinned_oracle_checkout(root)?;
    let inventory = source_inventory_with_authority(root, InventoryAuthority::PinnedOracle)?;
    crate::command::verify_pinned_oracle_checkout(root)?;
    Ok(inventory)
}

#[derive(Clone, Copy)]
enum InventoryAuthority {
    Candidate,
    PinnedOracle,
}

fn source_inventory_with_authority(
    root: &Path,
    authority: InventoryAuthority,
) -> Result<JsonValue, String> {
    let result = CommandSpec::new("git", Duration::from_secs(60))
        .git_safe_directory(root)
        .arguments(["ls-files", "--stage", "-z"])
        .current_directory(root)
        .run()
        .map_err(|error| format!("cannot enumerate tracked source: {error}"))?;
    if !result.status.success()
        || result.timed_out
        || (!result.stdout.is_empty() && !result.stdout.ends_with(&[0]))
    {
        return Err("cannot obtain canonical Git source inventory".to_owned());
    }
    let mut paths = BTreeSet::new();
    let mut entries = Vec::new();
    for record in result
        .stdout
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        let record = std::str::from_utf8(record)
            .map_err(|_| "tracked path record is not UTF-8".to_owned())?;
        let (metadata, relative) = record
            .split_once('\t')
            .ok_or_else(|| "tracked path record is malformed".to_owned())?;
        if ignored_ownership_path(relative) {
            continue;
        }
        let fields = metadata.split(' ').collect::<Vec<_>>();
        if fields.len() != 3 || fields[2] != "0" || !matches!(fields[0], "100644" | "100755") {
            return Err(format!(
                "tracked path {relative:?} is a link, submodule, or unsupported mode"
            ));
        }
        validate_relative_path(relative)?;
        if !paths.insert(relative.to_owned()) {
            return Err("duplicate tracked path".to_owned());
        }
        let path = root.join(relative);
        let bytes = read_regular(&path)?;
        validate_inventory_bytes(authority, relative, &bytes)?;
        entries.push(object([
            ("mode", string(fields[0])),
            ("path", string(relative)),
            ("sha256", string(&hell_testkit::sha256_bytes(&bytes).hex())),
            (
                "size",
                number(u64::try_from(bytes.len()).map_err(|_| "file size overflow".to_owned())?),
            ),
        ]));
    }
    Ok(object([
        ("files", JsonValue::Array(entries)),
        ("schemaVersion", number(1)),
    ]))
}

fn validate_inventory_bytes(
    authority: InventoryAuthority,
    relative: &str,
    bytes: &[u8],
) -> Result<(), String> {
    if matches!(authority, InventoryAuthority::Candidate)
        && std::str::from_utf8(bytes).is_ok()
        && !bytes.is_empty()
        && !bytes.ends_with(b"\n")
    {
        return Err(format!(
            "tracked text file {relative:?} has no trailing newline"
        ));
    }
    Ok(())
}

fn ignored_ownership_path(relative: &str) -> bool {
    matches!(
        relative,
        "CODEOWNERS" | ".github/CODEOWNERS" | "docs/CODEOWNERS"
    )
}

fn validate_relative_path(value: &str) -> Result<(), String> {
    let path = Path::new(value);
    if value.is_empty()
        || value.contains('\\')
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!("tracked path {value:?} is not normalized"));
    }
    Ok(())
}

fn validate_policy(bytes: &[u8], repository: &str) -> Result<(), String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "release policy is not UTF-8".to_owned())?;
    let canonical = include_str!("../../../../release-policy.toml");
    let expected_repository = "repository = \"Portfoligno/hell-rs\"";
    if !canonical.contains(expected_repository) {
        return Err("compiled release policy repository is not canonical".to_owned());
    }
    let expected = canonical.replace(
        expected_repository,
        &format!("repository = \"{repository}\""),
    );
    if text != expected {
        return Err("release policy differs from the closed canonical schema".to_owned());
    }
    Ok(())
}

fn git_output<const N: usize>(root: &Path, arguments: [OsString; N]) -> Result<String, String> {
    let result = CommandSpec::new("git", Duration::from_secs(60))
        .arguments(arguments)
        .current_directory(root)
        .run()
        .map_err(|error| format!("cannot run git: {error}"))?;
    if !result.status.success() || result.timed_out {
        return Err("git command failed".to_owned());
    }
    Ok(std::str::from_utf8(&result.stdout)
        .map_err(|_| "git output is not UTF-8".to_owned())?
        .trim_end_matches(['\r', '\n'])
        .to_owned())
}

fn append_outputs(plan: &ReleasePlan) -> Result<(), String> {
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
    writeln!(
        file,
        "version={}\ntag={}\nplan_digest={}\nbuild_inputs_digest={}\nconformance_plan_digest={}\ntrusted_conformance_inputs_digest={}",
        plan.version,
        plan.tag,
        plan.plan_sha256,
        plan.build_inputs_sha256,
        plan.conformance_plan_sha256,
        plan.trusted_conformance_inputs_sha256,
    )
    .and_then(|()| file.sync_all())
    .map_err(|error| format!("cannot write GITHUB_OUTPUT: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semver_derives_prerelease_state() {
        assert_eq!(semver_prerelease("0.2.0").unwrap(), false);
        assert_eq!(semver_prerelease("0.2.0-rc.1").unwrap(), true);
        assert!(semver_prerelease("01.2.0").is_err());
        assert!(semver_prerelease("1.2").is_err());
        assert!(semver_prerelease("1.0.0-01").is_err());
        assert_eq!(semver_prerelease("1.0.0-alpha-beta.1").unwrap(), true);
        assert_eq!(semver_prerelease("1.0.0+build-alpha").unwrap(), false);
        assert!(semver_prerelease("1.0.0-alpha..beta").is_err());
        assert!(semver_prerelease("1.0.0-alpha+one+two").is_err());
    }

    #[test]
    fn release_policy_rejects_duplicates_reordering_and_weakening() {
        let repository = "Portfoligno/hell-rs";
        let bytes =
            std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../release-policy.toml"))
                .unwrap();
        validate_policy(&bytes, repository).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        for changed in [
            format!("{text}package_smoke = true\n"),
            text.replace(
                "require_immutable_release = true",
                "require_immutable_release = false",
            ),
            text.replace(
                "id = \"linux-x86_64\"\nrunner = \"ubuntu-24.04\"",
                "runner = \"ubuntu-24.04\"\nid = \"linux-x86_64\"",
            ),
        ] {
            assert!(validate_policy(changed.as_bytes(), repository).is_err());
        }
    }

    #[test]
    fn ownership_metadata_is_not_a_release_build_input() {
        for path in ["CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"] {
            assert!(ignored_ownership_path(path));
        }
        assert!(!ignored_ownership_path("docs/release.md"));
    }

    #[test]
    fn pinned_oracle_inventory_preserves_historical_text_bytes() {
        let historical = b"<html>historical oracle output</html>";
        assert!(
            validate_inventory_bytes(
                InventoryAuthority::Candidate,
                "docs/api/index.html",
                historical,
            )
            .is_err()
        );
        assert!(
            validate_inventory_bytes(
                InventoryAuthority::PinnedOracle,
                "docs/api/index.html",
                historical,
            )
            .is_ok()
        );
    }

    #[test]
    fn changelog_date_requires_canonical_ascii_shape() {
        let root = std::env::temp_dir().join(format!(
            "hell-release-changelog-date-{}",
            std::process::id()
        ));
        let path = root.join("CHANGELOG.md");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(&path, "## [1.2.3] - 2026-08-13\n\nrelease\n").unwrap();
        assert!(changelog_section(&path, "1.2.3").is_ok());
        for malformed in ["2026-8-13", "２０２６-０８-１３", "2026/08/13"] {
            std::fs::write(&path, format!("## [1.2.3] - {malformed}\n\nrelease\n")).unwrap();
            assert!(changelog_section(&path, "1.2.3").is_err());
        }
        std::fs::remove_dir_all(root).unwrap();
    }
}
