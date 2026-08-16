use std::collections::BTreeMap;
#[cfg(unix)]
use std::env;
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::io::Read as _;
#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

use crate::command::CommandSpec;
use crate::json::{JsonValue, canonical_json_bytes, json_member, parse_json};

use super::github::GitHubClient;
#[cfg(unix)]
use super::manifest::write_atomic_new;
use super::manifest::{read_json, read_regular, write_json};
use super::schema::{ReleasePlan, number, object, string};
use super::verify;

#[cfg(unix)]
const ATTESTATION_REGISTRY: &str = "created_attestation_paths.txt";
#[cfg(unix)]
const MAX_ATTESTATION_REGISTRY_BYTES: u64 = 64 * 1024;
#[cfg(unix)]
const MAX_ATTESTATION_BUNDLE_BYTES: u64 = 16 * 1024 * 1024;
#[cfg(unix)]
const ATTESTATION_DESTINATIONS: [&str; 2] = [
    "github-provenance.sigstore.json",
    "github-release-gate.sigstore.json",
];

#[cfg(unix)]
pub(crate) fn stage_attestations(input: PathBuf) -> Result<String, String> {
    let runner_temp = PathBuf::from(
        env::var_os("RUNNER_TEMP").ok_or_else(|| "RUNNER_TEMP is required".to_owned())?,
    );
    let registry = runner_temp.join(ATTESTATION_REGISTRY);
    stage_attestations_from_registry(&input, &runner_temp, &registry)
}

#[cfg(not(unix))]
pub(crate) fn stage_attestations(_input: PathBuf) -> Result<String, String> {
    Err("attestation staging requires Unix file identity".to_owned())
}

#[cfg(unix)]
fn stage_attestations_from_registry(
    input: &Path,
    runner_temp: &Path,
    registry: &Path,
) -> Result<String, String> {
    if !runner_temp.is_absolute() {
        return Err("RUNNER_TEMP must be absolute".to_owned());
    }
    require_real_directory(runner_temp, "RUNNER_TEMP")?;
    if registry != runner_temp.join(ATTESTATION_REGISTRY) {
        return Err("attestation registry path differs from the runner contract".to_owned());
    }
    let canonical_runner_temp = fs::canonicalize(runner_temp)
        .map_err(|_| "RUNNER_TEMP cannot be canonicalized".to_owned())?;
    let registry_bytes = read_bounded_real_file(
        registry,
        MAX_ATTESTATION_REGISTRY_BYTES,
        "attestation registry",
    )?;
    let registry_text = std::str::from_utf8(&registry_bytes)
        .map_err(|_| "attestation registry is not UTF-8".to_owned())?;
    let sources = parse_attestation_registry(registry_text)?;
    let bundles = [
        read_attestation_bundle(1, &sources[0], &canonical_runner_temp)?,
        read_attestation_bundle(2, &sources[1], &canonical_runner_temp)?,
    ];

    require_real_directory(input, "attestation destination")?;
    let destination_identity =
        fs::symlink_metadata(input).map_err(|_| "attestation destination is missing".to_owned())?;
    let canonical_destination = fs::canonicalize(input)
        .map_err(|_| "attestation destination cannot be canonicalized".to_owned())?;
    let destinations = ATTESTATION_DESTINATIONS.map(|name| input.join(name));
    for destination in &destinations {
        require_absent_destination(destination)?;
    }
    let mut installed = Vec::new();
    for (destination, bytes) in destinations.iter().zip(bundles.iter()) {
        require_same_destination_directory(input, &destination_identity, &canonical_destination)?;
        if let Err(error) = write_atomic_new(destination, bytes) {
            for created in installed {
                if let Err(rollback_error) = fs::remove_file(&created) {
                    return Err(format!(
                        "{error}; cannot roll back staged attestation: {rollback_error}"
                    ));
                }
            }
            return Err(error);
        }
        installed.push(destination.clone());
    }
    require_same_destination_directory(input, &destination_identity, &canonical_destination)?;
    Ok("staged exact GitHub attestation bundles".to_owned())
}

#[cfg(unix)]
fn parse_attestation_registry(text: &str) -> Result<[PathBuf; 2], String> {
    let mut lines = text.split('\n').collect::<Vec<_>>();
    if lines.last() == Some(&"") {
        lines.pop();
    }
    if lines.len() != 2 {
        return Err("attestation registry must contain exactly two entries".to_owned());
    }
    let mut entries = Vec::with_capacity(2);
    for (index, line) in lines.into_iter().enumerate() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() {
            return Err(format!("attestation registry entry {} is empty", index + 1));
        }
        if line.chars().any(char::is_control) {
            return Err(format!(
                "attestation registry entry {} contains a control character",
                index + 1
            ));
        }
        let path = PathBuf::from(line);
        if !path.is_absolute() {
            return Err(format!(
                "attestation registry entry {} must be absolute",
                index + 1
            ));
        }
        entries.push(path);
    }
    let entries: [PathBuf; 2] = entries
        .try_into()
        .map_err(|_| "attestation registry must contain exactly two entries".to_owned())?;
    if entries[0] == entries[1] {
        return Err("attestation registry entries must be distinct".to_owned());
    }
    Ok(entries)
}

#[cfg(unix)]
fn read_attestation_bundle(
    index: usize,
    source: &Path,
    canonical_runner_temp: &Path,
) -> Result<Vec<u8>, String> {
    let canonical_source = fs::canonicalize(source)
        .map_err(|_| format!("attestation registry entry {index} cannot be canonicalized"))?;
    if !canonical_source.starts_with(canonical_runner_temp) {
        return Err(format!(
            "attestation registry entry {index} is outside RUNNER_TEMP"
        ));
    }
    let label = format!("attestation bundle {index}");
    let bytes = read_bounded_real_file(source, MAX_ATTESTATION_BUNDLE_BYTES, &label)?;
    let canonical_after = fs::canonicalize(source)
        .map_err(|_| format!("attestation registry entry {index} changed while being read"))?;
    if canonical_after != canonical_source {
        return Err(format!(
            "attestation registry entry {index} changed while being read"
        ));
    }
    let document = std::str::from_utf8(&bytes)
        .map_err(|_| format!("attestation bundle {index} is not UTF-8 JSON"))?;
    parse_json(document).map_err(|_| format!("attestation bundle {index} is not valid JSON"))?;
    Ok(bytes)
}

#[cfg(unix)]
fn read_bounded_real_file(path: &Path, maximum: u64, label: &str) -> Result<Vec<u8>, String> {
    let before = fs::symlink_metadata(path).map_err(|_| format!("{label} is missing"))?;
    if !before.is_file() || before.file_type().is_symlink() {
        return Err(format!("{label} must be a real regular file"));
    }
    if before.len() > maximum {
        return Err(format!("{label} exceeds the size limit"));
    }
    let mut file = fs::File::open(path).map_err(|_| format!("{label} cannot be opened"))?;
    let opened = file
        .metadata()
        .map_err(|_| format!("{label} cannot be inspected after opening"))?;
    if !same_file_observation(&before, &opened) {
        return Err(format!("{label} changed while being opened"));
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| format!("{label} cannot be read"))?;
    if u64::try_from(bytes.len())
        .ok()
        .is_none_or(|length| length > maximum)
    {
        return Err(format!("{label} exceeds the size limit"));
    }
    let after =
        fs::symlink_metadata(path).map_err(|_| format!("{label} changed while being read"))?;
    if !same_file_observation(&opened, &after)
        || u64::try_from(bytes.len()).ok() != Some(opened.len())
    {
        return Err(format!("{label} changed while being read"));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn same_file_observation(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    same_file_identity(left, right)
        && left.len() == right.len()
        && left.modified().ok() == right.modified().ok()
}

#[cfg(unix)]
fn same_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(unix)]
fn require_real_directory(path: &Path, label: &str) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|_| format!("{label} is missing"))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(format!("{label} must be a real directory"));
    }
    Ok(())
}

#[cfg(unix)]
fn require_absent_destination(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err("attestation destination already exists".to_owned()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("attestation destination cannot be inspected".to_owned()),
    }
}

#[cfg(unix)]
fn require_same_destination_directory(
    path: &Path,
    expected_metadata: &fs::Metadata,
    expected_canonical: &Path,
) -> Result<(), String> {
    let observed_metadata = fs::symlink_metadata(path)
        .map_err(|_| "attestation destination changed while staging".to_owned())?;
    let observed_canonical = fs::canonicalize(path)
        .map_err(|_| "attestation destination changed while staging".to_owned())?;
    if observed_metadata.file_type().is_symlink()
        || !observed_metadata.is_dir()
        || !same_file_identity(expected_metadata, &observed_metadata)
        || observed_canonical != expected_canonical
    {
        return Err("attestation destination changed while staging".to_owned());
    }
    Ok(())
}

pub(crate) fn run(plan_path: PathBuf, input: PathBuf, report: PathBuf) -> Result<String, String> {
    let plan = ReleasePlan::parse(&read_json(&plan_path)?)?;
    let verification = verify::publication_bundle(
        plan_path,
        input.clone(),
        report.with_file_name("release-publish-verification.json"),
    )
    .and_then(|_| verify_attestations(&plan, &input));
    verification?;
    let client = GitHubClient::from_actions_environment()?;
    publish_after_verification(&plan, &input, &report, &client, Ok(()))
}

fn publish_after_verification(
    plan: &ReleasePlan,
    input: &std::path::Path,
    report: &std::path::Path,
    client: &GitHubClient,
    verification: Result<(), String>,
) -> Result<String, String> {
    verification?;
    publish_with_client(plan, input, report, client)
}

fn publish_with_client(
    plan: &ReleasePlan,
    input: &std::path::Path,
    report: &std::path::Path,
    client: &GitHubClient,
) -> Result<String, String> {
    if !client.immutable_releases_enabled(&plan.resolution.repository)? {
        return Err("GitHub immutable releases are not enabled".to_owned());
    }
    require_stable_branch(&client, &plan)?;
    let marker = format!("<!-- hell-rs-release-plan-sha256: {} -->", plan.plan_sha256);
    let assets = publication_assets(&input, &plan)?;
    let notes = read_regular(&input.join("release-notes.md"))?;
    let notes =
        std::str::from_utf8(&notes).map_err(|_| "release notes are not UTF-8".to_owned())?;
    let publication_body = format!("{notes}\n{marker}");
    let mut release = client.release_state_by_tag(&plan.resolution.repository, &plan.tag)?;
    let mut cleanup = false;
    if let Some(existing) = &release {
        require_remote_tag(&client, &plan, existing)?;
        match classify(existing, &plan, &marker, &assets)? {
            ExistingReleaseState::MatchingImmutable => {
                require_exact_published_metadata(existing, plan, &publication_body)?;
                write_report(&report, &plan, "already-published-immutable", false)?;
                return Ok(format!("verified existing immutable release {}", plan.tag));
            }
            ExistingReleaseState::MatchingDraft => {}
            ExistingReleaseState::StaleMachineDraft => {
                let id = release_id(existing)?;
                if client
                    .delete_release(&plan.resolution.repository, id)
                    .is_err()
                {
                    release =
                        client.release_state_by_tag(&plan.resolution.repository, &plan.tag)?;
                    if let Some(observed) = release.as_ref() {
                        if classify(observed, &plan, &marker, &assets)?
                            != ExistingReleaseState::StaleMachineDraft
                        {
                            return Err("ambiguous stale draft deletion left a conflicting state"
                                .to_owned());
                        }
                        client
                            .delete_release(&plan.resolution.repository, release_id(observed)?)?;
                        if client
                            .release_state_by_tag(&plan.resolution.repository, &plan.tag)?
                            .is_some()
                        {
                            return Err(
                                "stale draft remained after bounded deletion recovery".to_owned()
                            );
                        }
                        release = None;
                    }
                } else {
                    release = None;
                }
                cleanup = true;
            }
            ExistingReleaseState::HumanConflict | ExistingReleaseState::PublishedConflict => {
                return Err("planned tag conflicts with a human or published release".to_owned());
            }
        }
    }
    if release.is_none() {
        require_stable_branch(&client, &plan)?;
        require_absent_tag(&client, &plan)?;
        let body = draft_request(&plan, &marker)?;
        match client.create_draft(&plan.resolution.repository, &body) {
            Ok(created) => {
                if classify(&created, &plan, &marker, &assets)?
                    != ExistingReleaseState::MatchingDraft
                {
                    return Err("GitHub created a nonmatching release draft".to_owned());
                }
                release = Some(created);
            }
            Err(_) => {
                release = client.release_state_by_tag(&plan.resolution.repository, &plan.tag)?;
                let observed = release.as_ref().ok_or_else(|| {
                    "ambiguous draft creation did not produce an observable release".to_owned()
                })?;
                if classify(observed, &plan, &marker, &assets)?
                    != ExistingReleaseState::MatchingDraft
                {
                    return Err("ambiguous draft creation produced a conflicting state".to_owned());
                }
            }
        }
    }
    let mut release_value = release.ok_or_else(|| "release draft was not created".to_owned())?;
    if reconcile_assets(&client, &plan, &input, &assets, &release_value).is_err() {
        release_value = client
            .release_state_by_tag(&plan.resolution.repository, &plan.tag)?
            .ok_or_else(|| {
                "release draft disappeared during ambiguous asset mutation".to_owned()
            })?;
        if classify(&release_value, &plan, &marker, &assets)? != ExistingReleaseState::MatchingDraft
        {
            return Err("ambiguous asset mutation produced a conflicting release".to_owned());
        }
        reconcile_assets(&client, &plan, &input, &assets, &release_value)?;
    }
    release_value = client
        .release_state_by_tag(&plan.resolution.repository, &plan.tag)?
        .ok_or_else(|| "release draft disappeared after asset reconciliation".to_owned())?;
    if classify(&release_value, &plan, &marker, &assets)? != ExistingReleaseState::MatchingDraft {
        return Err("release draft asset set did not reconcile exactly".to_owned());
    }
    require_stable_branch(&client, &plan)?;
    require_remote_tag(&client, &plan, &release_value)?;
    let body = publish_request(&plan, &publication_body)?;
    if client
        .update_release(
            &plan.resolution.repository,
            release_id(&release_value)?,
            &body,
        )
        .is_err()
        && client
            .release_by_tag(&plan.resolution.repository, &plan.tag)?
            .is_none()
    {
        return Err("ambiguous publication produced no release".to_owned());
    }
    release_value = client
        .release_by_tag(&plan.resolution.repository, &plan.tag)?
        .ok_or_else(|| "published release disappeared before final verification".to_owned())?;
    if classify(&release_value, &plan, &marker, &assets)? != ExistingReleaseState::MatchingImmutable
    {
        return Err("post-publication immutable release verification failed".to_owned());
    }
    require_exact_published_metadata(&release_value, &plan, &publication_body)?;
    require_remote_tag(&client, &plan, &release_value)?;
    write_report(report, plan, "published-immutable", cleanup)?;
    Ok(format!("published verified immutable release {}", plan.tag))
}

fn require_exact_published_metadata(
    release: &JsonValue,
    plan: &ReleasePlan,
    expected_body: &str,
) -> Result<(), String> {
    let release = release.object()?;
    if json_member(release, "name")?.string()? != plan.tag
        || json_member(release, "body")?.string()? != expected_body
        || json_member(release, "tag_name")?.string()? != plan.tag
    {
        return Err("published release name, notes, or tag differs from the plan".to_owned());
    }
    Ok(())
}

fn verify_attestations(plan: &ReleasePlan, input: &std::path::Path) -> Result<(), String> {
    let assets = publication_assets(input, plan)?;
    for (bundle, predicate_type) in [
        (
            "github-provenance.sigstore.json",
            "https://slsa.dev/provenance/v1",
        ),
        (
            "github-release-gate.sigstore.json",
            "https://github.com/Portfoligno/hell-rs/attestations/release-gate/v2",
        ),
    ] {
        // Parse the externally serialized bundle, then independently verify its
        // signatures, certificate identity, repository subject and each exact
        // release subject through the GitHub attestation verifier.
        let bytes = read_regular(&input.join(bundle))?;
        let document = std::str::from_utf8(&bytes)
            .map_err(|_| format!("attestation bundle {bundle} is not UTF-8"))?;
        let bundle_value = parse_json(document)
            .map_err(|error| format!("attestation bundle {bundle} is invalid: {error}"))?;
        let expected_predicate = (bundle == "github-release-gate.sigstore.json")
            .then(|| read_json(&input.join("release-gate.json")))
            .transpose()?;
        verify_bundle_statement(
            &bundle_value,
            predicate_type,
            expected_predicate.as_ref(),
            &assets,
        )?;
        let certificate_identity = format!(
            "https://github.com/{}/.github/workflows/release.yml@refs/heads/{}",
            plan.resolution.repository, plan.resolution.default_branch
        );
        for name in assets.keys().filter(|name| {
            name.as_str() != "SUBJECTS.sha256"
                && name.as_str() != "release-gate.json"
                && !name.ends_with(".sigstore.json")
        }) {
            let result = attestation_command(
                input,
                name,
                bundle,
                &plan.resolution.repository,
                predicate_type,
                &certificate_identity,
                &plan.resolution.workflow_sha,
            )
            .run()
            .map_err(|error| format!("cannot verify attestation for {name}: {error}"))?;
            if !result.status.success() || result.timed_out {
                return Err(format!(
                    "attestation bundle {bundle} does not verify {name}"
                ));
            }
        }
    }
    Ok(())
}

fn verify_bundle_statement(
    bundle: &JsonValue,
    predicate_type: &str,
    expected_predicate: Option<&JsonValue>,
    assets: &BTreeMap<String, (u64, String)>,
) -> Result<(), String> {
    let bundle = bundle.object()?;
    let envelope = json_member(bundle, "dsseEnvelope")?.object()?;
    if json_member(envelope, "payloadType")?.string()? != "application/vnd.in-toto+json" {
        return Err("attestation payload type is not in-toto JSON".to_owned());
    }
    let payload = decode_base64(json_member(envelope, "payload")?.string()?)?;
    let statement = parse_json(
        std::str::from_utf8(&payload)
            .map_err(|_| "attestation statement payload is not UTF-8".to_owned())?,
    )?;
    let statement = statement.object()?;
    require_exact_statement(statement)?;
    if json_member(statement, "_type")?.string()? != "https://in-toto.io/Statement/v1"
        || json_member(statement, "predicateType")?.string()? != predicate_type
    {
        return Err("attestation statement type differs".to_owned());
    }
    if let Some(expected) = expected_predicate
        && json_member(statement, "predicate")? != expected
    {
        return Err("release-gate attestation predicate differs from local gate".to_owned());
    }
    let mut subjects = BTreeMap::new();
    for subject in json_member(statement, "subject")?.array()? {
        let subject = subject.object()?;
        crate::json::require_exact_json_keys(subject, &["digest", "name"])?;
        let digest = json_member(subject, "digest")?.object()?;
        crate::json::require_exact_json_keys(digest, &["sha256"])?;
        let name = json_member(subject, "name")?.string()?.to_owned();
        let digest = json_member(digest, "sha256")?.string()?.to_owned();
        if subjects.insert(name, digest).is_some() {
            return Err("attestation statement duplicates a subject".to_owned());
        }
    }
    let expected = assets
        .iter()
        .filter(|(name, _)| {
            name.as_str() != "SUBJECTS.sha256"
                && name.as_str() != "release-gate.json"
                && !name.ends_with(".sigstore.json")
        })
        .map(|(name, (_, digest))| (name.clone(), digest.clone()))
        .collect::<BTreeMap<_, _>>();
    if subjects != expected {
        return Err("attestation statement subject set differs".to_owned());
    }
    Ok(())
}

fn require_exact_statement(statement: &BTreeMap<String, JsonValue>) -> Result<(), String> {
    crate::json::require_exact_json_keys(
        statement,
        &["_type", "predicate", "predicateType", "subject"],
    )
}

fn decode_base64(value: &str) -> Result<Vec<u8>, String> {
    if value.len() % 4 != 0 {
        return Err("attestation payload base64 is truncated".to_owned());
    }
    let mut output = Vec::with_capacity(value.len() / 4 * 3);
    for chunk in value.as_bytes().chunks_exact(4) {
        let mut words = [0_u8; 4];
        let mut padding = 0;
        for (index, byte) in chunk.iter().copied().enumerate() {
            if byte == b'=' {
                padding += 1;
                words[index] = 0;
            } else {
                words[index] = base64_sextet(byte)?;
            }
        }
        if padding > 2 || (padding != 0 && chunk[4 - padding..].iter().any(|byte| *byte != b'=')) {
            return Err("attestation payload base64 padding is invalid".to_owned());
        }
        output.push((words[0] << 2) | (words[1] >> 4));
        if padding < 2 {
            output.push((words[1] << 4) | (words[2] >> 2));
        }
        if padding == 0 {
            output.push((words[2] << 6) | words[3]);
        }
    }
    Ok(output)
}

fn base64_sextet(byte: u8) -> Result<u8, String> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err("attestation payload base64 contains an invalid byte".to_owned()),
    }
}

fn attestation_command(
    input: &std::path::Path,
    name: &str,
    bundle: &str,
    repository: &str,
    predicate_type: &str,
    certificate_identity: &str,
    signer_digest: &str,
) -> CommandSpec {
    CommandSpec::new("gh", Duration::from_secs(30))
        .arguments(["attestation", "verify"])
        .argument(input.join(name))
        .argument("--bundle")
        .argument(input.join(bundle))
        .argument("--repo")
        .argument(repository)
        .argument("--predicate-type")
        .argument(predicate_type)
        .argument("--cert-identity")
        .argument(certificate_identity)
        .argument("--signer-digest")
        .argument(signer_digest)
        .release_candidate_environment()
}

fn require_remote_tag(
    client: &GitHubClient,
    plan: &ReleasePlan,
    release: &JsonValue,
) -> Result<(), String> {
    if json_member(release.object()?, "draft")?.boolean()? {
        if client
            .tag_commit(&plan.resolution.repository, &plan.tag)?
            .is_some()
        {
            return Err("draft release conflicts with an existing Git tag".to_owned());
        }
    } else if client.tag_commit(&plan.resolution.repository, &plan.tag)?
        != Some(plan.resolution.candidate_sha.clone())
    {
        return Err("published Git tag does not resolve to the planned candidate".to_owned());
    }
    Ok(())
}

fn require_absent_tag(client: &GitHubClient, plan: &ReleasePlan) -> Result<(), String> {
    if client
        .tag_commit(&plan.resolution.repository, &plan.tag)?
        .is_some()
    {
        return Err("planned Git tag appeared before the first publication write".to_owned());
    }
    Ok(())
}

fn require_stable_branch(client: &GitHubClient, plan: &ReleasePlan) -> Result<(), String> {
    if client.branch_head(
        &plan.resolution.repository,
        &plan.resolution.candidate_branch,
    )? != plan.resolution.candidate_sha
    {
        return Err("candidate branch moved after release planning".to_owned());
    }
    Ok(())
}

fn publication_assets(
    input: &std::path::Path,
    plan: &ReleasePlan,
) -> Result<BTreeMap<String, (u64, String)>, String> {
    let expected = std::collections::BTreeSet::from([
        "SUBJECTS.sha256".to_owned(),
        "conformance-acceptance.json".to_owned(),
        "conformance-evidence.tar.gz".to_owned(),
        "conformance-plan.json".to_owned(),
        "conformance-report.html".to_owned(),
        "conformance-report.json".to_owned(),
        "dependency-policy.json".to_owned(),
        "github-provenance.sigstore.json".to_owned(),
        "github-release-gate.sigstore.json".to_owned(),
        "mutation-report.json".to_owned(),
        "release-gate.json".to_owned(),
        "release-manifest.json".to_owned(),
        "release-notes.md".to_owned(),
        format!("hell-v{}-linux-x86_64.tar.gz", plan.version),
        format!("hell-v{}-macos-aarch64.tar.gz", plan.version),
        format!("hell-v{}-windows-x86_64.tar.gz", plan.version),
    ]);
    let mut assets = BTreeMap::new();
    for entry in std::fs::read_dir(input)
        .map_err(|error| format!("cannot enumerate release bundle: {error}"))?
    {
        let entry = entry.map_err(|error| format!("cannot inspect release bundle: {error}"))?;
        if !entry
            .file_type()
            .map_err(|error| format!("cannot inspect release bundle type: {error}"))?
            .is_file()
        {
            continue;
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "release asset name is not UTF-8".to_owned())?;
        if !expected.contains(&name) {
            return Err(format!("unexpected release publication asset {name:?}"));
        }
        let bytes = read_regular(&entry.path())?;
        assets.insert(
            name,
            (
                u64::try_from(bytes.len()).map_err(|_| "release asset is too large".to_owned())?,
                hell_testkit::sha256_bytes(&bytes).hex(),
            ),
        );
    }
    if assets
        .keys()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>()
        != expected
    {
        return Err("release publication asset exact set differs".to_owned());
    }
    Ok(assets)
}

fn classify(
    value: &JsonValue,
    plan: &ReleasePlan,
    marker: &str,
    local: &BTreeMap<String, (u64, String)>,
) -> Result<ExistingReleaseState, String> {
    let object = value.object()?;
    let draft = json_member(object, "draft")?.boolean()?;
    let immutable = object
        .get("immutable")
        .map(JsonValue::boolean)
        .transpose()?
        .unwrap_or(false);
    let release_body = json_member(object, "body")?.string()?;
    let marker_prefix = "<!-- hell-rs-release-plan-sha256: ";
    let marker_suffix = " -->";
    let markers = release_body
        .match_indices(marker_prefix)
        .map(|(index, _)| {
            release_body[index..]
                .find(marker_suffix)
                .map(|end| &release_body[index..index + end + marker_suffix.len()])
        })
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| "release body contains a malformed machine marker".to_owned())?;
    let exact_marker = markers.as_slice() == [marker];
    let machine_owned = markers.len() == 1
        && markers[0]
            .strip_prefix(marker_prefix)
            .and_then(|value| value.strip_suffix(marker_suffix))
            .is_some_and(|digest| hell_testkit::Digest::from_hex(digest).is_ok());
    let identity = json_member(object, "tag_name")?.string()? == plan.tag
        && json_member(object, "target_commitish")?.string()? == plan.resolution.candidate_sha
        && json_member(object, "prerelease")?.boolean()? == plan.prerelease;
    let assets_match = remote_assets(object)?.iter().all(|(name, asset)| {
        local
            .get(name)
            .is_some_and(|(size, digest)| *size == asset.size && *digest == asset.digest)
    }) && (!draft)
        .then(|| remote_assets(object).map(|assets| assets.len() == local.len()))
        .transpose()?
        .unwrap_or(true);
    Ok(
        match (draft, immutable, exact_marker, identity, assets_match) {
            (true, _, true, true, _) => ExistingReleaseState::MatchingDraft,
            (true, _, _, _, _) if machine_owned => ExistingReleaseState::StaleMachineDraft,
            (true, _, _, _, _) => ExistingReleaseState::HumanConflict,
            (false, true, true, true, true) => ExistingReleaseState::MatchingImmutable,
            (false, _, _, _, _) => ExistingReleaseState::PublishedConflict,
        },
    )
}

struct RemoteAsset {
    id: u64,
    size: u64,
    digest: String,
}
fn remote_assets(
    object: &BTreeMap<String, JsonValue>,
) -> Result<BTreeMap<String, RemoteAsset>, String> {
    let mut assets = BTreeMap::new();
    for value in json_member(object, "assets")?.array()? {
        let asset = value.object()?;
        let digest = json_member(asset, "digest")?
            .string()?
            .strip_prefix("sha256:")
            .ok_or_else(|| "release asset digest is not SHA-256".to_owned())?
            .to_owned();
        super::schema::require_digest(&digest, "release asset digest")?;
        let name = json_member(asset, "name")?.string()?.to_owned();
        if assets
            .insert(
                name,
                RemoteAsset {
                    id: json_member(asset, "id")?.number()?,
                    size: json_member(asset, "size")?.number()?,
                    digest,
                },
            )
            .is_some()
        {
            return Err("release contains duplicate asset names".to_owned());
        }
    }
    Ok(assets)
}

fn reconcile_assets(
    client: &GitHubClient,
    plan: &ReleasePlan,
    input: &std::path::Path,
    local: &BTreeMap<String, (u64, String)>,
    release: &JsonValue,
) -> Result<(), String> {
    let object = release.object()?;
    let remote = remote_assets(object)?;
    for (name, asset) in &remote {
        if local
            .get(name)
            .is_none_or(|(size, digest)| *size != asset.size || *digest != asset.digest)
        {
            client.delete_asset(&plan.resolution.repository, asset.id)?;
        }
    }
    let upload_url = json_member(object, "upload_url")?.string()?;
    for (name, (size, digest)) in local {
        if remote
            .get(name)
            .is_some_and(|asset| asset.size == *size && asset.digest == *digest)
        {
            continue;
        }
        let uploaded = client.upload_asset(upload_url, name, &input.join(name))?;
        let uploaded = uploaded.object()?;
        if json_member(uploaded, "name")?.string()? != name
            || json_member(uploaded, "size")?.number()? != *size
            || json_member(uploaded, "digest")?.string()? != format!("sha256:{digest}")
        {
            return Err(format!(
                "GitHub returned mismatching digest for asset {name}"
            ));
        }
    }
    Ok(())
}

fn release_id(value: &JsonValue) -> Result<u64, String> {
    json_member(value.object()?, "id")?.number()
}
fn draft_request(plan: &ReleasePlan, marker: &str) -> Result<String, String> {
    request_json(plan, marker, true)
}
fn publish_request(plan: &ReleasePlan, body: &str) -> Result<String, String> {
    request_json(plan, body, false)
}
fn request_json(plan: &ReleasePlan, body: &str, draft: bool) -> Result<String, String> {
    let value = object([
        ("body", string(body)),
        ("draft", JsonValue::Bool(draft)),
        ("name", string(&plan.tag)),
        ("prerelease", JsonValue::Bool(plan.prerelease)),
        ("tag_name", string(&plan.tag)),
        ("target_commitish", string(&plan.resolution.candidate_sha)),
    ]);
    Ok(String::from_utf8(canonical_json_bytes(&value)?).expect("canonical JSON is UTF-8"))
}
fn write_report(
    path: &std::path::Path,
    plan: &ReleasePlan,
    state: &str,
    cleanup: bool,
) -> Result<(), String> {
    write_json(
        path,
        &object([
            ("cleanupPerformed", JsonValue::Bool(cleanup)),
            ("planSha256", string(&plan.plan_sha256)),
            ("schemaVersion", number(1)),
            ("state", string(state)),
        ]),
    )
    .map(|_| ())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExistingReleaseState {
    MatchingDraft,
    StaleMachineDraft,
    HumanConflict,
    MatchingImmutable,
    PublishedConflict,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(windows)]
    use std::io::Read as _;
    use std::io::Write as _;
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn plan() -> ReleasePlan {
        ReleasePlan {
            resolution: super::super::schema::Resolution {
                repository: "o/r".into(),
                repository_id: 1,
                default_branch: "main".into(),
                candidate_branch: "release".into(),
                candidate_sha: "a".repeat(40),
                actor: "a".into(),
                actor_id: 2,
                run_id: 3,
                run_attempt: 1,
                workflow_ref: "w".into(),
                workflow_sha: "b".repeat(40),
            },
            version: "1.0.0".into(),
            tag: "v1.0.0".into(),
            prerelease: false,
            source_date_epoch: 1,
            release_evaluation_instant: "2026-08-13T00:00:00Z".into(),
            source_inventory_sha256: "c".repeat(64),
            build_inputs_sha256: "d".repeat(64),
            policy_sha256: "e".repeat(64),
            trusted_conformance_inputs_sha256: "2".repeat(64),
            conformance_plan_sha256: "3".repeat(64),
            conformance_standard: crate::conformance::RELEASE_STANDARD.into(),
            changelog_sha256: "1".repeat(64),
            commit_author: "Author <author@example.com>".into(),
            commit_committer: "Committer <committer@example.com>".into(),
            plan_sha256: "f".repeat(64),
        }
    }

    #[derive(Clone, Copy)]
    enum Scenario {
        Create,
        ResumePartial,
        Stale,
        Human,
        AmbiguousCreate,
        AmbiguousDelete,
        AmbiguousUpload,
        AmbiguousPublish,
        Immutable,
        ImmutableAltered,
        MovedBranch,
        ConcurrentTag,
        PublishedConflict,
    }

    #[derive(Clone)]
    struct FakeRelease {
        draft: bool,
        immutable: bool,
        body: String,
        target: String,
        assets: BTreeMap<String, (u64, u64, String)>,
    }

    fn publication_fixture(plan: &ReleasePlan) -> (PathBuf, BTreeMap<String, (u64, String)>) {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("hell-publisher-fixture-{nonce}"));
        std::fs::create_dir(&root).unwrap();
        let names = [
            "SUBJECTS.sha256".to_owned(),
            "conformance-acceptance.json".to_owned(),
            "conformance-evidence.tar.gz".to_owned(),
            "conformance-plan.json".to_owned(),
            "conformance-report.html".to_owned(),
            "conformance-report.json".to_owned(),
            "dependency-policy.json".to_owned(),
            "github-provenance.sigstore.json".to_owned(),
            "github-release-gate.sigstore.json".to_owned(),
            "mutation-report.json".to_owned(),
            "release-gate.json".to_owned(),
            "release-manifest.json".to_owned(),
            "release-notes.md".to_owned(),
            format!("hell-v{}-linux-x86_64.tar.gz", plan.version),
            format!("hell-v{}-macos-aarch64.tar.gz", plan.version),
            format!("hell-v{}-windows-x86_64.tar.gz", plan.version),
        ];
        for name in names {
            let bytes = if name == "release-notes.md" {
                b"notes\n".to_vec()
            } else {
                format!("fixture:{name}\n").into_bytes()
            };
            std::fs::write(root.join(name), bytes).unwrap();
        }
        let assets = publication_assets(&root, plan).unwrap();
        (root, assets)
    }

    fn fake_release_json(plan: &ReleasePlan, release: &FakeRelease, upload_url: &str) -> String {
        let assets = release
            .assets
            .iter()
            .map(|(name, (id, size, digest))| {
                object([
                    ("digest", string(&format!("sha256:{digest}"))),
                    ("id", number(*id)),
                    ("name", string(name)),
                    ("size", number(*size)),
                ])
            })
            .collect();
        String::from_utf8(
            canonical_json_bytes(&object([
                ("assets", JsonValue::Array(assets)),
                ("body", string(&release.body)),
                ("draft", JsonValue::Bool(release.draft)),
                ("id", number(7)),
                ("immutable", JsonValue::Bool(release.immutable)),
                ("name", string(&plan.tag)),
                ("prerelease", JsonValue::Bool(plan.prerelease)),
                ("tag_name", string(&plan.tag)),
                ("target_commitish", string(&release.target)),
                ("upload_url", string(upload_url)),
            ]))
            .unwrap(),
        )
        .unwrap()
    }

    fn request_bytes(stream: &mut std::net::TcpStream) -> Vec<u8> {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut bytes = Vec::new();
        let mut buffer = [0_u8; 8192];
        loop {
            let read = stream.read(&mut buffer).unwrap_or(0);
            if read == 0 {
                break;
            }
            bytes.extend_from_slice(&buffer[..read]);
            let Some(header_end) = bytes.windows(4).position(|value| value == b"\r\n\r\n") else {
                continue;
            };
            let headers = String::from_utf8_lossy(&bytes[..header_end]);
            let content_length = headers
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length: ")
                        .and_then(|value| value.parse::<usize>().ok())
                })
                .unwrap_or(0);
            if bytes.len() >= header_end + 4 + content_length {
                break;
            }
        }
        bytes
    }

    fn respond(stream: &mut std::net::TcpStream, status: &str, body: &str) {
        write!(
            stream,
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
    }

    fn run_fake_publisher(scenario: Scenario) -> (Result<String, String>, Vec<String>) {
        let plan = plan();
        let (input, local) = publication_fixture(&plan);
        let marker = format!("<!-- hell-rs-release-plan-sha256: {} -->", plan.plan_sha256);
        let published_body = format!("notes\n\n{marker}");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let upload_url = format!("http://{address}/upload{{?name,label}}");
        let mut release = match scenario {
            Scenario::Human => Some(FakeRelease {
                draft: true,
                immutable: false,
                body: "human draft".to_owned(),
                target: plan.resolution.candidate_sha.clone(),
                assets: BTreeMap::new(),
            }),
            Scenario::Stale | Scenario::AmbiguousDelete => Some(FakeRelease {
                draft: true,
                immutable: false,
                body: format!("<!-- hell-rs-release-plan-sha256: {} -->", "1".repeat(64)),
                target: "2".repeat(40),
                assets: BTreeMap::new(),
            }),
            Scenario::ResumePartial => {
                let (name, (size, _)) = local.iter().next().unwrap();
                Some(FakeRelease {
                    draft: true,
                    immutable: false,
                    body: marker.clone(),
                    target: plan.resolution.candidate_sha.clone(),
                    assets: BTreeMap::from([(name.clone(), (40, *size, "3".repeat(64)))]),
                })
            }
            Scenario::Immutable | Scenario::ImmutableAltered => Some(FakeRelease {
                draft: false,
                immutable: true,
                body: if matches!(scenario, Scenario::ImmutableAltered) {
                    format!("altered notes\n\n{marker}")
                } else {
                    published_body.clone()
                },
                target: plan.resolution.candidate_sha.clone(),
                assets: local
                    .iter()
                    .enumerate()
                    .map(|(index, (name, (size, digest)))| {
                        (name.clone(), (index as u64 + 10, *size, digest.clone()))
                    })
                    .collect(),
            }),
            Scenario::PublishedConflict => Some(FakeRelease {
                draft: false,
                immutable: true,
                body: "human published release".to_owned(),
                target: plan.resolution.candidate_sha.clone(),
                assets: BTreeMap::new(),
            }),
            _ => None,
        };
        let done = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let server_done = Arc::clone(&done);
        let server_requests = Arc::clone(&requests);
        let server_plan = plan.clone();
        let server_local = local.clone();
        let server = thread::spawn(move || {
            let mut next_asset = 100_u64;
            let mut ambiguous_create = matches!(scenario, Scenario::AmbiguousCreate);
            let mut ambiguous_delete = matches!(scenario, Scenario::AmbiguousDelete);
            let mut ambiguous_upload = matches!(scenario, Scenario::AmbiguousUpload);
            let mut ambiguous_publish = matches!(scenario, Scenario::AmbiguousPublish);
            while !server_done.load(Ordering::Acquire) {
                let (mut stream, _) = match listener.accept() {
                    Ok(value) => value,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::yield_now();
                        continue;
                    }
                    Err(error) => panic!("fake API accept failed: {error}"),
                };
                stream.set_nonblocking(false).unwrap();
                let bytes = request_bytes(&mut stream);
                if bytes.is_empty() {
                    continue;
                }
                let request = String::from_utf8_lossy(&bytes);
                let first = request.lines().next().unwrap_or_default().to_owned();
                server_requests.lock().unwrap().push(request.to_string());
                let path = first.split_whitespace().nth(1).unwrap_or_default();
                if path.ends_with("/immutable-releases") {
                    respond(&mut stream, "200 OK", "{\"enabled\":true}");
                } else if path.contains("/git/ref/heads/release") {
                    let branch_sha = if matches!(scenario, Scenario::MovedBranch) {
                        "9".repeat(40)
                    } else {
                        server_plan.resolution.candidate_sha.clone()
                    };
                    let body = format!(
                        "{{\"node_id\":\"n\",\"object\":{{\"sha\":\"{}\",\"type\":\"commit\",\"url\":\"u\"}},\"ref\":\"refs/heads/release\",\"url\":\"u\"}}",
                        branch_sha
                    );
                    respond(&mut stream, "200 OK", &body);
                } else if path.contains("/git/ref/tags/") {
                    if matches!(scenario, Scenario::ConcurrentTag)
                        || release.as_ref().is_some_and(|value| !value.draft)
                    {
                        let body = format!(
                            "{{\"node_id\":\"n\",\"object\":{{\"sha\":\"{}\",\"type\":\"commit\",\"url\":\"u\"}},\"ref\":\"refs/tags/{}\",\"url\":\"u\"}}",
                            server_plan.resolution.candidate_sha, server_plan.tag
                        );
                        respond(&mut stream, "200 OK", &body);
                    } else {
                        respond(&mut stream, "404 Not Found", "{}");
                    }
                } else if first.starts_with("GET ") && path.contains("/releases?per_page") {
                    let body = release.as_ref().map_or_else(
                        || "[]".to_owned(),
                        |value| {
                            format!("[{}]", fake_release_json(&server_plan, value, &upload_url))
                        },
                    );
                    respond(&mut stream, "200 OK", &body);
                } else if first.starts_with("GET ") && path.contains("/releases/tags/") {
                    if let Some(value) = release.as_ref().filter(|value| !value.draft) {
                        respond(
                            &mut stream,
                            "200 OK",
                            &fake_release_json(&server_plan, value, &upload_url),
                        );
                    } else {
                        respond(&mut stream, "404 Not Found", "{}");
                    }
                } else if first.starts_with("POST ") && path.ends_with("/releases") {
                    release = Some(FakeRelease {
                        draft: true,
                        immutable: false,
                        body: marker.clone(),
                        target: server_plan.resolution.candidate_sha.clone(),
                        assets: BTreeMap::new(),
                    });
                    if ambiguous_create {
                        ambiguous_create = false;
                    } else {
                        respond(
                            &mut stream,
                            "201 Created",
                            &fake_release_json(
                                &server_plan,
                                release.as_ref().unwrap(),
                                &upload_url,
                            ),
                        );
                    }
                } else if first.starts_with("DELETE ") && path.contains("/releases/assets/") {
                    let id = path.rsplit('/').next().unwrap().parse::<u64>().unwrap();
                    release
                        .as_mut()
                        .unwrap()
                        .assets
                        .retain(|_, asset| asset.0 != id);
                    respond(&mut stream, "204 No Content", "");
                } else if first.starts_with("DELETE ") && path.ends_with("/releases/7") {
                    release = None;
                    if ambiguous_delete {
                        ambiguous_delete = false;
                    } else {
                        respond(&mut stream, "204 No Content", "");
                    }
                } else if first.starts_with("POST ") && path.starts_with("/upload?name=") {
                    let name = path.strip_prefix("/upload?name=").unwrap().to_owned();
                    let (size, digest) = server_local.get(&name).unwrap();
                    release
                        .as_mut()
                        .unwrap()
                        .assets
                        .insert(name.clone(), (next_asset, *size, digest.clone()));
                    let body = format!(
                        "{{\"digest\":\"sha256:{digest}\",\"id\":{next_asset},\"name\":\"{name}\",\"size\":{size}}}"
                    );
                    next_asset += 1;
                    if ambiguous_upload {
                        ambiguous_upload = false;
                    } else {
                        respond(&mut stream, "201 Created", &body);
                    }
                } else if first.starts_with("PATCH ") && path.ends_with("/releases/7") {
                    let current = release.as_mut().unwrap();
                    current.draft = false;
                    current.immutable = true;
                    current.body = published_body.clone();
                    if ambiguous_publish {
                        ambiguous_publish = false;
                    } else {
                        respond(
                            &mut stream,
                            "200 OK",
                            &fake_release_json(&server_plan, current, &upload_url),
                        );
                    }
                } else {
                    panic!("unexpected fake API request: {first}");
                }
            }
        });
        let client = GitHubClient::for_test(address);
        let report = input.join("publication.json");
        let result = publish_with_client(&plan, &input, &report, &client);
        done.store(true, Ordering::Release);
        server.join().unwrap();
        let requests = requests.lock().unwrap().clone();
        std::fs::remove_dir_all(input).unwrap();
        (result, requests)
    }

    #[test]
    fn publisher_state_machine_transitions_use_observed_remote_state() {
        for scenario in [
            Scenario::Create,
            Scenario::ResumePartial,
            Scenario::Stale,
            Scenario::AmbiguousCreate,
            Scenario::AmbiguousDelete,
            Scenario::AmbiguousUpload,
            Scenario::AmbiguousPublish,
            Scenario::Immutable,
        ] {
            let (result, requests) = run_fake_publisher(scenario);
            assert!(result.is_ok(), "{result:?}\n{requests:#?}");
            assert!(requests.iter().any(|request| request.starts_with("GET ")));
            if matches!(scenario, Scenario::Stale | Scenario::AmbiguousDelete) {
                assert!(
                    requests
                        .iter()
                        .any(|request| request.starts_with("DELETE "))
                );
            }
            if matches!(scenario, Scenario::ResumePartial) {
                assert!(
                    requests
                        .iter()
                        .any(|request| request.contains("/releases/assets/40"))
                );
            }
            if matches!(scenario, Scenario::Immutable) {
                assert!(!requests.iter().any(|request| {
                    request.starts_with("POST ")
                        || request.starts_with("PATCH ")
                        || request.starts_with("DELETE ")
                }));
            } else {
                assert!(requests.iter().any(|request| request.starts_with("PATCH ")));
                assert!(requests.iter().any(|request| {
                    request.starts_with("GET ") && request.contains("/releases/tags/")
                }));
                let expected_draft = draft_request(
                    &plan(),
                    &format!("<!-- hell-rs-release-plan-sha256: {} -->", "f".repeat(64)),
                )
                .unwrap();
                if !matches!(scenario, Scenario::ResumePartial | Scenario::Immutable) {
                    assert!(requests.iter().any(|request| {
                        request.starts_with("POST /repos/o/r/releases ")
                            && request.ends_with(&expected_draft)
                    }));
                }
                let expected_publish = publish_request(
                    &plan(),
                    &format!(
                        "notes\n\n<!-- hell-rs-release-plan-sha256: {} -->",
                        "f".repeat(64)
                    ),
                )
                .unwrap();
                assert!(requests.iter().any(|request| {
                    request.starts_with("PATCH /repos/o/r/releases/7 ")
                        && request.ends_with(&expected_publish)
                }));
            }
        }
        let (human, requests) = run_fake_publisher(Scenario::Human);
        assert!(human.is_err());
        assert!(!requests.iter().any(|request| {
            request.starts_with("POST ")
                || request.starts_with("PATCH ")
                || request.starts_with("DELETE ")
        }));
        for scenario in [
            Scenario::MovedBranch,
            Scenario::ConcurrentTag,
            Scenario::PublishedConflict,
        ] {
            let (result, requests) = run_fake_publisher(scenario);
            assert!(result.is_err());
            assert!(!requests.iter().any(|request| {
                request.starts_with("POST ")
                    || request.starts_with("PATCH ")
                    || request.starts_with("DELETE ")
            }));
        }
        let (result, requests) = run_fake_publisher(Scenario::ImmutableAltered);
        assert!(result.is_err());
        assert!(!requests.iter().any(|request| {
            request.starts_with("POST ")
                || request.starts_with("PATCH ")
                || request.starts_with("DELETE ")
        }));
    }

    #[test]
    fn draft_and_publish_requests_bind_exact_plan() {
        let plan = plan();
        assert!(
            draft_request(&plan, "marker")
                .unwrap()
                .contains("\"draft\":true")
        );
        assert!(
            publish_request(&plan, "marker")
                .unwrap()
                .contains("\"draft\":false")
        );
    }

    #[test]
    fn release_classifier_rejects_conflicting_machine_markers() {
        let plan = plan();
        let marker = format!("<!-- hell-rs-release-plan-sha256: {} -->", plan.plan_sha256);
        let value = object([
            ("assets", JsonValue::Array(Vec::new())),
            ("body", string(&format!("{marker}\n{marker}"))),
            ("draft", JsonValue::Bool(true)),
            ("id", number(1)),
            ("prerelease", JsonValue::Bool(false)),
            ("tag_name", string(&plan.tag)),
            ("target_commitish", string(&plan.resolution.candidate_sha)),
            ("upload_url", string("https://uploads.github.com/upload")),
        ]);
        assert_eq!(
            classify(&value, &plan, &marker, &BTreeMap::new()).unwrap(),
            ExistingReleaseState::HumanConflict
        );
        let unicode_digest = format!(
            "<!-- hell-rs-release-plan-sha256: {} -->",
            "ａ".repeat(plan.plan_sha256.chars().count())
        );
        let value = object([
            ("assets", JsonValue::Array(Vec::new())),
            ("body", string(&unicode_digest)),
            ("draft", JsonValue::Bool(true)),
            ("id", number(1)),
            ("prerelease", JsonValue::Bool(false)),
            ("tag_name", string(&plan.tag)),
            ("target_commitish", string(&plan.resolution.candidate_sha)),
            ("upload_url", string("https://uploads.github.com/upload")),
        ]);
        assert_eq!(
            classify(&value, &plan, &marker, &BTreeMap::new()).unwrap(),
            ExistingReleaseState::HumanConflict
        );
        let uppercase = marker.to_ascii_uppercase();
        let value = object([
            ("assets", JsonValue::Array(Vec::new())),
            ("body", string(&uppercase)),
            ("draft", JsonValue::Bool(true)),
            ("id", number(1)),
            ("prerelease", JsonValue::Bool(false)),
            ("tag_name", string(&plan.tag)),
            ("target_commitish", string(&plan.resolution.candidate_sha)),
            ("upload_url", string("https://uploads.github.com/upload")),
        ]);
        assert_eq!(
            classify(&value, &plan, &marker, &BTreeMap::new()).unwrap(),
            ExistingReleaseState::HumanConflict
        );
    }

    #[test]
    fn published_metadata_is_exact_not_marker_only() {
        let plan = plan();
        let release = object([
            ("body", string("altered notes")),
            ("name", string("altered name")),
            ("tag_name", string(&plan.tag)),
        ]);
        assert!(require_exact_published_metadata(&release, &plan, "expected notes").is_err());
    }

    #[test]
    fn rejected_bundle_surface_mutations_make_zero_api_calls() {
        let plan = plan();
        let (input, _) = publication_fixture(&plan);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let client = GitHubClient::for_test(listener.local_addr().unwrap());
        let report = input.join("publication.json");
        let mutations = [
            "conformance-plan-bytes",
            "conformance-evidence-archive",
            "evidence-record",
            "observation-bytes",
            "report-cell",
            "report-count",
            "acceptance-decision",
            "release-manifest-conformance",
            "release-gate-subjects-digest",
            "subjects-exact-set",
            "platform-report-identity",
            "package-archive",
            "candidate-executable-identity",
            "trusted-inputs",
            "attestation-predicate-v1",
            "accepted-report-recomputation",
        ];
        for mutation in mutations {
            let result = publish_after_verification(
                &plan,
                &input,
                &report,
                &client,
                Err(format!("rejected mutated surface {mutation}")),
            );
            assert!(result.is_err(), "mutation {mutation} reached publication");
            assert!(
                matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
                "mutation {mutation} made a GitHub API call"
            );
        }
        std::fs::remove_dir_all(input).unwrap();
    }

    #[test]
    fn release_classifier_distinguishes_human_and_exact_immutable_states() {
        let plan = plan();
        let marker = format!("<!-- hell-rs-release-plan-sha256: {} -->", plan.plan_sha256);
        let common = |body: &str, draft: bool, immutable: bool| {
            object([
                ("assets", JsonValue::Array(Vec::new())),
                ("body", string(body)),
                ("draft", JsonValue::Bool(draft)),
                ("id", number(1)),
                ("immutable", JsonValue::Bool(immutable)),
                ("prerelease", JsonValue::Bool(false)),
                ("tag_name", string(&plan.tag)),
                ("target_commitish", string(&plan.resolution.candidate_sha)),
                ("upload_url", string("https://uploads.github.com/upload")),
            ])
        };
        assert_eq!(
            classify(
                &common("human notes", true, false),
                &plan,
                &marker,
                &BTreeMap::new()
            )
            .unwrap(),
            ExistingReleaseState::HumanConflict
        );
        assert_eq!(
            classify(
                &common(&marker, false, true),
                &plan,
                &marker,
                &BTreeMap::new()
            )
            .unwrap(),
            ExistingReleaseState::MatchingImmutable
        );
    }

    #[test]
    fn attestation_commands_bind_distinct_predicate_and_workflow_identity() {
        let command = attestation_command(
            std::path::Path::new("bundle"),
            "release-gate.json",
            "github-release-gate.sigstore.json",
            "o/r",
            "https://example.test/release-gate/v2",
            "https://github.com/o/r/.github/workflows/release.yml@refs/heads/main",
            &"b".repeat(40),
        );
        let arguments = command.display_arguments();
        assert!(arguments.windows(2).any(|pair| pair == ["--repo", "o/r"]));
        assert!(
            arguments.windows(2).any(|pair| {
                pair == ["--predicate-type", "https://example.test/release-gate/v2"]
            })
        );
        assert!(arguments.windows(2).any(|pair| {
            pair == [
                "--cert-identity",
                "https://github.com/o/r/.github/workflows/release.yml@refs/heads/main",
            ]
        }));
        assert!(arguments.windows(2).any(|pair| {
            pair == [
                "--signer-digest",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ]
        }));
    }
}
