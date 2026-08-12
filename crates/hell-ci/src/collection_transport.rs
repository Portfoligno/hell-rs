//! Typed collection-authority provider and attestation transport actions.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use flate2::read::GzDecoder;
use hell_testkit::{Digest, sha256_bytes, sha256_file};

use crate::assurance::{JsonValue, canonical_json_bytes, json_member, parse_json};

const GH_VERSION: &str = "2.93.0";
const GH_ARCHIVE_URL: &str =
    "https://github.com/cli/cli/releases/download/v2.93.0/gh_2.93.0_linux_amd64.tar.gz";
const GH_ARCHIVE_SHA256: &str = "02d1290eba130e0b896f3709ffff22e1c75a51475ddb70476a85abc6b5807af0";
const GH_CHECKSUMS_URL: &str =
    "https://github.com/cli/cli/releases/download/v2.93.0/gh_2.93.0_checksums.txt";
const GH_CHECKSUMS_SHA256: &str =
    "f62a3bc9dedc88262c9c2b56eb653cb3ded6bde8076bdbb151f4cce9c8729da5";
const GH_BINARY_SHA256: &str = "014fcd614de4de5b4a1441d298175684bad99f713d10296c5fcaaba47ac332d1";
const GH_ARCHIVE_NAME: &str = "gh_2.93.0_linux_amd64.tar.gz";
const GH_BINARY_MEMBER: &str = "gh_2.93.0_linux_amd64/bin/gh";
const REPOSITORY: &str = "Portfoligno/hell-rs";
const REPOSITORY_URI: &str = "https://github.com/Portfoligno/hell-rs";
const REPOSITORY_ID: u64 = 1_327_351_238;
const OWNER_URI: &str = "https://github.com/Portfoligno";
const OWNER_ID: &str = "38184478";
const WORKFLOW: &str = ".github/workflows/collection-authority.yml";
const SOURCE_REF: &str = "refs/heads/main";
const CERTIFICATE_IDENTITY: &str = "https://github.com/Portfoligno/hell-rs/.github/workflows/collection-authority.yml@refs/heads/main";
const OIDC_ISSUER: &str = "https://token.actions.githubusercontent.com";
const PREDICATE_TYPE: &str = "https://slsa.dev/provenance/v1";
static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

pub(crate) fn reviewed_gh_binary_sha256() -> &'static str {
    GH_BINARY_SHA256
}

pub(crate) fn recognizes(arguments: &[OsString]) -> bool {
    arguments.first().and_then(|argument| argument.to_str()) == Some("collection-authority")
        && arguments
            .get(1)
            .and_then(|argument| argument.to_str())
            .is_some_and(|action| {
                matches!(
                    action,
                    "acquire-provider" | "install-pinned-gh" | "capture-custody-attestation"
                )
            })
}

pub(crate) fn run(root: &Path, arguments: &[OsString]) -> Result<String, String> {
    match arguments.get(1).and_then(|argument| argument.to_str()) {
        Some("acquire-provider") => acquire_provider(root, &arguments[2..]),
        Some("install-pinned-gh") => install_pinned_gh(&arguments[2..]),
        Some("capture-custody-attestation") => capture_attestation(&arguments[2..]),
        _ => Err("unknown collection transport action".to_owned()),
    }
}

fn exact_options(
    arguments: &[OsString],
    names: &[&str],
) -> Result<BTreeMap<String, OsString>, String> {
    if arguments.len() != names.len() * 2 {
        return Err("collection transport arguments are incomplete or extra".to_owned());
    }
    let allowed = names.iter().copied().collect::<BTreeSet<_>>();
    let mut parsed = BTreeMap::new();
    for pair in arguments.chunks_exact(2) {
        let name = pair[0]
            .to_str()
            .and_then(|name| name.strip_prefix("--"))
            .ok_or_else(|| "collection transport option is malformed".to_owned())?;
        if !allowed.contains(name)
            || pair[1].is_empty()
            || parsed.insert(name.to_owned(), pair[1].clone()).is_some()
        {
            return Err("collection transport option is unknown, empty, or duplicate".to_owned());
        }
    }
    if parsed.len() != names.len() {
        return Err("collection transport option is missing".to_owned());
    }
    Ok(parsed)
}

fn option_path(options: &BTreeMap<String, OsString>, name: &str) -> PathBuf {
    PathBuf::from(&options[name])
}

fn option_text<'a>(options: &'a BTreeMap<String, OsString>, name: &str) -> Result<&'a str, String> {
    options[name]
        .to_str()
        .ok_or_else(|| format!("collection transport --{name} is not UTF-8"))
}

fn option_positive(options: &BTreeMap<String, OsString>, name: &str) -> Result<u64, String> {
    option_text(options, name)?
        .parse::<u64>()
        .ok()
        .filter(|value| *value != 0)
        .ok_or_else(|| format!("collection transport --{name} is not positive"))
}

fn require_commit(value: &str, label: &str) -> Result<(), String> {
    let mut chunks = value.as_bytes().chunks_exact(2);
    let decoded = chunks
        .by_ref()
        .map(|digits| hex_byte(digits[0], digits[1]))
        .collect::<Option<Vec<_>>>();
    if !chunks.remainder().is_empty()
        || decoded
            .as_deref()
            .and_then(|bytes| <&[u8; 20]>::try_from(bytes).ok())
            .is_none()
    {
        return Err(format!("{label} is not a lowercase full Git commit"));
    }
    Ok(())
}

fn hex_byte(high: u8, low: u8) -> Option<u8> {
    let nibble = |value| match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    };
    Some((nibble(high)? << 4) | nibble(low)?)
}

fn private_temporary(label: &str) -> Result<PathBuf, String> {
    let path = std::env::temp_dir().join(format!(
        "hell-collection-{label}-{}-{}",
        std::process::id(),
        NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&path).map_err(|error| format!("cannot create temporary directory: {error}"))?;
    Ok(path)
}

fn run_bounded_command(
    command: &mut Command,
    label: &str,
    maximum_stdout: u64,
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    let temporary = private_temporary("bounded-command")?;
    let stdout_path = temporary.join("stdout.bin");
    let stderr_path = temporary.join("stderr.bin");
    let result = run_bounded_command_in(
        command,
        label,
        maximum_stdout,
        timeout,
        &stdout_path,
        &stderr_path,
    );
    let cleanup = fs::remove_dir_all(&temporary)
        .map_err(|error| format!("cannot remove bounded-command temporary directory: {error}"));
    match (result, cleanup) {
        (Ok(bytes), Ok(())) => Ok(bytes),
        (Err(error), _) | (Ok(_), Err(error)) => Err(error),
    }
}

fn run_bounded_command_in(
    command: &mut Command,
    label: &str,
    maximum_stdout: u64,
    timeout: Duration,
    stdout_path: &Path,
    stderr_path: &Path,
) -> Result<Vec<u8>, String> {
    let stdout = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(stdout_path)
        .map_err(|error| format!("cannot create bounded stdout: {error}"))?;
    let stderr = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(stderr_path)
        .map_err(|error| format!("cannot create bounded stderr: {error}"))?;
    let mut child = command
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .map_err(|error| format!("cannot invoke {label}: {error}"))?;
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("cannot inspect {label}: {error}"));
            }
        }
        let stdout_size = fs::metadata(stdout_path).map_or(0, |metadata| metadata.len());
        let stderr_size = fs::metadata(stderr_path).map_or(0, |metadata| metadata.len());
        if stdout_size > maximum_stdout || stderr_size > 1024 * 1024 || started.elapsed() > timeout
        {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("{label} exceeded its reviewed resource bound"));
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let stdout = fs::read(stdout_path).map_err(|error| format!("cannot read {label}: {error}"))?;
    let stderr = fs::read(stderr_path)
        .map_err(|error| format!("cannot read {label} diagnostics: {error}"))?;
    if !status.success() || stdout.is_empty() || stdout.len() as u64 > maximum_stdout {
        return Err(format!(
            "{label} failed: {}",
            String::from_utf8_lossy(&stderr)
        ));
    }
    Ok(stdout)
}

fn download_with_curl(url: &str, destination: &Path, maximum: u64) -> Result<Vec<u8>, String> {
    let maximum_argument = maximum.to_string();
    let status = Command::new("curl")
        .args(["--fail", "--location", "--silent", "--show-error"])
        .args(["--max-time", "60", "--max-filesize"])
        .arg(&maximum_argument)
        .arg("--output")
        .arg(destination)
        .arg(url)
        .stdin(Stdio::null())
        .status()
        .map_err(|error| format!("cannot invoke reviewed download transport: {error}"))?;
    if !status.success() {
        return Err("reviewed download transport failed".to_owned());
    }
    let metadata = fs::symlink_metadata(destination)
        .map_err(|error| format!("cannot inspect downloaded file: {error}"))?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > maximum {
        return Err("reviewed download has an invalid file type or size".to_owned());
    }
    fs::read(destination).map_err(|error| format!("cannot read downloaded file: {error}"))
}

struct GhArchive {
    binary: Vec<u8>,
    inventory_sha256: Digest,
    member_count: u64,
}

fn inspect_gh_archive(bytes: &[u8]) -> Result<GhArchive, String> {
    let mut archive = tar::Archive::new(GzDecoder::new(bytes));
    let mut inventory = Vec::new();
    let mut names = BTreeSet::new();
    let mut binary = None;
    for entry in archive
        .entries()
        .map_err(|error| format!("cannot read reviewed gh archive: {error}"))?
    {
        let mut entry = entry.map_err(|error| format!("cannot read gh archive entry: {error}"))?;
        let path = entry
            .path()
            .map_err(|error| format!("cannot decode gh archive path: {error}"))?
            .into_owned();
        if path.is_absolute()
            || path
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err("reviewed gh archive contains an unsafe path".to_owned());
        }
        let name = path
            .to_str()
            .ok_or_else(|| "reviewed gh archive path is not UTF-8".to_owned())?;
        if !names.insert(name.to_owned()) {
            return Err("reviewed gh archive contains a duplicate path".to_owned());
        }
        let kind = if entry.header().entry_type().is_dir() {
            "directory"
        } else if entry.header().entry_type().is_file() {
            "file"
        } else {
            return Err("reviewed gh archive contains a non-file entry".to_owned());
        };
        let mode = entry
            .header()
            .mode()
            .map_err(|error| format!("cannot read gh archive mode: {error}"))?;
        let size = entry
            .header()
            .size()
            .map_err(|error| format!("cannot read gh archive size: {error}"))?;
        inventory.extend_from_slice(format!("{name}\t{kind}\t{mode:04o}\t{size}\n").as_bytes());
        if name == GH_BINARY_MEMBER {
            if kind != "file" || mode != 0o755 || binary.is_some() {
                return Err("reviewed gh archive executable identity is invalid".to_owned());
            }
            let mut retained = Vec::new();
            entry
                .read_to_end(&mut retained)
                .map_err(|error| format!("cannot read gh executable: {error}"))?;
            if retained.len() as u64 != size {
                return Err("reviewed gh executable size differs".to_owned());
            }
            binary = Some(retained);
        }
    }
    let binary = binary.ok_or_else(|| "reviewed gh archive omits its executable".to_owned())?;
    Ok(GhArchive {
        binary,
        inventory_sha256: sha256_bytes(&inventory),
        member_count: names.len() as u64,
    })
}

fn install_pinned_gh(arguments: &[OsString]) -> Result<String, String> {
    let options = exact_options(arguments, &["output"])?;
    let output = option_path(&options, "output");
    if output.exists() {
        return Err("pinned gh output already exists".to_owned());
    }
    let temporary = private_temporary("gh-install")?;
    let result = install_pinned_gh_in(&output, &temporary);
    let cleanup = fs::remove_dir_all(&temporary)
        .map_err(|error| format!("cannot remove gh installer temporary directory: {error}"));
    match (result, cleanup) {
        (Ok(()), Ok(())) => {}
        (Err(error), _) => {
            if output.exists() {
                fs::remove_dir_all(&output).map_err(|cleanup| {
                    format!("{error}; cannot remove partial output: {cleanup}")
                })?;
            }
            return Err(error);
        }
        (Ok(()), Err(error)) => return Err(error),
    }
    Ok(format!(
        "installed reviewed gh {GH_VERSION} at {}",
        output.display()
    ))
}

fn install_pinned_gh_in(output: &Path, temporary: &Path) -> Result<(), String> {
    let checksums = download_with_curl(
        GH_CHECKSUMS_URL,
        &temporary.join("checksums.txt"),
        1024 * 1024,
    )?;
    if sha256_bytes(&checksums).hex() != GH_CHECKSUMS_SHA256 {
        return Err("reviewed gh checksums digest differs".to_owned());
    }
    let expected_line = format!("{GH_ARCHIVE_SHA256}  {GH_ARCHIVE_NAME}");
    let checksums_text = std::str::from_utf8(&checksums)
        .map_err(|_| "reviewed gh checksums are not UTF-8".to_owned())?;
    if checksums_text
        .lines()
        .filter(|line| line.ends_with(GH_ARCHIVE_NAME))
        .collect::<Vec<_>>()
        != [expected_line.as_str()]
    {
        return Err("reviewed gh checksums omit or duplicate the archive".to_owned());
    }
    let archive_bytes = download_with_curl(
        GH_ARCHIVE_URL,
        &temporary.join(GH_ARCHIVE_NAME),
        64 * 1024 * 1024,
    )?;
    if sha256_bytes(&archive_bytes).hex() != GH_ARCHIVE_SHA256 {
        return Err("reviewed gh archive digest differs".to_owned());
    }
    let inspected = inspect_gh_archive(&archive_bytes)?;
    if sha256_bytes(&inspected.binary).hex() != GH_BINARY_SHA256 {
        return Err("reviewed gh executable digest differs".to_owned());
    }
    fs::create_dir(output).map_err(|error| format!("cannot create pinned gh output: {error}"))?;
    write_exclusive(&output.join("gh"), &inspected.binary)?;
    set_executable(&output.join("gh"))?;
    let manifest = gh_install_manifest(&inspected, &expected_line);
    write_exclusive(
        &output.join("gh-install-manifest.json"),
        &canonical_json_bytes(&manifest)?,
    )?;
    Ok(())
}

fn gh_install_manifest(archive: &GhArchive, checksums_entry: &str) -> JsonValue {
    JsonValue::Object(BTreeMap::from([
        (
            "archiveInventorySha256".to_owned(),
            JsonValue::String(archive.inventory_sha256.hex()),
        ),
        (
            "archiveMemberCount".to_owned(),
            JsonValue::Number(archive.member_count),
        ),
        (
            "binaryArchivePath".to_owned(),
            JsonValue::String(GH_BINARY_MEMBER.to_owned()),
        ),
        (
            "binaryMode".to_owned(),
            JsonValue::String("0755".to_owned()),
        ),
        (
            "ghArchiveSha256".to_owned(),
            JsonValue::String(GH_ARCHIVE_SHA256.to_owned()),
        ),
        (
            "ghArchiveUrl".to_owned(),
            JsonValue::String(GH_ARCHIVE_URL.to_owned()),
        ),
        (
            "ghBinarySha256".to_owned(),
            JsonValue::String(GH_BINARY_SHA256.to_owned()),
        ),
        (
            "ghChecksumsEntry".to_owned(),
            JsonValue::String(checksums_entry.to_owned()),
        ),
        (
            "ghChecksumsSha256".to_owned(),
            JsonValue::String(GH_CHECKSUMS_SHA256.to_owned()),
        ),
        (
            "ghChecksumsUrl".to_owned(),
            JsonValue::String(GH_CHECKSUMS_URL.to_owned()),
        ),
        (
            "ghReleaseVersion".to_owned(),
            JsonValue::String(GH_VERSION.to_owned()),
        ),
        (
            "schema".to_owned(),
            JsonValue::String("hell.collection-custody.gh-install.v1".to_owned()),
        ),
    ]))
}

fn write_exclusive(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("cannot create transport output directory: {error}"))?;
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("cannot create {}: {error}", path.display()))?;
    output
        .write_all(bytes)
        .map_err(|error| format!("cannot write {}: {error}", path.display()))
}

#[cfg(unix)]
fn set_executable(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
        .map_err(|error| format!("cannot mark reviewed gh executable: {error}"))
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) -> Result<(), String> {
    Ok(())
}

struct ProviderRequest {
    repository: String,
    run_id: u64,
    run_attempt: u64,
    provider_head: String,
    candidate: String,
    workflow: String,
    gh: PathBuf,
    install_manifest: PathBuf,
    output: PathBuf,
    artifacts: [(String, u64); 3],
}

fn acquire_provider(root: &Path, arguments: &[OsString]) -> Result<String, String> {
    let options = exact_options(
        arguments,
        &[
            "repository",
            "run-id",
            "run-attempt",
            "provider-head",
            "candidate-commit",
            "workflow-path",
            "linux-artifact-id",
            "macos-artifact-id",
            "windows-artifact-id",
            "gh-executable",
            "gh-install-manifest",
            "output",
        ],
    )?;
    let request = ProviderRequest {
        repository: option_text(&options, "repository")?.to_owned(),
        run_id: option_positive(&options, "run-id")?,
        run_attempt: option_positive(&options, "run-attempt")?,
        provider_head: option_text(&options, "provider-head")?.to_owned(),
        candidate: option_text(&options, "candidate-commit")?.to_owned(),
        workflow: option_text(&options, "workflow-path")?.to_owned(),
        gh: option_path(&options, "gh-executable"),
        install_manifest: option_path(&options, "gh-install-manifest"),
        output: option_path(&options, "output"),
        artifacts: [
            (
                "linux-amd64".to_owned(),
                option_positive(&options, "linux-artifact-id")?,
            ),
            (
                "macos-arm64".to_owned(),
                option_positive(&options, "macos-artifact-id")?,
            ),
            (
                "windows-amd64".to_owned(),
                option_positive(&options, "windows-artifact-id")?,
            ),
        ],
    };
    validate_provider_request(root, &request)?;
    fs::create_dir(&request.output)
        .map_err(|error| format!("cannot create collection provider output: {error}"))?;
    let configuration = request.output.join(".gh-config");
    fs::create_dir(&configuration)
        .map_err(|error| format!("cannot create provider gh configuration: {error}"))?;
    let result = acquire_provider_validated(root, &request, &configuration);
    let configuration_cleanup = fs::remove_dir_all(&configuration)
        .map_err(|error| format!("cannot remove provider gh configuration: {error}"));
    let result = match (result, configuration_cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), _) | (Ok(()), Err(error)) => Err(error),
    };
    finalize_provider_acquisition(&request, result)?;
    Ok(format!(
        "acquired exact collection provider campaign at {}",
        request.output.display()
    ))
}

fn finalize_provider_acquisition(
    request: &ProviderRequest,
    result: Result<(), String>,
) -> Result<(), String> {
    if let Err(error) = result {
        let mut cleanup_errors = Vec::new();
        for path in provider_output_paths(request) {
            if path.exists()
                && let Err(cleanup) = fs::remove_dir_all(&path)
            {
                cleanup_errors.push(cleanup.to_string());
            }
        }
        return if cleanup_errors.is_empty() {
            Err(error)
        } else {
            Err(format!(
                "{error}; partial provider cleanup failed: {}",
                cleanup_errors.join(", ")
            ))
        };
    }
    Ok(())
}

fn acquire_provider_validated(
    root: &Path,
    request: &ProviderRequest,
    configuration: &Path,
) -> Result<(), String> {
    retain_provider_transport(request)?;
    let run = provider_json(
        request,
        configuration,
        &provider_endpoint(request, &["actions", "runs"], Some(request.run_id))?,
    )?;
    validate_provider_run(run.object()?, request)?;
    let artifact_pages = provider_pages(request, configuration, "artifacts")?;
    let job_pages = provider_pages(request, configuration, "jobs")?;
    write_provider_pages(&request.output.join("artifact-api-pages"), &artifact_pages)?;
    write_provider_pages(&request.output.join("job-api-pages"), &job_pages)?;
    let workflow_bytes = provider_workflow_at(root, request)?;
    if !workflow_bytes.starts_with(b"name: Collection Authority\n") {
        return Err("collection provider workflow is not exact".to_owned());
    }
    let observed_at = crate::custody_ops::current_utc_timestamp()?;
    let jobs = select_provider_jobs(&job_pages, request)?;
    for (platform, artifact_id) in &request.artifacts {
        retain_provider_platform_input(&RetainPlatformInput {
            request,
            platform,
            artifact_id: *artifact_id,
            run: &run,
            workflow_bytes: &workflow_bytes,
            artifact_pages: &artifact_pages,
            job_pages: &job_pages,
            job: jobs[platform].clone(),
            observed_at: &observed_at,
            configuration,
        })?;
    }
    Ok(())
}

fn provider_output_paths(request: &ProviderRequest) -> Vec<PathBuf> {
    let mut paths = vec![request.output.clone()];
    if let Some(parent) = request.output.parent() {
        paths.extend(
            request
                .artifacts
                .iter()
                .map(|(platform, _)| parent.join("native-shards").join(platform)),
        );
    }
    paths
}

fn provider_workflow_at(root: &Path, request: &ProviderRequest) -> Result<Vec<u8>, String> {
    let listing = Command::new("git")
        .arg("-C")
        .arg(root)
        .arg("ls-tree")
        .arg(&request.provider_head)
        .arg("--")
        .arg(&request.workflow)
        .output()
        .map_err(|error| format!("cannot inspect provider-head workflow: {error}"))?;
    if !listing.status.success() || !listing.stderr.is_empty() {
        return Err("cannot inspect exact provider-head workflow".to_owned());
    }
    let text = std::str::from_utf8(&listing.stdout)
        .map_err(|_| "provider workflow tree row is not UTF-8".to_owned())?;
    let rows = text.lines().collect::<Vec<_>>();
    let [row] = rows.as_slice() else {
        return Err("provider workflow tree row is not unique".to_owned());
    };
    let (identity, path) = row
        .split_once('\t')
        .ok_or_else(|| "provider workflow tree row is malformed".to_owned())?;
    let fields = identity.split_whitespace().collect::<Vec<_>>();
    let [mode, kind, object_id] = fields.as_slice() else {
        return Err("provider workflow tree identity is malformed".to_owned());
    };
    require_commit(object_id, "provider workflow blob")?;
    if *mode != "100644" || *kind != "blob" || path != request.workflow {
        return Err("provider workflow tree identity differs".to_owned());
    }
    let content = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["cat-file", "blob"])
        .arg(object_id)
        .output()
        .map_err(|error| format!("cannot read provider workflow blob: {error}"))?;
    if !content.status.success() || !content.stderr.is_empty() || content.stdout.is_empty() {
        return Err("cannot read exact provider workflow blob".to_owned());
    }
    Ok(content.stdout)
}

fn validate_provider_request(root: &Path, request: &ProviderRequest) -> Result<(), String> {
    if request.repository != REPOSITORY
        || request.workflow != WORKFLOW
        || provider_output_paths(request)
            .iter()
            .any(|path| path.exists())
    {
        return Err("collection provider request repository/workflow/output is invalid".to_owned());
    }
    require_commit(&request.provider_head, "collection provider head")?;
    require_commit(&request.candidate, "collection candidate commit")?;
    validate_reviewed_gh_install(&request.gh, &request.install_manifest)?;
    let ids = request
        .artifacts
        .iter()
        .map(|(_, id)| *id)
        .collect::<BTreeSet<_>>();
    if ids.len() != 3 {
        return Err("collection provider artifact IDs are not unique".to_owned());
    }
    let checkout = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["rev-parse", "HEAD"])
        .output()
        .map_err(|error| format!("cannot inspect provider checkout: {error}"))?;
    if !checkout.status.success()
        || std::str::from_utf8(&checkout.stdout)
            .map_err(|_| "provider checkout identity is not UTF-8".to_owned())?
            .trim()
            != request.provider_head
    {
        return Err("collection provider checkout differs from provider head".to_owned());
    }
    Ok(())
}

fn retain_provider_transport(request: &ProviderRequest) -> Result<(), String> {
    let directory = request.output.join("transport");
    fs::create_dir(&directory)
        .map_err(|error| format!("cannot create retained provider transport: {error}"))?;
    fs::copy(
        &request.install_manifest,
        directory.join("gh-install-manifest.json"),
    )
    .map_err(|error| format!("cannot retain provider gh manifest: {error}"))?;
    Ok(())
}

fn provider_endpoint(
    request: &ProviderRequest,
    suffix: &[&str],
    identifier: Option<u64>,
) -> Result<PathBuf, String> {
    let mut endpoint = PathBuf::from("repos");
    for component in request.repository.split('/') {
        if component.is_empty()
            || !component
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err("collection repository component is invalid".to_owned());
        }
        endpoint.push(component);
    }
    for component in suffix {
        endpoint.push(component);
    }
    if let Some(identifier) = identifier {
        endpoint.push(identifier.to_string());
    }
    Ok(endpoint)
}

fn provider_command(
    request: &ProviderRequest,
    configuration: &Path,
    endpoint: &Path,
) -> Result<Command, String> {
    let token = std::env::var("GITHUB_TOKEN")
        .map_err(|_| "collection provider acquisition requires GITHUB_TOKEN".to_owned())?;
    let mut command = Command::new(&request.gh);
    command
        .args(["api", "--method", "GET"])
        .arg(endpoint)
        .stdin(Stdio::null());
    configure_provider_environment(&mut command, configuration, &token);
    Ok(command)
}

fn configure_provider_environment(command: &mut Command, configuration: &Path, token: &str) {
    for name in [
        "GH_AUTH_TOKEN",
        "GH_ENTERPRISE_TOKEN",
        "GITHUB_ENTERPRISE_TOKEN",
        "GITHUB_HOST",
        "GITHUB_TOKEN",
    ] {
        command.env_remove(name);
    }
    command
        .env("GH_TOKEN", token)
        .env("GH_CONFIG_DIR", configuration)
        .env("GH_HOST", "github.com")
        .env("GH_PAGER", "cat")
        .env("NO_COLOR", "1");
}

fn provider_json(
    request: &ProviderRequest,
    configuration: &Path,
    endpoint: &Path,
) -> Result<JsonValue, String> {
    let mut command = provider_command(request, configuration, endpoint)?;
    let bytes = run_bounded_command(
        &mut command,
        "collection provider API",
        32 * 1024 * 1024,
        Duration::from_mins(1),
    )?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| "collection provider API JSON is not UTF-8".to_owned())?;
    parse_json(text)
}

fn provider_pages(
    request: &ProviderRequest,
    configuration: &Path,
    kind: &str,
) -> Result<Vec<JsonValue>, String> {
    let endpoint = if kind == "artifacts" {
        provider_endpoint(request, &["actions", "runs"], Some(request.run_id))?.join("artifacts")
    } else if kind == "jobs" {
        provider_endpoint(request, &["actions", "runs"], Some(request.run_id))?
            .join("attempts")
            .join(request.run_attempt.to_string())
            .join("jobs")
    } else {
        return Err("collection provider page kind is invalid".to_owned());
    };
    let probe = provider_json(request, configuration, &endpoint)?;
    let total = json_member(probe.object()?, "total_count")?.number()?;
    if total == 0 {
        return Err("collection provider pagination is empty".to_owned());
    }
    let page_count = usize::try_from(total.div_ceil(100))
        .map_err(|_| "collection provider pagination count overflows".to_owned())?;
    if page_count > 100 {
        return Err("collection provider pagination exceeds the reviewed bound".to_owned());
    }
    let mut command = provider_command(request, configuration, &endpoint)?;
    command.args(["--paginate", "--slurp", "--field", "per_page=100"]);
    let bytes = run_bounded_command(
        &mut command,
        "bounded collection provider pagination",
        64 * 1024 * 1024,
        Duration::from_mins(2),
    )?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| "collection provider pages are not UTF-8".to_owned())?;
    let JsonValue::Array(pages) = parse_json(text)? else {
        return Err("collection provider pagination is not an array".to_owned());
    };
    if pages.len() != page_count {
        return Err("collection provider pagination page count differs from probe".to_owned());
    }
    validate_complete_pages(&pages, kind)?;
    Ok(pages)
}

fn validate_complete_pages(pages: &[JsonValue], kind: &str) -> Result<(), String> {
    if pages.is_empty() || pages.len() > 100 {
        return Err("collection provider pagination count is outside the bound".to_owned());
    }
    let key = if kind == "artifacts" {
        "artifacts"
    } else {
        "jobs"
    };
    let mut total = None;
    let mut observed = 0_u64;
    let mut identifiers = BTreeSet::new();
    let mut previous = None;
    for page in pages {
        let page = page.object()?;
        let page_total = json_member(page, "total_count")?.number()?;
        if total
            .replace(page_total)
            .is_some_and(|expected| expected != page_total)
        {
            return Err("collection provider pagination total changed".to_owned());
        }
        let entries = json_member(page, key)?.array()?;
        if entries.is_empty() || entries.len() > 100 {
            return Err("collection provider page length is invalid".to_owned());
        }
        observed += entries.len() as u64;
        for entry in entries {
            let id = json_member(entry.object()?, "id")?.number()?;
            if id == 0 || !identifiers.insert(id) {
                return Err("collection provider page duplicates an identifier".to_owned());
            }
            if kind == "artifacts" && previous.is_some_and(|prior| prior <= id) {
                return Err("collection artifact IDs are not strictly descending".to_owned());
            }
            previous = Some(id);
        }
    }
    if total != Some(observed)
        || pages.len() != usize::try_from(observed.div_ceil(100)).unwrap_or(usize::MAX)
    {
        return Err("collection provider pages do not cover the exact total".to_owned());
    }
    Ok(())
}

fn write_provider_pages(directory: &Path, pages: &[JsonValue]) -> Result<(), String> {
    fs::create_dir(directory)
        .map_err(|error| format!("cannot create collection provider page directory: {error}"))?;
    for (index, page) in pages.iter().enumerate() {
        write_exclusive(
            &directory.join(format!("page-{:04}.json", index + 1)),
            &canonical_json_bytes(page)?,
        )?;
    }
    Ok(())
}

fn validate_provider_run(
    run: &BTreeMap<String, JsonValue>,
    request: &ProviderRequest,
) -> Result<(), String> {
    let repository = json_member(run, "repository")?.object()?;
    if json_member(run, "id")?.number()? != request.run_id
        || json_member(run, "run_attempt")?.number()? != request.run_attempt
        || json_member(run, "head_sha")?.string()? != request.provider_head
        || json_member(run, "path")?.string()? != request.workflow
        || json_member(run, "event")?.string()? != "workflow_dispatch"
        || json_member(run, "head_branch")?.string()? != "main"
        || json_member(repository, "full_name")?.string()? != REPOSITORY
        || json_member(repository, "id")?.number()? != REPOSITORY_ID
        || !matches!(
            json_member(run, "status")?.string()?,
            "in_progress" | "completed"
        )
    {
        return Err("collection provider run identity differs".to_owned());
    }
    Ok(())
}

fn page_entries<'a>(pages: &'a [JsonValue], key: &str) -> Result<Vec<&'a JsonValue>, String> {
    let mut entries = Vec::new();
    for page in pages {
        entries.extend(json_member(page.object()?, key)?.array()?);
    }
    Ok(entries)
}

fn select_provider_jobs(
    pages: &[JsonValue],
    request: &ProviderRequest,
) -> Result<BTreeMap<String, JsonValue>, String> {
    let expected = [
        ("linux-amd64", "Collection authority / Linux amd64"),
        ("macos-arm64", "Collection authority / macOS arm64"),
        ("windows-amd64", "Collection authority / Windows amd64"),
    ];
    let entries = page_entries(pages, "jobs")?;
    let mut selected = BTreeMap::new();
    for (platform, name) in expected {
        let matches = entries
            .iter()
            .filter(|entry| {
                entry
                    .object()
                    .ok()
                    .and_then(|object| json_member(object, "name").ok())
                    .and_then(|value| value.string().ok())
                    == Some(name)
            })
            .collect::<Vec<_>>();
        let [job] = matches.as_slice() else {
            return Err("collection producer job is not unique".to_owned());
        };
        let object = job.object()?;
        if json_member(object, "status")?.string()? != "completed"
            || json_member(object, "conclusion")?.string()? != "success"
            || json_member(object, "run_id")?.number()? != request.run_id
            || json_member(object, "run_attempt")?.number()? != request.run_attempt
        {
            return Err("collection producer job did not complete successfully".to_owned());
        }
        selected.insert(platform.to_owned(), (**job).clone());
    }
    Ok(selected)
}

struct RetainPlatformInput<'a> {
    request: &'a ProviderRequest,
    platform: &'a str,
    artifact_id: u64,
    run: &'a JsonValue,
    workflow_bytes: &'a [u8],
    artifact_pages: &'a [JsonValue],
    job_pages: &'a [JsonValue],
    job: JsonValue,
    observed_at: &'a str,
    configuration: &'a Path,
}

struct RetainedProviderArchive {
    archive_sha256: Digest,
    archive_size: u64,
    extracted: PathBuf,
    tree_sha256: String,
    inventory_count: u64,
}

fn retain_provider_platform_input(input: &RetainPlatformInput<'_>) -> Result<(), String> {
    let RetainPlatformInput {
        request,
        platform,
        artifact_id,
        run,
        workflow_bytes,
        artifact_pages,
        job_pages,
        job,
        observed_at,
        configuration,
    } = input;
    let expected_name = format!(
        "collection-authority-{platform}-{}-{}",
        request.run_id, request.run_attempt
    );
    let (artifact, artifact_page) = select_page_entry(
        artifact_pages,
        "artifacts",
        *artifact_id,
        Some(&expected_name),
    )?;
    let job_id = json_member(job.object()?, "id")?.number()?;
    let (_, job_page) = select_page_entry(job_pages, "jobs", job_id, None)?;
    validate_artifact(
        artifact.object()?,
        request,
        *artifact_id,
        &expected_name,
        observed_at,
    )?;
    let directory = request.output.join(platform);
    fs::create_dir(&directory)
        .map_err(|error| format!("cannot create collection platform output: {error}"))?;
    write_exclusive(
        &directory.join("provider-selected-run.json"),
        &canonical_json_bytes(run)?,
    )?;
    write_exclusive(
        &directory.join("provider-selected-artifact.json"),
        &canonical_json_bytes(artifact)?,
    )?;
    write_exclusive(&directory.join("provider-workflow.yml"), workflow_bytes)?;
    let retained = retain_provider_archive(
        request,
        configuration,
        platform,
        *artifact_id,
        artifact,
        &directory,
    )?;
    let install = validate_reviewed_gh_install(&request.gh, &request.install_manifest)?;
    let selection = provider_selection(&ProviderSelectionInput {
        request,
        platform,
        artifact_id: *artifact_id,
        artifact_name: &expected_name,
        archive: retained.archive_sha256,
        archive_size: retained.archive_size,
        artifact_page,
        job_page,
        job_id,
        job_name: json_member(job.object()?, "name")?.string()?,
        tree: &retained.tree_sha256,
        inventory_count: retained.inventory_count,
        observed_at,
        gh_install_manifest_sha256: install.manifest_sha256,
    });
    write_exclusive(
        &directory.join("selection.json"),
        &canonical_json_bytes(&selection)?,
    )?;
    let copied = request
        .output
        .parent()
        .ok_or_else(|| "collection provider output has no parent".to_owned())?
        .join("native-shards")
        .join(platform);
    copy_regular_tree(&retained.extracted, &copied)
}

fn retain_provider_archive(
    request: &ProviderRequest,
    configuration: &Path,
    platform: &str,
    artifact_id: u64,
    artifact: &JsonValue,
    directory: &Path,
) -> Result<RetainedProviderArchive, String> {
    let archive_endpoint =
        provider_endpoint(request, &["actions", "artifacts"], Some(artifact_id))?.join("zip");
    let artifact_object = artifact.object()?;
    let expected_size = json_member(artifact_object, "size_in_bytes")?.number()?;
    if expected_size == 0 || expected_size > 4 * 1024 * 1024 * 1024 {
        return Err("collection archive size is outside the reviewed bound".to_owned());
    }
    let mut archive_command = provider_command(request, configuration, &archive_endpoint)?;
    let archive = run_bounded_command(
        &mut archive_command,
        "collection provider archive",
        expected_size,
        Duration::from_mins(5),
    )?;
    let archive_sha256 = sha256_bytes(&archive);
    let provider_digest = json_member(artifact_object, "digest")?
        .string()?
        .strip_prefix("sha256:")
        .ok_or_else(|| "collection artifact digest is not SHA-256".to_owned())?;
    if archive_sha256.hex() != provider_digest || archive.len() as u64 != expected_size {
        return Err("collection archive bytes differ from provider object".to_owned());
    }
    let archive_path = directory.join("provider-archive.zip");
    write_exclusive(&archive_path, &archive)?;
    let extracted = directory.join("extracted").join(platform);
    crate::assurance::extract_external_zip(&archive_path, &extracted)?;
    let subject = extracted.join("collection-evidence/provider-subject.json");
    let observations = extracted.join("collection-evidence/observations");
    if !subject.is_file() || !observations.is_dir() || directory_count(&observations)? != 1_191 {
        return Err("collection archive lacks exact campaign evidence".to_owned());
    }
    let (tree_sha256, inventory_count) =
        crate::assurance::collection_provider_archive_tree_identity(&archive, &extracted)?;
    Ok(RetainedProviderArchive {
        archive_sha256,
        archive_size: archive.len() as u64,
        extracted,
        tree_sha256,
        inventory_count,
    })
}

fn select_page_entry<'a>(
    pages: &'a [JsonValue],
    key: &str,
    id: u64,
    expected_name: Option<&str>,
) -> Result<(&'a JsonValue, usize), String> {
    let mut matches = Vec::new();
    let mut name_count = 0_usize;
    for (page_index, page) in pages.iter().enumerate() {
        for entry in json_member(page.object()?, key)?.array()? {
            if expected_name.is_some_and(|name| {
                entry
                    .object()
                    .ok()
                    .and_then(|object| json_member(object, "name").ok())
                    .and_then(|value| value.string().ok())
                    == Some(name)
            }) {
                name_count += 1;
            }
            if json_member(entry.object()?, "id")?.number()? == id {
                matches.push((entry, page_index + 1));
            }
        }
    }
    let [(entry, page)] = matches.as_slice() else {
        return Err("collection selected provider object is not unique".to_owned());
    };
    if expected_name.is_some_and(|name| {
        entry
            .object()
            .and_then(|object| json_member(object, "name"))
            .and_then(JsonValue::string)
            .ok()
            != Some(name)
    }) || (expected_name.is_some() && name_count != 1)
    {
        return Err("collection selected artifact name differs".to_owned());
    }
    Ok((entry, *page))
}

fn validate_artifact(
    artifact: &BTreeMap<String, JsonValue>,
    request: &ProviderRequest,
    artifact_id: u64,
    name: &str,
    observed_at: &str,
) -> Result<(), String> {
    let workflow_run = json_member(artifact, "workflow_run")?.object()?;
    let expected_url = format!(
        "https://api.github.com/repos/{}/actions/artifacts/{artifact_id}/zip",
        request.repository
    );
    let created =
        crate::assurance::utc_timestamp_seconds(json_member(artifact, "created_at")?.string()?)?;
    let observed = crate::assurance::utc_timestamp_seconds(observed_at)?;
    let expires =
        crate::assurance::utc_timestamp_seconds(json_member(artifact, "expires_at")?.string()?)?;
    if json_member(artifact, "id")?.number()? != artifact_id
        || json_member(artifact, "name")?.string()? != name
        || json_member(workflow_run, "id")?.number()? != request.run_id
        || json_member(workflow_run, "head_sha")?.string()? != request.provider_head
        || json_member(artifact, "archive_download_url")?.string()? != expected_url
        || json_member(artifact, "expired")?.boolean()?
        || !(created < observed && observed < expires)
    {
        return Err("collection artifact identity or lifetime is invalid".to_owned());
    }
    Ok(())
}

struct ProviderSelectionInput<'a> {
    request: &'a ProviderRequest,
    platform: &'a str,
    artifact_id: u64,
    artifact_name: &'a str,
    archive: Digest,
    archive_size: u64,
    artifact_page: usize,
    job_page: usize,
    job_id: u64,
    job_name: &'a str,
    tree: &'a str,
    inventory_count: u64,
    observed_at: &'a str,
    gh_install_manifest_sha256: Digest,
}

fn provider_selection(input: &ProviderSelectionInput<'_>) -> JsonValue {
    JsonValue::Object(BTreeMap::from([
        (
            "artifact".to_owned(),
            JsonValue::String(input.artifact_name.to_owned()),
        ),
        (
            "candidateCommit".to_owned(),
            JsonValue::String(input.request.candidate.clone()),
        ),
        (
            "canonicalShardRoot".to_owned(),
            JsonValue::String(input.platform.to_owned()),
        ),
        (
            "inventoryCount".to_owned(),
            JsonValue::Number(input.inventory_count),
        ),
        (
            "observedAt".to_owned(),
            JsonValue::String(input.observed_at.to_owned()),
        ),
        (
            "platform".to_owned(),
            JsonValue::String(input.platform.to_owned()),
        ),
        (
            "providerArchiveSha256".to_owned(),
            JsonValue::String(input.archive.hex()),
        ),
        (
            "providerArchiveSize".to_owned(),
            JsonValue::Number(input.archive_size),
        ),
        (
            "providerArtifactApiPage".to_owned(),
            JsonValue::String(format!(
                "../artifact-api-pages/page-{:04}.json",
                input.artifact_page
            )),
        ),
        (
            "providerArtifactId".to_owned(),
            JsonValue::Number(input.artifact_id),
        ),
        (
            "providerHeadCommit".to_owned(),
            JsonValue::String(input.request.provider_head.clone()),
        ),
        (
            "providerGhExecutableSha256".to_owned(),
            JsonValue::String(GH_BINARY_SHA256.to_owned()),
        ),
        (
            "providerGhInstallManifestSha256".to_owned(),
            JsonValue::String(input.gh_install_manifest_sha256.hex()),
        ),
        (
            "providerJobApiPage".to_owned(),
            JsonValue::String(format!("../job-api-pages/page-{:04}.json", input.job_page)),
        ),
        ("providerJobId".to_owned(), JsonValue::Number(input.job_id)),
        (
            "providerJobName".to_owned(),
            JsonValue::String(input.job_name.to_owned()),
        ),
        (
            "providerRunAttempt".to_owned(),
            JsonValue::Number(input.request.run_attempt),
        ),
        (
            "providerRunId".to_owned(),
            JsonValue::Number(input.request.run_id),
        ),
        (
            "providerTreeSha256".to_owned(),
            JsonValue::String(input.tree.to_owned()),
        ),
        ("schemaVersion".to_owned(), JsonValue::Number(1)),
        (
            "workflowPath".to_owned(),
            JsonValue::String(input.request.workflow.clone()),
        ),
    ]))
}

fn directory_count(path: &Path) -> Result<usize, String> {
    fs::read_dir(path)
        .map_err(|error| format!("cannot enumerate collection observations: {error}"))?
        .try_fold(0_usize, |count, entry| {
            let entry = entry.map_err(|error| format!("cannot enumerate observation: {error}"))?;
            let kind = entry
                .file_type()
                .map_err(|error| format!("cannot inspect observation: {error}"))?;
            if kind.is_symlink() || !kind.is_dir() {
                return Err("collection observation inventory contains a non-directory".to_owned());
            }
            Ok(count + 1)
        })
}

fn copy_regular_tree(source: &Path, destination: &Path) -> Result<(), String> {
    if destination.exists() {
        return Err("collection copied shard destination already exists".to_owned());
    }
    fs::create_dir_all(destination)
        .map_err(|error| format!("cannot create copied shard: {error}"))?;
    for entry in fs::read_dir(source)
        .map_err(|error| format!("cannot enumerate copied shard source: {error}"))?
    {
        let entry = entry.map_err(|error| format!("cannot enumerate copied shard: {error}"))?;
        let kind = entry
            .file_type()
            .map_err(|error| format!("cannot inspect copied shard: {error}"))?;
        let target = destination.join(entry.file_name());
        if kind.is_dir() {
            copy_regular_tree(&entry.path(), &target)?;
        } else if kind.is_file() {
            fs::copy(entry.path(), target)
                .map_err(|error| format!("cannot copy collection shard file: {error}"))?;
        } else {
            return Err("collection copied shard contains a nonregular entry".to_owned());
        }
    }
    Ok(())
}

struct CaptureRequest {
    subject: PathBuf,
    bundle: PathBuf,
    provider_head: String,
    run_id: u64,
    run_attempt: u64,
    gh: PathBuf,
    install_manifest: PathBuf,
    trusted_root: PathBuf,
    provenance: PathBuf,
    raw_verification: PathBuf,
    online_verification: PathBuf,
}

fn capture_attestation(arguments: &[OsString]) -> Result<String, String> {
    let options = exact_options(
        arguments,
        &[
            "subject",
            "bundle",
            "provider-head",
            "run-id",
            "run-attempt",
            "gh-executable",
            "gh-install-manifest",
            "trusted-root",
            "trusted-root-provenance",
            "raw-verification",
            "online-verification",
        ],
    )?;
    let request = CaptureRequest {
        subject: option_path(&options, "subject"),
        bundle: option_path(&options, "bundle"),
        provider_head: option_text(&options, "provider-head")?.to_owned(),
        run_id: option_positive(&options, "run-id")?,
        run_attempt: option_positive(&options, "run-attempt")?,
        gh: option_path(&options, "gh-executable"),
        install_manifest: option_path(&options, "gh-install-manifest"),
        trusted_root: option_path(&options, "trusted-root"),
        provenance: option_path(&options, "trusted-root-provenance"),
        raw_verification: option_path(&options, "raw-verification"),
        online_verification: option_path(&options, "online-verification"),
    };
    require_commit(
        &request.provider_head,
        "collection attestation provider head",
    )?;
    capture_attestation_request(&request)
}

fn capture_attestation_request(request: &CaptureRequest) -> Result<String, String> {
    validate_capture_paths(request)?;
    let result = capture_attestation_request_validated(request);
    let Err(error) = result else {
        return result;
    };
    {
        let mut cleanup_errors = Vec::new();
        for output in [
            &request.trusted_root,
            &request.provenance,
            &request.raw_verification,
            &request.online_verification,
        ] {
            if output.exists()
                && let Err(cleanup) = fs::remove_file(output)
            {
                cleanup_errors.push(cleanup.to_string());
            }
        }
        if cleanup_errors.is_empty() {
            Err(error)
        } else {
            Err(format!(
                "{error}; partial attestation cleanup failed: {}",
                cleanup_errors.join(", ")
            ))
        }
    }
}

fn capture_attestation_request_validated(request: &CaptureRequest) -> Result<String, String> {
    let subject_bytes = read_regular_file(&request.subject, "attestation subject")?;
    let bundle_bytes = read_regular_file(&request.bundle, "attestation bundle")?;
    let subject_sha256 = sha256_bytes(&subject_bytes);
    let bundle_sha256 = sha256_bytes(&bundle_bytes);
    let bundle = parse_json(
        std::str::from_utf8(&bundle_bytes)
            .map_err(|_| "attestation bundle is not UTF-8".to_owned())?,
    )?;
    let statement = validate_attestation_bundle(&bundle, &request.subject, &subject_sha256.hex())?;
    let install = validate_reviewed_gh_install(&request.gh, &request.install_manifest)?;
    let gh_version = run_gh(&request.gh, [OsStr::new("--version")], false)?;
    let gh_version_text = std::str::from_utf8(&gh_version)
        .map_err(|_| "reviewed gh version is not UTF-8".to_owned())?;
    if gh_version_text
        .lines()
        .next()
        .is_none_or(|line| line != "gh version 2.93.0 (2026-04-01)")
    {
        return Err("reviewed gh version output is not exact".to_owned());
    }
    let root_bytes = run_gh(
        &request.gh,
        [OsStr::new("attestation"), OsStr::new("trusted-root")],
        false,
    )?;
    let root_count = validate_json_lines(&root_bytes)?;
    write_exclusive(&request.trusted_root, &root_bytes)?;
    let verify_arguments = attestation_verify_arguments(
        &request.subject,
        &request.bundle,
        &request.trusted_root,
        &request.provider_head,
    );
    let raw = run_gh(
        &request.gh,
        verify_arguments.iter().map(OsString::as_os_str),
        true,
    )?;
    let captured_at = crate::custody_ops::current_utc_timestamp()?;
    let result =
        validate_attestation_verification(&raw, &bundle, &statement, request, &captured_at)?;
    write_exclusive(&request.raw_verification, &raw)?;
    let trusted_root_sha256 = sha256_bytes(&root_bytes);
    let canonical_argv = std::iter::once(OsStr::new("gh"))
        .chain(verify_arguments.iter().map(OsString::as_os_str))
        .map(|argument| JsonValue::String(argument.to_string_lossy().into_owned()))
        .collect::<Vec<_>>();
    let provenance_value = attestation_provenance(AttestationProvenanceFacts {
        bundle: bundle_sha256,
        subject: subject_sha256,
        trusted_root: trusted_root_sha256,
        install_manifest: install.manifest_sha256,
        provider_head: &request.provider_head,
        run_id: request.run_id,
        run_attempt: request.run_attempt,
        captured_at: &captured_at,
        root_count,
        gh_version: gh_version_text
            .lines()
            .map(|line| JsonValue::String(line.to_owned()))
            .collect(),
        verify_argv: canonical_argv,
    });
    write_exclusive(
        &request.provenance,
        &canonical_json_bytes(&provenance_value)?,
    )?;
    let wrapper = online_verification_wrapper(
        bundle_sha256,
        subject_sha256,
        trusted_root_sha256,
        &captured_at,
        gh_version_text,
        &raw,
        result,
    );
    write_exclusive(
        &request.online_verification,
        &canonical_json_bytes(&wrapper)?,
    )?;
    Ok("captured exact collection custody attestation transport".to_owned())
}

fn validate_capture_paths(request: &CaptureRequest) -> Result<(), String> {
    validate_reviewed_gh_install(&request.gh, &request.install_manifest)?;
    validate_capture_io_paths(request)
}

fn validate_capture_io_paths(request: &CaptureRequest) -> Result<(), String> {
    for (path, label) in [
        (&request.subject, "attestation subject"),
        (&request.bundle, "attestation bundle"),
    ] {
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| format!("cannot inspect {label}: {error}"))?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            return Err(format!("{label} is indirect or nonregular"));
        }
    }
    let outputs = [
        &request.trusted_root,
        &request.provenance,
        &request.raw_verification,
        &request.online_verification,
    ];
    let mut identities = BTreeSet::new();
    for output in outputs {
        if output.exists() {
            return Err("collection attestation output already exists".to_owned());
        }
        let parent = output
            .parent()
            .ok_or_else(|| "collection attestation output has no parent".to_owned())?;
        fs::create_dir_all(parent)
            .map_err(|error| format!("cannot create attestation output parent: {error}"))?;
        let canonical_parent = fs::canonicalize(parent)
            .map_err(|error| format!("cannot resolve attestation output parent: {error}"))?;
        let name = output
            .file_name()
            .ok_or_else(|| "collection attestation output has no filename".to_owned())?;
        if !identities.insert(canonical_parent.join(name)) {
            return Err("collection attestation output paths are not distinct".to_owned());
        }
    }
    Ok(())
}

struct ReviewedGhInstall {
    manifest_sha256: Digest,
}

fn validate_reviewed_gh_install(
    executable: &Path,
    manifest_path: &Path,
) -> Result<ReviewedGhInstall, String> {
    let executable_metadata = fs::symlink_metadata(executable)
        .map_err(|error| format!("cannot inspect reviewed gh executable: {error}"))?;
    let manifest_metadata = fs::symlink_metadata(manifest_path)
        .map_err(|error| format!("cannot inspect reviewed gh manifest: {error}"))?;
    if executable_metadata.file_type().is_symlink()
        || manifest_metadata.file_type().is_symlink()
        || !executable_metadata.file_type().is_file()
        || !manifest_metadata.file_type().is_file()
        || executable.parent() != manifest_path.parent()
        || manifest_path.file_name() != Some(OsStr::new("gh-install-manifest.json"))
    {
        return Err("reviewed gh executable and manifest are indirect or not siblings".to_owned());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if executable_metadata.permissions().mode() & 0o777 != 0o755 {
            return Err("reviewed gh executable mode differs".to_owned());
        }
    }
    let manifest = fs::read(manifest_path)
        .map_err(|error| format!("cannot read reviewed gh manifest: {error}"))?;
    crate::collection_custody::verify_gh_install_manifest(&manifest)?;
    if sha256_file(executable)
        .map_err(|error| error.to_string())?
        .hex()
        != GH_BINARY_SHA256
    {
        return Err("reviewed gh executable differs from pinned binary".to_owned());
    }
    Ok(ReviewedGhInstall {
        manifest_sha256: sha256_bytes(&manifest),
    })
}

fn read_regular_file(path: &Path, label: &str) -> Result<Vec<u8>, String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("cannot inspect {label}: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(format!("{label} is indirect or nonregular"));
    }
    fs::read(path).map_err(|error| format!("cannot read {label}: {error}"))
}

fn validate_attestation_bundle(
    bundle: &JsonValue,
    subject_path: &Path,
    subject_sha256: &str,
) -> Result<JsonValue, String> {
    let document = bundle.object()?;
    if json_member(document, "mediaType")?.string()?
        != "application/vnd.dev.sigstore.bundle.v0.3+json"
    {
        return Err("attestation bundle media type differs".to_owned());
    }
    let material = json_member(document, "verificationMaterial")?.object()?;
    if json_member(material, "tlogEntries")?.array()?.is_empty() {
        return Err("attestation bundle has no transparency entry".to_owned());
    }
    let envelope = json_member(document, "dsseEnvelope")?.object()?;
    if json_member(envelope, "payloadType")?.string()? != "application/vnd.in-toto+json"
        || json_member(envelope, "signatures")?.array()?.len() != 1
    {
        return Err("attestation DSSE envelope differs".to_owned());
    }
    let payload = crate::assurance::decode_base64(json_member(envelope, "payload")?.string()?)?;
    let statement = parse_json(
        std::str::from_utf8(&payload)
            .map_err(|_| "attestation statement is not UTF-8".to_owned())?,
    )?;
    validate_attestation_statement(statement.object()?, subject_path, subject_sha256)?;
    Ok(statement)
}

fn validate_attestation_statement(
    statement: &BTreeMap<String, JsonValue>,
    subject_path: &Path,
    subject_sha256: &str,
) -> Result<(), String> {
    let subjects = json_member(statement, "subject")?.array()?;
    let [subject] = subjects else {
        return Err("attestation statement subject is not unique".to_owned());
    };
    let retained = subject.object()?;
    let name = subject_path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| "attestation subject name is not UTF-8".to_owned())?;
    let digest = json_member(retained, "digest")?.object()?;
    if json_member(statement, "_type")?.string()? != "https://in-toto.io/Statement/v1"
        || json_member(statement, "predicateType")?.string()? != PREDICATE_TYPE
        || json_member(retained, "name")?.string()? != name
        || digest.len() != 1
        || json_member(digest, "sha256")?.string()? != subject_sha256
    {
        return Err("attestation statement identity differs".to_owned());
    }
    Ok(())
}

fn online_verification_wrapper(
    bundle: Digest,
    subject: Digest,
    trusted_root: Digest,
    captured_at: &str,
    gh_version: &str,
    raw: &[u8],
    result: JsonValue,
) -> JsonValue {
    JsonValue::Object(BTreeMap::from([
        ("bundleSha256".to_owned(), JsonValue::String(bundle.hex())),
        (
            "capturedAt".to_owned(),
            JsonValue::String(captured_at.to_owned()),
        ),
        (
            "domain".to_owned(),
            JsonValue::String("hell.collection-custody.attestation.v1".to_owned()),
        ),
        (
            "ghExecutableSha256".to_owned(),
            JsonValue::String(GH_BINARY_SHA256.to_owned()),
        ),
        (
            "ghVersion".to_owned(),
            JsonValue::Array(
                gh_version
                    .lines()
                    .map(|line| JsonValue::String(line.to_owned()))
                    .collect(),
            ),
        ),
        (
            "rawVerificationPath".to_owned(),
            JsonValue::String("online-verification.raw.json".to_owned()),
        ),
        (
            "rawVerificationSha256".to_owned(),
            JsonValue::String(sha256_bytes(raw).hex()),
        ),
        (
            "schema".to_owned(),
            JsonValue::String("hell.collection-custody.online-verification.v1".to_owned()),
        ),
        ("subjectSha256".to_owned(), JsonValue::String(subject.hex())),
        (
            "trustedRootSha256".to_owned(),
            JsonValue::String(trusted_root.hex()),
        ),
        ("verificationResult".to_owned(), result),
    ]))
}

fn run_gh<'a>(
    executable: &Path,
    arguments: impl IntoIterator<Item = &'a OsStr>,
    offline: bool,
) -> Result<Vec<u8>, String> {
    let configuration = private_temporary("gh-config")?;
    let mut command = Command::new(executable);
    command.args(arguments).stdin(Stdio::null());
    configure_gh_environment(&mut command, &configuration, offline);
    let result = run_bounded_command(
        &mut command,
        "reviewed gh invocation",
        64 * 1024 * 1024,
        Duration::from_mins(2),
    );
    let cleanup = fs::remove_dir_all(&configuration)
        .map_err(|error| format!("cannot remove gh configuration directory: {error}"));
    match (result, cleanup) {
        (Ok(bytes), Ok(())) => Ok(bytes),
        (Err(error), _) | (Ok(_), Err(error)) => Err(error),
    }
}

fn configure_gh_environment(command: &mut Command, configuration: &Path, offline: bool) {
    for name in [
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
        "GH_AUTH_TOKEN",
        "GH_ENTERPRISE_TOKEN",
        "GH_TOKEN",
        "GITHUB_ACTIONS_RUNTIME_TOKEN",
        "GITHUB_ENTERPRISE_TOKEN",
        "GITHUB_TOKEN",
        "GIT_ASKPASS",
        "SSH_AUTH_SOCK",
    ] {
        command.env_remove(name);
    }
    command
        .env("GH_CONFIG_DIR", configuration)
        .env("GH_PAGER", "cat")
        .env("NO_COLOR", "1");
    if offline {
        for name in [
            "ALL_PROXY",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "all_proxy",
            "http_proxy",
            "https_proxy",
        ] {
            command.env(name, "http://127.0.0.1:9");
        }
        command.env("NO_PROXY", "").env("no_proxy", "");
    }
}

fn validate_json_lines(bytes: &[u8]) -> Result<u64, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "trusted root is not UTF-8".to_owned())?;
    if !text.ends_with('\n') || text.contains('\r') || text.contains('\0') {
        return Err("trusted root is not canonical JSONL".to_owned());
    }
    let mut count = 0_u64;
    for line in text.lines() {
        if line.is_empty() || !matches!(parse_json(line)?, JsonValue::Object(_)) {
            return Err("trusted root record is not one JSON object".to_owned());
        }
        count += 1;
    }
    (count != 0)
        .then_some(count)
        .ok_or_else(|| "trusted root is empty".to_owned())
}

fn validate_attestation_verification(
    bytes: &[u8],
    bundle: &JsonValue,
    statement: &JsonValue,
    request: &CaptureRequest,
    captured_at: &str,
) -> Result<JsonValue, String> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| "gh verification output is not UTF-8".to_owned())?;
    let value = parse_json(text)?;
    let JsonValue::Array(entries) = value else {
        return Err("gh verification output is not an array".to_owned());
    };
    let [result] = entries.as_slice() else {
        return Err("gh verification output is not exactly one result".to_owned());
    };
    let entry = result.object()?;
    if json_member(entry, "attestation")? != bundle {
        return Err("verified attestation bundle differs".to_owned());
    }
    let verification = json_member(entry, "verificationResult")?.object()?;
    if json_member(verification, "statement")? != statement {
        return Err("verified attestation statement differs".to_owned());
    }
    let signature = json_member(verification, "signature")?.object()?;
    validate_certificate(json_member(signature, "certificate")?.object()?, request)?;
    let identity = json_member(verification, "verifiedIdentity")?.object()?;
    let san = json_member(identity, "subjectAlternativeName")?.object()?;
    let issuer = json_member(identity, "issuer")?.object()?;
    if json_member(san, "subjectAlternativeName")?.string()? != CERTIFICATE_IDENTITY
        || json_member(issuer, "issuer")?.string()? != OIDC_ISSUER
    {
        return Err("verified attestation identity differs".to_owned());
    }
    validate_verified_timestamps(
        json_member(verification, "verifiedTimestamps")?.array()?,
        captured_at,
    )?;
    Ok(result.clone())
}

fn validate_certificate(
    certificate: &BTreeMap<String, JsonValue>,
    request: &CaptureRequest,
) -> Result<(), String> {
    let invocation = format!(
        "{REPOSITORY_URI}/actions/runs/{}/attempts/{}",
        request.run_id, request.run_attempt
    );
    let expected = BTreeMap::from([
        ("buildConfigDigest", request.provider_head.as_str()),
        ("buildConfigURI", CERTIFICATE_IDENTITY),
        ("buildSignerDigest", request.provider_head.as_str()),
        ("buildSignerURI", CERTIFICATE_IDENTITY),
        ("buildTrigger", "workflow_dispatch"),
        ("githubWorkflowName", "Collection Authority"),
        ("githubWorkflowRef", SOURCE_REF),
        ("githubWorkflowRepository", REPOSITORY),
        ("githubWorkflowSHA", request.provider_head.as_str()),
        ("githubWorkflowTrigger", "workflow_dispatch"),
        ("issuer", OIDC_ISSUER),
        ("runInvocationURI", invocation.as_str()),
        ("runnerEnvironment", "github-hosted"),
        ("sourceRepositoryDigest", request.provider_head.as_str()),
        ("sourceRepositoryIdentifier", "1327351238"),
        ("sourceRepositoryOwnerIdentifier", OWNER_ID),
        ("sourceRepositoryOwnerURI", OWNER_URI),
        ("sourceRepositoryRef", SOURCE_REF),
        ("sourceRepositoryURI", REPOSITORY_URI),
        ("sourceRepositoryVisibilityAtSigning", "public"),
        ("subjectAlternativeName", CERTIFICATE_IDENTITY),
    ]);
    if certificate.len() != expected.len()
        || expected.iter().any(|(field, value)| {
            json_member(certificate, field)
                .and_then(JsonValue::string)
                .ok()
                != Some(*value)
        })
    {
        return Err("verified certificate fields differ".to_owned());
    }
    Ok(())
}

fn validate_verified_timestamps(timestamps: &[JsonValue], captured_at: &str) -> Result<(), String> {
    if timestamps.is_empty() {
        return Err("verification has no witnessed timestamp".to_owned());
    }
    let captured = crate::assurance::utc_timestamp_seconds(captured_at)?;
    let mut saw_transparency = false;
    for timestamp in timestamps {
        let timestamp = timestamp.object()?;
        if json_member(timestamp, "type")?.string()? == "Tlog" {
            saw_transparency = true;
        }
        let witnessed = crate::assurance::utc_timestamp_seconds(
            json_member(timestamp, "timestamp")?.string()?,
        )?;
        if witnessed > captured {
            return Err("verified timestamp is after verification capture".to_owned());
        }
    }
    if !saw_transparency {
        return Err("verification has no transparency-log witness".to_owned());
    }
    Ok(())
}

fn attestation_verify_arguments(
    subject: &Path,
    bundle: &Path,
    root: &Path,
    provider_head: &str,
) -> Vec<OsString> {
    [
        OsString::from("attestation"),
        OsString::from("verify"),
        subject.as_os_str().to_owned(),
        OsString::from("--repo"),
        OsString::from(REPOSITORY),
        OsString::from("--bundle"),
        bundle.as_os_str().to_owned(),
        OsString::from("--custom-trusted-root"),
        root.as_os_str().to_owned(),
        OsString::from("--signer-workflow"),
        OsString::from("Portfoligno/hell-rs/.github/workflows/collection-authority.yml"),
        OsString::from("--signer-digest"),
        OsString::from(provider_head),
        OsString::from("--source-digest"),
        OsString::from(provider_head),
        OsString::from("--source-ref"),
        OsString::from("refs/heads/main"),
        OsString::from("--cert-identity"),
        OsString::from("https://github.com/Portfoligno/hell-rs/.github/workflows/collection-authority.yml@refs/heads/main"),
        OsString::from("--cert-oidc-issuer"),
        OsString::from("https://token.actions.githubusercontent.com"),
        OsString::from("--predicate-type"),
        OsString::from("https://slsa.dev/provenance/v1"),
        OsString::from("--deny-self-hosted-runners"),
        OsString::from("--format"),
        OsString::from("json"),
    ]
    .to_vec()
}

struct AttestationProvenanceFacts<'a> {
    bundle: Digest,
    subject: Digest,
    trusted_root: Digest,
    install_manifest: Digest,
    provider_head: &'a str,
    run_id: u64,
    run_attempt: u64,
    captured_at: &'a str,
    root_count: u64,
    gh_version: Vec<JsonValue>,
    verify_argv: Vec<JsonValue>,
}

fn attestation_provenance(facts: AttestationProvenanceFacts<'_>) -> JsonValue {
    JsonValue::Object(BTreeMap::from([
        (
            "bundleSha256".to_owned(),
            JsonValue::String(facts.bundle.hex()),
        ),
        (
            "domain".to_owned(),
            JsonValue::String("hell.collection-custody.attestation.v1".to_owned()),
        ),
        (
            "ghArchiveSha256".to_owned(),
            JsonValue::String(GH_ARCHIVE_SHA256.to_owned()),
        ),
        (
            "ghArchiveUrl".to_owned(),
            JsonValue::String(GH_ARCHIVE_URL.to_owned()),
        ),
        (
            "ghBinarySha256".to_owned(),
            JsonValue::String(GH_BINARY_SHA256.to_owned()),
        ),
        (
            "ghChecksumsSha256".to_owned(),
            JsonValue::String(GH_CHECKSUMS_SHA256.to_owned()),
        ),
        (
            "ghChecksumsUrl".to_owned(),
            JsonValue::String(GH_CHECKSUMS_URL.to_owned()),
        ),
        (
            "ghExecutableSha256".to_owned(),
            JsonValue::String(GH_BINARY_SHA256.to_owned()),
        ),
        (
            "ghInstallManifestSha256".to_owned(),
            JsonValue::String(facts.install_manifest.hex()),
        ),
        (
            "ghReleaseVersion".to_owned(),
            JsonValue::String(GH_VERSION.to_owned()),
        ),
        ("ghVersion".to_owned(), JsonValue::Array(facts.gh_version)),
        (
            "providerHead".to_owned(),
            JsonValue::String(facts.provider_head.to_owned()),
        ),
        (
            "repository".to_owned(),
            JsonValue::String(REPOSITORY.to_owned()),
        ),
        ("repositoryId".to_owned(), JsonValue::Number(REPOSITORY_ID)),
        (
            "runAttempt".to_owned(),
            JsonValue::Number(facts.run_attempt),
        ),
        ("runId".to_owned(), JsonValue::Number(facts.run_id)),
        (
            "schema".to_owned(),
            JsonValue::String("hell.collection-custody.trusted-root-provenance.v1".to_owned()),
        ),
        (
            "subjectSha256".to_owned(),
            JsonValue::String(facts.subject.hex()),
        ),
        (
            "trustedRootAcquiredAt".to_owned(),
            JsonValue::String(facts.captured_at.to_owned()),
        ),
        (
            "trustedRootAcquisitionArgv".to_owned(),
            JsonValue::Array(vec![
                JsonValue::String("gh".to_owned()),
                JsonValue::String("attestation".to_owned()),
                JsonValue::String("trusted-root".to_owned()),
            ]),
        ),
        (
            "trustedRootRecordCount".to_owned(),
            JsonValue::Number(facts.root_count),
        ),
        (
            "trustedRootRawSha256".to_owned(),
            JsonValue::String(facts.trusted_root.hex()),
        ),
        (
            "verificationCredentialsStripped".to_owned(),
            JsonValue::Bool(true),
        ),
        (
            "verificationNetworkIsolation".to_owned(),
            JsonValue::String("credentialless-loopback-proxy-best-effort".to_owned()),
        ),
        (
            "verifiedAt".to_owned(),
            JsonValue::String(facts.captured_at.to_owned()),
        ),
        ("verifyArgv".to_owned(), JsonValue::Array(facts.verify_argv)),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::GzEncoder};

    fn json_string(value: impl Into<String>) -> JsonValue {
        JsonValue::String(value.into())
    }

    fn page(kind: &str, total: u64, entries: Vec<JsonValue>) -> JsonValue {
        JsonValue::Object(BTreeMap::from([
            (kind.to_owned(), JsonValue::Array(entries)),
            ("total_count".to_owned(), JsonValue::Number(total)),
        ]))
    }

    fn entry(id: u64, name: &str) -> JsonValue {
        JsonValue::Object(BTreeMap::from([
            ("id".to_owned(), JsonValue::Number(id)),
            ("name".to_owned(), json_string(name)),
        ]))
    }

    fn provider_request() -> ProviderRequest {
        ProviderRequest {
            repository: REPOSITORY.to_owned(),
            run_id: 7,
            run_attempt: 2,
            provider_head: "a".repeat(<[u8; 20]>::default().len() * 2),
            candidate: "b".repeat(<[u8; 20]>::default().len() * 2),
            workflow: WORKFLOW.to_owned(),
            gh: PathBuf::from("gh"),
            install_manifest: PathBuf::from("gh-install-manifest.json"),
            output: PathBuf::from("unused"),
            artifacts: [
                ("linux-amd64".to_owned(), 1),
                ("macos-arm64".to_owned(), 2),
                ("windows-amd64".to_owned(), 3),
            ],
        }
    }

    #[test]
    fn transport_cli_and_oid_are_fail_closed() {
        let valid = [OsString::from("--output"), OsString::from("target")];
        assert!(exact_options(&valid, &["output"]).is_ok());
        for invalid in [
            vec![OsString::from("--output")],
            vec![OsString::from("--other"), OsString::from("target")],
            vec![
                OsString::from("--output"),
                OsString::from("one"),
                OsString::from("--output"),
                OsString::from("two"),
            ],
        ] {
            assert!(exact_options(&invalid, &["output"]).is_err());
        }
        let width = <[u8; 20]>::default().len() * 2;
        assert!(require_commit(&"a".repeat(width), "commit").is_ok());
        for invalid in [
            "a".repeat(width - 1),
            "A".repeat(width),
            "g".repeat(width),
            "a".repeat(width + 1),
        ] {
            assert!(require_commit(&invalid, "commit").is_err());
        }
    }

    #[test]
    fn provider_pagination_and_selection_reject_coherent_drift() {
        let artifacts = vec![entry(3, "selected"), entry(2, "other"), entry(1, "last")];
        let pages = vec![page("artifacts", 3, artifacts.clone())];
        assert!(validate_complete_pages(&pages, "artifacts").is_ok());
        assert!(select_page_entry(&pages, "artifacts", 3, Some("selected")).is_ok());

        let mut ascending = artifacts.clone();
        ascending.reverse();
        assert!(validate_complete_pages(&[page("artifacts", 3, ascending)], "artifacts").is_err());
        assert!(
            validate_complete_pages(&[page("artifacts", 4, artifacts.clone())], "artifacts")
                .is_err()
        );
        assert!(
            validate_complete_pages(
                &[
                    page("artifacts", 3, artifacts.clone()),
                    page("artifacts", 3, Vec::new()),
                ],
                "artifacts",
            )
            .is_err()
        );
        let duplicate_name = vec![page(
            "artifacts",
            2,
            vec![entry(3, "selected"), entry(2, "selected")],
        )];
        assert!(select_page_entry(&duplicate_name, "artifacts", 3, Some("selected")).is_err());
    }

    #[test]
    fn provider_run_identity_rejects_repository_workflow_and_event_drift() {
        let request = provider_request();
        let exact = BTreeMap::from([
            ("event".to_owned(), json_string("workflow_dispatch")),
            ("head_branch".to_owned(), json_string("main")),
            (
                "head_sha".to_owned(),
                json_string(request.provider_head.clone()),
            ),
            ("id".to_owned(), JsonValue::Number(request.run_id)),
            ("path".to_owned(), json_string(WORKFLOW)),
            (
                "repository".to_owned(),
                JsonValue::Object(BTreeMap::from([
                    ("full_name".to_owned(), json_string(REPOSITORY)),
                    ("id".to_owned(), JsonValue::Number(REPOSITORY_ID)),
                ])),
            ),
            (
                "run_attempt".to_owned(),
                JsonValue::Number(request.run_attempt),
            ),
            ("status".to_owned(), json_string("completed")),
        ]);
        assert!(validate_provider_run(&exact, &request).is_ok());
        for (field, value) in [
            ("event", json_string("push")),
            ("path", json_string(".github/workflows/nightly.yml")),
            ("head_branch", json_string("feature")),
        ] {
            let mut mutated = exact.clone();
            mutated.insert(field.to_owned(), value);
            assert!(validate_provider_run(&mutated, &request).is_err());
        }
        let mut mutated = exact;
        let JsonValue::Object(repository) = mutated.get_mut("repository").unwrap() else {
            panic!("fixture repository is not an object");
        };
        repository.insert("id".to_owned(), JsonValue::Number(REPOSITORY_ID + 1));
        assert!(validate_provider_run(&mutated, &request).is_err());
    }

    #[test]
    fn provider_workflow_is_read_from_exact_provider_head() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .unwrap();
        let head = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap();
        assert!(head.status.success());
        let mut request = provider_request();
        request.provider_head = String::from_utf8(head.stdout).unwrap().trim().to_owned();
        let workflow = provider_workflow_at(root, &request).unwrap();
        assert!(workflow.starts_with(b"name: Collection Authority\n"));
        request.workflow = ".github/workflows/nightly.yml".to_owned();
        assert!(validate_provider_request(root, &request).is_err());
    }

    fn tar_gzip(entries: &[(&str, tar::EntryType, &[u8])]) -> Vec<u8> {
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut builder = tar::Builder::new(encoder);
        for (name, kind, bytes) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(*kind);
            header.set_mode(if *name == GH_BINARY_MEMBER {
                0o755
            } else {
                0o644
            });
            header.set_size(bytes.len() as u64);
            header.set_path(name).unwrap();
            header.set_cksum();
            builder.append(&header, *bytes).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap()
    }

    fn unsafe_tar_gzip(name: &[u8]) -> Vec<u8> {
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut builder = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_mode(0o755);
        header.set_size(2);
        header.set_path("safe").unwrap();
        let header_bytes = header.as_mut_bytes();
        header_bytes[..name.len()].copy_from_slice(name);
        header_bytes[name.len()] = 0;
        header.set_cksum();
        builder.append(&header, b"gh".as_slice()).unwrap();
        builder.into_inner().unwrap().finish().unwrap()
    }

    #[test]
    fn gh_archive_parser_rejects_duplicate_nonfile_and_truncation() {
        let valid = tar_gzip(&[(GH_BINARY_MEMBER, tar::EntryType::Regular, b"gh")]);
        assert_eq!(inspect_gh_archive(&valid).unwrap().binary, b"gh");
        let duplicate = tar_gzip(&[
            (GH_BINARY_MEMBER, tar::EntryType::Regular, b"gh"),
            (GH_BINARY_MEMBER, tar::EntryType::Regular, b"gh"),
        ]);
        assert!(inspect_gh_archive(&duplicate).is_err());
        let link = tar_gzip(&[(GH_BINARY_MEMBER, tar::EntryType::Symlink, b"")]);
        assert!(inspect_gh_archive(&link).is_err());
        assert!(inspect_gh_archive(&unsafe_tar_gzip(b"../escape")).is_err());
        assert!(inspect_gh_archive(&valid[..valid.len() / 2]).is_err());
    }

    fn statement(subject_name: &str, digest: &str) -> JsonValue {
        JsonValue::Object(BTreeMap::from([
            (
                "_type".to_owned(),
                json_string("https://in-toto.io/Statement/v1"),
            ),
            ("predicate".to_owned(), JsonValue::Object(BTreeMap::new())),
            ("predicateType".to_owned(), json_string(PREDICATE_TYPE)),
            (
                "subject".to_owned(),
                JsonValue::Array(vec![JsonValue::Object(BTreeMap::from([
                    (
                        "digest".to_owned(),
                        JsonValue::Object(BTreeMap::from([(
                            "sha256".to_owned(),
                            json_string(digest),
                        )])),
                    ),
                    ("name".to_owned(), json_string(subject_name)),
                ]))]),
            ),
        ]))
    }

    fn bundle(statement: &JsonValue) -> JsonValue {
        let payload = canonical_json_bytes(statement).unwrap();
        JsonValue::Object(BTreeMap::from([
            (
                "dsseEnvelope".to_owned(),
                JsonValue::Object(BTreeMap::from([
                    (
                        "payload".to_owned(),
                        json_string(crate::assurance::encode_base64(&payload)),
                    ),
                    (
                        "payloadType".to_owned(),
                        json_string("application/vnd.in-toto+json"),
                    ),
                    (
                        "signatures".to_owned(),
                        JsonValue::Array(vec![JsonValue::Object(BTreeMap::from([
                            ("keyid".to_owned(), json_string("fixture")),
                            ("sig".to_owned(), json_string("fixture")),
                        ]))]),
                    ),
                ])),
            ),
            (
                "mediaType".to_owned(),
                json_string("application/vnd.dev.sigstore.bundle.v0.3+json"),
            ),
            (
                "verificationMaterial".to_owned(),
                JsonValue::Object(BTreeMap::from([(
                    "tlogEntries".to_owned(),
                    JsonValue::Array(vec![JsonValue::Object(BTreeMap::new())]),
                )])),
            ),
        ]))
    }

    fn capture_request() -> CaptureRequest {
        CaptureRequest {
            subject: PathBuf::from("custody-attestation-subject.json"),
            bundle: PathBuf::from("bundle.json"),
            provider_head: "a".repeat(<[u8; 20]>::default().len() * 2),
            run_id: 7,
            run_attempt: 2,
            gh: PathBuf::from("gh"),
            install_manifest: PathBuf::from("gh-install-manifest.json"),
            trusted_root: PathBuf::from("root"),
            provenance: PathBuf::from("provenance"),
            raw_verification: PathBuf::from("raw"),
            online_verification: PathBuf::from("online"),
        }
    }

    fn certificate(request: &CaptureRequest) -> BTreeMap<String, JsonValue> {
        let invocation = format!(
            "{REPOSITORY_URI}/actions/runs/{}/attempts/{}",
            request.run_id, request.run_attempt
        );
        [
            ("buildConfigDigest", request.provider_head.as_str()),
            ("buildConfigURI", CERTIFICATE_IDENTITY),
            ("buildSignerDigest", request.provider_head.as_str()),
            ("buildSignerURI", CERTIFICATE_IDENTITY),
            ("buildTrigger", "workflow_dispatch"),
            ("githubWorkflowName", "Collection Authority"),
            ("githubWorkflowRef", SOURCE_REF),
            ("githubWorkflowRepository", REPOSITORY),
            ("githubWorkflowSHA", request.provider_head.as_str()),
            ("githubWorkflowTrigger", "workflow_dispatch"),
            ("issuer", OIDC_ISSUER),
            ("runInvocationURI", invocation.as_str()),
            ("runnerEnvironment", "github-hosted"),
            ("sourceRepositoryDigest", request.provider_head.as_str()),
            ("sourceRepositoryIdentifier", "1327351238"),
            ("sourceRepositoryOwnerIdentifier", OWNER_ID),
            ("sourceRepositoryOwnerURI", OWNER_URI),
            ("sourceRepositoryRef", SOURCE_REF),
            ("sourceRepositoryURI", REPOSITORY_URI),
            ("sourceRepositoryVisibilityAtSigning", "public"),
            ("subjectAlternativeName", CERTIFICATE_IDENTITY),
        ]
        .into_iter()
        .map(|(field, value)| (field.to_owned(), json_string(value)))
        .collect()
    }

    #[test]
    fn attestation_bundle_certificate_and_timestamps_are_exact() {
        let digest = "b".repeat(sha256_bytes(b"").hex().len());
        let expected_statement = statement("custody-attestation-subject.json", &digest);
        let expected_bundle = bundle(&expected_statement);
        assert_eq!(
            validate_attestation_bundle(
                &expected_bundle,
                Path::new("custody-attestation-subject.json"),
                &digest,
            )
            .unwrap(),
            expected_statement
        );
        let request = capture_request();
        let mut certificate = certificate(&request);
        assert!(validate_certificate(&certificate, &request).is_ok());
        certificate.insert("githubWorkflowName".to_owned(), json_string("Nightly"));
        assert!(validate_certificate(&certificate, &request).is_err());
        let timestamp = |kind: &str, value: &str| {
            JsonValue::Object(BTreeMap::from([
                ("timestamp".to_owned(), json_string(value)),
                ("type".to_owned(), json_string(kind)),
            ]))
        };
        assert!(
            validate_verified_timestamps(
                &[timestamp("Tlog", "2026-08-12T00:00:00Z")],
                "2026-08-12T00:01:00Z",
            )
            .is_ok()
        );
        assert!(
            validate_verified_timestamps(
                &[timestamp("Tlog", "2026-08-12T00:02:00Z")],
                "2026-08-12T00:01:00Z",
            )
            .is_err()
        );
        assert!(
            validate_verified_timestamps(
                &[timestamp("TimestampAuthority", "2026-08-12T00:00:00Z")],
                "2026-08-12T00:01:00Z",
            )
            .is_err()
        );
    }

    fn verification_entry(
        bundle: &JsonValue,
        statement: &JsonValue,
        request: &CaptureRequest,
    ) -> JsonValue {
        JsonValue::Object(BTreeMap::from([
            ("attestation".to_owned(), bundle.clone()),
            (
                "verificationResult".to_owned(),
                JsonValue::Object(BTreeMap::from([
                    (
                        "signature".to_owned(),
                        JsonValue::Object(BTreeMap::from([(
                            "certificate".to_owned(),
                            JsonValue::Object(certificate(request)),
                        )])),
                    ),
                    ("statement".to_owned(), statement.clone()),
                    (
                        "verifiedIdentity".to_owned(),
                        JsonValue::Object(BTreeMap::from([
                            (
                                "issuer".to_owned(),
                                JsonValue::Object(BTreeMap::from([(
                                    "issuer".to_owned(),
                                    json_string(OIDC_ISSUER),
                                )])),
                            ),
                            (
                                "subjectAlternativeName".to_owned(),
                                JsonValue::Object(BTreeMap::from([(
                                    "subjectAlternativeName".to_owned(),
                                    json_string(CERTIFICATE_IDENTITY),
                                )])),
                            ),
                        ])),
                    ),
                    (
                        "verifiedTimestamps".to_owned(),
                        JsonValue::Array(vec![JsonValue::Object(BTreeMap::from([
                            ("timestamp".to_owned(), json_string("2026-08-12T00:00:00Z")),
                            ("type".to_owned(), json_string("Tlog")),
                        ]))]),
                    ),
                ])),
            ),
        ]))
    }

    #[test]
    fn attestation_verification_crossjoins_bundle_statement_identity_and_time() {
        let request = capture_request();
        let digest = "b".repeat(sha256_bytes(b"").hex().len());
        let statement = statement("custody-attestation-subject.json", &digest);
        let bundle = bundle(&statement);
        let entry = verification_entry(&bundle, &statement, &request);
        let raw = canonical_json_bytes(&JsonValue::Array(vec![entry.clone()])).unwrap();
        assert!(
            validate_attestation_verification(
                &raw,
                &bundle,
                &statement,
                &request,
                "2026-08-12T00:01:00Z",
            )
            .is_ok()
        );
        let JsonValue::Object(mut wrong_bundle) = bundle.clone() else {
            panic!("fixture bundle is not an object");
        };
        wrong_bundle.insert(
            "mediaType".to_owned(),
            json_string("application/octet-stream"),
        );
        let wrong_bundle = JsonValue::Object(wrong_bundle);
        assert!(
            validate_attestation_verification(
                &raw,
                &wrong_bundle,
                &statement,
                &request,
                "2026-08-12T00:01:00Z",
            )
            .is_err()
        );
        let malformed =
            canonical_json_bytes(&JsonValue::Array(vec![entry, JsonValue::Null])).unwrap();
        assert!(
            validate_attestation_verification(
                &malformed,
                &bundle,
                &statement,
                &request,
                "2026-08-12T00:01:00Z",
            )
            .is_err()
        );
    }

    #[test]
    fn attestation_argv_is_canonical_and_transport_is_reachable() {
        let request = capture_request();
        let arguments = attestation_verify_arguments(
            &request.subject,
            &request.bundle,
            &request.trusted_root,
            &request.provider_head,
        );
        assert_eq!(arguments.first(), Some(&OsString::from("attestation")));
        let canonical = std::iter::once(OsString::from("gh"))
            .chain(arguments)
            .collect::<Vec<_>>();
        assert_eq!(canonical.first(), Some(&OsString::from("gh")));
        assert!(recognizes(&[
            OsString::from("collection-authority"),
            OsString::from("capture-custody-attestation"),
        ]));
        assert!(!recognizes(&[
            OsString::from("collection-authority"),
            OsString::from("verify"),
        ]));
    }

    fn transport_temporaries(label: &str) -> BTreeSet<PathBuf> {
        let prefix = format!("hell-collection-{label}-{}-", std::process::id());
        fs::read_dir(std::env::temp_dir())
            .unwrap()
            .filter_map(Result::ok)
            .filter_map(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.starts_with(&prefix))
                    .then(|| entry.path())
            })
            .collect()
    }

    #[test]
    fn gh_spawn_failure_cleans_private_configuration() {
        let before = transport_temporaries("gh-config");
        assert!(
            run_gh(
                Path::new("definitely-not-a-reviewed-gh"),
                std::iter::empty::<&OsStr>(),
                true,
            )
            .is_err()
        );
        assert_eq!(transport_temporaries("gh-config"), before);
    }

    fn command_environment(command: &Command) -> BTreeMap<OsString, Option<OsString>> {
        command
            .get_envs()
            .map(|(name, value)| (name.to_owned(), value.map(OsStr::to_owned)))
            .collect()
    }

    #[test]
    fn provider_and_offline_gh_environments_are_exact_and_isolated() {
        let mut provider = Command::new("fixture-gh");
        configure_provider_environment(&mut provider, Path::new("fixture-config"), "fixture-token");
        let provider = command_environment(&provider);
        assert_eq!(
            provider.get(OsStr::new("GH_TOKEN")),
            Some(&Some(OsString::from("fixture-token")))
        );
        assert_eq!(
            provider.get(OsStr::new("GH_CONFIG_DIR")),
            Some(&Some(OsString::from("fixture-config")))
        );
        assert_eq!(
            provider.get(OsStr::new("GH_HOST")),
            Some(&Some(OsString::from("github.com")))
        );
        for removed in ["GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_HOST"] {
            assert_eq!(provider.get(OsStr::new(removed)), Some(&None));
        }

        let mut offline = Command::new("fixture-gh");
        configure_gh_environment(&mut offline, Path::new("fixture-config"), true);
        let offline = command_environment(&offline);
        for proxy in [
            "ALL_PROXY",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "all_proxy",
            "http_proxy",
            "https_proxy",
        ] {
            assert_eq!(
                offline.get(OsStr::new(proxy)),
                Some(&Some(OsString::from("http://127.0.0.1:9")))
            );
        }
        for removed in ["GITHUB_TOKEN", "GH_TOKEN", "GH_ENTERPRISE_TOKEN"] {
            assert_eq!(offline.get(OsStr::new(removed)), Some(&None));
        }
    }

    #[test]
    fn provider_failure_cleans_campaign_and_copied_outputs() {
        let temporary = private_temporary("provider-cleanup-test").unwrap();
        let mut request = provider_request();
        request.output = temporary.join("collection-provider");
        let copied = temporary.join("native-shards/linux-amd64");
        fs::create_dir(&request.output).unwrap();
        fs::create_dir_all(&copied).unwrap();
        let error = finalize_provider_acquisition(
            &request,
            Err("simulated gh configuration cleanup failure".to_owned()),
        )
        .unwrap_err();
        assert!(error.contains("simulated gh configuration cleanup failure"));
        assert!(!request.output.exists());
        assert!(!copied.exists());
        fs::remove_dir_all(temporary).unwrap();
    }

    #[test]
    fn capture_paths_require_regular_sibling_install_and_distinct_outputs() {
        let temporary = private_temporary("capture-path-test").unwrap();
        let install = temporary.join("install");
        let output = temporary.join("output");
        fs::create_dir(&install).unwrap();
        fs::create_dir(&output).unwrap();
        let gh = install.join("gh");
        let manifest = install.join("gh-install-manifest.json");
        let subject = temporary.join("subject.json");
        let bundle = temporary.join("bundle.json");
        fs::write(&gh, b"fixture").unwrap();
        set_executable(&gh).unwrap();
        fs::write(&manifest, b"fixture").unwrap();
        fs::write(&subject, b"fixture").unwrap();
        fs::write(&bundle, b"fixture").unwrap();
        let mut request = capture_request();
        request.gh = gh;
        request.install_manifest = manifest;
        request.subject = subject;
        request.bundle = bundle;
        request.trusted_root = output.join("root.jsonl");
        request.provenance = output.join("provenance.json");
        request.raw_verification = output.join("raw.json");
        request.online_verification = output.join("online.json");
        assert!(validate_capture_io_paths(&request).is_ok());
        request.online_verification = request.raw_verification.clone();
        assert!(validate_capture_io_paths(&request).is_err());
        fs::remove_dir_all(temporary).unwrap();
    }

    fn reviewed_manifest_fixture() -> Vec<u8> {
        canonical_json_bytes(&gh_install_manifest(
            &GhArchive {
                binary: Vec::new(),
                inventory_sha256: sha256_bytes(b"fixture inventory"),
                member_count: 1,
            },
            &format!("{GH_ARCHIVE_SHA256}  {GH_ARCHIVE_NAME}"),
        ))
        .unwrap()
    }

    #[test]
    fn reviewed_gh_install_rejects_binary_manifest_and_sibling_substitution() {
        let temporary = private_temporary("gh-pin-test").unwrap();
        let first = temporary.join("first");
        let second = temporary.join("second");
        fs::create_dir(&first).unwrap();
        fs::create_dir(&second).unwrap();
        let gh = first.join("gh");
        let manifest = first.join("gh-install-manifest.json");
        fs::write(&gh, b"not the reviewed binary").unwrap();
        set_executable(&gh).unwrap();
        fs::write(&manifest, reviewed_manifest_fixture()).unwrap();
        assert!(validate_reviewed_gh_install(&gh, &manifest).is_err());
        let wrong_sibling = second.join("gh-install-manifest.json");
        fs::write(&wrong_sibling, reviewed_manifest_fixture()).unwrap();
        assert!(validate_reviewed_gh_install(&gh, &wrong_sibling).is_err());
        let mut wrong_manifest =
            parse_json(std::str::from_utf8(&reviewed_manifest_fixture()).unwrap()).unwrap();
        let JsonValue::Object(fields) = &mut wrong_manifest else {
            panic!("fixture manifest is not an object");
        };
        fields.insert("ghReleaseVersion".to_owned(), json_string("2.92.0"));
        fs::write(&manifest, canonical_json_bytes(&wrong_manifest).unwrap()).unwrap();
        assert!(validate_reviewed_gh_install(&gh, &manifest).is_err());
        fs::remove_dir_all(temporary).unwrap();
    }
}
