//! Content-addressed acquisition of the pinned Linux release oracle.

use std::ffi::OsString;
use std::fs;
use std::io::Write as _;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

use hell_testkit::{Digest, sha256_bytes, sha256_file};

const REPOSITORY: &str = "chrisdone/hell";
const RELEASE_TAG: &str = "2026-05-29";
const ASSET_NAME: &str = "hell-linux-amd64";
const RELEASE_API_URL: &str =
    "https://api.github.com/repos/chrisdone/hell/releases/tags/2026-05-29";
const TAG_REF_API_URL: &str = "https://api.github.com/repos/chrisdone/hell/git/ref/tags/2026-05-29";
const UPSTREAM_COMMIT: &str = "d4d028609ed46a560c62caea8c70e7e91d1afd29";
const COMMIT_API_URL: &str =
    "https://api.github.com/repos/chrisdone/hell/commits/d4d028609ed46a560c62caea8c70e7e91d1afd29";
const RELEASE_URL: &str = "https://github.com/chrisdone/hell/releases/tag/2026-05-29";
const ASSET_DOWNLOAD_URL: &str =
    "https://github.com/chrisdone/hell/releases/download/2026-05-29/hell-linux-amd64";
const EXPECTED_SHA256: &str = "5ccc78e62200eb5aea8b9da9161334c61848d0d3e7de2f270929920cfbf357c9";
const JQ_RELEASE_FACTS: &str = r#"[
  .id,
  .tag_name,
  .target_commitish,
  .html_url,
  .published_at,
  ([.assets[] | select(.name == "hell-linux-amd64")] | length),
  (.assets[] | select(.name == "hell-linux-amd64") | .id),
  (.assets[] | select(.name == "hell-linux-amd64") | .url),
  (.assets[] | select(.name == "hell-linux-amd64") | .browser_download_url),
  (.assets[] | select(.name == "hell-linux-amd64") | .size),
  (.assets[] | select(.name == "hell-linux-amd64") | .digest)
] | .[]"#;
const JQ_TAG_FACTS: &str = r"[.ref, .object.type, .object.sha, .url, .object.url] | .[]";
const JQ_COMMIT_FACTS: &str = r"[.sha, .html_url, .commit.tree.sha, .commit.tree.url] | .[]";
const JQ_TRANSPORT_FACTS: &str = r#"if (keys | sort) == ["contentLength","effectiveHost","effectiveUrlSha256","etag","httpStatus","lastModified","redirectHosts","requestUrl","schemaVersion","sslVerifyResult"] then [.schemaVersion, .requestUrl, .effectiveHost, .effectiveUrlSha256, .httpStatus, (.redirectHosts | join(",")), .sslVerifyResult, .etag, .lastModified, .contentLength] | .[] else error("unexpected transport schema") end"#;
const JQ_CONTEXT_FACTS: &str = r#"if (keys | sort) == ["acquiredAt","acquirerActorId","channel","imageOs","imageVersion","repositoryId","runAttempt","runId","runnerArch","runnerOs","schemaVersion","workflowRef"] then [.schemaVersion, .acquiredAt, .acquirerActorId, .repositoryId, .runId, .runAttempt, .workflowRef, .runnerOs, .runnerArch, .imageOs, .imageVersion, .channel] | .[] else error("unexpected context schema") end"#;
const JQ_TOOLCHAIN_FACTS: &str = r#"if (keys | sort) == ["curlVersion","jqVersion","opensslVersion","schemaVersion"] then [.schemaVersion, .curlVersion, .jqVersion, .opensslVersion] | .[] else error("unexpected toolchain schema") end"#;
const JQ_TLS_FACTS: &str = r#"if (keys | sort) == ["certificateSha256","host","issuer","schemaVersion","spkiSha256","subject"] then [.schemaVersion, .host, .subject, .issuer, .certificateSha256, .spkiSha256] | .[] else error("unexpected TLS schema") end"#;

struct Options {
    action: String,
    artifact: PathBuf,
    provider_response: PathBuf,
    receipt: PathBuf,
    attestation: Option<PathBuf>,
}

struct ReleaseFacts {
    release_id: u64,
    target_commitish: String,
    published_at: String,
    asset_id: u64,
    asset_api_url: String,
    asset_size: u64,
    upstream_tree: String,
}

struct ProviderPaths {
    release: PathBuf,
    tag_ref: PathBuf,
    commit: PathBuf,
    transport: PathBuf,
    context: PathBuf,
    toolchain: PathBuf,
    tls: PathBuf,
}

struct ProviderDocuments {
    release: Vec<u8>,
    tag_ref: Vec<u8>,
    commit: Vec<u8>,
}

struct DownloadTransport {
    effective_host: String,
    effective_url_sha256: Digest,
    http_status: u64,
    redirect_hosts: Vec<String>,
    ssl_verify_result: u64,
    etag: String,
    last_modified: String,
    content_length: u64,
}

struct AcquisitionContext {
    acquired_at: String,
    actor_id: u64,
    repository_id: u64,
    run_id: u64,
    run_attempt: u64,
    workflow_ref: String,
    runner_os: String,
    runner_arch: String,
    image_os: String,
    image_version: String,
}

struct ToolchainFacts {
    curl: String,
    jq: String,
    openssl: String,
}

struct TlsFacts {
    host: String,
    subject: String,
    issuer: String,
    certificate_sha256: Digest,
    spki_sha256: Digest,
}

struct RetainedDocumentDigests {
    provider: Digest,
    tag_ref: Digest,
    commit: Digest,
    transport: Digest,
    context: Digest,
    toolchain: Digest,
    tls: Digest,
}

pub(crate) struct AcquisitionIdentity {
    pub(crate) receipt_id: String,
    pub(crate) receipt_sha256: Digest,
}

pub(crate) fn recognizes(arguments: &[OsString]) -> bool {
    arguments.first().and_then(|value| value.to_str()) == Some("release-oracle")
}

pub(crate) fn run(arguments: &[OsString]) -> Result<String, String> {
    let options = parse(arguments)?;
    match options.action.as_str() {
        "acquire" => acquire(&options),
        "attest" => attest(&options),
        "verify" => verify(&options),
        _ => Err("release-oracle action must be acquire, attest, or verify".into()),
    }
}

fn parse(arguments: &[OsString]) -> Result<Options, String> {
    let mut arguments = arguments.iter();
    if arguments.next().and_then(|value| value.to_str()) != Some("release-oracle") {
        return Err("release-oracle subcommand is missing".into());
    }
    let action = arguments
        .next()
        .and_then(|value| value.to_str())
        .ok_or_else(|| "release-oracle action is missing or not UTF-8".to_owned())?
        .to_owned();
    let mut artifact = None;
    let mut provider_response = None;
    let mut receipt = None;
    let mut attestation = None;
    while let Some(flag) = arguments.next() {
        let value = arguments
            .next()
            .ok_or_else(|| "release-oracle option has no value".to_owned())?;
        match flag.to_str() {
            Some("--artifact") if artifact.is_none() => artifact = Some(PathBuf::from(value)),
            Some("--provider-response") if provider_response.is_none() => {
                provider_response = Some(PathBuf::from(value));
            }
            Some("--receipt") if receipt.is_none() => receipt = Some(PathBuf::from(value)),
            Some("--attestation") if attestation.is_none() => {
                attestation = Some(PathBuf::from(value));
            }
            _ => return Err("release-oracle option is unknown or repeated".into()),
        }
    }
    Ok(Options {
        action,
        artifact: artifact.ok_or_else(|| "release-oracle requires --artifact".to_owned())?,
        provider_response: provider_response
            .ok_or_else(|| "release-oracle requires --provider-response".to_owned())?,
        receipt: receipt.ok_or_else(|| "release-oracle requires --receipt".to_owned())?,
        attestation,
    })
}

fn attest(options: &Options) -> Result<String, String> {
    let output = options
        .attestation
        .as_deref()
        .ok_or_else(|| "release-oracle attest requires --attestation".to_owned())?;
    crate::assurance::sign_linux_release_acquisition(
        &options.artifact,
        &options.provider_response,
        &options.receipt,
        output,
    )?;
    Ok(format!(
        "signed Linux release oracle acquisition at {}",
        output.display()
    ))
}

fn acquire(options: &Options) -> Result<String, String> {
    let paths = provider_paths(&options.provider_response)?;
    let providers = query_provider()?;
    let facts = release_facts(&providers)?;
    write_atomic(&paths.release, &providers.release)?;
    write_atomic(&paths.tag_ref, &providers.tag_ref)?;
    write_atomic(&paths.commit, &providers.commit)?;
    let transport = download_artifact(&options.artifact)?;
    write_atomic(&paths.transport, transport_json(&transport).as_bytes())?;
    let context = acquisition_context()?;
    write_atomic(&paths.context, context_json(&context).as_bytes())?;
    let toolchain = toolchain_facts()?;
    write_atomic(&paths.toolchain, toolchain_json(&toolchain).as_bytes())?;
    let tls = tls_facts(&transport.effective_host)?;
    write_atomic(&paths.tls, tls_json(&tls).as_bytes())?;
    let receipt = receipt_json(options, &facts)?;
    write_atomic(&options.receipt, receipt.as_bytes())?;
    write_receipt_digest(&options.receipt, receipt.as_bytes())?;
    verify_acquisition(
        &options.artifact,
        &options.provider_response,
        &options.receipt,
    )?;
    Ok(format!(
        "acquired Linux release oracle asset {} from release {}",
        facts.asset_id, facts.release_id
    ))
}

fn verify(options: &Options) -> Result<String, String> {
    let attestation = options
        .attestation
        .as_deref()
        .ok_or_else(|| "release-oracle verify requires --attestation".to_owned())?;
    let identity = crate::assurance::verify_linux_release_acquisition(
        &options.artifact,
        &options.provider_response,
        &options.receipt,
        attestation,
    )?;
    Ok(format!(
        "verified Linux release oracle receipt {}",
        identity.receipt_sha256.hex()
    ))
}

pub(crate) fn verify_acquisition(
    artifact: &Path,
    provider_response: &Path,
    receipt: &Path,
) -> Result<AcquisitionIdentity, String> {
    let options = Options {
        action: "verify".into(),
        artifact: artifact.to_owned(),
        provider_response: provider_response.to_owned(),
        receipt: receipt.to_owned(),
        attestation: None,
    };
    let paths = provider_paths(&options.provider_response)?;
    let providers = read_provider_documents(&paths)?;
    let facts = release_facts(&providers)?;
    let expected = receipt_json(&options, &facts)?;
    let observed = fs::read(&options.receipt)
        .map_err(|error| format!("cannot read release oracle receipt: {error}"))?;
    if observed != expected.as_bytes() {
        return Err("release oracle receipt is stale or non-canonical".into());
    }
    let digest_path = receipt_digest_path(&options.receipt)?;
    let digest = fs::read_to_string(&digest_path)
        .map_err(|error| format!("cannot read release oracle receipt digest: {error}"))?;
    let file_name = options
        .receipt
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "release oracle receipt filename is not UTF-8".to_owned())?;
    let expected_digest = format!("{}  {file_name}\n", sha256_bytes(&observed).hex());
    if digest != expected_digest {
        return Err("release oracle receipt digest does not match canonical bytes".into());
    }
    Ok(AcquisitionIdentity {
        receipt_id: receipt_id(&facts),
        receipt_sha256: sha256_bytes(&observed),
    })
}

fn receipt_id(facts: &ReleaseFacts) -> String {
    format!("github-release:{}:{}", facts.release_id, facts.asset_id)
}

fn provider_paths(release: &Path) -> Result<ProviderPaths, String> {
    let parent = release
        .parent()
        .ok_or_else(|| "release provider response has no parent directory".to_owned())?;
    Ok(ProviderPaths {
        release: release.to_owned(),
        tag_ref: parent.join("linux-release-tag-ref.json"),
        commit: parent.join("linux-release-commit.json"),
        transport: parent.join("linux-release-download-transport.json"),
        context: parent.join("linux-release-acquisition-context.json"),
        toolchain: parent.join("linux-release-acquisition-toolchain.json"),
        tls: parent.join("linux-release-download-tls.json"),
    })
}

fn read_provider_documents(paths: &ProviderPaths) -> Result<ProviderDocuments, String> {
    let read = |path: &Path, label: &str| {
        fs::read(path).map_err(|error| format!("cannot read {label}: {error}"))
    };
    Ok(ProviderDocuments {
        release: read(&paths.release, "release provider response")?,
        tag_ref: read(&paths.tag_ref, "release tag provider response")?,
        commit: read(&paths.commit, "release commit provider response")?,
    })
}

fn query_provider() -> Result<ProviderDocuments, String> {
    Ok(ProviderDocuments {
        release: query_provider_document(RELEASE_API_URL)?,
        tag_ref: query_provider_document(TAG_REF_API_URL)?,
        commit: query_provider_document(COMMIT_API_URL)?,
    })
}

fn query_provider_document(url: &str) -> Result<Vec<u8>, String> {
    let output = Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--tlsv1.2",
            "--proto",
            "=https",
            "--header",
            "Accept: application/vnd.github+json",
            "--header",
            "X-GitHub-Api-Version: 2022-11-28",
            url,
        ])
        .output()
        .map_err(|error| format!("cannot execute release provider client: {error}"))?;
    if !output.status.success() || output.stdout.is_empty() {
        return Err("release provider API request failed or returned empty bytes".into());
    }
    Ok(output.stdout)
}

fn release_facts(providers: &ProviderDocuments) -> Result<ReleaseFacts, String> {
    let fields = selected_fields(&providers.release, JQ_RELEASE_FACTS, 11)?;
    let tag_fields = selected_fields(&providers.tag_ref, JQ_TAG_FACTS, 5)?;
    let commit_fields = selected_fields(&providers.commit, JQ_COMMIT_FACTS, 4)?;
    if tag_fields[0] != format!("refs/tags/{RELEASE_TAG}")
        || tag_fields[1] != "commit"
        || tag_fields[2] != UPSTREAM_COMMIT
        || tag_fields[3] != TAG_REF_API_URL
        || tag_fields[4]
            != format!("https://api.github.com/repos/{REPOSITORY}/git/commits/{UPSTREAM_COMMIT}")
        || commit_fields[0] != UPSTREAM_COMMIT
        || commit_fields[1] != format!("https://github.com/{REPOSITORY}/commit/{UPSTREAM_COMMIT}")
        || commit_fields[3]
            != format!(
                "https://api.github.com/repos/{REPOSITORY}/git/trees/{}",
                commit_fields[2]
            )
    {
        return Err("release tag does not resolve to the pinned upstream commit and tree".into());
    }
    require_git_sha(&commit_fields[2], "release source tree")?;
    release_facts_from_fields(&fields, &commit_fields[2])
}

fn selected_fields(
    provider_bytes: &[u8],
    program: &str,
    count: usize,
) -> Result<Vec<String>, String> {
    let mut child = Command::new("jq")
        .args(["--exit-status", "--raw-output", program])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("cannot execute strict provider JSON selector: {error}"))?;
    child
        .stdin
        .take()
        .ok_or_else(|| "provider JSON selector stdin is unavailable".to_owned())?
        .write_all(provider_bytes)
        .map_err(|error| format!("cannot send provider JSON to selector: {error}"))?;
    let output = child
        .wait_with_output()
        .map_err(|error| format!("cannot wait for provider JSON selector: {error}"))?;
    if !output.status.success() {
        return Err("release provider response failed strict selection".into());
    }
    let text = std::str::from_utf8(&output.stdout)
        .map_err(|_| "release provider facts are not UTF-8".to_owned())?;
    let fields = text.lines().map(ToOwned::to_owned).collect::<Vec<_>>();
    if fields.len() != count {
        return Err("release provider response has an unexpected fact count".into());
    }
    Ok(fields)
}

fn release_facts_from_fields(
    fields: &[String],
    upstream_tree: &str,
) -> Result<ReleaseFacts, String> {
    if fields[1] != RELEASE_TAG
        || fields[3] != RELEASE_URL
        || fields[5] != "1"
        || fields[8] != ASSET_DOWNLOAD_URL
        || fields[10] != format!("sha256:{EXPECTED_SHA256}")
    {
        return Err("release provider identity or content digest is not the pinned asset".into());
    }
    let release_id = positive_number(&fields[0], "release ID")?;
    let asset_id = positive_number(&fields[6], "release asset ID")?;
    let expected_api_url =
        format!("https://api.github.com/repos/{REPOSITORY}/releases/assets/{asset_id}");
    if fields[7] != expected_api_url {
        return Err("release asset API identity is not canonical".into());
    }
    require_atom(&fields[2], "release target commitish")?;
    require_utc(&fields[4])?;
    Ok(ReleaseFacts {
        release_id,
        target_commitish: fields[2].clone(),
        published_at: fields[4].clone(),
        asset_id,
        asset_api_url: fields[7].clone(),
        asset_size: positive_number(&fields[9], "release asset size")?,
        upstream_tree: upstream_tree.to_owned(),
    })
}

fn download_artifact(path: &Path) -> Result<DownloadTransport, String> {
    let parent = path
        .parent()
        .ok_or_else(|| "release oracle artifact has no parent directory".to_owned())?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("cannot create release oracle directory: {error}"))?;
    let temporary = sibling_temporary(path)?;
    let headers = parent.join("linux-release-download-headers.tmp");
    let output = Command::new("curl")
        .args([
            "--fail",
            "--location",
            "--silent",
            "--show-error",
            "--tlsv1.2",
            "--proto",
            "=https",
            "--header",
            "Accept-Encoding: identity",
            "--dump-header",
        ])
        .arg(&headers)
        .args([
            "--write-out",
            "%{http_code}\n%{num_redirects}\n%{url_effective}\n%{ssl_verify_result}\n",
            "--output",
        ])
        .arg(&temporary)
        .arg(ASSET_DOWNLOAD_URL)
        .output()
        .map_err(|error| format!("cannot execute release asset client: {error}"))?;
    if !output.status.success() || !output.stderr.is_empty() {
        return Err("release asset download failed".into());
    }
    let transport_fields = std::str::from_utf8(&output.stdout)
        .map_err(|_| "release asset transport facts are not UTF-8".to_owned())?
        .lines()
        .collect::<Vec<_>>();
    if transport_fields.len() != 4 {
        return Err("release asset transport fact count is not canonical".into());
    }
    let http_status = positive_number(transport_fields[0], "release HTTP status")?;
    let redirect_count = transport_fields[1]
        .parse::<usize>()
        .map_err(|_| "release redirect count is malformed".to_owned())?;
    let effective_url = transport_fields[2];
    let effective_host = allowed_effective_host(effective_url)?;
    let ssl_verify_result = transport_fields[3]
        .parse::<u64>()
        .map_err(|_| "release TLS verification result is malformed".to_owned())?;
    let header_bytes = fs::read(&headers)
        .map_err(|error| format!("cannot read release response headers: {error}"))?;
    fs::remove_file(&headers)
        .map_err(|error| format!("cannot remove release response header scratch file: {error}"))?;
    let header_facts = parse_download_headers(&header_bytes)?;
    if http_status != 200
        || header_facts.http_status != http_status
        || header_facts.redirect_hosts.len() != redirect_count + 1
        || header_facts.redirect_hosts.last().map(String::as_str) != Some(effective_host)
        || ssl_verify_result != 0
    {
        return Err("release download HTTP, redirect, or TLS result is not acceptable".into());
    }
    fs::rename(&temporary, path)
        .map_err(|error| format!("cannot install release oracle atomically: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mut permissions = fs::metadata(path)
            .map_err(|error| format!("cannot stat installed release oracle: {error}"))?
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions)
            .map_err(|error| format!("cannot make release oracle executable: {error}"))?;
    }
    Ok(DownloadTransport {
        effective_host: effective_host.to_owned(),
        effective_url_sha256: sha256_bytes(effective_url.as_bytes()),
        http_status,
        redirect_hosts: header_facts.redirect_hosts,
        ssl_verify_result,
        etag: header_facts.etag,
        last_modified: header_facts.last_modified,
        content_length: header_facts.content_length,
    })
}

struct DownloadHeaderFacts {
    http_status: u64,
    redirect_hosts: Vec<String>,
    etag: String,
    last_modified: String,
    content_length: u64,
}

fn parse_download_headers(bytes: &[u8]) -> Result<DownloadHeaderFacts, String> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| "release response headers are not UTF-8".to_owned())?;
    let normalized = text.replace("\r\n", "\n");
    let blocks = normalized
        .split("\n\n")
        .filter(|block| !block.trim().is_empty())
        .collect::<Vec<_>>();
    if blocks.is_empty() {
        return Err("release response headers contain no HTTP response".into());
    }
    let mut redirect_hosts = vec!["github.com".to_owned()];
    for block in &blocks[..blocks.len() - 1] {
        let status = header_status(block)?;
        if !(300..400).contains(&status) {
            return Err("release redirect response has a non-redirect status".into());
        }
        let location = required_header(block, "location")?;
        redirect_hosts.push(allowed_effective_host(location)?.to_owned());
    }
    let final_block = blocks
        .last()
        .ok_or_else(|| "release response header final block is missing".to_owned())?;
    Ok(DownloadHeaderFacts {
        http_status: header_status(final_block)?,
        redirect_hosts,
        etag: required_header(final_block, "etag")?.to_owned(),
        last_modified: required_header(final_block, "last-modified")?.to_owned(),
        content_length: positive_number(
            required_header(final_block, "content-length")?,
            "release response content length",
        )?,
    })
}

fn header_status(block: &str) -> Result<u64, String> {
    let line = block
        .lines()
        .next()
        .ok_or_else(|| "release response status line is missing".to_owned())?;
    let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
    if fields.len() < 2 || !fields[0].starts_with("HTTP/") {
        return Err("release response status line is malformed".into());
    }
    positive_number(fields[1], "release response status")
}

fn required_header<'a>(block: &'a str, name: &str) -> Result<&'a str, String> {
    let mut values = block.lines().skip(1).filter_map(|line| {
        let (observed_name, value) = line.split_once(':')?;
        observed_name
            .eq_ignore_ascii_case(name)
            .then_some(value.trim())
    });
    let value = values
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("release response {name} header is missing"))?;
    if values.next().is_some() || value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(format!(
            "release response {name} header is not singular and canonical"
        ));
    }
    Ok(value)
}

fn allowed_effective_host(url: &str) -> Result<&str, String> {
    let authority = url
        .strip_prefix("https://")
        .and_then(|suffix| suffix.split('/').next())
        .ok_or_else(|| "release asset effective URL is not canonical HTTPS".to_owned())?;
    if !matches!(
        authority,
        "github.com" | "release-assets.githubusercontent.com"
    ) {
        return Err("release asset redirect host is not allowlisted".into());
    }
    Ok(authority)
}

fn transport_json(transport: &DownloadTransport) -> String {
    format!(
        "{{\n  \"schemaVersion\": 2,\n  \"requestUrl\": \"{ASSET_DOWNLOAD_URL}\",\n  \"effectiveHost\": \"{}\",\n  \"effectiveUrlSha256\": \"{}\",\n  \"httpStatus\": {},\n  \"redirectHosts\": {},\n  \"sslVerifyResult\": {},\n  \"etag\": {},\n  \"lastModified\": {},\n  \"contentLength\": {}\n}}\n",
        transport.effective_host,
        transport.effective_url_sha256.hex(),
        transport.http_status,
        json_string_array(&transport.redirect_hosts),
        transport.ssl_verify_result,
        json_string(&transport.etag),
        json_string(&transport.last_modified),
        transport.content_length,
    )
}

fn acquisition_context() -> Result<AcquisitionContext, String> {
    let required = |name: &str| {
        std::env::var(name).map_err(|_| format!("release acquisition environment lacks {name}"))
    };
    let positive_env = |name: &str| {
        let value = required(name)?;
        positive_number(&value, name)
    };
    let workflow_ref = required("GITHUB_WORKFLOW_REF")?;
    require_context_atom(&workflow_ref, "release acquisition workflow ref")?;
    let runner_os = required("RUNNER_OS")?;
    let runner_arch = required("RUNNER_ARCH")?;
    let image_os = required("ImageOS")?;
    let image_version = required("ImageVersion")?;
    for (value, label) in [
        (&runner_os, "release acquisition runner OS"),
        (&runner_arch, "release acquisition runner architecture"),
        (&image_os, "release acquisition image OS"),
        (&image_version, "release acquisition image version"),
    ] {
        require_context_atom(value, label)?;
    }
    if required("GITHUB_ACTIONS")?.as_str() != "true" {
        return Err("release acquisition did not run in GitHub Actions".into());
    }
    Ok(AcquisitionContext {
        acquired_at: crate::custody_ops::current_utc_timestamp()?,
        actor_id: positive_env("GITHUB_ACTOR_ID")?,
        repository_id: positive_env("GITHUB_REPOSITORY_ID")?,
        run_id: positive_env("GITHUB_RUN_ID")?,
        run_attempt: positive_env("GITHUB_RUN_ATTEMPT")?,
        workflow_ref,
        runner_os,
        runner_arch,
        image_os,
        image_version,
    })
}

fn context_json(context: &AcquisitionContext) -> String {
    format!(
        "{{\n  \"schemaVersion\": 1,\n  \"acquiredAt\": {},\n  \"acquirerActorId\": {},\n  \"repositoryId\": {},\n  \"runId\": {},\n  \"runAttempt\": {},\n  \"workflowRef\": {},\n  \"runnerOs\": {},\n  \"runnerArch\": {},\n  \"imageOs\": {},\n  \"imageVersion\": {},\n  \"channel\": \"github-actions-oidc\"\n}}\n",
        json_string(&context.acquired_at),
        context.actor_id,
        context.repository_id,
        context.run_id,
        context.run_attempt,
        json_string(&context.workflow_ref),
        json_string(&context.runner_os),
        json_string(&context.runner_arch),
        json_string(&context.image_os),
        json_string(&context.image_version),
    )
}

fn toolchain_facts() -> Result<ToolchainFacts, String> {
    Ok(ToolchainFacts {
        curl: command_version("curl", &["--version"], "curl")?,
        jq: command_version("jq", &["--version"], "jq")?,
        openssl: command_version("openssl", &["version"], "OpenSSL")?,
    })
}

fn command_version(program: &str, arguments: &[&str], label: &str) -> Result<String, String> {
    let output = Command::new(program)
        .args(arguments)
        .output()
        .map_err(|error| format!("cannot execute release acquisition {label}: {error}"))?;
    let stdout = std::str::from_utf8(&output.stdout)
        .map_err(|_| format!("release acquisition {label} version is not UTF-8"))?;
    let version = stdout
        .lines()
        .next()
        .filter(|line| !line.is_empty())
        .ok_or_else(|| format!("release acquisition {label} version is empty"))?;
    if !output.status.success()
        || version
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b'"')
    {
        return Err(format!(
            "release acquisition {label} version is not canonical"
        ));
    }
    Ok(version.to_owned())
}

fn toolchain_json(toolchain: &ToolchainFacts) -> String {
    format!(
        "{{\n  \"schemaVersion\": 1,\n  \"curlVersion\": {},\n  \"jqVersion\": {},\n  \"opensslVersion\": {}\n}}\n",
        json_string(&toolchain.curl),
        json_string(&toolchain.jq),
        json_string(&toolchain.openssl),
    )
}

fn tls_facts(host: &str) -> Result<TlsFacts, String> {
    match host {
        "github.com" | "release-assets.githubusercontent.com" => {}
        _ if valid_external_s3_host(host) => {}
        _ => return Err("release TLS host is not allowlisted".into()),
    }
    let endpoint = TlsServerEndpoint::new(host)?;
    let connection = Command::new("openssl")
        .args([
            "s_client",
            "-connect",
            endpoint.as_str(),
            "-servername",
            host,
            "-showcerts",
        ])
        .stdin(Stdio::null())
        .output()
        .map_err(|error| format!("cannot execute release TLS evidence probe: {error}"))?;
    if !connection.status.success() {
        return Err("release TLS evidence probe failed".into());
    }
    let certificate = first_pem_certificate(&connection.stdout)?;
    let identity = command_with_input(
        "openssl",
        &[
            "x509",
            "-noout",
            "-subject",
            "-issuer",
            "-fingerprint",
            "-sha256",
        ],
        certificate,
        "release TLS certificate identity",
    )?;
    let identity = std::str::from_utf8(&identity)
        .map_err(|_| "release TLS certificate identity is not UTF-8".to_owned())?;
    let mut lines = identity.lines();
    let subject = prefixed_line(lines.next(), "subject=", "release TLS subject")?;
    let issuer = prefixed_line(lines.next(), "issuer=", "release TLS issuer")?;
    let fingerprint = prefixed_line(
        lines.next(),
        "sha256 Fingerprint=",
        "release TLS certificate fingerprint",
    )?
    .replace(':', "");
    if lines.next().is_some() || Digest::from_hex(&fingerprint).is_err() {
        return Err("release TLS certificate identity has unexpected fields".into());
    }
    let public_key = command_with_input(
        "openssl",
        &["x509", "-pubkey", "-noout"],
        certificate,
        "release TLS public key",
    )?;
    let spki = command_with_input(
        "openssl",
        &["pkey", "-pubin", "-outform", "DER"],
        &public_key,
        "release TLS SPKI",
    )?;
    Ok(TlsFacts {
        host: host.to_owned(),
        subject: subject.to_owned(),
        issuer: issuer.to_owned(),
        certificate_sha256: sha256_bytes(certificate),
        spki_sha256: sha256_bytes(&spki),
    })
}

struct TlsServerEndpoint(String);

impl TlsServerEndpoint {
    fn new(host: &str) -> Result<Self, String> {
        if host.is_empty()
            || host.contains(':')
            || !host.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.')
            })
        {
            return Err("release TLS endpoint host is not canonical".to_owned());
        }
        let value = [host, "443"].join(":");
        let (decoded_host, decoded_port) = value
            .split_once(':')
            .ok_or_else(|| "release TLS endpoint lacks a port".to_owned())?;
        if decoded_host != host || decoded_port != "443" || decoded_port.contains(':') {
            return Err("release TLS endpoint is not canonical".to_owned());
        }
        Ok(Self(value))
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

fn valid_external_s3_host(host: &str) -> bool {
    host.ends_with(".amazonaws.com")
        && host.contains(".s3.")
        && host.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.')
        })
}

pub(crate) fn external_tls_identity_json(host: &str) -> Result<String, String> {
    tls_facts(host).map(|facts| tls_json(&facts))
}

fn first_pem_certificate(output: &[u8]) -> Result<&[u8], String> {
    const BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";
    const END: &[u8] = b"-----END CERTIFICATE-----";
    let start = output
        .windows(BEGIN.len())
        .position(|window| window == BEGIN)
        .ok_or_else(|| "release TLS probe returned no certificate".to_owned())?;
    let end_offset = output[start..]
        .windows(END.len())
        .position(|window| window == END)
        .ok_or_else(|| "release TLS certificate is incomplete".to_owned())?;
    let end = start + end_offset + END.len();
    Ok(&output[start..end])
}

fn command_with_input(
    program: &str,
    arguments: &[&str],
    input: &[u8],
    label: &str,
) -> Result<Vec<u8>, String> {
    let mut child = Command::new(program)
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("cannot execute {label}: {error}"))?;
    child
        .stdin
        .take()
        .ok_or_else(|| format!("{label} stdin is unavailable"))?
        .write_all(input)
        .map_err(|error| format!("cannot send input to {label}: {error}"))?;
    let output = child
        .wait_with_output()
        .map_err(|error| format!("cannot wait for {label}: {error}"))?;
    if !output.status.success() || !output.stderr.is_empty() || output.stdout.is_empty() {
        return Err(format!("{label} failed or returned incomplete evidence"));
    }
    Ok(output.stdout)
}

fn prefixed_line<'a>(line: Option<&'a str>, prefix: &str, label: &str) -> Result<&'a str, String> {
    let value = line
        .and_then(|line| line.strip_prefix(prefix))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{label} is missing"))?;
    if value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(format!("{label} is not canonical"));
    }
    Ok(value)
}

fn tls_json(tls: &TlsFacts) -> String {
    format!(
        "{{\n  \"schemaVersion\": 1,\n  \"host\": {},\n  \"subject\": {},\n  \"issuer\": {},\n  \"certificateSha256\": \"{}\",\n  \"spkiSha256\": \"{}\"\n}}\n",
        json_string(&tls.host),
        json_string(&tls.subject),
        json_string(&tls.issuer),
        tls.certificate_sha256.hex(),
        tls.spki_sha256.hex(),
    )
}

fn require_context_atom(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || value.bytes().any(|byte| {
            byte.is_ascii_control()
                || !matches!(
                    byte,
                    b'0'..=b'9'
                        | b'a'..=b'z'
                        | b'A'..=b'Z'
                        | b'.'
                        | b'/'
                        | b'_'
                        | b'-'
                        | b'@'
                )
        })
    {
        return Err(format!("{label} is not a canonical atom"));
    }
    Ok(())
}

fn json_string(value: &str) -> String {
    let mut output = String::with_capacity(value.len() + 2);
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character.is_control() => {
                use std::fmt::Write as _;
                write!(output, "\\u{:04x}", u32::from(character))
                    .expect("writing to a String cannot fail");
            }
            character => output.push(character),
        }
    }
    output.push('"');
    output
}

fn json_string_array(values: &[String]) -> String {
    let mut output = String::from("[");
    for (index, value) in values.iter().enumerate() {
        if index != 0 {
            output.push_str(", ");
        }
        output.push_str(&json_string(value));
    }
    output.push(']');
    output
}

fn require_git_sha(value: &str, label: &str) -> Result<(), String> {
    if value.len() != UPSTREAM_COMMIT.len()
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        || value.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err(format!("{label} is not a canonical Git object ID"));
    }
    Ok(())
}

fn receipt_json(options: &Options, facts: &ReleaseFacts) -> Result<String, String> {
    let artifact_sha256 = sha256_file(&options.artifact)
        .map_err(|error| format!("cannot hash release oracle artifact: {error}"))?;
    let expected = Digest::from_hex(EXPECTED_SHA256)
        .map_err(|error| format!("invalid pinned release oracle digest: {error}"))?;
    let observed_size = fs::metadata(&options.artifact)
        .map_err(|error| format!("cannot stat release oracle artifact: {error}"))?
        .len();
    if artifact_sha256 != expected || observed_size != facts.asset_size {
        return Err("release oracle bytes disagree with provider digest or size".into());
    }
    let paths = provider_paths(&options.provider_response)?;
    let transport_bytes = fs::read(&paths.transport)
        .map_err(|error| format!("cannot read release download transport: {error}"))?;
    let context_bytes = fs::read(&paths.context)
        .map_err(|error| format!("cannot read release acquisition context: {error}"))?;
    let toolchain_bytes = fs::read(&paths.toolchain)
        .map_err(|error| format!("cannot read release acquisition toolchain: {error}"))?;
    let tls_bytes = fs::read(&paths.tls)
        .map_err(|error| format!("cannot read release TLS evidence: {error}"))?;
    let transport = selected_fields(&transport_bytes, JQ_TRANSPORT_FACTS, 10)?;
    let context = selected_fields(&context_bytes, JQ_CONTEXT_FACTS, 12)?;
    let toolchain = selected_fields(&toolchain_bytes, JQ_TOOLCHAIN_FACTS, 4)?;
    let tls = selected_fields(&tls_bytes, JQ_TLS_FACTS, 6)?;
    if transport[0] != "2"
        || transport[1] != ASSET_DOWNLOAD_URL
        || !matches!(
            transport[2].as_str(),
            "github.com" | "release-assets.githubusercontent.com"
        )
        || Digest::from_hex(&transport[3]).is_err()
        || transport[4] != "200"
        || !valid_redirect_hosts(&transport[5], &transport[2])
        || transport[6] != "0"
        || transport[7].is_empty()
        || transport[8].is_empty()
        || positive_number(&transport[9], "release response content length")? != facts.asset_size
    {
        return Err("release download transport is not canonical or allowlisted".into());
    }
    validate_context(&context)?;
    validate_toolchain(&toolchain)?;
    validate_tls(&tls, &transport[2])?;
    let document_digests = retained_document_digests(
        &paths,
        &transport_bytes,
        &context_bytes,
        &toolchain_bytes,
        &tls_bytes,
    )?;
    let provider_path = retained_file_name(&paths.release)?;
    let tag_ref_path = retained_file_name(&paths.tag_ref)?;
    let commit_path = retained_file_name(&paths.commit)?;
    let transport_path = retained_file_name(&paths.transport)?;
    let context_path = retained_file_name(&paths.context)?;
    let toolchain_path = retained_file_name(&paths.toolchain)?;
    let tls_path = retained_file_name(&paths.tls)?;
    Ok(format!(
        "{{\n  \"schemaVersion\": 3,\n  \"receiptId\": \"{}\",\n  \"repository\": \"{REPOSITORY}\",\n  \"releaseTag\": \"{RELEASE_TAG}\",\n  \"releaseId\": {},\n  \"releaseUrl\": \"{RELEASE_URL}\",\n  \"targetCommitish\": \"{}\",\n  \"upstreamCommit\": \"{UPSTREAM_COMMIT}\",\n  \"upstreamTree\": \"{}\",\n  \"publishedAt\": \"{}\",\n  \"assetName\": \"{ASSET_NAME}\",\n  \"assetId\": {},\n  \"assetApiUrl\": \"{}\",\n  \"assetDownloadUrl\": \"{ASSET_DOWNLOAD_URL}\",\n  \"assetEffectiveHost\": \"{}\",\n  \"providerDigest\": \"sha256:{EXPECTED_SHA256}\",\n  \"observedSha256\": \"{}\",\n  \"observedSize\": {observed_size},\n  \"acquiredAt\": {},\n  \"acquirerActorId\": {},\n  \"repositoryId\": {},\n  \"runId\": {},\n  \"runAttempt\": {},\n  \"workflowRef\": {},\n  \"acquisitionChannel\": \"github-actions-oidc\",\n  \"httpStatus\": {},\n  \"redirectHosts\": {},\n  \"sslVerifyResult\": {},\n  \"etag\": {},\n  \"lastModified\": {},\n  \"contentLength\": {},\n  \"tlsSubject\": {},\n  \"tlsIssuer\": {},\n  \"tlsCertificateSha256\": \"{}\",\n  \"tlsSpkiSha256\": \"{}\",\n  \"providerResponsePath\": \"{provider_path}\",\n  \"providerResponseSha256\": \"{}\",\n  \"tagRefResponsePath\": \"{tag_ref_path}\",\n  \"tagRefResponseSha256\": \"{}\",\n  \"commitResponsePath\": \"{commit_path}\",\n  \"commitResponseSha256\": \"{}\",\n  \"downloadTransportPath\": \"{transport_path}\",\n  \"downloadTransportSha256\": \"{}\",\n  \"acquisitionContextPath\": \"{context_path}\",\n  \"acquisitionContextSha256\": \"{}\",\n  \"acquisitionToolchainPath\": \"{toolchain_path}\",\n  \"acquisitionToolchainSha256\": \"{}\",\n  \"tlsEvidencePath\": \"{tls_path}\",\n  \"tlsEvidenceSha256\": \"{}\",\n  \"curlVersion\": {},\n  \"jqVersion\": {},\n  \"opensslVersion\": {}\n}}\n",
        receipt_id(facts),
        facts.release_id,
        facts.target_commitish,
        facts.upstream_tree,
        facts.published_at,
        facts.asset_id,
        facts.asset_api_url,
        transport[2],
        artifact_sha256.hex(),
        json_string(&context[1]),
        context[2],
        context[3],
        context[4],
        context[5],
        json_string(&context[6]),
        transport[4],
        json_string_array(
            &transport[5]
                .split(',')
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        ),
        transport[6],
        json_string(&transport[7]),
        json_string(&transport[8]),
        transport[9],
        json_string(&tls[2]),
        json_string(&tls[3]),
        tls[4],
        tls[5],
        document_digests.provider.hex(),
        document_digests.tag_ref.hex(),
        document_digests.commit.hex(),
        document_digests.transport.hex(),
        document_digests.context.hex(),
        document_digests.toolchain.hex(),
        document_digests.tls.hex(),
        json_string(&toolchain[1]),
        json_string(&toolchain[2]),
        json_string(&toolchain[3]),
    ))
}

fn retained_document_digests(
    paths: &ProviderPaths,
    transport: &[u8],
    context: &[u8],
    toolchain: &[u8],
    tls: &[u8],
) -> Result<RetainedDocumentDigests, String> {
    let file_digest = |path: &Path, label: &str| {
        sha256_file(path).map_err(|error| format!("cannot hash {label}: {error}"))
    };
    Ok(RetainedDocumentDigests {
        provider: file_digest(&paths.release, "release provider response")?,
        tag_ref: file_digest(&paths.tag_ref, "release tag provider response")?,
        commit: file_digest(&paths.commit, "release commit provider response")?,
        transport: sha256_bytes(transport),
        context: sha256_bytes(context),
        toolchain: sha256_bytes(toolchain),
        tls: sha256_bytes(tls),
    })
}

fn valid_redirect_hosts(hosts: &str, effective_host: &str) -> bool {
    let hosts = hosts.split(',').collect::<Vec<_>>();
    hosts.len() >= 2
        && hosts.first() == Some(&"github.com")
        && hosts.last() == Some(&effective_host)
        && hosts
            .iter()
            .all(|host| matches!(*host, "github.com" | "release-assets.githubusercontent.com"))
}

fn validate_context(fields: &[String]) -> Result<(), String> {
    if fields[0] != "1" || fields[11] != "github-actions-oidc" {
        return Err("release acquisition context schema or channel is not canonical".into());
    }
    require_utc(&fields[1])?;
    for (index, label) in [
        (2, "release acquisition actor ID"),
        (3, "release acquisition repository ID"),
        (4, "release acquisition run ID"),
        (5, "release acquisition run attempt"),
    ] {
        positive_number(&fields[index], label)?;
    }
    if !fields[6].contains("/.github/workflows/nightly.yml@") {
        return Err("release acquisition workflow ref is not nightly.yml".into());
    }
    for (index, label) in [
        (6, "release acquisition workflow ref"),
        (7, "release acquisition runner OS"),
        (8, "release acquisition runner architecture"),
        (9, "release acquisition image OS"),
        (10, "release acquisition image version"),
    ] {
        require_context_atom(&fields[index], label)?;
    }
    Ok(())
}

fn validate_toolchain(fields: &[String]) -> Result<(), String> {
    if fields[0] != "1"
        || !fields[1].starts_with("curl ")
        || !fields[2].starts_with("jq-")
        || !fields[3].starts_with("OpenSSL ")
    {
        return Err("release acquisition toolchain is not canonical".into());
    }
    for value in &fields[1..] {
        if value.is_empty() || value.bytes().any(|byte| byte.is_ascii_control()) {
            return Err("release acquisition tool version is not canonical".into());
        }
    }
    Ok(())
}

fn validate_tls(fields: &[String], effective_host: &str) -> Result<(), String> {
    if fields[0] != "1"
        || fields[1] != effective_host
        || fields[2].is_empty()
        || fields[3].is_empty()
        || Digest::from_hex(&fields[4]).is_err()
        || Digest::from_hex(&fields[5]).is_err()
    {
        return Err(
            "release TLS identity is incomplete or does not match the download host".into(),
        );
    }
    Ok(())
}

fn write_receipt_digest(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "release oracle receipt filename is not UTF-8".to_owned())?;
    write_atomic(
        &receipt_digest_path(path)?,
        format!("{}  {name}\n", sha256_bytes(bytes).hex()).as_bytes(),
    )
}

fn receipt_digest_path(path: &Path) -> Result<PathBuf, String> {
    let name = path
        .file_name()
        .ok_or_else(|| "release oracle receipt has no filename".to_owned())?;
    let mut digest_name = name.to_os_string();
    digest_name.push(".sha256");
    Ok(path.with_file_name(digest_name))
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "release oracle output has no parent directory".to_owned())?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("cannot create release oracle output directory: {error}"))?;
    let temporary = sibling_temporary(path)?;
    fs::write(&temporary, bytes)
        .map_err(|error| format!("cannot write release oracle temporary output: {error}"))?;
    fs::rename(&temporary, path)
        .map_err(|error| format!("cannot install release oracle output atomically: {error}"))
}

fn sibling_temporary(path: &Path) -> Result<PathBuf, String> {
    let name = path
        .file_name()
        .ok_or_else(|| "release oracle output has no filename".to_owned())?;
    let mut temporary = name.to_os_string();
    temporary.push(".tmp");
    Ok(path.with_file_name(temporary))
}

fn positive_number(value: &str, label: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .ok()
        .filter(|value| *value != 0)
        .ok_or_else(|| format!("{label} is missing or malformed"))
}

fn require_atom(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'/' | b'_' | b'-'))
    {
        return Err(format!("{label} is not a canonical atom"));
    }
    Ok(())
}

fn require_utc(value: &str) -> Result<(), String> {
    let (date, time) = value
        .split_once('T')
        .ok_or_else(|| "release publication timestamp is not strict UTC".to_owned())?;
    let time = time
        .strip_suffix('Z')
        .ok_or_else(|| "release publication timestamp is not strict UTC".to_owned())?;
    let date_fields = date.split('-').collect::<Vec<_>>();
    let time_fields = time.split(':').collect::<Vec<_>>();
    let canonical_digits = |field: &str, width: usize| {
        field.len() == width && field.bytes().all(|byte| byte.is_ascii_digit())
    };
    if date_fields.len() != 3
        || time_fields.len() != 3
        || !canonical_digits(date_fields[0], 4)
        || !canonical_digits(date_fields[1], 2)
        || !canonical_digits(date_fields[2], 2)
        || !canonical_digits(time_fields[0], 2)
        || !canonical_digits(time_fields[1], 2)
        || !canonical_digits(time_fields[2], 2)
    {
        return Err("release publication timestamp is not strict UTC".into());
    }
    let month = positive_number(date_fields[1], "release publication month")?;
    let day = positive_number(date_fields[2], "release publication day")?;
    let hour = time_fields[0]
        .parse::<u64>()
        .map_err(|_| "release publication hour is malformed".to_owned())?;
    let minute = time_fields[1]
        .parse::<u64>()
        .map_err(|_| "release publication minute is malformed".to_owned())?;
    let second = time_fields[2]
        .parse::<u64>()
        .map_err(|_| "release publication second is malformed".to_owned())?;
    if month > 12 || day > 31 || hour > 23 || minute > 59 || second > 59 {
        return Err("release publication timestamp is outside UTC field bounds".into());
    }
    Ok(())
}

fn path_text(path: &Path) -> Result<String, String> {
    let mut components = Vec::new();
    for component in path.components() {
        let Component::Normal(component) = component else {
            return Err("release oracle retained path is not confined and canonical".into());
        };
        let component = component
            .to_str()
            .ok_or_else(|| "release oracle path component is not UTF-8".to_owned())?;
        if component.is_empty()
            || component.bytes().any(|byte| {
                byte.is_ascii_control() || byte == b'"' || byte == b'/' || byte == b'\\'
            })
        {
            return Err("release oracle retained path is not confined and canonical".into());
        }
        components.push(component);
    }
    if components.is_empty() {
        return Err("release oracle retained path is not confined and canonical".into());
    }
    Ok(components.join("/"))
}

fn retained_file_name(path: &Path) -> Result<String, String> {
    let name = path
        .file_name()
        .ok_or_else(|| "release oracle retained path has no filename".to_owned())?;
    path_text(Path::new(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_selector_rejects_wrong_asset_digest_and_duplicate_assets() {
        let tree = "a".repeat(UPSTREAM_COMMIT.len());
        let valid = format!(
            "{{\"id\":17,\"tag_name\":\"{RELEASE_TAG}\",\"target_commitish\":\"master\",\"html_url\":\"{RELEASE_URL}\",\"published_at\":\"2026-05-29T01:02:03Z\",\"assets\":[{{\"id\":23,\"name\":\"{ASSET_NAME}\",\"url\":\"https://api.github.com/repos/{REPOSITORY}/releases/assets/23\",\"browser_download_url\":\"{ASSET_DOWNLOAD_URL}\",\"size\":123,\"digest\":\"sha256:{EXPECTED_SHA256}\"}}]}}"
        );
        let providers = |release: String| {
            ProviderDocuments {
            release: release.into_bytes(),
            tag_ref: format!(
                "{{\"ref\":\"refs/tags/{RELEASE_TAG}\",\"object\":{{\"type\":\"commit\",\"sha\":\"{UPSTREAM_COMMIT}\",\"url\":\"https://api.github.com/repos/{REPOSITORY}/git/commits/{UPSTREAM_COMMIT}\"}},\"url\":\"{TAG_REF_API_URL}\"}}"
            )
            .into_bytes(),
            commit: format!(
                "{{\"sha\":\"{UPSTREAM_COMMIT}\",\"html_url\":\"https://github.com/{REPOSITORY}/commit/{UPSTREAM_COMMIT}\",\"commit\":{{\"tree\":{{\"sha\":\"{tree}\",\"url\":\"https://api.github.com/repos/{REPOSITORY}/git/trees/{tree}\"}}}}}}"
            )
            .into_bytes(),
        }
        };
        let facts = release_facts(&providers(valid.clone())).expect("valid release facts");
        assert_eq!(facts.release_id, 17);
        assert_eq!(facts.asset_id, 23);

        let wrong = valid.replace(EXPECTED_SHA256, &"0".repeat(EXPECTED_SHA256.len()));
        assert!(release_facts(&providers(wrong)).is_err());
        let duplicate = valid.replace("]}", ",{\"id\":24,\"name\":\"hell-linux-amd64\",\"url\":\"x\",\"browser_download_url\":\"x\",\"size\":1,\"digest\":\"x\"}]}");
        assert!(release_facts(&providers(duplicate)).is_err());
    }

    #[test]
    fn release_oracle_cli_rejects_repeated_and_unknown_options() {
        let args = [
            "release-oracle",
            "verify",
            "--artifact",
            "target/oracle/hell",
            "--artifact",
            "target/oracle/other",
            "--provider-response",
            "ci-out/provider.json",
            "--receipt",
            "ci-out/receipt.json",
        ]
        .map(OsString::from);
        assert!(parse(&args).is_err());
    }

    #[test]
    fn download_headers_bind_redirect_chain_and_final_response_facts() {
        let headers = b"HTTP/2 302\r\nlocation: https://release-assets.githubusercontent.com/object\r\n\r\nHTTP/2 200\r\netag: \"asset-etag\"\r\nlast-modified: Fri, 29 May 2026 01:02:03 GMT\r\ncontent-length: 123\r\n\r\n";
        let facts = parse_download_headers(headers).expect("strict download headers");
        assert_eq!(facts.http_status, 200);
        assert_eq!(
            facts.redirect_hosts,
            ["github.com", "release-assets.githubusercontent.com"]
        );
        assert_eq!(facts.etag, "\"asset-etag\"");
        assert_eq!(facts.last_modified, "Fri, 29 May 2026 01:02:03 GMT");
        assert_eq!(facts.content_length, 123);

        let duplicate = b"HTTP/2 302\r\nlocation: https://release-assets.githubusercontent.com/object\r\n\r\nHTTP/2 200\r\netag: one\r\netag: two\r\nlast-modified: Fri, 29 May 2026 01:02:03 GMT\r\ncontent-length: 123\r\n\r\n";
        assert!(parse_download_headers(duplicate).is_err());
        let untrusted = b"HTTP/2 302\r\nlocation: https://example.invalid/object\r\n\r\nHTTP/2 200\r\netag: one\r\nlast-modified: Fri, 29 May 2026 01:02:03 GMT\r\ncontent-length: 123\r\n\r\n";
        assert!(parse_download_headers(untrusted).is_err());
    }

    #[test]
    fn tls_endpoint_is_one_round_tripped_native_argument() {
        assert_eq!(
            TlsServerEndpoint::new("bucket.s3.ap-northeast-1.amazonaws.com")
                .unwrap()
                .as_str(),
            "bucket.s3.ap-northeast-1.amazonaws.com:443"
        );
        for invalid in ["", "Host.example", "host.example:8443", "host/example"] {
            assert!(TlsServerEndpoint::new(invalid).is_err());
        }
    }
}
