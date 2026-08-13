use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::Read as _;
use std::path::PathBuf;

use crate::json::{JsonValue, canonical_json_bytes, json_member, parse_json};
use crate::release::manifest::write_atomic;

const RELEASE_URL: &str = "https://api.github.com/repos/chrisdone/hell/releases/tags/2026-05-29";
const ASSET_URL: &str =
    "https://github.com/chrisdone/hell/releases/download/2026-05-29/hell-linux-amd64";
const ASSET_NAME: &str = "hell-linux-amd64";
const EXPECTED_SHA256: &str = "5ccc78e62200eb5aea8b9da9161334c61848d0d3e7de2f270929920cfbf357c9";
const RELEASE_TAG: &str = "2026-05-29";
const MAX_METADATA_BYTES: u64 = 4 * 1024 * 1024;
const MAX_ASSET_BYTES: u64 = 128 * 1024 * 1024;

struct Options {
    artifact: PathBuf,
    provider_response: PathBuf,
    receipt: PathBuf,
}

pub(crate) fn recognizes(arguments: &[OsString]) -> bool {
    arguments.first().and_then(|value| value.to_str()) == Some("oracle-acquire")
}

pub(crate) fn run(arguments: &[OsString]) -> Result<String, String> {
    let options = parse(arguments)?;
    acquire(&options)
}

fn parse(arguments: &[OsString]) -> Result<Options, String> {
    if arguments.get(1).and_then(|value| value.to_str()) != Some("acquire") || arguments.len() != 8
    {
        return Err("oracle-acquire requires exact acquire and three path options".to_owned());
    }
    Ok(Options {
        artifact: option(arguments, "--artifact")?,
        provider_response: option(arguments, "--provider-response")?,
        receipt: option(arguments, "--receipt")?,
    })
}

fn option(arguments: &[OsString], name: &str) -> Result<PathBuf, String> {
    let mut found = None;
    for pair in arguments[2..].chunks_exact(2) {
        let observed = pair[0]
            .to_str()
            .ok_or_else(|| "oracle option name must be UTF-8".to_owned())?;
        if !matches!(observed, "--artifact" | "--provider-response" | "--receipt") {
            return Err(format!("unknown oracle acquisition option {observed}"));
        }
        if observed == name && found.replace(PathBuf::from(&pair[1])).is_some() {
            return Err(format!("{name} was provided more than once"));
        }
    }
    found.ok_or_else(|| format!("{name} is required"))
}

fn acquire(options: &Options) -> Result<String, String> {
    distinct_outputs(options)?;
    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(90)))
        .https_only(true)
        .build()
        .new_agent();
    let metadata = bounded_response(
        agent
            .get(RELEASE_URL)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2026-03-10")
            .header("User-Agent", "hell-ci-oracle-acquire")
            .call()
            .map_err(|error| format!("cannot query pinned oracle release: {error}"))?,
        MAX_METADATA_BYTES,
    )?;
    let release = parse_release(&metadata)?;
    let asset = bounded_response(
        agent
            .get(ASSET_URL)
            .header("Accept-Encoding", "identity")
            .header("User-Agent", "hell-ci-oracle-acquire")
            .call()
            .map_err(|error| format!("cannot download pinned oracle: {error}"))?,
        MAX_ASSET_BYTES,
    )?;
    let digest = hell_testkit::sha256_bytes(&asset).hex();
    if digest != EXPECTED_SHA256 {
        return Err("pinned oracle asset digest differs".to_owned());
    }
    write_atomic(&options.artifact, &asset)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mut permissions = fs::metadata(&options.artifact)
            .map_err(|error| format!("cannot inspect oracle artifact: {error}"))?
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&options.artifact, permissions)
            .map_err(|error| format!("cannot set oracle permissions: {error}"))?;
    }
    let provider = JsonValue::Object(BTreeMap::from([
        ("assetId".to_owned(), JsonValue::Number(release.1)),
        (
            "assetName".to_owned(),
            JsonValue::String(ASSET_NAME.to_owned()),
        ),
        ("assetSha256".to_owned(), JsonValue::String(digest.clone())),
        ("releaseId".to_owned(), JsonValue::Number(release.0)),
        (
            "releaseTag".to_owned(),
            JsonValue::String(RELEASE_TAG.to_owned()),
        ),
        ("schemaVersion".to_owned(), JsonValue::Number(1)),
        (
            "sourceUrl".to_owned(),
            JsonValue::String(RELEASE_URL.to_owned()),
        ),
    ]));
    let provider_bytes = canonical_json_bytes(&provider)?;
    write_atomic(&options.provider_response, &provider_bytes)?;
    let receipt = JsonValue::Object(BTreeMap::from([
        ("artifactSha256".to_owned(), JsonValue::String(digest)),
        (
            "artifactSize".to_owned(),
            JsonValue::Number(asset.len().try_into().map_err(|_| "oracle size overflow")?),
        ),
        (
            "channel".to_owned(),
            JsonValue::String("github-release-https".to_owned()),
        ),
        (
            "providerResponseSha256".to_owned(),
            JsonValue::String(hell_testkit::sha256_bytes(&provider_bytes).hex()),
        ),
        ("schemaVersion".to_owned(), JsonValue::Number(1)),
    ]));
    let receipt_bytes = canonical_json_bytes(&receipt)?;
    write_atomic(&options.receipt, &receipt_bytes)?;
    let name = options
        .receipt
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| "oracle receipt name is not UTF-8".to_owned())?;
    write_atomic(
        &options.receipt.with_extension("sha256"),
        format!(
            "{}  {name}\n",
            hell_testkit::sha256_bytes(&receipt_bytes).hex()
        )
        .as_bytes(),
    )?;
    Ok("acquired and verified pinned Linux release oracle".to_owned())
}

fn bounded_response(
    mut response: ureq::http::Response<ureq::Body>,
    limit: u64,
) -> Result<Vec<u8>, String> {
    if response
        .body()
        .content_length()
        .is_some_and(|length| length > limit)
    {
        return Err("oracle response exceeds its size bound".to_owned());
    }
    let mut bytes = Vec::new();
    response
        .body_mut()
        .as_reader()
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read oracle response: {error}"))?;
    if u64::try_from(bytes.len()).map_err(|_| "oracle response size overflow")? > limit {
        return Err("oracle response exceeds its size bound".to_owned());
    }
    Ok(bytes)
}

fn parse_release(bytes: &[u8]) -> Result<(u64, u64), String> {
    let document = std::str::from_utf8(bytes)
        .map_err(|_| "oracle release metadata is not UTF-8".to_owned())?;
    let value = parse_json(document)?;
    let object = value.object()?;
    if json_member(object, "tag_name")?.string()? != RELEASE_TAG {
        return Err("oracle release tag differs".to_owned());
    }
    let mut assets = json_member(object, "assets")?
        .array()?
        .iter()
        .filter_map(|value| value.object().ok())
        .filter(|asset| json_member(asset, "name").and_then(JsonValue::string) == Ok(ASSET_NAME));
    let asset = assets
        .next()
        .ok_or_else(|| "pinned oracle asset is missing".to_owned())?;
    if assets.next().is_some()
        || json_member(asset, "browser_download_url")?.string()? != ASSET_URL
        || json_member(asset, "digest")?.string()? != format!("sha256:{EXPECTED_SHA256}")
    {
        return Err("pinned oracle asset identity differs".to_owned());
    }
    Ok((
        json_member(object, "id")?.number()?,
        json_member(asset, "id")?.number()?,
    ))
}

fn distinct_outputs(options: &Options) -> Result<(), String> {
    let paths = [
        &options.artifact,
        &options.provider_response,
        &options.receipt,
    ];
    if paths.iter().any(|path| path.exists())
        || paths[0] == paths[1]
        || paths[0] == paths[2]
        || paths[1] == paths[2]
    {
        return Err("oracle acquisition outputs must be distinct and absent".to_owned());
    }
    for path in paths {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("cannot create oracle output directory: {error}"))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn realistic_release_projection_selects_one_exact_asset() {
        let document = format!(
            "{{\"id\":1,\"tag_name\":\"{RELEASE_TAG}\",\"assets\":[{{\"id\":2,\"name\":\"{ASSET_NAME}\",\"browser_download_url\":\"{ASSET_URL}\",\"digest\":\"sha256:{EXPECTED_SHA256}\"}}],\"url\":\"metadata\"}}"
        );
        assert_eq!(parse_release(document.as_bytes()).unwrap(), (1, 2));
    }

    #[test]
    fn old_authority_actions_are_not_recognized() {
        assert!(parse(&["oracle-acquire", "attest"].map(OsString::from)).is_err());
    }
}
