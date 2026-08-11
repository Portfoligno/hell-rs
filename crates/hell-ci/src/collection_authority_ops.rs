use std::ffi::OsString;
use std::path::PathBuf;

use hell_testkit::Digest;

pub(crate) fn recognizes(arguments: &[OsString]) -> bool {
    arguments
        .first()
        .and_then(|value| value.to_str())
        .is_some_and(|command| command == "collection-authority")
}

pub(crate) fn run(arguments: &[OsString]) -> Result<String, String> {
    let CollectionOptions {
        action,
        input,
        oracle,
        oracle_sha256,
        candidate_executable,
        candidate_commit,
        source,
        platform,
        output,
        provider,
        report,
    } = parse_options(arguments)?;
    let root = std::env::current_dir()
        .map_err(|error| format!("cannot determine repository root: {error}"))?;
    match action.as_str() {
        "build-native"
            if input.is_none()
                && oracle.is_none()
                && oracle_sha256.is_none()
                && candidate_executable.is_none()
                && candidate_commit.is_none()
                && provider.is_none()
                && report.is_none() =>
        {
            let platform = platform
                .as_deref()
                .ok_or_else(|| "collection native build requires --platform".to_owned())?;
            let output = output
                .as_deref()
                .ok_or_else(|| "collection native build requires --output".to_owned())?;
            let source =
                source.ok_or_else(|| "collection native build requires --source".to_owned())?;
            let executable =
                crate::suite::collection_authority_build_native(&source, platform, output)?;
            Ok(format!(
                "built exact collection native oracle {}",
                executable.display()
            ))
        }
        "collect"
            if input.is_none() && source.is_none() && provider.is_none() && report.is_none() =>
        {
            run_collect(
                &root,
                oracle,
                oracle_sha256,
                candidate_executable,
                candidate_commit,
                platform.as_deref(),
                output.as_deref(),
            )
        }
        "subject"
            if oracle.is_none()
                && oracle_sha256.is_none()
                && candidate_executable.is_none()
                && candidate_commit.is_none()
                && source.is_none()
                && provider.is_none()
                && report.is_none() =>
        {
            let platform = platform
                .as_deref()
                .ok_or_else(|| "collection subject requires --platform".to_owned())?;
            let output = output
                .as_deref()
                .ok_or_else(|| "collection subject requires --output".to_owned())?;
            let input = input.ok_or_else(|| "collection subject requires --input".to_owned())?;
            crate::suite::collection_authority_subject(&root, &input, platform, output)?;
            Ok(format!(
                "wrote exact collection provider subject {}",
                output.display()
            ))
        }
        "verify"
            if oracle.is_none()
                && oracle_sha256.is_none()
                && candidate_executable.is_none()
                && candidate_commit.is_none()
                && source.is_none()
                && platform.is_none()
                && output.is_none() =>
        {
            let input = input.ok_or_else(|| "collection verify requires --input".to_owned())?;
            let provider =
                provider.ok_or_else(|| "collection verify requires --provider".to_owned())?;
            let report = report.ok_or_else(|| "collection verify requires --report".to_owned())?;
            crate::suite::collection_authority_verify(&root, &input, &provider, &report)?;
            Ok(format!(
                "verified exact collection campaign and wrote {}",
                report.display()
            ))
        }
        _ => Err(usage().to_owned()),
    }
}

fn run_collect(
    root: &std::path::Path,
    oracle: Option<PathBuf>,
    oracle_sha256: Option<Digest>,
    candidate_executable: Option<PathBuf>,
    candidate_commit: Option<String>,
    platform: Option<&str>,
    output: Option<&std::path::Path>,
) -> Result<String, String> {
    let platform = platform.ok_or_else(|| "collection collect requires --platform".to_owned())?;
    let output = output.ok_or_else(|| "collection collect requires --output".to_owned())?;
    let oracle = oracle.ok_or_else(|| "collection collect requires --oracle".to_owned())?;
    let oracle_sha256 =
        oracle_sha256.ok_or_else(|| "collection collect requires --oracle-sha256".to_owned())?;
    let candidate_executable = candidate_executable
        .ok_or_else(|| "collection collect requires --candidate-executable".to_owned())?;
    let candidate_commit = candidate_commit
        .ok_or_else(|| "collection collect requires --candidate-commit".to_owned())?;
    crate::suite::collection_authority_collect(
        root,
        &oracle,
        oracle_sha256,
        &candidate_executable,
        &candidate_commit,
        platform,
        output,
    )?;
    Ok(format!(
        "wrote exact dormant collection campaign {}",
        output.join("collection-evidence").display()
    ))
}

struct CollectionOptions {
    action: String,
    input: Option<PathBuf>,
    oracle: Option<PathBuf>,
    oracle_sha256: Option<Digest>,
    candidate_executable: Option<PathBuf>,
    candidate_commit: Option<String>,
    source: Option<PathBuf>,
    platform: Option<String>,
    output: Option<PathBuf>,
    provider: Option<PathBuf>,
    report: Option<PathBuf>,
}

fn parse_options(arguments: &[OsString]) -> Result<CollectionOptions, String> {
    let [command, action, rest @ ..] = arguments else {
        return Err(usage().to_owned());
    };
    if command != "collection-authority"
        || !matches!(
            action.to_str(),
            Some("build-native" | "collect" | "subject" | "verify")
        )
    {
        return Err(usage().to_owned());
    }
    let mut input = None;
    let mut oracle = None;
    let mut oracle_sha256 = None;
    let mut candidate_executable = None;
    let mut candidate_commit = None;
    let mut source = None;
    let mut platform = None;
    let mut output = None;
    let mut provider = None;
    let mut report = None;
    let mut fields = rest.iter();
    while let Some(flag) = fields.next() {
        let value = fields
            .next()
            .ok_or_else(|| format!("{} requires a value", flag.to_string_lossy()))?;
        match flag.to_str() {
            Some("--input") if input.is_none() => input = Some(PathBuf::from(value)),
            Some("--oracle") if oracle.is_none() => oracle = Some(PathBuf::from(value)),
            Some("--source") if source.is_none() => source = Some(PathBuf::from(value)),
            Some("--candidate-executable") if candidate_executable.is_none() => {
                candidate_executable = Some(PathBuf::from(value));
            }
            Some("--candidate-commit") if candidate_commit.is_none() => {
                candidate_commit = Some(
                    value
                        .to_str()
                        .ok_or_else(|| "candidate commit must be UTF-8".to_owned())?
                        .to_owned(),
                );
            }
            Some("--oracle-sha256") if oracle_sha256.is_none() => {
                oracle_sha256 = Some(
                    Digest::from_hex(
                        value
                            .to_str()
                            .ok_or_else(|| "oracle digest must be UTF-8".to_owned())?,
                    )
                    .map_err(str::to_owned)?,
                );
            }
            Some("--platform") if platform.is_none() => {
                platform = Some(
                    value
                        .to_str()
                        .ok_or_else(|| "collection platform must be UTF-8".to_owned())?
                        .to_owned(),
                );
            }
            Some("--output") if output.is_none() => output = Some(PathBuf::from(value)),
            Some("--provider") if provider.is_none() => provider = Some(PathBuf::from(value)),
            Some("--report") if report.is_none() => report = Some(PathBuf::from(value)),
            _ => return Err(usage().to_owned()),
        }
    }
    Ok(CollectionOptions {
        action: action
            .to_str()
            .expect("validated collection action is UTF-8")
            .to_owned(),
        input,
        oracle,
        oracle_sha256,
        candidate_executable,
        candidate_commit,
        source,
        platform,
        output,
        provider,
        report,
    })
}

fn usage() -> &'static str {
    "usage: hell-ci collection-authority build-native --source UPSTREAM --platform macos-arm64|windows-amd64 --output SHARD\n       hell-ci collection-authority collect --oracle PATH --oracle-sha256 HEX --candidate-executable PATH --candidate-commit 40HEX --platform PLATFORM --output SHARD\n       hell-ci collection-authority subject --input SHARD --platform PLATFORM --output SHARD/collection-evidence/provider-subject.json\n       hell-ci collection-authority verify --input SHARDS --provider PROVIDER --report REPORT"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn collection_collect_requires_explicit_candidate_subject_inputs() {
        let complete = arguments(&[
            "collection-authority",
            "collect",
            "--oracle",
            "oracle",
            "--oracle-sha256",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--candidate-executable",
            "isolated/candidate/hell",
            "--candidate-commit",
            "cccccccccccccccccccccccccccccccccccccccc",
            "--platform",
            "linux-amd64",
            "--output",
            "shard",
        ]);
        let parsed = parse_options(&complete).unwrap();
        assert_eq!(
            parsed.candidate_executable.as_deref(),
            Some(PathBuf::from("isolated/candidate/hell").as_path())
        );
        assert_eq!(
            parsed.candidate_commit.as_deref(),
            Some("cccccccccccccccccccccccccccccccccccccccc")
        );

        for omitted in ["--candidate-executable", "--candidate-commit"] {
            let mut mutation = complete.clone();
            let index = mutation.iter().position(|value| value == omitted).unwrap();
            mutation.drain(index..=index + 1);
            assert!(run(&mutation).is_err());
        }
    }
}
