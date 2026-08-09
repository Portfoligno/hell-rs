mod command;
mod fixtures;
mod policy;
mod report;
mod suite;

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use hell_testkit::Digest;
use report::Report;
use suite::FailureKind;

enum Invocation {
    Policy {
        report: PathBuf,
    },
    Verify {
        report: PathBuf,
    },
    Portability {
        report: PathBuf,
    },
    Nightly {
        report: PathBuf,
        oracle: PathBuf,
        oracle_sha256: Digest,
    },
    NativeOracleShard {
        report: PathBuf,
        source: PathBuf,
        platform: String,
    },
    MergeNativeShards {
        report: PathBuf,
        input: PathBuf,
    },
    PromotionGate {
        report: PathBuf,
        input: PathBuf,
    },
    Examples {
        profile: String,
        report: PathBuf,
    },
}

fn usage() -> &'static str {
    "usage: hell-ci policy --report PATH\n       hell-ci verify --report PATH\n       hell-ci portability --report PATH\n       hell-ci nightly --oracle PATH --oracle-sha256 HEX --report PATH\n       hell-ci native-oracle-shard --source PATH --platform ID --report PATH\n       hell-ci merge-native-shards --input PATH --report PATH\n       hell-ci promotion-gate --input PATH --report PATH\n       hell-ci examples --profile ci|release --report PATH"
}

#[allow(clippy::too_many_lines)]
fn parse(arguments: impl IntoIterator<Item = OsString>) -> Result<Invocation, String> {
    let mut arguments = arguments.into_iter();
    let command = arguments
        .next()
        .ok_or_else(|| usage().to_owned())?
        .into_string()
        .map_err(|_| "subcommand must be UTF-8".to_owned())?;
    let mut report = None;
    let mut profile = None;
    let mut oracle = None;
    let mut oracle_sha256 = None;
    let mut source = None;
    let mut platform = None;
    let mut input = None;
    while let Some(flag) = arguments.next() {
        let flag = flag
            .into_string()
            .map_err(|_| "option name must be UTF-8".to_owned())?;
        match flag.as_str() {
            "--report" => {
                if report.is_some() {
                    return Err("--report was provided more than once".to_owned());
                }
                report = Some(PathBuf::from(
                    arguments
                        .next()
                        .ok_or_else(|| "--report requires PATH".to_owned())?,
                ));
            }
            "--profile" => {
                if profile.is_some() {
                    return Err("--profile was provided more than once".to_owned());
                }
                profile = Some(
                    arguments
                        .next()
                        .ok_or_else(|| "--profile requires ci or release".to_owned())?
                        .into_string()
                        .map_err(|_| "profile must be UTF-8".to_owned())?,
                );
            }
            "--oracle" => {
                if oracle.is_some() {
                    return Err("--oracle was provided more than once".to_owned());
                }
                oracle = Some(PathBuf::from(
                    arguments
                        .next()
                        .ok_or_else(|| "--oracle requires PATH".to_owned())?,
                ));
            }
            "--oracle-sha256" => {
                if oracle_sha256.is_some() {
                    return Err("--oracle-sha256 was provided more than once".to_owned());
                }
                let digest = arguments
                    .next()
                    .ok_or_else(|| "--oracle-sha256 requires HEX".to_owned())?
                    .into_string()
                    .map_err(|_| "--oracle-sha256 must be UTF-8".to_owned())?;
                oracle_sha256 = Some(Digest::from_hex(&digest).map_err(str::to_owned)?);
            }
            "--source" => {
                if source.is_some() {
                    return Err("--source was provided more than once".to_owned());
                }
                source = Some(PathBuf::from(
                    arguments
                        .next()
                        .ok_or_else(|| "--source requires PATH".to_owned())?,
                ));
            }
            "--platform" => {
                if platform.is_some() {
                    return Err("--platform was provided more than once".to_owned());
                }
                platform = Some(
                    arguments
                        .next()
                        .ok_or_else(|| "--platform requires ID".to_owned())?
                        .into_string()
                        .map_err(|_| "--platform must be UTF-8".to_owned())?,
                );
            }
            "--input" => {
                if input.is_some() {
                    return Err("--input was provided more than once".to_owned());
                }
                input = Some(PathBuf::from(
                    arguments
                        .next()
                        .ok_or_else(|| "--input requires PATH".to_owned())?,
                ));
            }
            _ => return Err(format!("unknown option {flag}\n{}", usage())),
        }
    }
    let report = report.ok_or_else(|| "--report is required".to_owned())?;
    match command.as_str() {
        "policy"
            if profile.is_none()
                && oracle.is_none()
                && oracle_sha256.is_none()
                && source.is_none()
                && platform.is_none()
                && input.is_none() =>
        {
            Ok(Invocation::Policy { report })
        }
        "verify"
            if profile.is_none()
                && oracle.is_none()
                && oracle_sha256.is_none()
                && source.is_none()
                && platform.is_none()
                && input.is_none() =>
        {
            Ok(Invocation::Verify { report })
        }
        "portability"
            if profile.is_none()
                && oracle.is_none()
                && oracle_sha256.is_none()
                && source.is_none()
                && platform.is_none()
                && input.is_none() =>
        {
            Ok(Invocation::Portability { report })
        }
        "nightly"
            if profile.is_none() && source.is_none() && platform.is_none() && input.is_none() =>
        {
            Ok(Invocation::Nightly {
                report,
                oracle: oracle.ok_or_else(|| "nightly requires --oracle PATH".to_owned())?,
                oracle_sha256: oracle_sha256
                    .ok_or_else(|| "nightly requires --oracle-sha256 HEX".to_owned())?,
            })
        }
        "native-oracle-shard"
            if profile.is_none()
                && oracle.is_none()
                && oracle_sha256.is_none()
                && input.is_none() =>
        {
            Ok(Invocation::NativeOracleShard {
                report,
                source: source.ok_or_else(|| "native-oracle-shard requires --source".to_owned())?,
                platform: platform
                    .ok_or_else(|| "native-oracle-shard requires --platform".to_owned())?,
            })
        }
        "merge-native-shards"
            if profile.is_none()
                && oracle.is_none()
                && oracle_sha256.is_none()
                && source.is_none()
                && platform.is_none() =>
        {
            Ok(Invocation::MergeNativeShards {
                report,
                input: input.ok_or_else(|| "merge-native-shards requires --input".to_owned())?,
            })
        }
        "promotion-gate"
            if profile.is_none()
                && oracle.is_none()
                && oracle_sha256.is_none()
                && source.is_none()
                && platform.is_none() =>
        {
            Ok(Invocation::PromotionGate {
                report,
                input: input.ok_or_else(|| "promotion-gate requires --input".to_owned())?,
            })
        }
        "examples"
            if oracle.is_none()
                && oracle_sha256.is_none()
                && source.is_none()
                && platform.is_none()
                && input.is_none() =>
        {
            Ok(Invocation::Examples {
                profile: match profile.as_deref() {
                    Some("ci" | "release") => profile.expect("profile was matched"),
                    Some(value) => return Err(format!("invalid profile {value}\n{}", usage())),
                    None => return Err("examples requires --profile".to_owned()),
                },
                report,
            })
        }
        _ => Err(format!("invalid subcommand options\n{}", usage())),
    }
}

fn main() -> ExitCode {
    let invocation = match parse(std::env::args_os().skip(1)) {
        Ok(invocation) => invocation,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(2);
        }
    };
    let root = match std::env::current_dir() {
        Ok(root) => root,
        Err(error) => {
            eprintln!("cannot determine repository root: {error}");
            return ExitCode::from(40);
        }
    };
    run(&invocation, &root)
}

fn run(invocation: &Invocation, root: &Path) -> ExitCode {
    let (suite_name, report_path) = match invocation {
        Invocation::Policy { report } => ("policy", report),
        Invocation::Verify { report } => ("verify", report),
        Invocation::Portability { report } => ("portability", report),
        Invocation::Nightly { report, .. } => ("nightly", report),
        Invocation::NativeOracleShard { report, .. } => ("native-oracle-shard", report),
        Invocation::MergeNativeShards { report, .. } => ("merge-native-shards", report),
        Invocation::PromotionGate { report, .. } => ("promotion-gate", report),
        Invocation::Examples { report, .. } => ("examples", report),
    };
    let mut report = Report::new(suite_name);
    let failures = suite::failures_directory(report_path);
    let result = match invocation {
        Invocation::Policy { .. } => suite::policy_suite(root, &mut report),
        Invocation::Verify { .. } => suite::verify(root, &mut report, &failures),
        Invocation::Portability { .. } => suite::portability(root, &mut report, &failures),
        Invocation::Nightly {
            oracle,
            oracle_sha256,
            ..
        } => suite::nightly(root, &mut report, &failures, oracle, *oracle_sha256),
        Invocation::NativeOracleShard {
            source, platform, ..
        } => suite::native_oracle_shard(root, &mut report, &failures, source, platform),
        Invocation::MergeNativeShards { input, .. } => {
            suite::merge_native_shards(root, input, &mut report)
        }
        Invocation::PromotionGate { input, .. } => suite::promotion_gate(root, input, &mut report),
        Invocation::Examples { profile, .. } => {
            suite::examples(root, &mut report, &failures, profile)
        }
    };
    let suite_passed = finalize_suite_result(result, &mut report);
    if !suite_passed {
        for line in report_failure_lines(&report) {
            eprintln!("{line}");
        }
    }
    if let Err(error) = report.write(report_path) {
        eprintln!("cannot write report {}: {error}", report_path.display());
        return ExitCode::from(40);
    }
    println!(
        "{}: {}; report: {}",
        suite_name,
        if suite_passed { "passed" } else { "failed" },
        report_path.display()
    );
    match result {
        Ok(()) if suite_passed => ExitCode::SUCCESS,
        Ok(()) | Err(FailureKind::Fixture) => ExitCode::from(30),
        Err(FailureKind::Policy) => ExitCode::from(10),
        Err(FailureKind::Child) => ExitCode::from(20),
        Err(FailureKind::Io) => ExitCode::from(40),
    }
}

fn finalize_suite_result(result: Result<(), FailureKind>, report: &mut Report) -> bool {
    if let Err(error) = result
        && report.passed()
    {
        report.check(
            "suite-result",
            std::time::Duration::ZERO,
            Err(format!("suite returned an unreported {error:?} failure")),
        );
    }
    result.is_ok() && report.passed()
}

fn report_failure_lines(report: &Report) -> impl Iterator<Item = String> + '_ {
    report
        .failures
        .iter()
        .enumerate()
        .map(|(index, failure)| format!("failure[{index}]: {failure:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_examples_options_in_either_order() {
        let first =
            parse(["examples", "--profile", "ci", "--report", "out.json"].map(OsString::from));
        let second =
            parse(["examples", "--report", "out.json", "--profile", "release"].map(OsString::from));
        assert!(matches!(first, Ok(Invocation::Examples { .. })));
        assert!(matches!(second, Ok(Invocation::Examples { .. })));
    }

    #[test]
    fn rejects_missing_report_and_unknown_flags() {
        assert!(parse([OsString::from("policy")]).is_err());
        assert!(parse(["policy", "--unknown", "value"].map(OsString::from)).is_err());
    }

    #[test]
    fn nightly_requires_an_explicit_oracle_identity() {
        assert!(parse(["nightly", "--report", "out.json"].map(OsString::from)).is_err());
        let digest = "00".repeat(32);
        assert!(matches!(
            parse(
                [
                    "nightly",
                    "--oracle",
                    "oracle",
                    "--oracle-sha256",
                    &digest,
                    "--report",
                    "out.json",
                ]
                .map(OsString::from)
            ),
            Ok(Invocation::Nightly { .. })
        ));
    }

    #[test]
    fn native_oracle_shard_requires_typed_source_and_platform() {
        assert!(
            parse(["native-oracle-shard", "--report", "out.json"].map(OsString::from)).is_err()
        );
        assert!(matches!(
            parse(
                [
                    "native-oracle-shard",
                    "--source",
                    "upstream",
                    "--platform",
                    "macos-arm64",
                    "--report",
                    "out.json",
                ]
                .map(OsString::from)
            ),
            Ok(Invocation::NativeOracleShard { .. })
        ));
    }

    #[test]
    fn promotion_gate_requires_retained_native_shards() {
        assert!(parse(["promotion-gate", "--report", "out.json"].map(OsString::from)).is_err());
        assert!(matches!(
            parse(
                [
                    "promotion-gate",
                    "--input",
                    "native-shards",
                    "--report",
                    "out.json",
                ]
                .map(OsString::from)
            ),
            Ok(Invocation::PromotionGate { .. })
        ));
    }

    #[test]
    fn nightly_workflow_matches_the_reviewed_oracle_record() {
        const DIGEST: &str = "5ccc78e62200eb5aea8b9da9161334c61848d0d3e7de2f270929920cfbf357c9";
        const URL: &str =
            "https://github.com/chrisdone/hell/releases/download/2026-05-29/hell-linux-amd64";
        let record = include_str!("../oracle/linux-amd64.toml");
        let workflow = include_str!("../../../.github/workflows/nightly.yml");
        assert!(record.contains(DIGEST));
        assert!(record.contains(URL));
        assert!(workflow.contains(DIGEST));
        assert!(workflow.contains(URL));
    }

    #[test]
    fn unreported_suite_error_forces_failed_console_and_json_status() {
        let mut report = Report::new("synthetic");
        assert!(!finalize_suite_result(Err(FailureKind::Io), &mut report));
        assert!(!report.passed());
        assert!(
            report
                .failures
                .iter()
                .any(|failure| failure.contains("suite-result") && failure.contains("Io"))
        );
        assert_eq!(
            report_failure_lines(&report).collect::<Vec<_>>(),
            ["failure[0]: \"suite-result: suite returned an unreported Io failure\""]
        );
    }

    #[test]
    fn stderr_failure_lines_are_ordered_escaped_and_not_duplicated() {
        let mut report = Report::new("synthetic");
        report.check(
            "merge-linux-amd64",
            std::time::Duration::ZERO,
            Err("cannot read C:\\native\\summary.json\naccess denied".to_owned()),
        );
        report.check(
            "merge-windows-amd64",
            std::time::Duration::ZERO,
            Err("missing binarySha256".to_owned()),
        );
        assert!(!finalize_suite_result(Ok(()), &mut report));
        assert_eq!(
            report_failure_lines(&report).collect::<Vec<_>>(),
            [
                "failure[0]: \"merge-linux-amd64: cannot read C:\\\\native\\\\summary.json\\naccess denied\"",
                "failure[1]: \"merge-windows-amd64: missing binarySha256\"",
            ]
        );
    }
}
