#![allow(clippy::pedantic, clippy::nursery)]

mod command;
mod compatibility;
mod conformance;
mod fixtures;
mod fuzz_surfaces;
mod identity;
mod json;
mod mutation;
mod oracle_acquire;
mod policy;
mod readiness;
mod regression;
mod release;
mod release_suite;
mod report;
mod strict_toml;

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use hell_testkit::Digest;
use release_suite::FailureKind;
use report::Report;

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
        dependency_attestation: PathBuf,
    },
    NativeOracleShard {
        report: PathBuf,
        source: PathBuf,
        platform: String,
        dependency_attestation: PathBuf,
    },
    DependencyAttestation {
        report: PathBuf,
        output: PathBuf,
    },
    Examples {
        profile: String,
        report: PathBuf,
    },
}

fn usage() -> &'static str {
    "usage: hell-ci policy --report PATH\n       hell-ci verify --report PATH\n       hell-ci portability --report PATH\n       hell-ci dependency-attestation --output PATH --report PATH\n       hell-ci nightly --oracle PATH --oracle-sha256 HEX --dependency-attestation PATH --report PATH\n       hell-ci native-oracle-shard --source PATH --platform ID --dependency-attestation PATH --report PATH\n       hell-ci examples --profile ci|release --report PATH\n       hell-ci conformance audit --candidate-root PATH --output PATH\n       hell-ci readiness plan|platform|verify [options]\n       hell-ci release resolve|plan|platform|assemble|verify-bundle|stage-attestations|publish [options]"
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
    let mut format = None;
    let mut oracle = None;
    let mut oracle_sha256 = None;
    let mut source = None;
    let mut platform = None;
    let mut input = None;
    let mut output = None;
    let mut dependency_attestation = None;
    let mut proposal = None;
    let mut expect_source = None;
    let mut expect_epoch = None;
    let mut expect_proposal = None;
    let mut github_dispatch_inputs = false;
    let mut explain = false;
    let mut only = None;
    let mut group_by = None;
    while let Some(flag) = arguments.next() {
        let flag = flag
            .into_string()
            .map_err(|_| "option name must be UTF-8".to_owned())?;
        match flag.as_str() {
            "--github-dispatch-inputs" => {
                if github_dispatch_inputs {
                    return Err("--github-dispatch-inputs was provided more than once".to_owned());
                }
                github_dispatch_inputs = true;
            }
            "--explain" => {
                if explain {
                    return Err("--explain was provided more than once".to_owned());
                }
                explain = true;
            }
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
            "--format" => {
                if format.is_some() {
                    return Err("--format was provided more than once".to_owned());
                }
                format = Some(
                    arguments
                        .next()
                        .ok_or_else(|| "--format requires csv, json, or html".to_owned())?
                        .into_string()
                        .map_err(|_| "format must be UTF-8".to_owned())?,
                );
            }
            "--only" => {
                if only.is_some() {
                    return Err("--only was provided more than once".to_owned());
                }
                only = Some(
                    arguments
                        .next()
                        .ok_or_else(|| "--only requires ambiguous".to_owned())?
                        .into_string()
                        .map_err(|_| "--only must be UTF-8".to_owned())?,
                );
            }
            "--group-by" => {
                if group_by.is_some() {
                    return Err("--group-by was provided more than once".to_owned());
                }
                group_by = Some(
                    arguments
                        .next()
                        .ok_or_else(|| "--group-by requires assurance-equivalence".to_owned())?
                        .into_string()
                        .map_err(|_| "--group-by must be UTF-8".to_owned())?,
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
            "--output" => {
                if output.is_some() {
                    return Err("--output was provided more than once".to_owned());
                }
                output = Some(PathBuf::from(
                    arguments
                        .next()
                        .ok_or_else(|| "--output requires PATH".to_owned())?,
                ));
            }
            "--dependency-attestation" => {
                if dependency_attestation.is_some() {
                    return Err("--dependency-attestation was provided more than once".to_owned());
                }
                dependency_attestation =
                    Some(PathBuf::from(arguments.next().ok_or_else(|| {
                        "--dependency-attestation requires PATH".to_owned()
                    })?));
            }
            "--proposal" => {
                if proposal.is_some() {
                    return Err("--proposal was provided more than once".to_owned());
                }
                proposal = Some(PathBuf::from(
                    arguments
                        .next()
                        .ok_or_else(|| "--proposal requires PATH".to_owned())?,
                ));
            }
            "--expect-source" => {
                if expect_source.is_some() {
                    return Err("--expect-source was provided more than once".to_owned());
                }
                expect_source = Some(
                    arguments
                        .next()
                        .ok_or_else(|| "--expect-source requires SHA".to_owned())?
                        .into_string()
                        .map_err(|_| "--expect-source must be UTF-8".to_owned())?,
                );
            }
            "--expect-epoch" => {
                if expect_epoch.is_some() {
                    return Err("--expect-epoch was provided more than once".to_owned());
                }
                expect_epoch = Some(
                    arguments
                        .next()
                        .ok_or_else(|| "--expect-epoch requires SHA-256".to_owned())?
                        .into_string()
                        .map_err(|_| "--expect-epoch must be UTF-8".to_owned())?,
                );
            }
            "--expect-proposal" => {
                if expect_proposal.is_some() {
                    return Err("--expect-proposal was provided more than once".to_owned());
                }
                expect_proposal = Some(
                    arguments
                        .next()
                        .ok_or_else(|| "--expect-proposal requires SHA-256".to_owned())?
                        .into_string()
                        .map_err(|_| "--expect-proposal must be UTF-8".to_owned())?,
                );
            }
            _ => return Err(format!("unknown option {flag}\n{}", usage())),
        }
    }
    if github_dispatch_inputs || only.is_some() || group_by.is_some() {
        return Err("retired promotion options are not supported".to_owned());
    }
    let report = report.ok_or_else(|| "--report is required".to_owned())?;
    match command.as_str() {
        "policy"
            if profile.is_none()
                && format.is_none()
                && oracle.is_none()
                && oracle_sha256.is_none()
                && source.is_none()
                && platform.is_none()
                && input.is_none()
                && output.is_none()
                && dependency_attestation.is_none()
                && proposal.is_none()
                && expect_source.is_none()
                && expect_epoch.is_none()
                && expect_proposal.is_none()
                && !explain =>
        {
            Ok(Invocation::Policy { report })
        }
        "verify"
            if profile.is_none()
                && format.is_none()
                && oracle.is_none()
                && oracle_sha256.is_none()
                && source.is_none()
                && platform.is_none()
                && input.is_none()
                && output.is_none()
                && dependency_attestation.is_none()
                && proposal.is_none()
                && expect_source.is_none()
                && expect_epoch.is_none()
                && expect_proposal.is_none()
                && !explain =>
        {
            Ok(Invocation::Verify { report })
        }
        "portability"
            if profile.is_none()
                && format.is_none()
                && oracle.is_none()
                && oracle_sha256.is_none()
                && source.is_none()
                && platform.is_none()
                && input.is_none()
                && output.is_none()
                && dependency_attestation.is_none()
                && proposal.is_none()
                && expect_source.is_none()
                && expect_epoch.is_none()
                && expect_proposal.is_none()
                && !explain =>
        {
            Ok(Invocation::Portability { report })
        }
        "dependency-attestation"
            if profile.is_none()
                && format.is_none()
                && oracle.is_none()
                && oracle_sha256.is_none()
                && source.is_none()
                && platform.is_none()
                && input.is_none()
                && dependency_attestation.is_none()
                && proposal.is_none()
                && expect_source.is_none()
                && expect_epoch.is_none()
                && expect_proposal.is_none()
                && !explain =>
        {
            Ok(Invocation::DependencyAttestation {
                report,
                output: output
                    .ok_or_else(|| "dependency-attestation requires --output PATH".to_owned())?,
            })
        }
        "nightly"
            if profile.is_none()
                && format.is_none()
                && source.is_none()
                && platform.is_none()
                && input.is_none()
                && output.is_none()
                && proposal.is_none()
                && expect_source.is_none()
                && expect_epoch.is_none()
                && expect_proposal.is_none()
                && !explain =>
        {
            Ok(Invocation::Nightly {
                report,
                oracle: oracle.ok_or_else(|| "nightly requires --oracle PATH".to_owned())?,
                oracle_sha256: oracle_sha256
                    .ok_or_else(|| "nightly requires --oracle-sha256 HEX".to_owned())?,
                dependency_attestation: dependency_attestation
                    .ok_or_else(|| "nightly requires --dependency-attestation PATH".to_owned())?,
            })
        }
        "native-oracle-shard"
            if profile.is_none()
                && format.is_none()
                && oracle.is_none()
                && oracle_sha256.is_none()
                && input.is_none()
                && output.is_none()
                && proposal.is_none()
                && expect_source.is_none()
                && expect_epoch.is_none()
                && expect_proposal.is_none()
                && !explain =>
        {
            Ok(Invocation::NativeOracleShard {
                report,
                source: source.ok_or_else(|| "native-oracle-shard requires --source".to_owned())?,
                platform: platform
                    .ok_or_else(|| "native-oracle-shard requires --platform".to_owned())?,
                dependency_attestation: dependency_attestation.ok_or_else(|| {
                    "native-oracle-shard requires --dependency-attestation PATH".to_owned()
                })?,
            })
        }
        "examples"
            if format.is_none()
                && oracle.is_none()
                && oracle_sha256.is_none()
                && source.is_none()
                && platform.is_none()
                && input.is_none()
                && output.is_none()
                && dependency_attestation.is_none()
                && proposal.is_none()
                && expect_source.is_none()
                && expect_epoch.is_none()
                && expect_proposal.is_none()
                && !explain =>
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
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    #[cfg(unix)]
    if arguments.first().and_then(|value| value.to_str()) == Some("__release-posix-child") {
        return command::run_posix_release_child(&arguments[1..]);
    }
    #[cfg(windows)]
    if arguments.first().and_then(|value| value.to_str()) == Some("__release-restricted-child") {
        return command::run_windows_restricted_child(&arguments[1..]);
    }
    let root = match std::env::current_dir() {
        Ok(root) => root,
        Err(error) => {
            eprintln!("cannot determine repository root: {error}");
            return ExitCode::from(40);
        }
    };
    if compatibility::recognizes(&arguments) {
        return compatibility::run_cli(&root, &arguments);
    }
    if regression::recognizes(&arguments) {
        return regression::run_cli(&arguments);
    }
    if mutation::recognizes(&arguments) {
        return mutation::run_cli(&root, &arguments);
    }
    if conformance::recognizes(&arguments) {
        return match conformance::run_cli(&arguments) {
            Ok(message) => {
                println!("{message}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    if readiness::recognizes(&arguments) {
        return match readiness::run(&arguments) {
            Ok(message) => {
                println!("{message}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    if release::recognizes(&arguments) {
        return match release::run(&arguments) {
            Ok(message) => {
                println!("{message}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    if oracle_acquire::recognizes(&arguments) {
        return match oracle_acquire::run(&arguments) {
            Ok(message) => {
                println!("{message}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    let invocation = match parse(arguments) {
        Ok(invocation) => invocation,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(2);
        }
    };
    run(&invocation, &root)
}

#[allow(clippy::too_many_lines)]
fn run(invocation: &Invocation, root: &Path) -> ExitCode {
    let (suite_name, report_path) = match invocation {
        Invocation::Policy { report } => ("policy", report),
        Invocation::Verify { report } => ("verify", report),
        Invocation::Portability { report } => ("portability", report),
        Invocation::Nightly { report, .. } => ("nightly", report),
        Invocation::NativeOracleShard { report, .. } => ("native-oracle-shard", report),
        Invocation::DependencyAttestation { report, .. } => ("dependency-attestation", report),
        Invocation::Examples { report, .. } => ("examples", report),
    };
    let mut report = Report::new(suite_name);
    let failures = release_suite::failures_directory(report_path);
    let result = match invocation {
        Invocation::Policy { .. } => release_suite::policy_suite(root, &mut report),
        Invocation::Verify { .. } => release_suite::verify(root, &mut report, &failures),
        Invocation::Portability { .. } => release_suite::portability(root, &mut report, &failures),
        Invocation::Nightly {
            oracle,
            oracle_sha256,
            dependency_attestation,
            ..
        } => release_suite::nightly(
            root,
            &mut report,
            &failures,
            oracle,
            *oracle_sha256,
            dependency_attestation,
        ),
        Invocation::NativeOracleShard {
            source,
            platform,
            dependency_attestation,
            ..
        } => release_suite::native_oracle_shard(
            root,
            &mut report,
            &failures,
            source,
            platform,
            dependency_attestation,
        ),
        Invocation::DependencyAttestation { output, .. } => {
            release_suite::dependency_attestation(root, output, &mut report)
        }
        Invocation::Examples { profile, .. } => {
            release_suite::examples(root, &mut report, &failures, profile)
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
                    "--dependency-attestation",
                    "dependency-policy.json",
                    "--report",
                    "out.json",
                ]
                .map(OsString::from)
            ),
            Ok(Invocation::Nightly { .. })
        ));
        assert!(
            parse(["nightly-exploratory", "--report", "out.json"].map(OsString::from)).is_err()
        );
        assert!(
            parse(["nightly-surveillance-subject", "--report", "out.json"].map(OsString::from))
                .is_err()
        );
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
                    "--dependency-attestation",
                    "dependency-policy.json",
                    "--report",
                    "out.json",
                ]
                .map(OsString::from)
            ),
            Ok(Invocation::NativeOracleShard { .. })
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
        assert!(workflow.contains(
            "run: ./target/ci/hell-ci oracle-acquire acquire --artifact ci-out/linux-release-oracle --provider-response ci-out/linux-release-provider.json --receipt ci-out/linux-release-oracle-receipt.json"
        ));
        assert!(!workflow.contains("hell-ci release-oracle "));
    }

    #[test]
    fn unreported_suite_error_forces_failed_console_and_json_status() {
        let mut report = Report::new("synthetic");
        assert!(!finalize_suite_result(
            Err(FailureKind::Fixture),
            &mut report
        ));
        assert!(!report.passed());
        assert!(
            report
                .failures
                .iter()
                .any(|failure| failure.contains("suite-result") && failure.contains("Fixture"))
        );
        assert_eq!(
            report_failure_lines(&report).collect::<Vec<_>>(),
            ["failure[0]: \"suite-result: suite returned an unreported Fixture failure\""]
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
