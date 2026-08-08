mod command;
mod fixtures;
mod policy;
mod report;
mod suite;

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use report::Report;
use suite::FailureKind;

enum Invocation {
    Policy { report: PathBuf },
    Verify { report: PathBuf },
    Portability { report: PathBuf },
    Nightly { report: PathBuf },
    Examples { profile: String, report: PathBuf },
}

fn usage() -> &'static str {
    "usage: hell-ci policy --report PATH\n       hell-ci verify --report PATH\n       hell-ci portability --report PATH\n       hell-ci nightly --report PATH\n       hell-ci examples --profile ci|release --report PATH"
}

fn parse(arguments: impl IntoIterator<Item = OsString>) -> Result<Invocation, String> {
    let mut arguments = arguments.into_iter();
    let command = arguments
        .next()
        .ok_or_else(|| usage().to_owned())?
        .into_string()
        .map_err(|_| "subcommand must be UTF-8".to_owned())?;
    let mut report = None;
    let mut profile = None;
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
            _ => return Err(format!("unknown option {flag}\n{}", usage())),
        }
    }
    let report = report.ok_or_else(|| "--report is required".to_owned())?;
    match command.as_str() {
        "policy" if profile.is_none() => Ok(Invocation::Policy { report }),
        "verify" if profile.is_none() => Ok(Invocation::Verify { report }),
        "portability" if profile.is_none() => Ok(Invocation::Portability { report }),
        "nightly" if profile.is_none() => Ok(Invocation::Nightly { report }),
        "examples" => Ok(Invocation::Examples {
            profile: match profile.as_deref() {
                Some("ci" | "release") => profile.expect("profile was matched"),
                Some(value) => return Err(format!("invalid profile {value}\n{}", usage())),
                None => return Err("examples requires --profile".to_owned()),
            },
            report,
        }),
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
        Invocation::Nightly { report } => ("nightly", report),
        Invocation::Examples { report, .. } => ("examples", report),
    };
    let mut report = Report::new(suite_name);
    let failures = suite::failures_directory(report_path);
    let result = match invocation {
        Invocation::Policy { .. } => suite::policy_suite(root, &mut report),
        Invocation::Verify { .. } => suite::verify(root, &mut report, &failures),
        Invocation::Portability { .. } => suite::portability(root, &mut report, &failures),
        Invocation::Nightly { .. } => suite::nightly(root, &mut report, &failures),
        Invocation::Examples { profile, .. } => {
            suite::examples(root, &mut report, &failures, profile)
        }
    };
    if let Err(error) = report.write(report_path) {
        eprintln!("cannot write report {}: {error}", report_path.display());
        return ExitCode::from(40);
    }
    println!(
        "{}: {}; report: {}",
        suite_name,
        if report.passed() { "passed" } else { "failed" },
        report_path.display()
    );
    match result {
        Ok(()) if report.passed() => ExitCode::SUCCESS,
        Ok(()) | Err(FailureKind::Fixture) => ExitCode::from(30),
        Err(FailureKind::Policy) => ExitCode::from(10),
        Err(FailureKind::Child) => ExitCode::from(20),
        Err(FailureKind::Io) => ExitCode::from(40),
    }
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
}
