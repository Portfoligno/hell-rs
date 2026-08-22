pub mod assurance;
mod capability_policy;
mod command;
mod compatibility;
mod conformance;
mod fixtures;
pub mod fuzz;
mod fuzz_surfaces;
mod github_runtime;
mod identity;
mod json;
pub mod mutation;
mod oracle_acquire;
mod policy;
pub mod process_environment;
mod protocol;
mod readiness;
mod regression;
mod release;
mod release_suite;
mod report;
mod repository;
mod strict_toml;

#[cfg(unix)]
use std::ffi::OsStr;
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
    NativeDifferentialBenchmark {
        report: PathBuf,
        oracle: PathBuf,
        candidate: PathBuf,
        sample_count: usize,
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
    "usage: hell-ci policy --report PATH\n       hell-ci verify --report PATH\n       hell-ci portability --report PATH\n       hell-ci dependency-attestation --output PATH --report PATH\n       hell-ci nightly --oracle PATH --oracle-sha256 HEX --dependency-attestation PATH --report PATH\n       hell-ci native-oracle-shard --source PATH --platform ID --dependency-attestation PATH --report PATH\n       hell-ci native-differential-benchmark --oracle PATH --candidate PATH --sample-count 32..256 --report PATH\n       hell-ci examples --profile ci|release --report PATH\n       hell-ci conformance audit --candidate-root PATH --output PATH\n       hell-ci readiness plan|platform|verify [options]\n       hell-ci release resolve|plan|platform|assemble|verify-bundle|check-remote-state|stage-attestations|publish [options]"
}

fn parse(arguments: impl IntoIterator<Item = OsString>) -> Result<Invocation, String> {
    let mut arguments = arguments.into_iter();
    let command = arguments
        .next()
        .ok_or_else(|| usage().to_owned())?
        .into_string()
        .map_err(|_| "subcommand must be UTF-8".to_owned())?;
    InvocationOptions::parse(arguments)?.into_invocation(&command)
}

#[derive(Default)]
struct InvocationOptions {
    report: Option<PathBuf>,
    profile: Option<String>,
    format: Option<String>,
    oracle: Option<PathBuf>,
    oracle_sha256: Option<Digest>,
    candidate: Option<PathBuf>,
    sample_count: Option<usize>,
    source: Option<PathBuf>,
    platform: Option<String>,
    input: Option<PathBuf>,
    output: Option<PathBuf>,
    dependency_attestation: Option<PathBuf>,
    proposal: Option<PathBuf>,
    expect_source: Option<String>,
    expect_epoch: Option<String>,
    expect_proposal: Option<String>,
    github_dispatch_inputs: bool,
    explain: bool,
    only: Option<String>,
    group_by: Option<String>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum InvocationOption {
    Profile,
    Format,
    Oracle,
    OracleSha256,
    Candidate,
    SampleCount,
    Source,
    Platform,
    Input,
    Output,
    DependencyAttestation,
    Proposal,
    ExpectSource,
    ExpectEpoch,
    ExpectProposal,
    Explain,
}

impl InvocationOptions {
    fn parse(mut arguments: impl Iterator<Item = OsString>) -> Result<Self, String> {
        let mut options = Self::default();
        while let Some(flag) = arguments.next() {
            let flag = flag
                .into_string()
                .map_err(|_| "option name must be UTF-8".to_owned())?;
            options.parse_option(&flag, &mut arguments)?;
        }
        if options.github_dispatch_inputs || options.only.is_some() || options.group_by.is_some() {
            return Err("retired promotion options are not supported".to_owned());
        }
        Ok(options)
    }

    fn parse_option(
        &mut self,
        flag: &str,
        arguments: &mut impl Iterator<Item = OsString>,
    ) -> Result<(), String> {
        match flag {
            "--github-dispatch-inputs" => set_flag(&mut self.github_dispatch_inputs, flag),
            "--explain" => set_flag(&mut self.explain, flag),
            "--report" => set_path(&mut self.report, arguments, flag, "PATH"),
            "--oracle" => set_path(&mut self.oracle, arguments, flag, "PATH"),
            "--candidate" => set_path(&mut self.candidate, arguments, flag, "PATH"),
            "--source" => set_path(&mut self.source, arguments, flag, "PATH"),
            "--input" => set_path(&mut self.input, arguments, flag, "PATH"),
            "--output" => set_path(&mut self.output, arguments, flag, "PATH"),
            "--proposal" => set_path(&mut self.proposal, arguments, flag, "PATH"),
            "--dependency-attestation" => {
                set_path(&mut self.dependency_attestation, arguments, flag, "PATH")
            }
            "--profile" => set_string(
                &mut self.profile,
                arguments,
                flag,
                "ci or release",
                "profile",
            ),
            "--format" => set_string(
                &mut self.format,
                arguments,
                flag,
                "csv, json, or html",
                "format",
            ),
            "--only" => set_string(&mut self.only, arguments, flag, "ambiguous", "--only"),
            "--group-by" => set_string(
                &mut self.group_by,
                arguments,
                flag,
                "assurance-equivalence",
                "--group-by",
            ),
            "--platform" => set_string(&mut self.platform, arguments, flag, "ID", "--platform"),
            "--expect-source" => set_string(
                &mut self.expect_source,
                arguments,
                flag,
                "SHA",
                "--expect-source",
            ),
            "--expect-epoch" => set_string(
                &mut self.expect_epoch,
                arguments,
                flag,
                "SHA-256",
                "--expect-epoch",
            ),
            "--expect-proposal" => set_string(
                &mut self.expect_proposal,
                arguments,
                flag,
                "SHA-256",
                "--expect-proposal",
            ),
            "--oracle-sha256" => self.parse_oracle_digest(arguments),
            "--sample-count" => self.parse_sample_count(arguments),
            _ => Err(format!("unknown option {flag}\n{}", usage())),
        }
    }

    fn parse_oracle_digest(
        &mut self,
        arguments: &mut impl Iterator<Item = OsString>,
    ) -> Result<(), String> {
        require_absent(self.oracle_sha256.as_ref(), "--oracle-sha256")?;
        let value = next_string(arguments, "--oracle-sha256", "HEX", "--oracle-sha256")?;
        self.oracle_sha256 = Some(Digest::from_hex(&value).map_err(str::to_owned)?);
        Ok(())
    }

    fn parse_sample_count(
        &mut self,
        arguments: &mut impl Iterator<Item = OsString>,
    ) -> Result<(), String> {
        require_absent(self.sample_count.as_ref(), "--sample-count")?;
        let value = next_string(arguments, "--sample-count", "an integer", "--sample-count")?;
        let parsed = value
            .parse::<usize>()
            .map_err(|_| "--sample-count must be a canonical positive integer".to_owned())?;
        if value != parsed.to_string() {
            return Err("--sample-count must be a canonical positive integer".to_owned());
        }
        self.sample_count = Some(parsed);
        Ok(())
    }

    fn into_invocation(mut self, command: &str) -> Result<Invocation, String> {
        let report = self
            .report
            .take()
            .ok_or_else(|| "--report is required".to_owned())?;
        match command {
            "policy" if self.only_allows(&[]) => Ok(Invocation::Policy { report }),
            "verify" if self.only_allows(&[]) => Ok(Invocation::Verify { report }),
            "portability" if self.only_allows(&[]) => Ok(Invocation::Portability { report }),
            "dependency-attestation" if self.only_allows(&[InvocationOption::Output]) => {
                self.dependency_attestation_invocation(report)
            }
            "nightly"
                if self.only_allows(&[
                    InvocationOption::Oracle,
                    InvocationOption::OracleSha256,
                    InvocationOption::DependencyAttestation,
                ]) =>
            {
                self.nightly_invocation(report)
            }
            "native-oracle-shard"
                if self.only_allows(&[
                    InvocationOption::Source,
                    InvocationOption::Platform,
                    InvocationOption::DependencyAttestation,
                ]) =>
            {
                self.native_oracle_shard_invocation(report)
            }
            "native-differential-benchmark"
                if self.only_allows(&[
                    InvocationOption::Oracle,
                    InvocationOption::Candidate,
                    InvocationOption::SampleCount,
                ]) =>
            {
                self.native_benchmark_invocation(report)
            }
            "examples" if self.only_allows(&[InvocationOption::Profile]) => {
                self.examples_invocation(report)
            }
            _ => Err(format!("invalid subcommand options\n{}", usage())),
        }
    }

    fn only_allows(&self, allowed: &[InvocationOption]) -> bool {
        const ALL: [InvocationOption; 16] = [
            InvocationOption::Profile,
            InvocationOption::Format,
            InvocationOption::Oracle,
            InvocationOption::OracleSha256,
            InvocationOption::Candidate,
            InvocationOption::SampleCount,
            InvocationOption::Source,
            InvocationOption::Platform,
            InvocationOption::Input,
            InvocationOption::Output,
            InvocationOption::DependencyAttestation,
            InvocationOption::Proposal,
            InvocationOption::ExpectSource,
            InvocationOption::ExpectEpoch,
            InvocationOption::ExpectProposal,
            InvocationOption::Explain,
        ];
        ALL.into_iter()
            .all(|option| allowed.contains(&option) || !self.is_present(option))
    }

    fn is_present(&self, option: InvocationOption) -> bool {
        match option {
            InvocationOption::Profile => self.profile.is_some(),
            InvocationOption::Format => self.format.is_some(),
            InvocationOption::Oracle => self.oracle.is_some(),
            InvocationOption::OracleSha256 => self.oracle_sha256.is_some(),
            InvocationOption::Candidate => self.candidate.is_some(),
            InvocationOption::SampleCount => self.sample_count.is_some(),
            InvocationOption::Source => self.source.is_some(),
            InvocationOption::Platform => self.platform.is_some(),
            InvocationOption::Input => self.input.is_some(),
            InvocationOption::Output => self.output.is_some(),
            InvocationOption::DependencyAttestation => self.dependency_attestation.is_some(),
            InvocationOption::Proposal => self.proposal.is_some(),
            InvocationOption::ExpectSource => self.expect_source.is_some(),
            InvocationOption::ExpectEpoch => self.expect_epoch.is_some(),
            InvocationOption::ExpectProposal => self.expect_proposal.is_some(),
            InvocationOption::Explain => self.explain,
        }
    }

    fn dependency_attestation_invocation(self, report: PathBuf) -> Result<Invocation, String> {
        Ok(Invocation::DependencyAttestation {
            report,
            output: self
                .output
                .ok_or_else(|| "dependency-attestation requires --output PATH".to_owned())?,
        })
    }

    fn nightly_invocation(self, report: PathBuf) -> Result<Invocation, String> {
        Ok(Invocation::Nightly {
            report,
            oracle: self
                .oracle
                .ok_or_else(|| "nightly requires --oracle PATH".to_owned())?,
            oracle_sha256: self
                .oracle_sha256
                .ok_or_else(|| "nightly requires --oracle-sha256 HEX".to_owned())?,
            dependency_attestation: self
                .dependency_attestation
                .ok_or_else(|| "nightly requires --dependency-attestation PATH".to_owned())?,
        })
    }

    fn native_oracle_shard_invocation(self, report: PathBuf) -> Result<Invocation, String> {
        Ok(Invocation::NativeOracleShard {
            report,
            source: self
                .source
                .ok_or_else(|| "native-oracle-shard requires --source".to_owned())?,
            platform: self
                .platform
                .ok_or_else(|| "native-oracle-shard requires --platform".to_owned())?,
            dependency_attestation: self.dependency_attestation.ok_or_else(|| {
                "native-oracle-shard requires --dependency-attestation PATH".to_owned()
            })?,
        })
    }

    fn native_benchmark_invocation(self, report: PathBuf) -> Result<Invocation, String> {
        Ok(Invocation::NativeDifferentialBenchmark {
            report,
            oracle: self
                .oracle
                .ok_or_else(|| "native-differential-benchmark requires --oracle PATH".to_owned())?,
            candidate: self.candidate.ok_or_else(|| {
                "native-differential-benchmark requires --candidate PATH".to_owned()
            })?,
            sample_count: self.sample_count.ok_or_else(|| {
                "native-differential-benchmark requires --sample-count".to_owned()
            })?,
        })
    }

    fn examples_invocation(self, report: PathBuf) -> Result<Invocation, String> {
        let profile = match self.profile.as_deref() {
            Some("ci" | "release") => self.profile.expect("profile was matched"),
            Some(value) => return Err(format!("invalid profile {value}\n{}", usage())),
            None => return Err("examples requires --profile".to_owned()),
        };
        Ok(Invocation::Examples { profile, report })
    }
}

fn set_flag(slot: &mut bool, flag: &str) -> Result<(), String> {
    if *slot {
        return Err(format!("{flag} was provided more than once"));
    }
    *slot = true;
    Ok(())
}

fn set_path(
    slot: &mut Option<PathBuf>,
    arguments: &mut impl Iterator<Item = OsString>,
    flag: &str,
    requirement: &str,
) -> Result<(), String> {
    require_absent(slot.as_ref(), flag)?;
    *slot = Some(PathBuf::from(
        arguments
            .next()
            .ok_or_else(|| format!("{flag} requires {requirement}"))?,
    ));
    Ok(())
}

fn set_string(
    slot: &mut Option<String>,
    arguments: &mut impl Iterator<Item = OsString>,
    flag: &str,
    requirement: &str,
    utf_label: &str,
) -> Result<(), String> {
    require_absent(slot.as_ref(), flag)?;
    *slot = Some(next_string(arguments, flag, requirement, utf_label)?);
    Ok(())
}

fn next_string(
    arguments: &mut impl Iterator<Item = OsString>,
    flag: &str,
    requirement: &str,
    utf_label: &str,
) -> Result<String, String> {
    arguments
        .next()
        .ok_or_else(|| format!("{flag} requires {requirement}"))?
        .into_string()
        .map_err(|_| format!("{utf_label} must be UTF-8"))
}

fn require_absent<T>(slot: Option<&T>, flag: &str) -> Result<(), String> {
    if slot.is_some() {
        Err(format!("{flag} was provided more than once"))
    } else {
        Ok(())
    }
}

#[must_use]
pub fn main() -> ExitCode {
    let mut process_arguments = std::env::args_os();
    #[cfg(unix)]
    let invoked = process_arguments.next();
    #[cfg(not(unix))]
    process_arguments.next();
    let arguments = process_arguments.collect::<Vec<_>>();
    #[cfg(unix)]
    return dispatch_initial(arguments, invoked.as_deref());
    #[cfg(not(unix))]
    dispatch_initial(arguments)
}

fn dispatch_initial(arguments: Vec<OsString>, #[cfg(unix)] invoked: Option<&OsStr>) -> ExitCode {
    if arguments.first().and_then(|value| value.to_str())
        == Some("__verify-final-verification-transaction")
    {
        return match release::verify_transaction_for_integration(&arguments[1..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    #[cfg(any(unix, windows))]
    if arguments.first().and_then(|value| value.to_str()) == Some("__release-command-supervisor-v1")
    {
        return match release_suite::run_external_nightly_supervisor(&arguments[1..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    #[cfg(unix)]
    if arguments.first().and_then(|value| value.to_str())
        == Some("__nightly-supervisor-reporter-fixture")
    {
        return match release_suite::run_external_supervisor_reporter_fixture(&arguments[1..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    #[cfg(windows)]
    if arguments.first().and_then(|value| value.to_str())
        == Some("__nightly-supervisor-reporter-fixture")
    {
        return match release_suite::run_windows_external_supervisor_reporter_fixture(
            &arguments[1..],
        ) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    #[cfg(any(unix, windows))]
    if arguments.first().and_then(|value| value.to_str())
        == Some("__nightly-supervisor-owned-child")
    {
        return match release_suite::run_external_supervisor_owned_child(&arguments[1..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    #[cfg(windows)]
    if arguments.first().and_then(|value| value.to_str())
        == Some("__nightly-windows-session-access-probe")
    {
        return match release_suite::run_windows_supervisor_session_probe(&arguments[1..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    #[cfg(unix)]
    return dispatch_supervisor_verifications(arguments, invoked);
    #[cfg(not(unix))]
    dispatch_supervisor_verifications(arguments)
}

fn dispatch_supervisor_verifications(
    arguments: Vec<OsString>,
    #[cfg(unix)] invoked: Option<&OsStr>,
) -> ExitCode {
    #[cfg(any(unix, windows))]
    if arguments.first().and_then(|value| value.to_str())
        == Some("__nightly-supervisor-owned-grandchild")
    {
        if arguments.len() != 1 {
            eprintln!("nightly supervisor owned grandchild accepts no arguments");
            return ExitCode::FAILURE;
        }
        return match release_suite::run_external_supervisor_owned_grandchild() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    #[cfg(unix)]
    if arguments.first().and_then(|value| value.to_str())
        == Some("__verify-external-nightly-supervisor")
    {
        if arguments.len() != 1 {
            eprintln!("external nightly supervisor verification accepts no arguments");
            return ExitCode::FAILURE;
        }
        return match release_suite::verify_external_nightly_supervisor_for_integration() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    #[cfg(windows)]
    if arguments.first().and_then(|value| value.to_str())
        == Some("__verify-external-nightly-supervisor")
    {
        if arguments.len() != 2 {
            eprintln!("Windows external nightly supervisor verification requires one case");
            return ExitCode::FAILURE;
        }
        return match release_suite::verify_windows_external_nightly_supervisor_for_integration(
            &arguments[1..],
        ) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    #[cfg(unix)]
    if native_archive_adapter_dispatch(invoked) {
        return command::run_native_archive_adapter(&arguments);
    }
    if arguments.first().and_then(|value| value.to_str())
        == Some("__verify-portability-timeout-policy")
    {
        if arguments.len() != 1 {
            eprintln!("portability timeout policy verification accepts no arguments");
            return ExitCode::FAILURE;
        }
        return match release_suite::verify_portability_timeout_policy_for_integration() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    #[cfg(unix)]
    if arguments.first().and_then(|value| value.to_str())
        == Some("__verify-portability-supervision")
    {
        if arguments.len() != 1 {
            eprintln!("portability supervision verification accepts no arguments");
            return ExitCode::FAILURE;
        }
        return match release_suite::verify_portability_supervision_for_integration() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    dispatch_portability_children(arguments)
}

fn dispatch_portability_children(arguments: Vec<OsString>) -> ExitCode {
    #[cfg(unix)]
    if arguments.first().and_then(|value| value.to_str())
        == Some("__portability-supervision-fixture")
    {
        release_suite::run_portability_supervision_fixture(&arguments[1..]);
    }
    #[cfg(unix)]
    if arguments.first().and_then(|value| value.to_str())
        == Some("__portability-supervision-descendant")
    {
        release_suite::run_portability_supervision_descendant();
    }
    #[cfg(unix)]
    if arguments.first().and_then(|value| value.to_str())
        == Some(hell_testkit::POSIX_RELEASE_CHILD_REQUEST_V1)
    {
        return command::run_posix_release_child(&arguments[1..]);
    }
    #[cfg(target_os = "macos")]
    if arguments.first().and_then(|value| value.to_str())
        == Some("__verify-native-archive-broker-descendant-launcher")
    {
        return match command::verify_native_archive_broker_descendant_launcher(&arguments[1..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    #[cfg(target_os = "macos")]
    if arguments.first().and_then(|value| value.to_str())
        == Some("__verify-native-archive-broker-descendant-consumer")
    {
        return match command::verify_native_archive_broker_descendant_consumer(&arguments[1..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    #[cfg(target_os = "macos")]
    if arguments.first().and_then(|value| value.to_str())
        == Some("__verify-staged-native-toolchain")
    {
        let [adapter_root] = &arguments[1..] else {
            eprintln!("staged native toolchain verification requires one adapter root");
            return ExitCode::FAILURE;
        };
        return match command::verify_staged_native_toolchain_for_integration(Path::new(
            adapter_root,
        )) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    #[cfg(target_os = "macos")]
    if arguments.first().and_then(|value| value.to_str())
        == Some("__verify-native-archive-seal-rebinding")
    {
        let [adapter_root] = &arguments[1..] else {
            eprintln!("native archive seal verification requires one adapter root");
            return ExitCode::FAILURE;
        };
        return match command::verify_native_archive_seal_rebinding_for_integration(Path::new(
            adapter_root,
        )) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    dispatch_posix_transition_verifications(arguments)
}

fn dispatch_posix_transition_verifications(arguments: Vec<OsString>) -> ExitCode {
    #[cfg(unix)]
    if arguments.first().and_then(|value| value.to_str())
        == Some("__verify-posix-archive-adapter-transition")
    {
        if arguments.len() != 1 {
            eprintln!("POSIX archive adapter transition verification accepts no arguments");
            return ExitCode::FAILURE;
        }
        return match release::platform::verify_posix_archive_adapter_transition_for_integration() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    #[cfg(unix)]
    if arguments.first().and_then(|value| value.to_str())
        == Some("__verify-posix-source-stack-cleanup-order")
    {
        if arguments.len() != 1 {
            eprintln!("POSIX source Stack cleanup verification accepts no arguments");
            return ExitCode::FAILURE;
        }
        return match release::platform::verify_posix_source_stack_work_cleanup_order_for_integration(
        ) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    #[cfg(target_os = "macos")]
    if arguments.first().and_then(|value| value.to_str())
        == Some("__verify-macos-archive-cleanup-principal")
    {
        if arguments.len() != 1 {
            eprintln!("macOS archive cleanup principal verification accepts no arguments");
            return ExitCode::FAILURE;
        }
        return match release::platform::verify_macos_archive_cleanup_principal_for_integration() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    #[cfg(unix)]
    if arguments.first().and_then(|value| value.to_str())
        == Some("__verify-posix-post-state-metadata")
    {
        if arguments.len() != 1 {
            eprintln!("POSIX post-state metadata verification accepts no arguments");
            return ExitCode::FAILURE;
        }
        return match release::platform::verify_posix_post_state_metadata_for_integration() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    #[cfg(unix)]
    if arguments.first().and_then(|value| value.to_str())
        == Some("__verify-posix-candidate-environment-construction")
    {
        if arguments.len() != 1 {
            eprintln!("POSIX candidate environment verification accepts no arguments");
            return ExitCode::FAILURE;
        }
        return match release::platform::verify_posix_candidate_environment_construction_for_integration(
        ) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    #[cfg(unix)]
    if arguments.first().and_then(|value| value.to_str())
        == Some("__verify-posix-process-authority")
    {
        if arguments.len() != 1 {
            eprintln!("POSIX process authority verification accepts no arguments");
            return ExitCode::FAILURE;
        }
        return match release::platform::verify_posix_process_authority_for_integration() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    dispatch_posix_authority_verifications(arguments)
}

fn dispatch_posix_authority_verifications(arguments: Vec<OsString>) -> ExitCode {
    #[cfg(unix)]
    if arguments.first().and_then(|value| value.to_str())
        == Some("__verify-posix-identity-query-deadline")
    {
        if arguments.len() != 1 {
            eprintln!("POSIX identity query deadline verification accepts no arguments");
            return ExitCode::FAILURE;
        }
        return match release::platform::verify_posix_identity_query_deadline_for_integration() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    #[cfg(unix)]
    if arguments.first().and_then(|value| value.to_str())
        == Some("__verify-posix-candidate-target-remover")
    {
        if arguments.len() != 1 {
            eprintln!("POSIX candidate target remover verification accepts no arguments");
            return ExitCode::FAILURE;
        }
        return match release::platform::verify_posix_candidate_target_remover_for_integration() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    #[cfg(unix)]
    if arguments.first().and_then(|value| value.to_str())
        == Some("__verify-posix-principal-cleanup-order")
    {
        if arguments.len() != 1 {
            eprintln!("POSIX principal cleanup order verification accepts no arguments");
            return ExitCode::FAILURE;
        }
        return match release::platform::verify_posix_principal_cleanup_order_for_integration() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    dispatch_posix_candidate_verifications(arguments)
}

fn dispatch_posix_candidate_verifications(arguments: Vec<OsString>) -> ExitCode {
    #[cfg(unix)]
    if arguments.first().and_then(|value| value.to_str())
        == Some("__verify-posix-candidate-driver-receipt")
    {
        return match release::platform::verify_posix_candidate_driver_receipt_for_integration(
            &arguments[1..],
        ) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    #[cfg(unix)]
    if arguments.first().and_then(|value| value.to_str())
        == Some("__verify-posix-candidate-target-authority")
    {
        if arguments.len() != 1 {
            eprintln!("POSIX candidate target verification accepts no arguments");
            return ExitCode::FAILURE;
        }
        return match release::platform::verify_posix_candidate_target_authority_for_integration() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    #[cfg(unix)]
    if arguments.first().and_then(|value| value.to_str())
        == Some("__verify-posix-native-cargo-rejection")
    {
        if arguments.len() != 1 {
            eprintln!("POSIX native Cargo rejection verification accepts no arguments");
            return ExitCode::FAILURE;
        }
        return match release::platform::verify_posix_native_cargo_rejection_for_integration() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    #[cfg(unix)]
    if arguments.first().and_then(|value| value.to_str())
        == Some("__verify-posix-rustc-environment")
    {
        if arguments.len() != 1 {
            eprintln!("POSIX Rust compiler environment verification accepts no arguments");
            return ExitCode::FAILURE;
        }
        return match release::platform::verify_posix_rustc_environment_for_integration() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    #[cfg(unix)]
    if arguments.first().and_then(|value| value.to_str())
        == Some("__verify-posix-candidate-home-test-authority")
    {
        if arguments.len() != 1 {
            eprintln!("POSIX candidate home test verification accepts no arguments");
            return ExitCode::FAILURE;
        }
        return match release::platform::verify_posix_candidate_home_test_authority_for_integration()
        {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    dispatch_tool_resolution_verifications(arguments)
}

fn dispatch_tool_resolution_verifications(arguments: Vec<OsString>) -> ExitCode {
    #[cfg(unix)]
    if arguments.first().and_then(|value| value.to_str()) == Some("__verify-cargo-multicall-argv") {
        if arguments.len() != 1 {
            eprintln!("Cargo multicall argv verification accepts no arguments");
            return ExitCode::FAILURE;
        }
        return match command::verify_cargo_multicall_argv_for_integration() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    #[cfg(unix)]
    if arguments.first().and_then(|value| value.to_str()) == Some("__verify-standard-tool-resolver")
    {
        if arguments.len() != 1 {
            eprintln!("standard tool resolver verification accepts no arguments");
            return ExitCode::FAILURE;
        }
        return match command::verify_standard_tool_resolver_for_integration() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    #[cfg(unix)]
    if arguments.first().and_then(|value| value.to_str())
        == Some("__verify-cargo-multicall-argv-child")
    {
        if arguments.len() != 1 {
            eprintln!("Cargo multicall argv child verification accepts no arguments");
            return ExitCode::FAILURE;
        }
        return match command::verify_cargo_multicall_argv_child_for_integration() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    #[cfg(target_os = "macos")]
    if arguments.first().and_then(|value| value.to_str())
        == Some("__verify-staged-native-acl-policy")
    {
        if arguments.len() != 1 {
            eprintln!("staged native ACL verification accepts no arguments");
            return ExitCode::FAILURE;
        }
        return match command::verify_staged_native_acl_policy_for_integration() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    #[cfg(target_os = "macos")]
    if arguments.first().and_then(|value| value.to_str()) == Some("__native-archiver-receipt-child")
    {
        if arguments.len() != 1 {
            eprintln!("native archiver receipt child accepts no arguments");
            return ExitCode::FAILURE;
        }
        println!("member.o");
        return ExitCode::SUCCESS;
    }
    dispatch_macos_archive_verifications(arguments)
}

fn dispatch_macos_archive_verifications(arguments: Vec<OsString>) -> ExitCode {
    #[cfg(target_os = "macos")]
    if arguments.first().and_then(|value| value.to_str())
        == Some("__verify-macos-native-archiver-acquisition")
    {
        if arguments.len() != 2 {
            eprintln!("macOS native archiver acquisition verification requires RECEIPT");
            return ExitCode::FAILURE;
        }
        return match command::verify_macos_native_archiver_acquisition_for_integration(Path::new(
            &arguments[1],
        )) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    #[cfg(target_os = "macos")]
    if arguments.first().and_then(|value| value.to_str())
        == Some("__verify-macos-native-archiver-topology")
    {
        if arguments.len() != 2 {
            eprintln!("macOS native archiver topology verification requires RECEIPT");
            return ExitCode::FAILURE;
        }
        return match command::verify_macos_native_archiver_topology_for_integration(Path::new(
            &arguments[1],
        )) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    #[cfg(target_os = "macos")]
    if arguments.first().and_then(|value| value.to_str())
        == Some("__verify-macos-native-archiver-dependency-receipt")
    {
        if arguments.len() != 1 {
            eprintln!("macOS native archiver dependency verification accepts no arguments");
            return ExitCode::FAILURE;
        }
        return match command::verify_macos_native_archiver_dependency_receipt_for_integration() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    #[cfg(target_os = "macos")]
    if arguments.first().and_then(|value| value.to_str())
        == Some("__verify-macos-native-archiver-receipt")
    {
        if arguments.len() != 1 {
            eprintln!("macOS native archiver receipt verification accepts no arguments");
            return ExitCode::FAILURE;
        }
        return match command::verify_macos_native_archiver_receipt_for_integration() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    dispatch_native_archive_ghc_verifications(arguments)
}

fn dispatch_native_archive_ghc_verifications(arguments: Vec<OsString>) -> ExitCode {
    #[cfg(unix)]
    if arguments.first().and_then(|value| value.to_str())
        == Some("__verify-native-archive-ghc-configure-probe")
    {
        let [base] = &arguments[1..] else {
            eprintln!("native archive GHC configure verification requires one base path");
            return ExitCode::FAILURE;
        };
        return match command::verify_native_archive_ghc_configure_probe_for_integration(Path::new(
            base,
        )) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    #[cfg(target_os = "macos")]
    if arguments.first().and_then(|value| value.to_str())
        == Some("__native-archive-ghc-configure-hung-child")
    {
        return match command::run_native_archive_ghc_configure_hung_child_for_integration(
            &arguments[1..],
        ) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    dispatch_archive_policy_verifications(arguments)
}

fn dispatch_archive_policy_verifications(arguments: Vec<OsString>) -> ExitCode {
    #[cfg(unix)]
    if arguments.first().and_then(|value| value.to_str()) == Some("__verify-native-archive-policy")
    {
        if arguments.len() != 1 {
            eprintln!("native archive policy verification accepts no arguments");
            return ExitCode::FAILURE;
        }
        return match command::verify_native_archive_policy_for_integration() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    #[cfg(unix)]
    if arguments.first().and_then(|value| value.to_str())
        == Some("__verify-native-archive-adapter-cleanup")
    {
        let [base] = &arguments[1..] else {
            eprintln!("native archive adapter cleanup verification requires one base path");
            return ExitCode::FAILURE;
        };
        return match command::verify_native_archive_adapter_cleanup_for_integration(Path::new(base))
        {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    if arguments.first().and_then(|value| value.to_str())
        == Some("__verify-nightly-workspace-partition")
    {
        if arguments.len() != 1 {
            eprintln!("nightly workspace partition verification accepts no arguments");
            return ExitCode::FAILURE;
        }
        return match release_suite::verify_nightly_workspace_partition_for_integration() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    #[cfg(unix)]
    if arguments.first().and_then(|value| value.to_str()) == Some("__nightly-failed-case-child") {
        if arguments.len() != 1 {
            eprintln!("nightly failed-case child accepts no arguments");
            return ExitCode::FAILURE;
        }
        release_suite::run_nightly_failed_case_child();
        return ExitCode::FAILURE;
    }
    #[cfg(unix)]
    if arguments.first().and_then(|value| value.to_str())
        == Some("__verify-nightly-failed-case-attribution")
    {
        if arguments.len() != 1 {
            eprintln!("nightly failed-case attribution verification accepts no arguments");
            return ExitCode::FAILURE;
        }
        return match release_suite::verify_nightly_failed_case_attribution_for_integration() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    #[cfg(unix)]
    if arguments.first().and_then(|value| value.to_str())
        == Some("__verify-nightly-attributed-supervision")
    {
        if arguments.len() != 1 {
            eprintln!("nightly attributed supervision verification accepts no arguments");
            return ExitCode::FAILURE;
        }
        return match release_suite::verify_nightly_attributed_supervision_for_integration() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    dispatch_platform_children(arguments)
}

fn dispatch_platform_children(arguments: Vec<OsString>) -> ExitCode {
    #[cfg(windows)]
    if arguments.first().and_then(|value| value.to_str())
        == Some("__verify-windows-hell-testkit-diagnostics")
    {
        if arguments.len() != 1 {
            eprintln!("Windows hell-testkit diagnostic verification accepts no arguments");
            return ExitCode::FAILURE;
        }
        return match release_suite::verify_windows_hell_testkit_diagnostics_for_integration() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    #[cfg(any(unix, windows))]
    if arguments.first().and_then(|value| value.to_str())
        == Some("__verify-platform-command-failure-report")
    {
        if arguments.len() != 1 {
            eprintln!("platform command-failure report verification accepts no arguments");
            return ExitCode::FAILURE;
        }
        return match release::platform::verify_platform_command_failure_report_for_integration() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    #[cfg(any(unix, windows))]
    if arguments.first().and_then(|value| value.to_str())
        == Some("__platform-command-failure-child")
    {
        return release::platform::run_platform_command_failure_child(&arguments[1..]);
    }
    #[cfg(windows)]
    if arguments.first().and_then(|value| value.to_str())
        == Some("__repository-inventory-target-stderr-child")
    {
        return release::platform::run_repository_inventory_target_stderr_child(&arguments[1..]);
    }
    #[cfg(unix)]
    if arguments.first().and_then(|value| value.to_str())
        == Some("__release-normalize-candidate-cache")
    {
        return match release::platform::run_posix_candidate_cache_normalizer(&arguments[1..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    #[cfg(unix)]
    if arguments.first().and_then(|value| value.to_str())
        == Some("__release-remove-candidate-target-verifier")
    {
        return match release::platform::run_posix_candidate_target_verifier_remover(&arguments[1..])
        {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    dispatch_platform_normalizers(arguments)
}

fn dispatch_platform_normalizers(arguments: Vec<OsString>) -> ExitCode {
    #[cfg(unix)]
    if arguments.first().and_then(|value| value.to_str())
        == Some("__release-normalize-cargo-deny-home")
    {
        return match release::platform::run_posix_cargo_deny_home_normalizer(&arguments[1..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    #[cfg(unix)]
    if arguments.first().and_then(|value| value.to_str()) == Some("__release-normalize-stack-root")
    {
        return match release::platform::run_posix_stack_root_normalizer(&arguments[1..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    #[cfg(unix)]
    if arguments.first().and_then(|value| value.to_str()) == Some("__release-normalize-stack-work")
    {
        return match release::platform::run_posix_stack_work_normalizer(&arguments[1..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    #[cfg(windows)]
    if arguments.first().and_then(|value| value.to_str())
        == Some("__verify-windows-platform-gate-topology")
    {
        if arguments.len() != 1 {
            eprintln!("Windows platform gate topology verification accepts no arguments");
            return ExitCode::FAILURE;
        }
        return match release::platform::verify_windows_platform_gate_topology_for_integration() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    #[cfg(windows)]
    if arguments.first().and_then(|value| value.to_str())
        == Some("__verify-windows-final-platform-inventory")
    {
        if arguments.len() != 1 {
            eprintln!("Windows final platform inventory verification accepts no arguments");
            return ExitCode::FAILURE;
        }
        return match release::platform::verify_windows_final_platform_inventory_for_integration() {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    #[cfg(windows)]
    if arguments.first().and_then(|value| value.to_str())
        == Some("__verify-windows-candidate-target-authority")
    {
        if arguments.len() != 1 {
            eprintln!("Windows candidate target verification accepts no arguments");
            return ExitCode::FAILURE;
        }
        return match release::platform::verify_windows_candidate_target_authority_for_integration()
        {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    #[cfg(windows)]
    if arguments.first().and_then(|value| value.to_str()) == Some("__release-restricted-child") {
        return command::run_windows_restricted_child(&arguments[1..]);
    }
    #[cfg(windows)]
    if arguments.first().and_then(|value| value.to_str())
        == Some("__nightly-write-restricted-child")
    {
        return command::run_windows_write_restricted_child(&arguments[1..]);
    }
    dispatch_public_cli(arguments)
}

fn dispatch_public_cli(arguments: Vec<OsString>) -> ExitCode {
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
    if assurance::recognizes(&arguments) {
        return match assurance::run(&arguments) {
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
    if fuzz::recognizes(&arguments) {
        return match fuzz::run_cli(&arguments) {
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
    dispatch_release_cli(arguments, &root)
}

fn dispatch_release_cli(arguments: Vec<OsString>, root: &Path) -> ExitCode {
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
    if protocol::recognizes(&arguments) {
        return match protocol::run(&arguments) {
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
    if repository::recognizes(&arguments) {
        return match repository::run(&arguments) {
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
    if capability_policy::recognizes(&arguments) {
        return match capability_policy::run(&arguments) {
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
    if release::native_environment::recognizes(&arguments) {
        return match release::native_environment::run(&arguments) {
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
    run(&invocation, root)
}

#[cfg(unix)]
fn native_archive_adapter_dispatch(invoked: Option<&OsStr>) -> bool {
    invoked
        .map(Path::new)
        .and_then(Path::file_name)
        .and_then(OsStr::to_str)
        .is_some_and(|name| name == "ar")
}

fn run(invocation: &Invocation, root: &Path) -> ExitCode {
    let (suite_name, report_path) = match invocation {
        Invocation::Policy { report } => ("policy", report),
        Invocation::Verify { report } => ("verify", report),
        Invocation::Portability { report } => ("portability", report),
        Invocation::Nightly { report, .. } => ("nightly", report),
        Invocation::NativeOracleShard { report, .. } => ("native-oracle-shard", report),
        Invocation::NativeDifferentialBenchmark { report, .. } => {
            ("native-differential-benchmark", report)
        }
        Invocation::DependencyAttestation { report, .. } => ("dependency-attestation", report),
        Invocation::Examples { report, .. } => ("examples", report),
    };
    let mut report = Report::new(suite_name);
    if (matches!(invocation, Invocation::Nightly { .. })
        || (cfg!(target_os = "macos") && matches!(invocation, Invocation::Portability { .. })))
        && let Err(error) = report.attach_checkpoint(report_path.clone())
    {
        eprintln!(
            "cannot write initial report checkpoint {}: {error}",
            report_path.display()
        );
        return ExitCode::from(40);
    }
    if matches!(invocation, Invocation::NativeDifferentialBenchmark { .. }) {
        report.mark_non_authoritative();
    }
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
        Invocation::NativeDifferentialBenchmark {
            oracle,
            candidate,
            sample_count,
            ..
        } => release_suite::native_differential_benchmark(
            root,
            &mut report,
            oracle,
            candidate,
            *sample_count,
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
    report.complete();
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
fn test_thread_name_component(name: Option<&str>) -> String {
    hell_testkit::sha256_bytes(name.unwrap_or("unnamed").as_bytes()).hex()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn native_archive_adapter_dispatch_accepts_only_ar() {
        assert!(native_archive_adapter_dispatch(Some(OsStr::new("ar"))));
        assert!(native_archive_adapter_dispatch(Some(OsStr::new(
            "/fixed/adapter/ar"
        ))));
        assert!(!native_archive_adapter_dispatch(Some(OsStr::new(
            "llvm-ar"
        ))));
        assert!(!native_archive_adapter_dispatch(Some(OsStr::new(
            "/fixed/adapter/llvm-ar"
        ))));
        assert!(!native_archive_adapter_dispatch(Some(OsStr::new("ld"))));
        assert!(!native_archive_adapter_dispatch(Some(OsStr::new(
            "/fixed/adapter/ld"
        ))));
        assert!(!native_archive_adapter_dispatch(None));
    }

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
    fn test_thread_name_component_is_exact_bounded_and_windows_safe() {
        let adversarial = "conformance::CON:<>\":/\\|?* trailing. β";
        let component = test_thread_name_component(Some(adversarial));
        assert_eq!(component.len(), 64);
        assert!(component.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(component, test_thread_name_component(Some(adversarial)));
        assert_ne!(component, test_thread_name_component(Some("other::test")));
        assert_ne!(component, test_thread_name_component(None));
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
    fn native_benchmark_requires_typed_paths_and_canonical_sample_count() {
        assert!(
            parse(["native-differential-benchmark", "--report", "out.json"].map(OsString::from))
                .is_err()
        );
        assert!(
            parse(
                [
                    "native-differential-benchmark",
                    "--oracle",
                    "oracle",
                    "--candidate",
                    "candidate",
                    "--sample-count",
                    "0256",
                    "--report",
                    "out.json",
                ]
                .map(OsString::from)
            )
            .is_err()
        );
        assert!(matches!(
            parse(
                [
                    "native-differential-benchmark",
                    "--oracle",
                    "oracle",
                    "--candidate",
                    "candidate",
                    "--sample-count",
                    "256",
                    "--report",
                    "out.json",
                ]
                .map(OsString::from)
            ),
            Ok(Invocation::NativeDifferentialBenchmark {
                sample_count: 256,
                ..
            })
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
