mod assurance;
mod catalog_lock;
mod collection_authority_ops;
mod collection_custody;
mod collection_transport;
mod command;
mod custody_ops;
mod fixtures;
mod fuzz_surfaces;
mod offline_review_ops;
mod oracle_ops;
mod oracle_record;
mod policy;
mod promotion_policy;
mod release_oracle;
mod report;
mod strict_toml;
mod suite;
mod surveillance_impact;
mod surveillance_ops;
#[cfg(test)]
mod synthetic_promotion;
mod worklist_encoding;

const _: fn(&[u8]) -> Result<(), String> = assurance::fuzz_admit_acquisition_receipt;
const _: fn(&[u8]) -> Result<(), String> = assurance::fuzz_admit_evidence_graph_merge;
const _: fn(&[u8]) -> Result<(), String> = assurance::fuzz_admit_provenance_record;
const _: fn(&[u8]) -> Result<(), String> = assurance::fuzz_admit_review_graph;
const _: fn(&[u8]) -> Result<(), String> = assurance::fuzz_admit_dsse_envelope;
const _: fn() -> Result<Vec<u8>, String> = assurance::fuzz_evidence_graph_seed;
const _: fn(&[u8]) -> Result<(), String> = custody_ops::fuzz_admit_custody_receipt;

#[cfg(feature = "mutation-testing")]
pub(crate) fn assurance_control_mutant_active(id: &str) -> bool {
    std::env::var("HELL_ASSURANCE_MUTANT_ID").as_deref() == Ok(id)
}

#[cfg(not(feature = "mutation-testing"))]
pub(crate) const fn assurance_control_mutant_active(_id: &str) -> bool {
    false
}

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
        dependency_attestation: PathBuf,
        require_signed_acquisition: bool,
        surveillance_subject: bool,
    },
    NativeOracleShard {
        report: PathBuf,
        source: PathBuf,
        platform: String,
        dependency_attestation: PathBuf,
    },
    MergeNativeShards {
        report: PathBuf,
        input: PathBuf,
    },
    PromotionGate {
        report: PathBuf,
        input: PathBuf,
        proposal: PathBuf,
        expect_source: String,
        expect_epoch: String,
        expect_proposal: String,
        explain: bool,
    },
    DependencyAttestation {
        report: PathBuf,
        output: PathBuf,
    },
    PromotionWorklist {
        report: PathBuf,
        output: PathBuf,
        profile: String,
        format: String,
        only: String,
        group_by: String,
    },
    Examples {
        profile: String,
        report: PathBuf,
    },
}

fn usage() -> &'static str {
    "usage: hell-ci policy --report PATH\n       hell-ci verify --report PATH\n       hell-ci portability --report PATH\n       hell-ci dependency-attestation --output PATH --report PATH\n       hell-ci promotion-worklist --profile upstream --format csv|json|html --output PATH --report PATH\n       hell-ci nightly --oracle PATH --oracle-sha256 HEX --dependency-attestation PATH --report PATH\n       hell-ci nightly-exploratory --oracle PATH --oracle-sha256 HEX --dependency-attestation PATH --report PATH\n       hell-ci nightly-surveillance-subject --oracle PATH --oracle-sha256 HEX --dependency-attestation PATH --report PATH\n       hell-ci native-oracle-shard --source PATH --platform ID --dependency-attestation PATH --report PATH\n       hell-ci merge-native-shards --input PATH --report PATH\n       hell-ci promotion-gate --input PATH --proposal PATH --expect-source SHA --expect-epoch SHA256 --expect-proposal SHA256 --report PATH [--explain]\n       hell-ci examples --profile ci|release --report PATH"
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
    if github_dispatch_inputs && command != "promotion-gate" {
        return Err("--github-dispatch-inputs is valid only for promotion-gate".to_owned());
    }
    if command != "promotion-worklist" && (only.is_some() || group_by.is_some()) {
        return Err("--only and --group-by are valid only for promotion-worklist".to_owned());
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
        "promotion-worklist"
            if oracle.is_none()
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
            Ok(Invocation::PromotionWorklist {
                report,
                output: output
                    .ok_or_else(|| "promotion-worklist requires --output PATH".to_owned())?,
                profile: match profile.as_deref() {
                    Some("upstream") => "upstream".to_owned(),
                    Some(value) => return Err(format!("invalid promotion profile {value:?}")),
                    None => return Err("promotion-worklist requires --profile upstream".to_owned()),
                },
                format: match format.as_deref() {
                    Some("csv" | "json" | "html") => format.expect("format was matched"),
                    Some(value) => return Err(format!("invalid worklist format {value:?}")),
                    None => "csv".to_owned(),
                },
                only: match only.as_deref() {
                    Some("ambiguous") => "ambiguous".to_owned(),
                    Some(value) => return Err(format!("invalid worklist filter {value:?}")),
                    None => "all".to_owned(),
                },
                group_by: match group_by.as_deref() {
                    Some("assurance-equivalence") => "assurance-equivalence".to_owned(),
                    Some(value) => return Err(format!("invalid worklist grouping {value:?}")),
                    None => "builtin".to_owned(),
                },
            })
        }
        "nightly" | "nightly-exploratory" | "nightly-surveillance-subject"
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
                require_signed_acquisition: command == "nightly",
                surveillance_subject: command == "nightly-surveillance-subject",
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
        "merge-native-shards"
            if profile.is_none()
                && format.is_none()
                && oracle.is_none()
                && oracle_sha256.is_none()
                && source.is_none()
                && platform.is_none()
                && output.is_none()
                && dependency_attestation.is_none()
                && proposal.is_none()
                && expect_source.is_none()
                && expect_epoch.is_none()
                && expect_proposal.is_none()
                && !explain =>
        {
            Ok(Invocation::MergeNativeShards {
                report,
                input: input.ok_or_else(|| "merge-native-shards requires --input".to_owned())?,
            })
        }
        "promotion-gate"
            if profile.is_none()
                && format.is_none()
                && oracle.is_none()
                && oracle_sha256.is_none()
                && source.is_none()
                && platform.is_none()
                && output.is_none()
                && dependency_attestation.is_none() =>
        {
            let (expect_source, expect_epoch, expect_proposal) = if github_dispatch_inputs {
                if expect_source.is_some() || expect_epoch.is_some() || expect_proposal.is_some() {
                    return Err(
                        "dispatch event decoding cannot be combined with explicit expectations"
                            .to_owned(),
                    );
                }
                let (source, epoch, proposal) = assurance::github_dispatch_inputs()?;
                (Some(source), Some(epoch), Some(proposal))
            } else {
                (expect_source, expect_epoch, expect_proposal)
            };
            Ok(Invocation::PromotionGate {
                report,
                input: input.ok_or_else(|| "promotion-gate requires --input".to_owned())?,
                proposal: proposal
                    .ok_or_else(|| "promotion-gate requires --proposal".to_owned())?,
                expect_source: expect_source
                    .ok_or_else(|| "promotion-gate requires --expect-source".to_owned())?,
                expect_epoch: expect_epoch
                    .ok_or_else(|| "promotion-gate requires --expect-epoch".to_owned())?,
                expect_proposal: expect_proposal
                    .ok_or_else(|| "promotion-gate requires --expect-proposal".to_owned())?,
                explain,
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
    let root = match std::env::current_dir() {
        Ok(root) => root,
        Err(error) => {
            eprintln!("cannot determine repository root: {error}");
            return ExitCode::from(40);
        }
    };
    if assurance::recognizes(&arguments) {
        return assurance::run_cli(&root, &arguments);
    }
    for adapter in [
        (
            collection_authority_ops::recognizes as fn(&[OsString]) -> bool,
            collection_authority_ops::run as fn(&[OsString]) -> Result<String, String>,
        ),
        (
            oracle_ops::recognizes as fn(&[OsString]) -> bool,
            oracle_ops::run as fn(&[OsString]) -> Result<String, String>,
        ),
        (
            custody_ops::recognizes as fn(&[OsString]) -> bool,
            custody_ops::run as fn(&[OsString]) -> Result<String, String>,
        ),
        (
            offline_review_ops::recognizes as fn(&[OsString]) -> bool,
            offline_review_ops::run as fn(&[OsString]) -> Result<String, String>,
        ),
        (
            surveillance_ops::recognizes as fn(&[OsString]) -> bool,
            surveillance_ops::run as fn(&[OsString]) -> Result<String, String>,
        ),
        (
            release_oracle::recognizes as fn(&[OsString]) -> bool,
            release_oracle::run as fn(&[OsString]) -> Result<String, String>,
        ),
    ] {
        if adapter.0(&arguments) {
            return match adapter.1(&arguments) {
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
        Invocation::MergeNativeShards { report, .. } => ("merge-native-shards", report),
        Invocation::PromotionGate { report, .. } => ("promotion-gate", report),
        Invocation::DependencyAttestation { report, .. } => ("dependency-attestation", report),
        Invocation::PromotionWorklist { report, .. } => ("promotion-worklist", report),
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
            dependency_attestation,
            require_signed_acquisition,
            surveillance_subject,
            ..
        } => {
            if *surveillance_subject {
                suite::nightly_surveillance_subject(
                    root,
                    &mut report,
                    &failures,
                    oracle,
                    *oracle_sha256,
                    dependency_attestation,
                )
            } else if *require_signed_acquisition {
                suite::nightly(
                    root,
                    &mut report,
                    &failures,
                    oracle,
                    *oracle_sha256,
                    dependency_attestation,
                )
            } else {
                suite::nightly_exploratory(
                    root,
                    &mut report,
                    &failures,
                    oracle,
                    *oracle_sha256,
                    dependency_attestation,
                )
            }
        }
        Invocation::NativeOracleShard {
            source,
            platform,
            dependency_attestation,
            ..
        } => suite::native_oracle_shard(
            root,
            &mut report,
            &failures,
            source,
            platform,
            dependency_attestation,
        ),
        Invocation::MergeNativeShards { input, .. } => {
            suite::merge_native_shards(root, input, &mut report)
        }
        Invocation::PromotionGate {
            input,
            proposal,
            expect_source,
            expect_epoch,
            expect_proposal,
            explain,
            ..
        } => {
            if let Err(detail) = assurance::validate_promotion_dispatch(
                root,
                input,
                proposal,
                expect_source,
                expect_epoch,
                expect_proposal,
            ) {
                report.check(
                    "promotion-dispatch-binding",
                    std::time::Duration::ZERO,
                    Err(detail),
                );
                Err(FailureKind::Policy)
            } else {
                suite::promotion_gate(root, input, *explain, &mut report)
            }
        }
        Invocation::DependencyAttestation { output, .. } => {
            suite::dependency_attestation(root, output, &mut report)
        }
        Invocation::PromotionWorklist {
            output,
            profile,
            format,
            only,
            group_by,
            ..
        } => suite::promotion_worklist(root, output, profile, format, only, group_by, &mut report),
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
    if matches!(invocation, Invocation::PromotionGate { .. }) {
        let report_bytes = match std::fs::read(report_path) {
            Ok(bytes) => bytes,
            Err(error) => {
                eprintln!(
                    "cannot hash promotion report {}: {error}",
                    report_path.display()
                );
                return ExitCode::from(40);
            }
        };
        let digest = hell_testkit::sha256_bytes(&report_bytes).hex();
        let Some(name) = report_path.file_name().and_then(|name| name.to_str()) else {
            eprintln!("promotion report name must be UTF-8");
            return ExitCode::from(40);
        };
        let digest_path = report_path.with_extension("sha256");
        if let Err(error) = std::fs::write(&digest_path, format!("{digest}  {name}\n")) {
            eprintln!(
                "cannot write promotion report digest {}: {error}",
                digest_path.display()
            );
            return ExitCode::from(40);
        }
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
                    "--dependency-attestation",
                    "dependency-policy.json",
                    "--report",
                    "out.json",
                ]
                .map(OsString::from)
            ),
            Ok(Invocation::Nightly { .. })
        ));
        assert!(matches!(
            parse(
                [
                    "nightly-exploratory",
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
            Ok(Invocation::Nightly {
                require_signed_acquisition: false,
                ..
            })
        ));
        assert!(matches!(
            parse(
                [
                    "nightly-surveillance-subject",
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
            Ok(Invocation::Nightly {
                require_signed_acquisition: false,
                surveillance_subject: true,
                ..
            })
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
    fn promotion_gate_requires_retained_native_shards() {
        assert!(parse(["promotion-gate", "--report", "out.json"].map(OsString::from)).is_err());
        assert!(matches!(
            parse(
                [
                    "promotion-gate",
                    "--input",
                    "native-shards",
                    "--proposal",
                    "proposal.json",
                    "--expect-source",
                    "1111111111111111111111111111111111111111",
                    "--expect-epoch",
                    "2222222222222222222222222222222222222222222222222222222222222222",
                    "--expect-proposal",
                    "3333333333333333333333333333333333333333333333333333333333333333",
                    "--report",
                    "out.json",
                ]
                .map(OsString::from)
            ),
            Ok(Invocation::PromotionGate { .. })
        ));
    }

    #[test]
    fn promotion_gate_writes_a_digested_report_without_mutating_retained_input() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..");
        let sandbox =
            std::env::temp_dir().join(format!("hell-promotion-gate-main-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&sandbox);
        std::fs::create_dir(&sandbox).unwrap();
        let manifest = "{\n  \"validatedShardCount\": 3\n}\n";
        std::fs::write(sandbox.join("merged-native-shards.json"), manifest).unwrap();
        let manifest_digest = hell_testkit::sha256_bytes(manifest.as_bytes()).hex();
        std::fs::write(
            sandbox.join("merged-native-shards.sha256"),
            format!("{manifest_digest}  merged-native-shards.json\n"),
        )
        .unwrap();
        let report = sandbox.join("promotion-gate.json");
        let source = String::from_utf8(
            std::process::Command::new("git")
                .args(["rev-parse", "HEAD"])
                .current_dir(&root)
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap();
        let invocation = Invocation::PromotionGate {
            input: sandbox.clone(),
            proposal: sandbox.join("missing-proposal.json"),
            expect_source: source.trim().to_owned(),
            expect_epoch: hell_testkit::sha256_bytes(b"wrong epoch").hex(),
            expect_proposal: hell_testkit::sha256_bytes(b"wrong proposal").hex(),
            explain: true,
            report: report.clone(),
        };
        let _ = run(&invocation, &root);
        assert_eq!(
            std::fs::read_to_string(sandbox.join("merged-native-shards.json")).unwrap(),
            manifest
        );
        let report_bytes = std::fs::read(&report).unwrap();
        let expected = hell_testkit::sha256_bytes(&report_bytes).hex();
        let recorded = std::fs::read_to_string(report.with_extension("sha256")).unwrap();
        assert_eq!(recorded, format!("{expected}  promotion-gate.json\n"));
        std::fs::remove_dir_all(sandbox).unwrap();
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
            "run: ./target/ci/hell-ci release-oracle acquire --artifact ci-out/linux-release-oracle --provider-response ci-out/linux-release-provider.json --receipt ci-out/linux-release-oracle-receipt.json"
        ));
        assert!(workflow.contains(
            "run: ./target/ci/hell-ci release-oracle attest --artifact ci-out/linux-release-oracle --provider-response ci-out/linux-release-provider.json --receipt ci-out/linux-release-oracle-receipt.json --attestation ci-out/linux-release-oracle-acquisition.dsse.json"
        ));
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
