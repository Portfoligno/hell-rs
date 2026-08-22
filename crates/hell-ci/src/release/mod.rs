mod archive;
pub(crate) mod assemble;
mod decision;
mod event;
mod final_verify;
mod github;
pub(crate) mod governance;
pub(crate) mod manifest;
pub(crate) mod native_environment;
pub(crate) mod plan;
pub(crate) mod platform;
mod publish;
mod remote_state;
pub(crate) mod schema;
mod vectors;
mod verify;

pub(crate) use archive::assurance_extra_evidence_archive_member;
pub(crate) use archive::{fuzz_verify_gzip, fuzz_verify_tar};
pub(crate) use final_verify::fuzz_parse_publication_envelope;
pub(crate) use final_verify::verify_transaction_for_integration;
pub(crate) use verify::{assurance_omitted_subject, fuzz_parse_release_gate, fuzz_parse_subjects};

use std::ffi::OsString;
use std::path::PathBuf;

#[derive(Default)]
struct Options {
    output: Option<PathBuf>,
    report: Option<PathBuf>,
    resolution: Option<PathBuf>,
    repository_root: Option<PathBuf>,
    oracle_source: Option<PathBuf>,
    plan: Option<PathBuf>,
    conformance_plan: Option<PathBuf>,
    input: Option<PathBuf>,
    bundle: Option<PathBuf>,
    primary: Option<PathBuf>,
    independent: Option<PathBuf>,
    independent_verifier: Option<PathBuf>,
    protocol_projection: Option<PathBuf>,
    platform_input: Option<PathBuf>,
    manifest: Option<PathBuf>,
    vectors_root: Option<PathBuf>,
    obligation_rules: Option<PathBuf>,
    specification: Option<PathBuf>,
    policy: Option<PathBuf>,
    api_policy: Option<PathBuf>,
    baseline: Option<PathBuf>,
    predecessor: Option<PathBuf>,
    governance_post_assembly: Option<PathBuf>,
    governance_pre_attestation: Option<PathBuf>,
    phase: Option<governance::Phase>,
    expected_artifact_digest: Option<String>,
    platform: Option<schema::ReleasePlatform>,
}

pub(crate) fn recognizes(arguments: &[OsString]) -> bool {
    arguments
        .first()
        .is_some_and(|argument| argument == "release")
}

pub(crate) fn run(arguments: &[OsString]) -> Result<String, String> {
    let command = arguments
        .get(1)
        .ok_or_else(usage)?
        .to_str()
        .ok_or_else(|| "release subcommand must be UTF-8".to_owned())?;
    let options = parse_options(crate::mutation::without_test_activation_suffix(
        &arguments[2..],
    )?)?;
    match command {
        "resolve" => event::resolve(required(options.output, "--output")?),
        "plan" => plan::create(
            required(options.resolution, "--resolution")?,
            required(options.repository_root, "--repository-root")?,
            required(options.output, "--output")?,
            required(options.report, "--report")?,
        ),
        "platform" => platform::run(
            required(options.platform, "--platform")?,
            required(options.plan, "--plan")?,
            required(options.conformance_plan, "--conformance-plan")?,
            required(options.repository_root, "--repository-root")?,
            required(options.oracle_source, "--oracle-source")?,
            required(options.output, "--output")?,
        ),
        "assemble" => assemble::run(
            required(options.plan, "--plan")?,
            required(options.conformance_plan, "--conformance-plan")?,
            required(options.input, "--input")?,
            required(options.output, "--output")?,
            required(options.report, "--report")?,
        ),
        "verify-bundle" => verify::bundle(
            required(options.plan, "--plan")?,
            required(options.conformance_plan, "--conformance-plan")?,
            required(options.input, "--input")?,
            required(options.report, "--report")?,
            required(options.protocol_projection, "--protocol-projection")?,
        ),
        "agree" => decision::agree(
            required(options.primary, "--primary")?,
            required(options.independent, "--independent")?,
            required(options.output, "--output")?,
        ),
        "protocol-digest" => decision::write_protocol_digest(
            required(options.protocol_projection, "--projection")?,
            required(options.obligation_rules, "--obligation-rules")?,
            required(options.specification, "--spec")?,
            required(options.output, "--output")?,
        ),
        "materialize-protocol-vectors" => materialize_protocol_vectors(options),
        "verify-vectors" => vectors::verify(vectors::VerifyOptions {
            manifest: required(options.manifest, "--manifest")?,
            vectors_root: required(options.vectors_root, "--vectors-root")?,
            protocol_projection: required(options.protocol_projection, "--protocol-projection")?,
            output: required(options.output, "--output")?,
        }),
        "verify-vector-registry" => vectors::verify_registry(vectors::RegistryOptions {
            manifest: required(options.manifest, "--manifest")?,
            output: required(options.output, "--output")?,
        }),
        "final-verify" => run_final_verification(options),
        "governance-snapshot" => run_governance_snapshot(options),
        "check-remote-state" => remote_state::check(
            &required(options.plan, "--plan")?,
            &required(options.report, "--report")?,
        ),
        "stage-attestations" => publish::stage_attestations(required(options.input, "--input")?),
        "publish" => publish::run(
            required(options.plan, "--plan")?,
            required(options.input, "--input")?,
            required(options.report, "--report")?,
        ),
        _ => Err(usage()),
    }
}

fn materialize_protocol_vectors(options: Options) -> Result<String, String> {
    vectors::materialize(vectors::MaterializeOptions {
        plan: required(options.plan, "--plan")?,
        conformance_plan: required(options.conformance_plan, "--conformance-plan")?,
        bundle: required(options.bundle, "--bundle")?,
        platform_input: required(options.platform_input, "--platform-input")?,
        manifest: required(options.manifest, "--manifest")?,
        protocol_projection: required(options.protocol_projection, "--protocol-projection")?,
        independent_verifier: required(options.independent_verifier, "--independent-verifier")?,
        governance_post_assembly: required(
            options.governance_post_assembly,
            "--governance-post-assembly",
        )?,
        governance_pre_attestation: required(
            options.governance_pre_attestation,
            "--governance-pre-attestation",
        )?,
        output: required(options.output, "--output")?,
    })
}

fn run_final_verification(options: Options) -> Result<String, String> {
    final_verify::run(final_verify::Options {
        plan: required(options.plan, "--plan")?,
        conformance_plan: required(options.conformance_plan, "--conformance-plan")?,
        bundle: required(options.bundle.or(options.input), "--bundle")?,
        independent_verifier: required(options.independent_verifier, "--independent-verifier")?,
        protocol_projection: required(options.protocol_projection, "--protocol-projection")?,
        expected_artifact_digest: required(
            options.expected_artifact_digest,
            "--expected-artifact-digest",
        )?,
        governance_post_assembly: required(
            options.governance_post_assembly,
            "--governance-post-assembly",
        )?,
        governance_pre_attestation: required(
            options.governance_pre_attestation,
            "--governance-pre-attestation",
        )?,
        output: required(options.output, "--output")?,
        report: required(options.report, "--report")?,
    })
}

fn run_governance_snapshot(options: Options) -> Result<String, String> {
    governance::snapshot(governance::SnapshotOptions {
        policy: required(options.policy, "--policy")?,
        api_policy: required(options.api_policy, "--api-policy")?,
        plan: required(options.plan, "--plan")?,
        baseline: options.baseline,
        predecessor: options.predecessor,
        phase: required(options.phase, "--phase")?,
        output: required(options.output, "--output")?,
        report: required(options.report, "--report")?,
    })
}

fn required<T>(value: Option<T>, name: &str) -> Result<T, String> {
    value.ok_or_else(|| format!("release command requires {name}"))
}

fn parse_options(arguments: &[OsString]) -> Result<Options, String> {
    let mut options = Options::default();
    let mut index = 0;
    while index < arguments.len() {
        let flag = arguments[index]
            .to_str()
            .ok_or_else(|| "release option name must be UTF-8".to_owned())?;
        index += 1;
        let value = arguments
            .get(index)
            .ok_or_else(|| format!("{flag} requires a value"))?;
        index += 1;
        match flag {
            "--output" => set_path(&mut options.output, value, flag)?,
            "--report" => set_path(&mut options.report, value, flag)?,
            "--resolution" => set_path(&mut options.resolution, value, flag)?,
            "--repository-root" => set_path(&mut options.repository_root, value, flag)?,
            "--oracle-source" => set_path(&mut options.oracle_source, value, flag)?,
            "--plan" => set_path(&mut options.plan, value, flag)?,
            "--conformance-plan" => set_path(&mut options.conformance_plan, value, flag)?,
            "--input" => set_path(&mut options.input, value, flag)?,
            "--bundle" => set_path(&mut options.bundle, value, flag)?,
            "--primary" => set_path(&mut options.primary, value, flag)?,
            "--independent" => set_path(&mut options.independent, value, flag)?,
            "--independent-verifier" => set_path(&mut options.independent_verifier, value, flag)?,
            "--protocol-projection" | "--projection" => {
                set_path(&mut options.protocol_projection, value, flag)?;
            }
            "--platform-input" => set_path(&mut options.platform_input, value, flag)?,
            "--manifest" => set_path(&mut options.manifest, value, flag)?,
            "--vectors-root" => set_path(&mut options.vectors_root, value, flag)?,
            "--obligation-rules" => set_path(&mut options.obligation_rules, value, flag)?,
            "--spec" => set_path(&mut options.specification, value, flag)?,
            "--policy" => set_path(&mut options.policy, value, flag)?,
            "--api-policy" => set_path(&mut options.api_policy, value, flag)?,
            "--baseline" => set_path(&mut options.baseline, value, flag)?,
            "--predecessor" => set_path(&mut options.predecessor, value, flag)?,
            "--governance-post-assembly" => {
                set_path(&mut options.governance_post_assembly, value, flag)?;
            }
            "--governance-pre-attestation" => {
                set_path(&mut options.governance_pre_attestation, value, flag)?;
            }
            "--phase" => {
                if options.phase.is_some() {
                    return Err(format!("{flag} was provided more than once"));
                }
                options.phase =
                    Some(governance::Phase::parse(value.to_str().ok_or_else(
                        || "governance phase must be UTF-8".to_owned(),
                    )?)?);
            }
            "--expected-artifact-digest" => set_string(
                &mut options.expected_artifact_digest,
                value,
                flag,
                "artifact digest",
            )?,
            "--platform" => {
                if options.platform.is_some() {
                    return Err(format!("{flag} was provided more than once"));
                }
                options.platform = Some(schema::ReleasePlatform::parse(
                    value
                        .to_str()
                        .ok_or_else(|| "platform ID must be UTF-8".to_owned())?,
                )?);
            }
            _ => return Err(format!("unknown release option {flag:?}")),
        }
    }
    Ok(options)
}

fn set_path(target: &mut Option<PathBuf>, value: &OsString, flag: &str) -> Result<(), String> {
    if target.is_some() {
        return Err(format!("{flag} was provided more than once"));
    }
    *target = Some(PathBuf::from(value));
    Ok(())
}

fn set_string(
    target: &mut Option<String>,
    value: &OsString,
    flag: &str,
    label: &str,
) -> Result<(), String> {
    if target.is_some() {
        return Err(format!("{flag} was provided more than once"));
    }
    *target = Some(
        value
            .to_str()
            .ok_or_else(|| format!("{label} must be UTF-8"))?
            .to_owned(),
    );
    Ok(())
}

fn usage() -> String {
    "usage: hell-ci release resolve|plan|platform|assemble|verify-bundle|agree|protocol-digest|materialize-protocol-vectors|verify-vectors|verify-vector-registry|final-verify|governance-snapshot|check-remote-state|stage-attestations|publish [options]".to_owned()
}
