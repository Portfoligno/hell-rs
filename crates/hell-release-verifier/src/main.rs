use std::ffi::{OsStr, OsString};
use std::path::PathBuf;
use std::process::ExitCode;

use hell_release_verifier::{self as verifier, VerifyOptions};

#[derive(Default)]
struct Options {
    plan: Option<PathBuf>,
    conformance_plan: Option<PathBuf>,
    bundle: Option<PathBuf>,
    protocol_projection: Option<PathBuf>,
    output: Option<PathBuf>,
    envelope: Option<PathBuf>,
    subject_root: Option<PathBuf>,
    expected_artifact_digest: Option<String>,
    governance_resolve: Option<PathBuf>,
    governance_post_assembly: Option<PathBuf>,
    governance_pre_attestation: Option<PathBuf>,
    manifest: Option<PathBuf>,
    vectors_root: Option<PathBuf>,
}

fn main() -> ExitCode {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    match run(&arguments) {
        Ok(message) => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run(arguments: &[OsString]) -> Result<String, String> {
    let command = arguments
        .first()
        .and_then(|value| value.to_str())
        .ok_or_else(usage)?;
    let options = parse_options(&arguments[1..])?;
    match command {
        "verify" => verifier::verify(VerifyOptions {
            plan: required(options.plan, "--plan")?,
            conformance_plan: required(options.conformance_plan, "--conformance-plan")?,
            bundle: required(options.bundle, "--bundle")?,
            protocol_projection: required(options.protocol_projection, "--protocol-projection")?,
            governance_resolve: Some(required(
                options.governance_resolve,
                "--governance-resolve",
            )?),
            governance_post_assembly: Some(required(
                options.governance_post_assembly,
                "--governance-post-assembly",
            )?),
            governance_pre_attestation: Some(required(
                options.governance_pre_attestation,
                "--governance-pre-attestation",
            )?),
            output: required(options.output, "--output")?,
        }),
        "verify-envelope" => verifier::verify_envelope(
            required(options.envelope, "--envelope")?,
            required(options.subject_root, "--subject-root")?,
            required(
                options.expected_artifact_digest,
                "--expected-artifact-digest",
            )?,
            required(options.output, "--output")?,
        ),
        "verify-vectors" => verifier::verify_vectors(
            required(options.manifest, "--manifest")?,
            required(options.vectors_root, "--vectors-root")?,
            required(options.protocol_projection, "--protocol-projection")?,
            required(options.output, "--output")?,
        ),
        _ => Err(usage()),
    }
}

fn parse_options(arguments: &[OsString]) -> Result<Options, String> {
    let mut options = Options::default();
    let mut index = 0;
    while index < arguments.len() {
        let flag = arguments[index]
            .to_str()
            .ok_or_else(|| "option name must be UTF-8".to_owned())?;
        let value = arguments
            .get(index + 1)
            .ok_or_else(|| format!("{flag} requires a value"))?;
        index += 2;
        match flag {
            "--plan" => set_path(&mut options.plan, value, flag)?,
            "--conformance-plan" => set_path(&mut options.conformance_plan, value, flag)?,
            "--bundle" => set_path(&mut options.bundle, value, flag)?,
            "--protocol-projection" => set_path(&mut options.protocol_projection, value, flag)?,
            "--output" => set_path(&mut options.output, value, flag)?,
            "--envelope" => set_path(&mut options.envelope, value, flag)?,
            "--subject-root" => set_path(&mut options.subject_root, value, flag)?,
            "--expected-artifact-digest" => {
                set_text(&mut options.expected_artifact_digest, value, flag)?;
            }
            "--governance-resolve" => set_path(&mut options.governance_resolve, value, flag)?,
            "--governance-post-assembly" => {
                set_path(&mut options.governance_post_assembly, value, flag)?;
            }
            "--governance-pre-attestation" => {
                set_path(&mut options.governance_pre_attestation, value, flag)?;
            }
            "--manifest" => set_path(&mut options.manifest, value, flag)?,
            "--vectors-root" => set_path(&mut options.vectors_root, value, flag)?,
            _ => return Err(format!("unknown verifier option {flag:?}")),
        }
    }
    Ok(options)
}

fn set_path(target: &mut Option<PathBuf>, value: &OsStr, flag: &str) -> Result<(), String> {
    if target.is_some() {
        return Err(format!("{flag} was provided more than once"));
    }
    *target = Some(PathBuf::from(value));
    Ok(())
}

fn set_text(target: &mut Option<String>, value: &OsStr, flag: &str) -> Result<(), String> {
    if target.is_some() {
        return Err(format!("{flag} was provided more than once"));
    }
    *target = Some(
        value
            .to_str()
            .ok_or_else(|| format!("{flag} must be UTF-8"))?
            .to_owned(),
    );
    Ok(())
}

fn required<T>(value: Option<T>, flag: &str) -> Result<T, String> {
    value.ok_or_else(|| format!("verifier command requires {flag}"))
}

fn usage() -> String {
    "usage: hell-release-verifier verify|verify-envelope|verify-vectors [options]".to_owned()
}
