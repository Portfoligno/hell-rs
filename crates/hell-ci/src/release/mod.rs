#![allow(clippy::all)]

mod archive;
pub(crate) mod assemble;
mod event;
mod github;
pub(crate) mod manifest;
pub(crate) mod plan;
pub(crate) mod platform;
mod publish;
mod remote_state;
pub(crate) mod schema;
mod verify;

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
    platform: Option<schema::ReleasePlatform>,
    required_gates: Option<String>,
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
    let options = parse_options(&arguments[2..])?;
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
            required(options.required_gates, "--required-gates")?,
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
        ),
        "check-remote-state" => remote_state::check(
            required(options.plan, "--plan")?,
            required(options.report, "--report")?,
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
            "--required-gates" => {
                if options.required_gates.is_some() {
                    return Err(format!("{flag} was provided more than once"));
                }
                options.required_gates = Some(
                    value
                        .to_str()
                        .ok_or_else(|| "required gate inventory must be UTF-8".to_owned())?
                        .to_owned(),
                );
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

fn usage() -> String {
    "usage: hell-ci release resolve|plan|platform|assemble|verify-bundle|check-remote-state|stage-attestations|publish [options]".to_owned()
}
