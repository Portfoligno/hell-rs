mod action_metadata;
mod import;
mod load;
mod model;
mod projection;
mod render;
mod validate;

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::json::JsonValue;
use crate::release::manifest::write_json;
use model::Manifest;

#[derive(Default)]
struct Options {
    lock: Option<PathBuf>,
    manifest: Option<PathBuf>,
    repository_root: Option<PathBuf>,
    workflows: Option<PathBuf>,
    output: Option<PathBuf>,
    report: Option<PathBuf>,
}

pub(crate) fn recognizes(arguments: &[OsString]) -> bool {
    arguments.first().is_some_and(|value| value == "protocol")
}

pub(crate) fn run(arguments: &[OsString]) -> Result<String, String> {
    let command = arguments
        .get(1)
        .and_then(|value| value.to_str())
        .ok_or_else(usage)?;
    let options = parse_options(&arguments[2..])?;
    match command {
        "update-action-metadata" => action_metadata::update(
            &required(options.lock, "--lock")?,
            &required(options.output, "--output")?,
        ),
        "check" => check(
            &required(options.manifest, "--manifest")?,
            &required(options.repository_root, "--repository-root")?,
            &required(options.workflows, "--workflows")?,
            &required(options.report, "--report")?,
        ),
        "render" => render(
            &required(options.manifest, "--manifest")?,
            &required(options.repository_root, "--repository-root")?,
            &required(options.output, "--output")?,
        ),
        "import-steps" => import::steps(
            &required(options.manifest, "--manifest")?,
            &required(options.workflows, "--workflows")?,
            &required(options.output, "--output")?,
        ),
        "project" => projection::write(
            &required(options.manifest, "--manifest")?,
            &required(options.repository_root, "--repository-root")?,
            &required(options.output, "--output")?,
        ),
        _ => Err(usage()),
    }
}

fn check(
    manifest_path: &Path,
    repository_root: &Path,
    workflows: &Path,
    report: &Path,
) -> Result<String, String> {
    let result = Manifest::read(manifest_path)
        .and_then(|manifest| validate::workflows(&manifest, repository_root, workflows));
    let (state, diagnostics) = match &result {
        Ok(()) => ("passed", Vec::new()),
        Err(error) => ("blocked", vec![error.code.to_owned()]),
    };
    let report_value = object([
        (
            "diagnostics",
            JsonValue::Array(diagnostics.into_iter().map(JsonValue::String).collect()),
        ),
        ("manifest", JsonValue::String(display_path(manifest_path))),
        ("protocolId", JsonValue::String("hell-rs-ci-v1".to_owned())),
        ("schemaVersion", JsonValue::Number(1)),
        ("state", JsonValue::String(state.to_owned())),
        ("workflows", JsonValue::String(display_path(workflows))),
    ]);
    let persistence = write_json(report, &report_value).map(|_| ());
    match (result, persistence) {
        (Ok(()), Ok(())) => Ok(format!(
            "protocol workflows match {}",
            manifest_path.display()
        )),
        (Err(primary), Ok(())) => Err(primary.message),
        (Ok(()), Err(error)) => Err(format!(
            "protocol check passed but its report could not be written: {error}"
        )),
        (Err(primary), Err(persistence)) => Err(format!(
            "{}; protocol failure report could not be written: {persistence}",
            primary.message
        )),
    }
}

fn render(manifest_path: &Path, repository_root: &Path, output: &Path) -> Result<String, String> {
    let manifest = Manifest::read(manifest_path).map_err(|error| error.message)?;
    render::workflows(&manifest, repository_root, output).map_err(|error| error.message)?;
    Ok(format!(
        "rendered {} workflows from {}",
        manifest.workflows.len(),
        manifest_path.display()
    ))
}

pub(crate) fn repository_failures(repository_root: &Path) -> Vec<String> {
    let manifest = repository_root.join("ci/protocol/v1.toml");
    let workflows = repository_root.join(".github/workflows");
    match Manifest::read(&manifest)
        .and_then(|manifest| validate::workflows(&manifest, repository_root, &workflows))
    {
        Ok(()) => Vec::new(),
        Err(error) => vec![format!("{}: {}", error.code, error.message)],
    }
}

fn parse_options(arguments: &[OsString]) -> Result<Options, String> {
    let mut parsed = Options::default();
    let mut arguments = arguments.iter();
    while let Some(flag) = arguments.next() {
        let flag = flag
            .to_str()
            .ok_or_else(|| "protocol option name must be UTF-8".to_owned())?;
        let slot = match flag {
            "--lock" => &mut parsed.lock,
            "--manifest" => &mut parsed.manifest,
            "--repository-root" => &mut parsed.repository_root,
            "--workflows" => &mut parsed.workflows,
            "--output" => &mut parsed.output,
            "--report" => &mut parsed.report,
            _ => return Err(format!("unknown protocol option {flag}\n{}", usage())),
        };
        if slot.is_some() {
            return Err(format!("{flag} was provided more than once"));
        }
        *slot = Some(PathBuf::from(
            arguments
                .next()
                .ok_or_else(|| format!("{flag} requires PATH"))?,
        ));
    }
    Ok(parsed)
}

fn required<T>(value: Option<T>, name: &str) -> Result<T, String> {
    value.ok_or_else(|| format!("{name} is required\n{}", usage()))
}

fn usage() -> String {
    "usage: hell-ci protocol check --manifest PATH --repository-root PATH --workflows PATH --report PATH\n       hell-ci protocol render --manifest PATH --repository-root PATH --output PATH\n       hell-ci protocol project --manifest PATH --repository-root PATH --output PATH\n       hell-ci protocol import-steps --manifest PATH --workflows PATH --output PATH\n       hell-ci protocol update-action-metadata --lock PATH --output PATH".to_owned()
}

fn object<const N: usize>(members: [(&str, JsonValue); N]) -> JsonValue {
    JsonValue::Object(
        members
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value))
            .collect(),
    )
}

fn display_path(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}
