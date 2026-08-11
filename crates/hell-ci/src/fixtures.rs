use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::command::{CommandResult, CommandSpec};
use crate::policy::normalized_relative_path;
use crate::report::Report;

const FIXTURE_DIRECTORY: &str = "fixtures/upstream-2026-05-29";
const HEADER: &str =
    "id\tpath\tcheck_timeout_ms\trun_kind\trun_timeout_ms\tstdout_path\tstderr_path\tplatforms";
const EXPECTED_CASES: usize = 44;
const FAILURE_LIMIT: usize = 32;
const UPSTREAM_COMMIT: &str = "d4d028609ed46a560c62caea8c70e7e91d1afd29";
const LANGUAGE_VERSION: &str = "2026-05-29";
const SOURCE_SHA256: &str = "6b59dbbdaaa1e31938e8cbdf93ffb2b981fe8064009693f92fbdd134f7dd25f9";

static SANDBOX_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug)]
struct Case {
    id: String,
    path: PathBuf,
    check_timeout: Duration,
    run_kind: RunKind,
    run_timeout: Duration,
    stdout_path: Option<PathBuf>,
    stderr_path: Option<PathBuf>,
    platforms: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RunKind {
    CheckOnly,
    Exact,
}

pub fn validate_inventory(root: &Path) -> Result<(), String> {
    let fixture_root = root.join(FIXTURE_DIRECTORY);
    let cases = load_cases(&fixture_root)?;
    let example_paths = collect_hell_files(&fixture_root.join("examples"))?;
    let referenced = cases
        .iter()
        .map(|case| case.path.clone())
        .collect::<BTreeSet<_>>();
    if example_paths != referenced {
        return Err(format!(
            "fixture examples differ from manifest: files={example_paths:?}, manifest={referenced:?}"
        ));
    }
    let tracked = tracked_fixture_files(root)?;
    for required in ["LICENSE", "NOTICE", "cases.tsv"] {
        let relative = Path::new(FIXTURE_DIRECTORY).join(required);
        if !tracked.contains(&relative) {
            return Err(format!(
                "fixture provenance file is not tracked: {required}"
            ));
        }
    }
    for case in &cases {
        for path in [
            Some(case.path.as_path()),
            case.stdout_path.as_deref(),
            case.stderr_path.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if !fixture_root.join(path).is_file() {
                return Err(format!(
                    "fixture case {} references missing {}",
                    case.id,
                    path.display()
                ));
            }
            if !tracked.contains(&Path::new(FIXTURE_DIRECTORY).join(path)) {
                return Err(format!(
                    "fixture case {} references untracked {}",
                    case.id,
                    path.display()
                ));
            }
        }
    }

    let baseline = fs::read_to_string(root.join("baseline.toml"))
        .map_err(|error| format!("cannot read baseline.toml: {error}"))?;
    let compatibility = fs::read_to_string(root.join("compat").join("upstream-2026-05-29.json"))
        .map_err(|error| format!("cannot read compatibility snapshot: {error}"))?;
    for expected in [UPSTREAM_COMMIT, LANGUAGE_VERSION, SOURCE_SHA256] {
        if !baseline.contains(expected) || !compatibility.contains(expected) {
            return Err(format!(
                "baseline and compatibility snapshot do not agree on {expected}"
            ));
        }
    }
    if !baseline.contains("example_count = 44")
        || !baseline.contains("unique_primitive_count = 355")
        || !baseline.contains("public_primitive_count = 345")
        || !baseline.contains("internal_primitive_count = 10")
        || !compatibility.contains("\"upstreamExamples\": 44")
        || !compatibility.contains("\"publicTerms\": 345")
        || !compatibility.contains("\"internalTerms\": 10")
        || !compatibility.contains("\"typeConstructors\": 31")
        || !compatibility.contains("\"classes\": 10")
        || !compatibility.contains("\"instances\": 98")
    {
        return Err("baseline or compatibility inventory counts changed".to_owned());
    }
    let notice = fs::read_to_string(fixture_root.join("NOTICE"))
        .map_err(|error| format!("cannot read fixture NOTICE: {error}"))?;
    for expected in [
        "https://github.com/chrisdone/hell",
        UPSTREAM_COMMIT,
        LANGUAGE_VERSION,
        SOURCE_SHA256,
    ] {
        if !notice.contains(expected) {
            return Err(format!("fixture NOTICE omits provenance value {expected}"));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
pub fn run_examples(
    root: &Path,
    profile: &str,
    report: &mut Report,
    failures_directory: &Path,
) -> Result<(), String> {
    validate_inventory(root)?;
    let fixture_root = root.join(FIXTURE_DIRECTORY);
    let cases = load_cases(&fixture_root)?;
    let executable_name = if cfg!(windows) { "hell.exe" } else { "hell" };
    let executable = root.join("target").join(profile).join(executable_name);
    let executable = fs::canonicalize(&executable)
        .map_err(|error| format!("cannot locate {}: {error}", executable.display()))?;
    let mut detailed_failures = 0;

    for case in cases {
        let sandbox = Sandbox::create(&case.id)?;
        let source_name = case
            .path
            .file_name()
            .ok_or_else(|| format!("case {} source has no filename", case.id))?;
        let source = sandbox.path.join(source_name);
        fs::copy(fixture_root.join(&case.path), &source)
            .map_err(|error| format!("cannot stage case {}: {error}", case.id))?;
        let initial_filesystem = snapshot_filesystem(&sandbox.path)?;
        let check = CommandSpec::new(executable.as_os_str(), case.check_timeout)
            .argument("--check")
            .argument(source.as_os_str())
            .current_directory(&sandbox.path);
        let result = run_and_record(
            report,
            format!("example-{}-check", case.id),
            &check,
            failures_directory,
            &case.id,
            &mut detailed_failures,
        )?;
        if result.status.success()
            && !result.timed_out
            && case.run_kind == RunKind::Exact
            && platform_selected(&case.platforms)
        {
            let run = CommandSpec::new(executable.as_os_str(), case.run_timeout)
                .argument(source.as_os_str())
                .current_directory(&sandbox.path);
            let result = run_and_record(
                report,
                format!("example-{}-exact", case.id),
                &run,
                failures_directory,
                &case.id,
                &mut detailed_failures,
            )?;
            let expected_stdout = expected_bytes(&fixture_root, case.stdout_path.as_deref())?;
            let expected_stderr = expected_bytes(&fixture_root, case.stderr_path.as_deref())?;
            if result.status.success()
                && !result.timed_out
                && (result.stdout != expected_stdout || result.stderr != expected_stderr)
            {
                let detail = format!("example {} exact output mismatch", case.id);
                report.check(
                    format!("example-{}-observation", case.id),
                    Duration::ZERO,
                    Err(detail),
                );
                if detailed_failures < FAILURE_LIMIT {
                    write_capture(
                        failures_directory,
                        &case.id,
                        "actual.stdout",
                        &result.stdout,
                    )?;
                    write_capture(
                        failures_directory,
                        &case.id,
                        "actual.stderr",
                        &result.stderr,
                    )?;
                    write_capture(
                        failures_directory,
                        &case.id,
                        "expected.stdout",
                        &expected_stdout,
                    )?;
                    write_capture(
                        failures_directory,
                        &case.id,
                        "expected.stderr",
                        &expected_stderr,
                    )?;
                }
                detailed_failures += 1;
            }
        }
        let final_filesystem = snapshot_filesystem(&sandbox.path)?;
        if initial_filesystem != final_filesystem {
            let detail = format!("example {} changed its sandbox filesystem", case.id);
            report.check(
                format!("example-{}-filesystem", case.id),
                Duration::ZERO,
                Err(detail),
            );
            if detailed_failures < FAILURE_LIMIT {
                write_capture(
                    failures_directory,
                    &case.id,
                    "filesystem.before",
                    format!("{initial_filesystem:#?}\n").as_bytes(),
                )?;
                write_capture(
                    failures_directory,
                    &case.id,
                    "filesystem.after",
                    format!("{final_filesystem:#?}\n").as_bytes(),
                )?;
            }
            detailed_failures += 1;
        }
    }
    if detailed_failures > FAILURE_LIMIT {
        report.failures.push(format!(
            "fixture failure detail cap reached; {} failures were not captured",
            detailed_failures - FAILURE_LIMIT
        ));
    }
    Ok(())
}

fn run_and_record(
    report: &mut Report,
    name: String,
    command: &CommandSpec,
    failures_directory: &Path,
    case_id: &str,
    failure_count: &mut usize,
) -> Result<CommandResult, String> {
    let result = command
        .run()
        .map_err(|error| format!("cannot run {name}: {error}"))?;
    if (!result.status.success() || result.timed_out) && *failure_count < FAILURE_LIMIT {
        write_capture(failures_directory, case_id, "stdout", &result.stdout)?;
        write_capture(failures_directory, case_id, "stderr", &result.stderr)?;
    }
    if !result.status.success() || result.timed_out {
        *failure_count += 1;
    }
    report.command(name, command, &result);
    Ok(result)
}

fn write_capture(directory: &Path, id: &str, suffix: &str, bytes: &[u8]) -> Result<(), String> {
    fs::create_dir_all(directory)
        .map_err(|error| format!("cannot create failure directory: {error}"))?;
    let name = [id, suffix].join(".");
    fs::write(directory.join(name), bytes)
        .map_err(|error| format!("cannot write failure capture: {error}"))
}

fn expected_bytes(root: &Path, path: Option<&Path>) -> Result<Vec<u8>, String> {
    path.map_or_else(
        || Ok(Vec::new()),
        |path| {
            fs::read(root.join(path))
                .map_err(|error| format!("cannot read expected output {}: {error}", path.display()))
        },
    )
}

fn load_cases(root: &Path) -> Result<Vec<Case>, String> {
    let text = fs::read_to_string(root.join("cases.tsv"))
        .map_err(|error| format!("cannot read cases.tsv: {error}"))?;
    let mut lines = text.lines();
    if lines.next() != Some(HEADER) {
        return Err("cases.tsv has an unexpected header".to_owned());
    }
    let cases = lines
        .enumerate()
        .map(|(index, line)| parse_case(index + 2, line))
        .collect::<Result<Vec<_>, _>>()?;
    if cases.len() != EXPECTED_CASES {
        return Err(format!(
            "expected {EXPECTED_CASES} fixture cases, found {}",
            cases.len()
        ));
    }
    let ids = cases.iter().map(|case| &case.id).collect::<BTreeSet<_>>();
    if ids.len() != cases.len() {
        return Err("cases.tsv contains duplicate IDs".to_owned());
    }
    Ok(cases)
}

fn parse_case(line_number: usize, line: &str) -> Result<Case, String> {
    let fields = line.split('\t').collect::<Vec<_>>();
    let [
        id,
        path,
        check_timeout,
        run_kind,
        run_timeout,
        stdout_path,
        stderr_path,
        platforms,
    ] = fields.as_slice()
    else {
        return Err(format!(
            "cases.tsv line {line_number} does not have eight fields"
        ));
    };
    if id.is_empty() {
        return Err(format!("cases.tsv line {line_number} has no ID"));
    }
    let run_kind = match *run_kind {
        "check-only" => RunKind::CheckOnly,
        "exact" => RunKind::Exact,
        value => return Err(format!("unknown run kind {value} at line {line_number}")),
    };
    let stdout_path = optional_path(stdout_path)?;
    let stderr_path = optional_path(stderr_path)?;
    if run_kind == RunKind::CheckOnly && (stdout_path.is_some() || stderr_path.is_some()) {
        return Err(format!("check-only case {id} has expected output"));
    }
    if run_kind == RunKind::CheckOnly && *run_timeout != "0" {
        return Err(format!("check-only case {id} has a run timeout"));
    }
    if run_kind == RunKind::Exact && stdout_path.is_none() && stderr_path.is_none() {
        return Err(format!("exact case {id} has no expected observation"));
    }
    if run_kind == RunKind::Exact && *run_timeout == "0" {
        return Err(format!("exact case {id} has no run timeout"));
    }
    if *check_timeout == "0" {
        return Err(format!("case {id} has no check timeout"));
    }
    let platforms = platforms.split(',').map(str::to_owned).collect::<Vec<_>>();
    if platforms
        .iter()
        .any(|value| !matches!(value.as_str(), "all" | "linux" | "macos" | "windows"))
    {
        return Err(format!("case {id} has an unknown platform"));
    }
    Ok(Case {
        id: (*id).to_owned(),
        path: normalized_relative_path(path)?,
        check_timeout: parse_timeout(check_timeout, line_number)?,
        run_kind,
        run_timeout: parse_timeout(run_timeout, line_number)?,
        stdout_path,
        stderr_path,
        platforms,
    })
}

fn optional_path(value: &str) -> Result<Option<PathBuf>, String> {
    if value == "-" {
        Ok(None)
    } else {
        normalized_relative_path(value).map(Some)
    }
}

fn parse_timeout(value: &str, line: usize) -> Result<Duration, String> {
    value
        .parse::<u64>()
        .map(Duration::from_millis)
        .map_err(|error| format!("invalid timeout at cases.tsv line {line}: {error}"))
}

fn collect_hell_files(directory: &Path) -> Result<BTreeSet<PathBuf>, String> {
    let mut files = BTreeSet::new();
    for entry in
        fs::read_dir(directory).map_err(|error| format!("cannot read fixture examples: {error}"))?
    {
        let entry = entry.map_err(|error| format!("cannot read fixture entry: {error}"))?;
        if entry.path().extension().and_then(|value| value.to_str()) == Some("hell") {
            files.insert(Path::new("examples").join(entry.file_name()));
        }
    }
    Ok(files)
}

fn tracked_fixture_files(root: &Path) -> Result<BTreeSet<PathBuf>, String> {
    let output = Command::new("git")
        .args(["ls-files", "-z", "--", FIXTURE_DIRECTORY])
        .current_dir(root)
        .output()
        .map_err(|error| format!("cannot discover tracked fixtures: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "cannot discover tracked fixtures: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
        .map(|record| {
            std::str::from_utf8(record)
                .map(PathBuf::from)
                .map_err(|_| "tracked fixture path is not UTF-8".to_owned())
        })
        .collect()
}

struct Sandbox {
    path: PathBuf,
}

impl Sandbox {
    fn create(id: &str) -> Result<Self, String> {
        let sequence = SANDBOX_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("hell-ci-{id}-{}-{sequence}", std::process::id()));
        fs::create_dir(&path)
            .map_err(|error| format!("cannot create sandbox {}: {error}", path.display()))?;
        Ok(Self { path })
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn snapshot_filesystem(root: &Path) -> Result<BTreeMap<PathBuf, Vec<u8>>, String> {
    let mut snapshot = BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)
            .map_err(|error| format!("cannot snapshot {}: {error}", directory.display()))?
        {
            let entry = entry.map_err(|error| format!("cannot read sandbox entry: {error}"))?;
            let file_type = entry
                .file_type()
                .map_err(|error| format!("cannot inspect sandbox entry: {error}"))?;
            if file_type.is_dir() {
                pending.push(entry.path());
            } else if file_type.is_file() {
                let relative = entry
                    .path()
                    .strip_prefix(root)
                    .map_err(|error| format!("sandbox path escaped root: {error}"))?
                    .to_path_buf();
                let contents = fs::read(entry.path())
                    .map_err(|error| format!("cannot read sandbox file: {error}"))?;
                snapshot.insert(relative, contents);
            } else {
                return Err(format!(
                    "sandbox contains unsupported entry {}",
                    entry.path().display()
                ));
            }
        }
    }
    Ok(snapshot)
}

fn platform_selected(platforms: &[String]) -> bool {
    let current = if cfg!(windows) {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    };
    platforms
        .iter()
        .any(|platform| platform == "all" || platform == current)
}

pub fn timed_check(report: &mut Report, root: &Path) {
    let started = Instant::now();
    let result = validate_inventory(root);
    report.check("fixture-inventory", started.elapsed(), result);
}

pub fn profile_argument(profile: &str) -> Result<OsString, String> {
    match profile {
        "ci" | "release" => Ok(OsString::from(profile)),
        _ => Err(format!("profile must be ci or release, got {profile}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_has_exactly_the_pinned_cases() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
        validate_inventory(&root).unwrap();
    }

    #[test]
    fn only_known_profiles_are_accepted() {
        assert!(profile_argument("ci").is_ok());
        assert!(profile_argument("release").is_ok());
        assert!(profile_argument("debug").is_err());
    }

    #[test]
    fn exact_case_can_use_dash_for_an_expected_empty_stream() {
        let line = "01\texamples/01.hell\t5000\texact\t5000\texpected/01.stdout\t-\tall";
        let case = parse_case(2, line).unwrap();
        assert!(case.stdout_path.is_some());
        assert!(case.stderr_path.is_none());
    }

    #[test]
    fn manifest_semantics_reject_zero_and_unknown_values() {
        assert!(parse_case(2, "01\texamples/01.hell\t0\tcheck-only\t0\t-\t-\tall").is_err());
        assert!(parse_case(2, "01\texamples/01.hell\t1\texact\t0\texpected/o\t-\tall").is_err());
        assert!(parse_case(2, "01\texamples/01.hell\t1\tcheck-only\t0\t-\t-\tplan9").is_err());
    }
}
