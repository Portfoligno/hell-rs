use std::fs;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use hell_compiler::{CompileOptions, CompilerSession};
use hell_source::{SourceMap, SourceName};
use hell_testkit::{DeterministicBytes, DeterministicUtf8, release_gate};

use crate::command::CommandSpec;
use crate::fixtures;
use crate::policy;
use crate::report::Report;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureKind {
    Policy,
    Child,
    Fixture,
    Io,
}

pub fn policy_suite(root: &Path, report: &mut Report) -> Result<(), FailureKind> {
    let started = Instant::now();
    let result = policy::check_repository(root);
    let passed = result.is_ok();
    report.check("repository-policy", started.elapsed(), result);
    passed.then_some(()).ok_or(FailureKind::Policy)
}

pub fn verify(root: &Path, report: &mut Report, failures: &Path) -> Result<(), FailureKind> {
    policy_suite(root, report)?;
    if !run_command(
        root,
        report,
        failures,
        "format",
        cargo(Duration::from_mins(5), ["fmt", "--all", "--", "--check"]),
    ) {
        return Err(FailureKind::Child);
    }
    if !run_command(
        root,
        report,
        failures,
        "clippy",
        cargo(
            Duration::from_mins(15),
            [
                "clippy",
                "--workspace",
                "--all-targets",
                "--all-features",
                "--locked",
                "--profile",
                "ci",
                "--",
                "-D",
                "warnings",
            ],
        ),
    ) {
        return Err(FailureKind::Child);
    }
    if !workspace_tests(root, report, failures, "ci") {
        return Err(FailureKind::Child);
    }
    if !build_candidate(root, report, failures, "ci") {
        return Err(FailureKind::Child);
    }
    run_fixture_gates(root, report, failures, "ci")
}

pub fn portability(root: &Path, report: &mut Report, failures: &Path) -> Result<(), FailureKind> {
    if !workspace_tests(root, report, failures, "ci") {
        return Err(FailureKind::Child);
    }
    if !build_candidate(root, report, failures, "ci") {
        return Err(FailureKind::Child);
    }
    run_fixture_gates(root, report, failures, "ci")
}

pub fn nightly(root: &Path, report: &mut Report, failures: &Path) -> Result<(), FailureKind> {
    if !workspace_tests(root, report, failures, "release") {
        return Err(FailureKind::Child);
    }
    if !build_candidate(root, report, failures, "release") {
        return Err(FailureKind::Child);
    }
    run_fixture_gates(root, report, failures, "release")?;

    for repetition in 1..=3 {
        if !run_command(
            root,
            report,
            failures,
            &format!("runtime-effects-repetition-{repetition}"),
            cargo(
                Duration::from_mins(15),
                [
                    "test",
                    "--release",
                    "--package",
                    "hell-runtime",
                    "--all-targets",
                    "--locked",
                    "--",
                    "--test-threads",
                    "1",
                ],
            ),
        ) {
            return Err(FailureKind::Child);
        }
    }

    let runtime_observations = generated_runtime_cases(root, report, failures)?;

    let started = Instant::now();
    let stress = deterministic_stress(failures);
    let stress_passed = stress.is_ok();
    let stress_observations = stress.as_ref().copied().unwrap_or_default();
    report.check(
        "deterministic-stress",
        started.elapsed(),
        stress.map(|_| ()),
    );
    if !stress_passed {
        return Err(FailureKind::Fixture);
    }

    let started = Instant::now();
    let observations = stress_observations + runtime_observations;
    let gate = release_gate(observations, 1_024, &[]);
    let gate_result = gate.passed().then_some(()).ok_or_else(|| {
        format!(
            "release gate failed: cases={}, unexplained={}, rust bugs={}",
            gate.cases_run, gate.unexplained_mismatches, gate.rust_bug_mismatches
        )
    });
    let gate_passed = gate_result.is_ok();
    report.check("release-gate", started.elapsed(), gate_result);
    gate_passed.then_some(()).ok_or(FailureKind::Fixture)
}

pub fn examples(
    root: &Path,
    report: &mut Report,
    failures: &Path,
    profile: &str,
) -> Result<(), FailureKind> {
    fixtures::profile_argument(profile).map_err(|detail| {
        report.check("profile", Duration::ZERO, Err(detail));
        FailureKind::Fixture
    })?;
    if !build_candidate(root, report, failures, profile) {
        return Err(FailureKind::Child);
    }
    run_fixture_gates(root, report, failures, profile)
}

fn workspace_tests(root: &Path, report: &mut Report, failures: &Path, profile: &str) -> bool {
    let release = profile == "release";
    let mut target_arguments = vec!["test"];
    if release {
        target_arguments.push("--release");
    }
    target_arguments.extend(["--workspace", "--all-targets", "--all-features", "--locked"]);
    if !release {
        target_arguments.extend(["--profile", "ci"]);
    }
    if !run_command(
        root,
        report,
        failures,
        "workspace-tests",
        cargo(Duration::from_mins(20), target_arguments),
    ) {
        return false;
    }

    let mut doc_arguments = vec!["test"];
    if release {
        doc_arguments.push("--release");
    }
    doc_arguments.extend(["--workspace", "--doc", "--all-features", "--locked"]);
    if !release {
        doc_arguments.extend(["--profile", "ci"]);
    }
    run_command(
        root,
        report,
        failures,
        "documentation-tests",
        cargo(Duration::from_mins(15), doc_arguments),
    )
}

fn build_candidate(root: &Path, report: &mut Report, failures: &Path, profile: &str) -> bool {
    let mut arguments = vec!["build"];
    if profile == "release" {
        arguments.push("--release");
    }
    arguments.extend(["--package", "hell-cli", "--bin", "hell", "--locked"]);
    if profile != "release" {
        arguments.extend(["--profile", profile]);
    }
    run_command(
        root,
        report,
        failures,
        "build-candidate",
        cargo(Duration::from_mins(15), arguments),
    )
}

fn run_fixture_gates(
    root: &Path,
    report: &mut Report,
    failures: &Path,
    profile: &str,
) -> Result<(), FailureKind> {
    fixtures::timed_check(report, root);
    if !report.passed() {
        return Err(FailureKind::Fixture);
    }
    if let Err(detail) = fixtures::run_examples(root, profile, report, failures) {
        let kind = if detail.starts_with("cannot run example-") {
            FailureKind::Child
        } else if detail.starts_with("cannot ") {
            FailureKind::Io
        } else {
            FailureKind::Fixture
        };
        report.check("examples", Duration::ZERO, Err(detail));
        return Err(kind);
    }
    if report.has_failed_command() {
        Err(FailureKind::Child)
    } else {
        report.passed().then_some(()).ok_or(FailureKind::Fixture)
    }
}

fn cargo<'a>(timeout: Duration, arguments: impl IntoIterator<Item = &'a str>) -> CommandSpec {
    CommandSpec::new("cargo", timeout).arguments(arguments)
}

fn run_command(
    root: &Path,
    report: &mut Report,
    failures: &Path,
    name: &str,
    command: CommandSpec,
) -> bool {
    let command = if command.current_directory.is_some() {
        command
    } else {
        command.current_directory(root)
    };
    match command.run() {
        Ok(result) => {
            let passed = result.status.success() && !result.timed_out;
            if !passed {
                let _ = fs::create_dir_all(failures);
                let _ = fs::write(failures.join(format!("{name}.stdout")), &result.stdout);
                let _ = fs::write(failures.join(format!("{name}.stderr")), &result.stderr);
            }
            report.command(name, &command, &result);
            passed
        }
        Err(error) => {
            report.check(
                name,
                Duration::ZERO,
                Err(format!(
                    "could not execute {}: {error}",
                    command.display_program()
                )),
            );
            false
        }
    }
}

fn deterministic_stress(failures_directory: &Path) -> Result<usize, String> {
    const SEEDS: [u64; 2] = [0xc0de_2026, 0x5eed_2026];
    const FAILURE_CAP: usize = 32;
    let mut observations = 0;
    let mut failures = Vec::new();
    'seeds: for seed in SEEDS {
        for (index, bytes) in DeterministicBytes::new(seed, 4_096, 4_096).enumerate() {
            observations += 1;
            let outcome = catch_unwind(AssertUnwindSafe(|| {
                let mut sources = SourceMap::new();
                let _ = sources.add_bytes(
                    SourceName::Virtual(format!("bytes-{seed}-{index}").into()),
                    bytes.clone(),
                );
            }));
            if outcome.is_err() && failures.len() < FAILURE_CAP {
                fs::create_dir_all(failures_directory)
                    .map_err(|error| format!("cannot create stress failure directory: {error}"))?;
                fs::write(
                    failures_directory.join(format!("stress-bytes-{seed}-{index}.input")),
                    bytes,
                )
                .map_err(|error| format!("cannot write stress failure input: {error}"))?;
                failures.push(format!("seed {seed}, case {index}, phase source-bytes"));
                if failures.len() >= FAILURE_CAP {
                    break 'seeds;
                }
            }
        }
        for (index, text) in DeterministicUtf8::new(seed, 4_096, 4_096).enumerate() {
            observations += 1;
            let outcome = catch_unwind(AssertUnwindSafe(|| {
                let mut sources = SourceMap::new();
                let source = sources.add_text(format!("utf8-{seed}-{index}"), text.clone());
                let _ = hell_syntax::parse(&source);
                let mut compiler = CompilerSession {
                    options: CompileOptions {
                        max_expansion_depth: Some(64),
                        max_elaborated_nodes: Some(65_536),
                    },
                    ..CompilerSession::default()
                };
                let _ = hell_compiler::compile_source(
                    &mut compiler,
                    format!("utf8-{seed}-{index}"),
                    source.text.clone(),
                );
            }));
            if outcome.is_err() && failures.len() < FAILURE_CAP {
                fs::create_dir_all(failures_directory)
                    .map_err(|error| format!("cannot create stress failure directory: {error}"))?;
                fs::write(
                    failures_directory.join(format!("stress-utf8-{seed}-{index}.input")),
                    text.as_bytes(),
                )
                .map_err(|error| format!("cannot write stress failure input: {error}"))?;
                failures.push(format!("seed {seed}, case {index}, phase parse-compile"));
                if failures.len() >= FAILURE_CAP {
                    break 'seeds;
                }
            }
        }
    }
    if failures.is_empty() {
        Ok(observations)
    } else {
        Err(format!(
            "deterministic stress panicked in {} cases: {}",
            failures.len(),
            failures.join("; ")
        ))
    }
}

fn generated_runtime_cases(
    root: &Path,
    report: &mut Report,
    failures: &Path,
) -> Result<usize, FailureKind> {
    const CASES: usize = 256;
    const FAILURE_CAP: usize = 32;
    let executable_name = if cfg!(windows) { "hell.exe" } else { "hell" };
    let executable = fs::canonicalize(root.join("target/release").join(executable_name))
        .map_err(|_| FailureKind::Io)?;
    let sandbox = RuntimeSandbox::create().map_err(|_| FailureKind::Io)?;
    let source = sandbox.path.join("generated.hell");
    let mut observations = 0;
    let mut failures_seen = 0;
    for index in 0..CASES {
        let program =
            format!("-- deterministic runtime case {index}\nmain = IO.print $ Int.plus {index} 1\n");
        fs::write(&source, program).map_err(|_| FailureKind::Io)?;
        observations += 1;
        let passed = run_command(
            root,
            report,
            failures,
            &format!("generated-runtime-{index}"),
            CommandSpec::new(executable.as_os_str(), Duration::from_secs(5))
                .argument(source.as_os_str())
                .current_directory(&sandbox.path),
        );
        if !passed {
            failures_seen += 1;
            if failures_seen >= FAILURE_CAP {
                break;
            }
        }
    }
    if failures_seen == 0 {
        Ok(observations)
    } else {
        Err(FailureKind::Child)
    }
}

struct RuntimeSandbox {
    path: PathBuf,
}

impl RuntimeSandbox {
    fn create() -> std::io::Result<Self> {
        let path = std::env::temp_dir().join(format!("hell-ci-runtime-{}", std::process::id()));
        if path.exists() {
            fs::remove_dir_all(&path)?;
        }
        fs::create_dir(&path)?;
        Ok(Self { path })
    }
}

impl Drop for RuntimeSandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

pub fn failures_directory(report_path: &Path) -> PathBuf {
    report_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("failures")
}
