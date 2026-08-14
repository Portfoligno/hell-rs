use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use hell_builtins::ExecutionProfile;
use hell_compiler::{CompilerSession, DiagnosticBundle, compile_file};
use hell_core::VerifiedProgram;

enum Command {
    Help,
    Version,
    BuildInfo,
    Check {
        file: PathBuf,
        compiler_stats: bool,
        profile: ExecutionProfile,
    },
    Run {
        file: PathBuf,
        arguments: Vec<OsString>,
        profile: ExecutionProfile,
        evidence: EvidenceOptions,
    },
}

#[derive(Default)]
struct EvidenceOptions {
    resource_audit: Option<PathBuf>,
    semantic_trace: Option<PathBuf>,
    typed_result_builtin: Option<hell_builtins::BuiltinId>,
    typed_result_instance: Option<Arc<str>>,
}

impl EvidenceOptions {
    fn is_empty(&self) -> bool {
        self.resource_audit.is_none()
            && self.semantic_trace.is_none()
            && self.typed_result_builtin.is_none()
            && self.typed_result_instance.is_none()
    }
}

enum RunFailure {
    Message(String),
    Exit(i32),
}

fn usage() -> &'static str {
    "hell - A Haskell-driven scripting language\n\nUsage: hell [FILE | --check FILE | --version]\n\n  Runs and typechecks Hell scripts\n\nAvailable options:\n  FILE                     Run the given .hell file\n  --check FILE             Typecheck the given .hell file\n  --version                Print the version\n  -h,--help                Show this help text"
}

fn usage_summary() -> &'static str {
    "Usage: hell [FILE | --check FILE | --version]\n\n  Runs and typechecks Hell scripts"
}

#[allow(clippy::too_many_lines)]
fn parse(arguments: impl IntoIterator<Item = OsString>) -> Result<Command, String> {
    let mut arguments = arguments.into_iter().peekable();
    let evidence = parse_evidence_options(&mut arguments)?;
    let profile = parse_execution_profile(&mut arguments)?;
    let Some(first) = arguments.next() else {
        if !evidence.is_empty() {
            return Err("evidence options require a script".to_owned());
        }
        if profile != ExecutionProfile::Upstream {
            return Err("--execution-profile requires a script or --check".into());
        }
        return Ok(Command::Version);
    };
    if !first.to_string_lossy().starts_with('-') {
        return Ok(Command::Run {
            file: first.into(),
            arguments: arguments.collect(),
            profile,
            evidence,
        });
    }

    let remaining = arguments.collect::<Vec<_>>();
    if first == "--help"
        || first == "-h"
        || remaining
            .iter()
            .any(|option| option == "--help" || option == "-h")
    {
        if !evidence.is_empty() {
            return Err("evidence options require a script".to_owned());
        }
        return Ok(Command::Help);
    }
    if first == "--" {
        let mut remaining = remaining.into_iter();
        let Some(file) = remaining.next() else {
            if !evidence.is_empty() || profile != ExecutionProfile::Upstream {
                return Err("evidence and execution profile options require a script".to_owned());
            }
            return Ok(Command::Version);
        };
        return Ok(Command::Run {
            file: file.into(),
            arguments: remaining.collect(),
            profile,
            evidence,
        });
    }

    let mut options = std::iter::once(first).chain(remaining);
    let mut check = None;
    let mut compiler_stats = false;
    let mut terminal = None;
    while let Some(option) = options.next() {
        if option == "--check" {
            if check.is_some() {
                return Err("--check was provided more than once".into());
            }
            check = Some(
                options
                    .next()
                    .ok_or_else(|| {
                        format!(
                            "The option `--check` expects an argument.\n\n{}",
                            usage_summary()
                        )
                    })?
                    .into(),
            );
        } else if option == "--compiler-stats" {
            compiler_stats = true;
        } else if option == "--version" {
            terminal = Some(Command::Version);
        } else if option == "--build-info" {
            terminal = Some(Command::BuildInfo);
        } else if let Some(value) = option
            .to_str()
            .and_then(|value| value.strip_prefix("--check="))
        {
            if check.replace(PathBuf::from(value)).is_some() {
                return Err("--check was provided more than once".into());
            }
        } else {
            let argument = option.to_string_lossy();
            let message = if argument.starts_with('-') {
                format!("Invalid option `{argument}'")
            } else {
                format!("Invalid argument `{argument}'")
            };
            return Err(format!("{message}\n\n{}", usage_summary()));
        }
    }
    if let Some(command) = terminal {
        if check.is_some()
            || compiler_stats
            || profile != ExecutionProfile::Upstream
            || !evidence.is_empty()
        {
            return Err("help, version, and build info do not accept other options".into());
        }
        return Ok(command);
    }
    let file = check.ok_or_else(|| format!("Missing: --check FILE\n\n{}", usage_summary()))?;
    if !evidence.is_empty() {
        return Err("evidence options require execution, not --check".to_owned());
    }
    Ok(Command::Check {
        file,
        compiler_stats,
        profile,
    })
}

fn parse_evidence_options(
    arguments: &mut std::iter::Peekable<impl Iterator<Item = OsString>>,
) -> Result<EvidenceOptions, String> {
    let mut options = EvidenceOptions::default();
    loop {
        let flag = match arguments.peek().and_then(|value| value.to_str()) {
            Some("--evidence-resource-audit") => "--evidence-resource-audit",
            Some("--evidence-semantic-trace") => "--evidence-semantic-trace",
            _ => break,
        };
        let slot = if flag == "--evidence-resource-audit" {
            &mut options.resource_audit
        } else {
            &mut options.semantic_trace
        };
        arguments.next();
        if slot.is_some() {
            return Err(format!("{flag} was provided more than once"));
        }
        *slot = Some(PathBuf::from(
            arguments
                .next()
                .ok_or_else(|| format!("{flag} requires a path"))?,
        ));
    }
    if arguments.peek().and_then(|value| value.to_str()) == Some("--evidence-typed-result-builtin")
    {
        arguments.next();
        let name = arguments
            .next()
            .ok_or_else(|| "--evidence-typed-result-builtin requires a registry name".to_owned())?
            .into_string()
            .map_err(|_| "evidence builtin name must be UTF-8".to_owned())?;
        options.typed_result_builtin = Some(
            hell_builtins::lookup(&name)
                .ok_or_else(|| format!("unknown evidence builtin {name:?}"))?
                .id,
        );
        if arguments.peek().and_then(|value| value.to_str())
            == Some("--evidence-typed-result-builtin")
        {
            return Err("--evidence-typed-result-builtin was provided more than once".to_owned());
        }
    }
    if arguments.peek().and_then(|value| value.to_str()) == Some("--evidence-typed-result-instance")
    {
        arguments.next();
        let instance = arguments
            .next()
            .ok_or_else(|| "--evidence-typed-result-instance requires a target".to_owned())?
            .into_string()
            .map_err(|_| "evidence instance target must be UTF-8".to_owned())?;
        let builtin = options.typed_result_builtin.ok_or_else(|| {
            "typed result instance evidence requires a typed result builtin".to_owned()
        })?;
        let class = hell_builtins::registry()[usize::from(builtin.0)]
            .type_class
            .ok_or_else(|| "unconstrained typed result builtin rejects an instance".to_owned())?;
        if hell_builtins::instance(class, &instance).is_none() {
            return Err("typed result instance is not registry-backed".to_owned());
        }
        options.typed_result_instance = Some(Arc::from(instance));
        if arguments.peek().and_then(|value| value.to_str())
            == Some("--evidence-typed-result-instance")
        {
            return Err("--evidence-typed-result-instance was provided more than once".to_owned());
        }
    }
    if options.typed_result_builtin.is_some() && options.semantic_trace.is_none() {
        return Err("typed result evidence requires a semantic trace path".to_owned());
    }
    Ok(options)
}

fn parse_execution_profile(
    arguments: &mut std::iter::Peekable<impl Iterator<Item = OsString>>,
) -> Result<ExecutionProfile, String> {
    let Some(first) = arguments.peek() else {
        return Ok(ExecutionProfile::Upstream);
    };
    let value = if first == "--execution-profile" {
        arguments.next();
        arguments
            .next()
            .ok_or_else(|| "--execution-profile requires upstream or sandboxed".to_owned())?
            .into_string()
            .map_err(|_| "execution profile must be UTF-8".to_owned())?
    } else if let Some(value) = first
        .to_str()
        .and_then(|value| value.strip_prefix("--execution-profile="))
    {
        let value = value.to_owned();
        arguments.next();
        value
    } else {
        return Ok(ExecutionProfile::Upstream);
    };
    match value.as_str() {
        "upstream" => Ok(ExecutionProfile::Upstream),
        "sandboxed" => Ok(ExecutionProfile::Sandboxed),
        _ => Err(format!("unknown execution profile {value:?}")),
    }
}

fn run(command: Command) -> Result<(), RunFailure> {
    match command {
        Command::Help => {
            println!("{}", usage());
            Ok(())
        }
        Command::Version => {
            println!("{}", hell_builtins::LANGUAGE_VERSION);
            Ok(())
        }
        Command::BuildInfo => {
            println!("hell-rs {}", env!("CARGO_PKG_VERSION"));
            println!("language baseline {}", hell_builtins::LANGUAGE_VERSION);
            println!("upstream {}", hell_builtins::UPSTREAM_COMMIT);
            println!("compatibility evidence schema 2");
            println!(
                "compat tracing enabled {}",
                cfg!(feature = "compat-tracing")
            );
            println!(
                "compiler policy {:?}",
                hell_compiler::CompilerConfig::upstream()
            );
            println!(
                "runtime policy {:?}",
                hell_runtime::policy::RuntimePolicy::upstream()
            );
            Ok(())
        }
        Command::Check {
            file,
            compiler_stats,
            profile,
        } => compile_path(&file, compiler_stats, profile)
            .map(|_| ())
            .map_err(RunFailure::Message),
        Command::Run {
            file,
            arguments,
            profile,
            evidence,
        } => {
            let program = compile_path(&file, false, profile).map_err(RunFailure::Message)?;
            let mut platform = hell_platform::PlatformContext::process(arguments)
                .map_err(|error| RunFailure::Message(error.to_string()))?;
            if profile == ExecutionProfile::Sandboxed {
                platform.runtime = platform
                    .runtime
                    .with_policy(hell_runtime::policy::RuntimePolicy::sandboxed());
            }
            #[cfg(feature = "compat-tracing")]
            let outcome = hell_runtime::run_main_with_evidence(
                program,
                platform.runtime,
                evidence.resource_audit.as_deref(),
                evidence.semantic_trace.as_deref(),
                evidence.typed_result_builtin,
                evidence.typed_result_instance,
            );
            #[cfg(not(feature = "compat-tracing"))]
            let outcome = {
                if evidence.semantic_trace.is_some()
                    || evidence.typed_result_builtin.is_some()
                    || evidence.typed_result_instance.is_some()
                {
                    return Err(RunFailure::Message(
                        "semantic evidence requires the compat-tracing feature".to_owned(),
                    ));
                }
                hell_runtime::run_main_with_resource_audit(
                    program,
                    platform.runtime,
                    evidence.resource_audit.as_deref(),
                )
            };
            outcome.map_err(|error| match error.kind {
                hell_runtime::RuntimeErrorKind::Exit(status) => RunFailure::Exit(status),
                _ => RunFailure::Message(error.to_string()),
            })
        }
    }
}

fn compile_path(
    file: &std::path::Path,
    compiler_stats: bool,
    profile: ExecutionProfile,
) -> Result<VerifiedProgram, String> {
    let mut session = match profile {
        ExecutionProfile::Upstream => CompilerSession::upstream(),
        ExecutionProfile::Sandboxed => CompilerSession::default(),
    };
    if compiler_stats {
        session.enable_stats();
    }
    let result = compile_file(&mut session, file);
    if compiler_stats {
        print_compiler_stats(&session.stats);
    }
    result.map_err(|diagnostics| render_diagnostics(&session, &diagnostics))
}

fn print_compiler_stats(stats: &hell_compiler::CompilerStats) {
    for timing in &stats.timings {
        let indentation = "  ".repeat(usize::from(timing.depth));
        println!(
            "{indentation}stat: {} = {:.9}s",
            timing.label,
            timing.elapsed.as_secs_f64()
        );
    }
}

fn render_diagnostics(session: &CompilerSession, diagnostics: &DiagnosticBundle) -> String {
    diagnostics
        .0
        .iter()
        .map(|diagnostic| {
            let Some(span) = diagnostic.span else {
                return diagnostic.to_string();
            };
            let Some(source) = session.sources.get(span.source) else {
                return diagnostic.to_string();
            };
            let Some((line, column)) = source.line_column(span.start) else {
                return diagnostic.to_string();
            };
            format!("{}:{line}:{column}: {diagnostic}", source.name)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn main() -> ExitCode {
    let command = match parse(std::env::args_os().skip(1)) {
        Ok(command) => command,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    match run(command) {
        Ok(()) | Err(RunFailure::Exit(0)) => ExitCode::SUCCESS,
        Err(RunFailure::Message(error)) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
        Err(RunFailure::Exit(status)) => ExitCode::from(u8::try_from(status).unwrap_or(1)),
    }
}

#[cfg(test)]
mod evidence_tests {
    use super::*;

    #[test]
    fn evidence_options_require_execution() {
        for arguments in [
            vec!["--evidence-resource-audit", "audit.json"],
            vec!["--evidence-resource-audit", "audit.json", "--"],
            vec!["--evidence-resource-audit", "audit.json", "--version"],
            vec![
                "--evidence-resource-audit",
                "audit.json",
                "--check",
                "input.hell",
            ],
        ] {
            assert!(parse(arguments.into_iter().map(OsString::from)).is_err());
        }
    }

    #[test]
    fn evidence_options_are_prefix_only_and_typed_target_is_unique() {
        assert!(
            parse(
                [
                    "--evidence-semantic-trace",
                    "trace.json",
                    "--evidence-typed-result-builtin",
                    "Bool.bool",
                    "--evidence-typed-result-builtin",
                    "Bool.bool",
                    "input.hell",
                ]
                .map(OsString::from),
            )
            .is_err()
        );
        assert!(
            parse(["input.hell", "--evidence-resource-audit", "audit.json"].map(OsString::from),)
                .is_ok()
        );
        let command = parse(
            [
                "--evidence-semantic-trace",
                "trace.json",
                "--evidence-typed-result-builtin",
                "Ord.lt",
                "--evidence-typed-result-instance",
                "Set",
                "input.hell",
            ]
            .map(OsString::from),
        )
        .expect("registry-backed instance evidence");
        let Command::Run { evidence, .. } = command else {
            panic!("evidence command was not a run");
        };
        assert_eq!(evidence.typed_result_instance.as_deref(), Some("Set"));
        for arguments in [
            vec![
                "--evidence-semantic-trace",
                "trace.json",
                "--evidence-typed-result-instance",
                "Set",
                "input.hell",
            ],
            vec![
                "--evidence-semantic-trace",
                "trace.json",
                "--evidence-typed-result-builtin",
                "Ord.lt",
                "--evidence-typed-result-instance",
                "Unknown",
                "input.hell",
            ],
        ] {
            assert!(parse(arguments.into_iter().map(OsString::from)).is_err());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Command, ExecutionProfile, parse, usage};
    use std::ffi::OsString;

    #[test]
    fn hidden_compiler_stats_is_accepted_with_check_in_either_order() {
        for arguments in [
            vec!["--check", "main.hell", "--compiler-stats"],
            vec!["--compiler-stats", "--check", "main.hell"],
            vec!["--check=main.hell", "--compiler-stats"],
        ] {
            let command = parse(arguments.into_iter().map(OsString::from)).unwrap();
            assert!(matches!(
                command,
                Command::Check {
                    compiler_stats: true,
                    ..
                }
            ));
        }
        assert!(!usage().contains("compiler-stats"));
    }

    #[test]
    fn run_parser_preserves_script_arguments_as_native_strings() {
        let argument = OsString::from("--guest-flag");
        let command = parse([OsString::from("main.hell"), argument.clone()]).unwrap();
        let Command::Run { arguments, .. } = command else {
            panic!("non-option first argument must select script execution");
        };
        assert_eq!(arguments, vec![argument]);
    }

    #[test]
    fn help_short_circuits_and_no_arguments_print_version() {
        assert!(matches!(
            parse([OsString::from("--help")]),
            Ok(Command::Help)
        ));
        assert!(matches!(
            parse(["--version", "--help"].map(OsString::from)),
            Ok(Command::Help)
        ));
        assert!(matches!(
            parse(Vec::<OsString>::new()),
            Ok(Command::Version)
        ));
        assert!(parse(["--compiler-stats"].map(OsString::from)).is_err());
    }

    #[test]
    fn option_separator_allows_a_dash_prefixed_script_path() {
        let command = parse(["--", "--script.hell", "argument"].map(OsString::from)).unwrap();
        let Command::Run {
            file, arguments, ..
        } = command
        else {
            panic!("the option separator must select script execution");
        };
        assert_eq!(file, std::path::PathBuf::from("--script.hell"));
        assert_eq!(arguments, vec![OsString::from("argument")]);
    }

    #[test]
    fn execution_profile_is_explicit_and_precedes_the_script_invocation() {
        let command = parse(
            [
                "--execution-profile=sandboxed",
                "--",
                "main.hell",
                "argument",
            ]
            .map(OsString::from),
        )
        .unwrap();
        let Command::Run {
            profile, arguments, ..
        } = command
        else {
            panic!("profiled invocation must select script execution");
        };
        assert_eq!(profile, ExecutionProfile::Sandboxed);
        assert_eq!(arguments, [OsString::from("argument")]);
        assert!(parse(["--execution-profile=unknown", "main.hell"].map(OsString::from)).is_err());
        assert!(parse(["--execution-profile=sandboxed", "--version"].map(OsString::from)).is_err());
    }
}
