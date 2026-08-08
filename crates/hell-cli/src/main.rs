use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use hell_compiler::{CompilerSession, DiagnosticBundle, compile_file};
use hell_core::VerifiedProgram;

enum Command {
    Help,
    Version,
    BuildInfo,
    Check {
        file: PathBuf,
        compiler_stats: bool,
    },
    Run {
        file: PathBuf,
        arguments: Vec<OsString>,
    },
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

fn parse(arguments: impl IntoIterator<Item = OsString>) -> Result<Command, String> {
    let mut arguments = arguments.into_iter();
    let Some(first) = arguments.next() else {
        return Ok(Command::Version);
    };
    if !first.to_string_lossy().starts_with('-') {
        return Ok(Command::Run {
            file: first.into(),
            arguments: arguments.collect(),
        });
    }

    let remaining = arguments.collect::<Vec<_>>();
    if first == "--help"
        || first == "-h"
        || remaining
            .iter()
            .any(|option| option == "--help" || option == "-h")
    {
        return Ok(Command::Help);
    }
    if first == "--" {
        let mut remaining = remaining.into_iter();
        let Some(file) = remaining.next() else {
            return Ok(Command::Version);
        };
        return Ok(Command::Run {
            file: file.into(),
            arguments: remaining.collect(),
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
        if check.is_some() || compiler_stats {
            return Err("help, version, and build info do not accept other options".into());
        }
        return Ok(command);
    }
    let file = check.ok_or_else(|| format!("Missing: --check FILE\n\n{}", usage_summary()))?;
    Ok(Command::Check {
        file,
        compiler_stats,
    })
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
            println!(
                "source commit {}",
                option_env!("HELL_SOURCE_COMMIT").unwrap_or("unavailable")
            );
            println!("compatibility evidence schema 1");
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
        } => compile_path(&file, compiler_stats)
            .map(|_| ())
            .map_err(RunFailure::Message),
        Command::Run { file, arguments } => {
            let program = compile_path(&file, false).map_err(RunFailure::Message)?;
            let platform = hell_platform::PlatformContext::process(arguments)
                .map_err(|error| RunFailure::Message(error.to_string()))?;
            hell_runtime::run_main(program, platform.runtime).map_err(|error| match error.kind {
                hell_runtime::RuntimeErrorKind::Exit(status) => RunFailure::Exit(status),
                _ => RunFailure::Message(error.to_string()),
            })
        }
    }
}

fn compile_path(file: &std::path::Path, compiler_stats: bool) -> Result<VerifiedProgram, String> {
    let mut session = CompilerSession::upstream();
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
mod tests {
    use super::{Command, parse, usage};
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
        let Command::Run { file, arguments } = command else {
            panic!("the option separator must select script execution");
        };
        assert_eq!(file, std::path::PathBuf::from("--script.hell"));
        assert_eq!(arguments, vec![OsString::from("argument")]);
    }
}
