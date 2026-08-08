use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use hell_compiler::{CompilerSession, DiagnosticBundle, compile_file};
use hell_core::VerifiedProgram;

enum Command {
    Version,
    BuildInfo,
    Check(PathBuf),
    Run {
        file: PathBuf,
        arguments: Vec<Arc<str>>,
    },
}

enum RunFailure {
    Message(String),
    Exit(i32),
}

fn usage() -> &'static str {
    "usage: hell FILE [SCRIPT-ARGUMENTS...]\n       hell --check FILE\n       hell --version"
}

fn parse(arguments: impl IntoIterator<Item = OsString>) -> Result<Command, String> {
    let mut arguments = arguments.into_iter();
    let Some(first) = arguments.next() else {
        return Err(usage().into());
    };
    if first == "--version" {
        if arguments.next().is_some() {
            return Err("--version does not accept arguments".into());
        }
        return Ok(Command::Version);
    }
    if first == "--build-info" {
        if arguments.next().is_some() {
            return Err("--build-info does not accept arguments".into());
        }
        return Ok(Command::BuildInfo);
    }
    if first == "--check" {
        let Some(file) = arguments.next() else {
            return Err("--check requires FILE".into());
        };
        if arguments.next().is_some() {
            return Err("--check accepts exactly one FILE".into());
        }
        return Ok(Command::Check(file.into()));
    }
    if first.to_string_lossy().starts_with('-') {
        return Err(format!(
            "unknown option `{}`\n{}",
            first.to_string_lossy(),
            usage()
        ));
    }
    let script_arguments = arguments
        .map(|argument| {
            argument
                .into_string()
                .map(Arc::<str>::from)
                .map_err(|_| "script arguments must be UTF-8".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Command::Run {
        file: first.into(),
        arguments: script_arguments,
    })
}

fn run(command: Command) -> Result<(), RunFailure> {
    match command {
        Command::Version => {
            println!("{}", hell_builtins::LANGUAGE_VERSION);
            Ok(())
        }
        Command::BuildInfo => {
            println!("hell-rs {}", env!("CARGO_PKG_VERSION"));
            println!("language baseline {}", hell_builtins::LANGUAGE_VERSION);
            println!("upstream {}", hell_builtins::UPSTREAM_COMMIT);
            Ok(())
        }
        Command::Check(file) => compile_path(&file).map(|_| ()).map_err(RunFailure::Message),
        Command::Run { file, arguments } => {
            let program = compile_path(&file).map_err(RunFailure::Message)?;
            let platform = hell_platform::PlatformContext::process(arguments)
                .map_err(|error| RunFailure::Message(error.to_string()))?;
            hell_runtime::run_main(program, platform.runtime).map_err(|error| match error.kind {
                hell_runtime::RuntimeErrorKind::Exit(status) => RunFailure::Exit(status),
                _ => RunFailure::Message(error.to_string()),
            })
        }
    }
}

fn compile_path(file: &std::path::Path) -> Result<VerifiedProgram, String> {
    let mut session = CompilerSession::default();
    compile_file(&mut session, file)
        .map_err(|diagnostics| render_diagnostics(&session, &diagnostics))
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
            return ExitCode::from(2);
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
