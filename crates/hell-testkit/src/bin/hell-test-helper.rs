//! Portable hostile-child fixture used by process supervision tests.

use std::ffi::OsString;
use std::fs;
use std::io::{Read as _, Write as _};
use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};
use std::time::Duration;

fn main() -> ExitCode {
    mark_forbidden_invocation();
    match run(std::env::args_os().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(2)
        }
    }
}

fn mark_forbidden_invocation() {
    let Ok(executable) = std::env::current_exe() else {
        return;
    };
    let Some(name) = executable.file_name().and_then(|name| name.to_str()) else {
        return;
    };
    if name.strip_prefix("must-not-run-").is_some() {
        let mut marker = executable.into_os_string();
        marker.push(".invoked");
        let _ = fs::write(PathBuf::from(marker), b"invoked\n");
    }
}

fn run(arguments: Vec<OsString>) -> Result<(), String> {
    let mut arguments = arguments.into_iter();
    let command = arguments
        .next()
        .ok_or_else(|| "missing helper subcommand".to_owned())?;
    if command == "--version" {
        ensure_empty(arguments)?;
        println!("hell-test-helper-1");
        return Ok(());
    }
    if command == "--build-info" {
        ensure_empty(arguments)?;
        println!("hell-test-helper {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if command == "echo-stdin" {
        ensure_empty(arguments)?;
        let mut bytes = Vec::new();
        std::io::stdin()
            .read_to_end(&mut bytes)
            .map_err(|error| error.to_string())?;
        std::io::stdout()
            .write_all(&bytes)
            .map_err(|error| error.to_string())?;
        return Ok(());
    }
    if command == "emit" {
        let stdout_bytes = parse_named_usize(&mut arguments, "--stdout-bytes")?;
        let stderr_bytes = parse_named_usize(&mut arguments, "--stderr-bytes")?;
        ensure_empty(arguments)?;
        let stdout =
            std::thread::spawn(move || write_repeated(std::io::stdout(), b'O', stdout_bytes));
        let stderr =
            std::thread::spawn(move || write_repeated(std::io::stderr(), b'E', stderr_bytes));
        stdout
            .join()
            .map_err(|_| "stdout fixture thread panicked".to_owned())?
            .map_err(|error| error.to_string())?;
        stderr
            .join()
            .map_err(|_| "stderr fixture thread panicked".to_owned())?
            .map_err(|error| error.to_string())?;
        return Ok(());
    }
    if command == "sleep-ms" {
        let milliseconds = parse_usize(arguments.next(), "MILLISECONDS")?;
        ensure_empty(arguments)?;
        std::thread::sleep(Duration::from_millis(
            u64::try_from(milliseconds).unwrap_or(u64::MAX),
        ));
        return Ok(());
    }
    if command == "write-marker-after" {
        let milliseconds = parse_usize(arguments.next(), "MILLISECONDS")?;
        let path = arguments
            .next()
            .map(PathBuf::from)
            .ok_or_else(|| "write-marker-after requires PATH".to_owned())?;
        ensure_empty(arguments)?;
        std::thread::sleep(Duration::from_millis(
            u64::try_from(milliseconds).unwrap_or(u64::MAX),
        ));
        fs::write(path, b"descendant survived\n").map_err(|error| error.to_string())?;
        return Ok(());
    }
    if command == "spawn-grandchild" {
        return spawn_marker_child(arguments, true);
    }
    if command == "spawn-grandchild-and-exit" {
        return spawn_marker_child(arguments, false);
    }
    Err(format!(
        "unknown helper subcommand {}",
        command.to_string_lossy()
    ))
}

fn spawn_marker_child(
    mut arguments: impl Iterator<Item = OsString>,
    linger: bool,
) -> Result<(), String> {
    let milliseconds = parse_usize(arguments.next(), "MILLISECONDS")?;
    let marker = arguments
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| "grandchild fixture requires MARKER".to_owned())?;
    ensure_empty(arguments)?;
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    Command::new(executable)
        .arg("write-marker-after")
        .arg(milliseconds.to_string())
        .arg(marker)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|error| error.to_string())?;
    if linger {
        std::thread::sleep(Duration::from_secs(30));
    }
    Ok(())
}

fn parse_named_usize(
    arguments: &mut impl Iterator<Item = OsString>,
    expected: &str,
) -> Result<usize, String> {
    let flag = arguments
        .next()
        .ok_or_else(|| format!("missing {expected}"))?;
    if flag != expected {
        return Err(format!(
            "expected {expected}, received {}",
            flag.to_string_lossy()
        ));
    }
    parse_usize(arguments.next(), expected)
}

fn parse_usize(value: Option<OsString>, name: &str) -> Result<usize, String> {
    value
        .ok_or_else(|| format!("missing {name}"))?
        .into_string()
        .map_err(|_| format!("{name} must be UTF-8"))?
        .parse()
        .map_err(|_| format!("{name} must be an unsigned integer"))
}

fn ensure_empty(mut arguments: impl Iterator<Item = OsString>) -> Result<(), String> {
    arguments.next().map_or(Ok(()), |argument| {
        Err(format!(
            "unexpected argument {}",
            argument.to_string_lossy()
        ))
    })
}

fn write_repeated(mut output: impl std::io::Write, byte: u8, count: usize) -> std::io::Result<()> {
    let chunk = [byte; 8 * 1024];
    let mut remaining = count;
    while remaining != 0 {
        let length = remaining.min(chunk.len());
        output.write_all(&chunk[..length])?;
        remaining -= length;
    }
    output.flush()
}
