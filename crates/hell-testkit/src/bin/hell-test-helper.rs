//! Portable hostile-child fixture and minimal Windows restricted argv adapter.

use std::ffi::OsString;
use std::fs;
use std::io::{Read as _, Write as _};
use std::net::{Shutdown, TcpListener, TcpStream};
#[cfg(windows)]
use std::path::Path;
use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};
use std::time::Duration;

fn main() -> ExitCode {
    #[cfg(unix)]
    let (logical_invocation, arguments) = {
        let mut invocation = std::env::args_os();
        let logical_invocation = invocation.next();
        (logical_invocation, invocation.collect::<Vec<_>>())
    };
    #[cfg(not(unix))]
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    #[cfg(unix)]
    if matches!(arguments.as_slice(), [argument] if argument == "__posix-logical-invocation-child")
    {
        let Some(logical_name) = logical_invocation
            .as_deref()
            .and_then(|value| std::path::Path::new(value).file_name())
        else {
            return ExitCode::FAILURE;
        };
        println!("{}", logical_name.to_string_lossy());
        return ExitCode::SUCCESS;
    }
    #[cfg(unix)]
    if let Some(status) = run_cargo_probe(&arguments) {
        return status;
    }
    #[cfg(windows)]
    if arguments.first().and_then(|value| value.to_str()) == Some("__release-argv-child") {
        return run_windows_release_argv_child(&arguments[1..]);
    }
    #[cfg(windows)]
    if let Some(status) = run_windows_release_lifecycle_fixture(&arguments) {
        return status;
    }
    mark_forbidden_invocation();
    let (audit, arguments) = match parse_evidence_options(arguments) {
        Ok(parsed) => parsed,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::from(2);
        }
    };
    let omit_audit = arguments
        .last()
        .and_then(|argument| fs::read(argument).ok())
        .is_some_and(|source| {
            matches!(
                source.as_slice(),
                b"fail-before-audit" | b"fail-before-audit-slow"
            )
        });
    let run_result = run(arguments);
    let audit_result = if omit_audit {
        Ok(())
    } else {
        write_resource_audit_if_requested(audit.as_deref())
    };
    let result = match run_result {
        Ok(()) => audit_result,
        Err(error) => Err(error),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(2)
        }
    }
}

#[cfg(windows)]
fn run_windows_release_lifecycle_fixture(arguments: &[OsString]) -> Option<ExitCode> {
    if matches!(arguments, [argument] if argument == "__windows-status-zero") {
        return Some(ExitCode::SUCCESS);
    }
    let executable = std::env::current_exe().ok()?;
    if !executable
        .file_stem()
        .is_some_and(|name| name.eq_ignore_ascii_case("cargo"))
    {
        return None;
    }
    let [
        build,
        target_option,
        target,
        release,
        locked,
        package_option,
        package,
        binary_option,
        binary,
        features_option,
        features,
    ] = arguments
    else {
        return Some(ExitCode::FAILURE);
    };
    if build != "build"
        || target_option != "--target-dir"
        || release != "--release"
        || locked != "--locked"
        || package_option != "--package"
        || package != "hell-cli"
        || binary_option != "--bin"
        || binary != "hell"
        || features_option != "--features"
        || features != "compat-tracing"
    {
        return Some(ExitCode::FAILURE);
    }
    if executable
        .parent()
        .and_then(Path::file_name)
        .is_some_and(|name| name == "cargo-no-output")
    {
        return Some(ExitCode::SUCCESS);
    }
    let output = Path::new(target).join("release").join("hell.exe");
    let result = output
        .parent()
        .ok_or_else(|| std::io::Error::other("fixture output has no parent"))
        .and_then(fs::create_dir_all)
        .and_then(|()| fs::copy(&executable, output).map(|_| ()));
    Some(if result.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

#[cfg(unix)]
fn run_cargo_probe(arguments: &[OsString]) -> Option<ExitCode> {
    let configured = std::env::var_os("CARGO")?;
    let configured = fs::canonicalize(configured).ok()?;
    let executable = std::env::current_exe().ok()?;
    if configured != executable {
        return None;
    }
    if matches!(arguments, [argument] if ["--version", "-V"].iter().any(|value| argument == value))
    {
        println!("cargo 1.97.0 (hell-test-helper cargo probe)");
        return Some(ExitCode::SUCCESS);
    }
    if matches!(arguments, [argument] if argument == "-vV") {
        println!("cargo 1.97.0 (hell-test-helper cargo probe)");
        println!("release: 1.97.0");
        println!("commit-hash: 0000000000000000000000000000000000000000");
        println!("commit-date: 2026-08-16");
        println!("host: x86_64-unknown-linux-gnu");
        return Some(ExitCode::SUCCESS);
    }
    match hell_testkit::append_cargo_probe_invocation(&executable, arguments) {
        Ok(()) => Some(ExitCode::from(42)),
        Err(error) => {
            eprintln!("Cargo probe could not record its bounded argv: {error}");
            Some(ExitCode::FAILURE)
        }
    }
}

#[cfg(windows)]
fn run_windows_release_argv_child(arguments: &[OsString]) -> ExitCode {
    let result = (|| {
        let [encoded] = arguments else {
            return Err(std::io::Error::other(
                "Windows argv adapter requires one token",
            ));
        };
        let request = hell_testkit::parse_windows_release_child_request(
            hell_testkit::decode_windows_argv(encoded)?,
        )?;
        let cargo_release_target = request.cargo_release_target().map(Path::to_path_buf);
        if let Some(target) = cargo_release_target.as_deref() {
            hell_testkit::prepare_windows_cargo_release_receipt(target)?;
        }
        let (current_directory, environment, target_arguments) = request.into_parts();
        let (program, child_arguments) = target_arguments
            .split_first()
            .ok_or_else(|| std::io::Error::other("decoded Windows argv is empty"))?;
        let mut command = Command::new(program);
        command
            .args(child_arguments)
            .current_dir(current_directory)
            .env_clear()
            .envs(environment);
        let mut child = command.spawn()?;
        let status = child.wait()?;
        if status.success()
            && let Some(target) = cargo_release_target
        {
            hell_testkit::publish_windows_cargo_release_receipt(&target)?;
        }
        Ok(status)
    })();
    match result {
        Ok(status) => {
            let code = status.code();
            if let Some(diagnostic) = hell_testkit::windows_argv_child_status_diagnostic(code) {
                eprintln!("{diagnostic}");
                ExitCode::FAILURE
            } else {
                ExitCode::from(u8::try_from(code.expect("representable status")).expect("bounded"))
            }
        }
        Err(error) => {
            eprintln!("Windows argv adapter failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn parse_evidence_options(
    arguments: Vec<OsString>,
) -> Result<(Option<PathBuf>, Vec<OsString>), String> {
    let mut arguments = arguments.into_iter();
    let audit = if arguments
        .as_slice()
        .first()
        .is_some_and(|value| value == "--evidence-resource-audit")
    {
        arguments.next();
        Some(
            arguments
                .next()
                .map(PathBuf::from)
                .ok_or_else(|| "--evidence-resource-audit requires a path".to_owned())?,
        )
    } else {
        None
    };
    Ok((audit, arguments.collect()))
}

fn write_resource_audit_if_requested(path: Option<&std::path::Path>) -> Result<(), String> {
    let Some(path) = path else {
        return Ok(());
    };
    fs::write(
        path,
        concat!(
            "{\n",
            "  \"schemaVersion\": 1,\n",
            "  \"tasks\": 0,\n",
            "  \"handles\": 0,\n",
            "  \"processes\": 0,\n",
            "  \"httpBodies\": 0,\n",
            "  \"temporaryResources\": 0,\n",
            "  \"cleanupFailures\": 0\n",
            "}\n"
        ),
    )
    .map_err(|error| format!("cannot write fixture resource audit: {error}"))
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
    if run_profile_observer(&command, &mut arguments)? {
        return Ok(());
    }
    if run_unprofiled_oracle_script(&command, &mut arguments)? {
        return Ok(());
    }
    if run_output_command(&command, &mut arguments)?.is_some() {
        return Ok(());
    }
    if command == "emit" {
        return run_emit(&mut arguments);
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
    if command == "assert-current-dir-name" {
        let expected = arguments
            .next()
            .ok_or_else(|| "assert-current-dir-name requires NAME".to_owned())?;
        ensure_empty(arguments)?;
        let current = std::env::current_dir().map_err(|error| error.to_string())?;
        if current.file_name() != Some(expected.as_os_str()) {
            return Err(format!(
                "current directory {} differs from expected name {}",
                current.display(),
                PathBuf::from(expected).display()
            ));
        }
        return Ok(());
    }
    if run_environment_command(&command, &mut arguments)? {
        return Ok(());
    }
    if command == "fail" {
        ensure_empty(arguments)?;
        return Err("reviewed helper failure".to_owned());
    }
    if run_http_command(&command, &mut arguments)?.is_some() {
        return Ok(());
    }
    if command == "spawn-grandchild" {
        return spawn_marker_child(arguments, true);
    }
    if command == "spawn-grandchild-and-exit" {
        return spawn_marker_child(arguments, false);
    }
    #[cfg(unix)]
    if command == "escape-session-double-fork" {
        return escape_session_double_fork(arguments);
    }
    Err(format!(
        "unknown helper subcommand {}",
        command.to_string_lossy()
    ))
}

fn run_emit(arguments: &mut impl Iterator<Item = OsString>) -> Result<(), String> {
    let stdout_bytes = parse_named_usize(arguments, "--stdout-bytes")?;
    let stderr_bytes = parse_named_usize(arguments, "--stderr-bytes")?;
    ensure_empty(arguments)?;
    let stdout = std::thread::spawn(move || write_repeated(std::io::stdout(), b'O', stdout_bytes));
    let stderr = std::thread::spawn(move || write_repeated(std::io::stderr(), b'E', stderr_bytes));
    stdout
        .join()
        .map_err(|_| "stdout fixture thread panicked".to_owned())?
        .map_err(|error| error.to_string())?;
    stderr
        .join()
        .map_err(|_| "stderr fixture thread panicked".to_owned())?
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn run_unprofiled_oracle_script(
    command: &OsString,
    arguments: &mut impl Iterator<Item = OsString>,
) -> Result<bool, String> {
    if fs::read(command).is_err() {
        return Ok(false);
    }
    ensure_empty(arguments)?;
    println!("upstream");
    Ok(true)
}

#[cfg(target_os = "linux")]
fn escape_session_double_fork(mut arguments: impl Iterator<Item = OsString>) -> Result<(), String> {
    let milliseconds = parse_usize(arguments.next(), "MILLISECONDS")?;
    let marker = arguments
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| "escaped descendant fixture requires MARKER".to_owned())?;
    ensure_empty(arguments)?;
    // The grandchild deliberately retains inherited stdout/stderr while
    // escaping the original process group. Release supervision must sweep the
    // unique candidate UID before joining its capture readers.
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    let status = Command::new("/usr/bin/setsid")
        .arg(executable)
        .arg("spawn-grandchild-and-exit")
        .arg(milliseconds.to_string())
        .arg(marker)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|error| error.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("setsid fixture exited with status {status}"))
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
fn escape_session_double_fork(_arguments: impl Iterator<Item = OsString>) -> Result<(), String> {
    Err("setsid escaped-child fixture is available on Linux".to_owned())
}

fn run_environment_command(
    command: &OsString,
    arguments: &mut impl Iterator<Item = OsString>,
) -> Result<bool, String> {
    if command != "assert-env" {
        return Ok(false);
    }
    let name = arguments
        .next()
        .ok_or_else(|| "assert-env requires NAME".to_owned())?;
    let expected = arguments
        .next()
        .ok_or_else(|| "assert-env requires VALUE".to_owned())?;
    ensure_empty(arguments)?;
    if std::env::var_os(&name).as_ref() != Some(&expected) {
        return Err(format!(
            "environment variable {} differs from the reviewed value",
            name.to_string_lossy()
        ));
    }
    Ok(true)
}

fn run_profile_observer(
    command: &OsString,
    arguments: &mut impl Iterator<Item = OsString>,
) -> Result<bool, String> {
    if command != "--execution-profile" {
        return Ok(false);
    }
    let profile = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .filter(|value| matches!(value.as_str(), "upstream" | "sandboxed"))
        .ok_or_else(|| "execution profile fixture requires a typed profile".to_owned())?;
    let mode_or_script = arguments
        .next()
        .ok_or_else(|| "execution profile fixture requires a script".to_owned())?;
    if mode_or_script == "--check" {
        let script = arguments
            .next()
            .ok_or_else(|| "execution profile check requires a script".to_owned())?;
        if let Ok(source) = fs::read(script)
            && matches!(
                source.as_slice(),
                b"fail-before-audit" | b"fail-before-audit-slow"
            )
        {
            if source == b"fail-before-audit-slow" {
                std::thread::sleep(Duration::from_millis(100));
            }
            return Err("fixture failed before retaining audit".to_owned());
        }
    } else if let Ok(source) = fs::read(mode_or_script)
        && matches!(
            source.as_slice(),
            b"fail-before-audit" | b"fail-before-audit-slow"
        )
    {
        if source == b"fail-before-audit-slow" {
            std::thread::sleep(Duration::from_millis(100));
        }
        return Err("fixture failed before retaining audit".to_owned());
    }
    ensure_empty(arguments)?;
    println!("{profile}");
    Ok(true)
}

fn run_output_command(
    command: &OsString,
    arguments: &mut impl Iterator<Item = OsString>,
) -> Result<Option<()>, String> {
    let bytes = if command == "echo-stdin" {
        ensure_empty(arguments)?;
        let mut bytes = Vec::new();
        std::io::stdin()
            .read_to_end(&mut bytes)
            .map_err(|error| error.to_string())?;
        bytes
    } else if command == "emit-hex" {
        let encoded = arguments
            .next()
            .ok_or_else(|| "emit-hex requires HEX".to_owned())?;
        ensure_empty(arguments)?;
        decode_hex(&encoded.to_string_lossy())?
    } else {
        return Ok(None);
    };
    std::io::stdout()
        .write_all(&bytes)
        .map_err(|error| error.to_string())?;
    Ok(Some(()))
}

fn decode_hex(encoded: &str) -> Result<Vec<u8>, String> {
    if !encoded.len().is_multiple_of(2) {
        return Err("emit-hex requires an even number of hexadecimal digits".to_owned());
    }
    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_digit(pair[0])?;
            let low = hex_digit(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_digit(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("emit-hex received a non-hexadecimal digit".to_owned()),
    }
}

fn run_http_command(
    command: &OsString,
    arguments: &mut impl Iterator<Item = OsString>,
) -> Result<Option<()>, String> {
    if command == "available-http-port" {
        ensure_empty(arguments)?;
        let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(|error| error.to_string())?;
        let port = listener
            .local_addr()
            .map_err(|error| error.to_string())?
            .port();
        println!("{port}");
        return Ok(Some(()));
    }
    if command == "disconnect-http-stream" {
        let port = parse_u16(arguments.next(), "PORT")?;
        ensure_empty(arguments)?;
        disconnect_http_stream(port)?;
        return Ok(Some(()));
    }
    Ok(None)
}

fn disconnect_http_stream(port: u16) -> Result<(), String> {
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    let mut stream = loop {
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(stream) => break stream,
            Err(_) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(format!("cannot connect to HTTP fixture: {error}")),
        }
    };
    stream
        .write_all(b"GET /stream HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .map_err(|error| error.to_string())?;
    let mut response = [0_u8; 256];
    let read = stream
        .read(&mut response)
        .map_err(|error| error.to_string())?;
    if read == 0 || !response[..read].starts_with(b"HTTP/1.1 200 OK\r\n") {
        return Err("HTTP fixture did not receive the streaming response head".into());
    }
    stream
        .shutdown(Shutdown::Both)
        .map_err(|error| error.to_string())?;
    std::thread::sleep(Duration::from_millis(100));
    Ok(())
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

fn parse_u16(value: Option<OsString>, name: &str) -> Result<u16, String> {
    value
        .ok_or_else(|| format!("missing {name}"))?
        .into_string()
        .map_err(|_| format!("{name} must be UTF-8"))?
        .parse()
        .map_err(|_| format!("{name} must be a network port"))
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
