use std::ffi::OsString;
use std::io::{self, Write};

fn next_argument(arguments: &mut impl Iterator<Item = OsString>, name: &str) -> OsString {
    arguments
        .next()
        .unwrap_or_else(|| panic!("missing {name} argument"))
}

#[allow(clippy::zombie_processes)]
fn spawn_delayed_write(path: OsString, delay_millis: &str) -> std::process::Child {
    // These operations intentionally exercise a descendant that the process
    // supervisor, rather than the fixture parent, must reap or terminate.
    std::process::Command::new(std::env::current_exe().expect("resolve fixture executable"))
        .arg("delayed-write")
        .arg(path)
        .arg(delay_millis)
        .spawn()
        .expect("spawn fixture grandchild")
}

fn main() {
    let mut arguments = std::env::args_os().skip(1);
    let operation = next_argument(&mut arguments, "operation");

    match operation.to_str() {
        Some("emit") => {
            let stdout = next_argument(&mut arguments, "stdout");
            let stderr = next_argument(&mut arguments, "stderr");
            assert!(arguments.next().is_none(), "unexpected trailing argument");
            io::stdout()
                .write_all(stdout.to_string_lossy().as_bytes())
                .expect("write fixture stdout");
            io::stderr()
                .write_all(stderr.to_string_lossy().as_bytes())
                .expect("write fixture stderr");
        }
        Some("environment-path") => {
            assert!(arguments.next().is_none(), "unexpected trailing argument");
            let path = std::env::var_os("PATH").expect("PATH must be present");
            io::stdout()
                .write_all(path.to_string_lossy().as_bytes())
                .expect("write PATH value");
        }
        Some("exit") => {
            let code = next_argument(&mut arguments, "exit code")
                .to_string_lossy()
                .parse()
                .expect("exit code must be an integer");
            assert!(arguments.next().is_none(), "unexpected trailing argument");
            std::process::exit(code);
        }
        Some("delayed-write") => {
            let path = next_argument(&mut arguments, "output path");
            let delay_millis = next_argument(&mut arguments, "delay milliseconds")
                .to_string_lossy()
                .parse()
                .expect("delay must be an integer");
            assert!(arguments.next().is_none(), "unexpected trailing argument");
            std::thread::sleep(std::time::Duration::from_millis(delay_millis));
            std::fs::write(path, b"descendant survived").expect("write delayed marker");
        }
        Some("spawn-grandchild") => {
            let path = next_argument(&mut arguments, "output path");
            assert!(arguments.next().is_none(), "unexpected trailing argument");
            #[allow(clippy::zombie_processes)]
            let _grandchild = spawn_delayed_write(path, "400");
            std::thread::sleep(std::time::Duration::from_mins(1));
        }
        Some("spawn-grandchild-exit") => {
            let path = next_argument(&mut arguments, "output path");
            assert!(arguments.next().is_none(), "unexpected trailing argument");
            #[allow(clippy::zombie_processes)]
            let _grandchild = spawn_delayed_write(path, "2000");
        }
        _ => panic!("unknown fixture operation: {}", operation.to_string_lossy()),
    }
}
