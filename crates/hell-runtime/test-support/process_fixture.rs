use std::ffi::OsString;
use std::io::{self, Write};

fn next_argument(arguments: &mut impl Iterator<Item = OsString>, name: &str) -> OsString {
    arguments
        .next()
        .unwrap_or_else(|| panic!("missing {name} argument"))
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
        _ => panic!("unknown fixture operation: {}", operation.to_string_lossy()),
    }
}
