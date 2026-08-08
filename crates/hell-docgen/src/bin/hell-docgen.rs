fn main() {
    let mut arguments = std::env::args_os().skip(1);
    let command = arguments.next().unwrap_or_else(|| "api".into());
    let output = match command.to_str() {
        Some("api") if arguments.next().is_none() => hell_docgen::render_api_markdown(),
        Some("snapshot") if arguments.next().is_none() => hell_docgen::render_compatibility_json(),
        Some("check-snapshot") => {
            let Some(path) = arguments.next() else {
                usage();
            };
            if arguments.next().is_some() {
                usage();
            }
            let expected = std::fs::read_to_string(path).unwrap_or_else(|error| {
                eprintln!("could not read reviewed snapshot: {error}");
                std::process::exit(2);
            });
            if let Err(mismatch) = hell_docgen::verify_compatibility_snapshot(&expected) {
                eprintln!(
                    "compatibility snapshot changed at byte {} (reviewed {}, generated {})",
                    mismatch.first_differing_byte, mismatch.expected_len, mismatch.generated_len
                );
                std::process::exit(1);
            }
            return;
        }
        _ => {
            usage();
        }
    };
    print!("{output}");
}

fn usage() -> ! {
    eprintln!("usage: hell-docgen [api|snapshot|check-snapshot FILE]");
    std::process::exit(2);
}
