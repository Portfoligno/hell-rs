use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const CACHE_SHA: &str = "55cc8345863c7cc4c66a329aec7e433d2d1c52a9";

pub fn check_repository(root: &Path) -> Result<(), String> {
    let tracked = tracked_files(root)?;
    let modes = tracked_modes(root)?;
    let mut failures = Vec::new();
    for path in &tracked {
        check_tracked_file(
            root,
            path,
            modes.get(path).map(String::as_str),
            &mut failures,
        );
    }
    check_checkout_attributes(root, &mut failures);
    check_workflows(root, &tracked, &mut failures);
    check_test_infrastructure(root, &tracked, &mut failures);
    check_environment_configuration(root, &tracked, &mut failures);
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("\n"))
    }
}

fn check_checkout_attributes(root: &Path, failures: &mut Vec<String>) {
    const PATHS: &[&str] = &[
        "crates/hell-docgen/src/lib.rs",
        "compat/upstream-2026-05-29.json",
        "builtins/primitives.ron",
        "fixtures/upstream-2026-05-29/expected/01.stdout",
        "fixtures/upstream-2026-05-29/examples/01-hello-world.hell",
    ];

    let mut command = Command::new("git");
    command.args([
        "check-attr",
        "--cached",
        "-z",
        "text",
        "eol",
        "linguist-language",
        "--",
    ]);
    command.args(PATHS);
    command.current_dir(root);
    let output = match command.output() {
        Ok(output) => output,
        Err(error) => {
            failures.push(format!("git check-attr failed to start: {error}"));
            return;
        }
    };
    if !output.status.success() {
        failures.push(format!(
            "git check-attr failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
        return;
    }
    let attributes = match parse_checked_attributes(&output.stdout) {
        Ok(attributes) => attributes,
        Err(error) => {
            failures.push(error);
            return;
        }
    };
    for path in PATHS {
        require_attribute(&attributes, path, "text", "auto", failures);
        require_attribute(&attributes, path, "eol", "lf", failures);
    }
    require_attribute(
        &attributes,
        "fixtures/upstream-2026-05-29/examples/01-hello-world.hell",
        "linguist-language",
        "Haskell",
        failures,
    );
}

fn parse_checked_attributes(bytes: &[u8]) -> Result<BTreeMap<(String, String), String>, String> {
    let fields = split_nul(bytes).collect::<Vec<_>>();
    if !fields.len().is_multiple_of(3) {
        return Err("git check-attr returned malformed NUL-delimited output".to_owned());
    }
    let mut attributes = BTreeMap::new();
    for record in fields.chunks_exact(3) {
        let path = std::str::from_utf8(record[0])
            .map_err(|_| "git check-attr returned a non-UTF-8 path".to_owned())?;
        let attribute = std::str::from_utf8(record[1])
            .map_err(|_| "git check-attr returned a non-UTF-8 attribute".to_owned())?;
        let value = std::str::from_utf8(record[2])
            .map_err(|_| "git check-attr returned a non-UTF-8 value".to_owned())?;
        attributes.insert((path.to_owned(), attribute.to_owned()), value.to_owned());
    }
    Ok(attributes)
}

fn require_attribute(
    attributes: &BTreeMap<(String, String), String>,
    path: &str,
    attribute: &str,
    expected: &str,
    failures: &mut Vec<String>,
) {
    let key = (path.to_owned(), attribute.to_owned());
    let actual = attributes.get(&key).map_or("unspecified", String::as_str);
    if actual != expected {
        failures.push(format!(
            "checkout attribute {attribute} for {path} is {actual}, expected {expected}"
        ));
    }
}

pub fn normalized_relative_path(value: &str) -> Result<PathBuf, String> {
    if value.is_empty() {
        return Err(format!("path must be nonempty and relative: {value}"));
    }
    let mut normalized = PathBuf::new();
    for part in value.split('/') {
        if part.is_empty()
            || part == "."
            || part == ".."
            || part.contains('\\')
            || part.contains(':')
        {
            return Err(format!("path is not normalized: {value}"));
        }
        normalized.push(part);
    }
    Ok(normalized)
}

fn tracked_files(root: &Path) -> Result<Vec<PathBuf>, String> {
    let output = Command::new("git")
        .args(["ls-files", "-z"])
        .current_dir(root)
        .output()
        .map_err(|error| format!("git ls-files failed to start: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "git ls-files failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    split_nul(&output.stdout)
        .map(|value| {
            String::from_utf8(value.to_vec())
                .map(PathBuf::from)
                .map_err(|_| "tracked path is not UTF-8".to_owned())
        })
        .collect()
}

fn tracked_modes(root: &Path) -> Result<BTreeMap<PathBuf, String>, String> {
    let output = Command::new("git")
        .args(["ls-files", "--stage", "-z"])
        .current_dir(root)
        .output()
        .map_err(|error| format!("git ls-files --stage failed to start: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "git ls-files --stage failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let mut modes = BTreeMap::new();
    for record in split_nul(&output.stdout) {
        let text =
            std::str::from_utf8(record).map_err(|_| "git index record is not UTF-8".to_owned())?;
        let (metadata, path) = text
            .split_once('\t')
            .ok_or_else(|| "malformed git index record".to_owned())?;
        let mode = metadata
            .split_whitespace()
            .next()
            .ok_or_else(|| "git index record has no mode".to_owned())?;
        modes.insert(PathBuf::from(path), mode.to_owned());
    }
    Ok(modes)
}

fn split_nul(bytes: &[u8]) -> impl Iterator<Item = &[u8]> {
    bytes
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
}

fn check_tracked_file(root: &Path, path: &Path, mode: Option<&str>, failures: &mut Vec<String>) {
    let display = path.display();
    let extension = path.extension().and_then(|value| value.to_str());
    if matches!(extension, Some("sh" | "bash")) {
        failures.push(format!("shell script is forbidden: {display}"));
    }
    let bytes = match fs::read(root.join(path)) {
        Ok(bytes) => bytes,
        Err(error) => {
            failures.push(format!("cannot read {display}: {error}"));
            return;
        }
    };
    if bytes.is_empty() {
        failures.push(format!("tracked file is empty: {display}"));
        return;
    }
    if bytes.contains(&0) {
        failures.push(format!("tracked file contains NUL: {display}"));
    }
    if bytes.last() != Some(&b'\n') {
        failures.push(format!("tracked file does not end with LF: {display}"));
    }
    // The pinned upstream examples are deliberately byte-for-byte fixtures.
    // Their reviewed trailing spaces predate this repository's convention.
    let pinned_upstream_example = path.starts_with("fixtures/upstream-2026-05-29/examples");
    for (index, line) in bytes.split(|byte| *byte == b'\n').enumerate() {
        if !pinned_upstream_example && line.last().is_some_and(|byte| matches!(byte, b' ' | b'\t'))
        {
            failures.push(format!(
                "tracked file has trailing whitespace at {display}:{}",
                index + 1
            ));
        }
        if line.starts_with(b"<<<<<<< ") || line == b"=======" || line.starts_with(b">>>>>>> ") {
            failures.push(format!(
                "tracked file has a conflict marker at {display}:{}",
                index + 1
            ));
        }
    }
    if mode == Some("100755") && !bytes.starts_with(b"#!") {
        failures.push(format!("executable lacks a shebang: {display}"));
    }
}

fn check_workflows(root: &Path, tracked: &[PathBuf], failures: &mut Vec<String>) {
    for path in tracked.iter().filter(|path| {
        path.parent()
            .is_some_and(|parent| parent == Path::new(".github/workflows"))
            && path.extension().and_then(|value| value.to_str()) == Some("yml")
    }) {
        let text = match fs::read_to_string(root.join(path)) {
            Ok(text) => text,
            Err(error) => {
                failures.push(format!("cannot read {}: {error}", path.display()));
                continue;
            }
        };
        check_workflow(path, &text, failures);
    }
}

fn check_workflow(path: &Path, text: &str, failures: &mut Vec<String>) {
    let mut restore_keys = BTreeSet::new();
    let mut save_keys = BTreeSet::new();
    let lines = text.lines().collect::<Vec<_>>();
    for (index, original) in lines.iter().enumerate() {
        let line = strip_yaml_comment(original).trim();
        let entry = line.strip_prefix("- ").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        let location = format!("{}:{}", path.display(), index + 1);
        if yaml_key(entry, "shell").is_some() {
            failures.push(format!("workflow shell key is forbidden at {location}"));
        }
        if yaml_key(entry, "env").is_some() {
            failures.push(format!("workflow env key is forbidden at {location}"));
        }
        if yaml_key(entry, "pull_request").is_some()
            || yaml_key(entry, "pull_request_target").is_some()
        {
            failures.push(format!("pull request trigger is forbidden at {location}"));
        }
        if yaml_key(entry, "branches").is_some() {
            failures.push(format!(
                "branch-filtered workflow trigger is forbidden at {location}"
            ));
        }
        if let Some(run) = yaml_key(entry, "run") {
            check_run_value(run.trim(), &location, failures);
        }
        if let Some(uses) = yaml_key(entry, "uses") {
            check_uses_value(uses.trim(), &location, failures);
            if uses.contains("actions/checkout@")
                && following_value(&lines, index, "persist-credentials") != Some("false")
            {
                failures.push(format!("checkout persists credentials at {location}"));
            }
            if uses.contains("actions/cache/restore@")
                && let Some(key) = following_value(&lines, index, "key")
            {
                restore_keys.insert(key.to_owned());
            }
            if uses.contains("actions/cache/save@") {
                let condition = preceding_value(&lines, index, "if");
                if !condition.is_some_and(|value| value.contains("always()")) {
                    failures.push(format!("cache save lacks always() at {location}"));
                }
                if let Some(key) = following_value(&lines, index, "key") {
                    save_keys.insert(key.to_owned());
                }
            }
        }
    }
    if !save_keys.is_subset(&restore_keys) {
        failures.push(format!(
            "cache save key has no identical restore key in {}",
            path.display()
        ));
    }
}

fn strip_yaml_comment(line: &str) -> &str {
    let mut single = false;
    let mut double = false;
    let mut previous = '\0';
    for (index, character) in line.char_indices() {
        match character {
            '\'' if !double => single = !single,
            '"' if !single && previous != '\\' => double = !double,
            '#' if !single && !double && (index == 0 || previous.is_whitespace()) => {
                return &line[..index];
            }
            _ => {}
        }
        previous = character;
    }
    line
}

fn yaml_key<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.strip_prefix(key)?.strip_prefix(':')
}

fn check_run_value(value: &str, location: &str, failures: &mut Vec<String>) {
    if value.is_empty() || matches!(value, "|" | ">" | "|-" | ">-") {
        failures.push(format!(
            "workflow run must be an inline invocation at {location}"
        ));
        return;
    }
    let forbidden = ["&&", "||", ";", "|", "`", "$(", ">", "<"];
    if forbidden.iter().any(|token| value.contains(token)) {
        failures.push(format!(
            "workflow run contains shell control syntax at {location}"
        ));
    }
    let executable = value
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .trim_matches(['\'', '"']);
    let executable = Path::new(executable)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(executable)
        .to_ascii_lowercase();
    if matches!(
        executable.as_str(),
        "sh" | "sh.exe"
            | "bash"
            | "bash.exe"
            | "zsh"
            | "zsh.exe"
            | "fish"
            | "fish.exe"
            | "pwsh"
            | "pwsh.exe"
            | "powershell"
            | "powershell.exe"
            | "cmd"
            | "cmd.exe"
    ) {
        failures.push(format!(
            "workflow invokes a shell interpreter at {location}"
        ));
    }
}

fn check_uses_value(value: &str, location: &str, failures: &mut Vec<String>) {
    if value.starts_with("./") {
        return;
    }
    let value = value.split_whitespace().next().unwrap_or_default();
    let Some((action, revision)) = value.rsplit_once('@') else {
        failures.push(format!("external action is not pinned at {location}"));
        return;
    };
    if revision.len() != 40 || !revision.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        failures.push(format!(
            "external action pin is not 40 hex characters at {location}"
        ));
    }
    if matches!(action, "actions/cache/restore" | "actions/cache/save") && revision != CACHE_SHA {
        failures.push(format!("cache action has an unexpected pin at {location}"));
    }
}

fn following_value<'a>(lines: &'a [&str], start: usize, key: &str) -> Option<&'a str> {
    lines
        .iter()
        .skip(start + 1)
        .take(24)
        .find_map(|line| yaml_key(line.trim(), key).map(str::trim))
}

fn preceding_value<'a>(lines: &'a [&str], start: usize, key: &str) -> Option<&'a str> {
    lines[..start]
        .iter()
        .rev()
        .take(5)
        .find_map(|line| yaml_key(line.trim(), key).map(str::trim))
}

fn check_test_infrastructure(root: &Path, tracked: &[PathBuf], failures: &mut Vec<String>) {
    for path in tracked.iter().filter(|path| is_test_infrastructure(path)) {
        let Ok(text) = fs::read_to_string(root.join(path)) else {
            continue;
        };
        if path.file_name().and_then(|value| value.to_str()) == Some("Cargo.toml") {
            for line in text.lines() {
                let dependency = line
                    .split_once('=')
                    .map_or(line, |(name, _)| name)
                    .trim()
                    .trim_matches('"');
                if matches!(dependency, "regex" | "regex-automata" | "regex-syntax") {
                    failures.push(format!(
                        "regex dependency in test infrastructure: {}",
                        path.display()
                    ));
                }
                if dependency_package(line).is_some_and(|package| {
                    matches!(package, "regex" | "regex-automata" | "regex-syntax")
                }) {
                    failures.push(format!(
                        "regex package alias in test infrastructure: {}",
                        path.display()
                    ));
                }
            }
        }
        for identifier in rust_identifiers(&text) {
            if matches!(identifier.as_str(), "Regex" | "RegexSet" | "RegexBuilder") {
                failures.push(format!(
                    "regex API in test infrastructure: {}",
                    path.display()
                ));
                break;
            }
        }
        let identifiers = rust_identifiers(&text);
        if identifiers
            .windows(2)
            .any(|pair| matches!(pair, [first, second] if first == "use" && second == "regex"))
        {
            failures.push(format!(
                "regex import in test infrastructure: {}",
                path.display()
            ));
        }
    }
}

fn dependency_package(line: &str) -> Option<&str> {
    let line = strip_yaml_comment(line);
    let (_, inline_table) = line.split_once('=')?;
    inline_table.split(',').find_map(|field| {
        let field = field.trim().trim_matches(['{', '}']);
        let (key, value) = field.split_once('=')?;
        if key.trim() != "package" {
            return None;
        }
        let quoted = value.trim().strip_prefix('"')?;
        let (package, _) = quoted.split_once('"')?;
        Some(package)
    })
}

fn is_test_infrastructure(path: &Path) -> bool {
    path.starts_with("crates/hell-ci")
        || path.starts_with("crates/hell-testkit")
        || path
            .components()
            .any(|component| component.as_os_str() == "tests")
}

fn rust_identifiers(text: &str) -> Vec<String> {
    const LINE_COMMENT: &[u8] = b"//";
    const BLOCK_OPEN: &[u8] = b"/*";
    const BLOCK_CLOSE: &[u8] = b"*/";
    const ESCAPED_PAIR_WIDTH: usize = b"\\x".len();
    const APOSTROPHE_TOKEN: &[u8] = b"'";

    let bytes = text.as_bytes();
    let apostrophe = APOSTROPHE_TOKEN[0];
    let mut identifiers = Vec::new();
    let mut index = 0;
    let mut in_line_comment = false;
    let mut block_depth = 0_u32;
    let mut quote = None;
    while index < bytes.len() {
        if in_line_comment {
            if bytes[index] == b'\n' {
                in_line_comment = false;
            }
            index += 1;
            continue;
        }
        if block_depth != 0 {
            if bytes.get(index..index.saturating_add(BLOCK_OPEN.len())) == Some(BLOCK_OPEN) {
                block_depth += 1;
                index += BLOCK_OPEN.len();
            } else if bytes.get(index..index.saturating_add(BLOCK_CLOSE.len())) == Some(BLOCK_CLOSE)
            {
                block_depth -= 1;
                index += BLOCK_CLOSE.len();
            } else {
                index += 1;
            }
            continue;
        }
        if let Some(delimiter) = quote {
            if bytes[index] == b'\\' {
                index = index.saturating_add(ESCAPED_PAIR_WIDTH).min(bytes.len());
            } else {
                if bytes[index] == delimiter {
                    quote = None;
                }
                index += 1;
            }
            continue;
        }
        if bytes.get(index..index.saturating_add(LINE_COMMENT.len())) == Some(LINE_COMMENT) {
            in_line_comment = true;
            index += LINE_COMMENT.len();
        } else if bytes.get(index..index.saturating_add(BLOCK_OPEN.len())) == Some(BLOCK_OPEN) {
            block_depth = 1;
            index += BLOCK_OPEN.len();
        } else if bytes[index] == apostrophe {
            let rest = &bytes[index.saturating_add(APOSTROPHE_TOKEN.len())..];
            let line = rest.split(|byte| *byte == b'\n').next().unwrap_or_default();
            if let Some(closing) = unescaped_apostrophe(line, apostrophe) {
                index = index
                    .saturating_add(APOSTROPHE_TOKEN.len())
                    .saturating_add(closing)
                    .saturating_add(APOSTROPHE_TOKEN.len());
            } else {
                index += APOSTROPHE_TOKEN.len();
            }
        } else if bytes[index] == b'"' {
            quote = Some(bytes[index]);
            index += 1;
        } else if bytes[index].is_ascii_alphabetic() || bytes[index] == b'_' {
            let start = index;
            index += 1;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
            {
                index += 1;
            }
            identifiers.push(text[start..index].to_owned());
        } else {
            index += 1;
        }
    }
    identifiers
}

fn unescaped_apostrophe(bytes: &[u8], apostrophe: u8) -> Option<usize> {
    let mut escaped = false;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if escaped {
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if byte == apostrophe {
            return Some(index);
        }
    }
    None
}

fn check_environment_configuration(root: &Path, tracked: &[PathBuf], failures: &mut Vec<String>) {
    for path in tracked {
        let text_path = path.to_string_lossy();
        let relevant = text_path.starts_with(".cargo/config")
            || path.file_name().and_then(|value| value.to_str()) == Some("build.rs");
        if !relevant {
            continue;
        }
        let Ok(text) = fs::read_to_string(root.join(path)) else {
            continue;
        };
        if text_path.starts_with(".cargo/config") && text.lines().any(|line| line.trim() == "[env]")
        {
            failures.push(format!(
                "Cargo env configuration is forbidden: {}",
                path.display()
            ));
        }
        if text.contains("cargo:rustc-env") {
            failures.push(format!(
                "rustc environment output is forbidden: {}",
                path.display()
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workflow(body: &str) -> Vec<String> {
        let mut failures = Vec::new();
        check_workflow(Path::new("workflow.yml"), body, &mut failures);
        failures
    }

    #[test]
    fn compliant_workflow_is_accepted() {
        let text = "on:\n  push:\njobs:\n  test:\n    steps:\n      - run: cargo test --locked\n      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n        with:\n          persist-credentials: false\n";
        assert!(workflow(text).is_empty());
    }

    #[test]
    fn cached_attribute_output_preserves_checkout_policy() {
        let attributes = parse_checked_attributes(
            b"compat/upstream-2026-05-29.json\0text\0auto\0compat/upstream-2026-05-29.json\0eol\0lf\0fixtures/upstream-2026-05-29/examples/01-hello-world.hell\0linguist-language\0Haskell\0",
        )
        .unwrap();
        let mut failures = Vec::new();
        require_attribute(
            &attributes,
            "compat/upstream-2026-05-29.json",
            "text",
            "auto",
            &mut failures,
        );
        require_attribute(
            &attributes,
            "compat/upstream-2026-05-29.json",
            "eol",
            "lf",
            &mut failures,
        );
        require_attribute(
            &attributes,
            "fixtures/upstream-2026-05-29/examples/01-hello-world.hell",
            "linguist-language",
            "Haskell",
            &mut failures,
        );
        assert!(failures.is_empty());

        require_attribute(
            &attributes,
            "compat/upstream-2026-05-29.json",
            "eol",
            "crlf",
            &mut failures,
        );
        assert_eq!(failures.len(), 1);
    }

    #[test]
    fn malformed_cached_attribute_output_is_rejected() {
        assert!(parse_checked_attributes(b"path\0text\0").is_err());
    }

    #[test]
    fn unsafe_workflow_forms_are_rejected() {
        for value in [
            "      - run: |\n          cargo test\n",
            "      - run: cargo test && cargo fmt\n",
            "      - run: sh -c test\n",
            "      - shell: bash\n",
            "      - env:\n          TOKEN: no\n",
            "      - uses: actions/checkout@main\n",
            "  pull_request:\n",
            "    branches:\n      - main\n",
        ] {
            assert!(!workflow(value).is_empty(), "accepted {value:?}");
        }
    }

    #[test]
    fn cache_save_requires_always() {
        let text = "      - name: Save\n        if: success()\n        uses: actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9\n        with:\n          key: one\n";
        assert!(!workflow(text).is_empty());
    }

    #[test]
    fn cache_restore_and_save_keys_must_match() {
        let text = "      - uses: actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9\n        with:\n          key: restore\n      - name: Save\n        if: always()\n        uses: actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9\n        with:\n          key: save\n";
        assert!(!workflow(text).is_empty());
    }

    #[test]
    fn path_normalization_confines_fixture_paths() {
        assert_eq!(
            normalized_relative_path("examples/01.hell").unwrap(),
            Path::new("examples").join("01.hell")
        );
        for value in [
            "",
            "../escape",
            "examples/../escape",
            "/absolute",
            "examples/",
            "examples//01.hell",
            "examples/./01.hell",
            "examples\\01.hell",
            "\\\\server\\share\\01.hell",
            "C:examples/01.hell",
            "C:/examples/01.hell",
        ] {
            assert!(
                normalized_relative_path(value).is_err(),
                "accepted {value:?}"
            );
        }
    }

    #[test]
    fn lexical_scan_ignores_prose_and_strings() {
        assert!(
            rust_identifiers("// Regex\nlet value = \"Regex\";")
                .iter()
                .all(|value| value != "Regex")
        );
        assert!(
            rust_identifiers("let Regex = value;")
                .iter()
                .any(|value| value == "Regex")
        );
        let imported = rust_identifiers("use regex::Regex as R;");
        assert!(imported.iter().any(|value| value == "regex"));
        assert_eq!(
            dependency_package("matcher = { package = \"regex\", version = \"1\" }"),
            Some("regex")
        );
        assert_eq!(dependency_package("# package = \"regex\""), None);
        assert_eq!(
            dependency_package("description = \"package = regex\""),
            None
        );
        let multiline = rust_identifiers("use\n regex as matcher;");
        assert!(multiline.windows(2).any(|pair| {
            matches!(pair, [first, second] if first == "use" && second == "regex")
        }));
    }

    #[test]
    fn scanner_handles_its_own_char_literals() {
        let identifiers = rust_identifiers(include_str!("policy.rs"));
        assert!(!identifiers.iter().any(|identifier| {
            matches!(identifier.as_str(), "Regex" | "RegexSet" | "RegexBuilder")
        }));
    }

    #[test]
    fn shell_suffixes_are_rejected() {
        let root = std::env::temp_dir().join(format!("hell-ci-policy-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        for name in ["bad.sh", "bad.bash"] {
            fs::write(root.join(name), b"#!/bin/sh\n").unwrap();
            let mut failures = Vec::new();
            check_tracked_file(&root, Path::new(name), Some("100755"), &mut failures);
            assert!(
                failures
                    .iter()
                    .any(|failure| failure.contains("shell script"))
            );
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn missing_lf_is_rejected() {
        let root = std::env::temp_dir().join(format!("hell-ci-lf-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("bad.txt"), b"missing newline").unwrap();
        let mut failures = Vec::new();
        check_tracked_file(&root, Path::new("bad.txt"), Some("100644"), &mut failures);
        assert!(
            failures
                .iter()
                .any(|failure| failure.contains("end with LF"))
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn executable_without_shebang_is_rejected() {
        let root = std::env::temp_dir().join(format!("hell-ci-exec-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("tool"), b"not a script\n").unwrap();
        let mut failures = Vec::new();
        check_tracked_file(&root, Path::new("tool"), Some("100755"), &mut failures);
        assert!(failures.iter().any(|failure| failure.contains("shebang")));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pinned_upstream_examples_preserve_reviewed_trailing_spaces() {
        let root = std::env::temp_dir().join(format!("hell-ci-pinned-{}", std::process::id()));
        let relative = Path::new("fixtures/upstream-2026-05-29/examples/example.hell");
        fs::create_dir_all(root.join(relative).parent().unwrap()).unwrap();
        fs::write(root.join(relative), b"main = IO.pure () \n").unwrap();
        let mut failures = Vec::new();
        check_tracked_file(&root, relative, Some("100644"), &mut failures);
        assert!(failures.is_empty());
        fs::remove_dir_all(root).unwrap();
    }
}
