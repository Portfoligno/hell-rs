//! Minimal strict parser for the deliberately small promotion records.
//!
//! This is not a general TOML implementation. It accepts only section headers,
//! bare keys, quoted strings, integers, booleans, and arrays used by the
//! committed schemas. Unknown keys are rejected by each schema consumer.

use std::collections::BTreeMap;

pub(crate) fn assignments(document: &str) -> Result<BTreeMap<String, String>, String> {
    let mut values = BTreeMap::new();
    let mut section = String::new();
    let mut pending = None::<(String, String)>;
    for (line_index, original) in document.lines().enumerate() {
        let line_number = line_index + 1;
        let line = strip_comment(original)?.trim();
        if line.is_empty() {
            continue;
        }
        if let Some((_key, value)) = pending.as_mut() {
            if line.starts_with('[') {
                return Err(format!(
                    "section header inside array value at line {line_number}"
                ));
            }
            if !value.is_empty() {
                value.push(' ');
            }
            value.push_str(line);
            if balanced_array(value)? {
                let (key, value) = pending.take().expect("pending value exists");
                insert_unique(&mut values, &key, value)?;
            }
            continue;
        }
        if let Some(name) = line
            .strip_prefix('[')
            .and_then(|line| line.strip_suffix(']'))
        {
            if name.is_empty() || !name.bytes().all(is_key_byte) {
                return Err(format!("invalid section at line {line_number}"));
            }
            section.clear();
            section.push_str(name);
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("expected key/value assignment at line {line_number}"))?;
        let key = key.trim();
        if key.is_empty() || !key.bytes().all(is_key_byte) {
            return Err(format!("invalid key at line {line_number}"));
        }
        let qualified = if section.is_empty() {
            key.to_owned()
        } else {
            format!("{section}.{key}")
        };
        let value = value.trim();
        if value.starts_with('[') && !balanced_array(value)? {
            pending = Some((qualified, value.to_owned()));
        } else {
            insert_unique(&mut values, &qualified, value.to_owned())?;
        }
    }
    if let Some((key, _)) = pending {
        return Err(format!("unterminated array for {key}"));
    }
    Ok(values)
}

fn insert_unique(
    values: &mut BTreeMap<String, String>,
    key: &str,
    value: String,
) -> Result<(), String> {
    if values.insert(key.to_owned(), value).is_some() {
        return Err(format!("duplicate TOML key {key}"));
    }
    Ok(())
}

fn strip_comment(line: &str) -> Result<&str, String> {
    let mut quoted = false;
    let mut escaped = false;
    for (index, character) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            '#' if !quoted => return Ok(&line[..index]),
            _ => {}
        }
    }
    (!quoted)
        .then_some(line)
        .ok_or_else(|| "unterminated quoted TOML string".to_owned())
}

fn balanced_array(value: &str) -> Result<bool, String> {
    let mut quoted = false;
    let mut escaped = false;
    let mut depth = 0_usize;
    for character in value.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            '[' if !quoted => depth = depth.saturating_add(1),
            ']' if !quoted => {
                depth = depth
                    .checked_sub(1)
                    .ok_or_else(|| "unbalanced TOML array".to_owned())?;
            }
            _ => {}
        }
    }
    if quoted {
        return Err("unterminated string in TOML array".to_owned());
    }
    Ok(depth == 0)
}

const fn is_key_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')
}

pub(crate) fn string(value: &str) -> Result<String, String> {
    let value = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .ok_or_else(|| format!("expected quoted string, observed {value:?}"))?;
    if value.contains(['"', '\\', '\n', '\r']) {
        return Err("escaped or multiline TOML strings are not accepted".to_owned());
    }
    Ok(value.to_owned())
}

pub(crate) fn boolean(value: &str) -> Result<bool, String> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(format!("expected boolean, observed {value:?}")),
    }
}

pub(crate) fn unsigned(value: &str) -> Result<u64, String> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!("expected unsigned integer, observed {value:?}"));
    }
    value
        .parse()
        .map_err(|_| format!("unsigned integer is out of range: {value}"))
}

pub(crate) fn string_array(value: &str) -> Result<Vec<String>, String> {
    let inner = value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .ok_or_else(|| format!("expected array, observed {value:?}"))?
        .trim();
    let inner = inner.strip_suffix(',').unwrap_or(inner).trim();
    if inner.is_empty() {
        return Ok(Vec::new());
    }
    let mut values = Vec::new();
    for item in inner.split(',') {
        values.push(string(item.trim())?);
    }
    Ok(values)
}

pub(crate) fn take(values: &mut BTreeMap<String, String>, key: &str) -> Result<String, String> {
    values
        .remove(key)
        .ok_or_else(|| format!("missing required TOML key {key}"))
}

pub(crate) fn finish(values: &BTreeMap<String, String>) -> Result<(), String> {
    if values.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "unknown TOML keys: {}",
            values.keys().cloned().collect::<Vec<_>>().join(", ")
        ))
    }
}
