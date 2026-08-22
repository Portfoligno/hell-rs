use std::collections::BTreeMap;

use crate::Failure;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Value {
    Scalar(String),
    Map(BTreeMap<String, Value>),
    Sequence(Vec<Value>),
}

impl Value {
    pub fn map(&self, code: &'static str) -> Result<&BTreeMap<String, Value>, Failure> {
        match self {
            Self::Map(value) => Ok(value),
            _ => Err(Failure::new(code, "expected a YAML mapping")),
        }
    }

    pub fn sequence(&self, code: &'static str) -> Result<&[Value], Failure> {
        match self {
            Self::Sequence(value) => Ok(value),
            _ => Err(Failure::new(code, "expected a YAML sequence")),
        }
    }

    pub fn scalar(&self, code: &'static str) -> Result<&str, Failure> {
        match self {
            Self::Scalar(value) => Ok(value),
            _ => Err(Failure::new(code, "expected a YAML scalar")),
        }
    }
}

struct Line {
    number: usize,
    indent: usize,
    text: String,
}

pub fn parse(bytes: &[u8]) -> Result<Value, Failure> {
    if !bytes.ends_with(b"\n") {
        return Err(Failure::new(
            "workflow.trailing-lf",
            "workflow lacks its required trailing LF",
        ));
    }
    let source = std::str::from_utf8(bytes)
        .map_err(|_| Failure::new("workflow.yaml.utf8", "workflow is not UTF-8"))?;
    let mut lines = Vec::new();
    for (offset, raw) in source.lines().enumerate() {
        if raw.contains('\t') {
            return Err(at(
                "workflow.yaml.tab",
                offset + 1,
                "tabs are not supported",
            ));
        }
        let indent = raw.bytes().take_while(|byte| *byte == b' ').count();
        if !indent.is_multiple_of(2) {
            return Err(at(
                "workflow.yaml.indent",
                offset + 1,
                "indentation must use pairs of spaces",
            ));
        }
        let content = strip_comment(&raw[indent..])?.trim_end();
        if content.is_empty() || content == "---" {
            continue;
        }
        if content == "..." || content.starts_with('%') {
            return Err(at(
                "workflow.yaml.document",
                offset + 1,
                "multiple documents and YAML directives are not supported",
            ));
        }
        lines.push(Line {
            number: offset + 1,
            indent,
            text: content.to_owned(),
        });
    }
    if lines.is_empty() {
        return Err(Failure::new("workflow.yaml.empty", "workflow is empty"));
    }
    if lines[0].indent != 0 {
        return Err(at(
            "workflow.yaml.indent",
            lines[0].number,
            "root mapping must start at column one",
        ));
    }
    let (value, next) = parse_block(&lines, 0, 0)?;
    if next != lines.len() {
        return Err(at(
            "workflow.yaml.indent",
            lines[next].number,
            "unexpected indentation",
        ));
    }
    Ok(value)
}

fn parse_block(lines: &[Line], start: usize, indent: usize) -> Result<(Value, usize), Failure> {
    if lines[start].text.starts_with("- ") || lines[start].text == "-" {
        parse_sequence(lines, start, indent)
    } else {
        parse_map(lines, start, indent)
    }
}

fn parse_map(lines: &[Line], start: usize, indent: usize) -> Result<(Value, usize), Failure> {
    let mut values = BTreeMap::new();
    let mut index = start;
    while index < lines.len() && lines[index].indent == indent {
        if lines[index].text.starts_with("- ") || lines[index].text == "-" {
            break;
        }
        let line = &lines[index];
        let (key, rest) = split_mapping(&line.text, line.number)?;
        if values.contains_key(&key) {
            return Err(at(
                "workflow.yaml.duplicate-key",
                line.number,
                "mapping key is duplicated",
            ));
        }
        index += 1;
        let value = if rest.is_empty() {
            if index < lines.len()
                && lines[index].indent == indent
                && (lines[index].text.starts_with("- ") || lines[index].text == "-")
            {
                let (nested, next) = parse_sequence(lines, index, indent)?;
                index = next;
                nested
            } else if index >= lines.len() || lines[index].indent <= indent {
                Value::Map(BTreeMap::new())
            } else if lines[index].indent == indent + 2 {
                let (nested, next) = parse_block(lines, index, indent + 2)?;
                index = next;
                nested
            } else {
                return Err(at(
                    "workflow.yaml.indent",
                    lines[index].number,
                    "nested value has unexpected indentation",
                ));
            }
        } else if matches!(rest, "|" | "|-" | ">" | ">-") {
            let (nested, next) = parse_block_scalar(lines, index, indent, rest, line.number)?;
            index = next;
            nested
        } else {
            parse_scalar(rest, line.number)?
        };
        values.insert(key, value);
    }
    Ok((Value::Map(values), index))
}

fn parse_sequence(lines: &[Line], start: usize, indent: usize) -> Result<(Value, usize), Failure> {
    let mut values = Vec::new();
    let mut index = start;
    while index < lines.len() && lines[index].indent == indent {
        let line = &lines[index];
        let Some(rest) = line.text.strip_prefix('-') else {
            break;
        };
        let rest = rest.strip_prefix(' ').unwrap_or(rest);
        index += 1;
        if rest.is_empty() {
            if index >= lines.len() || lines[index].indent != indent + 2 {
                return Err(at(
                    "workflow.yaml.sequence",
                    line.number,
                    "sequence entry lacks a value",
                ));
            }
            let (nested, next) = parse_block(lines, index, indent + 2)?;
            index = next;
            values.push(nested);
            continue;
        }
        if mapping_separator(rest).is_some() {
            let (key, value_text) = split_mapping(rest, line.number)?;
            let mut fields = BTreeMap::new();
            let first = if value_text.is_empty() {
                if index < lines.len() && lines[index].indent == indent + 4 {
                    let (nested, next) = parse_block(lines, index, indent + 4)?;
                    index = next;
                    nested
                } else {
                    Value::Map(BTreeMap::new())
                }
            } else if matches!(value_text, "|" | "|-" | ">" | ">-") {
                let (nested, next) =
                    parse_block_scalar(lines, index, indent + 2, value_text, line.number)?;
                index = next;
                nested
            } else {
                parse_scalar(value_text, line.number)?
            };
            fields.insert(key, first);
            if index < lines.len() && lines[index].indent == indent + 2 {
                let (following, next) = parse_map(lines, index, indent + 2)?;
                for (key, value) in following.map("workflow.yaml.sequence")? {
                    if fields.insert(key.clone(), value.clone()).is_some() {
                        return Err(at(
                            "workflow.yaml.duplicate-key",
                            lines[index].number,
                            "sequence mapping key is duplicated",
                        ));
                    }
                }
                index = next;
            }
            values.push(Value::Map(fields));
        } else {
            values.push(parse_scalar(rest, line.number)?);
        }
    }
    Ok((Value::Sequence(values), index))
}

fn parse_scalar(text: &str, number: usize) -> Result<Value, Failure> {
    if text.starts_with('&') || text.starts_with('*') || text.starts_with('!') {
        return Err(at(
            "workflow.yaml.extended-feature",
            number,
            "anchors, aliases, and tags are outside the supported subset",
        ));
    }
    if text == "{}" {
        return Ok(Value::Map(BTreeMap::new()));
    }
    if text == "[]" {
        return Ok(Value::Sequence(Vec::new()));
    }
    let value = if let Some(inner) = text.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
        decode_double_quoted(inner, number)?
    } else if let Some(inner) = text.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')) {
        inner.replace("''", "'")
    } else {
        text.to_owned()
    };
    Ok(Value::Scalar(value))
}

fn parse_block_scalar(
    lines: &[Line],
    start: usize,
    parent_indent: usize,
    indicator: &str,
    number: usize,
) -> Result<(Value, usize), Failure> {
    if indicator.starts_with('>') {
        return Err(at(
            "workflow.yaml.folded-scalar",
            number,
            "folded block scalars are outside the supported subset",
        ));
    }
    if start >= lines.len() || lines[start].indent <= parent_indent {
        return Err(at(
            "workflow.yaml.block-scalar",
            number,
            "block scalar has no indented content",
        ));
    }
    let content_indent = lines[start].indent;
    let mut index = start;
    let mut value = String::new();
    while index < lines.len() && lines[index].indent > parent_indent {
        if lines[index].indent < content_indent {
            return Err(at(
                "workflow.yaml.block-scalar",
                lines[index].number,
                "block scalar indentation is inconsistent",
            ));
        }
        for _ in content_indent..lines[index].indent {
            value.push(' ');
        }
        value.push_str(&lines[index].text);
        value.push('\n');
        index += 1;
    }
    if indicator.ends_with('-') {
        value.pop();
    }
    Ok((Value::Scalar(value), index))
}

fn decode_double_quoted(text: &str, number: usize) -> Result<String, Failure> {
    let mut output = String::new();
    let mut characters = text.chars();
    while let Some(character) = characters.next() {
        if character != '\\' {
            output.push(character);
            continue;
        }
        let escaped = characters.next().ok_or_else(|| {
            at(
                "workflow.yaml.quote",
                number,
                "quoted scalar ends with an escape",
            )
        })?;
        output.push(match escaped {
            '"' => '"',
            '\\' => '\\',
            '/' => '/',
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            _ => {
                return Err(at(
                    "workflow.yaml.quote",
                    number,
                    "quoted scalar contains an unsupported escape",
                ));
            }
        });
    }
    Ok(output)
}

fn split_mapping(text: &str, number: usize) -> Result<(String, &str), Failure> {
    let position = mapping_separator(text).ok_or_else(|| {
        at(
            "workflow.yaml.mapping",
            number,
            "mapping entry lacks a colon separator",
        )
    })?;
    let key = text[..position].trim();
    if key.is_empty() || key.contains(['[', ']', '{', '}']) {
        return Err(at(
            "workflow.yaml.mapping",
            number,
            "mapping key is empty or uses flow syntax",
        ));
    }
    Ok((unquote(key).to_owned(), text[position + 1..].trim_start()))
}

fn mapping_separator(text: &str) -> Option<usize> {
    let mut single = false;
    let mut double = false;
    for (position, character) in text.char_indices() {
        match character {
            '\'' if !double => single = !single,
            '"' if !single => double = !double,
            ':' if !single && !double => {
                let after = &text[position + character.len_utf8()..];
                if after.is_empty() || after.starts_with(char::is_whitespace) {
                    return Some(position);
                }
            }
            _ => {}
        }
    }
    None
}

fn strip_comment(text: &str) -> Result<&str, Failure> {
    let mut single = false;
    let mut double = false;
    let mut escaped = false;
    for (position, character) in text.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if character == '\\' && double {
            escaped = true;
            continue;
        }
        match character {
            '\'' if !double => single = !single,
            '"' if !single => double = !double,
            '#' if !single
                && !double
                && (position == 0 || text[..position].ends_with(char::is_whitespace)) =>
            {
                return Ok(&text[..position]);
            }
            _ => {}
        }
    }
    if single || double {
        return Err(Failure::new(
            "workflow.yaml.quote",
            "workflow contains an unterminated quoted scalar",
        ));
    }
    Ok(text)
}

fn unquote(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|text| text.strip_suffix('"'))
        .or_else(|| {
            value
                .strip_prefix('\'')
                .and_then(|text| text.strip_suffix('\''))
        })
        .unwrap_or(value)
}

fn at(code: &'static str, line: usize, message: &str) -> Failure {
    Failure::new(code, format!("line {line}: {message}"))
}
