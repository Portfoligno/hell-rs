use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

pub(crate) const MAX_JSON_BYTES: usize = 16 * 1024 * 1024;
const MAX_JSON_DEPTH: usize = 64;
const MAX_JSON_MEMBERS: usize = 1_000_000;
const MAX_JSON_STRING_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Value {
    Null,
    Bool(bool),
    Number(u64),
    String(String),
    Array(Vec<Self>),
    Object(BTreeMap<String, Self>),
}

pub(crate) struct ClassifiedError {
    pub code: &'static str,
    pub message: String,
}

impl Value {
    pub(crate) fn object(&self) -> Result<&BTreeMap<String, Self>, String> {
        match self {
            Self::Object(value) => Ok(value),
            _ => Err("expected JSON object".to_owned()),
        }
    }

    pub(crate) fn array(&self) -> Result<&[Self], String> {
        match self {
            Self::Array(value) => Ok(value),
            _ => Err("expected JSON array".to_owned()),
        }
    }

    pub(crate) fn string(&self) -> Result<&str, String> {
        match self {
            Self::String(value) => Ok(value),
            _ => Err("expected JSON string".to_owned()),
        }
    }

    pub(crate) fn number(&self) -> Result<u64, String> {
        match self {
            Self::Number(value) => Ok(*value),
            _ => Err("expected unsigned JSON integer".to_owned()),
        }
    }

    pub(crate) fn boolean(&self) -> Result<bool, String> {
        match self {
            Self::Bool(value) => Ok(*value),
            _ => Err("expected JSON boolean".to_owned()),
        }
    }
}

pub(crate) fn parse(bytes: &[u8]) -> Result<Value, String> {
    parse_classified(bytes).map_err(|error| error.message)
}

pub(crate) fn parse_classified(bytes: &[u8]) -> Result<Value, ClassifiedError> {
    if bytes.len() > MAX_JSON_BYTES {
        return Err(ClassifiedError {
            code: "release.limit.json-bytes",
            message: "JSON input exceeds the independent verifier limit".to_owned(),
        });
    }
    let text = std::str::from_utf8(bytes).map_err(|_| ClassifiedError {
        code: "release.json.invalid",
        message: "JSON input is not UTF-8".to_owned(),
    })?;
    let mut parser = Parser {
        bytes: text.as_bytes(),
        index: 0,
        members: 0,
        diagnostic_code: None,
    };
    let value = parser.value(0).map_err(|message| ClassifiedError {
        code: parser.diagnostic_code.unwrap_or("release.json.invalid"),
        message,
    })?;
    parser.whitespace();
    if parser.index != parser.bytes.len() {
        return Err(ClassifiedError {
            code: "release.json.trailing-bytes",
            message: format!("trailing JSON data at byte {}", parser.index),
        });
    }
    Ok(value)
}

pub(crate) fn parse_canonical(bytes: &[u8]) -> Result<Value, String> {
    let value = parse(bytes)?;
    if canonical(&value)? != bytes {
        return Err("JSON input is not canonical with exactly one trailing LF".to_owned());
    }
    Ok(value)
}

pub(crate) fn parse_canonical_classified(bytes: &[u8]) -> Result<Value, ClassifiedError> {
    let value = parse_classified(bytes)?;
    if canonical(&value).map_err(|message| ClassifiedError {
        code: "release.json.invalid",
        message,
    })? != bytes
    {
        return Err(ClassifiedError {
            code: "release.json.noncanonical",
            message: "JSON input is not canonical with exactly one trailing LF".to_owned(),
        });
    }
    Ok(value)
}

pub(crate) fn canonical(value: &Value) -> Result<Vec<u8>, String> {
    let mut output = String::new();
    render(&mut output, value)?;
    output.push('\n');
    Ok(output.into_bytes())
}

pub(crate) fn member<'a>(
    object: &'a BTreeMap<String, Value>,
    name: &str,
) -> Result<&'a Value, String> {
    object
        .get(name)
        .ok_or_else(|| format!("missing JSON field {name}"))
}

pub(crate) fn exact_keys(
    object: &BTreeMap<String, Value>,
    expected: &[&str],
) -> Result<(), String> {
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    let observed = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if expected == observed {
        Ok(())
    } else {
        Err(format!(
            "JSON object keys differ: expected {expected:?}, observed {observed:?}"
        ))
    }
}

pub(crate) fn object<const N: usize>(fields: [(&str, Value); N]) -> Value {
    Value::Object(
        fields
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value))
            .collect(),
    )
}

pub(crate) fn string(value: &str) -> Value {
    Value::String(value.to_owned())
}

pub(crate) const fn number(value: u64) -> Value {
    Value::Number(value)
}

fn render(output: &mut String, value: &Value) -> Result<(), String> {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
        Value::Number(value) => write!(output, "{value}")
            .map_err(|error| format!("cannot render JSON number: {error}"))?,
        Value::String(value) => render_string(output, value),
        Value::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                render(output, value)?;
            }
            output.push(']');
        }
        Value::Object(values) => {
            output.push('{');
            for (index, (name, value)) in values.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                render_string(output, name);
                output.push(':');
                render(output, value)?;
            }
            output.push('}');
        }
    }
    Ok(())
}

fn render_string(output: &mut String, value: &str) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            value if value <= '\u{1f}' => {
                write!(output, "\\u{:04x}", u32::from(value))
                    .expect("writing to String cannot fail");
            }
            value => output.push(value),
        }
    }
    output.push('"');
}

struct Parser<'a> {
    bytes: &'a [u8],
    index: usize,
    members: usize,
    diagnostic_code: Option<&'static str>,
}

impl Parser<'_> {
    fn value(&mut self, depth: usize) -> Result<Value, String> {
        if depth > MAX_JSON_DEPTH {
            return Err("JSON nesting exceeds the independent verifier limit".to_owned());
        }
        self.whitespace();
        match self.peek() {
            Some(b'{') => self.object(depth + 1),
            Some(b'[') => self.array(depth + 1),
            Some(b'"') => self.string().map(Value::String),
            Some(b't') => self.keyword(b"true", Value::Bool(true)),
            Some(b'f') => self.keyword(b"false", Value::Bool(false)),
            Some(b'n') => self.keyword(b"null", Value::Null),
            Some(b'0'..=b'9') => self.number(),
            Some(byte) => Err(format!("unexpected JSON byte {byte:?} at {}", self.index)),
            None => Err("unexpected end of JSON".to_owned()),
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, String> {
        self.take(b'{')?;
        let mut values = BTreeMap::new();
        self.whitespace();
        if self.consume(b'}') {
            return Ok(Value::Object(values));
        }
        loop {
            self.bump_member()?;
            self.whitespace();
            let key = self.string()?;
            self.whitespace();
            self.take(b':')?;
            let value = self.value(depth)?;
            if values.insert(key.clone(), value).is_some() {
                self.diagnostic_code = Some("release.json.duplicate-key");
                return Err(format!("duplicate JSON object key {key:?}"));
            }
            self.whitespace();
            if self.consume(b'}') {
                return Ok(Value::Object(values));
            }
            self.take(b',')?;
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, String> {
        self.take(b'[')?;
        let mut values = Vec::new();
        self.whitespace();
        if self.consume(b']') {
            return Ok(Value::Array(values));
        }
        loop {
            self.bump_member()?;
            values.push(self.value(depth)?);
            self.whitespace();
            if self.consume(b']') {
                return Ok(Value::Array(values));
            }
            self.take(b',')?;
        }
    }

    fn bump_member(&mut self) -> Result<(), String> {
        self.members = self
            .members
            .checked_add(1)
            .ok_or_else(|| "JSON member count overflow".to_owned())?;
        if self.members > MAX_JSON_MEMBERS {
            return Err("JSON member count exceeds the independent verifier limit".to_owned());
        }
        Ok(())
    }

    fn string(&mut self) -> Result<String, String> {
        self.take(b'"')?;
        let mut output = String::new();
        loop {
            let byte = self
                .next()
                .ok_or_else(|| "unterminated JSON string".to_owned())?;
            match byte {
                b'"' => return Ok(output),
                b'\\' => self.escape(&mut output)?,
                0..=31 => return Err(format!("control byte in JSON string at {}", self.index)),
                32..=127 => output.push(char::from(byte)),
                _ => self.utf8(byte, &mut output)?,
            }
            if output.len() > MAX_JSON_STRING_BYTES {
                return Err("JSON string exceeds the independent verifier limit".to_owned());
            }
        }
    }

    fn escape(&mut self, output: &mut String) -> Result<(), String> {
        match self
            .next()
            .ok_or_else(|| "unterminated JSON escape".to_owned())?
        {
            b'"' => output.push('"'),
            b'\\' => output.push('\\'),
            b'/' => output.push('/'),
            b'b' => output.push('\u{8}'),
            b'f' => output.push('\u{c}'),
            b'n' => output.push('\n'),
            b'r' => output.push('\r'),
            b't' => output.push('\t'),
            b'u' => {
                let first = self.hex_quad()?;
                let scalar = if (0xd800..=0xdbff).contains(&first) {
                    if self.next() != Some(b'\\') || self.next() != Some(b'u') {
                        return Err("unpaired high surrogate in JSON string".to_owned());
                    }
                    let second = self.hex_quad()?;
                    if !(0xdc00..=0xdfff).contains(&second) {
                        return Err("unpaired high surrogate in JSON string".to_owned());
                    }
                    0x1_0000 + ((first - 0xd800) << 10) + (second - 0xdc00)
                } else if (0xdc00..=0xdfff).contains(&first) {
                    return Err("unpaired low surrogate in JSON string".to_owned());
                } else {
                    first
                };
                output.push(
                    char::from_u32(scalar)
                        .ok_or_else(|| "invalid JSON unicode scalar".to_owned())?,
                );
            }
            _ => return Err(format!("invalid JSON escape at byte {}", self.index)),
        }
        Ok(())
    }

    fn hex_quad(&mut self) -> Result<u32, String> {
        let mut value = 0_u32;
        for _ in 0..4 {
            let byte = self
                .next()
                .ok_or_else(|| "truncated JSON unicode escape".to_owned())?;
            let nibble = match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                _ => return Err("invalid hexadecimal JSON escape".to_owned()),
            };
            value = value
                .checked_mul(16)
                .and_then(|current| current.checked_add(u32::from(nibble)))
                .ok_or_else(|| "JSON unicode escape overflow".to_owned())?;
        }
        Ok(value)
    }

    fn utf8(&mut self, first: u8, output: &mut String) -> Result<(), String> {
        let start = self.index - 1;
        let width = match first {
            0xc2..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf4 => 4,
            _ => return Err("invalid UTF-8 leading byte in JSON string".to_owned()),
        };
        let end = start
            .checked_add(width)
            .ok_or_else(|| "JSON index overflow".to_owned())?;
        let bytes = self
            .bytes
            .get(start..end)
            .ok_or_else(|| "truncated UTF-8 in JSON string".to_owned())?;
        output.push_str(
            std::str::from_utf8(bytes).map_err(|_| "invalid UTF-8 in JSON string".to_owned())?,
        );
        self.index = end;
        Ok(())
    }

    fn number(&mut self) -> Result<Value, String> {
        let start = self.index;
        if self.consume(b'0') {
            if self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                self.diagnostic_code = Some("release.json.noncanonical-integer");
                return Err("JSON integer has a leading zero".to_owned());
            }
        } else {
            while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                self.index += 1;
            }
        }
        let text = std::str::from_utf8(&self.bytes[start..self.index])
            .map_err(|_| "JSON number is not UTF-8".to_owned())?;
        text.parse::<u64>()
            .map(Value::Number)
            .map_err(|_| "JSON integer is out of range".to_owned())
    }

    fn keyword(&mut self, keyword: &[u8], value: Value) -> Result<Value, String> {
        let end = self
            .index
            .checked_add(keyword.len())
            .ok_or_else(|| "JSON index overflow".to_owned())?;
        if self.bytes.get(self.index..end) != Some(keyword) {
            return Err(format!("invalid JSON keyword at byte {}", self.index));
        }
        self.index = end;
        Ok(value)
    }

    fn whitespace(&mut self) {
        while self
            .peek()
            .is_some_and(|byte| matches!(byte, b' ' | b'\n' | b'\r' | b'\t'))
        {
            self.index += 1;
        }
    }

    fn take(&mut self, expected: u8) -> Result<(), String> {
        self.consume(expected)
            .then_some(())
            .ok_or_else(|| format!("expected JSON byte {expected:?} at {}", self.index))
    }

    fn consume(&mut self, expected: u8) -> bool {
        if self.peek() == Some(expected) {
            self.index += 1;
            true
        } else {
            false
        }
    }

    fn next(&mut self) -> Option<u8> {
        let value = self.peek()?;
        self.index += 1;
        Some(value)
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.index).copied()
    }
}
