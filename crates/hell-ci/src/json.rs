use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum JsonValue {
    Null,
    Bool(bool),
    Number(u64),
    String(String),
    Array(Vec<Self>),
    Object(BTreeMap<String, Self>),
}

impl JsonValue {
    pub(crate) fn object(&self) -> Result<&BTreeMap<String, Self>, String> {
        match self {
            Self::Object(value) => Ok(value),
            _ => Err("expected JSON object".to_owned()),
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

    pub(crate) fn array(&self) -> Result<&[Self], String> {
        match self {
            Self::Array(value) => Ok(value),
            _ => Err("expected JSON array".to_owned()),
        }
    }
}

pub(crate) fn parse_json(document: &str) -> Result<JsonValue, String> {
    let document = crate::fuzz_surfaces::strict_json_record(document.as_bytes())?;
    let mut parser = JsonParser {
        bytes: document.as_bytes(),
        index: 0,
    };
    let value = parser.value()?;
    parser.whitespace();
    if parser.index != parser.bytes.len() {
        return Err(format!("trailing JSON data at byte {}", parser.index));
    }
    Ok(value)
}

pub(crate) fn canonical_json_bytes(value: &JsonValue) -> Result<Vec<u8>, String> {
    let mut output = String::new();
    push_json_value(&mut output, value)?;
    output.push('\n');
    Ok(output.into_bytes())
}

pub(crate) fn json_member<'a>(
    object: &'a BTreeMap<String, JsonValue>,
    name: &str,
) -> Result<&'a JsonValue, String> {
    object
        .get(name)
        .ok_or_else(|| format!("missing JSON field {name}"))
}

pub(crate) fn require_exact_json_keys(
    object: &BTreeMap<String, JsonValue>,
    expected: &[&str],
) -> Result<(), String> {
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    let observed = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if observed == expected {
        Ok(())
    } else {
        Err(format!(
            "JSON object keys differ: expected {expected:?}, observed {observed:?}"
        ))
    }
}

fn push_json_string(output: &mut String, value: &str) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character <= '\u{1f}' => {
                write!(output, "\\u{:04x}", u32::from(character))
                    .expect("writing to String cannot fail");
            }
            character => output.push(character),
        }
    }
    output.push('"');
}

fn push_json_value(output: &mut String, value: &JsonValue) -> Result<(), String> {
    match value {
        JsonValue::Null => output.push_str("null"),
        JsonValue::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
        JsonValue::Number(value) => write!(output, "{value}")
            .map_err(|error| format!("cannot serialize JSON number: {error}"))?,
        JsonValue::String(value) => push_json_string(output, value),
        JsonValue::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                push_json_value(output, value)?;
            }
            output.push(']');
        }
        JsonValue::Object(values) => {
            output.push('{');
            for (index, (key, value)) in values.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                push_json_string(output, key);
                output.push(':');
                push_json_value(output, value)?;
            }
            output.push('}');
        }
    }
    Ok(())
}

struct JsonParser<'a> {
    bytes: &'a [u8],
    index: usize,
}

impl JsonParser<'_> {
    fn value(&mut self) -> Result<JsonValue, String> {
        self.whitespace();
        match self.peek() {
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => self.string().map(JsonValue::String),
            Some(b't') => self.keyword(b"true", JsonValue::Bool(true)),
            Some(b'f') => self.keyword(b"false", JsonValue::Bool(false)),
            Some(b'n') => self.keyword(b"null", JsonValue::Null),
            Some(b'0'..=b'9') => self.number(),
            Some(byte) => Err(format!("unexpected JSON byte {byte:?} at {}", self.index)),
            None => Err("unexpected end of JSON".to_owned()),
        }
    }

    fn object(&mut self) -> Result<JsonValue, String> {
        self.take(b'{')?;
        let mut values = BTreeMap::new();
        self.whitespace();
        if self.consume(b'}') {
            return Ok(JsonValue::Object(values));
        }
        loop {
            self.whitespace();
            let key = self.string()?;
            self.whitespace();
            self.take(b':')?;
            let value = self.value()?;
            if values.insert(key.clone(), value).is_some() {
                return Err(format!("duplicate JSON object key {key:?}"));
            }
            self.whitespace();
            if self.consume(b'}') {
                break;
            }
            self.take(b',')?;
        }
        Ok(JsonValue::Object(values))
    }

    fn array(&mut self) -> Result<JsonValue, String> {
        self.take(b'[')?;
        let mut values = Vec::new();
        self.whitespace();
        if self.consume(b']') {
            return Ok(JsonValue::Array(values));
        }
        loop {
            values.push(self.value()?);
            self.whitespace();
            if self.consume(b']') {
                break;
            }
            self.take(b',')?;
        }
        Ok(JsonValue::Array(values))
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
        }
    }

    fn escape(&mut self, output: &mut String) -> Result<(), String> {
        let escaped = self
            .next()
            .ok_or_else(|| "unterminated JSON escape".to_owned())?;
        match escaped {
            b'"' => output.push('"'),
            b'\\' => output.push('\\'),
            b'/' => output.push('/'),
            b'b' => output.push('\u{8}'),
            b'f' => output.push('\u{c}'),
            b'n' => output.push('\n'),
            b'r' => output.push('\r'),
            b't' => output.push('\t'),
            b'u' => output.push(self.unicode_escape()?),
            _ => return Err(format!("invalid JSON escape at byte {}", self.index)),
        }
        Ok(())
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

    fn unicode_escape(&mut self) -> Result<char, String> {
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
                .and_then(|value| value.checked_add(u32::from(nibble)))
                .ok_or_else(|| "JSON unicode escape overflow".to_owned())?;
        }
        char::from_u32(value).ok_or_else(|| "invalid JSON unicode scalar".to_owned())
    }

    fn number(&mut self) -> Result<JsonValue, String> {
        let start = self.index;
        if self.consume(b'0') {
            if self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
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
            .map(JsonValue::Number)
            .map_err(|_| "JSON integer is out of range".to_owned())
    }

    fn keyword(&mut self, keyword: &[u8], value: JsonValue) -> Result<JsonValue, String> {
        let end = self.index.saturating_add(keyword.len());
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

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.index).copied()
    }

    fn next(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.index += 1;
        Some(byte)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_round_trip_is_stable_and_rejects_duplicate_keys() {
        let value = parse_json("{\"z\":2,\"a\":[true,null,\"x\"]}").unwrap();
        let bytes = canonical_json_bytes(&value).unwrap();
        assert_eq!(bytes, b"{\"a\":[true,null,\"x\"],\"z\":2}\n");
        assert_eq!(
            parse_json(std::str::from_utf8(&bytes).unwrap()).unwrap(),
            value
        );
        assert!(parse_json("{\"a\":1,\"a\":2}").is_err());
    }
}
