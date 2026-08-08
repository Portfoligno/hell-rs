//! Strict RFC 8259 JSON parsing helpers for the guest `Value` type.

use std::collections::BTreeMap;

const MAX_DEPTH: usize = 512;

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum JsonNode {
    Null,
    Bool(bool),
    String(String),
    Number(f64),
    Array(Vec<Self>),
    Object(BTreeMap<String, Self>),
}

pub(crate) fn parse(bytes: &[u8]) -> Option<JsonNode> {
    std::str::from_utf8(bytes).ok()?;
    let mut parser = Parser { bytes, offset: 0 };
    let value = parser.value(0)?;
    parser.whitespace();
    (parser.offset == bytes.len()).then_some(value)
}

pub(crate) fn push_string(output: &mut String, value: &str) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{08}' => output.push_str("\\b"),
            '\u{0c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character <= '\u{1f}' => {
                use std::fmt::Write as _;
                write!(output, "\\u{:04x}", u32::from(character))
                    .expect("writing into String cannot fail");
            }
            character => output.push(character),
        }
    }
    output.push('"');
}

struct Parser<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl Parser<'_> {
    fn value(&mut self, depth: usize) -> Option<JsonNode> {
        if depth > MAX_DEPTH {
            return None;
        }
        self.whitespace();
        match self.peek()? {
            b'n' => self.literal(b"null", JsonNode::Null),
            b't' => self.literal(b"true", JsonNode::Bool(true)),
            b'f' => self.literal(b"false", JsonNode::Bool(false)),
            b'"' => self.string().map(JsonNode::String),
            b'[' => self.array(depth + 1),
            b'{' => self.object(depth + 1),
            b'-' | b'0'..=b'9' => self.number().map(JsonNode::Number),
            _ => None,
        }
    }

    fn literal(&mut self, literal: &[u8], value: JsonNode) -> Option<JsonNode> {
        if self.bytes.get(self.offset..self.offset + literal.len())? != literal {
            return None;
        }
        self.offset += literal.len();
        Some(value)
    }

    fn array(&mut self, depth: usize) -> Option<JsonNode> {
        self.consume(b'[')?;
        self.whitespace();
        let mut values = Vec::new();
        if self.take(b']') {
            return Some(JsonNode::Array(values));
        }
        loop {
            values.push(self.value(depth)?);
            self.whitespace();
            if self.take(b']') {
                return Some(JsonNode::Array(values));
            }
            self.consume(b',')?;
        }
    }

    fn object(&mut self, depth: usize) -> Option<JsonNode> {
        self.consume(b'{')?;
        self.whitespace();
        let mut values = BTreeMap::new();
        if self.take(b'}') {
            return Some(JsonNode::Object(values));
        }
        loop {
            self.whitespace();
            let key = self.string()?;
            self.whitespace();
            self.consume(b':')?;
            values.insert(key, self.value(depth)?);
            self.whitespace();
            if self.take(b'}') {
                return Some(JsonNode::Object(values));
            }
            self.consume(b',')?;
        }
    }

    fn number(&mut self) -> Option<f64> {
        let start = self.offset;
        self.take(b'-');
        match self.peek()? {
            b'0' => {
                self.offset += 1;
                if matches!(self.peek(), Some(b'0'..=b'9')) {
                    return None;
                }
            }
            b'1'..=b'9' => {
                self.offset += 1;
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.offset += 1;
                }
            }
            _ => return None,
        }
        if self.take(b'.') {
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return None;
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.offset += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.offset += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.offset += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return None;
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.offset += 1;
            }
        }
        let number = std::str::from_utf8(&self.bytes[start..self.offset])
            .ok()?
            .parse::<f64>()
            .ok()?;
        number.is_finite().then_some(number)
    }

    fn string(&mut self) -> Option<String> {
        self.consume(b'"')?;
        let mut output = String::new();
        loop {
            let byte = self.peek()?;
            match byte {
                b'"' => {
                    self.offset += 1;
                    return Some(output);
                }
                b'\\' => {
                    self.offset += 1;
                    self.escape(&mut output)?;
                }
                0x00..=0x1f => return None,
                0x20..=0x7f => {
                    output.push(char::from(byte));
                    self.offset += 1;
                }
                _ => {
                    let tail = std::str::from_utf8(&self.bytes[self.offset..]).ok()?;
                    let character = tail.chars().next()?;
                    output.push(character);
                    self.offset += character.len_utf8();
                }
            }
        }
    }

    fn escape(&mut self, output: &mut String) -> Option<()> {
        let escaped = self.peek()?;
        self.offset += 1;
        match escaped {
            b'"' => output.push('"'),
            b'\\' => output.push('\\'),
            b'/' => output.push('/'),
            b'b' => output.push('\u{08}'),
            b'f' => output.push('\u{0c}'),
            b'n' => output.push('\n'),
            b'r' => output.push('\r'),
            b't' => output.push('\t'),
            b'u' => {
                let first = self.hex_quad()?;
                let scalar = if (0xd800..=0xdbff).contains(&first) {
                    self.consume(b'\\')?;
                    self.consume(b'u')?;
                    let second = self.hex_quad()?;
                    if !(0xdc00..=0xdfff).contains(&second) {
                        return None;
                    }
                    0x1_0000 + ((first - 0xd800) << 10) + (second - 0xdc00)
                } else if (0xdc00..=0xdfff).contains(&first) {
                    return None;
                } else {
                    first
                };
                output.push(char::from_u32(scalar)?);
            }
            _ => return None,
        }
        Some(())
    }

    fn hex_quad(&mut self) -> Option<u32> {
        let mut value = 0_u32;
        for _ in 0..4 {
            value = value.checked_mul(16)? + char::from(self.peek()?).to_digit(16)?;
            self.offset += 1;
        }
        Some(value)
    }

    fn whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.offset += 1;
        }
    }

    fn consume(&mut self, expected: u8) -> Option<()> {
        if self.peek()? != expected {
            return None;
        }
        self.offset += 1;
        Some(())
    }

    fn take(&mut self, expected: u8) -> bool {
        if self.peek() == Some(expected) {
            self.offset += 1;
            true
        } else {
            false
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.offset).copied()
    }
}
