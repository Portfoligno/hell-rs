//! Strict RFC 8259 JSON parsing helpers for the guest `Value` type.

use std::collections::BTreeMap;

use crate::native_integer::BigInteger;

#[cfg(test)]
const MAX_DEPTH: usize = 512;

/// Exact decimal number parsed from JSON source.
#[derive(Clone, Debug)]
pub struct JsonNumber {
    coefficient: BigInteger,
    exponent10: i64,
    lexeme: String,
}

impl PartialEq for JsonNumber {
    fn eq(&self, other: &Self) -> bool {
        self.normalized_parts() == other.normalized_parts()
    }
}

impl Eq for JsonNumber {}

impl JsonNumber {
    fn normalized_parts(&self) -> (BigInteger, i64) {
        let mut coefficient = self.coefficient.clone();
        let mut exponent10 = self.exponent10;
        if coefficient.to_string() == "0" {
            return (coefficient, 0);
        }
        loop {
            let (quotient, remainder) = coefficient.div_rem_euclid_small(10);
            if remainder != 0 {
                return (coefficient, exponent10);
            }
            coefficient = quotient;
            let Some(next_exponent) = exponent10.checked_add(1) else {
                return (coefficient, exponent10);
            };
            exponent10 = next_exponent;
        }
    }

    #[must_use]
    pub(crate) fn to_f64(&self) -> f64 {
        self.lexeme
            .parse::<f64>()
            .expect("a validated JSON number remains a valid floating-point literal")
    }

    pub(crate) fn push_json(&self, output: &mut String) {
        let mut coefficient = self.coefficient.clone();
        let mut exponent10 = self.exponent10;
        while exponent10 < -1 && coefficient.to_string() != "0" {
            let (quotient, remainder) = coefficient.div_rem_euclid_small(10);
            if remainder != 0 {
                break;
            }
            coefficient = quotient;
            exponent10 += 1;
        }
        let coefficient = coefficient.to_string();
        let (sign, digits) = coefficient
            .strip_prefix('-')
            .map_or(("", coefficient.as_str()), |digits| ("-", digits));
        output.push_str(sign);
        if digits == "0" {
            output.push_str(if exponent10 < 0 { "0.0" } else { "0" });
            return;
        }

        if exponent10 >= 0 {
            output.push_str(digits);
            for _ in 0..exponent10 {
                output.push('0');
            }
            return;
        }

        let decimal_position = i128::try_from(digits.len()).expect("string length fits in i128")
            + i128::from(exponent10);
        if decimal_position >= 0 {
            let decimal_position = usize::try_from(decimal_position)
                .expect("a nonnegative position within the coefficient fits in usize");
            if decimal_position == 0 {
                output.push_str("0.");
                output.push_str(digits);
            } else {
                output.push_str(&digits[..decimal_position]);
                output.push('.');
                output.push_str(&digits[decimal_position..]);
            }
            return;
        }

        let first_length = digits
            .chars()
            .next()
            .expect("a JSON coefficient always has at least one digit")
            .len_utf8();
        let (first, rest) = digits.split_at(first_length);
        output.push_str(first);
        output.push('.');
        output.push_str(if rest.is_empty() { "0" } else { rest });
        output.push('e');
        output.push_str(&(decimal_position - 1).to_string());
    }

    #[must_use]
    pub(crate) fn as_json(&self) -> &str {
        &self.lexeme
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum JsonNode {
    Null,
    Bool(bool),
    String(String),
    Number(JsonNumber),
    Array(Vec<Self>),
    Object(BTreeMap<String, Self>),
}

impl Drop for JsonNode {
    fn drop(&mut self) {
        let mut pending = Vec::new();
        match self {
            Self::Array(values) => pending.append(values),
            Self::Object(values) => pending.extend(std::mem::take(values).into_values()),
            Self::Null | Self::Bool(_) | Self::String(_) | Self::Number(_) => return,
        }
        while let Some(mut value) = pending.pop() {
            match &mut value {
                Self::Array(values) => pending.append(values),
                Self::Object(values) => pending.extend(std::mem::take(values).into_values()),
                Self::Null | Self::Bool(_) | Self::String(_) | Self::Number(_) => {}
            }
        }
    }
}

/// Flat, shareable representation of one decoded JSON document.
#[derive(Clone, Debug)]
pub struct JsonDocument {
    nodes: std::sync::Arc<[JsonDocumentNode]>,
    root: usize,
}

#[derive(Clone, Debug)]
pub(crate) enum JsonDocumentNode {
    Null,
    Bool(bool),
    String(String),
    Number(JsonNumber),
    Array(std::sync::Arc<[usize]>),
    Object(std::sync::Arc<[(String, usize)]>),
}

impl JsonDocument {
    pub(crate) fn from_node(node: JsonNode) -> Self {
        enum Task {
            Visit(JsonNode),
            FinishArray(usize),
            FinishObject(Vec<String>),
        }

        let mut tasks = vec![Task::Visit(node)];
        let mut nodes = Vec::new();
        let mut completed = Vec::new();
        while let Some(task) = tasks.pop() {
            match task {
                Task::Visit(mut node) => match &mut node {
                    JsonNode::Null => {
                        push_document_node(&mut nodes, &mut completed, JsonDocumentNode::Null);
                    }
                    JsonNode::Bool(value) => push_document_node(
                        &mut nodes,
                        &mut completed,
                        JsonDocumentNode::Bool(*value),
                    ),
                    JsonNode::String(value) => push_document_node(
                        &mut nodes,
                        &mut completed,
                        JsonDocumentNode::String(std::mem::take(value)),
                    ),
                    JsonNode::Number(value) => push_document_node(
                        &mut nodes,
                        &mut completed,
                        JsonDocumentNode::Number(value.clone()),
                    ),
                    JsonNode::Array(values) => {
                        let values = std::mem::take(values);
                        tasks.push(Task::FinishArray(values.len()));
                        tasks.extend(values.into_iter().rev().map(Task::Visit));
                    }
                    JsonNode::Object(values) => {
                        let (keys, values): (Vec<_>, Vec<_>) =
                            std::mem::take(values).into_iter().unzip();
                        tasks.push(Task::FinishObject(keys));
                        tasks.extend(values.into_iter().rev().map(Task::Visit));
                    }
                },
                Task::FinishArray(length) => {
                    let start = completed
                        .len()
                        .checked_sub(length)
                        .expect("JSON array has every child node");
                    let children = completed.drain(start..).collect::<Vec<_>>();
                    push_document_node(
                        &mut nodes,
                        &mut completed,
                        JsonDocumentNode::Array(children.into()),
                    );
                }
                Task::FinishObject(keys) => {
                    let start = completed
                        .len()
                        .checked_sub(keys.len())
                        .expect("JSON object has every child node");
                    let entries = keys
                        .into_iter()
                        .zip(completed.drain(start..))
                        .collect::<Vec<_>>();
                    push_document_node(
                        &mut nodes,
                        &mut completed,
                        JsonDocumentNode::Object(entries.into()),
                    );
                }
            }
        }
        let root = completed
            .pop()
            .expect("one JSON root produces one document node");
        Self {
            nodes: nodes.into(),
            root,
        }
    }

    #[must_use]
    pub(crate) fn root(&self) -> usize {
        self.root
    }

    pub(crate) fn node(&self, index: usize) -> Option<&JsonDocumentNode> {
        self.nodes.get(index)
    }
}

fn push_document_node(
    nodes: &mut Vec<JsonDocumentNode>,
    completed: &mut Vec<usize>,
    node: JsonDocumentNode,
) {
    let index = nodes.len();
    nodes.push(node);
    completed.push(index);
}

#[cfg(test)]
pub(crate) fn parse(bytes: &[u8]) -> Option<JsonNode> {
    parse_with_limits(bytes, Some(MAX_DEPTH), None)
}

#[cfg(test)]
pub(crate) fn parse_with_max_depth(bytes: &[u8], max_depth: Option<usize>) -> Option<JsonNode> {
    parse_with_limits(bytes, max_depth, None)
}

pub(crate) fn parse_with_limits(
    bytes: &[u8],
    max_depth: Option<usize>,
    max_nodes: Option<u64>,
) -> Option<JsonNode> {
    std::str::from_utf8(bytes).ok()?;
    let mut parser = Parser {
        bytes,
        offset: 0,
        max_depth,
        max_nodes,
    };
    let mut node_count = 0_u64;
    let mut frames = Vec::new();
    let mut next = parser.start_value(0, &mut node_count)?;
    let value = 'document: loop {
        match next {
            ValueStart::Container(frame) => {
                frames.push(frame);
                next = parser.start_value(frames.len(), &mut node_count)?;
            }
            ValueStart::Complete(mut value) => loop {
                let Some(frame) = frames.last_mut() else {
                    break 'document value;
                };
                let closes = match frame {
                    ContainerFrame::Array(values) => {
                        values.push(value);
                        parser.whitespace();
                        parser.take(b']')
                    }
                    ContainerFrame::Object { values, key } => {
                        values.insert(std::mem::take(key), value);
                        parser.whitespace();
                        parser.take(b'}')
                    }
                };
                if closes {
                    value = match frames.pop()? {
                        ContainerFrame::Array(values) => JsonNode::Array(values),
                        ContainerFrame::Object { values, .. } => JsonNode::Object(values),
                    };
                    continue;
                }

                parser.consume(b',')?;
                if let Some(ContainerFrame::Object { key, .. }) = frames.last_mut() {
                    parser.whitespace();
                    *key = parser.string()?;
                    parser.whitespace();
                    parser.consume(b':')?;
                }
                next = parser.start_value(frames.len(), &mut node_count)?;
                break;
            },
        }
    };
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
    max_depth: Option<usize>,
    max_nodes: Option<u64>,
}

enum ValueStart {
    Complete(JsonNode),
    Container(ContainerFrame),
}

enum ContainerFrame {
    Array(Vec<JsonNode>),
    Object {
        values: BTreeMap<String, JsonNode>,
        key: String,
    },
}

impl Parser<'_> {
    fn start_value(&mut self, depth: usize, node_count: &mut u64) -> Option<ValueStart> {
        if self.max_depth.is_some_and(|limit| depth > limit) {
            return None;
        }
        *node_count = node_count.checked_add(1)?;
        if self.max_nodes.is_some_and(|limit| *node_count > limit) {
            return None;
        }
        self.whitespace();
        match self.peek()? {
            b'n' => self
                .literal(b"null", JsonNode::Null)
                .map(ValueStart::Complete),
            b't' => self
                .literal(b"true", JsonNode::Bool(true))
                .map(ValueStart::Complete),
            b'f' => self
                .literal(b"false", JsonNode::Bool(false))
                .map(ValueStart::Complete),
            b'"' => self
                .string()
                .map(JsonNode::String)
                .map(ValueStart::Complete),
            b'[' => {
                self.consume(b'[')?;
                self.whitespace();
                if self.take(b']') {
                    Some(ValueStart::Complete(JsonNode::Array(Vec::new())))
                } else {
                    Some(ValueStart::Container(ContainerFrame::Array(Vec::new())))
                }
            }
            b'{' => {
                self.consume(b'{')?;
                self.whitespace();
                if self.take(b'}') {
                    Some(ValueStart::Complete(JsonNode::Object(BTreeMap::new())))
                } else {
                    let key = self.string()?;
                    self.whitespace();
                    self.consume(b':')?;
                    Some(ValueStart::Container(ContainerFrame::Object {
                        values: BTreeMap::new(),
                        key,
                    }))
                }
            }
            b'-' | b'0'..=b'9' => self
                .number()
                .map(JsonNode::Number)
                .map(ValueStart::Complete),
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

    fn number(&mut self) -> Option<JsonNumber> {
        let start = self.offset;
        let negative = self.take(b'-');
        let digits_start = self.offset;
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
        let integer_end = self.offset;
        let mut fraction_start = None;
        let mut fraction_end = integer_end;
        if self.take(b'.') {
            fraction_start = Some(self.offset);
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return None;
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.offset += 1;
            }
            fraction_end = self.offset;
        }
        let exponent_marker = self.offset;
        let mut explicit_exponent = 0_i64;
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.offset += 1;
            let exponent_negative = self.take(b'-');
            if !exponent_negative {
                self.take(b'+');
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return None;
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                explicit_exponent = explicit_exponent
                    .checked_mul(10)?
                    .checked_add(i64::from(self.peek()? - b'0'))?;
                self.offset += 1;
            }
            if exponent_negative {
                explicit_exponent = explicit_exponent.checked_neg()?;
            }
        }
        let fraction_digits =
            fraction_start.map_or(Some(0), |start| fraction_end.checked_sub(start))?;
        let fraction_digits = i64::try_from(fraction_digits).ok()?;
        let exponent10 = explicit_exponent.checked_sub(fraction_digits)?;
        let mut coefficient_text = String::new();
        if negative {
            coefficient_text.push('-');
        }
        coefficient_text
            .push_str(std::str::from_utf8(&self.bytes[digits_start..integer_end]).ok()?);
        if let Some(start) = fraction_start {
            coefficient_text.push_str(std::str::from_utf8(&self.bytes[start..fraction_end]).ok()?);
        }
        let coefficient = BigInteger::parse(&coefficient_text)?;
        let lexeme = std::str::from_utf8(&self.bytes[start..self.offset])
            .ok()?
            .to_owned();
        debug_assert!(exponent_marker <= self.offset);
        Some(JsonNumber {
            coefficient,
            exponent10,
            lexeme,
        })
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

#[cfg(test)]
mod tests {
    use super::{JsonNode, parse, parse_with_limits, parse_with_max_depth};

    fn number(source: &str) -> super::JsonNumber {
        let parsed = parse(source.as_bytes()).expect("valid JSON number");
        let JsonNode::Number(number) = &parsed else {
            panic!("JSON source did not parse as a number");
        };
        number.clone()
    }

    #[test]
    fn numbers_outside_f64_range_remain_exact_and_encodable() {
        let huge = format!("1{}", "0".repeat(400));
        for (source, expected) in [
            ("9007199254740993", "9007199254740993"),
            ("1e400", huge.as_str()),
            ("1e-10000", "1.0e-10000"),
            ("-0.0", "0.0"),
            ("1.2300", "1.23"),
            ("123.4500", "123.45"),
            ("1e-1", "0.1"),
            ("1e-2", "1.0e-2"),
            ("1.0", "1.0"),
            ("10.0", "10.0"),
            ("1.00", "1.0"),
            ("100.00", "100.0"),
            ("0.00", "0.0"),
            ("0e400", "0"),
            ("0e-400", "0.0"),
        ] {
            let number = number(source);
            let mut encoded = String::new();
            number.push_json(&mut encoded);
            assert_eq!(encoded, expected);
        }
        assert!(number("1e400").to_f64().is_infinite());
        assert_eq!(number("1e-10000").to_f64().to_bits(), 0.0_f64.to_bits());
        assert_eq!(number("1"), number("1.0"));
        assert_eq!(number("0"), number("-0.0"));
    }

    #[test]
    fn depth_limit_is_explicit_policy() {
        let source = b"[[[null]]]";
        assert!(parse_with_max_depth(source, Some(2)).is_none());
        assert!(parse_with_max_depth(source, Some(3)).is_some());
        assert!(parse_with_max_depth(source, None).is_some());

        let source = b"[null,null]";
        assert!(parse_with_limits(source, None, Some(2)).is_none());
        assert!(parse_with_limits(source, None, Some(3)).is_some());
    }

    #[test]
    fn deeply_nested_input_uses_an_explicit_frame_stack() {
        let depth = 20_000;
        let source = format!("{}null{}", "[".repeat(depth), "]".repeat(depth));
        let parsed = parse_with_limits(source.as_bytes(), None, None)
            .expect("deep upstream-profile JSON remains parseable");
        drop(parsed);
    }
}
