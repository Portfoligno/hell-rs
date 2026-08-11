//! Shared byte-level admission surfaces used by production parsers and fuzzers.

use std::collections::BTreeSet;

const MAX_RETAINED_JSON_BYTES: usize = 64 * 1024 * 1024;

pub(crate) fn strict_json_record(bytes: &[u8]) -> Result<&str, String> {
    if bytes.len() > MAX_RETAINED_JSON_BYTES {
        return Err("retained JSON record exceeds the bounded parser size".to_owned());
    }
    let document = std::str::from_utf8(bytes)
        .map_err(|_| "retained JSON record is not canonical UTF-8".to_owned())?;
    if document.as_bytes().contains(&0) {
        return Err("retained JSON record contains NUL".to_owned());
    }
    let mut parser = StructuralJson { bytes, index: 0 };
    parser.value(0)?;
    parser.whitespace();
    if parser.index != bytes.len() {
        return Err("retained JSON record has trailing bytes".to_owned());
    }
    Ok(document)
}

struct StructuralJson<'a> {
    bytes: &'a [u8],
    index: usize,
}

impl StructuralJson<'_> {
    fn value(&mut self, depth: usize) -> Result<(), String> {
        if depth > 256 {
            return Err("retained JSON nesting exceeds the parser bound".to_owned());
        }
        self.whitespace();
        match self.peek() {
            Some(b'{') => self.object(depth + 1),
            Some(b'[') => self.array(depth + 1),
            Some(b'"') => self.string().map(|_| ()),
            Some(b't') => self.keyword(b"true"),
            Some(b'f') => self.keyword(b"false"),
            Some(b'n') => self.keyword(b"null"),
            Some(b'0'..=b'9') => self.number(),
            _ => Err("retained JSON value is malformed".to_owned()),
        }
    }

    fn object(&mut self, depth: usize) -> Result<(), String> {
        self.take(b'{')?;
        self.whitespace();
        if self.consume(b'}') {
            return Ok(());
        }
        let mut keys = BTreeSet::new();
        loop {
            self.whitespace();
            let key = self.string()?;
            if !keys.insert(key) {
                return Err("retained JSON object repeats a key".to_owned());
            }
            self.whitespace();
            self.take(b':')?;
            self.value(depth)?;
            self.whitespace();
            if self.consume(b'}') {
                return Ok(());
            }
            self.take(b',')?;
        }
    }

    fn array(&mut self, depth: usize) -> Result<(), String> {
        self.take(b'[')?;
        self.whitespace();
        if self.consume(b']') {
            return Ok(());
        }
        loop {
            self.value(depth)?;
            self.whitespace();
            if self.consume(b']') {
                return Ok(());
            }
            self.take(b',')?;
        }
    }

    fn string(&mut self) -> Result<String, String> {
        self.take(b'"')?;
        let start = self.index;
        let mut escaped = false;
        loop {
            let byte = self
                .next()
                .ok_or_else(|| "unterminated retained JSON string".to_owned())?;
            match byte {
                b'"' if !escaped => {
                    return std::str::from_utf8(&self.bytes[start..self.index - 1])
                        .map(str::to_owned)
                        .map_err(|_| "retained JSON string is not UTF-8".to_owned());
                }
                b'\\' if !escaped => escaped = true,
                b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' if escaped => {
                    escaped = false;
                }
                b'u' if escaped => {
                    for _ in 0..4 {
                        let nibble = self
                            .next()
                            .ok_or_else(|| "truncated retained JSON escape".to_owned())?;
                        if !nibble.is_ascii_hexdigit() {
                            return Err("retained JSON escape is invalid".to_owned());
                        }
                    }
                    escaped = false;
                }
                _ if escaped || byte < 0x20 => {
                    return Err("retained JSON string escape is invalid".to_owned());
                }
                _ => {}
            }
        }
    }

    fn number(&mut self) -> Result<(), String> {
        let start = self.index;
        if self.consume(b'0') {
            if self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                return Err("retained JSON integer has a leading zero".to_owned());
            }
        } else {
            while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                self.index += 1;
            }
        }
        std::str::from_utf8(&self.bytes[start..self.index])
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| "retained JSON integer is out of range".to_owned())?;
        Ok(())
    }

    fn keyword(&mut self, keyword: &[u8]) -> Result<(), String> {
        let end = self.index.saturating_add(keyword.len());
        if self.bytes.get(self.index..end) != Some(keyword) {
            return Err("retained JSON keyword is invalid".to_owned());
        }
        self.index = end;
        Ok(())
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
        if self.consume(expected) {
            Ok(())
        } else {
            Err("retained JSON delimiter is invalid".to_owned())
        }
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
