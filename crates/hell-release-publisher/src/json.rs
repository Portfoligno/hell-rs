use std::collections::BTreeSet;

use serde_json::Value;

use crate::Failure;

pub fn parse(bytes: &[u8], code: &'static str) -> Result<Value, Failure> {
    let mut parser = Validator { bytes, offset: 0 };
    parser.whitespace();
    parser.value(code)?;
    parser.whitespace();
    if parser.offset != bytes.len() {
        return Err(Failure::new(code, "JSON has trailing non-whitespace bytes"));
    }
    serde_json::from_slice(bytes)
        .map_err(|error| Failure::new(code, format!("cannot parse JSON: {error}")))
}

struct Validator<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl Validator<'_> {
    fn value(&mut self, code: &'static str) -> Result<(), Failure> {
        self.whitespace();
        match self.bytes.get(self.offset) {
            Some(b'{') => self.object(code),
            Some(b'[') => self.array(code),
            Some(b'"') => self.string(code).map(|_| ()),
            Some(b't') => self.literal(b"true", code),
            Some(b'f') => self.literal(b"false", code),
            Some(b'n') => self.literal(b"null", code),
            Some(b'-' | b'0'..=b'9') => self.number(code),
            _ => Err(Failure::new(code, "JSON contains an invalid value")),
        }
    }

    fn object(&mut self, code: &'static str) -> Result<(), Failure> {
        self.offset += 1;
        let mut keys = BTreeSet::new();
        self.whitespace();
        if self.consume(b'}') {
            return Ok(());
        }
        loop {
            let key = self.string(code)?;
            if !keys.insert(key) {
                return Err(Failure::new(code, "JSON object contains a duplicate key"));
            }
            self.whitespace();
            self.expect(b':', code)?;
            self.value(code)?;
            self.whitespace();
            if self.consume(b'}') {
                return Ok(());
            }
            self.expect(b',', code)?;
            self.whitespace();
        }
    }

    fn array(&mut self, code: &'static str) -> Result<(), Failure> {
        self.offset += 1;
        self.whitespace();
        if self.consume(b']') {
            return Ok(());
        }
        loop {
            self.value(code)?;
            self.whitespace();
            if self.consume(b']') {
                return Ok(());
            }
            self.expect(b',', code)?;
        }
    }

    fn string(&mut self, code: &'static str) -> Result<Vec<u8>, Failure> {
        self.expect(b'"', code)?;
        let mut decoded = Vec::new();
        loop {
            let byte = *self
                .bytes
                .get(self.offset)
                .ok_or_else(|| Failure::new(code, "JSON string is unterminated"))?;
            self.offset += 1;
            match byte {
                b'"' => return Ok(decoded),
                b'\\' => {
                    let escaped = *self
                        .bytes
                        .get(self.offset)
                        .ok_or_else(|| Failure::new(code, "JSON escape is unterminated"))?;
                    self.offset += 1;
                    decoded.extend([b'\\', escaped]);
                    if escaped == b'u' {
                        for _ in 0..4 {
                            let hex = *self.bytes.get(self.offset).ok_or_else(|| {
                                Failure::new(code, "JSON Unicode escape is truncated")
                            })?;
                            if !hex.is_ascii_hexdigit() {
                                return Err(Failure::new(code, "JSON Unicode escape is invalid"));
                            }
                            decoded.push(hex);
                            self.offset += 1;
                        }
                    } else if !matches!(
                        escaped,
                        b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't'
                    ) {
                        return Err(Failure::new(code, "JSON escape is invalid"));
                    }
                }
                0..=31 => return Err(Failure::new(code, "JSON string has a control byte")),
                _ => decoded.push(byte),
            }
        }
    }

    fn number(&mut self, code: &'static str) -> Result<(), Failure> {
        let start = self.offset;
        while self.bytes.get(self.offset).is_some_and(|byte| {
            byte.is_ascii_digit() || matches!(byte, b'-' | b'+' | b'.' | b'e' | b'E')
        }) {
            self.offset += 1;
        }
        serde_json::from_slice::<Value>(&self.bytes[start..self.offset])
            .map(|_| ())
            .map_err(|_| Failure::new(code, "JSON number is invalid"))
    }

    fn literal(&mut self, value: &[u8], code: &'static str) -> Result<(), Failure> {
        if self.bytes.get(self.offset..self.offset + value.len()) != Some(value) {
            return Err(Failure::new(code, "JSON literal is invalid"));
        }
        self.offset += value.len();
        Ok(())
    }

    fn whitespace(&mut self) {
        while self
            .bytes
            .get(self.offset)
            .is_some_and(u8::is_ascii_whitespace)
        {
            self.offset += 1;
        }
    }

    fn expect(&mut self, byte: u8, code: &'static str) -> Result<(), Failure> {
        if self.consume(byte) {
            Ok(())
        } else {
            Err(Failure::new(code, "JSON punctuation is invalid"))
        }
    }

    fn consume(&mut self, byte: u8) -> bool {
        if self.bytes.get(self.offset) == Some(&byte) {
            self.offset += 1;
            true
        } else {
            false
        }
    }
}
