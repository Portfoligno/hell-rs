//! Lexer, Haskell layout normalization, and parser for the supported surface.

use std::fmt;
use std::sync::Arc;

use hell_source::{SourceFile, Span};

#[derive(Clone, Debug, PartialEq)]
pub enum TokenKind {
    Lower(Arc<str>),
    Upper(Arc<str>),
    Qualified(Arc<str>),
    Operator(Arc<str>),
    Integer(Arc<str>),
    Fraction(Arc<str>),
    Character(char),
    Text(Arc<str>),
    KwCase,
    KwData,
    KwDo,
    KwElse,
    KwIf,
    KwLet,
    KwOf,
    KwThen,
    LParen,
    RParen,
    LBracket,
    RBracket,
    LBrace,
    RBrace,
    Comma,
    Semicolon,
    Equals,
    Backslash,
    Arrow,
    BindArrow,
    DoubleColon,
    At,
    Pipe,
    Underscore,
    VirtualLBrace,
    VirtualRBrace,
    VirtualSemicolon,
    Eof,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Token {
    pub kind: TokenKind,
    pub span: Span,
    pub starts_line: bool,
    /// One-based display column with tabs expanded to eight-column stops.
    pub column: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyntaxError {
    pub code: &'static str,
    pub message: Arc<str>,
    pub span: Span,
}

impl SyntaxError {
    fn lex(message: impl Into<Arc<str>>, span: Span) -> Self {
        Self {
            code: "H0100",
            message: message.into(),
            span,
        }
    }

    fn parse(message: impl Into<Arc<str>>, span: Span) -> Self {
        Self {
            code: "H0200",
            message: message.into(),
            span,
        }
    }

    fn resource_limit(message: impl Into<Arc<str>>, span: Span) -> Self {
        Self {
            code: "H0801",
            message: message.into(),
            span,
        }
    }

    fn resource(code: &'static str, message: impl Into<Arc<str>>, span: Span) -> Self {
        Self {
            code,
            message: message.into(),
            span,
        }
    }
}

impl fmt::Display for SyntaxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for SyntaxError {}

fn span(source: &SourceFile, start: usize, end: usize) -> Span {
    Span::new(
        source.id,
        u32::try_from(start).unwrap_or(u32::MAX),
        u32::try_from(end).unwrap_or(u32::MAX),
    )
}

struct Lexer<'a> {
    source: &'a SourceFile,
    bytes: &'a [u8],
    at: usize,
    line_start: usize,
    saw_token_on_line: bool,
    errors: Vec<SyntaxError>,
}

impl<'a> Lexer<'a> {
    fn new(source: &'a SourceFile) -> Self {
        let at = source.shebang.map_or(0, |value| value.end as usize);
        Self {
            source,
            bytes: source.bytes.as_ref(),
            at,
            line_start: 0,
            saw_token_on_line: false,
            errors: Vec::new(),
        }
    }

    fn visual_column(&self, at: usize) -> u32 {
        let mut column = 1_u32;
        let text = std::str::from_utf8(&self.bytes[self.line_start..at]).expect("validated source");
        for character in text.chars() {
            column = if character == '\t' {
                ((column - 1) / 8 + 1) * 8 + 1
            } else {
                column.saturating_add(1)
            };
        }
        column
    }

    fn skip_trivia(&mut self) {
        loop {
            match self.bytes.get(self.at) {
                Some(b' ' | b'\r' | b'\t') => self.at += 1,
                Some(b'\n') => {
                    self.at += 1;
                    self.line_start = self.at;
                    self.saw_token_on_line = false;
                }
                Some(b'-') if self.bytes.get(self.at + 1) == Some(&b'-') => {
                    self.at += 2;
                    while self.bytes.get(self.at).is_some_and(|byte| *byte != b'\n') {
                        self.at += 1;
                    }
                }
                Some(b'{') if self.bytes.get(self.at + 1) == Some(&b'-') => {
                    let start = self.at;
                    if self.bytes.get(self.at + 2) == Some(&b'#') {
                        self.errors.push(SyntaxError::parse(
                            "Haskell pragmas are unsupported",
                            span(self.source, start, (start + 3).min(self.bytes.len())),
                        ));
                    }
                    self.at += 2;
                    let mut depth = 1_u32;
                    while self.at < self.bytes.len() && depth > 0 {
                        if self.bytes.get(self.at..self.at + 2) == Some(b"{-") {
                            depth += 1;
                            self.at += 2;
                        } else if self.bytes.get(self.at..self.at + 2) == Some(b"-}") {
                            depth -= 1;
                            self.at += 2;
                        } else {
                            if self.bytes[self.at] == b'\n' {
                                self.line_start = self.at + 1;
                                self.saw_token_on_line = false;
                            }
                            self.at += 1;
                        }
                    }
                    if depth != 0 {
                        self.errors.push(SyntaxError::lex(
                            "unterminated nested block comment",
                            span(self.source, start, self.at),
                        ));
                    }
                }
                _ => return,
            }
        }
    }

    fn next(&mut self) -> Token {
        self.skip_trivia();
        let start = self.at;
        let starts_line = !self.saw_token_on_line;
        let column = self.visual_column(start);
        if start >= self.bytes.len() {
            return Token {
                kind: TokenKind::Eof,
                span: span(self.source, start, start),
                starts_line,
                column,
            };
        }
        self.saw_token_on_line = true;
        let byte = self.bytes[self.at];
        let kind = match byte {
            b'(' => self.single(TokenKind::LParen),
            b')' => self.single(TokenKind::RParen),
            b'[' => self.single(TokenKind::LBracket),
            b']' => self.single(TokenKind::RBracket),
            b'{' => self.single(TokenKind::LBrace),
            b'}' => self.single(TokenKind::RBrace),
            b',' => self.single(TokenKind::Comma),
            b';' => self.single(TokenKind::Semicolon),
            b'=' => self.single(TokenKind::Equals),
            b'\\' => self.single(TokenKind::Backslash),
            b'@' => self.single(TokenKind::At),
            b'|' => self.single(TokenKind::Pipe),
            b':' if self.bytes.get(self.at + 1) == Some(&b':') => {
                self.at += 2;
                TokenKind::DoubleColon
            }
            b'-' if self.bytes.get(self.at + 1) == Some(&b'>') => {
                self.at += 2;
                TokenKind::Arrow
            }
            b'<' if self.bytes.get(self.at + 1) == Some(&b'-') => {
                self.at += 2;
                TokenKind::BindArrow
            }
            b'\'' => self.character(start),
            b'"' => self.string(start),
            b'0'..=b'9' => self.number(),
            b'_' => {
                self.at += 1;
                if self
                    .bytes
                    .get(self.at)
                    .is_some_and(|value| is_ident_continue(*value))
                {
                    self.identifier(start)
                } else {
                    TokenKind::Underscore
                }
            }
            value if is_ident_start(value) => self.identifier(start),
            b'$' | b'.' | b'<' | b'>' | b'*' => self.operator(start),
            _ => {
                self.at += char_len(self.bytes, self.at);
                self.errors.push(SyntaxError::lex(
                    "character cannot start a Hell token",
                    span(self.source, start, self.at),
                ));
                return self.next();
            }
        };
        Token {
            kind,
            span: span(self.source, start, self.at),
            starts_line,
            column,
        }
    }

    fn single(&mut self, kind: TokenKind) -> TokenKind {
        self.at += 1;
        kind
    }

    fn identifier(&mut self, start: usize) -> TokenKind {
        self.at += char_len(self.bytes, self.at);
        while self
            .bytes
            .get(self.at)
            .is_some_and(|value| is_ident_continue(*value))
        {
            self.at += char_len(self.bytes, self.at);
        }
        // Keep qualified names as one semantic token. A trailing reserved word
        // is rejected to preserve the baseline's `Monad.then` parser quirk.
        while self.bytes.get(self.at) == Some(&b'.')
            && self
                .bytes
                .get(self.at + 1)
                .is_some_and(|value| is_ident_start(*value))
        {
            self.at += 1;
            self.at += char_len(self.bytes, self.at);
            while self
                .bytes
                .get(self.at)
                .is_some_and(|value| is_ident_continue(*value))
            {
                self.at += char_len(self.bytes, self.at);
            }
        }
        let text = std::str::from_utf8(&self.bytes[start..self.at]).expect("validated source");
        if text.contains('.') {
            if text
                .rsplit('.')
                .next()
                .is_some_and(|last| keyword(last).is_some())
            {
                self.errors.push(SyntaxError::parse(
                    format!("reserved word in qualified name `{text}`"),
                    span(self.source, start, self.at),
                ));
            }
            return TokenKind::Qualified(Arc::from(text));
        }
        if let Some(keyword) = keyword(text) {
            return keyword;
        }
        if text == "_" {
            return TokenKind::Underscore;
        }
        if text.chars().next().is_some_and(char::is_uppercase) {
            TokenKind::Upper(Arc::from(text))
        } else {
            TokenKind::Lower(Arc::from(text))
        }
    }

    fn operator(&mut self, start: usize) -> TokenKind {
        while self
            .bytes
            .get(self.at)
            .is_some_and(|value| matches!(*value, b'$' | b'.' | b'<' | b'>' | b'*'))
        {
            self.at += 1;
        }
        let text = std::str::from_utf8(&self.bytes[start..self.at]).expect("ASCII operator");
        TokenKind::Operator(Arc::from(text))
    }

    fn number(&mut self) -> TokenKind {
        let start = self.at;
        if self
            .bytes
            .get(self.at..self.at + 2)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"0x"))
        {
            self.at += 2;
            let digits = self.at;
            while self.bytes.get(self.at).is_some_and(u8::is_ascii_hexdigit) {
                self.at += 1;
            }
            if self.at == digits {
                self.errors.push(SyntaxError::lex(
                    "hexadecimal literal has no digits",
                    span(self.source, start, self.at),
                ));
            }
            return TokenKind::Integer(Arc::from(
                std::str::from_utf8(&self.bytes[start..self.at]).expect("ASCII number"),
            ));
        }
        if self
            .bytes
            .get(self.at..self.at + 2)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"0o"))
        {
            self.at += 2;
            let digits = self.at;
            while self
                .bytes
                .get(self.at)
                .is_some_and(|byte| matches!(*byte, b'0'..=b'7'))
            {
                self.at += 1;
            }
            if self.at == digits || self.bytes.get(self.at).is_some_and(u8::is_ascii_digit) {
                if self.bytes.get(self.at).is_some_and(u8::is_ascii_digit) {
                    self.at += 1;
                }
                self.errors.push(SyntaxError::lex(
                    "invalid octal literal",
                    span(self.source, start, self.at),
                ));
            }
            return TokenKind::Integer(Arc::from(
                std::str::from_utf8(&self.bytes[start..self.at]).expect("ASCII number"),
            ));
        }
        while self.bytes.get(self.at).is_some_and(u8::is_ascii_digit) {
            self.at += 1;
        }
        let mut fraction = false;
        if self.bytes.get(self.at) == Some(&b'.')
            && self.bytes.get(self.at + 1).is_some_and(u8::is_ascii_digit)
        {
            fraction = true;
            self.at += 1;
            while self.bytes.get(self.at).is_some_and(u8::is_ascii_digit) {
                self.at += 1;
            }
        }
        if matches!(self.bytes.get(self.at), Some(b'e' | b'E')) {
            fraction = true;
            self.at += 1;
            if matches!(self.bytes.get(self.at), Some(b'+' | b'-')) {
                self.at += 1;
            }
            let exponent_digits = self.at;
            while self.bytes.get(self.at).is_some_and(u8::is_ascii_digit) {
                self.at += 1;
            }
            if self.at == exponent_digits {
                self.errors.push(SyntaxError::lex(
                    "fraction exponent has no digits",
                    span(self.source, start, self.at),
                ));
            }
        }
        let raw =
            Arc::from(std::str::from_utf8(&self.bytes[start..self.at]).expect("ASCII number"));
        if fraction {
            TokenKind::Fraction(raw)
        } else {
            TokenKind::Integer(raw)
        }
    }

    fn character(&mut self, start: usize) -> TokenKind {
        self.at += 1;
        let value = self.decode_char(start, b'\'').unwrap_or('\0');
        if self.bytes.get(self.at) == Some(&b'\'') {
            self.at += 1;
        } else {
            self.errors.push(SyntaxError::lex(
                "unterminated character literal",
                span(self.source, start, self.at),
            ));
        }
        TokenKind::Character(value)
    }

    fn string(&mut self, start: usize) -> TokenKind {
        self.at += 1;
        let mut result = String::new();
        while self.at < self.bytes.len() && self.bytes[self.at] != b'"' {
            if self.bytes[self.at] == b'\n' {
                self.errors.push(SyntaxError::lex(
                    "unterminated text literal",
                    span(self.source, start, self.at),
                ));
                break;
            }
            if self.bytes[self.at] == b'\\' && self.bytes.get(self.at + 1) == Some(&b'&') {
                self.at += 2;
                continue;
            }
            if let Some(value) = self.decode_char(start, b'"') {
                result.push(value);
            } else {
                break;
            }
        }
        if self.bytes.get(self.at) == Some(&b'"') {
            self.at += 1;
        } else {
            self.errors.push(SyntaxError::lex(
                "unterminated text literal",
                span(self.source, start, self.at),
            ));
        }
        TokenKind::Text(result.into())
    }

    fn decode_char(&mut self, literal_start: usize, delimiter: u8) -> Option<char> {
        if self.at >= self.bytes.len() || self.bytes[self.at] == delimiter {
            self.errors.push(SyntaxError::lex(
                "literal contains no character",
                span(self.source, literal_start, self.at),
            ));
            return None;
        }
        if self.bytes[self.at] != b'\\' {
            let text = std::str::from_utf8(&self.bytes[self.at..]).expect("validated source");
            let value = text.chars().next().expect("nonempty");
            self.at += value.len_utf8();
            return Some(value);
        }
        let escape_start = self.at;
        self.at += 1;
        let escaped = *self.bytes.get(self.at)?;
        self.at += char_len(self.bytes, self.at);
        let simple = match escaped {
            b'a' => Some('\u{7}'),
            b'b' => Some('\u{8}'),
            b'f' => Some('\u{c}'),
            b'n' => Some('\n'),
            b'r' => Some('\r'),
            b't' => Some('\t'),
            b'v' => Some('\u{b}'),
            b'\\' => Some('\\'),
            b'\'' => Some('\''),
            b'"' => Some('"'),
            _ => None,
        };
        if simple.is_some() {
            return simple;
        }
        let (radix, first_is_digit) = match escaped {
            b'x' | b'X' => (16, false),
            b'o' | b'O' => (8, false),
            value if value.is_ascii_digit() => {
                self.at -= 1;
                (10, true)
            }
            _ => (0, false),
        };
        if radix != 0 {
            let digit_start = self.at;
            while self.bytes.get(self.at).is_some_and(|byte| {
                let value = char::from(*byte).to_digit(radix);
                value.is_some()
            }) {
                self.at += 1;
            }
            if self.at == digit_start && !first_is_digit {
                self.errors.push(SyntaxError::lex(
                    "numeric escape has no digits",
                    span(self.source, escape_start, self.at),
                ));
                return None;
            }
            let digits = std::str::from_utf8(&self.bytes[digit_start..self.at]).ok()?;
            if let Ok(value) = u32::from_str_radix(digits, radix)
                && let Some(value) = char::from_u32(value)
            {
                return Some(value);
            }
        }
        self.errors.push(SyntaxError::lex(
            "invalid Haskell literal escape",
            span(self.source, escape_start, self.at),
        ));
        None
    }
}

fn char_len(bytes: &[u8], at: usize) -> usize {
    std::str::from_utf8(&bytes[at..])
        .ok()
        .and_then(|text| text.chars().next())
        .map_or(1, char::len_utf8)
}

fn is_ident_start(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphabetic() || byte >= 0x80
}

fn is_ident_continue(byte: u8) -> bool {
    is_ident_start(byte) || byte.is_ascii_digit() || byte == b'\''
}

fn keyword(text: &str) -> Option<TokenKind> {
    Some(match text {
        "case" => TokenKind::KwCase,
        "data" => TokenKind::KwData,
        "do" => TokenKind::KwDo,
        "else" => TokenKind::KwElse,
        "if" => TokenKind::KwIf,
        "let" => TokenKind::KwLet,
        "of" => TokenKind::KwOf,
        "then" => TokenKind::KwThen,
        _ => return None,
    })
}

#[derive(Clone, Copy)]
enum LayoutContext {
    Explicit,
    Implicit { column: u32, first: bool },
}

fn insert_layout(source: &SourceFile, physical: Vec<Token>) -> Vec<Token> {
    let mut output = Vec::with_capacity(physical.len() + 8);
    let root_span = physical.first().map_or_else(
        || source.eof_span(),
        |token| Span::empty(source.id, token.span.start),
    );
    output.push(Token {
        kind: TokenKind::VirtualLBrace,
        span: root_span,
        starts_line: true,
        column: 1,
    });
    let mut contexts = vec![LayoutContext::Implicit {
        column: physical.first().map_or(1, |token| token.column),
        first: true,
    }];
    let mut pending_layout = false;
    for token in physical {
        if matches!(token.kind, TokenKind::Eof) {
            while matches!(contexts.last(), Some(LayoutContext::Implicit { .. })) {
                contexts.pop();
                output.push(Token {
                    kind: TokenKind::VirtualRBrace,
                    span: token.span,
                    starts_line: token.starts_line,
                    column: token.column,
                });
            }
            output.push(token);
            break;
        }
        if pending_layout {
            pending_layout = false;
            if !matches!(token.kind, TokenKind::LBrace) {
                output.push(Token {
                    kind: TokenKind::VirtualLBrace,
                    span: Span::empty(token.span.source, token.span.start),
                    starts_line: token.starts_line,
                    column: token.column,
                });
                contexts.push(LayoutContext::Implicit {
                    column: token.column,
                    first: true,
                });
            }
        }
        if token.starts_line {
            loop {
                match contexts.last().copied() {
                    Some(LayoutContext::Implicit { column, .. }) if token.column < column => {
                        contexts.pop();
                        output.push(Token {
                            kind: TokenKind::VirtualRBrace,
                            span: Span::empty(token.span.source, token.span.start),
                            starts_line: true,
                            column: token.column,
                        });
                    }
                    _ => break,
                }
            }
            if let Some(LayoutContext::Implicit { column, first }) = contexts.last_mut()
                && token.column == *column
            {
                if *first {
                    *first = false;
                } else {
                    output.push(Token {
                        kind: TokenKind::VirtualSemicolon,
                        span: Span::empty(token.span.source, token.span.start),
                        starts_line: true,
                        column: token.column,
                    });
                }
            }
        } else if let Some(LayoutContext::Implicit { first, .. }) = contexts.last_mut() {
            *first = false;
        }
        match token.kind {
            TokenKind::LBrace => {
                contexts.push(LayoutContext::Explicit);
            }
            TokenKind::RBrace => {
                while let Some(context) = contexts.pop() {
                    if matches!(context, LayoutContext::Explicit) {
                        break;
                    }
                }
            }
            TokenKind::KwDo | TokenKind::KwOf => pending_layout = true,
            _ => {}
        }
        output.push(token);
    }
    output
}

/// Tokenizes a source file and inserts virtual layout braces and semicolons.
///
/// # Errors
///
/// Returns all lexical errors found while scanning the source.
pub fn lex(source: &SourceFile) -> Result<Vec<Token>, Vec<SyntaxError>> {
    let mut lexer = Lexer::new(source);
    let mut tokens = Vec::new();
    loop {
        let token = lexer.next();
        let eof = matches!(token.kind, TokenKind::Eof);
        tokens.push(token);
        if eof {
            break;
        }
    }
    if lexer.errors.is_empty() {
        Ok(insert_layout(source, tokens))
    } else {
        Err(lexer.errors)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ExprId(pub u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TypeExprId(pub u32);

#[derive(Clone, Debug, PartialEq)]
pub enum Literal {
    Integer(Arc<str>),
    Double(Arc<str>),
    Character(char),
    Text(Arc<str>),
    Unit,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Expr {
    Name(Arc<str>, Span),
    Literal(Literal, Span),
    Apply {
        function: ExprId,
        argument: ExprId,
        span: Span,
    },
    TypeApply {
        function: ExprId,
        argument: TypeExprId,
        span: Span,
    },
    Lambda {
        parameters: Vec<BindingPattern>,
        body: ExprId,
        span: Span,
    },
    If {
        condition: ExprId,
        then_branch: ExprId,
        else_branch: ExprId,
        span: Span,
    },
    Do {
        statements: Vec<DoStatement>,
        span: Span,
    },
    Case {
        scrutinee: ExprId,
        alternatives: Vec<CaseAlternative>,
        span: Span,
    },
    Tuple {
        elements: Vec<ExprId>,
        span: Span,
    },
    List {
        elements: Vec<ExprId>,
        span: Span,
    },
    RecordConstruction {
        constructor: Arc<str>,
        fields: Vec<RecordFieldExpr>,
        span: Span,
    },
    Annotation {
        expression: ExprId,
        ty: TypeExprId,
        span: Span,
    },
}

impl Expr {
    #[must_use]
    pub const fn span(&self) -> Span {
        match self {
            Self::Name(_, span)
            | Self::Literal(_, span)
            | Self::Apply { span, .. }
            | Self::TypeApply { span, .. }
            | Self::Lambda { span, .. }
            | Self::If { span, .. }
            | Self::Do { span, .. }
            | Self::Case { span, .. }
            | Self::Tuple { span, .. }
            | Self::List { span, .. }
            | Self::RecordConstruction { span, .. }
            | Self::Annotation { span, .. } => *span,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum BindingPattern {
    Variable(Arc<str>, Span),
    Wildcard(Span),
    Tuple(Vec<Arc<str>>, Span),
    Annotated(Box<BindingPattern>, TypeExprId, Span),
}

#[derive(Clone, Debug, PartialEq)]
pub enum DoStatement {
    Bind(BindingPattern, ExprId, Span),
    Let(BindingPattern, ExprId, Span),
    Then(ExprId, Span),
}

#[derive(Clone, Debug, PartialEq)]
pub struct CaseAlternative {
    pub pattern: CasePattern,
    pub expression: ExprId,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq)]
pub enum CasePattern {
    UserConstructor {
        name: Arc<str>,
        binder: Option<Arc<str>>,
        span: Span,
    },
    PrimitiveConstructor {
        name: Arc<str>,
        binders: Vec<Arc<str>>,
        span: Span,
    },
    Wildcard(Span),
}

impl CasePattern {
    #[must_use]
    pub const fn span(&self) -> Span {
        match self {
            Self::UserConstructor { span, .. }
            | Self::PrimitiveConstructor { span, .. }
            | Self::Wildcard(span) => *span,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct RecordFieldExpr {
    pub name: Arc<str>,
    pub value: ExprId,
    pub pun: bool,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq)]
pub enum TypeExpr {
    Name(Arc<str>, Span),
    Unit(Span),
    List(TypeExprId, Span),
    Tuple(Vec<TypeExprId>, Span),
    Function(TypeExprId, TypeExprId, Span),
    Apply(TypeExprId, TypeExprId, Span),
    Promoted(Arc<str>, Span),
}

impl TypeExpr {
    #[must_use]
    pub const fn span(&self) -> Span {
        match self {
            Self::Name(_, span)
            | Self::Unit(span)
            | Self::List(_, span)
            | Self::Tuple(_, span)
            | Self::Function(_, _, span)
            | Self::Apply(_, _, span)
            | Self::Promoted(_, span) => *span,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ValueDecl {
    pub name: Arc<str>,
    pub annotation: Option<TypeExprId>,
    pub value: ExprId,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RecordDecl {
    pub type_name: Arc<str>,
    pub constructor: Arc<str>,
    pub fields: Vec<FieldDecl>,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq)]
pub struct FieldDecl {
    pub name: Arc<str>,
    pub ty: TypeExprId,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SumDecl {
    pub type_name: Arc<str>,
    pub constructors: Vec<ConstructorDecl>,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ConstructorDecl {
    pub name: Arc<str>,
    pub payload: Option<TypeExprId>,
    pub span: Span,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Declaration {
    Value(ValueDecl),
    Record(RecordDecl),
    Sum(SumDecl),
}

impl Declaration {
    #[must_use]
    pub const fn span(&self) -> Span {
        match self {
            Self::Value(declaration) => declaration.span,
            Self::Record(declaration) => declaration.span,
            Self::Sum(declaration) => declaration.span,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ParsedFile {
    pub declarations: Vec<Declaration>,
    pub expressions: Vec<Expr>,
    pub types: Vec<TypeExpr>,
    pub span: Span,
}

struct Parser {
    tokens: Vec<Token>,
    at: usize,
    expressions: Vec<Expr>,
    types: Vec<TypeExpr>,
    errors: Vec<SyntaxError>,
}

/// Resource policy for parsing one source file.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ParserLimits {
    /// Stable profile label included in resource diagnostics.
    pub profile_id: &'static str,
    /// Maximum lexer tokens, including layout and end-of-file tokens.
    pub max_tokens: Option<usize>,
    /// Maximum nested delimiter/grammar depth, or no semantic limit.
    pub max_nesting_depth: Option<usize>,
}

impl ParserLimits {
    /// Conservative limits for parsing untrusted source.
    #[must_use]
    pub const fn sandboxed() -> Self {
        Self {
            profile_id: "sandboxed",
            max_tokens: Some(1_000_000),
            max_nesting_depth: Some(64),
        }
    }

    /// Compatibility policy without the sandbox's semantic nesting cap.
    #[must_use]
    pub const fn upstream() -> Self {
        Self {
            profile_id: "upstream",
            max_tokens: None,
            max_nesting_depth: None,
        }
    }
}

impl Parser {
    fn alloc_expr(&mut self, expression: Expr) -> ExprId {
        let id = ExprId(u32::try_from(self.expressions.len()).expect("expression arena overflow"));
        self.expressions.push(expression);
        id
    }

    fn alloc_type(&mut self, ty: TypeExpr) -> TypeExprId {
        let id = TypeExprId(u32::try_from(self.types.len()).expect("type AST arena overflow"));
        self.types.push(ty);
        id
    }

    fn current(&self) -> &Token {
        &self.tokens[self.at]
    }

    fn bump(&mut self) -> Token {
        let token = self.tokens[self.at].clone();
        self.at += 1;
        token
    }

    fn eat(&mut self, predicate: impl FnOnce(&TokenKind) -> bool) -> Option<Token> {
        if predicate(&self.current().kind) {
            Some(self.bump())
        } else {
            None
        }
    }

    fn expected(&mut self, expected: &str) -> SyntaxError {
        SyntaxError::parse(
            format!("expected {expected}, found {:?}", self.current().kind),
            self.current().span,
        )
    }

    /// A parenthesis can terminate an implicit `do`/`case` block before the
    /// layout pass sees a physical dedent. Remove the corresponding future
    /// virtual close so it cannot accidentally close the surrounding block.
    fn discard_deferred_layout_close(&mut self) {
        if let Some(relative) = self.tokens[self.at + 1..]
            .iter()
            .position(|token| matches!(token.kind, TokenKind::VirtualRBrace))
        {
            self.tokens.remove(self.at + 1 + relative);
        }
    }

    fn parse(mut self) -> Result<ParsedFile, Vec<SyntaxError>> {
        let start = self.current().span;
        if self
            .eat(|kind| matches!(kind, TokenKind::VirtualLBrace))
            .is_none()
        {
            let error = self.expected("top-level declaration block");
            self.errors.push(error);
        }
        let mut declarations = Vec::new();
        while !matches!(
            self.current().kind,
            TokenKind::VirtualRBrace | TokenKind::Eof
        ) {
            while self
                .eat(|kind| matches!(kind, TokenKind::VirtualSemicolon | TokenKind::Semicolon))
                .is_some()
            {}
            if matches!(
                self.current().kind,
                TokenKind::VirtualRBrace | TokenKind::Eof
            ) {
                break;
            }
            match self.parse_declaration() {
                Ok(declaration) => declarations.push(declaration),
                Err(error) => {
                    self.errors.push(error);
                    while !matches!(
                        self.current().kind,
                        TokenKind::VirtualSemicolon
                            | TokenKind::Semicolon
                            | TokenKind::VirtualRBrace
                            | TokenKind::Eof
                    ) {
                        self.bump();
                    }
                }
            }
        }
        let end = self.bump().span;
        if self.errors.is_empty() {
            Ok(ParsedFile {
                declarations,
                expressions: self.expressions,
                types: self.types,
                span: start.join(end),
            })
        } else {
            Err(self.errors)
        }
    }

    fn parse_declaration(&mut self) -> Result<Declaration, SyntaxError> {
        if matches!(self.current().kind, TokenKind::KwData) {
            return self.parse_data_declaration();
        }
        let token = self.bump();
        let TokenKind::Lower(name) = token.kind else {
            return Err(SyntaxError::parse(
                "top-level declarations must be `name [:: Type] = expression`",
                token.span,
            ));
        };
        let annotation = if self
            .eat(|kind| matches!(kind, TokenKind::DoubleColon))
            .is_some()
        {
            Some(self.parse_type()?)
        } else {
            None
        };
        if self.eat(|kind| matches!(kind, TokenKind::Equals)).is_none() {
            return Err(self.expected("`=`; top-level function equations are unsupported"));
        }
        let value = self.parse_expression(0)?;
        let span = token.span.join(self.expressions[value.0 as usize].span());
        Ok(Declaration::Value(ValueDecl {
            name,
            annotation,
            value,
            span,
        }))
    }

    fn parse_data_declaration(&mut self) -> Result<Declaration, SyntaxError> {
        let start = self.bump().span;
        let type_token = self.bump();
        let TokenKind::Upper(type_name) = type_token.kind else {
            return Err(SyntaxError::parse(
                "data declarations require an unqualified type name",
                type_token.span,
            ));
        };
        if self.eat(|kind| matches!(kind, TokenKind::Equals)).is_none() {
            return Err(SyntaxError::parse(
                "type parameters and contexts on data declarations are unsupported",
                self.current().span,
            ));
        }
        let first_token = self.bump();
        let TokenKind::Upper(first_name) = first_token.kind else {
            return Err(SyntaxError::parse(
                "data constructors must be unqualified uppercase names",
                first_token.span,
            ));
        };
        if self.eat(|kind| matches!(kind, TokenKind::LBrace)).is_some() {
            return self.parse_record_declaration(start, type_name, first_name);
        }
        self.parse_sum_declaration(start, type_name, first_name, first_token.span)
    }

    fn parse_record_declaration(
        &mut self,
        start: Span,
        type_name: Arc<str>,
        constructor: Arc<str>,
    ) -> Result<Declaration, SyntaxError> {
        let mut fields = Vec::new();
        if matches!(self.current().kind, TokenKind::RBrace) {
            return Err(SyntaxError::parse(
                "record declarations require at least one field",
                self.current().span,
            ));
        }
        loop {
            let mut names = Vec::new();
            loop {
                let field_token = self.bump();
                let TokenKind::Lower(field_name) = field_token.kind else {
                    return Err(SyntaxError::parse(
                        "record field declarations require lowercase names",
                        field_token.span,
                    ));
                };
                names.push((field_name, field_token.span));
                if matches!(self.current().kind, TokenKind::DoubleColon) {
                    break;
                }
                if self.eat(|kind| matches!(kind, TokenKind::Comma)).is_none() {
                    return Err(self.expected("`,` or `::` in record field declaration"));
                }
            }
            self.bump();
            let ty = self.parse_type()?;
            let type_span = self.types[ty.0 as usize].span();
            fields.extend(names.into_iter().map(|(name, name_span)| FieldDecl {
                name,
                ty,
                span: name_span.join(type_span),
            }));
            if self.eat(|kind| matches!(kind, TokenKind::Comma)).is_none() {
                break;
            }
        }
        let end = self.bump();
        if !matches!(end.kind, TokenKind::RBrace) {
            return Err(SyntaxError::parse(
                "expected `}` in record declaration",
                end.span,
            ));
        }
        Ok(Declaration::Record(RecordDecl {
            type_name,
            constructor,
            fields,
            span: start.join(end.span),
        }))
    }

    fn parse_sum_declaration(
        &mut self,
        start: Span,
        type_name: Arc<str>,
        first_name: Arc<str>,
        first_token_span: Span,
    ) -> Result<Declaration, SyntaxError> {
        let first_payload = if starts_type_atom(&self.current().kind) {
            Some(self.parse_type_atom()?)
        } else {
            None
        };
        let first_span = first_payload.map_or(first_token_span, |payload| {
            first_token_span.join(self.types[payload.0 as usize].span())
        });
        let mut constructors = vec![ConstructorDecl {
            name: first_name,
            payload: first_payload,
            span: first_span,
        }];
        if self.eat(|kind| matches!(kind, TokenKind::Pipe)).is_none() {
            return Err(SyntaxError::parse(
                "one-constructor ordinary sums are unsupported; use record syntax",
                first_span,
            ));
        }
        loop {
            let constructor_token = self.bump();
            let TokenKind::Upper(name) = constructor_token.kind else {
                return Err(SyntaxError::parse(
                    "sum constructors must be unqualified uppercase names",
                    constructor_token.span,
                ));
            };
            let payload = if starts_type_atom(&self.current().kind) {
                Some(self.parse_type_atom()?)
            } else {
                None
            };
            let constructor_span = payload.map_or(constructor_token.span, |payload| {
                constructor_token
                    .span
                    .join(self.types[payload.0 as usize].span())
            });
            constructors.push(ConstructorDecl {
                name,
                payload,
                span: constructor_span,
            });
            if self.eat(|kind| matches!(kind, TokenKind::Pipe)).is_none() {
                return Ok(Declaration::Sum(SumDecl {
                    type_name,
                    constructors,
                    span: start.join(constructor_span),
                }));
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn parse_expression(&mut self, minimum_precedence: u8) -> Result<ExprId, SyntaxError> {
        enum Work {
            ParseExpression(u8),
            ParsePrefix,
            AfterPrefix(u8),
            ResumeExpression {
                left: ExprId,
                minimum_precedence: u8,
            },
            FinishApplication {
                function: ExprId,
                minimum_precedence: u8,
            },
            FinishOperator {
                left: ExprId,
                operator: Arc<str>,
                operator_span: Span,
                minimum_precedence: u8,
            },
            FinishLambda {
                start: Span,
                parameters: Vec<BindingPattern>,
            },
            AfterIfCondition(Span),
            AfterIfThen {
                start: Span,
                condition: ExprId,
            },
            FinishIf {
                start: Span,
                condition: ExprId,
                then_branch: ExprId,
            },
            AfterCaseScrutinee(Span),
            CaseNext {
                start: Span,
                scrutinee: ExprId,
                alternatives: Vec<CaseAlternative>,
            },
            FinishCaseAlternative {
                start: Span,
                scrutinee: ExprId,
                alternatives: Vec<CaseAlternative>,
                pattern: CasePattern,
            },
            DoNext {
                start: Span,
                statements: Vec<DoStatement>,
            },
            FinishDoLet {
                start: Span,
                statements: Vec<DoStatement>,
                pattern: BindingPattern,
                statement_start: Span,
            },
            FinishDoBind {
                start: Span,
                statements: Vec<DoStatement>,
                pattern: BindingPattern,
            },
            FinishDoThen {
                start: Span,
                statements: Vec<DoStatement>,
            },
            ListAfterElement {
                start: Span,
                elements: Vec<ExprId>,
            },
            RecordNext {
                constructor: Arc<str>,
                start: Span,
                fields: Vec<RecordFieldExpr>,
            },
            FinishRecordField {
                constructor: Arc<str>,
                start: Span,
                fields: Vec<RecordFieldExpr>,
                name: Arc<str>,
                field_span: Span,
                pun: bool,
            },
            FinishParenthesized {
                start: Span,
                remaining: Vec<Span>,
            },
            ContinueParenthesizedTuple {
                start: Span,
                remaining: Vec<Span>,
                elements: Vec<ExprId>,
            },
        }

        let mut work = vec![Work::ParseExpression(minimum_precedence)];
        let mut output = None;
        while let Some(step) = work.pop() {
            match step {
                Work::ParseExpression(minimum_precedence) => {
                    work.push(Work::AfterPrefix(minimum_precedence));
                    work.push(Work::ParsePrefix);
                }
                Work::ParsePrefix => {
                    let token = self.bump();
                    match token.kind {
                        TokenKind::Backslash => {
                            let mut parameters = Vec::new();
                            while !matches!(self.current().kind, TokenKind::Arrow | TokenKind::Eof)
                            {
                                parameters.push(self.parse_pattern()?);
                            }
                            if parameters.is_empty() {
                                return Err(SyntaxError::parse(
                                    "lambda must bind a parameter",
                                    token.span,
                                ));
                            }
                            if self.eat(|kind| matches!(kind, TokenKind::Arrow)).is_none() {
                                return Err(self.expected("`->`"));
                            }
                            work.push(Work::FinishLambda {
                                start: token.span,
                                parameters,
                            });
                            work.push(Work::ParseExpression(0));
                        }
                        TokenKind::KwIf => {
                            work.push(Work::AfterIfCondition(token.span));
                            work.push(Work::ParseExpression(0));
                        }
                        TokenKind::KwCase => {
                            work.push(Work::AfterCaseScrutinee(token.span));
                            work.push(Work::ParseExpression(0));
                        }
                        TokenKind::KwDo => {
                            if self
                                .eat(|kind| {
                                    matches!(kind, TokenKind::VirtualLBrace | TokenKind::LBrace)
                                })
                                .is_none()
                            {
                                return Err(self.expected("do statement block"));
                            }
                            work.push(Work::DoNext {
                                start: token.span,
                                statements: Vec::new(),
                            });
                        }
                        TokenKind::Qualified(name)
                            if matches!(self.current().kind, TokenKind::LBrace) =>
                        {
                            self.bump();
                            work.push(Work::RecordNext {
                                constructor: name,
                                start: token.span,
                                fields: Vec::new(),
                            });
                        }
                        TokenKind::Lower(name)
                        | TokenKind::Upper(name)
                        | TokenKind::Qualified(name)
                        | TokenKind::Operator(name) => {
                            output = Some(self.alloc_expr(Expr::Name(name, token.span)));
                        }
                        TokenKind::Integer(value) => {
                            output = Some(
                                self.alloc_expr(Expr::Literal(Literal::Integer(value), token.span)),
                            );
                        }
                        TokenKind::Fraction(value) => {
                            output = Some(
                                self.alloc_expr(Expr::Literal(Literal::Double(value), token.span)),
                            );
                        }
                        TokenKind::Character(value) => {
                            output =
                                Some(self.alloc_expr(Expr::Literal(
                                    Literal::Character(value),
                                    token.span,
                                )));
                        }
                        TokenKind::Text(value) => {
                            output = Some(
                                self.alloc_expr(Expr::Literal(Literal::Text(value), token.span)),
                            );
                        }
                        TokenKind::LBracket => {
                            if let Some(end) = self.eat(|kind| matches!(kind, TokenKind::RBracket))
                            {
                                output = Some(self.alloc_expr(Expr::List {
                                    elements: Vec::new(),
                                    span: token.span.join(end.span),
                                }));
                            } else {
                                work.push(Work::ListAfterElement {
                                    start: token.span,
                                    elements: Vec::new(),
                                });
                                work.push(Work::ParseExpression(0));
                            }
                        }
                        TokenKind::LParen => {
                            let mut starts = vec![token.span];
                            while matches!(self.current().kind, TokenKind::LParen) {
                                starts.push(self.bump().span);
                            }
                            let start = starts.pop().expect("opening parenthesis exists");
                            if let Some(end) = self.eat(|kind| matches!(kind, TokenKind::RParen)) {
                                let expression = self
                                    .alloc_expr(Expr::Literal(Literal::Unit, start.join(end.span)));
                                if let Some(outer) = starts.pop() {
                                    work.push(Work::FinishParenthesized {
                                        start: outer,
                                        remaining: starts,
                                    });
                                    work.push(Work::ResumeExpression {
                                        left: expression,
                                        minimum_precedence: 0,
                                    });
                                } else {
                                    output = Some(expression);
                                }
                            } else {
                                work.push(Work::FinishParenthesized {
                                    start,
                                    remaining: starts,
                                });
                                work.push(Work::ParseExpression(0));
                            }
                        }
                        _ => {
                            return Err(SyntaxError::parse("expected expression", token.span));
                        }
                    }
                }
                Work::AfterPrefix(minimum_precedence) => {
                    let left = output.take().expect("expression prefix produced a value");
                    work.push(Work::ResumeExpression {
                        left,
                        minimum_precedence,
                    });
                }
                Work::ResumeExpression {
                    mut left,
                    minimum_precedence,
                } => loop {
                    if self.eat(|kind| matches!(kind, TokenKind::At)).is_some() {
                        let ty = if let TokenKind::Text(value) = self.current().kind.clone() {
                            let token = self.bump();
                            self.alloc_type(TypeExpr::Promoted(value, token.span))
                        } else {
                            self.parse_type_atom()?
                        };
                        let span = self.expressions[left.0 as usize]
                            .span()
                            .join(self.types[ty.0 as usize].span());
                        left = self.alloc_expr(Expr::TypeApply {
                            function: left,
                            argument: ty,
                            span,
                        });
                        continue;
                    }
                    if starts_expression_atom(&self.current().kind) {
                        work.push(Work::FinishApplication {
                            function: left,
                            minimum_precedence,
                        });
                        work.push(Work::ParsePrefix);
                        break;
                    }
                    let TokenKind::Operator(operator) = self.current().kind.clone() else {
                        if minimum_precedence == 0
                            && self
                                .eat(|kind| matches!(kind, TokenKind::DoubleColon))
                                .is_some()
                        {
                            let ty = self.parse_type()?;
                            let span = self.expressions[left.0 as usize]
                                .span()
                                .join(self.types[ty.0 as usize].span());
                            left = self.alloc_expr(Expr::Annotation {
                                expression: left,
                                ty,
                                span,
                            });
                        }
                        output = Some(left);
                        break;
                    };
                    let (precedence, right_associative) = fixity(&operator).ok_or_else(|| {
                        SyntaxError::parse(
                            format!("unsupported operator `{operator}`"),
                            self.current().span,
                        )
                    })?;
                    if precedence < minimum_precedence {
                        output = Some(left);
                        break;
                    }
                    let operator_span = self.bump().span;
                    work.push(Work::FinishOperator {
                        left,
                        operator,
                        operator_span,
                        minimum_precedence,
                    });
                    work.push(Work::ParseExpression(if right_associative {
                        precedence
                    } else {
                        precedence.saturating_add(1)
                    }));
                    break;
                },
                Work::FinishApplication {
                    function,
                    minimum_precedence,
                } => {
                    let argument = output.take().expect("function argument produced a value");
                    let span = self.expressions[function.0 as usize]
                        .span()
                        .join(self.expressions[argument.0 as usize].span());
                    let expression = self.alloc_expr(Expr::Apply {
                        function,
                        argument,
                        span,
                    });
                    work.push(Work::ResumeExpression {
                        left: expression,
                        minimum_precedence,
                    });
                }
                Work::FinishOperator {
                    left,
                    operator,
                    operator_span,
                    minimum_precedence,
                } => {
                    let right = output
                        .take()
                        .expect("operator right operand produced a value");
                    let op = self.alloc_expr(Expr::Name(operator, operator_span));
                    let op_left_span = self.expressions[left.0 as usize]
                        .span()
                        .join(self.expressions[op.0 as usize].span());
                    let applied_left = self.alloc_expr(Expr::Apply {
                        function: op,
                        argument: left,
                        span: op_left_span,
                    });
                    let span = self.expressions[left.0 as usize]
                        .span()
                        .join(self.expressions[right.0 as usize].span());
                    let expression = self.alloc_expr(Expr::Apply {
                        function: applied_left,
                        argument: right,
                        span,
                    });
                    work.push(Work::ResumeExpression {
                        left: expression,
                        minimum_precedence,
                    });
                }
                Work::FinishLambda { start, parameters } => {
                    let body = output.take().expect("lambda body produced a value");
                    let span = start.join(self.expressions[body.0 as usize].span());
                    output = Some(self.alloc_expr(Expr::Lambda {
                        parameters,
                        body,
                        span,
                    }));
                }
                Work::AfterIfCondition(start) => {
                    let condition = output.take().expect("if condition produced a value");
                    if self.eat(|kind| matches!(kind, TokenKind::KwThen)).is_none() {
                        return Err(self.expected("`then`"));
                    }
                    work.push(Work::AfterIfThen { start, condition });
                    work.push(Work::ParseExpression(0));
                }
                Work::AfterIfThen { start, condition } => {
                    let then_branch = output.take().expect("then branch produced a value");
                    if self.eat(|kind| matches!(kind, TokenKind::KwElse)).is_none() {
                        return Err(self.expected("`else`"));
                    }
                    work.push(Work::FinishIf {
                        start,
                        condition,
                        then_branch,
                    });
                    work.push(Work::ParseExpression(0));
                }
                Work::FinishIf {
                    start,
                    condition,
                    then_branch,
                } => {
                    let else_branch = output.take().expect("else branch produced a value");
                    let span = start.join(self.expressions[else_branch.0 as usize].span());
                    output = Some(self.alloc_expr(Expr::If {
                        condition,
                        then_branch,
                        else_branch,
                        span,
                    }));
                }
                Work::AfterCaseScrutinee(start) => {
                    let scrutinee = output.take().expect("case scrutinee produced a value");
                    if self.eat(|kind| matches!(kind, TokenKind::KwOf)).is_none() {
                        return Err(self.expected("`of`"));
                    }
                    if self
                        .eat(|kind| matches!(kind, TokenKind::VirtualLBrace | TokenKind::LBrace))
                        .is_none()
                    {
                        return Err(self.expected("case alternative block"));
                    }
                    work.push(Work::CaseNext {
                        start,
                        scrutinee,
                        alternatives: Vec::new(),
                    });
                }
                Work::CaseNext {
                    start,
                    scrutinee,
                    alternatives,
                } => {
                    while self
                        .eat(|kind| {
                            matches!(kind, TokenKind::VirtualSemicolon | TokenKind::Semicolon)
                        })
                        .is_some()
                    {}
                    if matches!(
                        self.current().kind,
                        TokenKind::VirtualRBrace | TokenKind::RBrace | TokenKind::RParen
                    ) {
                        let end = if matches!(self.current().kind, TokenKind::RParen) {
                            let span = self.current().span;
                            self.discard_deferred_layout_close();
                            span
                        } else {
                            self.bump().span
                        };
                        if alternatives.is_empty() {
                            return Err(SyntaxError::parse("empty case block", start.join(end)));
                        }
                        output = Some(self.alloc_expr(Expr::Case {
                            scrutinee,
                            alternatives,
                            span: start.join(end),
                        }));
                    } else {
                        if matches!(self.current().kind, TokenKind::Eof) {
                            return Err(self.expected("end of case block"));
                        }
                        let pattern = self.parse_case_pattern()?;
                        if self.eat(|kind| matches!(kind, TokenKind::Arrow)).is_none() {
                            return Err(self.expected("`->` in case alternative"));
                        }
                        work.push(Work::FinishCaseAlternative {
                            start,
                            scrutinee,
                            alternatives,
                            pattern,
                        });
                        work.push(Work::ParseExpression(0));
                    }
                }
                Work::FinishCaseAlternative {
                    start,
                    scrutinee,
                    mut alternatives,
                    pattern,
                } => {
                    let expression = output.take().expect("case branch produced a value");
                    let span = pattern
                        .span()
                        .join(self.expressions[expression.0 as usize].span());
                    alternatives.push(CaseAlternative {
                        pattern,
                        expression,
                        span,
                    });
                    work.push(Work::CaseNext {
                        start,
                        scrutinee,
                        alternatives,
                    });
                }
                Work::DoNext { start, statements } => {
                    while self
                        .eat(|kind| {
                            matches!(kind, TokenKind::VirtualSemicolon | TokenKind::Semicolon)
                        })
                        .is_some()
                    {}
                    if matches!(
                        self.current().kind,
                        TokenKind::VirtualRBrace | TokenKind::RBrace | TokenKind::RParen
                    ) {
                        let end = if matches!(self.current().kind, TokenKind::RParen) {
                            let span = self.current().span;
                            self.discard_deferred_layout_close();
                            span
                        } else {
                            self.bump().span
                        };
                        if statements.is_empty() {
                            return Err(SyntaxError::parse("empty do block", start.join(end)));
                        }
                        if !matches!(statements.last(), Some(DoStatement::Then(_, _))) {
                            return Err(SyntaxError::parse(
                                "the final do statement must be an expression",
                                start.join(end),
                            ));
                        }
                        output = Some(self.alloc_expr(Expr::Do {
                            statements,
                            span: start.join(end),
                        }));
                    } else {
                        if matches!(self.current().kind, TokenKind::Eof) {
                            return Err(self.expected("end of do block"));
                        }
                        if let Some(let_token) = self.eat(|kind| matches!(kind, TokenKind::KwLet)) {
                            let pattern = self.parse_pattern()?;
                            if self.eat(|kind| matches!(kind, TokenKind::Equals)).is_none() {
                                return Err(self.expected("`=` in do let"));
                            }
                            work.push(Work::FinishDoLet {
                                start,
                                statements,
                                pattern,
                                statement_start: let_token.span,
                            });
                            work.push(Work::ParseExpression(0));
                        } else {
                            let saved = self.at;
                            if let Ok(pattern) = self.parse_pattern()
                                && self
                                    .eat(|kind| matches!(kind, TokenKind::BindArrow))
                                    .is_some()
                            {
                                work.push(Work::FinishDoBind {
                                    start,
                                    statements,
                                    pattern,
                                });
                                work.push(Work::ParseExpression(0));
                            } else {
                                self.at = saved;
                                work.push(Work::FinishDoThen { start, statements });
                                work.push(Work::ParseExpression(0));
                            }
                        }
                    }
                }
                Work::FinishDoLet {
                    start,
                    mut statements,
                    pattern,
                    statement_start,
                } => {
                    let expression = output.take().expect("do let expression produced a value");
                    let span = statement_start.join(self.expressions[expression.0 as usize].span());
                    statements.push(DoStatement::Let(pattern, expression, span));
                    work.push(Work::DoNext { start, statements });
                }
                Work::FinishDoBind {
                    start,
                    mut statements,
                    pattern,
                } => {
                    let expression = output.take().expect("do bind expression produced a value");
                    let span =
                        pattern_span(&pattern).join(self.expressions[expression.0 as usize].span());
                    statements.push(DoStatement::Bind(pattern, expression, span));
                    work.push(Work::DoNext { start, statements });
                }
                Work::FinishDoThen {
                    start,
                    mut statements,
                } => {
                    let expression = output.take().expect("do expression produced a value");
                    let span = self.expressions[expression.0 as usize].span();
                    statements.push(DoStatement::Then(expression, span));
                    work.push(Work::DoNext { start, statements });
                }
                Work::ListAfterElement {
                    start,
                    mut elements,
                } => {
                    elements.push(output.take().expect("list element produced a value"));
                    if self.eat(|kind| matches!(kind, TokenKind::Comma)).is_some() {
                        work.push(Work::ListAfterElement { start, elements });
                        work.push(Work::ParseExpression(0));
                    } else {
                        let end = self.bump();
                        if !matches!(end.kind, TokenKind::RBracket) {
                            return Err(SyntaxError::parse("expected `]`", end.span));
                        }
                        output = Some(self.alloc_expr(Expr::List {
                            elements,
                            span: start.join(end.span),
                        }));
                    }
                }
                Work::RecordNext {
                    constructor,
                    start,
                    fields,
                } => {
                    if let Some(end) = self.eat(|kind| matches!(kind, TokenKind::RBrace)) {
                        output = Some(self.alloc_expr(Expr::RecordConstruction {
                            constructor,
                            fields,
                            span: start.join(end.span),
                        }));
                    } else {
                        let field_token = self.bump();
                        let TokenKind::Lower(name) = field_token.kind else {
                            return Err(SyntaxError::parse(
                                "record initializer labels must be unqualified lowercase names",
                                field_token.span,
                            ));
                        };
                        let pun = self.eat(|kind| matches!(kind, TokenKind::Equals)).is_none();
                        work.push(Work::FinishRecordField {
                            constructor,
                            start,
                            fields,
                            name: Arc::clone(&name),
                            field_span: field_token.span,
                            pun,
                        });
                        if pun {
                            output = Some(self.alloc_expr(Expr::Name(name, field_token.span)));
                        } else {
                            work.push(Work::ParseExpression(0));
                        }
                    }
                }
                Work::FinishRecordField {
                    constructor,
                    start,
                    mut fields,
                    name,
                    field_span,
                    pun,
                } => {
                    let value = output.take().expect("record field produced a value");
                    fields.push(RecordFieldExpr {
                        name,
                        value,
                        pun,
                        span: field_span.join(self.expressions[value.0 as usize].span()),
                    });
                    if self.eat(|kind| matches!(kind, TokenKind::Comma)).is_some() {
                        work.push(Work::RecordNext {
                            constructor,
                            start,
                            fields,
                        });
                    } else {
                        let end = self.bump();
                        if !matches!(end.kind, TokenKind::RBrace) {
                            return Err(SyntaxError::parse(
                                "expected `}` in record construction",
                                end.span,
                            ));
                        }
                        output = Some(self.alloc_expr(Expr::RecordConstruction {
                            constructor,
                            fields,
                            span: start.join(end.span),
                        }));
                    }
                }
                Work::FinishParenthesized {
                    start,
                    mut remaining,
                } => {
                    let first = output
                        .take()
                        .expect("parenthesized expression produced a value");
                    if self.eat(|kind| matches!(kind, TokenKind::Comma)).is_some() {
                        work.push(Work::ContinueParenthesizedTuple {
                            start,
                            remaining,
                            elements: vec![first],
                        });
                        work.push(Work::ParseExpression(0));
                    } else {
                        let end = self.bump();
                        if !matches!(end.kind, TokenKind::RParen) {
                            return Err(SyntaxError::parse("expected `)`", end.span));
                        }
                        if let Some(outer) = remaining.pop() {
                            work.push(Work::FinishParenthesized {
                                start: outer,
                                remaining,
                            });
                            work.push(Work::ResumeExpression {
                                left: first,
                                minimum_precedence: 0,
                            });
                        } else {
                            output = Some(first);
                        }
                    }
                }
                Work::ContinueParenthesizedTuple {
                    start,
                    mut remaining,
                    mut elements,
                } => {
                    elements.push(output.take().expect("tuple element produced a value"));
                    if self.eat(|kind| matches!(kind, TokenKind::Comma)).is_some() {
                        work.push(Work::ContinueParenthesizedTuple {
                            start,
                            remaining,
                            elements,
                        });
                        work.push(Work::ParseExpression(0));
                    } else {
                        let end = self.bump();
                        if !matches!(end.kind, TokenKind::RParen)
                            || !(2..=4).contains(&elements.len())
                        {
                            return Err(SyntaxError::parse(
                                "tuple arity must be two through four",
                                start.join(end.span),
                            ));
                        }
                        let expression = self.alloc_expr(Expr::Tuple {
                            elements,
                            span: start.join(end.span),
                        });
                        if let Some(outer) = remaining.pop() {
                            work.push(Work::FinishParenthesized {
                                start: outer,
                                remaining,
                            });
                            work.push(Work::ResumeExpression {
                                left: expression,
                                minimum_precedence: 0,
                            });
                        } else {
                            output = Some(expression);
                        }
                    }
                }
            }
        }
        Ok(output.expect("iterative expression parser produced a value"))
    }

    fn parse_case_pattern(&mut self) -> Result<CasePattern, SyntaxError> {
        let token = self.bump();
        match token.kind {
            TokenKind::Underscore => Ok(CasePattern::Wildcard(token.span)),
            TokenKind::Upper(name) => {
                let binder = if let TokenKind::Lower(name) = self.current().kind.clone() {
                    self.bump();
                    Some(name)
                } else {
                    None
                };
                let span = binder.as_ref().map_or(token.span, |_| {
                    token.span.join(self.tokens[self.at - 1].span)
                });
                Ok(CasePattern::UserConstructor { name, binder, span })
            }
            TokenKind::Qualified(name) => {
                let mut binders = Vec::new();
                let mut end = token.span;
                while let TokenKind::Lower(binder) = self.current().kind.clone() {
                    end = self.bump().span;
                    binders.push(binder);
                }
                Ok(CasePattern::PrimitiveConstructor {
                    name,
                    binders,
                    span: token.span.join(end),
                })
            }
            _ => Err(SyntaxError::parse("unsupported case pattern", token.span)),
        }
    }

    fn parse_pattern(&mut self) -> Result<BindingPattern, SyntaxError> {
        let token = self.bump();
        let mut pattern = match token.kind {
            TokenKind::Lower(name) => BindingPattern::Variable(name, token.span),
            TokenKind::Underscore => BindingPattern::Wildcard(token.span),
            TokenKind::LParen => {
                let name_token = self.bump();
                let TokenKind::Lower(first_name) = name_token.kind else {
                    return Err(SyntaxError::parse(
                        "parenthesized and tuple binders contain variables only",
                        name_token.span,
                    ));
                };
                if let Some(end) = self.eat(|kind| matches!(kind, TokenKind::RParen)) {
                    BindingPattern::Variable(first_name, token.span.join(end.span))
                } else {
                    if self
                        .eat(|kind| matches!(kind, TokenKind::DoubleColon))
                        .is_some()
                    {
                        let ty = self.parse_type()?;
                        let end = self.bump();
                        if !matches!(end.kind, TokenKind::RParen) {
                            return Err(SyntaxError::parse("expected `)`", end.span));
                        }
                        let inner = BindingPattern::Variable(first_name, name_token.span);
                        return Ok(BindingPattern::Annotated(
                            Box::new(inner),
                            ty,
                            token.span.join(end.span),
                        ));
                    }
                    if self.eat(|kind| matches!(kind, TokenKind::Comma)).is_none() {
                        return Err(self.expected("`,` or `)` in binding pattern"));
                    }
                    let mut names = vec![first_name];
                    loop {
                        let name_token = self.bump();
                        let TokenKind::Lower(name) = name_token.kind else {
                            return Err(SyntaxError::parse(
                                "tuple binders contain variables only",
                                name_token.span,
                            ));
                        };
                        if names.iter().any(|existing| existing == &name) {
                            return Err(SyntaxError::parse(
                                format!("duplicate tuple binder `{name}`"),
                                name_token.span,
                            ));
                        }
                        names.push(name);
                        if self.eat(|kind| matches!(kind, TokenKind::Comma)).is_none() {
                            let end = self.bump();
                            if !matches!(end.kind, TokenKind::RParen) {
                                return Err(SyntaxError::parse("expected `)`", end.span));
                            }
                            if !(2..=4).contains(&names.len()) {
                                return Err(SyntaxError::parse(
                                    "tuple binder arity must be two through four",
                                    token.span.join(end.span),
                                ));
                            }
                            break BindingPattern::Tuple(names, token.span.join(end.span));
                        }
                    }
                }
            }
            _ => {
                return Err(SyntaxError::parse(
                    "unsupported binding pattern",
                    token.span,
                ));
            }
        };
        if self
            .eat(|kind| matches!(kind, TokenKind::DoubleColon))
            .is_some()
        {
            let ty = self.parse_type()?;
            let full_span = pattern_span(&pattern).join(self.types[ty.0 as usize].span());
            pattern = BindingPattern::Annotated(Box::new(pattern), ty, full_span);
        }
        Ok(pattern)
    }

    fn parse_type(&mut self) -> Result<TypeExprId, SyntaxError> {
        self.parse_type_iterative(TypeParseEntry::Type)
    }

    fn parse_type_atom(&mut self) -> Result<TypeExprId, SyntaxError> {
        self.parse_type_iterative(TypeParseEntry::Atom)
    }

    #[allow(clippy::too_many_lines)]
    fn parse_type_iterative(&mut self, entry: TypeParseEntry) -> Result<TypeExprId, SyntaxError> {
        enum Work {
            ParseType,
            ParseApplication,
            ParseAtom,
            AfterTypeApplication,
            ContinueApplication,
            CombineApplication(TypeExprId),
            FinishFunction(TypeExprId),
            FinishList(Span),
            FinishParenthesized(Span),
            ContinueTuple { start: Span, items: Vec<TypeExprId> },
        }

        let mut work = vec![match entry {
            TypeParseEntry::Type => Work::ParseType,
            TypeParseEntry::Atom => Work::ParseAtom,
        }];
        let mut output = None;
        while let Some(step) = work.pop() {
            match step {
                Work::ParseType => {
                    work.push(Work::AfterTypeApplication);
                    work.push(Work::ParseApplication);
                }
                Work::AfterTypeApplication => {
                    let left = output.take().expect("type application produced a value");
                    if self.eat(|kind| matches!(kind, TokenKind::Arrow)).is_some() {
                        work.push(Work::FinishFunction(left));
                        work.push(Work::ParseType);
                    } else {
                        output = Some(left);
                    }
                }
                Work::FinishFunction(left) => {
                    let right = output
                        .take()
                        .expect("function result type produced a value");
                    let span = self.types[left.0 as usize]
                        .span()
                        .join(self.types[right.0 as usize].span());
                    output = Some(self.alloc_type(TypeExpr::Function(left, right, span)));
                }
                Work::ParseApplication => {
                    work.push(Work::ContinueApplication);
                    work.push(Work::ParseAtom);
                }
                Work::ContinueApplication => {
                    let left = output.take().expect("type atom produced a value");
                    if starts_type_atom(&self.current().kind) {
                        work.push(Work::CombineApplication(left));
                        work.push(Work::ParseAtom);
                    } else {
                        output = Some(left);
                    }
                }
                Work::CombineApplication(left) => {
                    let right = output.take().expect("type argument produced a value");
                    let span = self.types[left.0 as usize]
                        .span()
                        .join(self.types[right.0 as usize].span());
                    output = Some(self.alloc_type(TypeExpr::Apply(left, right, span)));
                    work.push(Work::ContinueApplication);
                }
                Work::ParseAtom => {
                    let token = self.bump();
                    match token.kind {
                        TokenKind::Upper(name) | TokenKind::Qualified(name) => {
                            output = Some(self.alloc_type(TypeExpr::Name(name, token.span)));
                        }
                        TokenKind::Text(value) => {
                            output = Some(self.alloc_type(TypeExpr::Promoted(value, token.span)));
                        }
                        TokenKind::LBracket => {
                            work.push(Work::FinishList(token.span));
                            work.push(Work::ParseType);
                        }
                        TokenKind::LParen => {
                            if let Some(end) = self.eat(|kind| matches!(kind, TokenKind::RParen)) {
                                output = Some(
                                    self.alloc_type(TypeExpr::Unit(token.span.join(end.span))),
                                );
                            } else {
                                work.push(Work::FinishParenthesized(token.span));
                                work.push(Work::ParseType);
                            }
                        }
                        _ => {
                            return Err(SyntaxError::parse(
                                "expected concrete monotype",
                                token.span,
                            ));
                        }
                    }
                }
                Work::FinishList(start) => {
                    let item = output.take().expect("list item type produced a value");
                    let end = self.bump();
                    if !matches!(end.kind, TokenKind::RBracket) {
                        return Err(SyntaxError::parse("expected `]` in type", end.span));
                    }
                    output = Some(self.alloc_type(TypeExpr::List(item, start.join(end.span))));
                }
                Work::FinishParenthesized(start) => {
                    let first = output.take().expect("parenthesized type produced a value");
                    if self.eat(|kind| matches!(kind, TokenKind::Comma)).is_some() {
                        work.push(Work::ContinueTuple {
                            start,
                            items: vec![first],
                        });
                        work.push(Work::ParseType);
                    } else {
                        let end = self.bump();
                        if !matches!(end.kind, TokenKind::RParen) {
                            return Err(SyntaxError::parse("expected `)` in type", end.span));
                        }
                        output = Some(first);
                    }
                }
                Work::ContinueTuple { start, mut items } => {
                    items.push(output.take().expect("tuple item type produced a value"));
                    if self.eat(|kind| matches!(kind, TokenKind::Comma)).is_some() {
                        work.push(Work::ContinueTuple { start, items });
                        work.push(Work::ParseType);
                    } else {
                        let end = self.bump();
                        if !matches!(end.kind, TokenKind::RParen) || !(2..=4).contains(&items.len())
                        {
                            return Err(SyntaxError::parse(
                                "tuple type arity must be two through four",
                                start.join(end.span),
                            ));
                        }
                        output =
                            Some(self.alloc_type(TypeExpr::Tuple(items, start.join(end.span))));
                    }
                }
            }
        }
        Ok(output.expect("iterative type parser produced a value"))
    }
}

#[derive(Clone, Copy)]
enum TypeParseEntry {
    Type,
    Atom,
}

fn pattern_span(pattern: &BindingPattern) -> Span {
    match pattern {
        BindingPattern::Variable(_, span)
        | BindingPattern::Wildcard(span)
        | BindingPattern::Tuple(_, span)
        | BindingPattern::Annotated(_, _, span) => *span,
    }
}

fn starts_expression_atom(kind: &TokenKind) -> bool {
    matches!(
        kind,
        TokenKind::Lower(_)
            | TokenKind::Upper(_)
            | TokenKind::Qualified(_)
            | TokenKind::Integer(_)
            | TokenKind::Fraction(_)
            | TokenKind::Character(_)
            | TokenKind::Text(_)
            | TokenKind::LParen
            | TokenKind::LBracket
            | TokenKind::Backslash
            | TokenKind::KwIf
            | TokenKind::KwCase
            | TokenKind::KwDo
    )
}

fn starts_type_atom(kind: &TokenKind) -> bool {
    matches!(
        kind,
        TokenKind::Upper(_)
            | TokenKind::Qualified(_)
            | TokenKind::Text(_)
            | TokenKind::LParen
            | TokenKind::LBracket
    )
}

fn fixity(operator: &str) -> Option<(u8, bool)> {
    match operator {
        "$" => Some((0, true)),
        "<$>" | "<*>" | "<**>" => Some((4, false)),
        "<>" => Some((6, true)),
        "." => Some((9, true)),
        _ => None,
    }
}

/// Parses one normalized Hell source file.
///
/// # Errors
///
/// Returns every lexical error, or the parser errors recovered at declaration boundaries.
pub fn parse(source: &SourceFile) -> Result<ParsedFile, Vec<SyntaxError>> {
    parse_with_limits(source, ParserLimits::sandboxed())
}

/// Parses one normalized Hell source file with explicit resource limits.
///
/// # Errors
///
/// Returns every lexical error, or parser errors recovered at declaration boundaries.
pub fn parse_with_limits(
    source: &SourceFile,
    limits: ParserLimits,
) -> Result<ParsedFile, Vec<SyntaxError>> {
    parse_on_current_thread(source, limits)
}

fn parse_on_current_thread(
    source: &SourceFile,
    limits: ParserLimits,
) -> Result<ParsedFile, Vec<SyntaxError>> {
    let tokens = lex(source)?;
    if limits
        .max_tokens
        .is_some_and(|configured| tokens.len() > configured)
    {
        return Err(vec![SyntaxError::resource(
            "H0802",
            format!(
                "token budget exceeded: operation=parse_tokens profile={} configured={} observed={}",
                limits.profile_id,
                limits.max_tokens.expect("finite token limit checked"),
                tokens.len()
            ),
            source.eof_span(),
        )]);
    }
    reject_excessive_delimiter_nesting(&tokens, limits.max_nesting_depth, limits.profile_id)?;
    Parser {
        tokens,
        at: 0,
        expressions: Vec::new(),
        types: Vec::new(),
        errors: Vec::new(),
    }
    .parse()
}

fn reject_excessive_delimiter_nesting(
    tokens: &[Token],
    max_nesting_depth: Option<usize>,
    profile_id: &str,
) -> Result<(), Vec<SyntaxError>> {
    // Reject unsafe input before recursive descent accumulates parser frames.
    // The parser's own guard remains the grammar-level backstop.
    let mut depth = 0_usize;
    for token in tokens {
        match token.kind {
            TokenKind::LParen | TokenKind::LBracket | TokenKind::LBrace => {
                if max_nesting_depth.is_some_and(|limit| depth >= limit) {
                    return Err(vec![SyntaxError::resource_limit(
                        format!(
                            "parser nesting limit exceeded: operation=parse_nesting profile={profile_id} configured={} observed={}",
                            max_nesting_depth.expect("finite nesting limit checked"),
                            depth.saturating_add(1)
                        ),
                        token.span,
                    )]);
                }
                depth += 1;
            }
            TokenKind::RParen | TokenKind::RBracket | TokenKind::RBrace => {
                depth = depth.saturating_sub(1);
            }
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use hell_source::{SourceFile, SourceMap};

    use super::{ParserLimits, parse, parse_with_limits};

    fn nested_application_source(delimiter_depth: usize) -> Arc<SourceFile> {
        let application_depth = delimiter_depth
            .checked_sub(1)
            .expect("the unit expression requires one delimiter level");
        let text = format!(
            "main = IO.pure {}(){}\n",
            "Function.id (".repeat(application_depth),
            ")".repeat(application_depth)
        );
        SourceMap::new().add_text("nesting.hell", text)
    }

    #[test]
    fn parser_accepts_the_depth_limit_and_rejects_the_next_level() {
        let limit = ParserLimits::sandboxed()
            .max_nesting_depth
            .expect("sandboxed parsing has a nesting limit");
        let at_limit = nested_application_source(limit);
        parse(&at_limit).expect("the configured parser depth limit must remain accepted");

        let beyond_limit = nested_application_source(limit + 1);
        let errors =
            parse(&beyond_limit).expect_err("input beyond the parser depth limit must be rejected");
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].code, "H0801");
        assert_eq!(
            errors[0].message.as_ref(),
            "parser nesting limit exceeded: operation=parse_nesting profile=sandboxed configured=64 observed=65"
        );
    }

    #[test]
    fn token_limit_reports_profile_operation_and_amounts() {
        let source = SourceMap::new().add_text("tokens.hell", "main = IO.pure ()\n");
        let limits = ParserLimits {
            max_tokens: Some(1),
            ..ParserLimits::sandboxed()
        };
        let errors = parse_with_limits(&source, limits).unwrap_err();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].code, "H0802");
        let message = errors[0].message.as_ref();
        assert!(message.contains("operation=parse_tokens"));
        assert!(message.contains("profile=sandboxed"));
        assert!(message.contains("configured=1"));
        assert!(message.contains("observed="));
    }

    #[test]
    fn upstream_policy_accepts_source_beyond_the_sandbox_limit() {
        let source = nested_application_source(4_096);
        parse_with_limits(&source, ParserLimits::upstream())
            .expect("upstream parsing must not apply the sandbox nesting limit");
    }

    fn generated_source(expression: &str) -> Arc<SourceFile> {
        SourceMap::new().add_text("deep-generated.hell", format!("main = {expression}\n"))
    }

    #[test]
    fn upstream_parser_uses_heap_worklists_for_deep_expression_families() {
        let depth = 2_048;
        let cases = [
            format!("{}(){}", "[".repeat(depth), "]".repeat(depth)),
            format!("({}{})", "\\value -> ".repeat(depth), "()"),
            format!(
                "{}(){}",
                "case True of { _ -> ".repeat(depth),
                " }".repeat(depth)
            ),
            format!("{}IO.pure (){}", "do { ".repeat(depth), " }".repeat(depth)),
            format!(
                "{}(){}",
                "Main.Record { field = ".repeat(depth),
                " }".repeat(depth)
            ),
        ];
        for expression in cases {
            parse_with_limits(&generated_source(&expression), ParserLimits::upstream())
                .expect("deep generated expression must parse without native-stack growth");
        }
    }

    #[test]
    fn upstream_parser_uses_heap_worklists_for_deep_types_and_reports_eof() {
        let depth = 4_096;
        let nested_list_type = format!("{}(){}", "[".repeat(depth), "]".repeat(depth));
        let source = SourceMap::new().add_text(
            "deep-type.hell",
            format!("value :: {nested_list_type} = ()\nmain = IO.pure ()\n"),
        );
        parse_with_limits(&source, ParserLimits::upstream())
            .expect("deep list type must parse without native-stack growth");

        let arrow_type = format!("{}()", "() -> ".repeat(depth));
        let source = SourceMap::new().add_text(
            "deep-arrow.hell",
            format!("value :: {arrow_type} = ()\nmain = IO.pure ()\n"),
        );
        parse_with_limits(&source, ParserLimits::upstream())
            .expect("deep function type must parse without native-stack growth");

        let malformed_expression = format!("{}()", "[".repeat(depth));
        let malformed = generated_source(&malformed_expression);
        let errors = parse_with_limits(&malformed, ParserLimits::upstream())
            .expect_err("unterminated deep list must remain a structural parse failure");
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].code, "H0200");
        assert_eq!(errors[0].span, malformed.eof_span());
    }
}
