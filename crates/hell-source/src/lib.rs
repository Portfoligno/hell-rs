//! Source ownership, UTF-8 validation, shebang trivia, and byte spans.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SourceId(pub u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Span {
    pub source: SourceId,
    pub start: u32,
    pub end: u32,
}

impl Span {
    #[must_use]
    pub const fn new(source: SourceId, start: u32, end: u32) -> Self {
        Self { source, start, end }
    }

    #[must_use]
    pub const fn empty(source: SourceId, at: u32) -> Self {
        Self::new(source, at, at)
    }

    #[must_use]
    pub const fn join(self, other: Self) -> Self {
        debug_assert!(self.source.0 == other.source.0);
        Self::new(self.source, self.start, other.end)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SourceName {
    Path(PathBuf),
    Virtual(Arc<str>),
}

impl fmt::Display for SourceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Path(path) => write!(f, "{}", path.display()),
            Self::Virtual(name) => f.write_str(name),
        }
    }
}

#[derive(Clone, Debug)]
pub struct SourceFile {
    pub id: SourceId,
    pub name: SourceName,
    pub bytes: Arc<[u8]>,
    pub text: Arc<str>,
    pub line_starts: Arc<[u32]>,
    pub shebang: Option<Span>,
}

impl SourceFile {
    #[must_use]
    pub fn eof_span(&self) -> Span {
        Span::empty(self.id, u32::try_from(self.bytes.len()).unwrap_or(u32::MAX))
    }

    #[must_use]
    pub fn slice(&self, span: Span) -> Option<&str> {
        if span.source != self.id {
            return None;
        }
        self.text.get(span.start as usize..span.end as usize)
    }

    /// Returns one-based `(line, display_column)`. Tabs advance to eight-column
    /// stops, matching the layout engine.
    #[must_use]
    pub fn line_column(&self, offset: u32) -> Option<(u32, u32)> {
        let offset = usize::try_from(offset).ok()?.min(self.text.len());
        if !self.text.is_char_boundary(offset) {
            return None;
        }
        let offset_u32 = u32::try_from(offset).ok()?;
        let line_index = match self.line_starts.binary_search(&offset_u32) {
            Ok(index) => index,
            Err(index) => index.saturating_sub(1),
        };
        let start = self.line_starts[line_index] as usize;
        let end = offset;
        let mut column = 1_u32;
        for ch in self.text[start..end].chars() {
            column = if ch == '\t' {
                ((column - 1) / 8 + 1) * 8 + 1
            } else {
                column.saturating_add(1)
            };
        }
        Some((u32::try_from(line_index).ok()?.checked_add(1)?, column))
    }
}

#[derive(Clone, Debug, Default)]
pub struct SourceMap {
    files: Vec<Arc<SourceFile>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Utf8SourceError {
    pub valid_up_to: usize,
    pub error_len: Option<usize>,
}

impl fmt::Display for Utf8SourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "source is not UTF-8 at byte {}", self.valid_up_to)
    }
}

impl std::error::Error for Utf8SourceError {}

impl SourceMap {
    #[must_use]
    pub const fn new() -> Self {
        Self { files: Vec::new() }
    }

    /// Adds a byte source after validating UTF-8 and representable byte spans.
    ///
    /// # Errors
    ///
    /// Returns the exact invalid UTF-8 interval, or a controlled size error if
    /// the source cannot be represented by the 32-bit span format.
    pub fn add_bytes(
        &mut self,
        name: SourceName,
        bytes: impl Into<Arc<[u8]>>,
    ) -> Result<Arc<SourceFile>, Utf8SourceError> {
        let bytes = bytes.into();
        let text = std::str::from_utf8(&bytes).map_err(|error| Utf8SourceError {
            valid_up_to: error.valid_up_to(),
            error_len: error.error_len(),
        })?;
        let id = SourceId(
            u32::try_from(self.files.len()).map_err(|_| Utf8SourceError {
                valid_up_to: bytes.len(),
                error_len: None,
            })?,
        );
        let mut starts = vec![0_u32];
        for (index, byte) in bytes.iter().enumerate() {
            if *byte == b'\n' {
                starts.push(u32::try_from(index + 1).map_err(|_| Utf8SourceError {
                    valid_up_to: index,
                    error_len: None,
                })?);
            }
        }
        let shebang = if bytes.starts_with(b"#!") {
            let end = bytes
                .iter()
                .position(|byte| *byte == b'\n')
                .unwrap_or(bytes.len());
            Some(Span::new(
                id,
                0,
                u32::try_from(end).map_err(|_| Utf8SourceError {
                    valid_up_to: end,
                    error_len: None,
                })?,
            ))
        } else {
            None
        };
        let text: Arc<str> = Arc::from(text);
        let file = Arc::new(SourceFile {
            id,
            name,
            bytes,
            text,
            line_starts: starts.into(),
            shebang,
        });
        self.files.push(Arc::clone(&file));
        Ok(file)
    }

    /// Adds an already validated Rust string as a virtual source.
    ///
    /// # Panics
    ///
    /// Panics only if the source arena exceeds the representable 32-bit source
    /// id space; Rust strings themselves are always valid UTF-8.
    pub fn add_text(
        &mut self,
        name: impl Into<Arc<str>>,
        text: impl Into<Arc<str>>,
    ) -> Arc<SourceFile> {
        let text = text.into();
        self.add_bytes(
            SourceName::Virtual(name.into()),
            Arc::<[u8]>::from(text.as_bytes()),
        )
        .expect("a Rust string is valid UTF-8")
    }

    /// Reads and validates a source file.
    ///
    /// # Errors
    ///
    /// Returns filesystem errors as-is and maps invalid UTF-8 to
    /// [`std::io::ErrorKind::InvalidData`].
    pub fn read_file(&mut self, path: &Path) -> std::io::Result<Arc<SourceFile>> {
        let bytes = std::fs::read(path)?;
        self.add_bytes(SourceName::Path(path.to_owned()), bytes)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
    }

    #[must_use]
    pub fn get(&self, id: SourceId) -> Option<&Arc<SourceFile>> {
        self.files.get(id.0 as usize)
    }
}
