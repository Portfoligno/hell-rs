use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use miniz_oxide::inflate::TINFLStatus;
use miniz_oxide::inflate::core::inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF;
use miniz_oxide::inflate::core::{DecompressorOxide, decompress};

use crate::ArchiveLimits;

const TAR_BLOCK: usize = 512;

#[derive(Clone, Debug)]
pub(crate) struct MemberSet {
    pub files: BTreeMap<String, Vec<u8>>,
    pub directories: BTreeSet<String>,
}

pub(crate) struct Error {
    pub(crate) code: &'static str,
    pub(crate) message: String,
}

impl Error {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl From<String> for Error {
    fn from(message: String) -> Self {
        Self::new("release.archive.invalid", message)
    }
}

pub(crate) fn read(
    path: &Path,
    expected_mtime: Option<u64>,
    limits: ArchiveLimits,
) -> Result<MemberSet, String> {
    read_classified(path, expected_mtime, limits).map_err(|error| error.message)
}

pub(crate) fn read_classified(
    path: &Path,
    expected_mtime: Option<u64>,
    limits: ArchiveLimits,
) -> Result<MemberSet, Error> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect archive {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || usize::try_from(metadata.len())
            .map_or(true, |size| size > limits.maximum_compressed_bytes)
    {
        return Err(Error::new(
            "release.limit.archive-compressed",
            "archive is not a bounded regular file",
        ));
    }
    let compressed = fs::read(path)
        .map_err(|error| format!("cannot read archive {}: {error}", path.display()))?;
    let expanded = gunzip(&compressed, limits.maximum_expanded_bytes)?;
    read_tar(&expanded, expected_mtime, limits)
}

fn gunzip(bytes: &[u8], maximum_expanded_bytes: usize) -> Result<Vec<u8>, Error> {
    const HEADER: [u8; 10] = [0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 2, 255];
    if bytes.len() < HEADER.len().saturating_add(8) || bytes[..HEADER.len()] != HEADER {
        return Err(Error::new(
            "release.archive.gzip-header",
            "gzip header is not the canonical single-member header",
        ));
    }
    let trailer_start = bytes
        .len()
        .checked_sub(8)
        .ok_or_else(|| "gzip trailer is absent".to_owned())?;
    let deflate = &bytes[HEADER.len()..trailer_start];
    let trailer = &bytes[trailer_start..];
    let expanded_size = u32::from_le_bytes(
        trailer[4..8]
            .try_into()
            .map_err(|_| "gzip size trailer is truncated".to_owned())?,
    );
    let expanded_size = usize::try_from(expanded_size)
        .map_err(|_| "gzip expanded size does not fit memory".to_owned())?;
    if expanded_size > maximum_expanded_bytes {
        return Err(Error::new(
            "release.limit.archive-expanded",
            "gzip expanded size exceeds the independent verifier limit",
        ));
    }
    let mut output = vec![0_u8; expanded_size];
    let mut state = DecompressorOxide::new();
    let (status, bytes_consumed, bytes_written) = decompress(
        &mut state,
        deflate,
        &mut output,
        0,
        TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF,
    );
    if status != TINFLStatus::Done
        || bytes_consumed != deflate.len()
        || bytes_written != output.len()
    {
        return Err(Error::new(
            "release.archive.trailing-gzip-member",
            "gzip contains an invalid stream, trailing bytes, or another member",
        ));
    }
    let expected_crc = u32::from_le_bytes(
        trailer[..4]
            .try_into()
            .map_err(|_| "gzip CRC trailer is truncated".to_owned())?,
    );
    if crc32(&output) != expected_crc {
        return Err(Error::new(
            "release.archive.gzip-crc",
            "gzip CRC differs from expanded bytes",
        ));
    }
    Ok(output)
}

pub(crate) fn fuzz_gzip(bytes: &[u8]) -> Result<(), String> {
    gunzip(bytes, ArchiveLimits::default().maximum_expanded_bytes)
        .map(|_| ())
        .map_err(|error| error.message)
}

fn read_tar(
    bytes: &[u8],
    expected_mtime: Option<u64>,
    limits: ArchiveLimits,
) -> Result<MemberSet, Error> {
    if !bytes.len().is_multiple_of(TAR_BLOCK) {
        return Err("tar stream is not block-aligned".to_owned().into());
    }
    let mut reader = TarReader::new(bytes, expected_mtime, limits);
    while let Some(header) = reader.next_header()? {
        reader.insert(header)?;
    }
    reader.finish()
}

struct TarHeader {
    path: String,
    mode: u64,
    size: u64,
    kind: u8,
}

struct TarReader<'a> {
    bytes: &'a [u8],
    expected_mtime: Option<u64>,
    limits: ArchiveLimits,
    files: BTreeMap<String, Vec<u8>>,
    directories: BTreeSet<String>,
    offset: usize,
    zero_blocks: usize,
    total_payload: u64,
    previous_path: Option<String>,
    observed_paths: BTreeSet<String>,
}

impl<'a> TarReader<'a> {
    fn new(bytes: &'a [u8], expected_mtime: Option<u64>, limits: ArchiveLimits) -> Self {
        Self {
            bytes,
            expected_mtime,
            limits,
            files: BTreeMap::new(),
            directories: BTreeSet::new(),
            offset: 0,
            zero_blocks: 0,
            total_payload: 0,
            previous_path: None,
            observed_paths: BTreeSet::new(),
        }
    }

    fn next_header(&mut self) -> Result<Option<TarHeader>, Error> {
        if self.offset == self.bytes.len() {
            return Ok(None);
        }
        let end = self
            .offset
            .checked_add(TAR_BLOCK)
            .ok_or_else(|| "tar block offset overflow".to_owned())?;
        let header = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| "tar header is truncated".to_owned())?;
        self.offset = end;
        if header.iter().all(|byte| *byte == 0) {
            self.zero_blocks = self
                .zero_blocks
                .checked_add(1)
                .ok_or_else(|| "tar zero-block count overflow".to_owned())?;
            return self.next_header();
        }
        if self.zero_blocks != 0 {
            return Err("tar contains data after an end marker".to_owned().into());
        }
        let count = self
            .files
            .len()
            .checked_add(self.directories.len())
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| "tar member count overflow".to_owned())?;
        if count > self.limits.maximum_members {
            return Err(Error::new(
                "release.limit.archive-members",
                "tar member count exceeds the independent verifier limit",
            ));
        }
        validate_checksum(header)
            .map_err(|message| Error::new("release.archive.tar-checksum", message))?;
        let path = header_text(&header[..100], "tar path")?;
        validate_path(&path, self.limits.maximum_path_bytes).map_err(|message| {
            let code = if path.starts_with('/') || path.as_bytes().get(1) == Some(&b':') {
                "release.archive.absolute-path"
            } else if path.split('/').any(|component| component == "..") {
                "release.archive.path-traversal"
            } else {
                "release.archive.path"
            };
            Error::new(code, message)
        })?;
        if !self.observed_paths.insert(path.clone()) {
            return Err(Error::new(
                "release.archive.duplicate-member",
                "tar contains a duplicate path",
            ));
        }
        if self
            .previous_path
            .as_ref()
            .is_some_and(|previous| previous >= &path)
        {
            return Err(Error::new(
                "release.archive.noncanonical-order",
                "tar paths are not in canonical order",
            ));
        }
        self.previous_path = Some(path.clone());
        validate_canonical_header(header)?;
        let mode = octal(&header[100..108], "tar mode")?;
        let uid = octal(&header[108..116], "tar uid")?;
        let gid = octal(&header[116..124], "tar gid")?;
        let size = octal(&header[124..136], "tar member size")?;
        let mtime = octal(&header[136..148], "tar mtime")?;
        if uid != 0
            || gid != 0
            || self
                .expected_mtime
                .is_some_and(|expected| expected != mtime)
        {
            return Err("tar ownership or modification time is not canonical"
                .to_owned()
                .into());
        }
        Ok(Some(TarHeader {
            path,
            mode,
            size,
            kind: header[156],
        }))
    }

    fn insert(&mut self, header: TarHeader) -> Result<(), Error> {
        match header.kind {
            0 | b'0' => self.insert_file(header),
            b'5' => self.insert_directory(header),
            _ => Err(Error::new(
                "release.archive.unsupported-type",
                "tar contains a link, extension, or special entry",
            )),
        }
    }

    fn insert_file(&mut self, header: TarHeader) -> Result<(), Error> {
        let executable = header.path.ends_with("/hell") || header.path.ends_with("/hell.exe");
        let expected_mode = if executable { 0o755 } else { 0o644 };
        if header.size
            > u64::try_from(self.limits.maximum_expanded_bytes)
                .map_err(|_| "archive expansion limit does not fit u64".to_owned())?
            || header.mode != expected_mode
        {
            return Err("tar regular-file size or mode is not canonical"
                .to_owned()
                .into());
        }
        self.total_payload = self
            .total_payload
            .checked_add(header.size)
            .ok_or_else(|| "tar payload size overflow".to_owned())?;
        if self.total_payload
            > u64::try_from(self.limits.maximum_expanded_bytes)
                .map_err(|_| "archive expansion limit does not fit u64".to_owned())?
        {
            return Err(Error::new(
                "release.limit.archive-expanded",
                "tar cumulative payload exceeds the independent verifier limit",
            ));
        }
        let size = usize::try_from(header.size)
            .map_err(|_| "tar member size does not fit memory".to_owned())?;
        let payload_end = self
            .offset
            .checked_add(size)
            .ok_or_else(|| "tar payload offset overflow".to_owned())?;
        let payload = self
            .bytes
            .get(self.offset..payload_end)
            .ok_or_else(|| "tar payload is truncated".to_owned())?
            .to_vec();
        if self.files.insert(header.path, payload).is_some() {
            return Err(Error::new(
                "release.archive.duplicate-member",
                "tar contains a duplicate path",
            ));
        }
        self.advance_past_padding(size, payload_end)
    }

    fn insert_directory(&mut self, header: TarHeader) -> Result<(), Error> {
        if header.size != 0 || header.mode != 0o755 || !self.directories.insert(header.path) {
            return Err(Error::new(
                "release.archive.duplicate-member",
                "tar directory is duplicated or not canonical",
            ));
        }
        Ok(())
    }

    fn advance_past_padding(&mut self, size: usize, payload_end: usize) -> Result<(), Error> {
        let blocks = size
            .checked_add(TAR_BLOCK - 1)
            .ok_or_else(|| "tar padding overflow".to_owned())?
            / TAR_BLOCK;
        self.offset = self
            .offset
            .checked_add(
                blocks
                    .checked_mul(TAR_BLOCK)
                    .ok_or_else(|| "tar padding overflow".to_owned())?,
            )
            .ok_or_else(|| "tar payload offset overflow".to_owned())?;
        if self.offset > self.bytes.len() {
            return Err("tar padding is truncated".to_owned().into());
        }
        if self.bytes[payload_end..self.offset]
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err("tar payload padding is not zero".to_owned().into());
        }
        Ok(())
    }

    fn finish(self) -> Result<MemberSet, Error> {
        if self.zero_blocks < 2 {
            return Err("tar stream lacks two end-marker blocks".to_owned().into());
        }
        Ok(MemberSet {
            files: self.files,
            directories: self.directories,
        })
    }
}

fn validate_canonical_header(header: &[u8]) -> Result<(), Error> {
    if header[257..265] != *b"ustar  \0"
        || header[345..500].iter().any(|byte| *byte != 0)
        || header[157..257].iter().any(|byte| *byte != 0)
        || header[329..345].iter().any(|byte| *byte != 0)
        || header[500..512].iter().any(|byte| *byte != 0)
    {
        return Err("tar is not a canonical GNU v1 header".to_owned().into());
    }
    if header[265..329].iter().any(|byte| *byte != 0) {
        return Err("tar user or group name is not empty".to_owned().into());
    }
    Ok(())
}

pub(crate) fn fuzz_tar(bytes: &[u8]) -> Result<(), String> {
    read_tar(bytes, Some(0), ArchiveLimits::default())
        .map(|_| ())
        .map_err(|error| error.message)
}

fn validate_checksum(header: &[u8]) -> Result<(), String> {
    let stated = octal(&header[148..156], "tar checksum")?;
    let observed = header
        .iter()
        .enumerate()
        .try_fold(0_u64, |sum, (index, byte)| {
            sum.checked_add(if (148..156).contains(&index) {
                u64::from(b' ')
            } else {
                u64::from(*byte)
            })
        })
        .ok_or_else(|| "tar checksum overflow".to_owned())?;
    if stated != observed {
        return Err("tar header checksum differs".to_owned());
    }
    Ok(())
}

fn octal(bytes: &[u8], label: &str) -> Result<u64, String> {
    if bytes.first().is_some_and(|byte| byte & 0x80 != 0) {
        return Err(format!("{label} uses unsupported base-256 encoding"));
    }
    let mut value = 0_u64;
    let mut saw_digit = false;
    let mut terminated = false;
    for byte in bytes {
        match *byte {
            b'0'..=b'7' if !terminated => {
                saw_digit = true;
                value = value
                    .checked_mul(8)
                    .and_then(|current| current.checked_add(u64::from(*byte - b'0')))
                    .ok_or_else(|| format!("{label} overflows"))?;
            }
            0 | b' ' => terminated = true,
            _ => return Err(format!("{label} is not canonical octal")),
        }
    }
    if !saw_digit {
        return Err(format!("{label} has no octal digits"));
    }
    Ok(value)
}

fn header_text(bytes: &[u8], label: &str) -> Result<String, String> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    if bytes[end..].iter().any(|byte| *byte != 0) {
        return Err(format!("{label} has data after its terminator"));
    }
    std::str::from_utf8(&bytes[..end])
        .map(str::to_owned)
        .map_err(|_| format!("{label} is not UTF-8"))
}

fn validate_path(path: &str, maximum_path_bytes: usize) -> Result<(), String> {
    if path.is_empty()
        || path.len() > maximum_path_bytes
        || path.starts_with('/')
        || path.contains('\\')
        || path.contains("//")
        || path.as_bytes().get(1) == Some(&b':')
        || path
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err("tar path is absolute, noncanonical, or escapes its root".to_owned());
    }
    Ok(())
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0_u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}
