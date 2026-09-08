use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::{CandidateBoundaryPolicy, PlatformId};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeArgument {
    pub display: String,
    pub raw: Option<NativeArgumentRaw>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeArgumentRaw {
    pub encoding: String,
    pub data: String,
}

impl NativeArgument {
    #[must_use]
    pub fn from_os_str(value: &OsStr) -> Self {
        if let Some(display) = value.to_str() {
            return Self {
                display: display.to_owned(),
                raw: None,
            };
        }
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt as _;
            Self {
                display: value.to_string_lossy().into_owned(),
                raw: Some(NativeArgumentRaw {
                    encoding: "unix-bytes-base64".to_owned(),
                    data: base64::engine::general_purpose::STANDARD.encode(value.as_bytes()),
                }),
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt as _;
            let bytes = value
                .encode_wide()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>();
            Self {
                display: value.to_string_lossy().into_owned(),
                raw: Some(NativeArgumentRaw {
                    encoding: "windows-u16le-base64".to_owned(),
                    data: base64::engine::general_purpose::STANDARD.encode(bytes),
                }),
            }
        }
    }

    /// Validates that exactly one lossless native representation is present.
    ///
    /// # Errors
    ///
    /// Returns an error for ambiguous or malformed native encodings.
    pub fn validate(&self) -> Result<(), &'static str> {
        let Some(raw) = &self.raw else {
            return Ok(());
        };
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&raw.data)
            .map_err(|_| "native argument contains invalid base64")?;
        match raw.encoding.as_str() {
            "unix-bytes-base64" => {
                if std::str::from_utf8(&decoded).is_ok() {
                    return Err("native Unix raw argument redundantly encodes valid UTF-8");
                }
                if String::from_utf8_lossy(&decoded) != self.display {
                    return Err("native Unix argument display disagrees with raw bytes");
                }
            }
            "windows-u16le-base64" if decoded.len() % 2 == 0 => {
                let units = decoded
                    .chunks_exact(2)
                    .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
                    .collect::<Vec<_>>();
                if String::from_utf16(&units).is_ok() {
                    return Err("native Windows raw argument redundantly encodes valid UTF-16");
                }
                if String::from_utf16_lossy(&units) != self.display {
                    return Err("native Windows argument display disagrees with raw UTF-16");
                }
            }
            "windows-u16le-base64" => {
                return Err("native Windows argument has an odd UTF-16 byte length");
            }
            _ => return Err("native argument uses an unsupported raw encoding"),
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedCandidateRequest {
    pub operation_id: String,
    pub platform: PlatformId,
    pub boundary: CandidateBoundaryPolicy,
    pub program: PathBuf,
    pub arguments: Vec<OsString>,
    pub cwd: PathBuf,
    pub environment: BTreeMap<OsString, OsString>,
    pub candidate_policy_digest: String,
    pub stdin: Vec<u8>,
}

#[derive(Debug)]
pub struct PreparedSealedInvocation<A> {
    pub memcordon: PathBuf,
    pub arguments: Vec<OsString>,
    pub report: PathBuf,
    pub request_digest: String,
    pub admission: A,
}

/// Builds the exact rc.23 sealed CLI arguments without shell interpretation.
///
/// # Errors
///
/// Returns an error for relative paths or a non-positive millisecond budget.
pub fn sealed_arguments(
    report: &Path,
    budget: Duration,
    target: &Path,
    target_args: &[OsString],
) -> io::Result<Vec<OsString>> {
    if !report.is_absolute() || !target.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "report and target paths must be absolute",
        ));
    }
    let millis = u64::try_from(budget.as_millis())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "budget is too large"))?;
    if millis == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "sealed attempt requires a positive millisecond budget",
        ));
    }
    let mut arguments = vec![
        OsString::from("--sealed"),
        OsString::from("--quiet"),
        OsString::from("--report"),
        report.as_os_str().to_owned(),
        OsString::from(format!("+{millis}ms")),
        OsString::from("--deadline-scope"),
        OsString::from("attempt"),
        OsString::from("--wait-for"),
        OsString::from("command"),
        OsString::from("--command-exit-grace"),
        OsString::from("0ms"),
        OsString::from("--"),
        target.as_os_str().to_owned(),
    ];
    arguments.extend_from_slice(target_args);
    Ok(arguments)
}
