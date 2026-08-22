mod archive;
mod digest;
mod external_inputs;
mod json;
mod model;
mod verifier;

pub mod fuzz;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub use verifier::{Options as VerifyOptions, verify, verify_envelope, verify_vectors};

/// Reconstructs the independently parsed external-input-lock digest.
///
/// # Errors
///
/// Returns an error when the lock is not the strict supported TOML subset or
/// does not contain the exact oracle authorities required by the protocol.
pub fn external_input_lock_sha256(path: &Path) -> Result<String, String> {
    external_inputs::load(path).map(|authority| authority.sha256)
}

/// Requires a claimed digest to equal the independently reconstructed lock.
///
/// # Errors
///
/// Returns an error when the lock is invalid, the claim is not a digest, or
/// the claim does not bind the exact typed lock contents.
pub fn validate_external_input_lock(path: &Path, expected: &str) -> Result<(), String> {
    let authority = external_inputs::load(path)?;
    external_inputs::require_expected(&authority, expected)
}

/// Validates the independent release-gate document schema and self-digest.
///
/// # Errors
///
/// Returns an error when the bytes are not canonical JSON, carry a field
/// outside the pre-governance gate schema, or have a forged self-digest.
pub fn validate_release_gate_document(bytes: &[u8]) -> Result<(), String> {
    verifier::validate_release_gate_document(bytes).map(|_| ())
}

/// Replays one semantic obligation against an independently parsed observation.
///
/// This narrow surface exists for external adversarial tests and fuzz targets;
/// release admission invokes the same implementation through the evidence
/// ledger.
///
/// # Errors
///
/// Returns an error when the observation or its target-scoped semantic facts
/// do not satisfy the named closed obligation class.
pub fn validate_semantic_obligation_observation(
    bytes: &[u8],
    builtin_name: &str,
    builtin_id: u64,
    obligation: &str,
) -> Result<(), String> {
    verifier::validate_semantic_obligation_observation(bytes, builtin_name, builtin_id, obligation)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArchiveLimits {
    pub maximum_compressed_bytes: usize,
    pub maximum_expanded_bytes: usize,
    pub maximum_members: usize,
    pub maximum_path_bytes: usize,
}

impl Default for ArchiveLimits {
    fn default() -> Self {
        Self {
            maximum_compressed_bytes: 256 * 1024 * 1024,
            maximum_expanded_bytes: 1024 * 1024 * 1024,
            maximum_members: 65_536,
            maximum_path_bytes: 4096,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalArchive {
    pub files: BTreeMap<String, Vec<u8>>,
    pub directories: BTreeSet<String>,
}

/// Reads and validates a canonical GNU tar gzip archive.
///
/// # Errors
///
/// Returns an error when the archive cannot be read, exceeds a limit, or is
/// not encoded with the canonical archive profile.
pub fn read_canonical_gnu_tar_gzip(
    path: &Path,
    expected_mtime: Option<u64>,
    limits: ArchiveLimits,
) -> Result<CanonicalArchive, String> {
    let members = archive::read(path, expected_mtime, limits)?;
    Ok(CanonicalArchive {
        files: members.files,
        directories: members.directories,
    })
}

pub mod strict_json {
    /// Parses bytes as the verifier's canonical JSON subset.
    ///
    /// # Errors
    ///
    /// Returns an error when the bytes are not canonical JSON or exceed the
    /// parser's structural limits.
    pub fn parse_canonical(bytes: &[u8]) -> Result<(), String> {
        super::json::parse_canonical(bytes).map(|_| ())
    }
}
