//! Reusable assurance admission surfaces shared by the command and robustness harnesses.
#![allow(dead_code)]

mod assurance;
mod catalog_lock;
mod command;
mod custody_ops;
mod fixtures;
mod fuzz_surfaces;
mod offline_review_ops;
mod oracle_ops;
mod oracle_record;
mod policy;
mod promotion_policy;
mod release_oracle;
mod report;
mod strict_toml;
mod suite;
mod surveillance_impact;
mod surveillance_ops;
#[cfg(test)]
mod synthetic_promotion;
mod worklist_encoding;

/// Runs the exact acquisition-receipt semantic admission used by production.
///
/// # Errors
///
/// Returns the production admission error for malformed or inconsistent bytes.
pub fn fuzz_admit_acquisition_receipt(bytes: &[u8]) -> Result<(), String> {
    assurance::fuzz_admit_acquisition_receipt(bytes)
}

/// Runs the exact build-provenance semantic admission used by production.
///
/// # Errors
///
/// Returns the production admission error for malformed or inconsistent bytes.
pub fn fuzz_admit_provenance_record(bytes: &[u8]) -> Result<(), String> {
    assurance::fuzz_admit_provenance_record(bytes)
}

/// Runs the exact custody upload-receipt semantic admission used by production.
///
/// # Errors
///
/// Returns the production admission error for malformed or inconsistent bytes.
pub fn fuzz_admit_custody_receipt(bytes: &[u8]) -> Result<(), String> {
    custody_ops::fuzz_admit_custody_receipt(bytes)
}

/// Runs the exact declared-review-graph semantic comparison used by production.
///
/// # Errors
///
/// Returns the production admission error for malformed or inconsistent bytes.
pub fn fuzz_admit_review_graph(bytes: &[u8]) -> Result<(), String> {
    assurance::fuzz_admit_review_graph(bytes)
}

/// Runs the exact final evidence-graph/readiness merge admission used by production.
///
/// # Errors
///
/// Returns the production admission error for malformed or inconsistent bytes.
pub fn fuzz_admit_evidence_graph_merge(bytes: &[u8]) -> Result<(), String> {
    assurance::fuzz_admit_evidence_graph_merge(bytes)
}

/// Renders the canonical accepted evidence-graph fuzz seed.
///
/// # Errors
///
/// Returns an error if canonical JSON rendering fails.
pub fn fuzz_evidence_graph_seed() -> Result<Vec<u8>, String> {
    assurance::fuzz_evidence_graph_seed()
}

/// Runs the production review-envelope schema and content-binding admission.
///
/// # Errors
///
/// Returns the production admission error for malformed or inconsistent bytes.
pub fn fuzz_admit_dsse_envelope(bytes: &[u8]) -> Result<(), String> {
    assurance::fuzz_admit_dsse_envelope(bytes)
}

#[cfg(feature = "mutation-testing")]
pub(crate) fn assurance_control_mutant_active(id: &str) -> bool {
    std::env::var("HELL_ASSURANCE_MUTANT_ID").as_deref() == Ok(id)
}

#[cfg(not(feature = "mutation-testing"))]
pub(crate) const fn assurance_control_mutant_active(_id: &str) -> bool {
    false
}
