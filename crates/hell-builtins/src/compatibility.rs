//! Reviewed compatibility overrides.
//!
//! Promotion tooling may render a worklist, but it never writes this module.
//! The table intentionally remains empty until retained evidence and native
//! provenance have completed independent review.

use crate::{CompatibilityDimension, ScopedClaim};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ClaimOverride {
    pub builtin: &'static str,
    pub dimension: CompatibilityDimension,
    pub scopes: &'static [ScopedClaim],
}

pub(crate) const OVERRIDES: &[ClaimOverride] = &[];
