use std::collections::{BTreeMap, BTreeSet};

use super::evidence::{
    EvidenceIndex, EvidenceRepository, ObligationVerdict, TrustedEvidenceBindings,
    exploratory_mismatches,
};
use super::{
    Blocker, ConformancePlan, DerivedPartition, ExemptionKind, FailureClass, FinalDisposition,
    ScopeDisposition, VerificationMode,
};

/// Publisher-oriented reconstruction from the plan and raw evidence.
///
/// This deliberately does not call assembly's `derive_partition` or consume
/// producer reports/acceptance as decision input. It builds and reduces its
/// own maps and treats `claimed` only as expected output.
pub(crate) fn independently_reconstruct_partition(
    plan: &ConformancePlan,
    expected_universe: &[super::CellKey],
    evidence: &EvidenceRepository,
    trusted: &TrustedEvidenceBindings,
) -> Result<DerivedPartition, String> {
    plan.validate(expected_universe)?;
    super::validate_plan_case_authority(plan)?;
    trusted.validate()?;
    if trusted.conformance_plan_sha256 != plan.plan_sha256
        || trusted.candidate_sha != plan.candidate_sha
        || trusted.source_inventory_sha256 != plan.source_inventory_sha256
    {
        return Err("publisher trusted bindings differ from conformance plan".to_owned());
    }
    let mut index = EvidenceIndex::build(evidence)?;
    let mut cells = BTreeMap::new();
    let mut obligations = BTreeSet::new();
    let mut exemptions = BTreeSet::new();
    for planned in &plan.cells {
        let disposition = match &planned.scope {
            ScopeDisposition::Excluded { scope_id, .. } => FinalDisposition::Excluded {
                scope_id: scope_id.clone(),
            },
            ScopeDisposition::NotApplicable { decision_id, .. } => {
                FinalDisposition::NotApplicable {
                    decision_id: decision_id.clone(),
                }
            }
            ScopeDisposition::Required { .. } => {
                let mut results = Vec::new();
                for obligation in &planned.obligations {
                    if !obligations.insert((planned.key.clone(), obligation.id.clone())) {
                        return Err("publisher reconstructed one obligation twice".to_owned());
                    }
                    results.push((
                        obligation.id.as_str(),
                        index.evaluate_obligation(planned, obligation, trusted),
                    ));
                }
                independently_reduce(planned, &results, &mut exemptions)?
            }
        };
        if cells.insert(planned.key.clone(), disposition).is_some() {
            return Err("publisher reconstructed a duplicate cell".to_owned());
        }
    }
    index.require_empty()?;
    let reconstructed = DerivedPartition {
        cells,
        unclassified_mismatches: exploratory_mismatches(evidence, trusted)?,
        consumed_obligations: obligations,
        consumed_exemptions: exemptions,
    };
    reconstructed.validate_complete_against(plan)?;
    let independent_counts = independently_count(&reconstructed.cells)?;
    if independent_counts.total()?
        != u64::try_from(reconstructed.cells.len())
            .map_err(|_| "independent cell count overflow")?
    {
        return Err("publisher independent counters do not cover the partition".to_owned());
    }
    Ok(reconstructed)
}

fn independently_reduce(
    cell: &super::PlannedCell,
    results: &[(&str, ObligationVerdict)],
    consumed_exemptions: &mut BTreeSet<String>,
) -> Result<FinalDisposition, String> {
    let failures = results
        .iter()
        .filter(|(_, result)| !matches!(result, ObligationVerdict::Verified { .. }))
        .collect::<Vec<_>>();
    if failures.is_empty() {
        if cell.exemption.is_some() {
            return Err("publisher found an unused exemption on a verified cell".to_owned());
        }
        let mut ids = Vec::new();
        let mut normalized = false;
        let mut platform_equivalent = false;
        for (_, result) in results {
            let ObligationVerdict::Verified { mode, evidence_ids } = result else {
                return Err("publisher verified reduction contains a failure".to_owned());
            };
            normalized |= *mode == VerificationMode::Normalized;
            platform_equivalent |= *mode == VerificationMode::PlatformEquivalent;
            ids.extend(evidence_ids.iter().cloned());
        }
        let mode = if platform_equivalent {
            VerificationMode::PlatformEquivalent
        } else if normalized {
            VerificationMode::Normalized
        } else {
            VerificationMode::Exact
        };
        return Ok(FinalDisposition::Verified {
            mode,
            evidence_ids: ids,
        });
    }
    if failures.len() == 1 {
        let (obligation_id, result) = failures[0];
        if let Some(exemption) = cell.exemption.as_ref().filter(|exemption| {
            exemption.obligation_id == *obligation_id
                && match (exemption.kind, result) {
                    (ExemptionKind::EvidenceGap, ObligationVerdict::Missing) => true,
                    (
                        ExemptionKind::KnownDivergence,
                        ObligationVerdict::Mismatch { mismatch_sha256 },
                    ) => exemption.expected_mismatch_sha256.as_ref() == Some(mismatch_sha256),
                    _ => false,
                }
        }) {
            if !consumed_exemptions.insert(exemption.id.clone()) {
                return Err("publisher consumed one exemption twice".to_owned());
            }
            return Ok(FinalDisposition::Exempted {
                exemption_id: exemption.id.clone(),
                underlying: match result {
                    ObligationVerdict::Missing => FailureClass::MissingEvidence,
                    ObligationVerdict::Mismatch { .. } => FailureClass::Mismatch,
                    ObligationVerdict::Invalid { .. } | ObligationVerdict::Verified { .. } => {
                        return Err("publisher cannot exempt invalid evidence".to_owned());
                    }
                },
            });
        }
    }
    let (obligation_id, result) = failures
        .iter()
        .find(|(_, result)| matches!(result, ObligationVerdict::Invalid { .. }))
        .or_else(|| {
            failures
                .iter()
                .find(|(_, result)| matches!(result, ObligationVerdict::Mismatch { .. }))
        })
        .unwrap_or(&failures[0]);
    Ok(FinalDisposition::Blocked {
        blocker: match result {
            ObligationVerdict::Missing => Blocker::MissingEvidence {
                obligation_id: (*obligation_id).to_owned(),
            },
            ObligationVerdict::Mismatch { mismatch_sha256 } => Blocker::Mismatch {
                obligation_id: (*obligation_id).to_owned(),
                mismatch_sha256: mismatch_sha256.clone(),
            },
            ObligationVerdict::Invalid { code } => Blocker::InvalidEvidence { code: *code },
            ObligationVerdict::Verified { .. } => {
                return Err("publisher selected verified evidence as failure".to_owned());
            }
        },
    })
}

#[derive(Default)]
struct IndependentCounts {
    verified: u64,
    not_applicable: u64,
    excluded: u64,
    exempted: u64,
    blocked: u64,
}

impl IndependentCounts {
    fn total(&self) -> Result<u64, String> {
        [
            self.verified,
            self.not_applicable,
            self.excluded,
            self.exempted,
            self.blocked,
        ]
        .into_iter()
        .try_fold(0_u64, |total, value| {
            total
                .checked_add(value)
                .ok_or_else(|| "independent count overflow".to_owned())
        })
    }
}

fn independently_count(
    cells: &BTreeMap<super::CellKey, FinalDisposition>,
) -> Result<IndependentCounts, String> {
    let mut counts = IndependentCounts::default();
    let mut evidence_ids = BTreeSet::new();
    for disposition in cells.values() {
        let counter = match disposition {
            FinalDisposition::Verified {
                evidence_ids: ids, ..
            } => {
                for id in ids {
                    if !evidence_ids.insert(id) {
                        return Err(
                            "one evidence record verifies multiple unapproved targets".to_owned()
                        );
                    }
                }
                &mut counts.verified
            }
            FinalDisposition::NotApplicable { .. } => &mut counts.not_applicable,
            FinalDisposition::Excluded { .. } => &mut counts.excluded,
            FinalDisposition::Exempted { .. } => &mut counts.exempted,
            FinalDisposition::Blocked { .. } => &mut counts.blocked,
        };
        *counter = counter
            .checked_add(1)
            .ok_or_else(|| "independent partition count overflow".to_owned())?;
    }
    Ok(counts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn independent_counter_rejects_reused_evidence_id() {
        let key = super::super::CellKey::new(
            "Bool.bool",
            hell_builtins::CompatibilityDimension::PureRuntime,
            super::super::ProfileId::Upstream,
            super::super::ConformancePlatform::LinuxX86_64,
        )
        .unwrap();
        let other = super::super::CellKey::new(
            "Bool.not",
            hell_builtins::CompatibilityDimension::PureRuntime,
            super::super::ProfileId::Upstream,
            super::super::ConformancePlatform::LinuxX86_64,
        )
        .unwrap();
        let cells = BTreeMap::from([
            (
                key,
                FinalDisposition::Verified {
                    mode: VerificationMode::Exact,
                    evidence_ids: vec!["ev-one".to_owned()],
                },
            ),
            (
                other,
                FinalDisposition::Verified {
                    mode: VerificationMode::Exact,
                    evidence_ids: vec!["ev-one".to_owned()],
                },
            ),
        ]);
        assert!(independently_count(&cells).is_err());
    }
}
